// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dpdk_pci_probe.cpp
 * @brief Bounded sysfs observation and exact i40e adapter ownership proof.
 * @author Fleming Patel
 */

#include "src/dp/backends/dpdk/dpdk_pci_probe.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <kinetum_i40e_pci_ids.hpp>
#include <rte_pci.h>

#include "src/provider/components/component_support.hpp"

namespace kinetum::provider::dpdk_component
{
namespace
{

/** Kernel-owned PCI function directory; no deployment input overrides it. */
constexpr char PCI_DEVICES_DIRECTORY[] = "/sys/bus/pci/devices";
/** Exact dddd:bb:ss.f spelling extent without its terminator. */
constexpr std::size_t PCI_ADDRESS_BYTES = 12;
/** Maximum complete attribute text, including its newline. */
constexpr std::size_t PCI_ATTRIBUTE_BYTES = 32;
/** Maximum inspected directory entries when proving no VF links exist. */
constexpr uint32_t PCI_DIRECTORY_ENTRY_LIMIT = 512;

/**
 * @brief Require the native PCI parser and canonical renderer to reproduce the input.
 * @param address Borrowed authored address.
 * @return True only for one complete canonical physical-function spelling.
 */
[[nodiscard]] bool canonical_pci_address(std::string_view address) noexcept
{
	if (address.size() != PCI_ADDRESS_BYTES || address.find('\0') != std::string_view::npos) {
		return false;
	}
	std::array<char, PCI_ADDRESS_BYTES + 1> input{};
	std::copy(address.begin(), address.end(), input.begin());
	rte_pci_addr parsed{};
	if (rte_pci_addr_parse(input.data(), &parsed) != 0 || parsed.devid > 31u || parsed.function > 7u) {
		return false;
	}
	std::array<char, PCI_PRI_STR_SIZE> rendered{};
	rte_pci_device_name(&parsed, rendered.data(), rendered.size());
	return address == rendered.data();
}

/**
 * @brief Read one optional unsigned sysfs attribute completely.
 * @param directory Borrowed device directory.
 * @param name Fixed attribute basename.
 * @param hexadecimal Whether exact 0x-prefixed hexadecimal syntax is required.
 * @param present Distinguishes a missing attribute from a read failure.
 * @param value Parsed uint16 value, zero when absent.
 * @return True only after exact absence or complete parsing and close.
 */
[[nodiscard]] bool read_attribute(int directory, const char *name, bool hexadecimal, bool &present,
				  uint16_t &value) noexcept
{
	present = false;
	value = 0;
	const int descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0) {
		return errno == ENOENT;
	}
	std::array<char, PCI_ATTRIBUTE_BYTES> bytes{};
	std::size_t used = 0;
	bool complete = false;
	while (used < bytes.size()) {
		const ssize_t received = read(descriptor, bytes.data() + used, bytes.size() - used);
		if (received < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (received == 0) {
			complete = true;
			break;
		}
		used += static_cast<std::size_t>(received);
	}
	if (close(descriptor) != 0 || !complete || used == 0) {
		return false;
	}
	std::string_view text(bytes.data(), used);
	if (text.ends_with('\n')) {
		text.remove_suffix(1);
	}
	if (hexadecimal) {
		if (text.size() != 6u || !text.starts_with("0x")) {
			return false;
		}
		text.remove_prefix(2);
	}
	const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, hexadecimal ? 16 : 10);
	if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
		return false;
	}
	present = true;
	return true;
}

/**
 * @brief Observe a symlink without treating a dangling link as absence.
 * @param directory Borrowed device directory.
 * @param name Fixed or kernel-enumerated link basename.
 * @param present True only for an existing symlink.
 * @return True for a symlink or exact absence; false for other types or errors.
 */
[[nodiscard]] bool read_link_presence(int directory, const char *name, bool &present) noexcept
{
	struct stat metadata{};
	present = false;
	if (fstatat(directory, name, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
		return errno == ENOENT;
	}
	present = S_ISLNK(metadata.st_mode);
	return present;
}

/**
 * @brief Collect one complete function observation from a retained directory.
 * @param directory Borrowed device directory stream.
 * @param observation Candidate output, not published on failure.
 * @return True only for complete attribute and link observations.
 */
[[nodiscard]] bool read_function_directory(DIR *directory, dpdk_pci_function_observation &observation) noexcept
{
	const int descriptor = dirfd(directory);
	bool vendor_present = false;
	bool device_present = false;
	if (!read_attribute(descriptor, "vendor", true, vendor_present, observation.vendor) || !vendor_present ||
	    !read_attribute(descriptor, "device", true, device_present, observation.device) || !device_present ||
	    !read_attribute(descriptor, "sriov_totalvfs", false, observation.totalvfs_present,
			    observation.sriov_totalvfs) ||
	    !read_attribute(descriptor, "sriov_numvfs", false, observation.numvfs_present, observation.sriov_numvfs) ||
	    !read_link_presence(descriptor, "physfn", observation.physfn_present)) {
		return false;
	}
	bool driver_present = false;
	if (!read_link_presence(descriptor, "driver", driver_present)) {
		return false;
	}
	if (driver_present) {
		std::array<char, 512> target{};
		const ssize_t size = readlinkat(descriptor, "driver", target.data(), target.size());
		if (size <= 0 || static_cast<std::size_t>(size) >= target.size()) {
			return false;
		}
		const std::string_view link(target.data(), static_cast<std::size_t>(size));
		auto basename = link;
		const auto separator = link.find_last_of('/');
		if (separator != std::string_view::npos) {
			basename.remove_prefix(separator + 1u);
		}
		observation.binding = basename == "vfio-pci" ? dpdk_pci_binding::VFIO : dpdk_pci_binding::FOREIGN;
	}
	for (uint32_t visited = 0; visited < PCI_DIRECTORY_ENTRY_LIMIT; ++visited) {
		errno = 0;
		const auto *entry = readdir(directory);
		if (entry == nullptr) {
			return errno == 0;
		}
		const std::string_view name(entry->d_name);
		if (name.starts_with("virtfn")) {
			bool present = false;
			if (!read_link_presence(descriptor, entry->d_name, present) || !present) {
				return false;
			}
			observation.virtfn_present = true;
		}
	}
	return false;
}

/**
 * @brief Open the kernel PCI directory for one ephemeral native observation.
 * @param state Unused native mechanism state.
 * @param address Canonical function address.
 * @param observation Complete output written only on success.
 * @return Exact observation outcome after closing all owned descriptors.
 */
dpdk_pci_probe_result native_read_function(void *state, const char *address,
					   dpdk_pci_function_observation *observation) noexcept
{
	(void)state;
	if (observation == nullptr) {
		return dpdk_pci_probe_result::UNAVAILABLE;
	}
	const int directory = open(PCI_DEVICES_DIRECTORY, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (directory < 0) {
		return dpdk_pci_probe_result::UNAVAILABLE;
	}
	const auto result = read_dpdk_pci_function_at(directory, address, *observation);
	return close(directory) == 0 ? result : dpdk_pci_probe_result::UNAVAILABLE;
}

/**
 * @brief Report a bounded cold ownership error with its exact PCI function.
 * @param diagnostic Optional caller-owned failure output.
 * @param address Canonical rejected function.
 * @param reason Static description of the rejected evidence.
 * @return FAILED_PRECONDITION; allocation failure propagates to the proof owner.
 */
[[nodiscard]] kinetum_provider_status reject_function(kinetum_provider_diagnostic *diagnostic, std::string_view address,
						      std::string_view reason)
{
	std::string message = "DPDK PCI ";
	message.append(address);
	message.append(": ");
	message.append(reason);
	return component_support::fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic, message);
}

}  // namespace

dpdk_pci_probe_result read_dpdk_pci_function_at(int devices_directory, const char *address,
						dpdk_pci_function_observation &observation) noexcept
{
	if (address == nullptr || !canonical_pci_address(address)) {
		return dpdk_pci_probe_result::UNAVAILABLE;
	}
	struct stat entry{};
	if (fstatat(devices_directory, address, &entry, AT_SYMLINK_NOFOLLOW) != 0) {
		return errno == ENOENT ? dpdk_pci_probe_result::ABSENT : dpdk_pci_probe_result::UNAVAILABLE;
	}
	const int descriptor = openat(devices_directory, address, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (descriptor < 0) {
		return dpdk_pci_probe_result::UNAVAILABLE;
	}
	DIR *directory = fdopendir(descriptor);
	if (directory == nullptr) {
		(void)close(descriptor);
		return dpdk_pci_probe_result::UNAVAILABLE;
	}
	dpdk_pci_function_observation candidate{};
	struct stat retained{};
	struct stat current{};
	const bool complete = fstat(descriptor, &retained) == 0 && read_function_directory(directory, candidate) &&
			      fstatat(devices_directory, address, &current, 0) == 0 &&
			      retained.st_dev == current.st_dev && retained.st_ino == current.st_ino;
	if (closedir(directory) != 0 || !complete) {
		return dpdk_pci_probe_result::UNAVAILABLE;
	}
	observation = candidate;
	return dpdk_pci_probe_result::PRESENT;
}

dpdk_pci_probe_api default_dpdk_pci_probe_api() noexcept
{
	return dpdk_pci_probe_api{.state = nullptr, .read_function = native_read_function};
}

kinetum_provider_status prove_dpdk_pci_ownership(std::span<const kinetum_provider_driver_attachment_fact> attachments,
						 const dpdk_pci_probe_api &api,
						 kinetum_provider_diagnostic *diagnostic) noexcept
{
	try {
		std::vector<std::string_view> addresses;
		addresses.reserve(attachments.size());
		for (const auto &attachment : attachments) {
			if (attachment.kind == KINETUM_PROVIDER_ATTACHMENT_TAP) {
				continue;
			}
			if (attachment.kind != KINETUM_PROVIDER_ATTACHMENT_PCI ||
			    !kinetum_provider_text_view_is_valid(attachment.attachment_identity)) {
				return component_support::fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
							       "DPDK PCI proof received an unsupported attachment");
			}
			const std::string_view address(attachment.attachment_identity.data,
						       attachment.attachment_identity.size);
			if (!canonical_pci_address(address)) {
				return component_support::fail(
					KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					"DPDK PCI attachment is not a canonical physical-function address");
			}
			addresses.push_back(address);
		}
		std::sort(addresses.begin(), addresses.end());
		if (std::adjacent_find(addresses.begin(), addresses.end()) != addresses.end()) {
			return component_support::fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						       "DPDK PCI attachment ownership is duplicated");
		}
		if (!addresses.empty() && api.read_function == nullptr) {
			return component_support::fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						       "DPDK PCI inspection mechanism is unavailable");
		}
		std::string_view previous_group;
		for (const auto address : addresses) {
			auto group = address;
			group.remove_suffix(1);
			if (group == previous_group) {
				continue;
			}
			previous_group = group;
			std::array<char, PCI_ADDRESS_BYTES + 1> candidate{};
			std::copy(address.begin(), address.end(), candidate.begin());
			for (uint8_t function = 0; function < 8u; ++function) {
				candidate[PCI_ADDRESS_BYTES - 1u] = static_cast<char>('0' + function);
				const std::string_view bdf(candidate.data(), PCI_ADDRESS_BYTES);
				const bool declared = std::binary_search(addresses.begin(), addresses.end(), bdf);
				dpdk_pci_function_observation observed{};
				const auto result = api.read_function(api.state, candidate.data(), &observed);
				if (result == dpdk_pci_probe_result::ABSENT && !declared) {
					continue;
				}
				if (result != dpdk_pci_probe_result::PRESENT) {
					return reject_function(diagnostic, bdf,
							       "function evidence is absent or unavailable");
				}
				const uint32_t identity = (static_cast<uint32_t>(observed.vendor) << 16u) |
							  observed.device;
				if (observed.vendor == 0 || observed.vendor == UINT16_MAX || observed.device == 0 ||
				    observed.device == UINT16_MAX) {
					return reject_function(diagnostic, bdf, "function has an invalid PCI identity");
				}
				if (declared &&
				    !std::binary_search(I40E_PF_PCI_IDS.begin(), I40E_PF_PCI_IDS.end(), identity)) {
					return reject_function(diagnostic, bdf,
							       "declared function is not a supported i40e PF");
				}
				if (observed.physfn_present || observed.virtfn_present || observed.sriov_numvfs != 0 ||
				    observed.totalvfs_present != observed.numvfs_present ||
				    (!observed.totalvfs_present && observed.sriov_totalvfs != 0)) {
					return reject_function(diagnostic, bdf,
							       "VF or inconsistent SR-IOV ownership evidence");
				}
				if (observed.binding !=
				    (declared ? dpdk_pci_binding::VFIO : dpdk_pci_binding::UNBOUND)) {
					return reject_function(
						diagnostic, bdf,
						"declared functions require vfio-pci and unused siblings must be unbound");
				}
			}
		}
		component_support::write_diagnostic(diagnostic, std::string_view{});
		return KINETUM_PROVIDER_STATUS_OK;
	} catch (const std::bad_alloc &) {
		return component_support::fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
					       "DPDK PCI ownership proof could not allocate its declared set");
	} catch (const std::length_error &) {
		return component_support::fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
					       "DPDK PCI ownership set exceeds the host size domain");
	}
}

}  // namespace kinetum::provider::dpdk_component
