// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dpdk_host_probe.cpp
 * @brief Non-materializing DPDK host-proof implementation.
 * @author Fleming Patel
 */

#include "src/dp/backends/dpdk/dpdk_host_probe.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <string_view>

#include <rte_version.h>

#include "src/provider/components/component_support.hpp"

namespace kinetum::provider::dpdk_component
{
namespace
{

using component_support::fail;

/** Exact process-facility contract accepted by this host proof. */
constexpr char DPDK_FACILITY_TYPE_URL[] = "type.googleapis.com/kinetum.facility.dpdk.v1.DpdkFacilityConfig";
/** Kernel snapshot used to prove available hugepage payload backing. */
constexpr char MEMINFO_PATH[] = "/proc/meminfo";
/** Maximum complete meminfo snapshot admitted by the probe. */
constexpr uint32_t MAX_MEMINFO_BYTES = UINT32_C(65536);
/** Kernel field naming currently free hugepages. */
constexpr std::string_view HUGE_PAGES_FREE = "HugePages_Free:";
/** Kernel field naming reservations deducted from free hugepages. */
constexpr std::string_view HUGE_PAGES_RESERVED = "HugePages_Rsvd:";
/** Kernel field naming the hugepage size in KiB. */
constexpr std::string_view HUGE_PAGE_SIZE = "Hugepagesize:";

/**
 * @brief Return the linked DPDK runtime identity.
 * @param state Opaque API context; unused by this native wrapper.
 * @return Borrowed process-lifetime DPDK version string.
 */
const char *native_runtime_version(void *state) noexcept
{
	(void)state;
	return rte_version();
}

/**
 * @brief Read one bounded complete snapshot of Linux meminfo.
 * @param state Opaque API context; unused by this native wrapper.
 * @param buffer Caller-owned output storage; may contain a partial snapshot on failure.
 * @param capacity Maximum readable output bytes.
 * @param size Destination for the complete extent, written only on success.
 * @return Zero after complete bounded read and successful close; -1 otherwise.
 */
int native_read_meminfo(void *state, char *buffer, uint32_t capacity, uint32_t *size) noexcept
{
	(void)state;
	if (buffer == nullptr || capacity == 0 || size == nullptr) {
		return -1;
	}
	const int descriptor = open(MEMINFO_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0) {
		return -1;
	}
	uint32_t used = 0;
	while (used < capacity) {
		ssize_t received = 0;
		do {
			received = read(descriptor, buffer + used, static_cast<std::size_t>(capacity - used));
		} while (received < 0 && errno == EINTR);
		if (received < 0) {
			(void)close(descriptor);
			return -1;
		}
		if (received == 0) {
			break;
		}
		if (static_cast<uint64_t>(received) > capacity - used) {
			(void)close(descriptor);
			return -1;
		}
		used += static_cast<uint32_t>(received);
	}
	if (used == capacity) {
		char extra = 0;
		ssize_t received = 0;
		do {
			received = read(descriptor, &extra, 1);
		} while (received < 0 && errno == EINTR);
		if (received != 0) {
			(void)close(descriptor);
			return -1;
		}
	}
	if (close(descriptor) != 0) {
		return -1;
	}
	*size = used;
	return 0;
}

/**
 * @brief Return true only for a complete bounded host-probe API.
 * @param api Borrowed candidate native version and meminfo callbacks.
 * @return true only when both required operations are present.
 */
[[nodiscard]] bool api_is_complete(const dpdk_host_probe_api &api) noexcept
{
	return api.runtime_version != nullptr && api.read_meminfo != nullptr;
}

/**
 * @brief Parse one unique unsigned meminfo field with exact optional kB suffix.
 *
 * @param text Complete bounded meminfo bytes.
 * @param key Exact line prefix including the colon.
 * @param require_kilobytes Whether the value must end in the literal `kB`.
 * @param[out] value Parsed unsigned value.
 * @return true only for one exact decimal field and no trailing token.
 */
[[nodiscard]] bool parse_meminfo_value(std::string_view text, std::string_view key, bool require_kilobytes,
				       uint64_t &value) noexcept
{
	bool found = false;
	std::size_t line_begin = 0;
	while (line_begin <= text.size()) {
		const std::size_t line_end = text.find('\n', line_begin);
		const std::size_t bounded_end = line_end == std::string_view::npos ? text.size() : line_end;
		std::string_view line = text;
		line.remove_prefix(line_begin);
		line.remove_suffix(text.size() - bounded_end);
		if (line.starts_with(key)) {
			if (found) {
				return false;
			}
			std::size_t cursor = key.size();
			while (cursor < line.size() && (line[cursor] == ' ' || line[cursor] == '\t')) {
				++cursor;
			}
			if (cursor == line.size() || line[cursor] < '0' || line[cursor] > '9') {
				return false;
			}
			uint64_t parsed = 0;
			while (cursor < line.size() && line[cursor] >= '0' && line[cursor] <= '9') {
				const uint64_t digit = static_cast<uint64_t>(line[cursor] - '0');
				if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10u) {
					return false;
				}
				parsed = parsed * 10u + digit;
				++cursor;
			}
			while (cursor < line.size() && (line[cursor] == ' ' || line[cursor] == '\t')) {
				++cursor;
			}
			if (require_kilobytes) {
				if (line.size() - cursor < 2u || line[cursor] != 'k' || line[cursor + 1u] != 'B') {
					return false;
				}
				cursor += 2;
				while (cursor < line.size() && (line[cursor] == ' ' || line[cursor] == '\t')) {
					++cursor;
				}
			}
			if (cursor != line.size()) {
				return false;
			}
			value = parsed;
			found = true;
		}
		if (line_end == std::string_view::npos) {
			break;
		}
		line_begin = line_end + 1u;
	}
	return found;
}

/**
 * @brief Derive the complete plan-visible DPDK packet-payload byte floor.
 * @param facts Compiled process-facility memory-domain facts.
 * @param bytes Accumulated payload bytes; only a true result establishes a complete floor.
 * @return true for a nonzero overflow-free sum over valid memory domains.
 */
[[nodiscard]] bool payload_floor(const kinetum_provider_process_facility_facts &facts, uint64_t &bytes) noexcept
{
	bytes = 0;
	for (uint32_t index = 0; index < facts.memory_domain_count; ++index) {
		const auto &domain = facts.memory_domains[index];
		if (domain.buffer_count == 0 || domain.data_room_bytes == 0 || domain.has_host_numa_node != 1 ||
		    domain.host_numa_node < 0) {
			return false;
		}
		const uint64_t count = domain.buffer_count;
		const uint64_t room = domain.data_room_bytes;
		if (count > std::numeric_limits<uint64_t>::max() / room) {
			return false;
		}
		const uint64_t domain_bytes = count * room;
		if (bytes > std::numeric_limits<uint64_t>::max() - domain_bytes) {
			return false;
		}
		bytes += domain_bytes;
	}
	return bytes != 0;
}

}  // namespace

dpdk_host_probe_api default_dpdk_host_probe_api() noexcept
{
	return dpdk_host_probe_api{
		.state = nullptr,
		.runtime_version = native_runtime_version,
		.read_meminfo = native_read_meminfo,
	};
}

kinetum_provider_status prove_dpdk_host(const kinetum_provider_host_proof_request &request,
					const dpdk_host_probe_api &api,
					kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!api_is_complete(api) || kinetum_provider_host_proof_request_is_valid(&request) == 0 ||
	    request.role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY ||
	    !component_support::text_equals(request.type_url, DPDK_FACILITY_TYPE_URL) ||
	    request.canonical_configuration.size != 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK host proof received a malformed exact request");
	}
	const char *version = api.runtime_version(api.state);
	if (version == nullptr || version[0] == '\0') {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK runtime identity is unavailable");
	}
	uint64_t required_bytes = 0;
	if (!payload_floor(*request.compiled_facts.process_facility, required_bytes)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK hugepage requirements are incomplete or unrepresentable");
	}

	std::array<char, MAX_MEMINFO_BYTES> meminfo{};
	uint32_t meminfo_size = 0;
	if (api.read_meminfo(api.state, meminfo.data(), static_cast<uint32_t>(meminfo.size()), &meminfo_size) != 0 ||
	    meminfo_size == 0 || meminfo_size > meminfo.size()) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "Linux hugepage inventory is unavailable");
	}
	const std::string_view text(meminfo.data(), meminfo_size);
	uint64_t free_pages = 0;
	uint64_t reserved_pages = 0;
	uint64_t page_kilobytes = 0;
	if (!parse_meminfo_value(text, HUGE_PAGES_FREE, false, free_pages) ||
	    !parse_meminfo_value(text, HUGE_PAGES_RESERVED, false, reserved_pages) ||
	    !parse_meminfo_value(text, HUGE_PAGE_SIZE, true, page_kilobytes) || free_pages < reserved_pages ||
	    page_kilobytes == 0 || page_kilobytes > std::numeric_limits<uint64_t>::max() / UINT64_C(1024)) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "Linux hugepage inventory is malformed or unavailable");
	}
	const uint64_t page_bytes = page_kilobytes * UINT64_C(1024);
	const uint64_t available_pages = free_pages - reserved_pages;
	if (available_pages > std::numeric_limits<uint64_t>::max() / page_bytes ||
	    available_pages * page_bytes < required_bytes) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "unreserved hugepage bytes are below the compiled payload floor");
	}
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

}  // namespace kinetum::provider::dpdk_component
