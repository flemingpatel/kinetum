// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_component_preflight.cpp
 * @brief Architecture-selectable static admission for provider artifacts.
 * @author Fleming Patel
 */

#include "src/provider/provider_component_preflight.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "src/common/status.hpp"
#include "src/provider/provider_inventory.hpp"

namespace kinetum::provider
{
namespace
{

using common::sha256_digest;
using common::status;
using common::status_or;
using kinetum::provider::v1::PrivateProviderArtifact;
using kinetum::provider::v1::ProviderComponentArtifact;

/**
 * Exact aarch64 platform-runtime SONAMEs permitted outside a signed private closure.
 *
 * `libnuma` is the sole DPDK-specific dynamic prerequisite of the hermetic
 * component. DPDK libraries, PMDs, optional helper libraries, and transitive
 * non-platform dependencies are intentionally absent.
 */
constexpr std::array<std::string_view, 9> AARCH64_PLATFORM_RUNTIME_SONAMES{
	LINUX_GNU_AARCH64_RUNTIME_LOADER_SONAME,
	"libc.so.6",
	"libdl.so.2",
	"libgcc_s.so.1",
	"libm.so.6",
	"libnuma.so.1",
	"libpthread.so.0",
	"librt.so.1",
	"libstdc++.so.6",
};

/** Exact x86-64 platform-runtime SONAME authority in strict lexical order. */
constexpr std::array<std::string_view, 9> X86_64_PLATFORM_RUNTIME_SONAMES{
	LINUX_GNU_X86_64_RUNTIME_LOADER_SONAME,
	"libc.so.6",
	"libdl.so.2",
	"libgcc_s.so.1",
	"libm.so.6",
	"libnuma.so.1",
	"libpthread.so.0",
	"librt.so.1",
	"libstdc++.so.6",
};

/**
 * @brief Prove binary-search order and uniqueness of a runtime SONAME authority.
 * @tparam size Number of entries in the fixed target-specific authority.
 * @param sonames Runtime SONAME list to inspect at compile time.
 * @return true only when every adjacent pair is strictly increasing.
 */
template <std::size_t size>
consteval bool platform_runtime_sonames_are_strictly_sorted(const std::array<std::string_view, size> &sonames) noexcept
{
	for (std::size_t index = 1; index < sonames.size(); ++index) {
		if (sonames[index - 1] >= sonames[index]) {
			return false;
		}
	}
	return true;
}

static_assert(platform_runtime_sonames_are_strictly_sorted(AARCH64_PLATFORM_RUNTIME_SONAMES),
	      "aarch64 runtime SONAME authority must remain strictly sorted and unique");
static_assert(platform_runtime_sonames_are_strictly_sorted(X86_64_PLATFORM_RUNTIME_SONAMES),
	      "x86-64 runtime SONAME authority must remain strictly sorted and unique");

/**
 * @brief Convert one exact 32-byte protobuf field to the digest value type.
 *
 * @param bytes Exact validated digest bytes.
 * @return Fixed-width digest.
 */
sha256_digest digest_from_bytes(std::string_view bytes) noexcept
{
	sha256_digest digest{};
	std::memcpy(digest.data(), bytes.data(), digest.size());
	return digest;
}

/**
 * @brief Compare authenticated dependency claims with inspected ELF facts.
 *
 * @param expected Authenticated sorted dependency set.
 * @param actual Inspected sorted dependency set.
 * @return OK only for exact two-directional equality.
 */
status verify_needed_sonames(const google::protobuf::RepeatedPtrField<std::string> &expected,
			     const std::vector<std::string> &actual)
{
	if (expected.size() != static_cast<int>(actual.size())) {
		return status::failed_precondition("provider ELF DT_NEEDED set disagrees with authenticated inventory");
	}
	for (int index = 0; index < expected.size(); ++index) {
		if (expected.Get(index) != actual[static_cast<std::size_t>(index)]) {
			return status::failed_precondition(
				"provider ELF DT_NEEDED set disagrees with authenticated inventory");
		}
	}
	return status::ok();
}

}  // namespace

bool is_platform_runtime_soname(std::string_view soname, provider_target_tuple target) noexcept
{
	switch (target) {
	case provider_target_tuple::LINUX_GNU_AARCH64:
		return std::binary_search(AARCH64_PLATFORM_RUNTIME_SONAMES.begin(),
					  AARCH64_PLATFORM_RUNTIME_SONAMES.end(), soname);
	case provider_target_tuple::LINUX_GNU_X86_64:
		return std::binary_search(X86_64_PLATFORM_RUNTIME_SONAMES.begin(),
					  X86_64_PLATFORM_RUNTIME_SONAMES.end(), soname);
	}
	std::abort();
}

preflighted_provider_component::preflighted_provider_component(
	kinetum::provider::v1::ProviderComponentArtifact record, common::held_file file, provider_elf_facts elf,
	std::vector<preflighted_provider_component::private_artifact> private_dependencies) noexcept
	: record_(std::move(record))
	, file_(std::move(file))
	, elf_(std::move(elf))
	, private_dependencies_(std::move(private_dependencies))
{
}

const ProviderComponentArtifact &preflighted_provider_component::record() const noexcept
{
	return record_;
}

std::size_t preflighted_provider_component::private_dependency_count() const noexcept
{
	return private_dependencies_.size();
}

std::string_view preflighted_provider_component::private_dependency_file_name(std::size_t index) const noexcept
{
	return index < private_dependencies_.size() ? private_dependencies_[index].file_name : std::string_view{};
}

std::string_view preflighted_provider_component::private_dependency_soname(std::size_t index) const noexcept
{
	return index < private_dependencies_.size() ? private_dependencies_[index].soname : std::string_view{};
}

const sha256_digest *preflighted_provider_component::private_dependency_sha256(std::size_t index) const noexcept
{
	return index < private_dependencies_.size() ? &private_dependencies_[index].file.identity().sha256 : nullptr;
}

status_or<preflighted_provider_component> preflight_provider_component(
	const std::filesystem::path &artifact_directory,
	const kinetum::provider::v1::ProviderComponentArtifact &component,
	const google::protobuf::RepeatedPtrField<kinetum::provider::v1::PrivateProviderArtifact> &private_artifacts,
	provider_target_tuple target, const common::held_file_policy &file_policy)
{
	if (artifact_directory.empty() || !artifact_directory.is_absolute() ||
	    artifact_directory != artifact_directory.lexically_normal()) {
		return status::invalid_argument("provider artifact directory must be exact, absolute, and normalized");
	}
	if (private_artifacts.size() > static_cast<int>(MAX_PROVIDER_PRIVATE_ARTIFACTS)) {
		return status::resource_exhausted(
			"provider private-artifact preflight set exceeds its inventory bound");
	}
	auto record_status = validate_canonical_provider_component_artifact(component);
	if (!record_status.is_ok()) {
		return record_status;
	}

	std::unordered_map<std::string, const PrivateProviderArtifact *> private_by_soname;
	private_by_soname.reserve(static_cast<std::size_t>(private_artifacts.size()));
	for (const auto &artifact : private_artifacts) {
		record_status = validate_canonical_provider_private_artifact(artifact);
		if (!record_status.is_ok()) {
			return record_status;
		}
		if (is_platform_runtime_soname(artifact.soname(), target)) {
			return status::invalid_argument(
				"provider inventory cannot redefine a platform runtime SONAME as a private artifact");
		}
		if (!private_by_soname.emplace(artifact.soname(), &artifact).second) {
			return status::invalid_argument(
				"provider inventory contains duplicate private SONAME ownership");
		}
	}

	auto component_file = common::open_held_regular_file(artifact_directory / component.file_name(), file_policy);
	if (!component_file.is_ok()) {
		return component_file.error();
	}
	auto identity_status = common::verify_held_file_identity(
		component_file.value(), digest_from_bytes(component.sha256()), component.size_bytes());
	if (!identity_status.is_ok()) {
		return identity_status;
	}
	auto component_elf = inspect_provider_component_elf(component_file.value(), target);
	if (!component_elf.is_ok()) {
		return component_elf.error();
	}
	auto needed_status = verify_needed_sonames(component.needed_sonames(), component_elf->needed_sonames);
	if (!needed_status.is_ok()) {
		return needed_status;
	}

	/** Iterative depth-first search frame for one private dependency vertex. */
	struct dependency_frame {
		const PrivateProviderArtifact *record;	///< Current authenticated graph vertex.
		std::size_t next_child;			///< Next direct dependency to inspect.
	};
	std::unordered_map<std::string, uint8_t> colors;
	std::vector<preflighted_provider_component::private_artifact> dependencies;
	std::vector<dependency_frame> stack;
	colors.reserve(private_by_soname.size());
	dependencies.reserve(private_by_soname.size());
	stack.reserve(private_by_soname.size());

	for (const auto &root_soname : component.needed_sonames()) {
		if (is_platform_runtime_soname(root_soname, target)) {
			continue;
		}
		const auto root = private_by_soname.find(root_soname);
		if (root == private_by_soname.end()) {
			return status::failed_precondition("provider ELF requires an undeclared private dependency");
		}
		if (colors[root_soname] == 2) {
			continue;
		}
		colors[root_soname] = 1;
		stack.push_back(dependency_frame{root->second, 0});

		while (!stack.empty()) {
			auto &frame = stack.back();
			const auto &record = *frame.record;
			if (frame.next_child < static_cast<std::size_t>(record.needed_sonames_size())) {
				const std::string &child_soname =
					record.needed_sonames(static_cast<int>(frame.next_child));
				++frame.next_child;
				if (is_platform_runtime_soname(child_soname, target)) {
					continue;
				}
				const auto child = private_by_soname.find(child_soname);
				if (child == private_by_soname.end()) {
					return status::failed_precondition(
						"provider ELF requires an undeclared private dependency");
				}
				const uint8_t color = colors[child_soname];
				if (color == 1) {
					return status::failed_precondition(
						"provider private dependency graph contains a cycle");
				}
				if (color == 2) {
					continue;
				}
				colors[child_soname] = 1;
				stack.push_back(dependency_frame{child->second, 0});
				continue;
			}

			auto file_or =
				common::open_held_regular_file(artifact_directory / record.file_name(), file_policy);
			if (!file_or.is_ok()) {
				return file_or.error();
			}
			identity_status = common::verify_held_file_identity(
				file_or.value(), digest_from_bytes(record.sha256()), record.size_bytes());
			if (!identity_status.is_ok()) {
				return identity_status;
			}
			auto elf_or = inspect_provider_private_elf(file_or.value(), record.soname(), target);
			if (!elf_or.is_ok()) {
				return elf_or.error();
			}
			auto dependency_status = verify_needed_sonames(record.needed_sonames(), elf_or->needed_sonames);
			if (!dependency_status.is_ok()) {
				return dependency_status;
			}
			colors[record.soname()] = 2;
			dependencies.push_back(preflighted_provider_component::private_artifact{
				record.file_name(), record.soname(), std::move(file_or).value(),
				std::move(elf_or).value()});
			stack.pop_back();
		}
	}
	return preflighted_provider_component(component, std::move(component_file).value(),
					      std::move(component_elf).value(), std::move(dependencies));
}

status validate_preflighted_provider_component_set(std::span<const preflighted_provider_component> components)
{
	/** One exact private SONAME authority across component closures. */
	struct private_identity {
		std::string file_name;	 ///< Exact authenticated artifact basename.
		sha256_digest sha256{};	 ///< Same-descriptor exact content identity.
	};

	/** One exact artifact basename authority across the complete preflight set. */
	struct file_identity {
		bool is_private{false};	 ///< Distinguish shareable closure entries from components.
		std::string soname;	 ///< Exact private SONAME, empty for components.
		sha256_digest sha256{};	 ///< Same-descriptor exact content identity.
	};

	if (components.empty()) {
		return status::invalid_argument("provider component preflight requires a nonempty set");
	}
	if (components.size() > MAX_PROVIDER_COMPONENTS) {
		return status::resource_exhausted("provider component preflight set exceeds its inventory bound");
	}
	std::unordered_set<std::string> component_ids;
	std::unordered_set<std::string> contract_urls;
	std::unordered_map<std::string, private_identity> private_identities;
	std::unordered_map<std::string, file_identity> file_identities;
	component_ids.reserve(components.size());
	file_identities.reserve(components.size() + MAX_PROVIDER_PRIVATE_ARTIFACTS);
	for (const auto &component : components) {
		if (!component_ids.insert(component.record().component_id()).second) {
			return status::invalid_argument("provider preflight contains duplicate component identity");
		}
		if (!file_identities
			     .emplace(component.record().file_name(),
				      file_identity{false, {}, digest_from_bytes(component.record().sha256())})
			     .second) {
			return status::invalid_argument("provider preflight contains duplicate artifact file identity");
		}
		for (const auto &type_url : component.record().contract_type_urls()) {
			if (!contract_urls.insert(type_url).second) {
				return status::invalid_argument(
					"provider preflight contains duplicate contract ownership");
			}
		}
		for (std::size_t index = 0; index < component.private_dependency_count(); ++index) {
			const std::string_view file_name = component.private_dependency_file_name(index);
			const std::string_view soname = component.private_dependency_soname(index);
			const auto *identity = component.private_dependency_sha256(index);
			if (file_name.empty() || soname.empty() || identity == nullptr) {
				std::abort();
			}
			const auto [soname_it, soname_inserted] = private_identities.emplace(
				std::string(soname), private_identity{std::string(file_name), *identity});
			if (!soname_inserted &&
			    (soname_it->second.file_name != file_name || soname_it->second.sha256 != *identity)) {
				return status::failed_precondition(
					"provider preflight maps one private SONAME to different artifacts");
			}
			const auto [file_it, file_inserted] = file_identities.emplace(
				std::string(file_name), file_identity{true, std::string(soname), *identity});
			if (!file_inserted && (!file_it->second.is_private || file_it->second.soname != soname ||
					       file_it->second.sha256 != *identity)) {
				return status::failed_precondition(
					"provider preflight maps one artifact file identity to different content");
			}
		}
	}
	if (private_identities.size() > MAX_PROVIDER_PRIVATE_ARTIFACTS) {
		return status::resource_exhausted(
			"provider preflight private-artifact set exceeds its inventory bound");
	}
	return status::ok();
}

}  // namespace kinetum::provider
