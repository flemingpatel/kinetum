// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_inventory_reconstruction.cpp
 * @brief Static exact-target provider inventory reconstruction implementation.
 * @author Fleming Patel
 */

#include "src/provider/provider_inventory_reconstruction.hpp"

#include <exception>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

#include "src/common/status.hpp"
#include "src/provider/provider_build_identity.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_elf.hpp"
#include "src/provider/provider_inventory.hpp"

namespace kinetum::provider
{
namespace
{

using common::status;
using kinetum::provider::v1::InstalledProviderInventory;

/**
 * @brief Append one fixed digest to a protobuf bytes field.
 *
 * @param digest Exact digest.
 * @param output Non-null protobuf string destination.
 */
void assign_digest(const common::sha256_digest &digest, std::string *output)
{
	output->assign(reinterpret_cast<const char *>(digest.data()), digest.size());
}

/**
 * @brief Require one artifact to be a direct child of the exact staging root.
 *
 * @param artifact_directory Exact common parent.
 * @param path Candidate output path.
 * @return OK only when parent and basename are exact.
 */
status validate_staged_child(const std::filesystem::path &artifact_directory, const std::filesystem::path &path)
{
	if (path.empty() || !path.is_absolute() || path != path.lexically_normal() ||
	    path.parent_path() != artifact_directory || path.filename().empty()) {
		return status::invalid_argument("provider release artifact must be one exact direct staging child");
	}
	return status::ok();
}

}  // namespace

common::status_or<reconstructed_provider_inventory>
reconstruct_provider_inventory(const std::filesystem::path &runtime_image,
			       const std::filesystem::path &artifact_directory,
			       std::vector<release_provider_component_input> components,
			       std::vector<release_provider_private_artifact_input> private_artifacts,
			       provider_target_tuple target, const common::held_file_policy &file_policy)
{
	if (components.empty()) {
		return status::invalid_argument("provider release requires at least one explicit component");
	}
	if (components.size() > MAX_PROVIDER_COMPONENTS || private_artifacts.size() > MAX_PROVIDER_PRIVATE_ARTIFACTS) {
		return status::resource_exhausted("provider release artifact set exceeds its inventory bound");
	}
	for (const auto &input : components) {
		if (input.contract_type_urls.size() > provider_contract_count()) {
			return status::resource_exhausted(
				"provider release component contract set exceeds the pure catalog bound");
		}
	}
	if (artifact_directory.empty() || !artifact_directory.is_absolute() ||
	    artifact_directory != artifact_directory.lexically_normal()) {
		return status::invalid_argument("provider release artifact directory must be exact and absolute");
	}
	auto runtime_or = common::open_held_regular_file(runtime_image, file_policy);
	if (!runtime_or.is_ok()) {
		return runtime_or.error();
	}
	auto runtime_status = inspect_provider_runtime_elf(runtime_or.value(), target);
	if (!runtime_status.is_ok()) {
		return runtime_status;
	}

	InstalledProviderInventory inventory;
	inventory.set_product_version(KINETUM_VERSION_STR);
	inventory.set_provider_abi_identity(reinterpret_cast<const char *>(PROVIDER_ABI_IDENTITY.data()),
					    PROVIDER_ABI_IDENTITY.size());
	assign_digest(runtime_or->identity().sha256, inventory.mutable_runtime_sha256());
	inventory.set_runtime_size_bytes(runtime_or->identity().size_bytes);

	for (const auto &input : private_artifacts) {
		auto path_status = validate_staged_child(artifact_directory, input.path);
		if (!path_status.is_ok()) {
			return path_status;
		}
		auto file_or = common::open_held_regular_file(input.path, file_policy);
		if (!file_or.is_ok()) {
			return file_or.error();
		}
		auto elf_or = inspect_provider_private_elf(file_or.value(), input.soname, target);
		if (!elf_or.is_ok()) {
			return elf_or.error();
		}
		auto *record = inventory.add_private_artifacts();
		record->set_file_name(input.path.filename().string());
		record->set_soname(input.soname);
		assign_digest(file_or->identity().sha256, record->mutable_sha256());
		record->set_size_bytes(file_or->identity().size_bytes);
		for (const auto &needed : elf_or->needed_sonames) {
			record->add_needed_sonames(needed);
		}
	}

	for (auto &input : components) {
		auto path_status = validate_staged_child(artifact_directory, input.path);
		if (!path_status.is_ok()) {
			return path_status;
		}
		auto file_or = common::open_held_regular_file(input.path, file_policy);
		if (!file_or.is_ok()) {
			return file_or.error();
		}
		auto elf_or = inspect_provider_component_elf(file_or.value(), target);
		if (!elf_or.is_ok()) {
			return elf_or.error();
		}
		auto *record = inventory.add_components();
		record->set_component_id(std::move(input.component_id));
		record->set_file_name(input.path.filename().string());
		assign_digest(file_or->identity().sha256, record->mutable_sha256());
		record->set_size_bytes(file_or->identity().size_bytes);
		for (auto &type_url : input.contract_type_urls) {
			record->add_contract_type_urls(std::move(type_url));
		}
		for (const auto &needed : elf_or->needed_sonames) {
			record->add_needed_sonames(needed);
		}
	}

	auto canonical_or = canonicalize_provider_inventory(std::move(inventory));
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	InstalledProviderInventory canonical_inventory;
	if (!canonical_inventory.ParseFromArray(canonical_or->data(), static_cast<int>(canonical_or->size()))) {
		return status::internal_error("canonical provider inventory failed its internal parse invariant");
	}

	std::vector<preflighted_provider_component> preflighted;
	preflighted.reserve(static_cast<std::size_t>(canonical_inventory.components_size()));
	std::unordered_set<std::string> reached_private_sonames;
	for (const auto &component : canonical_inventory.components()) {
		auto component_or = preflight_provider_component(
			artifact_directory, component, canonical_inventory.private_artifacts(), target, file_policy);
		if (!component_or.is_ok()) {
			return component_or.error();
		}
		for (std::size_t index = 0; index < component_or->private_dependency_count(); ++index) {
			const std::string_view soname = component_or->private_dependency_soname(index);
			if (soname.empty()) {
				std::terminate();
			}
			reached_private_sonames.emplace(soname);
		}
		preflighted.push_back(std::move(component_or).value());
	}
	auto preflight_status = validate_preflighted_provider_component_set(preflighted);
	if (!preflight_status.is_ok()) {
		return preflight_status;
	}
	if (reached_private_sonames.size() != static_cast<std::size_t>(canonical_inventory.private_artifacts_size())) {
		return status::invalid_argument("provider release inventory contains an unreachable private artifact");
	}
	for (const auto &artifact : canonical_inventory.private_artifacts()) {
		if (!reached_private_sonames.contains(artifact.soname())) {
			return status::invalid_argument(
				"provider release inventory contains an unreachable private artifact");
		}
	}
	return reconstructed_provider_inventory{std::move(canonical_inventory), std::move(canonical_or).value(),
						std::move(preflighted)};
}

}  // namespace kinetum::provider
