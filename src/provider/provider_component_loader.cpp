// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_component_loader.cpp
 * @brief Authenticated installed-provider loader and sealed catalog.
 * @author Fleming Patel
 */

#include "src/provider/provider_component_loader.hpp"

#include <algorithm>
#include <exception>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "src/common/status.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_inventory.hpp"

namespace kinetum::provider
{
namespace
{

using common::status;
using common::status_or;
using kinetum::provider::v1::InstalledProviderInventory;
using kinetum::provider::v1::ProviderComponentArtifact;

/**
 * @brief Validate the compiled required contract set.
 *
 * @param required_type_urls Candidate sorted set.
 * @return OK only for nonempty strict order and pure-catalog membership.
 */
status validate_required_contracts(std::span<const std::string_view> required_type_urls)
{
	if (required_type_urls.empty()) {
		return status::invalid_argument("provider loader requires a nonempty compiled contract set");
	}
	for (std::size_t index = 0; index < required_type_urls.size(); ++index) {
		if (find_provider_contract(required_type_urls[index]) == nullptr) {
			return status::invalid_argument(
				"provider loader received a contract absent from the pure catalog");
		}
		if (index != 0 && required_type_urls[index - 1] >= required_type_urls[index]) {
			return status::invalid_argument(
				"provider loader contract set must be strictly sorted and unique");
		}
	}
	return status::ok();
}

/**
 * @brief Select the minimal exact component set for required contracts.
 *
 * @param inventory Authenticated inventory with globally unique ownership.
 * @param required_type_urls Sorted exact required set.
 * @return Sorted component pointers covering the required set exactly.
 */
status_or<std::vector<const ProviderComponentArtifact *>>
select_required_components(const InstalledProviderInventory &inventory,
			   std::span<const std::string_view> required_type_urls)
{
	std::unordered_map<std::string_view, const ProviderComponentArtifact *> owner_by_contract;
	for (const auto &component : inventory.components()) {
		for (const auto &type_url : component.contract_type_urls()) {
			if (!owner_by_contract.emplace(type_url, &component).second) {
				return status::invalid_argument(
					"provider inventory contains duplicate contract ownership");
			}
		}
	}

	std::unordered_set<const ProviderComponentArtifact *> selected_set;
	std::vector<const ProviderComponentArtifact *> selected;
	for (const std::string_view type_url : required_type_urls) {
		const auto owner = owner_by_contract.find(type_url);
		if (owner == owner_by_contract.end()) {
			return status::not_found("required provider contract has no installed component");
		}
		if (selected_set.insert(owner->second).second) {
			selected.push_back(owner->second);
		}
	}
	std::sort(selected.begin(), selected.end(),
		  [](const auto *left, const auto *right) { return left->component_id() < right->component_id(); });
	return selected;
}

}  // namespace

runtime_provider_catalog::runtime_provider_catalog(
	admitted_provider_component_set admitted, std::vector<runtime_provider_implementation> implementations) noexcept
	: admitted_(std::move(admitted))
	, implementations_(std::move(implementations))
{
}

std::size_t runtime_provider_catalog::size() const noexcept
{
	return implementations_.size();
}

const runtime_provider_implementation *runtime_provider_catalog::at(std::size_t index) const noexcept
{
	return index < implementations_.size() ? &implementations_[index] : nullptr;
}

const runtime_provider_implementation *runtime_provider_catalog::find(std::string_view type_url) const noexcept
{
	const auto iterator =
		std::lower_bound(implementations_.begin(), implementations_.end(), type_url,
				 [](const runtime_provider_implementation &implementation, std::string_view requested) {
					 return implementation.type_url < requested;
				 });
	return iterator != implementations_.end() && iterator->type_url == type_url ? &*iterator : nullptr;
}

std::size_t runtime_provider_catalog::component_count() const noexcept
{
	return admitted_.component_count();
}

status_or<runtime_provider_catalog> load_installed_provider_catalog(
	const std::filesystem::path &installation_root, const std::filesystem::path &runtime_image,
	std::span<const std::string_view> required_type_urls, const common::ed25519_public_key &trust_anchor,
	const common::held_file_policy &file_policy)
{
	auto validation = validate_provider_installation_root(installation_root);
	if (!validation.is_ok()) {
		return validation;
	}
	validation = validate_required_contracts(required_type_urls);
	if (!validation.is_ok()) {
		return validation;
	}

	auto runtime_or = common::open_held_regular_file(runtime_image, file_policy);
	if (!runtime_or.is_ok()) {
		return runtime_or.error();
	}
	auto inventory_file_or = common::open_held_regular_file(
		installation_root / std::filesystem::path(std::string(PROVIDER_INVENTORY_RELATIVE_PATH)), file_policy);
	if (!inventory_file_or.is_ok()) {
		return inventory_file_or.error();
	}
	auto signature_file_or = common::open_held_regular_file(
		installation_root / std::filesystem::path(std::string(PROVIDER_INVENTORY_SIGNATURE_RELATIVE_PATH)),
		file_policy);
	if (!signature_file_or.is_ok()) {
		return signature_file_or.error();
	}
	auto inventory_bytes_or = common::read_held_file(inventory_file_or.value(), MAX_PROVIDER_INVENTORY_BYTES);
	if (!inventory_bytes_or.is_ok()) {
		return inventory_bytes_or.error();
	}
	auto signature_bytes_or = common::read_held_file(signature_file_or.value(), common::ED25519_SIGNATURE_SIZE);
	if (!signature_bytes_or.is_ok()) {
		return signature_bytes_or.error();
	}
	auto signature_or = parse_provider_inventory_signature(signature_bytes_or.value());
	if (!signature_or.is_ok()) {
		return signature_or.error();
	}
	auto inventory_or =
		authenticate_provider_inventory(inventory_bytes_or.value(), signature_or.value(), trust_anchor);
	if (!inventory_or.is_ok()) {
		return inventory_or.error();
	}
	validation = validate_provider_inventory_runtime_binding(inventory_or->inventory, runtime_or.value());
	if (!validation.is_ok()) {
		return validation;
	}

	auto selected_or = select_required_components(inventory_or->inventory, required_type_urls);
	if (!selected_or.is_ok()) {
		return selected_or.error();
	}
	std::vector<preflighted_provider_component> preflighted;
	preflighted.reserve(selected_or->size());
	const auto artifact_directory =
		installation_root / std::filesystem::path(std::string(PROVIDER_ARTIFACT_DIRECTORY));
	for (const auto *component : selected_or.value()) {
		auto component_or = preflight_provider_component(artifact_directory, *component,
								 inventory_or->inventory.private_artifacts(),
								 native_provider_target_tuple(), file_policy);
		if (!component_or.is_ok()) {
			return component_or.error();
		}
		preflighted.push_back(std::move(component_or).value());
	}

	std::vector<runtime_provider_implementation> implementations;
	implementations.reserve(required_type_urls.size());
	auto admitted_or = admit_preflighted_provider_components(std::move(preflighted));
	if (!admitted_or.is_ok()) {
		return admitted_or.error();
	}

	// Admission has executed foreign constructors. Capacity was reserved before
	// that boundary; any later exception is a process fault, never a recoverable
	// catalog-construction error.
	try {
		admitted_provider_component_set admitted = std::move(admitted_or).value();
		for (std::size_t component_index = 0; component_index < admitted.component_count(); ++component_index) {
			const auto *component = admitted.component_at(component_index);
			if (component == nullptr || component->descriptor == nullptr) {
				std::terminate();
			}
			for (uint32_t row_index = 0; row_index < component->descriptor->contract_count; ++row_index) {
				const auto *row = &component->descriptor->contracts[row_index];
				const std::string_view type_url(row->type_url.data, row->type_url.size);
				if (std::binary_search(required_type_urls.begin(), required_type_urls.end(),
						       type_url)) {
					implementations.push_back(runtime_provider_implementation{
						type_url, component->component_id, row});
				}
			}
		}
		std::sort(implementations.begin(), implementations.end(),
			  [](const auto &left, const auto &right) { return left.type_url < right.type_url; });
		if (implementations.size() != required_type_urls.size()) {
			std::terminate();
		}
		for (std::size_t index = 0; index < implementations.size(); ++index) {
			if (implementations[index].type_url != required_type_urls[index]) {
				std::terminate();
			}
		}
		return runtime_provider_catalog(std::move(admitted), std::move(implementations));
	} catch (...) {
		std::terminate();
	}
}

}  // namespace kinetum::provider
