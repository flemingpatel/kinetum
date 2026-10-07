// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_component_admission.cpp
 * @brief Shared held-artifact, ELF, and exact component-ABI admission.
 * @author Fleming Patel
 */

#include "src/provider/provider_component_admission.hpp"

#include <algorithm>
#include <cstring>
#include <exception>
#include <iterator>
#include <string_view>
#include <unordered_set>
#include <utility>

#include "src/provider/provider_build_identity.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_inventory.hpp"

namespace kinetum::provider
{

/** Private bridge that keeps preflight proof state opaque to ordinary callers. */
class provider_component_admission_access {
    public:
	/**
	 * @brief Return mutable private closure for one proven component.
	 * @param component Preflight proof whose held private artifacts remain owned here.
	 * @return Borrowed mutable dependency closure for admission bookkeeping.
	 */
	[[nodiscard]] static auto &private_dependencies(preflighted_provider_component &component) noexcept
	{
		return component.private_dependencies_;
	}

	/**
	 * @brief Return the held exact component image.
	 * @param component Preflight proof retaining the exact component descriptor.
	 * @return Borrowed held-file owner used during admission.
	 */
	[[nodiscard]] static common::held_file &file(preflighted_provider_component &component) noexcept
	{
		return component.file_;
	}
};

namespace
{

using common::status_or;
using kinetum::provider::v1::ProviderComponentArtifact;

/**
 * @brief Map one pure catalog role to its exact C ABI value.
 *
 * @param role Pure catalog role.
 * @return Exact C ABI role value.
 */
kinetum_provider_role abi_role(provider_contract_role role) noexcept
{
	switch (role) {
	case provider_contract_role::PROCESS_FACILITY:
		return KINETUM_PROVIDER_ROLE_PROCESS_FACILITY;
	case provider_contract_role::IO_DRIVER:
		return KINETUM_PROVIDER_ROLE_IO_DRIVER;
	case provider_contract_role::PACKET_STORAGE:
		return KINETUM_PROVIDER_ROLE_PACKET_STORAGE;
	case provider_contract_role::EXECUTION:
		return KINETUM_PROVIDER_ROLE_EXECUTION;
	case provider_contract_role::STORAGE_TRANSITION:
		return KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION;
	}
	std::terminate();
}

/**
 * @brief Require one foreign ABI text view to equal authenticated text.
 *
 * Length is compared before any foreign byte is read. The authenticated
 * inventory already proves canonical spelling and row order, so admission
 * never performs an unbounded lexical comparison over component-owned memory.
 *
 * @param view Candidate foreign descriptor view.
 * @param expected Authenticated exact text.
 */
void require_descriptor_text_or_terminate(const kinetum_provider_text_view &view, std::string_view expected) noexcept
{
	if (view.padding != 0 || view.size != expected.size() ||
	    (view.size != 0 &&
	     (view.data == nullptr || std::memcmp(view.data, expected.data(), expected.size()) != 0))) {
		std::terminate();
	}
}

/**
 * @brief Return whether a contract requires a component-owned host proof.
 *
 * @param contract Pure contract row.
 * @return true when any exact host requirement names component proof.
 */
bool requires_component_host_proof(const provider_contract_descriptor &contract) noexcept
{
	return std::any_of(contract.host_requirements.begin(), contract.host_requirements.end(),
			   [](const provider_host_requirement &requirement) {
				   return requirement.phase == provider_host_proof_phase::COMPONENT_HOST_PROOF;
			   });
}

/**
 * @brief Validate one queried descriptor against authenticated claims.
 *
 * This runs after foreign code has entered the process. Any disagreement fails
 * stop; it is intentionally not represented as a recoverable status.
 *
 * @param record Authenticated component record.
 * @param descriptor Queried immutable descriptor.
 */
void validate_descriptor_or_terminate(const ProviderComponentArtifact &record,
				      const kinetum_provider_component_descriptor *descriptor) noexcept
{
	if (descriptor == nullptr || descriptor->product_version_major != PROVIDER_PRODUCT_VERSION_MAJOR ||
	    descriptor->product_version_minor != PROVIDER_PRODUCT_VERSION_MINOR ||
	    descriptor->product_version_patch != PROVIDER_PRODUCT_VERSION_PATCH ||
	    std::any_of(std::begin(descriptor->version_padding), std::end(descriptor->version_padding),
			[](uint8_t byte) { return byte != 0; }) ||
	    std::memcmp(descriptor->abi_identity, PROVIDER_ABI_IDENTITY.data(), PROVIDER_ABI_IDENTITY.size()) != 0 ||
	    std::any_of(std::begin(descriptor->tail_padding), std::end(descriptor->tail_padding),
			[](uint8_t byte) { return byte != 0; }) ||
	    descriptor->contract_count != static_cast<uint32_t>(record.contract_type_urls_size()) ||
	    descriptor->contract_count == 0 || descriptor->contracts == nullptr) {
		std::terminate();
	}
	require_descriptor_text_or_terminate(descriptor->component_id, record.component_id());

	for (uint32_t index = 0; index < descriptor->contract_count; ++index) {
		const auto &implementation = descriptor->contracts[index];
		if (std::any_of(std::begin(implementation.padding), std::end(implementation.padding),
				[](uint8_t byte) { return byte != 0; }) ||
		    !kinetum_provider_factories_match_role(&implementation.factories, implementation.role)) {
			std::terminate();
		}
		const std::string_view expected_type_url = record.contract_type_urls(static_cast<int>(index));
		require_descriptor_text_or_terminate(implementation.type_url, expected_type_url);
		const auto *contract = find_provider_contract(expected_type_url);
		if (contract == nullptr || implementation.role != abi_role(contract->role) ||
		    (implementation.host_proof != nullptr) != requires_component_host_proof(*contract)) {
			std::terminate();
		}
	}
}

/** @brief Fail stop after foreign loading has begun. */
[[noreturn]] void terminate_after_foreign_load() noexcept
{
	std::terminate();
}

}  // namespace

std::size_t admitted_provider_component_set::component_count() const noexcept
{
	return components_.size();
}

const admitted_provider_component *admitted_provider_component_set::component_at(std::size_t index) const noexcept
{
	return index < components_.size() ? &components_[index] : nullptr;
}

status_or<admitted_provider_component_set>
admit_preflighted_provider_components(std::vector<preflighted_provider_component> components)
{
	const auto preflight_status = validate_preflighted_provider_component_set(components);
	if (!preflight_status.is_ok()) {
		return preflight_status;
	}
	std::sort(components.begin(), components.end(),
		  [](const preflighted_provider_component &left, const preflighted_provider_component &right) {
			  return left.record().component_id() < right.record().component_id();
		  });

	/** One unique private artifact's exact location in the preflight proofs. */
	struct dependency_location {
		std::size_t component_index;   ///< Sorted component proof index.
		std::size_t dependency_index;  ///< Children-before-parents closure index.
	};
	std::vector<dependency_location> dependency_schedule;
	dependency_schedule.reserve(MAX_PROVIDER_PRIVATE_ARTIFACTS);
	std::unordered_set<std::string_view> scheduled_sonames;
	scheduled_sonames.reserve(MAX_PROVIDER_PRIVATE_ARTIFACTS);
	for (std::size_t component_index = 0; component_index < components.size(); ++component_index) {
		const auto &component = components[component_index];
		for (std::size_t dependency_index = 0; dependency_index < component.private_dependency_count();
		     ++dependency_index) {
			const std::string_view soname = component.private_dependency_soname(dependency_index);
			if (soname.empty()) {
				std::terminate();
			}
			if (scheduled_sonames.insert(soname).second) {
				dependency_schedule.push_back(dependency_location{component_index, dependency_index});
			}
		}
	}

	admitted_provider_component_set admitted;
	admitted.private_dependencies_.reserve(dependency_schedule.size());
	admitted.components_.reserve(components.size());
	for (const auto &component : components) {
		admitted.components_.push_back(
			admitted_provider_component{component.record().component_id(), {}, nullptr});
	}

	// Every host-owned schedule, result row, and ownership vector is allocated
	// before the first foreign load attempt. From this point onward, loader
	// failure, a foreign exception, or an unexpected host exception cannot
	// escape as recoverable state: constructors may already have changed
	// process state.
	try {
		for (const auto &location : dependency_schedule) {
			auto &dependencies = provider_component_admission_access::private_dependencies(
				components[location.component_index]);
			auto &dependency = dependencies[location.dependency_index];
			auto library_or = common::shared_object::open_descriptor(dependency.file.descriptor());
			if (!library_or.is_ok()) {
				terminate_after_foreign_load();
			}
			admitted.private_dependencies_.push_back(std::move(library_or).value());
		}

		for (std::size_t component_index = 0; component_index < components.size(); ++component_index) {
			auto &component = components[component_index];
			auto image_or = common::shared_object::open_descriptor(
				provider_component_admission_access::file(component).descriptor());
			if (!image_or.is_ok()) {
				terminate_after_foreign_load();
			}
			common::shared_object image = std::move(image_or).value();
			auto query_or = image.symbol(KINETUM_PROVIDER_COMPONENT_QUERY_SYMBOL);
			if (!query_or.is_ok()) {
				terminate_after_foreign_load();
			}
			auto query = reinterpret_cast<kinetum_provider_component_query_fn>(query_or.value());
			const kinetum_provider_component_descriptor *descriptor = query();
			validate_descriptor_or_terminate(component.record(), descriptor);
			admitted.components_[component_index].image = std::move(image);
			admitted.components_[component_index].descriptor = descriptor;
		}
		return admitted;
	} catch (...) {
		terminate_after_foreign_load();
	}
}

}  // namespace kinetum::provider
