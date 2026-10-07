// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_runtime_admission.hpp
 * @brief Exact compiled-fact projection and installed provider admission.
 * @author Fleming Patel
 *
 * This cold authority projects the sole compiled provider topology into the
 * exact C component ABI, authenticates and loads only its required installed
 * component set, and invokes every COMPONENT-phase host proof exactly once.
 * It does not invoke a provider factory, reserve a native resource, publish a
 * runtime graph, or materialize any provider instance. The later
 * transactional materializer consumes the returned authority directly.
 *
 * The returned object owns all text, payload, array, fact-record, component,
 * and loader-handle storage required by later transactional materialization.
 * No view exposed by the object depends on the caller's topology lifetime.
 *
 * @par Thread Safety
 * Admission is single-threaded startup work. A completed object is immutable
 * and may be read concurrently while its sole owner keeps it alive.
 */

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>

#include "src/common/ed25519.hpp"
#include "src/common/held_file.hpp"
#include "src/common/status_or.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_component_abi.h"
#include "src/provider/provider_component_loader.hpp"

namespace kinetum::provider
{

/** @brief Immutable exact C-ABI facts for one compiled provider instance. */
struct provider_component_instance_facts {
	std::string_view instance_id;		   ///< Stable plan-owned instance identity.
	std::string_view type_url;		   ///< Exact canonical provider contract identity.
	std::string_view canonical_configuration;  ///< Exact canonical payload bytes.
	provider_contract_role role{provider_contract_role::PROCESS_FACILITY};	///< Exact structural role.
	uint32_t instance_index{0};				 ///< Compact role-relative instance index.
	kinetum_provider_compiled_fact_record compiled_facts{};	 ///< Exactly one role-matching fact tree.
};

/**
 * @brief Complete admitted provider availability and compiled C-ABI facts.
 *
 * Component code handles outlive every returned implementation and fact view.
 * Transactional materialization may consume these immutable records but must
 * continue to own factory invocation, dependency lifetime, rollback, and
 * materialization publication.
 */
class admitted_provider_runtime {
    public:
	/** @brief Destroy facts before their retained component-code authority. */
	~admitted_provider_runtime();

	/** @brief Disable aliasing of component and fact ownership. */
	admitted_provider_runtime(const admitted_provider_runtime &) = delete;

	/** @brief Disable aliasing by assignment. */
	admitted_provider_runtime &operator=(const admitted_provider_runtime &) = delete;

	/** @brief Transfer the complete immutable admission result. */
	admitted_provider_runtime(admitted_provider_runtime &&) noexcept;

	/** @brief Disable replacement to preserve exact retirement ordering. */
	admitted_provider_runtime &operator=(admitted_provider_runtime &&) = delete;

	/** @return Sealed requested-only implementation catalog. */
	[[nodiscard]] const runtime_provider_catalog &catalog() const noexcept;

	/**
	 * @brief Resolve one role-relative compiled instance fact tree.
	 *
	 * @param role Exact structural provider role.
	 * @param instance_index Compact index in that role's compiled vector.
	 * @return Stable immutable facts, or null when the pair is out of range.
	 */
	[[nodiscard]] const provider_component_instance_facts *instance_facts(provider_contract_role role,
									      uint32_t instance_index) const noexcept;

	/** @return Complete provider-instance count across all roles. */
	[[nodiscard]] std::size_t instance_count() const noexcept;

    private:
	/** Complete private owner for every C-ABI fact tree and borrowed view. */
	struct fact_storage;

	friend common::status_or<admitted_provider_runtime>
	admit_installed_provider_runtime(const compiled_provider_topology &, const std::filesystem::path &,
					 const std::filesystem::path &, const common::ed25519_public_key &,
					 const common::held_file_policy &);

	/**
	 * @brief Adopt one completely proved fact tree and sealed catalog.
	 * @param facts Complete self-owned C-ABI fact storage.
	 * @param catalog Sealed implementation and component-code authority.
	 */
	admitted_provider_runtime(std::unique_ptr<fact_storage> facts, runtime_provider_catalog catalog) noexcept;

	runtime_provider_catalog catalog_;     ///< Retained component-code and implementation authority.
	std::unique_ptr<fact_storage> facts_;  ///< Self-contained immutable C-ABI fact authority.
};

/**
 * @brief Admit the exact installed provider set required by compiled truth.
 *
 * The operation builds and validates every C-ABI fact tree before foreign code
 * loading, authenticates the fixed inventory through the supplied loader
 * policy, then invokes each distinct COMPONENT-phase provider instance proof
 * exactly once. Proof receipts cannot skip or satisfy any operation here.
 *
 * @par Failure Semantics
 * Projection, schedule, provenance, and preflight failures remain recoverable
 * only while no foreign component load has begun. After the installed loader
 * returns a component-owning catalog, any COMPONENT-phase callback failure or
 * host-side validation failure emits one bounded diagnostic and terminates the
 * process without unwinding or unloading component code.
 *
 * @param topology Sole complete shared compiler result.
 * @param installation_root Exact established installation root.
 * @param runtime_image Exact held-runtime identity path beneath that root.
 * @param trust_anchor Exact release public key.
 * @param file_policy Explicit caller-owned artifact and directory policy.
 * @return Immutable admitted runtime authority, or a fail-closed status only
 *         for a failure proven to precede foreign component loading.
 */
[[nodiscard]] common::status_or<admitted_provider_runtime> admit_installed_provider_runtime(
	const compiled_provider_topology &topology, const std::filesystem::path &installation_root,
	const std::filesystem::path &runtime_image, const common::ed25519_public_key &trust_anchor,
	const common::held_file_policy &file_policy);

}  // namespace kinetum::provider
