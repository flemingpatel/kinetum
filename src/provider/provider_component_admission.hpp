// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_component_admission.hpp
 * @brief Shared held-artifact, ELF, and exact component-ABI admission.
 * @author Fleming Patel
 *
 * Native callers pass execution-free proof tokens from the static preflight
 * authority. Admission preloads private dependencies from held descriptors,
 * loads each component from its held descriptor, resolves the sole query
 * symbol, and requires exact descriptor/catalog/inventory agreement.
 *
 * Once the first dlopen attempt begins, any subsequent failure terminates the
 * process. Foreign constructors make recoverable rollback unprovable; callers
 * must preflight the complete required set before invoking admission.
 *
 * @par Thread Safety
 * Proof tokens and an admitted set have one owner. Admission is a startup
 * transaction and must not race another dynamic-loader transaction.
 *
 * @par Performance
 * All operations are cold path. Admitted function pointers are copied into a
 * later sealed catalog; this mechanism is absent from packet-worker call graphs.
 */

#include <cstddef>
#include <string>
#include <vector>

#include "src/common/shared_object.hpp"
#include "src/common/status_or.hpp"
#include "src/provider/provider_component_abi.h"
#include "src/provider/provider_component_preflight.hpp"

namespace kinetum::provider
{

/** One successfully loaded component and its immutable exact descriptor. */
struct admitted_provider_component {
	std::string component_id;					   ///< Exact authenticated component identity.
	common::shared_object image;					   ///< Process-lifetime component code owner.
	const kinetum_provider_component_descriptor *descriptor{nullptr};  ///< Immutable queried descriptor.
};

/**
 * @brief Process-lifetime owner of one admitted component set.
 *
 * Component images are destroyed before private dependency handles by member
 * destruction order. Production keeps this owner alive until every provider
 * instance and runtime generation is gone.
 */
class admitted_provider_component_set {
    public:
	/** @brief Construct an empty set. */
	admitted_provider_component_set() = default;

	/** @brief Disable process-lifetime handle aliasing. */
	admitted_provider_component_set(const admitted_provider_component_set &) = delete;

	/** @brief Disable process-lifetime handle aliasing by assignment. */
	admitted_provider_component_set &operator=(const admitted_provider_component_set &) = delete;

	/** @brief Transfer complete admitted ownership. */
	admitted_provider_component_set(admitted_provider_component_set &&) noexcept = default;

	/** @brief Disable replacement because member-wise order could retire dependencies first. */
	admitted_provider_component_set &operator=(admitted_provider_component_set &&) = delete;

	/** @return Number of component images retained by this admitted set. */
	[[nodiscard]] std::size_t component_count() const noexcept;

	/**
	 * @brief Read one admitted component by sorted compact index.
	 *
	 * @param index Index in `[0, component_count())`.
	 * @return Stable component pointer, or null when out of range.
	 */
	[[nodiscard]] const admitted_provider_component *component_at(std::size_t index) const noexcept;

    private:
	friend common::status_or<admitted_provider_component_set>
		admit_preflighted_provider_components(std::vector<preflighted_provider_component>);

	std::vector<common::shared_object> private_dependencies_;  ///< Loaded before and destroyed after components.
	std::vector<admitted_provider_component> components_;	   ///< Sorted exact component owners.
};

/**
 * @brief Admit one complete preflighted component set atomically.
 *
 * Global component, contract, file, SONAME, and dependency identities are
 * validated before the first load. After the first load attempt, any loader,
 * symbol, query, or descriptor failure terminates rather than pretending that
 * foreign process state rolled back.
 *
 * @param components Complete required preflighted set.
 * @return Process-lifetime admitted owner, or a recoverable complete-set
 *         validation error raised before the first foreign load.
 */
[[nodiscard]] common::status_or<admitted_provider_component_set>
admit_preflighted_provider_components(std::vector<preflighted_provider_component> components);

}  // namespace kinetum::provider
