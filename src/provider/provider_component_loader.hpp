// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_component_loader.hpp
 * @brief Authenticated installed-provider loader and sealed runtime catalog.
 * @author Fleming Patel
 *
 * The loader consumes one fixed installation layout supplied by an established
 * process-image provenance authority. It authenticates inventory bytes before
 * parsing, binds them to the exact runtime image and generated ABI identity,
 * derives the minimal component set for a sorted required contract set,
 * preflights every artifact before loading, and seals only requested rows.
 *
 * It never scans a directory, accepts a plan-supplied component path, performs
 * suffix matching, tries an alternate component, or invokes a factory or host
 * proof. Production startup may consume it only after separately establishing
 * the fixed process installation and compiled required contract set.
 *
 * @par Thread Safety
 * Construction is single-threaded startup work. A sealed catalog is immutable
 * and safe for concurrent cold-path lookup while its owner remains alive.
 */

#include <cstddef>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

#include "src/common/ed25519.hpp"
#include "src/common/held_file.hpp"
#include "src/common/status_or.hpp"
#include "src/provider/provider_component_admission.hpp"
#include "src/provider/provider_installation.hpp"

namespace kinetum::provider
{

/** One immutable requested implementation row in the sealed catalog. */
struct runtime_provider_implementation {
	std::string_view type_url{};	  ///< Exact requested contract identity.
	std::string_view component_id{};  ///< Exact admitted component identity.
	const kinetum_provider_contract_implementation *implementation{nullptr};  ///< Immutable C ABI row.
};

/**
 * @brief Immutable exact requested provider implementation catalog.
 */
class runtime_provider_catalog {
    public:
	/** @brief Disable loader-handle aliasing. */
	runtime_provider_catalog(const runtime_provider_catalog &) = delete;

	/** @brief Disable loader-handle aliasing by assignment. */
	runtime_provider_catalog &operator=(const runtime_provider_catalog &) = delete;

	/** @brief Transfer the complete sealed catalog. */
	runtime_provider_catalog(runtime_provider_catalog &&) noexcept = default;

	/** @brief Disable replacement to preserve component/dependency retirement order. */
	runtime_provider_catalog &operator=(runtime_provider_catalog &&) = delete;

	/** @return Number of requested implementation rows in this immutable catalog. */
	[[nodiscard]] std::size_t size() const noexcept;

	/**
	 * @brief Read one row by sorted compact index.
	 *
	 * @param index Index in `[0, size())`.
	 * @return Stable row pointer, or null when out of range.
	 */
	[[nodiscard]] const runtime_provider_implementation *at(std::size_t index) const noexcept;

	/**
	 * @brief Find one exact requested contract implementation.
	 *
	 * @param type_url Complete canonical type URL.
	 * @return Stable row pointer, or null for an unrequested/unknown contract.
	 */
	[[nodiscard]] const runtime_provider_implementation *find(std::string_view type_url) const noexcept;

	/** @return Number of component images retained by this catalog. */
	[[nodiscard]] std::size_t component_count() const noexcept;

    private:
	friend common::status_or<runtime_provider_catalog>
	load_installed_provider_catalog(const std::filesystem::path &, const std::filesystem::path &,
					std::span<const std::string_view>, const common::ed25519_public_key &,
					const common::held_file_policy &);

	/**
	 * @brief Construct one completely admitted immutable catalog.
	 * @param admitted Sole component/dependency lifetime owner transferred into the catalog.
	 * @param implementations Sorted requested rows borrowing their code from @p admitted.
	 */
	runtime_provider_catalog(admitted_provider_component_set admitted,
				 std::vector<runtime_provider_implementation> implementations) noexcept;

	admitted_provider_component_set admitted_;			///< Code/dependency lifetime authority.
	std::vector<runtime_provider_implementation> implementations_;	///< Sorted requested rows.
};

/**
 * @brief Authenticate, minimally load, and seal one fixed installed catalog.
 *
 * @param installation_root Exact canonical installation root established by
 *        process-image provenance.
 * @param runtime_image Exact current runtime image path.
 * @param required_type_urls Strictly sorted unique complete contract set.
 * @param trust_anchor Exact release public key.
 * @param file_policy Exact runtime owner/mode/link policy.
 * @return Sealed requested-only catalog, or a pre-load provenance/admission
 *         failure. A failure after foreign loading begins terminates.
 */
[[nodiscard]] common::status_or<runtime_provider_catalog> load_installed_provider_catalog(
	const std::filesystem::path &installation_root, const std::filesystem::path &runtime_image,
	std::span<const std::string_view> required_type_urls, const common::ed25519_public_key &trust_anchor,
	const common::held_file_policy &file_policy);

}  // namespace kinetum::provider
