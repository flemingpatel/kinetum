// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file prepared_config_ownership.hpp
 * @brief Linear ownership token for one exact prepared module configuration.
 * @author Fleming Patel
 *
 * Preparation success is represented by explicit token state, never by pointer
 * non-nullness. A module may validly prepare both a null owner handle and a null
 * packet-config pointer. The move-only token binds that result to one module
 * image, context, and nonzero epoch and optionally owns the exact epoch arena.
 *
 * A live token must be consumed by exact retirement. Destroying or overwriting
 * a live token terminates the process because doing otherwise would silently
 * lose ownership evidence and permit use-after-free or leaked prepared state.
 *
 * @par Thread Safety
 * A token has one owner and is not internally synchronized. Ownership moves
 * through bounded SPSC channels or remains on one coordinator/executor thread.
 *
 * @par Performance
 * This type is cold-path only and is not visible to packet execution.
 */

#include <cstdint>
#include <optional>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"

namespace kinetum::dp::lifecycle
{

/** @brief Borrowed module values produced by one successful prepare callback. */
struct prepared_config_record {
	void *owner_handle{nullptr};	     ///< Module-owned immutable artifact handle.
	const void *packet_config{nullptr};  ///< Exact immutable packet-execution view.
};

/**
 * @brief Move-only ownership of one exact successful prepare result.
 */
class prepared_config_ownership {
    public:
	prepared_config_ownership(const prepared_config_ownership &) = delete;
	prepared_config_ownership &operator=(const prepared_config_ownership &) = delete;
	/**
	 * @brief Transfer exact prepared ownership without duplication.
	 *
	 * @param other Source token emptied by this move.
	 */
	prepared_config_ownership(prepared_config_ownership &&other) noexcept;
	/**
	 * @brief Transfer ownership only into an already empty token.
	 *
	 * @param other Source token emptied by this move.
	 * @return This exact destination token.
	 */
	prepared_config_ownership &operator=(prepared_config_ownership &&other) noexcept;
	/** @brief Destroy an empty token; live ownership is a fatal invariant fault. */
	~prepared_config_ownership();

	/**
	 * @brief Create one live exact prepared token.
	 *
	 * @param module_image_index Exact loaded-module image index.
	 * @param context_index Exact executable context index.
	 * @param epoch Nonzero prepared epoch.
	 * @param record Borrowed module values; both pointers may be null on success.
	 * @param arena Optional matching context/epoch arena whose lifetime joins the token.
	 * @return Live token, or failure without retained prepared ownership.
	 */
	[[nodiscard]] static kinetum::common::status_or<prepared_config_ownership>
	create(uint32_t module_image_index, uint32_t context_index, uint64_t epoch, prepared_config_record record,
	       std::optional<epoch_arena_ownership> arena = std::nullopt);

	/**
	 * @brief Return whether this object currently owns live prepared state.
	 *
	 * @return true until ownership moves or exact retirement consumes it.
	 */
	[[nodiscard]] bool owns_state() const noexcept;

	/**
	 * @brief Return the exact loaded-module image index.
	 *
	 * @return Module-image index, or zero after ownership is consumed.
	 */
	[[nodiscard]] uint32_t module_image_index() const noexcept;

	/**
	 * @brief Return the exact executable context index.
	 *
	 * @return Context index, or zero after ownership is consumed.
	 */
	[[nodiscard]] uint32_t context_index() const noexcept;

	/**
	 * @brief Return the exact nonzero prepared epoch.
	 *
	 * @return Exact epoch, or zero after ownership is consumed.
	 */
	[[nodiscard]] uint64_t epoch() const noexcept;

	/**
	 * @brief Borrow module values after exact identity validation.
	 *
	 * @param module_image_index Expected loaded-module image index.
	 * @param context_index Expected executable context index.
	 * @param epoch Expected nonzero epoch.
	 * @return Borrowed record, or failure while this token retains ownership.
	 */
	[[nodiscard]] kinetum::common::status_or<prepared_config_record>
	borrow_exact(uint32_t module_image_index, uint32_t context_index, uint64_t epoch) const noexcept;

	/**
	 * @brief Consume this token after the matching RETIRE callback has completed.
	 *
	 * Exact mismatch or repeated retirement fails without dropping live
	 * ownership. Success releases the optional arena and makes destruction safe.
	 *
	 * @param module_image_index Expected loaded-module image index.
	 * @param context_index Expected executable context index.
	 * @param epoch Expected nonzero epoch.
	 * @return OK after exact one-time consumption; non-OK otherwise.
	 */
	[[nodiscard]] kinetum::common::status retire_exact(uint32_t module_image_index, uint32_t context_index,
							   uint64_t epoch) noexcept;

	/**
	 * @brief Inspect the optional exact arena without transferring ownership.
	 *
	 * @return Arena pointer, or nullptr when prepare used no arena.
	 */
	[[nodiscard]] const epoch_arena_ownership *arena() const noexcept;

    private:
	/**
	 * @brief Construct one already validated live token.
	 *
	 * @param module_image_index Exact loaded-module image index.
	 * @param context_index Exact executable context index.
	 * @param epoch Exact nonzero prepared epoch.
	 * @param record Borrowed module-produced values.
	 * @param arena Optional matching arena ownership.
	 */
	prepared_config_ownership(uint32_t module_image_index, uint32_t context_index, uint64_t epoch,
				  prepared_config_record record, std::optional<epoch_arena_ownership> arena) noexcept;

	/**
	 * @brief Transfer every ownership field and empty the source token.
	 *
	 * @param other Source token whose ownership moves into this empty token.
	 */
	void move_from_(prepared_config_ownership &other) noexcept;

	uint32_t module_image_index_{0};	      ///< Exact image index while live.
	uint32_t context_index_{0};		      ///< Exact context index while live.
	uint64_t epoch_{0};			      ///< Exact nonzero epoch while live.
	prepared_config_record record_{};	      ///< Borrowed module-produced values.
	std::optional<epoch_arena_ownership> arena_;  ///< Optional exact arena ownership.
	bool owns_state_{false};		      ///< Explicit success/ownership state.
};

}  // namespace kinetum::dp::lifecycle
