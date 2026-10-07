// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file numa_lifecycle_memory_provider.hpp
 * @brief Bounded lifecycle-memory adapter over the shared NUMA mechanism.
 * @author Fleming Patel
 *
 * The adapter gives lifecycle contexts and epoch arenas their existing
 * allocate/release interface while retaining each mapping in the sole shared
 * `numa_memory_region` implementation. Its bookkeeping is cold-path state;
 * packet workers never include or call this type.
 *
 * @par Thread Safety
 * Lifecycle executor threads may allocate and release concurrently. A mutex
 * protects only the fixed ownership table and is never held while mapping,
 * binding, prefaulting, or unmapping memory.
 */

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <span>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/numa_memory.hpp"

namespace kinetum::dp::lifecycle
{

/** @brief Exact compiled lifecycle-memory authority for one NUMA node. */
struct numa_lifecycle_memory_budget {
	int32_t numa_node{-1};				///< Exact host NUMA identity.
	uint32_t context_count{0};			///< Exact module-context population.
	std::size_t complete_memory_capacity_bytes{0};	///< Context plus all exact epoch-slot arenas.
};

/**
 * @brief Bounded production lifecycle allocator backed by exact NUMA regions.
 *
 * Free-slot acquisition and token-directed release are constant-time under the
 * cold ownership mutex. NUMA-budget selection is logarithmic in the number of
 * compiled NUMA rows. Mapping, binding, prefaulting, and unmapping occur with
 * no ownership mutex held.
 */
class numa_lifecycle_memory_provider final : public lifecycle_memory_provider {
    public:
	/**
	 * @brief Create one provider from exact sorted compiled NUMA budgets.
	 *
	 * The fixed live-block population is derived as `context_count` times the
	 * long-lived allocation ledger plus the shared exact epoch-slot count. No
	 * caller-supplied block count or byte default exists.
	 *
	 * @param budgets Strictly sorted unique nonempty NUMA budget set.
	 * @return Provider, or validation/allocation failure.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<numa_lifecycle_memory_provider>>
	create(std::span<const numa_lifecycle_memory_budget> budgets) noexcept;

	/** @brief Lifecycle-memory providers cannot be copied. */
	numa_lifecycle_memory_provider(const numa_lifecycle_memory_provider &) = delete;
	/** @brief Lifecycle-memory providers cannot be copy-assigned. */
	numa_lifecycle_memory_provider &operator=(const numa_lifecycle_memory_provider &) = delete;
	/** @brief Lifecycle-memory providers cannot be moved. */
	numa_lifecycle_memory_provider(numa_lifecycle_memory_provider &&) = delete;
	/** @brief Lifecycle-memory providers cannot be move-assigned. */
	numa_lifecycle_memory_provider &operator=(numa_lifecycle_memory_provider &&) = delete;
	/**
	 * @brief Destroy a quiescent empty provider.
	 *
	 * All allocate and release calls must have completed. Any retained mapping,
	 * byte claim, or ownership slot is fatal rather than silently reclaimed.
	 */
	~numa_lifecycle_memory_provider() override;

	/** @copydoc lifecycle_memory_provider::allocate */
	[[nodiscard]] kinetum::common::status_or<lifecycle_memory_block>
	allocate(int32_t numa_node, std::size_t size, std::size_t alignment, bool zero_initialize) noexcept override;

	/** @copydoc lifecycle_memory_provider::release */
	void release(lifecycle_memory_block block) noexcept override;

    private:
	/** Invalid intrusive free-list identity and external token index. */
	static constexpr std::size_t INVALID_LIVE_BLOCK_INDEX = std::numeric_limits<std::size_t>::max();

	/** @brief Exact ownership phase for one fixed cold allocation slot. */
	enum class live_block_state : uint8_t {
		FREE = 0,    ///< No byte claim and no mapping ownership.
		ALLOCATING,  ///< Byte claim retained while NUMA mapping completes unlocked.
		LIVE,	     ///< Published lifecycle block owns one complete mapping.
		RELEASING,   ///< Byte claim retained while NUMA unmapping completes unlocked.
	};

	/** @brief One fixed ownership slot in the cold allocation ledger. */
	struct live_block {
		numa_memory_region region;    ///< Sole mapping owner while this slot is occupied.
		std::size_t size{0};	      ///< Exact reserved usable byte count.
		std::size_t alignment{0};     ///< Exact caller-visible alignment contract.
		std::size_t budget_index{0};  ///< Exact owning NUMA budget row.
		std::size_t next_free_slot{INVALID_LIVE_BLOCK_INDEX};  ///< Intrusive free-list successor while FREE.
		uint64_t allocation_nonce{0};			       ///< Nonzero live allocation reuse discriminator.
		int32_t numa_node{-1};				       ///< Exact caller-visible NUMA identity.
		live_block_state state{live_block_state::FREE};	       ///< Exact unlocked-operation ownership phase.
	};

	/** @brief Mutable usage paired with one immutable compiled budget. */
	struct live_budget {
		numa_lifecycle_memory_budget compiled{};  ///< Exact immutable compiled authority.
		std::size_t bytes_in_use{0};		  ///< Reserved plus materialized usable bytes.
	};

	/**
	 * @brief Adopt already allocated fixed budget and block arrays.
	 *
	 * @param budgets Exact sorted budget table.
	 * @param budget_count Number of initialized budget rows.
	 * @param blocks Complete fixed ownership-slot table.
	 * @param maximum_live_blocks Exact physical slot population.
	 */
	numa_lifecycle_memory_provider(std::unique_ptr<live_budget[]> budgets, std::size_t budget_count,
				       std::unique_ptr<live_block[]> blocks, std::size_t maximum_live_blocks) noexcept;

	/**
	 * @brief Return one non-live slot to the intrusive free list.
	 *
	 * The caller holds @ref mutex_ and has already proved that the slot is in
	 * ALLOCATING or RELEASING state with no mapping owner.
	 *
	 * @param slot_index Exact occupied slot to reset and publish as free.
	 */
	void return_slot_to_free_(std::size_t slot_index) noexcept;

	std::unique_ptr<live_budget[]> budgets_;		 ///< Sorted exact NUMA budgets and live usage.
	std::size_t budget_count_{0};				 ///< Number of exact NUMA budget rows.
	std::unique_ptr<live_block[]> blocks_;			 ///< Fixed ownership slots.
	std::size_t maximum_live_blocks_{0};			 ///< Physical slot population.
	std::size_t first_free_slot_{INVALID_LIVE_BLOCK_INDEX};	 ///< Intrusive free-list head.
	std::size_t free_slot_count_{0};			 ///< Exact free-list population.
	uint64_t next_allocation_nonce_{0};			 ///< Last issued nonzero allocation nonce.
	mutable std::mutex mutex_;				 ///< Protects slot ownership only.
};

}  // namespace kinetum::dp::lifecycle
