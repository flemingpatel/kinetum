// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file numa_lifecycle_memory_provider.cpp
 * @brief Bounded lifecycle-memory adapter implementation.
 * @author Fleming Patel
 */

#include "src/dp/lifecycle/numa_lifecycle_memory_provider.hpp"

#include <exception>
#include <limits>
#include <new>
#include <utility>

#include "src/common/status.hpp"

namespace kinetum::dp::lifecycle
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

namespace
{

/**
 * @brief Add two size values without wrapping.
 *
 * @param left First nonnegative value.
 * @param right Second nonnegative value.
 * @param[out] result Exact sum on success.
 * @return true when the sum is representable.
 */
[[nodiscard]] constexpr bool checked_add(std::size_t left, std::size_t right, std::size_t &result) noexcept
{
	if (right > std::numeric_limits<std::size_t>::max() - left) {
		return false;
	}
	result = left + right;
	return true;
}

/**
 * @brief Multiply two size values without wrapping.
 *
 * @param left First nonnegative value.
 * @param right Second nonnegative value.
 * @param[out] result Exact product on success.
 * @return true when the product is representable.
 */
[[nodiscard]] constexpr bool checked_multiply(std::size_t left, std::size_t right, std::size_t &result) noexcept
{
	if (left != 0u && right > std::numeric_limits<std::size_t>::max() / left) {
		return false;
	}
	result = left * right;
	return true;
}

/**
 * @brief Check whether an integer is a valid allocation alignment.
 *
 * @param alignment Candidate byte alignment.
 * @return true for a nonzero power of two.
 */
[[nodiscard]] constexpr bool is_power_of_two(std::size_t alignment) noexcept
{
	return alignment != 0u && (alignment & (alignment - 1u)) == 0u;
}

}  // namespace

status_or<std::unique_ptr<numa_lifecycle_memory_provider>>
numa_lifecycle_memory_provider::create(std::span<const numa_lifecycle_memory_budget> budgets) noexcept
{
	if (budgets.empty()) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "lifecycle NUMA provider requires at least one exact compiled budget"));
	}

	constexpr std::size_t LIVE_BLOCKS_PER_CONTEXT = LIFECYCLE_MAX_LONG_LIVED_ALLOCATIONS +
							LIFECYCLE_MAX_INTERNAL_TELEMETRY_ALLOCATIONS +
							kinetum::common::EXACT_EPOCH_SLOT_COUNT;
	std::size_t maximum_live_blocks = 0;
	int32_t previous_numa_node = -1;
	for (const auto &budget : budgets) {
		if (budget.numa_node < 0 || budget.context_count == 0u || budget.complete_memory_capacity_bytes == 0u) {
			return status(
				status_code::INVALID_ARGUMENT,
				kinetum::common::static_status_text(
					"lifecycle NUMA budgets require nonnegative nodes and nonzero context and byte bounds"));
		}
		if (budget.numa_node <= previous_numa_node) {
			return status(status_code::INVALID_ARGUMENT,
				      kinetum::common::static_status_text(
					      "lifecycle NUMA budgets must be strictly sorted and unique by node"));
		}
		previous_numa_node = budget.numa_node;

		std::size_t budget_live_blocks = 0;
		if (!checked_multiply(static_cast<std::size_t>(budget.context_count), LIVE_BLOCKS_PER_CONTEXT,
				      budget_live_blocks) ||
		    !checked_add(maximum_live_blocks, budget_live_blocks, maximum_live_blocks)) {
			return status(status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "lifecycle NUMA live-block population overflows size_t"));
		}
	}

	std::unique_ptr<live_budget[]> owned_budgets(new (std::nothrow) live_budget[budgets.size()]);
	if (owned_budgets == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      kinetum::common::static_status_text(
				      "lifecycle NUMA provider cannot allocate its fixed budget table"));
	}
	for (std::size_t index = 0; index < budgets.size(); ++index) {
		owned_budgets[index].compiled = budgets[index];
	}

	std::unique_ptr<live_block[]> blocks(new (std::nothrow) live_block[maximum_live_blocks]);
	if (blocks == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      kinetum::common::static_status_text(
				      "lifecycle NUMA provider cannot allocate its fixed ownership table"));
	}
	std::unique_ptr<numa_lifecycle_memory_provider> provider(new (std::nothrow) numa_lifecycle_memory_provider(
		std::move(owned_budgets), budgets.size(), std::move(blocks), maximum_live_blocks));
	if (provider == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      kinetum::common::static_status_text("lifecycle NUMA provider cannot allocate its owner"));
	}
	return provider;
}

numa_lifecycle_memory_provider::numa_lifecycle_memory_provider(std::unique_ptr<live_budget[]> budgets,
							       std::size_t budget_count,
							       std::unique_ptr<live_block[]> blocks,
							       std::size_t maximum_live_blocks) noexcept
	: budgets_(std::move(budgets))
	, budget_count_(budget_count)
	, blocks_(std::move(blocks))
	, maximum_live_blocks_(maximum_live_blocks)
	, first_free_slot_(maximum_live_blocks == 0u ? INVALID_LIVE_BLOCK_INDEX : 0u)
	, free_slot_count_(maximum_live_blocks)
{
	for (std::size_t index = 0; index < maximum_live_blocks_; ++index) {
		blocks_[index].next_free_slot = index + 1u < maximum_live_blocks_ ? index + 1u :
										    INVALID_LIVE_BLOCK_INDEX;
	}
}

numa_lifecycle_memory_provider::~numa_lifecycle_memory_provider()
{
	if (free_slot_count_ != maximum_live_blocks_) {
		std::terminate();
	}
	std::size_t free_index = first_free_slot_;
	for (std::size_t visited = 0; visited < maximum_live_blocks_; ++visited) {
		if (free_index >= maximum_live_blocks_ || blocks_[free_index].state != live_block_state::FREE) {
			std::terminate();
		}
		free_index = blocks_[free_index].next_free_slot;
	}
	if (free_index != INVALID_LIVE_BLOCK_INDEX) {
		std::terminate();
	}
	for (std::size_t index = 0; index < maximum_live_blocks_; ++index) {
		const auto &slot = blocks_[index];
		if (slot.state != live_block_state::FREE || slot.region || slot.size != 0u || slot.alignment != 0u ||
		    slot.budget_index != 0u || slot.allocation_nonce != 0u || slot.numa_node != -1) {
			std::terminate();
		}
	}
	for (std::size_t index = 0; index < budget_count_; ++index) {
		if (budgets_[index].bytes_in_use != 0u) {
			std::terminate();
		}
	}
}

void numa_lifecycle_memory_provider::return_slot_to_free_(std::size_t slot_index) noexcept
{
	if (slot_index >= maximum_live_blocks_ || free_slot_count_ >= maximum_live_blocks_) {
		std::terminate();
	}
	auto &slot = blocks_[slot_index];
	if ((slot.state != live_block_state::ALLOCATING && slot.state != live_block_state::RELEASING) || slot.region ||
	    slot.size == 0u || slot.alignment == 0u || slot.allocation_nonce == 0u || slot.numa_node < 0) {
		std::terminate();
	}
	slot = {};
	slot.next_free_slot = first_free_slot_;
	first_free_slot_ = slot_index;
	++free_slot_count_;
}

status_or<lifecycle_memory_block> numa_lifecycle_memory_provider::allocate(int32_t numa_node, std::size_t size,
									   std::size_t alignment,
									   bool zero_initialize) noexcept
{
	if (numa_node < 0 || size == 0u || !is_power_of_two(alignment)) {
		return status(
			status_code::INVALID_ARGUMENT,
			kinetum::common::static_status_text(
				"lifecycle NUMA allocation requires an exact node, positive size, and power-of-two alignment"));
	}

	std::size_t budget_index = budget_count_;
	std::size_t slot_index = maximum_live_blocks_;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		std::size_t first = 0;
		std::size_t count = budget_count_;
		while (count != 0u) {
			const std::size_t step = count / 2u;
			const std::size_t candidate = first + step;
			if (budgets_[candidate].compiled.numa_node < numa_node) {
				first = candidate + 1u;
				count -= step + 1u;
			} else {
				count = step;
			}
		}
		if (first == budget_count_ || budgets_[first].compiled.numa_node != numa_node) {
			return status(
				status_code::FAILED_PRECONDITION,
				kinetum::common::static_status_text(
					"lifecycle NUMA allocation names a node absent from compiled module budgets"));
		}
		budget_index = first;
		auto &budget = budgets_[budget_index];
		if (budget.bytes_in_use > budget.compiled.complete_memory_capacity_bytes ||
		    size > budget.compiled.complete_memory_capacity_bytes - budget.bytes_in_use) {
			return status(status_code::RESOURCE_EXHAUSTED,
				      kinetum::common::static_status_text(
					      "lifecycle NUMA allocation exceeds its exact compiled node capacity"));
		}

		if (free_slot_count_ == 0u) {
			if (first_free_slot_ != INVALID_LIVE_BLOCK_INDEX) {
				std::terminate();
			}
			return status(status_code::RESOURCE_EXHAUSTED,
				      kinetum::common::static_status_text(
					      "lifecycle NUMA provider exhausted its derived ownership slots"));
		}
		if (first_free_slot_ >= maximum_live_blocks_ ||
		    next_allocation_nonce_ == std::numeric_limits<uint64_t>::max()) {
			if (first_free_slot_ >= maximum_live_blocks_) {
				std::terminate();
			}
			return status(status_code::RESOURCE_EXHAUSTED,
				      kinetum::common::static_status_text(
					      "lifecycle NUMA allocation identity space is exhausted"));
		}
		slot_index = first_free_slot_;

		auto &slot = blocks_[slot_index];
		if (slot.region || slot.size != 0u || slot.alignment != 0u || slot.numa_node != -1 ||
		    slot.budget_index != 0u || slot.allocation_nonce != 0u || slot.state != live_block_state::FREE) {
			std::terminate();
		}
		first_free_slot_ = slot.next_free_slot;
		slot.next_free_slot = INVALID_LIVE_BLOCK_INDEX;
		--free_slot_count_;
		if ((free_slot_count_ == 0u) != (first_free_slot_ == INVALID_LIVE_BLOCK_INDEX)) {
			std::terminate();
		}
		slot.size = size;
		slot.alignment = alignment;
		slot.budget_index = budget_index;
		slot.allocation_nonce = ++next_allocation_nonce_;
		slot.numa_node = numa_node;
		slot.state = live_block_state::ALLOCATING;
		budget.bytes_in_use += size;
	}

	auto region_or = numa_memory_region::allocate({
		.usable_bytes = size,
		.alignment_bytes = alignment,
		.host_numa_node = numa_node,
	});
	if (!region_or.is_ok()) {
		std::lock_guard<std::mutex> lock(mutex_);
		auto &slot = blocks_[slot_index];
		auto &budget = budgets_[budget_index];
		if (slot.state != live_block_state::ALLOCATING || slot.region || slot.size != size ||
		    slot.alignment != alignment || slot.budget_index != budget_index || slot.numa_node != numa_node ||
		    budget.bytes_in_use < size) {
			std::terminate();
		}
		budget.bytes_in_use -= size;
		return_slot_to_free_(slot_index);
		return std::move(region_or).error();
	}
	auto region = std::move(region_or).value();
	if (!region || region.size() != size || !region.host_numa_node().has_value() ||
	    *region.host_numa_node() != numa_node) {
		std::terminate();
	}

	lifecycle_memory_block result{};
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto &slot = blocks_[slot_index];
		if (slot.state != live_block_state::ALLOCATING || slot.region || slot.size != size ||
		    slot.alignment != alignment || slot.budget_index != budget_index || slot.numa_node != numa_node) {
			std::terminate();
		}
		slot.region = std::move(region);
		slot.state = live_block_state::LIVE;
		result = {slot.region.data(),
			  slot.region.size(),
			  alignment,
			  numa_node,
			  {slot_index + 1u, slot.allocation_nonce}};
	}

	// The shared anonymous NUMA mechanism always returns zero-filled,
	// prefaulted storage. That stronger guarantee satisfies both caller modes.
	(void)zero_initialize;
	return result;
}

void numa_lifecycle_memory_provider::release(lifecycle_memory_block block) noexcept
{
	if (block.data == nullptr || block.provider_token.opaque_identity == 0u ||
	    block.provider_token.reuse_nonce == 0u) {
		std::terminate();
	}
	const std::size_t released_slot_index = block.provider_token.opaque_identity - 1u;
	if (released_slot_index >= maximum_live_blocks_) {
		std::terminate();
	}

	numa_memory_region released;
	std::size_t released_budget_index = budget_count_;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto &slot = blocks_[released_slot_index];
		if (slot.state != live_block_state::LIVE || slot.region.data() != block.data || !slot.region ||
		    slot.size != block.size || slot.region.size() != block.size || slot.alignment != block.alignment ||
		    slot.numa_node != block.numa_node || slot.budget_index >= budget_count_ ||
		    slot.allocation_nonce != block.provider_token.reuse_nonce ||
		    slot.next_free_slot != INVALID_LIVE_BLOCK_INDEX || !slot.region.host_numa_node().has_value() ||
		    *slot.region.host_numa_node() != block.numa_node) {
			std::terminate();
		}
		auto &budget = budgets_[slot.budget_index];
		if (budget.compiled.numa_node != block.numa_node || budget.bytes_in_use < block.size) {
			std::terminate();
		}
		released_budget_index = slot.budget_index;
		released = std::move(slot.region);
		slot.state = live_block_state::RELEASING;
	}
	if (!released || released_budget_index >= budget_count_) {
		std::terminate();
	}

	// Reclaim the physical mapping without the ledger mutex. The slot and its
	// byte claim remain reserved until the kernel has completed reclamation.
	released = {};
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto &slot = blocks_[released_slot_index];
		auto &budget = budgets_[released_budget_index];
		if (slot.state != live_block_state::RELEASING || slot.region || slot.size != block.size ||
		    slot.alignment != block.alignment || slot.budget_index != released_budget_index ||
		    slot.numa_node != block.numa_node || budget.compiled.numa_node != block.numa_node ||
		    slot.allocation_nonce != block.provider_token.reuse_nonce ||
		    slot.next_free_slot != INVALID_LIVE_BLOCK_INDEX || budget.bytes_in_use < block.size) {
			std::terminate();
		}
		budget.bytes_in_use -= block.size;
		return_slot_to_free_(released_slot_index);
	}
}

}  // namespace kinetum::dp::lifecycle
