// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file numa_spsc_ring.hpp
 * @brief Runtime-capacity SPSC ownership in exact prefaulted NUMA memory.
 * @author Fleming Patel
 *
 * This DP-local mechanism composes the public SPSC arithmetic with the exact
 * Linux NUMA-memory owner. The ring control object and complete element extent
 * occupy one prefaulted mapping on the caller-authored node. Construction is
 * cold and fallible; every queue operation is bounded and allocation-free.
 *
 * @par Thread Safety
 * One producer owns push operations and one consumer owns pop operations.
 * Producer/consumer observations retain the shared ring's exact side-specific
 * ownership; in particular, only the consumer may borrow the front value.
 * Destruction requires both owners to be quiescent and the ring to be empty.
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/queue.hpp>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/numa_memory.hpp"

namespace kinetum::dp
{

/**
 * @brief Own one runtime-capacity SPSC ring on an exact NUMA node.
 *
 * @tparam value_type Element type stored in the bounded ring.
 *
 * @par Ownership
 * The owner contains the sole mapping and placement-constructed ring. A value
 * successfully pushed belongs to the ring until one successful pop transfers
 * it to the consumer.
 *
 * @par Thread Safety
 * Exactly one producer may invoke push operations and exactly one consumer may
 * invoke pop operations. Each observation retains the shared SPSC contract's
 * producer/consumer ownership; only the consumer may call peek(). Construction
 * and destruction are externally serialized; destruction requires both owners
 * quiescent and the ring empty.
 *
 * @par Performance
 * Construction performs checked layout, mapping, NUMA binding, and prefault.
 * Push, pop, batch, and observation methods forward directly to the shared
 * SPSC core and allocate nothing.
 */
template <typename value_type>
class numa_spsc_ring final {
	static_assert(std::is_move_constructible_v<value_type>, "NUMA SPSC values must be move-constructible");

    public:
	/**
	 * @brief Allocate and bind one exact empty ring.
	 *
	 * @param capacity Exact power-of-two usable capacity, at least two.
	 * @param numa_node Exact nonnegative host NUMA node.
	 * @return Unique ring owner, or a fail-closed validation/allocation status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<numa_spsc_ring>> create(std::size_t capacity,
										       int32_t numa_node)
	{
		if (numa_node < 0) {
			return common::status::invalid_argument("NUMA SPSC ring requires a nonnegative host node");
		}

		std::size_t element_bytes = 0u;
		try {
			element_bytes = kinetum::algo::spsc_ring_storage_bytes<value_type>(capacity);
		} catch (const std::invalid_argument &) {
			return common::status::invalid_argument(
				"NUMA SPSC ring requires a power-of-two capacity of at least two");
		} catch (const std::length_error &) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "NUMA SPSC ring element extent exceeds the host size domain");
		}

		std::size_t element_offset = 0u;
		if (!round_up_checked_(sizeof(ring_type), alignof(value_type), element_offset) ||
		    element_bytes > std::numeric_limits<std::size_t>::max() - element_offset) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "NUMA SPSC ring combined extent exceeds the host size domain");
		}
		const std::size_t total_bytes = element_offset + element_bytes;
		const std::size_t alignment = std::max({static_cast<std::size_t>(kinetum::algo::CACHE_LINE_SIZE),
							alignof(ring_type), alignof(value_type)});
		auto region_or = numa_memory_region::allocate({
			.usable_bytes = total_bytes,
			.alignment_bytes = alignment,
			.host_numa_node = numa_node,
		});
		if (!region_or.is_ok()) {
			return region_or.error();
		}

		auto region = std::move(region_or).value();
		auto *base = static_cast<std::byte *>(region.data());
		ring_type *ring = nullptr;
		try {
			ring = new (base) ring_type(base + element_offset, element_bytes, capacity);
		} catch (const std::exception &) {
			return common::status::internal_error(
				"NUMA SPSC ring rejected its validated placement storage");
		}

		auto *owner = new (std::nothrow) numa_spsc_ring(std::move(region), ring, capacity, numa_node);
		if (owner == nullptr) {
			ring->~ring_type();
			return common::status::resource_exhausted("NUMA SPSC ring owner allocation failed");
		}
		return std::unique_ptr<numa_spsc_ring>(owner);
	}

	/** @brief Reject copying because ring and mapping ownership are linear. */
	numa_spsc_ring(const numa_spsc_ring &) = delete;
	/** @brief Reject copy assignment because ring ownership cannot be duplicated. */
	numa_spsc_ring &operator=(const numa_spsc_ring &) = delete;
	/** @brief Reject moving so published queue addresses remain stable. */
	numa_spsc_ring(numa_spsc_ring &&) = delete;
	/** @brief Reject move assignment so mapping identity cannot be replaced. */
	numa_spsc_ring &operator=(numa_spsc_ring &&) = delete;

	/** @brief Destroy only an empty quiescent ring, then reclaim its exact mapping. */
	~numa_spsc_ring()
	{
		if (ring_ != nullptr && !ring_->empty()) {
			std::terminate();
		}
		if (ring_ != nullptr) {
			ring_->~ring_type();
			ring_ = nullptr;
		}
	}

	/**
	 * @brief Publish one copied value when capacity remains.
	 *
	 * @param value Value borrowed for this call.
	 * @return true after publication; false when the ring is full.
	 */
	[[nodiscard]] bool try_push(const value_type &value) noexcept(std::is_nothrow_copy_constructible_v<value_type>)
	{
		return ring_->try_push(value);
	}

	/**
	 * @brief Publish one moved value without consuming it when full.
	 *
	 * @param value Value consumed only after capacity is proved.
	 * @return true after publication; false when the ring is full.
	 */
	[[nodiscard]] bool try_push(value_type &&value) noexcept(std::is_nothrow_move_constructible_v<value_type>)
	{
		return ring_->try_push(std::move(value));
	}

	/**
	 * @brief Publish the largest capacity-admitted copied prefix.
	 *
	 * @param items Contiguous input values; nonnull when @p count is nonzero.
	 * @param count Number of available input values.
	 * @return Number of values copied and published, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t push_batch(const value_type *items, std::size_t count) noexcept
		requires std::is_nothrow_copy_constructible_v<value_type>
	{
		return ring_->push_batch(items, count);
	}

	/**
	 * @brief Consume one value into an initialized destination.
	 *
	 * @param[out] out Destination replaced only when an element is available.
	 * @return true after one ownership transfer; false when empty.
	 */
	[[nodiscard]] bool try_pop(value_type &out) noexcept(std::is_nothrow_move_assignable_v<value_type>)
	{
		return ring_->try_pop(out);
	}

	/**
	 * @brief Consume one value into an optional owner.
	 *
	 * @return One consumed value, or an empty optional when empty.
	 */
	[[nodiscard]] std::optional<value_type> try_pop() noexcept(std::is_nothrow_move_constructible_v<value_type>)
	{
		return ring_->try_pop();
	}

	/**
	 * @brief Consume the largest available prefix into initialized storage.
	 *
	 * @param[out] out Contiguous initialized output; nonnull when @p count is nonzero.
	 * @param count Maximum number of values to consume.
	 * @return Number of values transferred, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t pop_batch(value_type *out, std::size_t count) noexcept
		requires std::is_nothrow_move_assignable_v<value_type>
	{
		return ring_->pop_batch(out, count);
	}

	/** @return Consumer-borrowed current front value, or null when empty. */
	[[nodiscard]] const value_type *peek() const noexcept
	{
		return ring_->peek();
	}

	/** @return true when no value is retained. */
	[[nodiscard]] bool empty() const noexcept
	{
		return ring_->empty();
	}

	/** @return true when no additional value can be published. */
	[[nodiscard]] bool full() const noexcept
	{
		return ring_->full();
	}

	/** @return Observational currently unused slots. */
	[[nodiscard]] std::size_t available() const noexcept
	{
		return ring_->available();
	}

	/** @return Observational currently retained values. */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		return ring_->size_approx();
	}

	/** @return Exact construction-time usable capacity. */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return capacity_;
	}

	/** @return Exact proven host NUMA node. */
	[[nodiscard]] int32_t numa_node() const noexcept
	{
		return numa_node_;
	}

    private:
	using ring_type = kinetum::algo::spsc_ring_view<value_type>;  ///< Shared borrowed-storage arithmetic.

	/**
	 * @brief Round one extent up to an exact power-of-two alignment.
	 *
	 * @param value Nonnegative byte extent.
	 * @param alignment Nonzero power-of-two alignment.
	 * @param[out] out Exact rounded extent, unchanged on failure.
	 * @return true when the result is representable.
	 */
	[[nodiscard]] static bool round_up_checked_(std::size_t value, std::size_t alignment, std::size_t &out) noexcept
	{
		if (alignment == 0u || (alignment & (alignment - 1u)) != 0u) {
			return false;
		}
		const std::size_t mask = alignment - 1u;
		if (value > std::numeric_limits<std::size_t>::max() - mask) {
			return false;
		}
		out = (value + mask) & ~mask;
		return true;
	}

	/**
	 * @brief Adopt one placement-constructed empty ring and its exact mapping.
	 *
	 * @param region Sole NUMA mapping owner.
	 * @param ring Placement-constructed ring inside @p region.
	 * @param capacity Exact usable element capacity.
	 * @param numa_node Exact proven host node.
	 */
	numa_spsc_ring(numa_memory_region region, ring_type *ring, std::size_t capacity, int32_t numa_node) noexcept
		: region_(std::move(region))
		, ring_(ring)
		, capacity_(capacity)
		, numa_node_(numa_node)
	{
		if (!region_ || ring_ == nullptr || !ring_->empty() || !region_.host_numa_node().has_value() ||
		    *region_.host_numa_node() != numa_node_) {
			std::terminate();
		}
	}

	numa_memory_region region_;  ///< Sole prefaulted exact-NUMA mapping owner.
	ring_type *ring_{nullptr};   ///< Placement-owned queue arithmetic and element lifetime.
	std::size_t capacity_{0};    ///< Exact usable element population.
	int32_t numa_node_{-1};	     ///< Exact proven host NUMA node.
};

}  // namespace kinetum::dp
