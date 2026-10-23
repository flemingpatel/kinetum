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
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <utility>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/queue.hpp>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/numa_layout.hpp"

namespace kinetum::dp
{

/**
 * @brief Own one runtime-capacity SPSC ring on an exact NUMA node.
 *
 * @tparam value_type Element type stored in the bounded ring.
 *
 * @par Ownership
 * The cold owner retains the mapping outside the placement-constructed ring.
 * A value successfully pushed belongs to the ring until one successful pop
 * transfers it to the consumer.
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
	[[nodiscard]] static common::status_or<numa_owner<numa_spsc_ring>> create(std::size_t capacity,
										  int32_t numa_node)
	{
		if (numa_node < 0) {
			return common::status::invalid_argument("NUMA SPSC ring requires a nonnegative host node");
		}

		auto bytes_or = required_element_bytes(capacity);
		if (!bytes_or.is_ok()) {
			return bytes_or.error();
		}
		numa_layout layout;
		std::size_t root_offset = 0u;
		std::size_t element_offset = 0u;
		if (!layout.append<numa_spsc_ring>(1u, root_offset) ||
		    !layout.append<std::byte>(bytes_or.value(), element_offset,
					      std::max(alignof(value_type), std::size_t{algo::CACHE_LINE_SIZE}))) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "NUMA SPSC ring combined extent exceeds the host size domain");
		}
		auto region_or = layout.allocate(numa_node);
		if (!region_or.is_ok()) {
			return region_or.error();
		}
		auto region = std::move(region_or).value();
		auto elements = numa_layout::storage<std::byte>(region, element_offset, bytes_or.value());
		auto *root = new (numa_layout::storage<numa_spsc_ring>(region, root_offset).data())
			numa_spsc_ring(region, elements, capacity);
		return adopt_numa_owner(root, std::move(region));
	}

	/**
	 * @brief Validate capacity through the sole SPSC arithmetic and size its elements.
	 * @param capacity Exact usable population.
	 * @return Complete element bytes or shape/overflow rejection before allocation.
	 */
	[[nodiscard]] static common::status_or<std::size_t> required_element_bytes(std::size_t capacity)
	{
		try {
			return algo::spsc_ring_storage_bytes<value_type>(capacity);
		} catch (const std::invalid_argument &) {
			return common::status::invalid_argument(
				"NUMA SPSC ring requires a power-of-two capacity of at least two");
		} catch (const std::length_error &) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "NUMA SPSC ring element extent exceeds the host size domain");
		}
	}

	/**
	 * @brief Construct a ring inside an already proved owning layout.
	 *
	 * Both this object and its disjoint element storage must lie in region.
	 * The caller retains that mapping through empty-ring destruction. This
	 * permits an owning hold to embed the core without a second allocation.
	 *
	 * @param region Bound, prefaulted exact-node mapping.
	 * @param elements Exact aligned element extent from the checked layout.
	 * @param capacity Previously validated usable element count.
	 */
	numa_spsc_ring(const numa_memory_region &region, std::span<std::byte> elements, std::size_t capacity) noexcept
		: ring_(validated_elements_(region, this, elements), elements.size(), capacity)
		, numa_node_(*region.host_numa_node())
	{
	}

	/** @brief Reject copying because ring and mapping ownership are linear. */
	numa_spsc_ring(const numa_spsc_ring &) = delete;
	/** @brief Reject copy assignment because ring ownership cannot be duplicated. */
	numa_spsc_ring &operator=(const numa_spsc_ring &) = delete;
	/** @brief Reject moving so published queue addresses remain stable. */
	numa_spsc_ring(numa_spsc_ring &&) = delete;
	/** @brief Reject move assignment so mapping identity cannot be replaced. */
	numa_spsc_ring &operator=(numa_spsc_ring &&) = delete;

	/** @brief Destroy only an empty quiescent ring while the cold owner retains its mapping. */
	~numa_spsc_ring()
	{
		if (!ring_.empty()) {
			std::terminate();
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
		return ring_.try_push(value);
	}

	/**
	 * @brief Publish one moved value without consuming it when full.
	 *
	 * @param value Value consumed only after capacity is proved.
	 * @return true after publication; false when the ring is full.
	 */
	[[nodiscard]] bool try_push(value_type &&value) noexcept(std::is_nothrow_move_constructible_v<value_type>)
	{
		return ring_.try_push(std::move(value));
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
		return ring_.push_batch(items, count);
	}

	/**
	 * @brief Consume one value into an initialized destination.
	 *
	 * @param[out] out Destination replaced only when an element is available.
	 * @return true after one ownership transfer; false when empty.
	 */
	[[nodiscard]] bool try_pop(value_type &out) noexcept(std::is_nothrow_move_assignable_v<value_type>)
	{
		return ring_.try_pop(out);
	}

	/**
	 * @brief Consume one value into an optional owner.
	 *
	 * @return One consumed value, or an empty optional when empty.
	 */
	[[nodiscard]] std::optional<value_type> try_pop() noexcept(std::is_nothrow_move_constructible_v<value_type>)
	{
		return ring_.try_pop();
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
		return ring_.pop_batch(out, count);
	}

	/**
	 * @brief Consume a locally admitted FIFO prefix through the shared SPSC core.
	 * @tparam accept_type Nonthrowing owner callback over a read-only value borrow.
	 * @param count Maximum number considered; zero invokes nothing.
	 * @param accept Completes local ownership before returning true. False retains
	 *        the head and suffix. No borrow escape, reentry, or foreign callback.
	 * @return Accepted prefix length, published once after element retirement.
	 */
	template <typename accept_type>
	[[nodiscard]] std::size_t consume_prefix(std::size_t count, accept_type &&accept) noexcept
		requires(std::is_nothrow_invocable_r_v<bool, accept_type &, const value_type &> &&
			 std::is_nothrow_destructible_v<value_type>)
	{
		return ring_.consume_prefix(count, std::forward<accept_type>(accept));
	}

	/** @return Consumer-borrowed current front value, or null when empty. */
	[[nodiscard]] const value_type *peek() const noexcept
	{
		return ring_.peek();
	}

	/** @return true when no value is retained. */
	[[nodiscard]] bool empty() const noexcept
	{
		return ring_.empty();
	}

	/** @return true when no additional value can be published. */
	[[nodiscard]] bool full() const noexcept
	{
		return ring_.full();
	}

	/** @return Observational currently unused slots. */
	[[nodiscard]] std::size_t available() const noexcept
	{
		return ring_.available();
	}

	/** @return Observational currently retained values. */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		return ring_.size_approx();
	}

	/** @return Exact construction-time usable capacity. */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return ring_.capacity();
	}

	/** @return Exact proven host NUMA node. */
	[[nodiscard]] int32_t numa_node() const noexcept
	{
		return numa_node_;
	}

    private:
	using ring_type = kinetum::algo::spsc_ring_view<value_type>;  ///< Shared borrowed-storage arithmetic.

	/**
	 * @brief Prove both control and element placement before binding queue arithmetic.
	 * @param region Live exact-node backing.
	 * @param root Placement address of this complete ring.
	 * @param elements Disjoint element extent.
	 * @return Element address, or termination for contradictory construction.
	 */
	[[nodiscard]] static void *validated_elements_(const numa_memory_region &region, const numa_spsc_ring *root,
						       std::span<std::byte> elements) noexcept
	{
		if (!region.host_numa_node().has_value() || !numa_layout::contains(region, root) ||
		    !numa_layout::contains_extent(region, elements) ||
		    !numa_layout::disjoint({reinterpret_cast<const std::byte *>(root), sizeof(*root)}, elements)) {
			std::terminate();
		}
		return elements.data();
	}

	ring_type ring_;	 ///< Shared queue arithmetic inside the proved mapping.
	int32_t numa_node_{-1};	 ///< Immutable exact proven host NUMA node.
};

}  // namespace kinetum::dp
