// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file aligned_atomic.hpp
 * @brief Cache-line-isolated lock-free integral atomics.
 * @author Fleming Patel
 *
 * `aligned_atomic` gives each independently written counter or gauge its own
 * cache line. The wrapper preserves caller-selected ordering for the required
 * load, store, add, and exchange operations and adds explicit relaxed
 * operations for owner-local telemetry.
 * Cold relocation samples the source without changing it so standard
 * containers can relocate unpublished counter arrays.
 *
 * @par Thread Safety
 * Atomic operations are safe for concurrent callers. Move construction and
 * move assignment require exclusive cold-path ownership and must finish before
 * the source or destination is published to another thread.
 *
 * @par Performance
 * Every published-state access is one lock-free atomic operation. Cold move
 * construction performs one relaxed load; cold move assignment performs one
 * relaxed load and one relaxed store. No method allocates, locks, throws,
 * formats, or invokes the operating system.
 */

#include <atomic>
#include <cstdint>
#include <type_traits>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

/**
 * @brief One integral atomic isolated on its own cache line.
 *
 * @tparam value_type Integral, non-boolean, always-lock-free atomic value type.
 */
template <typename value_type>
class alignas(CACHE_LINE_SIZE) aligned_atomic final {
	static_assert(std::is_integral_v<value_type> && !std::is_same_v<value_type, bool>,
		      "aligned_atomic requires a non-boolean integral type");
	static_assert(std::atomic<value_type>::is_always_lock_free,
		      "aligned_atomic requires an always-lock-free target atomic");
	static_assert(sizeof(std::atomic<value_type>) <= CACHE_LINE_SIZE,
		      "aligned_atomic value must fit within one cache line");

    public:
	/** @brief Construct a zero-valued atomic. */
	aligned_atomic() noexcept = default;

	/**
	 * @brief Construct an atomic with one exact initial value.
	 *
	 * @param initial_value Value visible before publication.
	 */
	explicit aligned_atomic(value_type initial_value) noexcept
		: value_(initial_value)
	{
	}

	/**
	 * @brief Relocate an unpublished atomic by sampling its current value.
	 *
	 * The source remains valid and unchanged. Both objects require exclusive
	 * cold-path ownership during this operation.
	 *
	 * @param other Unpublished source sampled with relaxed ordering.
	 */
	aligned_atomic(aligned_atomic &&other) noexcept
		: value_(other.value_.load(std::memory_order_relaxed))
	{
	}

	/**
	 * @brief Replace this unpublished atomic from another cold-owned value.
	 *
	 * The source remains valid and unchanged.
	 *
	 * @param other Unpublished source sampled with relaxed ordering.
	 * @return This object.
	 */
	aligned_atomic &operator=(aligned_atomic &&other) noexcept
	{
		if (this != &other) {
			value_.store(other.value_.load(std::memory_order_relaxed), std::memory_order_relaxed);
		}
		return *this;
	}

	/** @brief Atomic cache-line owners cannot be copied. */
	aligned_atomic(const aligned_atomic &) = delete;
	/** @brief Atomic cache-line owners cannot be copy-assigned. */
	aligned_atomic &operator=(const aligned_atomic &) = delete;

	/**
	 * @brief Load with the caller-selected memory ordering.
	 *
	 * @param order Atomic load ordering.
	 * @return Exact observed integral value.
	 */
	[[nodiscard]] value_type load(std::memory_order order = std::memory_order_seq_cst) const noexcept
	{
		return value_.load(order);
	}

	/**
	 * @brief Store with the caller-selected memory ordering.
	 *
	 * @param desired Exact replacement value.
	 * @param order Atomic store ordering.
	 */
	void store(value_type desired, std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		value_.store(desired, order);
	}

	/**
	 * @brief Add one value and return the value preceding the addition.
	 *
	 * @param increment Integral delta to add modulo the value type.
	 * @param order Atomic read-modify-write ordering.
	 * @return Value immediately preceding this addition.
	 */
	value_type fetch_add(value_type increment, std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		return value_.fetch_add(increment, order);
	}

	/**
	 * @brief Replace the value and return the preceding value.
	 *
	 * @param desired Exact replacement value.
	 * @param order Atomic read-modify-write ordering.
	 * @return Value immediately preceding this exchange.
	 */
	value_type exchange(value_type desired, std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		return value_.exchange(desired, order);
	}

	/**
	 * @brief Load a counter observation without ordering unrelated memory.
	 *
	 * @return Exact relaxed observation.
	 */
	[[nodiscard]] value_type load_relaxed() const noexcept
	{
		return value_.load(std::memory_order_relaxed);
	}

	/**
	 * @brief Store a counter observation without ordering unrelated memory.
	 *
	 * @param desired Exact replacement observation.
	 */
	void store_relaxed(value_type desired) noexcept
	{
		value_.store(desired, std::memory_order_relaxed);
	}

	/**
	 * @brief Add one counter delta without ordering unrelated memory.
	 *
	 * @param increment Integral counter delta.
	 * @return Value immediately preceding this relaxed addition.
	 */
	value_type fetch_add_relaxed(value_type increment) noexcept
	{
		return value_.fetch_add(increment, std::memory_order_relaxed);
	}

	/** @brief Increment the counter once without ordering unrelated memory. */
	void inc_relaxed() noexcept
	{
		value_.fetch_add(value_type{1}, std::memory_order_relaxed);
	}

    private:
	std::atomic<value_type> value_{value_type{0}};	///< Sole atomic value authority.
};

static_assert(sizeof(aligned_atomic<uint64_t>) == CACHE_LINE_SIZE,
	      "a canonical 64-bit aligned atomic must occupy exactly one cache line");

}  // namespace kinetum::algo
