// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file work_queue_indices.hpp
 * @brief Internal single-owner circular sequence arithmetic.
 * @author Fleming Patel
 *
 * Queue and timestamp-history owners share this index state. The caller owns
 * element lifetimes and proves capacity and live-prefix bounds before commits.
 */

#include <cstddef>
#include <exception>
#include <limits>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/** @brief Shared power-of-two head/tail arithmetic for every work-queue owner. */
class work_queue_indices final {
    public:
	/**
	 * @param capacity Candidate exact usable slot population.
	 * @return Whether it fits the power-of-two modular sequence domain.
	 */
	[[nodiscard]] static constexpr bool valid_capacity(std::size_t capacity) noexcept
	{
		return capacity >= 2u && (capacity & (capacity - 1u)) == 0u && capacity <= COUNTER_HALF_RANGE;
	}

	/**
	 * @brief Construct one empty exact-capacity sequence owner.
	 * @param capacity Power-of-two usable capacity in the modular half range.
	 */
	explicit work_queue_indices(std::size_t capacity) noexcept
		: capacity_(capacity)
		, mask_(capacity - 1u)
	{
		if (!valid_capacity(capacity_)) {
			std::terminate();
		}
	}

	/** @return true when no sequence is live. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool empty() const noexcept
	{
		return head_ == tail_;
	}
	/** @return true when every exact usable slot is live. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool full() const noexcept
	{
		return size() >= capacity_;
	}
	/** @return Exact current live sequence count. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE std::size_t size() const noexcept
	{
		return head_ - tail_;
	}
	/** @return Exact construction-time usable capacity. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE std::size_t capacity() const noexcept
	{
		return capacity_;
	}
	/** @return Storage ordinal for the next publication. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE std::size_t producer_slot() const noexcept
	{
		return head_ & mask_;
	}
	/**
	 * @param offset Ordinal relative to the consumer; the caller bounds any ensuing element access.
	 * @return Storage slot for that FIFO element; zero selects the next consumption.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE std::size_t consumer_slot(std::size_t offset = 0u) const noexcept
	{
		return (tail_ + offset) & mask_;
	}
	/** @brief Commit one already-constructed publication. */
	KINETUM_ALWAYS_INLINE void commit_push() noexcept
	{
		++head_;
	}
	/**
	 * @brief Commit an already-consumed FIFO prefix.
	 * @param count Number of live values whose ownership has been transferred.
	 */
	KINETUM_ALWAYS_INLINE void commit_pop(std::size_t count = 1u) noexcept
	{
		tail_ += count;
	}
	/** @brief Reset a proven-empty sequence owner to its canonical state. */
	void reset_empty() noexcept
	{
		if (!empty()) {
			std::terminate();
		}
		head_ = 0u;
		tail_ = 0u;
	}

    private:
	static constexpr std::size_t COUNTER_HALF_RANGE =
		std::numeric_limits<std::size_t>::max() / 2u;  ///< Largest unambiguous modular capacity.
	std::size_t capacity_{0};			       ///< Exact usable slot population.
	std::size_t mask_{0};				       ///< Capacity-minus-one slot mask.
	std::size_t head_{0};				       ///< Next owner publication sequence.
	std::size_t tail_{0};				       ///< Next owner consumption sequence.
};

}  // namespace detail
/** @endcond */

}  // namespace kinetum::algo
