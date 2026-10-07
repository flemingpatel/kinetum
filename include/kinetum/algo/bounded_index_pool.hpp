// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file bounded_index_pool.hpp
 * @brief Fixed-capacity owner-local recycling for compact indices.
 * @author Fleming Patel
 *
 * `bounded_index_pool` allocates its complete index array from one explicit
 * memory resource during cold construction. One owner then acquires and
 * releases indices by moving a plain stack cursor; the array never changes
 * size and no allocation or exception path exists after construction.
 *
 * The pool owns index availability only. A caller's slab entry remains the
 * semantic object/occupancy authority and must reject duplicate retirement.
 *
 * @par Thread Safety
 * One thread owns every operation. External synchronization is required before
 * transferring the complete quiescent pool to another owner.
 *
 * @par Performance
 * Construction is O(capacity) and may allocate. Acquisition and release are
 * O(1), allocation-free, lock-free, and nonthrowing.
 */

#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <memory_resource>
#include <stdexcept>
#include <vector>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/** @brief Emit bounded evidence and terminate on contradictory pool release. */
[[noreturn]] inline void terminate_invalid_index_pool_release() noexcept
{
	static constexpr char DIAGNOSTIC[] = "kinetum: bounded_index_pool invalid release\n";
	(void)std::fwrite(DIAGNOSTIC, 1u, sizeof(DIAGNOSTIC) - 1u, stderr);
	(void)std::fflush(stderr);
	std::terminate();
}

}  // namespace detail
/** @endcond */

/** @brief Fixed-capacity single-owner pool of zero-based uint32 indices. */
class bounded_index_pool final {
    public:
	/**
	 * @brief Construct one pool containing every index in `[0, capacity)`.
	 * @param capacity Exact index population; zero creates an exhausted pool.
	 * @param memory_resource Non-null owner of the complete fixed array.
	 * @throws std::invalid_argument when @p memory_resource is null.
	 * @throws std::bad_alloc or std::length_error when fixed storage cannot be constructed.
	 */
	explicit bounded_index_pool(uint32_t capacity, std::pmr::memory_resource *memory_resource)
		: indices_(require_memory_resource_(memory_resource))
		, available_(capacity)
	{
		indices_.resize(capacity);
		for (uint32_t index = 0u; index < capacity; ++index) {
			indices_[index] = capacity - index - 1u;
		}
	}

	/** @brief Reject copying because every available index has one owner. */
	bounded_index_pool(const bounded_index_pool &) = delete;
	/** @brief Reject copy assignment because index availability cannot duplicate. */
	bounded_index_pool &operator=(const bounded_index_pool &) = delete;
	/** @brief Reject moving because consumers retain one stable context-local pool. */
	bounded_index_pool(bounded_index_pool &&) = delete;
	/** @brief Reject move assignment because live index ownership cannot transfer implicitly. */
	bounded_index_pool &operator=(bounded_index_pool &&) = delete;
	/** @brief Destroy one quiescent pool together with its enclosing semantic slab. */
	~bounded_index_pool() = default;

	/**
	 * @brief Acquire one available index without waiting.
	 * @param[out] index Destination changed only on successful acquisition.
	 * @return True after transferring one index; false when exhausted.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool try_acquire(uint32_t &index) noexcept
	{
		if (KINETUM_UNLIKELY(available_ == 0u)) {
			return false;
		}
		--available_;
		index = indices_[available_];
		return true;
	}

	/**
	 * @brief Return one exactly acquired index to the available stack.
	 * @param index Exact live index whose semantic owner has already retired it.
	 *
	 * Out-of-range input or release into an already-full pool is a structural
	 * ownership contradiction and terminates.
	 */
	KINETUM_ALWAYS_INLINE void release(uint32_t index) noexcept
	{
		if (KINETUM_UNLIKELY(static_cast<std::size_t>(index) >= indices_.size() ||
				     static_cast<std::size_t>(available_) >= indices_.size())) {
			detail::terminate_invalid_index_pool_release();
		}
		indices_[available_] = index;
		++available_;
	}

	/** @return Exact fixed index population. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE uint32_t capacity() const noexcept
	{
		return static_cast<uint32_t>(indices_.size());
	}

	/** @return Exact index population currently available to acquire. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE uint32_t available() const noexcept
	{
		return available_;
	}

	/** @return Exact acquired index population. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE uint32_t in_use() const noexcept
	{
		return capacity() - available_;
	}

    private:
	/**
	 * @brief Require one explicit storage authority before vector construction.
	 * @param memory_resource Candidate PMR authority.
	 * @return The exact non-null authority.
	 * @throws std::invalid_argument when @p memory_resource is null.
	 */
	[[nodiscard]] static std::pmr::memory_resource *
	require_memory_resource_(std::pmr::memory_resource *memory_resource)
	{
		if (memory_resource == nullptr) {
			throw std::invalid_argument("bounded_index_pool requires an explicit memory resource");
		}
		return memory_resource;
	}

	std::pmr::vector<uint32_t> indices_;  ///< Fixed reverse-initialized index stack.
	uint32_t available_{0};		      ///< Plain sole-owner stack cursor and available count.
};

}  // namespace kinetum::algo
