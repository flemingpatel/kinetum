// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file compact_index_set.hpp
 * @brief Fixed-universe dense membership for compact runtime identities.
 * @author Fleming Patel
 *
 * `compact_index_set` replaces repeated search through sorted compact-index
 * arrays after a cold compiler has fixed their finite universe. Construction
 * allocates the complete word array once. Cold-path insertion then sets bits
 * without growth, and published readers perform one bounds check and one word
 * test with no allocation, lookup structure, or string identity.
 *
 * @par Thread Safety
 * One cold owner may call insert() before publication. After publication the
 * set is immutable and any number of readers may call contains() concurrently.
 * Concurrent insertion and reading is not supported.
 *
 * @par Performance
 * Construction is O(universe_size / 64) and may allocate. insert() and
 * contains() are O(1); neither allocates.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kinetum::algo
{

/** @brief Fixed-universe dense set for zero-based compact integer identities. */
class compact_index_set final {
    public:
	/** @brief Construct an empty zero-universe set. */
	compact_index_set() = default;

	/**
	 * @brief Construct an empty set over `[0, value_limit)`.
	 *
	 * @param value_limit Exclusive upper bound for every admitted identity.
	 * @throws std::bad_alloc when the complete fixed-universe word array cannot
	 *         be allocated.
	 */
	explicit compact_index_set(std::size_t value_limit)
		: words_(word_count_(value_limit), uint64_t{0})
		, value_limit_(value_limit)
	{
	}

	/**
	 * @brief Insert one identity during cold construction.
	 *
	 * @param value Candidate zero-based identity.
	 * @return True exactly when the value was in range and previously absent.
	 */
	[[nodiscard]] bool insert(std::size_t value) noexcept
	{
		if (value >= value_limit_) {
			return false;
		}
		const std::size_t word_index = value / BITS_PER_WORD;
		const uint64_t mask = uint64_t{1} << (value % BITS_PER_WORD);
		if ((words_[word_index] & mask) != 0) {
			return false;
		}
		words_[word_index] |= mask;
		return true;
	}

	/**
	 * @brief Return whether one identity belongs to the published set.
	 *
	 * This immutable lookup performs one bounds check and one word-mask test.
	 *
	 * @param value Candidate zero-based identity.
	 * @return true exactly when @p value was inserted within the fixed universe.
	 */
	[[nodiscard]] bool contains(std::size_t value) const noexcept
	{
		if (value >= value_limit_) {
			return false;
		}
		const std::size_t word_index = value / BITS_PER_WORD;
		const uint64_t mask = uint64_t{1} << (value % BITS_PER_WORD);
		return (words_[word_index] & mask) != 0;
	}

	/**
	 * @brief Return the exclusive upper bound of the fixed identity universe.
	 *
	 * @return Construction-time exclusive identity bound.
	 */
	[[nodiscard]] std::size_t value_limit() const noexcept
	{
		return value_limit_;
	}

    private:
	static constexpr std::size_t BITS_PER_WORD = 64;  ///< Membership bits represented by one storage word.

	/**
	 * @brief Derive the exact word population without overflowing addition.
	 *
	 * @param value_limit Exclusive identity bound.
	 * @return Exact number of 64-bit words required for @p value_limit bits.
	 */
	[[nodiscard]] static constexpr std::size_t word_count_(std::size_t value_limit) noexcept
	{
		return (value_limit / BITS_PER_WORD) + (value_limit % BITS_PER_WORD != 0 ? 1u : 0u);
	}

	std::vector<uint64_t> words_;  ///< Complete fixed-universe bit storage.
	std::size_t value_limit_{0};   ///< Exclusive admitted identity bound.
};

}  // namespace kinetum::algo
