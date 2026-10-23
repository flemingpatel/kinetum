// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file compact_index_set.hpp
 * @brief Fixed-universe dense membership for compact runtime identities.
 * @author Fleming Patel
 *
 * Owning and caller-storage forms replace repeated search through sorted
 * compact-index arrays after a cold compiler has fixed their finite universe.
 * Both use one word/index mechanism. Cold-path insertion then sets bits
 * without growth, and published readers perform one bounds check and one word
 * test with no allocation, lookup structure, or string identity.
 *
 * @par Thread Safety
 * One cold owner may call insert() before publication. After publication the
 * set is immutable and any number of readers may call contains() concurrently.
 * Concurrent insertion and reading is not supported.
 *
 * @par Performance
 * Construction is O(universe_size / 64). The owning form allocates once;
 * the view borrows exact caller storage. insert() and contains() are O(1)
 * and allocate nothing.
 */

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace kinetum::algo
{

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/** @brief Sole fixed-universe membership arithmetic for owning and borrowed sets. */
struct compact_index_set_core {
	static constexpr std::size_t BITS_PER_WORD = 64u;  ///< Exact bits in one storage word.

	/** @param limit Exclusive identity bound. @return Exact word population without overflowing addition. */
	[[nodiscard]] static constexpr std::size_t word_count(std::size_t limit) noexcept
	{
		return limit / BITS_PER_WORD + (limit % BITS_PER_WORD != 0u ? 1u : 0u);
	}

	/**
	 * @brief Insert one in-range identity into prevalidated word storage.
	 * @param words Exact zero-initialized storage for the fixed universe.
	 * @param limit Exclusive identity bound.
	 * @param value Identity to insert.
	 * @return True only for one previously absent in-range identity.
	 */
	[[nodiscard]] static bool insert(uint64_t *words, std::size_t limit, std::size_t value) noexcept
	{
		if (value >= limit) {
			return false;
		}
		const std::size_t index = value / BITS_PER_WORD;
		const uint64_t mask = uint64_t{1} << (value % BITS_PER_WORD);
		if ((words[index] & mask) != 0u) {
			return false;
		}
		words[index] |= mask;
		return true;
	}

	/**
	 * @param words Exact immutable word storage for the published universe.
	 * @param limit Exclusive identity bound.
	 * @param value Candidate identity.
	 * @return Whether that in-range identity is present.
	 */
	[[nodiscard]] static bool contains(const uint64_t *words, std::size_t limit, std::size_t value) noexcept
	{
		return value < limit && (words[value / BITS_PER_WORD] & (uint64_t{1} << (value % BITS_PER_WORD))) != 0u;
	}
};

}  // namespace detail
/** @endcond */

/**
 * @brief Fixed-universe membership over exact caller-owned words.
 *
 * Construction clears the complete extent. Storage outlives the view and all
 * readers; only the cold owner inserts, before immutable publication.
 */
class compact_index_set_view final {
    public:
	/** @brief Construct an empty zero-universe view without backing storage. */
	compact_index_set_view() noexcept = default;

	/**
	 * @brief Bind and clear the exact word extent for one fixed universe.
	 * @param words Caller-owned words, exactly storage_word_count(value_limit) elements.
	 * @param value_limit Exclusive admitted identity bound.
	 * @throws std::invalid_argument when the supplied extent disagrees with the universe.
	 */
	compact_index_set_view(std::span<uint64_t> words, std::size_t value_limit)
		: words_(words.data())
		, value_limit_(value_limit)
	{
		if (words.size() != storage_word_count(value_limit)) {
			throw std::invalid_argument("compact_index_set_view requires an exact word extent");
		}
		std::fill(words.begin(), words.end(), uint64_t{0});
	}

	/** @param value_limit Exclusive identity bound. @return Exact required caller word population. */
	[[nodiscard]] static constexpr std::size_t storage_word_count(std::size_t value_limit) noexcept
	{
		return detail::compact_index_set_core::word_count(value_limit);
	}
	/** @param value Cold candidate identity. @return True only for a new in-range member. */
	[[nodiscard]] bool insert(std::size_t value) noexcept
	{
		return detail::compact_index_set_core::insert(words_, value_limit_, value);
	}
	/** @param value Candidate identity. @return Whether that identity belongs to this immutable view. */
	[[nodiscard]] bool contains(std::size_t value) const noexcept
	{
		return detail::compact_index_set_core::contains(words_, value_limit_, value);
	}
	/** @return Exact exclusive identity bound, independent of padding bits in the final word. */
	[[nodiscard]] std::size_t value_limit() const noexcept
	{
		return value_limit_;
	}

    private:
	uint64_t *words_{nullptr};     ///< Borrowed complete word extent; immutable after publication.
	std::size_t value_limit_{0u};  ///< Exact exclusive universe bound.
};

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
		: words_(detail::compact_index_set_core::word_count(value_limit), uint64_t{0})
		, value_limit_(value_limit)
	{
	}

	/** @brief Copy the complete universe and its independent membership storage. */
	compact_index_set(const compact_index_set &) = default;
	/** @brief Replace this universe with an independent copy. @return This destination. */
	compact_index_set &operator=(const compact_index_set &) = default;

	/**
	 * @brief Transfer membership and leave the source as an empty zero-universe set.
	 * @param other Source whose storage and identity bound move together.
	 */
	compact_index_set(compact_index_set &&other) noexcept
		: words_(std::move(other.words_))
		, value_limit_(std::exchange(other.value_limit_, 0u))
	{
	}

	/**
	 * @brief Transfer the complete universe, preserving a valid empty source.
	 * @param other Source to empty, or this object for an unchanged self-transfer.
	 * @return This destination with the transferred membership.
	 */
	compact_index_set &operator=(compact_index_set &&other) noexcept
	{
		if (this != &other) {
			words_ = std::move(other.words_);
			value_limit_ = std::exchange(other.value_limit_, 0u);
		}
		return *this;
	}

	/**
	 * @brief Insert one identity during cold construction.
	 *
	 * @param value Candidate zero-based identity.
	 * @return True exactly when the value was in range and previously absent.
	 */
	[[nodiscard]] bool insert(std::size_t value) noexcept
	{
		return detail::compact_index_set_core::insert(words_.data(), value_limit_, value);
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
		return detail::compact_index_set_core::contains(words_.data(), value_limit_, value);
	}

	/**
	 * @brief Return the exclusive upper bound of the fixed identity universe.
	 *
	 * @return Exact exclusive identity bound of the current universe.
	 */
	[[nodiscard]] std::size_t value_limit() const noexcept
	{
		return value_limit_;
	}

    private:
	std::vector<uint64_t> words_;  ///< Complete fixed-universe bit storage.
	std::size_t value_limit_{0};   ///< Exclusive admitted identity bound.
};

}  // namespace kinetum::algo
