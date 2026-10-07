// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file atomic_index_pool.hpp
 * @brief Fixed concurrent index ownership with independent atomic-bit retirement.
 * @author Fleming Patel
 *
 * Availability belongs to one bit per index. Returning an index never waits
 * for an unrelated queue consumer to publish a recycled cell. The caller owns
 * each leased object's lifetime and must retire it before release().
 */

#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

/**
 * @brief Concurrent fixed-universe pool with bounded acquisition attempts.
 * @tparam Capacity Positive index population representable by uint32_t.
 *
 * @par Thread Safety
 * Concurrent acquire/release is permitted. Each successful acquisition has
 * one exact release; all callers must retire before pool destruction. Release
 * publishes completed object access to the next acquiring owner.
 *
 * @par Performance
 * Acquisition visits at most ceil(Capacity/64) cache-line-separated words and
 * attempts one CAS per nonempty word. Contention may reject an attempt even
 * when an index remains available. Release performs one atomic RMW and never
 * waits for another index. No operation allocates or calls foreign code.
 */
template <std::size_t Capacity>
class atomic_index_pool final {
	static_assert(Capacity > 0 && Capacity <= std::numeric_limits<uint32_t>::max());
	static_assert(std::atomic<uint64_t>::is_always_lock_free);

    public:
	/** @brief Publish exactly the declared index population as available. */
	atomic_index_pool() noexcept
	{
		for (std::size_t word = 0; word < WORD_COUNT; ++word) {
			const auto remaining = Capacity - word * WORD_BITS;
			const uint64_t mask = remaining >= WORD_BITS ? UINT64_MAX : (UINT64_C(1) << remaining) - 1u;
			words_[word].available.store(mask, std::memory_order_relaxed);
		}
	}
	atomic_index_pool(const atomic_index_pool &) = delete;
	atomic_index_pool &operator=(const atomic_index_pool &) = delete;

	/**
	 * @brief Attempt one bounded acquisition without waiting for another owner.
	 * @param[out] index Changed only after successful exclusive acquisition.
	 * @return True with one index, or false for exhaustion or contention.
	 */
	[[nodiscard]] bool try_acquire(uint32_t &index) noexcept
	{
		for (std::size_t word = 0; word < WORD_COUNT; ++word) {
			auto available = words_[word].available.load(std::memory_order_relaxed);
			if (available == 0) {
				continue;
			}
			const auto bit = static_cast<uint32_t>(std::countr_zero(available));
			const uint64_t selected = UINT64_C(1) << bit;
			if (words_[word].available.compare_exchange_strong(available, available & ~selected,
									   std::memory_order_acquire,
									   std::memory_order_relaxed)) {
				index = static_cast<uint32_t>(word * WORD_BITS) + bit;
				return true;
			}
		}
		return false;
	}

	/**
	 * @brief Return one exact lease after all accesses to its object have ended.
	 * @param index Exclusively owned index; out-of-range or already-free input terminates.
	 */
	void release(uint32_t index) noexcept
	{
		if (index >= Capacity) {
			std::terminate();
		}
		const uint64_t bit = UINT64_C(1) << (index % WORD_BITS);
		if ((words_[index / WORD_BITS].available.fetch_or(bit, std::memory_order_release) & bit) != 0) {
			std::terminate();
		}
	}

    private:
	static constexpr std::size_t WORD_BITS = 64;  ///< Availability bits per lock-free word.
	static constexpr std::size_t WORD_COUNT = (Capacity + WORD_BITS - 1) / WORD_BITS;  ///< Exact fixed extent.
	/** @brief Unrelated word owners never share a writable cache line. */
	struct alignas(CACHE_LINE_SIZE) word_state {
		std::atomic<uint64_t> available{0};  ///< Set bits have no current lease.
	};
	std::array<word_state, WORD_COUNT> words_{};  ///< Sole availability authority.
};

}  // namespace kinetum::algo
