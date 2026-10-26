// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_atomic_index_pool.cpp
 * @brief Concurrent compact-index geometry, ownership, and prefix publication tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdlib>
#include <cstdint>
#include <semaphore>
#include <memory>
#include <limits>
#include <span>
#include <thread>
#include <type_traits>
#include <vector>

#include <kinetum/algo/atomic_index_pool.hpp>

namespace kinetum::algo
{

/** @brief Acquire every partial-word index once and recycle without affecting held leases. */
TEST(algo_atomic_index_pool, exact_population_and_independent_release)
{
	atomic_index_pool<65> pool;
	std::array<bool, 65> seen{};
	for (uint32_t count = 0; count < seen.size(); ++count) {
		uint32_t index = UINT32_MAX;
		ASSERT_TRUE(pool.try_acquire(index));
		ASSERT_LT(index, seen.size());
		EXPECT_FALSE(seen[index]);
		seen[index] = true;
	}
	uint32_t index = UINT32_MAX;
	EXPECT_FALSE(pool.try_acquire(index));
	EXPECT_EQ(index, UINT32_MAX);
	for (uint32_t turn = 0; turn < 1024; ++turn) {
		pool.release(64);
		ASSERT_TRUE(pool.try_acquire(index));
		EXPECT_EQ(index, 64u);
	}
	for (uint32_t returned = 0; returned < seen.size(); ++returned) {
		pool.release(returned);
	}
	EXPECT_DEATH(pool.release(64), "");
	EXPECT_DEATH(pool.release(65), "");
}

/** @brief Concurrent leases never alias and all published objects return to the complete pool. */
TEST(algo_atomic_index_pool, concurrent_exclusive_ownership_and_publication)
{
	atomic_index_pool<65> pool;
	std::array<std::atomic<bool>, 65> occupied{};
	std::array<uint64_t, 65> touches{};
	std::atomic<bool> collision{false};
	std::atomic<uint64_t> admissions{0};
	std::array<std::thread, 8> callers;
	for (auto &caller : callers) {
		caller = std::thread([&] {
			for (uint32_t turn = 0; turn < 4096; ++turn) {
				uint32_t index = 0;
				if (!pool.try_acquire(index)) {
					continue;
				}
				if (index >= occupied.size() ||
				    occupied[index].exchange(true, std::memory_order_relaxed)) {
					collision.store(true, std::memory_order_relaxed);
					return;
				}
				++touches[index];
				admissions.fetch_add(1, std::memory_order_relaxed);
				occupied[index].store(false, std::memory_order_relaxed);
				pool.release(index);
			}
		});
	}
	for (auto &caller : callers) {
		caller.join();
	}
	ASSERT_FALSE(collision.load(std::memory_order_relaxed));
	uint64_t total = 0;
	for (uint32_t count = 0; count < touches.size(); ++count) {
		uint32_t index = 0;
		ASSERT_TRUE(pool.try_acquire(index));
		total += touches[index];
	}
	EXPECT_GT(total, 0u);
	EXPECT_EQ(total, admissions.load(std::memory_order_relaxed));
	for (uint32_t index = 0; index < touches.size(); ++index) {
		pool.release(index);
	}
}

namespace
{

/** @brief Own constructed words before their borrowed view; no alternate allocator semantics. */
struct index_fixture {
	std::unique_ptr<atomic_index_pool_view::storage_type[]> words;	///< Complete backing word objects.
	atomic_index_pool_view pool;  ///< Borrowed control retired before its backing.
	/** @brief Construct the exact positive population used by the production view. */
	explicit index_fixture(uint32_t capacity)
		: words(std::make_unique<atomic_index_pool_view::storage_type[]>(
			  atomic_index_pool_view::word_count(capacity)))
		, pool({words.get(), atomic_index_pool_view::word_count(capacity)}, capacity)
	{
	}
};

/** @brief Return an exact lease span without consulting indexed objects. */
void return_indices(atomic_index_pool_view &pool, std::span<const uint32_t> indices) noexcept
{
	pool.release_prefix(indices.size(), [indices](std::size_t ordinal) noexcept { return indices[ordinal]; });
}

/** @brief Collect an admitted prefix without touching its output suffix. */
template <class count_type>
count_type take_indices(atomic_index_pool_view &pool, count_type count, uint32_t *output) noexcept
{
	return pool.acquire_prefix(count,
				   [output](std::size_t ordinal, uint32_t index) noexcept { output[ordinal] = index; });
}

/** @brief Preserve each public count width across zero, bounded and full-universe requests. */
template <class count_type>
void check_count_width()
{
	for (const uint32_t population : {1u, 64u, 65u, 257u, 65537u}) {
		SCOPED_TRACE(::testing::Message() << "population=" << population << " count_bytes="
						  << sizeof(count_type) << " signed=" << std::is_signed_v<count_type>);
		index_fixture fixture(population);
		std::vector<uint32_t> output(static_cast<std::size_t>(population) + 1u, UINT32_MAX);
		for (const auto request :
		     {count_type{0}, count_type{1}, count_type{63}, std::numeric_limits<count_type>::max()}) {
			std::fill(output.begin(), output.end(), UINT32_MAX);
			const auto acquired = take_indices(fixture.pool, request, output.data());
			static_assert(std::is_same_v<decltype(acquired), const count_type>);
			ASSERT_EQ(acquired, std::min<uint64_t>(static_cast<uint64_t>(request), population));
			const auto count = static_cast<std::size_t>(acquired);
			std::vector<bool> seen(population, false);
			for (std::size_t ordinal = 0; ordinal < count; ++ordinal) {
				ASSERT_LT(output[ordinal], population);
				ASSERT_FALSE(seen[output[ordinal]]);
				seen[output[ordinal]] = true;
			}
			EXPECT_TRUE(std::all_of(output.begin() + static_cast<std::ptrdiff_t>(count), output.end(),
						[](uint32_t value) { return value == UINT32_MAX; }));
			return_indices(fixture.pool, {output.data(), count});
			EXPECT_EQ(fixture.pool.available_approx(), population);
		}
		if constexpr (std::is_signed_v<count_type>) {
			output[0] = UINT32_MAX;
			EXPECT_EQ(take_indices(fixture.pool, count_type{-1}, output.data()), 0);
			EXPECT_EQ(output[0], UINT32_MAX);
		}
	}
}

}  // namespace

/** @brief Preserve fixed-owner geometry and reject malformed borrowed geometry before use. */
TEST(algo_atomic_index_pool, fixed_layout_and_view_geometry)
{
	static_assert(sizeof(atomic_index_pool<1>) == CACHE_LINE_SIZE);
	static_assert(sizeof(atomic_index_pool<65>) == 2u * CACHE_LINE_SIZE);
	static_assert(alignof(atomic_index_pool<65>) == CACHE_LINE_SIZE);
	static_assert(!std::is_copy_constructible_v<atomic_index_pool_view>);
	static_assert(!std::is_move_constructible_v<atomic_index_pool_view>);
	EXPECT_EQ(atomic_index_pool_view::word_count(UINT32_MAX), 67108864u);
	EXPECT_DEATH(([] {
			     atomic_index_pool_view pool({}, 1);
			     std::_Exit(EXIT_SUCCESS);
		     }()),
		     "");
	EXPECT_DEATH(([] {
			     std::array<atomic_index_pool_view::storage_type, 1> words;
			     atomic_index_pool_view pool(words, 0);
			     std::_Exit(EXIT_SUCCESS);
		     }()),
		     "");
	EXPECT_DEATH(([] {
			     std::array<atomic_index_pool_view::storage_type, 1> words;
			     atomic_index_pool_view pool(words, 65);
			     std::_Exit(EXIT_SUCCESS);
		     }()),
		     "");
	EXPECT_DEATH(([] {
			     std::array<atomic_index_pool_view::storage_type, 2> words;
			     atomic_index_pool_view pool(words, 64);
			     std::_Exit(EXIT_SUCCESS);
		     }()),
		     "");
}

/** @brief Every request width returns an exact prefix while partial final words remain bounded. */
TEST(algo_atomic_index_pool, view_prefix_widths_suffix_and_padding)
{
	check_count_width<uint8_t>();
	check_count_width<uint16_t>();
	check_count_width<uint32_t>();
	check_count_width<uint64_t>();
	check_count_width<int8_t>();
	check_count_width<int16_t>();
	check_count_width<int32_t>();
	check_count_width<int64_t>();
	for (const uint32_t population : {1u, 2u, 63u, 64u, 65u, 127u, 129u, 4096u, 65537u}) {
		SCOPED_TRACE(population);
		index_fixture fixture(population);
		std::vector<uint32_t> output(65536u, UINT32_MAX);
		EXPECT_EQ(take_indices(fixture.pool, -1, output.data()), 0);
		EXPECT_EQ(take_indices(fixture.pool, uint8_t{0}, output.data()), 0u);
		const auto acquired = take_indices(fixture.pool, uint16_t{UINT16_MAX}, output.data());
		static_assert(std::is_same_v<decltype(acquired), const uint16_t>);
		ASSERT_EQ(acquired, std::min<uint32_t>(population, UINT16_MAX));
		std::vector<bool> seen(population, false);
		for (std::size_t ordinal = 0; ordinal < acquired; ++ordinal) {
			ASSERT_LT(output[ordinal], population);
			EXPECT_FALSE(seen[output[ordinal]]);
			seen[output[ordinal]] = true;
		}
		EXPECT_EQ(output[acquired], UINT32_MAX);
		return_indices(fixture.pool, {output.data(), acquired});
		EXPECT_EQ(fixture.pool.available_approx(), population);
		if (population % 64u != 0) {
			const auto mask = (UINT64_C(1) << (population % 64u)) - 1u;
			EXPECT_EQ(fixture.words[atomic_index_pool_view::word_count(population) - 1u].available.load(),
				  mask);
		}
		uint32_t single = UINT32_MAX;
		EXPECT_EQ(take_indices(fixture.pool, int64_t{1}, &single), 1);
		return_indices(fixture.pool, {&single, 1});
		EXPECT_EQ(fixture.pool.available_approx(), population);
	}
}

/** @brief Arbitrary return order agrees with an independent set of live leases. */
TEST(algo_atomic_index_pool, view_matches_independent_lease_oracle)
{
	for (const uint32_t population : {1u, 2u, 3u, 63u, 64u, 65u, 127u, 129u, 1024u, 4096u}) {
		SCOPED_TRACE(population);
		index_fixture fixture(population);
		std::vector<uint32_t> leases;
		std::vector<bool> owned(population, false);
		std::array<uint32_t, 65> output{};
		uint64_t random = UINT64_C(0x73b94d19);
		for (uint32_t turn = 0; turn < 20000u; ++turn) {
			random ^= random << 13u;
			random ^= random >> 7u;
			random ^= random << 17u;
			if ((random & 1u) != 0 && !leases.empty()) {
				const auto position = static_cast<std::size_t>(random % leases.size());
				const auto returned = leases[position];
				owned[returned] = false;
				leases[position] = leases.back();
				leases.pop_back();
				return_indices(fixture.pool, {&returned, 1});
			} else {
				const auto request = static_cast<uint16_t>(random % 65u);
				output.fill(UINT32_MAX);
				const auto acquired = take_indices(fixture.pool, request, output.data());
				ASSERT_EQ(acquired, std::min<std::size_t>(request, population - leases.size()));
				EXPECT_EQ(output[acquired], UINT32_MAX);
				for (uint16_t ordinal = 0; ordinal < acquired; ++ordinal) {
					const auto index = output[ordinal];
					ASSERT_LT(index, population);
					ASSERT_FALSE(owned[index]);
					owned[index] = true;
					leases.push_back(index);
				}
			}
			ASSERT_EQ(fixture.pool.available_approx(), population - leases.size());
		}
		return_indices(fixture.pool, leases);
		EXPECT_EQ(fixture.pool.available_approx(), population);
	}
}

/** @brief A paused inspector neither blocks independent leases nor hides a concurrent return. */
TEST(algo_atomic_index_pool, paused_inspector_preserves_independent_progress)
{
	index_fixture fixture(128);
	std::array<uint32_t, 128> held{};
	ASSERT_EQ(take_indices(fixture.pool, uint16_t{128}, held.data()), 128u);
	const uint32_t second_word = 64;
	return_indices(fixture.pool, {&second_word, 1});
	std::binary_semaphore entered(0), resume(0);
	uint32_t paused_index = UINT32_MAX;
	uint16_t paused_count = 0;
	std::jthread inspector([&] {
		paused_count = fixture.pool.acquire_prefix(uint16_t{1}, [&](std::size_t, uint32_t index) noexcept {
			paused_index = index;
			entered.release();
			resume.acquire();
		});
		if (paused_count == 0) {
			entered.release();
		}
	});
	entered.acquire();
	const uint32_t independent = 0;
	return_indices(fixture.pool, {&independent, 1});
	uint32_t other = UINT32_MAX;
	const auto count = take_indices(fixture.pool, uint16_t{1}, &other);
	if (count == 1) {
		return_indices(fixture.pool, {&other, 1});
	}
	resume.release();
	inspector.join();
	if (paused_count == 1) {
		return_indices(fixture.pool, {&paused_index, 1});
	}
	for (uint32_t index = 1; index < 128; ++index) {
		if (index != second_word) {
			return_indices(fixture.pool, {&index, 1});
		}
	}
	EXPECT_EQ(count, 1u);
	EXPECT_EQ(other, 0u);
	EXPECT_EQ(paused_count, 1u);
	EXPECT_EQ(paused_index, second_word);
	EXPECT_EQ(fixture.pool.available_approx(), 128u);
	EXPECT_EQ(take_indices(fixture.pool, uint16_t{128}, held.data()), 128u);
	return_indices(fixture.pool, held);
}

/** @brief Hint publication compares the current value after an intervening acquirer completes. */
TEST(algo_atomic_index_pool, hint_observes_intervening_acquirer)
{
	index_fixture fixture(128);
	std::array<uint32_t, 63> held{};
	ASSERT_EQ(take_indices(fixture.pool, uint16_t{63}, held.data()), 63u);
	std::binary_semaphore entered(0), resume(0);
	uint32_t paused = UINT32_MAX;
	uint16_t paused_count = 0;
	std::jthread caller([&] {
		paused_count = fixture.pool.acquire_prefix(uint16_t{1}, [&](std::size_t, uint32_t index) noexcept {
			paused = index;
			entered.release();
			resume.acquire();
		});
		if (paused_count == 0) {
			entered.release();
		}
	});
	entered.acquire();
	uint32_t intervening = UINT32_MAX;
	const auto intervening_count = take_indices(fixture.pool, uint16_t{1}, &intervening);
	if (intervening_count == 1) {
		return_indices(fixture.pool, {&intervening, 1});
	}
	return_indices(fixture.pool, held);
	resume.release();
	caller.join();
	if (paused_count == 1) {
		return_indices(fixture.pool, {&paused, 1});
	}
	uint32_t next = UINT32_MAX;
	const auto next_count = take_indices(fixture.pool, uint16_t{1}, &next);
	if (next_count == 1) {
		return_indices(fixture.pool, {&next, 1});
	}
	EXPECT_EQ(paused_count, 1u);
	EXPECT_EQ(paused, 63u);
	EXPECT_EQ(intervening_count, 1u);
	EXPECT_EQ(intervening, 64u);
	EXPECT_EQ(next_count, 1u);
	EXPECT_EQ(next, 0u);
	EXPECT_EQ(fixture.pool.available_approx(), 128u);
}

/** @brief Returned-object writes become visible to exclusive concurrent prefix owners. */
TEST(algo_atomic_index_pool, view_concurrent_payload_publication_and_reclamation)
{
	index_fixture fixture(129);
	std::array<std::atomic<bool>, 129> occupied{};
	std::array<uint64_t, 129> touches{};
	std::array<uint64_t, 4> accepted{};
	std::atomic<bool> collision{false};
	std::array<std::jthread, 4> callers;
	for (std::size_t caller = 0; caller < callers.size(); ++caller) {
		callers[caller] = std::jthread([&, caller] {
			std::array<uint32_t, 17> indices{};
			for (uint32_t turn = 0; turn < 8192u; ++turn) {
				const auto count = take_indices(fixture.pool, uint16_t{17}, indices.data());
				for (uint16_t ordinal = 0; ordinal < count; ++ordinal) {
					const auto index = indices[ordinal];
					if (index >= occupied.size() ||
					    occupied[index].exchange(true, std::memory_order_relaxed)) {
						collision.store(true);
						return;
					}
					++touches[index];
					occupied[index].store(false, std::memory_order_relaxed);
				}
				accepted[caller] += count;
				return_indices(fixture.pool, {indices.data(), count});
			}
		});
	}
	for (auto &caller : callers) {
		caller.join();
	}
	ASSERT_FALSE(collision.load());
	std::array<uint32_t, 129> all{};
	const auto count = take_indices(fixture.pool, uint16_t{129}, all.data());
	uint64_t observed = 0, expected = 0;
	for (uint16_t ordinal = 0; ordinal < count; ++ordinal) {
		observed += touches[all[ordinal]];
	}
	for (const auto value : accepted) {
		expected += value;
	}
	return_indices(fixture.pool, {all.data(), count});
	EXPECT_EQ(count, 129u);
	EXPECT_GT(observed, 0u);
	EXPECT_EQ(observed, expected);
	EXPECT_EQ(fixture.pool.available_approx(), 129u);
}

/** @brief Invalid, already-free and repeated leases fail at return rather than being republished. */
TEST(algo_atomic_index_pool, view_rejects_invalid_returns)
{
	EXPECT_DEATH(([] {
			     index_fixture fixture(65);
			     const uint32_t index = 65;
			     return_indices(fixture.pool, {&index, 1});
			     std::_Exit(EXIT_SUCCESS);
		     }()),
		     "");
	EXPECT_DEATH(([] {
			     index_fixture fixture(65);
			     const uint32_t index = 64;
			     return_indices(fixture.pool, {&index, 1});
			     std::_Exit(EXIT_SUCCESS);
		     }()),
		     "");
	EXPECT_DEATH(([] {
			     index_fixture fixture(65);
			     uint32_t index = 0;
			     if (take_indices(fixture.pool, uint16_t{1}, &index) != 1) {
				     std::_Exit(EXIT_SUCCESS);
			     }
			     const std::array<uint32_t, 2> duplicate{index, index};
			     return_indices(fixture.pool, duplicate);
			     std::_Exit(EXIT_SUCCESS);
		     }()),
		     "");
}

}  // namespace kinetum::algo
