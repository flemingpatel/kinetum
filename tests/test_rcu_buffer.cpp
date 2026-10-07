// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_rcu_buffer.cpp
 * @brief Public RCU value, version, concurrency, and guard-lifetime tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>

#include <kinetum/algo/rcu_buffer.hpp>

namespace kinetum::algo
{
namespace
{

/** Complete value whose fields must always come from one publication. */
struct published_value {
	uint64_t generation{0};	 ///< Publication identity.
	uint64_t complement{0};	 ///< Bitwise complement of the publication identity.
};

/** @brief Destroy one buffer while a guard still owns its reader pin. */
void destroy_buffer_with_live_guard()
{
	auto buffer = std::make_unique<rcu_buffer<uint64_t>>();
	buffer->store(7u);
	auto guard = buffer->borrow();
	buffer.reset();
	(void)guard;
}

/** @brief First publication makes one exact value available to guarded reads. */
TEST(rcu_buffer, unpublished_then_first_publication_is_exact)
{
	rcu_buffer<uint64_t> buffer;
	EXPECT_FALSE(buffer.has_value());

	buffer.store(42u);
	EXPECT_TRUE(buffer.has_value());
	EXPECT_EQ(buffer.get(), 42u);
	const auto guard = buffer.borrow();
	EXPECT_EQ(*guard, 42u);
}

/** @brief Moving a guard transfers one pin and invalidates each source. */
TEST(rcu_buffer, guard_move_transfers_one_reader_pin)
{
	static_assert(!std::is_copy_constructible_v<rcu_buffer<uint64_t>::read_guard>);
	static_assert(std::is_nothrow_move_constructible_v<rcu_buffer<uint64_t>::read_guard>);

	rcu_buffer<uint64_t> buffer;
	buffer.store(9u);
	auto first = buffer.borrow();
	auto second = std::move(first);
	// Querying the documented moved-from state is the behavior under test.
	// NOLINTNEXTLINE(bugprone-use-after-move)
	EXPECT_FALSE(first.valid());
	ASSERT_TRUE(second.valid());
	EXPECT_EQ(second.get(), 9u);

	auto destination = buffer.borrow();
	destination = std::move(second);
	// Querying the documented moved-from state is the behavior under test.
	// NOLINTNEXTLINE(bugprone-use-after-move)
	EXPECT_FALSE(second.valid());
	ASSERT_TRUE(destination.valid());
	EXPECT_EQ(*destination, 9u);
}

/** @brief Nonblocking read forms return one complete stable publication. */
TEST(rcu_buffer, nonblocking_reads_return_one_complete_value)
{
	rcu_buffer<published_value> buffer;
	buffer.emplace(published_value{11u, ~uint64_t{11}});

	auto guard = buffer.try_borrow();
	ASSERT_TRUE(guard.has_value());
	if (guard.has_value()) {
		EXPECT_EQ((*guard)->generation, 11u);
		EXPECT_EQ((*guard)->complement, ~uint64_t{11});
	}

	const auto copy = buffer.try_get();
	ASSERT_TRUE(copy.has_value());
	if (copy.has_value()) {
		EXPECT_EQ(copy->generation, 11u);
		EXPECT_EQ(copy->complement, ~uint64_t{11});
	}
}

/** @brief Concurrent readers observe one coherent value-and-version pair. */
TEST(rcu_buffer, concurrent_versioned_publication_never_tears_identity)
{
	constexpr uint64_t PUBLICATION_COUNT = 20000u;
	versioned_rcu_buffer<published_value> buffer;
	buffer.store(published_value{1u, ~uint64_t{1}}, 1u);
	auto initial_guard = std::optional{buffer.borrow()};

	std::atomic<bool> begin{false};
	std::atomic<bool> complete{false};
	std::thread writer([&]() {
		while (!begin.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
		for (uint64_t generation = 2u; generation <= PUBLICATION_COUNT; ++generation) {
			if ((generation & 1u) == 0u) {
				buffer.store(published_value{generation, ~generation}, generation);
			} else {
				buffer.emplace(generation, published_value{generation, ~generation});
			}
			if ((generation & 0xffu) == 0u) {
				std::this_thread::yield();
			}
		}
		complete.store(true, std::memory_order_release);
	});

	begin.store(true, std::memory_order_release);
	// The writer may publish the other slot, but cannot reuse this pinned one.
	while (buffer.version() == 1u) {
		std::this_thread::yield();
	}
	EXPECT_EQ(buffer.version(), 2u);
	EXPECT_EQ((*initial_guard)->generation, 1u);
	EXPECT_EQ((*initial_guard)->complement, ~uint64_t{1});
	EXPECT_EQ(initial_guard->epoch(), 1u);
	initial_guard.reset();

	std::size_t observations = 0u;
	const auto check_guard = [&observations](const auto &guard) {
		const uint64_t generation = guard->generation;
		EXPECT_EQ(guard->complement, ~generation);
		EXPECT_EQ(guard.epoch(), generation);
		std::this_thread::yield();
		EXPECT_EQ(guard->generation, generation);
		EXPECT_EQ(guard->complement, ~generation);
		EXPECT_EQ(guard.epoch(), generation);
		++observations;
	};
	do {
		{
			auto guard = buffer.borrow();
			check_guard(guard);
		}
		{
			auto guard = buffer.try_borrow();
			if (guard.has_value()) {
				check_guard(*guard);
			}
		}
	} while (!complete.load(std::memory_order_acquire) || observations < 100u);
	writer.join();

	EXPECT_GE(observations, 100u);
	EXPECT_EQ(buffer.version(), PUBLICATION_COUNT);
	const auto final = buffer.get();
	EXPECT_EQ(final.generation, PUBLICATION_COUNT);
	EXPECT_EQ(final.complement, ~PUBLICATION_COUNT);
}

/** @brief Buffer destruction fails stop before orphaning a live guard pin. */
TEST(rcu_buffer, destruction_with_live_guard_is_fail_stop)
{
	EXPECT_DEATH(destroy_buffer_with_live_guard(), "rcu_buffer destroyed with live reader pin");
}

}  // namespace
}  // namespace kinetum::algo
