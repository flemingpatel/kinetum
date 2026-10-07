// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_quiescence_domain.cpp
 * @brief Exact backend-neutral reader registration and grace tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <stdexcept>
#include <thread>
#include <type_traits>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/quiescence.hpp>

namespace kinetum::algo
{
namespace
{

static_assert(!std::is_copy_constructible_v<quiescence_reader>);
static_assert(!std::is_copy_assignable_v<quiescence_reader>);
static_assert(!std::is_move_constructible_v<quiescence_reader>);
static_assert(!std::is_move_assignable_v<quiescence_reader>);
static_assert(!std::is_copy_constructible_v<quiescence_domain>);
static_assert(!std::is_copy_assignable_v<quiescence_domain>);
static_assert(!std::is_move_constructible_v<quiescence_domain>);
static_assert(!std::is_move_assignable_v<quiescence_domain>);

/** @brief Attempt publication through one reader that no domain has bound. */
void publish_unbound_reader()
{
	quiescence_reader reader;
	(void)reader.publish_quiescent();
	std::_Exit(EXIT_SUCCESS);
}

/** @brief Destroy a reader while its exact domain still borrows the record. */
void destroy_bound_reader()
{
	auto reader = std::make_unique<quiescence_reader>();
	std::array<quiescence_reader *, 1> readers{reader.get()};
	auto domain = std::make_unique<quiescence_domain>(readers);
	(void)domain;
	reader.reset();
	std::_Exit(EXIT_SUCCESS);
}

/** @brief Destroy a domain while one exact grace generation remains active. */
void destroy_active_domain()
{
	quiescence_reader reader;
	std::array<quiescence_reader *, 1> readers{&reader};
	auto domain = std::make_unique<quiescence_domain>(readers);
	if (domain->start_grace_period() == 0u) {
		std::_Exit(EXIT_SUCCESS);
	}
	domain.reset();
	std::_Exit(EXIT_SUCCESS);
}

/** @brief Bind one exact immutable reader set and reject every alternate membership. */
TEST(quiescence_domain, registration_is_exact_cacheline_isolated_and_all_or_none)
{
	EXPECT_EQ(sizeof(quiescence_reader), CACHE_LINE_SIZE);
	EXPECT_EQ(alignof(quiescence_reader), CACHE_LINE_SIZE);
	std::array<quiescence_reader *, 0> none{};
	EXPECT_THROW((void)quiescence_domain(none), std::invalid_argument);

	quiescence_reader first;
	quiescence_reader second;
	std::array<quiescence_reader *, 2> duplicates{&first, &first};
	EXPECT_THROW((void)quiescence_domain(duplicates), std::invalid_argument);
	EXPECT_FALSE(first.bound());
	EXPECT_FALSE(second.bound());
	std::array<quiescence_reader *, 2> null_member{&first, nullptr};
	EXPECT_THROW((void)quiescence_domain(null_member), std::invalid_argument);
	EXPECT_FALSE(first.bound());
	EXPECT_FALSE(second.bound());

	std::array<quiescence_reader *, 2> readers{&first, &second};
	{
		quiescence_domain domain(readers);
		EXPECT_EQ(domain.reader_count(), 2u);
		EXPECT_TRUE(domain.owns_reader(0u, first));
		EXPECT_TRUE(domain.owns_reader(1u, second));
		EXPECT_FALSE(domain.owns_reader(1u, first));
		EXPECT_TRUE(first.bound());
		EXPECT_TRUE(second.bound());
		EXPECT_EQ(first.reader_index(), 0u);
		EXPECT_EQ(second.reader_index(), 1u);
		EXPECT_THROW((void)quiescence_domain(readers), std::invalid_argument);
	}
	EXPECT_FALSE(first.bound());
	EXPECT_FALSE(second.bound());
}

/** @brief Require every exact adjacent reader publication before grace completion. */
TEST(quiescence_domain, adjacent_generation_requires_every_reader_and_exact_finish)
{
	quiescence_reader first;
	quiescence_reader second;
	std::array<quiescence_reader *, 2> readers{&first, &second};
	quiescence_domain domain(readers);
	EXPECT_TRUE(domain.can_start_grace_period());
	const uint64_t first_generation = domain.start_grace_period();
	ASSERT_EQ(first_generation, 1u);
	EXPECT_EQ(domain.start_grace_period(), 0u);
	auto completed = domain.quiescent_reader_count(first_generation);
	ASSERT_TRUE(completed.has_value());
	EXPECT_EQ(completed.value(), 0u);
	EXPECT_FALSE(domain.grace_period_complete(first_generation));

	EXPECT_EQ(first.publish_quiescent(), first_generation);
	EXPECT_EQ(first.publish_quiescent(), first_generation);
	completed = domain.quiescent_reader_count(first_generation);
	ASSERT_TRUE(completed.has_value());
	EXPECT_EQ(completed.value(), 1u);
	EXPECT_FALSE(domain.finish_grace_period(first_generation));
	EXPECT_EQ(second.publish_quiescent(), first_generation);
	EXPECT_TRUE(domain.grace_period_complete(first_generation));
	EXPECT_TRUE(domain.finish_grace_period(first_generation));
	EXPECT_TRUE(domain.finish_grace_period(first_generation));
	EXPECT_EQ(domain.active_generation(), 0u);
	EXPECT_EQ(domain.completed_generation(), first_generation);
	EXPECT_EQ(first.publish_quiescent(), 0u);

	const uint64_t second_generation = domain.start_grace_period();
	ASSERT_EQ(second_generation, 2u);
	EXPECT_EQ(second.publish_quiescent(), second_generation);
	EXPECT_EQ(first.publish_quiescent(), second_generation);
	EXPECT_TRUE(domain.finish_grace_period(second_generation));
	EXPECT_FALSE(domain.quiescent_reader_count(first_generation + 2u).has_value());
}

/** @brief Concurrent exact publications cannot make an incomplete grace appear complete. */
TEST(quiescence_domain, concurrent_publication_never_completes_early)
{
	quiescence_reader first;
	quiescence_reader second;
	std::array<quiescence_reader *, 2> readers{&first, &second};
	quiescence_domain domain(readers);
	const uint64_t generation = domain.start_grace_period();
	ASSERT_NE(generation, 0u);
	std::atomic<bool> release{false};
	std::atomic<uint32_t> ready{0u};
	std::atomic<uint64_t> first_result{0u};
	std::atomic<uint64_t> second_result{0u};
	const auto publish = [&](quiescence_reader *reader, std::atomic<uint64_t> *result) {
		ready.fetch_add(1u, std::memory_order_release);
		while (!release.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
		result->store(reader->publish_quiescent(), std::memory_order_release);
	};
	std::thread first_thread(publish, &first, &first_result);
	std::thread second_thread(publish, &second, &second_result);
	while (ready.load(std::memory_order_acquire) != 2u) {
		std::this_thread::yield();
	}
	EXPECT_FALSE(domain.grace_period_complete(generation));
	release.store(true, std::memory_order_release);
	first_thread.join();
	second_thread.join();
	EXPECT_EQ(first_result.load(std::memory_order_acquire), generation);
	EXPECT_EQ(second_result.load(std::memory_order_acquire), generation);
	EXPECT_TRUE(domain.grace_period_complete(generation));
	EXPECT_TRUE(domain.finish_grace_period(generation));
}

/** @brief Refuse generation wrap and fail stop on violated borrow lifetimes. */
TEST(quiescence_domain, wrap_overlap_and_lifetime_violations_fail_closed)
{
	EXPECT_TRUE(quiescence_domain::can_advance_generation(0u));
	EXPECT_TRUE(quiescence_domain::can_advance_generation(std::numeric_limits<uint64_t>::max() - 2u));
	EXPECT_FALSE(quiescence_domain::can_advance_generation(std::numeric_limits<uint64_t>::max() - 1u));
	EXPECT_FALSE(quiescence_domain::can_advance_generation(std::numeric_limits<uint64_t>::max()));
	quiescence_reader completed_reader;
	std::array<quiescence_reader *, 1> completed_readers{&completed_reader};
	{
		quiescence_domain domain(completed_readers);
		const uint64_t generation = domain.start_grace_period();
		ASSERT_NE(generation, 0u);
		EXPECT_EQ(completed_reader.publish_quiescent(), generation);
		EXPECT_TRUE(domain.finish_grace_period(generation));
	}
	EXPECT_THROW((void)quiescence_domain(completed_readers), std::invalid_argument);
	EXPECT_DEATH(publish_unbound_reader(), "");
	EXPECT_DEATH(destroy_bound_reader(), "");
	EXPECT_DEATH(destroy_active_domain(), "");
}

}  // namespace
}  // namespace kinetum::algo
