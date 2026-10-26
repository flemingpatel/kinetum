// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_ratelimit.cpp
 * @brief Exact byte-credit and rolling event-window contracts.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <deque>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <type_traits>

#include <kinetum/algo/ratelimit.hpp>

namespace kinetum::algo
{

/**
 * @brief Verify oversized packet cost is fail closed.
 */
TEST(algo_ratelimit, oversized_packet_cost_is_fail_closed)
{
	token_bucket token(0, 64);
	EXPECT_FALSE(token.allow(1, std::numeric_limits<std::size_t>::max()));

	leaky_bucket leaky(0, 64);
	EXPECT_FALSE(leaky.allow(1, std::numeric_limits<std::size_t>::max()));
}

/** @brief Timestamp zero is ordinary identity and never reinitializes consumed credit. */
TEST(algo_ratelimit, zero_timestamp_binds_one_exact_initial_baseline)
{
	token_bucket token(1u, 1u);
	EXPECT_TRUE(token.allow(0u, 1u));
	EXPECT_FALSE(token.allow(1u, 1u));
	EXPECT_TRUE(token.allow(1'000'000'000u, 1u));

	leaky_bucket leaky(1u, 1u);
	EXPECT_TRUE(leaky.allow(0u, 1u));
	EXPECT_FALSE(leaky.allow(1u, 1u));
	EXPECT_TRUE(leaky.allow(1'000'000'000u, 1u));
}

/** @brief Sub-byte accrual survives every observation until one exact byte exists. */
TEST(algo_ratelimit, low_rates_accumulate_fractional_credit_without_truncation)
{
	token_bucket token(1u, 1u);
	ASSERT_TRUE(token.allow(0u, 1u));
	for (uint64_t now_ns : {250'000'000u, 500'000'000u, 750'000'000u}) {
		EXPECT_FALSE(token.allow(now_ns, 1u));
	}
	EXPECT_TRUE(token.allow(1'000'000'000u, 1u));

	leaky_bucket leaky(1u, 1u);
	ASSERT_TRUE(leaky.allow(0u, 1u));
	for (uint64_t now_ns : {250'000'000u, 500'000'000u, 750'000'000u}) {
		EXPECT_FALSE(leaky.allow(now_ns, 1u));
	}
	EXPECT_TRUE(leaky.allow(1'000'000'000u, 1u));
}

/** @brief Full-width capacities and costs retain exact arithmetic without saturation aliases. */
TEST(algo_ratelimit, complete_unsigned_byte_domain_is_exact)
{
	constexpr uint64_t MAX_BYTES = std::numeric_limits<uint64_t>::max();
	token_bucket token(0u, MAX_BYTES);
	if constexpr (sizeof(std::size_t) == sizeof(uint64_t)) {
		EXPECT_TRUE(token.allow(0u, std::numeric_limits<std::size_t>::max()));
		EXPECT_EQ(token.tokens(), 0u);
	}

	leaky_bucket leaky(0u, MAX_BYTES);
	EXPECT_TRUE(leaky.allow(0u, std::numeric_limits<std::size_t>::max()));
	EXPECT_EQ(leaky.level(), static_cast<uint64_t>(std::numeric_limits<std::size_t>::max()));
}

/** @brief Regressing time and reconfiguration cannot mint rate credit. */
TEST(algo_ratelimit, regression_and_reconfiguration_preserve_exact_credit)
{
	token_bucket token(1u, 2u);
	ASSERT_TRUE(token.allow(100u, 1u));
	EXPECT_FALSE(token.allow(99u, 1u));
	EXPECT_EQ(token.tokens(), 1u);
	EXPECT_TRUE(token.allow(100u, 1u));

	token_bucket reconfigured(1u, 10u);
	ASSERT_TRUE(reconfigured.allow(0u, 10u));
	EXPECT_FALSE(reconfigured.allow(500'000'000u, 1u));
	reconfigured.reconfigure(2u, 10u);
	EXPECT_FALSE(reconfigured.allow(1'000'000'000u, 1u));
	EXPECT_TRUE(reconfigured.allow(1'500'000'000u, 1u));

	leaky_bucket leaky(0u, 2u);
	ASSERT_TRUE(leaky.allow(100u, 1u));
	EXPECT_FALSE(leaky.allow(99u, 1u));
	EXPECT_EQ(leaky.level(), 1u);
}

/** @brief Exact credit retains every subdivision and caps before a full-width refill. */
TEST(algo_ratelimit, byte_credit_preserves_subdivisions_and_saturates_before_addition)
{
	byte_credit divided;
	byte_credit combined;
	// 512,000 microseconds at 125 bytes/s earn exactly 64 bytes.
	for (uint32_t interval = 0; interval < 512000u; ++interval) {
		ASSERT_TRUE(divided.consume(1000u, 125u, 1024u, 0u));
	}
	ASSERT_TRUE(combined.consume(512000000u, 125u, 1024u, 0u));
	EXPECT_EQ(divided.tokens(), 64u);
	EXPECT_EQ(combined.tokens(), 64u);
	EXPECT_TRUE(divided.consume(0u, 125u, 1024u, 64u));
	EXPECT_TRUE(combined.consume(0u, 125u, 1024u, 64u));
	EXPECT_FALSE(divided.consume(0u, 125u, 1024u, 1u));

	constexpr uint64_t MAX = std::numeric_limits<uint64_t>::max();
	byte_credit full(MAX);
	EXPECT_TRUE(full.consume(MAX, MAX, MAX, MAX));
	EXPECT_EQ(full.tokens(), 0u);
	full.reset(1024u);
	EXPECT_FALSE(full.consume(0u, MAX, 100u, 101u));
	EXPECT_EQ(full.tokens(), 100u);
	EXPECT_TRUE(full.consume(0u, 0u, 100u, 100u));
}

/** @brief Sliding windows reject zero duration and never reset on regressing time. */
TEST(algo_ratelimit, sliding_window_requires_positive_monotonic_time)
{
	EXPECT_THROW((sliding_window(1u, 0u, std::pmr::new_delete_resource())), std::invalid_argument);
	sliding_window window(2u, 100u, std::pmr::new_delete_resource());
	EXPECT_TRUE(window.allow(100u));
	EXPECT_TRUE(window.allow(101u));
	EXPECT_FALSE(window.allow(99u));
	EXPECT_EQ(window.count(), 2u);
	EXPECT_FALSE(window.allow(102u));
	EXPECT_TRUE(window.allow(200u));
}

namespace
{

/** @brief Count allocation boundaries without replacing the global PMR resource. */
class window_resource final : public std::pmr::memory_resource {
    public:
	std::size_t allocations{0};    ///< Successful cold allocations.
	std::size_t deallocations{0};  ///< Released allocations.
	bool reject{false};	       ///< Reject any later allocation to prove hot-path independence.
    private:
	/** @brief Allocate through the real resource unless the fixture closed admission. */
	void *do_allocate(std::size_t bytes, std::size_t alignment) override
	{
		if (reject) {
			throw std::bad_alloc();
		}
		auto *result = std::pmr::new_delete_resource()->allocate(bytes, alignment);
		++allocations;
		return result;
	}
	/** @brief Return exact storage to its issuing resource. */
	void do_deallocate(void *memory, std::size_t bytes, std::size_t alignment) override
	{
		++deallocations;
		std::pmr::new_delete_resource()->deallocate(memory, bytes, alignment);
	}
	/** @return Whether the caller names this same ownership domain. */
	bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override
	{
		return this == &other;
	}
};

}  // namespace

/** @brief Geometry and resource errors reject before a partial history can escape. */
TEST(algo_ratelimit, sliding_window_requires_representable_explicit_storage)
{
	static_assert(!std::is_copy_constructible_v<sliding_window> && !std::is_move_constructible_v<sliding_window>);
	window_resource resource;
	EXPECT_THROW((sliding_window(1, 1, nullptr)), std::invalid_argument);
	EXPECT_THROW((sliding_window(UINT64_MAX, 1, &resource)), std::length_error);
	EXPECT_THROW((sliding_window(1, 0, &resource)), std::invalid_argument);
	EXPECT_EQ(resource.allocations, 0u);
	resource.reject = true;
	EXPECT_THROW((sliding_window(1, 1, &resource)), std::bad_alloc);
	EXPECT_EQ(resource.deallocations, 0u);
}

/** @brief Boundary expiry is rolling; valid denials still bind the time regression check. */
TEST(algo_ratelimit, sliding_window_exact_boundaries_and_denied_observations)
{
	window_resource resource;
	sliding_window window(2, 100, &resource);
	EXPECT_TRUE(window.allow(100));
	EXPECT_TRUE(window.allow(199));
	EXPECT_TRUE(window.allow(200));
	EXPECT_FALSE(window.allow(201));
	EXPECT_EQ(window.count(), 2u);
	EXPECT_FALSE(window.allow(200));
	EXPECT_TRUE(window.allow(299));
	EXPECT_TRUE(window.allow(300));
	window.reset();
	EXPECT_TRUE(window.allow(0));
	EXPECT_TRUE(window.allow(0));
	EXPECT_FALSE(window.allow(99));
	EXPECT_TRUE(window.allow(100));
	EXPECT_TRUE(window.allow(UINT64_MAX - 1u));
	EXPECT_TRUE(window.allow(UINT64_MAX));
	EXPECT_FALSE(window.allow(0));
	EXPECT_EQ(window.count(), 2u);
	sliding_window full_duration(2, UINT64_MAX, &resource);
	EXPECT_TRUE(full_duration.allow(0));
	EXPECT_TRUE(full_duration.allow(UINT64_MAX - 1u));
	EXPECT_TRUE(full_duration.allow(UINT64_MAX));
	EXPECT_FALSE(full_duration.allow(UINT64_MAX));
	sliding_window regression(3, 100, &resource);
	EXPECT_TRUE(regression.allow(100));
	EXPECT_TRUE(regression.allow(180));
	EXPECT_FALSE(regression.allow(140));
	EXPECT_EQ(regression.count(), 2u);
	sliding_window zero(0, 1, &resource);
	EXPECT_FALSE(zero.allow(0));
	EXPECT_FALSE(zero.allow(UINT64_MAX));
	zero.reset();
	EXPECT_FALSE(zero.allow(0));
	EXPECT_EQ(zero.count(), 0u);
	EXPECT_EQ(zero.remaining(), 0u);
}

/** @brief A deque oracle proves wrap, duplicate timestamps, partial expiry and allocation-free reset. */
TEST(algo_ratelimit, sliding_window_matches_independent_event_history)
{
	for (const uint64_t quota : {0u, 1u, 2u, 3u, 64u, 65u, 257u}) {
		for (const uint64_t duration : {1u, 3u, 100u, 10000u}) {
			SCOPED_TRACE(::testing::Message() << "quota=" << quota << " duration=" << duration);
			window_resource resource;
			{
				sliding_window window(quota, duration, &resource);
				ASSERT_EQ(resource.allocations, 1u);
				resource.reject = true;
				std::deque<uint64_t> events;
				uint64_t now = 0, last = 0, random = UINT64_C(0x9e3779b97f4a7c15);
				bool bound = false;
				for (uint32_t iteration = 0; iteration < 50000u; ++iteration) {
					random ^= random << 13u;
					random ^= random >> 7u;
					random ^= random << 17u;
					if (iteration % 997u == 0) {
						window.reset();
						events.clear();
						bound = false;
					}
					const auto step = random % 37u;
					now = (random & 15u) == 0 && now > step ? now - step : now + step;
					bool expected = false;
					if (!bound || now >= last) {
						bound = true;
						last = now;
						while (!events.empty() && now - events.front() >= duration) {
							events.pop_front();
						}
						if (events.size() < quota) {
							events.push_back(now);
							expected = true;
						}
					}
					ASSERT_EQ(window.allow(now), expected) << iteration;
					ASSERT_EQ(window.count(), events.size()) << iteration;
					ASSERT_EQ(window.remaining(), quota - events.size()) << iteration;
				}
				EXPECT_EQ(resource.allocations, 1u);
			}
			EXPECT_EQ(resource.deallocations, 1u);
		}
	}
}

}  // namespace kinetum::algo
