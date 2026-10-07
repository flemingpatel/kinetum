// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_perf_regression.cpp
 * @brief Baseline performance regression guards for core hot-path primitives.
 * @author Fleming Patel
 *
 * These are coarse budget tests, not microbenchmarks. They are intentionally
 * generous and only fail on severe regressions.
 */

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>

#include <kinetum/algo/queue.hpp>
#include "src/dp/epoch/ordered_cut.hpp"

namespace
{

/**
 * @brief Verify SPSC ring push pop budget.
 */
TEST(perf_regression, spsc_ring_push_pop_budget)
{
	constexpr uint64_t OPS = 1000000;
	kinetum::algo::spsc_ring_static<uint64_t, 4096> ring;

	uint64_t produced = 0;
	uint64_t consumed = 0;
	uint64_t value = 0;

	const auto t0 = std::chrono::steady_clock::now();
	while (consumed < OPS) {
		if (produced < OPS && ring.try_push(produced)) {
			++produced;
		}
		if (ring.try_pop(value)) {
			++consumed;
		}
	}
	const auto t1 = std::chrono::steady_clock::now();
	const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

	EXPECT_LT(elapsed_ms, 5000) << "spsc_ring push/pop exceeded coarse regression budget";
}

/**
 * @brief Verify owner-local successful DATA sequence budget.
 */
TEST(perf_regression, boundary_data_sequence_budget)
{
	constexpr uint64_t OPS = 1000000;
	kinetum::dp::successful_data_sequence sequence;

	uint64_t recorded = 0;
	const auto t0 = std::chrono::steady_clock::now();
	for (uint64_t i = 0; i < OPS; ++i) {
		if (sequence.record_success()) {
			++recorded;
		}
	}
	const auto t1 = std::chrono::steady_clock::now();
	const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

	EXPECT_EQ(recorded, OPS);
	EXPECT_EQ(sequence.value(), OPS);
	EXPECT_LT(elapsed_ms, 2000) << "boundary DATA sequence exceeded coarse regression budget";
}

}  // namespace
