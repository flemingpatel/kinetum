// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_thread_affinity.cpp
 * @brief Dynamic Linux CPU-affinity ownership tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <thread>

#include "src/common/linux_cpu_set.hpp"
#include "src/dp/thread_affinity.hpp"
#include "tests/thread_affinity_test_guard.hpp"

namespace kinetum::dp
{

/** @brief Prove libc's fixed mask extent is not a logical-CPU identity ceiling. */
TEST(thread_affinity, dynamic_set_represents_sparse_identity_above_fixed_cpu_set)
{
	constexpr int32_t HIGH_CPU_ID = static_cast<int32_t>(CPU_SETSIZE) + 37;
	common::linux_cpu_set set;

	ASSERT_EQ(common::linux_cpu_set::single_cpu(HIGH_CPU_ID, set), 0);
	EXPECT_GT(set.capacity(), static_cast<std::size_t>(HIGH_CPU_ID));
	EXPECT_TRUE(set.contains(HIGH_CPU_ID));
	EXPECT_FALSE(set.contains(HIGH_CPU_ID - 1));
}

/** @brief Prove exact binding and dynamic capture agree on one allowed CPU. */
TEST(thread_affinity, binding_publishes_one_exact_allowed_cpu_and_restores_scope)
{
	test::thread_affinity_restore_guard restore;
	const auto allowed = restore.allowed_cores();
	ASSERT_FALSE(allowed.empty());
	const int32_t selected = allowed.front();

	const auto bound = bind_current_thread_to_cpu(selected, "affinity test");
	ASSERT_TRUE(bound.is_ok()) << bound.to_string();

	common::linux_cpu_set observed;
	ASSERT_EQ(common::linux_cpu_set::capture_current_thread(observed), 0);
	std::size_t selected_count = 0;
	for (std::size_t index = 0; index < observed.capacity(); ++index) {
		if (observed.contains(static_cast<int32_t>(index))) {
			++selected_count;
			EXPECT_EQ(index, static_cast<std::size_t>(selected));
		}
	}
	EXPECT_EQ(selected_count, 1u);
}

/** @brief A worker can replace inherited coordinator affinity with its distinct planned CPU. */
TEST(thread_affinity, worker_binding_replaces_inherited_single_cpu_affinity)
{
	test::thread_affinity_restore_guard restore;
	const auto allowed = restore.allowed_cores();
	ASSERT_GE(allowed.size(), 2u) << "two allowed CPUs are required for distinct coordinator and worker placement";
	ASSERT_EQ(bind_current_thread_to_cpu_raw(allowed.front()), 0);

	std::thread worker([&allowed]() {
		common::linux_cpu_set inherited;
		ASSERT_EQ(common::linux_cpu_set::capture_current_thread(inherited), 0);
		EXPECT_TRUE(inherited.contains(allowed.front()));
		EXPECT_FALSE(inherited.contains(allowed.back()));
		const auto bound = bind_current_thread_to_cpu(allowed.back(), "packet worker");
		ASSERT_TRUE(bound.is_ok()) << bound.to_string();
		common::linux_cpu_set observed;
		ASSERT_EQ(common::linux_cpu_set::capture_current_thread(observed), 0);
		EXPECT_TRUE(observed.contains(allowed.back()));
		EXPECT_FALSE(observed.contains(allowed.front()));
	});
	worker.join();
}

/** @brief Negative CPU identities reject before allocation or affinity effects. */
TEST(thread_affinity, negative_identity_rejects_at_raw_and_status_boundaries)
{
	EXPECT_EQ(bind_current_thread_to_cpu_raw(-1), EINVAL);
	const auto result = bind_current_thread_to_cpu(-1, "affinity test");
	EXPECT_EQ(result.code(), common::status_code::INVALID_ARGUMENT);
}

}  // namespace kinetum::dp
