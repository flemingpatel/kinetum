// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_runtime_command.cpp
 * @brief Exact one-load worker transition/stop publication tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <thread>
#include <utility>

#include "src/common/status.hpp"
#include "src/dp/worker_runtime_command.hpp"

namespace kinetum::dp
{

/** @brief Prove immutable alternation, completion gating, and STOP exactness. */
TEST(worker_runtime_command, alternating_records_require_global_completion_before_reuse)
{
	auto commands_or = worker_runtime_command_publication::create(1u);
	ASSERT_TRUE(commands_or.is_ok()) << commands_or.error().message();
	auto commands = std::move(commands_or).value();
	const auto *baseline = commands->observe();
	ASSERT_NE(baseline, nullptr);
	EXPECT_TRUE(baseline->valid());
	EXPECT_EQ(baseline->kind, worker_runtime_command_kind::RUN);

	ASSERT_TRUE(commands->preflight_transition(2u, 1u, 2u).is_ok());
	commands->publish_transition_or_terminate(2u, 1u, 2u);
	const auto *first = commands->observe();
	ASSERT_NE(first, baseline);
	EXPECT_EQ(first->transition_generation, 2u);
	EXPECT_EQ(commands->preflight_transition(3u, 2u, 3u).code(), common::status_code::FAILED_PRECONDITION);
	commands->complete_transition_or_terminate(2u);

	ASSERT_TRUE(commands->preflight_transition(3u, 2u, 3u).is_ok());
	commands->publish_transition_or_terminate(3u, 2u, 3u);
	const auto *second = commands->observe();
	ASSERT_NE(second, first);
	commands->complete_transition_or_terminate(3u);

	ASSERT_TRUE(commands->preflight_transition(4u, 3u, 4u).is_ok());
	commands->publish_transition_or_terminate(4u, 3u, 4u);
	const auto *third = commands->observe();
	EXPECT_EQ(third, first);
	EXPECT_EQ(third->transition_generation, 4u);
	EXPECT_EQ(third->from_epoch, 3u);
	EXPECT_EQ(third->to_epoch, 4u);
	commands->complete_transition_or_terminate(4u);

	commands->publish_transition_or_terminate(5u, 4u, 5u);
	commands->request_stop();
	commands->request_stop();
	const auto *stop = commands->observe();
	ASSERT_NE(stop, nullptr);
	EXPECT_TRUE(stop->valid());
	EXPECT_EQ(stop->kind, worker_runtime_command_kind::STOP);
	for (int observation = 0; observation < 3; ++observation) {
		EXPECT_EQ(commands->observe(), stop);
	}
	// RETIRING shutdown closes packet admission first, then still resolves the
	// exact transition generation after old-object reclamation.
	commands->complete_transition_or_terminate(5u);
	EXPECT_EQ(commands->preflight_transition(5u, 4u, 5u).code(), common::status_code::FAILED_PRECONDITION);
}

/** @brief Prove acquire readers observe only complete immutable command records. */
TEST(worker_runtime_command, concurrent_observation_never_exposes_partial_transition_identity)
{
	auto commands_or = worker_runtime_command_publication::create(7u);
	ASSERT_TRUE(commands_or.is_ok()) << commands_or.error().message();
	auto commands = std::move(commands_or).value();
	std::atomic<bool> start{false};
	std::atomic<bool> done{false};
	std::atomic<bool> malformed{false};
	std::thread reader([&] {
		while (!start.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
		while (!done.load(std::memory_order_acquire)) {
			const auto *observed = commands->observe();
			if (observed == nullptr || !observed->valid() || observed->runtime_generation != 7u) {
				malformed.store(true, std::memory_order_release);
				return;
			}
		}
	});
	start.store(true, std::memory_order_release);
	commands->publish_transition_or_terminate(11u, 9u, 10u);
	commands->complete_transition_or_terminate(11u);
	commands->publish_transition_or_terminate(12u, 10u, 12u);
	commands->complete_transition_or_terminate(12u);
	commands->request_stop();
	done.store(true, std::memory_order_release);
	reader.join();
	EXPECT_FALSE(malformed.load(std::memory_order_acquire));
}

/** @brief Prove unresolved transition publication cannot disappear silently. */
TEST(worker_runtime_command, unresolved_publication_destruction_is_terminate_class)
{
	EXPECT_DEATH(
		{
			auto commands_or = worker_runtime_command_publication::create(1u);
			if (!commands_or.is_ok()) {
				std::_Exit(71);
			}
			auto commands = std::move(commands_or).value();
			commands->publish_transition_or_terminate(2u, 1u, 2u);
			commands->request_stop();
			commands.reset();
			std::_Exit(72);
		},
		"");
}

}  // namespace kinetum::dp
