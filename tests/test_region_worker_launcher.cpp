// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_region_worker_launcher.cpp
 * @brief Provider-neutral packet-worker launch protocol tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <span>
#include <thread>
#include <utility>
#include <vector>

#include "src/common/status.hpp"
#include "src/common/packet_thread_log_guard.hpp"
#include "src/dp/region_worker_launcher.hpp"

namespace kinetum::dp
{

namespace
{

/** Exact worker population used by launch-gate tests. */
constexpr int TEST_WORKER_COUNT = 3;
/** Expected one-bit-per-worker completion mask. */
constexpr uint32_t TEST_EXPECTED_WORKER_MASK = (1U << TEST_WORKER_COUNT) - 1U;

/** Stable compact context storage retained throughout each launch. */
using test_worker_contexts = std::array<worker_lifecycle_context, TEST_WORKER_COUNT>;

/**
 * @brief Build one valid standard-thread launch request.
 *
 * @param contexts Exact compact worker contexts.
 * @param threads Runtime-owned thread output.
 * @param run_worker Worker body entered after set-wide release.
 * @return Complete launch request.
 */
region_worker_launch_spec make_launch_spec(test_worker_contexts &contexts, std::vector<std::thread> &threads,
					   std::function<void(int)> run_worker)
{
	return region_worker_launch_spec{
		.worker_contexts = std::span<worker_lifecycle_context>(contexts),
		.threads = &threads,
		.configure_worker = {},
		.activate_worker = [](int) {},
		.commit_activation = []() {},
		.activate_packet_io = []() {},
		.publish_running_generation = []() {},
		.release_worker = {},
		.run_worker = std::move(run_worker),
	};
}

}  // namespace

/** @brief Setup, activation, packet work, and retirement share one packet-log exclusion scope. */
TEST(region_worker_launcher, packet_diagnostics_remain_excluded_for_the_complete_owner_lifetime)
{
	std_thread_worker_launcher launcher;
	test_worker_contexts contexts;
	std::vector<std::thread> threads;
	std::atomic<uint32_t> guarded{0};
	const auto before = kinetum::common::packet_thread_log_rejections();
	auto probe = [&guarded](int) {
		if (kinetum::common::reject_packet_thread_log()) {
			guarded.fetch_add(1, std::memory_order_relaxed);
		}
	};
	auto spec = make_launch_spec(contexts, threads, probe);
	spec.configure_worker = [probe](int worker) {
		probe(worker);
		return kinetum::common::status::ok();
	};
	spec.activate_worker = probe;
	spec.release_worker = probe;
	const auto launched = launcher.launch(spec);
	const auto joined = launcher.join({.threads = &threads});
	ASSERT_TRUE(launched.is_ok()) << launched.message();
	ASSERT_TRUE(joined.is_ok()) << joined.message();
	EXPECT_EQ(guarded.load(std::memory_order_relaxed), 4u * TEST_WORKER_COUNT);
	EXPECT_EQ(kinetum::common::packet_thread_log_rejections(), before + uint64_t{4} * TEST_WORKER_COUNT);
}

/** @brief Verify worker entry advances a freshly reserved context to RUNNING. */
TEST(region_worker_launcher, worker_entry_transitions_starting_to_running)
{
	worker_lifecycle_context context;
	context.set_state(worker_lifecycle_state::STARTING);

	const auto result = try_enter_worker_running(context);

	EXPECT_EQ(result, worker_enter_running_result::RUNNING);
	EXPECT_EQ(context.get_state(), worker_lifecycle_state::RUNNING);
	EXPECT_TRUE(context.request_drain());
	EXPECT_EQ(context.get_state(), worker_lifecycle_state::DRAINING);
}

/** @brief Verify worker entry preserves an exit request observed before RUNNING. */
TEST(region_worker_launcher, worker_entry_honors_exit_request_before_running)
{
	worker_lifecycle_context context;
	context.set_state(worker_lifecycle_state::STARTING);
	EXPECT_FALSE(context.request_drain());
	ASSERT_EQ(context.get_state(), worker_lifecycle_state::REQ_EXIT);

	const auto result = try_enter_worker_running(context);

	EXPECT_EQ(result, worker_enter_running_result::CANCELLED_BEFORE_RUNNING);
	EXPECT_EQ(context.get_state(), worker_lifecycle_state::EXITED);
	context.request_exit();
	EXPECT_EQ(context.get_state(), worker_lifecycle_state::EXITED);
}

/** @brief Verify worker entry fails closed on malformed lifecycle state. */
TEST(region_worker_launcher, worker_entry_rejects_unexpected_state)
{
	worker_lifecycle_context context;
	context.set_state(worker_lifecycle_state::INIT);

	const auto result = try_enter_worker_running(context);

	EXPECT_EQ(result, worker_enter_running_result::INVALID_START_STATE);
	EXPECT_EQ(context.get_state(), worker_lifecycle_state::EXITED);
}

/** @brief Verify the standard launcher resets and creates the exact compact-worker set. */
TEST(region_worker_launcher, std_thread_launcher_creates_requested_workers)
{
	std_thread_worker_launcher launcher;
	test_worker_contexts contexts;
	std::vector<std::thread> threads;
	std::atomic<uint32_t> observed_workers{0};
	for (auto &context : contexts) {
		context.set_state(worker_lifecycle_state::DRAINING);
	}
	auto spec = make_launch_spec(contexts, threads, [&observed_workers](int worker_id) {
		observed_workers.fetch_or(static_cast<uint32_t>(1U << worker_id), std::memory_order_relaxed);
	});

	auto launch_status = launcher.launch(spec);
	ASSERT_TRUE(launch_status.is_ok()) << launch_status.to_string();
	ASSERT_EQ(threads.size(), contexts.size());
	auto join_status = launcher.join(region_worker_join_spec{.threads = &threads});
	ASSERT_TRUE(join_status.is_ok()) << join_status.to_string();

	EXPECT_EQ(observed_workers.load(std::memory_order_relaxed), TEST_EXPECTED_WORKER_MASK);
	for (const auto &context : contexts) {
		EXPECT_EQ(context.get_state(), worker_lifecycle_state::EXITED);
	}
}

/** @brief Verify a setup failure releases no worker body and joins every created thread. */
TEST(region_worker_launcher, std_thread_launcher_rolls_back_failed_worker_setup)
{
	std_thread_worker_launcher launcher;
	test_worker_contexts contexts;
	std::vector<std::thread> threads;
	std::atomic<uint32_t> worker_body_calls{0};
	std::atomic<uint32_t> registered_workers{0};
	std::array<std::thread::id, TEST_WORKER_COUNT> registration_threads{};
	auto spec = make_launch_spec(contexts, threads, [&worker_body_calls](int) {
		worker_body_calls.fetch_add(1, std::memory_order_relaxed);
	});
	spec.configure_worker = [&registered_workers, &registration_threads](int worker_id) {
		if (worker_id == 1) {
			return common::status::failed_precondition("injected owner setup failure");
		}
		registration_threads[static_cast<std::size_t>(worker_id)] = std::this_thread::get_id();
		registered_workers.fetch_or(static_cast<uint32_t>(1U << worker_id), std::memory_order_release);
		return common::status::ok();
	};
	spec.release_worker = [&registered_workers, &registration_threads](int worker_id) {
		if (registration_threads[static_cast<std::size_t>(worker_id)] != std::this_thread::get_id()) {
			std::terminate();
		}
		registered_workers.fetch_and(~static_cast<uint32_t>(1U << worker_id), std::memory_order_release);
	};

	const auto launch_status = launcher.launch(spec);

	EXPECT_EQ(launch_status.code(), common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(worker_body_calls.load(std::memory_order_relaxed), 0U);
	EXPECT_EQ(registered_workers.load(std::memory_order_acquire), 0U);
	EXPECT_TRUE(threads.empty());
	for (const auto &context : contexts) {
		EXPECT_EQ(context.get_state(), worker_lifecycle_state::INIT);
	}
}

/** @brief Verify complete setup precedes activation and complete activation precedes packet work. */
TEST(region_worker_launcher, std_thread_launcher_releases_complete_activated_set)
{
	std_thread_worker_launcher launcher;
	test_worker_contexts contexts;
	std::vector<std::thread> threads;
	std::atomic<uint32_t> configured_count{0};
	std::atomic<uint32_t> activated_count{0};
	std::atomic<uint32_t> commit_count{0};
	std::atomic<uint32_t> io_activation_count{0};
	std::atomic<uint32_t> running_publication_count{0};
	std::atomic<uint32_t> fully_configured_observers{0};
	std::atomic<uint32_t> fully_activated_observers{0};
	std::atomic<uint32_t> committed_observers{0};
	std::atomic<uint32_t> ready_observers{0};
	auto spec = make_launch_spec(contexts, threads,
				     [&activated_count, &commit_count, &io_activation_count, &running_publication_count,
				      &fully_activated_observers, &committed_observers, &ready_observers](int) {
					     if (activated_count.load(std::memory_order_acquire) == TEST_WORKER_COUNT) {
						     fully_activated_observers.fetch_add(1, std::memory_order_relaxed);
					     }
					     if (commit_count.load(std::memory_order_acquire) == 1) {
						     committed_observers.fetch_add(1, std::memory_order_relaxed);
					     }
					     if (io_activation_count.load(std::memory_order_acquire) == 1 &&
						 running_publication_count.load(std::memory_order_acquire) == 1) {
						     ready_observers.fetch_add(1, std::memory_order_relaxed);
					     }
				     });
	spec.activate_worker = [&configured_count, &activated_count, &fully_configured_observers](int) {
		if (configured_count.load(std::memory_order_acquire) == TEST_WORKER_COUNT) {
			fully_configured_observers.fetch_add(1, std::memory_order_relaxed);
		}
		activated_count.fetch_add(1, std::memory_order_release);
	};
	spec.configure_worker = [&configured_count](int) {
		configured_count.fetch_add(1, std::memory_order_release);
		return common::status::ok();
	};
	spec.commit_activation = [&activated_count, &commit_count]() {
		if (activated_count.load(std::memory_order_acquire) != TEST_WORKER_COUNT) {
			std::terminate();
		}
		commit_count.fetch_add(1, std::memory_order_release);
	};
	spec.activate_packet_io = [&contexts, &commit_count, &io_activation_count]() {
		for (const auto &context : contexts) {
			if (context.get_state() != worker_lifecycle_state::RUNNING) {
				std::terminate();
			}
		}
		if (commit_count.load(std::memory_order_acquire) != 1) {
			std::terminate();
		}
		io_activation_count.fetch_add(1, std::memory_order_release);
	};
	spec.publish_running_generation = [&io_activation_count, &running_publication_count]() {
		if (io_activation_count.load(std::memory_order_acquire) != 1) {
			std::terminate();
		}
		running_publication_count.fetch_add(1, std::memory_order_release);
	};

	auto launch_status = launcher.launch(spec);
	ASSERT_TRUE(launch_status.is_ok()) << launch_status.to_string();
	auto join_status = launcher.join(region_worker_join_spec{.threads = &threads});
	ASSERT_TRUE(join_status.is_ok()) << join_status.to_string();

	EXPECT_EQ(fully_configured_observers.load(std::memory_order_relaxed), static_cast<uint32_t>(TEST_WORKER_COUNT));
	EXPECT_EQ(fully_activated_observers.load(std::memory_order_relaxed), static_cast<uint32_t>(TEST_WORKER_COUNT));
	EXPECT_EQ(commit_count.load(std::memory_order_relaxed), 1U);
	EXPECT_EQ(committed_observers.load(std::memory_order_relaxed), static_cast<uint32_t>(TEST_WORKER_COUNT));
	EXPECT_EQ(io_activation_count.load(std::memory_order_relaxed), 1U);
	EXPECT_EQ(running_publication_count.load(std::memory_order_relaxed), 1U);
	EXPECT_EQ(ready_observers.load(std::memory_order_relaxed), static_cast<uint32_t>(TEST_WORKER_COUNT));
}

/** @brief Verify launch fails before mutating a pre-owned thread vector. */
TEST(region_worker_launcher, std_thread_launcher_rejects_preowned_thread_vector)
{
	std_thread_worker_launcher launcher;
	test_worker_contexts contexts;
	std::vector<std::thread> threads;
	std::atomic<bool> stop{false};
	threads.emplace_back([&stop]() {
		while (!stop.load(std::memory_order_acquire)) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	});
	auto spec = make_launch_spec(contexts, threads, [](int) {});

	const auto launch_status = launcher.launch(spec);

	EXPECT_EQ(launch_status.code(), common::status_code::FAILED_PRECONDITION);
	stop.store(true, std::memory_order_release);
	threads.front().join();
}

/** @brief Verify malformed launch requests fail without mutating worker state. */
TEST(region_worker_launcher, std_thread_launcher_rejects_malformed_spec)
{
	std_thread_worker_launcher launcher;
	test_worker_contexts contexts;
	std::vector<std::thread> threads;
	auto spec = make_launch_spec(contexts, threads, [](int) {});
	spec.run_worker = {};

	const auto launch_status = launcher.launch(spec);

	EXPECT_EQ(launch_status.code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_TRUE(threads.empty());
	for (const auto &context : contexts) {
		EXPECT_EQ(context.get_state(), worker_lifecycle_state::INIT);
	}

	spec = make_launch_spec(contexts, threads, [](int) {});
	spec.activate_packet_io = {};
	const auto missing_io_status = launcher.launch(spec);
	EXPECT_EQ(missing_io_status.code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_TRUE(threads.empty());
}

/** @brief Verify malformed join requests fail before touching worker state. */
TEST(region_worker_launcher, std_thread_launcher_rejects_malformed_join_spec)
{
	std_thread_worker_launcher launcher;
	const region_worker_join_spec spec{};

	const auto join_status = launcher.join(spec);

	EXPECT_EQ(join_status.code(), common::status_code::INVALID_ARGUMENT);
}

}  // namespace kinetum::dp
