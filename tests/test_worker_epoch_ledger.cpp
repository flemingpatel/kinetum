// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_epoch_ledger.cpp
 * @brief Exact worker-local packet-work accounting and publication tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <thread>
#include <type_traits>
#include <utility>

#include <kinetum/algo/platform.hpp>
#include "src/common/status.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"

namespace kinetum::dp
{
namespace
{

/** Exact worker owning the ledger fixture. */
constexpr uint32_t TEST_WORKER_INDEX = 3u;
/** Materialized generation bound to ledger observations. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 7u;
/** Initial epoch bound by ledger fixtures. */
constexpr uint64_t TEST_BOOTSTRAP_EPOCH = 11u;
/** Exact maximum unretired-credit population. */
constexpr uint64_t TEST_CREDIT_LIMIT = 8u;

static_assert(!std::is_copy_constructible_v<worker_epoch_ledger>);
static_assert(!std::is_copy_assignable_v<worker_epoch_ledger>);
static_assert(!std::is_move_constructible_v<worker_epoch_ledger>);
static_assert(!std::is_move_assignable_v<worker_epoch_ledger>);

/** @brief Pin exact synchronous, timer, async, and bounded-handoff budget arithmetic. */
TEST(worker_epoch_ledger, compiled_credit_budget_has_exact_async_handoff_terms)
{
	const auto first = compile_worker_epoch_credit_budget({
		.packet_storage_capacity = 100u,
		.synchronous_event_capacity = 5u,
		.timer_capacity = 7u,
		.async_work_capacity = 9u,
		.handoff_limit = 4u,
	});
	ASSERT_TRUE(first.is_ok()) << first.error().message();
	EXPECT_EQ(first->timer_handoff_capacity, 4u);
	EXPECT_EQ(first->async_handoff_capacity, 4u);
	EXPECT_EQ(first->total, 129u);

	const auto bounded = compile_worker_epoch_credit_budget({
		.packet_storage_capacity = 1u,
		.synchronous_event_capacity = 0u,
		.timer_capacity = 70u,
		.async_work_capacity = 130u,
		.handoff_limit = 64u,
	});
	ASSERT_TRUE(bounded.is_ok()) << bounded.error().message();
	EXPECT_EQ(bounded->timer_handoff_capacity, 64u);
	EXPECT_EQ(bounded->async_handoff_capacity, 64u);
	EXPECT_EQ(bounded->total, 329u);

	const auto synchronous = compile_worker_epoch_credit_budget({
		.packet_storage_capacity = 512u,
		.synchronous_event_capacity = 1u,
		.timer_capacity = 8u,
		.async_work_capacity = 0u,
		.handoff_limit = 64u,
	});
	ASSERT_TRUE(synchronous.is_ok()) << synchronous.error().message();
	EXPECT_EQ(synchronous->total, 529u);

	EXPECT_FALSE(compile_worker_epoch_credit_budget(
			     {
				     .packet_storage_capacity = std::numeric_limits<uint64_t>::max(),
				     .synchronous_event_capacity = 1u,
				     .timer_capacity = 0u,
				     .async_work_capacity = 0u,
				     .handoff_limit = 64u,
			     })
			     .is_ok());
	EXPECT_FALSE(compile_worker_epoch_credit_budget({.handoff_limit = 64u}).is_ok());
}

/**
 * @brief Construct one exact test ledger or report its unexpected failure.
 *
 * @param maximum_unretired Exact credit ceiling for the test.
 * @return Unique ledger, or null after recording a test failure.
 */
[[nodiscard]] std::unique_ptr<worker_epoch_ledger> make_ledger(uint64_t maximum_unretired = TEST_CREDIT_LIMIT)
{
	auto ledger_or = worker_epoch_ledger::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, maximum_unretired);
	if (!ledger_or.is_ok()) {
		ADD_FAILURE() << ledger_or.error().message();
		return nullptr;
	}
	return std::move(ledger_or).value();
}

/** @brief Trigger an ownership operation before exact Bootstrap binding. */
void acquire_before_bind()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->acquire(TEST_BOOTSTRAP_EPOCH);
}

/** @brief Trigger publication before exact Bootstrap binding. */
void publish_before_bind()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->publish();
}

/** @brief Trigger retirement before exact Bootstrap binding. */
void retire_before_bind()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->retire(TEST_BOOTSTRAP_EPOCH);
}

/** @brief Trigger a second Bootstrap binding on one immutable owner. */
void rebind_bootstrap()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
}

/** @brief Trigger binding of the reserved epoch wrap sentinel. */
void bind_reserved_epoch()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(std::numeric_limits<uint64_t>::max());
}

/** @brief Bind a future epoch before Bootstrap establishes the active slot. */
void bind_future_before_bootstrap()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_future_epoch(TEST_BOOTSTRAP_EPOCH + 1u);
}

/** @brief Bind a stale future epoch equal to the active slot. */
void bind_stale_future_epoch()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->bind_future_epoch(TEST_BOOTSTRAP_EPOCH);
}

/** @brief Bind a competing second future epoch. */
void bind_future_epoch_twice()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->bind_future_epoch(TEST_BOOTSTRAP_EPOCH + 1u);
	ledger->bind_future_epoch(TEST_BOOTSTRAP_EPOCH + 2u);
}

/** @brief Advance source identity without one exact future binding. */
void advance_source_without_future()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->advance_source_epoch(TEST_BOOTSTRAP_EPOCH + 1u);
}

/** @brief Advance source identity twice for one committed epoch. */
void advance_source_epoch_twice()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->bind_future_epoch(TEST_BOOTSTRAP_EPOCH + 1u);
	ledger->advance_source_epoch(TEST_BOOTSTRAP_EPOCH + 1u);
	ledger->advance_source_epoch(TEST_BOOTSTRAP_EPOCH + 1u);
}

/** @brief Trigger an exact active-slot credit overflow. */
void overflow_active_slot()
{
	auto ledger = make_ledger(1u);
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->acquire(TEST_BOOTSTRAP_EPOCH);
	ledger->acquire(TEST_BOOTSTRAP_EPOCH);
}

/** @brief Trigger an active-slot retirement underflow. */
void underflow_active_slot()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->retire(TEST_BOOTSTRAP_EPOCH);
}

/** @brief Trigger a wrong-epoch acquisition against both exact slots. */
void acquire_wrong_epoch()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->acquire(TEST_BOOTSTRAP_EPOCH + 1u);
}

/** @brief Trigger a zero-epoch acquisition against one bound ledger. */
void acquire_zero_epoch()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->acquire(0u);
}

/** @brief Trigger a wrong-epoch retirement against both exact slots. */
void retire_wrong_epoch()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->retire(TEST_BOOTSTRAP_EPOCH + 1u);
}

/** @brief Trigger a zero-epoch retirement against one bound ledger. */
void retire_zero_epoch()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->retire(0u);
}

/** @brief Trigger a second retirement of one exact logical credit. */
void double_retire_active_credit()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->acquire(TEST_BOOTSTRAP_EPOCH);
	ledger->retire(TEST_BOOTSTRAP_EPOCH);
	ledger->retire(TEST_BOOTSTRAP_EPOCH);
}

/** @brief Destroy one ledger while an executable packet credit remains live. */
void destroy_live_credit()
{
	auto ledger = make_ledger();
	if (ledger == nullptr) {
		return;
	}
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->acquire(TEST_BOOTSTRAP_EPOCH);
	ledger.reset();
}

}  // namespace

/** @brief Pin exact layout and reject incomplete cold construction authority. */
TEST(worker_epoch_ledger, layout_and_configuration_are_exact)
{
	EXPECT_EQ(sizeof(worker_epoch_ledger_snapshot), kinetum::algo::CACHE_LINE_SIZE);
	EXPECT_EQ(alignof(worker_epoch_ledger_snapshot), kinetum::algo::CACHE_LINE_SIZE);
	EXPECT_EQ(sizeof(worker_epoch_ledger), 3u * kinetum::algo::CACHE_LINE_SIZE);
	EXPECT_EQ(alignof(worker_epoch_ledger), kinetum::algo::CACHE_LINE_SIZE);

	auto sentinel_worker = worker_epoch_ledger::create(std::numeric_limits<uint32_t>::max(),
							   TEST_RUNTIME_GENERATION, TEST_CREDIT_LIMIT);
	ASSERT_FALSE(sentinel_worker.is_ok());
	EXPECT_EQ(sentinel_worker.error().code(), common::status_code::INVALID_ARGUMENT);

	auto missing_generation = worker_epoch_ledger::create(TEST_WORKER_INDEX, 0u, TEST_CREDIT_LIMIT);
	ASSERT_FALSE(missing_generation.is_ok());
	EXPECT_EQ(missing_generation.error().code(), common::status_code::INVALID_ARGUMENT);

	auto unrepresentable_generation = worker_epoch_ledger::create(
		TEST_WORKER_INDEX, static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1u, TEST_CREDIT_LIMIT);
	ASSERT_FALSE(unrepresentable_generation.is_ok());
	EXPECT_EQ(unrepresentable_generation.error().code(), common::status_code::INVALID_ARGUMENT);

	auto missing_limit = worker_epoch_ledger::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, 0u);
	ASSERT_FALSE(missing_limit.is_ok());
	EXPECT_EQ(missing_limit.error().code(), common::status_code::INVALID_ARGUMENT);
}

/** @brief Prove Bootstrap publishes one exact coherent worker value. */
TEST(worker_epoch_ledger, bootstrap_publication_is_exact_and_coherent)
{
	auto ledger = make_ledger();
	ASSERT_NE(ledger, nullptr);
	worker_epoch_ledger_snapshot observation{};
	EXPECT_EQ(ledger->try_read(observation), publication_read_result::UNAVAILABLE);

	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(ledger->active_epoch(), TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(ledger->source_epoch(), TEST_BOOTSTRAP_EPOCH);
	ASSERT_EQ(ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.publication_generation, 1u);
	EXPECT_EQ(observation.runtime_generation, TEST_RUNTIME_GENERATION);
	EXPECT_EQ(observation.worker_index, TEST_WORKER_INDEX);
	EXPECT_EQ(observation.active_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observation.source_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observation.active_unretired, 0u);
	EXPECT_EQ(observation.future_epoch, 0u);
	EXPECT_EQ(observation.future_unretired, 0u);
}

/** @brief Prove a live old credit remains visible until its exact retirement. */
TEST(worker_epoch_ledger, nonzero_old_credit_cannot_publish_quiescence)
{
	auto ledger = make_ledger();
	ASSERT_NE(ledger, nullptr);
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->acquire(TEST_BOOTSTRAP_EPOCH);
	ledger->publish();

	worker_epoch_ledger_snapshot observation{};
	ASSERT_EQ(ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.active_unretired, 1u);
	EXPECT_FALSE(ledger->empty());

	ledger->retire(TEST_BOOTSTRAP_EPOCH);
	ledger->publish();
	ASSERT_EQ(ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.active_unretired, 0u);
	EXPECT_TRUE(ledger->empty());
}

/** @brief Prove future binding and source advance preserve active execution. */
TEST(worker_epoch_ledger, future_binding_and_source_advance_are_exact)
{
	auto ledger = make_ledger();
	ASSERT_NE(ledger, nullptr);
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->bind_future_epoch(TEST_BOOTSTRAP_EPOCH + 1u);
	ledger->publish();

	worker_epoch_ledger_snapshot observation{};
	ASSERT_EQ(ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.active_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observation.source_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observation.future_epoch, TEST_BOOTSTRAP_EPOCH + 1u);
	EXPECT_EQ(observation.active_unretired, 0u);
	EXPECT_EQ(observation.future_unretired, 0u);

	ledger->advance_source_epoch(TEST_BOOTSTRAP_EPOCH + 1u);
	ledger->acquire(TEST_BOOTSTRAP_EPOCH + 1u);
	ledger->publish();
	ASSERT_EQ(ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.active_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observation.source_epoch, TEST_BOOTSTRAP_EPOCH + 1u);
	EXPECT_EQ(observation.future_epoch, TEST_BOOTSTRAP_EPOCH + 1u);
	EXPECT_EQ(observation.active_unretired, 0u);
	EXPECT_EQ(observation.future_unretired, 1u);

	ASSERT_TRUE(ledger->preflight_promote_future_epoch(TEST_BOOTSTRAP_EPOCH + 1u).is_ok());
	ledger->promote_future_epoch(TEST_BOOTSTRAP_EPOCH + 1u);
	ledger->publish();
	ASSERT_EQ(ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.active_epoch, TEST_BOOTSTRAP_EPOCH + 1u);
	EXPECT_EQ(observation.source_epoch, TEST_BOOTSTRAP_EPOCH + 1u);
	EXPECT_EQ(observation.active_unretired, 1u);
	EXPECT_EQ(observation.future_epoch, 0u);
	EXPECT_EQ(observation.future_unretired, 0u);
	ledger->retire(TEST_BOOTSTRAP_EPOCH + 1u);
	ledger->publish();
}

/** @brief Prove stale or unbound epochs cannot mutate either exact slot. */
TEST(worker_epoch_ledger, wrong_or_unbound_epoch_cannot_mutate_exact_slots)
{
	EXPECT_DEATH(acquire_before_bind(), "");
	EXPECT_DEATH(retire_before_bind(), "");
	EXPECT_DEATH(acquire_zero_epoch(), "");
	EXPECT_DEATH(acquire_wrong_epoch(), "");
	EXPECT_DEATH(retire_zero_epoch(), "");
	EXPECT_DEATH(retire_wrong_epoch(), "");
}

/** @brief Prove an unbound worker cannot claim a completed observation. */
TEST(worker_epoch_ledger, unbound_worker_cannot_claim_a_completed_observation)
{
	auto ledger = make_ledger();
	ASSERT_NE(ledger, nullptr);
	worker_epoch_ledger_snapshot sentinel{
		.publication_generation = 99u,
		.runtime_generation = 98u,
		.worker_index = 97u,
		.active_epoch = 96u,
		.source_epoch = 95u,
		.active_unretired = 94u,
		.future_epoch = 93u,
		.future_unretired = 92u,
	};
	const auto before = sentinel;
	EXPECT_EQ(ledger->try_read(sentinel), publication_read_result::UNAVAILABLE);
	EXPECT_EQ(sentinel.publication_generation, before.publication_generation);
	EXPECT_EQ(sentinel.runtime_generation, before.runtime_generation);
	EXPECT_EQ(sentinel.worker_index, before.worker_index);
	EXPECT_EQ(sentinel.active_epoch, before.active_epoch);
	EXPECT_EQ(sentinel.source_epoch, before.source_epoch);
	EXPECT_EQ(sentinel.active_unretired, before.active_unretired);
	EXPECT_EQ(sentinel.future_epoch, before.future_epoch);
	EXPECT_EQ(sentinel.future_unretired, before.future_unretired);
}

/** @brief Pin direct accounting overflow, underflow, rebind, and lifetime failures. */
TEST(worker_epoch_ledger, overflow_underflow_rebind_double_retire_and_live_destruction_fail_stop)
{
	EXPECT_DEATH(publish_before_bind(), "");
	EXPECT_DEATH(rebind_bootstrap(), "");
	EXPECT_DEATH(bind_reserved_epoch(), "");
	EXPECT_DEATH(bind_future_before_bootstrap(), "");
	EXPECT_DEATH(bind_stale_future_epoch(), "");
	EXPECT_DEATH(bind_future_epoch_twice(), "");
	EXPECT_DEATH(advance_source_without_future(), "");
	EXPECT_DEATH(advance_source_epoch_twice(), "");
	EXPECT_DEATH(overflow_active_slot(), "");
	EXPECT_DEATH(underflow_active_slot(), "");
	EXPECT_DEATH(double_retire_active_credit(), "");
	EXPECT_DEATH(destroy_live_credit(), "");
}

/** @brief Prove one boundary handoff credit moves through a boundary-owned gap. */
TEST(worker_epoch_ledger, boundary_handoff_conserves_sender_and_receiver_credits)
{
	auto sender = make_ledger();
	auto receiver_or =
		worker_epoch_ledger::create(TEST_WORKER_INDEX + 1u, TEST_RUNTIME_GENERATION, TEST_CREDIT_LIMIT);
	ASSERT_NE(sender, nullptr);
	ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
	auto receiver = std::move(receiver_or).value();
	sender->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	receiver->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	worker_epoch_ledger_snapshot sender_observation{};
	worker_epoch_ledger_snapshot receiver_observation{};

	sender->acquire(TEST_BOOTSTRAP_EPOCH);
	sender->publish();
	ASSERT_EQ(sender->try_read(sender_observation), publication_read_result::AVAILABLE);
	ASSERT_EQ(receiver->try_read(receiver_observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(sender_observation.active_unretired, 1u);
	EXPECT_EQ(receiver_observation.active_unretired, 0u);

	sender->retire(TEST_BOOTSTRAP_EPOCH);
	sender->publish();
	ASSERT_EQ(sender->try_read(sender_observation), publication_read_result::AVAILABLE);
	ASSERT_EQ(receiver->try_read(receiver_observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(sender_observation.active_unretired, 0u);
	EXPECT_EQ(receiver_observation.active_unretired, 0u);

	receiver->acquire(TEST_BOOTSTRAP_EPOCH);
	receiver->publish();
	ASSERT_EQ(sender->try_read(sender_observation), publication_read_result::AVAILABLE);
	ASSERT_EQ(receiver->try_read(receiver_observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(sender_observation.active_unretired, 0u);
	EXPECT_EQ(receiver_observation.active_unretired, 1u);

	receiver->retire(TEST_BOOTSTRAP_EPOCH);
	receiver->publish();
	ASSERT_EQ(receiver->try_read(receiver_observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(receiver_observation.active_unretired, 0u);
}

/** @brief Prove each successful fan-out clone owns and retires one child credit. */
TEST(worker_epoch_ledger, clone_and_terminal_disposition_conserve_branch_credits)
{
	auto ledger = make_ledger(2u);
	ASSERT_NE(ledger, nullptr);
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	ledger->acquire(TEST_BOOTSTRAP_EPOCH);
	ledger->acquire(TEST_BOOTSTRAP_EPOCH);
	ledger->publish();

	worker_epoch_ledger_snapshot observation{};
	ASSERT_EQ(ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.active_unretired, 2u);

	ledger->retire(TEST_BOOTSTRAP_EPOCH);
	ledger->retire(TEST_BOOTSTRAP_EPOCH);
	ledger->publish();
	ASSERT_EQ(ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.active_unretired, 0u);
}

/** @brief Prove observations never combine fields from two owner publications. */
TEST(worker_epoch_ledger, concurrent_observation_is_generation_coherent)
{
	auto ledger = make_ledger(1u);
	ASSERT_NE(ledger, nullptr);
	ledger->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
	std::atomic<bool> reader_ready{false};
	std::atomic<bool> stop{false};
	std::atomic<bool> malformed{false};
	std::atomic<uint64_t> observations{0u};
	std::atomic<uint64_t> maximum_generation{0u};
	std::thread reader([&]() {
		reader_ready.store(true, std::memory_order_release);
		worker_epoch_ledger_snapshot observation{};
		while (!stop.load(std::memory_order_acquire)) {
			const auto read = ledger->try_read(observation);
			if (read == publication_read_result::UNAVAILABLE) {
				continue;
			}
			if (read != publication_read_result::AVAILABLE) {
				malformed.store(true, std::memory_order_release);
				break;
			}
			observations.fetch_add(1u, std::memory_order_relaxed);
			const uint64_t prior_generation = maximum_generation.load(std::memory_order_relaxed);
			if (observation.publication_generation > prior_generation) {
				maximum_generation.store(observation.publication_generation, std::memory_order_relaxed);
			}
			const uint64_t expected_unretired =
				(observation.publication_generation & UINT64_C(1)) == 0u ? 1u : 0u;
			if (observation.runtime_generation != TEST_RUNTIME_GENERATION ||
			    observation.worker_index != TEST_WORKER_INDEX ||
			    observation.active_epoch != TEST_BOOTSTRAP_EPOCH ||
			    observation.source_epoch != TEST_BOOTSTRAP_EPOCH ||
			    observation.active_unretired != expected_unretired || observation.future_epoch != 0u ||
			    observation.future_unretired != 0u) {
				malformed.store(true, std::memory_order_release);
				break;
			}
		}
	});

	const auto ready_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
	while (!reader_ready.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < ready_deadline) {
		std::this_thread::yield();
	}
	const auto initial_observation_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
	while (observations.load(std::memory_order_relaxed) == 0u &&
	       std::chrono::steady_clock::now() < initial_observation_deadline) {
		std::this_thread::yield();
	}

	for (std::size_t iteration = 0; iteration < 10'000u; ++iteration) {
		ledger->acquire(TEST_BOOTSTRAP_EPOCH);
		ledger->publish();
		ledger->retire(TEST_BOOTSTRAP_EPOCH);
		ledger->publish();
	}
	const auto concurrent_observation_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
	while (maximum_generation.load(std::memory_order_relaxed) <= 1u &&
	       std::chrono::steady_clock::now() < concurrent_observation_deadline) {
		std::this_thread::yield();
	}
	stop.store(true, std::memory_order_release);
	reader.join();
	EXPECT_TRUE(reader_ready.load(std::memory_order_relaxed));
	EXPECT_FALSE(malformed.load(std::memory_order_acquire));
	EXPECT_GT(observations.load(std::memory_order_relaxed), 0u);
	EXPECT_GT(maximum_generation.load(std::memory_order_relaxed), 1u);
}

}  // namespace kinetum::dp
