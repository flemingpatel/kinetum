// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_epoch_transition_command_mailbox.cpp
 * @brief Unit tests for plan-sized command and process-event ownership.
 * @author Fleming Patel
 *
 * These tests pin role-correct capacity, fixed pointer records, linear stack
 * context lifetime, bounded exhaustion, wake coalescing, sole-consumer thread
 * identity, terminal admission closure, fail-stop destruction, and the
 * descriptor-driven command/signal process loop.
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <pthread.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "src/common/status.hpp"
#include "src/common/runtime_service_ids.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/dp_control_event_loop.hpp"
#include "src/dp/epoch/epoch_transition_command_mailbox.hpp"

namespace kinetum::dp
{
namespace
{

/** @brief Test context carrying one consumer-written scalar result. */
class mailbox_test_context final : public epoch_transition_command_context {
    public:
	uint32_t result{0};  ///< Consumer-owned value published before completion.
};

/**
 * @brief Build one exact coordinator/executor topology for mailbox construction.
 *
 * @param coordinator_capacity Exact coordinator command slots.
 * @param executor_capacity Exact lifecycle-executor command slots.
 * @return Complete role-indexed runtime-service topology.
 */
common::compiled_transition_topology make_mailbox_topology(uint32_t coordinator_capacity = 2u,
							   uint32_t executor_capacity = 0u)
{
	common::compiled_transition_topology topology;
	topology.runtime_services.push_back(common::compiled_runtime_service{
		.service_id = std::string(common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID),
		.service_index = 0u,
		.role = common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR,
		.cpu_core_id = 0,
		.numa_node = 0,
		.command_mailbox_capacity = coordinator_capacity,
	});
	topology.runtime_services.push_back(common::compiled_runtime_service{
		.service_id = common::runtime_services::make_lifecycle_executor_id(0),
		.service_index = 1u,
		.role = common::compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR,
		.cpu_core_id = 1,
		.numa_node = 0,
		.command_mailbox_capacity = executor_capacity,
	});
	topology.lifecycle_services = common::compiled_lifecycle_service_topology{
		.coordinator_service_index = 0u,
		.lifecycle_executor_service_indices = {1u},
	};
	return topology;
}

}  // namespace

/** @brief Verify mailbox construction independently enforces both service directions. */
TEST(epoch_transition_command_mailbox, topology_owns_exact_role_correct_capacity)
{
	auto mailbox_or = epoch_transition_command_mailbox::create(make_mailbox_topology(64u, 0u));
	ASSERT_TRUE(mailbox_or.is_ok()) << mailbox_or.error().message();
	EXPECT_EQ(mailbox_or.value()->capacity(), 64u);
	EXPECT_TRUE(mailbox_or.value()->ready_for_generation_adoption());

	for (const uint32_t invalid : {0u, 1u, 3u, 65u, 128u}) {
		auto invalid_or = epoch_transition_command_mailbox::create(make_mailbox_topology(invalid, 0u));
		EXPECT_FALSE(invalid_or.is_ok());
	}
	auto executor_owned_or = epoch_transition_command_mailbox::create(make_mailbox_topology(2u, 2u));
	EXPECT_FALSE(executor_owned_or.is_ok());
	auto misplaced_coordinator = make_mailbox_topology();
	misplaced_coordinator.lifecycle_services->coordinator_service_index = 1u;
	EXPECT_FALSE(epoch_transition_command_mailbox::create(misplaced_coordinator).is_ok());
	auto misplaced_executor = make_mailbox_topology();
	misplaced_executor.lifecycle_services->lifecycle_executor_service_indices[0] = 0u;
	EXPECT_FALSE(epoch_transition_command_mailbox::create(misplaced_executor).is_ok());
}

/** @brief Verify exact capacity, FIFO transfer, coalesced wake, and context resolution. */
TEST(epoch_transition_command_mailbox, full_mailbox_rejects_before_context_transfer)
{
	auto mailbox_or = epoch_transition_command_mailbox::create(make_mailbox_topology());
	ASSERT_TRUE(mailbox_or.is_ok()) << mailbox_or.error().message();
	auto mailbox = std::move(mailbox_or).value();
	ASSERT_TRUE(mailbox->bind_consumer_to_current_thread().is_ok());
	EXPECT_EQ(mailbox->bind_consumer_to_current_thread().code(), common::status_code::FAILED_PRECONDITION);
	EXPECT_FALSE(mailbox->ready_for_generation_adoption());
	mailbox_test_context invalid_kind_context;
	const auto invalid_kind = mailbox->submit(epoch_transition_command{
		static_cast<epoch_transition_command_kind>(UINT8_C(0xff)), &invalid_kind_context});
	EXPECT_EQ(invalid_kind.code(), common::status_code::INVALID_ARGUMENT);

	std::array<mailbox_test_context, 3> contexts{};
	std::array<common::status_code, 3> codes{
		common::status_code::UNKNOWN,
		common::status_code::UNKNOWN,
		common::status_code::UNKNOWN,
	};
	std::atomic<uint32_t> attempted{0u};
	std::thread first([&] {
		const auto status =
			mailbox->submit(epoch_transition_command{epoch_transition_command_kind::STATUS, &contexts[0]});
		codes[0] = status.code();
		attempted.store(1u, std::memory_order_release);
		if (status.is_ok()) {
			contexts[0].wait_for_completion();
		}
	});
	while (attempted.load(std::memory_order_acquire) != 1u) {
		std::this_thread::yield();
	}
	if (codes[0] != common::status_code::OK) {
		first.join();
		mailbox->close_admission();
		ADD_FAILURE() << "first command submission failed unexpectedly";
		return;
	}
	std::thread second([&] {
		const auto status =
			mailbox->submit(epoch_transition_command{epoch_transition_command_kind::ABORT, &contexts[1]});
		codes[1] = status.code();
		attempted.store(2u, std::memory_order_release);
		if (status.is_ok()) {
			contexts[1].wait_for_completion();
		}
	});
	while (attempted.load(std::memory_order_acquire) != 2u) {
		std::this_thread::yield();
	}
	if (codes[1] != common::status_code::OK) {
		epoch_transition_command cleanup;
		if (!mailbox->consume_notification().is_ok() || !mailbox->try_take(cleanup)) {
			std::terminate();
		}
		mailbox->complete(cleanup.context);
		first.join();
		second.join();
		mailbox->close_admission();
		ADD_FAILURE() << "second command submission failed unexpectedly";
		return;
	}
	std::thread third([&] {
		const auto status =
			mailbox->submit(epoch_transition_command{epoch_transition_command_kind::PREPARE, &contexts[2]});
		codes[2] = status.code();
	});
	third.join();
	EXPECT_EQ(codes[2], common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(mailbox->unresolved_count(), 2u);

	const auto notification_or = mailbox->consume_notification();
	ASSERT_TRUE(notification_or.is_ok());
	EXPECT_EQ(notification_or.value(), 2u);
	epoch_transition_command command;
	ASSERT_TRUE(mailbox->try_take(command));
	EXPECT_EQ(command.context, &contexts[0]);
	contexts[0].result = 11u;
	mailbox->complete(command.context);
	mailbox->defer_notifications(notification_or.value() - 1u);
	const auto deferred_or = mailbox->consume_notification();
	ASSERT_TRUE(deferred_or.is_ok());
	EXPECT_EQ(deferred_or.value(), 1u);
	ASSERT_TRUE(mailbox->try_take(command));
	EXPECT_EQ(command.context, &contexts[1]);
	contexts[1].result = 13u;
	mailbox->complete(command.context);
	EXPECT_FALSE(mailbox->try_take(command));
	first.join();
	second.join();
	EXPECT_EQ(codes[0], common::status_code::OK);
	EXPECT_EQ(codes[1], common::status_code::OK);
	EXPECT_EQ(contexts[0].result, 11u);
	EXPECT_EQ(contexts[1].result, 13u);
	EXPECT_EQ(mailbox->unresolved_count(), 0u);

	mailbox_test_context self_context;
	const auto self =
		mailbox->submit(epoch_transition_command{epoch_transition_command_kind::STATUS, &self_context});
	EXPECT_EQ(self.code(), common::status_code::FAILED_PRECONDITION);
	mailbox->close_admission();
	mailbox_test_context closed_context;
	common::status closed_status;
	std::thread closed_producer([&] {
		closed_status = mailbox->submit(
			epoch_transition_command{epoch_transition_command_kind::STATUS, &closed_context});
	});
	closed_producer.join();
	EXPECT_EQ(closed_status.code(), common::status_code::UNAVAILABLE);
}

/** @brief Verify foreign command consumption is terminate-class. */
TEST(epoch_transition_command_mailbox, foreign_consumer_cannot_mutate_queue_ownership)
{
	EXPECT_EXIT(
		{
			auto mailbox_or = epoch_transition_command_mailbox::create(make_mailbox_topology());
			if (!mailbox_or.is_ok()) {
				std::_Exit(71);
			}
			auto mailbox = std::move(mailbox_or).value();
			if (!mailbox->bind_consumer_to_current_thread().is_ok()) {
				std::_Exit(72);
			}
			std::thread foreign([&mailbox] {
				epoch_transition_command command;
				(void)mailbox->try_take(command);
			});
			foreign.join();
			std::_Exit(73);
		},
		::testing::KilledBySignal(SIGABRT), "");
}

/** @brief Verify a bound mailbox cannot discard one unresolved stack context. */
TEST(epoch_transition_command_mailbox, unresolved_context_destruction_fails_stop)
{
	EXPECT_EXIT(
		{
			auto mailbox_or = epoch_transition_command_mailbox::create(make_mailbox_topology());
			if (!mailbox_or.is_ok()) {
				std::_Exit(81);
			}
			auto mailbox = std::move(mailbox_or).value();
			if (!mailbox->bind_consumer_to_current_thread().is_ok()) {
				std::_Exit(82);
			}
			mailbox_test_context context;
			std::atomic<bool> attempted{false};
			std::atomic<bool> accepted{false};
			std::thread producer([&] {
				const auto status = mailbox->submit(
					epoch_transition_command{epoch_transition_command_kind::STATUS, &context});
				accepted.store(status.is_ok(), std::memory_order_relaxed);
				attempted.store(true, std::memory_order_release);
				if (status.is_ok()) {
					context.wait_for_completion();
				}
			});
			while (!attempted.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			if (!accepted.load(std::memory_order_relaxed)) {
				producer.join();
				std::_Exit(84);
			}
			mailbox.reset();
			producer.join();
			std::_Exit(83);
		},
		::testing::KilledBySignal(SIGABRT), "");
}

/** @brief Verify command/lifecycle fairness, deadline, and signal priority exactly. */
TEST(dp_control_event_loop, command_and_termination_share_one_owner_wait)
{
	EXPECT_EXIT(
		{
			sigset_t incomplete{};
			if (::sigemptyset(&incomplete) != 0 || ::sigaddset(&incomplete, SIGINT) != 0 ||
			    dp_control_event_loop::create(incomplete).is_ok()) {
				std::_Exit(90);
			}
			sigset_t signals{};
			if (::sigemptyset(&signals) != 0 || ::sigaddset(&signals, SIGINT) != 0 ||
			    ::sigaddset(&signals, SIGTERM) != 0 || ::sigaddset(&signals, SIGUSR1) != 0 ||
			    ::pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0) {
				std::_Exit(91);
			}
			auto loop_or = dp_control_event_loop::create(signals);
			if (!loop_or.is_ok()) {
				std::_Exit(92);
			}
			auto loop = std::move(loop_or).value();
			const int command_descriptor = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
			const int lifecycle_descriptor = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
			if (command_descriptor < 0 || lifecycle_descriptor < 0 ||
			    loop->wait(command_descriptor, command_descriptor, std::nullopt).is_ok() ||
			    ::eventfd_write(command_descriptor, 1u) != 0) {
				std::_Exit(93);
			}
			auto command_or = loop->wait(command_descriptor, lifecycle_descriptor, std::nullopt);
			if (!command_or.is_ok() || command_or->kind != dp_control_event_kind::COMMAND) {
				std::_Exit(94);
			}
			eventfd_t drained = 0;
			if (::eventfd_read(command_descriptor, &drained) != 0 ||
			    ::eventfd_write(lifecycle_descriptor, 2u) != 0) {
				std::_Exit(95);
			}
			auto lifecycle_or = loop->wait(command_descriptor, lifecycle_descriptor, std::nullopt);
			if (!lifecycle_or.is_ok() || lifecycle_or->kind != dp_control_event_kind::LIFECYCLE ||
			    ::eventfd_read(lifecycle_descriptor, &drained) != 0 || drained != 2u) {
				std::_Exit(96);
			}
			if (::eventfd_write(command_descriptor, 1u) != 0 ||
			    ::eventfd_write(lifecycle_descriptor, 1u) != 0) {
				std::_Exit(100);
			}
			auto tied_command_or = loop->wait(command_descriptor, lifecycle_descriptor, std::nullopt);
			if (!tied_command_or.is_ok() || tied_command_or->kind != dp_control_event_kind::COMMAND ||
			    ::eventfd_read(command_descriptor, &drained) != 0 || drained != 1u ||
			    ::eventfd_write(command_descriptor, 1u) != 0) {
				std::_Exit(101);
			}
			auto tied_lifecycle_or = loop->wait(command_descriptor, lifecycle_descriptor, std::nullopt);
			if (!tied_lifecycle_or.is_ok() || tied_lifecycle_or->kind != dp_control_event_kind::LIFECYCLE ||
			    ::eventfd_read(lifecycle_descriptor, &drained) != 0 || drained != 1u ||
			    ::eventfd_read(command_descriptor, &drained) != 0 || drained != 1u) {
				std::_Exit(102);
			}
			if (::eventfd_write(command_descriptor, 1u) != 0 ||
			    ::eventfd_write(lifecycle_descriptor, 1u) != 0) {
				std::_Exit(99);
			}
			const auto deadline = std::chrono::steady_clock::now() - std::chrono::nanoseconds(1);
			auto deadline_or = loop->wait(command_descriptor, lifecycle_descriptor, deadline);
			if (!deadline_or.is_ok() || deadline_or->kind != dp_control_event_kind::DEADLINE ||
			    ::eventfd_read(command_descriptor, &drained) != 0 || drained != 1u ||
			    ::eventfd_read(lifecycle_descriptor, &drained) != 0 || drained != 1u ||
			    ::kill(::getpid(), SIGUSR1) != 0) {
				std::_Exit(98);
			}
			auto reopen_deadline = loop->wait(command_descriptor, lifecycle_descriptor, deadline);
			if (!reopen_deadline.is_ok() || reopen_deadline->kind != dp_control_event_kind::DEADLINE) {
				std::_Exit(103);
			}
			auto reopen = loop->wait(command_descriptor, lifecycle_descriptor, std::nullopt);
			if (!reopen.is_ok() || reopen->kind != dp_control_event_kind::REOPEN_LOG ||
			    ::kill(::getpid(), SIGUSR1) != 0 || ::eventfd_write(command_descriptor, 1u) != 0) {
				std::_Exit(104);
			}
			auto runtime = loop->wait(command_descriptor, lifecycle_descriptor, std::nullopt);
			if (!runtime.is_ok() || runtime->kind != dp_control_event_kind::COMMAND ||
			    ::eventfd_read(command_descriptor, &drained) != 0) {
				std::_Exit(105);
			}
			auto retained_reopen = loop->wait(command_descriptor, lifecycle_descriptor, std::nullopt);
			if (!retained_reopen.is_ok() || retained_reopen->kind != dp_control_event_kind::REOPEN_LOG ||
			    ::kill(::getpid(), SIGUSR1) != 0 || ::kill(::getpid(), SIGTERM) != 0) {
				std::_Exit(106);
			}
			auto signal_or = loop->wait(command_descriptor, lifecycle_descriptor, std::nullopt);
			if (!signal_or.is_ok() || signal_or->kind != dp_control_event_kind::TERMINATE ||
			    signal_or->signal_number != SIGTERM) {
				std::_Exit(97);
			}
			(void)::close(command_descriptor);
			(void)::close(lifecycle_descriptor);
			std::_Exit(0);
		},
		::testing::ExitedWithCode(0), "");
}

}  // namespace kinetum::dp
