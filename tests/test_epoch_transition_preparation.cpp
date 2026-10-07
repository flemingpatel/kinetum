// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_epoch_transition_preparation.cpp
 * @brief Integrated tests for asynchronous PREPARE cancellation and cleanup.
 * @author Fleming Patel
 *
 * These rows exercise the production mailbox, coordinator, NUMA lifecycle
 * executor, module adapter, exact context store, result eventfd, and transient
 * preparation owner together. They intentionally isolate abortable cold
 * preparation; public activation and completion are exercised by their owning
 * runtime/service suites.
 */

#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <dlfcn.h>
#include <exception>
#include <filesystem>
#include <optional>
#include <thread>
#include <utility>

#include <poll.h>

#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/status.hpp"
#include "src/dp/epoch/epoch_transition_coordinator.hpp"
#include "src/dp/epoch/epoch_transition_preparation.hpp"
#include "tests/packet_runtime_test_fixture.hpp"

#if !defined(KINETUM_TEST_SERIALIZED_MODULE_PATH)
#error "Exact serialized test-module path is required"
#endif

namespace kinetum::dp
{
namespace
{

using kinetum::common::status_code;
using kinetum::test::packet_runtime_test_module_intent;
using kinetum::test::packet_runtime_test_owner;
using kinetum::test::packet_runtime_test_transition_timing;

/** @brief Exact lifecycle-memory bounds for the serialized test module. */
inline constexpr uint64_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = 64u * 1024u;
/** @brief Exact per-epoch arena bound for the serialized test module. */
inline constexpr uint64_t TEST_EPOCH_ARENA_CAPACITY_BYTES = 4u * 1024u;

/** @brief Scoped loader reference used only to reach test observation exports. */
class serialized_module_observer final {
    public:
	/**
	 * @brief Open the already admitted serialized module and resolve observers.
	 * @return Complete observer or a test diagnostic string.
	 */
	[[nodiscard]] static std::optional<serialized_module_observer> create()
	{
		void *handle = ::dlopen(KINETUM_TEST_SERIALIZED_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
		if (handle == nullptr) {
			return std::nullopt;
		}
		serialized_module_observer result(handle);
		result.reset_ = reinterpret_cast<reset_fn>(::dlsym(handle, "kinetum_test_serialized_reset"));
		result.hold_ = reinterpret_cast<hold_fn>(::dlsym(handle, "kinetum_test_serialized_hold_first"));
		result.entries_ = reinterpret_cast<read_fn>(::dlsym(handle, "kinetum_test_serialized_prepare_entries"));
		result.maximum_ = reinterpret_cast<read_fn>(::dlsym(handle, "kinetum_test_serialized_max_active"));
		result.cancelled_ = reinterpret_cast<read_bool_fn>(
			::dlsym(handle, "kinetum_test_serialized_cancellation_observed"));
		if (result.reset_ == nullptr || result.hold_ == nullptr || result.entries_ == nullptr ||
		    result.maximum_ == nullptr || result.cancelled_ == nullptr) {
			return std::nullopt;
		}
		return std::optional<serialized_module_observer>(std::move(result));
	}

	serialized_module_observer(const serialized_module_observer &) = delete;
	serialized_module_observer &operator=(const serialized_module_observer &) = delete;
	/**
	 * @brief Transfer one loader reference and observer table.
	 * @param other Source observer whose loader handle is transferred and cleared.
	 */
	serialized_module_observer(serialized_module_observer &&other) noexcept
		: handle_(std::exchange(other.handle_, nullptr))
		, reset_(other.reset_)
		, hold_(other.hold_)
		, entries_(other.entries_)
		, maximum_(other.maximum_)
		, cancelled_(other.cancelled_)
	{
	}
	serialized_module_observer &operator=(serialized_module_observer &&) = delete;

	/** @brief Release the test-only loader reference. */
	~serialized_module_observer()
	{
		if (handle_ != nullptr && ::dlclose(handle_) != 0) {
			std::terminate();
		}
	}

	/** @brief Reset exact module-global observations. */
	void reset() const noexcept
	{
		reset_();
	}
	/**
	 * @brief Hold or release the first subsequent PREPARE callback.
	 * @param hold Whether the module retains the first callback at its explicit gate.
	 */
	void hold_first(bool hold) const noexcept
	{
		hold_(hold);
	}
	/**
	 * @brief Drop the observer ref before releasing a runtime-owned callback.
	 *
	 * The admitted runtime retains the module image until the callback and its
	 * exact cleanup finish. Closing this test-only ref first prevents it from
	 * extending or racing the runtime's later unload authority.
	 */
	void close_before_releasing_first() noexcept
	{
		if (handle_ == nullptr) {
			std::terminate();
		}
		auto release = hold_;
		if (::dlclose(handle_) != 0) {
			std::terminate();
		}
		handle_ = nullptr;
		release(false);
	}
	/** @return Number of PREPARE callbacks that entered foreign code. */
	[[nodiscard]] uint32_t entries() const noexcept
	{
		return entries_();
	}
	/** @return Maximum concurrent callback count observed by the module. */
	[[nodiscard]] uint32_t maximum() const noexcept
	{
		return maximum_();
	}
	/** @return Whether the held callback acquired cooperative cancellation. */
	[[nodiscard]] bool cancellation_observed() const noexcept
	{
		return cancelled_();
	}

    private:
	/** Export signature resetting module concurrency observations. */
	using reset_fn = void (*)();
	/** Export signature controlling the first PREPARE gate. */
	using hold_fn = void (*)(bool);
	/** Export signature reading a module concurrency counter. */
	using read_fn = uint32_t (*)();
	/** Export signature reading observed cancellation state. */
	using read_bool_fn = bool (*)();

	/**
	 * @brief Adopt one exact loader reference before symbol resolution.
	 * @param handle Sole loaded-image reference transferred into the observer.
	 */
	explicit serialized_module_observer(void *handle) noexcept
		: handle_(handle)
	{
	}

	void *handle_{nullptr};		   ///< Test-only exact loader reference.
	reset_fn reset_{nullptr};	   ///< Reset observation export.
	hold_fn hold_{nullptr};		   ///< Callback hold/release export.
	read_fn entries_{nullptr};	   ///< Callback-entry observation export.
	read_fn maximum_{nullptr};	   ///< Maximum-concurrency observation export.
	read_bool_fn cancelled_{nullptr};  ///< Cooperative-cancellation observation export.
};

/** @return Exact serialized-module fixture intent with an empty config payload. */
[[nodiscard]] packet_runtime_test_module_intent serialized_module_intent()
{
	return {
		.module_id = "kinetum.test.serialized",
		.canonical_path = std::filesystem::path(KINETUM_TEST_SERIALIZED_MODULE_PATH),
		.config_blob = {},
		.context_memory_capacity_bytes = TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
		.epoch_arena_capacity_bytes = TEST_EPOCH_ARENA_CAPACITY_BYTES,
	};
}

/**
 * @brief Service one bounded command/lifecycle/deadline turn.
 * @param runtime Exact runtime whose coordinator is the current thread.
 * @param timeout_ms Bounded poll interval.
 */
void service_control_turn(partitioned_runtime &runtime, int timeout_ms)
{
	const auto lifecycle_descriptor = runtime.lifecycle_notification_descriptor();
	ASSERT_TRUE(lifecycle_descriptor.has_value());
	pollfd descriptors[2]{
		pollfd{.fd = runtime.command_notification_descriptor(), .events = POLLIN, .revents = 0},
		pollfd{.fd = *lifecycle_descriptor, .events = POLLIN, .revents = 0},
	};
	int result = 0;
	do {
		result = ::poll(descriptors, 2, timeout_ms);
	} while (result < 0 && errno == EINTR);
	ASSERT_GE(result, 0);
	ASSERT_EQ(descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL), 0);
	ASSERT_EQ(descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL), 0);
	if ((descriptors[0].revents & POLLIN) != 0) {
		ASSERT_TRUE(runtime.service_command_notifications().is_ok());
	}
	if ((descriptors[1].revents & POLLIN) != 0) {
		ASSERT_TRUE(runtime.service_lifecycle_notifications().is_ok());
	}
	ASSERT_TRUE(runtime.service_control_deadline().is_ok());
}

/**
 * @param deadline Absolute monotonic deadline bounding the test's polling loop.
 * @return true while the deadline has not yet elapsed.
 */
[[nodiscard]] bool before(std::chrono::steady_clock::time_point deadline) noexcept
{
	return std::chrono::steady_clock::now() < deadline;
}

/** @brief Post-cancellation SUCCESS is retired before both held commands complete. */
TEST(epoch_transition_preparation, explicit_abort_retires_post_cancellation_success_before_terminal_publication)
{
	const packet_runtime_test_transition_timing timing{
		.prepare_timeout_ms = 5000u,
		.prepare_cancel_grace_ms = 5000u,
		.prepared_lease_timeout_ms = 5000u,
		.commit_timeout_ms = 5000u,
		.retirement_timeout_ms = 5000u,
	};
	auto owner_or = packet_runtime_test_owner::create(serialized_module_intent(), timing);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());
	auto observer = serialized_module_observer::create();
	ASSERT_TRUE(observer.has_value()) << "serialized module observation exports are unavailable";
	observer->reset();
	observer->hold_first(true);

	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
	prepare.mutable_snapshot()->CopyFrom(owner->bootstrap_request().snapshot());
	prepare.set_target_epoch(2u);
	prepare.set_mutation_sequence(2u);
	prepare.set_idempotency_key("cancel-in-flight-prepare");
	auto validation_hash_or =
		common::decode_sha256_digest_claim(prepare.snapshot().content_hash(), "ConfigSnapshot.content_hash");
	ASSERT_TRUE(validation_hash_or.is_ok()) << validation_hash_or.error().message();
	const auto validation_hash = validation_hash_or.value();

	std::optional<epoch_transition_operation_result> prepare_result;
	std::atomic<bool> prepare_complete{false};
	std::thread prepare_producer([&] {
		prepare_result.emplace(owner->runtime().prepare_epoch_transition(prepare));
		prepare_complete.store(true, std::memory_order_release);
	});
	const auto entry_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	while (observer->entries() == 0u && before(entry_deadline)) {
		service_control_turn(owner->runtime(), 10);
	}
	if (observer->entries() != 1u || prepare_complete.load(std::memory_order_acquire)) {
		observer->close_before_releasing_first();
		observer.reset();
		owner->runtime().shutdown();
		prepare_producer.join();
		ADD_FAILURE() << "live PREPARE did not remain inside the held foreign callback";
		return;
	}
	const auto prepare_deadline = owner->runtime().next_control_deadline();
	if (!prepare_deadline.has_value()) {
		observer->hold_first(false);
		observer.reset();
		owner->runtime().shutdown();
		prepare_producer.join();
		ADD_FAILURE() << "held PREPARE published no behavior-driving deadline";
		return;
	}

	kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest abort;
	abort.set_epoch(prepare.target_epoch());
	abort.set_mutation_sequence(prepare.mutation_sequence());
	abort.set_validation_hash(reinterpret_cast<const char *>(validation_hash.data()), validation_hash.size());
	abort.set_idempotency_key(prepare.idempotency_key());
	std::optional<epoch_transition_operation_result> abort_result;
	std::atomic<bool> abort_complete{false};
	std::thread abort_producer([&] {
		abort_result.emplace(owner->runtime().abort_epoch_transition(abort));
		abort_complete.store(true, std::memory_order_release);
	});

	// Consume the Abort command while foreign PREPARE is still held. The
	// coordinator publishes cancellation, but neither producer can complete yet.
	const auto abort_admission_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	bool abort_serviced = false;
	while (!abort_serviced && !abort_complete.load(std::memory_order_acquire) && before(abort_admission_deadline)) {
		pollfd descriptor{
			.fd = owner->runtime().command_notification_descriptor(),
			.events = POLLIN,
			.revents = 0,
		};
		int poll_result = 0;
		do {
			poll_result = ::poll(&descriptor, 1, 10);
		} while (poll_result < 0 && errno == EINTR);
		if (poll_result < 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			break;
		}
		if ((descriptor.revents & POLLIN) != 0) {
			abort_serviced = owner->runtime().service_command_notifications().is_ok();
		}
	}
	const bool prepare_completed_early = prepare_complete.load(std::memory_order_acquire);
	const bool abort_completed_early = abort_complete.load(std::memory_order_acquire);
	if (!abort_serviced || prepare_completed_early || abort_completed_early) {
		observer->hold_first(false);
		observer.reset();
		owner->runtime().shutdown();
		prepare_producer.join();
		abort_producer.join();
		ADD_FAILURE() << "Abort admission did not hold both contexts: serviced=" << abort_serviced
			      << " prepare_completed_early=" << prepare_completed_early
			      << " abort_completed_early=" << abort_completed_early;
		return;
	}
	kinetum::dataplane::v1::GetEpochTransitionStatusRequest query;
	query.set_epoch(abort.epoch());
	query.set_mutation_sequence(abort.mutation_sequence());
	query.set_validation_hash(abort.validation_hash());
	query.set_idempotency_key(abort.idempotency_key());
	std::optional<epoch_transition_operation_result> status_result;
	std::atomic<bool> status_complete{false};
	std::thread status_producer([&] {
		status_result.emplace(owner->runtime().query_epoch_transition(query));
		status_complete.store(true, std::memory_order_release);
	});
	const auto status_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	while (!status_complete.load(std::memory_order_acquire) && before(status_deadline)) {
		service_control_turn(owner->runtime(), 10);
	}
	if (!status_complete.load(std::memory_order_acquire)) {
		observer->hold_first(false);
		observer.reset();
		owner->runtime().shutdown();
		prepare_producer.join();
		abort_producer.join();
		status_producer.join();
		ADD_FAILURE() << "Status did not resolve during transient abort cleanup";
		return;
	}
	status_producer.join();
	if (!status_result.has_value()) {
		observer->hold_first(false);
		observer.reset();
		owner->runtime().shutdown();
		prepare_producer.join();
		abort_producer.join();
		ADD_FAILURE() << "Status producer completed without an owned result";
		return;
	}
	EXPECT_EQ(status_result->code, status_code::UNAVAILABLE);
	EXPECT_EQ(status_result->observation.resolution, common::transition_identity_resolution::STATE_UNAVAILABLE);
	epoch_transition_progress_snapshot hidden_progress{};
	if (owner->runtime().try_read_transition_progress(hidden_progress) != publication_read_result::AVAILABLE) {
		observer->hold_first(false);
		observer.reset();
		owner->runtime().shutdown();
		prepare_producer.join();
		abort_producer.join();
		ADD_FAILURE() << "PREPARING progress became unavailable before ownership withdrawal";
		return;
	}
	EXPECT_EQ(hidden_progress.phase, epoch_transition_phase::PREPARING);
	observer->hold_first(false);

	const auto completion_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	while ((!prepare_complete.load(std::memory_order_acquire) || !abort_complete.load(std::memory_order_acquire)) &&
	       before(completion_deadline)) {
		service_control_turn(owner->runtime(), 10);
	}
	if (!prepare_complete.load(std::memory_order_acquire) || !abort_complete.load(std::memory_order_acquire)) {
		observer.reset();
		owner->runtime().shutdown();
		prepare_producer.join();
		abort_producer.join();
		ADD_FAILURE() << "held Prepare/Abort contexts did not complete after exact RETIRE";
		return;
	}
	prepare_producer.join();
	abort_producer.join();
	ASSERT_TRUE(prepare_result.has_value());
	ASSERT_TRUE(abort_result.has_value());
	ASSERT_TRUE(prepare_result->is_ok());
	ASSERT_TRUE(abort_result->is_ok());
	EXPECT_EQ(prepare_result->observation.outcome, epoch_transition_outcome::ABORTED);
	EXPECT_EQ(abort_result->observation.outcome, epoch_transition_outcome::ABORTED);
	EXPECT_EQ(prepare_result->observation.failure_code, epoch_transition_failure_code::EXPLICIT_ABORT);
	EXPECT_EQ(abort_result->observation.failure_code, epoch_transition_failure_code::EXPLICIT_ABORT);
	EXPECT_EQ(observer->entries(), 1u);
	EXPECT_EQ(observer->maximum(), 1u);

	epoch_transition_progress_snapshot progress{};
	ASSERT_EQ(owner->runtime().try_read_transition_progress(progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(progress.phase, epoch_transition_phase::IDLE);
	EXPECT_EQ(progress.active_epoch, owner->bootstrap_request().active_epoch());
	EXPECT_EQ(progress.last_terminal_outcome, epoch_transition_outcome::ABORTED);
}

/** @brief Monotonic PREPARED lease expiry retires ownership before terminal publication. */
TEST(epoch_transition_preparation, prepared_lease_expiry_is_monotonic_and_cleanup_complete)
{
	using clock = std::chrono::steady_clock;
	EXPECT_FALSE(checked_transition_deadline(clock::now(), clock::duration::zero()).is_ok());
	EXPECT_FALSE(
		checked_transition_deadline(clock::time_point::max() - clock::duration{1}, clock::duration{2}).is_ok());
	EXPECT_TRUE(checked_transition_deadline(clock::time_point::min(), clock::duration{1}).is_ok());

	const packet_runtime_test_transition_timing timing{
		.prepare_timeout_ms = 500u,
		.prepare_cancel_grace_ms = 100u,
		.prepared_lease_timeout_ms = 500u,
		.commit_timeout_ms = 500u,
		.retirement_timeout_ms = 500u,
	};
	auto owner_or = packet_runtime_test_owner::create(serialized_module_intent(), timing);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());

	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
	prepare.mutable_snapshot()->CopyFrom(owner->bootstrap_request().snapshot());
	prepare.set_target_epoch(2u);
	prepare.set_mutation_sequence(2u);
	prepare.set_idempotency_key("prepared-lease-expiry");
	const auto prepared =
		owner->run_control_producer([&]() { return owner->runtime().prepare_epoch_transition(prepare); });
	ASSERT_TRUE(prepared.is_ok());
	ASSERT_EQ(prepared.observation.phase, epoch_transition_phase::PREPARED);
	ASSERT_EQ(prepared.observation.lease_state, epoch_transition_prepared_lease_state::ARMED);
	ASSERT_NE(prepared.observation.prepared_lease_deadline_monotonic_ns, 0u);
	ASSERT_NE(prepared.observation.prepared_lease_deadline_unix_ms, 0u);

	const auto expiry_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	epoch_transition_progress_snapshot progress{};
	bool invalid_publication = false;
	while (before(expiry_deadline)) {
		service_control_turn(owner->runtime(), 10);
		const auto read = owner->runtime().try_read_transition_progress(progress);
		invalid_publication = invalid_publication || (read != publication_read_result::AVAILABLE &&
							      read != publication_read_result::UNAVAILABLE);
		if (read == publication_read_result::AVAILABLE && progress.phase == epoch_transition_phase::IDLE) {
			break;
		}
	}
	EXPECT_FALSE(invalid_publication);
	ASSERT_EQ(owner->runtime().try_read_transition_progress(progress), publication_read_result::AVAILABLE);
	ASSERT_EQ(progress.phase, epoch_transition_phase::IDLE);
	EXPECT_EQ(progress.active_epoch, owner->bootstrap_request().active_epoch());
	EXPECT_EQ(progress.last_terminal_outcome, epoch_transition_outcome::ABORTED);

	kinetum::dataplane::v1::GetEpochTransitionStatusRequest query;
	query.set_epoch(prepared.observation.identity.target_epoch);
	query.set_mutation_sequence(prepared.observation.identity.mutation_sequence);
	query.set_validation_hash(reinterpret_cast<const char *>(prepared.observation.identity.validation_hash.data()),
				  prepared.observation.identity.validation_hash.size());
	query.set_idempotency_key(prepare.idempotency_key());
	const auto terminal =
		owner->run_control_producer([&]() { return owner->runtime().query_epoch_transition(query); });
	ASSERT_TRUE(terminal.is_ok());
	EXPECT_EQ(terminal.observation.resolution, common::transition_identity_resolution::TERMINAL_EXACT);
	EXPECT_EQ(terminal.observation.outcome, epoch_transition_outcome::ABORTED);
	EXPECT_EQ(terminal.observation.failure_code, epoch_transition_failure_code::PREPARED_LEASE_EXPIRED);
	EXPECT_EQ(terminal.observation.prepare_duration_ns, prepared.observation.prepare_duration_ns);
	EXPECT_EQ(terminal.observation.duration_presence, TRANSITION_PREPARE_DURATION_PRESENT);
}

/** @brief Shutdown cancels and resolves one held PREPARE context before teardown. */
TEST(epoch_transition_preparation, shutdown_resolves_held_prepare_context_after_exact_cleanup)
{
	const packet_runtime_test_transition_timing timing{
		.prepare_timeout_ms = 5000u,
		.prepare_cancel_grace_ms = 5000u,
		.prepared_lease_timeout_ms = 5000u,
		.commit_timeout_ms = 5000u,
		.retirement_timeout_ms = 5000u,
	};
	auto owner_or = packet_runtime_test_owner::create(serialized_module_intent(), timing);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());
	auto observer = serialized_module_observer::create();
	ASSERT_TRUE(observer.has_value()) << "serialized module observation exports are unavailable";
	observer->reset();
	observer->hold_first(true);

	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
	prepare.mutable_snapshot()->CopyFrom(owner->bootstrap_request().snapshot());
	prepare.set_target_epoch(2u);
	prepare.set_mutation_sequence(2u);
	prepare.set_idempotency_key("shutdown-held-prepare");
	std::optional<epoch_transition_operation_result> prepare_result;
	std::atomic<bool> prepare_complete{false};
	std::thread prepare_producer([&] {
		prepare_result.emplace(owner->runtime().prepare_epoch_transition(prepare));
		prepare_complete.store(true, std::memory_order_release);
	});

	const auto entry_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	while (observer->entries() == 0u && before(entry_deadline)) {
		service_control_turn(owner->runtime(), 10);
	}
	if (observer->entries() != 1u || prepare_complete.load(std::memory_order_acquire)) {
		observer->hold_first(false);
		observer.reset();
		owner->runtime().shutdown();
		prepare_producer.join();
		ADD_FAILURE() << "live PREPARE did not remain held for shutdown cancellation";
		return;
	}

	bool cancellation_seen = false;
	std::thread callback_releaser([&] {
		const auto cancellation_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
		while (!observer->cancellation_observed() && before(cancellation_deadline)) {
			std::this_thread::yield();
		}
		cancellation_seen = observer->cancellation_observed();
		observer->close_before_releasing_first();
		observer.reset();
	});
	owner->runtime().shutdown();
	callback_releaser.join();
	prepare_producer.join();

	ASSERT_TRUE(cancellation_seen);
	ASSERT_TRUE(prepare_complete.load(std::memory_order_acquire));
	ASSERT_TRUE(prepare_result.has_value());
	ASSERT_TRUE(prepare_result->is_ok());
	EXPECT_EQ(prepare_result->observation.resolution, common::transition_identity_resolution::TERMINAL_EXACT);
	EXPECT_EQ(prepare_result->observation.outcome, epoch_transition_outcome::ABORTED);
	EXPECT_EQ(prepare_result->observation.failure_code, epoch_transition_failure_code::SHUTDOWN_ABORT);
	epoch_transition_progress_snapshot progress{};
	ASSERT_EQ(owner->runtime().try_read_transition_progress(progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(progress.phase, epoch_transition_phase::IDLE);
	EXPECT_EQ(progress.last_terminal_outcome, epoch_transition_outcome::ABORTED);
}

/** @brief Late SUCCESS cleans exactly; a callback past grace remains process-fatal. */
TEST(epoch_transition_preparation, prepare_deadline_retires_late_success_and_nonreturning_callback_is_fatal)
{
	{
		const packet_runtime_test_transition_timing timing{
			.prepare_timeout_ms = 500u,
			.prepare_cancel_grace_ms = 500u,
			.prepared_lease_timeout_ms = 5000u,
			.commit_timeout_ms = 5000u,
			.retirement_timeout_ms = 5000u,
		};
		auto owner_or = packet_runtime_test_owner::create(serialized_module_intent(), timing);
		ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
		auto owner = std::move(owner_or).value();
		ASSERT_TRUE(owner->bootstrap().is_ok());
		auto observer = serialized_module_observer::create();
		ASSERT_TRUE(observer.has_value()) << "serialized module observation exports are unavailable";
		observer->reset();
		observer->hold_first(true);

		kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
		prepare.mutable_snapshot()->CopyFrom(owner->bootstrap_request().snapshot());
		prepare.set_target_epoch(2u);
		prepare.set_mutation_sequence(2u);
		prepare.set_idempotency_key("late-prepare-success");
		std::optional<epoch_transition_operation_result> prepare_result;
		std::atomic<bool> prepare_complete{false};
		std::thread prepare_producer([&] {
			prepare_result.emplace(owner->runtime().prepare_epoch_transition(prepare));
			prepare_complete.store(true, std::memory_order_release);
		});

		const auto entry_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
		while (observer->entries() == 0u && before(entry_deadline)) {
			service_control_turn(owner->runtime(), 10);
		}
		const auto prepare_deadline = owner->runtime().next_control_deadline();
		if (observer->entries() != 1u || !prepare_deadline.has_value() ||
		    prepare_complete.load(std::memory_order_acquire)) {
			observer->close_before_releasing_first();
			observer.reset();
			owner->runtime().shutdown();
			prepare_producer.join();
			ADD_FAILURE() << "late-success fixture did not hold one deadline-bound PREPARE";
			return;
		}

		const auto wait_bound = std::chrono::steady_clock::now() + std::chrono::seconds(2);
		while (std::chrono::steady_clock::now() < *prepare_deadline && before(wait_bound)) {
			std::this_thread::yield();
		}
		if (std::chrono::steady_clock::now() < *prepare_deadline) {
			observer->close_before_releasing_first();
			observer.reset();
			owner->runtime().shutdown();
			prepare_producer.join();
			ADD_FAILURE() << "authored PREPARE deadline exceeded the bounded test interval";
			return;
		}
		observer->close_before_releasing_first();
		observer.reset();

		const auto terminal_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
		while (!prepare_complete.load(std::memory_order_acquire) && before(terminal_deadline)) {
			service_control_turn(owner->runtime(), 10);
		}
		if (!prepare_complete.load(std::memory_order_acquire)) {
			owner->runtime().shutdown();
			prepare_producer.join();
			ADD_FAILURE() << "late PREPARE success did not complete exact deadline cleanup";
			return;
		}
		prepare_producer.join();
		ASSERT_TRUE(prepare_result.has_value());
		ASSERT_TRUE(prepare_result->is_ok());
		EXPECT_EQ(prepare_result->observation.resolution,
			  common::transition_identity_resolution::TERMINAL_EXACT);
		EXPECT_EQ(prepare_result->observation.outcome, epoch_transition_outcome::ABORTED);
		EXPECT_EQ(prepare_result->observation.failure_code,
			  epoch_transition_failure_code::PREPARE_DEADLINE_EXCEEDED);
		epoch_transition_progress_snapshot progress{};
		ASSERT_EQ(owner->runtime().try_read_transition_progress(progress), publication_read_result::AVAILABLE);
		EXPECT_EQ(progress.phase, epoch_transition_phase::IDLE);
		EXPECT_EQ(progress.last_terminal_outcome, epoch_transition_outcome::ABORTED);
		owner->runtime().shutdown();
	}

	const packet_runtime_test_transition_timing fatal_timing{
		.prepare_timeout_ms = 500u,
		.prepare_cancel_grace_ms = 100u,
		.prepared_lease_timeout_ms = 500u,
		.commit_timeout_ms = 500u,
		.retirement_timeout_ms = 500u,
	};
	EXPECT_EXIT(
		{
			auto owner_or = packet_runtime_test_owner::create(serialized_module_intent(), fatal_timing);
			if (!owner_or.is_ok()) {
				std::_Exit(81);
			}
			auto owner = std::move(owner_or).value();
			if (!owner->bootstrap().is_ok()) {
				std::_Exit(82);
			}
			auto observer = serialized_module_observer::create();
			if (!observer.has_value()) {
				std::_Exit(83);
			}
			observer->reset();
			observer->hold_first(true);
			kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
			prepare.mutable_snapshot()->CopyFrom(owner->bootstrap_request().snapshot());
			prepare.set_target_epoch(2u);
			prepare.set_mutation_sequence(2u);
			prepare.set_idempotency_key("nonreturning-prepare");
			std::thread producer([&] { (void)owner->runtime().prepare_epoch_transition(prepare); });
			const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
			while (before(deadline)) {
				service_control_turn(owner->runtime(), 5);
			}
			observer->hold_first(false);
			owner->runtime().shutdown();
			producer.join();
			std::_Exit(84);
		},
		::testing::KilledBySignal(SIGABRT), "");
}

/** @brief A foreign thread cannot consume or advance coordinator deadlines. */
TEST(epoch_transition_preparation, foreign_deadline_service_is_terminate_class)
{
	EXPECT_EXIT(
		{
			auto owner_or = packet_runtime_test_owner::create();
			if (!owner_or.is_ok()) {
				std::_Exit(91);
			}
			auto owner = std::move(owner_or).value();
			std::thread foreign([&] { (void)owner->runtime().service_control_deadline(); });
			foreign.join();
			std::_Exit(92);
		},
		::testing::KilledBySignal(SIGABRT), "");
}

}  // namespace
}  // namespace kinetum::dp
