// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_config_lifecycle_executor.cpp
 * @brief Unit tests for bounded cold lifecycle task/result execution.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "src/common/runtime_service_ids.hpp"
#include "src/common/status.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/lifecycle/config_lifecycle_executor.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/lifecycle/runtime_service_launcher.hpp"

namespace kinetum::dp::lifecycle
{

namespace
{

/** Context-memory authority used by executor fixtures. */
constexpr std::size_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = 4096;
/** Epoch-arena authority used by executor fixtures. */
constexpr std::size_t TEST_EPOCH_ARENA_CAPACITY_BYTES = 256;

/** @brief Thread-safe exact provider used across coordinator and executor threads. */
class executor_test_memory_provider final : public lifecycle_memory_provider {
    public:
	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::allocate */
	[[nodiscard]] kinetum::common::status_or<lifecycle_memory_block>
	allocate(int32_t numa_node, std::size_t size, std::size_t alignment, bool zero_initialize) noexcept override
	{
		void *pointer = nullptr;
		if (posix_memalign(&pointer, alignment, size) != 0) {
			return kinetum::common::status(kinetum::common::status_code::RESOURCE_EXHAUSTED,
						       "executor test allocation failed");
		}
		std::memset(pointer, zero_initialize ? 0 : 0xa5, size);
		{
			std::lock_guard<std::mutex> lock(mutex_);
			active_.insert(pointer);
		}
		return lifecycle_memory_block{pointer, size, alignment, numa_node, {}};
	}

	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::release */
	void release(lifecycle_memory_block block) noexcept override
	{
		std::lock_guard<std::mutex> lock(mutex_);
		if (active_.erase(block.data) == 1u) {
			std::free(block.data);
			if (release_observer_ != nullptr) {
				published_count_at_release_ = release_observer_->published_result_count();
				release_observer_ = nullptr;
			}
		}
	}

	/**
	 * @brief Observe the publication count during the next actual allocation release.
	 * @param executor Stable executor retained through that release.
	 * @note Bind before submitting the task whose arena release is being checked.
	 */
	void observe_next_release(const config_lifecycle_executor &executor) noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		release_observer_ = &executor;
		published_count_at_release_.reset();
	}

	/** @return Publication count observed during release, or absence before release occurs. */
	[[nodiscard]] std::optional<uint64_t> published_count_at_release() const noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		return published_count_at_release_;
	}

	/**
	 * @brief Return the synchronized active-allocation count.
	 *
	 * @return Number of exact blocks not yet released.
	 */
	[[nodiscard]] std::size_t active_count() const noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		return active_.size();
	}

    private:
	mutable std::mutex mutex_;				      ///< Protects the cross-thread allocation set.
	std::set<void *> active_;				      ///< Exact allocation starts not yet released.
	const config_lifecycle_executor *release_observer_{nullptr};  ///< One-release executor borrow, then cleared.
	std::optional<uint64_t> published_count_at_release_;  ///< Synchronized observation made by the allocator.
};

/** @brief No-op log sink for executor tests. */
class executor_test_log_provider final : public lifecycle_log_provider {
    public:
	/** @copydoc kinetum::dp::lifecycle::lifecycle_log_provider::write */
	void write([[maybe_unused]] const lifecycle_log_record_view &record) noexcept override
	{
	}
};

/** @brief Deterministic adapter recording callback identity and outcome. */
class executor_test_adapter final : public config_lifecycle_adapter {
    public:
	/**
	 * @brief Record PREPARE identity and return the injected result; payload bytes are unused.
	 * @param context Borrowed lifecycle shell supplying the observed epoch.
	 * @return Injected callback code, diagnostic, and prepared ownership record.
	 */
	[[nodiscard]] lifecycle_prepare_callback_result prepare(const ::kinetum_lifecycle_ctx &context, const void *,
								std::size_t) noexcept override
	{
		prepare_calls.fetch_add(1, std::memory_order_relaxed);
		observed_epoch.store(lifecycle_current_epoch(context), std::memory_order_relaxed);
		return lifecycle_prepare_callback_result{prepare_code, module_error_code, prepared};
	}

	/**
	 * @brief Record RETIRE identity and the returned owner handle.
	 * @param context Borrowed lifecycle shell supplying the observed epoch.
	 * @param record Prepared artifact record returned to the fixture for retirement.
	 */
	void retire(const ::kinetum_lifecycle_ctx &context, prepared_config_record record) noexcept override
	{
		retire_calls.fetch_add(1, std::memory_order_relaxed);
		observed_epoch.store(lifecycle_current_epoch(context), std::memory_order_relaxed);
		observed_owner_handle.store(record.owner_handle, std::memory_order_relaxed);
	}

	std::atomic<uint32_t> prepare_calls{0};		     ///< PREPARE callback count.
	std::atomic<uint32_t> retire_calls{0};		     ///< RETIRE callback count.
	std::atomic<uint64_t> observed_epoch{0};	     ///< Latest callback epoch.
	std::atomic<void *> observed_owner_handle{nullptr};  ///< Latest retired owner handle.
	lifecycle_prepare_callback_code prepare_code{lifecycle_prepare_callback_code::SUCCESS};	 ///< Injected result.
	uint32_t module_error_code{0};	    ///< Injected bounded module diagnostic.
	prepared_config_record prepared{};  ///< Injected successful prepare record.
};

/** @brief Thread backend used to exercise the generic launcher deterministically. */
class executor_test_backend final : public runtime_service_backend {
    public:
	/** @return OK without changing placement; this fake leaves coordinator placement to the test thread. */
	[[nodiscard]] kinetum::common::status
	bind_coordinator(const kinetum::common::compiled_runtime_service &) noexcept override
	{
		return kinetum::common::status::ok();
	}

	/** @copydoc kinetum::dp::lifecycle::runtime_service_backend::launch_executor */
	[[nodiscard]] kinetum::common::status launch_executor(const kinetum::common::compiled_runtime_service &service,
							      runtime_service_entry_fn entry,
							      void *argument) noexcept override
	{
		threads_.push_back(
			{service.service_index, std::thread([entry, argument]() { (void)entry(argument); })});
		return kinetum::common::status::ok();
	}

	/** @copydoc kinetum::dp::lifecycle::runtime_service_backend::join_executor */
	[[nodiscard]] kinetum::common::status
	join_executor(const kinetum::common::compiled_runtime_service &service) noexcept override
	{
		for (auto iterator = threads_.begin(); iterator != threads_.end(); ++iterator) {
			if (iterator->service_index != service.service_index) {
				continue;
			}
			iterator->thread.join();
			threads_.erase(iterator);
			return kinetum::common::status::ok();
		}
		return kinetum::common::status(kinetum::common::status_code::NOT_FOUND,
					       "executor test service was not launched");
	}

	/** @brief Join any test thread left behind by a fatal assertion. */
	~executor_test_backend() override
	{
		for (auto &record : threads_) {
			if (record.thread.joinable()) {
				record.thread.join();
			}
		}
	}

    private:
	/** @brief One test-owned service thread keyed by compiled service index. */
	struct thread_record {
		uint32_t service_index{0};  ///< Exact compiled service index.
		std::thread thread;	    ///< Joinable test service thread.
	};
	std::vector<thread_record> threads_;  ///< Currently launched test services.
};

/** @brief Result sink that preserves exact token retirement during shutdown. */
class executor_test_result_consumer final : public config_lifecycle_result_consumer {
    public:
	/** @copydoc kinetum::dp::lifecycle::config_lifecycle_result_consumer::consume */
	void consume(config_lifecycle_result &&result) noexcept override
	{
		++count;
		if (!result.has_prepared_ownership()) {
			return;
		}
		auto token_or = result.take_prepared_ownership();
		if (!token_or.is_ok()) {
			++ownership_errors;
			return;
		}
		auto token = std::move(token_or).value();
		if (!token.retire_exact(result.module_image_index(), result.context_index(), result.epoch()).is_ok()) {
			++ownership_errors;
		}
	}

	std::size_t count{0};		  ///< Total results consumed.
	std::size_t ownership_errors{0};  ///< Token-transfer or exact-retire failures.
};

/**
 * @brief Build one exact context owner for executor tests.
 *
 * @param memory Thread-safe exact memory provider.
 * @param log No-op lifecycle log provider.
 * @return Unique valid owner, or nullptr after recording a test failure.
 */
std::unique_ptr<lifecycle_context_owner> make_executor_owner(executor_test_memory_provider &memory,
							     executor_test_log_provider &log)
{
	lifecycle_context_identity identity{"kinetum.test.module", "stage@lane_0", 3, 7, 2, 5, 0, 0u, 1u};
	auto owner_or = lifecycle_context_owner::create(std::move(identity), TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
							TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log);
	if (!owner_or.is_ok()) {
		ADD_FAILURE() << owner_or.error().message();
		return nullptr;
	}
	return std::move(owner_or).value();
}

/**
 * @brief Build one coordinator plus one NUMA-zero lifecycle service.
 *
 * @return Canonical two-service compiled placement.
 */
std::vector<kinetum::common::compiled_runtime_service> make_executor_services()
{
	using kinetum::common::compiled_runtime_service;
	using kinetum::common::compiled_runtime_service_role;
	return {
		compiled_runtime_service{std::string(kinetum::common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID),
					 0, compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR, 0, 0,
					 kinetum::common::MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY},
		compiled_runtime_service{kinetum::common::runtime_services::make_lifecycle_executor_id(0), 1,
					 compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR, 1, 0, 0u},
	};
}

/**
 * @brief Build the exact topology corresponding to make_executor_services().
 *
 * @return Coordinator/executor indices for the canonical fixture.
 */
kinetum::common::compiled_lifecycle_service_topology make_executor_topology()
{
	return kinetum::common::compiled_lifecycle_service_topology{0, {1}};
}

/**
 * @brief Launch one executor through the permanent generic launcher.
 *
 * @param launcher Empty launcher to populate.
 * @param backend Deterministic test backend.
 * @param executor Pre-created NUMA-zero lifecycle executor.
 * @return Exact launch status.
 */
kinetum::common::status start_executor(runtime_service_launcher &launcher, executor_test_backend &backend,
				       config_lifecycle_executor &executor)
{
	const std::vector<config_lifecycle_executor *> executors{&executor};
	return launcher.launch(make_executor_topology(), make_executor_services(), executors, backend);
}

/**
 * @brief Construct one exact PREPARE task for epoch 41.
 *
 * @param sequence Nonzero coordinator task sequence.
 * @param owner Exact context owner.
 * @param adapter Deterministic callback adapter.
 * @param control Stable operation control.
 * @param memory Exact arena allocation authority.
 * @return Move-only PREPARE task, or construction failure.
 */
kinetum::common::status_or<config_lifecycle_task> make_prepare_task(uint64_t sequence, lifecycle_context_owner &owner,
								    executor_test_adapter &adapter,
								    lifecycle_operation_control &control,
								    executor_test_memory_provider &memory)
{
	auto arena_or = epoch_arena_ownership::create(memory, owner.identity().context_index, 41,
						      owner.identity().numa_node, owner.epoch_arena_capacity_bytes(),
						      64);
	if (!arena_or.is_ok()) {
		return arena_or.error();
	}
	auto arena = std::move(arena_or).value();
	return config_lifecycle_task::create_prepare(sequence, owner, adapter, control, 41, nullptr, 0,
						     std::move(arena));
}

/**
 * @brief Return one bounded operation deadline.
 *
 * @return Steady-clock time five seconds in the future.
 */
std::chrono::steady_clock::time_point executor_deadline()
{
	return std::chrono::steady_clock::now() + std::chrono::seconds(5);
}

/**
 * @brief Wait for one exact executor result without an unbounded test sleep.
 *
 * @param executor Running executor to observe.
 * @return Next result, or nullopt after the test deadline.
 */
std::optional<config_lifecycle_result> wait_for_result(config_lifecycle_executor &executor)
{
	return executor.wait_take_result_until(std::chrono::steady_clock::now() + std::chrono::seconds(2));
}

/**
 * @brief Wait boundedly until one exact published-result count is visible.
 *
 * @param executor Running executor to observe.
 * @param expected Exact count required by the test.
 * @return true when the expected count appears before the deadline.
 */
bool wait_for_published_count(config_lifecycle_executor &executor, uint64_t expected)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	while (std::chrono::steady_clock::now() < deadline) {
		if (executor.published_result_count() == expected) {
			return true;
		}
		std::this_thread::yield();
	}
	return executor.published_result_count() == expected;
}

}  // namespace

/** @brief Verify exact payload admission and inactive submit preserve ownership. */
TEST(config_lifecycle_executor, payload_and_launch_admission_preserve_caller_ownership)
{
	executor_test_memory_provider memory;
	executor_test_log_provider log;
	executor_test_adapter adapter;
	auto owner = make_executor_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	lifecycle_operation_control control(executor_deadline());
	auto arena_or = epoch_arena_ownership::create(memory, owner->identity().context_index, 41,
						      owner->identity().numa_node, owner->epoch_arena_capacity_bytes(),
						      64);
	ASSERT_TRUE(arena_or.is_ok()) << arena_or.error().message();
	auto arena = std::move(arena_or).value();
	const uint8_t byte = 0;
	auto null_nonempty =
		config_lifecycle_task::create_prepare(1, *owner, adapter, control, 41, nullptr, 1, std::move(arena));
	EXPECT_FALSE(null_nonempty.is_ok());
	EXPECT_TRUE(arena.owns_memory());
	auto addressed_empty =
		config_lifecycle_task::create_prepare(1, *owner, adapter, control, 41, &byte, 0, std::move(arena));
	EXPECT_FALSE(addressed_empty.is_ok());
	EXPECT_TRUE(arena.owns_memory());
	lifecycle_operation_control unbound(std::chrono::steady_clock::time_point{});
	auto missing_deadline =
		config_lifecycle_task::create_prepare(1, *owner, adapter, unbound, 41, nullptr, 0, std::move(arena));
	EXPECT_FALSE(missing_deadline.is_ok());
	EXPECT_TRUE(arena.owns_memory());
	auto task_or =
		config_lifecycle_task::create_prepare(1, *owner, adapter, control, 41, nullptr, 0, std::move(arena));
	ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
	auto task = std::move(task_or).value();
	config_lifecycle_executor executor(1, 0);

	const auto status = executor.submit(std::move(task));
	EXPECT_EQ(status.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(task.task_sequence(), 1u);
	EXPECT_EQ(memory.active_count(), 2u);
}

/** @brief Verify explicit callback success creates a token even for null handles. */
TEST(config_lifecycle_executor, prepare_success_returns_explicit_null_value_ownership)
{
	executor_test_memory_provider memory;
	executor_test_log_provider log;
	executor_test_adapter adapter;
	auto owner = make_executor_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	config_lifecycle_executor executor(1, 0);
	executor_test_backend backend;
	runtime_service_launcher launcher;
	ASSERT_TRUE(start_executor(launcher, backend, executor).is_ok());
	lifecycle_operation_control control(executor_deadline());
	auto task_or = make_prepare_task(1, *owner, adapter, control, memory);
	ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
	auto task = std::move(task_or).value();
	memory.observe_next_release(executor);
	ASSERT_TRUE(executor.submit(std::move(task)).is_ok());

	auto result = wait_for_result(executor);
	ASSERT_TRUE(result.has_value());
	EXPECT_EQ(result->code(), config_lifecycle_result_code::SUCCESS);
	ASSERT_TRUE(result->has_prepared_ownership());
	EXPECT_EQ(memory.active_count(), 2u);
	EXPECT_FALSE(memory.published_count_at_release().has_value());
	auto token_or = result->take_prepared_ownership();
	ASSERT_TRUE(token_or.is_ok()) << token_or.error().message();
	auto token = std::move(token_or).value();
	ASSERT_TRUE(token.borrow_exact(3, 7, 41).is_ok());
	auto retire_task_or = config_lifecycle_task::create_retire(2, *owner, adapter, control, token);
	ASSERT_TRUE(retire_task_or.is_ok()) << retire_task_or.error().message();
	ASSERT_TRUE(executor.submit(std::move(retire_task_or).value()).is_ok());
	auto retired = wait_for_result(executor);
	ASSERT_TRUE(retired.has_value());
	EXPECT_EQ(retired->code(), config_lifecycle_result_code::SUCCESS);
	EXPECT_EQ(adapter.retire_calls.load(std::memory_order_relaxed), 1u);
	EXPECT_TRUE(token.retire_exact(3, 7, 41).is_ok());
	EXPECT_EQ(adapter.prepare_calls.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(memory.active_count(), 1u);
	EXPECT_EQ(memory.published_count_at_release(), std::optional<uint64_t>{2u});

	executor_test_result_consumer consumer;
	EXPECT_TRUE(launcher.stop_and_join(consumer).is_ok());
	EXPECT_EQ(consumer.count, 0u);
}

/** @brief Verify failed and cancelled callbacks reclaim the arena before publishing a result. */
TEST(config_lifecycle_executor, prepare_failure_returns_no_token_and_reclaims_arena)
{
	executor_test_memory_provider memory;
	executor_test_log_provider log;
	executor_test_adapter adapter;
	adapter.module_error_code = 77;
	auto owner = make_executor_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	config_lifecycle_executor executor(1, 0);
	executor_test_backend backend;
	runtime_service_launcher launcher;
	ASSERT_TRUE(start_executor(launcher, backend, executor).is_ok());
	lifecycle_operation_control control(executor_deadline());
	constexpr std::array CASES{
		std::pair{lifecycle_prepare_callback_code::FAILURE, config_lifecycle_result_code::CALLBACK_FAILURE},
		std::pair{lifecycle_prepare_callback_code::CANCELLED, config_lifecycle_result_code::CANCELLED},
	};
	uint64_t task_sequence = 1;
	for (const auto &[callback_code, result_code] : CASES) {
		SCOPED_TRACE(task_sequence);
		adapter.prepare_code = callback_code;
		auto task_or = make_prepare_task(task_sequence, *owner, adapter, control, memory);
		ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
		auto task = std::move(task_or).value();
		memory.observe_next_release(executor);
		ASSERT_TRUE(executor.submit(std::move(task)).is_ok());

		auto result = wait_for_result(executor);
		ASSERT_TRUE(result.has_value());
		EXPECT_EQ(result->code(), result_code);
		EXPECT_EQ(result->diagnostic_code(), 77u);
		EXPECT_FALSE(result->has_prepared_ownership());
		EXPECT_EQ(adapter.prepare_calls.load(std::memory_order_relaxed), task_sequence);
		EXPECT_EQ(memory.active_count(), 1u);
		EXPECT_EQ(memory.published_count_at_release(), std::optional<uint64_t>{task_sequence - 1u});
		++task_sequence;
	}

	executor_test_result_consumer consumer;
	EXPECT_TRUE(launcher.stop_and_join(consumer).is_ok());
}

/** @brief Verify pre-published cancellation prevents foreign callback execution. */
TEST(config_lifecycle_executor, cancelled_prepare_is_reported_without_callback)
{
	executor_test_memory_provider memory;
	executor_test_log_provider log;
	executor_test_adapter adapter;
	auto owner = make_executor_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	config_lifecycle_executor executor(1, 0);
	executor_test_backend backend;
	runtime_service_launcher launcher;
	ASSERT_TRUE(start_executor(launcher, backend, executor).is_ok());
	lifecycle_operation_control control(executor_deadline());
	control.request_cancellation();
	auto task_or = make_prepare_task(1, *owner, adapter, control, memory);
	ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
	auto task = std::move(task_or).value();
	memory.observe_next_release(executor);
	ASSERT_TRUE(executor.submit(std::move(task)).is_ok());

	auto result = wait_for_result(executor);
	ASSERT_TRUE(result.has_value());
	EXPECT_EQ(result->code(), config_lifecycle_result_code::CANCELLED);
	EXPECT_EQ(adapter.prepare_calls.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(memory.active_count(), 1u);
	EXPECT_EQ(memory.published_count_at_release(), std::optional<uint64_t>{0u});

	executor_test_result_consumer consumer;
	EXPECT_TRUE(launcher.stop_and_join(consumer).is_ok());
}

/** @brief Verify an expired deadline prevents foreign callback execution. */
TEST(config_lifecycle_executor, expired_prepare_is_reported_without_callback)
{
	executor_test_memory_provider memory;
	executor_test_log_provider log;
	executor_test_adapter adapter;
	auto owner = make_executor_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	config_lifecycle_executor executor(1, 0);
	executor_test_backend backend;
	runtime_service_launcher launcher;
	ASSERT_TRUE(start_executor(launcher, backend, executor).is_ok());
	lifecycle_operation_control control(std::chrono::steady_clock::now() - std::chrono::nanoseconds(1));
	auto task_or = make_prepare_task(1, *owner, adapter, control, memory);
	ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
	auto task = std::move(task_or).value();
	memory.observe_next_release(executor);
	ASSERT_TRUE(executor.submit(std::move(task)).is_ok());

	auto result = wait_for_result(executor);
	ASSERT_TRUE(result.has_value());
	EXPECT_EQ(result->code(), config_lifecycle_result_code::DEADLINE_EXCEEDED);
	EXPECT_EQ(adapter.prepare_calls.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(memory.active_count(), 1u);
	EXPECT_EQ(memory.published_count_at_release(), std::optional<uint64_t>{0u});

	executor_test_result_consumer consumer;
	EXPECT_TRUE(launcher.stop_and_join(consumer).is_ok());
}

/** @brief Verify overlapping context use fails before invoking foreign code. */
TEST(config_lifecycle_executor, active_context_rejection_runs_zero_callbacks)
{
	executor_test_memory_provider memory;
	executor_test_log_provider log;
	executor_test_adapter adapter;
	auto owner = make_executor_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	config_lifecycle_executor executor(1, 0);
	executor_test_backend backend;
	runtime_service_launcher launcher;
	ASSERT_TRUE(start_executor(launcher, backend, executor).is_ok());
	lifecycle_operation_control active_control(executor_deadline());
	auto active_or = owner->begin_operation(lifecycle_phase::INIT, 0, active_control);
	ASSERT_TRUE(active_or.is_ok()) << active_or.error().message();
	auto active = std::move(active_or).value();
	lifecycle_operation_control prepare_control(executor_deadline());
	auto task_or = make_prepare_task(1, *owner, adapter, prepare_control, memory);
	ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
	auto task = std::move(task_or).value();
	memory.observe_next_release(executor);
	ASSERT_TRUE(executor.submit(std::move(task)).is_ok());

	auto result = wait_for_result(executor);
	ASSERT_TRUE(result.has_value());
	EXPECT_EQ(result->code(), config_lifecycle_result_code::CONTEXT_REJECTED);
	EXPECT_EQ(adapter.prepare_calls.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(memory.active_count(), 1u);
	EXPECT_EQ(memory.published_count_at_release(), std::optional<uint64_t>{0u});
	active.release();

	executor_test_result_consumer consumer;
	EXPECT_TRUE(launcher.stop_and_join(consumer).is_ok());
}

/** @brief Verify RETIRE borrows exact ownership and leaves consumption to its issuer. */
TEST(config_lifecycle_executor, retire_borrows_prepared_ownership_and_reports_exact_completion)
{
	executor_test_memory_provider memory;
	executor_test_log_provider log;
	executor_test_adapter adapter;
	auto owner = make_executor_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	config_lifecycle_executor executor(1, 0);
	executor_test_backend backend;
	runtime_service_launcher launcher;
	ASSERT_TRUE(start_executor(launcher, backend, executor).is_ok());
	auto arena_or = epoch_arena_ownership::create(memory, 7, 41, 0, owner->epoch_arena_capacity_bytes(), 64);
	ASSERT_TRUE(arena_or.is_ok()) << arena_or.error().message();
	std::optional<epoch_arena_ownership> arena;
	arena.emplace(std::move(arena_or).value());
	auto token_or = prepared_config_ownership::create(
		3, 7, 41, {reinterpret_cast<void *>(static_cast<std::uintptr_t>(1)), nullptr}, std::move(arena));
	ASSERT_TRUE(token_or.is_ok()) << token_or.error().message();
	auto token = std::move(token_or).value();
	lifecycle_operation_control control(executor_deadline());
	auto invalid_claim = config_lifecycle_task::create_claimed_retire(1, *owner, adapter, control, token, 0u);
	EXPECT_FALSE(invalid_claim.is_ok());
	EXPECT_TRUE(token.owns_state());
	auto task_or = config_lifecycle_task::create_retire(1, *owner, adapter, control, token);
	ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
	auto task = std::move(task_or).value();
	EXPECT_EQ(task.retirement_claim_id(), 0u);
	ASSERT_TRUE(executor.submit(std::move(task)).is_ok());

	auto result = wait_for_result(executor);
	ASSERT_TRUE(result.has_value());
	EXPECT_EQ(result->code(), config_lifecycle_result_code::SUCCESS);
	EXPECT_EQ(result->retirement_claim_id(), 0u);
	EXPECT_FALSE(result->has_prepared_ownership());
	EXPECT_TRUE(token.owns_state());
	EXPECT_TRUE(token.retire_exact(3, 7, 41).is_ok());
	EXPECT_EQ(memory.active_count(), 1u);

	auto claimed_arena_or =
		epoch_arena_ownership::create(memory, 7, 42, 0, owner->epoch_arena_capacity_bytes(), 64);
	ASSERT_TRUE(claimed_arena_or.is_ok()) << claimed_arena_or.error().message();
	std::optional<epoch_arena_ownership> claimed_arena;
	claimed_arena.emplace(std::move(claimed_arena_or).value());
	auto claimed_token_or = prepared_config_ownership::create(
		3, 7, 42, {reinterpret_cast<void *>(static_cast<std::uintptr_t>(1)), nullptr},
		std::move(claimed_arena));
	ASSERT_TRUE(claimed_token_or.is_ok()) << claimed_token_or.error().message();
	auto claimed_token = std::move(claimed_token_or).value();
	lifecycle_operation_control claimed_control(executor_deadline());
	constexpr uint64_t CLAIM_ID = 91u;
	auto claimed_or = config_lifecycle_task::create_claimed_retire(2, *owner, adapter, claimed_control,
								       claimed_token, CLAIM_ID);
	ASSERT_TRUE(claimed_or.is_ok()) << claimed_or.error().message();
	auto claimed = std::move(claimed_or).value();
	EXPECT_EQ(claimed.retirement_claim_id(), CLAIM_ID);
	ASSERT_TRUE(executor.submit(std::move(claimed)).is_ok());
	auto claimed_result = wait_for_result(executor);
	ASSERT_TRUE(claimed_result.has_value());
	EXPECT_EQ(claimed_result->code(), config_lifecycle_result_code::SUCCESS);
	EXPECT_EQ(claimed_result->retirement_claim_id(), CLAIM_ID);
	EXPECT_FALSE(claimed_result->has_prepared_ownership());
	EXPECT_EQ(adapter.retire_calls.load(std::memory_order_relaxed), 2u);
	EXPECT_EQ(adapter.observed_epoch.load(std::memory_order_relaxed), 42u);
	EXPECT_EQ(adapter.observed_owner_handle.load(std::memory_order_relaxed),
		  reinterpret_cast<void *>(static_cast<std::uintptr_t>(1)));
	EXPECT_TRUE(claimed_token.owns_state());
	EXPECT_TRUE(claimed_token.retire_exact(3, 7, 42).is_ok());
	EXPECT_EQ(memory.active_count(), 1u);

	executor_test_result_consumer consumer;
	EXPECT_TRUE(launcher.stop_and_join(consumer).is_ok());
}

/** @brief Verify result backpressure and shutdown preserve every accepted ownership token. */
TEST(config_lifecycle_executor, full_result_channel_delays_task_pop_and_stop_drains_every_token)
{
	executor_test_memory_provider memory;
	executor_test_log_provider log;
	executor_test_adapter adapter;
	auto owner = make_executor_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	config_lifecycle_executor executor(1, 0);
	executor_test_backend backend;
	runtime_service_launcher launcher;
	ASSERT_TRUE(start_executor(launcher, backend, executor).is_ok());

	std::vector<std::unique_ptr<lifecycle_operation_control>> controls;
	controls.reserve(CONFIG_LIFECYCLE_TASK_CAPACITY * 2u);
	for (std::size_t i = 0; i < CONFIG_LIFECYCLE_TASK_CAPACITY; ++i) {
		controls.push_back(std::make_unique<lifecycle_operation_control>(executor_deadline()));
		auto task_or =
			make_prepare_task(static_cast<uint64_t>(i + 1u), *owner, adapter, *controls.back(), memory);
		ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
		auto task = std::move(task_or).value();
		ASSERT_TRUE(executor.submit(std::move(task)).is_ok());
	}
	ASSERT_TRUE(wait_for_published_count(executor, CONFIG_LIFECYCLE_RESULT_CAPACITY));

	for (std::size_t i = 0; i < CONFIG_LIFECYCLE_TASK_CAPACITY; ++i) {
		controls.push_back(std::make_unique<lifecycle_operation_control>(executor_deadline()));
		auto task_or = make_prepare_task(static_cast<uint64_t>(CONFIG_LIFECYCLE_TASK_CAPACITY + i + 1u), *owner,
						 adapter, *controls.back(), memory);
		ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
		auto task = std::move(task_or).value();
		ASSERT_TRUE(executor.submit(std::move(task)).is_ok());
	}
	EXPECT_EQ(executor.accepted_task_count(), CONFIG_LIFECYCLE_TASK_CAPACITY * 2u);
	EXPECT_EQ(executor.published_result_count(), CONFIG_LIFECYCLE_RESULT_CAPACITY);

	executor_test_result_consumer consumer;
	ASSERT_TRUE(launcher.stop_and_join(consumer).is_ok());
	EXPECT_EQ(consumer.count, CONFIG_LIFECYCLE_TASK_CAPACITY * 2u);
	EXPECT_EQ(consumer.ownership_errors, 0u);
	EXPECT_EQ(executor.published_result_count(), CONFIG_LIFECYCLE_TASK_CAPACITY * 2u);
	EXPECT_EQ(adapter.prepare_calls.load(std::memory_order_relaxed), CONFIG_LIFECYCLE_TASK_CAPACITY * 2u);
	EXPECT_EQ(memory.active_count(), 1u);
}

}  // namespace kinetum::dp::lifecycle
