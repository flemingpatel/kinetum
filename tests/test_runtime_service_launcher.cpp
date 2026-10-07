// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_runtime_service_launcher.cpp
 * @brief Unit tests for lifecycle-service topology and transactional launch.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/runtime_service_ids.hpp"
#include "src/common/status.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/lifecycle/config_lifecycle_executor.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/lifecycle/runtime_service_launcher.hpp"
#include "tests/thread_affinity_test_guard.hpp"

namespace kinetum::dp::lifecycle
{

namespace
{

/** @brief Explicit context-lifetime capacity for launcher task fixtures. */
constexpr std::size_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = 4096;

/** @brief Explicit per-epoch arena capacity for launcher task fixtures. */
constexpr std::size_t TEST_EPOCH_ARENA_CAPACITY_BYTES = 256;

/** @brief Exact policy-independent owner-observation cadence. */
constexpr uint64_t TEST_MODULE_HEALTH_POLL_INTERVAL_MS = 1000u;

/** @brief Exact callback budget strictly below the owner cadence. */
constexpr uint64_t TEST_MODULE_HEALTH_CALLBACK_BUDGET_NS = 10'000u;

/**
 * @brief Build one fixed-epoch plan with a real worker and no inferred services.
 *
 * @return Exact structural plan without transition policy or service records.
 */
kinetum::gluon::v1::DeploymentPlan make_fixed_worker_plan()
{
	kinetum::gluon::v1::DeploymentPlan plan;
	auto *region = plan.add_regions();
	region->set_region_id(0);
	region->set_numa_node(0);
	auto *lane = plan.add_execution_lanes();
	lane->set_lane_id("lane_0");
	lane->set_lane_index(0);
	auto *worker = plan.add_worker_placements();
	worker->set_worker_id(kinetum::common::execution_topology::make_worker_id(0, "lane_0"));
	worker->set_worker_index(0);
	worker->set_region_id(0);
	worker->set_lane_id("lane_0");
	worker->add_cpu_core_ids(0);
	worker->set_module_health_poll_interval_ms(TEST_MODULE_HEALTH_POLL_INTERVAL_MS);
	worker->set_module_health_callback_budget_ns(TEST_MODULE_HEALTH_CALLBACK_BUDGET_NS);
	return plan;
}

/**
 * @brief Append the canonical coordinator to a plan.
 *
 * @param plan Fixed-epoch plan to mutate.
 */
void add_coordinator(kinetum::gluon::v1::DeploymentPlan &plan)
{
	auto *service = plan.add_runtime_service_placements();
	service->set_service_id(std::string(kinetum::common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID));
	service->set_service_kind(kinetum::gluon::v1::RUNTIME_SERVICE_KIND_EPOCH_TRANSITION_COORDINATOR);
	service->set_cpu_core_id(1);
	service->set_numa_node(0);
	service->set_command_mailbox_capacity(kinetum::common::MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY);
}

/**
 * @brief Append the canonical NUMA-zero lifecycle executor to a plan.
 *
 * @param plan Fixed-epoch plan to mutate.
 */
void add_executor(kinetum::gluon::v1::DeploymentPlan &plan)
{
	auto *service = plan.add_runtime_service_placements();
	service->set_service_id(kinetum::common::runtime_services::make_lifecycle_executor_id(0));
	service->set_service_kind(kinetum::gluon::v1::RUNTIME_SERVICE_KIND_CONFIG_LIFECYCLE_EXECUTOR);
	service->set_cpu_core_id(2);
	service->set_numa_node(0);
	service->set_command_mailbox_capacity(0u);
}

/**
 * @brief Build compiled service records for exact NUMA executor placements.
 *
 * @param coordinator_core Exact coordinator CPU.
 * @param executor_cores Executor CPUs ordered by ascending NUMA node.
 * @return Canonical coordinator-first compiled service records.
 */
std::vector<kinetum::common::compiled_runtime_service>
make_compiled_services(int32_t coordinator_core, const std::vector<int32_t> &executor_cores)
{
	using kinetum::common::compiled_runtime_service;
	using kinetum::common::compiled_runtime_service_role;
	std::vector<compiled_runtime_service> services;
	services.push_back(compiled_runtime_service{
		std::string(kinetum::common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID), 0,
		compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR, coordinator_core, 0,
		kinetum::common::MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY});
	for (std::size_t i = 0; i < executor_cores.size(); ++i) {
		services.push_back(compiled_runtime_service{
			kinetum::common::runtime_services::make_lifecycle_executor_id(static_cast<int32_t>(i)),
			static_cast<uint32_t>(i + 1u), compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR,
			executor_cores[i], static_cast<int32_t>(i), 0u});
	}
	return services;
}

/**
 * @brief Build exact topology indices for one coordinator and N executors.
 *
 * @param executor_count Number of canonical executor records.
 * @return Coordinator-first exact service topology.
 */
kinetum::common::compiled_lifecycle_service_topology make_compiled_topology(std::size_t executor_count)
{
	kinetum::common::compiled_lifecycle_service_topology topology;
	topology.coordinator_service_index = 0;
	for (std::size_t i = 0; i < executor_count; ++i) {
		topology.lifecycle_executor_service_indices.push_back(static_cast<uint32_t>(i + 1u));
	}
	return topology;
}

/** @brief Controllable thread backend for all-or-none launcher tests. */
class launcher_test_backend final : public runtime_service_backend {
    public:
	/** @return Injected binding status after counting the attempt; the compiled row is deliberately unused. */
	[[nodiscard]] kinetum::common::status
	bind_coordinator(const kinetum::common::compiled_runtime_service &) noexcept override
	{
		++bind_calls;
		return bind_status;
	}

	/** @copydoc kinetum::dp::lifecycle::runtime_service_backend::launch_executor */
	[[nodiscard]] kinetum::common::status launch_executor(const kinetum::common::compiled_runtime_service &service,
							      runtime_service_entry_fn entry,
							      void *argument) noexcept override
	{
		++launch_calls;
		if (fail_launch_call != 0u && launch_calls == fail_launch_call) {
			return kinetum::common::status(kinetum::common::status_code::RESOURCE_EXHAUSTED,
						       "injected lifecycle launch failure");
		}
		threads_.push_back(
			{service.service_index, std::thread([entry, argument]() { (void)entry(argument); })});
		return kinetum::common::status::ok();
	}

	/** @copydoc kinetum::dp::lifecycle::runtime_service_backend::join_executor */
	[[nodiscard]] kinetum::common::status
	join_executor(const kinetum::common::compiled_runtime_service &service) noexcept override
	{
		++join_calls;
		for (auto iterator = threads_.begin(); iterator != threads_.end(); ++iterator) {
			if (iterator->service_index != service.service_index) {
				continue;
			}
			iterator->thread.join();
			threads_.erase(iterator);
			return kinetum::common::status::ok();
		}
		return kinetum::common::status(kinetum::common::status_code::NOT_FOUND,
					       "launcher test service was not launched");
	}

	/** @brief Join any test thread left behind by a fatal assertion. */
	~launcher_test_backend() override
	{
		for (auto &record : threads_) {
			if (record.thread.joinable()) {
				record.thread.join();
			}
		}
	}

	std::size_t bind_calls{0};		///< Coordinator-bind call count.
	std::size_t launch_calls{0};		///< Executor-launch call count.
	std::size_t join_calls{0};		///< Executor-join call count.
	std::size_t fail_launch_call{0};	///< One-based injected failing launch call.
	kinetum::common::status bind_status{};	///< Injected coordinator-bind result.

    private:
	/** @brief One test-owned native thread keyed by exact service index. */
	struct thread_record {
		uint32_t service_index{0};  ///< Exact compiled service index.
		std::thread thread;	    ///< Joinable test service thread.
	};
	std::vector<thread_record> threads_;  ///< Currently launched test services.
};

/** @brief Minimal provider used to prove callback absence after failed launch. */
class launcher_memory_provider final : public lifecycle_memory_provider {
    public:
	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::allocate */
	[[nodiscard]] kinetum::common::status_or<lifecycle_memory_block>
	allocate(int32_t numa_node, std::size_t size, std::size_t alignment, bool zero_initialize) noexcept override
	{
		void *pointer = nullptr;
		if (posix_memalign(&pointer, alignment, size) != 0) {
			return kinetum::common::status(kinetum::common::status_code::RESOURCE_EXHAUSTED,
						       "launcher test allocation failed");
		}
		std::memset(pointer, zero_initialize ? 0 : 0xa5, size);
		return lifecycle_memory_block{pointer, size, alignment, numa_node, {}};
	}

	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::release */
	void release(lifecycle_memory_block block) noexcept override
	{
		std::free(block.data);
	}
};

/** @brief No-op lifecycle logger for failed-launch task construction. */
class launcher_log_provider final : public lifecycle_log_provider {
    public:
	/** @brief Discard this fixture's cold lifecycle diagnostics. */
	void write(const lifecycle_log_record_view &) noexcept override
	{
	}
};

/** @brief Adapter whose counter must remain zero across rollback. */
class launcher_counting_adapter final : public config_lifecycle_adapter {
    public:
	/** @return Injected FAILURE with no artifact ownership after counting the PREPARE attempt. */
	[[nodiscard]] lifecycle_prepare_callback_result prepare(const ::kinetum_lifecycle_ctx &, const void *,
								std::size_t) noexcept override
	{
		prepare_calls.fetch_add(1, std::memory_order_relaxed);
		return {lifecycle_prepare_callback_code::FAILURE, 1, {}};
	}

	/** @brief Count RETIRE calls, which failed launch must prevent. */
	void retire(const ::kinetum_lifecycle_ctx &, prepared_config_record) noexcept override
	{
		retire_calls.fetch_add(1, std::memory_order_relaxed);
	}

	std::atomic<uint32_t> prepare_calls{0};	 ///< PREPARE callback count.
	std::atomic<uint32_t> retire_calls{0};	 ///< RETIRE callback count.
};

/** @brief Result consumer for successful no-task native launch. */
class empty_result_consumer final : public config_lifecycle_result_consumer {
    public:
	/** @brief Count completions, which this no-task fixture must never produce. */
	void consume(config_lifecycle_result &&) noexcept override
	{
		++count;
	}

	std::size_t count{0};  ///< Total shutdown results consumed.
};

}  // namespace

/** @brief Verify fixed-epoch workers cannot omit their bootstrap lifecycle authority. */
TEST(runtime_service_launcher, fixed_epoch_plan_without_services_rejects_missing_lifecycle_authority)
{
	const auto result = kinetum::common::compile_transition_topology(make_fixed_worker_plan());
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("exactly one canonical coordinator"), std::string::npos)
		<< result.error().message();
}

/** @brief Verify one fixed-epoch service commits the plan to a complete exact surface. */
TEST(runtime_service_launcher, fixed_epoch_partial_service_surface_fails_closed)
{
	auto missing_executor = make_fixed_worker_plan();
	add_coordinator(missing_executor);
	const auto missing_executor_result = kinetum::common::compile_transition_topology(missing_executor);
	ASSERT_FALSE(missing_executor_result.is_ok());
	EXPECT_NE(missing_executor_result.error().message().find("do not exactly cover"), std::string::npos)
		<< missing_executor_result.error().message();

	auto missing_coordinator = make_fixed_worker_plan();
	add_executor(missing_coordinator);
	const auto missing_coordinator_result = kinetum::common::compile_transition_topology(missing_coordinator);
	ASSERT_FALSE(missing_coordinator_result.is_ok());
	EXPECT_NE(missing_coordinator_result.error().message().find("exactly one canonical coordinator"),
		  std::string::npos)
		<< missing_coordinator_result.error().message();
}

/** @brief Verify a complete fixed-epoch service surface compiles independently of policy. */
TEST(runtime_service_launcher, fixed_epoch_complete_service_surface_compiles_exact_placement)
{
	auto plan = make_fixed_worker_plan();
	add_coordinator(plan);
	add_executor(plan);
	const auto result = kinetum::common::compile_transition_topology(plan);
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_TRUE(result.value().lifecycle_services.has_value());
	EXPECT_FALSE(result.value().policy.enabled);
	EXPECT_EQ(result.value().lifecycle_services->coordinator_service_index, 0u);
	ASSERT_EQ(result.value().lifecycle_services->lifecycle_executor_service_indices.size(), 1u);
	EXPECT_EQ(result.value().lifecycle_services->lifecycle_executor_service_indices[0], 1u);
}

/** @brief Verify launcher topology mismatch rejects before backend side effects. */
TEST(runtime_service_launcher, executor_mismatch_rejects_before_backend_launch_or_binding)
{
	auto services = make_compiled_services(0, {1});
	auto topology = make_compiled_topology(1);
	config_lifecycle_executor wrong_executor(9, 0);
	const std::vector<config_lifecycle_executor *> executors{&wrong_executor};
	launcher_test_backend backend;
	runtime_service_launcher launcher;

	const auto status = launcher.launch(topology, services, executors, backend);
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(backend.launch_calls, 0u);
	EXPECT_EQ(backend.bind_calls, 0u);
	EXPECT_FALSE(launcher.running());

	config_lifecycle_executor exact_executor(1, 0);
	const std::vector<config_lifecycle_executor *> exact_executors{&exact_executor};
	services[0].service_id = "noncanonical-coordinator";
	const auto identity_status = launcher.launch(topology, services, exact_executors, backend);
	EXPECT_EQ(identity_status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(backend.launch_calls, 0u);
	EXPECT_EQ(backend.bind_calls, 0u);

	for (const uint32_t invalid_capacity : {0u, 1u, 3u, 65u, 128u}) {
		services = make_compiled_services(0, {1});
		services[0].command_mailbox_capacity = invalid_capacity;
		const auto coordinator_capacity_status = launcher.launch(topology, services, exact_executors, backend);
		EXPECT_EQ(coordinator_capacity_status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
		EXPECT_EQ(backend.launch_calls, 0u);
		EXPECT_EQ(backend.bind_calls, 0u);
	}

	services = make_compiled_services(0, {1});
	services[1].command_mailbox_capacity = 2u;
	const auto executor_capacity_status = launcher.launch(topology, services, exact_executors, backend);
	EXPECT_EQ(executor_capacity_status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(backend.launch_calls, 0u);
	EXPECT_EQ(backend.bind_calls, 0u);

	services = make_compiled_services(0, {1});
	std::swap(services[0], services[1]);
	services[0].service_index = 0;
	services[1].service_index = 1;
	topology.coordinator_service_index = 1;
	topology.lifecycle_executor_service_indices = {0};
	const auto order_status = launcher.launch(topology, services, exact_executors, backend);
	EXPECT_EQ(order_status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(backend.launch_calls, 0u);
	EXPECT_EQ(backend.bind_calls, 0u);

	services = make_compiled_services(0, {1, 2});
	topology = make_compiled_topology(2);
	config_lifecycle_executor second_executor(2, 1);
	const std::vector<config_lifecycle_executor *> two_executors{&exact_executor, &second_executor};
	topology.lifecycle_executor_service_indices = {1, 1};
	const auto duplicate_status = launcher.launch(topology, services, two_executors, backend);
	EXPECT_EQ(duplicate_status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(backend.launch_calls, 0u);
	EXPECT_EQ(backend.bind_calls, 0u);

	topology = make_compiled_topology(2);
	services[2].cpu_core_id = services[1].cpu_core_id;
	const auto overlap_status = launcher.launch(topology, services, two_executors, backend);
	EXPECT_EQ(overlap_status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(backend.launch_calls, 0u);
	EXPECT_EQ(backend.bind_calls, 0u);

	services = make_compiled_services(0, {1});
	topology = make_compiled_topology(1);
	const auto active_status = launcher.launch(topology, services, exact_executors, backend);
	ASSERT_TRUE(active_status.is_ok()) << active_status.message();
	launcher_test_backend competing_backend;
	runtime_service_launcher competing_launcher;
	const auto competing_status = competing_launcher.launch(topology, services, exact_executors, competing_backend);
	EXPECT_EQ(competing_status.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(competing_backend.launch_calls, 0u);
	EXPECT_EQ(competing_backend.bind_calls, 0u);
	empty_result_consumer consumer;
	EXPECT_TRUE(launcher.stop_and_join(consumer).is_ok());
}

/** @brief Verify partial launch cancels the gate, joins prior services, and invokes zero callbacks. */
TEST(runtime_service_launcher, partial_launch_failure_rolls_back_with_zero_lifecycle_callbacks)
{
	auto services = make_compiled_services(0, {1, 2});
	auto topology = make_compiled_topology(2);
	config_lifecycle_executor first(1, 0);
	config_lifecycle_executor second(2, 1);
	const std::vector<config_lifecycle_executor *> executors{&first, &second};
	launcher_test_backend backend;
	backend.fail_launch_call = 2;
	runtime_service_launcher launcher;

	const auto status = launcher.launch(topology, services, executors, backend);
	EXPECT_EQ(status.code(), kinetum::common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(backend.launch_calls, 2u);
	EXPECT_EQ(backend.join_calls, 1u);
	EXPECT_EQ(backend.bind_calls, 0u);
	EXPECT_FALSE(launcher.running());

	launcher_test_backend binding_backend;
	binding_backend.bind_status = kinetum::common::status(kinetum::common::status_code::FAILED_PRECONDITION,
							      "injected coordinator binding failure");
	runtime_service_launcher binding_launcher;
	const auto binding_status = binding_launcher.launch(topology, services, executors, binding_backend);
	EXPECT_EQ(binding_status.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(binding_backend.launch_calls, 2u);
	EXPECT_EQ(binding_backend.join_calls, 2u);
	EXPECT_EQ(binding_backend.bind_calls, 1u);
	EXPECT_FALSE(binding_launcher.running());

	launcher_memory_provider memory;
	launcher_log_provider log;
	launcher_counting_adapter adapter;
	lifecycle_context_identity identity{"kinetum.test.module", "stage@lane_0", 3, 7, 2, 5, 0, 0u, 1u};
	auto owner_or = lifecycle_context_owner::create(std::move(identity), TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
							TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	auto arena_or = epoch_arena_ownership::create(memory, 7, 41, 0, owner->epoch_arena_capacity_bytes(), 64);
	ASSERT_TRUE(arena_or.is_ok()) << arena_or.error().message();
	auto arena = std::move(arena_or).value();
	lifecycle_operation_control control(std::chrono::steady_clock::now() + std::chrono::seconds(1));
	auto task_or =
		config_lifecycle_task::create_prepare(1, *owner, adapter, control, 41, nullptr, 0, std::move(arena));
	ASSERT_TRUE(task_or.is_ok()) << task_or.error().message();
	auto task = std::move(task_or).value();
	EXPECT_FALSE(first.submit(std::move(task)).is_ok());
	EXPECT_EQ(adapter.prepare_calls.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(adapter.retire_calls.load(std::memory_order_relaxed), 0u);
}

/** @brief Verify the native backend pins and joins an exact complete service set. */
TEST(runtime_service_launcher, native_backend_launches_complete_affinity_owned_service_set)
{
	kinetum::test::thread_affinity_restore_guard affinity;
	const auto cores = affinity.allowed_cores();
	ASSERT_GE(cores.size(), 2u) << "native lifecycle launch requires two allowed CPUs";
	auto services = make_compiled_services(cores[0], {cores[1]});
	services[0].command_mailbox_capacity = kinetum::common::MIN_COORDINATOR_COMMAND_MAILBOX_CAPACITY;
	auto topology = make_compiled_topology(1);
	config_lifecycle_executor executor(1, 0);
	const std::vector<config_lifecycle_executor *> executors{&executor};
	native_runtime_service_backend backend;
	runtime_service_launcher launcher;

	const auto launch_status = launcher.launch(topology, services, executors, backend);
	ASSERT_TRUE(launch_status.is_ok()) << launch_status.message();
	EXPECT_TRUE(launcher.running());
	empty_result_consumer consumer;
	const auto stop_status = launcher.stop_and_join(consumer);
	EXPECT_TRUE(stop_status.is_ok()) << stop_status.message();
	EXPECT_FALSE(launcher.running());
	EXPECT_EQ(consumer.count, 0u);
}

}  // namespace kinetum::dp::lifecycle
