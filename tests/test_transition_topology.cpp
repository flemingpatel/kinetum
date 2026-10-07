// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_transition_topology.cpp
 * @brief Unit tests for shared transition-topology and buffer-budget compilation.
 * @author Fleming Patel
 *
 * Valid plans come from the production Gluon lowering path. Failure tests then
 * alter one resolved fact at a time, proving that planner self-validation,
 * Quark host admission, and dataplane admission share one structural contract.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/plan_buffer_budget.hpp"
#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"
#include "src/common/transition_topology.hpp"
#include "src/gluon/gluon_planner.hpp"
#include "tests/gluon_test_deployment.hpp"

namespace kinetum::common
{

namespace
{

/** Context-memory authority supplied to module-bearing fixtures. */
constexpr uint64_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = 2u * 1024u * 1024u;
/** Epoch-arena authority supplied to module-bearing fixtures. */
constexpr uint64_t TEST_EPOCH_ARENA_CAPACITY_BYTES = 2u * 1024u * 1024u;

/**
 * @brief Build deterministic single-node hardware for planner fixtures.
 *
 * @return Eight-core, one-NUMA-node hardware inventory.
 */
kinetum::hw::v1::HardwareInventory make_test_hardware()
{
	kinetum::hw::v1::HardwareInventory hardware;
	auto *cpu = hardware.mutable_node()->mutable_cpu();
	for (int32_t core_id = 0; core_id < 8; ++core_id) {
		auto *core = cpu->add_core_topology();
		core->set_core_id(core_id);
		core->set_numa_node(0);
		core->set_is_hyperthread(false);
	}
	return hardware;
}

/**
 * @brief Add one stage with explicit preferred-region placement.
 *
 * @param pipeline Pipeline to mutate.
 * @param stage_id Stable logical stage ID.
 * @param kind Stage kind.
 * @param preferred_region Required logical region.
 * @return Added stage.
 */
kinetum::axiom::v1::Stage *add_stage(kinetum::axiom::v1::Pipeline &pipeline, const std::string &stage_id,
				     kinetum::axiom::v1::StageKind kind, int32_t preferred_region)
{
	auto *stage = pipeline.add_stages();
	stage->set_stage_id(stage_id);
	stage->set_kind(kind);
	stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	stage->set_preferred_region(preferred_region);
	if (kind == kinetum::axiom::v1::STAGE_KIND_RX || kind == kinetum::axiom::v1::STAGE_KIND_TX) {
		stage->mutable_io()->set_interface(stage_id);
	}
	return stage;
}

/**
 * @brief Add one directed logical pipeline edge.
 *
 * @param pipeline Pipeline to mutate.
 * @param from_stage_id Source logical stage.
 * @param to_stage_id Destination logical stage.
 */
void add_edge(kinetum::axiom::v1::Pipeline &pipeline, const std::string &from_stage_id, const std::string &to_stage_id)
{
	auto *edge = pipeline.add_edges();
	edge->set_from_stage_id(from_stage_id);
	edge->set_to_stage_id(to_stage_id);
	edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
}

/**
 * @brief Run the production planner for one explicitly placed pipeline.
 *
 * @param pipeline Pipeline to lower.
 * @param bindings Complete explicit deployment intent for the pipeline.
 * @param region_count Required logical-region count.
 * @return Complete transition-enabled plan.
 * @throws std::runtime_error If production planning rejects the fixture.
 */
kinetum::gluon::v1::DeploymentPlan plan_pipeline(const kinetum::axiom::v1::Pipeline &pipeline,
						 kinetum::gluon::v1::DeploymentBindings bindings, int region_count)
{
	kinetum::gluon::planner_options options;
	options.regions = region_count;
	options.deployment_bindings = std::move(bindings);
	auto result = kinetum::gluon::plan(pipeline, make_test_hardware(), options);
	if (!result.is_ok()) {
		throw std::runtime_error("transition test planner failed: " + std::string(result.error().message()));
	}
	return result.value();
}

/**
 * @brief Build one cross-worker RX-to-module-to-TX transition plan.
 *
 * @return Valid production-lowered plan with one executable boundary.
 */
kinetum::gluon::v1::DeploymentPlan make_linear_transition_plan()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("transition_linear");
	add_stage(pipeline, "rx", kinetum::axiom::v1::STAGE_KIND_RX, 0);
	auto *acl = add_stage(pipeline, "acl", kinetum::axiom::v1::STAGE_KIND_MODULE, 1);
	acl->mutable_module()->set_module_id("kinetum.test.acl");
	acl->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	add_stage(pipeline, "tx", kinetum::axiom::v1::STAGE_KIND_TX, 1);
	add_edge(pipeline, "rx", "acl");
	add_edge(pipeline, "acl", "tx");
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	kinetum::test::add_zero_copy_stage_transition_binding(bindings, "rx_to_acl_share", "rx", "lane_0", "acl",
							      "lane_0", "storage_host_0");
	return plan_pipeline(pipeline, std::move(bindings), 2);
}

/**
 * @brief Build one RX-to-active-module plan with distinct source workers.
 *
 * @return Valid plan whose RX and active origin each own source admission.
 */
kinetum::gluon::v1::DeploymentPlan make_active_transition_plan()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("transition_active_source");
	add_stage(pipeline, "rx", kinetum::axiom::v1::STAGE_KIND_RX, 0);
	auto *active = add_stage(pipeline, "active0", kinetum::axiom::v1::STAGE_KIND_MODULE, 1);
	active->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	active->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));
	active->mutable_module()->set_module_id("kinetum.test_active");
	active->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	add_stage(pipeline, "tx", kinetum::axiom::v1::STAGE_KIND_TX, 1);
	add_edge(pipeline, "rx", "active0");
	add_edge(pipeline, "active0", "tx");
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	kinetum::test::add_zero_copy_stage_transition_binding(bindings, "rx_to_active0_share", "rx", "lane_0",
							      "active0", "lane_0", "storage_host_0");
	return plan_pipeline(pipeline, std::move(bindings), 2);
}

/**
 * @brief Build a two-input fan-in plan whose join owns two inbound boundaries.
 *
 * @return Valid production-lowered fan-in transition plan.
 */
kinetum::gluon::v1::DeploymentPlan make_fan_in_transition_plan()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("transition_fan_in");
	pipeline.set_allow_dag(true);
	add_stage(pipeline, "rx0", kinetum::axiom::v1::STAGE_KIND_RX, 0);
	add_stage(pipeline, "rx1", kinetum::axiom::v1::STAGE_KIND_RX, 1);
	auto *join = add_stage(pipeline, "join", kinetum::axiom::v1::STAGE_KIND_MODULE, 2);
	join->mutable_module()->set_module_id("kinetum.test.join");
	join->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	add_stage(pipeline, "tx", kinetum::axiom::v1::STAGE_KIND_TX, 2);
	add_edge(pipeline, "rx0", "join");
	add_edge(pipeline, "rx1", "join");
	add_edge(pipeline, "join", "tx");
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	kinetum::test::add_zero_copy_stage_transition_binding(bindings, "rx0_to_join_share", "rx0", "lane_0", "join",
							      "lane_0", "storage_host_0");
	kinetum::test::add_zero_copy_stage_transition_binding(bindings, "rx1_to_join_share", "rx1", "lane_0", "join",
							      "lane_0", "storage_host_0");
	return plan_pipeline(pipeline, std::move(bindings), 3);
}

/**
 * @brief Find one stage instance by exact identity.
 *
 * @param plan Deployment plan to search.
 * @param stage_instance_id Exact stage-instance identity.
 * @return Matching instance, or nullptr.
 */
const kinetum::gluon::v1::StageInstance *find_stage_instance(const kinetum::gluon::v1::DeploymentPlan &plan,
							     const std::string &stage_instance_id)
{
	for (const auto &instance : plan.stage_instances()) {
		if (instance.stage_instance_id() == stage_instance_id) {
			return &instance;
		}
	}
	return nullptr;
}

/**
 * @brief Find the worker that owns one stage instance.
 *
 * @param plan Deployment plan to search.
 * @param instance Exact executable endpoint.
 * @return Matching worker, or nullptr.
 */
const kinetum::gluon::v1::WorkerPlacement *find_instance_worker(const kinetum::gluon::v1::DeploymentPlan &plan,
								const kinetum::gluon::v1::StageInstance &instance)
{
	for (const auto &worker : plan.worker_placements()) {
		if (worker.region_id() == instance.region_id() && worker.lane_id() == instance.lane_id()) {
			return &worker;
		}
	}
	return nullptr;
}

/**
 * @brief Sort boundary records by the shared endpoint-order contract.
 *
 * @param plan Deployment plan to mutate.
 */
void sort_boundaries(kinetum::gluon::v1::DeploymentPlan &plan)
{
	std::vector<kinetum::gluon::v1::BoundaryPlacement> boundaries(plan.boundaries().begin(),
								      plan.boundaries().end());
	std::ranges::sort(boundaries, [](const auto &lhs, const auto &rhs) {
		return std::tie(lhs.from_stage_instance_id(), lhs.to_stage_instance_id()) <
		       std::tie(rhs.from_stage_instance_id(), rhs.to_stage_instance_id());
	});
	plan.clear_boundaries();
	for (const auto &boundary : boundaries) {
		*plan.add_boundaries() = boundary;
	}
}

/**
 * @brief Add one exact boundary for an authored logical edge on lane_0.
 *
 * @param plan Deployment plan to mutate.
 * @param from_stage_id Source logical stage.
 * @param to_stage_id Destination logical stage.
 * @throws std::runtime_error If the fixture lacks either endpoint or its exact worker/region owner.
 */
void add_boundary(kinetum::gluon::v1::DeploymentPlan &plan, const std::string &from_stage_id,
		  const std::string &to_stage_id)
{
	namespace topology_ids = kinetum::common::execution_topology;
	const auto from_id = topology_ids::make_stage_instance_id(from_stage_id, "lane_0");
	const auto to_id = topology_ids::make_stage_instance_id(to_stage_id, "lane_0");
	const auto *from = find_stage_instance(plan, from_id);
	const auto *to = find_stage_instance(plan, to_id);
	if (from == nullptr || to == nullptr) {
		throw std::runtime_error("transition fixture lost an exact stage-instance endpoint");
	}
	const auto *sender = find_instance_worker(plan, *from);
	const auto *receiver = find_instance_worker(plan, *to);
	if (sender == nullptr || receiver == nullptr) {
		throw std::runtime_error("transition fixture lost exact endpoint worker ownership");
	}
	if (to->region_id() < 0 || to->region_id() >= plan.regions_size()) {
		throw std::runtime_error("transition fixture endpoint has no exact destination region");
	}

	auto *boundary = plan.add_boundaries();
	boundary->set_boundary_id(topology_ids::make_boundary_id(from_id, to_id));
	boundary->set_from_stage_instance_id(from_id);
	boundary->set_to_stage_instance_id(to_id);
	boundary->set_sender_worker_id(sender->worker_id());
	boundary->set_receiver_worker_id(receiver->worker_id());
	boundary->set_data_ring_capacity(static_cast<uint32_t>(runtime_sizing::INTER_REGION_DATA_RING_CAPACITY));
	boundary->set_future_output_hold_capacity(
		static_cast<uint32_t>(runtime_sizing::BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY));
	boundary->set_data_ring_numa_node(plan.regions(to->region_id()).numa_node());
	sort_boundaries(plan);
}

/**
 * @brief Expect shared transition-topology admission to reject one mutation.
 *
 * @param plan Malformed deployment plan.
 * @param message Expected stable diagnostic fragment.
 */
void expect_transition_reject(const kinetum::gluon::v1::DeploymentPlan &plan, const std::string &message)
{
	const auto result = compile_transition_topology(plan);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find(message), std::string::npos) << result.error().message();
}

}  // namespace

/**
 * @brief Verify the production baseline round-trips the complete shared compiler.
 */
TEST(transition_topology, compiles_generated_policy_participants_and_boundaries)
{
	const auto plan = make_linear_transition_plan();
	const auto result = compile_transition_topology(plan);

	ASSERT_TRUE(result.is_ok()) << result.error().message();
	EXPECT_TRUE(result.value().policy.enabled);
	ASSERT_EQ(result.value().source_worker_indices.size(), 1u);
	ASSERT_EQ(result.value().sink_worker_indices.size(), 1u);
	ASSERT_EQ(result.value().boundaries.size(), 1u);
	ASSERT_EQ(result.value().runtime_services.size(), 2u);
	ASSERT_TRUE(result.value().lifecycle_services.has_value());
	EXPECT_EQ(result.value().lifecycle_services->coordinator_service_index, 0u);
	ASSERT_EQ(result.value().lifecycle_services->lifecycle_executor_service_indices.size(), 1u);
	EXPECT_EQ(result.value().lifecycle_services->lifecycle_executor_service_indices[0], 1u);
	EXPECT_TRUE(result.value().workers[result.value().source_worker_indices[0]].is_source);
	EXPECT_TRUE(result.value().workers[result.value().sink_worker_indices[0]].is_sink);
}

/** @brief Verify standalone transition compilation rejects unknown plan bytes. */
TEST(transition_topology, exact_plan_wire_rejects_before_topology_compilation)
{
	auto plan = make_linear_transition_plan();
	plan.GetReflection()->MutableUnknownFields(&plan)->AddVarint(99, 1u);

	const auto result = compile_transition_topology(plan);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("unknown protobuf field"), std::string::npos);
}

/** @brief Verify active origination independently makes its owner a source. */
TEST(transition_topology, active_origin_worker_is_an_exact_transition_source)
{
	const auto plan = make_active_transition_plan();
	const auto result = compile_transition_topology(plan);

	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_EQ(result.value().source_worker_indices.size(), 2u);
	const auto active = std::find_if(plan.stage_instances().begin(), plan.stage_instances().end(),
					 [](const auto &stage) { return stage.logical_stage_id() == "active0"; });
	ASSERT_NE(active, plan.stage_instances().end());
	const auto active_worker =
		std::find_if(result.value().workers.begin(), result.value().workers.end(), [&](const auto &worker) {
			return worker.region_id == active->region_id() && worker.lane_id == active->lane_id();
		});
	ASSERT_NE(active_worker, result.value().workers.end());
	EXPECT_TRUE(active_worker->is_source);
	EXPECT_GT(active_worker->source_epoch_staging_capacity, 0u);
}

/** @brief Verify one omitted cross-worker endpoint pair fails closed. */
TEST(transition_topology, rejects_missing_boundary)
{
	auto plan = make_linear_transition_plan();
	ASSERT_EQ(plan.boundaries_size(), 1);
	plan.clear_boundaries();
	expect_transition_reject(plan, "boundaries[] missing executable edge");
}

/** @brief Verify duplicate boundary endpoints cannot be deduplicated implicitly. */
TEST(transition_topology, rejects_duplicate_boundary)
{
	auto plan = make_linear_transition_plan();
	ASSERT_EQ(plan.boundaries_size(), 1);
	*plan.add_boundaries() = plan.boundaries(0);
	sort_boundaries(plan);
	expect_transition_reject(plan, "strictly ordered by executable endpoint identity");
}

/** @brief Verify a cross-worker endpoint pair without a logical edge is extra. */
TEST(transition_topology, rejects_extra_boundary_without_logical_edge)
{
	auto plan = make_linear_transition_plan();
	add_boundary(plan, "rx", "tx");
	expect_transition_reject(plan, "extra, same-worker, or references an unknown executable edge");
}

/** @brief Verify a same-worker edge may not receive a boundary record. */
TEST(transition_topology, rejects_same_worker_boundary)
{
	auto plan = make_linear_transition_plan();
	add_boundary(plan, "acl", "tx");
	expect_transition_reject(plan, "extra, same-worker, or references an unknown executable edge");
}

/** @brief Verify an unknown executable endpoint is never inferred or repaired. */
TEST(transition_topology, rejects_unknown_boundary_endpoint)
{
	auto plan = make_linear_transition_plan();
	ASSERT_EQ(plan.boundaries_size(), 1);
	auto *boundary = plan.mutable_boundaries(0);
	boundary->set_to_stage_instance_id("missing@lane_0");
	boundary->set_boundary_id(execution_topology::make_boundary_id(boundary->from_stage_instance_id(),
								       boundary->to_stage_instance_id()));
	expect_transition_reject(plan, "extra, same-worker, or references an unknown executable edge");
}

/** @brief Verify endpoint ownership cannot name a different sender worker. */
TEST(transition_topology, rejects_boundary_owner_mismatch)
{
	auto plan = make_linear_transition_plan();
	ASSERT_EQ(plan.boundaries_size(), 1);
	plan.mutable_boundaries(0)->set_sender_worker_id(plan.boundaries(0).receiver_worker_id());
	expect_transition_reject(plan, "disagrees with deterministic endpoint or worker ownership");
}

/** @brief Verify a complete boundary set cannot form a participant cycle. */
TEST(transition_topology, rejects_worker_boundary_cycle)
{
	auto plan = make_linear_transition_plan();
	add_edge(*plan.mutable_pipeline(), "tx", "rx");
	add_boundary(plan, "tx", "rx");
	expect_transition_reject(plan, "boundary graph contains a cycle");
}

/** @brief Verify fan-in admission requires every inbound executable cut owner. */
TEST(transition_topology, rejects_incomplete_fan_in_boundary_set)
{
	auto plan = make_fan_in_transition_plan();
	ASSERT_EQ(plan.boundaries_size(), 2);
	plan.mutable_boundaries()->RemoveLast();
	expect_transition_reject(plan, "boundaries[] missing executable edge");
}

/** @brief Verify DATA and future-output capacities obey the exact SPSC bound. */
TEST(transition_topology, rejects_boundary_capacities_outside_exact_spsc_contract)
{
	auto data_plan = make_linear_transition_plan();
	data_plan.mutable_boundaries(0)->set_data_ring_capacity(1);
	expect_transition_reject(data_plan, "capacities must be powers of two with at least two slots");

	auto hold_plan = make_linear_transition_plan();
	hold_plan.mutable_boundaries(0)->set_future_output_hold_capacity(1000);
	expect_transition_reject(hold_plan, "capacities must be powers of two with at least two slots");
}

/** @brief Verify DATA storage must remain on the receiver's exact NUMA node. */
TEST(transition_topology, rejects_boundary_data_numa_mismatch)
{
	auto plan = make_linear_transition_plan();
	plan.mutable_boundaries(0)->set_data_ring_numa_node(1);
	expect_transition_reject(plan, "DATA NUMA node does not match receiver ownership");
}

/** @brief Verify lifecycle executors exactly cover module-context NUMA ownership. */
TEST(transition_topology, rejects_incomplete_lifecycle_executor_numa_coverage)
{
	auto plan = make_linear_transition_plan();
	ASSERT_EQ(plan.regions_size(), 2);
	plan.mutable_regions(1)->set_numa_node(1);
	for (auto &boundary : *plan.mutable_boundaries()) {
		if (boundary.receiver_worker_id() == "worker_r1_lane_0") {
			boundary.set_data_ring_numa_node(1);
		}
	}
	expect_transition_reject(plan, "missing config lifecycle executor for NUMA node 1");
}

/** @brief Verify cancellation grace cannot dominate the prepare timeout. */
TEST(transition_topology, rejects_prepare_cancel_grace_above_prepare_timeout)
{
	auto plan = make_linear_transition_plan();
	auto *policy = plan.mutable_epoch_transition_plan();
	policy->set_prepare_cancel_grace_ms(policy->prepare_timeout_ms() + 1u);
	expect_transition_reject(plan, "prepare_cancel_grace_ms must not exceed prepare_timeout_ms");
}

/** @brief Verify the prepared lease budget is at least the prepare timeout. */
TEST(transition_topology, rejects_prepared_lease_below_prepare_timeout)
{
	auto plan = make_linear_transition_plan();
	auto *policy = plan.mutable_epoch_transition_plan();
	policy->set_prepared_lease_timeout_ms(policy->prepare_timeout_ms() - 1u);
	expect_transition_reject(plan, "must cover prepare and commit timeout budgets");
}

/** @brief Verify the prepared lease independently covers commit completion. */
TEST(transition_topology, rejects_prepared_lease_below_commit_timeout)
{
	auto plan = make_linear_transition_plan();
	auto *policy = plan.mutable_epoch_transition_plan();
	policy->set_prepare_timeout_ms(1000);
	policy->set_prepared_lease_timeout_ms(policy->commit_timeout_ms() - 1u);
	expect_transition_reject(plan, "must cover prepare and commit timeout budgets");
}

/** @brief Verify retirement cannot time out before the commit budget. */
TEST(transition_topology, rejects_retirement_timeout_below_commit_timeout)
{
	auto plan = make_linear_transition_plan();
	auto *policy = plan.mutable_epoch_transition_plan();
	policy->set_retirement_timeout_ms(policy->commit_timeout_ms() - 1u);
	expect_transition_reject(plan, "retirement_timeout_ms must not be shorter than commit_timeout_ms");
}

/** @brief Verify one health callback cannot consume its whole polling period. */
TEST(transition_topology, rejects_health_budget_at_or_above_poll_interval)
{
	auto plan = make_linear_transition_plan();
	auto *worker = plan.mutable_worker_placements(0);
	worker->set_module_health_callback_budget_ns(worker->module_health_poll_interval_ms() * 1'000'000u);
	expect_transition_reject(plan, "health callback budget must be shorter than its poll interval");
}

/** @brief Verify the terminal-result journal bound is closed and nonzero. */
TEST(transition_topology, rejects_terminal_history_outside_closed_bound)
{
	auto empty_plan = make_linear_transition_plan();
	empty_plan.mutable_epoch_transition_plan()->set_result_history_capacity(0);
	const auto empty_result = compile_transition_topology(empty_plan);
	ASSERT_FALSE(empty_result.is_ok());
	EXPECT_EQ(empty_result.error().code(), status_code::OUT_OF_RANGE);

	auto oversized_plan = make_linear_transition_plan();
	oversized_plan.mutable_epoch_transition_plan()->set_result_history_capacity(65);
	const auto oversized_result = compile_transition_topology(oversized_plan);
	ASSERT_FALSE(oversized_result.is_ok());
	EXPECT_EQ(oversized_result.error().code(), status_code::OUT_OF_RANGE);
}

/** @brief Verify source epoch-staging capacity exists exactly on source workers. */
TEST(transition_topology, rejects_inverted_source_epoch_staging_ownership)
{
	auto missing_source_plan = make_linear_transition_plan();
	const auto compiled = compile_transition_topology(missing_source_plan);
	ASSERT_TRUE(compiled.is_ok()) << compiled.error().message();
	ASSERT_EQ(compiled.value().source_worker_indices.size(), 1u);
	const uint32_t source_index = compiled.value().source_worker_indices[0];
	missing_source_plan.mutable_worker_placements(static_cast<int>(source_index))
		->set_source_epoch_staging_capacity(0);
	expect_transition_reject(missing_source_plan,
				 "requires source_epoch_staging_capacity to be a power of two with at least two slots");

	auto undersized_source_plan = make_linear_transition_plan();
	undersized_source_plan.mutable_worker_placements(static_cast<int>(source_index))
		->set_source_epoch_staging_capacity(1);
	expect_transition_reject(undersized_source_plan,
				 "requires source_epoch_staging_capacity to be a power of two with at least two slots");

	auto non_power_source_plan = make_linear_transition_plan();
	non_power_source_plan.mutable_worker_placements(static_cast<int>(source_index))
		->set_source_epoch_staging_capacity(1000);
	expect_transition_reject(non_power_source_plan,
				 "requires source_epoch_staging_capacity to be a power of two with at least two slots");

	auto non_source_plan = make_linear_transition_plan();
	const uint32_t non_source_index = source_index == 0u ? 1u : 0u;
	non_source_plan.mutable_worker_placements(static_cast<int>(non_source_index))
		->set_source_epoch_staging_capacity(1024);
	expect_transition_reject(non_source_plan, "must not allocate source_epoch_staging_capacity");
}

/** @brief Verify all nine storage-domain terms contribute exactly once. */
TEST(plan_buffer_budget, includes_exact_boundary_and_future_staging_terms)
{
	const storage_domain_buffer_budget_inputs inputs{
		.storage_domain_id = "domain0",
		.declared_buffer_count = 6000,
		.rx_descriptor_count = 100,
		.tx_descriptor_count = 200,
		.worker_count = 2,
		.worker_staging_capacity = 2048,
		.handoff_staging_capacity = 1024,
		.source_future_staging_capacity = 1024,
		.future_output_capacity = 512,
		.cache_size_per_worker = 64,
	};

	const auto budget = compile_storage_domain_buffer_budget(inputs);
	ASSERT_TRUE(budget.is_ok()) << budget.error().message();
	EXPECT_EQ(budget.value().storage_domain_id, "domain0");
	EXPECT_EQ(budget.value().required_min_buffers, 5228u);
	EXPECT_EQ(budget.value().safety_margin, runtime_sizing::PACKET_MAX_BURST_SIZE);
}

/** @brief Verify a provider with zero native descriptors/cache uses the same formula. */
TEST(plan_buffer_budget, host_storage_uses_shared_topology_terms_without_native_pool_inputs)
{
	const storage_domain_buffer_budget_inputs inputs{
		.storage_domain_id = "host0",
		.declared_buffer_count = 5000,
		.rx_descriptor_count = 0,
		.tx_descriptor_count = 0,
		.worker_count = 2,
		.worker_staging_capacity = 2048,
		.handoff_staging_capacity = 1024,
		.source_future_staging_capacity = 1024,
		.future_output_capacity = 512,
		.cache_size_per_worker = 0,
	};

	const auto budget = compile_storage_domain_buffer_budget(inputs);
	ASSERT_TRUE(budget.is_ok()) << budget.error().message();
	EXPECT_EQ(budget.value().required_min_buffers, 4800u);
	EXPECT_EQ(budget.value().safety_margin, runtime_sizing::PACKET_MAX_BURST_SIZE);
}

/** @brief Verify insufficient capacity and checked arithmetic fail closed. */
TEST(plan_buffer_budget, rejects_capacity_below_floor_or_arithmetic_overflow)
{
	storage_domain_buffer_budget_inputs inputs{
		.storage_domain_id = "domain0",
		.declared_buffer_count = 1,
		.rx_descriptor_count = 1,
		.tx_descriptor_count = 1,
		.worker_count = 1,
		.worker_staging_capacity = 1024,
		.handoff_staging_capacity = 0,
		.source_future_staging_capacity = 0,
		.future_output_capacity = 0,
		.cache_size_per_worker = 0,
	};
	const auto undersized = compile_storage_domain_buffer_budget(inputs);
	ASSERT_FALSE(undersized.is_ok());
	EXPECT_NE(undersized.error().message().find("buffer_count below computed minimum"), std::string::npos);

	inputs.declared_buffer_count = UINT64_MAX;
	inputs.worker_staging_capacity = 0;
	const auto missing_staging = compile_storage_domain_buffer_budget(inputs);
	ASSERT_FALSE(missing_staging.is_ok());
	EXPECT_EQ(missing_staging.error().code(), status_code::INVALID_ARGUMENT);

	inputs.worker_staging_capacity = 1024;
	inputs.rx_descriptor_count = UINT64_MAX;
	const auto overflow = compile_storage_domain_buffer_budget(inputs);
	ASSERT_FALSE(overflow.is_ok());
	EXPECT_EQ(overflow.error().code(), status_code::OUT_OF_RANGE);
}

}  // namespace kinetum::common
