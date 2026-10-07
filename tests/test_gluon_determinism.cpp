// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_gluon_determinism.cpp
 * @brief Gluon planner determinism tests.
 * @author Fleming Patel
 *
 * The Gluon planner partitions pipeline stages into regions, lowers executable
 * workers, and assigns disjoint packet-worker and runtime-service cores. This
 * suite verifies the determinism requirement: given identical inputs, the
 * planner must produce identical placement and identity facts.
 *
 * Why Determinism Matters:
 * ------------------------
 * 1. Reproducible deployments across fleet nodes
 * 2. Debugging: same plan on dev machine as production
 * 3. Rollback safety: reverting config produces same execution plan
 * 4. Testing: CI/CD can validate plans deterministically
 *
 * Implementation Notes:
 * ---------------------
 * - Canonical identities and explicit lexical tie-breakers own ordering
 * - NUMA-aware assignment follows deterministic socket selection
 *
 * @see src/gluon/gluon_planner.cpp
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <limits>

#include "src/common/runtime_service_ids.hpp"
#include "src/common/transition_topology.hpp"
#include "src/gluon/gluon_planner.hpp"
#include "src/gluon/runtime_core_placement.hpp"
#include "src/gluon/transition_plan_lowering.hpp"
#include "src/provider/deployment_plan_identity.hpp"
#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "tests/gluon_test_deployment.hpp"

//==============================================================================
// Test Helpers
//==============================================================================

/**
 * @brief Create a simple linear 3-stage pipeline for testing.
 *
 * Creates the canonical pipeline: RX -> PARSE_IPV4 -> TX
 * This is the minimal valid pipeline per Axiom contract.
 *
 * @return Pipeline with RX -> PARSE_IPV4 -> TX stages
 */
static kinetum::axiom::v1::Pipeline make_linear()
{
	kinetum::axiom::v1::Pipeline p;
	p.set_pipeline_id("p");
	auto *rx = p.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->mutable_io()->set_interface("wan0");
	auto *pa = p.add_stages();
	pa->set_stage_id("p");
	pa->set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	pa->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	auto *tx = p.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface("lan0");
	auto *e1 = p.add_edges();
	e1->set_from_stage_id("rx");
	e1->set_to_stage_id("p");
	e1->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	auto *e2 = p.add_edges();
	e2->set_from_stage_id("p");
	e2->set_to_stage_id("tx");
	e2->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	return p;
}

/**
 * @brief Create a minimal hardware inventory with one CPU node.
 * @param cores Number of exact cores to author on NUMA node zero.
 * @return Complete single-node hardware inventory.
 */
static kinetum::hw::v1::HardwareInventory make_host_hw(int32_t cores = 4)
{
	kinetum::hw::v1::HardwareInventory hw;
	auto *cpu = hw.mutable_node()->mutable_cpu();
	for (int32_t core_id = 0; core_id < cores; ++core_id) {
		auto *core = cpu->add_core_topology();
		core->set_core_id(core_id);
		core->set_numa_node(0);
		core->set_is_hyperthread(false);
	}
	return hw;
}

/**
 * @brief Build planner options with complete explicit test deployment intent.
 *
 * @param pipeline Pipeline whose identities must be bound.
 * @param regions Exact logical-region count.
 * @return Planner options containing one complete UDP/host/CPU provider graph.
 */
static kinetum::gluon::planner_options make_planner_options(const kinetum::axiom::v1::Pipeline &pipeline,
							    int32_t regions = 2)
{
	kinetum::gluon::planner_options options;
	options.regions = regions;
	options.deployment_bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	return options;
}

/**
 * @brief Build complete two-worker deployment intent for the linear fixture.
 *
 * @param pipeline Exact RX-to-parse-to-TX fixture.
 * @return Planner options with the explicit cross-worker zero-copy transition.
 */
static kinetum::gluon::planner_options make_linear_planner_options(const kinetum::axiom::v1::Pipeline &pipeline)
{
	auto options = make_planner_options(pipeline);
	kinetum::test::add_zero_copy_stage_transition_binding(options.deployment_bindings, "rx_to_parse_share", "rx",
							      "lane_0", "p", "lane_0", "storage_host_0");
	return options;
}

//==============================================================================
// Determinism Tests
//==============================================================================

/**
 * @brief Verify Gluon produces deterministic emitted topology for identical inputs.
 *
 * Determinism requirement:
 * Given the same pipeline and hardware inventory, calling plan() multiple
 * times must produce the same deterministic placement and identity facts;
 * explicitly time-varying planning metadata is excluded. This enables:
 * - Fleet-wide consistency (all nodes get same plan)
 * - Reproducible debugging (dev matches prod)
 * - Safe rollback (old config produces old plan)
 *
 * Verification:
 * - Region count must match
 * - Execution-lane and stage-instance counts must match
 * - Worker-placement and emitted-boundary counts must match
 *
 * @note This test calls plan() twice and compares load-bearing structural
 *       equality plus deterministic plan identity.
 */
TEST(gluon, deterministic_regions)
{
	auto hw = make_host_hw();

	auto p = make_linear();
	auto opt = make_linear_planner_options(p);
	auto a = kinetum::gluon::plan(p, hw, opt);
	auto b = kinetum::gluon::plan(p, hw, opt);

	ASSERT_TRUE(a.is_ok()) << "First plan() call failed: " << a.error().message();
	ASSERT_TRUE(b.is_ok()) << "Second plan() call failed: " << b.error().message();

	// Structural equality checks
	EXPECT_EQ(a.value().regions_size(), b.value().regions_size()) << "Region count must be deterministic";
	EXPECT_EQ(a.value().execution_lanes_size(), b.value().execution_lanes_size())
		<< "Execution-lane count must be deterministic";
	EXPECT_EQ(a.value().stage_instances_size(), b.value().stage_instances_size())
		<< "Stage-instance count must be deterministic";
	EXPECT_EQ(a.value().worker_placements_size(), b.value().worker_placements_size())
		<< "Worker-placement count must be deterministic";
	EXPECT_EQ(a.value().plan_id(), b.value().plan_id()) << "Plan identity must be deterministic";
	EXPECT_EQ(a.value().content_hash(), b.value().content_hash())
		<< "Canonical plan content identity must exclude declared timing volatility";
	auto recomputed_hash_or = kinetum::provider::compute_deployment_plan_content_hash(a.value());
	ASSERT_TRUE(recomputed_hash_or.is_ok()) << recomputed_hash_or.error().message();
	EXPECT_EQ(a.value().content_hash(), recomputed_hash_or.value())
		<< "Planner must hash after late stable metadata is populated";
	EXPECT_TRUE(kinetum::provider::verify_deployment_plan_content_hash(a.value()).is_ok());
	ASSERT_GT(a.value().boundaries_size(), 0);
	ASSERT_EQ(a.value().boundaries_size(), b.value().boundaries_size());
	for (int i = 0; i < a.value().boundaries_size(); ++i) {
		EXPECT_EQ(a.value().boundaries(i).SerializeAsString(), b.value().boundaries(i).SerializeAsString());
	}
	ASSERT_TRUE(a.value().has_epoch_transition_plan());
	ASSERT_TRUE(b.value().has_epoch_transition_plan());
	EXPECT_EQ(a.value().epoch_transition_plan().SerializeAsString(),
		  b.value().epoch_transition_plan().SerializeAsString());
	ASSERT_EQ(a.value().runtime_service_placements_size(), 2);
	ASSERT_EQ(b.value().runtime_service_placements_size(), 2);
	for (int i = 0; i < a.value().runtime_service_placements_size(); ++i) {
		EXPECT_EQ(a.value().runtime_service_placements(i).SerializeAsString(),
			  b.value().runtime_service_placements(i).SerializeAsString());
	}
	EXPECT_EQ(a.value().runtime_service_placements(0).service_id(),
		  kinetum::common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID);
	EXPECT_EQ(a.value().runtime_service_placements(0).command_mailbox_capacity(),
		  kinetum::gluon::COORDINATOR_COMMAND_MAILBOX_CAPACITY);
	EXPECT_EQ(a.value().runtime_service_placements(1).service_id(),
		  kinetum::common::runtime_services::make_lifecycle_executor_id(0));
	EXPECT_EQ(a.value().runtime_service_placements(1).command_mailbox_capacity(), 0u);
	const auto compiled_or = kinetum::common::compile_transition_topology(a.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();
	EXPECT_TRUE(compiled.policy.enabled);
	EXPECT_EQ(a.value().epoch_transition_plan().prepare_timeout_ms(),
		  kinetum::gluon::TRANSITION_PREPARE_TIMEOUT_MS);
	EXPECT_EQ(a.value().epoch_transition_plan().prepare_cancel_grace_ms(),
		  kinetum::gluon::TRANSITION_PREPARE_CANCEL_GRACE_MS);
	EXPECT_EQ(a.value().epoch_transition_plan().prepared_lease_timeout_ms(),
		  kinetum::gluon::TRANSITION_PREPARED_LEASE_TIMEOUT_MS);
	EXPECT_EQ(a.value().epoch_transition_plan().commit_timeout_ms(), kinetum::gluon::TRANSITION_COMMIT_TIMEOUT_MS);
	EXPECT_EQ(a.value().epoch_transition_plan().retirement_timeout_ms(),
		  kinetum::gluon::TRANSITION_RETIREMENT_TIMEOUT_MS);
	EXPECT_EQ(a.value().epoch_transition_plan().result_history_capacity(),
		  kinetum::gluon::TRANSITION_RESULT_HISTORY_CAPACITY);
	ASSERT_GT(a.value().worker_placements_size(), 0);
	for (const auto &worker : a.value().worker_placements()) {
		const bool is_source = std::ranges::find(compiled.source_worker_indices, worker.worker_index()) !=
				       compiled.source_worker_indices.end();
		EXPECT_EQ(worker.source_epoch_staging_capacity(),
			  is_source ? kinetum::gluon::SOURCE_EPOCH_STAGING_CAPACITY : 0u);
		EXPECT_EQ(worker.module_health_poll_interval_ms(), kinetum::gluon::MODULE_HEALTH_POLL_INTERVAL_MS);
		EXPECT_EQ(worker.module_health_callback_budget_ns(), kinetum::gluon::MODULE_HEALTH_CALLBACK_BUDGET_NS);
	}
}

//==============================================================================
// Exact Axiom-to-Gluon Admission
//==============================================================================

/** @brief Direct planner callers cannot omit the explicit stage execution mode. */
TEST(gluon, direct_plan_rejects_missing_execution_mode)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	pipeline.mutable_stages(1)->clear_execution_mode();
	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("execution_mode"), std::string::npos);
}

/** @brief Direct planner callers cannot omit packet-edge driving mode. */
TEST(gluon, direct_plan_rejects_missing_edge_mode)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	pipeline.mutable_edges(0)->clear_mode();
	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("PUSH or PULL"), std::string::npos);
}

/** @brief Direct planner callers reject an undeclared stage-kind number. */
TEST(gluon, direct_plan_rejects_unknown_stage_kind)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	pipeline.mutable_stages(1)->set_kind(static_cast<kinetum::axiom::v1::StageKind>(255));
	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("unknown enum number"), std::string::npos);
}

/** @brief A stage kind cannot consume another kind's typed configuration. */
TEST(gluon, direct_plan_rejects_kind_configuration_mismatch)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	pipeline.mutable_stages(1)->mutable_io()->set_interface("wrong_owner");
	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("must not carry"), std::string::npos);
}

/**
 * @brief Unknown provider contracts fail at planner admission.
 *
 * Provider identity is the complete canonical type URL. Gluon must reject an
 * unregistered contract before emitting any plan provider graph.
 */
TEST(gluon, unknown_provider_contract_rejected)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	auto opt = make_planner_options(pipeline);
	opt.deployment_bindings.mutable_io_driver_instances(0)->mutable_configuration()->set_type_url(
		"type.googleapis.com/kinetum.io.unknown.v1.UnknownDriverConfig");

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok()) << "Unknown provider contract must be rejected by Gluon";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::NOT_FOUND);
	EXPECT_NE(result.error().message().find("no provider contract matches"), std::string::npos);
}

/**
 * @brief Missing deployment intent fails instead of acquiring defaults.
 */
TEST(gluon, missing_deployment_bindings_rejected)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();

	kinetum::gluon::planner_options opt;
	opt.regions = 2;

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok()) << "Missing deployment bindings must be rejected by Gluon";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("binding"), std::string::npos);
}

/**
 * @brief Negative reserved_cores fails at planner admission.
 */
TEST(gluon, negative_reserved_cores_rejected)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	auto opt = make_planner_options(pipeline);
	opt.reserved_cores = -1;

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok()) << "Negative reserved_cores must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("reserved_cores"), std::string::npos);
}

/**
 * @brief Negative allowed_numa_nodes entries fail at planner admission.
 */
TEST(gluon, negative_allowed_numa_node_rejected)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	auto opt = make_planner_options(pipeline);
	opt.allowed_numa_nodes.push_back(-1);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok()) << "Negative allowed_numa_nodes entry must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("allowed_numa_nodes"), std::string::npos);
}

/** @brief An I/O kind cannot carry module configuration. */
TEST(gluon, io_stage_rejects_module_configuration)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	pipeline.mutable_stages(0)->mutable_module()->set_module_id("kinetum.test");
	pipeline.mutable_stages(0)->mutable_module()->set_context_selection(
		kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("I/O stage"), std::string::npos);
}

/** @brief A module kind cannot carry I/O configuration. */
TEST(gluon, module_stage_rejects_io_configuration)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	auto *stage = pipeline.mutable_stages(1);
	stage->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	stage->mutable_io()->set_interface("wrong_owner");

	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("module stage"), std::string::npos);
}

/** @brief A module kind cannot omit its typed configuration. */
TEST(gluon, module_stage_rejects_missing_configuration)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	pipeline.mutable_stages(1)->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);

	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("module_id"), std::string::npos);
}

/** @brief An I/O stage cannot omit its exact interface identity. */
TEST(gluon, io_stage_rejects_empty_interface)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	pipeline.mutable_stages(0)->mutable_io()->clear_interface();

	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("interface"), std::string::npos);
}

/** @brief Stage.cost_weight is the sole authored planning-weight override. */
TEST(gluon, stage_cost_weight_is_the_exact_authored_override)
{
	auto hw = make_host_hw();
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("weighted_partition");
	const auto add_stage = [&pipeline](const char *stage_id, kinetum::axiom::v1::StageKind kind,
					   uint32_t cost_weight) {
		auto *stage = pipeline.add_stages();
		stage->set_stage_id(stage_id);
		stage->set_kind(kind);
		stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		stage->set_cost_weight(cost_weight);
		return stage;
	};
	add_stage("rx", kinetum::axiom::v1::STAGE_KIND_RX, 0u)->mutable_io()->set_interface("wan0");
	add_stage("p1", kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4, 1u);
	add_stage("p2", kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4, 10u);
	add_stage("p3", kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4, 10u);
	add_stage("tx", kinetum::axiom::v1::STAGE_KIND_TX, 0u)->mutable_io()->set_interface("lan0");
	for (const auto &[from, to] :
	     {std::pair{"rx", "p1"}, std::pair{"p1", "p2"}, std::pair{"p2", "p3"}, std::pair{"p3", "tx"}}) {
		auto *edge = pipeline.add_edges();
		edge->set_from_stage_id(from);
		edge->set_to_stage_id(to);
		edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	}

	auto opt = make_planner_options(pipeline);
	kinetum::test::add_zero_copy_stage_transition_binding(opt.deployment_bindings, "p2_to_p3_share", "p2", "lane_0",
							      "p3", "lane_0", "storage_host_0");

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_EQ(result->regions_size(), 2);
	ASSERT_EQ(result->regions(0).logical_stage_ids_size(), 3);
	EXPECT_EQ(result->regions(0).logical_stage_ids(0), "rx");
	EXPECT_EQ(result->regions(0).logical_stage_ids(1), "p1");
	EXPECT_EQ(result->regions(0).logical_stage_ids(2), "p2");
	ASSERT_EQ(result->regions(1).logical_stage_ids_size(), 2);
	EXPECT_EQ(result->regions(1).logical_stage_ids(0), "p3");
	EXPECT_EQ(result->regions(1).logical_stage_ids(1), "tx");

	auto maximum = pipeline;
	maximum.mutable_stages(1)->set_cost_weight(std::numeric_limits<uint32_t>::max());
	auto maximum_options = make_planner_options(maximum, 1);
	const auto maximum_result = kinetum::gluon::plan(maximum, hw, maximum_options);
	ASSERT_TRUE(maximum_result.is_ok()) << maximum_result.error().message();
	EXPECT_EQ(maximum_result->pipeline().stages(1).cost_weight(), std::numeric_limits<uint32_t>::max());
}

/** @brief The internal weight backstop cannot classify an undeclared stage. */
TEST(gluon, stage_weight_rejects_invalid_kind_and_module_identity)
{
	kinetum::axiom::v1::Stage invalid_kind;
	invalid_kind.set_kind(kinetum::axiom::v1::STAGE_KIND_UNSPECIFIED);
	EXPECT_DEATH({ (void)kinetum::gluon::default_stage_weight(invalid_kind); }, "");

	kinetum::axiom::v1::Stage missing_module;
	missing_module.set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	EXPECT_DEATH({ (void)kinetum::gluon::default_stage_weight(missing_module); }, "");
}

/** @brief Axiom affinity relations are enforced by the sole partitioner. */
TEST(gluon, authored_affinity_relations_are_enforced)
{
	auto hardware = make_host_hw();
	auto colocate = make_linear();
	colocate.mutable_stages(0)->mutable_constraints()->add_affinity_stages("tx");
	auto colocate_result = kinetum::gluon::plan(colocate, hardware, make_linear_planner_options(colocate));
	ASSERT_FALSE(colocate_result.is_ok());
	EXPECT_NE(colocate_result.error().message().find("must_colocate"), std::string::npos);

	auto separate = make_linear();
	separate.mutable_stages(0)->mutable_constraints()->add_anti_affinity_stages("tx");
	auto options = make_planner_options(separate, 1);
	auto separate_result = kinetum::gluon::plan(separate, hardware, options);
	ASSERT_FALSE(separate_result.is_ok());
	EXPECT_NE(separate_result.error().message().find("must_separate"), std::string::npos);
}

/** @brief PARSE_IPV4 rejects typed configuration residue. */
TEST(gluon, parse_stage_rejects_configuration_residue)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	pipeline.mutable_stages(1)->mutable_io()->set_interface("residue");

	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("PARSE_IPV4"), std::string::npos);
}

/** @brief Present module_path must contain one nonempty source identity. */
TEST(gluon, empty_module_path_presence_rejected)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	auto *stage = pipeline.mutable_stages(1);
	stage->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	stage->mutable_module()->set_module_id("kinetum.test");
	stage->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	stage->mutable_module()->set_module_path("");

	auto opt = make_planner_options(pipeline);

	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("module_path"), std::string::npos);
}

//==============================================================================
// Closed Stage-Kind Contract
//==============================================================================

/**
 * @brief Create a linear pipeline whose middle stage carries an invalid kind.
 *
 * @param kind Sentinel or unknown stage-kind value under test.
 * @return Complete pipeline with only the middle kind made invalid.
 */
static kinetum::axiom::v1::Pipeline make_with_invalid_kind(kinetum::axiom::v1::StageKind kind)
{
	auto pipeline = make_linear();
	pipeline.mutable_stages(1)->set_kind(kind);
	return pipeline;
}

/** @brief The required stage-kind sentinel cannot enter planner lowering. */
TEST(gluon, unspecified_stage_kind_rejected)
{
	auto hw = make_host_hw();
	auto pipeline = make_with_invalid_kind(kinetum::axiom::v1::STAGE_KIND_UNSPECIFIED);
	auto result = kinetum::gluon::plan(pipeline, hw, make_planner_options(pipeline));

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("current stage kind"), std::string::npos);
}

/** @brief An undeclared numeric stage kind cannot enter planner lowering. */
TEST(gluon, unknown_stage_kind_rejected)
{
	auto hw = make_host_hw();
	auto pipeline = make_with_invalid_kind(static_cast<kinetum::axiom::v1::StageKind>(255));
	auto result = kinetum::gluon::plan(pipeline, hw, make_planner_options(pipeline));

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("unknown enum number"), std::string::npos);
}

/**
 * @brief Supported stages still lower through an explicit provider graph.
 *
 * The closed kind set must still lower every currently executable stage.
 */
TEST(gluon, supported_stages_lower_through_explicit_provider_graph)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	auto opt = make_linear_planner_options(pipeline);
	auto result = kinetum::gluon::plan(pipeline, hw, opt);

	ASSERT_TRUE(result.is_ok())
		<< "Supported stages must lower through explicit deployment intent: " << result.error().message();
	EXPECT_GT(result.value().regions_size(), 0) << "Plan must have at least one region";
}

/** @brief A stage cannot bypass kind admission through foreign typed configuration. */
TEST(gluon, no_silent_kind_configuration_bypass)
{
	auto hw = make_host_hw();
	auto pipeline = make_linear();
	pipeline.mutable_stages(0)->mutable_module()->set_module_id("kinetum.test");
	pipeline.mutable_stages(0)->mutable_module()->set_context_selection(
		kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	auto result = kinetum::gluon::plan(pipeline, hw, make_planner_options(pipeline));

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("I/O stage"), std::string::npos);
}
