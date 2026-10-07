// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_gluon_boundary_topology.cpp
 * @brief Tests deterministic executable BoundaryPlacement lowering.
 * @author Fleming Patel
 *
 * The suite exercises the boundary lowering pass directly after constructing
 * final stage-instance, worker, and region-NUMA ownership. It proves the exact
 * cross-worker set contract, deterministic directed identity, transactional
 * failure, capacity/NUMA facts, and absence of runtime-style lane cloning.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/runtime_sizing.hpp"
#include "src/gluon/boundary_topology_lowering.hpp"

namespace kinetum::gluon
{
namespace
{

/**
 * @brief Add one logical region with resolved NUMA placement.
 *
 * @param plan Plan receiving the region.
 * @param region_id Compact region identity.
 * @param numa_node Final runtime NUMA placement.
 */
void add_region(kinetum::gluon::v1::DeploymentPlan &plan, int32_t region_id, int32_t numa_node)
{
	auto *region = plan.add_regions();
	region->set_region_id(region_id);
	region->set_numa_node(numa_node);
}

/**
 * @brief Add one canonical execution lane.
 *
 * @param plan Plan receiving the lane.
 * @param lane_index Compact lane index.
 * @return Canonical emitted lane ID.
 */
std::string add_lane(kinetum::gluon::v1::DeploymentPlan &plan, uint32_t lane_index)
{
	const auto lane_id = kinetum::common::execution_topology::make_lane_id(lane_index);
	auto *lane = plan.add_execution_lanes();
	lane->set_lane_id(lane_id);
	lane->set_lane_index(lane_index);
	return lane_id;
}

/**
 * @brief Add one logical stage to the authored pipeline.
 *
 * @param plan Plan receiving the stage.
 * @param stage_id Canonical logical stage ID.
 */
void add_stage(kinetum::gluon::v1::DeploymentPlan &plan, const std::string &stage_id)
{
	auto *stage = plan.mutable_pipeline()->add_stages();
	stage->set_stage_id(stage_id);
	stage->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	stage->mutable_module()->set_module_id("kinetum.test." + stage_id);
	stage->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
}

/**
 * @brief Add one authored directed stage edge.
 *
 * @param plan Plan receiving the edge.
 * @param from_stage_id Source logical stage ID.
 * @param to_stage_id Destination logical stage ID.
 */
void add_edge(kinetum::gluon::v1::DeploymentPlan &plan, const std::string &from_stage_id,
	      const std::string &to_stage_id)
{
	auto *edge = plan.mutable_pipeline()->add_edges();
	edge->set_from_stage_id(from_stage_id);
	edge->set_to_stage_id(to_stage_id);
	edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
}

/**
 * @brief Add one canonical executable stage instance.
 *
 * @param plan Plan receiving the stage instance.
 * @param logical_stage_id Authored logical stage ID.
 * @param lane_id Canonical execution lane ID.
 * @param region_id Owning logical region.
 */
void add_stage_instance(kinetum::gluon::v1::DeploymentPlan &plan, const std::string &logical_stage_id,
			const std::string &lane_id, int32_t region_id)
{
	auto *instance = plan.add_stage_instances();
	instance->set_stage_instance_id(
		kinetum::common::execution_topology::make_stage_instance_id(logical_stage_id, lane_id));
	instance->set_logical_stage_id(logical_stage_id);
	instance->set_lane_id(lane_id);
	instance->set_region_id(region_id);
}

/**
 * @brief Add one canonical runtime worker owner.
 *
 * @param plan Plan receiving the worker placement.
 * @param region_id Worker region.
 * @param lane_id Worker lane.
 * @param worker_index Compact worker index.
 */
void add_worker(kinetum::gluon::v1::DeploymentPlan &plan, int32_t region_id, const std::string &lane_id,
		uint32_t worker_index)
{
	auto *worker = plan.add_worker_placements();
	worker->set_worker_id(kinetum::common::execution_topology::make_worker_id(region_id, lane_id));
	worker->set_region_id(region_id);
	worker->set_lane_id(lane_id);
	worker->set_worker_index(worker_index);
}

/**
 * @brief Build a complete two-stage executable graph.
 *
 * @param source_region Region owning the source stage.
 * @param destination_region Region owning the destination stage.
 * @param lane_count Number of full lane-local graph replicas.
 * @return Plan ready for boundary lowering.
 */
kinetum::gluon::v1::DeploymentPlan make_two_stage_plan(int32_t source_region, int32_t destination_region,
						       uint32_t lane_count)
{
	kinetum::gluon::v1::DeploymentPlan plan;
	plan.set_plan_id("boundary_topology_test");
	plan.mutable_pipeline()->set_pipeline_id("boundary_topology_pipeline");
	add_stage(plan, "source");
	add_stage(plan, "destination");
	add_edge(plan, "source", "destination");

	add_region(plan, source_region, source_region);
	if (destination_region != source_region) {
		add_region(plan, destination_region, destination_region);
	}

	uint32_t worker_index = 0;
	for (uint32_t lane_index = 0; lane_index < lane_count; ++lane_index) {
		const auto lane_id = add_lane(plan, lane_index);
		add_stage_instance(plan, "source", lane_id, source_region);
		add_stage_instance(plan, "destination", lane_id, destination_region);
		add_worker(plan, source_region, lane_id, worker_index++);
		if (destination_region != source_region) {
			add_worker(plan, destination_region, lane_id, worker_index++);
		}
	}
	return plan;
}

/** @brief Same-worker executable edges require no boundary record. */
TEST(gluon_boundary_topology, same_worker_edge_emits_no_boundary)
{
	auto plan = make_two_stage_plan(0, 0, 1);

	const auto status = lower_boundary_topology(plan);

	ASSERT_TRUE(status.is_ok()) << status.message();
	EXPECT_EQ(plan.boundaries_size(), 0);
}

/** @brief Cross-worker lowering emits exact directed ownership, capacity, and NUMA facts. */
TEST(gluon_boundary_topology, cross_worker_edge_emits_exact_placement)
{
	auto plan = make_two_stage_plan(0, 1, 1);

	const auto status = lower_boundary_topology(plan);

	ASSERT_TRUE(status.is_ok()) << status.message();
	ASSERT_EQ(plan.boundaries_size(), 1);
	const auto &boundary = plan.boundaries(0);
	EXPECT_EQ(boundary.boundary_id(), "boundary.source@lane_0.destination@lane_0");
	EXPECT_EQ(boundary.from_stage_instance_id(), "source@lane_0");
	EXPECT_EQ(boundary.to_stage_instance_id(), "destination@lane_0");
	EXPECT_EQ(boundary.sender_worker_id(), "worker_r0_lane_0");
	EXPECT_EQ(boundary.receiver_worker_id(), "worker_r1_lane_0");
	EXPECT_EQ(boundary.data_ring_capacity(),
		  static_cast<uint32_t>(kinetum::common::runtime_sizing::INTER_REGION_DATA_RING_CAPACITY));
	EXPECT_EQ(boundary.future_output_hold_capacity(),
		  static_cast<uint32_t>(kinetum::common::runtime_sizing::BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY));
	EXPECT_EQ(boundary.data_ring_numa_node(), 1);
	EXPECT_NE(kinetum::common::execution_topology::make_boundary_id("source@lane_0", "destination@lane_0"),
		  kinetum::common::execution_topology::make_boundary_id("destination@lane_0", "source@lane_0"));

	// SPSC ownership is directional: the reverse authored edge owns a second
	// record with reversed workers and receiver-local NUMA placement.
	auto bidirectional = make_two_stage_plan(0, 1, 1);
	add_edge(bidirectional, "destination", "source");
	const auto bidirectional_status = lower_boundary_topology(bidirectional);
	ASSERT_TRUE(bidirectional_status.is_ok()) << bidirectional_status.message();
	ASSERT_EQ(bidirectional.boundaries_size(), 2);
	EXPECT_EQ(bidirectional.boundaries(0).boundary_id(), "boundary.destination@lane_0.source@lane_0");
	EXPECT_EQ(bidirectional.boundaries(0).sender_worker_id(), "worker_r1_lane_0");
	EXPECT_EQ(bidirectional.boundaries(0).receiver_worker_id(), "worker_r0_lane_0");
	EXPECT_EQ(bidirectional.boundaries(0).data_ring_numa_node(), 0);
	EXPECT_EQ(bidirectional.boundaries(1).boundary_id(), "boundary.source@lane_0.destination@lane_0");
}

/** @brief Fan-in emits the exact distinct cross-worker endpoint set in canonical order. */
TEST(gluon_boundary_topology, fan_in_graph_emits_two_sorted_boundaries)
{
	kinetum::gluon::v1::DeploymentPlan plan;
	plan.mutable_pipeline()->set_pipeline_id("fan_in");
	add_stage(plan, "rx0");
	add_stage(plan, "rx1");
	add_stage(plan, "join");
	// Deliberately reverse authored edge order; endpoint identity owns emission order.
	add_edge(plan, "rx1", "join");
	add_edge(plan, "rx0", "join");
	add_region(plan, 0, 0);
	add_region(plan, 1, 1);
	add_region(plan, 2, 2);
	const auto lane_id = add_lane(plan, 0);
	add_stage_instance(plan, "rx0", lane_id, 0);
	add_stage_instance(plan, "rx1", lane_id, 1);
	add_stage_instance(plan, "join", lane_id, 2);
	add_worker(plan, 0, lane_id, 0);
	add_worker(plan, 1, lane_id, 1);
	add_worker(plan, 2, lane_id, 2);

	const auto status = lower_boundary_topology(plan);

	ASSERT_TRUE(status.is_ok()) << status.message();
	ASSERT_EQ(plan.boundaries_size(), 2);
	EXPECT_EQ(plan.boundaries(0).boundary_id(), "boundary.rx0@lane_0.join@lane_0");
	EXPECT_EQ(plan.boundaries(1).boundary_id(), "boundary.rx1@lane_0.join@lane_0");
	EXPECT_EQ(plan.boundaries(0).receiver_worker_id(), "worker_r2_lane_0");
	EXPECT_EQ(plan.boundaries(1).receiver_worker_id(), "worker_r2_lane_0");
}

/** @brief Replicated cross-worker graphs emit one plan-owned boundary per lane. */
TEST(gluon_boundary_topology, multi_lane_graph_emits_one_boundary_per_lane_without_clones)
{
	auto plan = make_two_stage_plan(0, 1, 2);

	const auto status = lower_boundary_topology(plan);

	ASSERT_TRUE(status.is_ok()) << status.message();
	ASSERT_EQ(plan.boundaries_size(), 2);
	EXPECT_EQ(plan.boundaries(0).boundary_id(), "boundary.source@lane_0.destination@lane_0");
	EXPECT_EQ(plan.boundaries(1).boundary_id(), "boundary.source@lane_1.destination@lane_1");
	EXPECT_EQ(plan.boundaries(0).boundary_id().find(".si"), std::string::npos);
	EXPECT_EQ(plan.boundaries(1).boundary_id().find(".si"), std::string::npos);
}

/** @brief Incidental authored edge order cannot change emitted boundary order or identity. */
TEST(gluon_boundary_topology, reordered_authored_edges_emit_identical_boundary_records)
{
	auto first = make_two_stage_plan(0, 1, 1);
	add_stage(first, "sink");
	add_stage_instance(first, "sink", "lane_0", 1);
	add_edge(first, "destination", "sink");
	// A repeated authored edge does not mint a second executable channel.
	add_edge(first, "source", "destination");

	auto second = first;
	second.mutable_pipeline()->mutable_edges()->SwapElements(0, 1);

	const auto first_status = lower_boundary_topology(first);
	const auto second_status = lower_boundary_topology(second);

	ASSERT_TRUE(first_status.is_ok()) << first_status.message();
	ASSERT_TRUE(second_status.is_ok()) << second_status.message();
	ASSERT_EQ(first.boundaries_size(), 1);
	ASSERT_EQ(first.boundaries_size(), second.boundaries_size());
	for (int i = 0; i < first.boundaries_size(); ++i) {
		EXPECT_EQ(first.boundaries(i).SerializeAsString(), second.boundaries(i).SerializeAsString());
	}
}

/** @brief Missing destination coverage on one lane fails before boundary publication. */
TEST(gluon_boundary_topology, missing_lane_destination_fails_without_output)
{
	auto plan = make_two_stage_plan(0, 1, 2);
	plan.mutable_stage_instances()->RemoveLast();

	const auto status = lower_boundary_topology(plan);

	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("incomplete lane-local stage-instance coverage"), std::string::npos);
	EXPECT_EQ(plan.boundaries_size(), 0);
}

/** @brief Duplicate canonical stage-instance identity fails closed. */
TEST(gluon_boundary_topology, duplicate_stage_instance_identity_fails)
{
	auto plan = make_two_stage_plan(0, 1, 1);
	*plan.add_stage_instances() = plan.stage_instances(0);

	const auto status = lower_boundary_topology(plan);

	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("duplicate stage-instance ID"), std::string::npos);
	EXPECT_EQ(plan.boundaries_size(), 0);
}

/** @brief Duplicate canonical worker identity fails before endpoint ownership is used. */
TEST(gluon_boundary_topology, duplicate_worker_identity_fails)
{
	auto plan = make_two_stage_plan(0, 1, 1);
	*plan.add_worker_placements() = plan.worker_placements(0);

	const auto status = lower_boundary_topology(plan);

	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("duplicate worker ID"), std::string::npos);
	EXPECT_EQ(plan.boundaries_size(), 0);
}

/** @brief Generated identity components and worker identities are validated exactly. */
TEST(gluon_boundary_topology, noncanonical_generated_identity_fails)
{
	{
		auto plan = make_two_stage_plan(0, 1, 1);
		plan.mutable_worker_placements(0)->set_worker_id("worker_wrong");

		const auto status = lower_boundary_topology(plan);

		EXPECT_FALSE(status.is_ok());
		EXPECT_NE(status.message().find("does not match deterministic owner ID"), std::string::npos);
		EXPECT_EQ(plan.boundaries_size(), 0);
	}

	{
		auto plan = make_two_stage_plan(0, 1, 1);
		plan.mutable_pipeline()->mutable_stages(0)->set_stage_id("source.with_dot");

		const auto status = lower_boundary_topology(plan);

		EXPECT_FALSE(status.is_ok());
		EXPECT_NE(status.message().find("must match [A-Za-z_][A-Za-z0-9_]*"), std::string::npos);
		EXPECT_EQ(plan.boundaries_size(), 0);
	}
}

/** @brief Prepopulated boundary output is rejected and never overwritten. */
TEST(gluon_boundary_topology, prepopulated_boundary_surface_fails_without_overwrite)
{
	auto plan = make_two_stage_plan(0, 1, 1);
	plan.add_boundaries()->set_boundary_id("foreign_boundary");

	const auto status = lower_boundary_topology(plan);

	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("requires empty boundaries[]"), std::string::npos);
	ASSERT_EQ(plan.boundaries_size(), 1);
	EXPECT_EQ(plan.boundaries(0).boundary_id(), "foreign_boundary");
}

}  // namespace
}  // namespace kinetum::gluon
