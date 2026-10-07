// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_gluon_runtime_core_placement.cpp
 * @brief Tests deterministic worker and runtime-service CPU placement.
 * @author Fleming Patel
 *
 * The suite exercises the cold-path lowering component directly so core
 * ownership, NUMA locality, service identity, and transactional publication
 * remain pinned independently of the broader Gluon planner.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/runtime_service_ids.hpp"
#include "src/gluon/runtime_core_placement.hpp"

namespace kinetum::gluon
{
namespace
{

/**
 * @brief Build a compact worker plan with one logical stage per region.
 *
 * @param workers_per_region Number of executable workers in each region.
 * @param module_region Whether each region contains a module lifecycle owner.
 * @return Deployment plan ready for runtime core placement lowering.
 */
kinetum::gluon::v1::DeploymentPlan make_placement_plan(const std::vector<int> &workers_per_region,
						       const std::vector<bool> &module_region)
{
	kinetum::gluon::v1::DeploymentPlan plan;
	if (workers_per_region.size() != module_region.size()) {
		ADD_FAILURE() << "workers_per_region and module_region must have equal lengths";
		return plan;
	}
	plan.set_plan_id("runtime_core_placement_test");
	plan.mutable_pipeline()->set_pipeline_id("runtime_core_placement_pipeline");

	uint32_t worker_index = 0;
	for (std::size_t region_index = 0; region_index < workers_per_region.size(); ++region_index) {
		const auto region_id = static_cast<int32_t>(region_index);
		const std::string stage_id = "stage_" + std::to_string(region_index);
		auto *stage = plan.mutable_pipeline()->add_stages();
		stage->set_stage_id(stage_id);
		stage->set_kind(module_region[region_index] ? kinetum::axiom::v1::STAGE_KIND_MODULE :
							      kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
		stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		if (module_region[region_index]) {
			stage->mutable_module()->set_module_id("kinetum.test." + stage_id);
			stage->mutable_module()->set_context_selection(
				kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
		}

		auto *region = plan.add_regions();
		region->set_region_id(region_id);
		region->add_logical_stage_ids(stage_id);

		for (int lane_index = 0; lane_index < workers_per_region[region_index]; ++lane_index) {
			const std::string lane_id = "lane_" + std::to_string(lane_index);
			auto *worker = plan.add_worker_placements();
			worker->set_worker_id(kinetum::common::execution_topology::make_worker_id(region_id, lane_id));
			worker->set_region_id(region_id);
			worker->set_lane_id(lane_id);
			worker->set_worker_index(worker_index++);
		}
	}
	return plan;
}

/**
 * @brief Build an exact contiguous single-host CPU inventory.
 *
 * @param core_count Number of logical CPUs.
 * @return Hardware inventory containing explicit NUMA-zero core rows.
 */
kinetum::hw::v1::HardwareInventory make_contiguous_hardware(int32_t core_count)
{
	kinetum::hw::v1::HardwareInventory hardware;
	auto *cpu = hardware.mutable_node()->mutable_cpu();
	for (int32_t core_id = 0; core_id < core_count; ++core_id) {
		auto *core = cpu->add_core_topology();
		core->set_core_id(core_id);
		core->set_numa_node(0);
		core->set_is_hyperthread(false);
	}
	return hardware;
}

/**
 * @brief Build detailed CPU topology with explicit NUMA and sibling facts.
 *
 * @param cores Ordered tuples of logical core, NUMA node, and hyperthread flag.
 * @return Hardware inventory containing authoritative per-core topology.
 */
kinetum::hw::v1::HardwareInventory make_detailed_hardware(const std::vector<std::tuple<int32_t, int32_t, bool>> &cores)
{
	kinetum::hw::v1::HardwareInventory hardware;
	auto *cpu = hardware.mutable_node()->mutable_cpu();
	for (const auto &[core_id, numa_node, is_hyperthread] : cores) {
		auto *core = cpu->add_core_topology();
		core->set_core_id(core_id);
		core->set_numa_node(numa_node);
		core->set_is_hyperthread(is_hyperthread);
	}
	return hardware;
}

/** @brief Verify one worker and two services receive distinct deterministic cores. */
TEST(gluon_runtime_core_placement, single_numa_places_worker_and_services_on_distinct_cores)
{
	auto plan = make_placement_plan({1}, {false});
	const auto hardware = make_contiguous_hardware(3);

	const auto status = lower_runtime_core_placement(plan, hardware, {});

	ASSERT_TRUE(status.is_ok()) << status.message();
	ASSERT_EQ(plan.worker_placements_size(), 1);
	ASSERT_EQ(plan.worker_placements(0).cpu_core_ids_size(), 1);
	EXPECT_EQ(plan.worker_placements(0).cpu_core_ids(0), 1);
	ASSERT_EQ(plan.runtime_service_placements_size(), 2);
	EXPECT_EQ(plan.runtime_service_placements(0).service_id(),
		  kinetum::common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID);
	EXPECT_EQ(plan.runtime_service_placements(0).cpu_core_id(), 0);
	EXPECT_EQ(plan.runtime_service_placements(0).command_mailbox_capacity(), COORDINATOR_COMMAND_MAILBOX_CAPACITY);
	EXPECT_EQ(plan.runtime_service_placements(1).service_id(),
		  kinetum::common::runtime_services::make_lifecycle_executor_id(0));
	EXPECT_EQ(plan.runtime_service_placements(1).cpu_core_id(), 2);
	EXPECT_EQ(plan.runtime_service_placements(1).command_mailbox_capacity(), 0u);
}

/** @brief Verify unused reserved cores never become packet-worker ownership. */
TEST(gluon_runtime_core_placement, reserved_cores_are_service_first_and_never_packet_owned)
{
	auto plan = make_placement_plan({1}, {false});
	const auto hardware = make_contiguous_hardware(5);
	runtime_core_placement_options options;
	options.reserved_cores = 2;

	const auto status = lower_runtime_core_placement(plan, hardware, options);

	ASSERT_TRUE(status.is_ok()) << status.message();
	EXPECT_EQ(plan.runtime_service_placements(0).cpu_core_id(), 0);
	EXPECT_EQ(plan.runtime_service_placements(1).cpu_core_id(), 1);
	EXPECT_EQ(plan.worker_placements(0).cpu_core_ids(0), 2);
}

/** @brief Verify non-reserved service assignment preserves lower packet cores. */
TEST(gluon_runtime_core_placement, nonreserved_service_assignment_preserves_lower_packet_core)
{
	auto plan = make_placement_plan({1}, {false});
	const auto hardware = make_contiguous_hardware(3);
	runtime_core_placement_options options;
	options.reserved_cores = 0;

	const auto status = lower_runtime_core_placement(plan, hardware, options);

	ASSERT_TRUE(status.is_ok()) << status.message();
	EXPECT_EQ(plan.runtime_service_placements(0).cpu_core_id(), 2);
	EXPECT_EQ(plan.runtime_service_placements(1).cpu_core_id(), 1);
	EXPECT_EQ(plan.worker_placements(0).cpu_core_ids(0), 0);
}

/** @brief Verify all workers in one region remain on one eligible NUMA node. */
TEST(gluon_runtime_core_placement, region_worker_group_is_indivisible_across_numa_nodes)
{
	auto plan = make_placement_plan({2}, {false});
	const auto hardware = make_detailed_hardware(
		{{0, 0, false}, {1, 1, false}, {2, 0, false}, {3, 1, false}, {4, 0, false}, {5, 1, false}});

	const auto status = lower_runtime_core_placement(plan, hardware, {});

	ASSERT_TRUE(status.is_ok()) << status.message();
	EXPECT_EQ(plan.regions(0).numa_node(), 1);
	EXPECT_EQ(plan.worker_placements(0).cpu_core_ids(0), 1);
	EXPECT_EQ(plan.worker_placements(1).cpu_core_ids(0), 3);
	EXPECT_EQ(plan.runtime_service_placements(1).numa_node(), 1);
	EXPECT_EQ(plan.runtime_service_placements(1).cpu_core_id(), 5);
}

/** @brief Verify NUMA-aware placement balances distinct region worker groups. */
TEST(gluon_runtime_core_placement, numa_aware_mode_balances_region_worker_groups)
{
	auto plan = make_placement_plan({1, 1}, {false, false});
	// Reorder the protobuf records to prove that region_id, not incidental
	// repeated-field position, owns placement publication.
	plan.mutable_regions()->SwapElements(0, 1);
	const auto hardware = make_detailed_hardware(
		{{0, 0, false}, {1, 1, false}, {2, 0, false}, {3, 1, false}, {4, 0, false}, {5, 1, false}});

	const auto status = lower_runtime_core_placement(plan, hardware, {});

	ASSERT_TRUE(status.is_ok()) << status.message();
	ASSERT_EQ(plan.regions(0).region_id(), 1);
	ASSERT_EQ(plan.regions(1).region_id(), 0);
	EXPECT_EQ(plan.regions(0).numa_node(), 1);
	EXPECT_EQ(plan.regions(1).numa_node(), 0);
	EXPECT_NE(plan.worker_placements(0).cpu_core_ids(0), plan.worker_placements(1).cpu_core_ids(0));
}

/** @brief Verify each module-bearing NUMA node receives one lifecycle executor. */
TEST(gluon_runtime_core_placement, module_bearing_numa_nodes_receive_lifecycle_executors)
{
	auto plan = make_placement_plan({1, 1}, {true, true});
	const auto hardware = make_detailed_hardware({{0, 0, false},
						      {1, 1, false},
						      {2, 0, false},
						      {3, 1, false},
						      {4, 0, false},
						      {5, 1, false},
						      {6, 0, false},
						      {7, 1, false}});

	const auto status = lower_runtime_core_placement(plan, hardware, {});

	ASSERT_TRUE(status.is_ok()) << status.message();
	ASSERT_EQ(plan.runtime_service_placements_size(), 3);
	EXPECT_EQ(plan.runtime_service_placements(1).service_id(),
		  kinetum::common::runtime_services::make_lifecycle_executor_id(0));
	EXPECT_EQ(plan.runtime_service_placements(2).service_id(),
		  kinetum::common::runtime_services::make_lifecycle_executor_id(1));
}

/** @brief Verify an unsatisfied assignment leaves every plan placement unchanged. */
TEST(gluon_runtime_core_placement, insufficient_capacity_fails_without_partial_plan_mutation)
{
	auto plan = make_placement_plan({1}, {false});
	plan.mutable_worker_placements(0)->add_cpu_core_ids(99);
	plan.mutable_regions(0)->add_cpu_core_ids(99);
	plan.add_runtime_service_placements()->set_service_id("sentinel_service");
	const std::string original = plan.SerializeAsString();
	const auto hardware = make_contiguous_hardware(2);

	const auto status = lower_runtime_core_placement(plan, hardware, {});

	EXPECT_FALSE(status.is_ok());
	EXPECT_EQ(status.code(), kinetum::common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(plan.SerializeAsString(), original);
}

/** @brief Verify an inventory without exact core rows cannot invent CPU ownership. */
TEST(gluon_runtime_core_placement, missing_exact_core_rows_fail_closed)
{
	auto plan = make_placement_plan({1}, {false});
	kinetum::hw::v1::HardwareInventory hardware;
	const std::string original = plan.SerializeAsString();

	auto status = lower_runtime_core_placement(plan, hardware, {});
	EXPECT_FALSE(status.is_ok());
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(plan.SerializeAsString(), original);

	hardware.mutable_node()->mutable_cpu();
	status = lower_runtime_core_placement(plan, hardware, {});

	EXPECT_FALSE(status.is_ok());
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(status.message().find("core_topology"), std::string::npos);
	EXPECT_EQ(plan.SerializeAsString(), original);
}

/** @brief Malformed explicit core rows reject without partial placement. */
TEST(gluon_runtime_core_placement, malformed_exact_core_rows_fail_closed)
{
	auto plan = make_placement_plan({1}, {false});
	const std::string original = plan.SerializeAsString();
	auto hardware = make_contiguous_hardware(3);
	hardware.mutable_node()->mutable_cpu()->add_core_topology()->CopyFrom(hardware.node().cpu().core_topology(0));

	auto status = lower_runtime_core_placement(plan, hardware, {});
	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("duplicate core_id"), std::string::npos);
	EXPECT_EQ(plan.SerializeAsString(), original);

	hardware = make_contiguous_hardware(3);
	hardware.mutable_node()->mutable_cpu()->mutable_core_topology(0)->set_numa_node(-1);
	status = lower_runtime_core_placement(plan, hardware, {});
	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("negative numa_node"), std::string::npos);
	EXPECT_EQ(plan.SerializeAsString(), original);
}

/** @brief Verify malformed protobuf inventory bytes reject before plan mutation. */
TEST(gluon_runtime_core_placement, hardware_wire_shape_rejects_before_placement_mutation)
{
	auto plan = make_placement_plan({1}, {false});
	const std::string original = plan.SerializeAsString();
	auto hardware = make_contiguous_hardware(3);
	hardware.GetReflection()->MutableUnknownFields(&hardware)->AddVarint(99, 1u);

	auto status = lower_runtime_core_placement(plan, hardware, {});
	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("unknown protobuf field"), std::string::npos);
	EXPECT_EQ(plan.SerializeAsString(), original);

	hardware = make_contiguous_hardware(3);
	hardware.mutable_node()->add_nics()->set_driver(static_cast<kinetum::hw::v1::NicDriver>(99));
	status = lower_runtime_core_placement(plan, hardware, {});
	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("unknown enum number"), std::string::npos);
	EXPECT_EQ(plan.SerializeAsString(), original);
}

/** @brief Verify disabling physical preference restores logical-core ordering. */
TEST(gluon_runtime_core_placement, physical_core_preference_is_not_inverted_when_disabled)
{
	// Low-ID hyperthreads make the service fallback policy observable: physical
	// preference must dominate core-ID order for both service roles.
	const auto hardware = make_detailed_hardware({{0, 0, true}, {1, 0, true}, {2, 0, false}, {3, 0, false}});
	runtime_core_placement_options preferred_options;
	preferred_options.reserved_cores = 0;
	auto preferred_plan = make_placement_plan({1}, {false});
	ASSERT_TRUE(lower_runtime_core_placement(preferred_plan, hardware, preferred_options).is_ok());
	ASSERT_EQ(preferred_plan.runtime_service_placements_size(), 2);
	EXPECT_EQ(preferred_plan.runtime_service_placements(0).cpu_core_id(), 1);
	EXPECT_EQ(preferred_plan.runtime_service_placements(1).cpu_core_id(), 0);
	EXPECT_EQ(preferred_plan.worker_placements(0).cpu_core_ids(0), 2);

	runtime_core_placement_options logical_options = preferred_options;
	logical_options.prefer_physical_cores = false;
	auto logical_plan = make_placement_plan({1}, {false});
	ASSERT_TRUE(lower_runtime_core_placement(logical_plan, hardware, logical_options).is_ok());
	ASSERT_EQ(logical_plan.runtime_service_placements_size(), 2);
	EXPECT_EQ(logical_plan.runtime_service_placements(0).cpu_core_id(), 3);
	EXPECT_EQ(logical_plan.runtime_service_placements(1).cpu_core_id(), 2);
	EXPECT_EQ(logical_plan.worker_placements(0).cpu_core_ids(0), 0);
}

}  // namespace
}  // namespace kinetum::gluon
