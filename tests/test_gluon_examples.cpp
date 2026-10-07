// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_gluon_examples.cpp
 * @brief Plan shipped deployment examples through the production Gluon entry.
 * @author Fleming Patel
 *
 * Read the actual pipeline, inventory, and binding files shipped in the SDK
 * and private validation kit. Verify original-domain worker handoffs and reject
 * removal of each required transition without manufacturing missing bindings.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include "gen/kinetum/control/v1/control.pb.h"
#include "src/axiom/axiom_pbtxt_io.hpp"
#include "src/common/file_io.hpp"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/pbtxt.hpp"
#include "src/gluon/gluon_planner.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_contract_catalog.hpp"

#ifndef KINETUM_TEST_SOURCE_ROOT
#error "KINETUM_TEST_SOURCE_ROOT must identify the repository source root"
#endif

namespace kinetum::gluon
{
namespace
{

/** @brief Source files and expected worker handoffs for one shipped deployment. */
struct example_spec {
	const char *directory;	///< Example directory and pipeline filename stem.
	const char *bindings;	///< Exact deployment-binding filename.
	const char *hardware;	///< Exact hardware-inventory filename.
	int32_t regions;	///< Region count used by the deployment.
	int expected_handoffs;	///< Exact number of cross-worker stage edges.
};

/** @brief Single-queue deployments selected by the validation profiles. */
constexpr std::array<example_spec, 3> SINGLE_QUEUE_EXAMPLES{{
	{"passthrough", "passthrough_tap_bindings.pbtxt", "hardware_inventory_tap.pbtxt", 1, 0},
	{"fan_in_edge_gateway", "fan_in_edge_gateway_tap_bindings.pbtxt", "hardware_inventory_tap.pbtxt", 3, 2},
	{"fan_in_edge_gateway", "fan_in_edge_gateway_cloudlab_d430_bindings.pbtxt",
	 "hardware_inventory_cloudlab_d430.pbtxt", 3, 2},
}};

/** @brief Parsed inputs retained while planning or removing an authored handoff. */
struct example_inputs {
	kinetum::axiom::v1::Pipeline pipeline;	      ///< Exact shipped logical graph.
	kinetum::hw::v1::HardwareInventory hardware;  ///< Explicit planning hardware facts.
	planner_options options;		      ///< Exact bindings and requested regions.
};

/**
 * @brief Load one deployment through the production protobuf-text readers.
 * @param spec Exact source filenames and deployment region count.
 * @return Parsed inputs, or the original loading error.
 */
kinetum::common::status_or<example_inputs> load_example(const example_spec &spec)
{
	const auto directory = std::filesystem::path(KINETUM_TEST_SOURCE_ROOT) / "examples" / spec.directory;
	auto pipeline_or = kinetum::axiom::load_pipeline_pbtxt(
		(directory / (std::string(spec.directory) + ".axiom.pbtxt")).string(), {});
	if (!pipeline_or.is_ok()) {
		return pipeline_or.error();
	}
	example_inputs inputs;
	inputs.pipeline = std::move(pipeline_or).value();
	const auto hardware_status = kinetum::common::read_pbtxt_file(
		(directory / spec.hardware).string(), kinetum::common::DEFAULT_MAX_FILE_SIZE, &inputs.hardware);
	if (!hardware_status.is_ok()) {
		return hardware_status;
	}
	inputs.options.regions = spec.regions;
	const auto bindings_status = kinetum::common::read_pbtxt_file((directory / spec.bindings).string(),
								      kinetum::common::DEFAULT_MAX_FILE_SIZE,
								      &inputs.options.deployment_bindings);
	if (!bindings_status.is_ok()) {
		return bindings_status;
	}
	return inputs;
}

/**
 * @brief Match each shared-pool transition to its exact cross-worker boundary.
 * @param planned Plan accepted by Gluon and the shared provider compiler.
 * @param expected_handoffs Independently expected number of worker handoffs.
 */
void expect_shared_pool_handoffs(const kinetum::gluon::v1::DeploymentPlan &planned, int expected_handoffs)
{
	ASSERT_EQ(planned.boundaries_size(), expected_handoffs);
	ASSERT_EQ(planned.storage_transitions_size(), expected_handoffs);
	ASSERT_EQ(planned.packet_storage_domains_size(), 1);
	std::set<std::pair<std::string, std::string>> endpoints;
	for (const auto &transition : planned.storage_transitions()) {
		EXPECT_EQ(transition.configuration().type_url(), kinetum::provider::ZERO_COPY_SHARE_TYPE_URL);
		EXPECT_EQ(transition.from_storage_domain_id(), "storage_dpdk_0");
		EXPECT_EQ(transition.to_storage_domain_id(), "storage_dpdk_0");
		EXPECT_EQ(transition.staging_capacity(), 0u);
		EXPECT_FALSE(transition.has_staging_numa_node());
		EXPECT_TRUE(transition.facility_instance_ids().empty());
		ASSERT_TRUE(transition.from_endpoint().has_stage_instance_id());
		ASSERT_TRUE(transition.to_endpoint().has_stage_instance_id());
		const auto &from = transition.from_endpoint().stage_instance_id();
		const auto &to = transition.to_endpoint().stage_instance_id();
		EXPECT_TRUE(endpoints.emplace(from, to).second);
	}
	for (const auto &boundary : planned.boundaries()) {
		EXPECT_EQ(endpoints.erase({boundary.from_stage_instance_id(), boundary.to_stage_instance_id()}), 1u);
	}
	EXPECT_TRUE(endpoints.empty());
}

/**
 * @brief Remove each required handoff independently and prove planning rejects it.
 * @param inputs Complete deployment inputs already proved valid by the caller.
 */
void expect_missing_handoffs_reject(const example_inputs &inputs)
{
	const auto &bindings = inputs.options.deployment_bindings;
	for (int index = 0; index < bindings.storage_transition_bindings_size(); ++index) {
		SCOPED_TRACE(bindings.storage_transition_bindings(index).transition_id());
		auto incomplete = inputs.options;
		incomplete.deployment_bindings.mutable_storage_transition_bindings()->DeleteSubrange(index, 1);
		const auto rejected = plan(inputs.pipeline, inputs.hardware, incomplete);
		ASSERT_FALSE(rejected.is_ok());
		EXPECT_EQ(rejected.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
		EXPECT_NE(rejected.error().message().find("missing same-domain execution-owner transition"),
			  std::string::npos);
	}
}

/**
 * @brief Validate every retained authored snapshot against the exact newly planned graph.
 * @param planned Complete generated plan, already admitted by the shared compiler.
 * @param spec Source example whose current snapshots must retain exact module membership.
 */
void expect_snapshots_match(const kinetum::gluon::v1::DeploymentPlan &planned, const example_spec &spec)
{
	constexpr std::array<const char *, 3> SNAPSHOTS{
		"config_snapshot.pbtxt",
		"config_snapshot_v2.pbtxt",
		"config_snapshot_guardrails_degradation.pbtxt",
	};
	const std::size_t count = std::string_view(spec.directory) == "passthrough" ? 1u : SNAPSHOTS.size();
	for (std::size_t index = 0u; index < count; ++index) {
		SCOPED_TRACE(SNAPSHOTS[index]);
		const auto path = std::filesystem::path(KINETUM_TEST_SOURCE_ROOT) / "examples" / spec.directory /
				  SNAPSHOTS[index];
		kinetum::control::v1::ConfigSnapshot snapshot;
		const auto read = kinetum::common::read_pbtxt_file(path.string(),
								   kinetum::common::DEFAULT_MAX_FILE_SIZE, &snapshot);
		ASSERT_TRUE(read.is_ok()) << read.message();
		const auto canonical = kinetum::common::canonicalize_config_snapshot(snapshot, planned);
		ASSERT_TRUE(canonical.is_ok()) << canonical.error().message();
	}
}

}  // namespace

/** @brief Shipped single-queue examples plan with complete explicit shared-pool handoffs. */
TEST(gluon_examples, single_queue_bindings_plan_exact_handoffs)
{
	for (const auto &spec : SINGLE_QUEUE_EXAMPLES) {
		SCOPED_TRACE(spec.bindings);
		auto inputs_or = load_example(spec);
		ASSERT_TRUE(inputs_or.is_ok()) << inputs_or.error().message();
		const auto &inputs = inputs_or.value();
		const auto planned = plan(inputs.pipeline, inputs.hardware, inputs.options);
		ASSERT_TRUE(planned.is_ok()) << planned.error().message();
		expect_shared_pool_handoffs(planned.value(), spec.expected_handoffs);
		expect_snapshots_match(planned.value(), spec);
	}
}

/** @brief A missing handoff in an otherwise valid shipped deployment fails before publication. */
TEST(gluon_examples, missing_single_queue_handoff_rejects)
{
	for (const auto &spec : SINGLE_QUEUE_EXAMPLES) {
		SCOPED_TRACE(spec.bindings);
		auto inputs_or = load_example(spec);
		ASSERT_TRUE(inputs_or.is_ok()) << inputs_or.error().message();
		const auto &inputs = inputs_or.value();
		const auto baseline = plan(inputs.pipeline, inputs.hardware, inputs.options);
		ASSERT_TRUE(baseline.is_ok()) << baseline.error().message();
		expect_missing_handoffs_reject(inputs);
	}
}

/** @brief Every RSS ingress context can reach both NAT owners on the exact eight-core inventory. */
TEST(gluon_examples, rss_bindings_plan_complete_context_selection_handoffs)
{
	constexpr example_spec RSS_EXAMPLE{"fan_in_edge_gateway",
					   "fan_in_edge_gateway_cloudlab_d430_rx_rss_2_bindings.pbtxt",
					   "hardware_inventory_cloudlab_d430.pbtxt", 3, 8};
	auto inputs_or = load_example(RSS_EXAMPLE);
	ASSERT_TRUE(inputs_or.is_ok()) << inputs_or.error().message();
	const auto &inputs = inputs_or.value();
	const auto planned = plan(inputs.pipeline, inputs.hardware, inputs.options);
	ASSERT_TRUE(planned.is_ok()) << planned.error().message();
	EXPECT_EQ(planned.value().execution_lanes_size(), 2);
	EXPECT_EQ(planned.value().worker_placements_size(), 6);
	EXPECT_EQ(planned->pipeline().stages_size(), 9);
	EXPECT_EQ(planned->stage_instances_size(), 18);
	ASSERT_EQ(planned->module_context_domains_size(), 3);
	EXPECT_EQ(planned->module_context_domains(0).module_id(), "kinetum.acl");
	EXPECT_EQ(planned->module_context_domains(0).context_instance_ids_size(), 4);
	EXPECT_EQ(planned->module_context_domains(1).module_id(), "kinetum.nat44");
	EXPECT_EQ(planned->module_context_domains(1).context_instance_ids_size(), 2);
	const auto compiled = kinetum::provider::compile_provider_topology(planned.value());
	ASSERT_TRUE(compiled.is_ok()) << compiled.error().message();
	ASSERT_EQ(compiled->storage_domains.size(), 1u);
	EXPECT_EQ(compiled->storage_domains[0].budget.required_min_buffers, 34752u);
	expect_shared_pool_handoffs(planned.value(), RSS_EXAMPLE.expected_handoffs);
	expect_snapshots_match(planned.value(), RSS_EXAMPLE);
	expect_missing_handoffs_reject(inputs);
	auto incomplete = planned.value();
	incomplete.mutable_boundaries()->RemoveLast();
	const auto rejected = kinetum::provider::compile_provider_topology(incomplete);
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_NE(rejected.error().message().find("boundaries[] missing executable edge"), std::string::npos);
}

/** @brief Both shipped separate-storage fixtures compile through the strict readers and real planner. */
TEST(gluon_examples, per_queue_storage_bindings_plan_original_domains)
{
	/** @brief Independently expected pool and lane populations for one physical fixture. */
	struct storage_example {
		example_spec source;	    ///< Exact fixture paths and worker handoffs.
		int pool_count;		    ///< Independent number of RX allocation domains.
		int lane_count;		    ///< Independent execution-lane count.
		uint32_t pool_buffers;	    ///< Exact per-domain physical buffer population.
		uint64_t required_buffers;  ///< Independently derived complete per-domain ownership bound.
	};
	constexpr std::array<storage_example, 2> EXAMPLES{{
		{{"fan_in_edge_gateway", "fan_in_edge_gateway_cloudlab_d430_per_rx_queue_bindings.pbtxt",
		  "hardware_inventory_cloudlab_d430.pbtxt", 3, 2},
		 2,
		 1,
		 65535u,
		 7872u},
		{{"fan_in_edge_gateway", "fan_in_edge_gateway_cloudlab_d430_rx_rss_2_per_rx_queue_bindings.pbtxt",
		  "hardware_inventory_cloudlab_d430.pbtxt", 3, 8},
		 4,
		 2,
		 32767u,
		 12288u},
	}};
	for (const auto &spec : EXAMPLES) {
		SCOPED_TRACE(spec.source.bindings);
		auto inputs_or = load_example(spec.source);
		ASSERT_TRUE(inputs_or.is_ok()) << inputs_or.error().message();
		const auto &inputs = inputs_or.value();
		const auto planned = plan(inputs.pipeline, inputs.hardware, inputs.options);
		ASSERT_TRUE(planned.is_ok()) << planned.error().message();
		ASSERT_EQ(planned->packet_storage_domains_size(), spec.pool_count);
		EXPECT_EQ(planned->execution_lanes_size(), spec.lane_count);
		EXPECT_EQ(planned->worker_placements_size(), 3 * spec.lane_count);
		EXPECT_EQ(planned->boundaries_size(), spec.source.expected_handoffs);
		ASSERT_EQ(planned->storage_transitions_size(), spec.source.expected_handoffs);
		expect_snapshots_match(planned.value(), spec.source);
		const auto compiled = kinetum::provider::compile_provider_topology(planned.value());
		ASSERT_TRUE(compiled.is_ok()) << compiled.error().message();
		for (const auto &domain : compiled->storage_domains) {
			EXPECT_EQ(domain.budget.required_min_buffers, spec.required_buffers);
		}
		for (const auto &domain : planned->packet_storage_domains()) {
			EXPECT_EQ(domain.buffer_count(), spec.pool_buffers);
		}
		std::set<std::string> rx_domains;
		for (const auto &stream : planned->io_streams()) {
			if (stream.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				ASSERT_TRUE(stream.has_rx_storage_domain_id());
				EXPECT_TRUE(rx_domains.insert(stream.rx_storage_domain_id()).second);
			}
		}
		EXPECT_EQ(rx_domains.size(), static_cast<std::size_t>(spec.pool_count));
		for (const auto &stream : planned->io_streams()) {
			if (stream.direction() != kinetum::gluon::v1::IO_STREAM_DIRECTION_TX) {
				continue;
			}
			const std::set<std::string> admitted(stream.tx_storage().storage_domain_ids().begin(),
							     stream.tx_storage().storage_domain_ids().end());
			EXPECT_EQ(admitted, rx_domains);
			EXPECT_EQ(admitted.size(), static_cast<std::size_t>(spec.pool_count));
		}
		for (const auto &transition : planned->storage_transitions()) {
			EXPECT_EQ(transition.configuration().type_url(), kinetum::provider::ZERO_COPY_SHARE_TYPE_URL);
			EXPECT_EQ(transition.from_storage_domain_id(), transition.to_storage_domain_id());
			EXPECT_TRUE(rx_domains.contains(transition.from_storage_domain_id()));
			EXPECT_EQ(transition.staging_capacity(), 0u);
		}
		expect_missing_handoffs_reject(inputs);
	}
}

}  // namespace kinetum::gluon
