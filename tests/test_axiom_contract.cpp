// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_axiom_contract.cpp
 * @brief Axiom pipeline contract-verification tests.
 * @author Fleming Patel
 *
 * Axiom is the pipeline compiler that validates and transforms pipeline
 * definitions before deployment. The "contract" is the set of semantic
 * rules that every valid pipeline must satisfy.
 *
 * Contract Rules:
 * ---------------
 * 1. At least one RX stage (packet ingress point), or exactly one when
 *    require_single_ingress_egress is enabled.
 * 2. At least one TX stage (packet egress point), or exactly one when
 *    require_single_ingress_egress is enabled.
 * 3. All stages reachable from RX (no orphaned stages)
 * 4. TX reachable from RX (valid data path)
 * 5. No cycles (DAG structure)
 * 6. Stage-kind constraints for the exact current stage vocabulary.
 *
 * Why Early Validation:
 * ---------------------
 * Catching invalid pipelines at compile time (kinetum_axiom) prevents:
 * - Runtime crashes from missing stages
 * - Silent packet drops from disconnected graphs
 * - Undefined behavior from invalid stage types
 *
 * @see src/axiom/axiom_contract.cpp
 * @see src/axiom/axiom_main.cpp (pipeline compiler CLI)
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/descriptor.pb.h>
#include <kinetum/kinetum_sdk.h>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "src/axiom/axiom_contract.hpp"
#include "src/common/protobuf_contract.hpp"

//==============================================================================
// Test Helpers
//==============================================================================

namespace
{

static_assert(!noexcept(kinetum::axiom::verify_contract(std::declval<const kinetum::axiom::v1::Pipeline &>(),
							std::declval<const kinetum::axiom::contract_options &>())),
	      "allocation-backed semantic validation must not promise noexcept");
static_assert(
	!noexcept(kinetum::axiom::canonical_topological_order(std::declval<const kinetum::axiom::v1::Pipeline &>())),
	"allocation-backed topological ordering must not promise noexcept");

/**
 * @brief Creates a minimal valid pipeline with RX and TX stages connected.
 *
 * This is the simplest pipeline that satisfies all contract requirements:
 * - One RX stage
 * - One TX stage
 * - RX -> TX edge (connectivity)
 *
 * Used as a baseline for tests that modify a valid pipeline to test
 * specific validation failures.
 *
 * @return Minimal valid pipeline: RX -> TX
 */
kinetum::axiom::v1::Pipeline make_minimal_valid_pipeline()
{
	kinetum::axiom::v1::Pipeline p;
	p.set_pipeline_id("test_pipeline");

	// Add RX stage (packet ingress)
	auto *rx = p.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->mutable_io()->set_interface("ingress");

	// Add TX stage (packet egress)
	auto *tx = p.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface("egress");

	// Connect RX -> TX
	auto *edge = p.add_edges();
	edge->set_from_stage_id("rx");
	edge->set_to_stage_id("tx");
	edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

	return p;
}

}  // namespace

//==============================================================================
// RX/TX Requirement Tests
//==============================================================================

/**
 * @brief Verify empty pipeline (no stages) fails contract validation.
 *
 * An empty pipeline violates multiple contract rules:
 * - No RX stage (required: exactly 1)
 * - No TX stage (required: exactly 1)
 * - No data path (required: RX reachable to TX)
 *
 * Expected: verify_contract() returns error status
 */
TEST(axiom_contract, empty_pipeline_fails)
{
	kinetum::axiom::v1::Pipeline p;
	p.set_pipeline_id("t");
	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});

	EXPECT_FALSE(st.is_ok()) << "Empty pipeline must fail contract validation";
}

/** @brief Packet and control edges share one pre-allocation authoring bound. */
TEST(axiom_contract, packet_and_control_edges_share_one_exact_size_limit)
{
	auto pipeline = make_minimal_valid_pipeline();
	for (int32_t index = pipeline.edges_size(); index <= kinetum::axiom::MAX_PIPELINE_EDGES; ++index) {
		auto *edge = pipeline.add_control_edges();
		edge->set_from_stage_id("rx");
		edge->set_to_stage_id("tx");
		edge->set_subtype(kinetum::axiom::v1::CONTROL_EDGE_GENERIC);
	}

	const auto status = kinetum::axiom::verify_contract(pipeline, kinetum::axiom::contract_options{});

	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("shared bound"), std::string::npos);
}

/**
 * @brief Verify pipeline with RX but without TX fails validation.
 *
 * Contract Requirement: At least one TX (egress) stage is required.
 *
 * Scenario:
 * - Pipeline has only RX stage
 * - No TX stage present
 *
 * Expected:
 * - verify_contract() returns error
 * - Error message contains "0 TX" (indicating missing TX)
 */
TEST(axiom_contract, missing_tx_fails)
{
	kinetum::axiom::v1::Pipeline p;
	p.set_pipeline_id("test_missing_tx");

	// Add only RX stage (no TX)
	auto *rx = p.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->mutable_io()->set_interface("ingress");

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});

	EXPECT_FALSE(st.is_ok()) << "Pipeline without TX must fail validation";

	// Verify error message mentions the missing TX
	// Multi-core mode: error says "at least one TX" instead of "0 TX"
	EXPECT_NE(st.message().find("TX"), std::string::npos) << "Error should mention TX stage, got: " << st.message();
}

/**
 * @brief Verify pipeline with TX but without RX fails validation.
 *
 * Contract Requirement: At least one RX (ingress) stage is required.
 *
 * Scenario:
 * - Pipeline has only TX stage
 * - No RX stage present
 *
 * Expected:
 * - verify_contract() returns error
 * - Error message contains "0 RX" (indicating missing RX)
 */
TEST(axiom_contract, missing_rx_fails)
{
	kinetum::axiom::v1::Pipeline p;
	p.set_pipeline_id("test_missing_rx");

	// Add only TX stage (no RX)
	auto *tx = p.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface("egress");

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});

	EXPECT_FALSE(st.is_ok()) << "Pipeline without RX must fail validation";

	// Verify error message mentions the missing RX
	// Multi-core mode: error says "at least one RX" instead of "0 RX"
	EXPECT_NE(st.message().find("RX"), std::string::npos) << "Error should mention RX stage, got: " << st.message();
}

/**
 * @brief Verify valid pipeline with both RX and TX passes validation.
 *
 * Baseline Test:
 * The minimal valid pipeline (RX -> TX) must pass all contract checks.
 * This confirms the validation logic correctly accepts valid pipelines.
 * The same test pins Axiom's structural smallest-ready-stage tie-break without
 * importing RX/TX semantics into the ordering operation.
 *
 * Expected: verify_contract() succeeds and structural ordering is canonical.
 */
TEST(axiom_contract, valid_rx_tx_pipeline_passes)
{
	auto p = make_minimal_valid_pipeline();

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});

	EXPECT_TRUE(st.is_ok()) << "Valid RX->TX pipeline should pass: " << st.message();

	kinetum::axiom::v1::Pipeline structural;
	structural.set_pipeline_id("canonical_order_tie");
	for (const char *stage_id : {"z_branch", "a_branch", "sink"}) {
		structural.add_stages()->set_stage_id(stage_id);
	}
	auto *z_edge = structural.add_edges();
	z_edge->set_from_stage_id("z_branch");
	z_edge->set_to_stage_id("sink");
	auto *a_edge = structural.add_edges();
	a_edge->set_from_stage_id("a_branch");
	a_edge->set_to_stage_id("sink");

	auto order_or = kinetum::axiom::canonical_topological_order(structural);
	ASSERT_TRUE(order_or.is_ok()) << order_or.error().message();
	const std::vector<std::string> expected_order{"a_branch", "z_branch", "sink"};
	EXPECT_EQ(order_or.value(), expected_order);
}

/** @brief Require every RX path to a built-in IPv4 consumer to cross the parser. */
TEST(axiom_contract, builtin_ipv4_modules_reject_any_unparsed_ingress_path)
{
	const auto make_pipeline = [](const char *module_id, bool add_bypass) {
		auto pipeline = make_minimal_valid_pipeline();
		auto *parser = pipeline.add_stages();
		parser->set_stage_id("parse");
		parser->set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
		parser->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		auto *policy = pipeline.add_stages();
		policy->set_stage_id("policy");
		policy->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
		policy->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		policy->mutable_module()->set_module_id(module_id);
		policy->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

		pipeline.mutable_edges(0)->set_to_stage_id("parse");
		auto *parse_to_policy = pipeline.add_edges();
		parse_to_policy->set_from_stage_id("parse");
		parse_to_policy->set_to_stage_id("policy");
		parse_to_policy->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
		auto *policy_to_tx = pipeline.add_edges();
		policy_to_tx->set_from_stage_id("policy");
		policy_to_tx->set_to_stage_id("tx");
		policy_to_tx->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

		if (add_bypass) {
			pipeline.set_allow_dag(true);
			auto *bypass = pipeline.add_stages();
			bypass->set_stage_id("bypass");
			bypass->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
			bypass->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
			bypass->mutable_module()->set_module_id("kinetum.test_bypass");
			bypass->mutable_module()->set_context_selection(
				kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
			auto *rx_to_bypass = pipeline.add_edges();
			rx_to_bypass->set_from_stage_id("rx");
			rx_to_bypass->set_to_stage_id("bypass");
			rx_to_bypass->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
			auto *bypass_to_policy = pipeline.add_edges();
			bypass_to_policy->set_from_stage_id("bypass");
			bypass_to_policy->set_to_stage_id("policy");
			bypass_to_policy->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
		}
		return pipeline;
	};

	for (const char *module_id : {"kinetum.acl", "kinetum.nat44", "kinetum.qos"}) {
		SCOPED_TRACE(module_id);
		const auto parsed_pipeline = make_pipeline(module_id, false);
		const auto parsed_status =
			kinetum::axiom::verify_contract(parsed_pipeline, kinetum::axiom::contract_options{});
		EXPECT_TRUE(parsed_status.is_ok());
		const auto bypass_pipeline = make_pipeline(module_id, true);
		const auto bypass_status =
			kinetum::axiom::verify_contract(bypass_pipeline, kinetum::axiom::contract_options{});
		EXPECT_FALSE(bypass_status.is_ok());
		EXPECT_NE(bypass_status.message().find("reachable from RX without PARSE_IPV4"), std::string::npos);
	}
}

/** @brief Cycle diagnostics name the deterministic blocked remainder without overclaiming membership. */
TEST(axiom_contract, cycle_diagnostic_distinguishes_downstream_blocked_stages)
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("blocked_remainder");
	for (const char *stage_id : {"cycle_a", "cycle_b", "downstream"}) {
		pipeline.add_stages()->set_stage_id(stage_id);
	}
	auto add_edge = [&pipeline](const char *from, const char *to) {
		auto *edge = pipeline.add_edges();
		edge->set_from_stage_id(from);
		edge->set_to_stage_id(to);
	};
	add_edge("cycle_a", "cycle_b");
	add_edge("cycle_b", "cycle_a");
	add_edge("cycle_b", "downstream");

	const auto order_or = kinetum::axiom::canonical_topological_order(pipeline);
	ASSERT_FALSE(order_or.is_ok());
	EXPECT_EQ(order_or.error().message(),
		  "Pipeline validation failed: cycle detected; blocked stages [cycle_a, cycle_b, downstream]");
}

/** @brief Reject exact duplicate packet edges while admitting distinct match rules. */
TEST(axiom_contract, packet_edge_identity_is_exact)
{
	auto duplicate = make_minimal_valid_pipeline();
	duplicate.set_allow_dag(true);
	duplicate.add_edges()->CopyFrom(duplicate.edges(0));
	const auto duplicate_status = kinetum::axiom::verify_contract(duplicate, kinetum::axiom::contract_options{});
	EXPECT_FALSE(duplicate_status.is_ok());
	EXPECT_NE(duplicate_status.message().find("identical semantics"), std::string::npos);

	auto distinct = make_minimal_valid_pipeline();
	distinct.set_allow_dag(true);
	auto *conditional = distinct.add_edges();
	conditional->CopyFrom(distinct.edges(0));
	conditional->set_condition("proto == 6");
	conditional->set_priority(1);
	EXPECT_TRUE(kinetum::axiom::verify_contract(distinct, kinetum::axiom::contract_options{}).is_ok());
}

//==============================================================================
// Active-Stage Contract Tests
//==============================================================================

/** @brief Module routing requires one explicit known context-selection mode. */
TEST(axiom_contract, module_context_selection_is_required_and_closed)
{
	using namespace kinetum::axiom::v1;
	auto pipeline = make_minimal_valid_pipeline();
	auto *module = pipeline.add_stages();
	module->set_stage_id("module");
	module->set_kind(STAGE_KIND_MODULE);
	module->set_execution_mode(EXECUTION_MODE_PASSIVE);
	module->mutable_module()->set_module_id("kinetum.test");
	pipeline.mutable_edges(0)->set_to_stage_id("module");
	auto *edge = pipeline.add_edges();
	edge->set_from_stage_id("module");
	edge->set_to_stage_id("tx");
	edge->set_mode(EDGE_MODE_PUSH);
	for (const auto mode : {MODULE_CONTEXT_SELECTION_UNSPECIFIED, static_cast<ModuleContextSelection>(99),
				MODULE_CONTEXT_SELECTION_SAME_LANE, MODULE_CONTEXT_SELECTION_MODULE}) {
		SCOPED_TRACE(static_cast<int>(mode));
		module->mutable_module()->set_context_selection(mode);
		const auto result = kinetum::axiom::verify_contract(pipeline, kinetum::axiom::contract_options{});
		EXPECT_EQ(result.is_ok(),
			  mode == MODULE_CONTEXT_SELECTION_SAME_LANE || mode == MODULE_CONTEXT_SELECTION_MODULE)
			<< result.message();
	}
}

/**
 * @brief Verify active stage without trigger mask rejected.
 */
TEST(axiom_contract, active_stage_without_trigger_mask_rejected)
{
	auto p = make_minimal_valid_pipeline();

	// Insert active module between RX and TX
	auto *m = p.add_stages();
	m->set_stage_id("active_sched");
	m->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	m->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	m->set_trigger_mask(0);	 // No triggers - invalid
	m->mutable_module()->set_module_id("kinetum.test");
	m->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	// Re-wire: RX -> active_sched -> TX
	p.mutable_edges(0)->set_to_stage_id("active_sched");
	auto *e2 = p.add_edges();
	e2->set_from_stage_id("active_sched");
	e2->set_to_stage_id("tx");
	e2->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(st.is_ok());
	EXPECT_NE(st.message().find("trigger mode"), std::string::npos) << st.message();
}

/** @brief Pin the complete compact executable-only Axiom schema. */
TEST(axiom_contract, pipeline_schema_is_compact_typed_and_executable_only)
{
	const auto *stage = kinetum::axiom::v1::Stage::descriptor();
	ASSERT_NE(stage, nullptr);
	const std::array<std::pair<const char *, int>, 12> stage_fields{{
		{"stage_id", 1},
		{"kind", 2},
		{"io", 3},
		{"module", 4},
		{"preferred_region", 5},
		{"cost_weight", 6},
		{"constraints", 7},
		{"description", 8},
		{"execution_mode", 9},
		{"trigger_mask", 10},
		{"schedule_order", 11},
		{"active_stage_limits", 12},
	}};
	ASSERT_EQ(stage->field_count(), static_cast<int>(stage_fields.size()));
	ASSERT_EQ(stage->oneof_decl_count(), 2);
	ASSERT_EQ(stage->real_oneof_decl_count(), 1);
	const auto *configuration = stage->FindOneofByName("configuration");
	ASSERT_NE(configuration, nullptr);
	ASSERT_EQ(configuration->field_count(), 2);
	EXPECT_EQ(configuration->field(0)->real_containing_oneof(), configuration);
	for (const auto &[name, number] : stage_fields) {
		ASSERT_NE(stage->FindFieldByName(name), nullptr) << name;
		EXPECT_EQ(stage->FindFieldByName(name)->number(), number) << name;
	}
	const auto *preferred_region = stage->FindFieldByName("preferred_region");
	ASSERT_NE(preferred_region, nullptr);
	google::protobuf::FieldDescriptorProto preferred_region_schema;
	preferred_region->CopyTo(&preferred_region_schema);
	EXPECT_TRUE(preferred_region_schema.proto3_optional());
	ASSERT_NE(preferred_region->containing_oneof(), nullptr);
	EXPECT_EQ(preferred_region->real_containing_oneof(), nullptr);
	ASSERT_EQ(preferred_region->containing_oneof()->field_count(), 1);
	EXPECT_EQ(preferred_region->containing_oneof()->field(0), preferred_region);
	EXPECT_EQ(stage->FindFieldByName("params"), nullptr);
	EXPECT_EQ(stage->FindFieldByName("disabled"), nullptr);
	EXPECT_EQ(stage->FindFieldByName("retention_limits"), nullptr);

	const auto *io = kinetum::axiom::v1::IoStageConfig::descriptor();
	const auto *module = kinetum::axiom::v1::ModuleStageConfig::descriptor();
	const auto *constraints = kinetum::axiom::v1::StageConstraints::descriptor();
	ASSERT_EQ(io->field_count(), 1);
	EXPECT_EQ(io->field(0)->name(), "interface");
	EXPECT_EQ(io->field(0)->number(), 1);
	ASSERT_EQ(module->field_count(), 3);
	EXPECT_EQ(module->FindFieldByName("module_id")->number(), 1);
	const auto *module_path = module->FindFieldByName("module_path");
	ASSERT_NE(module_path, nullptr);
	EXPECT_EQ(module_path->number(), 2);
	google::protobuf::FieldDescriptorProto module_path_schema;
	module_path->CopyTo(&module_path_schema);
	EXPECT_TRUE(module_path_schema.proto3_optional());
	EXPECT_EQ(module->FindFieldByName("context_selection")->number(), 3);
	EXPECT_EQ(module->FindFieldByName("context_selection")->enum_type()->full_name(),
		  "kinetum.axiom.v1.ModuleContextSelection");
	ASSERT_EQ(constraints->field_count(), 2);
	EXPECT_EQ(constraints->FindFieldByName("affinity_stages")->number(), 1);
	EXPECT_EQ(constraints->FindFieldByName("anti_affinity_stages")->number(), 2);
	EXPECT_EQ(stage->FindFieldByName("io")->containing_oneof(), configuration);
	EXPECT_EQ(stage->FindFieldByName("io")->message_type(), io);
	EXPECT_EQ(stage->FindFieldByName("module")->containing_oneof(), configuration);
	EXPECT_EQ(stage->FindFieldByName("module")->message_type(), module);

	const auto *edge = kinetum::axiom::v1::Edge::descriptor();
	const std::array<std::pair<const char *, int>, 5> edge_fields{{
		{"from_stage_id", 1},
		{"to_stage_id", 2},
		{"condition", 3},
		{"priority", 4},
		{"mode", 5},
	}};
	ASSERT_EQ(edge->field_count(), static_cast<int>(edge_fields.size()));
	for (const auto &[name, number] : edge_fields) {
		ASSERT_NE(edge->FindFieldByName(name), nullptr) << name;
		EXPECT_EQ(edge->FindFieldByName(name)->number(), number) << name;
	}
	const auto *control_edge = kinetum::axiom::v1::ControlEdge::descriptor();
	ASSERT_EQ(control_edge->field_count(), 3);
	EXPECT_EQ(control_edge->FindFieldByName("from_stage_id")->number(), 1);
	EXPECT_EQ(control_edge->FindFieldByName("to_stage_id")->number(), 2);
	EXPECT_EQ(control_edge->FindFieldByName("subtype")->number(), 3);
	const auto *metadata = kinetum::axiom::v1::PipelineMetadata::descriptor();
	ASSERT_EQ(metadata->field_count(), 4);
	EXPECT_EQ(metadata->FindFieldByName("display_name")->number(), 1);
	EXPECT_EQ(metadata->FindFieldByName("description")->number(), 2);
	EXPECT_EQ(metadata->FindFieldByName("author")->number(), 3);
	EXPECT_EQ(metadata->FindFieldByName("version")->number(), 4);

	const auto *pipeline = kinetum::axiom::v1::Pipeline::descriptor();
	const std::array<std::pair<const char *, int>, 6> pipeline_fields{{
		{"pipeline_id", 1},
		{"stages", 2},
		{"edges", 3},
		{"allow_dag", 4},
		{"metadata", 5},
		{"control_edges", 6},
	}};
	ASSERT_EQ(pipeline->field_count(), static_cast<int>(pipeline_fields.size()));
	for (const auto &[name, number] : pipeline_fields) {
		ASSERT_NE(pipeline->FindFieldByName(name), nullptr) << name;
		EXPECT_EQ(pipeline->FindFieldByName(name)->number(), number) << name;
	}
	for (const char *removed : {"control_object_refs", "validation", "min_api_version"}) {
		EXPECT_EQ(pipeline->FindFieldByName(removed), nullptr) << removed;
	}

	const auto *limits = kinetum::axiom::v1::ActiveStageLimits::descriptor();
	ASSERT_NE(limits, nullptr);
	const std::array<std::pair<const char *, int>, 7> expected{{
		{"retained_packet_capacity", 1},
		{"retained_byte_capacity", 2},
		{"timer_capacity", 3},
		{"control_mailbox_capacity", 4},
		{"control_message_capacity_bytes", 5},
		{"async_work_capacity", 6},
		{"async_cancel_grace_ms", 7},
	}};
	EXPECT_EQ(limits->field_count(), static_cast<int>(expected.size()));
	for (const auto &[name, number] : expected) {
		ASSERT_NE(limits->FindFieldByName(name), nullptr);
		EXPECT_EQ(limits->FindFieldByName(name)->number(), number);
	}
	for (const char *removed :
	     {"kinetum.axiom.v1.KeyValue", "kinetum.axiom.v1.ValidationResult", "kinetum.axiom.v1.ValidationError",
	      "kinetum.axiom.v1.ValidationWarning", "kinetum.axiom.v1.RetentionLimits"}) {
		EXPECT_EQ(stage->file()->pool()->FindMessageTypeByName(removed), nullptr) << removed;
	}
	EXPECT_EQ(stage->file()->pool()->FindEnumTypeByName("kinetum.axiom.v1.StageCategory"), nullptr);

	const auto *kinds = kinetum::axiom::v1::StageKind_descriptor();
	const std::array<std::pair<const char *, int>, 5> kind_values{{
		{"STAGE_KIND_UNSPECIFIED", 0},
		{"STAGE_KIND_RX", 1},
		{"STAGE_KIND_TX", 2},
		{"STAGE_KIND_PARSE_IPV4", 3},
		{"STAGE_KIND_MODULE", 11},
	}};
	ASSERT_EQ(kinds->value_count(), static_cast<int>(kind_values.size()));
	for (const auto &[name, number] : kind_values) {
		ASSERT_NE(kinds->FindValueByName(name), nullptr) << name;
		EXPECT_EQ(kinds->FindValueByName(name)->number(), number) << name;
	}
	for (const char *removed : {"STAGE_KIND_PARSE_IPV6", "STAGE_KIND_EXPORT", "STAGE_KIND_MIRROR", "STAGE_KIND_LPM",
				    "STAGE_KIND_ECMP", "STAGE_KIND_VXLAN_ENCAP", "STAGE_KIND_VXLAN_DECAP"}) {
		EXPECT_EQ(kinds->FindValueByName(removed), nullptr) << removed;
	}

	const auto *execution_modes = kinetum::axiom::v1::ExecutionMode_descriptor();
	ASSERT_EQ(execution_modes->value_count(), 3);
	EXPECT_EQ(execution_modes->FindValueByName("EXECUTION_MODE_UNSPECIFIED")->number(), 0);
	EXPECT_EQ(execution_modes->FindValueByName("EXECUTION_MODE_ACTIVE")->number(), 1);
	EXPECT_EQ(execution_modes->FindValueByName("EXECUTION_MODE_PASSIVE")->number(), 2);
	const auto *edge_modes = kinetum::axiom::v1::EdgeMode_descriptor();
	ASSERT_EQ(edge_modes->value_count(), 3);
	EXPECT_EQ(edge_modes->FindValueByName("EDGE_MODE_UNSPECIFIED")->number(), 0);
	EXPECT_EQ(edge_modes->FindValueByName("EDGE_MODE_PULL")->number(), 1);
	EXPECT_EQ(edge_modes->FindValueByName("EDGE_MODE_PUSH")->number(), 2);
	const auto *control_subtypes = kinetum::axiom::v1::ControlEdgeSubtype_descriptor();
	ASSERT_EQ(control_subtypes->value_count(), 3);
	EXPECT_EQ(control_subtypes->FindValueByName("CONTROL_EDGE_SUBTYPE_UNSPECIFIED")->number(), 0);
	EXPECT_EQ(control_subtypes->FindValueByName("CONTROL_EDGE_FEEDBACK")->number(), 1);
	EXPECT_EQ(control_subtypes->FindValueByName("CONTROL_EDGE_GENERIC")->number(), 2);

	const auto *triggers = kinetum::axiom::v1::TriggerMode_descriptor();
	ASSERT_NE(triggers, nullptr);
	ASSERT_EQ(triggers->value_count(), 5);
	ASSERT_NE(triggers->FindValueByName("TRIGGER_MODE_UNSPECIFIED"), nullptr);
	EXPECT_EQ(triggers->FindValueByName("TRIGGER_MODE_UNSPECIFIED")->number(), 0);
	const std::array<std::pair<const char *, int>, 4> trigger_values{{
		{"TRIGGER_MODE_LOOP", KINETUM_TRIGGER_LOOP},
		{"TRIGGER_MODE_TIMER", KINETUM_TRIGGER_TIMER},
		{"TRIGGER_MODE_PULL_READY", KINETUM_TRIGGER_PULL_READY},
		{"TRIGGER_MODE_CONTROL", KINETUM_TRIGGER_CONTROL},
	}};
	for (const auto &[name, value] : trigger_values) {
		const auto *trigger = triggers->FindValueByName(name);
		ASSERT_NE(trigger, nullptr);
		EXPECT_EQ(trigger->number(), value);
	}
	EXPECT_EQ(triggers->FindValueByName("TRIGGER_MODE_DRAIN"), nullptr);
}

/** @brief Prove accepted free-form parameter bytes cannot become typed configuration. */
TEST(axiom_contract, removed_parameter_wire_rejects_without_compatibility_interpretation)
{
	constexpr std::array<uint8_t, 27> OLD_RX_STAGE_WIRE{
		0x0a, 0x02, 0x72, 0x78, 0x10, 0x01, 0x1a, 0x11, 0x0a, 0x09, 0x69, 0x6e, 0x74, 0x65,
		0x72, 0x66, 0x61, 0x63, 0x65, 0x12, 0x04, 0x77, 0x61, 0x6e, 0x30, 0x48, 0x01,
	};
	kinetum::axiom::v1::Stage stage;
	ASSERT_TRUE(stage.ParseFromArray(OLD_RX_STAGE_WIRE.data(), static_cast<int>(OLD_RX_STAGE_WIRE.size())));
	EXPECT_FALSE(kinetum::common::reject_unknown_protobuf_fields_recursive(stage, "Axiom Stage").is_ok());
	auto pipeline = make_minimal_valid_pipeline();
	pipeline.mutable_stages(0)->MergeFrom(stage);
	const auto admitted = kinetum::axiom::verify_contract(pipeline, kinetum::axiom::contract_options{});
	EXPECT_FALSE(admitted.is_ok());
	EXPECT_NE(admitted.message().find("unknown protobuf field"), std::string::npos);
}

/** @brief Stage constraints form one exact normalized undirected relation set. */
TEST(axiom_contract, stage_constraint_relations_are_exact)
{
	auto valid = make_minimal_valid_pipeline();
	valid.mutable_stages(0)->mutable_constraints()->add_affinity_stages("tx");
	EXPECT_TRUE(kinetum::axiom::verify_contract(valid, kinetum::axiom::contract_options{}).is_ok());

	auto unknown = make_minimal_valid_pipeline();
	unknown.mutable_stages(0)->mutable_constraints()->add_affinity_stages("missing");
	EXPECT_FALSE(kinetum::axiom::verify_contract(unknown, kinetum::axiom::contract_options{}).is_ok());

	auto self = make_minimal_valid_pipeline();
	self.mutable_stages(0)->mutable_constraints()->add_affinity_stages("rx");
	EXPECT_FALSE(kinetum::axiom::verify_contract(self, kinetum::axiom::contract_options{}).is_ok());

	auto duplicate = valid;
	duplicate.mutable_stages(1)->mutable_constraints()->add_affinity_stages("rx");
	const auto duplicate_status = kinetum::axiom::verify_contract(duplicate, kinetum::axiom::contract_options{});
	EXPECT_FALSE(duplicate_status.is_ok());
	EXPECT_NE(duplicate_status.message().find("declared more than once"), std::string::npos);

	auto contradictory = valid;
	contradictory.mutable_stages(1)->mutable_constraints()->add_anti_affinity_stages("rx");
	const auto contradictory_status =
		kinetum::axiom::verify_contract(contradictory, kinetum::axiom::contract_options{});
	EXPECT_FALSE(contradictory_status.is_ok());
	EXPECT_NE(contradictory_status.message().find("both affinity and anti-affinity"), std::string::npos);
}

/** @brief Prove removed active wire bytes cannot be reinterpreted by the new schema. */
TEST(axiom_contract, removed_active_wire_rejects_through_recursive_unknown_field_gate)
{
	// Old field 11 carried a nested RetentionLimits message and old field 12
	// carried schedule_order. Both wire types disagree with the compact
	// replacement, so the generated parser retains them as unknown input.
	constexpr std::array<uint8_t, 6> OLD_ACTIVE_WIRE{0x5a, 0x02, 0x08, 0x01, 0x60, 0x01};
	kinetum::axiom::v1::Stage stage;
	ASSERT_TRUE(stage.ParseFromArray(OLD_ACTIVE_WIRE.data(), static_cast<int>(OLD_ACTIVE_WIRE.size())));
	const auto status = kinetum::common::reject_unknown_protobuf_fields_recursive(stage, "Axiom Stage");
	EXPECT_FALSE(status.is_ok());
	auto pipeline = make_minimal_valid_pipeline();
	pipeline.mutable_stages(0)->MergeFrom(stage);
	const auto admitted = kinetum::axiom::verify_contract(pipeline, kinetum::axiom::contract_options{});
	EXPECT_FALSE(admitted.is_ok());
	EXPECT_NE(admitted.message().find("unknown protobuf field"), std::string::npos);
}

/** @brief Every removed stage-kind number reaches exact invalid-enum admission. */
TEST(axiom_contract, removed_stage_kind_numbers_reject_at_exact_message_admission)
{
	constexpr std::array<int, 7> REMOVED_KIND_NUMBERS{4, 5, 6, 7, 8, 9, 10};
	for (const int number : REMOVED_KIND_NUMBERS) {
		SCOPED_TRACE(number);
		auto pipeline = make_minimal_valid_pipeline();
		pipeline.mutable_stages(0)->set_kind(static_cast<kinetum::axiom::v1::StageKind>(number));

		const auto status = kinetum::axiom::verify_contract(pipeline, kinetum::axiom::contract_options{});
		EXPECT_FALSE(status.is_ok());
		EXPECT_NE(status.message().find("unknown enum number"), std::string::npos);
	}
}

/** @brief Former implicit-zero mode bytes reject as explicit unspecified input. */
TEST(axiom_contract, former_implicit_zero_modes_reject_without_semantic_reinterpretation)
{
	auto execution = make_minimal_valid_pipeline();
	execution.mutable_stages(0)->clear_execution_mode();
	const auto execution_status = kinetum::axiom::verify_contract(execution, kinetum::axiom::contract_options{});
	EXPECT_FALSE(execution_status.is_ok());
	EXPECT_NE(execution_status.message().find("execution_mode"), std::string::npos);

	auto packet_edge = make_minimal_valid_pipeline();
	packet_edge.mutable_edges(0)->clear_mode();
	const auto packet_status = kinetum::axiom::verify_contract(packet_edge, kinetum::axiom::contract_options{});
	EXPECT_FALSE(packet_status.is_ok());
	EXPECT_NE(packet_status.message().find("PUSH or PULL"), std::string::npos);

	auto control_edge = make_minimal_valid_pipeline();
	auto *edge = control_edge.add_control_edges();
	edge->set_from_stage_id("rx");
	edge->set_to_stage_id("tx");
	const auto control_status = kinetum::axiom::verify_contract(control_edge, kinetum::axiom::contract_options{});
	EXPECT_FALSE(control_status.is_ok());
	EXPECT_NE(control_status.message().find("GENERIC or FEEDBACK"), std::string::npos);
}

/**
 * @brief Verify passive stage with trigger mask rejected.
 */
TEST(axiom_contract, passive_stage_with_trigger_mask_rejected)
{
	auto p = make_minimal_valid_pipeline();

	auto *m = p.add_stages();
	m->set_stage_id("bad_passive");
	m->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	m->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	m->mutable_module()->set_module_id("kinetum.test_passive");
	m->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	m->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));

	p.mutable_edges(0)->set_to_stage_id("bad_passive");
	auto *e2 = p.add_edges();
	e2->set_from_stage_id("bad_passive");
	e2->set_to_stage_id("tx");
	e2->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(st.is_ok());
	EXPECT_NE(st.message().find("must not declare active triggers, schedule, or limits"), std::string::npos)
		<< st.message();
}

/**
 * @brief Verify passive stage with active limits rejected.
 */
TEST(axiom_contract, passive_stage_with_active_limits_rejected)
{
	auto p = make_minimal_valid_pipeline();

	auto *m = p.add_stages();
	m->set_stage_id("bad_passive_ret");
	m->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	m->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	m->mutable_module()->set_module_id("kinetum.test_passive");
	m->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	m->mutable_active_stage_limits()->set_retained_packet_capacity(100);
	m->mutable_active_stage_limits()->set_retained_byte_capacity(6400);

	p.mutable_edges(0)->set_to_stage_id("bad_passive_ret");
	auto *e2 = p.add_edges();
	e2->set_from_stage_id("bad_passive_ret");
	e2->set_to_stage_id("tx");
	e2->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(st.is_ok());
	EXPECT_NE(st.message().find("active"), std::string::npos) << st.message();
}

/**
 * @brief Verify pull edge from passive stage rejected.
 */
TEST(axiom_contract, pull_edge_from_passive_stage_rejected)
{
	auto p = make_minimal_valid_pipeline();

	auto *m = p.add_stages();
	m->set_stage_id("passive_src");
	m->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	m->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	m->mutable_module()->set_module_id("kinetum.test_passive");
	m->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	// PULL edge from passive stage - invalid
	p.mutable_edges(0)->set_to_stage_id("passive_src");
	auto *e2 = p.add_edges();
	e2->set_from_stage_id("passive_src");
	e2->set_to_stage_id("tx");
	e2->set_mode(kinetum::axiom::v1::EDGE_MODE_PULL);

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(st.is_ok());
	EXPECT_NE(st.message().find("PULL"), std::string::npos) << st.message();
}

/** @brief Verify a PULL request has active owner-worker callbacks at both ends. */
TEST(axiom_contract, pull_edge_requires_active_source_and_destination)
{
	auto p = make_minimal_valid_pipeline();
	auto *source = p.add_stages();
	source->set_stage_id("active_source");
	source->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	source->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	source->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_PULL_READY));
	source->mutable_module()->set_module_id("kinetum.test_active_source");
	source->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	auto *destination = p.add_stages();
	destination->set_stage_id("active_destination");
	destination->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	destination->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	destination->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));
	destination->mutable_module()->set_module_id("kinetum.test_active_destination");
	destination->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	p.mutable_edges(0)->set_to_stage_id("active_source");
	auto *pull = p.add_edges();
	pull->set_from_stage_id("active_source");
	pull->set_to_stage_id("active_destination");
	pull->set_mode(kinetum::axiom::v1::EDGE_MODE_PULL);
	auto *egress = p.add_edges();
	egress->set_from_stage_id("active_destination");
	egress->set_to_stage_id("tx");
	egress->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	ASSERT_TRUE(kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{}).is_ok());
	auto duplicate_pull = p;
	duplicate_pull.set_allow_dag(true);
	duplicate_pull.add_edges()->CopyFrom(duplicate_pull.edges(1));
	const auto duplicate_rejected =
		kinetum::axiom::verify_contract(duplicate_pull, kinetum::axiom::contract_options{});
	EXPECT_FALSE(duplicate_rejected.is_ok());
	EXPECT_NE(duplicate_rejected.message().find("declared more than once"), std::string::npos)
		<< duplicate_rejected.message();

	destination->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	destination->set_trigger_mask(0u);
	const auto rejected = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(rejected.is_ok());
	EXPECT_NE(rejected.message().find("active source and destination"), std::string::npos) << rejected.message();
}

/** @brief Reject active resource residue and every unknown scheduling enum. */
TEST(axiom_contract, active_resource_absence_and_scheduling_enums_are_exact)
{
	const auto make_active_pipeline = [] {
		auto pipeline = make_minimal_valid_pipeline();
		auto *active = pipeline.add_stages();
		active->set_stage_id("active_exact");
		active->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
		active->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
		active->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));
		active->mutable_module()->set_module_id("kinetum.test_active");
		active->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
		pipeline.mutable_edges(0)->set_to_stage_id("active_exact");
		auto *egress = pipeline.add_edges();
		egress->set_from_stage_id("active_exact");
		egress->set_to_stage_id("tx");
		egress->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
		return pipeline;
	};

	auto valid = make_active_pipeline();
	ASSERT_TRUE(kinetum::axiom::verify_contract(valid, kinetum::axiom::contract_options{}).is_ok());

	auto residue = valid;
	residue.mutable_stages(2)->mutable_active_stage_limits()->set_control_mailbox_capacity(1u);
	EXPECT_FALSE(kinetum::axiom::verify_contract(residue, kinetum::axiom::contract_options{}).is_ok());

	auto unknown_execution = valid;
	const auto *execution_field = kinetum::axiom::v1::Stage::descriptor()->FindFieldByName("execution_mode");
	ASSERT_NE(execution_field, nullptr);
	unknown_execution.mutable_stages(2)->GetReflection()->SetEnumValue(unknown_execution.mutable_stages(2),
									   execution_field, 127);
	EXPECT_FALSE(kinetum::axiom::verify_contract(unknown_execution, kinetum::axiom::contract_options{}).is_ok());

	auto unknown_edge = valid;
	const auto *edge_mode_field = kinetum::axiom::v1::Edge::descriptor()->FindFieldByName("mode");
	ASSERT_NE(edge_mode_field, nullptr);
	unknown_edge.mutable_edges(0)->GetReflection()->SetEnumValue(unknown_edge.mutable_edges(0), edge_mode_field,
								     127);
	EXPECT_FALSE(kinetum::axiom::verify_contract(unknown_edge, kinetum::axiom::contract_options{}).is_ok());

	auto unknown_control = valid;
	auto *active = unknown_control.mutable_stages(2);
	active->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP) |
				 static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_CONTROL));
	active->mutable_active_stage_limits()->set_control_mailbox_capacity(2u);
	active->mutable_active_stage_limits()->set_control_message_capacity_bytes(8u);
	auto *control = unknown_control.add_control_edges();
	control->set_from_stage_id("active_exact");
	control->set_to_stage_id("active_exact");
	control->set_subtype(kinetum::axiom::v1::CONTROL_EDGE_GENERIC);
	ASSERT_TRUE(kinetum::axiom::verify_contract(unknown_control, kinetum::axiom::contract_options{}).is_ok());
	const auto *subtype_field = kinetum::axiom::v1::ControlEdge::descriptor()->FindFieldByName("subtype");
	ASSERT_NE(subtype_field, nullptr);
	control = unknown_control.mutable_control_edges(0);
	control->GetReflection()->SetEnumValue(control, subtype_field, 127);
	EXPECT_FALSE(kinetum::axiom::verify_contract(unknown_control, kinetum::axiom::contract_options{}).is_ok());
}

/**
 * @brief Verify control edge with invalid stage rejected.
 */
TEST(axiom_contract, control_edge_with_invalid_stage_rejected)
{
	auto p = make_minimal_valid_pipeline();

	auto *ce = p.add_control_edges();
	ce->set_from_stage_id("nonexistent");
	ce->set_to_stage_id("rx");
	ce->set_subtype(kinetum::axiom::v1::CONTROL_EDGE_GENERIC);

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(st.is_ok());
	EXPECT_NE(st.message().find("not found"), std::string::npos) << st.message();
}

/**
 * @brief Verify valid active stage with trigger mask passes.
 */
TEST(axiom_contract, valid_active_stage_with_trigger_mask_passes)
{
	auto p = make_minimal_valid_pipeline();

	auto *m = p.add_stages();
	m->set_stage_id("active_ok");
	m->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	m->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	m->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP) |
			    static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_TIMER));
	m->mutable_active_stage_limits()->set_retained_packet_capacity(256);
	m->mutable_active_stage_limits()->set_retained_byte_capacity(65536);
	m->mutable_active_stage_limits()->set_timer_capacity(32);
	m->mutable_module()->set_module_id("kinetum.test_active");
	m->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	p.mutable_edges(0)->set_to_stage_id("active_ok");
	auto *e2 = p.add_edges();
	e2->set_from_stage_id("active_ok");
	e2->set_to_stage_id("tx");
	e2->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_TRUE(st.is_ok()) << "Valid active stage should pass: " << st.message();

	auto order_or = kinetum::axiom::canonical_topological_order(p);
	ASSERT_TRUE(order_or.is_ok()) << order_or.error().message();
	const std::vector<std::string> expected_order{"rx", "active_ok", "tx"};
	EXPECT_EQ(order_or.value(), expected_order);
}

/** @brief Verify tracked-async capacity and cancellation grace are one exact pair. */
TEST(axiom_contract, tracked_async_limits_are_both_present_or_both_absent)
{
	const auto make_active = [] {
		auto pipeline = make_minimal_valid_pipeline();
		auto *stage = pipeline.add_stages();
		stage->set_stage_id("active_async");
		stage->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
		stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
		stage->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));
		stage->mutable_module()->set_module_id("kinetum.test_active_async");
		stage->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
		pipeline.mutable_edges(0)->set_to_stage_id("active_async");
		auto *edge = pipeline.add_edges();
		edge->set_from_stage_id("active_async");
		edge->set_to_stage_id("tx");
		edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
		return pipeline;
	};

	auto capacity_only = make_active();
	capacity_only.mutable_stages(2)->mutable_active_stage_limits()->set_async_work_capacity(4u);
	const auto capacity_status = kinetum::axiom::verify_contract(capacity_only, kinetum::axiom::contract_options{});
	EXPECT_FALSE(capacity_status.is_ok());
	EXPECT_NE(capacity_status.message().find("present together"), std::string::npos);

	auto grace_only = make_active();
	grace_only.mutable_stages(2)->mutable_active_stage_limits()->set_async_cancel_grace_ms(1000u);
	const auto grace_status = kinetum::axiom::verify_contract(grace_only, kinetum::axiom::contract_options{});
	EXPECT_FALSE(grace_status.is_ok());
	EXPECT_NE(grace_status.message().find("present together"), std::string::npos);

	auto complete = make_active();
	auto *limits = complete.mutable_stages(2)->mutable_active_stage_limits();
	limits->set_async_work_capacity(4u);
	limits->set_async_cancel_grace_ms(1000u);
	EXPECT_TRUE(kinetum::axiom::verify_contract(complete, kinetum::axiom::contract_options{}).is_ok());
}

/**
 * @brief Verify active stage without module kind rejected.
 */
TEST(axiom_contract, active_stage_without_module_kind_rejected)
{
	auto p = make_minimal_valid_pipeline();

	auto *m = p.add_stages();
	m->set_stage_id("bad_active_kind");
	m->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);	 // Not MODULE
	m->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	m->mutable_io()->set_interface("active_ingress");
	m->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));

	p.mutable_edges(0)->set_to_stage_id("bad_active_kind");
	auto *e2 = p.add_edges();
	e2->set_from_stage_id("bad_active_kind");
	e2->set_to_stage_id("tx");
	e2->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(st.is_ok());
	EXPECT_NE(st.message().find("STAGE_KIND_MODULE"), std::string::npos) << st.message();
}

/**
 * @brief Verify active stage without module ID rejected.
 */
TEST(axiom_contract, active_stage_without_module_id_rejected)
{
	auto p = make_minimal_valid_pipeline();

	auto *m = p.add_stages();
	m->set_stage_id("bad_no_mod_id");
	m->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	m->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	m->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));
	// No typed module configuration.

	p.mutable_edges(0)->set_to_stage_id("bad_no_mod_id");
	auto *e2 = p.add_edges();
	e2->set_from_stage_id("bad_no_mod_id");
	e2->set_to_stage_id("tx");
	e2->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

	auto st = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(st.is_ok());
	EXPECT_NE(st.message().find("module_id"), std::string::npos) << st.message();
}
