// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_edge_conditions.cpp
 * @brief Unit tests for edge condition compilation and evaluation.
 * @author Fleming Patel
 *
 * Tests the shared route-condition grammar and compact compiler, the
 * packet-path evaluator, and the Axiom admission boundary.
 *
 * @see src/common/packet_route_condition.hpp
 * @see src/dp/edge_condition.hpp (evaluate_condition)
 * @see docs/AXIOM.md (Edge Condition Syntax)
 */

#include <gtest/gtest.h>

#include <cstdint>

#include "src/axiom/axiom_contract.hpp"
#include "src/dp/edge_condition.hpp"
#include "src/dp/packet.hpp"

namespace kinetum::dp
{

//==============================================================================
// Route-condition compiler tests
//==============================================================================

/**
 * @brief Verify an empty condition compiles as unconditional.
 */
TEST(edge_condition_test, EmptyConditionIsUnconditional)
{
	auto cond_or = common::compile_packet_route_condition("");
	ASSERT_TRUE(cond_or.is_ok()) << cond_or.error().message();
	const auto &cond = cond_or.value();
	EXPECT_TRUE(cond.is_unconditional());
	EXPECT_EQ(cond.field, common::compiled_packet_route_condition::field_id::NONE);
}

/**
 * @brief Verify DSCP greater-than-or-equal conditions parse.
 */
TEST(edge_condition_test, ParseDscpGreaterEqual)
{
	auto cond_or = common::compile_packet_route_condition("dscp >= 46");
	ASSERT_TRUE(cond_or.is_ok()) << cond_or.error().message();
	const auto &cond = cond_or.value();
	EXPECT_EQ(cond.field, common::compiled_packet_route_condition::field_id::DSCP);
	EXPECT_EQ(cond.op, common::compiled_packet_route_condition::op_id::GE);
	EXPECT_EQ(cond.value, 46u);
}

/**
 * @brief Verify destination-port equality conditions parse.
 */
TEST(edge_condition_test, ParseDstPortEqual)
{
	auto cond_or = common::compile_packet_route_condition("dst_port == 443");
	ASSERT_TRUE(cond_or.is_ok()) << cond_or.error().message();
	const auto &cond = cond_or.value();
	EXPECT_EQ(cond.field, common::compiled_packet_route_condition::field_id::DST_PORT);
	EXPECT_EQ(cond.op, common::compiled_packet_route_condition::op_id::EQ);
	EXPECT_EQ(cond.value, 443u);
}

/**
 * @brief Verify protocol less-than conditions parse.
 */
TEST(edge_condition_test, ParseProtoLessThan)
{
	auto cond_or = common::compile_packet_route_condition("proto < 10");
	ASSERT_TRUE(cond_or.is_ok()) << cond_or.error().message();
	const auto &cond = cond_or.value();
	EXPECT_EQ(cond.field, common::compiled_packet_route_condition::field_id::PROTO);
	EXPECT_EQ(cond.op, common::compiled_packet_route_condition::op_id::LT);
	EXPECT_EQ(cond.value, 10u);
}

/**
 * @brief Verify condition parsing tolerates ASCII whitespace.
 */
TEST(edge_condition_test, ParseWithWhitespace)
{
	auto cond_or = common::compile_packet_route_condition("  src_port   <=   1024  ");
	ASSERT_TRUE(cond_or.is_ok()) << cond_or.error().message();
	const auto &cond = cond_or.value();
	EXPECT_EQ(cond.field, common::compiled_packet_route_condition::field_id::SRC_PORT);
	EXPECT_EQ(cond.op, common::compiled_packet_route_condition::op_id::LE);
	EXPECT_EQ(cond.value, 1024u);
}

/**
 * @brief Verify condition parsing accepts UINT32_MAX.
 */
TEST(edge_condition_test, ParseUint32Max)
{
	auto cond_or = common::compile_packet_route_condition("flow_hash == 4294967295");
	ASSERT_TRUE(cond_or.is_ok()) << cond_or.error().message();
	const auto &cond = cond_or.value();
	EXPECT_EQ(cond.field, common::compiled_packet_route_condition::field_id::FLOW_HASH);
	EXPECT_EQ(cond.value, 4294967295u);
}

/**
 * @brief Verify unknown condition fields are rejected.
 */
TEST(edge_condition_test, ParseInvalidField)
{
	EXPECT_FALSE(common::compile_packet_route_condition("invalid_field == 1").is_ok());
}

/**
 * @brief Verify unknown condition operators are rejected.
 */
TEST(edge_condition_test, ParseInvalidOperator)
{
	EXPECT_FALSE(common::compile_packet_route_condition("dscp ?? 46").is_ok());
}

/**
 * @brief Verify conditions with missing values are rejected.
 */
TEST(edge_condition_test, ParseMissingValue)
{
	EXPECT_FALSE(common::compile_packet_route_condition("dscp >= ").is_ok());
}

/**
 * @brief Verify numeric literals with trailing junk are rejected.
 */
TEST(edge_condition_test, ParseTrailingJunkRejected)
{
	EXPECT_FALSE(common::compile_packet_route_condition("dscp >= 46junk").is_ok());
}

/**
 * @brief Verify overflowing numeric literals are rejected.
 */
TEST(edge_condition_test, ParseOverflowRejected)
{
	EXPECT_FALSE(common::compile_packet_route_condition("flow_hash == 4294967296").is_ok());
}

/**
 * @brief Verify negative numeric literals are rejected.
 */
TEST(edge_condition_test, ParseNegativeValueRejected)
{
	EXPECT_FALSE(common::compile_packet_route_condition("dscp >= -1").is_ok());
}

/**
 * @brief Verify flow-hash conditions parse.
 */
TEST(edge_condition_test, ParseFlowHash)
{
	auto cond_or = common::compile_packet_route_condition("flow_hash != 0");
	ASSERT_TRUE(cond_or.is_ok()) << cond_or.error().message();
	const auto &cond = cond_or.value();
	EXPECT_EQ(cond.field, common::compiled_packet_route_condition::field_id::FLOW_HASH);
	EXPECT_EQ(cond.op, common::compiled_packet_route_condition::op_id::NE);
	EXPECT_EQ(cond.value, 0u);
}

/**
 * @brief Verify malformed compiled state cannot become a fail-open route.
 */
TEST(edge_condition_test, malformed_compiled_condition_fails_closed)
{
	packet_private metadata{};
	common::compiled_packet_route_condition condition;

	EXPECT_TRUE(evaluate_condition(condition, nullptr));
	condition.op = static_cast<common::compiled_packet_route_condition::op_id>(UINT8_MAX);
	EXPECT_FALSE(condition.is_unconditional());
	EXPECT_FALSE(evaluate_condition(condition, &metadata));
	condition = common::compiled_packet_route_condition{};
	condition.value = 1;
	EXPECT_FALSE(condition.is_unconditional());
	EXPECT_FALSE(evaluate_condition(condition, &metadata));
	condition = common::compiled_packet_route_condition{};
	condition.field = static_cast<common::compiled_packet_route_condition::field_id>(UINT8_MAX);
	EXPECT_FALSE(evaluate_condition(condition, &metadata));
	condition.field = common::compiled_packet_route_condition::field_id::DSCP;
	condition.op = static_cast<common::compiled_packet_route_condition::op_id>(UINT8_MAX);
	EXPECT_FALSE(evaluate_condition(condition, &metadata));
	condition.op = common::compiled_packet_route_condition::op_id::EQ;
	EXPECT_FALSE(evaluate_condition(condition, nullptr));
}

//==============================================================================
// Edge Condition Contract Validation Tests
//==============================================================================

/**
 * @brief Build one exact passive RX-to-TX contract fixture.
 * @return Complete pipeline with one unconditional edge.
 */
[[nodiscard]] kinetum::axiom::v1::Pipeline make_edge_contract_pipeline()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("edge_condition_test");
	auto *rx = pipeline.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->mutable_io()->set_interface("ingress");
	auto *tx = pipeline.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface("egress");
	auto *edge = pipeline.add_edges();
	edge->set_from_stage_id("rx");
	edge->set_to_stage_id("tx");
	edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	return pipeline;
}

/**
 * @brief Verify valid edge conditions pass Axiom validation.
 */
TEST(edge_condition_contract_test, ValidConditionAccepted)
{
	auto p = make_edge_contract_pipeline();
	auto *edge = p.mutable_edges(0);
	edge->set_condition("dscp >= 46");
	edge->set_priority(100);

	// Verify contract passes
	auto status = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_TRUE(status.is_ok()) << status.message();
}

/**
 * @brief Verify invalid edge conditions fail Axiom validation.
 */
TEST(edge_condition_contract_test, InvalidConditionRejected)
{
	auto p = make_edge_contract_pipeline();
	auto *edge = p.mutable_edges(0);
	edge->set_condition("invalid_field == 1");  // Invalid field
	edge->set_priority(100);

	// Verify contract fails
	auto status = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("Invalid edge condition"), std::string::npos);
}

/**
 * @brief Verify out-of-range conditional edge priorities are rejected.
 */
TEST(edge_condition_contract_test, PriorityOutOfRangeRejected)
{
	auto p = make_edge_contract_pipeline();
	auto *edge = p.mutable_edges(0);
	edge->set_condition("dscp >= 46");
	edge->set_priority(2000);  // Out of range [-1000, 1000]

	// Verify contract fails
	auto status = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("priority"), std::string::npos);
}

/**
 * @brief Verify out-of-range unconditional edge priorities are rejected.
 */
TEST(edge_condition_contract_test, PriorityOutOfRangeRejectedForUnconditionalEdge)
{
	auto p = make_edge_contract_pipeline();
	auto *edge = p.mutable_edges(0);
	edge->set_priority(2000);  // Out of range [-1000, 1000]

	auto status = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("priority"), std::string::npos);
}

/**
 * @brief Verify Axiom validation rejects trailing condition junk.
 */
TEST(edge_condition_contract_test, TrailingJunkRejected)
{
	auto p = make_edge_contract_pipeline();
	auto *edge = p.mutable_edges(0);
	edge->set_condition("dscp >= 46junk");
	edge->set_priority(100);

	auto status = kinetum::axiom::verify_contract(p, kinetum::axiom::contract_options{});
	EXPECT_FALSE(status.is_ok());
	EXPECT_NE(status.message().find("trailing"), std::string::npos);
}

}  // namespace kinetum::dp
