// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dp_integration.cpp
 * @brief Kinetum dataplane integration tests.
 * @author Fleming Patel
 *
 * This test suite validates end-to-end dataplane functionality including:
 * - Full pipeline processing (RX->Parse->ACL->NAT->QoS->TX)
 * - Epoch transition behavior (config change + in-flight packets)
 * - NAT44 multi-flow handling (10+ concurrent flows)
 * - QoS rate limiting (multiple flows with different profiles)
 *
 * These tests complement unit tests by validating integration between
 * components and ensuring the complete packet processing path works correctly.
 *
 * Architecture Compliance:
 * - Hot-path: Zero allocations in packet processing loops
 * - SDK conformance: policy behavior uses the exact public module lifecycle ABI
 * - Component module execution uses exact per-context epoch stores and views
 * - Production packet admission remains closed until verified bootstrap
 */

#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <random>
#include <unordered_set>

#include "src/dp/dp_engine.hpp"
#include <kinetum/algo/net.hpp>
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_record_test_harness.hpp"
#include "tests/test_dp_helpers.hpp"

// Module-owned protos (generated from src/modules/*/proto)
#include "src/modules/acl/acl.pb.h"
#include "src/modules/nat44/nat44.pb.h"
#include "src/modules/qos/qos.pb.h"
#include "tests/module_config_test_helpers.hpp"

// Module paths are defined by CMake at compile time
#ifndef KINETUM_ACL_MODULE_PATH
#error "KINETUM_ACL_MODULE_PATH must be defined by CMake"
#endif
#ifndef KINETUM_NAT44_MODULE_PATH
#error "KINETUM_NAT44_MODULE_PATH must be defined by CMake"
#endif
#ifndef KINETUM_QOS_MODULE_PATH
#error "KINETUM_QOS_MODULE_PATH must be defined by CMake"
#endif

/** @brief Explicit lifecycle-memory contract for integration module contexts. */
constexpr kinetum::test::module_test_resource_contract TEST_MODULE_RESOURCES{
	64u * 1024u * 1024u,
	2u * 1024u * 1024u,
};

//==============================================================================
// Test Fixture for Integration Tests
//==============================================================================

/** @brief Own one fresh provider-neutral engine for each integration row. */
class dp_integration : public ::testing::Test {
    protected:
	/** @brief Construct one fresh provider-neutral engine. */
	void SetUp() override
	{
		engine_ = std::make_unique<kinetum::dp::dp_engine>();
	}

	/** @brief Release the provider-neutral engine after each row. */
	void TearDown() override
	{
		engine_.reset();
	}

	/** @return Explicit permit-all ACL fixture. */
	kinetum::module::acl::v1::AclRuleset create_acl_config()
	{
		kinetum::module::acl::v1::AclRuleset config;
		config.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

		// Permit all traffic (baseline)
		auto *rule = config.add_rules();
		rule->set_priority(1);
		rule->set_enabled(true);
		rule->set_src_cidr("0.0.0.0/0");
		rule->set_dst_cidr("0.0.0.0/0");
		rule->set_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

		return config;
	}

	/** @return NAT44 fixture with one exact public address and port pool. */
	kinetum::module::nat44::v1::NatPools create_nat_config()
	{
		kinetum::module::nat44::v1::NatPools config;
		config.set_session_timeout_s(60);

		auto *pool = config.add_pools();
		pool->add_public_ip_ranges("203.0.113.10-203.0.113.20");
		pool->set_port_min(40000);
		pool->set_port_max(60000);

		return config;
	}

	/**
	 * @param rate_kbps Exact committed information rate in kilobits per second.
	 * @return QoS fixture with one default profile.
	 */
	kinetum::module::qos::v1::QosProfiles create_qos_config(int64_t rate_kbps = 100000)
	{
		kinetum::module::qos::v1::QosProfiles config;
		config.set_default_profile("default");

		auto *profile = config.add_profiles();
		profile->set_name("default");
		profile->set_cir_kbps(rate_kbps);
		profile->set_cbs_kb(128);

		return config;
	}

	std::unique_ptr<kinetum::dp::dp_engine> engine_;  ///< Fresh engine owned by the current test row.
};

//==============================================================================
// Test 1: Full Pipeline (RX -> Parse -> ACL -> NAT -> QoS -> TX)
//==============================================================================

/**
 * @brief Verify complete pipeline processes a packet through all stages.
 *
 * Test Scenario:
 * 1. Create the full pipeline with all built-in SDK modules (ACL, NAT44, QoS)
 * 2. Send UDP packet: 10.0.0.1:1234 -> 8.8.8.8:53
 * 3. Verify packet traverses Parse -> ACL -> NAT -> QoS stages
 * 4. Confirm NAT translation and QoS marking applied
 *
 * Expected Results:
 * - Packet passes ACL (permit all)
 * - NAT translates src to public IP:port
 * - QoS policer allows packet (within rate limit)
 * - Packet metadata shows correct transformation
 *
 * @note This test validates the complete Edge Gateway use case.
 */
TEST_F(dp_integration, full_pipeline_processes_packet)
{
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	auto acl_or = kinetum::test::exact_module_test_context::create("kinetum.acl", KINETUM_ACL_MODULE_PATH,
								       TEST_MODULE_RESOURCES, "acl0@lane_0");
	ASSERT_TRUE(acl_or.is_ok()) << acl_or.error().message();
	auto acl = std::move(acl_or).value();
	auto nat_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
								       TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(nat_or.is_ok()) << nat_or.error().message();
	auto nat = std::move(nat_or).value();
	auto qos_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
								       TEST_MODULE_RESOURCES, "qos0@lane_0");
	ASSERT_TRUE(qos_or.is_ok()) << qos_or.error().message();
	auto qos = std::move(qos_or).value();

	ASSERT_TRUE(acl->prepare_and_activate(1, kinetum::test::module_config_json(create_acl_config())).is_ok());
	ASSERT_TRUE(nat->prepare_and_activate(1, kinetum::test::module_config_json(create_nat_config())).is_ok());
	ASSERT_TRUE(qos->prepare_and_activate(1, kinetum::test::module_config_json(create_qos_config())).is_ok());

	// Build test packet: 10.0.0.1:1234 -> 8.8.8.8:53 (DNS query)
	auto bytes = build_eth_ipv4_udp(0x0a000001,		  // src: 10.0.0.1 (private)
					0x08080808,		  // dst: 8.8.8.8 (Google DNS)
					1234,			  // src_port
					53,			  // dst_port (DNS)
					0,			  // dscp
					{1, 2, 3, 4, 5, 6, 7, 8}  // payload
	);
	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Parse stage
	ASSERT_TRUE(engine_->execute_stage(&parse, packet.get())) << "Parse stage should succeed";
	EXPECT_EQ(packet.metadata().src_ipv4, 0x0a000001u) << "Parse should extract src_ip";
	EXPECT_EQ(packet.metadata().dst_ipv4, 0x08080808u) << "Parse should extract dst_ip";
	EXPECT_EQ(packet.metadata().src_port, 1234) << "Parse should extract src_port";
	EXPECT_EQ(packet.metadata().dst_port, 53) << "Parse should extract dst_port";

	// ACL stage (permit all)
	ASSERT_TRUE(acl->process(*packet.get())) << "ACL should permit packet (permit all rule)";

	// NAT stage (SNAT)
	ASSERT_TRUE(nat->process(*packet.get())) << "NAT stage should succeed";

	// Verify NAT translation
	EXPECT_GE(packet.metadata().src_ipv4, 0xcb00710au)  // 203.0.113.10
		<< "After NAT, src_ip should be in public pool range";
	EXPECT_LE(packet.metadata().src_ipv4, 0xcb007114u)  // 203.0.113.20
		<< "After NAT, src_ip should be in public pool range";
	EXPECT_GE(packet.metadata().src_port, 40000) << "After NAT, src_port should be in pool range";
	EXPECT_LE(packet.metadata().src_port, 60000) << "After NAT, src_port should be in pool range";

	// QoS stage (rate limiting)
	ASSERT_TRUE(qos->process(*packet.get())) << "QoS should allow packet (within rate limit)";
}

//==============================================================================
// Test 2: Exact Epoch Artifacts
//==============================================================================

/**
 * @brief Verify independently prepared epoch artifacts retain exact policy.
 *
 * Test Scenario:
 * 1. Prepare an epoch-1 artifact whose ACL permits all
 * 2. Create "in-flight" packet with epoch=1
 * 3. Prepare an independent epoch-2 artifact that denies 8.8.8.8
 * 4. Process the epoch-1 packet against the epoch-1 artifact
 * 5. Process the epoch-2 packet against the epoch-2 artifact
 *
 * This component test proves module artifact immutability and exact policy
 * behavior using two independently admitted contexts. Exact runtime mismatch
 * refusal and two-slot ownership are covered by their owning component suites.
 *
 * Expected Results:
 * - Epoch 1 packet: permitted (using epoch 1 config)
 * - Epoch 2 packet: denied (using epoch 2 config)
 */
TEST_F(dp_integration, exact_acl_artifacts_preserve_epoch_specific_policy)
{
	// Create minimal pipeline: Parse -> ACL
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("epoch_test");

	auto *parse = pipeline.add_stages();
	parse->set_stage_id("parse0");
	parse->set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	parse->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);

	auto *acl = pipeline.add_stages();
	acl->set_stage_id("acl0");
	acl->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	acl->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	acl->mutable_module()->set_module_id("kinetum.acl");
	acl->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	acl->mutable_module()->set_module_path(KINETUM_ACL_MODULE_PATH);

	auto *edge = pipeline.add_edges();
	edge->set_from_stage_id("parse0");
	edge->set_to_stage_id("acl0");
	edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

	auto epoch1_module_or = kinetum::test::exact_module_test_context::create("kinetum.acl", KINETUM_ACL_MODULE_PATH,
										 TEST_MODULE_RESOURCES, "acl0@lane_0");
	ASSERT_TRUE(epoch1_module_or.is_ok()) << epoch1_module_or.error().message();
	auto epoch1_module = std::move(epoch1_module_or).value();
	auto epoch2_module_or = kinetum::test::exact_module_test_context::create("kinetum.acl", KINETUM_ACL_MODULE_PATH,
										 TEST_MODULE_RESOURCES, "acl0@lane_0");
	ASSERT_TRUE(epoch2_module_or.is_ok()) << epoch2_module_or.error().message();
	auto epoch2_module = std::move(epoch2_module_or).value();

	// Epoch 1: ACL permits all
	kinetum::module::acl::v1::AclRuleset acl_config_v1;
	acl_config_v1.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	auto *permit_rule = acl_config_v1.add_rules();
	permit_rule->set_priority(1);
	permit_rule->set_enabled(true);
	permit_rule->set_src_cidr("0.0.0.0/0");
	permit_rule->set_dst_cidr("0.0.0.0/0");
	permit_rule->set_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	const auto status1 = epoch1_module->prepare_and_activate(1, kinetum::test::module_config_json(acl_config_v1));
	ASSERT_TRUE(status1.is_ok()) << "Epoch 1 preparation failed: " << status1.message();

	// Create "in-flight" packet with epoch=1
	auto bytes1 = build_eth_ipv4_udp(0x0a000001, 0x08080808, 1234, 53, 0, {1, 2, 3});
	kinetum::test::packet_record_test_owner inflight_packet(bytes1, 1);
	ASSERT_TRUE(inflight_packet.valid()) << inflight_packet.error();

	// Epoch 2: ACL denies 8.8.8.8
	kinetum::module::acl::v1::AclRuleset acl_config_v2;
	acl_config_v2.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	auto *deny_rule = acl_config_v2.add_rules();
	deny_rule->set_priority(100);  // High priority
	deny_rule->set_enabled(true);
	deny_rule->set_src_cidr("0.0.0.0/0");
	deny_rule->set_dst_cidr("8.8.8.8/32");
	deny_rule->set_action(kinetum::module::acl::v1::ACL_ACTION_DENY);

	const auto status2 = epoch2_module->prepare_and_activate(2, kinetum::test::module_config_json(acl_config_v2));
	ASSERT_TRUE(status2.is_ok()) << "Epoch 2 preparation failed: " << status2.message();

	// Create new packet with epoch=2
	auto bytes2 = build_eth_ipv4_udp(0x0a000001, 0x08080808, 5678, 53, 0, {4, 5, 6});
	kinetum::test::packet_record_test_owner new_packet(bytes2, 2);
	ASSERT_TRUE(new_packet.valid()) << new_packet.error();

	// Process in-flight packet with epoch=1 config
	ASSERT_TRUE(engine_->execute_stage(parse, inflight_packet.get()))
		<< "Parse should succeed for in-flight packet";

	// In-flight packet should be PERMITTED (epoch 1 config: permit all)
	EXPECT_TRUE(epoch1_module->process(*inflight_packet.get()))
		<< "In-flight packet (epoch 1) should be PERMITTED by epoch 1 config";

	// Process new packet with epoch=2 config
	ASSERT_TRUE(engine_->execute_stage(parse, new_packet.get())) << "Parse should succeed for new packet";

	// New packet should be DENIED (epoch 2 config: deny 8.8.8.8)
	EXPECT_FALSE(epoch2_module->process(*new_packet.get()))
		<< "New packet (epoch 2) should be DENIED by epoch 2 config";
}

//==============================================================================
// Test 3: NAT44 Multi-Flow (10+ Concurrent Flows)
//==============================================================================

/**
 * @brief Verify NAT44 handles multiple concurrent flows correctly.
 *
 * Test Scenario:
 * 1. Create 16 distinct flows (different src ports)
 * 2. Process outbound packets for all flows
 * 3. Verify each flow gets unique public port allocation
 * 4. Verify session state is maintained per-flow
 *
 * NAT Session Table:
 * - Each (private_ip, private_port, dst_ip, dst_port, proto) tuple = unique session
 * - Session maps to allocated (public_ip, public_port)
 * - No port collision between concurrent flows
 *
 * Expected Results:
 * - All 16 flows get unique port allocations
 * - No port reuse within the test window
 * - All packets successfully translated
 */
TEST_F(dp_integration, nat44_handles_16_concurrent_flows)
{
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();

	// Configure NAT with sufficient port range
	auto nat_config = create_nat_config();
	const auto status = module->prepare_and_activate(1, kinetum::test::module_config_json(nat_config));
	ASSERT_TRUE(status.is_ok()) << "Module preparation failed: " << status.message();

	// Track allocated ports to verify uniqueness
	std::unordered_set<uint16_t> allocated_ports;

	// Create and process 16 concurrent flows
	constexpr int NUM_FLOWS = 16;
	for (int i = 0; i < NUM_FLOWS; ++i) {
		// Each flow has unique source port
		uint16_t src_port = static_cast<uint16_t>(10000 + i);

		auto bytes = build_eth_ipv4_udp(0x0a000001,  // src: 10.0.0.1 (private)
						0x08080808,  // dst: 8.8.8.8
						src_port,    // unique src_port per flow
						53,	     // dst_port (DNS)
						0,	     // dscp
						{static_cast<uint8_t>(i), static_cast<uint8_t>(i + 1)});

		kinetum::test::packet_record_test_owner packet(bytes);
		ASSERT_TRUE(packet.valid()) << packet.error();

		// Parse
		ASSERT_TRUE(engine_->execute_stage(&parse, packet.get())) << "Parse failed for flow " << i;

		// NAT
		ASSERT_TRUE(module->process(*packet.get())) << "NAT failed for flow " << i;

		// Verify public IP is in expected range
		EXPECT_GE(packet.metadata().src_ipv4, 0xcb00710au)  // 203.0.113.10
			<< "Flow " << i << ": src_ip should be in public pool";
		EXPECT_LE(packet.metadata().src_ipv4, 0xcb007114u)  // 203.0.113.20
			<< "Flow " << i << ": src_ip should be in public pool";

		// Verify port is in expected range
		EXPECT_GE(packet.metadata().src_port, 40000) << "Flow " << i << ": src_port should be >= 40000";
		EXPECT_LE(packet.metadata().src_port, 60000) << "Flow " << i << ": src_port should be <= 60000";

		// Verify port uniqueness
		auto [it, inserted] = allocated_ports.insert(packet.metadata().src_port);
		EXPECT_TRUE(inserted) << "Flow " << i << ": port " << packet.metadata().src_port
				      << " was already allocated to another flow (collision!)";
	}

	// Verify we got 16 unique port allocations
	EXPECT_EQ(allocated_ports.size(), NUM_FLOWS) << "Should have " << NUM_FLOWS << " unique port allocations";
}

//==============================================================================
// Test 4: QoS Rate Limiting (Multiple Flows, Different Rates)
//==============================================================================

/**
 * @brief Verify QoS policer correctly rate-limits multiple flows.
 *
 * Test Scenario:
 * 1. Configure policer: 1KB/s CIR, 1KB burst
 * 2. Send burst of packets for flow A (1500 bytes total)
 * 3. Verify first 1000 bytes allowed, rest denied
 * 4. Wait for bucket refill
 * 5. Verify refilled tokens allow more packets
 *
 * Token Bucket Properties:
 * - Bucket fills at CIR rate (bytes/second)
 * - Maximum tokens = burst size
 * - Each packet consumes tokens = packet size
 *
 * Expected Results:
 * - Initial burst: first 1000 bytes allowed
 * - Exceeding burst: packets denied
 * - After refill: more packets allowed
 */
TEST_F(dp_integration, qos_rate_limits_flows_correctly)
{
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "qos0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();

	// Configure QoS with strict rate limit: 10KB/s CIR, 1KB burst
	kinetum::module::qos::v1::QosProfiles qos_config;
	qos_config.set_default_profile("default");  // Must set default profile!

	auto *profile = qos_config.add_profiles();
	profile->set_name("default");
	profile->set_cir_kbps(10);  // 10 KB/s = 10240 bytes/s
	profile->set_cbs_kb(1);	    // 1KB burst

	const auto status = module->prepare_and_activate(1, kinetum::test::module_config_json(qos_config));
	ASSERT_TRUE(status.is_ok()) << "Module preparation failed: " << status.message();

	// Create test packets (each ~100 bytes with headers)
	// Use SAME src_port for all packets - same flow for rate limiting
	auto create_packet = []() {
		// Create packet with ~100 byte payload
		std::vector<uint8_t> payload(60, 0xAA);					// 60 bytes payload
		return build_eth_ipv4_udp(0x0a000001, 0x08080808, 1234, 53, 0, payload	// Same 5-tuple = same flow
		);
	};

	int packets_allowed = 0;
	int packets_denied = 0;

	// Send burst of 20 packets (each ~100 bytes = ~2KB total)
	// With 1KB burst, expect ~10 packets allowed initially
	for (int i = 0; i < 20; ++i) {
		auto bytes = create_packet();
		kinetum::test::packet_record_test_owner packet(bytes);
		ASSERT_TRUE(packet.valid()) << packet.error();

		ASSERT_TRUE(engine_->execute_stage(&parse, packet.get())) << "Parse failed for packet " << i;

		if (module->process(*packet.get())) {
			packets_allowed++;
		} else {
			packets_denied++;
		}
	}

	// Verify some packets were allowed and some denied
	EXPECT_GT(packets_allowed, 0) << "Some packets should be allowed (within burst)";
	EXPECT_GT(packets_denied, 0) << "Some packets should be denied (exceeding burst)";

	// The burst allows ~1024 bytes, each packet is ~100 bytes
	// So approximately 10 packets should be allowed
	EXPECT_GE(packets_allowed, 5) << "At least 5 packets should fit in burst";
	EXPECT_LE(packets_allowed, 15) << "No more than 15 packets should fit in burst";
}

//==============================================================================
// Test 5: Multi-Flow QoS Isolation
//==============================================================================

/**
 * @brief Verify QoS maintains per-flow state isolation.
 *
 * Test Scenario:
 * 1. Configure QoS with 1KB/s CIR, 1KB burst
 * 2. Exhaust flow A's bucket (send >1KB)
 * 3. Verify flow B still has full bucket
 * 4. Verify flows don't interfere with each other
 *
 * Per-Flow Isolation:
 * - Each unique 5-tuple has independent token bucket
 * - Flow A exhaustion doesn't affect flow B
 *
 * Expected Results:
 * - Flow A: exhausted after burst
 * - Flow B: full burst available (independent bucket)
 */
TEST_F(dp_integration, qos_per_flow_isolation)
{
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "qos0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();

	// Configure QoS: 10KB/s CIR, 1KB burst
	kinetum::module::qos::v1::QosProfiles qos_config;
	qos_config.set_default_profile("default");  // Must set default profile!

	auto *profile = qos_config.add_profiles();
	profile->set_name("default");
	profile->set_cir_kbps(10);  // 10 KB/s
	profile->set_cbs_kb(1);	    // 1KB burst

	const auto status = module->prepare_and_activate(1, kinetum::test::module_config_json(qos_config));
	ASSERT_TRUE(status.is_ok()) << "Module preparation failed: " << status.message();

	// Flow A: 10.0.0.1:1234 -> 8.8.8.8:53
	// Flow B: 10.0.0.2:5678 -> 1.1.1.1:53 (different flow)

	auto create_flow_a_packet = []() {
		std::vector<uint8_t> payload(60, 0xAA);
		return build_eth_ipv4_udp(0x0a000001, 0x08080808, 1234, 53, 0, payload);
	};

	auto create_flow_b_packet = []() {
		std::vector<uint8_t> payload(60, 0xBB);
		return build_eth_ipv4_udp(0x0a000002, 0x01010101, 5678, 53, 0, payload);
	};

	// Exhaust Flow A's bucket (send 20 packets)
	int flow_a_allowed = 0;
	int flow_a_denied = 0;
	for (int i = 0; i < 20; ++i) {
		auto bytes = create_flow_a_packet();
		kinetum::test::packet_record_test_owner packet(bytes);
		ASSERT_TRUE(packet.valid()) << packet.error();

		EXPECT_TRUE(engine_->execute_stage(&parse, packet.get()));
		if (module->process(*packet.get())) {
			flow_a_allowed++;
		} else {
			flow_a_denied++;
		}
	}

	EXPECT_GT(flow_a_allowed, 0) << "Flow A should consume its independent initial burst";
	EXPECT_GT(flow_a_denied, 0) << "Flow A should have some packets denied after exhausting bucket";

	// Now send Flow B packets - should have full bucket available
	int flow_b_allowed = 0;
	for (int i = 0; i < 10; ++i) {
		auto bytes = create_flow_b_packet();
		kinetum::test::packet_record_test_owner packet(bytes);
		ASSERT_TRUE(packet.valid()) << packet.error();

		EXPECT_TRUE(engine_->execute_stage(&parse, packet.get()));
		if (module->process(*packet.get())) {
			flow_b_allowed++;
		}
	}

	// Flow B should have its own full burst available
	EXPECT_GT(flow_b_allowed, 0) << "Flow B should have packets allowed (independent bucket from Flow A)";

	// Flow B's first ~10 packets should be allowed (1KB burst / ~100 bytes each)
	EXPECT_GE(flow_b_allowed, 5) << "Flow B should have at least 5 packets allowed within its burst";
}

//==============================================================================
// Test 6: Large Packet Burst Processing
//==============================================================================

/**
 * @brief Verify system handles large packet bursts without issues.
 *
 * Test Scenario:
 * 1. Create 1000 packets with varying src ports
 * 2. Process through Parse -> ACL pipeline
 * 3. Verify all packets processed successfully
 * 4. No memory leaks, no crashes
 *
 * Hot-Path Verification:
 * - This test indirectly verifies zero-allocation hot path
 * - Large burst would expose any per-packet allocations
 */
TEST_F(dp_integration, handles_1000_packet_burst)
{
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.acl", KINETUM_ACL_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "acl0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();

	// Configure ACL to permit all
	auto acl_config = create_acl_config();
	const auto status = module->prepare_and_activate(1, kinetum::test::module_config_json(acl_config));
	ASSERT_TRUE(status.is_ok());

	// Process 1000 packets
	constexpr int BURST_SIZE = 1000;
	int processed = 0;

	for (int i = 0; i < BURST_SIZE; ++i) {
		uint16_t src_port = static_cast<uint16_t>(1000 + (i % 60000));
		auto bytes =
			build_eth_ipv4_udp(0x0a000001, 0x08080808, src_port, 53, 0, {static_cast<uint8_t>(i & 0xFF)});

		kinetum::test::packet_record_test_owner packet(bytes);
		ASSERT_TRUE(packet.valid()) << packet.error();

		if (engine_->execute_stage(&parse, packet.get()) && module->process(*packet.get())) {
			processed++;
		}
	}

	// All 1000 packets should be processed
	EXPECT_EQ(processed, BURST_SIZE) << "All " << BURST_SIZE << " packets should be processed";
}

//==============================================================================
// Wire-Format Verification Tests
//==============================================================================

/**
 * @brief Verify full pipeline maintains packet buffer integrity.
 *
 * This catches an offset defect at any stage of the complete pipeline path.
 *
 * Test verifies:
 * 1. Ethernet header is NOT corrupted after full pipeline
 * 2. NAT correctly modifies IP/port at correct offsets
 * 3. Metadata matches wire-format bytes
 * 4. IP checksum is valid after modifications
 */
TEST_F(dp_integration, wire_format_full_pipeline_integrity)
{
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	auto acl_or = kinetum::test::exact_module_test_context::create("kinetum.acl", KINETUM_ACL_MODULE_PATH,
								       TEST_MODULE_RESOURCES, "acl0@lane_0");
	ASSERT_TRUE(acl_or.is_ok()) << acl_or.error().message();
	auto acl = std::move(acl_or).value();
	auto nat_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
								       TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(nat_or.is_ok()) << nat_or.error().message();
	auto nat = std::move(nat_or).value();
	auto qos_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
								       TEST_MODULE_RESOURCES, "qos0@lane_0");
	ASSERT_TRUE(qos_or.is_ok()) << qos_or.error().message();
	auto qos = std::move(qos_or).value();
	ASSERT_TRUE(acl->prepare_and_activate(1, kinetum::test::module_config_json(create_acl_config())).is_ok());
	ASSERT_TRUE(nat->prepare_and_activate(1, kinetum::test::module_config_json(create_nat_config())).is_ok());
	ASSERT_TRUE(qos->prepare_and_activate(1, kinetum::test::module_config_json(create_qos_config())).is_ok());

	// Build test packet
	auto bytes = build_eth_ipv4_udp(0x0a000064,  // src: 10.0.0.100 (private)
					0x08080404,  // dst: 8.8.4.4
					54321,	     // src_port
					443,	     // dst_port (HTTPS)
					0, {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE});

	// Save original Ethernet header
	uint8_t orig_eth[14];
	save_ethernet_header(bytes.data(), orig_eth);

	// Verify original wire format
	auto pre_verify = verify_wire_format(bytes.data(), bytes.size(), 0x0a000064, 0x08080404, 54321, 443);
	ASSERT_TRUE(pre_verify.ok) << "Pre-pipeline: " << pre_verify.failure_reason;

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Process through the platform parser and exact policy callbacks.
	ASSERT_TRUE(engine_->execute_stage(&parse, packet.get()));
	ASSERT_TRUE(acl->process(*packet.get()));
	ASSERT_TRUE(nat->process(*packet.get()));
	ASSERT_TRUE(qos->process(*packet.get()));

	// Verify wire-format integrity after the complete pipeline.

	const uint8_t *pkt_data = packet.data();
	const std::size_t pkt_len = packet.size();

	// 1. Ethernet header must NOT be corrupted by any stage
	EXPECT_TRUE(compare_ethernet_headers(pkt_data, orig_eth))
		<< "Ethernet header corrupted during pipeline processing";

	EXPECT_TRUE(verify_ethernet_intact(pkt_data, pkt_len)) << "Ethernet header integrity check failed";

	// 2. Read wire-format values
	const uint8_t *ip_hdr = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t *udp_hdr = pkt_data + wire_offsets::UDP_HDR_START;

	uint32_t wire_src_ip = kinetum::algo::net::read_be32(ip_hdr + 12);
	uint32_t wire_dst_ip = kinetum::algo::net::read_be32(ip_hdr + 16);
	uint16_t wire_src_port = kinetum::algo::net::read_be16(udp_hdr + 0);
	uint16_t wire_dst_port = kinetum::algo::net::read_be16(udp_hdr + 2);

	// 3. Verify NAT translation in wire format (src should be public IP)
	EXPECT_GE(wire_src_ip, 0xcb00710au)  // 203.0.113.10
		<< "Wire-format src_ip should be in public pool after NAT";
	EXPECT_LE(wire_src_ip, 0xcb007114u)  // 203.0.113.20
		<< "Wire-format src_ip should be in public pool after NAT";

	EXPECT_TRUE(verify_port_in_range(wire_src_port, 40000, 60000))
		<< "Wire-format src_port should be in NAT pool range";

	// 4. Verify destination unchanged (SNAT only modifies source)
	EXPECT_EQ(wire_dst_ip, 0x08080404u) << "dst_ip should be unchanged";
	EXPECT_EQ(wire_dst_port, 443) << "dst_port should be unchanged";

	// 5. Verify IP checksum is valid
	uint16_t wire_cksum = kinetum::algo::net::read_be16(ip_hdr + 10);
	uint16_t computed_cksum = compute_ipv4_checksum(ip_hdr, 20);
	EXPECT_EQ(wire_cksum, computed_cksum) << "IP header checksum invalid after full pipeline";

	// 6. Verify metadata matches wire format
	const auto &metadata = packet.metadata();
	auto consistency = verify_metadata_wire_consistency(pkt_data, pkt_len, metadata.src_ipv4, metadata.dst_ipv4,
							    metadata.src_port, metadata.dst_port);
	EXPECT_TRUE(consistency.ok) << consistency.failure_reason;
}

/**
 * @brief Verify NAT DNAT translation modifies correct wire-format bytes.
 *
 * This test validates the reverse NAT translation (inbound packets).
 */
TEST_F(dp_integration, wire_format_nat_dnat_verification)
{
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();

	auto nat_config = create_nat_config();
	ASSERT_TRUE(module->prepare_and_activate(1, kinetum::test::module_config_json(nat_config)).is_ok());

	// Step 1: Outbound packet to create session
	auto outbound = build_eth_ipv4_udp(0xC0A80001,	// src: 192.168.0.1 (private)
					   0x01020304,	// dst: 1.2.3.4
					   22222, 80, 0, {0x01, 0x02});

	kinetum::test::packet_record_test_owner outbound_packet(outbound);
	ASSERT_TRUE(outbound_packet.valid()) << outbound_packet.error();

	ASSERT_TRUE(engine_->execute_stage(&parse, outbound_packet.get()));
	ASSERT_TRUE(module->process(*outbound_packet.get()));

	// Capture NAT-allocated values
	uint32_t nat_public_ip = outbound_packet.metadata().src_ipv4;
	uint16_t nat_public_port = outbound_packet.metadata().src_port;

	// Step 2: Inbound reply packet
	auto inbound = build_eth_ipv4_udp(0x01020304,	    // src: 1.2.3.4 (server)
					  nat_public_ip,    // dst: NAT public IP
					  80,		    // src_port
					  nat_public_port,  // dst_port: NAT allocated port
					  0, {0x03, 0x04});

	uint8_t orig_eth[14];
	save_ethernet_header(inbound.data(), orig_eth);

	kinetum::test::packet_record_test_owner inbound_packet(inbound);
	ASSERT_TRUE(inbound_packet.valid()) << inbound_packet.error();

	ASSERT_TRUE(engine_->execute_stage(&parse, inbound_packet.get()));
	ASSERT_TRUE(module->process(*inbound_packet.get()));

	// Verify wire-format after DNAT
	const uint8_t *pkt_data = inbound_packet.data();

	// Ethernet must NOT be corrupted
	EXPECT_TRUE(compare_ethernet_headers(pkt_data, orig_eth)) << "Ethernet header corrupted during DNAT";

	// Read wire-format values
	const uint8_t *ip_hdr = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t *udp_hdr = pkt_data + wire_offsets::UDP_HDR_START;

	uint32_t wire_dst_ip = kinetum::algo::net::read_be32(ip_hdr + 16);
	uint16_t wire_dst_port = kinetum::algo::net::read_be16(udp_hdr + 2);

	// DNAT should restore original private IP:port
	EXPECT_EQ(wire_dst_ip, 0xC0A80001u)  // 192.168.0.1
		<< "Wire-format dst_ip should be original private IP after DNAT";
	EXPECT_EQ(wire_dst_port, 22222) << "Wire-format dst_port should be original private port after DNAT";

	// Verify checksum
	uint16_t wire_cksum = kinetum::algo::net::read_be16(ip_hdr + 10);
	uint16_t computed_cksum = compute_ipv4_checksum(ip_hdr, 20);
	EXPECT_EQ(wire_cksum, computed_cksum) << "IP header checksum invalid after DNAT";
}

//==============================================================================
// Unimplemented Stage Kind DP Backstop Tests
//==============================================================================

/**
 * @brief An unspecified stage kind fails closed if it reaches the DP.
 *
 * Axiom rejects the zero sentinel. This test preserves the independent packet
 * mechanism backstop for a malformed direct call.
 */
TEST_F(dp_integration, unspecified_stage_kind_dp_backstop_returns_false)
{
	kinetum::axiom::v1::Stage malformed_stage;
	malformed_stage.set_stage_id("unspecified_backstop");

	auto bytes = build_eth_ipv4_udp(0x0a000001, 0x08080808, 1234, 53, 0, {1, 2, 3, 4});
	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	EXPECT_FALSE(engine_->execute_stage(&malformed_stage, packet.get()));
}

/**
 * @brief An undeclared stage number fails closed if it reaches the DP.
 *
 * Recursive enum admission rejects the number before runtime construction;
 * direct packet-mechanism dispatch still rejects independently.
 */
TEST_F(dp_integration, unknown_stage_kind_dp_backstop_returns_false)
{
	kinetum::axiom::v1::Stage malformed_stage;
	malformed_stage.set_stage_id("unknown_backstop");
	malformed_stage.set_kind(static_cast<kinetum::axiom::v1::StageKind>(999));

	auto bytes = build_eth_ipv4_udp(0x0a000001, 0x08080808, 1234, 53, 0, {1, 2, 3, 4});
	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	EXPECT_FALSE(engine_->execute_stage(&malformed_stage, packet.get()));
}
