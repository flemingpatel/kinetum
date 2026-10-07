// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dp_acl.cpp
 * @brief ACL module behavior and admission tests.
 * @author Fleming Patel
 *
 * The ACL module is a policy module that implements packet filtering based
 * on 5-tuple matching with priority-based rule evaluation. ACL is implemented
 * as an ordinary SDK module through the same image and lifecycle contract used
 * by customer modules.
 *
 * ACL Evaluation Order:
 * ---------------------
 * 1. Rules are sorted by priority (highest first)
 * 2. First matching rule determines action (PERMIT/DENY)
 * 3. If no rule matches, default_action applies
 *
 * CIDR Matching:
 * --------------
 * - Source CIDR: matches packet source IP
 * - Destination CIDR: matches packet destination IP
 * - 0.0.0.0/0 matches any IP (wildcard)
 * - /32 matches exact IP
 *
 * SDK Conformance:
 * ----------------
 * - Built-in modules use same SDK as customer modules
 * - Same exact image, context, and prepared-artifact lifecycle
 *
 * @see src/modules/acl/acl_module.cpp
 * @see src/modules/acl/acl.proto
 */

#include <gtest/gtest.h>

#include <algorithm>  // std::sort
#include <memory_resource>
#include <stdexcept>

#include "src/dp/dp_engine.hpp"
#include "src/modules/acl/acl_impl.hpp"
#include <kinetum/algo/simd_classify.hpp>
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_record_test_harness.hpp"
#include "tests/test_dp_helpers.hpp"

// Module-owned ACL proto (generated from src/modules/acl/acl.proto)
#include "src/modules/acl/acl.pb.h"
#include "tests/module_config_test_helpers.hpp"

// KINETUM_ACL_MODULE_PATH is defined by CMake at compile time.
// This provides the absolute path to the ACL module .so file.
#ifndef KINETUM_ACL_MODULE_PATH
#error "KINETUM_ACL_MODULE_PATH must be defined by CMake"
#endif

/** @brief Explicit ACL fixture context-lifetime and per-epoch memory capacities. */
constexpr kinetum::test::module_test_resource_contract TEST_MODULE_RESOURCES{
	64u * 1024u * 1024u,
	2u * 1024u * 1024u,
};

//==============================================================================
// ACL Rule Priority Tests
//==============================================================================

/**
 * @brief Verify ACL correctly denies packets matching high-priority deny rule.
 *
 * Test Scenario:
 * - Packet: 10.0.0.1:1234 -> 8.8.8.8:53 (UDP/DNS)
 * - Rule 1 (priority 100): DENY dst 8.8.8.8/32 (matches!)
 * - Rule 2 (priority 1): PERMIT all (lower priority, not reached)
 * - Default: PERMIT
 *
 * Expected: Packet DENIED by Rule 1 (higher priority wins)
 *
 * This test validates:
 * 1. Exact image and context admission through the production module manager
 * 2. Module-owned proto configuration (AclRuleset)
 * 3. Priority-based rule evaluation
 * 4. CIDR matching (exact /32 match on destination)
 *
 * @note Uses build_eth_ipv4_udp() helper from test_dp_helpers.hpp
 */
TEST(dp_acl, denies_by_rule_priority)
{
	kinetum::dp::dp_engine eng;

	// Build test packet: 10.0.0.1:1234 -> 8.8.8.8:53 UDP
	auto bytes = build_eth_ipv4_udp(0x0a000001,  // src: 10.0.0.1
					0x08080808,  // dst: 8.8.8.8
					1234,	     // src_port
					53,	     // dst_port (DNS)
					0,	     // dscp
					{1, 2, 3}    // payload
	);
	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Parse stage (platform mechanism - extracts L3/L4 metadata)
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// Create ACL configuration using MODULE-OWNED proto
	kinetum::module::acl::v1::AclRuleset acl_config;
	acl_config.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	// Rule 1: Higher priority DENY for dst 8.8.8.8/32
	auto *r1 = acl_config.add_rules();
	r1->set_priority(100);	// HIGH priority
	r1->set_enabled(true);
	r1->set_src_cidr("0.0.0.0/0");	 // Any source
	r1->set_dst_cidr("8.8.8.8/32");	 // Exact dst match
	r1->set_action(kinetum::module::acl::v1::ACL_ACTION_DENY);

	// Rule 2: Lower priority PERMIT all (should not be reached for 8.8.8.8)
	auto *r2 = acl_config.add_rules();
	r2->set_priority(1);  // LOW priority
	r2->set_enabled(true);
	r2->set_src_cidr("0.0.0.0/0");
	r2->set_dst_cidr("0.0.0.0/0");
	r2->set_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.acl", KINETUM_ACL_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "acl0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << "Module admission failed: " << module_or.error().message();
	auto module = std::move(module_or).value();
	const auto status = module->prepare_and_activate(1, kinetum::test::module_config_json(acl_config));
	ASSERT_TRUE(status.is_ok()) << "Module preparation failed: " << status.message();

	// Execute parse stage
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get())) << "Parse stage should succeed";

	// Execute ACL stage - should DENY (return false = drop packet)
	EXPECT_FALSE(module->process(*packet.get())) << "ACL should DENY packet to 8.8.8.8 (high-priority deny rule)";
}

//==============================================================================
// ACL Wire-Format Verification Tests
//==============================================================================

/**
 * @brief Verify ACL PERMIT does not corrupt packet buffer.
 *
 * This catches an offset defect that writes through a read-only ACL path.
 *
 * Test verifies:
 * 1. Ethernet header is NOT corrupted after ACL permit
 * 2. IP header is unchanged (ACL doesn't modify)
 * 3. UDP header is unchanged
 * 4. Original packet bytes match after processing
 */
TEST(dp_acl, wire_format_permit_unchanged)
{
	kinetum::dp::dp_engine eng;

	// Build test packet: 192.168.1.1:5000 -> 10.10.10.10:80
	auto bytes = build_eth_ipv4_udp(0xC0A80101,		  // src: 192.168.1.1
					0x0A0A0A0A,		  // dst: 10.10.10.10
					5000,			  // src_port
					80,			  // dst_port
					0,			  // dscp
					{0xDE, 0xAD, 0xBE, 0xEF}  // payload
	);

	// Save original Ethernet header before processing
	uint8_t orig_eth[14];
	save_ethernet_header(bytes.data(), orig_eth);

	// Verify original packet structure
	auto pre_verify = verify_wire_format(bytes.data(), bytes.size(), 0xC0A80101, 0x0A0A0A0A, 5000, 80);
	ASSERT_TRUE(pre_verify.ok) << "Pre-ACL: " << pre_verify.failure_reason;

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Setup pipeline
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// ACL config: PERMIT all traffic
	kinetum::module::acl::v1::AclRuleset acl_config;
	acl_config.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	auto *rule = acl_config.add_rules();
	rule->set_priority(100);
	rule->set_enabled(true);
	rule->set_src_cidr("0.0.0.0/0");
	rule->set_dst_cidr("0.0.0.0/0");
	rule->set_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.acl", KINETUM_ACL_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "acl0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, kinetum::test::module_config_json(acl_config)).is_ok());

	// Execute parse and ACL
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get()));
	ASSERT_TRUE(module->process(*packet.get())) << "ACL should PERMIT packet";

	// Verify that the read-only callback preserved the complete packet.

	const uint8_t *pkt_data = packet.data();
	const std::size_t pkt_len = packet.size();

	// 1. Ethernet header must be unchanged
	EXPECT_TRUE(compare_ethernet_headers(pkt_data, orig_eth)) << "Ethernet header corrupted during ACL permit";

	EXPECT_TRUE(verify_ethernet_intact(pkt_data, pkt_len)) << "Ethernet header integrity check failed";

	// 2. IP and UDP should be unchanged (ACL is read-only)
	auto post_verify = verify_wire_format(pkt_data, pkt_len, 0xC0A80101, 0x0A0A0A0A, 5000, 80);
	EXPECT_TRUE(post_verify.ok) << "Post-ACL wire-format changed: " << post_verify.failure_reason;

	// 3. Verify IP checksum is still valid
	EXPECT_TRUE(post_verify.ip_checksum_ok) << "IP checksum corrupted after ACL";

	// 4. Verify metadata matches wire format
	const auto &metadata = packet.metadata();
	auto consistency = verify_metadata_wire_consistency(pkt_data, pkt_len, metadata.src_ipv4, metadata.dst_ipv4,
							    metadata.src_port, metadata.dst_port);
	EXPECT_TRUE(consistency.ok) << consistency.failure_reason;
}

/**
 * @brief Verify ACL correctly matches CIDR ranges in wire-format addresses.
 *
 * This test ensures ACL reads IP addresses from the parsed L3 location rather
 * than interpreting link-layer bytes as the IPv4 header.
 */
TEST(dp_acl, wire_format_cidr_matching)
{
	kinetum::dp::dp_engine eng;

	// Build packet with specific IPs for CIDR testing
	// 172.16.5.100:8080 -> 203.0.113.50:443
	auto bytes = build_eth_ipv4_udp(0xAC100564,  // src: 172.16.5.100
					0xCB007132,  // dst: 203.0.113.50
					8080,	     // src_port
					443,	     // dst_port (HTTPS)
					0, {0x01, 0x02, 0x03});

	// Verify the wire format has correct IPs before any processing
	auto pre_verify = verify_wire_format(bytes.data(), bytes.size(), 0xAC100564, 0xCB007132, 8080, 443);
	ASSERT_TRUE(pre_verify.ok) << pre_verify.failure_reason;

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Setup pipeline
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// ACL config: DENY traffic from 172.16.0.0/12 to 203.0.113.0/24
	kinetum::module::acl::v1::AclRuleset acl_config;
	acl_config.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	auto *rule = acl_config.add_rules();
	rule->set_priority(100);
	rule->set_enabled(true);
	rule->set_src_cidr("172.16.0.0/12");   // Matches 172.16.5.100
	rule->set_dst_cidr("203.0.113.0/24");  // Matches 203.0.113.50
	rule->set_action(kinetum::module::acl::v1::ACL_ACTION_DENY);

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.acl", KINETUM_ACL_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "acl0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, kinetum::test::module_config_json(acl_config)).is_ok());

	// Execute parse
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get()));

	// Verify parsed metadata matches wire format (ensures parser used correct offset)
	EXPECT_EQ(packet.metadata().src_ipv4, 0xAC100564u) << "Parser should extract correct src_ip";
	EXPECT_EQ(packet.metadata().dst_ipv4, 0xCB007132u) << "Parser should extract correct dst_ip";

	// Execute ACL - should DENY based on CIDR match
	EXPECT_FALSE(module->process(*packet.get()))
		<< "ACL should DENY packet matching CIDR rules (172.16.0.0/12 -> 203.0.113.0/24)";
}

//==============================================================================
// ACL Cache Counter Accounting Tests
//==============================================================================

/**
 * @brief Verify cache stats grow linearly across batches with reset_stats().
 *
 * get_stats() returns cumulative totals for the current interval. Adding those
 * cumulative values to an SDK counter after every batch would cause quadratic
 * inflation: after N batches of K hits, counter = K*N*(N+1)/2.
 *
 * reset_stats() after each read produces per-batch deltas, so the published
 * counter grows linearly: after N batches of K hits, counter = K*N.
 *
 * This test simulates the do_process() read-and-reset pattern to prove
 * linear growth.
 */
TEST(dp_acl, cache_counter_no_quadratic_inflation)
{
	using namespace kinetum::modules::acl;

	acl_cache cache(64, *std::pmr::get_default_resource());

	// Build a compiled ACL with one permit-all rule
	acl_compiled acl(*std::pmr::get_default_resource());
	acl.default_action = acl_action::PERMIT;
	acl_rule_compiled rule;
	rule.priority = 100;
	rule.src = parse_cidr("0.0.0.0/0");
	rule.dst = parse_cidr("0.0.0.0/0");
	rule.action = acl_action::PERMIT;
	acl.rules.push_back(rule);

	// Simulate 5 batches of 10 lookups each (same flow -> 1 miss + 9 hits per batch)
	constexpr int BATCHES = 5;
	constexpr int LOOKUPS_PER_BATCH = 10;
	constexpr uint64_t CONFIG_EPOCH = 1;

	uint64_t total_hits = 0;
	uint64_t total_misses = 0;

	for (int batch = 0; batch < BATCHES; ++batch) {
		// Simulate batch: 10 lookups of the same flow
		for (int i = 0; i < LOOKUPS_PER_BATCH; ++i) {
			auto action = eval_acl_cached(acl, cache, CONFIG_EPOCH,
						      0x0A000001,  // src: 10.0.0.1
						      0x0A000002,  // dst: 10.0.0.2
						      17, 1234, 5678);
			EXPECT_EQ(action, acl_action::PERMIT);
		}

		// Read-and-reset pattern used by acl_module::do_process().
		const auto stats = cache.get_stats();
		total_hits += stats.hits;
		total_misses += stats.misses;
		cache.reset_stats();
	}

	// First batch: 1 miss + 9 hits (cold cache)
	// Batches 2-5: 0 misses + 10 hits each (warm cache, same exact epoch)
	// Total: 1 miss, 49 hits
	//
	// Re-adding cumulative totals would produce:
	//   9 + 19 + 29 + 39 + 49 = 145 (quadratic - sum of cumulative values)
	// Resetting each interval produces:
	//   9 + 10 + 10 + 10 + 10 = 49 (linear - per-batch deltas)

	EXPECT_EQ(total_hits, 49u) << "Cache hits must grow linearly (49), not quadratically (145)";
	EXPECT_EQ(total_misses, 1u) << "Only the first lookup should miss (cold cache)";

	// The cache must follow the exact platform epoch and cannot
	// return the old policy's decision under the replacement config.
	acl_compiled replacement_acl(*std::pmr::get_default_resource());
	replacement_acl.default_action = acl_action::DENY;
	EXPECT_EQ(eval_acl_cached(replacement_acl, cache, 2, 0x0A000001, 0x0A000002, 17, 1234, 5678), acl_action::DENY);
	const auto replacement_stats = cache.get_stats();
	EXPECT_EQ(replacement_stats.hits, 0u);
	EXPECT_EQ(replacement_stats.misses, 1u);
}

/**
 * @brief Verify reset_stats() fully drains counters to zero.
 *
 * After reset_stats(), get_stats() must return all zeros. This ensures
 * the read-and-reset pattern produces exact per-batch deltas.
 */
TEST(dp_acl, cache_reset_stats_drains_to_zero)
{
	using namespace kinetum::modules::acl;

	auto &memory = *std::pmr::get_default_resource();
	EXPECT_THROW((void)acl_cache(0, memory), std::invalid_argument);
	EXPECT_THROW((void)acl_cache(63, memory), std::invalid_argument);
	acl_cache cache(64, memory);

	acl_compiled acl(memory);
	acl.default_action = acl_action::DENY;

	// Generate some stats via lookups (all misses for distinct flows, then cache hits)
	for (int i = 0; i < 5; ++i) {
		auto action = eval_acl_cached(acl, cache, 1, static_cast<uint32_t>(i), 0, 17, 0, 0);
		EXPECT_EQ(action, acl_action::DENY);
	}

	const auto before = cache.get_stats();
	EXPECT_GT(before.misses, 0u) << "Should have accumulated some misses";

	cache.reset_stats();

	const auto after = cache.get_stats();
	EXPECT_EQ(after.hits, 0u);
	EXPECT_EQ(after.misses, 0u);
}

//==============================================================================
// SIMD Batch Classification Tests
//==============================================================================

/**
 * @brief Verify SIMD batch results match linear eval for multi-rule ACL.
 *
 * Builds an ACL with two rules (permit 10.0.0.0/8, deny to 192.168.1.0/24),
 * evaluates 5 test packets via both the linear eval_acl_5tuple() path and
 * the algo-layer classify_batch_acl() SIMD path, and asserts identical results.
 *
 * This proves the SIMD batch path is semantically equivalent to the scalar
 * linear path for standard configurations.
 */
TEST(dp_acl, simd_batch_matches_linear_eval)
{
	using namespace kinetum::modules::acl;

	// Build ACL with two priority-ordered rules
	acl_compiled acl(*std::pmr::get_default_resource());
	acl.default_action = acl_action::DENY;

	// Rule 1 (priority 200): permit 10.0.0.0/8 -> any
	acl_rule_compiled r1;
	r1.priority = 200;
	r1.src = parse_cidr("10.0.0.0/8");
	r1.dst = parse_cidr("0.0.0.0/0");
	r1.action = acl_action::PERMIT;
	r1.protocol = l4_protocol::ANY;
	acl.rules.push_back(r1);

	// Rule 2 (priority 100): deny any -> 192.168.1.0/24
	acl_rule_compiled r2;
	r2.priority = 100;
	r2.src = parse_cidr("0.0.0.0/0");
	r2.dst = parse_cidr("192.168.1.0/24");
	r2.action = acl_action::DENY;
	r2.protocol = l4_protocol::ANY;
	acl.rules.push_back(r2);

	// Sort by priority (descending) - matches compile_acl_from_json() behavior
	std::sort(acl.rules.begin(), acl.rules.end(),
		  [](const acl_rule_compiled &a, const acl_rule_compiled &b) { return a.priority > b.priority; });

	// Build SIMD rules (same conversion as compile_acl_from_json)
	for (const auto &r : acl.rules) {
		kinetum::algo::acl_rule_simd sr{};
		sr.src_network = r.src.network;
		sr.src_mask = r.src.mask;
		sr.dst_network = r.dst.network;
		sr.dst_mask = r.dst.mask;
		sr.src_port_min = r.src_port.min;
		sr.src_port_max = r.src_port.max;
		sr.dst_port_min = r.dst_port.min;
		sr.dst_port_max = r.dst_port.max;
		sr.protocol = (r.protocol == l4_protocol::OTHER) ? r.protocol_num : static_cast<uint8_t>(r.protocol);
		sr.action = static_cast<uint8_t>(r.action);
		acl.simd_rules.push_back(sr);
	}

	// Test packets covering all classification outcomes
	struct test_pkt {
		uint32_t src_ip;
		uint32_t dst_ip;
		uint8_t proto;
		uint16_t src_port;
		uint16_t dst_port;
	};

	test_pkt pkts[] = {
		{0x0A000001, 0x08080808, 17, 1234, 53},	 // 10.0.0.1 -> 8.8.8.8 - permit (rule 1)
		{0xC0A80001, 0xC0A80101, 6, 5000, 80},	 // 192.168.0.1 -> 192.168.1.1 - deny (rule 2)
		{0x0A010203, 0xC0A80164, 6, 8080, 443},	 // 10.1.2.3 -> 192.168.1.100 - permit (rule 1, higher pri)
		{0xAC100001, 0x08080808, 17, 4000, 53},	 // 172.16.0.1 -> 8.8.8.8 - deny (default, no match)
		{0x0A0A0A0A, 0x0A0A0A0B, 1, 0, 0},	 // 10.10.10.10 -> 10.10.10.11 - permit (rule 1)
	};
	constexpr std::size_t COUNT = 5;

	// Evaluate via linear path
	acl_action linear_results[COUNT];
	for (std::size_t i = 0; i < COUNT; ++i) {
		linear_results[i] = eval_acl_5tuple(acl, pkts[i].src_ip, pkts[i].dst_ip, pkts[i].proto,
						    pkts[i].src_port, pkts[i].dst_port);
	}

	// Evaluate via SIMD batch path
	kinetum::algo::packet_batch_soa soa;
	soa.count = COUNT;
	for (std::size_t i = 0; i < COUNT; ++i) {
		soa.src_ips[i] = pkts[i].src_ip;
		soa.dst_ips[i] = pkts[i].dst_ip;
		soa.src_ports[i] = pkts[i].src_port;
		soa.dst_ports[i] = pkts[i].dst_port;
		soa.protocols[i] = pkts[i].proto;
	}

	uint8_t simd_results[COUNT];
	kinetum::algo::classify_batch_acl(soa, acl.simd_rules.data(), acl.simd_rules.size(), simd_results,
					  static_cast<uint8_t>(acl.default_action));

	// Verify exact equivalence between linear and SIMD paths
	for (std::size_t i = 0; i < COUNT; ++i) {
		EXPECT_EQ(static_cast<uint8_t>(linear_results[i]), simd_results[i]) << "Mismatch at packet " << i;
	}

	// Verify expected results
	EXPECT_EQ(linear_results[0], acl_action::PERMIT);  // 10.0.0.1 matches rule 1
	EXPECT_EQ(linear_results[1], acl_action::DENY);	   // 192.168.0.1 matches rule 2
	EXPECT_EQ(linear_results[2], acl_action::PERMIT);  // 10.1.2.3 matches rule 1 (higher pri)
	EXPECT_EQ(linear_results[3], acl_action::DENY);	   // 172.16.0.1 no match -> default deny
	EXPECT_EQ(linear_results[4], acl_action::PERMIT);  // 10.10.10.10 matches rule 1
}

/**
 * @brief Verify simd_rules are precomputed by compile_acl_from_json().
 *
 * compile_acl_from_json() must populate acl_compiled::simd_rules with
 * the same number of entries as rules, and correct field mappings.
 */
TEST(dp_acl, simd_rules_populated_on_compile)
{
	using namespace kinetum::modules::acl;

	// Build config via module-owned proto
	kinetum::module::acl::v1::AclRuleset rs;
	rs.set_default_action(kinetum::module::acl::v1::ACL_ACTION_DENY);

	auto *r1 = rs.add_rules();
	r1->set_priority(100);
	r1->set_enabled(true);
	r1->set_src_cidr("10.0.0.0/8");
	r1->set_dst_cidr("192.168.0.0/16");
	r1->set_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);
	r1->set_protocol(6);  // TCP
	r1->set_dst_port_min(80);
	r1->set_dst_port_max(80);

	auto *r2 = rs.add_rules();
	r2->set_priority(50);
	r2->set_enabled(true);
	r2->set_src_cidr("0.0.0.0/0");
	r2->set_dst_cidr("0.0.0.0/0");
	r2->set_action(kinetum::module::acl::v1::ACL_ACTION_DENY);

	std::string blob = kinetum::test::module_config_json(rs);
	auto compiled = kinetum::test::compile_acl_for_test(blob);
	ASSERT_NE(compiled, nullptr);

	// simd_rules must have same count as rules
	ASSERT_EQ(compiled->simd_rules.size(), compiled->rules.size());
	ASSERT_EQ(compiled->simd_rules.size(), 2u);

	// Rules are sorted by priority descending, so r1 is first.
	const auto &sr0 = compiled->simd_rules[0];
	EXPECT_EQ(sr0.protocol, 6u);  // TCP
	EXPECT_EQ(sr0.dst_port_min, 80u);
	EXPECT_EQ(sr0.dst_port_max, 80u);
	EXPECT_EQ(sr0.action, static_cast<uint8_t>(acl_action::PERMIT));

	const auto &sr1 = compiled->simd_rules[1];
	EXPECT_EQ(sr1.action, static_cast<uint8_t>(acl_action::DENY));
}

/** @brief Pin ACL action numbers and reject every unauthored runtime action form. */
TEST(dp_acl, action_schema_and_runtime_admission_are_exact)
{
	const auto *actions = kinetum::module::acl::v1::AclAction_descriptor();
	ASSERT_NE(actions, nullptr);
	ASSERT_EQ(actions->value_count(), 3);
	ASSERT_NE(actions->FindValueByNumber(0), nullptr);
	ASSERT_NE(actions->FindValueByNumber(1), nullptr);
	ASSERT_NE(actions->FindValueByNumber(2), nullptr);
	EXPECT_EQ(actions->FindValueByNumber(0)->name(), "ACL_ACTION_UNSPECIFIED");
	EXPECT_EQ(actions->FindValueByNumber(1)->name(), "ACL_ACTION_PERMIT");
	EXPECT_EQ(actions->FindValueByNumber(2)->name(), "ACL_ACTION_DENY");
	EXPECT_EQ(actions->FindValueByNumber(3), nullptr);

	constexpr const char *INVALID_CONFIGS[] = {
		R"json({})json",
		R"json({"rules":[]})json",
		R"json({"default_action":0})json",
		R"json({"default_action":3})json",
		R"json({"default_action":4})json",
		R"json({"default_action":-1})json",
		R"json({"default_action":1.0})json",
		R"json({"default_action":"1"})json",
		R"json({"default_action":true})json",
		R"json({"default_action":null})json",
		R"json({"default_action":[]})json",
		R"json({"default_action":{}})json",
		R"json({"rules":[{"enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":0,"enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":3,"enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":4,"enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":-1,"enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":1.0,"enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":"1","enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":true,"enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":null,"enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":[],"enabled":true}],"default_action":2})json",
		R"json({"rules":[{"action":{},"enabled":true}],"default_action":2})json",
	};
	for (const char *config : INVALID_CONFIGS) {
		EXPECT_EQ(kinetum::test::compile_acl_for_test(config), nullptr) << config;
	}

	const auto explicit_deny = kinetum::test::compile_acl_for_test(R"json({"default_action":2})json");
	ASSERT_NE(explicit_deny, nullptr);
	EXPECT_TRUE(explicit_deny->rules.empty());
	EXPECT_EQ(explicit_deny->default_action, kinetum::modules::acl::acl_action::DENY);

	const auto explicit_permit = kinetum::test::compile_acl_for_test(
		R"json({"rules":[{"action":1,"enabled":true}],"default_action":2})json");
	ASSERT_NE(explicit_permit, nullptr);
	ASSERT_EQ(explicit_permit->rules.size(), 1u);
	EXPECT_EQ(explicit_permit->rules[0].action, kinetum::modules::acl::acl_action::PERMIT);

	auto module_or = kinetum::test::exact_module_test_context::create(
		"kinetum.acl", KINETUM_ACL_MODULE_PATH, TEST_MODULE_RESOURCES, "acl_action_contract@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	const auto empty_status = module->prepare_and_activate(1, {});
	EXPECT_FALSE(empty_status.is_ok()) << "ACL must reject empty input before allocating an implicit policy";
	EXPECT_EQ(empty_status.code(), kinetum::common::status_code::MODULE_ERROR);
	EXPECT_EQ(empty_status.details(), std::to_string(KINETUM_ERR_INVALID_ARG));
}

/**
 * @brief Integration test: live module selects and runs simd_batch for >256 rules.
 *
 * Creates a 257-rule AclRuleset (>256 threshold), invokes one complete
 * 64-lane admitted-image callback, and runs a packet through the exact module
 * lifecycle (admit -> prepare -> activate -> process). The batch combines a
 * noncanonical CIDR with TCP/UDP-only port semantics so every compiled SIMD
 * implementation must agree with the scalar ACL contract.
 *
 * Rule setup:
 * - 255 filler deny rules for 1.0.0.x/32 (priority 10)
 * - 1 UDP deny rule for noncanonical dst 8.8.8.9/24 (priority 200)
 * - 1 ANY-plus-port deny rule for dst 9.9.9.9/32 (priority 190)
 * - Default: PERMIT
 * - Total: 257 rules -> simd_batch strategy
 *
 * Packet: 10.0.0.1 -> 8.8.8.8 -> DENIED by high-priority rule
 */
TEST(dp_acl, simd_batch_integration_large_ruleset)
{
	kinetum::dp::dp_engine eng;

	// Build test packet: 10.0.0.1:1234 -> 8.8.8.8:53 UDP
	auto bytes = build_eth_ipv4_udp(0x0a000001,  // src: 10.0.0.1
					0x08080808,  // dst: 8.8.8.8
					1234,	     // src_port
					53,	     // dst_port (DNS)
					0,	     // dscp
					{1, 2, 3}    // payload
	);
	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Parse stage
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// Build 257-rule ACL config (>256 triggers simd_batch strategy)
	kinetum::module::acl::v1::AclRuleset acl_config;
	acl_config.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	// 255 filler deny rules: dst 1.0.0.0/32 through 1.0.0.254/32 (low priority)
	for (int i = 0; i < 255; ++i) {
		auto *filler = acl_config.add_rules();
		filler->set_priority(10);
		filler->set_enabled(true);
		filler->set_src_cidr("0.0.0.0/0");
		filler->set_dst_cidr("1.0.0." + std::to_string(i) + "/32");
		filler->set_action(kinetum::module::acl::v1::ACL_ACTION_DENY);
	}

	// The SIMD path must mask the rule network just as scalar match_cidr does.
	auto *noncanonical_rule = acl_config.add_rules();
	noncanonical_rule->set_priority(200);
	noncanonical_rule->set_enabled(true);
	noncanonical_rule->set_src_cidr("0.0.0.0/0");
	noncanonical_rule->set_dst_cidr("8.8.8.9/24");
	noncanonical_rule->set_protocol(17);
	noncanonical_rule->set_action(kinetum::module::acl::v1::ACL_ACTION_DENY);

	// Port ranges are ignored for non-TCP/UDP packets by the scalar ACL law.
	auto *non_transport_rule = acl_config.add_rules();
	non_transport_rule->set_priority(190);
	non_transport_rule->set_enabled(true);
	non_transport_rule->set_src_cidr("0.0.0.0/0");
	non_transport_rule->set_dst_cidr("9.9.9.9/32");
	non_transport_rule->set_protocol(0);
	non_transport_rule->set_dst_port_min(80);
	non_transport_rule->set_dst_port_max(80);
	non_transport_rule->set_action(kinetum::module::acl::v1::ACL_ACTION_DENY);

	// Total: 257 rules -> strategy = simd_batch

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.acl", KINETUM_ACL_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "acl0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << "Module admission failed: " << module_or.error().message();
	auto module = std::move(module_or).value();
	const auto status = module->prepare_and_activate(1, kinetum::test::module_config_json(acl_config));
	ASSERT_TRUE(status.is_ok()) << "Module preparation failed: " << status.message();

	kinetum_batch_t full_batch{};
	full_batch.count = KINETUM_MAX_BURST;
	full_batch.epoch = module->active_epoch();
	full_batch.epoch_config = module->active_packet_config();
	full_batch.ctx = &module->context().packet_context;
	for (uint16_t index = 0u; index < full_batch.count; ++index) {
		full_batch.src_ip[index] = 0x0a000001u + index;
		if ((index & 1u) == 0u) {
			full_batch.dst_ip[index] = 0x08080801u + index;
			full_batch.proto[index] = kinetum::algo::net::protocol::UDP;
			full_batch.src_port[index] = static_cast<uint16_t>(1000u + index);
			full_batch.dst_port[index] = 53u;
		} else {
			full_batch.dst_ip[index] = 0x09090909u;
			full_batch.proto[index] = kinetum::algo::net::protocol::ICMP;
			full_batch.src_port[index] = 0u;
			full_batch.dst_port[index] = 0u;
		}
	}
	ASSERT_NE(module->descriptor().process, nullptr);
	EXPECT_EQ(module->descriptor().process(&full_batch), 0u)
		<< "Every vector lane must be denied under the scalar ACL rule contract";

	// Execute parse stage
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get())) << "Parse stage should succeed";

	// Execute ACL stage - SIMD batch path should DENY packet to 8.8.8.8
	EXPECT_FALSE(module->process(*packet.get()))
		<< "ACL simd_batch path should DENY packet to 8.8.8.8 (257 rules, high-priority deny)";
}
