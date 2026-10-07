// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dp_qos_policer.cpp
 * @brief QoS policer behavior and admission tests.
 * @author Fleming Patel
 *
 * The QoS policer implements per-flow rate limiting using a token bucket
 * algorithm. This is the mechanism behind Quality of Service enforcement
 * in the Edge Gateway pipeline.
 *
 * Token Bucket Algorithm:
 * -----------------------
 * - Each flow has a virtual bucket that fills at CIR (Committed Information Rate)
 * - Bucket has maximum capacity = burst_bytes
 * - Each packet consumes tokens equal to its size
 * - If insufficient tokens, packet is marked/dropped
 *
 * Fixed-Point Implementation:
 * ---------------------------
 * To avoid floating-point operations in the hot path, the policer uses
 * fixed-point arithmetic:
 * - Tokens are stored as signed 64-bit Q20 values.
 * - Refill uses exact unsigned 128-bit intermediate arithmetic.
 *
 * Owner-Local Design:
 * -------------------
 * Each executable context has owner-worker-local policer state. The packet
 * path takes no locks; the deployment routes each flow to one context owner.
 *
 * Wire-Format Testing:
 * --------------------
 * QoS module is read-only for packet buffer (only modifies DSCP for remarking).
 * Tests verify packet buffer integrity after processing.
 *
 * @see src/modules/qos/qos_impl.hpp
 */

#include <limits>
#include <memory_resource>

#include <gtest/gtest.h>

#include "src/modules/qos/qos_impl.hpp"
#include "src/dp/dp_engine.hpp"
#include "src/modules/qos/qos.pb.h"
#include "tests/module_config_test_helpers.hpp"
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_record_test_harness.hpp"
#include "tests/test_dp_helpers.hpp"

// KINETUM_QOS_MODULE_PATH is defined by CMake at compile time.
#ifndef KINETUM_QOS_MODULE_PATH
#error "KINETUM_QOS_MODULE_PATH must be defined by CMake"
#endif

/** @brief Explicit lifecycle-memory contract for each QoS module fixture. */
constexpr kinetum::test::module_test_resource_contract TEST_MODULE_RESOURCES{
	64u * 1024u * 1024u,
	2u * 1024u * 1024u,
};

//==============================================================================
// Token Bucket Tests
//==============================================================================

/**
 * @brief Verify token bucket correctly enforces rate limiting.
 *
 * Test Scenario:
 * - Profile: 1KB/s CIR, 1KB burst
 * - At t=0: bucket is full (1000 bytes)
 * - Send 500 + 500 bytes: should be allowed (consumes full bucket)
 * - Send 1 more byte: should be denied (bucket empty)
 * - Wait 1 second: bucket refills 1000 bytes
 * - Send 1000 bytes: should be allowed (full refill)
 * - Send 1 more byte: should be denied (bucket empty again)
 *
 * Time Units:
 * - Policer uses nanoseconds internally
 * - 1 second = 1,000,000,000 nanoseconds
 *
 * @note flow_hash is arbitrary for this test (single flow scenario)
 */
TEST(qos_policer, fixed_point_token_bucket)
{
	// Lock-free per-lcore policer (no shard count - each lcore has its own)
	kinetum::modules::qos::qos_policer p(kinetum::modules::qos::QOS_DEFAULT_MAX_FLOWS,
					     *std::pmr::get_default_resource());

	// Create rate-limiting profile
	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000;  // 1KB/s committed information rate
	prof.burst_bytes = 1000;      // 1KB burst (bucket capacity)
	kinetum::modules::qos::qos_runtime_tuning runtime;

	const uint64_t flow = 123;  // Arbitrary flow hash

	// At t=0, bucket full (burst), allow up to burst bytes
	uint64_t t0 = 1000000000ull;  // 1 second in nanoseconds

	// First 500 bytes: allowed
	EXPECT_TRUE(p.allow(t0, prof, runtime, flow, 500)) << "First 500 bytes should be allowed (bucket has 1000)";

	// Second 500 bytes: allowed (now bucket empty)
	EXPECT_TRUE(p.allow(t0, prof, runtime, flow, 500))
		<< "Second 500 bytes should be allowed (bucket had 500 remaining)";

	// One more byte: denied (bucket exhausted)
	EXPECT_FALSE(p.allow(t0, prof, runtime, flow, 1)) << "Bucket is empty, 1 byte should be denied";

	// A delayed packet cannot move the flow clock backward and manufacture a
	// larger refill interval for the next packet.
	EXPECT_FALSE(p.allow(t0 - 1000000000ull, prof, runtime, flow, 1));
	const uint64_t t_half = t0 + 500000000ull;
	EXPECT_FALSE(p.allow(t_half, prof, runtime, flow, 750))
		<< "Only 500 bytes may refill after the monotonic high-watermark";

	// After 1 second, refill 1000 bytes (CIR = 1000 bytes/s)
	uint64_t t1 = t0 + 1000000000ull;  // +1 second

	// 1000 bytes: allowed (full refill)
	EXPECT_TRUE(p.allow(t1, prof, runtime, flow, 1000)) << "After 1s, bucket should have 1000 bytes from refill";

	// One more byte: denied (bucket empty again)
	EXPECT_FALSE(p.allow(t1, prof, runtime, flow, 1)) << "Bucket exhausted again after consuming refill";

	// Existing flow state survives exact configuration activation, but credit
	// above the replacement profile's smaller burst must not. Without the
	// clamp, this flow would incorrectly retain 900 bytes of old-policy credit.
	const uint64_t reconfigured_flow = 456;
	ASSERT_TRUE(p.allow(t1, prof, runtime, reconfigured_flow, 100));
	kinetum::modules::qos::qos_profile_compiled smaller_burst(*std::pmr::get_default_resource());
	smaller_burst.name = prof.name;
	smaller_burst.cir_bytes_per_s = prof.cir_bytes_per_s;
	smaller_burst.conform_dscp = prof.conform_dscp;
	smaller_burst.burst_bytes = 100;
	EXPECT_FALSE(p.allow(t1, smaller_burst, runtime, reconfigured_flow, 101));
	EXPECT_TRUE(p.allow(t1, smaller_burst, runtime, reconfigured_flow, 100));

	// Maximal representable rate and elapsed time must saturate at the burst
	// ceiling without overflowing the wide refill intermediate.
	kinetum::modules::qos::qos_policer extreme_gap_policer(kinetum::modules::qos::QOS_DEFAULT_MAX_FLOWS,
							       *std::pmr::get_default_resource());
	kinetum::modules::qos::qos_profile_compiled extreme_rate(*std::pmr::get_default_resource());
	extreme_rate.name = prof.name;
	extreme_rate.burst_bytes = prof.burst_bytes;
	extreme_rate.conform_dscp = prof.conform_dscp;
	extreme_rate.cir_bytes_per_s = std::numeric_limits<uint64_t>::max();
	const uint64_t extreme_flow = 789;
	ASSERT_TRUE(extreme_gap_policer.allow(0, extreme_rate, runtime, extreme_flow, 1000));
	EXPECT_TRUE(extreme_gap_policer.allow(std::numeric_limits<uint64_t>::max(), extreme_rate, runtime, extreme_flow,
					      1000));
}

//==============================================================================
// Pre-Allocated Capacity Tests
//==============================================================================

/**
 * @brief Verify fail-closed behavior when flow table is exhausted.
 *
 * With max_flows=4, the fifth distinct flow must be dropped while the four
 * admitted flows remain owned. No unpoliced passthrough is permitted.
 */
TEST(qos_policer, capacity_exhaustion_drops_new_flows)
{
	// Small capacity to test boundary
	kinetum::modules::qos::qos_policer p(4, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	// Disable GC so flows are not evicted during this test
	runtime.gc_trigger_mask = ~0ull;

	const uint64_t t = 1000000000ull;

	// Fill all 4 slots with distinct flows
	for (uint64_t f = 1; f <= 4; ++f) {
		EXPECT_TRUE(p.allow(t, prof, runtime, f, 100))
			<< "Flow " << f << " must be allowed (capacity not yet full)";
	}

	EXPECT_EQ(p.active_flows(), 4u);

	// 5th flow must be dropped (fail-closed)
	EXPECT_FALSE(p.allow(t, prof, runtime, 5, 100)) << "5th flow must be dropped - table full, fail-closed";

	EXPECT_EQ(p.active_flows(), 4u);
}

/**
 * @brief Verify that existing flows still work after capacity is reached.
 *
 * When the table is full, packets for already-tracked flows must still
 * be processed normally. Only NEW flows are rejected.
 */
TEST(qos_policer, existing_flows_work_at_capacity)
{
	kinetum::modules::qos::qos_policer p(4, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	runtime.gc_trigger_mask = ~0ull;

	const uint64_t t = 1000000000ull;

	// Fill all 4 slots
	for (uint64_t f = 1; f <= 4; ++f) {
		EXPECT_TRUE(p.allow(t, prof, runtime, f, 100));
	}

	// Existing flow 1 at t+1s: tokens refilled, should allow
	const uint64_t t1 = t + 1000000000ull;
	EXPECT_TRUE(p.allow(t1, prof, runtime, 1, 100)) << "Existing flow must still be policed normally at capacity";
}

/**
 * @brief Verify flow slot reuse after GC reclaims expired flows.
 *
 * 1. Fill to capacity (4 flows)
 * 2. Advance time past idle timeout
 * 3. Trigger GC to reclaim expired slots
 * 4. New flow must now be accepted (reused slot from freelist)
 */
TEST(qos_policer, flow_reuse_after_gc)
{
	kinetum::modules::qos::qos_policer p(4, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	// Trigger GC every packet (mask=0 means every packet triggers)
	runtime.gc_trigger_mask = 0;
	runtime.gc_max_evictions = 256;
	runtime.idle_timeout_ns = 5000000000ull;  // 5s idle timeout

	const uint64_t t0 = 1000000000ull;

	// Fill all 4 slots
	for (uint64_t f = 1; f <= 4; ++f) {
		EXPECT_TRUE(p.allow(t0, prof, runtime, f, 100));
	}
	EXPECT_EQ(p.active_flows(), 4u);

	// 5th flow rejected at capacity
	EXPECT_FALSE(p.allow(t0, prof, runtime, 5, 100));

	// Advance time past idle timeout (t0 + 6s > 5s timeout)
	const uint64_t t1 = t0 + 6000000000ull;

	// An unlimited replacement still drives retirement of stale bounded-policy
	// state without allocating a bucket for the unlimited flow.
	kinetum::modules::qos::qos_profile_compiled unlimited(*std::pmr::get_default_resource());
	unlimited.name = "unlimited";
	unlimited.cir_bytes_per_s = 0u;
	unlimited.burst_bytes = 0u;
	EXPECT_TRUE(p.allow(t1, unlimited, runtime, 99, 100));
	EXPECT_EQ(p.active_flows(), 0u);

	// Returning to a bounded profile can consume one reclaimed slot.
	EXPECT_TRUE(p.allow(t1, prof, runtime, 99, 100));
	EXPECT_EQ(p.active_flows(), 1u);
}

/**
 * @brief Verify repeated capacity rejection preserves all admitted flow state.
 *
 * Rejected new flows must not displace an admitted flow or change occupancy.
 */
TEST(qos_policer, repeated_capacity_rejection_preserves_admitted_flows)
{
	kinetum::modules::qos::qos_policer p(2, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	runtime.gc_trigger_mask = ~0ull;

	const uint64_t t = 1000000000ull;

	// Fill both slots
	EXPECT_TRUE(p.allow(t, prof, runtime, 1, 100));
	EXPECT_TRUE(p.allow(t, prof, runtime, 2, 100));

	// 3 rejected attempts
	EXPECT_FALSE(p.allow(t, prof, runtime, 10, 100));
	EXPECT_FALSE(p.allow(t, prof, runtime, 11, 100));
	EXPECT_FALSE(p.allow(t, prof, runtime, 12, 100));

	EXPECT_EQ(p.active_flows(), 2u);
	EXPECT_TRUE(p.allow(t + 1'000'000'000ull, prof, runtime, 1, 100));
	EXPECT_TRUE(p.allow(t + 1'000'000'000ull, prof, runtime, 2, 100));
}

/**
 * @brief Verify zero-capacity policer is safe (no crash, fail-closed).
 *
 * qos_policer(0) creates an empty slab. All packets must be dropped
 * fail-closed, and GC must not access an absent slab entry.
 */
TEST(qos_policer, zero_capacity_is_safe)
{
	kinetum::modules::qos::qos_policer p(0, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	// Trigger GC every packet to exercise the GC guard path
	runtime.gc_trigger_mask = 0;

	const uint64_t t = 1000000000ull;

	// All packets must be dropped (no slab capacity)
	EXPECT_FALSE(p.allow(t, prof, runtime, 1, 100)) << "Zero-capacity policer must drop all packets (fail-closed)";
	EXPECT_FALSE(p.allow(t, prof, runtime, 2, 100)) << "Zero-capacity policer must drop all packets (fail-closed)";

	EXPECT_EQ(p.active_flows(), 0u);
}

//==============================================================================
// QoS Module Wire-Format Verification Tests
//==============================================================================

/**
 * @brief Verify QoS module does not corrupt packet buffer on PERMIT.
 *
 * This catches offset defects in the otherwise read-only path and in optional
 * DSCP remarking.
 *
 * Test verifies:
 * 1. Ethernet header is NOT corrupted after QoS permit
 * 2. IP src/dst addresses are unchanged
 * 3. UDP ports are unchanged
 * 4. IP checksum is valid (may be updated for DSCP change)
 */
TEST(qos_policer, wire_format_permit_unchanged)
{
	kinetum::dp::dp_engine eng;

	// Build test packet with high burst profile (will permit)
	auto bytes = build_eth_ipv4_udp(0xC0A80101,  // src: 192.168.1.1
					0xC0A80201,  // dst: 192.168.2.1
					12345,	     // src_port
					8080,	     // dst_port
					0,	     // dscp (will use default)
					{0x01, 0x02, 0x03, 0x04});

	// Save original Ethernet header before processing
	uint8_t orig_eth[14];
	save_ethernet_header(bytes.data(), orig_eth);

	// Verify original packet structure
	auto pre_verify = verify_wire_format(bytes.data(), bytes.size(), 0xC0A80101, 0xC0A80201, 12345, 8080);
	ASSERT_TRUE(pre_verify.ok) << "Pre-QoS: " << pre_verify.failure_reason;

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Setup pipeline
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// QoS config: high-rate profile (will permit small packets)
	kinetum::module::qos::v1::QosProfiles qos_config;
	qos_config.set_default_profile("default");

	auto *profile = qos_config.add_profiles();
	profile->set_name("default");
	profile->set_cir_kbps(1000000);	 // 1 Gbps (very high, will permit)
	profile->set_cbs_kb(1024);	 // 1MB burst

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "qos0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, kinetum::test::module_config_json(qos_config)).is_ok());

	// Execute parse and QoS
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get()));
	ASSERT_TRUE(module->process(*packet.get())) << "QoS should PERMIT packet with high-rate profile";

	// Verify that QoS changed no packet field outside its declared DSCP byte.

	const uint8_t *pkt_data = packet.data();
	const std::size_t pkt_len = packet.size();

	// 1. Ethernet header must be unchanged
	EXPECT_TRUE(compare_ethernet_headers(pkt_data, orig_eth)) << "Ethernet header corrupted during QoS processing";

	EXPECT_TRUE(verify_ethernet_intact(pkt_data, pkt_len)) << "Ethernet header integrity check failed";

	// 2. IP src/dst and UDP ports should be unchanged (QoS only touches DSCP)
	const uint8_t *ip_hdr = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t *udp_hdr = pkt_data + wire_offsets::UDP_HDR_START;

	uint32_t wire_src_ip = kinetum::algo::net::read_be32(ip_hdr + 12);
	uint32_t wire_dst_ip = kinetum::algo::net::read_be32(ip_hdr + 16);
	uint16_t wire_src_port = kinetum::algo::net::read_be16(udp_hdr + 0);
	uint16_t wire_dst_port = kinetum::algo::net::read_be16(udp_hdr + 2);

	EXPECT_EQ(wire_src_ip, 0xC0A80101u) << "QoS should not modify src_ip";
	EXPECT_EQ(wire_dst_ip, 0xC0A80201u) << "QoS should not modify dst_ip";
	EXPECT_EQ(wire_src_port, 12345) << "QoS should not modify src_port";
	EXPECT_EQ(wire_dst_port, 8080) << "QoS should not modify dst_port";

	// 3. Verify IP checksum is valid
	uint16_t wire_cksum = kinetum::algo::net::read_be16(ip_hdr + 10);
	uint16_t computed_cksum = compute_ipv4_checksum(ip_hdr, 20);
	EXPECT_EQ(wire_cksum, computed_cksum) << "IP header checksum invalid after QoS";

	// 4. Verify metadata-wire consistency
	const auto &metadata = packet.metadata();
	auto consistency = verify_metadata_wire_consistency(pkt_data, pkt_len, metadata.src_ipv4, metadata.dst_ipv4,
							    metadata.src_port, metadata.dst_port);
	EXPECT_TRUE(consistency.ok) << consistency.failure_reason;
}

// =============================================================================
// QoS DSCP Remarking (conform_dscp)
// =============================================================================

/**
 * @brief Verify DSCP remark validates bytes before policing and updates wire truth.
 */
TEST(qos_policer, conform_dscp_remark_writes_on_wire)
{
	// Configure QoS with conform_dscp=10 - every conforming packet
	// should have its on-wire DSCP set to 10 and checksum recomputed.
	kinetum::dp::dp_engine eng;

	auto bytes = build_eth_ipv4_udp(0xC0A80101,  // src: 192.168.1.1
					0xC0A80201,  // dst: 192.168.2.1
					12345,	     // src_port
					8080,	     // dst_port
					0,	     // dscp=0 (will be remarked to 10)
					{0x01, 0x02, 0x03, 0x04});

	// Record original DSCP (should be 0)
	const uint8_t orig_dscp = bytes[wire_offsets::IP_HDR_START + 1] >> 2;
	ASSERT_EQ(orig_dscp, 0) << "Test packet should start with DSCP=0";

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Parse stage
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	kinetum::module::qos::v1::QosProfiles qos_config;
	qos_config.set_default_profile("default");

	auto *profile = qos_config.add_profiles();
	profile->set_name("default");
	profile->set_cir_kbps(1000000);	 // 1 Gbps (will permit)
	profile->set_cbs_kb(1);
	profile->set_conform_dscp(10);	// Remark conforming packets to DSCP=10

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "qos_dscp@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, kinetum::test::module_config_json(qos_config)).is_ok());

	// Malformed same-flow packets must not consume tokens or allocate flow state
	// before the remarking precondition rejects them.
	for (std::size_t attempt = 0u; attempt < 32u; ++attempt) {
		kinetum::test::packet_record_test_owner malformed(bytes);
		ASSERT_TRUE(malformed.valid()) << malformed.error();
		ASSERT_TRUE(eng.execute_stage(&parse, malformed.get()));
		malformed.get()->storage.data[wire_offsets::IP_HDR_START] = 0x65u;
		EXPECT_FALSE(module->process(*malformed.get()));
	}

	// Execute
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get()));
	ASSERT_TRUE(module->process(*packet.get())) << "QoS should PERMIT packet";

	// Verify on-wire DSCP was remarked
	const uint8_t *pkt_data = packet.data();
	const uint8_t *ip_hdr = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t wire_dscp = ip_hdr[1] >> 2;
	const uint8_t wire_ecn = ip_hdr[1] & 0x03;

	EXPECT_EQ(wire_dscp, 10) << "On-wire DSCP should be remarked to 10";
	EXPECT_EQ(wire_ecn, 0) << "ECN bits should be preserved (was 0)";

	// Verify IP checksum is still valid after remark
	uint16_t wire_cksum = kinetum::algo::net::read_be16(ip_hdr + 10);
	uint16_t computed_cksum = compute_ipv4_checksum(ip_hdr, 20);
	EXPECT_EQ(wire_cksum, computed_cksum) << "IP header checksum must be valid after DSCP remark";

	// Verify IP src/dst and UDP ports are untouched
	uint32_t wire_src_ip = kinetum::algo::net::read_be32(ip_hdr + 12);
	uint32_t wire_dst_ip = kinetum::algo::net::read_be32(ip_hdr + 16);
	EXPECT_EQ(wire_src_ip, 0xC0A80101u) << "DSCP remark should not modify src_ip";
	EXPECT_EQ(wire_dst_ip, 0xC0A80201u) << "DSCP remark should not modify dst_ip";
}

/**
 * @brief Verify empty config is rejected by exact module preparation.
 */
TEST(qos_policer, empty_config_rejected_by_module_prepare)
{
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "qos_empty@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();

	const auto status = module->prepare_and_activate(1, {});
	EXPECT_FALSE(status.is_ok()) << "QoS must reject empty config instead of installing an implicit fallback";
}
