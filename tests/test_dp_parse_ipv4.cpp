// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dp_parse_ipv4.cpp
 * @brief IPv4 packet-parser behavior and admission tests.
 * @author Fleming Patel
 *
 * The PARSE_IPV4 stage is the foundation of the Edge Gateway pipeline.
 * It extracts L3/L4 metadata from raw packet bytes into the packet_record
 * metadata authority, enabling downstream stages (ACL, NAT, QoS) to
 * make policy decisions.
 *
 * Parsed Fields:
 * --------------
 * - L3: src_ipv4, dst_ipv4, dscp (TOS >> 2), fragment presence
 * - L4: l4_proto (TCP=6, UDP=17), src_port, dst_port
 * - Flow: flow_hash (5-tuple symmetric hash for load balancing)
 *
 * Header Format Support:
 * ----------------------
 * - Ethernet II (14 bytes) with up to two 802.1Q/802.1ad VLAN tags
 * - IPv4 with variable IHL (20-60 bytes)
 * - Available TCP or UDP source/destination port prefix
 *
 * Hot Path Optimization:
 * ----------------------
 * This is the first stage after RX - every packet goes through it.
 * Implementation uses:
 * - Prefetch hints for header access
 * - Branch prediction hints (KINETUM_LIKELY for common case)
 * - Zero-copy parsing (just pointer arithmetic)
 *
 * @see src/dp/dp_engine.cpp (execute_stage for STAGE_KIND_PARSE_IPV4)
 * @see tests/test_dp_helpers.hpp (packet construction utilities)
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "src/common/pbtxt.hpp"
#include "src/dp/dp_engine.hpp"
#include "src/dp/net/ipv4.hpp"
#include "tests/test_dp_helpers.hpp"
#include "tests/packet_record_test_harness.hpp"

//==============================================================================
// IPv4 Parser Tests
//==============================================================================

/**
 * @brief Verify parser correctly extracts UDP packet metadata.
 *
 * Test Packet:
 * - Src: 10.0.0.1:1234
 * - Dst: 8.8.8.8:53 (DNS)
 * - DSCP: 10 (AF11, low drop precedence in forwarding class 1)
 * - Protocol: UDP (17)
 * - Payload: 0xDEADBEEF (4 bytes)
 *
 * Expected Results:
 * - l3_ipv4 = true (IPv4 packet)
 * - src_ipv4 = 0x0a000001 (10.0.0.1 in network byte order)
 * - dst_ipv4 = 0x08080808 (8.8.8.8)
 * - src_port = 1234
 * - dst_port = 53
 * - dscp = 10
 * - l4_proto = 17 (UDP)
 * - is_fragment = false (DF bit set, MF=0, offset=0)
 * - flow_hash > 0 (5-tuple hash computed)
 *
 * @note Uses build_eth_ipv4_udp() helper from test_dp_helpers.hpp
 */
TEST(dp_parse_ipv4, parses_basic_udp)
{
	kinetum::dp::dp_engine eng;

	// Build test packet: 10.0.0.1:1234 -> 8.8.8.8:53, DSCP=10, payload=0xDEADBEEF
	auto bytes = build_eth_ipv4_udp(0x0a000001,		  // src_ip: 10.0.0.1
					0x08080808,		  // dst_ip: 8.8.8.8
					1234,			  // src_port
					53,			  // dst_port (DNS)
					10,			  // dscp (AF11)
					{0xde, 0xad, 0xbe, 0xef}  // payload
	);

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Create PARSE_IPV4 stage configuration
	kinetum::axiom::v1::Stage st;
	st.set_stage_id("p0");
	st.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// Execute parser
	ASSERT_TRUE(eng.execute_stage(&st, packet.get())) << "Parser should succeed for valid IPv4/UDP packet";
	const auto &metadata = packet.metadata();

	// Verify L3 metadata
	EXPECT_NE(metadata.platform_flags & kinetum::dp::packet_platform_flags::L3_IPV4, 0u) << "IPv4 flag must be set";
	EXPECT_EQ(metadata.src_ipv4, 0x0a000001u) << "src_ipv4 should be 10.0.0.1 (0x0a000001)";
	EXPECT_EQ(metadata.dst_ipv4, 0x08080808u) << "dst_ipv4 should be 8.8.8.8 (0x08080808)";
	EXPECT_EQ(metadata.dscp, 10) << "dscp should be 10 (AF11)";

	// Verify L4 metadata
	EXPECT_EQ(metadata.l4_proto, 17) << "l4_proto should be 17 (UDP)";
	EXPECT_EQ(metadata.src_port, 1234) << "src_port should be 1234";
	EXPECT_EQ(metadata.dst_port, 53) << "dst_port should be 53 (DNS)";

	// Verify fragment detection
	EXPECT_EQ(metadata.platform_flags & kinetum::dp::packet_platform_flags::FRAGMENT, 0u)
		<< "Non-fragmented packet must not carry the fragment flag";

	// Verify flow hash computation
	EXPECT_GT(metadata.flow_hash, 0u) << "flow_hash should be computed (non-zero for valid 5-tuple)";
}

/**
 * @brief Reject an IPv4 total length that extends beyond the packet record.
 */
TEST(dp_parse_ipv4, rejects_truncated_declared_ipv4_extent)
{
	kinetum::dp::dp_engine engine;
	auto bytes = build_eth_ipv4_udp(0x0a000001, 0x08080808, 1234, 53, 0, {0xde, 0xad, 0xbe, 0xef});
	ASSERT_GT(bytes.size(), wire_offsets::ETH_HDR_LEN + wire_offsets::IP_HDR_LEN_MIN);
	bytes.pop_back();

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	kinetum::axiom::v1::Stage stage;
	stage.set_stage_id("parse");
	stage.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	EXPECT_FALSE(engine.execute_stage(&stage, packet.get()));
	EXPECT_EQ(packet.metadata().platform_flags & kinetum::dp::packet_platform_flags::L3_IPV4, 0u);
}

/**
 * @brief Do not derive transport ports from bytes outside the IPv4 total length.
 */
TEST(dp_parse_ipv4, does_not_read_transport_ports_beyond_declared_ipv4_extent)
{
	kinetum::dp::dp_engine engine;
	auto bytes = build_eth_ipv4_udp(0x0a000001, 0x08080808, 1234, 53, 0, {0xde, 0xad, 0xbe, 0xef});
	kinetum::algo::net::write_be16(bytes.data() + wire_offsets::ETH_HDR_LEN + 2,
				       static_cast<uint16_t>(wire_offsets::IP_HDR_LEN_MIN));

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	kinetum::axiom::v1::Stage stage;
	stage.set_stage_id("parse");
	stage.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	ASSERT_TRUE(engine.execute_stage(&stage, packet.get()));
	EXPECT_EQ(packet.metadata().l4_proto, kinetum::algo::net::protocol::UDP);
	EXPECT_EQ(packet.metadata().src_port, 0u);
	EXPECT_EQ(packet.metadata().dst_port, 0u);
}

/**
 * @brief Reject an IPv4 header whose derived L4 offset cannot fit metadata.
 */
TEST(dp_parse_ipv4, rejects_unrepresentable_l4_offset)
{
	constexpr uint16_t IP_OFFSET = std::numeric_limits<uint16_t>::max() - 5;
	std::vector<uint8_t> bytes(static_cast<std::size_t>(IP_OFFSET) + wire_offsets::IP_HDR_LEN_MIN, 0);
	bytes[IP_OFFSET] = 0x45;
	kinetum::algo::net::write_be16(bytes.data() + IP_OFFSET + 2,
				       static_cast<uint16_t>(wire_offsets::IP_HDR_LEN_MIN));

	const auto result = kinetum::dp::net::parse_ipv4(bytes.data(), bytes.size(), IP_OFFSET);
	EXPECT_FALSE(result.ok);
}

/**
 * @brief Admit one and two VLAN tags while rejecting deeper nesting.
 */
TEST(dp_parse_ipv4, ethernet_vlan_depth_is_bounded_and_exact)
{
	const auto tagged_frame = [](std::size_t depth) {
		std::vector<uint8_t> bytes(wire_offsets::ETH_HDR_LEN + depth * 4, 0);
		kinetum::algo::net::write_be16(bytes.data() + 12, kinetum::dp::net::ethertype::VLAN);
		for (std::size_t index = 0; index < depth; ++index) {
			const uint16_t next = index + 1 == depth ? kinetum::dp::net::ethertype::IPV4 :
								   kinetum::dp::net::ethertype::VLAN;
			kinetum::algo::net::write_be16(bytes.data() + 16 + index * 4, next);
		}
		return bytes;
	};

	constexpr std::array<std::size_t, 2> ADMITTED_DEPTHS{1, 2};
	for (std::size_t depth : ADMITTED_DEPTHS) {
		const auto bytes = tagged_frame(depth);
		const auto result = kinetum::dp::net::parse_ethernet(bytes.data(), bytes.size());
		ASSERT_TRUE(result.ok);
		EXPECT_EQ(result.eth_type, kinetum::dp::net::ethertype::IPV4);
		EXPECT_EQ(result.vlan_depth, depth);
		EXPECT_EQ(result.l3_offset, wire_offsets::ETH_HDR_LEN + depth * 4);
	}

	const auto over_depth = tagged_frame(3);
	EXPECT_FALSE(kinetum::dp::net::parse_ethernet(over_depth.data(), over_depth.size()).ok);
}

//==============================================================================
// Parser Wire-Format Verification Tests
//==============================================================================

/**
 * @brief Verify parser extracts metadata from correct packet buffer offsets.
 *
 * This catches disagreement between link-layer-derived protocol offsets and
 * the bounded wire bytes consumed by the parser. An incorrect L3 offset could
 * otherwise interpret Ethernet bytes as IPv4.
 *
 * Test verifies:
 * 1. Parsed src_ip matches wire-format bytes at offset 14+12
 * 2. Parsed dst_ip matches wire-format bytes at offset 14+16
 * 3. Parsed ports match wire-format bytes at offset 34+0 and 34+2
 * 4. Metadata-wire consistency is maintained
 */
TEST(dp_parse_ipv4, wire_format_metadata_consistency)
{
	kinetum::dp::dp_engine eng;

	// Use distinctive IP addresses that are easy to verify in hex
	// 172.30.55.199 = 0xAC1E37C7
	// 203.0.113.100 = 0xCB007164
	auto bytes = build_eth_ipv4_udp(0xAC1E37C7,  // src: 172.30.55.199
					0xCB007164,  // dst: 203.0.113.100
					31337,	     // src_port (distinctive)
					65535,	     // dst_port (max port)
					42,	     // dscp
					{0xCA, 0xFE, 0xBA, 0xBE});

	// Verify wire format before parsing
	auto pre_verify = verify_wire_format(bytes.data(), bytes.size(), 0xAC1E37C7, 0xCB007164, 31337, 65535);
	ASSERT_TRUE(pre_verify.ok) << "Pre-parse: " << pre_verify.failure_reason;

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	kinetum::axiom::v1::Stage st;
	st.set_stage_id("p0");
	st.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	ASSERT_TRUE(eng.execute_stage(&st, packet.get()));

	// Verify metadata against an independent read of the packet bytes.

	const uint8_t *pkt_data = packet.data();
	const std::size_t pkt_len = packet.size();
	const auto &metadata = packet.metadata();

	// Read wire-format values directly from packet buffer
	const uint8_t *ip_hdr = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t *udp_hdr = pkt_data + wire_offsets::UDP_HDR_START;

	uint32_t wire_src_ip = kinetum::algo::net::read_be32(ip_hdr + 12);
	uint32_t wire_dst_ip = kinetum::algo::net::read_be32(ip_hdr + 16);
	uint16_t wire_src_port = kinetum::algo::net::read_be16(udp_hdr + 0);
	uint16_t wire_dst_port = kinetum::algo::net::read_be16(udp_hdr + 2);

	// Verify parser extracted correct values (from correct offsets)
	EXPECT_EQ(metadata.src_ipv4, wire_src_ip) << "Parser must extract src_ip from correct offset (14+12)";
	EXPECT_EQ(metadata.dst_ipv4, wire_dst_ip) << "Parser must extract dst_ip from correct offset (14+16)";
	EXPECT_EQ(metadata.src_port, wire_src_port) << "Parser must extract src_port from correct offset (34+0)";
	EXPECT_EQ(metadata.dst_port, wire_dst_port) << "Parser must extract dst_port from correct offset (34+2)";

	// Check the complete parsed/wire consistency relation.
	auto consistency = verify_metadata_wire_consistency(pkt_data, pkt_len, metadata.src_ipv4, metadata.dst_ipv4,
							    metadata.src_port, metadata.dst_port);
	EXPECT_TRUE(consistency.ok) << consistency.failure_reason;

	// Verify Ethernet header not corrupted by parser (should be read-only)
	EXPECT_TRUE(verify_ethernet_intact(pkt_data, pkt_len)) << "Parser should not corrupt Ethernet header";
}

/**
 * @brief Verify parser does not modify packet buffer (read-only operation).
 *
 * The parser stage is purely read-only - it extracts metadata but should
 * never write to the packet buffer. This test verifies that property.
 */
TEST(dp_parse_ipv4, wire_format_buffer_unchanged)
{
	kinetum::dp::dp_engine eng;

	auto bytes = build_eth_ipv4_udp(0x0a0b0c0d,  // 10.11.12.13
					0xc0a80001,  // 192.168.0.1
					8888, 9999, 20, {0x11, 0x22, 0x33, 0x44, 0x55});

	// Save complete original packet for comparison
	std::vector<uint8_t> original_bytes = bytes;

	// Save Ethernet header specifically
	uint8_t orig_eth[14];
	save_ethernet_header(bytes.data(), orig_eth);

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	kinetum::axiom::v1::Stage st;
	st.set_stage_id("p0");
	st.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	ASSERT_TRUE(eng.execute_stage(&st, packet.get()));

	// Verify entire packet buffer is unchanged
	const uint8_t *pkt_data = packet.data();
	const std::size_t pkt_len = packet.size();

	EXPECT_EQ(pkt_len, original_bytes.size()) << "Parser should not change packet length";

	for (std::size_t i = 0; i < pkt_len; ++i) {
		EXPECT_EQ(pkt_data[i], original_bytes[i]) << "Parser modified byte at offset " << i;
	}

	// Explicit Ethernet header check
	EXPECT_TRUE(compare_ethernet_headers(pkt_data, orig_eth)) << "Parser corrupted Ethernet header";
}

/**
 * @brief Verify parser correctly extracts DSCP from TOS byte.
 *
 * DSCP is stored in bits [7:2] of the TOS/DSCP+ECN byte (offset 14+1).
 * This test verifies the parser reads from the correct offset and shifts
 * correctly.
 */
TEST(dp_parse_ipv4, wire_format_dscp_extraction)
{
	kinetum::dp::dp_engine eng;

	// Test multiple DSCP values
	std::vector<uint8_t> dscp_values = {0, 10, 26, 34, 46, 63};

	for (uint8_t dscp : dscp_values) {
		auto bytes = build_eth_ipv4_udp(0x0a000001, 0x0a000002, 1000, 2000, dscp, {0x01});

		kinetum::test::packet_record_test_owner packet(bytes);
		ASSERT_TRUE(packet.valid()) << packet.error();

		kinetum::axiom::v1::Stage st;
		st.set_stage_id("p0");
		st.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

		ASSERT_TRUE(eng.execute_stage(&st, packet.get()));

		// Verify DSCP extracted correctly
		EXPECT_EQ(packet.metadata().dscp, dscp)
			<< "Parser should extract DSCP=" << static_cast<int>(dscp) << " from wire format";

		// Verify wire format has correct TOS byte (DSCP << 2)
		const uint8_t *ip_hdr = packet.data() + wire_offsets::IP_HDR_START;
		uint8_t wire_tos = ip_hdr[1];
		EXPECT_EQ(wire_tos, static_cast<uint8_t>(dscp << 2)) << "Wire TOS byte should be DSCP<<2";
	}
}
