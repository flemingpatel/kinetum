// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file test_dp_helpers.hpp
 * @brief Helper utilities for dataplane unit tests.
 * @author Fleming Patel
 *
 * Provides functions to construct test packets with valid headers for
 * use in unit tests of parsing, ACL, NAT, QoS, and other dataplane stages.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <kinetum/algo/net.hpp>

/**
 * @brief Accumulate network-order words for the independent test checksum oracle.
 * @param bytes Non-null byte sequence when @p length is nonzero.
 * @param length At most 65,535 bytes, including an optional odd trailing byte.
 * @return Unfolded one's-complement sum.
 */
inline uint64_t test_internet_checksum_sum(const uint8_t *bytes, std::size_t length) noexcept
{
	uint64_t sum = 0u;
	std::size_t offset = 0u;
	for (; offset + 1u < length; offset += 2u) {
		sum += (static_cast<uint64_t>(bytes[offset]) << 8u) | static_cast<uint64_t>(bytes[offset + 1u]);
	}
	if (offset < length) {
		sum += static_cast<uint64_t>(bytes[offset]) << 8u;
	}
	return sum;
}

/**
 * @brief Fold and complement one independent test checksum sum.
 * @param sum Unfolded one's-complement word sum.
 * @return Network checksum value in host integer representation.
 */
inline uint16_t finish_test_internet_checksum(uint64_t sum) noexcept
{
	while ((sum >> 16u) != 0u) {
		sum = (sum & UINT64_C(0xffff)) + (sum >> 16u);
	}
	return static_cast<uint16_t>(~sum & UINT64_C(0xffff));
}

/**
 * @brief Compute an IPv4 header checksum without using production checksum code.
 * @param ip_hdr Non-null complete IPv4 header.
 * @param ihl_bytes Even header length of at least 20 bytes.
 * @return Checksum with header bytes 10 and 11 treated as zero.
 */
inline uint16_t compute_ipv4_checksum(const uint8_t *ip_hdr, uint16_t ihl_bytes) noexcept
{
	uint64_t sum = 0u;
	for (std::size_t offset = 0u; offset < ihl_bytes; offset += 2u) {
		if (offset == 10u) {
			continue;
		}
		sum += (static_cast<uint64_t>(ip_hdr[offset]) << 8u) | static_cast<uint64_t>(ip_hdr[offset + 1u]);
	}
	return finish_test_internet_checksum(sum);
}

/** Complete typed input for the independent transport-checksum oracle. */
struct test_ipv4_l4_checksum_input {
	uint8_t ip_protocol{0};		      ///< Exact IPv4 transport protocol number.
	const uint8_t *ipv4_header{nullptr};  ///< Header containing source and destination addresses.
	const uint8_t *l4_segment{nullptr};   ///< Segment whose checksum field is already zero.
	std::size_t l4_length{0};	      ///< Representable transport segment byte count.
};

/**
 * @brief Compute an IPv4 TCP/UDP checksum with an independent pseudo-header oracle.
 * @param input Complete typed checksum input with non-null byte extents.
 * @return Complete pseudo-header and transport checksum.
 */
inline uint16_t compute_ipv4_l4_checksum(const test_ipv4_l4_checksum_input &input) noexcept
{
	uint64_t sum = test_internet_checksum_sum(input.ipv4_header + 12u, 8u);
	sum += static_cast<uint64_t>(input.ip_protocol);
	sum += static_cast<uint64_t>(input.l4_length);
	sum += test_internet_checksum_sum(input.l4_segment, input.l4_length);
	return finish_test_internet_checksum(sum);
}

/**
 * @brief Build a minimal Ethernet + IPv4 + UDP packet for unit tests.
 *
 * Constructs a valid packet with:
 * - Ethernet header (dst=11:11:11:11:11:11, src=22:22:22:22:22:22, EtherType=0x0800)
 * - IPv4 header (IHL=5, TTL=64, protocol=UDP)
 * - UDP header with optional payload
 *
 * @param src_ip Source IP in host byte order (e.g., 0x0a000001 for 10.0.0.1)
 * @param dst_ip Destination IP in host byte order
 * @param src_port Source UDP port in host byte order
 * @param dst_port Destination UDP port in host byte order
 * @param dscp DSCP value (6 bits, will be shifted into TOS field)
 * @param payload UDP payload bytes
 * @param udp_checksum_be UDP checksum in big-endian (0 = no checksum)
 * @return Complete packet as byte vector
 */
inline std::vector<uint8_t> build_eth_ipv4_udp(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
					       uint8_t dscp, const std::vector<uint8_t> &payload,
					       uint16_t udp_checksum_be = 0)
{
	const std::size_t eth_len = 14;
	const std::size_t ip_len = 20;
	const std::size_t udp_len = 8;

	// Validate inputs to prevent overflow and invalid packets
	if (dscp > 63) {
		// DSCP is 6 bits, values 0-63 are valid
		return {};
	}

	// Validate total packet size doesn't overflow uint16_t
	constexpr std::size_t max_ipv4_total_len = 65535;
	const std::size_t total_payload_len = ip_len + udp_len + payload.size();
	if (total_payload_len > max_ipv4_total_len) {
		// IPv4 total length field is 16-bit, cannot exceed 65535
		return {};
	}

	const uint16_t total_len = static_cast<uint16_t>(total_payload_len);

	std::vector<uint8_t> pkt;
	pkt.resize(eth_len + total_len);

	// Ethernet
	for (std::size_t i = 0; i < 6; ++i)
		pkt[i] = 0x11;
	for (std::size_t i = 0; i < 6; ++i)
		pkt[6 + i] = 0x22;
	kinetum::algo::net::write_be16(pkt.data() + 12, 0x0800);

	uint8_t *ip = pkt.data() + eth_len;
	ip[0] = 0x45;					   // v4, ihl=5
	ip[1] = static_cast<uint8_t>((dscp & 0x3f) << 2);  // DSCP <<2, ECN=0
	kinetum::algo::net::write_be16(ip + 2, total_len);
	kinetum::algo::net::write_be16(ip + 4, 0);   // id
	kinetum::algo::net::write_be16(ip + 6, 0);   // flags/frag
	ip[8] = 64;				     // ttl
	ip[9] = 17;				     // UDP
	kinetum::algo::net::write_be16(ip + 10, 0);  // checksum placeholder
	kinetum::algo::net::write_be32(ip + 12, src_ip);
	kinetum::algo::net::write_be32(ip + 16, dst_ip);

	kinetum::algo::net::write_be16(ip + 10u, compute_ipv4_checksum(ip, static_cast<uint16_t>(ip_len)));

	uint8_t *udp = pkt.data() + eth_len + ip_len;
	kinetum::algo::net::write_be16(udp + 0, src_port);
	kinetum::algo::net::write_be16(udp + 2, dst_port);
	kinetum::algo::net::write_be16(udp + 4, static_cast<uint16_t>(udp_len + payload.size()));
	kinetum::algo::net::write_be16(udp + 6, udp_checksum_be);

	if (!payload.empty()) {
		std::memcpy(pkt.data() + eth_len + ip_len + udp_len, payload.data(), payload.size());
	}
	return pkt;
}

//==============================================================================
// Wire-Format Verification Helpers
//==============================================================================
//
// These functions inspect packet-buffer bytes independently from parsed
// metadata, exposing disagreement in offsets or module byte mutation.
//==============================================================================

/**
 * @brief Standard Ethernet header offsets.
 *
 * Wire format layout for standard Ethernet + IPv4 + UDP:
 *   [0-5]    Destination MAC (6 bytes)
 *   [6-11]   Source MAC (6 bytes)
 *   [12-13]  EtherType (2 bytes, 0x0800 for IPv4)
 *   [14-33]  IPv4 header (20 bytes minimum)
 *   [34-41]  UDP header (8 bytes)
 *   [42+]    Payload
 */
namespace wire_offsets
{
constexpr std::size_t ETH_DST_MAC = 0;	 ///< Destination Ethernet address.
constexpr std::size_t ETH_SRC_MAC = 6;	 ///< Source Ethernet address.
constexpr std::size_t ETH_TYPE = 12;	 ///< Ethernet type field.
constexpr std::size_t ETH_HDR_LEN = 14;	 ///< Untagged Ethernet header length.

constexpr std::size_t IP_HDR_START = 14;    ///< IPv4 header start.
constexpr std::size_t IP_VER_IHL = 14;	    ///< IPv4 version and IHL byte.
constexpr std::size_t IP_TOS_DSCP = 15;	    ///< IPv4 DSCP and ECN byte.
constexpr std::size_t IP_TOTAL_LEN = 16;    ///< IPv4 total-length field.
constexpr std::size_t IP_CKSUM_OFF = 24;    ///< IPv4 checksum field.
constexpr std::size_t IP_SRC = 26;	    ///< IPv4 source-address field.
constexpr std::size_t IP_DST = 30;	    ///< IPv4 destination-address field.
constexpr std::size_t IP_HDR_LEN_MIN = 20;  ///< Minimum IPv4 header length.

constexpr std::size_t UDP_HDR_START = 34;  ///< UDP header start after minimum IPv4.
constexpr std::size_t UDP_SRC_PORT = 34;   ///< UDP source-port field.
constexpr std::size_t UDP_DST_PORT = 36;   ///< UDP destination-port field.
constexpr std::size_t UDP_LENGTH = 38;	   ///< UDP length field.
constexpr std::size_t UDP_CHECKSUM = 40;   ///< UDP checksum field.
constexpr std::size_t UDP_HDR_LEN = 8;	   ///< UDP header length.

constexpr std::size_t MIN_UDP_PACKET = 42;  ///< Ethernet, minimum IPv4, and UDP headers.
}  // namespace wire_offsets

/**
 * @brief Result of wire-format verification.
 *
 * Contains every verification detail needed for one failure report.
 */
struct wire_verify_result {
	bool ok{true};		     ///< Overall verification status
	std::string failure_reason;  ///< Detailed failure message

	// Ethernet verification
	bool eth_dst_mac_ok{true};  ///< Destination Ethernet bytes match.
	bool eth_src_mac_ok{true};  ///< Source Ethernet bytes match.
	bool eth_type_ok{true};	    ///< Ethernet type is IPv4.

	// IP verification
	bool ip_src_ok{true};	    ///< IPv4 source matches expected bytes.
	bool ip_dst_ok{true};	    ///< IPv4 destination matches expected bytes.
	bool ip_checksum_ok{true};  ///< IPv4 checksum matches independent arithmetic.

	// UDP verification
	bool udp_src_port_ok{true};  ///< UDP source port matches.
	bool udp_dst_port_ok{true};  ///< UDP destination port matches.

	// Metadata consistency
	bool metadata_ip_match{true};	 ///< Parsed and wire IPv4 identities agree.
	bool metadata_port_match{true};	 ///< Parsed and wire port identities agree.

	// Actual values found (for debugging)
	uint32_t wire_src_ip{0};	   ///< Observed wire source IPv4 value.
	uint32_t wire_dst_ip{0};	   ///< Observed wire destination IPv4 value.
	uint16_t wire_src_port{0};	   ///< Observed wire UDP source port.
	uint16_t wire_dst_port{0};	   ///< Observed wire UDP destination port.
	uint16_t wire_ip_checksum{0};	   ///< Observed wire IPv4 checksum.
	uint16_t computed_ip_checksum{0};  ///< Independently computed IPv4 checksum.
};

/**
 * @brief Verify Ethernet header integrity (detects offset bugs).
 *
 * Applying an L3/L4 mutation at the packet base instead of the parsed protocol
 * offset corrupts the Ethernet header. This function detects that contract
 * violation.
 *
 * @param pkt_data Pointer to packet buffer
 * @param pkt_len Total packet length
 * @param expected_dst_mac Expected destination MAC (default: 0x11 repeated)
 * @param expected_src_mac Expected source MAC (default: 0x22 repeated)
 * @return true if Ethernet header is intact
 */
inline bool verify_ethernet_intact(const uint8_t *pkt_data, std::size_t pkt_len, uint8_t expected_dst_mac = 0x11,
				   uint8_t expected_src_mac = 0x22)
{
	if (pkt_len < wire_offsets::ETH_HDR_LEN)
		return false;

	// Check destination MAC
	for (std::size_t i = 0; i < 6; ++i) {
		if (pkt_data[wire_offsets::ETH_DST_MAC + i] != expected_dst_mac)
			return false;
	}

	// Check source MAC
	for (std::size_t i = 0; i < 6; ++i) {
		if (pkt_data[wire_offsets::ETH_SRC_MAC + i] != expected_src_mac)
			return false;
	}

	// Check EtherType (0x0800 for IPv4)
	if (pkt_data[wire_offsets::ETH_TYPE] != 0x08)
		return false;
	if (pkt_data[wire_offsets::ETH_TYPE + 1] != 0x00)
		return false;

	return true;
}

/**
 * @brief Verify packet buffer matches expected wire-format values.
 *
 * This is the primary wire-format verification function. It checks:
 * 1. Ethernet header integrity (detects offset bugs)
 * 2. IP header src/dst match expected values
 * 3. UDP header src/dst ports match expected values
 * 4. IP checksum is valid
 *
 * @param pkt_data Pointer to packet buffer after processing
 * @param pkt_len Total packet length
 * @param expected_src_ip Expected source IP (host byte order)
 * @param expected_dst_ip Expected destination IP (host byte order)
 * @param expected_src_port Expected source port (host byte order), 0 = skip
 * @param expected_dst_port Expected destination port (host byte order), 0 = skip
 * @return Detailed verification result
 */
inline wire_verify_result verify_wire_format(const uint8_t *pkt_data, std::size_t pkt_len, uint32_t expected_src_ip,
					     uint32_t expected_dst_ip, uint16_t expected_src_port = 0,
					     uint16_t expected_dst_port = 0)
{
	wire_verify_result result;

	// Minimum packet size check
	if (pkt_len < wire_offsets::MIN_UDP_PACKET) {
		result.ok = false;
		result.failure_reason = "Packet too short (< 42 bytes)";
		return result;
	}

	// 1. Verify Ethernet header integrity
	for (std::size_t i = 0; i < 6; ++i) {
		if (pkt_data[wire_offsets::ETH_DST_MAC + i] != 0x11) {
			result.eth_dst_mac_ok = false;
			result.ok = false;
			result.failure_reason = "Dst MAC corrupted at offset " + std::to_string(i);
		}
		if (pkt_data[wire_offsets::ETH_SRC_MAC + i] != 0x22) {
			result.eth_src_mac_ok = false;
			result.ok = false;
			result.failure_reason = "Src MAC corrupted at offset " + std::to_string(6 + i);
		}
	}

	// Check EtherType
	if (pkt_data[wire_offsets::ETH_TYPE] != 0x08 || pkt_data[wire_offsets::ETH_TYPE + 1] != 0x00) {
		result.eth_type_ok = false;
		result.ok = false;
		result.failure_reason = "EtherType corrupted (expected 0x0800)";
	}

	// 2. Verify IP header
	const uint8_t *ip_hdr = pkt_data + wire_offsets::IP_HDR_START;

	// Extract wire-format values
	result.wire_src_ip = kinetum::algo::net::read_be32(ip_hdr + 12);  // src_ip at +12
	result.wire_dst_ip = kinetum::algo::net::read_be32(ip_hdr + 16);  // dst_ip at +16

	if (result.wire_src_ip != expected_src_ip) {
		result.ip_src_ok = false;
		result.ok = false;
		result.failure_reason = "Wire src_ip mismatch: expected 0x" + std::to_string(expected_src_ip) +
					", got 0x" + std::to_string(result.wire_src_ip);
	}

	if (result.wire_dst_ip != expected_dst_ip) {
		result.ip_dst_ok = false;
		result.ok = false;
		result.failure_reason = "Wire dst_ip mismatch: expected 0x" + std::to_string(expected_dst_ip) +
					", got 0x" + std::to_string(result.wire_dst_ip);
	}

	// 3. Verify IP checksum
	result.wire_ip_checksum = kinetum::algo::net::read_be16(ip_hdr + 10);
	result.computed_ip_checksum = compute_ipv4_checksum(ip_hdr, 20);

	if (result.wire_ip_checksum != result.computed_ip_checksum) {
		result.ip_checksum_ok = false;
		result.ok = false;
		result.failure_reason = "IP checksum invalid: stored 0x" + std::to_string(result.wire_ip_checksum) +
					", computed 0x" + std::to_string(result.computed_ip_checksum);
	}

	// 4. Verify UDP ports (if specified)
	const uint8_t *udp_hdr = pkt_data + wire_offsets::UDP_HDR_START;
	result.wire_src_port = kinetum::algo::net::read_be16(udp_hdr + 0);
	result.wire_dst_port = kinetum::algo::net::read_be16(udp_hdr + 2);

	if (expected_src_port != 0 && result.wire_src_port != expected_src_port) {
		result.udp_src_port_ok = false;
		result.ok = false;
		result.failure_reason = "Wire src_port mismatch: expected " + std::to_string(expected_src_port) +
					", got " + std::to_string(result.wire_src_port);
	}

	if (expected_dst_port != 0 && result.wire_dst_port != expected_dst_port) {
		result.udp_dst_port_ok = false;
		result.ok = false;
		result.failure_reason = "Wire dst_port mismatch: expected " + std::to_string(expected_dst_port) +
					", got " + std::to_string(result.wire_dst_port);
	}

	return result;
}

/**
 * @brief Verify metadata matches wire-format bytes.
 *
 * Ensures that packet metadata (md.src_ipv4, md.src_port, etc.) is consistent
 * with actual packet buffer bytes. This catches bugs where metadata is updated
 * but packet buffer is not (or vice versa).
 *
 * @param pkt_data Pointer to packet buffer
 * @param pkt_len Total packet length
 * @param md_src_ip Metadata source IP (host byte order)
 * @param md_dst_ip Metadata destination IP (host byte order)
 * @param md_src_port Metadata source port (host byte order)
 * @param md_dst_port Metadata destination port (host byte order)
 * @return wire_verify_result with metadata_*_match fields populated
 */
inline wire_verify_result verify_metadata_wire_consistency(const uint8_t *pkt_data, std::size_t pkt_len,
							   uint32_t md_src_ip, uint32_t md_dst_ip, uint16_t md_src_port,
							   uint16_t md_dst_port)
{
	wire_verify_result result;

	if (pkt_len < wire_offsets::MIN_UDP_PACKET) {
		result.ok = false;
		result.failure_reason = "Packet too short for metadata verification";
		return result;
	}

	// Read wire-format values
	const uint8_t *ip_hdr = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t *udp_hdr = pkt_data + wire_offsets::UDP_HDR_START;

	result.wire_src_ip = kinetum::algo::net::read_be32(ip_hdr + 12);
	result.wire_dst_ip = kinetum::algo::net::read_be32(ip_hdr + 16);
	result.wire_src_port = kinetum::algo::net::read_be16(udp_hdr + 0);
	result.wire_dst_port = kinetum::algo::net::read_be16(udp_hdr + 2);

	// Compare metadata to wire format
	if (md_src_ip != result.wire_src_ip) {
		result.metadata_ip_match = false;
		result.ok = false;
		result.failure_reason = "Metadata src_ip (0x" + std::to_string(md_src_ip) + ") != wire src_ip (0x" +
					std::to_string(result.wire_src_ip) + ")";
	}

	if (md_dst_ip != result.wire_dst_ip) {
		result.metadata_ip_match = false;
		result.ok = false;
		result.failure_reason = "Metadata dst_ip != wire dst_ip";
	}

	if (md_src_port != result.wire_src_port) {
		result.metadata_port_match = false;
		result.ok = false;
		result.failure_reason = "Metadata src_port != wire src_port";
	}

	if (md_dst_port != result.wire_dst_port) {
		result.metadata_port_match = false;
		result.ok = false;
		result.failure_reason = "Metadata dst_port != wire dst_port";
	}

	return result;
}

/**
 * @brief Verify port is within expected range (for NAT pool tests).
 *
 * @param port Port value to check
 * @param min_port Minimum expected port (inclusive)
 * @param max_port Maximum expected port (inclusive)
 * @return true if port is in range [min_port, max_port]
 */
inline bool verify_port_in_range(uint16_t port, uint16_t min_port, uint16_t max_port)
{
	return port >= min_port && port <= max_port;
}

/**
 * @brief Save original Ethernet header for later comparison.
 *
 * Use this before processing to capture the original header, then compare
 * after processing to detect corruption.
 *
 * @param pkt_data Pointer to packet buffer
 * @param out_header Output buffer (must be at least 14 bytes)
 */
inline void save_ethernet_header(const uint8_t *pkt_data, uint8_t *out_header)
{
	std::memcpy(out_header, pkt_data, wire_offsets::ETH_HDR_LEN);
}

/**
 * @brief Compare current Ethernet header with saved original.
 *
 * @param pkt_data Current packet buffer
 * @param saved_header Previously saved header (14 bytes)
 * @return true if headers match exactly
 */
inline bool compare_ethernet_headers(const uint8_t *pkt_data, const uint8_t *saved_header)
{
	return std::memcmp(pkt_data, saved_header, wire_offsets::ETH_HDR_LEN) == 0;
}
