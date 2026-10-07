// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file ipv4.cpp
 * @brief Implementation of IPv4 and Ethernet packet parsing for dataplane.
 * @author Fleming Patel
 *
 * This file implements zero-copy packet parsing directly over bounded packet
 * buffers. Every consumed header byte is covered by both the record extent and
 * the protocol-declared IPv4 extent.
 *
 * Implementation shape:
 * - Early validation: Check buffer bounds before any memory access
 * - Short-circuit returns: Reject malformed packet bytes immediately
 * - Minimal state: Results are self-contained structs, no hidden state
 * - Conservative: Strict validation, reject ambiguous packets
 *
 * Packet work is allocation-free, exception-free, and bounded by the Ethernet
 * header plus the protocol-declared IPv4 header extent. Byte-order helpers are
 * inlined from <kinetum/algo/net.hpp>.
 *
 * Correctness Considerations:
 * - All buffer accesses are bounds-checked before use
 * - Integer overflow is prevented by validation and careful casting
 * - Endianness is handled through the public byte-order primitives
 * - IPv4 version, IHL, total length, and fragment presence are validated
 * - IPv4 checksum and complete transport-header semantics are not validated
 *
 * @see RFC 791 - Internet Protocol (IPv4)
 * @see RFC 894 - IP over Ethernet
 * @see IEEE 802.1Q - VLAN Tagging
 */

#include "src/dp/net/ipv4.hpp"

#include <cstddef>
#include <limits>

namespace kinetum::dp::net
{

// Import byte order functions from canonical location
using kinetum::algo::net::read_be16;
using kinetum::algo::net::read_be32;

eth_parse_result parse_ethernet(const uint8_t *buf, std::size_t len) noexcept
{
	// Initialize result with ok=false (failure state)
	eth_parse_result result{};

	// Validate input: null buffer or too short for Ethernet header
	// Minimum Ethernet II frame: 14 bytes (6 dst MAC + 6 src MAC + 2 EtherType)
	if (!buf || len < 14) {
		return result;	// ok=false
	}

	// Ethernet II Frame Structure (RFC 894):
	// Offset 0-5:   Destination MAC (6 bytes)
	// Offset 6-11:  Source MAC (6 bytes)
	// Offset 12-13: EtherType or VLAN TPID (2 bytes)

	// Read initial EtherType at standard offset 12
	uint16_t eth_type = read_be16(buf + 12);
	std::size_t offset = 14;  // Offset past basic Ethernet header
	uint8_t vlan_depth = 0;	  // Count of VLAN tags encountered

	// VLAN Tag Unwinding Loop
	// VLAN tags are inserted between Ethernet header and payload
	// Each tag is 4 bytes: 2-byte TPID + 2-byte TCI
	// Standard TPIDs: 0x8100 (802.1Q), 0x88A8 (802.1ad QinQ)
	//
	// VLAN Tag Format:
	// - TPID (Tag Protocol Identifier): 0x8100 or 0x88A8
	// - TCI (Tag Control Information): Priority (3 bits) + DEI (1 bit) + VID (12 bits)
	//
	// We support up to 2 levels of VLAN tagging (common in provider networks)
	// Loop invariant: eth_type contains next protocol/TPID, offset points past it
	constexpr uint8_t MAX_VLAN_DEPTH = 2;
	while ((eth_type == ethertype::VLAN || eth_type == ethertype::QINQ) && vlan_depth < MAX_VLAN_DEPTH) {
		// Bounds check: ensure we can read the full 4-byte VLAN tag
		// We need: current offset (already consumed) + 4 bytes for this tag
		if (len < offset + 4) {
			return result;	// ok=false, truncated VLAN tag
		}

		// VLAN tag structure at current offset:
		// +0-1: TPID (already read into eth_type)
		// +2-3: TCI (not needed, skip)
		// +4-5: Next EtherType or TPID

		// Read next EtherType from offset+2 (skipping TPID we already checked)
		// This is the actual EtherType if no more VLAN tags, or next TPID if stacked
		eth_type = read_be16(buf + offset + 2);

		// Advance offset past this 4-byte VLAN tag
		offset += 4;
		vlan_depth++;
	}
	if (eth_type == ethertype::VLAN || eth_type == ethertype::QINQ) {
		return result;	// ok=false, nesting exceeds the supported exact bound
	}

	// Success: every VLAN tag was unwound and eth_type is the final protocol.
	result.ok = true;
	result.eth_type = eth_type;
	result.l3_offset = static_cast<uint16_t>(offset);
	result.vlan_depth = vlan_depth;

	return result;
}

ipv4_parse_result parse_ipv4(const uint8_t *buf, std::size_t len, uint16_t ip_offset) noexcept
{
	// Initialize result with ok=false (failure state)
	ipv4_parse_result result{};

	// Validate input: null buffer is invalid
	if (!buf) {
		return result;	// ok=false
	}

	// Minimum IPv4 header size is 20 bytes (IHL=5)
	// Validate buffer contains at least minimum header starting at ip_offset
	constexpr std::size_t MIN_IPV4_HEADER_SIZE = 20;
	if (len < static_cast<std::size_t>(ip_offset) + MIN_IPV4_HEADER_SIZE) {
		return result;	// ok=false, buffer too short
	}

	// IPv4 Header Structure (RFC 791 Section 3.1):
	// Offset 0:     Version(4 bits) + IHL(4 bits)
	// Offset 1:     DSCP(6 bits) + ECN(2 bits)
	// Offset 2-3:   Total Length (16 bits)
	// Offset 4-5:   Identification (16 bits)
	// Offset 6-7:   Flags(3 bits) + Fragment Offset(13 bits)
	// Offset 8:     TTL (8 bits)
	// Offset 9:     Protocol (8 bits)
	// Offset 10-11: Header Checksum (16 bits)
	// Offset 12-15: Source IP Address (32 bits)
	// Offset 16-19: Destination IP Address (32 bits)
	// Offset 20+:   Options (0-40 bytes, padded to 32-bit boundary)

	const uint8_t *ip_hdr = buf + ip_offset;

	// Extract Version and IHL from first byte
	// Byte 0: [7:4] = Version, [3:0] = IHL (header length in 32-bit words)
	const uint8_t ver_ihl = ip_hdr[0];
	const uint8_t version = static_cast<uint8_t>(ver_ihl >> 4);
	const uint8_t ihl_words = static_cast<uint8_t>(ver_ihl & 0x0f);

	// Validate IP version is 4
	if (version != 4) {
		return result;	// ok=false, not IPv4 (could be IPv6, malformed, etc.)
	}

	// Validate IHL (Internet Header Length)
	// IHL is in 32-bit words, so header length in bytes = IHL * 4
	// Valid range: 5-15 words = 20-60 bytes
	// - IHL < 5 (20 bytes): Invalid, header too short for required fields
	// - IHL > 15 (60 bytes): Invalid, would exceed 4-bit field
	const uint16_t ihl_bytes = static_cast<uint16_t>(ihl_words) * 4;
	constexpr uint16_t MIN_IHL_BYTES = 20;
	constexpr uint16_t MAX_IHL_BYTES = 60;
	if (ihl_bytes < MIN_IHL_BYTES || ihl_bytes > MAX_IHL_BYTES) {
		return result;	// ok=false, invalid header length
	}

	// Validate that the L4 offset is representable in packet metadata and that
	// the buffer contains the complete IPv4 header.
	const std::size_t l4_offset = static_cast<std::size_t>(ip_offset) + ihl_bytes;
	if (l4_offset > std::numeric_limits<uint16_t>::max() || len < l4_offset) {
		return result;	// ok=false, derived offset is unrepresentable or truncated
	}

	// Extract and validate Total Length field (bytes 2-3)
	// Total Length includes header + payload and must fit the exact record.
	const uint16_t total_length = read_be16(ip_hdr + 2);
	const std::size_t available_ip_bytes = len - static_cast<std::size_t>(ip_offset);
	if (total_length < ihl_bytes || static_cast<std::size_t>(total_length) > available_ip_bytes) {
		return result;	// ok=false, declared IPv4 extent is malformed or truncated
	}

	// Extract Flags and Fragment Offset (bytes 6-7)
	// Format: [15:13] = Flags, [12:0] = Fragment Offset (in 8-byte units)
	// Flags:
	// - Bit 15: Reserved (must be 0)
	// - Bit 14: DF (Don't Fragment)
	// - Bit 13: MF (More Fragments)
	// Fragment Offset: Offset of this fragment in original datagram (8-byte units)
	const uint16_t flags_frag = read_be16(ip_hdr + 6);
	const uint16_t frag_offset = static_cast<uint16_t>(flags_frag & 0x1fff);  // Lower 13 bits
	const bool more_fragments = (flags_frag & 0x2000) != 0;			  // Bit 13

	// A packet is fragmented if:
	// - MF (More Fragments) flag is set, OR
	// - Fragment Offset is non-zero (this is not the first fragment)
	const bool is_fragmented = more_fragments || (frag_offset != 0);

	// All validation passed - populate result structure
	result.ok = true;
	result.is_fragment = is_fragmented;
	result.ip_offset = ip_offset;
	result.ip_header_len = ihl_bytes;
	result.ip_total_len = total_length;

	// Extract DSCP (Differentiated Services Code Point) from TOS byte
	// Byte 1: [7:2] = DSCP (6 bits), [1:0] = ECN (2 bits)
	// We strip ECN and return only DSCP for QoS classification
	result.dscp = static_cast<uint8_t>(ip_hdr[1] >> 2);

	// Extract protocol number (byte 9)
	// Common values: 1=ICMP, 6=TCP, 17=UDP, 47=GRE, 50=ESP, etc.
	result.proto = ip_hdr[9];

	// Extract source and destination IP addresses (bytes 12-15 and 16-19)
	// read_be32() reads big-endian wire format and returns host byte order
	result.src_ipv4 = read_be32(ip_hdr + 12);
	result.dst_ipv4 = read_be32(ip_hdr + 16);

	// Calculate L4 header offset (immediately after IP header and options)
	result.l4_offset = static_cast<uint16_t>(l4_offset);

	// L4 Port Extraction (TCP/UDP only, non-fragmented packets only)
	// Ports are in the first 4 bytes of L4 header (src port, dst port)
	// Only extract if:
	// 1. Packet is not fragmented (fragment reassembly would be needed otherwise)
	// 2. Protocol is TCP (6) or UDP (17)
	// 3. The declared IPv4 extent contains at least 4 bytes of L4 data
	//
	// TCP Header (RFC 793): src_port(2) dst_port(2) seq(4) ack(4) ...
	// UDP Header (RFC 768): src_port(2) dst_port(2) length(2) checksum(2)
	// Both have ports at same offsets (0-1: src, 2-3: dst)
	if (!is_fragmented &&
	    (result.proto == kinetum::algo::net::protocol::TCP || result.proto == kinetum::algo::net::protocol::UDP)) {
		constexpr std::size_t L4_PORT_BYTES = 4;  // src_port(2) + dst_port(2)
		const std::size_t declared_l4_bytes = static_cast<std::size_t>(total_length - ihl_bytes);
		if (declared_l4_bytes >= L4_PORT_BYTES) {
			const uint8_t *l4_hdr = buf + result.l4_offset;
			result.src_port = read_be16(l4_hdr + 0);  // Source port at offset 0-1
			result.dst_port = read_be16(l4_hdr + 2);  // Destination port at offset 2-3
		}
		// If buffer doesn't contain ports, they remain 0 (initialized in result struct)
	}

	return result;
}

}  // namespace kinetum::dp::net
