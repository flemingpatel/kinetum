// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file ipv4.hpp
 * @brief IPv4 and Ethernet packet parsing for the dataplane.
 * @author Fleming Patel
 *
 * This file provides zero-copy, bounds-checked packet parsing primitives for
 * Ethernet and IPv4 headers on the data-plane hot path.
 *
 * Contract:
 * - Parsing operates directly on caller-owned packet bytes without allocation.
 * - Malformed packet content returns `ok=false` after bounded validation.
 * - The caller supplies storage valid for the complete declared byte extent.
 * - Only fields consumed by current dataplane operations are extracted.
 *
 * Key Features:
 * - Bounded VLAN tag handling (802.1Q and 802.1ad QinQ)
 * - IPv4 version, IHL, total-length validation, and fragment detection
 * - Explicit non-validation of the IPv4 checksum and complete L4 headers
 * - L4 port extraction only for complete TCP/UDP headers
 *
 * Hot-path Characteristics:
 * - Bounded Ethernet parsing with at most two VLAN tags
 * - IPv4 parsing is bounded by the header length field
 * - No memory allocations, no system calls, no exceptions
 * - Sequential buffer access for the common valid-packet case
 *
 * Usage Pattern:
 * 1. Parse Ethernet header to find L3 offset and EtherType
 * 2. If EtherType == 0x0800 (IPv4), parse IPv4 header
 * 3. Check ok flag before using any extracted fields
 * 4. Use extracted metadata for forwarding, filtering, NAT, etc.
 *
 * Thread Safety: All functions are thread-safe and reentrant (read-only on buffers).
 * Memory Safety: Caller must ensure buffer pointers are valid for specified length.
 *
 * @see RFC 791  - Internet Protocol (IPv4 specification)
 * @see RFC 894  - IP over Ethernet
 * @see IEEE 802.1Q - VLAN Tagging
 * @see IEEE 802.1ad - QinQ VLAN Stacking
 */

#include <cstddef>
#include <cstdint>

#include <kinetum/algo/net.hpp>

namespace kinetum::dp::net
{

/**
 * @brief EtherType constants for common network protocols.
 *
 * EtherType is a 16-bit field in Ethernet frames that indicates the protocol
 * encapsulated in the payload. These are the standard IANA-assigned values.
 *
 * @see IEEE 802.3 - Ethernet Frame Format
 * @see IANA EtherType Registry
 */
namespace ethertype
{
constexpr uint16_t IPV4 = 0x0800;  ///< Internet Protocol version 4
constexpr uint16_t ARP = 0x0806;   ///< Address Resolution Protocol
constexpr uint16_t IPV6 = 0x86DD;  ///< Internet Protocol version 6
constexpr uint16_t VLAN = 0x8100;  ///< 802.1Q VLAN tagging
constexpr uint16_t QINQ = 0x88A8;  ///< 802.1ad QinQ (stacked VLANs)
}  // namespace ethertype

/**
 * @brief Result of Ethernet frame parsing.
 *
 * Contains the extracted EtherType, offset to L3 header, and VLAN nesting depth.
 * The ok flag indicates whether parsing succeeded; if false, other fields are
 * undefined and must not be used.
 *
 * Field Semantics:
 * - ok: true if frame is valid, false if malformed or truncated
 * - eth_type: Final EtherType after unwinding all VLAN tags
 * - l3_offset: Byte offset from start of buffer to L3 header (IP, ARP, etc.)
 * - vlan_depth: Number of VLAN tags found (0-2 supported)
 *
 * Common EtherType Values:
 * - 0x0800: IPv4
 * - 0x86DD: IPv6
 * - 0x0806: ARP
 *
 * Example:
 * @code
 *   auto result = parse_ethernet(buffer, len);
 *   if (result.ok && result.eth_type == 0x0800) {
 *     // Parse IPv4 header at buffer[result.l3_offset]
 *   }
 * @endcode
 */
struct eth_parse_result {
	bool ok{false};		///< True if parsing succeeded
	uint16_t eth_type{0};	///< EtherType after unwinding VLAN tags
	uint16_t l3_offset{0};	///< Offset to L3 header (post-VLAN tags)
	uint8_t vlan_depth{0};	///< Number of VLAN tags (0, 1, or 2)
};

/**
 * @brief Result of IPv4 header parsing.
 *
 * Contains all commonly-needed IPv4 header fields plus automatically-extracted
 * TCP/UDP ports. The ok flag indicates parsing success; if false, all other
 * fields are undefined.
 *
 * Field Semantics:
 * - ok: true if the required IPv4 structure fits the supplied record
 * - is_fragment: true if packet is fragmented (MF=1 or FragOffset>0)
 * - ip_offset: Byte offset of IPv4 header start in buffer
 * - l4_offset: Byte offset of L4 header (TCP/UDP/etc.) in buffer
 * - ip_header_len: Length of IPv4 header in bytes (IHL * 4, typically 20)
 * - ip_total_len: Total length from IPv4 header (header + payload)
 * - src_ipv4: Source IP address in host byte order (via read_be32)
 * - dst_ipv4: Destination IP address in host byte order (via read_be32)
 * - proto: IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.)
 * - dscp: Differentiated Services Code Point (6 bits, ECN stripped)
 * - src_port: Source port (TCP/UDP), 0 if not TCP/UDP or fragment
 * - dst_port: Destination port (TCP/UDP), 0 if not TCP/UDP or fragment
 *
 * Important Notes:
 * - Ports are only extracted for TCP/UDP non-fragments
 * - IP addresses are in host byte order (read_be32 converts from network)
 * - Fragment state must be checked before consuming extracted L4 data
 * - DSCP is upper 6 bits of TOS byte, ECN bits (lower 2) are stripped
 *
 * Example:
 * @code
 *   auto result = parse_ipv4(buffer, len, l3_offset);
 *   if (result.ok && !result.is_fragment && result.proto == 6) {
 *     // Valid TCP packet, ports available
 *     uint16_t sport = result.src_port;
 *   }
 * @endcode
 *
 * @see RFC 791 Section 3.1 - IPv4 Header Format
 */
struct ipv4_parse_result {
	bool ok{false};		  ///< True if parsing succeeded
	bool is_fragment{false};  ///< True if fragmented (MF or FragOffset != 0)

	uint16_t ip_offset{0};	///< Offset of IPv4 header in buffer
	uint16_t l4_offset{0};	///< Offset of L4 header in buffer

	uint16_t ip_header_len{0};  ///< IPv4 header length (IHL * 4, bytes)
	uint16_t ip_total_len{0};   ///< Total length from IPv4 header (bytes)

	uint32_t src_ipv4{0};  ///< Source IP (host byte order)
	uint32_t dst_ipv4{0};  ///< Destination IP (host byte order)
	uint8_t proto{0};      ///< IP protocol number (6=TCP, 17=UDP, 1=ICMP)
	uint8_t dscp{0};       ///< DSCP value (6 bits, ECN stripped)

	uint16_t src_port{0};  ///< Source port (TCP/UDP only, 0 otherwise)
	uint16_t dst_port{0};  ///< Destination port (TCP/UDP only, 0 otherwise)
};

/**
 * @brief Parse Ethernet frame header with VLAN tag unwinding.
 *
 * Parses an Ethernet II frame, automatically unwinding up to 2 levels of VLAN
 * tags (802.1Q and 802.1ad QinQ). Returns the final EtherType and offset to
 * the L3 header.
 *
 * Ethernet II Frame Format (RFC 894):
 * - Destination MAC (6 bytes)
 * - Source MAC      (6 bytes)
 * - EtherType       (2 bytes) -- or first VLAN tag
 * - Payload         (46-1500 bytes)
 *
 * VLAN Tag Format (802.1Q):
 * - TPID            (2 bytes) -- 0x8100 or 0x88A8
 * - TCI             (2 bytes) -- Priority, CFI, VID
 *
 * Algorithm:
 * 1. Validate minimum Ethernet header (14 bytes)
 * 2. Read EtherType at offset 12
 * 3. While EtherType is VLAN tag and depth < 2:
 *    - Skip 4-byte VLAN tag
 *    - Read next EtherType
 * 4. Return final EtherType and L3 offset
 *
 * Example:
 * @code
 *   uint8_t frame[1514] = {...};
 *   auto result = parse_ethernet(frame, sizeof(frame));
 *   if (result.ok) {
 *     printf("EtherType: 0x%04x, L3 offset: %u, VLANs: %u\n",
 *            result.eth_type, result.l3_offset, result.vlan_depth);
 *   }
 * @endcode
 *
 * @param buf Pointer to Ethernet frame (must be valid for len bytes)
 * @param len Length of frame in bytes (must be >= 14 for valid frame)
 * @return eth_parse_result with ok=true if the complete header is admitted;
 *         malformed, truncated, or over-depth input returns ok=false.
 *
 * @note A maximum of two VLAN tags is supported; another nested tag rejects.
 * @note Null buffer or length < 14 returns ok=false
 * @note Does not validate MAC addresses or FCS
 *
 * @pre buf != nullptr || len == 0
 * @pre len <= actual buffer size
 *
 * Complexity: bounded by MAX_VLAN_DEPTH; performs no allocation.
 */
[[nodiscard]] eth_parse_result parse_ethernet(const uint8_t *buf, std::size_t len) noexcept;

/**
 * @brief Parse a bounded IPv4 header and extract an available L4 port prefix.
 *
 * Parses an IPv4 header at the specified offset with bounded structural
 * validation. Automatically extracts TCP/UDP ports for non-fragmented packets.
 *
 * IPv4 Header Format (RFC 791 Section 3.1):
 * - Version/IHL     (1 byte)  -- Version=4, IHL=5-15 (header length in 32-bit words)
 * - DSCP/ECN        (1 byte)  -- Type of Service
 * - Total Length    (2 bytes) -- Header + payload
 * - Identification  (2 bytes) -- Fragment identification
 * - Flags/FragOff   (2 bytes) -- Flags (DF, MF) and fragment offset
 * - TTL             (1 byte)  -- Time to live
 * - Protocol        (1 byte)  -- Next protocol (6=TCP, 17=UDP, etc.)
 * - Checksum        (2 bytes) -- Header checksum
 * - Source IP       (4 bytes) -- Source address
 * - Destination IP  (4 bytes) -- Destination address
 * - Options         (0-40 bytes) -- Optional, padded to 32-bit boundary
 *
 * Validation Checks:
 * - Buffer has space for minimum 20-byte header
 * - Version field is 4
 * - IHL is in valid range (5-15, meaning 20-60 bytes)
 * - Buffer contains full header (IHL bytes)
 * - L4 offset is representable as uint16 metadata
 * - Total length >= header length
 * - Total length <= bytes available from the IPv4 offset
 *
 * Fragment Detection:
 * - MF (More Fragments) flag set, or
 * - Fragment Offset > 0
 *
 * Port Extraction:
 * - Only for TCP (proto=6) or UDP (proto=17)
 * - Only for non-fragmented packets
 * - Only if the declared IPv4 extent contains at least 4 bytes of L4 data
 *
 * Example:
 * @code
 *   auto eth_res = parse_ethernet(buffer, len);
 *   if (eth_res.ok && eth_res.eth_type == 0x0800) {
 *     auto ip_res = parse_ipv4(buffer, len, eth_res.l3_offset);
 *     if (ip_res.ok && !ip_res.is_fragment) {
 *       // Valid, non-fragmented IPv4 packet
 *       if (ip_res.proto == 6) {
 *         printf("TCP: %u -> %u\n", ip_res.src_port, ip_res.dst_port);
 *       }
 *     }
 *   }
 * @endcode
 *
 * @param buf Pointer to packet buffer containing Ethernet + IPv4 headers
 * @param len Total length of packet buffer in bytes
 * @param ip_offset Offset from buf where IPv4 header starts
 * @return ipv4_parse_result with ok=true if valid, ok=false if malformed
 *
 * @note This parser does not validate the IPv4 header checksum.
 * @note IP addresses are returned in host byte order (via read_be32)
 * @note Ports are returned in host byte order
 * @note Options are not parsed, but offset past them is computed
 * @note Null buffer returns ok=false
 *
 * @pre buf != nullptr || len == 0
 * @pre ip_offset < len (if len > 0)
 * @pre len <= actual buffer size
 *
 * @see RFC 791 Section 3.1 - IPv4 Header Format
 * @see RFC 815 - IP Fragmentation Reassembly
 *
 * Complexity: bounded by IPv4 header length; performs no allocation.
 */
[[nodiscard]] ipv4_parse_result parse_ipv4(const uint8_t *buf, std::size_t len, uint16_t ip_offset) noexcept;

}  // namespace kinetum::dp::net
