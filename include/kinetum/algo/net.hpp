// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file net.hpp
 * @brief Network protocol algorithms - byte order, checksum updates, and IPv4 helpers.
 * @author Fleming Patel
 *
 * This is the canonical header-owned byte-order and IPv4 utility surface used
 * by the dataplane, built-in modules, and C++ SDK consumers.
 *
 * Contains:
 * - Byte order conversion (network/host byte order)
 * - IP address utilities (private IP detection, etc.)
 * - CIDR utilities (prefix to mask conversion)
 *
 * For the header-owned CIDR parsing/formatting contract, include
 * <kinetum/algo/cidr.hpp>.
 * Incremental checksum arithmetic is header-owned so module images retain
 * link closure. Each packet-processing owner validates its own packet bounds
 * and supplies the exact changed words.
 *
 * The same header-owned implementation serves Kinetum's little-endian x86-64 and AArch64
 * targets. Normative protocol specifications are indexed once in
 * docs/TECHNICAL_REFERENCES.md.
 */

#include <cstdint>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo::net
{

// =============================================================================
// Byte Order Conversion (Big-Endian / Network Order)
// =============================================================================

/**
 * @brief Read a 16-bit unsigned integer from big-endian byte buffer.
 *
 * Reads two consecutive bytes from the buffer and combines them into a 16-bit
 * value, interpreting the bytes as big-endian (network byte order). This is the
 * standard format for all 16-bit fields in IP, TCP, UDP headers.
 *
 * Algorithm: (byte[0] << 8) | byte[1]
 *
 * Example:
 *   Buffer: [0x12, 0x34] -> Returns: 0x1234
 *
 * @param p Pointer to buffer containing at least 2 bytes
 * @return 16-bit unsigned integer in host byte order
 *
 * @note Caller must ensure buffer has at least 2 bytes available
 * @note No alignment requirements, works with any byte address
 * @note constexpr allows compile-time evaluation for constant data
 *
 * Hot-path contract: constexpr, no alignment requirement, no allocation.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_PURE constexpr uint16_t read_be16(const uint8_t *p) noexcept
{
	return static_cast<uint16_t>((static_cast<uint32_t>(p[0]) << 8u) | static_cast<uint32_t>(p[1]));
}

/**
 * @brief Read a 32-bit unsigned integer from big-endian byte buffer.
 *
 * Reads four consecutive bytes from the buffer and combines them into a 32-bit
 * value, interpreting the bytes as big-endian (network byte order). Used for
 * IPv4 addresses, sequence numbers, timestamps, etc.
 *
 * Algorithm: (byte[0] << 24) | (byte[1] << 16) | (byte[2] << 8) | byte[3]
 *
 * Example:
 *   Buffer: [0x0a, 0x00, 0x00, 0x01] -> Returns: 0x0a000001 (IP 10.0.0.1)
 *
 * @param p Pointer to buffer containing at least 4 bytes
 * @return 32-bit unsigned integer in host byte order
 *
 * Hot-path contract: constexpr, no alignment requirement, no allocation.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_PURE constexpr uint32_t read_be32(const uint8_t *p) noexcept
{
	return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
	       (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

/**
 * @brief Read a 64-bit unsigned integer from big-endian byte buffer.
 *
 * @param p Pointer to buffer containing at least 8 bytes
 * @return 64-bit unsigned integer in host byte order
 *
 * Hot-path contract: constexpr, no alignment requirement, no allocation.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_PURE constexpr uint64_t read_be64(const uint8_t *p) noexcept
{
	return (static_cast<uint64_t>(p[0]) << 56) | (static_cast<uint64_t>(p[1]) << 48) |
	       (static_cast<uint64_t>(p[2]) << 40) | (static_cast<uint64_t>(p[3]) << 32) |
	       (static_cast<uint64_t>(p[4]) << 24) | (static_cast<uint64_t>(p[5]) << 16) |
	       (static_cast<uint64_t>(p[6]) << 8) | static_cast<uint64_t>(p[7]);
}

/**
 * @brief Write a 16-bit unsigned integer to big-endian byte buffer.
 *
 * Converts a 16-bit host byte order value to big-endian and writes it as two
 * consecutive bytes to the buffer.
 *
 * @param p Pointer to buffer with at least 2 bytes of writable space
 * @param v 16-bit unsigned integer in host byte order
 *
 * Hot-path contract: constexpr, no alignment requirement, no allocation.
 */
KINETUM_ALWAYS_INLINE
constexpr void write_be16(uint8_t *p, uint16_t v) noexcept
{
	p[0] = static_cast<uint8_t>((v >> 8) & 0xffu);
	p[1] = static_cast<uint8_t>(v & 0xffu);
}

/**
 * @brief Write a 32-bit unsigned integer to big-endian byte buffer.
 *
 * @param p Pointer to buffer with at least 4 bytes of writable space
 * @param v 32-bit unsigned integer in host byte order
 *
 * Hot-path contract: constexpr, no alignment requirement, no allocation.
 */
KINETUM_ALWAYS_INLINE
constexpr void write_be32(uint8_t *p, uint32_t v) noexcept
{
	p[0] = static_cast<uint8_t>((v >> 24) & 0xffu);
	p[1] = static_cast<uint8_t>((v >> 16) & 0xffu);
	p[2] = static_cast<uint8_t>((v >> 8) & 0xffu);
	p[3] = static_cast<uint8_t>(v & 0xffu);
}

/**
 * @brief Write a 64-bit unsigned integer to big-endian byte buffer.
 *
 * @param p Pointer to buffer with at least 8 bytes of writable space
 * @param v 64-bit unsigned integer in host byte order
 *
 * Hot-path contract: constexpr, no alignment requirement, no allocation.
 */
KINETUM_ALWAYS_INLINE
constexpr void write_be64(uint8_t *p, uint64_t v) noexcept
{
	p[0] = static_cast<uint8_t>((v >> 56) & 0xffu);
	p[1] = static_cast<uint8_t>((v >> 48) & 0xffu);
	p[2] = static_cast<uint8_t>((v >> 40) & 0xffu);
	p[3] = static_cast<uint8_t>((v >> 32) & 0xffu);
	p[4] = static_cast<uint8_t>((v >> 24) & 0xffu);
	p[5] = static_cast<uint8_t>((v >> 16) & 0xffu);
	p[6] = static_cast<uint8_t>((v >> 8) & 0xffu);
	p[7] = static_cast<uint8_t>(v & 0xffu);
}

// =============================================================================
// Incremental Internet Checksum
// =============================================================================

/**
 * @brief Adjust an Internet checksum for one changed 16-bit word.
 *
 * Uses one's-complement arithmetic and two bounded carry folds. All values
 * are host-order representations of network words. This operation neither
 * validates the incoming checksum nor applies protocol-specific zero rules.
 *
 * @param checksum Existing checksum field.
 * @param previous Word before mutation.
 * @param replacement Word after mutation.
 * @return Adjusted checksum, including the positive-zero boundary result.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr uint16_t
update_internet_checksum(uint16_t checksum, uint16_t previous, uint16_t replacement) noexcept
{
	uint32_t sum = static_cast<uint32_t>(checksum ^ UINT16_MAX) + static_cast<uint32_t>(previous ^ UINT16_MAX) +
		       static_cast<uint32_t>(replacement);
	sum = (sum & UINT16_MAX) + (sum >> 16u);
	sum = (sum & UINT16_MAX) + (sum >> 16u);
	return static_cast<uint16_t>(sum ^ UINT16_MAX);
}

// =============================================================================
// IP Protocol Constants
// =============================================================================

namespace protocol
{
constexpr uint8_t ICMP = 1;  ///< Internet Control Message Protocol
constexpr uint8_t TCP = 6;   ///< Transmission Control Protocol
constexpr uint8_t UDP = 17;  ///< User Datagram Protocol
}  // namespace protocol

// =============================================================================
// IP Address Utilities
// =============================================================================

/**
 * @brief Check if IP is in RFC 1918 private range.
 *
 * Private ranges:
 * - 10.0.0.0/8
 * - 172.16.0.0/12
 * - 192.168.0.0/16
 *
 * @param ip IP address (host byte order)
 * @return true if private
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr bool is_private_ip(uint32_t ip) noexcept
{
	// 10.0.0.0/8
	if ((ip & 0xFF000000u) == 0x0A000000u)
		return true;
	// 172.16.0.0/12
	if ((ip & 0xFFF00000u) == 0xAC100000u)
		return true;
	// 192.168.0.0/16
	if ((ip & 0xFFFF0000u) == 0xC0A80000u)
		return true;
	return false;
}

}  // namespace kinetum::algo::net
