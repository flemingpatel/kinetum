// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file cidr.hpp
 * @brief CIDR (Classless Inter-Domain Routing) utilities.
 * @author Fleming Patel
 *
 * This is the canonical C++ implementation for all CIDR operations in the
 * platform. Every C++ consumer, including SDK modules, includes this header
 * rather than importing an implementation from a host runtime library.
 *
 * Contains:
 * - CIDR struct for parsed prefix representation
 * - IPv4 address parsing from dotted-decimal notation
 * - CIDR notation parsing ("10.0.0.0/8")
 * - CIDR matching (check if IP falls within prefix)
 *
 * Image ownership:
 * - Every function is header-defined so SDK modules remain link-closed.
 * - match_cidr() is constexpr inline and allocation-free.
 * - parse_cidr() is cold-path only (config parsing)
 *
 * @see RFC 4632 - Classless Inter-domain Routing (CIDR)
 * @see RFC 791  - Internet Protocol (IPv4 addressing)
 * @see kinetum/algo/net.hpp for byte-order and protocol utilities
 */

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/** @brief Parse one canonical unsigned octet. */
[[nodiscard]] constexpr bool parse_cidr_octet(std::string_view input, uint8_t *output) noexcept
{
	if (output == nullptr || input.empty() || (input.size() > 1 && input.front() == '0')) {
		return false;
	}
	uint32_t value = 0;
	for (const char character : input) {
		if (character < '0' || character > '9') {
			return false;
		}
		value = value * 10u + static_cast<uint32_t>(character - '0');
		if (value > 255u) {
			return false;
		}
	}
	*output = static_cast<uint8_t>(value);
	return true;
}

/** @brief Parse one canonical IPv4 prefix length. */
[[nodiscard]] constexpr bool parse_cidr_prefix(std::string_view input, uint8_t *output) noexcept
{
	if (output == nullptr || input.empty() || (input.size() > 1 && input.front() == '0')) {
		return false;
	}
	uint32_t value = 0;
	for (const char character : input) {
		if (character < '0' || character > '9') {
			return false;
		}
		value = value * 10u + static_cast<uint32_t>(character - '0');
		if (value > 32u) {
			return false;
		}
	}
	*output = static_cast<uint8_t>(value);
	return true;
}

/** @brief Append one decimal octet without locale or allocation. */
[[nodiscard]] inline bool append_cidr_octet(uint8_t value, char **cursor, char *end) noexcept
{
	if (cursor == nullptr || *cursor == nullptr || end == nullptr || *cursor > end) {
		return false;
	}
	const auto result = std::to_chars(*cursor, end, value);
	if (result.ec != std::errc{}) {
		return false;
	}
	*cursor = result.ptr;
	return true;
}

/** @brief Append one dotted-decimal IPv4 value into reserved storage. */
[[nodiscard]] inline bool append_cidr_ipv4(uint32_t address, char **cursor, char *end) noexcept
{
	for (uint32_t index = 0; index < 4u; ++index) {
		const uint32_t shift = 24u - index * 8u;
		if (!append_cidr_octet(static_cast<uint8_t>((address >> shift) & 0xffu), cursor, end)) {
			return false;
		}
		if (index != 3u) {
			if (*cursor >= end) {
				return false;
			}
			**cursor = '.';
			++(*cursor);
		}
	}
	return true;
}

}  // namespace detail
/** @endcond */

// =============================================================================
// CIDR Types
// =============================================================================

/**
 * @brief Parsed CIDR representation.
 *
 * Represents an IPv4 network prefix in a fixed hot-path value type.
 * All values are stored in host byte order.
 *
 * Example: "192.168.1.0/24" becomes:
 *   - network: 0xC0A80100 (192.168.1.0)
 *   - mask: 0xFFFFFF00 (/24 mask)
 *   - prefix_len: 24
 *   - valid: true
 *
 * Special cases:
 *   - "0.0.0.0/0" matches all IPs (wildcard)
 *   - "10.0.0.1/32" matches exactly one IP
 */
struct alignas(8) cidr {
	uint32_t network{0};	///< Network address (host byte order)
	uint32_t mask{0};	///< Network mask (host byte order)
	uint8_t prefix_len{0};	///< Prefix length (0-32)
	bool valid{false};	///< true if successfully parsed
	uint8_t padding_[2]{};	///< Alignment padding
};

static_assert(sizeof(cidr) == 16, "cidr must retain four entries per 64-byte cache line");

// =============================================================================
// CIDR Parsing API (Cold-Path)
// =============================================================================

/**
 * @brief Parse IPv4 address from dotted-decimal notation.
 *
 * Parses strings like "192.168.1.1" or "10.0.0.255".
 * Does NOT accept CIDR notation (no slash).
 *
 * @param s Input string (e.g., "192.168.1.1")
 * @param out_ipv4 Output: parsed IP in host byte order
 * @return true on success, false on parse error
 *
 * Validation:
 * - Exactly 4 octets separated by dots
 * - Each octet 0-255
 * - No leading zeros allowed in octets
 * - No whitespace or trailing characters
 *
 * @note This is a COLD-PATH function for configuration parsing only.
 *       Do not call in packet processing hot path.
 */
[[nodiscard]] constexpr bool parse_ipv4(std::string_view s, uint32_t *out_ipv4) noexcept
{
	if (out_ipv4 == nullptr || s.empty() || s.size() > 15u) {
		return false;
	}

	uint8_t octets[4]{};
	std::size_t octet_index = 0;
	std::size_t start = 0;
	for (std::size_t index = 0; index <= s.size(); ++index) {
		if (index != s.size() && s[index] != '.') {
			continue;
		}
		const std::string_view octet(s.data() + start, index - start);
		if (octet_index >= 4u || !detail::parse_cidr_octet(octet, &octets[octet_index])) {
			return false;
		}
		++octet_index;
		start = index + 1u;
	}
	if (octet_index != 4u) {
		return false;
	}
	*out_ipv4 = (static_cast<uint32_t>(octets[0]) << 24u) | (static_cast<uint32_t>(octets[1]) << 16u) |
		    (static_cast<uint32_t>(octets[2]) << 8u) | static_cast<uint32_t>(octets[3]);
	return true;
}

/**
 * @brief Parse CIDR notation.
 *
 * Parses strings like "192.168.0.0/16" or "10.0.0.1/32".
 * If no prefix is specified, defaults to /32 (single host).
 *
 * @param s Input string (e.g., "10.0.0.0/8")
 * @return Parsed CIDR, or invalid cidr if parsing fails
 *
 * Validation:
 * - Valid IPv4 address portion
 * - Prefix length 0-32 (if specified)
 * - A missing prefix defaults to /32
 * - A slash with no prefix is invalid
 * - Returns cidr with valid=false on any error
 *
 * The returned network value preserves host bits from the input. Matching masks
 * both the candidate IP and stored network, so non-canonical host bits do not
 * affect match_cidr().
 *
 * Examples:
 * - "10.0.0.0/8" -> network=0x0A000000, mask=0xFF000000, prefix=8
 * - "192.168.1.1" -> network=0xC0A80101, mask=0xFFFFFFFF, prefix=32
 * - "0.0.0.0/0" -> network=0, mask=0, prefix=0 (any)
 *
 * @note This is a COLD-PATH function for configuration parsing only.
 */
[[nodiscard]] constexpr cidr parse_cidr(std::string_view s) noexcept
{
	cidr result{};
	if (s.empty() || s.size() > 18u) {
		return result;
	}

	const std::size_t slash = s.find('/');
	std::string_view address = s;
	std::string_view prefix;
	if (slash != std::string_view::npos) {
		const char *const begin = s.data();
		address = std::string_view(begin, slash);
		prefix = std::string_view(begin + slash + 1u, s.size() - slash - 1u);
	}
	if (slash != std::string_view::npos && (prefix.empty() || prefix.find('/') != std::string_view::npos)) {
		return result;
	}

	uint32_t parsed_address = 0;
	uint8_t parsed_prefix = 32;
	if (!parse_ipv4(address, &parsed_address) ||
	    (!prefix.empty() && !detail::parse_cidr_prefix(prefix, &parsed_prefix))) {
		return result;
	}

	result.network = parsed_address;
	result.mask = parsed_prefix == 0u ? 0u :
					    (parsed_prefix == 32u ? UINT32_MAX : UINT32_MAX << (32u - parsed_prefix));
	result.prefix_len = parsed_prefix;
	result.valid = true;
	return result;
}

/**
 * @brief Format CIDR to string.
 *
 * Converts a cidr struct back to string notation.
 * Output buffer must be at least 19 bytes ("255.255.255.255/32" + null).
 *
 * @param c CIDR to format
 * @param buf Output buffer (at least 19 bytes)
 * @param buf_len Size of output buffer
 * @return Number of characters written (excluding null), or 0 on error
 */
[[nodiscard]] inline std::size_t format_cidr(const cidr &c, char *buf, std::size_t buf_len) noexcept
{
	if (buf == nullptr || buf_len < 19u || !c.valid || c.prefix_len > 32u) {
		return 0;
	}
	char *cursor = buf;
	char *const end = buf + buf_len - 1u;
	if (!detail::append_cidr_ipv4(c.network, &cursor, end) || cursor >= end) {
		return 0;
	}
	*cursor++ = '/';
	const auto result = std::to_chars(cursor, end, c.prefix_len);
	if (result.ec != std::errc{}) {
		return 0;
	}
	cursor = result.ptr;
	*cursor = '\0';
	return static_cast<std::size_t>(cursor - buf);
}

// =============================================================================
// CIDR Matching API (Hot-Path)
// =============================================================================

/**
 * @brief Check if IP matches CIDR prefix.
 *
 * This is the HOT-PATH function for packet filtering. It performs a simple
 * bitwise AND comparison which compiles to 2-3 instructions.
 *
 * Algorithm: (ip & mask) == (network & mask)
 *
 * @param ip IP address to check (host byte order)
 * @param c CIDR prefix to match against
 * @return true if IP matches the CIDR prefix
 *
 * Complexity: fixed mask-and-compare operation.
 *
 * @note Always returns false for invalid CIDRs (c.valid == false)
 * @note Wildcard CIDR (0.0.0.0/0) matches all IPs
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr bool match_cidr(uint32_t ip, const cidr &c) noexcept
{
	if (!c.valid)
		return false;
	return (ip & c.mask) == (c.network & c.mask);
}

/**
 * @brief Check if IP falls within CIDR range (raw values).
 *
 * Same as match_cidr() but takes raw network/mask values instead of cidr struct.
 * Useful when you have pre-validated values and want to skip the valid check.
 *
 * @param ip IP address to check (host byte order)
 * @param network Network address (host byte order)
 * @param mask Network mask (host byte order)
 * @return true if IP matches
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr bool match_cidr_raw(uint32_t ip, uint32_t network,
										uint32_t mask) noexcept
{
	return (ip & mask) == (network & mask);
}

/**
 * @brief Check if one CIDR is a subset of another.
 *
 * Returns true if all IPs in 'inner' are also in 'outer'.
 * Example: 10.0.1.0/24 is a subset of 10.0.0.0/16
 *
 * @param inner The potentially smaller CIDR
 * @param outer The potentially larger CIDR
 * @return true if inner is contained within outer
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr bool cidr_contains(const cidr &inner,
									       const cidr &outer) noexcept
{
	if (!inner.valid || !outer.valid)
		return false;
	// Inner prefix must be at least as specific as outer
	if (inner.prefix_len < outer.prefix_len)
		return false;
	// Inner network must match outer's prefix
	return (inner.network & outer.mask) == (outer.network & outer.mask);
}

// =============================================================================
// IPv4 String Formatting (Cold-Path)
// =============================================================================

/**
 * @brief Format IPv4 address to dotted-decimal string.
 *
 * @param ip IP address (host byte order)
 * @param buf Output buffer (at least 16 bytes: "255.255.255.255" + null)
 * @param buf_len Size of output buffer
 * @return Number of characters written (excluding null), or 0 on error
 */
[[nodiscard]] inline std::size_t format_ipv4(uint32_t ip, char *buf, std::size_t buf_len) noexcept
{
	if (buf == nullptr || buf_len < 16u) {
		return 0;
	}
	char *cursor = buf;
	char *const end = buf + buf_len - 1u;
	if (!detail::append_cidr_ipv4(ip, &cursor, end)) {
		return 0;
	}
	*cursor = '\0';
	return static_cast<std::size_t>(cursor - buf);
}

}  // namespace kinetum::algo
