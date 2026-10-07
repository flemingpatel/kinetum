// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file simd_classify.hpp
 * @brief SIMD-accelerated batch packet classification.
 * @author Fleming Patel
 *
 * Provides vectorized classification for:
 * - CIDR matching (batch of IP addresses against prefix)
 * - ACL rule matching (batch of 5-tuples against rules)
 * - Port range matching (batch of ports against range)
 *
 * Supports:
 * - AVX-512: 16 packets/iteration (512-bit registers)
 * - AVX2: 8 packets/iteration (256-bit registers)
 * - SSE4.2: 4 packets/iteration (128-bit registers)
 * - NEON: 4 packets/iteration (128-bit registers)
 * - Scalar: feature-independent path on little-endian x86-64 and AArch64
 *
 * Design:
 * - Process bounded SoA batches rather than individual AoS objects
 * - Prefetch only an already bounded following vector
 * - Allocate nothing; every input and output extent belongs to the caller
 * - Preserve one scalar predicate across every architecture-selected path
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <kinetum/algo/platform.hpp>

// Include SIMD headers based on platform
#if defined(KINETUM_HAS_AVX512)
#include <immintrin.h>
#elif defined(KINETUM_HAS_AVX2)
#include <immintrin.h>
#elif defined(KINETUM_HAS_SSE42)
#include <nmmintrin.h>
#endif

#if defined(KINETUM_HAS_NEON)
#include <arm_neon.h>
#endif

#include <kinetum/algo/net.hpp>
#include <kinetum/algo/prefetch.hpp>

namespace kinetum::algo
{

// =============================================================================
// Batch Classification Result
// =============================================================================

/**
 * @brief Bitmask result for batch classification.
 *
 * Each bit corresponds to one packet in the batch.
 * Bit N = 1 means packet N matched.
 */
using classify_mask_t = uint64_t;

/** Maximum packet count representable by one classification mask. */
inline constexpr std::size_t MAX_BATCH_SIZE = 64;

// =============================================================================
// Safe Bitmask Generation
// =============================================================================

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/**
 * @brief Create a bitmask with 'count' lowest bits set.
 *
 * Returns ~0ULL for count >= 64, avoiding UB from shifting by >= 64.
 * This is the canonical way to create packet masks in the platform.
 *
 * @param count Number of bits to set (0-64)
 * @return Bitmask with count lowest bits set
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr classify_mask_t make_count_mask(std::size_t count) noexcept
{
	// Shifting by 64 is UB in C++, so use conditional
	// Note: Compiler optimizes this to a single cmov on x86
	return (count >= MAX_BATCH_SIZE) ? ~classify_mask_t{0} : (classify_mask_t{1} << count) - 1;
}

}  // namespace detail
/** @endcond */

// =============================================================================
// CIDR Batch Matching
// =============================================================================

/**
 * @brief Match batch of IP addresses against CIDR prefix.
 *
 * @param ips Array of IP addresses in host byte order; nonnull when the bounded
 *        count is nonzero.
 * @param count Number of IPs to check; values above 64 are clamped to 64.
 * @param network Network address in host byte order. Host bits outside
 *        @p mask are ignored.
 * @param mask Network mask (e.g., 0xFFFFFF00 for /24)
 * @return Bitmask where bit N = 1 if ips[N] matches CIDR
 *
 * Performance:
 * - AVX-512: 16 IPs per iteration
 * - AVX2: 8 IPs per iteration
 * - SSE/NEON: 4 IPs per iteration
 * - Scalar: 1 IP per iteration
 */
KINETUM_HOT
inline classify_mask_t match_cidr_batch(const uint32_t *ips, std::size_t count, uint32_t network,
					uint32_t mask) noexcept
{
	const uint32_t lane_count = static_cast<uint32_t>((count > MAX_BATCH_SIZE) ? MAX_BATCH_SIZE : count);
	const uint32_t masked_network = network & mask;
	classify_mask_t result = 0;

#if defined(KINETUM_HAS_AVX512)
	// AVX-512: Process 16 IPs at a time
	const __m512i vmask = _mm512_set1_epi32(static_cast<int32_t>(mask));
	const __m512i vnetwork = _mm512_set1_epi32(static_cast<int32_t>(masked_network));

	uint32_t i = 0;
	for (; lane_count - i >= 16u; i += 16u) {
		// Prefetch next batch
		if (lane_count - i >= 32u) {
			KINETUM_PREFETCH_L1(&ips[i + 16]);
		}

		__m512i vips = _mm512_loadu_si512(reinterpret_cast<const __m512i *>(&ips[i]));
		__m512i masked = _mm512_and_si512(vips, vmask);
		__mmask16 match = _mm512_cmpeq_epi32_mask(masked, vnetwork);
		result |= (static_cast<classify_mask_t>(match) << i);
	}

	// Handle remaining with scalar
	for (; i < lane_count; ++i) {
		if ((ips[i] & mask) == masked_network) {
			result |= (1ULL << i);
		}
	}

#elif defined(KINETUM_HAS_AVX2)
	// AVX2: Process 8 IPs at a time
	const __m256i vmask = _mm256_set1_epi32(static_cast<int32_t>(mask));
	const __m256i vnetwork = _mm256_set1_epi32(static_cast<int32_t>(masked_network));

	uint32_t i = 0;
	for (; lane_count - i >= 8u; i += 8u) {
		// Prefetch next batch
		if (lane_count - i >= 16u) {
			KINETUM_PREFETCH_L1(&ips[i + 8]);
		}

		__m256i vips = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&ips[i]));
		__m256i masked = _mm256_and_si256(vips, vmask);
		__m256i cmp = _mm256_cmpeq_epi32(masked, vnetwork);
		int match = _mm256_movemask_ps(_mm256_castsi256_ps(cmp));
		result |= (static_cast<classify_mask_t>(match) << i);
	}

	// Handle remaining with scalar
	for (; i < lane_count; ++i) {
		if ((ips[i] & mask) == masked_network) {
			result |= (1ULL << i);
		}
	}

#elif defined(KINETUM_HAS_SSE42)
	// SSE4.2: Process 4 IPs at a time
	const __m128i vmask = _mm_set1_epi32(static_cast<int32_t>(mask));
	const __m128i vnetwork = _mm_set1_epi32(static_cast<int32_t>(masked_network));

	uint32_t i = 0;
	for (; lane_count - i >= 4u; i += 4u) {
		// Prefetch next batch
		if (lane_count - i >= 8u) {
			KINETUM_PREFETCH_L1(&ips[i + 4]);
		}

		__m128i vips = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&ips[i]));
		__m128i masked = _mm_and_si128(vips, vmask);
		__m128i cmp = _mm_cmpeq_epi32(masked, vnetwork);
		int match = _mm_movemask_ps(_mm_castsi128_ps(cmp));
		result |= (static_cast<classify_mask_t>(match) << i);
	}

	// Handle remaining with scalar
	for (; i < lane_count; ++i) {
		if ((ips[i] & mask) == masked_network) {
			result |= (1ULL << i);
		}
	}

#elif defined(KINETUM_HAS_NEON)
	// NEON: Process 4 IPs at a time
	const uint32x4_t vmask = vdupq_n_u32(mask);
	const uint32x4_t vnetwork = vdupq_n_u32(masked_network);

	// Weights for collecting mask bits via horizontal add (hoisted out of loop)
	// Position weights: byte 0 -> bit 0, byte 2 -> bit 1, byte 4 -> bit 2, byte 6 -> bit 3
	static const uint8_t weight_data[8] = {1, 0, 2, 0, 4, 0, 8, 0};
	const uint8x8_t weights = vld1_u8(weight_data);

	uint32_t i = 0;
	for (; lane_count - i >= 4u; i += 4u) {
		// Prefetch next batch
		if (lane_count - i >= 8u) {
			KINETUM_PREFETCH_L1(&ips[i + 4]);
		}

		uint32x4_t vips = vld1q_u32(&ips[i]);
		uint32x4_t masked = vandq_u32(vips, vmask);
		uint32x4_t cmp = vceqq_u32(masked, vnetwork);

		// Efficient NEON movemask equivalent using vshrn/vget_lane pattern:
		// vceqq_u32 produces 0xFFFFFFFF for match, 0x00000000 for no match.
		//
		// Strategy: Use vshrn (shift-right-narrow) to compress comparison
		// results, then use horizontal add with weights to collect bits.
		//
		// Step 1: vshrn_n_u32 shifts right 16 and narrows 32->16 bit
		//         0xFFFFFFFF -> 0xFFFF, 0x00000000 -> 0x0000
		// Step 2: Reinterpret as bytes and AND with position weights
		// Step 3: Horizontal add (vaddv_u8) to collect into single value
		//
		// This reduces 4 vgetq_lane calls to 1 horizontal add.
		uint16x4_t narrow16 = vshrn_n_u32(cmp, 16);

		// Reinterpret the 4x16-bit values as 8x8-bit
		// Each matching lane has 0xFFFF, non-matching has 0x0000
		// As bytes: [0xFF, 0xFF, ...] for match, [0x00, 0x00, ...] for no match
		// We only need one byte per lane, so weights mask to even bytes only
		uint8x8_t bytes = vreinterpret_u8_u16(narrow16);
		uint8x8_t weighted = vand_u8(bytes, weights);
		uint32_t match = vaddv_u8(weighted);

		result |= (static_cast<classify_mask_t>(match) << i);
	}

	// Handle remaining with scalar
	for (; i < lane_count; ++i) {
		if ((ips[i] & mask) == masked_network) {
			result |= (1ULL << i);
		}
	}

#else
	// Scalar implementation on a supported target architecture.
	for (uint32_t i = 0; i < lane_count; ++i) {
		if ((ips[i] & mask) == masked_network) {
			result |= (1ULL << i);
		}
	}
#endif

	return result;
}

// =============================================================================
// Port Range Batch Matching
// =============================================================================

/**
 * @brief Match batch of ports against range.
 *
 * @param ports Array of port numbers; nonnull when the bounded count is nonzero.
 * @param count Number of ports to check; values above 64 are clamped to 64.
 * @param port_min Minimum port (inclusive)
 * @param port_max Maximum port (inclusive)
 * @return Bitmask where bit N = 1 if ports[N] is in range, or zero for an
 *         inverted range.
 */
KINETUM_HOT
inline classify_mask_t match_port_range_batch(const uint16_t *ports, std::size_t count, uint16_t port_min,
					      uint16_t port_max) noexcept
{
	const uint32_t lane_count = static_cast<uint32_t>((count > MAX_BATCH_SIZE) ? MAX_BATCH_SIZE : count);
	if (port_min > port_max) {
		return 0;
	}
	classify_mask_t result = 0;

#if defined(KINETUM_HAS_AVX2)
	// AVX2: Process 16 ports at a time (16x 16-bit in 256-bit register)
	// Use sign bias trick for unsigned comparison: XOR with 0x8000 converts
	// unsigned [0, 65535] to signed [-32768, 32767] while preserving order.
	// This allows using signed _mm256_cmpgt_epi16 for unsigned comparisons.
	const __m256i sign_bias = _mm256_set1_epi16(static_cast<int16_t>(0x8000));
	const __m256i all_lanes = _mm256_set1_epi16(static_cast<int16_t>(-1));
	const __m256i vmin_biased = _mm256_xor_si256(_mm256_set1_epi16(static_cast<int16_t>(port_min)), sign_bias);
	const __m256i vmax_biased = _mm256_xor_si256(_mm256_set1_epi16(static_cast<int16_t>(port_max)), sign_bias);

	uint32_t i = 0;
	for (; lane_count - i >= 16u; i += 16u) {
		__m256i vports = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&ports[i]));

		// Convert ports to signed range for comparison
		__m256i vports_biased = _mm256_xor_si256(vports, sign_bias);

		// Signed greater-than plus bitwise inversion implements inclusive
		// comparison without subtracting from INT16_MIN or adding to INT16_MAX.
		const __m256i cmp_min = _mm256_andnot_si256(_mm256_cmpgt_epi16(vmin_biased, vports_biased), all_lanes);
		const __m256i cmp_max = _mm256_andnot_si256(_mm256_cmpgt_epi16(vports_biased, vmax_biased), all_lanes);
		__m256i in_range = _mm256_and_si256(cmp_min, cmp_max);

		// Pack to bytes and get mask
		int match = _mm256_movemask_epi8(in_range);
		// Each 16-bit comparison produces 2 bytes, extract even bits
		uint32_t mask16 = 0;
		for (int j = 0; j < 16; ++j) {
			if (match & (1 << (j * 2))) {
				mask16 |= (1U << j);
			}
		}
		result |= (static_cast<classify_mask_t>(mask16) << i);
	}

	// Handle remaining with scalar
	for (; i < lane_count; ++i) {
		if (ports[i] >= port_min && ports[i] <= port_max) {
			result |= (1ULL << i);
		}
	}

#else
	// Scalar implementation when this operation has no selected vector body.
	for (uint32_t i = 0; i < lane_count; ++i) {
		if (ports[i] >= port_min && ports[i] <= port_max) {
			result |= (1ULL << i);
		}
	}
#endif

	return result;
}

// =============================================================================
// Protocol Batch Matching
// =============================================================================

/**
 * @brief Match batch of protocols against target.
 *
 * @param protocols Array of protocol numbers; nonnull when the bounded count
 *        is nonzero.
 * @param count Number of protocols to check; values above 64 are clamped to 64.
 * @param target Target protocol (0 = any)
 * @return Bitmask where bit N = 1 if protocols[N] matches
 */
KINETUM_HOT
inline classify_mask_t match_protocol_batch(const uint8_t *protocols, std::size_t count, uint8_t target) noexcept
{
	const uint32_t lane_count = static_cast<uint32_t>((count > MAX_BATCH_SIZE) ? MAX_BATCH_SIZE : count);

	// Protocol 0 means "any" - match all
	if (target == 0) {
		return detail::make_count_mask(lane_count);
	}

	classify_mask_t result = 0;

#if defined(KINETUM_HAS_AVX2)
	// AVX2: Process 32 protocols at a time
	const __m256i vtarget = _mm256_set1_epi8(static_cast<char>(target));

	uint32_t i = 0;
	for (; lane_count - i >= 32u; i += 32u) {
		__m256i vprotos = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&protocols[i]));
		__m256i cmp = _mm256_cmpeq_epi8(vprotos, vtarget);
		uint32_t match = static_cast<uint32_t>(_mm256_movemask_epi8(cmp));
		result |= (static_cast<classify_mask_t>(match) << i);
	}

	// Handle remaining with scalar
	for (; i < lane_count; ++i) {
		if (protocols[i] == target) {
			result |= (1ULL << i);
		}
	}

#else
	// Scalar implementation on a supported target architecture.
	for (uint32_t i = 0; i < lane_count; ++i) {
		if (protocols[i] == target) {
			result |= (1ULL << i);
		}
	}
#endif

	return result;
}

// =============================================================================
// Batch 5-Tuple Structure
// =============================================================================

/**
 * @brief Structure-of-Arrays layout for batch classification.
 *
 * SoA layout enables SIMD vectorization across packets.
 * Each array holds one field for all packets in the batch.
 *
 * Usage:
 * @code
 * packet_batch_soa batch;
 * batch.count = num_packets;
 * for (int i = 0; i < num_packets; ++i) {
 *     batch.src_ips[i] = packets[i].src_ip;
 *     batch.dst_ips[i] = packets[i].dst_ip;
 *     // ... etc
 * }
 * classify_mask_t result = classify_batch_5tuple(batch, rule);
 * @endcode
 */
struct alignas(CACHE_LINE_SIZE) packet_batch_soa {
	/** Number of populated packet lanes, with public classifiers bounded to 64. */
	std::size_t count{0};

	/** Source IPv4 addresses in host byte order. */
	alignas(64) std::array<uint32_t, MAX_BATCH_SIZE> src_ips{};

	/** Destination IPv4 addresses in host byte order. */
	alignas(64) std::array<uint32_t, MAX_BATCH_SIZE> dst_ips{};

	/** Source transport ports. */
	alignas(64) std::array<uint16_t, MAX_BATCH_SIZE> src_ports{};

	/** Destination transport ports. */
	alignas(64) std::array<uint16_t, MAX_BATCH_SIZE> dst_ports{};

	/** IPv4 protocol bytes. */
	alignas(64) std::array<uint8_t, MAX_BATCH_SIZE> protocols{};
};

// =============================================================================
// ACL Rule for Batch Classification
// =============================================================================

/**
 * @brief Single ACL rule for batch classification.
 *
 * Designed for SIMD evaluation - all fields are scalar constants
 * that get broadcast to SIMD registers.
 */
struct acl_rule_simd {
	uint32_t src_network{0};       ///< Source network address
	uint32_t src_mask{0};	       ///< Source network mask
	uint32_t dst_network{0};       ///< Destination network address
	uint32_t dst_mask{0};	       ///< Destination network mask
	uint16_t src_port_min{0};      ///< Source port range min
	uint16_t src_port_max{65535};  ///< Source port range max
	uint16_t dst_port_min{0};      ///< Destination port range min
	uint16_t dst_port_max{65535};  ///< Destination port range max
	uint8_t protocol{0};	       ///< Protocol (0 = any)
	uint8_t action{0};	       ///< Caller-defined action byte copied to matching lanes.
};

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/**
 * @brief Return whether one rule constrains either transport-port lane.
 *
 * @param rule Prevalidated SIMD rule.
 * @return True when at least one inclusive port range is narrower than any.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr bool
acl_rule_has_port_filter(const acl_rule_simd &rule) noexcept
{
	return rule.src_port_min != 0u || rule.src_port_max != UINT16_MAX || rule.dst_port_min != 0u ||
	       rule.dst_port_max != UINT16_MAX;
}

/**
 * @brief Classify transport-protocol lanes once for a complete packet batch.
 *
 * @param batch Prevalidated packet batch.
 * @return Mask containing exactly TCP and UDP packet lanes.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE classify_mask_t transport_protocol_mask(const packet_batch_soa &batch) noexcept
{
	const uint32_t lane_count = static_cast<uint32_t>(batch.count > MAX_BATCH_SIZE ? MAX_BATCH_SIZE : batch.count);
	classify_mask_t result = 0u;
#if defined(KINETUM_HAS_AVX2)
	const __m256i tcp = _mm256_set1_epi8(static_cast<char>(net::protocol::TCP));
	const __m256i udp = _mm256_set1_epi8(static_cast<char>(net::protocol::UDP));
	uint32_t index = 0u;
	for (; lane_count - index >= 32u; index += 32u) {
		const __m256i protocols =
			_mm256_loadu_si256(reinterpret_cast<const __m256i *>(&batch.protocols[index]));
		const __m256i transport =
			_mm256_or_si256(_mm256_cmpeq_epi8(protocols, tcp), _mm256_cmpeq_epi8(protocols, udp));
		result |= static_cast<classify_mask_t>(static_cast<uint32_t>(_mm256_movemask_epi8(transport))) << index;
	}
	for (; index < lane_count; ++index) {
		if (batch.protocols[index] == net::protocol::TCP || batch.protocols[index] == net::protocol::UDP) {
			result |= classify_mask_t{1} << index;
		}
	}
#else
	for (uint32_t index = 0u; index < lane_count; ++index) {
		if (batch.protocols[index] == net::protocol::TCP || batch.protocols[index] == net::protocol::UDP) {
			result |= classify_mask_t{1} << index;
		}
	}
#endif
	return result;
}

/**
 * @brief Classify one rule using one already-derived transport-lane mask.
 *
 * Port fields are meaningful only for TCP and UDP. Non-transport lanes retain
 * the scalar ACL rule semantics and are unaffected by authored port ranges.
 *
 * @param batch Packet batch in SoA layout.
 * @param rule Prevalidated SIMD rule.
 * @param transport_mask Exact TCP-or-UDP lanes for @p batch.
 * @return Bitmask where bit N is one exactly when lane N matches @p rule.
 */
[[nodiscard]] KINETUM_HOT inline classify_mask_t
classify_batch_rule_with_transport(const packet_batch_soa &batch, const acl_rule_simd &rule,
				   classify_mask_t transport_mask) noexcept
{
	classify_mask_t result = make_count_mask(batch.count);

	if (rule.src_mask != 0u) {
		result &= match_cidr_batch(batch.src_ips.data(), batch.count, rule.src_network, rule.src_mask);
	}
	if (result == 0u) {
		return 0u;
	}

	if (rule.dst_mask != 0u) {
		result &= match_cidr_batch(batch.dst_ips.data(), batch.count, rule.dst_network, rule.dst_mask);
	}
	if (result == 0u) {
		return 0u;
	}

	if (rule.protocol != 0u) {
		result &= match_protocol_batch(batch.protocols.data(), batch.count, rule.protocol);
	}
	if (result == 0u) {
		return 0u;
	}

	if (rule.src_port_min != 0u || rule.src_port_max != UINT16_MAX) {
		const classify_mask_t port_matches = match_port_range_batch(batch.src_ports.data(), batch.count,
									    rule.src_port_min, rule.src_port_max);
		result &= (~transport_mask | port_matches);
	}
	if (result == 0u) {
		return 0u;
	}

	if (rule.dst_port_min != 0u || rule.dst_port_max != UINT16_MAX) {
		const classify_mask_t port_matches = match_port_range_batch(batch.dst_ports.data(), batch.count,
									    rule.dst_port_min, rule.dst_port_max);
		result &= (~transport_mask | port_matches);
	}

	return result;
}

}  // namespace detail
/** @endcond */

/**
 * @brief Classify batch of packets against single ACL rule.
 *
 * Evaluates all packets in batch against one rule using SIMD.
 *
 * @param batch Packet batch in SoA layout
 * @param rule ACL rule to match. Port ranges constrain TCP and UDP lanes only.
 * @return Bitmask where bit N = 1 if packet N matches rule
 */
KINETUM_HOT
inline classify_mask_t classify_batch_rule(const packet_batch_soa &batch, const acl_rule_simd &rule) noexcept
{
	const classify_mask_t transport_mask =
		detail::acl_rule_has_port_filter(rule) ? detail::transport_protocol_mask(batch) : 0u;
	return detail::classify_batch_rule_with_transport(batch, rule, transport_mask);
}

/**
 * @brief Classify batch of packets against multiple ACL rules.
 *
 * Evaluates batch against ruleset in priority order.
 * Returns action for first matching rule per packet.
 *
 * @param batch Packet batch in SoA layout
 * @param rules Array of ACL rules sorted by priority, highest first; nonnull
 *        when both the bounded batch count and @p num_rules are nonzero.
 * @param num_rules Number of rules
 * @param out_actions Output array for caller-defined action bytes, nonnull
 *        when the bounded batch count is nonzero. The function writes
 *        `min(batch.count, MAX_BATCH_SIZE)` entries.
 * @param default_action Caller-defined action byte for non-matching packets.
 *
 * A zero-count batch returns before reading either pointer and writes nothing.
 */
KINETUM_HOT
inline void classify_batch_acl(const packet_batch_soa &batch, const acl_rule_simd *rules, std::size_t num_rules,
			       uint8_t *out_actions, uint8_t default_action) noexcept
{
	const uint32_t lane_count =
		static_cast<uint32_t>((batch.count > MAX_BATCH_SIZE) ? MAX_BATCH_SIZE : batch.count);
	if (lane_count == 0u) {
		return;
	}

	// Initialize all to default action
	std::memset(out_actions, default_action, lane_count);

	// Track which packets have been classified (use safe mask helper)
	classify_mask_t classified = 0;
	const classify_mask_t all_classified = detail::make_count_mask(lane_count);
	classify_mask_t transport_mask = 0u;
	bool transport_mask_ready = false;

	// Evaluate rules in priority order
	for (std::size_t r = 0; r < num_rules && classified != all_classified; ++r) {
		const auto &rule = rules[r];
		if (!transport_mask_ready && detail::acl_rule_has_port_filter(rule)) {
			transport_mask = detail::transport_protocol_mask(batch);
			transport_mask_ready = true;
		}

		// Get packets matching this rule (excluding already classified)
		classify_mask_t matches = detail::classify_batch_rule_with_transport(batch, rule, transport_mask) &
					  ~classified;

		// Apply action to matching packets
		if (matches != 0) {
			for (uint32_t i = 0; i < lane_count; ++i) {
				if (matches & (1ULL << i)) {
					out_actions[i] = rule.action;
				}
			}
			classified |= matches;
		}
	}
}

}  // namespace kinetum::algo
