// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file bits.hpp
 * @brief Bit manipulation utilities.
 * @author Fleming Patel
 *
 * Contains:
 * - Popcount: Count set bits
 * - CLZ/CTZ: Count leading/trailing zeros
 * - Power of 2 utilities
 * - Bit masking helpers
 *
 * All functions are constexpr on both supported little-endian target tuples.
 */

#include <cstdint>
#include <type_traits>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

// =============================================================================
// Population Count (Count Set Bits)
// =============================================================================

/**
 * @brief Count number of set bits in a 32-bit integer.
 * @param x Value to inspect.
 * @return Number of set bits in @p x.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr int popcount32(uint32_t x) noexcept
{
	return __builtin_popcount(x);
}

/**
 * @brief Count number of set bits in a 64-bit integer.
 * @param x Value to inspect.
 * @return Number of set bits in @p x.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr int popcount64(uint64_t x) noexcept
{
	return __builtin_popcountll(x);
}

// =============================================================================
// Count Leading/Trailing Zeros
// =============================================================================

/**
 * @brief Count leading zeros in a 32-bit integer.
 * @param x Value to inspect.
 * @return Number of leading zeros (0-32). Returns 32 if x == 0.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr int clz32(uint32_t x) noexcept
{
	if (x == 0)
		return 32;
	return __builtin_clz(x);
}

/**
 * @brief Count leading zeros in a 64-bit integer.
 * @param x Value to inspect.
 * @return Number of leading zeros (0-64). Returns 64 if x == 0.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr int clz64(uint64_t x) noexcept
{
	if (x == 0)
		return 64;
	return __builtin_clzll(x);
}

/**
 * @brief Count trailing zeros in a 32-bit integer.
 * @param x Value to inspect.
 * @return Number of trailing zeros (0-32). Returns 32 if x == 0.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr int ctz32(uint32_t x) noexcept
{
	if (x == 0)
		return 32;
	return __builtin_ctz(x);
}

/**
 * @brief Count trailing zeros in a 64-bit integer.
 * @param x Value to inspect.
 * @return Number of trailing zeros (0-64). Returns 64 if x == 0.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr int ctz64(uint64_t x) noexcept
{
	if (x == 0)
		return 64;
	return __builtin_ctzll(x);
}

// =============================================================================
// Power of 2 Utilities
// =============================================================================

/**
 * @brief Check if value is a power of 2.
 * @tparam T Integral value type.
 * @param x Value to inspect.
 * @return True only when @p x is a positive power of two.
 */
template <typename T>
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr bool is_power_of_2(T x) noexcept
{
	static_assert(std::is_integral_v<T>, "T must be integral");
	return x > 0 && (x & (x - 1)) == 0;
}

/**
 * @brief Round up to next power of 2.
 * @param x Input value (0 returns 1)
 * @return Smallest power of 2 >= x, or 0 if overflow would occur
 *
 * @note Returns 0 for inputs > 0x80000000 (would overflow uint32_t).
 *       Callers should check for 0 return on large inputs.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr uint32_t next_power_of_2_32(uint32_t x) noexcept
{
	if (x == 0)
		return 1;
	// Already a power of 2?
	if (is_power_of_2(x))
		return x;
	// Overflow protection: if x > 2^31, next power of 2 would be 2^32 which overflows
	if (x > (uint32_t{1} << 31))
		return 0;
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	return x + 1;
}

/**
 * @brief Round up to next power of 2.
 * @param x Input value (0 returns 1)
 * @return Smallest power of 2 >= x, or 0 if overflow would occur
 *
 * @note Returns 0 for inputs > 0x8000000000000000 (would overflow uint64_t).
 *       Callers should check for 0 return on large inputs.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr uint64_t next_power_of_2_64(uint64_t x) noexcept
{
	if (x == 0)
		return 1;
	// Already a power of 2?
	if (is_power_of_2(x))
		return x;
	// Overflow protection: if x > 2^63, next power of 2 would be 2^64 which overflows
	if (x > (uint64_t{1} << 63))
		return 0;
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	x |= x >> 32;
	return x + 1;
}

/**
 * @brief Calculate log2 of a power-of-2 value.
 * @param x Must be a power of 2
 * @return log2(x), or -1 when @p x is zero or not a power of two.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr int log2_of_power_of_2(uint64_t x) noexcept
{
	if (!is_power_of_2(x)) {
		return -1;
	}
	return 63 - clz64(x);
}

// =============================================================================
// Bit Masking
// =============================================================================

/**
 * @brief Create a bitmask with n bits set.
 * @param n Number of bits (0-64)
 * @return Mask with n lowest bits set
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr uint64_t bitmask(int n) noexcept
{
	if (n >= 64)
		return ~uint64_t{0};
	if (n <= 0)
		return 0;
	return (uint64_t{1} << n) - 1;
}

/**
 * @brief Extract bits [lo, hi) from value.
 * @param x Source value
 * @param lo Low bit (inclusive)
 * @param hi High bit (exclusive)
 * @return Extracted bits shifted to position zero, or zero when the requested
 *         half-open range is not contained in `[0, 64]`.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr uint64_t extract_bits(uint64_t x, int lo, int hi) noexcept
{
	if (lo < 0 || hi <= lo || lo >= 64 || hi > 64) {
		return 0u;
	}
	return (x >> lo) & bitmask(hi - lo);
}

}  // namespace kinetum::algo
