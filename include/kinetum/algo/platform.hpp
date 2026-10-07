// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file platform.hpp
 * @brief Public platform detection and feature macros for Kinetum algorithms.
 * @author Fleming Patel
 *
 * Kinetum supports GNU-compatible little-endian x86-64 and AArch64 builds.
 * SIMD feature selection remains compile-time and may choose scalar
 * implementations within either supported architecture; it never admits
 * another target architecture.
 */

#if !defined(__GNUC__) && !defined(__clang__)
#error "Kinetum requires a GNU-compatible compiler"
#endif

#if !defined(__x86_64__) && !defined(__aarch64__)
#error "Kinetum supports only x86-64 and AArch64 target architectures"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Kinetum supports only little-endian target architectures"
#endif

#include <cstddef>
#include <cstdint>
#include <limits>

// =============================================================================
// SIMD Feature Detection
// =============================================================================

#if defined(__AVX512F__)
/** Compile-selected AVX-512 feature availability. */
#define KINETUM_HAS_AVX512 1
#endif

#if defined(__AVX2__)
/** Compile-selected AVX2 feature availability. */
#define KINETUM_HAS_AVX2 1
#endif

#if defined(__SSE4_2__)
/** Compile-selected SSE4.2 feature availability. */
#define KINETUM_HAS_SSE42 1
#endif

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
/** Compile-selected AArch64 NEON feature availability. */
#define KINETUM_HAS_NEON 1
#endif

// =============================================================================
// Branch Prediction Hints
// =============================================================================

/** Mark one expression as the expected branch outcome. */
#define KINETUM_LIKELY(x) __builtin_expect(!!(x), 1)

/** Mark one expression as the unexpected branch outcome. */
#define KINETUM_UNLIKELY(x) __builtin_expect(!!(x), 0)

// =============================================================================
// Function Attributes
// =============================================================================

/** Require inlining of one small hot-path function. */
#define KINETUM_ALWAYS_INLINE __attribute__((always_inline)) inline

/** Prevent inlining where a stable out-of-line boundary is required. */
#define KINETUM_NOINLINE __attribute__((noinline))

/** Mark a function as execution-frequency hot. */
#define KINETUM_HOT __attribute__((hot))

/** Mark a function as execution-frequency cold. */
#define KINETUM_COLD __attribute__((cold))

/** Declare a function whose result depends only on arguments and readable memory. */
#define KINETUM_PURE __attribute__((pure))

/** Declare a function whose result depends only on its arguments. */
#define KINETUM_CONST __attribute__((const))

/** Permit aggressive flattening of one intentionally compact call graph. */
#define KINETUM_FLATTEN __attribute__((flatten))

// =============================================================================
// Cache Line Size
// =============================================================================

namespace kinetum::algo
{

/** Cache-line size used by Kinetum's supported little-endian target tuples. */
inline constexpr std::size_t CACHE_LINE_SIZE = 64;

/** Low address bits below one Kinetum cache-line boundary. */
inline constexpr std::size_t CACHE_LINE_MASK = CACHE_LINE_SIZE - 1;

/**
 * @brief Return whether one nonnull pointer starts on a cache-line boundary.
 * @param ptr Candidate pointer.
 * @return True only for a nonnull aligned address.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr bool is_cache_aligned(const void *ptr) noexcept
{
	return ptr != nullptr && (reinterpret_cast<std::uintptr_t>(ptr) & CACHE_LINE_MASK) == 0;
}

/**
 * @brief Align a byte count up to the next cache-line boundary.
 * @param size Candidate byte count.
 * @return Aligned count, or zero when the addition is not representable.
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr std::size_t align_to_cache_line(std::size_t size) noexcept
{
	if (size > std::numeric_limits<std::size_t>::max() - CACHE_LINE_MASK) {
		return 0u;
	}
	return (size + CACHE_LINE_MASK) & ~CACHE_LINE_MASK;
}

}  // namespace kinetum::algo
