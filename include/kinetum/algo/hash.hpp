// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file hash.hpp
 * @brief Consumed noncryptographic hash constants and integer mixing.
 * @author Fleming Patel
 *
 * FNV-1a constants support module-owned field-wise hashers. `splitmix64`
 * supplies deterministic integer mixing for cuckoo-table candidate locations.
 * This header deliberately provides no raw-object, generic flow-key, shard, or
 * hash-combine policy.
 *
 * The same definitions serve both supported little-endian target tuples.
 */

#include <cstdint>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

// =============================================================================
// FNV-1a Hash (Fowler-Noll-Vo)
// =============================================================================
// These constants are not cryptographic identity primitives.

/** FNV-1a 64-bit offset basis. */
constexpr uint64_t FNV1A_OFFSET_BASIS = 14695981039346656037ULL;

/** FNV-1a 64-bit prime. */
constexpr uint64_t FNV1A_PRIME = 1099511628211ULL;

// =============================================================================
// SplitMix64 Integer Mixing
// =============================================================================

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{
/** Fixed private SplitMix64 increment. */
inline constexpr uint64_t SPLIT_MIX_GAMMA = UINT64_C(0x9e3779b97f4a7c15);
}  // namespace detail
/** @endcond */

/**
 * @brief SplitMix64 integer mixing function.
 *
 * Transforms any 64-bit input into a well-distributed 64-bit hash.
 * Has full avalanche: every input bit affects every output bit.
 *
 * @param x Input value
 * @return Mixed hash value
 */
KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr uint64_t splitmix64(uint64_t x) noexcept
{
	x += detail::SPLIT_MIX_GAMMA;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
	return x ^ (x >> 31);
}

}  // namespace kinetum::algo
