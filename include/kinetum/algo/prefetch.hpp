// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file prefetch.hpp
 * @brief Fixed-cost compiler cache-prefetch hints.
 * @author Fleming Patel
 *
 * Exposes only direct read-locality, non-temporal, and write-prefetch macros.
 * Each invocation emits one compiler hint for the caller-supplied address;
 * correctness and ordering never depend on whether hardware acts on it.
 */

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

// =============================================================================
// Prefetch Macros
// =============================================================================
// __builtin_prefetch(addr, rw, locality)
//   addr: address to prefetch
//   rw: 0 = read, 1 = write
//   locality: 0 = NTA (non-temporal), 1 = L3, 2 = L2, 3 = L1

/** Prefetch for immediate read reuse at the highest locality. */
#define KINETUM_PREFETCH_L1(addr) __builtin_prefetch((addr), 0, 3)

/** Prefetch for near-term read reuse at medium locality. */
#define KINETUM_PREFETCH_L2(addr) __builtin_prefetch((addr), 0, 2)

/** Prefetch for later read reuse at low locality. */
#define KINETUM_PREFETCH_L3(addr) __builtin_prefetch((addr), 0, 1)

/** Prefetch one non-temporal streaming read. */
#define KINETUM_PREFETCH_NTA(addr) __builtin_prefetch((addr), 0, 0)

/** Prefetch one address for an imminent write. */
#define KINETUM_PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)

}  // namespace kinetum::algo
