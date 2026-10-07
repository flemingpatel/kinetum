// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file algo.hpp
 * @brief Master include for all Kinetum algorithm utilities.
 * @author Fleming Patel
 *
 * This header includes all algorithm components:
 * - aligned_atomic.hpp: Cache-line-isolated lock-free integral atomics
 * - bits.hpp: Bit manipulation (popcount, clz, power of 2)
 * - platform.hpp: Platform detection and macros
 * - hash.hpp: FNV-1a constants and SplitMix64 integer mixing
 * - atomic_index_pool.hpp: Bounded concurrent compact-index acquisition and retirement
 * - bounded_index_pool.hpp: Fixed-capacity owner-local compact-index recycling
 * - bounded_service_order.hpp: Fair bounded service with unfinished allowances
 * - compact_index_set.hpp: Fixed-universe dense compact-index membership
 * - prefetch.hpp: Fixed-cost compiler prefetch hints
 * - signal.hpp: Finite-input signal processing (EWMA, hysteresis, rates)
 * - control.hpp: Finite-input PID control with transactional anti-windup
 * - rcu_buffer.hpp: RCU double-buffer (torn-read-free config publishing)
 * - single_writer_snapshot.hpp: Bounded coherent owner-to-observer publication
 * - cache.hpp: Exact-owner intrusive LRU, cold LRU cache, aligned allocation
 * - queue.hpp: Lock-free queues (SPSC, MPMC)
 * - quiescence.hpp: Exact reader grace generations
 * - ratelimit.hpp: Exact-rational token, leaky, and sliding-window limits
 * - net.hpp: Network algorithms (byte order and IPv4 helpers)
 * - cidr.hpp: CIDR parsing and matching
 * - condition_parse.hpp: Edge-condition syntax parser
 * - graph.hpp: DAG algorithms (topological sort, cycle detection)
 * - cuckoo.hpp: O(1) worst-case cuckoo hash table
 * - simd_classify.hpp: SIMD batch packet classification
 * - timer_wheel.hpp: Hierarchical timer wheel for active stages
 *
 * @par Usage
 * @code{.cpp}
 *   #include <kinetum/algo/algo.hpp>  // Complete algorithm surface
 *
 *   // Or include specific headers:
 *   #include <kinetum/algo/hash.hpp>  // Hash primitives only
 *   #include <kinetum/algo/cidr.hpp>  // CIDR primitives only
 * @endcode
 */

#include <kinetum/algo/aligned_atomic.hpp>
#include <kinetum/algo/bits.hpp>
#include <kinetum/algo/atomic_index_pool.hpp>
#include <kinetum/algo/bounded_index_pool.hpp>
#include <kinetum/algo/bounded_service_order.hpp>
#include <kinetum/algo/cache.hpp>
#include <kinetum/algo/cidr.hpp>
#include <kinetum/algo/compact_index_set.hpp>
#include <kinetum/algo/condition_parse.hpp>
#include <kinetum/algo/control.hpp>
#include <kinetum/algo/cuckoo.hpp>
#include <kinetum/algo/graph.hpp>
#include <kinetum/algo/hash.hpp>
#include <kinetum/algo/net.hpp>
#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/prefetch.hpp>
#include <kinetum/algo/queue.hpp>
#include <kinetum/algo/quiescence.hpp>
#include <kinetum/algo/ratelimit.hpp>
#include <kinetum/algo/rcu_buffer.hpp>
#include <kinetum/algo/signal.hpp>
#include <kinetum/algo/simd_classify.hpp>
#include <kinetum/algo/single_writer_snapshot.hpp>
#include <kinetum/algo/timer_wheel.hpp>
