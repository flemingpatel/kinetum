// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file time.hpp
 * @brief Time utilities for consistent timestamps across the platform.
 * @author Fleming Patel
 *
 * Provides two primary time sources:
 * - Wall-clock time (unix_time_ms): For durable deadlines and audit projections
 * - Monotonic time (now_ns): For measuring durations and timeouts
 *
 * Performance Notes:
 * ------------------
 * - unix_time_ms() uses std::chrono::system_clock::now()
 * - now_ns() uses std::chrono::steady_clock; on Linux this generally maps
 *   to a monotonic clock source and may use vDSO
 * - Worker loops call update_cached_ns() once per turn and all packet stages,
 *   active callbacks, RX adapters, and TX timeout checks consume that value
 * - After a due non-null owner-health callback returns, its worker may call
 *   now_ns() once to measure the compiled budget; this never replaces the cached value
 * - Transition timing samples endpoint batches as described below
 * - Do NOT call a clock per stage or per packet in the dataplane hot path
 *
 * Thread-safety: All functions are thread-safe.
 *
 * @see std::chrono for the underlying C++ time library
 */

#include <cstdint>

namespace kinetum::common
{

/**
 * @brief Get current wall-clock time in milliseconds since Unix epoch.
 *
 * Returns the number of milliseconds since the Unix epoch (1970-01-01 00:00:00 UTC).
 * This is wall-clock time and may jump forward or backward due to NTP adjustments
 * or manual clock changes.
 *
 * Use cases:
 * - Restart-stable confirmation deadlines
 * - Durable audit projections
 * - Correlation with external systems
 *
 * @return Milliseconds since 1970-01-01 00:00:00 UTC
 *
 * @warning Wall-clock time can go backwards during NTP corrections. Do not use
 *          for measuring durations or timeouts; use now_ns() instead.
 *
 * @see now_ns for monotonic time suitable for duration measurement
 */
int64_t unix_time_ms() noexcept;

/**
 * @brief Get current monotonic time in nanoseconds.
 *
 * Uses std::chrono::steady_clock for nondecreasing elapsed-time measurements.
 *
 * Use cases:
 * - Measuring operation latency
 * - Implementing timeouts and deadlines
 * - Rate limiting and token buckets
 * - Worker time supplied to packet processing
 *
 * @return Nanoseconds since an unspecified epoch (typically system boot).
 *         The absolute value is meaningless; only differences are useful.
 *
 * @note For dataplane hot paths, the owner worker refreshes cached time once per
 *       loop turn and stamps packet_record::metadata.timestamp_ns from it. The
 *       worker may take one sample after a due non-null health callback returns,
 *       solely for duration enforcement and its context-bank publication time.
 * @note Transition timing may sample before a sender CUT batch, after a receiver
 *       CUT/data-drain batch, before a receiver ACK batch, and after a sender
 *       ACK-consumption batch. A pending publication retry also takes one sample
 *       for the batch. Only a successful enqueue records a publication time.
 *
 * @note On Linux, this typically uses CLOCK_MONOTONIC which does not advance
 *       during system suspend. Use CLOCK_BOOTTIME if suspend-aware timing
 *       is required.
 * @note A negative steady-clock representation is outside the runtime's
 *       unsigned timestamp domain and terminates instead of becoming zero.
 *
 * @see unix_time_ms for wall-clock time with calendar meaning
 */
uint64_t now_ns() noexcept;

/**
 * @brief Get cached timestamp for hot path use.
 *
 * Returns a cached nanosecond timestamp updated once per owner-worker loop
 * turn. This avoids per-stage and per-packet clock reads while giving packet
 * work in that turn the same time value.
 *
 * After command/source admission and prior return service, the owner-worker
 * loop calls update_cached_ns() immediately before packet or callback work.
 * Packet operations consume that cached value. Module callbacks receive it
 * through batch.now_ns or the active context; they do not sample a clock.
 *
 * @return Cached nanosecond timestamp from last update.
 *
 * @note Thread-local: each thread has its own cached value.
 */
uint64_t cached_ns() noexcept;

/**
 * @brief Update the cached timestamp.
 *
 * Call this exactly once per owner-worker loop turn, after command/source
 * admission and prior return service and before packet or callback work.
 *
 * @return The new cached timestamp (same value as subsequent cached_ns() calls).
 */
uint64_t update_cached_ns() noexcept;

}  // namespace kinetum::common
