// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_thread_log_guard.hpp
 * @brief Packet-thread exclusion from cold diagnostics with bounded rejection evidence.
 * @author Fleming Patel
 *
 * Install once before worker setup and retain through owner callbacks and
 * facility retirement. No packet-loop probe is required. A foreign logging
 * hook rejects through the current thread's counter before entering any cold
 * logging machinery. Registration and observation are cold operations.
 */

#include <atomic>
#include <cstdint>

#include <kinetum/algo/platform.hpp>

namespace kinetum::common
{

/**
 * @brief Mark one complete packet-owner thread lifetime without allocating.
 *
 * Construction and destruction are cold and must run on the same thread.
 * Live rejection state has one writer and a separate atomic publication;
 * registry membership is protected only at entry, exit, and cold observation.
 * Each scope occupies its own cache line. Copying, moving, and nesting reject.
 */
class alignas(algo::CACHE_LINE_SIZE) packet_thread_log_guard final {
    public:
	/** @brief Register this thread before its first provider or owner callback. */
	packet_thread_log_guard() noexcept;
	/** @brief Retain the final count and withdraw this exact scope after all callbacks retire. */
	~packet_thread_log_guard();
	packet_thread_log_guard(const packet_thread_log_guard &) = delete;
	packet_thread_log_guard &operator=(const packet_thread_log_guard &) = delete;
	packet_thread_log_guard(packet_thread_log_guard &&) = delete;
	packet_thread_log_guard &operator=(packet_thread_log_guard &&) = delete;

    private:
	uint64_t rejected_{0};			      ///< Sole owner's count, saturated at the representable ceiling.
	std::atomic<uint64_t> published_{0};	      ///< Independently readable count; hook never performs an RMW.
	packet_thread_log_guard *previous_{nullptr};  ///< Registry predecessor under the cold registry mutex.
	packet_thread_log_guard *next_{nullptr};      ///< Registry successor under the cold registry mutex.

	friend bool reject_packet_thread_log() noexcept;
	friend uint64_t packet_thread_log_rejections() noexcept;
};

/**
 * @brief Reject a foreign diagnostic before any text inspection or cold claim.
 * @return True after counting a packet-thread rejection; false on a cold thread.
 * @note One fixed TLS load, bounded arithmetic, and an atomic store. No lock,
 *       retry loop, clock, allocation, queue, formatter, or I/O is reachable.
 */
[[nodiscard]] bool reject_packet_thread_log() noexcept;

/**
 * @brief Observe live and retired packet-thread rejection counts.
 * @return Monotone process total, saturated at UINT64_MAX.
 * @note Cold only; the registry mutex protects scope lifetime, never packet work.
 */
[[nodiscard]] uint64_t packet_thread_log_rejections() noexcept;

}  // namespace kinetum::common
