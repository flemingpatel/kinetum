// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_telemetry_channel.hpp
 * @brief Poller-local SPSC transfer for one worker's completed telemetry banks.
 * @author Fleming Patel
 *
 * The worker publishes completed bank tokens into a coordinator-NUMA ring.
 * The cold aggregator returns cleared reusable banks through a worker-NUMA
 * ring. Payload storage remains with its exact bank owner; the channel carries
 * fixed identities only.
 *
 * @par Thread Safety
 * The worker is the sole completed-ring producer and return-ring consumer. The
 * coordinator aggregator owns the inverse endpoints. Successful queue transfer
 * is the only cross-thread ownership publication.
 *
 * @par Performance
 * Both rings allocate and bind once. Push/pop are bounded SPSC operations with
 * no allocation, lock, syscall, clock read, formatting, or retry loop.
 */

#include <cstddef>
#include <cstdint>
#include <memory>

#include "src/common/status_or.hpp"
#include "src/dp/numa_spsc_ring.hpp"
#include "src/dp/runtime_telemetry_bank.hpp"

namespace kinetum::dp
{

/** @brief Exact bidirectional bank-token transport for one packet worker. */
class worker_telemetry_channel final {
    public:
	/**
	 * @brief Derive the exact physical capacity for one worker.
	 * @param module_context_count Number of module-bank owners on the worker.
	 * @return Smallest legal power of two covering two tokens per owner.
	 */
	[[nodiscard]] static common::status_or<std::size_t> capacity_for(std::size_t module_context_count) noexcept;

	/**
	 * @brief Allocate both poller-local rings.
	 * @param worker_index Exact compact worker identity.
	 * @param module_context_count Exact module contexts owned by the worker.
	 * @param worker_numa_node Exact worker/return-poller node.
	 * @param coordinator_numa_node Exact aggregator/completed-poller node.
	 * @return Complete empty channel or a fail-closed allocation status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_telemetry_channel>>
	create(uint32_t worker_index, std::size_t module_context_count, int32_t worker_numa_node,
	       int32_t coordinator_numa_node);

	worker_telemetry_channel(const worker_telemetry_channel &) = delete;
	worker_telemetry_channel &operator=(const worker_telemetry_channel &) = delete;
	worker_telemetry_channel(worker_telemetry_channel &&) = delete;
	worker_telemetry_channel &operator=(worker_telemetry_channel &&) = delete;
	/** @brief Destroy only after both transfer directions are empty and quiescent. */
	~worker_telemetry_channel();

	/**
	 * @param token Exact completed-bank or retained-return identity.
	 * @return true after worker publication transfers one completed token.
	 */
	[[nodiscard]] bool publish_completed(const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @param[out] token Replaced only after one successful cold ownership transfer.
	 * @return true after the cold aggregator consumes one completed token.
	 */
	[[nodiscard]] bool take_completed(runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @param token Exact cleared-bank ownership transfer.
	 * @return true after the cold aggregator returns one cleared bank.
	 */
	[[nodiscard]] bool return_cleared(const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @param[out] token Replaced only after one successful worker ownership transfer.
	 * @return true after the worker consumes one returned bank.
	 */
	[[nodiscard]] bool take_returned(runtime_telemetry_bank_token &token) noexcept;

	/** @return Approximate completed-ring free capacity for worker preflight. */
	[[nodiscard]] std::size_t completed_available() const noexcept;
	/** @return Exact compact worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept;
	/** @return Exact derived capacity of each direction. */
	[[nodiscard]] std::size_t capacity() const noexcept;
	/** @return Exact NUMA node of the cold completed-bank poller. */
	[[nodiscard]] int32_t completed_numa_node() const noexcept;
	/** @return Exact NUMA node of the owner-worker return poller. */
	[[nodiscard]] int32_t returned_numa_node() const noexcept;
	/** @return true when the cold aggregator has no completed token to consume. */
	[[nodiscard]] bool completed_empty() const noexcept;
	/** @return true when the owner worker has no cleared token to consume. */
	[[nodiscard]] bool returned_empty() const noexcept;
	/** @return true only when both directions own no bank token. */
	[[nodiscard]] bool empty() const noexcept;

    private:
	/**
	 * @brief Adopt two complete exact-NUMA ring owners.
	 * @param worker_index Exact compact worker identity.
	 * @param capacity Exact derived capacity shared by both directions.
	 * @param completed Coordinator-poller completed-bank ring.
	 * @param returned Worker-poller cleared-bank ring.
	 */
	worker_telemetry_channel(uint32_t worker_index, std::size_t capacity,
				 std::unique_ptr<numa_spsc_ring<runtime_telemetry_bank_token>> completed,
				 std::unique_ptr<numa_spsc_ring<runtime_telemetry_bank_token>> returned) noexcept;

	uint32_t worker_index_{0};  ///< Exact compact worker identity.
	std::size_t capacity_{0};   ///< Exact derived capacity in each direction.
	std::unique_ptr<numa_spsc_ring<runtime_telemetry_bank_token>> completed_;  ///< Coordinator-poller ring.
	std::unique_ptr<numa_spsc_ring<runtime_telemetry_bank_token>> returned_;   ///< Worker-poller ring.
};

}  // namespace kinetum::dp
