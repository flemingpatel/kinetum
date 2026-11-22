// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_native_handoff.hpp
 * @brief Synchronous worker-local forwarding through one bound RX, TX and storage owner.
 * @author Fleming Patel
 */

#include <array>
#include <cstdint>
#include <span>

#include "src/common/runtime_sizing.hpp"
#include "src/dp/worker_packet_staging.hpp"
#include "src/provider/provider_component_abi.h"

namespace kinetum::dp
{
class worker_epoch_ledger;
class worker_runtime_telemetry;

/** @brief Worker-owned receipt. Its original view survives a provider TX call. */
struct native_packet_slot {
	kinetum_packet_native_view view{};  ///< Opaque buffer identity and admitted range.
	uint64_t timestamp_ns{0u};	    ///< Cached receive turn time.
	uint64_t epoch{0u};		    ///< Epoch owning this packet's ledger credit.
};

/** @brief Complete cold selection for synchronous local forwarding. */
struct native_packet_binding {
	const kinetum_packet_rx_burst_operations *rx;		  ///< Sole ingress queue.
	const kinetum_packet_tx_burst_operations *tx;		  ///< Sole egress queue.
	const kinetum_packet_native_storage_operations *storage;  ///< Original storage owner for the refused suffix.
	uint32_t rx_stream;					  ///< Compiled ingress stream index.
	uint32_t tx_stream;					  ///< Compiled egress stream index.
	uint32_t domain;					  ///< Compiled original storage domain.
	uint32_t rx_stage;					  ///< Exact RX stage instance.
	uint32_t tx_stage;					  ///< Exact TX stage instance.
	uint32_t rx_stage_counter;				  ///< Owner-local RX stage ordinal.
	uint32_t tx_stage_counter;				  ///< Owner-local TX stage ordinal.
	uint32_t tx_stream_counter;				  ///< Owner-local TX stream ordinal.
};

/** @brief Sole worker's receipt pool and bounded scratch for one immutable native binding. */
class worker_native_handoff final {
    public:
	/**
	 * @brief Bind the worker's empty, disjoint receipt and free-list extents before opening ingress.
	 * @param binding Queue callbacks, original storage owner and stream/stage counter identities.
	 * @param tx_key Executable TX ordinal in both roles.
	 * @param staging Role owner retained through shutdown.
	 * @param ledger Sole worker credit owner.
	 * @param telemetry Sole worker counter banks.
	 * @param slots Receipt storage covering both role capacities.
	 * @param free_slots Equal-capacity pointer storage on the worker's NUMA node.
	 */
	worker_native_handoff(native_packet_binding binding, uint32_t tx_key, packet_epoch_input_staging &staging,
			      worker_epoch_ledger &ledger, worker_runtime_telemetry &telemetry,
			      std::span<native_packet_slot> slots, std::span<native_packet_slot *> free_slots) noexcept;
	/** @brief One receipt population has one reclamation owner. */
	worker_native_handoff(const worker_native_handoff &) = delete;
	/** @brief Reject replacement beneath live role or queue borrows. */
	worker_native_handoff &operator=(const worker_native_handoff &) = delete;
	/** @return The immutable choice that supplies the active queue and storage operations. */
	[[nodiscard]] const native_packet_binding &binding() const noexcept
	{
		return binding_;
	}
	/** @brief Admission facts sampled together before transferring any provider ownership. */
	struct admission {
		uint64_t epoch;	     ///< Exact source epoch.
		uint64_t timestamp;  ///< Cached worker turn.
		uint32_t key;	     ///< Registered RX delivery ordinal.
		uint16_t capacity;   ///< Already reserved input population.
		bool future;	     ///< Select the source's inert future role.
	};
	/**
	 * @param input Reserved role and pre-call stamp.
	 * @param[out] bytes Bytes transferred to the worker, excluding provider-retired inputs.
	 * @return Compact transferred count and provider rejection count, whose sum fits the reservation.
	 */
	[[nodiscard]] kinetum_packet_rx_burst_result receive(const admission &input, uint64_t &bytes) noexcept;
	/** @param epoch Active epoch required of every slot selected by this bounded service. */
	void service(uint64_t epoch) noexcept;
	/** @brief Submit the pending TX prefix, verify the entire suffix and retire exactly the offered population. */
	void flush() noexcept;
	/** @return Whether all local receipts have returned and no TX prefix is pending. */
	[[nodiscard]] bool empty() const noexcept
	{
		return free_count_ == free_slots_.size() && tx_count_ == 0u;
	}

    private:
	static constexpr auto MAX_BURST = common::runtime_sizing::PACKET_MAX_BURST_SIZE;  ///< Maximum queue call.
	const native_packet_binding binding_;	      ///< Sole authority for representation, identities and operations.
	const uint32_t tx_key_;			      ///< Key assigned by ordinary work-staging construction.
	packet_epoch_input_staging &staging_;	      ///< Same role reservations used by activation.
	worker_epoch_ledger &ledger_;		      ///< Worker-local epoch credit.
	worker_runtime_telemetry &telemetry_;	      ///< Same stage and stream counters as full-record service.
	std::span<native_packet_slot *> free_slots_;  ///< Exact sum of active and future receipt capacities.
	std::size_t free_count_;		      ///< Live free prefix.
	std::array<kinetum_packet_native_view, MAX_BURST> incoming_{};	///< Zero on entry to every RX callback.
	std::array<native_packet_slot *, MAX_BURST> scratch_{};	 ///< Shared transient RX and local service pointers.
	std::array<native_packet_slot *, MAX_BURST> pending_{};	 ///< Retained pre-call receipts in FIFO order.
	uint16_t tx_count_{0u};					 ///< Live TX prefix.
};
}  // namespace kinetum::dp
