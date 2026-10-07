// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file boundary_epoch_sender_types.hpp
 * @brief Fixed sender-policy phases and packet dispositions.
 * @author Fleming Patel
 *
 * These one-byte values describe worker-owned sender policy only. Physical
 * DATA/CUT/ACK transport remains owned by `boundary_epoch_channel`, and packet
 * ownership remains represented by the exact record pointer plus worker
 * ledger credit.
 */

#include <array>
#include <cstdint>
#include <type_traits>

#include <kinetum/algo/platform.hpp>

namespace kinetum::dp
{

/** @brief Exact owner-local phase for one boundary sender gate. */
enum class boundary_epoch_sender_phase : uint8_t {
	UNBOUND = 0,  ///< Bootstrap has not bound the exact open epoch.
	OPEN,	      ///< One exact epoch may transfer directly to DATA.
	DRAINING,     ///< Old DATA may transfer while future DATA is held.
	CUT_PENDING,  ///< Old DATA is sealed and one CUT remains unpublished.
	WAITING_ACK,  ///< CUT is published and future DATA awaits its exact ACK.
};

/** @brief Exact ownership result from one sender-policy packet operation. */
enum class boundary_epoch_send_result : uint8_t {
	TRANSFERRED = 0,  ///< Channel owns DATA and the worker credit retired.
	HELD,		  ///< Future hold owns the pointer; worker credit remains.
	BACKPRESSURED,	  ///< Caller retains pointer, reservation, and credit.
};

/**
 * @brief Coherent sender-policy edge proof for one exact transition.
 *
 * The owner publishes Bootstrap baseline and each real transition state/timing
 * edge, including CUT ownership and matching-ACK gate opening. Observers
 * receive an independent value and never read the sender's writable policy or
 * timing lines.
 */
struct alignas(kinetum::algo::CACHE_LINE_SIZE) boundary_sender_transition_snapshot {
	uint64_t publication_generation{0};	 ///< Coherent publication generation.
	uint64_t runtime_generation{0};		 ///< Exact materialized runtime generation.
	uint64_t boundary_index{0};		 ///< Exact compact boundary identity.
	uint64_t transition_generation{0};	 ///< Exact mutation generation, or zero at Bootstrap.
	uint64_t from_epoch{0};			 ///< Exact old epoch, or zero at Bootstrap.
	uint64_t to_epoch{0};			 ///< Exact active target or Bootstrap epoch.
	uint64_t cut_sequence{0};		 ///< Exact sealed successful-enqueue watermark.
	uint64_t ack_observed{0};		 ///< One only after exact ACK gate opening.
	uint64_t cut_published_monotonic_ns{0};	 ///< Pre-CUT-publication batch sample.
	uint64_t ack_observed_monotonic_ns{0};	 ///< Post-ACK-consumption batch sample.
	uint64_t duplicate_ack_count{0};	 ///< Exact duplicate ACK population.
	uint64_t open_epoch{0};			 ///< Exact epoch currently admitted to DATA.
	boundary_epoch_sender_phase phase{boundary_epoch_sender_phase::UNBOUND};  ///< Exact gate phase.
	std::array<uint8_t, 31> padding{};  ///< Explicit two-cache-line completion.
};

static_assert(sizeof(boundary_epoch_sender_phase) == sizeof(uint8_t), "boundary sender phase must remain one byte");
static_assert(sizeof(boundary_epoch_send_result) == sizeof(uint8_t),
	      "boundary sender packet result must remain one byte");
static_assert(sizeof(boundary_sender_transition_snapshot) == 2u * kinetum::algo::CACHE_LINE_SIZE,
	      "boundary sender transition observation must occupy two cache lines");
static_assert(alignof(boundary_sender_transition_snapshot) == kinetum::algo::CACHE_LINE_SIZE,
	      "boundary sender transition observation must retain cache-line alignment");
static_assert(std::is_standard_layout_v<boundary_sender_transition_snapshot> &&
		      std::is_trivially_copyable_v<boundary_sender_transition_snapshot>,
	      "boundary sender transition observation must retain value semantics");

}  // namespace kinetum::dp
