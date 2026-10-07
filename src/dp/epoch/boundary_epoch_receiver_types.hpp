// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file boundary_epoch_receiver_types.hpp
 * @brief Fixed receiver-policy phases for exact ordered DATA cuts.
 * @author Fleming Patel
 *
 * These values describe one receiver worker's owner-local CUT and ACK policy.
 * Physical DATA/CUT/ACK transport remains solely in
 * `boundary_epoch_channel`; activation and packet ownership remain in their
 * separate worker authorities.
 */

#include <array>
#include <cstdint>
#include <type_traits>

#include <kinetum/algo/platform.hpp>

namespace kinetum::dp
{

/** @brief Exact owner-local phase for one inbound boundary receiver. */
enum class boundary_epoch_receiver_phase : uint8_t {
	UNBOUND = 0,	///< Bootstrap has not bound the executable epoch.
	OPEN,		///< Fixed execution is open and no CUT is admitted.
	WAITING_CUT,	///< One exact target CUT has not yet arrived.
	CUT_DRAINING,	///< CUT is exact but its DATA prefix is not yet consumed.
	CUT_DRAINED,	///< Receiver sequence reached the exact CUT.
	ACK_PENDING,	///< Activation completed; exact ACK is not yet published.
	ACK_PUBLISHED,	///< Exact ACK publication completed for this generation.
};

/**
 * @brief Coherent receiver-policy edge proof for one exact transition.
 *
 * The owner publishes Bootstrap baseline and each real transition state/timing
 * edge, including CUT observation/drain, local activation, and exact ACK
 * ownership. Observers receive an independent value and never read the
 * receiver's writable policy or timing lines.
 */
struct alignas(kinetum::algo::CACHE_LINE_SIZE) boundary_receiver_transition_snapshot {
	uint64_t publication_generation{0};	 ///< Coherent publication generation.
	uint64_t runtime_generation{0};		 ///< Exact materialized runtime generation.
	uint64_t boundary_index{0};		 ///< Exact compact boundary identity.
	uint64_t transition_generation{0};	 ///< Exact mutation generation, or zero at Bootstrap.
	uint64_t from_epoch{0};			 ///< Exact old epoch, or zero at Bootstrap.
	uint64_t to_epoch{0};			 ///< Exact active target or Bootstrap epoch.
	uint64_t cut_sequence{0};		 ///< Exact accepted DATA cut watermark.
	uint64_t ack_published{0};		 ///< One only after exact ACK publication.
	uint64_t cut_observed_monotonic_ns{0};	 ///< Post-CUT-consumption batch sample.
	uint64_t cut_drained_monotonic_ns{0};	 ///< Post-drain-classification batch sample.
	uint64_t activation_monotonic_ns{0};	 ///< Exact local activation sample.
	uint64_t ack_published_monotonic_ns{0};	 ///< Pre-ACK-publication batch sample.
	uint64_t duplicate_cut_count{0};	 ///< Exact duplicate CUT population.
	uint64_t active_epoch{0};		 ///< Exact epoch admitted by DATA receive.
	boundary_epoch_receiver_phase phase{boundary_epoch_receiver_phase::UNBOUND};  ///< Exact phase.
	std::array<uint8_t, 15> padding{};  ///< Explicit two-cache-line completion.
};

static_assert(sizeof(boundary_epoch_receiver_phase) == sizeof(uint8_t), "boundary receiver phase must remain one byte");
static_assert(sizeof(boundary_receiver_transition_snapshot) == 2u * kinetum::algo::CACHE_LINE_SIZE,
	      "boundary receiver transition observation must occupy two cache lines");
static_assert(alignof(boundary_receiver_transition_snapshot) == kinetum::algo::CACHE_LINE_SIZE,
	      "boundary receiver transition observation must retain cache-line alignment");
static_assert(std::is_standard_layout_v<boundary_receiver_transition_snapshot> &&
		      std::is_trivially_copyable_v<boundary_receiver_transition_snapshot>,
	      "boundary receiver transition observation must retain value semantics");

}  // namespace kinetum::dp
