// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file transition_types.hpp
 * @brief Fixed-width DP phases and messages for ordered epoch transitions.
 * @author Fleming Patel
 *
 * These DP value types cross coordinator, worker, and boundary ownership
 * domains. They contain no pointers, dynamic storage, or backend types and are
 * immutable after publication. Shared CP-DP identity lives in
 * `src/common/epoch_transition_contract.hpp`.
 */

#include <cstdint>
#include <limits>
#include <type_traits>

#include "src/common/epoch_transition_contract.hpp"

namespace kinetum::dp
{

/** @brief Greatest successful boundary DATA sequence before fail-closed stop. */
inline constexpr uint64_t MAX_BOUNDARY_DATA_SEQUENCE = std::numeric_limits<uint64_t>::max() - 1u;

/**
 * @brief Check whether a boundary DATA sequence is representable without wrap.
 *
 * Zero is valid before any successful DATA operation.
 *
 * @param sequence Successful enqueue/dequeue sequence to validate.
 * @return true unless the reserved UINT64_MAX sentinel is supplied.
 */
[[nodiscard]] constexpr bool valid_boundary_data_sequence(uint64_t sequence) noexcept
{
	return sequence <= MAX_BOUNDARY_DATA_SEQUENCE;
}

/**
 * @brief DP-wide transition phases owned by the epoch coordinator.
 *
 * COMPLETE and ABORTED are terminal transaction results, not live global
 * phases. A completed or pre-commit-aborted transaction leaves the coordinator
 * in IDLE; its result belongs to the bounded terminal journal.
 */
enum class epoch_transition_phase : uint8_t {
	AWAITING_BOOTSTRAP = 0,	 ///< Control surface exists but no exact config is active.
	BOOTSTRAPPING,		 ///< Startup-only exact config preparation and activation.
	IDLE,			 ///< One exact active epoch; no transaction is admitted.
	PREPARING,		 ///< Fallible cold preparation; abort remains permitted.
	PREPARED,		 ///< All artifacts are ready; abort remains permitted.
	COMMITTING,		 ///< Irreversible ordered cut and participant activation.
	RETIRING,		 ///< Global certificate, grace period, and old-slot retirement.
	FAILED_STOP,		 ///< Terminal fail-closed state requiring process recovery.
};

/**
 * @brief Terminal outcome retained for exact transaction retries.
 */
enum class epoch_transition_outcome : uint8_t {
	NONE = 0,     ///< Transaction has no terminal outcome.
	COMPLETE,     ///< Commit and retirement completed successfully.
	ABORTED,      ///< Preparation ended before the irreversible commit point.
	FAILED_STOP,  ///< Completion could not remain safe or make progress.
};

/**
 * @brief Sequence-defined logical cut carried by the boundary control lane.
 */
struct boundary_epoch_cut {
	uint64_t next_epoch{0};		///< Exact epoch prepared for activation.
	uint64_t data_cut_sequence{0};	///< Final successful old-epoch DATA enqueue.

	/**
	 * @brief Check whether this record names an actual transition.
	 *
	 * A zero cut sequence is valid for a boundary with no old DATA.
	 *
	 * @return true when epoch and sequence both belong to their exact domains.
	 */
	[[nodiscard]] constexpr bool valid() const noexcept
	{
		return common::valid_epoch_id(next_epoch) && valid_boundary_data_sequence(data_cut_sequence);
	}

	/**
	 * @brief Compare epoch and DATA cut sequence together.
	 *
	 * @param other CUT record to compare.
	 * @return true only for an exact duplicate.
	 */
	bool operator==(const boundary_epoch_cut &other) const noexcept = default;
};

/**
 * @brief Exact activation acknowledgment echoed to a boundary sender.
 */
struct boundary_epoch_ack {
	uint64_t ready_epoch{0};	    ///< Exact epoch activated by the receiver.
	uint64_t consumed_cut_sequence{0};  ///< Exact cut sequence being acknowledged.

	/**
	 * @brief Check whether this record names an activated epoch.
	 *
	 * A zero consumed cut is valid for a boundary with no old DATA.
	 *
	 * @return true when epoch and sequence both belong to their exact domains.
	 */
	[[nodiscard]] constexpr bool valid() const noexcept
	{
		return common::valid_epoch_id(ready_epoch) && valid_boundary_data_sequence(consumed_cut_sequence);
	}

	/**
	 * @brief Compare ready epoch and consumed cut sequence together.
	 *
	 * @param other ACK record to compare.
	 * @return true only for an exact duplicate.
	 */
	bool operator==(const boundary_epoch_ack &other) const noexcept = default;
};

static_assert(sizeof(boundary_epoch_cut) == 16, "boundary_epoch_cut must remain exactly 16 bytes");
static_assert(sizeof(boundary_epoch_ack) == 16, "boundary_epoch_ack must remain exactly 16 bytes");
static_assert(alignof(boundary_epoch_cut) == alignof(uint64_t),
	      "boundary_epoch_cut must retain natural uint64_t alignment");
static_assert(alignof(boundary_epoch_ack) == alignof(uint64_t),
	      "boundary_epoch_ack must retain natural uint64_t alignment");
static_assert(std::is_trivially_copyable_v<boundary_epoch_cut>, "boundary_epoch_cut must be trivially copyable");
static_assert(std::is_trivially_copyable_v<boundary_epoch_ack>, "boundary_epoch_ack must be trivially copyable");
static_assert(std::is_standard_layout_v<boundary_epoch_cut>, "boundary_epoch_cut must have standard layout");
static_assert(std::is_standard_layout_v<boundary_epoch_ack>, "boundary_epoch_ack must have standard layout");
static_assert(sizeof(epoch_transition_phase) == sizeof(uint8_t), "epoch_transition_phase must remain one byte");
static_assert(sizeof(epoch_transition_outcome) == sizeof(uint8_t), "epoch_transition_outcome must remain one byte");

}  // namespace kinetum::dp
