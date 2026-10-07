// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file transition_state_machine.hpp
 * @brief Exact DP-wide phase sequencing for one epoch transition at a time.
 * @author Fleming Patel
 *
 * The state machine validates phase, exact identity, and target-epoch ordering
 * only. Participant freezing, artifact leases, journals, deadlines, commands,
 * and side effects remain coordinator responsibilities and cannot become
 * implicit state transitions.
 *
 * @par Thread Safety
 * The epoch-transition coordinator is the sole owner. RPC handlers submit
 * bounded commands rather than invoking this object concurrently.
 */

#include <cstdint>

#include "src/common/epoch_transition_contract.hpp"
#include "src/dp/epoch/transition_types.hpp"

namespace kinetum::dp
{

/**
 * @brief Result of an exact global transition-state operation.
 */
enum class epoch_state_result : uint8_t {
	APPLIED = 0,		///< Requested phase transition completed.
	INVALID_ARGUMENT,	///< Epoch or transaction identity is malformed.
	STATE_MISMATCH,		///< Current global phase does not permit the operation.
	IDENTITY_MISMATCH,	///< Operation does not name the admitted transaction.
	EPOCH_ORDER_VIOLATION,	///< Target epoch does not advance the active epoch.
};

/**
 * @brief Enforce exact DP-wide transition phase ordering.
 *
 * No live mutation may overlap another. Pre-commit work can return to IDLE by
 * explicit abort; COMMITTING and RETIRING are completion-only. FAILED_STOP is
 * terminal and can be left only by process restart and exact bootstrap.
 */
class epoch_transition_state_machine {
    public:
	/** @brief Construct a coordinator authority in AWAITING_BOOTSTRAP. */
	epoch_transition_state_machine() noexcept = default;

	// Copying or moving would create a second global transition authority.
	epoch_transition_state_machine(const epoch_transition_state_machine &) = delete;
	epoch_transition_state_machine &operator=(const epoch_transition_state_machine &) = delete;
	epoch_transition_state_machine(epoch_transition_state_machine &&) = delete;
	epoch_transition_state_machine &operator=(epoch_transition_state_machine &&) = delete;

	/**
	 * @brief Return the current exact global phase.
	 *
	 * @return Current coordinator phase.
	 */
	[[nodiscard]] epoch_transition_phase phase() const noexcept
	{
		return phase_;
	}

	/**
	 * @brief Return the last globally completed active epoch.
	 *
	 * During PREPARING through RETIRING this remains the from-epoch. Participant
	 * active epochs are published separately during commit.
	 *
	 * @return Active baseline epoch, or zero before bootstrap.
	 */
	[[nodiscard]] uint64_t active_epoch() const noexcept
	{
		return active_epoch_;
	}

	/**
	 * @brief Return the admitted bootstrap or transition target epoch.
	 *
	 * @return Exact target while work exists, or zero in AWAITING/IDLE. A
	 * transition target remains available for diagnostics in FAILED_STOP.
	 */
	[[nodiscard]] uint64_t target_epoch() const noexcept
	{
		return target_epoch_;
	}

	/**
	 * @brief Return the admitted live-transition identity.
	 *
	 * Bootstrap has no mutation identity and therefore returns nullptr.
	 *
	 * @return Pointer to exact owner-local identity, or nullptr.
	 */
	[[nodiscard]] const common::epoch_transition_identity *identity() const noexcept
	{
		return has_identity_ ? &identity_ : nullptr;
	}

	/**
	 * @brief Enter startup-only bootstrap for an exact epoch.
	 *
	 * @param epoch Exact valid epoch supplied by durable CP state.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result begin_bootstrap(uint64_t epoch) noexcept
	{
		if (!common::valid_epoch_id(epoch)) {
			return epoch_state_result::INVALID_ARGUMENT;
		}
		if (phase_ != epoch_transition_phase::AWAITING_BOOTSTRAP) {
			return epoch_state_result::STATE_MISMATCH;
		}
		target_epoch_ = epoch;
		phase_ = epoch_transition_phase::BOOTSTRAPPING;
		return epoch_state_result::APPLIED;
	}

	/**
	 * @brief Complete startup bootstrap for the exact admitted epoch.
	 *
	 * @param epoch Epoch whose artifacts were prepared and activated.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result complete_bootstrap(uint64_t epoch) noexcept
	{
		if (phase_ != epoch_transition_phase::BOOTSTRAPPING) {
			return epoch_state_result::STATE_MISMATCH;
		}
		if (!common::valid_epoch_id(epoch)) {
			return epoch_state_result::INVALID_ARGUMENT;
		}
		if (epoch != target_epoch_) {
			return epoch_state_result::IDENTITY_MISMATCH;
		}
		active_epoch_ = epoch;
		target_epoch_ = 0;
		phase_ = epoch_transition_phase::IDLE;
		return epoch_state_result::APPLIED;
	}

	/**
	 * @brief Return an uncommitted bootstrap attempt to AWAITING_BOOTSTRAP.
	 *
	 * This operation is legal only before any module ACTIVATE callback or
	 * packet-worker publication. The bootstrap owner first retires every staged
	 * module and snapshot artifact, then uses this transition to permit an exact
	 * byte-identical retry. No active epoch or mutation identity is retained.
	 *
	 * @param epoch Exact epoch of the admitted bootstrap attempt.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result abort_bootstrap(uint64_t epoch) noexcept
	{
		if (phase_ != epoch_transition_phase::BOOTSTRAPPING) {
			return epoch_state_result::STATE_MISMATCH;
		}
		if (!common::valid_epoch_id(epoch)) {
			return epoch_state_result::INVALID_ARGUMENT;
		}
		if (epoch != target_epoch_) {
			return epoch_state_result::IDENTITY_MISMATCH;
		}
		target_epoch_ = 0;
		phase_ = epoch_transition_phase::AWAITING_BOOTSTRAP;
		return epoch_state_result::APPLIED;
	}

	/**
	 * @brief Admit one exact later mutation for cold preparation.
	 *
	 * @param identity Durable exact transaction identity.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result begin_prepare(const common::epoch_transition_identity &identity) noexcept
	{
		if (!identity.valid()) {
			return epoch_state_result::INVALID_ARGUMENT;
		}
		if (phase_ != epoch_transition_phase::IDLE || active_epoch_ == 0u) {
			return epoch_state_result::STATE_MISMATCH;
		}
		if (identity.target_epoch <= active_epoch_) {
			return epoch_state_result::EPOCH_ORDER_VIOLATION;
		}
		identity_ = identity;
		has_identity_ = true;
		target_epoch_ = identity.target_epoch;
		phase_ = epoch_transition_phase::PREPARING;
		return epoch_state_result::APPLIED;
	}

	/**
	 * @brief Mark every artifact prepared for the admitted identity.
	 *
	 * @param identity Exact transaction identity returned by preparation.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result mark_prepared(const common::epoch_transition_identity &identity) noexcept
	{
		return advance_exact_(epoch_transition_phase::PREPARING, epoch_transition_phase::PREPARED, identity);
	}

	/**
	 * @brief Abort an exact transaction before the irreversible commit point.
	 *
	 * @param identity Exact admitted transaction identity.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result abort_before_commit(const common::epoch_transition_identity &identity) noexcept
	{
		if (!identity.valid()) {
			return epoch_state_result::INVALID_ARGUMENT;
		}
		if (phase_ != epoch_transition_phase::PREPARING && phase_ != epoch_transition_phase::PREPARED) {
			return epoch_state_result::STATE_MISMATCH;
		}
		if (!matches_(identity)) {
			return epoch_state_result::IDENTITY_MISMATCH;
		}
		clear_transaction_();
		phase_ = epoch_transition_phase::IDLE;
		return epoch_state_result::APPLIED;
	}

	/**
	 * @brief Cross the irreversible point for an exact prepared transaction.
	 *
	 * @param identity Exact admitted transaction identity.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result begin_commit(const common::epoch_transition_identity &identity) noexcept
	{
		return advance_exact_(epoch_transition_phase::PREPARED, epoch_transition_phase::COMMITTING, identity);
	}

	/**
	 * @brief Begin certificate, grace-period, and old-slot retirement.
	 *
	 * @param identity Exact committed transaction identity.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result begin_retiring(const common::epoch_transition_identity &identity) noexcept
	{
		return advance_exact_(epoch_transition_phase::COMMITTING, epoch_transition_phase::RETIRING, identity);
	}

	/**
	 * @brief Complete retirement and publish the exact target as globally idle.
	 *
	 * @param identity Exact retiring transaction identity.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result complete_retirement(const common::epoch_transition_identity &identity) noexcept
	{
		if (!identity.valid()) {
			return epoch_state_result::INVALID_ARGUMENT;
		}
		if (phase_ != epoch_transition_phase::RETIRING) {
			return epoch_state_result::STATE_MISMATCH;
		}
		if (!matches_(identity)) {
			return epoch_state_result::IDENTITY_MISMATCH;
		}
		active_epoch_ = target_epoch_;
		clear_transaction_();
		phase_ = epoch_transition_phase::IDLE;
		return epoch_state_result::APPLIED;
	}

	/**
	 * @brief Enter the terminal fail-closed phase without erasing diagnostics.
	 *
	 * This operation is idempotent. Recovery requires process restart and exact
	 * bootstrap; no transition API leaves FAILED_STOP.
	 */
	void enter_failed_stop() noexcept
	{
		phase_ = epoch_transition_phase::FAILED_STOP;
	}

    private:
	/**
	 * @brief Advance between two exact transaction phases.
	 *
	 * @param expected Required current phase.
	 * @param next Phase published after validation.
	 * @param identity Exact admitted transaction identity.
	 * @return Exact state-operation result.
	 */
	[[nodiscard]] epoch_state_result advance_exact_(epoch_transition_phase expected, epoch_transition_phase next,
							const common::epoch_transition_identity &identity) noexcept
	{
		if (!identity.valid()) {
			return epoch_state_result::INVALID_ARGUMENT;
		}
		if (phase_ != expected) {
			return epoch_state_result::STATE_MISMATCH;
		}
		if (!matches_(identity)) {
			return epoch_state_result::IDENTITY_MISMATCH;
		}
		phase_ = next;
		return epoch_state_result::APPLIED;
	}

	/**
	 * @brief Compare a candidate with the exact admitted identity.
	 *
	 * @param identity Candidate identity.
	 * @return true only for byte-for-byte exact identity.
	 */
	[[nodiscard]] bool matches_(const common::epoch_transition_identity &identity) const noexcept
	{
		return has_identity_ && identity_ == identity;
	}

	/**
	 * @brief Clear live transaction identity after abort or complete retirement.
	 */
	void clear_transaction_() noexcept
	{
		identity_ = {};
		has_identity_ = false;
		target_epoch_ = 0;
	}

	epoch_transition_phase phase_{epoch_transition_phase::AWAITING_BOOTSTRAP};  ///< Sole-writer global phase.
	uint64_t active_epoch_{0};						    ///< Last globally completed epoch.
	uint64_t target_epoch_{0};						    ///< Exact in-progress target epoch.
	common::epoch_transition_identity identity_{};				    ///< Exact admitted live identity.
	bool has_identity_{false};  ///< Whether identity_ is authoritative.
};

}  // namespace kinetum::dp
