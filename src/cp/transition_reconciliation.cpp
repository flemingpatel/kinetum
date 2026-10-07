// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file transition_reconciliation.cpp
 * @brief Implementation of typed CP transition restart reconciliation.
 * @author Fleming Patel
 */

#include "src/cp/transition_reconciliation.hpp"

#include <new>

#include "src/common/status.hpp"

namespace kinetum::cp
{
namespace
{

/** CP's durable mutation phase, independent of the remote DP observation. */
using durable_phase = kinetum::control::internal::v1::DurableEpochTransitionPhase;
/** DP-observed transition state used during reconciliation. */
using remote_state = kinetum::telemetry::v1::EpochTransitionState;
/** Typed cause retained with the DP's transition observation. */
using remote_failure = kinetum::telemetry::v1::EpochTransitionFailureCode;
/** Result of comparing the queried and observed transaction identities. */
using resolution = kinetum::common::transition_identity_resolution;
/** Next CP operation selected from durable and remote evidence. */
using action = transition_reconciliation_action;

/**
 * @brief Validate one generated durable phase value.
 * @param phase Candidate local phase.
 * @return true only for one of the six required non-sentinel phases.
 */
[[nodiscard]] constexpr bool valid_local_phase(durable_phase phase) noexcept
{
	switch (phase) {
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED:
		return true;
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_UNSPECIFIED:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Construct the sole contradictory-observation result.
 * @return DATA_LOSS without state mutation.
 */
[[nodiscard]] kinetum::common::status_or<action> contradiction()
{
	return kinetum::common::status::data_loss("durable and Data Plane transition states contradict");
}

/**
 * @brief Classify one public failure value as an abortable pre-commit cause.
 * @param failure Candidate generated failure value.
 * @return true only for one exact pre-commit terminal cause.
 */
[[nodiscard]] constexpr bool precommit_failure(remote_failure failure) noexcept
{
	switch (failure) {
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED:
		return true;
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_NONE:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT:
	case kinetum::telemetry::v1::EpochTransitionFailureCode_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::telemetry::v1::EpochTransitionFailureCode_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Classify one public failure value as a non-frozen fail-stop cause.
 * @param failure Candidate generated failure value.
 * @return true only for a completion-only fail-stop cause.
 */
[[nodiscard]] constexpr bool fail_stop_failure(remote_failure failure) noexcept
{
	switch (failure) {
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT:
		return true;
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_NONE:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED:
	case remote_failure::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED:
	case kinetum::telemetry::v1::EpochTransitionFailureCode_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::telemetry::v1::EpochTransitionFailureCode_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

}  // namespace

kinetum::common::status_or<transition_reconciliation_action>
classify_transition_reconciliation(kinetum::control::internal::v1::DurableEpochTransitionPhase local_phase,
				   kinetum::common::transition_identity_resolution identity_resolution,
				   kinetum::telemetry::v1::EpochTransitionState observed_state,
				   kinetum::telemetry::v1::EpochTransitionFailureCode failure_code) noexcept
{
	try {
		if (!valid_local_phase(local_phase) ||
		    !kinetum::telemetry::v1::EpochTransitionState_IsValid(static_cast<int>(observed_state)) ||
		    !kinetum::telemetry::v1::EpochTransitionFailureCode_IsValid(static_cast<int>(failure_code)) ||
		    failure_code == remote_failure::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED) {
			return contradiction();
		}
		const bool no_failure = failure_code == remote_failure::EPOCH_TRANSITION_FAILURE_CODE_NONE;
		const bool exact_resolution = identity_resolution == resolution::ACTIVE_EXACT ||
					      identity_resolution == resolution::TERMINAL_EXACT;
		if (!exact_resolution &&
		    (!no_failure || observed_state != remote_state::EPOCH_TRANSITION_STATE_UNSPECIFIED)) {
			return contradiction();
		}

		switch (identity_resolution) {
		case resolution::INVALID:
		case resolution::ADMISSIBLE:
		case resolution::STALE:
		case resolution::INCONSISTENT:
		case resolution::IDENTITY_CONFLICT:
		case resolution::OVERLAP:
			return no_failure ? kinetum::common::status_or<action>(action::FAIL_CLOSED) : contradiction();

		case resolution::ACTIVE_EXACT:
			switch (observed_state) {
			case remote_state::EPOCH_TRANSITION_STATE_PREPARING:
				if (!no_failure) {
					return contradiction();
				}
				if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED) {
					return action::WAIT_FOR_PREPARE;
				}
				if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING) {
					return action::RETRY_ABORT;
				}
				return contradiction();
			case remote_state::EPOCH_TRANSITION_STATE_PREPARED:
				if (!no_failure) {
					return contradiction();
				}
				if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED) {
					return action::PERSIST_PREPARED;
				}
				if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED ||
				    local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING) {
					return action::RETRY_ACTIVATE;
				}
				if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING) {
					return action::RETRY_ABORT;
				}
				return contradiction();
			case remote_state::EPOCH_TRANSITION_STATE_COMMITTING:
				if (!no_failure) {
					return contradiction();
				}
				if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING) {
					return action::QUERY_COMPLETION;
				}
				return contradiction();
			case remote_state::EPOCH_TRANSITION_STATE_RETIRING:
				if (failure_code ==
				    remote_failure::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED) {
					if (local_phase ==
					    durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING) {
						return action::PRESERVE_UPDATE_FROZEN;
					}
					return contradiction();
				}
				if (!no_failure) {
					return contradiction();
				}
				if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING) {
					return action::QUERY_COMPLETION;
				}
				return contradiction();
			case remote_state::EPOCH_TRANSITION_STATE_UNSPECIFIED:
			case remote_state::EPOCH_TRANSITION_STATE_AWAITING_BOOTSTRAP:
			case remote_state::EPOCH_TRANSITION_STATE_BOOTSTRAPPING:
			case remote_state::EPOCH_TRANSITION_STATE_COMPLETE:
			case remote_state::EPOCH_TRANSITION_STATE_ABORTED:
			case remote_state::EPOCH_TRANSITION_STATE_IDLE:
			case kinetum::telemetry::v1::EpochTransitionState_INT_MIN_SENTINEL_DO_NOT_USE_:
			case kinetum::telemetry::v1::EpochTransitionState_INT_MAX_SENTINEL_DO_NOT_USE_:
				return contradiction();
			case remote_state::EPOCH_TRANSITION_STATE_FAILED_STOP:
				return fail_stop_failure(failure_code) ?
					       kinetum::common::status_or<action>(action::FAIL_CLOSED) :
					       contradiction();
			}
			return contradiction();

		case resolution::TERMINAL_EXACT:
			if (observed_state == remote_state::EPOCH_TRANSITION_STATE_COMPLETE && no_failure &&
			    (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING ||
			     local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE)) {
				return action::PERSIST_COMPLETE;
			}
			if (observed_state == remote_state::EPOCH_TRANSITION_STATE_ABORTED &&
			    precommit_failure(failure_code) &&
			    (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED ||
			     local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED ||
			     local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING ||
			     local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING ||
			     local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED)) {
				return action::PERSIST_ABORTED;
			}
			if (observed_state == remote_state::EPOCH_TRANSITION_STATE_FAILED_STOP &&
			    fail_stop_failure(failure_code)) {
				return action::FAIL_CLOSED;
			}
			return contradiction();

		case resolution::EXPIRED_RETRY:
			return no_failure ? kinetum::common::status_or<action>(action::REQUIRE_JOINT_RESTART) :
					    contradiction();

		case resolution::UNKNOWN_FUTURE:
			if (!no_failure || observed_state != remote_state::EPOCH_TRANSITION_STATE_UNSPECIFIED) {
				return contradiction();
			}
			if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED) {
				return action::RETRY_PREPARE;
			}
			if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING) {
				return action::PERSIST_ABORTED;
			}
			if (local_phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED) {
				return action::PERSIST_ABORTED;
			}
			return contradiction();

		case resolution::POLICY_DISABLED:
		case resolution::STATE_UNAVAILABLE:
			return no_failure ? kinetum::common::status_or<action>(action::PRESERVE_UNAVAILABLE) :
					    contradiction();
		}
		return contradiction();
	} catch (const std::bad_alloc &) {
		return kinetum::common::status::resource_exhausted(kinetum::common::static_status_text(
			"transition reconciliation classification exhausted memory"));
	}
}

}  // namespace kinetum::cp
