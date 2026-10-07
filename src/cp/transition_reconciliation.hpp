// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file transition_reconciliation.hpp
 * @brief Typed Control Plane restart reconciliation for one exact transition.
 * @author Fleming Patel
 *
 * This cold-path component maps CP durable intent plus the DP coordinator's
 * typed identity and phase observation to one exact recovery action. It never
 * parses diagnostic text, infers identity from an epoch, or mutates durable
 * state. The selected action names the exact config-store operation for the
 * sole control writer; the public gRPC adapter remains owned by the complete
 * passive-protocol activation.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent immutable inputs.
 *
 * @par Performance
 * Constant-time control-path classification with no allocation on success.
 * It must never execute from a packet worker or module callback.
 */

#include <cstdint>

#include "gen/kinetum/control/internal/v1/transition_authority.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::cp
{

/** @brief Exact next CP action selected from typed reconciliation evidence. */
enum class transition_reconciliation_action : uint8_t {
	RETRY_PREPARE = 0,	 ///< DP has never admitted the durable allocation.
	WAIT_FOR_PREPARE,	 ///< Exact DP preparation remains in progress.
	PERSIST_PREPARED,	 ///< DP proves PREPARED; persist that CP knowledge.
	RETRY_ACTIVATE,		 ///< CP may issue the exact Activate intent.
	QUERY_COMPLETION,	 ///< Commit may have begun; status queries are the only action.
	RETRY_ABORT,		 ///< CP has durable abort intent for an abortable DP phase.
	PERSIST_COMPLETE,	 ///< Exact terminal COMPLETE may atomically promote active state.
	PERSIST_ABORTED,	 ///< Exact terminal ABORTED may retain consumed watermarks.
	REQUIRE_JOINT_RESTART,	 ///< Retained allocation has no DP journal proof.
	PRESERVE_UNAVAILABLE,	 ///< DP policy/state cannot currently reconcile the transaction.
	PRESERVE_UPDATE_FROZEN,	 ///< Exact RETIRING grace timeout requires operator recovery.
	FAIL_CLOSED,		 ///< Typed evidence proves conflict or unsafe divergence.
};

/**
 * @brief Select one total typed reconciliation action.
 *
 * The function is exhaustive over every shared identity resolution and every
 * DP transition phase. A combination that violates CP's durable phase order
 * returns DATA_LOSS rather than selecting a nearby action.
 *
 * @param local_phase Exact admitted CP durable phase.
 * @param identity_resolution Typed DP identity-resolution result.
 * @param observed_state Typed DP transaction state accompanying the result.
 * @param failure_code Typed DP failure/freeze cause accompanying the state.
 * @return One exact action, or DATA_LOSS for a malformed/contradictory tuple.
 */
[[nodiscard]] kinetum::common::status_or<transition_reconciliation_action>
classify_transition_reconciliation(kinetum::control::internal::v1::DurableEpochTransitionPhase local_phase,
				   kinetum::common::transition_identity_resolution identity_resolution,
				   kinetum::telemetry::v1::EpochTransitionState observed_state,
				   kinetum::telemetry::v1::EpochTransitionFailureCode failure_code) noexcept;

}  // namespace kinetum::cp
