// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file transition_plan_lowering.hpp
 * @brief Transactional lowering of plan-owned epoch-transition policy.
 * @author Fleming Patel
 *
 * This pass runs after executable worker, service, and boundary placement. It
 * emits one explicit baseline transition profile, marks only workers owning an
 * RX or active packet-originating stage with future-input capacity, and
 * validates the complete candidate through the shared transition-topology
 * compiler before publication.
 *
 * @par Thread Safety
 * The function mutates only its caller-owned plan and has no shared state.
 * Concurrent calls are safe only for distinct plans.
 *
 * @par Performance
 * This is allocation-using planner cold-path work and must not run in a runtime
 * worker or module callback.
 */

#include <cstdint>

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/status.hpp"

namespace kinetum::gluon
{

/** @brief Per-queue source-worker epoch-staging capacity in the generated profile. */
inline constexpr uint32_t SOURCE_EPOCH_STAGING_CAPACITY = 1024;
static_assert(SOURCE_EPOCH_STAGING_CAPACITY >= 2u, "source epoch-staging capacity must contain at least two slots");
static_assert((SOURCE_EPOCH_STAGING_CAPACITY & (SOURCE_EPOCH_STAGING_CAPACITY - 1u)) == 0u,
	      "source epoch-staging capacity must be a power of two");

/** @brief Policy-independent owner telemetry/health cadence in milliseconds. */
inline constexpr uint64_t MODULE_HEALTH_POLL_INTERVAL_MS = 1000;

/** @brief Maximum owner-worker health callback pause in nanoseconds. */
inline constexpr uint64_t MODULE_HEALTH_CALLBACK_BUDGET_NS = 10'000;

/** @brief Abortable cold preparation timeout in milliseconds. */
inline constexpr uint64_t TRANSITION_PREPARE_TIMEOUT_MS = 30'000;

/** @brief Cooperative prepare cancellation grace in milliseconds. */
inline constexpr uint64_t TRANSITION_PREPARE_CANCEL_GRACE_MS = 1'000;

/** @brief Prepared transaction lease in milliseconds. */
inline constexpr uint64_t TRANSITION_PREPARED_LEASE_TIMEOUT_MS = 60'000;

/** @brief Completion-only ordered-cut commit timeout in milliseconds. */
inline constexpr uint64_t TRANSITION_COMMIT_TIMEOUT_MS = 5'000;

/** @brief Retirement update-freeze timeout in milliseconds. */
inline constexpr uint64_t TRANSITION_RETIREMENT_TIMEOUT_MS = 5'000;

/** @brief Bounded terminal-result history entries in the generated profile. */
inline constexpr uint32_t TRANSITION_RESULT_HISTORY_CAPACITY = 16;

/**
 * @brief Lower one complete epoch-transition policy into a deployment plan.
 *
 * The input must have empty epoch_transition_plan and zero transition/health
 * worker fields. The function builds and validates a full candidate copy, then
 * atomically swaps it into @p plan. Rejection leaves @p plan unchanged.
 *
 * @param plan Deployment plan with final workers, services, stages, boundaries,
 *             and buffer profiles.
 * @return OK after complete validated publication; INVALID_ARGUMENT,
 *         OUT_OF_RANGE, or INTERNAL_ERROR when emission cannot satisfy the
 *         shared contract.
 *
 * @warning Successful publication invalidates every pointer or reference to a
 *          submessage of @p plan. Callers must reacquire submessages after this
 *          function returns.
 */
[[nodiscard]] kinetum::common::status lower_transition_plan(kinetum::gluon::v1::DeploymentPlan &plan);

}  // namespace kinetum::gluon
