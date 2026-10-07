// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file boundary_topology_lowering.hpp
 * @brief Deterministic lowering of executable cross-worker boundaries.
 * @author Fleming Patel
 *
 * This cold-path pass consumes final stage-instance, worker, and region-NUMA
 * ownership after runtime core placement. It emits one plan-owned
 * BoundaryPlacement for each distinct directed cross-worker executable edge
 * and no record for a same-worker edge. Runtime code must consume those exact
 * records rather than infer channels from logical regions.
 */

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/status.hpp"

namespace kinetum::gluon
{

/**
 * @brief Lower final executable ownership into deterministic boundaries.
 *
 * The input plan must already contain canonical execution lanes, stage
 * instances, worker placements, and region NUMA placement, and boundaries[]
 * must be empty. The pass validates fixed stage-instance ID grammar, exact
 * worker ownership, and lane-complete executable edges before publishing any
 * output. Multiple authored edges with the same directed executable endpoints
 * collapse to one SPSC boundary.
 *
 * @param plan Deployment plan with final executable and core placement facts.
 * @return OK after transactional publication; INVALID_ARGUMENT when any input
 *         fact is missing, duplicate, ambiguous, noncanonical, or prepopulated.
 *
 * @par Thread Safety
 * The caller must exclusively own plan. This function is cold-path planning
 * code and performs no synchronization.
 */
[[nodiscard]] kinetum::common::status lower_boundary_topology(kinetum::gluon::v1::DeploymentPlan &plan);

}  // namespace kinetum::gluon
