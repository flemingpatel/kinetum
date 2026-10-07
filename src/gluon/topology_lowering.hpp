// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file topology_lowering.hpp
 * @brief Gluon lowering from exact deployment intent to executable topology.
 * @author Fleming Patel
 *
 * The partitioner decides logical stage-to-region placement. This phase emits
 * execution lanes, stage instances, I/O streams, workers, traffic steering,
 * module-context domains, and exact module-context resource bounds from required
 * DeploymentBindings. Queue, descriptor, storage, execution-provider,
 * steering, and lifecycle-memory facts are copied only from exact authored
 * records; no omitted value creates a default stream or allocation capacity.
 */

#include "gen/kinetum/gluon/v1/bindings.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/status.hpp"

namespace kinetum::gluon
{

/**
 * @brief Lower plan regions and exact bindings into executable topology.
 *
 * Every pipeline stage must have one execution-provider binding and every I/O
 * direction must carry one nonempty explicit queue set. Queue sets are sorted
 * by driver_queue_id and map positionally to deterministic execution lanes.
 * Every module stage/lane must additionally carry one nonzero context-lifetime
 * and per-epoch arena capacity binding; platform stages may carry neither.
 * A multi-lane plan requires equal queue cardinality on every I/O direction so
 * the complete pipeline can be replicated with explicit context-selection
 * policy on every module stage.
 *
 * @param plan Deployment plan with pipeline, regions, provider instances, and
 *        ports populated.
 * @param bindings Required exact deployment bindings.
 * @return OK on success; INVALID_ARGUMENT when topology inputs are malformed
 *         or incomplete.
 */
[[nodiscard]] kinetum::common::status lower_execution_topology(kinetum::gluon::v1::DeploymentPlan &plan,
							       const kinetum::gluon::v1::DeploymentBindings &bindings);

}  // namespace kinetum::gluon
