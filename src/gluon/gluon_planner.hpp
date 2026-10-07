// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file gluon_planner.hpp
 * @brief Gluon Planner: Pipeline partitioning and binding.
 * @author Fleming Patel
 *
 * Gluon transforms an Axiom pipeline IR into an executable DeploymentPlan.
 * The production planner has one runtime-shape authority:
 *
 * **Planning Algorithm:**
 *
 * 1. **Linear DP**: O(n^2*r) dynamic programming with optimal makespan
 *    - Minimizes maximum region weight for load balancing
 *    - Respects pinning and affinity constraints
 *    - Deterministic: same inputs produce identical placement/identity facts
 *
 * **Key Properties:**
 *
 * - Exact provider instances and packet-path bindings are required input
 * - Explicit executable lanes, stage instances, I/O streams, and workers
 * - No runtime inference of boundaries or transition-service ownership
 * - Region-local NUMA placement keeps workers and lifecycle services explicit
 * - Deterministic emitted topology for reproducible deployments
 *
 * The compact schema also defines BoundaryPlacement and transition-service
 * ownership. Runtime services, exact executable boundaries, source-worker
 * staging, policy-independent owner observation cadence/health budget, and one
 * complete epoch-transition policy are emitted deterministically before
 * canonical plan hashing.
 *
 */

#include <cstdint>
#include <vector>

#include "src/common/status_or.hpp"
#include "gen/kinetum/gluon/v1/bindings.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "gen/kinetum/axiom/v1/axiom.pb.h"

namespace kinetum::gluon
{

// =============================================================================
// Planner Configuration
// =============================================================================

/**
 * @brief Configuration options for the Gluon planner.
 */
struct planner_options {
	int32_t regions{2};  ///< Number of logical regions to partition into.

	/**
	 * Lowest logical cores excluded from packet-worker assignment.
	 *
	 * Runtime services consume this pool first in ascending core-ID order.
	 * Any reserved cores not needed by services remain unused.
	 */
	int32_t reserved_cores{1};

	/**
	 * Balance indivisible logical-region worker groups across eligible NUMA
	 * nodes. Every worker in one region remains on one node, and lifecycle
	 * executors are placed on every module-bearing node. When false, lower NUMA
	 * IDs are filled first. Multi-NUMA placement requires cpu.core_topology[].
	 */
	bool numa_aware{true};

	/**
	 * Prefer non-hyperthread packet cores within each NUMA node. When false,
	 * packet candidates use ascending logical core ID without a sibling-class
	 * preference. Detailed cpu.core_topology[] facts are required to distinguish
	 * physical cores from hyperthread siblings.
	 */
	bool prefer_physical_cores{true};

	std::vector<int32_t> allowed_numa_nodes;  ///< Eligible nodes; empty admits every explicitly authored node.

	/**
	 * Complete exact deployment intent.
	 *
	 * Provider instances, logical ports, explicit queues, storage domains,
	 * execution-provider ownership, and storage transitions have no defaults.
	 * An incomplete message fails the authoring ladder before plan publication.
	 */
	kinetum::gluon::v1::DeploymentBindings deployment_bindings;
};

// =============================================================================
// Core Planning API
// =============================================================================

/**
 * @brief Generate a deployment plan from a pipeline and hardware inventory.
 *
 * This is the primary entry point for the Gluon planner. It transforms an
 * Axiom pipeline IR into an executable DeploymentPlan by:
 *
 * 1. Validating the pipeline structure (DAG, stage references)
 * 2. Computing a deterministic topological order
 * 3. Extracting and validating constraints
 * 4. Partitioning stages into regions using the selected algorithm
 * 5. Lowering executable lanes, stage instances, I/O streams, and workers
 * 6. Assigning region-local worker and runtime-service cores with NUMA awareness
 * 7. Emitting the exact provider graph and deterministic identity facts
 *
 * Exact boundary and live-transition-policy lowering is deterministic and
 * explicit. Runtime-service placement, source-worker future-input capacity,
 * worker health policy, and the complete epoch_transition_plan are emitted
 * before provider-aware plan identity is finalized.
 *
 * @param pipeline The Axiom pipeline to plan
 * @param hw Hardware inventory for resource constraints
 * @param opt Planning options and constraints
 * @return The deployment plan or an error status
 *
 * @note Deterministic placement and identity facts are stable for identical
 *       inputs; planning timestamps and durations are intentionally variable.
 * @note Thread-safe: can be called concurrently on different pipelines.
 */
[[nodiscard]] kinetum::common::status_or<kinetum::gluon::v1::DeploymentPlan>
plan(const kinetum::axiom::v1::Pipeline &pipeline, const kinetum::hw::v1::HardwareInventory &hw,
     const planner_options &opt);

/**
 * @brief Compute the default weight for a stage based on its kind.
 *
 * Weights are stable relative planning heuristics used by the partitioning
 * algorithm. They are not measured CPU costs or performance evidence.
 *
 * Default weights:
 * - RX/TX: 0 (partition endpoints)
 * - PARSE_IPV4: 1 (baseline parser)
 * - ACL: 3 (rule evaluation)
 * - NAT44: 4 (session lookup and checksum update)
 * - QOS: 3 (flow policer)
 * - MODULE: 5 (generic heuristic for another admitted module)
 *
 * @param stage The stage to compute weight for
 * @return The computed weight
 */
[[nodiscard]] uint64_t default_stage_weight(const kinetum::axiom::v1::Stage &stage) noexcept;

}  // namespace kinetum::gluon
