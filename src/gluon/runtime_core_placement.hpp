// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_core_placement.hpp
 * @brief Deterministic CPU and NUMA placement for workers and runtime services.
 * @author Fleming Patel
 *
 * This cold-path lowering component assigns packet workers and provider-neutral
 * runtime services together so their CPU ownership cannot overlap. It keeps
 * every worker in a logical region on that region's NUMA node, emits one
 * coordinator with explicit command-mailbox capacity plus the required
 * zero-mailbox NUMA-local lifecycle executors. Provider-facility compilation
 * consumes those plan fields directly.
 *
 * The component mutates a DeploymentPlan only after a complete assignment has
 * been found. Failure therefore leaves worker, region, and service placement
 * facts unchanged.
 *
 * @par Thread Safety
 * Functions are reentrant and use no shared mutable state. Callers must provide
 * exclusive access to the DeploymentPlan being lowered.
 */

#include <cstdint>
#include <vector>

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::gluon
{

/** @brief Command slots emitted for the sole transition coordinator. */
inline constexpr uint32_t COORDINATOR_COMMAND_MAILBOX_CAPACITY = 64u;

/**
 * @brief CPU-placement policy consumed by deterministic runtime lowering.
 */
struct runtime_core_placement_options {
	/**
	 * Lowest logical cores excluded from packet workers. Runtime services use
	 * this pool first; any remainder stays unused.
	 */
	int32_t reserved_cores{1};

	/** @brief Balance logical regions across eligible NUMA nodes when true. */
	bool numa_aware{true};

	/** @brief Prefer non-hyperthread cores for packet workers when true. */
	bool prefer_physical_cores{true};

	/** @brief Allowed NUMA nodes; empty admits every represented node. */
	std::vector<int32_t> allowed_numa_nodes;
};

/**
 * @brief Lower worker and runtime-service CPU ownership into a deployment plan.
 *
 * Packet workers consume non-reserved cores. Runtime services consume reserved
 * cores in ascending core-ID order first, then the least packet-preferred
 * non-reserved spares. Unconsumed reserved cores remain unassigned. The emitted
 * service table contains the coordinator first and lifecycle executors in
 * ascending NUMA-node order. All worker and service cores are pairwise distinct.
 *
 * The singular hardware node's explicit `cpu.core_topology[]` rows are the
 * complete assignable core set. Missing rows, duplicate core IDs, and unknown
 * or negative NUMA ownership fail closed; no count can synthesize a core.
 *
 * @param plan Plan with regions and worker_placements[] already lowered.
 * @param hardware Hardware inventory supplying assignable CPU topology.
 * @param options Deterministic placement policy.
 * @return OK after atomically publishing a complete placement; otherwise a
 *         fail-closed error with the input plan unchanged.
 *
 * @note Cold path only. This function may allocate and sort temporary storage.
 */
[[nodiscard]] kinetum::common::status lower_runtime_core_placement(kinetum::gluon::v1::DeploymentPlan &plan,
								   const kinetum::hw::v1::HardwareInventory &hardware,
								   const runtime_core_placement_options &options);

}  // namespace kinetum::gluon
