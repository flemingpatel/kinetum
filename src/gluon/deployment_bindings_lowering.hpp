// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file deployment_bindings_lowering.hpp
 * @brief Exact DeploymentBindings validation and deterministic plan lowering.
 * @author Fleming Patel
 *
 * This cold authoring boundary converts environment-specific deployment intent
 * into provider-graph and packet-path facts in one DeploymentPlan. It owns the
 * authoring ladder: strict protobuf validation, identifier/scalar validation,
 * role-correct provider canonicalization, local reference integrity,
 * two-directional pipeline coverage, hardware resolution, logical transition
 * resolution, and deterministic emission.
 *
 * Complete facility reachability, access compatibility, transition-set
 * equality, NUMA feasibility, and resource-budget proof belong to the shared
 * provider-topology compiler. This component neither guesses those facts nor
 * performs native provider operations.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent calls on distinct messages. Callers must
 * not mutate any input concurrently.
 *
 * @par Performance
 * Cold-path only. Validation parses typed provider configuration and uses
 * allocation-backed maps and sorting before plan publication.
 */

#include "gen/kinetum/gluon/v1/bindings.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "src/common/status.hpp"

namespace kinetum::gluon
{

/**
 * @brief Lower one complete exact deployment binding into a candidate plan.
 *
 * The plan must already contain its pipeline and logical region partition.
 * Provider arrays, ports, executable topology, and storage transitions are
 * replaced transactionally on a candidate copy and published only after the
 * complete authoring ladder succeeds.
 *
 * @param bindings Required complete deployment intent.
 * @param hardware Physical hardware facts used for exact attachment resolution.
 * @param plan Candidate plan containing pipeline and regions.
 * @return OK after deterministic publication, or the first stable authoring
 *         validation failure. No native side effect occurs.
 */
[[nodiscard]] kinetum::common::status lower_deployment_bindings(const kinetum::gluon::v1::DeploymentBindings &bindings,
								const kinetum::hw::v1::HardwareInventory &hardware,
								kinetum::gluon::v1::DeploymentPlan &plan);

}  // namespace kinetum::gluon
