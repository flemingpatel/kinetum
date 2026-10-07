// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_compat.hpp
 * @brief Strict plan-vs-host CPU and NUMA compatibility gate.
 * @author Fleming Patel
 *
 * This module proves the shared compiler's packet-worker, runtime-service, and
 * host-memory requirements against the actual host topology discovered by
 * probe_host(). It returns only a decision and diagnostics without reparsing a
 * DeploymentPlan, interpreting provider configuration, or republishing
 * placement.
 *
 * ## Three-Phase Ownership
 *
 * 1. **Probe** (host_probe.hpp): discover what the process may use.
 * 2. **Validate** (this file): prove compiled requirements against that truth.
 * 3. **Apply**: later owners consume the original compiled topology through
 *    their launchers and materializers.
 *
 * ## Design Rationale
 *
 * - Gluon stays host-agnostic (plan provenance and reproducibility)
 * - provider semantics belong to the pure provider-contract catalog
 * - Quark owns host CPU and NUMA evidence only
 * - unavailable or mismatched placement always fails closed
 * - successful proof permits startup to continue with the same compiled truth
 *
 * @see host_probe.hpp for runtime CPU discovery
 * @see dp_main.cpp for gate wiring point
 */

#include <string>
#include <vector>

#include "src/provider/compiled_provider_topology.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::quark
{

// =============================================================================
// Compatibility Report
// =============================================================================

/**
 * @brief Result of plan/host compatibility validation.
 *
 * The report decides only whether startup may continue with the original
 * compiled topology. It never republishes worker, service, or process-core
 * placement as a second materialization authority.
 */
struct compat_report {
	/** @brief Whether the validation passed. */
	bool compatible{false};

	/** @brief Human-readable summary of validation result. */
	std::string summary;

	/** @brief Detailed diagnostics for logging on failure. */
	std::vector<std::string> diagnostics;
};

// =============================================================================
// Validation Function
// =============================================================================

/**
 * @brief Prove compiled CPU and host-NUMA requirements against live topology.
 *
 * This is the live-host compatibility gate. Called once at DP startup after
 * the sole shared provider compiler and before any worker, component, or native
 * resource. Quark never reparses the plan or reconstructs structural truth. It
 * proves each compiled worker/service CPU and each QUARK_LIVE_HOST NUMA-memory
 * requirement against one immutable host probe.
 *
 * @param topology Sole compiled semantic artifact for this exact plan.
 * @param host The discovered host topology from probe_host().
 * @return Compatibility decision plus bounded human-readable evidence. The
 *         original compiled topology remains the sole placement authority.
 * @throws std::bad_alloc If cold report storage cannot be allocated.
 * @throws std::length_error If report storage is not representable.
 *
 * Any unavailable core, unknown NUMA ownership, NUMA mismatch, malformed host
 * topology, unavailable host-memory node, or malformed compiled requirement
 * returns `compatible=false`. The function never filters, repairs, or
 * supplements compiled truth.
 */
[[nodiscard]] compat_report validate_runtime_compat(const kinetum::provider::compiled_provider_topology &topology,
						    const host_topology &host);

}  // namespace kinetum::quark
