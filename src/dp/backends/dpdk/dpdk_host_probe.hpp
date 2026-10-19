// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dpdk_host_probe.hpp
 * @brief Non-materializing DPDK runtime, hugepage, and PCI ownership proof.
 * @author Fleming Patel
 *
 * The DPDK facility contract requires a linked runtime, a minimum hugepage floor,
 * and exclusive PCI ownership before materialization initializes EAL. The probe
 * consumes the role-tagged compiled facility facts, performs bounded read-only
 * host inspection, and closes every temporary descriptor before return.
 */

#include <cstdint>

#include "src/dp/backends/dpdk/dpdk_pci_probe.hpp"
#include "src/provider/provider_component_abi.h"

namespace kinetum::provider::dpdk_component
{

/** @brief Cold native calls used by the non-materializing DPDK host proof. */
struct dpdk_host_probe_api {
	/** Optional injected test state. */
	void *state;
	const char *(*runtime_version)(void *state) noexcept;  ///< Return the linked DPDK runtime identity.
	int (*read_meminfo)(void *state, char *buffer, uint32_t capacity,
			    uint32_t *size) noexcept;  ///< Read bounded Linux /proc/meminfo bytes.
	dpdk_pci_probe_api pci;			       ///< Shared read-only PCI observation mechanism.
};

/**
 * @brief Return the complete production DPDK host-probe API.
 *
 * @return Immutable value table over linked DPDK and bounded Linux file I/O.
 */
[[nodiscard]] dpdk_host_probe_api default_dpdk_host_probe_api() noexcept;

/**
 * @brief Prove the current host can begin one exact DPDK facility transaction.
 *
 * The operation validates the empty DPDK facility contract and its exact
 * process-facility fact tree, verifies a linked DPDK runtime identity, and
 * proves that currently unreserved hugepage bytes cover at least the complete
 * plan-visible packet-payload floor. Exact mempool overhead, page placement,
 * and allocation remain native materialization results; this probe never
 * initializes EAL or reserves memory. The declared PCI attachment set passes
 * the same adapter-ownership proof used immediately before EAL initialization.
 *
 * @param request Exact role-tagged facility proof request.
 * @param api Complete bounded host-inspection mechanism.
 * @param diagnostic Optional caller-owned bounded diagnostic.
 * @return OK only after every current component-phase host fact is proven.
 */
[[nodiscard]] kinetum_provider_status prove_dpdk_host(const kinetum_provider_host_proof_request &request,
						      const dpdk_host_probe_api &api,
						      kinetum_provider_diagnostic *diagnostic) noexcept;

}  // namespace kinetum::provider::dpdk_component
