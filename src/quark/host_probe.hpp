// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file host_probe.hpp
 * @brief Runtime host CPU and NUMA topology discovery for Quark.
 * @author Fleming Patel
 *
 * This module provides the provider-neutral OS facts used by Quark's strict
 * plan/host placement proof. Provider capability meaning belongs to the pure
 * provider-contract catalog and is not inferred from host discovery.
 *
 * ## Design Rationale
 *
 * Host discovery reports only process-visible OS truth. Planning and provider
 * configuration remain immutable inputs owned by their respective compilers.
 *
 * ## Detection Method
 *
 * Uses sched_getaffinity(2) as the CPU discovery mechanism. This respects:
 * - cgroup cpuset constraints (container deployments)
 * - taskset restrictions
 * - any CPU isolation policy that is reflected in the process affinity mask
 *
 * Uses libnuma's process-allowed memory mask for host-memory discovery. A NUMA
 * node that exists globally but is excluded by the current cpuset is not
 * reported as allocatable host memory.
 *
 * The process affinity mask, rather than global online CPU inventory, is the
 * authority for CPUs this process may use.
 *
 * @see runtime_compat.hpp for plan/host validation gate
 */

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace kinetum::quark
{

/**
 * @brief One process-available CPU with proven NUMA ownership when available.
 */
struct host_cpu {
	int32_t core_id{-1};	///< Logical CPU identifier.
	int32_t numa_node{-1};	///< NUMA node, or -1 when the host cannot prove it.
};

/**
 * @brief Discovered host CPU topology at runtime.
 *
 * Immutable after construction. Captures the OS-allowed CPU set and
 * basic topology information for the current process.
 */
struct host_topology {
	/**
	 * Process-available CPUs sorted by core_id and duplicate-free. Each record
	 * carries the sole CPU-NUMA fact used by compiled-provider host admission.
	 */
	std::vector<host_cpu> cpus;

	/** Sorted host NUMA nodes with positive memory that the current process may allocate. */
	std::vector<int32_t> memory_numa_nodes;

	int32_t online_count{0};  ///< System online CPUs; may exceed cpus.size().

	bool valid{false};  ///< Whether OS topology discovery succeeded.

	/**
	 * @brief Format a bounded human-readable topology summary.
	 *
	 * @return CPU availability, affinity range, online count, and whether NUMA
	 *         ownership is incomplete.
	 */
	std::string summary() const;

	/**
	 * @brief Check whether a logical CPU is process-available.
	 *
	 * Uses binary search over the sorted cpus records.
	 *
	 * @param core_id Logical CPU identifier.
	 * @return true when the process affinity set contains @p core_id.
	 */
	[[nodiscard]] bool has_core(int32_t core_id) const noexcept;

	/**
	 * @brief Return one available core's proven NUMA node.
	 *
	 * @param core_id Logical CPU identifier.
	 * @return Nonnegative NUMA node when known; nullopt for an unavailable CPU or
	 *         when NUMA ownership could not be proven.
	 */
	[[nodiscard]] std::optional<int32_t> numa_node_for_core(int32_t core_id) const noexcept;

	/**
	 * @brief Check whether every process-available CPU has proven NUMA ownership.
	 *
	 * @return true only when cpus is nonempty and every numa_node is nonnegative.
	 */
	[[nodiscard]] bool has_complete_numa_topology() const noexcept;

	/**
	 * @brief Check whether a NUMA node can back host packet memory.
	 *
	 * @param numa_node Nonnegative NUMA node required by compiled topology.
	 * @return true only when live host discovery reports positive memory on the
	 *         exact node.
	 */
	[[nodiscard]] bool has_memory_numa_node(int32_t numa_node) const noexcept;
};

/**
 * @brief Discover the host's CPU topology at runtime.
 *
 * Uses Linux sched_getaffinity(2) to discover the exact CPU set available to
 * the current process and libnuma's process-allowed memory mask to intersect
 * global memory-bearing NUMA nodes with cpuset policy. The top-level build
 * rejects non-Linux targets or absence of the required discovery dependency
 * rather than substituting an approximate topology source.
 *
 * This function is intended for cold-path startup only (DP preflight). It has
 * no shared mutable state, but callers should run it once before worker launch
 * so every region sees the same validated affinity view.
 *
 * @return host_topology with discovered CPU information.
 * @throws std::bad_alloc If cold topology storage cannot be allocated.
 * @throws std::length_error If discovered topology storage is not representable.
 */
[[nodiscard]] host_topology probe_host();

}  // namespace kinetum::quark
