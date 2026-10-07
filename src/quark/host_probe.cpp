// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file host_probe.cpp
 * @brief Runtime host CPU topology discovery implementation.
 * @author Fleming Patel
 *
 * Detection Method:
 * - sched_getaffinity(2) respects cgroup cpuset, taskset, and any CPU isolation
 *   reflected in the current process affinity mask.
 * - numa_get_mems_allowed() reports the NUMA memory nodes the process cpuset
 *   permits, so global machine memory cannot satisfy a process-local proof.
 *
 * This is cold-path startup code only. Called once before worker launch.
 *
 * @see host_probe.hpp for interface documentation
 */

#include "src/quark/host_probe.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <memory>
#include <sstream>
#include <unistd.h>

#include <numa.h>

#include "src/common/linux_cpu_set.hpp"
#include "src/common/log.hpp"

namespace kinetum::quark
{

namespace
{

/** @brief Release one libnuma bitmask returned by a discovery operation. */
struct numa_bitmask_deleter {
	/**
	 * @brief Free a libnuma bitmask.
	 *
	 * @param mask Bitmask to release; nullptr is accepted.
	 */
	void operator()(struct bitmask *mask) const noexcept
	{
		if (mask != nullptr) {
			numa_bitmask_free(mask);
		}
	}
};

/**
 * @brief Narrow an OS CPU count into host_topology::online_count.
 *
 * @param count OS-reported CPU count.
 * @return Zero for a nonpositive count, otherwise the count capped at int32.
 */
[[nodiscard]] int32_t clamp_cpu_count(long count) noexcept
{
	if (count <= 0) {
		return 0;
	}
	if (count > static_cast<long>(std::numeric_limits<int32_t>::max())) {
		return std::numeric_limits<int32_t>::max();
	}
	return static_cast<int32_t>(count);
}

}  // namespace

// =============================================================================
// host_topology methods
// =============================================================================

std::string host_topology::summary() const
{
	if (!valid)
		return "invalid (discovery failed)";

	std::ostringstream os;
	os << cpus.size() << " cores available";

	if (!cpus.empty()) {
		// Build range notation: [0-5] or [0,2,4] for non-contiguous
		os << " [";
		bool contiguous = true;
		for (std::size_t i = 1; i < cpus.size(); ++i) {
			if (cpus[i - 1].core_id == std::numeric_limits<int32_t>::max() ||
			    cpus[i].core_id != cpus[i - 1].core_id + 1) {
				contiguous = false;
				break;
			}
		}

		if (contiguous && cpus.size() > 1) {
			os << cpus.front().core_id << "-" << cpus.back().core_id;
		} else {
			for (std::size_t i = 0; i < cpus.size(); ++i) {
				if (i > 0)
					os << ",";
				os << cpus[i].core_id;
			}
		}
		os << "]";
	}

	if (online_count > 0 && static_cast<std::size_t>(online_count) > cpus.size()) {
		os << " (system has " << online_count << " online)";
	}
	if (!has_complete_numa_topology()) {
		os << " (NUMA unknown)";
	}
	if (memory_numa_nodes.empty()) {
		os << " (NUMA memory unavailable)";
	}

	return os.str();
}

bool host_topology::has_core(int32_t core_id) const noexcept
{
	const auto it = std::lower_bound(cpus.begin(), cpus.end(), core_id,
					 [](const host_cpu &cpu, int32_t id) { return cpu.core_id < id; });
	return it != cpus.end() && it->core_id == core_id;
}

std::optional<int32_t> host_topology::numa_node_for_core(int32_t core_id) const noexcept
{
	const auto it = std::lower_bound(cpus.begin(), cpus.end(), core_id,
					 [](const host_cpu &cpu, int32_t id) { return cpu.core_id < id; });
	if (it == cpus.end() || it->core_id != core_id || it->numa_node < 0) {
		return std::nullopt;
	}
	return it->numa_node;
}

bool host_topology::has_complete_numa_topology() const noexcept
{
	return !cpus.empty() &&
	       std::all_of(cpus.begin(), cpus.end(), [](const host_cpu &cpu) { return cpu.numa_node >= 0; });
}

bool host_topology::has_memory_numa_node(int32_t numa_node) const noexcept
{
	return std::binary_search(memory_numa_nodes.begin(), memory_numa_nodes.end(), numa_node);
}

// =============================================================================
// probe_host() - Process-Visible CPU Discovery
// =============================================================================
//
// sched_getaffinity(2) reports what this process may actually use, including
// cgroup and taskset restrictions. Global online inventory is diagnostic only.
// =============================================================================

host_topology probe_host()
{
	host_topology topo;

	// Get total online CPUs (sysconf is always available on Linux).
	const long online = sysconf(_SC_NPROCESSORS_ONLN);
	topo.online_count = clamp_cpu_count(online);

	// Query the OS-allowed CPU set for this process.
	// sched_getaffinity(2) returns the set after cgroup/cpuset/taskset filtering.
	common::linux_cpu_set set;
	const int rc = common::linux_cpu_set::capture_current_thread(set);
	if (rc != 0) {
		KINETUM_LOG_ERROR("quark", "quark.affinity.failed", "sched_getaffinity failed (errno={})", rc);
		topo.valid = false;
		return topo;
	}

	const int numa_available_result = numa_available();
	if (numa_available_result >= 0) {
		std::unique_ptr<struct bitmask, numa_bitmask_deleter> allowed_memory_nodes(numa_get_mems_allowed());
		if (allowed_memory_nodes == nullptr) {
			KINETUM_LOG_ERROR("quark", "quark.memory_mask.failed", "numa_get_mems_allowed failed");
			topo.valid = false;
			return topo;
		}
		const int maximum_node = numa_max_node();
		if (maximum_node < 0 || allowed_memory_nodes->size <= static_cast<unsigned long>(maximum_node)) {
			KINETUM_LOG_ERROR("quark", "quark.memory_mask.invalid",
					  "libnuma returned an incoherent allowed-memory mask");
			topo.valid = false;
			return topo;
		}
		for (int node = 0; node <= maximum_node; ++node) {
			if (numa_bitmask_isbitset(allowed_memory_nodes.get(), static_cast<unsigned int>(node)) == 0) {
				continue;
			}
			long long free_bytes = 0;
			const long long total_bytes = numa_node_size64(node, &free_bytes);
			if (total_bytes > 0) {
				topo.memory_numa_nodes.push_back(node);
			}
		}
	}

	// Walk the complete kernel-accepted set. Dynamic capture keeps sparse CPU
	// identities above libc's fixed cpu_set_t extent representable.
	for (std::size_t i = 0; i < set.capacity(); ++i) {
		const auto core_id = static_cast<int32_t>(i);
		if (set.contains(core_id)) {
			int32_t numa_node = -1;
			if (numa_available_result >= 0) {
				numa_node = numa_node_of_cpu(core_id);
			}
			topo.cpus.push_back(host_cpu{core_id, numa_node});
		}
	}

	// cpus is already sorted (we iterated ascending).
	topo.valid = true;

	KINETUM_LOG_INFO("quark", "quark.host.probed", "host probe: {}", topo.summary());
	return topo;
}

}  // namespace kinetum::quark
