// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_compat.cpp
 * @brief Strict compiled-topology-vs-host CPU and NUMA compatibility proof.
 * @author Fleming Patel
 */

#include "src/quark/runtime_compat.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <sstream>

namespace kinetum::quark
{

namespace
{

/**
 * @brief Validate the binary-search and NUMA-record shape of a host probe.
 *
 * Unknown NUMA ownership is a valid probe representation and rejects when a
 * selected plan core requires exact placement. Malformed values, duplicate CPU
 * IDs, and unsorted input are host-shape failures.
 *
 * @param host Host topology to validate.
 * @param report Compatibility report receiving failure diagnostics.
 * @return true when host lookup invariants are valid.
 */
[[nodiscard]] bool validate_host_shape(const host_topology &host, compat_report &report)
{
	if (!host.valid) {
		report.summary = "host topology discovery failed";
		report.diagnostics.push_back("probe_host() returned valid=false");
		return false;
	}

	if (host.cpus.empty()) {
		report.summary = "no available cores on host";
		report.diagnostics.push_back("host reports 0 available cores");
		return false;
	}

	if (!std::ranges::is_sorted(host.cpus, {}, &host_cpu::core_id)) {
		report.summary = "invalid host topology: cpus is not sorted";
		report.diagnostics.push_back("host.cpus must be sorted ascending for binary-search lookup");
		return false;
	}

	for (const auto &cpu : host.cpus) {
		if (cpu.core_id < 0 || cpu.numa_node < -1) {
			report.summary = "invalid host topology: malformed CPU/NUMA record";
			report.diagnostics.push_back("host.cpus contains malformed CPU/NUMA record for core " +
						     std::to_string(cpu.core_id));
			return false;
		}
	}

	if (std::adjacent_find(host.cpus.begin(), host.cpus.end(), [](const host_cpu &lhs, const host_cpu &rhs) {
		    return lhs.core_id == rhs.core_id;
	    }) != host.cpus.end()) {
		report.summary = "invalid host topology: duplicate CPU core id";
		report.diagnostics.push_back("host.cpus must not contain duplicate core IDs");
		return false;
	}

	if (!std::ranges::is_sorted(host.memory_numa_nodes)) {
		report.summary = "invalid host topology: memory_numa_nodes is not sorted";
		report.diagnostics.push_back("host.memory_numa_nodes must be sorted ascending");
		return false;
	}
	if (std::ranges::any_of(host.memory_numa_nodes, [](int32_t node) { return node < 0; }) ||
	    std::adjacent_find(host.memory_numa_nodes.begin(), host.memory_numa_nodes.end()) !=
		    host.memory_numa_nodes.end()) {
		report.summary = "invalid host topology: malformed NUMA-memory inventory";
		report.diagnostics.push_back("host.memory_numa_nodes must be nonnegative and duplicate-free");
		return false;
	}

	return true;
}

/**
 * @brief Validate one compiled runtime-service role defensively.
 *
 * @param role Shared transition-topology service role.
 * @return true for every declared compiled service role.
 */
[[nodiscard]] bool valid_runtime_service_role(kinetum::common::compiled_runtime_service_role role) noexcept
{
	switch (role) {
	case kinetum::common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR:
	case kinetum::common::compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR:
		return true;
	default:
		return false;
	}
}

/**
 * @brief Prove every Quark-owned external requirement against one host probe.
 *
 * Structural role/index validity is normally guaranteed by the sole compiler;
 * explicit checks keep this trust boundary fail-closed if malformed input
 * reaches it despite upstream compilation.
 *
 * @param topology Exact compiled provider artifact.
 * @param host Immutable live-host facts.
 * @param report Compatibility report receiving bounded diagnostics.
 * @param unavailable_memory_nodes Count of unsatisfied exact memory-node facts.
 * @return true only when every QUARK_LIVE_HOST requirement is understood and
 *         satisfied.
 */
[[nodiscard]] bool validate_quark_host_requirements(const kinetum::provider::compiled_provider_topology &topology,
						    const host_topology &host, compat_report &report,
						    uint32_t &unavailable_memory_nodes)
{
	bool valid = true;
	for (const auto &requirement : topology.host_requirements) {
		switch (requirement.phase) {
		case kinetum::provider::provider_host_proof_phase::QUARK_LIVE_HOST:
			break;
		case kinetum::provider::provider_host_proof_phase::COMPONENT_HOST_PROOF:
		case kinetum::provider::provider_host_proof_phase::MATERIALIZATION_PROOF:
			continue;
		default:
			report.diagnostics.push_back("compiled provider requirement has an invalid proof phase");
			valid = false;
			continue;
		}

		switch (requirement.fact) {
		case kinetum::provider::provider_host_fact::CPU_WORKER_SET:
			if (requirement.role != kinetum::provider::provider_contract_role::EXECUTION ||
			    requirement.instance_index >= topology.execution_providers.size()) {
				report.diagnostics.push_back(
					"compiled CPU-worker requirement has an invalid execution-provider owner");
				valid = false;
			}
			break;
		case kinetum::provider::provider_host_fact::HOST_NUMA_MEMORY: {
			std::optional<int32_t> required_node;
			std::string owner;
			switch (requirement.role) {
			case kinetum::provider::provider_contract_role::PACKET_STORAGE:
				if (requirement.instance_index < topology.storage_domains.size()) {
					const auto &domain = topology.storage_domains[requirement.instance_index];
					required_node = domain.host_numa_node;
					owner = "packet-storage domain '" + domain.storage_domain_id + "'";
				}
				break;
			case kinetum::provider::provider_contract_role::STORAGE_TRANSITION:
				if (requirement.instance_index < topology.storage_transitions.size()) {
					const auto &transition =
						topology.storage_transitions[requirement.instance_index];
					required_node = transition.staging_numa_node;
					owner = "storage transition '" + transition.transition_id + "'";
				}
				break;
			default:
				break;
			}
			if (owner.empty() || !required_node.has_value()) {
				report.diagnostics.push_back(
					"compiled host-memory requirement has an invalid or unplaced owner");
				valid = false;
				break;
			}
			if (!host.has_memory_numa_node(required_node.value())) {
				++unavailable_memory_nodes;
				const std::string diagnostic = owner + " requires host memory on NUMA node " +
							       std::to_string(required_node.value()) +
							       " but live host discovery cannot prove it";
				report.diagnostics.push_back(diagnostic);
				valid = false;
			}
			break;
		}
		case kinetum::provider::provider_host_fact::DPDK_EAL_RUNTIME:
		case kinetum::provider::provider_host_fact::DPDK_HUGEPAGE_PAYLOAD_FLOOR:
		case kinetum::provider::provider_host_fact::DPDK_ETHDEV_PORT:
		case kinetum::provider::provider_host_fact::LINUX_IPV4_DATAGRAM_SOCKET:
			report.diagnostics.push_back(
				"compiled provider requirement assigns a non-Quark host fact to QUARK_LIVE_HOST");
			valid = false;
			break;
		default:
			report.diagnostics.push_back("compiled provider requirement has an invalid host fact");
			valid = false;
			break;
		}
	}
	return valid;
}

}  // namespace

compat_report validate_runtime_compat(const kinetum::provider::compiled_provider_topology &topology,
				      const host_topology &host)
{
	compat_report report;
	const auto &transition_topology = topology.transition_topology;

	if (!validate_host_shape(host, report)) {
		return report;
	}

	bool invalid = false;
	uint32_t unavailable_worker_cores = 0;
	uint32_t unavailable_service_cores = 0;
	uint32_t incompatible_numa_cores = 0;
	uint32_t unavailable_memory_nodes = 0;
	uint32_t total_plan_cores = 0;

	for (const auto &worker : transition_topology.workers) {
		for (const int32_t core : worker.cpu_core_ids) {
			++total_plan_cores;
			if (!host.has_core(core)) {
				++unavailable_worker_cores;
				const std::string diagnostic = "worker '" + worker.worker_id + "': plan core " +
							       std::to_string(core) +
							       " is not available to this process";
				report.diagnostics.push_back(diagnostic);
				invalid = true;
				continue;
			}

			const auto host_numa = host.numa_node_for_core(core);
			if (!host_numa.has_value()) {
				++incompatible_numa_cores;
				const std::string diagnostic = "worker '" + worker.worker_id +
							       "': host NUMA ownership for core " +
							       std::to_string(core) + " is unknown";
				report.diagnostics.push_back(diagnostic);
				invalid = true;
				continue;
			}
			if (host_numa.value() != worker.numa_node) {
				++incompatible_numa_cores;
				const std::string diagnostic =
					"worker '" + worker.worker_id + "': plan core " + std::to_string(core) +
					" requires NUMA node " + std::to_string(worker.numa_node) +
					" but host reports node " + std::to_string(host_numa.value());
				report.diagnostics.push_back(diagnostic);
				invalid = true;
				continue;
			}
		}
	}

	for (const auto &service : transition_topology.runtime_services) {
		if (!valid_runtime_service_role(service.role)) {
			const std::string diagnostic = "shared compiler returned an unsupported runtime-service role";
			report.diagnostics.push_back(diagnostic);
			invalid = true;
			continue;
		}

		++total_plan_cores;
		if (!host.has_core(service.cpu_core_id)) {
			++unavailable_service_cores;
			const std::string diagnostic = "runtime service '" + service.service_id + "': plan core " +
						       std::to_string(service.cpu_core_id) +
						       " is not available to this process";
			report.diagnostics.push_back(diagnostic);
			invalid = true;
			continue;
		}

		const auto host_numa = host.numa_node_for_core(service.cpu_core_id);
		if (!host_numa.has_value()) {
			++incompatible_numa_cores;
			const std::string diagnostic = "runtime service '" + service.service_id +
						       "': host NUMA ownership for core " +
						       std::to_string(service.cpu_core_id) + " is unknown";
			report.diagnostics.push_back(diagnostic);
			invalid = true;
			continue;
		}
		if (host_numa.value() != service.numa_node) {
			++incompatible_numa_cores;
			const std::string diagnostic = "runtime service '" + service.service_id + "': plan core " +
						       std::to_string(service.cpu_core_id) + " requires NUMA node " +
						       std::to_string(service.numa_node) + " but host reports node " +
						       std::to_string(host_numa.value());
			report.diagnostics.push_back(diagnostic);
			invalid = true;
			continue;
		}
	}
	if (!validate_quark_host_requirements(topology, host, report, unavailable_memory_nodes)) {
		invalid = true;
	}

	if (invalid) {
		std::ostringstream summary;
		summary << "plan/host CPU or NUMA mismatch: " << unavailable_worker_cores
			<< " packet-worker cores unavailable, " << unavailable_service_cores
			<< " runtime-service cores unavailable, and " << incompatible_numa_cores
			<< " cores with unknown or mismatched NUMA ownership of " << total_plan_cores
			<< " planned cores; " << unavailable_memory_nodes
			<< " host-memory NUMA requirements unavailable (" << host.summary() << ")";
		report.summary = summary.str();
		return report;
	}

	report.compatible = true;
	report.summary = "plan/host compat OK: all " + std::to_string(total_plan_cores) +
			 " process cores are available with exact NUMA ownership";
	return report;
}

}  // namespace kinetum::quark
