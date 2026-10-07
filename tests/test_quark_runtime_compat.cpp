// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_quark_runtime_compat.cpp
 * @brief Unit tests for strict provider-neutral plan/host compatibility.
 * @author Fleming Patel
 *
 * Quark consumes shared structural placement truth, then proves only external
 * host CPU and NUMA facts. It never repairs plan ownership, constructs native
 * provider arguments, or selects an implementation.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

#include "src/common/execution_topology_ids.hpp"
#include "src/common/runtime_service_ids.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/quark/host_probe.hpp"
#include "src/quark/runtime_compat.hpp"

namespace
{

/**
 * @brief Build exact already-compiled worker ownership for a host-proof test.
 *
 * @param worker_cores Exact CPU ownership for each worker index.
 * @return Synthetic compiler output carrying canonical worker identities.
 */
[[nodiscard]] kinetum::provider::compiled_provider_topology
make_compiled_topology(const std::vector<std::vector<int32_t>> &worker_cores)
{
	kinetum::provider::compiled_provider_topology topology;
	topology.transition_topology.workers.reserve(worker_cores.size());
	for (std::size_t index = 0; index < worker_cores.size(); ++index) {
		const auto region_id = static_cast<int32_t>(index);
		kinetum::common::compiled_transition_worker worker;
		worker.worker_id = kinetum::common::execution_topology::make_worker_id(
			region_id, kinetum::common::execution_topology::DEFAULT_LANE_ID);
		worker.worker_index = static_cast<uint32_t>(index);
		worker.worker_placement_index = static_cast<uint32_t>(index);
		worker.region_id = region_id;
		worker.lane_id = std::string(kinetum::common::execution_topology::DEFAULT_LANE_ID);
		worker.lane_index = 0;
		worker.numa_node = 0;
		worker.cpu_core_ids = worker_cores[index];
		topology.transition_topology.workers.push_back(std::move(worker));
	}
	return topology;
}

/**
 * @brief Add canonical coordinator and lifecycle-executor placements.
 *
 * @param topology Compiled topology to mutate.
 * @param coordinator_core Dedicated coordinator CPU.
 * @param executor_core Dedicated lifecycle-executor CPU.
 * @param numa_node Exact shared NUMA node.
 */
void add_runtime_services(kinetum::provider::compiled_provider_topology &topology, int32_t coordinator_core,
			  int32_t executor_core, int32_t numa_node = 0)
{
	topology.transition_topology.runtime_services.push_back(kinetum::common::compiled_runtime_service{
		std::string(kinetum::common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID), 0,
		kinetum::common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR, coordinator_core,
		numa_node, kinetum::common::MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY});
	topology.transition_topology.runtime_services.push_back(kinetum::common::compiled_runtime_service{
		kinetum::common::runtime_services::make_lifecycle_executor_id(numa_node), 1,
		kinetum::common::compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR, executor_core, numa_node,
		0u});
}

/**
 * @brief Build a deterministic synthetic host topology.
 *
 * @param available_cores Process-available CPU IDs in caller-supplied order.
 * @param numa_node NUMA node assigned to every CPU; -1 means unknown.
 * @return Host topology containing the exact supplied records.
 */
[[nodiscard]] kinetum::quark::host_topology make_topology(const std::vector<int32_t> &available_cores,
							  int32_t numa_node = 0)
{
	kinetum::quark::host_topology topology;
	for (const int32_t core_id : available_cores) {
		topology.cpus.push_back(kinetum::quark::host_cpu{core_id, numa_node});
	}
	if (numa_node >= 0) {
		topology.memory_numa_nodes.push_back(numa_node);
	}
	topology.valid = true;
	if (!available_cores.empty()) {
		topology.online_count = *std::ranges::max_element(available_cores) + 1;
	}
	return topology;
}

/**
 * @brief Add one exact host-storage NUMA requirement to compiled truth.
 *
 * @param topology Compiled artifact to extend.
 * @param numa_node Exact host-memory node required by the storage domain.
 */
void add_host_storage_requirement(kinetum::provider::compiled_provider_topology &topology, int32_t numa_node)
{
	kinetum::provider::compiled_packet_storage_domain storage;
	storage.storage_domain_id = "storage_host_0";
	storage.storage_domain_index = 0;
	storage.host_numa_node = numa_node;
	topology.storage_domains.push_back(std::move(storage));
	topology.host_requirements.push_back(kinetum::provider::compiled_provider_host_requirement{
		kinetum::provider::provider_host_proof_phase::QUARK_LIVE_HOST,
		kinetum::provider::provider_host_fact::HOST_NUMA_MEMORY,
		kinetum::provider::provider_contract_role::PACKET_STORAGE,
		0,
	});
}

/**
 * @brief Copy process-available CPU IDs from a probe.
 * @param topology Live host probe whose CPU rows are enumerated.
 * @return Owned CPU-ID vector preserving probe order.
 */
[[nodiscard]] std::vector<int32_t> available_core_ids(const kinetum::quark::host_topology &topology)
{
	std::vector<int32_t> result;
	result.reserve(topology.cpus.size());
	for (const auto &cpu : topology.cpus) {
		result.push_back(cpu.core_id);
	}
	return result;
}

/**
 * @brief Return whether any diagnostic contains one exact fragment.
 * @param report Compatibility diagnostics to inspect.
 * @param fragment Exact substring required by the assertion.
 * @return true when at least one diagnostic contains the fragment.
 */
[[nodiscard]] bool contains_diagnostic(const kinetum::quark::compat_report &report, const std::string &fragment)
{
	return std::ranges::any_of(report.diagnostics, [&fragment](const std::string &diagnostic) {
		return diagnostic.find(fragment) != std::string::npos;
	});
}

}  // namespace

/** @brief Verify Linux host probing returns sorted, representable topology. */
TEST(quark_host_probe, probe_returns_valid_topology)
{
	const auto topology = kinetum::quark::probe_host();

	EXPECT_TRUE(topology.valid);
	EXPECT_GT(topology.online_count, 0);
	EXPECT_FALSE(topology.cpus.empty());
	for (std::size_t index = 1; index < topology.cpus.size(); ++index) {
		EXPECT_LT(topology.cpus[index - 1].core_id, topology.cpus[index].core_id);
	}
	for (const auto &cpu : topology.cpus) {
		EXPECT_GE(cpu.core_id, 0);
		EXPECT_GE(cpu.numa_node, -1);
	}
	EXPECT_TRUE(std::ranges::is_sorted(topology.memory_numa_nodes));
	EXPECT_TRUE(std::ranges::none_of(topology.memory_numa_nodes, [](int32_t node) { return node < 0; }));
	EXPECT_LE(static_cast<int32_t>(topology.cpus.size()), topology.online_count);
}

/** @brief Verify exact binary-search lookup recognizes boundaries and rejects sentinels. */
TEST(quark_host_probe, has_core_uses_sorted_cpu_authority)
{
	const auto topology = kinetum::quark::probe_host();
	ASSERT_TRUE(topology.valid);
	ASSERT_FALSE(topology.cpus.empty());

	EXPECT_TRUE(topology.has_core(topology.cpus.front().core_id));
	EXPECT_TRUE(topology.has_core(topology.cpus.back().core_id));
	EXPECT_FALSE(topology.has_core(-1));
	if (topology.online_count < 99999) {
		EXPECT_FALSE(topology.has_core(99999));
	}
}

/** @brief Verify host topology summaries remain operator-readable. */
TEST(quark_host_probe, summary_is_nonempty)
{
	const auto topology = kinetum::quark::probe_host();
	ASSERT_TRUE(topology.valid);
	const auto summary = topology.summary();
	EXPECT_NE(summary.find("cores available"), std::string::npos);
}

/** @brief Verify any unavailable worker CPU fails instead of being filtered. */
TEST(quark_runtime_compat, rejects_unavailable_worker_core)
{
	const auto probed = kinetum::quark::probe_host();
	ASSERT_TRUE(probed.valid);
	const auto cores = available_core_ids(probed);
	ASSERT_FALSE(cores.empty());
	const auto topology = make_topology(cores);
	const auto compiled = make_compiled_topology({{cores.front(), 99999}});

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_FALSE(report.compatible);
	EXPECT_TRUE(contains_diagnostic(report, "is not available to this process"));
}

/** @brief Verify complete exact worker CPU and NUMA ownership passes host proof. */
TEST(quark_runtime_compat, admits_complete_exact_worker_host_proof)
{
	const auto probed = kinetum::quark::probe_host();
	ASSERT_TRUE(probed.valid);
	const auto cores = available_core_ids(probed);
	ASSERT_FALSE(cores.empty());
	std::vector<int32_t> selected{cores.front()};
	if (cores.size() > 1) {
		selected.push_back(cores[1]);
	}
	const auto topology = make_topology(cores);
	const auto compiled = make_compiled_topology({selected});

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_TRUE(report.compatible);
	EXPECT_TRUE(report.diagnostics.empty());
}

/** @brief Verify proven worker NUMA disagreement fails closed. */
TEST(quark_runtime_compat, rejects_proven_worker_numa_mismatch)
{
	const auto topology = make_topology({0}, 1);
	const auto compiled = make_compiled_topology({{0}});

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_FALSE(report.compatible);
	EXPECT_TRUE(contains_diagnostic(report, "requires NUMA node 0 but host reports node 1"));
}

/** @brief Verify unknown worker NUMA never becomes implicit node zero. */
TEST(quark_runtime_compat, rejects_unknown_worker_numa)
{
	const auto topology = make_topology({0}, -1);
	const auto compiled = make_compiled_topology({{0}});

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_FALSE(report.compatible);
	EXPECT_TRUE(contains_diagnostic(report, "host NUMA ownership for core 0 is unknown"));
}

/** @brief Verify one invalid worker makes the complete plan incompatible. */
TEST(quark_runtime_compat, rejects_mixed_validity_worker_set)
{
	const auto topology = make_topology({0});
	const auto compiled = make_compiled_topology({{0}, {99999}});

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_FALSE(report.compatible);
	EXPECT_TRUE(contains_diagnostic(report, "worker 'worker_r1_lane_0'"));
}

/** @brief Verify failed host discovery rejects before placement evaluation. */
TEST(quark_runtime_compat, rejects_invalid_host_topology)
{
	kinetum::quark::host_topology topology;
	topology.valid = false;
	const auto compiled = make_compiled_topology({{0}});

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_FALSE(report.compatible);
	EXPECT_NE(report.summary.find("discovery failed"), std::string::npos);
}

/** @brief Verify unsorted host CPU records reject the binary-search contract. */
TEST(quark_runtime_compat, rejects_unsorted_host_topology)
{
	const auto topology = make_topology({2, 0, 1});
	const auto compiled = make_compiled_topology({{0}});

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_FALSE(report.compatible);
	EXPECT_NE(report.summary.find("not sorted"), std::string::npos);
}

/** @brief Verify exact runtime-service CPU and NUMA ownership passes host proof. */
TEST(quark_runtime_compat, admits_exact_runtime_service_host_proof)
{
	const auto topology = make_topology({0, 1, 2});
	auto compiled = make_compiled_topology({{0}});
	add_runtime_services(compiled, 1, 2);

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_TRUE(report.compatible);
	EXPECT_TRUE(report.diagnostics.empty());
}

/** @brief Verify unavailable runtime-service ownership cannot be repaired. */
TEST(quark_runtime_compat, rejects_unavailable_runtime_service_core)
{
	const auto topology = make_topology({0, 1});
	auto compiled = make_compiled_topology({{0}});
	add_runtime_services(compiled, 2, 1);

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_FALSE(report.compatible);
	EXPECT_TRUE(contains_diagnostic(report, "runtime service"));

	const auto complete_host = make_topology({0, 1, 2});
	auto malformed = make_compiled_topology({{0}});
	add_runtime_services(malformed, 1, 2);
	malformed.transition_topology.runtime_services.front().role =
		static_cast<kinetum::common::compiled_runtime_service_role>(UINT8_MAX);
	const auto malformed_report = kinetum::quark::validate_runtime_compat(malformed, complete_host);
	EXPECT_FALSE(malformed_report.compatible);
	EXPECT_TRUE(contains_diagnostic(malformed_report, "unsupported runtime-service role"));
}

/** @brief Verify an exact host-storage NUMA requirement accepts live memory evidence. */
TEST(quark_runtime_compat, admits_exact_host_memory_numa_requirement)
{
	const auto topology = make_topology({0}, 0);
	auto compiled = make_compiled_topology({{0}});
	add_host_storage_requirement(compiled, 0);

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_TRUE(report.compatible);
}

/** @brief Verify Quark neither proves nor rejects requirements owned by later phases. */
TEST(quark_runtime_compat, ignores_component_and_materialization_proof_requirements)
{
	const auto topology = make_topology({0}, 0);
	auto compiled = make_compiled_topology({{0}});
	compiled.host_requirements.push_back(kinetum::provider::compiled_provider_host_requirement{
		kinetum::provider::provider_host_proof_phase::COMPONENT_HOST_PROOF,
		kinetum::provider::provider_host_fact::DPDK_EAL_RUNTIME,
		kinetum::provider::provider_contract_role::PROCESS_FACILITY,
		0,
	});
	compiled.host_requirements.push_back(kinetum::provider::compiled_provider_host_requirement{
		kinetum::provider::provider_host_proof_phase::MATERIALIZATION_PROOF,
		kinetum::provider::provider_host_fact::DPDK_ETHDEV_PORT,
		kinetum::provider::provider_contract_role::IO_DRIVER,
		0,
	});

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_TRUE(report.compatible);
	EXPECT_TRUE(report.diagnostics.empty());
}

/** @brief Verify malformed proof-phase and host-fact classifications fail closed. */
TEST(quark_runtime_compat, rejects_malformed_compiled_host_requirement)
{
	const auto topology = make_topology({0}, 0);
	auto malformed_phase = make_compiled_topology({{0}});
	malformed_phase.host_requirements.push_back(kinetum::provider::compiled_provider_host_requirement{
		static_cast<kinetum::provider::provider_host_proof_phase>(UINT8_MAX),
		kinetum::provider::provider_host_fact::CPU_WORKER_SET,
		kinetum::provider::provider_contract_role::EXECUTION,
		0,
	});
	const auto phase_report = kinetum::quark::validate_runtime_compat(malformed_phase, topology);
	EXPECT_FALSE(phase_report.compatible);
	EXPECT_TRUE(contains_diagnostic(phase_report, "invalid proof phase"));

	auto malformed_fact = make_compiled_topology({{0}});
	malformed_fact.host_requirements.push_back(kinetum::provider::compiled_provider_host_requirement{
		kinetum::provider::provider_host_proof_phase::QUARK_LIVE_HOST,
		static_cast<kinetum::provider::provider_host_fact>(UINT8_MAX),
		kinetum::provider::provider_contract_role::EXECUTION,
		0,
	});
	const auto fact_report = kinetum::quark::validate_runtime_compat(malformed_fact, topology);
	EXPECT_FALSE(fact_report.compatible);
	EXPECT_TRUE(contains_diagnostic(fact_report, "invalid host fact"));
}

/** @brief Verify CPU presence cannot substitute for missing host-memory evidence. */
TEST(quark_runtime_compat, rejects_unavailable_host_memory_numa_requirement)
{
	auto topology = make_topology({0}, 0);
	topology.memory_numa_nodes.clear();
	auto compiled = make_compiled_topology({{0}});
	add_host_storage_requirement(compiled, 0);

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_FALSE(report.compatible);
	EXPECT_TRUE(contains_diagnostic(report, "cannot prove it"));
}

/** @brief Verify malformed host-memory inventory rejects before requirement lookup. */
TEST(quark_runtime_compat, rejects_unsorted_host_memory_numa_inventory)
{
	auto topology = make_topology({0}, 0);
	topology.memory_numa_nodes = {1, 0};
	const auto compiled = make_compiled_topology({{0}});

	const auto report = kinetum::quark::validate_runtime_compat(compiled, topology);

	EXPECT_FALSE(report.compatible);
	EXPECT_NE(report.summary.find("memory_numa_nodes is not sorted"), std::string::npos);
}
