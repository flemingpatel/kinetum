// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_core_placement.cpp
 * @brief Deterministic runtime worker and control-service CPU placement.
 * @author Fleming Patel
 *
 * The implementation performs one transactional cold-path lowering pass. It
 * normalizes assignable CPU facts, selects a complete region-local worker and
 * service assignment in temporary storage, and publishes protobuf placement
 * facts only after every core and NUMA invariant succeeds.
 */

#include "src/gluon/runtime_core_placement.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_service_ids.hpp"

namespace kinetum::gluon
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

namespace
{

/** @brief One normalized assignable logical CPU. */
struct core_candidate {
	int32_t core_id{0};	     ///< OS logical CPU identifier.
	int32_t numa_node{0};	     ///< NUMA node owning this CPU.
	bool is_hyperthread{false};  ///< Whether this CPU is a sibling thread.
	bool reserved{false};	     ///< Excluded from packet workers and preferred by services.
};

/** @brief Mutable candidate pools for one NUMA node during an assignment attempt. */
struct node_candidate_pool {
	std::vector<core_candidate> reserved;  ///< Service-preferred cores, ascending by ID.
	std::vector<core_candidate> packet;    ///< Packet candidates in worker preference order.
	std::size_t assigned_workers{0};       ///< Worker load used for NUMA balancing.
	bool executor_assigned{false};	       ///< Whether this node already owns an executor.
	int32_t executor_core{-1};	       ///< Assigned executor core when present.
};

/** @brief One logical region's indivisible worker-core demand. */
struct region_placement_request {
	int32_t region_id{0};		       ///< Region being placed.
	std::vector<int> worker_plan_indices;  ///< WorkerPlacement indices owned by the region.
	bool requires_executor{false};	       ///< Whether module lifecycle work exists here.
};

/** @brief Complete temporary assignment published only after validation succeeds. */
struct placement_attempt {
	core_candidate coordinator;			   ///< Sole coordinator placement.
	std::vector<int32_t> worker_core_by_plan_index;	   ///< Core per WorkerPlacement index.
	std::vector<int32_t> region_numa_by_id;		   ///< NUMA node per compact region ID.
	std::map<int32_t, int32_t> executor_core_by_numa;  ///< Executor core per required NUMA node.
};

static_assert(std::is_nothrow_move_constructible_v<placement_attempt>,
	      "runtime placement selection requires a non-throwing ownership handoff");

/**
 * @brief Check whether a NUMA node is admitted by planner constraints.
 *
 * @param numa_node Candidate NUMA node.
 * @param allowed Sorted or unsorted allowed-node list; empty means all.
 * @return true when the candidate may be used.
 */
[[nodiscard]] bool numa_node_allowed(int32_t numa_node, const std::vector<int32_t> &allowed) noexcept
{
	return allowed.empty() || std::find(allowed.begin(), allowed.end(), numa_node) != allowed.end();
}

/**
 * @brief Normalize hardware CPU facts into one deterministic candidate list.
 *
 * The lowest `reserved_cores` logical IDs are marked service-preferred before
 * allowed-NUMA filtering. Every candidate is an explicit row; no count-only
 * core or NUMA identity is synthesized.
 *
 * @param hardware Hardware inventory supplied to Gluon.
 * @param options Runtime placement policy.
 * @return Sorted eligible core candidates, or a fail-closed inventory error.
 */
[[nodiscard]] status_or<std::vector<core_candidate>>
normalize_core_candidates(const kinetum::hw::v1::HardwareInventory &hardware,
			  const runtime_core_placement_options &options)
{
	if (!hardware.has_node() || !hardware.node().has_cpu()) {
		return status(status_code::INVALID_ARGUMENT, "runtime core placement requires hardware CPU inventory");
	}
	if (options.reserved_cores < 0) {
		return status(status_code::INVALID_ARGUMENT,
			      "reserved_cores must be >= 0, got " + std::to_string(options.reserved_cores));
	}

	const auto &cpu = hardware.node().cpu();
	std::vector<core_candidate> candidates;
	if (cpu.core_topology_size() == 0) {
		return status::invalid_argument("hardware CPU inventory requires explicit core_topology[] rows");
	}
	candidates.reserve(static_cast<std::size_t>(cpu.core_topology_size()));
	std::unordered_set<int32_t> seen_core_ids;
	seen_core_ids.reserve(static_cast<std::size_t>(cpu.core_topology_size()));
	for (const auto &core : cpu.core_topology()) {
		if (core.core_id() < 0) {
			return status(status_code::INVALID_ARGUMENT,
				      "cpu.core_topology contains negative core_id " + std::to_string(core.core_id()));
		}
		if (core.numa_node() < 0) {
			return status(status_code::INVALID_ARGUMENT, "cpu core " + std::to_string(core.core_id()) +
									     " has negative numa_node " +
									     std::to_string(core.numa_node()));
		}
		if (!seen_core_ids.insert(core.core_id()).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "duplicate core_id in cpu.core_topology[]: " + std::to_string(core.core_id()));
		}
		candidates.push_back(core_candidate{core.core_id(), core.numa_node(), core.is_hyperthread(), false});
	}

	std::ranges::sort(candidates, {}, &core_candidate::core_id);
	const auto reserved_count = std::min(static_cast<std::size_t>(options.reserved_cores), candidates.size());
	for (std::size_t i = 0; i < reserved_count; ++i) {
		candidates[i].reserved = true;
	}

	candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
					[&](const core_candidate &candidate) {
						return !numa_node_allowed(candidate.numa_node,
									  options.allowed_numa_nodes);
					}),
			 candidates.end());
	if (candidates.empty()) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      "runtime core placement has no CPUs after NUMA constraints");
	}
	return candidates;
}

/**
 * @brief Build NUMA-local reserved and packet candidate pools.
 *
 * @param candidates Normalized eligible cores.
 * @param prefer_physical Whether packet workers prefer non-hyperthreads.
 * @return NUMA-keyed pools with deterministic core ordering.
 */
[[nodiscard]] std::map<int32_t, node_candidate_pool> build_node_pools(const std::vector<core_candidate> &candidates,
								      bool prefer_physical)
{
	std::map<int32_t, node_candidate_pool> pools;
	for (const auto &candidate : candidates) {
		auto &pool = pools[candidate.numa_node];
		if (candidate.reserved) {
			pool.reserved.push_back(candidate);
		} else {
			pool.packet.push_back(candidate);
		}
	}
	for (auto &[numa_node, pool] : pools) {
		(void)numa_node;
		std::ranges::sort(pool.reserved, {}, &core_candidate::core_id);
		std::ranges::sort(pool.packet, [prefer_physical](const core_candidate &lhs, const core_candidate &rhs) {
			if (prefer_physical && lhs.is_hyperthread != rhs.is_hyperthread) {
				return !lhs.is_hyperthread;
			}
			return lhs.core_id < rhs.core_id;
		});
	}
	return pools;
}

/**
 * @brief Build region worker demands and identify module-lifecycle NUMA needs.
 *
 * @param plan Plan after executable topology lowering.
 * @return Region requests sorted later by the placement algorithm.
 */
[[nodiscard]] status_or<std::vector<region_placement_request>>
build_region_requests(const kinetum::gluon::v1::DeploymentPlan &plan)
{
	if (plan.regions_size() <= 0 || plan.worker_placements_size() <= 0) {
		return status(status_code::INVALID_ARGUMENT,
			      "runtime core placement requires nonempty regions and worker_placements[]");
	}

	std::vector<region_placement_request> requests(static_cast<std::size_t>(plan.regions_size()));
	std::vector<bool> seen_region_ids(static_cast<std::size_t>(plan.regions_size()), false);
	for (const auto &region : plan.regions()) {
		if (region.region_id() < 0 || region.region_id() >= plan.regions_size()) {
			return status(status_code::INVALID_ARGUMENT,
				      "runtime core placement received out-of-range region_id " +
					      std::to_string(region.region_id()));
		}
		const auto index = static_cast<std::size_t>(region.region_id());
		if (seen_region_ids[index]) {
			return status(status_code::INVALID_ARGUMENT,
				      "duplicate region_id during runtime core placement: " +
					      std::to_string(region.region_id()));
		}
		seen_region_ids[index] = true;
		requests[index].region_id = region.region_id();
	}
	for (std::size_t i = 0; i < seen_region_ids.size(); ++i) {
		if (!seen_region_ids[i]) {
			return status(status_code::INVALID_ARGUMENT,
				      "missing compact region_id during runtime core placement: " + std::to_string(i));
		}
	}

	for (int i = 0; i < plan.worker_placements_size(); ++i) {
		const auto &worker = plan.worker_placements(i);
		if (worker.region_id() < 0 || worker.region_id() >= plan.regions_size()) {
			return status(status_code::INVALID_ARGUMENT, "worker placement '" + worker.worker_id() +
									     "' has invalid region_id " +
									     std::to_string(worker.region_id()));
		}
		requests[static_cast<std::size_t>(worker.region_id())].worker_plan_indices.push_back(i);
	}

	std::unordered_set<std::string> module_stage_ids;
	for (const auto &stage : plan.pipeline().stages()) {
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
			module_stage_ids.insert(stage.stage_id());
		}
	}
	bool found_module_region = false;
	for (const auto &region : plan.regions()) {
		auto &request = requests[static_cast<std::size_t>(region.region_id())];
		for (const auto &stage_id : region.logical_stage_ids()) {
			if (module_stage_ids.contains(stage_id)) {
				request.requires_executor = true;
				found_module_region = true;
				break;
			}
		}
	}

	// Bootstrap always has one lifecycle executor, including module-free
	// mechanism-only pipelines. Anchor that executor to the lowest populated
	// region when no module context establishes a stronger NUMA requirement.
	if (!found_module_region) {
		for (auto &request : requests) {
			if (!request.worker_plan_indices.empty()) {
				request.requires_executor = true;
				break;
			}
		}
	}

	requests.erase(std::remove_if(requests.begin(), requests.end(),
				      [](const region_placement_request &request) {
					      return request.worker_plan_indices.empty();
				      }),
		       requests.end());
	if (requests.empty()) {
		return status(status_code::INVALID_ARGUMENT, "runtime core placement found no populated worker region");
	}
	return requests;
}

/**
 * @brief Remove one exact core from a candidate pool.
 *
 * @param pools NUMA-keyed mutable pools.
 * @param core Coordinator candidate to remove.
 * @return true when the core was present and removed exactly once.
 */
[[nodiscard]] bool remove_core(std::map<int32_t, node_candidate_pool> &pools, const core_candidate &core) noexcept
{
	auto pool_it = pools.find(core.numa_node);
	if (pool_it == pools.end()) {
		return false;
	}
	auto &values = core.reserved ? pool_it->second.reserved : pool_it->second.packet;
	const auto it = std::find_if(values.begin(), values.end(), [&](const core_candidate &candidate) {
		return candidate.core_id == core.core_id;
	});
	if (it == values.end()) {
		return false;
	}
	values.erase(it);
	return true;
}

/**
 * @brief Reserve one NUMA-local lifecycle executor from a node pool.
 *
 * Reserved cores are consumed in ascending ID order. When none remain, the
 * least-preferred packet candidate (the back of the worker ordering) becomes
 * the executor so packet workers retain the strongest available cores.
 *
 * @param pool Mutable NUMA-local candidate pool.
 * @return Executor core ID, or -1 when no service core remains.
 */
[[nodiscard]] int32_t reserve_executor_core(node_candidate_pool &pool) noexcept
{
	if (!pool.reserved.empty()) {
		const int32_t core = pool.reserved.front().core_id;
		pool.reserved.erase(pool.reserved.begin());
		return core;
	}
	if (!pool.packet.empty()) {
		const int32_t core = pool.packet.back().core_id;
		pool.packet.pop_back();
		return core;
	}
	return -1;
}

/**
 * @brief Attempt complete placement for one coordinator candidate.
 *
 * Regions requiring lifecycle state are placed first, then larger worker
 * demands, then region ID. This reserves executor capacity before mechanism-
 * only regions can consume it. NUMA-aware mode balances worker counts; the
 * non-NUMA-aware policy fills lower NUMA IDs first.
 *
 * @param base_pools Unmodified NUMA candidate pools.
 * @param requests Region worker and lifecycle demands.
 * @param coordinator Coordinator core to reserve.
 * @param worker_count Number of emitted WorkerPlacement records.
 * @param region_count Number of compact plan regions.
 * @param numa_aware Whether to balance region placement across NUMA nodes.
 * @return Complete assignment, or an error when this coordinator choice cannot
 *         satisfy every region and service.
 */
[[nodiscard]] status_or<placement_attempt> attempt_placement(const std::map<int32_t, node_candidate_pool> &base_pools,
							     std::vector<region_placement_request> requests,
							     const core_candidate &coordinator, int worker_count,
							     int region_count, bool numa_aware)
{
	auto pools = base_pools;
	if (!remove_core(pools, coordinator)) {
		return status(status_code::INTERNAL_ERROR,
			      "coordinator candidate disappeared during runtime core placement");
	}

	std::ranges::sort(requests, [](const region_placement_request &lhs, const region_placement_request &rhs) {
		if (lhs.requires_executor != rhs.requires_executor) {
			return lhs.requires_executor > rhs.requires_executor;
		}
		if (lhs.worker_plan_indices.size() != rhs.worker_plan_indices.size()) {
			return lhs.worker_plan_indices.size() > rhs.worker_plan_indices.size();
		}
		return lhs.region_id < rhs.region_id;
	});

	placement_attempt result;
	result.coordinator = coordinator;
	result.worker_core_by_plan_index.assign(static_cast<std::size_t>(worker_count), -1);
	result.region_numa_by_id.assign(static_cast<std::size_t>(region_count), -1);

	for (const auto &request : requests) {
		bool found = false;
		int32_t selected_numa = -1;
		std::size_t selected_assigned_workers = 0;
		node_candidate_pool selected_pool;
		std::vector<int32_t> selected_worker_cores;

		for (const auto &[numa_node, original_pool] : pools) {
			auto candidate_pool = original_pool;
			if (request.requires_executor && !candidate_pool.executor_assigned) {
				const int32_t executor_core = reserve_executor_core(candidate_pool);
				if (executor_core < 0) {
					continue;
				}
				candidate_pool.executor_assigned = true;
				candidate_pool.executor_core = executor_core;
			}
			if (candidate_pool.packet.size() < request.worker_plan_indices.size()) {
				continue;
			}

			std::vector<int32_t> worker_cores;
			worker_cores.reserve(request.worker_plan_indices.size());
			for (std::size_t i = 0; i < request.worker_plan_indices.size(); ++i) {
				worker_cores.push_back(candidate_pool.packet[i].core_id);
			}
			candidate_pool.packet.erase(
				candidate_pool.packet.begin(),
				candidate_pool.packet.begin() +
					static_cast<std::ptrdiff_t>(request.worker_plan_indices.size()));

			const bool better =
				!found || (numa_aware && original_pool.assigned_workers < selected_assigned_workers) ||
				(numa_aware && original_pool.assigned_workers == selected_assigned_workers &&
				 numa_node < selected_numa) ||
				(!numa_aware && numa_node < selected_numa);
			if (!better) {
				continue;
			}
			found = true;
			selected_numa = numa_node;
			selected_assigned_workers = original_pool.assigned_workers;
			selected_pool = std::move(candidate_pool);
			selected_worker_cores = std::move(worker_cores);
		}

		if (!found) {
			return status(status_code::RESOURCE_EXHAUSTED,
				      "insufficient NUMA-local CPU capacity for region " +
					      std::to_string(request.region_id) + " with " +
					      std::to_string(request.worker_plan_indices.size()) + " workers" +
					      (request.requires_executor ? " and lifecycle executor" : ""));
		}

		selected_pool.assigned_workers += request.worker_plan_indices.size();
		pools[selected_numa] = std::move(selected_pool);
		result.region_numa_by_id[static_cast<std::size_t>(request.region_id)] = selected_numa;
		for (std::size_t i = 0; i < request.worker_plan_indices.size(); ++i) {
			const auto plan_index = static_cast<std::size_t>(request.worker_plan_indices[i]);
			result.worker_core_by_plan_index[plan_index] = selected_worker_cores[i];
		}
	}

	for (const auto &[numa_node, pool] : pools) {
		if (pool.executor_assigned) {
			result.executor_core_by_numa.emplace(numa_node, pool.executor_core);
		}
	}
	if (result.executor_core_by_numa.empty()) {
		return status(status_code::INTERNAL_ERROR, "runtime core placement produced no lifecycle executor");
	}
	if (std::find(result.worker_core_by_plan_index.begin(), result.worker_core_by_plan_index.end(), -1) !=
	    result.worker_core_by_plan_index.end()) {
		return status(status_code::INTERNAL_ERROR,
			      "runtime core placement left a worker without CPU ownership");
	}
	return result;
}

/**
 * @brief Validate a complete temporary assignment before mutating the plan.
 *
 * This backstop independently proves that every selected core comes from the
 * normalized inventory, service and packet ownership are pairwise disjoint,
 * every region is NUMA-local, and every module-bearing NUMA node owns a
 * lifecycle executor.
 *
 * @param plan Plan whose worker/region ownership is being assigned.
 * @param candidates Normalized hardware CPU candidates.
 * @param requests Populated region worker and lifecycle requirements.
 * @param assignment Complete temporary placement candidate.
 * @return OK when every placement invariant holds; INTERNAL_ERROR otherwise.
 */
[[nodiscard]] status validate_assignment(const kinetum::gluon::v1::DeploymentPlan &plan,
					 const std::vector<core_candidate> &candidates,
					 const std::vector<region_placement_request> &requests,
					 const placement_attempt &assignment)
{
	if (assignment.worker_core_by_plan_index.size() != static_cast<std::size_t>(plan.worker_placements_size()) ||
	    assignment.region_numa_by_id.size() != static_cast<std::size_t>(plan.regions_size())) {
		return status(status_code::INTERNAL_ERROR,
			      "runtime core placement produced incomplete assignment dimensions");
	}

	std::unordered_map<int32_t, int32_t> numa_by_core;
	numa_by_core.reserve(candidates.size());
	for (const auto &candidate : candidates) {
		numa_by_core.emplace(candidate.core_id, candidate.numa_node);
	}

	std::unordered_set<int32_t> owned_cores;
	owned_cores.reserve(assignment.worker_core_by_plan_index.size() + assignment.executor_core_by_numa.size() + 1);
	const auto coordinator_it = numa_by_core.find(assignment.coordinator.core_id);
	if (coordinator_it == numa_by_core.end() || coordinator_it->second != assignment.coordinator.numa_node ||
	    !owned_cores.insert(assignment.coordinator.core_id).second) {
		return status(status_code::INTERNAL_ERROR,
			      "runtime core placement produced an invalid coordinator assignment");
	}

	for (int i = 0; i < plan.worker_placements_size(); ++i) {
		const auto &worker = plan.worker_placements(i);
		const auto worker_index = static_cast<std::size_t>(i);
		const int32_t core_id = assignment.worker_core_by_plan_index[worker_index];
		const auto core_it = numa_by_core.find(core_id);
		if (core_it == numa_by_core.end() || worker.region_id() < 0 ||
		    worker.region_id() >= plan.regions_size()) {
			return status(status_code::INTERNAL_ERROR,
				      "runtime core placement produced an invalid worker assignment");
		}
		const auto region_index = static_cast<std::size_t>(worker.region_id());
		if (assignment.region_numa_by_id[region_index] != core_it->second) {
			return status(status_code::INTERNAL_ERROR,
				      "runtime core placement split one region across NUMA nodes");
		}
		if (!owned_cores.insert(core_id).second) {
			return status(status_code::INTERNAL_ERROR,
				      "runtime core placement assigned one CPU to multiple owners");
		}
	}

	for (const auto &[numa_node, core_id] : assignment.executor_core_by_numa) {
		const auto core_it = numa_by_core.find(core_id);
		if (core_it == numa_by_core.end() || core_it->second != numa_node ||
		    !owned_cores.insert(core_id).second) {
			return status(status_code::INTERNAL_ERROR,
				      "runtime core placement produced an invalid lifecycle-executor assignment");
		}
	}

	for (const auto &request : requests) {
		if (!request.requires_executor) {
			continue;
		}
		const auto region_index = static_cast<std::size_t>(request.region_id);
		const int32_t numa_node = assignment.region_numa_by_id[region_index];
		if (!assignment.executor_core_by_numa.contains(numa_node)) {
			return status(status_code::INTERNAL_ERROR,
				      "runtime core placement omitted a required NUMA-local lifecycle executor");
		}
	}
	return status::ok();
}

/**
 * @brief Enumerate coordinator candidates in deterministic service preference.
 *
 * Reserved cores come first in ascending ID order. Non-reserved candidates
 * follow in least-packet-preferred order. When packet workers prefer physical
 * cores, hyperthreads are offered to the service first; descending core ID
 * breaks ties within one thread class. Without physical preference, all
 * non-reserved candidates use descending core ID.
 *
 * @param pools NUMA-keyed candidate pools.
 * @param prefer_physical_workers Whether packet workers prefer physical cores.
 * @return Ordered coordinator candidate list.
 */
[[nodiscard]] std::vector<core_candidate> coordinator_candidates(const std::map<int32_t, node_candidate_pool> &pools,
								 bool prefer_physical_workers)
{
	std::vector<core_candidate> reserved;
	std::vector<core_candidate> nonreserved;
	for (const auto &[numa_node, pool] : pools) {
		(void)numa_node;
		reserved.insert(reserved.end(), pool.reserved.begin(), pool.reserved.end());
		nonreserved.insert(nonreserved.end(), pool.packet.begin(), pool.packet.end());
	}
	std::ranges::sort(reserved, {}, &core_candidate::core_id);
	std::ranges::sort(nonreserved, [prefer_physical_workers](const core_candidate &lhs, const core_candidate &rhs) {
		if (prefer_physical_workers && lhs.is_hyperthread != rhs.is_hyperthread) {
			return lhs.is_hyperthread;
		}
		return lhs.core_id > rhs.core_id;
	});
	reserved.insert(reserved.end(), nonreserved.begin(), nonreserved.end());
	return reserved;
}

}  // namespace

status lower_runtime_core_placement(kinetum::gluon::v1::DeploymentPlan &plan,
				    const kinetum::hw::v1::HardwareInventory &hardware,
				    const runtime_core_placement_options &options)
{
	if (const auto unknown_status =
		    kinetum::common::reject_unknown_protobuf_fields_recursive(hardware, "HardwareInventory");
	    !unknown_status.is_ok()) {
		return unknown_status;
	}
	if (const auto enum_status =
		    kinetum::common::reject_invalid_protobuf_enum_values_recursive(hardware, "HardwareInventory");
	    !enum_status.is_ok()) {
		return enum_status;
	}
	auto candidates_or = normalize_core_candidates(hardware, options);
	if (!candidates_or.is_ok()) {
		return candidates_or.error();
	}
	auto requests_or = build_region_requests(plan);
	if (!requests_or.is_ok()) {
		return requests_or.error();
	}

	const auto pools = build_node_pools(candidates_or.value(), options.prefer_physical_cores);
	// Try coordinator candidates in deterministic service-preference order. Each
	// placement attempt stays private until the complete worker/service ownership
	// graph validates, so a failed candidate cannot partially mutate the plan.
	const auto coordinators = coordinator_candidates(pools, options.prefer_physical_cores);
	status last_error(status_code::RESOURCE_EXHAUSTED, "runtime core placement has no coordinator candidate");
	std::optional<placement_attempt> selected;
	for (const auto &coordinator : coordinators) {
		auto attempt = attempt_placement(pools, requests_or.value(), coordinator, plan.worker_placements_size(),
						 plan.regions_size(), options.numa_aware);
		if (attempt.is_ok()) {
			selected.emplace(std::move(attempt).value());
			break;
		}
		last_error = attempt.error();
	}
	if (!selected.has_value()) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      "unable to place disjoint packet workers, coordinator, and lifecycle executors: " +
				      std::string(last_error.message()));
	}

	const auto &assignment = *selected;
	if (const auto validation = validate_assignment(plan, candidates_or.value(), requests_or.value(), assignment);
	    !validation.is_ok()) {
		return validation;
	}
	std::vector<std::set<int32_t>> cores_by_region(static_cast<std::size_t>(plan.regions_size()));
	for (int i = 0; i < plan.worker_placements_size(); ++i) {
		const auto &worker = plan.worker_placements(i);
		cores_by_region[static_cast<std::size_t>(worker.region_id())].insert(
			assignment.worker_core_by_plan_index[static_cast<std::size_t>(i)]);
	}

	// Build the complete protobuf publication privately. Any allocation failure
	// leaves the caller's plan byte-identical; one final swap publishes it.
	kinetum::gluon::v1::DeploymentPlan published = plan;
	for (int i = 0; i < published.worker_placements_size(); ++i) {
		auto *worker = published.mutable_worker_placements(i);
		worker->clear_cpu_core_ids();
		worker->add_cpu_core_ids(assignment.worker_core_by_plan_index[static_cast<std::size_t>(i)]);
	}
	for (int region_plan_index = 0; region_plan_index < published.regions_size(); ++region_plan_index) {
		auto *region = published.mutable_regions(region_plan_index);
		const auto region_id = static_cast<std::size_t>(region->region_id());
		region->clear_cpu_core_ids();
		const int32_t numa_node = assignment.region_numa_by_id[region_id];
		if (numa_node >= 0) {
			region->set_numa_node(numa_node);
		}
		for (const auto core : cores_by_region[region_id]) {
			region->add_cpu_core_ids(core);
		}
	}

	published.clear_runtime_service_placements();
	auto *coordinator = published.add_runtime_service_placements();
	coordinator->set_service_id(std::string(kinetum::common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID));
	coordinator->set_service_kind(kinetum::gluon::v1::RUNTIME_SERVICE_KIND_EPOCH_TRANSITION_COORDINATOR);
	coordinator->set_cpu_core_id(assignment.coordinator.core_id);
	coordinator->set_numa_node(assignment.coordinator.numa_node);
	coordinator->set_command_mailbox_capacity(COORDINATOR_COMMAND_MAILBOX_CAPACITY);

	for (const auto &[numa_node, core_id] : assignment.executor_core_by_numa) {
		auto *executor = published.add_runtime_service_placements();
		executor->set_service_id(kinetum::common::runtime_services::make_lifecycle_executor_id(numa_node));
		executor->set_service_kind(kinetum::gluon::v1::RUNTIME_SERVICE_KIND_CONFIG_LIFECYCLE_EXECUTOR);
		executor->set_cpu_core_id(core_id);
		executor->set_numa_node(numa_node);
		executor->set_command_mailbox_capacity(0u);
	}
	plan.Swap(&published);
	return status::ok();
}

}  // namespace kinetum::gluon
