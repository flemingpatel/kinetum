// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file gluon_planner.cpp
 * @brief Gluon Planner implementation.
 * @author Fleming Patel
 *
 * This implementation provides deterministic exact partitioning of Axiom
 * pipelines into executable regions.
 *
 * Algorithm Overview:
 * 1. Topological Sort: Kahn's algorithm with deterministic tie-breaking
 * 2. Region Partitioning: Weight-balanced linear DP with O(n^2*r) complexity
 * 3. Executable Topology: Deterministic lane, stage-instance, stream, and worker lowering
 * 4. Runtime Core Assignment: Region-local worker and service placement
 * 5. Boundary Topology: Exact directed cross-worker endpoint ownership
 * 6. Provider Graph: Exact authored instances, ports, streams, transitions, and identity
 *
 * The DP formulation minimizes makespan (max region weight):
 *   dp[r][i] = min cost to partition stages [0..i) into r regions
 *   cost = max(dp[r-1][j], sum(weights[j..i)))
 *
 * Complexity: O(n^2*r) time, O(nr) space where n=stages, r=regions
 *
 */

#include "src/gluon/gluon_planner.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <kinetum/algo/platform.hpp>  // KINETUM_LIKELY/UNLIKELY macros
#include "src/axiom/axiom_contract.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_service_ids.hpp"
#include "src/common/version.hpp"
#include "src/gluon/boundary_topology_lowering.hpp"
#include "src/gluon/deployment_bindings_lowering.hpp"
#include "src/gluon/runtime_core_placement.hpp"
#include "src/gluon/transition_plan_lowering.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/deployment_plan_identity.hpp"

namespace kinetum::gluon
{

using kinetum::gluon::v1::DeploymentPlan;
using kinetum::gluon::v1::Region;
using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

// =============================================================================
// Constants
// =============================================================================

namespace
{

/** Prefix joining the planner identity to the platform release version. */
constexpr std::string_view PLANNER_VERSION_PREFIX = "gluon-";
/** Algorithm identity recorded in compiled plan metadata. */
constexpr std::string_view PLANNING_ALGORITHM = "linear_dp_v2";

/**
 * @brief Maximum supported runtime regions accepted by planner sanity checks.
 */
constexpr int MAX_REGIONS = 256;

// Default stage weights for planner cost modeling.
// These are relative cost units, not measured CPU cycles.
//
// Module conformance model:
// - Platform mechanism stages (RX, TX, PARSE) have fixed weights
// - All policy stages use STAGE_KIND_MODULE with weight from module_id
// - Built-in modules (kinetum.acl, kinetum.nat44, kinetum.qos) have known weights
// - Custom modules default to WEIGHT_MODULE_DEFAULT
constexpr uint64_t WEIGHT_RX_TX = 0;	       ///< Partition endpoints contribute no modeled stage cost.
constexpr uint64_t WEIGHT_PARSE = 1;	       ///< Baseline parser cost unit.
constexpr uint64_t WEIGHT_MODULE_ACL = 3;      ///< ACL rule-evaluation cost heuristic.
constexpr uint64_t WEIGHT_MODULE_NAT = 4;      ///< NAT session-lookup and checksum cost heuristic.
constexpr uint64_t WEIGHT_MODULE_QOS = 3;      ///< QoS flow-policer cost heuristic.
constexpr uint64_t WEIGHT_MODULE_DEFAULT = 5;  ///< Generic admitted-module cost heuristic.

}  // namespace

// =============================================================================
// Stage Weight Computation
// =============================================================================

uint64_t default_stage_weight(const kinetum::axiom::v1::Stage &stage) noexcept
{
	switch (stage.kind()) {
	case kinetum::axiom::v1::STAGE_KIND_RX:
	case kinetum::axiom::v1::STAGE_KIND_TX:
		return WEIGHT_RX_TX;
	case kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4:
		return WEIGHT_PARSE;
	case kinetum::axiom::v1::STAGE_KIND_MODULE: {
		if (!stage.has_module() || stage.module().module_id().empty()) {
			std::terminate();
		}
		const std::string &module_id = stage.module().module_id();
		if (module_id == "kinetum.acl") {
			return WEIGHT_MODULE_ACL;
		}
		if (module_id == "kinetum.nat44") {
			return WEIGHT_MODULE_NAT;
		}
		if (module_id == "kinetum.qos") {
			return WEIGHT_MODULE_QOS;
		}
		return WEIGHT_MODULE_DEFAULT;
	}
	case kinetum::axiom::v1::STAGE_KIND_UNSPECIFIED:
	case kinetum::axiom::v1::StageKind_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::axiom::v1::StageKind_INT_MAX_SENTINEL_DO_NOT_USE_:
		std::terminate();
	}
	std::terminate();
}

/**
 * @brief Resolve one stage's exact authored or built-in planning weight.
 *
 * `Stage.cost_weight` is the sole authored override. Zero selects the stable
 * kind/module default; no callback or string parameter can alter placement.
 *
 * @param s The pipeline stage to compute weight for.
 * @return The computed weight for load balancing decisions.
 *
 * @note Higher weights contribute more cost to partition balancing.
 * @see default_stage_weight For default weight assignments.
 */
static uint64_t get_stage_weight(const kinetum::axiom::v1::Stage &s) noexcept
{
	return s.cost_weight() > 0u ? s.cost_weight() : default_stage_weight(s);
}

namespace
{

// =============================================================================
// Pinning Constraints
// =============================================================================

/**
 * @brief Tracks pinned stage indices for a single region.
 *
 * Used to validate that pinning constraints form a valid partition
 * (pinned regions must be monotonically non-decreasing in topological order).
 */
struct pinned_constraint {
	int first_index{-1};  ///< First stage index pinned to this region (-1 if none)
	int last_index{-1};   ///< Last stage index pinned to this region (-1 if none)
};

/**
 * @brief Compute pinning constraints from stage metadata.
 *
 * Multi-RX/TX pinning strategy:
 * 1. RX stages with preferred_region -> pin to that region
 * 2. TX stages with preferred_region -> pin to that region
 * 3. Single RX without preference -> region 0 (pipeline entry point)
 * 4. Single TX without preference -> last region (pipeline exit point)
 * 5. Multiple RX without preference -> auto-distribute across early regions
 * 6. Multiple TX without preference -> auto-distribute across late regions
 *
 * @param order Stages in topological order.
 * @param stage_map Map from stage_id to Stage pointer.
 * @param regions Total number of regions.
 * @return Vector where pinned[i] = region for stage i, or -1 if unpinned.
 *         Returns error if:
 *         - preferred_region exceeds available regions
 *         - Pinned regions are not monotonic (violates DAG structure)
 *
 * @note Part of the constraint-aware partitioning.
 */
status_or<std::vector<int>>
compute_pinning(const std::vector<std::string> &order,
		const std::unordered_map<std::string, const kinetum::axiom::v1::Stage *> &stage_map, int regions)
{
	// Early validation: regions must be positive (Gluon invariant)
	if (KINETUM_UNLIKELY(regions <= 0)) {
		return status(status_code::INVALID_ARGUMENT,
			      "compute_pinning: regions must be > 0, got " + std::to_string(regions));
	}

	const int n = static_cast<int>(order.size());
	std::vector<int> pinned(static_cast<size_t>(n), -1);

	std::size_t rx_count = 0u;
	std::size_t tx_count = 0u;
	std::vector<int> rx_no_pref;  // RX stages without preferred_region
	std::vector<int> tx_no_pref;  // TX stages without preferred_region

	for (int i = 0; i < n; ++i) {
		const auto *s = stage_map.at(order[static_cast<size_t>(i)]);
		if (s->kind() == kinetum::axiom::v1::STAGE_KIND_RX) {
			++rx_count;
			if (!s->has_preferred_region()) {
				rx_no_pref.push_back(i);
			}
		} else if (s->kind() == kinetum::axiom::v1::STAGE_KIND_TX) {
			++tx_count;
			if (!s->has_preferred_region()) {
				tx_no_pref.push_back(i);
			}
		}
	}

	const bool multi_rx = rx_count > 1u;
	const bool multi_tx = tx_count > 1u;

	// First pass: Pin RX/TX stages with explicit preferred_region
	for (int i = 0; i < n; ++i) {
		const auto *s = stage_map.at(order[static_cast<size_t>(i)]);
		const bool is_rx = (s->kind() == kinetum::axiom::v1::STAGE_KIND_RX);
		const bool is_tx = (s->kind() == kinetum::axiom::v1::STAGE_KIND_TX);

		if (s->has_preferred_region()) {
			int pr = s->preferred_region();
			if (KINETUM_UNLIKELY(pr < 0)) {
				return status(status_code::INVALID_ARGUMENT,
					      "stage " + s->stage_id() +
						      " has negative preferred_region: " + std::to_string(pr));
			}
			if (KINETUM_UNLIKELY(pr >= regions)) {
				return status(status_code::INVALID_ARGUMENT,
					      "stage " + s->stage_id() + " preferred_region " + std::to_string(pr) +
						      " >= regions " + std::to_string(regions));
			}
			pinned[static_cast<size_t>(i)] = pr;
		} else if (is_rx && !multi_rx) {
			// Single RX without preference -> region 0 (pipeline entry point)
			pinned[static_cast<size_t>(i)] = 0;
		} else if (is_tx && !multi_tx) {
			// Single TX without preference -> last region (pipeline exit point)
			pinned[static_cast<size_t>(i)] = regions - 1;
		}
	}

	// Second pass: distribute RX stages without preference across early regions.
	if (multi_rx && !rx_no_pref.empty()) {
		int rx_region = 0;
		for (int idx : rx_no_pref) {
			pinned[static_cast<size_t>(idx)] = std::min(rx_region, regions - 1);
			++rx_region;
		}
	}

	// Third pass: distribute TX stages without preference across late regions.
	if (multi_tx && !tx_no_pref.empty()) {
		// Distribute TX across late regions (..., n-2, n-1) for multi-core TX
		int tx_region = regions - 1;
		for (auto it = tx_no_pref.rbegin(); it != tx_no_pref.rend(); ++it) {
			int idx = *it;
			if (pinned[static_cast<size_t>(idx)] < 0) {
				pinned[static_cast<size_t>(idx)] = std::max(tx_region, 0);
				--tx_region;
			}
		}
	}

	// Validate pinning monotonicity (pinned regions must not decrease in topo order)
	// This ensures DAG structure is preserved for epoch-consistent updates
	int last_pin = -1;
	for (int i = 0; i < n; ++i) {
		int p = pinned[static_cast<size_t>(i)];
		if (p >= 0) {
			if (p < last_pin) {
				return status(status_code::INVALID_ARGUMENT,
					      "preferred_region constraints are not monotonic in topological order");
			}
			last_pin = p;
		}
	}

	return pinned;
}

// =============================================================================
// Weight-Balanced Linear DP Partitioning
// =============================================================================

/**
 * @brief Partition stages into regions minimizing max region weight.
 *
 * DP formulation:
 *   dp[r][i] = minimum makespan to partition stages [0..i) into r regions
 *   dp[r][i] = min over j < i of: max(dp[r-1][j], sum(w[j..i)))
 *
 * With pinning constraints:
 *   - Each region r has a valid range [min_end[r], max_end[r]] for its end index
 *   - Derived from pinned stages (RX->0, TX->last, user preferences)
 *
 * @param stage_map Exact stage lookup indexed by stable stage identity.
 * @param order Canonical topological stage order.
 * @param pinned Region pin per order position, or -1 when unconstrained.
 * @param regions Exact positive output-region count.
 * @return Exact stage assignment, or a fail-closed planning status.
 *
 * Complexity: O(n^2*r) time, O(nr) space.
 */
status_or<std::unordered_map<std::string, int>>
partition_linear_dp(const std::unordered_map<std::string, const kinetum::axiom::v1::Stage *> &stage_map,
		    const std::vector<std::string> &order, const std::vector<int> &pinned, int regions)
{
	const int n = static_cast<int>(order.size());

	// Input validation with branch hints (KINETUM_UNLIKELY for error paths)
	if (KINETUM_UNLIKELY(n == 0)) {
		return status(status_code::INVALID_ARGUMENT, "pipeline has no stages");
	}
	if (KINETUM_UNLIKELY(regions <= 0)) {
		return status(status_code::INVALID_ARGUMENT, "regions must be > 0");
	}
	if (KINETUM_UNLIKELY(regions > n)) {
		return status(status_code::INVALID_ARGUMENT,
			      "regions cannot exceed stage count (would create empty regions)");
	}

	// Compute each stage weight once for this partition.
	std::vector<uint64_t> weights(static_cast<size_t>(n));
	for (int i = 0; i < n; ++i) {
		const auto *s = stage_map.at(order[static_cast<size_t>(i)]);
		weights[static_cast<size_t>(i)] = get_stage_weight(*s);
	}

	// Prefix sums provide O(1) range queries only after complete checked
	// accumulation. A wrapped authored cost must never select a different cut.
	std::vector<uint64_t> prefix(static_cast<size_t>(n + 1), 0);
	for (int i = 0; i < n; ++i) {
		const uint64_t previous = prefix[static_cast<size_t>(i)];
		const uint64_t weight = weights[static_cast<size_t>(i)];
		if (weight > std::numeric_limits<uint64_t>::max() - previous) {
			return status(status_code::OUT_OF_RANGE,
				      "aggregate authored stage weight exceeds the uint64 planning domain");
		}
		prefix[static_cast<size_t>(i + 1)] = previous + weight;
	}
	auto range_sum = [&](int a, int b) -> uint64_t {
		return prefix[static_cast<size_t>(b)] - prefix[static_cast<size_t>(a)];
	};

	// Compute region end constraints from pinning
	std::vector<pinned_constraint> region_constraints(static_cast<size_t>(regions));
	for (int r = 0; r < regions; ++r) {
		region_constraints[static_cast<size_t>(r)].first_index = n;
		region_constraints[static_cast<size_t>(r)].last_index = -1;
	}
	for (int i = 0; i < n; ++i) {
		int pr = pinned[static_cast<size_t>(i)];
		if (pr >= 0) {
			auto &rc = region_constraints[static_cast<size_t>(pr)];
			rc.first_index = std::min(rc.first_index, i);
			rc.last_index = std::max(rc.last_index, i);
		}
	}

	// Compute valid end ranges for each region
	std::vector<int> min_end(static_cast<size_t>(regions), 0);
	std::vector<int> max_end(static_cast<size_t>(regions), n);

	for (int r = 0; r < regions; ++r) {
		const auto &rc = region_constraints[static_cast<size_t>(r)];
		// Region must end after its last pinned stage
		if (rc.last_index >= 0) {
			min_end[static_cast<size_t>(r)] = rc.last_index + 1;
		}
		// Region must end before next region's first pinned stage
		if (r + 1 < regions) {
			const auto &next_rc = region_constraints[static_cast<size_t>(r + 1)];
			if (next_rc.first_index < n) {
				max_end[static_cast<size_t>(r)] = next_rc.first_index;
			}
		} else {
			max_end[static_cast<size_t>(r)] = n;
		}

		if (KINETUM_UNLIKELY(min_end[static_cast<size_t>(r)] > max_end[static_cast<size_t>(r)])) {
			return status(status_code::INVALID_ARGUMENT,
				      "pinning constraints make region " + std::to_string(r) + " infeasible");
		}
	}

	// DP tables for weight-balanced partitioning.
	// dp[r][i] = min makespan to partition [0..i) into r regions
	std::vector<std::vector<uint64_t>> dp;
	std::vector<std::vector<bool>> reachable;
	std::vector<std::vector<int>> parent;

	dp.resize(static_cast<size_t>(regions + 1), std::vector<uint64_t>(static_cast<size_t>(n + 1), 0u));
	reachable.resize(static_cast<size_t>(regions + 1), std::vector<bool>(static_cast<size_t>(n + 1), false));
	parent.resize(static_cast<size_t>(regions + 1), std::vector<int>(static_cast<size_t>(n + 1), -1));

	dp[0][0] = 0;
	reachable[0][0] = true;

	for (int r = 1; r <= regions; ++r) {
		const int ridx = r - 1;	 // Current region index
		for (int i = 1; i <= n; ++i) {
			// Check if this end position is valid for region ridx
			if (i < min_end[static_cast<size_t>(ridx)] || i > max_end[static_cast<size_t>(ridx)]) {
				continue;
			}

			// Try all possible previous cut points
			for (int j = r - 1; j <= i - 1; ++j) {
				if (!reachable[static_cast<size_t>(r - 1)][static_cast<size_t>(j)])
					continue;

				uint64_t prev_makespan = dp[static_cast<size_t>(r - 1)][static_cast<size_t>(j)];
				uint64_t region_weight = range_sum(j, i);
				uint64_t candidate = std::max(prev_makespan, region_weight);

				if (!reachable[static_cast<size_t>(r)][static_cast<size_t>(i)] ||
				    candidate < dp[static_cast<size_t>(r)][static_cast<size_t>(i)]) {
					dp[static_cast<size_t>(r)][static_cast<size_t>(i)] = candidate;
					reachable[static_cast<size_t>(r)][static_cast<size_t>(i)] = true;
					parent[static_cast<size_t>(r)][static_cast<size_t>(i)] = j;
				}
			}
		}
	}

	if (KINETUM_UNLIKELY(!reachable[static_cast<size_t>(regions)][static_cast<size_t>(n)])) {
		return status(status_code::INVALID_ARGUMENT, "no valid region partition found");
	}

	// Backtrack to recover cut points deterministically.
	std::vector<int> cuts(static_cast<size_t>(regions + 1));
	cuts[static_cast<size_t>(regions)] = n;
	int cur = n;
	for (int r = regions; r >= 1; --r) {
		int prev = parent[static_cast<size_t>(r)][static_cast<size_t>(cur)];
		if (KINETUM_UNLIKELY(prev < 0)) {
			return status(status_code::INTERNAL_ERROR, "DP backtrack failed");
		}
		cuts[static_cast<size_t>(r - 1)] = prev;
		cur = prev;
	}

	// Build the complete assignment without incremental rehashing.
	std::unordered_map<std::string, int> assignment;
	assignment.reserve(static_cast<size_t>(n));
	for (int r = 0; r < regions; ++r) {
		int start = cuts[static_cast<size_t>(r)];
		int end = cuts[static_cast<size_t>(r + 1)];
		for (int i = start; i < end; ++i) {
			assignment[order[static_cast<size_t>(i)]] = r;
		}
	}

	// Verify pinning constraints
	for (int i = 0; i < n; ++i) {
		int pr = pinned[static_cast<size_t>(i)];
		if (pr >= 0 && assignment[order[static_cast<size_t>(i)]] != pr) {
			return status(status_code::INTERNAL_ERROR,
				      "DP violated pinning constraint for stage " + order[static_cast<size_t>(i)]);
		}
	}

	return assignment;
}

// =============================================================================
// Core Planning Logic
// =============================================================================

/**
 * @brief Internal implementation of the Gluon planning algorithm.
 *
 * This is the core planning algorithm that transforms an Axiom pipeline
 * into an executable DeploymentPlan. The algorithm proceeds in phases:
 *
 * **Phase 1: Validation and Setup**
 * - Validate input parameters
 * - Build stage lookup map
 * - Compute stable topological order (Kahn's algorithm)
 *
 * **Phase 2: Constraint Analysis**
 * - Extract pinning constraints (RX->0, TX->last, user preferences)
 * - Validate constraint consistency
 *
 * **Phase 3: Region Partitioning**
 * - Execute linear DP algorithm O(n^2 * r)
 * - Minimize makespan (max region weight)
 * - Respect all pinning constraints
 *
 * **Phase 4: Executable Provider-Graph Construction**
 * - Create regions and assign stages
 * - Resolve exact typed driver attachments against hardware facts
 * - Lower provider instances, ports, queues, stage instances, and transitions
 * - Emit exact boundaries, runtime services, and transition policy
 *
 * **Phase 5: Placement and Identity Finalization**
 * - Compute NUMA-aware worker/service cores and exact coordinator ownership
 * - Finalize metadata, plan identity, and content hash
 *
 * @param pipeline The Axiom pipeline to plan.
 * @param hw Hardware inventory for resource constraints.
 * @param opt Planning options and constraints.
 * @return Complete DeploymentPlan, or an error status.
 *
 * @note Placement and identity facts are deterministic for identical inputs;
 *       planning timestamps and durations are intentionally variable.
 *
 */
status_or<DeploymentPlan> plan_impl(const kinetum::axiom::v1::Pipeline &pipeline,
				    const kinetum::hw::v1::HardwareInventory &hw, const planner_options &opt)
{
	if (const auto contract_status = kinetum::axiom::verify_contract(pipeline, kinetum::axiom::contract_options{});
	    !contract_status.is_ok()) {
		return contract_status;
	}
	if (const auto unknown_status =
		    kinetum::common::reject_unknown_protobuf_fields_recursive(hw, "HardwareInventory");
	    !unknown_status.is_ok()) {
		return unknown_status;
	}
	if (const auto enum_status =
		    kinetum::common::reject_invalid_protobuf_enum_values_recursive(hw, "HardwareInventory");
	    !enum_status.is_ok()) {
		return enum_status;
	}
	if (const auto unknown_status = kinetum::common::reject_unknown_protobuf_fields_recursive(
		    opt.deployment_bindings, "DeploymentBindings");
	    !unknown_status.is_ok()) {
		return unknown_status;
	}
	if (const auto enum_status = kinetum::common::reject_invalid_protobuf_enum_values_recursive(
		    opt.deployment_bindings, "DeploymentBindings");
	    !enum_status.is_ok()) {
		return enum_status;
	}
	auto start_time = std::chrono::steady_clock::now();

	// Validate scalar planner inputs before allocating partition tables.
	if (KINETUM_UNLIKELY(opt.regions <= 0)) {
		return status(status_code::INVALID_ARGUMENT, "regions must be > 0");
	}

	// Enforce MAX_REGIONS limit
	if (KINETUM_UNLIKELY(opt.regions > MAX_REGIONS)) {
		return status(status_code::INVALID_ARGUMENT, "regions exceeds max: " + std::to_string(opt.regions) +
								     " > " + std::to_string(MAX_REGIONS));
	}
	if (KINETUM_UNLIKELY(opt.reserved_cores < 0)) {
		return status(status_code::INVALID_ARGUMENT,
			      "reserved_cores must be >= 0, got " + std::to_string(opt.reserved_cores));
	}
	for (int32_t numa_node : opt.allowed_numa_nodes) {
		if (KINETUM_UNLIKELY(numa_node < 0)) {
			return status(status_code::INVALID_ARGUMENT,
				      "allowed_numa_nodes entries must be >= 0, got " + std::to_string(numa_node));
		}
	}

	// Build stage lookup map
	std::unordered_map<std::string, const kinetum::axiom::v1::Stage *> stage_map;
	stage_map.reserve(static_cast<size_t>(pipeline.stages_size()));
	for (const auto &s : pipeline.stages()) {
		stage_map.emplace(s.stage_id(), &s);
	}

	// Compute the canonical topological order.
	auto order_or = kinetum::axiom::canonical_topological_order(pipeline);
	if (KINETUM_UNLIKELY(!order_or.is_ok()))
		return order_or.error();
	const auto &order = order_or.value();

	// Compute pinning constraints
	auto pinned_or = compute_pinning(order, stage_map, opt.regions);
	if (KINETUM_UNLIKELY(!pinned_or.is_ok()))
		return pinned_or.error();
	const auto &pinned = pinned_or.value();

	// Axiom is the sole affinity authority; Gluon consumes its exact relations.
	std::vector<std::pair<std::string, std::string>> must_colocate;
	std::vector<std::pair<std::string, std::string>> must_separate;
	for (const auto &stage : pipeline.stages()) {
		if (stage.has_constraints()) {
			for (const auto &affinity_id : stage.constraints().affinity_stages()) {
				must_colocate.push_back({stage.stage_id(), affinity_id});
			}
			for (const auto &anti_id : stage.constraints().anti_affinity_stages()) {
				must_separate.push_back({stage.stage_id(), anti_id});
			}
		}
	}

	// Axiom has already admitted one exact normalized relation set. Sorting its
	// pairs makes partition input deterministic without repairing duplicates.
	auto sort_pairs = [](std::vector<std::pair<std::string, std::string>> &pairs) {
		for (auto &p : pairs) {
			// Normalize pair order: always put lexicographically smaller first.
			if (p.first > p.second) {
				std::swap(p.first, p.second);
			}
		}
		// Sort by first element, then second.
		std::sort(pairs.begin(), pairs.end());
	};

	sort_pairs(must_colocate);
	sort_pairs(must_separate);

	auto partition_or = partition_linear_dp(stage_map, order, pinned, opt.regions);
	if (KINETUM_UNLIKELY(!partition_or.is_ok())) {
		return partition_or.error();
	}
	std::unordered_map<std::string, int> assignment = std::move(partition_or).value();

	// Validate must_colocate constraints
	for (const auto &[stage_a, stage_b] : must_colocate) {
		auto it_a = assignment.find(stage_a);
		auto it_b = assignment.find(stage_b);
		if (it_a == assignment.end() || it_b == assignment.end()) {
			return status::internal_error("Axiom affinity relation lost its planner assignment");
		}
		if (it_a->second != it_b->second) {
			return status(status_code::INVALID_ARGUMENT,
				      "must_colocate constraint violated: stages " + stage_a + " (region " +
					      std::to_string(it_a->second) + ") and " + stage_b + " (region " +
					      std::to_string(it_b->second) + ") are in different regions");
		}
	}

	// Validate must_separate constraints
	for (const auto &[stage_a, stage_b] : must_separate) {
		auto it_a = assignment.find(stage_a);
		auto it_b = assignment.find(stage_b);
		if (it_a == assignment.end() || it_b == assignment.end()) {
			return status::internal_error("Axiom anti-affinity relation lost its planner assignment");
		}
		if (it_a->second == it_b->second) {
			return status(status_code::INVALID_ARGUMENT,
				      "must_separate constraint violated: stages " + stage_a + " and " + stage_b +
					      " are both in region " + std::to_string(it_a->second));
		}
	}

	// Active-stage validation: enforce v1 same-region constraints
	for (int i = 0; i < pipeline.edges_size(); ++i) {
		const auto &edge = pipeline.edges(i);

		// PULL edges must be same-region
		if (edge.mode() == kinetum::axiom::v1::EDGE_MODE_PULL) {
			auto from_it = assignment.find(edge.from_stage_id());
			auto to_it = assignment.find(edge.to_stage_id());
			if (from_it != assignment.end() && to_it != assignment.end()) {
				if (from_it->second != to_it->second) {
					return status(status_code::INVALID_ARGUMENT,
						      "PULL edge from '" + edge.from_stage_id() + "' (region " +
							      std::to_string(from_it->second) + ") to '" +
							      edge.to_stage_id() + "' (region " +
							      std::to_string(to_it->second) +
							      ") crosses regions; PULL must be same-region");
				}
			}
		}
	}

	// Control/feedback edges must be same-region
	for (int i = 0; i < pipeline.control_edges_size(); ++i) {
		const auto &ce = pipeline.control_edges(i);
		auto from_it = assignment.find(ce.from_stage_id());
		auto to_it = assignment.find(ce.to_stage_id());
		if (from_it != assignment.end() && to_it != assignment.end()) {
			if (from_it->second != to_it->second) {
				return status(status_code::INVALID_ARGUMENT,
					      "control edge from '" + ce.from_stage_id() + "' (region " +
						      std::to_string(from_it->second) + ") to '" + ce.to_stage_id() +
						      "' (region " + std::to_string(to_it->second) +
						      ") crosses regions; control/feedback must be same-region");
			}
		}
	}

	// Build the deployment plan
	DeploymentPlan plan;
	plan.mutable_pipeline()->CopyFrom(pipeline);

	// Create regions and assign stages
	plan.mutable_regions()->Reserve(opt.regions);

	for (int r = 0; r < opt.regions; ++r) {
		Region *reg = plan.add_regions();
		reg->set_region_id(r);
	}

	for (const auto &sid : order) {
		int r = assignment.at(sid);
		plan.mutable_regions(r)->add_logical_stage_ids(sid);
	}

	// Worker-level core placement is emitted after executable topology lowering,
	// because stream intent can create more runtime workers than logical regions.

	// Confirm that partition ownership covers every pipeline edge before
	// executable topology lowering. This logical-region check must not infer a
	// worker-to-worker boundary or populate the compact boundaries[] contract.
	for (const auto &e : pipeline.edges()) {
		auto from_it = assignment.find(e.from_stage_id());
		auto to_it = assignment.find(e.to_stage_id());
		if (from_it == assignment.end() || to_it == assignment.end()) {
			return status(status_code::INVALID_ARGUMENT, "edge references unknown stage in assignment");
		}
	}

	if (const auto deployment_bindings_status = lower_deployment_bindings(opt.deployment_bindings, hw, plan);
	    !deployment_bindings_status.is_ok()) {
		return deployment_bindings_status;
	}

	runtime_core_placement_options placement_options;
	placement_options.reserved_cores = opt.reserved_cores;
	placement_options.numa_aware = opt.numa_aware;
	placement_options.prefer_physical_cores = opt.prefer_physical_cores;
	placement_options.allowed_numa_nodes = opt.allowed_numa_nodes;
	if (const auto placement_status = lower_runtime_core_placement(plan, hw, placement_options);
	    !placement_status.is_ok()) {
		return placement_status;
	}
	if (const auto boundary_status = lower_boundary_topology(plan); !boundary_status.is_ok()) {
		return boundary_status;
	}
	if (const auto transition_status = lower_transition_plan(plan); !transition_status.is_ok()) {
		return transition_status;
	}
	auto compiled_provider_or = kinetum::provider::compile_provider_topology(plan);
	if (!compiled_provider_or.is_ok()) {
		return compiled_provider_or.error();
	}

	if (plan.runtime_service_placements_size() == 0) {
		return status(status_code::INTERNAL_ERROR,
			      "runtime core placement omitted the epoch-transition coordinator");
	}
	const auto &coordinator = plan.runtime_service_placements(0);
	if (coordinator.service_kind() != kinetum::gluon::v1::RUNTIME_SERVICE_KIND_EPOCH_TRANSITION_COORDINATOR ||
	    coordinator.service_id() != kinetum::common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID ||
	    coordinator.cpu_core_id() < 0 ||
	    coordinator.command_mailbox_capacity() != COORDINATOR_COMMAND_MAILBOX_CAPACITY) {
		return status(status_code::INTERNAL_ERROR,
			      "runtime core placement emitted an invalid epoch-transition coordinator");
	}

	// Set metadata
	auto *meta = plan.mutable_metadata();
	meta->set_planner_version(std::string(PLANNER_VERSION_PREFIX) + kinetum::common::KINETUM_VERSION_STRING);
	meta->set_planned_unix_ms(std::chrono::duration_cast<std::chrono::milliseconds>(
					  std::chrono::system_clock::now().time_since_epoch())
					  .count());
	meta->set_algorithm(std::string(PLANNING_ALGORITHM));

	auto end_time = std::chrono::steady_clock::now();
	meta->set_planning_duration_ms(
		std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

	// Derive the human-scale plan ID from the complete canonical structure with
	// both self-identities absent. Then publish the final content hash over that
	// plan ID and every other stable field. Provider Any payloads pass through
	// the same role-correct catalog authority in both operations.
	plan.clear_plan_id();
	plan.clear_content_hash();
	auto structural_hash_or = kinetum::provider::compute_deployment_plan_content_hash(plan);
	if (!structural_hash_or.is_ok()) {
		return structural_hash_or.error();
	}
	plan.set_plan_id("plan_" + structural_hash_or.value().substr(0, 16));
	if (const auto identity_status = kinetum::provider::finalize_deployment_plan_identity(&plan);
	    !identity_status.is_ok()) {
		return identity_status;
	}

	return plan;
}

}  // namespace

// =============================================================================
// Public API (inside kinetum::gluon)
// =============================================================================

status_or<DeploymentPlan> plan(const kinetum::axiom::v1::Pipeline &pipeline,
			       const kinetum::hw::v1::HardwareInventory &hw, const planner_options &opt)
{
	try {
		return plan_impl(pipeline, hw, opt);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Gluon planning exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Gluon planning exceeds the host size domain");
	}
}

}  // namespace kinetum::gluon
