// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file transition_topology.cpp
 * @brief Shared exact transition-topology compiler implementation.
 * @author Fleming Patel
 *
 * This cold-path compiler turns plan-authored identities into compact indices,
 * proves exact boundary-set equality, validates the execution-participant DAG,
 * resolves source/sink and lifecycle-service ownership, and compiles bounded
 * monotonic-clock policy. It allocates no runtime queue and invokes no provider.
 */

#include "src/common/transition_topology.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <queue>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "src/common/execution_topology_ids.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_service_ids.hpp"
#include "src/common/status.hpp"

namespace kinetum::common
{

namespace
{

using kinetum::common::status;
using kinetum::common::status_code;

/** @brief Stable worker owner key independent of protobuf construction order. */
struct worker_owner_key {
	int32_t region_id{-1};	///< Logical region.
	std::string lane_id;	///< Execution lane.

	/**
	 * @brief Compare ownership keys deterministically.
	 *
	 * @param other Key to compare.
	 * @return true when this key precedes @p other.
	 */
	[[nodiscard]] bool operator<(const worker_owner_key &other) const noexcept
	{
		return std::tie(region_id, lane_id) < std::tie(other.region_id, other.lane_id);
	}
};

/** @brief Stable logical-stage/lane key for exact executable endpoints. */
struct stage_lane_key {
	std::string logical_stage_id;  ///< Authored logical stage.
	std::string lane_id;	       ///< Exact execution lane.

	/**
	 * @brief Compare executable endpoint keys deterministically.
	 *
	 * @param other Key to compare.
	 * @return true when this key precedes @p other.
	 */
	[[nodiscard]] bool operator<(const stage_lane_key &other) const noexcept
	{
		return std::tie(logical_stage_id, lane_id) < std::tie(other.logical_stage_id, other.lane_id);
	}
};

/** @brief Resolved stage-instance facts needed by boundary compilation. */
struct stage_instance_record {
	uint32_t stage_instance_index{0};  ///< Plan-order executable index.
	uint32_t worker_index{0};	   ///< Sole worker owner.
	int32_t region_id{-1};		   ///< Owner region.
	int32_t numa_node{-1};		   ///< Owner region NUMA node.
};

/** @brief Expected semantic ownership for one cross-worker endpoint pair. */
struct expected_boundary {
	uint32_t from_stage_instance_index{0};	///< Source executable endpoint.
	uint32_t to_stage_instance_index{0};	///< Destination executable endpoint.
	uint32_t sender_worker_index{0};	///< Sole sender worker.
	uint32_t receiver_worker_index{0};	///< Sole receiver worker.
	int32_t receiver_numa_node{-1};		///< Required DATA-ring NUMA node.
};

/**
 * @brief Check a required power-of-two capacity.
 *
 * @param value Candidate capacity.
 * @return true when nonzero and a power of two.
 */
[[nodiscard]] constexpr bool is_nonzero_power_of_two(uint32_t value) noexcept
{
	return value != 0 && (value & (value - 1u)) == 0;
}

/**
 * @brief Check the complete shared SPSC usable-capacity contract.
 *
 * @param value Candidate usable element population.
 * @return true when at least two and a power of two.
 */
[[nodiscard]] constexpr bool is_spsc_capacity(uint32_t value) noexcept
{
	return value >= 2u && is_nonzero_power_of_two(value);
}

/**
 * @brief Compile positive milliseconds into the runtime monotonic duration.
 *
 * @param value Plan-authored duration in milliseconds.
 * @param field Field name used in diagnostics.
 * @return Representable monotonic duration, or an admission error.
 */
[[nodiscard]] status_or<std::chrono::steady_clock::duration> compile_milliseconds(uint64_t value,
										  std::string_view field)
{
	if (value == 0) {
		return status(status_code::INVALID_ARGUMENT, std::string(field) + " must be positive");
	}
	const auto max_count =
		std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::duration::max())
			.count();
	if (max_count <= 0 || value > static_cast<uint64_t>(max_count)) {
		return status(status_code::OUT_OF_RANGE, std::string(field) + " is not representable by steady_clock");
	}
	const auto compiled = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
		std::chrono::milliseconds(static_cast<int64_t>(value)));
	if (compiled <= std::chrono::steady_clock::duration::zero() ||
	    std::chrono::duration_cast<std::chrono::milliseconds>(compiled) !=
		    std::chrono::milliseconds(static_cast<int64_t>(value))) {
		return status(status_code::OUT_OF_RANGE,
			      std::string(field) + " is not exactly representable by steady_clock");
	}
	return compiled;
}

/**
 * @brief Compile positive nanoseconds into the runtime monotonic duration.
 *
 * @param value Plan-authored duration in nanoseconds.
 * @param field Field name used in diagnostics.
 * @return Representable monotonic duration, or an admission error.
 */
[[nodiscard]] status_or<std::chrono::steady_clock::duration> compile_nanoseconds(uint64_t value, std::string_view field)
{
	if (value == 0) {
		return status(status_code::INVALID_ARGUMENT, std::string(field) + " must be positive");
	}
	const auto max_count =
		std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::duration::max()).count();
	if (max_count <= 0 || value > static_cast<uint64_t>(max_count)) {
		return status(status_code::OUT_OF_RANGE, std::string(field) + " is not representable by steady_clock");
	}
	const auto compiled = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
		std::chrono::nanoseconds(static_cast<int64_t>(value)));
	if (compiled <= std::chrono::steady_clock::duration::zero() ||
	    std::chrono::duration_cast<std::chrono::nanoseconds>(compiled) !=
		    std::chrono::nanoseconds(static_cast<int64_t>(value))) {
		return status(status_code::OUT_OF_RANGE,
			      std::string(field) + " is not exactly representable by steady_clock");
	}
	return compiled;
}

/**
 * @brief Check one typed module identity without inventing a default.
 *
 * @param stage Module stage to inspect.
 * @return true when typed module configuration has a nonempty identity.
 */
[[nodiscard]] bool has_exact_module_id(const kinetum::axiom::v1::Stage &stage)
{
	return stage.has_module() && !stage.module().module_id().empty();
}

/**
 * @brief Validate that the worker graph is acyclic.
 *
 * Multiple executable boundaries between the same worker pair collapse to one
 * graph edge for cycle analysis; boundary identity and ownership remain
 * per-endpoint elsewhere.
 *
 * @param topology Compiled workers and boundaries.
 * @return OK for a DAG; INVALID_ARGUMENT when a cycle exists.
 */
[[nodiscard]] status validate_worker_dag(const compiled_transition_topology &topology)
{
	std::vector<std::set<uint32_t>> successors(topology.workers.size());
	std::vector<uint32_t> indegree(topology.workers.size(), 0);
	for (const auto &boundary : topology.boundaries) {
		if (successors[boundary.sender_worker_index].insert(boundary.receiver_worker_index).second) {
			++indegree[boundary.receiver_worker_index];
		}
	}

	std::priority_queue<uint32_t, std::vector<uint32_t>, std::greater<>> ready;
	for (std::size_t i = 0; i < indegree.size(); ++i) {
		if (indegree[i] == 0) {
			ready.push(static_cast<uint32_t>(i));
		}
	}

	std::size_t visited = 0;
	while (!ready.empty()) {
		const uint32_t worker_index = ready.top();
		ready.pop();
		++visited;
		for (const uint32_t successor : successors[worker_index]) {
			if (--indegree[successor] == 0) {
				ready.push(successor);
			}
		}
	}

	if (visited != topology.workers.size()) {
		return status(status_code::INVALID_ARGUMENT,
			      "epoch-transition execution-participant boundary graph contains a cycle");
	}
	return status::ok();
}

}  // namespace

status_or<compiled_transition_topology> compile_transition_topology(const kinetum::gluon::v1::DeploymentPlan &plan)
{
	namespace topology_ids = kinetum::common::execution_topology;
	namespace service_ids = kinetum::common::runtime_services;
	if (const auto unknown_status = reject_unknown_protobuf_fields_recursive(plan, "DeploymentPlan");
	    !unknown_status.is_ok()) {
		return unknown_status;
	}
	if (const auto enum_status = reject_invalid_protobuf_enum_values_recursive(plan, "DeploymentPlan");
	    !enum_status.is_ok()) {
		return enum_status;
	}

	compiled_transition_topology out;

	std::map<int32_t, const kinetum::gluon::v1::Region *> regions_by_id;
	for (const auto &region : plan.regions()) {
		if (region.region_id() < 0 || region.region_id() >= plan.regions_size()) {
			return status(status_code::INVALID_ARGUMENT, "region_id " + std::to_string(region.region_id()) +
									     " is outside the compact region range");
		}
		if (region.numa_node() < 0) {
			return status(status_code::INVALID_ARGUMENT, "region " + std::to_string(region.region_id()) +
									     " has unresolved NUMA ownership");
		}
		if (!regions_by_id.emplace(region.region_id(), &region).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "duplicate region_id " + std::to_string(region.region_id()));
		}
	}
	for (int32_t region_id = 0; region_id < plan.regions_size(); ++region_id) {
		if (!regions_by_id.contains(region_id)) {
			return status(status_code::INVALID_ARGUMENT,
				      "regions[] missing compact region_id " + std::to_string(region_id));
		}
	}
	if (plan.pipeline().stages_size() > 0 && plan.execution_lanes_size() == 0) {
		return status(status_code::INVALID_ARGUMENT, "deployment plan missing execution_lanes[]");
	}
	if (plan.pipeline().stages_size() > 0 && plan.stage_instances_size() == 0) {
		return status(status_code::INVALID_ARGUMENT, "deployment plan missing stage_instances[]");
	}

	std::map<std::string, uint32_t> lane_indices;
	std::vector<bool> seen_lane_indices(static_cast<std::size_t>(plan.execution_lanes_size()), false);
	for (const auto &lane : plan.execution_lanes()) {
		if (!topology_ids::is_topology_identifier(lane.lane_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "execution lane_id '" + lane.lane_id() + "' is not a topology identifier",
				      lane.lane_id());
		}
		if (lane.lane_index() >= static_cast<uint32_t>(plan.execution_lanes_size()) ||
		    seen_lane_indices[lane.lane_index()] ||
		    !lane_indices.emplace(lane.lane_id(), lane.lane_index()).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "execution_lanes[] has duplicate or noncompact identity", lane.lane_id());
		}
		seen_lane_indices[lane.lane_index()] = true;
	}

	std::set<int32_t> owned_cpu_cores;
	std::map<worker_owner_key, uint32_t> worker_by_owner;
	std::unordered_map<std::string, uint32_t> worker_by_id;
	out.workers.resize(static_cast<std::size_t>(plan.worker_placements_size()));
	std::vector<bool> seen_worker_indices(out.workers.size(), false);
	for (int placement_index = 0; placement_index < plan.worker_placements_size(); ++placement_index) {
		const auto &worker = plan.worker_placements(placement_index);
		if (!topology_ids::is_topology_identifier(worker.lane_id()) ||
		    !lane_indices.contains(worker.lane_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker placement '" + worker.worker_id() + "' references invalid lane_id '" +
					      worker.lane_id() + "'",
				      worker.worker_id());
		}
		if (!regions_by_id.contains(worker.region_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker placement '" + worker.worker_id() + "' references unknown region",
				      worker.worker_id());
		}
		if (worker.worker_index() >= out.workers.size() || seen_worker_indices[worker.worker_index()]) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker_placements[] has duplicate or noncompact worker_index",
				      worker.worker_id());
		}
		const auto expected_id = topology_ids::make_worker_id(worker.region_id(), worker.lane_id());
		if (worker.worker_id() != expected_id) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker_id '" + worker.worker_id() + "' does not match deterministic ID '" +
					      expected_id + "'",
				      worker.worker_id());
		}
		if (!worker_by_id.emplace(worker.worker_id(), worker.worker_index()).second ||
		    !worker_by_owner
			     .emplace(worker_owner_key{worker.region_id(), worker.lane_id()}, worker.worker_index())
			     .second) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker_placements[] has duplicate executable ownership", worker.worker_id());
		}
		if (worker.cpu_core_ids_size() != 1) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker placement '" + worker.worker_id() +
					      "' requires exactly one dedicated CPU core",
				      worker.worker_id());
		}

		auto &compiled = out.workers[worker.worker_index()];
		compiled.worker_id = worker.worker_id();
		compiled.worker_index = worker.worker_index();
		compiled.worker_placement_index = static_cast<uint32_t>(placement_index);
		compiled.region_id = worker.region_id();
		compiled.lane_id = worker.lane_id();
		compiled.lane_index = lane_indices.at(worker.lane_id());
		compiled.numa_node = regions_by_id.at(worker.region_id())->numa_node();
		compiled.source_epoch_staging_capacity = worker.source_epoch_staging_capacity();
		int32_t previous_core = -1;
		for (const int32_t core_id : worker.cpu_core_ids()) {
			if (core_id < 0 || core_id <= previous_core || !owned_cpu_cores.insert(core_id).second) {
				return status(
					status_code::INVALID_ARGUMENT,
					"worker CPU ownership must be nonnegative, strictly ordered, and disjoint",
					worker.worker_id());
			}
			previous_core = core_id;
			compiled.cpu_core_ids.push_back(core_id);
		}
		seen_worker_indices[worker.worker_index()] = true;
	}
	for (std::size_t worker_index = 0; worker_index < seen_worker_indices.size(); ++worker_index) {
		if (!seen_worker_indices[worker_index]) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker_placements[] missing compact worker_index " +
					      std::to_string(worker_index));
		}
	}
	if (!regions_by_id.empty() && out.workers.empty()) {
		return status(status_code::INVALID_ARGUMENT, "regions[] require explicit worker_placements[]");
	}

	std::unordered_map<std::string, const kinetum::axiom::v1::Stage *> logical_stages;
	logical_stages.reserve(static_cast<std::size_t>(plan.pipeline().stages_size()));
	for (const auto &stage : plan.pipeline().stages()) {
		if (!topology_ids::is_topology_identifier(stage.stage_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "pipeline stage_id '" + stage.stage_id() + "' is not a valid topology identifier",
				      stage.stage_id());
		}
		if (!logical_stages.emplace(stage.stage_id(), &stage).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "pipeline has duplicate logical stage_id '" + stage.stage_id() + "'",
				      stage.stage_id());
		}
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE && !has_exact_module_id(stage)) {
			return status(status_code::INVALID_ARGUMENT,
				      "module stage '" + stage.stage_id() + "' requires one nonempty module_id",
				      stage.stage_id());
		}
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE &&
		    stage.module().context_selection() != kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE &&
		    stage.module().context_selection() != kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_MODULE) {
			return status::invalid_argument("module stage requires explicit context selection");
		}
	}

	std::map<stage_lane_key, stage_instance_record> stage_by_logical_lane;
	std::unordered_map<std::string, stage_instance_record> stage_by_id;
	stage_by_id.reserve(static_cast<std::size_t>(plan.stage_instances_size()));
	std::map<std::string, std::set<std::string>> lanes_by_logical_stage;
	std::unordered_set<std::string> module_context_ids;
	std::set<int32_t> module_context_numa_nodes;
	if (static_cast<uint64_t>(plan.stage_instances_size()) > std::numeric_limits<uint32_t>::max()) {
		return status(status_code::OUT_OF_RANGE,
			      "stage_instances[] exceeds compact transition-topology index range");
	}
	for (int i = 0; i < plan.stage_instances_size(); ++i) {
		const auto &instance = plan.stage_instances(i);
		const auto logical_it = logical_stages.find(instance.logical_stage_id());
		if (logical_it == logical_stages.end() || !lane_indices.contains(instance.lane_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage instance '" + instance.stage_instance_id() +
					      " references an unknown logical stage or lane",
				      instance.stage_instance_id());
		}
		if (!regions_by_id.contains(instance.region_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage instance '" + instance.stage_instance_id() + "' references unknown region",
				      instance.stage_instance_id());
		}
		const auto worker_it = worker_by_owner.find(worker_owner_key{instance.region_id(), instance.lane_id()});
		if (worker_it == worker_by_owner.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage instance '" + instance.stage_instance_id() + "' has no exact worker owner",
				      instance.stage_instance_id());
		}
		const auto expected_id =
			topology_ids::make_stage_instance_id(instance.logical_stage_id(), instance.lane_id());
		if (instance.stage_instance_id() != expected_id ||
		    instance.replica_index() != lane_indices.at(instance.lane_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage instance '" + instance.stage_instance_id() +
					      " has noncanonical identity or replica index",
				      instance.stage_instance_id());
		}
		const auto stage_index = static_cast<uint32_t>(i);
		const stage_instance_record record{stage_index, worker_it->second, instance.region_id(),
						   regions_by_id.at(instance.region_id())->numa_node()};
		if (!stage_by_id.emplace(instance.stage_instance_id(), record).second ||
		    !stage_by_logical_lane
			     .emplace(stage_lane_key{instance.logical_stage_id(), instance.lane_id()}, record)
			     .second) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage_instances[] has duplicate executable identity",
				      instance.stage_instance_id());
		}
		lanes_by_logical_stage[instance.logical_stage_id()].insert(instance.lane_id());
		auto &worker = out.workers[worker_it->second];
		worker.stage_instance_indices.push_back(stage_index);
		const bool active = logical_it->second->execution_mode() == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE;
		const bool has_active_origin = !instance.active_origin_storage_domain_id().empty();
		if (active != has_active_origin) {
			return status(status_code::INVALID_ARGUMENT,
				      active ? "active stage instance requires one exact origin storage domain" :
					       "passive stage instance must not carry an origin storage domain",
				      instance.stage_instance_id());
		}
		if (logical_it->second->kind() == kinetum::axiom::v1::STAGE_KIND_RX || has_active_origin) {
			worker.is_source = true;
		}
		if (logical_it->second->kind() == kinetum::axiom::v1::STAGE_KIND_TX) {
			worker.is_sink = true;
		}
		if (logical_it->second->kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
			if (instance.context_instance_id() != instance.stage_instance_id() ||
			    !module_context_ids.insert(instance.context_instance_id()).second) {
				return status(status_code::INVALID_ARGUMENT,
					      "module stage instance '" + instance.stage_instance_id() +
						      "' lacks exact per-instance context ownership",
					      instance.stage_instance_id());
			}
			worker.owns_module_context = true;
			module_context_numa_nodes.insert(record.numa_node);
		}
	}
	out.boundaries_by_source_stage_instance.resize(static_cast<std::size_t>(plan.stage_instances_size()));
	out.module_context_numa_nodes.assign(module_context_numa_nodes.begin(), module_context_numa_nodes.end());
	for (const auto &[logical_stage_id, stage] : logical_stages) {
		(void)stage;
		const auto lanes_it = lanes_by_logical_stage.find(logical_stage_id);
		if (lanes_it == lanes_by_logical_stage.end() || lanes_it->second.empty()) {
			return status(status_code::INVALID_ARGUMENT,
				      "logical stage '" + logical_stage_id + "' has no executable stage_instance",
				      logical_stage_id);
		}
	}
	if (static_cast<uint64_t>(plan.io_streams_size()) > std::numeric_limits<uint32_t>::max()) {
		return status(status_code::OUT_OF_RANGE,
			      "io_streams[] exceeds compact transition-topology index range");
	}
	std::unordered_set<std::string> io_stream_ids;
	io_stream_ids.reserve(static_cast<std::size_t>(plan.io_streams_size()));
	for (int i = 0; i < plan.io_streams_size(); ++i) {
		const auto &stream = plan.io_streams(i);
		const auto instance_it = stage_by_id.find(stream.stage_instance_id());
		if (stream.io_stream_id().empty()) {
			return status(status_code::INVALID_ARGUMENT, "io_streams[] contains an empty io_stream_id",
				      stream.io_stream_id());
		}
		if (!io_stream_ids.insert(stream.io_stream_id()).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "io_streams[] contains duplicate io_stream_id '" + stream.io_stream_id() + "'",
				      stream.io_stream_id());
		}
		if (instance_it == stage_by_id.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      "io_stream '" + stream.io_stream_id() +
					      "' references unknown stage_instance_id '" + stream.stage_instance_id() +
					      "'",
				      stream.io_stream_id());
		}
		const auto &instance = plan.stage_instances(static_cast<int>(instance_it->second.stage_instance_index));
		const auto owner_it = worker_by_id.find(stream.owning_worker_id());
		if (owner_it == worker_by_id.end() || owner_it->second != instance_it->second.worker_index ||
		    stream.lane_id() != instance.lane_id()) {
			return status(status_code::INVALID_ARGUMENT,
				      "io_stream '" + stream.io_stream_id() +
					      " disagrees with its stage-instance worker ownership",
				      stream.io_stream_id());
		}
		out.workers[instance_it->second.worker_index].io_stream_indices.push_back(static_cast<uint32_t>(i));
	}
	for (const auto &worker : out.workers) {
		if (worker.is_source) {
			out.source_worker_indices.push_back(worker.worker_index);
		}
		if (worker.is_sink) {
			out.sink_worker_indices.push_back(worker.worker_index);
		}
	}

	using endpoint_key = std::pair<std::string, std::string>;
	std::map<endpoint_key, expected_boundary> expected_boundaries;
	for (const auto &edge : plan.pipeline().edges()) {
		if (!logical_stages.contains(edge.from_stage_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "pipeline edge references unknown source stage '" + edge.from_stage_id() + "'",
				      edge.from_stage_id());
		}
		if (!logical_stages.contains(edge.to_stage_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "pipeline edge references unknown destination stage '" + edge.to_stage_id() + "'",
				      edge.to_stage_id());
		}
		const auto from_lanes_it = lanes_by_logical_stage.find(edge.from_stage_id());
		const auto to_lanes_it = lanes_by_logical_stage.find(edge.to_stage_id());
		if (from_lanes_it == lanes_by_logical_stage.end() || to_lanes_it == lanes_by_logical_stage.end() ||
		    from_lanes_it->second.empty() || from_lanes_it->second != to_lanes_it->second) {
			return status(status_code::INVALID_ARGUMENT,
				      "pipeline edge '" + edge.from_stage_id() + "' -> '" + edge.to_stage_id() +
					      "' has incomplete lane-local stage-instance coverage");
		}
		const auto &target_stage = *logical_stages.at(edge.to_stage_id());
		const bool selects_context = edge.mode() == kinetum::axiom::v1::EDGE_MODE_PUSH &&
					     target_stage.has_module() &&
					     target_stage.module().context_selection() ==
						     kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_MODULE;
		for (const auto &lane_id : from_lanes_it->second) {
			const auto from_it = stage_by_logical_lane.find(stage_lane_key{edge.from_stage_id(), lane_id});
			if (from_it == stage_by_logical_lane.end()) {
				return status(status_code::INTERNAL_ERROR,
					      "stage-instance coverage changed during transition compilation");
			}
			/** @brief Record one independently derived exact destination crossing. */
			const auto admit_destination = [&](const std::string &destination_lane) -> status {
				const auto to_it = stage_by_logical_lane.find(
					stage_lane_key{edge.to_stage_id(), destination_lane});
				if (to_it == stage_by_logical_lane.end()) {
					return status::internal_error(
						"destination coverage changed during transition compilation");
				}
				if (from_it->second.worker_index == to_it->second.worker_index) {
					return status::ok();
				}
				const endpoint_key key{
					topology_ids::make_stage_instance_id(edge.from_stage_id(), lane_id),
					topology_ids::make_stage_instance_id(edge.to_stage_id(), destination_lane)};
				expected_boundaries.try_emplace(
					key, expected_boundary{from_it->second.stage_instance_index,
							       to_it->second.stage_instance_index,
							       from_it->second.worker_index, to_it->second.worker_index,
							       to_it->second.numa_node});
				if (expected_boundaries.size() > static_cast<std::size_t>(plan.boundaries_size())) {
					return status::invalid_argument(
						"boundaries[] missing executable edge: declared set is smaller than required");
				}
				return status::ok();
			};
			if (selects_context) {
				for (const auto &destination_lane : to_lanes_it->second) {
					if (auto result = admit_destination(destination_lane); !result.is_ok()) {
						return result;
					}
				}
			} else if (auto result = admit_destination(lane_id); !result.is_ok()) {
				return result;
			}
		}
	}

	std::set<std::string> boundary_ids;
	std::set<endpoint_key> actual_endpoint_keys;
	std::optional<endpoint_key> previous_endpoint;
	out.boundaries.reserve(static_cast<std::size_t>(plan.boundaries_size()));
	for (const auto &boundary : plan.boundaries()) {
		const endpoint_key key{boundary.from_stage_instance_id(), boundary.to_stage_instance_id()};
		if (previous_endpoint.has_value() && !(previous_endpoint.value() < key)) {
			return status(status_code::INVALID_ARGUMENT,
				      "boundaries[] must be strictly ordered by executable endpoint identity",
				      boundary.boundary_id());
		}
		previous_endpoint = key;
		const auto expected_it = expected_boundaries.find(key);
		if (expected_it == expected_boundaries.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      "boundary '" + boundary.boundary_id() +
					      " is extra, same-worker, or references an unknown executable edge",
				      boundary.boundary_id());
		}
		if (!boundary_ids.insert(boundary.boundary_id()).second || !actual_endpoint_keys.insert(key).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "boundaries[] contains duplicate identity or endpoints", boundary.boundary_id());
		}
		const auto expected_id = topology_ids::make_boundary_id(key.first, key.second);
		const auto &expected = expected_it->second;
		if (boundary.boundary_id() != expected_id ||
		    boundary.sender_worker_id() != out.workers[expected.sender_worker_index].worker_id ||
		    boundary.receiver_worker_id() != out.workers[expected.receiver_worker_index].worker_id) {
			return status(status_code::INVALID_ARGUMENT,
				      "boundary '" + boundary.boundary_id() +
					      " disagrees with deterministic endpoint or worker ownership",
				      boundary.boundary_id());
		}
		if (!is_spsc_capacity(boundary.data_ring_capacity()) ||
		    !is_spsc_capacity(boundary.future_output_hold_capacity())) {
			return status(status_code::INVALID_ARGUMENT,
				      "boundary '" + boundary.boundary_id() +
					      " capacities must be powers of two with at least two slots",
				      boundary.boundary_id());
		}
		if (boundary.data_ring_numa_node() != expected.receiver_numa_node) {
			return status(status_code::INVALID_ARGUMENT,
				      "boundary '" + boundary.boundary_id() +
					      " DATA NUMA node does not match receiver ownership",
				      boundary.boundary_id());
		}

		const uint32_t boundary_index = static_cast<uint32_t>(out.boundaries.size());
		out.boundaries.push_back(compiled_transition_boundary{
			boundary.boundary_id(), boundary_index, expected.from_stage_instance_index,
			expected.to_stage_instance_index, expected.sender_worker_index, expected.receiver_worker_index,
			boundary.data_ring_capacity(), boundary.future_output_hold_capacity(),
			boundary.data_ring_numa_node()});
		out.workers[expected.sender_worker_index].outbound_boundary_indices.push_back(boundary_index);
		out.workers[expected.receiver_worker_index].inbound_boundary_indices.push_back(boundary_index);
		out.boundaries_by_source_stage_instance[expected.from_stage_instance_index].push_back(
			compiled_transition_edge{expected.to_stage_instance_index, boundary_index});
	}
	if (actual_endpoint_keys.size() != expected_boundaries.size()) {
		for (const auto &[key, expected] : expected_boundaries) {
			(void)expected;
			if (!actual_endpoint_keys.contains(key)) {
				return status(status_code::INVALID_ARGUMENT, "boundaries[] missing executable edge '" +
										     key.first + "' -> '" + key.second +
										     "'");
			}
		}
	}

	std::optional<uint32_t> coordinator_service_index;
	std::map<int32_t, uint32_t> executor_service_by_numa;
	std::optional<int32_t> previous_executor_numa;
	out.runtime_services.reserve(static_cast<std::size_t>(plan.runtime_service_placements_size()));
	std::unordered_set<std::string> runtime_service_ids;
	for (int i = 0; i < plan.runtime_service_placements_size(); ++i) {
		const auto &service = plan.runtime_service_placements(i);
		if (service.service_id().empty() || service.cpu_core_id() < 0 || service.numa_node() < 0 ||
		    !runtime_service_ids.insert(service.service_id()).second ||
		    !owned_cpu_cores.insert(service.cpu_core_id()).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "runtime services require unique identity, CPU, and nonnegative NUMA ownership",
				      service.service_id());
		}

		compiled_runtime_service_role role{};
		switch (service.service_kind()) {
		case kinetum::gluon::v1::RUNTIME_SERVICE_KIND_EPOCH_TRANSITION_COORDINATOR:
			role = compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR;
			if (service.service_id() != service_ids::EPOCH_TRANSITION_COORDINATOR_ID ||
			    coordinator_service_index.has_value() || i != 0) {
				return status(status_code::INVALID_ARGUMENT,
					      "runtime service coordinator identity or order is invalid",
					      service.service_id());
			}
			if (service.command_mailbox_capacity() < MIN_COORDINATOR_COMMAND_MAILBOX_CAPACITY ||
			    service.command_mailbox_capacity() > MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY) {
				return status(status_code::OUT_OF_RANGE,
					      "runtime service coordinator command-mailbox capacity is outside 2..64",
					      service.service_id());
			}
			if (!is_nonzero_power_of_two(service.command_mailbox_capacity())) {
				return status::invalid_argument(
					"runtime service coordinator command-mailbox capacity must be a power of two");
			}
			coordinator_service_index = static_cast<uint32_t>(i);
			break;
		case kinetum::gluon::v1::RUNTIME_SERVICE_KIND_CONFIG_LIFECYCLE_EXECUTOR: {
			role = compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR;
			const auto expected_id = service_ids::make_lifecycle_executor_id(service.numa_node());
			if (service.service_id() != expected_id || service.command_mailbox_capacity() != 0u ||
			    !executor_service_by_numa.emplace(service.numa_node(), static_cast<uint32_t>(i)).second ||
			    (previous_executor_numa.has_value() &&
			     previous_executor_numa.value() >= service.numa_node())) {
				return status(
					status_code::INVALID_ARGUMENT,
					"runtime lifecycle executors have invalid identity, mailbox ownership, NUMA cardinality, or order",
					service.service_id());
			}
			previous_executor_numa = service.numa_node();
			break;
		}
		case kinetum::gluon::v1::RUNTIME_SERVICE_KIND_UNSPECIFIED:
		case kinetum::gluon::v1::RuntimeServiceKind_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::gluon::v1::RuntimeServiceKind_INT_MAX_SENTINEL_DO_NOT_USE_:
			return status(status_code::INVALID_ARGUMENT, "runtime service has unsupported service_kind",
				      service.service_id());
		}
		out.runtime_services.push_back(compiled_runtime_service{
			service.service_id(), static_cast<uint32_t>(i), role, service.cpu_core_id(),
			service.numa_node(), service.command_mailbox_capacity()});
	}

	out.policy.enabled = plan.has_epoch_transition_plan();
	// Service placement is permanent execution topology, not transition policy.
	// Fixed-epoch bootstrap executes module lifecycle work through the same exact
	// coordinator/executor shape used by later live transitions, so every worker
	// topology requires the complete service set before materialization.
	std::vector<int32_t> required_executor_numa;
	if (out.workers.empty() && !out.runtime_services.empty()) {
		return status(status_code::INVALID_ARGUMENT,
			      "runtime service placements require an executable worker topology");
	}
	if (!out.workers.empty()) {
		if (!coordinator_service_index.has_value()) {
			return status(status_code::INVALID_ARGUMENT,
				      "lifecycle service topology requires exactly one canonical coordinator service");
		}

		required_executor_numa = out.module_context_numa_nodes;
		if (required_executor_numa.empty()) {
			if (regions_by_id.empty()) {
				return status(
					status_code::INVALID_ARGUMENT,
					"module-free lifecycle service topology has no region for NUMA ownership");
			}
			int32_t lowest_numa = std::numeric_limits<int32_t>::max();
			for (const auto &[region_id, region] : regions_by_id) {
				(void)region_id;
				lowest_numa = std::min(lowest_numa, region->numa_node());
			}
			required_executor_numa.push_back(lowest_numa);
		}
		if (executor_service_by_numa.size() != required_executor_numa.size() ||
		    out.runtime_services.size() != required_executor_numa.size() + 1u) {
			return status(status_code::INVALID_ARGUMENT,
				      "runtime lifecycle executors do not exactly cover module-context NUMA nodes");
		}

		compiled_lifecycle_service_topology services;
		services.coordinator_service_index = coordinator_service_index.value();
		services.lifecycle_executor_service_indices.reserve(required_executor_numa.size());
		for (const int32_t numa_node : required_executor_numa) {
			const auto executor_it = executor_service_by_numa.find(numa_node);
			if (executor_it == executor_service_by_numa.end()) {
				return status(status_code::INVALID_ARGUMENT,
					      "missing config lifecycle executor for NUMA node " +
						      std::to_string(numa_node));
			}
			services.lifecycle_executor_service_indices.push_back(executor_it->second);
		}
		out.lifecycle_services.emplace(std::move(services));
	}
	for (const auto &plan_worker : plan.worker_placements()) {
		auto poll_or = compile_milliseconds(plan_worker.module_health_poll_interval_ms(),
						    "module_health_poll_interval_ms");
		auto budget_or = compile_nanoseconds(plan_worker.module_health_callback_budget_ns(),
						     "module_health_callback_budget_ns");
		if (!poll_or.is_ok()) {
			return poll_or.error();
		}
		if (!budget_or.is_ok()) {
			return budget_or.error();
		}
		if (budget_or.value() >= poll_or.value()) {
			return status(status_code::INVALID_ARGUMENT,
				      "module health callback budget must be shorter than its poll interval",
				      plan_worker.worker_id());
		}
		auto &compiled_worker = out.workers[plan_worker.worker_index()];
		compiled_worker.health_poll_interval = poll_or.value();
		compiled_worker.health_callback_budget = budget_or.value();
	}
	if (!out.policy.enabled) {
		for (const auto &worker : plan.worker_placements()) {
			if (worker.source_epoch_staging_capacity() != 0) {
				return status(status_code::INVALID_ARGUMENT,
					      "fixed-epoch worker carries source_epoch_staging_capacity",
					      worker.worker_id());
			}
		}
	} else {
		if (out.workers.empty() || plan.stage_instances_size() == 0) {
			return status(status_code::INVALID_ARGUMENT,
				      "epoch_transition_plan requires explicit workers and stage instances");
		}
		for (const auto &worker : out.workers) {
			if (!worker.is_source && worker.source_epoch_staging_capacity != 0) {
				return status(status_code::INVALID_ARGUMENT,
					      "non-source worker '" + worker.worker_id +
						      " must not allocate source_epoch_staging_capacity",
					      worker.worker_id);
			}
			if (worker.is_source && !is_spsc_capacity(worker.source_epoch_staging_capacity)) {
				return status(
					status_code::INVALID_ARGUMENT,
					"source worker '" + worker.worker_id +
						" requires source_epoch_staging_capacity to be a power of two with at least two slots",
					worker.worker_id);
			}
		}
		if (out.source_worker_indices.empty() || out.sink_worker_indices.empty()) {
			return status(status_code::INVALID_ARGUMENT,
				      "epoch_transition_plan requires packet-originating sources and TX sinks");
		}

		if (const auto dag_status = validate_worker_dag(out); !dag_status.is_ok()) {
			return dag_status;
		}

		const auto &policy = plan.epoch_transition_plan();
		const auto &services = out.lifecycle_services.value();
		if (policy.coordinator_service_id() !=
		    out.runtime_services[services.coordinator_service_index].service_id) {
			return status(
				status_code::INVALID_ARGUMENT,
				"epoch_transition_plan coordinator_service_id does not name the canonical coordinator");
		}
		if (policy.lifecycle_executor_service_ids_size() != static_cast<int>(required_executor_numa.size())) {
			return status(status_code::INVALID_ARGUMENT,
				      "epoch_transition_plan lifecycle executor list has incomplete NUMA coverage");
		}
		for (std::size_t i = 0; i < required_executor_numa.size(); ++i) {
			const uint32_t service_index = services.lifecycle_executor_service_indices[i];
			if (policy.lifecycle_executor_service_ids(static_cast<int>(i)) !=
			    out.runtime_services[service_index].service_id) {
				return status(
					status_code::INVALID_ARGUMENT,
					"epoch_transition_plan lifecycle executor list is not the exact canonical NUMA set");
			}
		}

		auto prepare_or = compile_milliseconds(policy.prepare_timeout_ms(), "prepare_timeout_ms");
		auto cancel_or = compile_milliseconds(policy.prepare_cancel_grace_ms(), "prepare_cancel_grace_ms");
		auto lease_or = compile_milliseconds(policy.prepared_lease_timeout_ms(), "prepared_lease_timeout_ms");
		auto commit_or = compile_milliseconds(policy.commit_timeout_ms(), "commit_timeout_ms");
		auto retirement_or = compile_milliseconds(policy.retirement_timeout_ms(), "retirement_timeout_ms");
		for (const auto *result : {&prepare_or, &cancel_or, &lease_or, &commit_or, &retirement_or}) {
			if (!result->is_ok()) {
				return result->error();
			}
		}
		// The abortable cancellation grace cannot dominate preparation. The
		// prepared lease must cover both the admitted prepare and commit budgets,
		// and retirement cannot be shorter than completion-only commit. These
		// relations make the plan a coherent policy rather than five unrelated
		// representable integers.
		if (cancel_or.value() > prepare_or.value()) {
			return status(status_code::INVALID_ARGUMENT,
				      "prepare_cancel_grace_ms must not exceed prepare_timeout_ms");
		}
		if (lease_or.value() < prepare_or.value() || lease_or.value() < commit_or.value()) {
			return status(status_code::INVALID_ARGUMENT,
				      "prepared_lease_timeout_ms must cover prepare and commit timeout budgets");
		}
		if (retirement_or.value() < commit_or.value()) {
			return status(status_code::INVALID_ARGUMENT,
				      "retirement_timeout_ms must not be shorter than commit_timeout_ms");
		}
		if (policy.result_history_capacity() < MIN_TRANSITION_RESULT_HISTORY_CAPACITY ||
		    policy.result_history_capacity() > MAX_TRANSITION_RESULT_HISTORY_CAPACITY) {
			return status(status_code::OUT_OF_RANGE,
				      "result_history_capacity must be in the closed range 1..64");
		}
		out.policy.prepare_timeout = prepare_or.value();
		out.policy.prepare_cancel_grace = cancel_or.value();
		out.policy.prepared_lease_timeout = lease_or.value();
		out.policy.commit_timeout = commit_or.value();
		out.policy.retirement_timeout = retirement_or.value();
		out.policy.result_history_capacity = policy.result_history_capacity();
	}

	return out;
}

}  // namespace kinetum::common
