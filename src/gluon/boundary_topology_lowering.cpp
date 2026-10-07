// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file boundary_topology_lowering.cpp
 * @brief Deterministic executable-boundary topology lowering.
 * @author Fleming Patel
 */

#include "src/gluon/boundary_topology_lowering.hpp"

#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <google/protobuf/repeated_field.h>

#include "src/common/execution_topology_ids.hpp"
#include "src/common/runtime_sizing.hpp"

namespace kinetum::gluon
{

using kinetum::common::status;
using kinetum::common::status_code;

namespace
{

/**
 * @brief Stable semantic key for one executable stage instance.
 *
 * Protobuf construction order is not an ownership authority. Pairing the
 * authored logical stage with its canonical lane gives the lowering pass an
 * order-independent lookup for each exact executable endpoint.
 */
struct stage_lane_key {
	/** @brief Authored logical stage identity. */
	std::string logical_stage_id;

	/** @brief Resolved execution-lane identity. */
	std::string lane_id;

	/**
	 * @brief Order keys independently of protobuf construction order.
	 *
	 * @param other Key to compare.
	 * @return true when this key precedes other lexicographically.
	 */
	[[nodiscard]] bool operator<(const stage_lane_key &other) const noexcept
	{
		return std::tie(logical_stage_id, lane_id) < std::tie(other.logical_stage_id, other.lane_id);
	}
};

/**
 * @brief Stable semantic key for one runtime worker owner.
 *
 * A region may contain multiple lane-local workers. The pair is therefore the
 * minimum complete ownership key; region identity alone would recreate the
 * ambiguous logical-region mapping this pass is designed to remove.
 */
struct worker_owner_key {
	/** @brief Logical region containing the worker. */
	int32_t region_id{0};

	/** @brief Execution lane owned by the worker. */
	std::string lane_id;

	/**
	 * @brief Order worker-owner keys deterministically.
	 *
	 * @param other Key to compare.
	 * @return true when this key precedes other.
	 */
	[[nodiscard]] bool operator<(const worker_owner_key &other) const noexcept
	{
		return std::tie(region_id, lane_id) < std::tie(other.region_id, other.lane_id);
	}
};

/**
 * @brief Resolved immutable ownership facts for one executable endpoint.
 *
 * Boundary emission uses these prevalidated pointers only during the cold
 * lowering pass. The NUMA value follows the owning region and is copied into a
 * receiver-side DATA-ring placement when this endpoint is the consumer.
 */
struct stage_owner {
	/** @brief Exact executable endpoint. */
	const kinetum::gluon::v1::StageInstance *instance{nullptr};

	/** @brief Sole runtime worker owner. */
	const kinetum::gluon::v1::WorkerPlacement *worker{nullptr};

	/** @brief Owner region's resolved NUMA node. */
	int32_t numa_node{-1};
};

/**
 * @brief Validate one canonical topology atom.
 *
 * @param value Candidate atom.
 * @param field Human-readable field name for diagnostics.
 * @return OK when value excludes every generated-ID delimiter.
 */
[[nodiscard]] status validate_topology_atom(std::string_view value, std::string_view field)
{
	if (kinetum::common::execution_topology::is_topology_identifier(value)) {
		return status::ok();
	}
	return status(status_code::INVALID_ARGUMENT,
		      std::string(field) + " '" + std::string(value) +
			      "' must match [A-Za-z_][A-Za-z0-9_]* for generated topology IDs");
}

}  // namespace

status lower_boundary_topology(kinetum::gluon::v1::DeploymentPlan &plan)
{
	namespace topo = kinetum::common::execution_topology;
	namespace sizing = kinetum::common::runtime_sizing;

	if (plan.boundaries_size() != 0) {
		return status(
			status_code::INVALID_ARGUMENT,
			"boundary topology lowering requires empty boundaries[]; prepopulated output has no owner");
	}

	std::map<int32_t, const kinetum::gluon::v1::Region *> regions_by_id;
	for (const auto &region : plan.regions()) {
		if (region.region_id() < 0) {
			return status(status_code::INVALID_ARGUMENT, "boundary topology contains negative region_id " +
									     std::to_string(region.region_id()));
		}
		if (region.numa_node() < 0) {
			return status(status_code::INVALID_ARGUMENT,
				      "region " + std::to_string(region.region_id()) +
					      " has no resolved NUMA node for boundary placement");
		}
		if (!regions_by_id.emplace(region.region_id(), &region).second) {
			return status(status_code::INVALID_ARGUMENT, "duplicate region_id in boundary topology: " +
									     std::to_string(region.region_id()));
		}
	}

	std::set<std::string> lane_ids;
	for (const auto &lane : plan.execution_lanes()) {
		if (const auto st = validate_topology_atom(lane.lane_id(), "execution lane ID"); !st.is_ok()) {
			return st;
		}
		if (!lane_ids.insert(lane.lane_id()).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "duplicate execution lane ID in boundary topology: '" + lane.lane_id() + "'");
		}
	}

	std::map<std::string, const kinetum::axiom::v1::Stage *> logical_stages;
	for (const auto &stage : plan.pipeline().stages()) {
		if (const auto st = validate_topology_atom(stage.stage_id(), "logical stage ID"); !st.is_ok()) {
			return st;
		}
		if (!logical_stages.emplace(stage.stage_id(), &stage).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "duplicate logical stage ID in boundary topology: '" + stage.stage_id() + "'");
		}
	}

	std::map<worker_owner_key, const kinetum::gluon::v1::WorkerPlacement *> workers_by_owner;
	std::set<std::string> worker_ids;
	for (const auto &worker : plan.worker_placements()) {
		if (!regions_by_id.contains(worker.region_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker placement '" + worker.worker_id() + "' references unknown region " +
					      std::to_string(worker.region_id()),
				      worker.worker_id());
		}
		if (const auto st = validate_topology_atom(worker.lane_id(), "worker lane ID"); !st.is_ok()) {
			return st;
		}
		if (!lane_ids.contains(worker.lane_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker placement '" + worker.worker_id() + "' references unknown lane '" +
					      worker.lane_id() + "'",
				      worker.worker_id());
		}
		const auto expected_worker_id = topo::make_worker_id(worker.region_id(), worker.lane_id());
		if (worker.worker_id() != expected_worker_id) {
			return status(status_code::INVALID_ARGUMENT,
				      "worker placement '" + worker.worker_id() +
					      "' does not match deterministic owner ID '" + expected_worker_id + "'",
				      worker.worker_id());
		}
		if (!worker_ids.insert(worker.worker_id()).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "duplicate worker ID in boundary topology: '" + worker.worker_id() + "'",
				      worker.worker_id());
		}
		if (!workers_by_owner.emplace(worker_owner_key{worker.region_id(), worker.lane_id()}, &worker).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "multiple workers own region " + std::to_string(worker.region_id()) + " lane '" +
					      worker.lane_id() + "'",
				      worker.worker_id());
		}
	}

	std::map<stage_lane_key, stage_owner> stages_by_lane;
	std::map<std::string, std::set<std::string>> lanes_by_logical_stage;
	std::set<std::string> stage_instance_ids;
	for (const auto &instance : plan.stage_instances()) {
		if (!logical_stages.contains(instance.logical_stage_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage instance '" + instance.stage_instance_id() +
					      "' references unknown logical stage '" + instance.logical_stage_id() +
					      "'",
				      instance.stage_instance_id());
		}
		if (const auto st = validate_topology_atom(instance.logical_stage_id(), "logical stage ID");
		    !st.is_ok()) {
			return st;
		}
		if (const auto st = validate_topology_atom(instance.lane_id(), "stage-instance lane ID"); !st.is_ok()) {
			return st;
		}
		if (!lane_ids.contains(instance.lane_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage instance '" + instance.stage_instance_id() +
					      "' references unknown lane '" + instance.lane_id() + "'",
				      instance.stage_instance_id());
		}
		const auto expected_instance_id =
			topo::make_stage_instance_id(instance.logical_stage_id(), instance.lane_id());
		if (instance.stage_instance_id() != expected_instance_id) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage instance '" + instance.stage_instance_id() +
					      "' does not match deterministic ID '" + expected_instance_id + "'",
				      instance.stage_instance_id());
		}
		if (!stage_instance_ids.insert(instance.stage_instance_id()).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "duplicate stage-instance ID in boundary topology: '" +
					      instance.stage_instance_id() + "'",
				      instance.stage_instance_id());
		}
		const auto region_it = regions_by_id.find(instance.region_id());
		if (region_it == regions_by_id.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage instance '" + instance.stage_instance_id() +
					      "' references unknown region " + std::to_string(instance.region_id()),
				      instance.stage_instance_id());
		}
		const auto worker_it =
			workers_by_owner.find(worker_owner_key{instance.region_id(), instance.lane_id()});
		if (worker_it == workers_by_owner.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      "stage instance '" + instance.stage_instance_id() +
					      "' has no exact runtime worker owner",
				      instance.stage_instance_id());
		}
		if (!stages_by_lane
			     .emplace(stage_lane_key{instance.logical_stage_id(), instance.lane_id()},
				      stage_owner{&instance, worker_it->second, region_it->second->numa_node()})
			     .second) {
			return status(status_code::INVALID_ARGUMENT,
				      "multiple stage instances own logical stage '" + instance.logical_stage_id() +
					      "' on lane '" + instance.lane_id() + "'",
				      instance.stage_instance_id());
		}
		lanes_by_logical_stage[instance.logical_stage_id()].insert(instance.lane_id());
	}

	using endpoint_key = std::pair<std::string, std::string>;
	std::map<endpoint_key, kinetum::gluon::v1::BoundaryPlacement> boundaries_by_endpoint;
	for (const auto &edge : plan.pipeline().edges()) {
		if (!logical_stages.contains(edge.from_stage_id()) || !logical_stages.contains(edge.to_stage_id())) {
			return status(status_code::INVALID_ARGUMENT,
				      "pipeline edge references an unknown logical stage during boundary lowering");
		}

		const auto source_lanes_it = lanes_by_logical_stage.find(edge.from_stage_id());
		const auto destination_lanes_it = lanes_by_logical_stage.find(edge.to_stage_id());
		if (source_lanes_it == lanes_by_logical_stage.end() || source_lanes_it->second.empty() ||
		    destination_lanes_it == lanes_by_logical_stage.end() || destination_lanes_it->second.empty()) {
			return status(status_code::INVALID_ARGUMENT, "executable edge '" + edge.from_stage_id() +
									     "' -> '" + edge.to_stage_id() +
									     "' is missing stage-instance coverage");
		}
		const auto &source_lanes = source_lanes_it->second;
		const auto &destination_lanes = destination_lanes_it->second;
		if (source_lanes != destination_lanes) {
			return status(status_code::INVALID_ARGUMENT,
				      "executable edge '" + edge.from_stage_id() + "' -> '" + edge.to_stage_id() +
					      "' has incomplete lane-local stage-instance coverage");
		}

		const auto &target_stage = *logical_stages.at(edge.to_stage_id());
		const bool selects_context = edge.mode() == kinetum::axiom::v1::EDGE_MODE_PUSH &&
					     target_stage.has_module() &&
					     target_stage.module().context_selection() ==
						     kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_MODULE;
		for (const auto &lane_id : source_lanes) {
			const auto source_it = stages_by_lane.find(stage_lane_key{edge.from_stage_id(), lane_id});
			if (source_it == stages_by_lane.end()) {
				return status(status_code::INTERNAL_ERROR,
					      "lane coverage changed during executable boundary lowering");
			}
			const auto &source = source_it->second;
			/** @brief Emit one exact candidate crossing without changing logical-edge multiplicity. */
			const auto emit_destination = [&](const std::string &destination_lane) -> status {
				const auto destination_it =
					stages_by_lane.find(stage_lane_key{edge.to_stage_id(), destination_lane});
				if (destination_it == stages_by_lane.end()) {
					return status::internal_error(
						"destination lane coverage changed during boundary lowering");
				}
				const auto &destination = destination_it->second;
				if (source.worker->worker_id() == destination.worker->worker_id()) {
					return status::ok();
				}

				const endpoint_key endpoints{source.instance->stage_instance_id(),
							     destination.instance->stage_instance_id()};
				auto [boundary_it, inserted] = boundaries_by_endpoint.try_emplace(endpoints);
				if (!inserted) {
					const auto &existing = boundary_it->second;
					if (existing.sender_worker_id() != source.worker->worker_id() ||
					    existing.receiver_worker_id() != destination.worker->worker_id()) {
						return status(
							status_code::INVALID_ARGUMENT,
							"duplicate executable endpoint pair resolves to different worker owners");
					}
					return status::ok();
				}
				if (boundaries_by_endpoint.size() >
				    static_cast<std::size_t>(std::numeric_limits<int>::max())) {
					return status(status_code::OUT_OF_RANGE,
						      "expanded boundaries exceed protobuf cardinality");
				}

				auto &boundary = boundary_it->second;
				boundary.set_boundary_id(topo::make_boundary_id(endpoints.first, endpoints.second));
				boundary.set_from_stage_instance_id(endpoints.first);
				boundary.set_to_stage_instance_id(endpoints.second);
				boundary.set_sender_worker_id(source.worker->worker_id());
				boundary.set_receiver_worker_id(destination.worker->worker_id());
				boundary.set_data_ring_capacity(
					static_cast<uint32_t>(sizing::INTER_REGION_DATA_RING_CAPACITY));
				boundary.set_future_output_hold_capacity(
					static_cast<uint32_t>(sizing::BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY));
				// DATA-ring memory is receiver-local because drain-through-cut and
				// downstream admission are the ordered handoff's load-bearing side.
				boundary.set_data_ring_numa_node(destination.numa_node);
				return status::ok();
			};
			if (selects_context) {
				for (const auto &destination_lane : destination_lanes) {
					if (auto result = emit_destination(destination_lane); !result.is_ok()) {
						return result;
					}
				}
			} else if (auto result = emit_destination(lane_id); !result.is_ok()) {
				return result;
			}
		}
	}

	google::protobuf::RepeatedPtrField<kinetum::gluon::v1::BoundaryPlacement> emitted;
	emitted.Reserve(static_cast<int>(boundaries_by_endpoint.size()));
	for (const auto &[endpoints, boundary] : boundaries_by_endpoint) {
		(void)endpoints;
		*emitted.Add() = boundary;
	}
	plan.mutable_boundaries()->Swap(&emitted);
	return status::ok();
}

}  // namespace kinetum::gluon
