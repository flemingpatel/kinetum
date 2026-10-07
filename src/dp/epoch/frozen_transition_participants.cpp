// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file frozen_transition_participants.cpp
 * @brief Immutable transition-participant projection implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/frozen_transition_participants.hpp"

#include <algorithm>
#include <cstddef>
#include <exception>
#include <iterator>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "src/common/canonical_content_identity.hpp"
#include "src/common/status.hpp"
#include "src/common/transition_topology.hpp"
#include "src/provider/compiled_provider_topology.hpp"

namespace kinetum::dp
{
namespace
{

using kinetum::common::static_status_text;
using kinetum::common::status;
using kinetum::common::status_code;

/**
 * @brief Require one host count to fit every compact participant field.
 *
 * @param count Candidate host container size.
 * @param role Stable diagnostic role.
 * @return Compact count, or OUT_OF_RANGE.
 */
[[nodiscard]] common::status_or<uint32_t> compact_count(std::size_t count, const char *role)
{
	if (count > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
		return status(status_code::OUT_OF_RANGE, std::string(role) + " exceeds compact participant range");
	}
	return static_cast<uint32_t>(count);
}

/**
 * @brief Require one compact index vector to be strictly sorted and owner-exact.
 *
 * @tparam owner_function Callable returning the compiled owner for one index.
 * @param input Candidate owner-local index set.
 * @param expected_owner Required owner identity.
 * @param seen Complete category-wide consumption ledger, sized once from the
 *             compiled universe; its extent is the exclusive index bound.
 * @param output Flat immutable destination.
 * @param role Stable diagnostic role.
 * @param owner_of Callable mapping an index to its compiled owner.
 * @return Exact flat range, or the first ownership error.
 */
template <typename owner_function>
[[nodiscard]] common::status_or<frozen_index_range>
append_owned_indices(const std::vector<uint32_t> &input, uint32_t expected_owner, std::vector<uint8_t> &seen,
		     std::vector<uint32_t> &output, const char *role, owner_function owner_of)
{
	const std::size_t limit = seen.size();
	auto offset_or = compact_count(output.size(), role);
	if (!offset_or.is_ok()) {
		return offset_or.error();
	}
	std::optional<uint32_t> previous;
	for (const uint32_t index : input) {
		if (index >= limit || (previous.has_value() && previous.value() >= index) || seen[index] != 0u ||
		    owner_of(index) != expected_owner) {
			return status::invalid_argument(
				std::string(role) + " membership is noncompact, duplicate, unsorted, or cross-owned");
		}
		seen[index] = 1u;
		output.push_back(index);
		previous = index;
	}
	auto count_or = compact_count(input.size(), role);
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	return frozen_index_range{offset_or.value(), count_or.value()};
}

/**
 * @brief Require complete one-time consumption of a compact category.
 *
 * @param seen Category-wide consumption ledger.
 * @param role Stable diagnostic role.
 * @return OK only when every compact identity was consumed exactly once.
 */
[[nodiscard]] status require_complete(const std::vector<uint8_t> &seen, const char *role)
{
	if (std::any_of(seen.begin(), seen.end(), [](uint8_t value) { return value != 1u; })) {
		return status::invalid_argument(std::string(role) + " membership is incomplete");
	}
	return status::ok();
}

/**
 * @brief Require one sorted worker-index set to equal compiled flags.
 *
 * @param indices Candidate source or sink indices.
 * @param workers Complete compact worker vector.
 * @param source True for source flags, false for sink flags.
 * @return OK for exact two-directional membership.
 */
[[nodiscard]] status validate_worker_role_indices(const std::vector<uint32_t> &indices,
						  const std::vector<common::compiled_transition_worker> &workers,
						  bool source)
{
	std::vector<uint8_t> seen(workers.size(), 0u);
	std::optional<uint32_t> previous;
	for (const uint32_t index : indices) {
		if (index >= workers.size() || (previous.has_value() && previous.value() >= index) ||
		    seen[index] != 0u || (source ? !workers[index].is_source : !workers[index].is_sink)) {
			return status::invalid_argument(
				source ? static_status_text("source participant membership is not exact") :
					 static_status_text("sink participant membership is not exact"));
		}
		seen[index] = 1u;
		previous = index;
	}
	for (std::size_t index = 0; index < workers.size(); ++index) {
		const bool expected = source ? workers[index].is_source : workers[index].is_sink;
		if ((seen[index] != 0u) != expected) {
			return status::invalid_argument(
				source ? static_status_text("source participant membership is incomplete") :
					 static_status_text("sink participant membership is incomplete"));
		}
	}
	return status::ok();
}

/**
 * @brief Require the redundant lane tables to equal exact stage/stream facts.
 *
 * @param topology Complete compiled provider topology.
 * @return OK only when every lane, logical-stage position, stage instance, and
 *         I/O stream is consumed exactly once with matching compact identity.
 */
[[nodiscard]] status validate_execution_lane_membership(const provider::compiled_provider_topology &topology)
{
	if (topology.execution_lanes.empty()) {
		return status::invalid_argument(
			static_status_text("frozen participant set requires a nonempty execution-lane set"));
	}
	std::vector<uint8_t> logical_stage_seen(topology.stage_instances.size(), 0u);
	for (std::size_t index = 0; index < topology.logical_stages.size(); ++index) {
		const auto &logical = topology.logical_stages[index];
		if (logical.logical_stage_index != index) {
			return status::invalid_argument(static_status_text("logical-stage identity is not compact"));
		}
		std::optional<uint32_t> previous_stage;
		for (const uint32_t stage_index : logical.stage_instance_indices) {
			if (stage_index >= topology.stage_instances.size() || logical_stage_seen[stage_index] != 0u ||
			    (previous_stage.has_value() && previous_stage.value() >= stage_index) ||
			    topology.stage_instances[stage_index].logical_stage_index != index) {
				return status::invalid_argument(static_status_text(
					"logical-stage membership is duplicate, unsorted, incomplete, or cross-owned"));
			}
			logical_stage_seen[stage_index] = 1u;
			previous_stage = stage_index;
		}
	}
	if (const auto complete = require_complete(logical_stage_seen, "logical-stage instance"); !complete.is_ok()) {
		return complete;
	}

	std::vector<uint8_t> stage_seen(topology.stage_instances.size(), 0u);
	std::vector<uint8_t> stream_seen(topology.io_streams.size(), 0u);
	for (std::size_t lane_index = 0; lane_index < topology.execution_lanes.size(); ++lane_index) {
		const auto &lane = topology.execution_lanes[lane_index];
		if (lane.lane_index != lane_index || lane.lane_id.empty() ||
		    lane.stage_instance_indices.size() != topology.logical_stages.size()) {
			return status::invalid_argument(
				static_status_text("execution-lane identity or logical-stage table is not exact"));
		}
		for (std::size_t logical_index = 0; logical_index < lane.stage_instance_indices.size();
		     ++logical_index) {
			const uint32_t stage_index = lane.stage_instance_indices[logical_index];
			if (stage_index == provider::INVALID_COMPILED_STAGE_INSTANCE_INDEX ||
			    stage_index >= topology.stage_instances.size() || stage_seen[stage_index] != 0u) {
				return status::invalid_argument(static_status_text(
					"execution-lane stage membership is missing, duplicate, or out of range"));
			}
			const auto &stage = topology.stage_instances[stage_index];
			if (stage.stage_instance_index != stage_index || stage.logical_stage_index != logical_index ||
			    stage.lane_index != lane_index) {
				return status::invalid_argument(static_status_text(
					"execution-lane stage membership disagrees with exact stage identity"));
			}
			stage_seen[stage_index] = 1u;
		}

		std::optional<uint32_t> previous_stream;
		for (const uint32_t stream_index : lane.io_stream_indices) {
			if (stream_index >= topology.io_streams.size() || stream_seen[stream_index] != 0u ||
			    (previous_stream.has_value() && previous_stream.value() >= stream_index)) {
				return status::invalid_argument(static_status_text(
					"execution-lane I/O-stream membership is duplicate, unsorted, or out of range"));
			}
			const auto &stream = topology.io_streams[stream_index];
			if (stream.io_stream_index != stream_index || stream.lane_index != lane_index) {
				return status::invalid_argument(static_status_text(
					"execution-lane I/O-stream membership disagrees with exact stream identity"));
			}
			stream_seen[stream_index] = 1u;
			previous_stream = stream_index;
		}
	}
	if (const auto complete = require_complete(stage_seen, "execution-lane stage"); !complete.is_ok()) {
		return complete;
	}
	return require_complete(stream_seen, "execution-lane I/O stream");
}

}  // namespace

common::status_or<std::unique_ptr<const frozen_transition_participants>>
frozen_transition_participants::create(const provider::compiled_provider_topology &topology)
{
	try {
		const auto hash_status = common::validate_sha256_hex_claim(topology.source_plan_content_hash,
									   "DeploymentPlan.content_hash");
		if (!hash_status.is_ok()) {
			return hash_status;
		}

		const auto &transition = topology.transition_topology;
		const auto worker_count_or = compact_count(transition.workers.size(), "execution participant count");
		const auto logical_count_or = compact_count(topology.logical_stages.size(), "logical-stage count");
		const auto lane_count_or = compact_count(topology.execution_lanes.size(), "execution-lane count");
		const auto region_count_or = compact_count(topology.execution_regions.size(), "region count");
		const auto stage_count_or = compact_count(topology.stage_instances.size(), "stage-instance count");
		const auto stream_count_or = compact_count(topology.io_streams.size(), "I/O-stream count");
		const auto boundary_count_or = compact_count(transition.boundaries.size(), "boundary count");
		const auto context_count_or = compact_count(topology.module_contexts.size(), "module context count");
		if (!worker_count_or.is_ok()) {
			return worker_count_or.error();
		}
		if (!logical_count_or.is_ok()) {
			return logical_count_or.error();
		}
		if (!lane_count_or.is_ok()) {
			return lane_count_or.error();
		}
		if (!region_count_or.is_ok()) {
			return region_count_or.error();
		}
		if (topology.execution_regions.size() > static_cast<std::size_t>(std::numeric_limits<int32_t>::max())) {
			return status(status_code::OUT_OF_RANGE,
				      static_status_text("region count exceeds signed compact identity range"));
		}
		if (!stage_count_or.is_ok()) {
			return stage_count_or.error();
		}
		if (!stream_count_or.is_ok()) {
			return stream_count_or.error();
		}
		if (!boundary_count_or.is_ok()) {
			return boundary_count_or.error();
		}
		if (!context_count_or.is_ok()) {
			return context_count_or.error();
		}
		if (transition.workers.empty() || topology.logical_stages.empty() || topology.stage_instances.empty() ||
		    topology.worker_schedules.size() != transition.workers.size()) {
			return status::invalid_argument(static_status_text(
				"frozen participant set requires nonempty stages and one exact worker schedule set"));
		}
		if (const auto lanes = validate_execution_lane_membership(topology); !lanes.is_ok()) {
			return lanes;
		}
		for (std::size_t index = 0; index < transition.workers.size(); ++index) {
			const auto &worker = transition.workers[index];
			if (worker.worker_index != index || worker.region_id < 0 ||
			    static_cast<std::size_t>(worker.region_id) >= topology.execution_regions.size() ||
			    worker.lane_index >= topology.execution_lanes.size() || worker.cpu_core_ids.size() != 1u ||
			    worker.cpu_core_ids.front() < 0 || worker.numa_node < 0 ||
			    worker.lane_id != topology.execution_lanes[worker.lane_index].lane_id ||
			    worker.numa_node !=
				    topology.execution_regions[static_cast<std::size_t>(worker.region_id)].numa_node) {
				return status::invalid_argument(static_status_text(
					"execution participant identity or placement is not compact and exact"));
			}
		}

		std::vector<std::vector<uint32_t>> contexts_by_worker(transition.workers.size());
		std::vector<uint8_t> context_seen(topology.module_contexts.size(), 0u);
		for (std::size_t index = 0; index < topology.module_contexts.size(); ++index) {
			const auto &context = topology.module_contexts[index];
			const auto context_stage_index = context.stage_instance_index;
			if (context.module_context_index != index ||
			    context.worker_index >= transition.workers.size() ||
			    context_stage_index >= topology.stage_instances.size() ||
			    topology.stage_instances[context_stage_index].worker_index != context.worker_index ||
			    !topology.stage_instances[context_stage_index].module_context_index.has_value() ||
			    topology.stage_instances[context_stage_index].module_context_index.value() != index ||
			    topology.stage_instances[context_stage_index].logical_stage_index !=
				    context.logical_stage_index ||
			    topology.stage_instances[context_stage_index].stage_instance_id !=
				    context.context_instance_id ||
			    context.logical_stage_index >= topology.logical_stages.size() ||
			    topology.logical_stages[context.logical_stage_index].kind !=
				    provider::compiled_stage_kind::MODULE ||
			    topology.logical_stages[context.logical_stage_index].module_id != context.module_id ||
			    context.region_id != transition.workers[context.worker_index].region_id ||
			    context.cpu_core_id != transition.workers[context.worker_index].cpu_core_ids.front() ||
			    context.numa_node != transition.workers[context.worker_index].numa_node) {
				return status::invalid_argument(static_status_text(
					"module context membership disagrees with exact stage or worker ownership"));
			}
			contexts_by_worker[context.worker_index].push_back(static_cast<uint32_t>(index));
		}

		std::vector<frozen_execution_participant> participants;
		participants.reserve(transition.workers.size());
		std::vector<uint32_t> reader_indices;
		reader_indices.reserve(transition.workers.size());
		std::vector<uint32_t> stage_indices;
		stage_indices.reserve(topology.stage_instances.size());
		std::vector<uint32_t> stream_indices;
		stream_indices.reserve(topology.io_streams.size());
		std::vector<uint32_t> inbound_indices;
		inbound_indices.reserve(transition.boundaries.size());
		std::vector<uint32_t> outbound_indices;
		outbound_indices.reserve(transition.boundaries.size());
		std::vector<uint32_t> context_indices;
		context_indices.reserve(topology.module_contexts.size());
		std::vector<uint8_t> stage_seen(topology.stage_instances.size(), 0u);
		std::vector<uint8_t> stream_seen(topology.io_streams.size(), 0u);
		std::vector<uint8_t> inbound_seen(transition.boundaries.size(), 0u);
		std::vector<uint8_t> outbound_seen(transition.boundaries.size(), 0u);

		for (std::size_t index = 0; index < transition.workers.size(); ++index) {
			const auto &worker = transition.workers[index];
			const auto &schedule = topology.worker_schedules[index];
			const auto not_increasing = [](uint32_t lhs, uint32_t rhs) { return lhs >= rhs; };
			if (std::adjacent_find(schedule.rx_stream_indices.begin(), schedule.rx_stream_indices.end(),
					       not_increasing) != schedule.rx_stream_indices.end() ||
			    std::adjacent_find(schedule.tx_stream_indices.begin(), schedule.tx_stream_indices.end(),
					       not_increasing) != schedule.tx_stream_indices.end()) {
				return status::invalid_argument(
					static_status_text("worker schedule I/O sets are not strictly sorted"));
			}
			if (schedule.rx_stream_indices.size() >
			    std::numeric_limits<std::size_t>::max() - schedule.tx_stream_indices.size()) {
				return status(status_code::OUT_OF_RANGE,
					      static_status_text("worker schedule I/O population overflows size_t"));
			}
			std::vector<uint32_t> scheduled_streams;
			scheduled_streams.reserve(schedule.rx_stream_indices.size() +
						  schedule.tx_stream_indices.size());
			std::merge(schedule.rx_stream_indices.begin(), schedule.rx_stream_indices.end(),
				   schedule.tx_stream_indices.begin(), schedule.tx_stream_indices.end(),
				   std::back_inserter(scheduled_streams));
			if (schedule.worker_index != index ||
			    schedule.stage_instance_indices != worker.stage_instance_indices ||
			    scheduled_streams != worker.io_stream_indices ||
			    std::adjacent_find(scheduled_streams.begin(), scheduled_streams.end()) !=
				    scheduled_streams.end()) {
				return status::invalid_argument(
					static_status_text("execution participant schedule is not exact"));
			}
			bool derived_source = false;
			bool derived_sink = false;
			bool derived_module_context = false;
			for (const uint32_t stage_index : worker.stage_instance_indices) {
				if (stage_index >= topology.stage_instances.size() ||
				    topology.stage_instances[stage_index].stage_instance_index != stage_index ||
				    topology.stage_instances[stage_index].logical_stage_index >=
					    topology.logical_stages.size() ||
				    topology.stage_instances[stage_index].region_index !=
					    static_cast<uint32_t>(worker.region_id) ||
				    topology.stage_instances[stage_index].lane_index != worker.lane_index) {
					return status::invalid_argument(static_status_text(
						"execution participant stage disagrees with exact region or lane ownership"));
				}
				const auto &stage = topology.stage_instances[stage_index];
				const auto &logical = topology.logical_stages[stage.logical_stage_index];
				const auto kind = logical.kind;
				if (kind != provider::compiled_stage_kind::RX &&
				    kind != provider::compiled_stage_kind::TX &&
				    kind != provider::compiled_stage_kind::PARSE_IPV4 &&
				    kind != provider::compiled_stage_kind::MODULE) {
					return status::invalid_argument(static_status_text(
						"execution participant stage has an unknown compiled mechanism"));
				}
				const bool is_io = kind == provider::compiled_stage_kind::RX ||
						   kind == provider::compiled_stage_kind::TX;
				const bool is_module = kind == provider::compiled_stage_kind::MODULE;
				const bool is_active = logical.execution_mode ==
						       provider::compiled_stage_execution_mode::ACTIVE;
				if ((!is_active &&
				     logical.execution_mode != provider::compiled_stage_execution_mode::PASSIVE) ||
				    is_active != stage.active_origin_storage_domain_index.has_value()) {
					return status::invalid_argument(static_status_text(
						"execution participant stage scheduling ownership is incomplete"));
				}
				if (stage.logical_stage_id != logical.logical_stage_id ||
				    is_io != stage.io_stream_index.has_value() ||
				    is_module != stage.module_context_index.has_value()) {
					return status::invalid_argument(static_status_text(
						"execution participant stage mechanism ownership is incomplete"));
				}
				derived_source = derived_source || kind == provider::compiled_stage_kind::RX ||
						 stage.active_origin_storage_domain_index.has_value();
				derived_sink = derived_sink || kind == provider::compiled_stage_kind::TX;
				derived_module_context = derived_module_context || is_module;
			}
			for (const uint32_t stream_index : worker.io_stream_indices) {
				if (stream_index >= topology.io_streams.size()) {
					return status::invalid_argument(static_status_text(
						"execution participant stream is outside the compact namespace"));
				}
				const auto &stream = topology.io_streams[stream_index];
				if (stream.stage_instance_index >= topology.stage_instances.size()) {
					return status::invalid_argument(static_status_text(
						"execution participant stream references an unknown stage"));
				}
				const auto &stream_stage = topology.stage_instances[stream.stage_instance_index];
				const auto stream_kind = topology.logical_stages[stream_stage.logical_stage_index].kind;
				const bool direction_matches_stage =
					(stream_kind == provider::compiled_stage_kind::RX &&
					 stream.direction == provider::compiled_io_stream_direction::RX) ||
					(stream_kind == provider::compiled_stage_kind::TX &&
					 stream.direction == provider::compiled_io_stream_direction::TX);
				if (stream.io_stream_index != stream_index || stream.lane_index != worker.lane_index ||
				    stream_stage.worker_index != index ||
				    stream_stage.lane_index != worker.lane_index ||
				    !stream_stage.io_stream_index.has_value() ||
				    stream_stage.io_stream_index.value() != stream_index || !direction_matches_stage) {
					return status::invalid_argument(static_status_text(
						"execution participant stream disagrees with exact stage or lane ownership"));
				}
			}
			for (const uint32_t stream_index : schedule.rx_stream_indices) {
				if (stream_index >= topology.io_streams.size() ||
				    topology.io_streams[stream_index].direction !=
					    provider::compiled_io_stream_direction::RX) {
					return status::invalid_argument(
						static_status_text("worker RX schedule contains a non-RX stream"));
				}
			}
			for (const uint32_t stream_index : schedule.tx_stream_indices) {
				if (stream_index >= topology.io_streams.size() ||
				    topology.io_streams[stream_index].direction !=
					    provider::compiled_io_stream_direction::TX) {
					return status::invalid_argument(
						static_status_text("worker TX schedule contains a non-TX stream"));
				}
			}
			if (worker.is_source != derived_source || worker.is_sink != derived_sink ||
			    worker.owns_module_context != derived_module_context) {
				return status::invalid_argument(static_status_text(
					"execution participant role flags disagree with exact stage semantics"));
			}

			auto stages_or = append_owned_indices(
				worker.stage_instance_indices, static_cast<uint32_t>(index), stage_seen, stage_indices,
				"execution participant stage",
				[&topology](uint32_t value) { return topology.stage_instances[value].worker_index; });
			if (!stages_or.is_ok()) {
				return stages_or.error();
			}
			auto streams_or = append_owned_indices(
				worker.io_stream_indices, static_cast<uint32_t>(index), stream_seen, stream_indices,
				"execution participant I/O stream",
				[&topology](uint32_t value) { return topology.io_streams[value].worker_index; });
			if (!streams_or.is_ok()) {
				return streams_or.error();
			}
			auto inbound_or = append_owned_indices(
				worker.inbound_boundary_indices, static_cast<uint32_t>(index), inbound_seen,
				inbound_indices, "execution participant inbound boundary",
				[&transition](uint32_t value) {
					return transition.boundaries[value].receiver_worker_index;
				});
			if (!inbound_or.is_ok()) {
				return inbound_or.error();
			}
			auto outbound_or = append_owned_indices(
				worker.outbound_boundary_indices, static_cast<uint32_t>(index), outbound_seen,
				outbound_indices, "execution participant outbound boundary",
				[&transition](uint32_t value) {
					return transition.boundaries[value].sender_worker_index;
				});
			if (!outbound_or.is_ok()) {
				return outbound_or.error();
			}
			auto contexts_or = append_owned_indices(
				contexts_by_worker[index], static_cast<uint32_t>(index), context_seen, context_indices,
				"execution participant module context",
				[&topology](uint32_t value) { return topology.module_contexts[value].worker_index; });
			if (!contexts_or.is_ok()) {
				return contexts_or.error();
			}
			if (derived_module_context != !contexts_by_worker[index].empty()) {
				return status::invalid_argument(static_status_text(
					"execution participant module-context flag disagrees with exact membership"));
			}

			reader_indices.push_back(static_cast<uint32_t>(index));
			participants.push_back(frozen_execution_participant{
				.participant_index = static_cast<uint32_t>(index),
				.worker_index = static_cast<uint32_t>(index),
				.region_index = static_cast<uint32_t>(worker.region_id),
				.lane_index = worker.lane_index,
				.quiescence_reader_index = static_cast<uint32_t>(index),
				.is_source = worker.is_source,
				.is_sink = worker.is_sink,
				.stages = stages_or.value(),
				.io_streams = streams_or.value(),
				.inbound_boundaries = inbound_or.value(),
				.outbound_boundaries = outbound_or.value(),
				.module_contexts = contexts_or.value(),
			});
		}

		if (const auto complete = require_complete(stage_seen, "stage"); !complete.is_ok()) {
			return complete;
		}
		if (const auto complete = require_complete(stream_seen, "I/O stream"); !complete.is_ok()) {
			return complete;
		}
		if (const auto complete = require_complete(inbound_seen, "inbound boundary"); !complete.is_ok()) {
			return complete;
		}
		if (const auto complete = require_complete(outbound_seen, "outbound boundary"); !complete.is_ok()) {
			return complete;
		}
		if (const auto complete = require_complete(context_seen, "module context"); !complete.is_ok()) {
			return complete;
		}

		for (std::size_t index = 0; index < transition.boundaries.size(); ++index) {
			const auto &boundary = transition.boundaries[index];
			if (boundary.boundary_index != index ||
			    boundary.sender_worker_index >= transition.workers.size() ||
			    boundary.receiver_worker_index >= transition.workers.size() ||
			    boundary.sender_worker_index == boundary.receiver_worker_index ||
			    boundary.from_stage_instance_index >= topology.stage_instances.size() ||
			    boundary.to_stage_instance_index >= topology.stage_instances.size() ||
			    topology.stage_instances[boundary.from_stage_instance_index].worker_index !=
				    boundary.sender_worker_index ||
			    topology.stage_instances[boundary.to_stage_instance_index].worker_index !=
				    boundary.receiver_worker_index ||
			    boundary.data_ring_numa_node !=
				    transition.workers[boundary.receiver_worker_index].numa_node) {
				return status::invalid_argument(
					static_status_text("boundary participant ownership is not exact"));
			}
		}
		if (transition.boundaries_by_source_stage_instance.size() != topology.stage_instances.size()) {
			return status::invalid_argument(
				static_status_text("boundary source-stage membership has the wrong compact universe"));
		}
		std::vector<uint8_t> source_boundary_seen(transition.boundaries.size(), 0u);
		for (std::size_t stage_index = 0; stage_index < transition.boundaries_by_source_stage_instance.size();
		     ++stage_index) {
			std::optional<std::pair<uint32_t, uint32_t>> previous;
			for (const auto &edge : transition.boundaries_by_source_stage_instance[stage_index]) {
				const std::pair<uint32_t, uint32_t> identity{edge.to_stage_instance_index,
									     edge.boundary_index};
				if (edge.boundary_index >= transition.boundaries.size() ||
				    edge.to_stage_instance_index >= topology.stage_instances.size() ||
				    source_boundary_seen[edge.boundary_index] != 0u ||
				    transition.boundaries[edge.boundary_index].from_stage_instance_index !=
					    stage_index ||
				    transition.boundaries[edge.boundary_index].to_stage_instance_index !=
					    edge.to_stage_instance_index ||
				    (previous.has_value() && previous.value() >= identity)) {
					return status::invalid_argument(static_status_text(
						"boundary source-stage membership is duplicate, unsorted, or cross-owned"));
				}
				source_boundary_seen[edge.boundary_index] = 1u;
				previous = identity;
			}
		}
		if (const auto complete = require_complete(source_boundary_seen, "boundary source-stage");
		    !complete.is_ok()) {
			return complete;
		}

		if (const auto source_status =
			    validate_worker_role_indices(transition.source_worker_indices, transition.workers, true);
		    !source_status.is_ok()) {
			return source_status;
		}
		if (const auto sink_status =
			    validate_worker_role_indices(transition.sink_worker_indices, transition.workers, false);
		    !sink_status.is_ok()) {
			return sink_status;
		}
		if (transition.policy.enabled &&
		    (transition.source_worker_indices.empty() || transition.sink_worker_indices.empty())) {
			return status::invalid_argument(static_status_text(
				"transition-enabled participant set requires nonempty source and sink ownership"));
		}

		std::vector<frozen_region_membership> regions;
		regions.reserve(topology.execution_regions.size());
		std::vector<uint32_t> region_workers;
		region_workers.reserve(transition.workers.size());
		std::vector<uint8_t> region_worker_seen(transition.workers.size(), 0u);
		std::vector<uint32_t> region_stages;
		region_stages.reserve(topology.stage_instances.size());
		std::vector<uint8_t> region_stage_seen(topology.stage_instances.size(), 0u);
		for (std::size_t index = 0; index < topology.execution_regions.size(); ++index) {
			const auto &region = topology.execution_regions[index];
			if (region.region_id != static_cast<int32_t>(index) || region.numa_node < 0 ||
			    region.worker_indices.empty() || region.stage_instance_indices.empty()) {
				return status::invalid_argument(static_status_text(
					"logical region identity, placement, or participant membership is incomplete"));
			}
			auto workers_or = append_owned_indices(
				region.worker_indices, static_cast<uint32_t>(index), region_worker_seen, region_workers,
				"logical region worker", [&transition](uint32_t value) {
					return static_cast<uint32_t>(transition.workers[value].region_id);
				});
			if (!workers_or.is_ok()) {
				return workers_or.error();
			}
			auto stages_or = append_owned_indices(
				region.stage_instance_indices, static_cast<uint32_t>(index), region_stage_seen,
				region_stages, "logical region stage",
				[&topology](uint32_t value) { return topology.stage_instances[value].region_index; });
			if (!stages_or.is_ok()) {
				return stages_or.error();
			}
			regions.push_back(frozen_region_membership{static_cast<uint32_t>(index), workers_or.value()});
		}
		if (const auto complete = require_complete(region_worker_seen, "logical region worker");
		    !complete.is_ok()) {
			return complete;
		}
		if (const auto complete = require_complete(region_stage_seen, "logical region stage");
		    !complete.is_ok()) {
			return complete;
		}

		return std::unique_ptr<const frozen_transition_participants>(new frozen_transition_participants(
			topology.source_plan_content_hash, std::move(participants), std::move(regions),
			transition.source_worker_indices, transition.sink_worker_indices, std::move(reader_indices),
			std::move(stage_indices), std::move(stream_indices), std::move(inbound_indices),
			std::move(outbound_indices), std::move(context_indices), std::move(region_workers)));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(
			static_status_text("failed to allocate frozen transition participant set"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("frozen transition participant set exceeds host containers"));
	}
}

frozen_transition_participants::frozen_transition_participants(
	std::string plan_content_hash, std::vector<frozen_execution_participant> participants,
	std::vector<frozen_region_membership> regions, std::vector<uint32_t> source_indices,
	std::vector<uint32_t> sink_indices, std::vector<uint32_t> reader_indices, std::vector<uint32_t> stage_indices,
	std::vector<uint32_t> stream_indices, std::vector<uint32_t> inbound_indices,
	std::vector<uint32_t> outbound_indices, std::vector<uint32_t> context_indices,
	std::vector<uint32_t> region_worker_indices) noexcept
	: plan_content_hash_(std::move(plan_content_hash))
	, participants_(std::move(participants))
	, regions_(std::move(regions))
	, source_indices_(std::move(source_indices))
	, sink_indices_(std::move(sink_indices))
	, reader_indices_(std::move(reader_indices))
	, stage_indices_(std::move(stage_indices))
	, stream_indices_(std::move(stream_indices))
	, inbound_indices_(std::move(inbound_indices))
	, outbound_indices_(std::move(outbound_indices))
	, context_indices_(std::move(context_indices))
	, region_worker_indices_(std::move(region_worker_indices))
{
}

std::string_view frozen_transition_participants::plan_content_hash() const noexcept
{
	return plan_content_hash_;
}

std::size_t frozen_transition_participants::execution_participant_count() const noexcept
{
	return participants_.size();
}

std::size_t frozen_transition_participants::region_count() const noexcept
{
	return regions_.size();
}

std::size_t frozen_transition_participants::boundary_count() const noexcept
{
	return inbound_indices_.size();
}

std::size_t frozen_transition_participants::module_context_count() const noexcept
{
	return context_indices_.size();
}

std::size_t frozen_transition_participants::quiescence_reader_count() const noexcept
{
	return reader_indices_.size();
}

const frozen_execution_participant *
frozen_transition_participants::execution_participant(uint32_t participant_index) const noexcept
{
	return participant_index < participants_.size() ? &participants_[participant_index] : nullptr;
}

const frozen_region_membership *frozen_transition_participants::region(uint32_t region_index) const noexcept
{
	return region_index < regions_.size() ? &regions_[region_index] : nullptr;
}

std::span<const uint32_t> frozen_transition_participants::source_participant_indices() const noexcept
{
	return std::span<const uint32_t>(source_indices_);
}

std::span<const uint32_t> frozen_transition_participants::sink_participant_indices() const noexcept
{
	return std::span<const uint32_t>(sink_indices_);
}

std::span<const uint32_t> frozen_transition_participants::quiescence_reader_indices() const noexcept
{
	return std::span<const uint32_t>(reader_indices_);
}

std::span<const uint32_t> frozen_transition_participants::stage_indices(uint32_t participant_index) const noexcept
{
	const auto *participant = execution_participant(participant_index);
	if (participant == nullptr) {
		std::terminate();
	}
	return range_(stage_indices_, participant->stages);
}

std::span<const uint32_t> frozen_transition_participants::io_stream_indices(uint32_t participant_index) const noexcept
{
	const auto *participant = execution_participant(participant_index);
	if (participant == nullptr) {
		std::terminate();
	}
	return range_(stream_indices_, participant->io_streams);
}

std::span<const uint32_t>
frozen_transition_participants::inbound_boundary_indices(uint32_t participant_index) const noexcept
{
	const auto *participant = execution_participant(participant_index);
	if (participant == nullptr) {
		std::terminate();
	}
	return range_(inbound_indices_, participant->inbound_boundaries);
}

std::span<const uint32_t>
frozen_transition_participants::outbound_boundary_indices(uint32_t participant_index) const noexcept
{
	const auto *participant = execution_participant(participant_index);
	if (participant == nullptr) {
		std::terminate();
	}
	return range_(outbound_indices_, participant->outbound_boundaries);
}

std::span<const uint32_t>
frozen_transition_participants::module_context_indices(uint32_t participant_index) const noexcept
{
	const auto *participant = execution_participant(participant_index);
	if (participant == nullptr) {
		std::terminate();
	}
	return range_(context_indices_, participant->module_contexts);
}

std::span<const uint32_t> frozen_transition_participants::region_worker_indices(uint32_t region_index) const noexcept
{
	const auto *membership = region(region_index);
	if (membership == nullptr) {
		std::terminate();
	}
	return range_(region_worker_indices_, membership->workers);
}

std::span<const uint32_t> frozen_transition_participants::range_(const std::vector<uint32_t> &values,
								 frozen_index_range range) noexcept
{
	const std::size_t offset = range.offset;
	const std::size_t count = range.count;
	if (offset > values.size() || count > values.size() - offset) {
		std::terminate();
	}
	if (count == 0u) {
		return {};
	}
	return std::span<const uint32_t>(values.data() + offset, count);
}

}  // namespace kinetum::dp
