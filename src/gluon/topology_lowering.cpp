// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file topology_lowering.cpp
 * @brief Exact executable topology lowering implementation.
 * @author Fleming Patel
 */

#include "src/gluon/topology_lowering.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "src/axiom/stage_configuration.hpp"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/status_or.hpp"
#include "src/provider/deployment_plan_identity.hpp"

namespace kinetum::gluon
{

namespace
{

using kinetum::common::status;
using kinetum::common::status_code;

/** @brief Exact logical-port/direction key for one authored stream binding. */
struct stream_binding_key {
	std::string logical_name;  ///< Logical pipeline interface.
	kinetum::gluon::v1::IoStreamDirection direction{
		kinetum::gluon::v1::IO_STREAM_DIRECTION_UNSPECIFIED};  ///< Exact RX or TX direction.

	/**
	 * @brief Compare keys in canonical identity order.
	 *
	 * @param other Key to compare.
	 * @return true when this key sorts before `other`.
	 */
	[[nodiscard]] bool operator<(const stream_binding_key &other) const noexcept
	{
		if (logical_name != other.logical_name) {
			return logical_name < other.logical_name;
		}
		return static_cast<int>(direction) < static_cast<int>(other.direction);
	}
};

/** @brief Canonical executable stream intent for one logical direction. */
struct stream_binding {
	std::vector<kinetum::gluon::v1::DriverQueueBinding> queues;  ///< Sorted queues with exact storage contracts.
	kinetum::gluon::v1::TrafficSteeringKind steering_kind{
		kinetum::gluon::v1::TRAFFIC_STEERING_KIND_UNSPECIFIED};	 ///< Exact steering mode.
	bool symmetric{false};						 ///< Reverse-flow co-steering request.
	std::vector<std::string> hash_fields;				 ///< Order-contractual hash fields.
	std::string hash_key;						 ///< Exact deterministic key bytes.
};

/** @brief Exact authored lifecycle-memory bounds for one module context. */
struct module_context_resource_binding {
	uint64_t context_memory_capacity_bytes{0};  ///< Context-lifetime allocation bound.
	uint64_t epoch_arena_capacity_bytes{0};	    ///< Capacity of each exact epoch arena.
};

/** @brief Pipeline-position lookup entry ordered by logical stage identity. */
struct logical_stage_index_entry {
	std::string_view logical_stage_id;  ///< Borrowed stable logical stage identity.
	std::size_t stage_index{0};	    ///< Exact pipeline position.
	kinetum::axiom::v1::StageKind kind{kinetum::axiom::v1::STAGE_KIND_UNSPECIFIED};	 ///< Authored stage kind.
};

/** @brief One cell in the dense logical-stage by execution-lane resource table. */
struct module_context_resource_slot {
	module_context_resource_binding resources{};  ///< Exact authored capacities when present.
	bool present{false};			      ///< Whether the sole binding claimed this cell.
};

/** @brief Resolved I/O-stage input to lane and stream emission. */
struct io_stage_plan {
	const kinetum::axiom::v1::Stage *stage{nullptr};      ///< Exact authored I/O stage.
	const kinetum::gluon::v1::PortConfig *port{nullptr};  ///< Exact resolved logical port.
	stream_binding binding;				      ///< Exact stream/queue binding.
	int32_t region_id{-1};				      ///< Logical region owning the stage.
};

/** @brief Deterministic steering-profile emission accumulator. */
struct steering_profile_emission {
	std::string steering_profile_id;  ///< Stable generated profile identity.
	kinetum::gluon::v1::TrafficSteeringKind kind{
		kinetum::gluon::v1::TRAFFIC_STEERING_KIND_UNSPECIFIED};	 ///< Exact profile kind.
	bool symmetric{false};						 ///< Exact symmetry requirement.
	std::vector<std::string> hash_fields;				 ///< Exact hash field order.
	std::string hash_key;						 ///< Exact key bytes.
	std::vector<std::string> stream_ids;				 ///< Governed stream identities.
};

/**
 * @brief Return a canonical direction suffix for generated IDs.
 *
 * @param direction Exact stream direction.
 * @return `rx` or `tx`; an undeclared value is a programmer-contract failure.
 */
[[nodiscard]] std::string_view stream_direction_suffix(kinetum::gluon::v1::IoStreamDirection direction) noexcept
{
	switch (direction) {
	case kinetum::gluon::v1::IO_STREAM_DIRECTION_RX:
		return "rx";
	case kinetum::gluon::v1::IO_STREAM_DIRECTION_TX:
		return "tx";
	case kinetum::gluon::v1::IO_STREAM_DIRECTION_UNSPECIFIED:
	case kinetum::gluon::v1::IoStreamDirection_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::gluon::v1::IoStreamDirection_INT_MAX_SENTINEL_DO_NOT_USE_:
		std::terminate();
	}
	std::terminate();
}

/**
 * @brief Check whether a stream direction is executable.
 *
 * @param direction Direction to inspect.
 * @return true only for RX or TX.
 */
[[nodiscard]] constexpr bool is_executable_direction(kinetum::gluon::v1::IoStreamDirection direction) noexcept
{
	return direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX ||
	       direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_TX;
}

/**
 * @brief Parse one canonical generated lane identity into its dense index.
 *
 * @param lane_id Candidate `lane_<index>` identity.
 * @param lane_count Exact generated lane count.
 * @return Dense index when the spelling is canonical and in range; otherwise
 *         no value.
 */
[[nodiscard]] std::optional<std::size_t> parse_lane_index(std::string_view lane_id, std::size_t lane_count) noexcept
{
	constexpr std::string_view PREFIX = "lane_";
	if (!lane_id.starts_with(PREFIX) || lane_id.size() == PREFIX.size()) {
		return std::nullopt;
	}

	lane_id.remove_prefix(PREFIX.size());
	const std::string_view digits = lane_id;
	if (digits.size() > 1u && digits.front() == '0') {
		return std::nullopt;
	}
	uint32_t parsed_index = 0;
	const char *const first = &digits.front();
	const char *const last = first + digits.size();
	const auto parsed = std::from_chars(first, last, parsed_index);
	if (parsed.ec != std::errc{} || parsed.ptr != last || static_cast<std::size_t>(parsed_index) >= lane_count) {
		return std::nullopt;
	}
	return static_cast<std::size_t>(parsed_index);
}

/**
 * @brief Check whether a logical port permits one exact stream direction.
 *
 * @param port_direction Exact logical-port direction.
 * @param stream_direction Required stream direction.
 * @return true when the port admits that operation.
 */
[[nodiscard]] constexpr bool port_direction_allows(kinetum::gluon::v1::PortDirection port_direction,
						   kinetum::gluon::v1::IoStreamDirection stream_direction) noexcept
{
	if (port_direction == kinetum::gluon::v1::PORT_DIRECTION_BIDIRECTIONAL) {
		return true;
	}
	if (stream_direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
		return port_direction == kinetum::gluon::v1::PORT_DIRECTION_RX_ONLY;
	}
	if (stream_direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_TX) {
		return port_direction == kinetum::gluon::v1::PORT_DIRECTION_TX_ONLY;
	}
	return false;
}

/**
 * @brief Build the generated RSS profile identity for one logical port.
 *
 * @param logical_name Exact logical port.
 * @return Stable profile ID.
 */
[[nodiscard]] std::string rss_profile_id_for_port(std::string_view logical_name)
{
	std::string profile_id("steering_rss_");
	profile_id.append(logical_name.data(), logical_name.size());
	return profile_id;
}

/**
 * @brief Build the generated unsteered profile identity for one logical port.
 *
 * @param logical_name Exact logical port.
 * @return Stable profile ID.
 */
[[nodiscard]] std::string none_profile_id_for_port(std::string_view logical_name)
{
	std::string profile_id("steering_none_");
	profile_id.append(logical_name.data(), logical_name.size());
	return profile_id;
}

/**
 * @brief Build logical stage-to-region ownership.
 *
 * @param plan Candidate plan with complete regions.
 * @param stage_regions Output stage ownership.
 * @return OK only for exact one-region coverage.
 */
[[nodiscard]] status build_stage_region_map(const kinetum::gluon::v1::DeploymentPlan &plan,
					    std::unordered_map<std::string, int32_t> &stage_regions)
{
	stage_regions.clear();
	stage_regions.reserve(static_cast<std::size_t>(plan.pipeline().stages_size()));
	std::unordered_set<int32_t> region_ids;
	region_ids.reserve(static_cast<std::size_t>(plan.regions_size()));

	for (const auto &region : plan.regions()) {
		if (region.region_id() < 0 || region.region_id() >= plan.regions_size()) {
			return status::invalid_argument("region_id is outside executable topology range");
		}
		if (!region_ids.insert(region.region_id()).second) {
			return status::invalid_argument("duplicate region_id during executable topology lowering");
		}
		for (const auto &stage_id : region.logical_stage_ids()) {
			if (!stage_regions.emplace(stage_id, region.region_id()).second) {
				return status::invalid_argument("logical stage '" + stage_id +
								"' is assigned to multiple regions");
			}
		}
	}
	for (const auto &stage : plan.pipeline().stages()) {
		if (stage_regions.find(stage.stage_id()) == stage_regions.end()) {
			return status::invalid_argument("logical stage '" + stage.stage_id() +
							"' has no assigned region");
		}
	}
	return status::ok();
}

/**
 * @brief Build exact logical-port lookup tables.
 *
 * @param plan Candidate plan with resolved ports.
 * @param ports Output logical-name lookup.
 * @return OK only for unique complete port identities.
 */
[[nodiscard]] status build_port_lookup(const kinetum::gluon::v1::DeploymentPlan &plan,
				       std::unordered_map<std::string, const kinetum::gluon::v1::PortConfig *> &ports)
{
	ports.clear();
	ports.reserve(static_cast<std::size_t>(plan.ports_size()));
	std::unordered_set<uint32_t> logical_port_ids;
	logical_port_ids.reserve(static_cast<std::size_t>(plan.ports_size()));

	for (const auto &port : plan.ports()) {
		if (!kinetum::common::execution_topology::is_topology_identifier(port.logical_name())) {
			return status::invalid_argument("plan port has an invalid logical_name");
		}
		if (!logical_port_ids.insert(port.logical_port_id()).second) {
			return status::invalid_argument("plan contains duplicate logical_port_id");
		}
		if (!ports.emplace(port.logical_name(), &port).second) {
			return status::invalid_argument("plan contains duplicate logical port name");
		}
	}
	return status::ok();
}

/**
 * @brief Canonicalize and validate all exact stream bindings.
 *
 * @param bindings Required deployment intent.
 * @param plan Candidate plan with ports and storage domains.
 * @param streams Output canonical stream-binding map.
 * @return OK after duplicate, queue, storage, and steering validation.
 */
[[nodiscard]] status build_stream_bindings(const kinetum::gluon::v1::DeploymentBindings &bindings,
					   const kinetum::gluon::v1::DeploymentPlan &plan,
					   std::map<stream_binding_key, stream_binding> &streams)
{
	std::unordered_set<std::string> storage_ids;
	storage_ids.reserve(static_cast<std::size_t>(plan.packet_storage_domains_size()));
	for (const auto &storage : plan.packet_storage_domains()) {
		storage_ids.insert(storage.storage_domain_id());
	}

	streams.clear();
	for (const auto &input : bindings.io_stream_bindings()) {
		if (!kinetum::common::execution_topology::is_topology_identifier(input.logical_name())) {
			return status::invalid_argument("I/O-stream binding has an invalid logical_name");
		}
		if (!is_executable_direction(input.direction())) {
			return status::invalid_argument("I/O-stream binding has an unspecified direction");
		}
		if (input.queues_size() == 0) {
			return status::invalid_argument("I/O-stream binding for '" + input.logical_name() +
							"' requires at least one explicit queue");
		}
		if (!input.has_steering()) {
			return status::invalid_argument("I/O-stream binding for '" + input.logical_name() +
							"' requires an explicit steering contract");
		}

		stream_binding canonical;
		canonical.steering_kind = input.steering().kind();
		canonical.symmetric = input.steering().symmetric();
		canonical.hash_fields.assign(input.steering().hash_fields().begin(),
					     input.steering().hash_fields().end());
		canonical.hash_key = input.steering().hash_key();
		canonical.queues.reserve(static_cast<std::size_t>(input.queues_size()));
		for (const auto &queue : input.queues()) {
			if (queue.descriptor_count() == 0) {
				return status::invalid_argument("I/O-stream binding for '" + input.logical_name() +
								"' has a queue with zero descriptor_count");
			}
			auto normalized = queue;
			if (input.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				if (!queue.has_rx_storage_domain_id() ||
				    !storage_ids.contains(queue.rx_storage_domain_id())) {
					return status::invalid_argument(
						"RX queue requires one known allocation domain");
				}
			} else {
				if (!queue.has_tx_storage()) {
					return status::invalid_argument("TX queue requires its storage admission set");
				}
				if (const auto valid = kinetum::provider::canonicalize_tx_storage_binding(
					    normalized.mutable_tx_storage());
				    !valid.is_ok()) {
					return valid;
				}
				for (const auto &domain : normalized.tx_storage().storage_domain_ids()) {
					if (!storage_ids.contains(domain)) {
						return status::invalid_argument(
							"TX queue references unknown storage domain '" + domain + "'");
					}
				}
			}
			canonical.queues.push_back(std::move(normalized));
		}
		std::sort(canonical.queues.begin(), canonical.queues.end(), [](const auto &lhs, const auto &rhs) {
			return lhs.driver_queue_id() < rhs.driver_queue_id();
		});
		for (std::size_t index = 1; index < canonical.queues.size(); ++index) {
			if (canonical.queues[index - 1u].driver_queue_id() ==
			    canonical.queues[index].driver_queue_id()) {
				return status::invalid_argument("I/O-stream binding for '" + input.logical_name() +
								"' contains duplicate driver_queue_id");
			}
		}

		switch (canonical.steering_kind) {
		case kinetum::gluon::v1::TRAFFIC_STEERING_KIND_NONE:
			if (canonical.symmetric || !canonical.hash_fields.empty() || !canonical.hash_key.empty()) {
				return status::invalid_argument("no-steering binding for '" + input.logical_name() +
								"' must not carry steering parameters");
			}
			if (input.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX &&
			    canonical.queues.size() > 1u) {
				return status::invalid_argument("multi-queue RX binding for '" + input.logical_name() +
								"' requires exact RSS steering");
			}
			break;
		case kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS: {
			if (input.direction() != kinetum::gluon::v1::IO_STREAM_DIRECTION_RX ||
			    canonical.queues.size() < 2u || canonical.hash_fields.empty() ||
			    canonical.hash_key.empty()) {
				return status::invalid_argument("RSS binding for '" + input.logical_name() +
								"' requires RX, at least two queues, "
								"nonempty fields, and an exact key");
			}
			std::unordered_set<std::string> fields;
			fields.reserve(canonical.hash_fields.size());
			for (const auto &field : canonical.hash_fields) {
				if (!kinetum::common::execution_topology::is_topology_identifier(field) ||
				    !fields.insert(field).second) {
					return status::invalid_argument("RSS binding for '" + input.logical_name() +
									"' contains an invalid or duplicate "
									"hash field");
				}
			}
			break;
		}
		case kinetum::gluon::v1::TRAFFIC_STEERING_KIND_UNSPECIFIED:
		case kinetum::gluon::v1::TrafficSteeringKind_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::gluon::v1::TrafficSteeringKind_INT_MAX_SENTINEL_DO_NOT_USE_:
			return status::invalid_argument("I/O-stream binding for '" + input.logical_name() +
							"' requests unsupported steering kind");
		}

		stream_binding_key key{input.logical_name(), input.direction()};
		if (!streams.emplace(std::move(key), std::move(canonical)).second) {
			return status::invalid_argument("duplicate I/O-stream binding for logical port '" +
							input.logical_name() + "' and direction " +
							std::string(stream_direction_suffix(input.direction())));
		}
	}
	return status::ok();
}

/**
 * @brief Build exact logical-stage execution-provider bindings.
 *
 * @param bindings Required deployment intent.
 * @param plan Candidate plan with pipeline and execution providers.
 * @param execution_by_stage Output logical-stage map.
 * @return OK only for two-directional exact stage coverage.
 */
[[nodiscard]] status build_stage_execution_bindings(const kinetum::gluon::v1::DeploymentBindings &bindings,
						    const kinetum::gluon::v1::DeploymentPlan &plan,
						    std::unordered_map<std::string, std::string> &execution_by_stage)
{
	std::unordered_set<std::string> execution_ids;
	execution_ids.reserve(static_cast<std::size_t>(plan.execution_provider_instances_size()));
	for (const auto &execution : plan.execution_provider_instances()) {
		execution_ids.insert(execution.execution_provider_instance_id());
	}

	execution_by_stage.clear();
	execution_by_stage.reserve(static_cast<std::size_t>(bindings.stage_execution_bindings_size()));
	for (const auto &binding : bindings.stage_execution_bindings()) {
		if (!kinetum::common::execution_topology::is_topology_identifier(binding.logical_stage_id()) ||
		    !kinetum::common::execution_topology::is_topology_identifier(
			    binding.execution_provider_instance_id())) {
			return status::invalid_argument(
				"stage-execution binding contains an invalid topology identifier");
		}
		if (execution_ids.find(binding.execution_provider_instance_id()) == execution_ids.end()) {
			return status::invalid_argument("stage-execution binding for '" + binding.logical_stage_id() +
							"' references unknown execution provider '" +
							binding.execution_provider_instance_id() + "'");
		}
		if (!execution_by_stage.emplace(binding.logical_stage_id(), binding.execution_provider_instance_id())
			     .second) {
			return status::invalid_argument("duplicate stage-execution binding for '" +
							binding.logical_stage_id() + "'");
		}
	}

	if (execution_by_stage.size() != static_cast<std::size_t>(plan.pipeline().stages_size())) {
		return status::invalid_argument(
			"stage_execution_bindings[] must cover every logical pipeline stage exactly once");
	}
	for (const auto &stage : plan.pipeline().stages()) {
		if (execution_by_stage.find(stage.stage_id()) == execution_by_stage.end()) {
			return status::invalid_argument("logical stage '" + stage.stage_id() +
							"' has no execution-provider binding");
		}
	}
	return status::ok();
}

/**
 * @brief Build exact lane-local storage ownership for active packet origins.
 *
 * @param bindings Required deployment intent.
 * @param plan Candidate plan with the logical pipeline and storage domains.
 * @param lane_count Exact generated execution-lane count.
 * @param storage_by_active_stage_lane Output `(logical_stage_id, lane_id)` to
 *        exact storage-domain identity.
 * @return OK only when every active stage/lane has one binding and every
 *         passive stage/lane has none.
 */
[[nodiscard]] status
build_active_origin_bindings(const kinetum::gluon::v1::DeploymentBindings &bindings,
			     const kinetum::gluon::v1::DeploymentPlan &plan, std::size_t lane_count,
			     std::map<std::pair<std::string, std::string>, std::string> &storage_by_active_stage_lane)
{
	namespace topo = kinetum::common::execution_topology;

	std::unordered_map<std::string, kinetum::axiom::v1::ExecutionMode> execution_mode_by_stage;
	execution_mode_by_stage.reserve(static_cast<std::size_t>(plan.pipeline().stages_size()));
	for (const auto &stage : plan.pipeline().stages()) {
		execution_mode_by_stage.emplace(stage.stage_id(), stage.execution_mode());
	}

	std::unordered_set<std::string> storage_ids;
	storage_ids.reserve(static_cast<std::size_t>(plan.packet_storage_domains_size()));
	for (const auto &storage : plan.packet_storage_domains()) {
		storage_ids.insert(storage.storage_domain_id());
	}

	std::unordered_set<std::string> lane_ids;
	lane_ids.reserve(lane_count);
	for (std::size_t lane_index = 0; lane_index < lane_count; ++lane_index) {
		lane_ids.insert(topo::make_lane_id(static_cast<uint32_t>(lane_index)));
	}

	storage_by_active_stage_lane.clear();
	for (const auto &binding : bindings.active_origin_bindings()) {
		const auto stage_it = execution_mode_by_stage.find(binding.logical_stage_id());
		if (stage_it == execution_mode_by_stage.end()) {
			return status::invalid_argument("active-origin binding references unknown logical stage '" +
							binding.logical_stage_id() + "'");
		}
		if (stage_it->second != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
			return status::invalid_argument("passive stage '" + binding.logical_stage_id() +
							"' must not carry an active-origin binding");
		}
		if (!lane_ids.contains(binding.lane_id())) {
			return status::invalid_argument("active-origin binding for stage '" +
							binding.logical_stage_id() + "' references unknown lane '" +
							binding.lane_id() + "'");
		}
		if (!storage_ids.contains(binding.storage_domain_id())) {
			return status::invalid_argument("active-origin binding for stage/lane '" +
							binding.logical_stage_id() + "/" + binding.lane_id() +
							"' references unknown storage domain");
		}
		if (!storage_by_active_stage_lane
			     .emplace(std::make_pair(binding.logical_stage_id(), binding.lane_id()),
				      binding.storage_domain_id())
			     .second) {
			return status::invalid_argument("duplicate active-origin binding for stage/lane '" +
							binding.logical_stage_id() + "/" + binding.lane_id() + "'");
		}
	}

	std::size_t required_count = 0u;
	for (const auto &stage : plan.pipeline().stages()) {
		if (stage.execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
			continue;
		}
		for (std::size_t lane_index = 0; lane_index < lane_count; ++lane_index) {
			const auto lane_id = topo::make_lane_id(static_cast<uint32_t>(lane_index));
			++required_count;
			if (!storage_by_active_stage_lane.contains(std::make_pair(stage.stage_id(), lane_id))) {
				return status::invalid_argument("active stage/lane '" + stage.stage_id() + "/" +
								lane_id +
								"' requires one exact active-origin storage binding");
			}
		}
	}
	if (storage_by_active_stage_lane.size() != required_count) {
		return status::internal_error("active-origin binding coverage count is inconsistent");
	}
	return status::ok();
}

/**
 * @brief Build exact lane-local lifecycle-memory ownership for module contexts.
 *
 * @param bindings Required deployment intent.
 * @param plan Candidate plan with the logical pipeline.
 * @param lane_count Exact generated execution-lane count.
 * @return Dense stage-major resource table when every module stage/lane has
 *         one nonzero binding and every platform stage/lane has none; error
 *         otherwise.
 */
[[nodiscard]] kinetum::common::status_or<std::vector<module_context_resource_slot>>
build_module_context_resource_bindings(const kinetum::gluon::v1::DeploymentBindings &bindings,
				       const kinetum::gluon::v1::DeploymentPlan &plan, std::size_t lane_count)
{
	const std::size_t stage_count = static_cast<std::size_t>(plan.pipeline().stages_size());
	if (lane_count == 0u || stage_count > std::numeric_limits<std::size_t>::max() / lane_count) {
		return status(status_code::OUT_OF_RANGE, "module-context resource table exceeds the platform range");
	}

	std::vector<logical_stage_index_entry> stages_by_id;
	stages_by_id.reserve(stage_count);
	std::size_t stage_index = 0u;
	for (const auto &stage : plan.pipeline().stages()) {
		stages_by_id.push_back(logical_stage_index_entry{stage.stage_id(), stage_index, stage.kind()});
		++stage_index;
	}
	std::sort(stages_by_id.begin(), stages_by_id.end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.logical_stage_id < rhs.logical_stage_id; });
	for (std::size_t index = 1u; index < stages_by_id.size(); ++index) {
		if (stages_by_id[index - 1u].logical_stage_id == stages_by_id[index].logical_stage_id) {
			return status::invalid_argument("pipeline contains a duplicate logical stage identity");
		}
	}

	std::vector<module_context_resource_slot> resources_by_module_stage_lane(stage_count * lane_count);
	for (const auto &binding : bindings.module_context_resource_bindings()) {
		const std::string_view logical_stage_id = binding.logical_stage_id();
		const auto stage_it =
			std::lower_bound(stages_by_id.begin(), stages_by_id.end(), logical_stage_id,
					 [](const logical_stage_index_entry &entry, std::string_view identity) {
						 return entry.logical_stage_id < identity;
					 });
		if (stage_it == stages_by_id.end() || stage_it->logical_stage_id != logical_stage_id) {
			return status::invalid_argument(
				"module-context resource binding references unknown logical stage '" +
				binding.logical_stage_id() + "'");
		}
		if (stage_it->kind != kinetum::axiom::v1::STAGE_KIND_MODULE) {
			return status::invalid_argument("platform stage '" + binding.logical_stage_id() +
							"' must not carry a module-context resource binding");
		}
		const auto lane_index = parse_lane_index(binding.lane_id(), lane_count);
		if (!lane_index.has_value()) {
			return status::invalid_argument("module-context resource binding for stage '" +
							binding.logical_stage_id() + "' references unknown lane '" +
							binding.lane_id() + "'");
		}
		if (binding.context_memory_capacity_bytes() == 0u || binding.epoch_arena_capacity_bytes() == 0u) {
			return status::invalid_argument("module-context resource binding for stage/lane '" +
							binding.logical_stage_id() + "/" + binding.lane_id() +
							"' requires nonzero context and epoch capacities");
		}
		auto &slot = resources_by_module_stage_lane[stage_it->stage_index * lane_count + lane_index.value()];
		if (slot.present) {
			return status::invalid_argument("duplicate module-context resource binding for stage/lane '" +
							binding.logical_stage_id() + "/" + binding.lane_id() + "'");
		}
		slot.resources = module_context_resource_binding{binding.context_memory_capacity_bytes(),
								 binding.epoch_arena_capacity_bytes()};
		slot.present = true;
	}

	for (const auto &stage : stages_by_id) {
		if (stage.kind != kinetum::axiom::v1::STAGE_KIND_MODULE) {
			continue;
		}
		for (std::size_t lane_index = 0; lane_index < lane_count; ++lane_index) {
			if (!resources_by_module_stage_lane[stage.stage_index * lane_count + lane_index].present) {
				return status::invalid_argument("module stage/lane '" +
								std::string(stage.logical_stage_id) + "/" +
								kinetum::common::execution_topology::make_lane_id(
									static_cast<uint32_t>(lane_index)) +
								"' requires one exact module-context resource binding");
			}
		}
	}
	return resources_by_module_stage_lane;
}

/**
 * @brief Sort one repeated string field lexically.
 *
 * @tparam repeated_strings Protobuf repeated-string container type.
 * @param values Mutable repeated field.
 */
template <typename repeated_strings>
void sort_repeated_strings(repeated_strings *values)
{
	std::sort(values->begin(), values->end());
}

/**
 * @brief Canonically order all emitted executable arrays.
 *
 * @param plan Candidate completed topology.
 */
void sort_emitted_topology(kinetum::gluon::v1::DeploymentPlan &plan)
{
	for (auto &lane : *plan.mutable_execution_lanes()) {
		sort_repeated_strings(lane.mutable_stage_instance_ids());
		sort_repeated_strings(lane.mutable_io_stream_ids());
	}
	for (auto &profile : *plan.mutable_traffic_steering_profiles()) {
		sort_repeated_strings(profile.mutable_stream_ids());
	}
	for (auto &domain : *plan.mutable_module_context_domains()) {
		sort_repeated_strings(domain.mutable_context_instance_ids());
	}
	std::sort(plan.mutable_execution_lanes()->begin(), plan.mutable_execution_lanes()->end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.lane_id() < rhs.lane_id(); });
	std::sort(plan.mutable_stage_instances()->begin(), plan.mutable_stage_instances()->end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.stage_instance_id() < rhs.stage_instance_id(); });
	std::sort(plan.mutable_io_streams()->begin(), plan.mutable_io_streams()->end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.io_stream_id() < rhs.io_stream_id(); });
	std::sort(plan.mutable_traffic_steering_profiles()->begin(), plan.mutable_traffic_steering_profiles()->end(),
		  [](const auto &lhs, const auto &rhs) {
			  return lhs.steering_profile_id() < rhs.steering_profile_id();
		  });
	std::sort(plan.mutable_module_context_domains()->begin(), plan.mutable_module_context_domains()->end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.module_id() < rhs.module_id(); });
	std::sort(plan.mutable_worker_placements()->begin(), plan.mutable_worker_placements()->end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.worker_id() < rhs.worker_id(); });
	for (int index = 0; index < plan.worker_placements_size(); ++index) {
		plan.mutable_worker_placements(index)->set_worker_index(static_cast<uint32_t>(index));
	}
}

/**
 * @brief Revalidate exact active-stage authoring before lowering.
 *
 * This is Gluon's independent backstop after Axiom admission. It additionally
 * proves same-region control/PULL placement from the planner's completed region
 * assignment; the shared provider compiler later proves exact same-worker
 * lane-local ownership.
 *
 * @param plan Complete pre-lowering plan with authored pipeline and regions.
 * @param stage_regions Exact logical-stage to region assignment.
 * @return OK only for the compact active-resource and local-edge contract.
 */
[[nodiscard]] status validate_active_stage_lowering(const kinetum::gluon::v1::DeploymentPlan &plan,
						    const std::unordered_map<std::string, int32_t> &stage_regions)
{
	constexpr uint32_t TIMER = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_TIMER);
	constexpr uint32_t PULL = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_PULL_READY);
	constexpr uint32_t CONTROL = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_CONTROL);
	constexpr uint32_t KNOWN = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP) | TIMER | PULL |
				   CONTROL;
	std::unordered_map<std::string_view, const kinetum::axiom::v1::Stage *> stages;
	std::unordered_map<std::string_view, uint32_t> inbound_control;
	std::unordered_map<std::string_view, uint32_t> outbound_pull;
	for (const auto &stage : plan.pipeline().stages()) {
		stages.emplace(stage.stage_id(), &stage);
	}
	std::set<std::pair<std::string_view, std::string_view>> pull_endpoint_pairs;
	for (const auto &edge : plan.pipeline().edges()) {
		if (edge.mode() != kinetum::axiom::v1::EDGE_MODE_PUSH &&
		    edge.mode() != kinetum::axiom::v1::EDGE_MODE_PULL) {
			return status::invalid_argument("packet edge declares an unknown work-driving mode");
		}
		if (edge.mode() != kinetum::axiom::v1::EDGE_MODE_PULL) {
			continue;
		}
		if (!pull_endpoint_pairs.emplace(edge.from_stage_id(), edge.to_stage_id()).second) {
			return status::invalid_argument("active PULL endpoint pair is declared more than once");
		}
		++outbound_pull[edge.from_stage_id()];
		const auto source = stages.find(edge.from_stage_id());
		const auto destination = stages.find(edge.to_stage_id());
		const auto from = stage_regions.find(edge.from_stage_id());
		const auto to = stage_regions.find(edge.to_stage_id());
		if (source == stages.end() || destination == stages.end() ||
		    source->second->execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE ||
		    destination->second->execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE ||
		    from == stage_regions.end() || to == stage_regions.end() || from->second != to->second) {
			return status::invalid_argument(
				"active PULL edge requires same-region active source and destination stages");
		}
	}
	std::set<std::pair<std::string_view, std::string_view>> control_endpoint_pairs;
	for (const auto &edge : plan.pipeline().control_edges()) {
		if (edge.subtype() != kinetum::axiom::v1::CONTROL_EDGE_GENERIC &&
		    edge.subtype() != kinetum::axiom::v1::CONTROL_EDGE_FEEDBACK) {
			return status::invalid_argument("control edge declares an unknown subtype");
		}
		++inbound_control[edge.to_stage_id()];
		if (!control_endpoint_pairs.emplace(edge.from_stage_id(), edge.to_stage_id()).second) {
			return status::invalid_argument("active control endpoint pair is declared more than once");
		}
		const auto source = stages.find(edge.from_stage_id());
		const auto destination = stages.find(edge.to_stage_id());
		const auto from = stage_regions.find(edge.from_stage_id());
		const auto to = stage_regions.find(edge.to_stage_id());
		if (source == stages.end() || destination == stages.end() ||
		    source->second->execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE ||
		    destination->second->execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE ||
		    from == stage_regions.end() || to == stage_regions.end() || from->second != to->second) {
			return status::invalid_argument(
				"active control edge requires same-region active source and destination stages");
		}
	}
	for (const auto &stage : plan.pipeline().stages()) {
		const auto &limits = stage.active_stage_limits();
		if (stage.execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_PASSIVE &&
		    stage.execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
			return status::invalid_argument("logical stage declares an unknown execution_mode");
		}
		if (stage.execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
			if (stage.trigger_mask() != 0u || stage.schedule_order() != 0 ||
			    limits.retained_packet_capacity() != 0u || limits.retained_byte_capacity() != 0u ||
			    limits.timer_capacity() != 0u || limits.control_mailbox_capacity() != 0u ||
			    limits.control_message_capacity_bytes() != 0u || limits.async_work_capacity() != 0u ||
			    limits.async_cancel_grace_ms() != 0u) {
				return status::invalid_argument("passive stage carries active lowering authority");
			}
			continue;
		}
		const bool retained_packets = limits.retained_packet_capacity() != 0u;
		const bool retained_bytes = limits.retained_byte_capacity() != 0u;
		const bool timer = (stage.trigger_mask() & TIMER) != 0u;
		const bool control = (stage.trigger_mask() & CONTROL) != 0u;
		const bool control_fields_present = limits.control_mailbox_capacity() != 0u ||
						    limits.control_message_capacity_bytes() != 0u;
		const bool control_capacity_valid =
			limits.control_mailbox_capacity() >= 2u &&
			(limits.control_mailbox_capacity() & (limits.control_mailbox_capacity() - 1u)) == 0u &&
			limits.control_message_capacity_bytes() != 0u;
		const bool async_capacity_present = limits.async_work_capacity() != 0u;
		const bool async_grace_present = limits.async_cancel_grace_ms() != 0u;
		if (stage.kind() != kinetum::axiom::v1::STAGE_KIND_MODULE || stage.trigger_mask() == 0u ||
		    (stage.trigger_mask() & ~KNOWN) != 0u || retained_packets != retained_bytes ||
		    (retained_packets && limits.retained_byte_capacity() < limits.retained_packet_capacity()) ||
		    timer != (limits.timer_capacity() != 0u) || control != control_fields_present ||
		    (control_fields_present && !control_capacity_valid) ||
		    async_capacity_present != async_grace_present ||
		    control != (inbound_control[stage.stage_id()] != 0u) ||
		    ((stage.trigger_mask() & PULL) != 0u) != (outbound_pull[stage.stage_id()] != 0u)) {
			return status::invalid_argument(
				"active stage lowering contract is incomplete or contradictory");
		}
	}
	return status::ok();
}

}  // namespace

common::status lower_execution_topology(kinetum::gluon::v1::DeploymentPlan &plan,
					const kinetum::gluon::v1::DeploymentBindings &bindings)
{
	namespace topo = kinetum::common::execution_topology;

	plan.clear_execution_lanes();
	plan.clear_stage_instances();
	plan.clear_io_streams();
	plan.clear_traffic_steering_profiles();
	plan.clear_module_context_domains();
	plan.clear_worker_placements();

	std::unordered_map<std::string, int32_t> stage_regions;
	if (const auto region_status = build_stage_region_map(plan, stage_regions); !region_status.is_ok()) {
		return region_status;
	}
	if (const auto active_status = validate_active_stage_lowering(plan, stage_regions); !active_status.is_ok()) {
		return active_status;
	}
	std::unordered_map<std::string, const kinetum::gluon::v1::PortConfig *> ports;
	if (const auto port_status = build_port_lookup(plan, ports); !port_status.is_ok()) {
		return port_status;
	}
	std::map<stream_binding_key, stream_binding> stream_bindings;
	if (const auto stream_status = build_stream_bindings(bindings, plan, stream_bindings); !stream_status.is_ok()) {
		return stream_status;
	}
	std::unordered_map<std::string, std::string> execution_by_stage;
	if (const auto execution_status = build_stage_execution_bindings(bindings, plan, execution_by_stage);
	    !execution_status.is_ok()) {
		return execution_status;
	}

	std::vector<io_stage_plan> io_stages;
	io_stages.reserve(static_cast<std::size_t>(plan.pipeline().stages_size()));
	std::set<stream_binding_key> consumed_stream_bindings;
	std::size_t lane_count = 1u;

	for (const auto &stage : plan.pipeline().stages()) {
		if (!topo::is_topology_identifier(stage.stage_id())) {
			return status::invalid_argument("stage_id '" + stage.stage_id() +
							"' cannot form an injective stage-instance ID");
		}
		kinetum::gluon::v1::IoStreamDirection direction = kinetum::gluon::v1::IO_STREAM_DIRECTION_UNSPECIFIED;
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_RX) {
			direction = kinetum::gluon::v1::IO_STREAM_DIRECTION_RX;
		} else if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_TX) {
			direction = kinetum::gluon::v1::IO_STREAM_DIRECTION_TX;
		} else {
			continue;
		}

		const std::string logical_name(kinetum::axiom::stage_interface(stage));
		const auto port_it = ports.find(logical_name);
		if (port_it == ports.end()) {
			return status::invalid_argument("I/O stage '" + stage.stage_id() +
							"' references unknown logical port '" + logical_name + "'");
		}
		if (!port_direction_allows(port_it->second->direction(), direction)) {
			return status::invalid_argument("I/O stage '" + stage.stage_id() +
							"' direction disagrees with logical port");
		}
		const stream_binding_key key{logical_name, direction};
		const auto binding_it = stream_bindings.find(key);
		if (binding_it == stream_bindings.end()) {
			return status::invalid_argument("I/O stage '" + stage.stage_id() +
							"' has no explicit queue binding");
		}
		if (!consumed_stream_bindings.insert(key).second) {
			return status::invalid_argument("multiple I/O stages claim one logical port/direction binding");
		}
		lane_count = std::max(lane_count, binding_it->second.queues.size());
		io_stages.push_back(
			io_stage_plan{&stage, port_it->second, binding_it->second, stage_regions.at(stage.stage_id())});
	}

	if (consumed_stream_bindings.size() != stream_bindings.size()) {
		return status::invalid_argument(
			"io_stream_bindings[] contains a logical port/direction unused by the pipeline");
	}
	for (const auto &io_stage : io_stages) {
		if (io_stage.binding.queues.size() != lane_count) {
			return status::invalid_argument(
				"every I/O direction must declare the same explicit queue count");
		}
	}
	std::map<std::pair<std::string, std::string>, std::string> active_origin_storage_by_stage_lane;
	if (const auto active_origin_status =
		    build_active_origin_bindings(bindings, plan, lane_count, active_origin_storage_by_stage_lane);
	    !active_origin_status.is_ok()) {
		return active_origin_status;
	}
	auto module_resources_or = build_module_context_resource_bindings(bindings, plan, lane_count);
	if (!module_resources_or.is_ok()) {
		return module_resources_or.error();
	}
	auto module_resources_by_stage_lane = std::move(module_resources_or.value());

	std::vector<kinetum::gluon::v1::ExecutionLane *> lanes;
	lanes.reserve(lane_count);
	for (std::size_t lane_index = 0; lane_index < lane_count; ++lane_index) {
		const auto lane_id = topo::make_lane_id(static_cast<uint32_t>(lane_index));
		auto *lane = plan.add_execution_lanes();
		lane->set_lane_id(lane_id);
		lane->set_lane_index(static_cast<uint32_t>(lane_index));
		lanes.push_back(lane);
	}

	std::unordered_set<std::string> stage_instance_ids;
	std::map<std::string, std::vector<std::string>> module_contexts_by_id;
	stage_instance_ids.reserve(static_cast<std::size_t>(plan.pipeline().stages_size()) * lane_count);
	const std::size_t logical_stage_count = static_cast<std::size_t>(plan.pipeline().stages_size());
	for (std::size_t lane_index = 0; lane_index < lane_count; ++lane_index) {
		const auto lane_id = topo::make_lane_id(static_cast<uint32_t>(lane_index));
		for (std::size_t stage_index = 0; stage_index < logical_stage_count; ++stage_index) {
			const auto &stage = plan.pipeline().stages(static_cast<int>(stage_index));
			const auto stage_instance_id = topo::make_stage_instance_id(stage.stage_id(), lane_id);
			if (!stage_instance_ids.insert(stage_instance_id).second) {
				return status::invalid_argument("duplicate generated stage_instance_id '" +
								stage_instance_id + "'");
			}
			auto *instance = plan.add_stage_instances();
			instance->set_stage_instance_id(stage_instance_id);
			instance->set_logical_stage_id(stage.stage_id());
			instance->set_lane_id(lane_id);
			instance->set_region_id(stage_regions.at(stage.stage_id()));
			instance->set_replica_index(static_cast<uint32_t>(lane_index));
			if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
				instance->set_context_instance_id(stage_instance_id);
				module_contexts_by_id[stage.module().module_id()].push_back(stage_instance_id);
				const auto &resource_slot =
					module_resources_by_stage_lane[stage_index * lane_count + lane_index];
				if (!resource_slot.present) {
					return status::internal_error(
						"module-context resource table lost exact stage/lane coverage");
				}
				const auto &resources = resource_slot.resources;
				instance->set_context_memory_capacity_bytes(resources.context_memory_capacity_bytes);
				instance->set_epoch_arena_capacity_bytes(resources.epoch_arena_capacity_bytes);
			}
			instance->set_execution_provider_instance_id(execution_by_stage.at(stage.stage_id()));
			if (stage.execution_mode() == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
				instance->set_active_origin_storage_domain_id(active_origin_storage_by_stage_lane.at(
					std::make_pair(stage.stage_id(), lane_id)));
			}
			lanes[lane_index]->add_stage_instance_ids(stage_instance_id);
		}
	}

	for (int32_t region_id = 0; region_id < plan.regions_size(); ++region_id) {
		for (std::size_t lane_index = 0; lane_index < lane_count; ++lane_index) {
			const auto lane_id = topo::make_lane_id(static_cast<uint32_t>(lane_index));
			auto *worker = plan.add_worker_placements();
			worker->set_worker_id(topo::make_worker_id(region_id, lane_id));
			worker->set_region_id(region_id);
			worker->set_lane_id(lane_id);
		}
	}

	std::unordered_set<std::string> io_stream_ids;
	io_stream_ids.reserve(io_stages.size() * lane_count);
	std::map<std::string, steering_profile_emission> steering_profiles;
	for (const auto &io_stage : io_stages) {
		for (std::size_t lane_index = 0; lane_index < lane_count; ++lane_index) {
			const auto lane_id = topo::make_lane_id(static_cast<uint32_t>(lane_index));
			const auto direction = io_stage.stage->kind() == kinetum::axiom::v1::STAGE_KIND_RX ?
						       kinetum::gluon::v1::IO_STREAM_DIRECTION_RX :
						       kinetum::gluon::v1::IO_STREAM_DIRECTION_TX;
			const auto stream_id = topo::make_io_stream_id(io_stage.port->logical_name(),
								       stream_direction_suffix(direction), lane_id);
			if (!io_stream_ids.insert(stream_id).second) {
				return status::invalid_argument("duplicate generated io_stream_id '" + stream_id + "'");
			}

			std::string steering_profile_id;
			if (direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				steering_profile_id = io_stage.binding.steering_kind ==
								      kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS ?
							      rss_profile_id_for_port(io_stage.port->logical_name()) :
							      none_profile_id_for_port(io_stage.port->logical_name());
				auto &profile = steering_profiles[steering_profile_id];
				if (profile.steering_profile_id.empty()) {
					profile.steering_profile_id = steering_profile_id;
					profile.kind = io_stage.binding.steering_kind;
					profile.symmetric = io_stage.binding.symmetric;
					profile.hash_fields = io_stage.binding.hash_fields;
					profile.hash_key = io_stage.binding.hash_key;
				}
				profile.stream_ids.push_back(stream_id);
			}

			auto *stream = plan.add_io_streams();
			stream->set_io_stream_id(stream_id);
			stream->set_logical_port_id(io_stage.port->logical_port_id());
			stream->set_lane_id(lane_id);
			stream->set_direction(direction);
			stream->set_stage_instance_id(
				topo::make_stage_instance_id(io_stage.stage->stage_id(), lane_id));
			stream->set_steering_profile_id(steering_profile_id);
			const auto &queue = io_stage.binding.queues[lane_index];
			stream->set_driver_queue_id(queue.driver_queue_id());
			stream->set_owning_worker_id(topo::make_worker_id(io_stage.region_id, lane_id));
			if (direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				stream->set_rx_storage_domain_id(queue.rx_storage_domain_id());
			} else {
				stream->mutable_tx_storage()->CopyFrom(queue.tx_storage());
			}
			stream->set_descriptor_count(queue.descriptor_count());
			lanes[lane_index]->add_io_stream_ids(stream_id);
		}
	}

	for (const auto &[profile_id, profile] : steering_profiles) {
		(void)profile_id;
		auto *out = plan.add_traffic_steering_profiles();
		out->set_steering_profile_id(profile.steering_profile_id);
		out->set_kind(profile.kind);
		out->set_symmetric(profile.symmetric);
		for (const auto &field : profile.hash_fields) {
			out->add_hash_fields(field);
		}
		out->set_hash_key(profile.hash_key);
		for (const auto &stream_id : profile.stream_ids) {
			out->add_stream_ids(stream_id);
		}
	}

	for (const auto &[module_id, context_ids] : module_contexts_by_id) {
		auto *domain = plan.add_module_context_domains();
		domain->set_module_id(module_id);
		for (const auto &context_id : context_ids) {
			domain->add_context_instance_ids(context_id);
		}
	}

	sort_emitted_topology(plan);
	return status::ok();
}

}  // namespace kinetum::gluon
