// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file deployment_bindings_lowering.cpp
 * @brief Exact DeploymentBindings validation and deterministic plan lowering.
 * @author Fleming Patel
 */

#include "src/gluon/deployment_bindings_lowering.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <kinetum/kinetum_sdk.h>
#include "gen/kinetum/io/dpdk/v1/dpdk_driver.pb.h"
#include "gen/kinetum/io/udp/v1/udp_driver.pb.h"
#include "src/axiom/stage_configuration.hpp"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/status_or.hpp"
#include "src/gluon/topology_lowering.hpp"
#include "src/provider/deployment_plan_identity.hpp"
#include "src/provider/provider_contract_catalog.hpp"

namespace kinetum::gluon
{

namespace
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

/** Bit marking a logical port's required ingress use. */
constexpr uint8_t REQUIRED_RX = 1u;
/** Bit marking a logical port's required egress use. */
constexpr uint8_t REQUIRED_TX = 2u;

/** @brief Native attachment category needed only for authoring-time resolution. */
enum class driver_attachment_kind : uint8_t {
	DPDK_PCI,  ///< Exact PCI function requiring hardware-inventory agreement.
	DPDK_TAP,  ///< Exact DPDK TAP attachment with no physical inventory record.
	UDP,	   ///< Exact numeric UDP endpoint.
};

/** @brief Canonical driver-local port fact extracted from typed configuration. */
struct driver_port_fact {
	driver_attachment_kind kind{driver_attachment_kind::UDP};  ///< Attachment resolution policy.
	std::string pci_address;				   ///< Exact PCI BDF for DPDK_PCI.
};

/** @brief Pipeline-required direction set for one logical interface. */
struct required_interface {
	uint8_t directions{0};	///< Bitwise union of REQUIRED_RX and REQUIRED_TX.
};

/**
 * @brief Validate one topology identifier.
 *
 * @param field Stable field name used in diagnostics.
 * @param value Candidate identifier.
 * @return OK only for the shared topology grammar.
 */
[[nodiscard]] status validate_identifier(std::string_view field, std::string_view value)
{
	if (value.size() > kinetum::provider::MAX_PROVIDER_ID_BYTES) {
		return status(status_code::INVALID_ARGUMENT,
			      std::string(field) + " exceeds the " +
				      std::to_string(kinetum::provider::MAX_PROVIDER_ID_BYTES) +
				      "-byte identity bound");
	}
	if (!kinetum::common::execution_topology::is_topology_identifier(value)) {
		return status(status_code::INVALID_ARGUMENT,
			      std::string(field) + " '" + std::string(value) + "' is not a valid topology identifier");
	}
	return status::ok();
}

/**
 * @brief Validate one declared facility-reference set without resolving it.
 *
 * @tparam repeated_strings Protobuf repeated-string container type.
 * @param owner_kind Stable owner category.
 * @param owner_id Exact owner identity.
 * @param refs Authored facility-reference set.
 * @return OK only when every identity is valid and appears once.
 */
template <typename repeated_strings>
[[nodiscard]] status validate_facility_reference_shape(std::string_view owner_kind, std::string_view owner_id,
						       const repeated_strings &refs)
{
	std::unordered_set<std::string> observed;
	observed.reserve(static_cast<std::size_t>(refs.size()));
	for (const auto &facility_id : refs) {
		if (const auto id_status = validate_identifier("facility_instance_id", facility_id);
		    !id_status.is_ok()) {
			return status(status_code::INVALID_ARGUMENT,
				      std::string(owner_kind) + " '" + std::string(owner_id) +
					      "' has invalid facility reference '" + facility_id + "'");
		}
		if (!observed.insert(facility_id).second) {
			return status(status_code::INVALID_ARGUMENT,
				      std::string(owner_kind) + " '" + std::string(owner_id) +
					      "' has duplicate facility reference '" + facility_id + "'");
		}
	}
	return status::ok();
}

/**
 * @brief Sort one already validated repeated-string set.
 *
 * @tparam repeated_strings Protobuf repeated-string container type.
 * @param values Mutable duplicate-free set.
 */
template <typename repeated_strings>
void sort_string_set(repeated_strings *values)
{
	std::sort(values->begin(), values->end());
}

/**
 * @brief Check whether a port direction names an exact admitted operation set.
 *
 * @param direction Candidate port direction.
 * @return true only for RX, TX, or bidirectional.
 */
[[nodiscard]] constexpr bool is_exact_port_direction(kinetum::gluon::v1::PortDirection direction) noexcept
{
	return direction == kinetum::gluon::v1::PORT_DIRECTION_RX_ONLY ||
	       direction == kinetum::gluon::v1::PORT_DIRECTION_TX_ONLY ||
	       direction == kinetum::gluon::v1::PORT_DIRECTION_BIDIRECTIONAL;
}

/**
 * @brief Check whether a stream direction names one executable operation.
 *
 * @param direction Candidate stream direction.
 * @return true only for RX or TX.
 */
[[nodiscard]] constexpr bool is_exact_stream_direction(kinetum::gluon::v1::IoStreamDirection direction) noexcept
{
	return direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX ||
	       direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_TX;
}

/**
 * @brief Validate one authored logical endpoint's scalar shape.
 *
 * @param field Stable endpoint field name.
 * @param endpoint Candidate endpoint.
 * @return OK only for one exact, well-formed endpoint identity.
 */
[[nodiscard]] status validate_endpoint_shape(std::string_view field,
					     const kinetum::gluon::v1::LogicalPacketPathEndpoint &endpoint)
{
	switch (endpoint.endpoint_case()) {
	case kinetum::gluon::v1::LogicalPacketPathEndpoint::kIo:
		if (const auto id_status = validate_identifier("logical_name", endpoint.io().logical_name());
		    !id_status.is_ok()) {
			return status(status_code::INVALID_ARGUMENT,
				      std::string(field) + " has an invalid logical_name");
		}
		if (!is_exact_stream_direction(endpoint.io().direction())) {
			return status::invalid_argument(std::string(field) + " has an unspecified I/O direction");
		}
		return status::ok();
	case kinetum::gluon::v1::LogicalPacketPathEndpoint::kStage:
		if (const auto id_status = validate_identifier("logical_stage_id", endpoint.stage().logical_stage_id());
		    !id_status.is_ok()) {
			return status(status_code::INVALID_ARGUMENT,
				      std::string(field) + " has an invalid logical_stage_id");
		}
		if (const auto id_status = validate_identifier("lane_id", endpoint.stage().lane_id());
		    !id_status.is_ok()) {
			return status(status_code::INVALID_ARGUMENT, std::string(field) + " has an invalid lane_id");
		}
		return status::ok();
	case kinetum::gluon::v1::LogicalPacketPathEndpoint::ENDPOINT_NOT_SET:
		return status::invalid_argument(std::string(field) + " must select exactly one endpoint");
	}
	return status::invalid_argument(std::string(field) + " contains an unknown endpoint case");
}

/**
 * @brief Validate every DeploymentBindings identifier, duplicate, and scalar.
 *
 * This pass deliberately performs no provider-catalog lookup and resolves no
 * reference. Completing the whole pass first makes the authoring ladder
 * independent of authored array order.
 *
 * @param bindings Complete authored deployment intent.
 * @return OK only when the complete scalar surface is well formed.
 */
[[nodiscard]] status validate_binding_scalar_contracts(const kinetum::gluon::v1::DeploymentBindings &bindings)
{
	std::unordered_set<std::string> facility_ids;
	facility_ids.reserve(static_cast<std::size_t>(bindings.process_facility_instances_size()));
	for (const auto &facility : bindings.process_facility_instances()) {
		if (const auto id_status = validate_identifier("facility_instance_id", facility.facility_instance_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!facility_ids.insert(facility.facility_instance_id()).second) {
			return status::invalid_argument("duplicate facility_instance_id '" +
							facility.facility_instance_id() + "'");
		}
	}

	std::unordered_set<std::string> driver_ids;
	driver_ids.reserve(static_cast<std::size_t>(bindings.io_driver_instances_size()));
	for (const auto &driver : bindings.io_driver_instances()) {
		if (const auto id_status = validate_identifier("io_driver_instance_id", driver.io_driver_instance_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!driver_ids.insert(driver.io_driver_instance_id()).second) {
			return status::invalid_argument("duplicate io_driver_instance_id '" +
							driver.io_driver_instance_id() + "'");
		}
		if (const auto refs_status = validate_facility_reference_shape(
			    "I/O driver instance", driver.io_driver_instance_id(), driver.facility_instance_ids());
		    !refs_status.is_ok()) {
			return refs_status;
		}
	}

	std::unordered_set<std::string> storage_ids;
	storage_ids.reserve(static_cast<std::size_t>(bindings.packet_storage_domains_size()));
	for (const auto &storage : bindings.packet_storage_domains()) {
		if (const auto id_status = validate_identifier("storage_domain_id", storage.storage_domain_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!storage_ids.insert(storage.storage_domain_id()).second) {
			return status::invalid_argument("duplicate storage_domain_id '" + storage.storage_domain_id() +
							"'");
		}
		if (storage.buffer_count() == 0 || storage.data_room_bytes() == 0 || storage.alignment_bytes() == 0) {
			return status::invalid_argument(
				"packet storage domain '" + storage.storage_domain_id() +
				"' requires nonzero buffer_count, data_room_bytes, and alignment_bytes");
		}
		if ((storage.alignment_bytes() & (storage.alignment_bytes() - 1u)) != 0u) {
			return status::invalid_argument("packet storage domain '" + storage.storage_domain_id() +
							"' alignment_bytes must be a power of two");
		}
		if (storage.headroom_bytes() >= storage.data_room_bytes()) {
			return status::invalid_argument("packet storage domain '" + storage.storage_domain_id() +
							"' headroom_bytes must be smaller than data_room_bytes");
		}
		if (storage.has_host_numa_node() && storage.host_numa_node() < 0) {
			return status::invalid_argument("packet storage domain '" + storage.storage_domain_id() +
							"' host_numa_node must be nonnegative when present");
		}
		if (const auto refs_status = validate_facility_reference_shape(
			    "packet storage domain", storage.storage_domain_id(), storage.facility_instance_ids());
		    !refs_status.is_ok()) {
			return refs_status;
		}
	}

	std::unordered_set<std::string> execution_ids;
	execution_ids.reserve(static_cast<std::size_t>(bindings.execution_provider_instances_size()));
	for (const auto &execution : bindings.execution_provider_instances()) {
		if (const auto id_status = validate_identifier("execution_provider_instance_id",
							       execution.execution_provider_instance_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!execution_ids.insert(execution.execution_provider_instance_id()).second) {
			return status::invalid_argument("duplicate execution_provider_instance_id '" +
							execution.execution_provider_instance_id() + "'");
		}
		if (const auto refs_status = validate_facility_reference_shape(
			    "execution provider instance", execution.execution_provider_instance_id(),
			    execution.facility_instance_ids());
		    !refs_status.is_ok()) {
			return refs_status;
		}
	}

	std::unordered_set<std::string> logical_names;
	logical_names.reserve(static_cast<std::size_t>(bindings.logical_port_bindings_size()));
	std::set<std::pair<std::string, std::string>> driver_port_claims;
	for (const auto &binding : bindings.logical_port_bindings()) {
		if (const auto id_status = validate_identifier("logical_name", binding.logical_name());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto id_status =
			    validate_identifier("io_driver_instance_id", binding.io_driver_instance_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto id_status = validate_identifier("driver_port_id", binding.driver_port_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!logical_names.insert(binding.logical_name()).second) {
			return status::invalid_argument("duplicate logical-port binding for '" +
							binding.logical_name() + "'");
		}
		if (!driver_port_claims.emplace(binding.io_driver_instance_id(), binding.driver_port_id()).second) {
			return status::invalid_argument("driver-local port '" + binding.io_driver_instance_id() + "/" +
							binding.driver_port_id() +
							"' is bound to more than one logical port");
		}
		if (!is_exact_port_direction(binding.direction())) {
			return status::invalid_argument("logical-port binding '" + binding.logical_name() +
							"' has an unspecified direction");
		}
		if (binding.mtu() == 0 || binding.mtu() > static_cast<uint32_t>(std::numeric_limits<uint16_t>::max())) {
			return status::invalid_argument("logical-port binding '" + binding.logical_name() +
							"' has an invalid exact MTU");
		}
		if (binding.has_host_numa_node() && binding.host_numa_node() < 0) {
			return status::invalid_argument("logical-port binding '" + binding.logical_name() +
							"' host_numa_node must be nonnegative when present");
		}
	}

	std::set<std::pair<std::string, int>> stream_keys;
	for (const auto &binding : bindings.io_stream_bindings()) {
		if (const auto id_status = validate_identifier("logical_name", binding.logical_name());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!is_exact_stream_direction(binding.direction())) {
			return status::invalid_argument("I/O-stream binding for '" + binding.logical_name() +
							"' has an unspecified direction");
		}
		if (!stream_keys.emplace(binding.logical_name(), static_cast<int>(binding.direction())).second) {
			return status::invalid_argument("duplicate I/O-stream binding for logical port '" +
							binding.logical_name() + "'");
		}
		if (binding.queues_size() == 0) {
			return status::invalid_argument("I/O-stream binding for '" + binding.logical_name() +
							"' requires at least one explicit queue");
		}
		std::unordered_set<uint32_t> queue_ids;
		queue_ids.reserve(static_cast<std::size_t>(binding.queues_size()));
		for (const auto &queue : binding.queues()) {
			if (!queue_ids.insert(queue.driver_queue_id()).second) {
				return status::invalid_argument("I/O-stream binding for '" + binding.logical_name() +
								"' contains duplicate driver_queue_id");
			}
			if (queue.descriptor_count() == 0) {
				return status::invalid_argument("I/O-stream binding for '" + binding.logical_name() +
								"' has a queue with zero descriptor_count");
			}
			if (binding.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				if (!queue.has_rx_storage_domain_id()) {
					return status::invalid_argument(
						"RX queue requires its allocation storage domain");
				}
				if (const auto valid =
					    validate_identifier("rx_storage_domain_id", queue.rx_storage_domain_id());
				    !valid.is_ok()) {
					return valid;
				}
			} else if (!queue.has_tx_storage()) {
				return status::invalid_argument("TX queue requires its storage admission set");
			}
		}
		if (!binding.has_steering()) {
			return status::invalid_argument("I/O-stream binding for '" + binding.logical_name() +
							"' requires an explicit steering contract");
		}

		const auto &steering = binding.steering();
		switch (steering.kind()) {
		case kinetum::gluon::v1::TRAFFIC_STEERING_KIND_NONE:
			if (steering.symmetric() || !steering.hash_fields().empty() || !steering.hash_key().empty()) {
				return status::invalid_argument("no-steering binding for '" + binding.logical_name() +
								"' must not carry steering parameters");
			}
			if (binding.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX &&
			    binding.queues_size() > 1) {
				return status::invalid_argument("multi-queue RX binding for '" +
								binding.logical_name() +
								"' requires exact RSS steering");
			}
			break;
		case kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS: {
			if (binding.direction() != kinetum::gluon::v1::IO_STREAM_DIRECTION_RX ||
			    binding.queues_size() < 2 || steering.hash_fields().empty() ||
			    steering.hash_key().empty()) {
				return status::invalid_argument("RSS binding for '" + binding.logical_name() +
								"' requires RX, at least two queues, "
								"nonempty fields, and an exact key");
			}
			std::unordered_set<std::string> hash_fields;
			hash_fields.reserve(static_cast<std::size_t>(steering.hash_fields_size()));
			for (const auto &field : steering.hash_fields()) {
				if (const auto id_status = validate_identifier("RSS hash field", field);
				    !id_status.is_ok()) {
					return id_status;
				}
				if (!hash_fields.insert(field).second) {
					return status::invalid_argument("RSS binding for '" + binding.logical_name() +
									"' contains a duplicate hash field");
				}
			}
			break;
		}
		case kinetum::gluon::v1::TRAFFIC_STEERING_KIND_UNSPECIFIED:
		case kinetum::gluon::v1::TrafficSteeringKind_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::gluon::v1::TrafficSteeringKind_INT_MAX_SENTINEL_DO_NOT_USE_:
			return status::invalid_argument("I/O-stream binding for '" + binding.logical_name() +
							"' requests unsupported steering kind");
		}
	}

	std::unordered_set<std::string> stage_ids;
	stage_ids.reserve(static_cast<std::size_t>(bindings.stage_execution_bindings_size()));
	for (const auto &binding : bindings.stage_execution_bindings()) {
		if (const auto id_status = validate_identifier("logical_stage_id", binding.logical_stage_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto id_status = validate_identifier("execution_provider_instance_id",
							       binding.execution_provider_instance_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!stage_ids.insert(binding.logical_stage_id()).second) {
			return status::invalid_argument("duplicate stage-execution binding for '" +
							binding.logical_stage_id() + "'");
		}
	}

	std::set<std::pair<std::string, std::string>> active_origin_keys;
	for (const auto &binding : bindings.active_origin_bindings()) {
		if (const auto id_status = validate_identifier("logical_stage_id", binding.logical_stage_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto id_status = validate_identifier("lane_id", binding.lane_id()); !id_status.is_ok()) {
			return id_status;
		}
		if (const auto id_status = validate_identifier("storage_domain_id", binding.storage_domain_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!active_origin_keys.emplace(binding.logical_stage_id(), binding.lane_id()).second) {
			return status::invalid_argument("duplicate active-origin binding for stage/lane '" +
							binding.logical_stage_id() + "/" + binding.lane_id() + "'");
		}
	}

	std::vector<std::pair<std::string_view, std::string_view>> module_context_resource_keys;
	module_context_resource_keys.reserve(
		static_cast<std::size_t>(bindings.module_context_resource_bindings_size()));
	for (const auto &binding : bindings.module_context_resource_bindings()) {
		if (const auto id_status = validate_identifier("logical_stage_id", binding.logical_stage_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto id_status = validate_identifier("lane_id", binding.lane_id()); !id_status.is_ok()) {
			return id_status;
		}
		if (binding.context_memory_capacity_bytes() == 0u || binding.epoch_arena_capacity_bytes() == 0u) {
			return status::invalid_argument("module-context resource binding for stage/lane '" +
							binding.logical_stage_id() + "/" + binding.lane_id() +
							"' requires nonzero context and epoch capacities");
		}
		module_context_resource_keys.emplace_back(binding.logical_stage_id(), binding.lane_id());
	}
	std::sort(module_context_resource_keys.begin(), module_context_resource_keys.end());
	const auto duplicate_module_context =
		std::adjacent_find(module_context_resource_keys.begin(), module_context_resource_keys.end());
	if (duplicate_module_context != module_context_resource_keys.end()) {
		return status::invalid_argument("duplicate module-context resource binding for stage/lane '" +
						std::string(duplicate_module_context->first) + "/" +
						std::string(duplicate_module_context->second) + "'");
	}

	std::unordered_set<std::string> transition_ids;
	transition_ids.reserve(static_cast<std::size_t>(bindings.storage_transition_bindings_size()));
	for (const auto &binding : bindings.storage_transition_bindings()) {
		if (const auto id_status = validate_identifier("transition_id", binding.transition_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!transition_ids.insert(binding.transition_id()).second) {
			return status::invalid_argument("duplicate storage transition '" + binding.transition_id() +
							"'");
		}
		if (const auto endpoint_status =
			    validate_endpoint_shape("storage-transition source", binding.from_endpoint());
		    !endpoint_status.is_ok()) {
			return endpoint_status;
		}
		if (const auto endpoint_status =
			    validate_endpoint_shape("storage-transition destination", binding.to_endpoint());
		    !endpoint_status.is_ok()) {
			return endpoint_status;
		}
		if (const auto id_status =
			    validate_identifier("from_storage_domain_id", binding.from_storage_domain_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto id_status = validate_identifier("to_storage_domain_id", binding.to_storage_domain_id());
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto refs_status = validate_facility_reference_shape(
			    "storage transition", binding.transition_id(), binding.facility_instance_ids());
		    !refs_status.is_ok()) {
			return refs_status;
		}
		if (binding.has_staging_numa_node() && binding.staging_numa_node() < 0) {
			return status::invalid_argument("storage transition '" + binding.transition_id() +
							"' staging_numa_node must be nonnegative when present");
		}
	}
	return status::ok();
}

/**
 * @brief Normalize every authoring array declared set-like by identity.
 *
 * @param bindings Mutable scalar-validated authoring message.
 * @return OK after normalization, or an invalid TX storage-set error.
 */
[[nodiscard]] status normalize_binding_set_order(kinetum::gluon::v1::DeploymentBindings *bindings)
{
	std::sort(bindings->mutable_process_facility_instances()->begin(),
		  bindings->mutable_process_facility_instances()->end(), [](const auto &lhs, const auto &rhs) {
			  return lhs.facility_instance_id() < rhs.facility_instance_id();
		  });
	std::sort(bindings->mutable_io_driver_instances()->begin(), bindings->mutable_io_driver_instances()->end(),
		  [](const auto &lhs, const auto &rhs) {
			  return lhs.io_driver_instance_id() < rhs.io_driver_instance_id();
		  });
	std::sort(bindings->mutable_packet_storage_domains()->begin(),
		  bindings->mutable_packet_storage_domains()->end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.storage_domain_id() < rhs.storage_domain_id(); });
	std::sort(bindings->mutable_execution_provider_instances()->begin(),
		  bindings->mutable_execution_provider_instances()->end(), [](const auto &lhs, const auto &rhs) {
			  return lhs.execution_provider_instance_id() < rhs.execution_provider_instance_id();
		  });
	std::sort(bindings->mutable_logical_port_bindings()->begin(), bindings->mutable_logical_port_bindings()->end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.logical_name() < rhs.logical_name(); });
	std::sort(bindings->mutable_io_stream_bindings()->begin(), bindings->mutable_io_stream_bindings()->end(),
		  [](const auto &lhs, const auto &rhs) {
			  return std::make_tuple(lhs.logical_name(), lhs.direction()) <
				 std::make_tuple(rhs.logical_name(), rhs.direction());
		  });
	std::sort(bindings->mutable_stage_execution_bindings()->begin(),
		  bindings->mutable_stage_execution_bindings()->end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.logical_stage_id() < rhs.logical_stage_id(); });
	std::sort(bindings->mutable_active_origin_bindings()->begin(),
		  bindings->mutable_active_origin_bindings()->end(), [](const auto &lhs, const auto &rhs) {
			  return std::tie(lhs.logical_stage_id(), lhs.lane_id()) <
				 std::tie(rhs.logical_stage_id(), rhs.lane_id());
		  });
	std::sort(bindings->mutable_module_context_resource_bindings()->begin(),
		  bindings->mutable_module_context_resource_bindings()->end(), [](const auto &lhs, const auto &rhs) {
			  return std::tie(lhs.logical_stage_id(), lhs.lane_id()) <
				 std::tie(rhs.logical_stage_id(), rhs.lane_id());
		  });
	std::sort(bindings->mutable_storage_transition_bindings()->begin(),
		  bindings->mutable_storage_transition_bindings()->end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.transition_id() < rhs.transition_id(); });

	for (auto &driver : *bindings->mutable_io_driver_instances()) {
		sort_string_set(driver.mutable_facility_instance_ids());
	}
	for (auto &storage : *bindings->mutable_packet_storage_domains()) {
		sort_string_set(storage.mutable_facility_instance_ids());
	}
	for (auto &execution : *bindings->mutable_execution_provider_instances()) {
		sort_string_set(execution.mutable_facility_instance_ids());
	}
	for (auto &stream : *bindings->mutable_io_stream_bindings()) {
		for (auto &queue : *stream.mutable_queues()) {
			if (queue.has_tx_storage()) {
				if (const auto normalized = kinetum::provider::canonicalize_tx_storage_binding(
					    queue.mutable_tx_storage());
				    !normalized.is_ok()) {
					return normalized;
				}
			}
		}
		std::sort(stream.mutable_queues()->begin(), stream.mutable_queues()->end(),
			  [](const auto &lhs, const auto &rhs) {
				  return lhs.driver_queue_id() < rhs.driver_queue_id();
			  });
	}
	for (auto &transition : *bindings->mutable_storage_transition_bindings()) {
		sort_string_set(transition.mutable_facility_instance_ids());
	}
	return status::ok();
}

/**
 * @brief Require every local facility reference to resolve.
 *
 * @tparam repeated_strings Protobuf repeated-string container type.
 * @param owner_kind Stable owner category.
 * @param owner_id Exact owner identity.
 * @param refs Canonical facility-reference set.
 * @param facility_ids Complete locally declared facility identities.
 * @return OK only when every reference resolves.
 */
template <typename repeated_strings>
[[nodiscard]] status validate_facility_references(std::string_view owner_kind, std::string_view owner_id,
						  const repeated_strings &refs,
						  const std::unordered_set<std::string> &facility_ids)
{
	for (const auto &facility_id : refs) {
		if (facility_ids.find(facility_id) == facility_ids.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      std::string(owner_kind) + " '" + std::string(owner_id) +
					      "' references unknown facility_instance_id '" + facility_id + "'");
		}
	}
	return status::ok();
}

/**
 * @brief Canonicalize one role-owned provider configuration.
 *
 * @param role Exact enclosing provider role.
 * @param configuration Mutable Any envelope.
 * @return OK after exact canonical repack, or the catalog failure.
 */
[[nodiscard]] status canonicalize_configuration(kinetum::provider::provider_contract_role role,
						google::protobuf::Any *configuration)
{
	if (configuration == nullptr) {
		return status::internal_error("provider configuration destination must not be null");
	}
	auto canonical_or = kinetum::provider::canonicalize_provider_configuration(role, *configuration);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	configuration->CopyFrom(canonical_or.value().configuration);
	return status::ok();
}

/**
 * @brief Canonicalize every role-owned provider configuration as one pass.
 *
 * No local reference is inspected until this pass succeeds for the complete
 * message. That preserves the catalog stage even when an earlier authored
 * record has a bad reference and a later record has malformed provider bytes.
 *
 * @param bindings Mutable normalized authoring message.
 * @return OK after every Any is role-correct and byte-canonical.
 */
[[nodiscard]] status canonicalize_binding_configurations(kinetum::gluon::v1::DeploymentBindings *bindings)
{
	if (bindings == nullptr) {
		return status::internal_error("deployment bindings destination must not be null");
	}
	for (auto &facility : *bindings->mutable_process_facility_instances()) {
		const auto canonical_status = canonicalize_configuration(
			kinetum::provider::provider_contract_role::PROCESS_FACILITY, facility.mutable_configuration());
		if (!canonical_status.is_ok()) {
			return canonical_status;
		}
	}
	for (auto &driver : *bindings->mutable_io_driver_instances()) {
		const auto canonical_status = canonicalize_configuration(
			kinetum::provider::provider_contract_role::IO_DRIVER, driver.mutable_configuration());
		if (!canonical_status.is_ok()) {
			return canonical_status;
		}
	}
	for (auto &storage : *bindings->mutable_packet_storage_domains()) {
		const auto canonical_status = canonicalize_configuration(
			kinetum::provider::provider_contract_role::PACKET_STORAGE, storage.mutable_configuration());
		if (!canonical_status.is_ok()) {
			return canonical_status;
		}
	}
	for (auto &execution : *bindings->mutable_execution_provider_instances()) {
		const auto canonical_status = canonicalize_configuration(
			kinetum::provider::provider_contract_role::EXECUTION, execution.mutable_configuration());
		if (!canonical_status.is_ok()) {
			return canonical_status;
		}
	}
	for (auto &transition : *bindings->mutable_storage_transition_bindings()) {
		const auto canonical_status =
			canonicalize_configuration(kinetum::provider::provider_contract_role::STORAGE_TRANSITION,
						   transition.mutable_configuration());
		if (!canonical_status.is_ok()) {
			return canonical_status;
		}
	}
	return status::ok();
}

/**
 * @brief Emit canonical provider-instance arrays and collect their identities.
 *
 * Scalar shape, duplicate rejection, set ordering, and configuration
 * canonicalization are complete preconditions. This operation performs no
 * semantic validation and cannot publish to the caller's plan.
 *
 * @param bindings Canonical normalized authoring input.
 * @param candidate Candidate plan whose provider arrays are replaced.
 * @param facility_ids Output set of facility identities.
 * @param driver_ids Output set of I/O-driver identities.
 * @param storage_ids Output set of storage-domain identities.
 * @param execution_ids Output set of execution-provider identities.
 */
void emit_provider_instances(const kinetum::gluon::v1::DeploymentBindings &bindings,
			     kinetum::gluon::v1::DeploymentPlan &candidate,
			     std::unordered_set<std::string> &facility_ids, std::unordered_set<std::string> &driver_ids,
			     std::unordered_set<std::string> &storage_ids,
			     std::unordered_set<std::string> &execution_ids)
{
	candidate.clear_process_facility_instances();
	candidate.clear_io_driver_instances();
	candidate.clear_packet_storage_domains();
	candidate.clear_execution_provider_instances();

	facility_ids.clear();
	facility_ids.reserve(static_cast<std::size_t>(bindings.process_facility_instances_size()));
	for (const auto &facility : bindings.process_facility_instances()) {
		facility_ids.insert(facility.facility_instance_id());
		candidate.add_process_facility_instances()->CopyFrom(facility);
	}

	driver_ids.clear();
	driver_ids.reserve(static_cast<std::size_t>(bindings.io_driver_instances_size()));
	for (const auto &driver : bindings.io_driver_instances()) {
		driver_ids.insert(driver.io_driver_instance_id());
		candidate.add_io_driver_instances()->CopyFrom(driver);
	}

	storage_ids.clear();
	storage_ids.reserve(static_cast<std::size_t>(bindings.packet_storage_domains_size()));
	for (const auto &storage : bindings.packet_storage_domains()) {
		storage_ids.insert(storage.storage_domain_id());
		candidate.add_packet_storage_domains()->CopyFrom(storage);
	}

	execution_ids.clear();
	execution_ids.reserve(static_cast<std::size_t>(bindings.execution_provider_instances_size()));
	for (const auto &execution : bindings.execution_provider_instances()) {
		execution_ids.insert(execution.execution_provider_instance_id());
		candidate.add_execution_provider_instances()->CopyFrom(execution);
	}
}

/**
 * @brief Extract every canonical driver-local port from typed configurations.
 *
 * @param plan Candidate plan containing canonical I/O-driver configurations.
 * @param ports Output key `(io_driver_instance_id, driver_port_id)` to fact.
 * @return OK for the complete current catalog, or INTERNAL when a newly added
 *         driver contract has no authoring lowerer.
 */
[[nodiscard]] status build_driver_port_catalog(const kinetum::gluon::v1::DeploymentPlan &plan,
					       std::map<std::pair<std::string, std::string>, driver_port_fact> &ports)
{
	ports.clear();
	for (const auto &driver : plan.io_driver_instances()) {
		const auto &configuration = driver.configuration();
		if (configuration.type_url() == kinetum::provider::DPDK_DRIVER_TYPE_URL) {
			kinetum::io::dpdk::v1::DpdkDriverConfig typed;
			if (!configuration.UnpackTo(&typed)) {
				return status::internal_error(
					"canonical DPDK driver configuration could not be unpacked");
			}
			for (const auto &port : typed.ports()) {
				driver_port_fact fact;
				switch (port.attachment_case()) {
				case kinetum::io::dpdk::v1::DpdkDriverPort::kPci:
					fact.kind = driver_attachment_kind::DPDK_PCI;
					fact.pci_address = port.pci().pci_address();
					break;
				case kinetum::io::dpdk::v1::DpdkDriverPort::kTap:
					fact.kind = driver_attachment_kind::DPDK_TAP;
					break;
				case kinetum::io::dpdk::v1::DpdkDriverPort::ATTACHMENT_NOT_SET:
					return status::internal_error(
						"catalog admitted a DPDK driver port without an attachment");
				}
				const auto key = std::make_pair(driver.io_driver_instance_id(), port.driver_port_id());
				if (!ports.emplace(key, std::move(fact)).second) {
					return status::internal_error(
						"catalog admitted duplicate DPDK driver-local port identity");
				}
			}
			continue;
		}
		if (configuration.type_url() == kinetum::provider::UDP_DRIVER_TYPE_URL) {
			kinetum::io::udp::v1::UdpDriverConfig typed;
			if (!configuration.UnpackTo(&typed)) {
				return status::internal_error(
					"canonical UDP driver configuration could not be unpacked");
			}
			for (const auto &port : typed.ports()) {
				const auto key = std::make_pair(driver.io_driver_instance_id(), port.driver_port_id());
				if (!ports.emplace(key, driver_port_fact{driver_attachment_kind::UDP, {}}).second) {
					return status::internal_error(
						"catalog admitted duplicate UDP driver-local port identity");
				}
			}
			continue;
		}
		return status::internal_error("I/O-driver contract has no Gluon authoring lowerer: " +
					      configuration.type_url());
	}
	return status::ok();
}

/**
 * @brief Validate every authoring-local provider and packet-path reference.
 *
 * Complete facility requirements and graph reachability belong to the shared
 * provider-topology compiler. This pass proves only that each explicitly
 * named local object exists in the same DeploymentBindings message.
 *
 * @param bindings Canonical normalized authoring input.
 * @param candidate Candidate plan containing canonical provider instances.
 * @param facility_ids Complete local facility identities.
 * @param driver_ids Complete local I/O-driver identities.
 * @param storage_ids Complete local storage-domain identities.
 * @param execution_ids Complete local execution-provider identities.
 * @param driver_ports Canonical driver-local endpoint catalog.
 * @return OK only when every local reference resolves.
 */
[[nodiscard]] status validate_local_references(
	const kinetum::gluon::v1::DeploymentBindings &bindings, const kinetum::gluon::v1::DeploymentPlan &candidate,
	const std::unordered_set<std::string> &facility_ids, const std::unordered_set<std::string> &driver_ids,
	const std::unordered_set<std::string> &storage_ids, const std::unordered_set<std::string> &execution_ids,
	const std::map<std::pair<std::string, std::string>, driver_port_fact> &driver_ports)
{
	for (const auto &driver : candidate.io_driver_instances()) {
		if (const auto refs_status = validate_facility_references("I/O driver instance",
									  driver.io_driver_instance_id(),
									  driver.facility_instance_ids(), facility_ids);
		    !refs_status.is_ok()) {
			return refs_status;
		}
	}
	for (const auto &storage : candidate.packet_storage_domains()) {
		if (const auto refs_status =
			    validate_facility_references("packet storage domain", storage.storage_domain_id(),
							 storage.facility_instance_ids(), facility_ids);
		    !refs_status.is_ok()) {
			return refs_status;
		}
	}
	for (const auto &execution : candidate.execution_provider_instances()) {
		if (const auto refs_status = validate_facility_references(
			    "execution provider instance", execution.execution_provider_instance_id(),
			    execution.facility_instance_ids(), facility_ids);
		    !refs_status.is_ok()) {
			return refs_status;
		}
	}
	for (const auto &binding : bindings.logical_port_bindings()) {
		if (driver_ids.find(binding.io_driver_instance_id()) == driver_ids.end()) {
			return status::invalid_argument("logical-port binding '" + binding.logical_name() +
							"' references unknown io_driver_instance_id '" +
							binding.io_driver_instance_id() + "'");
		}
		const auto driver_port_key = std::make_pair(binding.io_driver_instance_id(), binding.driver_port_id());
		if (driver_ports.find(driver_port_key) == driver_ports.end()) {
			return status::invalid_argument("logical-port binding '" + binding.logical_name() +
							"' references an unknown driver-local port");
		}
	}
	for (const auto &binding : bindings.io_stream_bindings()) {
		for (const auto &queue : binding.queues()) {
			if (queue.has_rx_storage_domain_id()) {
				if (!storage_ids.contains(queue.rx_storage_domain_id())) {
					return status::invalid_argument(
						"RX queue references unknown storage_domain_id '" +
						queue.rx_storage_domain_id() + "'");
				}
			} else {
				for (const auto &domain : queue.tx_storage().storage_domain_ids()) {
					if (!storage_ids.contains(domain)) {
						return status::invalid_argument(
							"TX queue references unknown storage_domain_id '" + domain +
							"'");
					}
				}
			}
		}
	}
	for (const auto &binding : bindings.stage_execution_bindings()) {
		if (execution_ids.find(binding.execution_provider_instance_id()) == execution_ids.end()) {
			return status::invalid_argument("stage-execution binding for '" + binding.logical_stage_id() +
							"' references unknown execution provider '" +
							binding.execution_provider_instance_id() + "'");
		}
	}
	for (const auto &binding : bindings.active_origin_bindings()) {
		if (storage_ids.find(binding.storage_domain_id()) == storage_ids.end()) {
			return status::invalid_argument("active-origin binding for stage/lane '" +
							binding.logical_stage_id() + "/" + binding.lane_id() +
							"' references unknown storage_domain_id '" +
							binding.storage_domain_id() + "'");
		}
	}
	for (const auto &binding : bindings.storage_transition_bindings()) {
		if (storage_ids.find(binding.from_storage_domain_id()) == storage_ids.end() ||
		    storage_ids.find(binding.to_storage_domain_id()) == storage_ids.end()) {
			return status::invalid_argument("storage transition '" + binding.transition_id() +
							"' references an unknown storage domain");
		}
		if (const auto refs_status = validate_facility_references("storage transition", binding.transition_id(),
									  binding.facility_instance_ids(),
									  facility_ids);
		    !refs_status.is_ok()) {
			return refs_status;
		}
	}
	return status::ok();
}

/**
 * @brief Parse a physical-inventory MAC spelling into exact six-byte identity.
 *
 * Hardware inventory is physical input rather than plan identity, so uppercase
 * hexadecimal is accepted and normalized to bytes. Shape is exact
 * `xx:xx:xx:xx:xx:xx`; no shortened or alternate separator form is accepted.
 *
 * @param text Hardware-inventory MAC spelling.
 * @return Exact six bytes or INVALID_ARGUMENT.
 */
[[nodiscard]] status_or<std::string> parse_mac_address(std::string_view text)
{
	if (text.size() != 17u) {
		return status::invalid_argument("hardware inventory MAC address must use xx:xx:xx:xx:xx:xx form");
	}
	auto nibble = [](char value) -> int {
		if (value >= '0' && value <= '9') {
			return value - '0';
		}
		if (value >= 'a' && value <= 'f') {
			return value - 'a' + 10;
		}
		if (value >= 'A' && value <= 'F') {
			return value - 'A' + 10;
		}
		return -1;
	};

	std::string bytes(6u, '\0');
	for (std::size_t index = 0; index < 6u; ++index) {
		const std::size_t offset = index * 3u;
		const int high = nibble(text[offset]);
		const int low = nibble(text[offset + 1u]);
		if (high < 0 || low < 0 || (index != 5u && text[offset + 2u] != ':')) {
			return status::invalid_argument(
				"hardware inventory MAC address must use xx:xx:xx:xx:xx:xx form");
		}
		bytes[index] = static_cast<char>((high << 4) | low);
	}
	return bytes;
}

/**
 * @brief Collect exact I/O coverage from typed Axiom stage configuration.
 *
 * @param pipeline Authored pipeline.
 * @param required Output logical interface to required direction mask.
 * @return OK after exact parameter validation.
 */
[[nodiscard]] status collect_pipeline_interface_requirements(const kinetum::axiom::v1::Pipeline &pipeline,
							     std::map<std::string, required_interface> &required)
{
	required.clear();
	for (const auto &stage : pipeline.stages()) {
		uint8_t direction = 0;
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_RX) {
			direction = REQUIRED_RX;
		} else if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_TX) {
			direction = REQUIRED_TX;
		} else {
			continue;
		}
		if (!stage.has_io()) {
			return status::invalid_argument("I/O stage '" + stage.stage_id() +
							"' must carry exact typed interface configuration");
		}
		const std::string logical_name(kinetum::axiom::stage_interface(stage));
		if (const auto id_status = validate_identifier("logical interface", logical_name); !id_status.is_ok()) {
			return id_status;
		}
		required[logical_name].directions = static_cast<uint8_t>(required[logical_name].directions | direction);
	}
	return status::ok();
}

/**
 * @brief Convert one exact plan port direction to a coverage mask.
 *
 * @param direction Authored direction.
 * @return Required-direction mask, or zero for an invalid enum.
 */
[[nodiscard]] constexpr uint8_t direction_mask(kinetum::gluon::v1::PortDirection direction) noexcept
{
	switch (direction) {
	case kinetum::gluon::v1::PORT_DIRECTION_RX_ONLY:
		return REQUIRED_RX;
	case kinetum::gluon::v1::PORT_DIRECTION_TX_ONLY:
		return REQUIRED_TX;
	case kinetum::gluon::v1::PORT_DIRECTION_BIDIRECTIONAL:
		return static_cast<uint8_t>(REQUIRED_RX | REQUIRED_TX);
	case kinetum::gluon::v1::PORT_DIRECTION_UNSPECIFIED:
	case kinetum::gluon::v1::PortDirection_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::gluon::v1::PortDirection_INT_MAX_SENTINEL_DO_NOT_USE_:
		return 0;
	}
	return 0;
}

/**
 * @brief Lower exact two-directional logical-port coverage.
 *
 * Hardware agreement is a later pass. This operation copies only authored
 * identities and constraints so every pipeline-coverage failure precedes
 * physical inventory inspection.
 *
 * @param bindings Canonical normalized authoring input.
 * @param candidate Candidate plan containing the logical pipeline.
 * @return OK after complete two-directional coverage and deterministic
 *         logical-port emission.
 */
[[nodiscard]] status lower_logical_ports(const kinetum::gluon::v1::DeploymentBindings &bindings,
					 kinetum::gluon::v1::DeploymentPlan &candidate)
{
	std::map<std::string, required_interface> required;
	if (const auto requirements_status = collect_pipeline_interface_requirements(candidate.pipeline(), required);
	    !requirements_status.is_ok()) {
		return requirements_status;
	}
	if (required.size() > static_cast<std::size_t>(KINETUM_MAX_PORTS)) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      "pipeline requires more logical ports than the module ABI can represent");
	}

	if (static_cast<std::size_t>(bindings.logical_port_bindings_size()) != required.size()) {
		return status::invalid_argument(
			"DeploymentBindings.logical_port_bindings[] must cover every pipeline interface exactly once");
	}

	candidate.clear_ports();
	for (int index = 0; index < bindings.logical_port_bindings_size(); ++index) {
		const auto &binding = bindings.logical_port_bindings(index);
		const auto required_it = required.find(binding.logical_name());
		if (required_it == required.end()) {
			return status::invalid_argument("logical-port binding '" + binding.logical_name() +
							"' is not used by any pipeline I/O stage");
		}
		const uint8_t admitted_direction = direction_mask(binding.direction());
		if (admitted_direction == 0 || admitted_direction != required_it->second.directions) {
			return status::invalid_argument("logical-port binding '" + binding.logical_name() +
							"' direction does not exactly match pipeline use");
		}

		auto *port = candidate.add_ports();
		port->set_logical_port_id(static_cast<uint32_t>(index));
		port->set_logical_name(binding.logical_name());
		port->set_io_driver_instance_id(binding.io_driver_instance_id());
		port->set_driver_port_id(binding.driver_port_id());
		port->set_direction(binding.direction());
		port->set_mtu(binding.mtu());
		if (binding.has_host_numa_node()) {
			port->set_host_numa_node(binding.host_numa_node());
		}
	}

	return status::ok();
}

/**
 * @brief Resolve logical ports against exact physical hardware facts.
 *
 * @param hardware Physical inventory.
 * @param driver_ports Canonical typed driver-local endpoint catalog.
 * @param candidate Candidate plan with complete logical ports.
 * @return OK after exact PCI attachment, MTU, NUMA, and MAC agreement.
 */
[[nodiscard]] status
resolve_logical_port_hardware(const kinetum::hw::v1::HardwareInventory &hardware,
			      const std::map<std::pair<std::string, std::string>, driver_port_fact> &driver_ports,
			      kinetum::gluon::v1::DeploymentPlan &candidate)
{
	std::map<std::string, const kinetum::hw::v1::NicPort *> nic_by_pci;
	std::map<std::string, std::string> mac_by_pci;
	if (hardware.has_node()) {
		for (const auto &nic : hardware.node().nics()) {
			if (nic.pci_address().empty() || nic.max_mtu() == 0u || nic.numa_node() < 0 ||
			    nic.driver() != kinetum::hw::v1::NIC_DRIVER_DPDK) {
				return status::invalid_argument(
					"hardware NIC rows require PCI identity, DPDK ownership, NUMA, and nonzero MTU");
			}
			if (const auto pci_status = kinetum::provider::validate_pci_address(nic.pci_address());
			    !pci_status.is_ok()) {
				return pci_status;
			}
			if (!nic_by_pci.emplace(nic.pci_address(), &nic).second) {
				return status::invalid_argument("hardware inventory contains duplicate PCI identity '" +
								nic.pci_address() + "'");
			}
			if (!nic.mac_address().empty()) {
				auto mac_or = parse_mac_address(nic.mac_address());
				if (!mac_or.is_ok()) {
					return status(status_code::INVALID_ARGUMENT, "hardware MAC is malformed",
						      nic.pci_address());
				}
				mac_by_pci.emplace(nic.pci_address(), std::move(mac_or).value());
			}
		}
	}

	for (auto &port : *candidate.mutable_ports()) {
		const auto driver_port_key = std::make_pair(port.io_driver_instance_id(), port.driver_port_id());
		const auto fact_it = driver_ports.find(driver_port_key);
		if (fact_it == driver_ports.end()) {
			return status::internal_error("validated logical port lost its driver-local endpoint");
		}
		if (fact_it->second.kind != driver_attachment_kind::DPDK_PCI) {
			if (port.has_host_numa_node()) {
				return status::invalid_argument("logical-port binding '" + port.logical_name() +
								"' requires NUMA placement but its typed attachment "
								"supplies no NUMA fact");
			}
			continue;
		}

		const auto nic_it = nic_by_pci.find(fact_it->second.pci_address);
		if (nic_it == nic_by_pci.end()) {
			return status::invalid_argument("logical-port binding '" + port.logical_name() +
							"' PCI attachment '" + fact_it->second.pci_address +
							"' is absent from hardware inventory");
		}
		const auto &nic = *nic_it->second;
		if (port.mtu() > nic.max_mtu()) {
			return status::invalid_argument("logical-port binding '" + port.logical_name() +
							"' MTU exceeds hardware inventory capability");
		}
		if (port.has_host_numa_node() && port.host_numa_node() != nic.numa_node()) {
			return status::invalid_argument("logical-port binding '" + port.logical_name() +
							"' NUMA constraint disagrees with hardware inventory");
		}
		port.set_host_numa_node(nic.numa_node());
		if (const auto mac_it = mac_by_pci.find(nic.pci_address()); mac_it != mac_by_pci.end()) {
			port.set_resolved_mac_address(mac_it->second);
		}
	}
	return status::ok();
}

/**
 * @brief Resolve one logical transition endpoint into the final typed ID.
 *
 * @param logical Candidate authored endpoint.
 * @param from_endpoint True for a source endpoint; I/O sources must be RX and
 *        I/O destinations must be TX.
 * @param io_stream_ids Exact logical-I/O endpoint lookup.
 * @param stage_instance_ids Exact logical-stage endpoint lookup.
 * @param out Destination final endpoint.
 * @return OK after exact local resolution.
 */
[[nodiscard]] status
resolve_transition_endpoint(const kinetum::gluon::v1::LogicalPacketPathEndpoint &logical, bool from_endpoint,
			    const std::map<std::tuple<std::string, int, uint32_t>, std::string> &io_stream_ids,
			    const std::map<std::pair<std::string, std::string>, std::string> &stage_instance_ids,
			    kinetum::gluon::v1::PacketPathEndpoint *out)
{
	if (out == nullptr) {
		return status::internal_error("storage-transition endpoint destination must not be null");
	}
	switch (logical.endpoint_case()) {
	case kinetum::gluon::v1::LogicalPacketPathEndpoint::kIo: {
		const auto &io = logical.io();
		const auto required_direction = from_endpoint ? kinetum::gluon::v1::IO_STREAM_DIRECTION_RX :
								kinetum::gluon::v1::IO_STREAM_DIRECTION_TX;
		if (io.direction() != required_direction) {
			return status::invalid_argument(
				from_endpoint ? "storage-transition I/O source must name an RX stream" :
						"storage-transition I/O destination must name a TX stream");
		}
		const auto key =
			std::make_tuple(io.logical_name(), static_cast<int>(io.direction()), io.driver_queue_id());
		const auto stream_it = io_stream_ids.find(key);
		if (stream_it == io_stream_ids.end()) {
			return status::invalid_argument("storage-transition endpoint references unknown I/O stream");
		}
		out->set_io_stream_id(stream_it->second);
		return status::ok();
	}
	case kinetum::gluon::v1::LogicalPacketPathEndpoint::kStage: {
		const auto &stage = logical.stage();
		const auto instance_it =
			stage_instance_ids.find(std::make_pair(stage.logical_stage_id(), stage.lane_id()));
		if (instance_it == stage_instance_ids.end()) {
			return status::invalid_argument(
				"storage-transition endpoint references unknown stage/lane instance");
		}
		out->set_stage_instance_id(instance_it->second);
		return status::ok();
	}
	case kinetum::gluon::v1::LogicalPacketPathEndpoint::ENDPOINT_NOT_SET:
		return status::invalid_argument("storage-transition endpoint must select exactly one endpoint");
	}
	return status::invalid_argument("storage-transition endpoint contains an unknown endpoint case");
}

/**
 * @brief Build a collision-free identity for one resolved transition endpoint.
 *
 * @param endpoint Final typed endpoint emitted by deterministic lowering.
 * @return Namespace-qualified endpoint identity, or INTERNAL_ERROR when the
 *         lowering invariant was violated.
 */
[[nodiscard]] status_or<std::string>
transition_endpoint_identity(const kinetum::gluon::v1::PacketPathEndpoint &endpoint)
{
	switch (endpoint.endpoint_case()) {
	case kinetum::gluon::v1::PacketPathEndpoint::kIoStreamId:
		return "io:" + endpoint.io_stream_id();
	case kinetum::gluon::v1::PacketPathEndpoint::kStageInstanceId:
		return "stage:" + endpoint.stage_instance_id();
	case kinetum::gluon::v1::PacketPathEndpoint::ENDPOINT_NOT_SET:
		return status::internal_error("lowered storage transition has an unset endpoint");
	}
	return status::internal_error("lowered storage transition has an unknown endpoint case");
}

/**
 * @brief Lower exact logical storage-transition bindings.
 *
 * Scalar, catalog, and local-reference validation are complete preconditions.
 *
 * @param bindings Canonical normalized authoring input.
 * @param candidate Candidate plan with final streams and stage instances.
 * @return OK after sorted exact transition emission.
 */
[[nodiscard]] status lower_storage_transitions(const kinetum::gluon::v1::DeploymentBindings &bindings,
					       kinetum::gluon::v1::DeploymentPlan &candidate)
{
	std::unordered_map<uint32_t, std::string> logical_name_by_port;
	logical_name_by_port.reserve(static_cast<std::size_t>(candidate.ports_size()));
	for (const auto &port : candidate.ports()) {
		logical_name_by_port.emplace(port.logical_port_id(), port.logical_name());
	}

	std::map<std::tuple<std::string, int, uint32_t>, std::string> io_stream_ids;
	for (const auto &stream : candidate.io_streams()) {
		const auto port_it = logical_name_by_port.find(stream.logical_port_id());
		if (port_it == logical_name_by_port.end()) {
			return status::internal_error("lowered I/O stream references an unknown logical port");
		}
		const auto key = std::make_tuple(port_it->second, static_cast<int>(stream.direction()),
						 stream.driver_queue_id());
		if (!io_stream_ids.emplace(key, stream.io_stream_id()).second) {
			return status::internal_error("lowered I/O endpoint identity is ambiguous");
		}
	}

	std::map<std::pair<std::string, std::string>, std::string> stage_instance_ids;
	for (const auto &instance : candidate.stage_instances()) {
		const auto key = std::make_pair(instance.logical_stage_id(), instance.lane_id());
		if (!stage_instance_ids.emplace(key, instance.stage_instance_id()).second) {
			return status::internal_error("lowered stage/lane endpoint identity is ambiguous");
		}
	}

	candidate.clear_storage_transitions();
	std::set<std::tuple<std::string, std::string, std::string, std::string>> transition_coverage;
	for (const auto &binding : bindings.storage_transition_bindings()) {
		kinetum::gluon::v1::StorageTransition lowered;
		lowered.set_transition_id(binding.transition_id());
		if (const auto endpoint_status = resolve_transition_endpoint(binding.from_endpoint(), true,
									     io_stream_ids, stage_instance_ids,
									     lowered.mutable_from_endpoint());
		    !endpoint_status.is_ok()) {
			return endpoint_status;
		}
		if (const auto endpoint_status = resolve_transition_endpoint(binding.to_endpoint(), false,
									     io_stream_ids, stage_instance_ids,
									     lowered.mutable_to_endpoint());
		    !endpoint_status.is_ok()) {
			return endpoint_status;
		}
		lowered.set_from_storage_domain_id(binding.from_storage_domain_id());
		lowered.set_to_storage_domain_id(binding.to_storage_domain_id());
		for (const auto &facility_id : binding.facility_instance_ids()) {
			lowered.add_facility_instance_ids(facility_id);
		}
		lowered.mutable_configuration()->CopyFrom(binding.configuration());
		lowered.set_staging_capacity(binding.staging_capacity());
		if (binding.has_staging_numa_node()) {
			lowered.set_staging_numa_node(binding.staging_numa_node());
		}

		auto from_identity_or = transition_endpoint_identity(lowered.from_endpoint());
		if (!from_identity_or.is_ok()) {
			return from_identity_or.error();
		}
		auto to_identity_or = transition_endpoint_identity(lowered.to_endpoint());
		if (!to_identity_or.is_ok()) {
			return to_identity_or.error();
		}
		const auto coverage = std::make_tuple(std::move(from_identity_or).value(),
						      std::move(to_identity_or).value(),
						      lowered.from_storage_domain_id(), lowered.to_storage_domain_id());
		if (!transition_coverage.insert(coverage).second) {
			return status::invalid_argument(
				"multiple storage transitions claim the same endpoint/domain relation");
		}
		candidate.add_storage_transitions()->Swap(&lowered);
	}
	return status::ok();
}

}  // namespace

common::status lower_deployment_bindings(const kinetum::gluon::v1::DeploymentBindings &bindings,
					 const kinetum::hw::v1::HardwareInventory &hardware,
					 kinetum::gluon::v1::DeploymentPlan &plan)
{
	if (const auto unknown_status = common::reject_unknown_protobuf_fields_recursive(hardware, "HardwareInventory");
	    !unknown_status.is_ok()) {
		return unknown_status;
	}
	if (const auto enum_status =
		    common::reject_invalid_protobuf_enum_values_recursive(hardware, "HardwareInventory");
	    !enum_status.is_ok()) {
		return enum_status;
	}
	if (const auto unknown_status =
		    common::reject_unknown_protobuf_fields_recursive(bindings, "DeploymentBindings");
	    !unknown_status.is_ok()) {
		return unknown_status;
	}
	if (const auto enum_status =
		    common::reject_invalid_protobuf_enum_values_recursive(bindings, "DeploymentBindings");
	    !enum_status.is_ok()) {
		return enum_status;
	}
	if (const auto scalar_status = validate_binding_scalar_contracts(bindings); !scalar_status.is_ok()) {
		return scalar_status;
	}

	auto normalized_bindings = bindings;
	if (const auto normalized = normalize_binding_set_order(&normalized_bindings); !normalized.is_ok()) {
		return normalized;
	}
	if (const auto catalog_status = canonicalize_binding_configurations(&normalized_bindings);
	    !catalog_status.is_ok()) {
		return catalog_status;
	}

	auto candidate = plan;
	std::unordered_set<std::string> facility_ids;
	std::unordered_set<std::string> driver_ids;
	std::unordered_set<std::string> storage_ids;
	std::unordered_set<std::string> execution_ids;
	emit_provider_instances(normalized_bindings, candidate, facility_ids, driver_ids, storage_ids, execution_ids);

	std::map<std::pair<std::string, std::string>, driver_port_fact> driver_ports;
	if (const auto port_catalog_status = build_driver_port_catalog(candidate, driver_ports);
	    !port_catalog_status.is_ok()) {
		return port_catalog_status;
	}
	if (const auto reference_status = validate_local_references(
		    normalized_bindings, candidate, facility_ids, driver_ids, storage_ids, execution_ids, driver_ports);
	    !reference_status.is_ok()) {
		return reference_status;
	}
	if (const auto port_status = lower_logical_ports(normalized_bindings, candidate); !port_status.is_ok()) {
		return port_status;
	}
	if (const auto topology_status = lower_execution_topology(candidate, normalized_bindings);
	    !topology_status.is_ok()) {
		return topology_status;
	}
	if (const auto hardware_status = resolve_logical_port_hardware(hardware, driver_ports, candidate);
	    !hardware_status.is_ok()) {
		return hardware_status;
	}
	if (const auto transition_status = lower_storage_transitions(normalized_bindings, candidate);
	    !transition_status.is_ok()) {
		return transition_status;
	}

	plan.Swap(&candidate);
	return status::ok();
}

}  // namespace kinetum::gluon
