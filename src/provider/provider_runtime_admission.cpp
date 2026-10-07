// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_runtime_admission.cpp
 * @brief Exact compiled-fact projection and installed provider admission.
 * @author Fleming Patel
 */

#include "src/provider/provider_runtime_admission.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <exception>
#include <limits>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "src/common/log.hpp"
#include "src/common/status.hpp"
#include "src/provider/provider_component_abi.h"
#include "src/provider/provider_contract_catalog.hpp"

namespace kinetum::provider
{
namespace
{

using common::status;
using common::status_or;

/** Maximum component diagnostic accepted at the cold host-proof boundary. */
constexpr std::size_t PROVIDER_HOST_PROOF_DIAGNOSTIC_BYTES = 256;

/** Maximum complete operator diagnostic emitted after foreign loading. */
constexpr std::size_t PROVIDER_POST_LOAD_FAILURE_DIAGNOSTIC_BYTES = 512;

/** Canonical role order shared by fact lookup and host-proof scheduling. */
constexpr std::array ALL_PROVIDER_ROLES{
	provider_contract_role::PROCESS_FACILITY,   provider_contract_role::IO_DRIVER,
	provider_contract_role::PACKET_STORAGE,	    provider_contract_role::EXECUTION,
	provider_contract_role::STORAGE_TRANSITION,
};

static_assert(access_agent_bit(packet_access_agent::CPU) == KINETUM_PROVIDER_ACCESS_AGENT_CPU,
	      "catalog and component ABI CPU access bits must agree");
static_assert(access_agent_bit(packet_access_agent::NIC_DMA) == KINETUM_PROVIDER_ACCESS_AGENT_NIC_DMA,
	      "catalog and component ABI NIC-DMA access bits must agree");

/**
 * @brief Return a vector's storage only when its count is nonzero.
 * @param values Borrowed vector whose storage backs the returned view.
 * @return Contiguous data pointer, or nullptr for an empty vector.
 * @tparam value_type Element type of the projected array.
 */
template <typename value_type>
[[nodiscard]] const value_type *data_or_null(const std::vector<value_type> &values) noexcept
{
	return values.empty() ? nullptr : values.data();
}

/**
 * @brief Narrow one ABI array or byte count without truncation.
 *
 * @param value Native source count.
 * @param subject Stable internal diagnostic subject.
 * @return Exact uint32 count or an internal compiler/ABI disagreement.
 */
[[nodiscard]] status_or<uint32_t> abi_count(std::size_t value, std::string_view subject)
{
	if (value > std::numeric_limits<uint32_t>::max()) {
		return status::internal_error(std::string(subject) + " exceeds the provider ABI count width");
	}
	return static_cast<uint32_t>(value);
}

/**
 * @brief Build one exact borrowed ABI text view after checked narrowing.
 * @param value Borrowed bytes that must outlive every use of the resulting view.
 * @return ABI view with canonical null-for-empty representation, or a count-range error.
 */
[[nodiscard]] status_or<kinetum_provider_text_view> abi_text_view(std::string_view value)
{
	auto size_or = abi_count(value.size(), "provider text view");
	if (!size_or.is_ok()) {
		return size_or.error();
	}
	return kinetum_provider_text_view{
		.data = value.empty() ? nullptr : value.data(),
		.size = size_or.value(),
		.padding = 0,
	};
}

/**
 * @brief Build one exact borrowed ABI byte view after checked narrowing.
 * @param value Borrowed bytes that must outlive every use of the resulting view.
 * @return ABI view with canonical null-for-empty representation, or a count-range error.
 */
[[nodiscard]] status_or<kinetum_provider_byte_view> abi_byte_view(std::string_view value)
{
	auto size_or = abi_count(value.size(), "provider byte view");
	if (!size_or.is_ok()) {
		return size_or.error();
	}
	return kinetum_provider_byte_view{
		.data = value.empty() ? nullptr : reinterpret_cast<const uint8_t *>(value.data()),
		.size = size_or.value(),
		.padding = 0,
	};
}

/**
 * @brief Map one compiled CPU-owner role into the exact C ABI.
 * @param source Compiled enum value to translate.
 * @param destination Output written only for an admitted enum value.
 * @return true after exact translation; false for an unknown value.
 */
[[nodiscard]] bool abi_cpu_owner(compiled_facility_cpu_owner_kind source,
				 kinetum_provider_cpu_owner_kind &destination) noexcept
{
	switch (source) {
	case compiled_facility_cpu_owner_kind::PACKET_WORKER:
		destination = KINETUM_PROVIDER_CPU_OWNER_PACKET_WORKER;
		return true;
	case compiled_facility_cpu_owner_kind::TRANSITION_COORDINATOR:
		destination = KINETUM_PROVIDER_CPU_OWNER_TRANSITION_COORDINATOR;
		return true;
	case compiled_facility_cpu_owner_kind::LIFECYCLE_EXECUTOR:
		destination = KINETUM_PROVIDER_CPU_OWNER_LIFECYCLE_EXECUTOR;
		return true;
	}
	return false;
}

/**
 * @brief Map one compiled native-attachment kind into the exact C ABI.
 * @param source Compiled enum value to translate.
 * @param destination Output written only for an admitted enum value.
 * @return true after exact translation; false for an unknown value.
 */
[[nodiscard]] bool abi_attachment_kind(compiled_driver_attachment_kind source,
				       kinetum_provider_attachment_kind &destination) noexcept
{
	switch (source) {
	case compiled_driver_attachment_kind::PCI:
		destination = KINETUM_PROVIDER_ATTACHMENT_PCI;
		return true;
	case compiled_driver_attachment_kind::TAP:
		destination = KINETUM_PROVIDER_ATTACHMENT_TAP;
		return true;
	case compiled_driver_attachment_kind::UDP_IPV4:
		destination = KINETUM_PROVIDER_ATTACHMENT_UDP_IPV4;
		return true;
	}
	return false;
}

/**
 * @brief Map one compiled logical-port direction into the exact C ABI.
 * @param source Compiled enum value to translate.
 * @param destination Output written only for an admitted enum value.
 * @return true after exact translation; false for an unknown value.
 */
[[nodiscard]] bool abi_port_direction(compiled_io_port_direction source,
				      kinetum_provider_io_direction &destination) noexcept
{
	switch (source) {
	case compiled_io_port_direction::RX_ONLY:
		destination = KINETUM_PROVIDER_IO_DIRECTION_RX;
		return true;
	case compiled_io_port_direction::TX_ONLY:
		destination = KINETUM_PROVIDER_IO_DIRECTION_TX;
		return true;
	case compiled_io_port_direction::BIDIRECTIONAL:
		destination = KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL;
		return true;
	}
	return false;
}

/**
 * @brief Map one compiled stream direction into the exact C ABI.
 * @param source Compiled enum value to translate.
 * @param destination Output written only for an admitted enum value.
 * @return true after exact translation; false for an unknown value.
 */
[[nodiscard]] bool abi_stream_direction(compiled_io_stream_direction source,
					kinetum_provider_io_direction &destination) noexcept
{
	switch (source) {
	case compiled_io_stream_direction::RX:
		destination = KINETUM_PROVIDER_IO_DIRECTION_RX;
		return true;
	case compiled_io_stream_direction::TX:
		destination = KINETUM_PROVIDER_IO_DIRECTION_TX;
		return true;
	}
	return false;
}

/**
 * @brief Map one compiled steering mechanism into the exact C ABI.
 * @param source Compiled enum value to translate.
 * @param destination Output written only for an admitted enum value.
 * @return true after exact translation; false for an unknown value.
 */
[[nodiscard]] bool abi_steering_kind(compiled_steering_kind source,
				     kinetum_provider_steering_kind &destination) noexcept
{
	switch (source) {
	case compiled_steering_kind::NONE:
		destination = KINETUM_PROVIDER_STEERING_NONE;
		return true;
	case compiled_steering_kind::RSS:
		destination = KINETUM_PROVIDER_STEERING_RSS;
		return true;
	}
	return false;
}

/**
 * @brief Map one compiled endpoint namespace into the exact C ABI.
 * @param source Compiled enum value to translate.
 * @param destination Output written only for an admitted enum value.
 * @return true after exact translation; false for an unknown value.
 */
[[nodiscard]] bool abi_endpoint_kind(compiled_packet_path_endpoint_kind source,
				     kinetum_provider_endpoint_kind &destination) noexcept
{
	switch (source) {
	case compiled_packet_path_endpoint_kind::IO_STREAM:
		destination = KINETUM_PROVIDER_ENDPOINT_IO_STREAM;
		return true;
	case compiled_packet_path_endpoint_kind::STAGE_INSTANCE:
		destination = KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE;
		return true;
	}
	return false;
}

/**
 * @brief Map one implemented transition mechanism into the C ABI.
 * @param source Compiled transition mechanism.
 * @param destination Output ABI value, written only for a declared mechanism.
 * @return true when @p source has one exact ABI representation.
 */
[[nodiscard]] bool abi_transition_mode(storage_transition_mode source,
				       kinetum_provider_transition_mode &destination) noexcept
{
	switch (source) {
	case storage_transition_mode::ZERO_COPY_SHARE:
		destination = KINETUM_PROVIDER_TRANSITION_ZERO_COPY_SHARE;
		return true;
	case storage_transition_mode::BOUNDED_COPY:
		destination = KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY;
		return true;
	}
	return false;
}

/**
 * @brief Map one pure provider role into its fixed-width C ABI value.
 * @param source Compiled enum value to translate.
 * @param destination Output written only for an admitted enum value.
 * @return true after exact translation; false for an unknown value.
 */
[[nodiscard]] bool abi_provider_role(provider_contract_role source, kinetum_provider_role &destination) noexcept
{
	switch (source) {
	case provider_contract_role::PROCESS_FACILITY:
		destination = KINETUM_PROVIDER_ROLE_PROCESS_FACILITY;
		return true;
	case provider_contract_role::IO_DRIVER:
		destination = KINETUM_PROVIDER_ROLE_IO_DRIVER;
		return true;
	case provider_contract_role::PACKET_STORAGE:
		destination = KINETUM_PROVIDER_ROLE_PACKET_STORAGE;
		return true;
	case provider_contract_role::EXECUTION:
		destination = KINETUM_PROVIDER_ROLE_EXECUTION;
		return true;
	case provider_contract_role::STORAGE_TRANSITION:
		destination = KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION;
		return true;
	}
	return false;
}

/** @brief Self-contained identity and canonical payload for one ABI fact tree. */
struct instance_identity_storage {
	std::string instance_id;		 ///< Owned plan identity bytes.
	std::string type_url;			 ///< Owned exact provider type URL.
	std::string configuration;		 ///< Owned canonical provider payload.
	provider_component_instance_facts view;	 ///< Stable public view after finalization.
};

/** @brief Self-contained native attachment text and exact ABI rows. */
struct attachment_storage {
	std::vector<std::string> driver_port_ids;		     ///< Stable driver-local identities.
	std::vector<std::string> attachment_identities;		     ///< Stable canonical native identities.
	std::vector<kinetum_provider_driver_attachment_fact> facts;  ///< Contiguous exact ABI rows.
};

/** @brief Owned C-ABI projection for one compiled process facility. */
struct process_facility_fact_storage {
	instance_identity_storage identity;				  ///< Instance identity and canonical payload.
	std::vector<kinetum_provider_cpu_assignment> cpu_assignments;	  ///< Exact CPU-role rows.
	attachment_storage attachments;					  ///< Exact dependent native attachments.
	std::vector<kinetum_provider_memory_domain_fact> memory_domains;  ///< Exact memory rows.
	kinetum_provider_process_facility_facts facts{};		  ///< Root C-ABI fact record.
};

/** @brief Owned C-ABI projection for one compiled I/O driver. */
struct io_driver_fact_storage {
	instance_identity_storage identity;				  ///< Instance identity and canonical payload.
	attachment_storage attachments;					  ///< Exact configured native attachments.
	std::vector<kinetum_provider_io_port_fact> ports;		  ///< Exact logical/driver ports.
	std::vector<kinetum_provider_io_stream_fact> streams;		  ///< Exact driver queues.
	std::vector<std::vector<uint32_t>> stream_storage_domains;	  ///< Owned immutable queue storage sets.
	std::vector<compiled_traffic_steering_profile> steering_sources;  ///< Stable source identities and bytes.
	std::vector<std::vector<kinetum_provider_text_view>> steering_hash_fields;  ///< Stable field views.
	std::vector<kinetum_provider_steering_fact> steering_profiles;		    ///< Exact steering rows.
	kinetum_provider_io_driver_facts facts{};				    ///< Root C-ABI fact record.
};

/** @brief Owned C-ABI projection for one compiled packet-storage domain. */
struct packet_storage_fact_storage {
	instance_identity_storage identity;		///< Instance identity and canonical payload.
	kinetum_provider_packet_storage_facts facts{};	///< Exact storage and budget facts.
};

/** @brief Owned C-ABI projection for one compiled execution provider. */
struct execution_fact_storage {
	instance_identity_storage identity;	       ///< Instance identity and canonical payload.
	std::vector<uint32_t> stage_instance_indices;  ///< Stable exact stage set.
	std::vector<uint32_t> worker_indices;	       ///< Stable exact owner set.
	kinetum_provider_execution_facts facts{};      ///< Root C-ABI fact record.
};

/** @brief Owned C-ABI projection for one compiled storage transition. */
struct storage_transition_fact_storage {
	instance_identity_storage identity;		    ///< Instance identity and canonical payload.
	kinetum_provider_storage_transition_facts facts{};  ///< Exact transition facts.
};

/** @brief Complete role-partitioned fact storage before component loading. */
struct fact_collection {
	std::vector<process_facility_fact_storage> process_facilities;	   ///< Role-relative facilities.
	std::vector<io_driver_fact_storage> io_drivers;			   ///< Role-relative I/O drivers.
	std::vector<packet_storage_fact_storage> packet_storage;	   ///< Role-relative storage domains.
	std::vector<execution_fact_storage> execution;			   ///< Role-relative execution providers.
	std::vector<storage_transition_fact_storage> storage_transitions;  ///< Role-relative transitions.

	/**
	 * @brief Return one role-relative immutable instance view.
	 * @param role Provider role selecting the owning row vector.
	 * @param index Compact index within that role.
	 * @return Borrowed matching row, or nullptr for an unknown role or invalid index.
	 */
	[[nodiscard]] const provider_component_instance_facts *instance(provider_contract_role role,
									uint32_t index) const noexcept;

	/** @return Total instance count across the five disjoint provider-role vectors. */
	[[nodiscard]] std::size_t size() const noexcept;

	/**
	 * @brief Return one role-relative row's unique flat ordinal.
	 * @param role Provider role selecting the owning row vector.
	 * @param index Compact index within that role.
	 * @return Flat ordinal in canonical role order, or an error for an unknown role or invalid index.
	 */
	[[nodiscard]] status_or<std::size_t> ordinal(provider_contract_role role, uint32_t index) const;
};

const provider_component_instance_facts *fact_collection::instance(provider_contract_role role,
								   uint32_t index) const noexcept
{
	switch (role) {
	case provider_contract_role::PROCESS_FACILITY:
		return index < process_facilities.size() ? &process_facilities[index].identity.view : nullptr;
	case provider_contract_role::IO_DRIVER:
		return index < io_drivers.size() ? &io_drivers[index].identity.view : nullptr;
	case provider_contract_role::PACKET_STORAGE:
		return index < packet_storage.size() ? &packet_storage[index].identity.view : nullptr;
	case provider_contract_role::EXECUTION:
		return index < execution.size() ? &execution[index].identity.view : nullptr;
	case provider_contract_role::STORAGE_TRANSITION:
		return index < storage_transitions.size() ? &storage_transitions[index].identity.view : nullptr;
	}
	return nullptr;
}

std::size_t fact_collection::size() const noexcept
{
	return process_facilities.size() + io_drivers.size() + packet_storage.size() + execution.size() +
	       storage_transitions.size();
}

status_or<std::size_t> fact_collection::ordinal(provider_contract_role role, uint32_t index) const
{
	std::size_t offset = 0;
	for (const auto candidate : ALL_PROVIDER_ROLES) {
		std::size_t count = 0;
		switch (candidate) {
		case provider_contract_role::PROCESS_FACILITY:
			count = process_facilities.size();
			break;
		case provider_contract_role::IO_DRIVER:
			count = io_drivers.size();
			break;
		case provider_contract_role::PACKET_STORAGE:
			count = packet_storage.size();
			break;
		case provider_contract_role::EXECUTION:
			count = execution.size();
			break;
		case provider_contract_role::STORAGE_TRANSITION:
			count = storage_transitions.size();
			break;
		}
		if (candidate == role) {
			if (index >= count) {
				return status::internal_error(
					"compiled provider host requirement has an out-of-range owner");
			}
			return offset + index;
		}
		offset += count;
	}
	return status::internal_error("compiled provider host requirement has an unknown role");
}

/**
 * @brief Finalize one stable instance identity and exactly-one fact record.
 *
 * @param identity Destination owning strings and public view.
 * @param instance_id Exact compiled instance identity.
 * @param configuration Exact canonical provider configuration.
 * @param role Exact structural role.
 * @param instance_index Compact role-relative index.
 * @param compiled_facts Exactly one matching C-ABI fact pointer.
 * @return OK only when every borrowed byte count fits the ABI.
 */
[[nodiscard]] status finalize_identity(instance_identity_storage &identity, std::string_view instance_id,
				       const compiled_provider_configuration &configuration,
				       provider_contract_role role, uint32_t instance_index,
				       kinetum_provider_compiled_fact_record compiled_facts)
{
	identity.instance_id.assign(instance_id);
	identity.type_url = configuration.type_url;
	identity.configuration = configuration.canonical_payload;
	auto instance_view_or = abi_text_view(identity.instance_id);
	if (!instance_view_or.is_ok()) {
		return instance_view_or.error();
	}
	auto type_url_view_or = abi_text_view(identity.type_url);
	if (!type_url_view_or.is_ok()) {
		return type_url_view_or.error();
	}
	auto configuration_view_or = abi_byte_view(identity.configuration);
	if (!configuration_view_or.is_ok()) {
		return configuration_view_or.error();
	}
	kinetum_provider_role abi_role = 0;
	if (!abi_provider_role(role, abi_role) ||
	    kinetum_provider_compiled_facts_are_valid_for_role(&compiled_facts, abi_role) == 0) {
		return status::internal_error("compiled provider topology produced an invalid C-ABI fact tree");
	}
	identity.view = provider_component_instance_facts{
		.instance_id = std::string_view(identity.instance_id),
		.type_url = std::string_view(identity.type_url),
		.canonical_configuration = std::string_view(identity.configuration),
		.role = role,
		.instance_index = instance_index,
		.compiled_facts = compiled_facts,
	};
	return status::ok();
}

/**
 * @brief Project one stable native-attachment vector into exact ABI rows.
 *
 * @param source Canonical compiled attachment rows.
 * @param destination Self-contained text and ABI storage.
 * @return OK only for representable text lengths and closed enum values.
 */
[[nodiscard]] status project_attachments(std::span<const compiled_driver_attachment> source,
					 attachment_storage &destination)
{
	auto count_or = abi_count(source.size(), "provider attachment set");
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	destination.driver_port_ids.resize(source.size());
	destination.attachment_identities.resize(source.size());
	destination.facts.resize(source.size());
	for (std::size_t index = 0; index < source.size(); ++index) {
		destination.driver_port_ids[index] = source[index].driver_port_id;
		destination.attachment_identities[index] = source[index].attachment_identity;
	}
	for (std::size_t index = 0; index < source.size(); ++index) {
		auto driver_port_view_or = abi_text_view(destination.driver_port_ids[index]);
		if (!driver_port_view_or.is_ok()) {
			return driver_port_view_or.error();
		}
		auto attachment_view_or = abi_text_view(destination.attachment_identities[index]);
		if (!attachment_view_or.is_ok()) {
			return attachment_view_or.error();
		}
		kinetum_provider_attachment_kind kind = 0;
		if (!abi_attachment_kind(source[index].kind, kind)) {
			return status::internal_error("compiled provider attachment has an unknown kind");
		}
		destination.facts[index] = kinetum_provider_driver_attachment_fact{
			.driver_port_id = driver_port_view_or.value(),
			.attachment_identity = attachment_view_or.value(),
			.io_driver_index = source[index].io_driver_index,
			.endpoint_port = source[index].endpoint_port,
			.kind = kind,
			.padding = {0},
		};
	}
	return status::ok();
}

/**
 * @brief Project every process-facility fact tree before component loading.
 * @param topology Compiled source topology and canonical provider configuration.
 * @param destination Unpublished projection storage; may be partially populated when a later row fails.
 * @return OK for a complete validated projection, or the first width/contract failure.
 */
[[nodiscard]] status project_process_facilities(const compiled_provider_topology &topology,
						std::vector<process_facility_fact_storage> &destination)
{
	auto facility_count_or = abi_count(topology.process_facilities.size(), "process-facility instance set");
	if (!facility_count_or.is_ok()) {
		return facility_count_or.error();
	}
	destination.resize(topology.process_facilities.size());
	for (std::size_t index = 0; index < topology.process_facilities.size(); ++index) {
		const auto &source = topology.process_facilities[index];
		auto &owner = destination[index];
		if (source.facility_index != index || !source.main_core_id.has_value() || *source.main_core_id < 0) {
			return status::internal_error(
				"compiled process-facility identity or coordinator core is incomplete");
		}
		auto cpu_count_or = abi_count(source.cpu_assignments.size(), "process-facility CPU assignment set");
		auto memory_count_or = abi_count(source.memory_domains.size(), "process-facility memory-domain set");
		if (!cpu_count_or.is_ok()) {
			return cpu_count_or.error();
		}
		if (!memory_count_or.is_ok()) {
			return memory_count_or.error();
		}
		auto projection_status = project_attachments(source.attachments, owner.attachments);
		if (!projection_status.is_ok()) {
			return projection_status;
		}
		auto attachment_count_or = abi_count(owner.attachments.facts.size(), "process-facility attachment set");
		if (!attachment_count_or.is_ok()) {
			return attachment_count_or.error();
		}
		owner.cpu_assignments.resize(source.cpu_assignments.size());
		for (std::size_t cpu_index = 0; cpu_index < source.cpu_assignments.size(); ++cpu_index) {
			kinetum_provider_cpu_owner_kind kind = 0;
			if (!abi_cpu_owner(source.cpu_assignments[cpu_index].kind, kind)) {
				return status::internal_error(
					"compiled process-facility CPU row has an unknown owner role");
			}
			owner.cpu_assignments[cpu_index] = kinetum_provider_cpu_assignment{
				.owner_index = source.cpu_assignments[cpu_index].owner_index,
				.cpu_core_id = source.cpu_assignments[cpu_index].cpu_core_id,
				.numa_node = source.cpu_assignments[cpu_index].numa_node,
				.kind = kind,
				.padding = {0},
			};
		}
		owner.memory_domains.resize(source.memory_domains.size());
		for (std::size_t memory_index = 0; memory_index < source.memory_domains.size(); ++memory_index) {
			const auto &memory = source.memory_domains[memory_index];
			owner.memory_domains[memory_index] = kinetum_provider_memory_domain_fact{
				.storage_domain_index = memory.storage_domain_index,
				.buffer_count = memory.buffer_count,
				.data_room_bytes = memory.data_room_bytes,
				.headroom_bytes = memory.headroom_bytes,
				.alignment_bytes = memory.alignment_bytes,
				.cache_size_per_worker = memory.cache_size_per_worker,
				.host_numa_node = memory.host_numa_node.value_or(0),
				.has_host_numa_node = static_cast<uint8_t>(memory.host_numa_node.has_value()),
				.padding = {0},
			};
		}
		owner.facts = kinetum_provider_process_facility_facts{
			.facility_index = source.facility_index,
			.main_core_id = *source.main_core_id,
			.cpu_assignments = data_or_null(owner.cpu_assignments),
			.cpu_assignment_count = cpu_count_or.value(),
			.cpu_assignment_padding = 0,
			.attachments = data_or_null(owner.attachments.facts),
			.attachment_count = attachment_count_or.value(),
			.attachment_padding = 0,
			.memory_domains = data_or_null(owner.memory_domains),
			.memory_domain_count = memory_count_or.value(),
			.padding = {0},
		};
		kinetum_provider_compiled_fact_record record{};
		record.process_facility = &owner.facts;
		projection_status = finalize_identity(owner.identity, source.facility_instance_id, source.configuration,
						      provider_contract_role::PROCESS_FACILITY,
						      static_cast<uint32_t>(index), record);
		if (!projection_status.is_ok()) {
			return projection_status;
		}
	}
	return status::ok();
}

/**
 * @brief Return whether one sorted driver stream set owns an exact stream index.
 * @param driver_stream_indices Sorted compiled stream membership.
 * @param stream_index Candidate stream identity.
 * @return true only when the exact stream belongs to the driver.
 */
[[nodiscard]] bool owns_stream(std::span<const uint32_t> driver_stream_indices, uint32_t stream_index) noexcept
{
	return std::binary_search(driver_stream_indices.begin(), driver_stream_indices.end(), stream_index);
}

/**
 * @brief Project the steering rows referenced by one exact I/O driver.
 *
 * @param topology Sole compiled topology.
 * @param driver_stream_indices Sorted exact stream set owned by this driver.
 * @param steering_indices Sorted unique referenced steering-profile indices.
 * @param owner Destination driver fact storage.
 * @return OK only when every profile is role-local and ABI-representable.
 */
[[nodiscard]] status project_driver_steering(const compiled_provider_topology &topology,
					     std::span<const uint32_t> driver_stream_indices,
					     std::span<const uint32_t> steering_indices, io_driver_fact_storage &owner)
{
	owner.steering_sources.reserve(steering_indices.size());
	for (const uint32_t steering_index : steering_indices) {
		if (steering_index >= topology.steering_profiles.size() ||
		    topology.steering_profiles[steering_index].steering_profile_index != steering_index) {
			return status::internal_error("compiled I/O driver references an invalid steering profile");
		}
		const auto &source = topology.steering_profiles[steering_index];
		for (const uint32_t stream_index : source.io_stream_indices) {
			if (!owns_stream(driver_stream_indices, stream_index)) {
				return status::internal_error("compiled steering profile crosses I/O-driver ownership");
			}
		}
		owner.steering_sources.push_back(source);
	}
	owner.steering_hash_fields.resize(owner.steering_sources.size());
	owner.steering_profiles.resize(owner.steering_sources.size());
	for (std::size_t index = 0; index < owner.steering_sources.size(); ++index) {
		const auto &source = owner.steering_sources[index];
		auto field_count_or = abi_count(source.hash_fields.size(), "steering hash-field set");
		auto stream_count_or = abi_count(source.io_stream_indices.size(), "steering stream set");
		if (!field_count_or.is_ok()) {
			return field_count_or.error();
		}
		if (!stream_count_or.is_ok()) {
			return stream_count_or.error();
		}
		auto &field_views = owner.steering_hash_fields[index];
		field_views.reserve(source.hash_fields.size());
		for (const auto &field : source.hash_fields) {
			auto field_view_or = abi_text_view(field);
			if (!field_view_or.is_ok()) {
				return field_view_or.error();
			}
			field_views.push_back(field_view_or.value());
		}
		auto hash_key_or = abi_byte_view(source.hash_key);
		if (!hash_key_or.is_ok()) {
			return hash_key_or.error();
		}
		kinetum_provider_steering_kind kind = 0;
		if (!abi_steering_kind(source.kind, kind)) {
			return status::internal_error("compiled steering profile has an unknown mechanism");
		}
		owner.steering_profiles[index] = kinetum_provider_steering_fact{
			.steering_profile_index = source.steering_profile_index,
			.kind = kind,
			.symmetric = static_cast<uint8_t>(source.symmetric),
			.kind_padding = {0},
			.hash_fields = data_or_null(field_views),
			.hash_field_count = field_count_or.value(),
			.hash_field_padding = 0,
			.hash_key = hash_key_or.value(),
			.io_stream_indices = data_or_null(source.io_stream_indices),
			.io_stream_count = stream_count_or.value(),
			.padding = {0},
		};
	}
	return status::ok();
}

/**
 * @brief Project every exact I/O-driver fact tree before component loading.
 * @param topology Compiled source topology and canonical provider configuration.
 * @param destination Unpublished projection storage; may be partially populated when a later row fails.
 * @return OK for a complete validated projection, or the first width/contract failure.
 */
[[nodiscard]] status project_io_drivers(const compiled_provider_topology &topology,
					std::vector<io_driver_fact_storage> &destination)
{
	auto driver_count_or = abi_count(topology.io_drivers.size(), "I/O-driver instance set");
	if (!driver_count_or.is_ok()) {
		return driver_count_or.error();
	}
	destination.resize(topology.io_drivers.size());
	for (std::size_t index = 0; index < topology.io_drivers.size(); ++index) {
		const auto &source = topology.io_drivers[index];
		auto &owner = destination[index];
		if (source.io_driver_index != index) {
			return status::internal_error(
				"compiled I/O-driver index disagrees with stable vector identity");
		}
		auto projection_status = project_attachments(source.attachments, owner.attachments);
		if (!projection_status.is_ok()) {
			return projection_status;
		}
		for (const auto &port : topology.ports) {
			if (port.io_driver_index != index) {
				continue;
			}
			kinetum_provider_io_direction direction = 0;
			if (!abi_port_direction(port.direction, direction)) {
				return status::internal_error("compiled I/O port has an unknown direction");
			}
			owner.ports.push_back(kinetum_provider_io_port_fact{
				.port_index = port.port_index,
				.driver_port_index = port.driver_port_index,
				.logical_port_id = port.logical_port_id,
				.mtu = port.mtu,
				.host_numa_node = port.host_numa_node.value_or(0),
				.direction = direction,
				.has_host_numa_node = static_cast<uint8_t>(port.host_numa_node.has_value()),
				.has_resolved_mac_address = static_cast<uint8_t>(port.has_resolved_mac_address),
				.direction_padding = 0,
				.resolved_mac_address = {port.resolved_mac_address[0], port.resolved_mac_address[1],
							 port.resolved_mac_address[2], port.resolved_mac_address[3],
							 port.resolved_mac_address[4], port.resolved_mac_address[5]},
				.padding = {0},
			});
		}

		std::vector<uint32_t> driver_stream_indices;
		std::vector<uint32_t> steering_indices;
		for (const auto &stream : topology.io_streams) {
			if (stream.port_index >= topology.ports.size()) {
				return status::internal_error("compiled I/O stream references an out-of-range port");
			}
			if (topology.ports[stream.port_index].io_driver_index != index) {
				continue;
			}
			kinetum_provider_io_direction direction = 0;
			if (!abi_stream_direction(stream.direction, direction)) {
				return status::internal_error("compiled I/O stream has an unknown direction");
			}
			if ((stream.direction == compiled_io_stream_direction::RX &&
			     (stream.rx_storage_domain_index >= KINETUM_INVALID_STORAGE_DOMAIN ||
			      !stream.tx_storage_domain_indices.empty())) ||
			    (stream.direction == compiled_io_stream_direction::TX &&
			     (stream.rx_storage_domain_index != INVALID_COMPILED_PROVIDER_INDEX ||
			      stream.tx_storage_domain_indices.empty()))) {
				return status::internal_error("compiled stream storage does not match its direction");
			}
			const auto domains = stream.storage_domain_indices();
			auto domain_count_or = abi_count(domains.size(), "I/O stream storage domains");
			if (!domain_count_or.is_ok()) {
				return domain_count_or.error();
			}
			owner.stream_storage_domains.emplace_back(domains.begin(), domains.end());
			const auto &storage = owner.stream_storage_domains.back();
			owner.streams.push_back(kinetum_provider_io_stream_fact{
				.io_stream_index = stream.io_stream_index,
				.port_index = stream.port_index,
				.stage_instance_index = stream.stage_instance_index,
				.worker_index = stream.worker_index,
				.driver_queue_id = stream.driver_queue_id,
				.descriptor_count = stream.descriptor_count,
				.steering_profile_index = stream.steering_profile_index.value_or(0),
				.direction = direction,
				.has_steering_profile = static_cast<uint8_t>(stream.steering_profile_index.has_value()),
				.padding = {0},
				.storage_domain_indices = storage.empty() ? nullptr : storage.data(),
				.storage_domain_count = domain_count_or.value(),
				.storage_padding = 0,
			});
			driver_stream_indices.push_back(stream.io_stream_index);
			if (stream.steering_profile_index.has_value()) {
				steering_indices.push_back(*stream.steering_profile_index);
			}
		}
		if (!std::is_sorted(driver_stream_indices.begin(), driver_stream_indices.end()) ||
		    std::adjacent_find(driver_stream_indices.begin(), driver_stream_indices.end()) !=
			    driver_stream_indices.end()) {
			return status::internal_error(
				"compiled I/O-driver stream set is not strictly sorted and unique");
		}
		std::sort(steering_indices.begin(), steering_indices.end());
		steering_indices.erase(std::unique(steering_indices.begin(), steering_indices.end()),
				       steering_indices.end());
		projection_status = project_driver_steering(topology, driver_stream_indices, steering_indices, owner);
		if (!projection_status.is_ok()) {
			return projection_status;
		}

		auto attachment_count_or = abi_count(owner.attachments.facts.size(), "I/O-driver attachment set");
		auto port_count_or = abi_count(owner.ports.size(), "I/O-driver port set");
		auto stream_count_or = abi_count(owner.streams.size(), "I/O-driver stream set");
		auto steering_count_or = abi_count(owner.steering_profiles.size(), "I/O-driver steering set");
		if (!attachment_count_or.is_ok()) {
			return attachment_count_or.error();
		}
		if (!port_count_or.is_ok()) {
			return port_count_or.error();
		}
		if (!stream_count_or.is_ok()) {
			return stream_count_or.error();
		}
		if (!steering_count_or.is_ok()) {
			return steering_count_or.error();
		}
		owner.facts = kinetum_provider_io_driver_facts{
			.io_driver_index = source.io_driver_index,
			.index_padding = 0,
			.attachments = data_or_null(owner.attachments.facts),
			.attachment_count = attachment_count_or.value(),
			.attachment_padding = 0,
			.ports = data_or_null(owner.ports),
			.port_count = port_count_or.value(),
			.port_padding = 0,
			.streams = data_or_null(owner.streams),
			.stream_count = stream_count_or.value(),
			.stream_padding = 0,
			.steering_profiles = data_or_null(owner.steering_profiles),
			.steering_profile_count = steering_count_or.value(),
			.steering_padding = 0,
		};
		kinetum_provider_compiled_fact_record record{};
		record.io_driver = &owner.facts;
		projection_status = finalize_identity(owner.identity, source.io_driver_instance_id,
						      source.configuration, provider_contract_role::IO_DRIVER,
						      static_cast<uint32_t>(index), record);
		if (!projection_status.is_ok()) {
			return projection_status;
		}
	}
	return status::ok();
}

/**
 * @brief Project every packet-storage fact record before component loading.
 * @param topology Compiled source topology and canonical provider configuration.
 * @param destination Unpublished projection storage; may be partially populated when a later row fails.
 * @return OK for a complete validated projection, or the first width/contract failure.
 */
[[nodiscard]] status project_packet_storage(const compiled_provider_topology &topology,
					    std::vector<packet_storage_fact_storage> &destination)
{
	auto storage_count_or = abi_count(topology.storage_domains.size(), "packet-storage instance set");
	if (!storage_count_or.is_ok()) {
		return storage_count_or.error();
	}
	destination.resize(topology.storage_domains.size());
	for (std::size_t index = 0; index < topology.storage_domains.size(); ++index) {
		const auto &source = topology.storage_domains[index];
		auto &owner = destination[index];
		if (source.storage_domain_index != index ||
		    source.budget.required_min_buffers > std::numeric_limits<uint32_t>::max()) {
			return status::internal_error(
				"compiled packet-storage identity or budget exceeds the component ABI");
		}
		owner.facts = kinetum_provider_packet_storage_facts{
			.storage_domain_index = source.storage_domain_index,
			.buffer_count = source.buffer_count,
			.data_room_bytes = source.data_room_bytes,
			.headroom_bytes = source.headroom_bytes,
			.alignment_bytes = source.alignment_bytes,
			.cache_size_per_worker = source.cache_size_per_worker,
			.required_buffer_count = static_cast<uint32_t>(source.budget.required_min_buffers),
			.safety_margin = source.budget.safety_margin,
			.host_numa_node = source.host_numa_node.value_or(0),
			.maximum_packet_length = source.maximum_packet_length,
			.access_agents = source.capabilities.access_agents,
			.has_host_numa_node = static_cast<uint8_t>(source.host_numa_node.has_value()),
			.padding = {0},
		};
		kinetum_provider_compiled_fact_record record{};
		record.packet_storage = &owner.facts;
		auto projection_status = finalize_identity(owner.identity, source.storage_domain_id,
							   source.configuration, provider_contract_role::PACKET_STORAGE,
							   static_cast<uint32_t>(index), record);
		if (!projection_status.is_ok()) {
			return projection_status;
		}
	}
	return status::ok();
}

/**
 * @brief Project every execution-provider fact tree before component loading.
 * @param topology Compiled source topology and canonical provider configuration.
 * @param destination Unpublished projection storage; may be partially populated when a later row fails.
 * @return OK for a complete validated projection, or the first width/contract failure.
 */
[[nodiscard]] status project_execution(const compiled_provider_topology &topology,
				       std::vector<execution_fact_storage> &destination)
{
	auto execution_count_or = abi_count(topology.execution_providers.size(), "execution-provider instance set");
	if (!execution_count_or.is_ok()) {
		return execution_count_or.error();
	}
	destination.resize(topology.execution_providers.size());
	for (std::size_t index = 0; index < topology.execution_providers.size(); ++index) {
		const auto &source = topology.execution_providers[index];
		auto &owner = destination[index];
		if (source.execution_provider_index != index) {
			return status::internal_error(
				"compiled execution-provider index disagrees with stable vector identity");
		}
		owner.stage_instance_indices = source.stage_instance_indices;
		owner.worker_indices = source.worker_indices;
		auto stage_count_or = abi_count(owner.stage_instance_indices.size(), "execution-provider stage set");
		auto worker_count_or = abi_count(owner.worker_indices.size(), "execution-provider worker set");
		if (!stage_count_or.is_ok()) {
			return stage_count_or.error();
		}
		if (!worker_count_or.is_ok()) {
			return worker_count_or.error();
		}
		owner.facts = kinetum_provider_execution_facts{
			.execution_provider_index = source.execution_provider_index,
			.required_access_agents = source.capabilities.required_access_agents,
			.index_padding = {0},
			.stage_instance_indices = data_or_null(owner.stage_instance_indices),
			.stage_instance_count = stage_count_or.value(),
			.stage_padding = 0,
			.worker_indices = data_or_null(owner.worker_indices),
			.worker_count = worker_count_or.value(),
			.worker_padding = 0,
		};
		kinetum_provider_compiled_fact_record record{};
		record.execution = &owner.facts;
		auto projection_status = finalize_identity(owner.identity, source.execution_provider_instance_id,
							   source.configuration, provider_contract_role::EXECUTION,
							   static_cast<uint32_t>(index), record);
		if (!projection_status.is_ok()) {
			return projection_status;
		}
	}
	return status::ok();
}

/**
 * @brief Project every storage-transition fact record before component loading.
 * @param topology Compiled source topology and canonical provider configuration.
 * @param destination Unpublished projection storage; may be partially populated when a later row fails.
 * @return OK for a complete validated projection, or the first width/contract failure.
 */
[[nodiscard]] status project_storage_transitions(const compiled_provider_topology &topology,
						 std::vector<storage_transition_fact_storage> &destination)
{
	auto transition_count_or = abi_count(topology.storage_transitions.size(), "storage-transition instance set");
	if (!transition_count_or.is_ok()) {
		return transition_count_or.error();
	}
	destination.resize(topology.storage_transitions.size());
	for (std::size_t index = 0; index < topology.storage_transitions.size(); ++index) {
		const auto &source = topology.storage_transitions[index];
		auto &owner = destination[index];
		kinetum_provider_endpoint_kind from_kind = 0;
		kinetum_provider_endpoint_kind to_kind = 0;
		kinetum_provider_transition_mode mode = 0;
		if (source.transition_index != index || !abi_endpoint_kind(source.from_endpoint.kind, from_kind) ||
		    !abi_endpoint_kind(source.to_endpoint.kind, to_kind) ||
		    !abi_transition_mode(source.capabilities.mode, mode)) {
			return status::internal_error(
				"compiled storage transition cannot be represented by the current ABI");
		}
		owner.facts = kinetum_provider_storage_transition_facts{
			.transition_index = source.transition_index,
			.from_endpoint =
				kinetum_provider_endpoint_fact{
					.kind = from_kind,
					.padding = {0},
					.endpoint_index = source.from_endpoint.endpoint_index,
				},
			.to_endpoint =
				kinetum_provider_endpoint_fact{
					.kind = to_kind,
					.padding = {0},
					.endpoint_index = source.to_endpoint.endpoint_index,
				},
			.from_storage_domain_index = source.from_storage_domain_index,
			.to_storage_domain_index = source.to_storage_domain_index,
			.staging_capacity = source.staging_capacity,
			.staging_numa_node = source.staging_numa_node.value_or(0),
			.mode = mode,
			.has_staging_numa_node = static_cast<uint8_t>(source.staging_numa_node.has_value()),
			.padding = {0},
		};
		kinetum_provider_compiled_fact_record record{};
		record.storage_transition = &owner.facts;
		auto projection_status = finalize_identity(owner.identity, source.transition_id, source.configuration,
							   provider_contract_role::STORAGE_TRANSITION,
							   static_cast<uint32_t>(index), record);
		if (!projection_status.is_ok()) {
			return projection_status;
		}
	}
	return status::ok();
}

/**
 * @brief Build and structurally validate the complete C-ABI projection.
 * @param topology Compiled source topology and canonical provider configuration.
 * @param destination Unpublished projection storage; may be partially populated when a later row fails.
 * @return OK for a complete validated projection, or the first width/contract failure.
 */
[[nodiscard]] status project_all_facts(const compiled_provider_topology &topology, fact_collection &destination)
{
	auto result = project_process_facilities(topology, destination.process_facilities);
	if (!result.is_ok()) {
		return result;
	}
	result = project_io_drivers(topology, destination.io_drivers);
	if (!result.is_ok()) {
		return result;
	}
	result = project_packet_storage(topology, destination.packet_storage);
	if (!result.is_ok()) {
		return result;
	}
	result = project_execution(topology, destination.execution);
	if (!result.is_ok()) {
		return result;
	}
	return project_storage_transitions(topology, destination.storage_transitions);
}

/**
 * @brief Map one closed host-fact value to its exact set bit.
 * @param fact Candidate host-fact enum.
 * @return One unique bit for a known fact, or zero for an unknown value.
 */
[[nodiscard]] constexpr uint8_t host_fact_bit(provider_host_fact fact) noexcept
{
	switch (fact) {
	case provider_host_fact::DPDK_EAL_RUNTIME:
		return uint8_t{1} << 0;
	case provider_host_fact::DPDK_HUGEPAGE_PAYLOAD_FLOOR:
		return uint8_t{1} << 1;
	case provider_host_fact::DPDK_ETHDEV_PORT:
		return uint8_t{1} << 2;
	case provider_host_fact::LINUX_IPV4_DATAGRAM_SOCKET:
		return uint8_t{1} << 3;
	case provider_host_fact::HOST_NUMA_MEMORY:
		return uint8_t{1} << 4;
	case provider_host_fact::CPU_WORKER_SET:
		return uint8_t{1} << 5;
	}
	return 0;
}

/**
 * @brief Compile one contract's duplicate-free COMPONENT-phase fact set.
 * @param contract Pure catalog contract whose requirements are inspected.
 * @return Component-proof mask, or an error for duplicate or unknown facts.
 */
[[nodiscard]] status_or<uint8_t> component_requirement_mask(const provider_contract_descriptor &contract)
{
	uint8_t mask = 0;
	for (const auto &requirement : contract.host_requirements) {
		if (requirement.phase != provider_host_proof_phase::COMPONENT_HOST_PROOF) {
			continue;
		}
		const uint8_t bit = host_fact_bit(requirement.fact);
		if (bit == 0 || (mask & bit) != 0) {
			return status::internal_error("pure provider contract has an invalid component host-proof set");
		}
		mask = static_cast<uint8_t>(mask | bit);
	}
	return mask;
}

/**
 * @brief Validate and compile the exact distinct component host-proof schedule.
 *
 * @param topology Sole compiled topology and requirement authority.
 * @param facts Complete role-indexed ABI projection.
 * @return Canonical role/instance schedule, or an internal two-authority
 *         disagreement before any component is loaded.
 */
[[nodiscard]] status_or<std::vector<const provider_component_instance_facts *>>
compile_component_host_proof_schedule(const compiled_provider_topology &topology, const fact_collection &facts)
{
	std::vector<uint8_t> compiled_masks(facts.size(), 0);
	for (const auto &requirement : topology.host_requirements) {
		if (requirement.phase != provider_host_proof_phase::COMPONENT_HOST_PROOF) {
			continue;
		}
		const auto *instance = facts.instance(requirement.role, requirement.instance_index);
		auto ordinal_or = facts.ordinal(requirement.role, requirement.instance_index);
		if (instance == nullptr || !ordinal_or.is_ok()) {
			return status::internal_error(
				"compiled component host proof has no exact provider-instance owner");
		}
		const auto *contract = find_provider_contract(instance->type_url);
		if (contract == nullptr || contract->role != instance->role) {
			return status::internal_error(
				"compiled component host-proof requirement disagrees with the pure contract catalog");
		}
		const uint8_t bit = host_fact_bit(requirement.fact);
		auto &mask = compiled_masks[ordinal_or.value()];
		if (bit == 0 || (mask & bit) != 0) {
			return status::internal_error(
				"compiled component host-proof set contains an invalid or duplicate fact");
		}
		mask = static_cast<uint8_t>(mask | bit);
	}

	std::vector<const provider_component_instance_facts *> schedule;
	schedule.reserve(facts.size());
	for (const auto role : ALL_PROVIDER_ROLES) {
		for (uint32_t index = 0;; ++index) {
			const auto *instance = facts.instance(role, index);
			if (instance == nullptr) {
				break;
			}
			auto ordinal_or = facts.ordinal(role, index);
			if (!ordinal_or.is_ok()) {
				return ordinal_or.error();
			}
			const auto *contract = find_provider_contract(instance->type_url);
			if (contract == nullptr || contract->role != role) {
				return status::internal_error(
					"compiled provider facts disagree with the pure contract catalog");
			}
			auto expected_or = component_requirement_mask(*contract);
			if (!expected_or.is_ok()) {
				return expected_or.error();
			}
			if (expected_or.value() != compiled_masks[ordinal_or.value()]) {
				return status::internal_error(
					"compiled component host-proof set is not exact in both directions");
			}
			if (expected_or.value() != 0) {
				schedule.push_back(instance);
			}
		}
	}
	return schedule;
}

/**
 * @brief Return whether a bounded component diagnostic is safe plain ASCII.
 * @param diagnostic Foreign result retaining caller-owned buffer identity and bounded extent.
 * @return true only for a representable buffer extent containing printable ASCII bytes.
 */
[[nodiscard]] bool diagnostic_is_valid(const kinetum_provider_diagnostic &diagnostic) noexcept
{
	if (diagnostic.size > diagnostic.capacity || (diagnostic.capacity != 0 && diagnostic.data == nullptr)) {
		return false;
	}
	for (uint32_t index = 0; index < diagnostic.size; ++index) {
		const auto byte = static_cast<unsigned char>(diagnostic.data[index]);
		if (byte < 0x20u || byte > 0x7eu) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Convert one exact callback result into the platform status domain.
 * @param callback_status Status returned by the component's host-proof callback.
 * @param instance Exact compiled instance identity used to attribute a failure.
 * @param diagnostic Caller-owned diagnostic bytes returned by the callback.
 * @return Admitted local status, or INTERNAL_ERROR for malformed foreign output.
 */
[[nodiscard]] status host_proof_status(kinetum_provider_status callback_status,
				       const provider_component_instance_facts &instance,
				       const kinetum_provider_diagnostic &diagnostic)
{
	if (!kinetum_provider_status_is_valid(callback_status) || !diagnostic_is_valid(diagnostic)) {
		return status::internal_error("provider component returned an invalid host-proof result");
	}
	if (callback_status == KINETUM_PROVIDER_STATUS_OK) {
		if (diagnostic.size != 0u) {
			return status::internal_error(
				"provider component host-proof success carried diagnostic residue");
		}
		return status::ok();
	}
	std::string message =
		"provider component host proof failed for instance '" + std::string(instance.instance_id) + "'";
	if (diagnostic.size != 0) {
		message.append(": ");
		message.append(diagnostic.data, diagnostic.size);
	}
	switch (callback_status) {
	case KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT:
		return status::internal_error(std::move(message));
	case KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION:
		return status::failed_precondition(std::move(message));
	case KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED:
		return status::resource_exhausted(std::move(message));
	case KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR:
		return status::internal_error(std::move(message));
	case KINETUM_PROVIDER_STATUS_OK:
	default:
		break;
	}
	return status::internal_error("provider component returned an unreachable host-proof status");
}

/**
 * @brief Invoke every precompiled non-materializing component proof exactly once.
 * @param schedule Canonical borrowed instance rows requiring component-side host proof.
 * @param catalog Admitted component images retaining the required proof callbacks.
 * @return OK after all scheduled proofs succeed, or the first admission/callback failure.
 */
[[nodiscard]] status
prove_component_host_requirements(const std::vector<const provider_component_instance_facts *> &schedule,
				  const runtime_provider_catalog &catalog)
{
	for (const auto *instance : schedule) {
		if (instance == nullptr) {
			return status::internal_error("provider component host-proof schedule contains a null row");
		}
		const auto *catalog_row = catalog.find(instance->type_url);
		kinetum_provider_role role = 0;
		if (catalog_row == nullptr || catalog_row->implementation == nullptr ||
		    !abi_provider_role(instance->role, role) || catalog_row->implementation->role != role ||
		    catalog_row->implementation->host_proof == nullptr) {
			return status::internal_error(
				"sealed provider catalog lacks one exact compiled component host-proof authority");
		}
		auto type_url_or = abi_text_view(instance->type_url);
		auto configuration_or = abi_byte_view(instance->canonical_configuration);
		if (!type_url_or.is_ok()) {
			return type_url_or.error();
		}
		if (!configuration_or.is_ok()) {
			return configuration_or.error();
		}
		const kinetum_provider_host_proof_request request{
			.type_url = type_url_or.value(),
			.canonical_configuration = configuration_or.value(),
			.compiled_facts = instance->compiled_facts,
			.role = role,
			.padding = {0},
		};
		if (kinetum_provider_host_proof_request_is_valid(&request) == 0) {
			return status::internal_error("compiled component host-proof request violates the exact C ABI");
		}
		std::array<char, PROVIDER_HOST_PROOF_DIAGNOSTIC_BYTES> diagnostic_bytes{};
		kinetum_provider_diagnostic diagnostic{
			.data = diagnostic_bytes.data(),
			.capacity = static_cast<uint32_t>(diagnostic_bytes.size()),
			.size = 0,
		};
		char *const diagnostic_data = diagnostic.data;
		const uint32_t diagnostic_capacity = diagnostic.capacity;
		const auto callback_status = catalog_row->implementation->host_proof(&request, &diagnostic);
		if (diagnostic.data != diagnostic_data || diagnostic.capacity != diagnostic_capacity) {
			return status::internal_error(
				"provider component replaced caller-owned host-proof diagnostic storage");
		}
		auto result = host_proof_status(callback_status, *instance, diagnostic);
		if (!result.is_ok()) {
			return result;
		}
	}
	return status::ok();
}

/**
 * @brief Emit one bounded post-load failure and terminate without unwinding.
 *
 * The retained catalog may own component and private-dependency handles whose
 * constructors have executed. Returning would destroy those handles and make
 * `dlclose()` an unproved rollback path, so this function cannot return.
 *
 * @param failure Exact COMPONENT-phase callback or host-validation failure.
 */
[[noreturn]] void fail_stop_after_component_load(const status &failure) noexcept
{
	try {
		std::string diagnostic = "provider runtime admission failed after component loading [";
		diagnostic.append(common::status_code_name(failure.code()));
		diagnostic.append("]: ");

		const std::string_view message = failure.message();
		const std::size_t remaining = diagnostic.size() < PROVIDER_POST_LOAD_FAILURE_DIAGNOSTIC_BYTES ?
						      PROVIDER_POST_LOAD_FAILURE_DIAGNOSTIC_BYTES - diagnostic.size() :
						      0;
		if (message.size() <= remaining) {
			diagnostic.append(message);
		} else if (remaining > 3) {
			std::string_view prefix = message;
			prefix.remove_suffix(prefix.size() - (remaining - 3u));
			diagnostic.append(prefix);
			diagnostic.append("...");
		} else {
			std::string_view prefix = message;
			prefix.remove_suffix(prefix.size() - remaining);
			diagnostic.append(prefix);
		}

		std::fprintf(stderr, "provider: %s\n", diagnostic.c_str());
		(void)std::fflush(stderr);
		common::offer_fatal_log({common::log_level::FATAL, "provider", "provider.admission.fatal", __func__},
					diagnostic);
	} catch (...) {
		std::fputs("provider: runtime admission failed after component loading; diagnostic emission failed\n",
			   stderr);
	}
	std::terminate();
}

}  // namespace

/** @brief Heap-owned stable ABI fact projection retained by the admitted runtime. */
struct admitted_provider_runtime::fact_storage {
	fact_collection facts;	///< Complete self-contained role-partitioned ABI projection.
};

admitted_provider_runtime::admitted_provider_runtime(std::unique_ptr<fact_storage> facts,
						     runtime_provider_catalog catalog) noexcept
	: catalog_(std::move(catalog))
	, facts_(std::move(facts))
{
}

admitted_provider_runtime::~admitted_provider_runtime() = default;

admitted_provider_runtime::admitted_provider_runtime(admitted_provider_runtime &&) noexcept = default;

const runtime_provider_catalog &admitted_provider_runtime::catalog() const noexcept
{
	return catalog_;
}

const provider_component_instance_facts *
admitted_provider_runtime::instance_facts(provider_contract_role role, uint32_t instance_index) const noexcept
{
	return facts_ != nullptr ? facts_->facts.instance(role, instance_index) : nullptr;
}

std::size_t admitted_provider_runtime::instance_count() const noexcept
{
	return facts_ != nullptr ? facts_->facts.size() : 0;
}

status_or<admitted_provider_runtime> admit_installed_provider_runtime(const compiled_provider_topology &topology,
								      const std::filesystem::path &installation_root,
								      const std::filesystem::path &runtime_image,
								      const common::ed25519_public_key &trust_anchor,
								      const common::held_file_policy &file_policy)
{
	std::unique_ptr<admitted_provider_runtime::fact_storage> facts;
	std::vector<const provider_component_instance_facts *> schedule;
	std::vector<std::string_view> required_type_urls;
	try {
		facts = std::make_unique<admitted_provider_runtime::fact_storage>();
		auto result = project_all_facts(topology, facts->facts);
		if (!result.is_ok()) {
			return result;
		}
		auto schedule_or = compile_component_host_proof_schedule(topology, facts->facts);
		if (!schedule_or.is_ok()) {
			return schedule_or.error();
		}
		schedule = std::move(schedule_or).value();
		required_type_urls.reserve(topology.required_contract_type_urls.size());
		for (const auto &type_url : topology.required_contract_type_urls) {
			required_type_urls.emplace_back(type_url);
		}
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(
			kinetum::common::static_status_text("provider runtime fact projection exhausted host memory"));
	} catch (const std::length_error &) {
		return status(common::status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "provider runtime fact projection exceeded the host size domain"));
	}
	auto catalog_or = load_installed_provider_catalog(installation_root, runtime_image, required_type_urls,
							  trust_anchor, file_policy);
	if (!catalog_or.is_ok()) {
		return catalog_or.error();
	}
	runtime_provider_catalog catalog = std::move(catalog_or).value();
	try {
		auto result = prove_component_host_requirements(schedule, catalog);
		if (!result.is_ok()) {
			fail_stop_after_component_load(result);
		}
		return admitted_provider_runtime(std::move(facts), std::move(catalog));
	} catch (...) {
		// The catalog remains alive in this enclosing scope. Terminate before
		// stack unwinding can turn its retained handles into an implicit unload.
		std::terminate();
	}
}

}  // namespace kinetum::provider
