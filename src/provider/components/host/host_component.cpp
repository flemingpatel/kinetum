// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file host_component.cpp
 * @brief Exact host storage, CPU execution, and core transition component.
 * @author Fleming Patel
 *
 * One link-closed component implements four orthogonal host contracts. Each
 * factory returns only its role-specific operation record. Packet work uses
 * pre-resolved burst callbacks and performs no lookup, allocation, lock,
 * exception, string operation, or provider-kind branch.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <exception>
#include <iterator>
#include <limits>
#include <new>
#include <string_view>
#include <utility>

#include "gen/kinetum/provider/provider_build_identity.h"
#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"
#include "src/dp/fixed_packet_pool.hpp"
#include "src/provider/components/component_support.hpp"
#include "src/provider/provider_component_abi.h"

namespace kinetum::provider::host_component
{
namespace
{

using component_support::empty_factory_request_is_exact;
using component_support::fail;
using component_support::static_text_view;

/** Stable identity exported by the host component descriptor. */
constexpr char COMPONENT_ID[] = "kinetum.provider.host";
/** Exact contract identity admitted by the CPU execution factory. */
constexpr char CPU_EXECUTION_TYPE_URL[] = "type.googleapis.com/kinetum.execution.cpu.v1.CpuExecutionConfig";
/** Exact contract identity admitted by the host-storage factory. */
constexpr char HOST_STORAGE_TYPE_URL[] = "type.googleapis.com/kinetum.storage.host.v1.HostStorageConfig";
/** Exact contract identity for same-domain ownership transfer. */
constexpr char ZERO_COPY_SHARE_TYPE_URL[] = "type.googleapis.com/kinetum.transition.core.v1.ZeroCopyShareConfig";
/** Exact contract identity for copying between distinct storage domains. */
constexpr char BOUNDED_COPY_TYPE_URL[] = "type.googleapis.com/kinetum.transition.cpu.v1.BoundedCopyConfig";
/** Maximum record prefix supported by the component's fixed packet-path staging. */
constexpr uint16_t MAX_BURST = static_cast<uint16_t>(common::runtime_sizing::PACKET_MAX_BURST_SIZE);

/** @brief One exact CPU execution instance and immutable role record. */
struct cpu_execution_instance {
	kinetum_provider_execution_operations operations{};  ///< Published exact execution operations.
};

/** @brief One exact zero-copy or bounded-copy transition instance. */
struct transition_instance {
	kinetum_provider_storage_transition_operations operations{};	       ///< Published transition operation.
	const kinetum_packet_storage_domain_operations *source{nullptr};       ///< Borrowed source-domain table.
	const kinetum_packet_storage_domain_operations *destination{nullptr};  ///< Borrowed destination table.
	uint16_t maximum_burst{0};  ///< Exact synchronous staging bound for one call.
};

/**
 * @brief Destroy one host fixed-pool instance after every dependent object.
 * @param instance Sole quiescent instance returned by this component, or nullptr.
 */
void destroy_host_storage(void *instance) noexcept
{
	delete static_cast<dp::fixed_packet_pool *>(instance);
}

/**
 * @brief Destroy one CPU execution instance.
 * @param instance Sole quiescent instance returned by this component, or nullptr.
 */
void destroy_cpu_execution(void *instance) noexcept
{
	delete static_cast<cpu_execution_instance *>(instance);
}

/**
 * @brief Destroy one quiescent transition instance.
 * @param instance Sole quiescent instance returned by this component, or nullptr.
 */
void destroy_transition(void *instance) noexcept
{
	delete static_cast<transition_instance *>(instance);
}

/**
 * @brief Find one exact storage dependency by compact domain identity.
 *
 * @param request Exact factory request.
 * @param domain_index Required compact storage domain.
 * @return Borrowed immutable storage operations, or null on mismatch.
 */
[[nodiscard]] const kinetum_packet_storage_domain_operations *
find_storage_dependency(const kinetum_provider_factory_request &request, uint32_t domain_index) noexcept
{
	if (domain_index >= KINETUM_INVALID_STORAGE_DOMAIN) {
		return nullptr;
	}
	const kinetum_packet_storage_domain_operations *match = nullptr;
	for (uint32_t index = 0; index < request.dependency_count; ++index) {
		const auto &dependency = request.dependencies[index];
		if (dependency.role != KINETUM_PROVIDER_ROLE_PACKET_STORAGE) {
			continue;
		}
		const auto *operations =
			static_cast<const kinetum_packet_storage_domain_operations *>(dependency.operations);
		if (operations->domain_index != domain_index) {
			continue;
		}
		if (match != nullptr) {
			return nullptr;
		}
		match = operations;
	}
	return match;
}

/**
 * @brief Transfer one fully validated same-domain burst without copying.
 *
 * @param state Exact transition instance.
 * @param sources Caller-owned source array.
 * @param destinations Caller-owned destination array.
 * @param count Exact requested packet count.
 * @return Complete count on success, or zero without publication.
 */
uint16_t transfer_zero_copy(void *state, kinetum_packet_record *const *sources, kinetum_packet_record **destinations,
			    uint16_t count) noexcept
{
	auto *transition = static_cast<transition_instance *>(state);
	if (transition == nullptr || sources == nullptr || destinations == nullptr || count == 0 ||
	    count > transition->maximum_burst || transition->source == nullptr ||
	    transition->destination != transition->source) {
		return 0;
	}
	for (uint16_t index = 0; index < count; ++index) {
		const auto *record = sources[index];
		if (record == nullptr || record->storage.operations != transition->source ||
		    record->storage.generation != transition->source->generation ||
		    record->storage.domain_index != transition->source->domain_index) {
			return 0;
		}
	}
	// The ABI permits overlap between source and destination pointer-array
	// ranges. memmove preserves the validated ownership prefix without a second
	// per-packet branch or an additional scratch pass.
	std::memmove(destinations, sources, static_cast<std::size_t>(count) * sizeof(*destinations));
	return count;
}

/**
 * @brief Copy one bounded source prefix into preallocated destination storage.
 *
 * The complete attempted prefix is validated before the destination provider
 * is invoked. Each destination receives the exact source metadata, then the
 * source domain retires only the prefix actually materialized. The untouched
 * suffix remains caller-owned.
 *
 * @param state Exact transition instance.
 * @param sources Caller-owned source array.
 * @param destinations Caller-owned destination array.
 * @param count Exact requested packet count.
 * @return Exact copied and source-retired prefix.
 */
uint16_t transfer_bounded_copy(void *state, kinetum_packet_record *const *sources, kinetum_packet_record **destinations,
			       uint16_t count) noexcept
{
	auto *transition = static_cast<transition_instance *>(state);
	if (transition == nullptr || sources == nullptr || destinations == nullptr || count == 0 ||
	    transition->source == nullptr || transition->destination == nullptr ||
	    transition->source == transition->destination) {
		return 0;
	}
	const uint16_t attempted = std::min(count, transition->maximum_burst);
	// Both operations consume only their exact written prefix. Do not clear the
	// untouched stack suffix on this packet-path transition.
	std::array<kinetum_packet_origin_view, common::runtime_sizing::PACKET_MAX_BURST_SIZE> origins;
	std::array<kinetum_packet_record *, common::runtime_sizing::PACKET_MAX_BURST_SIZE> copied;
	std::array<kinetum_packet_record *, common::runtime_sizing::PACKET_MAX_BURST_SIZE> owned_sources;
	for (uint16_t index = 0; index < attempted; ++index) {
		auto *record = sources[index];
		if (record == nullptr || record->storage.operations != transition->source ||
		    record->storage.generation != transition->source->generation ||
		    record->storage.domain_index != transition->source->domain_index ||
		    record->storage.data == nullptr || record->storage.length == 0 ||
		    record->storage.length > transition->destination->maximum_packet_length ||
		    record->storage.contiguous_length < record->storage.length || record->storage.segment_count != 1 ||
		    (record->storage.capabilities & KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ) == 0) {
			return 0;
		}
		origins[index] = kinetum_packet_origin_view{
			.data = record->storage.data,
			.length = record->storage.length,
			.padding = 0,
		};
		owned_sources[index] = record;
	}

	const uint16_t accepted = transition->destination->copy_origins_burst(transition->destination->state,
									      origins.data(), copied.data(), attempted);
	if (accepted > attempted) {
		std::terminate();
	}
	for (uint16_t index = 0; index < accepted; ++index) {
		if (copied[index] == nullptr || copied[index]->storage.operations != transition->destination ||
		    copied[index]->storage.generation != transition->destination->generation ||
		    copied[index]->storage.domain_index != transition->destination->domain_index ||
		    copied[index]->storage.length != owned_sources[index]->storage.length) {
			std::terminate();
		}
		copied[index]->metadata = owned_sources[index]->metadata;
		destinations[index] = copied[index];
	}
	if (accepted != 0) {
		transition->source->release_burst(transition->source->state, owned_sources.data(), accepted);
	}
	return accepted;
}

/**
 * @brief Map fixed-pool construction status into the closed component status set.
 * @param status Non-OK pool-construction result.
 * @return Matching provider failure code; unclassified errors become IMPLEMENTATION_ERROR.
 */
[[nodiscard]] kinetum_provider_status storage_status(const common::status &status) noexcept
{
	switch (status.code()) {
	case common::status_code::INVALID_ARGUMENT:
	case common::status_code::OUT_OF_RANGE:
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	case common::status_code::RESOURCE_EXHAUSTED:
		return KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED;
	case common::status_code::FAILED_PRECONDITION:
		return KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION;
	default:
		return KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR;
	}
}

/**
 * @brief Materialize one exact fixed host-storage domain.
 * @param request Borrowed compiled facts and dependency handles for this exact factory role.
 * @param result Initially empty output receiving the instance, operations, and destroy callback on success.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK transfers complete instance ownership; failure transfers none.
 */
kinetum_provider_status create_host_storage(const kinetum_provider_factory_request *request,
					    kinetum_provider_factory_result *result,
					    kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!empty_factory_request_is_exact(request, result, KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
					    HOST_STORAGE_TYPE_URL)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "host storage factory received a malformed request");
	}
	const auto &facts = *request->compiled_facts.packet_storage;
	if (request->dependency_count != 0 || facts.storage_domain_index >= KINETUM_INVALID_STORAGE_DOMAIN ||
	    facts.buffer_count == 0 || facts.buffer_count < facts.required_buffer_count || facts.data_room_bytes == 0 ||
	    facts.headroom_bytes >= facts.data_room_bytes || facts.alignment_bytes == 0 ||
	    (facts.alignment_bytes & (facts.alignment_bytes - 1u)) != 0 ||
	    facts.maximum_packet_length != facts.data_room_bytes - facts.headroom_bytes ||
	    facts.access_agents != KINETUM_PROVIDER_ACCESS_AGENT_CPU || facts.has_host_numa_node != 1 ||
	    facts.host_numa_node < 0 || request->runtime_generation > UINT32_MAX) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "host storage facts do not describe one exact CPU domain");
	}

	try {
		auto pool_or = dp::fixed_packet_pool::create(dp::fixed_packet_pool_options{
			.record_count = facts.buffer_count,
			.data_room_bytes = facts.data_room_bytes,
			.headroom_bytes = facts.headroom_bytes,
			.alignment_bytes = facts.alignment_bytes,
			.domain_index = static_cast<uint16_t>(facts.storage_domain_index),
			.generation = static_cast<uint32_t>(request->runtime_generation),
			.host_numa_node = facts.host_numa_node,
		});
		if (!pool_or.is_ok()) {
			return fail(storage_status(pool_or.error()), diagnostic, "host storage allocation failed");
		}
		auto pool = std::move(pool_or).value();
		result->instance = pool.release();
		result->operations = &static_cast<dp::fixed_packet_pool *>(result->instance)->operations();
		result->destroy = destroy_host_storage;
		component_support::write_diagnostic(diagnostic, std::string_view{});
		return KINETUM_PROVIDER_STATUS_OK;
	} catch (const std::bad_alloc &) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
			    "host storage construction exhausted process memory");
	} catch (...) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "host storage construction raised an unexpected failure");
	}
}

/**
 * @brief Materialize one exact CPU execution identity and access proof.
 * @param request Borrowed compiled facts and dependency handles for this exact factory role.
 * @param result Initially empty output receiving the instance, operations, and destroy callback on success.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK transfers complete instance ownership; failure transfers none.
 */
kinetum_provider_status create_cpu_execution(const kinetum_provider_factory_request *request,
					     kinetum_provider_factory_result *result,
					     kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!empty_factory_request_is_exact(request, result, KINETUM_PROVIDER_ROLE_EXECUTION, CPU_EXECUTION_TYPE_URL)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "CPU execution factory received a malformed request");
	}
	const auto &facts = *request->compiled_facts.execution;
	if (facts.required_access_agents != KINETUM_PROVIDER_ACCESS_AGENT_CPU || facts.stage_instance_count == 0 ||
	    facts.stage_instance_indices == nullptr || facts.worker_count == 0 || facts.worker_indices == nullptr ||
	    request->dependency_count == 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "CPU execution facts or storage dependencies are incomplete");
	}
	constexpr uint32_t REQUIRED_CPU_ACCESS = KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ |
						 KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE;
	for (uint32_t index = 0; index < request->dependency_count; ++index) {
		if (request->dependencies[index].role != KINETUM_PROVIDER_ROLE_PACKET_STORAGE) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "CPU execution received a non-storage dependency");
		}
		const auto *storage = static_cast<const kinetum_packet_storage_domain_operations *>(
			request->dependencies[index].operations);
		if ((storage->capabilities & REQUIRED_CPU_ACCESS) != REQUIRED_CPU_ACCESS) {
			return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
				    "CPU execution storage lacks contiguous read/write access");
		}
	}

	auto *instance = new (std::nothrow) cpu_execution_instance;
	if (instance == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic, "CPU execution allocation failed");
	}
	instance->operations.state = instance;
	instance->operations.execution_provider_index = facts.execution_provider_index;
	instance->operations.required_access_agents = facts.required_access_agents;
	result->instance = instance;
	result->operations = &instance->operations;
	result->destroy = destroy_cpu_execution;
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Materialize one exact same-domain zero-copy transition.
 * @param request Borrowed compiled facts and dependency handles for this exact factory role.
 * @param result Initially empty output receiving the instance, operations, and destroy callback on success.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK transfers complete instance ownership; failure transfers none.
 */
kinetum_provider_status create_zero_copy(const kinetum_provider_factory_request *request,
					 kinetum_provider_factory_result *result,
					 kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!empty_factory_request_is_exact(request, result, KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION,
					    ZERO_COPY_SHARE_TYPE_URL)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "zero-copy factory received a malformed request");
	}
	const auto &facts = *request->compiled_facts.storage_transition;
	const auto *storage = find_storage_dependency(*request, facts.from_storage_domain_index);
	if (request->runtime_generation > UINT32_MAX || request->dependency_count != 1 || storage == nullptr ||
	    facts.mode != KINETUM_PROVIDER_TRANSITION_ZERO_COPY_SHARE ||
	    facts.from_storage_domain_index != facts.to_storage_domain_index || facts.staging_capacity != 0 ||
	    facts.has_staging_numa_node != 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "zero-copy facts do not describe one exact same-domain handoff");
	}
	auto *instance = new (std::nothrow) transition_instance;
	if (instance == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
			    "zero-copy transition allocation failed");
	}
	instance->source = storage;
	instance->destination = storage;
	instance->maximum_burst = MAX_BURST;
	instance->operations.state = instance;
	instance->operations.transfer_burst = transfer_zero_copy;
	instance->operations.generation = static_cast<uint32_t>(request->runtime_generation);
	instance->operations.transition_index = facts.transition_index;
	instance->operations.from_storage_domain_index = facts.from_storage_domain_index;
	instance->operations.to_storage_domain_index = facts.to_storage_domain_index;
	instance->operations.mode = facts.mode;
	result->instance = instance;
	result->operations = &instance->operations;
	result->destroy = destroy_transition;
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Materialize one exact CPU bounded-copy transition.
 * @param request Borrowed compiled facts and dependency handles for this exact factory role.
 * @param result Initially empty output receiving the instance, operations, and destroy callback on success.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK transfers complete instance ownership; failure transfers none.
 */
kinetum_provider_status create_bounded_copy(const kinetum_provider_factory_request *request,
					    kinetum_provider_factory_result *result,
					    kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!empty_factory_request_is_exact(request, result, KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION,
					    BOUNDED_COPY_TYPE_URL)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "bounded-copy factory received a malformed request");
	}
	const auto &facts = *request->compiled_facts.storage_transition;
	const auto *source = find_storage_dependency(*request, facts.from_storage_domain_index);
	const auto *destination = find_storage_dependency(*request, facts.to_storage_domain_index);
	if (request->runtime_generation > UINT32_MAX || request->dependency_count != 2 || source == nullptr ||
	    destination == nullptr || source == destination || facts.mode != KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY ||
	    facts.from_storage_domain_index == facts.to_storage_domain_index || facts.staging_capacity == 0 ||
	    facts.has_staging_numa_node == 0 ||
	    (source->capabilities & KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ) == 0 ||
	    (destination->capabilities & KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE) == 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "bounded-copy facts or storage dependencies are incomplete");
	}
	auto *instance = new (std::nothrow) transition_instance;
	if (instance == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
			    "bounded-copy transition allocation failed");
	}
	instance->source = source;
	instance->destination = destination;
	instance->maximum_burst = static_cast<uint16_t>(
		std::min<uint32_t>(facts.staging_capacity, common::runtime_sizing::PACKET_MAX_BURST_SIZE));
	instance->operations.state = instance;
	instance->operations.transfer_burst = transfer_bounded_copy;
	instance->operations.generation = static_cast<uint32_t>(request->runtime_generation);
	instance->operations.transition_index = facts.transition_index;
	instance->operations.from_storage_domain_index = facts.from_storage_domain_index;
	instance->operations.to_storage_domain_index = facts.to_storage_domain_index;
	instance->operations.mode = facts.mode;
	result->instance = instance;
	result->operations = &instance->operations;
	result->destroy = destroy_transition;
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

/** Type-URL-sorted factory inventory exported by this component. */
constexpr kinetum_provider_contract_implementation CONTRACTS[]{
	{
		.type_url = static_text_view(CPU_EXECUTION_TYPE_URL),
		.factories =
			{
				.process_facility = nullptr,
				.io_driver = nullptr,
				.packet_storage = nullptr,
				.execution = create_cpu_execution,
				.storage_transition = nullptr,
			},
		.host_proof = nullptr,
		.role = KINETUM_PROVIDER_ROLE_EXECUTION,
		.padding = {0},
	},
	{
		.type_url = static_text_view(HOST_STORAGE_TYPE_URL),
		.factories =
			{
				.process_facility = nullptr,
				.io_driver = nullptr,
				.packet_storage = create_host_storage,
				.execution = nullptr,
				.storage_transition = nullptr,
			},
		.host_proof = nullptr,
		.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
		.padding = {0},
	},
	{
		.type_url = static_text_view(ZERO_COPY_SHARE_TYPE_URL),
		.factories =
			{
				.process_facility = nullptr,
				.io_driver = nullptr,
				.packet_storage = nullptr,
				.execution = nullptr,
				.storage_transition = create_zero_copy,
			},
		.host_proof = nullptr,
		.role = KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION,
		.padding = {0},
	},
	{
		.type_url = static_text_view(BOUNDED_COPY_TYPE_URL),
		.factories =
			{
				.process_facility = nullptr,
				.io_driver = nullptr,
				.packet_storage = nullptr,
				.execution = nullptr,
				.storage_transition = create_bounded_copy,
			},
		.host_proof = nullptr,
		.role = KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION,
		.padding = {0},
	},
};

/** Immutable product, ABI, and contract identity returned by the component query. */
constexpr kinetum_provider_component_descriptor DESCRIPTOR{
	.product_version_major = KINETUM_PROVIDER_PRODUCT_VERSION_MAJOR,
	.product_version_minor = KINETUM_PROVIDER_PRODUCT_VERSION_MINOR,
	.product_version_patch = KINETUM_PROVIDER_PRODUCT_VERSION_PATCH,
	.version_padding = {0},
	.abi_identity = KINETUM_PROVIDER_ABI_IDENTITY_INITIALIZER,
	.component_id = static_text_view(COMPONENT_ID),
	.contracts = CONTRACTS,
	.contract_count = static_cast<uint32_t>(std::size(CONTRACTS)),
	.tail_padding = {0},
};

static_assert(std::string_view(CPU_EXECUTION_TYPE_URL) < std::string_view(HOST_STORAGE_TYPE_URL));
static_assert(std::string_view(HOST_STORAGE_TYPE_URL) < std::string_view(ZERO_COPY_SHARE_TYPE_URL));
static_assert(std::string_view(ZERO_COPY_SHARE_TYPE_URL) < std::string_view(BOUNDED_COPY_TYPE_URL));

}  // namespace
}  // namespace kinetum::provider::host_component

extern "C" const kinetum_provider_component_descriptor *kinetum_provider_component_query(void) noexcept
{
	return &kinetum::provider::host_component::DESCRIPTOR;
}
