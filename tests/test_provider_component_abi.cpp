// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_component_abi.cpp
 * @brief Exact provider-component C ABI identity and layout tests.
 * @author Fleming Patel
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

#include <gtest/gtest.h>

#include "src/dp/packet.hpp"
#include "src/provider/provider_build_identity.hpp"
#include "src/provider/provider_component_abi.h"
#include "tests/provider_log_capture.hpp"

namespace kinetum::provider
{
namespace
{

/**
 * @brief Minimal callback used only to prove role-partitioned factory shape.
 * @return OK without constructing an instance; only callback shape is under test.
 */
kinetum_provider_status abi_test_factory(const kinetum_provider_factory_request *, kinetum_provider_factory_result *,
					 kinetum_provider_diagnostic *) noexcept
{
	return KINETUM_PROVIDER_STATUS_OK;
}

/** @brief Minimal destroy callback used only to prove result ownership shape. */
void abi_test_destroy(void *) noexcept
{
}

/**
 * @brief Minimal facility worker-registration callback for ABI shape tests.
 * @return OK without registering a thread.
 */
kinetum_provider_status abi_test_register_worker(void *, uint32_t, kinetum_provider_diagnostic *) noexcept
{
	return KINETUM_PROVIDER_STATUS_OK;
}

/** @brief Minimal facility worker-unregistration callback for ABI shape tests. */
void abi_test_unregister_worker(void *, uint32_t) noexcept
{
}

/**
 * @brief Minimal facility coordinator-binding callback for ABI shape tests.
 * @return OK without binding a coordinator.
 */
kinetum_provider_status abi_test_bind_coordinator(void *, uint32_t, int32_t, kinetum_provider_diagnostic *) noexcept
{
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Minimal facility service-launch callback for ABI shape tests.
 * @return OK without launching the unused callback.
 */
kinetum_provider_status abi_test_launch_service(void *, uint32_t, int32_t, kinetum_provider_runtime_service_entry_fn,
						void *, kinetum_provider_diagnostic *) noexcept
{
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Minimal facility service-join callback for ABI shape tests.
 * @return OK without joining a service.
 */
kinetum_provider_status abi_test_join_service(void *, uint32_t, int32_t, kinetum_provider_diagnostic *) noexcept
{
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Minimal storage acquire callback for ABI legality tests.
 * @return Zero without acquiring records.
 */
uint16_t abi_test_acquire(void *, kinetum_packet_record **, uint16_t) noexcept
{
	return 0;
}

/**
 * @brief Minimal storage clone callback for ABI legality tests.
 * @return nullptr without cloning a record.
 */
kinetum_packet_record *abi_test_clone(void *, const kinetum_packet_record *) noexcept
{
	return nullptr;
}

/**
 * @brief Minimal storage origin-copy callback for ABI legality tests.
 * @return Zero without copying or acquiring records.
 */
uint16_t abi_test_copy_origins(void *, const kinetum_packet_origin_view *, kinetum_packet_record **, uint16_t) noexcept
{
	return 0;
}

/** @brief Minimal storage retirement callback for ABI legality tests. */
void abi_test_release(void *, kinetum_packet_record *const *, uint16_t) noexcept
{
}

/**
 * @brief Minimal storage-observation callback for ABI legality tests.
 * @return OK without populating observation storage.
 */
kinetum_provider_status abi_test_observe_storage(void *, kinetum_provider_storage_observation *,
						 kinetum_provider_diagnostic *) noexcept
{
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Minimal receive callback for ABI legality tests.
 * @return An empty transfer/rejection result without receiving records.
 */
kinetum_packet_rx_burst_result abi_test_receive(void *, kinetum_packet_record **, uint16_t) noexcept
{
	return {};
}

/**
 * @brief Minimal cold I/O lifecycle callback for ABI legality tests.
 * @return OK without changing packet-I/O state.
 */
kinetum_provider_status abi_test_io_lifecycle(void *, kinetum_provider_diagnostic *) noexcept
{
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Minimal whole-driver observation callback for ABI legality tests.
 * @return OK without populating observation storage.
 */
kinetum_provider_status abi_test_observe_io(void *, kinetum_provider_io_observation_batch *,
					    kinetum_provider_diagnostic *) noexcept
{
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Minimal transmit callback for ABI legality tests.
 * @return Zero without accepting records.
 */
uint16_t abi_test_transmit(void *, kinetum_packet_record *const *, uint16_t) noexcept
{
	return 0;
}

/** @brief Minimal transmit flush callback for ABI legality tests. */
void abi_test_flush(void *) noexcept
{
}

/**
 * @brief Minimal transmit flush predicate for ABI legality tests.
 * @return Zero because this callback owns no deferred work.
 */
uint8_t abi_test_maybe_flush(void *) noexcept
{
	return 0;
}

/**
 * @brief Minimal transition callback for ABI legality tests.
 * @return Zero without transferring records.
 */
uint16_t abi_test_transfer(void *, kinetum_packet_record *const *, kinetum_packet_record **, uint16_t) noexcept
{
	return 0;
}

/**
 * @brief Build one complete exact process-facility operation record.
 *
 * @param state Non-null stable test state.
 * @return Complete zero-padded facility operations.
 */
kinetum_provider_process_facility_operations abi_test_facility_operations(void *state) noexcept
{
	return kinetum_provider_process_facility_operations{
		.state = state,
		.register_worker_thread = abi_test_register_worker,
		.unregister_worker_thread = abi_test_unregister_worker,
		.bind_runtime_service_coordinator = abi_test_bind_coordinator,
		.launch_runtime_service = abi_test_launch_service,
		.join_runtime_service = abi_test_join_service,
		.generation = 1,
		.facility_index = 0,
		.padding = {0},
	};
}

/**
 * @brief Build one complete exact packet-storage operation record.
 *
 * @param state Non-null stable test state.
 * @return Complete zero-padded storage operations.
 */
kinetum_packet_storage_domain_operations abi_test_storage_operations(void *state) noexcept
{
	return kinetum_packet_storage_domain_operations{
		.state = state,
		.acquire_burst = abi_test_acquire,
		.clone_writable = abi_test_clone,
		.copy_origins_burst = abi_test_copy_origins,
		.release_burst = abi_test_release,
		.observe_statistics = abi_test_observe_storage,
		.generation = 1,
		.domain_index = 0,
		.maximum_packet_length = 1500,
		.capabilities = KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ |
				KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE | KINETUM_PACKET_STORAGE_WRITABLE_CLONE,
		.padding = {0},
	};
}

/**
 * @brief Build one exact nonempty borrowed text view.
 *
 * @param text Static NUL-terminated text.
 * @param size Exact byte count excluding NUL.
 * @return Valid zero-padded ABI view.
 */
kinetum_provider_text_view abi_test_text(const char *text, uint32_t size) noexcept
{
	return kinetum_provider_text_view{.data = text, .size = size, .padding = 0};
}

}  // namespace

/** @brief Pin the one product version and generated exact provider ABI identity. */
TEST(provider_component_abi, generated_product_and_identity_are_exact)
{
	EXPECT_EQ(PROVIDER_PRODUCT_VERSION_MAJOR, 0u);
	EXPECT_EQ(PROVIDER_PRODUCT_VERSION_MINOR, 1u);
	EXPECT_EQ(PROVIDER_PRODUCT_VERSION_PATCH, 0u);
	EXPECT_EQ(PROVIDER_ABI_IDENTITY.size(), 32u);
	EXPECT_EQ(PROVIDER_ABI_IDENTITY_HEX.size(), 64u);
	EXPECT_TRUE(std::all_of(PROVIDER_ABI_IDENTITY_HEX.begin(), PROVIDER_ABI_IDENTITY_HEX.end(), [](char value) {
		return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
	}));
	EXPECT_TRUE(std::any_of(PROVIDER_ABI_IDENTITY.begin(), PROVIDER_ABI_IDENTITY.end(),
				[](uint8_t value) { return value != 0; }));
}

/** @brief Prove the C ABI remains the sole exact packet-record layout authority. */
TEST(provider_component_abi, packet_record_physical_authority_preserves_exact_layout)
{
	EXPECT_TRUE((std::is_same_v<dp::packet_private, ::kinetum_packet_private>));
	EXPECT_TRUE((std::is_same_v<dp::packet_record, ::kinetum_packet_record>));
	EXPECT_EQ(sizeof(kinetum_packet_private), 128u);
	EXPECT_EQ(alignof(kinetum_packet_private), 64u);
	EXPECT_EQ(sizeof(kinetum_packet_record), 192u);
	EXPECT_EQ(alignof(kinetum_packet_record), 64u);
	EXPECT_EQ(offsetof(kinetum_packet_record, metadata), 0u);
	EXPECT_EQ(offsetof(kinetum_packet_record, storage), 128u);
}

/** @brief Prove packet and operation records remain plain exact ABI values. */
TEST(provider_component_abi, packet_and_operation_types_remain_plain_exact_values)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_packet_private>);
	EXPECT_TRUE(std::is_trivially_copyable_v<kinetum_packet_private>);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_packet_record>);
	EXPECT_TRUE(std::is_trivially_copyable_v<kinetum_packet_record>);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_packet_storage_domain_operations>);
	EXPECT_TRUE(std::is_trivially_copyable_v<kinetum_packet_storage_domain_operations>);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, acquire_burst), 8u);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, clone_writable), 16u);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, copy_origins_burst), 24u);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, release_burst), 32u);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, observe_statistics), 40u);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, generation), 48u);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, domain_index), 52u);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, maximum_packet_length), 54u);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, capabilities), 56u);
	EXPECT_EQ(offsetof(kinetum_packet_storage_domain_operations, padding), 60u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_packet_rx_burst_operations>);
	EXPECT_TRUE(std::is_trivially_copyable_v<kinetum_packet_rx_burst_operations>);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_packet_tx_burst_operations>);
	EXPECT_TRUE(std::is_trivially_copyable_v<kinetum_packet_tx_burst_operations>);
	EXPECT_EQ(kinetum_provider_observation_state_is_valid(0u), 0u);
	EXPECT_EQ(kinetum_provider_observation_state_is_valid(KINETUM_PROVIDER_OBSERVATION_AVAILABLE_EXACT), 1u);
	EXPECT_EQ(kinetum_provider_observation_state_is_valid(KINETUM_PROVIDER_OBSERVATION_READ_FAILED), 1u);
	EXPECT_EQ(kinetum_provider_observation_has_values(KINETUM_PROVIDER_OBSERVATION_AVAILABLE_APPROXIMATE), 1u);
	EXPECT_EQ(kinetum_provider_observation_has_values(KINETUM_PROVIDER_OBSERVATION_UNSUPPORTED), 0u);
}

/** @brief Pin every bounded view and diagnostic record layout. */
TEST(provider_component_abi, bounded_views_and_diagnostic_layout_are_exact)
{
	EXPECT_EQ(sizeof(kinetum_provider_byte_view), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_byte_view, data), 0u);
	EXPECT_EQ(offsetof(kinetum_provider_byte_view, size), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_byte_view, padding), 12u);
	EXPECT_EQ(sizeof(kinetum_provider_text_view), 16u);
	EXPECT_EQ(sizeof(kinetum_provider_diagnostic), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_diagnostic, capacity), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_diagnostic, size), 12u);
	EXPECT_EQ(sizeof(kinetum_provider_storage_observation), 64u);
	EXPECT_EQ(alignof(kinetum_provider_storage_observation), 64u);
	EXPECT_EQ(offsetof(kinetum_provider_storage_observation, runtime_generation), 0u);
	EXPECT_EQ(offsetof(kinetum_provider_storage_observation, storage_domain_index), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_storage_observation, state), 12u);
	EXPECT_EQ(offsetof(kinetum_provider_storage_observation, identity_padding), 13u);
	EXPECT_EQ(offsetof(kinetum_provider_storage_observation, in_use), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_storage_observation, available), 24u);
	EXPECT_EQ(offsetof(kinetum_provider_storage_observation, padding), 32u);
	EXPECT_EQ(sizeof(kinetum_packet_rx_burst_result), 4u);
	EXPECT_EQ(alignof(kinetum_packet_rx_burst_result), 2u);
	EXPECT_EQ(offsetof(kinetum_packet_rx_burst_result, transferred_count), 0u);
	EXPECT_EQ(offsetof(kinetum_packet_rx_burst_result, rejected_count), 2u);
	EXPECT_EQ(sizeof(kinetum_provider_port_observation), 128u);
	EXPECT_EQ(alignof(kinetum_provider_port_observation), 64u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, port_index), 0u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, state), 4u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, identity_padding), 5u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, rx_packets), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, tx_packets), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, rx_bytes), 24u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, tx_bytes), 32u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, rx_missed), 40u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, rx_errors), 48u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, tx_errors), 56u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, rx_no_buffer), 64u);
	EXPECT_EQ(offsetof(kinetum_provider_port_observation, padding), 72u);
	EXPECT_EQ(sizeof(kinetum_provider_io_observation_batch), 64u);
	EXPECT_EQ(alignof(kinetum_provider_io_observation_batch), 64u);
	EXPECT_EQ(offsetof(kinetum_provider_io_observation_batch, ports), 0u);
	EXPECT_EQ(offsetof(kinetum_provider_io_observation_batch, port_count), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_io_observation_batch, port_padding), 12u);
	EXPECT_EQ(offsetof(kinetum_provider_io_observation_batch, padding), 16u);
}

/** @brief Pin factory and host-proof request/result layouts. */
TEST(provider_component_abi, factory_and_host_proof_layout_are_exact)
{
	EXPECT_EQ(sizeof(kinetum_provider_cpu_assignment), 16u);
	EXPECT_EQ(sizeof(kinetum_provider_driver_attachment_fact), 48u);
	EXPECT_EQ(sizeof(kinetum_provider_memory_domain_fact), 32u);
	EXPECT_EQ(sizeof(kinetum_provider_process_facility_facts), 64u);
	EXPECT_EQ(sizeof(kinetum_provider_io_port_fact), 32u);
	EXPECT_EQ(sizeof(kinetum_provider_io_stream_fact), 48u);
	EXPECT_EQ(alignof(kinetum_provider_io_stream_fact), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_io_stream_fact, storage_domain_indices), 32u);
	EXPECT_EQ(offsetof(kinetum_provider_io_stream_fact, storage_domain_count), 40u);
	EXPECT_EQ(sizeof(kinetum_provider_steering_fact), 64u);
	EXPECT_EQ(sizeof(kinetum_provider_io_driver_facts), 72u);
	EXPECT_EQ(sizeof(kinetum_provider_packet_storage_facts), 48u);
	EXPECT_EQ(sizeof(kinetum_provider_execution_facts), 40u);
	EXPECT_EQ(sizeof(kinetum_provider_endpoint_fact), 8u);
	EXPECT_EQ(sizeof(kinetum_provider_storage_transition_facts), 48u);
	EXPECT_EQ(sizeof(kinetum_provider_compiled_fact_record), 40u);
	EXPECT_EQ(offsetof(kinetum_provider_compiled_fact_record, process_facility), 0u);
	EXPECT_EQ(offsetof(kinetum_provider_compiled_fact_record, io_driver), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_compiled_fact_record, packet_storage), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_compiled_fact_record, execution), 24u);
	EXPECT_EQ(offsetof(kinetum_provider_compiled_fact_record, storage_transition), 32u);
	EXPECT_EQ(sizeof(kinetum_provider_process_facility_operations), 64u);
	EXPECT_EQ(offsetof(kinetum_provider_process_facility_operations, register_worker_thread), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_process_facility_operations, unregister_worker_thread), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_process_facility_operations, bind_runtime_service_coordinator), 24u);
	EXPECT_EQ(offsetof(kinetum_provider_process_facility_operations, launch_runtime_service), 32u);
	EXPECT_EQ(offsetof(kinetum_provider_process_facility_operations, join_runtime_service), 40u);
	EXPECT_EQ(offsetof(kinetum_provider_process_facility_operations, generation), 48u);
	EXPECT_EQ(offsetof(kinetum_provider_process_facility_operations, facility_index), 56u);
	EXPECT_EQ(sizeof(kinetum_provider_io_driver_operations), 64u);
	EXPECT_EQ(offsetof(kinetum_provider_io_driver_operations, activate_packet_io), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_io_driver_operations, deactivate_packet_io), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_io_driver_operations, rx_queues), 24u);
	EXPECT_EQ(offsetof(kinetum_provider_io_driver_operations, tx_queues), 32u);
	EXPECT_EQ(offsetof(kinetum_provider_io_driver_operations, observe_statistics), 40u);
	EXPECT_EQ(offsetof(kinetum_provider_io_driver_operations, rx_queue_count), 48u);
	EXPECT_EQ(offsetof(kinetum_provider_io_driver_operations, tx_queue_count), 52u);
	EXPECT_EQ(offsetof(kinetum_provider_io_driver_operations, io_driver_index), 56u);
	EXPECT_EQ(sizeof(kinetum_provider_execution_operations), 64u);
	EXPECT_EQ(sizeof(kinetum_provider_storage_transition_operations), 64u);
	EXPECT_EQ(sizeof(kinetum_provider_dependency_handle), 56u);
	EXPECT_EQ(offsetof(kinetum_provider_dependency_handle, instance_id), 0u);
	EXPECT_EQ(offsetof(kinetum_provider_dependency_handle, type_url), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_dependency_handle, instance), 32u);
	EXPECT_EQ(offsetof(kinetum_provider_dependency_handle, operations), 40u);
	EXPECT_EQ(offsetof(kinetum_provider_dependency_handle, role), 48u);
	EXPECT_EQ(sizeof(kinetum_provider_factory_request), 136u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_request, logging), 120u);
	EXPECT_EQ(sizeof(kinetum_provider_cold_log), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_request, canonical_configuration), 32u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_request, compiled_facts), 48u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_request, dependencies), 88u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_request, dependency_count), 96u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_request, runtime_generation), 104u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_request, role), 112u);
	EXPECT_EQ(sizeof(kinetum_provider_factory_result), 24u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_result, destroy), 16u);
	EXPECT_EQ(sizeof(kinetum_provider_host_proof_request), 80u);
	EXPECT_EQ(offsetof(kinetum_provider_host_proof_request, type_url), 0u);
	EXPECT_EQ(offsetof(kinetum_provider_host_proof_request, canonical_configuration), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_host_proof_request, compiled_facts), 32u);
	EXPECT_EQ(offsetof(kinetum_provider_host_proof_request, role), 72u);
	EXPECT_EQ(offsetof(kinetum_provider_host_proof_request, padding), 73u);
}

/** @brief Pin the component descriptor's one compact exact physical shape. */
TEST(provider_component_abi, descriptor_has_one_compact_exact_shape)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_provider_component_descriptor>);
	EXPECT_TRUE(std::is_trivially_copyable_v<kinetum_provider_component_descriptor>);
	EXPECT_EQ(sizeof(kinetum_provider_factory_record), 40u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_record, process_facility), 0u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_record, io_driver), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_record, packet_storage), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_record, execution), 24u);
	EXPECT_EQ(offsetof(kinetum_provider_factory_record, storage_transition), 32u);
	EXPECT_EQ(sizeof(kinetum_provider_contract_implementation), 72u);
	EXPECT_EQ(offsetof(kinetum_provider_contract_implementation, factories), 16u);
	EXPECT_EQ(offsetof(kinetum_provider_contract_implementation, host_proof), 56u);
	EXPECT_EQ(offsetof(kinetum_provider_contract_implementation, role), 64u);
	EXPECT_EQ(sizeof(kinetum_provider_component_descriptor), 72u);
	EXPECT_EQ(offsetof(kinetum_provider_component_descriptor, abi_identity), 8u);
	EXPECT_EQ(offsetof(kinetum_provider_component_descriptor, component_id), 40u);
	EXPECT_EQ(offsetof(kinetum_provider_component_descriptor, contracts), 56u);
	EXPECT_EQ(offsetof(kinetum_provider_component_descriptor, contract_count), 64u);
}

/** @brief Pin the closed fixed values of provider statuses and roles. */
TEST(provider_component_abi, statuses_and_roles_have_closed_fixed_values)
{
	EXPECT_EQ(sizeof(kinetum_provider_status), 4u);
	EXPECT_EQ(sizeof(kinetum_provider_role), 1u);
	EXPECT_EQ(KINETUM_PROVIDER_STATUS_OK, 0);
	EXPECT_EQ(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, 4);
	EXPECT_EQ(KINETUM_PROVIDER_ROLE_PROCESS_FACILITY, 1u);
	EXPECT_EQ(KINETUM_PROVIDER_ROLE_IO_DRIVER, 2u);
	EXPECT_EQ(KINETUM_PROVIDER_ROLE_PACKET_STORAGE, 3u);
	EXPECT_EQ(KINETUM_PROVIDER_ROLE_EXECUTION, 4u);
	EXPECT_EQ(KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION, 5u);
}

/** @brief Receive transfer and rejection counts share one widened input bound. */
TEST(provider_component_abi, receive_result_bounds_include_rejected_only_input)
{
	EXPECT_EQ(kinetum_packet_rx_burst_result_is_valid({0u, 0u}, 0u), 1u);
	EXPECT_EQ(kinetum_packet_rx_burst_result_is_valid({0u, 3u}, 3u), 1u);
	EXPECT_EQ(kinetum_packet_rx_burst_result_is_valid({2u, 1u}, 3u), 1u);
	EXPECT_EQ(kinetum_packet_rx_burst_result_is_valid({3u, 1u}, 3u), 0u);
	EXPECT_EQ(kinetum_packet_rx_burst_result_is_valid({0u, 1u}, 0u), 0u);
	EXPECT_EQ(kinetum_packet_rx_burst_result_is_valid({UINT16_MAX, 0u}, UINT16_MAX), 1u);
	EXPECT_EQ(kinetum_packet_rx_burst_result_is_valid({0u, UINT16_MAX}, UINT16_MAX), 1u);
	EXPECT_EQ(kinetum_packet_rx_burst_result_is_valid({UINT16_MAX, UINT16_MAX}, UINT16_MAX), 0u);
}

/** @brief Prove packet operation tables remain structurally role-partitioned. */
TEST(provider_component_abi, packet_operations_are_structurally_role_partitioned)
{
	using acquire_fn = uint16_t (*)(void *, kinetum_packet_record **, uint16_t) noexcept;
	using receive_fn = kinetum_packet_rx_burst_result (*)(void *, kinetum_packet_record **, uint16_t) noexcept;
	using transmit_fn = uint16_t (*)(void *, kinetum_packet_record *const *, uint16_t) noexcept;
	using release_fn = void (*)(void *, kinetum_packet_record *const *, uint16_t) noexcept;
	using clone_fn = kinetum_packet_record *(*)(void *, const kinetum_packet_record *) noexcept;
	using observe_storage_fn = kinetum_provider_status (*)(void *, kinetum_provider_storage_observation *,
							       kinetum_provider_diagnostic *) noexcept;
	using observe_io_fn = kinetum_provider_status (*)(void *, kinetum_provider_io_observation_batch *,
							  kinetum_provider_diagnostic *) noexcept;
	using flush_predicate_fn = uint8_t (*)(void *) noexcept;
	using transition_fn =
		uint16_t (*)(void *, kinetum_packet_record *const *, kinetum_packet_record **, uint16_t) noexcept;

	EXPECT_TRUE((std::is_same_v<decltype(kinetum_packet_rx_burst_operations::receive_burst), receive_fn>));
	EXPECT_TRUE((std::is_same_v<decltype(kinetum_packet_tx_burst_operations::transmit_burst), transmit_fn>));
	EXPECT_TRUE((std::is_same_v<decltype(kinetum_packet_tx_burst_operations::maybe_flush), flush_predicate_fn>));
	EXPECT_TRUE((std::is_same_v<decltype(kinetum_packet_storage_domain_operations::acquire_burst), acquire_fn>));
	EXPECT_TRUE((std::is_same_v<decltype(kinetum_packet_storage_domain_operations::release_burst), release_fn>));
	EXPECT_TRUE((std::is_same_v<decltype(kinetum_packet_storage_domain_operations::clone_writable), clone_fn>));
	EXPECT_TRUE((std::is_same_v<decltype(kinetum_packet_storage_domain_operations::observe_statistics),
				    observe_storage_fn>));
	EXPECT_TRUE(
		(std::is_same_v<decltype(kinetum_provider_io_driver_operations::observe_statistics), observe_io_fn>));
	EXPECT_TRUE((std::is_same_v<decltype(kinetum_provider_storage_transition_operations::transfer_burst),
				    transition_fn>));
}

/** @brief Prove each compiled fact selects exactly one role-specific factory. */
TEST(provider_component_abi, compiled_facts_and_factories_enforce_exact_role_partition)
{
	const kinetum_provider_process_facility_facts facility_facts{};
	const kinetum_provider_io_driver_facts driver_facts{};
	kinetum_provider_compiled_fact_record facts{};
	facts.process_facility = &facility_facts;
	EXPECT_EQ(kinetum_provider_compiled_facts_match_role(&facts, KINETUM_PROVIDER_ROLE_PROCESS_FACILITY), 1u);
	EXPECT_EQ(kinetum_provider_compiled_facts_match_role(&facts, KINETUM_PROVIDER_ROLE_IO_DRIVER), 0u);
	facts.io_driver = &driver_facts;
	EXPECT_EQ(kinetum_provider_compiled_facts_match_role(&facts, KINETUM_PROVIDER_ROLE_PROCESS_FACILITY), 0u);

	kinetum_provider_factory_record factories{};
	factories.execution = abi_test_factory;
	EXPECT_EQ(kinetum_provider_factories_match_role(&factories, KINETUM_PROVIDER_ROLE_EXECUTION), 1u);
	EXPECT_EQ(kinetum_provider_factories_match_role(&factories, KINETUM_PROVIDER_ROLE_PACKET_STORAGE), 0u);
	factories.packet_storage = abi_test_factory;
	EXPECT_EQ(kinetum_provider_factories_match_role(&factories, KINETUM_PROVIDER_ROLE_EXECUTION), 0u);
	EXPECT_EQ(kinetum_provider_factories_match_role(&factories, 0), 0u);
}

/** @brief Reject malformed nested fact trees before any provider factory runs. */
TEST(provider_component_abi, compiled_fact_trees_enforce_closed_c_shape_before_factory)
{
	kinetum_provider_cpu_assignment assignment{
		.owner_index = 0,
		.cpu_core_id = 2,
		.numa_node = 0,
		.kind = KINETUM_PROVIDER_CPU_OWNER_PACKET_WORKER,
		.padding = {0},
	};
	kinetum_provider_process_facility_facts facility{
		.facility_index = 0,
		.main_core_id = 1,
		.cpu_assignments = &assignment,
		.cpu_assignment_count = 1,
		.cpu_assignment_padding = 0,
		.attachments = nullptr,
		.attachment_count = 0,
		.attachment_padding = 0,
		.memory_domains = nullptr,
		.memory_domain_count = 0,
		.padding = {0},
	};
	EXPECT_EQ(kinetum_provider_process_facility_facts_are_valid(&facility), 1u);
	assignment.kind = 0;
	EXPECT_EQ(kinetum_provider_process_facility_facts_are_valid(&facility), 0u);
	assignment.kind = KINETUM_PROVIDER_CPU_OWNER_PACKET_WORKER;
	facility.cpu_assignment_padding = 1;
	EXPECT_EQ(kinetum_provider_process_facility_facts_are_valid(&facility), 0u);
	facility.cpu_assignment_padding = 0;
	kinetum_provider_memory_domain_fact memory_domain{
		.storage_domain_index = 0,
		.buffer_count = 64,
		.data_room_bytes = 2048,
		.headroom_bytes = 128,
		.alignment_bytes = 64,
		.cache_size_per_worker = 0,
		.host_numa_node = 0,
		.has_host_numa_node = 0,
		.padding = {0},
	};
	facility.memory_domains = &memory_domain;
	facility.memory_domain_count = 1;
	EXPECT_EQ(kinetum_provider_process_facility_facts_are_valid(&facility), 1u);
	memory_domain.has_host_numa_node = 2;
	EXPECT_EQ(kinetum_provider_process_facility_facts_are_valid(&facility), 0u);
	memory_domain.has_host_numa_node = 0;
	memory_domain.host_numa_node = 1;
	EXPECT_EQ(kinetum_provider_process_facility_facts_are_valid(&facility), 0u);
	memory_domain.has_host_numa_node = 1;
	EXPECT_EQ(kinetum_provider_process_facility_facts_are_valid(&facility), 1u);
	memory_domain.host_numa_node = -1;
	EXPECT_EQ(kinetum_provider_process_facility_facts_are_valid(&facility), 0u);
	memory_domain.host_numa_node = 0;

	static constexpr char DRIVER_PORT_ID[] = "port_0";
	static constexpr char ENDPOINT[] = "127.0.0.1";
	kinetum_provider_driver_attachment_fact attachment{
		.driver_port_id = abi_test_text(DRIVER_PORT_ID, static_cast<uint32_t>(sizeof(DRIVER_PORT_ID) - 1u)),
		.attachment_identity = abi_test_text(ENDPOINT, static_cast<uint32_t>(sizeof(ENDPOINT) - 1u)),
		.io_driver_index = 0,
		.endpoint_port = 9000,
		.kind = KINETUM_PROVIDER_ATTACHMENT_UDP_IPV4,
		.padding = {0},
	};
	kinetum_provider_io_port_fact port{
		.port_index = 0,
		.driver_port_index = 0,
		.logical_port_id = 1,
		.mtu = 1500,
		.host_numa_node = 0,
		.direction = KINETUM_PROVIDER_IO_DIRECTION_RX,
		.has_host_numa_node = 0,
		.has_resolved_mac_address = 0,
		.direction_padding = 0,
		.resolved_mac_address = {0},
		.padding = {0},
	};
	std::array<uint32_t, 2> storage_domains{0, 1};
	kinetum_provider_io_stream_fact stream{
		.io_stream_index = 0,
		.port_index = 0,
		.stage_instance_index = 0,
		.worker_index = 0,
		.driver_queue_id = 0,
		.descriptor_count = 128,
		.steering_profile_index = 0,
		.direction = KINETUM_PROVIDER_IO_DIRECTION_RX,
		.has_steering_profile = 0,
		.padding = {0},
		.storage_domain_indices = storage_domains.data(),
		.storage_domain_count = 1,
		.storage_padding = 0,
	};
	kinetum_provider_io_driver_facts driver{
		.io_driver_index = 0,
		.index_padding = 0,
		.attachments = &attachment,
		.attachment_count = 1,
		.attachment_padding = 0,
		.ports = &port,
		.port_count = 1,
		.port_padding = 0,
		.streams = &stream,
		.stream_count = 1,
		.stream_padding = 0,
		.steering_profiles = nullptr,
		.steering_profile_count = 0,
		.steering_padding = 0,
	};
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 1u);
	stream.storage_domain_count = 2;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	stream.direction = KINETUM_PROVIDER_IO_DIRECTION_TX;
	port.direction = KINETUM_PROVIDER_IO_DIRECTION_TX;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 1u);
	EXPECT_EQ(kinetum_provider_io_stream_uses_storage(&stream, 0u), 1u);
	EXPECT_EQ(kinetum_provider_io_stream_uses_storage(&stream, 1u), 1u);
	EXPECT_EQ(kinetum_provider_io_stream_uses_storage(&stream, 2u), 0u);
	storage_domains[1] = 0;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	storage_domains[1] = KINETUM_INVALID_STORAGE_DOMAIN;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	storage_domains = {1, 0};
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	storage_domains = {0, 1};
	stream.storage_domain_count = 0;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	stream.storage_domain_count = 1;
	stream.storage_domain_indices = nullptr;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	stream.storage_domain_indices = storage_domains.data();
	stream.storage_padding = 1;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	stream.storage_padding = 0;
	stream.direction = KINETUM_PROVIDER_IO_DIRECTION_RX;
	port.direction = KINETUM_PROVIDER_IO_DIRECTION_RX;
	driver.port_count = 0;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	driver.port_count = 1;
	stream.direction = KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	stream.direction = KINETUM_PROVIDER_IO_DIRECTION_RX;
	port.has_resolved_mac_address = 2;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	port.has_resolved_mac_address = 0;
	port.has_host_numa_node = 2;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	port.has_host_numa_node = 0;
	port.host_numa_node = 1;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	port.has_host_numa_node = 1;
	port.host_numa_node = -1;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	port.has_host_numa_node = 0;
	port.host_numa_node = 0;
	port.resolved_mac_address[0] = 1;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	port.resolved_mac_address[0] = 0;
	stream.has_steering_profile = 2;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	stream.has_steering_profile = 0;
	stream.steering_profile_index = 1;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	stream.steering_profile_index = 0;
	kinetum_provider_io_stream_fact streams[2]{stream, stream};
	streams[0].io_stream_index = 1;
	streams[1].io_stream_index = 0;
	driver.streams = streams;
	driver.stream_count = 2;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 0u);
	streams[0].io_stream_index = 0;
	streams[1].io_stream_index = 1;
	EXPECT_EQ(kinetum_provider_io_driver_facts_are_valid(&driver), 1u);
	driver.streams = &stream;
	driver.stream_count = 1;

	kinetum_provider_packet_storage_facts storage{
		.storage_domain_index = 0,
		.buffer_count = 0,
		.data_room_bytes = 0,
		.headroom_bytes = 0,
		.alignment_bytes = 0,
		.cache_size_per_worker = 0,
		.required_buffer_count = 0,
		.safety_margin = 0,
		.host_numa_node = 0,
		.maximum_packet_length = 0,
		.access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.has_host_numa_node = 0,
		.padding = {0},
	};
	EXPECT_EQ(kinetum_provider_packet_storage_facts_are_valid(&storage), 1u);
	storage.access_agents = 0;
	EXPECT_EQ(kinetum_provider_packet_storage_facts_are_valid(&storage), 0u);
	storage.access_agents = UINT8_C(1) << 7;
	EXPECT_EQ(kinetum_provider_packet_storage_facts_are_valid(&storage), 0u);
	storage.access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU;
	storage.has_host_numa_node = 2;
	EXPECT_EQ(kinetum_provider_packet_storage_facts_are_valid(&storage), 0u);
	storage.has_host_numa_node = 0;
	storage.host_numa_node = 1;
	EXPECT_EQ(kinetum_provider_packet_storage_facts_are_valid(&storage), 0u);
	storage.has_host_numa_node = 1;
	EXPECT_EQ(kinetum_provider_packet_storage_facts_are_valid(&storage), 1u);
	storage.host_numa_node = -1;
	EXPECT_EQ(kinetum_provider_packet_storage_facts_are_valid(&storage), 0u);

	uint32_t stage_index = 0;
	kinetum_provider_execution_facts execution{
		.execution_provider_index = 0,
		.required_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.index_padding = {0},
		.stage_instance_indices = &stage_index,
		.stage_instance_count = 1,
		.stage_padding = 0,
		.worker_indices = nullptr,
		.worker_count = 0,
		.worker_padding = 0,
	};
	EXPECT_EQ(kinetum_provider_execution_facts_are_valid(&execution), 1u);
	execution.required_access_agents = 0;
	EXPECT_EQ(kinetum_provider_execution_facts_are_valid(&execution), 0u);
	execution.required_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU;
	execution.stage_instance_count = 0;
	EXPECT_EQ(kinetum_provider_execution_facts_are_valid(&execution), 0u);

	kinetum_provider_storage_transition_facts transition{
		.transition_index = 0,
		.from_endpoint = {.kind = KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE, .padding = {0}, .endpoint_index = 0},
		.to_endpoint = {.kind = KINETUM_PROVIDER_ENDPOINT_IO_STREAM, .padding = {0}, .endpoint_index = 0},
		.from_storage_domain_index = 0,
		.to_storage_domain_index = 1,
		.staging_capacity = 64,
		.staging_numa_node = 0,
		.mode = KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY,
		.has_staging_numa_node = 1,
		.padding = {0},
	};
	EXPECT_EQ(kinetum_provider_storage_transition_facts_are_valid(&transition), 1u);
	transition.from_endpoint.padding[0] = 1;
	EXPECT_EQ(kinetum_provider_storage_transition_facts_are_valid(&transition), 0u);
	transition.from_endpoint.padding[0] = 0;
	transition.has_staging_numa_node = 2;
	EXPECT_EQ(kinetum_provider_storage_transition_facts_are_valid(&transition), 0u);
	transition.has_staging_numa_node = 0;
	transition.staging_numa_node = 1;
	EXPECT_EQ(kinetum_provider_storage_transition_facts_are_valid(&transition), 0u);
	transition.has_staging_numa_node = 1;
	transition.staging_numa_node = -1;
	EXPECT_EQ(kinetum_provider_storage_transition_facts_are_valid(&transition), 0u);
}

/** @brief Enforce canonical dependency order and exact role nullability. */
TEST(provider_component_abi, dependencies_are_strictly_ordered_and_role_nullability_is_exact)
{
	static constexpr char FACILITY_ID[] = "facility_0";
	static constexpr char STORAGE_ID[] = "storage_0";
	static constexpr char FACILITY_URL[] = "type.googleapis.com/kinetum.facility.dpdk.v1.DpdkFacilityConfig";
	static constexpr char STORAGE_URL[] = "type.googleapis.com/kinetum.storage.dpdk.v1.DpdkStorageConfig";
	uint32_t facility_instance = 1;
	uint32_t storage_instance = 2;
	auto facility_operations = abi_test_facility_operations(&facility_instance);
	auto storage_operations = abi_test_storage_operations(&storage_instance);
	kinetum_provider_dependency_handle dependencies[]{
		{
			.instance_id = abi_test_text(FACILITY_ID, static_cast<uint32_t>(sizeof(FACILITY_ID) - 1u)),
			.type_url = abi_test_text(FACILITY_URL, static_cast<uint32_t>(sizeof(FACILITY_URL) - 1u)),
			.instance = &facility_instance,
			.operations = &facility_operations,
			.role = KINETUM_PROVIDER_ROLE_PROCESS_FACILITY,
			.padding = {0},
		},
		{
			.instance_id = abi_test_text(STORAGE_ID, static_cast<uint32_t>(sizeof(STORAGE_ID) - 1u)),
			.type_url = abi_test_text(STORAGE_URL, static_cast<uint32_t>(sizeof(STORAGE_URL) - 1u)),
			.instance = &storage_instance,
			.operations = &storage_operations,
			.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
			.padding = {0},
		},
	};
	EXPECT_EQ(kinetum_provider_dependencies_are_valid(nullptr, 0), 1u);
	EXPECT_EQ(kinetum_provider_dependencies_are_valid(dependencies, 2), 1u);
	EXPECT_EQ(kinetum_provider_dependencies_are_valid(nullptr, 1), 0u);

	std::swap(dependencies[0], dependencies[1]);
	EXPECT_EQ(kinetum_provider_dependencies_are_valid(dependencies, 2), 0u);
	std::swap(dependencies[0], dependencies[1]);
	dependencies[0].operations = nullptr;
	EXPECT_EQ(kinetum_provider_dependencies_are_valid(dependencies, 2), 0u);
	dependencies[0].operations = &facility_operations;
	dependencies[1].instance_id = dependencies[0].instance_id;
	dependencies[1].role = dependencies[0].role;
	dependencies[1].operations = &storage_operations;
	EXPECT_EQ(kinetum_provider_dependencies_are_valid(dependencies, 2), 0u);
}

/** @brief Validate complete factory request views, role facts, and zero padding. */
TEST(provider_component_abi, factory_request_validates_views_role_facts_and_padding)
{
	kinetum::test_support::provider_log_capture logging;
	static constexpr char INSTANCE_ID[] = "execution_0";
	static constexpr char TYPE_URL[] = "type.googleapis.com/kinetum.execution.cpu.v1.CpuExecutionConfig";
	const uint32_t stage_index = 0;
	const kinetum_provider_execution_facts execution_facts{
		.execution_provider_index = 0,
		.required_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.index_padding = {0},
		.stage_instance_indices = &stage_index,
		.stage_instance_count = 1,
		.stage_padding = 0,
		.worker_indices = nullptr,
		.worker_count = 0,
		.worker_padding = 0,
	};
	const kinetum_provider_packet_storage_facts storage_facts{};
	kinetum_provider_factory_request request{
		.instance_id = abi_test_text(INSTANCE_ID, static_cast<uint32_t>(sizeof(INSTANCE_ID) - 1u)),
		.type_url = abi_test_text(TYPE_URL, static_cast<uint32_t>(sizeof(TYPE_URL) - 1u)),
		.canonical_configuration = {},
		.compiled_facts =
			{
				.process_facility = nullptr,
				.io_driver = nullptr,
				.packet_storage = nullptr,
				.execution = &execution_facts,
				.storage_transition = nullptr,
			},
		.dependencies = nullptr,
		.dependency_count = 0,
		.dependency_padding = 0,
		.runtime_generation = 1,
		.role = KINETUM_PROVIDER_ROLE_EXECUTION,
		.padding = {0},
		.logging = logging.capability(),
	};
	EXPECT_EQ(kinetum_provider_factory_request_is_valid(&request), 1u);
	request.logging.context = nullptr;
	EXPECT_EQ(kinetum_provider_factory_request_is_valid(&request), 0u);
	request.logging = logging.capability();
	request.logging.write = nullptr;
	EXPECT_EQ(kinetum_provider_factory_request_is_valid(&request), 0u);
	request.logging = logging.capability();
	request.compiled_facts.packet_storage = &storage_facts;
	EXPECT_EQ(kinetum_provider_factory_request_is_valid(&request), 0u);
	request.compiled_facts.packet_storage = nullptr;
	request.canonical_configuration = {.data = nullptr, .size = 1, .padding = 0};
	EXPECT_EQ(kinetum_provider_factory_request_is_valid(&request), 0u);
	request.canonical_configuration = {};
	request.padding[0] = 1;
	EXPECT_EQ(kinetum_provider_factory_request_is_valid(&request), 0u);
}

/** @brief Validate complete host-proof request views, role facts, and padding. */
TEST(provider_component_abi, host_proof_request_validates_exact_role_facts_and_padding)
{
	static constexpr char TYPE_URL[] = "type.googleapis.com/kinetum.execution.cpu.v1.CpuExecutionConfig";
	const uint32_t stage_index = 0;
	const kinetum_provider_execution_facts execution_facts{
		.execution_provider_index = 0,
		.required_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.index_padding = {0},
		.stage_instance_indices = &stage_index,
		.stage_instance_count = 1,
		.stage_padding = 0,
		.worker_indices = nullptr,
		.worker_count = 0,
		.worker_padding = 0,
	};
	const kinetum_provider_packet_storage_facts storage_facts{};
	kinetum_provider_host_proof_request request{
		.type_url = abi_test_text(TYPE_URL, static_cast<uint32_t>(sizeof(TYPE_URL) - 1u)),
		.canonical_configuration = {},
		.compiled_facts =
			{
				.process_facility = nullptr,
				.io_driver = nullptr,
				.packet_storage = nullptr,
				.execution = &execution_facts,
				.storage_transition = nullptr,
			},
		.role = KINETUM_PROVIDER_ROLE_EXECUTION,
		.padding = {0},
	};

	EXPECT_EQ(kinetum_provider_host_proof_request_is_valid(&request), 1u);
	request.compiled_facts.packet_storage = &storage_facts;
	EXPECT_EQ(kinetum_provider_host_proof_request_is_valid(&request), 0u);
	request.compiled_facts.packet_storage = nullptr;
	request.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE;
	EXPECT_EQ(kinetum_provider_host_proof_request_is_valid(&request), 0u);
	request.role = KINETUM_PROVIDER_ROLE_EXECUTION;
	request.padding[0] = 1;
	EXPECT_EQ(kinetum_provider_host_proof_request_is_valid(&request), 0u);
}

/** @brief Enforce status- and role-specific factory-result nullability. */
TEST(provider_component_abi, factory_result_nullability_is_status_and_role_exact)
{
	kinetum_provider_factory_result result{};
	EXPECT_EQ(kinetum_provider_factory_result_matches_status(KINETUM_PROVIDER_ROLE_EXECUTION,
								 KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, &result),
		  1u);
	uint32_t instance = 1;
	auto facility_operations = abi_test_facility_operations(&instance);
	kinetum_provider_execution_operations execution_operations{
		.state = &instance,
		.execution_provider_index = 0,
		.required_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.padding = {0},
	};
	result.instance = &instance;
	result.destroy = abi_test_destroy;
	EXPECT_EQ(kinetum_provider_factory_result_matches_status(KINETUM_PROVIDER_ROLE_PROCESS_FACILITY,
								 KINETUM_PROVIDER_STATUS_OK, &result),
		  0u);
	EXPECT_EQ(kinetum_provider_factory_result_matches_status(KINETUM_PROVIDER_ROLE_EXECUTION,
								 KINETUM_PROVIDER_STATUS_OK, &result),
		  0u);
	result.operations = &facility_operations;
	EXPECT_EQ(kinetum_provider_factory_result_matches_status(KINETUM_PROVIDER_ROLE_PROCESS_FACILITY,
								 KINETUM_PROVIDER_STATUS_OK, &result),
		  1u);
	EXPECT_EQ(kinetum_provider_factory_result_matches_status(KINETUM_PROVIDER_ROLE_EXECUTION,
								 KINETUM_PROVIDER_STATUS_OK, &result),
		  0u);
	result.operations = &execution_operations;
	EXPECT_EQ(kinetum_provider_factory_result_matches_status(KINETUM_PROVIDER_ROLE_EXECUTION,
								 KINETUM_PROVIDER_STATUS_OK, &result),
		  1u);
	EXPECT_EQ(kinetum_provider_factory_result_matches_status(KINETUM_PROVIDER_ROLE_EXECUTION,
								 KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, &result),
		  0u);
	result = {};
	EXPECT_EQ(kinetum_provider_factory_result_matches_status(KINETUM_PROVIDER_ROLE_EXECUTION,
								 static_cast<kinetum_provider_status>(5), &result),
		  0u);
}

/** @brief Pin the process-facility callback table's one exact C shape. */
TEST(provider_component_abi, process_facility_callbacks_have_one_exact_c_shape)
{
	uint32_t state = 1;
	auto operations = abi_test_facility_operations(&state);
	EXPECT_EQ(kinetum_provider_process_facility_operations_are_valid(&operations), 1u);
	EXPECT_EQ(operations.register_worker_thread(&state, 0, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(operations.bind_runtime_service_coordinator(&state, 0, 0, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(operations.launch_runtime_service(&state, 1, 1, nullptr, nullptr, nullptr),
		  KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(operations.join_runtime_service(&state, 1, 1, nullptr), KINETUM_PROVIDER_STATUS_OK);
	operations.padding[0] = 1;
	EXPECT_EQ(kinetum_provider_process_facility_operations_are_valid(&operations), 0u);
}

/** @brief Reject every malformed role operation record before publication. */
TEST(provider_component_abi, every_role_operation_record_is_validated_before_publication)
{
	uint32_t state = 1;
	auto storage = abi_test_storage_operations(&state);
	kinetum_packet_rx_burst_operations rx{
		.state = &state,
		.receive_burst = abi_test_receive,
		.maximum_burst = 64,
		.logical_port = 1,
		.padding = {0},
	};
	kinetum_packet_tx_burst_operations tx{
		.state = &state,
		.transmit_burst = abi_test_transmit,
		.flush = abi_test_flush,
		.maybe_flush = abi_test_maybe_flush,
		.maximum_burst = 64,
		.logical_port = 2,
		.padding = {0},
	};
	kinetum_provider_io_driver_operations driver{
		.state = &state,
		.activate_packet_io = abi_test_io_lifecycle,
		.deactivate_packet_io = abi_test_io_lifecycle,
		.rx_queues = &rx,
		.tx_queues = &tx,
		.observe_statistics = abi_test_observe_io,
		.rx_queue_count = 1,
		.tx_queue_count = 1,
		.io_driver_index = 0,
		.padding = {0},
	};
	kinetum_provider_execution_operations execution{
		.state = &state,
		.execution_provider_index = 0,
		.required_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.padding = {0},
	};
	kinetum_provider_storage_transition_operations transition{
		.state = &state,
		.transfer_burst = abi_test_transfer,
		.generation = 1,
		.transition_index = 0,
		.from_storage_domain_index = 0,
		.to_storage_domain_index = 1,
		.mode = KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY,
		.padding = {0},
	};

	EXPECT_EQ(kinetum_provider_packet_storage_operations_are_valid(&storage), 1u);
	EXPECT_EQ(kinetum_provider_io_driver_operations_are_valid(&driver), 1u);
	EXPECT_EQ(kinetum_provider_execution_operations_are_valid(&execution), 1u);
	EXPECT_EQ(kinetum_provider_storage_transition_operations_are_valid(&transition), 1u);
	EXPECT_EQ(kinetum_provider_operations_match_role(KINETUM_PROVIDER_ROLE_PACKET_STORAGE, &storage), 1u);
	EXPECT_EQ(kinetum_provider_operations_match_role(KINETUM_PROVIDER_ROLE_IO_DRIVER, &storage), 0u);

	rx.maximum_burst = 0;
	EXPECT_EQ(kinetum_provider_io_driver_operations_are_valid(&driver), 0u);
	rx.maximum_burst = 64;
	driver.activate_packet_io = nullptr;
	EXPECT_EQ(kinetum_provider_io_driver_operations_are_valid(&driver), 0u);
	driver.activate_packet_io = abi_test_io_lifecycle;
	driver.deactivate_packet_io = nullptr;
	EXPECT_EQ(kinetum_provider_io_driver_operations_are_valid(&driver), 0u);
	driver.deactivate_packet_io = abi_test_io_lifecycle;
	driver.observe_statistics = nullptr;
	EXPECT_EQ(kinetum_provider_io_driver_operations_are_valid(&driver), 0u);
	driver.observe_statistics = abi_test_observe_io;
	driver.io_driver_index = UINT32_MAX;
	EXPECT_EQ(kinetum_provider_io_driver_operations_are_valid(&driver), 0u);
	driver.io_driver_index = 0u;
	storage.observe_statistics = nullptr;
	EXPECT_EQ(kinetum_provider_packet_storage_operations_are_valid(&storage), 0u);
	storage.observe_statistics = abi_test_observe_storage;
	storage.capabilities |= UINT32_C(1) << 31;
	EXPECT_EQ(kinetum_provider_packet_storage_operations_are_valid(&storage), 0u);
	execution.required_access_agents = 0;
	EXPECT_EQ(kinetum_provider_execution_operations_are_valid(&execution), 0u);
	transition.mode = 0;
	EXPECT_EQ(kinetum_provider_storage_transition_operations_are_valid(&transition), 0u);
}

}  // namespace kinetum::provider
