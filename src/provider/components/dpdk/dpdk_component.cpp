// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dpdk_component.cpp
 * @brief Exact DPDK process-facility, I/O-driver, and storage component.
 * @author Fleming Patel
 *
 * One link-closed component owns the complete native DPDK dependency closure
 * while publishing three orthogonal provider roles. The process-facility
 * factory owns EAL, the storage factory owns one mbuf population, and the I/O
 * factory owns ethdev ports and queues. Their dependency handles preserve that
 * lifetime order without exposing a DPDK type through the component ABI.
 */

#include <cstdint>
#include <iterator>
#include <memory>
#include <string_view>

#include "gen/kinetum/provider/provider_build_identity.h"
#include "src/dp/backends/dpdk/dpdk_host_probe.hpp"
#include "src/dp/backends/dpdk/dpdk_io.hpp"
#include "src/dp/backends/dpdk/dpdk_process_facility.hpp"
#include "src/provider/components/component_support.hpp"
#include "src/provider/provider_component_abi.h"

namespace kinetum::provider::dpdk_component
{
namespace
{

using component_support::factory_request_matches;
using component_support::fail;
using component_support::static_text_view;

/** Stable identity exported by the DPDK component descriptor. */
constexpr char COMPONENT_ID[] = "kinetum.provider.dpdk";
/** Exact contract identity for process-wide EAL ownership. */
constexpr char DPDK_FACILITY_TYPE_URL[] = "type.googleapis.com/kinetum.facility.dpdk.v1.DpdkFacilityConfig";
/** Exact contract identity for ethdev port and queue ownership. */
constexpr char DPDK_DRIVER_TYPE_URL[] = "type.googleapis.com/kinetum.io.dpdk.v1.DpdkDriverConfig";
/** Exact contract identity for mbuf pool ownership. */
constexpr char DPDK_STORAGE_TYPE_URL[] = "type.googleapis.com/kinetum.storage.dpdk.v1.DpdkStorageConfig";

/**
 * @brief Destroy one quiescent exact DPDK process facility.
 * @param instance Sole quiescent instance returned by this component, or nullptr.
 */
void destroy_process_facility(void *instance) noexcept
{
	delete static_cast<dpdk_process_facility *>(instance);
}

/**
 * @brief Destroy one quiescent exact DPDK I/O driver.
 * @param instance Sole quiescent instance returned by this component, or nullptr.
 */
void destroy_io_driver(void *instance) noexcept
{
	delete static_cast<dpdk_io_driver *>(instance);
}

/**
 * @brief Destroy one quiescent exact DPDK packet-storage domain.
 * @param instance Sole quiescent instance returned by this component, or nullptr.
 */
void destroy_packet_storage(void *instance) noexcept
{
	delete static_cast<dpdk_packet_storage *>(instance);
}

/**
 * @brief Adapt the non-materializing DPDK facility host proof to the ABI.
 * @param request Borrowed exact host-proof request.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK only when the native host proof succeeds; failure acquires no EAL generation.
 */
kinetum_provider_status prove_process_facility_host(const kinetum_provider_host_proof_request *request,
						    kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (request == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK host proof received a null request");
	}
	return prove_dpdk_host(*request, default_dpdk_host_probe_api(), diagnostic);
}

/**
 * @brief Construct one exact process-generation DPDK EAL owner.
 * @param request Borrowed compiled facts and dependency handles for this exact factory role.
 * @param result Initially empty output receiving the instance, operations, and destroy callback on success.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK transfers complete instance ownership; failure transfers none.
 */
kinetum_provider_status create_process_facility(const kinetum_provider_factory_request *request,
						kinetum_provider_factory_result *result,
						kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!factory_request_matches(request, result, KINETUM_PROVIDER_ROLE_PROCESS_FACILITY, DPDK_FACILITY_TYPE_URL)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK facility factory received a malformed request");
	}
	std::unique_ptr<dpdk_process_facility> instance;
	const auto status =
		dpdk_process_facility::create(*request, default_dpdk_process_facility_api(), instance, diagnostic);
	if (status != KINETUM_PROVIDER_STATUS_OK) {
		return status;
	}
	result->instance = instance.release();
	result->operations = &static_cast<dpdk_process_facility *>(result->instance)->operations();
	result->destroy = destroy_process_facility;
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Construct one exact DPDK ethdev driver instance.
 * @param request Borrowed compiled facts and dependency handles for this exact factory role.
 * @param result Initially empty output receiving the instance, operations, and destroy callback on success.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK transfers complete instance ownership; failure transfers none.
 */
kinetum_provider_status create_io_driver(const kinetum_provider_factory_request *request,
					 kinetum_provider_factory_result *result,
					 kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!factory_request_matches(request, result, KINETUM_PROVIDER_ROLE_IO_DRIVER, DPDK_DRIVER_TYPE_URL)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK I/O factory received a malformed request");
	}
	std::unique_ptr<dpdk_io_driver> instance;
	const auto status = dpdk_io_driver::create(*request, default_dpdk_ethdev_api(), instance, diagnostic);
	if (status != KINETUM_PROVIDER_STATUS_OK) {
		return status;
	}
	result->instance = instance.release();
	result->operations = &static_cast<dpdk_io_driver *>(result->instance)->operations();
	result->destroy = destroy_io_driver;
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Construct one exact DPDK mbuf-backed storage domain.
 * @param request Borrowed compiled facts and dependency handles for this exact factory role.
 * @param result Initially empty output receiving the instance, operations, and destroy callback on success.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK transfers complete instance ownership; failure transfers none.
 */
kinetum_provider_status create_packet_storage(const kinetum_provider_factory_request *request,
					      kinetum_provider_factory_result *result,
					      kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!factory_request_matches(request, result, KINETUM_PROVIDER_ROLE_PACKET_STORAGE, DPDK_STORAGE_TYPE_URL)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK storage factory received a malformed request");
	}
	std::unique_ptr<dpdk_packet_storage> instance;
	const auto status = dpdk_packet_storage::create(*request, default_dpdk_mempool_api(), instance, diagnostic);
	if (status != KINETUM_PROVIDER_STATUS_OK) {
		return status;
	}
	result->instance = instance.release();
	result->operations = &static_cast<dpdk_packet_storage *>(result->instance)->operations();
	result->destroy = destroy_packet_storage;
	return KINETUM_PROVIDER_STATUS_OK;
}

/** Type-URL-sorted factory and host-proof inventory exported by this component. */
constexpr kinetum_provider_contract_implementation CONTRACTS[]{
	{
		.type_url = static_text_view(DPDK_FACILITY_TYPE_URL),
		.factories =
			{
				.process_facility = create_process_facility,
				.io_driver = nullptr,
				.packet_storage = nullptr,
				.execution = nullptr,
				.storage_transition = nullptr,
			},
		.host_proof = prove_process_facility_host,
		.role = KINETUM_PROVIDER_ROLE_PROCESS_FACILITY,
		.padding = {0},
	},
	{
		.type_url = static_text_view(DPDK_DRIVER_TYPE_URL),
		.factories =
			{
				.process_facility = nullptr,
				.io_driver = create_io_driver,
				.packet_storage = nullptr,
				.execution = nullptr,
				.storage_transition = nullptr,
			},
		.host_proof = nullptr,
		.role = KINETUM_PROVIDER_ROLE_IO_DRIVER,
		.padding = {0},
	},
	{
		.type_url = static_text_view(DPDK_STORAGE_TYPE_URL),
		.factories =
			{
				.process_facility = nullptr,
				.io_driver = nullptr,
				.packet_storage = create_packet_storage,
				.execution = nullptr,
				.storage_transition = nullptr,
			},
		.host_proof = nullptr,
		.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
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

static_assert(std::string_view(DPDK_FACILITY_TYPE_URL) < std::string_view(DPDK_DRIVER_TYPE_URL));
static_assert(std::string_view(DPDK_DRIVER_TYPE_URL) < std::string_view(DPDK_STORAGE_TYPE_URL));

}  // namespace
}  // namespace kinetum::provider::dpdk_component

extern "C" const kinetum_provider_component_descriptor *kinetum_provider_component_query(void) noexcept
{
	return &kinetum::provider::dpdk_component::DESCRIPTOR;
}
