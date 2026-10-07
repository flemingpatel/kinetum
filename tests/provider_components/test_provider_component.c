// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_component.c
 * @brief Plain-C exact provider-component and private-closure canary.
 * @author Fleming Patel
 *
 * This test image deliberately depends on one separately loaded private
 * artifact. It has no loader search path, so successful RTLD_NOW admission
 * proves that held-descriptor preloading and SONAME reuse close the dependency
 * graph. The component exports only kinetum_provider_component_query.
 */

#include "src/provider/provider_component_abi.h"

#include <stdlib.h>
#include <string.h>

#include "gen/kinetum/provider/provider_build_identity.h"
#include "tests/provider_components/test_provider_private.h"

#ifndef KINETUM_TEST_PROVIDER_COMPONENT_ID
/** Default conformance component identity, overridden by image-specific build definitions. */
#define KINETUM_TEST_PROVIDER_COMPONENT_ID "kinetum.test.provider"
#endif

#ifndef KINETUM_TEST_PROVIDER_PRODUCT_VERSION_MINOR
/** Default matching product minor version, overridden by version-refusal fixtures. */
#define KINETUM_TEST_PROVIDER_PRODUCT_VERSION_MINOR KINETUM_PROVIDER_PRODUCT_VERSION_MINOR
#endif

#ifndef KINETUM_TEST_PROVIDER_ROLE
/** Descriptor role selected by the conformance image. */
#define KINETUM_TEST_PROVIDER_ROLE KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION
#endif

#ifndef KINETUM_TEST_PROVIDER_FACTORY_ROLE
/** Factory role independently varied to exercise role-shape refusal. */
#define KINETUM_TEST_PROVIDER_FACTORY_ROLE KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION
#endif

#ifndef KINETUM_TEST_PROVIDER_DESCRIPTOR_TAIL_PADDING
/** Canonical descriptor tail padding, overridden by padding-refusal fixtures. */
#define KINETUM_TEST_PROVIDER_DESCRIPTOR_TAIL_PADDING UINT8_C(0)
#endif

#ifndef KINETUM_TEST_PROVIDER_CONTRACT_TYPE_URL
/** Default contract implemented by the conformance factory. */
#define KINETUM_TEST_PROVIDER_CONTRACT_TYPE_URL "type.googleapis.com/kinetum.transition.core.v1.ZeroCopyShareConfig"
#endif

/** Exact pure-catalog row implemented by the C conformance component. */
static const char TEST_CONTRACT_TYPE_URL[] = KINETUM_TEST_PROVIDER_CONTRACT_TYPE_URL;

#if defined(KINETUM_TEST_PROVIDER_SECOND_CONTRACT_TYPE_URL)
#ifndef KINETUM_TEST_PROVIDER_SECOND_ROLE
#error "A second provider contract requires its exact descriptor role"
#endif
#ifndef KINETUM_TEST_PROVIDER_SECOND_FACTORY_ROLE
/** Second factory role follows its descriptor unless the test overrides it. */
#define KINETUM_TEST_PROVIDER_SECOND_FACTORY_ROLE KINETUM_TEST_PROVIDER_SECOND_ROLE
#endif

/** Second exact pure-catalog row implemented by the multi-contract fixture. */
static const char TEST_SECOND_CONTRACT_TYPE_URL[] = KINETUM_TEST_PROVIDER_SECOND_CONTRACT_TYPE_URL;
#endif

/** Minimal cold instance proving a real private dependency relocation. */
struct test_provider_instance {
	uint32_t private_marker;    ///< Value returned through the private artifact.
	uint32_t operation_marker;  ///< Row-specific conformance identity.
	kinetum_provider_process_facility_operations facility_operations;  ///< Exact facility result when selected.
	kinetum_provider_execution_operations execution_operations;	   ///< Exact execution result when selected.
	kinetum_provider_storage_transition_operations transition_operations;  ///< Exact transition result when selected.
};

/** Primary row marker retained inside the exact returned role record. */
static const uint32_t TEST_PROVIDER_OPERATION_MARKER = UINT32_C(0x4b4f5053);

#if defined(KINETUM_TEST_PROVIDER_SECOND_CONTRACT_TYPE_URL)
/** Distinct marker retained by the second exact returned role record. */
static const uint32_t TEST_PROVIDER_SECOND_OPERATION_MARKER = UINT32_C(0x4b4f5032);
#endif

/**
 * @brief Reject unsupported conformance facility execution without side effects.
 *
 * @param state Non-null conformance instance.
 * @param identity Exact compact worker or service identity.
 * @param cpu_core_id Exact service CPU when supplied.
 * @param diagnostic Optional bounded diagnostic.
 * @return FAILED_PRECONDITION for the deliberately non-native canary.
 */
static kinetum_provider_status test_provider_facility_unavailable(void *state, uint32_t identity, int32_t cpu_core_id,
								  kinetum_provider_diagnostic *diagnostic)
{
	(void)identity;
	(void)cpu_core_id;
	if (diagnostic != NULL) {
		diagnostic->size = 0;
	}
	return state != NULL ? KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION : KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
}

/**
 * @brief Facility worker-register shape adapter for the conformance canary.
 * @param state Candidate canary instance; only non-nullness is inspected.
 * @param worker_index Unused candidate worker identity.
 * @param diagnostic Optional diagnostic record whose occupied size is cleared.
 * @return FAILED_PRECONDITION for a non-null instance, otherwise INVALID_ARGUMENT; no registration occurs.
 */
static kinetum_provider_status test_provider_register_worker(void *state, uint32_t worker_index,
							     kinetum_provider_diagnostic *diagnostic)
{
	return test_provider_facility_unavailable(state, worker_index, 0, diagnostic);
}

/**
 * @brief Facility worker-unregister shape adapter for the conformance canary.
 * @param state Unused canary instance.
 * @param worker_index Unused worker identity.
 */
static void test_provider_unregister_worker(void *state, uint32_t worker_index)
{
	(void)state;
	(void)worker_index;
}

/**
 * @brief Facility coordinator-bind shape adapter for the conformance canary.
 * @param state Candidate canary instance; only non-nullness is inspected.
 * @param service_index Unused coordinator identity.
 * @param cpu_core_id Unused placement identity.
 * @param diagnostic Optional diagnostic record whose occupied size is cleared.
 * @return FAILED_PRECONDITION for a non-null instance, otherwise INVALID_ARGUMENT.
 */
static kinetum_provider_status test_provider_bind_coordinator(void *state, uint32_t service_index, int32_t cpu_core_id,
							      kinetum_provider_diagnostic *diagnostic)
{
	return test_provider_facility_unavailable(state, service_index, cpu_core_id, diagnostic);
}

/**
 * @brief Facility service-launch shape adapter for the conformance canary.
 * @param state Candidate canary instance; only non-nullness is inspected.
 * @param service_index Unused executor identity.
 * @param cpu_core_id Unused placement identity.
 * @param entry Unused callback; this canary never launches it.
 * @param argument Unused callback state.
 * @param diagnostic Optional diagnostic record whose occupied size is cleared.
 * @return FAILED_PRECONDITION for a non-null instance, otherwise INVALID_ARGUMENT.
 */
static kinetum_provider_status test_provider_launch_service(void *state, uint32_t service_index, int32_t cpu_core_id,
							    kinetum_provider_runtime_service_entry_fn entry,
							    void *argument, kinetum_provider_diagnostic *diagnostic)
{
	(void)entry;
	(void)argument;
	return test_provider_facility_unavailable(state, service_index, cpu_core_id, diagnostic);
}

/**
 * @brief Facility service-join shape adapter for the conformance canary.
 * @param state Candidate canary instance; only non-nullness is inspected.
 * @param service_index Unused executor identity.
 * @param cpu_core_id Unused placement identity.
 * @param diagnostic Optional diagnostic record whose occupied size is cleared.
 * @return FAILED_PRECONDITION for a non-null instance, otherwise INVALID_ARGUMENT.
 */
static kinetum_provider_status test_provider_join_service(void *state, uint32_t service_index, int32_t cpu_core_id,
							  kinetum_provider_diagnostic *diagnostic)
{
	return test_provider_facility_unavailable(state, service_index, cpu_core_id, diagnostic);
}

/**
 * @brief Transfer one conformance zero-copy prefix.
 *
 * @param state Non-null conformance instance.
 * @param sources Exact source-owner array.
 * @param destinations Caller-owned destination array.
 * @param count Exact bounded source count.
 * @return Exact transferred prefix, or zero for malformed input.
 */
static uint16_t test_provider_transfer_burst(void *state, kinetum_packet_record *const *sources,
					     kinetum_packet_record **destinations, uint16_t count)
{
	if (state == NULL || (count != 0 && (sources == NULL || destinations == NULL))) {
		return 0;
	}
	for (uint16_t i = 0; i < count; ++i) {
		if (sources[i] == NULL) {
			return i;
		}
		destinations[i] = sources[i];
	}
	return count;
}

/**
 * @brief Compare one foreign ABI text view with exact static text.
 *
 * @param view Candidate foreign text.
 * @param expected Exact static text.
 * @param expected_size Exact text width.
 * @return Nonzero only for byte-exact equality.
 */
static int test_provider_text_equals(kinetum_provider_text_view view, const char *expected, uint32_t expected_size)
{
	return view.data != NULL && view.size == expected_size && memcmp(view.data, expected, expected_size) == 0;
}

#if defined(KINETUM_TEST_PROVIDER_FAILING_HOST_PROOF)
/**
 * @brief Return one deterministic post-load host-proof failure.
 *
 * @param request Exact role-owned proof request.
 * @param diagnostic Optional caller-owned bounded diagnostic.
 * @return FAILED_PRECONDITION after exact request validation.
 */
static kinetum_provider_status test_provider_host_proof(const kinetum_provider_host_proof_request *request,
							kinetum_provider_diagnostic *diagnostic)
{
	static const char FAILURE_DIAGNOSTIC[] = "injected component host-proof failure";
	if (diagnostic != NULL) {
		diagnostic->size = 0;
	}
	if (!kinetum_provider_host_proof_request_is_valid(request) || request->role != KINETUM_TEST_PROVIDER_ROLE ||
	    !test_provider_text_equals(request->type_url, TEST_CONTRACT_TYPE_URL,
				       (uint32_t)(sizeof(TEST_CONTRACT_TYPE_URL) - 1u))) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	if (diagnostic != NULL && diagnostic->data != NULL &&
	    diagnostic->capacity >= (uint32_t)(sizeof(FAILURE_DIAGNOSTIC) - 1u)) {
		memcpy(diagnostic->data, FAILURE_DIAGNOSTIC, sizeof(FAILURE_DIAGNOSTIC) - 1u);
		diagnostic->size = (uint32_t)(sizeof(FAILURE_DIAGNOSTIC) - 1u);
	}
	return KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION;
}
#endif

/**
 * @brief Return whether one request names an exact contract and role.
 *
 * @param request Candidate factory request.
 * @param expected_role Exact row role.
 * @param expected_type_url Exact static contract identity.
 * @param expected_type_url_size Exact identity width.
 * @return Nonzero only for exact row agreement.
 */
static int test_provider_request_is_exact(const kinetum_provider_factory_request *request,
					  kinetum_provider_role expected_role, const char *expected_type_url,
					  uint32_t expected_type_url_size)
{
	if (request == NULL || request->role != expected_role || request->runtime_generation == 0 ||
	    request->runtime_generation > UINT32_MAX || !kinetum_provider_factory_request_is_valid(request) ||
	    !test_provider_text_equals(request->type_url, expected_type_url, expected_type_url_size)) {
		return 0;
	}
	return 1;
}

/**
 * @brief Retire one exact conformance instance.
 *
 * @param instance Instance returned by test_provider_factory().
 */
static void test_provider_destroy(void *instance)
{
	free(instance);
}

/**
 * @brief Construct one minimal exact conformance result.
 *
 * @param result Non-null caller-owned result.
 * @param diagnostic Optional bounded diagnostic.
 * @param request Exact role-specific compiled facts.
 * @param operation_marker Exact row-specific conformance marker.
 * @return Exact provider status.
 */
static kinetum_provider_status test_provider_materialize(kinetum_provider_factory_result *result,
							 kinetum_provider_diagnostic *diagnostic,
							 const kinetum_provider_factory_request *request,
							 uint32_t operation_marker)
{
	if (diagnostic != NULL) {
		diagnostic->size = 0;
	}
	struct test_provider_instance *instance =
		(struct test_provider_instance *)malloc(sizeof(struct test_provider_instance));
	if (instance == NULL) {
		return KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED;
	}
	instance->private_marker = kinetum_test_provider_private_marker();
	instance->operation_marker = operation_marker;
	result->instance = instance;
	if (request->role == KINETUM_PROVIDER_ROLE_PROCESS_FACILITY) {
		instance->facility_operations.state = instance;
		instance->facility_operations.register_worker_thread = test_provider_register_worker;
		instance->facility_operations.unregister_worker_thread = test_provider_unregister_worker;
		instance->facility_operations.bind_runtime_service_coordinator = test_provider_bind_coordinator;
		instance->facility_operations.launch_runtime_service = test_provider_launch_service;
		instance->facility_operations.join_runtime_service = test_provider_join_service;
		instance->facility_operations.generation = request->runtime_generation;
		instance->facility_operations.facility_index = request->compiled_facts.process_facility->facility_index;
		memset(instance->facility_operations.padding, 0, sizeof(instance->facility_operations.padding));
		result->operations = &instance->facility_operations;
	} else if (request->role == KINETUM_PROVIDER_ROLE_EXECUTION) {
		instance->execution_operations.state = instance;
		instance->execution_operations.execution_provider_index =
			request->compiled_facts.execution->execution_provider_index;
		instance->execution_operations.required_access_agents =
			request->compiled_facts.execution->required_access_agents;
		memset(instance->execution_operations.padding, 0, sizeof(instance->execution_operations.padding));
		result->operations = &instance->execution_operations;
	} else if (request->role == KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION) {
		instance->transition_operations.state = instance;
		instance->transition_operations.transfer_burst = test_provider_transfer_burst;
		instance->transition_operations.generation = (uint32_t)request->runtime_generation;
		instance->transition_operations.transition_index =
			request->compiled_facts.storage_transition->transition_index;
		instance->transition_operations.from_storage_domain_index =
			request->compiled_facts.storage_transition->from_storage_domain_index;
		instance->transition_operations.to_storage_domain_index =
			request->compiled_facts.storage_transition->to_storage_domain_index;
		instance->transition_operations.mode = request->compiled_facts.storage_transition->mode;
		memset(instance->transition_operations.padding, 0, sizeof(instance->transition_operations.padding));
		result->operations = &instance->transition_operations;
	} else {
		free(instance);
		result->instance = NULL;
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	result->destroy = test_provider_destroy;
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Materialize one primary-row conformance instance.
 *
 * @param request Exact role request.
 * @param result Non-null caller-owned result.
 * @param diagnostic Optional bounded diagnostic.
 * @return Exact provider status.
 */
static kinetum_provider_status test_provider_factory(const kinetum_provider_factory_request *request,
						     kinetum_provider_factory_result *result,
						     kinetum_provider_diagnostic *diagnostic)
{
	if (result == NULL ||
	    !test_provider_request_is_exact(request, KINETUM_TEST_PROVIDER_FACTORY_ROLE, TEST_CONTRACT_TYPE_URL,
					    (uint32_t)(sizeof(TEST_CONTRACT_TYPE_URL) - 1u))) {
		if (diagnostic != NULL) {
			diagnostic->size = 0;
		}
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	return test_provider_materialize(result, diagnostic, request, TEST_PROVIDER_OPERATION_MARKER);
}

#if defined(KINETUM_TEST_PROVIDER_SECOND_CONTRACT_TYPE_URL)
/**
 * @brief Materialize one second-row conformance instance.
 *
 * @param request Exact role request.
 * @param result Non-null caller-owned result.
 * @param diagnostic Optional bounded diagnostic.
 * @return Exact provider status.
 */
static kinetum_provider_status test_provider_second_factory(const kinetum_provider_factory_request *request,
							    kinetum_provider_factory_result *result,
							    kinetum_provider_diagnostic *diagnostic)
{
	if (result == NULL || !test_provider_request_is_exact(request, KINETUM_TEST_PROVIDER_SECOND_FACTORY_ROLE,
							      TEST_SECOND_CONTRACT_TYPE_URL,
							      (uint32_t)(sizeof(TEST_SECOND_CONTRACT_TYPE_URL) - 1u))) {
		if (diagnostic != NULL) {
			diagnostic->size = 0;
		}
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	return test_provider_materialize(result, diagnostic, request, TEST_PROVIDER_SECOND_OPERATION_MARKER);
}
#endif

/** Role-partitioned conformance factory rows exported by the selected image. */
static const kinetum_provider_contract_implementation TEST_PROVIDER_CONTRACTS[] = {
	{
		.type_url =
			{
				.data = TEST_CONTRACT_TYPE_URL,
				.size = (uint32_t)(sizeof(TEST_CONTRACT_TYPE_URL) - 1u),
				.padding = 0,
			},
		.factories =
			{
				.process_facility = KINETUM_TEST_PROVIDER_FACTORY_ROLE ==
								    KINETUM_PROVIDER_ROLE_PROCESS_FACILITY ?
							    test_provider_factory :
							    NULL,
				.io_driver = KINETUM_TEST_PROVIDER_FACTORY_ROLE == KINETUM_PROVIDER_ROLE_IO_DRIVER ?
						     test_provider_factory :
						     NULL,
				.packet_storage = KINETUM_TEST_PROVIDER_FACTORY_ROLE ==
								  KINETUM_PROVIDER_ROLE_PACKET_STORAGE ?
							  test_provider_factory :
							  NULL,
				.execution = KINETUM_TEST_PROVIDER_FACTORY_ROLE == KINETUM_PROVIDER_ROLE_EXECUTION ?
						     test_provider_factory :
						     NULL,
				.storage_transition = KINETUM_TEST_PROVIDER_FACTORY_ROLE ==
								      KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION ?
							      test_provider_factory :
							      NULL,
			},
#if defined(KINETUM_TEST_PROVIDER_FAILING_HOST_PROOF)
		.host_proof = test_provider_host_proof,
#else
		.host_proof = NULL,
#endif
		.role = KINETUM_TEST_PROVIDER_ROLE,
		.padding = {0},
	},
#if defined(KINETUM_TEST_PROVIDER_SECOND_CONTRACT_TYPE_URL)
	{
		.type_url =
			{
				.data = TEST_SECOND_CONTRACT_TYPE_URL,
				.size = (uint32_t)(sizeof(TEST_SECOND_CONTRACT_TYPE_URL) - 1u),
				.padding = 0,
			},
		.factories =
			{
				.process_facility = KINETUM_TEST_PROVIDER_SECOND_FACTORY_ROLE ==
								    KINETUM_PROVIDER_ROLE_PROCESS_FACILITY ?
							    test_provider_second_factory :
							    NULL,
				.io_driver = KINETUM_TEST_PROVIDER_SECOND_FACTORY_ROLE ==
							     KINETUM_PROVIDER_ROLE_IO_DRIVER ?
						     test_provider_second_factory :
						     NULL,
				.packet_storage = KINETUM_TEST_PROVIDER_SECOND_FACTORY_ROLE ==
								  KINETUM_PROVIDER_ROLE_PACKET_STORAGE ?
							  test_provider_second_factory :
							  NULL,
				.execution = KINETUM_TEST_PROVIDER_SECOND_FACTORY_ROLE ==
							     KINETUM_PROVIDER_ROLE_EXECUTION ?
						     test_provider_second_factory :
						     NULL,
				.storage_transition = KINETUM_TEST_PROVIDER_SECOND_FACTORY_ROLE ==
								      KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION ?
							      test_provider_second_factory :
							      NULL,
			},
		.host_proof = NULL,
		.role = KINETUM_TEST_PROVIDER_SECOND_ROLE,
		.padding = {0},
	},
#endif
};

#if defined(KINETUM_TEST_PROVIDER_CORRUPT_ABI)
/** Deliberately corrupted physical ABI identity for the refusal image. */
#define KINETUM_TEST_PROVIDER_ABI_INITIALIZER \
	{(uint8_t)(KINETUM_PROVIDER_ABI_IDENTITY_BYTE_0 ^ UINT8_C(1)), KINETUM_PROVIDER_ABI_IDENTITY_TAIL_INITIALIZER}
#else
/** Exact generated physical ABI identity for compatible conformance images. */
#define KINETUM_TEST_PROVIDER_ABI_INITIALIZER KINETUM_PROVIDER_ABI_IDENTITY_INITIALIZER
#endif

/** Immutable conformance descriptor including any deliberately altered admission fact. */
static const kinetum_provider_component_descriptor TEST_PROVIDER_DESCRIPTOR = {
	.product_version_major = KINETUM_PROVIDER_PRODUCT_VERSION_MAJOR,
	.product_version_minor = KINETUM_TEST_PROVIDER_PRODUCT_VERSION_MINOR,
	.product_version_patch = KINETUM_PROVIDER_PRODUCT_VERSION_PATCH,
	.version_padding = {0},
	.abi_identity = KINETUM_TEST_PROVIDER_ABI_INITIALIZER,
	.component_id =
		{
			.data = KINETUM_TEST_PROVIDER_COMPONENT_ID,
			.size = (uint32_t)(sizeof(KINETUM_TEST_PROVIDER_COMPONENT_ID) - 1u),
			.padding = 0,
		},
	.contracts = TEST_PROVIDER_CONTRACTS,
	.contract_count = (uint32_t)(sizeof(TEST_PROVIDER_CONTRACTS) / sizeof(TEST_PROVIDER_CONTRACTS[0])),
	.tail_padding = {KINETUM_TEST_PROVIDER_DESCRIPTOR_TAIL_PADDING},
};

const kinetum_provider_component_descriptor *kinetum_provider_component_query(void)
{
	return &TEST_PROVIDER_DESCRIPTOR;
}

#undef KINETUM_TEST_PROVIDER_ABI_INITIALIZER
