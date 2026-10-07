// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_materialization_component.c
 * @brief Five-role component for exact materializer transaction proofs.
 * @author Fleming Patel
 *
 * This hardened test image implements seven contracts across the five provider
 * roles: DPDK process-facility, CPU execution, UDP and DPDK I/O, host and DPDK
 * storage, and same-domain transition. Factories publish complete inert
 * operation records, validate the production-shaped dependency handles, and
 * record their linear ownership events through one test-supplied descriptor.
 * A single exact non-facility role may be selected to fail before publishing
 * ownership, allowing the real materializer's complete rollback and
 * post-facility fail-stop order to be observed without a second materializer.
 * The facility's deliberately invalid worker-registration result proves that
 * unclassifiable foreign thread ownership fails stop.
 */

#include "src/provider/provider_component_abi.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gen/kinetum/provider/provider_build_identity.h"

/** Test-only inherited descriptor used for bounded ownership-event records. */
#define KINETUM_TEST_MATERIALIZER_TRACE_FD "KINETUM_TEST_MATERIALIZER_TRACE_FD"

/** Test-only exact role selected for one recoverable factory failure. */
#define KINETUM_TEST_MATERIALIZER_FAIL_ROLE "KINETUM_TEST_MATERIALIZER_FAIL_ROLE"

/** Test-only successful callback selected to return forbidden diagnostic residue. */
#define KINETUM_TEST_MATERIALIZER_SUCCESS_DIAGNOSTIC "KINETUM_TEST_MATERIALIZER_SUCCESS_DIAGNOSTIC"

/** Exact component identity exported by the test descriptor. */
static const char COMPONENT_ID[] = "kinetum.test.provider.materialization";
/** Exact CPU-execution catalog identity. */
static const char CPU_EXECUTION_TYPE_URL[] = "type.googleapis.com/kinetum.execution.cpu.v1.CpuExecutionConfig";
/** Exact DPDK process-facility catalog identity. */
static const char DPDK_FACILITY_TYPE_URL[] = "type.googleapis.com/kinetum.facility.dpdk.v1.DpdkFacilityConfig";
/** Exact DPDK I/O-driver catalog identity. */
static const char DPDK_DRIVER_TYPE_URL[] = "type.googleapis.com/kinetum.io.dpdk.v1.DpdkDriverConfig";
/** Exact UDP I/O-driver catalog identity. */
static const char UDP_DRIVER_TYPE_URL[] = "type.googleapis.com/kinetum.io.udp.v1.UdpDriverConfig";
/** Exact DPDK storage catalog identity. */
static const char DPDK_STORAGE_TYPE_URL[] = "type.googleapis.com/kinetum.storage.dpdk.v1.DpdkStorageConfig";
/** Exact host-storage catalog identity. */
static const char HOST_STORAGE_TYPE_URL[] = "type.googleapis.com/kinetum.storage.host.v1.HostStorageConfig";
/** Exact same-domain transition catalog identity. */
static const char ZERO_COPY_SHARE_TYPE_URL[] = "type.googleapis.com/kinetum.transition.core.v1.ZeroCopyShareConfig";

/** Exact host-storage capabilities projected by the pure catalog. */
static const uint32_t HOST_STORAGE_CAPABILITIES = KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ |
						  KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE |
						  KINETUM_PACKET_STORAGE_WRITABLE_CLONE;

/** One role-specific instance and its complete immutable operation record. */
struct materialization_test_instance {
	int trace_fd;		     ///< Borrowed test descriptor retained for this instance lifetime.
	kinetum_provider_role role;  ///< Exact role selecting the operation member below.
	uint8_t packet_io_active;    ///< One only between successful activate/deactivate callbacks.
	uint8_t padding[2];	     ///< Zeroed native-structure padding.
	kinetum_provider_process_facility_operations facility_operations;      ///< Process-facility result.
	kinetum_packet_storage_domain_operations storage_operations;	       ///< Storage role result.
	kinetum_provider_io_driver_operations io_operations;		       ///< I/O role result.
	kinetum_provider_execution_operations execution_operations;	       ///< Execution role result.
	kinetum_provider_storage_transition_operations transition_operations;  ///< Transition role result.
	kinetum_packet_rx_burst_operations *rx_operations;		       ///< Exact filtered RX operation rows.
	kinetum_packet_tx_burst_operations *tx_operations;		       ///< Exact filtered TX operation rows.
	uint32_t *port_indices;	 ///< Exact driver-local observation port order.
	uint32_t port_count;	 ///< Complete port-index population.
};

/**
 * @brief Clear one optional caller-owned diagnostic.
 *
 * @param diagnostic Mutable bounded diagnostic, or null.
 */
static void clear_diagnostic(kinetum_provider_diagnostic *diagnostic)
{
	if (diagnostic != NULL) {
		diagnostic->size = 0;
	}
}

/**
 * @brief Parse the exact inherited test trace descriptor.
 *
 * @return Nonnegative descriptor, or -1 for malformed test injection.
 */
static int trace_descriptor(void)
{
	const char *text = getenv(KINETUM_TEST_MATERIALIZER_TRACE_FD);
	char *end = NULL;
	long value;
	if (text == NULL || text[0] == '\0') {
		return -1;
	}
	errno = 0;
	value = strtol(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || value < 0 || value > INT_MAX) {
		return -1;
	}
	return (int)value;
}

/**
 * @brief Record one single-byte linear ownership event.
 *
 * @param descriptor Exact inherited descriptor.
 * @param event Stable event byte.
 * @return Nonzero only after one complete write.
 */
static int record_event(int descriptor, char event)
{
	ssize_t written;
	do {
		written = write(descriptor, &event, 1u);
	} while (written < 0 && errno == EINTR);
	return written == 1;
}

/**
 * @brief Test whether one exact role is selected for factory failure.
 *
 * @param role Stable role event byte.
 * @return Nonzero only when the injected failure selector equals @p role.
 */
static int role_must_fail(char role)
{
	const char *selected = getenv(KINETUM_TEST_MATERIALIZER_FAIL_ROLE);
	return selected != NULL && selected[0] == role && selected[1] == '\0';
}

/**
 * @brief Test whether one successful callback must publish diagnostic residue.
 *
 * @param operation Exact test operation identity.
 * @return Nonzero only when the injection selects @p operation.
 */
static int success_diagnostic_requested(const char *operation)
{
	const char *selected = getenv(KINETUM_TEST_MATERIALIZER_SUCCESS_DIAGNOSTIC);
	return selected != NULL && operation != NULL && strcmp(selected, operation) == 0;
}

/**
 * @brief Publish one deliberately invalid success diagnostic when selected.
 *
 * @param diagnostic Caller-owned bounded diagnostic.
 * @param operation Exact test operation identity.
 */
static void maybe_publish_success_diagnostic(kinetum_provider_diagnostic *diagnostic, const char *operation)
{
	if (!success_diagnostic_requested(operation)) {
		return;
	}
	if (diagnostic == NULL || diagnostic->data == NULL || diagnostic->capacity == 0u) {
		abort();
	}
	diagnostic->data[0] = 'x';
	diagnostic->size = 1u;
}

/**
 * @brief Compare one borrowed ABI text view with exact static text.
 *
 * @param view Borrowed ABI text view.
 * @param expected Exact static byte sequence.
 * @param expected_size Exact byte extent of @p expected.
 * @return Nonzero only for byte-identical text.
 */
static int text_equals(kinetum_provider_text_view view, const char *expected, uint32_t expected_size)
{
	return view.data != NULL && view.size == expected_size && memcmp(view.data, expected, expected_size) == 0;
}

/**
 * @brief Match one exact borrowed dependency handle.
 *
 * The enclosing factory-request validator owns pointer/count, padding, and
 * non-null operation checks. This helper pins the role and contract identity
 * expected by the production compiler's canonical dependency schedule.
 *
 * @param request Exact validated factory request.
 * @param index Canonical dependency index.
 * @param role Required provider role.
 * @param type_url Required canonical contract identity.
 * @param type_url_size Exact byte extent of @p type_url.
 * @return Nonzero only for the exact dependency row.
 */
static int dependency_matches(const kinetum_provider_factory_request *request, uint32_t index,
			      kinetum_provider_role role, const char *type_url, uint32_t type_url_size)
{
	const kinetum_provider_dependency_handle *dependency;
	if (request == NULL || index >= request->dependency_count) {
		return 0;
	}
	dependency = &request->dependencies[index];
	return dependency->role == role && text_equals(dependency->type_url, type_url, type_url_size);
}

/**
 * @brief Match either exact storage contract implemented by this component.
 *
 * @param request Exact validated factory request.
 * @param index Canonical dependency index.
 * @return Nonzero only for one exact packet-storage dependency row.
 */
static int storage_dependency_matches(const kinetum_provider_factory_request *request, uint32_t index)
{
	return dependency_matches(request, index, KINETUM_PROVIDER_ROLE_PACKET_STORAGE, DPDK_STORAGE_TYPE_URL,
				  (uint32_t)(sizeof(DPDK_STORAGE_TYPE_URL) - 1u)) ||
	       dependency_matches(request, index, KINETUM_PROVIDER_ROLE_PACKET_STORAGE, HOST_STORAGE_TYPE_URL,
				  (uint32_t)(sizeof(HOST_STORAGE_TYPE_URL) - 1u));
}

/**
 * @brief Resolve one compiled logical-port row by compact port index.
 *
 * @param facts Exact compiled I/O-driver fact tree.
 * @param port_index Exact compact port index.
 * @return Unique matching port row, or null for absent/duplicate identity.
 */
static const kinetum_provider_io_port_fact *find_port(const kinetum_provider_io_driver_facts *facts,
						      uint32_t port_index)
{
	const kinetum_provider_io_port_fact *match = NULL;
	uint32_t index;
	for (index = 0; index < facts->port_count; ++index) {
		if (facts->ports[index].port_index != port_index) {
			continue;
		}
		if (match != NULL) {
			return NULL;
		}
		match = &facts->ports[index];
	}
	return match;
}

/**
 * @brief Return no storage on the inert materializer proof path.
 *
 * @param state Inert storage instance.
 * @param[out] records Caller-owned output array left unchanged.
 * @param capacity Maximum requested record count.
 * @return Zero accepted records.
 */
static uint16_t acquire_no_packets(void *state, kinetum_packet_record **records, uint16_t capacity)
{
	(void)state;
	(void)records;
	(void)capacity;
	return 0;
}

/**
 * @brief Return no clone on the inert materializer proof path.
 *
 * @param state Inert storage instance.
 * @param source Borrowed source record.
 * @return Null because the fixture owns no packet population.
 */
static kinetum_packet_record *clone_no_packet(void *state, const kinetum_packet_record *source)
{
	(void)state;
	(void)source;
	return NULL;
}

/**
 * @brief Return no copied origin on the inert materializer proof path.
 *
 * @param state Inert storage instance.
 * @param origins Borrowed packet-origin array.
 * @param[out] records Caller-owned output array left unchanged.
 * @param count Requested origin count.
 * @return Zero copied origins.
 */
static uint16_t copy_no_origins(void *state, const kinetum_packet_origin_view *origins, kinetum_packet_record **records,
				uint16_t count)
{
	(void)state;
	(void)origins;
	(void)records;
	(void)count;
	return 0;
}

/**
 * @brief Accept no record retirement because the inert storage owns none.
 *
 * @param state Inert storage instance.
 * @param records Borrowed record array.
 * @param count Record count, required to remain zero in this fixture.
 */
static void release_no_packets(void *state, kinetum_packet_record *const *records, uint16_t count)
{
	(void)state;
	(void)records;
	(void)count;
}

/**
 * @brief Publish explicit unsupported occupancy for inert test storage.
 * @param state Exact storage instance.
 * @param[out] observation Caller-owned exact identity row.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return OK after publishing one unsupported row.
 */
static kinetum_provider_status observe_storage(void *state, kinetum_provider_storage_observation *observation,
					       kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)state;
	clear_diagnostic(diagnostic);
	if (instance == NULL || instance->role != KINETUM_PROVIDER_ROLE_PACKET_STORAGE || observation == NULL) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	memset(observation, 0, sizeof(*observation));
	observation->runtime_generation = instance->storage_operations.generation;
	observation->storage_domain_index = instance->storage_operations.domain_index;
	observation->state = KINETUM_PROVIDER_OBSERVATION_UNSUPPORTED;
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Return no packet from one inert receive queue.
 *
 * @param state Inert I/O-driver instance.
 * @param[out] records Caller-owned output array left unchanged.
 * @param capacity Maximum requested burst count.
 * @return Zero transferred and rejected packets.
 */
static kinetum_packet_rx_burst_result receive_no_packets(void *state, kinetum_packet_record **records,
							 uint16_t capacity)
{
	(void)state;
	(void)records;
	(void)capacity;
	return (kinetum_packet_rx_burst_result){0, 0};
}

/**
 * @brief Consume no packet through one inert transmit queue.
 *
 * @param state Inert I/O-driver instance.
 * @param records Borrowed packet-record array.
 * @param count Submitted packet count.
 * @return Zero consumed packets.
 */
static uint16_t transmit_no_packets(void *state, kinetum_packet_record *const *records, uint16_t count)
{
	(void)state;
	(void)records;
	(void)count;
	return 0;
}

/**
 * @brief Flush one inert transmit queue.
 *
 * @param state Inert I/O-driver instance.
 */
static void flush_no_packets(void *state)
{
	(void)state;
}

/**
 * @brief Report that one inert transmit queue needs no flush.
 *
 * @param state Inert I/O-driver instance.
 * @return Zero because no flush is required.
 */
static uint8_t maybe_flush_no_packets(void *state)
{
	(void)state;
	return UINT8_C(0);
}

/**
 * @brief Transfer one exact zero-copy prefix for operation-table validity.
 *
 * @param state Inert transition instance.
 * @param sources Exact source-record ownership array.
 * @param[out] destinations Caller-owned destination array receiving aliases.
 * @param count Requested bounded prefix size.
 * @return Exact accepted non-null prefix length.
 */
static uint16_t transfer_zero_copy(void *state, kinetum_packet_record *const *sources,
				   kinetum_packet_record **destinations, uint16_t count)
{
	uint16_t index;
	if (state == NULL || (count != 0 && (sources == NULL || destinations == NULL))) {
		return 0;
	}
	for (index = 0; index < count; ++index) {
		if (sources[index] == NULL) {
			return index;
		}
		destinations[index] = sources[index];
	}
	return count;
}

/**
 * @brief Return an out-of-domain result after one valid inert registration call.
 *
 * @param state Exact process-facility instance.
 * @param worker_index Exact compact worker index; the fixture accepts only zero.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return Deliberately invalid status after recording registration, or a valid
 *         rejection before that point.
 */
static kinetum_provider_status invalid_register_worker(void *state, uint32_t worker_index,
						       kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)state;
	clear_diagnostic(diagnostic);
	if (instance == NULL || instance->role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY || worker_index != 0) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	if (!record_event(instance->trace_fd, 'R')) {
		return KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR;
	}
	if (success_diagnostic_requested("worker-registration")) {
		maybe_publish_success_diagnostic(diagnostic, "worker-registration");
		return KINETUM_PROVIDER_STATUS_OK;
	}
	return INT32_C(99);
}

/**
 * @brief Record an invalid attempt to release an unclassified registration.
 *
 * @param state Exact process-facility instance.
 * @param worker_index Exact compact worker index; any malformed input aborts.
 */
static void record_unexpected_worker_unregister(void *state, uint32_t worker_index)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)state;
	if (instance == NULL || instance->role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY || worker_index != 0 ||
	    !record_event(instance->trace_fd, 'U')) {
		abort();
	}
}

/**
 * @brief Bind the inert facility coordinator without retaining state.
 *
 * @param state Exact process-facility instance.
 * @param service_index Exact coordinator service index.
 * @param cpu_core_id Exact nonnegative coordinator CPU identity.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return Valid provider status for the exact inert binding.
 */
static kinetum_provider_status bind_inert_coordinator(void *state, uint32_t service_index, int32_t cpu_core_id,
						      kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)state;
	clear_diagnostic(diagnostic);
	if (instance == NULL || instance->role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY || service_index != 0 ||
	    cpu_core_id < 0) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	if (success_diagnostic_requested("lifecycle-bind") && !record_event(instance->trace_fd, 'B')) {
		abort();
	}
	maybe_publish_success_diagnostic(diagnostic, "lifecycle-bind");
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Reject inert runtime-service launch without retaining callback storage.
 *
 * @param state Exact process-facility instance.
 * @param service_index Candidate runtime-service index.
 * @param cpu_core_id Candidate runtime-service CPU identity.
 * @param entry Borrowed service entry point, never retained or invoked.
 * @param argument Borrowed service argument, never retained.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return FAILED_PRECONDITION for the exact process-facility instance.
 */
static kinetum_provider_status reject_runtime_service_launch(void *state, uint32_t service_index, int32_t cpu_core_id,
							     kinetum_provider_runtime_service_entry_fn entry,
							     void *argument, kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)state;
	(void)service_index;
	(void)cpu_core_id;
	(void)entry;
	(void)argument;
	clear_diagnostic(diagnostic);
	if (instance == NULL || instance->role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	return KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION;
}

/**
 * @brief Reject inert runtime-service join because no launch can succeed.
 *
 * @param state Exact process-facility instance.
 * @param service_index Candidate runtime-service index.
 * @param cpu_core_id Candidate runtime-service CPU identity.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return FAILED_PRECONDITION for the exact process-facility instance.
 */
static kinetum_provider_status reject_runtime_service_join(void *state, uint32_t service_index, int32_t cpu_core_id,
							   kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)state;
	(void)service_index;
	(void)cpu_core_id;
	clear_diagnostic(diagnostic);
	if (instance == NULL || instance->role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	return KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION;
}

/**
 * @brief Activate the complete inert driver and record the lifecycle edge.
 *
 * @param state Exact I/O-driver instance.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return OK after one cold-to-live transition, or a valid failure status.
 */
static kinetum_provider_status activate_packet_io(void *state, kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)state;
	clear_diagnostic(diagnostic);
	if (instance == NULL || instance->role != KINETUM_PROVIDER_ROLE_IO_DRIVER || instance->packet_io_active != 0) {
		return KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION;
	}
	if (!record_event(instance->trace_fd, 'A')) {
		return KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR;
	}
	instance->packet_io_active = UINT8_C(1);
	maybe_publish_success_diagnostic(diagnostic, "io-activation");
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Deactivate the complete inert driver and record the lifecycle edge.
 *
 * @param state Exact I/O-driver instance.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return OK after one live-to-cold transition, or a valid failure status.
 */
static kinetum_provider_status deactivate_packet_io(void *state, kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)state;
	clear_diagnostic(diagnostic);
	if (instance == NULL || instance->role != KINETUM_PROVIDER_ROLE_IO_DRIVER || instance->packet_io_active != 1) {
		return KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION;
	}
	if (!record_event(instance->trace_fd, 'D')) {
		return KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR;
	}
	instance->packet_io_active = UINT8_C(0);
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Publish explicit unsupported I/O observations in compiled fact order.
 * @param state Exact I/O-driver instance.
 * @param[out] observations Complete caller-owned port and stream arrays.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return OK after exact identity publication, or INVALID_ARGUMENT.
 */
static kinetum_provider_status observe_packet_io(void *state, kinetum_provider_io_observation_batch *observations,
						 kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)state;
	uint32_t index;
	clear_diagnostic(diagnostic);
	if (instance == NULL || instance->role != KINETUM_PROVIDER_ROLE_IO_DRIVER || observations == NULL ||
	    observations->port_count != instance->port_count ||
	    (instance->port_count != 0u && observations->ports == NULL) || observations->port_padding != 0u) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	for (index = 0u; index < (uint32_t)sizeof(observations->padding); ++index) {
		if (observations->padding[index] != 0u) {
			return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
		}
	}
	for (index = 0u; index < instance->port_count; ++index) {
		memset(&observations->ports[index], 0, sizeof(observations->ports[index]));
		observations->ports[index].port_index = instance->port_indices[index];
		observations->ports[index].state = KINETUM_PROVIDER_OBSERVATION_UNSUPPORTED;
	}
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Destroy one exact materialized role and record reverse ownership.
 *
 * @param opaque Sole materialized instance ownership.
 */
static void destroy_instance(void *opaque)
{
	struct materialization_test_instance *instance = (struct materialization_test_instance *)opaque;
	char event = '\0';
	if (instance == NULL || instance->packet_io_active != 0) {
		abort();
	}
	switch (instance->role) {
	case KINETUM_PROVIDER_ROLE_PROCESS_FACILITY:
		event = 'f';
		break;
	case KINETUM_PROVIDER_ROLE_PACKET_STORAGE:
		event = 's';
		break;
	case KINETUM_PROVIDER_ROLE_IO_DRIVER:
		event = 'i';
		break;
	case KINETUM_PROVIDER_ROLE_EXECUTION:
		event = 'e';
		break;
	case KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION:
		event = 't';
		break;
	default:
		abort();
	}
	if (!record_event(instance->trace_fd, event)) {
		abort();
	}
	free(instance->rx_operations);
	free(instance->tx_operations);
	free(instance->port_indices);
	free(instance);
}

/**
 * @brief Reclaim one factory-local instance before ownership publication.
 *
 * @param instance Sole unpublished factory-local instance ownership.
 */
static void discard_instance(struct materialization_test_instance *instance)
{
	if (instance == NULL || instance->packet_io_active != 0) {
		abort();
	}
	free(instance->rx_operations);
	free(instance->tx_operations);
	free(instance->port_indices);
	free(instance);
}

/**
 * @brief Allocate and initialize one common exact role owner.
 *
 * @param role Exact role being materialized.
 * @param event Factory-attempt event.
 * @param[out] result Caller-owned empty factory result.
 * @param[out] failure_status Exact valid status returned when creation fails.
 * @return Instance on success, or null after an injected/operational failure.
 */
static struct materialization_test_instance *begin_factory(kinetum_provider_role role, char event,
							   kinetum_provider_factory_result *result,
							   kinetum_provider_status *failure_status)
{
	struct materialization_test_instance *instance;
	const int descriptor = trace_descriptor();
	if (failure_status == NULL) {
		return NULL;
	}
	*failure_status = KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR;
	if (result == NULL || result->instance != NULL || result->operations != NULL || result->destroy != NULL ||
	    descriptor < 0 || !record_event(descriptor, event)) {
		return NULL;
	}
	if (role_must_fail(event)) {
		*failure_status = KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION;
		return NULL;
	}
	instance = (struct materialization_test_instance *)calloc(1u, sizeof(*instance));
	if (instance == NULL) {
		*failure_status = KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED;
		return NULL;
	}
	instance->trace_fd = descriptor;
	instance->role = role;
	return instance;
}

/**
 * @brief Materialize one inert process facility with an invalid registration canary.
 *
 * @param request Exact validated process-facility factory request.
 * @param[out] result Caller-owned empty result populated only on success.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return Valid provider status for the complete factory attempt.
 */
static kinetum_provider_status create_process_facility(const kinetum_provider_factory_request *request,
						       kinetum_provider_factory_result *result,
						       kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance;
	const kinetum_provider_process_facility_facts *facts;
	kinetum_provider_status failure_status;
	clear_diagnostic(diagnostic);
	if (request == NULL || request->role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY ||
	    !text_equals(request->type_url, DPDK_FACILITY_TYPE_URL, (uint32_t)(sizeof(DPDK_FACILITY_TYPE_URL) - 1u)) ||
	    !kinetum_provider_factory_request_is_valid(request) || request->dependency_count != 0) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	instance = begin_factory(KINETUM_PROVIDER_ROLE_PROCESS_FACILITY, 'F', result, &failure_status);
	if (instance == NULL) {
		return failure_status;
	}
	facts = request->compiled_facts.process_facility;
	instance->facility_operations.state = instance;
	instance->facility_operations.register_worker_thread = invalid_register_worker;
	instance->facility_operations.unregister_worker_thread = record_unexpected_worker_unregister;
	instance->facility_operations.bind_runtime_service_coordinator = bind_inert_coordinator;
	instance->facility_operations.launch_runtime_service = reject_runtime_service_launch;
	instance->facility_operations.join_runtime_service = reject_runtime_service_join;
	instance->facility_operations.generation = request->runtime_generation;
	instance->facility_operations.facility_index = facts->facility_index;
	result->instance = instance;
	result->operations = &instance->facility_operations;
	result->destroy = destroy_instance;
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Materialize one inert exact host- or DPDK-storage operation record.
 *
 * @param request Exact validated packet-storage factory request.
 * @param[out] result Caller-owned empty result populated only on success.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return Valid provider status for the complete factory attempt.
 */
static kinetum_provider_status create_storage(const kinetum_provider_factory_request *request,
					      kinetum_provider_factory_result *result,
					      kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance;
	const kinetum_provider_packet_storage_facts *facts;
	int is_dpdk_storage;
	int is_host_storage;
	kinetum_provider_status failure_status;
	clear_diagnostic(diagnostic);
	if (request == NULL || request->role != KINETUM_PROVIDER_ROLE_PACKET_STORAGE ||
	    !kinetum_provider_factory_request_is_valid(request) || request->runtime_generation > UINT32_MAX) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	is_dpdk_storage =
		text_equals(request->type_url, DPDK_STORAGE_TYPE_URL, (uint32_t)(sizeof(DPDK_STORAGE_TYPE_URL) - 1u));
	is_host_storage =
		text_equals(request->type_url, HOST_STORAGE_TYPE_URL, (uint32_t)(sizeof(HOST_STORAGE_TYPE_URL) - 1u));
	if ((!is_dpdk_storage && !is_host_storage) ||
	    (is_dpdk_storage &&
	     (request->dependency_count != 1 ||
	      !dependency_matches(request, 0, KINETUM_PROVIDER_ROLE_PROCESS_FACILITY, DPDK_FACILITY_TYPE_URL,
				  (uint32_t)(sizeof(DPDK_FACILITY_TYPE_URL) - 1u)))) ||
	    (is_host_storage && request->dependency_count != 0)) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	instance = begin_factory(KINETUM_PROVIDER_ROLE_PACKET_STORAGE, 'S', result, &failure_status);
	if (instance == NULL) {
		return failure_status;
	}
	facts = request->compiled_facts.packet_storage;
	instance->storage_operations.state = instance;
	instance->storage_operations.acquire_burst = acquire_no_packets;
	instance->storage_operations.clone_writable = clone_no_packet;
	instance->storage_operations.copy_origins_burst = copy_no_origins;
	instance->storage_operations.release_burst = release_no_packets;
	instance->storage_operations.observe_statistics = observe_storage;
	instance->storage_operations.generation = (uint32_t)request->runtime_generation;
	instance->storage_operations.domain_index = (uint16_t)facts->storage_domain_index;
	instance->storage_operations.maximum_packet_length = facts->maximum_packet_length;
	instance->storage_operations.capabilities = HOST_STORAGE_CAPABILITIES;
	if (is_dpdk_storage) {
		instance->storage_operations.capabilities |= KINETUM_PACKET_STORAGE_NIC_RX_DMA |
							     KINETUM_PACKET_STORAGE_NIC_TX_DMA;
	}
	result->instance = instance;
	result->operations = &instance->storage_operations;
	result->destroy = destroy_instance;
	maybe_publish_success_diagnostic(diagnostic, "factory");
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Materialize exact inert queue tables for one compiled UDP or DPDK driver.
 *
 * @param request Exact validated I/O-driver factory request.
 * @param[out] result Caller-owned empty result populated only on success.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return Valid provider status for the complete factory attempt.
 */
static kinetum_provider_status create_io_driver(const kinetum_provider_factory_request *request,
						kinetum_provider_factory_result *result,
						kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance;
	const kinetum_provider_io_driver_facts *facts;
	int is_dpdk_driver;
	int is_udp_driver;
	uint32_t rx_count = 0;
	uint32_t tx_count = 0;
	uint32_t rx_index = 0;
	uint32_t tx_index = 0;
	uint32_t index;
	kinetum_provider_status failure_status;
	clear_diagnostic(diagnostic);
	if (request == NULL || request->role != KINETUM_PROVIDER_ROLE_IO_DRIVER ||
	    !kinetum_provider_factory_request_is_valid(request)) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	is_dpdk_driver =
		text_equals(request->type_url, DPDK_DRIVER_TYPE_URL, (uint32_t)(sizeof(DPDK_DRIVER_TYPE_URL) - 1u));
	is_udp_driver =
		text_equals(request->type_url, UDP_DRIVER_TYPE_URL, (uint32_t)(sizeof(UDP_DRIVER_TYPE_URL) - 1u));
	if ((!is_dpdk_driver && !is_udp_driver) ||
	    (is_dpdk_driver &&
	     (request->dependency_count != 2 ||
	      !dependency_matches(request, 0, KINETUM_PROVIDER_ROLE_PROCESS_FACILITY, DPDK_FACILITY_TYPE_URL,
				  (uint32_t)(sizeof(DPDK_FACILITY_TYPE_URL) - 1u)) ||
	      !dependency_matches(request, 1, KINETUM_PROVIDER_ROLE_PACKET_STORAGE, DPDK_STORAGE_TYPE_URL,
				  (uint32_t)(sizeof(DPDK_STORAGE_TYPE_URL) - 1u)))) ||
	    (is_udp_driver &&
	     (request->dependency_count != 1 ||
	      !dependency_matches(request, 0, KINETUM_PROVIDER_ROLE_PACKET_STORAGE, HOST_STORAGE_TYPE_URL,
				  (uint32_t)(sizeof(HOST_STORAGE_TYPE_URL) - 1u))))) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	instance = begin_factory(KINETUM_PROVIDER_ROLE_IO_DRIVER, 'I', result, &failure_status);
	if (instance == NULL) {
		return failure_status;
	}
	facts = request->compiled_facts.io_driver;
	instance->port_count = facts->port_count;
	if (instance->port_count != 0u) {
		instance->port_indices = (uint32_t *)calloc(instance->port_count, sizeof(*instance->port_indices));
	}
	if (instance->port_count != 0u && instance->port_indices == NULL) {
		discard_instance(instance);
		return KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED;
	}
	for (index = 0u; index < instance->port_count; ++index) {
		instance->port_indices[index] = facts->ports[index].port_index;
	}
	for (index = 0; index < facts->stream_count; ++index) {
		if (facts->streams[index].direction == KINETUM_PROVIDER_IO_DIRECTION_RX) {
			++rx_count;
		} else if (facts->streams[index].direction == KINETUM_PROVIDER_IO_DIRECTION_TX) {
			++tx_count;
		} else {
			discard_instance(instance);
			return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
		}
	}
	if (rx_count != 0) {
		instance->rx_operations =
			(kinetum_packet_rx_burst_operations *)calloc(rx_count, sizeof(*instance->rx_operations));
	}
	if (tx_count != 0) {
		instance->tx_operations =
			(kinetum_packet_tx_burst_operations *)calloc(tx_count, sizeof(*instance->tx_operations));
	}
	if ((rx_count != 0 && instance->rx_operations == NULL) || (tx_count != 0 && instance->tx_operations == NULL)) {
		discard_instance(instance);
		return KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED;
	}
	for (index = 0; index < facts->stream_count; ++index) {
		const kinetum_provider_io_stream_fact *stream = &facts->streams[index];
		const kinetum_provider_io_port_fact *port = find_port(facts, stream->port_index);
		if (port == NULL || port->logical_port_id >= KINETUM_INVALID_PORT) {
			discard_instance(instance);
			return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
		}
		if (stream->direction == KINETUM_PROVIDER_IO_DIRECTION_RX) {
			kinetum_packet_rx_burst_operations *operations = &instance->rx_operations[rx_index++];
			operations->state = instance;
			operations->receive_burst = receive_no_packets;
			operations->maximum_burst = UINT16_C(1);
			operations->logical_port = (uint16_t)port->logical_port_id;
		} else {
			kinetum_packet_tx_burst_operations *operations = &instance->tx_operations[tx_index++];
			operations->state = instance;
			operations->transmit_burst = transmit_no_packets;
			operations->flush = flush_no_packets;
			operations->maybe_flush = maybe_flush_no_packets;
			operations->maximum_burst = UINT16_C(1);
			operations->logical_port = (uint16_t)port->logical_port_id;
		}
	}
	instance->io_operations.state = instance;
	instance->io_operations.activate_packet_io = activate_packet_io;
	instance->io_operations.deactivate_packet_io = deactivate_packet_io;
	instance->io_operations.rx_queues = instance->rx_operations;
	instance->io_operations.tx_queues = instance->tx_operations;
	instance->io_operations.observe_statistics = observe_packet_io;
	instance->io_operations.rx_queue_count = rx_count;
	instance->io_operations.tx_queue_count = tx_count;
	instance->io_operations.io_driver_index = facts->io_driver_index;
	result->instance = instance;
	result->operations = &instance->io_operations;
	result->destroy = destroy_instance;
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Materialize one inert exact CPU execution record.
 *
 * @param request Exact validated execution-provider factory request.
 * @param[out] result Caller-owned empty result populated only on success.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return Valid provider status for the complete factory attempt.
 */
static kinetum_provider_status create_execution(const kinetum_provider_factory_request *request,
						kinetum_provider_factory_result *result,
						kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance;
	const kinetum_provider_execution_facts *facts;
	kinetum_provider_status failure_status;
	clear_diagnostic(diagnostic);
	if (request == NULL || request->role != KINETUM_PROVIDER_ROLE_EXECUTION ||
	    !text_equals(request->type_url, CPU_EXECUTION_TYPE_URL, (uint32_t)(sizeof(CPU_EXECUTION_TYPE_URL) - 1u)) ||
	    !kinetum_provider_factory_request_is_valid(request) || request->dependency_count != 1 ||
	    !storage_dependency_matches(request, 0)) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	instance = begin_factory(KINETUM_PROVIDER_ROLE_EXECUTION, 'E', result, &failure_status);
	if (instance == NULL) {
		return failure_status;
	}
	facts = request->compiled_facts.execution;
	instance->execution_operations.state = instance;
	instance->execution_operations.execution_provider_index = facts->execution_provider_index;
	instance->execution_operations.required_access_agents = facts->required_access_agents;
	result->instance = instance;
	result->operations = &instance->execution_operations;
	result->destroy = destroy_instance;
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Materialize one inert exact same-domain transition record.
 *
 * @param request Exact validated storage-transition factory request.
 * @param[out] result Caller-owned empty result populated only on success.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return Valid provider status for the complete factory attempt.
 */
static kinetum_provider_status create_transition(const kinetum_provider_factory_request *request,
						 kinetum_provider_factory_result *result,
						 kinetum_provider_diagnostic *diagnostic)
{
	struct materialization_test_instance *instance;
	const kinetum_provider_storage_transition_facts *facts;
	kinetum_provider_status failure_status;
	clear_diagnostic(diagnostic);
	if (request == NULL || request->role != KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION ||
	    !text_equals(request->type_url, ZERO_COPY_SHARE_TYPE_URL,
			 (uint32_t)(sizeof(ZERO_COPY_SHARE_TYPE_URL) - 1u)) ||
	    !kinetum_provider_factory_request_is_valid(request) || request->runtime_generation > UINT32_MAX ||
	    request->dependency_count != 1 || !storage_dependency_matches(request, 0)) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	instance = begin_factory(KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION, 'T', result, &failure_status);
	if (instance == NULL) {
		return failure_status;
	}
	facts = request->compiled_facts.storage_transition;
	instance->transition_operations.state = instance;
	instance->transition_operations.transfer_burst = transfer_zero_copy;
	instance->transition_operations.generation = (uint32_t)request->runtime_generation;
	instance->transition_operations.transition_index = facts->transition_index;
	instance->transition_operations.from_storage_domain_index = facts->from_storage_domain_index;
	instance->transition_operations.to_storage_domain_index = facts->to_storage_domain_index;
	instance->transition_operations.mode = facts->mode;
	result->instance = instance;
	result->operations = &instance->transition_operations;
	result->destroy = destroy_instance;
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Prove the exact UDP component-host callback shape without side effects.
 *
 * @param request Exact I/O-driver host-proof request.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return OK for an exact valid request; otherwise INVALID_ARGUMENT.
 */
static kinetum_provider_status prove_udp_host(const kinetum_provider_host_proof_request *request,
					      kinetum_provider_diagnostic *diagnostic)
{
	clear_diagnostic(diagnostic);
	if (request == NULL || request->role != KINETUM_PROVIDER_ROLE_IO_DRIVER ||
	    !text_equals(request->type_url, UDP_DRIVER_TYPE_URL, (uint32_t)(sizeof(UDP_DRIVER_TYPE_URL) - 1u)) ||
	    !kinetum_provider_host_proof_request_is_valid(request)) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	if (success_diagnostic_requested("host-proof") && !record_event(trace_descriptor(), 'H')) {
		abort();
	}
	maybe_publish_success_diagnostic(diagnostic, "host-proof");
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Prove the exact inert DPDK facility host-callback shape.
 *
 * @param request Exact process-facility host-proof request.
 * @param diagnostic Mutable caller-owned diagnostic.
 * @return OK for an exact valid request; otherwise INVALID_ARGUMENT.
 */
static kinetum_provider_status prove_dpdk_facility_host(const kinetum_provider_host_proof_request *request,
							kinetum_provider_diagnostic *diagnostic)
{
	clear_diagnostic(diagnostic);
	if (request == NULL || request->role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY ||
	    !text_equals(request->type_url, DPDK_FACILITY_TYPE_URL, (uint32_t)(sizeof(DPDK_FACILITY_TYPE_URL) - 1u)) ||
	    !kinetum_provider_host_proof_request_is_valid(request)) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	if (success_diagnostic_requested("host-proof") && !record_event(trace_descriptor(), 'H')) {
		abort();
	}
	maybe_publish_success_diagnostic(diagnostic, "host-proof");
	return KINETUM_PROVIDER_STATUS_OK;
}

/** Exact seven-contract/five-role descriptor rows in strict type-URL order. */
static const kinetum_provider_contract_implementation CONTRACTS[] = {
	{
		.type_url = {CPU_EXECUTION_TYPE_URL, (uint32_t)(sizeof(CPU_EXECUTION_TYPE_URL) - 1u), 0},
		.factories = {NULL, NULL, NULL, create_execution, NULL},
		.host_proof = NULL,
		.role = KINETUM_PROVIDER_ROLE_EXECUTION,
		.padding = {0},
	},
	{
		.type_url = {DPDK_FACILITY_TYPE_URL, (uint32_t)(sizeof(DPDK_FACILITY_TYPE_URL) - 1u), 0},
		.factories = {create_process_facility, NULL, NULL, NULL, NULL},
		.host_proof = prove_dpdk_facility_host,
		.role = KINETUM_PROVIDER_ROLE_PROCESS_FACILITY,
		.padding = {0},
	},
	{
		.type_url = {DPDK_DRIVER_TYPE_URL, (uint32_t)(sizeof(DPDK_DRIVER_TYPE_URL) - 1u), 0},
		.factories = {NULL, create_io_driver, NULL, NULL, NULL},
		.host_proof = NULL,
		.role = KINETUM_PROVIDER_ROLE_IO_DRIVER,
		.padding = {0},
	},
	{
		.type_url = {UDP_DRIVER_TYPE_URL, (uint32_t)(sizeof(UDP_DRIVER_TYPE_URL) - 1u), 0},
		.factories = {NULL, create_io_driver, NULL, NULL, NULL},
		.host_proof = prove_udp_host,
		.role = KINETUM_PROVIDER_ROLE_IO_DRIVER,
		.padding = {0},
	},
	{
		.type_url = {DPDK_STORAGE_TYPE_URL, (uint32_t)(sizeof(DPDK_STORAGE_TYPE_URL) - 1u), 0},
		.factories = {NULL, NULL, create_storage, NULL, NULL},
		.host_proof = NULL,
		.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
		.padding = {0},
	},
	{
		.type_url = {HOST_STORAGE_TYPE_URL, (uint32_t)(sizeof(HOST_STORAGE_TYPE_URL) - 1u), 0},
		.factories = {NULL, NULL, create_storage, NULL, NULL},
		.host_proof = NULL,
		.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
		.padding = {0},
	},
	{
		.type_url = {ZERO_COPY_SHARE_TYPE_URL, (uint32_t)(sizeof(ZERO_COPY_SHARE_TYPE_URL) - 1u), 0},
		.factories = {NULL, NULL, NULL, NULL, create_transition},
		.host_proof = NULL,
		.role = KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION,
		.padding = {0},
	},
};

/** Exact immutable descriptor exported by the hardened test image. */
static const kinetum_provider_component_descriptor DESCRIPTOR = {
	.product_version_major = KINETUM_PROVIDER_PRODUCT_VERSION_MAJOR,
	.product_version_minor = KINETUM_PROVIDER_PRODUCT_VERSION_MINOR,
	.product_version_patch = KINETUM_PROVIDER_PRODUCT_VERSION_PATCH,
	.version_padding = {0},
	.abi_identity = KINETUM_PROVIDER_ABI_IDENTITY_INITIALIZER,
	.component_id = {COMPONENT_ID, (uint32_t)(sizeof(COMPONENT_ID) - 1u), 0},
	.contracts = CONTRACTS,
	.contract_count = (uint32_t)(sizeof(CONTRACTS) / sizeof(CONTRACTS[0])),
	.tail_padding = {0},
};

/** @return Exact immutable descriptor for the five-role test component. */
const kinetum_provider_component_descriptor *kinetum_provider_component_query(void)
{
	return &DESCRIPTOR;
}
