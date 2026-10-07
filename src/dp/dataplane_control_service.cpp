// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dataplane_control_service.cpp
 * @brief Data Plane runtime gRPC adapter implementation.
 * @author Fleming Patel
 */

#include "src/dp/dataplane_control_service.hpp"

#include <cstdint>
#include <exception>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>

#include "gen/kinetum/common/v1/common.pb.h"
#include "src/common/application_status.hpp"
#include "src/common/log.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_telemetry_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/version.hpp"
#include "src/common/logging_status.hpp"
#include "src/dp/partitioned_runtime.hpp"
#include "src/dp/runtime_telemetry_wire.hpp"

namespace kinetum::dp
{
namespace
{

/** @brief Application diagnostic for unavailable runtime lifecycle operations. */
constexpr char RUNTIME_LIFECYCLE_UNAVAILABLE[] = "Data Plane runtime lifecycle operation is unavailable";

/**
 * @brief Map one platform status code to its canonical wire classification.
 *
 * @param code Platform status code.
 * @return Exact wire error classification for @p code.
 */
kinetum::common::v1::ErrorCode to_wire_error_code(kinetum::common::status_code code) noexcept
{
	return kinetum::common::application_error_code(code);
}

/**
 * @brief Populate one complete application status from platform truth.
 *
 * @param source Immutable platform status.
 * @param target Caller-owned wire status. Must not be null.
 */
void set_application_status(const kinetum::common::status &source, kinetum::common::v1::Status *target)
{
	target->Clear();
	target->set_code(static_cast<int32_t>(source.code()));
	target->set_error_code(to_wire_error_code(source.code()));
	const auto message = source.message();
	const auto details = source.details();
	target->set_message(message.empty() ? "" : message.data(), message.size());
	target->set_details(details.empty() ? "" : details.data(), details.size());
}

/**
 * @brief Populate canonical application success.
 * @param target Caller-owned status cleared before publication; must not be null.
 */
void set_application_success(kinetum::common::v1::Status *target)
{
	target->Clear();
	target->set_code(static_cast<int32_t>(kinetum::common::status_code::OK));
	target->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
}

/**
 * @brief Populate a precise unavailable application result.
 * @param target Caller-owned status; must not be null.
 * @param message Borrowed non-null diagnostic copied into the response.
 */
void set_application_unavailable(kinetum::common::v1::Status *target, const char *message)
{
	set_application_status(kinetum::common::status::unavailable(message), target);
}

/** @return Transport INVALID_ARGUMENT with the fixed null-input diagnostic. */
grpc::Status null_request_or_response()
{
	return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
}

/**
 * @brief Preserve transport ambiguity when a response cannot be represented.
 * @param operation Calling handler or adapter whose response could not be constructed.
 * @return gRPC UNAVAILABLE without an authoritative partial response.
 */
grpc::Status response_construction_unavailable(std::string_view operation) noexcept
{
	KINETUM_LOG_ERROR("dp", "dp.response.unavailable", "operation={} response construction exhausted storage",
			  operation);
	// The log carries the diagnostic; allocation failure must not allocate another message.
	return grpc::Status(grpc::StatusCode::UNAVAILABLE, {});
}

/**
 * @brief Borrow exact bounded diagnostic bytes from one internal observation.
 * @param observation Fixed coordinator observation whose storage outlives the borrow.
 * @return Exact retained diagnostic prefix.
 */
std::string_view transition_diagnostic(const epoch_transition_transaction_observation &observation) noexcept
{
	if (observation.diagnostic.size > observation.diagnostic.bytes.size()) {
		std::terminate();
	}
	return {observation.diagnostic.bytes.data(), observation.diagnostic.size};
}

/**
 * @brief Map one internal identity relation to its exact public wire value.
 * @param resolution Declared internal identity relation.
 * @return Exact non-UNSPECIFIED public counterpart.
 */
kinetum::dataplane::v1::EpochTransitionIdentityResolution
to_wire_resolution(common::transition_identity_resolution resolution) noexcept
{
	using internal = common::transition_identity_resolution;
	using namespace kinetum::dataplane::v1;
	switch (resolution) {
	case internal::INVALID:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_INVALID;
	case internal::ADMISSIBLE:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_ADMISSIBLE;
	case internal::ACTIVE_EXACT:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_ACTIVE_EXACT;
	case internal::TERMINAL_EXACT:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT;
	case internal::STALE:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_STALE;
	case internal::INCONSISTENT:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_INCONSISTENT;
	case internal::EXPIRED_RETRY:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_EXPIRED_RETRY;
	case internal::IDENTITY_CONFLICT:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_IDENTITY_CONFLICT;
	case internal::UNKNOWN_FUTURE:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_UNKNOWN_FUTURE;
	case internal::OVERLAP:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_OVERLAP;
	case internal::POLICY_DISABLED:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_POLICY_DISABLED;
	case internal::STATE_UNAVAILABLE:
		return EPOCH_TRANSITION_IDENTITY_RESOLUTION_STATE_UNAVAILABLE;
	}
	std::terminate();
}

/**
 * @brief Map one internal failure cause to its exact public wire value.
 * @param code Declared internal failure cause, including explicit NONE.
 * @return Exact non-UNSPECIFIED public counterpart.
 */
kinetum::telemetry::v1::EpochTransitionFailureCode to_wire_failure_code(epoch_transition_failure_code code) noexcept
{
	using internal = epoch_transition_failure_code;
	using namespace kinetum::telemetry::v1;
	switch (code) {
	case internal::NONE:
		return EPOCH_TRANSITION_FAILURE_CODE_NONE;
	case internal::EXPLICIT_ABORT:
		return EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT;
	case internal::SHUTDOWN_ABORT:
		return EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT;
	case internal::PREPARE_FAILURE:
		return EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE;
	case internal::PREPARE_CANCELLED:
		return EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED;
	case internal::PREPARE_DEADLINE_EXCEEDED:
		return EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED;
	case internal::PREPARED_LEASE_EXPIRED:
		return EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED;
	case internal::COMMIT_DEADLINE_EXCEEDED:
		return EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED;
	case internal::CERTIFICATE_CONTRADICTION:
		return EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION;
	case internal::RETIREMENT_GRACE_DEADLINE_EXCEEDED:
		return EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED;
	case internal::RETIRE_CALLBACK_FAILURE:
		return EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE;
	case internal::RETIRE_CALLBACK_DEADLINE_EXCEEDED:
		return EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED;
	case internal::COMMIT_SHUTDOWN:
		return EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN;
	case internal::PROTOCOL_FAULT:
		return EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT;
	}
	std::terminate();
}

/**
 * @brief Project one exact active or terminal coordinator state onto the wire.
 * @param observation Already shape-validated exact observation.
 * @return Exact non-UNSPECIFIED active or terminal state.
 */
kinetum::telemetry::v1::EpochTransitionState
to_wire_transition_state(const epoch_transition_transaction_observation &observation) noexcept
{
	using namespace kinetum::telemetry::v1;
	switch (observation.outcome) {
	case epoch_transition_outcome::COMPLETE:
		return EPOCH_TRANSITION_STATE_COMPLETE;
	case epoch_transition_outcome::ABORTED:
		return EPOCH_TRANSITION_STATE_ABORTED;
	case epoch_transition_outcome::FAILED_STOP:
		return EPOCH_TRANSITION_STATE_FAILED_STOP;
	case epoch_transition_outcome::NONE:
		break;
	}
	switch (observation.phase) {
	case epoch_transition_phase::AWAITING_BOOTSTRAP:
		return EPOCH_TRANSITION_STATE_AWAITING_BOOTSTRAP;
	case epoch_transition_phase::BOOTSTRAPPING:
		return EPOCH_TRANSITION_STATE_BOOTSTRAPPING;
	case epoch_transition_phase::PREPARING:
		return EPOCH_TRANSITION_STATE_PREPARING;
	case epoch_transition_phase::PREPARED:
		return EPOCH_TRANSITION_STATE_PREPARED;
	case epoch_transition_phase::COMMITTING:
		return EPOCH_TRANSITION_STATE_COMMITTING;
	case epoch_transition_phase::RETIRING:
		return EPOCH_TRANSITION_STATE_RETIRING;
	case epoch_transition_phase::FAILED_STOP:
		return EPOCH_TRANSITION_STATE_FAILED_STOP;
	case epoch_transition_phase::IDLE:
		return EPOCH_TRANSITION_STATE_IDLE;
	}
	std::terminate();
}

/**
 * @brief Test whether one operation resolved exact active or terminal identity.
 * @param result Fixed coordinator operation result.
 * @return true only for ACTIVE_EXACT or TERMINAL_EXACT.
 */
bool transition_observation_is_exact(const epoch_transition_operation_result &result) noexcept
{
	return result.observation.resolution == common::transition_identity_resolution::ACTIVE_EXACT ||
	       result.observation.resolution == common::transition_identity_resolution::TERMINAL_EXACT;
}

/**
 * @brief Validate all cross-field invariants required by the public response shape.
 * @param result Fixed coordinator operation result.
 * @return true only when the result has one exact representable wire projection.
 */
bool valid_transition_result_shape(const epoch_transition_operation_result &result) noexcept
{
	const auto &observation = result.observation;
	const bool exact = transition_observation_is_exact(result);
	common::status_code decoded_code{};
	const bool declared_code =
		common::decode_application_status_code(static_cast<int32_t>(result.code), decoded_code);
	const bool duration_shape =
		(observation.duration_presence & static_cast<uint8_t>(~TRANSITION_DURATION_PRESENCE_MASK)) == 0u &&
		(((observation.duration_presence & TRANSITION_PREPARE_DURATION_PRESENT) != 0u) ||
		 observation.prepare_duration_ns == 0u) &&
		(((observation.duration_presence & TRANSITION_COMMIT_DURATION_PRESENT) != 0u) ||
		 observation.commit_duration_ns == 0u) &&
		(((observation.duration_presence & TRANSITION_RETIREMENT_DURATION_PRESENT) != 0u) ||
		 observation.retirement_duration_ns == 0u);
	if (!declared_code || decoded_code != result.code || (exact && !observation.identity.valid()) ||
	    observation.diagnostic.size > observation.diagnostic.bytes.size() || !duration_shape) {
		return false;
	}
	if (!exact) {
		return result.code != common::status_code::OK &&
		       observation.outcome == epoch_transition_outcome::NONE &&
		       observation.failure_code == epoch_transition_failure_code::NONE;
	}
	if (!common::valid_epoch_id(observation.from_epoch) || observation.from_epoch >= observation.to_epoch ||
	    observation.to_epoch != observation.identity.target_epoch || observation.admitted_monotonic_ns == 0u) {
		return false;
	}
	if (observation.resolution == common::transition_identity_resolution::TERMINAL_EXACT) {
		const bool complete = observation.outcome == epoch_transition_outcome::COMPLETE &&
				      observation.phase == epoch_transition_phase::IDLE &&
				      observation.failure_code == epoch_transition_failure_code::NONE;
		const bool aborted = observation.outcome == epoch_transition_outcome::ABORTED &&
				     observation.phase == epoch_transition_phase::IDLE &&
				     is_precommit_failure(observation.failure_code);
		const bool failed_stop = observation.outcome == epoch_transition_outcome::FAILED_STOP &&
					 observation.phase == epoch_transition_phase::FAILED_STOP &&
					 observation.failure_code != epoch_transition_failure_code::NONE &&
					 observation.failure_code !=
						 epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED;
		return observation.terminal_monotonic_ns >= observation.admitted_monotonic_ns &&
		       (complete || aborted || failed_stop);
	}
	if (observation.outcome == epoch_transition_outcome::FAILED_STOP) {
		return observation.phase == epoch_transition_phase::FAILED_STOP &&
		       observation.failure_code != epoch_transition_failure_code::NONE &&
		       observation.failure_code != epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED;
	}
	const bool active_phase = observation.phase == epoch_transition_phase::PREPARING ||
				  observation.phase == epoch_transition_phase::PREPARED ||
				  observation.phase == epoch_transition_phase::COMMITTING ||
				  observation.phase == epoch_transition_phase::RETIRING;
	const bool unfrozen = observation.outcome == epoch_transition_outcome::NONE && active_phase &&
			      observation.failure_code == epoch_transition_failure_code::NONE;
	const bool frozen = observation.outcome == epoch_transition_outcome::NONE &&
			    observation.phase == epoch_transition_phase::RETIRING &&
			    observation.failure_code ==
				    epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED;
	return unfrozen || frozen;
}

/**
 * @brief Populate fields common to every live-transition response.
 * @tparam response_type Generated response carrying status/state/resolution/failure.
 * @param result Exact internal operation result.
 * @param response Cleared caller-owned response.
 */
template <typename response_type>
void populate_transition_result(const epoch_transition_operation_result &result, response_type *response)
{
	if (!valid_transition_result_shape(result)) {
		std::terminate();
	}
	const auto diagnostic = transition_diagnostic(result.observation);
	if (result.code == common::status_code::OK) {
		set_application_success(response->mutable_status());
	} else {
		set_application_status(kinetum::common::status(result.code, std::string(diagnostic)),
				       response->mutable_status());
	}
	response->set_identity_resolution(to_wire_resolution(result.observation.resolution));
	response->set_failure_code(to_wire_failure_code(result.observation.failure_code));
	response->set_transition_state(transition_observation_is_exact(result) ?
					       to_wire_transition_state(result.observation) :
					       kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED);
}

/**
 * @brief Log one completed cold mutation call without implying a new transition.
 * @param operation Requested RPC operation, including exact retries.
 * @param mutation_sequence Requested CP allocation identity.
 * @param epoch Requested target epoch.
 * @param result Shape-validated runtime result; active observations are not completion.
 */
void log_transition_result(std::string_view operation, uint64_t mutation_sequence, uint64_t epoch,
			   const epoch_transition_operation_result &result) noexcept
{
	const auto &observation = result.observation;
	const auto state = transition_observation_is_exact(result) ?
				   to_wire_transition_state(observation) :
				   kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED;
	const bool requested_abort = observation.failure_code == epoch_transition_failure_code::EXPLICIT_ABORT ||
				     observation.failure_code == epoch_transition_failure_code::SHUTDOWN_ABORT ||
				     observation.failure_code == epoch_transition_failure_code::PREPARE_CANCELLED;
	auto level = common::log_level::INFO;
	if (observation.failure_code != epoch_transition_failure_code::NONE && !requested_abort) {
		level = common::log_level::ERROR;
	} else if (requested_abort || !result.is_ok()) {
		level = common::log_level::WARN;
	}
	KINETUM_LOG(
		level, "dp", "dp.transition.result",
		"operation={} mutation_sequence={} target_epoch={} status={} resolution={} state={} failure={} reason={}",
		operation, mutation_sequence, epoch, common::status_code_name(result.code),
		std::string_view(kinetum::dataplane::v1::EpochTransitionIdentityResolution_Name(
					 to_wire_resolution(observation.resolution)))
			.substr(sizeof("EPOCH_TRANSITION_IDENTITY_RESOLUTION_") - 1u),
		std::string_view(kinetum::telemetry::v1::EpochTransitionState_Name(state))
			.substr(sizeof("EPOCH_TRANSITION_STATE_") - 1u),
		std::string_view(kinetum::telemetry::v1::EpochTransitionFailureCode_Name(
					 to_wire_failure_code(observation.failure_code)))
			.substr(sizeof("EPOCH_TRANSITION_FAILURE_CODE_") - 1u),
		transition_diagnostic(observation));
}

/**
 * @brief Reject one lifecycle operation without publishing synthetic state.
 *
 * @tparam request_type Generated request type.
 * @tparam response_type Generated response type with mutable_status().
 * @param request Caller request.
 * @param response Caller response.
 * @return Transport OK with application UNAVAILABLE, or INVALID_ARGUMENT.
 */
template <typename request_type, typename response_type>
grpc::Status reject_runtime_lifecycle(const request_type *request, response_type *response)
try {
	if (request == nullptr || response == nullptr) {
		return null_request_or_response();
	}
	response->Clear();
	set_application_unavailable(response->mutable_status(), RUNTIME_LIFECYCLE_UNAVAILABLE);
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

}  // namespace

dataplane_control_service::dataplane_control_service(partitioned_runtime &runtime) noexcept
	: runtime_(runtime)
{
}

grpc::Status dataplane_control_service::BootstrapConfigSnapshot(
	grpc::ServerContext *, const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest *request,
	kinetum::dataplane::v1::BootstrapConfigSnapshotResponse *response)
try {
	if (request == nullptr || response == nullptr) {
		return null_request_or_response();
	}
	response->Clear();

	KINETUM_LOG_INFO("dp", "dp.bootstrap.requested", "snapshot={} revision={} epoch={}",
			 request->snapshot().snapshot_id(), request->snapshot().revision(), request->active_epoch());
	auto result_or = runtime_.bootstrap(*request);
	if (!result_or.is_ok()) {
		KINETUM_LOG_ERROR("dp", "dp.bootstrap.failed", "snapshot={} epoch={} status={} reason={} details={}",
				  request->snapshot().snapshot_id(), request->active_epoch(),
				  common::status_code_name(result_or.error().code()), result_or.error().message(),
				  result_or.error().details());
		set_application_status(result_or.error(), response->mutable_status());
		return grpc::Status::OK;
	}

	const auto &result = result_or.value();
	set_application_success(response->mutable_status());
	response->set_restored_epoch(result.restored_epoch);
	response->set_validation_hash(reinterpret_cast<const char *>(result.validation_hash.data()),
				      result.validation_hash.size());
	response->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	response->set_allocated_epoch_high_watermark(result.allocated_epoch_high_watermark);
	response->set_mutation_sequence_high_watermark(result.mutation_sequence_high_watermark);
	KINETUM_LOG_INFO("dp", "dp.bootstrap.completed", "snapshot={} revision={} epoch={}",
			 request->snapshot().snapshot_id(), request->snapshot().revision(), result.restored_epoch);
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

grpc::Status
dataplane_control_service::PrepareConfigSnapshot(grpc::ServerContext *,
						 const kinetum::dataplane::v1::PrepareConfigSnapshotRequest *request,
						 kinetum::dataplane::v1::PrepareConfigSnapshotResponse *response)
try {
	if (request == nullptr || response == nullptr) {
		return null_request_or_response();
	}
	response->Clear();
	KINETUM_LOG_INFO("dp", "dp.prepare.requested", "snapshot={} revision={} mutation_sequence={} target_epoch={}",
			 request->snapshot().snapshot_id(), request->snapshot().revision(),
			 request->mutation_sequence(), request->target_epoch());
	const auto result = runtime_.prepare_epoch_transition(*request);
	populate_transition_result(result, response);
	log_transition_result("prepare", request->mutation_sequence(), request->target_epoch(), result);
	if (transition_observation_is_exact(result)) {
		response->set_mutation_sequence(result.observation.identity.mutation_sequence);
	}
	if (result.observation.resolution == common::transition_identity_resolution::ACTIVE_EXACT &&
	    result.observation.phase == epoch_transition_phase::PREPARED) {
		if (result.observation.lease_state != epoch_transition_prepared_lease_state::ARMED ||
		    result.observation.prepared_lease_deadline_unix_ms == 0u) {
			std::terminate();
		}
		response->set_prepared_epoch(result.observation.identity.target_epoch);
		response->set_validation_hash(
			reinterpret_cast<const char *>(result.observation.identity.validation_hash.data()),
			result.observation.identity.validation_hash.size());
		response->set_prepared_lease_deadline_unix_ms(result.observation.prepared_lease_deadline_unix_ms);
	}
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

grpc::Status
dataplane_control_service::ActivateConfigSnapshot(grpc::ServerContext *,
						  const kinetum::dataplane::v1::ActivateConfigSnapshotRequest *request,
						  kinetum::dataplane::v1::ActivateConfigSnapshotResponse *response)
try {
	if (request == nullptr || response == nullptr) {
		return null_request_or_response();
	}
	response->Clear();
	KINETUM_LOG_INFO("dp", "dp.activate.requested", "mutation_sequence={} target_epoch={}",
			 request->mutation_sequence(), request->epoch());
	const auto result = runtime_.activate_epoch_transition(*request);
	populate_transition_result(result, response);
	log_transition_result("activate", request->mutation_sequence(), request->epoch(), result);
	if (transition_observation_is_exact(result)) {
		response->set_mutation_sequence(result.observation.identity.mutation_sequence);
	}
	if (result.observation.resolution == common::transition_identity_resolution::TERMINAL_EXACT &&
	    result.observation.outcome == epoch_transition_outcome::COMPLETE) {
		if (result.observation.terminal_monotonic_ns < result.observation.admitted_monotonic_ns) {
			std::terminate();
		}
		response->set_completed_epoch(result.observation.identity.target_epoch);
		response->set_transition_duration_ns(result.observation.terminal_monotonic_ns -
						     result.observation.admitted_monotonic_ns);
		KINETUM_LOG_DEBUG("dp", "dp.transition.timing",
				  "mutation_sequence={} from_epoch={} to_epoch={} duration_ns={}",
				  request->mutation_sequence(), result.observation.from_epoch,
				  result.observation.to_epoch, response->transition_duration_ns());
	}
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

grpc::Status dataplane_control_service::AbortPreparedConfigSnapshot(
	grpc::ServerContext *, const kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest *request,
	kinetum::dataplane::v1::AbortPreparedConfigSnapshotResponse *response)
try {
	if (request == nullptr || response == nullptr) {
		return null_request_or_response();
	}
	response->Clear();
	KINETUM_LOG_INFO("dp", "dp.abort.requested", "mutation_sequence={} target_epoch={}",
			 request->mutation_sequence(), request->epoch());
	const auto result = runtime_.abort_epoch_transition(*request);
	populate_transition_result(result, response);
	log_transition_result("abort", request->mutation_sequence(), request->epoch(), result);
	if (transition_observation_is_exact(result)) {
		response->set_mutation_sequence(result.observation.identity.mutation_sequence);
	}
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

grpc::Status dataplane_control_service::GetEpochTransitionStatus(
	grpc::ServerContext *, const kinetum::dataplane::v1::GetEpochTransitionStatusRequest *request,
	kinetum::dataplane::v1::GetEpochTransitionStatusResponse *response)
try {
	if (request == nullptr || response == nullptr) {
		return null_request_or_response();
	}
	response->Clear();
	const auto result = runtime_.query_epoch_transition(*request);
	populate_transition_result(result, response);
	if (!transition_observation_is_exact(result)) {
		return grpc::Status::OK;
	}
	const auto &observation = result.observation;
	response->set_from_epoch(observation.from_epoch);
	response->set_to_epoch(observation.to_epoch);
	response->set_validation_hash(reinterpret_cast<const char *>(observation.identity.validation_hash.data()),
				      observation.identity.validation_hash.size());
	const auto plan_content_hash = runtime_.transition_plan_content_hash();
	response->set_plan_content_hash(plan_content_hash.data(), plan_content_hash.size());
	response->set_mutation_sequence(observation.identity.mutation_sequence);
	if ((observation.duration_presence & TRANSITION_PREPARE_DURATION_PRESENT) != 0u) {
		response->set_prepare_duration_ns(observation.prepare_duration_ns);
	}
	if ((observation.duration_presence & TRANSITION_COMMIT_DURATION_PRESENT) != 0u) {
		response->set_commit_duration_ns(observation.commit_duration_ns);
	}
	if ((observation.duration_presence & TRANSITION_RETIREMENT_DURATION_PRESENT) != 0u) {
		response->set_retirement_duration_ns(observation.retirement_duration_ns);
	}
	const auto diagnostic = transition_diagnostic(observation);
	if (!diagnostic.empty()) {
		response->set_failure_reason(diagnostic.data(), diagnostic.size());
	}
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

grpc::Status dataplane_control_service::GetStats(grpc::ServerContext *,
						 const kinetum::dataplane::v1::StatsRequest *request,
						 kinetum::dataplane::v1::StatsResponse *response)
try {
	if (request == nullptr || response == nullptr) {
		return null_request_or_response();
	}
	response->Clear();
	const auto selection_status = common::validate_dataplane_stats_request(*request);
	if (!selection_status.is_ok()) {
		set_application_status(selection_status, response->mutable_status());
		return grpc::Status::OK;
	}
	const auto &selection = request->selection();
	runtime_telemetry_request internal{
		.include_stage_stats = selection.include_stage_stats(),
		.include_module_metrics = selection.include_module_metrics(),
		.include_module_health = selection.include_module_health(),
		.include_worker_epoch_stats = selection.include_worker_epoch_stats(),
		.include_region_epoch_stats = selection.include_region_epoch_stats(),
		.include_boundary_epoch_stats = selection.include_boundary_epoch_stats(),
		.include_stream_stats = selection.include_stream_stats(),
		.include_storage_domain_stats = selection.include_storage_domain_stats(),
		.include_port_stats = selection.include_port_stats(),
		.include_topology_stats = selection.include_topology_stats(),
	};
	auto snapshot_or = runtime_.collect_runtime_telemetry(internal);
	if (!snapshot_or.is_ok()) {
		set_application_status(snapshot_or.error(), response->mutable_status());
		return grpc::Status::OK;
	}
	auto mapped = populate_runtime_telemetry_wire(snapshot_or.value(), selection, response->mutable_telemetry());
	if (!mapped.is_ok()) {
		response->Clear();
		set_application_status(mapped, response->mutable_status());
		return grpc::Status::OK;
	}
	set_application_success(response->mutable_status());
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

grpc::Status dataplane_control_service::Health(grpc::ServerContext *,
					       const kinetum::dataplane::v1::HealthRequest *request,
					       kinetum::dataplane::v1::HealthResponse *response)
try {
	if (request == nullptr || response == nullptr) {
		return null_request_or_response();
	}
	response->Clear();
	response->set_version(kinetum::common::KINETUM_VERSION_STRING);
	kinetum::common::project_process_logging_status(*response->mutable_logging());
	const auto request_unknown =
		kinetum::common::reject_unknown_protobuf_fields_recursive(*request, "HealthRequest");
	const auto request_enums =
		kinetum::common::reject_invalid_protobuf_enum_values_recursive(*request, "HealthRequest");
	if (!request_unknown.is_ok() || !request_enums.is_ok()) {
		response->set_state(kinetum::dataplane::v1::HealthResponse::STATE_ERROR);
		set_application_status(!request_unknown.is_ok() ? request_unknown : request_enums,
				       response->mutable_status());
		return grpc::Status::OK;
	}

	runtime_status_snapshot observed{};
	const auto read = runtime_.status_publication().try_read(observed);
	if (read != publication_read_result::AVAILABLE) {
		response->set_state(kinetum::dataplane::v1::HealthResponse::STATE_ERROR);
		set_application_status(
			read == publication_read_result::UNAVAILABLE ?
				common::status::unavailable(
					"coherent packet-runtime status is temporarily unavailable") :
				common::status::data_loss("packet-runtime status publication is invalid"),
			response->mutable_status());
		return grpc::Status::OK;
	}

	set_application_success(response->mutable_status());
	response->set_active_epoch(observed.last_activated_epoch);
	response->set_active_workers(observed.active_workers);
	response->set_expected_workers(observed.expected_workers);
	response->set_runtime_generation(observed.runtime_generation);
	response->set_state(observed.readiness == runtime_readiness::PACKET_READY ?
				    kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY :
				    kinetum::dataplane::v1::HealthResponse::STATE_CONTROL_READY);
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

grpc::Status dataplane_control_service::Drain(grpc::ServerContext *,
					      const kinetum::dataplane::v1::DrainRequest *request,
					      kinetum::dataplane::v1::DrainResponse *response)
{
	return reject_runtime_lifecycle(request, response);
}

grpc::Status dataplane_control_service::DrainStatus(grpc::ServerContext *,
						    const kinetum::dataplane::v1::DrainStatusRequest *request,
						    kinetum::dataplane::v1::DrainStatusResponse *response)
{
	return reject_runtime_lifecycle(request, response);
}

grpc::Status dataplane_control_service::Shutdown(grpc::ServerContext *,
						 const kinetum::dataplane::v1::ShutdownRequest *request,
						 kinetum::dataplane::v1::ShutdownResponse *response)
{
	return reject_runtime_lifecycle(request, response);
}

grpc::Status dataplane_control_service::DumpState(grpc::ServerContext *,
						  const kinetum::dataplane::v1::DumpStateRequest *request,
						  kinetum::dataplane::v1::DumpStateResponse *response)
{
	return reject_runtime_lifecycle(request, response);
}

}  // namespace kinetum::dp
