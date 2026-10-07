// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file cp_grpc.cpp
 * @brief Implementation of Control Plane gRPC service.
 * @author Fleming Patel
 *
 * This file implements the ControlService gRPC interface, providing configuration
 * management with epoch-consistent updates, exact observation, and guardrails.
 *
 * @par Architecture Overview
 * - Mutation RPCs first require a running control-loop authority
 * - Admitted mutation RPCs translate wire requests into control_loop mutations
 * - The shared control_loop owns mutation ordering and published state
 * - Reads use config_store, control_loop state, or the DP stats backchannel
 * - Guardrails policy updates are published through the control_loop-owned RCU buffer
 *
 * @par Error Handling Strategy
 * - Ordinary non-null RPC calls return errors via response.status
 * - Those calls return gRPC OK; application errors use response.status.code
 * - A null response is a transport INVALID_ARGUMENT programming error
 * - Response construction exhaustion is transport UNAVAILABLE with no
 *   authoritative partial payload; unexpected boundary exceptions terminate
 * - This enables rich error details and consistent error handling across languages
 *
 * @par Current Snapshot/Epoch Admission Flow
 * Packet-ready production admits SetConfigSnapshot through one durable typed
 * transaction. Control-only production keeps the same loop stopped and rejects
 * before mutation construction:
 *
 * @code
 *   Client -> SetConfigSnapshot(snap) -> ControlService
 *       -> control_loop.submit(set_config_payload)
 *       -> validate snapshot and commit-confirmed preconditions
 *       -> canonical corpus staging + atomic epoch/mutation allocation
 *       -> DP Status/Prepare -> durable PREPARED
 *       -> durable COMPLETION_PENDING -> DP Activate/Status
 *       -> exact terminal COMPLETE -> atomic active-content promotion
 * @endcode
 *
 * @see cp_grpc.hpp For the public interface documentation
 * @see config_store For snapshot persistence
 * @see guardrails_runner For automatic rollback monitoring
 *
 */

#include "src/cp/cp_grpc.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "src/common/application_status.hpp"
#include "src/common/control_plane_contract.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/log.hpp"
#include "src/common/runtime_telemetry_contract.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/time.hpp"
#include "src/common/version.hpp"
#include "src/common/logging_status.hpp"
#include "src/cp/guardrails_policy.hpp"
#include "src/cp/runtime_authority_fence.hpp"

namespace kinetum::cp
{

/** @brief Maximum diagnostic bytes relayed from a failed DP stats call. */
static constexpr std::size_t MAX_STATS_FAILURE_MESSAGE_BYTES = 512u;

/**
 * @brief Populate one canonical embedded application status.
 * @param source Exact platform status.
 * @param[out] target Caller-owned wire status. Must not be null.
 */
static void set_application_status(const kinetum::common::status &source, kinetum::common::v1::Status *target)
{
	target->Clear();
	target->set_code(static_cast<int32_t>(source.code()));
	target->set_error_code(kinetum::common::application_error_code(source.code()));
	const auto message = source.message();
	const auto details = source.details();
	target->set_message(message.empty() ? "" : message.data(), message.size());
	target->set_details(details.empty() ? "" : details.data(), details.size());
}

/**
 * @brief Return retryable transport ambiguity when no response can be represented.
 * @param operation Calling handler or adapter whose response could not be constructed.
 * @return gRPC UNAVAILABLE without a partial application response.
 */
static grpc::Status response_construction_unavailable(std::string_view operation) noexcept
{
	KINETUM_LOG_ERROR("cp", "cp.response.unavailable", "operation={} response construction exhausted storage",
			  operation);
	// The log carries the diagnostic; allocation failure must not allocate another message.
	return grpc::Status(grpc::StatusCode::UNAVAILABLE, {});
}

/**
 * @brief Return the existing transport result and record a non-success mutation response.
 * @param operation Exact mutation RPC name.
 * @param snapshot Requested snapshot identity; empty for a policy request.
 * @param status Completed application result, including queue/admission failures.
 * @return Transport OK; application status remains the sole outcome authority.
 */
static grpc::Status mutation_response(std::string_view operation, std::string_view snapshot,
				      const kinetum::common::v1::Status &status)
{
	if (status.code() != static_cast<int32_t>(common::status_code::OK)) {
		KINETUM_LOG_WARN("cp", "cp.mutation.response",
				 "operation={} snapshot={} status={} reason={} details={}", operation, snapshot,
				 common::status_code_name(static_cast<common::status_code>(status.code())),
				 status.message(), status.details());
	}
	return grpc::Status::OK;
}

/**
 * @brief Set one bounded aggregate application failure.
 *
 * @param response Destination response cleared before status publication.
 * @param code Exact nonzero numeric status code.
 * @param error_code Semantic classification selected or relayed by the caller.
 * @param message Diagnostic text, truncated to the aggregate bound.
 */
static void set_stats_failure(kinetum::control::v1::StatsResponse *response, int32_t code,
			      kinetum::common::v1::ErrorCode error_code, std::string_view message)
{
	response->Clear();
	auto *status = response->mutable_status();
	status->set_code(code);
	status->set_error_code(error_code);
	const auto size = std::min(message.size(), MAX_STATS_FAILURE_MESSAGE_BYTES);
	status->set_message(size == 0u ? "" : message.data(), size);
}

/**
 * @brief Map one successful DP observation and coherent CP state into an aggregate response.
 *
 * The caller classifies transport and application status before invoking this
 * helper. The destination is caller-owned and initially empty.
 *
 * @param cp_state Coherent Control Plane publication.
 * @param active_authority Exact durable active snapshot and epoch authority.
 * @param dp_response Successful Data Plane observation.
 * @param response Empty aggregate response to populate.
 * @return OK after one exact aggregate mapping; DATA_LOSS on contradiction.
 */
static kinetum::common::status map_successful_stats(const cp_published_state &cp_state,
						    const durable_active_runtime_view &active_authority,
						    const kinetum::dataplane::v1::StatsResponse &dp_response,
						    kinetum::control::v1::StatsResponse *response)
{
	if (response == nullptr || !dp_response.has_telemetry() || cp_state.snapshot_id.empty() ||
	    active_authority.snapshot_id != cp_state.snapshot_id || active_authority.revision != cp_state.revision ||
	    !dp_response.telemetry().has_runtime() ||
	    active_authority.active_epoch != dp_response.telemetry().transition().active_epoch()) {
		return kinetum::common::status::data_loss(
			"Control Plane active configuration and runtime telemetry identity disagree");
	}
	auto *active = response->mutable_active_config();
	active->set_revision(cp_state.revision);
	active->set_snapshot_id(cp_state.snapshot_id);
	response->mutable_telemetry()->CopyFrom(dp_response.telemetry());
	return kinetum::common::status::ok();
}

/**
 * @brief Enforce the mutation-authority boundary before mutation materialization.
 *
 * A stopped control loop is a deliberate fail-closed state: the handler must
 * not construct a mutation, resolve durable retry identity, write persistent
 * configuration, or contact the Data Plane.
 *
 * @param loop Shared mutation authority queried for readiness.
 * @param status Application response status populated on rejection. Must not be null.
 * @return true when mutation construction may proceed; false after populating
 *         @p status with `UNAVAILABLE`.
 *
 * @par Thread Safety
 * Calls the atomic `control_loop::is_running()` query and writes only
 * caller-owned response memory.
 */
[[nodiscard]] static bool require_mutation_authority(const control_loop &loop, kinetum::common::v1::Status *status)
{
	if (loop.is_running()) {
		return true;
	}

	set_application_status(
		kinetum::common::status::unavailable(
			"Control Plane is control-ready; packet configuration mutations are unavailable"),
		status);
	return false;
}

/**
 * @brief Validate one complete Control Plane request message shape.
 * @param request Candidate generated request.
 * @param name Stable message name used only in diagnostics.
 * @return OK only when recursive unknown fields and enum values are absent.
 */
[[nodiscard]] static kinetum::common::status validate_control_request(const google::protobuf::Message &request,
								      std::string_view name)
{
	auto unknown = kinetum::common::reject_unknown_protobuf_fields_recursive(request, name);
	if (!unknown.is_ok()) {
		return unknown;
	}
	return kinetum::common::reject_invalid_protobuf_enum_values_recursive(request, name);
}

/**
 * @brief Validate an optional exact revision at the RPC admission boundary.
 * @param present Whether the proto3 optional field was authored.
 * @param revision Candidate value when present.
 * @return OK for absence or one exact bounded revision.
 */
[[nodiscard]] static kinetum::common::status validate_optional_revision(bool present, int64_t revision)
{
	return !present || kinetum::common::valid_config_snapshot_revision(revision) ?
		       kinetum::common::status::ok() :
		       kinetum::common::status::invalid_argument("expected_revision is outside the exact domain");
}

// =============================================================================
// Construction
// =============================================================================

control_service_impl::control_service_impl(config_store *store,
					   std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> dp_stub,
					   control_loop &loop)
	: store_(store)
	, dp_(std::move(dp_stub))
	, loop_(loop)
{
	// The single shared control_loop is injected from cp_main, ensuring one
	// mutation authority for the entire CP. The runner consumes the loop's RCU
	// policy projection; read RPCs consume the durable store directly.
}

// =============================================================================
// Configuration Snapshot Operations
// =============================================================================

// Validate the complete request before constructing the single-writer mutation.
grpc::Status control_service_impl::SetConfigSnapshot(grpc::ServerContext *context,
						     const kinetum::control::v1::SetConfigSnapshotRequest *request,
						     kinetum::control::v1::SetConfigSnapshotResponse *response)
try {
	(void)context;
	// Null pointer safety checks
	if (!request || !response) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
	}
	response->Clear();
	if (!require_mutation_authority(loop_, response->mutable_status())) {
		return mutation_response(__func__, request->snapshot().snapshot_id(), response->status());
	}
	const auto request_shape = validate_control_request(*request, "SetConfigSnapshotRequest");
	if (!request_shape.is_ok()) {
		set_application_status(request_shape, response->mutable_status());
		return mutation_response(__func__, request->snapshot().snapshot_id(), response->status());
	}
	if (!request->has_snapshot()) {
		set_application_status(
			kinetum::common::status::invalid_argument("SetConfigSnapshot snapshot presence is required"),
			response->mutable_status());
		return mutation_response(__func__, request->snapshot().snapshot_id(), response->status());
	}
	const auto key_status = kinetum::common::validate_transition_idempotency_key(request->idempotency_key());
	if (!key_status.is_ok()) {
		set_application_status(key_status, response->mutable_status());
		return mutation_response(__func__, request->snapshot().snapshot_id(), response->status());
	}
	const auto revision_status =
		validate_optional_revision(request->has_expected_revision(), request->expected_revision());
	if (!revision_status.is_ok()) {
		set_application_status(revision_status, response->mutable_status());
		return mutation_response(__func__, request->snapshot().snapshot_id(), response->status());
	}
	if (request->confirm_timeout_ms() > std::numeric_limits<uint32_t>::max()) {
		set_application_status(
			kinetum::common::status::invalid_argument("confirm_timeout_ms exceeds maximum supported value"),
			response->mutable_status());
		return mutation_response(__func__, request->snapshot().snapshot_id(), response->status());
	}

	std::optional<int64_t> expected_revision;
	if (request->has_expected_revision()) {
		expected_revision = request->expected_revision();
	}
	mutation m(request->idempotency_key(), expected_revision,
		   set_config_payload{request->snapshot(), static_cast<uint32_t>(request->confirm_timeout_ms())});
	KINETUM_LOG_INFO("cp", "cp.snapshot.requested", "snapshot={} revision={} confirm_timeout_ms={}",
			 request->snapshot().snapshot_id(), request->snapshot().revision(),
			 request->confirm_timeout_ms());

	// Submit to the control loop and wait for its exact result.
	const auto result = loop_.submit(std::move(m));

	// Map result to response
	set_application_status(result.status, response->mutable_status());

	if (result.ok()) {
		response->set_snapshot_id(result.snapshot_id);
		response->set_revision(result.revision);
		response->set_epoch(result.epoch);
	}

	return mutation_response(__func__, request->snapshot().snapshot_id(), response->status());
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

// Active identity comes only from the store's atomic listing authority.
grpc::Status control_service_impl::ListSnapshots(grpc::ServerContext *context,
						 const kinetum::control::v1::ListSnapshotsRequest *request,
						 kinetum::control::v1::ListSnapshotsResponse *response)
try {
	(void)context;
	if (request == nullptr || response == nullptr) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
	}
	response->Clear();
	const auto request_shape = validate_control_request(*request, "ListSnapshotsRequest");
	if (!request_shape.is_ok()) {
		set_application_status(request_shape, response->mutable_status());
		return grpc::Status::OK;
	}
	if (request->page_size() == 0u || request->page_size() > kinetum::common::MAX_SNAPSHOT_LIST_PAGE_SIZE ||
	    request->page_token().size() > kinetum::common::MAX_SNAPSHOT_LIST_PAGE_TOKEN_BYTES) {
		set_application_status(kinetum::common::status::invalid_argument(
					       "ListSnapshots page size or token is outside the bounded contract"),
				       response->mutable_status());
		return grpc::Status::OK;
	}

	const auto page_or = store_->list_snapshot_page(request->page_size(), request->page_token());
	if (!page_or.is_ok()) {
		set_application_status(page_or.error(), response->mutable_status());
		return grpc::Status::OK;
	}

	response->mutable_snapshots()->Reserve(static_cast<int>(page_or->snapshots.size()));
	for (const auto &info : page_or->snapshots) {
		response->add_snapshots()->CopyFrom(info);
	}
	response->set_next_page_token(page_or->next_page_token);
	response->set_total_count(page_or->total_count);
	set_application_status(kinetum::common::status::ok(), response->mutable_status());
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

// Copy active content under one coherent store read.
grpc::Status control_service_impl::GetActiveSnapshot(grpc::ServerContext *context,
						     const kinetum::control::v1::GetActiveSnapshotRequest *request,
						     kinetum::control::v1::GetActiveSnapshotResponse *response)
try {
	(void)context;
	if (request == nullptr || response == nullptr) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
	}
	response->Clear();
	const auto request_shape = validate_control_request(*request, "GetActiveSnapshotRequest");
	if (!request_shape.is_ok()) {
		set_application_status(request_shape, response->mutable_status());
		return grpc::Status::OK;
	}

	const auto snap_or = store_->active_snapshot();
	if (!snap_or.is_ok()) {
		set_application_status(snap_or.error(), response->mutable_status());
		return grpc::Status::OK;
	}

	set_application_status(kinetum::common::status::ok(), response->mutable_status());
	*response->mutable_snapshot() = snap_or.value();
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

// Admit selective membership before transferring one rollback mutation.
grpc::Status control_service_impl::Rollback(grpc::ServerContext *context,
					    const kinetum::control::v1::RollbackRequest *request,
					    kinetum::control::v1::RollbackResponse *response)
try {
	(void)context;
	// Null pointer safety checks
	if (!request || !response) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
	}
	response->Clear();
	if (!require_mutation_authority(loop_, response->mutable_status())) {
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	const auto request_shape = validate_control_request(*request, "RollbackRequest");
	if (!request_shape.is_ok()) {
		set_application_status(request_shape, response->mutable_status());
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	if (!kinetum::common::valid_config_snapshot_id(request->snapshot_id())) {
		set_application_status(
			kinetum::common::status::invalid_argument("Rollback snapshot identity is malformed"),
			response->mutable_status());
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	const auto key_status = kinetum::common::validate_transition_idempotency_key(request->idempotency_key());
	if (!key_status.is_ok()) {
		set_application_status(key_status, response->mutable_status());
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	const auto revision_status =
		validate_optional_revision(request->has_expected_revision(), request->expected_revision());
	if (!revision_status.is_ok()) {
		set_application_status(revision_status, response->mutable_status());
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	try {
		std::set<std::string_view> unique_modules;
		for (const auto &module_id : request->module_ids()) {
			if (module_id.empty() || !unique_modules.insert(module_id).second) {
				set_application_status(
					kinetum::common::status::invalid_argument(
						"Rollback module identities must be nonempty and unique"),
					response->mutable_status());
				return mutation_response(__func__, request->snapshot_id(), response->status());
			}
		}
	} catch (const std::bad_alloc &) {
		set_application_status(
			kinetum::common::status::resource_exhausted("Rollback identity validation exhausted memory"),
			response->mutable_status());
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	std::optional<int64_t> expected_revision;
	if (request->has_expected_revision()) {
		expected_revision = request->expected_revision();
	}

	// Build rollback payload
	rollback_payload p;
	p.target_snapshot_id = request->snapshot_id();
	for (const auto &mod_id : request->module_ids()) {
		p.module_ids.push_back(mod_id);
	}
	mutation m(request->idempotency_key(), expected_revision, std::move(p));
	KINETUM_LOG_INFO("cp", "cp.rollback.requested", "target_snapshot={} selective_module_count={}",
			 request->snapshot_id(), request->module_ids_size());

	// Submit to the control loop and wait for its exact result.
	const auto result = loop_.submit(std::move(m));

	// Map result to response
	set_application_status(result.status, response->mutable_status());

	if (result.ok()) {
		response->set_new_snapshot_id(result.snapshot_id);
		response->set_new_revision(result.revision);
		response->set_epoch(result.epoch);
	}

	return mutation_response(__func__, request->snapshot_id(), response->status());
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

// =============================================================================
// Commit-Confirmed Pattern
// =============================================================================

// The header owns the RPC contract; this definition only maps wire identity to
// the single-writer mutation and clears non-success payload fields.
grpc::Status control_service_impl::ConfirmConfig(grpc::ServerContext *context,
						 const kinetum::control::v1::ConfirmConfigRequest *request,
						 kinetum::control::v1::ConfirmConfigResponse *response)
try {
	(void)context;
	// Null pointer safety checks
	if (!request || !response) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
	}
	response->Clear();
	if (!require_mutation_authority(loop_, response->mutable_status())) {
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	const auto request_shape = validate_control_request(*request, "ConfirmConfigRequest");
	if (!request_shape.is_ok()) {
		set_application_status(request_shape, response->mutable_status());
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	if (!request->has_revision()) {
		set_application_status(
			kinetum::common::status::invalid_argument("ConfirmConfig revision presence is required"),
			response->mutable_status());
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	const auto key_status = kinetum::common::validate_transition_idempotency_key(request->idempotency_key());
	if (!key_status.is_ok()) {
		set_application_status(key_status, response->mutable_status());
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}
	if (!kinetum::common::valid_config_snapshot_id(request->snapshot_id()) ||
	    !kinetum::common::valid_epoch_id(request->epoch()) ||
	    !kinetum::common::valid_config_snapshot_revision(request->revision())) {
		set_application_status(kinetum::common::status::invalid_argument("ConfirmConfig identity is malformed"),
				       response->mutable_status());
		return mutation_response(__func__, request->snapshot_id(), response->status());
	}

	mutation m(request->idempotency_key(), std::nullopt,
		   confirm_config_payload{request->snapshot_id(), request->epoch(), request->revision()});
	KINETUM_LOG_INFO("cp", "cp.confirm.requested", "snapshot={} revision={} epoch={}", request->snapshot_id(),
			 request->revision(), request->epoch());

	// Submit to the control loop and wait for its exact result.
	const auto result = loop_.submit(std::move(m));

	// Map result to response
	set_application_status(result.status, response->mutable_status());

	if (result.ok()) {
		response->set_snapshot_id(result.snapshot_id);
		response->set_time_remaining_ms(
			result.time_remaining_ms > 0 ? static_cast<uint64_t>(result.time_remaining_ms) : 0);
		response->set_epoch(result.epoch);
		response->set_revision(result.revision);
		KINETUM_LOG_INFO("cp", "cp.confirm.completed", "snapshot={} revision={} epoch={}", result.snapshot_id,
				 result.revision, result.epoch);
	}

	return mutation_response(__func__, request->snapshot_id(), response->status());
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

// =============================================================================
// Guardrails Operations
// =============================================================================

// A stopped control-only authority rejects before policy work; otherwise the
// complete request enters the sole mutation writer after shared validation.
grpc::Status control_service_impl::ConfigureGuardrails(grpc::ServerContext *context,
						       const kinetum::control::v1::ConfigureGuardrailsRequest *request,
						       kinetum::control::v1::ConfigureGuardrailsResponse *response)
try {
	(void)context;
	// Null pointer safety checks
	if (!request || !response) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
	}
	response->Clear();
	if (!require_mutation_authority(loop_, response->mutable_status())) {
		return mutation_response(__func__, {}, response->status());
	}
	const auto request_shape = validate_control_request(*request, "ConfigureGuardrailsRequest");
	if (!request_shape.is_ok()) {
		set_application_status(request_shape, response->mutable_status());
		return mutation_response(__func__, {}, response->status());
	}

	if (!request->has_policy() || !request->has_expected_policy_generation()) {
		set_application_status(kinetum::common::status::invalid_argument(
					       "GuardrailsPolicy and expected policy generation presence are required"),
				       response->mutable_status());
		return mutation_response(__func__, {}, response->status());
	}
	const auto key_status = kinetum::common::validate_transition_idempotency_key(request->idempotency_key());
	if (!key_status.is_ok()) {
		set_application_status(key_status, response->mutable_status());
		return mutation_response(__func__, {}, response->status());
	}
	const auto &policy = request->policy();

	// -------------------------------------------------------------------------
	// Strict Validation (shared with startup path - single authority)
	// -------------------------------------------------------------------------
	const auto validate_status = validate_guardrails_policy(policy);
	if (!validate_status.is_ok()) {
		set_application_status(validate_status, response->mutable_status());
		return mutation_response(__func__, {}, response->status());
	}
	mutation m(request->idempotency_key(), std::nullopt,
		   set_guardrails_policy_payload{policy, request->expected_policy_generation()});
	KINETUM_LOG_INFO("cp", "cp.guardrails.requested", "expected_generation={}",
			 request->expected_policy_generation());

	const auto result = loop_.submit(std::move(m));

	set_application_status(result.status, response->mutable_status());

	if (result.ok()) {
		response->set_policy_generation(result.policy_generation);
		response->set_policy_hash(reinterpret_cast<const char *>(result.policy_hash.data()),
					  result.policy_hash.size());
		KINETUM_LOG_INFO("cp", "cp.guardrails.configured", "generation={}", result.policy_generation);
	}
	return mutation_response(__func__, {}, response->status());
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

// =============================================================================
// Monitoring and Statistics
// =============================================================================

grpc::Status control_service_impl::GetStats(grpc::ServerContext *context,
					    const kinetum::control::v1::StatsRequest *request,
					    kinetum::control::v1::StatsResponse *response)
try {
	if (context == nullptr || request == nullptr || response == nullptr) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null context, request, or response");
	}
	response->Clear();
	const auto selection_status = kinetum::common::validate_control_stats_request(*request);
	if (!selection_status.is_ok()) {
		set_application_status(selection_status, response->mutable_status());
		return grpc::Status::OK;
	}
	const auto cp_state_before = loop_.published_state();
	auto active_before_or = store_->runtime_authority();
	if (!active_before_or.is_ok()) {
		const auto code = active_before_or.error().code() == kinetum::common::status_code::NOT_FOUND ?
					  kinetum::common::status_code::UNAVAILABLE :
					  active_before_or.error().code();
		set_stats_failure(response, static_cast<int32_t>(code), kinetum::common::application_error_code(code),
				  "Control Plane active configuration is unavailable");
		return grpc::Status::OK;
	}
	if (active_before_or->active.snapshot_id != cp_state_before.snapshot_id ||
	    active_before_or->active.revision != cp_state_before.revision) {
		set_stats_failure(response, static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE),
				  kinetum::common::v1::ERROR_CODE_UNAVAILABLE,
				  "Control Plane active configuration is not coherent");
		return grpc::Status::OK;
	}

	// ---------------------------------------------------------------------
	// Data Plane Statistics (via gRPC)
	// ---------------------------------------------------------------------
	kinetum::dataplane::v1::StatsRequest dataplane_request;
	dataplane_request.mutable_selection()->CopyFrom(request->selection());

	kinetum::dataplane::v1::StatsResponse dataplane_response;
	const auto now = std::chrono::system_clock::now();
	const auto deadline = std::min(context->deadline(), now + std::chrono::seconds(30));
	if (deadline <= now || context->IsCancelled()) {
		const auto code = deadline <= now ? common::status_code::DEADLINE_EXCEEDED :
						    common::status_code::CANCELLED;
		set_stats_failure(response, static_cast<int32_t>(code), common::application_error_code(code),
				  "Statistics caller deadline or cancellation ended the observation");
		return grpc::Status::OK;
	}
	auto dataplane_context = grpc::ClientContext::FromServerContext(*context);
	dataplane_context->set_deadline(deadline);
	if (dp_ == nullptr) {
		set_stats_failure(response, static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE),
				  kinetum::common::v1::ERROR_CODE_UNAVAILABLE,
				  "Data Plane statistics channel is unavailable");
		return grpc::Status::OK;
	}

	grpc::Status grpc_status;
	try {
		grpc_status = dp_->GetStats(dataplane_context.get(), dataplane_request, &dataplane_response);
	} catch (const std::bad_alloc &) {
		throw;
	} catch (const std::length_error &) {
		throw;
	} catch (const std::exception &e) {
		(void)e;
		set_stats_failure(response, static_cast<int32_t>(kinetum::common::status_code::INTERNAL_ERROR),
				  kinetum::common::v1::ERROR_CODE_INTERNAL,
				  "Data Plane statistics call raised an exception");
		return grpc::Status::OK;
	} catch (...) {
		set_stats_failure(response, static_cast<int32_t>(kinetum::common::status_code::INTERNAL_ERROR),
				  kinetum::common::v1::ERROR_CODE_INTERNAL,
				  "Data Plane statistics call raised an exception");
		return grpc::Status::OK;
	}

	if (!grpc_status.ok()) {
		common::status_code code{};
		if (!common::decode_application_status_code(static_cast<int32_t>(grpc_status.error_code()), code) ||
		    static_cast<int32_t>(code) > static_cast<int32_t>(common::status_code::UNAUTHENTICATED)) {
			code = common::status_code::DATA_LOSS;
		}
		set_stats_failure(response, static_cast<int32_t>(code), common::application_error_code(code),
				  grpc_status.error_message());
		return grpc::Status::OK;
	}

	const auto dataplane_application = map_dataplane_application_status(dataplane_response.status(),
									    "Data Plane statistics application failed");
	if (!dataplane_application.is_ok()) {
		const auto envelope = common::validate_failed_dataplane_stats_response(dataplane_response);
		if (!envelope.is_ok()) {
			const auto invalid = map_dataplane_response_validation_failure(
				envelope, "Data Plane returned a malformed statistics failure");
			set_stats_failure(response, static_cast<int32_t>(invalid.code()),
					  common::application_error_code(invalid.code()), invalid.message());
			return grpc::Status::OK;
		}
		set_stats_failure(response, static_cast<int32_t>(dataplane_application.code()),
				  kinetum::common::application_error_code(dataplane_application.code()),
				  dataplane_response.status().message());
		return grpc::Status::OK;
	}
	const auto telemetry_status =
		kinetum::common::validate_successful_dataplane_stats_response(dataplane_response, request->selection());
	if (!telemetry_status.is_ok()) {
		const auto mapped_failure = map_dataplane_response_validation_failure(
			telemetry_status, "Data Plane returned malformed runtime telemetry");
		set_stats_failure(response, static_cast<int32_t>(mapped_failure.code()),
				  kinetum::common::application_error_code(mapped_failure.code()),
				  mapped_failure.message());
		return grpc::Status::OK;
	}

	auto active_or = store_->runtime_authority();
	if (!active_or.is_ok()) {
		set_stats_failure(response, static_cast<int32_t>(active_or.error().code()),
				  kinetum::common::application_error_code(active_or.error().code()),
				  "Control Plane active statistics configuration is unavailable");
		return grpc::Status::OK;
	}
	const auto cp_state_after = loop_.published_state();
	const bool same_active = same_active_runtime_authority(active_before_or.value(), active_or.value());
	if (cp_state_before.revision != cp_state_after.revision ||
	    cp_state_before.snapshot_id != cp_state_after.snapshot_id || !same_active) {
		set_stats_failure(response, static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE),
				  kinetum::common::v1::ERROR_CODE_UNAVAILABLE,
				  "Control Plane active configuration changed during statistics collection");
		return grpc::Status::OK;
	}
	auto relation_or = classify_runtime_authority(active_or.value(), dataplane_response.telemetry());
	const auto &active_authority = active_or->active;
	if (active_authority.snapshot_id != cp_state_after.snapshot_id ||
	    active_authority.revision != cp_state_after.revision || !relation_or.is_ok()) {
		const auto code = relation_or.is_ok() ? kinetum::common::status_code::UNAVAILABLE :
							relation_or.error().code();
		set_stats_failure(response, static_cast<int32_t>(code), kinetum::common::application_error_code(code),
				  relation_or.is_ok() ? "Control Plane and Data Plane active truth has not converged" :
							relation_or.error().message());
		return grpc::Status::OK;
	}
	if (relation_or.value() != runtime_authority_relation::ACTIVE_EXACT) {
		set_stats_failure(response, static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE),
				  kinetum::common::v1::ERROR_CODE_UNAVAILABLE,
				  "Data Plane completion is awaiting durable Control Plane publication");
		return grpc::Status::OK;
	}
	auto mapped = map_successful_stats(cp_state_after, active_authority, dataplane_response, response);
	if (!mapped.is_ok()) {
		set_stats_failure(response, static_cast<int32_t>(mapped.code()),
				  kinetum::common::application_error_code(mapped.code()), mapped.message());
		return grpc::Status::OK;
	}
	set_application_status(kinetum::common::status::ok(), response->mutable_status());
	const auto aggregate_status =
		kinetum::common::validate_successful_control_stats_response(*response, request->selection());
	if (!aggregate_status.is_ok()) {
		const bool bounded_resource_failure =
			aggregate_status.code() == kinetum::common::status_code::RESOURCE_EXHAUSTED ||
			aggregate_status.code() == kinetum::common::status_code::OUT_OF_RANGE;
		const auto code = bounded_resource_failure ? aggregate_status.code() :
							     kinetum::common::status_code::DATA_LOSS;
		set_stats_failure(response, static_cast<int32_t>(code), kinetum::common::application_error_code(code),
				  bounded_resource_failure ?
					  aggregate_status.message() :
					  "Control Plane statistics aggregate failed final validation");
	}
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

// =============================================================================
// GetGuardrails Implementation
// =============================================================================

// Read the one durable policy record; unconfigured state is successful absence.
grpc::Status control_service_impl::GetGuardrails(grpc::ServerContext *context,
						 const kinetum::control::v1::GetGuardrailsRequest *request,
						 kinetum::control::v1::GetGuardrailsResponse *response)
try {
	(void)context;
	if (request == nullptr || response == nullptr) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
	}
	response->Clear();
	const auto request_shape = validate_control_request(*request, "GetGuardrailsRequest");
	if (!request_shape.is_ok()) {
		set_application_status(request_shape, response->mutable_status());
		return grpc::Status::OK;
	}
	auto policy_or = store_->guardrails_policy();
	if (!policy_or.is_ok()) {
		if (policy_or.error().code() == kinetum::common::status_code::NOT_FOUND) {
			set_application_status(kinetum::common::status::ok(), response->mutable_status());
			return grpc::Status::OK;
		}
		set_application_status(policy_or.error(), response->mutable_status());
		return grpc::Status::OK;
	}
	response->mutable_policy()->CopyFrom(policy_or->policy);
	response->set_policy_generation(policy_or->generation);
	response->set_policy_hash(reinterpret_cast<const char *>(policy_or->policy_hash.data()),
				  policy_or->policy_hash.size());
	set_application_status(kinetum::common::status::ok(), response->mutable_status());
	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

// =============================================================================
// HealthCheck Implementation
// =============================================================================

// SERVING describes this control surface, not packet-runtime readiness.
grpc::Status control_service_impl::HealthCheck(grpc::ServerContext *context,
					       const kinetum::control::v1::HealthCheckRequest *request,
					       kinetum::control::v1::HealthCheckResponse *response)
try {
	(void)context;
	if (request == nullptr || response == nullptr) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
	}
	response->Clear();
	const auto request_shape = validate_control_request(*request, "HealthCheckRequest");
	if (!request_shape.is_ok()) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, std::string(request_shape.message()));
	}

	// SERVING describes this gRPC control surface only. Mutation and packet
	// readiness have independent fail-closed admission gates.
	response->set_status(kinetum::control::v1::HealthCheckResponse::STATUS_SERVING);

	// Version information
	response->set_version(kinetum::common::KINETUM_VERSION_STRING);

	// Calculate uptime in seconds
	const auto now = std::chrono::steady_clock::now();
	const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);
	response->set_uptime_seconds(uptime.count());
	kinetum::common::project_process_logging_status(*response->mutable_logging());

	return grpc::Status::OK;
} catch (const std::bad_alloc &) {
	return response_construction_unavailable(__func__);
} catch (const std::length_error &) {
	return response_construction_unavailable(__func__);
} catch (...) {
	std::terminate();
}

}  // namespace kinetum::cp
