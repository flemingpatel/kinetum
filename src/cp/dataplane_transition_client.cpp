// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dataplane_transition_client.cpp
 * @brief Exact typed Data Plane transition-client implementation.
 * @author Fleming Patel
 */

#include "src/cp/dataplane_transition_client.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "src/common/application_status.hpp"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/cp/runtime_authority_fence.hpp"

namespace kinetum::cp
{
namespace
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;
/** Admitted local interpretation of an exact transition identity observation. */
using resolution = kinetum::common::transition_identity_resolution;
/** Wire identity-resolution values validated before local conversion. */
using wire_resolution = kinetum::dataplane::v1::EpochTransitionIdentityResolution;
/** Wire transition failure taxonomy admitted by this client. */
using wire_failure = kinetum::telemetry::v1::EpochTransitionFailureCode;
/** Wire transition lifecycle states admitted by this client. */
using wire_state = kinetum::telemetry::v1::EpochTransitionState;

/** @brief Maximum untrusted transition diagnostic retained by CP. */
constexpr std::size_t MAX_REMOTE_TRANSITION_DIAGNOSTIC_BYTES = kinetum::common::MAX_TRANSITION_DIAGNOSTIC_BYTES;

/**
 * @brief Derive one RPC deadline without crossing an enclosing steady bound.
 * @param configured_timeout Positive client-owned per-attempt timeout.
 * @param operation_deadline Optional enclosing steady deadline.
 * @return System-clock deadline for gRPC, or DEADLINE_EXCEEDED before any RPC.
 */
[[nodiscard]] status_or<std::chrono::system_clock::time_point>
rpc_deadline(std::chrono::milliseconds configured_timeout, std::chrono::steady_clock::time_point operation_deadline)
{
	auto permitted = std::chrono::duration_cast<std::chrono::steady_clock::duration>(configured_timeout);
	if (operation_deadline != std::chrono::steady_clock::time_point::max()) {
		const auto now = std::chrono::steady_clock::now();
		if (operation_deadline <= now) {
			return status::deadline_exceeded(
				"Data Plane transition operation deadline expired before transport");
		}
		permitted = std::min(permitted, operation_deadline - now);
	}
	return std::chrono::system_clock::now() +
	       std::chrono::duration_cast<std::chrono::system_clock::duration>(permitted);
}

/**
 * @brief Decode one public identity relation without accepting a sentinel.
 * @param value Candidate generated enum value.
 * @return Exact common relation or INVALID_ARGUMENT for unknown/UNSPECIFIED input.
 */
status_or<resolution> decode_resolution(wire_resolution value) noexcept
{
	switch (value) {
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_INVALID:
		return resolution::INVALID;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_ADMISSIBLE:
		return resolution::ADMISSIBLE;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_ACTIVE_EXACT:
		return resolution::ACTIVE_EXACT;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT:
		return resolution::TERMINAL_EXACT;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_STALE:
		return resolution::STALE;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_INCONSISTENT:
		return resolution::INCONSISTENT;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_EXPIRED_RETRY:
		return resolution::EXPIRED_RETRY;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_IDENTITY_CONFLICT:
		return resolution::IDENTITY_CONFLICT;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_UNKNOWN_FUTURE:
		return resolution::UNKNOWN_FUTURE;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_OVERLAP:
		return resolution::OVERLAP;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_POLICY_DISABLED:
		return resolution::POLICY_DISABLED;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_STATE_UNAVAILABLE:
		return resolution::STATE_UNAVAILABLE;
	case wire_resolution::EPOCH_TRANSITION_IDENTITY_RESOLUTION_UNSPECIFIED:
	case kinetum::dataplane::v1::EpochTransitionIdentityResolution_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::dataplane::v1::EpochTransitionIdentityResolution_INT_MAX_SENTINEL_DO_NOT_USE_:
		return status::invalid_argument(kinetum::common::static_status_text(
			"Data Plane transition identity resolution is unspecified or invalid"));
	}
	return status::invalid_argument(
		kinetum::common::static_status_text("Data Plane transition identity resolution is undeclared"));
}

/**
 * @brief Convert one failed gRPC attempt into a bounded observation failure.
 * @param transport Failed generated-stub transport result.
 * @return Exact canonical transport category with bounded diagnostic details
 *         that never select transition policy.
 */
status transport_failure(const grpc::Status &transport) noexcept
{
	status_code code{};
	if (!kinetum::common::decode_application_status_code(static_cast<int32_t>(transport.error_code()), code) ||
	    code == status_code::OK) {
		code = status_code::UNKNOWN;
	}
	try {
		status failure(code, "Data Plane transition transport did not complete");
		const std::string diagnostic = transport.error_message();
		failure.set_details(std::string(diagnostic.data(),
						std::min(diagnostic.size(), MAX_REMOTE_TRANSITION_DIAGNOSTIC_BYTES)));
		return failure;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(
			kinetum::common::static_status_text("Data Plane transition diagnostic exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "Data Plane transition diagnostic exceeded host size limits"));
	}
}

/**
 * @brief Populate one exact identity-only transition request.
 * @tparam request_type Generated Activate, Abort, or Status request type.
 * @param identity Durable fixed identity.
 * @param idempotency_key Exact printable key whose digest must match @p identity.
 * @param[out] request Cleared/default caller-owned request to populate.
 * @return OK after exact reconstruction, otherwise identity/grammar failure.
 */
template <typename request_type>
status populate_identity_request(const kinetum::common::epoch_transition_identity &identity,
				 std::string_view idempotency_key, request_type &request)
{
	try {
		auto exact_or = kinetum::common::make_epoch_transition_identity(
			identity.mutation_sequence, identity.target_epoch,
			std::string_view(reinterpret_cast<const char *>(identity.validation_hash.data()),
					 identity.validation_hash.size()),
			idempotency_key);
		if (!exact_or.is_ok()) {
			return exact_or.error();
		}
		if (exact_or.value() != identity) {
			return status::failed_precondition(
				"Data Plane transition key does not match durable exact identity");
		}
		request.set_epoch(identity.target_epoch);
		request.set_validation_hash(reinterpret_cast<const char *>(identity.validation_hash.data()),
					    identity.validation_hash.size());
		request.set_idempotency_key(idempotency_key.data(), idempotency_key.size());
		request.set_mutation_sequence(identity.mutation_sequence);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(
			kinetum::common::static_status_text("Data Plane transition request exhausted memory"));
	} catch (const std::length_error &) {
		return status(
			status_code::OUT_OF_RANGE,
			kinetum::common::static_status_text("Data Plane transition request exceeded host size limits"));
	}
}

/**
 * @brief Normalize fields shared by every transition response.
 * @tparam response_type Generated Prepare, Activate, Abort, or Status response.
 * @param response Complete transport-success response.
 * @param identity Exact caller-owned transaction identity.
 * @param contract_name Stable generated message name for diagnostics.
 * @return Typed normalized observation or exact malformed-wire failure.
 */
template <typename response_type>
status_or<dataplane_transition_observation> normalize_common(const response_type &response,
							     const kinetum::common::epoch_transition_identity &identity,
							     std::string_view contract_name)
{
	try {
		const auto unknown = kinetum::common::reject_unknown_protobuf_fields_recursive(response, contract_name);
		if (!unknown.is_ok()) {
			return map_dataplane_response_validation_failure(
				unknown, "Data Plane returned malformed transition response");
		}
		const auto enums =
			kinetum::common::reject_invalid_protobuf_enum_values_recursive(response, contract_name);
		if (!enums.is_ok()) {
			return map_dataplane_response_validation_failure(
				enums, "Data Plane returned malformed transition response");
		}
		status_code application_code{};
		if (!kinetum::common::decode_exact_application_status(response.status(), application_code) ||
		    !response.status().details().empty() ||
		    (application_code == status_code::OK && !response.status().message().empty()) ||
		    response.status().message().size() > MAX_REMOTE_TRANSITION_DIAGNOSTIC_BYTES) {
			return status::data_loss("Data Plane transition response has a malformed application status");
		}
		auto resolution_or = decode_resolution(response.identity_resolution());
		if (!resolution_or.is_ok()) {
			return status::data_loss(std::string(resolution_or.error().message()));
		}
		if (response.failure_code() == wire_failure::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED) {
			return status::data_loss("Data Plane transition response omitted its typed failure code");
		}
		const bool exact = resolution_or.value() == resolution::ACTIVE_EXACT ||
				   resolution_or.value() == resolution::TERMINAL_EXACT;
		if ((exact && response.transition_state() == wire_state::EPOCH_TRANSITION_STATE_UNSPECIFIED) ||
		    (!exact && response.transition_state() != wire_state::EPOCH_TRANSITION_STATE_UNSPECIFIED) ||
		    (!exact && response.failure_code() != wire_failure::EPOCH_TRANSITION_FAILURE_CODE_NONE) ||
		    (!exact && application_code == status_code::OK)) {
			return status::data_loss(
				"Data Plane transition response state disagrees with typed identity resolution");
		}
		dataplane_transition_observation observation;
		if (application_code != status_code::OK) {
			observation.application_status =
				status(application_code, response.status().message(), response.status().details());
		}
		observation.resolution = resolution_or.value();
		observation.state = response.transition_state();
		observation.failure_code = response.failure_code();
		if (exact) {
			observation.identity = identity;
		}
		return observation;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(
			kinetum::common::static_status_text("Data Plane transition response exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "Data Plane transition response exceeded host size limits"));
	}
}

/**
 * @brief Test whether one normalized response resolved the caller's identity.
 * @param observation Typed normalized observation.
 * @return true only for ACTIVE_EXACT or TERMINAL_EXACT.
 */
bool exact_observation(const dataplane_transition_observation &observation) noexcept
{
	return observation.resolution == resolution::ACTIVE_EXACT ||
	       observation.resolution == resolution::TERMINAL_EXACT;
}

/**
 * @brief Validate nonzero Status durations against their sole producing phase.
 * @param state Exact admitted active or terminal state.
 * @param prepare_ns Candidate prepare duration.
 * @param commit_ns Candidate commit duration.
 * @param retirement_ns Candidate retirement duration.
 * @return true only when no duration appears before its producing edge.
 */
bool status_durations_are_qualified(wire_state state, uint64_t prepare_ns, uint64_t commit_ns,
				    uint64_t retirement_ns) noexcept
{
	switch (state) {
	case wire_state::EPOCH_TRANSITION_STATE_UNSPECIFIED:
	case wire_state::EPOCH_TRANSITION_STATE_AWAITING_BOOTSTRAP:
	case wire_state::EPOCH_TRANSITION_STATE_BOOTSTRAPPING:
	case wire_state::EPOCH_TRANSITION_STATE_PREPARING:
		return prepare_ns == 0u && commit_ns == 0u && retirement_ns == 0u;
	case wire_state::EPOCH_TRANSITION_STATE_PREPARED:
	case wire_state::EPOCH_TRANSITION_STATE_COMMITTING:
	case wire_state::EPOCH_TRANSITION_STATE_ABORTED:
		return commit_ns == 0u && retirement_ns == 0u;
	case wire_state::EPOCH_TRANSITION_STATE_RETIRING:
	case wire_state::EPOCH_TRANSITION_STATE_FAILED_STOP:
		return retirement_ns == 0u;
	case wire_state::EPOCH_TRANSITION_STATE_COMPLETE:
		return true;
	case wire_state::EPOCH_TRANSITION_STATE_IDLE:
		return false;
	case kinetum::telemetry::v1::EpochTransitionState_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::telemetry::v1::EpochTransitionState_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

}  // namespace

status_or<std::unique_ptr<dataplane_transition_client>>
dataplane_transition_client::create(std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> stub,
				    std::chrono::milliseconds timeout)
{
	if (stub == nullptr || timeout <= std::chrono::milliseconds::zero() ||
	    timeout > DATAPLANE_TRANSITION_RPC_TIMEOUT) {
		return status::invalid_argument(
			"Data Plane transition client requires one stub and a timeout in (0, 5000] ms");
	}
	try {
		return std::unique_ptr<dataplane_transition_client>(
			new dataplane_transition_client(std::move(stub), timeout));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate Data Plane transition client");
	}
}

dataplane_transition_client::dataplane_transition_client(
	std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> stub,
	std::chrono::milliseconds timeout) noexcept
	: stub_(std::move(stub))
	, timeout_(timeout)
{
}

status_or<dataplane_transition_observation>
dataplane_transition_client::prepare(const kinetum::dataplane::v1::PrepareConfigSnapshotRequest &request,
				     const kinetum::common::epoch_transition_identity &identity,
				     std::chrono::steady_clock::time_point operation_deadline) const
{
	auto request_identity_or = kinetum::common::make_epoch_transition_identity(
		request.mutation_sequence(), request.target_epoch(),
		std::string_view(reinterpret_cast<const char *>(identity.validation_hash.data()),
				 identity.validation_hash.size()),
		request.idempotency_key());
	auto snapshot_hash_or = kinetum::common::decode_sha256_digest_claim(
		request.snapshot().content_hash(), "PrepareConfigSnapshotRequest.snapshot.content_hash");
	if (!request_identity_or.is_ok() || !snapshot_hash_or.is_ok() || request_identity_or.value() != identity ||
	    snapshot_hash_or.value() != identity.validation_hash) {
		return status::failed_precondition(
			"durable Prepare request does not match its exact transition identity");
	}
	auto deadline_or = rpc_deadline(timeout_, operation_deadline);
	if (!deadline_or.is_ok()) {
		return deadline_or.error();
	}
	grpc::ClientContext context;
	context.set_deadline(deadline_or.value());
	kinetum::dataplane::v1::PrepareConfigSnapshotResponse response;
	grpc::Status transport;
	try {
		transport = stub_->PrepareConfigSnapshot(&context, request, &response);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane Prepare call exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane Prepare call exceeded host size limits");
	} catch (const std::exception &) {
		return status::internal_error("Data Plane Prepare call raised an exception");
	} catch (...) {
		return status::internal_error("Data Plane Prepare call raised a non-standard exception");
	}
	if (!transport.ok()) {
		return transport_failure(transport);
	}
	auto normalized_or = normalize_common(response, identity, "PrepareConfigSnapshotResponse");
	if (!normalized_or.is_ok()) {
		return normalized_or.error();
	}
	auto normalized = std::move(normalized_or).value();
	if (exact_observation(normalized)) {
		if (!normalized.application_status.is_ok()) {
			return status::data_loss("Data Plane exact Prepare observation carried application failure");
		}
		if (response.mutation_sequence() != identity.mutation_sequence) {
			return status::data_loss("Data Plane Prepare response mutation identity is inexact");
		}
		if (normalized.state == wire_state::EPOCH_TRANSITION_STATE_PREPARED) {
			const bool exact_hash =
				response.validation_hash().size() == identity.validation_hash.size() &&
				std::equal(identity.validation_hash.begin(), identity.validation_hash.end(),
					   response.validation_hash().begin(), [](uint8_t expected, char observed) {
						   return expected == static_cast<uint8_t>(observed);
					   });
			if (response.prepared_epoch() != identity.target_epoch || !exact_hash ||
			    response.prepared_lease_deadline_unix_ms() == 0u) {
				return status::data_loss(
					"Data Plane PREPARED response did not echo exact identity and lease");
			}
			normalized.prepared_lease_deadline_unix_ms = response.prepared_lease_deadline_unix_ms();
		} else if (response.prepared_epoch() != 0u || !response.validation_hash().empty() ||
			   response.prepared_lease_deadline_unix_ms() != 0u) {
			return status::data_loss("Data Plane non-PREPARED response retained prepared-only fields");
		}
	} else if (response.prepared_epoch() != 0u || !response.validation_hash().empty() ||
		   response.prepared_lease_deadline_unix_ms() != 0u || response.mutation_sequence() != 0u) {
		return status::data_loss("Data Plane rejected Prepare response retained observation fields");
	}
	return normalized;
}

status_or<dataplane_transition_observation>
dataplane_transition_client::activate(const kinetum::common::epoch_transition_identity &identity,
				      std::string_view idempotency_key,
				      std::chrono::steady_clock::time_point operation_deadline) const
{
	kinetum::dataplane::v1::ActivateConfigSnapshotRequest request;
	const auto request_status = populate_identity_request(identity, idempotency_key, request);
	if (!request_status.is_ok()) {
		return request_status;
	}
	auto deadline_or = rpc_deadline(timeout_, operation_deadline);
	if (!deadline_or.is_ok()) {
		return deadline_or.error();
	}
	grpc::ClientContext context;
	context.set_deadline(deadline_or.value());
	kinetum::dataplane::v1::ActivateConfigSnapshotResponse response;
	grpc::Status transport;
	try {
		transport = stub_->ActivateConfigSnapshot(&context, request, &response);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane Activate call exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane Activate call exceeded host size limits");
	} catch (const std::exception &) {
		return status::internal_error("Data Plane Activate call raised an exception");
	} catch (...) {
		return status::internal_error("Data Plane Activate call raised a non-standard exception");
	}
	if (!transport.ok()) {
		return transport_failure(transport);
	}
	auto normalized_or = normalize_common(response, identity, "ActivateConfigSnapshotResponse");
	if (!normalized_or.is_ok()) {
		return normalized_or.error();
	}
	auto normalized = std::move(normalized_or).value();
	if (exact_observation(normalized)) {
		if (!normalized.application_status.is_ok()) {
			return status::data_loss("Data Plane exact Activate observation carried application failure");
		}
		if (response.mutation_sequence() != identity.mutation_sequence) {
			return status::data_loss("Data Plane Activate response mutation identity is inexact");
		}
		if (normalized.state == wire_state::EPOCH_TRANSITION_STATE_COMPLETE) {
			if (response.completed_epoch() != identity.target_epoch) {
				return status::data_loss("Data Plane COMPLETE response did not echo its exact epoch");
			}
			normalized.transition_duration_ns = response.transition_duration_ns();
		} else if (response.completed_epoch() != 0u || response.transition_duration_ns() != 0u) {
			return status::data_loss("Data Plane non-COMPLETE response retained completion-only fields");
		}
	} else if (response.completed_epoch() != 0u || response.transition_duration_ns() != 0u ||
		   response.mutation_sequence() != 0u) {
		return status::data_loss("Data Plane rejected Activate response retained observation fields");
	}
	return normalized;
}

status_or<dataplane_transition_observation>
dataplane_transition_client::abort(const kinetum::common::epoch_transition_identity &identity,
				   std::string_view idempotency_key,
				   std::chrono::steady_clock::time_point operation_deadline) const
{
	kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest request;
	const auto request_status = populate_identity_request(identity, idempotency_key, request);
	if (!request_status.is_ok()) {
		return request_status;
	}
	auto deadline_or = rpc_deadline(timeout_, operation_deadline);
	if (!deadline_or.is_ok()) {
		return deadline_or.error();
	}
	grpc::ClientContext context;
	context.set_deadline(deadline_or.value());
	kinetum::dataplane::v1::AbortPreparedConfigSnapshotResponse response;
	grpc::Status transport;
	try {
		transport = stub_->AbortPreparedConfigSnapshot(&context, request, &response);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane Abort call exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane Abort call exceeded host size limits");
	} catch (const std::exception &) {
		return status::internal_error("Data Plane Abort call raised an exception");
	} catch (...) {
		return status::internal_error("Data Plane Abort call raised a non-standard exception");
	}
	if (!transport.ok()) {
		return transport_failure(transport);
	}
	auto normalized_or = normalize_common(response, identity, "AbortPreparedConfigSnapshotResponse");
	if (!normalized_or.is_ok()) {
		return normalized_or.error();
	}
	auto normalized = std::move(normalized_or).value();
	if (exact_observation(normalized)) {
		const bool postcommit_refusal = normalized.state == wire_state::EPOCH_TRANSITION_STATE_COMMITTING ||
						normalized.state == wire_state::EPOCH_TRANSITION_STATE_RETIRING ||
						normalized.state == wire_state::EPOCH_TRANSITION_STATE_FAILED_STOP;
		if (postcommit_refusal == normalized.application_status.is_ok()) {
			return status::data_loss(
				"Data Plane exact Abort application status disagrees with transition state");
		}
	}
	if ((exact_observation(normalized) && response.mutation_sequence() != identity.mutation_sequence) ||
	    (!exact_observation(normalized) && response.mutation_sequence() != 0u)) {
		return status::data_loss("Data Plane Abort response mutation identity is inexact");
	}
	return normalized;
}

status_or<dataplane_transition_observation>
dataplane_transition_client::query(const kinetum::common::epoch_transition_identity &identity,
				   std::string_view idempotency_key, std::string_view plan_content_hash,
				   std::chrono::steady_clock::time_point operation_deadline) const
{
	auto plan_hash_or = kinetum::common::decode_sha256_digest_claim(
		plan_content_hash, "GetEpochTransitionStatus expected plan_content_hash");
	if (!plan_hash_or.is_ok()) {
		return plan_hash_or.error();
	}
	kinetum::dataplane::v1::GetEpochTransitionStatusRequest request;
	const auto request_status = populate_identity_request(identity, idempotency_key, request);
	if (!request_status.is_ok()) {
		return request_status;
	}
	auto deadline_or = rpc_deadline(timeout_, operation_deadline);
	if (!deadline_or.is_ok()) {
		return deadline_or.error();
	}
	grpc::ClientContext context;
	context.set_deadline(deadline_or.value());
	kinetum::dataplane::v1::GetEpochTransitionStatusResponse response;
	grpc::Status transport;
	try {
		transport = stub_->GetEpochTransitionStatus(&context, request, &response);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane Status call exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane Status call exceeded host size limits");
	} catch (const std::exception &) {
		return status::internal_error("Data Plane Status call raised an exception");
	} catch (...) {
		return status::internal_error("Data Plane Status call raised a non-standard exception");
	}
	if (!transport.ok()) {
		return transport_failure(transport);
	}
	auto normalized_or = normalize_common(response, identity, "GetEpochTransitionStatusResponse");
	if (!normalized_or.is_ok()) {
		return normalized_or.error();
	}
	auto normalized = std::move(normalized_or).value();
	if (!exact_observation(normalized)) {
		if (response.from_epoch() != 0u || response.to_epoch() != 0u || !response.validation_hash().empty() ||
		    !response.plan_content_hash().empty() || response.prepare_duration_ns() != 0u ||
		    response.commit_duration_ns() != 0u || response.retirement_duration_ns() != 0u ||
		    !response.failure_reason().empty() || response.mutation_sequence() != 0u) {
			return status::data_loss("Data Plane rejected Status response retained observation fields");
		}
		return normalized;
	}
	if (!normalized.application_status.is_ok()) {
		return status::data_loss("Data Plane exact Status observation carried application failure");
	}
	if (!status_durations_are_qualified(normalized.state, response.prepare_duration_ns(),
					    response.commit_duration_ns(), response.retirement_duration_ns()) ||
	    (normalized.failure_code == wire_failure::EPOCH_TRANSITION_FAILURE_CODE_NONE &&
	     !response.failure_reason().empty())) {
		return status::data_loss("Data Plane Status response retained fields outside their producing state");
	}
	const bool exact_hash = response.validation_hash().size() == identity.validation_hash.size() &&
				std::equal(identity.validation_hash.begin(), identity.validation_hash.end(),
					   response.validation_hash().begin(), [](uint8_t expected, char observed) {
						   return expected == static_cast<uint8_t>(observed);
					   });
	if (!kinetum::common::valid_epoch_id(response.from_epoch()) || response.from_epoch() >= response.to_epoch() ||
	    response.to_epoch() != identity.target_epoch || !exact_hash ||
	    response.plan_content_hash() != plan_content_hash ||
	    response.mutation_sequence() != identity.mutation_sequence ||
	    response.failure_reason().size() > MAX_REMOTE_TRANSITION_DIAGNOSTIC_BYTES) {
		return status::data_loss("Data Plane Status response did not echo complete exact identity");
	}
	normalized.prepare_duration_ns = response.prepare_duration_ns();
	normalized.commit_duration_ns = response.commit_duration_ns();
	normalized.retirement_duration_ns = response.retirement_duration_ns();
	try {
		normalized.plan_content_hash = response.plan_content_hash();
		normalized.failure_reason = response.failure_reason();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane Status normalization exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane Status normalization exceeded host size limits");
	}
	return normalized;
}

}  // namespace kinetum::cp
