// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_telemetry_contract.cpp
 * @brief Intrinsic final runtime-telemetry wire validation.
 * @author Fleming Patel
 */

#include "src/common/runtime_telemetry_contract.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "src/common/application_status.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/module_health_contract.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/transition_topology.hpp"
#include "src/common/utf8.hpp"

namespace kinetum::common
{
namespace
{

namespace telemetry = kinetum::telemetry::v1;

/** @brief Exact SHA-256 byte width used by transition identities. */
constexpr std::size_t SHA256_BYTES = 32u;

/**
 * @brief Check one canonical embedded application success value.
 * @param value Candidate embedded application status.
 * @return true only for status-only canonical application success.
 */
[[nodiscard]] bool canonical_success_status(const kinetum::common::v1::Status &value) noexcept
{
	return application_status_succeeded(value) && value.message().empty() && value.details().empty();
}

/**
 * @brief Check one provider-observation enum value.
 * @param state Candidate provider-observation state.
 * @return true only for one typed provider-observation state.
 */
[[nodiscard]] bool provider_state_valid(telemetry::ProviderObservationState state) noexcept
{
	return state == telemetry::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT ||
	       state == telemetry::PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE ||
	       state == telemetry::PROVIDER_OBSERVATION_STATE_UNSUPPORTED ||
	       state == telemetry::PROVIDER_OBSERVATION_STATE_READ_FAILED;
}

/**
 * @brief Check one compiler-supported steering kind.
 * @param kind Candidate plan-schema steering kind.
 * @return true only for a steering mechanism admitted by the current compiler.
 */
[[nodiscard]] bool steering_kind_valid(kinetum::gluon::v1::TrafficSteeringKind kind) noexcept
{
	return kind == kinetum::gluon::v1::TRAFFIC_STEERING_KIND_NONE ||
	       kind == kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS;
}

/**
 * @brief Check provider-value presence against typed availability.
 * @param state Exact provider availability classification.
 * @param any Whether any optional counter is present.
 * @param complete Whether the complete optional counter tuple is present.
 * @return true only when provider counter presence matches availability.
 */
[[nodiscard]] bool provider_values_present(telemetry::ProviderObservationState state, bool any, bool complete) noexcept
{
	const bool available = state == telemetry::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT ||
			       state == telemetry::PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE;
	return available ? complete : !any;
}

/**
 * @brief Check a certificate fault's compact identity namespace.
 * @param fault Typed certificate fault.
 * @param fault_index Compact fault identity or UINT32_MAX sentinel.
 * @param execution_total Frozen execution-participant population.
 * @param boundary_total Frozen boundary population.
 * @return true only when one certificate fault selects its exact compact namespace.
 */
[[nodiscard]] bool certificate_fault_index_valid(telemetry::EpochCertificateFault fault, uint32_t fault_index,
						 uint32_t execution_total, uint32_t boundary_total) noexcept
{
	switch (fault) {
	case telemetry::EPOCH_CERTIFICATE_FAULT_NONE:
	case telemetry::EPOCH_CERTIFICATE_FAULT_REQUEST_IDENTITY:
	case telemetry::EPOCH_CERTIFICATE_FAULT_READER_MEMBERSHIP:
		return fault_index == UINT32_MAX;
	case telemetry::EPOCH_CERTIFICATE_FAULT_EXECUTION_MEMBERSHIP:
	case telemetry::EPOCH_CERTIFICATE_FAULT_EXECUTION_STATE:
		return fault_index < execution_total;
	case telemetry::EPOCH_CERTIFICATE_FAULT_BOUNDARY_MEMBERSHIP:
	case telemetry::EPOCH_CERTIFICATE_FAULT_BOUNDARY_STATE:
	case telemetry::EPOCH_CERTIFICATE_FAULT_CUT_IDENTITY:
		return fault_index < boundary_total;
	case telemetry::EPOCH_CERTIFICATE_FAULT_UNSPECIFIED:
	case telemetry::EpochCertificateFault_INT_MIN_SENTINEL_DO_NOT_USE_:
	case telemetry::EpochCertificateFault_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Check one protocol fault's immediate disposition.
 * @param code Typed protocol-fault code.
 * @param disposition Immediate fail-closed disposition.
 * @return true only when one wire fault code names its exact immediate disposition.
 */
[[nodiscard]] bool protocol_fault_disposition_valid(telemetry::EpochProtocolFaultCode code,
						    telemetry::EpochProtocolFaultDisposition disposition) noexcept
{
	if (code == telemetry::EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED) {
		return disposition == telemetry::EPOCH_PROTOCOL_FAULT_DISPOSITION_RESOURCE_REFUSED;
	}
	if (code == telemetry::EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH) {
		return disposition == telemetry::EPOCH_PROTOCOL_FAULT_DISPOSITION_DROP_AND_RETIRE ||
		       disposition == telemetry::EPOCH_PROTOCOL_FAULT_DISPOSITION_TERMINATE;
	}
	return disposition == telemetry::EPOCH_PROTOCOL_FAULT_DISPOSITION_TERMINATE;
}

/**
 * @brief Check the compact namespace required by one protocol-fault code.
 * @param fault Candidate immutable first-fault row.
 * @return true only when applicable and sentinel identities match the producer class.
 */
[[nodiscard]] bool protocol_fault_identity_shape_valid(const telemetry::EpochProtocolFirstFault &fault) noexcept
{
	const bool worker = fault.worker_index() != UINT32_MAX;
	const bool boundary = fault.boundary_index() != UINT32_MAX;
	const bool context = fault.context_index() != UINT32_MAX;
	const bool stage = fault.stage_instance_index() != UINT32_MAX;
	switch (fault.code()) {
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH:
		return worker && (!context || stage) && (!boundary || !context);
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_OLD_DATA_AFTER_SEAL:
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_FUTURE_DATA_BEFORE_ACK:
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_CUT_IDENTITY_MISMATCH:
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_ACTIVATION:
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_CUT_DRAIN:
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_SEQUENCE_EXHAUSTED:
		return worker && boundary && !context;
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_UNDERFLOW:
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_OVERFLOW:
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_DOUBLE_RETIRE:
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_WRONG_SLOT:
		return worker && !boundary && !context && !stage;
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_RETIREMENT_BEFORE_QUIESCENCE:
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED:
		return !worker && !boundary && !context && !stage;
	case telemetry::EPOCH_PROTOCOL_FAULT_CODE_UNSPECIFIED:
	case telemetry::EpochProtocolFaultCode_INT_MIN_SENTINEL_DO_NOT_USE_:
	case telemetry::EpochProtocolFaultCode_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Classify one pre-commit transition failure.
 * @param failure Candidate transition failure code.
 * @return true only for one abortable pre-commit wire failure.
 */
[[nodiscard]] bool precommit_failure(telemetry::EpochTransitionFailureCode failure) noexcept
{
	switch (failure) {
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED:
		return true;
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_NONE:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT:
	case telemetry::EpochTransitionFailureCode_INT_MIN_SENTINEL_DO_NOT_USE_:
	case telemetry::EpochTransitionFailureCode_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Classify one completion-only transition failure.
 * @param failure Candidate transition failure code.
 * @return true only for one completion-only fail-stop wire failure.
 */
[[nodiscard]] bool fail_stop_failure(telemetry::EpochTransitionFailureCode failure) noexcept
{
	switch (failure) {
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT:
		return true;
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_NONE:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED:
	case telemetry::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED:
	case telemetry::EpochTransitionFailureCode_INT_MIN_SENTINEL_DO_NOT_USE_:
	case telemetry::EpochTransitionFailureCode_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Check one stable text identity for presence.
 * @param value Candidate stable identity text.
 * @return true only for a nonempty identity-bearing text field.
 */
[[nodiscard]] bool identity_present(std::string_view value) noexcept
{
	return !value.empty();
}

/**
 * @brief Validate one active or terminal transaction.
 * @param transaction Candidate active or terminal transaction.
 * @param collection_monotonic_ns Exact enclosing collection timestamp.
 * @return true only when one transaction has a complete intrinsic shape.
 */
[[nodiscard]] bool transaction_valid(const telemetry::EpochTransactionTelemetry &transaction,
				     uint64_t collection_monotonic_ns) noexcept
{
	if (!valid_mutation_sequence(transaction.mutation_sequence()) || !valid_epoch_id(transaction.from_epoch()) ||
	    !valid_epoch_id(transaction.to_epoch()) || transaction.to_epoch() <= transaction.from_epoch() ||
	    transaction.validation_hash().size() != SHA256_BYTES ||
	    transaction.idempotency_key_digest().size() != SHA256_BYTES || transaction.admitted_monotonic_ns() == 0u ||
	    transaction.admitted_monotonic_ns() > collection_monotonic_ns ||
	    transaction.outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_UNSPECIFIED ||
	    transaction.failure_code() == telemetry::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED) {
		return false;
	}
	if (transaction.has_prepared_monotonic_ns() &&
	    (transaction.prepared_monotonic_ns() < transaction.admitted_monotonic_ns() ||
	     transaction.prepared_monotonic_ns() > collection_monotonic_ns)) {
		return false;
	}
	if (transaction.has_prepared_lease_deadline_monotonic_ns() !=
	    transaction.has_prepared_lease_deadline_unix_ms()) {
		return false;
	}
	if (transaction.has_prepared_lease_deadline_monotonic_ns() &&
	    (!transaction.has_prepared_monotonic_ns() ||
	     transaction.prepared_lease_deadline_monotonic_ns() <= transaction.prepared_monotonic_ns() ||
	     transaction.prepared_lease_deadline_unix_ms() == 0u)) {
		return false;
	}
	if (transaction.has_commit_started_monotonic_ns() &&
	    (!transaction.has_prepared_monotonic_ns() ||
	     transaction.commit_started_monotonic_ns() < transaction.prepared_monotonic_ns() ||
	     transaction.commit_started_monotonic_ns() > collection_monotonic_ns)) {
		return false;
	}
	if (transaction.has_retiring_started_monotonic_ns() &&
	    (!transaction.has_commit_started_monotonic_ns() ||
	     transaction.retiring_started_monotonic_ns() < transaction.commit_started_monotonic_ns() ||
	     transaction.retiring_started_monotonic_ns() > collection_monotonic_ns)) {
		return false;
	}
	if (transaction.has_failure_observed_monotonic_ns() &&
	    (transaction.failure_observed_monotonic_ns() < transaction.admitted_monotonic_ns() ||
	     (transaction.has_prepared_monotonic_ns() &&
	      transaction.failure_observed_monotonic_ns() < transaction.prepared_monotonic_ns()) ||
	     (transaction.has_commit_started_monotonic_ns() &&
	      transaction.failure_observed_monotonic_ns() < transaction.commit_started_monotonic_ns()) ||
	     (transaction.has_retiring_started_monotonic_ns() &&
	      transaction.failure_observed_monotonic_ns() < transaction.retiring_started_monotonic_ns()) ||
	     transaction.failure_observed_monotonic_ns() > collection_monotonic_ns)) {
		return false;
	}
	if (transaction.has_terminal_monotonic_ns() &&
	    (transaction.terminal_monotonic_ns() < transaction.admitted_monotonic_ns() ||
	     transaction.terminal_monotonic_ns() > collection_monotonic_ns)) {
		return false;
	}
	if (transaction.has_failure_observed_monotonic_ns() && transaction.has_terminal_monotonic_ns() &&
	    transaction.failure_observed_monotonic_ns() > transaction.terminal_monotonic_ns()) {
		return false;
	}
	if (transaction.has_terminal_monotonic_ns() &&
	    ((transaction.has_prepared_monotonic_ns() &&
	      transaction.terminal_monotonic_ns() < transaction.prepared_monotonic_ns()) ||
	     (transaction.has_commit_started_monotonic_ns() &&
	      transaction.terminal_monotonic_ns() < transaction.commit_started_monotonic_ns()) ||
	     (transaction.has_retiring_started_monotonic_ns() &&
	      transaction.terminal_monotonic_ns() < transaction.retiring_started_monotonic_ns()))) {
		return false;
	}
	const bool terminal = transaction.outcome() != telemetry::EPOCH_TRANSITION_OUTCOME_NONE;
	if (terminal != transaction.has_terminal_monotonic_ns()) {
		return false;
	}
	if (transaction.outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_COMPLETE) {
		return transaction.failure_code() == telemetry::EPOCH_TRANSITION_FAILURE_CODE_NONE &&
		       transaction.has_prepared_monotonic_ns() &&
		       !transaction.has_prepared_lease_deadline_monotonic_ns() &&
		       transaction.has_commit_started_monotonic_ns() &&
		       transaction.has_retiring_started_monotonic_ns() &&
		       !transaction.has_failure_observed_monotonic_ns() && !transaction.retirement_frozen();
	}
	if (transaction.outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_NONE) {
		const bool frozen = transaction.failure_code() ==
				    telemetry::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED;
		return transaction.retirement_frozen() == frozen &&
		       (transaction.failure_code() == telemetry::EPOCH_TRANSITION_FAILURE_CODE_NONE ?
				!transaction.has_failure_observed_monotonic_ns() :
				transaction.has_failure_observed_monotonic_ns());
	}
	if (transaction.outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_ABORTED) {
		return precommit_failure(transaction.failure_code()) && transaction.has_prepared_monotonic_ns() &&
		       !transaction.has_prepared_lease_deadline_monotonic_ns() &&
		       !transaction.has_commit_started_monotonic_ns() &&
		       !transaction.has_retiring_started_monotonic_ns() &&
		       transaction.has_failure_observed_monotonic_ns() && !transaction.retirement_frozen();
	}
	return transaction.outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_FAILED_STOP &&
	       fail_stop_failure(transaction.failure_code()) && transaction.has_failure_observed_monotonic_ns() &&
	       !transaction.retirement_frozen();
}

/**
 * @brief Check one sorted repeated stable-identity sequence.
 * @tparam repeated_type Protobuf repeated-string container type.
 * @param values Candidate stable identity sequence.
 * @return true when every present identity is nonempty and strictly increasing;
 *         an empty sequence is vacuously valid for its caller to qualify.
 */
template <typename repeated_type>
[[nodiscard]] bool strictly_increasing_text(const repeated_type &values) noexcept
{
	std::string_view previous;
	for (const auto &value : values) {
		const std::string_view current(value);
		if (current.empty() || (!previous.empty() && current <= previous)) {
			return false;
		}
		previous = current;
	}
	return true;
}

/**
 * @brief Check one repeated row family's projected identities in O(n log n).
 * @tparam key_type Copyable, totally ordered identity type.
 * @tparam repeated_type Protobuf repeated-row container type.
 * @tparam projection_type Callable mapping one row to @c key_type.
 * @param values Immutable repeated rows.
 * @param projection Identity projection with no retained row ownership.
 * @return true only when one projected identity appears at most once.
 */
template <typename key_type, typename repeated_type, typename projection_type>
[[nodiscard]] bool projected_identities_unique(const repeated_type &values, projection_type projection)
{
	std::vector<key_type> identities;
	identities.reserve(static_cast<std::size_t>(values.size()));
	for (const auto &value : values) {
		identities.push_back(projection(value));
	}
	std::sort(identities.begin(), identities.end());
	return std::adjacent_find(identities.begin(), identities.end()) == identities.end();
}

/**
 * @brief Check that two repeated row families occupy disjoint identity sets.
 * @tparam key_type Copyable, totally ordered identity type.
 * @tparam left_type First protobuf repeated-row container type.
 * @tparam right_type Second protobuf repeated-row container type.
 * @tparam left_projection_type Callable mapping a first-family row to @c key_type.
 * @tparam right_projection_type Callable mapping a second-family row to @c key_type.
 * @param left Immutable first row family.
 * @param right Immutable second row family.
 * @param left_projection First-family identity projection.
 * @param right_projection Second-family identity projection.
 * @return true only when no projected identity crosses the two families.
 */
template <typename key_type, typename left_type, typename right_type, typename left_projection_type,
	  typename right_projection_type>
[[nodiscard]] bool projected_identity_sets_disjoint(const left_type &left, const right_type &right,
						    left_projection_type left_projection,
						    right_projection_type right_projection)
{
	std::vector<key_type> left_identities;
	left_identities.reserve(static_cast<std::size_t>(left.size()));
	for (const auto &value : left) {
		left_identities.push_back(left_projection(value));
	}
	std::sort(left_identities.begin(), left_identities.end());
	return std::none_of(right.begin(), right.end(), [&](const auto &value) {
		return std::binary_search(left_identities.begin(), left_identities.end(), right_projection(value));
	});
}

/**
 * @brief Add one cold aggregate value with uint64 saturation.
 * @param[in,out] target Aggregate destination.
 * @param value Value to add without wrapping.
 */
void add_saturating(uint64_t &target, uint64_t value) noexcept
{
	target = value > UINT64_MAX - target ? UINT64_MAX : target + value;
}

/**
 * @brief Check one module counter row's intrinsic identity.
 * @param row Candidate module counter row.
 * @return true only when one module counter row has complete identity.
 */
[[nodiscard]] bool module_counter_valid(const telemetry::ModuleCounterStats &row) noexcept
{
	return identity_present(row.module_id()) && identity_present(row.context_instance_id()) &&
	       identity_present(row.name()) && valid_epoch_id(row.epoch());
}

/**
 * @brief Check one module mismatch row's first-fault presence.
 * @param row Candidate module epoch-mismatch row.
 * @return true only when all first-fault fields are jointly qualified.
 */
[[nodiscard]] bool module_mismatch_valid(const telemetry::ModuleEpochMismatchStats &row) noexcept
{
	const bool any_fault = row.has_first_packet_epoch() || row.has_first_active_epoch() ||
			       row.has_first_stage_instance_index() || row.has_first_region_id();
	const bool complete_fault = row.has_first_packet_epoch() && valid_epoch_id(row.first_packet_epoch()) &&
				    row.has_first_active_epoch() && valid_epoch_id(row.first_active_epoch()) &&
				    row.has_first_stage_instance_index() && row.has_first_region_id() &&
				    row.first_region_id() >= 0;
	return identity_present(row.module_id()) && identity_present(row.context_instance_id()) &&
	       valid_epoch_id(row.observation_epoch()) && (row.mismatch_count() == 0u ? !any_fault : complete_fault);
}

/**
 * @brief Check one module-health row's typed availability contract.
 * @param row Candidate module-health row.
 * @return true only when one module-health row obeys its typed availability state.
 */
[[nodiscard]] bool module_health_valid(const telemetry::ModuleHealthStats &row) noexcept
{
	if (!identity_present(row.module_id()) || !identity_present(row.context_instance_id()) ||
	    row.state() == telemetry::MODULE_HEALTH_STATE_UNSPECIFIED ||
	    (row.latest_fault_mask() & ~static_cast<uint32_t>(MODULE_HEALTH_CONTRACT_FAULT_KNOWN_MASK)) != 0u ||
	    (row.first_fault_mask() & ~static_cast<uint32_t>(MODULE_HEALTH_CONTRACT_FAULT_KNOWN_MASK)) != 0u) {
		return false;
	}
	const bool attempt = row.has_observation_epoch() || row.has_observed_at_ns() || row.has_callback_duration_ns();
	const bool complete_attempt = row.has_observation_epoch() && valid_epoch_id(row.observation_epoch()) &&
				      row.has_observed_at_ns() && row.observed_at_ns() != 0u &&
				      row.has_callback_duration_ns();
	const bool any_first = row.has_first_fault_epoch() || row.has_first_fault_timestamp_ns() ||
			       row.has_first_fault_duration_ns();
	const bool complete_first = row.has_first_fault_epoch() && valid_epoch_id(row.first_fault_epoch()) &&
				    row.has_first_fault_timestamp_ns() && row.first_fault_timestamp_ns() != 0u &&
				    row.has_first_fault_duration_ns();
	const bool any_signal = row.has_health_score() || row.has_health_flags() || row.has_reason();
	const bool complete_signal = row.has_health_score() && row.health_score() <= 100u && row.has_health_flags() &&
				     (row.health_flags() & ~static_cast<uint32_t>(KINETUM_HEALTH_F_KNOWN_MASK)) == 0u &&
				     row.has_reason() && row.reason().size() < KINETUM_HEALTH_REASON_CAPACITY &&
				     row.reason().find('\0') == std::string::npos && valid_utf8(row.reason());
	if ((row.contract_fault_count() == 0u && (row.first_fault_mask() != 0u || any_first)) ||
	    (row.contract_fault_count() != 0u && (row.first_fault_mask() == 0u || !complete_first)) ||
	    (row.latest_fault_mask() != 0u && row.contract_fault_count() == 0u) ||
	    (complete_first && (!complete_attempt || row.first_fault_epoch() > row.observation_epoch() ||
				row.first_fault_timestamp_ns() > row.observed_at_ns()))) {
		return false;
	}
	switch (row.state()) {
	case telemetry::MODULE_HEALTH_STATE_CALLBACK_UNAVAILABLE:
	case telemetry::MODULE_HEALTH_STATE_AWAITING_OBSERVATION:
		return row.publication_generation() == 0u && !attempt && !any_signal &&
		       row.contract_fault_count() == 0u && row.latest_fault_mask() == 0u;
	case telemetry::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE:
		return row.publication_generation() != 0u && complete_attempt && complete_signal &&
		       row.latest_fault_mask() == 0u;
	case telemetry::MODULE_HEALTH_STATE_ATTEMPT_SUPPRESSED:
		return row.publication_generation() != 0u && complete_attempt && !any_signal &&
		       row.latest_fault_mask() != 0u;
	case telemetry::MODULE_HEALTH_STATE_STALE_EPOCH:
		return row.publication_generation() != 0u && complete_attempt && !any_signal;
	case telemetry::MODULE_HEALTH_STATE_UNSPECIFIED:
	case telemetry::ModuleHealthState_INT_MIN_SENTINEL_DO_NOT_USE_:
	case telemetry::ModuleHealthState_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Check one worker row's exact epoch slots.
 * @param row Candidate worker epoch row.
 * @return true only when one worker row preserves exact epoch-slot presence.
 */
[[nodiscard]] bool worker_valid(const telemetry::WorkerEpochStats &row) noexcept
{
	if (!identity_present(row.worker_id()) || !identity_present(row.lane_id()) || row.region_id() < 0 ||
	    row.ledger_publication_generation() == 0u || !valid_epoch_id(row.active_epoch()) ||
	    !valid_epoch_id(row.source_epoch()) || row.activation_publication_generation() == 0u ||
	    (row.has_future_epoch() &&
	     (!valid_epoch_id(row.future_epoch()) || row.future_epoch() <= row.active_epoch())) ||
	    (!row.has_future_epoch() && row.future_unretired() != 0u) ||
	    (row.source_epoch() != row.active_epoch() &&
	     (!row.has_future_epoch() || row.source_epoch() != row.future_epoch()))) {
		return false;
	}
	const bool any_transition = row.has_transition_generation() || row.has_from_epoch() || row.has_to_epoch() ||
				    row.has_activation_monotonic_ns();
	const bool complete_transition = row.has_transition_generation() &&
					 valid_mutation_sequence(row.transition_generation()) && row.has_from_epoch() &&
					 valid_epoch_id(row.from_epoch()) && row.has_to_epoch() &&
					 valid_epoch_id(row.to_epoch()) && row.to_epoch() > row.from_epoch() &&
					 row.has_activation_monotonic_ns() && row.activation_monotonic_ns() != 0u &&
					 row.active_epoch() == row.to_epoch();
	return row.activation_complete() ? complete_transition : !any_transition;
}

/**
 * @brief Check one cold region row's intrinsic derivation shape.
 * @param row Candidate cold region derivation.
 * @return true only when one region row is self-consistent.
 */
[[nodiscard]] bool region_valid(const telemetry::RegionEpochStats &row) noexcept
{
	const bool any_activation = row.has_minimum_activation_monotonic_ns() ||
				    row.has_maximum_activation_monotonic_ns();
	const bool complete_activation = row.has_minimum_activation_monotonic_ns() &&
					 row.minimum_activation_monotonic_ns() != 0u &&
					 row.has_maximum_activation_monotonic_ns() &&
					 row.maximum_activation_monotonic_ns() >= row.minimum_activation_monotonic_ns();
	return row.region_id() >= 0 && row.worker_count() != 0u && valid_epoch_id(row.minimum_active_epoch()) &&
	       valid_epoch_id(row.maximum_active_epoch()) && row.minimum_active_epoch() <= row.maximum_active_epoch() &&
	       valid_epoch_id(row.minimum_source_epoch()) && valid_epoch_id(row.maximum_source_epoch()) &&
	       row.minimum_source_epoch() <= row.maximum_source_epoch() &&
	       row.activated_participants() <= row.worker_count() &&
	       (row.activated_participants() == 0u ? !any_activation : complete_activation);
}

/**
 * @brief Check one boundary row's identities, timestamps, and durations.
 * @param row Candidate boundary protocol row.
 * @param collection_monotonic_ns Exact enclosing collection timestamp.
 * @return true only when optional identities and durations are complete.
 */
[[nodiscard]] bool boundary_valid(const telemetry::BoundaryEpochStats &row, uint64_t collection_monotonic_ns) noexcept
{
	if (!identity_present(row.boundary_id()) || row.from_region_id() < 0 || row.to_region_id() < 0 ||
	    row.sender_worker_index() == row.receiver_worker_index() || row.data_ring_capacity() < 2u ||
	    (row.data_ring_capacity() & (row.data_ring_capacity() - 1u)) != 0u ||
	    row.future_output_hold_capacity() < 2u ||
	    (row.future_output_hold_capacity() & (row.future_output_hold_capacity() - 1u)) != 0u ||
	    row.data_enqueued_sequence() == UINT64_MAX || row.data_dequeued_sequence() == UINT64_MAX ||
	    row.data_dequeued_sequence() > row.data_enqueued_sequence()) {
		return false;
	}
	const bool pending_cut = row.has_pending_cut_epoch() || row.has_pending_cut_sequence();
	const bool complete_pending_cut = row.has_pending_cut_epoch() && valid_epoch_id(row.pending_cut_epoch()) &&
					  row.has_pending_cut_sequence();
	const bool pending_ack = row.has_pending_ack_epoch() || row.has_pending_ack_sequence();
	const bool complete_pending_ack = row.has_pending_ack_epoch() && valid_epoch_id(row.pending_ack_epoch()) &&
					  row.has_pending_ack_sequence();
	const bool any_transition = row.has_transition_generation() || row.has_from_epoch() || row.has_to_epoch();
	const bool complete_transition = row.has_transition_generation() &&
					 valid_mutation_sequence(row.transition_generation()) && row.has_from_epoch() &&
					 valid_epoch_id(row.from_epoch()) && row.has_to_epoch() &&
					 valid_epoch_id(row.to_epoch()) && row.to_epoch() > row.from_epoch();
	if ((pending_cut && !complete_pending_cut) || (pending_ack && !complete_pending_ack) ||
	    (any_transition && !complete_transition) || (row.has_cut_sequence() && !complete_transition) ||
	    (row.has_cut_sequence() && row.cut_sequence() == UINT64_MAX) ||
	    (complete_pending_cut && row.pending_cut_sequence() == UINT64_MAX) ||
	    (complete_pending_ack && row.pending_ack_sequence() == UINT64_MAX) ||
	    (complete_pending_cut && row.pending_cut_sequence() > row.data_enqueued_sequence()) ||
	    (complete_pending_ack && row.pending_ack_sequence() > row.data_dequeued_sequence())) {
		return false;
	}
	const auto timestamp_valid = [collection_monotonic_ns](bool present, uint64_t value) noexcept {
		return !present || (value != 0u && value <= collection_monotonic_ns);
	};
	if (!timestamp_valid(row.has_cut_published_monotonic_ns(), row.cut_published_monotonic_ns()) ||
	    !timestamp_valid(row.has_cut_observed_monotonic_ns(), row.cut_observed_monotonic_ns()) ||
	    !timestamp_valid(row.has_cut_drained_monotonic_ns(), row.cut_drained_monotonic_ns()) ||
	    !timestamp_valid(row.has_activation_monotonic_ns(), row.activation_monotonic_ns()) ||
	    !timestamp_valid(row.has_ack_published_monotonic_ns(), row.ack_published_monotonic_ns()) ||
	    !timestamp_valid(row.has_ack_observed_monotonic_ns(), row.ack_observed_monotonic_ns())) {
		return false;
	}
	const bool any_timing = row.has_cut_published_monotonic_ns() || row.has_cut_observed_monotonic_ns() ||
				row.has_cut_drained_monotonic_ns() || row.has_activation_monotonic_ns() ||
				row.has_ack_published_monotonic_ns() || row.has_ack_observed_monotonic_ns() ||
				row.has_cut_delivery_duration_ns() || row.has_cut_drain_duration_ns() ||
				row.has_ack_gate_duration_ns();
	if (any_timing && !complete_transition) {
		return false;
	}
	if (!complete_transition) {
		return row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_OPEN &&
		       row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_OPEN && !pending_cut &&
		       !pending_ack && !row.has_cut_sequence() && row.duplicate_cut_count() == 0u &&
		       row.duplicate_ack_count() == 0u;
	}

	const bool sender_cut = row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_CUT_PENDING ||
				row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_WAITING_ACK ||
				row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_OPEN;
	const bool sender_cut_published = row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_WAITING_ACK ||
					  row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_OPEN;
	const bool sender_ack_observed = row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_OPEN;
	const bool receiver_cut = row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_CUT_DRAINING ||
				  row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_CUT_DRAINED ||
				  row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PENDING ||
				  row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED ||
				  row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_OPEN;
	const bool receiver_cut_drained = row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_CUT_DRAINED ||
					  row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PENDING ||
					  row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED ||
					  row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_OPEN;
	const bool receiver_cut_pending = row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_CUT_DRAINING;
	const bool receiver_drained_before_ack = row.receiver_phase() ==
							 telemetry::BOUNDARY_RECEIVER_PHASE_CUT_DRAINED ||
						 row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PENDING;
	const bool receiver_ack_complete = row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED ||
					   row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_OPEN;
	const bool receiver_activated = row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PENDING ||
					row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED ||
					row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_OPEN;
	const bool receiver_ack_published = row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED ||
					    row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_OPEN;
	const bool sender_phase_valid = row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_DRAINING || sender_cut;
	const bool receiver_phase_valid = row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_WAITING_CUT ||
					  receiver_cut;
	const bool paired_phase =
		((row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_DRAINING ||
		  row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_CUT_PENDING) &&
		 row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_WAITING_CUT) ||
		row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_WAITING_ACK ||
		(row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_OPEN && receiver_ack_published);
	if (!sender_phase_valid || !receiver_phase_valid || !paired_phase || row.has_cut_sequence() != sender_cut ||
	    (sender_cut && row.cut_sequence() > row.data_enqueued_sequence()) ||
	    (receiver_cut_pending && row.data_dequeued_sequence() >= row.cut_sequence()) ||
	    (receiver_drained_before_ack && row.data_dequeued_sequence() != row.cut_sequence()) ||
	    (receiver_ack_complete && row.data_dequeued_sequence() < row.cut_sequence()) ||
	    pending_cut != (row.sender_phase() == telemetry::BOUNDARY_SENDER_PHASE_CUT_PENDING) ||
	    pending_ack != (row.receiver_phase() == telemetry::BOUNDARY_RECEIVER_PHASE_ACK_PENDING) ||
	    row.has_cut_published_monotonic_ns() != sender_cut_published ||
	    row.has_ack_observed_monotonic_ns() != sender_ack_observed ||
	    row.has_cut_observed_monotonic_ns() != receiver_cut ||
	    row.has_cut_drained_monotonic_ns() != receiver_cut_drained ||
	    row.has_activation_monotonic_ns() != receiver_activated ||
	    row.has_ack_published_monotonic_ns() != receiver_ack_published ||
	    (pending_cut &&
	     (row.pending_cut_epoch() != row.to_epoch() || row.pending_cut_sequence() != row.cut_sequence())) ||
	    (pending_ack &&
	     (row.pending_ack_epoch() != row.to_epoch() || row.pending_ack_sequence() != row.cut_sequence())) ||
	    (row.duplicate_cut_count() != 0u && !receiver_cut) ||
	    (row.duplicate_ack_count() != 0u && !sender_ack_observed)) {
		return false;
	}
	if ((row.has_cut_published_monotonic_ns() && row.has_ack_observed_monotonic_ns() &&
	     row.ack_observed_monotonic_ns() < row.cut_published_monotonic_ns()) ||
	    (row.has_cut_observed_monotonic_ns() && !row.has_cut_published_monotonic_ns()) ||
	    (row.has_cut_drained_monotonic_ns() && !row.has_cut_observed_monotonic_ns()) ||
	    (row.has_activation_monotonic_ns() && !row.has_cut_drained_monotonic_ns()) ||
	    (row.has_ack_published_monotonic_ns() && !row.has_activation_monotonic_ns()) ||
	    (row.has_ack_observed_monotonic_ns() &&
	     (!row.has_ack_published_monotonic_ns() || !row.has_cut_published_monotonic_ns())) ||
	    (row.has_cut_published_monotonic_ns() && row.has_cut_observed_monotonic_ns() &&
	     row.cut_observed_monotonic_ns() < row.cut_published_monotonic_ns()) ||
	    (row.has_cut_observed_monotonic_ns() && row.has_cut_drained_monotonic_ns() &&
	     row.cut_drained_monotonic_ns() < row.cut_observed_monotonic_ns()) ||
	    (row.has_cut_drained_monotonic_ns() && row.has_activation_monotonic_ns() &&
	     row.activation_monotonic_ns() < row.cut_drained_monotonic_ns()) ||
	    (row.has_activation_monotonic_ns() && row.has_ack_published_monotonic_ns() &&
	     row.ack_published_monotonic_ns() < row.activation_monotonic_ns()) ||
	    (row.has_ack_published_monotonic_ns() && row.has_ack_observed_monotonic_ns() &&
	     row.ack_observed_monotonic_ns() < row.ack_published_monotonic_ns())) {
		return false;
	}
	const bool cut_delivery_complete = row.has_cut_published_monotonic_ns() && row.has_cut_observed_monotonic_ns();
	const bool cut_drain_complete = row.has_cut_observed_monotonic_ns() && row.has_cut_drained_monotonic_ns();
	const bool ack_gate_complete = row.has_cut_published_monotonic_ns() && row.has_ack_observed_monotonic_ns();
	if (row.has_cut_delivery_duration_ns() != cut_delivery_complete ||
	    row.has_cut_drain_duration_ns() != cut_drain_complete ||
	    row.has_ack_gate_duration_ns() != ack_gate_complete) {
		return false;
	}
	if (row.has_cut_delivery_duration_ns() &&
	    (!row.has_cut_published_monotonic_ns() || !row.has_cut_observed_monotonic_ns() ||
	     row.cut_delivery_duration_ns() != row.cut_observed_monotonic_ns() - row.cut_published_monotonic_ns())) {
		return false;
	}
	if (row.has_cut_drain_duration_ns() &&
	    (!row.has_cut_observed_monotonic_ns() || !row.has_cut_drained_monotonic_ns() ||
	     row.cut_drain_duration_ns() != row.cut_drained_monotonic_ns() - row.cut_observed_monotonic_ns())) {
		return false;
	}
	if (row.has_ack_gate_duration_ns() &&
	    (!row.has_cut_published_monotonic_ns() || !row.has_ack_observed_monotonic_ns() ||
	     row.ack_gate_duration_ns() != row.ack_observed_monotonic_ns() - row.cut_published_monotonic_ns())) {
		return false;
	}
	return true;
}

/**
 * @brief Check one provider stream row's typed field presence.
 * @param row Candidate provider stream row.
 * @return true only when one stream row has exact field presence.
 */
[[nodiscard]] bool stream_valid(const telemetry::StreamStats &row) noexcept
{
	return identity_present(row.io_stream_id()) &&
	       row.direction() != kinetum::gluon::v1::IO_STREAM_DIRECTION_UNSPECIFIED &&
	       row.published_monotonic_ns() != 0u && row.has_packets() && row.has_bytes() &&
	       row.has_rejected_packets() && row.packets() != UINT64_MAX && row.bytes() != UINT64_MAX &&
	       row.rejected_packets() != UINT64_MAX && ((row.packets() == 0u) == (row.bytes() == 0u)) &&
	       row.bytes() >= row.packets();
}

/**
 * @brief Check one storage row's typed field presence and bounds.
 * @param row Candidate provider storage row.
 * @return true only when one storage row has exact field presence.
 */
[[nodiscard]] bool storage_valid(const telemetry::StorageDomainStats &row) noexcept
{
	const bool any = row.has_observed_monotonic_ns() || row.has_in_use() || row.has_available();
	const bool complete = row.has_observed_monotonic_ns() && row.observed_monotonic_ns() != 0u &&
			      row.has_in_use() && row.has_available() && row.in_use() <= row.buffer_count() &&
			      row.available() <= row.buffer_count();
	const bool available = row.observation_state() == telemetry::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT ||
			       row.observation_state() == telemetry::PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE;
	const bool complete_partition = !available || (row.has_in_use() && row.has_available() &&
						       row.in_use() <= UINT64_MAX - row.available() &&
						       row.in_use() + row.available() == row.buffer_count());
	return identity_present(row.storage_domain_id()) && row.buffer_count() != 0u &&
	       row.required_min_buffers() != 0u && row.required_min_buffers() <= row.buffer_count() &&
	       row.safety_margin() != 0u && provider_state_valid(row.observation_state()) &&
	       provider_values_present(row.observation_state(), any, complete) && complete_partition;
}

/**
 * @brief Check one provider port row's typed field presence.
 * @param row Candidate provider port row.
 * @return true only when one port row has exact field presence.
 */
[[nodiscard]] bool port_valid(const telemetry::PortStats &row) noexcept
{
	const bool any = row.has_observed_monotonic_ns() || row.has_rx_packets() || row.has_tx_packets() ||
			 row.has_rx_bytes() || row.has_tx_bytes() || row.has_rx_missed() || row.has_rx_errors() ||
			 row.has_tx_errors() || row.has_rx_no_buffer();
	const bool complete = row.has_observed_monotonic_ns() && row.observed_monotonic_ns() != 0u &&
			      row.has_rx_packets() && row.has_tx_packets() && row.has_rx_bytes() &&
			      row.has_tx_bytes() && row.has_rx_missed() && row.has_rx_errors() && row.has_tx_errors() &&
			      row.has_rx_no_buffer();
	return identity_present(row.logical_name()) && identity_present(row.io_driver_instance_id()) &&
	       identity_present(row.driver_port_id()) && provider_state_valid(row.observation_state()) &&
	       provider_values_present(row.observation_state(), any, complete);
}

}  // namespace

/**
 * @brief Validate one statistics wrapper before admitting its selection.
 * @tparam request_type Generated CP or DP request type.
 * @param request Candidate wrapper.
 * @param label Stable diagnostic identity for recursive validation.
 * @return OK only for an explicit, unknown-free selection wrapper.
 */
template <typename request_type>
[[nodiscard]] static status validate_stats_request_impl(const request_type &request, std::string_view label)
{
	try {
		auto unknown = reject_unknown_protobuf_fields_recursive(request, label);
		if (!unknown.is_ok()) {
			return unknown;
		}
		auto enums = reject_invalid_protobuf_enum_values_recursive(request, label);
		if (!enums.is_ok()) {
			return enums;
		}
		if (!request.has_selection()) {
			return status::invalid_argument("statistics request requires an explicit telemetry selection");
		}
		return validate_telemetry_selection(request.selection());
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("statistics request validation exhausted bounded scratch memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "statistics request exceeds the host size domain");
	}
}

status validate_dataplane_stats_request(const kinetum::dataplane::v1::StatsRequest &request)
{
	return validate_stats_request_impl(request, "dataplane StatsRequest");
}

status validate_control_stats_request(const kinetum::control::v1::StatsRequest &request)
{
	return validate_stats_request_impl(request, "control StatsRequest");
}

status validate_telemetry_selection(const kinetum::telemetry::v1::TelemetrySelection &selection)
{
	try {
		auto unknown = reject_unknown_protobuf_fields_recursive(selection, "TelemetrySelection");
		if (!unknown.is_ok()) {
			return unknown;
		}
		return reject_invalid_protobuf_enum_values_recursive(selection, "TelemetrySelection");
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("telemetry selection validation exhausted bounded scratch memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "telemetry selection exceeds the host size domain");
	}
}

/**
 * @brief Prove selected module populations cover every context exactly once.
 * @param value Complete message whose context observations are already validated.
 * @param selection Exact requested row families.
 * @param context_count Generation's complete module-context population.
 * @return OK for canonical membership and agreement with every selected context row.
 */
static status validate_module_context_domains(const telemetry::RuntimeTelemetry &value,
					      const telemetry::TelemetrySelection &selection, uint32_t context_count)
{
	if (!selection.include_topology_stats()) {
		return status::ok();
	}
	using context_identity = std::pair<std::string_view, std::string_view>;
	std::vector<context_identity> contexts;
	std::string_view previous_module;
	for (const auto &domain : value.module_context_domains()) {
		if (!identity_present(domain.module_id()) || domain.module_id() <= previous_module ||
		    domain.context_instance_ids().empty() || !strictly_increasing_text(domain.context_instance_ids())) {
			return status::invalid_argument(
				"RuntimeTelemetry contains a noncanonical module-context domain");
		}
		previous_module = domain.module_id();
		for (const auto &identity : domain.context_instance_ids()) {
			if (contexts.size() >= context_count) {
				return status::invalid_argument(
					"RuntimeTelemetry module domains exceed the context population");
			}
			contexts.emplace_back(identity, domain.module_id());
		}
	}
	if (contexts.size() != context_count) {
		return status::invalid_argument("RuntimeTelemetry module domains omit admitted contexts");
	}
	std::sort(contexts.begin(), contexts.end());
	if (std::adjacent_find(contexts.begin(), contexts.end(), [](const auto &left, const auto &right) {
		    return left.first == right.first;
	    }) != contexts.end()) {
		return status::invalid_argument("RuntimeTelemetry module domains repeat a context identity");
	}
	const auto member = [&contexts](const auto &row) {
		return std::binary_search(contexts.begin(), contexts.end(),
					  context_identity{row.context_instance_id(), row.module_id()});
	};
	if (!std::all_of(value.module_epoch_mismatches().begin(), value.module_epoch_mismatches().end(), member) ||
	    !std::all_of(value.module_health().begin(), value.module_health().end(), member)) {
		return status::invalid_argument(
			"RuntimeTelemetry module domains contradict observed context ownership");
	}
	return status::ok();
}

/**
 * @brief Validate one complete runtime telemetry message intrinsically.
 * @param value Candidate complete runtime telemetry message.
 * @param selection Exact optional-row selection.
 * @return Intrinsic validation before allocation failures are normalized.
 */
static status validate_runtime_telemetry_impl(const telemetry::RuntimeTelemetry &value,
					      const telemetry::TelemetrySelection &selection)
{
	auto selection_status = validate_telemetry_selection(selection);
	if (!selection_status.is_ok()) {
		return selection_status;
	}
	auto unknown = reject_unknown_protobuf_fields_recursive(value, "RuntimeTelemetry");
	if (!unknown.is_ok()) {
		return unknown;
	}
	auto enums = reject_invalid_protobuf_enum_values_recursive(value, "RuntimeTelemetry");
	if (!enums.is_ok()) {
		return enums;
	}
	if (!value.has_runtime() || !value.has_engine() || !value.has_transition() || !value.has_protocol_faults()) {
		return status::invalid_argument("RuntimeTelemetry lacks one required observation family");
	}
	const auto &engine = value.engine();
	if (engine.rx_packets() == UINT64_MAX || engine.tx_packets() == UINT64_MAX || engine.rx_bytes() == UINT64_MAX ||
	    engine.tx_bytes() == UINT64_MAX) {
		return status::invalid_argument("RuntimeTelemetry engine transfer counters are exhausted");
	}
	const auto &runtime = value.runtime();
	if (runtime.runtime_generation() == 0u || runtime.runtime_generation() > UINT32_MAX ||
	    runtime.status_publication_generation() == 0u || !valid_epoch_id(runtime.active_epoch()) ||
	    !valid_epoch_id(runtime.minimum_retained_epoch()) ||
	    runtime.minimum_retained_epoch() > runtime.active_epoch() ||
	    !valid_epoch_id(runtime.last_activated_epoch()) ||
	    runtime.last_activated_epoch() != runtime.active_epoch() || runtime.active_workers() == 0u ||
	    runtime.active_workers() != runtime.expected_workers() || runtime.collection_monotonic_ns() == 0u ||
	    runtime.latest_bank_publication_monotonic_ns() == 0u ||
	    runtime.latest_bank_publication_monotonic_ns() > runtime.collection_monotonic_ns()) {
		return status::invalid_argument("RuntimeTelemetry runtime identity or timestamp shape is malformed");
	}
	const auto &transition = value.transition();
	if (transition.publication_generation() == 0u ||
	    transition.state() == telemetry::EPOCH_TRANSITION_STATE_UNSPECIFIED ||
	    transition.state() == telemetry::EPOCH_TRANSITION_STATE_AWAITING_BOOTSTRAP ||
	    transition.state() == telemetry::EPOCH_TRANSITION_STATE_BOOTSTRAPPING ||
	    transition.state() == telemetry::EPOCH_TRANSITION_STATE_COMPLETE ||
	    transition.state() == telemetry::EPOCH_TRANSITION_STATE_ABORTED ||
	    !valid_epoch_id(transition.active_epoch()) ||
	    (transition.target_epoch() != 0u && !valid_epoch_id(transition.target_epoch())) ||
	    !valid_epoch_id(transition.allocated_epoch_high_watermark()) ||
	    transition.allocated_epoch_high_watermark() < transition.active_epoch() ||
	    !valid_mutation_sequence(transition.mutation_sequence_high_watermark()) ||
	    transition.plan_content_hash().size() != SHA256_BYTES ||
	    transition.active_validation_hash().size() != SHA256_BYTES ||
	    transition.execution_participant_count() == 0u || transition.region_count() == 0u ||
	    transition.source_participant_count() == 0u || transition.sink_participant_count() == 0u ||
	    transition.quiescence_reader_count() != transition.execution_participant_count() ||
	    transition.terminal_history_size() > MAX_TRANSITION_RESULT_HISTORY_CAPACITY) {
		return status::invalid_argument("RuntimeTelemetry transition identity is malformed");
	}
	if (transition.has_active_transaction() &&
	    !transaction_valid(transition.active_transaction(), runtime.collection_monotonic_ns())) {
		return status::invalid_argument("RuntimeTelemetry active transaction is malformed");
	}
	if (transition.has_active_transaction() &&
	    (transition.active_transaction().outcome() != telemetry::EPOCH_TRANSITION_OUTCOME_NONE ||
	     transition.active_transaction().has_terminal_monotonic_ns())) {
		return status::invalid_argument("RuntimeTelemetry active transaction claims a terminal outcome");
	}
	if (transition.has_latest_terminal() &&
	    (!transaction_valid(transition.latest_terminal(), runtime.collection_monotonic_ns()) ||
	     transition.latest_terminal().outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_NONE)) {
		return status::invalid_argument("RuntimeTelemetry latest terminal transaction is malformed");
	}
	const bool active_state = transition.state() == telemetry::EPOCH_TRANSITION_STATE_PREPARING ||
				  transition.state() == telemetry::EPOCH_TRANSITION_STATE_PREPARED ||
				  transition.state() == telemetry::EPOCH_TRANSITION_STATE_COMMITTING ||
				  transition.state() == telemetry::EPOCH_TRANSITION_STATE_RETIRING ||
				  (transition.state() == telemetry::EPOCH_TRANSITION_STATE_FAILED_STOP &&
				   transition.target_epoch() != 0u);
	if (active_state != transition.has_active_transaction() ||
	    transition.participant_set_frozen() != active_state ||
	    (active_state &&
	     (transition.target_epoch() != transition.active_transaction().to_epoch() ||
	      transition.active_epoch() != transition.active_transaction().from_epoch() ||
	      transition.allocated_epoch_high_watermark() != transition.active_transaction().to_epoch() ||
	      transition.mutation_sequence_high_watermark() != transition.active_transaction().mutation_sequence()))) {
		return status::invalid_argument("RuntimeTelemetry phase and active transaction disagree");
	}
	if ((!active_state && transition.state() != telemetry::EPOCH_TRANSITION_STATE_FAILED_STOP &&
	     transition.target_epoch() != 0u) ||
	    (transition.state() == telemetry::EPOCH_TRANSITION_STATE_IDLE && transition.retirement_frozen()) ||
	    transition.retirement_frozen() !=
		    (transition.has_active_transaction() && transition.active_transaction().retirement_frozen()) ||
	    (transition.terminal_history_size() == 0u) != !transition.has_latest_terminal() ||
	    (transition.has_latest_terminal() &&
	     (transition.latest_terminal().to_epoch() > transition.allocated_epoch_high_watermark() ||
	      transition.latest_terminal().mutation_sequence() > transition.mutation_sequence_high_watermark())) ||
	    (transition.state() == telemetry::EPOCH_TRANSITION_STATE_IDLE && transition.has_latest_terminal() &&
	     ((transition.latest_terminal().outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_COMPLETE &&
	       (transition.latest_terminal().to_epoch() != transition.active_epoch() ||
		transition.latest_terminal().validation_hash() != transition.active_validation_hash())) ||
	      (transition.latest_terminal().outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_ABORTED &&
	       transition.latest_terminal().from_epoch() != transition.active_epoch()) ||
	      transition.latest_terminal().outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_FAILED_STOP))) {
		return status::invalid_argument("RuntimeTelemetry phase, history, or watermark shape is malformed");
	}
	if ((transition.state() == telemetry::EPOCH_TRANSITION_STATE_IDLE &&
	     (transition.active_epoch() != runtime.active_epoch() ||
	      runtime.minimum_retained_epoch() != runtime.active_epoch())) ||
	    ((transition.state() == telemetry::EPOCH_TRANSITION_STATE_PREPARING ||
	      transition.state() == telemetry::EPOCH_TRANSITION_STATE_PREPARED ||
	      transition.state() == telemetry::EPOCH_TRANSITION_STATE_COMMITTING) &&
	     transition.active_epoch() != runtime.active_epoch()) ||
	    (transition.state() == telemetry::EPOCH_TRANSITION_STATE_RETIRING &&
	     (runtime.active_epoch() != transition.target_epoch() ||
	      runtime.minimum_retained_epoch() != transition.active_epoch())) ||
	    (transition.state() == telemetry::EPOCH_TRANSITION_STATE_FAILED_STOP &&
	     !((runtime.active_epoch() == transition.active_epoch() &&
		runtime.minimum_retained_epoch() == transition.active_epoch()) ||
	       (transition.target_epoch() != 0u && runtime.active_epoch() == transition.target_epoch() &&
		runtime.minimum_retained_epoch() == transition.active_epoch()))) ||
	    (transition.has_active_transaction() && transition.has_latest_terminal() &&
	     (transition.active_transaction().mutation_sequence() <= transition.latest_terminal().mutation_sequence() ||
	      transition.active_transaction().to_epoch() <= transition.latest_terminal().to_epoch()))) {
		return status::invalid_argument("RuntimeTelemetry runtime and transition epochs disagree");
	}
	if (transition.has_active_transaction()) {
		const auto &active = transition.active_transaction();
		bool phase_shape = true;
		switch (transition.state()) {
		case telemetry::EPOCH_TRANSITION_STATE_PREPARING:
			phase_shape = !active.has_prepared_monotonic_ns() &&
				      !active.has_prepared_lease_deadline_monotonic_ns() &&
				      !active.has_commit_started_monotonic_ns() &&
				      !active.has_retiring_started_monotonic_ns() &&
				      active.failure_code() == telemetry::EPOCH_TRANSITION_FAILURE_CODE_NONE;
			break;
		case telemetry::EPOCH_TRANSITION_STATE_PREPARED:
			phase_shape = active.has_prepared_monotonic_ns() &&
				      active.has_prepared_lease_deadline_monotonic_ns() &&
				      !active.has_commit_started_monotonic_ns() &&
				      !active.has_retiring_started_monotonic_ns() &&
				      active.failure_code() == telemetry::EPOCH_TRANSITION_FAILURE_CODE_NONE;
			break;
		case telemetry::EPOCH_TRANSITION_STATE_COMMITTING:
			phase_shape = active.has_prepared_monotonic_ns() &&
				      !active.has_prepared_lease_deadline_monotonic_ns() &&
				      active.has_commit_started_monotonic_ns() &&
				      !active.has_retiring_started_monotonic_ns() &&
				      active.failure_code() == telemetry::EPOCH_TRANSITION_FAILURE_CODE_NONE;
			break;
		case telemetry::EPOCH_TRANSITION_STATE_RETIRING:
			phase_shape =
				active.has_prepared_monotonic_ns() &&
				!active.has_prepared_lease_deadline_monotonic_ns() &&
				active.has_commit_started_monotonic_ns() &&
				active.has_retiring_started_monotonic_ns() &&
				(active.failure_code() == telemetry::EPOCH_TRANSITION_FAILURE_CODE_NONE ||
				 (active.retirement_frozen() &&
				  active.failure_code() ==
					  telemetry::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED));
			break;
		case telemetry::EPOCH_TRANSITION_STATE_FAILED_STOP:
			phase_shape = fail_stop_failure(active.failure_code()) &&
				      active.has_failure_observed_monotonic_ns();
			break;
		case telemetry::EPOCH_TRANSITION_STATE_UNSPECIFIED:
		case telemetry::EPOCH_TRANSITION_STATE_AWAITING_BOOTSTRAP:
		case telemetry::EPOCH_TRANSITION_STATE_BOOTSTRAPPING:
		case telemetry::EPOCH_TRANSITION_STATE_IDLE:
		case telemetry::EPOCH_TRANSITION_STATE_COMPLETE:
		case telemetry::EPOCH_TRANSITION_STATE_ABORTED:
		case telemetry::EpochTransitionState_INT_MIN_SENTINEL_DO_NOT_USE_:
		case telemetry::EpochTransitionState_INT_MAX_SENTINEL_DO_NOT_USE_:
			phase_shape = false;
			break;
		}
		if (!phase_shape) {
			return status::invalid_argument("RuntimeTelemetry active transaction is not phase-qualified");
		}
	}
	const bool active_commit_started = transition.has_active_transaction() &&
					   transition.active_transaction().has_commit_started_monotonic_ns();
	const bool committed_phase = transition.state() == telemetry::EPOCH_TRANSITION_STATE_COMMITTING ||
				     transition.state() == telemetry::EPOCH_TRANSITION_STATE_RETIRING;
	if ((committed_phase && !active_commit_started) ||
	    (active_commit_started && !committed_phase &&
	     transition.state() != telemetry::EPOCH_TRANSITION_STATE_FAILED_STOP) ||
	    (active_commit_started && !transition.has_grace())) {
		return status::invalid_argument("RuntimeTelemetry committed transaction lacks exact grace ownership");
	}
	if (transition.has_certificate()) {
		const auto &certificate = transition.certificate();
		const bool fault_index_valid =
			certificate_fault_index_valid(certificate.fault(), certificate.fault_index(),
						      certificate.execution_total(), certificate.boundary_total());
		if (certificate.evaluated_monotonic_ns() == 0u ||
		    certificate.runtime_generation() != runtime.runtime_generation() ||
		    !valid_mutation_sequence(certificate.transition_generation()) ||
		    !valid_epoch_id(certificate.from_epoch()) || !valid_epoch_id(certificate.to_epoch()) ||
		    certificate.to_epoch() <= certificate.from_epoch() ||
		    certificate.execution_complete() > certificate.execution_total() ||
		    certificate.boundary_complete() > certificate.boundary_total() ||
		    certificate.reader_complete() > certificate.reader_total() ||
		    certificate.execution_total() != transition.execution_participant_count() ||
		    certificate.boundary_total() != transition.boundary_count() ||
		    certificate.reader_total() != transition.quiescence_reader_count() ||
		    certificate.evaluated_monotonic_ns() > runtime.collection_monotonic_ns() ||
		    certificate.state() == telemetry::EPOCH_CERTIFICATE_STATE_UNSPECIFIED ||
		    certificate.fault() == telemetry::EPOCH_CERTIFICATE_FAULT_UNSPECIFIED || !fault_index_valid ||
		    ((certificate.state() == telemetry::EPOCH_CERTIFICATE_STATE_CONTRADICTION) !=
		     (certificate.fault() != telemetry::EPOCH_CERTIFICATE_FAULT_NONE)) ||
		    ((certificate.state() == telemetry::EPOCH_CERTIFICATE_STATE_EXECUTION_COMPLETE ||
		      certificate.state() == telemetry::EPOCH_CERTIFICATE_STATE_RECLAMATION_READY) &&
		     (certificate.execution_complete() != certificate.execution_total() ||
		      certificate.boundary_complete() != certificate.boundary_total())) ||
		    (certificate.state() == telemetry::EPOCH_CERTIFICATE_STATE_INCOMPLETE &&
		     certificate.execution_complete() == certificate.execution_total() &&
		     certificate.boundary_complete() == certificate.boundary_total()) ||
		    (certificate.state() == telemetry::EPOCH_CERTIFICATE_STATE_EXECUTION_COMPLETE &&
		     certificate.reader_complete() == certificate.reader_total()) ||
		    (certificate.state() == telemetry::EPOCH_CERTIFICATE_STATE_RECLAMATION_READY &&
		     certificate.reader_complete() != certificate.reader_total())) {
			return status::invalid_argument("RuntimeTelemetry certificate progress is malformed");
		}
		const bool matches_active = transition.has_active_transaction() &&
					    certificate.transition_generation() ==
						    transition.active_transaction().mutation_sequence() &&
					    certificate.from_epoch() == transition.active_transaction().from_epoch() &&
					    certificate.to_epoch() == transition.active_transaction().to_epoch();
		const bool matches_terminal = transition.has_latest_terminal() &&
					      certificate.transition_generation() ==
						      transition.latest_terminal().mutation_sequence() &&
					      certificate.from_epoch() == transition.latest_terminal().from_epoch() &&
					      certificate.to_epoch() == transition.latest_terminal().to_epoch();
		if ((!matches_active && !matches_terminal) || (active_commit_started && !matches_active)) {
			return status::invalid_argument(
				"RuntimeTelemetry certificate lacks an exact transaction owner");
		}
		const auto &owner = matches_active ? transition.active_transaction() : transition.latest_terminal();
		if (certificate.evaluated_monotonic_ns() < owner.admitted_monotonic_ns() ||
		    (owner.has_commit_started_monotonic_ns() &&
		     certificate.evaluated_monotonic_ns() < owner.commit_started_monotonic_ns())) {
			return status::invalid_argument(
				"RuntimeTelemetry certificate timestamp precedes its transaction owner");
		}
	}
	if (transition.has_grace()) {
		const auto &grace = transition.grace();
		const auto *owner = transition.has_active_transaction() &&
						    transition.active_transaction().has_commit_started_monotonic_ns() ?
					    &transition.active_transaction() :
				    transition.has_latest_terminal() &&
						    transition.latest_terminal().has_commit_started_monotonic_ns() ?
					    &transition.latest_terminal() :
					    nullptr;
		if (grace.generation() == 0u || grace.readers_complete() > grace.readers_total() ||
		    grace.readers_total() != transition.quiescence_reader_count() ||
		    !grace.has_started_monotonic_ns() || grace.started_monotonic_ns() == 0u ||
		    grace.started_monotonic_ns() > runtime.collection_monotonic_ns() ||
		    (grace.has_completion_observed_monotonic_ns() &&
		     (grace.completion_observed_monotonic_ns() < grace.started_monotonic_ns() ||
		      grace.completion_observed_monotonic_ns() > runtime.collection_monotonic_ns())) ||
		    (grace.has_finished_monotonic_ns() &&
		     (!grace.has_completion_observed_monotonic_ns() ||
		      grace.finished_monotonic_ns() < grace.completion_observed_monotonic_ns() ||
		      grace.finished_monotonic_ns() > runtime.collection_monotonic_ns())) ||
		    grace.active() == grace.has_finished_monotonic_ns() ||
		    (grace.has_completion_observed_monotonic_ns() &&
		     grace.readers_complete() != grace.readers_total()) ||
		    (grace.update_frozen() && (!grace.active() || !transition.retirement_frozen())) ||
		    (grace.active() && (transition.state() != telemetry::EPOCH_TRANSITION_STATE_COMMITTING &&
					transition.state() != telemetry::EPOCH_TRANSITION_STATE_RETIRING &&
					transition.state() != telemetry::EPOCH_TRANSITION_STATE_FAILED_STOP)) ||
		    (active_commit_started && !grace.active()) || owner == nullptr ||
		    grace.started_monotonic_ns() != owner->commit_started_monotonic_ns() ||
		    (!grace.active() &&
		     (!transition.has_latest_terminal() ||
		      transition.latest_terminal().outcome() != telemetry::EPOCH_TRANSITION_OUTCOME_COMPLETE))) {
			return status::invalid_argument("RuntimeTelemetry grace progress is malformed");
		}
	}
	const auto &faults = value.protocol_faults();
	constexpr int FAULT_COUNT = telemetry::EpochProtocolFaultCode_ARRAYSIZE - 1;
	if (faults.counters_size() != FAULT_COUNT) {
		return status::invalid_argument("RuntimeTelemetry protocol fault membership is incomplete");
	}
	for (int index = 0; index < FAULT_COUNT; ++index) {
		if (faults.counters(index).code() != static_cast<telemetry::EpochProtocolFaultCode>(index + 1)) {
			return status::invalid_argument("RuntimeTelemetry protocol fault order is noncanonical");
		}
	}
	bool any_fault_observed = false;
	bool blocking_fault_observed = false;
	for (int index = 0; index < FAULT_COUNT; ++index) {
		any_fault_observed = any_fault_observed || faults.counters(index).count() != 0u;
		if (faults.counters(index).code() != telemetry::EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED &&
		    faults.counters(index).count() != 0u) {
			blocking_fault_observed = true;
			break;
		}
	}
	if (faults.has_first_fault()) {
		const auto &first = faults.first_fault();
		const bool transition_identity_valid =
			first.transition_generation() == 0u ?
				(first.from_epoch() == 0u || valid_epoch_id(first.from_epoch())) &&
					(first.to_epoch() == 0u || valid_epoch_id(first.to_epoch())) &&
					(first.from_epoch() == 0u || first.to_epoch() == 0u ||
					 first.to_epoch() > first.from_epoch()) :
				valid_mutation_sequence(first.transition_generation()) &&
					valid_epoch_id(first.from_epoch()) && valid_epoch_id(first.to_epoch()) &&
					first.to_epoch() > first.from_epoch();
		if (first.code() == telemetry::EPOCH_PROTOCOL_FAULT_CODE_UNSPECIFIED ||
		    first.disposition() == telemetry::EPOCH_PROTOCOL_FAULT_DISPOSITION_UNSPECIFIED ||
		    first.runtime_generation() != runtime.runtime_generation() || first.observed_monotonic_ns() == 0u ||
		    first.observed_monotonic_ns() > runtime.collection_monotonic_ns() || !transition_identity_valid ||
		    !protocol_fault_identity_shape_valid(first) ||
		    !protocol_fault_disposition_valid(first.code(), first.disposition()) ||
		    faults.counters(static_cast<int>(first.code()) - 1).count() == 0u ||
		    (first.worker_index() != UINT32_MAX &&
		     first.worker_index() >= transition.execution_participant_count()) ||
		    (first.boundary_index() != UINT32_MAX && first.boundary_index() >= transition.boundary_count()) ||
		    (first.context_index() != UINT32_MAX &&
		     first.context_index() >= transition.module_context_count()) ||
		    (first.stage_instance_index() != UINT32_MAX && first.stage_instance_index() > UINT16_MAX) ||
		    ((first.boundary_index() != UINT32_MAX || first.context_index() != UINT32_MAX ||
		      first.stage_instance_index() != UINT32_MAX) &&
		     first.worker_index() == UINT32_MAX) ||
		    (first.boundary_index() != UINT32_MAX && first.context_index() != UINT32_MAX) ||
		    (first.context_index() != UINT32_MAX && first.stage_instance_index() == UINT32_MAX)) {
			return status::invalid_argument("RuntimeTelemetry first protocol fault is malformed");
		}
	}
	if (faults.transition_success_blocked() != blocking_fault_observed ||
	    (any_fault_observed != faults.has_first_fault())) {
		return status::invalid_argument(
			"RuntimeTelemetry transition success block and typed fault counts disagree");
	}

	const bool selection_shape = (selection.include_stage_stats() || value.stages().empty()) &&
				     (selection.include_module_metrics() ||
				      (value.module_counters().empty() && value.module_histograms().empty() &&
				       value.module_epoch_mismatches().empty())) &&
				     (selection.include_module_health() || value.module_health().empty()) &&
				     (selection.include_worker_epoch_stats() || value.workers().empty()) &&
				     (selection.include_region_epoch_stats() || value.regions().empty()) &&
				     (selection.include_boundary_epoch_stats() || value.boundaries().empty()) &&
				     (selection.include_stream_stats() || value.streams().empty()) &&
				     (selection.include_storage_domain_stats() || value.storage_domains().empty()) &&
				     (selection.include_port_stats() || value.ports().empty()) &&
				     (selection.include_topology_stats() ||
				      (value.steering_profiles().empty() && value.module_context_domains().empty()));
	if (!selection_shape) {
		return status::invalid_argument("RuntimeTelemetry contains an unrequested row family");
	}
	if ((selection.include_module_health() &&
	     static_cast<uint32_t>(value.module_health_size()) != transition.module_context_count()) ||
	    (selection.include_module_metrics() &&
	     static_cast<uint32_t>(value.module_epoch_mismatches_size()) != transition.module_context_count()) ||
	    (selection.include_worker_epoch_stats() &&
	     static_cast<uint32_t>(value.workers_size()) != transition.execution_participant_count()) ||
	    (selection.include_region_epoch_stats() &&
	     static_cast<uint32_t>(value.regions_size()) != transition.region_count()) ||
	    (selection.include_boundary_epoch_stats() &&
	     static_cast<uint32_t>(value.boundaries_size()) != transition.boundary_count())) {
		return status::invalid_argument("RuntimeTelemetry selected membership is incomplete");
	}
	using metric_identity = std::pair<uint32_t, std::string_view>;
	const bool unique_rows =
		projected_identities_unique<std::string_view>(
			value.stages(), [](const auto &row) { return std::string_view(row.stage_id()); }) &&
		projected_identities_unique<metric_identity>(
			value.module_counters(),
			[](const auto &row) { return metric_identity{row.context_index(), row.name()}; }) &&
		projected_identities_unique<metric_identity>(
			value.module_histograms(),
			[](const auto &row) { return metric_identity{row.context_index(), row.name()}; }) &&
		projected_identity_sets_disjoint<metric_identity>(
			value.module_counters(), value.module_histograms(),
			[](const auto &row) { return metric_identity{row.context_index(), row.name()}; },
			[](const auto &row) { return metric_identity{row.context_index(), row.name()}; }) &&
		projected_identities_unique<std::string_view>(
			value.module_epoch_mismatches(),
			[](const auto &row) { return std::string_view(row.context_instance_id()); }) &&
		projected_identities_unique<std::string_view>(
			value.module_health(),
			[](const auto &row) { return std::string_view(row.context_instance_id()); }) &&
		projected_identities_unique<std::string_view>(
			value.workers(), [](const auto &row) { return std::string_view(row.worker_id()); }) &&
		projected_identities_unique<std::string_view>(
			value.boundaries(), [](const auto &row) { return std::string_view(row.boundary_id()); }) &&
		projected_identities_unique<std::string_view>(
			value.streams(), [](const auto &row) { return std::string_view(row.io_stream_id()); }) &&
		projected_identities_unique<std::string_view>(value.storage_domains(),
							      [](const auto &row) {
								      return std::string_view(row.storage_domain_id());
							      }) &&
		projected_identities_unique<uint32_t>(value.ports(),
						      [](const auto &row) { return row.logical_port_id(); }) &&
		projected_identities_unique<std::string_view>(
			value.ports(), [](const auto &row) { return std::string_view(row.logical_name()); }) &&
		projected_identities_unique<std::string_view>(
			value.steering_profiles(),
			[](const auto &row) { return std::string_view(row.steering_profile_id()); }) &&
		projected_identities_unique<std::string_view>(value.module_context_domains(), [](const auto &row) {
			return std::string_view(row.module_id());
		});
	if (!unique_rows) {
		return status::invalid_argument("RuntimeTelemetry contains duplicate stable row identity");
	}
	for (const auto &row : value.stages()) {
		if (!identity_present(row.stage_id())) {
			return status::invalid_argument("RuntimeTelemetry contains a stage without identity");
		}
	}
	for (const auto &row : value.module_counters()) {
		if (!module_counter_valid(row) || row.context_index() >= transition.module_context_count() ||
		    row.worker_index() >= transition.execution_participant_count()) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed module counter");
		}
		const auto &identity = value.module_epoch_mismatches(static_cast<int>(row.context_index()));
		if (row.module_id() != identity.module_id() ||
		    row.context_instance_id() != identity.context_instance_id() ||
		    row.worker_index() != identity.worker_index() || row.epoch() != identity.observation_epoch()) {
			return status::invalid_argument("RuntimeTelemetry module counter identity is contradictory");
		}
	}
	for (const auto &row : value.module_histograms()) {
		const bool any_distribution = row.has_minimum() || row.has_maximum() || row.has_p50() ||
					      row.has_p90() || row.has_p99() || row.has_p999();
		const bool complete_distribution = row.has_minimum() && row.has_maximum() && row.has_p50() &&
						   row.has_p90() && row.has_p99() && row.has_p999();
		const bool sum_below_minimum = row.sample_count() != 0u &&
					       (row.minimum() > UINT64_MAX / row.sample_count() ?
							row.sample_sum() != UINT64_MAX :
							row.sample_sum() < row.minimum() * row.sample_count());
		const bool sum_above_maximum = row.sample_count() != 0u &&
					       row.maximum() <= UINT64_MAX / row.sample_count() &&
					       row.sample_sum() > row.maximum() * row.sample_count();
		if (!identity_present(row.module_id()) || !identity_present(row.context_instance_id()) ||
		    !identity_present(row.name()) || !valid_epoch_id(row.epoch()) ||
		    row.context_index() >= transition.module_context_count() ||
		    row.worker_index() >= transition.execution_participant_count() ||
		    (row.sample_count() == 0u && (row.sample_sum() != 0u || any_distribution)) ||
		    (row.sample_count() != 0u &&
		     (!complete_distribution || row.minimum() > row.p50() || row.minimum() > row.maximum() ||
		      row.p50() > row.p90() || row.p90() > row.p99() || row.p99() > row.p999() ||
		      row.p999() > row.maximum() || sum_below_minimum || sum_above_maximum))) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed module histogram");
		}
		const auto &identity = value.module_epoch_mismatches(static_cast<int>(row.context_index()));
		if (row.module_id() != identity.module_id() ||
		    row.context_instance_id() != identity.context_instance_id() ||
		    row.worker_index() != identity.worker_index() || row.epoch() != identity.observation_epoch()) {
			return status::invalid_argument("RuntimeTelemetry module histogram identity is contradictory");
		}
	}
	for (int index = 0; index < value.module_epoch_mismatches_size(); ++index) {
		const auto &row = value.module_epoch_mismatches(index);
		if (!module_mismatch_valid(row) || row.context_index() != static_cast<uint32_t>(index) ||
		    row.worker_index() >= transition.execution_participant_count() ||
		    (row.has_first_stage_instance_index() && row.first_stage_instance_index() > UINT16_MAX)) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed module mismatch row");
		}
	}
	for (int index = 0; index < value.module_health_size(); ++index) {
		const auto &row = value.module_health(index);
		const bool current_attempt = row.state() == telemetry::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE ||
					     row.state() == telemetry::MODULE_HEALTH_STATE_ATTEMPT_SUPPRESSED;
		const bool stale_attempt = row.state() == telemetry::MODULE_HEALTH_STATE_STALE_EPOCH;
		if (!module_health_valid(row) || row.context_index() != static_cast<uint32_t>(index) ||
		    row.worker_index() >= transition.execution_participant_count() ||
		    row.stage_instance_index() > UINT16_MAX ||
		    (current_attempt && row.observation_epoch() != runtime.active_epoch()) ||
		    (stale_attempt && row.observation_epoch() >= runtime.active_epoch()) ||
		    (row.has_observed_at_ns() && row.observed_at_ns() > runtime.collection_monotonic_ns()) ||
		    (row.has_first_fault_timestamp_ns() &&
		     row.first_fault_timestamp_ns() > runtime.collection_monotonic_ns())) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed module health row");
		}
		if (selection.include_module_metrics()) {
			const auto &identity = value.module_epoch_mismatches(index);
			if (row.module_id() != identity.module_id() ||
			    row.context_instance_id() != identity.context_instance_id() ||
			    row.worker_index() != identity.worker_index()) {
				return status::invalid_argument(
					"RuntimeTelemetry module health identity is contradictory");
			}
		}
	}
	for (int index = 0; index < value.workers_size(); ++index) {
		const auto &row = value.workers(index);
		if (!worker_valid(row) || row.worker_index() != static_cast<uint32_t>(index) ||
		    row.worker_index() >= transition.execution_participant_count() ||
		    static_cast<uint32_t>(row.region_id()) >= transition.region_count() ||
		    (row.has_activation_monotonic_ns() &&
		     row.activation_monotonic_ns() > runtime.collection_monotonic_ns())) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed worker epoch row");
		}
		if (active_commit_started) {
			const auto &active = transition.active_transaction();
			if ((row.has_transition_generation() &&
			     row.transition_generation() > active.mutation_sequence()) ||
			    (row.has_transition_generation() &&
			     row.transition_generation() == active.mutation_sequence() &&
			     (row.from_epoch() != active.from_epoch() || row.to_epoch() != active.to_epoch())) ||
			    (transition.state() == telemetry::EPOCH_TRANSITION_STATE_RETIRING &&
			     (!row.has_transition_generation() ||
			      row.transition_generation() != active.mutation_sequence()))) {
				return status::invalid_argument(
					"RuntimeTelemetry worker activation contradicts the committed transaction");
			}
		} else if (transition.has_latest_terminal() &&
			   transition.latest_terminal().outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_COMPLETE &&
			   (!row.has_transition_generation() ||
			    row.transition_generation() != transition.latest_terminal().mutation_sequence() ||
			    row.from_epoch() != transition.latest_terminal().from_epoch() ||
			    row.to_epoch() != transition.latest_terminal().to_epoch())) {
			return status::invalid_argument(
				"RuntimeTelemetry worker activation contradicts the latest completed transaction");
		}
	}
	for (int index = 0; index < value.regions_size(); ++index) {
		const auto &row = value.regions(index);
		if (!region_valid(row) || row.region_id() != index ||
		    (row.has_maximum_activation_monotonic_ns() &&
		     row.maximum_activation_monotonic_ns() > runtime.collection_monotonic_ns())) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed region epoch row");
		}
	}
	if (selection.include_region_epoch_stats()) {
		uint64_t worker_population = 0u;
		uint64_t region_fanout_overflow = 0u;
		for (const auto &region : value.regions()) {
			add_saturating(worker_population, region.worker_count());
			add_saturating(region_fanout_overflow, region.fanout_overflow());
		}
		if (worker_population != transition.execution_participant_count() ||
		    region_fanout_overflow != value.engine().fanout_overflow()) {
			return status::invalid_argument(
				"RuntimeTelemetry region derivation disagrees with mandatory engine truth");
		}
	}
	if (selection.include_worker_epoch_stats() && selection.include_region_epoch_stats()) {
		for (const auto &region : value.regions()) {
			uint32_t worker_count = 0u;
			uint32_t activated = 0u;
			uint64_t minimum_active = UINT64_MAX;
			uint64_t maximum_active = 0u;
			uint64_t minimum_source = UINT64_MAX;
			uint64_t maximum_source = 0u;
			uint64_t active_unretired = 0u;
			uint64_t future_unretired = 0u;
			uint64_t minimum_activation = UINT64_MAX;
			uint64_t maximum_activation = 0u;
			for (const auto &worker : value.workers()) {
				if (worker.region_id() != region.region_id()) {
					continue;
				}
				++worker_count;
				minimum_active = std::min(minimum_active, worker.active_epoch());
				maximum_active = std::max(maximum_active, worker.active_epoch());
				minimum_source = std::min(minimum_source, worker.source_epoch());
				maximum_source = std::max(maximum_source, worker.source_epoch());
				add_saturating(active_unretired, worker.active_unretired());
				add_saturating(future_unretired, worker.future_unretired());
				if (worker.activation_complete()) {
					++activated;
					minimum_activation =
						std::min(minimum_activation, worker.activation_monotonic_ns());
					maximum_activation =
						std::max(maximum_activation, worker.activation_monotonic_ns());
				}
			}
			const bool timing_matches =
				activated == 0u ?
					!region.has_minimum_activation_monotonic_ns() &&
						!region.has_maximum_activation_monotonic_ns() :
					region.has_minimum_activation_monotonic_ns() &&
						region.has_maximum_activation_monotonic_ns() &&
						region.minimum_activation_monotonic_ns() == minimum_activation &&
						region.maximum_activation_monotonic_ns() == maximum_activation;
			if (worker_count != region.worker_count() || minimum_active != region.minimum_active_epoch() ||
			    maximum_active != region.maximum_active_epoch() ||
			    minimum_source != region.minimum_source_epoch() ||
			    maximum_source != region.maximum_source_epoch() ||
			    active_unretired != region.active_unretired() ||
			    future_unretired != region.future_unretired() ||
			    activated != region.activated_participants() || !timing_matches) {
				return status::invalid_argument(
					"RuntimeTelemetry worker and region observations disagree");
			}
		}
	}
	for (int index = 0; index < value.boundaries_size(); ++index) {
		const auto &row = value.boundaries(index);
		if (!boundary_valid(row, runtime.collection_monotonic_ns()) ||
		    row.boundary_index() != static_cast<uint32_t>(index) ||
		    row.boundary_index() >= transition.boundary_count() ||
		    row.sender_worker_index() >= transition.execution_participant_count() ||
		    row.receiver_worker_index() >= transition.execution_participant_count()) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed boundary epoch row");
		}
		if (active_commit_started &&
		    (!row.has_transition_generation() ||
		     row.transition_generation() != transition.active_transaction().mutation_sequence() ||
		     row.from_epoch() != transition.active_transaction().from_epoch() ||
		     row.to_epoch() != transition.active_transaction().to_epoch())) {
			return status::invalid_argument(
				"RuntimeTelemetry boundary has not reached the committed transaction");
		}
		if (!active_commit_started && transition.has_latest_terminal() &&
		    transition.latest_terminal().outcome() == telemetry::EPOCH_TRANSITION_OUTCOME_COMPLETE &&
		    (!row.has_transition_generation() ||
		     row.transition_generation() != transition.latest_terminal().mutation_sequence() ||
		     row.from_epoch() != transition.latest_terminal().from_epoch() ||
		     row.to_epoch() != transition.latest_terminal().to_epoch())) {
			return status::invalid_argument(
				"RuntimeTelemetry boundary contradicts the latest completed transaction");
		}
		if (selection.include_worker_epoch_stats() &&
		    (value.workers(static_cast<int>(row.sender_worker_index())).region_id() != row.from_region_id() ||
		     value.workers(static_cast<int>(row.receiver_worker_index())).region_id() != row.to_region_id())) {
			return status::invalid_argument(
				"RuntimeTelemetry boundary and worker ownership projections disagree");
		}
	}
	uint64_t stream_rx_packets = 0u;
	uint64_t stream_rx_bytes = 0u;
	uint64_t stream_tx_packets = 0u;
	uint64_t stream_tx_bytes = 0u;
	for (const auto &row : value.streams()) {
		if (!stream_valid(row) || row.owning_region_id() < 0 ||
		    static_cast<uint32_t>(row.owning_region_id()) >= transition.region_count() ||
		    row.worker_index() >= transition.execution_participant_count() ||
		    row.published_monotonic_ns() > runtime.latest_bank_publication_monotonic_ns() ||
		    row.published_monotonic_ns() > runtime.collection_monotonic_ns()) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed stream observation");
		}
		if (selection.include_worker_epoch_stats() &&
		    value.workers(static_cast<int>(row.worker_index())).region_id() != row.owning_region_id()) {
			return status::invalid_argument(
				"RuntimeTelemetry stream and worker ownership projections disagree");
		}
		if (row.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
			add_saturating(stream_rx_packets, row.packets());
			add_saturating(stream_rx_bytes, row.bytes());
		} else {
			add_saturating(stream_tx_packets, row.packets());
			add_saturating(stream_tx_bytes, row.bytes());
		}
	}
	if (selection.include_stream_stats() &&
	    (stream_rx_packets == UINT64_MAX || stream_rx_bytes == UINT64_MAX || stream_tx_packets == UINT64_MAX ||
	     stream_tx_bytes == UINT64_MAX || stream_rx_packets != value.engine().rx_packets() ||
	     stream_rx_bytes != value.engine().rx_bytes() || stream_tx_packets != value.engine().tx_packets() ||
	     stream_tx_bytes != value.engine().tx_bytes())) {
		return status::invalid_argument("RuntimeTelemetry engine and software stream totals disagree");
	}
	for (const auto &row : value.storage_domains()) {
		if (!storage_valid(row) || (row.has_host_numa_node() && row.host_numa_node() < 0) ||
		    (row.has_observed_monotonic_ns() &&
		     row.observed_monotonic_ns() > runtime.collection_monotonic_ns())) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed storage observation");
		}
	}
	for (const auto &row : value.ports()) {
		if (!port_valid(row) || (row.has_observed_monotonic_ns() &&
					 row.observed_monotonic_ns() > runtime.collection_monotonic_ns())) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed port observation");
		}
	}
	if (selection.include_stream_stats() && selection.include_port_stats()) {
		std::vector<uint32_t> port_ids;
		port_ids.reserve(static_cast<std::size_t>(value.ports_size()));
		for (const auto &port : value.ports()) {
			port_ids.push_back(port.logical_port_id());
		}
		std::sort(port_ids.begin(), port_ids.end());
		for (const auto &stream : value.streams()) {
			if (!std::binary_search(port_ids.begin(), port_ids.end(), stream.logical_port_id())) {
				return status::invalid_argument(
					"RuntimeTelemetry stream references an unknown selected logical port");
			}
		}
	}
	using stream_identity = std::pair<std::string_view, kinetum::gluon::v1::IoStreamDirection>;
	std::vector<stream_identity> stream_identities;
	if (selection.include_stream_stats() && selection.include_topology_stats()) {
		stream_identities.reserve(static_cast<std::size_t>(value.streams_size()));
		for (const auto &stream : value.streams()) {
			stream_identities.emplace_back(stream.io_stream_id(), stream.direction());
		}
		std::sort(stream_identities.begin(), stream_identities.end());
	}
	const auto find_stream = [&stream_identities](std::string_view stream_id) {
		return std::lower_bound(stream_identities.begin(), stream_identities.end(), stream_id,
					[](const stream_identity &entry, std::string_view candidate) {
						return entry.first < candidate;
					});
	};
	for (const auto &row : value.steering_profiles()) {
		if (!identity_present(row.steering_profile_id()) || !steering_kind_valid(row.kind()) ||
		    row.io_stream_ids().empty() || !strictly_increasing_text(row.io_stream_ids())) {
			return status::invalid_argument("RuntimeTelemetry contains a malformed steering projection");
		}
		if (selection.include_stream_stats()) {
			for (const auto &stream_id : row.io_stream_ids()) {
				const auto found = find_stream(stream_id);
				if (found == stream_identities.end() || found->first != stream_id) {
					return status::invalid_argument(
						"RuntimeTelemetry steering profile references an unknown selected stream");
				}
			}
		}
	}
	return validate_module_context_domains(value, selection, transition.module_context_count());
}

status validate_runtime_telemetry(const kinetum::telemetry::v1::RuntimeTelemetry &value,
				  const kinetum::telemetry::v1::TelemetrySelection &selection)
{
	try {
		return validate_runtime_telemetry_impl(value, selection);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(
			"RuntimeTelemetry identity validation exhausted bounded scratch memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      "RuntimeTelemetry identity population exceeds the host size domain");
	}
}

status validate_failed_dataplane_stats_response(const kinetum::dataplane::v1::StatsResponse &response)
{
	try {
		const auto unknown =
			reject_unknown_protobuf_fields_recursive(response, "failed dataplane StatsResponse");
		if (!unknown.is_ok()) {
			return unknown;
		}
		const auto enums =
			reject_invalid_protobuf_enum_values_recursive(response, "failed dataplane StatsResponse");
		if (!enums.is_ok()) {
			return enums;
		}
		status_code code{};
		if (!response.has_status() || !decode_exact_application_status(response.status(), code) ||
		    code == status_code::OK || response.has_telemetry()) {
			return status::invalid_argument(
				"failed dataplane StatsResponse requires only a canonical failure status");
		}
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("dataplane statistics failure validation exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "dataplane statistics failure exceeds the host size domain");
	}
}

status validate_successful_dataplane_stats_response(const kinetum::dataplane::v1::StatsResponse &response,
						    const kinetum::telemetry::v1::TelemetrySelection &selection)
{
	try {
		auto unknown = reject_unknown_protobuf_fields_recursive(response, "dataplane StatsResponse");
		if (!unknown.is_ok()) {
			return unknown;
		}
		auto enums = reject_invalid_protobuf_enum_values_recursive(response, "dataplane StatsResponse");
		if (!enums.is_ok()) {
			return enums;
		}
		if (!canonical_success_status(response.status()) || !response.has_telemetry()) {
			return status::invalid_argument(
				"successful dataplane StatsResponse requires canonical status and telemetry");
		}
		return validate_runtime_telemetry(response.telemetry(), selection);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("dataplane statistics response validation exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "dataplane statistics response exceeds the host size domain");
	}
}

status validate_successful_control_stats_response(const kinetum::control::v1::StatsResponse &response,
						  const kinetum::telemetry::v1::TelemetrySelection &selection)
{
	try {
		auto unknown = reject_unknown_protobuf_fields_recursive(response, "control StatsResponse");
		if (!unknown.is_ok()) {
			return unknown;
		}
		auto enums = reject_invalid_protobuf_enum_values_recursive(response, "control StatsResponse");
		if (!enums.is_ok()) {
			return enums;
		}
		if (!canonical_success_status(response.status()) || !response.has_active_config() ||
		    !response.has_telemetry()) {
			return status::invalid_argument(
				"successful control StatsResponse requires active configuration and telemetry");
		}
		const auto &active = response.active_config();
		if (!valid_config_snapshot_id(active.snapshot_id()) ||
		    !valid_config_snapshot_revision(active.revision())) {
			return status::invalid_argument("control StatsResponse active configuration is malformed");
		}
		return validate_runtime_telemetry(response.telemetry(), selection);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("control statistics response validation exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "control statistics response exceeds the host size domain");
	}
}

}  // namespace kinetum::common
