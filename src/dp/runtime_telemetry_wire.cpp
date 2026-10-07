// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_telemetry_wire.cpp
 * @brief Final all-or-none runtime telemetry wire mapping.
 * @author Fleming Patel
 */

#include "src/dp/runtime_telemetry_wire.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <string_view>

#include "src/common/runtime_telemetry_contract.hpp"
#include "src/common/sha256.hpp"

namespace kinetum::dp
{
namespace
{

namespace wire = kinetum::telemetry::v1;

static_assert(EPOCH_PROTOCOL_FAULT_COUNT + 1u == static_cast<std::size_t>(wire::EpochProtocolFaultCode_ARRAYSIZE),
	      "internal and wire protocol-fault vocabularies must remain total");

/**
 * @brief Map one internal transition phase without a fallback value.
 * @param phase Declared internal coordinator phase.
 * @return Exact public transition-state counterpart.
 */
[[nodiscard]] wire::EpochTransitionState transition_state(epoch_transition_phase phase) noexcept
{
	switch (phase) {
	case epoch_transition_phase::AWAITING_BOOTSTRAP:
		return wire::EPOCH_TRANSITION_STATE_AWAITING_BOOTSTRAP;
	case epoch_transition_phase::BOOTSTRAPPING:
		return wire::EPOCH_TRANSITION_STATE_BOOTSTRAPPING;
	case epoch_transition_phase::IDLE:
		return wire::EPOCH_TRANSITION_STATE_IDLE;
	case epoch_transition_phase::PREPARING:
		return wire::EPOCH_TRANSITION_STATE_PREPARING;
	case epoch_transition_phase::PREPARED:
		return wire::EPOCH_TRANSITION_STATE_PREPARED;
	case epoch_transition_phase::COMMITTING:
		return wire::EPOCH_TRANSITION_STATE_COMMITTING;
	case epoch_transition_phase::RETIRING:
		return wire::EPOCH_TRANSITION_STATE_RETIRING;
	case epoch_transition_phase::FAILED_STOP:
		return wire::EPOCH_TRANSITION_STATE_FAILED_STOP;
	}
	std::terminate();
}

/**
 * @brief Map one internal terminal outcome without a fallback value.
 * @param outcome Declared internal terminal outcome.
 * @return Exact public transition-outcome counterpart.
 */
[[nodiscard]] wire::EpochTransitionOutcome transition_outcome(epoch_transition_outcome outcome) noexcept
{
	switch (outcome) {
	case epoch_transition_outcome::NONE:
		return wire::EPOCH_TRANSITION_OUTCOME_NONE;
	case epoch_transition_outcome::COMPLETE:
		return wire::EPOCH_TRANSITION_OUTCOME_COMPLETE;
	case epoch_transition_outcome::ABORTED:
		return wire::EPOCH_TRANSITION_OUTCOME_ABORTED;
	case epoch_transition_outcome::FAILED_STOP:
		return wire::EPOCH_TRANSITION_OUTCOME_FAILED_STOP;
	}
	std::terminate();
}

/**
 * @brief Map one internal failure code without parsing diagnostics.
 * @param failure Declared internal transition failure.
 * @return Exact public failure-code counterpart.
 */
[[nodiscard]] wire::EpochTransitionFailureCode transition_failure(epoch_transition_failure_code failure) noexcept
{
	switch (failure) {
	case epoch_transition_failure_code::NONE:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_NONE;
	case epoch_transition_failure_code::EXPLICIT_ABORT:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT;
	case epoch_transition_failure_code::SHUTDOWN_ABORT:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT;
	case epoch_transition_failure_code::PREPARE_FAILURE:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE;
	case epoch_transition_failure_code::PREPARE_CANCELLED:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED;
	case epoch_transition_failure_code::PREPARE_DEADLINE_EXCEEDED:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED;
	case epoch_transition_failure_code::PREPARED_LEASE_EXPIRED:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED;
	case epoch_transition_failure_code::COMMIT_DEADLINE_EXCEEDED:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED;
	case epoch_transition_failure_code::CERTIFICATE_CONTRADICTION:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION;
	case epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED;
	case epoch_transition_failure_code::RETIRE_CALLBACK_FAILURE:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE;
	case epoch_transition_failure_code::RETIRE_CALLBACK_DEADLINE_EXCEEDED:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED;
	case epoch_transition_failure_code::COMMIT_SHUTDOWN:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN;
	case epoch_transition_failure_code::PROTOCOL_FAULT:
		return wire::EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT;
	}
	std::terminate();
}

/**
 * @brief Map one internal certificate state without a fallback value.
 * @param state Declared internal certificate state.
 * @return Exact public certificate-state counterpart.
 */
[[nodiscard]] wire::EpochCertificateState certificate_state(epoch_transition_certificate_state state) noexcept
{
	switch (state) {
	case epoch_transition_certificate_state::INCOMPLETE:
		return wire::EPOCH_CERTIFICATE_STATE_INCOMPLETE;
	case epoch_transition_certificate_state::EXECUTION_COMPLETE:
		return wire::EPOCH_CERTIFICATE_STATE_EXECUTION_COMPLETE;
	case epoch_transition_certificate_state::RECLAMATION_READY:
		return wire::EPOCH_CERTIFICATE_STATE_RECLAMATION_READY;
	case epoch_transition_certificate_state::CONTRADICTION:
		return wire::EPOCH_CERTIFICATE_STATE_CONTRADICTION;
	}
	std::terminate();
}

/**
 * @brief Map one internal certificate fault without a fallback value.
 * @param fault Declared internal certificate fault.
 * @return Exact public certificate-fault counterpart.
 */
[[nodiscard]] wire::EpochCertificateFault certificate_fault(epoch_transition_certificate_fault fault) noexcept
{
	switch (fault) {
	case epoch_transition_certificate_fault::NONE:
		return wire::EPOCH_CERTIFICATE_FAULT_NONE;
	case epoch_transition_certificate_fault::REQUEST_IDENTITY:
		return wire::EPOCH_CERTIFICATE_FAULT_REQUEST_IDENTITY;
	case epoch_transition_certificate_fault::EXECUTION_MEMBERSHIP:
		return wire::EPOCH_CERTIFICATE_FAULT_EXECUTION_MEMBERSHIP;
	case epoch_transition_certificate_fault::EXECUTION_STATE:
		return wire::EPOCH_CERTIFICATE_FAULT_EXECUTION_STATE;
	case epoch_transition_certificate_fault::BOUNDARY_MEMBERSHIP:
		return wire::EPOCH_CERTIFICATE_FAULT_BOUNDARY_MEMBERSHIP;
	case epoch_transition_certificate_fault::BOUNDARY_STATE:
		return wire::EPOCH_CERTIFICATE_FAULT_BOUNDARY_STATE;
	case epoch_transition_certificate_fault::CUT_IDENTITY:
		return wire::EPOCH_CERTIFICATE_FAULT_CUT_IDENTITY;
	case epoch_transition_certificate_fault::READER_MEMBERSHIP:
		return wire::EPOCH_CERTIFICATE_FAULT_READER_MEMBERSHIP;
	}
	std::terminate();
}

/**
 * @brief Map one sender phase without a fallback value.
 * @param phase Declared sender-policy phase.
 * @return Exact public sender-phase counterpart.
 */
[[nodiscard]] wire::BoundarySenderPhase sender_phase(boundary_epoch_sender_phase phase) noexcept
{
	switch (phase) {
	case boundary_epoch_sender_phase::UNBOUND:
		return wire::BOUNDARY_SENDER_PHASE_UNBOUND;
	case boundary_epoch_sender_phase::OPEN:
		return wire::BOUNDARY_SENDER_PHASE_OPEN;
	case boundary_epoch_sender_phase::DRAINING:
		return wire::BOUNDARY_SENDER_PHASE_DRAINING;
	case boundary_epoch_sender_phase::CUT_PENDING:
		return wire::BOUNDARY_SENDER_PHASE_CUT_PENDING;
	case boundary_epoch_sender_phase::WAITING_ACK:
		return wire::BOUNDARY_SENDER_PHASE_WAITING_ACK;
	}
	std::terminate();
}

/**
 * @brief Map one receiver phase without a fallback value.
 * @param phase Declared receiver-policy phase.
 * @return Exact public receiver-phase counterpart.
 */
[[nodiscard]] wire::BoundaryReceiverPhase receiver_phase(boundary_epoch_receiver_phase phase) noexcept
{
	switch (phase) {
	case boundary_epoch_receiver_phase::UNBOUND:
		return wire::BOUNDARY_RECEIVER_PHASE_UNBOUND;
	case boundary_epoch_receiver_phase::OPEN:
		return wire::BOUNDARY_RECEIVER_PHASE_OPEN;
	case boundary_epoch_receiver_phase::WAITING_CUT:
		return wire::BOUNDARY_RECEIVER_PHASE_WAITING_CUT;
	case boundary_epoch_receiver_phase::CUT_DRAINING:
		return wire::BOUNDARY_RECEIVER_PHASE_CUT_DRAINING;
	case boundary_epoch_receiver_phase::CUT_DRAINED:
		return wire::BOUNDARY_RECEIVER_PHASE_CUT_DRAINED;
	case boundary_epoch_receiver_phase::ACK_PENDING:
		return wire::BOUNDARY_RECEIVER_PHASE_ACK_PENDING;
	case boundary_epoch_receiver_phase::ACK_PUBLISHED:
		return wire::BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED;
	}
	std::terminate();
}

/**
 * @brief Map one provider ABI availability state without a fallback value.
 * @param state Declared provider ABI observation state.
 * @return Exact provider-neutral wire counterpart.
 */
[[nodiscard]] wire::ProviderObservationState provider_state(kinetum_provider_observation_state state) noexcept
{
	switch (state) {
	case KINETUM_PROVIDER_OBSERVATION_AVAILABLE_EXACT:
		return wire::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT;
	case KINETUM_PROVIDER_OBSERVATION_AVAILABLE_APPROXIMATE:
		return wire::PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE;
	case KINETUM_PROVIDER_OBSERVATION_UNSUPPORTED:
		return wire::PROVIDER_OBSERVATION_STATE_UNSUPPORTED;
	case KINETUM_PROVIDER_OBSERVATION_READ_FAILED:
		return wire::PROVIDER_OBSERVATION_STATE_READ_FAILED;
	default:
		std::terminate();
	}
}

/**
 * @brief Map one compact internal protocol-fault code.
 * @param code Declared internal protocol-fault code.
 * @return Exact compact public counterpart.
 */
[[nodiscard]] wire::EpochProtocolFaultCode protocol_fault(epoch_protocol_fault_code code) noexcept
{
	switch (code) {
	case epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH;
	case epoch_protocol_fault_code::OLD_DATA_AFTER_SEAL:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_OLD_DATA_AFTER_SEAL;
	case epoch_protocol_fault_code::FUTURE_DATA_BEFORE_ACK:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_FUTURE_DATA_BEFORE_ACK;
	case epoch_protocol_fault_code::CUT_IDENTITY_MISMATCH:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_CUT_IDENTITY_MISMATCH;
	case epoch_protocol_fault_code::ACK_BEFORE_ACTIVATION:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_ACTIVATION;
	case epoch_protocol_fault_code::ACK_BEFORE_CUT_DRAIN:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_CUT_DRAIN;
	case epoch_protocol_fault_code::RETIREMENT_BEFORE_QUIESCENCE:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_RETIREMENT_BEFORE_QUIESCENCE;
	case epoch_protocol_fault_code::OWNERSHIP_UNDERFLOW:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_UNDERFLOW;
	case epoch_protocol_fault_code::OWNERSHIP_OVERFLOW:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_OVERFLOW;
	case epoch_protocol_fault_code::OWNERSHIP_DOUBLE_RETIRE:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_DOUBLE_RETIRE;
	case epoch_protocol_fault_code::OWNERSHIP_WRONG_SLOT:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_WRONG_SLOT;
	case epoch_protocol_fault_code::SEQUENCE_EXHAUSTED:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_SEQUENCE_EXHAUSTED;
	case epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED:
		return wire::EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED;
	}
	std::terminate();
}

/**
 * @brief Map one internal protocol-fault disposition.
 * @param disposition Declared internal immediate disposition.
 * @return Exact public disposition counterpart.
 */
[[nodiscard]] wire::EpochProtocolFaultDisposition
protocol_disposition(epoch_protocol_fault_disposition disposition) noexcept
{
	switch (disposition) {
	case epoch_protocol_fault_disposition::DROP_AND_RETIRE:
		return wire::EPOCH_PROTOCOL_FAULT_DISPOSITION_DROP_AND_RETIRE;
	case epoch_protocol_fault_disposition::TERMINATE:
		return wire::EPOCH_PROTOCOL_FAULT_DISPOSITION_TERMINATE;
	case epoch_protocol_fault_disposition::RESOURCE_REFUSED:
		return wire::EPOCH_PROTOCOL_FAULT_DISPOSITION_RESOURCE_REFUSED;
	}
	std::terminate();
}

/**
 * @brief Check whether a sender has captured its exact cut.
 * @param sender Coherent sender transition observation.
 * @return true after the sender captured one exact cut, including cut zero.
 */
[[nodiscard]] bool sender_has_cut(const boundary_sender_transition_snapshot &sender) noexcept
{
	return sender.transition_generation != 0u && sender.phase != boundary_epoch_sender_phase::DRAINING;
}

/**
 * @brief Check whether a receiver has accepted its exact cut.
 * @param receiver Coherent receiver transition observation.
 * @return true after the receiver accepted one exact cut, including cut zero.
 */
[[nodiscard]] bool receiver_has_cut(const boundary_receiver_transition_snapshot &receiver) noexcept
{
	return receiver.transition_generation != 0u && receiver.phase != boundary_epoch_receiver_phase::WAITING_CUT;
}

/**
 * @brief Copy one exact internal transaction into caller-owned wire storage.
 * @param source Present, validated transaction observation.
 * @param[out] target Nonnull empty transaction destination.
 */
void populate_transaction(const epoch_transition_telemetry_transaction_snapshot &source,
			  wire::EpochTransactionTelemetry *target)
{
	if (!source.present || target == nullptr) {
		std::terminate();
	}
	target->set_mutation_sequence(source.identity.mutation_sequence);
	target->set_from_epoch(source.from_epoch);
	target->set_to_epoch(source.to_epoch);
	target->set_validation_hash(reinterpret_cast<const char *>(source.identity.validation_hash.data()),
				    source.identity.validation_hash.size());
	target->set_idempotency_key_digest(
		reinterpret_cast<const char *>(source.identity.idempotency_key_digest.data()),
		source.identity.idempotency_key_digest.size());
	target->set_admitted_monotonic_ns(source.admitted_monotonic_ns);
	if (source.prepared_monotonic_ns != 0u) {
		target->set_prepared_monotonic_ns(source.prepared_monotonic_ns);
	}
	if (source.prepared_lease_deadline_monotonic_ns != 0u) {
		target->set_prepared_lease_deadline_monotonic_ns(source.prepared_lease_deadline_monotonic_ns);
		target->set_prepared_lease_deadline_unix_ms(source.prepared_lease_deadline_unix_ms);
	}
	if (source.commit_started_monotonic_ns != 0u) {
		target->set_commit_started_monotonic_ns(source.commit_started_monotonic_ns);
	}
	if (source.retiring_started_monotonic_ns != 0u) {
		target->set_retiring_started_monotonic_ns(source.retiring_started_monotonic_ns);
	}
	if (source.failure_observed_monotonic_ns != 0u) {
		target->set_failure_observed_monotonic_ns(source.failure_observed_monotonic_ns);
	}
	if (source.terminal_monotonic_ns != 0u) {
		target->set_terminal_monotonic_ns(source.terminal_monotonic_ns);
	}
	target->set_outcome(transition_outcome(source.outcome));
	target->set_failure_code(transition_failure(source.failure_code));
	target->set_retirement_frozen(source.retirement_frozen);
}

/**
 * @brief Derive one nonnegative duration from a causally ordered timestamp pair.
 * @param begin Exact nonzero beginning sample.
 * @param end Exact ending sample.
 * @param[out] duration Destination changed only for a valid pair.
 * @return OK with the exact difference, or DATA_LOSS for malformed timing.
 */
[[nodiscard]] common::status checked_duration(uint64_t begin, uint64_t end, uint64_t *duration) noexcept
{
	if (duration == nullptr || begin == 0u || end < begin) {
		return common::status::data_loss(kinetum::common::static_status_text(
			"runtime telemetry transition timestamps contradict causal order"));
	}
	*duration = end - begin;
	return common::status::ok();
}

}  // namespace

common::status populate_runtime_telemetry_wire(const runtime_telemetry_snapshot &snapshot,
					       const kinetum::telemetry::v1::TelemetrySelection &selection,
					       kinetum::telemetry::v1::RuntimeTelemetry *output)
{
	if (output == nullptr) {
		return common::status::invalid_argument("runtime telemetry wire output is null");
	}
	auto *caller_output = output;
	caller_output->Clear();
	wire::RuntimeTelemetry candidate;
	output = &candidate;
	try {
		const auto &status = snapshot.runtime_status;
		if (status.runtime_generation == 0u || snapshot.collection_monotonic_ns == 0u ||
		    snapshot.latest_bank_publication_monotonic_ns == 0u ||
		    snapshot.latest_bank_publication_monotonic_ns > snapshot.collection_monotonic_ns) {
			return common::status::data_loss("runtime telemetry source lacks exact collection provenance");
		}
		auto *runtime = output->mutable_runtime();
		runtime->set_runtime_generation(status.runtime_generation);
		runtime->set_status_publication_generation(status.publication_generation);
		runtime->set_active_epoch(status.active_epoch);
		runtime->set_minimum_retained_epoch(status.minimum_retained_epoch);
		runtime->set_last_activated_epoch(status.last_activated_epoch);
		runtime->set_active_workers(status.active_workers);
		runtime->set_expected_workers(status.expected_workers);
		runtime->set_collection_monotonic_ns(snapshot.collection_monotonic_ns);
		runtime->set_latest_bank_publication_monotonic_ns(snapshot.latest_bank_publication_monotonic_ns);
		runtime->set_skipped_publications(snapshot.skipped_publications);

		auto *engine = output->mutable_engine();
		engine->set_rx_packets(snapshot.engine.rx_packets);
		engine->set_tx_packets(snapshot.engine.tx_packets);
		engine->set_dropped_packets(snapshot.engine.dropped_packets);
		engine->set_rx_bytes(snapshot.engine.rx_bytes);
		engine->set_tx_bytes(snapshot.engine.tx_bytes);
		engine->set_fanout_overflow(snapshot.engine.fanout_overflow);

		auto plan_hash_or = common::hex_to_bytes(snapshot.plan_content_hash);
		if (!plan_hash_or.is_ok() || plan_hash_or->size() != common::SHA256_DIGEST_SIZE) {
			return common::status::data_loss("runtime telemetry plan-content hash is malformed");
		}
		const auto &progress = snapshot.transition_progress;
		const auto &transactions = snapshot.transition_transactions;
		if (progress.publication_generation == 0u ||
		    progress.publication_generation != transactions.publication_generation) {
			return common::status::unavailable(
				"runtime telemetry transition publications are not one generation");
		}
		auto *transition = output->mutable_transition();
		transition->set_publication_generation(progress.publication_generation);
		transition->set_state(transition_state(progress.phase));
		transition->set_active_epoch(progress.active_epoch);
		transition->set_target_epoch(progress.target_epoch);
		transition->set_allocated_epoch_high_watermark(progress.allocated_epoch_high_watermark);
		transition->set_mutation_sequence_high_watermark(progress.mutation_sequence_high_watermark);
		transition->set_plan_content_hash(reinterpret_cast<const char *>(plan_hash_or->data()),
						  plan_hash_or->size());
		transition->set_active_validation_hash(
			reinterpret_cast<const char *>(progress.active_validation_hash.data()),
			progress.active_validation_hash.size());
		transition->set_participant_set_frozen(progress.participants_frozen);
		transition->set_execution_participant_count(progress.execution_participant_count);
		transition->set_region_count(progress.region_count);
		transition->set_boundary_count(progress.boundary_count);
		transition->set_source_participant_count(progress.source_participant_count);
		transition->set_sink_participant_count(progress.sink_participant_count);
		transition->set_module_context_count(progress.module_context_count);
		transition->set_quiescence_reader_count(progress.quiescence_reader_count);
		transition->set_terminal_history_size(progress.terminal_history_size);
		transition->set_retirement_frozen(progress.retirement_frozen);
		if (transactions.active.present) {
			populate_transaction(transactions.active, transition->mutable_active_transaction());
		}
		if (transactions.latest_terminal.present) {
			populate_transaction(transactions.latest_terminal, transition->mutable_latest_terminal());
		}
		if (snapshot.completion_progress.has_value()) {
			const auto &completion = *snapshot.completion_progress;
			const bool matches_active = transactions.active.present &&
						    completion.transition_generation ==
							    transactions.active.identity.mutation_sequence &&
						    completion.from_epoch == transactions.active.from_epoch &&
						    completion.to_epoch == transactions.active.to_epoch;
			const bool matches_terminal = transactions.latest_terminal.present &&
						      completion.transition_generation ==
							      transactions.latest_terminal.identity.mutation_sequence &&
						      completion.from_epoch ==
							      transactions.latest_terminal.from_epoch &&
						      completion.to_epoch == transactions.latest_terminal.to_epoch;
			if (!matches_active && !matches_terminal) {
				return common::status::data_loss(
					"runtime completion progress lacks one exact transaction owner");
			}
			if ((matches_active || matches_terminal) && completion.evaluated_monotonic_ns != 0u) {
				auto *certificate = transition->mutable_certificate();
				certificate->set_evaluated_monotonic_ns(completion.evaluated_monotonic_ns);
				certificate->set_runtime_generation(completion.runtime_generation);
				certificate->set_transition_generation(completion.transition_generation);
				certificate->set_from_epoch(completion.from_epoch);
				certificate->set_to_epoch(completion.to_epoch);
				certificate->set_execution_complete(completion.execution_complete);
				certificate->set_execution_total(completion.execution_total);
				certificate->set_boundary_complete(completion.boundary_complete);
				certificate->set_boundary_total(completion.boundary_total);
				certificate->set_reader_complete(completion.reader_complete);
				certificate->set_reader_total(completion.reader_total);
				certificate->set_fault_index(completion.fault_index);
				certificate->set_state(certificate_state(completion.certificate_state));
				certificate->set_fault(certificate_fault(completion.certificate_fault));
			}
			if ((matches_active || matches_terminal) && completion.grace_generation != 0u) {
				auto *grace = transition->mutable_grace();
				grace->set_generation(completion.grace_generation);
				grace->set_started_monotonic_ns(completion.grace_started_monotonic_ns);
				if (completion.grace_completion_observed_monotonic_ns != 0u) {
					grace->set_completion_observed_monotonic_ns(
						completion.grace_completion_observed_monotonic_ns);
				}
				if (completion.grace_finished_monotonic_ns != 0u) {
					grace->set_finished_monotonic_ns(completion.grace_finished_monotonic_ns);
				}
				grace->set_readers_complete(completion.reader_complete);
				grace->set_readers_total(completion.reader_total);
				grace->set_active(completion.grace_finished_monotonic_ns == 0u);
				grace->set_update_frozen(completion.update_frozen);
			}
		}

		auto *faults = output->mutable_protocol_faults();
		faults->set_transition_success_blocked(snapshot.transition_success_blocked);
		for (std::size_t index = 0u; index < snapshot.protocol_fault_counts.size(); ++index) {
			auto *counter = faults->add_counters();
			counter->set_code(protocol_fault(static_cast<epoch_protocol_fault_code>(index + 1u)));
			counter->set_count(snapshot.protocol_fault_counts[index]);
		}
		if (snapshot.first_protocol_fault.has_value()) {
			const auto &source = *snapshot.first_protocol_fault;
			auto *first = faults->mutable_first_fault();
			first->set_code(protocol_fault(source.code));
			first->set_disposition(protocol_disposition(source.disposition));
			first->set_runtime_generation(source.runtime_generation);
			first->set_transition_generation(source.transition_generation);
			first->set_from_epoch(source.from_epoch);
			first->set_to_epoch(source.to_epoch);
			first->set_observed_epoch(source.observed_epoch);
			first->set_worker_index(source.worker_index);
			first->set_boundary_index(source.boundary_index);
			first->set_context_index(source.context_index);
			first->set_stage_instance_index(source.stage_instance_index);
			first->set_expected_value(source.expected_value);
			first->set_observed_value(source.observed_value);
			first->set_observed_monotonic_ns(source.observed_monotonic_ns);
		}

		for (const auto &row : snapshot.stages) {
			auto *target = output->add_stages();
			target->set_stage_id(row.stage_id);
			target->set_in_packets(row.in_packets);
			target->set_out_packets(row.out_packets);
			target->set_dropped_packets(row.dropped_packets);
			target->set_in_bytes(row.in_bytes);
			target->set_out_bytes(row.out_bytes);
		}
		for (const auto &row : snapshot.module_counters) {
			auto *target = output->add_module_counters();
			target->set_module_id(row.module_id);
			target->set_context_instance_id(row.context_instance_id);
			target->set_context_index(row.context_index);
			target->set_worker_index(row.worker_index);
			target->set_epoch(row.epoch);
			target->set_name(row.name);
			target->set_value(row.value);
		}
		for (const auto &row : snapshot.module_histograms) {
			if (row.count == 0u && (row.sum != 0u || row.minimum != UINT64_MAX || row.maximum != 0u ||
						row.p50 != 0u || row.p90 != 0u || row.p99 != 0u || row.p999 != 0u)) {
				return common::status::data_loss(
					"empty module histogram retained nonempty distribution state");
			}
			auto *target = output->add_module_histograms();
			target->set_module_id(row.module_id);
			target->set_context_instance_id(row.context_instance_id);
			target->set_context_index(row.context_index);
			target->set_worker_index(row.worker_index);
			target->set_epoch(row.epoch);
			target->set_name(row.name);
			target->set_sample_count(row.count);
			target->set_sample_sum(row.sum);
			if (row.count != 0u) {
				target->set_minimum(row.minimum);
				target->set_maximum(row.maximum);
				target->set_p50(row.p50);
				target->set_p90(row.p90);
				target->set_p99(row.p99);
				target->set_p999(row.p999);
			}
		}
		for (const auto &row : snapshot.module_epoch_mismatches) {
			if (!row.first_fault_valid &&
			    (row.mismatch_count != 0u || row.packet_epoch != 0u || row.active_epoch != 0u ||
			     row.stage_instance_index != 0u || row.region_id != -1)) {
				return common::status::data_loss(
					"module mismatch row retained identity without a first fault");
			}
			auto *target = output->add_module_epoch_mismatches();
			target->set_module_id(row.module_id);
			target->set_context_instance_id(row.context_instance_id);
			target->set_context_index(row.context_index);
			target->set_worker_index(row.worker_index);
			target->set_observation_epoch(row.observation_epoch);
			target->set_mismatch_count(row.mismatch_count);
			if (row.first_fault_valid) {
				target->set_first_packet_epoch(row.packet_epoch);
				target->set_first_active_epoch(row.active_epoch);
				target->set_first_stage_instance_index(row.stage_instance_index);
				target->set_first_region_id(row.region_id);
			}
		}
		for (const auto &row : snapshot.module_health) {
			const kinetum_health_signal zero_signal{};
			if ((row.publication_generation == 0u &&
			     (row.observation_epoch != 0u || row.observed_at_ns != 0u ||
			      row.callback_duration_ns != 0u)) ||
			    (!row.signal_available &&
			     std::memcmp(&row.signal, &zero_signal, sizeof(row.signal)) != 0)) {
				return common::status::data_loss(
					"module health row retained unavailable attempt or signal state");
			}
			auto *target = output->add_module_health();
			target->set_module_id(row.module_id);
			target->set_context_instance_id(row.context_instance_id);
			target->set_context_index(row.context_index);
			target->set_worker_index(row.worker_index);
			target->set_stage_instance_index(row.stage_instance_index);
			wire::ModuleHealthState health_state = wire::MODULE_HEALTH_STATE_AWAITING_OBSERVATION;
			if (!row.callback_available) {
				health_state = wire::MODULE_HEALTH_STATE_CALLBACK_UNAVAILABLE;
			} else if (row.publication_generation == 0u) {
				health_state = wire::MODULE_HEALTH_STATE_AWAITING_OBSERVATION;
			} else if (row.observation_epoch != status.active_epoch) {
				health_state = wire::MODULE_HEALTH_STATE_STALE_EPOCH;
			} else if (row.signal_available) {
				health_state = wire::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE;
			} else {
				health_state = wire::MODULE_HEALTH_STATE_ATTEMPT_SUPPRESSED;
			}
			target->set_state(health_state);
			target->set_publication_generation(row.publication_generation);
			if (row.publication_generation != 0u) {
				target->set_observation_epoch(row.observation_epoch);
				target->set_observed_at_ns(row.observed_at_ns);
				target->set_callback_duration_ns(row.callback_duration_ns);
			}
			target->set_contract_fault_count(row.contract_fault_count);
			target->set_latest_fault_mask(row.latest_fault_mask);
			target->set_first_fault_mask(row.first_fault_mask);
			if (row.first_fault_mask != 0u) {
				target->set_first_fault_epoch(row.first_fault_epoch);
				target->set_first_fault_timestamp_ns(row.first_fault_timestamp_ns);
				target->set_first_fault_duration_ns(row.first_fault_duration_ns);
			}
			if (health_state == wire::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE) {
				target->set_health_score(row.signal.assessment.health_score);
				target->set_health_flags(row.signal.assessment.flags);
				const auto *terminator = static_cast<const char *>(std::memchr(
					row.signal.assessment.reason, '\0', sizeof(row.signal.assessment.reason)));
				if (terminator == nullptr) {
					return common::status::data_loss(
						"module health reason lost its bounded terminator");
				}
				target->set_reason(row.signal.assessment.reason,
						   static_cast<std::size_t>(terminator - row.signal.assessment.reason));
			}
		}

		for (const auto &row : snapshot.workers) {
			auto *target = output->add_workers();
			target->set_worker_id(row.worker_id);
			target->set_worker_index(row.worker_index);
			target->set_region_id(row.region_id);
			target->set_lane_id(row.lane_id);
			target->set_ledger_publication_generation(row.ledger.publication_generation);
			target->set_active_epoch(row.ledger.active_epoch);
			target->set_source_epoch(row.ledger.source_epoch);
			target->set_active_unretired(row.ledger.active_unretired);
			if (row.ledger.future_epoch != 0u) {
				target->set_future_epoch(row.ledger.future_epoch);
			}
			target->set_future_unretired(row.ledger.future_unretired);
			target->set_activation_publication_generation(row.activation.publication_generation);
			if (row.activation.transition_generation != 0u) {
				target->set_transition_generation(row.activation.transition_generation);
				target->set_from_epoch(row.activation.from_epoch);
				target->set_to_epoch(row.activation.to_epoch);
				target->set_activation_monotonic_ns(row.activation.activation_monotonic_ns);
			}
			target->set_activation_complete(row.activation.activation_complete == 1u);
		}
		for (const auto &row : snapshot.regions) {
			auto *target = output->add_regions();
			target->set_region_id(row.region_id);
			target->set_worker_count(row.worker_count);
			target->set_minimum_active_epoch(row.minimum_active_epoch);
			target->set_maximum_active_epoch(row.maximum_active_epoch);
			target->set_minimum_source_epoch(row.minimum_source_epoch);
			target->set_maximum_source_epoch(row.maximum_source_epoch);
			target->set_active_unretired(row.active_unretired);
			target->set_future_unretired(row.future_unretired);
			target->set_activated_participants(row.activated_participants);
			if (row.minimum_activation_monotonic_ns.has_value()) {
				if (!row.maximum_activation_monotonic_ns.has_value()) {
					return common::status::data_loss(
						"region activation timing lost its maximum endpoint");
				}
				target->set_minimum_activation_monotonic_ns(*row.minimum_activation_monotonic_ns);
				target->set_maximum_activation_monotonic_ns(*row.maximum_activation_monotonic_ns);
			}
			target->set_fanout_overflow(row.fanout_overflow);
		}
		for (const auto &row : snapshot.boundaries) {
			const auto &sender = row.observation.sender;
			const auto &receiver = row.observation.receiver;
			const auto &sender_transport = row.observation.sender_transport;
			const auto &receiver_transport = row.observation.receiver_transport;
			auto *target = output->add_boundaries();
			target->set_boundary_id(row.boundary_id);
			target->set_boundary_index(row.boundary_index);
			target->set_from_stage_instance_index(row.from_stage_instance_index);
			target->set_to_stage_instance_index(row.to_stage_instance_index);
			target->set_sender_worker_index(row.sender_worker_index);
			target->set_receiver_worker_index(row.receiver_worker_index);
			target->set_from_region_id(row.from_region_id);
			target->set_to_region_id(row.to_region_id);
			target->set_data_ring_capacity(row.data_ring_capacity);
			target->set_future_output_hold_capacity(row.future_output_hold_capacity);
			target->set_data_enqueued_sequence(sender_transport.data_enqueued_sequence);
			target->set_data_dequeued_sequence(receiver_transport.data_dequeued_sequence);
			target->set_data_backpressure_events(sender_transport.data_backpressure_events);
			if (sender_transport.pending_cut_epoch != 0u) {
				target->set_pending_cut_epoch(sender_transport.pending_cut_epoch);
				target->set_pending_cut_sequence(sender_transport.pending_cut_sequence);
			}
			if (receiver_transport.pending_ack_epoch != 0u) {
				target->set_pending_ack_epoch(receiver_transport.pending_ack_epoch);
				target->set_pending_ack_sequence(receiver_transport.pending_ack_sequence);
			}
			target->set_sender_phase(sender_phase(sender.phase));
			target->set_receiver_phase(receiver_phase(receiver.phase));
			target->set_duplicate_cut_count(receiver.duplicate_cut_count);
			target->set_duplicate_ack_count(sender.duplicate_ack_count);
			const bool same_generation = sender.transition_generation != 0u &&
						     sender.transition_generation == receiver.transition_generation;
			if (same_generation) {
				const bool sender_cut = sender_has_cut(sender);
				const bool receiver_cut = receiver_has_cut(receiver);
				if (sender.from_epoch != receiver.from_epoch || sender.to_epoch != receiver.to_epoch ||
				    sender.to_epoch <= sender.from_epoch ||
				    (sender_cut && receiver_cut && sender.cut_sequence != receiver.cut_sequence)) {
					return common::status::data_loss(
						"boundary transition publications contradict identity");
				}
				target->set_transition_generation(sender.transition_generation);
				target->set_from_epoch(sender.from_epoch);
				target->set_to_epoch(sender.to_epoch);
				if (sender_cut || receiver_cut) {
					target->set_cut_sequence(sender_cut ? sender.cut_sequence :
									      receiver.cut_sequence);
				}
			} else if (sender.transition_generation != 0u || receiver.transition_generation != 0u) {
				return common::status::unavailable(
					"boundary endpoint transition publications are not one generation");
			}
			if (!same_generation &&
			    (sender.cut_published_monotonic_ns != 0u || receiver.cut_observed_monotonic_ns != 0u ||
			     receiver.cut_drained_monotonic_ns != 0u || receiver.activation_monotonic_ns != 0u ||
			     receiver.ack_published_monotonic_ns != 0u || sender.ack_observed_monotonic_ns != 0u)) {
				return common::status::data_loss(
					"boundary transition timing lacks one exact endpoint generation");
			}
			if (same_generation &&
			    ((receiver.cut_observed_monotonic_ns != 0u && sender.cut_published_monotonic_ns == 0u) ||
			     (sender.ack_observed_monotonic_ns != 0u && receiver.ack_published_monotonic_ns == 0u))) {
				return common::status::unavailable(
					"boundary causal edge publications are temporally misaligned");
			}
			if (same_generation && sender.cut_published_monotonic_ns != 0u) {
				target->set_cut_published_monotonic_ns(sender.cut_published_monotonic_ns);
			}
			if (same_generation && receiver.cut_observed_monotonic_ns != 0u) {
				target->set_cut_observed_monotonic_ns(receiver.cut_observed_monotonic_ns);
			}
			if (same_generation && receiver.cut_drained_monotonic_ns != 0u) {
				target->set_cut_drained_monotonic_ns(receiver.cut_drained_monotonic_ns);
			}
			if (same_generation && receiver.activation_monotonic_ns != 0u) {
				target->set_activation_monotonic_ns(receiver.activation_monotonic_ns);
			}
			if (same_generation && receiver.ack_published_monotonic_ns != 0u) {
				target->set_ack_published_monotonic_ns(receiver.ack_published_monotonic_ns);
			}
			if (same_generation && sender.ack_observed_monotonic_ns != 0u) {
				target->set_ack_observed_monotonic_ns(sender.ack_observed_monotonic_ns);
			}
			uint64_t duration = 0u;
			if (same_generation && sender.cut_published_monotonic_ns != 0u &&
			    receiver.cut_observed_monotonic_ns != 0u) {
				auto valid = checked_duration(sender.cut_published_monotonic_ns,
							      receiver.cut_observed_monotonic_ns, &duration);
				if (!valid.is_ok()) {
					return valid;
				}
				target->set_cut_delivery_duration_ns(duration);
			}
			if (same_generation && receiver.cut_observed_monotonic_ns != 0u &&
			    receiver.cut_drained_monotonic_ns != 0u) {
				auto valid = checked_duration(receiver.cut_observed_monotonic_ns,
							      receiver.cut_drained_monotonic_ns, &duration);
				if (!valid.is_ok()) {
					return valid;
				}
				target->set_cut_drain_duration_ns(duration);
			}
			if (same_generation && sender.cut_published_monotonic_ns != 0u &&
			    sender.ack_observed_monotonic_ns != 0u) {
				auto valid = checked_duration(sender.cut_published_monotonic_ns,
							      sender.ack_observed_monotonic_ns, &duration);
				if (!valid.is_ok()) {
					return valid;
				}
				target->set_ack_gate_duration_ns(duration);
			}
		}

		for (const auto &row : snapshot.streams) {
			if (row.published_monotonic_ns == 0u || row.packets == UINT64_MAX || row.bytes == UINT64_MAX ||
			    row.rejected_packets == UINT64_MAX || ((row.packets == 0u) != (row.bytes == 0u)) ||
			    row.bytes < row.packets) {
				return common::status::data_loss(
					"stream software accounting is incomplete or exhausted");
			}
			auto *target = output->add_streams();
			target->set_io_stream_id(row.io_stream_id);
			target->set_logical_port_id(row.logical_port_id);
			target->set_direction(row.direction);
			target->set_owning_region_id(row.owning_region_id);
			target->set_worker_index(row.worker_index);
			target->set_driver_queue_id(row.driver_queue_id);
			target->set_published_monotonic_ns(row.published_monotonic_ns);
			target->set_packets(row.packets);
			target->set_bytes(row.bytes);
			target->set_rejected_packets(row.rejected_packets);
		}
		for (const auto &row : snapshot.storage_domains) {
			const bool any_values = row.observed_monotonic_ns.has_value() || row.in_use.has_value() ||
						row.available.has_value();
			const bool complete_values = row.observed_monotonic_ns.has_value() && row.in_use.has_value() &&
						     row.available.has_value();
			if (!kinetum_provider_observation_state_is_valid(row.observation_state) ||
			    any_values != complete_values) {
				return common::status::data_loss("storage provider observation has partial values");
			}
			auto *target = output->add_storage_domains();
			target->set_storage_domain_id(row.storage_domain_id);
			if (row.host_numa_node.has_value()) {
				target->set_host_numa_node(*row.host_numa_node);
			}
			target->set_buffer_count(row.buffer_count);
			target->set_required_min_buffers(row.required_min_buffers);
			target->set_safety_margin(row.safety_margin);
			target->set_observation_state(provider_state(row.observation_state));
			if (row.observed_monotonic_ns.has_value()) {
				target->set_observed_monotonic_ns(*row.observed_monotonic_ns);
				target->set_in_use(*row.in_use);
				target->set_available(*row.available);
			}
		}
		for (const auto &row : snapshot.ports) {
			const bool any_values = row.observed_monotonic_ns.has_value() || row.rx_packets.has_value() ||
						row.tx_packets.has_value() || row.rx_bytes.has_value() ||
						row.tx_bytes.has_value() || row.rx_missed.has_value() ||
						row.rx_errors.has_value() || row.tx_errors.has_value() ||
						row.rx_no_buffer.has_value();
			const bool complete_values = row.observed_monotonic_ns.has_value() &&
						     row.rx_packets.has_value() && row.tx_packets.has_value() &&
						     row.rx_bytes.has_value() && row.tx_bytes.has_value() &&
						     row.rx_missed.has_value() && row.rx_errors.has_value() &&
						     row.tx_errors.has_value() && row.rx_no_buffer.has_value();
			if (!kinetum_provider_observation_state_is_valid(row.observation_state) ||
			    any_values != complete_values) {
				return common::status::data_loss("port provider observation has partial values");
			}
			auto *target = output->add_ports();
			target->set_logical_port_id(row.logical_port_id);
			target->set_logical_name(row.logical_name);
			target->set_io_driver_instance_id(row.io_driver_instance_id);
			target->set_driver_port_id(row.driver_port_id);
			target->set_observation_state(provider_state(row.observation_state));
			if (row.observed_monotonic_ns.has_value()) {
				target->set_observed_monotonic_ns(*row.observed_monotonic_ns);
				target->set_rx_packets(*row.rx_packets);
				target->set_tx_packets(*row.tx_packets);
				target->set_rx_bytes(*row.rx_bytes);
				target->set_tx_bytes(*row.tx_bytes);
				target->set_rx_missed(*row.rx_missed);
				target->set_rx_errors(*row.rx_errors);
				target->set_tx_errors(*row.tx_errors);
				target->set_rx_no_buffer(*row.rx_no_buffer);
			}
		}
		for (const auto &row : snapshot.steering_profiles) {
			auto *target = output->add_steering_profiles();
			target->set_steering_profile_id(row.steering_profile_id);
			target->set_kind(row.kind);
			target->set_symmetric(row.symmetric);
			for (const auto &stream : row.io_stream_ids) {
				target->add_io_stream_ids(stream);
			}
		}
		for (const auto &row : snapshot.module_context_domains) {
			auto *target = output->add_module_context_domains();
			target->set_module_id(row.module_id);
			for (const auto &identity : row.context_instance_ids) {
				target->add_context_instance_ids(identity);
			}
		}
		auto validated = common::validate_runtime_telemetry(*output, selection);
		if (!validated.is_ok()) {
			output->Clear();
			if (validated.code() == common::status_code::RESOURCE_EXHAUSTED ||
			    validated.code() == common::status_code::OUT_OF_RANGE) {
				return validated;
			}
			return common::status::data_loss("runtime telemetry wire mapping failed intrinsic validation");
		}
		caller_output->Swap(output);
		return common::status::ok();
	} catch (const std::bad_alloc &) {
		output->Clear();
		return common::status::resource_exhausted("runtime telemetry protobuf mapping exhausted memory");
	} catch (const std::length_error &) {
		output->Clear();
		return common::status(common::status_code::OUT_OF_RANGE,
				      "runtime telemetry protobuf extent exceeds the host size domain");
	} catch (...) {
		output->Clear();
		return common::status::internal_error(
			"runtime telemetry protobuf mapping raised an unexpected library exception");
	}
}

}  // namespace kinetum::dp
