// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file epoch_transition_coordinator.cpp
 * @brief Sole epoch-transition coordinator implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/epoch_transition_coordinator.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "src/common/time.hpp"
#include "src/common/transition_topology.hpp"
#include "src/provider/compiled_provider_topology.hpp"

namespace kinetum::dp
{
namespace
{

/** @brief Fixed uint64 field count for one transaction telemetry projection. */
constexpr std::size_t TRANSACTION_TELEMETRY_FIELDS = 24u;

/**
 * @brief Convert one fixed digest into four lossless publication words.
 * @param digest Exact digest bytes to encode.
 * @return Four native words retaining every digest bit.
 */
[[nodiscard]] std::array<uint64_t, 4> digest_words(const common::sha256_digest &digest) noexcept
{
	return std::bit_cast<std::array<uint64_t, 4>>(digest);
}

/**
 * @brief Reconstruct one fixed digest from four publication words.
 * @param words Borrowed array containing at least four encoded words.
 * @return Digest reconstructed without changing its bytes.
 */
[[nodiscard]] common::sha256_digest digest_from_words(const uint64_t *words) noexcept
{
	std::array<uint64_t, 4> input{};
	std::copy_n(words, input.size(), input.begin());
	return std::bit_cast<common::sha256_digest>(input);
}

/**
 * @brief Test whether a fixed digest carries no published identity.
 * @param digest Candidate fixed-width content identity.
 * @return true only when every byte is zero.
 */
[[nodiscard]] bool digest_is_zero(const common::sha256_digest &digest) noexcept
{
	return std::all_of(digest.begin(), digest.end(), [](uint8_t value) { return value == 0u; });
}

/**
 * @brief Encode one fixed transaction observation into atomic publication words.
 * @param value Coherent transaction observation to publish.
 * @return Fixed-width field array consumed by the snapshot publication.
 */
[[nodiscard]] std::array<uint64_t, TRANSACTION_TELEMETRY_FIELDS>
encode_transaction(const epoch_transition_telemetry_transaction_snapshot &value) noexcept
{
	const auto validation = digest_words(value.identity.validation_hash);
	const auto key = digest_words(value.identity.idempotency_key_digest);
	return {
		value.present ? 1u : 0u,
		value.identity.mutation_sequence,
		value.identity.target_epoch,
		validation[0],
		validation[1],
		validation[2],
		validation[3],
		key[0],
		key[1],
		key[2],
		key[3],
		value.from_epoch,
		value.to_epoch,
		value.admitted_monotonic_ns,
		value.prepared_monotonic_ns,
		value.prepared_lease_deadline_monotonic_ns,
		value.prepared_lease_deadline_unix_ms,
		value.commit_started_monotonic_ns,
		value.retiring_started_monotonic_ns,
		value.failure_observed_monotonic_ns,
		value.terminal_monotonic_ns,
		static_cast<uint64_t>(value.outcome),
		static_cast<uint64_t>(value.failure_code),
		value.retirement_frozen ? 1u : 0u,
	};
}

/**
 * @brief Decode one fixed transaction observation from publication words.
 * @param fields Borrowed complete field array from one coherent publication.
 * @return Reconstructed transaction observation.
 */
[[nodiscard]] epoch_transition_telemetry_transaction_snapshot decode_transaction(const uint64_t *fields) noexcept
{
	return epoch_transition_telemetry_transaction_snapshot{
		.present = fields[0] == 1u,
		.identity =
			common::epoch_transition_identity{
				.mutation_sequence = fields[1],
				.target_epoch = fields[2],
				.validation_hash = digest_from_words(fields + 3),
				.idempotency_key_digest = digest_from_words(fields + 7),
			},
		.from_epoch = fields[11],
		.to_epoch = fields[12],
		.admitted_monotonic_ns = fields[13],
		.prepared_monotonic_ns = fields[14],
		.prepared_lease_deadline_monotonic_ns = fields[15],
		.prepared_lease_deadline_unix_ms = fields[16],
		.commit_started_monotonic_ns = fields[17],
		.retiring_started_monotonic_ns = fields[18],
		.failure_observed_monotonic_ns = fields[19],
		.terminal_monotonic_ns = fields[20],
		.outcome = static_cast<epoch_transition_outcome>(fields[21]),
		.failure_code = static_cast<epoch_transition_failure_code>(fields[22]),
		.retirement_frozen = fields[23] == 1u,
	};
}

using kinetum::common::status;
using kinetum::common::status_code;

/**
 * @brief Require one host count to fit the fixed progress publication.
 *
 * @param count Candidate immutable population.
 * @return Exact compact count; terminates when the compiled population cannot
 *         fit the fixed publication.
 */
[[nodiscard]] uint32_t progress_count_or_terminate(std::size_t count) noexcept
{
	if (count > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
		std::terminate();
	}
	return static_cast<uint32_t>(count);
}

/**
 * @brief Decode one raw phase field without accepting undeclared values.
 *
 * @param raw Published integer representation.
 * @param out Decoded destination.
 * @return true for one exact enum value.
 */
[[nodiscard]] bool decode_phase(uint64_t raw, epoch_transition_phase &out) noexcept
{
	if (raw > static_cast<uint64_t>(epoch_transition_phase::FAILED_STOP)) {
		return false;
	}
	out = static_cast<epoch_transition_phase>(raw);
	return true;
}

/**
 * @brief Decode one terminal outcome without accepting undeclared values.
 *
 * @param raw Published integer representation.
 * @param out Decoded destination.
 * @return true for one exact enum value.
 */
[[nodiscard]] bool decode_outcome(uint64_t raw, epoch_transition_outcome &out) noexcept
{
	if (raw > static_cast<uint64_t>(epoch_transition_outcome::FAILED_STOP)) {
		return false;
	}
	out = static_cast<epoch_transition_outcome>(raw);
	return true;
}

/**
 * @brief Require one typed fail-stop cause to match its exact active phase.
 * @param phase Current global transition phase.
 * @param code Candidate non-freeze failure classification.
 * @return true only for one legal phase/category pair.
 */
[[nodiscard]] constexpr bool failure_matches_phase(epoch_transition_phase phase,
						   epoch_transition_failure_code code) noexcept
{
	if (code == epoch_transition_failure_code::PROTOCOL_FAULT) {
		return phase == epoch_transition_phase::PREPARING || phase == epoch_transition_phase::PREPARED ||
		       phase == epoch_transition_phase::COMMITTING || phase == epoch_transition_phase::RETIRING;
	}
	if (phase == epoch_transition_phase::PREPARING || phase == epoch_transition_phase::PREPARED) {
		return is_precommit_failure(code);
	}
	if (phase == epoch_transition_phase::COMMITTING) {
		return code == epoch_transition_failure_code::COMMIT_DEADLINE_EXCEEDED ||
		       code == epoch_transition_failure_code::CERTIFICATE_CONTRADICTION ||
		       code == epoch_transition_failure_code::COMMIT_SHUTDOWN;
	}
	if (phase == epoch_transition_phase::RETIRING) {
		return code == epoch_transition_failure_code::CERTIFICATE_CONTRADICTION ||
		       code == epoch_transition_failure_code::RETIRE_CALLBACK_FAILURE ||
		       code == epoch_transition_failure_code::RETIRE_CALLBACK_DEADLINE_EXCEEDED;
	}
	return false;
}

}  // namespace

common::status_or<std::unique_ptr<epoch_transition_coordinator>>
epoch_transition_coordinator::create(const provider::compiled_provider_topology &topology)
{
	const bool enabled = topology.transition_topology.policy.enabled;
	const uint32_t history_capacity = topology.transition_topology.policy.result_history_capacity;
	if (!enabled && history_capacity != 0u) {
		return status::invalid_argument(
			"coordinator terminal history capacity disagrees with transition policy");
	}
	if (enabled && (history_capacity < common::MIN_TRANSITION_RESULT_HISTORY_CAPACITY ||
			history_capacity > common::MAX_TRANSITION_RESULT_HISTORY_CAPACITY)) {
		return status(status_code::OUT_OF_RANGE,
			      "coordinator terminal history capacity is outside the closed range 1..64");
	}
	const auto prepared_lease_timeout = topology.transition_topology.policy.prepared_lease_timeout;
	if ((enabled && prepared_lease_timeout <= std::chrono::steady_clock::duration::zero()) ||
	    (!enabled && prepared_lease_timeout != std::chrono::steady_clock::duration::zero())) {
		return status::invalid_argument(
			"coordinator prepared-lease policy disagrees with transition enablement");
	}
	auto participants_or = frozen_transition_participants::create(topology);
	if (!participants_or.is_ok()) {
		return participants_or.error();
	}
	try {
		return std::unique_ptr<epoch_transition_coordinator>(new epoch_transition_coordinator(
			std::move(participants_or).value(), enabled, history_capacity, prepared_lease_timeout));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate epoch transition coordinator");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "epoch transition coordinator exceeds host containers");
	}
}

epoch_transition_coordinator::epoch_transition_coordinator(
	std::unique_ptr<const frozen_transition_participants> participants, bool transitions_enabled,
	uint32_t history_capacity, std::chrono::steady_clock::duration prepared_lease_timeout)
	: participants_(std::move(participants))
	, terminal_history_(history_capacity)
	, prepared_lease_timeout_(prepared_lease_timeout)
	, transitions_enabled_(transitions_enabled)
{
	if (!participants_) {
		std::terminate();
	}
	publish_progress_or_terminate_();
}

epoch_transition_coordinator::~epoch_transition_coordinator()
{
	const auto current = state_.phase();
	const bool destructible_phase =
		(current == epoch_transition_phase::AWAITING_BOOTSTRAP && state_.active_epoch() == 0u &&
		 state_.target_epoch() == 0u && state_.identity() == nullptr) ||
		(current == epoch_transition_phase::IDLE && common::valid_epoch_id(state_.active_epoch()) &&
		 state_.target_epoch() == 0u && state_.identity() == nullptr);
	const bool watermark_state_valid =
		(current == epoch_transition_phase::AWAITING_BOOTSTRAP && !watermarks_.valid()) ||
		(current == epoch_transition_phase::IDLE &&
		 common::valid_bootstrap_watermarks(state_.active_epoch(), watermarks_));
	if (active_generation_.has_value() || bootstrap_publication_preflighted_ || !snapshots_.empty() ||
	    abort_cleanup_in_progress_ || completion_armed_ || !destructible_phase || !watermark_state_valid) {
		std::terminate();
	}
}

const frozen_transition_participants &epoch_transition_coordinator::participants() const noexcept
{
	return *participants_;
}

status epoch_transition_coordinator::bind_protocol_faults(uint64_t runtime_generation,
							  epoch_protocol_fault_latch &faults) noexcept
{
	if (runtime_generation == 0u || runtime_generation > std::numeric_limits<uint32_t>::max()) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"transition coordinator protocol-fault generation is outside the exact domain"));
	}
	if (protocol_faults_ == nullptr && protocol_runtime_generation_ == 0u) {
		protocol_faults_ = &faults;
		protocol_runtime_generation_ = runtime_generation;
		return status::ok();
	}
	return protocol_faults_ == &faults && protocol_runtime_generation_ == runtime_generation ?
		       status::ok() :
		       status::failed_precondition(kinetum::common::static_status_text(
			       "transition coordinator protocol-fault authority changed identity"));
}

bool epoch_transition_coordinator::owns_protocol_faults(uint64_t runtime_generation,
							const epoch_protocol_fault_latch &faults) const noexcept
{
	return protocol_runtime_generation_ == runtime_generation && protocol_faults_ == &faults;
}

epoch_transition_phase epoch_transition_coordinator::phase() const noexcept
{
	return state_.phase();
}

uint64_t epoch_transition_coordinator::active_epoch() const noexcept
{
	return state_.active_epoch();
}

bool epoch_transition_coordinator::snapshot_store_empty() const noexcept
{
	return snapshots_.empty();
}

uint64_t epoch_transition_coordinator::prepared_snapshot_epoch() const noexcept
{
	return snapshots_.prepared_epoch();
}

status epoch_transition_coordinator::bind_bootstrap_request(std::string_view serialized_request,
							    std::string_view plan_content_hash, uint64_t epoch,
							    common::epoch_transition_watermarks watermarks)
{
	if (serialized_request.empty() || !common::valid_bootstrap_watermarks(epoch, watermarks)) {
		return status::invalid_argument("bootstrap retry identity is empty or has an invalid epoch");
	}
	if (plan_content_hash != participants_->plan_content_hash()) {
		return status::failed_precondition("bootstrap plan identity does not match frozen participants");
	}
	if (state_.phase() != epoch_transition_phase::AWAITING_BOOTSTRAP) {
		return status::failed_precondition("bootstrap identity is unavailable after global activation");
	}
	if (!bound_bootstrap_request_.empty()) {
		if (bound_bootstrap_epoch_ != epoch ||
		    bound_bootstrap_watermarks_.allocated_epoch != watermarks.allocated_epoch ||
		    bound_bootstrap_watermarks_.mutation_sequence != watermarks.mutation_sequence ||
		    bound_bootstrap_request_ != serialized_request) {
			return status::failed_precondition(
				"bootstrap retry does not match the exact first admitted request");
		}
		return status::ok();
	}
	try {
		bound_bootstrap_request_.assign(serialized_request);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to retain exact bootstrap retry identity");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "bootstrap retry identity exceeds host string bounds");
	}
	bound_bootstrap_epoch_ = epoch;
	bound_bootstrap_watermarks_ = watermarks;
	return status::ok();
}

status epoch_transition_coordinator::stage_bootstrap_snapshot(uint64_t epoch,
							      std::unique_ptr<const config_snapshot_artifact> &artifact)
{
	if (bound_bootstrap_request_.empty() || bound_bootstrap_epoch_ != epoch || bootstrap_publication_preflighted_ ||
	    !snapshots_.empty()) {
		return status::failed_precondition(
			"bootstrap snapshot staging lacks one exact empty coordinator state");
	}
	const auto state_result = state_.begin_bootstrap(epoch);
	if (state_result != epoch_state_result::APPLIED) {
		return state_error_(state_result, "begin bootstrap");
	}
	auto staged = snapshots_.stage_prepared(epoch, artifact);
	if (!staged.is_ok()) {
		if (state_.abort_bootstrap(epoch) != epoch_state_result::APPLIED || !snapshots_.empty()) {
			std::terminate();
		}
		return staged;
	}
	publish_progress_or_terminate_();
	return status::ok();
}

status epoch_transition_coordinator::preflight_bootstrap_publication(uint64_t epoch)
{
	if (state_.phase() != epoch_transition_phase::BOOTSTRAPPING || state_.target_epoch() != epoch ||
	    bootstrap_publication_preflighted_ || snapshots_.prepared_epoch() != epoch ||
	    snapshots_.active_epoch() != 0u || snapshots_.retained_epoch() != 0u) {
		return status::failed_precondition("bootstrap publication preflight lacks exact staged ownership");
	}
	auto preflight = snapshots_.preflight_publish_prepared(epoch);
	if (!preflight.is_ok()) {
		return preflight;
	}
	bootstrap_publication_preflighted_ = true;
	return status::ok();
}

void epoch_transition_coordinator::publish_bootstrap_or_terminate(uint64_t epoch) noexcept
{
	const auto *prepared = snapshots_.find_exact(epoch);
	if (state_.phase() != epoch_transition_phase::BOOTSTRAPPING || state_.target_epoch() != epoch ||
	    !bootstrap_publication_preflighted_ || snapshots_.prepared_epoch() != epoch ||
	    snapshots_.active_epoch() != 0u || !bound_bootstrap_watermarks_.valid() || watermarks_.valid() ||
	    prepared == nullptr || !snapshots_.publish_prepared(epoch).is_ok() ||
	    state_.complete_bootstrap(epoch) != epoch_state_result::APPLIED) {
		std::terminate();
	}
	active_validation_hash_ = prepared->validation_hash();
	bootstrap_publication_preflighted_ = false;
	watermarks_ = bound_bootstrap_watermarks_;
	std::string{}.swap(bound_bootstrap_request_);
	if (watermarks_.allocated_epoch == common::MAX_EPOCH_ID ||
	    watermarks_.mutation_sequence == common::MAX_MUTATION_SEQUENCE) {
		record_protocol_fault_(epoch_protocol_first_fault{
			.runtime_generation = protocol_runtime_generation_,
			.transition_generation = 0u,
			.from_epoch = epoch,
			.to_epoch = 0u,
			.observed_epoch = epoch,
			.expected_value = 0u,
			.observed_value = watermarks_.allocated_epoch == common::MAX_EPOCH_ID ?
						  watermarks_.allocated_epoch :
						  watermarks_.mutation_sequence,
			.observed_monotonic_ns = common::now_ns(),
			.worker_index = UINT32_MAX,
			.boundary_index = UINT32_MAX,
			.context_index = UINT32_MAX,
			.stage_instance_index = UINT32_MAX,
			.code = epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED,
			.disposition = epoch_protocol_fault_disposition::RESOURCE_REFUSED,
			.padding = {},
		});
	}
	publish_progress_or_terminate_();
}

status epoch_transition_coordinator::abort_bootstrap(uint64_t epoch)
{
	if (state_.phase() != epoch_transition_phase::BOOTSTRAPPING || state_.target_epoch() != epoch ||
	    snapshots_.prepared_epoch() != epoch || snapshots_.active_epoch() != 0u ||
	    snapshots_.retained_epoch() != 0u) {
		return status::failed_precondition("bootstrap abort lacks exact staged snapshot ownership");
	}
	auto discarded_or = snapshots_.discard_prepared(epoch);
	if (!discarded_or.is_ok()) {
		return discarded_or.error();
	}
	if (state_.abort_bootstrap(epoch) != epoch_state_result::APPLIED || !snapshots_.empty()) {
		std::terminate();
	}
	bootstrap_publication_preflighted_ = false;
	if (watermarks_.valid()) {
		std::terminate();
	}
	publish_progress_or_terminate_();
	return status::ok();
}

status epoch_transition_coordinator::retire_published_after_quiescence(uint64_t epoch)
{
	if (state_.phase() != epoch_transition_phase::IDLE || state_.active_epoch() != epoch ||
	    active_generation_.has_value() || bootstrap_publication_preflighted_ ||
	    snapshots_.active_epoch() != epoch || snapshots_.prepared_epoch() != 0u ||
	    snapshots_.retained_epoch() != 0u) {
		return status::failed_precondition("generation retirement lacks one idle published snapshot");
	}
	auto claim_or = snapshots_.claim_published_for_shutdown(epoch);
	if (!claim_or.is_ok()) {
		return claim_or.error();
	}
	auto claim = std::move(claim_or).value();
	if (!snapshots_.complete_retirement(claim).is_ok() || !snapshots_.empty()) {
		std::terminate();
	}
	return status::ok();
}

status epoch_transition_coordinator::preflight_begin_commit(const common::epoch_transition_identity &identity,
							    uint64_t commit_started_monotonic_ns) const noexcept
{
	const auto *active_identity = state_.identity();
	if (!identity.valid() || active_identity == nullptr || *active_identity != identity ||
	    state_.phase() != epoch_transition_phase::PREPARED || !active_generation_.has_value() ||
	    active_generation_->identity != active_identity || active_generation_->candidate != nullptr ||
	    active_generation_->lease_state != epoch_transition_prepared_lease_state::ARMED ||
	    active_generation_->failure_code != epoch_transition_failure_code::NONE ||
	    active_generation_->retirement_frozen || abort_cleanup_in_progress_ || !completion_armed_ ||
	    commit_started_monotonic_ns == 0u ||
	    commit_started_monotonic_ns < active_generation_->prepared_monotonic_ns ||
	    commit_started_monotonic_ns >= active_generation_->prepared_lease_deadline_monotonic_ns ||
	    active_generation_->commit_started_monotonic_ns != 0u ||
	    active_generation_->retiring_started_monotonic_ns != 0u) {
		return status::failed_precondition(
			kinetum::common::static_status_text("commit preflight lacks exact armed PREPARED ownership"));
	}
	return snapshots_.preflight_future_retained(state_.active_epoch(), identity.target_epoch);
}

void epoch_transition_coordinator::begin_commit_or_terminate(const common::epoch_transition_identity &identity,
							     uint64_t commit_started_monotonic_ns) noexcept
{
	if (!preflight_begin_commit(identity, commit_started_monotonic_ns).is_ok() ||
	    state_.begin_commit(identity) != epoch_state_result::APPLIED) {
		std::terminate();
	}
	if (!active_generation_.has_value()) {
		std::terminate();
	}
	auto &generation = *active_generation_;
	generation.lease_state = epoch_transition_prepared_lease_state::NOT_ARMED;
	generation.prepared_lease_deadline_monotonic_ns = 0u;
	generation.prepared_lease_deadline_unix_ms = 0u;
	generation.commit_started_monotonic_ns = commit_started_monotonic_ns;
	publish_progress_or_terminate_();
}

status epoch_transition_coordinator::preflight_begin_retiring(const common::epoch_transition_identity &identity,
							      uint64_t retiring_started_monotonic_ns) const noexcept
{
	const auto *active_identity = state_.identity();
	if (!identity.valid() || active_identity == nullptr || *active_identity != identity ||
	    state_.phase() != epoch_transition_phase::COMMITTING || !active_generation_.has_value() ||
	    active_generation_->identity != active_identity || active_generation_->candidate != nullptr ||
	    active_generation_->lease_state != epoch_transition_prepared_lease_state::NOT_ARMED ||
	    active_generation_->commit_started_monotonic_ns == 0u ||
	    retiring_started_monotonic_ns < active_generation_->commit_started_monotonic_ns ||
	    active_generation_->retiring_started_monotonic_ns != 0u ||
	    active_generation_->failure_code != epoch_transition_failure_code::NONE ||
	    active_generation_->retirement_frozen || abort_cleanup_in_progress_) {
		return status::failed_precondition(
			kinetum::common::static_status_text("RETIRING preflight lacks exact COMMITTING ownership"));
	}
	return snapshots_.preflight_future_retained(state_.active_epoch(), identity.target_epoch);
}

void epoch_transition_coordinator::publish_target_snapshot_or_terminate(
	const common::epoch_transition_identity &identity) noexcept
{
	const auto *active_identity = state_.identity();
	if (active_identity == nullptr || *active_identity != identity ||
	    state_.phase() != epoch_transition_phase::COMMITTING || !active_generation_.has_value() ||
	    active_generation_->retiring_started_monotonic_ns != 0u ||
	    !snapshots_.publish_prepared(identity.target_epoch).is_ok()) {
		std::terminate();
	}
}

void epoch_transition_coordinator::enter_retiring_or_terminate(const common::epoch_transition_identity &identity,
							       uint64_t retiring_started_monotonic_ns) noexcept
{
	const auto *active_identity = state_.identity();
	if (active_identity == nullptr || *active_identity != identity ||
	    state_.phase() != epoch_transition_phase::COMMITTING || !active_generation_.has_value() ||
	    active_generation_->retiring_started_monotonic_ns != 0u ||
	    retiring_started_monotonic_ns < active_generation_->commit_started_monotonic_ns ||
	    snapshots_.active_epoch() != identity.target_epoch || snapshots_.prepared_epoch() != 0u ||
	    snapshots_.retained_epoch() != state_.active_epoch() ||
	    state_.begin_retiring(identity) != epoch_state_result::APPLIED) {
		std::terminate();
	}
	active_generation_->retiring_started_monotonic_ns = retiring_started_monotonic_ns;
	publish_progress_or_terminate_();
}

status epoch_transition_coordinator::preflight_retained_snapshot(
	const common::epoch_transition_identity &identity) const noexcept
{
	const auto *active_identity = state_.identity();
	if (active_identity == nullptr || *active_identity != identity ||
	    state_.phase() != epoch_transition_phase::RETIRING || !active_generation_.has_value() ||
	    active_generation_->identity != active_identity || active_generation_->retirement_frozen ||
	    active_generation_->failure_code != epoch_transition_failure_code::NONE ||
	    snapshots_.active_epoch() != identity.target_epoch ||
	    snapshots_.retained_epoch() != state_.active_epoch()) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"snapshot retirement lacks exact unfrozen RETIRING ownership"));
	}
	return snapshots_.preflight_claim_retained(state_.active_epoch());
}

void epoch_transition_coordinator::retire_retained_snapshot_or_terminate(
	const common::epoch_transition_identity &identity) noexcept
{
	if (!preflight_retained_snapshot(identity).is_ok()) {
		std::terminate();
	}
	auto claim_or = snapshots_.claim_retained(state_.active_epoch());
	if (!claim_or.is_ok()) {
		std::terminate();
	}
	auto claim = std::move(claim_or).value();
	if (!snapshots_.complete_retirement(claim).is_ok() || snapshots_.retained_epoch() != 0u ||
	    snapshots_.active_epoch() != identity.target_epoch) {
		std::terminate();
	}
}

void epoch_transition_coordinator::freeze_retirement_or_terminate(const common::epoch_transition_identity &identity,
								  uint64_t observed_monotonic_ns,
								  std::string_view diagnostic) noexcept
{
	const auto *active_identity = state_.identity();
	if (active_identity == nullptr || *active_identity != identity ||
	    state_.phase() != epoch_transition_phase::RETIRING || !active_generation_.has_value() ||
	    active_generation_->retirement_frozen ||
	    active_generation_->failure_code != epoch_transition_failure_code::NONE ||
	    active_generation_->retiring_started_monotonic_ns == 0u ||
	    observed_monotonic_ns < active_generation_->retiring_started_monotonic_ns ||
	    !preflight_retained_snapshot(identity).is_ok()) {
		std::terminate();
	}
	active_generation_->failure_observed_monotonic_ns = observed_monotonic_ns;
	active_generation_->failure_code = epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED;
	active_generation_->diagnostic = bounded_diagnostic_(diagnostic);
	active_generation_->retirement_frozen = true;
	publish_progress_or_terminate_();
}

void epoch_transition_coordinator::fail_active_or_terminate(const common::epoch_transition_identity &identity,
							    uint64_t observed_monotonic_ns,
							    epoch_transition_failure_code failure_code,
							    std::string_view diagnostic) noexcept
{
	const auto *active_identity = state_.identity();
	const auto current_phase = state_.phase();
	if (active_identity == nullptr || *active_identity != identity || !active_generation_.has_value() ||
	    active_generation_->identity != active_identity || failure_code == epoch_transition_failure_code::NONE ||
	    failure_code == epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED ||
	    !failure_matches_phase(current_phase, failure_code) || observed_monotonic_ns == 0u ||
	    observed_monotonic_ns < active_generation_->admitted_monotonic_ns ||
	    current_phase == epoch_transition_phase::AWAITING_BOOTSTRAP ||
	    current_phase == epoch_transition_phase::BOOTSTRAPPING || current_phase == epoch_transition_phase::IDLE ||
	    current_phase == epoch_transition_phase::FAILED_STOP) {
		std::terminate();
	}
	active_generation_->failure_observed_monotonic_ns = observed_monotonic_ns;
	active_generation_->failure_code = failure_code;
	active_generation_->diagnostic = bounded_diagnostic_(diagnostic);
	state_.enter_failed_stop();
	last_terminal_outcome_ = epoch_transition_outcome::FAILED_STOP;
	publish_progress_or_terminate_();
}

void epoch_transition_coordinator::complete_retirement_or_terminate(const common::epoch_transition_identity &identity,
								    uint64_t terminal_monotonic_ns) noexcept
{
	const auto *active_identity = state_.identity();
	const auto *target_snapshot = snapshots_.active_artifact();
	if (active_identity == nullptr || *active_identity != identity ||
	    state_.phase() != epoch_transition_phase::RETIRING || !active_generation_.has_value() ||
	    active_generation_->identity != active_identity || active_generation_->retirement_frozen ||
	    active_generation_->failure_code != epoch_transition_failure_code::NONE ||
	    active_generation_->commit_started_monotonic_ns == 0u ||
	    active_generation_->retiring_started_monotonic_ns < active_generation_->commit_started_monotonic_ns ||
	    terminal_monotonic_ns < active_generation_->retiring_started_monotonic_ns ||
	    snapshots_.active_epoch() != identity.target_epoch || snapshots_.prepared_epoch() != 0u ||
	    snapshots_.retained_epoch() != 0u || target_snapshot == nullptr ||
	    target_snapshot->validation_hash() != identity.validation_hash) {
		std::terminate();
	}
	epoch_transition_terminal_result terminal{
		.identity = identity,
		.from_epoch = state_.active_epoch(),
		.to_epoch = identity.target_epoch,
		.admitted_monotonic_ns = active_generation_->admitted_monotonic_ns,
		.terminal_monotonic_ns = terminal_monotonic_ns,
		.prepare_duration_ns =
			active_generation_->prepared_monotonic_ns - active_generation_->admitted_monotonic_ns,
		.commit_duration_ns = active_generation_->retiring_started_monotonic_ns -
				      active_generation_->commit_started_monotonic_ns,
		.retirement_duration_ns = terminal_monotonic_ns - active_generation_->retiring_started_monotonic_ns,
		.duration_presence = TRANSITION_PREPARE_DURATION_PRESENT | TRANSITION_COMMIT_DURATION_PRESENT |
				     TRANSITION_RETIREMENT_DURATION_PRESENT,
		.outcome = epoch_transition_outcome::COMPLETE,
		.failure_code = epoch_transition_failure_code::NONE,
		.diagnostic = {},
	};
	if (state_.complete_retirement(identity) != epoch_state_result::APPLIED) {
		std::terminate();
	}
	active_validation_hash_ = identity.validation_hash;
	append_terminal_result_(terminal);
	active_generation_.reset();
	completion_armed_ = false;
	last_terminal_outcome_ = epoch_transition_outcome::COMPLETE;
	publish_progress_or_terminate_();
}

uint64_t epoch_transition_coordinator::retained_snapshot_epoch() const noexcept
{
	return snapshots_.retained_epoch();
}

bool epoch_transition_coordinator::retirement_frozen() const noexcept
{
	return active_generation_.has_value() && active_generation_->retirement_frozen;
}

epoch_transition_operation_result
epoch_transition_coordinator::admit_prepare(const common::epoch_transition_identity &identity,
					    std::unique_ptr<const config_snapshot_artifact> &candidate,
					    uint64_t admitted_monotonic_ns) noexcept
{
	if (candidate == nullptr || candidate->validation_hash() != identity.validation_hash ||
	    admitted_monotonic_ns == 0u) {
		epoch_transition_operation_result invalid;
		invalid.code = status_code::INVALID_ARGUMENT;
		invalid.observation.identity = identity;
		invalid.observation.watermarks = watermarks_;
		invalid.observation.phase = state_.phase();
		invalid.observation.resolution = common::transition_identity_resolution::INVALID;
		invalid.observation.diagnostic = bounded_diagnostic_(
			"PREPARE requires one hash-matched immutable candidate and nonzero monotonic timestamp");
		return invalid;
	}

	auto resolved = resolve_identity_(identity, false);
	if (!resolved.is_ok() ||
	    resolved.observation.resolution != common::transition_identity_resolution::ADMISSIBLE) {
		return resolved;
	}
	if (snapshots_.active_epoch() != state_.active_epoch() || snapshots_.active_epoch() == 0u ||
	    snapshots_.prepared_epoch() != 0u || snapshots_.retained_epoch() != 0u ||
	    state_.phase() != epoch_transition_phase::IDLE || active_generation_.has_value() || completion_armed_) {
		resolved.code = status_code::FAILED_PRECONDITION;
		resolved.observation.resolution = common::transition_identity_resolution::STATE_UNAVAILABLE;
		resolved.observation.diagnostic =
			bounded_diagnostic_("live transition admission requires one idle published snapshot");
		return resolved;
	}

	if (state_.begin_prepare(identity) != epoch_state_result::APPLIED) {
		std::terminate();
	}
	const auto *admitted_identity = state_.identity();
	if (admitted_identity == nullptr || *admitted_identity != identity) {
		std::terminate();
	}
	active_generation_.emplace(active_generation{
		.identity = admitted_identity,
		.participants = participants_.get(),
		.candidate = std::move(candidate),
		.admitted_monotonic_ns = admitted_monotonic_ns,
		.prepared_monotonic_ns = 0u,
		.lease_state = epoch_transition_prepared_lease_state::NOT_ARMED,
		.prepared_lease_deadline_monotonic_ns = 0u,
		.prepared_lease_deadline_unix_ms = 0u,
	});
	watermarks_ = common::epoch_transition_watermarks{identity.target_epoch, identity.mutation_sequence};
	publish_progress_or_terminate_();
	return epoch_transition_operation_result{
		.code = status_code::OK,
		.observation = active_observation_(common::transition_identity_resolution::ADMISSIBLE),
	};
}

const kinetum::control::v1::ConfigSnapshot *epoch_transition_coordinator::preparing_candidate_snapshot(
	const common::epoch_transition_identity &identity) const noexcept
{
	const auto *active_identity = state_.identity();
	if (state_.phase() != epoch_transition_phase::PREPARING || active_identity == nullptr ||
	    *active_identity != identity || !active_generation_.has_value() ||
	    active_generation_->candidate == nullptr) {
		return nullptr;
	}
	return &active_generation_->candidate->snapshot();
}

status
epoch_transition_coordinator::preflight_completion_arm(const common::epoch_transition_identity &identity) const noexcept
{
	const auto *active_identity = state_.identity();
	if (state_.phase() != epoch_transition_phase::PREPARING || active_identity == nullptr ||
	    *active_identity != identity || !active_generation_.has_value() ||
	    active_generation_->candidate == nullptr ||
	    active_generation_->candidate->validation_hash() != identity.validation_hash ||
	    active_generation_->lease_state != epoch_transition_prepared_lease_state::NOT_ARMED ||
	    abort_cleanup_in_progress_) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"completion arm lacks exact PREPARING candidate ownership"));
	}
	return snapshots_.preflight_future_preparation(state_.active_epoch(), identity.target_epoch);
}

status epoch_transition_coordinator::arm_completion(const common::epoch_transition_identity &identity) noexcept
{
	if (completion_armed_ || !preflight_completion_arm(identity).is_ok()) {
		return status::failed_precondition(
			kinetum::common::static_status_text("completion resources cannot arm this PREPARING identity"));
	}
	completion_armed_ = true;
	return status::ok();
}

epoch_transition_operation_result
epoch_transition_coordinator::mark_prepared(const common::epoch_transition_identity &identity,
					    uint64_t prepared_monotonic_ns, uint64_t lease_deadline_monotonic_ns,
					    uint64_t lease_deadline_unix_ms) noexcept
{
	auto resolved = resolve_identity_(identity, true);
	if (resolved.observation.resolution != common::transition_identity_resolution::ACTIVE_EXACT ||
	    state_.phase() != epoch_transition_phase::PREPARING || !active_generation_.has_value() ||
	    active_generation_->candidate == nullptr ||
	    prepared_monotonic_ns < active_generation_->admitted_monotonic_ns ||
	    lease_deadline_monotonic_ns <= prepared_monotonic_ns || lease_deadline_unix_ms == 0u ||
	    snapshots_.prepared_epoch() != 0u || !completion_armed_) {
		resolved.code = status_code::FAILED_PRECONDITION;
		resolved.observation.resolution = common::transition_identity_resolution::STATE_UNAVAILABLE;
		resolved.observation.diagnostic =
			bounded_diagnostic_("PREPARED publication lacks exact completed ownership");
		return resolved;
	}
	const auto staged = snapshots_.stage_prepared(identity.target_epoch, active_generation_->candidate);
	if (!staged.is_ok()) {
		resolved.code = staged.code();
		resolved.observation.resolution = common::transition_identity_resolution::STATE_UNAVAILABLE;
		resolved.observation.diagnostic = bounded_diagnostic_(staged.message());
		return resolved;
	}
	if (state_.mark_prepared(identity) != epoch_state_result::APPLIED) {
		std::terminate();
	}
	active_generation_->lease_state = epoch_transition_prepared_lease_state::ARMED;
	active_generation_->prepared_monotonic_ns = prepared_monotonic_ns;
	active_generation_->prepared_lease_deadline_monotonic_ns = lease_deadline_monotonic_ns;
	active_generation_->prepared_lease_deadline_unix_ms = lease_deadline_unix_ms;
	publish_progress_or_terminate_();
	return epoch_transition_operation_result{
		.code = status_code::OK,
		.observation = active_observation_(common::transition_identity_resolution::ACTIVE_EXACT),
	};
}

status
epoch_transition_coordinator::begin_prepared_abort_cleanup(const common::epoch_transition_identity &identity) noexcept
{
	const auto *active_identity = state_.identity();
	if (state_.phase() != epoch_transition_phase::PREPARED || active_identity == nullptr ||
	    *active_identity != identity || !active_generation_.has_value() ||
	    active_generation_->candidate != nullptr || snapshots_.prepared_epoch() != identity.target_epoch ||
	    active_generation_->lease_state != epoch_transition_prepared_lease_state::ARMED) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"prepared abort cleanup requires the exact active PREPARED ownership"));
	}
	if (abort_cleanup_in_progress_) {
		return status::ok();
	}
	abort_cleanup_in_progress_ = true;
	publish_progress_or_terminate_();
	return status::ok();
}

epoch_transition_operation_result epoch_transition_coordinator::abort_before_commit(
	const common::epoch_transition_identity &identity, uint64_t terminal_monotonic_ns,
	epoch_transition_failure_code failure_code, std::string_view diagnostic) noexcept
{
	if (!is_precommit_failure(failure_code) || terminal_monotonic_ns == 0u) {
		epoch_transition_operation_result invalid;
		invalid.code = status_code::INVALID_ARGUMENT;
		invalid.observation.identity = identity;
		invalid.observation.watermarks = watermarks_;
		invalid.observation.phase = state_.phase();
		invalid.observation.resolution = common::transition_identity_resolution::INVALID;
		invalid.observation.diagnostic =
			bounded_diagnostic_("pre-commit abort requires an exact cause and monotonic timestamp");
		return invalid;
	}

	auto resolved = resolve_identity_(identity, true);
	if (!resolved.is_ok() ||
	    resolved.observation.resolution == common::transition_identity_resolution::TERMINAL_EXACT) {
		return resolved;
	}
	const auto current_phase = state_.phase();
	const bool preparing = current_phase == epoch_transition_phase::PREPARING;
	const bool prepared = current_phase == epoch_transition_phase::PREPARED;
	if (resolved.observation.resolution != common::transition_identity_resolution::ACTIVE_EXACT ||
	    !active_generation_.has_value() || (!preparing && !prepared) ||
	    (preparing && (active_generation_->candidate == nullptr ||
			   active_generation_->lease_state != epoch_transition_prepared_lease_state::NOT_ARMED)) ||
	    (prepared &&
	     (active_generation_->candidate != nullptr || snapshots_.prepared_epoch() != identity.target_epoch ||
	      active_generation_->lease_state != epoch_transition_prepared_lease_state::ARMED))) {
		resolved.code = status_code::FAILED_PRECONDITION;
		resolved.observation.resolution = common::transition_identity_resolution::STATE_UNAVAILABLE;
		resolved.observation.diagnostic =
			bounded_diagnostic_("pre-commit abort does not own the exact abortable transaction");
		return resolved;
	}
	if (terminal_monotonic_ns < active_generation_->admitted_monotonic_ns) {
		resolved.code = status_code::INVALID_ARGUMENT;
		resolved.observation.resolution = common::transition_identity_resolution::INVALID;
		resolved.observation.diagnostic =
			bounded_diagnostic_("pre-commit abort timestamp precedes transaction admission");
		return resolved;
	}

	epoch_transition_terminal_result terminal{
		.identity = identity,
		.from_epoch = state_.active_epoch(),
		.to_epoch = identity.target_epoch,
		.admitted_monotonic_ns = active_generation_->admitted_monotonic_ns,
		.terminal_monotonic_ns = terminal_monotonic_ns,
		.prepare_duration_ns = prepared ? active_generation_->prepared_monotonic_ns -
							  active_generation_->admitted_monotonic_ns :
						  terminal_monotonic_ns - active_generation_->admitted_monotonic_ns,
		.commit_duration_ns = 0u,
		.retirement_duration_ns = 0u,
		.duration_presence = TRANSITION_PREPARE_DURATION_PRESENT,
		.outcome = epoch_transition_outcome::ABORTED,
		.failure_code = failure_code,
		.diagnostic = bounded_diagnostic_(diagnostic),
	};
	if (prepared) {
		auto discarded_or = snapshots_.discard_prepared(identity.target_epoch);
		if (!discarded_or.is_ok()) {
			std::terminate();
		}
	}
	if (state_.abort_before_commit(identity) != epoch_state_result::APPLIED) {
		std::terminate();
	}
	append_terminal_result_(terminal);
	active_generation_.reset();
	abort_cleanup_in_progress_ = false;
	completion_armed_ = false;
	last_terminal_outcome_ = epoch_transition_outcome::ABORTED;
	publish_progress_or_terminate_();
	return epoch_transition_operation_result{
		.code = status_code::OK,
		.observation = terminal_observation_(terminal),
	};
}

epoch_transition_operation_result
epoch_transition_coordinator::query_transaction(const common::epoch_transition_identity &identity) const noexcept
{
	return resolve_identity_(identity, true);
}

epoch_transition_operation_result
epoch_transition_coordinator::abort_active_for_shutdown(uint64_t terminal_monotonic_ns) noexcept
{
	const auto *identity = state_.identity();
	if (identity == nullptr) {
		epoch_transition_operation_result result;
		result.code = status_code::FAILED_PRECONDITION;
		result.observation.watermarks = watermarks_;
		result.observation.phase = state_.phase();
		result.observation.resolution = common::transition_identity_resolution::STATE_UNAVAILABLE;
		result.observation.diagnostic =
			bounded_diagnostic_("shutdown abort requires one exact abortable transaction");
		return result;
	}
	return abort_before_commit(*identity, terminal_monotonic_ns, epoch_transition_failure_code::SHUTDOWN_ABORT,
				   "runtime shutdown aborted the active pre-commit transaction");
}

publication_read_result
epoch_transition_coordinator::try_read_progress(epoch_transition_progress_snapshot &out) const noexcept
{
	kinetum::algo::single_writer_snapshot<PROGRESS_FIELD_COUNT>::snapshot observed{};
	if (!progress_.try_read(observed, OBSERVATION_ATTEMPTS)) {
		return publication_read_result::UNAVAILABLE;
	}
	if (observed.fields[EXECUTION_PARTICIPANT_COUNT] != participants_->execution_participant_count() ||
	    observed.fields[REGION_COUNT] != participants_->region_count() ||
	    observed.fields[BOUNDARY_COUNT] != participants_->boundary_count() ||
	    observed.fields[SOURCE_COUNT] != participants_->source_participant_indices().size() ||
	    observed.fields[SINK_COUNT] != participants_->sink_participant_indices().size() ||
	    observed.fields[MODULE_CONTEXT_COUNT] != participants_->module_context_count() ||
	    observed.fields[QUIESCENCE_READER_COUNT] != participants_->quiescence_reader_count()) {
		return publication_read_result::INVALID_IDENTITY;
	}

	epoch_transition_phase decoded_phase{};
	epoch_transition_outcome decoded_outcome{};
	if (!decode_phase(observed.fields[PHASE], decoded_phase) ||
	    !decode_outcome(observed.fields[LAST_TERMINAL_OUTCOME], decoded_outcome) ||
	    observed.fields[PARTICIPANTS_FROZEN] > 1u || observed.fields[ABORT_CLEANUP_IN_PROGRESS] > 1u ||
	    observed.fields[RETIREMENT_FROZEN] > 1u ||
	    observed.fields[EXECUTION_PARTICIPANT_COUNT] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[REGION_COUNT] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[BOUNDARY_COUNT] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[SOURCE_COUNT] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[SINK_COUNT] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[MODULE_CONTEXT_COUNT] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[QUIESCENCE_READER_COUNT] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[TERMINAL_HISTORY_SIZE] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[EXECUTION_PARTICIPANT_COUNT] == 0u || observed.fields[REGION_COUNT] == 0u ||
	    observed.fields[REGION_COUNT] > observed.fields[EXECUTION_PARTICIPANT_COUNT] ||
	    observed.fields[SOURCE_COUNT] > observed.fields[EXECUTION_PARTICIPANT_COUNT] ||
	    observed.fields[SINK_COUNT] > observed.fields[EXECUTION_PARTICIPANT_COUNT] ||
	    observed.fields[QUIESCENCE_READER_COUNT] != observed.fields[EXECUTION_PARTICIPANT_COUNT] ||
	    observed.fields[TERMINAL_HISTORY_SIZE] > terminal_history_.size()) {
		return publication_read_result::INVALID_STATE;
	}
	if (observed.fields[RETIREMENT_FROZEN] != 0u && decoded_phase != epoch_transition_phase::RETIRING) {
		return publication_read_result::INVALID_STATE;
	}

	const uint64_t active_epoch = observed.fields[ACTIVE_EPOCH];
	const std::array<uint64_t, 4> active_hash_words{
		observed.fields[ACTIVE_VALIDATION_HASH_0],
		observed.fields[ACTIVE_VALIDATION_HASH_1],
		observed.fields[ACTIVE_VALIDATION_HASH_2],
		observed.fields[ACTIVE_VALIDATION_HASH_3],
	};
	const auto active_validation_hash = digest_from_words(active_hash_words.data());
	const uint64_t target_epoch = observed.fields[TARGET_EPOCH];
	const uint64_t mutation_sequence = observed.fields[MUTATION_SEQUENCE];
	const common::epoch_transition_watermarks observed_watermarks{
		observed.fields[ALLOCATED_EPOCH_HIGH_WATERMARK],
		observed.fields[MUTATION_SEQUENCE_HIGH_WATERMARK],
	};
	const bool frozen = observed.fields[PARTICIPANTS_FROZEN] != 0u;
	switch (decoded_phase) {
	case epoch_transition_phase::AWAITING_BOOTSTRAP:
		if (active_epoch != 0u || target_epoch != 0u || mutation_sequence != 0u || frozen ||
		    observed_watermarks.valid()) {
			return publication_read_result::INVALID_STATE;
		}
		if (observed_watermarks.allocated_epoch != 0u || observed_watermarks.mutation_sequence != 0u) {
			return publication_read_result::INVALID_STATE;
		}
		break;
	case epoch_transition_phase::BOOTSTRAPPING:
		if (active_epoch != 0u || !common::valid_epoch_id(target_epoch) || mutation_sequence != 0u || frozen ||
		    observed_watermarks.allocated_epoch != 0u || observed_watermarks.mutation_sequence != 0u) {
			return publication_read_result::INVALID_STATE;
		}
		break;
	case epoch_transition_phase::IDLE:
		if (!common::valid_epoch_id(active_epoch) || target_epoch != 0u || mutation_sequence != 0u || frozen ||
		    !common::valid_bootstrap_watermarks(active_epoch, observed_watermarks)) {
			return publication_read_result::INVALID_STATE;
		}
		break;
	case epoch_transition_phase::PREPARING:
	case epoch_transition_phase::PREPARED:
	case epoch_transition_phase::COMMITTING:
	case epoch_transition_phase::RETIRING:
		if (!common::valid_epoch_id(active_epoch) || !common::valid_epoch_id(target_epoch) ||
		    target_epoch <= active_epoch || !common::valid_mutation_sequence(mutation_sequence) || !frozen ||
		    !common::valid_bootstrap_watermarks(active_epoch, observed_watermarks) ||
		    observed_watermarks.allocated_epoch != target_epoch ||
		    observed_watermarks.mutation_sequence != mutation_sequence) {
			return publication_read_result::INVALID_STATE;
		}
		break;
	case epoch_transition_phase::FAILED_STOP:
		if (decoded_outcome != epoch_transition_outcome::FAILED_STOP) {
			return publication_read_result::INVALID_STATE;
		}
		if (frozen) {
			if (!common::valid_epoch_id(active_epoch) || !common::valid_epoch_id(target_epoch) ||
			    target_epoch <= active_epoch || !common::valid_mutation_sequence(mutation_sequence) ||
			    observed_watermarks.allocated_epoch != target_epoch ||
			    observed_watermarks.mutation_sequence != mutation_sequence) {
				return publication_read_result::INVALID_STATE;
			}
		} else if (mutation_sequence != 0u || !((active_epoch == 0u && target_epoch == 0u) ||
							(active_epoch == 0u && common::valid_epoch_id(target_epoch)) ||
							(common::valid_epoch_id(active_epoch) && target_epoch == 0u))) {
			return publication_read_result::INVALID_STATE;
		}
		if (!frozen && active_epoch == 0u &&
		    (observed_watermarks.allocated_epoch != 0u || observed_watermarks.mutation_sequence != 0u)) {
			return publication_read_result::INVALID_STATE;
		}
		if (!frozen && common::valid_epoch_id(active_epoch) &&
		    !common::valid_bootstrap_watermarks(active_epoch, observed_watermarks)) {
			return publication_read_result::INVALID_STATE;
		}
		break;
	}
	if (decoded_phase != epoch_transition_phase::FAILED_STOP &&
	    decoded_outcome == epoch_transition_outcome::FAILED_STOP) {
		return publication_read_result::INVALID_STATE;
	}
	if (decoded_phase != epoch_transition_phase::FAILED_STOP &&
	    ((observed.fields[TERMINAL_HISTORY_SIZE] == 0u) != (decoded_outcome == epoch_transition_outcome::NONE))) {
		return publication_read_result::INVALID_STATE;
	}

	epoch_transition_progress_snapshot decoded{
		.publication_generation = observed.generation,
		.phase = decoded_phase,
		.active_epoch = active_epoch,
		.active_validation_hash = active_validation_hash,
		.target_epoch = target_epoch,
		.mutation_sequence = mutation_sequence,
		.allocated_epoch_high_watermark = observed_watermarks.allocated_epoch,
		.mutation_sequence_high_watermark = observed_watermarks.mutation_sequence,
		.participants_frozen = frozen,
		.execution_participant_count = static_cast<uint32_t>(observed.fields[EXECUTION_PARTICIPANT_COUNT]),
		.region_count = static_cast<uint32_t>(observed.fields[REGION_COUNT]),
		.boundary_count = static_cast<uint32_t>(observed.fields[BOUNDARY_COUNT]),
		.source_participant_count = static_cast<uint32_t>(observed.fields[SOURCE_COUNT]),
		.sink_participant_count = static_cast<uint32_t>(observed.fields[SINK_COUNT]),
		.module_context_count = static_cast<uint32_t>(observed.fields[MODULE_CONTEXT_COUNT]),
		.quiescence_reader_count = static_cast<uint32_t>(observed.fields[QUIESCENCE_READER_COUNT]),
		.terminal_history_size = static_cast<uint32_t>(observed.fields[TERMINAL_HISTORY_SIZE]),
		.last_terminal_outcome = decoded_outcome,
		.retirement_frozen = observed.fields[RETIREMENT_FROZEN] != 0u,
	};
	if (observed.fields[ABORT_CLEANUP_IN_PROGRESS] != 0u) {
		return publication_read_result::UNAVAILABLE;
	}
	out = decoded;
	return publication_read_result::AVAILABLE;
}

publication_read_result
epoch_transition_coordinator::try_read_telemetry(epoch_transition_telemetry_snapshot &out) const noexcept
{
	kinetum::algo::single_writer_snapshot<TELEMETRY_FIELD_COUNT>::snapshot observed{};
	if (!telemetry_.try_read(observed, OBSERVATION_ATTEMPTS)) {
		return publication_read_result::UNAVAILABLE;
	}
	if (observed.fields[0] > 1u || observed.fields[23] > 1u ||
	    observed.fields[TELEMETRY_TRANSACTION_FIELD_COUNT] > 1u ||
	    observed.fields[TELEMETRY_TRANSACTION_FIELD_COUNT + 23u] > 1u ||
	    observed.fields[21] > static_cast<uint64_t>(epoch_transition_outcome::FAILED_STOP) ||
	    observed.fields[22] > static_cast<uint64_t>(epoch_transition_failure_code::PROTOCOL_FAULT) ||
	    observed.fields[TELEMETRY_TRANSACTION_FIELD_COUNT + 21u] >
		    static_cast<uint64_t>(epoch_transition_outcome::FAILED_STOP) ||
	    observed.fields[TELEMETRY_TRANSACTION_FIELD_COUNT + 22u] >
		    static_cast<uint64_t>(epoch_transition_failure_code::PROTOCOL_FAULT)) {
		return publication_read_result::INVALID_STATE;
	}
	const auto active = decode_transaction(observed.fields.data());
	const auto latest = decode_transaction(observed.fields.data() + TELEMETRY_TRANSACTION_FIELD_COUNT);
	const auto absent_is_zero = [](const uint64_t *fields) noexcept {
		return std::all_of(fields, fields + TRANSACTION_TELEMETRY_FIELDS,
				   [](uint64_t value) { return value == 0u; });
	};
	if ((!active.present && !absent_is_zero(observed.fields.data())) ||
	    (!latest.present && !absent_is_zero(observed.fields.data() + TELEMETRY_TRANSACTION_FIELD_COUNT))) {
		return publication_read_result::INVALID_STATE;
	}
	if (active.present) {
		const auto raw_failure = static_cast<uint8_t>(active.failure_code);
		if (!active.identity.valid() || active.from_epoch == 0u ||
		    active.to_epoch != active.identity.target_epoch || active.to_epoch <= active.from_epoch ||
		    active.admitted_monotonic_ns == 0u || active.terminal_monotonic_ns != 0u ||
		    active.outcome != epoch_transition_outcome::NONE ||
		    raw_failure > static_cast<uint8_t>(epoch_transition_failure_code::PROTOCOL_FAULT) ||
		    (active.failure_code == epoch_transition_failure_code::NONE) !=
			    (active.failure_observed_monotonic_ns == 0u) ||
		    active.retirement_frozen != (active.failure_code ==
						 epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED) ||
		    (active.prepared_monotonic_ns != 0u &&
		     active.prepared_monotonic_ns < active.admitted_monotonic_ns) ||
		    ((active.prepared_lease_deadline_monotonic_ns == 0u) !=
		     (active.prepared_lease_deadline_unix_ms == 0u)) ||
		    (active.prepared_lease_deadline_monotonic_ns != 0u &&
		     (active.prepared_monotonic_ns == 0u ||
		      active.prepared_lease_deadline_monotonic_ns <= active.prepared_monotonic_ns)) ||
		    (active.commit_started_monotonic_ns != 0u &&
		     (active.prepared_monotonic_ns == 0u ||
		      active.commit_started_monotonic_ns < active.prepared_monotonic_ns)) ||
		    (active.retiring_started_monotonic_ns != 0u &&
		     (active.commit_started_monotonic_ns == 0u ||
		      active.retiring_started_monotonic_ns < active.commit_started_monotonic_ns)) ||
		    (active.failure_observed_monotonic_ns != 0u &&
		     active.failure_observed_monotonic_ns < active.admitted_monotonic_ns)) {
			return publication_read_result::INVALID_STATE;
		}
	}
	if (latest.present) {
		const auto raw_outcome = static_cast<uint8_t>(latest.outcome);
		const auto raw_failure = static_cast<uint8_t>(latest.failure_code);
		if (!latest.identity.valid() || latest.from_epoch == 0u ||
		    latest.to_epoch != latest.identity.target_epoch || latest.to_epoch <= latest.from_epoch ||
		    latest.admitted_monotonic_ns == 0u || latest.terminal_monotonic_ns < latest.admitted_monotonic_ns ||
		    raw_outcome < static_cast<uint8_t>(epoch_transition_outcome::COMPLETE) ||
		    raw_outcome > static_cast<uint8_t>(epoch_transition_outcome::FAILED_STOP) ||
		    raw_failure > static_cast<uint8_t>(epoch_transition_failure_code::PROTOCOL_FAULT) ||
		    latest.retirement_frozen || latest.prepared_lease_deadline_monotonic_ns != 0u ||
		    latest.prepared_lease_deadline_unix_ms != 0u ||
		    (latest.failure_code == epoch_transition_failure_code::NONE) !=
			    (latest.failure_observed_monotonic_ns == 0u) ||
		    (latest.outcome == epoch_transition_outcome::COMPLETE) !=
			    (latest.failure_code == epoch_transition_failure_code::NONE)) {
			return publication_read_result::INVALID_STATE;
		}
	}
	out = epoch_transition_telemetry_snapshot{
		.publication_generation = observed.generation,
		.active = active,
		.latest_terminal = latest,
		.protocol_fault_counts = {},
	};
	std::copy_n(observed.fields.begin() + 2u * TELEMETRY_TRANSACTION_FIELD_COUNT, EPOCH_PROTOCOL_FAULT_COUNT,
		    out.protocol_fault_counts.begin());
	return publication_read_result::AVAILABLE;
}

std::size_t epoch_transition_coordinator::terminal_history_capacity() const noexcept
{
	return terminal_history_.size();
}

std::size_t epoch_transition_coordinator::terminal_history_size() const noexcept
{
	return terminal_history_size_;
}

std::chrono::steady_clock::duration epoch_transition_coordinator::prepared_lease_timeout() const noexcept
{
	return prepared_lease_timeout_;
}

const epoch_transition_terminal_result *
epoch_transition_coordinator::terminal_result(std::size_t ordinal) const noexcept
{
	if (ordinal >= terminal_history_size_ || terminal_history_.empty()) {
		return nullptr;
	}
	const std::size_t index = (terminal_history_begin_ + ordinal) % terminal_history_.size();
	return &terminal_history_[index];
}

epoch_transition_operation_result
epoch_transition_coordinator::resolve_identity_(const common::epoch_transition_identity &identity,
						bool status_query) const noexcept
{
	auto rejected = [this, &identity](status_code code, common::transition_identity_resolution resolution,
					  std::string_view diagnostic) noexcept {
		epoch_transition_operation_result result;
		result.code = code;
		result.observation.identity = identity;
		result.observation.watermarks = watermarks_;
		result.observation.phase = state_.phase();
		result.observation.from_epoch = state_.active_epoch();
		result.observation.to_epoch = identity.target_epoch;
		result.observation.resolution = resolution;
		result.observation.diagnostic = bounded_diagnostic_(diagnostic);
		return result;
	};

	if (!identity.valid()) {
		return rejected(status_code::INVALID_ARGUMENT, common::transition_identity_resolution::INVALID,
				"transition identity is outside the exact allocation domain");
	}
	if (!transitions_enabled_) {
		return rejected(status_code::UNAVAILABLE, common::transition_identity_resolution::POLICY_DISABLED,
				"live transition policy is disabled for this runtime generation");
	}
	if (!common::valid_bootstrap_watermarks(state_.active_epoch(), watermarks_)) {
		return rejected(status_code::FAILED_PRECONDITION,
				common::transition_identity_resolution::STATE_UNAVAILABLE,
				"transition identity lookup requires completed Bootstrap authority");
	}

	const auto *active_identity = state_.identity();
	if (active_identity != nullptr && *active_identity == identity) {
		return epoch_transition_operation_result{
			.code = status_code::OK,
			.observation = active_observation_(common::transition_identity_resolution::ACTIVE_EXACT),
		};
	}
	for (std::size_t ordinal = 0; ordinal < terminal_history_size_; ++ordinal) {
		const auto *terminal = terminal_result(ordinal);
		if (terminal == nullptr) {
			std::terminate();
		}
		if (terminal->identity == identity) {
			return epoch_transition_operation_result{
				.code = status_code::OK,
				.observation = terminal_observation_(*terminal),
			};
		}
	}

	const auto conflicts_with_retained_identity =
		[&identity](const common::epoch_transition_identity &retained) noexcept {
			return (retained.target_epoch == identity.target_epoch &&
				retained.mutation_sequence == identity.mutation_sequence) ||
			       retained.idempotency_key_digest == identity.idempotency_key_digest;
		};
	if ((active_identity != nullptr && conflicts_with_retained_identity(*active_identity)) ||
	    std::any_of(terminal_history_.begin(), terminal_history_.end(), [&](const auto &terminal) {
		    return terminal.outcome != epoch_transition_outcome::NONE &&
			   conflicts_with_retained_identity(terminal.identity);
	    })) {
		return rejected(
			status_code::FAILED_PRECONDITION, common::transition_identity_resolution::IDENTITY_CONFLICT,
			"transition allocation pair or idempotency key is bound to different exact identity content");
	}
	if (active_identity != nullptr) {
		return rejected(status_code::FAILED_PRECONDITION, common::transition_identity_resolution::OVERLAP,
				"another epoch transition generation owns the global token");
	}

	switch (common::classify_transition_watermarks(identity, watermarks_)) {
	case common::transition_watermark_result::INVALID:
		return rejected(status_code::INVALID_ARGUMENT, common::transition_identity_resolution::INVALID,
				"transition identity cannot be classified against restored watermarks");
	case common::transition_watermark_result::STALE:
		return rejected(status_code::FAILED_PRECONDITION, common::transition_identity_resolution::STALE,
				"transition allocation is stale relative to admitted high watermarks");
	case common::transition_watermark_result::EXACT_RETRY_CANDIDATE:
		return rejected(status_code::FAILED_PRECONDITION, common::transition_identity_resolution::EXPIRED_RETRY,
				"transition retry expired from the bounded terminal journal");
	case common::transition_watermark_result::ADVANCES:
		if (status_query) {
			return rejected(status_code::NOT_FOUND, common::transition_identity_resolution::UNKNOWN_FUTURE,
					"transition identity has not been admitted");
		}
		return epoch_transition_operation_result{
			.code = status_code::OK,
			.observation =
				epoch_transition_transaction_observation{
					.resolution = common::transition_identity_resolution::ADMISSIBLE,
					.identity = identity,
					.watermarks = watermarks_,
					.phase = state_.phase(),
					.outcome = epoch_transition_outcome::NONE,
					.from_epoch = state_.active_epoch(),
					.to_epoch = identity.target_epoch,
				},
		};
	case common::transition_watermark_result::INCONSISTENT:
		return rejected(status_code::FAILED_PRECONDITION, common::transition_identity_resolution::INCONSISTENT,
				"transition allocations must both equal or both advance their watermarks");
	}
	std::terminate();
}

epoch_transition_transaction_observation
epoch_transition_coordinator::active_observation_(common::transition_identity_resolution resolution) const noexcept
{
	const auto *identity = state_.identity();
	if (!active_generation_.has_value() || identity == nullptr || active_generation_->identity != identity ||
	    active_generation_->participants != participants_.get() ||
	    active_generation_->admitted_monotonic_ns == 0u) {
		std::terminate();
	}
	const bool candidate_location_valid =
		(state_.phase() == epoch_transition_phase::PREPARING && active_generation_->candidate != nullptr &&
		 snapshots_.prepared_epoch() == 0u) ||
		(state_.phase() == epoch_transition_phase::PREPARED && active_generation_->candidate == nullptr &&
		 snapshots_.prepared_epoch() == identity->target_epoch) ||
		(state_.phase() == epoch_transition_phase::COMMITTING && active_generation_->candidate == nullptr &&
		 snapshots_.prepared_epoch() == identity->target_epoch &&
		 snapshots_.active_epoch() == state_.active_epoch()) ||
		(state_.phase() == epoch_transition_phase::RETIRING && active_generation_->candidate == nullptr &&
		 snapshots_.prepared_epoch() == 0u && snapshots_.active_epoch() == identity->target_epoch &&
		 snapshots_.retained_epoch() == state_.active_epoch()) ||
		state_.phase() == epoch_transition_phase::FAILED_STOP;
	if (!candidate_location_valid) {
		std::terminate();
	}
	const bool prepared = active_generation_->prepared_monotonic_ns != 0u;
	const bool commit_complete = active_generation_->retiring_started_monotonic_ns != 0u;
	const uint8_t duration_presence =
		static_cast<uint8_t>((prepared ? TRANSITION_PREPARE_DURATION_PRESENT : 0u) |
				     (commit_complete ? TRANSITION_COMMIT_DURATION_PRESENT : 0u));
	return epoch_transition_transaction_observation{
		.resolution = resolution,
		.identity = *identity,
		.watermarks = watermarks_,
		.phase = state_.phase(),
		.outcome = state_.phase() == epoch_transition_phase::FAILED_STOP ?
				   epoch_transition_outcome::FAILED_STOP :
				   epoch_transition_outcome::NONE,
		.from_epoch = state_.active_epoch(),
		.to_epoch = identity->target_epoch,
		.admitted_monotonic_ns = active_generation_->admitted_monotonic_ns,
		.terminal_monotonic_ns = 0u,
		.prepare_duration_ns = prepared ? active_generation_->prepared_monotonic_ns -
							  active_generation_->admitted_monotonic_ns :
						  0u,
		.commit_duration_ns = commit_complete ? active_generation_->retiring_started_monotonic_ns -
								active_generation_->commit_started_monotonic_ns :
							0u,
		.retirement_duration_ns = 0u,
		.duration_presence = duration_presence,
		.lease_state = active_generation_->lease_state,
		.prepared_lease_deadline_monotonic_ns = active_generation_->prepared_lease_deadline_monotonic_ns,
		.prepared_lease_deadline_unix_ms = active_generation_->prepared_lease_deadline_unix_ms,
		.failure_code = active_generation_->failure_code,
		.diagnostic = active_generation_->diagnostic,
	};
}

epoch_transition_transaction_observation
epoch_transition_coordinator::terminal_observation_(const epoch_transition_terminal_result &result) const noexcept
{
	return epoch_transition_transaction_observation{
		.resolution = common::transition_identity_resolution::TERMINAL_EXACT,
		.identity = result.identity,
		.watermarks = watermarks_,
		.phase = result.outcome == epoch_transition_outcome::FAILED_STOP ? epoch_transition_phase::FAILED_STOP :
										   epoch_transition_phase::IDLE,
		.outcome = result.outcome,
		.from_epoch = result.from_epoch,
		.to_epoch = result.to_epoch,
		.admitted_monotonic_ns = result.admitted_monotonic_ns,
		.terminal_monotonic_ns = result.terminal_monotonic_ns,
		.prepare_duration_ns = result.prepare_duration_ns,
		.commit_duration_ns = result.commit_duration_ns,
		.retirement_duration_ns = result.retirement_duration_ns,
		.duration_presence = result.duration_presence,
		.lease_state = epoch_transition_prepared_lease_state::NOT_ARMED,
		.prepared_lease_deadline_monotonic_ns = 0u,
		.prepared_lease_deadline_unix_ms = 0u,
		.failure_code = result.failure_code,
		.diagnostic = result.diagnostic,
	};
}

epoch_transition_diagnostic epoch_transition_coordinator::bounded_diagnostic_(std::string_view diagnostic) noexcept
{
	static_assert(common::MAX_TRANSITION_DIAGNOSTIC_BYTES <= std::numeric_limits<uint16_t>::max());
	epoch_transition_diagnostic bounded;
	const std::size_t size = std::min(diagnostic.size(), bounded.bytes.size());
	std::copy_n(diagnostic.begin(), size, bounded.bytes.data());
	bounded.size = static_cast<uint16_t>(size);
	return bounded;
}

status epoch_transition_coordinator::state_error_(epoch_state_result result, const char *operation)
{
	switch (result) {
	case epoch_state_result::APPLIED:
		return status::ok();
	case epoch_state_result::INVALID_ARGUMENT:
		return status::invalid_argument(std::string(operation) + " rejected an invalid transition identity");
	case epoch_state_result::STATE_MISMATCH:
		return status::failed_precondition(std::string(operation) + " is unavailable in the current phase");
	case epoch_state_result::IDENTITY_MISMATCH:
		return status::failed_precondition(std::string(operation) + " does not own the active generation");
	case epoch_state_result::EPOCH_ORDER_VIOLATION:
		return status::failed_precondition(std::string(operation) +
						   " target epoch does not advance active truth");
	}
	return status::internal_error(std::string(operation) + " returned an unknown state result");
}

void epoch_transition_coordinator::publish_progress_or_terminate_() noexcept
{
	const auto *admitted_identity = state_.identity();
	const auto current_phase = state_.phase();
	const bool before_bootstrap = current_phase == epoch_transition_phase::AWAITING_BOOTSTRAP ||
				      current_phase == epoch_transition_phase::BOOTSTRAPPING;
	const bool active_transaction = current_phase == epoch_transition_phase::PREPARING ||
					current_phase == epoch_transition_phase::PREPARED ||
					current_phase == epoch_transition_phase::COMMITTING ||
					current_phase == epoch_transition_phase::RETIRING;
	const bool failed_watermark_state_valid =
		current_phase != epoch_transition_phase::FAILED_STOP ||
		(active_generation_.has_value() && admitted_identity != nullptr &&
		 watermarks_.allocated_epoch == admitted_identity->target_epoch &&
		 watermarks_.mutation_sequence == admitted_identity->mutation_sequence) ||
		(!active_generation_.has_value() && common::valid_epoch_id(state_.active_epoch()) &&
		 common::valid_bootstrap_watermarks(state_.active_epoch(), watermarks_)) ||
		(!active_generation_.has_value() && state_.active_epoch() == 0u && watermarks_.allocated_epoch == 0u &&
		 watermarks_.mutation_sequence == 0u);
	const bool preparing_generation_shape =
		active_generation_.has_value() && active_generation_->candidate != nullptr &&
		active_generation_->lease_state == epoch_transition_prepared_lease_state::NOT_ARMED &&
		active_generation_->prepared_monotonic_ns == 0u &&
		active_generation_->prepared_lease_deadline_monotonic_ns == 0u &&
		active_generation_->prepared_lease_deadline_unix_ms == 0u &&
		active_generation_->commit_started_monotonic_ns == 0u &&
		active_generation_->retiring_started_monotonic_ns == 0u && snapshots_.prepared_epoch() == 0u;
	const bool prepared_generation_shape =
		active_generation_.has_value() && active_generation_->candidate == nullptr &&
		active_generation_->lease_state == epoch_transition_prepared_lease_state::ARMED &&
		active_generation_->prepared_monotonic_ns >= active_generation_->admitted_monotonic_ns &&
		active_generation_->prepared_lease_deadline_monotonic_ns > active_generation_->prepared_monotonic_ns &&
		active_generation_->prepared_lease_deadline_unix_ms != 0u && admitted_identity != nullptr &&
		active_generation_->commit_started_monotonic_ns == 0u &&
		active_generation_->retiring_started_monotonic_ns == 0u &&
		snapshots_.prepared_epoch() == admitted_identity->target_epoch;
	const bool committing_generation_shape =
		active_generation_.has_value() && active_generation_->candidate == nullptr &&
		active_generation_->lease_state == epoch_transition_prepared_lease_state::NOT_ARMED &&
		active_generation_->prepared_monotonic_ns >= active_generation_->admitted_monotonic_ns &&
		active_generation_->prepared_lease_deadline_monotonic_ns == 0u &&
		active_generation_->prepared_lease_deadline_unix_ms == 0u &&
		active_generation_->commit_started_monotonic_ns >= active_generation_->prepared_monotonic_ns &&
		active_generation_->commit_started_monotonic_ns != 0u &&
		active_generation_->retiring_started_monotonic_ns == 0u && admitted_identity != nullptr &&
		snapshots_.active_epoch() == state_.active_epoch() &&
		snapshots_.prepared_epoch() == admitted_identity->target_epoch;
	const bool retiring_generation_shape =
		active_generation_.has_value() && active_generation_->candidate == nullptr &&
		active_generation_->lease_state == epoch_transition_prepared_lease_state::NOT_ARMED &&
		active_generation_->prepared_monotonic_ns >= active_generation_->admitted_monotonic_ns &&
		active_generation_->prepared_lease_deadline_monotonic_ns == 0u &&
		active_generation_->prepared_lease_deadline_unix_ms == 0u &&
		active_generation_->commit_started_monotonic_ns >= active_generation_->prepared_monotonic_ns &&
		active_generation_->commit_started_monotonic_ns != 0u &&
		active_generation_->retiring_started_monotonic_ns >= active_generation_->commit_started_monotonic_ns &&
		active_generation_->retiring_started_monotonic_ns != 0u && admitted_identity != nullptr &&
		snapshots_.active_epoch() == admitted_identity->target_epoch && snapshots_.prepared_epoch() == 0u &&
		(snapshots_.retained_epoch() == state_.active_epoch() || snapshots_.retained_epoch() == 0u);
	const bool no_active_failure =
		active_generation_.has_value() && active_generation_->failure_observed_monotonic_ns == 0u &&
		active_generation_->failure_code == epoch_transition_failure_code::NONE &&
		active_generation_->diagnostic.size == 0u && !active_generation_->retirement_frozen;
	const bool frozen_retirement_shape =
		active_generation_.has_value() && retiring_generation_shape &&
		active_generation_->failure_observed_monotonic_ns >=
			active_generation_->retiring_started_monotonic_ns &&
		active_generation_->failure_code == epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED &&
		active_generation_->diagnostic.size != 0u && active_generation_->retirement_frozen &&
		snapshots_.retained_epoch() == state_.active_epoch();
	const bool failed_generation_shape =
		active_generation_.has_value() &&
		active_generation_->failure_observed_monotonic_ns >= active_generation_->admitted_monotonic_ns &&
		active_generation_->failure_code != epoch_transition_failure_code::NONE &&
		active_generation_->failure_code != epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED &&
		active_generation_->diagnostic.size != 0u && !active_generation_->retirement_frozen;
	const bool generation_phase_shape_valid =
		!active_generation_.has_value() ||
		(current_phase == epoch_transition_phase::PREPARING && preparing_generation_shape &&
		 no_active_failure) ||
		(current_phase == epoch_transition_phase::PREPARED && prepared_generation_shape && no_active_failure) ||
		(current_phase == epoch_transition_phase::COMMITTING && committing_generation_shape &&
		 no_active_failure) ||
		(current_phase == epoch_transition_phase::RETIRING &&
		 ((retiring_generation_shape && no_active_failure) || frozen_retirement_shape)) ||
		(current_phase == epoch_transition_phase::FAILED_STOP && failed_generation_shape &&
		 (preparing_generation_shape || prepared_generation_shape || committing_generation_shape ||
		  retiring_generation_shape));
	const bool abort_cleanup_shape_valid = !abort_cleanup_in_progress_ ||
					       ((current_phase == epoch_transition_phase::PREPARED ||
						 current_phase == epoch_transition_phase::FAILED_STOP) &&
						prepared_generation_shape);
	// active_epoch and active_validation_hash intentionally remain the last
	// globally COMPLETE pair while participant truth has advanced to N/E/N in
	// RETIRING. Exact lookup therefore follows coordinator truth, not the
	// worker-selected active artifact, which already names N in that phase.
	const auto *globally_complete_snapshot = snapshots_.find_exact(state_.active_epoch());
	const bool active_content_shape_valid = (before_bootstrap || state_.active_epoch() == 0u) ?
							digest_is_zero(active_validation_hash_) :
							globally_complete_snapshot != nullptr &&
								globally_complete_snapshot->validation_hash() ==
									active_validation_hash_;
	if (active_generation_.has_value() != (admitted_identity != nullptr) ||
	    (!active_generation_.has_value() && completion_armed_) ||
	    ((current_phase == epoch_transition_phase::PREPARED ||
	      current_phase == epoch_transition_phase::COMMITTING ||
	      current_phase == epoch_transition_phase::RETIRING) &&
	     !completion_armed_) ||
	    (active_generation_.has_value() && (active_generation_->identity != admitted_identity ||
						active_generation_->participants != participants_.get() ||
						active_generation_->admitted_monotonic_ns == 0u)) ||
	    !generation_phase_shape_valid || !abort_cleanup_shape_valid || !active_content_shape_valid ||
	    ((current_phase == epoch_transition_phase::FAILED_STOP) !=
	     (last_terminal_outcome_ == epoch_transition_outcome::FAILED_STOP)) ||
	    (current_phase != epoch_transition_phase::FAILED_STOP &&
	     ((terminal_history_size_ == 0u) != (last_terminal_outcome_ == epoch_transition_outcome::NONE))) ||
	    (before_bootstrap && (watermarks_.allocated_epoch != 0u || watermarks_.mutation_sequence != 0u)) ||
	    (!before_bootstrap && current_phase != epoch_transition_phase::FAILED_STOP &&
	     !common::valid_bootstrap_watermarks(state_.active_epoch(), watermarks_)) ||
	    !failed_watermark_state_valid ||
	    (active_transaction && (watermarks_.allocated_epoch != admitted_identity->target_epoch ||
				    watermarks_.mutation_sequence != admitted_identity->mutation_sequence))) {
		std::terminate();
	}
	const uint32_t execution_count = progress_count_or_terminate(participants_->execution_participant_count());
	const uint32_t region_count = progress_count_or_terminate(participants_->region_count());
	const uint32_t boundary_count = progress_count_or_terminate(participants_->boundary_count());
	const uint32_t source_count = progress_count_or_terminate(participants_->source_participant_indices().size());
	const uint32_t sink_count = progress_count_or_terminate(participants_->sink_participant_indices().size());
	const uint32_t context_count = progress_count_or_terminate(participants_->module_context_count());
	const uint32_t reader_count = progress_count_or_terminate(participants_->quiescence_reader_count());
	const uint32_t history_size = progress_count_or_terminate(terminal_history_size_);

	epoch_transition_telemetry_transaction_snapshot active_telemetry{};
	if (active_generation_.has_value()) {
		if (admitted_identity == nullptr) {
			std::terminate();
		}
		active_telemetry = epoch_transition_telemetry_transaction_snapshot{
			.present = true,
			.identity = *admitted_identity,
			.from_epoch = state_.active_epoch(),
			.to_epoch = admitted_identity->target_epoch,
			.admitted_monotonic_ns = active_generation_->admitted_monotonic_ns,
			.prepared_monotonic_ns = active_generation_->prepared_monotonic_ns,
			.prepared_lease_deadline_monotonic_ns =
				active_generation_->prepared_lease_deadline_monotonic_ns,
			.prepared_lease_deadline_unix_ms = active_generation_->prepared_lease_deadline_unix_ms,
			.commit_started_monotonic_ns = active_generation_->commit_started_monotonic_ns,
			.retiring_started_monotonic_ns = active_generation_->retiring_started_monotonic_ns,
			.failure_observed_monotonic_ns = active_generation_->failure_observed_monotonic_ns,
			.terminal_monotonic_ns = 0u,
			.outcome = epoch_transition_outcome::NONE,
			.failure_code = active_generation_->failure_code,
			.retirement_frozen = active_generation_->retirement_frozen,
		};
	}

	epoch_transition_telemetry_transaction_snapshot terminal_telemetry{};
	if (terminal_history_size_ != 0u) {
		const auto *terminal = terminal_result(terminal_history_size_ - 1u);
		if (terminal == nullptr || terminal->terminal_monotonic_ns < terminal->admitted_monotonic_ns) {
			std::terminate();
		}
		uint64_t prepared_ns = 0u;
		uint64_t commit_ns = 0u;
		uint64_t retiring_ns = 0u;
		if ((terminal->duration_presence & TRANSITION_PREPARE_DURATION_PRESENT) != 0u) {
			if (terminal->prepare_duration_ns > UINT64_MAX - terminal->admitted_monotonic_ns) {
				std::terminate();
			}
			prepared_ns = terminal->admitted_monotonic_ns + terminal->prepare_duration_ns;
		}
		if ((terminal->duration_presence & TRANSITION_RETIREMENT_DURATION_PRESENT) != 0u) {
			if (terminal->retirement_duration_ns > terminal->terminal_monotonic_ns) {
				std::terminate();
			}
			retiring_ns = terminal->terminal_monotonic_ns - terminal->retirement_duration_ns;
		}
		if ((terminal->duration_presence & TRANSITION_COMMIT_DURATION_PRESENT) != 0u) {
			if (retiring_ns == 0u || terminal->commit_duration_ns > retiring_ns) {
				std::terminate();
			}
			commit_ns = retiring_ns - terminal->commit_duration_ns;
		}
		terminal_telemetry = epoch_transition_telemetry_transaction_snapshot{
			.present = true,
			.identity = terminal->identity,
			.from_epoch = terminal->from_epoch,
			.to_epoch = terminal->to_epoch,
			.admitted_monotonic_ns = terminal->admitted_monotonic_ns,
			.prepared_monotonic_ns = prepared_ns,
			.prepared_lease_deadline_monotonic_ns = 0u,
			.prepared_lease_deadline_unix_ms = 0u,
			.commit_started_monotonic_ns = commit_ns,
			.retiring_started_monotonic_ns = retiring_ns,
			.failure_observed_monotonic_ns = terminal->failure_code == epoch_transition_failure_code::NONE ?
								 0u :
								 terminal->terminal_monotonic_ns,
			.terminal_monotonic_ns = terminal->terminal_monotonic_ns,
			.outcome = terminal->outcome,
			.failure_code = terminal->failure_code,
			.retirement_frozen = false,
		};
	}
	const auto active_fields = encode_transaction(active_telemetry);
	const auto terminal_fields = encode_transaction(terminal_telemetry);
	static_assert(TRANSACTION_TELEMETRY_FIELDS == TELEMETRY_TRANSACTION_FIELD_COUNT);
	std::array<uint64_t, TELEMETRY_FIELD_COUNT> telemetry_fields{};
	std::copy(active_fields.begin(), active_fields.end(), telemetry_fields.begin());
	std::copy(terminal_fields.begin(), terminal_fields.end(),
		  telemetry_fields.begin() + TELEMETRY_TRANSACTION_FIELD_COUNT);
	std::copy(protocol_fault_counts_.begin(), protocol_fault_counts_.end(),
		  telemetry_fields.begin() + 2u * TELEMETRY_TRANSACTION_FIELD_COUNT);
	if (!telemetry_.publish(telemetry_fields)) {
		std::terminate();
	}

	const auto active_hash_words = digest_words(active_validation_hash_);
	const std::array<uint64_t, PROGRESS_FIELD_COUNT> fields{
		static_cast<uint64_t>(current_phase),
		state_.active_epoch(),
		active_hash_words[0],
		active_hash_words[1],
		active_hash_words[2],
		active_hash_words[3],
		state_.target_epoch(),
		active_generation_.has_value() ? admitted_identity->mutation_sequence : 0u,
		watermarks_.allocated_epoch,
		watermarks_.mutation_sequence,
		active_generation_.has_value() ? 1u : 0u,
		execution_count,
		region_count,
		boundary_count,
		source_count,
		sink_count,
		context_count,
		reader_count,
		history_size,
		static_cast<uint64_t>(last_terminal_outcome_),
		abort_cleanup_in_progress_ ? 1u : 0u,
		active_generation_.has_value() && active_generation_->retirement_frozen ? 1u : 0u,
	};
	if (!progress_.publish(fields)) {
		std::terminate();
	}
}

void epoch_transition_coordinator::record_protocol_fault_(const epoch_protocol_first_fault &fault) noexcept
{
	if (!valid_epoch_protocol_fault_code(fault.code)) {
		std::terminate();
	}
	auto &count = protocol_fault_counts_[epoch_protocol_fault_ordinal(fault.code)];
	if (count != UINT64_MAX) {
		++count;
	}
	if (protocol_faults_ != nullptr) {
		if (fault.runtime_generation != protocol_runtime_generation_) {
			std::terminate();
		}
		(void)protocol_faults_->record(fault);
	}
}

void epoch_transition_coordinator::append_terminal_result_(const epoch_transition_terminal_result &result) noexcept
{
	const bool diagnostic_shape_valid = (result.outcome == epoch_transition_outcome::COMPLETE &&
					     result.failure_code == epoch_transition_failure_code::NONE &&
					     result.diagnostic.size == 0u) ||
					    (result.outcome != epoch_transition_outcome::COMPLETE &&
					     result.failure_code != epoch_transition_failure_code::NONE);
	const bool duration_shape_valid =
		(result.duration_presence & static_cast<uint8_t>(~TRANSITION_DURATION_PRESENCE_MASK)) == 0u &&
		(((result.duration_presence & TRANSITION_PREPARE_DURATION_PRESENT) != 0u) ||
		 result.prepare_duration_ns == 0u) &&
		(((result.duration_presence & TRANSITION_COMMIT_DURATION_PRESENT) != 0u) ||
		 result.commit_duration_ns == 0u) &&
		(((result.duration_presence & TRANSITION_RETIREMENT_DURATION_PRESENT) != 0u) ||
		 result.retirement_duration_ns == 0u);
	if (terminal_history_.empty() || result.outcome == epoch_transition_outcome::NONE || !result.identity.valid() ||
	    result.from_epoch == 0u || result.to_epoch != result.identity.target_epoch ||
	    result.admitted_monotonic_ns == 0u || result.terminal_monotonic_ns < result.admitted_monotonic_ns ||
	    result.prepare_duration_ns > result.terminal_monotonic_ns - result.admitted_monotonic_ns ||
	    result.commit_duration_ns > result.terminal_monotonic_ns - result.admitted_monotonic_ns ||
	    result.retirement_duration_ns > result.terminal_monotonic_ns - result.admitted_monotonic_ns ||
	    !duration_shape_valid || !diagnostic_shape_valid ||
	    result.diagnostic.size > result.diagnostic.bytes.size()) {
		std::terminate();
	}
	std::size_t index = 0;
	if (terminal_history_size_ < terminal_history_.size()) {
		index = (terminal_history_begin_ + terminal_history_size_) % terminal_history_.size();
		++terminal_history_size_;
	} else {
		index = terminal_history_begin_;
		terminal_history_begin_ = (terminal_history_begin_ + 1u) % terminal_history_.size();
	}
	terminal_history_[index] = result;
}

}  // namespace kinetum::dp
