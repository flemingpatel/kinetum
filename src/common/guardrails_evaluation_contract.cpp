// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file guardrails_evaluation_contract.cpp
 * @brief Exact public evaluator state and retained attribution validation.
 * @author Fleming Patel
 */

#include "src/common/guardrails_evaluation_contract.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <new>
#include <optional>
#include <stdexcept>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_telemetry_contract.hpp"
#include "src/common/sha256_digest.hpp"
#include "src/common/utf8.hpp"

namespace kinetum::common
{
namespace
{

namespace wire = kinetum::control::v1;

/**
 * @param identity Candidate runtime/content binding.
 * @return True for complete bounded identity fields.
 */
[[nodiscard]] bool identity_valid(const wire::GuardrailsObservationIdentity &identity) noexcept
{
	return identity.runtime_generation() != 0u && identity.runtime_generation() <= UINT32_MAX &&
	       !identity.snapshot_id().empty() && identity.snapshot_id().size() <= MAX_CONFIG_SNAPSHOT_ID_BYTES &&
	       valid_utf8(identity.snapshot_id()) && identity.epoch() != 0u && identity.epoch() != UINT64_MAX &&
	       identity.revision() <= static_cast<uint64_t>(MAX_CONFIG_SNAPSHOT_REVISION) &&
	       identity.validation_hash().size() == SHA256_DIGEST_SIZE && identity.expected_workers() != 0u;
}

/**
 * @param candidate Retained evaluation or attribution identity.
 * @param observed Current evaluator binding.
 * @return True for the same runtime/population and an exact current or older epoch.
 */
[[nodiscard]] bool retained_identity_valid(const wire::GuardrailsObservationIdentity &candidate,
					   const wire::GuardrailsObservationIdentity &observed) noexcept
{
	return identity_valid(candidate) && candidate.runtime_generation() == observed.runtime_generation() &&
	       candidate.expected_workers() == observed.expected_workers() && candidate.epoch() <= observed.epoch() &&
	       (candidate.epoch() != observed.epoch() ||
		(candidate.snapshot_id() == observed.snapshot_id() && candidate.revision() == observed.revision() &&
		 candidate.validation_hash() == observed.validation_hash()));
}

/**
 * @param left First complete identity.
 * @param right Second complete identity.
 * @return True when every public content/namespace field matches.
 */
[[nodiscard]] bool same_identity(const wire::GuardrailsObservationIdentity &left,
				 const wire::GuardrailsObservationIdentity &right) noexcept
{
	return left.runtime_generation() == right.runtime_generation() && left.snapshot_id() == right.snapshot_id() &&
	       left.epoch() == right.epoch() && left.revision() == right.revision() &&
	       left.validation_hash() == right.validation_hash() && left.expected_workers() == right.expected_workers();
}

/**
 * @param proof Retained attribution with a validated candidate identity.
 * @return Positive common coverage for complete advancing endpoints, or absence for invalid evidence.
 */
[[nodiscard]] std::optional<uint64_t> proof_coverage(const wire::GuardrailsAttribution &proof) noexcept
{
	if (static_cast<uint64_t>(proof.previous_workers_size()) != proof.candidate().expected_workers() ||
	    proof.current_workers_size() != proof.previous_workers_size()) {
		return std::nullopt;
	}
	uint64_t begin = 0u;
	uint64_t end = UINT64_MAX;
	std::array<uint64_t, 6> previous_totals{};
	std::array<uint64_t, 6> current_totals{};
	for (int index = 0; index < proof.previous_workers_size(); ++index) {
		const auto &before = proof.previous_workers(index);
		const auto &after = proof.current_workers(index);
		if (!valid_worker_counter_observation(before) || !valid_worker_counter_observation(after) ||
		    before.worker_index() != static_cast<uint32_t>(index) ||
		    before.worker_index() != after.worker_index() ||
		    before.observation_epoch() != proof.candidate().epoch() ||
		    after.observation_epoch() != proof.candidate().epoch() ||
		    after.publication_generation() <= before.publication_generation() ||
		    after.published_monotonic_ns() <= before.published_monotonic_ns()) {
			return std::nullopt;
		}
		const auto previous_counts = engine_counter_values(before.counters());
		const auto current_counts = engine_counter_values(after.counters());
		for (std::size_t ordinal = 0u; ordinal < current_counts.size(); ++ordinal) {
			if (current_counts[ordinal] < previous_counts[ordinal] ||
			    previous_counts[ordinal] >= UINT64_MAX - previous_totals[ordinal] ||
			    current_counts[ordinal] >= UINT64_MAX - current_totals[ordinal]) {
				return std::nullopt;
			}
			previous_totals[ordinal] += previous_counts[ordinal];
			current_totals[ordinal] += current_counts[ordinal];
		}
		begin = std::max(begin, before.published_monotonic_ns());
		end = std::min(end, after.published_monotonic_ns());
	}
	return end > begin ? std::optional<uint64_t>{end - begin} : std::nullopt;
}

}  // namespace

status validate_guardrails_evaluation(const kinetum::control::v1::GuardrailsEvaluation &value,
				      const kinetum::control::v1::GuardrailsPolicy *policy, uint64_t generation)
try {
	auto unknown = reject_unknown_protobuf_fields_recursive(value, "GuardrailsEvaluation");
	if (!unknown.is_ok()) {
		return unknown;
	}
	auto enums = reject_invalid_protobuf_enum_values_recursive(value, "GuardrailsEvaluation");
	if (!enums.is_ok()) {
		return enums;
	}
	if (generation == UINT64_MAX || value.state() == wire::GUARDRAILS_EVALUATION_STATE_UNSPECIFIED ||
	    value.policy_generation() != generation || (generation == 0u) != (policy == nullptr)) {
		return status::invalid_argument("guardrails evaluation lacks exact policy identity or state");
	}
	const bool enabled = policy != nullptr && policy->enabled();
	const bool empty = !value.has_observed_identity() && value.baseline_intervals() == 0u &&
			   value.valid_observation_ns() == 0u && !value.has_last_completed() &&
			   !value.has_last_attribution();
	if (!enabled) {
		const auto expected = policy == nullptr ? wire::GUARDRAILS_EVALUATION_STATE_UNCONFIGURED :
							  wire::GUARDRAILS_EVALUATION_STATE_DISABLED;
		return empty && (value.state() == expected ||
				 value.state() == wire::GUARDRAILS_EVALUATION_STATE_ROLLBACK_PENDING) ?
			       status::ok() :
			       status::invalid_argument("inactive guardrails evaluation retained measurement evidence");
	}
	if (value.state() == wire::GUARDRAILS_EVALUATION_STATE_UNCONFIGURED ||
	    value.state() == wire::GUARDRAILS_EVALUATION_STATE_DISABLED ||
	    ((value.state() == wire::GUARDRAILS_EVALUATION_STATE_BASELINE_BUILDING ||
	      value.state() == wire::GUARDRAILS_EVALUATION_STATE_ARMED) &&
	     value.valid_observation_ns() != 0u) ||
	    value.baseline_intervals() > policy->telemetry_history_capacity() ||
	    value.valid_observation_ns() > policy->evaluation_window_ms() * 1'000'000u) {
		return status::invalid_argument("guardrails evaluation contradicts its enabled policy bounds");
	}
	if (!value.has_observed_identity()) {
		return empty && (value.state() == wire::GUARDRAILS_EVALUATION_STATE_BASELINE_BUILDING ||
				 value.state() == wire::GUARDRAILS_EVALUATION_STATE_ROLLBACK_PENDING) ?
			       status::ok() :
			       status::invalid_argument(
				       "guardrails evaluation has evidence without an observed identity");
	}
	if (!identity_valid(value.observed_identity()) ||
	    ((value.state() == wire::GUARDRAILS_EVALUATION_STATE_ARMED ||
	      value.state() == wire::GUARDRAILS_EVALUATION_STATE_EVALUATING) &&
	     value.baseline_intervals() < policy->attribution().baseline_samples())) {
		return status::invalid_argument(
			"guardrails evaluation has an invalid identity or incomplete armed baseline");
	}
	if (value.has_last_completed()) {
		const auto &completed = value.last_completed();
		if (!completed.has_candidate() ||
		    !retained_identity_valid(completed.candidate(), value.observed_identity()) ||
		    completed.outcome() == wire::GUARDRAILS_EVALUATION_OUTCOME_UNSPECIFIED ||
		    completed.valid_observation_ns() > policy->evaluation_window_ms() * 1'000'000u ||
		    (completed.outcome() == wire::GUARDRAILS_EVALUATION_OUTCOME_HISTORY_EXHAUSTED &&
		     completed.valid_observation_ns() == 0u) ||
		    (completed.outcome() == wire::GUARDRAILS_EVALUATION_OUTCOME_WINDOW_COMPLETE &&
		     completed.valid_observation_ns() != policy->evaluation_window_ms() * 1'000'000u)) {
			return status::invalid_argument("guardrails completed evaluation is malformed");
		}
	}
	if (value.has_last_attribution()) {
		const auto &proof = value.last_attribution();
		const auto coverage = proof_coverage(proof);
		if (!proof.has_candidate() || !retained_identity_valid(proof.candidate(), value.observed_identity()) ||
		    proof.rollback_snapshot_id().empty() ||
		    proof.rollback_snapshot_id().size() > MAX_CONFIG_SNAPSHOT_ID_BYTES ||
		    !valid_utf8(proof.rollback_snapshot_id()) ||
		    proof.rollback_snapshot_id() == proof.candidate().snapshot_id() || !coverage.has_value() ||
		    *coverage > policy->evaluation_window_ms() * 1'000'000u ||
		    !std::isfinite(proof.baseline_tx_pps()) || proof.baseline_tx_pps() <= 0.0 ||
		    proof.has_confidence() != proof.evidence_complete() ||
		    (proof.has_confidence() &&
		     (!std::isfinite(proof.confidence()) || proof.confidence() < 0.0 || proof.confidence() > 1.0)) ||
		    proof.recommendation() == wire::GUARDRAILS_RECOMMENDATION_UNSPECIFIED) {
			return status::invalid_argument("guardrails attribution lacks exact measurement evidence");
		}
		if ((value.state() == wire::GUARDRAILS_EVALUATION_STATE_EVALUATING &&
		     same_identity(proof.candidate(), value.observed_identity()) &&
		     *coverage > value.valid_observation_ns()) ||
		    (value.has_last_completed() &&
		     same_identity(proof.candidate(), value.last_completed().candidate()) &&
		     *coverage > value.last_completed().valid_observation_ns())) {
			return status::invalid_argument("guardrails attribution exceeds its recorded evaluation time");
		}
		const auto expected = !proof.evidence_complete() ? wire::GUARDRAILS_RECOMMENDATION_LOG_ONLY :
				      proof.confidence() >= policy->attribution().auto_rollback_threshold() ?
								   wire::GUARDRAILS_RECOMMENDATION_AUTO_ROLLBACK :
				      proof.confidence() >= policy->attribution().defer_threshold() ?
								   wire::GUARDRAILS_RECOMMENDATION_DEFER_TO_HUMAN :
								   wire::GUARDRAILS_RECOMMENDATION_LOG_ONLY;
		if (proof.recommendation() != expected ||
		    (proof.intent_accepted() &&
		     (!proof.evidence_complete() || expected != wire::GUARDRAILS_RECOMMENDATION_AUTO_ROLLBACK))) {
			return status::invalid_argument(
				"guardrails attribution recommendation contradicts policy or acceptance");
		}
	}
	const bool accepted = value.has_last_attribution() && value.last_attribution().intent_accepted();
	const bool accepted_window = value.has_last_completed() &&
				     value.last_completed().outcome() ==
					     wire::GUARDRAILS_EVALUATION_OUTCOME_ROLLBACK_ACCEPTED;
	if (accepted_window &&
	    (value.last_completed().valid_observation_ns() == 0u || !value.has_last_attribution() ||
	     value.last_attribution().candidate().epoch() < value.last_completed().candidate().epoch() ||
	     (value.last_attribution().candidate().epoch() == value.last_completed().candidate().epoch() &&
	      (!accepted ||
	       !same_identity(value.last_completed().candidate(), value.last_attribution().candidate()))))) {
		return status::invalid_argument("guardrails accepted evaluation lacks its attribution proof");
	}
	if (accepted && (!value.has_last_completed() ||
			 value.last_completed().candidate().epoch() < value.last_attribution().candidate().epoch() ||
			 (value.last_completed().candidate().epoch() == value.last_attribution().candidate().epoch() &&
			  (!accepted_window || !same_identity(value.last_completed().candidate(),
							      value.last_attribution().candidate()))))) {
		return status::invalid_argument("guardrails accepted attribution lacks its completed evaluation");
	}
	return status::ok();
} catch (const std::bad_alloc &) {
	return status::resource_exhausted("guardrails evaluation validation exhausted memory");
} catch (const std::length_error &) {
	return status(status_code::OUT_OF_RANGE, "guardrails evaluation validation exceeded host size limits");
}

}  // namespace kinetum::common
