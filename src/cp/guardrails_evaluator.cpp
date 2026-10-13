// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file guardrails_evaluator.cpp
 * @brief Deterministic evidence-window and rollback-attribution owner.
 * @author Fleming Patel
 */

#include "src/cp/guardrails_evaluator.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "gen/kinetum/control/internal/v1/transition_authority.pb.h"
#include "src/common/time.hpp"
#include "src/common/runtime_telemetry_contract.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/cp/guardrails_policy.hpp"

namespace kinetum::cp
{
namespace
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

/**
 * @brief Test whether one private transition phase remains unresolved.
 * @param phase Candidate durable phase.
 * @return true only for one nonterminal phase.
 */
[[nodiscard]] bool nonterminal_phase(kinetum::control::internal::v1::DurableEpochTransitionPhase phase) noexcept
{
	using phase_type = kinetum::control::internal::v1::DurableEpochTransitionPhase;
	switch (phase) {
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING:
		return true;
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_UNSPECIFIED:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Require every compiled module context to contribute current health.
 * @param observation Exact fenced observation with selected module-health rows.
 * @return true only for a nonempty complete current signal set.
 */
[[nodiscard]] bool complete_current_module_health(const guardrails_runtime_observation &observation) noexcept
{
	const auto &telemetry = observation.stats.telemetry();
	if (telemetry.transition().module_context_count() == 0u ||
	    static_cast<uint64_t>(telemetry.module_health_size()) != telemetry.transition().module_context_count()) {
		return false;
	}
	return std::all_of(telemetry.module_health().begin(), telemetry.module_health().end(), [&](const auto &row) {
		return row.state() == kinetum::telemetry::v1::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE &&
		       row.has_observation_epoch() && row.has_health_score() && row.has_health_flags() &&
		       row.observation_epoch() == telemetry.runtime().active_epoch();
	});
}

/**
 * @brief Determine whether one exact boundary exceeded configured ACK age.
 * @param observation Exact fenced transition observation.
 * @param timeout_ms Positive policy timeout.
 * @return true only for a generation-exact WAITING_ACK row at or beyond age.
 */
[[nodiscard]] bool boundary_ack_timeout(const guardrails_runtime_observation &observation, uint64_t timeout_ms) noexcept
{
	const auto &telemetry = observation.stats.telemetry();
	if (!telemetry.transition().has_active_transaction() || timeout_ms == 0u ||
	    timeout_ms > std::numeric_limits<uint64_t>::max() / 1'000'000u) {
		return false;
	}
	const uint64_t timeout_ns = timeout_ms * 1'000'000u;
	const uint64_t now = telemetry.runtime().collection_monotonic_ns();
	const uint64_t generation = telemetry.transition().active_transaction().mutation_sequence();
	return std::any_of(telemetry.boundaries().begin(), telemetry.boundaries().end(), [&](const auto &row) {
		return row.sender_phase() == kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_WAITING_ACK &&
		       row.has_transition_generation() && row.transition_generation() == generation &&
		       row.has_cut_published_monotonic_ns() && !row.has_ack_observed_monotonic_ns() &&
		       now >= row.cut_published_monotonic_ns() && now - row.cut_published_monotonic_ns() >= timeout_ns;
	});
}

/**
 * @brief Add one elapsed interval without unsigned wrap.
 * @param left Accumulated valid-observation time.
 * @param right Current contiguous interval.
 * @return Exact sum or the uint64_t maximum on overflow.
 */
[[nodiscard]] uint64_t saturating_add(uint64_t left, uint64_t right) noexcept
{
	return right > std::numeric_limits<uint64_t>::max() - left ? std::numeric_limits<uint64_t>::max() :
								     left + right;
}

/**
 * @param action Actual attribution outcome.
 * @return Exact public recommendation for that result.
 */
[[nodiscard]] kinetum::control::v1::GuardrailsRecommendation recommendation(attribution_result::action action) noexcept
{
	switch (action) {
	case attribution_result::action::AUTO_ROLLBACK:
		return kinetum::control::v1::GUARDRAILS_RECOMMENDATION_AUTO_ROLLBACK;
	case attribution_result::action::DEFER_TO_HUMAN:
		return kinetum::control::v1::GUARDRAILS_RECOMMENDATION_DEFER_TO_HUMAN;
	case attribution_result::action::LOG_ONLY:
		return kinetum::control::v1::GUARDRAILS_RECOMMENDATION_LOG_ONLY;
	}
	std::terminate();
}

}  // namespace

void guardrails_evaluator::reset_evidence_(guardrails_evaluator_state state) noexcept
{
	state_ = state;
	previous_.reset();
	std::vector<telemetry_snapshot>{}.swap(frozen_baseline_);
	current_identity_.reset();
	rollback_snapshot_id_.clear();
	baseline_tx_pps_ = 0.0;
	evaluation_elapsed_ns_ = 0u;
	interval_contiguous_ = false;
	if (history_ != nullptr) {
		history_->clear();
	}
	if (correlator_ != nullptr) {
		correlator_->reset();
	}
}

void guardrails_evaluator::seed_current_(const cumulative_point &point)
{
	const bool current = std::all_of(point.workers.begin(), point.workers.end(),
					 [&point](const auto &row) { return row.observation_epoch() == point.epoch; });
	auto identity = identity_from_(point);
	auto previous = current ? std::optional<cumulative_point>{point} : std::nullopt;
	current_identity_ = std::move(identity);
	previous_ = std::move(previous);
	interval_contiguous_ = current;
	if (correlator_ != nullptr) {
		correlator_->on_config_change(point.snapshot_id);
	}
}

status guardrails_evaluator::apply_policy(const kinetum::control::v1::GuardrailsPolicy &policy, uint64_t generation)
{
	if (generation == 0u || generation == std::numeric_limits<uint64_t>::max()) {
		return status::invalid_argument("guardrails policy generation is invalid");
	}
	auto validation = validate_guardrails_policy(policy);
	if (!validation.is_ok()) {
		return validation;
	}
	if (policy_generation_ != 0u && generation < policy_generation_) {
		return status::failed_precondition("guardrails policy generation regressed");
	}
	if (generation == policy_generation_) {
		auto current_or = canonicalize_guardrails_policy(policy_);
		auto candidate_or = canonicalize_guardrails_policy(policy);
		if (!current_or.is_ok() || !candidate_or.is_ok()) {
			return !current_or.is_ok() ? current_or.error() : candidate_or.error();
		}
		return current_or->policy_hash == candidate_or->policy_hash ?
			       status::ok() :
			       status::failed_precondition(
				       "guardrails policy generation is retained by different content");
	}
	try {
		kinetum::control::v1::GuardrailsPolicy next_policy(policy);
		std::unique_ptr<telemetry_history> next_history;
		std::unique_ptr<attribution_scorer> next_scorer;
		std::unique_ptr<health_correlator> next_correlator;
		if (policy.enabled()) {
			next_history = std::make_unique<telemetry_history>(policy.telemetry_history_capacity());
			const attribution_config attribution{
				.auto_rollback_threshold = policy.attribution().auto_rollback_threshold(),
				.defer_threshold = policy.attribution().defer_threshold(),
				.baseline_samples = policy.attribution().baseline_samples(),
				.degradation_threshold = policy.attribution().degradation_threshold(),
				.require_module_health = policy.has_correlation() &&
							 (policy.correlation().module_health_weight() > 0.0 ||
							  policy.correlation().config_issue_boost() > 0.0),
			};
			next_scorer = std::make_unique<attribution_scorer>(attribution);
			if (policy.has_correlation()) {
				const auto &configured = policy.correlation();
				next_correlator = std::make_unique<health_correlator>(health_correlation_config{
					.ewma_alpha = configured.ewma_alpha(),
					.degradation_threshold = configured.degradation_threshold(),
					.hysteresis_band = configured.hysteresis_band(),
					.normalization_max_drop_ratio = configured.normalization_max_drop_ratio(),
					.normalization_min_tx_ratio = configured.normalization_min_tx_ratio(),
					.weights =
						correlation_weights{
							.drop_ratio = configured.drop_ratio_weight(),
							.throughput_ratio = configured.throughput_ratio_weight(),
							.module_health = configured.module_health_weight(),
							.config_issue_boost = configured.config_issue_boost(),
						},
					.min_samples = configured.min_samples(),
				});
			}
		}

		policy_ = std::move(next_policy);
		policy_generation_ = generation;
		history_ = std::move(next_history);
		scorer_ = std::move(next_scorer);
		correlator_ = std::move(next_correlator);
		last_completed_.reset();
		last_attribution_.reset();
		reset_evidence_(policy_.enabled() ? guardrails_evaluator_state::BASELINE_BUILDING :
						    guardrails_evaluator_state::DISABLED);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("guardrails evaluator policy allocation failed");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "guardrails evaluator policy exceeded host size limits");
	}
}

void guardrails_evaluator::pause_observation() noexcept
{
	interval_contiguous_ = false;
}

void guardrails_evaluator::mark_rollback_pending(bool attribution_accepted) noexcept
{
	if (attribution_accepted && state_ == guardrails_evaluator_state::EVALUATING && last_attribution_.has_value() &&
	    observed_.has_value() &&
	    last_attribution_->recommendation() == kinetum::control::v1::GUARDRAILS_RECOMMENDATION_AUTO_ROLLBACK &&
	    last_attribution_->candidate().epoch() == observed_->epoch &&
	    last_attribution_->candidate().snapshot_id() == observed_->snapshot_id) {
		last_attribution_->set_intent_accepted(true);
		complete_evaluation_(*observed_, kinetum::control::v1::GUARDRAILS_EVALUATION_OUTCOME_ROLLBACK_ACCEPTED);
	}
	state_ = guardrails_evaluator_state::ROLLBACK_PENDING;
	interval_contiguous_ = false;
}

void guardrails_evaluator::resume_after_intent() noexcept
{
	reset_evidence_(policy_generation_ == 0u ? guardrails_evaluator_state::UNCONFIGURED :
			policy_.enabled()	 ? guardrails_evaluator_state::BASELINE_BUILDING :
						   guardrails_evaluator_state::DISABLED);
}

guardrails_evaluator_state guardrails_evaluator::state() const noexcept
{
	return state_;
}

uint64_t guardrails_evaluator::policy_generation() const noexcept
{
	return policy_generation_;
}

bool guardrails_evaluator::enabled() const noexcept
{
	return policy_generation_ != 0u && policy_.enabled();
}

bool guardrails_evaluator::requires_module_health() const noexcept
{
	return enabled() && policy_.has_correlation() &&
	       (policy_.correlation().module_health_weight() > 0.0 || policy_.correlation().config_issue_boost() > 0.0);
}

bool guardrails_evaluator::requires_boundary_rows() const noexcept
{
	return enabled() && policy_.has_boundary();
}

std::chrono::milliseconds guardrails_evaluator::poll_interval() const noexcept
{
	return enabled() ? std::chrono::milliseconds(static_cast<int64_t>(policy_.poll_interval_ms())) :
			   std::chrono::milliseconds::zero();
}

guardrails_evaluator::cumulative_point
guardrails_evaluator::point_from_(const guardrails_runtime_observation &observation)
{
	const auto &telemetry = observation.stats.telemetry();
	return cumulative_point{
		.snapshot_id = observation.active_authority.snapshot_id,
		.epoch = observation.active_authority.active_epoch,
		.runtime_generation = telemetry.runtime().runtime_generation(),
		.revision = static_cast<uint64_t>(observation.active_authority.revision),
		.validation_hash = observation.active_authority.active_validation_hash,
		.rx_packets = telemetry.engine().rx_packets(),
		.tx_packets = telemetry.engine().tx_packets(),
		.dropped_packets = telemetry.engine().dropped_packets(),
		.workers = {telemetry.worker_counters().begin(), telemetry.worker_counters().end()},
	};
}

status guardrails_evaluator::accept_cursors_(const cumulative_point &point)
{
	if (point.workers.empty()) {
		return status::data_loss("guardrails worker observations are absent");
	}
	const bool same_runtime = observed_.has_value() && observed_->runtime_generation == point.runtime_generation;
	if (same_runtime && observed_->workers.size() != point.workers.size()) {
		return status::data_loss("guardrails worker membership changed inside one runtime generation");
	}
	if (same_runtime && (point.epoch < observed_->epoch ||
			     (point.epoch == observed_->epoch &&
			      (point.snapshot_id != observed_->snapshot_id || point.revision != observed_->revision ||
			       point.validation_hash != observed_->validation_hash)))) {
		return status::data_loss("guardrails active content changed without a new epoch");
	}
	for (std::size_t index = 0u; index < point.workers.size(); ++index) {
		const auto &row = point.workers[index];
		if (row.worker_index() != index || !kinetum::common::valid_worker_counter_observation(row)) {
			return status::data_loss("guardrails worker observation identity is malformed");
		}
		if (!same_runtime) {
			continue;
		}
		const auto &prior = observed_->workers[index];
		const auto counts = kinetum::common::engine_counter_values(row.counters());
		const auto previous_counts = kinetum::common::engine_counter_values(prior.counters());
		if (row.publication_generation() < prior.publication_generation() ||
		    row.observation_epoch() < prior.observation_epoch() ||
		    row.published_monotonic_ns() < prior.published_monotonic_ns() ||
		    (row.publication_generation() == prior.publication_generation() &&
		     (row.observation_epoch() != prior.observation_epoch() ||
		      row.published_monotonic_ns() != prior.published_monotonic_ns() || counts != previous_counts))) {
			return status::data_loss(
				"guardrails worker publication regressed or changed without a new identity");
		}
		for (std::size_t ordinal = 0u; ordinal < counts.size(); ++ordinal) {
			if (counts[ordinal] < previous_counts[ordinal]) {
				return status::data_loss(
					"guardrails worker counters regressed inside one runtime generation");
			}
		}
	}
	// Allocate the replacement before changing the namespace or either cursor.
	cumulative_point next(point);
	if (observed_.has_value() && !same_runtime) {
		reset_evidence_(guardrails_evaluator_state::BASELINE_BUILDING);
		last_completed_.reset();
		last_attribution_.reset();
	}
	observed_ = std::move(next);
	return status::ok();
}

kinetum::control::v1::GuardrailsObservationIdentity guardrails_evaluator::identity_from_(const cumulative_point &point)
{
	kinetum::control::v1::GuardrailsObservationIdentity identity;
	identity.set_runtime_generation(point.runtime_generation);
	identity.set_snapshot_id(point.snapshot_id);
	identity.set_epoch(point.epoch);
	identity.set_revision(point.revision);
	identity.set_validation_hash(reinterpret_cast<const char *>(point.validation_hash.data()),
				     point.validation_hash.size());
	identity.set_expected_workers(static_cast<uint32_t>(point.workers.size()));
	return identity;
}

void guardrails_evaluator::complete_evaluation_(const cumulative_point &point,
						kinetum::control::v1::GuardrailsEvaluationOutcome outcome)
{
	kinetum::control::v1::GuardrailsCompletedEvaluation completed;
	*completed.mutable_candidate() = identity_from_(point);
	completed.set_valid_observation_ns(evaluation_elapsed_ns_);
	completed.set_outcome(outcome);
	last_completed_ = std::move(completed);
}

kinetum::control::v1::GuardrailsEvaluation guardrails_evaluator::evaluation() const
{
	using namespace kinetum::control::v1;
	GuardrailsEvaluation result;
	switch (state_) {
	case guardrails_evaluator_state::UNCONFIGURED:
		result.set_state(GUARDRAILS_EVALUATION_STATE_UNCONFIGURED);
		break;
	case guardrails_evaluator_state::DISABLED:
		result.set_state(GUARDRAILS_EVALUATION_STATE_DISABLED);
		break;
	case guardrails_evaluator_state::BASELINE_BUILDING:
		result.set_state(GUARDRAILS_EVALUATION_STATE_BASELINE_BUILDING);
		break;
	case guardrails_evaluator_state::ARMED:
		result.set_state(GUARDRAILS_EVALUATION_STATE_ARMED);
		break;
	case guardrails_evaluator_state::EVALUATING:
		result.set_state(GUARDRAILS_EVALUATION_STATE_EVALUATING);
		break;
	case guardrails_evaluator_state::ROLLBACK_PENDING:
		result.set_state(GUARDRAILS_EVALUATION_STATE_ROLLBACK_PENDING);
		break;
	}
	result.set_policy_generation(policy_generation_);
	if (enabled() && current_identity_.has_value()) {
		*result.mutable_observed_identity() = *current_identity_;
	}
	if (history_ != nullptr && current_identity_.has_value()) {
		result.set_baseline_intervals(static_cast<uint32_t>(
			!frozen_baseline_.empty() ?
				frozen_baseline_.size() :
				history_->summary_for_config(current_identity_->snapshot_id()).sample_count));
	}
	result.set_valid_observation_ns(evaluation_elapsed_ns_);
	if (result.has_observed_identity() && last_completed_.has_value()) {
		*result.mutable_last_completed() = *last_completed_;
	}
	if (result.has_observed_identity() && last_attribution_.has_value()) {
		*result.mutable_last_attribution() = *last_attribution_;
	}
	return result;
}

status_or<std::optional<telemetry_snapshot>>
guardrails_evaluator::interval_sample_(const cumulative_point &previous, const cumulative_point &point,
				       const guardrails_runtime_observation &current, double baseline_tx_pps)
{
	if (previous.snapshot_id != point.snapshot_id || previous.epoch != point.epoch ||
	    previous.runtime_generation != point.runtime_generation) {
		return status::failed_precondition("telemetry interval crossed an identity boundary");
	}
	if (point.workers.size() != previous.workers.size()) {
		return status::data_loss("telemetry interval changed worker membership");
	}
	uint64_t common_start = 0u;
	uint64_t common_end = UINT64_MAX;
	long double tx_rate = 0.0L;
	long double drop_rate = 0.0L;
	for (std::size_t index = 0u; index < point.workers.size(); ++index) {
		const auto &before = previous.workers[index];
		const auto &after = point.workers[index];
		if (after.publication_generation() == before.publication_generation() ||
		    after.published_monotonic_ns() == before.published_monotonic_ns()) {
			return std::optional<telemetry_snapshot>{};
		}
		common_start = std::max(common_start, before.published_monotonic_ns());
		common_end = std::min(common_end, after.published_monotonic_ns());
		const long double elapsed =
			static_cast<long double>(after.published_monotonic_ns() - before.published_monotonic_ns());
		tx_rate += static_cast<long double>(after.counters().tx_packets() - before.counters().tx_packets()) *
			   1'000'000'000.0L / elapsed;
		drop_rate += static_cast<long double>(after.counters().dropped_packets() -
						      before.counters().dropped_packets()) *
			     1'000'000'000.0L / elapsed;
	}
	if (common_end <= common_start) {
		return std::optional<telemetry_snapshot>{};
	}
	const double tx_pps = static_cast<double>(tx_rate);
	const double drop_pps = static_cast<double>(drop_rate);
	const double drop_ratio = tx_rate + drop_rate == 0.0L ? 0.0 :
								static_cast<double>(drop_rate / (tx_rate + drop_rate));

	telemetry_snapshot sample;
	sample.config_snapshot_id = point.snapshot_id;
	sample.epoch = point.epoch;
	sample.runtime_generation = point.runtime_generation;
	sample.timestamp_ms = static_cast<uint64_t>(std::max<int64_t>(0, kinetum::common::unix_time_ms()));
	sample.timestamp_mono_ns = common_end;
	sample.covered_duration_ns = common_end - common_start;
	sample.rx_packets = point.rx_packets;
	sample.tx_packets = point.tx_packets;
	sample.dropped_packets = point.dropped_packets;
	sample.tx_pps = tx_pps;
	sample.drop_pps = drop_pps;
	sample.drop_ratio = drop_ratio;
	sample.throughput_ratio = baseline_tx_pps > 0.0 ? tx_pps / baseline_tx_pps : 1.0;

	double health_sum = 0.0;
	for (const auto &health : current.stats.telemetry().module_health()) {
		if (health.state() != kinetum::telemetry::v1::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE ||
		    !health.has_health_score() || !health.has_health_flags()) {
			continue;
		}
		++sample.module_health_count;
		health_sum += health.health_score();
		if ((health.health_flags() & KINETUM_HEALTH_F_CONFIG_ISSUE) != 0u) {
			++sample.config_issue_count;
		}
	}
	if (sample.module_health_count != 0u) {
		sample.module_health_avg = health_sum / static_cast<double>(sample.module_health_count);
	}
	const double infrastructure_degradation =
		std::clamp(std::max(drop_ratio, 1.0 - sample.throughput_ratio), 0.0, 1.0);
	sample.degradation_score = infrastructure_degradation;
	sample.health_score = (1.0 - infrastructure_degradation) * 100.0;
	return std::optional<telemetry_snapshot>{std::move(sample)};
}

status_or<std::optional<rollback_intent_request>>
guardrails_evaluator::observe(const guardrails_runtime_observation &observation)
{
	try {
		if (!enabled() || state_ == guardrails_evaluator_state::ROLLBACK_PENDING) {
			return std::optional<rollback_intent_request>{};
		}
		if (!observation.stats.has_telemetry() || !observation.stats.telemetry().has_runtime() ||
		    !observation.stats.telemetry().has_engine() || !observation.stats.telemetry().has_transition() ||
		    observation.active_authority.revision < 0 ||
		    observation.active_authority.revision > kinetum::common::MAX_CONFIG_SNAPSHOT_REVISION ||
		    observation.active_authority.snapshot_id.empty() ||
		    observation.active_authority.active_epoch == 0u ||
		    observation.active_authority.active_epoch == UINT64_MAX ||
		    observation.stats.telemetry().runtime().runtime_generation() == 0u ||
		    observation.stats.telemetry().runtime().runtime_generation() > UINT32_MAX ||
		    observation.stats.telemetry().runtime().active_epoch() !=
			    observation.active_authority.active_epoch ||
		    static_cast<uint64_t>(observation.stats.telemetry().worker_counters_size()) !=
			    observation.stats.telemetry().runtime().expected_workers()) {
			return status::data_loss("guardrails evaluator received incomplete fenced telemetry");
		}
		const auto point = point_from_(observation);
		const auto cursors = accept_cursors_(point);
		if (!cursors.is_ok()) {
			pause_observation();
			return cursors;
		}
		if (observation.protocol_faulted) {
			pause_observation();
			return std::optional<rollback_intent_request>{};
		}

		const auto &telemetry = observation.stats.telemetry();
		if (requires_boundary_rows() &&
		    boundary_ack_timeout(observation, policy_.boundary().ack_timeout_ms())) {
			pause_observation();
			if (!observation.transition.has_value() || !nonterminal_phase(observation.transition->phase) ||
			    !telemetry.transition().has_active_transaction() ||
			    telemetry.transition().active_transaction().mutation_sequence() !=
				    observation.transition->identity.mutation_sequence ||
			    observation.transition->snapshot_id == observation.active_authority.snapshot_id) {
				return std::optional<rollback_intent_request>{};
			}
			rollback_intent_request request;
			request.target_snapshot_id = observation.active_authority.snapshot_id;
			request.guarded_snapshot_id = observation.transition->snapshot_id;
			request.guarded_epoch = observation.transition->identity.target_epoch;
			request.guarded_revision = observation.transition->revision;
			request.guarded_validation_hash = observation.transition->identity.validation_hash;
			request.wait_for_mutation_sequence = observation.transition->identity.mutation_sequence;
			request.policy_generation = policy_generation_;
			request.runtime_generation = telemetry.runtime().runtime_generation();
			request.cause = rollback_intent_cause::BOUNDARY_ACK_TIMEOUT;
			request.observed_monotonic_ns = telemetry.runtime().collection_monotonic_ns();
			return std::optional<rollback_intent_request>{std::move(request)};
		}

		if (observation.transition.has_value() && nonterminal_phase(observation.transition->phase)) {
			pause_observation();
			return std::optional<rollback_intent_request>{};
		}
		if (telemetry.transition().state() != kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE) {
			pause_observation();
			return std::optional<rollback_intent_request>{};
		}
		const bool identity_changed = !current_identity_.has_value() ||
					      point.snapshot_id != current_identity_->snapshot_id() ||
					      point.epoch != current_identity_->epoch();
		if (!current_identity_.has_value()) {
			seed_current_(point);
		} else if (identity_changed) {
			const bool content_changed = point.snapshot_id != current_identity_->snapshot_id();
			if (state_ == guardrails_evaluator_state::ARMED && content_changed) {
				std::string rollback_snapshot_id = current_identity_->snapshot_id();
				auto frozen_baseline = history_->take_for_config(current_identity_->snapshot_id());
				frozen_baseline_ = std::move(frozen_baseline);
				rollback_snapshot_id_ = std::move(rollback_snapshot_id);
				evaluation_elapsed_ns_ = 0u;
				state_ = guardrails_evaluator_state::EVALUATING;
				seed_current_(point);
			} else {
				reset_evidence_(guardrails_evaluator_state::BASELINE_BUILDING);
				seed_current_(point);
			}
		}

		if (requires_module_health() && !complete_current_module_health(observation)) {
			pause_observation();
			return std::optional<rollback_intent_request>{};
		}
		if (!std::all_of(point.workers.begin(), point.workers.end(),
				 [&point](const auto &row) { return row.observation_epoch() == point.epoch; })) {
			pause_observation();
			return std::optional<rollback_intent_request>{};
		}
		if (identity_changed) {
			return std::optional<rollback_intent_request>{};
		}
		if (!previous_.has_value()) {
			previous_ = point;
			interval_contiguous_ = true;
			return std::optional<rollback_intent_request>{};
		}
		if (!interval_contiguous_) {
			previous_ = point;
			interval_contiguous_ = true;
			return std::optional<rollback_intent_request>{};
		}

		auto sample_or = interval_sample_(*previous_, point, observation, baseline_tx_pps_);
		if (!sample_or.is_ok()) {
			pause_observation();
			return sample_or.error();
		}
		if (!sample_or->has_value()) {
			return std::optional<rollback_intent_request>{};
		}
		auto sample = std::move(sample_or).value().value();
		if (state_ == guardrails_evaluator_state::EVALUATING) {
			const uint64_t window_ns = policy_.evaluation_window_ms() * 1'000'000u;
			const bool history_full =
				history_->summary_for_config(current_identity_->snapshot_id()).sample_count >=
				policy_.telemetry_history_capacity();
			if (history_full || sample.covered_duration_ns > window_ns - evaluation_elapsed_ns_) {
				complete_evaluation_(
					point,
					history_full ?
						kinetum::control::v1::GUARDRAILS_EVALUATION_OUTCOME_HISTORY_EXHAUSTED :
						kinetum::control::v1::
							GUARDRAILS_EVALUATION_OUTCOME_INTERVAL_EXCEEDS_WINDOW);
				reset_evidence_(guardrails_evaluator_state::BASELINE_BUILDING);
				seed_current_(point);
				return std::optional<rollback_intent_request>{};
			}
		} else if (baseline_tx_pps_ == 0.0 && sample.tx_pps == 0.0) {
			// A seed with no throughput reference cannot fabricate neutral health.
			previous_ = point;
			return std::optional<rollback_intent_request>{};
		}
		uint64_t correlation_sample_count = 0u;
		if (correlator_ != nullptr) {
			const auto breakdown = correlator_->update(sample);
			sample.health_score = breakdown.health_score;
			sample.degradation_score = breakdown.degradation_score;
			sample.is_degraded = breakdown.is_degraded;
			correlation_sample_count = breakdown.samples_since_config_change;
		}
		std::optional<rollback_intent_request> decision;
		if (state_ == guardrails_evaluator_state::BASELINE_BUILDING ||
		    state_ == guardrails_evaluator_state::ARMED) {
			history_->record(sample);
			const auto baseline = history_->summary_for_config(point.snapshot_id);
			baseline_tx_pps_ = baseline.mean_tx_pps;
			if (baseline.sample_count >= policy_.attribution().baseline_samples() &&
			    baseline_tx_pps_ > 0.0) {
				state_ = guardrails_evaluator_state::ARMED;
			} else {
				state_ = guardrails_evaluator_state::BASELINE_BUILDING;
			}
		} else if (state_ == guardrails_evaluator_state::EVALUATING) {
			evaluation_elapsed_ns_ += sample.covered_duration_ns;
			bool detector_triggered = false;
			if (policy_.has_threshold()) {
				const auto &threshold = policy_.threshold();
				const uint64_t delta_tx = point.tx_packets - previous_->tx_packets;
				const uint64_t delta_drop = point.dropped_packets - previous_->dropped_packets;
				const uint64_t population = saturating_add(delta_tx, delta_drop);
				detector_triggered = population >= threshold.min_packets_per_window() &&
						     sample.drop_ratio > threshold.max_drop_ratio() &&
						     sample.throughput_ratio < threshold.min_tx_ratio();
			} else if (correlator_ != nullptr) {
				detector_triggered = sample.is_degraded &&
						     correlation_sample_count >= correlator_->min_samples();
			}
			history_->record(sample);
			if (detector_triggered) {
				const auto current_window = history_->get_for_config(current_identity_->snapshot_id());
				const auto attribution = scorer_->compute(sample, frozen_baseline_, current_window);
				kinetum::control::v1::GuardrailsAttribution proof;
				*proof.mutable_candidate() = identity_from_(point);
				proof.set_rollback_snapshot_id(rollback_snapshot_id_);
				for (const auto &row : previous_->workers) {
					*proof.add_previous_workers() = row;
				}
				for (const auto &row : point.workers) {
					*proof.add_current_workers() = row;
				}
				proof.set_baseline_tx_pps(baseline_tx_pps_);
				if (attribution.evidence_complete) {
					proof.set_confidence(attribution.confidence);
				}
				proof.set_recommendation(recommendation(attribution.recommended_action));
				proof.set_evidence_complete(attribution.evidence_complete);
				last_attribution_ = std::move(proof);
				if (attribution.evidence_complete &&
				    attribution.recommended_action == attribution_result::action::AUTO_ROLLBACK) {
					if (rollback_snapshot_id_.empty() ||
					    rollback_snapshot_id_ == point.snapshot_id) {
						return status::data_loss(
							"guardrails attribution lost its distinct rollback content");
					}
					rollback_intent_request request;
					request.target_snapshot_id = rollback_snapshot_id_;
					request.guarded_snapshot_id = point.snapshot_id;
					request.guarded_epoch = point.epoch;
					request.guarded_revision = observation.active_authority.revision;
					request.guarded_validation_hash =
						observation.active_authority.active_validation_hash;
					request.policy_generation = policy_generation_;
					request.runtime_generation = point.runtime_generation;
					request.cause = policy_.has_threshold() ?
								rollback_intent_cause::THRESHOLD_DEGRADATION :
								rollback_intent_cause::CORRELATED_DEGRADATION;
					request.observed_monotonic_ns = telemetry.runtime().collection_monotonic_ns();
					decision = std::move(request);
				}
			}
			const uint64_t window_ns = policy_.evaluation_window_ms() * 1'000'000u;
			if (!decision.has_value() && evaluation_elapsed_ns_ >= window_ns) {
				complete_evaluation_(
					point, kinetum::control::v1::GUARDRAILS_EVALUATION_OUTCOME_WINDOW_COMPLETE);
				reset_evidence_(guardrails_evaluator_state::BASELINE_BUILDING);
				seed_current_(point);
				return std::optional<rollback_intent_request>{};
			}
		}

		previous_ = point;
		interval_contiguous_ = true;
		return decision;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("guardrails evaluation exhausted bounded host memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "guardrails evaluation exceeded host size limits");
	}
}

}  // namespace kinetum::cp
