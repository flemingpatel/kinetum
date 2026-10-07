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

}  // namespace

void guardrails_evaluator::reset_evidence_(guardrails_evaluator_state state) noexcept
{
	state_ = state;
	previous_.reset();
	std::vector<telemetry_snapshot>{}.swap(frozen_baseline_);
	current_snapshot_id_.clear();
	current_epoch_ = 0u;
	rollback_snapshot_id_.clear();
	runtime_generation_ = 0u;
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
	current_snapshot_id_ = point.snapshot_id;
	current_epoch_ = point.epoch;
	runtime_generation_ = point.runtime_generation;
	previous_ = point;
	interval_contiguous_ = true;
	if (correlator_ != nullptr) {
		correlator_->on_config_change(point.snapshot_id);
	}
}

status guardrails_evaluator::apply_policy(const kinetum::control::v1::GuardrailsPolicy &policy, uint64_t generation)
{
	if (generation == 0u || generation == std::numeric_limits<uint64_t>::max()) {
		return status::invalid_argument("guardrails policy generation is invalid");
	}
	const auto validation = validate_guardrails_policy(policy);
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

void guardrails_evaluator::mark_rollback_pending() noexcept
{
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
		.collection_ns = telemetry.runtime().collection_monotonic_ns(),
		.rx_packets = telemetry.engine().rx_packets(),
		.tx_packets = telemetry.engine().tx_packets(),
		.dropped_packets = telemetry.engine().dropped_packets(),
	};
}

status_or<telemetry_snapshot> guardrails_evaluator::interval_sample_(const cumulative_point &previous,
								     const cumulative_point &point,
								     const guardrails_runtime_observation &current,
								     double baseline_tx_pps)
{
	if (previous.snapshot_id != point.snapshot_id || previous.epoch != point.epoch ||
	    previous.runtime_generation != point.runtime_generation) {
		return status::failed_precondition("telemetry interval crossed an identity boundary");
	}
	if (point.collection_ns <= previous.collection_ns || point.rx_packets < previous.rx_packets ||
	    point.tx_packets < previous.tx_packets || point.dropped_packets < previous.dropped_packets) {
		return status::data_loss("same-generation telemetry time or counters regressed");
	}
	const uint64_t delta_tx = point.tx_packets - previous.tx_packets;
	const uint64_t delta_dropped = point.dropped_packets - previous.dropped_packets;
	const long double elapsed_seconds =
		static_cast<long double>(point.collection_ns - previous.collection_ns) / 1'000'000'000.0L;
	const double tx_pps = static_cast<double>(static_cast<long double>(delta_tx) / elapsed_seconds);
	const double drop_pps = static_cast<double>(static_cast<long double>(delta_dropped) / elapsed_seconds);
	const long double total = static_cast<long double>(delta_tx) + static_cast<long double>(delta_dropped);
	const double drop_ratio = total == 0.0L ? 0.0 :
						  static_cast<double>(static_cast<long double>(delta_dropped) / total);

	telemetry_snapshot sample;
	sample.config_snapshot_id = point.snapshot_id;
	sample.epoch = point.epoch;
	sample.runtime_generation = point.runtime_generation;
	sample.timestamp_ms = static_cast<uint64_t>(std::max<int64_t>(0, kinetum::common::unix_time_ms()));
	sample.timestamp_mono_ns = point.collection_ns;
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
	return sample;
}

status_or<std::optional<rollback_intent_request>>
guardrails_evaluator::observe(const guardrails_runtime_observation &observation)
{
	try {
		if (!enabled() || state_ == guardrails_evaluator_state::ROLLBACK_PENDING) {
			return std::optional<rollback_intent_request>{};
		}
		if (!observation.stats.has_telemetry() || !observation.stats.telemetry().has_runtime() ||
		    !observation.stats.telemetry().has_engine() || !observation.stats.telemetry().has_transition()) {
			return status::data_loss("guardrails evaluator received incomplete fenced telemetry");
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
		if (requires_module_health() && !complete_current_module_health(observation)) {
			pause_observation();
			return std::optional<rollback_intent_request>{};
		}

		const auto point = point_from_(observation);
		if (runtime_generation_ != 0u && runtime_generation_ != point.runtime_generation) {
			reset_evidence_(guardrails_evaluator_state::BASELINE_BUILDING);
		}
		if (current_snapshot_id_.empty()) {
			seed_current_(point);
			return std::optional<rollback_intent_request>{};
		}
		if (previous_.has_value() &&
		    (point.collection_ns <= previous_->collection_ns || point.rx_packets < previous_->rx_packets ||
		     point.tx_packets < previous_->tx_packets || point.dropped_packets < previous_->dropped_packets)) {
			pause_observation();
			return std::optional<rollback_intent_request>{};
		}

		const bool identity_changed = point.snapshot_id != current_snapshot_id_ ||
					      point.epoch != current_epoch_;
		if (identity_changed) {
			const bool content_changed = point.snapshot_id != current_snapshot_id_;
			if (state_ == guardrails_evaluator_state::ARMED && content_changed) {
				std::string rollback_snapshot_id = current_snapshot_id_;
				auto frozen_baseline = history_->take_for_config(current_snapshot_id_);
				frozen_baseline_ = std::move(frozen_baseline);
				rollback_snapshot_id_ = std::move(rollback_snapshot_id);
				evaluation_elapsed_ns_ = 0u;
				state_ = guardrails_evaluator_state::EVALUATING;
				seed_current_(point);
			} else {
				reset_evidence_(guardrails_evaluator_state::BASELINE_BUILDING);
				seed_current_(point);
			}
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
			return std::optional<rollback_intent_request>{};
		}
		auto sample = std::move(sample_or).value();
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
			}
		} else if (state_ == guardrails_evaluator_state::EVALUATING) {
			const uint64_t interval_ns = point.collection_ns - previous_->collection_ns;
			evaluation_elapsed_ns_ = saturating_add(evaluation_elapsed_ns_, interval_ns);
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
				const auto current_window = history_->get_for_config(current_snapshot_id_);
				const auto attribution = scorer_->compute(sample, frozen_baseline_, current_window);
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
					request.observed_monotonic_ns = point.collection_ns;
					decision = std::move(request);
				}
			}
			const uint64_t window_ns = policy_.evaluation_window_ms() * 1'000'000u;
			if (!decision.has_value() && evaluation_elapsed_ns_ >= window_ns) {
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
