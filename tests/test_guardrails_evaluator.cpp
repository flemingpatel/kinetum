// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_guardrails_evaluator.cpp
 * @brief Deterministic guardrails evidence-window state-product tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <utility>

#include <kinetum/kinetum_sdk.h>

#include "src/cp/guardrails_evaluator.hpp"

namespace kinetum::cp
{
namespace
{

/**
 * @brief Build one explicit threshold policy.
 * @param window_ms Valid-observation evaluation window.
 * @param baseline_samples Stable samples required before arming.
 * @param trigger Whether interval degradation should trigger the detector.
 * @return Complete admitted policy.
 */
kinetum::control::v1::GuardrailsPolicy make_threshold_policy(uint64_t window_ms, uint32_t baseline_samples,
							     bool trigger)
{
	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(true);
	policy.set_poll_interval_ms(10u);
	policy.set_evaluation_window_ms(window_ms);
	policy.set_telemetry_history_capacity(16u);
	policy.mutable_threshold()->set_max_drop_ratio(trigger ? 0.10 : 1.0);
	policy.mutable_threshold()->set_min_tx_ratio(trigger ? 0.50 : 0.0);
	policy.mutable_threshold()->set_min_packets_per_window(trigger ? 1u : 0u);
	policy.mutable_attribution()->set_auto_rollback_threshold(0.80);
	policy.mutable_attribution()->set_defer_threshold(0.50);
	policy.mutable_attribution()->set_baseline_samples(baseline_samples);
	policy.mutable_attribution()->set_degradation_threshold(0.30);
	return policy;
}

/**
 * @brief Build a correlation policy whose CONFIG_ISSUE boost alone needs health rows.
 * @return Complete explicit correlation policy.
 */
kinetum::control::v1::GuardrailsPolicy make_config_issue_policy()
{
	auto policy = make_threshold_policy(100u, 1u, false);
	policy.clear_threshold();
	auto *correlation = policy.mutable_correlation();
	correlation->set_drop_ratio_weight(0.40);
	correlation->set_throughput_ratio_weight(0.40);
	correlation->set_module_health_weight(0.0);
	correlation->set_config_issue_boost(0.20);
	correlation->set_ewma_alpha(0.5);
	correlation->set_degradation_threshold(0.5);
	correlation->set_hysteresis_band(0.1);
	correlation->set_min_samples(1u);
	correlation->set_normalization_max_drop_ratio(0.10);
	correlation->set_normalization_min_tx_ratio(0.50);
	return policy;
}

/**
 * @brief Build one intrinsically shaped evaluator observation.
 * @param snapshot_id Durable content identity.
 * @param revision Durable content revision.
 * @param epoch Last globally COMPLETE epoch.
 * @param collection_ns Monotonic collection time.
 * @param tx Cumulative accepted TX count.
 * @param dropped Cumulative terminal drop count.
 * @param runtime_generation Exact cumulative-counter namespace.
 * @return Exact evaluator input with no optional rows.
 */
guardrails_runtime_observation make_observation(std::string snapshot_id, int64_t revision, uint64_t epoch,
						uint64_t collection_ns, uint64_t tx, uint64_t dropped,
						uint64_t runtime_generation = 1u)
{
	guardrails_runtime_observation observation;
	observation.active_authority.snapshot_id = std::move(snapshot_id);
	observation.active_authority.revision = revision;
	observation.active_authority.active_epoch = epoch;
	observation.active_authority.active_validation_hash.fill(static_cast<uint8_t>(epoch));
	auto *runtime = observation.stats.mutable_telemetry()->mutable_runtime();
	runtime->set_runtime_generation(runtime_generation);
	runtime->set_active_epoch(epoch);
	runtime->set_collection_monotonic_ns(collection_ns);
	auto *engine = observation.stats.mutable_telemetry()->mutable_engine();
	engine->set_rx_packets(tx + dropped);
	engine->set_tx_packets(tx);
	engine->set_dropped_packets(dropped);
	auto *transition = observation.stats.mutable_telemetry()->mutable_transition();
	transition->set_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE);
	transition->set_active_epoch(epoch);
	return observation;
}

/**
 * @brief Attach one complete current module-health observation.
 * @param observation Evaluator input to extend.
 * @param epoch Exact active epoch.
 * @param score Bounded module score.
 * @param flags Exact SDK health flags.
 */
void add_current_health(guardrails_runtime_observation &observation, uint64_t epoch, uint32_t score, uint32_t flags)
{
	observation.stats.mutable_telemetry()->mutable_transition()->set_module_context_count(1u);
	auto *health = observation.stats.mutable_telemetry()->add_module_health();
	health->set_module_id("kinetum.test");
	health->set_context_instance_id("active@lane_0");
	health->set_state(kinetum::telemetry::v1::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE);
	health->set_observation_epoch(epoch);
	health->set_health_score(score);
	health->set_health_flags(flags);
}

/**
 * @brief Feed one observation and require no rollback decision.
 * @param evaluator Sole deterministic evaluator under test.
 * @param observation Complete candidate observation.
 */
void observe_without_decision(guardrails_evaluator &evaluator, const guardrails_runtime_observation &observation)
{
	auto decision_or = evaluator.observe(observation);
	ASSERT_TRUE(decision_or.is_ok()) << decision_or.error().message();
	EXPECT_FALSE(decision_or->has_value());
}

/** @brief Missing or protocol-faulted time never consumes the evaluation window. */
TEST(guardrails_evaluator, missing_evidence_breaks_interval_without_advancing_window)
{
	guardrails_evaluator evaluator;
	ASSERT_TRUE(evaluator.apply_policy(make_threshold_policy(30u, 2u, false), 1u).is_ok());
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u));
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u));
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 30'000'000u, 3'000u, 0u));
	ASSERT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 40'000'000u, 4'000u, 0u));
	ASSERT_EQ(evaluator.state(), guardrails_evaluator_state::EVALUATING);

	auto faulted = make_observation("candidate", 2, 2u, 1'000'000'000u, 5'000u, 0u);
	faulted.protocol_faulted = true;
	observe_without_decision(evaluator, faulted);
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::EVALUATING);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 1'010'000'000u, 6'000u, 0u));
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 1'020'000'000u, 7'000u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::EVALUATING);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 1'030'000'000u, 8'000u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::EVALUATING);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 1'040'000'000u, 9'000u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::BASELINE_BUILDING);
}

/** @brief CONFIG_ISSUE boost requires complete health even when health weight is zero. */
TEST(guardrails_evaluator, config_issue_boost_never_interprets_missing_health_as_zero)
{
	guardrails_evaluator evaluator;
	ASSERT_TRUE(evaluator.apply_policy(make_config_issue_policy(), 1u).is_ok());
	ASSERT_TRUE(evaluator.requires_module_health());
	auto missing = make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u);
	missing.stats.mutable_telemetry()->mutable_transition()->set_module_context_count(0u);
	observe_without_decision(evaluator, missing);

	auto first = make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u);
	first.stats.mutable_telemetry()->mutable_transition()->set_module_context_count(1u);
	auto *first_health = first.stats.mutable_telemetry()->add_module_health();
	first_health->set_state(kinetum::telemetry::v1::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE);
	first_health->set_observation_epoch(1u);
	first_health->set_health_score(100u);
	first_health->set_health_flags(0u);
	observe_without_decision(evaluator, first);
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::BASELINE_BUILDING);

	auto second = make_observation("baseline", 1, 1u, 30'000'000u, 3'000u, 0u);
	second.stats.mutable_telemetry()->mutable_transition()->set_module_context_count(1u);
	auto *second_health = second.stats.mutable_telemetry()->add_module_health();
	second_health->set_state(kinetum::telemetry::v1::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE);
	second_health->set_observation_epoch(1u);
	second_health->set_health_score(100u);
	second_health->set_health_flags(0u);
	observe_without_decision(evaluator, second);
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
}

/** @brief Correlation consumes the evaluator's one exact interval and emits typed intent. */
TEST(guardrails_evaluator, correlation_uses_shared_delta_and_complete_health_attribution)
{
	guardrails_evaluator evaluator;
	ASSERT_TRUE(evaluator.apply_policy(make_config_issue_policy(), 3u).is_ok());
	auto baseline_seed = make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u);
	add_current_health(baseline_seed, 1u, 100u, 0u);
	observe_without_decision(evaluator, baseline_seed);
	auto baseline_sample = make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u);
	add_current_health(baseline_sample, 1u, 100u, 0u);
	observe_without_decision(evaluator, baseline_sample);
	ASSERT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);

	auto candidate_seed = make_observation("candidate", 2, 2u, 30'000'000u, 2'100u, 0u);
	add_current_health(candidate_seed, 2u, 100u, 0u);
	observe_without_decision(evaluator, candidate_seed);
	auto degraded = make_observation("candidate", 2, 2u, 40'000'000u, 2'101u, 999u);
	add_current_health(degraded, 2u, 20u, KINETUM_HEALTH_F_CONFIG_ISSUE);
	auto decision_or = evaluator.observe(degraded);
	ASSERT_TRUE(decision_or.is_ok()) << decision_or.error().message();
	ASSERT_TRUE(decision_or->has_value());
	EXPECT_EQ(decision_or->value().target_snapshot_id, "baseline");
	EXPECT_EQ(decision_or->value().guarded_snapshot_id, "candidate");
	EXPECT_EQ(decision_or->value().cause, rollback_intent_cause::CORRELATED_DEGRADATION);

	// Baseline and candidate attribution must use the same correlated-health
	// formula. Identical module degradation on both sides can trip the detector,
	// but it is not evidence that the configuration change caused the condition.
	auto consistent_policy = make_config_issue_policy();
	auto *correlation = consistent_policy.mutable_correlation();
	correlation->set_drop_ratio_weight(0.20);
	correlation->set_throughput_ratio_weight(0.20);
	correlation->set_module_health_weight(0.60);
	correlation->set_config_issue_boost(0.0);
	correlation->set_ewma_alpha(1.0);
	correlation->set_degradation_threshold(0.30);
	correlation->set_hysteresis_band(0.0);
	consistent_policy.mutable_attribution()->set_auto_rollback_threshold(0.45);
	consistent_policy.mutable_attribution()->set_defer_threshold(0.40);
	consistent_policy.mutable_attribution()->set_baseline_samples(1u);

	guardrails_evaluator consistent;
	ASSERT_TRUE(consistent.apply_policy(consistent_policy, 4u).is_ok());
	auto stable_seed = make_observation("stable", 1, 1u, 10'000'000u, 1'000u, 0u);
	add_current_health(stable_seed, 1u, 40u, 0u);
	observe_without_decision(consistent, stable_seed);
	auto stable_sample = make_observation("stable", 1, 1u, 20'000'000u, 2'000u, 0u);
	add_current_health(stable_sample, 1u, 40u, 0u);
	observe_without_decision(consistent, stable_sample);
	ASSERT_EQ(consistent.state(), guardrails_evaluator_state::ARMED);
	auto unchanged_seed = make_observation("unchanged-health", 2, 2u, 30'000'000u, 3'000u, 0u);
	add_current_health(unchanged_seed, 2u, 40u, 0u);
	observe_without_decision(consistent, unchanged_seed);
	auto unchanged_sample = make_observation("unchanged-health", 2, 2u, 40'000'000u, 4'000u, 0u);
	add_current_health(unchanged_sample, 2u, 40u, 0u);
	observe_without_decision(consistent, unchanged_sample);
	EXPECT_EQ(consistent.state(), guardrails_evaluator_state::EVALUATING);
}

/** @brief A complete degraded window emits one fully bound desired rollback. */
TEST(guardrails_evaluator, threshold_and_attribution_emit_exact_intent_without_key_or_unix_time)
{
	guardrails_evaluator evaluator;
	ASSERT_TRUE(evaluator.apply_policy(make_threshold_policy(100u, 1u, true), 7u).is_ok());
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u));
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u));
	ASSERT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 30'000'000u, 2'100u, 0u));
	ASSERT_EQ(evaluator.state(), guardrails_evaluator_state::EVALUATING);
	auto decision_or = evaluator.observe(make_observation("candidate", 2, 2u, 40'000'000u, 2'101u, 999u));
	ASSERT_TRUE(decision_or.is_ok()) << decision_or.error().message();
	ASSERT_TRUE(decision_or->has_value());
	const auto &request = decision_or->value();
	EXPECT_EQ(request.target_snapshot_id, "baseline");
	EXPECT_EQ(request.guarded_snapshot_id, "candidate");
	EXPECT_EQ(request.guarded_epoch, 2u);
	EXPECT_EQ(request.guarded_revision, 2);
	EXPECT_EQ(request.policy_generation, 7u);
	EXPECT_EQ(request.runtime_generation, 1u);
	EXPECT_EQ(request.cause, rollback_intent_cause::THRESHOLD_DEGRADATION);
	EXPECT_TRUE(request.idempotency_key.empty());
	EXPECT_EQ(request.created_unix_ms, 0);
	evaluator.mark_rollback_pending();
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::ROLLBACK_PENDING);
	evaluator.resume_after_intent();
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::BASELINE_BUILDING);
}

/** @brief Exact WAITING_ACK age binds one transition-scoped safety intent. */
TEST(guardrails_evaluator, boundary_timeout_binds_exact_transition_generation)
{
	guardrails_evaluator evaluator;
	auto policy = make_threshold_policy(100u, 1u, false);
	policy.mutable_boundary()->set_ack_timeout_ms(1u);
	ASSERT_TRUE(evaluator.apply_policy(policy, 9u).is_ok());
	auto observation = make_observation("active", 1, 1u, 10'000'000u, 1'000u, 0u);
	auto *transition_telemetry = observation.stats.mutable_telemetry()->mutable_transition();
	transition_telemetry->set_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMMITTING);
	auto *active = transition_telemetry->mutable_active_transaction();
	active->set_mutation_sequence(2u);
	auto *boundary = observation.stats.mutable_telemetry()->add_boundaries();
	boundary->set_sender_phase(kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_WAITING_ACK);
	boundary->set_transition_generation(2u);
	boundary->set_cut_published_monotonic_ns(1'000'000u);
	durable_runtime_transition_view transition;
	transition.identity.mutation_sequence = 2u;
	transition.identity.target_epoch = 2u;
	transition.identity.validation_hash.fill(UINT8_C(0x22));
	transition.identity.idempotency_key_digest.fill(UINT8_C(0x33));
	transition.phase = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING;
	transition.snapshot_id = "candidate";
	transition.revision = 2;
	observation.transition = transition;
	auto same_content = observation;
	same_content.transition->snapshot_id = "active";
	observe_without_decision(evaluator, same_content);

	auto decision_or = evaluator.observe(observation);
	ASSERT_TRUE(decision_or.is_ok()) << decision_or.error().message();
	ASSERT_TRUE(decision_or->has_value());
	EXPECT_EQ(decision_or->value().target_snapshot_id, "active");
	EXPECT_EQ(decision_or->value().guarded_snapshot_id, "candidate");
	EXPECT_EQ(decision_or->value().wait_for_mutation_sequence, 2u);
	EXPECT_EQ(decision_or->value().policy_generation, 9u);
	EXPECT_EQ(decision_or->value().cause, rollback_intent_cause::BOUNDARY_ACK_TIMEOUT);
}

/** @brief Same-generation counter regression never becomes a replacement baseline. */
TEST(guardrails_evaluator, regressing_counter_pauses_until_a_fresh_monotonic_interval)
{
	guardrails_evaluator evaluator;
	ASSERT_TRUE(evaluator.apply_policy(make_threshold_policy(30u, 1u, false), 1u).is_ok());
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u));
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u));
	ASSERT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 30'000'000u, 1'500u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED)
		<< "content change cannot hide a same-runtime cumulative regression";
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 40'000'000u, 3'000u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::EVALUATING);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 50'000'000u, 2'500u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::EVALUATING);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 60'000'000u, 3'100u, 0u));
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 70'000'000u, 4'100u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::EVALUATING);
}

/** @brief Runtime replacement resets baseline and never fabricates a cross-generation delta. */
TEST(guardrails_evaluator, runtime_generation_replacement_rebuilds_baseline_without_delta)
{
	guardrails_evaluator evaluator;
	ASSERT_TRUE(evaluator.apply_policy(make_threshold_policy(30u, 1u, false), 1u).is_ok());
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u));
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u));
	ASSERT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);

	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 30'000'000u, 10u, 0u, 2u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::BASELINE_BUILDING);
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 40'000'000u, 1'010u, 0u, 2u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
}

}  // namespace
}  // namespace kinetum::cp
