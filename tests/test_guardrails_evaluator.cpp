// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_guardrails_evaluator.cpp
 * @brief Deterministic guardrails evidence-window state-product tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>

#include <kinetum/kinetum_sdk.h>

#include "src/cp/guardrails_evaluator.hpp"
#include "src/common/guardrails_evaluation_contract.hpp"

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
	observation.active_authority.allocated_epoch_high_watermark = epoch;
	observation.active_authority.mutation_sequence_high_watermark = epoch;
	observation.active_authority.plan_content_hash.fill(UINT8_C(0x11));
	observation.active_authority.active_validation_hash.fill(static_cast<uint8_t>(epoch));
	observation.stats.mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
	auto *runtime = observation.stats.mutable_telemetry()->mutable_runtime();
	runtime->set_runtime_generation(runtime_generation);
	runtime->set_status_publication_generation(1u);
	runtime->set_active_epoch(epoch);
	runtime->set_minimum_retained_epoch(epoch);
	runtime->set_last_activated_epoch(epoch);
	runtime->set_active_workers(1u);
	runtime->set_collection_monotonic_ns(collection_ns);
	runtime->set_expected_workers(1u);
	runtime->set_latest_bank_publication_monotonic_ns(collection_ns);
	auto *engine = observation.stats.mutable_telemetry()->mutable_engine();
	engine->set_rx_packets(tx + dropped);
	engine->set_tx_packets(tx);
	engine->set_dropped_packets(dropped);
	engine->set_rx_bytes(engine->rx_packets());
	engine->set_tx_bytes(tx);
	auto *worker = observation.stats.mutable_telemetry()->add_worker_counters();
	worker->set_worker_index(0u);
	worker->set_observation_epoch(epoch);
	worker->set_publication_generation(collection_ns);
	worker->set_published_monotonic_ns(collection_ns);
	*worker->mutable_counters() = *engine;
	auto *transition = observation.stats.mutable_telemetry()->mutable_transition();
	transition->set_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE);
	transition->set_active_epoch(epoch);
	transition->set_publication_generation(1u);
	transition->set_allocated_epoch_high_watermark(epoch);
	transition->set_mutation_sequence_high_watermark(epoch);
	transition->set_plan_content_hash(std::string(32u, '\x11'));
	transition->set_active_validation_hash(std::string(32u, static_cast<char>(epoch)));
	transition->set_execution_participant_count(1u);
	transition->set_region_count(1u);
	transition->set_source_participant_count(1u);
	transition->set_sink_participant_count(1u);
	transition->set_quiescence_reader_count(1u);
	for (int code = 1; code <= 13; ++code) {
		auto *fault = observation.stats.mutable_telemetry()->mutable_protocol_faults()->add_counters();
		fault->set_code(static_cast<kinetum::telemetry::v1::EpochProtocolFaultCode>(code));
	}
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
	health->set_publication_generation(observation.stats.telemetry().runtime().collection_monotonic_ns());
	health->set_observed_at_ns(observation.stats.telemetry().runtime().collection_monotonic_ns());
	health->set_callback_duration_ns(0u);
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

/**
 * @brief Author distinct RX, processing-only drop, and TX measurement owners.
 * @param snapshot Exact active content.
 * @param epoch Active epoch shared by these source publications.
 * @param times Independent measurement times for RX, processing, and TX.
 * @param tx Cumulative accepted TX packets.
 * @param dropped Cumulative terminal drops owned by the processing worker.
 * @return One complete compact three-worker observation.
 */
guardrails_runtime_observation make_worker_observation(const std::string &snapshot, uint64_t epoch,
						       std::array<uint64_t, 3> times, uint64_t tx, uint64_t dropped)
{
	auto observation = make_observation(snapshot, static_cast<int64_t>(epoch), epoch,
					    *std::max_element(times.begin(), times.end()) + 1u, tx, dropped);
	auto *telemetry = observation.stats.mutable_telemetry();
	telemetry->mutable_runtime()->set_expected_workers(3u);
	telemetry->mutable_runtime()->set_active_workers(3u);
	telemetry->mutable_transition()->set_execution_participant_count(3u);
	telemetry->mutable_transition()->set_quiescence_reader_count(3u);
	telemetry->clear_worker_counters();
	for (uint32_t index = 0u; index < times.size(); ++index) {
		auto *row = telemetry->add_worker_counters();
		row->set_worker_index(index);
		row->set_observation_epoch(epoch);
		row->set_publication_generation(times[index]);
		row->set_published_monotonic_ns(times[index]);
		auto *counts = row->mutable_counters();
		if (index == 0u) {
			counts->set_rx_packets(telemetry->engine().rx_packets());
			counts->set_rx_bytes(telemetry->engine().rx_bytes());
		} else if (index == 1u) {
			counts->set_dropped_packets(dropped);
		} else {
			counts->set_tx_packets(tx);
			counts->set_tx_bytes(tx);
		}
	}
	return observation;
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
	add_current_health(first, 1u, 100u, 0u);
	observe_without_decision(evaluator, first);
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::BASELINE_BUILDING);

	auto second = make_observation("baseline", 1, 1u, 30'000'000u, 3'000u, 0u);
	add_current_health(second, 1u, 100u, 0u);
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
	evaluator.mark_rollback_pending(true);
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
	auto regressing_change = evaluator.observe(make_observation("candidate", 2, 2u, 30'000'000u, 1'500u, 0u));
	ASSERT_FALSE(regressing_change.is_ok());
	EXPECT_EQ(regressing_change.error().code(), kinetum::common::status_code::DATA_LOSS);
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED)
		<< "content change cannot hide a same-runtime cumulative regression";
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 40'000'000u, 3'000u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::EVALUATING);
	auto regressing_interval = evaluator.observe(make_observation("candidate", 2, 2u, 50'000'000u, 2'500u, 0u));
	ASSERT_FALSE(regressing_interval.is_ok());
	EXPECT_EQ(regressing_interval.error().code(), kinetum::common::status_code::DATA_LOSS);
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

/** @brief Extra retrievals of the same source point never build a baseline or change arming. */
TEST(guardrails_evaluator, duplicate_retrieval_times_do_not_create_measurements)
{
	guardrails_evaluator evaluator;
	ASSERT_TRUE(evaluator.apply_policy(make_threshold_policy(100u, 2u, false), 1u).is_ok());
	auto point = make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u);
	observe_without_decision(evaluator, point);
	for (uint64_t read = 1u; read <= 100u; ++read) {
		point.stats.mutable_telemetry()->mutable_runtime()->set_collection_monotonic_ns(10'000'000u + read);
		observe_without_decision(evaluator, point);
	}
	EXPECT_EQ(evaluator.evaluation().baseline_intervals(), 0u);
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u));
	EXPECT_EQ(evaluator.evaluation().baseline_intervals(), 1u);
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::BASELINE_BUILDING);
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 30'000'000u, 3'000u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
}

/** @brief A processing-only owner participates in freshness and invalidity wins at every row position. */
TEST(guardrails_evaluator, all_worker_progress_and_order_independent_mutation_rejection)
{
	guardrails_evaluator evaluator;
	ASSERT_TRUE(evaluator.apply_policy(make_threshold_policy(100u, 1u, false), 1u).is_ok());
	auto seed = make_worker_observation("baseline", 1u, {10u, 10u, 10u}, 1'000u, 0u);
	observe_without_decision(evaluator, seed);
	auto partial = make_worker_observation("baseline", 1u, {20u, 10u, 20u}, 2'000u, 0u);
	observe_without_decision(evaluator, partial);
	EXPECT_EQ(evaluator.evaluation().baseline_intervals(), 0u);
	for (int worker = 0; worker < 3; ++worker) {
		auto invalid = partial;
		invalid.stats.mutable_telemetry()
			->mutable_worker_counters(worker)
			->mutable_counters()
			->set_fanout_overflow(1u);
		invalid.stats.mutable_telemetry()->mutable_engine()->set_fanout_overflow(1u);
		auto rejected = evaluator.observe(invalid);
		ASSERT_FALSE(rejected.is_ok());
		EXPECT_EQ(rejected.error().code(), kinetum::common::status_code::DATA_LOSS);
	}
	// Contradictory evidence broke the interval; the next exact vector seeds it.
	auto current = make_worker_observation("baseline", 1u, {20u, 20u, 20u}, 2'000u, 0u);
	observe_without_decision(evaluator, current);
	EXPECT_EQ(evaluator.evaluation().baseline_intervals(), 0u);
	observe_without_decision(evaluator, make_worker_observation("baseline", 1u, {30u, 30u, 30u}, 3'000u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
}

/** @brief A new content binding remains observable while its worker measurements are still old. */
TEST(guardrails_evaluator, evaluation_binding_does_not_relabel_lagging_worker_measurements)
{
	guardrails_evaluator evaluator;
	const auto policy = make_threshold_policy(100u, 1u, false);
	ASSERT_TRUE(evaluator.apply_policy(policy, 1u).is_ok());
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u));
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u));
	auto candidate = make_observation("candidate", 2, 2u, 30'000'000u, 3'000u, 0u);
	candidate.stats.mutable_telemetry()->mutable_worker_counters(0)->set_observation_epoch(1u);
	observe_without_decision(evaluator, candidate);
	auto evaluated = evaluator.evaluation();
	EXPECT_EQ(evaluated.state(), kinetum::control::v1::GUARDRAILS_EVALUATION_STATE_EVALUATING);
	ASSERT_TRUE(evaluated.has_observed_identity());
	EXPECT_EQ(evaluated.observed_identity().epoch(), 2u);
	EXPECT_EQ(evaluated.valid_observation_ns(), 0u);
	EXPECT_TRUE(kinetum::common::validate_guardrails_evaluation(evaluated, &policy, 1u).is_ok());
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 40'000'000u, 4'000u, 0u));
	EXPECT_EQ(evaluator.evaluation().valid_observation_ns(), 0u);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 50'000'000u, 5'000u, 0u));
	EXPECT_EQ(evaluator.evaluation().valid_observation_ns(), 10'000'000u);
}

/** @brief Missing current health pauses measurement without corrupting the new content's status projection. */
TEST(guardrails_evaluator, health_gap_preserves_a_complete_evaluation_binding)
{
	guardrails_evaluator evaluator;
	const auto policy = make_config_issue_policy();
	ASSERT_TRUE(evaluator.apply_policy(policy, 1u).is_ok());
	auto seed = make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u);
	add_current_health(seed, 1u, 100u, 0u);
	observe_without_decision(evaluator, seed);
	auto baseline = make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u);
	add_current_health(baseline, 1u, 100u, 0u);
	observe_without_decision(evaluator, baseline);
	auto candidate = make_observation("candidate", 2, 2u, 30'000'000u, 3'000u, 0u);
	add_current_health(candidate, 1u, 100u, 0u);
	auto *stale = candidate.stats.mutable_telemetry()->mutable_module_health(0);
	stale->set_state(kinetum::telemetry::v1::MODULE_HEALTH_STATE_STALE_EPOCH);
	stale->set_publication_generation(20'000'000u);
	stale->set_observed_at_ns(20'000'000u);
	stale->clear_health_score();
	stale->clear_health_flags();
	stale->clear_reason();
	observe_without_decision(evaluator, candidate);
	const auto waiting = evaluator.evaluation();
	EXPECT_EQ(waiting.state(), kinetum::control::v1::GUARDRAILS_EVALUATION_STATE_EVALUATING);
	ASSERT_TRUE(waiting.has_observed_identity());
	EXPECT_EQ(waiting.observed_identity().epoch(), 2u);
	EXPECT_EQ(waiting.valid_observation_ns(), 0u);
	EXPECT_TRUE(kinetum::common::validate_guardrails_evaluation(waiting, &policy, 1u).is_ok());
	for (uint64_t time = 40'000'000u; time <= 50'000'000u; time += 10'000'000u) {
		auto current = make_observation("candidate", 2, 2u, time, time / 10'000u, 0u);
		add_current_health(current, 2u, 100u, 0u);
		observe_without_decision(evaluator, current);
	}
	EXPECT_EQ(evaluator.evaluation().valid_observation_ns(), 10'000'000u);
}

/** @brief Policy replacement cannot erase a same-runtime cumulative regression. */
TEST(guardrails_evaluator, policy_replacement_retains_worker_regression_cursor)
{
	guardrails_evaluator evaluator;
	auto policy = make_threshold_policy(100u, 1u, false);
	ASSERT_TRUE(evaluator.apply_policy(policy, 1u).is_ok());
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u));
	ASSERT_TRUE(evaluator.apply_policy(policy, 2u).is_ok());
	auto rejected = evaluator.observe(make_observation("candidate", 2, 2u, 20'000'000u, 500u, 0u));
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), kinetum::common::status_code::DATA_LOSS);
	observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 20'000'000u, 10u, 0u, 2u));
	EXPECT_EQ(evaluator.evaluation().baseline_intervals(), 0u);
}

/** @brief Owner-specific elapsed times determine rates while only their intersection advances the window. */
TEST(guardrails_evaluator, skewed_worker_measurements_preserve_rates_and_common_coverage)
{
	guardrails_evaluator evaluator;
	auto policy = make_threshold_policy(100u, 1u, true);
	ASSERT_TRUE(evaluator.apply_policy(policy, 1u).is_ok());
	observe_without_decision(evaluator,
				 make_worker_observation("baseline", 1u, {10'000'000u, 10'000'000u, 10'000'000u},
							 1'000u, 0u));
	observe_without_decision(evaluator,
				 make_worker_observation("baseline", 1u, {20'000'000u, 25'000'000u, 30'000'000u},
							 3'000u, 0u));
	ASSERT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
	observe_without_decision(evaluator,
				 make_worker_observation("candidate", 2u, {40'000'000u, 45'000'000u, 50'000'000u},
							 3'100u, 0u));
	auto decision = evaluator.observe(
		make_worker_observation("candidate", 2u, {60'000'000u, 65'000'000u, 80'000'000u}, 3'101u, 2'000u));
	ASSERT_TRUE(decision.is_ok()) << decision.error().message();
	ASSERT_TRUE(decision->has_value());
	auto evaluated = evaluator.evaluation();
	EXPECT_EQ(evaluated.valid_observation_ns(), 10'000'000u);
	ASSERT_TRUE(evaluated.has_last_attribution());
	EXPECT_DOUBLE_EQ(evaluated.last_attribution().baseline_tx_pps(), 100'000.0);
	EXPECT_EQ(decision->value().observed_monotonic_ns, 80'000'001u);
	EXPECT_TRUE(kinetum::common::validate_guardrails_evaluation(evaluated, &policy, 1u).is_ok());
	evaluator.mark_rollback_pending(true);
	evaluator.resume_after_intent();
	auto restored =
		make_worker_observation("baseline", 3u, {90'000'000u, 95'000'000u, 100'000'000u}, 4'000u, 2'000u);
	restored.active_authority.revision = 1;
	restored.active_authority.active_validation_hash.fill(UINT8_C(1));
	restored.stats.mutable_telemetry()->mutable_transition()->set_active_validation_hash(std::string(32u, '\x01'));
	observe_without_decision(evaluator, restored);
	evaluated = evaluator.evaluation();
	ASSERT_TRUE(evaluated.has_last_attribution());
	EXPECT_TRUE(evaluated.last_attribution().intent_accepted());
	EXPECT_EQ(evaluated.last_attribution().candidate().epoch(), 2u);
	EXPECT_EQ(evaluated.observed_identity().epoch(), 3u);
	EXPECT_TRUE(kinetum::common::validate_guardrails_evaluation(evaluated, &policy, 1u).is_ok());
}

/** @brief Fresh zero-throughput intervals disarm; rereading the positive endpoint does not. */
TEST(guardrails_evaluator, real_zero_intervals_remove_baseline_eligibility)
{
	guardrails_evaluator evaluator;
	auto policy = make_threshold_policy(100u, 1u, false);
	policy.set_telemetry_history_capacity(1u);
	ASSERT_TRUE(evaluator.apply_policy(policy, 1u).is_ok());
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u));
	auto point = make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u);
	observe_without_decision(evaluator, point);
	ASSERT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
	point.stats.mutable_telemetry()->mutable_runtime()->set_collection_monotonic_ns(25'000'000u);
	observe_without_decision(evaluator, point);
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::ARMED);
	observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 30'000'000u, 2'000u, 0u));
	EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::BASELINE_BUILDING);
}

/** @brief Exhausted history and oversized intervals end evaluation without clipping or automatic action. */
TEST(guardrails_evaluator, history_and_time_budgets_refuse_incomplete_evaluation)
{
	for (const bool history_limit : {false, true}) {
		guardrails_evaluator evaluator;
		auto policy = make_threshold_policy(20u, 1u, !history_limit);
		policy.set_telemetry_history_capacity(1u);
		ASSERT_TRUE(evaluator.apply_policy(policy, 1u).is_ok());
		observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 10'000'000u, 1'000u, 0u));
		observe_without_decision(evaluator, make_observation("baseline", 1, 1u, 20'000'000u, 2'000u, 0u));
		observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 30'000'000u, 2'100u, 0u));
		if (history_limit) {
			observe_without_decision(evaluator,
						 make_observation("candidate", 2, 2u, 40'000'000u, 3'100u, 0u));
		}
		observe_without_decision(evaluator, make_observation("candidate", 2, 2u, 60'000'000u, 3'101u, 999u));
		EXPECT_EQ(evaluator.state(), guardrails_evaluator_state::BASELINE_BUILDING);
		const auto evaluated = evaluator.evaluation();
		ASSERT_TRUE(evaluated.has_last_completed());
		EXPECT_EQ(evaluated.last_completed().outcome(),
			  history_limit ? kinetum::control::v1::GUARDRAILS_EVALUATION_OUTCOME_HISTORY_EXHAUSTED :
					  kinetum::control::v1::GUARDRAILS_EVALUATION_OUTCOME_INTERVAL_EXCEEDS_WINDOW);
		EXPECT_EQ(evaluated.last_completed().valid_observation_ns(), history_limit ? 10'000'000u : 0u);
		EXPECT_FALSE(evaluated.has_last_attribution());
	}
}

}  // namespace
}  // namespace kinetum::cp
