// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_guardrails_evaluation_contract.cpp
 * @brief Public guardrails readiness and retained-proof admission tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <string>

#include "src/common/guardrails_evaluation_contract.hpp"

namespace kinetum::common
{
namespace
{

namespace wire = kinetum::control::v1;

/** @return Complete threshold policy whose history and time budgets are independent. */
wire::GuardrailsPolicy policy()
{
	wire::GuardrailsPolicy value;
	value.set_enabled(true);
	value.set_poll_interval_ms(100u);
	value.set_evaluation_window_ms(10'000u);
	value.set_telemetry_history_capacity(100u);
	value.mutable_threshold()->set_max_drop_ratio(0.01);
	value.mutable_threshold()->set_min_tx_ratio(0.99);
	value.mutable_threshold()->set_min_packets_per_window(1u);
	value.mutable_attribution()->set_baseline_samples(10u);
	value.mutable_attribution()->set_auto_rollback_threshold(0.8);
	value.mutable_attribution()->set_defer_threshold(0.5);
	value.mutable_attribution()->set_degradation_threshold(0.3);
	return value;
}

/**
 * @param snapshot Exact authored content name.
 * @param epoch Exact active epoch.
 * @return One bounded single-worker observation identity.
 */
wire::GuardrailsObservationIdentity identity(const std::string &snapshot, uint64_t epoch)
{
	wire::GuardrailsObservationIdentity value;
	value.set_runtime_generation(7u);
	value.set_snapshot_id(snapshot);
	value.set_epoch(epoch);
	value.set_revision(1u);
	value.set_validation_hash(std::string(32u, '\x11'));
	value.set_expected_workers(1u);
	return value;
}

/** @return Actual armed baseline with no candidate outcome or attribution yet. */
wire::GuardrailsEvaluation armed()
{
	wire::GuardrailsEvaluation value;
	value.set_state(wire::GUARDRAILS_EVALUATION_STATE_ARMED);
	value.set_policy_generation(1u);
	*value.mutable_observed_identity() = identity("baseline", 1u);
	value.set_baseline_intervals(10u);
	return value;
}

/** @return Accepted candidate measurements retained after baseline restoration. */
wire::GuardrailsEvaluation restored()
{
	auto value = armed();
	value.set_state(wire::GUARDRAILS_EVALUATION_STATE_BASELINE_BUILDING);
	value.set_baseline_intervals(0u);
	*value.mutable_observed_identity() = identity("baseline", 3u);
	auto *completed = value.mutable_last_completed();
	*completed->mutable_candidate() = identity("candidate", 2u);
	completed->set_valid_observation_ns(10u);
	completed->set_outcome(wire::GUARDRAILS_EVALUATION_OUTCOME_ROLLBACK_ACCEPTED);
	auto *proof = value.mutable_last_attribution();
	*proof->mutable_candidate() = completed->candidate();
	proof->set_rollback_snapshot_id("baseline");
	proof->set_baseline_tx_pps(1'000.0);
	proof->set_confidence(0.9);
	proof->set_recommendation(wire::GUARDRAILS_RECOMMENDATION_AUTO_ROLLBACK);
	proof->set_evidence_complete(true);
	proof->set_intent_accepted(true);
	auto *before = proof->add_previous_workers();
	before->set_worker_index(0u);
	before->set_observation_epoch(2u);
	before->set_publication_generation(1u);
	before->set_published_monotonic_ns(10u);
	before->mutable_counters()->set_rx_packets(100u);
	before->mutable_counters()->set_rx_bytes(6400u);
	before->mutable_counters()->set_tx_packets(100u);
	before->mutable_counters()->set_tx_bytes(6400u);
	auto *after = proof->add_current_workers();
	*after = *before;
	after->set_publication_generation(2u);
	after->set_published_monotonic_ns(20u);
	after->mutable_counters()->set_rx_packets(200u);
	after->mutable_counters()->set_rx_bytes(12800u);
	after->mutable_counters()->set_dropped_packets(100u);
	return value;
}

}  // namespace

/** @brief An enabled policy does not admit armed state without its complete baseline. */
TEST(guardrails_evaluation_contract, exact_readiness_is_distinct_from_policy_enabledness)
{
	const auto configured = policy();
	auto value = armed();
	EXPECT_TRUE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value.set_baseline_intervals(9u);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value.set_state(wire::GUARDRAILS_EVALUATION_STATE_BASELINE_BUILDING);
	EXPECT_TRUE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value.clear_observed_identity();
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value.set_baseline_intervals(0u);
	EXPECT_TRUE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 2u).is_ok());
}

/** @brief Retained candidate proof remains usable after the active identity advances through rollback. */
TEST(guardrails_evaluation_contract, retained_proof_requires_exact_namespace_and_accepted_intent)
{
	const auto configured = policy();
	auto value = restored();
	ASSERT_TRUE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value.mutable_last_attribution()->set_intent_accepted(false);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value = restored();
	value.mutable_last_attribution()->mutable_candidate()->set_runtime_generation(8u);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value = restored();
	value.mutable_last_attribution()->set_confidence(0.7);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value = restored();
	value.mutable_last_completed()->set_valid_observation_ns(0u);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value = restored();
	value.clear_last_completed();
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value = restored();
	value.mutable_last_attribution()->mutable_candidate()->set_epoch(3u);
	value.mutable_last_attribution()->mutable_previous_workers(0)->set_observation_epoch(3u);
	value.mutable_last_attribution()->mutable_current_workers(0)->set_observation_epoch(3u);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
}

/** @brief Attribution source coverage fits the policy and its current or completed evaluation. */
TEST(guardrails_evaluation_contract, source_duration_cannot_exceed_recorded_evaluation)
{
	const auto configured = policy();
	auto value = restored();
	ASSERT_TRUE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value.mutable_last_completed()->set_valid_observation_ns(9u);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());

	value = restored();
	value.clear_last_completed();
	value.mutable_last_attribution()->set_intent_accepted(false);
	ASSERT_TRUE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value.mutable_last_attribution()->mutable_current_workers(0)->set_published_monotonic_ns(10'000'000'011u);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());

	value = restored();
	value.clear_last_completed();
	value.mutable_last_attribution()->set_intent_accepted(false);
	*value.mutable_observed_identity() = value.last_attribution().candidate();
	value.set_state(wire::GUARDRAILS_EVALUATION_STATE_EVALUATING);
	value.set_baseline_intervals(10u);
	value.set_valid_observation_ns(10u);
	ASSERT_TRUE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value.set_valid_observation_ns(9u);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());

	value = restored();
	value.clear_last_attribution();
	value.mutable_last_completed()->set_outcome(wire::GUARDRAILS_EVALUATION_OUTCOME_HISTORY_EXHAUSTED);
	ASSERT_TRUE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	value.mutable_last_completed()->set_valid_observation_ns(0u);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
}

/** @brief An inconclusive attribution retains no fabricated numeric confidence. */
TEST(guardrails_evaluation_contract, confidence_presence_matches_actual_scoring)
{
	const auto configured = policy();
	auto value = restored();
	value.clear_last_completed();
	auto *proof = value.mutable_last_attribution();
	proof->set_intent_accepted(false);
	proof->set_evidence_complete(false);
	proof->set_recommendation(wire::GUARDRAILS_RECOMMENDATION_LOG_ONLY);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	proof->clear_confidence();
	EXPECT_TRUE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
	proof->set_evidence_complete(true);
	EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok());
}

/** @brief Every copied worker endpoint is required, canonical, nonregressing and newly measured. */
TEST(guardrails_evaluation_contract, malformed_worker_proof_cannot_authorize_observation)
{
	const auto configured = policy();
	for (int fault = 0; fault < 6; ++fault) {
		auto value = restored();
		auto *proof = value.mutable_last_attribution();
		auto *after = proof->mutable_current_workers(0);
		switch (fault) {
		case 0:
			proof->clear_current_workers();
			break;
		case 1:
			*proof->add_current_workers() = *after;
			break;
		case 2:
			after->set_worker_index(1u);
			break;
		case 3:
			after->set_publication_generation(1u);
			break;
		case 4:
			after->set_published_monotonic_ns(10u);
			break;
		case 5:
			after->mutable_counters()->set_tx_packets(99u);
			break;
		}
		EXPECT_FALSE(validate_guardrails_evaluation(value, &configured, 1u).is_ok()) << fault;
	}
}

}  // namespace kinetum::common
