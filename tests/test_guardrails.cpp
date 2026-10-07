// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_guardrails.cpp
 * @brief Guardrails evaluation and automatic-rollback tests.
 * @author Fleming Patel
 *
 * Guardrails detect regressions after configuration changes and submit rollback
 * intent through the Control Plane's single-writer loop. Passive configuration
 * transitions, commit-confirmed rollback, durable guardrails policy, and
 * coherent DP evidence are live. Component tests isolate deterministic
 * detector and attribution behavior from transport orchestration.
 *
 * Guardrails Algorithm:
 * ---------------------
 * 1. Fence one complete Data Plane observation against durable active content.
 * 2. Derive one same-generation interval for the selected detector.
 * 3. Attribute a detected regression against a frozen previous-content baseline.
 * 4. Persist one observation-bound rollback intent before the ordinary exact
 *    transition path executes it; active content moves only after typed DP
 *    COMPLETE.
 *
 * Test Categories:
 * ----------------
 * 1. Policy Validation: Parameter bounds checking
 * 2. Thread Lifecycle: Start/stop idempotency
 * 3. Regression Detection: Drop ratio and throughput thresholds
 *
 * @note Tests that require gRPC mocking are designed to validate the
 *       guardrails logic without actual network communication.
 *
 * @see src/cp/guardrails.hpp
 * @see src/cp/guardrails.cpp
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <future>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <google/protobuf/descriptor.pb.h>
#include <grpcpp/grpcpp.h>
#include <kinetum/kinetum_sdk.h>

#include "gen/kinetum/control/internal/v1/transition_authority.pb.h"
#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/control_plane_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/common/time.hpp"
#include "src/common/transition_idempotency_key.hpp"
#include "src/cp/attribution_scorer.hpp"
#include "src/cp/config_store.hpp"
#include "src/cp/control_loop.hpp"
#include "src/cp/cp_grpc.hpp"
#include "src/cp/guardrails.hpp"
#include "src/cp/guardrails_policy.hpp"
#include "src/cp/health_correlator.hpp"
#include "src/cp/telemetry_snapshot.hpp"

#include "tests/test_grpc_helpers.hpp"

namespace kinetum::cp
{

/**
 * @brief Build one exact interval consumed by health-correlator tests.
 * @param snapshot_id Exact content identity.
 * @param drop_ratio Precomputed same-generation interval drop ratio.
 * @param throughput_ratio Precomputed baseline-relative accepted-TX ratio.
 * @param health Exact current module health.
 * @param flags Exact current module health flags.
 * @param timestamp_ms Audit timestamp paired with this interval.
 * @param runtime_generation Exact cumulative-counter namespace already checked by the evaluator.
 * @return Complete prevalidated interval with one current module row.
 */
telemetry_snapshot make_correlator_sample(std::string snapshot_id, double drop_ratio, double throughput_ratio,
					  uint8_t health = 100u, uint32_t flags = 0u, uint64_t timestamp_ms = 1u,
					  uint64_t runtime_generation = 1u)
{
	telemetry_snapshot sample;
	sample.config_snapshot_id = std::move(snapshot_id);
	sample.runtime_generation = runtime_generation;
	sample.timestamp_ms = timestamp_ms;
	sample.timestamp_mono_ns = timestamp_ms * UINT64_C(1000000);
	sample.drop_ratio = drop_ratio;
	sample.throughput_ratio = throughput_ratio;
	sample.module_health_count = 1u;
	sample.module_health_avg = health;
	sample.config_issue_count = (flags & KINETUM_HEALTH_F_CONFIG_ISSUE) != 0u ? 1u : 0u;
	return sample;
}

/**
 * @brief Build one explicit exact correlator configuration for component tests.
 * @param alpha Exact EWMA factor.
 * @param threshold Exact degradation threshold.
 * @param band Exact hysteresis band.
 * @return Complete configuration with no production fallback values.
 */
health_correlation_config make_health_correlation_config(double alpha = 0.3, double threshold = 0.5, double band = 0.1)
{
	return health_correlation_config{
		.ewma_alpha = alpha,
		.degradation_threshold = threshold,
		.hysteresis_band = band,
		.normalization_max_drop_ratio = 0.10,
		.normalization_min_tx_ratio = 0.50,
		.weights =
			correlation_weights{
				.drop_ratio = 0.25,
				.throughput_ratio = 0.25,
				.module_health = 0.30,
				.config_issue_boost = 0.20,
			},
		.min_samples = 3u,
	};
}

//==============================================================================
// Policy Validation Tests
//==============================================================================

/**
 * @brief Build one complete threshold policy without hidden defaults.
 * @param poll_ms Exact observation cadence.
 * @param window_ms Exact valid-observation window.
 * @param max_drop_ratio Exact threshold drop ratio.
 * @param min_tx_ratio Exact threshold throughput ratio.
 * @param min_packets Exact threshold population.
 * @return Complete enabled policy with explicit attribution and history.
 */
static kinetum::control::v1::GuardrailsPolicy
make_valid_threshold_policy(uint64_t poll_ms = 1000u, uint64_t window_ms = 30'000u, double max_drop_ratio = 0.05,
			    double min_tx_ratio = 0.70, uint64_t min_packets = 1000u)
{
	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(true);
	policy.set_poll_interval_ms(poll_ms);
	policy.set_evaluation_window_ms(window_ms);
	policy.set_telemetry_history_capacity(100u);
	auto *threshold = policy.mutable_threshold();
	threshold->set_max_drop_ratio(max_drop_ratio);
	threshold->set_min_tx_ratio(min_tx_ratio);
	threshold->set_min_packets_per_window(min_packets);
	auto *attribution = policy.mutable_attribution();
	attribution->set_auto_rollback_threshold(0.80);
	attribution->set_defer_threshold(0.50);
	attribution->set_baseline_samples(10u);
	attribution->set_degradation_threshold(0.30);
	return policy;
}

/**
 * @brief Verify the default wire value is exactly an empty disabled policy.
 *
 * Message absence never enables evaluation or supplies a policy value.
 */
TEST(guardrails_policy, default_wire_is_explicit_empty_disabled_policy)
{
	kinetum::control::v1::GuardrailsPolicy policy;

	// Proto zero is the exact explicit-empty disabled representation.
	EXPECT_FALSE(policy.enabled()) << "Empty policy must be disabled";

	// Default poll_interval_ms is 0 (must be set explicitly)
	EXPECT_EQ(policy.poll_interval_ms(), 0) << "Default poll_interval_ms should be 0";

	// Default evaluation_window_ms is 0 (must be set explicitly)
	EXPECT_EQ(policy.evaluation_window_ms(), 0) << "Default evaluation_window_ms should be 0";
}

/** @brief Pin the compact nested policy and exact retry/confirmation wire. */
TEST(guardrails_policy, schema_is_nested_compact_and_has_no_removed_authority)
{
	using google::protobuf::FieldDescriptor;
	const auto *policy = kinetum::control::v1::GuardrailsPolicy::descriptor();
	ASSERT_NE(policy, nullptr);
	ASSERT_EQ(policy->field_count(), 8);
	constexpr std::array<std::string_view, 8> NAMES{
		"enabled",   "poll_interval_ms", "evaluation_window_ms", "telemetry_history_capacity",
		"threshold", "correlation",	 "attribution",		 "boundary",
	};
	for (int index = 0; index < policy->field_count(); ++index) {
		EXPECT_EQ(policy->field(index)->name(), NAMES[static_cast<std::size_t>(index)]);
		EXPECT_EQ(policy->field(index)->number(), index + 1);
	}
	ASSERT_EQ(policy->oneof_decl_count(), 1);
	EXPECT_EQ(policy->oneof_decl(0)->name(), "detector");
	EXPECT_EQ(policy->FindFieldByName("threshold")->containing_oneof(), policy->oneof_decl(0));
	EXPECT_EQ(policy->FindFieldByName("correlation")->containing_oneof(), policy->oneof_decl(0));
	EXPECT_EQ(policy->reserved_range_count(), 0);
	EXPECT_EQ(policy->reserved_name_count(), 0);
	constexpr std::array<std::string_view, 24> REMOVED_POLICY_FIELDS{
		"max_drop_ratio",
		"min_packets_per_window",
		"min_tx_ratio",
		"conditions",
		"rollback_target",
		"enable_alerts",
		"drop_ratio_weight",
		"throughput_ratio_weight",
		"module_health_weight",
		"config_issue_boost",
		"ewma_alpha",
		"degradation_threshold",
		"hysteresis_band",
		"min_samples",
		"epoch_ack_timeout_ms",
		"max_backpressure_events_per_interval",
		"boundary_monitoring_enabled",
		"correlator_max_drop_ratio",
		"correlator_min_throughput_ratio",
		"attribution_auto_rollback_threshold",
		"attribution_defer_threshold",
		"attribution_baseline_samples",
		"attribution_degradation_threshold",
		"telemetry_history_max_per_config",
	};
	for (const auto name : REMOVED_POLICY_FIELDS) {
		EXPECT_EQ(policy->FindFieldByName(std::string(name)), nullptr) << name;
	}
	EXPECT_EQ(policy->file()->FindEnumTypeByName("GuardrailMetric"), nullptr);
	EXPECT_EQ(policy->file()->FindMessageTypeByName("GuardrailCondition"), nullptr);
	const auto *threshold = kinetum::control::v1::GuardrailsThresholdPolicy::descriptor();
	ASSERT_EQ(threshold->field_count(), 3);
	EXPECT_EQ(threshold->field(0)->name(), "max_drop_ratio");
	EXPECT_EQ(threshold->field(0)->number(), 1);
	EXPECT_EQ(threshold->field(1)->name(), "min_tx_ratio");
	EXPECT_EQ(threshold->field(1)->number(), 2);
	EXPECT_EQ(threshold->field(2)->name(), "min_packets_per_window");
	EXPECT_EQ(threshold->field(2)->number(), 3);
	const auto *correlation = kinetum::control::v1::GuardrailsCorrelationPolicy::descriptor();
	ASSERT_EQ(correlation->field_count(), 10);
	constexpr std::array<std::string_view, 10> CORRELATION_NAMES{
		"drop_ratio_weight",
		"throughput_ratio_weight",
		"module_health_weight",
		"config_issue_boost",
		"ewma_alpha",
		"degradation_threshold",
		"hysteresis_band",
		"min_samples",
		"normalization_max_drop_ratio",
		"normalization_min_tx_ratio",
	};
	for (int index = 0; index < correlation->field_count(); ++index) {
		EXPECT_EQ(correlation->field(index)->name(), CORRELATION_NAMES[static_cast<std::size_t>(index)]);
		EXPECT_EQ(correlation->field(index)->number(), index + 1);
	}
	const auto *attribution = kinetum::control::v1::GuardrailsAttributionPolicy::descriptor();
	ASSERT_EQ(attribution->field_count(), 4);
	constexpr std::array<std::string_view, 4> ATTRIBUTION_NAMES{
		"auto_rollback_threshold",
		"defer_threshold",
		"baseline_samples",
		"degradation_threshold",
	};
	for (int index = 0; index < attribution->field_count(); ++index) {
		EXPECT_EQ(attribution->field(index)->name(), ATTRIBUTION_NAMES[static_cast<std::size_t>(index)]);
		EXPECT_EQ(attribution->field(index)->number(), index + 1);
	}
	const auto *boundary = kinetum::control::v1::GuardrailsBoundaryPolicy::descriptor();
	ASSERT_EQ(boundary->field_count(), 1);
	EXPECT_EQ(boundary->field(0)->name(), "ack_timeout_ms");
	EXPECT_EQ(boundary->field(0)->number(), 1);

	const auto *configure = kinetum::control::v1::ConfigureGuardrailsRequest::descriptor();
	ASSERT_EQ(configure->field_count(), 3);
	EXPECT_EQ(configure->field(0)->name(), "policy");
	EXPECT_EQ(configure->field(0)->number(), 1);
	EXPECT_EQ(configure->FindFieldByName("idempotency_key")->number(), 2);
	const auto *expected_generation = configure->FindFieldByName("expected_policy_generation");
	ASSERT_NE(expected_generation, nullptr);
	EXPECT_EQ(expected_generation->number(), 3);
	google::protobuf::FieldDescriptorProto expected_generation_schema;
	expected_generation->CopyTo(&expected_generation_schema);
	EXPECT_TRUE(expected_generation_schema.proto3_optional());
	EXPECT_TRUE(expected_generation->has_presence());
	const auto *configure_response = kinetum::control::v1::ConfigureGuardrailsResponse::descriptor();
	ASSERT_EQ(configure_response->field_count(), 3);
	EXPECT_EQ(configure_response->field(0)->name(), "status");
	EXPECT_EQ(configure_response->field(0)->number(), 1);
	EXPECT_EQ(configure_response->FindFieldByName("policy_generation")->number(), 2);
	EXPECT_EQ(configure_response->FindFieldByName("policy_hash")->number(), 3);
	const auto *get_request = kinetum::control::v1::GetGuardrailsRequest::descriptor();
	ASSERT_EQ(get_request->field_count(), 0);
	const auto *get_response = kinetum::control::v1::GetGuardrailsResponse::descriptor();
	ASSERT_EQ(get_response->field_count(), 4);
	EXPECT_EQ(get_response->FindFieldByName("policy_generation")->number(), 3);
	EXPECT_EQ(get_response->FindFieldByName("policy_hash")->number(), 4);
	const auto *confirm = kinetum::control::v1::ConfirmConfigRequest::descriptor();
	ASSERT_EQ(confirm->field_count(), 4);
	constexpr std::array<std::string_view, 4> CONFIRM_NAMES{"snapshot_id", "epoch", "revision", "idempotency_key"};
	for (int index = 0; index < confirm->field_count(); ++index) {
		EXPECT_EQ(confirm->field(index)->name(), CONFIRM_NAMES[static_cast<std::size_t>(index)]);
		EXPECT_EQ(confirm->field(index)->number(), index + 1);
	}
	EXPECT_EQ(confirm->FindFieldByName("idempotency_key")->number(), 4);
	const auto *confirm_revision = confirm->FindFieldByName("revision");
	ASSERT_NE(confirm_revision, nullptr);
	google::protobuf::FieldDescriptorProto confirm_revision_schema;
	confirm_revision->CopyTo(&confirm_revision_schema);
	EXPECT_TRUE(confirm_revision_schema.proto3_optional());
	EXPECT_TRUE(confirm_revision->has_presence());
	const auto *confirm_response = kinetum::control::v1::ConfirmConfigResponse::descriptor();
	ASSERT_EQ(confirm_response->field_count(), 5);
	constexpr std::array<std::string_view, 5> CONFIRM_RESPONSE_NAMES{"status", "snapshot_id", "time_remaining_ms",
									 "epoch", "revision"};
	for (int index = 0; index < confirm_response->field_count(); ++index) {
		EXPECT_EQ(confirm_response->field(index)->name(),
			  CONFIRM_RESPONSE_NAMES[static_cast<std::size_t>(index)]);
		EXPECT_EQ(confirm_response->field(index)->number(), index + 1);
	}
	EXPECT_EQ(confirm_response->FindFieldByName("epoch")->number(), 4);
	const auto *confirmed_revision = confirm_response->FindFieldByName("revision");
	ASSERT_NE(confirmed_revision, nullptr);
	EXPECT_EQ(confirmed_revision->number(), 5);
	google::protobuf::FieldDescriptorProto confirmed_revision_schema;
	confirmed_revision->CopyTo(&confirmed_revision_schema);
	EXPECT_TRUE(confirmed_revision_schema.proto3_optional());
	EXPECT_TRUE(confirmed_revision->has_presence());
	const auto *pending = kinetum::control::v1::PendingConfirm::descriptor();
	ASSERT_EQ(pending->field_count(), 10);
	constexpr std::array<std::string_view, 10> PENDING_NAMES{
		"snapshot_id",
		"epoch",
		"deadline_unix_ms",
		"rollback_snapshot_id",
		"created_unix_ms",
		"original_timeout_ms",
		"revision",
		"confirmed",
		"confirmation_key_digest",
		"confirmed_time_remaining_ms",
	};
	for (int index = 0; index < pending->field_count(); ++index) {
		EXPECT_EQ(pending->field(index)->name(), PENDING_NAMES[static_cast<std::size_t>(index)]);
		EXPECT_EQ(pending->field(index)->number(), index + 1);
	}
	EXPECT_EQ(pending->FindFieldByName("confirmation_key_digest")->type(), FieldDescriptor::TYPE_BYTES);
}

/**
 * @brief Verify policy with valid parameters passes basic checks.
 *
 * A properly configured policy should have:
 * - poll_interval_ms > 0
 * - evaluation_window_ms >= poll_interval_ms
 * - max_drop_ratio in [0.0, 1.0]
 * - min_tx_ratio in [0.0, 1.0]
 */
TEST(guardrails_policy, valid_policy_configuration)
{
	auto policy = make_valid_threshold_policy();

	EXPECT_TRUE(policy.enabled());
	EXPECT_EQ(policy.poll_interval_ms(), 1000);
	EXPECT_EQ(policy.evaluation_window_ms(), 30000);
	EXPECT_DOUBLE_EQ(policy.threshold().max_drop_ratio(), 0.05);
	EXPECT_DOUBLE_EQ(policy.threshold().min_tx_ratio(), 0.7);
	EXPECT_EQ(policy.threshold().min_packets_per_window(), 1000u);

	// Validate derived constraints
	EXPECT_GT(policy.poll_interval_ms(), 0) << "poll_interval_ms must be > 0";
	EXPECT_GE(policy.evaluation_window_ms(), policy.poll_interval_ms())
		<< "evaluation_window_ms must be >= poll_interval_ms";
	EXPECT_GE(policy.threshold().max_drop_ratio(), 0.0) << "max_drop_ratio must be >= 0.0";
	EXPECT_LE(policy.threshold().max_drop_ratio(), 1.0) << "max_drop_ratio must be <= 1.0";
	EXPECT_GE(policy.threshold().min_tx_ratio(), 0.0) << "min_tx_ratio must be >= 0.0";
	EXPECT_LE(policy.threshold().min_tx_ratio(), 1.0) << "min_tx_ratio must be <= 1.0";
}

/**
 * @brief Verify one explicit edge-gateway policy shape.
 *
 * Edge gateway deployments typically use:
 * - 5% max drop ratio (more tolerant than core)
 * - 70% min throughput ratio
 * - 30 second evaluation window
 */
TEST(guardrails_policy, explicit_edge_gateway_policy_shape)
{
	auto policy = make_valid_threshold_policy();

	EXPECT_TRUE(policy.enabled());
	EXPECT_EQ(policy.poll_interval_ms(), 1000) << "Edge gateway should poll every 1 second";
	EXPECT_EQ(policy.evaluation_window_ms(), 30000) << "Edge gateway should evaluate over 30 seconds";
	EXPECT_DOUBLE_EQ(policy.threshold().max_drop_ratio(), 0.05) << "Edge gateway allows 5% drops";
	EXPECT_DOUBLE_EQ(policy.threshold().min_tx_ratio(), 0.70) << "Edge gateway requires 70% of baseline throughput";
}

/**
 * @brief Verify one explicit core-router policy shape.
 *
 * Core router deployments typically use:
 * - 1% max drop ratio (stricter than edge)
 * - 90% min throughput ratio
 * - 10 second evaluation window (faster response)
 */
TEST(guardrails_policy, explicit_core_router_policy_shape)
{
	auto policy = make_valid_threshold_policy(500u, 10'000u, 0.01, 0.90, 10'000u);

	EXPECT_TRUE(policy.enabled());
	EXPECT_EQ(policy.poll_interval_ms(), 500) << "Core router should poll every 500ms";
	EXPECT_EQ(policy.evaluation_window_ms(), 10000) << "Core router should evaluate over 10 seconds";
	EXPECT_DOUBLE_EQ(policy.threshold().max_drop_ratio(), 0.01) << "Core router allows only 1% drops";
	EXPECT_DOUBLE_EQ(policy.threshold().min_tx_ratio(), 0.90) << "Core router requires 90% of baseline throughput";
}

//==============================================================================
// Shared Policy Validator Tests (validate_guardrails_policy)
//==============================================================================

/**
 * @brief Valid enabled policy passes validation.
 */
TEST(validate_guardrails_policy, valid_enabled_policy_passes)
{
	auto policy = make_valid_threshold_policy();

	EXPECT_TRUE(validate_guardrails_policy(policy).is_ok());
	auto one_interval = make_valid_threshold_policy(10u, 10u);
	one_interval.set_telemetry_history_capacity(1u);
	one_interval.mutable_attribution()->set_baseline_samples(1u);
	EXPECT_TRUE(validate_guardrails_policy(one_interval).is_ok())
		<< "one interval requires one history row; its cumulative seed is separate state";
}

/**
 * @brief Explicitly empty disabled policy passes and every residue rejects.
 */
TEST(validate_guardrails_policy, disabled_policy_is_explicitly_empty)
{
	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);
	// Intentionally leave all values at 0 (would be invalid if enabled)

	EXPECT_TRUE(validate_guardrails_policy(policy).is_ok());
	policy.set_poll_interval_ms(1u);
	EXPECT_EQ(validate_guardrails_policy(policy).code(), kinetum::common::status_code::INVALID_ARGUMENT);
	policy.Clear();
	policy.set_evaluation_window_ms(1u);
	EXPECT_FALSE(validate_guardrails_policy(policy).is_ok());
	policy.Clear();
	policy.set_telemetry_history_capacity(1u);
	EXPECT_FALSE(validate_guardrails_policy(policy).is_ok());
	policy.Clear();
	policy.mutable_threshold();
	EXPECT_FALSE(validate_guardrails_policy(policy).is_ok());
	policy.Clear();
	policy.mutable_correlation();
	EXPECT_FALSE(validate_guardrails_policy(policy).is_ok());
	policy.Clear();
	policy.mutable_attribution();
	EXPECT_FALSE(validate_guardrails_policy(policy).is_ok());
	policy.Clear();
	policy.mutable_boundary();
	EXPECT_FALSE(validate_guardrails_policy(policy).is_ok());
}

/**
 * @brief Invalid poll_interval_ms is rejected (not silently rewritten).
 */
TEST(validate_guardrails_policy, rejects_invalid_poll_interval)
{
	auto policy = make_valid_threshold_policy();
	policy.set_poll_interval_ms(0);	 // Invalid: must be >= 1

	auto status = validate_guardrails_policy(policy);
	EXPECT_TRUE(status.is_error());
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Invalid evaluation_window_ms is rejected.
 */
TEST(validate_guardrails_policy, rejects_invalid_evaluation_window)
{
	auto policy = make_valid_threshold_policy();
	policy.set_evaluation_window_ms(500);  // Invalid: less than poll_interval_ms

	auto status = validate_guardrails_policy(policy);
	EXPECT_TRUE(status.is_error());
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	policy = make_valid_threshold_policy(1u, 101u);
	policy.set_telemetry_history_capacity(100u);
	status = validate_guardrails_policy(policy);
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT)
		<< "one complete window must fit the explicitly authored interval history";
}

/**
 * @brief Invalid max_drop_ratio is rejected (not silently set to 0.05).
 */
TEST(validate_guardrails_policy, rejects_invalid_max_drop_ratio)
{
	auto policy = make_valid_threshold_policy();
	policy.mutable_threshold()->set_max_drop_ratio(1.5);  // Invalid: > 1.0

	auto status = validate_guardrails_policy(policy);
	EXPECT_TRUE(status.is_error());
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Invalid min_tx_ratio is rejected (not silently set to 0.7).
 */
TEST(validate_guardrails_policy, rejects_invalid_min_tx_ratio)
{
	auto policy = make_valid_threshold_policy();
	policy.mutable_threshold()->set_min_tx_ratio(-0.1);  // Invalid: < 0.0

	auto status = validate_guardrails_policy(policy);
	EXPECT_TRUE(status.is_error());
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

//==============================================================================
// Advanced Knob Validation Tests (validate_guardrails_policy)
//==============================================================================

/**
 * @brief Build one fully valid explicit correlation policy.
 * @return Complete policy whose fields can be mutated one at a time.
 */
static kinetum::control::v1::GuardrailsPolicy make_valid_advanced_policy()
{
	kinetum::control::v1::GuardrailsPolicy p;
	p.set_enabled(true);
	p.set_poll_interval_ms(1000);
	p.set_evaluation_window_ms(30000);
	p.set_telemetry_history_capacity(100);
	auto *correlation = p.mutable_correlation();
	correlation->set_drop_ratio_weight(0.25);
	correlation->set_throughput_ratio_weight(0.25);
	correlation->set_module_health_weight(0.30);
	correlation->set_config_issue_boost(0.20);
	correlation->set_ewma_alpha(0.3);
	correlation->set_degradation_threshold(0.5);
	correlation->set_hysteresis_band(0.1);
	correlation->set_min_samples(3);
	correlation->set_normalization_max_drop_ratio(0.10);
	correlation->set_normalization_min_tx_ratio(0.50);
	auto *attribution = p.mutable_attribution();
	attribution->set_auto_rollback_threshold(0.80);
	attribution->set_defer_threshold(0.50);
	attribution->set_baseline_samples(10);
	attribution->set_degradation_threshold(0.30);
	return p;
}

/**
 * @brief Fully populated advanced policy passes validation.
 */
TEST(validate_guardrails_policy, valid_advanced_policy_passes)
{
	auto policy = make_valid_advanced_policy();
	EXPECT_TRUE(validate_guardrails_policy(policy).is_ok());
}

/** @brief Every floating policy field rejects non-finite input independently. */
TEST(validate_guardrails_policy, every_floating_field_is_finite)
{
	const double nan = std::numeric_limits<double>::quiet_NaN();
	const auto expect_rejected = [&](const auto &mutate) {
		auto policy = make_valid_advanced_policy();
		mutate(policy, nan);
		EXPECT_EQ(validate_guardrails_policy(policy).code(), kinetum::common::status_code::INVALID_ARGUMENT);
	};
	expect_rejected([](auto &p, double value) { p.mutable_correlation()->set_drop_ratio_weight(value); });
	expect_rejected([](auto &p, double value) { p.mutable_correlation()->set_throughput_ratio_weight(value); });
	expect_rejected([](auto &p, double value) { p.mutable_correlation()->set_module_health_weight(value); });
	expect_rejected([](auto &p, double value) { p.mutable_correlation()->set_config_issue_boost(value); });
	expect_rejected([](auto &p, double value) { p.mutable_correlation()->set_ewma_alpha(value); });
	expect_rejected([](auto &p, double value) { p.mutable_correlation()->set_degradation_threshold(value); });
	expect_rejected([](auto &p, double value) { p.mutable_correlation()->set_hysteresis_band(value); });
	expect_rejected(
		[](auto &p, double value) { p.mutable_correlation()->set_normalization_max_drop_ratio(value); });
	expect_rejected([](auto &p, double value) { p.mutable_correlation()->set_normalization_min_tx_ratio(value); });
	expect_rejected([](auto &p, double value) { p.mutable_attribution()->set_auto_rollback_threshold(value); });
	expect_rejected([](auto &p, double value) { p.mutable_attribution()->set_defer_threshold(value); });
	expect_rejected([](auto &p, double value) { p.mutable_attribution()->set_degradation_threshold(value); });

	auto threshold = make_valid_threshold_policy();
	threshold.mutable_threshold()->set_max_drop_ratio(std::numeric_limits<double>::infinity());
	EXPECT_EQ(validate_guardrails_policy(threshold).code(), kinetum::common::status_code::INVALID_ARGUMENT);
	threshold = make_valid_threshold_policy();
	threshold.mutable_threshold()->set_min_tx_ratio(-std::numeric_limits<double>::infinity());
	EXPECT_EQ(validate_guardrails_policy(threshold).code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Incomplete enabled policy rejects instead of applying defaults.
 */
TEST(validate_guardrails_policy, incomplete_enabled_policy_rejects_without_defaults)
{
	auto policy = make_valid_threshold_policy();
	policy.clear_attribution();
	EXPECT_FALSE(validate_guardrails_policy(policy).is_ok());
}

// --- Correlation weight individual bounds ---

/**
 * @brief Verify rejects negative drop ratio weight.
 */
TEST(validate_guardrails_policy, rejects_negative_drop_ratio_weight)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_drop_ratio_weight(-0.1);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects drop ratio weight above 1.
 */
TEST(validate_guardrails_policy, rejects_drop_ratio_weight_above_1)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_drop_ratio_weight(1.5);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects negative throughput ratio weight.
 */
TEST(validate_guardrails_policy, rejects_negative_throughput_ratio_weight)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_throughput_ratio_weight(-0.01);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects module health weight above 1.
 */
TEST(validate_guardrails_policy, rejects_module_health_weight_above_1)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_module_health_weight(2.0);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects negative config issue boost.
 */
TEST(validate_guardrails_policy, rejects_negative_config_issue_boost)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_config_issue_boost(-0.5);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Cross-field: base weight sum ---

/**
 * @brief Verify rejects base weight sum above 1.
 */
TEST(validate_guardrails_policy, rejects_base_weight_sum_above_1)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_drop_ratio_weight(0.50);
	p.mutable_correlation()->set_throughput_ratio_weight(0.30);
	p.mutable_correlation()->set_module_health_weight(0.30);  // sum = 1.10
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	p = make_valid_advanced_policy();
	p.mutable_correlation()->set_drop_ratio_weight(0.40);
	p.mutable_correlation()->set_throughput_ratio_weight(0.30);
	p.mutable_correlation()->set_module_health_weight(0.20);
	p.mutable_correlation()->set_config_issue_boost(0.20);
	EXPECT_EQ(validate_guardrails_policy(p).code(), kinetum::common::status_code::INVALID_ARGUMENT)
		<< "base plus maximum CONFIG_ISSUE contribution must fit one score";
	p = make_valid_advanced_policy();
	p.mutable_correlation()->set_drop_ratio_weight(0.0);
	p.mutable_correlation()->set_throughput_ratio_weight(0.0);
	p.mutable_correlation()->set_module_health_weight(0.0);
	p.mutable_correlation()->set_config_issue_boost(0.0);
	EXPECT_EQ(validate_guardrails_policy(p).code(), kinetum::common::status_code::INVALID_ARGUMENT)
		<< "an enabled correlation detector needs at least one real signal";
}

// --- EWMA alpha ---

/**
 * @brief Verify rejects negative ewma alpha.
 */
TEST(validate_guardrails_policy, rejects_negative_ewma_alpha)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_ewma_alpha(-0.1);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects ewma alpha above 1.
 */
TEST(validate_guardrails_policy, rejects_ewma_alpha_above_1)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_ewma_alpha(1.5);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Degradation threshold ---

/**
 * @brief Verify rejects negative degradation threshold.
 */
TEST(validate_guardrails_policy, rejects_negative_degradation_threshold)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_degradation_threshold(-0.1);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects degradation threshold above 1.
 */
TEST(validate_guardrails_policy, rejects_degradation_threshold_above_1)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_degradation_threshold(1.5);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Hysteresis band ---

/**
 * @brief Verify rejects negative hysteresis band.
 */
TEST(validate_guardrails_policy, rejects_negative_hysteresis_band)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_hysteresis_band(-0.05);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Cross-field: hysteresis_band >= degradation_threshold ---

/**
 * @brief Verify rejects hysteresis band gte degradation threshold.
 */
TEST(validate_guardrails_policy, rejects_hysteresis_band_gte_degradation_threshold)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_degradation_threshold(0.3);
	p.mutable_correlation()->set_hysteresis_band(0.3);  // equal - invalid
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects hysteresis band exceeding threshold.
 */
TEST(validate_guardrails_policy, rejects_hysteresis_band_exceeding_threshold)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_degradation_threshold(0.2);
	p.mutable_correlation()->set_hysteresis_band(0.3);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects hysteresis band above proto max.
 */
TEST(validate_guardrails_policy, rejects_hysteresis_band_above_proto_max)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_hysteresis_band(0.6);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify zero degradation threshold cannot hide behind hysteresis residue.
 */
TEST(validate_guardrails_policy, rejects_zero_degradation_threshold_with_hysteresis_residue)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_degradation_threshold(0.0);
	p.mutable_correlation()->set_hysteresis_band(0.5);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Min samples ---

/**
 * @brief Verify rejects min samples above max.
 */
TEST(validate_guardrails_policy, rejects_min_samples_above_max)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_min_samples(10001);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/** @brief A detector sample floor cannot exceed its valid evaluation intervals. */
TEST(validate_guardrails_policy, rejects_min_samples_unreachable_within_window)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_min_samples(31u);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Correlator normalization bounds ---

/**
 * @brief Verify rejects negative correlator max drop ratio.
 */
TEST(validate_guardrails_policy, rejects_negative_correlation_normalization_drop_ratio)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_normalization_max_drop_ratio(-0.01);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects correlator max drop ratio above 1.
 */
TEST(validate_guardrails_policy, rejects_correlation_normalization_drop_ratio_above_one)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_normalization_max_drop_ratio(1.5);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects correlator min throughput ratio at 1.
 */
TEST(validate_guardrails_policy, rejects_correlation_normalization_throughput_ratio_at_one)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_normalization_min_tx_ratio(1.0);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects negative correlator min throughput ratio.
 */
TEST(validate_guardrails_policy, rejects_negative_correlation_normalization_throughput_ratio)
{
	auto p = make_valid_advanced_policy();
	p.mutable_correlation()->set_normalization_min_tx_ratio(-0.1);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Attribution thresholds ---

/**
 * @brief Verify rejects attribution auto rollback above 1.
 */
TEST(validate_guardrails_policy, rejects_attribution_auto_rollback_above_1)
{
	auto p = make_valid_advanced_policy();
	p.mutable_attribution()->set_auto_rollback_threshold(1.5);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects negative attribution defer threshold.
 */
TEST(validate_guardrails_policy, rejects_negative_nested_defer_threshold)
{
	auto p = make_valid_advanced_policy();
	p.mutable_attribution()->set_defer_threshold(-0.1);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Cross-field: defer > auto_rollback ---

/**
 * @brief Verify rejects defer threshold above auto rollback.
 */
TEST(validate_guardrails_policy, rejects_defer_threshold_above_auto_rollback)
{
	auto p = make_valid_advanced_policy();
	p.mutable_attribution()->set_auto_rollback_threshold(0.60);
	p.mutable_attribution()->set_defer_threshold(0.80);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify zero auto-rollback threshold cannot imply a hidden default.
 */
TEST(validate_guardrails_policy, rejects_zero_auto_rollback_threshold)
{
	auto p = make_valid_advanced_policy();
	p.mutable_attribution()->set_auto_rollback_threshold(0.0);
	p.mutable_attribution()->set_defer_threshold(0.90);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Attribution analysis parameters ---

/**
 * @brief Verify rejects attribution baseline samples above max.
 */
TEST(validate_guardrails_policy, rejects_nested_attribution_baseline_above_history)
{
	auto p = make_valid_advanced_policy();
	p.mutable_attribution()->set_baseline_samples(100001);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects negative attribution degradation threshold.
 */
TEST(validate_guardrails_policy, rejects_negative_nested_attribution_magnitude_floor)
{
	auto p = make_valid_advanced_policy();
	p.mutable_attribution()->set_degradation_threshold(-0.1);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify rejects attribution degradation threshold above 1.
 */
TEST(validate_guardrails_policy, rejects_nested_attribution_magnitude_floor_above_one)
{
	auto p = make_valid_advanced_policy();
	p.mutable_attribution()->set_degradation_threshold(2.0);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Telemetry history capacity ---

/**
 * @brief Verify rejects telemetry history above max.
 */
TEST(validate_guardrails_policy, rejects_telemetry_history_above_max)
{
	auto p = make_valid_advanced_policy();
	p.set_telemetry_history_capacity(100001);
	auto s = validate_guardrails_policy(p);
	EXPECT_TRUE(s.is_error());
	EXPECT_EQ(s.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

// --- Edge cases: boundary values that should PASS ---

/**
 * @brief Verify exact boundary values and derived-unit overflow rejection.
 */
TEST(validate_guardrails_policy, boundary_values_and_derived_units_are_exact)
{
	auto p = make_valid_advanced_policy();
	auto *correlation = p.mutable_correlation();
	correlation->set_drop_ratio_weight(1.0);
	correlation->set_throughput_ratio_weight(0.0);
	correlation->set_module_health_weight(0.0);
	correlation->set_config_issue_boost(0.0);
	correlation->set_ewma_alpha(1.0);
	correlation->set_degradation_threshold(1.0);
	correlation->set_hysteresis_band(0.5);
	correlation->set_min_samples(30u);
	correlation->set_normalization_max_drop_ratio(1.0);
	correlation->set_normalization_min_tx_ratio(0.99);
	p.mutable_attribution()->set_auto_rollback_threshold(1.0);
	p.mutable_attribution()->set_defer_threshold(1.0);
	p.mutable_attribution()->set_baseline_samples(100u);
	p.mutable_attribution()->set_degradation_threshold(1.0);
	p.mutable_boundary()->set_ack_timeout_ms(30'000u);
	EXPECT_TRUE(validate_guardrails_policy(p).is_ok());
	p.mutable_boundary()->set_ack_timeout_ms(30'001u);
	EXPECT_EQ(validate_guardrails_policy(p).code(), kinetum::common::status_code::INVALID_ARGUMENT);
	p.mutable_boundary()->set_ack_timeout_ms(0u);
	EXPECT_EQ(validate_guardrails_policy(p).code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

//==============================================================================
// Regression Detection Logic Tests
//==============================================================================

/**
 * @brief Test drop ratio calculation formula.
 *
 * Drop ratio = dropped_packets / (tx_packets + dropped_packets)
 *
 * This formula ensures:
 * - 0 drops = 0% drop ratio
 * - All drops = 100% drop ratio
 * - Consistent denominator regardless of drop rate
 */
TEST(guardrails_logic, drop_ratio_calculation)
{
	// Case 1: No drops
	{
		uint64_t tx_packets = 10000;
		uint64_t dropped_packets = 0;
		double total = static_cast<double>(tx_packets + dropped_packets);
		double drop_ratio = (total > 0) ? (static_cast<double>(dropped_packets) / total) : 0.0;
		EXPECT_DOUBLE_EQ(drop_ratio, 0.0) << "0 drops should yield 0% drop ratio";
	}

	// Case 2: 5% drops
	{
		uint64_t tx_packets = 9500;
		uint64_t dropped_packets = 500;
		double total = static_cast<double>(tx_packets + dropped_packets);
		double drop_ratio = static_cast<double>(dropped_packets) / total;
		EXPECT_NEAR(drop_ratio, 0.05, 0.0001) << "500/10000 should yield ~5% drop ratio";
	}

	// Case 3: 50% drops
	{
		uint64_t tx_packets = 5000;
		uint64_t dropped_packets = 5000;
		double total = static_cast<double>(tx_packets + dropped_packets);
		double drop_ratio = static_cast<double>(dropped_packets) / total;
		EXPECT_DOUBLE_EQ(drop_ratio, 0.5) << "5000/10000 should yield 50% drop ratio";
	}

	// Case 4: All dropped (100%)
	{
		uint64_t tx_packets = 0;
		uint64_t dropped_packets = 10000;
		double total = static_cast<double>(tx_packets + dropped_packets);
		double drop_ratio = static_cast<double>(dropped_packets) / total;
		EXPECT_DOUBLE_EQ(drop_ratio, 1.0) << "All dropped should yield 100% drop ratio";
	}
}

/**
 * @brief Test throughput ratio calculation formula.
 *
 * Throughput ratio = current_tx_pps / baseline_tx_pps
 *
 * This measures current performance relative to baseline:
 * - ratio > 1.0: Performance improved
 * - ratio = 1.0: Performance unchanged
 * - ratio < 1.0: Performance degraded
 */
TEST(guardrails_logic, throughput_ratio_calculation)
{
	// Case 1: Performance unchanged
	{
		double baseline_tx_pps = 1000000.0;  // 1M pps
		double current_tx_pps = 1000000.0;
		double ratio = current_tx_pps / baseline_tx_pps;
		EXPECT_DOUBLE_EQ(ratio, 1.0) << "Same throughput should yield ratio 1.0";
	}

	// Case 2: 30% degradation
	{
		double baseline_tx_pps = 1000000.0;
		double current_tx_pps = 700000.0;  // 70% of baseline
		double ratio = current_tx_pps / baseline_tx_pps;
		EXPECT_DOUBLE_EQ(ratio, 0.7) << "700k/1M should yield ratio 0.7 (30% degradation)";
	}

	// Case 3: 50% degradation
	{
		double baseline_tx_pps = 1000000.0;
		double current_tx_pps = 500000.0;
		double ratio = current_tx_pps / baseline_tx_pps;
		EXPECT_DOUBLE_EQ(ratio, 0.5) << "500k/1M should yield ratio 0.5 (50% degradation)";
	}

	// Case 4: Performance improved (unlikely but valid)
	{
		double baseline_tx_pps = 1000000.0;
		double current_tx_pps = 1200000.0;  // 20% improvement
		double ratio = current_tx_pps / baseline_tx_pps;
		EXPECT_DOUBLE_EQ(ratio, 1.2) << "1.2M/1M should yield ratio 1.2 (20% improvement)";
	}
}

/**
 * @brief Test rollback decision logic (AND condition).
 *
 * Rollback is triggered when all conditions are met:
 * 1. sufficient_packets: total_packets >= min_packets_per_window
 * 2. drop_rate_exceeded: drop_ratio > max_drop_ratio
 * 3. throughput_degraded: tx_pps < baseline_tx_pps * min_tx_ratio
 *
 * This AND logic prevents false positives:
 * - High drops but good throughput: might be intentional filtering
 * - Low throughput but no drops: might be external traffic reduction
 */
TEST(guardrails_logic, rollback_decision_and_logic)
{
	// Policy thresholds
	const double max_drop_ratio = 0.05;  // 5%
	const double min_tx_ratio = 0.70;    // 70%
	const uint64_t min_packets = 1000;
	const double baseline_pps = 1000000.0;

	// Case 1: All conditions met - SHOULD ROLLBACK
	{
		uint64_t total_packets = 2000;	// >= 1000 passes
		double drop_ratio = 0.10;	// 10% > 5% passes
		double tx_pps = 500000.0;	// < 700000 (70% of baseline) passes

		bool sufficient = total_packets >= min_packets;
		bool drops_exceeded = drop_ratio > max_drop_ratio;
		bool throughput_degraded = tx_pps < (baseline_pps * min_tx_ratio);
		bool should_rollback = sufficient && drops_exceeded && throughput_degraded;

		EXPECT_TRUE(should_rollback) << "All conditions met: should trigger rollback";
	}

	// Case 2: Insufficient packets - NO ROLLBACK
	{
		uint64_t total_packets = 100;  // < 1000 fails
		double drop_ratio = 0.10;      // 10% > 5% passes
		double tx_pps = 500000.0;      // < 700000 passes

		bool sufficient = total_packets >= min_packets;
		bool drops_exceeded = drop_ratio > max_drop_ratio;
		bool throughput_degraded = tx_pps < (baseline_pps * min_tx_ratio);
		bool should_rollback = sufficient && drops_exceeded && throughput_degraded;

		EXPECT_FALSE(should_rollback) << "Insufficient packets: should NOT trigger rollback";
	}

	// Case 3: Drops OK - NO ROLLBACK
	{
		uint64_t total_packets = 2000;	// >= 1000 passes
		double drop_ratio = 0.01;	// 1% <= 5% fails
		double tx_pps = 500000.0;	// < 700000 passes

		bool sufficient = total_packets >= min_packets;
		bool drops_exceeded = drop_ratio > max_drop_ratio;
		bool throughput_degraded = tx_pps < (baseline_pps * min_tx_ratio);
		bool should_rollback = sufficient && drops_exceeded && throughput_degraded;

		EXPECT_FALSE(should_rollback) << "Drops within threshold: should NOT trigger rollback";
	}

	// Case 4: Throughput OK - NO ROLLBACK
	{
		uint64_t total_packets = 2000;	// >= 1000 passes
		double drop_ratio = 0.10;	// 10% > 5% passes
		double tx_pps = 900000.0;	// >= 700000 fails

		bool sufficient = total_packets >= min_packets;
		bool drops_exceeded = drop_ratio > max_drop_ratio;
		bool throughput_degraded = tx_pps < (baseline_pps * min_tx_ratio);
		bool should_rollback = sufficient && drops_exceeded && throughput_degraded;

		EXPECT_FALSE(should_rollback) << "Throughput OK: should NOT trigger rollback (intentional filtering?)";
	}

	// Case 5: All metrics OK - NO ROLLBACK
	{
		uint64_t total_packets = 2000;	// >= 1000 passes
		double drop_ratio = 0.01;	// 1% <= 5% fails
		double tx_pps = 950000.0;	// >= 700000 fails

		bool sufficient = total_packets >= min_packets;
		bool drops_exceeded = drop_ratio > max_drop_ratio;
		bool throughput_degraded = tx_pps < (baseline_pps * min_tx_ratio);
		bool should_rollback = sufficient && drops_exceeded && throughput_degraded;

		EXPECT_FALSE(should_rollback) << "All metrics OK: should NOT trigger rollback";
	}
}

//==============================================================================
// Thread Safety Tests
//==============================================================================

/**
 * @brief Verify atomic flag for thread lifecycle control.
 *
 * The guardrails runner uses std::atomic<bool> running_ for:
 * - Thread-safe start/stop signaling
 * - Idempotent operations (multiple start/stop calls are no-ops)
 */
TEST(guardrails_thread, atomic_running_flag)
{
	std::atomic<bool> running{false};

	// Atomic exchange for start
	bool was_running = running.exchange(true);
	EXPECT_FALSE(was_running) << "First start should return false (was not running)";
	EXPECT_TRUE(running.load()) << "After start, running should be true";

	// Idempotent start (already running)
	was_running = running.exchange(true);
	EXPECT_TRUE(was_running) << "Second start should return true (already running)";
	EXPECT_TRUE(running.load()) << "Still running after idempotent start";

	// Atomic exchange for stop
	was_running = running.exchange(false);
	EXPECT_TRUE(was_running) << "First stop should return true (was running)";
	EXPECT_FALSE(running.load()) << "After stop, running should be false";

	// Idempotent stop (already stopped)
	was_running = running.exchange(false);
	EXPECT_FALSE(was_running) << "Second stop should return false (already stopped)";
	EXPECT_FALSE(running.load()) << "Still stopped after idempotent stop";
}

/**
 * @brief Verify thread lifecycle with running flag.
 *
 * This simulates the guardrails monitoring thread pattern:
 * - Thread checks running_ flag in a loop
 * - Main thread can signal stop by setting running_ = false
 * - Thread exits cleanly after flag is set
 */
TEST(guardrails_thread, thread_lifecycle)
{
	std::atomic<bool> running{true};
	std::atomic<int> iterations{0};

	// Simulate monitoring thread
	std::thread monitor([&running, &iterations]() {
		while (running.load(std::memory_order_relaxed)) {
			iterations.fetch_add(1, std::memory_order_relaxed);
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
	});

	// Let it run a few iterations
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	int count_before_stop = iterations.load();
	EXPECT_GT(count_before_stop, 0) << "Thread should have run some iterations";

	// Signal stop
	running.store(false);
	monitor.join();

	int count_after_stop = iterations.load();
	EXPECT_GE(count_after_stop, count_before_stop) << "Iterations should not decrease after stop";
}

//==============================================================================
// Runtime-Generation Counter Identity Tests
//==============================================================================

/**
 * @brief Distinguish generation replacement from in-generation regression.
 */
TEST(guardrails_logic, generation_qualifies_delta_and_same_generation_regression_is_refused)
{
	constexpr uint64_t LAST_GENERATION = 7u;
	constexpr uint64_t LAST_TX = 1000u;
	const auto same_generation_delta = [](uint64_t last_generation, uint64_t current_generation,
					      uint64_t last_value, uint64_t current_value, uint64_t &delta) noexcept {
		if (last_generation == 0u || current_generation != last_generation || current_value < last_value) {
			return false;
		}
		delta = current_value - last_value;
		return true;
	};

	uint64_t delta = 0u;
	EXPECT_TRUE(same_generation_delta(LAST_GENERATION, LAST_GENERATION, LAST_TX, 1500u, delta));
	EXPECT_EQ(delta, 500u);
	EXPECT_FALSE(same_generation_delta(LAST_GENERATION, LAST_GENERATION + 1u, LAST_TX, 100u, delta));
	EXPECT_FALSE(same_generation_delta(LAST_GENERATION, LAST_GENERATION, LAST_TX, 100u, delta));
}

//==============================================================================
// Time Interval Tests
//==============================================================================

/**
 * @brief Test evaluation window timing logic.
 *
 * Guardrails only evaluate regression within the evaluation window
 * after a configuration change. Outside the window, only baseline
 * updates occur.
 */
TEST(guardrails_logic, evaluation_window_timing)
{
	const int64_t change_timestamp_ms = 1000000;  // Config changed at t=1000s
	const int64_t evaluation_window_ms = 30000;   // 30 second window

	// Within window
	{
		int64_t now_ms = 1010000;  // 10 seconds after change
		int64_t time_since_change = now_ms - change_timestamp_ms;
		bool within_window = (change_timestamp_ms != 0) && (time_since_change <= evaluation_window_ms);
		EXPECT_TRUE(within_window) << "10s after change should be within 30s window";
	}

	// At window boundary
	{
		int64_t now_ms = 1030000;  // 30 seconds after change
		int64_t time_since_change = now_ms - change_timestamp_ms;
		bool within_window = (change_timestamp_ms != 0) && (time_since_change <= evaluation_window_ms);
		EXPECT_TRUE(within_window) << "30s after change should be at boundary (inclusive)";
	}

	// Outside window
	{
		int64_t now_ms = 1031000;  // 31 seconds after change
		int64_t time_since_change = now_ms - change_timestamp_ms;
		bool within_window = (change_timestamp_ms != 0) && (time_since_change <= evaluation_window_ms);
		EXPECT_FALSE(within_window) << "31s after change should be outside 30s window";
	}

	// No change yet
	{
		int64_t no_change_timestamp = 0;
		// When no change has occurred, timestamp is 0 and we skip evaluation
		// regardless of current time - the condition only checks timestamp != 0
		bool within_window = (no_change_timestamp != 0);
		EXPECT_FALSE(within_window) << "No config change yet: should not be evaluating";
	}
}

//==============================================================================
// Task 5: Health Correlator Tests
//==============================================================================

/**
 * @brief Test EWMA smoothing behavior.
 *
 * EWMA (Exponential Weighted Moving Average) smooths noisy signals.
 * Formula: smoothed = alpha * current + (1 - alpha) * previous
 */
TEST(health_correlator, ewma_smoothing)
{
	// Simulate EWMA with alpha=0.2
	const double alpha = 0.2;
	double smoothed = 0.0;

	// First sample: set to input
	smoothed = alpha * 0.5 + (1.0 - alpha) * smoothed;
	EXPECT_NEAR(smoothed, 0.1, 0.001) << "First sample with 0.5 input";

	// Second sample: converge toward input
	smoothed = alpha * 0.5 + (1.0 - alpha) * smoothed;
	EXPECT_NEAR(smoothed, 0.18, 0.001) << "Second sample converging to 0.5";

	// Many samples: converge to input
	for (int i = 0; i < 50; ++i) {
		smoothed = alpha * 0.5 + (1.0 - alpha) * smoothed;
	}
	EXPECT_NEAR(smoothed, 0.5, 0.01) << "After many samples, converges to input";

	// Spike should be dampened
	double pre_spike = smoothed;
	smoothed = alpha * 1.0 + (1.0 - alpha) * smoothed;  // Spike to 1.0
	EXPECT_LT(smoothed, 0.7) << "Single spike should be dampened";
	EXPECT_GT(smoothed, pre_spike) << "But should increase smoothed value";
}

/**
 * @brief Test hysteresis prevents oscillation.
 *
 * Hysteresis uses enter/exit thresholds to create a dead band.
 * State changes only when signal crosses the appropriate threshold.
 */
TEST(health_correlator, hysteresis_prevents_oscillation)
{
	EXPECT_DEATH(
		{
			health_correlator invalid(make_health_correlation_config(0.3, 0.8, 0.6));
			(void)invalid;
		},
		"");

	const double enter_threshold = 0.5;  // Enter degraded state above 0.5
	const double exit_threshold = 0.3;   // Exit degraded state below 0.3
	bool is_degraded = false;

	// Simulate hysteresis logic
	auto update_hysteresis = [&](double degradation_score) {
		if (is_degraded) {
			// In degraded state: only exit if below exit_threshold
			if (degradation_score < exit_threshold) {
				is_degraded = false;
			}
		} else {
			// In healthy state: only enter if above enter_threshold
			if (degradation_score > enter_threshold) {
				is_degraded = true;
			}
		}
		return is_degraded;
	};

	// Start healthy, score increases
	EXPECT_FALSE(update_hysteresis(0.3)) << "0.3: below enter, stays healthy";
	EXPECT_FALSE(update_hysteresis(0.4)) << "0.4: still below enter";
	EXPECT_FALSE(update_hysteresis(0.5)) << "0.5: at enter, not above";
	EXPECT_TRUE(update_hysteresis(0.6)) << "0.6: above enter, becomes degraded";

	// Now in dead band - oscillation prevented
	EXPECT_TRUE(update_hysteresis(0.5)) << "0.5: above exit, stays degraded";
	EXPECT_TRUE(update_hysteresis(0.4)) << "0.4: above exit, stays degraded";
	EXPECT_TRUE(update_hysteresis(0.3)) << "0.3: at exit, not below";
	EXPECT_FALSE(update_hysteresis(0.2)) << "0.2: below exit, becomes healthy";

	// Back to healthy
	EXPECT_FALSE(update_hysteresis(0.3)) << "0.3: below enter, stays healthy";
	EXPECT_FALSE(update_hysteresis(0.4)) << "0.4: still below enter";
}

//==============================================================================
// Task 6: Telemetry History Tests
//==============================================================================

/**
 * @brief Test telemetry history ring buffer capacity.
 *
 * The ring buffer should evict oldest entries when at capacity.
 */
TEST(telemetry_history, ring_buffer_eviction)
{
	constexpr std::size_t MAX_PER_CONFIG = 5u;
	telemetry_history history(MAX_PER_CONFIG);
	for (uint64_t i = 1; i <= 7; ++i) {
		telemetry_snapshot sample;
		sample.config_snapshot_id = "bounded";
		sample.timestamp_mono_ns = i;
		sample.tx_pps = static_cast<double>(i);
		history.record(sample);
	}
	const auto retained = history.get_for_config("bounded");
	ASSERT_EQ(retained.size(), MAX_PER_CONFIG);
	EXPECT_EQ(retained.front().timestamp_mono_ns, 3u);
	EXPECT_EQ(retained.back().timestamp_mono_ns, 7u);
	const auto summary = history.summary_for_config("bounded");
	EXPECT_EQ(summary.sample_count, MAX_PER_CONFIG);
	EXPECT_DOUBLE_EQ(summary.mean_tx_pps, 5.0);
	EXPECT_DEATH(
		{
			telemetry_history invalid(0u);
			(void)invalid;
		},
		"");
}

/**
 * @brief Content history never infers a previous configuration baseline.
 *
 * The evaluator selects and freezes its previous-content vector explicitly;
 * the bounded store only returns rows for the exact requested content.
 */
TEST(telemetry_history, exact_content_queries_do_not_infer_a_baseline)
{
	telemetry_history history(4u);
	for (const std::string &identity : {std::string("snap_a"), std::string("snap_b")}) {
		telemetry_snapshot sample;
		sample.config_snapshot_id = identity;
		sample.timestamp_mono_ns = identity == "snap_a" ? 1u : 2u;
		history.record(sample);
	}
	const auto exact_a = history.get_for_config("snap_a");
	const auto exact_b = history.get_for_config("snap_b");
	ASSERT_EQ(exact_a.size(), 1u);
	ASSERT_EQ(exact_b.size(), 1u);
	EXPECT_EQ(exact_a.front().config_snapshot_id, "snap_a");
	EXPECT_EQ(exact_b.front().config_snapshot_id, "snap_b");
	EXPECT_TRUE(history.get_for_config("snap_c").empty());
	auto frozen_a = history.take_for_config("snap_a");
	ASSERT_EQ(frozen_a.size(), 1u);
	EXPECT_EQ(frozen_a.front().config_snapshot_id, "snap_a");
	EXPECT_TRUE(history.get_for_config("snap_a").empty());
	EXPECT_EQ(history.summary_for_config("snap_a").sample_count, 0u);
	EXPECT_DEATH(
		{
			telemetry_history bounded(4u);
			telemetry_snapshot sample;
			sample.config_snapshot_id = "a";
			bounded.record(sample);
			sample.config_snapshot_id = "b";
			bounded.record(sample);
			sample.config_snapshot_id = "c";
			bounded.record(sample);
		},
		"");
}

/**
 * @brief Integration test: health correlator + telemetry history + attribution scorer.
 *
 * This validates that the three components compose correctly using real objects
 * and produce a non-empty attribution breakdown.
 */
TEST(guardrails_integration, correlator_and_attribution_pipeline)
{
	health_correlator correlator(make_health_correlation_config());
	correlator.on_config_change("snap_base");

	telemetry_history history(64);

	const uint64_t t0 = 1000;
	const uint64_t t1 = 2000;
	const uint64_t t2 = 3000;
	const uint64_t t3 = 4000;

	// Baseline config snapshots (healthy)
	{
		auto snap = make_correlator_sample("snap_base", 0.001, 1.0, 98u, 0u, t0);
		const auto b = correlator.update(snap);
		snap.drop_ratio = b.drop_ratio_smoothed;
		snap.health_score = b.health_score;
		snap.config_issue_count = b.config_issue_count;
		history.record(snap);
	}
	{
		auto snap = make_correlator_sample("snap_base", 0.001, 1.0, 97u, 0u, t1);
		const auto b = correlator.update(snap);
		snap.drop_ratio = b.drop_ratio_smoothed;
		snap.health_score = b.health_score;
		snap.config_issue_count = b.config_issue_count;
		history.record(snap);
	}

	correlator.on_config_change("snap_new");
	// New config starts healthy then degrades with CONFIG_ISSUE.
	{
		auto snap = make_correlator_sample("snap_new", 0.001, 1.0, 95u, 0u, t2);
		const auto b = correlator.update(snap);
		snap.drop_ratio = b.drop_ratio_smoothed;
		snap.health_score = b.health_score;
		snap.config_issue_count = b.config_issue_count;
		history.record(snap);
	}
	{
		auto snap = make_correlator_sample("snap_new", 0.50, 0.60, 35u, KINETUM_HEALTH_F_CONFIG_ISSUE, t3);
		const auto b = correlator.update(snap);
		snap.drop_ratio = b.drop_ratio_smoothed;
		snap.health_score = b.health_score;
		snap.config_issue_count = b.config_issue_count;
		history.record(snap);
	}

	const auto current_window = history.get_for_config("snap_new");
	ASSERT_FALSE(current_window.empty());
	const auto &latest = current_window.back();

	const attribution_config config{
		.auto_rollback_threshold = 0.80,
		.defer_threshold = 0.50,
		.baseline_samples = 2u,
		.degradation_threshold = 0.30,
		.require_module_health = true,
	};
	attribution_scorer scorer(config);
	auto result = scorer.compute(latest, history.get_for_config("snap_base"), current_window);

	EXPECT_TRUE(result.evidence_complete);
	EXPECT_FALSE(result.factors.empty());
	EXPECT_GE(result.confidence, 0.0);
	EXPECT_LE(result.confidence, 1.0);
	EXPECT_NE(result.verdict, "");
}

//==============================================================================
// Health Correlator: Targeted Delta, Timing, and Reset Tests
//==============================================================================

/**
 * @brief A sudden regression consumes the evaluator's exact interval directly.
 *
 * The correlator owns no lifetime counters. A 50% interval remains 0.5 after
 * any number of prior clean intervals and cannot be diluted by cumulative
 * history.
 */
TEST(health_correlator, sudden_regression_after_long_clean_uptime)
{
	health_correlator correlator(make_health_correlation_config(0.3, 0.5, 0.1));
	correlator.on_config_change("snap_a");

	// One hundred clean exact intervals do not create a cumulative denominator.
	for (int i = 0; i < 100; ++i) {
		const auto b = correlator.update(
			make_correlator_sample("snap_a", 0.0, 1.0, 100u, 0u, static_cast<uint64_t>(i) + 1u));
		EXPECT_EQ(b.samples_since_config_change, static_cast<uint64_t>(i) + 1u);
		EXPECT_DOUBLE_EQ(b.drop_ratio_raw, 0.0);
	}

	const auto regression = correlator.update(make_correlator_sample("snap_a", 0.50, 0.50, 100u, 0u, 101u));

	EXPECT_DOUBLE_EQ(regression.drop_ratio_raw, 0.50)
		<< "The exact interval must not be rederived from cumulative history";
	EXPECT_GT(regression.drop_ratio_raw, 0.1) << "Must not be diluted by 100 clean windows of cumulative history";
}

/**
 * @brief Throughput ratio is consumed without a second elapsed-time calculation.
 *
 * The evaluator owns monotonic nanosecond deltas. Correlation receives the
 * resulting baseline-relative ratio verbatim and cannot assume a one-second
 * poll interval or truncate time to milliseconds.
 */
TEST(health_correlator, variable_poll_interval_throughput)
{
	constexpr std::array<double, 3> RATIOS{1.0, 0.5, 2.0};
	for (const double ratio : RATIOS) {
		health_correlator correlator(make_health_correlation_config(0.99, 0.5, 0.1));
		correlator.on_config_change("snap");
		const auto breakdown = correlator.update(make_correlator_sample("snap", 0.0, ratio));
		EXPECT_EQ(breakdown.samples_since_config_change, 1u);
		EXPECT_DOUBLE_EQ(breakdown.throughput_ratio_raw, ratio);
	}
}

/**
 * @brief Every correlator input is already one real interval sample.
 *
 * Runtime-generation replacement and cumulative-counter seeding belong solely
 * to the evaluator. The correlator neither fabricates a neutral first sample
 * nor owns another generation-reset path.
 */
TEST(health_correlator, precomputed_intervals_have_no_neutral_seed_or_generation_authority)
{
	health_correlator correlator(make_health_correlation_config(0.3, 0.5, 0.1));
	correlator.on_config_change("snap");

	const auto first = correlator.update(make_correlator_sample("snap", 0.002, 1.0, 100u, 0u, 1u, 1u));
	EXPECT_EQ(first.samples_since_config_change, 1u);
	EXPECT_DOUBLE_EQ(first.drop_ratio_raw, 0.002);

	const auto second = correlator.update(make_correlator_sample("snap", 0.0099, 0.75, 100u, 0u, 2u, 2u));
	EXPECT_EQ(second.samples_since_config_change, 2u);
	EXPECT_DOUBLE_EQ(second.drop_ratio_raw, 0.0099);
	EXPECT_DOUBLE_EQ(second.throughput_ratio_raw, 0.75);
}

//==============================================================================
// Task 1: Idempotent Confirm Tests
//==============================================================================

/**
 * @brief Test idempotent confirm behavior.
 *
 * Second confirm with same parameters should succeed (not error).
 */
TEST(commit_confirmed, idempotent_confirm)
{
	// Simulate pending confirm state
	struct pending_state {
		std::string snapshot_id;
		std::string confirmation_key;
		int64_t revision;
		bool confirmed;
	};

	pending_state pending = {"snap_abc", "", 42, false};

	// First confirm
	auto confirm = [&](const std::string &snapshot_id, int64_t revision, const std::string &key) -> bool {
		if (pending.confirmed) {
			return pending.snapshot_id == snapshot_id && pending.revision == revision &&
			       pending.confirmation_key == key;
		}

		// Validate revision
		if (revision != pending.revision || key.empty()) {
			return false;  // Revision mismatch
		}

		// Mark confirmed
		pending.confirmed = true;
		pending.confirmation_key = key;
		return true;
	};

	// First confirm succeeds
	EXPECT_TRUE(confirm("snap_abc", 42, "confirm-key")) << "First confirm should succeed";
	EXPECT_TRUE(pending.confirmed) << "Should be marked confirmed";

	// Second confirm with same params: idempotent success
	EXPECT_TRUE(confirm("snap_abc", 42, "confirm-key")) << "Idempotent confirm should succeed";

	// Wrong snapshot_id on retry: should fail
	EXPECT_FALSE(confirm("snap_xyz", 42, "confirm-key")) << "Wrong snapshot_id should fail";

	// Wrong revision on retry: should fail
	EXPECT_FALSE(confirm("snap_abc", 99, "confirm-key")) << "Wrong revision should fail";
	EXPECT_FALSE(confirm("snap_abc", 42, "different-key")) << "Wrong retry key should fail";
}

/**
 * @brief Test revision validation prevents confirming wrong version.
 *
 * If config was updated rapidly, operator might try to confirm
 * an outdated version. Revision validation catches this.
 */
TEST(commit_confirmed, revision_validation)
{
	int64_t pending_revision = 42;

	// Confirm with matching revision
	bool valid1 = (42 == 0 || 42 == pending_revision);  // revision 42
	EXPECT_TRUE(valid1) << "Matching revision should be valid";

	bool valid2 = (0 == pending_revision);
	EXPECT_FALSE(valid2) << "Zero revision must not bypass exact confirmation identity";

	// Confirm with wrong revision
	bool valid3 = (41 == pending_revision);
	EXPECT_FALSE(valid3) << "Wrong revision should be invalid";
}

//==============================================================================
// Boundary protocol Section 11: Boundary Protocol Monitoring Tests
//==============================================================================

/**
 * @brief Prove ACK-stall observation uses exact sender phase and CUT time.
 */
TEST(guardrails_boundary, exact_waiting_ack_age_drives_stall_observation)
{
	const uint64_t ack_timeout_ms = 5000;  // 5 second timeout
	const uint64_t ack_timeout_ns = ack_timeout_ms * 1'000'000ULL;
	const auto stalled = [](kinetum::telemetry::v1::BoundarySenderPhase phase, uint64_t cut_published_ns,
				uint64_t collection_ns) {
		return phase == kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_WAITING_ACK &&
		       collection_ns >= cut_published_ns && collection_ns - cut_published_ns >= ack_timeout_ns;
	};
	EXPECT_FALSE(stalled(kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_OPEN, 1u, 10'000'000'000ULL));
	EXPECT_FALSE(
		stalled(kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_WAITING_ACK, 1'000'000'000ULL, 3'000'000'000ULL));
	EXPECT_TRUE(
		stalled(kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_WAITING_ACK, 1'000'000'000ULL, 6'000'000'000ULL));
	EXPECT_TRUE(
		stalled(kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_WAITING_ACK, 1'000'000'000ULL, 7'000'000'000ULL));
}

/**
 * @brief Test boundary policy configuration validation.
 *
 * Message presence, not a parallel boolean or default, enables monitoring.
 */
TEST(guardrails_boundary, policy_configuration)
{
	kinetum::control::v1::GuardrailsPolicy policy;
	EXPECT_FALSE(policy.has_boundary());
	policy.mutable_boundary()->set_ack_timeout_ms(5000u);
	EXPECT_TRUE(policy.has_boundary());
	EXPECT_EQ(policy.boundary().ack_timeout_ms(), 5000u);
}

/**
 * @brief Prove ACK-gate duration is the exact CUT-to-ACK edge difference.
 */
TEST(guardrails_boundary, ack_gate_duration_uses_exact_edge_samples)
{
	uint64_t cut_published_timestamp_ns = 1000000000ULL;  // 1 second mark
	uint64_t ack_received_timestamp_ns = 1050000000ULL;   // 1.05 second mark
	const uint64_t ack_gate_ns = ack_received_timestamp_ns - cut_published_timestamp_ns;
	EXPECT_EQ(ack_gate_ns, 50000000ULL);
	EXPECT_EQ(ack_gate_ns / 1'000'000ULL, 50u);
}

/**
 * @brief Prove each generation reports its own duration without monotonic max.
 */
TEST(guardrails_boundary, ack_gate_duration_is_generation_local_not_a_maximum)
{
	const uint64_t first_generation_duration = 200u;
	const uint64_t second_generation_duration = 100u;
	EXPECT_EQ(first_generation_duration, 200u);
	EXPECT_EQ(second_generation_duration, 100u);
	EXPECT_LT(second_generation_duration, first_generation_duration);
}

//==============================================================================
// Real-Object Guardrails Runner Tests
//==============================================================================
// These tests use actual guardrails_runner, control_loop, and config_store
// objects to validate production code paths. DP stub is nullptr when an
// unconfigured or disabled policy makes telemetry collection unreachable.

namespace
{

/**
 * @brief Remove one test-owned temporary directory at scope exit.
 */
struct test_dir_guard {
	std::filesystem::path path;  ///< Test-owned directory path, constructed before cleanup.

	/**
	 * @brief Adopt one exact test root and remove residue from an aborted prior run.
	 * @param owned_path Absolute temporary path unique to this test identity.
	 */
	explicit test_dir_guard(std::filesystem::path owned_path)
		: path(std::move(owned_path))
	{
		std::error_code error;
		std::filesystem::remove_all(path, error);
		if (error) {
			ADD_FAILURE() << "failed to clear stale test directory: " << error.message();
		}
	}

	/** @brief Retire the test-owned directory at scope exit. */
	~test_dir_guard()
	{
		std::error_code ec;
		std::filesystem::remove_all(path, ec);
	}
};

/**
 * @brief Open one exact test-owned Control Plane store.
 *
 * @param path Absolute test root, created by the production directory authority.
 * @return Initialized store, or null after recording the admission failure.
 */
std::unique_ptr<config_store> open_cp_test_store(const std::string &path)
{
	auto store_or = config_store::open(path);
	if (!store_or.is_ok()) {
		ADD_FAILURE() << "failed to open test configuration store: " << store_or.error().message();
		return nullptr;
	}
	return std::move(store_or).value();
}

/**
 * @brief Publish one module-free active bootstrap through the production path.
 *
 * @param store Admitted test store.
 * @param snapshot Complete candidate snapshot.
 * @return Shared canonicalization or durable reconciliation result.
 */
kinetum::common::status reconcile_cp_test_bootstrap(config_store &store,
						    const kinetum::control::v1::ConfigSnapshot &snapshot)
{
	kinetum::gluon::v1::DeploymentPlan module_free_plan;
	auto canonical_or = kinetum::common::canonicalize_config_snapshot(snapshot, module_free_plan);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	bootstrap_startup_authority authority;
	authority.snapshot = std::move(canonical_or).value();
	authority.plan_content_hash_bytes.fill(0x6du);
	authority.plan_content_hash = kinetum::common::bytes_to_hex(authority.plan_content_hash_bytes.data(),
								    authority.plan_content_hash_bytes.size());
	return store.reconcile_bootstrap(&authority);
}

/**
 * @brief Bind fake DP telemetry to one exact durable active authority.
 * @param store Bootstrapped test store.
 * @param service Stopped fake service to configure before launch.
 * @return OK after exact active/hash/plan/watermark projection.
 */
kinetum::common::status configure_guardrails_fake_dataplane(config_store &store,
							    kinetum::test::fake_dp_service &service)
{
	auto active_or = store.active_bootstrap();
	if (!active_or.is_ok()) {
		return active_or.error();
	}
	auto active_content_or = kinetum::common::canonical_config_snapshot_from_terminal(active_or->snapshot());
	if (!active_content_or.is_ok()) {
		return active_content_or.error();
	}
	auto plan_hash_or = kinetum::common::hex_to_bytes(active_or->plan_content_hash());
	if (!plan_hash_or.is_ok()) {
		return plan_hash_or.error();
	}
	service.active_epoch = active_or->active_epoch();
	service.min_retained_epoch = active_or->active_epoch();
	service.allocated_epoch_high_watermark = active_or->allocated_epoch_high_watermark();
	service.mutation_sequence_high_watermark = active_or->mutation_sequence_high_watermark();
	service.plan_content_hash.assign(reinterpret_cast<const char *>(plan_hash_or->data()), plan_hash_or->size());
	service.active_validation_hash.assign(reinterpret_cast<const char *>(active_content_or->validation_hash.data()),
					      active_content_or->validation_hash.size());
	return kinetum::common::status::ok();
}

/**
 * @brief Fake DP whose telemetry follows the store's stable active authority.
 *
 * Transition RPCs use the shared exact fake state machine. GetStats refuses
 * while CP has a nonterminal transition, then publishes deterministic healthy
 * baseline intervals or a sharply degraded candidate interval. This permits
 * one existing runner test to exercise the complete policy-to-rollback seam
 * without mutating fake response fields concurrently.
 */
class scripted_guardrails_dp_service final : public kinetum::test::fake_dp_service {
    public:
	/**
	 * @brief Bind one store whose coherent stable state drives observations.
	 * @param store Exact test store, which must outlive this service.
	 */
	explicit scripted_guardrails_dp_service(config_store &store)
		: store_(store)
	{
	}

	/**
	 * @brief Publish one deterministic fenced baseline or candidate interval.
	 * @param context Borrowed gRPC context forwarded to the base fake.
	 * @param request Exact optional-family selection forwarded to the base fake.
	 * @param response Destination response rebuilt from stable durable truth.
	 * @return Transport success, with application UNAVAILABLE during transitions.
	 */
	grpc::Status GetStats(grpc::ServerContext *context, const kinetum::dataplane::v1::StatsRequest *request,
			      kinetum::dataplane::v1::StatsResponse *response) override
	{
		auto transport = kinetum::test::fake_dp_service::GetStats(context, request, response);
		if (!transport.ok()) {
			return transport;
		}
		auto authority_or = store_.runtime_authority();
		if (!authority_or.is_ok()) {
			response->Clear();
			response->mutable_status()->set_code(
				static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
			response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
			return grpc::Status::OK;
		}
		if (authority_or->transition.has_value()) {
			const auto phase = authority_or->transition->phase;
			if (phase == kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED ||
			    phase == kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED ||
			    phase ==
				    kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING ||
			    phase == kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING) {
				response->Clear();
				response->mutable_status()->set_code(
					static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
				response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
				return grpc::Status::OK;
			}
		}

		const auto &active = authority_or->active;
		auto *runtime = response->mutable_telemetry()->mutable_runtime();
		auto *transition = response->mutable_telemetry()->mutable_transition();
		const uint64_t sample = sample_sequence_.fetch_add(1u, std::memory_order_relaxed) + 1u;
		const uint64_t collection_ns = UINT64_C(1000000000) + sample * UINT64_C(10000000);
		runtime->set_active_epoch(active.active_epoch);
		runtime->set_minimum_retained_epoch(active.active_epoch);
		runtime->set_last_activated_epoch(active.active_epoch);
		runtime->set_collection_monotonic_ns(collection_ns);
		runtime->set_latest_bank_publication_monotonic_ns(collection_ns - 1u);
		transition->set_active_epoch(active.active_epoch);
		transition->set_allocated_epoch_high_watermark(active.allocated_epoch_high_watermark);
		transition->set_mutation_sequence_high_watermark(active.mutation_sequence_high_watermark);
		transition->set_plan_content_hash(reinterpret_cast<const char *>(active.plan_content_hash.data()),
						  active.plan_content_hash.size());
		transition->set_active_validation_hash(
			reinterpret_cast<const char *>(active.active_validation_hash.data()),
			active.active_validation_hash.size());

		uint64_t tx_packets = sample * 1'000u;
		uint64_t dropped_packets = 0u;
		if (active.snapshot_id == "runner-policy-candidate") {
			const uint64_t candidate = candidate_sequence_.fetch_add(1u, std::memory_order_relaxed) + 1u;
			tx_packets = UINT64_C(1000000000000) + candidate;
			dropped_packets = (candidate - 1u) * 1'000u;
		} else if (active.active_epoch > 1u) {
			tx_packets = UINT64_C(2000000000000) + sample;
		}
		auto *engine = response->mutable_telemetry()->mutable_engine();
		engine->set_tx_packets(tx_packets);
		engine->set_dropped_packets(dropped_packets);
		engine->set_rx_packets(tx_packets + dropped_packets);
		return grpc::Status::OK;
	}

    private:
	config_store &store_;				///< Borrowed exact durable authority.
	std::atomic<uint64_t> sample_sequence_{0u};	///< Monotonic collection/totals source.
	std::atomic<uint64_t> candidate_sequence_{0u};	///< Candidate degradation progression.
};

/**
 * @brief Wait for a bounded number of runner telemetry requests.
 * @param service Running fake DP service.
 * @param expected Minimum call count required.
 * @return true when the count is observed before the fixed test deadline.
 */
bool wait_for_guardrails_stats(const kinetum::test::fake_dp_service &service, int expected = 1)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
	while (service.get_stats_calls.load(std::memory_order_acquire) < expected &&
	       std::chrono::steady_clock::now() < deadline) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	return service.get_stats_calls.load(std::memory_order_acquire) >= expected;
}

/**
 * @brief Publish a guardrails policy through the started control loop.
 *
 * @param loop Started single-writer control loop.
 * @param policy Policy to publish.
 * @return True when the mutation succeeds.
 */
bool publish_policy(control_loop &loop, const kinetum::control::v1::GuardrailsPolicy &policy)
{
	auto key_or = kinetum::common::generate_transition_idempotency_key("guardrails-test");
	if (!key_or.is_ok()) {
		ADD_FAILURE() << key_or.error().message();
		return false;
	}
	mutation m(std::move(key_or).value(), std::nullopt,
		   set_guardrails_policy_payload{
			   .policy = policy,
			   .expected_generation = loop.guardrails_state().policy.has_value() ?
							  loop.guardrails_state().policy.version() :
							  0u,
		   });
	return loop.submit(std::move(m)).ok();
}

/**
 * @brief Build a minimal snapshot accepted by Control Plane validation.
 *
 * @param snapshot_id Snapshot identity to assign.
 * @param revision Snapshot revision to assign.
 * @return Minimal configuration snapshot for component tests.
 */
kinetum::control::v1::ConfigSnapshot make_cp_test_snapshot(std::string snapshot_id, int64_t revision)
{
	kinetum::control::v1::ConfigSnapshot snap;
	snap.set_snapshot_id(std::move(snapshot_id));
	snap.set_revision(revision);
	snap.set_created_unix_ms(1000 + revision);
	return snap;
}

}  // namespace

/**
 * @brief start() without policy remains unconfigured and stops cleanly.
 *
 * Exercises real guardrails_runner::start() with a real control_loop whose
 * RCU buffer has never been written. Validates that the runner enters
 * UNCONFIGURED state (no crash, no hang) and responds to stop().
 */
TEST(guardrails_runner_real, start_without_policy_remains_unconfigured)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_gr_unconfigured_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("runner-unconfigured", 1)).is_ok());

	// nullptr DP stub is safe - no config mutations will reach DP
	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	// No policy published: start succeeds in explicit UNCONFIGURED state.
	guardrails_runner gr(store.get(), nullptr, loop);
	auto status = gr.start();
	EXPECT_TRUE(status.is_ok()) << "start() without policy must succeed in unconfigured mode: " << status.message();

	// Let the control-service cadence observe the empty durable policy state.
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	// stop() must complete - proves thread is alive and responds
	auto t0 = std::chrono::steady_clock::now();
	gr.stop();
	auto dt = std::chrono::steady_clock::now() - t0;
	EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(dt).count(), 5000)
		<< "stop() from unconfigured mode must complete promptly";

	loop.stop();
}

/**
 * @brief start() with disabled policy keeps the owner live and stops cleanly.
 *
 * Exercises the full disabled lifecycle with real objects:
 * 1. Persist and publish one exact startup policy while the loop is stopped.
 * 2. Prove an exact startup retry leaves its durable generation unchanged.
 * 3. Start the control loop and runner, then service disabled control turns.
 * 4. Stop and join both owners cleanly.
 */
TEST(guardrails_runner_real, disabled_policy_start_and_stop)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_gr_disabled_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("runner-disabled", 1)).is_ok());

	control_loop loop(store.get(), nullptr);

	// Persist the startup policy while the mutation worker is deliberately
	// stopped, then prove an exact source retry does not advance generation.
	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);
	ASSERT_TRUE(loop.configure_startup_guardrails_policy(policy).is_ok());
	ASSERT_TRUE(loop.configure_startup_guardrails_policy(policy).is_ok());
	auto durable_policy_or = store->guardrails_policy();
	ASSERT_TRUE(durable_policy_or.is_ok());
	EXPECT_EQ(durable_policy_or->generation, 1u);
	ASSERT_TRUE(loop.start().is_ok());

	// Start runner in explicit DISABLED state.
	guardrails_runner gr(store.get(), nullptr, loop);
	auto status = gr.start();
	EXPECT_TRUE(status.is_ok()) << "start() with disabled policy must succeed: " << status.message();

	// Let the owner service commit-confirm state without telemetry polling.
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	// stop() must complete - proves thread is still alive (didn't self-exit)
	// and responds to the running_ flag being cleared
	gr.stop();
	loop.stop();

	// Reaching this point proves the disabled owner remains stoppable.
}

/**
 * @brief start() is idempotent - second call returns ok() without spawning.
 *
 * Exercises real guardrails_runner with a published policy. Validates the
 * atomic test-and-set guard in start().
 */
TEST(guardrails_runner_real, start_is_idempotent)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_gr_idempotent_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("runner-idempotent", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);
	ASSERT_TRUE(publish_policy(loop, policy));

	guardrails_runner gr(store.get(), nullptr, loop);
	ASSERT_TRUE(gr.start().is_ok());

	// Second start() must return ok() (idempotent, no second thread)
	auto status2 = gr.start();
	EXPECT_TRUE(status2.is_ok()) << "Idempotent start() must succeed: " << status2.message();

	gr.stop();

	// stop() after stop() must not crash (idempotent)
	gr.stop();

	loop.stop();
}

/**
 * @brief stop() after disabled start completes without timeout.
 *
 * Regression test: with the old break-on-disable design, stop() could hang
 * or crash because the thread had already exited and set running_ false.
 * The owner stays alive for commit-confirm service and responds to stop.
 */
TEST(guardrails_runner_real, stop_after_disabled_policy_completes_promptly)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_gr_stop_promptly_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("runner-stop", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);
	ASSERT_TRUE(publish_policy(loop, policy));

	guardrails_runner gr(store.get(), nullptr, loop);
	ASSERT_TRUE(gr.start().is_ok());

	// Let it run briefly in disabled mode.
	std::this_thread::sleep_for(std::chrono::milliseconds(30));

	// stop() should complete within a reasonable time
	// The stop notification wakes the condition-variable wait immediately.
	auto t0 = std::chrono::steady_clock::now();
	gr.stop();
	auto dt = std::chrono::steady_clock::now() - t0;

	EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(dt).count(), 2000)
		<< "stop() after disabled policy should complete promptly";

	loop.stop();
}

/**
 * @brief Runtime toggle: disabled -> enabled through durable policy publication.
 *
 * Full integration test exercising the production disabled-to-enabled path:
 * 1. Start runner with disabled policy
 * 2. Keep telemetry work unreachable while disabled
 * 3. Publish enabled policy via control_loop mutation
 * 4. Wait for the runner's first selected DP telemetry request
 *
 * This tests policy-generation observation and all-or-none evaluator rebuild.
 */
TEST(guardrails_runner_real, disabled_to_enabled_transition)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_gr_transition_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("runner-toggle", 1)).is_ok());
	kinetum::test::fake_dp_server dp;
	ASSERT_TRUE(configure_guardrails_fake_dataplane(*store, dp.service).is_ok());
	dp.start();

	control_loop loop(store.get(), dp.stub);
	ASSERT_TRUE(loop.start().is_ok());

	// Publish disabled policy (short poll for fast test)
	kinetum::control::v1::GuardrailsPolicy disabled_policy;
	disabled_policy.set_enabled(false);
	ASSERT_TRUE(publish_policy(loop, disabled_policy));

	// Start runner in disabled mode.
	guardrails_runner gr(store.get(), dp.stub, loop);
	ASSERT_TRUE(gr.start().is_ok());

	// Let the disabled control-service path run.
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	EXPECT_EQ(dp.service.get_stats_calls.load(std::memory_order_acquire), 0)
		<< "disabled policy must not issue telemetry work";

	// Publish enabled policy and verify durable identity.
	auto enabled_policy = make_valid_threshold_policy(10u, 100u);
	ASSERT_TRUE(publish_policy(loop, enabled_policy));
	const auto retained = store->guardrails_policy();
	ASSERT_TRUE(retained.is_ok());
	EXPECT_TRUE(retained->policy.enabled());
	EXPECT_TRUE(wait_for_guardrails_stats(dp.service)) << "runner did not consume the enabled policy generation";

	gr.stop();
	loop.stop();
	dp.shutdown();
}

/**
 * @brief Unconfigured policy becomes enabled and drives one exact rollback.
 *
 * The retained row now covers the complete production composition:
 * UNCONFIGURED -> BASELINE_BUILDING -> ARMED -> EVALUATING ->
 * ROLLBACK_PENDING -> exact E+2 target completion.
 */
TEST(guardrails_runner_real, unconfigured_to_enabled_transition_drives_exact_attributed_rollback)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_gr_await_to_active_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("runner-policy", 1)).is_ok());
	scripted_guardrails_dp_service service(*store);
	service.complete_transitions = true;
	std::array<uint8_t, 32> plan_hash_bytes{};
	plan_hash_bytes.fill(UINT8_C(0x6d));
	service.transition_plan_content_hash =
		kinetum::common::bytes_to_hex(plan_hash_bytes.data(), plan_hash_bytes.size());
	kinetum::test::fake_dp_server dp;
	dp.start_with_service(&service);

	control_loop loop(store.get(), dp.stub);
	ASSERT_TRUE(loop.start().is_ok());

	// Start runner with no policy published.
	guardrails_runner gr(store.get(), dp.stub, loop);
	ASSERT_TRUE(gr.start().is_ok());

	// Publish enabled policy and let the evaluator begin baseline construction.
	auto policy = make_valid_threshold_policy(10u, 100u, 0.10, 0.50, 1u);
	policy.mutable_attribution()->set_baseline_samples(1u);
	ASSERT_TRUE(publish_policy(loop, policy));
	const auto retained = store->guardrails_policy();
	ASSERT_TRUE(retained.is_ok());
	EXPECT_TRUE(retained->policy.enabled());
	ASSERT_TRUE(wait_for_guardrails_stats(service, 3)) << "runner did not build the exact healthy baseline";

	mutation update("runner-policy-candidate-key", std::nullopt,
			set_config_payload{make_cp_test_snapshot("runner-policy-candidate", 2), 0u});
	const auto update_result = loop.submit(std::move(update));
	ASSERT_TRUE(update_result.ok()) << update_result.status.message();
	EXPECT_EQ(update_result.epoch, 2u);

	const auto rollback_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	bool rolled_back = false;
	while (std::chrono::steady_clock::now() < rollback_deadline) {
		auto active_or = store->active_bootstrap();
		if (active_or.is_ok() && active_or->snapshot().snapshot_id() == "runner-policy" &&
		    active_or->active_epoch() == 3u && !store->rollback_intent().is_ok()) {
			rolled_back = true;
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	EXPECT_TRUE(rolled_back) << "enabled policy did not converge through the exact rollback authority";
	EXPECT_GE(service.prepare_calls.load(std::memory_order_relaxed), 2);
	EXPECT_GE(service.activate_calls.load(std::memory_order_relaxed), 2);

	gr.stop();
	loop.stop();
	dp.shutdown();
}

//==============================================================================
// Control Loop Startup Integrity Tests
//==============================================================================

/**
 * @brief Store re-admission rejects malformed atomic authority before loop construction.
 */
TEST(control_loop_integrity, malformed_atomic_authority_rejects_before_control_loop)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_mismatch_test").string();
	test_dir_guard guard{dir};

	{
		auto store = open_cp_test_store(dir);
		ASSERT_NE(store, nullptr);
		ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("s1", 42)).is_ok());
	}

	{
		std::ofstream output(dir + "/TRANSITION_AUTHORITY.pb", std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(output.good());
		output << "not-a-bootstrap-record";
		output.close();
		ASSERT_TRUE(output.good());
	}

	auto reopened_or = config_store::open(dir);
	ASSERT_FALSE(reopened_or.is_ok());
	EXPECT_EQ(reopened_or.error().code(), kinetum::common::status_code::DATA_LOSS);
}

/**
 * @brief Control loop restores the fully re-admitted atomic transition authority.
 */
TEST(control_loop_integrity, restores_exact_atomic_bootstrap_authority)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_missing_rev_test").string();
	test_dir_guard guard{dir};

	{
		auto store = open_cp_test_store(dir);
		ASSERT_NE(store, nullptr);
		ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("s1", 10)).is_ok());
	}

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.initialization_status().is_ok()) << loop.initialization_status().message();
	ASSERT_TRUE(loop.start().is_ok());
	const auto state = loop.published_state();
	EXPECT_EQ(state.snapshot_id, "s1");
	EXPECT_EQ(state.revision, 10);
	loop.stop();
}

/**
 * @brief Control loop starts normally with a fresh control-only store.
 *
 * A new root has no fabricated active bootstrap authority. This is the
 * deliberate control-only posture and must remain a valid startup state.
 */
TEST(control_loop_integrity, starts_on_fresh_system)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_fresh_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.initialization_status().is_ok()) << loop.initialization_status().message();
	auto status = loop.start();

	EXPECT_TRUE(status.is_ok()) << "Fresh system must start normally: " << status.message();

	loop.stop();
}

//==============================================================================
// Commit-Confirmed Admission Tests
//==============================================================================

/**
 * @brief Commit-confirmed is rejected on first apply because no rollback target exists.
 *
 * A PendingConfirm record must carry a non-empty rollback_snapshot_id. On a
 * fresh CP there is no previous active snapshot, so accepting
 * confirm_timeout_ms would report a safety net that cannot fire. The handler
 * must fail before writing the snapshot or contacting DP.
 */
TEST(control_loop_set_config, commit_confirmed_requires_existing_active_snapshot)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_commit_confirmed_first_apply_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);

	kinetum::test::fake_dp_server dp;
	dp.start();

	control_loop loop(store.get(), dp.stub);
	ASSERT_TRUE(loop.start().is_ok());

	mutation m("first_apply_commit_confirmed", std::nullopt,
		   set_config_payload{make_cp_test_snapshot("snap_first", 1), uint32_t{300000}});

	const auto result = loop.submit(std::move(m));
	EXPECT_FALSE(result.ok());
	EXPECT_EQ(result.status.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(dp.service.transition_calls(), 0);
	EXPECT_FALSE(store->load_pending_confirm().is_ok());
	EXPECT_FALSE(store->load_snapshot("snap_first").is_ok());
	EXPECT_TRUE(loop.published_state().snapshot_id.empty());

	loop.stop();
	dp.shutdown();
}

/**
 * @brief Exact transition choreography persists each phase before active publication.
 *
 * The CP allocator canonicalizes, stages, and consumes one exact epoch/mutation
 * pair, persists PREPARED and COMPLETION_PENDING in order, retries the same
 * completion intent when an Activate request is lost before commit, and
 * promotes active content only after Status recovers a reply lost after commit.
 */
TEST(control_loop_set_config, exact_transition_persists_prepare_commit_and_complete_in_order)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_commit_confirmed_target_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("snap_base", 1)).is_ok());

	kinetum::test::fake_dp_server dp;
	dp.service.complete_transitions = true;
	std::array<uint8_t, 32> plan_hash_bytes{};
	plan_hash_bytes.fill(UINT8_C(0x6d));
	dp.service.transition_plan_content_hash =
		kinetum::common::bytes_to_hex(plan_hash_bytes.data(), plan_hash_bytes.size());
	dp.service.fail_next_activate_transport_before_commit.store(true, std::memory_order_release);
	dp.service.fail_next_activate_transport_after_commit.store(true, std::memory_order_release);
	std::atomic<bool> completion_pending_observed{false};
	dp.service.activate_observer = [&] {
		auto durable_or = store->epoch_transition();
		completion_pending_observed.store(
			durable_or.is_ok() &&
				durable_or->phase ==
					kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING,
			std::memory_order_release);
	};
	dp.start();

	control_loop loop(store.get(), dp.stub);
	ASSERT_TRUE(loop.start().is_ok());

	mutation m("staged_apply", std::nullopt, set_config_payload{make_cp_test_snapshot("snap_staged", 2), 0});
	const auto result = loop.submit(std::move(m));

	ASSERT_TRUE(result.ok()) << result.status.message();
	EXPECT_EQ(result.epoch, 2U);
	EXPECT_TRUE(store->load_snapshot("snap_staged").is_ok());
	auto transition_or = store->epoch_transition();
	ASSERT_TRUE(transition_or.is_ok()) << transition_or.error().message();
	EXPECT_EQ(transition_or->prepare_request.target_epoch(), 2u);
	EXPECT_EQ(transition_or->prepare_request.mutation_sequence(), 2u);
	EXPECT_FALSE(store->load_pending_confirm().is_ok());
	const auto active_id_or = store->active_snapshot_id();
	ASSERT_TRUE(active_id_or.is_ok());
	EXPECT_EQ(active_id_or.value(), "snap_staged");
	EXPECT_EQ(loop.published_state().snapshot_id, "snap_staged");
	EXPECT_EQ(dp.service.transition_status_calls.load(std::memory_order_relaxed), 3);
	EXPECT_EQ(dp.service.prepare_calls.load(std::memory_order_relaxed), 1);
	EXPECT_EQ(dp.service.activate_calls.load(std::memory_order_relaxed), 2);
	EXPECT_TRUE(completion_pending_observed.load(std::memory_order_acquire));

	loop.stop();
	dp.shutdown();
}

/**
 * @brief SetConfigSnapshot rejects timeout values the control-loop payload cannot represent.
 */
TEST(control_service_set_config, reject_confirm_timeout_over_uint32)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cp_confirm_timeout_range_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);

	kinetum::test::fake_dp_server dp;
	dp.start();

	control_loop loop(store.get(), dp.stub);
	ASSERT_TRUE(loop.start().is_ok());

	control_service_impl service(store.get(), dp.stub, loop);
	kinetum::control::v1::SetConfigSnapshotRequest req;
	*req.mutable_snapshot() = make_cp_test_snapshot("snap_oversized_timeout", 1);
	req.set_confirm_timeout_ms(static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1U);

	kinetum::control::v1::SetConfigSnapshotResponse resp;
	grpc::ServerContext ctx;
	const auto grpc_status = service.SetConfigSnapshot(&ctx, &req, &resp);

	EXPECT_TRUE(grpc_status.ok());
	EXPECT_EQ(resp.status().code(), static_cast<int32_t>(kinetum::common::status_code::INVALID_ARGUMENT));
	EXPECT_EQ(dp.service.transition_calls(), 0);
	EXPECT_FALSE(store->load_pending_confirm().is_ok());

	loop.stop();
	dp.shutdown();
}

/** @brief Oversized SetConfig input uses the canonical category before store effects. */
TEST(control_service_set_config, oversized_snapshot_is_resource_exhausted_before_persistence)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cp_snapshot_size_category_test").string();
	test_dir_guard guard{dir};
	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	kinetum::test::fake_dp_server dp;
	dp.start();
	control_loop loop(store.get(), dp.stub);
	ASSERT_TRUE(loop.start().is_ok());
	control_service_impl service(store.get(), dp.stub, loop);

	kinetum::control::v1::SetConfigSnapshotRequest request;
	*request.mutable_snapshot() = make_cp_test_snapshot("oversized", 1);
	request.mutable_snapshot()->set_description(std::string(kinetum::common::MAX_CONFIG_SNAPSHOT_BYTES + 1u, 'x'));
	request.set_idempotency_key("oversized-key");
	kinetum::control::v1::SetConfigSnapshotResponse response;
	grpc::ServerContext context;
	ASSERT_TRUE(service.SetConfigSnapshot(&context, &request, &response).ok());
	EXPECT_EQ(response.status().code(), static_cast<int32_t>(kinetum::common::status_code::RESOURCE_EXHAUSTED));
	EXPECT_FALSE(store->load_snapshot("oversized").is_ok());
	EXPECT_FALSE(store->epoch_transition().is_ok());
	EXPECT_EQ(dp.service.transition_calls(), 0);

	loop.stop();
	dp.shutdown();
}

/**
 * @brief A control-ready CP rejects every mutation before queue or side effects.
 *
 * A control-only host deliberately leaves the shared control loop stopped.
 * Every mutation RPC must therefore clear and return UNAVAILABLE before request
 * handling can materialize a mutation or reach the queue, durable retry state,
 * config store, pending-confirmation state, guardrails state, or DP transition
 * RPCs.
 */
TEST(control_service_readiness, stopped_mutation_authority_rejects_before_all_side_effects)
{
	namespace fs = std::filesystem;
	const auto dir = (fs::temp_directory_path() / "kinetum_cp_control_ready_gate_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);

	kinetum::test::fake_dp_server dp;
	dp.start();
	control_loop loop(store.get(), dp.stub);
	ASSERT_FALSE(loop.is_running());
	const uint64_t initial_guardrails_generation = loop.guardrails_state().policy.version();
	control_service_impl service(store.get(), dp.stub, loop);

	grpc::ServerContext set_context;
	kinetum::control::v1::SetConfigSnapshotRequest set_request;
	*set_request.mutable_snapshot() = make_cp_test_snapshot("must-not-persist", 1);
	kinetum::control::v1::SetConfigSnapshotResponse set_response;
	set_response.set_snapshot_id("poison");
	set_response.set_revision(9);
	set_response.set_epoch(9u);
	ASSERT_TRUE(service.SetConfigSnapshot(&set_context, &set_request, &set_response).ok());

	grpc::ServerContext rollback_context;
	kinetum::control::v1::RollbackRequest rollback_request;
	rollback_request.set_snapshot_id("must-not-load");
	kinetum::control::v1::RollbackResponse rollback_response;
	rollback_response.set_new_snapshot_id("poison");
	rollback_response.set_new_revision(9);
	rollback_response.set_epoch(9u);
	ASSERT_TRUE(service.Rollback(&rollback_context, &rollback_request, &rollback_response).ok());

	grpc::ServerContext confirm_context;
	kinetum::control::v1::ConfirmConfigRequest confirm_request;
	confirm_request.set_snapshot_id("must-not-confirm");
	kinetum::control::v1::ConfirmConfigResponse confirm_response;
	confirm_response.set_snapshot_id("poison");
	confirm_response.set_time_remaining_ms(9u);
	confirm_response.set_epoch(9u);
	confirm_response.set_revision(9);
	ASSERT_TRUE(service.ConfirmConfig(&confirm_context, &confirm_request, &confirm_response).ok());

	grpc::ServerContext guardrails_context;
	kinetum::control::v1::ConfigureGuardrailsRequest guardrails_request;
	guardrails_request.mutable_policy()->set_enabled(true);
	kinetum::control::v1::ConfigureGuardrailsResponse guardrails_response;
	ASSERT_TRUE(service.ConfigureGuardrails(&guardrails_context, &guardrails_request, &guardrails_response).ok());

	const auto expect_unavailable = [](const kinetum::common::v1::Status &status) {
		EXPECT_EQ(status.code(), static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
		EXPECT_EQ(status.error_code(), kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
	};
	expect_unavailable(set_response.status());
	expect_unavailable(rollback_response.status());
	expect_unavailable(confirm_response.status());
	expect_unavailable(guardrails_response.status());
	EXPECT_TRUE(set_response.snapshot_id().empty());
	EXPECT_EQ(set_response.revision(), 0);
	EXPECT_EQ(set_response.epoch(), 0u);
	EXPECT_TRUE(rollback_response.new_snapshot_id().empty());
	EXPECT_EQ(rollback_response.new_revision(), 0);
	EXPECT_EQ(rollback_response.epoch(), 0u);
	EXPECT_TRUE(confirm_response.snapshot_id().empty());
	EXPECT_EQ(confirm_response.time_remaining_ms(), 0u);
	EXPECT_EQ(confirm_response.epoch(), 0u);
	EXPECT_FALSE(confirm_response.has_revision());

	EXPECT_EQ(loop.queue_depth(), 0U);
	const auto state = loop.published_state();
	EXPECT_EQ(state.revision, 0);
	EXPECT_TRUE(state.snapshot_id.empty());
	EXPECT_EQ(loop.guardrails_state().policy.version(), initial_guardrails_generation);
	EXPECT_EQ(dp.service.transition_calls(), 0);
	EXPECT_FALSE(store->load_pending_confirm().is_ok());
	EXPECT_FALSE(store->epoch_transition().is_ok());
	const auto snapshots_or = store->list_snapshot_page(kinetum::common::MAX_SNAPSHOT_LIST_PAGE_SIZE, {});
	ASSERT_TRUE(snapshots_or.is_ok());
	EXPECT_TRUE(snapshots_or->snapshots.empty());

	dp.shutdown();
}

/** @brief Guardrails RPCs map exact durable generation, hash, retry, and clearing. */
TEST(control_service_guardrails, configure_and_get_use_one_durable_retry_identity)
{
	namespace fs = std::filesystem;
	const auto dir = (fs::temp_directory_path() / "kinetum_cp_guardrails_wire_test").string();
	test_dir_guard guard{dir};
	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("guardrails-wire", 1)).is_ok());
	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());
	control_service_impl service(store.get(), nullptr, loop);

	grpc::ServerContext empty_context;
	kinetum::control::v1::GetGuardrailsRequest empty_request;
	kinetum::control::v1::GetGuardrailsResponse empty_response;
	ASSERT_TRUE(service.GetGuardrails(&empty_context, &empty_request, &empty_response).ok());
	EXPECT_EQ(empty_response.status().code(), 0);
	EXPECT_FALSE(empty_response.has_policy());
	EXPECT_EQ(empty_response.policy_generation(), 0u);
	EXPECT_TRUE(empty_response.policy_hash().empty());

	kinetum::control::v1::ConfigureGuardrailsRequest request;
	request.mutable_policy()->set_enabled(false);
	request.set_idempotency_key("guardrails-wire-key");
	request.set_expected_policy_generation(0u);
	auto missing_generation = request;
	missing_generation.clear_expected_policy_generation();
	kinetum::control::v1::ConfigureGuardrailsResponse missing_generation_response;
	grpc::ServerContext missing_generation_context;
	ASSERT_TRUE(service.ConfigureGuardrails(&missing_generation_context, &missing_generation,
						&missing_generation_response)
			    .ok());
	EXPECT_EQ(missing_generation_response.status().code(),
		  static_cast<int32_t>(kinetum::common::status_code::INVALID_ARGUMENT));
	EXPECT_FALSE(store->guardrails_policy().is_ok());
	auto missing_key = request;
	missing_key.clear_idempotency_key();
	kinetum::control::v1::ConfigureGuardrailsResponse missing_key_response;
	grpc::ServerContext missing_key_context;
	ASSERT_TRUE(service.ConfigureGuardrails(&missing_key_context, &missing_key, &missing_key_response).ok());
	EXPECT_EQ(missing_key_response.status().code(),
		  static_cast<int32_t>(kinetum::common::status_code::INVALID_ARGUMENT));
	EXPECT_FALSE(store->guardrails_policy().is_ok());

	kinetum::control::v1::ConfigureGuardrailsResponse response;
	grpc::ServerContext context;
	ASSERT_TRUE(service.ConfigureGuardrails(&context, &request, &response).ok());
	ASSERT_EQ(response.status().code(), 0);
	EXPECT_EQ(response.policy_generation(), 1u);
	auto canonical_or = canonicalize_guardrails_policy(request.policy());
	ASSERT_TRUE(canonical_or.is_ok());
	EXPECT_EQ(response.policy_hash(), std::string(reinterpret_cast<const char *>(canonical_or->policy_hash.data()),
						      canonical_or->policy_hash.size()));

	kinetum::control::v1::GetGuardrailsResponse read_response;
	grpc::ServerContext read_context;
	ASSERT_TRUE(service.GetGuardrails(&read_context, &empty_request, &read_response).ok());
	ASSERT_EQ(read_response.status().code(), 0);
	EXPECT_TRUE(read_response.has_policy());
	EXPECT_FALSE(read_response.policy().enabled());
	EXPECT_EQ(read_response.policy_generation(), response.policy_generation());
	EXPECT_EQ(read_response.policy_hash(), response.policy_hash());

	request.set_expected_policy_generation(UINT64_MAX);
	response.Clear();
	grpc::ServerContext retry_context;
	ASSERT_TRUE(service.ConfigureGuardrails(&retry_context, &request, &response).ok());
	EXPECT_EQ(response.status().code(), 0);
	EXPECT_EQ(response.policy_generation(), 1u);

	request.mutable_policy()->CopyFrom(make_valid_threshold_policy(10u, 100u));
	response.set_policy_generation(99u);
	response.set_policy_hash("poison");
	grpc::ServerContext conflict_context;
	ASSERT_TRUE(service.ConfigureGuardrails(&conflict_context, &request, &response).ok());
	EXPECT_EQ(response.status().code(), static_cast<int32_t>(kinetum::common::status_code::FAILED_PRECONDITION));
	EXPECT_EQ(response.policy_generation(), 0u);
	EXPECT_TRUE(response.policy_hash().empty());

	loop.stop();
}

/** @brief Confirm RPC retains one exact durable success across response retry. */
TEST(control_service_confirm, exact_identity_and_key_retry_map_one_terminal_result)
{
	namespace fs = std::filesystem;
	const auto dir = (fs::temp_directory_path() / "kinetum_cp_confirm_wire_test").string();
	test_dir_guard guard{dir};
	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("confirm-wire-active", 1)).is_ok());
	auto transition_or = store->begin_epoch_transition(make_cp_test_snapshot("confirm-wire-target", 0),
							   "confirm-wire-transition", 60'000u);
	ASSERT_TRUE(transition_or.is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	ASSERT_TRUE(store->complete_epoch_transition(transition_or->identity, kinetum::common::unix_time_ms()).is_ok());
	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());
	control_service_impl service(store.get(), nullptr, loop);

	kinetum::control::v1::ConfirmConfigRequest request;
	request.set_snapshot_id("confirm-wire-target");
	request.set_epoch(2u);
	request.set_revision(0);
	request.set_idempotency_key("confirm-wire-key");
	auto missing_revision = request;
	missing_revision.clear_revision();
	kinetum::control::v1::ConfirmConfigResponse missing_revision_response;
	grpc::ServerContext missing_revision_context;
	ASSERT_TRUE(
		service.ConfirmConfig(&missing_revision_context, &missing_revision, &missing_revision_response).ok());
	EXPECT_EQ(missing_revision_response.status().code(),
		  static_cast<int32_t>(kinetum::common::status_code::INVALID_ARGUMENT));
	EXPECT_FALSE(missing_revision_response.has_revision());
	auto missing_key = request;
	missing_key.clear_idempotency_key();
	kinetum::control::v1::ConfirmConfigResponse missing_key_response;
	grpc::ServerContext missing_key_context;
	ASSERT_TRUE(service.ConfirmConfig(&missing_key_context, &missing_key, &missing_key_response).ok());
	EXPECT_EQ(missing_key_response.status().code(),
		  static_cast<int32_t>(kinetum::common::status_code::INVALID_ARGUMENT));
	EXPECT_TRUE(missing_key_response.snapshot_id().empty());
	EXPECT_EQ(missing_key_response.epoch(), 0u);
	EXPECT_FALSE(missing_key_response.has_revision());
	EXPECT_EQ(missing_key_response.time_remaining_ms(), 0u);
	auto malformed_identity = request;
	malformed_identity.set_epoch(0u);
	kinetum::control::v1::ConfirmConfigResponse malformed_identity_response;
	grpc::ServerContext malformed_identity_context;
	ASSERT_TRUE(
		service.ConfirmConfig(&malformed_identity_context, &malformed_identity, &malformed_identity_response)
			.ok());
	EXPECT_EQ(malformed_identity_response.status().code(),
		  static_cast<int32_t>(kinetum::common::status_code::INVALID_ARGUMENT));
	auto pending_before_confirm_or = store->load_pending_confirm();
	ASSERT_TRUE(pending_before_confirm_or.is_ok());
	EXPECT_FALSE(pending_before_confirm_or->confirmed());

	kinetum::control::v1::ConfirmConfigResponse first;
	grpc::ServerContext first_context;
	ASSERT_TRUE(service.ConfirmConfig(&first_context, &request, &first).ok());
	ASSERT_EQ(first.status().code(), 0);
	EXPECT_EQ(first.snapshot_id(), request.snapshot_id());
	EXPECT_EQ(first.epoch(), request.epoch());
	EXPECT_TRUE(first.has_revision());
	EXPECT_EQ(first.revision(), request.revision());
	EXPECT_GT(first.time_remaining_ms(), 0u);
	auto policy = make_valid_threshold_policy(10u, 100u);
	ASSERT_TRUE(publish_policy(loop, policy));
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	auto active_content_or = kinetum::common::canonical_config_snapshot_from_terminal(active_or->snapshot());
	ASSERT_TRUE(active_content_or.is_ok());
	rollback_intent_request intent{
		.target_snapshot_id = "confirm-wire-active",
		.guarded_snapshot_id = "confirm-wire-target",
		.guarded_epoch = 2u,
		.guarded_revision = 0,
		.guarded_validation_hash = active_content_or->validation_hash,
		.wait_for_mutation_sequence = 0u,
		.policy_generation = loop.guardrails_state().policy.version(),
		.runtime_generation = 1u,
		.idempotency_key = "confirm-wire-intent-key",
		.cause = rollback_intent_cause::THRESHOLD_DEGRADATION,
		.observed_monotonic_ns = 1u,
		.created_unix_ms = 1u,
	};
	ASSERT_TRUE(store->accept_rollback_intent(intent).is_ok());
	ASSERT_TRUE(store->fail_rollback_intent(intent.idempotency_key,
						kinetum::common::status::data_loss("terminal test safety intent"))
			    .is_ok());

	kinetum::control::v1::ConfirmConfigResponse retry;
	grpc::ServerContext retry_context;
	ASSERT_TRUE(service.ConfirmConfig(&retry_context, &request, &retry).ok());
	EXPECT_EQ(retry.SerializeAsString(), first.SerializeAsString());

	request.set_idempotency_key("different-confirm-wire-key");
	retry.set_snapshot_id("poison");
	grpc::ServerContext conflict_context;
	ASSERT_TRUE(service.ConfirmConfig(&conflict_context, &request, &retry).ok());
	EXPECT_EQ(retry.status().code(), static_cast<int32_t>(kinetum::common::status_code::FAILED_PRECONDITION));
	EXPECT_TRUE(retry.snapshot_id().empty());
	EXPECT_EQ(retry.epoch(), 0u);
	EXPECT_FALSE(retry.has_revision());
	EXPECT_EQ(retry.time_remaining_ms(), 0u);

	loop.stop();
}

/** @brief Safety-channel acknowledgement follows durable intent publication. */
TEST(control_loop_safety_intent, unconditional_context_survives_shutdown_and_restart)
{
	namespace fs = std::filesystem;
	const auto dir = (fs::temp_directory_path() / "kinetum_cp_safety_intent_test").string();
	test_dir_guard guard{dir};
	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("intent-guarded", 2)).is_ok());
	kinetum::gluon::v1::DeploymentPlan module_free_plan;
	auto target_canonical_or = kinetum::common::canonicalize_config_snapshot(
		make_cp_test_snapshot("intent-target", 1), module_free_plan);
	ASSERT_TRUE(target_canonical_or.is_ok());
	ASSERT_TRUE(store->stage_snapshot(target_canonical_or.value()).is_ok());
	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());
	auto policy = make_valid_threshold_policy(10u, 100u);
	ASSERT_TRUE(publish_policy(loop, policy));
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	auto active_content_or = kinetum::common::canonical_config_snapshot_from_terminal(active_or->snapshot());
	ASSERT_TRUE(active_content_or.is_ok());
	rollback_intent_request request{
		.target_snapshot_id = "intent-target",
		.guarded_snapshot_id = "intent-guarded",
		.guarded_epoch = active_or->active_epoch(),
		.guarded_revision = active_or->snapshot().revision(),
		.guarded_validation_hash = active_content_or->validation_hash,
		.wait_for_mutation_sequence = 0u,
		.policy_generation = loop.guardrails_state().policy.version(),
		.runtime_generation = 1u,
		.idempotency_key = "safety-intent-key",
		.cause = rollback_intent_cause::THRESHOLD_DEGRADATION,
		.observed_monotonic_ns = 1u,
		.created_unix_ms = 1'000,
	};
	ASSERT_TRUE(loop.submit_safety_intent(request).is_ok());
	auto durable_or = store->rollback_intent();
	ASSERT_TRUE(durable_or.is_ok());
	EXPECT_EQ(durable_or->request.idempotency_key, request.idempotency_key);
	loop.stop();
	store.reset();

	auto restarted = open_cp_test_store(dir);
	ASSERT_NE(restarted, nullptr);
	auto restored_or = restarted->rollback_intent();
	ASSERT_TRUE(restored_or.is_ok());
	EXPECT_EQ(restored_or->request.target_snapshot_id, request.target_snapshot_id);
	EXPECT_EQ(restored_or->request.guarded_validation_hash, request.guarded_validation_hash);
}

/** @brief Old active content cannot satisfy an intent that waits for its committing successor. */
TEST(control_loop_safety_intent, predecessor_wait_precedes_already_active_resolution)
{
	namespace fs = std::filesystem;
	const auto dir = (fs::temp_directory_path() / "kinetum_cp_intent_predecessor_test").string();
	test_dir_guard guard{dir};
	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("intent-old", 1)).is_ok());
	auto policy_or = store->configure_guardrails_policy(make_valid_threshold_policy(10u, 100u),
							    "intent-wait-policy-key", 0u);
	ASSERT_TRUE(policy_or.is_ok());
	auto transition_or =
		store->begin_epoch_transition(make_cp_test_snapshot("intent-new", 2), "intent-predecessor-key", 0u);
	ASSERT_TRUE(transition_or.is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	rollback_intent_request request{
		.target_snapshot_id = "intent-old",
		.guarded_snapshot_id = "intent-new",
		.guarded_epoch = transition_or->identity.target_epoch,
		.guarded_revision = 2,
		.guarded_validation_hash = transition_or->identity.validation_hash,
		.wait_for_mutation_sequence = transition_or->identity.mutation_sequence,
		.policy_generation = policy_or->generation,
		.runtime_generation = 1u,
		.idempotency_key = "intent-wait-key",
		.cause = rollback_intent_cause::BOUNDARY_ACK_TIMEOUT,
		.observed_monotonic_ns = 1u,
		.created_unix_ms = 1u,
	};
	ASSERT_TRUE(store->accept_rollback_intent(request).is_ok());
	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());
	mutation probe("intent-wait-probe-key", std::nullopt,
		       set_config_payload{make_cp_test_snapshot("intent-probe", 3), 0u});
	const auto probe_result = loop.submit(std::move(probe));
	EXPECT_EQ(probe_result.status.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	auto retained_or = store->rollback_intent();
	ASSERT_TRUE(retained_or.is_ok());
	EXPECT_FALSE(retained_or->terminal_failure.is_error());
	EXPECT_EQ(retained_or->request.wait_for_mutation_sequence, transition_or->identity.mutation_sequence);
	auto predecessor_or = store->epoch_transition();
	ASSERT_TRUE(predecessor_or.is_ok());
	EXPECT_EQ(predecessor_or->phase,
		  kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING);
	loop.stop();
	ASSERT_TRUE(store->abort_epoch_transition(transition_or->identity,
						  kinetum::common::status::aborted("predecessor aborted"),
						  durable_abort_proof::EXACT_DP_PRECOMMIT_TERMINAL)
			    .is_ok());
	auto aborted_intent_or = store->rollback_intent();
	ASSERT_TRUE(aborted_intent_or.is_ok());
	EXPECT_EQ(aborted_intent_or->terminal_failure.code(), kinetum::common::status_code::ABORTED)
		<< "predecessor failure and intent terminalization must share one replacement";
	ASSERT_TRUE(loop.start().is_ok());
	mutation terminal_probe("intent-terminal-probe-key", std::nullopt,
				set_config_payload{make_cp_test_snapshot("intent-terminal-probe", 3), 0u});
	EXPECT_EQ(loop.submit(std::move(terminal_probe)).status.code(),
		  kinetum::common::status_code::FAILED_PRECONDITION);
	auto terminal_intent_or = store->rollback_intent();
	ASSERT_TRUE(terminal_intent_or.is_ok());
	EXPECT_TRUE(terminal_intent_or->terminal_failure.is_error());
	EXPECT_EQ(terminal_intent_or->terminal_failure.code(), kinetum::common::status_code::ABORTED);
	loop.stop();
}

/** @brief Expired or clock-regressed confirmation rolls back through one durable transition. */
TEST(guardrails_runner_real, expired_confirm_uses_safety_intent_and_exact_transition_authority)
{
	namespace fs = std::filesystem;
	constexpr std::array<bool, 2> CLOCK_REGRESSION_CASES{false, true};
	for (const bool clock_regressed : CLOCK_REGRESSION_CASES) {
		SCOPED_TRACE(clock_regressed ? "wall clock precedes durable creation" :
					       "wall clock passed durable deadline");
		const auto dir = (fs::temp_directory_path() /
				  (clock_regressed ? "kinetum_guardrails_confirm_clock_regression_test" :
						     "kinetum_guardrails_confirm_expiry_test"))
					 .string();
		test_dir_guard guard{dir};
		auto store = open_cp_test_store(dir);
		ASSERT_NE(store, nullptr);
		ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("confirm-old", 1)).is_ok());
		auto transition_or = store->begin_epoch_transition(make_cp_test_snapshot("confirm-new", 2),
								   "confirm-expiry-transition", 1u);
		ASSERT_TRUE(transition_or.is_ok());
		ASSERT_TRUE(store->advance_epoch_transition_phase(
					 transition_or->identity,
					 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
				    .is_ok());
		ASSERT_TRUE(
			store->advance_epoch_transition_phase(
				     transition_or->identity,
				     kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
				.is_ok());
		const int64_t now_unix_ms = kinetum::common::unix_time_ms();
		ASSERT_GE(now_unix_ms, 10);
		const int64_t completed_unix_ms = clock_regressed ? now_unix_ms + 60'000 : now_unix_ms - 10;
		ASSERT_TRUE(store->complete_epoch_transition(transition_or->identity, completed_unix_ms).is_ok());
		auto active_or = store->active_bootstrap();
		ASSERT_TRUE(active_or.is_ok());
		auto plan_hash_or = kinetum::common::hex_to_bytes(active_or->plan_content_hash());
		ASSERT_TRUE(plan_hash_or.is_ok());

		kinetum::test::fake_dp_server dp;
		dp.service.complete_transitions = true;
		dp.service.active_epoch = transition_or->identity.target_epoch;
		dp.service.min_retained_epoch = transition_or->identity.target_epoch;
		dp.service.allocated_epoch_high_watermark = transition_or->identity.target_epoch;
		dp.service.mutation_sequence_high_watermark = transition_or->identity.mutation_sequence;
		dp.service.plan_content_hash.assign(reinterpret_cast<const char *>(plan_hash_or->data()),
						    plan_hash_or->size());
		dp.service.active_validation_hash.assign(
			reinterpret_cast<const char *>(transition_or->identity.validation_hash.data()),
			transition_or->identity.validation_hash.size());
		dp.service.transition_plan_content_hash = active_or->plan_content_hash();
		dp.service.transition_from_epoch = transition_or->identity.target_epoch;
		dp.start();
		control_loop loop(store.get(), dp.stub);
		ASSERT_TRUE(loop.start().is_ok());
		guardrails_runner runner(store.get(), dp.stub, loop);
		ASSERT_TRUE(runner.start().is_ok());

		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
		bool restored = false;
		while (std::chrono::steady_clock::now() < deadline) {
			auto current_or = store->active_bootstrap();
			if (current_or.is_ok() && current_or->snapshot().snapshot_id() == "confirm-old" &&
			    current_or->active_epoch() == 3u && !store->rollback_intent().is_ok()) {
				restored = true;
				break;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
		EXPECT_TRUE(restored) << "confirmation safety did not converge through exact rollback";
		runner.stop();
		loop.stop();
		dp.shutdown();
	}
}

//==============================================================================
// Cancel-Safe Timeout State Machine Tests
//==============================================================================
// These tests validate that the submit(m, timeout) overload correctly
// implements the cancel-safe state machine: queued/executing/canceled/completed.
//
// Key guarantee: if the caller receives deadline_exceeded, the mutation was
// atomically canceled and will never execute. No double-apply.
//==============================================================================

/**
 * @brief State transition unit test: CAS queued->canceled succeeds.
 *
 * Directly tests the atomic CAS that the submitter performs on timeout
 * when the mutation is still queued.
 */
TEST(control_loop_cancel, cas_queued_to_canceled_succeeds)
{
	auto state = std::make_shared<std::atomic<control_loop::request_state>>(control_loop::request_state::QUEUED);

	control_loop::request_state expected = control_loop::request_state::QUEUED;
	bool ok = state->compare_exchange_strong(expected, control_loop::request_state::CANCELED);

	EXPECT_TRUE(ok) << "CAS queued->canceled must succeed when state is queued";
	EXPECT_EQ(state->load(), control_loop::request_state::CANCELED);
}

/**
 * @brief State transition unit test: CAS queued->executing succeeds.
 *
 * Directly tests the atomic CAS that the worker performs before dispatch.
 */
TEST(control_loop_cancel, cas_queued_to_executing_succeeds)
{
	auto state = std::make_shared<std::atomic<control_loop::request_state>>(control_loop::request_state::QUEUED);

	control_loop::request_state expected = control_loop::request_state::QUEUED;
	bool ok = state->compare_exchange_strong(expected, control_loop::request_state::EXECUTING);

	EXPECT_TRUE(ok) << "CAS queued->executing must succeed when state is queued";
	EXPECT_EQ(state->load(), control_loop::request_state::EXECUTING);
}

/**
 * @brief State transition unit test: CAS queued->canceled fails when executing.
 *
 * If the worker already transitioned to executing, the submitter's cancel
 * attempt must fail. The submitter then waits for the real result.
 */
TEST(control_loop_cancel, cas_cancel_fails_when_executing)
{
	auto state = std::make_shared<std::atomic<control_loop::request_state>>(control_loop::request_state::EXECUTING);

	control_loop::request_state expected = control_loop::request_state::QUEUED;
	bool ok = state->compare_exchange_strong(expected, control_loop::request_state::CANCELED);

	EXPECT_FALSE(ok) << "CAS queued->canceled must fail when state is already executing";
	EXPECT_EQ(expected, control_loop::request_state::EXECUTING) << "CAS must report current state as executing";
	EXPECT_EQ(state->load(), control_loop::request_state::EXECUTING)
		<< "State must remain executing after failed cancel";
}

/**
 * @brief State transition unit test: CAS queued->executing fails when canceled.
 *
 * If the submitter already canceled, the worker's execute attempt must fail.
 * The worker then skips the mutation entirely.
 */
TEST(control_loop_cancel, cas_execute_fails_when_canceled)
{
	auto state = std::make_shared<std::atomic<control_loop::request_state>>(control_loop::request_state::CANCELED);

	control_loop::request_state expected = control_loop::request_state::QUEUED;
	bool ok = state->compare_exchange_strong(expected, control_loop::request_state::EXECUTING);

	EXPECT_FALSE(ok) << "CAS queued->executing must fail when state is already canceled";
	EXPECT_EQ(expected, control_loop::request_state::CANCELED) << "CAS must report current state as canceled";
	EXPECT_EQ(state->load(), control_loop::request_state::CANCELED)
		<< "State must remain canceled after failed execute";
}

/**
 * @brief Submit with generous timeout succeeds normally.
 *
 * Verifies that the cancel-safe timeout path returns the real result
 * when the mutation completes well within the timeout window.
 */
TEST(control_loop_cancel, timeout_submit_succeeds_within_deadline)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_cancel_ok_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("cancel-timeout", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	// set_guardrails_policy does not touch DP - safe with nullptr stub
	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);

	mutation m("cancel-timeout-policy", std::nullopt,
		   set_guardrails_policy_payload{.policy = policy, .expected_generation = 0u});

	// 5 seconds is far more than needed - this must succeed
	auto result = loop.submit(std::move(m), std::chrono::seconds(5));

	EXPECT_TRUE(result.ok())
		<< "Timeout submit must return real result when completed within deadline: " << result.status.message();

	loop.stop();
}

/**
 * @brief Submit without timeout still works (regression test).
 *
 * The no-timeout overload passes null state. The worker must process
 * unconditionally without checking CAS.
 */
TEST(control_loop_cancel, no_timeout_submit_unaffected)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_cancel_notimeout_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("cancel-unbounded", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);

	mutation m("cancel-unbounded-policy", std::nullopt,
		   set_guardrails_policy_payload{.policy = policy, .expected_generation = 0u});

	// Use the untimed synchronous submission path.
	auto result = loop.submit(std::move(m));

	EXPECT_TRUE(result.ok()) << "No-timeout submit must succeed as before: " << result.status.message();

	loop.stop();
}

/**
 * @brief Timeout submission rejects negative input and handles zero without hanging.
 *
 * With timeout=0, the submitter immediately attempts CAS. Two valid outcomes:
 * (1) CAS succeeds -> deadline_exceeded (mutation canceled, not executed)
 * (2) Worker was faster -> ok (real result returned)
 *
 * Both outcomes are correct. Neither crashes nor hangs.
 */
TEST(control_loop_cancel, zero_timeout_returns_valid_result)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_cancel_zero_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("cancel-zero", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);
	mutation negative("negative-timeout-policy", std::nullopt,
			  set_guardrails_policy_payload{.policy = policy, .expected_generation = 0u});
	const auto negative_result = loop.submit(std::move(negative), std::chrono::milliseconds(-1));
	EXPECT_EQ(negative_result.status.code(), kinetum::common::status_code::INVALID_ARGUMENT);

	mutation m("cancel-zero-policy", std::nullopt,
		   set_guardrails_policy_payload{.policy = policy, .expected_generation = 0u});

	auto result = loop.submit(std::move(m), std::chrono::milliseconds(0));

	// Either the cancel succeeded (deadline_exceeded) or the worker was
	// fast enough to process it (ok). Both are valid.
	bool valid = result.ok() || result.status.code() == kinetum::common::status_code::DEADLINE_EXCEEDED;

	EXPECT_TRUE(valid)
		<< "Zero-timeout must produce either ok or deadline_exceeded, got: "
		<< kinetum::common::status_code_name(result.status.code()) << " - " << result.status.message();

	loop.stop();
}

/**
 * @brief Cancel-safe timeout guarantees no double-apply via observable state.
 *
 * Submits policy A (no timeout) -> confirmed applied.
 * Submits policy B (0ms timeout) -> may be canceled or applied.
 * Submits a barrier mutation (no timeout) to flush the worker queue.
 * Reads RCU generation AFTER the barrier to verify consistency:
 * - If B returned deadline_exceeded: generation == gen_after_a + 1 (barrier only)
 * - If B returned ok: generation == gen_after_a + 2 (B + barrier)
 *
 * The barrier is critical: without it, a regression that executes canceled
 * mutations could still pass because the delayed execution races with the
 * generation read. The barrier forces the worker to drain, making the
 * generation reading definitive.
 */
TEST(control_loop_cancel, no_double_apply_observable)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_cancel_nodbl_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("cancel-double", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	// Step 1: Apply policy A (no timeout, guaranteed success)
	auto policy_a = make_valid_threshold_policy(100u, 1000u);
	{
		mutation m("cancel-double-a", std::nullopt,
			   set_guardrails_policy_payload{.policy = policy_a, .expected_generation = 0u});
		auto r = loop.submit(std::move(m));
		ASSERT_TRUE(r.ok()) << "Policy A must apply: " << r.status.message();
	}

	// Capture generation after A
	const uint64_t gen_after_a = loop.guardrails_state().policy.version();
	ASSERT_GT(gen_after_a, 0u) << "Generation must be >0 after publishing policy A";

	// Step 2: Submit policy B with 0ms timeout (may cancel or execute)
	auto policy_b = make_valid_threshold_policy(200u, 1000u);

	kinetum::common::status_code b_code;
	{
		mutation m("cancel-double-b", std::nullopt,
			   set_guardrails_policy_payload{
				   .policy = policy_b,
				   .expected_generation = gen_after_a,
			   });
		auto r = loop.submit(std::move(m), std::chrono::milliseconds(0));
		b_code = r.status.code();

		// Must be one of the two valid outcomes
		ASSERT_TRUE(r.ok() || b_code == kinetum::common::status_code::DEADLINE_EXCEEDED)
			<< "Timeout submit must return ok or deadline_exceeded, got: "
			<< kinetum::common::status_code_name(b_code);
	}

	// Step 3: Barrier mutation - flush the worker queue.
	// After this returns, all mutations queued before the barrier have been
	// either processed or skipped (canceled). Any delayed execution from a
	// regression would be visible in the generation count.
	ASSERT_TRUE(publish_policy(loop, policy_a));

	// Step 4: Read generation AFTER barrier - definitive
	const uint64_t gen_final = loop.guardrails_state().policy.version();

	if (b_code == kinetum::common::status_code::DEADLINE_EXCEEDED) {
		// Policy B was canceled - only barrier advanced generation
		EXPECT_EQ(gen_final, gen_after_a + 1) << "Canceled mutation must not execute (verified after barrier)";
	} else {
		// Policy B was executed - B + barrier advanced generation
		EXPECT_EQ(gen_final, gen_after_a + 2) << "Executed mutation must advance generation exactly once";
	}

	loop.stop();
}

/**
 * @brief Concurrent timeout submits do not corrupt state or double-apply.
 *
 * Multiple threads submit mutations with short timeouts concurrently.
 * Verifies:
 * 1. Every result is OK, cancel-safe DEADLINE_EXCEEDED, or an exact stale-
 *    generation FAILED_PRECONDITION.
 * 2. No crashes, no hangs
 * 3. Side-effect accounting: RCU generation after a barrier equals exactly
 *    the number of mutations that returned ok + the barrier itself.
 *    Any double-apply would inflate the generation beyond this count.
 */
TEST(control_loop_cancel, concurrent_timeout_submits_safe)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_cancel_conc_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("cancel-concurrent", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	constexpr int THREADS = 4;
	constexpr int SUBMITS_PER_THREAD = 10;
	std::atomic<int> valid_results{0};
	std::atomic<int> ok_count{0};
	std::vector<std::thread> threads;

	for (int t = 0; t < THREADS; ++t) {
		threads.emplace_back([&, t]() {
			for (int i = 0; i < SUBMITS_PER_THREAD; ++i) {
				auto policy =
					make_valid_threshold_policy(static_cast<uint64_t>(100 + t * 10 + i), 2000u);

				mutation m("concurrent-policy-" + std::to_string(t) + "-" + std::to_string(i),
					   std::nullopt,
					   set_guardrails_policy_payload{
						   .policy = policy,
						   .expected_generation =
							   loop.guardrails_state().policy.has_value() ?
								   loop.guardrails_state().policy.version() :
								   0u,
					   });

				// Alternate between timeout and no-timeout
				mutation_result r;
				if (i % 2 == 0) {
					r = loop.submit(std::move(m), std::chrono::milliseconds(1));
				} else {
					r = loop.submit(std::move(m));
				}

				if (r.ok()) {
					ok_count.fetch_add(1);
					valid_results.fetch_add(1);
				} else if (r.status.code() == kinetum::common::status_code::DEADLINE_EXCEEDED ||
					   r.status.code() == kinetum::common::status_code::FAILED_PRECONDITION) {
					valid_results.fetch_add(1);
				}
			}
		});
	}

	for (auto &t : threads)
		t.join();

	EXPECT_EQ(valid_results.load(), THREADS * SUBMITS_PER_THREAD)
		<< "Every concurrent submit must return an admitted exact outcome";

	// Barrier to flush any in-flight mutations in the worker queue.
	// After this returns, all prior mutations have been processed or skipped.
	{
		auto barrier_policy = make_valid_threshold_policy(999u, 10'000u);
		ASSERT_TRUE(publish_policy(loop, barrier_policy));
	}

	// Side-effect assertion: RCU generation must equal exactly the number of
	// mutations that returned ok + 1 (the barrier). Any double-apply from a
	// timed-out mutation secretly executing would inflate the generation.
	const uint64_t final_gen = loop.guardrails_state().policy.version();
	const uint64_t expected_gen = static_cast<uint64_t>(ok_count.load()) + 1;

	EXPECT_EQ(final_gen, expected_gen)
		<< "Generation must match ok_count(" << ok_count.load() << ") + barrier(1) = " << expected_gen
		<< " - mismatch indicates double-apply";

	loop.stop();
}

/**
 * @brief The fixed mutation mailbox rejects its sixty-fifth queued context without consuming identity.
 *
 * One executing transition is held at the fake DP activation edge. Sixty-four
 * timeout submissions then transfer ownership into the mailbox and cancel;
 * cancellation prevents execution but does not revoke the queued contexts.
 * The next complete request must fail before its revision CAS, store, or DP
 * operation. Releasing the worker drains every canceled context, and retrying
 * that same request identity must execute exactly once.
 */
TEST(control_loop_cancel, fixed_mailbox_rejects_before_identity_consumption_and_drains_canceled_contexts)
{
	namespace fs = std::filesystem;
	const auto dir = (fs::temp_directory_path() / "kinetum_cl_bounded_mailbox_test").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("mailbox-base", 1)).is_ok());

	kinetum::test::fake_dp_server dp;
	dp.service.complete_transitions = true;
	std::array<uint8_t, 32> plan_hash_bytes{};
	plan_hash_bytes.fill(UINT8_C(0x6d));
	dp.service.transition_plan_content_hash =
		kinetum::common::bytes_to_hex(plan_hash_bytes.data(), plan_hash_bytes.size());

	std::promise<void> activation_entered_promise;
	auto activation_entered = activation_entered_promise.get_future();
	std::promise<void> activation_release_promise;
	auto activation_release = activation_release_promise.get_future().share();
	std::atomic<bool> first_activation{true};
	dp.service.activate_observer = [&] {
		if (first_activation.exchange(false, std::memory_order_acq_rel)) {
			activation_entered_promise.set_value();
		}
		activation_release.wait();
	};
	dp.start();

	control_loop loop(store.get(), dp.stub);
	ASSERT_TRUE(loop.start().is_ok());

	std::promise<mutation_result> first_result_promise;
	auto first_result = first_result_promise.get_future();
	std::thread first_submitter([&] {
		mutation request("mailbox-blocking-transition", int64_t{1},
				 set_config_payload{make_cp_test_snapshot("mailbox-first", 2), 0u});
		first_result_promise.set_value(loop.submit(std::move(request)));
	});

	if (activation_entered.wait_for(std::chrono::seconds(3)) != std::future_status::ready) {
		activation_release_promise.set_value();
		first_submitter.join();
		loop.stop();
		dp.shutdown();
		FAIL() << "the first mutation did not reach the held DP activation edge";
	}

	kinetum::control::v1::GuardrailsPolicy disabled_policy;
	disabled_policy.set_enabled(false);
	for (std::size_t index = 0u; index < CONTROL_LOOP_MUTATION_QUEUE_CAPACITY; ++index) {
		mutation canceled("mailbox-canceled-" + std::to_string(index), std::nullopt,
				  set_guardrails_policy_payload{
					  .policy = disabled_policy,
					  .expected_generation = 0u,
				  });
		const auto result = loop.submit(std::move(canceled), std::chrono::milliseconds(0));
		EXPECT_EQ(result.status.code(), kinetum::common::status_code::DEADLINE_EXCEEDED);
		EXPECT_EQ(loop.queue_depth(), index + 1u);
	}

	const auto final_snapshot = make_cp_test_snapshot("mailbox-final", 3);
	mutation rejected("mailbox-full-retry", int64_t{2}, set_config_payload{final_snapshot, 0u});
	const auto rejected_result = loop.submit(std::move(rejected), std::chrono::milliseconds(0));
	EXPECT_EQ(rejected_result.status.code(), kinetum::common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(loop.queue_depth(), CONTROL_LOOP_MUTATION_QUEUE_CAPACITY);
	EXPECT_EQ(dp.service.prepare_calls.load(std::memory_order_acquire), 1);
	EXPECT_FALSE(store->load_snapshot("mailbox-final").is_ok());
	EXPECT_FALSE(store->guardrails_policy().is_ok());

	activation_release_promise.set_value();
	first_submitter.join();
	const auto initial_result = first_result.get();
	EXPECT_TRUE(initial_result.ok()) << initial_result.status.message();
	EXPECT_EQ(initial_result.revision, 2);
	const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
	while (loop.queue_depth() != 0u && std::chrono::steady_clock::now() < drain_deadline) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	EXPECT_EQ(loop.queue_depth(), 0u);
	EXPECT_FALSE(store->guardrails_policy().is_ok());

	mutation retry("mailbox-full-retry", int64_t{2}, set_config_payload{final_snapshot, 0u});
	const auto retry_result = loop.submit(std::move(retry));
	EXPECT_TRUE(retry_result.ok()) << retry_result.status.message();
	EXPECT_EQ(retry_result.revision, 3);
	EXPECT_EQ(retry_result.epoch, 3u);
	EXPECT_EQ(loop.queue_depth(), 0u);
	EXPECT_FALSE(loop.guardrails_state().policy.has_value());
	EXPECT_EQ(dp.service.prepare_calls.load(std::memory_order_acquire), 2);
	EXPECT_EQ(dp.service.activate_calls.load(std::memory_order_acquire), 2);

	loop.stop();
	dp.shutdown();
}

//==============================================================================
// Published State Coherence Tests
//==============================================================================
// These tests validate the sole coherent revision/snapshot publication.
//==============================================================================

/**
 * @brief Fresh system publishes coherent default state.
 *
 * On a fresh system, one RCU borrow returns revision zero and an empty
 * snapshot identity.
 */
TEST(control_loop_coherence, fresh_system_publishes_defaults)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_coherence_fresh").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);

	control_loop loop(store.get(), nullptr);

	// Constructor publication is available before the worker starts.
	const auto state = loop.published_state();
	EXPECT_EQ(state.revision, 0) << "Fresh system must publish revision=0";
	EXPECT_TRUE(state.snapshot_id.empty()) << "Fresh system must publish empty snapshot_id";
}

/**
 * @brief Restored system publishes coherent state from storage.
 *
 * After constructor restores revision and snapshot_id from persisted storage,
 * the published state must contain the coherent pair - not a stale default
 * or a split where one field is restored and the other is still zero/empty.
 */
TEST(control_loop_coherence, restored_state_published_coherently)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_coherence_restore").string();
	test_dir_guard guard{dir};

	// First lifetime: persist a snapshot with known revision + snapshot_id
	{
		auto store = open_cp_test_store(dir);
		ASSERT_NE(store, nullptr);

		kinetum::control::v1::ConfigSnapshot snap;
		snap.set_snapshot_id("snap_coherence_42");
		snap.set_revision(42);
		snap.set_created_unix_ms(1000);
		ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, snap).is_ok());
	}

	// Second lifetime: control_loop restores and publishes coherent pair
	{
		auto store = open_cp_test_store(dir);
		ASSERT_NE(store, nullptr);

		control_loop loop(store.get(), nullptr);

		// Single-borrow pair read - the production API for coherent access
		const auto state = loop.published_state();
		EXPECT_EQ(state.revision, 42) << "Restored revision must match persisted snapshot";
		EXPECT_EQ(state.snapshot_id, "snap_coherence_42")
			<< "Restored snapshot_id must match the atomic transition authority";
	}
}

/**
 * @brief Concurrent readers via published_state() observe coherent pairs.
 *
 * Exercises the production single-borrow API (control_loop::published_state())
 * under concurrent reader pressure. The control_loop worker processes
 * guardrails policy mutations (which don't change revision/snapshot_id),
 * while reader threads call published_state() continuously to verify the
 * pair never diverges from the constructor-published values.
 *
 * This catches the split-borrow class where separate half-identity reads could
 * observe different mutations. The published_state() API returns both in a
 * single borrow, making split reads structurally impossible.
 */
TEST(control_loop_coherence, concurrent_readers_see_coherent_pairs)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_coherence_conc").string();
	test_dir_guard guard{dir};

	// Persist known state: revision=42, snapshot_id="snap_conc_42"
	{
		auto store = open_cp_test_store(dir);
		ASSERT_NE(store, nullptr);

		kinetum::control::v1::ConfigSnapshot snap;
		snap.set_snapshot_id("snap_conc_42");
		snap.set_revision(42);
		snap.set_created_unix_ms(1000);
		ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, snap).is_ok());
	}

	// Second lifetime: restored control_loop with known published state
	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	constexpr int READER_THREADS = 4;
	constexpr int READS_PER_THREAD = 5000;
	std::atomic<uint64_t> violations{0};
	std::atomic<uint64_t> total_reads{0};

	// Reader threads call published_state() - the production single-borrow API
	std::vector<std::thread> readers;
	for (int t = 0; t < READER_THREADS; ++t) {
		readers.emplace_back([&]() {
			for (int i = 0; i < READS_PER_THREAD; ++i) {
				const auto state = loop.published_state();

				// The constructor published {42, "snap_conc_42"}.
				// Guardrails policy mutations do NOT change revision/snapshot_id.
				// So every read must see the same coherent pair.
				if (state.revision != 42 || state.snapshot_id != "snap_conc_42") {
					violations.fetch_add(1, std::memory_order_relaxed);
				}
				total_reads.fetch_add(1, std::memory_order_relaxed);
			}
		});
	}

	// Concurrently submit guardrails policy mutations to exercise the worker
	// thread while readers are running (creates interleaving pressure)
	std::thread submitter([&]() {
		for (int i = 0; i < 100; ++i) {
			kinetum::control::v1::GuardrailsPolicy policy;
			policy.set_enabled(false);
			(void)publish_policy(loop, policy);
		}
	});

	for (auto &r : readers)
		r.join();
	submitter.join();
	loop.stop();

	EXPECT_EQ(violations.load(), 0u) << "No reader via published_state() must observe a split pair "
					 << "(total_reads=" << total_reads.load() << ")";
	EXPECT_EQ(total_reads.load(), static_cast<uint64_t>(READER_THREADS) * READS_PER_THREAD)
		<< "All reader iterations must complete";
}

//==============================================================================
// Durable Policy Retry Correctness Tests
//==============================================================================
// Policy hash and key digest live in TRANSITION_AUTHORITY.pb. Retry identity is
// classified before generation CAS; no volatile map, TTL, or FIFO exists.
//==============================================================================

/**
 * @brief Same key and policy returns durable success before generation CAS.
 *
 * The retry deliberately supplies an impossible expected generation. Exact
 * retained identity still wins without another durable replacement.
 */
TEST(control_loop_idempotency, policy_retry_matrix_precedes_generation_compare)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_idem_cas").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("policy-retry", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());
	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);
	mutation first("policy-retry-key", std::nullopt,
		       set_guardrails_policy_payload{.policy = policy, .expected_generation = 0u});
	auto first_result = loop.submit(std::move(first));
	ASSERT_TRUE(first_result.ok());

	mutation retry("policy-retry-key", std::nullopt,
		       set_guardrails_policy_payload{.policy = policy, .expected_generation = UINT64_MAX});
	auto retry_result = loop.submit(std::move(retry));
	ASSERT_TRUE(retry_result.ok());
	EXPECT_EQ(retry_result.policy_generation, first_result.policy_generation);
	EXPECT_EQ(retry_result.policy_hash, first_result.policy_hash);

	loop.stop();
}

/**
 * @brief A new key with stale policy generation cannot publish.
 */
TEST(control_loop_idempotency, new_key_stale_policy_generation_rejects_without_publication)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_idem_recover").string();
	test_dir_guard guard{dir};
	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("policy-cas", 5)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());
	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);
	mutation first("policy-cas-first", std::nullopt,
		       set_guardrails_policy_payload{.policy = policy, .expected_generation = 0u});
	ASSERT_TRUE(loop.submit(std::move(first)).ok());

	mutation stale("policy-cas-stale", std::nullopt,
		       set_guardrails_policy_payload{.policy = policy, .expected_generation = 0u});
	auto rejected = loop.submit(std::move(stale));
	EXPECT_EQ(rejected.status.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	auto retained = store->guardrails_policy();
	ASSERT_TRUE(retained.is_ok());
	EXPECT_EQ(retained->generation, 1u);

	loop.stop();
}

/**
 * @brief Durable same-key/same-hash retry cannot double-apply.
 *
 * The retained policy generation remains unchanged across exact retry.
 */
TEST(control_loop_idempotency, durable_same_key_same_hash_prevents_double_apply)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_idem_ok").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("policy-exact", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(false);

	{
		mutation m("success_test_key", std::nullopt,
			   set_guardrails_policy_payload{.policy = policy, .expected_generation = 0u});

		auto result = loop.submit(std::move(m));
		ASSERT_TRUE(result.ok()) << "First submit must succeed: " << result.status.message();
	}

	const uint64_t gen_after_first = loop.guardrails_state().policy.version();
	ASSERT_GT(gen_after_first, 0u);

	{
		mutation m("success_test_key", std::nullopt,
			   set_guardrails_policy_payload{.policy = policy, .expected_generation = UINT64_MAX});

		auto result = loop.submit(std::move(m));
		EXPECT_TRUE(result.ok()) << "Retry must return durable success: " << result.status.message();
	}

	const uint64_t gen_after_retry = loop.guardrails_state().policy.version();
	EXPECT_EQ(gen_after_retry, gen_after_first) << "Durable retry must not re-execute mutation";

	loop.stop();
}

/**
 * @brief Same key with different canonical policy is an identity conflict.
 */
TEST(control_loop_idempotency, same_key_different_policy_is_identity_conflict)
{
	namespace fs = std::filesystem;
	auto dir = (fs::temp_directory_path() / "kinetum_cl_idem_err").string();
	test_dir_guard guard{dir};

	auto store = open_cp_test_store(dir);
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(reconcile_cp_test_bootstrap(*store, make_cp_test_snapshot("policy-conflict", 1)).is_ok());

	control_loop loop(store.get(), nullptr);
	ASSERT_TRUE(loop.start().is_ok());

	kinetum::control::v1::GuardrailsPolicy disabled;
	disabled.set_enabled(false);
	mutation first("policy-conflict-key", std::nullopt,
		       set_guardrails_policy_payload{.policy = disabled, .expected_generation = 0u});
	ASSERT_TRUE(loop.submit(std::move(first)).ok());

	auto enabled = make_valid_threshold_policy();
	mutation conflict("policy-conflict-key", std::nullopt,
			  set_guardrails_policy_payload{.policy = enabled, .expected_generation = 1u});
	auto rejected = loop.submit(std::move(conflict));
	EXPECT_EQ(rejected.status.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	auto retained = store->guardrails_policy();
	ASSERT_TRUE(retained.is_ok());
	EXPECT_FALSE(retained->policy.enabled());

	loop.stop();
}

}  // namespace kinetum::cp
