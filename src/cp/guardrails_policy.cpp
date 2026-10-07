// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file guardrails_policy.cpp
 * @brief Exact guardrails policy admission and canonical identity.
 * @author Fleming Patel
 */

#include "src/cp/guardrails_policy.hpp"

#include <cmath>
#include <cstdint>
#include <limits>
#include <new>
#include <utility>

#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"

namespace kinetum::cp
{
namespace
{

constexpr uint64_t MAX_POLL_INTERVAL_MS = 3'600'000u;	    ///< One hour.
constexpr uint64_t MAX_EVALUATION_WINDOW_MS = 86'400'000u;  ///< One day.
constexpr uint32_t MAX_HISTORY_CAPACITY = 100'000u;	    ///< Bounded CP storage.

/**
 * @brief Test whether a floating policy value is finite and in a closed range.
 * @param value Candidate value.
 * @param minimum Inclusive lower bound.
 * @param maximum Inclusive upper bound.
 * @return true only for a finite value inside the closed interval.
 */
[[nodiscard]] bool finite_in_closed_range(double value, double minimum, double maximum) noexcept
{
	return std::isfinite(value) && value >= minimum && value <= maximum;
}

/**
 * @brief Test whether a floating policy value is finite and positive in range.
 * @param value Candidate value.
 * @param maximum Inclusive upper bound.
 * @return true only for `0 < value <= maximum`.
 */
[[nodiscard]] bool finite_positive(double value, double maximum) noexcept
{
	return std::isfinite(value) && value > 0.0 && value <= maximum;
}

/**
 * @brief Validate exact attribution common to both detector modes.
 * @param policy Complete parent policy.
 * @return OK only for one bounded, ordered attribution contract.
 */
[[nodiscard]] kinetum::common::status validate_attribution(const kinetum::control::v1::GuardrailsPolicy &policy)
{
	if (!policy.has_attribution()) {
		return kinetum::common::status::invalid_argument("enabled guardrails policy requires attribution");
	}
	const auto &attribution = policy.attribution();
	if (!finite_positive(attribution.auto_rollback_threshold(), 1.0) ||
	    !finite_positive(attribution.defer_threshold(), 1.0) ||
	    attribution.defer_threshold() > attribution.auto_rollback_threshold() ||
	    attribution.baseline_samples() == 0u ||
	    attribution.baseline_samples() > policy.telemetry_history_capacity() ||
	    !finite_positive(attribution.degradation_threshold(), 1.0)) {
		return kinetum::common::status::invalid_argument(
			"guardrails attribution is incomplete, out of range, or exceeds history capacity");
	}
	return kinetum::common::status::ok();
}

}  // namespace

kinetum::common::status validate_guardrails_policy(const kinetum::control::v1::GuardrailsPolicy &policy)
{
	const auto unknown = kinetum::common::reject_unknown_protobuf_fields_recursive(policy, "GuardrailsPolicy");
	if (!unknown.is_ok()) {
		return unknown;
	}
	const auto enums = kinetum::common::reject_invalid_protobuf_enum_values_recursive(policy, "GuardrailsPolicy");
	if (!enums.is_ok()) {
		return enums;
	}

	if (!policy.enabled()) {
		if (policy.poll_interval_ms() != 0u || policy.evaluation_window_ms() != 0u ||
		    policy.telemetry_history_capacity() != 0u ||
		    policy.detector_case() != kinetum::control::v1::GuardrailsPolicy::DETECTOR_NOT_SET ||
		    policy.has_attribution() || policy.has_boundary()) {
			return kinetum::common::status::invalid_argument(
				"disabled guardrails policy must be explicitly empty");
		}
		return kinetum::common::status::ok();
	}

	if (policy.poll_interval_ms() == 0u || policy.poll_interval_ms() > MAX_POLL_INTERVAL_MS ||
	    policy.evaluation_window_ms() < policy.poll_interval_ms() ||
	    policy.evaluation_window_ms() > MAX_EVALUATION_WINDOW_MS || policy.telemetry_history_capacity() == 0u ||
	    policy.telemetry_history_capacity() > MAX_HISTORY_CAPACITY) {
		return kinetum::common::status::invalid_argument(
			"enabled guardrails cadence, window, or history capacity is out of range");
	}

	const uint64_t sample_intervals = policy.evaluation_window_ms() / policy.poll_interval_ms() +
					  (policy.evaluation_window_ms() % policy.poll_interval_ms() != 0u ? 1u : 0u);
	if (sample_intervals > policy.telemetry_history_capacity()) {
		return kinetum::common::status::invalid_argument(
			"guardrails history capacity cannot retain one complete evaluation window");
	}

	const auto attribution = validate_attribution(policy);
	if (!attribution.is_ok()) {
		return attribution;
	}

	switch (policy.detector_case()) {
	case kinetum::control::v1::GuardrailsPolicy::kThreshold: {
		const auto &threshold = policy.threshold();
		if (!finite_in_closed_range(threshold.max_drop_ratio(), 0.0, 1.0) ||
		    !finite_in_closed_range(threshold.min_tx_ratio(), 0.0, 1.0)) {
			return kinetum::common::status::invalid_argument(
				"guardrails threshold detector is incomplete or out of range");
		}
		break;
	}
	case kinetum::control::v1::GuardrailsPolicy::kCorrelation: {
		const auto &correlation = policy.correlation();
		if (!finite_in_closed_range(correlation.drop_ratio_weight(), 0.0, 1.0) ||
		    !finite_in_closed_range(correlation.throughput_ratio_weight(), 0.0, 1.0) ||
		    !finite_in_closed_range(correlation.module_health_weight(), 0.0, 1.0) ||
		    !finite_in_closed_range(correlation.config_issue_boost(), 0.0, 1.0) ||
		    !finite_positive(correlation.ewma_alpha(), 1.0) ||
		    !finite_positive(correlation.degradation_threshold(), 1.0) ||
		    !finite_in_closed_range(correlation.hysteresis_band(), 0.0, 0.5) ||
		    correlation.hysteresis_band() >= correlation.degradation_threshold() ||
		    correlation.min_samples() == 0u ||
		    correlation.min_samples() > policy.telemetry_history_capacity() ||
		    correlation.min_samples() > sample_intervals ||
		    !finite_positive(correlation.normalization_max_drop_ratio(), 1.0) ||
		    !finite_positive(correlation.normalization_min_tx_ratio(), 1.0) ||
		    correlation.normalization_min_tx_ratio() >= 1.0) {
			return kinetum::common::status::invalid_argument(
				"guardrails correlation detector is incomplete or out of range");
		}
		const double base_weight_sum = correlation.drop_ratio_weight() + correlation.throughput_ratio_weight() +
					       correlation.module_health_weight();
		if (!std::isfinite(base_weight_sum) || base_weight_sum <= 0.0 || base_weight_sum > 1.0 ||
		    base_weight_sum + correlation.config_issue_boost() > 1.0) {
			return kinetum::common::status::invalid_argument(
				"guardrails correlation weights exceed one complete score");
		}
		break;
	}
	case kinetum::control::v1::GuardrailsPolicy::DETECTOR_NOT_SET:
		return kinetum::common::status::invalid_argument(
			"enabled guardrails policy requires exactly one detector");
	}

	if (policy.has_boundary() &&
	    (policy.boundary().ack_timeout_ms() == 0u ||
	     policy.boundary().ack_timeout_ms() > policy.evaluation_window_ms() ||
	     policy.boundary().ack_timeout_ms() > std::numeric_limits<uint64_t>::max() / 1'000'000u)) {
		return kinetum::common::status::invalid_argument(
			"guardrails boundary ACK timeout is zero, exceeds the window, or overflows nanoseconds");
	}

	return kinetum::common::status::ok();
}

kinetum::common::status_or<canonical_guardrails_policy>
canonicalize_guardrails_policy(const kinetum::control::v1::GuardrailsPolicy &policy)
{
	try {
		const auto validation = validate_guardrails_policy(policy);
		if (!validation.is_ok()) {
			return validation;
		}
		auto serialized_or = kinetum::common::serialize_protobuf_deterministically(policy);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto hash_or = kinetum::common::sha256_raw(serialized_or.value());
		if (!hash_or.is_ok()) {
			return hash_or.error();
		}
		return canonical_guardrails_policy{
			.policy = policy,
			.serialized_bytes = std::move(serialized_or).value(),
			.policy_hash = hash_or.value(),
		};
	} catch (const std::bad_alloc &) {
		return kinetum::common::status::resource_exhausted(
			"guardrails policy canonicalization exhausted memory");
	}
}

}  // namespace kinetum::cp
