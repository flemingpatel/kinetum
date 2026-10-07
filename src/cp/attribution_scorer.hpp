// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file attribution_scorer.hpp
 * @brief Confidence scoring for configuration change attribution.
 * @author Fleming Patel
 *
 * Guardrails attribution confidence scoring.
 *
 * This module quantifies confidence that a configuration change caused
 * observed degradation. It combines multiple factors:
 * - Timing correlation: Did degradation start at config change?
 * - Magnitude match: Is degradation proportional to change?
 * - Baseline deviation: How far from historical normal?
 * - Config issue flags: Did modules report CONFIG_ISSUE?
 *
 * Design Philosophy (Platform Engineering Guide):
 * - Transparent scoring with factor breakdown
 * - Configurable thresholds for auto-rollback vs human decision
 * - All factors available for postmortem analysis
 * - Missing baseline or module evidence is inconclusive, never neutral
 *
 * @see PLATFORM_ENGINEERING_GUIDE.md Pat-15 for out-of-band guardrails ownership
 * @see MODULE_SDK.md for owner-worker health publication semantics
 *
 */

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <vector>

#include "src/cp/telemetry_snapshot.hpp"

namespace kinetum::cp
{

/**
 * @brief Individual confidence factor with value and explanation.
 */
struct confidence_factor {
	std::string name;	   ///< Factor name (e.g., "timing_correlation")
	double value{0.0};	   ///< Factor value [0.0, 1.0]
	double weight{0.0};	   ///< Weight in final calculation
	double contribution{0.0};  ///< value * weight
	std::string explanation;   ///< Human-readable explanation
};

/**
 * @brief Complete attribution score result.
 */
struct attribution_result {
	// -------------------------------------------------------------------------
	// Overall Score
	// -------------------------------------------------------------------------
	double confidence{0.0};		///< Final confidence [0.0, 1.0]
	std::string verdict;		///< "high", "medium", "low"
	bool evidence_complete{false};	///< Whether every required factor was observed.

	// -------------------------------------------------------------------------
	// Decision
	// -------------------------------------------------------------------------
	/** @brief Operator action selected from complete attribution evidence. */
	enum class action : uint8_t {
		AUTO_ROLLBACK,	 ///< High confidence - proceed with rollback
		DEFER_TO_HUMAN,	 ///< Medium confidence - wait for confirmation
		LOG_ONLY	 ///< Low confidence - external factors likely
	};
	action recommended_action{action::LOG_ONLY};  ///< Selected action; LOG_ONLY while inconclusive.

	// -------------------------------------------------------------------------
	// Factor Breakdown
	// -------------------------------------------------------------------------
	std::vector<confidence_factor> factors;	 ///< Complete selected-factor breakdown.

	// -------------------------------------------------------------------------
	// Context
	// -------------------------------------------------------------------------
	std::string config_snapshot_id;	 ///< Config being evaluated
	uint64_t timestamp_ms{0};	 ///< When this score was computed
	std::string explanation;	 ///< Summary explanation

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * @brief Get factor by name.
	 * @param name Exact factor identity.
	 * @return Pointer into this result, or nullptr when absent.
	 */
	[[nodiscard]] const confidence_factor *get_factor(const std::string &name) const
	{
		for (const auto &f : factors) {
			if (f.name == name)
				return &f;
		}
		return nullptr;
	}

	/**
	 * @brief Format as human-readable text for cold diagnostics.
	 * @return Complete factor and summary representation.
	 */
	[[nodiscard]] std::string to_string() const;
};

static_assert(sizeof(attribution_result::action) == sizeof(uint8_t), "attribution action must remain one byte");

/**
 * @brief Configuration for attribution scoring.
 */
struct attribution_config {
	double auto_rollback_threshold;	 ///< At or above this value, submit rollback intent.
	double defer_threshold;		 ///< At or above this value, require human action.
	std::size_t baseline_samples;	 ///< Exact minimum previous-config sample count.
	double degradation_threshold;	 ///< Minimum significant degradation in (0, 1].
	bool require_module_health;	 ///< Whether CONFIG_ISSUE evidence is mandatory.
};

/**
 * @brief Attribution scorer for config change confidence.
 *
 * Analyzes telemetry history to determine if a configuration change
 * caused observed degradation.
 *
 * @par Usage
 * @code
 *   attribution_config config{...};
 *   attribution_scorer scorer(config);
 *
 *   // When degradation is detected:
 *   auto result = scorer.compute(
 *       current_snapshot,          // Current telemetry
 *       frozen_baseline,           // Previous-configuration evidence
 *       current_window             // Current-configuration evidence
 *   );
 *
 *   if (result.recommended_action == attribution_result::action::AUTO_ROLLBACK) {
 *     // High confidence - proceed with rollback
 *   } else if (result.recommended_action == attribution_result::action::DEFER_TO_HUMAN) {
 *     // Medium confidence - wait for confirmation
 *   }
 * @endcode
 *
 * @par Thread Safety
 * Not thread-safe. One guardrails_evaluator owns each instance.
 */
class attribution_scorer {
    public:
	// ---------------------------------------------------------------------------
	// Construction
	// ---------------------------------------------------------------------------

	/**
	 * @brief Construct scorer with one complete exact configuration.
	 * @param config Validated scoring configuration. Invalid internal input
	 *        terminates; public policy admission rejects it first.
	 */
	explicit attribution_scorer(const attribution_config &config) noexcept;

	// ---------------------------------------------------------------------------
	// Scoring
	// ---------------------------------------------------------------------------

	/**
	 * @brief Compute the configured attribution factors and recommendation.
	 *
	 * Combines timing correlation, magnitude matching, baseline deviation, and
	 * CONFIG_ISSUE observations without treating the score as causal proof.
	 *
	 * @param current Current degraded telemetry interval.
	 * @param baseline Frozen previous-configuration samples.
	 * @param current_window Valid current-configuration samples.
	 * @return Bounded attribution score, factors, and recommendation.
	 */
	[[nodiscard]] attribution_result compute(const telemetry_snapshot &current,
						 const std::vector<telemetry_snapshot> &baseline,
						 const std::vector<telemetry_snapshot> &current_window) const;

    private:
	static constexpr double TIMING_WEIGHT = 0.30;	     ///< Fixed causal-timing contribution.
	static constexpr double MAGNITUDE_WEIGHT = 0.20;     ///< Fixed degradation-shape contribution.
	static constexpr double BASELINE_WEIGHT = 0.20;	     ///< Fixed baseline-deviation contribution.
	static constexpr double CONFIG_ISSUE_WEIGHT = 0.30;  ///< Fixed module-attribution contribution.

	// ---------------------------------------------------------------------------
	// Factor Computation
	// ---------------------------------------------------------------------------

	/**
	 * @brief Compute timing correlation factor.
	 *
	 * High if degradation started at config change.
	 * Low if degradation was already happening before.
	 *
	 * @param before Complete previous-content baseline.
	 * @param after Valid current-content window.
	 * @return Bounded timing factor and explanation.
	 */
	[[nodiscard]] confidence_factor compute_timing_correlation(const std::vector<telemetry_snapshot> &before,
								   const std::vector<telemetry_snapshot> &after) const;

	/**
	 * @brief Compute magnitude match factor.
	 *
	 * High if degradation is proportional to typical config-caused issues.
	 * Low if degradation is suspiciously severe (suggests external cause).
	 *
	 * @param before Complete previous-content baseline.
	 * @param current Current degraded interval.
	 * @return Bounded magnitude factor and explanation.
	 */
	[[nodiscard]] confidence_factor compute_magnitude_match(const std::vector<telemetry_snapshot> &before,
								const telemetry_snapshot &current) const;

	/**
	 * @brief Compute baseline deviation factor.
	 *
	 * High if current state is far from historical baseline.
	 * Low if within normal variance.
	 *
	 * @param baseline Complete previous-content baseline.
	 * @param current Current degraded interval.
	 * @return Bounded deviation factor and explanation.
	 */
	[[nodiscard]] confidence_factor compute_baseline_deviation(const std::vector<telemetry_snapshot> &baseline,
								   const telemetry_snapshot &current) const;

	/**
	 * @brief Compute CONFIG_ISSUE flags factor.
	 *
	 * High if modules report CONFIG_ISSUE flag.
	 * Low if no modules suspect config problem.
	 *
	 * @param current Current interval with complete module-health aggregates.
	 * @return Bounded module-attribution factor and explanation.
	 */
	[[nodiscard]] confidence_factor compute_config_issue_flags(const telemetry_snapshot &current) const;

	// ---------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------

	/**
	 * @brief Compute average health score from snapshots.
	 * @param snaps Nonempty exact interval set.
	 * @return Arithmetic mean of correlated health scores.
	 */
	[[nodiscard]] static double average_health(const std::vector<telemetry_snapshot> &snaps);

	/**
	 * @brief Compute average drop ratio from snapshots.
	 * @param snaps Nonempty exact interval set.
	 * @return Arithmetic mean of interval drop ratios.
	 */
	[[nodiscard]] static double average_drop_ratio(const std::vector<telemetry_snapshot> &snaps);

	/**
	 * @brief Compute standard deviation of health scores.
	 * @param snaps Exact interval set; fewer than two rows returns zero.
	 * @return Sample standard deviation of correlated health scores.
	 */
	[[nodiscard]] static double health_stddev(const std::vector<telemetry_snapshot> &snaps);

	// ---------------------------------------------------------------------------
	// Member Variables
	// ---------------------------------------------------------------------------
	attribution_config config_;  ///< Immutable exact scoring configuration.
};

// =============================================================================
// Inline Implementation
// =============================================================================

inline attribution_scorer::attribution_scorer(const attribution_config &config) noexcept
	: config_(config)
{
	if (!std::isfinite(config_.auto_rollback_threshold) || config_.auto_rollback_threshold <= 0.0 ||
	    config_.auto_rollback_threshold > 1.0 || !std::isfinite(config_.defer_threshold) ||
	    config_.defer_threshold <= 0.0 || config_.defer_threshold > config_.auto_rollback_threshold ||
	    config_.baseline_samples == 0u || !std::isfinite(config_.degradation_threshold) ||
	    config_.degradation_threshold <= 0.0 || config_.degradation_threshold > 1.0) {
		std::terminate();
	}
}

inline std::string attribution_result::to_string() const
{
	std::string result = "Attribution Score: " + std::to_string(confidence) + " (" + verdict + ")\n";
	result += "Recommended: ";
	switch (recommended_action) {
	case action::AUTO_ROLLBACK:
		result += "AUTO_ROLLBACK\n";
		break;
	case action::DEFER_TO_HUMAN:
		result += "DEFER_TO_HUMAN\n";
		break;
	case action::LOG_ONLY:
		result += "LOG_ONLY\n";
		break;
	}
	result += "Factors:\n";
	for (const auto &f : factors) {
		result += "  - " + f.name + ": " + std::to_string(f.value) + " (weight=" + std::to_string(f.weight) +
			  ", contrib=" + std::to_string(f.contribution) + ")\n";
		if (!f.explanation.empty()) {
			result += "    " + f.explanation + "\n";
		}
	}
	if (!explanation.empty()) {
		result += "Summary: " + explanation + "\n";
	}
	return result;
}

inline attribution_result attribution_scorer::compute(const telemetry_snapshot &current,
						      const std::vector<telemetry_snapshot> &baseline,
						      const std::vector<telemetry_snapshot> &current_window) const
{
	attribution_result result;
	result.config_snapshot_id = current.config_snapshot_id;
	result.timestamp_ms = current.timestamp_ms;
	if (baseline.size() < config_.baseline_samples || current_window.empty() ||
	    (config_.require_module_health && current.module_health_count == 0u)) {
		result.verdict = "inconclusive";
		result.explanation = "Required previous or current evidence is incomplete";
		return result;
	}
	result.evidence_complete = true;

	// Compute individual factors
	result.factors.push_back(compute_timing_correlation(baseline, current_window));
	result.factors.push_back(compute_magnitude_match(baseline, current));
	result.factors.push_back(compute_baseline_deviation(baseline, current));
	if (config_.require_module_health) {
		result.factors.push_back(compute_config_issue_flags(current));
	}

	const double selected_weight = TIMING_WEIGHT + MAGNITUDE_WEIGHT + BASELINE_WEIGHT +
				       (config_.require_module_health ? CONFIG_ISSUE_WEIGHT : 0.0);
	result.factors[0].weight = TIMING_WEIGHT / selected_weight;
	result.factors[1].weight = MAGNITUDE_WEIGHT / selected_weight;
	result.factors[2].weight = BASELINE_WEIGHT / selected_weight;
	if (config_.require_module_health) {
		result.factors[3].weight = CONFIG_ISSUE_WEIGHT / selected_weight;
	}

	// Compute weighted sum
	double total = 0.0;
	for (auto &f : result.factors) {
		f.contribution = f.value * f.weight;
		total += f.contribution;
	}
	result.confidence = std::clamp(total, 0.0, 1.0);

	// Determine verdict and action
	if (result.confidence >= config_.auto_rollback_threshold) {
		result.verdict = "high";
		result.recommended_action = attribution_result::action::AUTO_ROLLBACK;
	} else if (result.confidence >= config_.defer_threshold) {
		result.verdict = "medium";
		result.recommended_action = attribution_result::action::DEFER_TO_HUMAN;
	} else {
		result.verdict = "low";
		result.recommended_action = attribution_result::action::LOG_ONLY;
	}

	// Build explanation
	std::string explanation;
	const auto *timing = result.get_factor("timing_correlation");
	const auto *config_issue = result.get_factor("config_issue_flags");

	if (timing && timing->value > 0.7) {
		explanation += "Strong timing correlation (degraded immediately after change). ";
	}
	if (config_issue && config_issue->value > 0.5) {
		explanation += std::to_string(current.config_issue_count) + " module(s) report CONFIG_ISSUE flag. ";
	}
	if (result.verdict == "low") {
		explanation += "Low confidence suggests external factors may be involved.";
	}

	result.explanation = explanation;
	return result;
}

inline confidence_factor
attribution_scorer::compute_timing_correlation(const std::vector<telemetry_snapshot> &before,
					       const std::vector<telemetry_snapshot> &after) const
{
	confidence_factor f;
	f.name = "timing_correlation";

	// Compare health before vs after
	double health_before = average_health(before);
	double health_after = average_health(after);

	// Compare drop ratio before vs after
	double drop_before = average_drop_ratio(before);
	double drop_after = average_drop_ratio(after);

	// Strong timing correlation if:
	// - Health dropped significantly after change
	// - Drop ratio increased significantly after change
	double health_delta = health_before - health_after;  // Positive = degraded
	double drop_delta = drop_after - drop_before;	     // Positive = worse

	// Normalize deltas to [0, 1] range
	double health_signal = std::min(1.0, std::max(0.0, health_delta / 50.0));  // 50 point drop = max
	double drop_signal = std::min(1.0, std::max(0.0, drop_delta / 0.1));	   // 10% increase = max

	// Combine signals
	f.value = (health_signal + drop_signal) / 2.0;

	f.explanation = "Health before=" + std::to_string(static_cast<int>(health_before)) +
			" after=" + std::to_string(static_cast<int>(health_after)) +
			", drop_ratio before=" + std::to_string(drop_before) + " after=" + std::to_string(drop_after);
	return f;
}

inline confidence_factor attribution_scorer::compute_magnitude_match(const std::vector<telemetry_snapshot> &before,
								     const telemetry_snapshot &current) const
{
	confidence_factor f;
	f.name = "magnitude_match";

	double health_before = average_health(before);
	double health_current = current.health_score;
	double degradation = (health_before - health_current) / 100.0;	// 0-1

	// Config-caused degradation is typically moderate (10-50%)
	// Extreme degradation (>50%) often indicates external issues
	// No degradation (0%) also low confidence

	if (degradation < config_.degradation_threshold) {
		// Not enough degradation to be significant
		f.value = 0.3;
		f.explanation = "Degradation below significance threshold";
	} else if (degradation >= 0.5) {
		// Extreme degradation - suspicious, might be external
		f.value = 0.4;
		f.explanation = "Extreme degradation suggests possible external factors";
	} else {
		// Moderate degradation - typical of config issues
		f.value = 0.8 + (0.2 * (degradation - 0.1) / 0.4);  // 0.8-1.0 for 10-50%
		f.explanation = "Moderate degradation consistent with config issues";
	}

	return f;
}

inline confidence_factor attribution_scorer::compute_baseline_deviation(const std::vector<telemetry_snapshot> &baseline,
									const telemetry_snapshot &current) const
{
	confidence_factor f;
	f.name = "baseline_deviation";

	double baseline_health = average_health(baseline);
	double baseline_stddev = health_stddev(baseline);
	if (baseline_stddev < 1.0)
		baseline_stddev = 1.0;	// Prevent division by zero

	// Z-score: how many standard deviations from baseline
	double z_score = (baseline_health - current.health_score) / baseline_stddev;

	// High z-score = far from baseline = high confidence
	if (z_score > 3.0) {
		f.value = 1.0;
		f.explanation = "Current state >3 std devs from baseline";
	} else if (z_score > 2.0) {
		f.value = 0.8;
		f.explanation = "Current state 2-3 std devs from baseline";
	} else if (z_score > 1.0) {
		f.value = 0.5;
		f.explanation = "Current state 1-2 std devs from baseline";
	} else {
		f.value = 0.2;
		f.explanation = "Current state within normal baseline variance";
	}

	return f;
}

inline confidence_factor attribution_scorer::compute_config_issue_flags(const telemetry_snapshot &current) const
{
	confidence_factor f;
	f.name = "config_issue_flags";

	// Ratio of modules reporting CONFIG_ISSUE
	double ratio =
		static_cast<double>(current.config_issue_count) / static_cast<double>(current.module_health_count);

	// More modules reporting = higher confidence
	f.value = std::min(1.0, ratio * 2.0);  // 50% of modules reporting = max

	f.explanation = std::to_string(current.config_issue_count) + "/" + std::to_string(current.module_health_count) +
			" modules report CONFIG_ISSUE flag";
	return f;
}

inline double attribution_scorer::average_health(const std::vector<telemetry_snapshot> &snaps)
{
	if (snaps.empty()) {
		std::terminate();
	}
	double sum = 0.0;
	for (const auto &s : snaps) {
		sum += s.health_score;
	}
	return sum / static_cast<double>(snaps.size());
}

inline double attribution_scorer::average_drop_ratio(const std::vector<telemetry_snapshot> &snaps)
{
	if (snaps.empty()) {
		std::terminate();
	}
	double sum = 0.0;
	for (const auto &s : snaps) {
		sum += s.drop_ratio;
	}
	return sum / static_cast<double>(snaps.size());
}

inline double attribution_scorer::health_stddev(const std::vector<telemetry_snapshot> &snaps)
{
	if (snaps.size() < 2)
		return 0.0;
	double mean = average_health(snaps);
	double sq_sum = 0.0;
	for (const auto &s : snaps) {
		double diff = s.health_score - mean;
		sq_sum += diff * diff;
	}
	return std::sqrt(sq_sum / static_cast<double>(snaps.size() - 1));
}

}  // namespace kinetum::cp
