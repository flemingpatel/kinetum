// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file health_correlator.hpp
 * @brief Multi-signal health correlation for intelligent rollback decisions.
 * @author Fleming Patel
 *
 * Guardrails multi-signal health correlation.
 *
 * This module combines multiple signals for better rollback decisions:
 * - Infrastructure: drop_ratio, throughput_ratio
 * - Module: owner-worker-published health_score (0-100), CONFIG_ISSUE flag
 * - Time-based: samples since config change
 *
 * Design Philosophy (Platform Engineering Guide):
 * - Use existing signal.hpp primitives (ewma, hysteresis)
 * - Configurable weights via GuardrailsPolicy
 * - All computation in CP (not DP hot-path)
 * - Emit breakdown for debugging/postmortems
 *
 * @see PLATFORM_ENGINEERING_GUIDE.md Pat-15 for out-of-band guardrails ownership
 * @see MODULE_SDK.md for health_check() API documentation
 *
 */

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <exception>
#include <string>

#include <kinetum/algo/signal.hpp>
#include "src/cp/telemetry_snapshot.hpp"

namespace kinetum::cp
{

/**
 * @brief Signal breakdown for one exact guardrails interval.
 *
 * Contains both raw and normalized values for each signal,
 * plus the weighted contribution to the final score.
 */
struct signal_breakdown {
	// -------------------------------------------------------------------------
	// Infrastructure signals
	// -------------------------------------------------------------------------
	double drop_ratio_raw{0.0};	      ///< Raw drop ratio: dropped / (tx + dropped)
	double drop_ratio_smoothed{0.0};      ///< After EWMA smoothing
	double drop_ratio_normalized{0.0};    ///< Normalized to [0,1] (1 = bad)
	double drop_ratio_contribution{0.0};  ///< Weighted contribution

	double throughput_ratio_raw{1.0};	    ///< tx_pps / baseline_tx_pps
	double throughput_ratio_smoothed{1.0};	    ///< After EWMA smoothing
	double throughput_ratio_normalized{0.0};    ///< Normalized to [0,1] (1 = bad)
	double throughput_ratio_contribution{0.0};  ///< Weighted throughput contribution.

	// -------------------------------------------------------------------------
	// Module health signals from coherent DP owner-worker publications
	// -------------------------------------------------------------------------
	double module_health_avg{0.0};		 ///< Average only when total_modules is nonzero.
	double module_health_normalized{0.0};	 ///< Normalized to [0,1] (1 = bad)
	double module_health_contribution{0.0};	 ///< Weighted module-health contribution.

	uint32_t config_issue_count{0};	 ///< Modules reporting CONFIG_ISSUE flag
	uint32_t total_modules{0};	 ///< Complete health signal population; zero is unavailable.

	// -------------------------------------------------------------------------
	// Final computed values
	// -------------------------------------------------------------------------
	double health_score{100.0};	///< Final health score [0-100] (100 = healthy)
	double degradation_score{0.0};	///< Inverse: [0-1] (1 = unhealthy)
	bool is_degraded{false};	///< After hysteresis filter

	// -------------------------------------------------------------------------
	// Sample tracking
	// -------------------------------------------------------------------------
	uint64_t samples_since_config_change{0};  ///< Real intervals since content binding.
	std::string config_snapshot_id;		  ///< Exact content identity for this breakdown.
};

/**
 * @brief Exact configured contributions to one correlation score.
 */
struct correlation_weights {
	double drop_ratio;	    ///< Normalized drop-ratio contribution.
	double throughput_ratio;    ///< Normalized throughput contribution.
	double module_health;	    ///< Normalized module-health contribution.
	double config_issue_boost;  ///< Additive CONFIG_ISSUE contribution.
};

/** @brief Complete immutable configuration for one correlator instance. */
struct health_correlation_config {
	double ewma_alpha;		      ///< Exact smoothing factor in (0, 1].
	double degradation_threshold;	      ///< Exact hysteresis center in (0, 1].
	double hysteresis_band;		      ///< Exact hysteresis band below the center.
	double normalization_max_drop_ratio;  ///< Drop ratio mapping to full degradation.
	double normalization_min_tx_ratio;    ///< Throughput ratio mapping to full degradation.
	correlation_weights weights;	      ///< Complete explicit score contributions.
	uint32_t min_samples;		      ///< Exact post-change sample floor.
};

/**
 * @brief Multi-signal health correlator.
 *
 * Combines multiple signals to produce a single health score.
 * Uses EWMA smoothing and hysteresis to prevent oscillation.
 *
 * @par Usage
 * @code
 *   health_correlation_config config{...};
 *   health_correlator correlator(config);
 *   correlator.on_config_change("candidate");
 *
 *   // The evaluator derives one exact interval from cumulative telemetry.
 *   auto breakdown = correlator.update(interval_sample);
 *
 *   if (breakdown.is_degraded && breakdown.samples_since_config_change >= 5) {
 *     // Consider rollback
 *   }
 * @endcode
 *
 * @par Thread Safety
 * Not thread-safe. One guardrails_evaluator owns each instance.
 */
class health_correlator {
    public:
	// ---------------------------------------------------------------------------
	// Construction
	// ---------------------------------------------------------------------------

	/**
	 * @brief Construct from one completely validated explicit configuration.
	 * @param config Exact policy projection. Invalid internal input terminates;
	 *        public policy admission must reject it before construction.
	 */
	explicit health_correlator(const health_correlation_config &config) noexcept;

	// ---------------------------------------------------------------------------
	// Configuration
	// ---------------------------------------------------------------------------

	/**
	 * @brief Record configuration change.
	 *
	 * Resets every smoother, hysteresis state, and sample count before binding
	 * the new exact content identity. No old policy sample
	 * may cross this edge.
	 *
	 * @param snapshot_id Nonempty exact content identity.
	 */
	void on_config_change(const std::string &snapshot_id);

	// ---------------------------------------------------------------------------
	// Update and Query
	// ---------------------------------------------------------------------------

	/**
	 * @brief Correlate one already-derived exact telemetry interval.
	 *
	 * Counter identity, monotonic elapsed time, and throughput ratio are derived
	 * once by `guardrails_evaluator`. This method smooths and combines that one
	 * interval; it owns no cumulative-counter seed, reset, or clock arithmetic.
	 *
	 * @param sample Complete same-content, same-runtime-generation interval.
	 * @return Signal breakdown with one available correlated sample.
	 * @pre The evaluator validated identity, finite ratios, and any required
	 *      complete health aggregate; violation terminates.
	 */
	[[nodiscard]] signal_breakdown update(const telemetry_snapshot &sample);

	/**
	 * @brief Get the configured minimum sample count for a decision.
	 *
	 * @return Exact configured minimum sample count.
	 */
	[[nodiscard]] uint32_t min_samples() const
	{
		return min_samples_;
	}

	/** @brief Reset every smoothing and hysteresis state value. */
	void reset();

    private:
	// ---------------------------------------------------------------------------
	// Internal Helpers
	// ---------------------------------------------------------------------------

	/**
	 * @brief Normalize drop ratio to [0,1] where 1 = bad.
	 *
	 * Uses max_drop_ratio as the upper bound for normalization.
	 *
	 * @param ratio Finite nonnegative exact interval ratio.
	 * @return Clamped configured degradation contribution.
	 */
	[[nodiscard]] double normalize_drop_ratio(double ratio) const;

	/**
	 * @brief Normalize throughput ratio to [0,1] where 1 = bad.
	 *
	 * Low throughput = high degradation.
	 *
	 * @param ratio Finite nonnegative baseline-relative throughput.
	 * @return Clamped configured degradation contribution.
	 */
	[[nodiscard]] double normalize_throughput_ratio(double ratio) const;

	/**
	 * @brief Normalize module health (0-100) to [0,1] where 1 = bad.
	 * @param avg_score Complete current module-health average.
	 * @return Inverted and clamped degradation contribution.
	 */
	[[nodiscard]] double normalize_module_health(double avg_score) const;

	// ---------------------------------------------------------------------------
	// Member Variables
	// ---------------------------------------------------------------------------

	// Signal smoothers
	algo::ewma drop_ratio_ewma_;	    ///< Exact interval drop-ratio smoother.
	algo::ewma throughput_ratio_ewma_;  ///< Baseline-relative throughput smoother.
	algo::ewma module_health_ewma_;	    ///< Complete module-health smoother.

	// Degradation hysteresis
	algo::hysteresis degradation_hysteresis_;  ///< Configured entry/exit state filter.

	// Configuration
	double max_drop_ratio_;	       ///< Configured drop ratio mapping to full degradation.
	double min_throughput_;	       ///< Configured throughput ratio mapping to full degradation.
	correlation_weights weights_;  ///< Exact validated signal contributions.
	uint32_t min_samples_;	       ///< Required post-binding real interval count.

	// State
	std::string current_snapshot_id_;   ///< Bound exact content identity.
	uint64_t samples_since_change_{0};  ///< Saturating real interval count.
};

// =============================================================================
// Inline Implementation
// =============================================================================

inline health_correlator::health_correlator(const health_correlation_config &config) noexcept
	: drop_ratio_ewma_(config.ewma_alpha)
	, throughput_ratio_ewma_(config.ewma_alpha)
	, module_health_ewma_(config.ewma_alpha)
	, degradation_hysteresis_(config.degradation_threshold, config.hysteresis_band)
	, max_drop_ratio_(config.normalization_max_drop_ratio)
	, min_throughput_(config.normalization_min_tx_ratio)
	, weights_(config.weights)
	, min_samples_(config.min_samples)
{
	const double base_weight = weights_.drop_ratio + weights_.throughput_ratio + weights_.module_health;
	if (!std::isfinite(config.ewma_alpha) || config.ewma_alpha <= 0.0 || config.ewma_alpha > 1.0 ||
	    !std::isfinite(config.degradation_threshold) || config.degradation_threshold <= 0.0 ||
	    config.degradation_threshold > 1.0 || !std::isfinite(config.hysteresis_band) ||
	    config.hysteresis_band < 0.0 || config.hysteresis_band > 0.5 ||
	    config.hysteresis_band >= config.degradation_threshold || !std::isfinite(max_drop_ratio_) ||
	    max_drop_ratio_ <= 0.0 || max_drop_ratio_ > 1.0 || !std::isfinite(min_throughput_) ||
	    min_throughput_ <= 0.0 || min_throughput_ >= 1.0 || !std::isfinite(weights_.drop_ratio) ||
	    weights_.drop_ratio < 0.0 || weights_.drop_ratio > 1.0 || !std::isfinite(weights_.throughput_ratio) ||
	    weights_.throughput_ratio < 0.0 || weights_.throughput_ratio > 1.0 ||
	    !std::isfinite(weights_.module_health) || weights_.module_health < 0.0 || weights_.module_health > 1.0 ||
	    !std::isfinite(weights_.config_issue_boost) || weights_.config_issue_boost < 0.0 ||
	    weights_.config_issue_boost > 1.0 || !std::isfinite(base_weight) || base_weight <= 0.0 ||
	    base_weight + weights_.config_issue_boost > 1.0 || min_samples_ == 0u) {
		std::terminate();
	}
}

inline void health_correlator::on_config_change(const std::string &snapshot_id)
{
	if (snapshot_id.empty()) {
		std::terminate();
	}
	drop_ratio_ewma_.reset();
	throughput_ratio_ewma_.reset();
	module_health_ewma_.reset();
	degradation_hysteresis_.reset();
	current_snapshot_id_ = snapshot_id;
	samples_since_change_ = 0;
}

inline void health_correlator::reset()
{
	drop_ratio_ewma_.reset();
	throughput_ratio_ewma_.reset();
	module_health_ewma_.reset();
	degradation_hysteresis_.reset();
	current_snapshot_id_.clear();
	samples_since_change_ = 0;
}

inline double health_correlator::normalize_drop_ratio(double ratio) const
{
	// Clamp to [0, max_drop_ratio] then normalize to [0, 1]
	const double clamped = std::clamp(ratio, 0.0, max_drop_ratio_);
	return clamped / max_drop_ratio_;
}

inline double health_correlator::normalize_throughput_ratio(double ratio) const
{
	// ratio < min_throughput = max degradation
	// ratio >= 1.0 = no degradation
	if (ratio >= 1.0)
		return 0.0;
	if (ratio <= min_throughput_)
		return 1.0;

	// Linear interpolation: 1.0 -> 0, min_throughput_ -> 1
	return (1.0 - ratio) / (1.0 - min_throughput_);
}

inline double health_correlator::normalize_module_health(double avg_score) const
{
	// 100 = healthy (degradation=0), 0 = unhealthy (degradation=1)
	return (100.0 - std::clamp(avg_score, 0.0, 100.0)) / 100.0;
}

}  // namespace kinetum::cp
