// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file health_correlator.cpp
 * @brief Implementation of multi-signal health correlation.
 * @author Fleming Patel
 *
 * @see health_correlator.hpp for design documentation
 */

#include "src/cp/health_correlator.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>

#include "src/common/log.hpp"

namespace kinetum::cp
{

signal_breakdown health_correlator::update(const telemetry_snapshot &sample)
{
	if (current_snapshot_id_.empty() || sample.config_snapshot_id != current_snapshot_id_ ||
	    sample.runtime_generation == 0u || sample.timestamp_mono_ns == 0u || !std::isfinite(sample.drop_ratio) ||
	    sample.drop_ratio < 0.0 || sample.drop_ratio > 1.0 || !std::isfinite(sample.throughput_ratio) ||
	    sample.throughput_ratio < 0.0 || sample.config_issue_count > sample.module_health_count ||
	    (sample.module_health_count != 0u &&
	     (!std::isfinite(sample.module_health_avg) || sample.module_health_avg < 0.0 ||
	      sample.module_health_avg > 100.0)) ||
	    (sample.module_health_count == 0u &&
	     (sample.module_health_avg != 0.0 || sample.config_issue_count != 0u)) ||
	    ((weights_.module_health > 0.0 || weights_.config_issue_boost > 0.0) && sample.module_health_count == 0u)) {
		std::terminate();
	}

	signal_breakdown breakdown;
	breakdown.config_snapshot_id = current_snapshot_id_;
	if (samples_since_change_ != std::numeric_limits<uint64_t>::max()) {
		++samples_since_change_;
	}
	breakdown.samples_since_config_change = samples_since_change_;

	// ---------------------------------------------------------------------------
	// 1. Smooth the evaluator's one exact infrastructure interval
	// ---------------------------------------------------------------------------
	breakdown.drop_ratio_raw = sample.drop_ratio;

	// Smooth and normalize
	breakdown.drop_ratio_smoothed = drop_ratio_ewma_.update(breakdown.drop_ratio_raw);
	breakdown.drop_ratio_normalized = normalize_drop_ratio(breakdown.drop_ratio_smoothed);
	breakdown.drop_ratio_contribution = breakdown.drop_ratio_normalized * weights_.drop_ratio;

	// ---------------------------------------------------------------------------
	// 2. Smooth the evaluator's exact baseline-relative throughput
	// ---------------------------------------------------------------------------
	breakdown.throughput_ratio_raw = sample.throughput_ratio;

	// Smooth and normalize
	breakdown.throughput_ratio_smoothed = throughput_ratio_ewma_.update(breakdown.throughput_ratio_raw);
	breakdown.throughput_ratio_normalized = normalize_throughput_ratio(breakdown.throughput_ratio_smoothed);
	breakdown.throughput_ratio_contribution = breakdown.throughput_ratio_normalized * weights_.throughput_ratio;

	// ---------------------------------------------------------------------------
	// 3. Aggregate module health signals
	// ---------------------------------------------------------------------------
	breakdown.total_modules = sample.module_health_count;
	breakdown.config_issue_count = sample.config_issue_count;

	if (sample.module_health_count != 0u) {
		breakdown.module_health_avg = sample.module_health_avg;
	}

	if (breakdown.total_modules != 0u) {
		const double smoothed_health = module_health_ewma_.update(breakdown.module_health_avg);
		breakdown.module_health_normalized = normalize_module_health(smoothed_health);
		breakdown.module_health_contribution = breakdown.module_health_normalized * weights_.module_health;
	}

	// ---------------------------------------------------------------------------
	// 4. Compute final degradation score
	// ---------------------------------------------------------------------------
	// Base degradation from weighted signals
	double degradation = breakdown.drop_ratio_contribution + breakdown.throughput_ratio_contribution +
			     breakdown.module_health_contribution;

	// Boost if modules report CONFIG_ISSUE (strong signal that config caused it)
	if (sample.config_issue_count > 0u) {
		const double config_issue_ratio = static_cast<double>(sample.config_issue_count) /
						  static_cast<double>(sample.module_health_count);
		degradation += config_issue_ratio * weights_.config_issue_boost;
	}

	// Clamp to [0, 1]
	breakdown.degradation_score = std::clamp(degradation, 0.0, 1.0);

	// Convert to health score [0-100]
	breakdown.health_score = (1.0 - breakdown.degradation_score) * 100.0;

	// ---------------------------------------------------------------------------
	// 5. Apply hysteresis to prevent oscillation
	// ---------------------------------------------------------------------------
	breakdown.is_degraded = degradation_hysteresis_.update(breakdown.degradation_score);

	// ---------------------------------------------------------------------------
	// 6. Log for debugging/postmortems.
	// ---------------------------------------------------------------------------
	// Log every 30 valid interval samples. Policy cadence determines elapsed
	// time; the correlator owns no hidden one-second assumption.
	constexpr uint32_t PERIODIC_LOG_INTERVAL = 30;

	if (breakdown.is_degraded) {
		// Degradation detected - log as warning with full breakdown
		KINETUM_LOG_WARN(
			"cp.health", "health.degraded",
			"Health DEGRADED: score={}% drop_contrib={} throughput_contrib={} module_contrib={} config_issue_count={} samples={}",
			static_cast<int>(breakdown.health_score), breakdown.drop_ratio_contribution,
			breakdown.throughput_ratio_contribution, breakdown.module_health_contribution,
			sample.config_issue_count, breakdown.samples_since_config_change);
	} else if (breakdown.samples_since_config_change % PERIODIC_LOG_INTERVAL == 0) {
		// Periodic logging (not degraded) - log as info for audit trail
		KINETUM_LOG_INFO(
			"cp.health", "health.periodic",
			"Health periodic: score={}% degradation={} drop={} throughput={} module_health={} config={} samples={}",
			static_cast<int>(breakdown.health_score), breakdown.degradation_score,
			breakdown.drop_ratio_smoothed, breakdown.throughput_ratio_smoothed, breakdown.module_health_avg,
			breakdown.config_snapshot_id, breakdown.samples_since_config_change);
	}

	return breakdown;
}

}  // namespace kinetum::cp
