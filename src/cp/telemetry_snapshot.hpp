// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file telemetry_snapshot.hpp
 * @brief Time-series telemetry snapshots for attribution analysis.
 * @author Fleming Patel
 *
 * Guardrails telemetry collection infrastructure.
 *
 * This module captures periodic telemetry snapshots that enable:
 * - Before/after comparison around configuration changes
 * - Historical baseline establishment
 * - Attribution analysis (did config change cause degradation?)
 *
 * Design Philosophy (Platform Engineering Guide):
 * - Bounded storage (ring buffer, configurable size)
 * - Key by config snapshot_id for correlation
 * - Include both infrastructure metrics and module health
 * - Zero hot-path impact (snapshots taken on poll thread)
 *
 * @see PLATFORM_ENGINEERING_GUIDE.md Pat-15 for out-of-band guardrails ownership
 * @see MODULE_SDK.md for owner-worker health publication semantics
 *
 */

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace kinetum::cp
{

/**
 * @brief Complete telemetry snapshot at a point in time.
 *
 * Contains infrastructure metrics, module health, and metadata
 * for attribution analysis.
 *
 * @par Counter Sources
 *
 * Infrastructure counters come from one application-successful Data Plane
 * StatsResponse via gRPC. A non-OK response contributes no observation:
 *
 * | Counter         | Source                       | Notes                           |
 * |-----------------|------------------------------|---------------------------------|
 * | rx_packets      | successful DP StatsResponse  | Total packets admitted by RX    |
 * | tx_packets      | successful DP StatsResponse  | Total packets accepted by TX    |
 * | dropped_packets | successful DP StatsResponse  | Total packets retired before TX |
 *
 * Module health signals originate from exact owner-worker health callbacks and
 * reach this cold-path snapshot only through a completed publication bridge.
 * The evaluator validates complete context membership, then stores only the
 * fixed aggregates consumed by correlation and attribution:
 *
 * | Signal          | Source                          | Notes                            |
 * |-----------------|--------------------------------|----------------------------------|
 * | module_health_count | complete current publication set          | Zero when unavailable   |
 * | module_health_avg   | validated health scores                   | [0-100]                 |
 * | config_issue_count  | validated health flags                    | No greater than count   |
 *
 * @par Runtime Generation Handling
 *
 * Counters are cumulative only inside one exact runtime generation. A new
 * generation resets the baseline and history without producing a delta. A
 * lower value inside the same generation is contradictory evidence and is
 * refused; it is never reinterpreted as a reset.
 */
struct telemetry_snapshot {
	// -------------------------------------------------------------------------
	// Metadata
	// -------------------------------------------------------------------------
	std::string config_snapshot_id;	 ///< Config snapshot this applies to
	uint64_t epoch{0};		 ///< Active epoch at capture time
	uint64_t runtime_generation{0};	 ///< Exact cumulative-counter namespace.
	uint64_t timestamp_ms{0};	 ///< Unix timestamp (milliseconds) - persistence/audit
	uint64_t timestamp_mono_ns{0};	 ///< Monotonic timestamp (nanoseconds) - precise timing

	// -------------------------------------------------------------------------
	// Infrastructure Metrics
	// -------------------------------------------------------------------------
	uint64_t rx_packets{0};	      ///< Total records admitted by runtime RX owners.
	uint64_t tx_packets{0};	      ///< Total records accepted by runtime TX owners.
	uint64_t dropped_packets{0};  ///< Total records retired before TX acceptance.

	// Computed rates (packets per second)
	double tx_pps{0.0};	       ///< Accepted-TX rate for this exact interval.
	double drop_pps{0.0};	       ///< Terminal-drop rate for this exact interval.
	double drop_ratio{0.0};	       ///< dropped / (tx + dropped)
	double throughput_ratio{1.0};  ///< tx_pps / baseline_tx_pps (deviation from normal)

	// -------------------------------------------------------------------------
	// Module Health
	// -------------------------------------------------------------------------
	uint32_t module_health_count{0};  ///< Complete current signal population; zero is unavailable.
	double module_health_avg{0.0};	  ///< Average only when module_health_count is nonzero.
	uint32_t config_issue_count{0};	  ///< Modules reporting CONFIG_ISSUE flag

	// -------------------------------------------------------------------------
	// Derived Signals (from health_correlator)
	// -------------------------------------------------------------------------
	double health_score{100.0};	///< Correlated health [0-100]
	double degradation_score{0.0};	///< Inverse [0-1]
	bool is_degraded{false};	///< After hysteresis
};

/** @brief Constant-time aggregate over one exact content history. */
struct telemetry_history_summary {
	std::size_t sample_count{0};  ///< Number of retained exact intervals.
	double mean_tx_pps{0.0};      ///< Mean accepted-TX rate, or zero when empty.
};

/**
 * @brief Bounded ring buffer of telemetry snapshots per config.
 *
 * Maintains a fixed-size history of telemetry snapshots for each
 * configuration snapshot_id. This enables before/after comparison
 * for attribution analysis.
 *
 * @par Thread Safety
 * Not thread-safe. One guardrails evaluator owns the complete instance.
 *
 * @par Performance
 * Bounded cold-path storage. Construction fixes per-content capacity and the
 * evaluator state machine needs at most the armed and candidate identities.
 * A third identity without `clear()` is an internal contract violation.
 * `record()` performs no unbounded work and evicts at most one oldest row.
 *
 * @par Usage
 * @code
 *   telemetry_history history(100);  // Keep last 100 snapshots per config
 *
 *   // Record snapshot at each poll
 *   history.record(snapshot);
 *
 *   // Get history for a specific config
 *   auto snaps = history.get_for_config("snap_abc123");
 *
 * @endcode
 */
class telemetry_history {
    public:
	// ---------------------------------------------------------------------------
	// Construction
	// ---------------------------------------------------------------------------

	/**
	 * @brief Construct history with specified capacity.
	 *
	 * @param max_per_config Positive immutable snapshots-per-content bound.
	 *        Zero is an internal contract violation and terminates.
	 */
	explicit telemetry_history(std::size_t max_per_config);

	// ---------------------------------------------------------------------------
	// Recording
	// ---------------------------------------------------------------------------

	/**
	 * @brief Record one validated telemetry interval.
	 *
	 * Adds the interval to its exact content history and evicts at most one
	 * oldest row after the configured bound is crossed.
	 *
	 * @param snap Complete interval with a nonempty content identity.
	 * @throws std::bad_alloc If bounded history storage cannot be allocated.
	 * @throws std::length_error If storage exceeds its representable size.
	 */
	void record(const telemetry_snapshot &snap);

	// ---------------------------------------------------------------------------
	// Querying
	// ---------------------------------------------------------------------------

	/**
	 * @brief Copy all retained intervals for one content identity.
	 *
	 * @param config_snapshot_id Exact content identity to query.
	 * @return Oldest-first copy, or an empty vector when absent.
	 * @throws std::bad_alloc If result storage cannot be allocated.
	 * @throws std::length_error If result storage exceeds its representable size.
	 */
	[[nodiscard]] std::vector<telemetry_snapshot> get_for_config(const std::string &config_snapshot_id) const;

	/**
	 * @brief Read the count and mean accepted-TX rate without copying history.
	 * @param config_snapshot_id Exact content identity to summarize.
	 * @return Constant-time zero summary when absent, otherwise the complete
	 *         retained interval count and mean.
	 */
	[[nodiscard]] telemetry_history_summary summary_for_config(const std::string &config_snapshot_id) const;

	/**
	 * @brief Transfer one exact content history out of the bounded store.
	 *
	 * Complete vector construction precedes map mutation. The resulting
	 * vector preserves oldest-first order, and successful transfer removes the
	 * map entry so a frozen baseline is never duplicated in memory.
	 *
	 * @param config_snapshot_id Exact content identity to transfer.
	 * @return Transferred oldest-first samples, or an empty vector when absent.
	 */
	[[nodiscard]] std::vector<telemetry_snapshot> take_for_config(const std::string &config_snapshot_id);

	// ---------------------------------------------------------------------------
	// Management
	// ---------------------------------------------------------------------------

	/** @brief Clear both bounded content histories and their aggregates. */
	void clear();

    private:
	static constexpr std::size_t MAX_CONTENT_IDENTITIES = 2u;  ///< Armed plus candidate content.
	const std::size_t max_per_config_;			   ///< Exact configured per-content storage bound.

	/** @brief One bounded row set plus its constant-time throughput aggregate. */
	struct content_history {
		std::deque<telemetry_snapshot> samples;	 ///< Oldest-first exact intervals.
		long double tx_pps_sum{0.0L};		 ///< Sum matching every retained sample.
	};

	std::unordered_map<std::string, content_history> history_;  ///< Exact bounded content rows.
};

// =============================================================================
// Inline Implementation
// =============================================================================

inline telemetry_history::telemetry_history(std::size_t max_per_config)
	: max_per_config_(max_per_config)
{
	if (max_per_config_ == 0u) {
		std::terminate();
	}
}

inline void telemetry_history::record(const telemetry_snapshot &snap)
{
	if (snap.config_snapshot_id.empty() || !std::isfinite(snap.tx_pps) || snap.tx_pps < 0.0 ||
	    !std::isfinite(snap.drop_ratio) || snap.drop_ratio < 0.0 || snap.drop_ratio > 1.0 ||
	    !std::isfinite(snap.health_score) || snap.health_score < 0.0 || snap.health_score > 100.0) {
		std::terminate();
	}
	auto position = history_.find(snap.config_snapshot_id);
	if (position == history_.end()) {
		if (history_.size() >= MAX_CONTENT_IDENTITIES) {
			std::terminate();
		}
		content_history candidate;
		candidate.samples.push_back(snap);
		candidate.tx_pps_sum = static_cast<long double>(snap.tx_pps);
		const bool inserted = history_.try_emplace(snap.config_snapshot_id, std::move(candidate)).second;
		if (!inserted) {
			std::terminate();
		}
		return;
	}
	auto &entry = position->second;
	// Publish first so a failed copy leaves every retained sample untouched.
	// The one temporary extra element is bounded cold-path storage.
	entry.samples.push_back(snap);
	entry.tx_pps_sum += static_cast<long double>(snap.tx_pps);
	if (!std::isfinite(entry.tx_pps_sum)) {
		std::terminate();
	}
	if (entry.samples.size() > max_per_config_) {
		entry.tx_pps_sum -= static_cast<long double>(entry.samples.front().tx_pps);
		entry.samples.pop_front();
	}
}

inline std::vector<telemetry_snapshot> telemetry_history::get_for_config(const std::string &config_snapshot_id) const
{
	auto it = history_.find(config_snapshot_id);
	if (it == history_.end()) {
		return {};
	}
	return {it->second.samples.begin(), it->second.samples.end()};
}

inline telemetry_history_summary telemetry_history::summary_for_config(const std::string &config_snapshot_id) const
{
	const auto position = history_.find(config_snapshot_id);
	if (position == history_.end()) {
		return {};
	}
	const auto count = position->second.samples.size();
	if (count == 0u || !std::isfinite(position->second.tx_pps_sum)) {
		std::terminate();
	}
	return telemetry_history_summary{
		.sample_count = count,
		.mean_tx_pps = static_cast<double>(position->second.tx_pps_sum / static_cast<long double>(count)),
	};
}

inline std::vector<telemetry_snapshot> telemetry_history::take_for_config(const std::string &config_snapshot_id)
{
	auto position = history_.find(config_snapshot_id);
	if (position == history_.end()) {
		return {};
	}
	std::vector<telemetry_snapshot> result(position->second.samples.begin(), position->second.samples.end());
	history_.erase(position);
	return result;
}

inline void telemetry_history::clear()
{
	history_.clear();
}

}  // namespace kinetum::cp
