// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file guardrails_evaluator.hpp
 * @brief Deterministic evidence-window and rollback-attribution owner.
 * @author Fleming Patel
 *
 * This component owns the six-state guardrails evaluation machine. It accepts
 * only already-fenced runtime observations, keeps cumulative-counter and
 * valid-observation time separate, freezes one previous-content baseline, and
 * emits an observation-bound desired rollback without contacting storage or
 * the Data Plane. The runner owns I/O and the control loop owns durability.
 *
 * @par Thread Safety
 * Not thread-safe. One guardrails runner thread owns an instance for its full
 * lifetime.
 *
 * @par Performance
 * Bounded Control Plane work. History and attribution may allocate within the
 * configured cold-path bound. No method may run on a packet worker.
 */

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/sha256_digest.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/cp/attribution_scorer.hpp"
#include "src/cp/config_store.hpp"
#include "src/cp/health_correlator.hpp"
#include "src/cp/telemetry_snapshot.hpp"

namespace kinetum::cp
{

/** @brief Exact lifecycle of one guardrails evaluation owner. */
enum class guardrails_evaluator_state : uint8_t {
	UNCONFIGURED = 0,   ///< No durable policy exists.
	DISABLED,	    ///< One explicit empty disabled policy exists.
	BASELINE_BUILDING,  ///< Valid same-generation baseline is incomplete.
	ARMED,		    ///< Baseline is complete and stable configuration is watched.
	EVALUATING,	    ///< A changed configuration owns one bounded evidence window.
	ROLLBACK_PENDING,   ///< One durable safety intent exists; no second decision may arm.
};

static_assert(sizeof(guardrails_evaluator_state) == sizeof(uint8_t), "guardrails evaluator state must remain one byte");

/** @brief One exact CP-fenced observation consumed by the evaluator. */
struct guardrails_runtime_observation {
	durable_active_runtime_view active_authority;		    ///< Compact durable active identity.
	kinetum::dataplane::v1::StatsResponse stats;		    ///< Intrinsically validated runtime response.
	std::optional<durable_runtime_transition_view> transition;  ///< Compact lock-coherent durable transition.
	bool protocol_faulted{false};  ///< Sticky protocol safety fact from the same response.
};

/**
 * @brief Own exact baseline, evaluation-window, detector, and attribution state.
 *
 * The evaluator emits no idempotency key and no Unix creation time. Those are
 * producer facts added once by the runner immediately before the desired
 * action crosses the linear safety-intent channel.
 */
class guardrails_evaluator {
    public:
	/** @brief Construct one unconfigured empty evaluator. */
	guardrails_evaluator() = default;

	guardrails_evaluator(const guardrails_evaluator &) = delete;
	guardrails_evaluator &operator=(const guardrails_evaluator &) = delete;
	guardrails_evaluator(guardrails_evaluator &&) = delete;
	guardrails_evaluator &operator=(guardrails_evaluator &&) = delete;
	~guardrails_evaluator() = default;

	/**
	 * @brief Replace policy and all derived bounded state atomically.
	 * @param policy Complete already-admitted durable policy.
	 * @param generation Exact nonzero durable policy generation.
	 * @return OK after complete replacement, or validation/allocation failure
	 *         with the prior evaluator state unchanged.
	 */
	[[nodiscard]] kinetum::common::status apply_policy(const kinetum::control::v1::GuardrailsPolicy &policy,
							   uint64_t generation);

	/**
	 * @brief Mark one observation gap without advancing behavior time.
	 *
	 * The last cumulative high-watermark remains retained. The next valid sample
	 * must still be nonregressing but seeds a fresh interval, so missing time is
	 * never charged to the evaluation window.
	 */
	void pause_observation() noexcept;

	/** @brief Enter ROLLBACK_PENDING after the intent is durably accepted. */
	void mark_rollback_pending() noexcept;

	/** @brief Rebuild baseline after the one durable intent disappears. */
	void resume_after_intent() noexcept;

	/**
	 * @brief Consume one exact fenced observation.
	 * @param observation Complete active/content/runtime/transition evidence.
	 * @return Optional desired rollback with key/time deliberately empty, or an
	 *         allocation/host-bound failure. Missing or inapplicable evidence
	 *         returns no decision and pauses the current interval.
	 */
	[[nodiscard]] kinetum::common::status_or<std::optional<rollback_intent_request>>
	observe(const guardrails_runtime_observation &observation);

	/** @return Current exact evaluator phase. */
	[[nodiscard]] guardrails_evaluator_state state() const noexcept;

	/** @return Current policy generation, or zero while unconfigured. */
	[[nodiscard]] uint64_t policy_generation() const noexcept;

	/** @return true only for one configured enabled policy. */
	[[nodiscard]] bool enabled() const noexcept;

	/** @return true when module-health rows are mandatory for each sample. */
	[[nodiscard]] bool requires_module_health() const noexcept;

	/** @return true when boundary ACK-age rows are selected. */
	[[nodiscard]] bool requires_boundary_rows() const noexcept;

	/** @return Enabled policy cadence, or zero while unconfigured/disabled. */
	[[nodiscard]] std::chrono::milliseconds poll_interval() const noexcept;

    private:
	/**
	 * @brief Clear all evidence while preserving the configured policy.
	 * @param state Exact post-reset evaluator phase.
	 */
	void reset_evidence_(guardrails_evaluator_state state) noexcept;

	/** @brief Last accepted cumulative point used for exact interval deltas. */
	struct cumulative_point {
		std::string snapshot_id;	 ///< Exact durable active content.
		uint64_t epoch{0};		 ///< Last globally COMPLETE epoch.
		uint64_t runtime_generation{0};	 ///< Exact cumulative-counter namespace.
		uint64_t collection_ns{0};	 ///< Data Plane monotonic collection time.
		uint64_t rx_packets{0};		 ///< Cumulative admitted ingress.
		uint64_t tx_packets{0};		 ///< Cumulative accepted egress.
		uint64_t dropped_packets{0};	 ///< Cumulative terminal drop.
	};

	/**
	 * @brief Bind one cumulative seed and reset correlation to that content.
	 * @param point Exact first point in a new evidence namespace.
	 */
	void seed_current_(const cumulative_point &point);

	/**
	 * @brief Project one fenced response into cumulative-counter identity.
	 * @param observation Exact fenced source.
	 * @return Compact cumulative point.
	 */
	[[nodiscard]] static cumulative_point point_from_(const guardrails_runtime_observation &observation);

	/**
	 * @brief Derive one exact same-identity interval sample.
	 * @param previous Prior accepted cumulative point.
	 * @param point Current accepted cumulative point.
	 * @param current Complete current observation for module-health projection.
	 * @param baseline_tx_pps Positive stable baseline, or zero while building it.
	 * @return One real interval sample or exact identity/regression failure.
	 */
	[[nodiscard]] static kinetum::common::status_or<telemetry_snapshot>
	interval_sample_(const cumulative_point &previous, const cumulative_point &point,
			 const guardrails_runtime_observation &current, double baseline_tx_pps);

	guardrails_evaluator_state state_{guardrails_evaluator_state::UNCONFIGURED};  ///< Sole phase.
	uint64_t policy_generation_{0};			   ///< Exact durable policy generation.
	kinetum::control::v1::GuardrailsPolicy policy_;	   ///< Current complete policy.
	std::unique_ptr<health_correlator> correlator_;	   ///< Correlation detector, when selected.
	std::unique_ptr<telemetry_history> history_;	   ///< Bounded valid interval history.
	std::unique_ptr<attribution_scorer> scorer_;	   ///< Explicit previous/current attribution.
	std::optional<cumulative_point> previous_;	   ///< Last valid cumulative high-watermark.
	std::vector<telemetry_snapshot> frozen_baseline_;  ///< Previous-content evidence.
	std::string current_snapshot_id_;		   ///< Current active content identity.
	uint64_t current_epoch_{0};			   ///< Exact epoch paired with current_snapshot_id_.
	std::string rollback_snapshot_id_;		   ///< Frozen prior content during evaluation.
	uint64_t runtime_generation_{0};		   ///< Current cumulative-counter namespace.
	double baseline_tx_pps_{0.0};			   ///< Mean valid stable throughput.
	uint64_t evaluation_elapsed_ns_{0};		   ///< Sum of contiguous valid intervals only.
	bool interval_contiguous_{false};		   ///< Whether next valid point may produce a delta.
};

}  // namespace kinetum::cp
