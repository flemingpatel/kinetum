// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file guardrails.hpp
 * @brief Durable, evidence-fenced Control Plane guardrails evaluator.
 * @author Fleming Patel
 *
 * One background evaluator consumes only complete CP-fenced runtime telemetry.
 * It builds an initial same-generation baseline, pauses rather than imputing
 * missing evidence, performs explicit detector and attribution work, and sends
 * one observation-bound rollback intent to the Control Plane's sole mutation
 * writer. The intent is persisted before acknowledgement and later executes
 * through the ordinary durable epoch-transition authority.
 *
 * Commit-confirmed deadlines share that durable intent path. They retain Unix
 * time only because the deadline must survive restart; telemetry windows and
 * boundary ages use Data Plane monotonic collection time. A wall-clock sample
 * before durable confirmation creation is deadline-winning and cannot extend
 * the original interval.
 *
 * @par Thread Safety
 * `start()` and `stop()` are idempotent when serialized by the process
 * lifecycle owner; they are not a concurrent control API. The evaluator thread
 * is the sole writer of its correlation/history state. Policy arrives through
 * the control loop's coherent publication; configuration and intent mutation
 * remain on the control-loop thread.
 *
 * @par Performance
 * This is bounded cold Control Plane work. It has no packet-worker, provider,
 * queue, NUMA, or module-callback footprint.
 */

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "src/common/status.hpp"
#include "src/cp/guardrails_evaluator.hpp"

namespace kinetum::cp
{

class config_store;
class control_loop;

/**
 * @brief Own the guardrails evaluator and commit-confirmed deadline service.
 *
 * Construction borrows process-lifetime authorities but starts no thread.
 * The object is neither copyable nor movable because its worker captures its
 * stable address.
 */
class guardrails_runner {
    public:
	/**
	 * @brief Construct one stopped runner.
	 * @param store Sole durable CP authority; must outlive this object.
	 * @param dp_stub Generated DP client; may be null only in component tests
	 *        that never obtain a valid telemetry observation.
	 * @param loop Sole CP mutation and safety-intent authority; must outlive this object.
	 */
	guardrails_runner(config_store *store, std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> dp_stub,
			  control_loop &loop) noexcept;

	/** @brief Stop and join the worker before releasing borrowed authorities. */
	~guardrails_runner();

	guardrails_runner(const guardrails_runner &) = delete;
	guardrails_runner &operator=(const guardrails_runner &) = delete;
	guardrails_runner(guardrails_runner &&) = delete;
	guardrails_runner &operator=(guardrails_runner &&) = delete;

	/**
	 * @brief Allocate evaluator state and launch its sole worker.
	 *
	 * The borrowed control loop must already be running so a published safety
	 * context always has a live unconditional consumer.
	 *
	 * @return OK after launch/idempotent reuse, or exact dependency, allocation,
	 *         or native thread-creation failure.
	 */
	[[nodiscard]] kinetum::common::status start();

	/**
	 * @brief Request stop, wake every condition-variable wait, and join.
	 *
	 * A safety intent already published to the control-loop channel retains its
	 * unconditional stack-context wait there; this method never cancels it.
	 */
	void stop() noexcept;

    private:
	struct runtime_state;

	/** @brief Execute bounded cadence, deadline, and policy-state service. */
	void thread_main_() noexcept;

	config_store *store_{nullptr};					      ///< Borrowed sole durable CP authority.
	std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> dp_;  ///< Borrowed generated client owner.
	control_loop &loop_;			///< Borrowed sole mutation/safety-intent authority.
	std::atomic<bool> running_{false};	///< Release/acquire lifecycle predicate.
	std::mutex wait_mutex_;			///< Owns the stop-aware cadence predicate.
	std::condition_variable wait_cv_;	///< Wakes cadence immediately on stop.
	std::thread thread_;			///< Sole evaluator worker.
	std::unique_ptr<runtime_state> state_;	///< Worker-private bounded evaluation state.
};

}  // namespace kinetum::cp
