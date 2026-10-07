// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_lifecycle.hpp
 * @brief Compact provider-neutral packet-worker lifecycle state.
 * @author Fleming Patel
 *
 * Runtime workers are identified by their compact compiled worker index. A
 * native scheduler or provider may bind that worker to another identity during
 * launch, but native IDs never index core state or appear in generic runtime
 * telemetry.
 *
 * @par Concurrency
 * Startup and shutdown threads publish lifecycle transitions with release
 * ordering; the owner observes them with acquire ordering. Each context
 * occupies exactly one cache line, preventing different workers from writing
 * the same coherence unit.
 */

#include <atomic>
#include <cstdint>

namespace kinetum::dp
{

/** @brief Provider-neutral packet-worker lifecycle states. */
enum class worker_lifecycle_state : uint8_t {
	INIT = 0,  ///< Runtime owns the context but launch has not reserved it.
	STARTING,  ///< A launcher reserved the exact compact worker.
	RUNNING,   ///< Worker entry completed; packet work may still await the bootstrap gate.
	DRAINING,  ///< The owner retires admitted work without new RX admission.
	REQ_EXIT,  ///< Exit requested; the worker body must retire its admitted work before returning.
	EXITED,	   ///< The worker body returned and may be joined.
};

static_assert(std::atomic<worker_lifecycle_state>::is_always_lock_free,
	      "worker lifecycle publication requires lock-free state atomics");

/**
 * @brief Return the stable diagnostic name of one worker lifecycle state.
 *
 * @param state State to render.
 * @return Static state name, or `UNKNOWN` for an unrecognized value.
 */
[[nodiscard]] inline const char *worker_lifecycle_state_to_string(worker_lifecycle_state state) noexcept
{
	switch (state) {
	case worker_lifecycle_state::INIT:
		return "INIT";
	case worker_lifecycle_state::STARTING:
		return "STARTING";
	case worker_lifecycle_state::RUNNING:
		return "RUNNING";
	case worker_lifecycle_state::DRAINING:
		return "DRAINING";
	case worker_lifecycle_state::REQ_EXIT:
		return "REQ_EXIT";
	case worker_lifecycle_state::EXITED:
		return "EXITED";
	default:
		return "UNKNOWN";
	}
}

/** @brief Result of the sole legal worker-entry transition. */
enum class worker_enter_running_result : uint8_t {
	RUNNING = 0,		   ///< STARTING advanced to RUNNING.
	CANCELLED_BEFORE_RUNNING,  ///< Shutdown was already visible at entry.
	INVALID_START_STATE,	   ///< Entry observed a malformed lifecycle state.
};

/**
 * @brief One cache-line lifecycle record for one compact worker.
 *
 * The context has one runtime owner and is indexed only by compact worker ID.
 * It deliberately contains no native lcore/thread ID, packet counter, or
 * watchdog timestamp.
 */
struct alignas(64) worker_lifecycle_context {
	std::atomic<worker_lifecycle_state> state{worker_lifecycle_state::INIT};  ///< Published lifecycle state.

	/** @param desired State published to the owner or shutdown observer. */
	void set_state(worker_lifecycle_state desired) noexcept
	{
		state.store(desired, std::memory_order_release);
	}

	/**
	 * @brief Publish one exact lifecycle transition.
	 *
	 * @param expected Required current state.
	 * @param desired State to publish on success.
	 * @return true only when the expected state was replaced.
	 */
	[[nodiscard]] bool try_transition(worker_lifecycle_state expected, worker_lifecycle_state desired) noexcept
	{
		return state.compare_exchange_strong(expected, desired, std::memory_order_acq_rel,
						     std::memory_order_acquire);
	}

	/**
	 * @brief Publish an exit request without overwriting an inactive terminal state.
	 *
	 * STARTING, RUNNING, DRAINING, and unrecognized states fail closed to
	 * REQ_EXIT. INIT has no released worker, and EXITED proves the owner body
	 * returned; preserving both keeps all_workers_exited() truthful across final
	 * join and teardown. The compare/exchange loop prevents a concurrent owner
	 * publication of EXITED from being overwritten by shutdown.
	 */
	void request_exit() noexcept
	{
		auto current = state.load(std::memory_order_acquire);
		while (current != worker_lifecycle_state::INIT && current != worker_lifecycle_state::REQ_EXIT &&
		       current != worker_lifecycle_state::EXITED) {
			if (state.compare_exchange_weak(current, worker_lifecycle_state::REQ_EXIT,
							std::memory_order_acq_rel, std::memory_order_acquire)) {
				return;
			}
		}
	}

	/**
	 * @brief Publish the exact graceful-shutdown state for the observed phase.
	 *
	 * A STARTING worker has admitted no packet work and is cancelled with
	 * REQ_EXIT. A RUNNING worker advances to DRAINING. INIT, DRAINING,
	 * REQ_EXIT, and EXITED are already safe and remain unchanged. If worker
	 * entry races this request, compare/exchange refreshes the observed state
	 * and recomputes RUNNING to DRAINING rather than losing the request.
	 * Unrecognized states fail closed to REQ_EXIT.
	 *
	 * @return true only when this call publishes RUNNING to DRAINING.
	 */
	[[nodiscard]] bool request_drain() noexcept
	{
		auto current = state.load(std::memory_order_acquire);
		for (;;) {
			worker_lifecycle_state desired{};
			switch (current) {
			case worker_lifecycle_state::INIT:
			case worker_lifecycle_state::DRAINING:
			case worker_lifecycle_state::REQ_EXIT:
			case worker_lifecycle_state::EXITED:
				return false;
			case worker_lifecycle_state::STARTING:
				desired = worker_lifecycle_state::REQ_EXIT;
				break;
			case worker_lifecycle_state::RUNNING:
				desired = worker_lifecycle_state::DRAINING;
				break;
			default:
				desired = worker_lifecycle_state::REQ_EXIT;
				break;
			}
			if (state.compare_exchange_weak(current, desired, std::memory_order_acq_rel,
							std::memory_order_acquire)) {
				return desired == worker_lifecycle_state::DRAINING;
			}
		}
	}

	/** @return Current lifecycle state with acquire visibility. */
	[[nodiscard]] worker_lifecycle_state get_state() const noexcept
	{
		return state.load(std::memory_order_acquire);
	}

	/** @brief Reset lifecycle state before a new launch reservation. */
	void reset() noexcept
	{
		state.store(worker_lifecycle_state::INIT, std::memory_order_relaxed);
	}
};

static_assert(sizeof(worker_lifecycle_context) == 64, "worker_lifecycle_context must occupy exactly one cache line");
static_assert(alignof(worker_lifecycle_context) == 64, "worker_lifecycle_context must be cache-line aligned");

/**
 * @brief Enter RUNNING without overwriting a concurrent shutdown request.
 *
 * @param context Exact compact worker context entered by its owner.
 * @return RUNNING on the sole legal transition, cancellation when shutdown was
 *         already visible, or INVALID_START_STATE for malformed launch state.
 */
[[nodiscard]] inline worker_enter_running_result try_enter_worker_running(worker_lifecycle_context &context) noexcept
{
	if (context.try_transition(worker_lifecycle_state::STARTING, worker_lifecycle_state::RUNNING)) {
		return worker_enter_running_result::RUNNING;
	}

	const auto state = context.get_state();
	if (state == worker_lifecycle_state::REQ_EXIT || state == worker_lifecycle_state::EXITED) {
		context.set_state(worker_lifecycle_state::EXITED);
		return worker_enter_running_result::CANCELLED_BEFORE_RUNNING;
	}

	context.set_state(worker_lifecycle_state::EXITED);
	return worker_enter_running_result::INVALID_START_STATE;
}

}  // namespace kinetum::dp
