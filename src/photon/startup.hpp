// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file startup.hpp
 * @brief Transactional DP-then-CP startup under exact readiness gates.
 * @author Fleming Patel
 *
 * Photon owns one ordered startup transaction:
 *
 * 1. spawn DP;
 * 2. observe exact CONTROL_READY;
 * 3. spawn CP with the verified bootstrap snapshot and plan identity;
 * 4. observe exact PACKET_READY;
 * 5. transfer both sole child/reaping authorities to ordinary supervision.
 *
 * Failure or cancellation before the final gate terminates and reaps CP before
 * DP. Restart policy belongs to the pair owner after the startup transaction;
 * no restart occurs inside this function.
 *
 * The component is cold-path orchestration. It performs process operations,
 * gRPC observation, filesystem-path shape validation, string construction, and
 * bounded waits. It must never execute on a packet worker.
 *
 * @par Thread Safety
 * One startup thread owns a transaction, observer, and process controller.
 * Distinct transactions may use distinct controller instances concurrently.
 * A shutdown predicate must synchronize any state it reads.
 */

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "src/common/status.hpp"
#include "src/common/log_options.hpp"
#include "src/common/status_or.hpp"
#include "src/photon/process.hpp"
#include "src/photon/readiness.hpp"

namespace kinetum::photon
{

/** @brief Grace interval used when rolling back an incomplete startup. */
inline constexpr int STARTUP_TERMINATE_TIMEOUT_MS = 10'000;

/** @brief Pair-wide policy for an unexpected supervised-child exit. */
enum class restart_policy : uint8_t {
	NEVER,	    ///< Report the service loss after complete pair cleanup.
	ON_FAILURE  ///< Replace the pair when an observed child exit is nonzero.
};

/**
 * @brief Complete immutable input for one supervised startup transaction.
 *
 * `dp_executable` and `cp_executable` are exact canonical sibling images
 * resolved before the transaction. `bundle_root`, `bootstrap_snapshot_path`,
 * and `plan_content_hash` come from one admitted runtime bundle. DP re-admits
 * that complete root independently; CP receives the exact bootstrap artifact
 * and plan identity. The pair owner retains this complete value unchanged for
 * any policy-authorized replacement.
 */
struct supervised_startup_spec {
	std::string dp_executable;					///< Canonical absolute DP process image.
	std::string cp_executable;					///< Canonical absolute CP process image.
	std::string bundle_root;					///< Canonical verified runtime-bundle root.
	std::string dp_endpoint;					///< Shared DP listen/CP client endpoint.
	std::string cp_listen;						///< CP listen endpoint.
	std::string config_store_dir;					///< Absolute CP durable-state directory.
	std::string bootstrap_snapshot_path;				///< Canonical verified ConfigSnapshot path.
	std::string plan_content_hash;					///< Exact lowercase DeploymentPlan SHA-256.
	readiness_wait_policy control_wait{CONTROL_READY_WAIT_POLICY};	///< First exact readiness gate.
	readiness_wait_policy packet_wait{PACKET_READY_WAIT_POLICY};	///< Second exact readiness gate.
	int termination_timeout_ms{STARTUP_TERMINATE_TIMEOUT_MS};	///< Rollback SIGTERM grace interval.
	kinetum::common::log_options logging;  ///< Exact immutable settings forwarded to both children.
};

/**
 * @brief Both children after the exact PACKET_READY gate has closed.
 *
 * Each child remains the sole observation/termination authority for its PID. Moving
 * this value transfers that ownership into Photon's ordinary supervision loop.
 */
struct supervised_children {
	child_proc dp;		    ///< Running and exact-ready Data Plane child.
	child_proc cp;		    ///< Running Control Plane child that completed bootstrap.
	uint32_t restart_count{0};  ///< Number of complete pair generations started after the first.
};

/**
 * @brief Process operations required by transactional startup.
 *
 * The interface makes ordering and rollback directly testable without forking.
 * Production delegates every operation to the single process-management
 * authority in `process.cpp`.
 */
class startup_process_controller {
    public:
	/** @brief Release controller-owned implementation resources. */
	virtual ~startup_process_controller() = default;

	/**
	 * @brief Spawn one direct-argv child.
	 *
	 * @param name Stable child role used in diagnostics.
	 * @param argv Direct executable and argument vector.
	 * @return Sole child authority, or a spawn error.
	 */
	[[nodiscard]] virtual kinetum::common::status_or<child_proc>
	spawn_argv(const std::string &name, const std::vector<std::string> &argv) = 0;

	/**
	 * @brief Poll and reap one child when it has exited.
	 *
	 * @param child Sole child authority to update.
	 * @return `true` while the child remains running, `false` after a proven
	 *         exit, or the process-observation failure.
	 */
	[[nodiscard]] virtual kinetum::common::status_or<bool> check(child_proc &child) = 0;

	/**
	 * @brief Terminate and reap one child through the shared process authority.
	 *
	 * @param child Sole child authority to terminate.
	 * @param timeout_ms Nonnegative graceful termination interval.
	 * @return OK after reaping or confirming prior reaping; error otherwise.
	 */
	[[nodiscard]] virtual kinetum::common::status terminate(child_proc &child, int timeout_ms) = 0;
};

/** @brief Production adapter over Photon's POSIX child-process functions. */
class posix_startup_process_controller final : public startup_process_controller {
    public:
	/** @copydoc startup_process_controller::spawn_argv */
	[[nodiscard]] kinetum::common::status_or<child_proc> spawn_argv(const std::string &name,
									const std::vector<std::string> &argv) override;

	/** @copydoc startup_process_controller::check */
	[[nodiscard]] kinetum::common::status_or<bool> check(child_proc &child) override;

	/** @copydoc startup_process_controller::terminate */
	[[nodiscard]] kinetum::common::status terminate(child_proc &child, int timeout_ms) override;
};

/** @brief Predicate returning true when supervisor shutdown is requested. */
using startup_shutdown_check = std::function<bool()>;

/**
 * @brief Validate all startup authority and timing before child construction.
 *
 * @param spec Candidate startup transaction input.
 * @return OK when every required string/path/hash is present, both readiness
 *         policies are coherent, and the termination timeout is positive;
 *         INVALID_ARGUMENT otherwise.
 *
 * @par Side Effects
 * None. This function does not inspect filesystem contents or create children.
 */
[[nodiscard]] kinetum::common::status validate_supervised_startup_spec(const supervised_startup_spec &spec);

/**
 * @brief Execute one DP-then-CP startup transaction.
 *
 * Startup succeeds only after exact CONTROL_READY followed by exact
 * PACKET_READY. Progress checks reap children that exit during either gate.
 * Every failure or shutdown request rolls back CP before DP. Ordinary restart
 * supervision is intentionally outside this function and
 * may begin only after the returned value transfers both child authorities.
 *
 * @param spec Complete validated startup input.
 * @param observer Health observer bound to `spec.dp_endpoint`.
 * @param processes Process spawn/check/terminate authority.
 * @param shutdown_requested Optional synchronized shutdown predicate.
 * @return Both running children after exact packet readiness, or the original
 *         validation, spawn, readiness, liveness, cancellation, or timeout
 *         error. A first cleanup failure is appended to status details and
 *         retried by the transaction owner; a second failure terminates before
 *         child authority can be discarded.
 *
 * @par Thread Safety
 * One startup thread must exclusively own all arguments for the duration of
 * this call.
 */
[[nodiscard]] kinetum::common::status_or<supervised_children>
start_supervised_children(const supervised_startup_spec &spec, dp_health_observer &observer,
			  startup_process_controller &processes, const startup_shutdown_check &shutdown_requested = {});

/**
 * @brief Scope-bound owner of one packet-ready supervised pair.
 *
 * Construction transfers both child/reaping authorities, the exact admitted
 * startup specification, and one pair-wide restart policy without allocating.
 * Explicit `stop()` reports cleanup failures. If an exception or early return
 * abandons an armed owner, destruction still attempts CP-before-DP termination
 * through the same process authority. A failed final attempt terminates rather
 * than discarding unproven child/reaping authority. This closes the interval
 * between startup handoff and ordinary supervision without creating a second
 * cleanup path.
 *
 * The process controller must outlive this owner. The type is deliberately
 * immovable so references to its child records and retained specification
 * remain stable throughout the supervision loop and pair replacement.
 */
class supervised_pair_owner {
    public:
	/**
	 * @brief Take sole ownership of one packet-ready pair.
	 *
	 * @param children Exact children returned by `start_supervised_children()`.
	 * @param startup_spec Exact admitted specification retained for replacement.
	 * @param policy Sole pair-wide restart policy.
	 * @param processes Sole process-operation authority.
	 */
	supervised_pair_owner(supervised_children &&children, supervised_startup_spec &&startup_spec,
			      restart_policy policy, startup_process_controller &processes) noexcept;

	/** @brief Owners cannot share child/reaping authority. */
	supervised_pair_owner(const supervised_pair_owner &) = delete;

	/** @brief Owners cannot replace child/reaping authority. */
	supervised_pair_owner &operator=(const supervised_pair_owner &) = delete;

	/** @brief Stable child references make the owner immovable. */
	supervised_pair_owner(supervised_pair_owner &&) = delete;

	/** @brief Stable child references make the owner move-assignment inapplicable. */
	supervised_pair_owner &operator=(supervised_pair_owner &&) = delete;

	/** @brief Attempt cleanup when armed; fail stop if reaping remains unproven. */
	~supervised_pair_owner() noexcept;

	/** @return Mutable pair authority for liveness and restart supervision. */
	[[nodiscard]] supervised_children &children() noexcept;

	/**
	 * @brief Resolve one observed child exit as an indivisible pair operation.
	 *
	 * At least one child must already be terminal. The old pair is always reaped
	 * CP before DP. OK means exclusively that policy authorized replacement and
	 * the new pair completed DP CONTROL_READY, CP bootstrap, and DP PACKET_READY.
	 * A policy-declined replacement is FAILED_PRECONDITION after cleanup.
	 *
	 * @param observer Health observer bound to the retained DP endpoint.
	 * @param shutdown_requested Optional synchronized cancellation predicate.
	 * @return OK only with a complete packet-ready replacement pair; otherwise
	 *         the policy, cleanup, startup, cancellation, or count failure.
	 */
	[[nodiscard]] kinetum::common::status
	resolve_observed_exit(dp_health_observer &observer, const startup_shutdown_check &shutdown_requested = {});

	/**
	 * @brief Terminate and reap the owned pair exactly once.
	 *
	 * A successful call disarms destructor cleanup. A failed call retains
	 * ownership so destruction makes one final cleanup attempt.
	 *
	 * @return OK when already stopped or after complete CP-before-DP cleanup;
	 *         otherwise the aggregate termination failure.
	 */
	[[nodiscard]] kinetum::common::status stop();

    private:
	supervised_children children_;		 ///< Sole mutable pair authority.
	supervised_startup_spec startup_spec_;	 ///< Exact immutable replacement input.
	restart_policy policy_;			 ///< Sole pair-wide restart policy.
	startup_process_controller &processes_;	 ///< Non-owning process-operation authority.
	bool armed_{true};			 ///< Whether destruction must attempt cleanup.
};

}  // namespace kinetum::photon
