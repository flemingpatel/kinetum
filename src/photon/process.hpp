// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file process.hpp
 * @brief Child process management for Photon supervisor.
 * @author Fleming Patel
 *
 * Provides linear process lifecycle ownership with:
 * - Graceful termination with bounded SIGKILL escalation
 * - Process state tracking
 * - Exit code capture
 *
 * Thread Safety:
 * - Distinct child records may be operated independently
 * - One record has one owner and must not receive concurrent access
 *
 */

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "src/common/status_or.hpp"

namespace kinetum::photon
{

// =============================================================================
// Process State
// =============================================================================

/**
 * @brief Process lifecycle states.
 */
enum class process_state : uint8_t {
	NOT_STARTED,  ///< Process has not been started
	RUNNING,      ///< Record owns a running or not-yet-reaped child
	TERMINATED,   ///< Termination completed without an observed SIGKILL status
	KILLED,	      ///< Process was killed (SIGKILL)
	EXITED	      ///< Process exited on its own
};
// =============================================================================
// Process Information
// =============================================================================

/**
 * @brief Information about a child process.
 *
 * One process owner mutates and observes this record. Moving it transfers the
 * PID and reaping obligation; concurrent access to one record is forbidden.
 */
struct child_proc {
	int pid{-1};					  ///< Process ID (-1 if not started).
	std::string name;				  ///< Human-readable process name.
	process_state state{process_state::NOT_STARTED};  ///< Owner-observed lifecycle state.
	int exit_code{-1};				  ///< Exit code, or -1 when unavailable.

	/** @brief Construct an empty, non-owning process record. */
	child_proc() = default;

	/**
	 * @brief Destroy one non-owning or already reaped process record.
	 *
	 * A record still classified RUNNING retains the PID/reaping obligation even
	 * when the operating-system child has already exited. Destruction emits one
	 * bounded diagnostic and aborts rather than silently discarding authority.
	 */
	~child_proc() noexcept;

	/**
	 * @brief Move one complete process and reaping authority.
	 *
	 * @param other Process record whose authority is transferred.
	 */
	child_proc(child_proc &&other) noexcept
		: pid(other.pid)
		, name(std::move(other.name))
		, state(other.state)
		, exit_code(other.exit_code)
	{
		other.relinquish_moved_authority_();
	}

	/**
	 * @brief Replace a non-live record with one transferred process authority.
	 *
	 * @param other Process record whose authority is transferred.
	 * @return This updated process record.
	 */
	child_proc &operator=(child_proc &&other) noexcept
	{
		if (this != &other) {
			if (is_running()) {
				fail_stop_live_authority_();
			}
			pid = other.pid;
			name = std::move(other.name);
			state = other.state;
			exit_code = other.exit_code;
			other.relinquish_moved_authority_();
		}
		return *this;
	}

	/** @brief Process records cannot share one PID/reaping authority. */
	child_proc(const child_proc &) = delete;

	/** @brief Process records cannot be copy-assigned. */
	child_proc &operator=(const child_proc &) = delete;

	/**
	 * @brief Check whether this record retains unresolved child authority.
	 *
	 * RUNNING remains set until the owner observes and reaps an exit, so
	 * true is conservative ownership state rather than a fresh kernel-liveness
	 * observation.
	 *
	 * @return true only while the retained state is RUNNING.
	 */
	[[nodiscard]] bool is_running() const noexcept
	{
		return state == process_state::RUNNING;
	}

    private:
	/** @brief Emit bounded ownership evidence and abort before losing a live PID. */
	[[noreturn]] void fail_stop_live_authority_() const noexcept;

	/** @brief Leave a moved-from record with no process or reaping authority. */
	void relinquish_moved_authority_() noexcept
	{
		pid = -1;
		name.clear();
		state = process_state::NOT_STARTED;
		exit_code = -1;
	}
};

// =============================================================================
// Process Operations
// =============================================================================

/**
 * @brief Spawn a new child process from one exact direct argv vector.
 *
 * The executable path in argv[0] must already be absolute, lexically
 * normalized, canonical, symlink-free, regular, and executable. The function
 * invokes `posix_spawn()` with that exact path: it never executes a shell,
 * searches PATH, consults the current working directory, or repairs the path.
 * Every process name and argv element must be free of embedded NUL bytes.
 * Shell metacharacters in later arguments remain ordinary argument bytes.
 *
 * @param name Human-readable process name (max 64 chars).
 * @param argv Exact executable path plus arguments.
 *
 * @return Sole child authority on success; an exact path-admission error,
 *         INVALID_ARGUMENT for malformed process metadata, or an explicit
 *         `posix_spawn()` failure.
 *
 * @warning The spawned process inherits standard I/O and a snapshot of the
 *          parent's environment after every variable whose name begins
 *          `LD_` has been removed. This prevents environment-controlled
 *          dynamic-loader redirection at the process-launch boundary.
 * @warning The returned record has no implicit process-termination destructor.
 *          Its owner must reap it through observation/termination or immediately
 *          transfer it into the supervised startup/pair owner.
 */
kinetum::common::status_or<child_proc> spawn_process_argv(const std::string &name,
							  const std::vector<std::string> &argv);

/**
 * @brief Terminate a child process with bounded SIGTERM-to-SIGKILL escalation.
 *
 * Implements a two-phase termination strategy:
 * 1. Send SIGTERM and wait up to timeout_ms for graceful exit
 * 2. If timeout expires, send SIGKILL for immediate termination
 *
 * The child_proc structure is updated with the final state and exit code.
 * Every successful path either reaps the child with `waitpid()` or confirms
 * that another owner already reaped it with `ECHILD`. After SIGKILL the
 * function performs the mandatory blocking reap; it never labels an
 * unreaped child as terminated merely because a polling deadline elapsed.
 *
 * @param p The child process to terminate. Updated in-place with:
 *          - state: process_state::TERMINATED (SIGTERM) or KILLED (SIGKILL)
 *          - exit_code: Actual exit code, 128 + signal number, or -1 when
 *            another wait owner consumed the status before this call.
 * @param timeout_ms Maximum time to wait for graceful exit in milliseconds.
 *
 * @return status::ok() on successful termination (graceful or forced).
 *         Error status if kill() or waitpid() fails unexpectedly.
 *
 * @warning This function blocks for up to timeout_ms before SIGKILL and then
 *          waits until the kernel reports the forced child exit.
 *
 * @note Thread-safe: Can be called concurrently for different processes.
 * @note If process already exited, returns success immediately.
 *
 * @see spawn_process_argv For creating processes.
 * @see check_process For non-blocking status checks.
 */
kinetum::common::status terminate_process(child_proc &p, int timeout_ms);

/**
 * @brief Request log reopen from one still-owned child without changing its lifecycle.
 * @param child Sole unreaped process authority; an already retired child is a no-op.
 * @return OK after SIGUSR1 submission or prior retirement; a native failure otherwise.
 */
[[nodiscard]] kinetum::common::status request_process_log_reopen(const child_proc &child);

/**
 * @brief Check if a process is still running and update its state.
 *
 * Performs a non-blocking status check using waitpid() with WNOHANG.
 * If the process has exited, the child_proc structure is updated with
 * the exit status.
 *
 * @param p The child process to check. Updated in-place with:
 *          - state: Updated to exited/terminated/killed if process ended
 *          - exit_code: Set if process has exited
 *
 * @return `true` if the process is still running, `false` if it has exited or
 *         was never started, or INTERNAL_ERROR when `waitpid()` cannot prove
 *         either state. An error leaves RUNNING unchanged so termination still
 *         owns the child.
 *
 * @note Thread-safe: Can be called concurrently for different processes.
 * @note This function does not block; returns immediately.
 *
 * @see terminate_process For forcing process exit.
 */
[[nodiscard]] kinetum::common::status_or<bool> check_process(child_proc &p);

}  // namespace kinetum::photon
