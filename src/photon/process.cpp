// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file process.cpp
 * @brief Child process management implementation.
 * @author Fleming Patel
 *
 * Implements linear process lifecycle ownership with:
 * - Graceful SIGTERM with bounded SIGKILL escalation
 * - Non-blocking process status checks
 * - Linear PID and reaping ownership
 *
 */

#include "src/photon/process.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <spawn.h>
#include <thread>
#include <vector>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/common/log.hpp"
#include "src/common/process_image.hpp"
#include "src/common/status.hpp"

/** @brief Process environment supplied by libc for child inheritance. */
extern char **environ;

namespace kinetum::photon
{

using kinetum::common::status;
using kinetum::common::status_code;

/** @brief Maximum accepted process-name length and diagnostic copy bound. */
constexpr std::size_t MAX_PROCESS_NAME_LENGTH = 64;

child_proc::~child_proc() noexcept
{
	if (state == process_state::RUNNING) {
		fail_stop_live_authority_();
	}
}

[[noreturn]] void child_proc::fail_stop_live_authority_() const noexcept
{
	std::array<char, MAX_PROCESS_NAME_LENGTH> printable_name{};
	const std::size_t name_size = std::min(name.size(), printable_name.size());
	for (std::size_t index = 0; index < name_size; ++index) {
		const unsigned char byte = static_cast<unsigned char>(name[index]);
		printable_name[index] =
			byte >= 0x20u && byte <= 0x7eu && byte != '\'' && byte != '\\' ? static_cast<char>(byte) : '?';
	}
	std::fprintf(stderr, "Photon process ownership violation: unreaped child name='%.*s' pid=%d\n",
		     static_cast<int>(name_size), printable_name.data(), pid);
	std::fflush(stderr);
	std::abort();
}

namespace
{

/** @brief Maximum interval requested between graceful-reap observations. */
constexpr auto TERMINATION_POLL_INTERVAL = std::chrono::milliseconds(100);

/** Child environment with storage that owns every pointer passed to spawn. */
struct child_environment {
	std::vector<std::string> values;  ///< Preserved non-loader environment entries.
	std::vector<char *> pointers;	  ///< Mutable POSIX view terminated by null.
};

/**
 * @param entry Borrowed environment entry in NAME=VALUE form.
 * @return true when the variable name starts with `LD_`.
 */
[[nodiscard]] bool is_dynamic_loader_environment(std::string_view entry) noexcept
{
	return entry.starts_with("LD_");
}

/** @return Owned environment strings and their POSIX pointer view, excluding dynamic-loader controls. */
[[nodiscard]] child_environment make_child_environment()
{
	child_environment result;
	if (environ != nullptr) {
		for (char **entry = environ; *entry != nullptr; ++entry) {
			const std::string_view value(*entry);
			if (!is_dynamic_loader_environment(value)) {
				result.values.emplace_back(value);
			}
		}
	}
	result.pointers.reserve(result.values.size() + 1);
	for (auto &value : result.values) {
		result.pointers.push_back(value.data());
	}
	result.pointers.push_back(nullptr);
	return result;
}

}  // namespace
using kinetum::common::status_or;

namespace
{

/**
 * @brief Map one posix_spawn failure into the platform status taxonomy.
 *
 * @param error_number POSIX error number returned directly by posix_spawn().
 * @param executable Exact executable path supplied to posix_spawn().
 * @return Detailed non-OK status.
 */
status spawn_error_status(int error_number, const std::string &executable)
{
	status_code code = status_code::INTERNAL_ERROR;
	switch (error_number) {
	case ENOENT:
	case ENOTDIR:
		code = status_code::NOT_FOUND;
		break;
	case EACCES:
	case EPERM:
		code = status_code::PERMISSION_DENIED;
		break;
	case E2BIG:
	case EAGAIN:
	case ENOMEM:
		code = status_code::RESOURCE_EXHAUSTED;
		break;
	default:
		break;
	}
	return status(code, "posix_spawn failed for exact process image",
		      executable + ": " + std::strerror(error_number));
}

/**
 * @brief Update child_proc state based on waitpid result.
 *
 * Interprets the status value returned by waitpid() and updates the
 * child_proc structure with the appropriate state and exit code.
 *
 * Exit code conventions:
 * - Normal exit: Actual exit code (0-255)
 * - Signal termination: 128 + signal number (e.g., 137 for SIGKILL)
 *
 * @param p The child process to update. Modified in-place with:
 *          - state: Set to exited, terminated, or killed
 *          - exit_code: Set based on exit status or signal
 * @param wstatus The raw status value from waitpid().
 * @param was_killed true if SIGKILL was explicitly sent by terminate_process,
 *                   used to distinguish intentional kills from external signals.
 *
 * @note This is an internal helper function, not exposed in the API.
 */
void update_state_from_wait(child_proc &p, int wstatus, bool was_killed)
{
	if (WIFEXITED(wstatus)) {
		p.exit_code = WEXITSTATUS(wstatus);
		p.state = process_state::EXITED;
	} else if (WIFSIGNALED(wstatus)) {
		p.exit_code = 128 + WTERMSIG(wstatus);	// Convention: 128 + signal number
		if (was_killed || WTERMSIG(wstatus) == SIGKILL) {
			p.state = process_state::KILLED;
		} else {
			p.state = process_state::TERMINATED;
		}
	} else {
		std::fputs("Photon received an unclassifiable child wait status\n", stderr);
		(void)std::fflush(stderr);
		std::abort();
	}
}

/**
 * @brief Reap a child after kill reports that its PID no longer exists.
 *
 * A child that has exited but has not been waited remains a zombie even though
 * `kill()` reports `ESRCH`. This helper preserves an actual wait status when
 * available and treats `ECHILD` as proof that another wait owner already
 * completed reaping.
 *
 * @param p Child whose PID was reported absent.
 * @param expected_state Terminal state used only when no wait status remains.
 * @param expected_exit_code Conservative exit code used only after `ECHILD`.
 * @param was_killed Whether a recovered signal status follows explicit
 *        SIGKILL.
 * @return OK after reaping or confirming `ECHILD`; INTERNAL_ERROR otherwise.
 */
status reap_missing_child(child_proc &p, process_state expected_state, int expected_exit_code, bool was_killed)
{
	for (;;) {
		int wstatus = 0;
		const pid_t result = waitpid(p.pid, &wstatus, WNOHANG);
		if (result > 0) {
			update_state_from_wait(p, wstatus, was_killed);
			return status::ok();
		}
		if (result == 0) {
			return status::internal_error("child PID disappeared from kill but remains unreaped");
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == ECHILD) {
			p.state = expected_state;
			p.exit_code = expected_exit_code;
			return status::ok();
		}
		return status::internal_error("waitpid after ESRCH failed: " + std::string(std::strerror(errno)));
	}
}

/**
 * @brief Block until an explicitly SIGKILLed child has been reaped.
 *
 * @param p Child that accepted SIGKILL.
 * @return OK with the actual signal status, or an explicit waitpid failure.
 */
status reap_killed_child(child_proc &p)
{
	for (;;) {
		int wstatus = 0;
		const pid_t result = waitpid(p.pid, &wstatus, 0);
		if (result > 0) {
			update_state_from_wait(p, wstatus, true);
			return status::ok();
		}
		if (result < 0 && errno == EINTR) {
			continue;
		}
		if (result < 0 && errno == ECHILD) {
			p.state = process_state::KILLED;
			p.exit_code = 128 + SIGKILL;
			return status::ok();
		}
		return status::internal_error("waitpid after SIGKILL failed: " + std::string(std::strerror(errno)));
	}
}

/**
 * @brief Spawn one validated exact-image argv vector.
 *
 * @param name Stable process role retained for diagnostics.
 * @param argv Exact executable and argument vector passed to `posix_spawn()`.
 * @return Running child authority or an explicit admission/spawn failure.
 */
status_or<child_proc> spawn_process_impl(const std::string &name, const std::vector<std::string> &argv)
{
	if (name.empty()) {
		return status(status_code::INVALID_ARGUMENT, "process name cannot be empty");
	}
	if (name.find('\0') != std::string::npos) {
		return status(status_code::INVALID_ARGUMENT, "process name must not contain an embedded NUL byte");
	}
	if (name.length() > MAX_PROCESS_NAME_LENGTH) {
		return status(status_code::INVALID_ARGUMENT, "process name too long");
	}
	if (argv.empty() || argv[0].empty()) {
		return status(status_code::INVALID_ARGUMENT, "argv must include a non-empty executable path");
	}
	for (const auto &arg : argv) {
		if (arg.find('\0') != std::string::npos) {
			return status(status_code::INVALID_ARGUMENT,
				      "argv elements must not contain embedded NUL bytes");
		}
	}
	const auto image_status = kinetum::common::validate_exact_process_image(std::filesystem::path(argv[0]), name);
	if (!image_status.is_ok()) {
		return image_status;
	}

	// Finish every allocating ownership record before the child exists. Once
	// posix_spawn() succeeds, moving this record is non-throwing, so no child can
	// escape without a retained PID and bounded diagnostic identity.
	child_proc p;
	p.name = name;

	std::vector<char *> exec_argv;
	exec_argv.reserve(argv.size() + 1);
	for (const auto &arg : argv) {
		exec_argv.push_back(const_cast<char *>(arg.c_str()));
	}
	exec_argv.push_back(nullptr);
	auto child_env = make_child_environment();

	pid_t pid = -1;
	const int spawn_result =
		::posix_spawn(&pid, argv[0].c_str(), nullptr, nullptr, exec_argv.data(), child_env.pointers.data());
	if (spawn_result != 0) {
		return spawn_error_status(spawn_result, argv[0]);
	}

	p.pid = pid;
	p.state = process_state::RUNNING;
	p.exit_code = -1;

	// Diagnostic formatting is not part of the child-ownership transaction.
	KINETUM_LOG_INFO("photon", "process.spawned", "spawned process '{}' (pid={})", name, pid);

	return p;
}

}  // namespace

// =============================================================================
// Process Operations
// =============================================================================

status_or<child_proc> spawn_process_argv(const std::string &name, const std::vector<std::string> &argv)
{
	return spawn_process_impl(name, argv);
}

status request_process_log_reopen(const child_proc &child)
{
	if (child.state != process_state::RUNNING) {
		return status::ok();
	}
	if (child.pid <= 0) {
		return status::failed_precondition("running child has no exact PID for log reopen");
	}
	if (::kill(child.pid, SIGUSR1) != 0) {
		return status::unavailable("failed to request child log reopen: " + std::string(std::strerror(errno)));
	}
	return status::ok();
}

status terminate_process(child_proc &p, int timeout_ms)
{
	if (timeout_ms < 0) {
		return status::invalid_argument("termination timeout must be nonnegative");
	}
	if (p.pid <= 0) {
		return status::ok();  // Nothing to terminate
	}

	if (p.state != process_state::RUNNING) {
		return status::ok();  // Already terminated
	}

	// First, check if process is still running
	auto running_or = check_process(p);
	if (running_or.is_ok() && !running_or.value()) {
		return status::ok();  // Already exited
	}
	// Only a reaped terminal observation ends cleanup. A running or failed
	// preflight leaves SIGTERM and the authoritative reap as the owner.

	// Send SIGTERM for graceful shutdown
	if (kill(p.pid, SIGTERM) != 0) {
		int err = errno;
		if (err == ESRCH) {
			return reap_missing_child(p, process_state::EXITED, -1, false);
		}
		return status(status_code::INTERNAL_ERROR, "kill(SIGTERM) failed: " + std::string(std::strerror(err)));
	}

	// Wait for graceful exit with timeout
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

	while (std::chrono::steady_clock::now() < deadline) {
		int wstatus = 0;
		pid_t result = waitpid(p.pid, &wstatus, WNOHANG);

		if (result < 0) {
			int err = errno;
			if (err == EINTR) {
				continue;
			}
			if (err == ECHILD) {
				// Another wait owner already reaped the child. No actual
				// exit status remains, so preserve that fact explicitly.
				p.state = process_state::TERMINATED;
				p.exit_code = -1;
				return status::ok();
			}
			return status(status_code::INTERNAL_ERROR,
				      "waitpid failed: " + std::string(std::strerror(err)));
		}

		if (result > 0) {
			// Process exited
			update_state_from_wait(p, wstatus, false);
			return status::ok();
		}

		// Never request sleep beyond the remaining graceful interval.
		const auto sleep_deadline =
			std::min(deadline, std::chrono::steady_clock::now() + TERMINATION_POLL_INTERVAL);
		std::this_thread::sleep_until(sleep_deadline);
	}

	// Timeout expired; SIGKILL and its blocking reap remain one ownership edge.
	if (kill(p.pid, SIGKILL) != 0) {
		int err = errno;
		if (err == ESRCH) {
			return reap_missing_child(p, process_state::KILLED, 128 + SIGKILL, true);
		}
		return status(status_code::INTERNAL_ERROR, "kill(SIGKILL) failed: " + std::string(std::strerror(err)));
	}

	// SIGKILL has no userspace cleanup phase. Once accepted, waitpid is the
	// ownership transfer that prevents a zombie; returning before that point
	// would falsely report complete process cleanup.
	return reap_killed_child(p);
}

status_or<bool> check_process(child_proc &p)
{
	if (p.pid <= 0) {
		return false;
	}

	if (p.state != process_state::RUNNING) {
		return false;
	}

	int wstatus = 0;
	pid_t result = -1;
	do {
		result = waitpid(p.pid, &wstatus, WNOHANG);
	} while (result < 0 && errno == EINTR);

	if (result < 0) {
		if (errno == ECHILD) {
			// ECHILD is the only error that proves no reap remains for this
			// authority. The actual exit status is no longer available.
			p.state = process_state::EXITED;
			p.exit_code = -1;
			return false;
		}
		return status::internal_error("check_process waitpid failed for '" + p.name +
					      "': " + std::string(std::strerror(errno)));
	}

	if (result == 0) {
		// Still running
		return true;
	}

	// Process exited
	update_state_from_wait(p, wstatus, false);
	return false;
}

}  // namespace kinetum::photon
