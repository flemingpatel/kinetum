// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_photon_process.cpp
 * @brief Process ownership and cleanup tests for the Photon supervisor.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/common/status.hpp"
#include "src/photon/process.hpp"

namespace kinetum::photon
{
namespace
{

namespace fs = std::filesystem;
using kinetum::common::status_code;

/**
 * @brief Await a child exit through the production nonblocking observer.
 *
 * @param child Sole process authority to observe and reap.
 * @param timeout Maximum test wait.
 * @return true after exact reaping, false at the deadline, or the observation
 *         error returned by `check_process()`.
 */
kinetum::common::status_or<bool> await_child_exit(child_proc &child, std::chrono::milliseconds timeout)
{
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	for (;;) {
		auto running_or = check_process(child);
		if (!running_or.is_ok()) {
			return running_or.error();
		}
		if (!running_or.value()) {
			return true;
		}
		const auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			return false;
		}
		std::this_thread::sleep_until(std::min(deadline, now + std::chrono::milliseconds(10)));
	}
}

/** @brief Destroy one short-lived exited child without consuming its wait status. */
void destroy_exited_unreaped_child()
{
	int exit_pipe[2] = {-1, -1};
	if (pipe(exit_pipe) != 0) {
		_exit(120);
	}
	const pid_t child = fork();
	if (child < 0) {
		(void)close(exit_pipe[0]);
		(void)close(exit_pipe[1]);
		_exit(121);
	}
	if (child == 0) {
		(void)close(exit_pipe[0]);
		(void)close(exit_pipe[1]);
		_exit(0);
	}
	(void)close(exit_pipe[1]);
	char byte = '\0';
	ssize_t observed = -1;
	do {
		observed = read(exit_pipe[0], &byte, sizeof(byte));
	} while (observed < 0 && errno == EINTR);
	(void)close(exit_pipe[0]);
	if (observed != 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, nullptr, 0);
		_exit(122);
	}

	child_proc unreaped;
	unreaped.pid = child;
	unreaped.name = "exited-unreaped";
	unreaped.state = process_state::RUNNING;
}

/**
 * @brief Resolve one fixed system test executable to its canonical path.
 * @param name Filename expected under `/usr/bin` on the Linux test host.
 * @return Canonical absolute process-image path.
 */
std::string canonical_system_image(std::string_view name)
{
	std::error_code error;
	const fs::path image = fs::canonical(fs::path("/usr/bin") / fs::path(name), error);
	EXPECT_FALSE(error) << error.message();
	return image.string();
}

/** @brief Test-scoped environment mutation with exact restoration. */
class scoped_environment_variable {
    public:
	/**
	 * @brief Install one temporary process-environment value.
	 * @param name Exact variable name.
	 * @param value Value installed for this scope.
	 */
	scoped_environment_variable(std::string name, std::string value)
		: name_(std::move(name))
	{
		const char *previous = ::getenv(name_.c_str());
		if (previous != nullptr) {
			had_previous_ = true;
			previous_ = previous;
		}
		valid_ = ::setenv(name_.c_str(), value.c_str(), 1) == 0;
	}

	/** @brief Restore the exact prior process-environment state. */
	~scoped_environment_variable()
	{
		if (!valid_) {
			return;
		}
		if (had_previous_) {
			(void)::setenv(name_.c_str(), previous_.c_str(), 1);
		} else {
			(void)::unsetenv(name_.c_str());
		}
	}

	scoped_environment_variable(const scoped_environment_variable &) = delete;
	scoped_environment_variable &operator=(const scoped_environment_variable &) = delete;

	/** @return true when the temporary value was installed. */
	[[nodiscard]] bool valid() const noexcept
	{
		return valid_;
	}

    private:
	std::string name_;	///< Exact variable name.
	std::string previous_;	///< Prior value when one existed.
	bool had_previous_{};	///< Whether the parent already carried the variable.
	bool valid_{};		///< Whether the scoped mutation succeeded.
};

/** @brief Argv-based spawning never routes arguments through a shell. */
TEST(photon_process, spawn_process_argv_does_not_shell_interpret_arguments)
{
	auto process_or = spawn_process_argv("argv-test", std::vector<std::string>{canonical_system_image("true"),
										   "ignored; exit 77"});
	ASSERT_TRUE(process_or.is_ok()) << process_or.error().message();

	auto process = std::move(process_or).value();
	auto waited_or = await_child_exit(process, std::chrono::seconds(5));
	ASSERT_TRUE(waited_or.is_ok()) << waited_or.error().message();
	EXPECT_TRUE(waited_or.value());
	EXPECT_EQ(process.state, process_state::EXITED);
	EXPECT_EQ(process.exit_code, 0);
}

/** @brief Child construction removes loader controls but preserves ordinary values. */
TEST(photon_process, spawn_process_argv_strips_dynamic_loader_environment_only)
{
	scoped_environment_variable loader_control("LD_KINETUM_PHOTON_ENVIRONMENT_TEST", "removed");
	scoped_environment_variable ordinary_value("KINETUM_LD_PHOTON_ENVIRONMENT_TEST", "preserved");
	ASSERT_TRUE(loader_control.valid());
	ASSERT_TRUE(ordinary_value.valid());

	const auto printenv = canonical_system_image("printenv");
	auto loader_process_or = spawn_process_argv(
		"loader-env-test", std::vector<std::string>{printenv, "LD_KINETUM_PHOTON_ENVIRONMENT_TEST"});
	ASSERT_TRUE(loader_process_or.is_ok()) << loader_process_or.error().message();
	auto loader_process = std::move(loader_process_or).value();
	auto loader_wait_or = await_child_exit(loader_process, std::chrono::seconds(5));
	ASSERT_TRUE(loader_wait_or.is_ok()) << loader_wait_or.error().message();
	EXPECT_TRUE(loader_wait_or.value());
	EXPECT_EQ(loader_process.exit_code, 1);

	auto ordinary_process_or = spawn_process_argv(
		"ordinary-env-test", std::vector<std::string>{printenv, "KINETUM_LD_PHOTON_ENVIRONMENT_TEST"});
	ASSERT_TRUE(ordinary_process_or.is_ok()) << ordinary_process_or.error().message();
	auto ordinary_process = std::move(ordinary_process_or).value();
	auto ordinary_wait_or = await_child_exit(ordinary_process, std::chrono::seconds(5));
	ASSERT_TRUE(ordinary_wait_or.is_ok()) << ordinary_wait_or.error().message();
	EXPECT_TRUE(ordinary_wait_or.value());
	EXPECT_EQ(ordinary_process.exit_code, 0);
}

/** @brief Spawn rejects malformed arguments before process effects. */
TEST(photon_process, spawn_rejects_malformed_arguments)
{
	auto empty_argv = spawn_process_argv("bad", std::vector<std::string>{});
	ASSERT_FALSE(empty_argv.is_ok());
	EXPECT_EQ(empty_argv.error().code(), status_code::INVALID_ARGUMENT);

	auto empty_executable = spawn_process_argv("bad", std::vector<std::string>{""});
	ASSERT_FALSE(empty_executable.is_ok());
	EXPECT_EQ(empty_executable.error().code(), status_code::INVALID_ARGUMENT);

	auto relative_executable = spawn_process_argv("bad", std::vector<std::string>{"true"});
	ASSERT_FALSE(relative_executable.is_ok());
	EXPECT_EQ(relative_executable.error().code(), status_code::INVALID_ARGUMENT);

	const std::string embedded_nul("argument\0tail", 13);
	auto truncated_argument =
		spawn_process_argv("bad", std::vector<std::string>{canonical_system_image("true"), embedded_nul});
	ASSERT_FALSE(truncated_argument.is_ok());
	EXPECT_EQ(truncated_argument.error().code(), status_code::INVALID_ARGUMENT);
}

/** @brief A live record cannot discard an exited but unreaped child authority. */
TEST(photon_process, exited_unreaped_child_destruction_fails_stop_with_identity)
{
	EXPECT_DEATH(destroy_exited_unreaped_child(),
		     "Photon process ownership violation: unreaped child name='exited-unreaped' pid=[1-9][0-9]*");
}

/** @brief Moved-from and reaped records destruct without retaining authority. */
TEST(photon_process, moved_from_and_terminal_records_are_safe_to_destroy)
{
	child_proc source;
	source.pid = 123;
	source.name = "moved";
	source.state = process_state::RUNNING;
	child_proc destination(std::move(source));
	EXPECT_EQ(source.pid, -1);
	EXPECT_EQ(source.state, process_state::NOT_STARTED);
	destination.state = process_state::EXITED;

	child_proc terminal;
	terminal.pid = 456;
	terminal.name = "terminal";
	terminal.state = process_state::TERMINATED;
}

/** @brief Graceful and forced termination leave no waitable zombie. */
TEST(photon_process, terminate_process_reaps_graceful_and_forced_children_before_success)
{
	auto process_or =
		spawn_process_argv("reap-test", std::vector<std::string>{canonical_system_image("sleep"), "30"});
	ASSERT_TRUE(process_or.is_ok()) << process_or.error().message();

	auto process = std::move(process_or).value();
	const auto pid = static_cast<pid_t>(process.pid);
	const auto terminate_status = terminate_process(process, 1000);
	if (!terminate_status.is_ok()) {
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, nullptr, 0);
		FAIL() << terminate_status.message();
	}
	EXPECT_FALSE(process.is_running());

	int wait_status = 0;
	errno = 0;
	EXPECT_EQ(waitpid(pid, &wait_status, WNOHANG), static_cast<pid_t>(-1));
	EXPECT_EQ(errno, ECHILD) << "successful termination must consume the child wait status";

	int ready_pipe[2] = {-1, -1};
	ASSERT_EQ(pipe(ready_pipe), 0);
	const pid_t forced_pid = fork();
	if (forced_pid < 0) {
		(void)close(ready_pipe[0]);
		(void)close(ready_pipe[1]);
		FAIL() << "fork failed for forced-termination child";
	}
	if (forced_pid == 0) {
		(void)close(ready_pipe[0]);
		struct sigaction action{};
		action.sa_handler = SIG_IGN;
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGTERM, &action, nullptr) != 0) {
			_exit(126);
		}
		const char ready = 'R';
		if (write(ready_pipe[1], &ready, sizeof(ready)) != static_cast<ssize_t>(sizeof(ready))) {
			_exit(126);
		}
		(void)close(ready_pipe[1]);
		for (;;) {
			pause();
		}
	}

	(void)close(ready_pipe[1]);
	char ready = '\0';
	const ssize_t ready_bytes = read(ready_pipe[0], &ready, sizeof(ready));
	(void)close(ready_pipe[0]);
	if (ready_bytes != static_cast<ssize_t>(sizeof(ready)) || ready != 'R') {
		(void)kill(forced_pid, SIGKILL);
		(void)waitpid(forced_pid, nullptr, 0);
		FAIL() << "forced-termination child did not establish its SIGTERM disposition";
	}

	child_proc forced;
	forced.pid = forced_pid;
	forced.name = "forced-reap-test";
	forced.state = process_state::RUNNING;
	forced.exit_code = -1;
	const auto forced_status = terminate_process(forced, 0);
	if (!forced_status.is_ok()) {
		(void)kill(forced_pid, SIGKILL);
		(void)waitpid(forced_pid, nullptr, 0);
		FAIL() << forced_status.message();
	}
	EXPECT_EQ(forced.state, process_state::KILLED);
	EXPECT_EQ(forced.exit_code, 128 + SIGKILL);

	wait_status = 0;
	errno = 0;
	EXPECT_EQ(waitpid(forced_pid, &wait_status, WNOHANG), static_cast<pid_t>(-1));
	EXPECT_EQ(errno, ECHILD) << "forced termination must consume the child wait status";
}

}  // namespace
}  // namespace kinetum::photon
