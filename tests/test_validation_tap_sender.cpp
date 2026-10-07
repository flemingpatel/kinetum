// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_validation_tap_sender.cpp
 * @brief Production-image tests for native TAP sender signal admission.
 * @author Fleming Patel
 *
 * These tests launch the exact built validation sender and exercise only its
 * pre-socket CLI and signal-admission boundaries. No TAP interface or packet
 * traffic is created.
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef KINETUM_VALIDATION_TAP_SENDER_PATH
#error "KINETUM_VALIDATION_TAP_SENDER_PATH must name the exact native sender image"
#endif

namespace kinetum::validation
{

namespace
{

/** Maximum lifetime of one exact sender child in this test process. */
constexpr unsigned int TEST_CHILD_TIMEOUT_SECONDS = 10u;

/** @brief Complete result from one exact native-sender child process. */
struct sender_result {
	int exit_code{-1};   ///< Normal process exit code, or -1 after abnormal exit.
	std::string output;  ///< Complete merged stdout and stderr bytes.
};

/** Exact output destination for one native-sender child. */
enum class sender_output_destination : uint8_t {
	CAPTURE,  ///< Capture merged stdout/stderr.
	FULL,	  ///< Route stdout/stderr to /dev/full.
};

/**
 * @brief Launch the native sender and capture its complete diagnostic stream.
 *
 * @param arguments Arguments following the exact sender image path.
 * @param block_generation_signal True to block SIGUSR1 in the child before
 * exec, matching the Python generation-owner choreography.
 * @param destination Capture output or route it to /dev/full.
 * @return Child exit status and merged output.
 */
[[nodiscard]] sender_result run_sender(const std::vector<std::string> &arguments, bool block_generation_signal,
				       sender_output_destination destination)
{
	int output_pipe[2]{};
	if (::pipe(output_pipe) != 0) {
		return {};
	}

	std::vector<std::string> storage;
	storage.reserve(arguments.size() + 1u);
	storage.emplace_back(KINETUM_VALIDATION_TAP_SENDER_PATH);
	storage.insert(storage.end(), arguments.begin(), arguments.end());
	std::vector<char *> argv;
	argv.reserve(storage.size() + 1u);
	for (auto &argument : storage) {
		argv.push_back(argument.data());
	}
	argv.push_back(nullptr);

	const pid_t child = ::fork();
	if (child < 0) {
		(void)::close(output_pipe[0]);
		(void)::close(output_pipe[1]);
		return {};
	}
	if (child == 0) {
		if (block_generation_signal) {
			sigset_t blocked{};
			if (::sigemptyset(&blocked) != 0 || ::sigaddset(&blocked, SIGUSR1) != 0 ||
			    ::sigprocmask(SIG_BLOCK, &blocked, nullptr) != 0) {
				::_exit(126);
			}
		}
		(void)::close(output_pipe[0]);
		int output_descriptor = output_pipe[1];
		if (destination == sender_output_destination::FULL) {
			output_descriptor = ::open("/dev/full", O_WRONLY | O_CLOEXEC);
			if (output_descriptor < 0) {
				::_exit(126);
			}
		}
		if (::dup2(output_descriptor, STDOUT_FILENO) < 0 || ::dup2(output_descriptor, STDERR_FILENO) < 0) {
			::_exit(126);
		}
		if (output_descriptor != output_pipe[1]) {
			(void)::close(output_descriptor);
		}
		(void)::close(output_pipe[1]);
		(void)::alarm(TEST_CHILD_TIMEOUT_SECONDS);
		::execv(KINETUM_VALIDATION_TAP_SENDER_PATH, argv.data());
		::_exit(127);
	}

	(void)::close(output_pipe[1]);
	sender_result result;
	char buffer[512];
	for (;;) {
		const ssize_t count = ::read(output_pipe[0], buffer, sizeof(buffer));
		if (count > 0) {
			result.output.append(buffer, static_cast<std::size_t>(count));
			continue;
		}
		if (count < 0 && errno == EINTR) {
			continue;
		}
		break;
	}
	(void)::close(output_pipe[0]);

	int wait_status = 0;
	pid_t waited = -1;
	do {
		waited = ::waitpid(child, &wait_status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited == child && WIFEXITED(wait_status)) {
		result.exit_code = WEXITSTATUS(wait_status);
	}
	return result;
}

/**
 * @brief Launch the native sender and capture ordinary output.
 *
 * @param arguments Arguments following the exact sender image path.
 * @param block_generation_signal Whether the child inherits SIGUSR1 blocked.
 * @return Child exit status and merged output.
 */
[[nodiscard]] sender_result run_sender(const std::vector<std::string> &arguments, bool block_generation_signal)
{
	return run_sender(arguments, block_generation_signal, sender_output_destination::CAPTURE);
}

/** @return One process-unique valid interface atom that should not exist. */
[[nodiscard]] std::string absent_interface_name()
{
	return "k" + std::to_string(static_cast<unsigned long long>(::getpid()));
}

}  // namespace

/** @brief Prove help and parser expose only the one-way signal contract. */
TEST(validation_tap_sender, help_and_removed_control_option_are_exact)
{
	const auto help = run_sender({"--help"}, false);
	ASSERT_EQ(help.exit_code, 0) << help.output;
	EXPECT_NE(help.output.find("--initial-generation-tag"), std::string::npos);
	EXPECT_NE(help.output.find("--next-generation-tag"), std::string::npos);
	EXPECT_EQ(help.output.find("generation-tag-shm"), std::string::npos);
	const auto unreported_help = run_sender({"--help"}, false, sender_output_destination::FULL);
	EXPECT_EQ(unreported_help.exit_code, 1) << unreported_help.output;

	const auto removed = run_sender({"--generation-tag-shm", "/tmp/removed"}, false);
	EXPECT_EQ(removed.exit_code, 2) << removed.output;
	EXPECT_NE(removed.output.find("unknown argument: --generation-tag-shm"), std::string::npos);
}

/** @brief Prove exact tags and inherited signal blocking precede socket work. */
TEST(validation_tap_sender, generation_signal_admission_is_complete_before_sockets)
{
	const std::string interface_name = absent_interface_name();
	const std::vector<std::string> base{
		"--mode", "generation-tagged", "--ports", interface_name, "--pps", "1", "--duration", "1",
	};
	const auto unreported_lifecycle =
		run_sender({"--mode", "standard", "--ports", interface_name, "--pps", "1", "--duration", "1"}, false,
			   sender_output_destination::FULL);
	EXPECT_EQ(unreported_lifecycle.exit_code, 1) << unreported_lifecycle.output;

	auto missing_arguments = base;
	missing_arguments.insert(missing_arguments.end(), {"--initial-generation-tag", "1"});
	const auto missing = run_sender(missing_arguments, false);
	EXPECT_EQ(missing.exit_code, 2) << missing.output;
	EXPECT_NE(missing.output.find("requires both generation-tag values"), std::string::npos);

	auto equal_arguments = base;
	equal_arguments.insert(equal_arguments.end(), {"--initial-generation-tag", "7", "--next-generation-tag", "7"});
	const auto equal = run_sender(equal_arguments, false);
	EXPECT_EQ(equal.exit_code, 2) << equal.output;
	EXPECT_NE(equal.output.find("requires distinct generation-tag values"), std::string::npos);

	auto exact_arguments = base;
	exact_arguments.insert(exact_arguments.end(), {"--initial-generation-tag", "1", "--next-generation-tag", "2"});
	const auto unblocked = run_sender(exact_arguments, false);
	EXPECT_EQ(unblocked.exit_code, 1) << unblocked.output;
	EXPECT_NE(unblocked.output.find("requires inherited SIGUSR1 blocking"), std::string::npos);

	const auto blocked = run_sender(exact_arguments, true);
	EXPECT_EQ(blocked.exit_code, 1) << blocked.output;
	EXPECT_EQ(blocked.output.find("requires inherited SIGUSR1 blocking"), std::string::npos);
	EXPECT_EQ(blocked.output.find("failed to install generation signal policy"), std::string::npos);
	EXPECT_EQ(blocked.output.find("failed to unblock generation signal"), std::string::npos);
	const bool reached_socket_admission = blocked.output.find("socket(AF_PACKET) failed") != std::string::npos ||
					      blocked.output.find("if_nametoindex(" + interface_name + ") failed") !=
						      std::string::npos;
	EXPECT_TRUE(reached_socket_admission) << blocked.output;
}

}  // namespace kinetum::validation
