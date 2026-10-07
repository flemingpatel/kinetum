// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_cp_termination_signal.cpp
 * @brief Exact Control Plane descriptor-owned signal tests.
 * @author Fleming Patel
 *
 * Signals are directed to the calling test thread after the production owner
 * blocks them. The signalfd consumes that thread-pending record, so these tests
 * neither install a process handler nor depend on signal delivery to another
 * gTest or gRPC thread.
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include "gen/kinetum/control/v1/control.grpc.pb.h"
#include "src/common/status.hpp"
#include "src/cp/cp_termination_signal.hpp"
#include "src/photon/process.hpp"
#include "tests/test_grpc_helpers.hpp"

#ifndef KINETUM_PRODUCTION_CP_PATH
#error "KINETUM_PRODUCTION_CP_PATH must name the exact Control Plane test image"
#endif

namespace kinetum::cp
{
namespace
{

using kinetum::common::status_code;

namespace fs = std::filesystem;

/** @brief Own one exact temporary parent for the production CP store. */
class cp_signal_test_directory final {
    public:
	/** @brief Create an owner-only process-unique directory. */
	cp_signal_test_directory()
	{
		std::error_code error;
		const fs::path temporary_root = fs::canonical(fs::temp_directory_path(), error);
		if (error) {
			return;
		}
		std::string pattern = (temporary_root / "kinetum_cp_signal.XXXXXX").string();
		if (char *created = ::mkdtemp(pattern.data()); created != nullptr) {
			root_ = created;
		}
	}

	/** @brief Remove every test-owned store artifact. */
	~cp_signal_test_directory()
	{
		if (!root_.empty()) {
			std::error_code error;
			fs::remove_all(root_, error);
		}
	}

	/** @return Exact temporary parent, or an empty path on setup failure. */
	[[nodiscard]] const fs::path &root() const noexcept
	{
		return root_;
	}

    private:
	fs::path root_;	 ///< Exact test-owned parent directory.
};

/**
 * @brief Reserve and release one kernel-selected loopback TCP port.
 * @return Host-order port, or zero on socket admission failure.
 */
[[nodiscard]] uint16_t select_loopback_port() noexcept
{
	const int descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (descriptor < 0) {
		return 0;
	}
	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	if (::bind(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
		(void)::close(descriptor);
		return 0;
	}
	socklen_t length = sizeof(address);
	if (::getsockname(descriptor, reinterpret_cast<sockaddr *>(&address), &length) != 0 ||
	    length != sizeof(address)) {
		(void)::close(descriptor);
		return 0;
	}
	const uint16_t port = ntohs(address.sin_port);
	return ::close(descriptor) == 0 ? port : 0;
}

/** @brief Ensure one production child is reaped on every assertion path. */
class cp_child_cleanup final {
    public:
	/**
	 * @brief Bind cleanup to one live Photon child authority.
	 * @param child Child record retained by the surrounding test fixture.
	 */
	explicit cp_child_cleanup(kinetum::photon::child_proc *child) noexcept
		: child_(child)
	{
	}

	cp_child_cleanup(const cp_child_cleanup &) = delete;
	cp_child_cleanup &operator=(const cp_child_cleanup &) = delete;
	cp_child_cleanup(cp_child_cleanup &&) = delete;
	cp_child_cleanup &operator=(cp_child_cleanup &&) = delete;

	/** @brief Terminate and reap the child if the test did not already do so. */
	~cp_child_cleanup()
	{
		if (child_ != nullptr && child_->state == kinetum::photon::process_state::RUNNING) {
			(void)kinetum::photon::terminate_process(*child_, 5'000);
		}
	}

    private:
	kinetum::photon::child_proc *child_;  ///< Borrowed exact child authority.
};

/**
 * @brief Read the calling thread's exact current signal mask.
 * @param[out] mask Destination mask.
 * @return true only when pthread_sigmask returned success.
 */
[[nodiscard]] bool read_current_mask(sigset_t *mask) noexcept
{
	return mask != nullptr && ::pthread_sigmask(SIG_SETMASK, nullptr, mask) == 0;
}

/**
 * @brief Prove one thread-directed signal crosses only the exact descriptor.
 * @param signal_number SIGINT or SIGTERM.
 */
void expect_exact_signal_record(int signal_number)
{
	sigset_t before{};
	ASSERT_TRUE(read_current_mask(&before));

	auto owner_or = cp_termination_signal::create();
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();

	sigset_t blocked{};
	ASSERT_TRUE(read_current_mask(&blocked));
	EXPECT_EQ(::sigismember(&blocked, SIGINT), 1);
	EXPECT_EQ(::sigismember(&blocked, SIGTERM), 1);
	ASSERT_EQ(::pthread_kill(::pthread_self(), signal_number), 0);

	auto observed_or = owner->wait();
	ASSERT_TRUE(observed_or.is_ok()) << observed_or.error().message();
	EXPECT_EQ(observed_or.value(), signal_number);
	auto repeated_or = owner->wait();
	ASSERT_FALSE(repeated_or.is_ok());
	EXPECT_EQ(repeated_or.error().code(), status_code::FAILED_PRECONDITION);

	owner.reset();
	sigset_t after{};
	ASSERT_TRUE(read_current_mask(&after));
	EXPECT_EQ(::sigismember(&after, SIGINT), ::sigismember(&before, SIGINT));
	EXPECT_EQ(::sigismember(&after, SIGTERM), ::sigismember(&before, SIGTERM));
}

}  // namespace

/** @brief Prove SIGINT is consumed as one exact main-thread descriptor record. */
TEST(cp_termination_signal, sigint_is_consumed_as_one_exact_descriptor_record)
{
	expect_exact_signal_record(SIGINT);
}

/** @brief Prove Photon's SIGTERM shape reaches the exact CP descriptor owner. */
TEST(cp_termination_signal, photon_style_sigterm_reaches_the_exact_descriptor_owner)
{
	expect_exact_signal_record(SIGTERM);
}

/** @brief Reopen observation leaves the exact termination capability live for a later signal. */
TEST(cp_termination_signal, reopen_does_not_consume_termination_authority)
{
	auto owner_or = cp_termination_signal::create();
	ASSERT_TRUE(owner_or.is_ok());
	auto owner = std::move(owner_or).value();
	ASSERT_EQ(::pthread_kill(::pthread_self(), SIGUSR1), 0);
	const auto reopened = owner->wait();
	ASSERT_TRUE(reopened.is_ok());
	EXPECT_EQ(reopened.value(), SIGUSR1);
	ASSERT_EQ(::pthread_kill(::pthread_self(), SIGTERM), 0);
	const auto terminated = owner->wait();
	ASSERT_TRUE(terminated.is_ok());
	EXPECT_EQ(terminated.value(), SIGTERM);
}

/** @brief Reopen requests pending at retirement cannot fire after the original mask is restored. */
TEST(cp_termination_signal, pending_reopen_retires_before_mask_restoration)
{
	EXPECT_EXIT(
		{
			auto owner_or = cp_termination_signal::create();
			if (!owner_or.is_ok() || ::pthread_kill(::pthread_self(), SIGUSR1) != 0) {
				std::_Exit(2);
			}
			auto owner = std::move(owner_or).value();
			owner.reset();
			std::_Exit(0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Prove process ownership is linear and descriptor lifetime is exact. */
TEST(cp_termination_signal, live_duplicate_rejects_and_release_closes_the_descriptor)
{
	sigset_t before{};
	ASSERT_TRUE(read_current_mask(&before));
	auto owner_or = cp_termination_signal::create();
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();

	const int descriptor = owner->descriptor();
	ASSERT_GE(descriptor, 0);
	const int descriptor_flags = ::fcntl(descriptor, F_GETFD);
	ASSERT_GE(descriptor_flags, 0);
	EXPECT_NE(descriptor_flags & FD_CLOEXEC, 0);

	auto duplicate_or = cp_termination_signal::create();
	ASSERT_FALSE(duplicate_or.is_ok());
	EXPECT_EQ(duplicate_or.error().code(), status_code::FAILED_PRECONDITION);

	owner.reset();
	errno = 0;
	EXPECT_EQ(::fcntl(descriptor, F_GETFD), -1);
	EXPECT_EQ(errno, EBADF);

	sigset_t after{};
	ASSERT_TRUE(read_current_mask(&after));
	EXPECT_EQ(::sigismember(&after, SIGINT), ::sigismember(&before, SIGINT));
	EXPECT_EQ(::sigismember(&after, SIGTERM), ::sigismember(&before, SIGTERM));

	auto replacement_or = cp_termination_signal::create();
	ASSERT_TRUE(replacement_or.is_ok()) << replacement_or.error().message();
	auto replacement = std::move(replacement_or).value();
	replacement.reset();
}

/** @brief Prove signal-mask ownership cannot retire on a foreign thread. */
TEST(cp_termination_signal, foreign_thread_destruction_fails_stop)
{
	EXPECT_DEATH(
		{
			auto owner_or = cp_termination_signal::create();
			if (!owner_or.is_ok()) {
				::_exit(2);
			}
			auto owner = std::move(owner_or).value();
			std::thread foreign_owner([owner = std::move(owner)]() mutable { owner.reset(); });
			foreign_owner.join();
		},
		"owner destroyed outside its creating thread");
}

/** @brief Prove Photon's production SIGTERM path cleanly retires the CP image. */
TEST(cp_termination_signal, photon_spawn_and_sigterm_retires_production_cp_cleanly)
{
	kinetum::test::fake_dp_server dataplane;
	dataplane.service.readiness_state = kinetum::dataplane::v1::HealthResponse::STATE_CONTROL_READY;
	dataplane.start();

	cp_signal_test_directory directory;
	ASSERT_FALSE(directory.root().empty());
	const uint16_t cp_port = select_loopback_port();
	ASSERT_NE(cp_port, 0u);
	const std::string cp_endpoint = "127.0.0.1:" + std::to_string(cp_port);
	const std::string dp_endpoint = "127.0.0.1:" + std::to_string(dataplane.port);
	const std::vector<std::string> arguments{
		KINETUM_PRODUCTION_CP_PATH,
		"--listen-addr",
		cp_endpoint,
		"--dp-addr",
		dp_endpoint,
		"--config-store-dir",
		(directory.root() / "store").string(),
		"--log-dir",
		(directory.root() / "logs").string(),
	};
	auto child_or = kinetum::photon::spawn_process_argv("cp-signal-test", arguments);
	ASSERT_TRUE(child_or.is_ok()) << child_or.error().message();
	auto child = std::move(child_or).value();
	cp_child_cleanup cleanup(&child);

	auto channel = grpc::CreateChannel(cp_endpoint, grpc::InsecureChannelCredentials());
	auto control = kinetum::control::v1::ControlService::NewStub(channel);
	ASSERT_NE(control, nullptr);
	bool serving = false;
	const auto readiness_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (std::chrono::steady_clock::now() < readiness_deadline) {
		grpc::ClientContext context;
		context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(100));
		kinetum::control::v1::HealthCheckRequest request;
		kinetum::control::v1::HealthCheckResponse response;
		const auto transport = control->HealthCheck(&context, request, &response);
		if (transport.ok() && response.status() == kinetum::control::v1::HealthCheckResponse::STATUS_SERVING) {
			serving = true;
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	ASSERT_TRUE(serving);

	const auto termination_status = kinetum::photon::terminate_process(child, 5'000);
	ASSERT_TRUE(termination_status.is_ok()) << termination_status.message();
	EXPECT_EQ(child.state, kinetum::photon::process_state::EXITED);
	EXPECT_EQ(child.exit_code, 0);
}

}  // namespace kinetum::cp
