// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_log_delivery.cpp
 * @brief Native-error delivery, emergency output, and timed-out receipt ownership.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>

#include <fcntl.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <unistd.h>

#include "src/common/log.hpp"
#include "src/common/log_service.hpp"
#include "src/common/process_output.hpp"
#include "tests/log_test_support.hpp"

namespace kinetum::common
{
namespace
{

/**
 * @brief Hold a real writer inside a full console pipe while retaining a separate emergency destination.
 *
 * A large mirror write fills the final PIPE_BUF bytes. FIONREAD then proves
 * that the writer entered that pipe; replacing fd 2 cannot change its blocked
 * syscall's held file description. Closing the read end releases that write.
 */
class stalled_console final {
    public:
	/** @param root Exact fixture-owned directory for the independent emergency capture. */
	explicit stalled_console(const std::filesystem::path &root)
	{
		saved_ = ::fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);
		capture_ = ::open((root / "console").c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		if (saved_ < 0 || capture_ < 0 || ::pipe2(pipe_.data(), O_CLOEXEC) != 0) {
			return;
		}
		capacity_ = ::fcntl(pipe_[1], F_GETPIPE_SZ);
		if (capacity_ < PIPE_BUF) {
			return;
		}
		const std::string prefix(static_cast<std::size_t>(capacity_ - PIPE_BUF), 'p');
		valid_ = detail::write_process_output(pipe_[1], prefix) &&
			 ::dup2(pipe_[1], STDERR_FILENO) == STDERR_FILENO;
	}
	/** @brief Release every fixture descriptor even after an assertion or setup failure. */
	~stalled_console()
	{
		release_writer();
		restore();
		if (pipe_[1] >= 0) {
			(void)::close(pipe_[1]);
		}
		if (capture_ >= 0) {
			(void)::close(capture_);
		}
	}
	stalled_console(const stalled_console &) = delete;
	stalled_console &operator=(const stalled_console &) = delete;
	/** @return Whether the pipe and emergency capture were completely admitted. */
	[[nodiscard]] bool valid() const noexcept
	{
		return valid_;
	}
	/** @return True only after the writer added bytes to the otherwise unchanged pipe. */
	[[nodiscard]] bool wait_until_blocked() const
	{
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		do {
			int occupied = 0;
			if (::ioctl(pipe_[0], FIONREAD, &occupied) != 0) {
				return false;
			}
			if (occupied == capacity_) {
				return true;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		} while (std::chrono::steady_clock::now() < deadline);
		return false;
	}
	/** @return Whether future writes now target the independent regular-file capture. */
	[[nodiscard]] bool redirect() const noexcept
	{
		return capture_ >= 0 && ::dup2(capture_, STDERR_FILENO) == STDERR_FILENO;
	}
	/** @brief Release the old blocked pipe before joining either producer or logger. */
	void release_writer() noexcept
	{
		if (pipe_[0] < 0) {
			return;
		}
		(void)redirect();
		if (pipe_[0] >= 0) {
			(void)::close(pipe_[0]);
			pipe_[0] = -1;
		}
	}
	/** @brief Restore assertion diagnostics only after producers and the writer retire. */
	void restore() noexcept
	{
		if (saved_ >= 0) {
			(void)::dup2(saved_, STDERR_FILENO);
			(void)::close(saved_);
			saved_ = -1;
		}
	}

    private:
	int saved_{-1};			   ///< Original child diagnostic descriptor.
	int capture_{-1};		   ///< Exact emergency capture, separate from the stalled pipe.
	std::array<int, 2> pipe_{-1, -1};  ///< Fixture-owned pipe descriptions.
	int capacity_{0};		   ///< Kernel-reported finite pipe capacity.
	bool valid_{false};		   ///< Complete setup before any log is submitted.
};

/**
 * @param root Protected file destination owned by the outer test.
 * @brief Prove a native ERROR bypasses suppression and reaches the file before return.
 */
void verify_confirmed_delivery(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	options.level = log_level::FATAL;
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok());
	auto owner = std::move(owner_or).value();
	owner->startup_complete();
	test_support::log_stderr_capture capture;
	ASSERT_TRUE(capture.valid());
	uint32_t formatted = 0;
	log_foreign_lazy({log_level::INFO, "grpc", "test.filtered", __func__}, [&](std::span<char>) {
		++formatted;
		return std::size_t{0};
	});
	log_foreign_lazy({log_level::ERROR, "grpc", "test.confirmed", __func__}, [&](std::span<char> output) {
		++formatted;
		return static_cast<std::size_t>(std::format_to_n(output.data(),
								 static_cast<std::ptrdiff_t>(output.size()),
								 "native error before return")
							.size);
	});
	const auto bytes_at_return = test_support::read_log_file(root / "kinetum_cp.log");
	const auto observed = owner->health();
	owner.reset();
	std::string console;
	ASSERT_TRUE(capture.finish(console));
	EXPECT_EQ(formatted, 1u);
	EXPECT_NE(bytes_at_return.find("native error before return"), std::string::npos);
	EXPECT_EQ(observed.accepted_records, 1u);
	EXPECT_EQ(observed.delivery_timeouts, 0u);
	EXPECT_EQ(observed.undelivered_records, 0u);
	EXPECT_TRUE(console.empty()) << console;
}

/** @param depth Remaining ordinary reservations to hold before the native call. */
void fill_arena_before_foreign_error(uint32_t depth)
{
	log_lazy({log_level::INFO, "logging", "test.reserved", __func__}, [depth](std::span<char> output) {
		if (depth != 0) {
			fill_arena_before_foreign_error(depth - 1);
		} else {
			log_foreign_lazy({log_level::ERROR, "grpc", "test.full", {}}, [](std::span<char> destination) {
				return static_cast<std::size_t>(
					std::format_to_n(destination.data(),
							 static_cast<std::ptrdiff_t>(destination.size()),
							 "native queue refusal")
						.size);
			});
		}
		output[0] = 'x';
		return std::size_t{1};
	});
}

/** @param root Protected destination; refusal is observed through real synchronous stderr. */
void verify_queue_refusal(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok());
	auto owner = std::move(owner_or).value();
	owner->startup_complete();
	test_support::log_stderr_capture capture;
	ASSERT_TRUE(capture.valid());
	fill_arena_before_foreign_error(255);
	const auto observed = owner->health();
	owner.reset();
	std::string console;
	ASSERT_TRUE(capture.finish(console));
	EXPECT_EQ(observed.accepted_records, 256u);
	EXPECT_EQ(observed.queue_rejections, 1u);
	EXPECT_EQ(observed.delivery_timeouts, 0u);
	EXPECT_NE(console.find("native queue refusal"), std::string::npos);
}

/** @param root Protected destination; a broken emergency pipe must not change the caller's process fate. */
void verify_broken_emergency(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok());
	auto owner = std::move(owner_or).value();
	owner->startup_complete();
	std::array<int, 2> pipe{-1, -1};
	ASSERT_EQ(::pipe2(pipe.data(), O_CLOEXEC), 0);
	const int saved = ::dup(STDERR_FILENO);
	ASSERT_GE(saved, 0);
	ASSERT_EQ(::close(pipe[0]), 0);
	ASSERT_EQ(::dup2(pipe[1], STDERR_FILENO), STDERR_FILENO);
	(void)::close(pipe[1]);
	sigset_t signals{};
	sigset_t previous{};
	(void)::sigemptyset(&signals);
	(void)::sigaddset(&signals, SIGPIPE);
	const auto old_handler = ::signal(SIGPIPE, SIG_DFL);
	const int unblocked = ::pthread_sigmask(SIG_UNBLOCK, &signals, &previous);
	if (old_handler != SIG_ERR && unblocked == 0) {
		fill_arena_before_foreign_error(255);
	}
	const int restored = ::dup2(saved, STDERR_FILENO);
	(void)::close(saved);
	if (unblocked == 0) {
		(void)::pthread_sigmask(SIG_SETMASK, &previous, nullptr);
	}
	if (old_handler != SIG_ERR) {
		(void)::signal(SIGPIPE, old_handler);
	}
	const auto observed = owner->health();
	owner.reset();
	ASSERT_NE(old_handler, SIG_ERR);
	ASSERT_EQ(unblocked, 0);
	ASSERT_EQ(restored, STDERR_FILENO);
	EXPECT_EQ(observed.queue_rejections, 1u);
	EXPECT_EQ(observed.console_failures, 1u);
	EXPECT_EQ(observed.delivery_timeouts, 0u);
}

/** @param root Protected destination whose existing bytes must survive a real write failure. */
void verify_failed_delivery(const std::filesystem::path &root)
{
	const auto path = root / "kinetum_cp.log";
	const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	ASSERT_GE(descriptor, 0);
	const std::string prefix = std::string(511, 'p') + '\n';
	const bool seeded = detail::write_process_output(descriptor, prefix);
	const int closed = ::close(descriptor);
	ASSERT_TRUE(seeded);
	ASSERT_EQ(closed, 0);
	log_options options;
	options.directory = root.string();
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok());
	auto owner = std::move(owner_or).value();
	owner->startup_complete();
	ASSERT_NE(::signal(SIGXFSZ, SIG_IGN), SIG_ERR);
	rlimit original{};
	ASSERT_EQ(::getrlimit(RLIMIT_FSIZE, &original), 0);
	const rlimit restricted{512, original.rlim_max};
	test_support::log_stderr_capture capture;
	ASSERT_TRUE(capture.valid());
	const int limited = ::setrlimit(RLIMIT_FSIZE, &restricted);
	if (limited == 0) {
		log_foreign_lazy({log_level::ERROR, "grpc", "test.write_failure", {}}, [](std::span<char> output) {
			return static_cast<std::size_t>(std::format_to_n(output.data(),
									 static_cast<std::ptrdiff_t>(output.size()),
									 "native write failure")
								.size);
		});
	}
	const int restored = ::setrlimit(RLIMIT_FSIZE, &original);
	log_foreign_lazy({log_level::ERROR, "grpc", "test.unavailable", {}}, [](std::span<char> output) {
		return static_cast<std::size_t>(std::format_to_n(output.data(),
								 static_cast<std::ptrdiff_t>(output.size()),
								 "native unavailable destination")
							.size);
	});
	const auto observed = owner->health();
	owner.reset();
	std::string console;
	ASSERT_TRUE(capture.finish(console));
	ASSERT_EQ(limited, 0);
	ASSERT_EQ(restored, 0);
	EXPECT_EQ(observed.accepted_records, 1u);
	EXPECT_EQ(observed.undelivered_records, 1u);
	EXPECT_EQ(observed.unavailable_rejections, 1u);
	EXPECT_EQ(observed.delivery_timeouts, 0u);
	EXPECT_NE(console.find("native write failure"), std::string::npos);
	EXPECT_NE(console.find("native unavailable destination"), std::string::npos);
	EXPECT_EQ(test_support::read_log_file(path), prefix);
}

/** @param root Protected destination; a real blocked mirror separates file completion from queue progress. */
void verify_timeout_and_reuse(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	options.console = true;
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok());
	auto owner = std::move(owner_or).value();
	owner->startup_complete();
	stalled_console console(root);
	ASSERT_TRUE(console.valid());
	const std::string large(LOG_MESSAGE_BYTES, 'x');
	std::string message = "record retained after timeout";
	std::thread first([&] {
		log_foreign_lazy({log_level::ERROR, "grpc", "test.first", {}}, [&](std::span<char> output) {
			return static_cast<std::size_t>(
				std::format_to_n(output.data(), static_cast<std::ptrdiff_t>(output.size()), "{}", large)
					.size);
		});
	});
	const bool blocked = console.wait_until_blocked();
	const bool redirected = console.redirect();
	if (blocked && redirected) {
		log_foreign_lazy({log_level::ERROR, "grpc", "test.late", {}}, [&](std::span<char> output) {
			return static_cast<std::size_t>(std::format_to_n(output.data(),
									 static_cast<std::ptrdiff_t>(output.size()),
									 "{}", message)
								.size);
		});
	}
	message.assign("caller storage reused");
	console.release_writer();
	first.join();
	for (uint32_t index = 0; index < 300; ++index) {
		log_foreign_lazy({log_level::ERROR, "grpc", "test.reused", {}}, [index](std::span<char> output) {
			return static_cast<std::size_t>(std::format_to_n(output.data(),
									 static_cast<std::ptrdiff_t>(output.size()),
									 "replacement={}", index)
								.size);
		});
	}
	const auto observed = owner->health();
	owner.reset();
	console.restore();
	ASSERT_TRUE(blocked);
	ASSERT_TRUE(redirected);
	EXPECT_EQ(observed.accepted_records, 302u);
	EXPECT_EQ(observed.delivery_timeouts, 1u);
	EXPECT_EQ(observed.undelivered_records, 0u);
	const auto file = test_support::read_log_file(root / "kinetum_cp.log");
	const auto emergency = test_support::read_log_file(root / "console");
	EXPECT_NE(file.find("record retained after timeout"), std::string::npos);
	EXPECT_EQ(file.find("caller storage reused"), std::string::npos);
	EXPECT_NE(file.find("replacement=299"), std::string::npos);
	EXPECT_NE(emergency.find("record retained after timeout"), std::string::npos);
}

}  // namespace

/** @brief Native errors are file-confirmed despite a suppressing ordinary severity threshold. */
TEST(log_delivery, native_error_confirms_its_file_record_before_return)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_confirmed_delivery(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief A full ordinary arena selects immediate counted emergency output without a fictitious wait. */
TEST(log_delivery, full_queue_uses_emergency_output_without_waiting)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_queue_refusal(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Emergency EPIPE is counted without delivering SIGPIPE to an otherwise live caller. */
TEST(log_delivery, broken_emergency_pipe_does_not_terminate_the_caller)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_broken_emergency(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Consuming a failed write never acknowledges delivery and known outage skips queue admission. */
TEST(log_delivery, failed_write_and_unavailable_destination_are_not_delivery)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_failed_delivery(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief A timed-out caller cannot release queued bytes or corrupt the next use of a completion slot. */
TEST(log_delivery, timeout_keeps_writer_ownership_until_late_completion)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_timeout_and_reuse(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

}  // namespace kinetum::common
