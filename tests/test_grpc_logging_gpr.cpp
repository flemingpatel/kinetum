// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_grpc_logging_gpr.cpp
 * @brief Real GPR emission through the platform's owned native hook.
 * @author Fleming Patel
 */

#include <cstdlib>
#include <algorithm>
#include <filesystem>
#include <string>

#include <grpc/support/log.h>
#include <gtest/gtest.h>

#include "src/common/grpc_logging.hpp"
#include "src/common/log.hpp"
#include "src/common/log_service.hpp"
#include "src/common/packet_thread_log_guard.hpp"
#include "tests/log_test_support.hpp"

namespace kinetum::common
{
namespace
{

/**
 * @brief Exercise the actual native API, including callback copying and scoped unregister.
 * @param root Protected fixture destination retained through native and writer retirement.
 */
void verify_native_capture(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	auto logger_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(logger_or.is_ok());
	auto logger = std::move(logger_or).value();
	{
		auto native_or = grpc_logging::create();
		ASSERT_TRUE(native_or.is_ok());
		auto native = std::move(native_or).value();
		EXPECT_FALSE(grpc_logging::create().is_ok());
		std::string message = "native-message-canary\nsecond line";
		::gpr_log_message("native.cc", 73, GPR_LOG_SEVERITY_INFO, message.c_str());
		message.assign("changed-after-callback");
		::gpr_log_message("native.cc", 74, GPR_LOG_SEVERITY_DEBUG, "filtered-native-canary");
		const auto before = packet_thread_log_rejections();
		{
			packet_thread_log_guard packet;
			::gpr_log_message("native.cc", 75, GPR_LOG_SEVERITY_ERROR, "packet-native-canary");
		}
		EXPECT_EQ(packet_thread_log_rejections(), before + 1);
	}
	logger.reset();
	const auto records = test_support::read_log_file(root / "kinetum_cp.log");
	EXPECT_NE(records.find("grpc.message - grpc: native.cc:73: native-message-canary\\x0asecond line"),
		  std::string::npos);
	EXPECT_EQ(records.find("changed-after-callback"), std::string::npos);
	EXPECT_EQ(records.find("filtered-native-canary"), std::string::npos);
	EXPECT_EQ(records.find("packet-native-canary"), std::string::npos);
}

/** @brief Finite commands suppress native startup chatter while preserving native errors. */
void verify_finite_capture()
{
	set_command_log_identity("kinetumctl");
	test_support::log_stderr_capture capture;
	ASSERT_TRUE(capture.valid());
	{
		auto native_or = grpc_logging::create();
		ASSERT_TRUE(native_or.is_ok());
		auto native = std::move(native_or).value();
		::gpr_log_message("native.cc", 73, GPR_LOG_SEVERITY_INFO, "finite startup canary");
		::gpr_log_message("native.cc", 74, GPR_LOG_SEVERITY_ERROR, "finite error canary");
	}
	std::string output;
	ASSERT_TRUE(capture.finish(output));
	EXPECT_TRUE(flush_logs());
	EXPECT_EQ(output.find("finite startup canary"), std::string::npos);
	EXPECT_NE(output.find(" [ERROR] "), std::string::npos);
	EXPECT_NE(output.find("finite error canary"), std::string::npos);
	EXPECT_EQ(std::count(output.begin(), output.end(), '\n'), 1);
}

}  // namespace

/** @brief The real GPR route keeps successful command output quiet and reports native errors. */
TEST(grpc_logging, finite_commands_admit_native_errors_without_startup_chatter)
{
	ASSERT_EXIT(
		{
			verify_finite_capture();
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief The declared GPR hook must actually receive native messages, not merely compile. */
TEST(grpc_logging, native_records_are_captured_and_copied)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_native_capture(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief The native ERROR-then-abort assertion preserves its explanation without destructor flushing. */
TEST(grpc_logging, native_assertion_record_reaches_file_before_abort)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			log_options options;
			options.directory = directory.path().string();
			options.level = log_level::FATAL;
			auto owner = log_service::start(options, "kinetum_cp");
			if (!owner.is_ok()) {
				std::_Exit(70);
			}
			owner.value()->startup_complete();
			auto native = grpc_logging::create();
			if (!native.is_ok()) {
				std::_Exit(71);
			}
			GPR_ASSERT(false);
		},
		::testing::KilledBySignal(SIGABRT), "^$");
	EXPECT_NE(test_support::read_log_file(directory.path() / "kinetum_cp.log").find("assertion failed"),
		  std::string::npos);
}

}  // namespace kinetum::common
