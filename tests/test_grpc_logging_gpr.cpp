// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_grpc_logging_gpr.cpp
 * @brief Real GPR emission through the platform's owned native hook.
 * @author Fleming Patel
 */

#include <cstdlib>
#include <algorithm>
#include <array>
#include <filesystem>
#include <optional>
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
	const auto component = log_component_index("grpc");
	ASSERT_TRUE(component.has_value());
	options.component_levels[*component] = log_level::INFO;
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

/** @brief Authored filter choices and independently specified native visibility. */
struct native_filter_case {
	log_level global_level;			   ///< Ordinary platform threshold.
	std::optional<log_level> component_level;  ///< Explicit gRPC override, if authored.
	bool expect_info;			   ///< Whether native INFO must reach the file.
	bool expect_debug;			   ///< Whether native DEBUG must reach the file.
};

/**
 * @brief Prove native verbosity and frontend filtering agree without hiding actual errors.
 * @param root Protected fixture destination retained through logger retirement.
 * @param selection Authored filters with independently specified expected visibility.
 */
void verify_native_filters(const std::filesystem::path &root, const native_filter_case &selection)
{
	log_options options;
	options.directory = root.string();
	options.level = selection.global_level;
	const auto component = log_component_index("grpc");
	ASSERT_TRUE(component.has_value());
	options.component_levels[*component] = selection.component_level;
	auto logger_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(logger_or.is_ok());
	auto logger = std::move(logger_or).value();
	logger->startup_complete();
	{
		auto native_or = grpc_logging::create();
		ASSERT_TRUE(native_or.is_ok());
		auto native = std::move(native_or).value();
		EXPECT_EQ(::gpr_should_log(GPR_LOG_SEVERITY_INFO) != 0, selection.expect_info);
		EXPECT_EQ(::gpr_should_log(GPR_LOG_SEVERITY_DEBUG) != 0, selection.expect_debug);
		EXPECT_NE(::gpr_should_log(GPR_LOG_SEVERITY_ERROR), 0);
		::gpr_log_message("native.cc", 81, GPR_LOG_SEVERITY_INFO, "native-info-filter-canary");
		::gpr_log_message("native.cc", 82, GPR_LOG_SEVERITY_DEBUG, "native-debug-filter-canary");
		::gpr_log_message("native.cc", 83, GPR_LOG_SEVERITY_ERROR, "native-error-filter-canary");
		KINETUM_LOG_INFO("cp", "test.platform.info", "ordinary platform information");
	}
	logger.reset();
	const auto records = test_support::read_log_file(root / "kinetum_cp.log");
	EXPECT_EQ(records.find("native-info-filter-canary") != std::string::npos, selection.expect_info);
	EXPECT_EQ(records.find("native-debug-filter-canary") != std::string::npos, selection.expect_debug);
	EXPECT_NE(records.find("native-error-filter-canary"), std::string::npos);
	EXPECT_EQ(records.find("test.platform.info") != std::string::npos, selection.global_level <= log_level::INFO);
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

/** @brief Ordinary runs retain native errors; DEBUG and explicit overrides select connection details. */
TEST(grpc_logging, native_verbosity_matches_default_debug_and_component_filters)
{
	constexpr std::array<native_filter_case, 8> CASES{{
		{log_level::INFO, std::nullopt, false, false},
		{log_level::WARN, std::nullopt, false, false},
		{log_level::DEBUG, std::nullopt, true, true},
		{log_level::INFO, log_level::INFO, true, false},
		{log_level::FATAL, log_level::DEBUG, true, true},
		{log_level::DEBUG, log_level::INFO, true, false},
		{log_level::DEBUG, log_level::ERROR, false, false},
		{log_level::FATAL, log_level::FATAL, false, false},
	}};
	for (const auto &selection : CASES) {
		SCOPED_TRACE(static_cast<int>(selection.global_level));
		SCOPED_TRACE(selection.component_level.has_value() ? static_cast<int>(*selection.component_level) : 0);
		test_support::log_test_directory directory;
		ASSERT_FALSE(directory.path().empty());
		ASSERT_EXIT(
			{
				verify_native_filters(directory.path(), selection);
				std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
			},
			::testing::ExitedWithCode(0), "");
	}
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
