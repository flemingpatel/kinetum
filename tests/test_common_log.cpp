// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_common_log.cpp
 * @brief Readable records, bounded ownership, filtering, and service logging retirement.
 * @author Fleming Patel
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "src/common/log.hpp"
#include "src/common/log_options.hpp"
#include "src/common/log_service.hpp"
#include "tests/log_test_support.hpp"

namespace kinetum::common
{
namespace
{

/** @return Independently specified metadata and text for an exact wire-format answer. */
log_record example_record()
{
	log_record record;
	record.realtime_us = 1700000000123456;
	record.process_id = 42;
	record.thread_id = 73;
	(void)copy_log_field(record.hostname, "dut");
	(void)copy_log_field(record.application, "kinetum_dp");
	(void)copy_log_field(record.component, "module");
	(void)copy_log_field(record.function, "admit");
	(void)copy_log_field(record.event, "module.admitted");
	constexpr std::string_view MESSAGE = "images=3 contexts=3";
	std::copy(MESSAGE.begin(), MESSAGE.end(), record.message.begin());
	record.message_size = MESSAGE.size();
	return record;
}

/** @brief Exercise synchronous descriptor serialization before any async service exists. */
void verify_synchronous_records()
{
	test_support::log_stderr_capture capture;
	ASSERT_TRUE(capture.valid());
	constexpr uint32_t THREADS = 8;
	constexpr uint32_t RECORDS = 64;
	std::vector<std::jthread> threads;
	threads.reserve(THREADS);
	for (uint32_t thread = 0; thread < THREADS; ++thread) {
		threads.emplace_back([thread] {
			for (uint32_t index = 0; index < RECORDS; ++index) {
				KINETUM_LOG_INFO("logging", "test.concurrent", "producer={} index={}", thread, index);
			}
		});
	}
	threads.clear();
	EXPECT_TRUE(flush_logs());
	std::string output;
	ASSERT_TRUE(capture.finish(output));
	std::istringstream lines(output);
	std::set<std::string> messages;
	for (std::string line; std::getline(lines, line);) {
		EXPECT_NE(line.find(" [INFO] "), std::string::npos) << line;
		const auto message = line.find(": producer=");
		ASSERT_NE(message, std::string::npos) << line;
		EXPECT_TRUE(messages.insert(line.substr(message)).second);
	}
	EXPECT_EQ(messages.size(), THREADS * RECORDS);
}

/**
 * @brief Hold ordinary reservations through synchronous formatter re-entry.
 * @param depth Remaining nested submissions before unwinding.
 * @param constructed Caller-owned count of admitted formatter invocations.
 */
void reserve_nested(uint32_t depth, uint32_t &constructed)
{
	log_lazy({log_level::INFO, "logging", "test.capacity", __func__}, [&](std::span<char> output) -> std::size_t {
		++constructed;
		if (depth != 0) {
			reserve_nested(depth - 1, constructed);
		}
		output[0] = 'x';
		return 1;
	});
}

/**
 * @brief Prove the exact 256-slot bound without scheduler timing or hundreds of threads.
 * @param root Protected fixture destination, retained through writer retirement.
 */
void verify_bounded_arena(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	owner->startup_complete();
	uint32_t constructed = 0;
	reserve_nested(256, constructed);
	EXPECT_EQ(constructed, 256u);
	const auto health = owner->health();
	EXPECT_EQ(health.accepted_records, 256u);
	EXPECT_EQ(health.queue_rejections, 1u);
	EXPECT_EQ(health.format_rejections, 0u);
	owner.reset();
	EXPECT_FALSE(log_service::start(options, "kinetum_cp").is_ok());
	const auto output = test_support::read_log_file(root / "kinetum_cp.log");
	EXPECT_EQ(std::count(output.begin(), output.end(), '\n'), 256);
}

/**
 * @brief Prove each concurrent submission is either preserved whole or explicitly refused.
 * @param root Protected fixture destination, retained through writer retirement.
 */
void verify_async_records(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	owner->startup_complete();
	std::vector<std::jthread> threads;
	threads.reserve(8);
	for (uint32_t producer = 0; producer < 8; ++producer) {
		threads.emplace_back([producer] {
			for (uint32_t index = 0; index < 64; ++index) {
				KINETUM_LOG_INFO("logging", "test.concurrent", "producer={} index={}", producer, index);
			}
		});
	}
	threads.clear();
	const auto health = owner->health();
	EXPECT_EQ(health.accepted_records + health.queue_rejections, 512u);
	EXPECT_EQ(health.format_rejections, 0u);
	EXPECT_EQ(health.unavailable_rejections, 0u);
	owner.reset();
	std::istringstream input(test_support::read_log_file(root / "kinetum_cp.log"));
	std::set<std::string> records;
	for (std::string line; std::getline(input, line);) {
		EXPECT_NE(line.find(" [INFO] "), std::string::npos) << line;
		const auto message = line.find(": producer=");
		ASSERT_NE(message, std::string::npos) << line;
		EXPECT_TRUE(records.insert(line.substr(message)).second);
	}
	EXPECT_EQ(records.size(), health.accepted_records);
}

/**
 * @brief Filter before argument evaluation and reclaim failed formatter reservations.
 * @param root Protected fixture destination, retained through writer retirement.
 */
void verify_filter_and_format_failure(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	options.level = log_level::ERROR;
	const auto module_component = log_component_index("module");
	ASSERT_TRUE(module_component.has_value());
	options.component_levels[*module_component] = log_level::DEBUG;
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	owner->startup_complete();
	int evaluations = 0;
	KINETUM_LOG_INFO("logging", "test.filtered", "{}", ++evaluations);
	KINETUM_LOG_DEBUG("module", "test.override", "{}", ++evaluations);
	EXPECT_EQ(evaluations, 1);
	log_lazy({log_level::ERROR, "logging", "test.format_failure", __func__},
		 [](std::span<char>) -> std::size_t { throw std::format_error("deliberate formatter failure"); });
	KINETUM_LOG_ERROR("logging", "test.after_failure", "format failure did not escape");
	const auto health = owner->health();
	EXPECT_EQ(health.accepted_records, 2u);
	EXPECT_EQ(health.format_rejections, 1u);
	EXPECT_EQ(health.queue_rejections, 0u);
	owner.reset();
	const auto output = test_support::read_log_file(root / "kinetum_cp.log");
	EXPECT_EQ(std::count(output.begin(), output.end(), '\n'), 2);
	EXPECT_EQ(output.find("test.filtered"), std::string::npos);
	EXPECT_NE(output.find("test.after_failure"), std::string::npos);
}

/**
 * @brief Queue ownership outlives caller mutation and exposes bounded truncation.
 * @param root Protected fixture destination, retained through writer retirement.
 */
void verify_owned_bytes(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	std::string message = "original message";
	log_text({log_level::INFO, "logging", "test.owned", __func__}, message);
	message.assign("mutated after submission");
	const std::string oversized(LOG_MESSAGE_BYTES + 1, 'q');
	log_text({log_level::INFO, "logging", "test.truncated", __func__}, oversized);
	EXPECT_EQ(owner->health().truncated_records, 1u);
	owner.reset();
	const auto output = test_support::read_log_file(root / "kinetum_cp.log");
	EXPECT_NE(output.find("original message"), std::string::npos);
	EXPECT_EQ(output.find("mutated after submission"), std::string::npos);
	EXPECT_NE(output.find("...[truncated]"), std::string::npos);
}

/**
 * @brief Observe one exact writer outcome within a finite test deadline.
 * @tparam predicate_type Test predicate over independently published logging health.
 * @param owner Live logger retained throughout observation.
 * @param predicate Required observation, invoked only on the test thread.
 * @return True if the predicate holds within five seconds.
 */
template <typename predicate_type>
bool wait_for_log_health(log_service &owner, predicate_type predicate)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	do {
		if (predicate(owner.health())) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
}

/**
 * @brief Force a real partial file write and prove explicit recovery preserves both bytes and loss.
 * @param root Protected fixture destination, retained through writer retirement.
 */
void verify_write_failure_and_reopen(const std::filesystem::path &root)
{
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
	ASSERT_EQ(::setrlimit(RLIMIT_FSIZE, &restricted), 0);
	const std::string message(2000, 'x');
	log_text({log_level::INFO, "logging", "test.partial_write", __func__}, message);
	const bool unavailable = wait_for_log_health(*owner, [](const log_health &health) {
		return health.destination == log_destination_state::UNAVAILABLE && health.undelivered_records == 1;
	});
	const int restored = ::setrlimit(RLIMIT_FSIZE, &original);
	ASSERT_EQ(restored, 0);
	ASSERT_TRUE(unavailable);
	const auto prefix = test_support::read_log_file(root / "kinetum_cp.log");
	ASSERT_EQ(prefix.size(), 512u);
	const auto failed = owner->health();
	EXPECT_EQ(failed.write_failures, 1u);
	EXPECT_NE(std::string(failed.failure.data()).find("append"), std::string::npos);
	int evaluated = 0;
	KINETUM_LOG_INFO("logging", "test.unavailable", "{}", ++evaluated);
	EXPECT_EQ(evaluated, 0);
	EXPECT_EQ(owner->health().unavailable_rejections, 1u);
	ASSERT_EQ(::chmod(root.c_str(), 0770), 0);
	owner->request_reopen();
	const bool reopen_failed =
		wait_for_log_health(*owner, [](const log_health &health) { return health.write_failures == 2; });
	const int permissions_restored = ::chmod(root.c_str(), 0700);
	ASSERT_EQ(permissions_restored, 0);
	ASSERT_TRUE(reopen_failed);
	EXPECT_EQ(owner->health().failure, failed.failure);
	owner->request_reopen();
	ASSERT_TRUE(wait_for_log_health(*owner, [](const log_health &health) {
		return health.destination == log_destination_state::AVAILABLE && health.accepted_records == 2;
	}));
	EXPECT_EQ(owner->health().undelivered_records, 1u);
	KINETUM_LOG_INFO("logging", "test.recovered", "new record after explicit reopen");
	owner.reset();
	const auto output = test_support::read_log_file(root / "kinetum_cp.log");
	EXPECT_TRUE(output.starts_with(prefix + "\n"));
	EXPECT_NE(output.find("logging.reopened"), std::string::npos);
	EXPECT_NE(output.find("undelivered_records=1"), std::string::npos);
	EXPECT_NE(output.find("previous_failure=append"), std::string::npos);
	EXPECT_NE(output.find("test.recovered"), std::string::npos);
	EXPECT_EQ(output.find("test.unavailable"), std::string::npos);
}

/**
 * @brief Mandatory startup errors remain visible while ordinary service output stays file-owned.
 * @param root Protected fixture destination, retained through writer retirement.
 */
void verify_startup_mirror(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok());
	auto owner = std::move(owner_or).value();
	test_support::log_stderr_capture capture;
	ASSERT_TRUE(capture.valid());
	KINETUM_LOG_ERROR("logging", "test.startup", "startup error");
	owner->startup_complete();
	KINETUM_LOG_ERROR("logging", "test.runtime", "ordinary runtime error");
	owner.reset();
	std::string console;
	ASSERT_TRUE(capture.finish(console));
	EXPECT_NE(console.find("test.startup"), std::string::npos);
	EXPECT_EQ(console.find("test.runtime"), std::string::npos);
	const auto file = test_support::read_log_file(root / "kinetum_cp.log");
	EXPECT_NE(file.find("test.startup"), std::string::npos);
	EXPECT_NE(file.find("test.runtime"), std::string::npos);
}

/**
 * @brief A failed optional console never suppresses successful file delivery.
 * @param root Protected fixture destination, retained through writer retirement.
 */
void verify_console_failure(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	options.console = true;
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok());
	auto owner = std::move(owner_or).value();
	owner->startup_complete();
	const int saved = ::dup(STDERR_FILENO);
	ASSERT_GE(saved, 0);
	const int full = ::open("/dev/full", O_WRONLY | O_CLOEXEC);
	ASSERT_GE(full, 0);
	ASSERT_EQ(::dup2(full, STDERR_FILENO), STDERR_FILENO);
	(void)::close(full);
	KINETUM_LOG_INFO("logging", "test.console_failure", "file remains independent");
	const bool observed =
		wait_for_log_health(*owner, [](const log_health &health) { return health.console_failures == 1; });
	const int restored = ::dup2(saved, STDERR_FILENO);
	(void)::close(saved);
	ASSERT_EQ(restored, STDERR_FILENO);
	ASSERT_TRUE(observed);
	EXPECT_EQ(owner->health().destination, log_destination_state::AVAILABLE);
	EXPECT_EQ(owner->health().undelivered_records, 0u);
	owner.reset();
	const auto file = test_support::read_log_file(root / "kinetum_cp.log");
	EXPECT_NE(file.find("test.console_failure"), std::string::npos);
}

/**
 * @brief A fatal reservation remains usable while every ordinary record is held by an emitter.
 * @param depth Remaining ordinary reservations before offering the reserved record.
 */
void reserve_with_fatal(uint32_t depth)
{
	log_lazy({log_level::INFO, "logging", "test.ordinary", __func__},
		 [depth](std::span<char> output) -> std::size_t {
			 if (depth != 0) {
				 reserve_with_fatal(depth - 1);
			 } else {
				 offer_fatal_log({log_level::FATAL, "logging", "test.fatal", __func__},
						 "reserved fatal diagnostic");
			 }
			 output[0] = 'x';
			 return 1;
		 });
}

/**
 * @brief Give the reserved record its own delivery opportunity, then retire all ordinary owners.
 * @param root Protected fixture destination, retained through writer retirement.
 */
void verify_fatal_reservation(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	auto owner_or = log_service::start(options, "kinetum_cp");
	ASSERT_TRUE(owner_or.is_ok());
	auto owner = std::move(owner_or).value();
	reserve_with_fatal(255);
	EXPECT_EQ(owner->health().accepted_records, 257u);
	EXPECT_EQ(owner->health().queue_rejections, 0u);
	owner.reset();
	const auto output = test_support::read_log_file(root / "kinetum_cp.log");
	EXPECT_NE(output.find("test.fatal"), std::string::npos);
	EXPECT_EQ(std::count(output.begin(), output.end(), '\n'), 257);
}

}  // namespace

/** @brief Pin UTC precision, named severity, bracketed process identity, context, and newline framing. */
TEST(log_record, readable_record_has_exact_known_bytes)
{
	const auto record = example_record();
	std::array<char, LOG_ENCODED_BYTES> output{};
	const auto size = encode_log_record(record, output);
	ASSERT_GT(size, 0u);
	EXPECT_EQ(
		std::string_view(output.data(), size),
		"2023-11-14T22:13:20.123456Z [INFO] dut kinetum_dp[42:73] module.admitted - module/admit: images=3 contexts=3\n");
}

/** @brief Named severity preserves ordinary levels and every native override independently of filtering. */
TEST(log_record, severity_labels_preserve_ordinary_and_native_identity)
{
	auto record = example_record();
	std::array<char, LOG_ENCODED_BYTES> output{};
	constexpr std::array<std::string_view, 5> ORDINARY{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
	for (std::size_t index = 0; index < ORDINARY.size(); ++index) {
		record.level = static_cast<log_level>(index + 1);
		const auto size = encode_log_record(record, output);
		ASSERT_GT(size, 0u);
		EXPECT_NE(std::string_view(output.data(), size).find(" [" + std::string(ORDINARY[index]) + "] "),
			  std::string_view::npos);
	}
	record.level = log_level::DEBUG;
	constexpr std::array<std::string_view, 8> NATIVE{"EMERG", "ALERT",  "CRIT", "ERROR",
							 "WARN",  "NOTICE", "INFO", "DEBUG"};
	for (std::size_t index = 0; index < NATIVE.size(); ++index) {
		record.native_severity = static_cast<uint8_t>(index);
		const auto size = encode_log_record(record, output);
		ASSERT_GT(size, 0u);
		EXPECT_NE(std::string_view(output.data(), size).find(" [" + std::string(NATIVE[index]) + "] "),
			  std::string_view::npos);
	}
}

/** @brief Escape controls and literal escape markers without inventing extra records. */
TEST(log_record, message_control_bytes_are_unambiguous)
{
	auto record = example_record();
	constexpr std::string_view MESSAGE("line\n\t\\\x1b\0", 9);
	std::copy(MESSAGE.begin(), MESSAGE.end(), record.message.begin());
	record.message_size = MESSAGE.size();
	std::array<char, LOG_ENCODED_BYTES> output{};
	const auto size = encode_log_record(record, output);
	ASSERT_GT(size, 0u);
	const std::string_view encoded(output.data(), size);
	EXPECT_TRUE(encoded.ends_with("line\\x0a\\x09\\\\\\x1b\\x00\n"));
	EXPECT_EQ(std::count(encoded.begin(), encoded.end(), '\n'), 1);
	EXPECT_EQ(encoded.find('\033'), std::string_view::npos);
}

/** @brief Missing metadata remains absent and native severity names remain exact. */
TEST(log_record, missing_metadata_and_native_severity_are_not_synthesized)
{
	auto record = example_record();
	record.realtime_us = 0;
	record.process_id = 0;
	record.thread_id = 0;
	record.hostname.fill('\0');
	record.application.fill('\0');
	record.native_severity = 0;
	std::array<char, LOG_ENCODED_BYTES> output{};
	const auto size = encode_log_record(record, output);
	EXPECT_TRUE(std::string_view(output.data(), size).starts_with("- [EMERG] - -[-] module.admitted - "));
	record.native_severity = 8;
	EXPECT_EQ(encode_log_record(record, output), 0u);
}

/** @brief Maximum raw payload expansion fits the declared encoded record bound. */
TEST(log_record, maximum_expansion_is_bounded_and_truncation_is_explicit)
{
	auto record = example_record();
	record.message.fill('\0');
	record.message_size = record.message.size();
	record.truncated = true;
	std::array<char, LOG_ENCODED_BYTES> output{};
	const auto size = encode_log_record(record, output);
	ASSERT_GT(size, LOG_MESSAGE_BYTES * 4);
	EXPECT_LE(size, LOG_ENCODED_BYTES);
	EXPECT_TRUE(std::string_view(output.data(), size).ends_with("...[truncated]\n"));
	EXPECT_EQ(encode_log_record(record, std::span(output).first(LOG_ENCODED_BYTES - 1)), 0u);
}

/** @brief Complete finite-command records survive concurrent emitters without a background writer. */
TEST(common_log, concurrent_stderr_records_preserve_timestamp_and_boundaries)
{
	ASSERT_EXIT(
		{
			verify_synchronous_records();
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Undeclared internal severity is a programmer-contract fail stop. */
TEST(common_log, undeclared_severity_fails_stop)
{
	EXPECT_DEATH((void)log_enabled(static_cast<log_level>(0), "logging"), "logging ownership invariant");
}

/** @brief A full arena refuses one new record while preserving every existing owner. */
TEST(common_log, full_arena_rejects_new_without_overwriting_accepted_records)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_bounded_arena(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Concurrent service logs conserve accepted and rejected submissions and drain exactly. */
TEST(common_log, concurrent_service_records_have_one_accounted_fate)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_async_records(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Suppression avoids argument evaluation and formatter exceptions release their reservation. */
TEST(common_log, filters_and_formatter_failure_do_not_change_caller_work)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_filter_and_format_failure(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Owned text survives caller mutation and reports raw-message truncation. */
TEST(common_log, queued_records_own_bytes_and_mark_truncation)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_owned_bytes(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Partial delivery remains counted as loss until explicit file readmission. */
TEST(common_log, write_failure_counts_loss_and_requires_explicit_reopen)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_write_failure_and_reopen(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Startup-only console visibility ends at the service's existing startup gate. */
TEST(common_log, startup_errors_are_visible_without_enabling_a_runtime_mirror)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_startup_mirror(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Independent console failure is counted without changing file availability or delivery. */
TEST(common_log, console_failure_does_not_revoke_file_delivery)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_console_failure(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Fatal diagnostics do not compete for ordinary queue capacity or select the caller's action. */
TEST(common_log, fatal_offer_uses_its_reserved_record)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_fatal_reservation(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief One parser rejects duplicate, unknown-component, malformed, and overflowing settings. */
TEST(log_options, exact_values_and_duplicate_laws_are_shared)
{
	log_options options;
	log_option_parser parser(options);
	std::array<std::string, 5> arguments{"service", "--log-component-level", "module=debug", "--log-level", "warn"};
	std::array<char *, 5> argv{};
	for (std::size_t index = 0; index < argv.size(); ++index) {
		argv[index] = arguments[index].data();
	}
	int index = 1;
	ASSERT_TRUE(parser.consume(index, static_cast<int>(argv.size()), argv.data()).is_ok());
	index = 3;
	ASSERT_TRUE(parser.consume(index, static_cast<int>(argv.size()), argv.data()).is_ok());
	EXPECT_EQ(options.level, log_level::WARN);
	const auto module_component = log_component_index("module");
	ASSERT_TRUE(module_component.has_value());
	EXPECT_EQ(options.component_levels[*module_component], log_level::DEBUG);
	index = 3;
	EXPECT_FALSE(parser.consume(index, static_cast<int>(argv.size()), argv.data()).is_ok());
	index = 1;
	EXPECT_FALSE(parser.consume(index, static_cast<int>(argv.size()), argv.data()).is_ok());
	options.maximum_bytes = LOG_ENCODED_BYTES - 1;
	EXPECT_FALSE(validate_log_options(options).is_ok());
	options.maximum_bytes = UINT64_MAX;
	EXPECT_FALSE(validate_log_options(options).is_ok());
	options.maximum_bytes = LOG_ENCODED_BYTES;
	options.directory = "relative/logs";
	EXPECT_FALSE(validate_log_options(options).is_ok());
}

/** @brief Child argv preserves admitted configuration through the same exact parser. */
TEST(log_options, child_projection_keeps_every_setting)
{
	log_options options;
	options.directory = "/var/tmp/logs";
	options.console = true;
	options.keep_files = 3;
	options.maximum_bytes = 65536;
	const auto provider_component = log_component_index("provider");
	ASSERT_TRUE(provider_component.has_value());
	options.component_levels[*provider_component] = log_level::ERROR;
	const std::vector<std::string> expected{"--log-dir",
						"/var/tmp/logs",
						"--log-level",
						"info",
						"--log-max-bytes",
						"65536",
						"--log-keep-files",
						"3",
						"--log-component-level",
						"provider=error",
						"--log-console"};
	EXPECT_EQ(log_arguments(options), expected);
}

/** @brief Input errors are rejected without spelling repair or numeric clamping. */
TEST(log_options, malformed_values_are_not_repaired)
{
	const std::array<std::array<std::string, 2>, 6> invalid{{
		{"--log-level", "INFO"},
		{"--log-component-level", "unknown=debug"},
		{"--log-component-level", "cp=trace"},
		{"--log-max-bytes", "-1"},
		{"--log-max-bytes", "01234"},
		{"--log-max-bytes", "18446744073709551616"},
	}};
	for (const auto &input : invalid) {
		SCOPED_TRACE(input[1]);
		log_options options;
		log_option_parser parser(options);
		std::array<std::string, 3> arguments{"service", input[0], input[1]};
		std::array<char *, 3> argv{arguments[0].data(), arguments[1].data(), arguments[2].data()};
		int index = 1;
		EXPECT_FALSE(parser.consume(index, static_cast<int>(argv.size()), argv.data()).is_ok());
	}
}

}  // namespace kinetum::common
