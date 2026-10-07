// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_log_file.cpp
 * @brief Log file ownership, retention, interrupted rotation, and checked reopen.
 * @author Fleming Patel
 */

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include <sys/resource.h>

#include <gtest/gtest.h>

#include "src/common/log_file.hpp"
#include "tests/log_test_support.hpp"

namespace kinetum::common
{
namespace
{

/**
 * @param marker Distinct record identity for independently checking archive contents.
 * @return Large encoded ASCII record representing fewer than 8 KiB of raw message bytes.
 */
std::string large_record(char marker)
{
	std::string result = "- [INFO] dut kinetum_cp[10:11] test.record - logging: ";
	result += marker;
	for (int index = 0; index < 5000; ++index) {
		result += "\\x00";
	}
	result += '\n';
	return result;
}

/**
 * @brief Write an independently authored crash-recovery file before admitting its owner.
 * @param path Fixture-owned destination created or replaced before logger admission.
 * @param bytes Exact seeded file contents.
 */
void write_fixture(const std::filesystem::path &path, std::string_view bytes)
{
	std::ofstream output(path, std::ios::binary | std::ios::trunc);
	ASSERT_TRUE(output.is_open());
	output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
	output.close();
	ASSERT_FALSE(output.fail());
	std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
}

/**
 * @brief Exercise native EMFILE after rename progress without modifying another process's limits.
 * @param root Protected fixture destination retained through file-owner retirement.
 */
void verify_partial_rotation_failure(const std::filesystem::path &root)
{
	log_options options;
	options.directory = root.string();
	options.maximum_bytes = LOG_ENCODED_BYTES;
	options.keep_files = 2;
	log_file file;
	ASSERT_TRUE(file.open(options, "kinetum_cp").is_ok());
	const auto first = large_record('A');
	const auto second = large_record('B');
	const auto third = large_record('C');
	ASSERT_TRUE(file.append(first).is_ok());
	ASSERT_TRUE(file.append(second).is_ok());
	rlimit original{};
	ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &original), 0);
	const rlimit restricted{3, original.rlim_max};
	ASSERT_EQ(::setrlimit(RLIMIT_NOFILE, &restricted), 0);
	const auto failed = file.append(third);
	const int restored = ::setrlimit(RLIMIT_NOFILE, &original);
	ASSERT_EQ(restored, 0);
	EXPECT_FALSE(failed.is_ok());
	EXPECT_EQ(test_support::read_log_file(root / "kinetum_cp.log.1"), second);
	EXPECT_EQ(test_support::read_log_file(root / "kinetum_cp.log.2"), first);
	ASSERT_TRUE(file.reopen().is_ok());
	ASSERT_TRUE(file.append(third).is_ok());
	ASSERT_TRUE(file.close().is_ok());
	EXPECT_EQ(test_support::read_log_file(root / "kinetum_cp.log"), third);
	EXPECT_EQ(test_support::read_log_file(root / "kinetum_cp.log.1"), second);
	EXPECT_FALSE(std::filesystem::exists(root / "kinetum_cp.log.2"));
}

}  // namespace

/** @brief Rotate complete records within both the file-size and total-file bounds. */
TEST(log_file, retains_exact_complete_records_in_newest_first_order)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	log_options options;
	options.directory = directory.path().string();
	options.maximum_bytes = LOG_ENCODED_BYTES;
	options.keep_files = 3;
	log_file file;
	ASSERT_TRUE(file.open(options, "kinetum_cp").is_ok());
	for (char marker : {'A', 'B', 'C', 'D'}) {
		ASSERT_TRUE(file.append(large_record(marker)).is_ok());
	}
	ASSERT_TRUE(file.close().is_ok());
	EXPECT_EQ(test_support::read_log_file(directory.path() / "kinetum_cp.log"), large_record('D'));
	EXPECT_EQ(test_support::read_log_file(directory.path() / "kinetum_cp.log.1"), large_record('C'));
	EXPECT_EQ(test_support::read_log_file(directory.path() / "kinetum_cp.log.2"), large_record('B'));
	EXPECT_FALSE(std::filesystem::exists(directory.path() / "kinetum_cp.log.3"));
}

/** @brief One role's process lock survives active-file rotation and excludes another writer. */
TEST(log_file, duplicate_writer_rejects_without_disrupting_live_owner)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	log_options options;
	options.directory = directory.path().string();
	options.maximum_bytes = LOG_ENCODED_BYTES;
	log_file first;
	ASSERT_TRUE(first.open(options, "kinetum_cp").is_ok());
	ASSERT_TRUE(first.append(large_record('A')).is_ok());
	ASSERT_TRUE(first.append(large_record('B')).is_ok());
	log_file duplicate;
	EXPECT_FALSE(duplicate.open(options, "kinetum_cp").is_ok());
	ASSERT_TRUE(first.append(large_record('C')).is_ok());
	ASSERT_TRUE(first.close().is_ok());
	EXPECT_TRUE(duplicate.open(options, "kinetum_cp").is_ok());
}

/** @brief Startup rejects symlink and multiply-linked targets without changing their bytes. */
TEST(log_file, foreign_file_aliases_are_not_admitted_or_truncated)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	const auto original = directory.path() / "foreign";
	write_fixture(original, "must survive");
	const auto active = directory.path() / "kinetum_cp.log";
	std::filesystem::create_symlink(original, active);
	log_options options;
	options.directory = directory.path().string();
	log_file file;
	EXPECT_FALSE(file.open(options, "kinetum_cp").is_ok());
	EXPECT_EQ(test_support::read_log_file(original), "must survive");
	ASSERT_TRUE(std::filesystem::remove(active));
	std::filesystem::create_hard_link(original, active);
	EXPECT_FALSE(file.open(options, "kinetum_cp").is_ok());
	EXPECT_EQ(test_support::read_log_file(original), "must survive");
}

/** @brief A crash tail remains intact and later records start on a distinct line. */
TEST(log_file, preserves_incomplete_tail_before_append)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	const auto active = directory.path() / "kinetum_cp.log";
	write_fixture(active, "- [INFO] interrupted");
	log_options options;
	options.directory = directory.path().string();
	log_file file;
	ASSERT_TRUE(file.open(options, "kinetum_cp").is_ok());
	const std::string next = "- [INFO] dut kinetum_cp[10:11] test - logging: resumed\n";
	ASSERT_TRUE(file.append(next).is_ok());
	ASSERT_TRUE(file.close().is_ok());
	EXPECT_EQ(test_support::read_log_file(active), "- [INFO] interrupted\n" + next);
}

/** @brief Resume an interrupted descending rename without overwriting surviving archives. */
TEST(log_file, resumes_parked_oldest_and_archive_gap)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	write_fixture(directory.path() / "kinetum_cp.log", large_record('D'));
	write_fixture(directory.path() / "kinetum_cp.log.1", large_record('C'));
	write_fixture(directory.path() / "kinetum_cp.log.3", large_record('B'));
	write_fixture(directory.path() / "kinetum_cp.log.4", large_record('A'));
	log_options options;
	options.directory = directory.path().string();
	options.maximum_bytes = LOG_ENCODED_BYTES;
	options.keep_files = 4;
	log_file file;
	ASSERT_TRUE(file.open(options, "kinetum_cp").is_ok());
	ASSERT_TRUE(file.append(large_record('E')).is_ok());
	ASSERT_TRUE(file.close().is_ok());
	EXPECT_EQ(test_support::read_log_file(directory.path() / "kinetum_cp.log"), large_record('E'));
	EXPECT_EQ(test_support::read_log_file(directory.path() / "kinetum_cp.log.1"), large_record('D'));
	EXPECT_EQ(test_support::read_log_file(directory.path() / "kinetum_cp.log.2"), large_record('C'));
	EXPECT_EQ(test_support::read_log_file(directory.path() / "kinetum_cp.log.3"), large_record('B'));
	EXPECT_FALSE(std::filesystem::exists(directory.path() / "kinetum_cp.log.4"));
}

/** @brief Descriptor exhaustion after rename progress preserves bytes until explicit recovery. */
TEST(log_file, failed_rotation_never_truncates_or_discards_uncommitted_archives)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	ASSERT_EXIT(
		{
			verify_partial_rotation_failure(directory.path());
			std::_Exit(::testing::Test::HasFailure() ? 1 : 0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief A smaller configured limit refuses oversized prior data rather than silently deleting it. */
TEST(log_file, preexisting_data_must_fit_the_selected_retention_contract)
{
	test_support::log_test_directory directory;
	ASSERT_FALSE(directory.path().empty());
	const std::string oversized(LOG_ENCODED_BYTES + 1, 'x');
	write_fixture(directory.path() / "kinetum_cp.log.1", oversized);
	log_options options;
	options.directory = directory.path().string();
	options.maximum_bytes = LOG_ENCODED_BYTES;
	log_file file;
	EXPECT_FALSE(file.open(options, "kinetum_cp").is_ok());
	EXPECT_EQ(test_support::read_log_file(directory.path() / "kinetum_cp.log.1"), oversized);
}

}  // namespace kinetum::common
