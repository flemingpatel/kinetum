// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_process_image.cpp
 * @brief Failure-oriented tests for exact Linux process-image provenance.
 * @author Fleming Patel
 *
 * These tests pin the no-argv0/no-PATH/no-CWD contract, canonical executable
 * admission, and deterministic sibling resolution used by production process
 * launch.
 */

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include <sys/stat.h>
#include <unistd.h>

#include "src/common/process_image.hpp"

namespace kinetum::common
{
namespace
{

namespace fs = std::filesystem;

/**
 * @brief Own one canonical temporary directory for process-image tests.
 */
class ProcessImageTest : public ::testing::Test {
    protected:
	/** @brief Create an empty canonical directory unique to the current test. */
	void SetUp() override
	{
		const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
		root_ = fs::temp_directory_path() /
			("kinetum_process_image_" + std::to_string(static_cast<long long>(::getpid())) + "_" +
			 std::string(info->name()));
		std::error_code ec;
		fs::remove_all(root_, ec);
		ec.clear();
		fs::create_directories(root_, ec);
		ASSERT_FALSE(ec) << ec.message();
		root_ = fs::canonical(root_, ec);
		ASSERT_FALSE(ec) << ec.message();
	}

	/** @brief Remove every test-owned artifact. */
	void TearDown() override
	{
		std::error_code ec;
		fs::remove_all(root_, ec);
	}

	/**
	 * @brief Create one regular test file with exact POSIX permissions.
	 *
	 * @param name Filename relative to the test root.
	 * @param mode POSIX mode applied after writing.
	 * @return Canonical absolute file path.
	 */
	fs::path create_file(const std::string &name, mode_t mode)
	{
		const fs::path path = root_ / name;
		std::ofstream output(path, std::ios::binary | std::ios::trunc);
		output << "process-image-test\n";
		output.close();
		EXPECT_TRUE(output.good());
		EXPECT_EQ(::chmod(path.c_str(), mode), 0);
		return path;
	}

	fs::path root_;	 ///< Canonical test-owned root.
};

/**
 * @brief Verify the kernel process-image authority returns an admitted path.
 */
TEST_F(ProcessImageTest, current_image_is_canonical_absolute_and_executable)
{
	auto image_or = current_process_image();
	ASSERT_TRUE(image_or.is_ok()) << image_or.error().message();
	EXPECT_TRUE(image_or->is_absolute());
	EXPECT_EQ(*image_or, image_or->lexically_normal());
	EXPECT_TRUE(validate_exact_process_image(*image_or, "test").is_ok());
}

/**
 * @brief Verify non-exact path representations are rejected without repair.
 */
TEST_F(ProcessImageTest, relative_and_non_normalized_paths_are_rejected)
{
	auto relative = validate_exact_process_image("kinetum_dp", "child");
	EXPECT_EQ(relative.code(), status_code::INVALID_ARGUMENT);

	auto image_or = current_process_image();
	ASSERT_TRUE(image_or.is_ok()) << image_or.error().message();
	const fs::path non_normalized = image_or->parent_path() / "." / image_or->filename();
	auto result = validate_exact_process_image(non_normalized, "child");
	EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify symbolic-link indirection cannot become executable authority.
 */
TEST_F(ProcessImageTest, symlinked_process_image_is_rejected)
{
	const fs::path target = create_file("target", 0755);
	const fs::path link = root_ / "link";
	std::error_code ec;
	fs::create_symlink(target, link, ec);
	ASSERT_FALSE(ec) << ec.message();

	const auto result = validate_exact_process_image(link, "child");
	EXPECT_EQ(result.code(), status_code::FAILED_PRECONDITION);
}

/**
 * @brief Verify executable admission rejects directories and missing execute permission.
 */
TEST_F(ProcessImageTest, non_regular_and_non_executable_paths_are_rejected)
{
	const auto directory = validate_exact_process_image(root_, "child");
	EXPECT_EQ(directory.code(), status_code::FAILED_PRECONDITION);

	const fs::path file = create_file("not_executable", 0644);
	const auto non_executable = validate_exact_process_image(file, "child");
	EXPECT_EQ(non_executable.code(), status_code::PERMISSION_DENIED);
}

/**
 * @brief Verify sibling resolution uses the admitted parent image directory.
 */
TEST_F(ProcessImageTest, exact_sibling_is_resolved_from_parent_image)
{
	const fs::path supervisor = create_file("kinetum_photon", 0755);
	const fs::path dataplane = create_file("kinetum_dp", 0755);

	auto sibling_or = resolve_sibling_process_image(supervisor, "kinetum_dp");
	ASSERT_TRUE(sibling_or.is_ok()) << sibling_or.error().message();
	EXPECT_EQ(*sibling_or, dataplane);
}

/**
 * @brief Verify unsafe names and absent siblings fail instead of searching.
 */
TEST_F(ProcessImageTest, unsafe_or_missing_sibling_is_rejected)
{
	const fs::path supervisor = create_file("kinetum_photon", 0755);

	auto nested = resolve_sibling_process_image(supervisor, "bin/kinetum_dp");
	ASSERT_FALSE(nested.is_ok());
	EXPECT_EQ(nested.error().code(), status_code::INVALID_ARGUMENT);
	auto whitespace = resolve_sibling_process_image(supervisor, "kinetum dp");
	ASSERT_FALSE(whitespace.is_ok());
	EXPECT_EQ(whitespace.error().code(), status_code::INVALID_ARGUMENT);
	const std::string embedded_nul("kinetum_dp\0shadow", 17);
	auto truncated = resolve_sibling_process_image(supervisor, embedded_nul);
	ASSERT_FALSE(truncated.is_ok());
	EXPECT_EQ(truncated.error().code(), status_code::INVALID_ARGUMENT);

	auto missing = resolve_sibling_process_image(supervisor, "kinetum_dp");
	ASSERT_FALSE(missing.is_ok());
	EXPECT_EQ(missing.error().code(), status_code::NOT_FOUND);
}

}  // namespace
}  // namespace kinetum::common
