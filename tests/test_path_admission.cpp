// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_path_admission.cpp
 * @brief Unit tests for explicit cold-path artifact admission.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include <unistd.h>

#include "src/common/path_admission.hpp"
#include "src/common/status.hpp"

namespace kinetum::common
{
namespace
{

namespace fs = std::filesystem;

/** @brief Own one temporary filesystem tree for artifact-admission tests. */
class PathAdmissionTest : public ::testing::Test {
    protected:
	/** @brief Create one canonical test-owned directory. */
	void SetUp() override
	{
		const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
		root_ = fs::temp_directory_path() /
			("kinetum_path_admission_" + std::to_string(static_cast<long long>(::getpid())) + "_" +
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
	 * @brief Create one regular test artifact.
	 *
	 * @param name Filename relative to the test root.
	 * @return Canonical absolute artifact path.
	 */
	fs::path create_file(const std::string &name)
	{
		const fs::path path = root_ / name;
		std::ofstream output(path, std::ios::binary | std::ios::trunc);
		output << "artifact\n";
		output.close();
		EXPECT_TRUE(output.good());
		return path;
	}

	fs::path root_;	 ///< Canonical test-owned directory.
};

/** @brief Verify explicit relative input resolves once to canonical identity. */
TEST_F(PathAdmissionTest, relative_file_resolves_to_canonical_absolute_identity)
{
	const fs::path artifact = create_file("module.so");
	std::error_code ec;
	const fs::path relative = fs::relative(artifact, fs::current_path(), ec);
	ASSERT_FALSE(ec) << ec.message();
	ASSERT_FALSE(relative.is_absolute());

	auto admitted_or = admit_explicit_regular_file(relative, "module source");
	ASSERT_TRUE(admitted_or.is_ok()) << admitted_or.error().message();
	EXPECT_EQ(*admitted_or, artifact);
}

/** @brief Verify a symlink is resolved to one canonical artifact identity. */
TEST_F(PathAdmissionTest, symbolic_link_input_returns_canonical_target)
{
	const fs::path artifact = create_file("module.so");
	const fs::path link = root_ / "module-link.so";
	std::error_code ec;
	fs::create_symlink(artifact, link, ec);
	ASSERT_FALSE(ec) << ec.message();

	auto admitted_or = admit_explicit_regular_file(link, "module source");
	ASSERT_TRUE(admitted_or.is_ok()) << admitted_or.error().message();
	EXPECT_EQ(*admitted_or, artifact);
}

/** @brief Verify absent and non-regular artifacts fail closed. */
TEST_F(PathAdmissionTest, missing_and_non_regular_inputs_are_rejected)
{
	auto missing = admit_explicit_regular_file(root_ / "missing.so", "module source");
	ASSERT_FALSE(missing.is_ok());
	EXPECT_EQ(missing.error().code(), status_code::NOT_FOUND);

	auto directory = admit_explicit_regular_file(root_, "module source");
	ASSERT_FALSE(directory.is_ok());
	EXPECT_EQ(directory.error().code(), status_code::FAILED_PRECONDITION);
}

/** @brief Verify an explicit relative directory resolves to canonical identity. */
TEST_F(PathAdmissionTest, relative_directory_resolves_to_canonical_absolute_identity)
{
	std::error_code ec;
	const fs::path relative = fs::relative(root_, fs::current_path(), ec);
	ASSERT_FALSE(ec) << ec.message();
	ASSERT_FALSE(relative.is_absolute());

	auto admitted_or = admit_explicit_directory(relative, "binary source directory");
	ASSERT_TRUE(admitted_or.is_ok()) << admitted_or.error().message();
	EXPECT_EQ(*admitted_or, root_);
}

/** @brief Verify directory admission rejects a regular-file target. */
TEST_F(PathAdmissionTest, directory_admission_rejects_regular_file)
{
	const fs::path artifact = create_file("not-a-directory");
	auto admitted_or = admit_explicit_directory(artifact, "binary source directory");
	ASSERT_FALSE(admitted_or.is_ok());
	EXPECT_EQ(admitted_or.error().code(), status_code::FAILED_PRECONDITION);
}

/** @brief Verify exact regular-file admission rejects repaired representations. */
TEST_F(PathAdmissionTest, exact_regular_file_requires_canonical_symlink_free_identity)
{
	const fs::path artifact = create_file("module.so");
	EXPECT_TRUE(validate_exact_regular_file(artifact, "module artifact").is_ok());

	std::error_code ec;
	const fs::path relative = fs::relative(artifact, fs::current_path(), ec);
	ASSERT_FALSE(ec) << ec.message();
	EXPECT_EQ(validate_exact_regular_file(relative, "module artifact").code(), status_code::INVALID_ARGUMENT);

	const fs::path link = root_ / "module-link.so";
	fs::create_symlink(artifact, link, ec);
	ASSERT_FALSE(ec) << ec.message();
	EXPECT_EQ(validate_exact_regular_file(link, "module artifact").code(), status_code::FAILED_PRECONDITION);
}

/** @brief Verify exact directory admission enforces object kind and identity. */
TEST_F(PathAdmissionTest, exact_directory_requires_canonical_directory_identity)
{
	EXPECT_TRUE(validate_exact_directory(root_, "installation prefix").is_ok());

	const fs::path artifact = create_file("not-a-directory");
	EXPECT_EQ(validate_exact_directory(artifact, "installation prefix").code(), status_code::FAILED_PRECONDITION);

	const fs::path non_normal = root_ / ".";
	EXPECT_EQ(validate_exact_directory(non_normal, "installation prefix").code(), status_code::INVALID_ARGUMENT);

	const fs::path target = root_ / "exact-directory-target";
	const fs::path link = root_ / "exact-directory-link";
	std::error_code ec;
	fs::create_directories(target, ec);
	ASSERT_FALSE(ec) << ec.message();
	fs::create_directory_symlink(target, link, ec);
	ASSERT_FALSE(ec) << ec.message();
	EXPECT_EQ(validate_exact_directory(link, "installation prefix").code(), status_code::FAILED_PRECONDITION);
}

}  // namespace
}  // namespace kinetum::common
