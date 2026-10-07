// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_file_io.cpp
 * @brief Exact bounded reads and durable publication tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include <sys/stat.h>
#include <unistd.h>

#include "gen/kinetum/common/v1/common.pb.h"
#include "src/common/file_io.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/status.hpp"

namespace kinetum::common
{
namespace
{

/** @brief Scope-bound regular file containing one exact byte sequence. */
class scoped_test_file {
    public:
	/**
	 * @brief Create and completely write one private temporary file.
	 * @param contents Exact file bytes.
	 */
	explicit scoped_test_file(std::string_view contents)
	{
		char pattern[] = "/tmp/kinetum_file_io_XXXXXX";
		const int descriptor = ::mkstemp(pattern);
		if (descriptor < 0) {
			return;
		}
		path_ = pattern;
		const char *next = contents.data();
		std::size_t remaining = contents.size();
		while (remaining != 0u) {
			const ssize_t written = ::write(descriptor, next, remaining);
			if (written < 0 && errno == EINTR) {
				continue;
			}
			if (written <= 0) {
				(void)::close(descriptor);
				return;
			}
			const std::size_t count = static_cast<std::size_t>(written);
			next += count;
			remaining -= count;
		}
		valid_ = ::close(descriptor) == 0;
	}

	/** @brief Remove the exact temporary file when one was created. */
	~scoped_test_file()
	{
		if (!path_.empty()) {
			(void)::unlink(path_.c_str());
		}
	}

	scoped_test_file(const scoped_test_file &) = delete;
	scoped_test_file &operator=(const scoped_test_file &) = delete;

	/** @return true when creation, writing, and close all completed. */
	[[nodiscard]] bool valid() const noexcept
	{
		return valid_;
	}

	/** @return Exact temporary path. */
	[[nodiscard]] const std::string &path() const noexcept
	{
		return path_;
	}

    private:
	std::string path_;   ///< Created temporary path, or empty before creation.
	bool valid_{false};  ///< Complete publication result.
};

/** @brief Scope-bound private directory for publication tests. */
class scoped_test_directory {
    public:
	/** @brief Create one empty private temporary directory. */
	scoped_test_directory()
	{
		char pattern[] = "/tmp/kinetum_file_io_dir_XXXXXX";
		if (char *created = ::mkdtemp(pattern); created != nullptr) {
			path_ = created;
		}
	}

	/** @brief Recursively remove the exact private test directory. */
	~scoped_test_directory()
	{
		if (!path_.empty()) {
			std::error_code error;
			(void)std::filesystem::remove_all(path_, error);
		}
	}

	scoped_test_directory(const scoped_test_directory &) = delete;
	scoped_test_directory &operator=(const scoped_test_directory &) = delete;

	/** @return true exactly when directory creation succeeded. */
	[[nodiscard]] bool valid() const noexcept
	{
		return !path_.empty();
	}

	/** @return Borrowed exact test-directory path. */
	[[nodiscard]] const std::filesystem::path &path() const noexcept
	{
		return path_;
	}

    private:
	std::filesystem::path path_;  ///< Created private directory, or empty on failure.
};

/** @brief Scope-bound process umask override for exact-mode publication evidence. */
class scoped_umask {
    public:
	/**
	 * @brief Install one temporary process umask.
	 * @param value Mask active until this owner is destroyed.
	 */
	explicit scoped_umask(mode_t value) noexcept
		: prior_(::umask(value))
	{
	}

	/** @brief Restore the exact process umask observed at construction. */
	~scoped_umask()
	{
		(void)::umask(prior_);
	}

	scoped_umask(const scoped_umask &) = delete;
	scoped_umask &operator=(const scoped_umask &) = delete;

    private:
	mode_t prior_;	///< Exact process umask to restore.
};

/**
 * @brief Count the complete member set of one private test directory.
 * @param directory Existing test directory.
 * @return Number of direct directory entries.
 */
std::size_t directory_entry_count(const std::filesystem::path &directory)
{
	std::size_t count = 0;
	for (const auto &entry : std::filesystem::directory_iterator(directory)) {
		(void)entry;
		++count;
	}
	return count;
}

/**
 * @brief Return the exact permission bits for one existing filesystem object.
 * @param path Existing object path.
 * @return Low twelve mode bits, or no value when stat fails.
 */
std::optional<uint32_t> permission_bits(const std::filesystem::path &path) noexcept
{
	struct stat metadata{};
	if (::stat(path.c_str(), &metadata) != 0) {
		return std::nullopt;
	}
	return static_cast<uint32_t>(metadata.st_mode) & 07777u;
}

/** @brief An exact maximum admits and preserves every byte. */
TEST(file_io, exact_read_bound_succeeds_byte_for_byte)
{
	const std::string payload(4096u, 'x');
	scoped_test_file file(payload);
	ASSERT_TRUE(file.valid());

	const auto result = read_file_to_string(file.path(), payload.size());

	ASSERT_TRUE(result.is_ok()) << result.error().message();
	EXPECT_EQ(result.value(), payload);
}

/** @brief Observing one byte beyond the maximum fails before appending it. */
TEST(file_io, next_byte_beyond_read_bound_is_resource_exhausted)
{
	const std::string payload(4097u, 'y');
	scoped_test_file file(payload);
	ASSERT_TRUE(file.valid());

	const auto result = read_file_to_string(file.path(), payload.size() - 1u);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::RESOURCE_EXHAUSTED);
}

/** @brief Zero capacity rejects, while an absent source retains NOT_FOUND. */
TEST(file_io, zero_bound_and_missing_file_keep_exact_status_categories)
{
	std::string missing_path;
	{
		scoped_test_file file("removed");
		ASSERT_TRUE(file.valid());
		missing_path = file.path();
	}

	const auto zero = read_file_to_string(missing_path, 0u);
	ASSERT_FALSE(zero.is_ok());
	EXPECT_EQ(zero.error().code(), status_code::INVALID_ARGUMENT);

	const auto missing = read_file_to_string(missing_path, 1u);
	ASSERT_FALSE(missing.is_ok());
	EXPECT_EQ(missing.error().code(), status_code::NOT_FOUND);
}

/** @brief A Linux size-zero procfs source remains subject to the byte bound. */
TEST(file_io, procfs_reported_size_zero_cannot_bypass_incremental_bound)
{
	constexpr const char *PROC_MAPS_PATH = "/proc/self/maps";
	struct stat metadata{};
	ASSERT_EQ(::stat(PROC_MAPS_PATH, &metadata), 0);
	ASSERT_EQ(metadata.st_size, 0);

	const auto result = read_file_to_string(PROC_MAPS_PATH, 1u);

	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::RESOURCE_EXHAUSTED);
}

/** @brief Protobuf-text file admission obeys only its explicit caller bound. */
TEST(file_io, pbtxt_reader_requires_and_enforces_one_explicit_bound)
{
	const std::string payload = "code: 0\nerror_code: ERROR_CODE_UNSPECIFIED\n";
	scoped_test_file file(payload);
	ASSERT_TRUE(file.valid());

	kinetum::common::v1::Status parsed;
	const auto exact = read_pbtxt_file(file.path(), payload.size(), &parsed);
	ASSERT_TRUE(exact.is_ok()) << exact.message();
	EXPECT_EQ(parsed.code(), 0);
	EXPECT_EQ(parsed.error_code(), kinetum::common::v1::ERROR_CODE_UNSPECIFIED);

	const auto next_byte = read_pbtxt_file(file.path(), payload.size() - 1u, &parsed);
	EXPECT_EQ(next_byte.code(), status_code::RESOURCE_EXHAUSTED);
	const auto zero = read_pbtxt_file(file.path(), 0u, &parsed);
	EXPECT_EQ(zero.code(), status_code::INVALID_ARGUMENT);
	const auto null_destination = read_pbtxt_file(file.path() + ".absent", 1u, nullptr);
	EXPECT_EQ(null_destination.code(), status_code::INVALID_ARGUMENT);
}

/** @brief Replacement accepts ordinary double dots, fixes mode, and cleans failed publication. */
TEST(file_io, replacement_is_exact_mode_and_residue_free)
{
	scoped_test_directory directory;
	ASSERT_TRUE(directory.valid());
	const auto target = directory.path() / "value..txt";
	scoped_umask restrictive_umask(0077);

	const auto first_publication = write_string_to_file(target, "first");
	ASSERT_TRUE(first_publication.is_ok()) << first_publication.message();
	const auto first_mode = permission_bits(target);
	ASSERT_TRUE(first_mode.has_value());
	EXPECT_EQ(*first_mode, 0644u);
	const auto first = read_file_to_string(target.string());
	ASSERT_TRUE(first.is_ok()) << first.error().message();
	EXPECT_EQ(first.value(), "first");

	const auto replacement_publication = write_string_to_file(target, "replacement");
	ASSERT_TRUE(replacement_publication.is_ok()) << replacement_publication.message();
	const auto replacement = read_file_to_string(target.string());
	ASSERT_TRUE(replacement.is_ok()) << replacement.error().message();
	EXPECT_EQ(replacement.value(), "replacement");
	const auto replacement_mode = permission_bits(target);
	ASSERT_TRUE(replacement_mode.has_value());
	EXPECT_EQ(*replacement_mode, 0644u);

	const auto occupied = directory.path() / "occupied";
	ASSERT_TRUE(std::filesystem::create_directory(occupied));
	const auto failed_publication = write_string_to_file(occupied, "must not publish");
	EXPECT_FALSE(failed_publication.is_ok());
	EXPECT_TRUE(std::filesystem::is_directory(occupied));
	EXPECT_EQ(directory_entry_count(directory.path()), 2u);
}

/** @brief Create-only publication is complete, exact-mode, and preserves an existing target. */
TEST(file_io, create_only_publication_preserves_existing_target_without_residue)
{
	scoped_test_directory directory;
	ASSERT_TRUE(directory.valid());
	const auto target = directory.path() / "created.txt";

	const auto created = publish_new_string_file(target, "original");
	ASSERT_TRUE(created.is_ok()) << created.message();
	const auto mode = permission_bits(target);
	ASSERT_TRUE(mode.has_value());
	EXPECT_EQ(*mode, 0644u);

	const auto duplicate = publish_new_string_file(target, "replacement");
	ASSERT_FALSE(duplicate.is_ok());
	EXPECT_EQ(duplicate.code(), status_code::ALREADY_EXISTS);
	const auto contents = read_file_to_string(target.string());
	ASSERT_TRUE(contents.is_ok()) << contents.error().message();
	EXPECT_EQ(contents.value(), "original");
	EXPECT_EQ(directory_entry_count(directory.path()), 1u);
}

}  // namespace
}  // namespace kinetum::common
