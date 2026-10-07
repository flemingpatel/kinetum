// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file log_test_support.hpp
 * @brief Exact temporary-file ownership for native logging tests.
 * @author Fleming Patel
 */

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include <fcntl.h>
#include <unistd.h>

namespace kinetum::test_support
{

/** @brief Own only the directory created by this fixture and its test artifacts. */
class log_test_directory final {
    public:
	/** @brief Create one protected Linux temporary directory. */
	log_test_directory()
	{
		char pattern[] = "/tmp/kinetum-log-test.XXXXXX";
		if (const char *created = ::mkdtemp(pattern); created != nullptr) {
			path_ = created;
		}
	}
	/** @brief Remove this fixture's artifacts after every child and writer has retired. */
	~log_test_directory()
	{
		if (!path_.empty()) {
			std::error_code error;
			std::filesystem::remove_all(path_, error);
		}
	}
	log_test_directory(const log_test_directory &) = delete;
	log_test_directory &operator=(const log_test_directory &) = delete;
	/** @return Exact owned root, or empty after creation failure. */
	[[nodiscard]] const std::filesystem::path &path() const noexcept
	{
		return path_;
	}

    private:
	std::filesystem::path path_;  ///< Sole fixture-created root.
};

/**
 * @brief Own a descriptor-level stderr capture inside an isolated test process.
 *
 * Google Test already captures stderr for a death test. This independent
 * file redirection preserves that outer descriptor and restores it before
 * assertions inspect the captured bytes. Every emitter must retire before
 * finish(); the scope restores stderr on an earlier assertion return as well.
 */
class log_stderr_capture final {
    public:
	/** @brief Admit a private regular file and redirect stderr while retaining its prior descriptor. */
	log_stderr_capture()
	{
		if (directory_.path().empty() || std::fflush(stderr) != 0) {
			return;
		}
		capture_ = ::open((directory_.path() / "stderr").c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		if (capture_ < 0) {
			return;
		}
		saved_ = ::fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);
		if (saved_ >= 0) {
			active_ = redirect_(capture_);
		}
	}
	/** @brief Restore the exact outer capture before releasing fixture descriptors and files. */
	~log_stderr_capture()
	{
		if (active_ && !restore_()) {
			std::terminate();
		}
		if (saved_ >= 0) {
			(void)::close(saved_);
		}
		if (capture_ >= 0) {
			(void)::close(capture_);
		}
	}
	log_stderr_capture(const log_stderr_capture &) = delete;
	log_stderr_capture &operator=(const log_stderr_capture &) = delete;
	/** @return True only after complete descriptor admission and redirection. */
	[[nodiscard]] bool valid() const noexcept
	{
		return active_;
	}
	/**
	 * @brief Restore outer diagnostics and read the completed capture with checked I/O.
	 * @param output Caller-owned destination, cleared before reading.
	 * @return True only after complete flush, restoration, seek, and read.
	 * @throws std::bad_alloc or std::length_error if the caller's string cannot hold the capture.
	 */
	[[nodiscard]] bool finish(std::string &output)
	{
		if (!active_) {
			return false;
		}
		const bool flushed = std::fflush(stderr) == 0;
		if (!restore_() || !flushed || ::lseek(capture_, 0, SEEK_SET) != 0) {
			return false;
		}
		output.clear();
		std::array<char, 4096> bytes{};
		for (;;) {
			const ssize_t count = ::read(capture_, bytes.data(), bytes.size());
			if (count < 0 && errno == EINTR) {
				continue;
			}
			if (count <= 0) {
				return count == 0;
			}
			output.append(bytes.data(), static_cast<std::size_t>(count));
		}
	}

    private:
	/** @param source Live source descriptor. @return True after exact stderr replacement. */
	[[nodiscard]] static bool redirect_(int source) noexcept
	{
		int result;
		do {
			result = ::dup2(source, STDERR_FILENO);
		} while (result < 0 && errno == EINTR);
		return result == STDERR_FILENO;
	}
	/** @return True after releasing the active redirection without losing the outer descriptor. */
	[[nodiscard]] bool restore_() noexcept
	{
		if (!redirect_(saved_)) {
			return false;
		}
		active_ = false;
		return true;
	}

	log_test_directory directory_;	///< Private capture root outlives every descriptor.
	int saved_{-1};			///< Exact outer stderr destination.
	int capture_{-1};		///< Private seekable capture file.
	bool active_{false};		///< This scope currently owns stderr redirection.
};

/**
 * @param path Exact test-owned file after its writer retires.
 * @return Complete file bytes; failed input produces an empty observation.
 */
[[nodiscard]] inline std::string read_log_file(const std::filesystem::path &path)
{
	std::ifstream input(path, std::ios::binary);
	return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

}  // namespace kinetum::test_support
