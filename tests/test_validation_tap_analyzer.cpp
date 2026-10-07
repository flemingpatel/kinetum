// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_validation_tap_analyzer.cpp
 * @brief Real-image output tests for the native TAP analyzer.
 * @author Fleming Patel
 *
 * The test supplies one exact empty classic PCAP, preserving analysis
 * semantics while isolating the analyzer's final JSON delivery boundary.
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef KINETUM_VALIDATION_TAP_ANALYZER_PATH
#error "KINETUM_VALIDATION_TAP_ANALYZER_PATH must name the exact native analyzer image"
#endif

namespace kinetum::validation
{
namespace
{

/** Maximum lifetime of one exact analyzer child in this test process. */
constexpr unsigned int TEST_CHILD_TIMEOUT_SECONDS = 10u;

/** Exact output destination for one analyzer child. */
enum class analyzer_output_destination : uint8_t {
	CAPTURE,  ///< Capture merged stdout/stderr.
	FULL,	  ///< Route stdout/stderr to /dev/full.
};

/** @brief Scope-bound owner for one exact empty classic-PCAP file. */
class empty_pcap final {
    public:
	/** @brief Create and write one fresh PCAP header. */
	empty_pcap()
	{
		std::string pattern = (std::filesystem::temp_directory_path() / "kinetum_tap_analyzer.XXXXXX").string();
		std::vector<char> writable(pattern.begin(), pattern.end());
		writable.push_back('\0');
		const int descriptor = ::mkstemp(writable.data());
		if (descriptor < 0) {
			return;
		}
		path_ = writable.data();
		const std::uint8_t header[]{
			0xd4, 0xc3, 0xb2, 0xa1,	 // Little-endian microsecond magic.
			0x02, 0x00, 0x04, 0x00,	 // Version 2.4.
			0x00, 0x00, 0x00, 0x00,	 // Time-zone correction.
			0x00, 0x00, 0x00, 0x00,	 // Timestamp accuracy.
			0xff, 0xff, 0x00, 0x00,	 // Snapshot length 65535.
			0x01, 0x00, 0x00, 0x00,	 // Ethernet link type.
		};
		std::size_t offset = 0;
		while (offset < sizeof(header)) {
			const ssize_t count = ::write(descriptor, header + offset, sizeof(header) - offset);
			if (count > 0) {
				offset += static_cast<std::size_t>(count);
				continue;
			}
			if (count < 0 && errno == EINTR) {
				continue;
			}
			break;
		}
		const int close_result = ::close(descriptor);
		valid_ = offset == sizeof(header) && close_result == 0;
	}

	/** @brief Remove the exact test file. */
	~empty_pcap()
	{
		if (!path_.empty()) {
			std::error_code error;
			std::filesystem::remove(path_, error);
		}
	}

	/** @brief Disable file-ownership aliasing. */
	empty_pcap(const empty_pcap &) = delete;

	/** @brief Disable replacement of file ownership. */
	empty_pcap &operator=(const empty_pcap &) = delete;

	/** @return true when the exact header was written completely. */
	[[nodiscard]] bool valid() const noexcept
	{
		return valid_;
	}

	/** @return Exact absolute PCAP path. */
	[[nodiscard]] const std::filesystem::path &path() const noexcept
	{
		return path_;
	}

    private:
	std::filesystem::path path_;  ///< Exact owned PCAP path.
	bool valid_{false};	      ///< Complete-header publication result.
};

/** @brief Complete analyzer process observation. */
struct analyzer_result {
	int exit_code{-1};   ///< Normal process exit code, or -1 when abnormal.
	std::string output;  ///< Complete merged output when captured.
};

/**
 * @brief Launch the exact analyzer over one empty PCAP.
 *
 * @param pcap Exact PCAP input path.
 * @param destination Capture output or route it to /dev/full.
 * @return Child exit status and captured bytes.
 */
[[nodiscard]] analyzer_result run_analyzer(const std::filesystem::path &pcap, analyzer_output_destination destination)
{
	int output_pipe[2]{};
	if (::pipe(output_pipe) != 0) {
		return {};
	}
	std::vector<std::string> storage{
		KINETUM_VALIDATION_TAP_ANALYZER_PATH, "--pcap", pcap.string(), "--expected", "0", "--no-latency"};
	std::vector<char *> argv;
	argv.reserve(storage.size() + 1u);
	for (auto &argument : storage) {
		argv.push_back(argument.data());
	}
	argv.push_back(nullptr);

	const pid_t child = ::fork();
	if (child < 0) {
		(void)::close(output_pipe[0]);
		(void)::close(output_pipe[1]);
		return {};
	}
	if (child == 0) {
		(void)::close(output_pipe[0]);
		int output_descriptor = output_pipe[1];
		if (destination == analyzer_output_destination::FULL) {
			output_descriptor = ::open("/dev/full", O_WRONLY | O_CLOEXEC);
			if (output_descriptor < 0) {
				::_exit(126);
			}
		}
		if (::dup2(output_descriptor, STDOUT_FILENO) < 0 || ::dup2(output_descriptor, STDERR_FILENO) < 0) {
			::_exit(126);
		}
		if (output_descriptor != output_pipe[1]) {
			(void)::close(output_descriptor);
		}
		(void)::close(output_pipe[1]);
		(void)::alarm(TEST_CHILD_TIMEOUT_SECONDS);
		::execv(KINETUM_VALIDATION_TAP_ANALYZER_PATH, argv.data());
		::_exit(127);
	}

	(void)::close(output_pipe[1]);
	analyzer_result result;
	char buffer[512];
	for (;;) {
		const ssize_t count = ::read(output_pipe[0], buffer, sizeof(buffer));
		if (count > 0) {
			result.output.append(buffer, static_cast<std::size_t>(count));
			continue;
		}
		if (count < 0 && errno == EINTR) {
			continue;
		}
		break;
	}
	(void)::close(output_pipe[0]);
	int wait_status = 0;
	pid_t waited = -1;
	do {
		waited = ::waitpid(child, &wait_status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited == child && WIFEXITED(wait_status)) {
		result.exit_code = WEXITSTATUS(wait_status);
	}
	return result;
}

}  // namespace

/** @brief Prove analyzer JSON is byte-exact and incomplete delivery is failure. */
TEST(validation_tap_analyzer, result_delivery_is_complete_or_nonzero)
{
	empty_pcap pcap;
	ASSERT_TRUE(pcap.valid());
	const auto captured = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE);
	ASSERT_EQ(captured.exit_code, 0) << captured.output;
	EXPECT_EQ(captured.output,
		  "{\"total_rx\":0,\"valid\":0,\"invalid\":0,\"duplicates\":0,\"out_of_order\":0,"
		  "\"transition_seq\":-1,\"tag_transition_count\":0,\"max_gap\":0,\"loss_pct\":0.0000,"
		  "\"missing_count\":0,\"latency\":{\"avg\":0.00,\"min\":0.00,\"max\":0.00,\"p50\":0.00,"
		  "\"p99\":0.00,\"count\":0},\"tag_counts\":{}}\n");

	const auto unreported = run_analyzer(pcap.path(), analyzer_output_destination::FULL);
	EXPECT_EQ(unreported.exit_code, 1) << unreported.output;
}

}  // namespace kinetum::validation
