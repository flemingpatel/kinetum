// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file process_output.hpp
 * @brief Complete process-result delivery through POSIX descriptors.
 * @author Fleming Patel
 *
 * This private cold-path primitive gives finite command-line tools one output
 * delivery authority. Callers compose complete stdout and stderr byte strings
 * before entry. The emitter handles interrupted and partial writes and permits
 * the caller's completion exit code only after both streams are accepted.
 *
 * It performs no allocation, formatting, logging, buffering, or exception-
 * throwing operation. It is not an installed SDK or a process-logging API.
 *
 * @par Thread Safety
 * A process must serialize calls that target the same descriptors. The helper
 * owns no shared state.
 */

#include <cerrno>
#include <cstddef>
#include <limits>
#include <string_view>

#include <sys/types.h>
#include <unistd.h>

namespace kinetum::common
{

/** Complete borrowed output and exit intent for one finite process result. */
struct process_output_view {
	std::string_view standard_output;  ///< Complete bytes for STDOUT_FILENO.
	std::string_view standard_error;   ///< Complete bytes for STDERR_FILENO.
	int complete_exit_code;		   ///< Result after complete delivery.
};

namespace detail
{

/**
 * @brief Deliver one complete byte sequence to an exact descriptor.
 *
 * @param descriptor Exact process output descriptor.
 * @param bytes Complete borrowed bytes to deliver in order.
 * @return True only after every byte is accepted.
 */
[[nodiscard]] inline bool write_process_output(int descriptor, std::string_view bytes) noexcept
{
	constexpr auto MAX_WRITE_BYTES = static_cast<std::size_t>(std::numeric_limits<ssize_t>::max());
	while (!bytes.empty()) {
		const std::size_t requested = bytes.size() < MAX_WRITE_BYTES ? bytes.size() : MAX_WRITE_BYTES;
		const ssize_t written = ::write(descriptor, bytes.data(), requested);
		if (written > 0) {
			bytes.remove_prefix(static_cast<std::size_t>(written));
			continue;
		}
		if (written < 0 && errno == EINTR) {
			continue;
		}
		return false;
	}
	return true;
}

}  // namespace detail

/**
 * @brief Emit one complete finite-process result exactly once.
 *
 * Direct descriptor writes bypass userspace stream buffering. Stdout is
 * delivered before stderr. A write failure reported to this helper does not
 * suppress the attempt on the other descriptor; process-level signal policy
 * remains the caller's responsibility.
 *
 * @param output Complete borrowed bytes and semantic exit outcome.
 * @return `output.complete_exit_code` after complete delivery, otherwise one.
 */
[[nodiscard]] inline int emit_process_output(process_output_view output) noexcept
{
	const bool stdout_complete = detail::write_process_output(STDOUT_FILENO, output.standard_output);
	const bool stderr_complete = detail::write_process_output(STDERR_FILENO, output.standard_error);
	return stdout_complete && stderr_complete ? output.complete_exit_code : 1;
}

}  // namespace kinetum::common
