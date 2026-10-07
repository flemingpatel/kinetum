// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file process_image.hpp
 * @brief Exact Linux process-image provenance and sibling resolution.
 * @author Fleming Patel
 *
 * Production process launch must not infer executable identity from argv[0],
 * PATH, or the current working directory. This component resolves the running
 * Linux image through /proc/self/exe and admits only canonical, absolute,
 * executable regular files. Supervisors use the admitted image directory to
 * resolve fixed sibling roles before creating any child process.
 *
 * These are cold-path filesystem operations. They are thread-safe, allocate,
 * and must never be called from a packet-processing path.
 */

#include <filesystem>
#include <string_view>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Validate one exact process-image path without normalizing it.
 *
 * The path must already be absolute, lexically normalized, canonical,
 * symlink-free, a regular file, and executable by the current process. The
 * function never searches PATH and never substitutes another location.
 *
 * @param path Exact process-image path to validate.
 * @param role Stable role name used in diagnostics.
 * @return OK when the path is exact and executable; INVALID_ARGUMENT for an
 *         empty, relative, or non-normalized representation; NOT_FOUND when it
 *         does not exist; FAILED_PRECONDITION for a symlinked or non-regular
 *         representation; PERMISSION_DENIED when it is not executable; or an
 *         explicit filesystem failure.
 */
[[nodiscard]] status validate_exact_process_image(const std::filesystem::path &path, std::string_view role);

/**
 * @brief Resolve the canonical absolute path of the running Linux image.
 *
 * Resolution uses /proc/self/exe as the sole authority. argv[0], PATH, the
 * current working directory, environment variables, and install-prefix
 * defaults are intentionally not consulted.
 *
 * @return Canonical absolute executable path, or an explicit fail-closed
 *         status when the kernel image link cannot be resolved or admitted.
 */
[[nodiscard]] status_or<std::filesystem::path> current_process_image();

/**
 * @brief Resolve one exact executable sibling of an admitted process image.
 *
 * @param process_image Canonical absolute path returned by
 *        current_process_image() or admitted by validate_exact_process_image().
 * @param sibling_name Single ASCII filename component for the required
 *        sibling, using only alphanumeric, dot, underscore, and hyphen bytes.
 * @return Canonical sibling path, or INVALID_ARGUMENT for an unsafe filename
 *         or non-exact parent image and an explicit admission error when the
 *         sibling is missing, symlinked, non-regular, or non-executable.
 */
[[nodiscard]] status_or<std::filesystem::path> resolve_sibling_process_image(const std::filesystem::path &process_image,
									     std::string_view sibling_name);

}  // namespace kinetum::common
