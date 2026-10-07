// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file path_admission.hpp
 * @brief Exact and canonical admission for cold-path filesystem authority.
 * @author Fleming Patel
 *
 * Exact cross-component authority must already be absolute, normalized,
 * canonical, and symlink-free. Caller-supplied source paths are a distinct
 * authority class: an explicit relative path may be resolved once at
 * admission, but the admitted result is always canonical and absolute.
 * Resolution failure is terminal; callers must not retain the unresolved
 * representation as a fallback.
 *
 * These helpers perform filesystem I/O, allocate, and may consult the current
 * working directory for an explicitly relative input. They are cold-path only
 * and must never execute on a packet-processing path.
 *
 * @par Thread Safety
 * Calls with absolute inputs share no mutable library state. Relative-path
 * admission requires the process working directory to remain stable for the
 * duration of the call; production hosts must not call `chdir()` concurrently.
 */

#include <filesystem>
#include <string_view>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Validate one exact canonical regular-file identity.
 *
 * The input must already be absolute and lexically normalized. Symbolic-link
 * path components are rejected rather than resolved, and the target must be a
 * regular file. The function never repairs or substitutes the supplied path.
 *
 * @param input Exact filesystem identity to validate.
 * @param role Stable file role used in diagnostics.
 * @return OK for an exact regular file; INVALID_ARGUMENT for an empty,
 *         relative, or non-normalized path; NOT_FOUND for an absent path;
 *         PERMISSION_DENIED for denied traversal; FAILED_PRECONDITION for a
 *         symbolic-link representation or non-regular target; or an explicit
 *         filesystem failure.
 */
[[nodiscard]] status validate_exact_regular_file(const std::filesystem::path &input, std::string_view role);

/**
 * @brief Validate one exact canonical directory identity.
 *
 * Exact-path and symbolic-link semantics match
 * `validate_exact_regular_file()`, but the target must be a directory.
 *
 * @param input Exact filesystem identity to validate.
 * @param role Stable directory role used in diagnostics.
 * @return OK for an exact directory, with the same path errors as
 *         `validate_exact_regular_file()` or FAILED_PRECONDITION for a
 *         non-directory target.
 */
[[nodiscard]] status validate_exact_directory(const std::filesystem::path &input, std::string_view role);

/**
 * @brief Resolve one explicit artifact path to a canonical regular file.
 *
 * A relative input is interpreted exactly once against the caller's current
 * working directory by `std::filesystem::canonical()`. Symbolic links are
 * resolved into the returned canonical identity. This function is not suitable
 * for process-image admission or bundle-tree integrity, whose contracts reject
 * symbolic-link representations entirely.
 *
 * @param input Explicit operator- or artifact-supplied path.
 * @param role Stable artifact role used in diagnostics.
 * @return Canonical absolute regular-file path; INVALID_ARGUMENT for an empty
 *         input, NOT_FOUND for an absent path, PERMISSION_DENIED for denied
 *         traversal, FAILED_PRECONDITION for a non-regular target, or an
 *         explicit filesystem failure.
 */
[[nodiscard]] status_or<std::filesystem::path> admit_explicit_regular_file(const std::filesystem::path &input,
									   std::string_view role);

/**
 * @brief Resolve one explicit artifact path to a canonical directory.
 *
 * Relative-input and symbolic-link semantics match
 * `admit_explicit_regular_file()`, but the resolved target must be a directory.
 *
 * @param input Explicit operator- or artifact-supplied path.
 * @param role Stable directory role used in diagnostics.
 * @return Canonical absolute directory path, with the same path-resolution
 *         errors as `admit_explicit_regular_file()` or FAILED_PRECONDITION for
 *         a non-directory target.
 */
[[nodiscard]] status_or<std::filesystem::path> admit_explicit_directory(const std::filesystem::path &input,
									std::string_view role);

}  // namespace kinetum::common
