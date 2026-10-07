// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file path_admission.cpp
 * @brief Exact and canonical filesystem-authority admission implementation.
 * @author Fleming Patel
 */

#include "src/common/path_admission.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>

#include "src/common/status.hpp"

namespace kinetum::common
{
namespace
{

namespace fs = std::filesystem;

/** @brief Filesystem object kind required by exact-path admission. */
enum class exact_path_kind : uint8_t {
	REGULAR_FILE = 0,
	DIRECTORY = 1,
};

/**
 * @brief Map one filesystem failure into the platform status taxonomy.
 *
 * @param error Filesystem error code.
 * @param operation Stable failed operation.
 * @param input Path involved in the failure.
 * @return Detailed non-OK status.
 */
status path_filesystem_error(const std::error_code &error, std::string operation, const fs::path &input)
{
	status_code code = status_code::INTERNAL_ERROR;
	if (error == std::errc::no_such_file_or_directory || error == std::errc::not_a_directory) {
		code = status_code::NOT_FOUND;
	} else if (error == std::errc::permission_denied || error == std::errc::operation_not_permitted) {
		code = status_code::PERMISSION_DENIED;
	}
	return status(code, std::move(operation), input.string() + ": " + error.message());
}

/**
 * @brief Validate one exact path against its required filesystem kind.
 *
 * @param input Exact path representation to inspect.
 * @param role Stable role used in diagnostics.
 * @param required_kind Required regular-file or directory kind.
 * @return OK for exact identity, or the first syntax, filesystem, symlink, or
 *         object-kind failure.
 */
status validate_exact_path(const fs::path &input, std::string_view role, exact_path_kind required_kind)
{
	const std::string subject(role);
	if (input.empty()) {
		return status::invalid_argument(subject + " path cannot be empty");
	}
	if (!input.is_absolute()) {
		return status::invalid_argument(subject + " path must be absolute");
	}
	if (input != input.lexically_normal()) {
		return status::invalid_argument(subject + " path must be lexically normalized");
	}

	std::error_code ec;
	const fs::file_status link_status = fs::symlink_status(input, ec);
	if (ec) {
		return path_filesystem_error(ec, "failed to inspect " + subject, input);
	}
	if (!fs::exists(link_status)) {
		return status(status_code::NOT_FOUND, subject + " does not exist", input.string());
	}
	if (fs::is_symlink(link_status)) {
		return status::failed_precondition(subject + " path must be symlink-free");
	}

	const fs::path canonical = fs::canonical(input, ec);
	if (ec) {
		return path_filesystem_error(ec, "failed to canonicalize " + subject, input);
	}
	if (canonical != input) {
		return status::failed_precondition(subject + " path must have no symbolic-link components");
	}

	const bool kind_matches = required_kind == exact_path_kind::REGULAR_FILE ? fs::is_regular_file(link_status) :
										   fs::is_directory(link_status);
	if (!kind_matches) {
		return status::failed_precondition(subject + (required_kind == exact_path_kind::REGULAR_FILE ?
								      " must identify a regular file" :
								      " must identify a directory"));
	}
	return status::ok();
}

/**
 * @brief Resolve one nonempty explicit path to canonical identity.
 *
 * @param input Explicit path to resolve.
 * @param role Stable role used in diagnostics.
 * @return Canonical absolute path or an explicit resolution failure.
 */
status_or<fs::path> canonical_explicit_path(const fs::path &input, std::string_view role)
{
	if (input.empty()) {
		return status::invalid_argument(std::string(role) + " path cannot be empty");
	}

	std::error_code ec;
	const fs::path canonical = fs::canonical(input, ec);
	if (ec) {
		return path_filesystem_error(ec, "failed to resolve " + std::string(role), input);
	}
	return canonical;
}

}  // namespace

status validate_exact_regular_file(const std::filesystem::path &input, std::string_view role)
{
	return validate_exact_path(input, role, exact_path_kind::REGULAR_FILE);
}

status validate_exact_directory(const std::filesystem::path &input, std::string_view role)
{
	return validate_exact_path(input, role, exact_path_kind::DIRECTORY);
}

status_or<std::filesystem::path> admit_explicit_regular_file(const std::filesystem::path &input, std::string_view role)
{
	auto canonical_or = canonical_explicit_path(input, role);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	const fs::path canonical = std::move(canonical_or).value();

	std::error_code ec;
	const fs::file_status file_status = fs::status(canonical, ec);
	if (ec) {
		return path_filesystem_error(ec, "failed to inspect " + std::string(role), canonical);
	}
	if (!fs::is_regular_file(file_status)) {
		return status(status_code::FAILED_PRECONDITION, std::string(role) + " must identify a regular file",
			      canonical.string());
	}
	return canonical;
}

status_or<std::filesystem::path> admit_explicit_directory(const std::filesystem::path &input, std::string_view role)
{
	auto canonical_or = canonical_explicit_path(input, role);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	const fs::path canonical = std::move(canonical_or).value();

	std::error_code ec;
	const fs::file_status file_status = fs::status(canonical, ec);
	if (ec) {
		return path_filesystem_error(ec, "failed to inspect " + std::string(role), canonical);
	}
	if (!fs::is_directory(file_status)) {
		return status(status_code::FAILED_PRECONDITION, std::string(role) + " must identify a directory",
			      canonical.string());
	}
	return canonical;
}

}  // namespace kinetum::common
