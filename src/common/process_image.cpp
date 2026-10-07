// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file process_image.cpp
 * @brief Exact Linux process-image provenance implementation.
 * @author Fleming Patel
 */

#include "src/common/process_image.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

#include "src/common/path_admission.hpp"

namespace kinetum::common
{
namespace
{

namespace fs = std::filesystem;

/** @brief Kernel-owned link identifying the running Linux process image. */
constexpr std::string_view PROCESS_IMAGE_LINK = "/proc/self/exe";

/**
 * @brief Build one role-qualified diagnostic subject.
 *
 * @param role Optional stable process role.
 * @return Human-readable process-image subject.
 */
std::string image_subject(std::string_view role)
{
	if (role.empty()) {
		return "process image";
	}
	return std::string(role) + " process image";
}

/**
 * @brief Validate the byte grammar for one fixed process sibling role.
 *
 * @param name Candidate single-component executable filename.
 * @return True only for nonempty ASCII alphanumeric, dot, underscore, and
 *         hyphen bytes excluding the reserved dot components.
 */
bool is_safe_sibling_name(std::string_view name)
{
	if (name.empty() || name == "." || name == "..") {
		return false;
	}
	for (const char raw : name) {
		const auto byte = static_cast<unsigned char>(raw);
		const bool alphanumeric = (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
					  (byte >= '0' && byte <= '9');
		if (!alphanumeric && byte != '.' && byte != '_' && byte != '-') {
			return false;
		}
	}
	return true;
}

/**
 * @brief Map a filesystem error to the platform status taxonomy.
 *
 * @param ec Filesystem error code.
 * @param message Stable failure message.
 * @param path Path that failed admission.
 * @return Detailed non-OK status.
 */
status filesystem_error_status(const std::error_code &ec, std::string message, const fs::path &path)
{
	status_code code = status_code::INTERNAL_ERROR;
	if (ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory) {
		code = status_code::NOT_FOUND;
	} else if (ec == std::errc::permission_denied || ec == std::errc::operation_not_permitted) {
		code = status_code::PERMISSION_DENIED;
	}
	return status(code, std::move(message), path.string() + ": " + ec.message());
}

}  // namespace

status validate_exact_process_image(const std::filesystem::path &path, std::string_view role)
{
	const std::string subject = image_subject(role);
	auto exact_status = validate_exact_regular_file(path, subject);
	if (!exact_status.is_ok()) {
		return exact_status;
	}
	// execve()/posix_spawn() authorize with effective credentials. Match that
	// kernel decision here instead of access(), whose real-ID semantics can
	// disagree for a supervised process running under changed credentials.
	if (::faccessat(AT_FDCWD, path.c_str(), X_OK, AT_EACCESS) != 0) {
		const int err = errno;
		status_code code = status_code::INTERNAL_ERROR;
		std::string message = "failed to verify " + subject + " executable permission";
		if (err == EACCES || err == EPERM) {
			code = status_code::PERMISSION_DENIED;
			message = subject + " is not executable";
		} else if (err == ENOENT || err == ENOTDIR) {
			code = status_code::NOT_FOUND;
			message = subject + " disappeared during executable admission";
		}
		return status(code, std::move(message), path.string() + ": " + std::strerror(err));
	}
	return status::ok();
}

status_or<fs::path> current_process_image()
{
	std::error_code ec;
	const fs::path image = fs::canonical(fs::path(std::string(PROCESS_IMAGE_LINK)), ec);
	if (ec) {
		return filesystem_error_status(ec, "failed to resolve running process image",
					       fs::path(std::string(PROCESS_IMAGE_LINK)));
	}

	const auto validation = validate_exact_process_image(image, "running");
	if (!validation.is_ok()) {
		return validation;
	}
	return image;
}

status_or<std::filesystem::path> resolve_sibling_process_image(const std::filesystem::path &process_image,
							       std::string_view sibling_name)
{
	const auto parent_validation = validate_exact_process_image(process_image, "parent");
	if (!parent_validation.is_ok()) {
		return parent_validation;
	}

	if (!is_safe_sibling_name(sibling_name)) {
		return status::invalid_argument("sibling process-image name must be one safe ASCII filename component");
	}
	const fs::path name(sibling_name);
	if (name.has_parent_path() || name.filename() != name) {
		return status::invalid_argument("sibling process-image name must be one safe ASCII filename component");
	}

	const fs::path sibling = (process_image.parent_path() / name).lexically_normal();
	const auto sibling_validation = validate_exact_process_image(sibling, sibling_name);
	if (!sibling_validation.is_ok()) {
		return sibling_validation;
	}
	return sibling;
}

}  // namespace kinetum::common
