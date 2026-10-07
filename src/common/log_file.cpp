// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file log_file.cpp
 * @brief Checked append, non-overwriting rotation, and explicit log reopen.
 * @author Fleming Patel
 */

#include "src/common/log_file.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <utility>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace kinetum::common
{
namespace
{

/**
 * @param metadata Held descriptor or no-follow leaf metadata.
 * @return True for a regular, single-linked, protected current-UID inode.
 */
[[nodiscard]] bool owned_file(const struct stat &metadata) noexcept
{
	return S_ISREG(metadata.st_mode) && metadata.st_uid == ::geteuid() && metadata.st_nlink == 1 &&
	       (metadata.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID | S_ISVTX)) == 0;
}

/**
 * @brief Write every byte or return the first failure; partial bytes remain intact.
 * @param descriptor Sole writer's held append descriptor.
 * @param bytes Complete borrowed encoded record.
 * @return Complete delivery or the first failing write.
 */
[[nodiscard]] log_io_result write_complete(int descriptor, std::string_view bytes) noexcept
{
	while (!bytes.empty()) {
		const ssize_t written = ::write(descriptor, bytes.data(), bytes.size());
		if (written < 0 && errno == EINTR) {
			continue;
		}
		if (written <= 0) {
			return {written < 0 ? errno : EIO, "append"};
		}
		bytes.remove_prefix(static_cast<std::size_t>(written));
	}
	return {};
}

/**
 * @brief Close once; Linux releases descriptor ownership even when close reports EINTR.
 * @param descriptor Consumed descriptor, replaced with -1 before close.
 * @return First close failure or success, with no retained descriptor ownership.
 */
[[nodiscard]] log_io_result close_descriptor(int &descriptor) noexcept
{
	const int owned = std::exchange(descriptor, -1);
	return owned >= 0 && ::close(owned) != 0 ? log_io_result{errno, "close"} : log_io_result{};
}

}  // namespace

log_file::~log_file()
{
	(void)close();
}

status log_file::open(const log_options &options, std::string_view application)
{
	if (directory_ >= 0 || lock_ >= 0 || active_ >= 0) {
		return status::failed_precondition(static_status_text("log destination already owns descriptors"));
	}
	auto validated = validate_log_options(options);
	if (!validated.is_ok()) {
		return validated;
	}
	if (application != "kinetum_photon" && application != "kinetum_cp" && application != "kinetum_dp") {
		return status::invalid_argument(static_status_text("unknown service log role"));
	}
	maximum_bytes_ = options.maximum_bytes;
	keep_files_ = options.keep_files;
	for (uint32_t index = 0; index < names_.size(); ++index) {
		const auto name = std::string(application) + ".log" + (index == 0 ? "" : "." + std::to_string(index));
		if (!copy_log_field(names_[index], name)) {
			std::terminate();
		}
	}

	// Allocate the path representation before taking descriptor ownership.
	const std::filesystem::path path(options.directory);
	std::vector<std::string> components;
	for (const auto &part : path.relative_path()) {
		components.push_back(part.string());
	}
	directory_ = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	log_io_result failure{directory_ < 0 ? errno : 0, "open directory root"};
	for (std::size_t index = 0; failure.is_ok() && index < components.size(); ++index) {
		const auto &component = components[index];
		int next = ::openat(directory_, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (next < 0 && errno == ENOENT && index + 1 == components.size()) {
			if (::mkdirat(directory_, component.c_str(), 0750) != 0 && errno != EEXIST) {
				failure = {errno, "create log directory"};
				break;
			}
			next = ::openat(directory_, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		}
		if (next < 0) {
			failure = {errno, "open log directory component"};
			break;
		}
		failure = close_descriptor(directory_);
		directory_ = next;
	}
	struct stat metadata{};
	if (failure.is_ok() && ::fstat(directory_, &metadata) != 0) {
		failure = {errno, "inspect log directory"};
	}
	if (failure.is_ok() && (metadata.st_uid != ::geteuid() || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0)) {
		failure = {EPERM, "admit log directory ownership and permissions"};
	}
	std::array<char, 64> lock_name{};
	const int lock_name_size = std::snprintf(lock_name.data(), lock_name.size(), "%s.lock", names_[0].data());
	if (lock_name_size < 0 || static_cast<std::size_t>(lock_name_size) >= lock_name.size()) {
		std::terminate();
	}
	if (failure.is_ok()) {
		lock_ = ::openat(directory_, lock_name.data(), O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
				 0600);
		if (lock_ < 0) {
			failure = {errno, "open log ownership lock"};
		} else if (::fstat(lock_, &metadata) != 0) {
			failure = {errno, "inspect log ownership lock"};
		} else if (!owned_file(metadata)) {
			failure = {EPERM, "admit log ownership lock"};
		} else if (::flock(lock_, LOCK_EX | LOCK_NB) != 0) {
			failure = {errno, "acquire exclusive log ownership"};
		}
	}
	if (failure.is_ok()) {
		failure = reopen();
	}
	if (!failure.is_ok()) {
		(void)close();
		return status::unavailable(std::string("logging ") + failure.operation + ": " +
					   std::strerror(failure.error));
	}
	return status::ok();
}

log_io_result log_file::check_leaf_(uint32_t index, bool absence_allowed) const noexcept
{
	struct stat metadata{};
	if (::fstatat(directory_, names_[index].data(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
		return absence_allowed && errno == ENOENT ? log_io_result{} : log_io_result{errno, "inspect log file"};
	}
	if (!owned_file(metadata) || metadata.st_size < 0) {
		return {EPERM, "admit log file ownership and type"};
	}
	return static_cast<uint64_t>(metadata.st_size) <= maximum_bytes_ ?
		       log_io_result{} :
		       log_io_result{EFBIG, "existing log file exceeds configured size limit"};
}

log_io_result log_file::check_family_() const noexcept
{
	for (uint32_t index = 0; index < names_.size(); ++index) {
		const auto result = check_leaf_(index, true);
		if (!result.is_ok()) {
			return result;
		}
		if (index > keep_files_) {
			struct stat metadata{};
			if (::fstatat(directory_, names_[index].data(), &metadata, AT_SYMLINK_NOFOLLOW) == 0) {
				return {E2BIG, "existing log archives exceed configured retention"};
			}
		}
	}
	return {};
}

log_io_result log_file::open_active_() noexcept
{
	active_ = ::openat(directory_, names_[0].data(),
			   O_RDWR | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0640);
	if (active_ < 0) {
		return {errno, "open active log"};
	}
	struct stat metadata{};
	if (::fstat(active_, &metadata) != 0) {
		return {errno, "inspect active log"};
	}
	if (!owned_file(metadata) || metadata.st_size < 0) {
		return {EPERM, "admit active log"};
	}
	size_ = static_cast<uint64_t>(metadata.st_size);
	if (size_ > maximum_bytes_) {
		return {EFBIG, "existing active log exceeds configured size limit"};
	}
	if (size_ != 0) {
		char last = '\0';
		ssize_t read;
		do {
			read = ::pread(active_, &last, 1, metadata.st_size - 1);
		} while (read < 0 && errno == EINTR);
		if (read != 1) {
			return {read < 0 ? errno : EIO, "inspect incomplete log tail"};
		}
		if (last != '\n' && size_ < maximum_bytes_) {
			// Keep the interrupted bytes; start the following record on a new line.
			const auto separated = write_complete(active_, "\n");
			if (!separated.is_ok()) {
				return separated;
			}
			++size_;
		}
	}
	return {};
}

log_io_result log_file::finish_rotation_() noexcept
{
	const auto checked = check_leaf_(keep_files_, true);
	if (!checked.is_ok()) {
		return checked;
	}
	if (::unlinkat(directory_, names_[keep_files_].data(), 0) != 0 && errno != ENOENT) {
		return {errno, "retire oldest log archive"};
	}
	return {};
}

log_io_result log_file::rotate_() noexcept
{
	const auto checked = check_family_();
	if (!checked.is_ok()) {
		return checked;
	}
	uint32_t hole = 1;
	for (; hole <= keep_files_; ++hole) {
		struct stat metadata{};
		if (::fstatat(directory_, names_[hole].data(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
			if (errno != ENOENT) {
				return {errno, "locate log rotation slot"};
			}
			break;
		}
	}
	if (hole > keep_files_) {
		return {EEXIST, "log rotation has no unoccupied slot"};
	}
	while (hole != 0) {
		if (::syscall(SYS_renameat2, directory_, names_[hole - 1].data(), directory_, names_[hole].data(),
			      RENAME_NOREPLACE) != 0) {
			return {errno, "rotate log without replacement"};
		}
		--hole;
	}
	const auto closed = close_descriptor(active_);
	if (!closed.is_ok()) {
		return closed;
	}
	const auto opened = open_active_();
	if (!opened.is_ok()) {
		return opened;
	}
	return finish_rotation_();
}

log_io_result log_file::append(std::string_view record) noexcept
{
	if (active_ < 0 || record.empty() || record.back() != '\n' || record.size() > maximum_bytes_) {
		return {EINVAL, "append complete log record"};
	}
	if (size_ > maximum_bytes_ - record.size()) {
		const auto rotated = rotate_();
		if (!rotated.is_ok()) {
			return rotated;
		}
	}
	const auto result = write_complete(active_, record);
	if (result.is_ok()) {
		size_ += record.size();
	}
	return result;
}

log_io_result log_file::reopen() noexcept
{
	if (directory_ < 0 || lock_ < 0) {
		return {EBADF, "reopen unowned log destination"};
	}
	struct stat metadata{};
	if (::fstat(directory_, &metadata) != 0) {
		return {errno, "reinspect log directory"};
	}
	if (metadata.st_uid != ::geteuid() || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		return {EPERM, "readmit log directory"};
	}
	const auto family = check_family_();
	if (!family.is_ok()) {
		return family;
	}
	const auto closed = close_descriptor(active_);
	if (!closed.is_ok()) {
		return closed;
	}
	const auto opened = open_active_();
	if (!opened.is_ok()) {
		return opened;
	}
	if (::fstatat(directory_, names_[keep_files_].data(), &metadata, AT_SYMLINK_NOFOLLOW) == 0) {
		for (uint32_t index = 1; index < keep_files_; ++index) {
			if (::fstatat(directory_, names_[index].data(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
				return errno == ENOENT ? rotate_() : log_io_result{errno, "resume log rotation"};
			}
		}
		return finish_rotation_();
	}
	return errno == ENOENT ? log_io_result{} : log_io_result{errno, "inspect parked log archive"};
}

log_io_result log_file::close() noexcept
{
	auto result = close_descriptor(active_);
	const auto lock_result = close_descriptor(lock_);
	const auto directory_result = close_descriptor(directory_);
	if (result.is_ok()) {
		result = lock_result;
	}
	return result.is_ok() ? directory_result : result;
}

}  // namespace kinetum::common
