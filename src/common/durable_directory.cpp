// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file durable_directory.cpp
 * @brief Descriptor-rooted durable file publication implementation.
 * @author Fleming Patel
 */

#include "src/common/durable_directory.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

namespace kinetum::common
{
namespace
{

/** @brief Reserved namespace for same-directory publication temporaries. */
constexpr std::string_view PRIVATE_TEMPORARY_PREFIX = ".kinetum.tmp.";

/** @brief Unique local descriptor owner used by one operation. */
class unique_fd {
    public:
	/**
	 * @brief Adopt one descriptor.
	 * @param descriptor Sole descriptor transferred to this guard, or -1 for an empty guard.
	 */
	explicit unique_fd(int descriptor = -1) noexcept
		: descriptor_(descriptor)
	{
	}

	/** @brief Close the descriptor. */
	~unique_fd()
	{
		if (descriptor_ >= 0) {
			(void)::close(descriptor_);
		}
	}

	/** @brief Disable descriptor aliasing. */
	unique_fd(const unique_fd &) = delete;

	/** @brief Disable descriptor aliasing by assignment. */
	unique_fd &operator=(const unique_fd &) = delete;

	/**
	 * @brief Transfer one descriptor.
	 * @param other Source guard, left empty after transfer.
	 */
	unique_fd(unique_fd &&other) noexcept
		: descriptor_(std::exchange(other.descriptor_, -1))
	{
	}

	/**
	 * @brief Close this guard's descriptor and transfer another; self-assignment preserves ownership.
	 * @param other Source guard, left empty after a distinct-owner transfer.
	 * @return This guard after transfer.
	 */
	unique_fd &operator=(unique_fd &&other) noexcept
	{
		if (this != &other) {
			if (descriptor_ >= 0) {
				(void)::close(descriptor_);
			}
			descriptor_ = std::exchange(other.descriptor_, -1);
		}
		return *this;
	}

	/** @return Borrowed descriptor, or -1 for an empty guard. */
	[[nodiscard]] int get() const noexcept
	{
		return descriptor_;
	}

	/** @return Descriptor transferred to the caller without closing; this guard becomes empty. */
	[[nodiscard]] int release() noexcept
	{
		return std::exchange(descriptor_, -1);
	}

    private:
	int descriptor_{-1};  ///< Unique descriptor.
};

/** @brief Directory-stream owner that closes its duplicated descriptor. */
class unique_directory_stream {
    public:
	/**
	 * @brief Adopt one directory stream and its descriptor.
	 * @param stream Sole stream transferred into this guard, or nullptr for an empty guard.
	 */
	explicit unique_directory_stream(DIR *stream = nullptr) noexcept
		: stream_(stream)
	{
	}

	/** @brief Close the directory stream and its descriptor. */
	~unique_directory_stream()
	{
		if (stream_ != nullptr) {
			(void)::closedir(stream_);
		}
	}

	/** @brief Disable stream aliasing. */
	unique_directory_stream(const unique_directory_stream &) = delete;

	/** @brief Disable stream aliasing by assignment. */
	unique_directory_stream &operator=(const unique_directory_stream &) = delete;

	/** @return Borrowed directory stream, or nullptr for an empty guard. */
	[[nodiscard]] DIR *get() const noexcept
	{
		return stream_;
	}

    private:
	DIR *stream_{nullptr};	///< Unique directory stream.
};

/**
 * @brief Remove one private temporary entry durably or fail stop.
 *
 * @param directory_descriptor Retained directory descriptor.
 * @param temporary_name Exact private leaf.
 */
void discard_temporary_file_or_terminate(int directory_descriptor, const std::string &temporary_name) noexcept;

/** @brief Exact exception guard for one private directory entry. */
class temporary_entry_guard {
    public:
	/**
	 * @brief Track one already-created private entry.
	 *
	 * @param directory_descriptor Retained directory descriptor.
	 * @param name Stable leaf storage that outlives this guard.
	 */
	temporary_entry_guard(int directory_descriptor, const std::string &name) noexcept
		: directory_descriptor_(directory_descriptor)
		, name_(&name)
	{
	}

	/** @brief Remove the entry durably if an exceptional path skipped cleanup. */
	~temporary_entry_guard()
	{
		if (name_ != nullptr) {
			discard_temporary_file_or_terminate(directory_descriptor_, *name_);
		}
	}

	/** @brief Disable guard aliasing. */
	temporary_entry_guard(const temporary_entry_guard &) = delete;

	/** @brief Disable guard aliasing by assignment. */
	temporary_entry_guard &operator=(const temporary_entry_guard &) = delete;

	/** @brief Mark the private entry as already removed or published. */
	void release() noexcept
	{
		name_ = nullptr;
	}

    private:
	int directory_descriptor_{-1};	    ///< Borrowed retained directory descriptor.
	const std::string *name_{nullptr};  ///< Borrowed stable private leaf.
};

/**
 * @brief Map a captured errno into the platform status taxonomy.
 *
 * @param error Captured errno.
 * @param action Stable failed operation.
 * @param subject Exact diagnostic subject.
 * @return Detailed non-OK status.
 */
status descriptor_error(int error, std::string action, std::string subject)
{
	status_code code = status_code::INTERNAL_ERROR;
	if (error == ENOENT) {
		code = status_code::NOT_FOUND;
	} else if (error == EEXIST) {
		code = status_code::ALREADY_EXISTS;
	} else if (error == EACCES || error == EPERM) {
		code = status_code::PERMISSION_DENIED;
	} else if (error == ENOTDIR || error == ELOOP) {
		code = status_code::FAILED_PRECONDITION;
	} else if (error == ENOSPC || error == EDQUOT || error == EFBIG) {
		code = status_code::RESOURCE_EXHAUSTED;
	}
	return status(code, std::move(action), std::move(subject) + ": " + std::strerror(error));
}

/**
 * @brief Return whether one token is the canonical spelling of a positive uint64.
 *
 * @param token Candidate decimal token.
 * @param maximum Inclusive upper bound of the generating native type.
 * @return true only for an in-range nonzero value without leading zeroes.
 */
bool is_canonical_positive_decimal(std::string_view token, uint64_t maximum) noexcept
{
	if (token.empty() || token.front() == '0') {
		return false;
	}
	uint64_t value = 0;
	const char *const begin = &token.front();
	const char *const end = begin + token.size();
	const auto result = std::from_chars(begin, end, value);
	return result.ec == std::errc{} && result.ptr == end && value != 0u && value <= maximum;
}

/**
 * @brief Identify one exact private publication-temporary leaf.
 *
 * @param leaf Candidate directory entry.
 * @return true only for `.kinetum.tmp.<positive-pid>.<positive-sequence>`.
 */
bool is_private_temporary_leaf(std::string_view leaf) noexcept
{
	if (!leaf.starts_with(PRIVATE_TEMPORARY_PREFIX)) {
		return false;
	}
	leaf.remove_prefix(PRIVATE_TEMPORARY_PREFIX.size());
	const std::string_view suffix = leaf;
	const std::size_t separator = suffix.find('.');
	if (separator == std::string_view::npos || suffix.find('.', separator + 1u) != std::string_view::npos) {
		return false;
	}
	std::string_view process_id = suffix;
	process_id.remove_suffix(suffix.size() - separator);
	std::string_view sequence = suffix;
	sequence.remove_prefix(separator + 1u);
	return is_canonical_positive_decimal(process_id, static_cast<uint64_t>(std::numeric_limits<pid_t>::max())) &&
	       is_canonical_positive_decimal(sequence, std::numeric_limits<uint64_t>::max());
}

/**
 * @brief Validate an externally supplied file leaf.
 *
 * @param leaf Candidate single path component.
 * @return OK only for a nonempty printable ASCII storage leaf without path
 *         separators or traversal spelling.
 */
status validate_leaf(std::string_view leaf)
{
	if (leaf.empty() || leaf == "." || leaf == ".." || leaf.find("..") != std::string_view::npos) {
		return status::invalid_argument("durable file name must be one exact non-traversing component");
	}
	if (leaf.starts_with(PRIVATE_TEMPORARY_PREFIX)) {
		return status::invalid_argument("durable file name uses the reserved private-publication namespace");
	}
	for (const char character : leaf) {
		const auto value = static_cast<unsigned char>(character);
		const bool allowed =
			(value >= static_cast<unsigned char>('a') && value <= static_cast<unsigned char>('z')) ||
			(value >= static_cast<unsigned char>('A') && value <= static_cast<unsigned char>('Z')) ||
			(value >= static_cast<unsigned char>('0') && value <= static_cast<unsigned char>('9')) ||
			value == static_cast<unsigned char>('_') || value == static_cast<unsigned char>('-') ||
			value == static_cast<unsigned char>('.');
		if (!allowed) {
			return status::invalid_argument(
				"durable file name contains a character outside the storage grammar");
		}
	}
	return status::ok();
}

/**
 * @brief Validate one admitted terminal directory.
 *
 * @param descriptor Open terminal directory descriptor.
 * @return OK only for current-UID ownership without group/world write access.
 */
status validate_terminal_directory(int descriptor)
{
	struct stat metadata{};
	if (::fstat(descriptor, &metadata) != 0) {
		return descriptor_error(errno, "failed to inspect durable directory", "retained directory");
	}
	if (!S_ISDIR(metadata.st_mode)) {
		return status::failed_precondition("durable storage terminal is not a directory");
	}
	if (metadata.st_uid != ::geteuid()) {
		return status::permission_denied(
			"durable storage terminal is not owned by the current process authority");
	}
	if ((metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		return status::permission_denied("durable storage terminal has forbidden writable permission bits");
	}
	return status::ok();
}

/**
 * @brief Validate one owned durable file's exact metadata contract.
 *
 * @param metadata Metadata sampled through the opened descriptor.
 * @return OK only for a regular, current-UID, single-linked mode-0600 file.
 */
status validate_owned_file_metadata(const struct stat &metadata)
{
	if (!S_ISREG(metadata.st_mode)) {
		return status::failed_precondition("durable store entry is not a regular file");
	}
	if (metadata.st_uid != ::geteuid()) {
		return status::permission_denied("durable store file is not owned by the current process authority");
	}
	if (metadata.st_nlink != 1) {
		return status::failed_precondition("durable store file must have exactly one filesystem link");
	}
	if ((metadata.st_mode & static_cast<mode_t>(07777)) != static_cast<mode_t>(0600)) {
		return status::permission_denied("durable store file must have exact mode 0600");
	}
	return status::ok();
}

/**
 * @brief Compare metadata that must remain stable during a descriptor read.
 *
 * @param before Metadata before the read.
 * @param after Metadata after the read.
 * @return true only when identity, mode, owner, links, size, and timestamps
 *         remain exact.
 */
bool stable_file_metadata(const struct stat &before, const struct stat &after) noexcept
{
	return before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
	       before.st_uid == after.st_uid && before.st_gid == after.st_gid && before.st_nlink == after.st_nlink &&
	       before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
	       before.st_mtim.tv_nsec == after.st_mtim.tv_nsec && before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
	       before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

/**
 * @brief Flush one descriptor, retrying interrupted calls.
 *
 * @param descriptor File or directory descriptor.
 * @param subject Stable diagnostic subject.
 * @return OK after successful fsync, otherwise a structured error.
 */
status fsync_descriptor(int descriptor, std::string subject)
{
	for (;;) {
		if (::fsync(descriptor) == 0) {
			return status::ok();
		}
		if (errno != EINTR) {
			return descriptor_error(errno, "failed to make durable storage state persistent",
						std::move(subject));
		}
	}
}

/**
 * @brief Make an irreversible namespace mutation durable or fail stop.
 *
 * Once renameat, renameat2, or unlinkat succeeds, an ordinary error cannot
 * truthfully report whether the old or new authority owns the durable name.
 * Continuing would permit an in-memory/filesystem split, so the process is the
 * recovery boundary for a post-publication directory-sync failure.
 *
 * @param descriptor Retained directory descriptor whose namespace changed.
 */
void fsync_published_directory_or_terminate(int descriptor) noexcept
{
	for (;;) {
		if (::fsync(descriptor) == 0) {
			return;
		}
		if (errno != EINTR) {
			std::terminate();
		}
	}
}

/**
 * @brief Atomically rename one directory entry only when the target is absent.
 *
 * Linux renameat2 is the required no-clobber primitive. There is deliberately
 * no link/unlink fallback because that would expose a multiply linked target
 * and weaken the exact file contract.
 *
 * @param directory_descriptor Retained directory descriptor for both names.
 * @param source Private complete source leaf.
 * @param target Exact target leaf.
 * @return Zero on publication or -1 with errno set.
 */
int rename_without_replacement(int directory_descriptor, const char *source, const char *target) noexcept
{
#if defined(SYS_renameat2)
	return static_cast<int>(
		::syscall(SYS_renameat2, directory_descriptor, source, directory_descriptor, target, RENAME_NOREPLACE));
#else
	(void)directory_descriptor;
	(void)source;
	(void)target;
	errno = ENOSYS;
	return -1;
#endif
}

void discard_temporary_file_or_terminate(int directory_descriptor, const std::string &temporary_name) noexcept
{
	for (;;) {
		if (::unlinkat(directory_descriptor, temporary_name.c_str(), 0) == 0 || errno == ENOENT) {
			break;
		}
		if (errno != EINTR) {
			std::terminate();
		}
	}
	fsync_published_directory_or_terminate(directory_descriptor);
}

/**
 * @brief Write all bytes to one descriptor without relying on a shared offset.
 *
 * @param descriptor Open writable descriptor.
 * @param bytes Complete content.
 * @return OK only after the complete byte range is written.
 */
status write_all(int descriptor, std::string_view bytes)
{
	if (bytes.size() > static_cast<std::size_t>(std::numeric_limits<off_t>::max())) {
		return status::resource_exhausted("durable store file exceeds representable write offset");
	}
	constexpr std::size_t WRITE_CHUNK_BYTES = std::size_t{64} * 1024u;
	std::size_t offset = 0;
	while (offset < bytes.size()) {
		const std::size_t chunk_size = std::min(bytes.size() - offset, WRITE_CHUNK_BYTES);
		const ssize_t count =
			::pwrite(descriptor, bytes.data() + offset, chunk_size, static_cast<off_t>(offset));
		if (count < 0) {
			if (errno == EINTR) {
				continue;
			}
			return descriptor_error(errno, "failed to write durable store file", "retained directory");
		}
		if (count == 0) {
			return status::internal_error("durable store write made no progress");
		}
		offset += static_cast<std::size_t>(count);
	}
	return status::ok();
}

/**
 * @brief Open and validate one exact durable-store file.
 *
 * @param directory_descriptor Retained directory descriptor.
 * @param leaf Validated leaf name.
 * @return Unique read descriptor and its initial metadata.
 */
status_or<std::pair<unique_fd, struct stat>> open_owned_file(int directory_descriptor, std::string_view leaf)
{
	unique_fd file(::openat(directory_descriptor, std::string(leaf).c_str(),
				O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
	if (file.get() < 0) {
		return descriptor_error(errno, "failed to open durable store file", std::string(leaf));
	}
	struct stat metadata{};
	if (::fstat(file.get(), &metadata) != 0) {
		return descriptor_error(errno, "failed to inspect durable store file", std::string(leaf));
	}
	auto metadata_status = validate_owned_file_metadata(metadata);
	if (!metadata_status.is_ok()) {
		return metadata_status;
	}
	return std::pair<unique_fd, struct stat>{std::move(file), metadata};
}

/**
 * @brief Validate metadata possible for an interrupted private publication.
 *
 * The creating open requests mode 0600 and the immediate fchmod establishes
 * exact mode 0600. A process may stop between those operations, so an admitted
 * abandoned entry may carry any umask-reduced subset of the two owner bits.
 *
 * @param metadata Metadata sampled without following the entry.
 * @return OK only for a current-UID, regular, single-linked private inode.
 */
status validate_abandoned_temporary_metadata(const struct stat &metadata)
{
	if (!S_ISREG(metadata.st_mode)) {
		return status::failed_precondition("abandoned durable publication is not a regular file");
	}
	if (metadata.st_uid != ::geteuid()) {
		return status::permission_denied(
			"abandoned durable publication is not owned by the current process authority");
	}
	if (metadata.st_nlink != 1) {
		return status::failed_precondition(
			"abandoned durable publication must have exactly one filesystem link");
	}
	const uint32_t permissions = static_cast<uint32_t>(metadata.st_mode) & 07777u;
	if ((permissions & ~0600u) != 0u) {
		return status::permission_denied("abandoned durable publication has impossible permission bits");
	}
	return status::ok();
}

/**
 * @brief Durably discard exact private publications abandoned by process stop.
 *
 * @param directory_descriptor Retained admitted terminal directory.
 * @param path Exact path used only for diagnostics.
 * @return OK after every exact abandoned entry is absent and the namespace is
 *         durable, otherwise the first enumeration, metadata, or unlink error.
 */
status discard_abandoned_publications(int directory_descriptor, const std::filesystem::path &path)
{
	const int enumeration_descriptor =
		::openat(directory_descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (enumeration_descriptor < 0) {
		return descriptor_error(errno, "failed to open abandoned-publication recovery", path.string());
	}
	DIR *raw_stream = ::fdopendir(enumeration_descriptor);
	if (raw_stream == nullptr) {
		const int error = errno;
		(void)::close(enumeration_descriptor);
		return descriptor_error(error, "failed to enumerate abandoned durable publications", path.string());
	}
	unique_directory_stream stream(raw_stream);

	std::vector<std::string> abandoned_names;
	for (;;) {
		errno = 0;
		dirent *entry = ::readdir(stream.get());
		if (entry == nullptr) {
			if (errno != 0) {
				return descriptor_error(errno,
							"failed while enumerating abandoned durable publications",
							path.string());
			}
			break;
		}
		const std::string name(entry->d_name);
		if (!is_private_temporary_leaf(name)) {
			continue;
		}

		struct stat metadata{};
		if (::fstatat(directory_descriptor, name.c_str(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
			return descriptor_error(errno, "failed to inspect abandoned durable publication", name);
		}
		auto metadata_status = validate_abandoned_temporary_metadata(metadata);
		if (!metadata_status.is_ok()) {
			return metadata_status;
		}
		abandoned_names.push_back(name);
	}

	std::sort(abandoned_names.begin(), abandoned_names.end());
	bool namespace_changed = false;
	for (const auto &name : abandoned_names) {
		for (;;) {
			if (::unlinkat(directory_descriptor, name.c_str(), 0) == 0) {
				namespace_changed = true;
				break;
			}
			if (errno == EINTR) {
				continue;
			}
			const int error = errno;
			if (namespace_changed) {
				fsync_published_directory_or_terminate(directory_descriptor);
			}
			return descriptor_error(error, "failed to discard abandoned durable publication", name);
		}
	}
	if (namespace_changed) {
		fsync_published_directory_or_terminate(directory_descriptor);
	}
	return status::ok();
}

}  // namespace

durable_directory::durable_directory(int descriptor, std::filesystem::path path) noexcept
	: descriptor_(descriptor)
	, path_(std::move(path))
{
}

durable_directory::~durable_directory()
{
	if (descriptor_ >= 0) {
		(void)::close(descriptor_);
	}
}

durable_directory::durable_directory(durable_directory &&other) noexcept
	: descriptor_(std::exchange(other.descriptor_, -1))
	, path_(std::move(other.path_))
	, temporary_sequence_(std::exchange(other.temporary_sequence_, 0))
{
}

durable_directory &durable_directory::operator=(durable_directory &&other) noexcept
{
	if (this != &other) {
		if (descriptor_ >= 0) {
			(void)::close(descriptor_);
		}
		descriptor_ = std::exchange(other.descriptor_, -1);
		path_ = std::move(other.path_);
		temporary_sequence_ = std::exchange(other.temporary_sequence_, 0);
	}
	return *this;
}

status_or<durable_directory> durable_directory::open(const std::filesystem::path &path)
{
	try {
		if (path.empty() || path == path.root_path() || !path.is_absolute() ||
		    path != path.lexically_normal()) {
			return status::invalid_argument(
				"durable storage root must be exact, absolute, lexically normalized, and non-root");
		}

		std::vector<std::filesystem::path> components;
		for (const auto &component : path.relative_path()) {
			if (component.empty() || component == "." || component == ".." || component.has_parent_path()) {
				return status::invalid_argument(
					"durable storage root contains a noncanonical component");
			}
			components.push_back(component);
		}
		if (components.empty()) {
			return status::invalid_argument("durable storage root must name a terminal directory");
		}

		unique_fd current(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
		if (current.get() < 0) {
			return descriptor_error(errno, "failed to open filesystem root", path.string());
		}

		for (std::size_t index = 0; index + 1u < components.size(); ++index) {
			const int next = ::openat(current.get(), components[index].c_str(),
						  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
			if (next < 0) {
				return descriptor_error(errno, "failed symlink-free durable-directory traversal",
							path.string());
			}
			current = unique_fd(next);
		}

		const auto &terminal = components.back();
		bool created = false;
		int terminal_descriptor =
			::openat(current.get(), terminal.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (terminal_descriptor < 0 && errno == ENOENT) {
			if (::mkdirat(current.get(), terminal.c_str(), static_cast<mode_t>(0700)) != 0) {
				return descriptor_error(errno, "failed to create durable storage terminal",
							path.string());
			}
			created = true;
			terminal_descriptor = ::openat(current.get(), terminal.c_str(),
						       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		}
		if (terminal_descriptor < 0) {
			return descriptor_error(errno, "failed to open durable storage terminal", path.string());
		}
		unique_fd terminal_owner(terminal_descriptor);

		if (created) {
			if (::fchmod(terminal_owner.get(), static_cast<mode_t>(0700)) != 0) {
				return descriptor_error(errno, "failed to set durable storage terminal mode",
							path.string());
			}
			auto terminal_sync_status = fsync_descriptor(terminal_owner.get(), path.string());
			if (!terminal_sync_status.is_ok()) {
				return terminal_sync_status;
			}
			auto parent_sync_status = fsync_descriptor(current.get(), path.parent_path().string());
			if (!parent_sync_status.is_ok()) {
				return parent_sync_status;
			}
		}

		auto terminal_status = validate_terminal_directory(terminal_owner.get());
		if (!terminal_status.is_ok()) {
			return terminal_status;
		}
		auto recovery_status = discard_abandoned_publications(terminal_owner.get(), path);
		if (!recovery_status.is_ok()) {
			return recovery_status;
		}
		return durable_directory(terminal_owner.release(), path);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("durable directory admission exhausted memory");
	}
}

bool durable_directory::valid() const noexcept
{
	return descriptor_ >= 0;
}

const std::filesystem::path &durable_directory::path() const noexcept
{
	return path_;
}

status_or<std::vector<std::string>> durable_directory::list_files() const
{
	if (!valid()) {
		return status::failed_precondition("cannot enumerate an empty durable directory authority");
	}
	try {
		const int enumeration_descriptor =
			::openat(descriptor_, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (enumeration_descriptor < 0) {
			return descriptor_error(errno, "failed to open independent durable directory enumeration",
						path_.string());
		}
		DIR *raw_stream = ::fdopendir(enumeration_descriptor);
		if (raw_stream == nullptr) {
			const int error = errno;
			(void)::close(enumeration_descriptor);
			return descriptor_error(error, "failed to enumerate durable directory", path_.string());
		}
		unique_directory_stream stream(raw_stream);

		std::vector<std::string> names;
		for (;;) {
			errno = 0;
			dirent *entry = ::readdir(stream.get());
			if (entry == nullptr) {
				if (errno != 0) {
					return descriptor_error(errno, "failed while enumerating durable directory",
								path_.string());
				}
				break;
			}
			const std::string name(entry->d_name);
			if (name == "." || name == "..") {
				continue;
			}
			auto leaf_status = validate_leaf(name);
			if (!leaf_status.is_ok()) {
				return status::data_loss(
					"durable directory contains a name outside the storage grammar");
			}
			auto file_or = open_owned_file(descriptor_, name);
			if (!file_or.is_ok()) {
				return file_or.error();
			}
			names.push_back(name);
		}
		std::sort(names.begin(), names.end());
		return names;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("durable directory enumeration exhausted memory");
	}
}

status_or<std::string> durable_directory::read_file(std::string_view leaf, uint64_t maximum_size_bytes) const
{
	if (!valid()) {
		return status::failed_precondition("cannot read through an empty durable directory authority");
	}
	auto leaf_status = validate_leaf(leaf);
	if (!leaf_status.is_ok()) {
		return leaf_status;
	}
	try {
		auto file_or = open_owned_file(descriptor_, leaf);
		if (!file_or.is_ok()) {
			return file_or.error();
		}
		auto file_and_metadata = std::move(file_or).value();
		auto &file = file_and_metadata.first;
		const auto &before = file_and_metadata.second;
		if (before.st_size < 0 || static_cast<uint64_t>(before.st_size) > maximum_size_bytes ||
		    static_cast<uint64_t>(before.st_size) >
			    static_cast<uint64_t>(std::numeric_limits<std::size_t>::max())) {
			return status::resource_exhausted("durable store file exceeds the caller's read bound");
		}

		std::string bytes(static_cast<std::size_t>(before.st_size), '\0');
		constexpr std::size_t READ_CHUNK_BYTES = std::size_t{64} * 1024u;
		std::size_t offset = 0;
		while (offset < bytes.size()) {
			const std::size_t chunk_size = std::min(bytes.size() - offset, READ_CHUNK_BYTES);
			const ssize_t count =
				::pread(file.get(), bytes.data() + offset, chunk_size, static_cast<off_t>(offset));
			if (count < 0) {
				if (errno == EINTR) {
					continue;
				}
				return descriptor_error(errno, "failed to read durable store file", std::string(leaf));
			}
			if (count == 0) {
				return status::data_loss("durable store file became shorter during its exact read");
			}
			offset += static_cast<std::size_t>(count);
		}

		struct stat after{};
		if (::fstat(file.get(), &after) != 0) {
			return descriptor_error(errno, "failed to re-inspect durable store file", std::string(leaf));
		}
		if (!stable_file_metadata(before, after)) {
			return status::data_loss("durable store file changed during its exact read");
		}
		return bytes;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("durable store read exhausted memory");
	}
}

status durable_directory::publish_new_file(std::string_view leaf, std::string_view bytes)
{
	if (!valid()) {
		return status::failed_precondition("cannot publish through an empty durable directory authority");
	}
	auto leaf_status = validate_leaf(leaf);
	if (!leaf_status.is_ok()) {
		return leaf_status;
	}
	return publish_file_(leaf, bytes, publication_mode::CREATE_ONLY);
}

status_or<uint64_t> durable_directory::next_temporary_sequence() noexcept
{
	if (temporary_sequence_ == std::numeric_limits<uint64_t>::max()) {
		return status::resource_exhausted(kinetum::common::static_status_text(
			"durable replacement temporary-name sequence is exhausted"));
	}
	return ++temporary_sequence_;
}

status durable_directory::replace_file(std::string_view leaf, std::string_view bytes)
{
	if (!valid()) {
		return status::failed_precondition("cannot replace through an empty durable directory authority");
	}
	auto leaf_status = validate_leaf(leaf);
	if (!leaf_status.is_ok()) {
		return leaf_status;
	}
	return publish_file_(leaf, bytes, publication_mode::REPLACE_OR_CREATE);
}

status durable_directory::publish_file_(std::string_view leaf, std::string_view bytes, publication_mode mode)
{
	try {
		const std::string name(leaf);
		if (mode == publication_mode::REPLACE_OR_CREATE) {
			auto existing_or = open_owned_file(descriptor_, leaf);
			if (!existing_or.is_ok() && existing_or.error().code() != status_code::NOT_FOUND) {
				return existing_or.error();
			}
		}

		std::string temporary_name;
		unique_fd temporary;
		for (uint32_t attempt = 0; attempt < 64u; ++attempt) {
			auto sequence_or = next_temporary_sequence();
			if (!sequence_or.is_ok()) {
				return sequence_or.error();
			}
			temporary_name = std::string(PRIVATE_TEMPORARY_PREFIX) +
					 std::to_string(static_cast<uint64_t>(::getpid())) + "." +
					 std::to_string(sequence_or.value());
			const int descriptor = ::openat(descriptor_, temporary_name.c_str(),
							O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
							static_cast<mode_t>(0600));
			if (descriptor >= 0) {
				temporary = unique_fd(descriptor);
				break;
			}
			if (errno != EEXIST) {
				return descriptor_error(errno, "failed to create durable replacement file",
							temporary_name);
			}
		}
		if (temporary.get() < 0) {
			return status::resource_exhausted("durable replacement temporary-name space is exhausted");
		}
		temporary_entry_guard entry_guard(descriptor_, temporary_name);

		if (::fchmod(temporary.get(), static_cast<mode_t>(0600)) != 0) {
			const auto result =
				descriptor_error(errno, "failed to set durable replacement mode", temporary_name);
			discard_temporary_file_or_terminate(descriptor_, temporary_name);
			entry_guard.release();
			return result;
		}
		auto write_status = write_all(temporary.get(), bytes);
		if (!write_status.is_ok()) {
			discard_temporary_file_or_terminate(descriptor_, temporary_name);
			entry_guard.release();
			return write_status;
		}
		auto file_sync_status = fsync_descriptor(temporary.get(), temporary_name);
		if (!file_sync_status.is_ok()) {
			discard_temporary_file_or_terminate(descriptor_, temporary_name);
			entry_guard.release();
			return file_sync_status;
		}

		const int rename_result =
			mode == publication_mode::CREATE_ONLY ?
				rename_without_replacement(descriptor_, temporary_name.c_str(), name.c_str()) :
				::renameat(descriptor_, temporary_name.c_str(), descriptor_, name.c_str());
		if (rename_result != 0) {
			const auto result = descriptor_error(errno, "failed to publish durable store file", name);
			discard_temporary_file_or_terminate(descriptor_, temporary_name);
			entry_guard.release();
			return result;
		}
		entry_guard.release();
		fsync_published_directory_or_terminate(descriptor_);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("durable file publication exhausted memory");
	}
}

status durable_directory::remove_file(std::string_view leaf)
{
	if (!valid()) {
		return status::failed_precondition("cannot remove through an empty durable directory authority");
	}
	auto leaf_status = validate_leaf(leaf);
	if (!leaf_status.is_ok()) {
		return leaf_status;
	}
	try {
		const std::string name(leaf);
		auto file_or = open_owned_file(descriptor_, leaf);
		if (!file_or.is_ok()) {
			if (file_or.error().code() == status_code::NOT_FOUND) {
				return status::ok();
			}
			return file_or.error();
		}
		if (::unlinkat(descriptor_, name.c_str(), 0) != 0) {
			return descriptor_error(errno, "failed to remove durable store file", name);
		}
		fsync_published_directory_or_terminate(descriptor_);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("durable removal exhausted memory");
	}
}

}  // namespace kinetum::common
