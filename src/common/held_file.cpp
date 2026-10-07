// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file held_file.cpp
 * @brief Symlink-free held-descriptor artifact admission implementation.
 * @author Fleming Patel
 */

#include "src/common/held_file.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/common/sha256.hpp"

namespace kinetum::common
{
namespace
{

/** @brief Fixed descriptor-read chunk size. */
constexpr std::size_t HELD_FILE_IO_CHUNK_BYTES = std::size_t{64} * 1024u;

/** @brief Unique local file-descriptor owner used during path traversal. */
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

/**
 * @brief Map one errno value to the platform status taxonomy.
 *
 * @param error Captured errno.
 * @param action Stable failed operation.
 * @param path Exact artifact path.
 * @return Detailed non-OK status.
 */
status descriptor_error(int error, std::string action, const std::filesystem::path &path)
{
	status_code code = status_code::INTERNAL_ERROR;
	if (error == ENOENT) {
		code = status_code::NOT_FOUND;
	} else if (error == EACCES || error == EPERM) {
		code = status_code::PERMISSION_DENIED;
	} else if (error == ENOTDIR || error == ELOOP) {
		code = status_code::FAILED_PRECONDITION;
	}
	return status(code, std::move(action), path.string() + ": " + std::strerror(error));
}

/**
 * @brief Compare metadata that must remain stable while hashing.
 *
 * @param before Metadata sampled before hashing.
 * @param after Metadata sampled after hashing.
 * @return true only when identity, size, mode, ownership, and timestamps agree.
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
 * @brief Hash one descriptor without mutating its shared file offset.
 *
 * @param descriptor Open regular-file descriptor.
 * @return Exact digest and bytes read, or an explicit pread/provider failure.
 */
status_or<held_file_identity> hash_descriptor(int descriptor)
{
	sha256_hasher hasher;
	std::array<uint8_t, HELD_FILE_IO_CHUNK_BYTES> buffer{};
	uint64_t offset = 0;
	for (;;) {
		if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
			return status::resource_exhausted("artifact exceeds representable pread offset");
		}
		const ssize_t count = ::pread(descriptor, buffer.data(), buffer.size(), static_cast<off_t>(offset));
		if (count < 0) {
			if (errno == EINTR) {
				continue;
			}
			return status(status_code::INTERNAL_ERROR, "failed to read held artifact",
				      std::strerror(errno));
		}
		if (count == 0) {
			break;
		}
		const auto chunk_size = static_cast<uint64_t>(count);
		if (offset > std::numeric_limits<uint64_t>::max() - chunk_size) {
			return status::resource_exhausted("artifact size exceeds uint64 range");
		}
		hasher.update(buffer.data(), static_cast<std::size_t>(count));
		offset += chunk_size;
	}

	auto digest_or = hasher.finalize_raw();
	if (!digest_or.is_ok()) {
		return digest_or.error();
	}
	return held_file_identity{std::move(digest_or).value(), offset};
}

/**
 * @brief Return whether one normalized absolute path is at or below another.
 *
 * @param path Candidate descendant.
 * @param root Candidate ancestor.
 * @return true only when every root component is an exact path prefix.
 */
bool is_at_or_beneath(const std::filesystem::path &path, const std::filesystem::path &root) noexcept
{
	std::string_view path_view(path.native());
	std::string_view root_view(root.native());
	while (root_view.size() > 1u && root_view.back() == '/') {
		root_view.remove_suffix(1u);
	}
	if (root_view == "/") {
		return !path_view.empty() && path_view.front() == '/';
	}
	return path_view.starts_with(root_view) &&
	       (path_view.size() == root_view.size() ||
		(path_view.size() > root_view.size() && path_view[root_view.size()] == '/'));
}

/**
 * @brief Validate one already-open directory against its subtree authority.
 *
 * @param descriptor Exact directory descriptor.
 * @param policy Required owner and forbidden mode bits.
 * @return OK only for an exact trusted directory.
 */
status validate_directory_authority(int descriptor, const held_directory_policy &policy)
{
	struct stat metadata{};
	if (::fstat(descriptor, &metadata) != 0) {
		return status(status_code::INTERNAL_ERROR, "failed to inspect held artifact directory",
			      std::strerror(errno));
	}
	if (!S_ISDIR(metadata.st_mode)) {
		return status::failed_precondition("held artifact path component is not a directory");
	}
	if (static_cast<uint64_t>(metadata.st_uid) != static_cast<uint64_t>(policy.required_owner_uid)) {
		return status::permission_denied(
			"held artifact directory owner does not match the required installation authority");
	}
	if ((static_cast<uint32_t>(metadata.st_mode) & policy.forbidden_mode_bits) != 0u) {
		return status::permission_denied("held artifact directory has forbidden writable permission bits");
	}
	return status::ok();
}

}  // namespace

held_file::held_file(int descriptor, std::filesystem::path path, held_file_identity identity) noexcept
	: descriptor_(descriptor)
	, path_(std::move(path))
	, identity_(identity)
{
}

held_file::~held_file()
{
	if (descriptor_ >= 0) {
		(void)::close(descriptor_);
	}
}

held_file::held_file(held_file &&other) noexcept
	: descriptor_(std::exchange(other.descriptor_, -1))
	, path_(std::move(other.path_))
	, identity_(other.identity_)
{
}

held_file &held_file::operator=(held_file &&other) noexcept
{
	if (this != &other) {
		if (descriptor_ >= 0) {
			(void)::close(descriptor_);
		}
		descriptor_ = std::exchange(other.descriptor_, -1);
		path_ = std::move(other.path_);
		identity_ = other.identity_;
	}
	return *this;
}

bool held_file::valid() const noexcept
{
	return descriptor_ >= 0;
}

int held_file::descriptor() const noexcept
{
	return descriptor_;
}

const std::filesystem::path &held_file::path() const noexcept
{
	return path_;
}

const held_file_identity &held_file::identity() const noexcept
{
	return identity_;
}

std::string held_file::proc_descriptor_path() const
{
	if (!valid()) {
		return {};
	}
	return "/proc/self/fd/" + std::to_string(descriptor_);
}

status_or<held_file> open_held_regular_file(const std::filesystem::path &path, const held_file_policy &policy)
{
	if (path.native().find('\0') != std::filesystem::path::string_type::npos || path.empty() ||
	    !path.is_absolute() || path != path.lexically_normal()) {
		return status::invalid_argument("held artifact path must be exact, absolute, and lexically normalized");
	}
	if (policy.directories.has_value()) {
		const auto &root = policy.directories->root;
		if (root.native().find('\0') != std::filesystem::path::string_type::npos || root.empty() ||
		    !root.is_absolute() || root != root.lexically_normal() ||
		    !is_at_or_beneath(path.parent_path(), root)) {
			return status::invalid_argument(
				"held artifact directory authority must be one exact ancestor of the file");
		}
	}

	unique_fd current(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	if (current.get() < 0) {
		return descriptor_error(errno, "failed to open filesystem root", path);
	}

	std::vector<std::filesystem::path> components;
	for (const auto &component : path.relative_path()) {
		if (component.empty() || component == "." || component == ".." || component.has_parent_path()) {
			return status::invalid_argument("held artifact path contains a noncanonical component");
		}
		components.push_back(component);
	}
	if (components.empty()) {
		return status::invalid_argument("held artifact path must name a regular file");
	}

	std::filesystem::path traversed = "/";
	for (std::size_t index = 0; index + 1u < components.size(); ++index) {
		const int next = ::openat(current.get(), components[index].c_str(),
					  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (next < 0) {
			return descriptor_error(errno, "failed symlink-free artifact-directory admission", path);
		}
		current = unique_fd(next);
		traversed /= components[index];
		if (policy.directories.has_value() && is_at_or_beneath(traversed, policy.directories->root)) {
			const auto directory_status = validate_directory_authority(current.get(), *policy.directories);
			if (!directory_status.is_ok()) {
				return directory_status;
			}
		}
	}

	unique_fd artifact(
		::openat(current.get(), components.back().c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
	if (artifact.get() < 0) {
		return descriptor_error(errno, "failed symlink-free artifact admission", path);
	}

	struct stat before{};
	if (::fstat(artifact.get(), &before) != 0) {
		return descriptor_error(errno, "failed to inspect held artifact", path);
	}
	if (!S_ISREG(before.st_mode)) {
		return status::failed_precondition("held artifact is not a regular file");
	}
	if (policy.required_owner_uid.has_value() &&
	    static_cast<uint64_t>(before.st_uid) != static_cast<uint64_t>(*policy.required_owner_uid)) {
		return status::permission_denied(
			"held artifact owner does not match the required installation authority");
	}
	if ((static_cast<uint32_t>(before.st_mode) & policy.forbidden_mode_bits) != 0u) {
		return status::permission_denied("held artifact has forbidden writable permission bits");
	}
	if (policy.require_single_link && before.st_nlink != 1) {
		return status::failed_precondition("held artifact must have exactly one filesystem link");
	}
	if (before.st_size < 0) {
		return status::failed_precondition("held artifact reports a negative size");
	}
	if (policy.maximum_size_bytes.has_value() &&
	    static_cast<uint64_t>(before.st_size) > *policy.maximum_size_bytes) {
		return status::resource_exhausted("held artifact exceeds the admission size bound");
	}

	auto identity_or = hash_descriptor(artifact.get());
	if (!identity_or.is_ok()) {
		return identity_or.error();
	}

	struct stat after{};
	if (::fstat(artifact.get(), &after) != 0) {
		return descriptor_error(errno, "failed to re-inspect held artifact", path);
	}
	if (!stable_file_metadata(before, after) || static_cast<uint64_t>(after.st_size) != identity_or->size_bytes) {
		return status::failed_precondition("held artifact changed while its identity was computed");
	}

	return held_file(artifact.release(), path, std::move(identity_or).value());
}

status verify_held_file_identity(const held_file &file, const sha256_digest &expected_sha256,
				 uint64_t expected_size_bytes)
{
	if (!file.valid()) {
		return status::failed_precondition("cannot verify an empty held artifact");
	}
	if (file.identity().size_bytes != expected_size_bytes) {
		return status::data_loss("held artifact size does not match its authenticated inventory claim");
	}
	if (file.identity().sha256 != expected_sha256) {
		return status::data_loss("held artifact SHA-256 does not match its authenticated inventory claim");
	}
	return status::ok();
}

status_or<std::string> read_held_file(const held_file &file, uint64_t maximum_size_bytes)
{
	if (!file.valid()) {
		return status::failed_precondition("cannot read an empty held artifact");
	}
	if (file.identity().size_bytes > maximum_size_bytes ||
	    file.identity().size_bytes > static_cast<uint64_t>(std::numeric_limits<std::size_t>::max())) {
		return status::resource_exhausted("held artifact exceeds the caller's read bound");
	}

	try {
		std::string bytes(static_cast<std::size_t>(file.identity().size_bytes), '\0');
		sha256_hasher hasher;
		uint64_t offset = 0;
		while (offset < file.identity().size_bytes) {
			if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
				return status::resource_exhausted("held artifact exceeds representable pread offset");
			}
			const uint64_t remaining = file.identity().size_bytes - offset;
			const std::size_t chunk_size = static_cast<std::size_t>(
				std::min<uint64_t>(remaining, static_cast<uint64_t>(HELD_FILE_IO_CHUNK_BYTES)));
			const ssize_t count = ::pread(file.descriptor(),
						      bytes.data() + static_cast<std::size_t>(offset), chunk_size,
						      static_cast<off_t>(offset));
			if (count < 0) {
				if (errno == EINTR) {
					continue;
				}
				return status(status_code::INTERNAL_ERROR, "failed to read held artifact",
					      std::strerror(errno));
			}
			if (count == 0) {
				return status::data_loss("held artifact became shorter after identity admission");
			}
			hasher.update(bytes.data() + static_cast<std::size_t>(offset), static_cast<std::size_t>(count));
			offset += static_cast<uint64_t>(count);
		}

		struct stat after{};
		if (::fstat(file.descriptor(), &after) != 0) {
			return status(status_code::INTERNAL_ERROR, "failed to re-inspect held artifact",
				      std::strerror(errno));
		}
		if (after.st_size < 0 || static_cast<uint64_t>(after.st_size) != file.identity().size_bytes) {
			return status::data_loss("held artifact size changed after identity admission");
		}

		auto digest_or = hasher.finalize_raw();
		if (!digest_or.is_ok()) {
			return digest_or.error();
		}
		if (digest_or.value() != file.identity().sha256) {
			return status::data_loss("held artifact bytes changed after identity admission");
		}
		return bytes;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("held artifact read exhausted memory");
	}
}

}  // namespace kinetum::common
