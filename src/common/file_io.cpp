// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file file_io.cpp
 * @brief Bounded descriptor reads and durable file publication.
 * @author Fleming Patel
 */

#include "src/common/file_io.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fcntl.h>
#include <linux/fs.h>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <type_traits>
#include <utility>

#include <unistd.h>

#ifndef O_CLOEXEC
#error "Kinetum file I/O requires O_CLOEXEC"
#endif

#ifndef O_DIRECTORY
#error "Kinetum file I/O requires O_DIRECTORY"
#endif

namespace kinetum::common
{
namespace
{

/** @brief Fixed transfer bound for each read or write system call. */
constexpr std::size_t FILE_TRANSFER_CHUNK_BYTES = std::size_t{64} * 1024u;

/** @brief Maximum number of private-name collisions attempted per publication. */
constexpr uint32_t MAX_TEMPORARY_NAME_ATTEMPTS = 128u;

/** @brief Private same-directory namespace used only during publication. */
constexpr std::string_view PRIVATE_TEMPORARY_PREFIX = ".kinetum.file.tmp.";

/** @brief Select whether publication may replace the target name. */
enum class publication_mode : uint8_t {
	REPLACE_OR_CREATE,  ///< Atomically replace the target or create it.
	CREATE_ONLY,	    ///< Atomically publish only when the target is absent.
};

/** @brief Parent-directory path and terminal name resolved before effects. */
struct publication_target {
	std::string parent;  ///< Parent path opened exactly once.
	std::string leaf;    ///< Terminal name used only relative to the parent descriptor.
};

/** @brief Complete no-replacement rename arguments. */
struct no_replace_rename_request {
	int directory_descriptor;  ///< Borrowed parent descriptor for both names.
	const char *source;	   ///< Exact private source leaf.
	const char *target;	   ///< Exact absent target leaf.
};

/**
 * @brief Emit one fixed diagnostic and terminate.
 * @tparam extent Complete literal extent including its terminator.
 * @param message Fixed bounded diagnostic ending in a newline.
 */
template <std::size_t extent>
[[noreturn]] void emit_breadcrumb_and_terminate(const char (&message)[extent]) noexcept
{
	std::size_t offset = 0;
	while (offset + 1u < extent) {
		const ssize_t count = ::write(STDERR_FILENO, message + offset, extent - offset - 1u);
		if (count > 0) {
			offset += static_cast<std::size_t>(count);
			continue;
		}
		if (count < 0 && errno == EINTR) {
			continue;
		}
		break;
	}
	std::terminate();
}

/**
 * @brief Map one captured errno value to the shared status taxonomy.
 * @param error Captured nonzero errno value.
 * @return Stable application status category.
 */
status_code code_from_errno(int error) noexcept
{
	switch (error) {
	case EACCES:
	case EPERM:
		return status_code::PERMISSION_DENIED;
	case ENOENT:
	case ENOTDIR:
		return status_code::NOT_FOUND;
	case ENOSPC:
#if defined(EDQUOT) && EDQUOT != ENOSPC
	case EDQUOT:
#endif
		return status_code::RESOURCE_EXHAUSTED;
	case EEXIST:
		return status_code::ALREADY_EXISTS;
	default:
		return status_code::INTERNAL_ERROR;
	}
}

/**
 * @brief Build one status from a captured errno value.
 * @param error Captured errno value that will not be reread.
 * @param message Stable operation diagnostic.
 * @param detail Exact path or object identity.
 * @return Typed status containing the captured system diagnostic text.
 */
status errno_status(int error, std::string message, std::string detail)
{
	return status(code_from_errno(error), std::move(message), std::move(detail) + ": " + std::strerror(error));
}

/** @brief Unique local descriptor owner used by one operation. */
class unique_fd {
    public:
	/**
	 * @brief Adopt one descriptor, or remain empty for a negative value.
	 * @param descriptor Descriptor ownership, or a negative empty value.
	 */
	explicit unique_fd(int descriptor = -1) noexcept
		: descriptor_(descriptor)
	{
	}

	/** @brief Close an owned descriptor without allowing ownership to escape. */
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
	 * @brief Transfer one descriptor without closing it.
	 * @param other Descriptor owner made empty by the transfer.
	 */
	unique_fd(unique_fd &&other) noexcept
		: descriptor_(std::exchange(other.descriptor_, -1))
	{
	}

	/** @brief Descriptor ownership is fixed after construction. */
	unique_fd &operator=(unique_fd &&) = delete;

	/** @return Borrowed descriptor, or -1 when empty. */
	[[nodiscard]] int get() const noexcept
	{
		return descriptor_;
	}

	/** @return Owned descriptor while making this object empty. */
	[[nodiscard]] int release() noexcept
	{
		return std::exchange(descriptor_, -1);
	}

    private:
	int descriptor_{-1};  ///< Unique descriptor.
};

/**
 * @brief Synchronize one open descriptor, retrying interruption.
 * @param descriptor Borrowed open descriptor.
 * @param subject Stable diagnostic identity for the descriptor.
 * @return OK after fsync succeeds, otherwise the captured system failure.
 */
status fsync_descriptor(int descriptor, const std::string &subject)
{
	for (;;) {
		if (::fsync(descriptor) == 0) {
			return status::ok();
		}
		if (errno == EINTR) {
			continue;
		}
		return errno_status(errno, "failed to fsync file", subject);
	}
}

/**
 * @brief Make an irreversible namespace mutation durable or fail stop.
 * @param directory_descriptor Borrowed parent-directory descriptor.
 */
void fsync_published_directory_or_terminate(int directory_descriptor) noexcept
{
	for (;;) {
		if (::fsync(directory_descriptor) == 0) {
			return;
		}
		if (errno != EINTR) {
			emit_breadcrumb_and_terminate(
				"Kinetum file publication lost post-rename durability certainty\n");
		}
	}
}

/**
 * @brief Own one unpublished temporary descriptor and directory entry.
 *
 * Destruction closes the descriptor, removes the private entry, and makes that
 * removal durable. Any uncertain cleanup fails stop before ownership can be
 * forgotten.
 */
class unpublished_file {
    public:
	/**
	 * @brief Adopt one already-created private entry.
	 * @param directory_descriptor Parent descriptor that outlives this owner.
	 * @param name Exact private leaf ownership.
	 * @param descriptor Open writable descriptor ownership.
	 */
	unpublished_file(int directory_descriptor, std::string &&name, int descriptor) noexcept
		: directory_descriptor_(directory_descriptor)
		, name_(std::move(name))
		, descriptor_(descriptor)
	{
	}

	/** @brief Roll back any entry that has not crossed the publication edge. */
	~unpublished_file()
	{
		if (armed_) {
			rollback_or_terminate_();
		}
	}

	/** @brief Disable ownership aliasing. */
	unpublished_file(const unpublished_file &) = delete;

	/** @brief Disable ownership aliasing by assignment. */
	unpublished_file &operator=(const unpublished_file &) = delete;

	/**
	 * @brief Transfer complete unpublished ownership.
	 * @param other Owner disarmed by the transfer.
	 */
	unpublished_file(unpublished_file &&other) noexcept
		: directory_descriptor_(std::exchange(other.directory_descriptor_, -1))
		, name_(std::move(other.name_))
		, descriptor_(std::exchange(other.descriptor_, -1))
		, armed_(std::exchange(other.armed_, false))
	{
	}

	/** @brief Unpublished ownership is fixed after construction. */
	unpublished_file &operator=(unpublished_file &&) = delete;

	/** @return Borrowed writable descriptor. */
	[[nodiscard]] int descriptor() const noexcept
	{
		return descriptor_;
	}

	/** @return Borrowed exact private leaf. */
	[[nodiscard]] const std::string &name() const noexcept
	{
		return name_;
	}

	/**
	 * @brief Close the writable descriptor before namespace publication.
	 * @return OK after close, otherwise the captured close failure.
	 */
	status close_checked()
	{
		if (descriptor_ < 0) {
			emit_breadcrumb_and_terminate(
				"Kinetum file publication attempted a duplicate temporary close\n");
		}
		const int descriptor = std::exchange(descriptor_, -1);
		if (::close(descriptor) == 0) {
			return status::ok();
		}
		return errno_status(errno, "failed to close publication temporary", name_);
	}

	/** @brief Disarm cleanup immediately after a successful atomic rename. */
	void release_after_publication() noexcept
	{
		if (!armed_ || descriptor_ >= 0) {
			emit_breadcrumb_and_terminate("Kinetum file publication released an invalid temporary claim\n");
		}
		armed_ = false;
	}

    private:
	/** @brief Close and durably remove the private entry or fail stop. */
	void rollback_or_terminate_() noexcept
	{
		bool close_failed = false;
		if (descriptor_ >= 0) {
			const int descriptor = std::exchange(descriptor_, -1);
			close_failed = ::close(descriptor) != 0;
		}

		for (;;) {
			if (::unlinkat(directory_descriptor_, name_.c_str(), 0) == 0 || errno == ENOENT) {
				break;
			}
			if (errno != EINTR) {
				emit_breadcrumb_and_terminate(
					"Kinetum file publication could not remove its temporary\n");
			}
		}
		fsync_published_directory_or_terminate(directory_descriptor_);
		if (close_failed) {
			emit_breadcrumb_and_terminate("Kinetum file publication could not close its temporary\n");
		}
		armed_ = false;
	}

	int directory_descriptor_{-1};	///< Borrowed parent descriptor.
	std::string name_;		///< Owned private leaf.
	int descriptor_{-1};		///< Owned writable descriptor.
	bool armed_{true};		///< Whether destruction must roll back the entry.
};

static_assert(std::is_nothrow_move_constructible_v<unpublished_file>);

/** @brief Complete immutable input for one descriptor write. */
struct file_write_request {
	int descriptor;		///< Borrowed writable descriptor.
	std::string_view data;	///< Complete bytes to write.
	std::string_view path;	///< Diagnostic path identity.
};

/**
 * @brief Write every byte in one request using bounded system calls.
 * @param request Complete descriptor, data, and diagnostic identity.
 * @return OK after complete write, otherwise the first system failure.
 */
status write_all(const file_write_request &request)
{
	const char *next = request.data.data();
	std::size_t remaining = request.data.size();
	while (remaining > 0u) {
		const std::size_t requested = std::min(remaining, FILE_TRANSFER_CHUNK_BYTES);
		const ssize_t count = ::write(request.descriptor, next, requested);
		if (count < 0) {
			if (errno == EINTR) {
				continue;
			}
			return errno_status(errno, "failed to write file", std::string(request.path));
		}
		if (count == 0) {
			return status(status_code::INTERNAL_ERROR, "failed to write file",
				      std::string(request.path) + ": write returned 0");
		}
		next += count;
		remaining -= static_cast<std::size_t>(count);
	}
	return status::ok();
}

/**
 * @brief Close one owned descriptor and preserve close failure.
 * @param descriptor Open descriptor whose ownership is consumed.
 * @param path Diagnostic path identity.
 * @return OK after close succeeds, otherwise the captured system failure.
 */
status close_fd_checked(int descriptor, const std::string &path)
{
	if (::close(descriptor) == 0) {
		return status::ok();
	}
	return errno_status(errno, "failed to close file", path);
}

/**
 * @brief Resolve one target into a parent path and terminal name before effects.
 * @param path Caller-authorized target representation.
 * @return Complete target identity or INVALID_ARGUMENT for an unusable leaf.
 */
status_or<publication_target> resolve_publication_target(const std::filesystem::path &path)
{
	if (path.empty()) {
		return status::invalid_argument("file publication requires a nonempty target path");
	}

	std::string leaf = path.filename().string();
	if (leaf.empty() || leaf == "." || leaf == "..") {
		return status::invalid_argument("file publication target must have one terminal filename");
	}
	if (leaf.find('\0') != std::string::npos) {
		return status::invalid_argument("file publication target contains a null byte");
	}
	if (leaf.starts_with(PRIVATE_TEMPORARY_PREFIX)) {
		return status::invalid_argument("file publication target uses the private temporary namespace");
	}

	std::filesystem::path parent = path.parent_path();
	if (parent.empty()) {
		parent = ".";
	}
	std::string parent_text = parent.string();
	if (parent_text.find('\0') != std::string::npos) {
		return status::invalid_argument("file publication parent contains a null byte");
	}
	return publication_target{.parent = std::move(parent_text), .leaf = std::move(leaf)};
}

/**
 * @brief Open one parent directory exactly once for a publication transaction.
 * @param parent Exact parent path resolved before effects.
 * @return Unique directory descriptor or the captured open failure.
 */
status_or<unique_fd> open_parent_directory(const std::string &parent)
{
	int descriptor = -1;
	for (;;) {
		descriptor = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (descriptor >= 0 || errno != EINTR) {
			break;
		}
	}
	if (descriptor < 0) {
		return errno_status(errno, "failed to open publication parent directory", parent);
	}
	return unique_fd(descriptor);
}

/**
 * @brief Create one private same-directory publication file.
 * @param directory_descriptor Borrowed parent-directory descriptor.
 * @return Scope-bound unpublished owner or the first creation failure.
 */
status_or<unpublished_file> create_temporary_file(int directory_descriptor)
{
	for (uint32_t attempt = 0; attempt < MAX_TEMPORARY_NAME_ATTEMPTS; ++attempt) {
		std::string name = std::string(PRIVATE_TEMPORARY_PREFIX) +
				   std::to_string(static_cast<uint64_t>(::getpid())) + "." + std::to_string(attempt);
		const int descriptor = ::openat(directory_descriptor, name.c_str(),
						O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
						static_cast<mode_t>(0600));
		if (descriptor >= 0) {
			return unpublished_file(directory_descriptor, std::move(name), descriptor);
		}
		if (errno != EEXIST) {
			return errno_status(errno, "failed to create publication temporary", std::move(name));
		}
	}
	return status::resource_exhausted(static_status_text("file publication temporary-name space is exhausted"));
}

/**
 * @brief Atomically rename one entry only when its target is absent.
 * @param request Complete parent, source, and target identity.
 * @return Zero on publication or -1 with errno set.
 */
int rename_without_replacement(const no_replace_rename_request &request) noexcept
{
#if defined(SYS_renameat2)
	return static_cast<int>(::syscall(SYS_renameat2, request.directory_descriptor, request.source,
					  request.directory_descriptor, request.target, RENAME_NOREPLACE));
#else
	(void)request;
	errno = ENOSYS;
	return -1;
#endif
}

/**
 * @brief Publish one complete byte sequence under the selected namespace rule.
 * @param path Caller-authorized target path.
 * @param data Complete bytes to publish.
 * @param mode Replacement or create-only behavior.
 * @return OK only after durable publication, otherwise a prepublication error.
 */
status publish_string_file(const std::filesystem::path &path, std::string_view data, publication_mode mode)
{
	try {
		auto target_or = resolve_publication_target(path);
		if (!target_or.is_ok()) {
			return std::move(target_or).error();
		}
		publication_target target = std::move(target_or).value();

		auto parent_or = open_parent_directory(target.parent);
		if (!parent_or.is_ok()) {
			return std::move(parent_or).error();
		}
		unique_fd parent = std::move(parent_or).value();

		auto temporary_or = create_temporary_file(parent.get());
		if (!temporary_or.is_ok()) {
			return std::move(temporary_or).error();
		}
		unpublished_file temporary = std::move(temporary_or).value();

		auto write_status = write_all(file_write_request{
			.descriptor = temporary.descriptor(), .data = data, .path = temporary.name()});
		if (!write_status.is_ok()) {
			return write_status;
		}
		if (::fchmod(temporary.descriptor(), static_cast<mode_t>(0644)) != 0) {
			return errno_status(errno, "failed to set published file mode", temporary.name());
		}
		auto file_sync_status = fsync_descriptor(temporary.descriptor(), temporary.name());
		if (!file_sync_status.is_ok()) {
			return file_sync_status;
		}
		auto close_status = temporary.close_checked();
		if (!close_status.is_ok()) {
			return close_status;
		}

		const int rename_result =
			mode == publication_mode::CREATE_ONLY ?
				rename_without_replacement(no_replace_rename_request{
					.directory_descriptor = parent.get(),
					.source = temporary.name().c_str(),
					.target = target.leaf.c_str(),
				}) :
				::renameat(parent.get(), temporary.name().c_str(), parent.get(), target.leaf.c_str());
		if (rename_result != 0) {
			return errno_status(errno, "failed to publish file", target.leaf);
		}
		temporary.release_after_publication();
		fsync_published_directory_or_terminate(parent.get());
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(static_status_text("file publication exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("file publication exceeded a representation limit"));
	} catch (const std::exception &) {
		return status::internal_error(static_status_text("file publication failed with an internal exception"));
	} catch (...) {
		return status::internal_error(static_status_text("file publication failed with an unknown exception"));
	}
}

}  // namespace

status_or<std::string> read_file_to_string(const std::string &path, std::size_t max_size)
{
	try {
		if (max_size == 0u) {
			return status::invalid_argument("file read requires a positive maximum size");
		}
		if (path.find('\0') != std::string::npos) {
			return status::invalid_argument("file read path contains a null byte");
		}

		int descriptor = -1;
		for (;;) {
			descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
			if (descriptor >= 0 || errno != EINTR) {
				break;
			}
		}
		if (descriptor < 0) {
			return status(status_code::NOT_FOUND, "failed to open file", path);
		}
		unique_fd file(descriptor);

		std::string contents;
		std::array<char, FILE_TRANSFER_CHUNK_BYTES> chunk{};
		for (;;) {
			const ssize_t bytes_read = ::read(file.get(), chunk.data(), chunk.size());
			if (bytes_read < 0) {
				if (errno == EINTR) {
					continue;
				}
				return errno_status(errno, "failed to read file", path);
			}
			if (bytes_read == 0) {
				break;
			}

			const std::size_t count = static_cast<std::size_t>(bytes_read);
			if (count > max_size - contents.size()) {
				return status(status_code::RESOURCE_EXHAUSTED, "file size exceeds maximum allowed",
					      "max=" + std::to_string(max_size));
			}
			contents.append(chunk.data(), count);
		}

		auto close_status = close_fd_checked(file.release(), path);
		if (!close_status.is_ok()) {
			return close_status;
		}
		return contents;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(static_status_text("file read exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("file read exceeded the string size domain"));
	} catch (const std::exception &) {
		return status::internal_error(static_status_text("file read failed with an internal exception"));
	} catch (...) {
		return status::internal_error(static_status_text("file read failed with an unknown exception"));
	}
}

status write_string_to_file(const std::filesystem::path &path, std::string_view data)
{
	return publish_string_file(path, data, publication_mode::REPLACE_OR_CREATE);
}

status publish_new_string_file(const std::filesystem::path &path, std::string_view data)
{
	return publish_string_file(path, data, publication_mode::CREATE_ONLY);
}

}  // namespace kinetum::common
