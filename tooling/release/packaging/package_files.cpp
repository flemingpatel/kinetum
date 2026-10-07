// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file package_files.cpp
 * @brief Native bounded package codecs and descriptor-relative file operations.
 * @author Fleming Patel
 */

#include "tooling/release/packaging/package_files.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <zlib.h>

#include "src/common/process_output.hpp"
#include "src/common/sha256.hpp"
#include "src/provider/provider_elf.hpp"

namespace kinetum::release
{
namespace fs = std::filesystem;

namespace
{
using common::status;
using common::status_code;
using common::status_or;
using common::static_status_text;

constexpr std::size_t IO_BLOCK_BYTES = 64u * 1024u;  ///< Fixed streaming buffer size.

/**
 * @brief Preserve the failing syscall's diagnostic at the cold boundary.
 * @param action Failed I/O operation.
 * @param error Saved errno value.
 * @return Owned INTERNAL_ERROR diagnostic; allocation propagates at this cold boundary.
 */
status io_error(std::string_view action, int error = errno)
{
	return status(status_code::INTERNAL_ERROR, std::string(action), std::strerror(error));
}

/** One locally owned descriptor; successful writers explicitly sync and close. */
class descriptor {
    public:
	/** @brief Adopt the result of one successful open.
	 * @param value Unique live descriptor whose close obligation is transferred.
	 */
	explicit descriptor(int value) noexcept
		: value_(value)
	{
	}
	/** @brief Prevent duplicate descriptor ownership. */
	descriptor(const descriptor &) = delete;
	/** @brief Prevent duplicate descriptor ownership. */
	descriptor &operator=(const descriptor &) = delete;
	/** @brief Transfer the one close obligation.
	 * @param other Source disarmed by this move.
	 */
	descriptor(descriptor &&other) noexcept
		: value_(std::exchange(other.value_, -1))
	{
	}
	/** @brief Retire a prior read descriptor and transfer ownership.
	 * @param other Source disarmed by this move.
	 * @return This owner; self-assignment preserves its descriptor.
	 */
	descriptor &operator=(descriptor &&other) noexcept
	{
		if (this != &other) {
			if (value_ >= 0) {
				(void)::close(value_);
			}
			value_ = std::exchange(other.value_, -1);
		}
		return *this;
	}
	/** @brief Close abandoned private or read-only state. */
	~descriptor()
	{
		if (value_ >= 0) {
			(void)::close(value_);
		}
	}
	/** @return Exact descriptor borrowed until close, transfer or destruction. */
	[[nodiscard]] int get() const noexcept
	{
		return value_;
	}
	/** @return Close outcome after disarming this owner; callers never retry close. */
	[[nodiscard]] status close()
	{
		const int value = std::exchange(value_, -1);
		return ::close(value) == 0 ? status::ok() : io_error("cannot close package file");
	}

    private:
	int value_;  ///< Sole close obligation, or -1 after transfer.
};

/**
 * @brief Open every absolute directory component without following a link.
 * @param path Canonical absolute directory path.
 * @return One owned descriptor after component-by-component no-follow opens.
 */
status_or<descriptor> open_directory(const fs::path &path)
{
	if (!path.is_absolute() || path != path.lexically_normal() || path.native().find('\0') != std::string::npos) {
		return status::invalid_argument(static_status_text("package directory must be exact and absolute"));
	}
	const int initial = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (initial < 0) {
		return io_error("cannot open filesystem root");
	}
	descriptor current(initial);
	for (const auto &component : path.relative_path()) {
		const int next =
			::openat(current.get(), component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (next < 0) {
			return io_error("cannot open exact package directory");
		}
		current = descriptor(next);
	}
	return current;
}

/**
 * @brief Admit one owner-private empty directory through its held descriptor.
 * @param root Held directory descriptor borrowed for this check.
 * @return OK only for current-UID mode0700 and no child entry.
 */
status require_empty_private_directory(int root)
{
	struct stat metadata{};
	if (::fstat(root, &metadata) != 0) {
		return io_error("cannot inspect extraction directory");
	}
	if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() || (metadata.st_mode & 07777) != 0700) {
		return status::permission_denied(
			static_status_text("extraction directory must be owner-private mode 0700"));
	}
	const int duplicate = ::fcntl(root, F_DUPFD_CLOEXEC, 3);
	if (duplicate < 0) {
		return io_error("cannot retain extraction directory");
	}
	/** @brief Close the directory stream and its adopted descriptor. */
	struct directory_deleter {
		/** @brief Retire the stream and its adopted directory descriptor. */
		void operator()(DIR *value) const noexcept
		{
			(void)::closedir(value);
		}
	};
	std::unique_ptr<DIR, directory_deleter> directory(::fdopendir(duplicate));
	if (!directory) {
		const int error = errno;
		(void)::close(duplicate);
		return io_error("cannot enumerate extraction directory", error);
	}
	for (;;) {
		errno = 0;
		const dirent *entry = ::readdir(directory.get());
		if (entry == nullptr) {
			return errno == 0 ? status::ok() : io_error("cannot read extraction directory");
		}
		if (std::strcmp(entry->d_name, ".") != 0 && std::strcmp(entry->d_name, "..") != 0) {
			return status::failed_precondition(static_status_text("extraction directory must be empty"));
		}
	}
}

/**
 * @brief Open or create exact relative parents beneath an already-owned root.
 * @param root Held current-owner private destination root.
 * @param relative Canonical relative file path.
 * @return Owned parent descriptor after creating and syncing missing exact-mode directories.
 */
status_or<descriptor> destination_parent(int root, std::string_view relative)
{
	const auto valid = validate_payload_path(relative);
	if (!valid.is_ok()) {
		return valid;
	}
	const int duplicate = ::fcntl(root, F_DUPFD_CLOEXEC, 3);
	if (duplicate < 0) {
		return io_error("cannot retain extraction root");
	}
	descriptor current(duplicate);
	std::size_t begin = 0;
	for (std::size_t end = relative.find('/'); end != std::string_view::npos; end = relative.find('/', begin)) {
		const std::string part(relative.substr(begin, end - begin));
		const bool created = ::mkdirat(current.get(), part.c_str(), 0700) == 0;
		if (!created && errno != EEXIST) {
			return io_error("cannot create package parent directory");
		}
		const int next = ::openat(current.get(), part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (next < 0) {
			return io_error("cannot open package parent directory");
		}
		descriptor child(next);
		struct stat metadata{};
		if (::fstat(child.get(), &metadata) != 0) {
			return io_error("cannot inspect package parent directory");
		}
		if (metadata.st_uid != ::geteuid() || (metadata.st_mode & 0022) != 0) {
			return status::permission_denied(static_status_text("package parent is not exclusively owned"));
		}
		if (created &&
		    (::fchmod(child.get(), 0755) != 0 || ::fsync(child.get()) != 0 || ::fsync(current.get()) != 0)) {
			return io_error("cannot make package directory durable");
		}
		current = std::move(child);
		begin = end + 1u;
	}
	return current;
}

/**
 * @brief Deliver a bounded buffer completely, including partial writes and EINTR.
 * @param output Borrowed writable descriptor.
 * @param data Readable buffer outliving the call.
 * @param size Exact buffer extent.
 * @return OK only after every byte is written; partial writes and EINTR retain progress.
 */
status write_all(int output, const void *data, std::size_t size)
{
	const auto *bytes = static_cast<const char *>(data);
	while (size != 0u) {
		const ssize_t written = ::write(output, bytes, size);
		if (written < 0 && errno == EINTR) {
			continue;
		}
		if (written <= 0) {
			return io_error("cannot write complete package bytes", written == 0 ? EIO : errno);
		}
		const auto count = static_cast<std::size_t>(written);
		bytes += count;
		size -= count;
	}
	return status::ok();
}

/**
 * @brief Stream a held file through a consumer and prove the exact second read.
 * @param file Held immutable source.
 * @param expected Previously admitted complete identity.
 * @param consume Cold synchronous consumer whose status is propagated.
 * @tparam consumer Synchronous C++ callback returning status.
 * @return OK after delivered bytes match the expected identity; callback/allocation exceptions propagate.
 */
template <typename consumer>
status stream_file(const common::held_file &file, const common::held_file_identity &expected, consumer &&consume)
{
	const auto identity = common::verify_held_file_identity(file, expected.sha256, expected.size_bytes);
	if (!identity.is_ok()) {
		return identity;
	}
	std::array<char, IO_BLOCK_BYTES> buffer{};
	common::sha256_hasher hash;
	uint64_t offset = 0;
	while (offset < expected.size_bytes) {
		const auto request =
			static_cast<std::size_t>(std::min<uint64_t>(buffer.size(), expected.size_bytes - offset));
		const ssize_t count = ::pread(file.descriptor(), buffer.data(), request, static_cast<off_t>(offset));
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			return io_error("cannot read complete package file", count == 0 ? EIO : errno);
		}
		const auto size = static_cast<std::size_t>(count);
		hash.update(buffer.data(), size);
		const auto result = consume(buffer.data(), size);
		if (!result.is_ok()) {
			return result;
		}
		offset += static_cast<uint64_t>(count);
	}
	auto digest_or = hash.finalize_raw();
	if (!digest_or.is_ok()) {
		return digest_or.error();
	}
	struct stat metadata{};
	if (::fstat(file.descriptor(), &metadata) != 0) {
		return io_error("cannot recheck package file");
	}
	if (metadata.st_size < 0 || static_cast<uint64_t>(metadata.st_size) != expected.size_bytes ||
	    digest_or.value() != expected.sha256) {
		return status::data_loss(static_status_text("package file changed during its second read"));
	}
	return status::ok();
}

/**
 * @brief Compare two complete observed copy sets without recomputing expectations.
 * @param first First complete sorted observed copy set.
 * @param second Second complete sorted observed copy set.
 * @return True only for equal paths, sizes, digests, and modes.
 */
bool same_files(std::span<const payload_file> first, std::span<const payload_file> second) noexcept
{
	return first.size() == second.size() &&
	       std::equal(first.begin(), first.end(), second.begin(), [](const payload_file &a, const payload_file &b) {
		       return a.relative_path == b.relative_path && a.mode == b.mode &&
			      a.identity.sha256 == b.identity.sha256 && a.identity.size_bytes == b.identity.size_bytes;
	       });
}

/**
 * @brief Preserve libarchive's diagnostic; warnings are failures too.
 * @param codec Live libarchive object owning the diagnostic.
 * @param action Failed codec operation.
 * @return Owned DATA_LOSS diagnostic, copied before codec retirement.
 */
status codec_error(struct archive *codec, std::string_view action)
{
	const char *detail = archive_error_string(codec);
	return status(status_code::DATA_LOSS, std::string(action), detail == nullptr ? "no codec diagnostic" : detail);
}

/** @brief Retire the independent libelf cursor before its input descriptor. */
struct elf_deleter {
	/** @param value Live libelf state whose cursor ownership is being retired. */
	void operator()(Elf *value) const noexcept
	{
		(void)::elf_end(value);
	}
};

/** @brief Retire reader state after explicit success-close or failed admission. */
struct reader_deleter {
	/** @brief Release a reader while its caller-owned input cursor remains alive.
	 * @param value Reader whose storage is being retired.
	 */
	void operator()(struct archive *value) const noexcept
	{
		(void)archive_read_free(value);
	}
};
/** @brief Retire writer state after explicit success-close or a rejected private output. */
struct writer_deleter {
	/** @brief Close/free writer state while its output callback context remains alive.
	 * @param value Writer whose storage and pending output are being retired.
	 */
	void operator()(struct archive *value) const noexcept
	{
		(void)archive_write_free(value);
	}
};
/** @brief Retire one temporary archive header. */
struct entry_deleter {
	/** @brief Release the temporary owned header.
	 * @param value Header returned by archive_entry_new.
	 */
	void operator()(struct archive_entry *value) const noexcept
	{
		archive_entry_free(value);
	}
};
using archive_reader = std::unique_ptr<struct archive, reader_deleter>;	 ///< Owns one reader and its close/free.
using archive_writer =
	std::unique_ptr<struct archive, writer_deleter>;  ///< Owns one writer; callback context outlives it.

/** Retained input cursor; callbacks never change the caller's descriptor offset. */
struct archive_input {
	int descriptor;				    ///< Borrowed immutable descriptor.
	uint64_t size;				    ///< Exact accepted length.
	uint64_t offset{0};			    ///< Bytes returned to the codec.
	std::array<char, IO_BLOCK_BYTES> buffer{};  ///< Callback-owned stable storage.
};

/**
 * @brief Read a bounded block without allocating or throwing through the C ABI.
 * @param codec Live libarchive diagnostic owner.
 * @param context archive_input storage outliving the reader.
 * @param output Receives a buffer valid until the next callback.
 * @return Positive byte count, zero at exact EOF, or minus one on failure; never throws.
 */
la_ssize_t codec_read(struct archive *codec, void *context, const void **output) noexcept
{
	auto &input = *static_cast<archive_input *>(context);
	if (input.offset == input.size) {
		*output = nullptr;
		return 0;
	}
	const auto request =
		static_cast<std::size_t>(std::min<uint64_t>(input.buffer.size(), input.size - input.offset));
	ssize_t count;
	do {
		count = ::pread(input.descriptor, input.buffer.data(), request, static_cast<off_t>(input.offset));
	} while (count < 0 && errno == EINTR);
	if (count <= 0) {
		archive_set_error(codec, count == 0 ? EIO : errno, "package input ended before its accepted size");
		return -1;
	}
	input.offset += static_cast<uint64_t>(count);
	*output = input.buffer.data();
	return count;
}

/** Bounded private output cursor. */
struct archive_output {
	int descriptor;	   ///< Borrowed newly created file.
	uint64_t size{0};  ///< Exact compressed bytes written.
};

/**
 * @brief Enforce the compressed-output ceiling before every complete write.
 * @param codec Live libarchive diagnostic owner.
 * @param context archive_output storage outliving the writer and its close.
 * @param data Readable codec-owned bytes.
 * @param size Exact callback buffer extent.
 * @return Complete byte count or minus one; the output bound is checked before writes.
 */
la_ssize_t codec_write(struct archive *codec, void *context, const void *data, std::size_t size) noexcept
{
	auto &output = *static_cast<archive_output *>(context);
	if (size > MAX_PACKAGE_ARCHIVE_BYTES - output.size) {
		archive_set_error(codec, EFBIG, "compressed package exceeds its byte bound");
		return -1;
	}
	const auto *bytes = static_cast<const char *>(data);
	std::size_t offset = 0;
	while (offset < size) {
		const ssize_t count = ::write(output.descriptor, bytes + offset, size - offset);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			archive_set_error(codec, count == 0 ? EIO : errno, "cannot write compressed package");
			return -1;
		}
		offset += static_cast<std::size_t>(count);
	}
	output.size += size;
	return static_cast<la_ssize_t>(size);
}

/**
 * @brief Open the uncompressed TAR decoder with no automatic formats or filters.
 * @param input Borrowed read cursor that must outlive the returned codec.
 * @return Owned TAR reader with only uncompressed input admitted, or an explicit error.
 */
status_or<archive_reader> open_tar_reader(archive_input &input)
{
	archive_reader reader(archive_read_new());
	if (!reader) {
		return status::resource_exhausted(static_status_text("cannot allocate archive reader"));
	}
	if (archive_read_support_filter_none(reader.get()) != ARCHIVE_OK ||
	    archive_read_support_format_tar(reader.get()) != ARCHIVE_OK ||
	    archive_read_set_format_option(reader.get(), "tar", "mac-ext", nullptr) != ARCHIVE_OK ||
	    archive_read_set_format_option(reader.get(), "tar", "read_concatenated_archives", "1") != ARCHIVE_OK) {
		return codec_error(reader.get(), "cannot select the exact TAR decoder");
	}
	if (archive_read_open(reader.get(), &input, nullptr, codec_read, nullptr) != ARCHIVE_OK) {
		return codec_error(reader.get(), "cannot open package decoder");
	}
	return reader;
}

/**
 * @brief Finish a reader only after every input byte was consumed.
 * @param reader Live reader at semantic EOF.
 * @param size Exact physical input-byte count.
 * @return OK only after complete byte consumption and checked close.
 */
status finish_reader(struct archive *reader, uint64_t size)
{
	const auto consumed = archive_filter_bytes(reader, -1);
	if (consumed < 0 || static_cast<uint64_t>(consumed) != size) {
		return status::data_loss(static_status_text("archive has unconsumed or truncated input bytes"));
	}
	if (archive_read_close(reader) != ARCHIVE_OK) {
		return codec_error(reader, "cannot finish package read");
	}
	return status::ok();
}

/**
 * @brief Decode the complete gzip stream into a bounded unlinked TAR spool.
 * @param file Held immutable compressed input.
 * @param spool Borrowed writable unlinked output file.
 * @return Total decoded bytes only after the exact compressed buffers consumed by zlib
 *         reproduce the held input's digest and extent and every member validates.
 */
status_or<uint64_t> decode_gzip(const common::held_file &file, int spool)
{
	if (file.identity().size_bytes == 0 || file.identity().size_bytes > MAX_PACKAGE_ARCHIVE_BYTES) {
		return status::resource_exhausted(
			static_status_text("compressed archive is empty or exceeds its bound"));
	}
	z_stream stream{};
	// Gzip-only mode checks the optional header CRC, trailer CRC and length.
	// libarchive's gzip filter does not validate the trailer's CRC or length.
	const int initialized = ::inflateInit2(&stream, MAX_WBITS + 16);
	if (initialized != Z_OK) {
		return initialized == Z_MEM_ERROR ?
			       status::resource_exhausted(static_status_text("cannot allocate gzip decoder")) :
			       status::failed_precondition(static_status_text("native gzip decoder is unavailable"));
	}
	/** @brief Retire initialized zlib state on every failure or explicit completion. */
	struct inflater_owner {
		z_stream *value;  ///< Sole inflateEnd obligation, cleared after explicit completion.
		/** @brief Free unfinished decoder state without publishing its private spool. */
		~inflater_owner()
		{
			if (value != nullptr) {
				(void)::inflateEnd(value);
			}
		}
	} decoder{&stream};
	std::array<unsigned char, IO_BLOCK_BYTES> input{};
	std::array<unsigned char, IO_BLOCK_BYTES> output{};
	common::sha256_hasher compressed_hash;
	uint64_t offset = 0;
	uint64_t decoded = 0;
	for (;;) {
		if (stream.avail_in == 0 && offset < file.identity().size_bytes) {
			const auto request = static_cast<std::size_t>(
				std::min<uint64_t>(input.size(), file.identity().size_bytes - offset));
			ssize_t count;
			do {
				count = ::pread(file.descriptor(), input.data(), request, static_cast<off_t>(offset));
			} while (count < 0 && errno == EINTR);
			if (count <= 0) {
				return io_error("cannot read complete gzip input", count == 0 ? EIO : errno);
			}
			// Bind verification to these owned bytes before zlib consumes them.
			// A later reread could observe restored bytes after a transient mutation.
			compressed_hash.update(input.data(), static_cast<std::size_t>(count));
			offset += static_cast<uint64_t>(count);
			stream.next_in = input.data();
			stream.avail_in = static_cast<uInt>(count);
		}
		stream.next_out = output.data();
		stream.avail_out = static_cast<uInt>(output.size());
		const int result = ::inflate(&stream, Z_NO_FLUSH);
		if (result == Z_MEM_ERROR) {
			return status::resource_exhausted(static_status_text("gzip decoding exhausted memory"));
		}
		if (result != Z_OK && result != Z_STREAM_END) {
			return status::data_loss(static_status_text(
				"gzip header, payload, checksum or trailer is invalid or truncated"));
		}
		const std::size_t size = output.size() - stream.avail_out;
		if (size > MAX_PACKAGE_ARCHIVE_BYTES - decoded) {
			return status::resource_exhausted(
				static_status_text("decoded archive exceeds its contiguous byte bound"));
		}
		const auto written = write_all(spool, output.data(), size);
		if (!written.is_ok()) {
			return written;
		}
		decoded += size;
		if (result == Z_STREAM_END) {
			if (stream.avail_in == 0 && offset == file.identity().size_bytes) {
				break;
			}
			// RFC 1952 concatenation stays one gzip stream. Every member is
			// checked; trailing non-gzip bytes cannot become ignored input.
			if (::inflateReset(&stream) != Z_OK) {
				return status::internal_error(
					static_status_text("cannot reset gzip decoder between members"));
			}
		}
	}
	if (::inflateEnd(std::exchange(decoder.value, nullptr)) != Z_OK) {
		return status::internal_error(static_status_text("cannot retire completed gzip decoder"));
	}
	auto digest_or = compressed_hash.finalize_raw();
	if (!digest_or.is_ok()) {
		return digest_or.error();
	}
	struct stat metadata{};
	if (::fstat(file.descriptor(), &metadata) != 0) {
		return io_error("cannot recheck decoded archive input");
	}
	if (metadata.st_size < 0 || static_cast<uint64_t>(metadata.st_size) != file.identity().size_bytes ||
	    digest_or.value() != file.identity().sha256) {
		return status::data_loss(static_status_text("compressed archive changed during decoding"));
	}
	if (decoded == 0 || decoded % 512u != 0u) {
		return status::data_loss(static_status_text("decoded TAR is empty or has a partial block"));
	}
	return decoded;
}

/** Exact admitted TAR member; the hash is filled by the first full data pass. */
struct tar_member {
	std::string path;		 ///< Canonical full path, without a directory suffix.
	bool directory;			 ///< True for an explicit directory record.
	uint64_t size;			 ///< Bounded logical size.
	uint32_t mode;			 ///< Exact 0644/0755 file or 0755 directory mode.
	common::sha256_digest digest{};	 ///< Admitted regular-file content identity.
};

/**
 * @brief Validate every authority-bearing TAR field before consuming its data.
 * @param reader Live TAR-format decoder.
 * @param entry Borrowed current header.
 * @return Owned canonical header fields; all unsupported metadata and oversized claims reject.
 */
status_or<tar_member> admit_header(struct archive *reader, struct archive_entry *entry)
{
	const char *pathname = archive_entry_pathname(entry);
	if (pathname == nullptr) {
		return status::data_loss(static_status_text("archive member lacks a path"));
	}
	const std::size_t length = ::strnlen(pathname, MAX_PAYLOAD_PATH_BYTES + 2u);
	if (length > MAX_PAYLOAD_PATH_BYTES + 1u) {
		return status::resource_exhausted(static_status_text("archive member path exceeds its bound"));
	}
	const bool directory = archive_entry_filetype(entry) == AE_IFDIR;
	std::string path(pathname, length);
	if (directory && !path.empty() && path.back() == '/') {
		path.pop_back();
	}
	const auto valid = validate_payload_path(path);
	if (!valid.is_ok()) {
		return valid;
	}
	const int format = archive_format(reader);
	if (format != ARCHIVE_FORMAT_TAR_USTAR && format != ARCHIVE_FORMAT_TAR_PAX_INTERCHANGE &&
	    format != ARCHIVE_FORMAT_TAR_PAX_RESTRICTED) {
		return status::data_loss(static_status_text("package member is not POSIX TAR/PAX"));
	}
	const auto mode = static_cast<uint32_t>(archive_entry_perm(entry));
	const auto size = archive_entry_size(entry);
	const char *user = archive_entry_uname(entry);
	const char *group = archive_entry_gname(entry);
	unsigned long flags_set = 0, flags_clear = 0;
	archive_entry_fflags(entry, &flags_set, &flags_clear);
	if ((!directory && archive_entry_filetype(entry) != AE_IFREG) || archive_entry_hardlink(entry) != nullptr ||
	    archive_entry_symlink(entry) != nullptr || archive_entry_sparse_count(entry) != 0 ||
	    archive_entry_xattr_count(entry) != 0 ||
	    archive_entry_acl_count(entry, ARCHIVE_ENTRY_ACL_TYPE_POSIX1E | ARCHIVE_ENTRY_ACL_TYPE_NFS4) != 0 ||
	    flags_set != 0 || flags_clear != 0 || archive_entry_nlink(entry) > 1u || archive_entry_uid(entry) != 0 ||
	    archive_entry_gid(entry) != 0 || (user != nullptr && *user != '\0') ||
	    (group != nullptr && *group != '\0') || archive_entry_mtime(entry) != 0 ||
	    archive_entry_mtime_nsec(entry) != 0 || archive_entry_atime_is_set(entry) ||
	    archive_entry_ctime_is_set(entry) || archive_entry_birthtime_is_set(entry) ||
	    (directory ? mode != 0755u : (mode != 0644u && mode != 0755u)) || !archive_entry_size_is_set(entry) ||
	    size < 0 || (directory && size != 0)) {
		return status::data_loss(
			static_status_text("archive member has forbidden type or authority-bearing metadata"));
	}
	if (static_cast<uint64_t>(size) > MAX_PAYLOAD_FILE_BYTES) {
		return status::resource_exhausted(static_status_text("archive member exceeds its file-byte bound"));
	}
	return tar_member{std::move(path), directory, static_cast<uint64_t>(size), mode, {}};
}

/**
 * @brief Consume one contiguous file completely, optionally writing it after admission.
 * @param reader Live decoder positioned at the current member.
 * @param expected_size Admitted contiguous logical extent.
 * @param output Writable destination, or minus one for validation-only reading.
 * @return Digest of the exact complete member, or failure before acceptance.
 */
status_or<common::sha256_digest> read_member(struct archive *reader, uint64_t expected_size, int output)
{
	common::sha256_hasher hash;
	uint64_t consumed = 0;
	for (;;) {
		const void *data = nullptr;
		std::size_t size = 0;
		la_int64_t offset = 0;
		const int result = archive_read_data_block(reader, &data, &size, &offset);
		if (result == ARCHIVE_EOF) {
			break;
		}
		if (result != ARCHIVE_OK) {
			return codec_error(reader, "cannot read complete TAR member");
		}
		if (size == 0 || offset < 0 || static_cast<uint64_t>(offset) != consumed ||
		    size > expected_size - consumed) {
			return status::data_loss(static_status_text("TAR member has noncontiguous or oversized data"));
		}
		hash.update(data, size);
		if (output >= 0) {
			const auto written = write_all(output, data, size);
			if (!written.is_ok()) {
				return written;
			}
		}
		consumed += size;
	}
	if (consumed != expected_size) {
		return status::data_loss(static_status_text("TAR member is truncated"));
	}
	return hash.finalize_raw();
}

/**
 * @brief Admit the complete sorted tree, including every parent and no empty branches.
 * @param spool Borrowed immutable unlinked TAR input.
 * @param size Exact decoded extent.
 * @param root Required canonical top-level directory.
 * @return Complete bounded member identities after ordered parent and nonempty-tree admission.
 */
status_or<std::vector<tar_member>> admit_tar(int spool, uint64_t size, std::string_view root)
{
	archive_input input{spool, size};
	auto reader_or = open_tar_reader(input);
	if (!reader_or.is_ok()) {
		return reader_or.error();
	}
	auto &reader = reader_or.value();
	std::vector<tar_member> members;
	std::set<std::string> directories;
	std::set<std::string> empty_directories;
	uint64_t payload_size = 0;
	for (;;) {
		struct archive_entry *entry = nullptr;
		const int result = archive_read_next_header(reader.get(), &entry);
		if (result == ARCHIVE_EOF) {
			break;
		}
		if (result != ARCHIVE_OK) {
			return codec_error(reader.get(), "cannot admit TAR header");
		}
		if (members.size() == MAX_PAYLOAD_ENTRIES) {
			return status::resource_exhausted(static_status_text("archive exceeds its member-count bound"));
		}
		auto member_or = admit_header(reader.get(), entry);
		if (!member_or.is_ok()) {
			return member_or.error();
		}
		auto member = std::move(member_or).value();
		if (members.empty() ? (!member.directory || member.path != root) :
				      (members.back().path >= member.path ||
				       !std::string_view(member.path).starts_with(std::string(root) + "/"))) {
			return status::data_loss(static_status_text(
				"archive lacks its exact root or strictly ordered unique membership"));
		}
		if (member.size > MAX_PAYLOAD_BYTES - payload_size) {
			return status::resource_exhausted(
				static_status_text("archive exceeds its aggregate payload-byte bound"));
		}
		payload_size += member.size;
		if (!members.empty()) {
			const std::string parent = member.path.substr(0, member.path.rfind('/'));
			if (!directories.contains(parent)) {
				return status::data_loss(
					static_status_text("archive member lacks its declared parent directory"));
			}
			empty_directories.erase(parent);
		}
		if (member.directory) {
			directories.insert(member.path);
			empty_directories.insert(member.path);
		}
		auto digest_or = read_member(reader.get(), member.size, -1);
		if (!digest_or.is_ok()) {
			return digest_or.error();
		}
		member.digest = digest_or.value();
		members.push_back(std::move(member));
	}
	if (members.empty() || !empty_directories.empty()) {
		return status::data_loss(static_status_text("archive directory membership is incomplete or unbound"));
	}
	const auto finished = finish_reader(reader.get(), size);
	if (!finished.is_ok()) {
		return finished;
	}
	return members;
}

/**
 * @brief Extract the already-admitted spool using only held directory descriptors.
 * @param spool Borrowed immutable TAR input.
 * @param size Exact decoded extent.
 * @param destination Held empty private destination.
 * @param members Complete prior admission, retained by the caller.
 * @return OK after every exact-mode file is hashed, synced and closed; caller owns failed-tree cleanup.
 */
status extract_tar(int spool, uint64_t size, int destination, const std::vector<tar_member> &members)
{
	archive_input input{spool, size};
	auto reader_or = open_tar_reader(input);
	if (!reader_or.is_ok()) {
		return reader_or.error();
	}
	auto &reader = reader_or.value();
	for (const auto &expected : members) {
		struct archive_entry *entry = nullptr;
		if (archive_read_next_header(reader.get(), &entry) != ARCHIVE_OK) {
			return codec_error(reader.get(), "admitted TAR changed before extraction");
		}
		auto observed_or = admit_header(reader.get(), entry);
		if (!observed_or.is_ok()) {
			return observed_or.error();
		}
		const auto &observed = observed_or.value();
		if (observed.path != expected.path || observed.directory != expected.directory ||
		    observed.size != expected.size || observed.mode != expected.mode) {
			return status::data_loss(
				static_status_text("TAR header changed between admission and extraction"));
		}
		if (expected.directory) {
			continue;
		}
		auto parent_or = destination_parent(destination, expected.path);
		if (!parent_or.is_ok()) {
			return parent_or.error();
		}
		const std::string name = fs::path(expected.path).filename().string();
		const int raw = ::openat(parent_or->get(), name.c_str(),
					 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
		if (raw < 0) {
			return io_error("cannot create extracted package file");
		}
		descriptor output(raw);
		auto digest_or = read_member(reader.get(), expected.size, output.get());
		if (!digest_or.is_ok()) {
			return digest_or.error();
		}
		if (digest_or.value() != expected.digest) {
			return status::data_loss(
				static_status_text("TAR file changed between admission and extraction"));
		}
		if (::fchmod(output.get(), static_cast<mode_t>(expected.mode)) != 0 || ::fsync(output.get()) != 0) {
			return io_error("cannot finalize extracted package file");
		}
		const auto closed = output.close();
		if (!closed.is_ok()) {
			return closed;
		}
		if (::fsync(parent_or->get()) != 0) {
			return io_error("cannot sync extracted file's parent");
		}
	}
	struct archive_entry *extra = nullptr;
	if (archive_read_next_header(reader.get(), &extra) != ARCHIVE_EOF) {
		return codec_error(reader.get(), "unexpected member after admitted TAR tree");
	}
	return finish_reader(reader.get(), size);
}

/** @brief Abort with a bounded diagnostic when publication durability is unknowable. */
[[noreturn]] void publication_failed() noexcept
{
	(void)common::emit_process_output({{}, "kinetum_package: published file durability is unresolved\n", 1});
	std::abort();
}

}  // namespace

status_or<std::vector<payload_file>> read_package_tree(const std::filesystem::path &root,
						       const common::held_file_policy &policy)
{
	auto files_or = read_payload_tree(root, policy);
	if (!files_or.is_ok()) {
		return files_or.error();
	}
	for (const auto &file : files_or.value()) {
		if (file.mode != 0644u && file.mode != 0755u) {
			return status::permission_denied(
				static_status_text("package files must have exact mode 0644 or 0755"));
		}
	}
	return std::move(files_or).value();
}

status write_package_archive(const std::filesystem::path &root, std::span<const payload_file> files, int output,
			     const common::held_file_policy &policy)
{
	if (files.empty() || files.size() >= MAX_PAYLOAD_ENTRIES) {
		return status::resource_exhausted(static_status_text("archive copy set is empty or over bound"));
	}
	const std::string root_name = root.filename().string();
	const auto root_valid = validate_payload_path(root_name);
	if (!root_valid.is_ok()) {
		return root_valid;
	}
	struct stat metadata{};
	if (::fstat(output, &metadata) != 0) {
		return io_error("cannot inspect archive output");
	}
	if (!S_ISREG(metadata.st_mode) || metadata.st_size != 0 || metadata.st_nlink != 1 ||
	    metadata.st_uid != ::geteuid() || (metadata.st_mode & 07777) != 0600) {
		return status::failed_precondition(static_status_text("archive output is not one empty private file"));
	}
	// The writer may flush through its callback during error cleanup, so the
	// callback state must outlive the writer on every return and exception.
	archive_output sink{output};
	archive_writer writer(archive_write_new());
	if (!writer) {
		return status::resource_exhausted(static_status_text("cannot allocate archive writer"));
	}
	// ARCHIVE_WARN from the gzip selector means an external-program fallback.
	// Only native gzip is admitted; even that warning is a terminal failure.
	if (archive_write_set_format_pax_restricted(writer.get()) != ARCHIVE_OK ||
	    archive_write_add_filter_gzip(writer.get()) != ARCHIVE_OK ||
	    archive_write_set_filter_option(writer.get(), "gzip", "compression-level", "9") != ARCHIVE_OK ||
	    archive_write_set_filter_option(writer.get(), "gzip", "timestamp", nullptr) != ARCHIVE_OK ||
	    archive_write_set_bytes_per_block(writer.get(), 512) != ARCHIVE_OK ||
	    archive_write_set_bytes_in_last_block(writer.get(), 1) != ARCHIVE_OK) {
		return codec_error(writer.get(), "cannot select deterministic native gzip/PAX output");
	}
	if (archive_write_open(writer.get(), &sink, nullptr, codec_write, nullptr) != ARCHIVE_OK) {
		return codec_error(writer.get(), "cannot open archive output");
	}
	std::map<std::string, const payload_file *> entries;
	entries.emplace(root_name, nullptr);
	for (const auto &file : files) {
		const std::string name = root_name + "/" + file.relative_path;
		const auto position = entries.lower_bound(name);
		if (!validate_payload_path(name).is_ok() || (position != entries.end() && position->first == name)) {
			return status::invalid_argument(
				static_status_text("archive copy set has an unsafe or duplicate path"));
		}
		if (entries.size() == MAX_PAYLOAD_ENTRIES) {
			return status::resource_exhausted(
				static_status_text("archive copy set exceeds its entry bound"));
		}
		entries.emplace_hint(position, name, &file);
		std::string_view prefix(name);
		for (std::size_t separator = prefix.rfind('/'); separator != std::string_view::npos;
		     separator = prefix.rfind('/')) {
			prefix = prefix.substr(0, separator);
			std::string parent(prefix);
			const auto found = entries.lower_bound(parent);
			if (found != entries.end() && found->first == parent) {
				if (found->second != nullptr) {
					return status::invalid_argument(
						static_status_text("archive file overlaps a parent directory"));
				}
				break;
			}
			if (entries.size() == MAX_PAYLOAD_ENTRIES) {
				return status::resource_exhausted(
					static_status_text("archive copy set exceeds its entry bound"));
			}
			entries.emplace_hint(found, std::move(parent), nullptr);
		}
	}
	for (const auto &[name, file] : entries) {
		std::unique_ptr<struct archive_entry, entry_deleter> entry(archive_entry_new());
		if (!entry) {
			return status::resource_exhausted(static_status_text("cannot allocate archive header"));
		}
		archive_entry_set_pathname(entry.get(), name.c_str());
		archive_entry_set_filetype(entry.get(), file == nullptr ? AE_IFDIR : AE_IFREG);
		archive_entry_set_perm(entry.get(), static_cast<mode_t>(file == nullptr ? 0755u : file->mode));
		archive_entry_set_uid(entry.get(), 0);
		archive_entry_set_gid(entry.get(), 0);
		archive_entry_set_uname(entry.get(), "");
		archive_entry_set_gname(entry.get(), "");
		archive_entry_set_mtime(entry.get(), 0, 0);
		archive_entry_set_size(entry.get(),
				       file == nullptr ? 0 : static_cast<la_int64_t>(file->identity.size_bytes));
		if (archive_write_header(writer.get(), entry.get()) != ARCHIVE_OK) {
			return codec_error(writer.get(), "cannot write package header");
		}
		if (file != nullptr) {
			auto held_or = common::open_held_regular_file(root / file->relative_path, policy);
			if (!held_or.is_ok()) {
				return held_or.error();
			}
			const auto copied = stream_file(
				held_or.value(), file->identity, [&writer](const void *data, std::size_t size) {
					const auto count = archive_write_data(writer.get(), data, size);
					return count >= 0 && static_cast<std::size_t>(count) == size ?
						       status::ok() :
						       codec_error(writer.get(),
								   "cannot write complete package member");
				});
			if (!copied.is_ok()) {
				return copied;
			}
		}
		if (archive_write_finish_entry(writer.get()) != ARCHIVE_OK) {
			return codec_error(writer.get(), "cannot finish package member");
		}
	}
	if (archive_write_close(writer.get()) != ARCHIVE_OK) {
		return codec_error(writer.get(), "cannot finish package archive");
	}
	const int freed = archive_write_free(writer.release());
	if (freed != ARCHIVE_OK) {
		return status::data_loss(static_status_text("cannot retire completed archive writer"));
	}
	auto after_or = read_package_tree(root, policy);
	if (!after_or.is_ok()) {
		return after_or.error();
	}
	if (!same_files(files, after_or.value())) {
		return status::data_loss(static_status_text("archive source changed while writing"));
	}
	if (::fchmod(output, 0644) != 0 || ::fsync(output) != 0) {
		return io_error("cannot sync completed archive");
	}
	return status::ok();
}

status extract_package_archive(const common::held_file &file, const std::filesystem::path &destination,
			       std::string_view expected_root)
{
	const auto valid = validate_payload_path(expected_root);
	if (!valid.is_ok() || expected_root.find('/') != std::string_view::npos) {
		return status::invalid_argument(static_status_text("archive root must be one canonical component"));
	}
	auto root_or = open_directory(destination);
	if (!root_or.is_ok()) {
		return root_or.error();
	}
	const auto private_root = require_empty_private_directory(root_or->get());
	if (!private_root.is_ok()) {
		return private_root;
	}
	const int raw = ::openat(root_or->get(), ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
	if (raw < 0) {
		return io_error("cannot create an unlinked private archive spool");
	}
	descriptor spool(raw);
	auto size_or = decode_gzip(file, spool.get());
	if (!size_or.is_ok()) {
		return size_or.error();
	}
	auto members_or = admit_tar(spool.get(), size_or.value(), expected_root);
	if (!members_or.is_ok()) {
		return members_or.error();
	}
	return extract_tar(spool.get(), size_or.value(), root_or->get(), members_or.value());
}

status verify_package_elf(const common::held_file &file, provider::provider_target_tuple target,
			  std::string_view version)
{
	const auto target_status = provider::inspect_provider_runtime_elf(file, target);
	if (!target_status.is_ok()) {
		return target_status;
	}
	const std::string descriptor_path = file.proc_descriptor_path();
	const int raw = ::open(descriptor_path.c_str(), O_RDONLY | O_CLOEXEC);
	if (raw < 0) {
		return io_error("cannot retain versioned ELF descriptor");
	}
	descriptor input(raw);
	std::unique_ptr<Elf, elf_deleter> elf(::elf_begin(input.get(), ELF_C_READ, nullptr));
	if (!elf) {
		return status::data_loss(static_status_text("cannot inspect package ELF symbols"));
	}
	const std::string expected = "KINETUM_RELEASE_VERSION=" + std::string(version) + '\0';
	std::size_t matches = 0;
	Elf_Scn *section = nullptr;
	while ((section = ::elf_nextscn(elf.get(), section)) != nullptr) {
		GElf_Shdr header{};
		if (::gelf_getshdr(section, &header) == nullptr) {
			return status::data_loss(static_status_text("invalid ELF section"));
		}
		if (header.sh_type != SHT_SYMTAB) {
			continue;
		}
		Elf_Data *data = ::elf_getdata(section, nullptr);
		if (data == nullptr || header.sh_entsize == 0 || data->d_size % header.sh_entsize != 0 ||
		    data->d_size / header.sh_entsize > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
			return status::data_loss(static_status_text("invalid ELF symbol table"));
		}
		const auto count = data->d_size / header.sh_entsize;
		for (std::size_t index = 0; index < count; ++index) {
			GElf_Sym symbol{};
			if (::gelf_getsym(data, static_cast<int>(index), &symbol) == nullptr) {
				return status::data_loss(static_status_text("invalid ELF symbol"));
			}
			const char *name = ::elf_strptr(elf.get(), header.sh_link, symbol.st_name);
			if (name == nullptr) {
				return status::data_loss(static_status_text("invalid ELF symbol name"));
			}
			if (std::strcmp(name, "kinetum_release_version_marker") != 0) {
				continue;
			}
			++matches;
			Elf_Scn *storage = ::elf_getscn(elf.get(), symbol.st_shndx);
			GElf_Shdr storage_header{};
			if (storage == nullptr || ::gelf_getshdr(storage, &storage_header) == nullptr ||
			    storage_header.sh_type != SHT_PROGBITS || GELF_ST_TYPE(symbol.st_info) != STT_OBJECT ||
			    (GELF_ST_BIND(symbol.st_info) != STB_LOCAL &&
			     GELF_ST_VISIBILITY(symbol.st_other) != STV_HIDDEN) ||
			    symbol.st_value < storage_header.sh_addr || symbol.st_size != expected.size()) {
				return status::data_loss(static_status_text("invalid compiled version-marker storage"));
			}
			const uint64_t offset = symbol.st_value - storage_header.sh_addr;
			Elf_Data *bytes = ::elf_getdata(storage, nullptr);
			if (bytes == nullptr || bytes->d_buf == nullptr || offset > bytes->d_size ||
			    expected.size() > bytes->d_size - offset ||
			    std::memcmp(static_cast<const char *>(bytes->d_buf) + offset, expected.data(),
					expected.size()) != 0) {
				return status::data_loss(
					static_status_text("ELF compiled version disagrees with package VERSION"));
			}
		}
	}
	return matches == 1u ? status::ok() :
			       status::data_loss(static_status_text("ELF lacks one exact compiled version marker"));
}

status publish_package_file(const std::filesystem::path &candidate, const std::filesystem::path &output,
			    const common::held_file_identity &identity)
{
	common::held_file_policy policy;
	policy.required_owner_uid = static_cast<uint32_t>(::geteuid());
	policy.forbidden_mode_bits = 0022u;
	policy.maximum_size_bytes = MAX_PACKAGE_ARCHIVE_BYTES;
	auto source_or = common::open_held_regular_file(candidate, policy);
	if (!source_or.is_ok()) {
		return source_or.error();
	}
	const auto exact = common::verify_held_file_identity(source_or.value(), identity.sha256, identity.size_bytes);
	if (!exact.is_ok()) {
		return exact;
	}
	auto source_parent_or = open_directory(candidate.parent_path());
	if (!source_parent_or.is_ok()) {
		return source_parent_or.error();
	}
	auto output_parent_or = open_directory(output.parent_path());
	if (!output_parent_or.is_ok()) {
		return output_parent_or.error();
	}
	struct stat held{};
	struct stat named{};
	if (::fstat(source_or->descriptor(), &held) != 0 ||
	    ::fstatat(source_parent_or->get(), candidate.filename().c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
		return io_error("cannot bind package-file publication to its held candidate");
	}
	if (held.st_dev != named.st_dev || held.st_ino != named.st_ino || !S_ISREG(named.st_mode) ||
	    named.st_nlink != 1 || named.st_uid != ::geteuid() || (named.st_mode & 07777) != 0644) {
		return status::data_loss(
			static_status_text("package-file candidate namespace identity changed before publication"));
	}
	if (::syscall(SYS_renameat2, source_parent_or->get(), candidate.filename().c_str(), output_parent_or->get(),
		      output.filename().c_str(), RENAME_NOREPLACE) == 0) {
		if (::fsync(output_parent_or->get()) != 0 || ::fsync(source_parent_or->get()) != 0) {
			publication_failed();
		}
		return status::ok();
	}
	if (errno != EEXIST) {
		return io_error("cannot publish package without replacement");
	}
	auto winner_or = common::open_held_regular_file(output, policy);
	if (!winner_or.is_ok()) {
		return winner_or.error();
	}
	struct stat winner_metadata{};
	if (::fstat(winner_or->descriptor(), &winner_metadata) != 0) {
		return io_error("cannot inspect existing package-file mode");
	}
	if ((winner_metadata.st_mode & 07777) != 0644) {
		return status::already_exists(static_status_text("existing package output has a foreign file mode"));
	}
	if (winner_or->identity().size_bytes != identity.size_bytes ||
	    winner_or->identity().sha256 != identity.sha256) {
		return status::already_exists(static_status_text("existing package output contains different bytes"));
	}
	if (::unlinkat(source_parent_or->get(), candidate.filename().c_str(), 0) != 0 ||
	    ::fsync(source_parent_or->get()) != 0) {
		return io_error("cannot retire private candidate after exact-winner convergence");
	}
	return status::ok();
}

}  // namespace kinetum::release
