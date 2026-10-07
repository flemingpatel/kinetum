// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file durable_directory.hpp
 * @brief Descriptor-rooted durable file publication authority.
 * @author Fleming Patel
 *
 * This cold-path primitive admits one exact absolute directory without
 * following symbolic links, retains its descriptor, and makes every later
 * file operation relative to that descriptor. It is the persistence analogue
 * of held_file: pathname resolution establishes authority once, while bounded
 * reads and durable create, replace, remove, and enumeration operations never
 * re-resolve the directory through the process working directory.
 *
 * A fresh terminal directory may be created beneath an exact existing parent.
 * The terminal directory is owned by the current effective UID and may not be
 * group- or world-writable. Files owned by this authority are regular,
 * single-linked, current-UID-owned, and mode 0600. Opening an existing
 * directory durably discards exact private publication temporaries left by an
 * interrupted prior owner before ordinary state enumeration can observe them.
 *
 * @par Thread Safety
 * One durable_directory is a unique movable owner. Its operations require
 * external serialization because durable replacement uses an owner-local
 * temporary-name sequence. The Control Plane config store supplies one shared
 * synchronization domain for all readers and writers. Exactly one process may
 * own a durable root; concurrent open or mutation by another process is outside
 * this primitive's contract.
 *
 * @par Performance
 * Directory traversal, descriptor I/O, fsync, and enumeration are cold-path
 * persistence operations. They must not execute on packet workers.
 */

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Unique descriptor authority for one durable directory.
 */
class durable_directory {
    public:
	/** @brief Construct an empty non-owning value. */
	durable_directory() noexcept = default;

	/** @brief Close the retained directory descriptor. */
	~durable_directory();

	/** @brief Disable directory-authority aliasing. */
	durable_directory(const durable_directory &) = delete;

	/** @brief Disable directory-authority aliasing by assignment. */
	durable_directory &operator=(const durable_directory &) = delete;

	/**
	 * @brief Transfer one retained directory authority.
	 *
	 * @param other Source owner left empty.
	 */
	durable_directory(durable_directory &&other) noexcept;

	/**
	 * @brief Replace this owner with another retained directory authority.
	 *
	 * @param other Source owner left empty.
	 * @return This owner after transfer.
	 */
	durable_directory &operator=(durable_directory &&other) noexcept;

	/**
	 * @brief Admit or create one exact durable terminal directory.
	 *
	 * Every existing component is opened with openat/O_NOFOLLOW. Only the
	 * terminal component may be absent; when absent it is created with mode
	 * 0700 beneath its exact existing parent and the parent descriptor is
	 * fsynced before success. The admitted terminal must belong to the current
	 * effective UID and omit group/world write bits. Under the one-process-owner
	 * precondition, exact `.kinetum.tmp.<pid>.<sequence>` files abandoned by a
	 * stopped prior owner are metadata-validated, unlinked through the retained
	 * descriptor, and made durably absent before this call returns. The private
	 * prefix is reserved and cannot name a caller-owned durable file.
	 *
	 * @param path Exact absolute, lexically normalized, non-root directory.
	 * @return Retained authority, or the first path, ownership, permission,
	 *         recovery, creation, or durability error.
	 */
	[[nodiscard]] static status_or<durable_directory> open(const std::filesystem::path &path);

	/** @return true while this value owns a directory descriptor. */
	[[nodiscard]] bool valid() const noexcept;

	/** @return Borrowed admitted path for diagnostics; the held descriptor remains the I/O authority. */
	[[nodiscard]] const std::filesystem::path &path() const noexcept;

	/**
	 * @brief Enumerate every admitted regular file by exact leaf name.
	 *
	 * Entries are returned in bytewise lexical order. A symbolic link,
	 * directory, nonregular file, wrong owner, wrong mode, or multiply linked
	 * entry fails the complete enumeration instead of disappearing. Final
	 * entries are opened nonblocking so a named pipe cannot stall admission.
	 *
	 * @return Sorted leaf names, or the first descriptor/metadata error.
	 */
	[[nodiscard]] status_or<std::vector<std::string>> list_files() const;

	/**
	 * @brief Read one exact regular file through the retained directory.
	 *
	 * The file is opened with openat/O_NOFOLLOW/O_NONBLOCK, validated before and
	 * after pread, and bounded before allocation. Nonregular named objects reject
	 * without blocking, and metadata mutation during the read rejects.
	 *
	 * @param leaf Exact safe single-component file name.
	 * @param maximum_size_bytes Maximum bytes the caller permits.
	 * @return Exact file bytes, or the first naming, metadata, bound, or I/O
	 *         error.
	 */
	[[nodiscard]] status_or<std::string> read_file(std::string_view leaf, uint64_t maximum_size_bytes) const;

	/**
	 * @brief Publish one new durable file without replacing an existing name.
	 *
	 * Complete bytes are written and fsynced under a unique private temporary
	 * name, then published with one Linux rename-without-replacement operation.
	 * The target name therefore never exposes partial content. A failure before
	 * publication removes the temporary file before returning. A directory
	 * fsync failure after the namespace change is process-fatal because durable
	 * commit state can no longer be reported or rolled back truthfully.
	 *
	 * @param leaf Exact safe single-component file name.
	 * @param bytes Complete file contents.
	 * @return OK only after file and directory durability; ALREADY_EXISTS when
	 *         the name already exists.
	 */
	[[nodiscard]] status publish_new_file(std::string_view leaf, std::string_view bytes);

	/**
	 * @brief Durably replace or create one file through a same-directory rename.
	 *
	 * Any existing target must already satisfy this authority's exact regular
	 * file contract. Complete bytes are written and fsynced under a unique
	 * private temporary name, renamed with renameat, then made durable by
	 * fsyncing the retained directory. A directory fsync failure after rename is
	 * process-fatal because the old/new durable commit state is then uncertain.
	 *
	 * @param leaf Exact safe single-component target name.
	 * @param bytes Complete replacement contents.
	 * @return OK after durable replacement, or the first target, temporary-file,
	 *         write, rename, or fsync error.
	 */
	[[nodiscard]] status replace_file(std::string_view leaf, std::string_view bytes);

	/**
	 * @brief Durably remove one exact file when present.
	 *
	 * A present target is fully admitted before unlinkat. Absence is idempotent.
	 * The retained directory is fsynced after a successful removal. A directory
	 * fsync failure after unlink is process-fatal because removal has crossed
	 * its irreversible namespace boundary.
	 *
	 * @param leaf Exact safe single-component file name.
	 * @return OK for absence or durable removal, otherwise the first admission,
	 *         unlink, or fsync error.
	 */
	[[nodiscard]] status remove_file(std::string_view leaf);

    private:
	/** Publication collision policy for one complete private file. */
	enum class publication_mode : uint8_t {
		CREATE_ONLY,	    ///< Reject an existing target without replacing it.
		REPLACE_OR_CREATE,  ///< Atomically replace an admitted target or create it.
	};

	/**
	 * @brief Adopt one fully admitted terminal directory descriptor.
	 * @param descriptor Sole admitted directory descriptor transferred into this owner.
	 * @param path Admitted path retained for diagnostics.
	 */
	durable_directory(int descriptor, std::filesystem::path path) noexcept;

	/** @return Next nonzero owner-local temporary-name sequence, or an exhaustion status. */
	[[nodiscard]] status_or<uint64_t> next_temporary_sequence() noexcept;

	/**
	 * @brief Publish complete bytes through one private same-directory file.
	 *
	 * @param leaf Validated target leaf.
	 * @param bytes Complete target bytes.
	 * @param mode Exact target collision policy.
	 * @return OK only after durable publication, otherwise a pre-publication
	 *         failure. A post-publication directory-sync failure terminates.
	 */
	[[nodiscard]] status publish_file_(std::string_view leaf, std::string_view bytes, publication_mode mode);

	int descriptor_{-1};		  ///< Unique retained directory descriptor.
	std::filesystem::path path_;	  ///< Admitted path retained for diagnostics.
	uint64_t temporary_sequence_{0};  ///< Externally serialized replacement nonce.
};

}  // namespace kinetum::common
