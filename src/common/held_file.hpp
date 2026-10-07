// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file held_file.hpp
 * @brief Symlink-free held-descriptor artifact admission.
 * @author Fleming Patel
 *
 * Provider artifact verification and dynamic loading must name the same inode.
 * This primitive opens every absolute path component with openat/O_NOFOLLOW,
 * validates the caller's trusted directory subtree plus one regular file,
 * hashes the file through pread on that descriptor, and retains the descriptor
 * for subsequent ELF inspection and `/proc/self/fd/N` loading.
 *
 * It does not decide whether a path is required or trusted provenance. The
 * caller supplies an already-established exact path and ownership policy.
 *
 * @par Thread Safety
 * A held_file is a unique movable owner. Distinct instances may be inspected
 * concurrently. The artifact must remain immutable under its admitted
 * filesystem ownership policy for the held lifetime.
 *
 * @par Performance
 * Path traversal, metadata checks, and hashing are cold-path operations.
 */

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

#include "src/common/sha256_digest.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/** Exact observed identity of one held regular file. */
struct held_file_identity {
	sha256_digest sha256{};	 ///< SHA-256 read through the retained descriptor.
	uint64_t size_bytes{0};	 ///< Bytes read through the same descriptor.
};

/** Filesystem authority required from one trusted directory subtree. */
struct held_directory_policy {
	std::filesystem::path root;	  ///< Exact absolute root at which checks begin.
	uint32_t required_owner_uid{0};	  ///< Exact owner for root and descendants.
	uint32_t forbidden_mode_bits{0};  ///< POSIX mode bits absent from every directory.
};

/** Filesystem authority required for one admitted artifact. */
struct held_file_policy {
	/** Exact owning UID, or no owner constraint when explicitly absent. */
	std::optional<uint32_t> required_owner_uid{0u};
	uint32_t forbidden_mode_bits{0};  ///< POSIX mode bits that must be absent.
	bool require_single_link{true};	  ///< Require one filesystem name for the inode.
	/** Optional authority for the exact directory subtree containing the file. */
	std::optional<held_directory_policy> directories;
	/** Optional inclusive file-size ceiling enforced before content hashing. */
	std::optional<uint64_t> maximum_size_bytes;
};

/**
 * @brief Unique owner of one verified regular-file descriptor.
 */
class held_file {
    public:
	/** @brief Construct an empty non-owning value. */
	held_file() noexcept = default;

	/** @brief Close the owned descriptor. */
	~held_file();

	/** @brief Disable descriptor aliasing. */
	held_file(const held_file &) = delete;

	/** @brief Disable descriptor aliasing by assignment. */
	held_file &operator=(const held_file &) = delete;

	/**
	 * @brief Transfer one held descriptor and its observed identity.
	 *
	 * @param other Source owner left empty.
	 */
	held_file(held_file &&other) noexcept;

	/**
	 * @brief Replace this owner with another held descriptor.
	 *
	 * @param other Source owner left empty.
	 * @return This owner after transfer.
	 */
	held_file &operator=(held_file &&other) noexcept;

	/** @return true while this value owns a descriptor. */
	[[nodiscard]] bool valid() const noexcept;

	/** @return Borrowed retained descriptor, or -1 when this owner is empty. */
	[[nodiscard]] int descriptor() const noexcept;

	/** @return Borrowed admitted absolute path representation. */
	[[nodiscard]] const std::filesystem::path &path() const noexcept;

	/** @return Borrowed hash and size observed through the retained descriptor. */
	[[nodiscard]] const held_file_identity &identity() const noexcept;

	/**
	 * @brief Return the Linux descriptor path used for exact dynamic loading.
	 *
	 * @return `/proc/self/fd/N` for a valid owner, otherwise an empty string.
	 */
	[[nodiscard]] std::string proc_descriptor_path() const;

    private:
	friend status_or<held_file> open_held_regular_file(const std::filesystem::path &, const held_file_policy &);

	/**
	 * @brief Adopt one fully admitted descriptor.
	 *
	 * @param descriptor Open descriptor owned by this object after construction.
	 * @param path Exact absolute path used for admission.
	 * @param identity Hash and size observed through descriptor.
	 */
	held_file(int descriptor, std::filesystem::path path, held_file_identity identity) noexcept;

	int descriptor_{-1};		 ///< Unique retained descriptor.
	std::filesystem::path path_;	 ///< Exact admitted absolute representation.
	held_file_identity identity_{};	 ///< Same-descriptor content identity.
};

/**
 * @brief Open, validate, hash, and retain one exact regular file.
 *
 * Every path component must be absolute, NUL-free, lexically normalized, and
 * not a symbolic link. When a directory policy is present, its root must be an
 * ancestor of the file and every traversed directory at or below that root
 * must have the required owner and omit the forbidden mode bits. The final
 * file must be regular, obey its optional owner and forbidden-mode-bit policy,
 * and have one link when required. An optional size ceiling is checked from
 * held descriptor metadata before content hashing. The final component is
 * opened nonblocking so a named pipe or other nonregular object cannot stall
 * admission. File metadata is sampled before and after hashing; mutation
 * rejects.
 *
 * @param path Exact absolute artifact path.
 * @param policy Exact owner, forbidden-mode, link-count, directory, and size
 *        policy.
 * @return Unique held descriptor plus observed identity, or the first
 *         fail-closed path, metadata, or read error.
 */
[[nodiscard]] status_or<held_file> open_held_regular_file(const std::filesystem::path &path,
							  const held_file_policy &policy);

/**
 * @brief Verify one held file against an authoritative identity claim.
 *
 * @param file Held file whose same-descriptor observation is compared.
 * @param expected_sha256 Exact expected digest.
 * @param expected_size_bytes Exact expected size.
 * @return OK only when both claims match.
 */
[[nodiscard]] status verify_held_file_identity(const held_file &file, const sha256_digest &expected_sha256,
					       uint64_t expected_size_bytes);

/**
 * @brief Read and reverify exact bytes from one held file without changing its offset.
 *
 * @param file Held file to read.
 * @param maximum_size_bytes Caller-owned preallocation bound.
 * @return Exact bytes reproducing the admitted size and SHA-256 identity, or
 *         RESOURCE_EXHAUSTED, DATA_LOSS, or a descriptor-read failure.
 */
[[nodiscard]] status_or<std::string> read_held_file(const held_file &file, uint64_t maximum_size_bytes);

}  // namespace kinetum::common
