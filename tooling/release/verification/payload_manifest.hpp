// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file payload_manifest.hpp
 * @brief Canonical payload-manifest generation and verification.
 * @author Fleming Patel
 *
 * One implementation owns the sorted lowercase-SHA256, two-space, relative-
 * path, newline grammar. Generation derives membership from a CMake-staged
 * tree. Installation reads that complete manifest; an independent verifier
 * may additionally require its own expected set. Neither operation
 * authenticates product or provider semantics.
 *
 * @par Thread Safety
 * Distinct payload roots may be verified concurrently. A payload root must not
 * be mutated during verification.
 *
 * @par Performance
 * Verification first retains and parses the manifest, then traverses the
 * payload tree twice and streams every declared file. It is intended only for
 * installation and release checks.
 */

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "src/common/held_file.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::release
{

/** Inclusive bound on all file and directory entries in one payload. */
inline constexpr std::size_t MAX_PAYLOAD_ENTRIES = 16'384;
/** Inclusive bound on a portable relative payload path. */
inline constexpr std::size_t MAX_PAYLOAD_PATH_BYTES = 4'096;
/** Inclusive bound on one payload file. */
inline constexpr uint64_t MAX_PAYLOAD_FILE_BYTES = 2ULL * 1024ULL * 1024ULL * 1024ULL;
/** Inclusive bound on the aggregate payload bytes, excluding its manifest. */
inline constexpr uint64_t MAX_PAYLOAD_BYTES = 8ULL * 1024ULL * 1024ULL * 1024ULL;
/** Inclusive bound derived from the complete canonical manifest grammar. */
inline constexpr uint64_t MAX_PAYLOAD_MANIFEST_BYTES =
	static_cast<uint64_t>(MAX_PAYLOAD_ENTRIES) *
	static_cast<uint64_t>(common::SHA256_HEX_LENGTH + 2u + MAX_PAYLOAD_PATH_BYTES + 1u);

/** One verified file and its byte/mode identity in an immutable admitted tree. */
struct payload_file {
	std::string relative_path;	      ///< Canonical path below the admitted root.
	common::held_file_identity identity;  ///< Observed same-descriptor digest and size.
	uint32_t mode;			      ///< Verified permission bits copied with the bytes.
};

/**
 * @brief Admit one bounded portable relative payload path.
 * @param path Nonempty slash-separated path with no indirect components.
 * @return OK for the manifest/archive path grammar, otherwise INVALID_ARGUMENT.
 */
[[nodiscard]] common::status validate_payload_path(std::string_view path);

/**
 * @brief Derive the complete file set from one immutable regular-file tree.
 * @param root Exact absolute root whose directories are all file-implied.
 * @param policy Exact file/directory ownership and size authority.
 * @return Sorted identities after complete before/after tree validation.
 *         This is staging evidence, not a claim that a manifest was verified.
 */
[[nodiscard]] common::status_or<std::vector<payload_file>> read_payload_tree(const std::filesystem::path &root,
									     const common::held_file_policy &policy);

/**
 * @brief Render exact observed identities using the sole checksum-row grammar.
 * @param files Nonempty canonical, strictly sorted, unique relative identities.
 * @return Lowercase SHA-256, two spaces, path, and LF for every row. The
 *         calling file authority owns size admission and self exclusion.
 */
[[nodiscard]] common::status_or<std::string> render_payload_manifest(std::span<const payload_file> files);

/**
 * @brief Verify an exact complete byte projection between two immutable trees.
 * @param source Canonical source tree under its explicit admission policy.
 * @param destination Distinct canonical staged tree under its own policy.
 * @param source_policy Source file/directory authority.
 * @param destination_policy Staged file/directory authority.
 * @return OK only for equal complete path sets and equal sizes/digests. File
 *         modes belong to each policy; this does not claim content semantics.
 */
[[nodiscard]] common::status verify_payload_projection(const std::filesystem::path &source,
						       const std::filesystem::path &destination,
						       const common::held_file_policy &source_policy,
						       const common::held_file_policy &destination_policy);

/**
 * @brief Generate a complete manifest from one immutable staged tree.
 *
 * CMake owns membership. This operation admits the staged tree, hashes every
 * regular file, and rechecks file/directory identity before publishing the
 * manifest without replacement. Only directories implied by a file or the
 * manifest path are accepted. The output's parent must already exist.
 *
 * @param root Exact absolute staged root, immutable for the operation.
 * @param manifest_relative_path Canonical absent output beneath that root.
 * @param policy Exact file and directory admission authority.
 * @return OK after complete publication; no existing output is replaced.
 * @throws std::bad_alloc, std::length_error At the owning cold process boundary.
 */
[[nodiscard]] common::status generate_payload_manifest(const std::filesystem::path &root,
						       std::string_view manifest_relative_path,
						       const common::held_file_policy &policy);

/**
 * @brief Verify and return every file in a complete immutable payload.
 *
 * The returned sorted set includes the manifest with its actual digest and
 * size, so it describes the complete verified file domain. The wire manifest
 * still excludes itself. Callers retain the source tree's immutability and
 * preserve these identities when copying or transferring the files; paths
 * alone are not custody.
 *
 * @param root Exact absolute payload root.
 * @param manifest_relative_path Canonical manifest beneath the root.
 * @param policy Exact file and directory admission authority.
 * @return Complete verified files or the first admission/integrity failure.
 * @throws std::bad_alloc, std::length_error At the owning cold process boundary.
 */
[[nodiscard]] common::status_or<std::vector<payload_file>>
read_verified_payload(const std::filesystem::path &root, std::string_view manifest_relative_path,
		      const common::held_file_policy &policy);

/** Exact caller-owned shape of one payload-manifest verification domain. */
struct payload_manifest_contract {
	std::string_view manifest_relative_path;		    ///< Manifest path beneath the payload root.
	std::span<const std::string_view> expected_relative_paths;  ///< Complete sorted manifest row set.
	/**
	 * Sorted top-level peers owned by other authorities. Their directory entries
	 * must be exact and direct, but descendants are outside this manifest's
	 * authority.
	 */
	std::span<const std::string_view> excluded_directory_roots;
};

/**
 * @brief Verify one complete deterministic payload manifest.
 *
 * The contract and every observed path use the same bounded portable grammar
 * as the release producer. Manifest rows must be strictly sorted, unique, and
 * exactly equal to @p contract.expected_relative_paths. The manifest is held
 * through symlink-free admission before tree traversal. Every declared file
 * is then opened and hashed through
 * `open_held_regular_file()` under the remaining aggregate byte budget. A
 * traversal before and after payload hashing rejects missing, extra, indirect,
 * special, or concurrently added/removed objects outside explicitly excluded
 * top-level peer roots.
 *
 * @param root Exact absolute normalized payload root.
 * @param contract Complete caller-owned payload membership contract.
 * @param policy Owner, mode, link, directory, and size authority for files.
 * @return OK only when manifest grammar, hashes, and tree membership agree.
 */
[[nodiscard]] common::status verify_payload_manifest(const std::filesystem::path &root,
						     const payload_manifest_contract &contract,
						     const common::held_file_policy &policy);

}  // namespace kinetum::release
