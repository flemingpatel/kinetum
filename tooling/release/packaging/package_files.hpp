// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file package_files.hpp
 * @brief Bounded package-tree admission, archive I/O, and publication.
 * @author Fleming Patel
 *
 * These private cold operations consume CMake-staged or fully admitted trees.
 * libarchive and zlib are private implementation dependencies. No
 * archive codec, installer, or filesystem discovery enters a runtime image.
 */

#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

#include "tooling/release/verification/payload_manifest.hpp"
#include "src/provider/provider_target_tuple.hpp"

namespace kinetum::release
{

/** Inclusive compressed-input, compressed-output, and decoded-TAR bound. */
inline constexpr uint64_t MAX_PACKAGE_ARCHIVE_BYTES = 9ULL * 1024ULL * 1024ULL * 1024ULL;

/**
 * @brief Admit and hash the complete regular-file tree beneath an exact root.
 * @param root Immutable canonical absolute root.
 * @param policy Held-file and directory ownership authority.
 * @return Sorted file identities; directories must be exactly file-implied.
 *         Links, special files, non-0644/0755 files, and over-bound trees reject.
 */
[[nodiscard]] common::status_or<std::vector<payload_file>> read_package_tree(const std::filesystem::path &root,
									     const common::held_file_policy &policy);

/**
 * @brief Write deterministic gzip/PAX bytes from one complete staged envelope.
 * @param root Immutable envelope whose basename is the one archive root.
 * @param files Complete admitted file identities derived from that tree.
 * @param output Caller-held empty private regular output on the output filesystem.
 * @param policy Exact source admission policy.
 * @return OK after codec completion, source identity recheck, and fsync. The
 *         caller owns checked close and candidate cleanup on every outcome.
 */
[[nodiscard]] common::status write_package_archive(const std::filesystem::path &root,
						   std::span<const payload_file> files, int output,
						   const common::held_file_policy &policy);

/**
 * @brief Completely admit a gzip/TAR stream before extracting any member.
 *
 * Gzip-only zlib decoding checks each member's header, CRC and length before
 * completing a bounded unlinked spool. The exact compressed buffers fed to
 * zlib are hashed against the held input identity before TAR admission;
 * verification never substitutes a later reread for the consumed bytes.
 * Libarchive then owns TAR admission,
 * rejecting unsafe paths, ordering, links, sparse/special files, metadata that
 * changes file semantics, and over-bound sizes. A second pass copies through
 * directory descriptors. Non-authoritative PAX comments are ignored.
 *
 * @param archive Immutable compressed file retained by the caller.
 * @param destination Existing empty private extraction root.
 * @param expected_root Exact single top-level archive directory.
 * @return OK after complete extraction and same-descriptor identity proof.
 *         The caller runs this operation in a bounded disposable process and
 *         owns cleanup of the destination on every failure.
 */
[[nodiscard]] common::status extract_package_archive(const common::held_file &archive,
						     const std::filesystem::path &destination,
						     std::string_view expected_root);

/**
 * @brief Prove an ELF's target and its retained compiled release-version symbol.
 * @param file Immutable held executable or shared object.
 * @param target Exact target tuple; inspection executes no target code.
 * @param version Exact root VERSION text without its terminal newline.
 * @return OK only for one exact hidden version marker of that target.
 */
[[nodiscard]] common::status verify_package_elf(const common::held_file &file, provider::provider_target_tuple target,
						std::string_view version);

/**
 * @brief Atomically publish a completed file, converging only on exact bytes.
 * @param candidate Private same-filesystem file owned by the caller.
 * @param output Exact final pathname; existing foreign files are preserved.
 * @param identity Verified candidate identity, rechecked before rename.
 * @return OK after publication or exact-winner convergence and candidate
 *         retirement. Post-rename durability uncertainty terminates loudly.
 */
[[nodiscard]] common::status publish_package_file(const std::filesystem::path &candidate,
						  const std::filesystem::path &output,
						  const common::held_file_identity &identity);

}  // namespace kinetum::release
