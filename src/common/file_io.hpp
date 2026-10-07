// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file file_io.hpp
 * @brief Bounded descriptor reads and durable file publication.
 * @author Fleming Patel
 *
 * These helpers own byte transfer and namespace publication only. Callers own
 * path authorization, containment, provenance, and stable-object admission.
 * Publication opens the target parent once, writes through descriptor-relative
 * operations, and makes a complete file visible through one atomic rename.
 *
 * Thread-safety: Reentrant for independent filesystem objects. Concurrent
 * operations on the same target require external synchronization.
 *
 * @see status.hpp for error handling types
 * @see status_or.hpp for result type with error
 */

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/** @brief Default maximum file size for read_file_to_string (64 MiB). */
inline constexpr std::size_t DEFAULT_MAX_FILE_SIZE = std::size_t{64} * 1024u * 1024u;

/**
 * @brief Read the entire contents of a file into a string.
 *
 * Opens the file once and appends fixed-size read chunks only while the exact
 * positive byte bound permits them. Files whose reported metadata size is
 * zero, files that grow during the read, and non-seekable sources cannot bypass
 * the bound. A read error never returns partial bytes as success.
 *
 * @param path Filesystem path to the file to read
 * @param max_size Positive maximum allowed bytes (default: 64 MiB). The exact
 *        bound is accepted; observing one additional byte returns
 *        RESOURCE_EXHAUSTED.
 * @return status_or<std::string> containing file contents on success,
 *         INVALID_ARGUMENT for a zero bound or an unrepresentable path,
 *         NOT_FOUND if the file cannot be opened, RESOURCE_EXHAUSTED if the
 *         bound or memory capacity is exceeded, OUT_OF_RANGE for a string
 *         representation limit, or a typed read/close/internal error. Partial
 *         content is never returned.
 *
 * @par Thread Safety
 * Reentrant for independent filesystem objects. Concurrent file mutation
 * cannot bypass the byte ceiling or turn a read error into success, but this
 * helper does not claim stable inode/content provenance; callers requiring
 * that guarantee use the held-file admission authority.
 *
 * @par Performance
 * Cold-path operation with O(n) read and allocation work for n admitted bytes.
 *
 * @see write_string_to_file for the inverse operation
 */
status_or<std::string> read_file_to_string(const std::string &path, std::size_t max_size = DEFAULT_MAX_FILE_SIZE);

/**
 * @brief Write string data to a file, replacing any existing content.
 *
 * Opens the existing parent directory once, creates a private same-directory
 * temporary at mode 0600, writes the complete string, establishes exact mode
 * 0644, fsyncs and closes the file, then renames it over the target and fsyncs
 * the parent. Readers never observe a partial target. A prepublication failure
 * durably removes the private temporary; uncertainty after rename terminates
 * because a recoverable status could not identify which namespace state won.
 * Parent directories must already exist.
 *
 * @param path Filesystem path to the file to write
 * @param data String data to write to the file
 * @return status::ok() only after durable publication, or a typed
 *         prepublication failure status.
 *
 * @note This operation is intended for small control/configuration files, not
 *       bulk data streams.
 *
 * @see read_file_to_string for the inverse operation
 */
status write_string_to_file(const std::filesystem::path &path, std::string_view data);

/**
 * @brief Durably publish a new regular file without replacing any path.
 *
 * Uses the same private-complete-file transaction as write_string_to_file, then
 * publishes with Linux renameat2(RENAME_NOREPLACE). An existing regular file,
 * directory, or symbolic link rejects without changing that object; there is
 * no check-then-replace window or weaker fallback. A prepublication failure
 * leaves no private entry. Uncertain durability after publication terminates.
 *
 * @param path Filesystem path that must not already exist.
 * @param data Complete file contents.
 * @return status::ok() only after durable publication, ALREADY_EXISTS when
 *         any object owns the target path, or another exact failure status.
 *
 * @par Path Admission
 * This function validates only the path representation needed by its
 * descriptor-relative mechanism. The caller must authorize the parent and
 * target before invocation.
 */
status publish_new_string_file(const std::filesystem::path &path, std::string_view data);

}  // namespace kinetum::common
