// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file bundle_manifest.hpp
 * @brief Bundle manifest system with deterministic integrity verification.
 * @author Fleming Patel
 *
 * @section overview Overview
 * This module provides a deterministic SHA-256 content-verification manifest
 * for Kinetum deployable artifacts. Runnable bundles are portable directory
 * structures containing a canonical plan, a mandatory complete bootstrap
 * snapshot, optional module artifacts, and canonical content-identity
 * metadata. Platform runtime binaries are installed separately and never
 * belong to this production bundle shape. This component owns the generic
 * low-level manifest grammar;
 * runtime_bundle.hpp composes it with canonical path, plan-identity,
 * snapshot-identity, and production-membership admission.
 *
 * @section bundle_format Bundle Format
 * A Kinetum bundle is a directory with the following structure:
 * ```
 * bundle/
 *   configs/                      # Pipeline, hardware, and plan configurations
 *     pipeline.axiom.pbtxt        # Axiom pipeline definition
 *     hardware.pbtxt              # Hardware inventory
 *     plan.pbtxt                  # Gluon execution plan
 *     config_snapshot.pbtxt       # Mandatory complete bootstrap snapshot
 *   modules/                      # Module .so files (optional)
 *   BUNDLE_MANIFEST.txt           # Integrity manifest (this file)
 *   README_BUNDLE.md              # Human-readable bundle documentation
 * ```
 *
 * @section manifest_format Manifest Format
 * The manifest uses this canonical text representation:
 * ```
 * bundle_name=<name>
 * bundle_version=<version>
 * file <relative_path> <size_bytes> <sha256_hex>
 * file <relative_path> <size_bytes> <sha256_hex>
 * ...
 * ```
 *
 * Example:
 * ```
 * bundle_name=kinetum_fan_in_edge_gateway
 * bundle_version=0.1.0
 * file configs/hardware.pbtxt 2456 a7f3c89d4e5b...
 * file configs/pipeline.axiom.pbtxt 4321 b2e4d6f8...
 * ```
 *
 * @section integrity_verification Integrity Verification
 * Verification process:
 * 1. Parse manifest from BUNDLE_MANIFEST.txt
 * 2. For each file entry:
 *    - Check file exists at specified relative path
 *    - Compute SHA-256 hash and compare
 *    - Verify the byte count from that same read
 * 3. Reject the first undeclared regular file
 * 4. All checks must pass for verification success
 *
 * `verify_manifest()` is intentionally a low-level integrity primitive. A
 * runnable deployment must use `verify_runtime_bundle()` so canonical paths,
 * symlink rejection, plan identity, and exact snapshot module ownership are
 * enforced as well.
 *
 * @section determinism Canonical Representation
 * - Metadata occupies two fixed required lines
 * - Files are strictly sorted and unique by relative path
 * - Sizes use shortest-form decimal and hashes use lowercase hexadecimal
 * - Every line, including the final line, ends in LF
 * - A separately trusted manifest binds exact file bytes through SHA-256
 * - Text format is canonical ASCII
 * - Manifest excludes itself to avoid circular dependencies
 *
 * @section usage Usage Example
 * ```cpp
 * // Generate manifest
 * auto manifest_text = generate_manifest_text("/path/to/bundle");
 * if (!manifest_text.is_ok()) {
 *   // Handle error
 * }
 * auto write_status =
 *     write_string_to_file("/path/to/bundle/BUNDLE_MANIFEST.txt", manifest_text.value());
 * if (!write_status.is_ok()) {
 *   // Handle publication error
 * }
 *
 * // Verify bundle
 * auto text = read_file_to_string("/path/to/bundle/BUNDLE_MANIFEST.txt",
 *                                 MAX_MANIFEST_SIZE + 1u);
 * auto status = verify_manifest("/path/to/bundle", text.value());
 * if (!status.is_ok()) {
 *   // Integrity check failed
 * }
 * ```
 *
 */

#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "src/common/status_or.hpp"

namespace kinetum::pack
{

// =============================================================================
// Constants
// =============================================================================

/** @brief Manifest file name, excluded from scanning to avoid circularity. */
inline constexpr std::string_view MANIFEST_FILENAME = "BUNDLE_MANIFEST.txt";

/** @brief Maximum bundle-manifest size admitted for denial-of-service protection. */
inline constexpr std::size_t MAX_MANIFEST_SIZE = std::size_t{1024} * 1024;  // 1 MB

/** @brief Maximum byte width of one canonical bundle name. */
inline constexpr std::size_t MAX_BUNDLE_NAME_LENGTH = 255;

/** @brief Maximum number of file records admitted in one bundle manifest. */
inline constexpr std::size_t MAX_BUNDLE_FILES = 10000;

/** @brief Maximum manifest-relative artifact path length. */
inline constexpr std::size_t MAX_REL_PATH_LENGTH = 512;

/**
 * @brief Test one bundle name against the canonical manifest grammar.
 *
 * A canonical name contains 1..MAX_BUNDLE_NAME_LENGTH ASCII letters, digits,
 * periods, underscores, or hyphens. The complete values `.` and `..` are
 * reserved. The same predicate governs pack output admission, manifest
 * serialization, and manifest parsing.
 *
 * @param name Candidate bundle name.
 * @return true only when `name` has the one canonical representation.
 */
[[nodiscard]] bool is_canonical_bundle_name(std::string_view name) noexcept;

/**
 * @brief Represents a single file entry in the bundle manifest.
 *
 * Each entry contains the relative path, size, and SHA-256 hash of a file
 * within the bundle. This enables deterministic verification of bundle contents.
 *
 * Canonical serialization requires a nonempty safe `rel_path`, an exact
 * lowercase 64-character `sha256_hex`, and the observed `size_bytes`.
 */
struct bundle_file_entry {
	std::string rel_path;	 ///< Relative path from bundle root (e.g., "configs/plan.pbtxt")
	uint64_t size_bytes{0};	 ///< File size in bytes
	std::string sha256_hex;	 ///< SHA-256 hash in lowercase hexadecimal (64 chars)

	/**
	 * @brief Compare entries by relative path for sorting.
	 * @param other The entry to compare against
	 * @return true if this entry's path is lexicographically less than other's path
	 */
	[[nodiscard]] auto operator<=>(const bundle_file_entry &other) const noexcept
	{
		return rel_path <=> other.rel_path;
	}

	/**
	 * @brief Check equality of two file entries.
	 * @param other The entry to compare against
	 * @return true if all fields match exactly
	 */
	[[nodiscard]] bool operator==(const bundle_file_entry &other) const noexcept = default;
};

/**
 * @brief Bundle manifest containing metadata and file entries.
 *
 * The manifest is the source of truth for bundle integrity. It contains:
 * - Bundle identification (name, version)
 * - Complete list of files with SHA-256 content hashes
 * - Deterministic serialization format
 *
 * `to_text()` admits only a canonical bundle name, the exact compiled product
 * version, and valid file entries in strictly increasing path order. The
 * mutable value itself is an authoring carrier and may be incomplete before
 * that admission call.
 */
struct bundle_manifest {
	std::string bundle_name;	       ///< Canonical retained bundle identifier.
	std::string bundle_version;	       ///< Exact compiled Kinetum product version.
	std::vector<bundle_file_entry> files;  ///< Sorted list of file entries

	/**
	 * @brief Serialize the manifest to canonical text.
	 *
	 * Output format:
	 * ```
	 * bundle_name=<name>
	 * bundle_version=<version>
	 * file <path> <size> <hash>
	 * file <path> <size> <hash>
	 * ...
	 * ```
	 *
	 * The complete structured value is validated before any representation is
	 * returned. Serialization is locale-independent, size-bounded, and accepted
	 * by the same strict parser used by bundle verification.
	 *
	 * @return Canonical text suitable for `BUNDLE_MANIFEST.txt`, or the first
	 *         metadata, ordering, entry, version, or size-bound failure.
	 * @throws std::bad_alloc If result or validation storage cannot be allocated.
	 * @throws std::length_error If storage cannot represent the result.
	 */
	[[nodiscard]] kinetum::common::status_or<std::string> to_text() const;

	/**
	 * @brief Parse one canonical manifest representation.
	 *
	 * Metadata occupies the first two lines, the version equals the compiled
	 * Kinetum version, file paths are strictly increasing, hashes are lowercase,
	 * integers use shortest-form decimal, and every line ends in LF. The parser
	 * performs no whitespace normalization and supplies no defaults.
	 *
	 * @param txt Complete manifest text.
	 * @return Parsed manifest, INVALID_ARGUMENT for malformed/noncanonical text,
	 *         or FAILED_PRECONDITION for another Kinetum version.
	 * @throws std::bad_alloc If parsed-result or diagnostic storage cannot be allocated.
	 * @throws std::length_error If storage exceeds its representable size.
	 */
	[[nodiscard]] static kinetum::common::status_or<bundle_manifest> from_text(const std::string &txt);
};

/**
 * @brief Generate manifest text by scanning bundle directory.
 *
 * Walks the bundle directory recursively, computing SHA-256 hashes for all regular files.
 * Files are sorted deterministically by relative path. The BUNDLE_MANIFEST.txt file itself is
 * excluded to avoid circular dependencies.
 *
 * @param bundle_dir Absolute or relative path to bundle root directory
 * @return Manifest text on success, error status on failure
 * @throws std::bad_alloc If manifest, path, or diagnostic storage cannot be allocated.
 * @throws std::length_error If manifest, path, or diagnostic storage exceeds its representable size.
 *
 * @retval status_code::NOT_FOUND Bundle directory or an observed file is unavailable
 * @retval status_code::RESOURCE_EXHAUSTED File count or serialized bytes exceed the format bound
 * @retval status_code::INTERNAL_ERROR File I/O or hashing error
 * @retval status_code::OK Successfully generated manifest
 *
 * @note Bundle name is derived from and validated against the bundle directory name
 * @note Bundle version is set to kinetum::common::KINETUM_VERSION_STRING.
 * @note Directory entries reported as regular are included; this low-level
 *       generator is not a symlink-admission authority
 * @note The file "BUNDLE_MANIFEST.txt" is excluded from the manifest
 *
 * @par Thread Safety
 * Callers must keep the bundle directory immutable. Detectable concurrent
 * mutation is returned as the exact filesystem or hash failure; no observed
 * file is omitted from a successful manifest.
 *
 * @par Performance
 * Time complexity: O(n + f log f), where n is total file bytes and f is the
 * file count
 * Space complexity: O(m) where m is number of files (for storing entries)
 *
 * @par Example
 * ```cpp
 * auto result = generate_manifest_text("/var/lib/kinetum/bundles/production_v1");
 * if (!result.is_ok()) {
 *   std::cerr << "Failed to generate manifest: " << result.error().message() << "\n";
 *   return 1;
 * }
 * std::string manifest_text = result.value();
 * ```
 */
[[nodiscard]] kinetum::common::status_or<std::string> generate_manifest_text(const std::string &bundle_dir);

/**
 * @brief Verify bundle integrity against manifest text.
 *
 * Performs complete low-level manifest verification:
 * 1. Parse manifest from text
 * 2. For each file in manifest:
 *    - Open and hash the file
 *    - Verify SHA-256 hash matches
 *    - Verify byte count from the same read matches
 * 3. Reject the first regular bundle file absent from the manifest
 *
 * @param bundle_dir Nonempty path to the bundle root, without embedded NUL
 *        bytes.
 * @param manifest_text Manifest content (typically from BUNDLE_MANIFEST.txt)
 * @return OK status if all files verified, error status otherwise
 * @throws std::bad_alloc If parser, path, membership, or diagnostic storage cannot be allocated.
 * @throws std::length_error If parser, path, membership, or diagnostic storage exceeds its representable size.
 *
 * @retval status_code::INVALID_ARGUMENT Malformed manifest
 * @retval status_code::NOT_FOUND File declared in manifest is missing
 * @retval status_code::FAILED_PRECONDITION Foreign product version, file size or hash mismatch, or extra files
 * @retval status_code::INTERNAL_ERROR I/O error during verification
 * @retval status_code::OK All files verified successfully and no extra files
 *
 * @note Verification stops at the first error encountered
 * @note Error details include the problematic file path
 *
 * @par Integrity Considerations
 * - SHA-256 binds each file's bytes to its admitted digest
 * - Size check uses the byte count from the same stream that produced the hash
 * - Extra-file detection rejects undeclared content
 * - Manifest authenticity belongs to the trusted deployment channel; this
 *   primitive verifies content integrity only
 * - This low-level primitive does not establish runtime artifact semantics or
 *   reject every path-indirection shape; use verify_runtime_bundle() for
 *   deployment admission
 *
 * @par Thread Safety
 * This function is thread-safe if the bundle directory is not modified concurrently.
 *
 * @par Performance
 * Time complexity: O(n) where n is total bytes verified (SHA-256 computation)
 * Space complexity: O(f) where f is manifest file count (streaming hash plus
 * expected-file set for the extra-files scan)
 *
 * @par Example
 * ```cpp
 * auto text = read_file_to_string(
 *     "/var/lib/kinetum/bundles/edge-v1/BUNDLE_MANIFEST.txt",
 *     MAX_MANIFEST_SIZE + 1u);
 * if (!text.is_ok()) {
 *   return text.error();
 * }
 *
 * auto status = verify_manifest("/var/lib/kinetum/bundles/edge-v1",
 *                               text.value());
 * if (!status.is_ok()) {
 *   std::cerr << "Verification failed: " << status.message() << "\n";
 *   std::cerr << "Details: " << status.details() << "\n";
 *   return 1;
 * }
 * std::cout << "Bundle integrity verified successfully\n";
 * ```
 */
[[nodiscard]] kinetum::common::status verify_manifest(const std::string &bundle_dir, const std::string &manifest_text);

}  // namespace kinetum::pack
