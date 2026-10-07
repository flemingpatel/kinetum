// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file bundle_manifest.cpp
 * @brief Implementation of bundle manifest generation and verification.
 * @author Fleming Patel
 *
 * This file implements the core algorithms for:
 * - Manifest serialization/deserialization
 * - Recursive directory scanning with SHA-256 hashing
 * - Deterministic file ordering for reproducibility
 * - Content verification against a separately trusted manifest
 *
 * @section implementation_notes Implementation Notes
 *
 * Determinism Strategy:
 * - Files are sorted lexicographically by relative path
 * - Canonical ASCII text has fixed metadata, separators, ordering, and LF
 * - SHA-256 binds each file's bytes to its admitted manifest row
 * - File sizes provide early mismatch detection
 *
 * Error Handling:
 * - All functions return status or status_or for error propagation
 * - Detailed error messages include file paths and context
 * - Verification fails fast on first integrity violation
 *
 * Performance Characteristics:
 * - Manifest generation: O(n + f log f), where n is total bytes and f is files
 * - Manifest verification: O(n + f), with SHA-256 streaming dominating
 * - Memory usage: O(f) for file entry storage
 * - Streaming hash computation minimizes memory overhead
 *
 */

#include "src/pack/bundle_manifest.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <filesystem>
#include <limits>
#include <string_view>
#include <system_error>
#include <unordered_set>

#include "src/common/file_io.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"
#include "src/common/version.hpp"

namespace kinetum::pack
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

namespace
{

/** @brief Exact byte prefix of the canonical name metadata row. */
constexpr std::string_view BUNDLE_NAME_PREFIX = "bundle_name=";

/** @brief Exact byte prefix of the canonical version metadata row. */
constexpr std::string_view BUNDLE_VERSION_PREFIX = "bundle_version=";

/** @brief Exact byte prefix of each canonical file row. */
constexpr std::string_view FILE_PREFIX = "file ";

/** @brief Maximum decimal width of an unsigned 64-bit value. */
constexpr std::size_t UINT64_DECIMAL_CAPACITY = std::numeric_limits<uint64_t>::digits10 + 1;

/**
 * @brief Return whether a version has the root VERSION file's canonical shape.
 *
 * @param value Candidate version text.
 * @return true only for a numeric triplet with the optional admitted suffix.
 */
[[nodiscard]] bool is_canonical_product_version(std::string_view value) noexcept
{
	std::size_t offset = 0;
	for (std::size_t component = 0; component < 3; ++component) {
		const std::size_t start = offset;
		while (offset < value.size() && value[offset] >= '0' && value[offset] <= '9') {
			++offset;
		}
		if (offset == start) {
			return false;
		}
		if (component != 2) {
			if (offset == value.size() || value[offset] != '.') {
				return false;
			}
			++offset;
		}
	}
	if (offset == value.size()) {
		return true;
	}
	if (value[offset] != '-' && value[offset] != '+') {
		return false;
	}
	++offset;
	if (offset == value.size()) {
		return false;
	}
	for (; offset < value.size(); ++offset) {
		const char byte = value[offset];
		if (!((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
		      byte == '.' || byte == '_' || byte == '-')) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Return whether one digest is exact lowercase SHA-256 text.
 *
 * @param value Candidate hexadecimal digest.
 * @return true only for the fixed width and lowercase hexadecimal alphabet.
 */
[[nodiscard]] bool is_lowercase_sha256(std::string_view value) noexcept
{
	return value.size() == kinetum::common::SHA256_HEX_LENGTH &&
	       std::all_of(value.begin(), value.end(),
			   [](char byte) { return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'); });
}

/**
 * @brief Add one representation extent under the exact manifest byte ceiling.
 *
 * @param[in,out] extent Current and resulting serialized byte count.
 * @param addition Bytes to add.
 * @return OK when the sum is representable and no greater than MAX_MANIFEST_SIZE.
 */
status add_manifest_extent(std::size_t &extent, std::size_t addition)
{
	if (extent > MAX_MANIFEST_SIZE || addition > MAX_MANIFEST_SIZE - extent) {
		return status::resource_exhausted("canonical bundle manifest exceeds maximum size");
	}
	extent += addition;
	return status::ok();
}

/**
 * @brief Return the shortest-form decimal width of one unsigned value.
 *
 * @param value Value to measure.
 * @return Number of decimal digits in the canonical representation.
 */
[[nodiscard]] std::size_t decimal_width(uint64_t value) noexcept
{
	std::size_t width = 1;
	while (value >= 10) {
		value /= 10;
		++width;
	}
	return width;
}

/**
 * @brief Account the fixed metadata rows in one canonical manifest.
 *
 * @param name Canonical bundle name.
 * @param version Candidate numeric-triplet version.
 * @return Exact metadata byte extent, or the first size-bound failure.
 */
status_or<std::size_t> manifest_header_extent(std::string_view name, std::string_view version)
{
	std::size_t extent = 0;
	for (const std::size_t addition : {BUNDLE_NAME_PREFIX.size(), name.size(), std::size_t{1},
					   BUNDLE_VERSION_PREFIX.size(), version.size(), std::size_t{1}}) {
		const auto extent_status = add_manifest_extent(extent, addition);
		if (!extent_status.is_ok()) {
			return extent_status;
		}
	}
	return extent;
}

/**
 * @brief Account one canonical file row under the shared manifest byte ceiling.
 *
 * @param[in,out] extent Current and resulting serialized byte count.
 * @param entry File entry whose canonical row will be emitted.
 * @return OK when the row fits, or RESOURCE_EXHAUSTED.
 */
status add_manifest_entry_extent(std::size_t &extent, const bundle_file_entry &entry)
{
	for (const std::size_t addition :
	     {FILE_PREFIX.size(), entry.rel_path.size(), std::size_t{1}, decimal_width(entry.size_bytes),
	      std::size_t{1}, entry.sha256_hex.size(), std::size_t{1}}) {
		const auto extent_status = add_manifest_extent(extent, addition);
		if (!extent_status.is_ok()) {
			return extent_status;
		}
	}
	return status::ok();
}

/**
 * @brief Return the next LF-terminated row from already admitted text.
 *
 * @param bytes Complete manifest bytes ending in LF.
 * @param[in,out] offset Current row offset and next unread byte on return.
 * @return Row bytes excluding LF.
 */
[[nodiscard]] std::string_view next_manifest_line(std::string_view bytes, std::size_t &offset) noexcept
{
	const std::size_t end = bytes.find('\n', offset);
	const std::string_view line(bytes.data() + offset, end - offset);
	offset = end + 1;
	return line;
}

/**
 * @brief Validate one exact manifest-relative path representation.
 *
 * @param rel_path Candidate path bytes.
 * @return OK only for one bounded canonical ASCII relative path.
 */
status validate_safe_relative_path(std::string_view rel_path);

}  // namespace

bool is_canonical_bundle_name(std::string_view name) noexcept
{
	if (name.empty() || name.size() > MAX_BUNDLE_NAME_LENGTH || name == "." || name == "..") {
		return false;
	}
	return std::all_of(name.begin(), name.end(), [](char byte) {
		return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
		       byte == '.' || byte == '_' || byte == '-';
	});
}

status_or<std::string> bundle_manifest::to_text() const
{
	if (!is_canonical_bundle_name(bundle_name)) {
		return status::invalid_argument("bundle manifest name is not canonical");
	}
	if (!is_canonical_product_version(bundle_version)) {
		return status::invalid_argument("bundle manifest version is not canonical");
	}
	if (files.size() > MAX_BUNDLE_FILES) {
		return status::resource_exhausted("bundle manifest exceeds maximum number of files");
	}

	auto extent_or = manifest_header_extent(bundle_name, bundle_version);
	if (!extent_or.is_ok()) {
		return extent_or.error();
	}
	std::size_t extent = extent_or.value();
	std::string_view previous_path;
	for (const auto &entry : files) {
		const auto path_status = validate_safe_relative_path(entry.rel_path);
		if (!path_status.is_ok()) {
			return path_status;
		}
		if (entry.rel_path == MANIFEST_FILENAME) {
			return status::invalid_argument("bundle manifest must not list itself");
		}
		if (!previous_path.empty() && previous_path >= entry.rel_path) {
			return status::invalid_argument(
				"bundle manifest file paths are not strictly sorted and unique");
		}
		if (!is_lowercase_sha256(entry.sha256_hex)) {
			return status::invalid_argument(
				"bundle manifest SHA-256 is not canonical lowercase hexadecimal");
		}
		const auto extent_status = add_manifest_entry_extent(extent, entry);
		if (!extent_status.is_ok()) {
			return extent_status;
		}
		previous_path = entry.rel_path;
	}

	std::string text;
	text.reserve(extent);
	text.append(BUNDLE_NAME_PREFIX);
	text.append(bundle_name);
	text.push_back('\n');
	text.append(BUNDLE_VERSION_PREFIX);
	text.append(bundle_version);
	text.push_back('\n');
	for (const auto &entry : files) {
		text.append(FILE_PREFIX);
		text.append(entry.rel_path);
		text.push_back(' ');
		std::array<char, UINT64_DECIMAL_CAPACITY> size_text{};
		const auto [end, error] =
			std::to_chars(size_text.data(), size_text.data() + size_text.size(), entry.size_bytes, 10);
		if (error != std::errc{}) {
			return status(status_code::INTERNAL_ERROR, "failed to serialize canonical manifest size");
		}
		text.append(size_text.data(), static_cast<std::size_t>(end - size_text.data()));
		text.push_back(' ');
		text.append(entry.sha256_hex);
		text.push_back('\n');
	}
	if (text.size() != extent) {
		return status(status_code::INTERNAL_ERROR, "canonical manifest extent disagrees with serialization");
	}

	// The strict parser is the sole product-version admission wall. Running the
	// emitted bytes through it keeps direct structured callers from creating a
	// representation that a verifier would reject without duplicating that wall.
	const auto parsed_or = from_text(text);
	if (!parsed_or.is_ok()) {
		return parsed_or.error();
	}
	return text;
}

namespace
{

status validate_safe_relative_path(std::string_view rel_path)
{
	namespace fs = std::filesystem;

	// Reject empty paths
	if (rel_path.empty()) {
		return status(status_code::INVALID_ARGUMENT, "empty relative path not allowed", "");
	}

	// Reject paths exceeding maximum length
	if (rel_path.size() > MAX_REL_PATH_LENGTH) {
		return status(status_code::INVALID_ARGUMENT, "relative path exceeds maximum length",
			      std::string(rel_path.substr(0, 100)));
	}

	// Reject absolute paths
	if (rel_path[0] == '/' || rel_path[0] == '\\') {
		return status(status_code::INVALID_ARGUMENT, "absolute paths not allowed in manifest",
			      std::string(rel_path));
	}

	// Check for drive-letter absolute paths (e.g., C:\path)
	if (rel_path.size() >= 2 && rel_path[1] == ':') {
		return status(status_code::INVALID_ARGUMENT, "absolute paths not allowed in manifest",
			      std::string(rel_path));
	}

	for (const char raw : rel_path) {
		const auto c = static_cast<unsigned char>(raw);
		if (c <= 0x20 || c > 0x7E) {
			return status(status_code::INVALID_ARGUMENT,
				      "relative path contains noncanonical whitespace, control, or non-ASCII byte",
				      std::string(rel_path));
		}
		if (raw == '\\') {
			return status(status_code::INVALID_ARGUMENT,
				      "relative path must use '/' separators, not backslashes", std::string(rel_path));
		}
	}

	// A safe path also has one lexical representation. Repeated separators,
	// trailing separators, and every dot component are rejected, not repaired.
	const fs::path path{std::string(rel_path)};
	if (path.is_absolute() || path.lexically_normal().generic_string() != rel_path) {
		return status(status_code::INVALID_ARGUMENT, "relative path is not in canonical lexical form",
			      std::string(rel_path));
	}
	for (const auto &part : path) {
		std::string part_str = part.string();

		// Reject parent directory references
		if (part_str == "..") {
			return status(status_code::INVALID_ARGUMENT, "directory traversal not allowed (.. detected)",
				      std::string(rel_path));
		}

		// Reject current-directory components rather than normalizing them.
		if (part_str == ".") {
			return status(status_code::INVALID_ARGUMENT,
				      "current directory references not allowed (. detected)", std::string(rel_path));
		}
	}

	return status::ok();
}

}  // namespace

status_or<bundle_manifest> bundle_manifest::from_text(const std::string &txt)
{
	// Enforce manifest size limit for DoS protection
	if (txt.size() > MAX_MANIFEST_SIZE) {
		return status(status_code::INVALID_ARGUMENT, "manifest exceeds maximum size",
			      std::to_string(txt.size()) + " > " + std::to_string(MAX_MANIFEST_SIZE));
	}

	if (txt.empty() || txt.back() != '\n') {
		return status::invalid_argument("bundle manifest is empty or lacks its final LF");
	}
	if (txt.find('\r') != std::string::npos) {
		return status::invalid_argument("bundle manifest must use LF line endings");
	}

	const std::string_view bytes(txt);
	std::size_t offset = 0;
	const std::string_view name_line = next_manifest_line(bytes, offset);
	if (!name_line.starts_with(BUNDLE_NAME_PREFIX)) {
		return status::invalid_argument("bundle manifest line 1 must declare bundle_name");
	}
	const std::string_view name = name_line.substr(BUNDLE_NAME_PREFIX.size());
	if (!is_canonical_bundle_name(name)) {
		return status::invalid_argument("bundle manifest name is not canonical");
	}
	if (offset >= bytes.size()) {
		return status::invalid_argument("bundle manifest line 2 must declare bundle_version");
	}

	const std::string_view version_line = next_manifest_line(bytes, offset);
	if (!version_line.starts_with(BUNDLE_VERSION_PREFIX)) {
		return status::invalid_argument("bundle manifest line 2 must declare bundle_version");
	}
	const std::string_view version = version_line.substr(BUNDLE_VERSION_PREFIX.size());
	if (!is_canonical_product_version(version)) {
		return status::invalid_argument("bundle manifest version is not canonical");
	}
	if (version != kinetum::common::KINETUM_VERSION_STRING) {
		return status(
			status_code::FAILED_PRECONDITION, "bundle manifest version does not match this Kinetum runtime",
			"manifest=" + std::string(version) + " runtime=" + kinetum::common::KINETUM_VERSION_STRING);
	}

	bundle_manifest manifest;
	manifest.bundle_name.assign(name);
	manifest.bundle_version.assign(version);
	while (offset < bytes.size()) {
		const std::string_view line = next_manifest_line(bytes, offset);
		if (!line.starts_with(FILE_PREFIX)) {
			return status(status_code::INVALID_ARGUMENT,
				      "invalid manifest file line (expected 'file <path> <size> <hash>')",
				      std::string(line));
		}

		const std::string_view fields = line.substr(FILE_PREFIX.size());
		const std::size_t first_separator = fields.find(' ');
		const std::size_t second_separator = first_separator == std::string_view::npos ?
							     std::string_view::npos :
							     fields.find(' ', first_separator + 1);
		if (first_separator == std::string_view::npos || second_separator == std::string_view::npos ||
		    fields.find(' ', second_separator + 1) != std::string_view::npos) {
			return status(status_code::INVALID_ARGUMENT,
				      "invalid manifest file line (expected 'file <path> <size> <hash>')",
				      std::string(line));
		}

		const std::string_view path = fields.substr(0, first_separator);
		const std::string_view size_text =
			fields.substr(first_separator + 1, second_separator - first_separator - 1);
		const std::string_view hash = fields.substr(second_separator + 1);
		const auto path_status = validate_safe_relative_path(path);
		if (!path_status.is_ok()) {
			return path_status;
		}
		if (path == MANIFEST_FILENAME) {
			return status::invalid_argument("bundle manifest must not list itself");
		}
		if (!manifest.files.empty() && std::string_view(manifest.files.back().rel_path) >= path) {
			return status::invalid_argument(
				"bundle manifest file paths are not strictly sorted and unique");
		}
		if (size_text.empty() || (size_text.size() > 1 && size_text.front() == '0')) {
			return status(status_code::INVALID_ARGUMENT, "invalid file size in manifest",
				      "line: " + std::string(line));
		}

		uint64_t size_bytes = 0;
		const auto [size_end, size_error] =
			std::from_chars(size_text.data(), size_text.data() + size_text.size(), size_bytes, 10);
		if (size_error != std::errc{} || size_end != size_text.data() + size_text.size()) {
			return status(status_code::INVALID_ARGUMENT, "invalid file size in manifest",
				      "line: " + std::string(line));
		}
		std::array<char, UINT64_DECIMAL_CAPACITY> canonical_size{};
		const auto [canonical_end, canonical_error] = std::to_chars(
			canonical_size.data(), canonical_size.data() + canonical_size.size(), size_bytes, 10);
		if (canonical_error != std::errc{} ||
		    std::string_view(canonical_size.data(),
				     static_cast<std::size_t>(canonical_end - canonical_size.data())) != size_text) {
			return status(status_code::INVALID_ARGUMENT, "invalid file size in manifest",
				      "line: " + std::string(line));
		}

		if (hash.size() != kinetum::common::SHA256_HEX_LENGTH) {
			return status(status_code::INVALID_ARGUMENT,
				      "invalid SHA-256 hash length (expected 64 hex chars)", std::string(hash));
		}
		if (!is_lowercase_sha256(hash)) {
			return status(status_code::INVALID_ARGUMENT,
				      "invalid SHA-256 hash (expected lowercase hexadecimal)", std::string(hash));
		}
		if (manifest.files.size() >= MAX_BUNDLE_FILES) {
			return status(status_code::INVALID_ARGUMENT, "manifest exceeds maximum number of files",
				      std::to_string(manifest.files.size() + 1) + " > " +
					      std::to_string(MAX_BUNDLE_FILES));
		}

		manifest.files.push_back(bundle_file_entry{
			.rel_path = std::string(path), .size_bytes = size_bytes, .sha256_hex = std::string(hash)});
	}

	return manifest;
}

status_or<std::string> generate_manifest_text(const std::string &bundle_dir)
{
	namespace fs = std::filesystem;

	// Initialize manifest metadata
	bundle_manifest m;
	m.bundle_name = fs::path(bundle_dir).filename().string();
	m.bundle_version = kinetum::common::KINETUM_VERSION_STRING;
	if (!is_canonical_bundle_name(m.bundle_name)) {
		return status::invalid_argument("bundle directory name is not a canonical bundle name");
	}
	auto extent_or = manifest_header_extent(m.bundle_name, m.bundle_version);
	if (!extent_or.is_ok()) {
		return extent_or.error();
	}
	std::size_t serialized_extent = extent_or.value();

	// Scan directory and build file entries.
	std::vector<bundle_file_entry> entries;

	try {
		std::error_code ec;
		auto dir_iter = fs::recursive_directory_iterator(bundle_dir, ec);
		if (ec) {
			if (ec == std::errc::no_such_file_or_directory) {
				return status(status_code::NOT_FOUND, "bundle directory does not exist", bundle_dir);
			} else if (ec == std::errc::not_a_directory) {
				return status(status_code::INVALID_ARGUMENT, "bundle path is not a directory",
					      bundle_dir);
			} else {
				return status(status_code::INTERNAL_ERROR, "failed to open bundle directory",
					      bundle_dir + ": " + ec.message());
			}
		}

		for (const auto &ent : dir_iter) {
			// Only process regular files
			if (!ent.is_regular_file()) {
				continue;
			}

			// Compute relative path from bundle root
			auto rel = fs::relative(ent.path(), bundle_dir).string();

			// Exclude the manifest file itself to avoid circular dependency
			if (rel == MANIFEST_FILENAME) {
				continue;
			}
			if (entries.size() >= MAX_BUNDLE_FILES) {
				return status::resource_exhausted("bundle exceeds maximum manifest file count");
			}

			auto path_status = validate_safe_relative_path(rel);
			if (!path_status.is_ok()) {
				return status(path_status.code(),
					      "bundle contains a path that cannot be represented in the manifest: " +
						      std::string(path_status.message()),
					      rel);
			}

			// Create file entry
			bundle_file_entry e;
			e.rel_path = std::move(rel);

			auto file_hash_or = kinetum::common::sha256_file_hex_and_size(ent.path().string());
			if (!file_hash_or.is_ok()) {
				return file_hash_or.error();
			}
			auto file_hash = std::move(file_hash_or).value();
			e.sha256_hex = std::move(file_hash.sha256_hex);
			e.size_bytes = file_hash.size_bytes;
			const auto extent_status = add_manifest_entry_extent(serialized_extent, e);
			if (!extent_status.is_ok()) {
				return extent_status;
			}

			entries.push_back(std::move(e));
		}
	} catch (const fs::filesystem_error &ex) {
		// Handle filesystem errors that weren't caught by error_code path
		if (ex.code() == std::errc::no_such_file_or_directory) {
			return status(status_code::NOT_FOUND, "bundle directory does not exist", bundle_dir);
		} else if (ex.code() == std::errc::not_a_directory) {
			return status(status_code::INVALID_ARGUMENT, "bundle path is not a directory", bundle_dir);
		}
		return status(status_code::INTERNAL_ERROR, "filesystem error during manifest generation",
			      std::string(ex.what()));
	}

	// Sort entries deterministically by relative path
	// This ensures manifest is reproducible across runs
	std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) { return a.rel_path < b.rel_path; });

	m.files = std::move(entries);

	return m.to_text();
}

/**
 * @brief Reject the first regular bundle file absent from the manifest.
 *
 * Returning at the first contradiction bounds retained diagnostic state and
 * prevents an undeclared file population from becoming a work target.
 *
 * @param bundle_dir Path to bundle root directory
 * @param manifest Parsed manifest containing expected files
 * @return OK when no undeclared regular file exists, or the first filesystem
 *         or membership failure.
 *
 * @note The manifest file itself is excluded from the extra files check
 * @note Only entries reported as regular are checked; high-level
 *       runtime-bundle admission owns symlink rejection
 */
static status reject_extra_files(const std::string &bundle_dir, const bundle_manifest &manifest)
{
	namespace fs = std::filesystem;

	// Build a set of expected files for average O(1) lookup.
	std::unordered_set<std::string> expected_files;
	expected_files.reserve(manifest.files.size());
	for (const auto &f : manifest.files) {
		expected_files.insert(f.rel_path);
	}

	// Scan the bundle directory for all files
	try {
		std::error_code ec;
		auto dir_iter = fs::recursive_directory_iterator(bundle_dir, ec);
		if (ec) {
			if (ec == std::errc::no_such_file_or_directory) {
				return status(status_code::NOT_FOUND, "bundle directory does not exist", bundle_dir);
			} else if (ec == std::errc::not_a_directory) {
				return status(status_code::INVALID_ARGUMENT, "bundle path is not a directory",
					      bundle_dir);
			} else {
				return status(status_code::INTERNAL_ERROR,
					      "failed to open bundle directory for extra files scan",
					      bundle_dir + ": " + ec.message());
			}
		}

		for (const auto &ent : dir_iter) {
			// Only check regular files
			if (!ent.is_regular_file()) {
				continue;
			}

			// Compute relative path from bundle root
			auto rel = fs::relative(ent.path(), bundle_dir).string();

			// Skip the manifest file itself
			if (rel == MANIFEST_FILENAME) {
				continue;
			}

			// One absent path is already a complete integrity contradiction.
			if (expected_files.find(rel) == expected_files.end()) {
				return status(status_code::FAILED_PRECONDITION,
					      "bundle contains extra file not declared in manifest", rel);
			}
		}
	} catch (const fs::filesystem_error &ex) {
		if (ex.code() == std::errc::no_such_file_or_directory) {
			return status(status_code::NOT_FOUND, "bundle directory does not exist", bundle_dir);
		} else if (ex.code() == std::errc::not_a_directory) {
			return status(status_code::INVALID_ARGUMENT, "bundle path is not a directory", bundle_dir);
		}
		return status(status_code::INTERNAL_ERROR, "filesystem error during extra files scan",
			      std::string(ex.what()));
	}

	return status::ok();
}

status verify_manifest(const std::string &bundle_dir, const std::string &manifest_text)
{
	namespace fs = std::filesystem;
	if (bundle_dir.empty() || bundle_dir.find('\0') != std::string::npos) {
		return status::invalid_argument("bundle verification requires a nonempty path without NUL bytes");
	}

	// Parse manifest
	auto m_or = bundle_manifest::from_text(manifest_text);
	if (!m_or.is_ok()) {
		return m_or.error();
	}
	const auto &m = m_or.value();

	// Verify each file entry
	for (const auto &f : m.files) {
		const auto path = fs::path(bundle_dir) / f.rel_path;

		auto file_hash_or = kinetum::common::sha256_file_hex_and_size(path.string());
		if (!file_hash_or.is_ok()) {
			// Map error codes to appropriate verification errors
			if (file_hash_or.error().code() == status_code::NOT_FOUND) {
				return status(status_code::NOT_FOUND,
					      "missing file in bundle (declared in manifest but not found on disk)",
					      f.rel_path);
			}
			return status(status_code::INTERNAL_ERROR, "failed to read file for verification",
				      std::string(f.rel_path) + ": " + std::string(file_hash_or.error().message()));
		}
		const auto file_hash = std::move(file_hash_or).value();

		// Check hash first so corrupted content produces the strongest diagnostic.
		if (file_hash.sha256_hex != f.sha256_hex) {
			return status(status_code::FAILED_PRECONDITION,
				      "SHA-256 hash mismatch for file (expected " + f.sha256_hex + ", got " +
					      file_hash.sha256_hex + ")",
				      f.rel_path);
		}

		if (file_hash.size_bytes != f.size_bytes) {
			return status(status_code::FAILED_PRECONDITION,
				      "size mismatch for file (expected " + std::to_string(f.size_bytes) +
					      " bytes, got " + std::to_string(file_hash.size_bytes) + " bytes)",
				      f.rel_path);
		}
	}

	// Reject the first undeclared regular file without retaining untrusted
	// diagnostic state or scanning a known-invalid remainder.
	auto scan_status = reject_extra_files(bundle_dir, m);
	if (!scan_status.is_ok()) {
		return scan_status;
	}

	// All files verified successfully and no extra files found
	return status::ok();
}

}  // namespace kinetum::pack
