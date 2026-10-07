// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file payload_manifest.cpp
 * @brief Canonical payload-manifest generation and verification.
 * @author Fleming Patel
 */

#include "tooling/release/verification/payload_manifest.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "src/common/canonical_content_identity.hpp"
#include "src/common/file_io.hpp"
#include "src/common/sha256.hpp"

namespace kinetum::release
{
namespace fs = std::filesystem;

namespace
{

/** Exact fixed characters before one manifest path. */
constexpr std::size_t MANIFEST_ROW_PREFIX_BYTES = common::SHA256_HEX_LENGTH + 2u;

static_assert(MAX_PAYLOAD_MANIFEST_BYTES < std::numeric_limits<std::size_t>::max(),
	      "payload manifest bound must fit the process size type");

/** One grammar-admitted manifest row, before its file has been verified. */
struct manifest_row {
	std::string path;	       ///< Canonical relative file name.
	common::sha256_digest digest;  ///< Exact lowercase-hex decoded claim.
};

/** Metadata retained across the complete operation, excluding read access time. */
struct tree_entry {
	std::string path;      ///< Relative entry name; empty denotes the root.
	struct stat metadata;  ///< Identity observed without following links.
	bool peer;	       ///< A separately owned subtree not traversed.
};

/** Exact file/directory shape supplied by a manifest or independent assertion. */
struct tree_shape {
	std::set<std::string> files;	    ///< All files, including the manifest itself.
	std::set<std::string> directories;  ///< Exactly the parents implied by those files.
	std::set<std::string> peers;	    ///< Exact independent top-level directory names.
};

/**
 * @brief Classify one byte in the portable path-component grammar.
 * @param value One path byte.
 * @param first Whether it begins a component.
 * @return True only for the portable component grammar.
 */
bool is_component_byte(char value, bool first) noexcept
{
	const bool alpha = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
	const bool digit = value >= '0' && value <= '9';
	return alpha || digit || value == '_' || (!first && (value == '.' || value == '+' || value == '-'));
}

/**
 * @brief Map an observed filesystem failure without discarding its context.
 * @param error Saved errno.
 * @param action Failed filesystem operation.
 * @param path Exact input being diagnosed.
 * @return NOT_FOUND for absence, otherwise INTERNAL_ERROR with owned context.
 */
common::status filesystem_error(int error, std::string_view action, const fs::path &path)
{
	const auto code = error == ENOENT ? common::status_code::NOT_FOUND : common::status_code::INTERNAL_ERROR;
	return common::status(code, std::string(action), path.string() + ": " + std::strerror(error));
}

/**
 * @brief Compare the identity that an immutable tree must retain.
 * @param first Earlier snapshot.
 * @param second Later snapshot.
 * @return True for identical immutable metadata; peer descendants and read access time are excluded.
 */
bool same_entry(const tree_entry &first, const tree_entry &second) noexcept
{
	const auto &a = first.metadata;
	const auto &b = second.metadata;
	if (first.path != second.path || first.peer != second.peer || a.st_dev != b.st_dev || a.st_ino != b.st_ino ||
	    a.st_mode != b.st_mode || a.st_uid != b.st_uid || a.st_gid != b.st_gid) {
		return false;
	}
	if (first.peer) {
		return true;
	}
	return a.st_nlink == b.st_nlink && a.st_size == b.st_size && a.st_mtim.tv_sec == b.st_mtim.tv_sec &&
	       a.st_mtim.tv_nsec == b.st_mtim.tv_nsec && a.st_ctim.tv_sec == b.st_ctim.tv_sec &&
	       a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}

/**
 * @brief Prove that two complete operation snapshots name the same objects.
 * @param first Earlier complete sorted snapshot.
 * @param second Later complete sorted snapshot.
 * @return True only for equal membership and retained entry identities.
 */
bool same_tree(const std::vector<tree_entry> &first, const std::vector<tree_entry> &second) noexcept
{
	return first.size() == second.size() &&
	       std::equal(first.begin(), first.end(), second.begin(), second.end(), same_entry);
}

/**
 * @brief Check the caller's directory policy on one observed directory.
 * @param metadata No-follow directory observation.
 * @param policy Caller-owned directory authority.
 * @return OK for exact kind and applicable owner/mode constraints.
 */
common::status check_directory(const struct stat &metadata, const common::held_file_policy &policy)
{
	if (!S_ISDIR(metadata.st_mode)) {
		return common::status::failed_precondition(
			common::static_status_text("payload directory is not one exact directory"));
	}
	if (policy.directories.has_value()) {
		const auto &authority = *policy.directories;
		if (static_cast<uint64_t>(metadata.st_uid) != authority.required_owner_uid ||
		    (static_cast<uint32_t>(metadata.st_mode) & authority.forbidden_mode_bits) != 0u) {
			return common::status::permission_denied(
				common::static_status_text("payload directory violates its ownership policy"));
		}
	}
	return common::status::ok();
}

/**
 * @brief Admit the root before any filesystem traversal can follow it.
 * @param root Exact immutable absolute payload root.
 * @param policy Caller file/directory authority.
 * @return OK for a direct root contained by its declared policy, before traversal.
 */
common::status check_root(const fs::path &root, const common::held_file_policy &policy)
{
	if (root.empty() || !root.is_absolute() || root != root.lexically_normal() || root == root.root_path() ||
	    root.native().find('\0') != std::string::npos) {
		return common::status::invalid_argument(
			common::static_status_text("payload root must be an exact absolute normalized non-root path"));
	}
	std::error_code error;
	const fs::path canonical = fs::canonical(root, error);
	if (error) {
		return common::status(common::status_code::NOT_FOUND, "payload root cannot be resolved",
				      error.message());
	}
	if (canonical != root) {
		return common::status::failed_precondition(
			common::static_status_text("payload root contains path indirection"));
	}
	if (policy.directories.has_value()) {
		const auto &authority = policy.directories->root;
		if (authority.empty() || !authority.is_absolute() || authority != authority.lexically_normal()) {
			return common::status::invalid_argument(
				common::static_status_text("payload directory policy has an invalid root"));
		}
		const fs::path relative = root.lexically_relative(authority);
		if (relative.empty() || *relative.begin() == "..") {
			return common::status::invalid_argument(
				common::static_status_text("payload directory policy is outside its root"));
		}
	}
	struct stat metadata{};
	if (::lstat(root.c_str(), &metadata) != 0) {
		return filesystem_error(errno, "cannot inspect payload root", root);
	}
	return check_directory(metadata, policy);
}

/**
 * @brief Extend a complete ancestor set within its remaining entry budget.
 * @param path Canonical relative file path.
 * @param directories Ancestor-closed set from prior successful calls; discard on failure.
 * @param maximum Inclusive directory budget after other entry classes are charged.
 * @return OK with every parent present, or RESOURCE_EXHAUSTED before another insertion.
 */
[[nodiscard]] common::status insert_parent_directories(std::string_view path, std::set<std::string> &directories,
						       std::size_t maximum)
{
	if (directories.size() > maximum) {
		return common::status::resource_exhausted(
			common::static_status_text("payload directory derivation exceeds its entry budget"));
	}
	for (std::size_t separator = path.rfind('/'); separator != std::string_view::npos;
	     separator = path.rfind('/')) {
		path = path.substr(0, separator);
		std::string parent(path);
		const auto position = directories.lower_bound(parent);
		if (position != directories.end() && *position == parent) {
			// A prior successful call already established all of this parent's ancestors.
			break;
		}
		if (directories.size() == maximum) {
			return common::status::resource_exhausted(
				common::static_status_text("payload directory derivation exceeds its entry budget"));
		}
		directories.emplace_hint(position, std::move(parent));
	}
	return common::status::ok();
}

/**
 * @brief Validate and own a sorted, unique caller path span.
 * @param paths Caller-owned expected or excluded path span.
 * @param role Diagnostic role of the span.
 * @param may_be_empty Whether an empty set is legal for this role.
 * @return Owned sorted unique canonical paths, or INVALID_ARGUMENT.
 */
common::status_or<std::vector<std::string>> admit_contract_paths(std::span<const std::string_view> paths,
								 std::string_view role, bool may_be_empty)
{
	if ((!may_be_empty && paths.empty()) || paths.size() > MAX_PAYLOAD_ENTRIES) {
		return common::status::invalid_argument(std::string(role) + " is empty or exceeds its bound");
	}
	std::vector<std::string> result;
	result.reserve(paths.size());
	std::string_view previous;
	for (const auto path : paths) {
		if (!validate_payload_path(path).is_ok() || (!previous.empty() && previous >= path)) {
			return common::status::invalid_argument(std::string(role) +
								" is not canonical, sorted and unique");
		}
		result.emplace_back(path);
		previous = path;
	}
	return result;
}

/**
 * @brief Construct exact tree membership, rejecting overlapping peer domains.
 * @param paths Canonical unique manifest file paths.
 * @param manifest_path Required self-excluded manifest path.
 * @param peers Canonical sorted independent top-level directory names.
 * @return Bounded complete tree shape with no overlapping peer authority.
 */
common::status_or<tree_shape> make_shape(const std::vector<std::string> &paths, std::string_view manifest_path,
					 const std::vector<std::string> &peers)
{
	tree_shape shape;
	shape.files.insert(paths.begin(), paths.end());
	if (shape.files.contains(std::string(manifest_path))) {
		return common::status::invalid_argument(
			common::static_status_text("payload manifest must not contain a row for itself"));
	}
	shape.files.emplace(manifest_path);
	if (shape.files.size() > MAX_PAYLOAD_ENTRIES || peers.size() > MAX_PAYLOAD_ENTRIES - shape.files.size()) {
		return common::status::resource_exhausted(
			common::static_status_text("payload-manifest contract exceeds its complete tree-entry bound"));
	}
	const std::size_t maximum_directories = MAX_PAYLOAD_ENTRIES - shape.files.size() - peers.size();
	for (const auto &path : shape.files) {
		const auto inserted = insert_parent_directories(path, shape.directories, maximum_directories);
		if (!inserted.is_ok()) {
			return inserted;
		}
	}
	for (const auto &peer : peers) {
		if (peer.find('/') != std::string::npos || shape.files.contains(peer) ||
		    shape.directories.contains(peer)) {
			return common::status::invalid_argument(common::static_status_text(
				"excluded package domain overlaps payload-manifest authority"));
		}
		shape.peers.insert(peer);
	}
	return shape;
}

/**
 * @brief Capture every admitted entry without traversing an independent peer.
 * @param root Exact immutable payload root.
 * @param policy File/directory metadata authority.
 * @param peers Independent top-level directories whose descendants are skipped.
 * @return Complete sorted bounded metadata snapshot, rejecting indirection and special entries.
 */
common::status_or<std::vector<tree_entry>> capture_tree(const fs::path &root, const common::held_file_policy &policy,
							const std::set<std::string> &peers)
{
	const auto root_status = check_root(root, policy);
	if (!root_status.is_ok()) {
		return root_status;
	}
	std::vector<tree_entry> entries;
	struct stat root_metadata{};
	if (::lstat(root.c_str(), &root_metadata) != 0) {
		return filesystem_error(errno, "cannot inspect payload root", root);
	}
	entries.push_back({{}, root_metadata, false});
	std::error_code error;
	fs::recursive_directory_iterator iterator(root, fs::directory_options::none, error);
	const fs::recursive_directory_iterator end;
	if (error) {
		return common::status(common::status_code::INTERNAL_ERROR, "failed to enumerate payload",
				      error.message());
	}
	for (; iterator != end; iterator.increment(error)) {
		if (error) {
			return common::status(common::status_code::INTERNAL_ERROR, "failed during payload traversal",
					      error.message());
		}
		if (entries.size() > MAX_PAYLOAD_ENTRIES) {
			return common::status::resource_exhausted(
				common::static_status_text("payload tree exceeds its entry-count bound"));
		}
		const fs::path path = iterator->path();
		const std::string relative = path.lexically_relative(root).generic_string();
		if (!validate_payload_path(relative).is_ok()) {
			return common::status::data_loss(
				common::static_status_text("payload contains a noncanonical path"));
		}
		struct stat metadata{};
		if (::lstat(path.c_str(), &metadata) != 0) {
			return filesystem_error(errno, "cannot inspect payload entry", path);
		}
		if (S_ISLNK(metadata.st_mode) || (!S_ISDIR(metadata.st_mode) && !S_ISREG(metadata.st_mode))) {
			return common::status(common::status_code::DATA_LOSS,
					      "payload contains an indirect or special entry", relative);
		}
		const bool peer = peers.contains(relative);
		if (S_ISDIR(metadata.st_mode)) {
			const auto directory_status = check_directory(metadata, policy);
			if (!directory_status.is_ok()) {
				return directory_status;
			}
			if (peer) {
				iterator.disable_recursion_pending();
			}
		} else if (peer) {
			return common::status::data_loss(
				common::static_status_text("independent payload peer is not a directory"));
		}
		entries.push_back({relative, metadata, peer});
	}
	if (error) {
		return common::status(common::status_code::INTERNAL_ERROR, "failed during payload traversal",
				      error.message());
	}
	std::sort(entries.begin(), entries.end(),
		  [](const tree_entry &a, const tree_entry &b) { return a.path < b.path; });
	return entries;
}

/**
 * @brief Require all observed directories and files to belong to the exact shape.
 * @param entries Complete observed snapshot.
 * @param shape Exact file/directory/peer contract.
 * @return OK only for complete owned file membership and no unbound directory.
 */
common::status check_shape(const std::vector<tree_entry> &entries, const tree_shape &shape)
{
	std::size_t files = 0;
	for (const auto &entry : entries) {
		if (entry.path.empty() || entry.peer) {
			continue;
		}
		if (S_ISDIR(entry.metadata.st_mode)) {
			if (!shape.directories.contains(entry.path)) {
				return common::status::data_loss(
					common::static_status_text("payload contains an unexpected directory"));
			}
		} else {
			if (!shape.files.contains(entry.path)) {
				return common::status::data_loss(
					common::static_status_text("payload contains an unexpected file"));
			}
			++files;
		}
	}
	if (files != shape.files.size()) {
		return common::status::data_loss(common::static_status_text("payload file membership is incomplete"));
	}
	return common::status::ok();
}

/**
 * @brief Parse the sole manifest grammar independently of expected membership.
 * @param bytes Bounded complete manifest text borrowed for parsing.
 * @return Owned canonical rows without normalization, or DATA_LOSS on malformed input.
 */
common::status_or<std::vector<manifest_row>> parse_manifest_rows(std::string_view bytes)
{
	if (bytes.empty() || bytes.back() != '\n' || bytes.size() > MAX_PAYLOAD_MANIFEST_BYTES) {
		return common::status::data_loss(
			common::static_status_text("payload manifest is empty, oversized or lacks its final newline"));
	}
	std::vector<manifest_row> rows;
	std::size_t offset = 0;
	std::string_view previous;
	while (offset < bytes.size()) {
		const std::size_t end = bytes.find('\n', offset);
		if (end == std::string_view::npos || rows.size() == MAX_PAYLOAD_ENTRIES) {
			return common::status::data_loss(
				common::static_status_text("payload manifest has a truncated or overbound row set"));
		}
		const std::string_view row = bytes.substr(offset, end - offset);
		if (row.size() <= MANIFEST_ROW_PREFIX_BYTES || row[common::SHA256_HEX_LENGTH] != ' ' ||
		    row[common::SHA256_HEX_LENGTH + 1u] != ' ') {
			return common::status::data_loss(
				common::static_status_text("payload manifest contains a malformed row"));
		}
		const std::string_view digest = row.substr(0, common::SHA256_HEX_LENGTH);
		const std::string_view path = row.substr(MANIFEST_ROW_PREFIX_BYTES);
		if (!common::validate_sha256_hex_claim(digest, "payload SHA-256").is_ok() ||
		    !validate_payload_path(path).is_ok() || (!previous.empty() && previous >= path)) {
			return common::status::data_loss(common::static_status_text(
				"payload manifest contains a malformed or non-increasing row"));
		}
		auto decoded_or = common::hex_to_bytes(digest);
		if (!decoded_or.is_ok()) {
			return decoded_or.error();
		}
		manifest_row parsed{std::string(path), {}};
		for (std::size_t index = 0; index < common::SHA256_DIGEST_SIZE; ++index) {
			parsed.digest[index] = decoded_or.value()[index];
		}
		rows.push_back(std::move(parsed));
		previous = path;
		offset = end + 1u;
	}
	return rows;
}

/**
 * @brief Apply the shared file ceiling and current aggregate remainder.
 * @param policy Caller policy to preserve.
 * @param bound Remaining operation byte budget.
 * @return A policy enforcing the smaller of the caller and operation limits.
 */
common::held_file_policy bounded_policy(const common::held_file_policy &policy, uint64_t bound)
{
	auto result = policy;
	if (!result.maximum_size_bytes.has_value() || *result.maximum_size_bytes > bound) {
		result.maximum_size_bytes = bound;
	}
	return result;
}

/**
 * @brief Append one admitted path/digest pair using the sole output spelling.
 * @param bytes Owned output text to append to.
 * @param path Already admitted relative path.
 * @param digest Exact observed digest.
 */
void append_manifest_row(std::string &bytes, std::string_view path, const common::sha256_digest &digest)
{
	bytes += common::bytes_to_hex(digest.data(), digest.size());
	bytes += "  ";
	bytes += path;
	bytes += '\n';
}

/**
 * @brief Bind a held descriptor to the inode captured for its exact tree name.
 * @param entries Complete earlier sorted snapshot.
 * @param relative Canonical file identity within that tree.
 * @param file Live held descriptor to bind to the observed name.
 * @return OK only when metadata and inode still equal the captured entry.
 */
common::status check_held_snapshot(const std::vector<tree_entry> &entries, std::string_view relative,
				   const common::held_file &file)
{
	const auto found =
		std::lower_bound(entries.begin(), entries.end(), relative,
				 [](const tree_entry &entry, std::string_view path) { return entry.path < path; });
	struct stat metadata{};
	if (::fstat(file.descriptor(), &metadata) != 0) {
		return filesystem_error(errno, "cannot inspect held payload identity", file.path());
	}
	if (found == entries.end() || found->path != relative ||
	    !same_entry(*found, tree_entry{std::string(relative), metadata, false})) {
		return common::status::data_loss(
			common::static_status_text("held payload descriptor differs from its tree snapshot"));
	}
	return common::status::ok();
}

/**
 * @brief Verify parsed membership and retain every admitted file identity.
 * @param root Exact immutable payload root.
 * @param manifest_path Canonical manifest location.
 * @param policy Caller file/directory authority.
 * @param independent_shape Optional consumer assertion; null selects manifest-declared membership.
 * @return All verified file identities including the manifest, after before/after tree checks.
 */
common::status_or<std::vector<payload_file>> verify_tree(const fs::path &root, std::string_view manifest_path,
							 const common::held_file_policy &policy,
							 const tree_shape *independent_shape)
{
	const auto path_status = validate_payload_path(manifest_path);
	if (!path_status.is_ok()) {
		return path_status;
	}
	const auto root_status = check_root(root, policy);
	if (!root_status.is_ok()) {
		return root_status;
	}
	auto manifest_or = common::open_held_regular_file(root / manifest_path,
							  bounded_policy(policy, MAX_PAYLOAD_MANIFEST_BYTES));
	if (!manifest_or.is_ok()) {
		return manifest_or.error();
	}
	auto bytes_or = common::read_held_file(manifest_or.value(), MAX_PAYLOAD_MANIFEST_BYTES);
	if (!bytes_or.is_ok()) {
		return bytes_or.error();
	}
	auto rows_or = parse_manifest_rows(bytes_or.value());
	if (!rows_or.is_ok()) {
		return rows_or.error();
	}
	std::vector<std::string> paths;
	paths.reserve(rows_or->size());
	for (const auto &row : rows_or.value()) {
		if (row.path == manifest_path) {
			return common::status::data_loss(
				common::static_status_text("payload manifest contains a row for itself"));
		}
		paths.push_back(row.path);
	}
	const std::vector<std::string> peers =
		independent_shape == nullptr ?
			std::vector<std::string>{} :
			std::vector<std::string>(independent_shape->peers.begin(), independent_shape->peers.end());
	auto shape_or = make_shape(paths, manifest_path, peers);
	if (!shape_or.is_ok()) {
		return shape_or.error();
	}
	const auto &shape = shape_or.value();
	if (independent_shape != nullptr && shape.files != independent_shape->files) {
		return common::status::data_loss(
			common::static_status_text("payload manifest disagrees with exact expected membership"));
	}
	auto before_or = capture_tree(root, policy, shape.peers);
	if (!before_or.is_ok()) {
		return before_or.error();
	}
	const auto shape_status = check_shape(before_or.value(), shape);
	if (!shape_status.is_ok()) {
		return shape_status;
	}
	const auto manifest_snapshot_status =
		check_held_snapshot(before_or.value(), manifest_path, manifest_or.value());
	if (!manifest_snapshot_status.is_ok()) {
		return manifest_snapshot_status;
	}
	std::vector<payload_file> files;
	files.reserve(rows_or->size() + 1u);
	uint64_t aggregate = 0;
	for (const auto &row : rows_or.value()) {
		auto file_or = common::open_held_regular_file(
			root / row.path,
			bounded_policy(policy, std::min(MAX_PAYLOAD_FILE_BYTES, MAX_PAYLOAD_BYTES - aggregate)));
		if (!file_or.is_ok()) {
			return file_or.error();
		}
		const auto snapshot_status = check_held_snapshot(before_or.value(), row.path, file_or.value());
		if (!snapshot_status.is_ok()) {
			return snapshot_status;
		}
		if (file_or->identity().sha256 != row.digest) {
			return common::status(common::status_code::DATA_LOSS,
					      "payload SHA-256 disagrees with its manifest", row.path);
		}
		struct stat metadata{};
		if (::fstat(file_or->descriptor(), &metadata) != 0) {
			return filesystem_error(errno, "cannot inspect verified payload file", root / row.path);
		}
		aggregate += file_or->identity().size_bytes;
		files.push_back({row.path, file_or->identity(), static_cast<uint32_t>(metadata.st_mode & 07777)});
	}
	auto after_or = capture_tree(root, policy, shape.peers);
	if (!after_or.is_ok()) {
		return after_or.error();
	}
	if (!same_tree(before_or.value(), after_or.value())) {
		return common::status::data_loss(
			common::static_status_text("payload changed during manifest verification"));
	}
	// Retain the actual manifest identity too; its bytes remain excluded from
	// the grammar's self hash but belong to the complete verified file domain.
	struct stat metadata{};
	if (::fstat(manifest_or->descriptor(), &metadata) != 0) {
		return filesystem_error(errno, "cannot inspect verified payload manifest", root / manifest_path);
	}
	files.push_back(
		{std::string(manifest_path), manifest_or->identity(), static_cast<uint32_t>(metadata.st_mode & 07777)});
	std::sort(files.begin(), files.end(),
		  [](const payload_file &a, const payload_file &b) { return a.relative_path < b.relative_path; });
	return files;
}

}  // namespace

common::status validate_payload_path(std::string_view path)
{
	if (path.empty() || path.size() > MAX_PAYLOAD_PATH_BYTES || path.front() == '/' ||
	    path.find('\\') != std::string_view::npos) {
		return common::status::invalid_argument(
			common::static_status_text("payload manifest path has a forbidden representation"));
	}
	bool first = true;
	for (const char byte : path) {
		if (byte == '/') {
			if (first) {
				return common::status::invalid_argument(
					common::static_status_text("payload manifest path has an empty component"));
			}
			first = true;
		} else {
			if (!is_component_byte(byte, first)) {
				return common::status::invalid_argument(
					common::static_status_text("payload manifest path is not canonical"));
			}
			first = false;
		}
	}
	return first ? common::status::invalid_argument(
			       common::static_status_text("payload manifest path has an empty terminal component")) :
		       common::status::ok();
}

common::status generate_payload_manifest(const std::filesystem::path &root, std::string_view manifest_path,
					 const common::held_file_policy &policy)
{
	const auto path_status = validate_payload_path(manifest_path);
	if (!path_status.is_ok()) {
		return path_status;
	}
	auto before_or = capture_tree(root, policy, {});
	if (!before_or.is_ok()) {
		return before_or.error();
	}
	std::vector<std::string> paths;
	for (const auto &entry : before_or.value()) {
		if (entry.path == manifest_path) {
			return common::status::already_exists(
				common::static_status_text("payload manifest output already exists"));
		}
		if (S_ISREG(entry.metadata.st_mode)) {
			paths.push_back(entry.path);
		}
	}
	if (paths.empty()) {
		return common::status::invalid_argument(
			common::static_status_text("cannot create a manifest for an empty payload"));
	}
	auto shape_or = make_shape(paths, manifest_path, {});
	if (!shape_or.is_ok()) {
		return shape_or.error();
	}
	auto shape = std::move(shape_or).value();
	shape.files.erase(std::string(manifest_path));
	const auto shape_status = check_shape(before_or.value(), shape);
	if (!shape_status.is_ok()) {
		return shape_status;
	}
	std::string bytes;
	uint64_t aggregate = 0;
	for (const auto &path : paths) {
		auto file_or = common::open_held_regular_file(
			root / path,
			bounded_policy(policy, std::min(MAX_PAYLOAD_FILE_BYTES, MAX_PAYLOAD_BYTES - aggregate)));
		if (!file_or.is_ok()) {
			return file_or.error();
		}
		const auto snapshot_status = check_held_snapshot(before_or.value(), path, file_or.value());
		if (!snapshot_status.is_ok()) {
			return snapshot_status;
		}
		aggregate += file_or->identity().size_bytes;
		append_manifest_row(bytes, path, file_or->identity().sha256);
	}
	auto after_or = capture_tree(root, policy, {});
	if (!after_or.is_ok()) {
		return after_or.error();
	}
	if (!same_tree(before_or.value(), after_or.value())) {
		return common::status::data_loss(
			common::static_status_text("staged payload changed during manifest generation"));
	}
	// This is the last operation: it publishes complete bytes without replacing
	// an existing name, and owns cleanup/durability on every publication edge.
	return common::publish_new_string_file(root / manifest_path, bytes);
}

common::status_or<std::string> render_payload_manifest(std::span<const payload_file> files)
{
	if (files.empty() || files.size() > MAX_PAYLOAD_ENTRIES) {
		return common::status::invalid_argument(
			common::static_status_text("checksum row set is empty or over bound"));
	}
	std::string bytes;
	std::string_view previous;
	for (const auto &file : files) {
		if (!validate_payload_path(file.relative_path).is_ok() ||
		    (!previous.empty() && previous >= file.relative_path)) {
			return common::status::invalid_argument(common::static_status_text(
				"checksum row paths must be canonical and strictly increasing"));
		}
		append_manifest_row(bytes, file.relative_path, file.identity.sha256);
		previous = file.relative_path;
	}
	return bytes;
}

common::status_or<std::vector<payload_file>> read_payload_tree(const std::filesystem::path &root,
							       const common::held_file_policy &policy)
{
	auto before_or = capture_tree(root, policy, {});
	if (!before_or.is_ok()) {
		return before_or.error();
	}
	tree_shape shape;
	for (const auto &entry : before_or.value()) {
		if (S_ISREG(entry.metadata.st_mode)) {
			shape.files.insert(entry.path);
			const auto inserted = insert_parent_directories(entry.path, shape.directories,
									MAX_PAYLOAD_ENTRIES - shape.files.size());
			if (!inserted.is_ok()) {
				return inserted;
			}
		}
	}
	if (shape.files.empty()) {
		return common::status::invalid_argument(common::static_status_text("payload tree is empty"));
	}
	const auto shape_status = check_shape(before_or.value(), shape);
	if (!shape_status.is_ok()) {
		return shape_status;
	}
	std::vector<payload_file> files;
	files.reserve(shape.files.size());
	uint64_t aggregate = 0;
	for (const auto &entry : before_or.value()) {
		if (!S_ISREG(entry.metadata.st_mode)) {
			continue;
		}
		auto file_or = common::open_held_regular_file(
			root / entry.path,
			bounded_policy(policy, std::min(MAX_PAYLOAD_FILE_BYTES, MAX_PAYLOAD_BYTES - aggregate)));
		if (!file_or.is_ok()) {
			return file_or.error();
		}
		const auto snapshot_status = check_held_snapshot(before_or.value(), entry.path, file_or.value());
		if (!snapshot_status.is_ok()) {
			return snapshot_status;
		}
		aggregate += file_or->identity().size_bytes;
		files.push_back(
			{entry.path, file_or->identity(), static_cast<uint32_t>(entry.metadata.st_mode & 07777)});
	}
	auto after_or = capture_tree(root, policy, {});
	if (!after_or.is_ok()) {
		return after_or.error();
	}
	if (!same_tree(before_or.value(), after_or.value())) {
		return common::status::data_loss(
			common::static_status_text("payload changed while its complete file set was read"));
	}
	return files;
}

common::status verify_payload_projection(const std::filesystem::path &source, const std::filesystem::path &destination,
					 const common::held_file_policy &source_policy,
					 const common::held_file_policy &destination_policy)
{
	if (source == destination) {
		return common::status::invalid_argument(
			common::static_status_text("source and staged projection must be distinct"));
	}
	auto source_or = read_payload_tree(source, source_policy);
	if (!source_or.is_ok()) {
		return source_or.error();
	}
	auto copied_or = read_payload_tree(destination, destination_policy);
	if (!copied_or.is_ok()) {
		return copied_or.error();
	}
	if (source_or->size() != copied_or->size()) {
		return common::status::data_loss(common::static_status_text(
			"staged tree membership differs from its complete source projection"));
	}
	for (std::size_t index = 0; index < source_or->size(); ++index) {
		const auto &original = (*source_or)[index];
		const auto &copy = (*copied_or)[index];
		if (original.relative_path != copy.relative_path || original.identity.sha256 != copy.identity.sha256 ||
		    original.identity.size_bytes != copy.identity.size_bytes) {
			return common::status::data_loss(
				common::static_status_text("staged tree bytes differ from their source projection"));
		}
	}
	return common::status::ok();
}

common::status_or<std::vector<payload_file>> read_verified_payload(const std::filesystem::path &root,
								   std::string_view manifest_path,
								   const common::held_file_policy &policy)
{
	return verify_tree(root, manifest_path, policy, nullptr);
}

common::status verify_payload_manifest(const std::filesystem::path &root, const payload_manifest_contract &contract,
				       const common::held_file_policy &policy)
{
	const auto path_status = validate_payload_path(contract.manifest_relative_path);
	if (!path_status.is_ok()) {
		return path_status;
	}
	auto expected_or = admit_contract_paths(contract.expected_relative_paths, "expected payload path set", false);
	if (!expected_or.is_ok()) {
		return expected_or.error();
	}
	auto excluded_or =
		admit_contract_paths(contract.excluded_directory_roots, "excluded payload directory set", true);
	if (!excluded_or.is_ok()) {
		return excluded_or.error();
	}
	auto shape_or = make_shape(expected_or.value(), contract.manifest_relative_path, excluded_or.value());
	if (!shape_or.is_ok()) {
		return shape_or.error();
	}
	auto verified_or = verify_tree(root, contract.manifest_relative_path, policy, &shape_or.value());
	return verified_or.is_ok() ? common::status::ok() : verified_or.error();
}

}  // namespace kinetum::release
