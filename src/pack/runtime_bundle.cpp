// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_bundle.cpp
 * @brief Canonical runtime-bundle admission implementation.
 * @author Fleming Patel
 *
 * The implementation deliberately composes the existing manifest and content-
 * identity authorities. It does not introduce an alternate hash, protobuf
 * parser, module-set validator, or deployment-plan interpretation.
 */

#include "src/pack/runtime_bundle.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>

#include "src/common/canonical_content_identity.hpp"
#include "src/common/file_io.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"
#include "src/pack/bundle_manifest.hpp"
#include "src/pack/pack_source_admission.hpp"
#include "src/provider/deployment_plan_identity.hpp"

namespace kinetum::pack
{

namespace
{

namespace fs = std::filesystem;

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

/** @brief Maximum protobuf-text artifact size admitted by bundle verification. */
constexpr std::size_t MAX_RUNTIME_BUNDLE_PBTXT_BYTES = kinetum::common::DEFAULT_MAX_FILE_SIZE;

static_assert(sizeof(std::size_t) <= sizeof(uint64_t), "bundle artifact sizes must fit uint64_t manifests");

/**
 * @brief Convert one filesystem failure into a stable bundle-admission status.
 *
 * @param operation Description of the failed filesystem operation.
 * @param path Path involved in the failure.
 * @param error Filesystem error code.
 * @return NOT_FOUND for an absent path, or INTERNAL for another filesystem
 *         failure.
 */
status filesystem_failure(const std::string &operation, const fs::path &path, const std::error_code &error)
{
	if (error == std::errc::no_such_file_or_directory) {
		return status(status_code::NOT_FOUND, operation, path.string());
	}
	return status(status_code::INTERNAL_ERROR, operation, path.string() + ": " + error.message());
}

/**
 * @brief Resolve an existing path without symlink or invalid component traversal.
 *
 * @param input Existing file or directory path to inspect component by
 *              component.
 * @param role Diagnostic name for the path's bundle role.
 * @return Lexically normalized absolute path, or a fail-closed filesystem,
 *         non-directory traversal, or symlink error.
 */
status_or<fs::path> absolute_path_without_symlinks(const fs::path &input, const std::string &role)
{
	std::error_code ec;
	fs::path absolute = input;
	if (!input.is_absolute()) {
		const auto current_directory = fs::current_path(ec);
		if (ec) {
			return filesystem_failure("failed to resolve " + role, input, ec);
		}
		absolute = current_directory / input;
	}

	fs::path current;
	for (const auto &component : absolute) {
		if (component == fs::path(".")) {
			continue;
		}
		if (component == fs::path("..")) {
			// Kernel path traversal can cross ".." only through a directory.
			// Preserve that rule before lexical cancellation so an invalid
			// regular-file/../bundle path cannot redirect verification.
			const auto path_status = fs::symlink_status(current, ec);
			if (ec) {
				return filesystem_failure("failed to inspect " + role, current, ec);
			}
			if (!fs::is_directory(path_status)) {
				return status(status_code::FAILED_PRECONDITION,
					      role + " contains a non-directory path component", current.string());
			}
			current = current.parent_path();
			continue;
		}
		current /= component;
		const auto path_status = fs::symlink_status(current, ec);
		if (ec) {
			return filesystem_failure("failed to inspect " + role, current, ec);
		}
		if (!fs::exists(path_status)) {
			return status(status_code::NOT_FOUND, role + " does not exist", current.string());
		}
		if (fs::is_symlink(path_status)) {
			return status(status_code::FAILED_PRECONDITION,
				      role + " must not contain a symbolic-link component", current.string());
		}
	}

	return current.lexically_normal();
}

/**
 * @brief Require the physical tree to equal manifest files and their parents.
 *
 * @param root Absolute symlink-free bundle root.
 * @param manifest Canonical manifest whose paths own the complete file tree.
 * @return OK when every descendant is direct and manifest-derived, or the
 *         first traversal, indirection, membership, or runtime-owner failure.
 */
status validate_bundle_tree_entries(const fs::path &root, const bundle_manifest &manifest)
{
	std::unordered_set<std::string> expected_files;
	std::unordered_set<std::string> expected_directories;
	expected_files.reserve(manifest.files.size() + 1u);
	expected_files.emplace(MANIFEST_FILENAME);
	for (const auto &entry : manifest.files) {
		expected_files.emplace(entry.rel_path);
		fs::path parent = fs::path(entry.rel_path).parent_path();
		while (!parent.empty() && parent != fs::path(".")) {
			expected_directories.emplace(parent.generic_string());
			parent = parent.parent_path();
		}
	}

	std::error_code ec;
	fs::recursive_directory_iterator iterator(root, fs::directory_options::none, ec);
	if (ec) {
		return filesystem_failure("failed to inspect bundle tree", root, ec);
	}
	const fs::recursive_directory_iterator end;
	while (iterator != end) {
		const fs::path relative = iterator->path().lexically_relative(root);
		const std::string relative_text = relative.generic_string();
		if (!relative.empty() && *relative.begin() == fs::path("bin")) {
			return status(status_code::FAILED_PRECONDITION,
				      "deployment bundle must not contain a runtime bin directory", relative.string());
		}
		const auto entry_status = iterator->symlink_status(ec);
		if (ec) {
			return filesystem_failure("failed to inspect bundle entry", iterator->path(), ec);
		}
		if (fs::is_symlink(entry_status)) {
			return status(status_code::FAILED_PRECONDITION,
				      "runtime bundle must not contain symbolic links", iterator->path().string());
		}
		if (!fs::is_directory(entry_status) && !fs::is_regular_file(entry_status)) {
			return status(status_code::FAILED_PRECONDITION,
				      "runtime bundle contains an unsupported filesystem object",
				      iterator->path().string());
		}
		if (fs::is_directory(entry_status)) {
			if (expected_directories.find(relative_text) == expected_directories.end()) {
				return status(status_code::FAILED_PRECONDITION,
					      "runtime bundle contains an undeclared directory", relative_text);
			}
		} else if (expected_files.find(relative_text) == expected_files.end()) {
			return status(status_code::FAILED_PRECONDITION, "runtime bundle contains an undeclared file",
				      relative_text);
		}
		iterator.increment(ec);
		if (ec) {
			return filesystem_failure("failed to traverse bundle tree", root, ec);
		}
	}
	return status::ok();
}

/**
 * @brief Find one required canonical artifact entry in a parsed manifest.
 *
 * @param manifest Parsed bundle manifest.
 * @param relative_path Exact manifest-relative path required by runtime.
 * @return Pointer to the manifest-owned entry, or NOT_FOUND. Duplicate paths
 *         have already failed manifest parsing.
 */
status_or<const bundle_file_entry *> required_manifest_entry(const bundle_manifest &manifest,
							     std::string_view relative_path)
{
	const auto entry = std::lower_bound(manifest.files.begin(), manifest.files.end(), relative_path,
					    [](const bundle_file_entry &candidate, std::string_view path) {
						    return candidate.rel_path < path;
					    });
	if (entry != manifest.files.end() && entry->rel_path == relative_path) {
		return &*entry;
	}
	return status(status_code::NOT_FOUND, "runtime bundle is missing required canonical artifact",
		      std::string(relative_path));
}

/**
 * @brief Read exact artifact bytes and recheck their manifest binding.
 *
 * @param path Canonical absolute artifact path.
 * @param entry Parsed manifest entry for that exact path.
 * @return Exact verified bytes, or a bounded read, size, or SHA-256 failure.
 */
status_or<std::string> read_manifest_bound_bytes(const fs::path &path, const bundle_file_entry &entry)
{
	if (entry.size_bytes > static_cast<uint64_t>(MAX_RUNTIME_BUNDLE_PBTXT_BYTES)) {
		return status::resource_exhausted("bundle protobuf-text artifact exceeds its read bound");
	}
	auto bytes_or = kinetum::common::read_file_to_string(path.string(), MAX_RUNTIME_BUNDLE_PBTXT_BYTES);
	if (!bytes_or.is_ok()) {
		return bytes_or.error();
	}
	const auto &bytes = bytes_or.value();
	if (static_cast<uint64_t>(bytes.size()) != entry.size_bytes) {
		return status(status_code::FAILED_PRECONDITION,
			      "bundle artifact changed after manifest verification: size mismatch", entry.rel_path);
	}

	auto hash_or = kinetum::common::sha256_hex(bytes);
	if (!hash_or.is_ok()) {
		return hash_or.error();
	}
	if (hash_or.value() != entry.sha256_hex) {
		return status(status_code::FAILED_PRECONDITION,
			      "bundle artifact changed after manifest verification: SHA-256 mismatch", entry.rel_path);
	}
	return bytes;
}

/**
 * @brief Normalize one already parsed bootstrap snapshot.
 *
 * @param snapshot Candidate complete snapshot.
 * @param plan Exact verified deployment plan.
 * @return Canonical snapshot and validation hash, or the canonicalizer/parser
 *         failure.
 */
status_or<normalized_bootstrap_snapshot> normalize_parsed_snapshot(const kinetum::control::v1::ConfigSnapshot &snapshot,
								   const kinetum::gluon::v1::DeploymentPlan &plan)
{
	auto canonical_or = kinetum::common::canonicalize_config_snapshot(snapshot, plan);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	auto canonical = std::move(canonical_or).value();

	normalized_bootstrap_snapshot normalized;
	if (!normalized.snapshot.ParseFromString(canonical.serialized_bytes)) {
		return status(status_code::INTERNAL_ERROR, "failed to parse canonical bootstrap snapshot bytes");
	}
	normalized.validation_hash = canonical.validation_hash;
	return normalized;
}

/**
 * @brief Resolve the complete sorted main-module image set from compiled truth.
 *
 * @param root Canonical symlink-free bundle root.
 * @param manifest Parsed and completely verified bundle manifest.
 * @param topology Sole compiled provider topology for the verified plan.
 * @return Sorted unique module identities and canonical main-image paths, or
 *         the first unsafe identity, authored path, missing manifest row, or
 *         filesystem-indirection failure.
 */
status_or<std::vector<verified_module_image>>
resolve_verified_module_images(const fs::path &root, const bundle_manifest &manifest,
			       const kinetum::provider::compiled_provider_topology &topology)
{
	std::vector<std::string> module_ids;
	module_ids.reserve(topology.logical_stages.size());
	for (const auto &stage : topology.logical_stages) {
		if (stage.module_id.empty()) {
			continue;
		}
		if (stage.module_path.has_value()) {
			return status(status_code::FAILED_PRECONDITION,
				      "runtime-bundle module stage must not carry a direct-development module path",
				      stage.logical_stage_id);
		}
		if (!is_safe_bundle_module_atom(stage.module_id)) {
			return status(status_code::INVALID_ARGUMENT,
				      "runtime-bundle module identity is not a safe path atom", stage.module_id);
		}
		module_ids.push_back(stage.module_id);
	}

	std::sort(module_ids.begin(), module_ids.end());
	module_ids.erase(std::unique(module_ids.begin(), module_ids.end()), module_ids.end());

	std::vector<verified_module_image> images;
	images.reserve(module_ids.size());
	for (const auto &module_id : module_ids) {
		const std::string relative_path = "modules/" + module_id + ".so";
		auto entry_or = required_manifest_entry(manifest, relative_path);
		if (!entry_or.is_ok()) {
			return entry_or.error();
		}
		auto path_or = absolute_path_without_symlinks(root / relative_path, "runtime bundle module image");
		if (!path_or.is_ok()) {
			return path_or.error();
		}
		images.push_back(verified_module_image{.module_id = module_id, .image_path = path_or.value().string()});
	}
	return images;
}

}  // namespace

status_or<normalized_bootstrap_snapshot>
load_and_normalize_bootstrap_snapshot(const std::string &snapshot_path, const kinetum::gluon::v1::DeploymentPlan &plan)
{
	const auto plan_status = kinetum::provider::verify_deployment_plan_content_hash(plan);
	if (!plan_status.is_ok()) {
		return plan_status;
	}
	const auto compiled_provider_or = kinetum::provider::compile_provider_topology(plan);
	if (!compiled_provider_or.is_ok()) {
		return compiled_provider_or.error();
	}

	auto snapshot_text_or = kinetum::common::read_file_to_string(snapshot_path, MAX_RUNTIME_BUNDLE_PBTXT_BYTES);
	if (!snapshot_text_or.is_ok()) {
		return snapshot_text_or.error();
	}
	kinetum::control::v1::ConfigSnapshot snapshot;
	const auto parse_status = kinetum::common::parse_pbtxt_text(snapshot_text_or.value(), snapshot_path, &snapshot);
	if (!parse_status.is_ok()) {
		return parse_status;
	}
	return normalize_parsed_snapshot(snapshot, plan);
}

status_or<verified_runtime_bundle> verify_runtime_bundle(const std::string &bundle_root)
{
	if (bundle_root.empty() || bundle_root.find('\0') != std::string::npos) {
		return status(status_code::INVALID_ARGUMENT,
			      "runtime bundle root must be nonempty and contain no embedded NUL byte");
	}

	auto root_or = absolute_path_without_symlinks(fs::path(bundle_root), "runtime bundle root");
	if (!root_or.is_ok()) {
		return root_or.error();
	}
	const fs::path root = std::move(root_or).value();

	std::error_code ec;
	const auto root_status = fs::status(root, ec);
	if (ec) {
		return filesystem_failure("failed to inspect runtime bundle root", root, ec);
	}
	if (!fs::is_directory(root_status)) {
		return status(status_code::INVALID_ARGUMENT, "runtime bundle root is not a directory", root.string());
	}

	const fs::path manifest_path = root / std::string(MANIFEST_FILENAME);
	auto manifest_path_or = absolute_path_without_symlinks(manifest_path, "runtime bundle manifest");
	if (!manifest_path_or.is_ok()) {
		return manifest_path_or.error();
	}
	auto manifest_text_or =
		kinetum::common::read_file_to_string(manifest_path_or.value().string(), MAX_MANIFEST_SIZE + 1);
	if (!manifest_text_or.is_ok()) {
		return manifest_text_or.error();
	}
	auto manifest_or = bundle_manifest::from_text(manifest_text_or.value());
	if (!manifest_or.is_ok()) {
		return manifest_or.error();
	}
	const auto &manifest = manifest_or.value();
	const auto tree_status = validate_bundle_tree_entries(root, manifest);
	if (!tree_status.is_ok()) {
		return tree_status;
	}

	auto plan_entry_or = required_manifest_entry(manifest, RUNTIME_PLAN_RELATIVE_PATH);
	if (!plan_entry_or.is_ok()) {
		return plan_entry_or.error();
	}
	auto snapshot_entry_or = required_manifest_entry(manifest, BOOTSTRAP_SNAPSHOT_RELATIVE_PATH);
	if (!snapshot_entry_or.is_ok()) {
		return snapshot_entry_or.error();
	}

	const auto manifest_status = verify_manifest(root.string(), manifest_text_or.value());
	if (!manifest_status.is_ok()) {
		return manifest_status;
	}

	auto plan_path_or = absolute_path_without_symlinks(root / std::string(RUNTIME_PLAN_RELATIVE_PATH),
							   "runtime bundle deployment plan");
	if (!plan_path_or.is_ok()) {
		return plan_path_or.error();
	}
	auto snapshot_path_or = absolute_path_without_symlinks(root / std::string(BOOTSTRAP_SNAPSHOT_RELATIVE_PATH),
							       "runtime bundle bootstrap snapshot");
	if (!snapshot_path_or.is_ok()) {
		return snapshot_path_or.error();
	}

	auto plan_text_or = read_manifest_bound_bytes(plan_path_or.value(), *plan_entry_or.value());
	if (!plan_text_or.is_ok()) {
		return plan_text_or.error();
	}
	kinetum::gluon::v1::DeploymentPlan plan;
	const auto plan_parse_status =
		kinetum::common::parse_pbtxt_text(plan_text_or.value(), plan_path_or.value().string(), &plan);
	if (!plan_parse_status.is_ok()) {
		return plan_parse_status;
	}
	const auto plan_identity_status = kinetum::provider::verify_deployment_plan_content_hash(plan);
	if (!plan_identity_status.is_ok()) {
		return plan_identity_status;
	}
	auto compiled_provider_or = kinetum::provider::compile_provider_topology(plan);
	if (!compiled_provider_or.is_ok()) {
		return compiled_provider_or.error();
	}
	auto compiled_topology = std::move(compiled_provider_or).value();

	auto module_images_or = resolve_verified_module_images(root, manifest, compiled_topology);
	if (!module_images_or.is_ok()) {
		return module_images_or.error();
	}

	auto snapshot_text_or = read_manifest_bound_bytes(snapshot_path_or.value(), *snapshot_entry_or.value());
	if (!snapshot_text_or.is_ok()) {
		return snapshot_text_or.error();
	}
	kinetum::control::v1::ConfigSnapshot snapshot;
	const auto snapshot_parse_status = kinetum::common::parse_pbtxt_text(
		snapshot_text_or.value(), snapshot_path_or.value().string(), &snapshot);
	if (!snapshot_parse_status.is_ok()) {
		return snapshot_parse_status;
	}
	auto normalized_or = normalize_parsed_snapshot(snapshot, plan);
	if (!normalized_or.is_ok()) {
		return normalized_or.error();
	}
	auto normalized = std::move(normalized_or).value();

	verified_runtime_bundle verified;
	verified.bundle_root = root.string();
	verified.plan_path = plan_path_or.value().string();
	verified.bootstrap_snapshot_path = snapshot_path_or.value().string();
	verified.plan = std::move(plan);
	verified.compiled_topology = std::move(compiled_topology);
	verified.module_images = std::move(module_images_or).value();
	verified.bootstrap_snapshot = std::move(normalized.snapshot);
	verified.bootstrap_validation_hash = normalized.validation_hash;
	return verified;
}

}  // namespace kinetum::pack
