// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file pack_source_admission.cpp
 * @brief Deployment-bundle source-artifact admission implementation.
 * @author Fleming Patel
 */

#include "src/pack/pack_source_admission.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <string>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

#include "src/common/path_admission.hpp"
#include "src/common/status.hpp"

namespace kinetum::pack
{
namespace
{

namespace fs = std::filesystem;

/**
 * @param filename Borrowed direct-child filename under consideration.
 * @return true when the name contains a final .so suffix or a .so. version suffix.
 */
[[nodiscard]] bool is_shared_object_filename(std::string_view filename) noexcept
{
	const std::size_t marker = filename.find(".so");
	return marker != std::string_view::npos && (marker + 3 == filename.size() || filename[marker + 3] == '.');
}

}  // namespace

bool is_safe_bundle_module_atom(std::string_view value) noexcept
{
	if (value.empty() || value == "." || value == "..") {
		return false;
	}
	for (const char character : value) {
		const bool valid = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				   (character >= '0' && character <= '9') || character == '.' || character == '_' ||
				   character == '-';
		if (!valid) {
			return false;
		}
	}
	return true;
}

kinetum::common::status_or<builtin_module_image> resolve_builtin_module_image(std::string_view module_id)
{
	if (module_id == "kinetum.acl") {
		return builtin_module_image{.source_filename = "libkinetum_acl.so"};
	}
	if (module_id == "kinetum.nat44") {
		return builtin_module_image{.source_filename = "libkinetum_nat44.so"};
	}
	if (module_id == "kinetum.qos") {
		return builtin_module_image{.source_filename = "libkinetum_qos.so"};
	}
	return kinetum::common::status::invalid_argument("unknown reserved built-in module_id '" +
							 std::string(module_id) + "'");
}

kinetum::common::status_or<admitted_pack_sources> admit_pack_sources(const pack_source_spec &spec)
{
	auto pipeline_or = kinetum::common::admit_explicit_regular_file(spec.pipeline, "Axiom pipeline source");
	if (!pipeline_or.is_ok()) {
		return pipeline_or.error();
	}
	auto hardware_or = kinetum::common::admit_explicit_regular_file(spec.hardware, "hardware inventory source");
	if (!hardware_or.is_ok()) {
		return hardware_or.error();
	}
	auto snapshot_or =
		kinetum::common::admit_explicit_regular_file(spec.bootstrap_snapshot, "bootstrap snapshot source");
	if (!snapshot_or.is_ok()) {
		return snapshot_or.error();
	}

	auto bindings_or =
		kinetum::common::admit_explicit_regular_file(spec.deployment_bindings, "deployment bindings source");
	if (!bindings_or.is_ok()) {
		return bindings_or.error();
	}

	std::optional<std::filesystem::path> module_directory;
	if (spec.module_directory.has_value()) {
		auto module_or =
			kinetum::common::admit_explicit_directory(*spec.module_directory, "module source directory");
		if (!module_or.is_ok()) {
			return module_or.error();
		}
		module_directory = std::move(module_or).value();
	}

	admitted_pack_sources sources;
	sources.pipeline = std::move(pipeline_or).value();
	sources.hardware = std::move(hardware_or).value();
	sources.bootstrap_snapshot = std::move(snapshot_or).value();
	sources.deployment_bindings = std::move(bindings_or).value();
	sources.module_directory = std::move(module_directory);
	return sources;
}

kinetum::common::status_or<std::vector<admitted_module_dependency>>
admit_module_dependencies(const std::filesystem::path &module_directory,
			  const std::unordered_map<std::string, std::filesystem::path> &main_sources)
{
	const auto directory_status =
		kinetum::common::validate_exact_directory(module_directory, "module source directory");
	if (!directory_status.is_ok()) {
		return directory_status;
	}

	std::unordered_set<std::string> main_paths;
	main_paths.reserve(main_sources.size());
	for (const auto &[module_id, source] : main_sources) {
		(void)module_id;
		main_paths.insert(source.string());
	}

	std::vector<admitted_module_dependency> dependencies;
	std::unordered_set<std::string> dependency_names;
	std::error_code iteration_error;
	for (fs::directory_iterator iterator(module_directory, iteration_error), end;
	     iterator != end && !iteration_error; iterator.increment(iteration_error)) {
		const std::string filename = iterator->path().filename().string();
		if (!is_shared_object_filename(filename)) {
			continue;
		}
		if (!is_safe_bundle_module_atom(filename)) {
			return kinetum::common::status::invalid_argument(
				"module dependency filename is not bundle-safe: '" + filename + "'");
		}

		const fs::path source = iterator->path().lexically_normal();
		const auto source_status =
			kinetum::common::validate_exact_regular_file(source, "module dependency source");
		if (!source_status.is_ok()) {
			return source_status;
		}
		if (main_paths.contains(source.string())) {
			continue;
		}
		if (!dependency_names.insert(filename).second) {
			return kinetum::common::status::invalid_argument(
				"module source directory contains duplicate dependency basename '" + filename + "'");
		}
		dependencies.push_back(admitted_module_dependency{.filename = filename, .source = source});
	}
	if (iteration_error) {
		return kinetum::common::status(kinetum::common::status_code::INTERNAL_ERROR,
					       "failed to enumerate module source directory",
					       module_directory.string() + ": " + iteration_error.message());
	}

	std::sort(dependencies.begin(), dependencies.end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.filename < rhs.filename; });
	return dependencies;
}

}  // namespace kinetum::pack
