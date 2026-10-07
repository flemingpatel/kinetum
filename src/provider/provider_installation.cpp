// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_installation.cpp
 * @brief Fixed provider-release installation authority implementation.
 * @author Fleming Patel
 */

#include "src/provider/provider_installation.hpp"

#include <optional>
#include <string>
#include <utility>

#include <sys/stat.h>

#include "src/common/process_image.hpp"
#include "src/common/status.hpp"

namespace kinetum::provider
{
namespace
{

/** UID owning every production runtime artifact and directory. */
constexpr uint32_t PRODUCTION_OWNER_UID = 0;

/** Group/world write permissions forbidden from production release state. */
constexpr uint32_t PRODUCTION_FORBIDDEN_MODE_BITS = S_IWGRP | S_IWOTH;

}  // namespace

common::status validate_provider_installation_root(const std::filesystem::path &root)
{
	if (root.empty() || !root.is_absolute() || root != root.lexically_normal() || root == root.root_path()) {
		return common::status::invalid_argument(
			"provider installation root must be an exact absolute normalized non-root path");
	}
	return common::status::ok();
}

common::status_or<provider_process_installation> current_provider_process_installation()
{
	auto image_or = common::current_process_image();
	if (!image_or.is_ok()) {
		return image_or.error();
	}
	const std::filesystem::path image = std::move(image_or).value();
	if (image.filename() != "kinetum_dp" || image.parent_path().filename() != "bin") {
		return common::status::failed_precondition(
			"running dataplane image must have exact installed shape <root>/bin/kinetum_dp");
	}
	const std::filesystem::path root = image.parent_path().parent_path();
	const auto root_status = validate_provider_installation_root(root);
	if (!root_status.is_ok()) {
		return root_status;
	}
	const std::filesystem::path expected =
		(root / std::filesystem::path(std::string(PROVIDER_RUNTIME_RELATIVE_PATH))).lexically_normal();
	if (image != expected) {
		return common::status::failed_precondition(
			"running dataplane image disagrees with the fixed provider installation layout");
	}
	return provider_process_installation{root, image};
}

common::held_file_policy production_provider_file_policy(const std::filesystem::path &root)
{
	return common::held_file_policy{
		.required_owner_uid = PRODUCTION_OWNER_UID,
		.forbidden_mode_bits = PRODUCTION_FORBIDDEN_MODE_BITS,
		.require_single_link = true,
		.directories =
			common::held_directory_policy{
				.root = root,
				.required_owner_uid = PRODUCTION_OWNER_UID,
				.forbidden_mode_bits = PRODUCTION_FORBIDDEN_MODE_BITS,
			},
		.maximum_size_bytes = std::nullopt,
	};
}

common::held_file_policy release_candidate_file_policy(const std::filesystem::path &root, uint32_t owner_uid)
{
	return common::held_file_policy{
		.required_owner_uid = owner_uid,
		.forbidden_mode_bits = PRODUCTION_FORBIDDEN_MODE_BITS,
		.require_single_link = true,
		.directories =
			common::held_directory_policy{
				.root = root,
				.required_owner_uid = owner_uid,
				.forbidden_mode_bits = PRODUCTION_FORBIDDEN_MODE_BITS,
			},
		.maximum_size_bytes = std::nullopt,
	};
}

}  // namespace kinetum::provider
