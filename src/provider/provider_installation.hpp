// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_installation.hpp
 * @brief Fixed provider-release layout and production installation authority.
 * @author Fleming Patel
 *
 * Provider loading begins from one exact installed process image. This
 * authority owns the immutable relative layout, derives the installation root
 * from `/proc/self/exe` without a caller override, and constructs the
 * root-owned file policy used by production DP and static installation
 * verification. Generic loader and preflight mechanisms continue to accept an
 * explicit root and policy so test fixtures remain injectable.
 *
 * @par Thread Safety
 * The operations are stateless cold-path functions and may run concurrently.
 */

#include <cstdint>
#include <filesystem>
#include <string_view>

#include "src/common/held_file.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::provider
{

/** Fixed runtime executable path beneath one installation root. */
inline constexpr std::string_view PROVIDER_RUNTIME_RELATIVE_PATH = "bin/kinetum_dp";

/** Fixed provider artifact directory beneath one installation root. */
inline constexpr std::string_view PROVIDER_ARTIFACT_DIRECTORY = "lib/kinetum/providers";

/** Fixed canonical inventory path beneath one installation root. */
inline constexpr std::string_view PROVIDER_INVENTORY_RELATIVE_PATH =
	"share/kinetum/providers/installed_provider_inventory.pb";

/** Fixed detached inventory-signature path beneath one installation root. */
inline constexpr std::string_view PROVIDER_INVENTORY_SIGNATURE_RELATIVE_PATH =
	"share/kinetum/providers/installed_provider_inventory.pb.sig";

/** Fixed native self-admission receipt path beneath one candidate root. */
inline constexpr std::string_view PROVIDER_ADMISSION_RECEIPT_RELATIVE_PATH =
	"share/kinetum/release/native_provider_admission_receipt.pb";

/** Exact process image and installation root derived from kernel authority. */
struct provider_process_installation {
	std::filesystem::path root;	      ///< Canonical installation root.
	std::filesystem::path runtime_image;  ///< Exact `<root>/bin/kinetum_dp` image.
};

/**
 * @brief Validate one explicit installation-root representation.
 *
 * This validates representation only. Artifact traversal and directory
 * authority are enforced later through the caller's held-file policy.
 *
 * @param root Candidate installation root.
 * @return OK only for an exact absolute normalized non-root path.
 */
[[nodiscard]] common::status validate_provider_installation_root(const std::filesystem::path &root);

/**
 * @brief Derive the production installation from the running DP image.
 *
 * `/proc/self/exe` must resolve exactly to `<root>/bin/kinetum_dp`. No CLI,
 * environment, current-directory, or default-prefix fallback is consulted.
 *
 * @return Exact process installation, or a fail-closed shape/provenance error.
 */
[[nodiscard]] common::status_or<provider_process_installation> current_provider_process_installation();

/**
 * @brief Construct the production root-owned artifact policy.
 *
 * Every file must be owned by UID 0, omit group/world write bits, and have one
 * link. The installation root and every traversed descendant directory must
 * be root-owned and omit the same write bits.
 *
 * @param root Exact validated installation root.
 * @return Production held-file policy rooted at @p root.
 */
[[nodiscard]] common::held_file_policy production_provider_file_policy(const std::filesystem::path &root);

/**
 * @brief Construct the exact policy for a private release-candidate root.
 *
 * Candidate preparation and architecture-neutral finalization run as their
 * unprivileged release owner. Every file and traversed directory must belong
 * to @p owner_uid, omit group/world write bits, and every file must have one
 * link. Final installation deliberately replaces this policy with the
 * root-owned production policy above.
 *
 * @param root Exact validated candidate root.
 * @param owner_uid Exact release-process owner UID.
 * @return Candidate held-file policy rooted at @p root.
 */
[[nodiscard]] common::held_file_policy release_candidate_file_policy(const std::filesystem::path &root,
								     uint32_t owner_uid);

}  // namespace kinetum::provider
