// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_inventory_reconstruction.hpp
 * @brief Static exact-target provider inventory reconstruction.
 * @author Fleming Patel
 *
 * A release aggregate supplies one explicit runtime image, explicit completed
 * component outputs with source-controlled descriptor claims, and explicit
 * private artifacts. This authority hashes and inspects those exact files for
 * an explicit target tuple, constructs canonical inventory metadata, and
 * preflights the complete artifact closure without loading code.
 *
 * The target has no dynamic-loader dependency. Native release preparation may
 * compose its proof with component admission, while an architecture-neutral
 * finalizer can apply the same proof to foreign target artifacts.
 *
 * @par Thread Safety
 * Operations are stateless. Input paths and files must not mutate during a
 * call; retained descriptors bind every successful artifact proof.
 */

#include <filesystem>
#include <string>
#include <vector>

#include "gen/kinetum/provider/v1/installed_provider_inventory.pb.h"
#include "src/common/held_file.hpp"
#include "src/common/status_or.hpp"
#include "src/provider/provider_component_preflight.hpp"
#include "src/provider/provider_target_tuple.hpp"

namespace kinetum::provider
{

/** Explicit release-owned component output and descriptor claims. */
struct release_provider_component_input {
	std::string component_id;		      ///< Stable source-controlled component identity.
	std::filesystem::path path;		      ///< Exact completed shared-object path.
	std::vector<std::string> contract_type_urls;  ///< Exact source-controlled contract set.
};

/** Explicit release-owned private dependency output. */
struct release_provider_private_artifact_input {
	std::filesystem::path path;  ///< Exact completed private shared-object path.
	std::string soname;	     ///< Exact source-controlled DT_SONAME claim.
};

/** Canonical target-tuple inventory and its complete static preflight proof. */
struct reconstructed_provider_inventory {
	kinetum::provider::v1::InstalledProviderInventory inventory;  ///< Canonical parsed authority.
	std::string canonical_bytes;				      ///< Exact deterministic wire bytes.
	std::vector<preflighted_provider_component> components;	      ///< Complete held static proof set.
};

/**
 * @brief Reconstruct and statically preflight one complete provider inventory.
 *
 * This operation never signs, loads, or executes an artifact. Runtime-image,
 * component, and private-artifact ELF facts are selected by @p target rather
 * than the architecture of the inspecting process.
 *
 * @param runtime_image Exact completed runtime image.
 * @param artifact_directory Exact common parent of every component/private
 *        artifact.
 * @param components Explicit complete component outputs.
 * @param private_artifacts Explicit complete private dependency outputs.
 * @param target Exact release target tuple.
 * @param file_policy Exact staging owner/mode/link and directory policy.
 * @return Canonical inventory bytes and complete static preflight proof.
 */
[[nodiscard]] common::status_or<reconstructed_provider_inventory>
reconstruct_provider_inventory(const std::filesystem::path &runtime_image,
			       const std::filesystem::path &artifact_directory,
			       std::vector<release_provider_component_input> components,
			       std::vector<release_provider_private_artifact_input> private_artifacts,
			       provider_target_tuple target, const common::held_file_policy &file_policy);

}  // namespace kinetum::provider
