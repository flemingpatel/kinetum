// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file package_release.hpp
 * @brief Separate native preparation and static signing of provider releases.
 * @author Fleming Patel
 *
 * Preparation runs in a disposable native process without signing inputs.
 * Finalization reconstructs the candidate from held files and never executes
 * component code. The combined packaging image contains both operations;
 * their invocation and key lifetimes, rather than image symbol absence,
 * enforce the signing boundary.
 */

#include <cstdint>
#include <filesystem>

#include "tooling/release/packaging/provider_release_signing_key.hpp"
#include "src/common/status.hpp"
#include "src/provider/provider_target_tuple.hpp"

namespace kinetum::release
{

/**
 * @brief Reconstruct and self-admit a native runtime before publishing evidence.
 * @param candidate_root Exact private staged runtime root.
 * @param target Native target tuple; a different tuple rejects.
 * @param candidate_owner_uid Exact staged-file and directory owner.
 * @return OK after complete static reconstruction, dynamic self-admission, and
 *         verified inventory/receipt publication. No signature is produced.
 * @note The packaging command owns the disposable worker and never supplies
 *       signing inputs to preparation. Library conformance alone does not
 *       qualify that process boundary.
 */
[[nodiscard]] common::status prepare_provider_release_candidate(const std::filesystem::path &candidate_root,
								provider::provider_target_tuple target,
								uint32_t candidate_owner_uid);

/**
 * @brief Statically reconstruct, sign, and verify one native or foreign candidate.
 * @param candidate_root Exact private extracted runtime root.
 * @param target Target tuple represented by the candidate's ELF files.
 * @param candidate_owner_uid Exact candidate-file and directory owner.
 * @param signing_key Admitted key deriving the configured production anchor.
 * @param expected_anchor Sole public anchor for final static verification.
 * @return OK only after reconstruction, native-receipt equality, signing, and
 *         verification of the signed closure. No target code is executed.
 */
[[nodiscard]] common::status finalize_provider_release_candidate(const std::filesystem::path &candidate_root,
								 provider::provider_target_tuple target,
								 uint32_t candidate_owner_uid,
								 const provider_release_signing_key &signing_key,
								 const common::ed25519_public_key &expected_anchor);

}  // namespace kinetum::release
