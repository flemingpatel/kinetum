// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_verification.hpp
 * @brief Shared static verification of a complete runtime installation.
 * @author Fleming Patel
 *
 * The information tool and package installer consume one independent runtime
 * assertion. CMake remains the producer membership authority. Verification
 * never loads a component, executes target code, or admits signing inputs.
 */

#include <filesystem>
#include <span>
#include <string_view>
#include <utility>

#include "src/common/held_file.hpp"
#include "src/common/status.hpp"
#include "src/provider/provider_target_tuple.hpp"

namespace kinetum::release
{

/** Exact runtime-manifest path; its contents never contain its own row. */
inline constexpr std::string_view RUNTIME_PAYLOAD_MANIFEST = "share/kinetum/release/runtime_payload_manifest.sha256";

/** One independent expected artifact and its presentation role. */
struct runtime_artifact {
	std::string_view relative_path;	 ///< Canonical path below the runtime root.
	std::string_view description;	 ///< Operator-facing role, unchanged by rendering.
};

/** Immutable outcomes of the two independent runtime checks. */
struct runtime_verification_result {
	/**
	 * @brief Construct both observed outcomes without an implicit successful default.
	 * @param payload_result Complete manifest and membership outcome to own.
	 * @param provider_result Independent signature/static-closure outcome to own.
	 */
	runtime_verification_result(common::status payload_result, common::status provider_result)
		: payload(std::move(payload_result))
		, provider(std::move(provider_result))
	{
	}

	const common::status payload;	///< Complete runtime payload integrity.
	const common::status provider;	///< Release-anchor authentication and static provider closure.
};

/** @return The immutable verifier assertion, never a producer file-selection table. */
[[nodiscard]] std::span<const runtime_artifact> expected_runtime_artifacts() noexcept;

/**
 * @brief Verify a complete runtime package payload without installed-peer exemptions.
 * @param root Exact private runtime payload root.
 * @param target Admitted target tuple; static verification may inspect either supported tuple.
 * @param policy Filesystem authority selected by the installed/staged caller.
 * @return Both independent check outcomes for the complete private payload.
 * @throws std::bad_alloc, std::length_error At the owning cold process boundary.
 */
[[nodiscard]] runtime_verification_result verify_runtime_payload(const std::filesystem::path &root,
								 provider::provider_target_tuple target,
								 const common::held_file_policy &policy);

/**
 * @brief Verify the installed runtime while preserving independent SDK/dependency peers.
 * @param root Exact installed runtime root.
 * @param target Exact runtime target tuple.
 * @param policy Installed file/directory ownership authority.
 * @return Independent runtime payload and provider outcomes; peer contents are outside this domain.
 * @throws std::bad_alloc, std::length_error At the owning cold process boundary.
 */
[[nodiscard]] runtime_verification_result verify_installed_runtime(const std::filesystem::path &root,
								   provider::provider_target_tuple target,
								   const common::held_file_policy &policy);

}  // namespace kinetum::release
