// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_target_tuple.hpp
 * @brief Exact supported target identities for provider artifact admission.
 * @author Fleming Patel
 *
 * Provider artifacts are inspected without executing target code. This
 * authority gives native runtime admission and architecture-neutral release
 * finalization one closed spelling for ELF class, machine, byte order, and
 * runtime-loader policy selection.
 */

#include <cstdint>
#include <string_view>

#include "src/common/status_or.hpp"

namespace kinetum::provider
{

/** @brief Supported Linux GNU target tuple for one exact release closure. */
enum class provider_target_tuple : uint8_t {
	LINUX_GNU_AARCH64,  ///< 64-bit little-endian AArch64 GNU/Linux.
	LINUX_GNU_X86_64,   ///< 64-bit little-endian x86-64 GNU/Linux.
};

/** @brief Canonical AArch64 release-target spelling. */
inline constexpr std::string_view LINUX_GNU_AARCH64_TARGET_TUPLE = "linux-gnu-aarch64";

/** @brief Canonical x86-64 release-target spelling. */
inline constexpr std::string_view LINUX_GNU_X86_64_TARGET_TUPLE = "linux-gnu-x86_64";

/** @brief Exact AArch64 GNU/Linux runtime-loader SONAME. */
inline constexpr std::string_view LINUX_GNU_AARCH64_RUNTIME_LOADER_SONAME = "ld-linux-aarch64.so.1";

/** @brief Exact x86-64 GNU/Linux runtime-loader SONAME. */
inline constexpr std::string_view LINUX_GNU_X86_64_RUNTIME_LOADER_SONAME = "ld-linux-x86-64.so.2";

/**
 * @brief Parse one canonical target-tuple spelling.
 *
 * @param value Candidate complete tuple identity.
 * @return Exact supported tuple, or INVALID_ARGUMENT without normalization.
 */
[[nodiscard]] common::status_or<provider_target_tuple> parse_provider_target_tuple(std::string_view value);

/**
 * @brief Return one target tuple's canonical spelling.
 *
 * @param target Exact supported target tuple.
 * @return Stable source-controlled tuple identity.
 */
[[nodiscard]] std::string_view provider_target_tuple_name(provider_target_tuple target) noexcept;

/**
 * @brief Return the tuple of the currently compiled process.
 *
 * @return Exact native tuple. Unsupported build architectures fail at compile
 *         time rather than creating an approximate identity.
 */
[[nodiscard]] provider_target_tuple native_provider_target_tuple() noexcept;

/**
 * @brief Return the exact runtime-loader SONAME for one tuple.
 *
 * @param target Exact supported target tuple.
 * @return Canonical GNU/Linux runtime-loader SONAME.
 */
[[nodiscard]] std::string_view provider_runtime_loader_soname(provider_target_tuple target) noexcept;

}  // namespace kinetum::provider
