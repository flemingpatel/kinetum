// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file sha256_digest.hpp
 * @brief Fixed-width SHA-256 digest value type.
 * @author Fleming Patel
 *
 * This header contains only the immutable SHA-256 layout contract. Hot-path
 * protocol value types may include it without inheriting OpenSSL, protobuf,
 * strings, allocation, or hashing-policy dependencies.
 *
 * @par Thread Safety
 * A digest is an ordinary value. Distinct instances may be read or written
 * concurrently; one instance must not be mutated concurrently without external
 * synchronization.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace kinetum::common
{

/**
 * @brief Exact byte width mandated by the SHA-256 standard.
 *
 * Transition records and canonical-content results use this value for static
 * layout checks; it is not a runtime-selectable digest width.
 */
inline constexpr std::size_t SHA256_DIGEST_SIZE = 32;

/**
 * @brief Exact character width of lowercase hexadecimal SHA-256.
 *
 * Each digest byte is represented by two characters without separators or a
 * prefix.
 */
inline constexpr std::size_t SHA256_HEX_LENGTH = SHA256_DIGEST_SIZE * 2;

/**
 * @brief Fixed-width binary SHA-256 digest used by content identities.
 *
 * The array representation makes digest width part of the C++ type system, so
 * transition records and canonical-content results cannot carry an empty or
 * truncated digest. It owns its bytes by value and has no provider, allocation,
 * or lifetime dependency.
 */
using sha256_digest = std::array<uint8_t, SHA256_DIGEST_SIZE>;

static_assert(sizeof(sha256_digest) == SHA256_DIGEST_SIZE, "sha256_digest must remain exactly 32 bytes");
static_assert(std::is_trivially_copyable_v<sha256_digest>, "sha256_digest must be trivially copyable");
static_assert(std::is_standard_layout_v<sha256_digest>, "sha256_digest must have standard layout");

}  // namespace kinetum::common
