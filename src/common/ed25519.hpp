// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file ed25519.hpp
 * @brief Exact OpenSSL-backed Ed25519 signature primitives.
 * @author Fleming Patel
 *
 * Provider inventory authentication uses one algorithm and one representation:
 * a 32-byte raw Ed25519 public key, a 32-byte raw private seed, and a 64-byte
 * detached signature over exact bytes. There is no algorithm identifier,
 * capability probe, alternate signature format, or unsigned mode.
 *
 * @par Thread Safety
 * Operations own independent OpenSSL state and may run concurrently. Key and
 * message views must not be mutated during a call.
 *
 * @par Performance
 * Key construction and signing/verification are cold-path work and are
 * forbidden from packet-worker call graphs.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

inline constexpr std::size_t ED25519_PUBLIC_KEY_SIZE = 32;   ///< Exact raw public-key bytes.
inline constexpr std::size_t ED25519_PRIVATE_KEY_SIZE = 32;  ///< Exact raw private-seed bytes.
inline constexpr std::size_t ED25519_SIGNATURE_SIZE = 64;    ///< Exact detached-signature bytes.

/** Raw public-key bytes used as the verification trust anchor. */
using ed25519_public_key = std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>;
/** Secret raw seed supplied to Ed25519 key derivation and signing. */
using ed25519_private_key = std::array<uint8_t, ED25519_PRIVATE_KEY_SIZE>;
/** Detached signature over the caller's exact message bytes. */
using ed25519_signature = std::array<uint8_t, ED25519_SIGNATURE_SIZE>;

/**
 * @brief Derive the exact public key for one raw Ed25519 private seed.
 *
 * @param private_key Exact 32-byte private seed.
 * @return Exact raw public key, or an explicit OpenSSL failure.
 */
[[nodiscard]] status_or<ed25519_public_key> ed25519_derive_public_key(const ed25519_private_key &private_key);

/**
 * @brief Sign exact bytes with one raw Ed25519 private seed.
 *
 * @param private_key Exact 32-byte private seed.
 * @param message Exact bytes covered by the detached signature.
 * @return Exact 64-byte signature, or an explicit OpenSSL failure.
 */
[[nodiscard]] status_or<ed25519_signature> ed25519_sign(const ed25519_private_key &private_key,
							std::span<const uint8_t> message);

/**
 * @brief Verify one detached Ed25519 signature over exact bytes.
 *
 * @param public_key Exact 32-byte public key.
 * @param message Exact signed bytes.
 * @param signature Exact 64-byte detached signature.
 * @return OK only for a valid signature; UNAUTHENTICATED for mismatch and an
 *         explicit provider failure for OpenSSL errors.
 */
[[nodiscard]] status ed25519_verify(const ed25519_public_key &public_key, std::span<const uint8_t> message,
				    const ed25519_signature &signature);

static_assert(sizeof(ed25519_public_key) == ED25519_PUBLIC_KEY_SIZE, "Ed25519 public-key width changed");
static_assert(sizeof(ed25519_private_key) == ED25519_PRIVATE_KEY_SIZE, "Ed25519 private-key width changed");
static_assert(sizeof(ed25519_signature) == ED25519_SIGNATURE_SIZE, "Ed25519 signature width changed");

}  // namespace kinetum::common
