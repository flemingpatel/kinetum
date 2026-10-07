// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_release_trust.hpp
 * @brief Sole production provider-release trust-anchor declaration.
 * @author Fleming Patel
 *
 * Kinetum release verification has one Ed25519 public-key authority. Runtime
 * admission, release finalization, and static installation verification call
 * this declaration rather than carrying independent key literals. A source
 * builder who changes the definition creates a distinct release lineage and
 * becomes that lineage's release authority.
 */

#include "src/common/ed25519.hpp"

namespace kinetum::provider
{

/**
 * @brief Return the exact production provider-inventory trust anchor.
 *
 * @return Process-lifetime 32-byte raw Ed25519 public key.
 */
[[nodiscard]] const common::ed25519_public_key &provider_release_trust_anchor() noexcept;

}  // namespace kinetum::provider
