// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file generated_snapshot_identity.hpp
 * @brief Deterministic identity for platform-generated snapshots.
 * @author Fleming Patel
 *
 * CP generation and operator-response validation consume one domain-separated
 * function. The helper owns no allocation sequence, active-state choice, or
 * mutation authority.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent use.
 */

#include <string>
#include <string_view>

#include "src/common/status_or.hpp"

namespace kinetum::common
{

/** @brief Typed derivation inputs that cannot be positionally exchanged. */
struct generated_snapshot_identity_spec {
	std::string_view domain;	   ///< Nonempty operation-specific domain.
	std::string_view prefix;	   ///< Nonempty human-readable ID prefix.
	std::string_view idempotency_key;  ///< Exact bounded caller key.
};

/**
 * @brief Derive one collision-resistant generated snapshot identity.
 * @param spec Typed domain, prefix, and idempotency-key inputs.
 * @return Prefix plus lowercase SHA-256, or key/hash/allocation failure.
 */
[[nodiscard]] status_or<std::string> derive_generated_snapshot_id(const generated_snapshot_identity_spec &spec);

}  // namespace kinetum::common
