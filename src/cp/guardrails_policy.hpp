// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file guardrails_policy.hpp
 * @brief Exact validation and canonical identity for guardrails policy.
 * @author Fleming Patel
 *
 * This cold-path authority validates the complete nested guardrails contract
 * without supplying defaults, then hashes its deterministic protobuf bytes.
 * RPC admission, durable storage, startup, and the evaluator consume the same
 * result so no layer can reinterpret zero or message absence independently.
 *
 * @par Thread Safety
 * The functions are stateless and may be called concurrently.
 *
 * @par Performance
 * Validation, deterministic serialization, and SHA-256 are bounded control-
 * plane work and must never run on a packet worker.
 */

#include <string>

#include "gen/kinetum/control/v1/control.pb.h"
#include "src/common/sha256_digest.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::cp
{

/** @brief Canonical bytes and identity of one fully admitted policy. */
struct canonical_guardrails_policy {
	kinetum::control::v1::GuardrailsPolicy policy;	///< Exact validated policy.
	std::string serialized_bytes;			///< Deterministic wire representation.
	kinetum::common::sha256_digest policy_hash{};	///< SHA-256 of @ref serialized_bytes.
};

/**
 * @brief Validate one complete GuardrailsPolicy without normalization.
 *
 * Disabled policy must contain only `enabled=false`. Enabled policy requires
 * exact cadence, history, one detector, attribution, and every cross-field
 * relation needed by bounded evaluation. Zero is never replaced by a hidden
 * runtime value.
 *
 * @param policy Candidate generated policy.
 * @return OK for the exact final contract, or the first structural, numeric,
 *         enum, unknown-field, or bounded-arithmetic rejection.
 */
[[nodiscard]] kinetum::common::status validate_guardrails_policy(const kinetum::control::v1::GuardrailsPolicy &policy);

/**
 * @brief Validate, deterministically serialize, and hash one policy.
 *
 * @param policy Candidate generated policy.
 * @return Canonical policy value, or the first validation, allocation,
 *         serialization, or SHA-256 provider failure.
 */
[[nodiscard]] kinetum::common::status_or<canonical_guardrails_policy>
canonicalize_guardrails_policy(const kinetum::control::v1::GuardrailsPolicy &policy);

}  // namespace kinetum::cp
