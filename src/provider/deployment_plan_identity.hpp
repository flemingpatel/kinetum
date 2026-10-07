// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file deployment_plan_identity.hpp
 * @brief Provider-aware canonical DeploymentPlan identity.
 * @author Fleming Patel
 *
 * This cold composition authority canonicalizes every provider configuration
 * through the pure contract catalog, normalizes declared set-like facility
 * references and TX storage admission, and hashes the complete plan after
 * clearing its self hash and declared timing volatility. Generic common code
 * therefore remains independent from provider semantics.
 *
 * Final plan arrays are order-contractual. This component never reorders those
 * arrays: changing their order changes plan identity. Facility references and
 * TX accepted-domain lists are sets, sorted after duplicate rejection. Only a
 * facility-reference set may be empty when its contract declares no dependency.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent calls on distinct messages. Callers must
 * not mutate an input plan concurrently.
 *
 * @par Performance
 * Cold-path only. Operations copy protobufs, parse typed provider payloads,
 * sort bounded reference sets, serialize deterministically, and compute
 * SHA-256.
 */

#include <string>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::gluon::v1
{
class DeploymentPlan;
class TxStorageBinding;
}  // namespace kinetum::gluon::v1

namespace kinetum::provider
{

/**
 * @brief Validate and canonically sort one nonempty TX storage admission set.
 *
 * Authoring and plan identity share this normalizer. Invalid or duplicate
 * domain identities reject before the list is reordered.
 *
 * @param binding Mutable exact TX storage binding; must not be null.
 * @return OK after normalization, or a precise input-contract error.
 */
[[nodiscard]] common::status canonicalize_tx_storage_binding(kinetum::gluon::v1::TxStorageBinding *binding);

/**
 * @brief Canonicalize provider-owned fields in one mutable deployment plan.
 *
 * Every provider Any is decoded and repacked through its role-correct catalog
 * row. Every present facility reference must be a nonempty valid identity;
 * each set is duplicate-free and then sorted. Stream storage must match its
 * direction; TX admission uses the same nonempty-set normalizer as authoring.
 * Top-level plan arrays retain their exact order.
 *
 * @param plan Mutable plan to canonicalize. Must not be null.
 * @return OK on success, or the exact unknown-field, contract, identity,
 *         duplicate, parse, normalization, or serialization-independent
 *         validation failure.
 */
[[nodiscard]] common::status canonicalize_deployment_plan(kinetum::gluon::v1::DeploymentPlan *plan);

/**
 * @brief Compute the canonical hexadecimal content hash of a DeploymentPlan.
 *
 * The plan is copied and provider fields are canonicalized. The preimage
 * clears `content_hash` and only the declared volatile metadata fields
 * `planned_unix_ms` and `planning_duration_ms`. Every other field and every
 * final plan-array position is hash-covered.
 *
 * @param plan Plan whose deterministic identity is required.
 * @return Exact lowercase SHA-256 digest or the canonicalization,
 *         serialization, or hash failure.
 */
[[nodiscard]] common::status_or<std::string>
compute_deployment_plan_content_hash(const kinetum::gluon::v1::DeploymentPlan &plan);

/**
 * @brief Canonicalize a producer plan and publish its exact content hash.
 *
 * @param plan Mutable complete producer plan. Must not be null.
 * @return OK after canonical provider fields and `content_hash` are published,
 *         or the first canonicalization/identity failure.
 */
[[nodiscard]] common::status finalize_deployment_plan_identity(kinetum::gluon::v1::DeploymentPlan *plan);

/**
 * @brief Verify canonical plan form and the required content-hash claim.
 *
 * Consumer admission rejects a plan whose provider Any or facility-reference
 * representation would change under canonicalization, even if its supplied
 * hash happens to match the normalized content.
 *
 * @param plan Plan containing the required exact content-hash claim.
 * @return OK only for canonical form and an exact hash match;
 *         INVALID_ARGUMENT for missing, malformed, or noncanonical input;
 *         DATA_LOSS for a well-formed hash mismatch; otherwise the underlying
 *         provider/serialization/hash failure.
 */
[[nodiscard]] common::status verify_deployment_plan_content_hash(const kinetum::gluon::v1::DeploymentPlan &plan);

}  // namespace kinetum::provider
