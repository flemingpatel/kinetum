// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file bootstrap_config_snapshot.hpp
 * @brief Shared exact fixed-epoch bootstrap-request admission.
 * @author Fleming Patel
 *
 * This cold-path authority validates the complete six-field bootstrap request
 * used by durable CP state and DP activation. It owns scalar bounds, terminal
 * snapshot re-admission, plan-hash representation, deterministic idempotency
 * identity, and canonical protobuf bytes. CP persistence and DP bootstrap
 * compose this one contract without importing one another's implementation.
 *
 * @par Thread Safety
 * Every operation is stateless and safe for concurrent immutable inputs.
 *
 * @par Performance
 * Validation parses, serializes, and hashes configuration data. It is startup
 * and control-path work and must never execute on a packet worker.
 */

#include <cstdint>
#include <string>
#include <string_view>

#include "src/common/canonical_content_identity.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/sha256_digest.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::dataplane::v1
{
class BootstrapConfigSnapshotRequest;
}  // namespace kinetum::dataplane::v1

namespace kinetum::common
{

/** @brief Exact closed binary size bound for one bootstrap request. */
inline constexpr uint64_t MAX_BOOTSTRAP_CONFIG_SNAPSHOT_REQUEST_BYTES = MAX_CONFIG_SNAPSHOT_BYTES + 4096u;

/** @brief Fully admitted canonical bootstrap-request representation. */
struct validated_bootstrap_config_snapshot {
	canonical_config_snapshot snapshot;	   ///< Exact terminal nested snapshot.
	sha256_digest plan_content_hash{};	   ///< Exact raw deployment-plan identity.
	uint64_t active_epoch{0};		   ///< Exact active epoch restored by this request.
	epoch_transition_watermarks watermarks{};  ///< Exact durable allocator authority.
	std::string serialized_request;		   ///< Deterministic complete request bytes.
};

/**
 * @brief Decode one exact lowercase SHA-256 claim.
 *
 * @param claim Candidate lowercase hexadecimal digest.
 * @param field_name Stable diagnostic field name.
 * @return Exact 32-byte digest, or the representation/decoding failure.
 */
[[nodiscard]] status_or<sha256_digest> decode_sha256_digest_claim(std::string_view claim, std::string_view field_name);

/**
 * @brief Derive the entropy-free identity for one exact bootstrap request.
 *
 * The key is `kinetum-bootstrap-v1-<sha256hex>` over the versioned domain,
 * exact snapshot and plan digests, and the three unsigned identities encoded
 * in network byte order.
 *
 * @param snapshot_hash Raw canonical ConfigSnapshot identity.
 * @param plan_hash Raw DeploymentPlan identity.
 * @param active_epoch Exact active epoch.
 * @param allocated_high_watermark Exact allocated-epoch watermark.
 * @param mutation_high_watermark Exact mutation-sequence watermark.
 * @return Deterministic key, or the hashing failure.
 */
[[nodiscard]] status_or<std::string>
derive_bootstrap_config_snapshot_idempotency_key(const sha256_digest &snapshot_hash, const sha256_digest &plan_hash,
						 uint64_t active_epoch, uint64_t allocated_high_watermark,
						 uint64_t mutation_high_watermark);

/**
 * @brief Fully validate one exact six-field bootstrap request.
 *
 * No field is inferred, repaired, or accepted from another representation.
 * The nested snapshot is terminally re-admitted, the idempotency key is
 * recomputed, and the complete request is deterministically serialized under
 * its closed size bound.
 *
 * @param request Candidate bootstrap request.
 * @return Canonical nested snapshot, raw plan digest, active epoch, exact
 *         allocator watermarks, and deterministic request bytes, or the first
 *         protobuf, scalar, identity, or size failure.
 */
[[nodiscard]] status_or<validated_bootstrap_config_snapshot>
validate_bootstrap_config_snapshot_request(const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &request);

}  // namespace kinetum::common
