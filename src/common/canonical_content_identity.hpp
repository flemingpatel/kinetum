// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file canonical_content_identity.hpp
 * @brief Canonical ConfigSnapshot content identity.
 * @author Fleming Patel
 *
 * This cold-path component defines the deterministic protobuf representation
 * used for transition validation hashes. It rejects unknown protobuf fields,
 * applies the snapshot's explicit set-like rules, and hashes only validated
 * canonical bytes. Provider-aware DeploymentPlan identity is owned by
 * `deployment_plan_identity.hpp` so generic common code does not depend on the
 * provider contract catalog.
 *
 * Protobuf deterministic serialization is treated as stable for Kinetum's
 * pinned protobuf runtime and one-tree CP/DP build. It is not claimed to be a
 * universal canonical format across arbitrary protobuf versions. New fields are
 * hash-covered and repeated-field order is contractual unless the owning
 * canonicalization rule explicitly declares a field set-like or volatile.
 *
 * @par Thread Safety
 * Every operation is stateless and thread-safe. Returned strings and digests
 * own their storage. Callers must not mutate an input message concurrently.
 *
 * @par Performance
 * These functions allocate, copy protobuf messages, sort set-like fields, and
 * compute SHA-256. They are configuration/planning operations and must never be
 * called from a packet worker or module packet callback.
 */

#include <string>
#include <string_view>

#include "src/common/sha256_digest.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::control::v1
{
class ConfigSnapshot;
}  // namespace kinetum::control::v1

namespace kinetum::gluon::v1
{
class DeploymentPlan;
}  // namespace kinetum::gluon::v1

namespace kinetum::common
{

/**
 * @brief Validated canonical bytes and raw transition validation hash.
 *
 * `serialized_bytes` contains a complete ConfigSnapshot with modules ordered
 * by module_id, every module content hash recomputed, and the snapshot's
 * content_hash normalized to the hexadecimal form of `validation_hash`.
 * `validation_hash` itself is SHA-256 over the same canonical snapshot with the
 * self-referential top-level content_hash cleared.
 */
struct canonical_config_snapshot {
	std::string serialized_bytes;	  ///< Complete deterministic ConfigSnapshot bytes.
	sha256_digest validation_hash{};  ///< Raw SHA-256 of the self-hash-free canonical preimage.
};

/**
 * @brief Re-admit one terminal canonical ConfigSnapshot representation.
 *
 * This plan-independent boundary parses the exact deterministic bytes,
 * rejects recursive unknown fields and undeclared enum numbers, requires the
 * shared snapshot identity/revision scalar contract, requires strictly sorted
 * unique module identities, verifies every module blob hash, recomputes the
 * self-hash-free snapshot digest, and binds both the embedded lowercase
 * content hash and supplied raw digest to that preimage. It performs no
 * plan-dependent module-set normalization.
 *
 * @param canonical Candidate terminal bytes and raw validation identity.
 * @param[out] snapshot Exact parsed snapshot on success. Cleared before any
 *             validation work and left empty on every failure. Must not be
 *             null.
 * @return OK for one exact terminal representation, otherwise the first size,
 *         parse, protobuf-tree, ordering, deterministic-form, or identity
 *         failure.
 */
[[nodiscard]] status admit_terminal_config_snapshot(const canonical_config_snapshot &canonical,
						    kinetum::control::v1::ConfigSnapshot *snapshot);

/**
 * @brief Reconstruct and re-admit canonical identity from one terminal message.
 *
 * The message must already contain exact deterministic terminal content: a
 * lowercase snapshot hash, strictly sorted unique modules, exact module hashes,
 * and no unknown or invalid-enum fields. The returned raw digest is decoded
 * from the embedded claim and independently verified by terminal admission.
 *
 * @param snapshot Candidate terminal ConfigSnapshot message.
 * @return Canonical deterministic bytes and raw hash, or the first size,
 *         serialization, representation, or terminal-admission failure.
 */
[[nodiscard]] status_or<canonical_config_snapshot>
canonical_config_snapshot_from_terminal(const kinetum::control::v1::ConfigSnapshot &snapshot);

/**
 * @brief Validate the platform's textual SHA-256 identity-claim format.
 *
 * Textual content identities are exactly 64 lowercase hexadecimal characters.
 * This function validates representation only; it does not recompute or trust
 * the claimed identity.
 *
 * @param claim Candidate textual SHA-256 claim.
 * @param field_name Stable field or argument name used in diagnostics.
 * @return OK for the exact lowercase representation; INVALID_ARGUMENT for an
 *         empty, incorrectly sized, uppercase, or non-hexadecimal claim.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent calls. The caller retains ownership of
 * both string views for the duration of the call.
 *
 * @par Performance
 * Cold-path O(claim length) validation with diagnostic allocation only on
 * rejection. It must not run from packet processing.
 */
[[nodiscard]] status validate_sha256_hex_claim(std::string_view claim, std::string_view field_name);

/**
 * @brief Validate and canonicalize one complete ConfigSnapshot for a plan.
 *
 * The expected module set is derived from STAGE_KIND_MODULE entries in the
 * supplied DeploymentPlan. Snapshot modules must match that set exactly in both
 * directions and may appear only once. Module blobs remain opaque exact bytes:
 * the platform hashes them but never parses their contents as protobuf. A
 * supplied module or snapshot content_hash is an integrity claim that must
 * match recomputation; absence is normalized rather than treated as authority.
 * Both the admitted input and final canonical representation are bounded by
 * MAX_CONFIG_SNAPSHOT_BYTES.
 *
 * @param snapshot Candidate complete configuration snapshot.
 * @param plan Deployment plan that owns the exact expected module set.
 * @return Canonical bytes and raw validation hash, or an explicit validation,
 *         size, serialization, or SHA-256 failure.
 */
[[nodiscard]] status_or<canonical_config_snapshot>
canonicalize_config_snapshot(const kinetum::control::v1::ConfigSnapshot &snapshot,
			     const kinetum::gluon::v1::DeploymentPlan &plan);

/**
 * @brief Canonicalize one live candidate against the active module-set authority.
 *
 * The active snapshot is first fully re-admitted as a terminal canonical
 * representation. Its strictly sorted module identities then replace the plan
 * only as the expected live configuration set; candidate normalization,
 * hashing, bounds, and terminal proof use the same implementation as the
 * plan-based overload.
 *
 * @param snapshot Candidate live configuration snapshot.
 * @param active_snapshot Exact terminal snapshot for the current fixed plan.
 * @return Canonical bytes and raw validation hash, or the first active-state,
 *         candidate, membership, size, serialization, or hash failure.
 */
[[nodiscard]] status_or<canonical_config_snapshot>
canonicalize_config_snapshot(const kinetum::control::v1::ConfigSnapshot &snapshot,
			     const kinetum::control::v1::ConfigSnapshot &active_snapshot);

}  // namespace kinetum::common
