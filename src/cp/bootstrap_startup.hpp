// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file bootstrap_startup.hpp
 * @brief Control Plane startup admission for exact bootstrap artifact authority.
 * @author Fleming Patel
 *
 * A supervised Control Plane receives the canonical bootstrap-snapshot path
 * and exact deployment-plan identity already admitted by Photon. This component
 * opens that exact file once, retains its descriptor, strictly parses and
 * re-admits its complete terminal ConfigSnapshot, and decodes the plan hash.
 * This establishes immutable input authority without allocating an epoch,
 * mutating the configuration store, or contacting the Data Plane.
 *
 * Omitting both values selects the explicit control-only posture: the process
 * may expose read/control RPCs, but it has no bootstrap authority and cannot
 * enable packet-configuration mutation. Supplying only one value is malformed.
 *
 * @par Thread Safety
 * Admission is stateless and thread-safe. The retained-descriptor read must
 * reproduce its admitted SHA-256 identity; concurrent source mutation rejects.
 * The returned canonical snapshot bytes are an independent immutable copy.
 *
 * @par Performance
 * Cold startup work. Admission performs bounded path/hash validation,
 * descriptor I/O, SHA-256 hashing, protobuf parsing, and deterministic
 * serialization. It must never execute on a packet worker.
 */

#include <optional>
#include <string>
#include <string_view>

#include "src/common/canonical_content_identity.hpp"
#include "src/common/held_file.hpp"
#include "src/common/sha256_digest.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::cp
{

/**
 * @brief Exact bootstrap artifact authority carried across the process boundary.
 *
 * The retained descriptor and canonical bytes are the only snapshot-content
 * authority used by durable reconciliation. The textual and raw plan hashes
 * are the exact verified claim that DP later compares with its independently
 * admitted plan. No later path reopen may replace these facts.
 */
struct bootstrap_startup_authority {
	kinetum::common::held_file snapshot_source;		   ///< Exact retained source descriptor and identity.
	kinetum::common::canonical_config_snapshot snapshot;	   ///< Terminal canonical ConfigSnapshot.
	std::string plan_content_hash;				   ///< Exact lowercase DeploymentPlan identity.
	kinetum::common::sha256_digest plan_content_hash_bytes{};  ///< Decoded fixed-width plan identity.
};

/**
 * @brief Admit an optional exact bootstrap authority before CP side effects.
 *
 * When both inputs are empty, the result contains `std::nullopt` and represents
 * the control-only process posture. Otherwise both must be present. The path
 * must be an absolute, lexically normalized regular file reached without
 * symbolic links, group/world writable permission, or a second hard link. Its
 * owner is deliberately unconstrained because verified bundle input can be
 * prepared by the invoking deployment user. Descriptor metadata rejects a
 * source above 64 MiB before its initial SHA-256; the decoded ConfigSnapshot
 * is then bounded to 10 MiB, strictly parsed, recursively protobuf-validated,
 * deterministically serialized, and admitted through the common terminal
 * ConfigSnapshot authority. The plan hash must satisfy the shared lowercase
 * SHA-256 claim and decode to 32 bytes.
 *
 * @param snapshot_path Candidate canonical bootstrap-snapshot path.
 * @param plan_content_hash Candidate exact deployment-plan content hash.
 * @return An owned authority, `std::nullopt` for the explicit control-only
 *         posture, or the first path, metadata, I/O, size, parse,
 *         canonical-form, identity, or allocation failure.
 *
 * @par Side Effects
 * Opens and retains one read-only file descriptor and allocates canonical
 * content. It does not create files, initialize the configuration store,
 * allocate identities, or contact DP.
 *
 * @par Thread Safety
 * Thread-safe. Path replacement cannot redirect the retained descriptor, and
 * mutation of its inode during the exact read rejects by content identity.
 */
[[nodiscard]] kinetum::common::status_or<std::optional<bootstrap_startup_authority>>
admit_bootstrap_startup_authority(std::string_view snapshot_path, std::string_view plan_content_hash);

}  // namespace kinetum::cp
