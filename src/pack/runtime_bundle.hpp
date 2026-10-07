// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_bundle.hpp
 * @brief Canonical runtime-bundle admission and bootstrap-snapshot normalization.
 * @author Fleming Patel
 *
 * A runnable bundle has one semantic authority: a manifest-bound deployment
 * plan at `configs/plan.pbtxt` and a complete bootstrap ConfigSnapshot at
 * `configs/config_snapshot.pbtxt`. This cold-path component composes manifest
 * integrity, canonical plan identity, shared provider-topology semantics,
 * strict protobuf parsing, exact plan module-set admission, and canonical
 * snapshot identity into one verifier.
 *
 * Runtime bundles are symlink-free directory trees containing deployment
 * configuration and module artifacts only. The verifier rejects a `bin/`
 * runtime payload, a symlink in the supplied bundle-root path, any indirect
 * directory component, or any unsupported bundle entry before reading
 * deployment artifacts. Returned paths are canonical absolute paths. The
 * caller must keep the verified directory immutable while those paths are in
 * use.
 *
 * A manifest proves integrity relative to its own contents; it is not an
 * authenticity signature. Bundle signing and provenance remain separate
 * supply-chain mechanisms.
 *
 * @par Thread Safety
 * The functions are stateless and thread-safe for immutable, distinct bundle
 * trees. Concurrent mutation of a bundle under verification is unsupported.
 *
 * @par Performance
 * Verification performs filesystem traversal, file reads, protobuf parsing,
 * canonicalization, and SHA-256 hashing. It is startup/packaging work and must
 * never execute on a packet worker.
 */

#include <string>
#include <string_view>
#include <vector>

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/sha256_digest.hpp"
#include "src/common/status_or.hpp"
#include "src/provider/compiled_provider_topology.hpp"

namespace kinetum::pack
{

/** @brief Canonical manifest-relative deployment-plan path. */
inline constexpr std::string_view RUNTIME_PLAN_RELATIVE_PATH = "configs/plan.pbtxt";

/** @brief Canonical manifest-relative bootstrap-snapshot path. */
inline constexpr std::string_view BOOTSTRAP_SNAPSHOT_RELATIVE_PATH = "configs/config_snapshot.pbtxt";

/**
 * @brief Canonical bootstrap snapshot prepared for bundle publication.
 *
 * `snapshot` is parsed from the canonical deterministic bytes emitted by the
 * shared content-identity component. Its module and top-level content hashes
 * therefore match `validation_hash` and the exact deployment plan.
 */
struct normalized_bootstrap_snapshot {
	kinetum::control::v1::ConfigSnapshot snapshot;	   ///< Complete canonical snapshot.
	kinetum::common::sha256_digest validation_hash{};  ///< Raw canonical snapshot identity.
};

/** @brief One exact main module image admitted from a runnable bundle. */
struct verified_module_image {
	std::string module_id;	 ///< Exact plan-owned module identity.
	std::string image_path;	 ///< Canonical absolute symlink-free main-image path.
};

/**
 * @brief Fully verified runnable-bundle view.
 *
 * The paths are canonical absolute paths within the verified symlink-free
 * bundle root. The protobuf messages own their parsed storage and correspond
 * to exact bytes whose size and SHA-256 matched the manifest.
 */
struct verified_runtime_bundle {
	std::string bundle_root;		  ///< Canonical absolute bundle-root path.
	std::string plan_path;			  ///< Canonical absolute plan path.
	std::string bootstrap_snapshot_path;	  ///< Canonical absolute bootstrap-snapshot path.
	kinetum::gluon::v1::DeploymentPlan plan;  ///< Manifest-bound plan with verified content hash.
	kinetum::provider::compiled_provider_topology compiled_topology;  ///< Sole compiled semantic artifact.
	std::vector<verified_module_image> module_images;		  ///< Sorted exact main-image authority.
	kinetum::control::v1::ConfigSnapshot bootstrap_snapshot;	  ///< Canonical complete bootstrap snapshot.
	kinetum::common::sha256_digest bootstrap_validation_hash{};	  ///< Raw canonical snapshot identity.
};

/**
 * @brief Strictly load and normalize an explicit bootstrap snapshot for a plan.
 *
 * The plan's required canonical content-hash claim and complete compiled
 * provider semantics are verified first. The snapshot text is bounded, parsed
 * with unknown-field rejection, required to contain exactly the plan's module
 * set, and normalized through the shared ConfigSnapshot identity contract. No
 * default snapshot is synthesized.
 *
 * @param snapshot_path Path to the explicit ConfigSnapshot protobuf text.
 * @param plan Exact deployment plan the snapshot must configure.
 * @return Canonical snapshot and raw validation hash, or the first bounded I/O,
 *         strict-parse, plan-identity, module-set, or hash-claim failure.
 *
 * @par Thread Safety
 * Thread-safe when the input file and plan are not mutated concurrently.
 *
 * @par Performance
 * Cold-path operation that reads, parses, sorts, serializes, and hashes.
 */
[[nodiscard]] kinetum::common::status_or<normalized_bootstrap_snapshot>
load_and_normalize_bootstrap_snapshot(const std::string &snapshot_path, const kinetum::gluon::v1::DeploymentPlan &plan);

/**
 * @brief Verify one runnable bundle and return its canonical runtime artifacts.
 *
 * Admission requires a regular canonical `BUNDLE_MANIFEST.txt` carrying the
 * exact compiled product version, exact manifest entries for the canonical
 * plan and bootstrap-snapshot paths, no runtime `bin/`
 * payload, no symlink anywhere in the bundle path/tree, no missing or extra
 * regular files, matching per-file size and SHA-256, a valid canonical plan
 * content hash, a complete provider
 * graph admitted by the shared semantic compiler, one canonical main image
 * for every exact module identity with no authored module path, and a
 * canonical ConfigSnapshot bound to that plan. The exact protobuf artifact
 * bytes are rechecked against their parsed manifest entries immediately
 * before parsing.
 *
 * @param bundle_root Nonempty supplied bundle-root path without embedded NUL
 *        bytes.
 * @return Canonical paths, the owned plan and sole compiled topology, sorted
 *         exact module images, canonical snapshot, and validation hash, or the
 *         first fail-closed admission error.
 *
 * @par Thread Safety
 * Thread-safe for immutable, distinct bundle trees. The caller owns exclusion
 * against concurrent bundle mutation.
 *
 * @par Performance
 * Cold startup/verification path; O(total bundle bytes) hashing plus protobuf
 * parsing/canonicalization and O(number of entries) storage.
 */
[[nodiscard]] kinetum::common::status_or<verified_runtime_bundle> verify_runtime_bundle(const std::string &bundle_root);

}  // namespace kinetum::pack
