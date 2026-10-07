// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_inventory.hpp
 * @brief Canonical Ed25519-authenticated installed-provider inventory.
 * @author Fleming Patel
 *
 * The inventory is provenance and artifact authority only. It binds one exact
 * runtime image, ABI identity, component set, private dependency closure, and
 * descriptor claims. Pure provider semantics remain in
 * provider_contract_catalog; plan-required selection remains with the loader.
 *
 * Runtime admission verifies a detached Ed25519 signature before protobuf
 * parsing, rejects unknown wire state, validates every bound and identity,
 * reserializes deterministically, and requires byte equality. Producers use
 * the same canonicalizer before signing.
 *
 * @par Thread Safety
 * Operations are stateless and may run concurrently. Inputs must not mutate
 * during a call.
 *
 * @par Performance
 * Signature verification, protobuf parsing, sorting, and serialization are
 * cold-path operations and must finish before provider loading.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "gen/kinetum/provider/v1/installed_provider_inventory.pb.h"
#include "src/common/ed25519.hpp"
#include "src/common/held_file.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::provider
{

/** Maximum exact serialized inventory bytes accepted before signature work. */
inline constexpr std::size_t MAX_PROVIDER_INVENTORY_BYTES = std::size_t{4} * 1024u * 1024u;

/** Maximum component records in one target-tuple release. */
inline constexpr std::size_t MAX_PROVIDER_COMPONENTS = 128;

/** Maximum private artifacts in one target-tuple release. */
inline constexpr std::size_t MAX_PROVIDER_PRIVATE_ARTIFACTS = 256;

/** Maximum dependency SONAMEs declared by one ELF image. */
inline constexpr std::size_t MAX_PROVIDER_NEEDED_SONAMES = 256;

/** Maximum exact installed artifact basename bytes. */
inline constexpr std::size_t MAX_PROVIDER_ARTIFACT_NAME_BYTES = 255;

/** Exact signature-domain bytes; both explicit NUL separators participate. */
inline constexpr char PROVIDER_INVENTORY_SIGNATURE_DOMAIN_BYTES[] = "KINETUM-PROVIDER-INVENTORY\0v1\0";

/** Exact signature-domain prefix view excluding only the implicit C terminator. */
inline constexpr std::string_view PROVIDER_INVENTORY_SIGNATURE_DOMAIN{
	PROVIDER_INVENTORY_SIGNATURE_DOMAIN_BYTES, sizeof(PROVIDER_INVENTORY_SIGNATURE_DOMAIN_BYTES) - 1u};

/** Canonical bytes paired with one detached signature. */
struct signed_provider_inventory {
	std::string canonical_bytes;		///< Deterministic canonical protobuf bytes.
	common::ed25519_signature signature{};	///< Detached signature over the domain-separated preimage.
};

/** Authenticated canonical inventory retained by the runtime loader. */
struct authenticated_provider_inventory {
	kinetum::provider::v1::InstalledProviderInventory inventory;  ///< Parsed exact canonical inventory.
	std::string canonical_bytes;				      ///< Exact verified input bytes.
};

/**
 * @brief Validate one canonical private-artifact record.
 *
 * @param artifact Candidate authenticated artifact record.
 * @return OK only for exact names, identity widths, bounds, and sorted direct
 *         dependencies.
 */
[[nodiscard]] common::status
validate_canonical_provider_private_artifact(const kinetum::provider::v1::PrivateProviderArtifact &artifact);

/**
 * @brief Validate one canonical component-artifact record.
 *
 * @param component Candidate authenticated component record.
 * @return OK only for exact identities, pure-catalog contracts, bounds, and
 *         sorted direct dependencies.
 */
[[nodiscard]] common::status
validate_canonical_provider_component_artifact(const kinetum::provider::v1::ProviderComponentArtifact &component);

/**
 * @brief Parse one detached inventory signature from exact file bytes.
 *
 * @param bytes Candidate detached-signature bytes.
 * @return Fixed signature value, or INVALID_ARGUMENT unless @p bytes contains
 *         exactly one Ed25519 signature.
 */
[[nodiscard]] common::status_or<common::ed25519_signature> parse_provider_inventory_signature(std::string_view bytes);

/**
 * @brief Validate one inventory's exact runtime, product, and ABI binding.
 *
 * @param inventory Authenticated canonical inventory.
 * @param runtime Held runtime image whose identity is authoritative.
 * @return OK only when product version, provider ABI identity, runtime size,
 *         and runtime SHA-256 all match this release.
 */
[[nodiscard]] common::status
validate_provider_inventory_runtime_binding(const kinetum::provider::v1::InstalledProviderInventory &inventory,
					    const common::held_file &runtime);

/**
 * @brief Normalize, validate, and deterministically serialize one inventory.
 *
 * Set-like fields are sorted by their declared exact identity. No value is
 * inferred, defaulted, path-normalized, or discarded.
 *
 * @param inventory Candidate release inventory copied for normalization.
 * @return Exact canonical bytes, or a fail-closed field/identity error.
 */
[[nodiscard]] common::status_or<std::string>
canonicalize_provider_inventory(kinetum::provider::v1::InstalledProviderInventory inventory);

/**
 * @brief Canonicalize and sign one release inventory.
 *
 * @param inventory Candidate release inventory.
 * @param private_key Exact release-integration signing seed.
 * @return Canonical bytes and detached signature.
 */
[[nodiscard]] common::status_or<signed_provider_inventory>
sign_provider_inventory(kinetum::provider::v1::InstalledProviderInventory inventory,
			const common::ed25519_private_key &private_key);

/**
 * @brief Authenticate exact bytes before parsing and enforce canonical form.
 *
 * The signature preimage is PROVIDER_INVENTORY_SIGNATURE_DOMAIN followed by
 * the exact input bytes. Signature failure returns UNAUTHENTICATED before any
 * protobuf parse. A valid signature over noncanonical or malformed bytes still
 * rejects.
 *
 * @param bytes Exact serialized inventory bytes.
 * @param signature Exact detached signature.
 * @param public_key Exact trusted release public key.
 * @return Parsed authenticated inventory plus the original canonical bytes.
 */
[[nodiscard]] common::status_or<authenticated_provider_inventory>
authenticate_provider_inventory(std::string_view bytes, const common::ed25519_signature &signature,
				const common::ed25519_public_key &public_key);

}  // namespace kinetum::provider
