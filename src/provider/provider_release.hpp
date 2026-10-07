// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_release.hpp
 * @brief Exact production provider aggregate and release evidence authority.
 * @author Fleming Patel
 *
 * This authority fixes production component membership for one target tuple,
 * reconstructs that aggregate without discovery, defines deterministic native
 * self-admission evidence, and verifies an installed signed closure without
 * executing provider code. Provider semantics remain in the pure catalog;
 * runtime required-set selection remains in the provider loader.
 *
 * The native receipt is deterministic, unsigned evidence from the trusted
 * native preparation and custody path; it is not cryptographic builder
 * attestation. Static finalization repeats every artifact, ELF, closure,
 * canonical-inventory, and signature check and then requires byte equality
 * with the receipt; receipt content can never suppress or satisfy one of those
 * checks.
 *
 * @par Thread Safety
 * Operations are stateless. Input roots must remain immutable during a call.
 *
 * @par Performance
 * All operations are bounded release/startup work and complete before provider
 * loading or packet-runtime construction.
 */

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "src/common/ed25519.hpp"
#include "src/common/held_file.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/provider/provider_inventory.hpp"
#include "src/provider/provider_inventory_reconstruction.hpp"
#include "src/provider/provider_target_tuple.hpp"

namespace kinetum::provider
{

/** Version of the deterministic native component-admission receipt. */
inline constexpr uint32_t PROVIDER_ADMISSION_RECEIPT_FORMAT_VERSION = 1;

/** Fixed installed basename of the production DPDK provider component. */
inline constexpr std::string_view PRODUCTION_DPDK_COMPONENT_FILE_NAME = "libkinetum_provider_dpdk_component.so";

/** Fixed installed basename of the production host provider component. */
inline constexpr std::string_view PRODUCTION_HOST_COMPONENT_FILE_NAME = "libkinetum_provider_host_component.so";

/**
 * Maximum receipt size: one maximum inventory-sized artifact set plus bounded
 * receipt-only tuple, hash, size, version, and wire framing.
 */
inline constexpr std::size_t MAX_PROVIDER_ADMISSION_RECEIPT_BYTES = MAX_PROVIDER_INVENTORY_BYTES + 4096u;

/**
 * @brief Reconstruct the source-controlled production provider aggregate.
 *
 * The aggregate contains exactly the production host and DPDK components.
 * UDP remains a development component and is not part of a production release.
 * No directory enumeration or installed-file inference participates.
 *
 * @param installation_root Exact staged or installed release root.
 * @param target Exact target tuple represented by the staged ELF files.
 * @param file_policy Exact caller-owned file and directory admission policy.
 * @return Canonical inventory and retained static preflight proof.
 */
[[nodiscard]] common::status_or<reconstructed_provider_inventory>
reconstruct_production_provider_release(const std::filesystem::path &installation_root, provider_target_tuple target,
					const common::held_file_policy &file_policy);

/**
 * @brief Build deterministic expected native self-admission evidence.
 *
 * The caller may publish these bytes only after admitting every component in
 * @p reconstructed through the dynamic component-admission authority.
 *
 * @param reconstructed Exact statically reconstructed release aggregate.
 * @param target Exact target tuple admitted by the native producer.
 * @return Canonical deterministic receipt bytes.
 */
[[nodiscard]] common::status_or<std::string>
build_native_provider_admission_receipt(const reconstructed_provider_inventory &reconstructed,
					provider_target_tuple target);

/**
 * @brief Verify exact additive native self-admission evidence.
 *
 * @param bytes Candidate receipt bytes from the target-native producer.
 * @param reconstructed Independently reconstructed static release proof.
 * @param target Exact target tuple being finalized.
 * @return OK only for canonical byte equality with the independently expected
 *         receipt; no receipt field substitutes for a reconstruction check.
 */
[[nodiscard]] common::status validate_native_provider_admission_receipt(
	std::string_view bytes, const reconstructed_provider_inventory &reconstructed, provider_target_tuple target);

/**
 * @brief Statically verify one installed production provider release.
 *
 * Signature verification precedes protobuf parsing. The operation then binds
 * the authenticated inventory to the held runtime image, independently
 * reconstructs every fixed production artifact for @p target, requires exact
 * canonical byte equality, and validates the additive native receipt against
 * that independent reconstruction. It never loads or executes provider code.
 *
 * @param installation_root Exact installed release root.
 * @param target Exact installed target tuple.
 * @param trust_anchor Exact release public key.
 * @param file_policy Exact caller-owned file and directory admission policy.
 * @return Authenticated canonical inventory after complete static closure
 *         verification.
 */
[[nodiscard]] common::status_or<authenticated_provider_inventory>
verify_installed_provider_release(const std::filesystem::path &installation_root, provider_target_tuple target,
				  const common::ed25519_public_key &trust_anchor,
				  const common::held_file_policy &file_policy);

}  // namespace kinetum::provider
