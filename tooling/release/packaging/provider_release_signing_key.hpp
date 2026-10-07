// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_release_signing_key.hpp
 * @brief Private release-seed generation and descriptor-based admission.
 * @author Fleming Patel
 *
 * Admission consumes an already-open read-only regular 32-byte seed owned by
 * the exact release UID, mode 0400, and link count one. It derives and compares
 * the expected Ed25519 public anchor before returning usable key material.
 * Generation fills a caller-owned private output descriptor and returns only
 * the public anchor. Both paths cleanse private storage; the command owns
 * process protection and file publication.
 *
 * @par Thread Safety
 * One admitted key object has one owner. Distinct descriptors may be inspected
 * concurrently when their underlying files are immutable.
 */

#include <cstdint>

#include "src/common/ed25519.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::release
{

/** Move-only admitted signing seed whose storage is cleansed at retirement. */
class provider_release_signing_key {
    public:
	/** @brief Disable secret duplication. */
	provider_release_signing_key(const provider_release_signing_key &) = delete;

	/** @brief Disable secret duplication by assignment. */
	provider_release_signing_key &operator=(const provider_release_signing_key &) = delete;

	/** @brief Transfer exact secret ownership and cleanse the source.
	 * @param other Source whose key and public-anchor storage are invalidated.
	 */
	provider_release_signing_key(provider_release_signing_key &&other) noexcept;

	/** @brief Transfer exact secret ownership and cleanse replaced storage.
	 * @param other Source whose key and public-anchor storage are invalidated.
	 * @return This owner after replacement; self-assignment retains its key.
	 */
	provider_release_signing_key &operator=(provider_release_signing_key &&other) noexcept;

	/** @brief Cleanse the admitted seed bytes. */
	~provider_release_signing_key();

	/** @return Admitted seed borrowed until this owner is moved, replaced or destroyed. */
	[[nodiscard]] const common::ed25519_private_key &key() const noexcept;

	/** @return Proven public anchor borrowed until this owner is moved, replaced or destroyed. */
	[[nodiscard]] const common::ed25519_public_key &public_key() const noexcept;

    private:
	friend common::status_or<provider_release_signing_key>
	admit_provider_release_signing_key(int, uint32_t, const common::ed25519_public_key &);

	/** @brief Construct from exact validated seed bytes and their proven public anchor.
	 * @param key Validated seed copied into owned storage and then cleansed.
	 * @param public_key Exact derived anchor proven by admission.
	 */
	provider_release_signing_key(common::ed25519_private_key &key,
				     const common::ed25519_public_key &public_key) noexcept;

	common::ed25519_private_key key_{};	   ///< Exact private seed; cleansed on move/destruction.
	common::ed25519_public_key public_key_{};  ///< Exact public anchor derived during admission.
};

/**
 * @brief Admit one already-open raw Ed25519 release seed.
 *
 * The descriptor's shared offset is ignored. Metadata is sampled before and
 * after `pread`, and any identity or timestamp change rejects.
 *
 * @param descriptor Already-open candidate seed descriptor at or above 3.
 * @param required_owner_uid Exact release-owner UID.
 * @param expected_anchor Exact public key the seed must derive.
 * @return Move-only cleansed-at-retirement signing key.
 */
[[nodiscard]] common::status_or<provider_release_signing_key>
admit_provider_release_signing_key(int descriptor, uint32_t required_owner_uid,
				   const common::ed25519_public_key &expected_anchor);

/**
 * @brief Disable core dumps before any process-owned private key is read.
 * @return OK after the process is nondumpable with a zero hard core limit.
 */
[[nodiscard]] common::status protect_provider_release_key_process();

/**
 * @brief Generate a raw seed into a caller-owned private output descriptor.
 *
 * Private bytes never leave this implementation in memory and are cleansed
 * on every return. The caller owns checked close, reporting, cancellation,
 * no-replacement publication, and cleanup of the private file.
 *
 * @param descriptor Writable owner-held empty regular mode-0600 file.
 * @return Derived public anchor after exact 32-byte writing, mode0400, and
 *         fsync, or an explicit failure leaving cleanup with the caller.
 * @pre protect_provider_release_key_process() succeeded before entry.
 */
[[nodiscard]] common::status_or<common::ed25519_public_key> stage_provider_release_signing_key(int descriptor);

}  // namespace kinetum::release
