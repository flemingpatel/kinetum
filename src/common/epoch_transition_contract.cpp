// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file epoch_transition_contract.cpp
 * @brief Cold-path construction and validation of exact transition identities.
 * @author Fleming Patel
 *
 * This implementation validates bounded caller identities, decodes exact
 * binary digests, and reduces caller-sized retry keys to fixed SHA-256 state.
 * It performs no allocation or mutation of live transition-coordinator state
 * beyond ordinary cold-path status and digest construction.
 *
 * @par Thread Safety
 * The functions are stateless and thread-safe. Returned identity and digest
 * values own their bytes and may be published by value.
 *
 * @par Performance
 * Printable-key validation and SHA-256 calculation are control-path admission
 * work and must not execute on a packet worker or module packet callback.
 */

#include "src/common/epoch_transition_contract.hpp"

#include <algorithm>

#include "src/common/sha256.hpp"

namespace kinetum::common
{

status validate_transition_idempotency_key(std::string_view key)
{
	if (key.size() < MIN_TRANSITION_IDEMPOTENCY_KEY_BYTES || key.size() > MAX_TRANSITION_IDEMPOTENCY_KEY_BYTES) {
		return status::invalid_argument("transition idempotency_key must contain 1..256 bytes");
	}
	const bool printable = std::all_of(key.begin(), key.end(), [](char value) {
		const auto byte = static_cast<unsigned char>(value);
		return byte >= 0x20u && byte <= 0x7eu;
	});
	if (!printable) {
		return status::invalid_argument("transition idempotency_key must contain printable ASCII only");
	}
	return status::ok();
}

status_or<sha256_digest> digest_transition_idempotency_key(std::string_view key)
{
	const auto key_status = validate_transition_idempotency_key(key);
	if (!key_status.is_ok()) {
		return key_status;
	}
	return sha256_raw(key);
}

status_or<sha256_digest> decode_transition_validation_hash(std::string_view bytes)
{
	if (bytes.size() != SHA256_DIGEST_SIZE) {
		return status::invalid_argument("transition validation_hash must contain exactly 32 bytes");
	}
	sha256_digest digest{};
	for (std::size_t i = 0; i < digest.size(); ++i) {
		digest[i] = static_cast<uint8_t>(static_cast<unsigned char>(bytes[i]));
	}
	return digest;
}

status_or<epoch_transition_identity> make_epoch_transition_identity(uint64_t mutation_sequence, uint64_t target_epoch,
								    std::string_view validation_hash,
								    std::string_view idempotency_key)
{
	if (!valid_mutation_sequence(mutation_sequence)) {
		return status::invalid_argument("transition mutation_sequence is outside the allocatable range");
	}
	if (!valid_epoch_id(target_epoch)) {
		return status::invalid_argument("transition target_epoch is outside the allocatable range");
	}

	auto validation_hash_or = decode_transition_validation_hash(validation_hash);
	if (!validation_hash_or.is_ok()) {
		return validation_hash_or.error();
	}
	auto key_digest_or = digest_transition_idempotency_key(idempotency_key);
	if (!key_digest_or.is_ok()) {
		return key_digest_or.error();
	}

	epoch_transition_identity identity{};
	identity.mutation_sequence = mutation_sequence;
	identity.target_epoch = target_epoch;
	identity.validation_hash = validation_hash_or.value();
	identity.idempotency_key_digest = key_digest_or.value();
	return identity;
}

}  // namespace kinetum::common
