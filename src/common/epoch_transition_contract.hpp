// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_contract.hpp
 * @brief Shared fixed-width identity contract for epoch transitions.
 * @author Fleming Patel
 *
 * The control plane allocates transition identities and the dataplane validates
 * them. This header is their only C++ authority for digest layout, wire bounds,
 * durable numeric domains, and high-watermark classification. Fixed records
 * and numeric classifiers have no protobuf, gRPC, backend, allocation, or
 * subsystem-policy dependency. Cold string validators return ordinary platform
 * status values for bounded diagnostics.
 *
 * @par Thread Safety
 * These constants and validators are immutable. Construct an
 * `epoch_transition_identity` under one owner and publish it by value; do not
 * mutate the same instance concurrently.
 */

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <type_traits>

#include "src/common/sha256_digest.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Maximum admitted serialized ConfigSnapshot size: 10 MiB.
 *
 * The same bound applies to caller input and canonical output so
 * normalization cannot create an unbounded transaction record.
 */
inline constexpr std::size_t MAX_CONFIG_SNAPSHOT_BYTES = std::size_t{10} * 1024u * 1024u;

/**
 * @brief Maximum admitted ConfigSnapshot identity width.
 *
 * Snapshot identities are semantic bytes, not filesystem paths. Durable
 * stores derive fixed-width leaves from these bytes rather than narrowing the
 * identity grammar.
 */
inline constexpr std::size_t MAX_CONFIG_SNAPSHOT_ID_BYTES = 256u;

/**
 * @brief Exact simultaneous epoch-artifact slot population.
 *
 * One slot owns the published epoch while the other owns either the next
 * prepared epoch or the retained prior epoch. The compiler uses this same
 * authority when budgeting every module context's epoch arenas.
 */
inline constexpr std::size_t EXACT_EPOCH_SLOT_COUNT = 2u;

/**
 * @brief Greatest admitted ConfigSnapshot revision.
 *
 * The closed 48-bit bound leaves arithmetic headroom for later allocation and
 * rejects values that cannot belong to the Control Plane revision domain.
 */
inline constexpr int64_t MAX_CONFIG_SNAPSHOT_REVISION = int64_t{1} << 48;

/**
 * @brief Check the exact ConfigSnapshot identity-width contract.
 *
 * @param snapshot_id Candidate semantic identity bytes.
 * @return true for an identity containing 1..256 bytes.
 */
[[nodiscard]] constexpr bool valid_config_snapshot_id(std::string_view snapshot_id) noexcept
{
	return !snapshot_id.empty() && snapshot_id.size() <= MAX_CONFIG_SNAPSHOT_ID_BYTES;
}

/**
 * @brief Check the exact ConfigSnapshot revision domain.
 *
 * @param revision Candidate CP-global revision.
 * @return true for a value in the closed range 0..2^48.
 */
[[nodiscard]] constexpr bool valid_config_snapshot_revision(int64_t revision) noexcept
{
	return revision >= 0 && revision <= MAX_CONFIG_SNAPSHOT_REVISION;
}

/**
 * @brief Minimum byte length of an exact transition idempotency key.
 *
 * Empty input never means "no idempotency" on the internal lifecycle wire.
 */
inline constexpr std::size_t MIN_TRANSITION_IDEMPOTENCY_KEY_BYTES = 1;

/**
 * @brief Maximum byte length of an exact transition idempotency key.
 *
 * Runtime state stores only the digest, but admission still bounds caller work
 * before hashing and mailbox construction.
 */
inline constexpr std::size_t MAX_TRANSITION_IDEMPOTENCY_KEY_BYTES = 256;

/** @brief Maximum retained or wire-projected transition diagnostic bytes. */
inline constexpr std::size_t MAX_TRANSITION_DIAGNOSTIC_BYTES = 256;

/**
 * @brief Greatest allocatable epoch identifier.
 *
 * UINT64_MAX remains unallocatable so approach-to-wrap is detected before an
 * identity can overflow or be reused.
 */
inline constexpr uint64_t MAX_EPOCH_ID = std::numeric_limits<uint64_t>::max() - 1u;

/**
 * @brief Greatest allocatable control-plane mutation sequence.
 *
 * The terminal uint64 value is reserved under the same fail-before-wrap rule as
 * epoch allocation.
 */
inline constexpr uint64_t MAX_MUTATION_SEQUENCE = std::numeric_limits<uint64_t>::max() - 1u;

/**
 * @brief Check whether an epoch belongs to the exact shared identity domain.
 *
 * @param epoch Epoch to validate.
 * @return true for a nonzero value below the reserved wrap sentinel.
 */
[[nodiscard]] constexpr bool valid_epoch_id(uint64_t epoch) noexcept
{
	return epoch != 0u && epoch <= MAX_EPOCH_ID;
}

/**
 * @brief Check whether a mutation sequence belongs to the durable CP domain.
 *
 * @param sequence Mutation sequence to validate.
 * @return true for a nonzero value below the reserved wrap sentinel.
 */
[[nodiscard]] constexpr bool valid_mutation_sequence(uint64_t sequence) noexcept
{
	return sequence != 0u && sequence <= MAX_MUTATION_SEQUENCE;
}

/**
 * @brief Exact fixed-width identity of one control-plane mutation.
 *
 * The idempotency key is represented only by its SHA-256 digest. Caller-sized
 * strings never enter runtime transition state.
 */
struct epoch_transition_identity {
	uint64_t mutation_sequence{0};		 ///< Durable CP mutation allocation.
	uint64_t target_epoch{0};		 ///< Durable CP epoch allocation.
	sha256_digest validation_hash{};	 ///< Canonical snapshot SHA-256.
	sha256_digest idempotency_key_digest{};	 ///< Caller key SHA-256.

	/**
	 * @brief Check the numeric identity fields required by shared admission.
	 *
	 * Digest byte length is guaranteed by the fixed representation. Digest
	 * content is not assigned a sentinel value; all 256-bit values are valid.
	 *
	 * @return true when both durable allocation values are nonzero and below
	 * their reserved wrap sentinels.
	 */
	[[nodiscard]] constexpr bool valid() const noexcept
	{
		return valid_mutation_sequence(mutation_sequence) && valid_epoch_id(target_epoch);
	}

	/**
	 * @brief Compare every numeric and digest field for exact identity.
	 *
	 * @param other Identity to compare.
	 * @return true only when every field is equal.
	 */
	bool operator==(const epoch_transition_identity &other) const noexcept = default;
};

static_assert(sizeof(epoch_transition_identity) == 80, "epoch_transition_identity must remain a fixed 80-byte record");
static_assert(alignof(epoch_transition_identity) == alignof(uint64_t),
	      "epoch_transition_identity must retain natural uint64_t alignment");
static_assert(std::is_trivially_copyable_v<epoch_transition_identity>,
	      "epoch_transition_identity must be trivially copyable");
static_assert(std::is_standard_layout_v<epoch_transition_identity>,
	      "epoch_transition_identity must have standard layout");

/**
 * @brief Durable epoch and mutation allocation high watermarks.
 *
 * Both values are consumed monotonically by CP allocation and restored during
 * bootstrap. They describe allocation authority, not transition completion.
 */
struct epoch_transition_watermarks {
	uint64_t allocated_epoch{0};	///< Greatest epoch durably allocated by CP.
	uint64_t mutation_sequence{0};	///< Greatest mutation sequence durably allocated by CP.

	/**
	 * @brief Check both watermarks against their reserved-wrap domains.
	 *
	 * @return true when both values are valid durable allocations.
	 */
	[[nodiscard]] constexpr bool valid() const noexcept
	{
		return valid_epoch_id(allocated_epoch) && valid_mutation_sequence(mutation_sequence);
	}
};

static_assert(sizeof(epoch_transition_watermarks) == 16,
	      "epoch_transition_watermarks must remain a fixed 16-byte record");
static_assert(alignof(epoch_transition_watermarks) == alignof(uint64_t),
	      "epoch_transition_watermarks must retain natural uint64_t alignment");
static_assert(std::is_trivially_copyable_v<epoch_transition_watermarks>,
	      "epoch_transition_watermarks must be trivially copyable");
static_assert(std::is_standard_layout_v<epoch_transition_watermarks>,
	      "epoch_transition_watermarks must have standard layout");

/**
 * @brief Classification of a proposed identity against durable watermarks.
 */
enum class transition_watermark_result : uint8_t {
	INVALID = 0,		///< Candidate or restored watermark is malformed.
	STALE,			///< At least one candidate allocation is below its watermark.
	EXACT_RETRY_CANDIDATE,	///< Both values equal; a journal must prove exact identity.
	ADVANCES,		///< Both values strictly advance and may create one transaction.
	INCONSISTENT,		///< One value equals while the other advances.
};

static_assert(sizeof(transition_watermark_result) == sizeof(uint8_t),
	      "transition_watermark_result must remain one byte");

/**
 * @brief Typed result of resolving one complete identity against DP authority.
 *
 * This classification is shared with CP reconciliation so no caller parses
 * diagnostic text to distinguish stale, conflicting, or expired work.
 */
enum class transition_identity_resolution : uint8_t {
	INVALID = 0,	    ///< Candidate identity or restored authority is malformed.
	ADMISSIBLE,	    ///< Both allocations advance and no transaction conflicts.
	ACTIVE_EXACT,	    ///< Exact identity names the current live transaction.
	TERMINAL_EXACT,	    ///< Exact identity names one retained terminal result.
	STALE,		    ///< At least one allocation is below its high watermark.
	INCONSISTENT,	    ///< One allocation equals while the other advances.
	EXPIRED_RETRY,	    ///< Equal watermarks have no retained identity record.
	IDENTITY_CONFLICT,  ///< Retained allocation pair or key digest names another identity.
	UNKNOWN_FUTURE,	    ///< Status queried a never-admitted advancing identity.
	OVERLAP,	    ///< A different active transaction owns the global token.
	POLICY_DISABLED,    ///< This runtime has no live-transition policy.
	STATE_UNAVAILABLE,  ///< Coordinator phase cannot admit or resolve the operation.
};

static_assert(sizeof(transition_identity_resolution) == sizeof(uint8_t),
	      "transition identity resolution must remain one byte");

/**
 * @brief Validate bootstrap epoch and restored allocator authority together.
 *
 * @param active_epoch Exact active epoch restored by bootstrap.
 * @param watermarks Greatest epoch and mutation allocations restored by CP.
 * @return true when all values are valid and the epoch watermark covers the
 *         active epoch.
 */
[[nodiscard]] constexpr bool valid_bootstrap_watermarks(uint64_t active_epoch,
							const epoch_transition_watermarks &watermarks) noexcept
{
	return valid_epoch_id(active_epoch) && watermarks.valid() && watermarks.allocated_epoch >= active_epoch;
}

/**
 * @brief Classify a live-transition allocation against restored watermarks.
 *
 * Equality is only a retry candidate. The transaction journal must still find
 * and exactly match every identity field; an evicted equal record is an expired
 * retry, not permission to create work.
 *
 * @param identity Proposed complete transition identity.
 * @param watermarks Current durable allocation high watermarks.
 * @return Deterministic allocation relation without side effects.
 */
[[nodiscard]] constexpr transition_watermark_result
classify_transition_watermarks(const epoch_transition_identity &identity,
			       const epoch_transition_watermarks &watermarks) noexcept
{
	if (!identity.valid() || !watermarks.valid()) {
		return transition_watermark_result::INVALID;
	}
	if (identity.target_epoch < watermarks.allocated_epoch ||
	    identity.mutation_sequence < watermarks.mutation_sequence) {
		return transition_watermark_result::STALE;
	}
	if (identity.target_epoch == watermarks.allocated_epoch &&
	    identity.mutation_sequence == watermarks.mutation_sequence) {
		return transition_watermark_result::EXACT_RETRY_CANDIDATE;
	}
	if (identity.target_epoch > watermarks.allocated_epoch &&
	    identity.mutation_sequence > watermarks.mutation_sequence) {
		return transition_watermark_result::ADVANCES;
	}
	return transition_watermark_result::INCONSISTENT;
}

/**
 * @brief Validate an exact transition idempotency key.
 *
 * Valid keys contain 1..256 bytes and every byte is printable ASCII in the
 * inclusive range 0x20..0x7e. CP mutation entrances and the internal CP-DP
 * transition identity share this representation; durable mutation state owns
 * retry and retention semantics.
 *
 * @param key Candidate key bytes.
 * @return OK when the key is bounded printable ASCII; otherwise
 *         INVALID_ARGUMENT.
 */
[[nodiscard]] status validate_transition_idempotency_key(std::string_view key);

/**
 * @brief Hash one validated idempotency key into fixed transition state.
 *
 * The caller-sized key is retained only through its SHA-256 digest.
 *
 * @param key Candidate key bytes.
 * @return Exact SHA-256 digest, INVALID_ARGUMENT for a malformed key, or an
 *         explicit OpenSSL provider failure.
 */
[[nodiscard]] status_or<sha256_digest> digest_transition_idempotency_key(std::string_view key);

/**
 * @brief Decode an exact binary validation hash from the protobuf bytes field.
 *
 * Bytes are copied exactly without hexadecimal parsing or sentinel-value
 * interpretation; every 256-bit value is valid identity content.
 *
 * @param bytes Candidate binary digest bytes.
 * @return Fixed SHA-256 digest, or INVALID_ARGUMENT unless @p bytes contains
 *         exactly 32 bytes.
 */
[[nodiscard]] status_or<sha256_digest> decode_transition_validation_hash(std::string_view bytes);

/**
 * @brief Construct the complete fixed transition identity from wire values.
 *
 * Numeric allocations are validated before hashing, and the caller-sized
 * idempotency key is retained only through its fixed SHA-256 digest.
 *
 * @param mutation_sequence Durable nonzero CP mutation allocation.
 * @param target_epoch Durable nonzero CP epoch allocation.
 * @param validation_hash Exact binary canonical-snapshot digest.
 * @param idempotency_key Bounded printable retry identity.
 * @return Complete transition identity, INVALID_ARGUMENT for the first
 *         malformed field, or an explicit OpenSSL provider failure.
 */
[[nodiscard]] status_or<epoch_transition_identity> make_epoch_transition_identity(uint64_t mutation_sequence,
										  uint64_t target_epoch,
										  std::string_view validation_hash,
										  std::string_view idempotency_key);

}  // namespace kinetum::common
