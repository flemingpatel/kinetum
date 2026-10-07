// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_telemetry_bank.hpp
 * @brief Fixed identities for owner-worker telemetry-bank transfer.
 * @author Fleming Patel
 *
 * These values carry ownership only between one packet worker and the cold
 * runtime telemetry aggregator. They contain no metric payload, routing
 * policy, provider identity, or transition authority.
 */

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace kinetum::dp
{

/** @brief Exact active/standby/activation-reserve bank population per owner. */
inline constexpr std::size_t RUNTIME_TELEMETRY_BANK_COUNT = 3u;

/** @brief Exact owner namespace of one completed telemetry bank. */
enum class runtime_telemetry_bank_owner_kind : uint8_t {
	WORKER = 0,  ///< Stream, stage, and terminal-disposition accounting for one worker.
	MODULE,	     ///< Registered module telemetry for one exact context.
};

/** @brief Exact semantic reason for one bank-token transfer. */
enum class runtime_telemetry_publication_reason : uint8_t {
	CADENCE = 0,  ///< Ordinary plan-cadence publication.
	ACTIVATION,   ///< Mandatory final old-epoch publication.
	SHUTDOWN,     ///< Mandatory final active-epoch publication.
	RECLAIMED,    ///< Cleared old bank transferred for target-epoch reuse.
};

/** @brief Worker action required after one owner-local cadence service. */
enum class runtime_telemetry_return_need : uint8_t {
	NONE = 0,	///< No return-ring work was created or is currently useful.
	EXPECTED,	///< One ordinary completed bank will return asynchronously.
	POLL_REQUIRED,	///< A missing standby may have a reclaimed return available.
};

/** @brief Direction-independent meaning of one telemetry-channel token. */
enum class runtime_telemetry_bank_token_kind : uint8_t {
	BANK = 0,	  ///< Linear ownership of one immutable or cleared bank.
	RETURN_RETAINED,  ///< Worker acknowledgment that a returned bank stayed old.
};

/** @brief Fixed ownership token for one immutable completed bank. */
struct runtime_telemetry_bank_token {
	uint64_t runtime_generation{0};		    ///< Exact materialized runtime generation.
	uint64_t epoch{0};			    ///< Exact epoch represented by the bank.
	uint64_t bank_generation{0};		    ///< Exact nonzero reuse generation.
	uint64_t published_at_ns{0};		    ///< Cached publication time; zero only for RECLAIMED transfer.
	uint32_t worker_index{0};		    ///< Exact compact worker owner.
	uint32_t owner_index{0};		    ///< Worker index or module-context index.
	uint16_t stage_instance_index{UINT16_MAX};  ///< Module stage instance, or UINT16_MAX.
	uint8_t bank_index{UINT8_MAX};		    ///< Exact three-bank slot.
	uint8_t companion_bank_index{UINT8_MAX};    ///< Clean retained companion, or UINT8_MAX.
	/** Selects the worker or module-context bank owner named by this token. */
	runtime_telemetry_bank_owner_kind owner_kind{runtime_telemetry_bank_owner_kind::WORKER};
	/** Lifecycle or cadence event that published this observation. */
	runtime_telemetry_publication_reason reason{runtime_telemetry_publication_reason::CADENCE};
	/** Distinguishes bank ownership transfer from acknowledgment of an owner-retained returned bank. */
	runtime_telemetry_bank_token_kind kind{runtime_telemetry_bank_token_kind::BANK};
	uint8_t padding[9]{};  ///< Fixed zero padding through the exact object boundary.
};

static_assert(sizeof(runtime_telemetry_bank_token) == 56);
static_assert(alignof(runtime_telemetry_bank_token) == alignof(uint64_t));
static_assert(offsetof(runtime_telemetry_bank_token, padding) == 47u);
static_assert(std::is_standard_layout_v<runtime_telemetry_bank_token>);
static_assert(std::is_trivially_copyable_v<runtime_telemetry_bank_token>);

/**
 * @brief Validate every explicit reserved byte in one transfer token.
 * @param token Candidate transfer identity.
 * @return true only when all reserved bytes remain zero.
 */
[[nodiscard]] inline bool runtime_telemetry_bank_token_padding_zero(const runtime_telemetry_bank_token &token) noexcept
{
	for (const uint8_t byte : token.padding) {
		if (byte != 0u) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Compare every fixed token identity field, including reserved bytes.
 * @param left First candidate token.
 * @param right Second candidate token.
 * @return true only for complete byte-field equality.
 */
[[nodiscard]] inline bool runtime_telemetry_bank_tokens_equal(const runtime_telemetry_bank_token &left,
							      const runtime_telemetry_bank_token &right) noexcept
{
	if (left.runtime_generation != right.runtime_generation || left.epoch != right.epoch ||
	    left.bank_generation != right.bank_generation || left.published_at_ns != right.published_at_ns ||
	    left.worker_index != right.worker_index || left.owner_index != right.owner_index ||
	    left.stage_instance_index != right.stage_instance_index || left.bank_index != right.bank_index ||
	    left.companion_bank_index != right.companion_bank_index || left.owner_kind != right.owner_kind ||
	    left.reason != right.reason || left.kind != right.kind) {
		return false;
	}
	for (std::size_t index = 0u; index < sizeof(left.padding); ++index) {
		if (left.padding[index] != right.padding[index]) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Test whether a bank has no retained transfer identity.
 * @param token Candidate bank-owned transfer identity.
 * @return true only when every token field has its default empty value.
 */
[[nodiscard]] inline bool runtime_telemetry_bank_token_is_empty(const runtime_telemetry_bank_token &token) noexcept
{
	return runtime_telemetry_bank_tokens_equal(token, runtime_telemetry_bank_token{});
}

}  // namespace kinetum::dp
