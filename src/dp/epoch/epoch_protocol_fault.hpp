// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_protocol_fault.hpp
 * @brief Write-once ordered-transition safety-fault authority.
 * @author Fleming Patel
 *
 * This mechanism is not telemetry. A witnessed protocol-safety fault blocks
 * transition success until process restart. The final telemetry source merely
 * observes the immutable record and owner-published counters.
 *
 * @par Thread Safety
 * Any worker or the sole coordinator may attempt the first record. Exactly one
 * writer wins a single compare/exchange; losers do not spin. Any foreign cold
 * reader may acquire-observe the completed immutable record.
 *
 * @par Performance
 * Fault-free execution never calls record(). There is no packet-path load,
 * branch, or atomic operation associated with this class. The rare fault path
 * performs one bounded CAS and one release publication.
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace kinetum::dp
{

/** @brief Complete typed protocol-fault vocabulary. */
enum class epoch_protocol_fault_code : uint8_t {
	EPOCH_EXECUTION_MISMATCH = 1,
	OLD_DATA_AFTER_SEAL,
	FUTURE_DATA_BEFORE_ACK,
	CUT_IDENTITY_MISMATCH,
	ACK_BEFORE_ACTIVATION,
	ACK_BEFORE_CUT_DRAIN,
	RETIREMENT_BEFORE_QUIESCENCE,
	OWNERSHIP_UNDERFLOW,
	OWNERSHIP_OVERFLOW,
	OWNERSHIP_DOUBLE_RETIRE,
	OWNERSHIP_WRONG_SLOT,
	SEQUENCE_EXHAUSTED,
	EPOCH_ALLOCATOR_EXHAUSTED,
};

/** @brief Exact disposition after the fault was classified. */
enum class epoch_protocol_fault_disposition : uint8_t {
	DROP_AND_RETIRE = 1,
	TERMINATE,
	RESOURCE_REFUSED,
};

/** @brief Number of declared protocol-fault counter classes. */
inline constexpr std::size_t EPOCH_PROTOCOL_FAULT_COUNT =
	static_cast<std::size_t>(epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED);

/**
 * @brief Immutable fixed numeric identity of the first observed fault.
 *
 * UINT32_MAX denotes an inapplicable compact identity. Zero denotes an
 * inapplicable epoch, generation, sequence, or value.
 */
struct alignas(64) epoch_protocol_first_fault {
	uint64_t runtime_generation{0};		    ///< Exact materialized runtime generation.
	uint64_t transition_generation{0};	    ///< Exact mutation generation, or zero.
	uint64_t from_epoch{0};			    ///< Exact old epoch, or zero.
	uint64_t to_epoch{0};			    ///< Exact target epoch, or zero.
	uint64_t observed_epoch{0};		    ///< Packet, owner, or requested epoch.
	uint64_t expected_value{0};		    ///< Expected sequence, credit, or epoch.
	uint64_t observed_value{0};		    ///< Contradictory sequence, credit, or epoch.
	uint64_t observed_monotonic_ns{0};	    ///< Owner-cached or cold coordinator time.
	uint32_t worker_index{UINT32_MAX};	    ///< Compact worker, or sentinel.
	uint32_t boundary_index{UINT32_MAX};	    ///< Compact boundary, or sentinel.
	uint32_t context_index{UINT32_MAX};	    ///< Compact module context, or sentinel.
	uint32_t stage_instance_index{UINT32_MAX};  ///< Compact stage instance, or sentinel.
	/** Typed invariant violated by the first reporter. */
	epoch_protocol_fault_code code{epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH};
	/** Required ownership disposition associated with that violation. */
	epoch_protocol_fault_disposition disposition{epoch_protocol_fault_disposition::DROP_AND_RETIRE};
	std::array<uint8_t, 46> padding{};  ///< Explicit two-cache-line completion.
};

static_assert(sizeof(epoch_protocol_first_fault) == 128u, "protocol first-fault record must remain two cache lines");
static_assert(alignof(epoch_protocol_first_fault) == 64u,
	      "protocol first-fault record must retain cache-line alignment");
static_assert(sizeof(epoch_protocol_fault_code) == sizeof(uint8_t) &&
		      sizeof(epoch_protocol_fault_disposition) == sizeof(uint8_t),
	      "protocol fault classifications must remain one byte");
static_assert(offsetof(epoch_protocol_first_fault, runtime_generation) == 0u &&
		      offsetof(epoch_protocol_first_fault, transition_generation) == 8u &&
		      offsetof(epoch_protocol_first_fault, from_epoch) == 16u &&
		      offsetof(epoch_protocol_first_fault, to_epoch) == 24u &&
		      offsetof(epoch_protocol_first_fault, observed_epoch) == 32u &&
		      offsetof(epoch_protocol_first_fault, expected_value) == 40u &&
		      offsetof(epoch_protocol_first_fault, observed_value) == 48u &&
		      offsetof(epoch_protocol_first_fault, observed_monotonic_ns) == 56u &&
		      offsetof(epoch_protocol_first_fault, worker_index) == 64u &&
		      offsetof(epoch_protocol_first_fault, boundary_index) == 68u &&
		      offsetof(epoch_protocol_first_fault, context_index) == 72u &&
		      offsetof(epoch_protocol_first_fault, stage_instance_index) == 76u &&
		      offsetof(epoch_protocol_first_fault, code) == 80u &&
		      offsetof(epoch_protocol_first_fault, disposition) == 81u &&
		      offsetof(epoch_protocol_first_fault, padding) == 82u,
	      "protocol first-fault field offsets changed");
static_assert(std::is_standard_layout_v<epoch_protocol_first_fault> &&
		      std::is_trivially_copyable_v<epoch_protocol_first_fault>,
	      "protocol first-fault record must retain fixed value semantics");

/** @brief One process-lifetime first-fault and transition-success latch. */
class alignas(64) epoch_protocol_fault_latch final {
    public:
	/** @brief Construct one empty latch that does not block transition success. */
	epoch_protocol_fault_latch() noexcept = default;
	epoch_protocol_fault_latch(const epoch_protocol_fault_latch &) = delete;
	epoch_protocol_fault_latch &operator=(const epoch_protocol_fault_latch &) = delete;
	epoch_protocol_fault_latch(epoch_protocol_fault_latch &&) = delete;
	epoch_protocol_fault_latch &operator=(epoch_protocol_fault_latch &&) = delete;
	/** @brief Default destruction; the immutable record owns no resource. */
	~epoch_protocol_fault_latch() = default;

	/**
	 * @brief Attempt the sole immutable first-fault publication.
	 * @param fault Complete valid numeric fault identity.
	 * @return true only for the writer that claimed the first-fault record.
	 */
	[[nodiscard]] bool record(const epoch_protocol_first_fault &fault) noexcept;

	/**
	 * @brief Acquire one completed immutable first-fault record.
	 * @param[out] out Observer-owned destination changed only on success.
	 * @return true only after the first writer completed publication.
	 */
	[[nodiscard]] bool try_read(epoch_protocol_first_fault &out) const noexcept;

	/** @return true after any transition-safety classification was observed. */
	[[nodiscard]] bool transition_success_blocked() const noexcept;

    private:
	/** Single-winner construction and release/acquire visibility of the retained first fault. */
	enum class publication_state : uint8_t {
		EMPTY = 0,  ///< No reporter has claimed the record.
		WRITING,    ///< One reporter owns immutable record construction.
		READY,	    ///< The complete record is acquire-readable.
	};

	alignas(64) std::atomic<uint8_t> state_{
		static_cast<uint8_t>(publication_state::EMPTY)};  ///< Linear publication state.
	alignas(64) std::atomic<uint8_t> transition_blocked_{0};  ///< Sticky transition-safety latch.
	alignas(64) epoch_protocol_first_fault first_{};	  ///< Immutable completed first-fault bytes.
};

static_assert(std::atomic<uint8_t>::is_always_lock_free,
	      "protocol first-fault publication requires a lock-free byte atomic");
static_assert(sizeof(epoch_protocol_fault_latch) == 256u && alignof(epoch_protocol_fault_latch) == 64u,
	      "protocol first-fault authority must retain four-cache-line isolation");

/**
 * @param code Candidate typed value, including values decoded from untrusted integers.
 * @return true only for one declared protocol-fault code.
 */
[[nodiscard]] constexpr bool valid_epoch_protocol_fault_code(epoch_protocol_fault_code code) noexcept
{
	const auto raw = static_cast<uint8_t>(code);
	return raw >= 1u && raw <= EPOCH_PROTOCOL_FAULT_COUNT;
}

/**
 * @param code Previously validated declared fault code.
 * @return Zero-based counter ordinal for that code.
 */
[[nodiscard]] constexpr std::size_t epoch_protocol_fault_ordinal(epoch_protocol_fault_code code) noexcept
{
	return static_cast<std::size_t>(static_cast<uint8_t>(code) - 1u);
}

}  // namespace kinetum::dp
