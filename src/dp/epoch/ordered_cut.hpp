// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file ordered_cut.hpp
 * @brief Exact record and sequence primitives for logical DATA cuts.
 * @author Fleming Patel
 *
 * A CUT travels on an independent control lane but carries the final successful
 * old-epoch DATA enqueue sequence. These bounded primitives preserve that exact
 * identity, reject wrap and malformed records, and surface duplicate-different
 * conflicts. Transition-relative staleness remains owning-endpoint policy.
 *
 * @par Thread Safety
 * Each object has exactly one endpoint owner. Foreign threads consume coherent
 * publications or SPSC records instead of reading owner-local state directly.
 */

#include <concepts>
#include <cstdint>
#include <type_traits>

#include "src/dp/epoch/transition_types.hpp"

namespace kinetum::dp
{

/**
 * @brief Compile-time contract for an exact bounded protocol record.
 *
 * @tparam record_type Candidate record type.
 */
template <typename record_type>
concept exact_protocol_record_type =
	std::is_trivially_copyable_v<record_type> && std::is_standard_layout_v<record_type> &&
	std::is_nothrow_default_constructible_v<record_type> && std::is_nothrow_copy_assignable_v<record_type> &&
	requires(const record_type &record) {
		{ record.valid() } noexcept -> std::same_as<bool>;
		{ record == record } noexcept -> std::same_as<bool>;
	};

/**
 * @brief Result of observing a record that must remain exact for one transition.
 */
enum class exact_record_result : uint8_t {
	ACCEPTED = 0,  ///< First valid record was stored.
	DUPLICATE,     ///< Record exactly matches the already stored value.
	INVALID,       ///< Record does not name a valid transition.
	CONFLICT,      ///< Record differs from the already stored value.
};

/**
 * @brief Classify one exact protocol record without owning its storage.
 *
 * This is the sole accepted/duplicate/invalid/conflict algorithm. Stateful
 * owners retain their own lifetime and placement, then store a candidate only
 * when this function returns ACCEPTED.
 *
 * @tparam record_type Trivially copyable exact protocol record.
 * @param present Whether @p accepted already names authoritative content.
 * @param accepted Existing authoritative content when @p present is true.
 * @param candidate Newly observed record.
 * @return Exact observation classification without mutation.
 */
template <exact_protocol_record_type record_type>
[[nodiscard]] constexpr exact_record_result classify_exact_protocol_record(bool present, const record_type &accepted,
									   const record_type &candidate) noexcept
{
	if (!candidate.valid()) {
		return exact_record_result::INVALID;
	}
	if (!present) {
		return exact_record_result::ACCEPTED;
	}
	return accepted == candidate ? exact_record_result::DUPLICATE : exact_record_result::CONFLICT;
}

/**
 * @brief Latch one exact CUT- or ACK-shaped record for a transition.
 *
 * Exact duplicates are idempotent. A duplicate with different content is a
 * protocol conflict and never overwrites the first accepted record.
 *
 * @tparam record_type Trivially copyable standard-layout record exposing
 * valid() and equality.
 *
 * @par Thread Safety
 * One endpoint owner calls observe() and clear_exact(). Foreign observers
 * consume a separate coherent publication; they do not read this object
 * directly.
 */
template <exact_protocol_record_type record_type>
class exact_protocol_record {
    public:
	/** @brief Construct an empty owner-local record latch. */
	exact_protocol_record() noexcept = default;

	// Copying or moving would create a second writable endpoint authority.
	exact_protocol_record(const exact_protocol_record &) = delete;
	exact_protocol_record &operator=(const exact_protocol_record &) = delete;
	exact_protocol_record(exact_protocol_record &&) = delete;
	exact_protocol_record &operator=(exact_protocol_record &&) = delete;

	/**
	 * @brief Observe a candidate record without weakening exact identity.
	 *
	 * @param candidate Record received from the owning SPSC control lane.
	 * @return ACCEPTED for the first valid value, DUPLICATE for an exact retry,
	 * INVALID for a zero/invalid record, or CONFLICT for different content.
	 */
	[[nodiscard]] exact_record_result observe(const record_type &candidate) noexcept
	{
		const exact_record_result result = classify_exact_protocol_record(present_, record_, candidate);
		if (result == exact_record_result::ACCEPTED) {
			record_ = candidate;
			present_ = true;
		}
		return result;
	}

	/**
	 * @brief Return whether one valid record has been accepted.
	 *
	 * @return true when record() can return an exact value.
	 */
	[[nodiscard]] bool present() const noexcept
	{
		return present_;
	}

	/**
	 * @brief Return the accepted exact record.
	 *
	 * @return Pointer to owner-local storage, or nullptr before acceptance.
	 */
	[[nodiscard]] const record_type *record() const noexcept
	{
		return present_ ? &record_ : nullptr;
	}

	/**
	 * @brief Clear one exact record after the global transaction has completed.
	 *
	 * The caller must prove no worker or observer can still refer to the prior
	 * transition before clearing endpoint-local state. A stale or mismatched
	 * expected value leaves the authoritative record intact.
	 *
	 * @param expected Exact completed record being retired.
	 * @return true when the matching record was cleared; false otherwise.
	 */
	[[nodiscard]] bool clear_exact(const record_type &expected) noexcept
	{
		if (!present_ || !(record_ == expected)) {
			return false;
		}
		record_ = record_type{};
		present_ = false;
		return true;
	}

    private:
	record_type record_{};	///< First accepted exact record.
	bool present_{false};	///< Whether record_ is authoritative.
};

/**
 * @brief Progress classification for a receiver relative to an ordered cut.
 */
enum class sequence_cut_progress : uint8_t {
	INVALID = 0,	///< One sequence is outside the non-wrapping domain.
	PENDING,	///< Receiver has not consumed through the cut.
	REACHED,	///< Receiver consumed exactly through the cut.
	CONTRADICTION,	///< Receiver consumed beyond the sender's final old enqueue.
};

/**
 * @brief Classify successful DATA dequeues relative to a received cut.
 *
 * Comparisons are ordinary monotonic integer comparisons; wrapping sequence
 * counters are rejected before they can invalidate this ordering.
 *
 * @param consumed_sequence Number of successful DATA dequeues.
 * @param cut_sequence Final successful old-epoch DATA enqueue.
 * @return INVALID, PENDING, REACHED, or CONTRADICTION.
 */
[[nodiscard]] constexpr sequence_cut_progress classify_sequence_cut(uint64_t consumed_sequence,
								    uint64_t cut_sequence) noexcept
{
	if (!valid_boundary_data_sequence(consumed_sequence) || !valid_boundary_data_sequence(cut_sequence)) {
		return sequence_cut_progress::INVALID;
	}
	if (consumed_sequence < cut_sequence) {
		return sequence_cut_progress::PENDING;
	}
	if (consumed_sequence == cut_sequence) {
		return sequence_cut_progress::REACHED;
	}
	return sequence_cut_progress::CONTRADICTION;
}

/**
 * @brief Single-owner count of successful DATA-ring operations.
 *
 * Failed enqueue/dequeue attempts do not call record_success() and therefore
 * do not consume sequence values. UINT64_MAX is permanently reserved so wrap
 * cannot make a later event compare older than a cut.
 *
 * @par Thread Safety
 * Exactly one endpoint worker owns mutation. Foreign readers consume a
 * coherent observer snapshot, not value() on this object.
 */
class successful_data_sequence {
    public:
	/** @brief Greatest usable sequence; UINT64_MAX remains a wrap sentinel. */
	static constexpr uint64_t MAX_VALUE = MAX_BOUNDARY_DATA_SEQUENCE;

	/** @brief Construct a process-lifetime sequence at zero. */
	successful_data_sequence() noexcept = default;

	// Copying or moving would create a second writable sequence authority.
	successful_data_sequence(const successful_data_sequence &) = delete;
	successful_data_sequence &operator=(const successful_data_sequence &) = delete;
	successful_data_sequence(successful_data_sequence &&) = delete;
	successful_data_sequence &operator=(successful_data_sequence &&) = delete;

	/**
	 * @brief Determine whether a value can record another success without wrap.
	 *
	 * @param current Existing successful-operation count.
	 * @return true when current can advance by one and remain below UINT64_MAX.
	 */
	[[nodiscard]] static constexpr bool can_advance(uint64_t current) noexcept
	{
		return current < MAX_VALUE;
	}

	/**
	 * @brief Record one successful DATA-ring operation.
	 *
	 * The caller invokes this only after queue ownership has transferred
	 * successfully. Failure leaves the sequence unchanged and requires the
	 * owning protocol endpoint to fail closed.
	 *
	 * @return true when the sequence advanced; false at the wrap guard.
	 */
	[[nodiscard]] bool record_success() noexcept
	{
		if (!can_advance(value_)) {
			return false;
		}
		++value_;
		return true;
	}

	/**
	 * @brief Return the owner-local successful-operation count.
	 *
	 * @return Current process-lifetime sequence value.
	 */
	[[nodiscard]] uint64_t value() const noexcept
	{
		return value_;
	}

    private:
	uint64_t value_{0};  ///< Successful operations recorded by the sole owner.
};

}  // namespace kinetum::dp
