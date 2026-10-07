// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file exact_slot_table.hpp
 * @brief Exact lifecycle state for two epoch-tagged configuration slots.
 * @author Fleming Patel
 *
 * The table proves that one current and one next/retained epoch are the only
 * representable configuration generations. It stores metadata only; artifact
 * ownership and participant-local active indices remain explicit in their
 * owning module or snapshot stores.
 *
 * @par Thread Safety
 * The table is not internally synchronized. Exactly one thread may own it at a
 * time; lifecycle-to-worker ownership transfer requires an explicit external
 * release/acquire handoff. Foreign observers never read it directly.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "src/common/epoch_transition_contract.hpp"

namespace kinetum::dp
{

/** @brief DP-local spelling of the shared exact epoch-slot population. */
inline constexpr std::size_t EXACT_EPOCH_SLOT_COUNT = common::EXACT_EPOCH_SLOT_COUNT;

/** @brief Out-of-range sentinel returned when no exact slot exists. */
inline constexpr std::size_t INVALID_EPOCH_SLOT_INDEX = EXACT_EPOCH_SLOT_COUNT;

/**
 * @brief Exact lifecycle states for one epoch-tagged configuration slot.
 */
enum class epoch_slot_state : uint8_t {
	EMPTY = 0,  ///< Slot owns no artifact.
	PREPARED,   ///< Complete immutable artifact awaiting activation.
	PUBLISHED,  ///< Artifact selected for current execution.
	RETAINED,   ///< Prior artifact retained until certificate and grace complete.
};

/**
 * @brief Epoch and lifecycle state associated with one of exactly two slots.
 */
struct epoch_slot_descriptor {
	uint64_t epoch{0};				  ///< Exact epoch tag; zero only when EMPTY.
	epoch_slot_state state{epoch_slot_state::EMPTY};  ///< Current exact lifecycle state.

	/**
	 * @brief Compare exact epoch and lifecycle state.
	 *
	 * @param other Slot descriptor to compare.
	 * @return true only when both fields are equal.
	 */
	bool operator==(const epoch_slot_descriptor &other) const noexcept = default;
};

static_assert(sizeof(epoch_slot_descriptor) == 16, "epoch_slot_descriptor must remain 16 bytes");
static_assert(alignof(epoch_slot_descriptor) == alignof(uint64_t),
	      "epoch_slot_descriptor must retain natural uint64_t alignment");
static_assert(std::is_trivially_copyable_v<epoch_slot_descriptor>, "epoch_slot_descriptor must be trivially copyable");
static_assert(std::is_standard_layout_v<epoch_slot_descriptor>, "epoch_slot_descriptor must have standard layout");

/**
 * @brief Outcome of an exact two-slot state transition.
 */
enum class epoch_slot_result : uint8_t {
	APPLIED = 0,		///< Requested state transition completed.
	INVALID_EPOCH,		///< Epoch is outside the exact non-wrapping domain.
	INVALID_STATE,		///< Current two-slot layout does not permit the operation.
	EPOCH_ALREADY_PRESENT,	///< Exact epoch already occupies a slot.
	EPOCH_NOT_FOUND,	///< Exact epoch does not occupy a slot.
	EPOCH_ORDER_VIOLATION,	///< Prepared epoch does not advance the published epoch.
	NO_EMPTY_SLOT,		///< Both slots remain owned; a later epoch cannot be prepared.
};

/**
 * @brief Result and affected index from one slot-table operation.
 */
struct epoch_slot_operation {
	epoch_slot_result result{epoch_slot_result::INVALID_STATE};  ///< Exact operation result.
	std::size_t slot_index{INVALID_EPOCH_SLOT_INDEX};	     ///< Affected slot on success.

	/**
	 * @brief Check whether the requested state transition completed.
	 *
	 * @return true only for APPLIED.
	 */
	[[nodiscard]] constexpr bool applied() const noexcept
	{
		return result == epoch_slot_result::APPLIED;
	}
};

/**
 * @brief Enforce the lifecycle of exactly two epoch-tagged configuration slots.
 *
 * Valid layouts are EMPTY/EMPTY before preparation, PREPARED/EMPTY during
 * cold bootstrap, PUBLISHED/EMPTY while idle, PUBLISHED/PREPARED before a
 * transition activation, and PUBLISHED/RETAINED during retirement. The active
 * participant index remains separate runtime state; callers never infer packet
 * execution authority merely from this table.
 *
 * @par Thread Safety
 * Exactly one thread mutates or reads this table at a time. Publication of
 * prepared artifacts, ownership transfer, and participant active indices are
 * composed by the owning store in a later layer; foreign threads must not read
 * this object directly.
 */
class exact_epoch_slot_table {
    public:
	/** @brief Construct an exact table in the EMPTY/EMPTY startup layout. */
	exact_epoch_slot_table() noexcept = default;

	// Copying or moving would create a second writable slot authority.
	exact_epoch_slot_table(const exact_epoch_slot_table &) = delete;
	exact_epoch_slot_table &operator=(const exact_epoch_slot_table &) = delete;
	exact_epoch_slot_table(exact_epoch_slot_table &&) = delete;
	exact_epoch_slot_table &operator=(exact_epoch_slot_table &&) = delete;

	/**
	 * @brief Prove one exact epoch can enter PREPARED without mutating slots.
	 *
	 * @param epoch Exact candidate epoch.
	 * @return The same result and slot identity consumed by stage_prepared().
	 */
	[[nodiscard]] epoch_slot_operation preflight_stage_prepared(uint64_t epoch) const noexcept
	{
		if (!common::valid_epoch_id(epoch)) {
			return {epoch_slot_result::INVALID_EPOCH, INVALID_EPOCH_SLOT_INDEX};
		}
		if (find_exact(epoch) != nullptr) {
			return {epoch_slot_result::EPOCH_ALREADY_PRESENT, INVALID_EPOCH_SLOT_INDEX};
		}
		if (all_empty_()) {
			// EMPTY/EMPTY intentionally has no unique empty-state match. Cold
			// bootstrap owns deterministic slot zero; later publication/retirement
			// preserves the ordinary unique-empty invariant.
			return {epoch_slot_result::APPLIED, 0u};
		}

		const std::size_t empty_index = find_state_(epoch_slot_state::EMPTY);
		if (empty_index == INVALID_EPOCH_SLOT_INDEX) {
			return {epoch_slot_result::NO_EMPTY_SLOT, INVALID_EPOCH_SLOT_INDEX};
		}
		if (!idle_layout_()) {
			return {epoch_slot_result::INVALID_STATE, INVALID_EPOCH_SLOT_INDEX};
		}

		const std::size_t published_index = find_state_(epoch_slot_state::PUBLISHED);
		if (published_index == INVALID_EPOCH_SLOT_INDEX) {
			return {epoch_slot_result::INVALID_STATE, INVALID_EPOCH_SLOT_INDEX};
		}
		if (epoch <= slots_[published_index].epoch) {
			return {epoch_slot_result::EPOCH_ORDER_VIOLATION, INVALID_EPOCH_SLOT_INDEX};
		}
		return {epoch_slot_result::APPLIED, empty_index};
	}

	/**
	 * @brief Stage one exact epoch in the only admissible empty slot.
	 *
	 * The first staged epoch creates the PREPARED/EMPTY bootstrap layout. Once
	 * an epoch is published, staging requires the idle PUBLISHED/EMPTY layout
	 * and a strictly later epoch.
	 *
	 * @param epoch Exact valid epoch to prepare.
	 * @return Result and prepared slot index.
	 */
	[[nodiscard]] epoch_slot_operation stage_prepared(uint64_t epoch) noexcept
	{
		const auto preflight = preflight_stage_prepared(epoch);
		if (!preflight.applied()) {
			return preflight;
		}
		slots_[preflight.slot_index] = {epoch, epoch_slot_state::PREPARED};
		return preflight;
	}

	/**
	 * @brief Preflight publication without mutating exact slot state.
	 *
	 * This check lets an owner construct a complete prospective executable view
	 * and invoke its bounded ACTIVATE callback before the metadata commit. A
	 * successful preflight guarantees that `publish_prepared()` is an infallible
	 * bounded assignment while this single-owner table remains unchanged.
	 *
	 * @param epoch Exact prepared epoch selected for execution.
	 * @return APPLIED and the prepared slot index when publication is legal.
	 */
	[[nodiscard]] epoch_slot_operation preflight_publish_prepared(uint64_t epoch) const noexcept
	{
		if (!common::valid_epoch_id(epoch)) {
			return {epoch_slot_result::INVALID_EPOCH, INVALID_EPOCH_SLOT_INDEX};
		}
		const std::size_t prepared_index = find_exact_index_(epoch);
		if (prepared_index == INVALID_EPOCH_SLOT_INDEX) {
			return {epoch_slot_result::EPOCH_NOT_FOUND, INVALID_EPOCH_SLOT_INDEX};
		}
		if (slots_[prepared_index].state != epoch_slot_state::PREPARED) {
			return {epoch_slot_result::INVALID_STATE, INVALID_EPOCH_SLOT_INDEX};
		}
		if (initial_prepared_layout_()) {
			return {epoch_slot_result::APPLIED, prepared_index};
		}
		if (!prepared_layout_()) {
			return {epoch_slot_result::INVALID_STATE, INVALID_EPOCH_SLOT_INDEX};
		}

		const std::size_t published_index = find_state_(epoch_slot_state::PUBLISHED);
		if (published_index == INVALID_EPOCH_SLOT_INDEX || slots_[published_index].epoch >= epoch) {
			return {epoch_slot_result::EPOCH_ORDER_VIOLATION, INVALID_EPOCH_SLOT_INDEX};
		}
		return {epoch_slot_result::APPLIED, prepared_index};
	}

	/**
	 * @brief Discard an exact prepared slot before commit.
	 *
	 * @param epoch Exact epoch whose preparation is being aborted.
	 * @return Result and cleared slot index.
	 */
	[[nodiscard]] epoch_slot_operation discard_prepared(uint64_t epoch) noexcept
	{
		if (!common::valid_epoch_id(epoch)) {
			return {epoch_slot_result::INVALID_EPOCH, INVALID_EPOCH_SLOT_INDEX};
		}
		const std::size_t index = find_exact_index_(epoch);
		if (index == INVALID_EPOCH_SLOT_INDEX) {
			return {epoch_slot_result::EPOCH_NOT_FOUND, INVALID_EPOCH_SLOT_INDEX};
		}
		if (slots_[index].state != epoch_slot_state::PREPARED) {
			return {epoch_slot_result::INVALID_STATE, INVALID_EPOCH_SLOT_INDEX};
		}
		slots_[index] = {};
		return {epoch_slot_result::APPLIED, index};
	}

	/**
	 * @brief Publish an exact prepared epoch and retain the prior published slot.
	 *
	 * This bounded metadata transition accompanies owner-worker activation. The
	 * participant's active index remains an explicit separate authority.
	 *
	 * @param epoch Exact prepared epoch selected for execution.
	 * @return Result and newly published slot index.
	 */
	[[nodiscard]] epoch_slot_operation publish_prepared(uint64_t epoch) noexcept
	{
		const auto preflight = preflight_publish_prepared(epoch);
		if (!preflight.applied()) {
			return preflight;
		}
		const std::size_t prepared_index = preflight.slot_index;
		const std::size_t published_index = find_state_(epoch_slot_state::PUBLISHED);
		if (published_index != INVALID_EPOCH_SLOT_INDEX) {
			slots_[published_index].state = epoch_slot_state::RETAINED;
		}
		slots_[prepared_index].state = epoch_slot_state::PUBLISHED;
		return {epoch_slot_result::APPLIED, prepared_index};
	}

	/**
	 * @brief Empty one exact retained slot after certificate and grace completion.
	 *
	 * @param epoch Exact old epoch proven globally quiescent.
	 * @return Result and cleared slot index.
	 */
	[[nodiscard]] epoch_slot_operation retire_retained(uint64_t epoch) noexcept
	{
		if (!common::valid_epoch_id(epoch)) {
			return {epoch_slot_result::INVALID_EPOCH, INVALID_EPOCH_SLOT_INDEX};
		}
		const std::size_t index = find_exact_index_(epoch);
		if (index == INVALID_EPOCH_SLOT_INDEX) {
			return {epoch_slot_result::EPOCH_NOT_FOUND, INVALID_EPOCH_SLOT_INDEX};
		}
		if (slots_[index].state != epoch_slot_state::RETAINED || !retiring_layout_()) {
			return {epoch_slot_result::INVALID_STATE, INVALID_EPOCH_SLOT_INDEX};
		}
		slots_[index] = {};
		return {epoch_slot_result::APPLIED, index};
	}

	/**
	 * @brief Preflight final published-slot retirement without mutation.
	 *
	 * A successful result proves that no PREPARED or RETAINED artifact remains.
	 * Callers use this before transferring the live ownership token to foreign
	 * RETIRE work, so an invalid shutdown order fails while recovery is possible.
	 *
	 * @param epoch Exact published epoch selected for final shutdown.
	 * @return APPLIED and the published slot index only for the idle layout.
	 */
	[[nodiscard]] epoch_slot_operation preflight_retire_published(uint64_t epoch) const noexcept
	{
		if (!common::valid_epoch_id(epoch)) {
			return {epoch_slot_result::INVALID_EPOCH, INVALID_EPOCH_SLOT_INDEX};
		}
		const std::size_t index = find_exact_index_(epoch);
		if (index == INVALID_EPOCH_SLOT_INDEX) {
			return {epoch_slot_result::EPOCH_NOT_FOUND, INVALID_EPOCH_SLOT_INDEX};
		}
		if (slots_[index].state != epoch_slot_state::PUBLISHED || !idle_layout_()) {
			return {epoch_slot_result::INVALID_STATE, INVALID_EPOCH_SLOT_INDEX};
		}
		return {epoch_slot_result::APPLIED, index};
	}

	/**
	 * @brief Empty the sole published slot during final quiescent shutdown.
	 *
	 * This operation is not transition retirement. It is legal only in the idle
	 * PUBLISHED/EMPTY layout after packet ownership has stopped and the owning
	 * store has transferred the exact artifact to RETIRE.
	 *
	 * @param epoch Exact published epoch being retired at shutdown.
	 * @return Result and cleared slot index.
	 */
	[[nodiscard]] epoch_slot_operation retire_published(uint64_t epoch) noexcept
	{
		const auto preflight = preflight_retire_published(epoch);
		if (!preflight.applied()) {
			return preflight;
		}
		slots_[preflight.slot_index] = {};
		return preflight;
	}

	/**
	 * @brief Look up a slot by exact epoch identity.
	 *
	 * @param epoch Exact epoch requested by the caller.
	 * @return Pointer to the matching descriptor, or nullptr. No inequality
	 * fallback is performed.
	 */
	[[nodiscard]] const epoch_slot_descriptor *find_exact(uint64_t epoch) const noexcept
	{
		const std::size_t index = find_exact_index_(epoch);
		return index == INVALID_EPOCH_SLOT_INDEX ? nullptr : &slots_[index];
	}

	/**
	 * @brief Read one slot descriptor by fixed index.
	 *
	 * @param index Slot index in [0, EXACT_EPOCH_SLOT_COUNT).
	 * @return Pointer to the descriptor, or nullptr for an invalid index.
	 */
	[[nodiscard]] const epoch_slot_descriptor *slot(std::size_t index) const noexcept
	{
		return index < EXACT_EPOCH_SLOT_COUNT ? &slots_[index] : nullptr;
	}

	/**
	 * @brief Check whether the table is in one of its five legal layouts.
	 *
	 * @return true for startup, idle, prepared, or retiring layout.
	 */
	[[nodiscard]] bool valid_layout() const noexcept
	{
		return all_empty_() || initial_prepared_layout_() || idle_layout_() || prepared_layout_() ||
		       retiring_layout_();
	}

	/**
	 * @brief Return whether both exact slots are empty.
	 *
	 * @return true only after no artifact lifecycle state remains.
	 */
	[[nodiscard]] bool empty() const noexcept
	{
		return all_empty_();
	}

    private:
	/**
	 * @brief Find the index of an exact nonempty epoch.
	 *
	 * @param epoch Exact epoch to find.
	 * @return Matching slot index, or INVALID_EPOCH_SLOT_INDEX.
	 */
	[[nodiscard]] std::size_t find_exact_index_(uint64_t epoch) const noexcept
	{
		if (!common::valid_epoch_id(epoch)) {
			return INVALID_EPOCH_SLOT_INDEX;
		}
		for (std::size_t i = 0; i < EXACT_EPOCH_SLOT_COUNT; ++i) {
			if (slots_[i].state != epoch_slot_state::EMPTY && slots_[i].epoch == epoch) {
				return i;
			}
		}
		return INVALID_EPOCH_SLOT_INDEX;
	}

	/**
	 * @brief Find the unique slot in a requested state.
	 *
	 * @param state Slot state to locate.
	 * @return Unique matching index, or INVALID_EPOCH_SLOT_INDEX when absent or
	 * duplicated.
	 */
	[[nodiscard]] std::size_t find_state_(epoch_slot_state state) const noexcept
	{
		std::size_t result = INVALID_EPOCH_SLOT_INDEX;
		for (std::size_t i = 0; i < EXACT_EPOCH_SLOT_COUNT; ++i) {
			if (slots_[i].state != state) {
				continue;
			}
			if (result != INVALID_EPOCH_SLOT_INDEX) {
				return INVALID_EPOCH_SLOT_INDEX;
			}
			result = i;
		}
		return result;
	}

	/**
	 * @brief Check whether both slots are empty and consistently zero-tagged.
	 *
	 * @return true only for the pre-bootstrap layout.
	 */
	[[nodiscard]] bool all_empty_() const noexcept
	{
		return slots_[0].state == epoch_slot_state::EMPTY && slots_[0].epoch == 0u &&
		       slots_[1].state == epoch_slot_state::EMPTY && slots_[1].epoch == 0u;
	}

	/**
	 * @brief Check the one-prepared/one-empty cold-bootstrap layout.
	 *
	 * @return true only when the prepared tag is valid and the empty tag is zero.
	 */
	[[nodiscard]] bool initial_prepared_layout_() const noexcept
	{
		const std::size_t prepared = find_state_(epoch_slot_state::PREPARED);
		const std::size_t empty = find_state_(epoch_slot_state::EMPTY);
		return prepared != INVALID_EPOCH_SLOT_INDEX && empty != INVALID_EPOCH_SLOT_INDEX &&
		       common::valid_epoch_id(slots_[prepared].epoch) && slots_[empty].epoch == 0u;
	}

	/**
	 * @brief Check the one-published/one-empty idle layout.
	 *
	 * @return true only when states and empty/valid epoch tags agree.
	 */
	[[nodiscard]] bool idle_layout_() const noexcept
	{
		const std::size_t published = find_state_(epoch_slot_state::PUBLISHED);
		const std::size_t empty = find_state_(epoch_slot_state::EMPTY);
		return published != INVALID_EPOCH_SLOT_INDEX && empty != INVALID_EPOCH_SLOT_INDEX &&
		       common::valid_epoch_id(slots_[published].epoch) && slots_[empty].epoch == 0u;
	}

	/**
	 * @brief Check the one-published/one-prepared layout.
	 *
	 * @return true only when both exact epoch tags are valid and ordered.
	 */
	[[nodiscard]] bool prepared_layout_() const noexcept
	{
		const std::size_t published = find_state_(epoch_slot_state::PUBLISHED);
		const std::size_t prepared = find_state_(epoch_slot_state::PREPARED);
		return published != INVALID_EPOCH_SLOT_INDEX && prepared != INVALID_EPOCH_SLOT_INDEX &&
		       common::valid_epoch_id(slots_[published].epoch) &&
		       common::valid_epoch_id(slots_[prepared].epoch) &&
		       slots_[published].epoch < slots_[prepared].epoch;
	}

	/**
	 * @brief Check the one-published/one-retained layout.
	 *
	 * @return true only when the retained epoch precedes the published epoch.
	 */
	[[nodiscard]] bool retiring_layout_() const noexcept
	{
		const std::size_t published = find_state_(epoch_slot_state::PUBLISHED);
		const std::size_t retained = find_state_(epoch_slot_state::RETAINED);
		return published != INVALID_EPOCH_SLOT_INDEX && retained != INVALID_EPOCH_SLOT_INDEX &&
		       common::valid_epoch_id(slots_[published].epoch) &&
		       common::valid_epoch_id(slots_[retained].epoch) &&
		       slots_[retained].epoch < slots_[published].epoch;
	}

	std::array<epoch_slot_descriptor, EXACT_EPOCH_SLOT_COUNT> slots_{};  ///< Exact fixed slot metadata.
};

}  // namespace kinetum::dp
