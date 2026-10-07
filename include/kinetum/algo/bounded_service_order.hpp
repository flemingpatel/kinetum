// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file bounded_service_order.hpp
 * @brief Caller-storage fair service with bounded carried allowances.
 * @author Fleming Patel
 *
 * A completed quantum moves behind waiting inputs. Capacity-limited work
 * keeps its unfinished allowance and position; other inputs may still run.
 * The order owns no queued objects or capacity. Eligibility and resource
 * transfer belong to the caller.
 *
 * @par Thread Safety
 * One owner invokes service(). The callback must not reenter the order or
 * modify its borrowed storage. Storage outlives the order and every callback.
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <span>
#include <stdexcept>
#include <type_traits>

namespace kinetum::algo
{

/** @brief Whether an input relinquishes or retains its unfinished opportunity. */
enum class service_disposition : uint8_t {
	YIELDED = 1,   ///< Empty, temporarily yielding, or no longer eligible.
	RETAINED = 2,  ///< More service may be needed when capacity permits.
};

/** @brief Work performed by one bounded, nonthrowing service invocation. */
struct service_result {
	uint16_t work{0};  ///< Consumed allowance, including rejected work.
	service_disposition disposition{service_disposition::YIELDED};	///< Exact continuation disposition.
};

/**
 * @brief Maintain fair service order over one immutable input population.
 *
 * Each input consumes at most its quantum per turn. A partial quantum survives
 * capacity exhaustion; a yielding input discards its remainder. Completing a
 * carried quantum permits one additional visit for the unused turn allowance.
 * There are at most two visits per input and O(1) order updates, independent of
 * queued work. No operation allocates, locks, reads a clock, or owns work.
 */
class bounded_service_order final {
	/** Absence sentinel outside the admitted compact input population. */
	static constexpr uint32_t INVALID_INDEX = std::numeric_limits<uint32_t>::max();

    public:
	/** @brief Caller-owned storage for one immutable quantum and its service state. */
	class entry final {
	    public:
		/**
		 * @brief Supply a quantum for validation when the complete order is bound.
		 * @param quantum Nonzero maximum work per turn and complete opportunity.
		 */
		explicit constexpr entry(uint16_t quantum) noexcept
			: quantum_(quantum)
		{
		}

	    private:
		friend class bounded_service_order;
		uint32_t previous_{INVALID_INDEX};  ///< Previous input in persistent service order.
		uint32_t next_{INVALID_INDEX};	    ///< Next input in persistent service order.
		uint16_t quantum_{0};		    ///< Immutable complete opportunity and per-turn ceiling.
		uint16_t remainder_{0};		    ///< Unfinished opportunity; zero means a fresh quantum.
		uint16_t turn_remainder_{0};	    ///< Remaining work budget for this turn.
	};

	/**
	 * @brief Validate all quanta, then bind and initialize exact caller storage.
	 * @param entries Complete population, empty only for an input-free owner.
	 * @throws std::length_error if compact input identities cannot represent the population.
	 * @throws std::invalid_argument if any quantum is zero.
	 */
	explicit bounded_service_order(std::span<entry> entries)
		: entries_(entries)
	{
		if (entries.size() >= INVALID_INDEX) {
			throw std::length_error("service order input population exceeds compact identity range");
		}
		for (const auto &input : entries) {
			if (input.quantum_ == 0u) {
				throw std::invalid_argument("service order requires nonzero input quanta");
			}
		}
		const auto count = static_cast<uint32_t>(entries.size());
		for (uint32_t index = 0u; index < count; ++index) {
			auto &input = entries_[index];
			input.previous_ = index == 0u ? INVALID_INDEX : index - 1u;
			input.next_ = index + 1u == count ? INVALID_INDEX : index + 1u;
			input.remainder_ = 0u;
			input.turn_remainder_ = 0u;
		}
		if (count != 0u) {
			head_ = 0u;
			tail_ = count - 1u;
		}
	}

	/** @brief Borrowed mutable ordering state cannot be copied. */
	bounded_service_order(const bounded_service_order &) = delete;
	/** @brief Copy assignment would create a second writer. */
	bounded_service_order &operator=(const bounded_service_order &) = delete;
	/** @brief Keep the single ordering owner stable for its storage lifetime. */
	bounded_service_order(bounded_service_order &&) = delete;
	/** @brief Move assignment cannot replace an active ordering owner. */
	bounded_service_order &operator=(bounded_service_order &&) = delete;

	/**
	 * @brief Service one bounded turn, preserving unfinished input precedence.
	 * @tparam visitor_type Nonthrowing callable returning service_result.
	 * @param visitor Receives the stable input index and a positive allowance.
	 *        It reports actual work no greater than that allowance. YIELDED
	 *        clears carry; RETAINED preserves only an unfinished quantum.
	 */
	template <typename visitor_type>
	void service(visitor_type &&visitor) noexcept
	{
		static_assert(std::is_nothrow_invocable_r_v<service_result, visitor_type &, uint32_t, uint16_t>);
		const auto count = static_cast<uint32_t>(entries_.size());
		if (count == 0u) {
			return;
		}
		if (count == 1u) {
			// One input has no competing opportunity to preserve across turns.
			validate_result_(visitor(0u, entries_[0].quantum_), entries_[0].quantum_);
			return;
		}
		uint32_t index = head_;
		bool have_revisit = false;
		for (uint32_t visited = 0u; visited < count; ++visited) {
			auto &input = entries_[index];
			const uint32_t next = input.next_;
			input.turn_remainder_ = input.quantum_;
			visit_(index, visitor);
			have_revisit |= input.turn_remainder_ != 0u;
			index = next;
		}
		if (!have_revisit) {
			return;
		}
		index = head_;
		for (uint32_t visited = 0u; visited < count; ++visited) {
			auto &input = entries_[index];
			const uint32_t next = input.next_;
			if (input.turn_remainder_ != 0u) {
				visit_(index, visitor);
			}
			index = next;
		}
	}

    private:
	/**
	 * @brief Reject invalid callback progress before applying its result.
	 * @param result Exact callback outcome.
	 * @param offered Maximum permitted work for that invocation.
	 */
	static void validate_result_(service_result result, uint16_t offered) noexcept
	{
		if (result.work > offered) {
			std::terminate();
		}
		switch (result.disposition) {
		case service_disposition::YIELDED:
		case service_disposition::RETAINED:
			return;
		}
		std::terminate();
	}

	/**
	 * @brief Consume one opportunity prefix and update only its owner's state.
	 * @tparam visitor_type Nonthrowing service callable.
	 * @param index Exact input being visited.
	 * @param visitor Borrowed callback retained only during this invocation.
	 */
	template <typename visitor_type>
	void visit_(uint32_t index, visitor_type &visitor) noexcept
	{
		auto &input = entries_[index];
		const uint16_t turn_allowance = input.turn_remainder_;
		const uint16_t remaining = input.remainder_ == 0u ? input.quantum_ : input.remainder_;
		const uint16_t offered = std::min(remaining, turn_allowance);
		const service_result result = visitor(index, offered);
		validate_result_(result, offered);
		input.turn_remainder_ = 0u;
		if (result.disposition == service_disposition::YIELDED) {
			input.remainder_ = 0u;
			move_to_back_(index);
			return;
		}
		input.remainder_ = static_cast<uint16_t>(remaining - result.work);
		if (input.remainder_ == 0u) {
			input.turn_remainder_ = static_cast<uint16_t>(turn_allowance - result.work);
			move_to_back_(index);
		}
	}

	/**
	 * @brief Move a completed or yielding input behind every waiting input.
	 * @param index Exact input whose service opportunity has ended.
	 */
	void move_to_back_(uint32_t index) noexcept
	{
		if (index == tail_) {
			return;
		}
		auto &input = entries_[index];
		if (input.previous_ == INVALID_INDEX) {
			head_ = input.next_;
		} else {
			entries_[input.previous_].next_ = input.next_;
		}
		entries_[input.next_].previous_ = input.previous_;
		input.previous_ = tail_;
		input.next_ = INVALID_INDEX;
		entries_[tail_].next_ = index;
		tail_ = index;
	}

	std::span<entry> entries_;	///< Borrowed fixed input population and sole mutable service state.
	uint32_t head_{INVALID_INDEX};	///< Earliest unfinished input.
	uint32_t tail_{INVALID_INDEX};	///< Most recently completed or yielding input.
};

}  // namespace kinetum::algo
