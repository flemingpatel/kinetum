// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file timer_wheel.hpp
 * @brief Shared caller-storage hierarchical timer wheel.
 * @author Fleming Patel
 *
 * One arithmetic core serves both compile-time owning and runtime-capacity
 * caller-storage forms. The core uses a two-level intrusive wheel, O(1)
 * arm/cancel, generation-checked handles, bounded batch expiry, and no internal
 * clock. Large absolute-time advances rebuild from the exact occupied entry
 * population rather than iterating elapsed empty ticks.
 *
 * @par Thread Safety
 * Every wheel has one owner. Construction, arm, cancel, rearm, advance, reset,
 * and destruction must occur on that owner. A caller-storage view borrows its
 * entry and slot-head arrays for its complete lifetime.
 *
 * @par Performance
 * No operation allocates. Arm/cancel/rearm are O(1). Ordinary adjacent advance
 * is O(expired work); an elapsed jump larger than the fine wheel is bounded by
 * the exact armed-entry population and never by elapsed ticks or empty capacity.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <type_traits>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

/** @brief Opaque generation-checked timer identity. */
struct timer_handle {
	uint64_t value{UINT64_MAX};  ///< High generation bits and low slot index.

	/** @return true when the handle is not the fixed invalid sentinel. */
	[[nodiscard]] bool valid() const noexcept
	{
		return value != UINT64_MAX;
	}
	/**
	 * @param other Candidate opaque handle.
	 * @return true only when both opaque handle values are byte-exact.
	 */
	bool operator==(const timer_handle &other) const noexcept = default;
};

/** Fixed invalid timer identity returned without ownership transfer. */
inline constexpr timer_handle INVALID_TIMER_HANDLE{UINT64_MAX};

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/** @brief Caller-storage representation of one timer-wheel entry. */
struct timer_wheel_entry {
	uint64_t expiry_tick{0};	    ///< Exact absolute expiry tick.
	uint64_t user_key{0};		    ///< Caller-owned opaque metadata.
	uint32_t next_in_slot{UINT32_MAX};  ///< Intrusive slot successor.
	uint32_t prev_in_slot{UINT32_MAX};  ///< Intrusive slot predecessor.
	uint32_t next_free{UINT32_MAX};	    ///< Intrusive free-list successor.
	uint32_t next_active{UINT32_MAX};   ///< Intrusive armed-list successor.
	uint32_t prev_active{UINT32_MAX};   ///< Intrusive armed-list predecessor.
	uint32_t slot_idx{UINT32_MAX};	    ///< Current fine/coarse slot.
	uint32_t generation{0};		    ///< Handle reuse generation.
	bool armed{false};		    ///< Entry owns one live timer.
	bool in_coarse{false};		    ///< slot_idx addresses coarse heads.
	std::array<uint8_t, 2> padding{};   ///< Explicit fixed layout.
};

static_assert(std::is_standard_layout_v<timer_wheel_entry>);
static_assert(std::is_trivially_copyable_v<timer_wheel_entry>);

}  // namespace detail
/** @endcond */

/**
 * @brief Runtime-capacity hierarchical wheel over exact caller-owned storage.
 *
 * @tparam FineSlots Power-of-two near-deadline slot count.
 * @tparam CoarseSlots Power-of-two far-deadline slot count.
 */
template <std::size_t FineSlots = 256, std::size_t CoarseSlots = 256>
class timer_wheel_view {
	static_assert(FineSlots >= 2u && (FineSlots & (FineSlots - 1u)) == 0u);
	static_assert(CoarseSlots >= 2u && (CoarseSlots & (CoarseSlots - 1u)) == 0u);
	static_assert(FineSlots <= std::numeric_limits<uint64_t>::max() / CoarseSlots,
		      "Timer-wheel horizon must fit uint64_t");

    public:
	using entry_type = detail::timer_wheel_entry;		      ///< Exact caller-storage entry type.
	static constexpr std::size_t FINE_SLOTS = FineSlots;	      ///< Near-deadline slot population.
	static constexpr std::size_t COARSE_SLOTS = CoarseSlots;      ///< Far-deadline slot population.
	static constexpr std::size_t FINE_MASK = FineSlots - 1u;      ///< Fine-slot modular mask.
	static constexpr std::size_t COARSE_MASK = CoarseSlots - 1u;  ///< Coarse-slot modular mask.
	static constexpr uint64_t MAX_RANGE =
		static_cast<uint64_t>(FineSlots) * static_cast<uint64_t>(CoarseSlots);	///< Maximum delay horizon.
	static constexpr std::size_t MAX_EXPIRE_BATCH = 64u;  ///< Maximum handles returned by one adjacent advance.

	/** @brief One bounded expiration prefix. */
	struct expire_result {
		std::array<timer_handle, MAX_EXPIRE_BATCH> handles{};  ///< Exact expired handles.
		uint32_t count{0};				       ///< Number of populated entries.
		/** @return true when this prefix contains no expired handle. */
		[[nodiscard]] bool empty() const noexcept
		{
			return count == 0u;
		}
	};

	/**
	 * @brief Bind exact empty-capable storage and reset it.
	 *
	 * @param entries Exact entry array with @p capacity elements.
	 * @param capacity Nonzero entry count representable by timer_handle.
	 * @param fine_heads Exact @c FineSlots head array.
	 * @param coarse_heads Exact @c CoarseSlots head array.
	 */
	timer_wheel_view(entry_type *entries, std::size_t capacity, uint32_t *fine_heads,
			 uint32_t *coarse_heads) noexcept
		: entries_(entries)
		, capacity_(capacity)
		, fine_wheel_(fine_heads)
		, coarse_wheel_(coarse_heads)
	{
		if (entries_ == nullptr || fine_wheel_ == nullptr || coarse_wheel_ == nullptr || capacity_ == 0u ||
		    capacity_ > UINT32_MAX) {
			std::terminate();
		}
		reset();
	}

	/** @brief Reject copying because entries have one exact sequence owner. */
	timer_wheel_view(const timer_wheel_view &) = delete;
	/** @brief Reject copy assignment because live timer ownership cannot duplicate. */
	timer_wheel_view &operator=(const timer_wheel_view &) = delete;
	/** @brief Reject moving because caller-storage addresses remain stable. */
	timer_wheel_view(timer_wheel_view &&) = delete;
	/** @brief Reject move assignment because caller-storage addresses remain stable. */
	timer_wheel_view &operator=(timer_wheel_view &&) = delete;
	/** @brief Release only the non-owning view; caller retains storage lifetime. */
	~timer_wheel_view() = default;

	/** @brief Clear every timer and invalidate all prior handles. */
	void reset() noexcept
	{
		current_tick_ = 0u;
		active_count_ = 0u;
		drain_pending_ = false;
		total_armed_ = 0u;
		total_expired_ = 0u;
		total_cancelled_ = 0u;
		for (uint32_t index = 0u; index < capacity_; ++index) {
			auto &entry = entries_[index];
			const uint32_t prior_generation = entry.generation;
			entry = {};
			entry.generation = next_generation_(prior_generation);
			entry.next_free = index + 1u < capacity_ ? index + 1u : UINT32_MAX;
		}
		free_head_ = 0u;
		active_head_ = UINT32_MAX;
		std::fill_n(fine_wheel_, FineSlots, UINT32_MAX);
		std::fill_n(coarse_wheel_, CoarseSlots, UINT32_MAX);
	}

	/**
	 * @brief Arm one relative timer, clamping only to the representable wheel horizon.
	 * @param ticks_from_now Positive relative delay; zero becomes one tick.
	 * @param user_key Caller-owned opaque metadata.
	 * @return Exact live handle, or the invalid sentinel on capacity/time overflow.
	 */
	[[nodiscard]] timer_handle arm(uint64_t ticks_from_now, uint64_t user_key = 0u) noexcept
	{
		if (ticks_from_now == 0u) {
			ticks_from_now = 1u;
		}
		if (ticks_from_now >= MAX_RANGE) {
			ticks_from_now = MAX_RANGE - 1u;
		}
		if (ticks_from_now > std::numeric_limits<uint64_t>::max() - current_tick_) {
			return INVALID_TIMER_HANDLE;
		}
		if (free_head_ == UINT32_MAX) {
			return INVALID_TIMER_HANDLE;
		}
		const uint32_t index = free_head_;
		auto &entry = entries_[index];
		free_head_ = entry.next_free;
		entry.next_free = UINT32_MAX;
		entry.generation = next_generation_(entry.generation);
		entry.expiry_tick = current_tick_ + ticks_from_now;
		entry.user_key = user_key;
		entry.armed = true;
		prepend_active_(index);
		insert_into_wheel_(index, entry.expiry_tick);
		++active_count_;
		++total_armed_;
		return make_handle_(index);
	}

	/**
	 * @brief Re-arm one exact live handle.
	 * @param handle Exact currently armed handle.
	 * @param ticks_from_now Positive relative delay, clamped to the wheel horizon.
	 * @return true only when the exact live timer was re-armed.
	 */
	bool rearm(timer_handle handle, uint64_t ticks_from_now) noexcept
	{
		if (!handle_matches_(handle)) {
			return false;
		}
		auto &entry = entries_[handle_index_(handle)];
		if (!entry.armed) {
			return false;
		}
		if (ticks_from_now == 0u) {
			ticks_from_now = 1u;
		}
		if (ticks_from_now >= MAX_RANGE) {
			ticks_from_now = MAX_RANGE - 1u;
		}
		if (ticks_from_now > std::numeric_limits<uint64_t>::max() - current_tick_) {
			return false;
		}
		unlink_from_slot_(handle_index_(handle));
		entry.expiry_tick = current_tick_ + ticks_from_now;
		insert_into_wheel_(handle_index_(handle), entry.expiry_tick);
		return true;
	}

	/**
	 * @brief Cancel one exact live handle and return its slot to the pool.
	 * @param handle Exact currently armed handle.
	 * @return true only when cancellation consumed that live timer.
	 */
	bool cancel(timer_handle handle) noexcept
	{
		if (!handle_matches_(handle)) {
			return false;
		}
		const uint32_t index = handle_index_(handle);
		if (!entries_[index].armed) {
			return false;
		}
		unlink_from_slot_(index);
		free_entry_(index);
		++total_cancelled_;
		return true;
	}

	/** @return Bounded exact expiration prefix after advancing one logical tick. */
	expire_result advance() noexcept
	{
		return advance_limited_(MAX_EXPIRE_BATCH);
	}

	/**
	 * @brief Advance toward an absolute tick without elapsed-empty-tick work.
	 *
	 * Adjacent movement preserves exact per-tick semantics. A jump larger than
	 * the fine-wheel range follows the intrusive armed-entry list exactly once,
	 * making the operation occupancy-bounded rather than proportional to elapsed
	 * ticks or empty capacity.
	 *
	 * @param target_tick Absolute owner tick at or after current_tick().
	 * @param[out] out Exact output storage, or null only when @p out_capacity is zero.
	 * @param out_capacity Number of writable handles at @p out.
	 * @return Number of exact expired handles written to @p out.
	 */
	uint32_t advance_to(uint64_t target_tick, timer_handle *out, uint32_t out_capacity) noexcept
	{
		if ((out == nullptr && out_capacity != 0u) || target_tick < current_tick_) {
			return 0u;
		}
		uint32_t total = 0u;
		if (!drain_pending_ && active_count_ == 0u) {
			current_tick_ = target_tick;
			return 0u;
		}
		if (!drain_pending_ && target_tick - current_tick_ > FineSlots) {
			total += rebuild_at_(target_tick, out, out_capacity);
		}
		while ((current_tick_ < target_tick || drain_pending_) && total < out_capacity) {
			auto batch = advance_limited_(out_capacity - total);
			for (uint32_t index = 0u; index < batch.count; ++index) {
				out[total++] = batch.handles[index];
			}
		}
		return total;
	}

	/** @return Current absolute owner tick. */
	[[nodiscard]] uint64_t current_tick() const noexcept
	{
		return current_tick_;
	}
	/** @return Number of currently armed entries. */
	[[nodiscard]] uint32_t active_count() const noexcept
	{
		return active_count_;
	}
	/** @return Successful arm count since the latest reset. */
	[[nodiscard]] uint64_t total_armed() const noexcept
	{
		return total_armed_;
	}
	/** @return Expiration count since the latest reset. */
	[[nodiscard]] uint64_t total_expired() const noexcept
	{
		return total_expired_;
	}
	/** @return Explicit cancellation count since the latest reset. */
	[[nodiscard]] uint64_t total_cancelled() const noexcept
	{
		return total_cancelled_;
	}
	/** @return Exact caller-storage entry capacity. */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return capacity_;
	}

	/**
	 * @brief Reconstruct one exact live handle by caller-storage slot.
	 *
	 * This bounded owner-only observation supports shutdown/drain scans without
	 * exposing or mutating entry internals outside the wheel arithmetic.
	 *
	 * @param slot_index Candidate caller-storage slot.
	 * @return Exact live handle, or the invalid sentinel when the slot is free.
	 */
	[[nodiscard]] timer_handle live_handle_at(std::size_t slot_index) const noexcept
	{
		if (slot_index >= capacity_ || !entries_[slot_index].armed) {
			return INVALID_TIMER_HANDLE;
		}
		return make_handle_(static_cast<uint32_t>(slot_index));
	}

	/**
	 * @param handle Exact current or just-expired handle.
	 * @return Caller metadata while the handle generation still matches.
	 */
	[[nodiscard]] uint64_t user_key(timer_handle handle) const noexcept
	{
		return handle_matches_(handle) ? entries_[handle_index_(handle)].user_key : 0u;
	}

    private:
	static constexpr uint64_t HANDLE_INDEX_MASK = UINT32_MAX;  ///< Low handle bits carrying the slot index.
	static constexpr uint32_t HANDLE_GENERATION_SHIFT = 32u;   ///< High handle generation bit offset.
	/** @param handle Opaque timer handle. @return Low compact slot identity. */
	static constexpr uint32_t handle_index_(timer_handle handle) noexcept
	{
		return static_cast<uint32_t>(handle.value & HANDLE_INDEX_MASK);
	}
	/** @param handle Opaque timer handle. @return High reuse generation. */
	static constexpr uint32_t handle_generation_(timer_handle handle) noexcept
	{
		return static_cast<uint32_t>(handle.value >> HANDLE_GENERATION_SHIFT);
	}
	/** @param generation Current slot generation. @return Next nonzero generation. */
	static uint32_t next_generation_(uint32_t generation) noexcept
	{
		if (generation == UINT32_MAX) {
			std::terminate();
		}
		return generation + 1u;
	}
	/** @param index Exact live entry index. @return Opaque current-generation handle. */
	[[nodiscard]] timer_handle make_handle_(uint32_t index) const noexcept
	{
		return timer_handle{(static_cast<uint64_t>(entries_[index].generation) << HANDLE_GENERATION_SHIFT) |
				    index};
	}
	/** @param handle Candidate handle. @return true only for this entry generation. */
	[[nodiscard]] bool handle_matches_(timer_handle handle) const noexcept
	{
		if (!handle.valid()) {
			return false;
		}
		const uint32_t index = handle_index_(handle);
		return index < capacity_ && entries_[index].generation == handle_generation_(handle);
	}

	/**
	 * @brief Advance or continue the current slot under one output bound.
	 * @param requested Maximum handles requested by the caller.
	 * @return Exact bounded expiration prefix.
	 */
	[[nodiscard]] expire_result advance_limited_(uint32_t requested) noexcept
	{
		expire_result result{};
		const uint32_t limit = static_cast<uint32_t>(
			std::min<std::size_t>(requested, static_cast<std::size_t>(MAX_EXPIRE_BATCH)));
		if (limit == 0u) {
			return result;
		}
		if (!drain_pending_) {
			if (current_tick_ == std::numeric_limits<uint64_t>::max()) {
				std::terminate();
			}
			++current_tick_;
			if ((current_tick_ & FINE_MASK) == 0u) {
				cascade_coarse_to_fine_();
			}
		}
		const std::size_t slot_index = current_tick_ & FINE_MASK;
		uint32_t cursor = fine_wheel_[slot_index];
		while (cursor != UINT32_MAX && result.count < limit) {
			const uint32_t next = entries_[cursor].next_in_slot;
			if (entries_[cursor].expiry_tick <= current_tick_) {
				result.handles[result.count++] = make_handle_(cursor);
				free_entry_(cursor);
				++total_expired_;
			}
			cursor = next;
		}
		fine_wheel_[slot_index] = cursor;
		if (cursor != UINT32_MAX) {
			entries_[cursor].prev_in_slot = UINT32_MAX;
		}
		drain_pending_ = cursor != UINT32_MAX;
		return result;
	}

	/**
	 * @brief Rebuild wheel heads at one far absolute tick.
	 * @param target_tick New exact absolute tick.
	 * @param[out] out Output handle storage, or null only at zero capacity.
	 * @param out_capacity Writable output handle count.
	 * @return Number of expired handles written.
	 */
	uint32_t rebuild_at_(uint64_t target_tick, timer_handle *out, uint32_t out_capacity) noexcept
	{
		std::fill_n(fine_wheel_, FineSlots, UINT32_MAX);
		std::fill_n(coarse_wheel_, CoarseSlots, UINT32_MAX);
		current_tick_ = target_tick;
		drain_pending_ = false;
		uint32_t emitted = 0u;
		const uint32_t expected_active = active_count_;
		uint32_t inspected = 0u;
		uint32_t index = active_head_;
		while (index != UINT32_MAX) {
			if (inspected >= expected_active || index >= capacity_) {
				std::terminate();
			}
			auto &entry = entries_[index];
			if (!entry.armed) {
				std::terminate();
			}
			const uint32_t next_active = entry.next_active;
			++inspected;
			entry.next_in_slot = UINT32_MAX;
			entry.prev_in_slot = UINT32_MAX;
			entry.slot_idx = UINT32_MAX;
			entry.in_coarse = false;
			if (entry.expiry_tick <= target_tick && emitted < out_capacity) {
				out[emitted++] = make_handle_(index);
				free_entry_(index);
				++total_expired_;
			} else if (entry.expiry_tick <= target_tick) {
				entry.slot_idx = static_cast<uint32_t>(current_tick_ & FINE_MASK);
				prepend_to_slot_(fine_wheel_[entry.slot_idx], index);
				drain_pending_ = true;
			} else {
				insert_into_wheel_(index, entry.expiry_tick);
			}
			index = next_active;
		}
		if (inspected != expected_active) {
			std::terminate();
		}
		return emitted;
	}

	/**
	 * @brief Insert one armed entry into its exact fine or coarse slot.
	 * @param index Exact armed entry index.
	 * @param absolute_tick Exact future expiry tick.
	 */
	void insert_into_wheel_(uint32_t index, uint64_t absolute_tick) noexcept
	{
		const uint64_t delta = absolute_tick - current_tick_;
		if (delta < FineSlots) {
			const std::size_t slot = absolute_tick & FINE_MASK;
			entries_[index].in_coarse = false;
			entries_[index].slot_idx = static_cast<uint32_t>(slot);
			prepend_to_slot_(fine_wheel_[slot], index);
		} else {
			const std::size_t slot = (absolute_tick / FineSlots) & COARSE_MASK;
			entries_[index].in_coarse = true;
			entries_[index].slot_idx = static_cast<uint32_t>(slot);
			prepend_to_slot_(coarse_wheel_[slot], index);
		}
	}

	/**
	 * @brief Prepend one detached entry to an intrusive slot list.
	 * @param[in,out] head Slot-list head identity.
	 * @param index Exact detached entry index.
	 */
	void prepend_to_slot_(uint32_t &head, uint32_t index) noexcept
	{
		entries_[index].prev_in_slot = UINT32_MAX;
		entries_[index].next_in_slot = head;
		if (head != UINT32_MAX) {
			entries_[head].prev_in_slot = index;
		}
		head = index;
	}

	/** @brief Prepend one newly armed entry to the occupied list. @param index Exact entry index. */
	void prepend_active_(uint32_t index) noexcept
	{
		auto &entry = entries_[index];
		if (entry.next_active != UINT32_MAX || entry.prev_active != UINT32_MAX) {
			std::terminate();
		}
		entry.next_active = active_head_;
		if (active_head_ != UINT32_MAX) {
			entries_[active_head_].prev_active = index;
		}
		active_head_ = index;
	}

	/** @brief Remove one armed entry from the occupied list. @param index Exact entry index. */
	void unlink_active_(uint32_t index) noexcept
	{
		auto &entry = entries_[index];
		if (entry.prev_active != UINT32_MAX) {
			entries_[entry.prev_active].next_active = entry.next_active;
		} else if (active_head_ == index) {
			active_head_ = entry.next_active;
		} else {
			std::terminate();
		}
		if (entry.next_active != UINT32_MAX) {
			entries_[entry.next_active].prev_active = entry.prev_active;
		}
		entry.next_active = UINT32_MAX;
		entry.prev_active = UINT32_MAX;
	}

	/** @brief Unlink one exact armed entry. @param index Exact entry index. */
	void unlink_from_slot_(uint32_t index) noexcept
	{
		auto &entry = entries_[index];
		uint32_t *head = entry.in_coarse ? &coarse_wheel_[entry.slot_idx] : &fine_wheel_[entry.slot_idx];
		if (entry.prev_in_slot != UINT32_MAX) {
			entries_[entry.prev_in_slot].next_in_slot = entry.next_in_slot;
		} else {
			*head = entry.next_in_slot;
		}
		if (entry.next_in_slot != UINT32_MAX) {
			entries_[entry.next_in_slot].prev_in_slot = entry.prev_in_slot;
		}
		entry.prev_in_slot = UINT32_MAX;
		entry.next_in_slot = UINT32_MAX;
		entry.slot_idx = UINT32_MAX;
		entry.in_coarse = false;
	}

	/** @brief Move the current coarse bucket into exact fine slots. */
	void cascade_coarse_to_fine_() noexcept
	{
		const std::size_t coarse_index = (current_tick_ / FineSlots) & COARSE_MASK;
		uint32_t cursor = coarse_wheel_[coarse_index];
		coarse_wheel_[coarse_index] = UINT32_MAX;
		while (cursor != UINT32_MAX) {
			const uint32_t next = entries_[cursor].next_in_slot;
			entries_[cursor].prev_in_slot = UINT32_MAX;
			entries_[cursor].next_in_slot = UINT32_MAX;
			const std::size_t fine_index = entries_[cursor].expiry_tick & FINE_MASK;
			entries_[cursor].in_coarse = false;
			entries_[cursor].slot_idx = static_cast<uint32_t>(fine_index);
			prepend_to_slot_(fine_wheel_[fine_index], cursor);
			cursor = next;
		}
	}

	/** @brief Return one expired/cancelled entry to the free list. @param index Exact entry index. */
	void free_entry_(uint32_t index) noexcept
	{
		auto &entry = entries_[index];
		if (!entry.armed) {
			std::terminate();
		}
		unlink_active_(index);
		entry.armed = false;
		entry.next_free = free_head_;
		entry.prev_in_slot = UINT32_MAX;
		entry.next_in_slot = UINT32_MAX;
		entry.slot_idx = UINT32_MAX;
		entry.in_coarse = false;
		free_head_ = index;
		if (active_count_ == 0u) {
			std::terminate();
		}
		--active_count_;
	}

	entry_type *entries_{nullptr};	    ///< Exact caller-owned entry population.
	std::size_t capacity_{0};	    ///< Exact runtime capacity.
	uint32_t *fine_wheel_{nullptr};	    ///< Exact caller-owned fine heads.
	uint32_t *coarse_wheel_{nullptr};   ///< Exact caller-owned coarse heads.
	uint64_t current_tick_{0};	    ///< Current absolute owner tick.
	uint32_t active_count_{0};	    ///< Exact armed-entry population.
	uint32_t free_head_{0};		    ///< Intrusive free-list head.
	uint32_t active_head_{UINT32_MAX};  ///< Intrusive occupied-list head.
	bool drain_pending_{false};	    ///< Current fine slot still has expired entries.
	uint64_t total_armed_{0};	    ///< Successful arm count since reset.
	uint64_t total_expired_{0};	    ///< Expired handle count since reset.
	uint64_t total_cancelled_{0};	    ///< Explicit cancellation count since reset.
};

/**
 * @brief Compile-time owning wrapper over the shared caller-storage wheel.
 * @tparam MaxTimers Exact embedded timer-entry capacity.
 * @tparam FineSlots Power-of-two near-deadline slot count.
 * @tparam CoarseSlots Power-of-two far-deadline slot count.
 */
template <std::size_t MaxTimers = 4096, std::size_t FineSlots = 256, std::size_t CoarseSlots = 256>
class timer_wheel {
	static_assert(MaxTimers >= 1u && MaxTimers <= UINT32_MAX);

    public:
	using view_type = timer_wheel_view<FineSlots, CoarseSlots>;   ///< Shared caller-storage arithmetic type.
	using expire_result = typename view_type::expire_result;      ///< Shared bounded expiry result.
	static constexpr std::size_t MAX_TIMERS = MaxTimers;	      ///< Exact embedded entry population.
	static constexpr std::size_t FINE_SLOTS = FineSlots;	      ///< Near-deadline slot population.
	static constexpr std::size_t COARSE_SLOTS = CoarseSlots;      ///< Far-deadline slot population.
	static constexpr std::size_t FINE_MASK = FineSlots - 1u;      ///< Fine-slot modular mask.
	static constexpr std::size_t COARSE_MASK = CoarseSlots - 1u;  ///< Coarse-slot modular mask.
	static constexpr uint64_t MAX_RANGE = view_type::MAX_RANGE;   ///< Maximum delay horizon.
	static constexpr std::size_t MAX_EXPIRE_BATCH =
		view_type::MAX_EXPIRE_BATCH;  ///< Maximum adjacent expiration prefix.

	/** @brief Construct one empty wheel over its exact embedded storage. */
	timer_wheel() noexcept
		: view_(entries_.data(), entries_.size(), fine_wheel_.data(), coarse_wheel_.data())
	{
	}

	/** @brief Clear every timer and invalidate all prior handles. */
	void reset() noexcept
	{
		view_.reset();
	}
	/**
	 * @brief Arm one relative timer.
	 * @param ticks_from_now Positive relative ticks, clamped to the wheel horizon.
	 * @param user_key Caller-owned opaque metadata.
	 * @return Exact handle, or the invalid sentinel when capacity is exhausted.
	 */
	[[nodiscard]] timer_handle arm(uint64_t ticks_from_now, uint64_t user_key = 0u) noexcept
	{
		return view_.arm(ticks_from_now, user_key);
	}
	/**
	 * @brief Re-arm one exact live timer.
	 * @param handle Exact currently armed handle.
	 * @param ticks_from_now Positive relative ticks.
	 * @return true only when the handle was live and re-armed.
	 */
	bool rearm(timer_handle handle, uint64_t ticks_from_now) noexcept
	{
		return view_.rearm(handle, ticks_from_now);
	}
	/**
	 * @brief Cancel one exact live timer.
	 * @param handle Exact currently armed handle.
	 * @return true only when cancellation consumed the timer.
	 */
	bool cancel(timer_handle handle) noexcept
	{
		return view_.cancel(handle);
	}
	/** @return Bounded expiration prefix after one logical tick. */
	expire_result advance() noexcept
	{
		return view_.advance();
	}
	/**
	 * @brief Advance toward one absolute tick.
	 * @param target_tick Absolute owner tick at or after current_tick().
	 * @param[out] out Exact output storage.
	 * @param out_capacity Writable handle count at @p out.
	 * @return Number of exact handles written.
	 */
	uint32_t advance_to(uint64_t target_tick, timer_handle *out, uint32_t out_capacity) noexcept
	{
		return view_.advance_to(target_tick, out, out_capacity);
	}
	/** @return Current absolute owner tick. */
	[[nodiscard]] uint64_t current_tick() const noexcept
	{
		return view_.current_tick();
	}
	/** @return Number of currently armed entries. */
	[[nodiscard]] uint32_t active_count() const noexcept
	{
		return view_.active_count();
	}
	/** @return Successful arm count since the latest reset. */
	[[nodiscard]] uint64_t total_armed() const noexcept
	{
		return view_.total_armed();
	}
	/** @return Expiration count since the latest reset. */
	[[nodiscard]] uint64_t total_expired() const noexcept
	{
		return view_.total_expired();
	}
	/** @return Explicit cancellation count since the latest reset. */
	[[nodiscard]] uint64_t total_cancelled() const noexcept
	{
		return view_.total_cancelled();
	}
	/**
	 * @brief Read caller metadata while one handle generation still matches.
	 * @param handle Exact current or just-expired handle.
	 * @return Caller metadata, or zero for an invalid generation.
	 */
	[[nodiscard]] uint64_t user_key(timer_handle handle) const noexcept
	{
		return view_.user_key(handle);
	}

    private:
	std::array<typename view_type::entry_type, MaxTimers> entries_{};  ///< Embedded timer entries.
	std::array<uint32_t, FineSlots> fine_wheel_{};			   ///< Embedded fine-slot heads.
	std::array<uint32_t, CoarseSlots> coarse_wheel_{};		   ///< Embedded coarse-slot heads.
	view_type view_;						   ///< Sole shared arithmetic owner.
};

}  // namespace kinetum::algo
