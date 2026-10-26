// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file queue.hpp
 * @brief Bounded concurrent and single-owner queues for packet processing.
 * @author Fleming Patel
 *
 * This is the canonical queue implementation for the platform.
 * All components (DP, CP, Photon, Gluon, SDK) should include from here.
 *
 * Contains:
 * - spsc_ring_static: SPSC with compile-time capacity
 * - spsc_ring: SPSC with runtime capacity
 * - spsc_ring_view: SPSC over exact caller-owned runtime storage
 * - mpmc_queue: MPMC with compile-time capacity
 * - mpmc_queue_dynamic: MPMC with construction-time capacity
 * - mpmc_queue_view: MPMC over exact caller-owned runtime storage
 * - work_queue_view: caller-storage single-owner circular arithmetic
 *
 * Hot-path characteristics:
 *  - No dynamic allocation after construction
 *  - Power-of-2 capacity enables mask-based indexing
 *  - Private SPSC cursor caches are isolated from shared publications
 *  - Acquire/release publication between the exact queue owners
 *  - Batch operations reduce synchronization work per element
 *  - Actual latency depends on element type, CPU, compiler, and cache state
 *
 * Supported targets: little-endian x86-64 and AArch64.
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/work_queue_indices.hpp>

namespace kinetum::algo
{

// =============================================================================
// Constants
// =============================================================================

/** @brief Default power-of-two SPSC ring capacity. */
inline constexpr std::size_t DEFAULT_RING_CAPACITY = 2048;

// =============================================================================
// SPSC Ring Buffer - Shared Arithmetic Core and Storage Owners
// =============================================================================

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/** @brief Uninitialized storage for one SPSC element. */
template <typename T>
using spsc_storage = std::aligned_storage_t<sizeof(T), alignof(T)>;

/**
 * @brief Validate one runtime SPSC capacity before storage ownership changes.
 *
 * @param capacity Candidate usable capacity.
 * @return The same exact power-of-two capacity.
 * @throws std::invalid_argument when capacity is below two, is not a power of
 *         two, or exceeds the modular counter half-range.
 */
inline std::size_t validate_spsc_capacity(std::size_t capacity)
{
	if (capacity < 2) {
		throw std::invalid_argument("spsc_ring: capacity must be at least 2");
	}
	if ((capacity & (capacity - 1)) != 0) {
		throw std::invalid_argument("spsc_ring: capacity must be a power of 2");
	}
	if (capacity > std::numeric_limits<std::size_t>::max() / 2u) {
		throw std::invalid_argument("spsc_ring: capacity exceeds the modular counter half-range");
	}
	return capacity;
}

/**
 * @brief Compile-time capacity owner with no runtime capacity field.
 *
 * @tparam StaticCapacity Exact nonzero ring capacity.
 */
template <std::size_t StaticCapacity>
class spsc_capacity_owner {
    protected:
	/** @brief Construct the field-free compile-time capacity owner. */
	constexpr spsc_capacity_owner() noexcept = default;

	/**
	 * @brief Return the exact compile-time ring capacity.
	 *
	 * @return @c StaticCapacity.
	 */
	[[nodiscard]] static constexpr std::size_t ring_capacity() noexcept
	{
		return StaticCapacity;
	}
};

/** @brief Runtime-capacity owner used by dynamic and borrowed-storage rings. */
template <>
class spsc_capacity_owner<0> {
    protected:
	/**
	 * @brief Validate and retain one exact runtime capacity.
	 *
	 * @param requested Candidate power-of-two capacity.
	 * @throws std::invalid_argument when @p requested violates the SPSC
	 *         capacity contract.
	 */
	explicit spsc_capacity_owner(std::size_t requested)
		: capacity_(validate_spsc_capacity(requested))
	{
	}

	/**
	 * @brief Return the exact admitted runtime ring capacity.
	 *
	 * @return Construction-time capacity.
	 */
	[[nodiscard]] std::size_t ring_capacity() const noexcept
	{
		return capacity_;
	}

    private:
	std::size_t capacity_;	///< Exact runtime usable capacity.
};

/**
 * @brief Sole SPSC sequence, lifetime, and acquire/release implementation.
 *
 * @tparam T Element type.
 * @tparam StaticCapacity Compile-time capacity, or zero for runtime capacity.
 *
 * @par Thread Safety
 * One producer owns head and cached tail. One consumer owns tail and cached
 * head. Each publication and each private cache occupies a separate cache
 * line. Cross-owner publication uses release stores and acquire reloads. The
 * caller owns disjoint backing storage for the complete core lifetime.
 *
 * @par Performance
 * Every single-element operation is O(1). A batch of length k is O(k) with
 * at most one acquire refresh and one release publication. No operation
 * allocates after the backing storage has been bound.
 */
template <typename T, std::size_t StaticCapacity>
class spsc_ring_core final : private spsc_capacity_owner<StaticCapacity> {
	static_assert(std::is_move_constructible_v<T>, "T must be move-constructible");
	static_assert(StaticCapacity == 0 || StaticCapacity >= 2, "Capacity must be at least 2");
	static_assert(StaticCapacity == 0 || (StaticCapacity & (StaticCapacity - 1)) == 0,
		      "Capacity must be power of 2");

    public:
	using storage_type = spsc_storage<T>;  ///< Uninitialized backing-slot representation.

	/**
	 * @brief Bind one static-capacity core to exact uninitialized storage.
	 *
	 * The caller retains storage for the complete core lifetime and supplies
	 * exactly @c StaticCapacity aligned slots.
	 *
	 * @param storage Exact embedded aligned-storage array.
	 */
	explicit spsc_ring_core(std::array<storage_type, StaticCapacity> &storage) noexcept
		requires(StaticCapacity != 0)
		: spsc_capacity_owner<StaticCapacity>()
		, storage_(storage.data())
	{
	}

	/**
	 * @brief Bind one runtime-capacity core to exact uninitialized storage.
	 *
	 * The caller retains storage for the complete core lifetime and may reclaim
	 * it only after the quiescent core is destroyed.
	 *
	 * @param storage Aligned storage for exactly @p capacity elements.
	 * @param capacity Exact usable power-of-two capacity.
	 * @throws std::invalid_argument for null storage or an invalid capacity.
	 */
	spsc_ring_core(storage_type *storage, std::size_t capacity)
		requires(StaticCapacity == 0)
		: spsc_capacity_owner<StaticCapacity>(capacity)
		, storage_(storage)
	{
		if (storage_ == nullptr) {
			throw std::invalid_argument("spsc_ring: backing storage must not be null");
		}
	}

	spsc_ring_core(const spsc_ring_core &) = delete;
	spsc_ring_core &operator=(const spsc_ring_core &) = delete;
	spsc_ring_core(spsc_ring_core &&) = delete;
	spsc_ring_core &operator=(spsc_ring_core &&) = delete;

	/** @brief Destroy every element still owned by the ring. */
	~spsc_ring_core()
	{
		clear_remaining_();
	}

	/**
	 * @brief Try to publish one copied value.
	 *
	 * @param value Value borrowed for this call.
	 * @return true when copied and release-published; false when full.
	 */
	[[nodiscard]] bool try_push(const T &value) noexcept(std::is_nothrow_copy_constructible_v<T>)
	{
		return try_push_impl_(value);
	}

	/**
	 * @brief Try to publish one moved value without consuming it on full.
	 *
	 * @param value Value consumed only after capacity is proved.
	 * @return true when moved and release-published; false when full.
	 */
	[[nodiscard]] bool try_push(T &&value) noexcept(std::is_nothrow_move_constructible_v<T>)
	{
		return try_push_impl_(std::move(value));
	}

	/**
	 * @brief Construct and publish one element when capacity is available.
	 *
	 * @tparam Args Constructor argument types.
	 * @param args Arguments forwarded only after capacity is proved.
	 * @return true when constructed and release-published; false when full.
	 */
	template <typename... Args>
	[[nodiscard]] bool try_emplace(Args &&...args) noexcept(std::is_nothrow_constructible_v<T, Args...>)
	{
		const std::size_t head = head_.load(std::memory_order_relaxed);
		if (!producer_has_capacity_(head)) {
			return false;
		}
		new (&storage_[head & mask_()]) T(std::forward<Args>(args)...);
		head_.store(head + 1u, std::memory_order_release);
		return true;
	}

	/**
	 * @brief Publish the largest capacity-admitted prefix of one copied batch.
	 *
	 * All accepted elements are constructed before one release publication, so
	 * the operation is available only when copying cannot throw. The producer
	 * performs no allocation and publishes at most once.
	 *
	 * @param items Contiguous input values; nonnull when @p count is nonzero.
	 * @param count Number of available input values.
	 * @return Number of values copied and published, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t push_batch(const T *items, std::size_t count) noexcept
		requires std::is_nothrow_copy_constructible_v<T>
	{
		if (count == 0u) {
			return 0u;
		}
		const std::size_t head = head_.load(std::memory_order_relaxed);
		const std::size_t available = producer_available_(head, count);
		const std::size_t to_push = count < available ? count : available;
		const std::size_t mask = mask_();
		for (std::size_t index = 0; index < to_push; ++index) {
			new (&storage_[(head + index) & mask]) T(items[index]);
		}
		if (to_push != 0) {
			head_.store(head + to_push, std::memory_order_release);
		}
		return to_push;
	}

	/**
	 * @brief Move-assign and consume one element when available.
	 *
	 * @param out Initialized destination replaced only when a value is present.
	 * @return true when one value is consumed; false when empty.
	 */
	[[nodiscard]] bool try_pop(T &out) noexcept
		requires std::is_nothrow_move_assignable_v<T>
	{
		const std::size_t tail = tail_.load(std::memory_order_relaxed);
		if (!consumer_has_value_(tail)) {
			return false;
		}
		T *slot = slot_(tail & mask_());
		out = std::move(*slot);
		slot->~T();
		tail_.store(tail + 1u, std::memory_order_release);
		return true;
	}

	/**
	 * @brief Move-construct and consume one optional element.
	 *
	 * @return One consumed value, or an empty optional when the ring is empty.
	 */
	[[nodiscard]] std::optional<T> try_pop() noexcept
		requires std::is_nothrow_move_constructible_v<T>
	{
		const std::size_t tail = tail_.load(std::memory_order_relaxed);
		if (!consumer_has_value_(tail)) {
			return std::nullopt;
		}
		T *slot = slot_(tail & mask_());
		std::optional<T> value(std::in_place, std::move(*slot));
		slot->~T();
		tail_.store(tail + 1u, std::memory_order_release);
		return value;
	}

	/**
	 * @brief Consume the largest available prefix into caller-owned storage.
	 *
	 * All accepted ring elements are destroyed before one release publication,
	 * so the operation is available only when output move assignment cannot
	 * throw. The consumer performs no allocation and publishes at most once.
	 *
	 * @param out Contiguous initialized output values; nonnull when
	 *            @p max_count is nonzero.
	 * @param max_count Maximum number of values to consume.
	 * @return Number of values move-assigned and consumed, in
	 *         `[0, max_count]`.
	 */
	[[nodiscard]] std::size_t pop_batch(T *out, std::size_t max_count) noexcept
		requires std::is_nothrow_move_assignable_v<T>
	{
		std::size_t index = 0u;
		return consume_prefix_(max_count, [&](T &value) noexcept {
			out[index++] = std::move(value);
			return true;
		});
	}

	/**
	 * @brief Admit and consume one bounded FIFO prefix with one tail publication.
	 * The sole consumer borrows each value before its lifetime ends. Returning
	 * false leaves that value and every later value in the ring. Returning true
	 * completes the caller's ownership work before destruction and publication.
	 * @tparam accept_type Nonthrowing callback over a read-only element borrow.
	 * @param max_count Maximum number of values considered; zero invokes nothing.
	 * @param accept Returns true only after accepting that element. It must not
	 *        retain the borrow, mutate this ring, or invoke foreign callbacks.
	 * @return Number accepted and consumed before the first refusal or limit.
	 */
	template <typename accept_type>
	[[nodiscard]] std::size_t consume_prefix(std::size_t max_count, accept_type &&accept) noexcept
		requires(std::is_nothrow_invocable_r_v<bool, accept_type &, const T &> &&
			 std::is_nothrow_destructible_v<T>)
	{
		return consume_prefix_(max_count,
				       [&](T &value) noexcept { return std::invoke(accept, std::as_const(value)); });
	}

	/**
	 * @brief Borrow the current front value without consuming it.
	 *
	 * Only the sole consumer may call this method. The returned pointer remains
	 * valid until that consumer performs the matching pop operation; it must not
	 * be retained across any consumer-side mutation of the ring.
	 *
	 * @return Pointer to the current front value, or null when the ring is empty.
	 */
	[[nodiscard]] const T *peek() const noexcept
	{
		const std::size_t tail = tail_.load(std::memory_order_relaxed);
		if (!consumer_has_value_(tail)) {
			return nullptr;
		}
		return std::launder(reinterpret_cast<const T *>(&storage_[tail & mask_()]));
	}

	/**
	 * @brief Return whether the observed ring is empty.
	 *
	 * @return One acquire-ordered observation; concurrent ownership may change
	 *         immediately after return.
	 */
	[[nodiscard]] bool empty() const noexcept
	{
		return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
	}

	/**
	 * @brief Return whether the observed ring is full.
	 *
	 * @return One observational full-state result.
	 */
	[[nodiscard]] bool full() const noexcept
	{
		return size_approx() >= capacity_();
	}

	/**
	 * @brief Return one observational count of currently unused slots.
	 *
	 * @return Approximate free-slot count bounded by exact capacity.
	 */
	[[nodiscard]] std::size_t available() const noexcept
	{
		const std::size_t size = size_approx();
		return size < capacity_() ? capacity_() - size : 0;
	}

	/**
	 * @brief Return one observational element count.
	 *
	 * @return Approximate published element count.
	 */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		return head_.load(std::memory_order_acquire) - tail_.load(std::memory_order_acquire);
	}

	/**
	 * @brief Return the exact usable capacity.
	 *
	 * @return Compile-time or construction-time capacity selected by the owner.
	 */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return capacity_();
	}

    private:
	/**
	 * @brief Return the exact usable capacity from the selected owner.
	 *
	 * @return Compile-time or retained runtime capacity.
	 */
	[[nodiscard]] std::size_t capacity_() const noexcept
	{
		return this->ring_capacity();
	}

	/**
	 * @brief Return the prevalidated power-of-two index mask.
	 *
	 * @return Exact capacity minus one.
	 */
	[[nodiscard]] std::size_t mask_() const noexcept
	{
		return capacity_() - 1u;
	}

	/**
	 * @brief Return conservative producer capacity, refreshing only an insufficient cache.
	 *
	 * @param head Producer-owned publication sequence.
	 * @param requested Desired prefix length.
	 * @return Available slots established by the acquired peer cursor.
	 */
	[[nodiscard]] std::size_t producer_available_(std::size_t head, std::size_t requested) noexcept
	{
		std::size_t available = capacity_() - (head - cached_tail_);
		if (available < requested) {
			cached_tail_ = tail_.load(std::memory_order_acquire);
			available = capacity_() - (head - cached_tail_);
		}
		return available;
	}

	/**
	 * @brief Return the acquired consumer prefix, refreshing only an insufficient cache.
	 *
	 * @param tail Consumer-owned publication sequence.
	 * @param requested Desired prefix length.
	 * @return Published values established by the acquired peer cursor.
	 */
	[[nodiscard]] std::size_t consumer_available_(std::size_t tail, std::size_t requested) const noexcept
	{
		std::size_t available = cached_head_ - tail;
		if (available < requested) {
			cached_head_ = head_.load(std::memory_order_acquire);
			available = cached_head_ - tail;
		}
		return available;
	}

	/** @param head Sole producer sequence. @return Whether one slot is available. */
	[[nodiscard]] bool producer_has_capacity_(std::size_t head) noexcept
	{
		return producer_available_(head, 1u) != 0u;
	}

	/** @param tail Sole consumer sequence. @return Whether one value is available. */
	[[nodiscard]] bool consumer_has_value_(std::size_t tail) const noexcept
	{
		return consumer_available_(tail, 1u) != 0u;
	}

	/**
	 * @brief Share prefix lifetime and publication arithmetic across consumer APIs.
	 * @tparam consume_type Nonthrowing callback that may move an accepted value.
	 * @param max_count Maximum number of elements considered.
	 * @param consume Accepts the next value or refuses it without changing it.
	 * @return Exact consumed prefix; no later value bypasses a refusal.
	 */
	template <typename consume_type>
	[[nodiscard]] std::size_t consume_prefix_(std::size_t max_count, consume_type &&consume) noexcept
	{
		static_assert(std::is_nothrow_invocable_r_v<bool, consume_type &, T &>);
		if (max_count == 0u) {
			return 0u;
		}
		const std::size_t tail = tail_.load(std::memory_order_relaxed);
		const std::size_t available = consumer_available_(tail, max_count);
		const std::size_t limit = std::min(max_count, available);
		const std::size_t mask = mask_();
		std::size_t consumed = 0u;
		while (consumed < limit) {
			T *slot = slot_((tail + consumed) & mask);
			if (!std::invoke(consume, *slot)) {
				break;
			}
			std::destroy_at(slot);
			++consumed;
		}
		if (consumed != 0u) {
			tail_.store(tail + consumed, std::memory_order_release);
		}
		return consumed;
	}

	/**
	 * @brief Construct and release-publish one forwarded value when space exists.
	 *
	 * @tparam U Forwarded value type.
	 * @param value Value consumed only after capacity is proved.
	 * @return true when constructed and published; false when full.
	 */
	template <typename U>
	[[nodiscard]] bool try_push_impl_(U &&value) noexcept(std::is_nothrow_constructible_v<T, U &&>)
	{
		const std::size_t head = head_.load(std::memory_order_relaxed);
		if (!producer_has_capacity_(head)) {
			return false;
		}
		new (&storage_[head & mask_()]) T(std::forward<U>(value));
		head_.store(head + 1u, std::memory_order_release);
		return true;
	}

	/**
	 * @brief Resolve one live element at an already bounded physical slot.
	 *
	 * @param ordinal Physical storage index naming one live slot.
	 * @return Laundered pointer to that exact slot.
	 */
	[[nodiscard]] T *slot_(std::size_t ordinal) noexcept
	{
		return std::launder(reinterpret_cast<T *>(&storage_[ordinal]));
	}

	/** @brief Destroy every element retained when a quiescent core retires. */
	void clear_remaining_() noexcept
	{
		std::size_t tail = tail_.load(std::memory_order_relaxed);
		const std::size_t head = head_.load(std::memory_order_relaxed);
		const std::size_t mask = mask_();
		while (tail != head) {
			slot_(tail & mask)->~T();
			++tail;
		}
		tail_.store(head, std::memory_order_relaxed);
		cached_head_ = head;
		cached_tail_ = head;
	}

	storage_type *storage_;					       ///< Caller-owned uninitialized element storage.
	alignas(CACHE_LINE_SIZE) std::atomic<std::size_t> head_{0};    ///< Producer publication sequence.
	alignas(CACHE_LINE_SIZE) std::size_t cached_tail_{0};	       ///< Producer-private acquired consumer sequence.
	alignas(CACHE_LINE_SIZE) std::atomic<std::size_t> tail_{0};    ///< Consumer publication sequence.
	alignas(CACHE_LINE_SIZE) mutable std::size_t cached_head_{0};  ///< Consumer-private acquired producer sequence.
};

/**
 * @brief Validate and reinterpret caller-owned borrowed SPSC storage.
 *
 * The returned pointer borrows @p storage. The caller retains the complete
 * extent until the composed ring is quiescent and destroyed. Validation and
 * reinterpretation are constant-time and allocate nothing.
 *
 * @tparam T Element type stored in the borrowed extent.
 * @param storage Start of caller-owned uninitialized storage.
 * @param storage_bytes Accessible byte extent beginning at @p storage.
 * @param capacity Exact power-of-two usable element count.
 * @return Typed uninitialized storage borrowed from the caller.
 * @throws std::invalid_argument for invalid capacity, null/misaligned storage,
 *         or an undersized extent.
 */
template <typename T>
[[nodiscard]] spsc_storage<T> *validated_spsc_storage(void *storage, std::size_t storage_bytes, std::size_t capacity)
{
	const std::size_t admitted_capacity = validate_spsc_capacity(capacity);
	if (storage == nullptr || reinterpret_cast<std::uintptr_t>(storage) % alignof(spsc_storage<T>) != 0) {
		throw std::invalid_argument("spsc_ring: backing storage is null or misaligned");
	}
	if (admitted_capacity > std::numeric_limits<std::size_t>::max() / sizeof(spsc_storage<T>) ||
	    storage_bytes < admitted_capacity * sizeof(spsc_storage<T>)) {
		throw std::invalid_argument("spsc_ring: backing storage is smaller than the exact capacity");
	}
	return static_cast<spsc_storage<T> *>(storage);
}

}  // namespace detail
/** @endcond */

/**
 * @brief Return the exact uninitialized byte count for runtime-capacity SPSC storage.
 *
 * Counts elements only; the composed owner accounts for its core object size.
 *
 * @tparam T Element type stored in the resulting extent.
 * @param capacity Exact power-of-two usable capacity.
 * @return Byte count for @p capacity elements.
 * @throws std::invalid_argument for an invalid capacity and std::length_error
 *         when the multiplication is not representable.
 */
template <typename T>
[[nodiscard]] std::size_t spsc_ring_storage_bytes(std::size_t capacity)
{
	const std::size_t admitted = detail::validate_spsc_capacity(capacity);
	using storage_type = typename detail::spsc_ring_core<T, 0>::storage_type;
	if (admitted > std::numeric_limits<std::size_t>::max() / sizeof(storage_type)) {
		throw std::length_error("spsc_ring: storage byte count is not representable");
	}
	return admitted * sizeof(storage_type);
}

/**
 * @brief Lock-free SPSC ring with compile-time owned storage and capacity.
 *
 * @tparam T Element type.
 * @tparam Capacity Exact power-of-two usable capacity, at least two.
 *
 * @par Thread Safety
 * Exactly one producer may call push operations and exactly one consumer may
 * call pop operations. Observational accessors may race with those owners.
 * Destruction requires both owners to be quiescent.
 *
 * @par Performance
 * Storage is embedded in the ring. Single-element operations are O(1), batch
 * operations are O(k), and no operation allocates.
 */
template <typename T, std::size_t Capacity = DEFAULT_RING_CAPACITY>
class spsc_ring_static {
	static_assert(Capacity >= 2, "Capacity must be at least 2");
	static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
	static_assert(Capacity <= std::numeric_limits<std::size_t>::max() / 2u,
		      "Capacity must fit the modular counter half-range");

    public:
	using value_type = T;				   ///< Stored element type.
	static constexpr std::size_t capacity = Capacity;  ///< Exact usable compile-time capacity.

	/**
	 * @brief Construct one empty statically sized ring.
	 *
	 * Keep this constructor user-provided so value-initialization does not
	 * zero-fill unused backing storage.
	 */
	spsc_ring_static() noexcept
	{
	}

	spsc_ring_static(const spsc_ring_static &) = delete;
	spsc_ring_static &operator=(const spsc_ring_static &) = delete;
	spsc_ring_static(spsc_ring_static &&) = delete;
	spsc_ring_static &operator=(spsc_ring_static &&) = delete;
	~spsc_ring_static() = default;

	/**
	 * @brief Try to publish one copied value without waiting.
	 *
	 * @param value Value borrowed for this call.
	 * @return true when copied and published; false when full.
	 */
	[[nodiscard]] bool try_push(const T &value) noexcept(std::is_nothrow_copy_constructible_v<T>)
	{
		return core_.try_push(value);
	}
	/**
	 * @brief Try to publish one moved value without consuming it on full.
	 *
	 * @param value Value consumed only after capacity is proved.
	 * @return true when moved and published; false when full.
	 */
	[[nodiscard]] bool try_push(T &&value) noexcept(std::is_nothrow_move_constructible_v<T>)
	{
		return core_.try_push(std::move(value));
	}
	/**
	 * @brief Construct and publish one value when capacity is available.
	 *
	 * @tparam Args Constructor argument types.
	 * @param args Arguments forwarded only after capacity is proved.
	 * @return true when constructed and published; false when full.
	 */
	template <typename... Args>
	[[nodiscard]] bool try_emplace(Args &&...args) noexcept(std::is_nothrow_constructible_v<T, Args...>)
	{
		return core_.try_emplace(std::forward<Args>(args)...);
	}
	/**
	 * @brief Publish the largest capacity-admitted prefix of one copied batch.
	 *
	 * This overload exists only for nothrow-copy-constructible values. It
	 * performs no allocation and release-publishes the accepted prefix once.
	 *
	 * @param items Contiguous input values; nonnull when @p count is nonzero.
	 * @param count Number of available input values.
	 * @return Number of values copied and published, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t push_batch(const T *items, std::size_t count) noexcept
		requires std::is_nothrow_copy_constructible_v<T>
	{
		return core_.push_batch(items, count);
	}
	/**
	 * @brief Move-assign and consume one value when available.
	 *
	 * @param out Initialized destination replaced only when a value is present.
	 * @return true when one value is consumed; false when empty.
	 */
	[[nodiscard]] bool try_pop(T &out) noexcept
		requires std::is_nothrow_move_assignable_v<T>
	{
		return core_.try_pop(out);
	}
	/**
	 * @brief Move-construct and consume one optional value.
	 *
	 * @return One consumed value, or an empty optional when the ring is empty.
	 */
	[[nodiscard]] std::optional<T> try_pop() noexcept
		requires std::is_nothrow_move_constructible_v<T>
	{
		return core_.try_pop();
	}
	/**
	 * @brief Consume the largest available prefix into caller-owned storage.
	 *
	 * This overload exists only for nothrow-move-assignable values. It performs
	 * no allocation, destroys the consumed prefix, and release-publishes once.
	 *
	 * @param out Contiguous initialized output values; nonnull when @p count is
	 *            nonzero.
	 * @param count Maximum number of values to consume.
	 * @return Number of values move-assigned and consumed, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t pop_batch(T *out, std::size_t count) noexcept
		requires std::is_nothrow_move_assignable_v<T>
	{
		return core_.pop_batch(out, count);
	}
	/**
	 * @brief Consume an admitted FIFO prefix and publish its completed tail once.
	 * @tparam accept_type Nonthrowing callback over a read-only element borrow.
	 * @param count Maximum number considered; zero invokes nothing.
	 * @param accept Returns true after accepting the value, or false to retain
	 *        it and the suffix. It cannot retain the borrow, reenter this ring,
	 *        or invoke foreign callbacks.
	 * @return Exact number consumed before the first refusal or limit.
	 */
	template <typename accept_type>
	[[nodiscard]] std::size_t consume_prefix(std::size_t count, accept_type &&accept) noexcept
		requires(std::is_nothrow_invocable_r_v<bool, accept_type &, const T &> &&
			 std::is_nothrow_destructible_v<T>)
	{
		return core_.consume_prefix(count, std::forward<accept_type>(accept));
	}
	/**
	 * @brief Borrow the current front value without consuming it.
	 *
	 * Only the sole consumer may call this method. The pointer follows the
	 * underlying ring's contract and expires at the next consumer-side mutation.
	 *
	 * @return Pointer to the current front value, or null when the ring is empty.
	 */
	[[nodiscard]] const T *peek() const noexcept
	{
		return core_.peek();
	}
	/**
	 * @brief Return whether the observed ring is empty.
	 *
	 * @return One acquire-ordered empty-state observation.
	 */
	[[nodiscard]] bool empty() const noexcept
	{
		return core_.empty();
	}
	/**
	 * @brief Return whether the observed ring is full.
	 *
	 * @return One observational full-state result.
	 */
	[[nodiscard]] bool full() const noexcept
	{
		return core_.full();
	}
	/**
	 * @brief Return one observational count of currently unused slots.
	 *
	 * @return Approximate free-slot count bounded by @c Capacity.
	 */
	[[nodiscard]] std::size_t available() const noexcept
	{
		return core_.available();
	}
	/**
	 * @brief Return one observational element count.
	 *
	 * @return Approximate published element count.
	 */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		return core_.size_approx();
	}
	/**
	 * @brief Return the exact usable compile-time capacity.
	 *
	 * @return @c Capacity.
	 */
	[[nodiscard]] static constexpr std::size_t max_size() noexcept
	{
		return Capacity;
	}

    private:
	using storage_type = detail::spsc_storage<T>;  ///< Uninitialized embedded-slot representation.
	alignas(CACHE_LINE_SIZE) std::array<storage_type, Capacity> storage_;  ///< Owned uninitialized slots.
	detail::spsc_ring_core<T, Capacity> core_{storage_};  ///< Sole sequence and element-lifetime authority.
};

/**
 * @brief Lock-free SPSC ring with runtime-sized owned storage.
 *
 * @tparam T Element type.
 *
 * @par Thread Safety
 * Exactly one producer may call push and exactly one consumer may call pop.
 * Destruction requires both owners to be quiescent.
 *
 * @par Performance
 * Construction allocates the complete element extent once. Scalar operations
 * are O(1); a batch or destruction of n values is O(n). Queue operations do not
 * allocate.
 */
template <typename T>
class spsc_ring {
    public:
	using value_type = T;  ///< Stored element type.

	/**
	 * @brief Allocate and bind one exact runtime-capacity ring.
	 *
	 * Construction allocates the complete uninitialized element extent once;
	 * no queue operation allocates afterward.
	 *
	 * @param capacity Exact power-of-two usable capacity, at least two.
	 * @throws std::invalid_argument for invalid capacity and std::bad_alloc when
	 *         the complete storage extent cannot be allocated.
	 */
	explicit spsc_ring(std::size_t capacity)
		: capacity_(detail::validate_spsc_capacity(capacity))
		, storage_(new storage_type[capacity_])
		, core_(storage_.get(), capacity_)
	{
	}

	spsc_ring(const spsc_ring &) = delete;
	spsc_ring &operator=(const spsc_ring &) = delete;
	spsc_ring(spsc_ring &&) = delete;
	spsc_ring &operator=(spsc_ring &&) = delete;
	~spsc_ring() = default;

	/**
	 * @brief Try to publish one copied value without waiting.
	 *
	 * @param value Value borrowed for this call.
	 * @return true when copied and published; false when full.
	 */
	[[nodiscard]] bool push(const T &value) noexcept(std::is_nothrow_copy_constructible_v<T>)
	{
		return core_.try_push(value);
	}
	/**
	 * @brief Try to publish one moved value without consuming it on full.
	 *
	 * @param value Value consumed only after capacity is proved.
	 * @return true when moved and published; false when full.
	 */
	[[nodiscard]] bool push(T &&value) noexcept(std::is_nothrow_move_constructible_v<T>)
	{
		return core_.try_push(std::move(value));
	}
	/**
	 * @brief Publish the largest capacity-admitted prefix of one copied batch.
	 *
	 * @param items Contiguous input values; nonnull when @p count is nonzero.
	 * @param count Number of available input values.
	 * @return Number of values copied and published, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t push_batch(const T *items, std::size_t count) noexcept
		requires std::is_nothrow_copy_constructible_v<T>
	{
		return core_.push_batch(items, count);
	}
	/**
	 * @brief Move-construct and consume one optional value.
	 *
	 * @return One consumed value, or an empty optional when the ring is empty.
	 */
	[[nodiscard]] std::optional<T> pop() noexcept
		requires std::is_nothrow_move_constructible_v<T>
	{
		return core_.try_pop();
	}
	/**
	 * @brief Consume the largest available prefix into caller-owned storage.
	 *
	 * @param out Contiguous initialized output values; nonnull when @p count is
	 *            nonzero.
	 * @param count Maximum number of values to consume.
	 * @return Number of values move-assigned and consumed, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t pop_batch(T *out, std::size_t count) noexcept
		requires std::is_nothrow_move_assignable_v<T>
	{
		return core_.pop_batch(out, count);
	}
	/**
	 * @brief Consume an admitted FIFO prefix and publish its completed tail once.
	 * @tparam accept_type Nonthrowing callback over a read-only element borrow.
	 * @param count Maximum number considered; zero invokes nothing.
	 * @param accept Returns true after accepting the value, or false to retain
	 *        it and the suffix. It cannot retain the borrow, reenter this ring,
	 *        or invoke foreign callbacks.
	 * @return Exact number consumed before the first refusal or limit.
	 */
	template <typename accept_type>
	[[nodiscard]] std::size_t consume_prefix(std::size_t count, accept_type &&accept) noexcept
		requires(std::is_nothrow_invocable_r_v<bool, accept_type &, const T &> &&
			 std::is_nothrow_destructible_v<T>)
	{
		return core_.consume_prefix(count, std::forward<accept_type>(accept));
	}
	/**
	 * @brief Return whether the observed ring is empty.
	 *
	 * @return One acquire-ordered empty-state observation.
	 */
	[[nodiscard]] bool empty() const noexcept
	{
		return core_.empty();
	}
	/**
	 * @brief Return whether the observed ring is full.
	 *
	 * @return One observational full-state result.
	 */
	[[nodiscard]] bool full() const noexcept
	{
		return core_.full();
	}
	/**
	 * @brief Return one observational count of currently unused slots.
	 *
	 * @return Approximate free-slot count bounded by exact capacity.
	 */
	[[nodiscard]] std::size_t available() const noexcept
	{
		return core_.available();
	}
	/**
	 * @brief Return one observational element count.
	 *
	 * @return Approximate published element count.
	 */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		return core_.size_approx();
	}
	/**
	 * @brief Return the exact usable runtime capacity.
	 *
	 * @return Construction-time capacity.
	 */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return capacity_;
	}

    private:
	using storage_type = detail::spsc_storage<T>;  ///< Uninitialized owned-slot representation.
	std::size_t capacity_;			       ///< Exact usable runtime capacity.
	std::unique_ptr<storage_type[]> storage_;      ///< Owned uninitialized slots.
	detail::spsc_ring_core<T, 0> core_;	       ///< Sole sequence and element-lifetime authority.
};

/**
 * @brief Lock-free runtime-capacity SPSC ring over borrowed backing storage.
 *
 * This owner is used when the subsystem, rather than the queue, owns NUMA or
 * hugepage allocation. The storage must outlive the ring and may be reclaimed
 * only after the ring is destroyed and its remaining elements are retired.
 * Exactly one producer and one consumer may operate concurrently; destruction
 * requires both owners to be quiescent.
 *
 * @tparam T Element type stored in the borrowed extent.
 *
 * @par Performance
 * Construction validates and binds in O(1). Scalar operations are O(1); a batch
 * or destruction of n values is O(n). Queue operations do not allocate.
 */
template <typename T>
class spsc_ring_view {
    public:
	using value_type = T;  ///< Stored element type.

	/**
	 * @brief Bind exact caller-owned storage without allocating.
	 *
	 * @param storage Start of aligned caller-owned uninitialized storage.
	 * @param storage_bytes Accessible byte extent beginning at @p storage.
	 * @param capacity Exact power-of-two usable element count.
	 * @throws std::invalid_argument for invalid capacity, null/misaligned
	 *         storage, or an undersized extent.
	 */
	spsc_ring_view(void *storage, std::size_t storage_bytes, std::size_t capacity)
		: core_(detail::validated_spsc_storage<T>(storage, storage_bytes, capacity), capacity)
	{
	}

	spsc_ring_view(const spsc_ring_view &) = delete;
	spsc_ring_view &operator=(const spsc_ring_view &) = delete;
	spsc_ring_view(spsc_ring_view &&) = delete;
	spsc_ring_view &operator=(spsc_ring_view &&) = delete;
	~spsc_ring_view() = default;

	/**
	 * @brief Try to publish one copied value without waiting.
	 *
	 * @param value Value borrowed for this call.
	 * @return true when copied and published; false when full.
	 */
	[[nodiscard]] bool try_push(const T &value) noexcept(std::is_nothrow_copy_constructible_v<T>)
	{
		return core_.try_push(value);
	}
	/**
	 * @brief Try to publish one moved value without consuming it on full.
	 *
	 * @param value Value consumed only after capacity is proved.
	 * @return true when moved and published; false when full.
	 */
	[[nodiscard]] bool try_push(T &&value) noexcept(std::is_nothrow_move_constructible_v<T>)
	{
		return core_.try_push(std::move(value));
	}
	/**
	 * @brief Publish the largest capacity-admitted prefix of one copied batch.
	 *
	 * @param items Contiguous input values; nonnull when @p count is nonzero.
	 * @param count Number of available input values.
	 * @return Number of values copied and published, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t push_batch(const T *items, std::size_t count) noexcept
		requires std::is_nothrow_copy_constructible_v<T>
	{
		return core_.push_batch(items, count);
	}
	/**
	 * @brief Move-assign and consume one value when available.
	 *
	 * @param out Initialized destination replaced only when a value is present.
	 * @return true when one value is consumed; false when empty.
	 */
	[[nodiscard]] bool try_pop(T &out) noexcept
		requires std::is_nothrow_move_assignable_v<T>
	{
		return core_.try_pop(out);
	}
	/**
	 * @brief Move-construct and consume one optional value.
	 *
	 * @return One consumed value, or an empty optional when the ring is empty.
	 */
	[[nodiscard]] std::optional<T> try_pop() noexcept
		requires std::is_nothrow_move_constructible_v<T>
	{
		return core_.try_pop();
	}
	/**
	 * @brief Consume the largest available prefix into caller-owned storage.
	 *
	 * @param out Contiguous initialized output values; nonnull when @p count is
	 *            nonzero.
	 * @param count Maximum number of values to consume.
	 * @return Number of values move-assigned and consumed, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t pop_batch(T *out, std::size_t count) noexcept
		requires std::is_nothrow_move_assignable_v<T>
	{
		return core_.pop_batch(out, count);
	}
	/**
	 * @brief Consume an admitted FIFO prefix and publish its completed tail once.
	 * @tparam accept_type Nonthrowing callback over a read-only element borrow.
	 * @param count Maximum number considered; zero invokes nothing.
	 * @param accept Returns true after accepting the value, or false to retain
	 *        it and the suffix. It cannot retain the borrow, reenter this ring,
	 *        or invoke foreign callbacks.
	 * @return Exact number consumed before the first refusal or limit.
	 */
	template <typename accept_type>
	[[nodiscard]] std::size_t consume_prefix(std::size_t count, accept_type &&accept) noexcept
		requires(std::is_nothrow_invocable_r_v<bool, accept_type &, const T &> &&
			 std::is_nothrow_destructible_v<T>)
	{
		return core_.consume_prefix(count, std::forward<accept_type>(accept));
	}
	/**
	 * @brief Borrow the current front value without consuming it.
	 *
	 * Only the sole consumer may call this method. The pointer follows the
	 * underlying ring's contract and expires at the next consumer-side mutation.
	 *
	 * @return Pointer to the current front value, or null when the ring is empty.
	 */
	[[nodiscard]] const T *peek() const noexcept
	{
		return core_.peek();
	}
	/**
	 * @brief Return whether the observed ring is empty.
	 *
	 * @return One acquire-ordered empty-state observation.
	 */
	[[nodiscard]] bool empty() const noexcept
	{
		return core_.empty();
	}
	/**
	 * @brief Return whether the observed ring is full.
	 *
	 * @return One observational full-state result.
	 */
	[[nodiscard]] bool full() const noexcept
	{
		return core_.full();
	}
	/**
	 * @brief Return one observational count of currently unused slots.
	 *
	 * @return Approximate free-slot count bounded by exact capacity.
	 */
	[[nodiscard]] std::size_t available() const noexcept
	{
		return core_.available();
	}
	/**
	 * @brief Return one observational element count.
	 *
	 * @return Approximate published element count.
	 */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		return core_.size_approx();
	}
	/**
	 * @brief Return the exact usable runtime capacity.
	 *
	 * @return Construction-time capacity.
	 */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return core_.capacity();
	}

    private:
	detail::spsc_ring_core<T, 0> core_;  ///< Sole sequence and element-lifetime authority.
};

// =============================================================================
// MPMC Queue (Multiple Producer Multiple Consumer)
// =============================================================================

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/**
 * @brief Element contract required after an irreversible MPMC reservation.
 *
 * A producer or consumer cursor cannot be rolled back once claimed. Cell
 * assignment must therefore complete without an escaping exception.
 */
template <typename T>
concept mpmc_queue_value = std::is_default_constructible_v<T> && std::is_nothrow_copy_assignable_v<T> &&
			   std::is_nothrow_move_assignable_v<T>;

/**
 * @brief Sole runtime-capacity MPMC sequence and publication mechanism.
 *
 * The core owns only producer/consumer cursors and borrows an exact caller-
 * supplied cell extent. Static, dynamic, and caller-storage public forms all
 * delegate to this implementation so queue arithmetic cannot drift.
 *
 * @tparam T Default-constructible fixed queue value.
 */
template <mpmc_queue_value T>
class mpmc_queue_core {
	static_assert(std::atomic<std::size_t>::is_always_lock_free,
		      "MPMC sequence publication requires lock-free size_t atomics");

    public:
	/** @brief One independently sequenced caller-owned queue cell. */
	struct alignas(CACHE_LINE_SIZE) storage_type {
		std::atomic<std::size_t> sequence{0};  ///< Cell ownership/publication sequence.
		T data{};			       ///< Value owned according to sequence.
	};
	static_assert(sizeof(storage_type) % CACHE_LINE_SIZE == 0, "MPMC cells must not share cache-line boundaries");

	/**
	 * @brief Bind one exact empty queue to prevalidated caller storage.
	 * @param storage Exact array containing @p capacity cells.
	 * @param capacity Power-of-two physical capacity of at least two.
	 */
	mpmc_queue_core(storage_type *storage, std::size_t capacity) noexcept
		: storage_(storage)
		, capacity_(capacity)
		, mask_(capacity - 1u)
	{
		if (storage_ == nullptr || !valid_capacity(capacity_)) {
			std::terminate();
		}
		for (std::size_t index = 0u; index < capacity_; ++index) {
			storage_[index].sequence.store(index, std::memory_order_relaxed);
		}
	}

	/** @brief Reject copying because cursor and cell ownership is unique. */
	mpmc_queue_core(const mpmc_queue_core &) = delete;
	/** @brief Reject copy assignment because published cells cannot be duplicated. */
	mpmc_queue_core &operator=(const mpmc_queue_core &) = delete;
	/** @brief Reject moving so concurrent callers retain one stable address. */
	mpmc_queue_core(mpmc_queue_core &&) = delete;
	/** @brief Reject move assignment so queue identity cannot be replaced. */
	mpmc_queue_core &operator=(mpmc_queue_core &&) = delete;

	/**
	 * @param capacity Candidate physical cell population.
	 * @return true only for one representable physical queue capacity.
	 */
	[[nodiscard]] static constexpr bool valid_capacity(std::size_t capacity) noexcept
	{
		return capacity >= 2u && (capacity & (capacity - 1u)) == 0u && capacity <= COUNTER_HALF_RANGE;
	}

	/**
	 * @brief Publish one copied value if a physical cell is available.
	 * @param value Value borrowed until its copy is published.
	 * @return true after publication; false when no cell can be reserved.
	 */
	[[nodiscard]] bool try_enqueue(const T &value) noexcept(std::is_nothrow_copy_assignable_v<T>)
	{
		storage_type *target;
		std::size_t position = enqueue_pos_.load(std::memory_order_relaxed);
		for (;;) {
			target = &storage_[position & mask_];
			const std::size_t sequence = target->sequence.load(std::memory_order_acquire);
			const std::size_t difference = sequence - position;
			if (difference == 0u) {
				if (enqueue_pos_.compare_exchange_weak(position, position + 1u,
								       std::memory_order_relaxed)) {
					break;
				}
			} else if (difference > COUNTER_HALF_RANGE) {
				return false;
			} else {
				position = enqueue_pos_.load(std::memory_order_relaxed);
			}
		}
		target->data = value;
		target->sequence.store(position + 1u, std::memory_order_release);
		return true;
	}

	/**
	 * @brief Consume one value if a published physical cell is available.
	 * @param[out] out Initialized destination, unchanged when no value is available.
	 * @return true after transfer; false when no published cell can be reserved.
	 */
	[[nodiscard]] bool try_dequeue(T &out) noexcept(std::is_nothrow_move_assignable_v<T>)
	{
		storage_type *target;
		std::size_t position = dequeue_pos_.load(std::memory_order_relaxed);
		for (;;) {
			target = &storage_[position & mask_];
			const std::size_t sequence = target->sequence.load(std::memory_order_acquire);
			const std::size_t difference = sequence - (position + 1u);
			if (difference == 0u) {
				if (dequeue_pos_.compare_exchange_weak(position, position + 1u,
								       std::memory_order_relaxed)) {
					break;
				}
			} else if (difference > COUNTER_HALF_RANGE) {
				return false;
			} else {
				position = dequeue_pos_.load(std::memory_order_relaxed);
			}
		}
		out = std::move(target->data);
		target->sequence.store(position + capacity_, std::memory_order_release);
		return true;
	}

	/** @return Concurrent observational empty state. */
	[[nodiscard]] bool empty() const noexcept
	{
		return enqueue_pos_.load(std::memory_order_acquire) == dequeue_pos_.load(std::memory_order_acquire);
	}

	/** @return Conservative concurrent observation of occupied cells. */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		const std::size_t dequeued = dequeue_pos_.load(std::memory_order_acquire);
		const std::size_t enqueued = enqueue_pos_.load(std::memory_order_acquire);
		const std::size_t occupied = enqueued - dequeued;
		return occupied <= capacity_ ? occupied : 0u;
	}

	/** @return Exact immutable physical capacity. */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return capacity_;
	}

    private:
	static constexpr std::size_t COUNTER_HALF_RANGE =
		std::numeric_limits<std::size_t>::max() / 2u;		    ///< Largest unambiguous modular distance.
	storage_type *storage_{nullptr};				    ///< Exact borrowed cell extent.
	std::size_t capacity_{0};					    ///< Immutable power-of-two cell count.
	std::size_t mask_{0};						    ///< Capacity-minus-one index mask.
	alignas(CACHE_LINE_SIZE) std::atomic<std::size_t> enqueue_pos_{0};  ///< Producer reservation cursor.
	alignas(CACHE_LINE_SIZE) std::atomic<std::size_t> dequeue_pos_{0};  ///< Consumer reservation cursor.
};

}  // namespace detail
/** @endcond */

/**
 * @brief Bounded MPMC queue over exact caller-owned aligned cells.
 *
 * @tparam T Fixed queue value type.
 *
 * @par Thread Safety
 * Any number of producers and consumers may operate concurrently. Construction
 * and destruction require external quiescence and caller storage must outlive
 * the view.
 * Cursor reservation precedes cell publication/release. A try operation may
 * refuse the next cell while an earlier caller is paused, even when another
 * cell is available; failure transfers no ownership. Neither global fullness
 * nor emptiness follows from that result. This is not a lock-free FIFO
 * progress guarantee.
 *
 * @par Performance
 * Queue bookkeeping allocates no memory, takes no locks and reads no clock.
 * Element operations retain T's own cost and side-effect contract. CAS
 * contention has no per-call step bound. Every cell occupies an independent
 * cache-line extent.
 */
template <typename T>
	requires detail::mpmc_queue_value<T>
class mpmc_queue_view {
    public:
	using storage_type = typename detail::mpmc_queue_core<T>::storage_type;	 ///< Caller-owned cell type.

	/**
	 * @brief Bind one exact empty queue to caller-owned cells.
	 * @param storage Array of exactly @p capacity pristine cells.
	 * @param capacity Representable power-of-two physical cell count.
	 */
	mpmc_queue_view(storage_type *storage, std::size_t capacity) noexcept
		: core_(storage, capacity)
	{
	}

	mpmc_queue_view(const mpmc_queue_view &) = delete;
	mpmc_queue_view &operator=(const mpmc_queue_view &) = delete;
	mpmc_queue_view(mpmc_queue_view &&) = delete;
	mpmc_queue_view &operator=(mpmc_queue_view &&) = delete;

	/**
	 * @param capacity Candidate physical cell count.
	 * @return true only for one representable power-of-two physical capacity.
	 */
	[[nodiscard]] static constexpr bool valid_capacity(std::size_t capacity) noexcept
	{
		return detail::mpmc_queue_core<T>::valid_capacity(capacity);
	}

	/**
	 * @brief Try to publish one copied value.
	 * @param value Value copied into one claimed cell.
	 * @return true after publication; false when the next cell cannot be reserved.
	 */
	[[nodiscard]] bool try_enqueue(const T &value) noexcept(std::is_nothrow_copy_assignable_v<T>)
	{
		return core_.try_enqueue(value);
	}
	/**
	 * @brief Try to consume one published value.
	 * @param[out] out Destination assigned after one cell is claimed.
	 * @return true after consumption; false when the next cell is not consumable.
	 */
	[[nodiscard]] bool try_dequeue(T &out) noexcept(std::is_nothrow_move_assignable_v<T>)
	{
		return core_.try_dequeue(out);
	}
	/** @return Concurrent observational empty state; never an ownership reservation. */
	[[nodiscard]] bool empty() const noexcept
	{
		return core_.empty();
	}
	/** @return Conservative concurrent observation of occupied cells. */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		return core_.size_approx();
	}
	/** @return Exact immutable physical cell capacity. */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return core_.capacity();
	}

    private:
	detail::mpmc_queue_core<T> core_;  ///< Sole shared MPMC publication mechanism.
};

/**
 * @brief Bounded MPMC queue with embedded storage.
 *
 * Uses per-slot sequence numbers for coordination.
 * Suitable for stats collection and control plane messaging.
 *
 * @tparam T Default-constructible element type.
 * @tparam Capacity Exact power-of-two queue capacity, at least two.
 *
 * @par Thread Safety
 * Any number of producers and consumers may operate concurrently. Destruction
 * requires all callers to be quiescent. Try-operation availability and progress
 * follow mpmc_queue_view; a failed try is not proof of global fullness or emptiness.
 *
 * @par Performance
 * Storage is embedded in the queue. Bookkeeping takes no lock and allocates no
 * memory; element operations and contention follow mpmc_queue_view.
 */
template <typename T, std::size_t Capacity = 1024>
	requires detail::mpmc_queue_value<T>
class mpmc_queue {
	static_assert(Capacity >= 2, "Capacity must be at least 2");
	static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
	static_assert(mpmc_queue_view<T>::valid_capacity(Capacity),
		      "Capacity exceeds the unambiguous modular counter range");

    public:
	/** @brief Construct one empty queue over its embedded caller-storage cells. */
	mpmc_queue() noexcept
		: view_(cells_.data(), cells_.size())
	{
	}

	/**
	 * @brief Try to enqueue one copied element.
	 *
	 * @param value Value copied into a claimed cell.
	 * @return true after publication; false when the next cell cannot be reserved.
	 */
	[[nodiscard]] bool try_enqueue(const T &value) noexcept(std::is_nothrow_copy_assignable_v<T>)
	{
		return view_.try_enqueue(value);
	}

	/**
	 * @brief Try to dequeue one element.
	 *
	 * @param[out] out Destination assigned after one cell is claimed.
	 * @return true after consumption; false when the next cell is not consumable.
	 */
	[[nodiscard]] bool try_dequeue(T &out) noexcept(std::is_nothrow_move_assignable_v<T>)
	{
		return view_.try_dequeue(out);
	}

	/**
	 * @brief Return whether one concurrent observation sees no queued value.
	 *
	 * @return Observational empty-state result; it is not a reservation.
	 */
	[[nodiscard]] bool empty() const noexcept
	{
		return view_.empty();
	}

	/**
	 * @brief Return one concurrent observation of occupied cells.
	 *
	 * @return Approximate published element count; it is not a reservation.
	 */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		return view_.size_approx();
	}

    private:
	/** Embedded cell representation shared with the caller-storage form. */
	using storage_type = typename mpmc_queue_view<T>::storage_type;
	std::array<storage_type, Capacity> cells_{};  ///< Embedded exact caller-storage cells.
	mpmc_queue_view<T> view_;		      ///< Sole shared MPMC publication mechanism.
};

// =============================================================================
// MPMC Queue - Dynamic Capacity
// =============================================================================

/**
 * @brief Bounded MPMC queue with construction-time capacity.
 *
 * This is the runtime-capacity form of mpmc_queue. It uses the same per-cell
 * sequence-number algorithm and allocates all cells during construction; no
 * enqueue or dequeue allocates. The physical queue capacity must be a power of
 * two. A caller may seed fewer elements when its logical resource population
 * is not a power of two.
 *
 * @tparam T Default-constructible value type with non-throwing copy and move
 *         assignment. Once a producer or consumer claims a cell, assignment
 *         must not escape before the sequence publication that releases it.
 *
 * @par Thread Safety
 * Any number of producers and consumers may call try_enqueue and try_dequeue
 * concurrently. Destruction and capacity inspection require external lifetime
 * ownership; size_approx is observational and not a reservation.
 * Try-operation availability and progress follow mpmc_queue_view; a failed try
 * is not proof of global fullness or emptiness.
 * Monotonic positions use unsigned modular arithmetic. Capacity is restricted
 * to the lower half of the counter range, so a modular difference above that
 * half-range unambiguously denotes a sequence behind the requested position.
 *
 * @par Performance
 * Cell storage is allocated once by the cold constructor. Each cell starts on
 * its own cache-line boundary so concurrent reservations of adjacent positions
 * do not false-share publication sequences. Bookkeeping takes no lock and
 * allocates no memory; element operations and contention follow mpmc_queue_view.
 */
template <typename T>
	requires detail::mpmc_queue_value<T>
class mpmc_queue_dynamic {
	static_assert(std::is_default_constructible_v<T>, "T must be default-constructible");
	static_assert(std::is_nothrow_copy_assignable_v<T>, "T must be nothrow copy-assignable");
	static_assert(std::is_nothrow_move_assignable_v<T>, "T must be nothrow move-assignable");

    public:
	/**
	 * @brief Construct an empty queue with exact physical capacity.
	 *
	 * @param capacity_pow2 Physical capacity, which must be a power of two and
	 *        at least two.
	 * @throws std::invalid_argument when the capacity contract is violated.
	 */
	explicit mpmc_queue_dynamic(std::size_t capacity_pow2)
		: capacity_(validate_capacity_(capacity_pow2))
		, cells_(new storage_type[capacity_])
		, view_(cells_.get(), capacity_)
	{
	}

	/** @brief Disable copying because queue cells and reservation cursors have one identity. */
	mpmc_queue_dynamic(const mpmc_queue_dynamic &) = delete;
	/** @brief Disable copy assignment because published cells cannot be duplicated. */
	mpmc_queue_dynamic &operator=(const mpmc_queue_dynamic &) = delete;
	/** @brief Disable moving so concurrent callers never observe relocated queue state. */
	mpmc_queue_dynamic(mpmc_queue_dynamic &&) = delete;
	/** @brief Disable move assignment so queue identity remains stable for its lifetime. */
	mpmc_queue_dynamic &operator=(mpmc_queue_dynamic &&) = delete;

	/**
	 * @brief Try to enqueue one copied value.
	 *
	 * @param value Value to publish.
	 * @return true after publication; false when the next cell cannot be reserved.
	 */
	[[nodiscard]] bool try_enqueue(const T &value) noexcept
	{
		return view_.try_enqueue(value);
	}

	/**
	 * @brief Try to dequeue one value.
	 *
	 * @param[out] out Destination assigned only after one cell is claimed.
	 * @return true after consumption; false when the next cell is not consumable.
	 */
	[[nodiscard]] bool try_dequeue(T &out) noexcept
	{
		return view_.try_dequeue(out);
	}

	/**
	 * @brief Return a concurrent snapshot of the occupied cell count.
	 *
	 * The consumer cursor is sampled first so ordinary coherent observations
	 * produce a bounded modular difference. A weakly ordered observer can still
	 * see the two independent atomics from different logical instants. Such an
	 * inverted snapshot has a difference above capacity and is reported as zero,
	 * conservatively understating availability instead of manufacturing credits.
	 * At quiescence the exact difference is returned.
	 *
	 * @return Bounded observational occupancy, or zero for an inverted sample.
	 */
	[[nodiscard]] std::size_t size_approx() const noexcept
	{
		return view_.size_approx();
	}

	/**
	 * @brief Return the immutable physical queue capacity.
	 *
	 * @return Construction-time power-of-two cell population.
	 */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return view_.capacity();
	}

    private:
	/**
	 * @brief Validate the physical ring mask contract before allocating cells.
	 *
	 * @param capacity_pow2 Requested physical capacity.
	 * @return The validated capacity unchanged.
	 * @throws std::invalid_argument when capacity is below two or not a power of two.
	 */
	[[nodiscard]] static std::size_t validate_capacity_(std::size_t capacity_pow2)
	{
		if (capacity_pow2 < 2u) {
			throw std::invalid_argument("mpmc_queue_dynamic: capacity must be at least 2");
		}
		if ((capacity_pow2 & (capacity_pow2 - 1u)) != 0u) {
			throw std::invalid_argument("mpmc_queue_dynamic: capacity must be a power of 2");
		}
		if (!mpmc_queue_view<T>::valid_capacity(capacity_pow2)) {
			throw std::invalid_argument("mpmc_queue_dynamic: capacity exceeds modular counter half-range");
		}
		return capacity_pow2;
	}

	/** Allocated cell representation shared with the caller-storage form. */
	using storage_type = typename mpmc_queue_view<T>::storage_type;
	const std::size_t capacity_;		 ///< Immutable power-of-two physical capacity.
	std::unique_ptr<storage_type[]> cells_;	 ///< Complete construction-time cell storage.
	mpmc_queue_view<T> view_;		 ///< Sole shared MPMC publication mechanism.
};

// =============================================================================
// Work Queue (Single-Threaded, Caller Storage)
// =============================================================================

/**
 * @brief Runtime-capacity single-owner FIFO over exact caller storage.
 *
 * Capacity is fixed at construction, power-of-two, and never becomes a
 * per-turn work target.
 *
 * @par Thread Safety
 * One thread owns construction, publication, consumption, and destruction.
 * No operation is a cross-thread publication mechanism.
 *
 * @par Performance
 * Construction adopts already allocated storage. Scalar operations are O(1);
 * consuming or clearing n values is O(n). Batch consumption reads at most two
 * contiguous slot ranges and advances the owner cursor once. Every operation
 * is allocation-free and lock-free, using the shared mask/index core.
 *
 * @tparam T Move-constructible value type.
 */
template <typename T>
class work_queue_view {
	static_assert(std::is_move_constructible_v<T>);

    public:
	using value_type = T;						     ///< Exact queue element type.
	using storage_type = std::aligned_storage_t<sizeof(T), alignof(T)>;  ///< Uninitialized caller slot.

	/**
	 * @param capacity Candidate exact usable slot population.
	 * @return Whether a cold owner may allocate this extent before binding the view.
	 */
	[[nodiscard]] static constexpr bool valid_capacity(std::size_t capacity) noexcept
	{
		return detail::work_queue_indices::valid_capacity(capacity);
	}

	/**
	 * @brief Bind one exact empty queue to caller-owned storage.
	 * @param storage Exact array containing @p capacity slots.
	 * @param capacity Power-of-two usable capacity of at least two.
	 */
	work_queue_view(storage_type *storage, std::size_t capacity) noexcept
		: storage_(storage)
		, indices_(capacity)
	{
		if (storage_ == nullptr) {
			std::terminate();
		}
	}

	/** @brief Reject copying because live values have one exact queue owner. */
	work_queue_view(const work_queue_view &) = delete;
	/** @brief Reject copy assignment because live values cannot be duplicated. */
	work_queue_view &operator=(const work_queue_view &) = delete;
	/** @brief Reject moving because caller-storage addresses remain stable. */
	work_queue_view(work_queue_view &&) = delete;
	/** @brief Reject move assignment because caller-storage addresses remain stable. */
	work_queue_view &operator=(work_queue_view &&) = delete;
	/** @brief Destroy every value still retained by the quiescent owner. */
	~work_queue_view()
	{
		clear();
	}

	/**
	 * @brief Publish one copied value when one exact slot remains.
	 * @param value Value copied into the next producer slot.
	 * @return true only when one slot accepted the complete value.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool
	try_push(const T &value) noexcept(std::is_nothrow_copy_constructible_v<T>)
	{
		if (KINETUM_UNLIKELY(full())) {
			return false;
		}
		new (&storage_[indices_.producer_slot()]) T(value);
		indices_.commit_push();
		return true;
	}

	/**
	 * @brief Publish one moved value when one exact slot remains.
	 * @param value Value moved into the next producer slot.
	 * @return true only when one slot accepted the complete value.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool try_push(T &&value) noexcept(std::is_nothrow_move_constructible_v<T>)
	{
		if (KINETUM_UNLIKELY(full())) {
			return false;
		}
		new (&storage_[indices_.producer_slot()]) T(std::move(value));
		indices_.commit_push();
		return true;
	}

	/**
	 * @brief Consume one FIFO value into initialized caller storage.
	 * @param[out] out Initialized destination receiving the oldest value.
	 * @return true only when one live value was consumed.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool try_pop(T &out) noexcept
		requires std::is_nothrow_move_assignable_v<T>
	{
		if (KINETUM_UNLIKELY(empty())) {
			return false;
		}
		auto *slot = slot_(indices_.consumer_slot());
		out = std::move(*slot);
		slot->~T();
		indices_.commit_pop();
		return true;
	}

	/**
	 * @brief Consume the available bounded FIFO prefix into initialized storage.
	 *
	 * Move assignment and destruction finish before the single cursor advance.
	 * Output storage must not overlap this queue's backing slots.
	 *
	 * @param[out] out Initialized destinations; nonnull when @p max_count is nonzero.
	 * @param max_count Maximum number of values to transfer.
	 * @return Number of values consumed, no greater than @p max_count.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE std::size_t pop_batch(T *out, std::size_t max_count) noexcept
		requires(std::is_nothrow_move_assignable_v<T> && std::is_nothrow_destructible_v<T>)
	{
		if (KINETUM_UNLIKELY(out == nullptr && max_count != 0u)) {
			std::terminate();
		}
		const std::size_t count = std::min(max_count, indices_.size());
		if (count == 0u) {
			return 0u;
		}
		const std::size_t begin = indices_.consumer_slot();
		const std::size_t first = std::min(count, indices_.capacity() - begin);
		consume_range_(out, begin, first);
		consume_range_(out + first, 0u, count - first);
		indices_.commit_pop(count);
		return count;
	}

	/** @return true when no value is retained. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool empty() const noexcept
	{
		return indices_.empty();
	}
	/** @return true when every exact caller slot is retained. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool full() const noexcept
	{
		return indices_.full();
	}
	/** @return Exact current retained-value count. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE std::size_t size() const noexcept
	{
		return indices_.size();
	}
	/** @return Exact construction-time usable capacity. */
	[[nodiscard]] KINETUM_ALWAYS_INLINE std::size_t capacity() const noexcept
	{
		return indices_.capacity();
	}

	/** @brief Destroy all retained values and reset owner sequences. */
	void clear() noexcept
	{
		while (!empty()) {
			auto *slot = slot_(indices_.consumer_slot());
			slot->~T();
			indices_.commit_pop();
		}
		indices_.reset_empty();
	}

    private:
	/**
	 * @brief Access the live placement-constructed value rather than its backing slot.
	 * @param ordinal Physical ordinal whose value has been constructed and not consumed.
	 * @return Pointer to that live value.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE T *slot_(std::size_t ordinal) noexcept
	{
		return std::launder(reinterpret_cast<T *>(&storage_[ordinal]));
	}

	/**
	 * @brief Move and destroy one contiguous slot range without changing queue indices.
	 * @param[out] out Initialized nonoverlapping output range.
	 * @param begin First physical storage ordinal.
	 * @param count Number of live slots before the physical end.
	 */
	KINETUM_ALWAYS_INLINE void consume_range_(T *out, std::size_t begin, std::size_t count) noexcept
		requires(std::is_nothrow_move_assignable_v<T> && std::is_nothrow_destructible_v<T>)
	{
		for (std::size_t index = 0u; index < count; ++index) {
			auto *slot = slot_(begin + index);
			out[index] = std::move(*slot);
			std::destroy_at(slot);
		}
	}

	storage_type *storage_{nullptr};      ///< Exact borrowed slot array.
	detail::work_queue_indices indices_;  ///< Shared exact circular sequence arithmetic.
};

}  // namespace kinetum::algo
