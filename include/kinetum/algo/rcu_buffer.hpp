// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file rcu_buffer.hpp
 * @brief RCU-style double buffer for torn-read-free configuration publishing.
 * @author Fleming Patel
 *
 * This implements a Read-Copy-Update inspired double buffer pattern:
 * - Two storage slots, one active, one standby
 * - Reader pins current slot via atomic counter
 * - Writer waits for readers == 0 before writing to standby
 * - Lock-free hot path (reader pins via atomic counter)
 * - Cold path waits for readers to leave the active slot
 *
 * @section rcu_design Design Philosophy
 *
 * The key insight: WRITER waits, not READER.
 * - Reader: Lock-free read with RAII guard
 * - Writer: May wait for a grace period
 *
 * This is the opposite of seqlock where reader retries on torn read.
 * Publication is cold work per Platform Engineering Guide. Kinetum uses this
 * primitive for CP published state and guardrails policy; DP packet
 * configuration uses its own exact generation-bound slots.
 *
 * @section rcu_safety Thread Safety
 *
 * - Multiple readers: Safe (lock-free, concurrent)
 * - Single writer: Safe (serialized externally or via mutex)
 * - Reader + writer: Safe (RCU protocol guarantees no torn reads)
 *
 * Active-slot publication, reader pinning/revalidation, and the writer's
 * zero-reader check share sequentially consistent ordering. Acquire/release
 * on separate atomics alone permits the writer to miss a new pin while the
 * reader still accepts the old active index. Pin release needs only release
 * ordering: the writer's acquiring zero check then observes completed reads.
 *
 * @par Lifetime
 * Every read guard must resolve before its buffer is destroyed. Destruction
 * with a live pin emits one fixed diagnostic and terminates before reader
 * storage can be reclaimed.
 *
 * @section rcu_performance Synchronization Characteristics
 *
 * | Operation | Behavior |
 * |-----------|----------|
 * | borrow()  | Pins current slot with an RAII guard |
 * | try_borrow() | Returns empty if a swap is in progress |
 * | get() (copy) | Copies from the active slot under a guard |
 * | store() | Waits for readers before updating standby |
 *
 * @section rcu_usage Usage
 *
 * @code
 * rcu_buffer<my_config> buffer;
 *
 * // Writer (cold path)
 * buffer.store(my_config{...});
 *
 * // Reader - zero-copy with RAII guard
 * {
 *     auto guard = buffer.borrow();
 *     process(guard->field1, guard->field2);
 * } // guard releases automatically
 *
 * // Reader (hot path) - copy for local use
 * my_config copy = buffer.get();
 * @endcode
 */

#include <kinetum/algo/platform.hpp>

#include <atomic>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>

// x86-64 spin hint; AArch64 uses an inline YIELD instruction below.
#if defined(__x86_64__)
#include <emmintrin.h>	// _mm_pause
#endif

namespace kinetum::algo
{

// =============================================================================
// CPU Relaxation Primitives
// =============================================================================

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/** @brief Emit bounded evidence and terminate before orphaning an RCU pin. */
[[noreturn]] inline void terminate_live_rcu_reader() noexcept
{
	static constexpr char DIAGNOSTIC[] = "kinetum: rcu_buffer destroyed with live reader pin\n";
	(void)std::fwrite(DIAGNOSTIC, 1u, sizeof(DIAGNOSTIC) - 1u, stderr);
	(void)std::fflush(stderr);
	std::terminate();
}

/**
 * @brief CPU-specific spin hint for busy-wait loops.
 *
 * x86-64 uses PAUSE and AArch64 uses YIELD. The public platform gate rejects
 * every other architecture before this helper is declared.
 */
inline void cpu_relax() noexcept
{
#if defined(__x86_64__)
	_mm_pause();
#else
	asm volatile("yield" ::: "memory");
#endif
}

/**
 * @brief Exponential backoff for writer waiting.
 *
 * Strategy:
 * - First 64 iterations: spin with cpu_relax() (low latency)
 * - After 64 iterations: yield to OS scheduler (prevents CPU burn)
 *
 * @param iteration Current iteration count (0-based)
 */
inline void spin_backoff(uint32_t iteration) noexcept
{
	constexpr uint32_t SPIN_THRESHOLD = 64;

	if (iteration < SPIN_THRESHOLD) {
		// Spin phase: exponential backoff with cpu_relax
		const uint32_t spins = 1u << (iteration < 6 ? iteration : 6);  // Cap at 64 spins
		for (uint32_t i = 0; i < spins; ++i) {
			cpu_relax();
		}
	} else {
		// Yield phase: let OS schedule other threads
		std::this_thread::yield();
	}
}

}  // namespace detail
/** @endcond */

// =============================================================================
// RCU Buffer
// =============================================================================

/**
 * @brief RCU-style double buffer for lock-free reading with writer grace period.
 *
 * @tparam T Value type. Can be any type (trivially copyable or complex like
 *           std::string, std::vector). Complex types work because:
 *           - Writer waits for readers == 0 before modifying standby
 *           - A guard excludes writer mutation of its pinned slot
 *           - No concurrent read/write ever happens
 *
 * Thread safety:
 * - Multiple readers: Safe (lock-free)
 * - Single writer: Safe (must be externally serialized if multiple writers)
 * - Reader + writer: Safe (RCU protocol)
 */
template <typename T>
class rcu_buffer {
    public:
	// =========================================================================
	// Read Guard (RAII)
	// =========================================================================

	/**
	 * @brief RAII guard for zero-copy read access.
	 *
	 * While the guard owns its pin, the underlying slot will not be
	 * overwritten by the writer. The guard automatically decrements the reader
	 * count on destruction.
	 *
	 * Usage:
	 * @code
	 * auto guard = buffer.borrow();
	 * use(guard->field);       // Pointer access
	 * use(guard.get().field);  // Reference access
	 * @endcode
	 */
	class read_guard {
	    public:
		/**
		 * @brief Disable copy construction because one guard owns one pin.
		 */
		read_guard(const read_guard &) = delete;

		/**
		 * @brief Disable copy assignment because one guard owns one pin.
		 */
		read_guard &operator=(const read_guard &) = delete;

		/**
		 * @brief Transfer one slot pin from another guard.
		 * @param other Guard whose pin is consumed.
		 */
		read_guard(read_guard &&other) noexcept
			: buffer_(other.buffer_)
			, idx_(other.idx_)
			, valid_(other.valid_)
		{
			other.valid_ = false;  // Source no longer owns the pin
		}

		/**
		 * @brief Release any current pin and consume another guard's pin.
		 * @param other Guard whose pin is consumed.
		 * @return This guard after ownership transfer.
		 */
		read_guard &operator=(read_guard &&other) noexcept
		{
			if (this != &other) {
				release();
				buffer_ = other.buffer_;
				idx_ = other.idx_;
				valid_ = other.valid_;
				other.valid_ = false;
			}
			return *this;
		}

		/** @brief Release the owned slot pin. */
		~read_guard()
		{
			release();
		}

		/**
		 * @brief Return the pinned value by reference.
		 * @return Immutable reference valid for this guard's lifetime.
		 */
		[[nodiscard]] const T &get() const noexcept
		{
			return buffer_->slots_[idx_].value;
		}

		/**
		 * @brief Return the pinned value for pointer-style access.
		 * @return Immutable pointer valid for this guard's lifetime.
		 */
		[[nodiscard]] const T *operator->() const noexcept
		{
			return &buffer_->slots_[idx_].value;
		}

		/**
		 * @brief Return the pinned value for dereference-style access.
		 * @return Immutable reference valid for this guard's lifetime.
		 */
		[[nodiscard]] const T &operator*() const noexcept
		{
			return buffer_->slots_[idx_].value;
		}

		/**
		 * @brief Return whether this guard still owns a slot pin.
		 * @return True unless the guard was moved from.
		 */
		[[nodiscard]] bool valid() const noexcept
		{
			return valid_;
		}

		/**
		 * @brief Return whether this guard still owns a slot pin.
		 * @return True unless the guard was moved from.
		 */
		explicit operator bool() const noexcept
		{
			return valid_;
		}

	    private:
		friend class rcu_buffer;

		/**
		 * @brief Adopt one already-acquired reader pin.
		 * @param buf Stable buffer that owns the pin.
		 * @param idx Exact pinned slot index.
		 */
		read_guard(const rcu_buffer *buf, uint8_t idx) noexcept
			: buffer_(buf)
			, idx_(idx)
			, valid_(true)
		{
		}

		/** @brief Release the exact pin once; moved-from release is a no-op. */
		void release() noexcept
		{
			if (valid_) {
				buffer_->readers_[idx_].fetch_sub(1, std::memory_order_release);
				valid_ = false;
			}
		}

		const rcu_buffer *buffer_;  ///< Stable buffer owning the reader counter.
		uint8_t idx_;		    ///< Exact slot whose reader counter is pinned.
		bool valid_;		    ///< Whether this guard still owns its one pin.
	};

	// =========================================================================
	// Construction / Destruction
	// =========================================================================

	/** @brief Construct an empty buffer with both slots value-initialized. */
	rcu_buffer() = default;

	/** @brief Destroy the buffer or fail stop before orphaning a live guard. */
	~rcu_buffer()
	{
		const uint32_t first_readers = readers_[0].load(std::memory_order_acquire);
		const uint32_t second_readers = readers_[1].load(std::memory_order_acquire);
		if (first_readers != 0u || second_readers != 0u) {
			detail::terminate_live_rcu_reader();
		}
	}

	/**
	 * @brief Disable copy construction because atomics and reader pins are local.
	 */
	rcu_buffer(const rcu_buffer &) = delete;

	/**
	 * @brief Disable copy assignment because atomics and reader pins are local.
	 */
	rcu_buffer &operator=(const rcu_buffer &) = delete;

	/**
	 * @brief Disable move construction because published addresses are stable.
	 */
	rcu_buffer(rcu_buffer &&) = delete;

	/**
	 * @brief Disable move assignment because published addresses are stable.
	 */
	rcu_buffer &operator=(rcu_buffer &&) = delete;

	// =========================================================================
	// Writer Interface (Cold Path)
	// =========================================================================

	/**
	 * @brief Store a new value (cold path).
	 *
	 * RCU Protocol:
	 * 1. Identify inactive slot (the one not currently active)
	 * 2. Wait for all readers on inactive slot to finish (grace period)
	 * 3. Write new value to inactive slot
	 * 4. Atomically swap active pointer to new slot
	 *
	 * @param value The new value to store (moved)
	 */
	void store(T value)
	{
		const uint8_t current = active_.load(std::memory_order_acquire);
		const uint8_t next = 1 - current;

		// Grace period: wait for readers on inactive slot
		wait_for_readers(next);

		// Safe to write - no readers on this slot
		slots_[next].value = std::move(value);

		// Publish: atomically swap active slot
		active_.store(next, std::memory_order_seq_cst);
		has_value_.store(true, std::memory_order_release);
	}

	/**
	 * @brief Store a replacement constructed from arguments (cold path).
	 *
	 * @tparam Args Constructor argument types
	 * @param args Arguments forwarded to T's constructor
	 */
	template <typename... Args>
	void emplace(Args &&...args)
	{
		const uint8_t current = active_.load(std::memory_order_acquire);
		const uint8_t next = 1 - current;

		// Grace period: wait for readers on inactive slot
		wait_for_readers(next);

		// Construct in-place
		slots_[next].value = T(std::forward<Args>(args)...);

		// Publish
		active_.store(next, std::memory_order_seq_cst);
		has_value_.store(true, std::memory_order_release);
	}

	// =========================================================================
	// Reader Interface (Hot Path)
	// =========================================================================

	/**
	 * @brief Borrow a read guard (hot path, lock-free).
	 *
	 * Returns an RAII guard that pins the current slot. The slot will not be
	 * overwritten while any guard exists.
	 *
	 * May retry briefly if caught during the exact moment of a swap.
	 *
	 * @return RAII guard providing access to current value
	 */
	[[nodiscard]] read_guard borrow() const
	{
		for (;;) {
			const uint8_t idx = active_.load(std::memory_order_acquire);
			readers_[idx].fetch_add(1, std::memory_order_seq_cst);

			// The shared order makes a writer observe this pin or this
			// validation observe its publication before standby reuse.
			if (KINETUM_LIKELY(active_.load(std::memory_order_seq_cst) == idx)) {
				return read_guard(this, idx);
			}

			// Slot changed during our increment - release and retry
			readers_[idx].fetch_sub(1, std::memory_order_release);
			detail::cpu_relax();
		}
	}

	/**
	 * @brief Try to borrow once without retry.
	 *
	 * Returns std::nullopt when revalidation observes a different active slot.
	 *
	 * @return Guard if successful, std::nullopt if revalidation rejects the slot.
	 */
	[[nodiscard]] std::optional<read_guard> try_borrow() const
	{
		const uint8_t idx = active_.load(std::memory_order_acquire);
		readers_[idx].fetch_add(1, std::memory_order_seq_cst);

		if (KINETUM_LIKELY(active_.load(std::memory_order_seq_cst) == idx)) {
			return read_guard(this, idx);
		}

		// Slot changed - release and return failure
		readers_[idx].fetch_sub(1, std::memory_order_release);
		return std::nullopt;
	}

	/**
	 * @brief Get a copy of the current value (hot path).
	 *
	 * Convenience method that borrows, copies, and releases under one guard.
	 * Use when you need a local copy to work with.
	 *
	 * @return Copy of current value
	 */
	[[nodiscard]] T get() const
	{
		auto guard = borrow();
		return guard.get();
	}

	/**
	 * @brief Try once to get a copy without retry.
	 *
	 * @return Copy if successful, std::nullopt if slot was changing
	 */
	[[nodiscard]] std::optional<T> try_get() const
	{
		auto maybe_guard = try_borrow();
		if (KINETUM_LIKELY(maybe_guard.has_value())) {
			return maybe_guard->get();
		}
		return std::nullopt;
	}

	// =========================================================================
	// State Query
	// =========================================================================

	/**
	 * @brief Check if any value has been stored.
	 * @return true if store() has been called at least once
	 */
	[[nodiscard]] bool has_value() const noexcept
	{
		return has_value_.load(std::memory_order_acquire);
	}

    private:
	// =========================================================================
	// Internal Helpers
	// =========================================================================

	/**
	 * @brief Wait for all readers on a slot to finish.
 *
	 * Before reuse, the writer has published the other slot. That publication
	 * and this zero check share the reader's pin/revalidation order, so an
	 * accepted older reader remains counted. The acquiring load also pairs
	 * with the last reader's release.
 *
	 * @param slot_idx Slot to wait on
	 */
	void wait_for_readers(uint8_t slot_idx)
	{
		uint32_t iteration = 0;
		while (readers_[slot_idx].load(std::memory_order_seq_cst) != 0) {
			detail::spin_backoff(iteration++);
		}
	}

	// =========================================================================
	// Cache-line-isolated storage layout.
	// =========================================================================

	/** @brief One cache-line-aligned immutable publication slot. */
	struct alignas(CACHE_LINE_SIZE) slot {
		T value{};  ///< Value replaced only while this slot has no readers.
	};

	alignas(CACHE_LINE_SIZE) mutable std::atomic<uint32_t> readers_[2]{{0}, {0}};  ///< Per-slot pins.
	alignas(CACHE_LINE_SIZE) std::atomic<uint8_t> active_{0};		       ///< Published slot identity.
	alignas(CACHE_LINE_SIZE) std::atomic<bool> has_value_{false};  ///< Whether first publication completed.
	alignas(CACHE_LINE_SIZE) slot slots_[2];		       ///< Alternating cache-line-isolated values.
};

// =============================================================================
// Versioned RCU Buffer (with epoch tracking)
// =============================================================================

/**
 * @brief RCU buffer with version/epoch tracking.
 *
 * Extends rcu_buffer with:
 * - Version number (epoch) for each stored value
 * - Version query without full borrow
 *
 * Used by control-plane published state and guardrails policy readers.
 */
template <typename T>
class versioned_rcu_buffer {
    private:
	/** @brief Value and exact epoch published as one pinned RCU object. */
	struct versioned_slot {
		T value{};	    ///< Immutable value for this slot publication.
		uint64_t epoch{0};  ///< Exact caller-authored version paired with `value`.
	};

    public:
	// =========================================================================
	// Read Guard
	// =========================================================================

	/**
	 * @brief RAII guard with epoch access.
	 *
	 * The guard owns one underlying slot pin and exposes the immutable epoch
	 * stored beside that slot's value.
	 */
	class read_guard {
	    public:
		/**
		 * @brief Disable copy construction because one guard owns one pin.
		 */
		read_guard(const read_guard &) = delete;

		/**
		 * @brief Disable copy assignment because one guard owns one pin.
		 */
		read_guard &operator=(const read_guard &) = delete;

		/**
		 * @brief Transfer one underlying slot pin from another guard.
		 * @param other Guard whose pin is consumed.
		 */
		read_guard(read_guard &&other) noexcept = default;

		/**
		 * @brief Release any current pin and consume another guard's pin.
		 * @param other Guard whose pin is consumed.
		 * @return This guard after ownership transfer.
		 */
		read_guard &operator=(read_guard &&other) noexcept = default;

		/** @brief Release the owned underlying slot pin. */
		~read_guard() = default;

		/**
		 * @brief Return the pinned value by reference.
		 * @return Immutable reference valid for this guard's lifetime.
		 */
		[[nodiscard]] const T &get() const noexcept
		{
			return inner_->value;
		}

		/**
		 * @brief Return the pinned value for pointer-style access.
		 * @return Immutable pointer valid for this guard's lifetime.
		 */
		[[nodiscard]] const T *operator->() const noexcept
		{
			return &inner_->value;
		}

		/**
		 * @brief Return the pinned value for dereference-style access.
		 * @return Immutable reference valid for this guard's lifetime.
		 */
		[[nodiscard]] const T &operator*() const noexcept
		{
			return inner_->value;
		}

		/**
		 * @brief Return the exact epoch stored beside the pinned value.
		 * @return Epoch supplied with the pinned publication.
		 */
		[[nodiscard]] uint64_t epoch() const noexcept
		{
			return inner_->epoch;
		}

		/**
		 * @brief Return whether this guard still owns a slot pin.
		 * @return True unless the guard was moved from.
		 */
		[[nodiscard]] bool valid() const noexcept
		{
			return inner_.valid();
		}

		/**
		 * @brief Return whether this guard still owns a slot pin.
		 * @return True unless the guard was moved from.
		 */
		explicit operator bool() const noexcept
		{
			return inner_.valid();
		}

	    private:
		friend class versioned_rcu_buffer;

		/**
		 * @brief Adopt one already-acquired versioned-slot pin.
		 * @param inner Exact underlying guard to own.
		 */
		explicit read_guard(typename rcu_buffer<versioned_slot>::read_guard inner)
			: inner_(std::move(inner))
		{
		}

		typename rcu_buffer<versioned_slot>::read_guard inner_;	 ///< Sole underlying slot pin.
	};

	// =========================================================================
	// Construction
	// =========================================================================

	/** @brief Construct an empty versioned buffer. */
	versioned_rcu_buffer() = default;

	/** @brief Destroy through the contained buffer's exact guard-lifetime check. */
	~versioned_rcu_buffer() = default;

	/**
	 * @brief Disable copy construction because publication ownership is local.
	 */
	versioned_rcu_buffer(const versioned_rcu_buffer &) = delete;

	/**
	 * @brief Disable copy assignment because publication ownership is local.
	 */
	versioned_rcu_buffer &operator=(const versioned_rcu_buffer &) = delete;

	/**
	 * @brief Disable move construction because published addresses are stable.
	 */
	versioned_rcu_buffer(versioned_rcu_buffer &&) = delete;

	/**
	 * @brief Disable move assignment because published addresses are stable.
	 */
	versioned_rcu_buffer &operator=(versioned_rcu_buffer &&) = delete;

	// =========================================================================
	// Writer Interface
	// =========================================================================

	/**
	 * @brief Store a new value with epoch (cold path).
	 *
	 * @param value The new value to store
	 * @param epoch The epoch/version number for this value
	 */
	void store(T value, uint64_t epoch)
	{
		buffer_.store(versioned_slot{std::move(value), epoch});
	}

	/**
	 * @brief Store a new value with epoch, constructed in-place.
	 *
	 * @tparam Args Constructor argument types.
	 * @param epoch The epoch/version number
	 * @param args Constructor arguments for T
	 */
	template <typename... Args>
	void emplace(uint64_t epoch, Args &&...args)
	{
		buffer_.store(versioned_slot{T(std::forward<Args>(args)...), epoch});
	}

	// =========================================================================
	// Reader Interface
	// =========================================================================

	/**
	 * @brief Borrow with epoch access (hot path).
	 * @return Guard pinning the current value and its epoch.
	 */
	[[nodiscard]] read_guard borrow() const
	{
		return read_guard(buffer_.borrow());
	}

	/**
	 * @brief Try to borrow without retry.
	 * @return Guard on success, or empty when publication changed concurrently.
	 */
	[[nodiscard]] std::optional<read_guard> try_borrow() const
	{
		auto maybe = buffer_.try_borrow();
		if (maybe.has_value()) {
			return read_guard(std::move(*maybe));
		}
		return std::nullopt;
	}

	/**
	 * @brief Get a copy of the current value (hot path).
	 * @return Copy read under one slot guard.
	 */
	[[nodiscard]] T get() const
	{
		return borrow().get();
	}

	/**
	 * @brief Try to get a copy without retry.
	 * @return Copy on success, or empty when publication changed concurrently.
	 */
	[[nodiscard]] std::optional<T> try_get() const
	{
		auto maybe = try_borrow();
		if (maybe.has_value()) {
			return maybe->get();
		}
		return std::nullopt;
	}

	// =========================================================================
	// State Query
	// =========================================================================

	/**
	 * @brief Return whether at least one value has been published.
	 * @return True after the first successful publication.
	 */
	[[nodiscard]] bool has_value() const noexcept
	{
		return buffer_.has_value();
	}

	/**
	 * @brief Get current epoch/version number.
	 *
	 * Note: This does a full borrow internally. For frequent queries,
	 * prefer using the guard's epoch() method.
	 *
	 * @return Current published epoch, or zero before the first publication.
	 */
	[[nodiscard]] uint64_t version() const noexcept
	{
		if (!has_value())
			return 0;
		return borrow().epoch();
	}

    private:
	rcu_buffer<versioned_slot> buffer_;  ///< Coherent value-and-epoch publication owner.
};

}  // namespace kinetum::algo
