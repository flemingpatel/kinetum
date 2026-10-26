// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file atomic_index_pool.hpp
 * @brief Concurrent compact-index ownership with independent atomic-bit retirement.
 * @author Fleming Patel
 */

#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>
#include <type_traits>
#include <utility>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail::index_pool
{
inline constexpr std::size_t WORD_BITS = 64;  ///< Indices represented by one atomic word.

/** @brief Isolate independently updated availability words. */
struct alignas(CACHE_LINE_SIZE) word {
	std::atomic<uint64_t> available{0};  ///< Set bits have no lease holder.
};
static_assert(sizeof(word) == CACHE_LINE_SIZE && alignof(word) == CACHE_LINE_SIZE);
static_assert(std::is_standard_layout_v<word> && offsetof(word, available) == 0);
static_assert(std::atomic<uint64_t>::is_always_lock_free);
static_assert(std::atomic<uint32_t>::is_always_lock_free);
static_assert(std::atomic<std::size_t>::is_always_lock_free);

/** @return Exact atomic-word extent for a nonnegative uint32 universe. */
constexpr std::size_t word_count(uint32_t population) noexcept
{
	return (static_cast<std::size_t>(population) + WORD_BITS - 1u) / WORD_BITS;
}

/** @brief Initialize complete live word objects before publishing a new pool. */
inline void initialize(std::span<word> words, uint32_t population) noexcept
{
	if (population == 0 || words.data() == nullptr || words.size() != word_count(population) ||
	    reinterpret_cast<std::uintptr_t>(words.data()) % alignof(word) != 0) {
		std::terminate();
	}
	for (std::size_t ordinal = 0; ordinal < words.size(); ++ordinal) {
		const auto remaining = static_cast<std::size_t>(population) - ordinal * WORD_BITS;
		words[ordinal].available.store(remaining >= WORD_BITS ? UINT64_MAX : (UINT64_C(1) << remaining) - 1u,
					       std::memory_order_relaxed);
	}
}

/** @brief Claim one observed mask once; a failed CAS transfers nothing. */
KINETUM_ALWAYS_INLINE bool claim(word &source, uint64_t observed, uint64_t selected) noexcept
{
	return source.available.compare_exchange_strong(observed, observed & ~selected, std::memory_order_acquire,
							std::memory_order_relaxed);
}

/** @brief Claim the first observed free bit. @pre The observed mask is nonzero. */
KINETUM_ALWAYS_INLINE bool claim_one(word &source, uint64_t observed, uint32_t &bit) noexcept
{
	const auto selected = static_cast<uint32_t>(std::countr_zero(observed));
	if (!claim(source, observed, UINT64_C(1) << selected)) {
		return false;
	}
	bit = selected;
	return true;
}

/** @brief Search the fixed owner's linear universe without prefix or cache bookkeeping. */
KINETUM_ALWAYS_INLINE bool acquire_one(std::span<word> words, uint32_t &index) noexcept
{
	for (std::size_t ordinal = 0; ordinal < words.size(); ++ordinal) {
		const auto observed = words[ordinal].available.load(std::memory_order_relaxed);
		if (observed == 0) {
			continue;
		}
		uint32_t bit = 0;
		if (claim_one(words[ordinal], observed, bit)) {
			index = static_cast<uint32_t>(ordinal * WORD_BITS) + bit;
			return true;
		}
	}
	return false;
}

/**
 * @brief Deliver the budget-admitted mask from one word through a bounded projection.
 * @pre The available mask is nonzero and done is strictly below limit.
 */
template <class emit_type>
KINETUM_ALWAYS_INLINE void claim_word(word &source, std::size_t ordinal, uint64_t available, std::size_t limit,
				      std::size_t &done, emit_type &emit) noexcept
{
	const auto remaining = limit - done;
	if (remaining == 1) {
		uint32_t bit = 0;
		if (claim_one(source, available, bit)) {
			emit(done, static_cast<uint32_t>(ordinal * WORD_BITS) + bit);
			++done;
		}
		return;
	}
	uint64_t selected = available;
	if (static_cast<std::size_t>(std::popcount(available)) > remaining) {
		selected = 0;
		for (std::size_t index = 0; index < remaining; ++index) {
			const auto unused = available & ~selected;
			selected |= unused & (UINT64_C(0) - unused);
		}
	}
	if (!claim(source, available, selected)) {
		return;
	}
	while (selected != 0) {
		emit(done,
		     static_cast<uint32_t>(ordinal * WORD_BITS) + static_cast<uint32_t>(std::countr_zero(selected)));
		++done;
		selected &= selected - 1u;
	}
}

/**
 * @brief Scan a bounded circular range through the shared ownership primitive.
 * @pre The caller has remaining budget and supplies at most the backing word count.
 * @param words Exact initialized backing.
 * @param begin First word ordinal; wrapping visits each word at most once.
 * @param visits Maximum words to inspect.
 * @param limit Total accepted-prefix ceiling, including prior progress.
 * @param emit Borrowed nonthrowing local projection.
 * @param[in,out] done Exact emitted population.
 * @param[in,out] first First successful word, changed only when progress begins here.
 * @param[in,out] observed Set for any nonzero mask, even when its ownership CAS loses.
 */
template <std::memory_order order, class emit_type>
KINETUM_ALWAYS_INLINE void scan(std::span<word> words, std::size_t begin, std::size_t visits, std::size_t limit,
				emit_type &emit, std::size_t &done, std::size_t &first, bool &observed) noexcept
{
	for (std::size_t visited = 0, ordinal = begin; visited < visits;
	     ++visited, ordinal = ordinal + 1u == words.size() ? 0u : ordinal + 1u) {
		const auto available = words[ordinal].available.load(order);
		if (available == 0) {
			continue;
		}
		observed = true;
		const auto before = done;
		claim_word(words[ordinal], ordinal, available, limit, done, emit);
		if (before == 0 && done != 0) {
			first = ordinal;
		}
		if (done == limit) {
			return;
		}
	}
}

/** @brief Return an exact owned mask; already-free bits are a caller contradiction. */
template <std::memory_order order>
KINETUM_ALWAYS_INLINE void publish(word &destination, uint64_t mask) noexcept
{
	if ((destination.available.fetch_or(mask, order) & mask) != 0) {
		std::terminate();
	}
}

/** @brief Preserve the fixed owner's exact capacity check and single-index return. */
template <std::size_t Capacity>
KINETUM_ALWAYS_INLINE void release_one(std::span<word> words, uint32_t index) noexcept
{
	if (index >= Capacity) {
		std::terminate();
	}
	publish<std::memory_order_release>(words[index / WORD_BITS], UINT64_C(1) << (index % WORD_BITS));
}

/** @brief Read each supplied lease once and publish maximal contiguous equal-word runs. */
template <std::memory_order order, class read_type>
KINETUM_ALWAYS_INLINE void release(std::span<word> words, uint32_t capacity, std::size_t count,
				   read_type &read) noexcept
{
	if (count == 0) {
		return;
	}
	if (count > capacity) {
		std::terminate();
	}
	std::size_t ordinal = words.size();
	uint64_t mask = 0;
	for (std::size_t position = 0; position < count; ++position) {
		const auto index = read(position);
		if (index >= capacity) {
			std::terminate();
		}
		const auto target = index / WORD_BITS;
		if (target != ordinal) {
			if (mask != 0) {
				publish<order>(words[ordinal], mask);
			}
			ordinal = target;
			mask = 0;
		}
		const auto bit = UINT64_C(1) << (index % WORD_BITS);
		if ((mask & bit) != 0) {
			std::terminate();
		}
		mask |= bit;
	}
	publish<order>(words[ordinal], mask);
}
}  // namespace detail::index_pool
/** @endcond */

/**
 * @brief Fixed concurrent index pool with one independent availability bit per index.
 * @tparam Capacity Positive uint32-representable population.
 *
 * @par Thread Safety
 * Concurrent callers own distinct leases. Finish object access before release;
 * callers and leases must quiesce before destruction. Already-free or invalid
 * returns terminate; a stale lease after reacquisition violates caller ownership.
 *
 * @par Performance
 * Scalar acquisition visits at most ceil(Capacity/64) separated words, with one
 * CAS per nonempty word. Contention may refuse despite available indices. Return
 * performs one release RMW. Neither operation allocates or calls foreign code;
 * native atomics may retry internally, so no wait-free guarantee is made.
 */
template <std::size_t Capacity>
class atomic_index_pool final {
	static_assert(Capacity > 0 && Capacity <= UINT32_MAX);

    public:
	/** @brief Initialize the exact fixed universe. */
	atomic_index_pool() noexcept
	{
		detail::index_pool::initialize(words_, static_cast<uint32_t>(Capacity));
	}
	/** @brief Fixed owners cannot be copied. */
	atomic_index_pool(const atomic_index_pool &) = delete;
	/** @brief Fixed owners cannot be assigned. */
	atomic_index_pool &operator=(const atomic_index_pool &) = delete;
	/**
	 * @brief Attempt one bounded scalar claim without waiting for another owner.
	 * @param[out] index Changed only after successful exclusive acquisition.
	 * @return True with one index, or false for exhaustion or contention.
	 */
	[[nodiscard]] bool try_acquire(uint32_t &index) noexcept
	{
		return detail::index_pool::acquire_one(words_, index);
	}
	/**
	 * @brief Publish one owned index after all object accesses finish.
	 * @param index Exact lease; out-of-range or already-free input terminates.
	 */
	void release(uint32_t index) noexcept
	{
		detail::index_pool::release_one<Capacity>(words_, index);
	}

    private:
	std::array<detail::index_pool::word, detail::index_pool::word_count(static_cast<uint32_t>(Capacity))>
		words_{};  ///< Sole availability authority.
};

/**
 * @brief Concurrent prefix acquisition over caller-constructed availability words.
 *
 * A set bit is the sole free-index authority. Geometry occupies a separate line
 * from the shared certificate and relaxed first-successful-word hint; these
 * controls are not worker-private state. Each availability word has its own line.
 *
 * @par Thread Safety
 * The exact backing span and this view outlive all calls and leases. Callers
 * exclusively own leased objects and finish access before returning their indices.
 * Returning an index never waits for an unrelated lease. Concurrent acquisition
 * may return short under contention; a short result does not prove exhaustion.
 *
 * @par Performance
 * Acquisition performs at most ceil(population/64)+1 explicit word loads and one
 * ownership CAS per word, plus work proportional to accepted indices. Return is
 * linear in its input, with one RMW per contiguous same-word run. Native atomics
 * may retry internally; no wait-free or fairness guarantee is made. No hot operation
 * allocates, locks, reads time, or invokes foreign code.
 */
class atomic_index_pool_view final {
    public:
	using storage_type = detail::index_pool::word;	///< Exact caller-constructed backing element.
	/**
	 * @param capacity Logical index population, including zero for cold sizing.
	 * @return Exact backing word count; constructing a view still requires positive capacity.
	 */
	static constexpr std::size_t word_count(uint32_t capacity) noexcept
	{
		return detail::index_pool::word_count(capacity);
	}
	/**
	 * @brief Initialize the exclusive exact backing extent before publication.
	 * @param words Constructed, aligned word objects; owned by the caller.
	 * @param capacity Positive logical population, including a partial final word.
	 * @pre All prior calls and leases using this backing have retired.
	 * Invalid geometry terminates before any word is initialized.
	 */
	atomic_index_pool_view(std::span<storage_type> words, uint32_t capacity) noexcept
		: words_(words)
		, capacity_(capacity)
	{
		static_assert(std::is_standard_layout_v<atomic_index_pool_view>);
		static_assert(sizeof(atomic_index_pool_view) == 2u * CACHE_LINE_SIZE);
		static_assert(alignof(atomic_index_pool_view) == CACHE_LINE_SIZE);
		static_assert(offsetof(atomic_index_pool_view, words_) == 0u);
		static_assert(offsetof(atomic_index_pool_view, capacity_) == 16u);
		static_assert(offsetof(atomic_index_pool_view, control_) == CACHE_LINE_SIZE);
		static_assert(offsetof(atomic_index_pool_view, cursor_) == CACHE_LINE_SIZE + 8u);
		detail::index_pool::initialize(words_, capacity_);
	}
	/** @brief Reject copying of live search and lease state. */
	atomic_index_pool_view(const atomic_index_pool_view &) = delete;
	/** @brief Reject assignment of live search and lease state. */
	atomic_index_pool_view &operator=(const atomic_index_pool_view &) = delete;
	/** @brief Preserve the address of live search control. */
	atomic_index_pool_view(atomic_index_pool_view &&) = delete;
	/** @brief Moving cannot replace live search or lease state. */
	atomic_index_pool_view &operator=(atomic_index_pool_view &&) = delete;
	/**
	 * @brief Acquire a bounded prefix, preserving the request's integral result type.
	 * @param requested Maximum accepted count; nonpositive requests return zero.
	 * @param emit Trivially copyable, nonthrowing borrowed projection of (ordinal, index).
	 * It returns void, performs bounded local work, and neither reenters this pool
	 * nor invokes foreign code. Each acquired index is emitted exactly once.
	 * @return Exact accepted prefix; the caller's remaining output stays untouched.
	 */
	template <class count_type, class emit_type>
	[[nodiscard]] KINETUM_ALWAYS_INLINE count_type acquire_prefix(count_type requested, emit_type emit) noexcept
	{
		static_assert(std::is_integral_v<count_type> && !std::is_same_v<std::remove_cv_t<count_type>, bool> &&
			      sizeof(count_type) <= sizeof(std::size_t));
		static_assert(std::is_trivially_copyable_v<emit_type>);
		static_assert(std::is_nothrow_invocable_r_v<void, emit_type &, std::size_t, uint32_t>);
		static_assert(std::is_same_v<std::invoke_result_t<emit_type &, std::size_t, uint32_t>, void>);
		if (requested <= 0) {
			return 0;
		}
		if (words_.size() != 1 && control_.load(std::memory_order_relaxed) == EMPTY) {
			return 0;
		}
		const auto begin = words_.size() == 1 ? 0 : cursor_.load(std::memory_order_relaxed);
		const auto initial = words_[begin].available.load(std::memory_order_relaxed);
		if (words_.size() == 1 && initial == 0) {
			return 0;
		}
		return acquire_observed_(requested, begin, initial, emit);
	}
	/**
	 * @brief Publish maximal contiguous same-word runs of exact owned indices.
	 * @param count Number of leases to return; zero performs no work.
	 * @param read Nonthrowing bounded local reader returning uint32 indices by ordinal,
	 * read once each. Object access must end before its index is published; no reentry.
	 * Invalid or already-free indices terminate, possibly after a valid prefix was
	 * published. The caller guarantees unique leases; stale returns racing a later
	 * owner are outside detection. No rollback follows a contract violation.
	 */
	template <class read_type>
	KINETUM_ALWAYS_INLINE void release_prefix(std::size_t count, read_type &&read) noexcept
	{
		static_assert(std::is_nothrow_invocable_r_v<uint32_t, read_type &, std::size_t>);
		static_assert(std::is_same_v<std::invoke_result_t<read_type &, std::size_t>, uint32_t>);
		if (count == 0) {
			return;
		}
		detail::index_pool::release<std::memory_order_seq_cst>(words_, capacity_, count, read);
		// SC bit publication precedes the control read. A clean inspector either
		// reads this return in its SC scan or observes our DIRTY invalidation.
		// Clearing SCANNING here could erase another caller's newer inspection.
		if (words_.size() != 1) {
			const auto state = control_.load(std::memory_order_seq_cst);
			if (state == SCANNING || state == EMPTY) {
				control_.fetch_or(DIRTY, std::memory_order_seq_cst);
			}
		}
	}
	/**
	 * @return Approximate free population, exact after callers quiesce.
	 * @note Cold O(ceil(population/64)) scan, not a simultaneous concurrent snapshot.
	 * Packet and replenishment paths must not use this observation for admission.
	 */
	[[nodiscard]] uint32_t available_approx() const noexcept
	{
		uint32_t result = 0;
		for (const auto &word : words_) {
			result += static_cast<uint32_t>(std::popcount(word.available.load(std::memory_order_relaxed)));
		}
		return result;
	}

    private:
	static constexpr uint32_t SCANNING = 1;	 ///< One caller owns the full-scan obligation.
	static constexpr uint32_t DIRTY = 2;	 ///< A return prevents clean empty certification.
	static constexpr uint32_t EMPTY = 4;	 ///< Complete clean scan observed no availability.

	/** @brief Linear ownership of one optional empty-certification scan. */
	class inspection_claim final {
	    public:
		/** @brief Attempt enrollment once; another inspector never blocks this caller. */
		inspection_claim(std::atomic<uint32_t> &control, uint32_t observed) noexcept
		{
			if ((observed & SCANNING) == 0 &&
			    control.compare_exchange_strong(observed, SCANNING, std::memory_order_seq_cst)) {
				control_ = &control;
			}
		}
		/** @brief An inspection obligation cannot be duplicated. */
		inspection_claim(const inspection_claim &) = delete;
		/** @brief An inspection obligation cannot be overwritten. */
		inspection_claim &operator=(const inspection_claim &) = delete;
		/** @brief Transfer the sole inspection obligation. */
		inspection_claim(inspection_claim &&other) noexcept
			: control_(std::exchange(other.control_, nullptr))
		{
		}
		/** @brief Resolve before replacement rather than discarding a claim. */
		inspection_claim &operator=(inspection_claim &&) = delete;
		/** @brief Unresolved inspection cannot silently leave SCANNING set. */
		~inspection_claim()
		{
			if (control_ != nullptr) {
				std::terminate();
			}
		}
		/** @return Whether this caller acquired the inspection obligation. */
		[[nodiscard]] bool owns() const noexcept
		{
			return control_ != nullptr;
		}
		/**
		 * @brief Complete this scan exactly once.
		 * @param observed Whether any availability was observed, even if its CAS lost.
		 * False requires a complete scan. Returns dirty the enrolled scan before it
		 * can certify empty; a failed certification only clears our SCANNING bit.
		 */
		void finish(bool observed) noexcept
		{
			if (control_ == nullptr) {
				std::terminate();
			}
			if (!observed) {
				auto expected = SCANNING;
				if (control_->compare_exchange_strong(expected, EMPTY, std::memory_order_seq_cst)) {
					control_ = nullptr;
					return;
				}
			}
			control_->fetch_and(~SCANNING, std::memory_order_seq_cst);
			control_ = nullptr;
		}

	    private:
		std::atomic<uint32_t> *control_{nullptr};  ///< Non-null until the owned scan completes.
	};

	/** @brief Enroll an optional inspector, share the bounded scan, and retire inspection ownership once. */
	template <class count_type, class emit_type>
	KINETUM_NOINLINE count_type acquire_observed_(count_type requested, std::size_t begin, uint64_t initial,
						      emit_type emit) noexcept
	{
		const auto limit = static_cast<std::size_t>(requested);
		std::size_t done = 0, first = begin;
		bool observed = false;
		if (initial != 0) {
			detail::index_pool::claim_word(words_[begin], begin, initial, limit, done, emit);
			if (done < limit && words_.size() > 1) {
				const auto next = begin + 1u == words_.size() ? 0u : begin + 1u;
				detail::index_pool::scan<std::memory_order_seq_cst>(words_, next, words_.size() - 1u,
										    limit, emit, done, first, observed);
			}
		} else {
			// Registration precedes the SC reread of every word. An observed free
			// bit forbids empty certification even when its ownership CAS loses.
			auto state = control_.load(std::memory_order_seq_cst);
			if (state == EMPTY) {
				return 0;
			}
			inspection_claim inspector(control_, state);
			detail::index_pool::scan<std::memory_order_seq_cst>(words_, begin, words_.size(), limit, emit,
									    done, first, observed);
			if (inspector.owns()) {
				inspector.finish(observed);
			}
		}
		if (done != 0 && words_.size() != 1 && cursor_.load(std::memory_order_relaxed) != first) {
			cursor_.store(first, std::memory_order_relaxed);
		}
		return static_cast<count_type>(done);
	}

	std::span<storage_type> words_;	 ///< Borrowed words outlive the view and all operations.
	uint32_t capacity_;		 ///< Exact logical index population.
	alignas(CACHE_LINE_SIZE) std::atomic<uint32_t> control_{0};  ///< Sole inspector/certificate state.
	std::atomic<std::size_t> cursor_{0};			     ///< Advisory first-successful-word hint.
};

}  // namespace kinetum::algo
