// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file quiescence.hpp
 * @brief Exact backend-neutral reader quiescence and grace generations.
 * @author Fleming Patel
 *
 * A `quiescence_domain` binds one immutable ordered set of caller-owned
 * `quiescence_reader` records. The sole coordinator starts one adjacent grace
 * generation at a time. Each reader publishes that exact generation once after
 * crossing its owning read-side safe point; missing publication keeps the grace
 * incomplete and no numeric maximum can hide a skipped generation.
 *
 * @par Thread Safety
 * Exactly one externally serialized coordinator calls the domain's start,
 * observation, and finish methods. Each bound reader has exactly one writer.
 * Domain construction/destruction and reader lifetime changes require all
 * reader threads to be absent or joined.
 *
 * @par Performance
 * Reader storage is caller-owned and cache-line isolated. One grace publication
 * performs one request load and at most one reader-local atomic compare/exchange.
 * Domain observation is cold O(reader_count) work. No operation allocates after
 * construction, locks, sleeps, invokes the operating system, reads a clock,
 * logs, formats, or retries without a fixed bound.
 */

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <unordered_set>
#include <vector>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

class quiescence_domain;

/**
 * @brief One stable caller-placed reader publication record.
 *
 * The record is bound by exactly one domain for its useful lifetime. It owns
 * only its exact grace publication; transition, epoch, reclamation, and timeout
 * policy remain with the caller.
 */
class alignas(CACHE_LINE_SIZE) quiescence_reader final {
    public:
	/** @brief Construct one unbound unpublished reader record. */
	quiescence_reader() noexcept = default;

	/** @brief Fail stop if caller storage is destroyed while still domain-bound. */
	~quiescence_reader()
	{
		if (domain_ != nullptr) {
			std::terminate();
		}
	}

	/** @brief Stable reader records cannot be copied. */
	quiescence_reader(const quiescence_reader &) = delete;
	/** @brief Stable reader records cannot be copy-assigned. */
	quiescence_reader &operator=(const quiescence_reader &) = delete;
	/** @brief Stable reader records cannot move after a domain observes their address. */
	quiescence_reader(quiescence_reader &&) = delete;
	/** @brief Stable reader records cannot be move-assigned. */
	quiescence_reader &operator=(quiescence_reader &&) = delete;

	/**
	 * @brief Publish the domain's exact active grace after one safe point.
	 *
	 * Exact duplicate publication is idempotent. A zero return means no grace is
	 * currently active. Stale, skipped, regressing, or otherwise nonadjacent
	 * retained state terminates instead of manufacturing quiescence. The
	 * class-level single-writer rule remains an external ownership precondition.
	 *
	 * @return Exact nonzero published grace generation, or zero when inactive.
	 */
	[[nodiscard]] uint64_t publish_quiescent() noexcept;

	/** @return true after one domain has bound this stable record. */
	[[nodiscard]] bool bound() const noexcept
	{
		return domain_ != nullptr;
	}

	/** @return Exact domain-local reader index, or UINT64_MAX while unbound. */
	[[nodiscard]] uint64_t reader_index() const noexcept
	{
		return reader_index_;
	}

    private:
	friend class quiescence_domain;

	/**
	 * @brief Bind one prevalidated domain/index pair before reader launch.
	 *
	 * @param domain Sole immutable domain borrowing this record.
	 * @param reader_index Exact position in the domain's ordered reader set.
	 */
	void bind_(quiescence_domain &domain, uint64_t reader_index) noexcept
	{
		if (domain_ != nullptr || reader_index == std::numeric_limits<uint64_t>::max() ||
		    observed_generation_.load(std::memory_order_relaxed) != 0u) {
			std::terminate();
		}
		domain_ = &domain;
		reader_index_ = reader_index;
	}

	/**
	 * @brief Release one exact domain binding after every reader thread joins.
	 *
	 * @param domain Exact domain ending its borrow.
	 * @param reader_index Exact immutable index assigned by that domain.
	 */
	void unbind_(const quiescence_domain &domain, uint64_t reader_index) noexcept
	{
		if (domain_ != &domain || reader_index_ != reader_index) {
			std::terminate();
		}
		domain_ = nullptr;
		reader_index_ = std::numeric_limits<uint64_t>::max();
	}

	std::atomic<uint64_t> observed_generation_{0};		       ///< Last exact adjacent grace publication.
	quiescence_domain *domain_{nullptr};			       ///< Sole borrowing domain while bound.
	uint64_t reader_index_{std::numeric_limits<uint64_t>::max()};  ///< Exact immutable bound index.
};

static_assert(sizeof(quiescence_reader) == CACHE_LINE_SIZE, "quiescence reader must occupy exactly one cache line");
static_assert(alignof(quiescence_reader) == CACHE_LINE_SIZE, "quiescence reader must retain cache-line alignment");
static_assert(std::atomic<uint64_t>::is_always_lock_free, "quiescence publication requires a lock-free uint64 atomic");

/**
 * @brief One immutable exact reader domain with serialized grace ownership.
 *
 * The domain borrows every reader record in caller-supplied order and assigns
 * that position as the sole reader identity. It owns grace generation but does
 * not own reader storage, reclamation, timeout, or subsystem transition state.
 */
class quiescence_domain final {
    public:
	/**
	 * @brief Bind one complete ordered nonempty reader set atomically.
	 *
	 * All pointers are validated for nonnull, uniqueness, stable unbound state,
	 * and zero prior publication before the first reader is mutated.
	 *
	 * @param readers Complete caller-owned stable reader set.
	 * @throws std::invalid_argument for zero, null, duplicate, bound, or reused readers.
	 * @throws std::bad_alloc or std::length_error when cold membership storage fails.
	 */
	explicit quiescence_domain(std::span<quiescence_reader *const> readers)
		: readers_(readers.begin(), readers.end())
	{
		if (readers_.empty()) {
			throw std::invalid_argument("quiescence_domain requires at least one exact reader");
		}
		std::unordered_set<quiescence_reader *> identities;
		identities.reserve(readers_.size());
		for (auto *reader : readers_) {
			if (!identities.insert(reader).second) {
				throw std::invalid_argument("quiescence_domain reader membership contains a duplicate");
			}
		}
		for (const auto *reader : readers_) {
			if (reader == nullptr || reader->bound() ||
			    reader->observed_generation_.load(std::memory_order_relaxed) != 0u) {
				throw std::invalid_argument("quiescence_domain reader membership is not pristine");
			}
		}
		for (std::size_t index = 0u; index < readers_.size(); ++index) {
			readers_[index]->bind_(*this, static_cast<uint64_t>(index));
		}
	}

	/** @brief Unbind readers only with no active grace period. */
	~quiescence_domain()
	{
		if (active_generation_.load(std::memory_order_acquire) != 0u) {
			std::terminate();
		}
		for (std::size_t index = readers_.size(); index != 0u; --index) {
			readers_[index - 1u]->unbind_(*this, static_cast<uint64_t>(index - 1u));
		}
	}

	/** @brief Domain membership and generation ownership cannot be copied. */
	quiescence_domain(const quiescence_domain &) = delete;
	/** @brief Domain membership and generation ownership cannot be copy-assigned. */
	quiescence_domain &operator=(const quiescence_domain &) = delete;
	/** @brief Bound reader addresses prevent domain movement. */
	quiescence_domain(quiescence_domain &&) = delete;
	/** @brief Bound reader addresses prevent domain move assignment. */
	quiescence_domain &operator=(quiescence_domain &&) = delete;

	/**
	 * @brief Determine whether one adjacent grace generation can start.
	 *
	 * @param completed_generation Last completed generation.
	 * @return true when adding one cannot enter the reserved wrap value.
	 */
	[[nodiscard]] static constexpr bool can_advance_generation(uint64_t completed_generation) noexcept
	{
		return completed_generation < std::numeric_limits<uint64_t>::max() - 1u;
	}

	/**
	 * @brief Prove the sole coordinator can start another grace without mutation.
	 *
	 * @return true only with no active grace, available adjacent identity, and
	 *         every reader exactly equal to the last completed generation.
	 */
	[[nodiscard]] bool can_start_grace_period() const noexcept
	{
		if (active_generation_.load(std::memory_order_acquire) != 0u ||
		    !can_advance_generation(completed_generation_)) {
			return false;
		}
		return std::all_of(readers_.begin(), readers_.end(), [this](const quiescence_reader *reader) {
			return reader->observed_generation_.load(std::memory_order_acquire) == completed_generation_;
		});
	}

	/**
	 * @brief Start one exact adjacent grace generation.
	 *
	 * The sole coordinator preflights this method before an irreversible caller
	 * transition. A violated precondition returns zero without publication.
	 *
	 * @return New nonzero active grace generation, or zero on precondition failure.
	 */
	[[nodiscard]] uint64_t start_grace_period() noexcept
	{
		if (!can_start_grace_period()) {
			return 0u;
		}
		const uint64_t generation = completed_generation_ + 1u;
		active_generation_.store(generation, std::memory_order_release);
		return generation;
	}

	/**
	 * @brief Count readers that published one exact active or completed grace.
	 *
	 * This pure observation never advances or clears domain state. An unrelated
	 * generation returns no value rather than borrowing nearby progress.
	 *
	 * @param generation Exact grace generation to inspect.
	 * @return Exact completed-reader count, or no value for an unrelated identity.
	 */
	[[nodiscard]] std::optional<std::size_t> quiescent_reader_count(uint64_t generation) const noexcept
	{
		if (generation == 0u) {
			return std::nullopt;
		}
		const uint64_t active = active_generation_.load(std::memory_order_acquire);
		if (active == 0u) {
			return completed_generation_ == generation ? std::optional<std::size_t>(readers_.size()) :
								     std::nullopt;
		}
		if (active != generation) {
			return std::nullopt;
		}
		std::size_t completed = 0u;
		for (const auto *reader : readers_) {
			const uint64_t observed = reader->observed_generation_.load(std::memory_order_acquire);
			if (observed == generation) {
				++completed;
			} else if (observed == std::numeric_limits<uint64_t>::max() || observed + 1u != generation) {
				return std::nullopt;
			}
		}
		return completed;
	}

	/**
	 * @brief Observe complete publication without changing grace ownership.
	 *
	 * @param generation Exact active or last completed generation.
	 * @return true only when every immutable reader published exactly generation.
	 */
	[[nodiscard]] bool grace_period_complete(uint64_t generation) const noexcept
	{
		const auto completed = quiescent_reader_count(generation);
		return completed.has_value() && *completed == readers_.size();
	}

	/**
	 * @brief Finish one exactly complete grace generation.
	 *
	 * Exact repeat after a prior finish is idempotent. The active generation is
	 * retained when membership is incomplete or the identity is unrelated.
	 *
	 * @param generation Exact generation whose caller-side reclamation is complete.
	 * @return true after exact finish or repeat; false with no state change otherwise.
	 */
	[[nodiscard]] bool finish_grace_period(uint64_t generation) noexcept
	{
		const uint64_t active = active_generation_.load(std::memory_order_acquire);
		if (active == 0u) {
			return generation != 0u && completed_generation_ == generation;
		}
		if (active != generation || !grace_period_complete(generation)) {
			return false;
		}
		completed_generation_ = generation;
		active_generation_.store(0u, std::memory_order_release);
		return true;
	}

	/** @return Immutable exact reader count. */
	[[nodiscard]] std::size_t reader_count() const noexcept
	{
		return readers_.size();
	}

	/**
	 * @brief Verify one exact bound reader identity without exposing storage.
	 *
	 * @param reader_index Domain-local immutable reader index.
	 * @param reader Candidate caller-owned reader record.
	 * @return true only when this domain bound that exact address at the index.
	 */
	[[nodiscard]] bool owns_reader(std::size_t reader_index, const quiescence_reader &reader) const noexcept
	{
		return reader_index < readers_.size() && readers_[reader_index] == &reader && reader.domain_ == this &&
		       reader.reader_index_ == static_cast<uint64_t>(reader_index);
	}

	/** @return Exact active grace generation, or zero while inactive. */
	[[nodiscard]] uint64_t active_generation() const noexcept
	{
		return active_generation_.load(std::memory_order_acquire);
	}

	/** @return Last exactly finished grace generation. */
	[[nodiscard]] uint64_t completed_generation() const noexcept
	{
		return completed_generation_;
	}

    private:
	friend class quiescence_reader;

	/**
	 * @brief Publish one reader's exact active generation after its safe point.
	 *
	 * @param reader Exact bound record owned by the calling reader.
	 * @return Exact nonzero active generation, or zero while no grace is active.
	 */
	[[nodiscard]] uint64_t publish_(quiescence_reader &reader) noexcept
	{
		const uint64_t generation = active_generation_.load(std::memory_order_acquire);
		if (generation == 0u) {
			return 0u;
		}
		uint64_t observed = reader.observed_generation_.load(std::memory_order_acquire);
		if (observed == generation) {
			return generation;
		}
		if (observed == std::numeric_limits<uint64_t>::max() || observed + 1u != generation) {
			std::terminate();
		}
		if (!reader.observed_generation_.compare_exchange_strong(
			    observed, generation, std::memory_order_release, std::memory_order_acquire)) {
			if (observed == generation) {
				return generation;
			}
			std::terminate();
		}
		return generation;
	}

	alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> active_generation_{0};  ///< Current grace request.
	uint64_t completed_generation_{0};	    ///< Sole-coordinator last finished generation.
	std::vector<quiescence_reader *> readers_;  ///< Immutable exact reader order.
};

inline uint64_t quiescence_reader::publish_quiescent() noexcept
{
	if (domain_ == nullptr || reader_index_ == std::numeric_limits<uint64_t>::max()) {
		std::terminate();
	}
	return domain_->publish_(*this);
}

}  // namespace kinetum::algo
