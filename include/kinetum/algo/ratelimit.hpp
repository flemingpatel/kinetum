// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file ratelimit.hpp
 * @brief Rate limiting algorithms.
 * @author Fleming Patel
 *
 * Contains:
 * - Token and leaky buckets with exact integer-rational byte accrual
 * - Exact sliding-window event counts with explicit resource-owned history
 *
 * Token Bucket Algorithm:
 * - Tokens accumulate at rate R (bytes/second)
 * - Bucket holds maximum B tokens (burst size)
 * - Each packet consumes tokens equal to its size
 * - If tokens >= packet_size: allow and consume
 * - If tokens < packet_size: drop (rate limited)
 *
 * The primitives are reusable SDK mechanisms. Token buckets and the built-in
 * QoS module share byte_credit; QoS owns its context-local flow slab and clock.
 */

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <vector>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/work_queue_indices.hpp>

namespace kinetum::algo
{

// =============================================================================
// Exact Rate Numerator
// =============================================================================

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/** One exact byte balance numerator is divided by this nanosecond scale. */
inline constexpr uint64_t RATE_DENOMINATOR = 1'000'000'000u;

/** Exact wide type for a full uint64 rate multiplied by a full uint64 interval. */
using rate_numerator = unsigned __int128;

/**
 * @brief Convert an integer byte quantity to the exact rate numerator domain.
 * @param bytes Whole byte quantity.
 * @return Exact @p bytes multiplied by `RATE_DENOMINATOR`.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr rate_numerator byte_numerator(uint64_t bytes) noexcept
{
	return static_cast<rate_numerator>(bytes) * RATE_DENOMINATOR;
}

/**
 * @brief Derive exact accrued byte numerator from elapsed nanoseconds and rate.
 * @param elapsed_ns Exact monotonic elapsed nanoseconds.
 * @param rate_bytes_per_sec Exact whole-byte rate per second.
 * @return Exact product; two uint64 factors are representable in 128 bits.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE KINETUM_CONST constexpr rate_numerator
accrued_numerator(uint64_t elapsed_ns, uint64_t rate_bytes_per_sec) noexcept
{
	return static_cast<rate_numerator>(elapsed_ns) * rate_bytes_per_sec;
}

}  // namespace detail
/** @endcond */

/**
 * @brief Exact byte credit with caller-owned time and policy.
 *
 * One owner supplies nonnegative elapsed intervals after validating its clock.
 * Refill retains fractional bytes over the nanosecond denominator and saturates
 * before addition. Consumption is bounded arithmetic with no division, clock
 * read, allocation, or synchronization.
 */
class byte_credit {
    public:
	/** @brief Construct an empty balance. */
	constexpr byte_credit() noexcept = default;
	/** @brief Construct an exact whole-byte balance. @param bytes Initial credit. */
	explicit constexpr byte_credit(uint64_t bytes) noexcept
		: numerator_(detail::byte_numerator(bytes))
	{
	}

	/**
	 * @brief Cap, refill, and conditionally consume exact byte credit.
	 * @param elapsed_ns Validated elapsed interval; zero earns no new credit.
	 * @param rate_bytes_per_sec Exact current refill rate.
	 * @param capacity_bytes Current ceiling, including after a policy change.
	 * @param bytes Exact packet or operation cost.
	 * @return true after consuming the cost; false retains capped, accrued credit.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE constexpr bool consume(uint64_t elapsed_ns, uint64_t rate_bytes_per_sec,
								   uint64_t capacity_bytes, uint64_t bytes) noexcept
	{
		const auto capacity = detail::byte_numerator(capacity_bytes);
		const auto retained = numerator_ < capacity ? numerator_ : capacity;
		const auto earned = detail::accrued_numerator(elapsed_ns, rate_bytes_per_sec);
		numerator_ = earned >= capacity - retained ? capacity : retained + earned;
		const auto cost = detail::byte_numerator(bytes);
		if (cost > numerator_) {
			return false;
		}
		numerator_ -= cost;
		return true;
	}

	/** @return Whole available bytes without discarding the retained fraction. */
	[[nodiscard]] constexpr uint64_t tokens() const noexcept
	{
		return static_cast<uint64_t>(numerator_ / detail::RATE_DENOMINATOR);
	}
	/** @brief Explicitly replace credit. @param bytes Exact whole-byte balance. */
	constexpr void reset(uint64_t bytes) noexcept
	{
		numerator_ = detail::byte_numerator(bytes);
	}

    private:
	detail::rate_numerator numerator_{0};  ///< Sole exact balance; bounded by the last supplied capacity.
};

// =============================================================================
// Token Bucket
// =============================================================================

/**
 * @brief Token bucket for rate limiting.
 *
 * Implements the standard token bucket algorithm with an exact rational byte
 * balance. The internal numerator carries every fractional byte generated by
 * an integer bytes-per-second rate at nanosecond timestamps.
 *
 * @par Thread Safety
 * One caller owns each bucket. Shared use requires external synchronization.
 *
 * @par Performance
 * Construction initializes fixed state. `allow()` performs fixed-width
 * arithmetic and allocates, locks, and reads no clock.
 */
class token_bucket {
    public:
	/**
	 * @brief Construct token bucket.
	 *
	 * @param rate_bytes_per_sec Token accumulation rate in bytes per second.
	 * @param burst_bytes Maximum whole-byte bucket capacity.
	 */
	constexpr token_bucket(uint64_t rate_bytes_per_sec, uint64_t burst_bytes) noexcept
		: rate_bytes_per_sec_(rate_bytes_per_sec)
		, burst_bytes_(burst_bytes)
		, credit_(burst_bytes)
		, last_ns_(0)
		, initialized_(false)
	{
	}

	/**
	 * @brief Check if packet should be allowed.
	 *
	 * Updates token count based on elapsed time, then checks if
	 * there are enough tokens for the packet.
	 *
	 * @param now_ns Explicit monotonic timestamp in nanoseconds.
	 * @param bytes Whole-byte cost.
	 * @return true if allowed and consumed; false for insufficient credit or
	 *         timestamp regression. Rejection preserves cost ownership.
	 */
	[[nodiscard]]
	KINETUM_ALWAYS_INLINE bool allow(uint64_t now_ns, std::size_t bytes) noexcept
	{
		uint64_t elapsed_ns = 0u;
		if (KINETUM_UNLIKELY(!initialized_)) {
			last_ns_ = now_ns;
			initialized_ = true;
		} else if (KINETUM_UNLIKELY(now_ns < last_ns_)) {
			return false;
		} else {
			elapsed_ns = now_ns - last_ns_;
			last_ns_ = now_ns;
		}

		static_assert(sizeof(std::size_t) <= sizeof(uint64_t));
		return credit_.consume(elapsed_ns, rate_bytes_per_sec_, burst_bytes_, static_cast<uint64_t>(bytes));
	}

	/** @return Whole available bytes, excluding retained fractional credit. */
	[[nodiscard]] constexpr uint64_t tokens() const noexcept
	{
		return credit_.tokens();
	}

	/** @return Exact configured whole-byte capacity. */
	[[nodiscard]] constexpr uint64_t burst() const noexcept
	{
		return burst_bytes_;
	}

	/** @brief Reset to full capacity with an unbound timestamp baseline. */
	void reset() noexcept
	{
		credit_.reset(burst_bytes_);
		last_ns_ = 0;
		initialized_ = false;
	}

	/**
	 * @brief Replace rate and burst without retroactive accrual.
	 *
	 * Existing whole-byte credit is retained up to the new capacity. Fractional
	 * credit from the old rate is discarded and the next accepted timestamp
	 * establishes a fresh baseline.
	 *
	 * @param rate_bytes_per_sec New exact whole-byte rate.
	 * @param burst_bytes New exact whole-byte capacity.
	 */
	void reconfigure(uint64_t rate_bytes_per_sec, uint64_t burst_bytes) noexcept
	{
		const uint64_t current_tokens = tokens();
		const uint64_t retained_bytes = current_tokens < burst_bytes ? current_tokens : burst_bytes;
		credit_.reset(retained_bytes);
		rate_bytes_per_sec_ = rate_bytes_per_sec;
		burst_bytes_ = burst_bytes;
		last_ns_ = 0u;
		initialized_ = false;
	}

    private:
	uint64_t rate_bytes_per_sec_;  ///< Exact configured whole-byte rate.
	uint64_t burst_bytes_;	       ///< Exact maximum whole-byte capacity.
	byte_credit credit_;	       ///< Exact balance shared with policy-owned policers.
	uint64_t last_ns_;	       ///< Last accepted timestamp.
	bool initialized_;	       ///< Whether the timestamp baseline is bound, including zero.
};

// =============================================================================
// Leaky Bucket (Alternative Rate Limiter)
// =============================================================================

/**
 * @brief Leaky-bucket meter with a fixed drain rate and bounded burst capacity.
 *
 * Accepted bytes raise the level; elapsed time drains it at the configured
 * rate. Calls at the same timestamp can admit a burst up to available capacity.
 * The caller owns packet disposition; this meter does not queue or pace output.
 *
 * Algorithm:
 * - Bucket "leaks" at constant rate R
 * - Each accepted packet adds its byte cost to the level
 * - If bucket would overflow: reject without adding the packet's cost
 *
 * @par Thread Safety
 * One caller owns each bucket. Shared use requires external synchronization.
 */
class leaky_bucket {
    public:
	/**
	 * @brief Construct leaky bucket.
	 * @param rate_bytes_per_sec Exact leak rate in bytes per second.
	 * @param capacity_bytes Exact maximum whole-byte level.
	 */
	constexpr leaky_bucket(uint64_t rate_bytes_per_sec, uint64_t capacity_bytes) noexcept
		: rate_bytes_per_sec_(rate_bytes_per_sec)
		, capacity_bytes_(capacity_bytes)
		, level_numerator_(0)
		, last_ns_(0)
		, initialized_(false)
	{
	}

	/**
	 * @brief Check if packet should be allowed.
	 *
	 * @param now_ns Explicit monotonic timestamp in nanoseconds.
	 * @param bytes Whole-byte cost.
	 * @return true if added; false for overflow or timestamp regression.
	 */
	[[nodiscard]]
	KINETUM_ALWAYS_INLINE bool allow(uint64_t now_ns, std::size_t bytes) noexcept
	{
		if (KINETUM_UNLIKELY(!initialized_)) {
			last_ns_ = now_ns;
			initialized_ = true;
		} else if (KINETUM_UNLIKELY(now_ns < last_ns_)) {
			return false;
		} else if (now_ns > last_ns_) {
			const uint64_t elapsed_ns = now_ns - last_ns_;
			const detail::rate_numerator leaked =
				detail::accrued_numerator(elapsed_ns, rate_bytes_per_sec_);
			level_numerator_ = leaked >= level_numerator_ ? 0u : level_numerator_ - leaked;
			last_ns_ = now_ns;
		}

		static_assert(sizeof(std::size_t) <= sizeof(uint64_t));
		const detail::rate_numerator cost = detail::byte_numerator(static_cast<uint64_t>(bytes));
		const detail::rate_numerator capacity = detail::byte_numerator(capacity_bytes_);
		if (cost <= capacity && level_numerator_ <= capacity - cost) {
			level_numerator_ += cost;
			return true;
		}

		return false;  // Overflow
	}

	/** @return Whole occupied bytes, excluding retained fractional leakage. */
	[[nodiscard]] constexpr uint64_t level() const noexcept
	{
		return static_cast<uint64_t>(level_numerator_ / detail::RATE_DENOMINATOR);
	}

	/** @brief Empty the level and unbind its timestamp baseline. */
	void reset() noexcept
	{
		level_numerator_ = 0;
		last_ns_ = 0;
		initialized_ = false;
	}

    private:
	uint64_t rate_bytes_per_sec_;		  ///< Exact configured whole-byte leak rate.
	uint64_t capacity_bytes_;		  ///< Exact maximum whole-byte level.
	detail::rate_numerator level_numerator_;  ///< Exact level over the shared denominator.
	uint64_t last_ns_;			  ///< Last accepted timestamp.
	bool initialized_;			  ///< Whether the timestamp baseline is bound.
};

// =============================================================================
// Sliding Window Rate Limiter
// =============================================================================

/**
 * @brief Exact event-count limit over the rolling interval (now - window, now].
 *
 * @par Thread Safety
 * One caller owns each window; the explicit memory resource outlives it.
 * Copy and move are disabled to preserve that storage ownership.
 *
 * @par Performance
 * Construction allocates one timestamp array. No-expiry and all-expired calls
 * are O(1); partial expiry binary-searches the FIFO in O(log quota). allow/reset
 * allocate nothing, lock nothing, and read no clock.
 */
class sliding_window {
    public:
	/**
	 * @brief Allocate the complete exact-window history before admission.
	 * @param max_count Maximum retained events; zero deliberately denies all events.
	 * @param window_ns Positive interval duration in nanoseconds.
	 * @param resource Non-null storage owner that outlives the window.
	 * @throws std::invalid_argument for zero duration or a null resource.
	 * @throws std::length_error for unrepresentable history geometry, before allocation.
	 * @throws std::bad_alloc when the resource cannot supply the complete history.
	 */
	sliding_window(uint64_t max_count, uint64_t window_ns, std::pmr::memory_resource *resource)
		: max_count_(max_count)
		, window_ns_(checked_duration_(window_ns))
		, timestamps_(history_capacity_(max_count), checked_resource_(resource))
		, positions_(timestamps_.size())
	{
	}
	/** @brief History storage has one owner. */
	sliding_window(const sliding_window &) = delete;
	/** @brief History ownership cannot be copied. */
	sliding_window &operator=(const sliding_window &) = delete;
	/** @brief Preserve the exact resource and history owner. */
	sliding_window(sliding_window &&) = delete;
	/** @brief History ownership cannot be replaced by moving. */
	sliding_window &operator=(sliding_window &&) = delete;

	/**
	 * @brief Expire old events and admit one event below the exact quota.
	 * @param now_ns Explicit monotonic observation; zero is an ordinary timestamp.
	 * @return True after admission; false for quota denial or backward time.
	 * Backward time leaves all state unchanged. A valid denied attempt advances
	 * the observation baseline and expires history, without adding an event.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool allow(uint64_t now_ns) noexcept
	{
		if (initialized_ && now_ns < last_ns_) {
			return false;
		}
		last_ns_ = now_ns;
		initialized_ = true;
		const auto retained = positions_.size();
		if (retained != 0 && expired_(now_ns, 0)) {
			if (expired_(now_ns, retained - 1u)) {
				positions_.commit_pop(retained);
			} else {
				// Monotonic timestamps make expiry a prefix predicate. The oldest
				// is expired and the newest is live; locate the first live event.
				std::size_t lower = 1u, upper = retained - 1u;
				while (lower < upper) {
					const auto middle = lower + (upper - lower) / 2u;
					if (expired_(now_ns, middle)) {
						lower = middle + 1u;
					} else {
						upper = middle;
					}
				}
				positions_.commit_pop(lower);
			}
		}
		if (positions_.size() >= max_count_) {
			return false;
		}
		timestamps_[positions_.producer_slot()] = now_ns;
		positions_.commit_push();
		return true;
	}

	/** @return Retained accepted events at the last valid observation; reads no clock. */
	[[nodiscard]] uint64_t count() const noexcept
	{
		return positions_.size();
	}
	/** @return Exact unused quota at the last valid observation. */
	[[nodiscard]] uint64_t remaining() const noexcept
	{
		return max_count_ - positions_.size();
	}
	/** @brief Clear logical history and unbind time in O(1), retaining the allocation. */
	void reset() noexcept
	{
		positions_.commit_pop(positions_.size());
		positions_.reset_empty();
		last_ns_ = 0u;
		initialized_ = false;
	}

    private:
	/** @return Positive duration; zero rejects before history allocation. */
	static uint64_t checked_duration_(uint64_t duration)
	{
		if (duration == 0u) {
			throw std::invalid_argument("sliding_window: window duration must be positive");
		}
		return duration;
	}
	/** @return Non-null explicit resource; no default-heap fallback is permitted. */
	static std::pmr::memory_resource *checked_resource_(std::pmr::memory_resource *resource)
	{
		if (resource == nullptr) {
			throw std::invalid_argument("sliding_window: memory resource must be non-null");
		}
		return resource;
	}
	/** @return Representable power-of-two timestamp extent without changing the logical quota. */
	static std::size_t history_capacity_(uint64_t quota)
	{
		constexpr auto MAXIMUM =
			std::numeric_limits<std::ptrdiff_t>::max() / static_cast<std::ptrdiff_t>(sizeof(uint64_t));
		constexpr auto CEILING = std::bit_floor(static_cast<std::size_t>(MAXIMUM));
		if (quota > CEILING) {
			throw std::length_error("sliding_window: timestamp history exceeds representable storage");
		}
		return std::bit_ceil(std::max<std::size_t>(2u, static_cast<std::size_t>(quota)));
	}
	/** @return Whether a retained timestamp lies outside the validated observation's interval. */
	[[nodiscard]] bool expired_(uint64_t now_ns, std::size_t offset) const noexcept
	{
		return now_ns - timestamps_[positions_.consumer_slot(offset)] >= window_ns_;
	}

	uint64_t max_count_;			 ///< Exact logical event quota.
	uint64_t window_ns_;			 ///< Positive duration, never added to an absolute timestamp.
	std::pmr::vector<uint64_t> timestamps_;	 ///< One construction-time circular history allocation.
	detail::work_queue_indices positions_;	 ///< Sole FIFO index authority, shared with work queues.
	uint64_t last_ns_{0};			 ///< Last valid observation, including a quota-denied call.
	bool initialized_{false};		 ///< Whether time is bound, including timestamp zero.
};

}  // namespace kinetum::algo
