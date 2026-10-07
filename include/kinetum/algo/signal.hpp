// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file signal.hpp
 * @brief Signal processing algorithms for telemetry and control.
 * @author Fleming Patel
 *
 * Contains:
 * - EWMA: Exponential Weighted Moving Average (noise reduction)
 * - Hysteresis: Dead-band for oscillation prevention
 * - Rate calculator: Explicit-time smoothed counter rates
 *
 * Used by owner-local telemetry and guardrails evidence processing.
 */

#include <cmath>
#include <cstdint>
#include <stdexcept>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

// =============================================================================
// EWMA (Exponential Weighted Moving Average)
// =============================================================================

/**
 * @brief Exponential Weighted Moving Average filter.
 *
 * Formula: ewma[t] = alpha * sample[t] + (1 - alpha) * ewma[t-1]
 *
 * Properties:
 * - alpha close to 1.0: Fast response, less smoothing
 * - alpha close to 0.0: Slow response, more smoothing
 * - Typical values: 0.1 (heavy smoothing) to 0.5 (light smoothing)
 *
 * @par Thread Safety
 * One control-path owner mutates each filter. Concurrent access requires
 * external synchronization.
 */
class ewma {
    public:
	/**
     * @brief Construct EWMA filter.
	 * @param alpha Finite smoothing factor in (0, 1]. Default: 0.3.
	 * @throws std::invalid_argument when @p alpha is outside its exact domain.
	 */
	explicit ewma(double alpha = 0.3)
		: alpha_(alpha)
		, value_(0.0)
		, initialized_(false)
	{
		if (!std::isfinite(alpha_) || alpha_ <= 0.0 || alpha_ > 1.0) {
			throw std::invalid_argument("ewma: alpha must be finite and in (0, 1]");
		}
	}

	/**
     * @brief Update with new sample.
	 * @param sample Finite new measurement.
	 * @return Smoothed value.
	 * @throws std::invalid_argument when @p sample is not finite; prior state is
	 *         preserved.
	 */
	[[nodiscard]]
	KINETUM_ALWAYS_INLINE double update(double sample)
	{
		if (KINETUM_UNLIKELY(!std::isfinite(sample))) {
			throw std::invalid_argument("ewma: sample must be finite");
		}
		if (KINETUM_UNLIKELY(!initialized_)) {
			value_ = sample;
			initialized_ = true;
		} else {
			value_ = alpha_ * sample + (1.0 - alpha_) * value_;
		}
		return value_;
	}

	/** @return Current finite smoothed value, or zero before initialization. */
	[[nodiscard]] constexpr double value() const noexcept
	{
		return value_;
	}

	/** @return True after at least one valid sample. */
	[[nodiscard]] constexpr bool initialized() const noexcept
	{
		return initialized_;
	}

	/** @brief Clear all accumulated sample state. */
	constexpr void reset() noexcept
	{
		value_ = 0.0;
		initialized_ = false;
	}

	/** @return Exact validated smoothing factor. */
	[[nodiscard]] constexpr double alpha() const noexcept
	{
		return alpha_;
	}

    private:
	double alpha_;	    ///< Exact smoothing factor in `(0, 1]`.
	double value_;	    ///< Current finite smoothed value.
	bool initialized_;  ///< Whether one valid sample established the baseline.
};

// =============================================================================
// Hysteresis (Dead-Band Filter)
// =============================================================================

/**
 * @brief Hysteresis filter for oscillation prevention.
 *
 * Creates a dead-band around a threshold:
 * - Only switch to HIGH when value > threshold + band/2
 * - Only switch to LOW when value < threshold - band/2
 *
 * This prevents rapid switching when value hovers near threshold.
 *
 * @par Thread Safety
 * One control-path owner mutates each filter. Concurrent access requires
 * external synchronization.
 */
class hysteresis {
    public:
	/**
     * @brief Construct hysteresis filter.
	 * @param threshold Finite center threshold.
	 * @param band_width Finite nonnegative width of the complete dead band.
	 * @throws std::invalid_argument when either input or a derived boundary is
	 *         not finite, or when @p band_width is negative.
	 */
	hysteresis(double threshold, double band_width)
		: threshold_(threshold)
		, half_band_(band_width / 2.0)
		, high_state_(false)
	{
		if (!std::isfinite(threshold_) || !std::isfinite(band_width) || band_width < 0.0 ||
		    !std::isfinite(threshold_ - half_band_) || !std::isfinite(threshold_ + half_band_)) {
			throw std::invalid_argument("hysteresis: threshold and nonnegative band must be finite");
		}
	}

	/**
     * @brief Update with new value.
	 * @param value Finite current measurement.
	 * @return true if in HIGH state, false if in LOW state.
	 * @throws std::invalid_argument when @p value is not finite; prior state is
	 *         preserved.
	 */
	[[nodiscard]]
	KINETUM_ALWAYS_INLINE bool update(double value)
	{
		if (KINETUM_UNLIKELY(!std::isfinite(value))) {
			throw std::invalid_argument("hysteresis: sample must be finite");
		}
		if (high_state_) {
			// Currently HIGH: need to drop below lower threshold to go LOW
			if (value < threshold_ - half_band_) {
				high_state_ = false;
			}
		} else {
			// Currently LOW: need to rise above upper threshold to go HIGH
			if (value > threshold_ + half_band_) {
				high_state_ = true;
			}
		}
		return high_state_;
	}

	/** @return Current high/low state. */
	[[nodiscard]] constexpr bool is_high() const noexcept
	{
		return high_state_;
	}

	/** @brief Reset to the low state without changing thresholds. */
	constexpr void reset() noexcept
	{
		high_state_ = false;
	}

	/** @return Exact validated center threshold. */
	[[nodiscard]] constexpr double threshold() const noexcept
	{
		return threshold_;
	}

    private:
	double threshold_;  ///< Exact center threshold.
	double half_band_;  ///< Half of the validated nonnegative band width.
	bool high_state_;   ///< Current retained threshold state.
};

// =============================================================================
// Rate Calculator
// =============================================================================

/**
 * @brief Calculate rate from counter deltas.
 *
 * Counter or timestamp regression starts a fresh baseline and emits zero for
 * the unmeasurable interval. Timestamp zero is a valid baseline.
 *
 * @par Thread Safety
 * One control-path owner mutates each calculator. Concurrent access requires
 * external synchronization.
 */
class rate_calculator {
    public:
	/**
     * @brief Construct rate calculator.
	 * @param ewma_alpha Finite smoothing factor in (0, 1].
	 * @throws std::invalid_argument when @p ewma_alpha is outside its domain.
	 */
	explicit rate_calculator(double ewma_alpha = 0.3)
		: smoother_(ewma_alpha)
		, last_count_(0)
		, last_time_ns_(0)
		, rate_(0.0)
		, initialized_(false)
	{
	}

	/**
     * @brief Update with new counter value.
     * @param count Current counter value
     * @param time_ns Current timestamp (nanoseconds)
     * @return Smoothed rate (units per second)
     */
	[[nodiscard]] double update(uint64_t count, uint64_t time_ns)
	{
		if (!initialized_) {
			// First sample: initialize
			last_count_ = count;
			last_time_ns_ = time_ns;
			initialized_ = true;
			return 0.0;
		}

		if (time_ns < last_time_ns_ || count < last_count_) {
			// A timestamp or counter regression gives no exact interval. Establish
			// a fresh baseline rather than attributing post-reset work to an
			// unknowable duration.
			last_count_ = count;
			last_time_ns_ = time_ns;
			smoother_.reset();
			rate_ = 0.0;
			return rate_;
		}

		uint64_t delta_time = time_ns - last_time_ns_;
		if (delta_time == 0)
			return rate_;

		const uint64_t delta_count = count - last_count_;

		// Calculate instantaneous rate (per second)
		double instant_rate = static_cast<double>(delta_count) * 1e9 / static_cast<double>(delta_time);

		// Smooth and store
		rate_ = smoother_.update(instant_rate);

		last_count_ = count;
		last_time_ns_ = time_ns;

		return rate_;
	}

	/** @return Current finite smoothed rate, or zero before a complete interval. */
	[[nodiscard]] double rate() const noexcept
	{
		return rate_;
	}

	/** @brief Clear baseline, smoothing, and current rate. */
	void reset() noexcept
	{
		smoother_.reset();
		last_count_ = 0;
		last_time_ns_ = 0;
		rate_ = 0.0;
		initialized_ = false;
	}

    private:
	ewma smoother_;		 ///< Explicit finite-rate smoothing owner.
	uint64_t last_count_;	 ///< Last accepted cumulative counter.
	uint64_t last_time_ns_;	 ///< Last accepted caller timestamp.
	double rate_;		 ///< Current finite smoothed rate.
	bool initialized_;	 ///< Whether one baseline sample has been accepted.
};

}  // namespace kinetum::algo
