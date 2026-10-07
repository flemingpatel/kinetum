// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file control.hpp
 * @brief Control theory algorithms.
 * @author Fleming Patel
 *
 * This is the canonical header-owned control-algorithm implementation for
 * installed SDK and platform consumers.
 *
 * Contains:
 * - pid_controller: Full PID with derivative and anti-windup
 *
 * Design principles:
 * - Header-owned so module images remain link-closed
 * - Zero dynamic allocation
 * - Configurable via params struct
 * - Anti-windup mechanisms
 *
 * The controller uses integral clamping with conditional integration and
 * optional derivative-on-measurement to avoid setpoint kick.
 */

#include <algorithm>
#include <cmath>
#include <stdexcept>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

// =============================================================================
// PID Controller
// =============================================================================

/**
 * @brief Full PID controller with derivative and anti-windup.
 *
 * Computes control output based on:
 * - Proportional (P): Immediate response to current error
 * - Integral (I): Eliminates steady-state error over time
 * - Derivative (D): Provides damping, reduces overshoot
 *
 * Features:
 * - Anti-windup via integral clamping + conditional integration
 * - Derivative-on-measurement option (avoids setpoint kick)
 * - Configurable output limits
 * - Zero allocation after construction
 *
 * @par Thread Safety
 * One control-loop owner mutates each controller. Concurrent use requires
 * external synchronization.
 *
 * @par Performance
 * This is a cold/control-loop primitive, not a packet-path operation. It
 * allocates nothing after construction but validates finite arithmetic on each
 * update.
 *
 * Usage:
 * @code
 * algo::pid_controller::params p{
 *     .kp = 2.0,
 *     .ki = 0.5,
 *     .kd = 0.1,
 *     .output_min = -1.0,
 *     .output_max = 1.0,
 *     .integral_max = 5.0,
 *     .derivative_on_measurement = true
 * };
 * algo::pid_controller pid(p, 0.01);  // setpoint = 0.01
 *
 * // In control loop:
 * double output = pid.compute(current_measurement, dt_seconds);
 * @endcode
 */
class pid_controller {
    public:
	/**
	 * @brief PID configuration parameters.
	 */
	struct params {
		double kp{1.0};			       ///< Proportional gain
		double ki{0.1};			       ///< Integral gain
		double kd{0.01};		       ///< Derivative gain
		double output_min{-1.0};	       ///< Output clamp (min)
		double output_max{1.0};		       ///< Output clamp (max)
		double integral_max{10.0};	       ///< Anti-windup limit for integral term
		bool derivative_on_measurement{true};  ///< Use measurement for D term (recommended)
	};

	/**
	 * @brief Construct with parameters and setpoint.
	 * @param p Finite configuration parameters with ordered output bounds and a
	 *        nonnegative integral bound.
	 * @param setpoint Finite target value for the controlled variable.
	 * @throws std::invalid_argument when the complete controller configuration
	 *         is outside its exact domain.
	 */
	explicit pid_controller(params p, double setpoint)
		: p_(p)
		, setpoint_(setpoint)
	{
		validate_configuration_(p_, setpoint_);
	}

	/**
	 * @brief Construct with individual gains (convenience).
	 * @param kp Finite proportional gain.
	 * @param ki Finite integral gain.
	 * @param setpoint Finite target value.
	 * @throws std::invalid_argument when any input is not finite.
	 */
	pid_controller(double kp, double ki, double setpoint)
		: pid_controller(params{kp, ki, 0.0, -1.0, 1.0, 100.0, true}, setpoint)
	{
	}

	/** @brief Copy one complete controller, including accumulated state. */
	pid_controller(const pid_controller &) = default;

	/**
	 * @brief Copy one complete controller, including accumulated state.
	 * @return This controller after replacement.
	 */
	pid_controller &operator=(const pid_controller &) = default;

	/** @brief Move one complete controller, including accumulated state. */
	pid_controller(pid_controller &&) = default;

	/**
	 * @brief Move one complete controller, including accumulated state.
	 * @return This controller after replacement.
	 */
	pid_controller &operator=(pid_controller &&) = default;

	/**
	 * @brief Compute control output given current measurement.
	 *
	 * Call this at regular intervals with the current process variable.
	 * The dt_seconds parameter should reflect actual elapsed time.
	 *
	 * @param measurement Finite current process variable (for example, a drop ratio).
	 * @param dt_seconds Finite positive elapsed time in seconds.
	 * @return Control output clamped to the configured output bounds.
	 * @throws std::invalid_argument when an input or derived control term is not
	 *         finite. The complete prior controller state is preserved.
	 */
	[[nodiscard]]
	KINETUM_ALWAYS_INLINE double compute(double measurement, double dt_seconds)
	{
		if (KINETUM_UNLIKELY(!std::isfinite(measurement) || !std::isfinite(dt_seconds) || dt_seconds <= 0.0)) {
			throw std::invalid_argument(
				"pid_controller: measurement and positive elapsed time must be finite");
		}

		const double error = setpoint_ - measurement;
		const double integral_delta = error * dt_seconds;
		const double unclamped_integral = integral_ + integral_delta;
		if (KINETUM_UNLIKELY(!std::isfinite(error) || !std::isfinite(integral_delta) ||
				     !std::isfinite(unclamped_integral))) {
			throw std::invalid_argument("pid_controller: integral calculation is not finite");
		}
		const double candidate_integral = std::clamp(unclamped_integral, -p_.integral_max, p_.integral_max);

		const double p_term = p_.kp * error;
		const double i_term = p_.ki * candidate_integral;

		double d_term = 0.0;
		if (KINETUM_LIKELY(!first_call_)) {
			if (p_.derivative_on_measurement) {
				const double d_measurement = (measurement - prev_measurement_) / dt_seconds;
				d_term = -p_.kd * d_measurement;
			} else {
				const double d_error = (error - prev_error_) / dt_seconds;
				d_term = p_.kd * d_error;
			}
		}

		const double unclamped_output = p_term + i_term + d_term;
		const double integral_output_delta = p_.ki * (candidate_integral - integral_);
		if (KINETUM_UNLIKELY(!std::isfinite(p_term) || !std::isfinite(i_term) || !std::isfinite(d_term) ||
				     !std::isfinite(unclamped_output) || !std::isfinite(integral_output_delta))) {
			throw std::invalid_argument("pid_controller: control output calculation is not finite");
		}

		const double output = std::clamp(unclamped_output, p_.output_min, p_.output_max);
		const bool integration_drives_high = unclamped_output > p_.output_max && integral_output_delta > 0.0;
		const bool integration_drives_low = unclamped_output < p_.output_min && integral_output_delta < 0.0;
		if (!integration_drives_high && !integration_drives_low) {
			integral_ = candidate_integral;
		}
		prev_measurement_ = measurement;
		prev_error_ = error;
		first_call_ = false;
		return output;
	}

	/**
	 * @brief Reset controller state.
	 *
	 * Call this when restarting control or after significant discontinuities.
	 */
	void reset() noexcept
	{
		integral_ = 0.0;
		prev_measurement_ = 0.0;
		prev_error_ = 0.0;
		first_call_ = true;
	}

	/**
	 * @brief Replace the finite target value.
	 * @param setpoint Finite new target.
	 * @throws std::invalid_argument when @p setpoint is not finite; prior state is preserved.
	 */
	void set_setpoint(double setpoint)
	{
		if (!std::isfinite(setpoint)) {
			throw std::invalid_argument("pid_controller: setpoint must be finite");
		}
		setpoint_ = setpoint;
	}

	/** @return Current finite target value. */
	[[nodiscard]] double setpoint() const noexcept
	{
		return setpoint_;
	}

	/** @return Current bounded integral state. */
	[[nodiscard]] double integral() const noexcept
	{
		return integral_;
	}

	/** @return Immutable validated controller parameters. */
	[[nodiscard]] const params &get_params() const noexcept
	{
		return p_;
	}

    private:
	/**
	 * @brief Validate one complete immutable controller configuration.
	 * @param p Candidate gains and bounds.
	 * @param setpoint Candidate target value.
	 * @throws std::invalid_argument when any value or bound relation is invalid.
	 */
	static void validate_configuration_(const params &p, double setpoint)
	{
		if (!std::isfinite(p.kp) || !std::isfinite(p.ki) || !std::isfinite(p.kd) ||
		    !std::isfinite(p.output_min) || !std::isfinite(p.output_max) || p.output_min >= p.output_max ||
		    !std::isfinite(p.integral_max) || p.integral_max < 0.0 || !std::isfinite(setpoint)) {
			throw std::invalid_argument("pid_controller: gains and ordered bounds must be finite");
		}
	}

	params p_;			///< Immutable validated gains and output bounds.
	double setpoint_;		///< Current finite target value.
	double integral_{0.0};		///< Current anti-windup-bounded integral state.
	double prev_measurement_{0.0};	///< Prior finite measurement for derivative-on-measurement.
	double prev_error_{0.0};	///< Prior finite error retained for reset observability.
	bool first_call_{true};		///< Whether no prior derivative baseline exists.
};

}  // namespace kinetum::algo
