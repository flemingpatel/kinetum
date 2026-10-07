// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_signal_control.cpp
 * @brief Public signal-smoothing and control-algorithm tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <limits>
#include <stdexcept>

#include <kinetum/algo/control.hpp>
#include <kinetum/algo/signal.hpp>

namespace kinetum::algo
{
namespace
{

/** @brief An EWMA initializes from its first sample without fabricated history. */
TEST(algo_ewma, first_sample_passthrough)
{
	ewma smoother(0.3);
	EXPECT_DOUBLE_EQ(smoother.update(100.0), 100.0);
}

/** @brief EWMA blending follows the authored alpha exactly. */
TEST(algo_ewma, blending_formula)
{
	ewma smoother(0.3);
	(void)smoother.update(100.0);
	EXPECT_DOUBLE_EQ(smoother.update(200.0), 130.0);
}

/** @brief Alpha one follows each new sample without smoothing. */
TEST(algo_ewma, alpha_one_no_smoothing)
{
	ewma smoother(1.0);
	(void)smoother.update(100.0);
	EXPECT_DOUBLE_EQ(smoother.update(200.0), 200.0);
}

/** @brief A small positive alpha retains the expected heavy smoothing. */
TEST(algo_ewma, small_alpha_heavy_smoothing)
{
	ewma smoother(0.001);
	(void)smoother.update(100.0);
	EXPECT_NEAR(smoother.update(200.0), 100.1, 0.01);
}

/** @brief Every positive finite alpha is retained exactly and malformed alpha rejects. */
TEST(algo_ewma, alpha_admission_is_exact_without_clamping)
{
	constexpr double SMALL_ALPHA = 0.000001;
	ewma exact(SMALL_ALPHA);
	EXPECT_DOUBLE_EQ(exact.alpha(), SMALL_ALPHA);
	EXPECT_THROW((ewma(0.0)), std::invalid_argument);
	EXPECT_THROW((ewma(-0.1)), std::invalid_argument);
	EXPECT_THROW((ewma(1.1)), std::invalid_argument);
	EXPECT_THROW((ewma(std::numeric_limits<double>::infinity())), std::invalid_argument);
	EXPECT_THROW((ewma(std::numeric_limits<double>::quiet_NaN())), std::invalid_argument);
}

/** @brief A non-finite EWMA sample rejects before changing accumulated state. */
TEST(algo_ewma, malformed_sample_preserves_complete_state)
{
	ewma smoother(0.5);
	EXPECT_DOUBLE_EQ(smoother.update(10.0), 10.0);
	EXPECT_THROW((void)smoother.update(std::numeric_limits<double>::quiet_NaN()), std::invalid_argument);
	EXPECT_DOUBLE_EQ(smoother.value(), 10.0);
	EXPECT_TRUE(smoother.initialized());
}

/** @brief Reset removes all EWMA history. */
TEST(algo_ewma, reset_clears_state)
{
	ewma smoother(0.5);
	(void)smoother.update(100.0);
	(void)smoother.update(200.0);
	smoother.reset();
	EXPECT_DOUBLE_EQ(smoother.update(50.0), 50.0);
}

/** @brief PID proportional output follows setpoint error. */
TEST(algo_pid, proportional_response)
{
	pid_controller::params params;
	params.kp = 1.0;
	params.ki = 0.0;
	params.kd = 0.0;
	params.output_min = -100.0;
	params.output_max = 100.0;
	pid_controller controller(params, 100.0);
	EXPECT_DOUBLE_EQ(controller.compute(90.0, 1.0), 10.0);
}

/** @brief PID integral output accumulates error across samples. */
TEST(algo_pid, integral_accumulation)
{
	pid_controller::params params;
	params.kp = 0.0;
	params.ki = 0.1;
	params.kd = 0.0;
	params.output_min = -100.0;
	params.output_max = 100.0;
	params.integral_max = 100.0;
	pid_controller controller(params, 100.0);
	(void)controller.compute(90.0, 1.0);
	EXPECT_DOUBLE_EQ(controller.compute(90.0, 1.0), 2.0);
}

/** @brief PID output never exceeds its configured bounds. */
TEST(algo_pid, output_clamping)
{
	pid_controller::params params;
	params.kp = 100.0;
	params.ki = 0.0;
	params.kd = 0.0;
	params.output_min = -1.0;
	params.output_max = 1.0;
	pid_controller controller(params, 100.0);
	EXPECT_DOUBLE_EQ(controller.compute(0.0, 1.0), 1.0);
}

/** @brief Saturation never moves integral state outside its configured bound. */
TEST(algo_pid, conditional_integration_commits_only_when_it_reduces_saturation)
{
	pid_controller::params params;
	params.kp = 100.0;
	params.ki = 1.0;
	params.kd = 0.0;
	params.output_min = -1.0;
	params.output_max = 1.0;
	params.integral_max = 10.0;
	pid_controller controller(params, 100.0);

	EXPECT_DOUBLE_EQ(controller.compute(0.0, 1.0), 1.0);
	EXPECT_DOUBLE_EQ(controller.integral(), 0.0);
	controller.set_setpoint(-100.0);
	EXPECT_DOUBLE_EQ(controller.compute(0.0, 1.0), -1.0);
	EXPECT_DOUBLE_EQ(controller.integral(), 0.0);
}

/** @brief Invalid PID configuration and samples reject without state mutation. */
TEST(algo_pid, numeric_admission_is_finite_transactional_and_ordered)
{
	pid_controller::params malformed;
	malformed.output_min = 1.0;
	malformed.output_max = 1.0;
	EXPECT_THROW((pid_controller(malformed, 0.0)), std::invalid_argument);
	malformed.output_max = 2.0;
	malformed.integral_max = -1.0;
	EXPECT_THROW((pid_controller(malformed, 0.0)), std::invalid_argument);

	pid_controller::params valid;
	valid.kp = 0.0;
	valid.ki = 1.0;
	valid.kd = 0.0;
	valid.output_min = -100.0;
	valid.output_max = 100.0;
	valid.integral_max = 100.0;
	pid_controller controller(valid, 10.0);
	EXPECT_DOUBLE_EQ(controller.compute(9.0, 1.0), 1.0);
	const double integral = controller.integral();
	EXPECT_THROW((void)controller.compute(std::numeric_limits<double>::quiet_NaN(), 1.0), std::invalid_argument);
	EXPECT_THROW((void)controller.compute(9.0, 0.0), std::invalid_argument);
	EXPECT_THROW(controller.set_setpoint(std::numeric_limits<double>::infinity()), std::invalid_argument);
	EXPECT_DOUBLE_EQ(controller.integral(), integral);
	EXPECT_DOUBLE_EQ(controller.setpoint(), 10.0);
}

/** @brief Reset clears all PID integral and derivative history. */
TEST(algo_pid, reset_clears_state)
{
	pid_controller::params params;
	params.kp = 0.0;
	params.ki = 1.0;
	params.kd = 0.0;
	params.output_min = -100.0;
	params.output_max = 100.0;
	pid_controller controller(params, 100.0);
	(void)controller.compute(90.0, 1.0);
	(void)controller.compute(90.0, 1.0);
	controller.reset();
	EXPECT_DOUBLE_EQ(controller.compute(90.0, 1.0), 10.0);
}

/** @brief Hysteresis changes state only outside its dead band. */
TEST(algo_hysteresis, prevents_oscillation)
{
	hysteresis guard(100.0, 20.0);
	EXPECT_FALSE(guard.update(50.0));
	EXPECT_FALSE(guard.update(105.0));
	EXPECT_TRUE(guard.update(115.0));
	EXPECT_TRUE(guard.update(95.0));
	EXPECT_FALSE(guard.update(85.0));
}

/** @brief Reset returns a hysteresis guard to its low state. */
TEST(algo_hysteresis, reset_to_low)
{
	hysteresis guard(100.0, 20.0);
	(void)guard.update(200.0);
	EXPECT_TRUE(guard.update(100.0));
	guard.reset();
	EXPECT_FALSE(guard.update(100.0));
}

/** @brief Hysteresis validates its complete numeric domain before state mutation. */
TEST(algo_hysteresis, malformed_configuration_and_sample_reject_exactly)
{
	EXPECT_THROW((hysteresis(1.0, -0.1)), std::invalid_argument);
	EXPECT_THROW((hysteresis(std::numeric_limits<double>::infinity(), 1.0)), std::invalid_argument);
	hysteresis guard(1.0, 0.5);
	EXPECT_TRUE(guard.update(2.0));
	EXPECT_THROW((void)guard.update(std::numeric_limits<double>::quiet_NaN()), std::invalid_argument);
	EXPECT_TRUE(guard.is_high());
}

/** @brief Zero timestamps and counter resets establish exact rate baselines. */
TEST(algo_rate_calculator, zero_time_and_regressions_never_fabricate_an_interval)
{
	rate_calculator calculator(1.0);
	EXPECT_DOUBLE_EQ(calculator.update(100u, 0u), 0.0);
	EXPECT_DOUBLE_EQ(calculator.update(200u, 1'000'000'000u), 100.0);

	EXPECT_DOUBLE_EQ(calculator.update(10u, 2'000'000'000u), 0.0);
	EXPECT_DOUBLE_EQ(calculator.update(110u, 3'000'000'000u), 100.0);

	EXPECT_DOUBLE_EQ(calculator.update(120u, 2'500'000'000u), 0.0);
	EXPECT_DOUBLE_EQ(calculator.update(220u, 3'500'000'000u), 100.0);
}

}  // namespace
}  // namespace kinetum::algo
