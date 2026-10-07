// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file time.cpp
 * @brief Time utilities implementation.
 * @author Fleming Patel
 *
 * Implements time functions using C++ std::chrono library. The implementation
 * is straightforward and relies on the standard library for platform-specific
 * clock access.
 *
 * Hot Path Timing:
 * - cached_ns(): thread-local timestamp shared by one worker-loop turn
 * - update_cached_ns(): ordinary once-per-turn steady-clock refresh
 * - now_ns(): one additional post-health sample only after a real callback
 */

#include "src/common/time.hpp"

#include <chrono>
#include <exception>

namespace kinetum::common
{

/** Owner-thread timestamp refreshed once per worker-loop turn. */
thread_local uint64_t g_cached_ns = 0;

int64_t unix_time_ms() noexcept
{
	using namespace std::chrono;
	return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

uint64_t now_ns() noexcept
{
	using namespace std::chrono;
	auto count = duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
	// The runtime cannot represent a negative monotonic epoch.
	if (count < 0) {
		std::terminate();
	}
	return static_cast<uint64_t>(count);
}

uint64_t cached_ns() noexcept
{
	return g_cached_ns;
}

uint64_t update_cached_ns() noexcept
{
	g_cached_ns = now_ns();
	return g_cached_ns;
}

}  // namespace kinetum::common
