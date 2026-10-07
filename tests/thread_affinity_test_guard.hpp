// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file thread_affinity_test_guard.hpp
 * @brief Test-only ownership of a calling thread's original Linux CPU affinity.
 * @author Fleming Patel
 *
 * Native runtime-service tests deliberately exercise the production
 * coordinator binding path, which changes the calling thread's affinity.
 * This guard captures that process-visible test state once and restores it on
 * every exit so one test cannot constrain later tests.
 */

#include <cstdint>
#include <exception>
#include <vector>

#include "src/common/linux_cpu_set.hpp"

namespace kinetum::test
{

/** @brief Restore the calling thread's exact captured affinity at scope exit or fail stop. */
class thread_affinity_restore_guard final {
    public:
	/** @brief Capture the calling thread's current Linux affinity mask. */
	thread_affinity_restore_guard() noexcept
	{
		valid_ = common::linux_cpu_set::capture_current_thread(original_) == 0;
	}

	/** @brief Affinity restoration ownership cannot be copied. */
	thread_affinity_restore_guard(const thread_affinity_restore_guard &) = delete;
	/** @brief Affinity restoration ownership cannot be copy-assigned. */
	thread_affinity_restore_guard &operator=(const thread_affinity_restore_guard &) = delete;
	/** @brief Affinity restoration ownership cannot be moved between threads. */
	thread_affinity_restore_guard(thread_affinity_restore_guard &&) = delete;
	/** @brief Affinity restoration ownership cannot be move-assigned. */
	thread_affinity_restore_guard &operator=(thread_affinity_restore_guard &&) = delete;

	/** @brief Restore the captured affinity mask when capture succeeded, or fail stop. */
	~thread_affinity_restore_guard() noexcept
	{
		if (valid_ && original_.apply_to_current_thread() != 0) {
			std::terminate();
		}
	}

	/**
	 * @brief Return the exact captured process-allowed CPU identities.
	 *
	 * @return Sorted logical CPU IDs, or an empty vector when capture failed.
	 */
	[[nodiscard]] std::vector<int32_t> allowed_cores() const
	{
		std::vector<int32_t> cores;
		if (!valid_) {
			return cores;
		}
		for (std::size_t index = 0; index < original_.capacity(); ++index) {
			const auto core = static_cast<int32_t>(index);
			if (original_.contains(core)) {
				cores.push_back(core);
			}
		}
		return cores;
	}

    private:
	common::linux_cpu_set original_;  ///< Calling-thread affinity captured at construction.
	bool valid_{false};		  ///< Whether original_ may be restored and inspected.
};

}  // namespace kinetum::test
