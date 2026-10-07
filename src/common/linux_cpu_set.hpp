// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file linux_cpu_set.hpp
 * @brief Dynamically sized Linux CPU-affinity set ownership.
 * @author Fleming Patel
 *
 * Linux CPU identities are sparse kernel indices, not a fixed cpu_set_t
 * range. This cold mechanism owns CPU_ALLOC storage, grows affinity queries
 * until the kernel accepts their extent, and applies an exact set to the
 * calling thread without introducing a platform-specific CPU ceiling.
 *
 * @par Thread Safety
 * One owner mutates a set. Distinct sets are independent and may be used by
 * concurrent cold-path threads.
 *
 * @par Performance
 * Allocation and affinity syscalls are startup/test mechanisms and are never
 * reachable from packet execution.
 */

#include <sched.h>

#include <cstddef>
#include <cstdint>
#include <memory>

namespace kinetum::common
{

/** @brief Move-only owner of one dynamically sized Linux CPU set. */
class linux_cpu_set final {
    public:
	/** @brief Construct an empty set with no allocated mask. */
	linux_cpu_set() noexcept = default;
	/** @brief CPU-set ownership cannot be copied. */
	linux_cpu_set(const linux_cpu_set &) = delete;
	/** @brief CPU-set ownership cannot be copy-assigned. */
	linux_cpu_set &operator=(const linux_cpu_set &) = delete;
	/**
	 * @brief Transfer one complete allocated mask.
	 *
	 * @param other Sole source owner, left empty after transfer.
	 */
	linux_cpu_set(linux_cpu_set &&other) noexcept = default;
	/**
	 * @brief Replace this mask with one complete transferred mask.
	 *
	 * @param other Sole source owner, left empty after transfer.
	 * @return This replacement owner.
	 */
	linux_cpu_set &operator=(linux_cpu_set &&other) noexcept = default;
	/** @brief Release the exact CPU_ALLOC storage. */
	~linux_cpu_set() = default;

	/**
	 * @brief Construct a set containing one exact logical CPU.
	 *
	 * @param cpu_core_id Required nonnegative Linux logical CPU identity.
	 * @param[out] output Replaced with the exact one-bit set on success.
	 * @return Zero on success or an errno value on validation/allocation failure.
	 */
	[[nodiscard]] static int single_cpu(int32_t cpu_core_id, linux_cpu_set &output) noexcept;

	/**
	 * @brief Capture the calling thread's complete current affinity mask.
	 *
	 * The query begins with the libc fixed-mask extent and doubles only when
	 * Linux reports that the buffer is too small. No sysconf count is treated
	 * as an identity bound.
	 *
	 * @param[out] output Replaced with the exact accepted mask on success.
	 * @return Zero on success or an errno value on query/allocation failure.
	 */
	[[nodiscard]] static int capture_current_thread(linux_cpu_set &output) noexcept;

	/**
	 * @brief Apply this exact mask to the calling thread.
	 *
	 * @return Zero on success or an errno value on incomplete state/kernel
	 *         rejection.
	 */
	[[nodiscard]] int apply_to_current_thread() const noexcept;

	/**
	 * @brief Test one representable logical CPU bit.
	 *
	 * @param cpu_core_id Candidate nonnegative logical CPU identity.
	 * @return true only when the identity is within this mask and selected.
	 */
	[[nodiscard]] bool contains(int32_t cpu_core_id) const noexcept;

	/** @return Exact logical-CPU capacity represented by this mask. */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return cpu_capacity_;
	}

	/** @return true when this owner contains an allocated mask. */
	[[nodiscard]] explicit operator bool() const noexcept
	{
		return set_ != nullptr;
	}

    private:
	/** @brief CPU_FREE deleter paired with CPU_ALLOC storage. */
	struct cpu_set_deleter {
		/**
		 * @brief Release one allocation; null is accepted.
		 *
		 * @param set Exact CPU_ALLOC result to release, or null.
		 */
		void operator()(cpu_set_t *set) const noexcept;
	};

	/**
	 * @brief Allocate and zero one exact representable CPU extent.
	 *
	 * @param cpu_capacity Nonzero logical-CPU bit capacity to represent.
	 * @param[out] output Replaced with the empty allocated set on success.
	 * @return Zero on success or an errno value on validation/allocation failure.
	 */
	[[nodiscard]] static int allocate_(std::size_t cpu_capacity, linux_cpu_set &output) noexcept;

	std::unique_ptr<cpu_set_t, cpu_set_deleter> set_;  ///< Exact CPU_ALLOC storage.
	std::size_t set_bytes_{0};			   ///< Exact kernel syscall extent.
	std::size_t cpu_capacity_{0};			   ///< Exact representable logical-CPU count.
};

}  // namespace kinetum::common
