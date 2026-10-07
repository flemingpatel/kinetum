// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file linux_cpu_set.cpp
 * @brief Dynamically sized Linux CPU-affinity implementation.
 * @author Fleming Patel
 */

#include "src/common/linux_cpu_set.hpp"

#include <cerrno>
#include <limits>
#include <utility>

namespace kinetum::common
{

void linux_cpu_set::cpu_set_deleter::operator()(cpu_set_t *set) const noexcept
{
	if (set != nullptr) {
		CPU_FREE(set);
	}
}

int linux_cpu_set::allocate_(std::size_t cpu_capacity, linux_cpu_set &output) noexcept
{
	constexpr std::size_t MAX_REPRESENTABLE_CPU_COUNT =
		static_cast<std::size_t>(std::numeric_limits<int32_t>::max()) + 1u;
	if (cpu_capacity == 0u || cpu_capacity > MAX_REPRESENTABLE_CPU_COUNT) {
		return EOVERFLOW;
	}

	linux_cpu_set candidate;
	candidate.set_.reset(CPU_ALLOC(cpu_capacity));
	if (candidate.set_ == nullptr) {
		return ENOMEM;
	}
	candidate.set_bytes_ = CPU_ALLOC_SIZE(cpu_capacity);
	candidate.cpu_capacity_ = cpu_capacity;
	CPU_ZERO_S(candidate.set_bytes_, candidate.set_.get());
	output = std::move(candidate);
	return 0;
}

int linux_cpu_set::single_cpu(int32_t cpu_core_id, linux_cpu_set &output) noexcept
{
	if (cpu_core_id < 0) {
		return EINVAL;
	}
	linux_cpu_set candidate;
	const std::size_t cpu_capacity = static_cast<std::size_t>(cpu_core_id) + 1u;
	const int allocation_result = allocate_(cpu_capacity, candidate);
	if (allocation_result != 0) {
		return allocation_result;
	}
	CPU_SET_S(static_cast<std::size_t>(cpu_core_id), candidate.set_bytes_, candidate.set_.get());
	output = std::move(candidate);
	return 0;
}

int linux_cpu_set::capture_current_thread(linux_cpu_set &output) noexcept
{
	constexpr std::size_t MAX_REPRESENTABLE_CPU_COUNT =
		static_cast<std::size_t>(std::numeric_limits<int32_t>::max()) + 1u;
	std::size_t cpu_capacity = static_cast<std::size_t>(CPU_SETSIZE);
	for (;;) {
		linux_cpu_set candidate;
		const int allocation_result = allocate_(cpu_capacity, candidate);
		if (allocation_result != 0) {
			return allocation_result;
		}
		if (::sched_getaffinity(0, candidate.set_bytes_, candidate.set_.get()) == 0) {
			output = std::move(candidate);
			return 0;
		}
		const int query_error = errno;
		if (query_error != EINVAL) {
			return query_error;
		}
		if (cpu_capacity > MAX_REPRESENTABLE_CPU_COUNT / 2u) {
			return EOVERFLOW;
		}
		cpu_capacity *= 2u;
	}
}

int linux_cpu_set::apply_to_current_thread() const noexcept
{
	if (set_ == nullptr || set_bytes_ == 0u || cpu_capacity_ == 0u) {
		return EINVAL;
	}
	if (::sched_setaffinity(0, set_bytes_, set_.get()) != 0) {
		return errno;
	}
	return 0;
}

bool linux_cpu_set::contains(int32_t cpu_core_id) const noexcept
{
	return cpu_core_id >= 0 && static_cast<std::size_t>(cpu_core_id) < cpu_capacity_ && set_ != nullptr &&
	       CPU_ISSET_S(static_cast<std::size_t>(cpu_core_id), set_bytes_, set_.get()) != 0;
}

}  // namespace kinetum::common
