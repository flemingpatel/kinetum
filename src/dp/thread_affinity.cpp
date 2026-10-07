// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file thread_affinity.cpp
 * @brief Exact Linux CPU-affinity mechanism implementation.
 * @author Fleming Patel
 */

#include "src/dp/thread_affinity.hpp"

#include <cerrno>
#include <string>

#include "src/common/linux_cpu_set.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;

int bind_current_thread_to_cpu_raw(int32_t cpu_core_id) noexcept
{
	common::linux_cpu_set set;
	const int construction_result = common::linux_cpu_set::single_cpu(cpu_core_id, set);
	if (construction_result != 0) {
		return construction_result;
	}
	return set.apply_to_current_thread();
}

status bind_current_thread_to_cpu(int32_t cpu_core_id, std::string_view owner)
{
	if (cpu_core_id < 0) {
		return status(status_code::INVALID_ARGUMENT, std::string(owner) + " CPU identity is negative");
	}
	const int result = bind_current_thread_to_cpu_raw(cpu_core_id);
	if (result == ENOMEM) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      "failed to allocate exact " + std::string(owner) + " CPU affinity set");
	}
	if (result == EOVERFLOW) {
		return status(status_code::OUT_OF_RANGE,
			      std::string(owner) + " CPU identity exceeds the platform representation");
	}
	if (result != 0) {
		return status(status_code::FAILED_PRECONDITION,
			      "failed to bind " + std::string(owner) + " to CPU " + std::to_string(cpu_core_id) +
				      " (sched_setaffinity=" + std::to_string(result) + ")");
	}
	return status::ok();
}

}  // namespace kinetum::dp
