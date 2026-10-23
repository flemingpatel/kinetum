// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file numa_test_support.hpp
 * @brief Native memory-node prerequisites shared by allocation-owner fixtures.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <algorithm>

#include "src/quark/host_probe.hpp"

namespace kinetum::test
{

/**
 * @brief Require a live process-allowed memory node before constructing native ownership.
 * @return The first proved node, or -1 after recording the failed prerequisite.
 */
[[nodiscard]] inline int32_t required_memory_numa_node()
{
	const auto host = quark::probe_host();
	if (!host.valid || host.memory_numa_nodes.empty()) {
		ADD_FAILURE() << "native allocation fixture requires a proved process-allowed memory node";
		return -1;
	}
	return host.memory_numa_nodes.front();
}

/**
 * @brief Require one allowed CPU whose proved node also permits memory allocation.
 * @return A complete native worker placement, or invalid fields after recording failure.
 */
[[nodiscard]] inline quark::host_cpu required_worker_cpu()
{
	const auto host = quark::probe_host();
	if (host.valid) {
		for (const auto &cpu : host.cpus) {
			if (cpu.numa_node >= 0 && std::binary_search(host.memory_numa_nodes.begin(),
								     host.memory_numa_nodes.end(), cpu.numa_node)) {
				return cpu;
			}
		}
	}
	ADD_FAILURE() << "native worker fixture requires an allowed CPU and memory on its proved node";
	return {};
}

}  // namespace kinetum::test
