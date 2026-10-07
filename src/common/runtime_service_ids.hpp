// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_service_ids.hpp
 * @brief Deterministic identities for plan-owned runtime services.
 * @author Fleming Patel
 *
 * Gluon emits runtime service placements and later admission/lifecycle
 * components consume those records. This header is the single authority for
 * the stable coordinator identity and NUMA-local lifecycle-executor identity
 * grammar so independently implemented producers and validators cannot drift.
 */

#include <cstdint>
#include <string>
#include <string_view>

namespace kinetum::common::runtime_services
{

/** @brief Stable identity of the sole dataplane epoch-transition coordinator. */
inline constexpr std::string_view EPOCH_TRANSITION_COORDINATOR_ID = "epoch_transition_coordinator";

/**
 * @brief Build the deterministic lifecycle-executor identity for a NUMA node.
 *
 * @param numa_node Nonnegative NUMA node owned by the executor.
 * @return Service ID in `config_lifecycle_executor_numa_<numa_node>` form.
 */
[[nodiscard]] inline std::string make_lifecycle_executor_id(int32_t numa_node)
{
	const auto NUMA_SUFFIX = std::to_string(numa_node);
	return "config_lifecycle_executor_numa_" + NUMA_SUFFIX;
}

}  // namespace kinetum::common::runtime_services
