// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file thread_affinity.hpp
 * @brief Exact Linux CPU-affinity mechanism for runtime-owned threads.
 * @author Fleming Patel
 *
 * Packet workers and lifecycle services use one authority for binding the
 * calling thread to an exact logical CPU. The mechanism performs no topology
 * discovery and never filters or repairs an authored CPU identity.
 *
 * @par Thread Safety
 * Each call affects only the calling thread and is safe for concurrent use.
 *
 * @par Performance
 * Cold startup mechanism only; never reachable from packet execution.
 */

#include <cstdint>
#include <string_view>

#include "src/common/status.hpp"

namespace kinetum::dp
{

/**
 * @brief Bind the calling thread without allocating a diagnostic.
 *
 * @param cpu_core_id Required nonnegative logical CPU identity.
 * @return Zero on success or an errno value on validation, allocation, or
 *         Linux affinity rejection.
 */
[[nodiscard]] int bind_current_thread_to_cpu_raw(int32_t cpu_core_id) noexcept;

/**
 * @brief Bind the calling thread and return one bounded cold-path status.
 *
 * @param cpu_core_id Required nonnegative logical CPU identity.
 * @param owner Static owner description used only in failure diagnostics.
 * @return OK after exact affinity publication; non-OK otherwise.
 * @throws std::bad_alloc If a dynamic native-failure diagnostic cannot be allocated.
 * @throws std::length_error If that diagnostic exceeds its representable size.
 */
[[nodiscard]] kinetum::common::status bind_current_thread_to_cpu(int32_t cpu_core_id, std::string_view owner);

}  // namespace kinetum::dp
