// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file control_plane_contract.hpp
 * @brief Shared bounded Control Plane wire and CLI constants.
 * @author Fleming Patel
 *
 * These constants define representation bounds shared by the CP producer,
 * operator CLI, and tests. They authorize no mutation, retry, or pagination
 * progress; the owning CP store and exact response validators retain those
 * decisions.
 *
 * @par Thread Safety
 * Immutable compile-time values are safe for concurrent use.
 */

#include <cstddef>
#include <cstdint>

namespace kinetum::common
{

/** @brief Maximum snapshots carried by one bounded ListSnapshots response. */
inline constexpr uint32_t MAX_SNAPSHOT_LIST_PAGE_SIZE = 256u;

/** @brief Page size explicitly authored by the operator CLI. */
inline constexpr uint32_t DEFAULT_SNAPSHOT_LIST_PAGE_SIZE = 100u;

/** @brief Maximum bytes in one stateless snapshot-list continuation token. */
inline constexpr std::size_t MAX_SNAPSHOT_LIST_PAGE_TOKEN_BYTES = 640u;

static_assert(DEFAULT_SNAPSHOT_LIST_PAGE_SIZE > 0u, "default snapshot-list page size must be positive");
static_assert(DEFAULT_SNAPSHOT_LIST_PAGE_SIZE <= MAX_SNAPSHOT_LIST_PAGE_SIZE,
	      "default snapshot-list page size must fit the wire bound");

}  // namespace kinetum::common
