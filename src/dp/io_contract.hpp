// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file io_contract.hpp
 * @brief Provider-neutral dataplane I/O identity bounds.
 * @author Fleming Patel
 *
 * The module SDK owns the wire-visible logical-port width. Runtime compilers
 * and packet stages consume that one authority without importing any native
 * provider header or maintaining a parallel capacity constant.
 */

#include <cstddef>

#include <kinetum/kinetum_sdk.h>

namespace kinetum::dp
{

/** Maximum number of logical ports representable by the module/runtime ABI. */
inline constexpr std::size_t MAX_LOGICAL_PORTS = KINETUM_MAX_PORTS;

static_assert(MAX_LOGICAL_PORTS > 0);
static_assert(MAX_LOGICAL_PORTS <= static_cast<std::size_t>(KINETUM_PORT_DROP));

}  // namespace kinetum::dp
