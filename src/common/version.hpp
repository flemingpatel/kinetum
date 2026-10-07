// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file version.hpp
 * @brief Compile-time version string.
 * @author Fleming Patel
 *
 * Owned host binaries consume this identity for:
 *   - bundle metadata
 *   - diagnostics
 *   - reproducibility tracking
 *
 * The version macro is injected by CMake from the top-level VERSION file.
 */

#ifndef KINETUM_VERSION_STR
#error "KINETUM_VERSION_STR must be supplied by the owning CMake target"
#endif

namespace kinetum::common
{

/** @brief Exact product version injected from the repository VERSION authority. */
inline constexpr const char *KINETUM_VERSION_STRING = KINETUM_VERSION_STR;

}  // namespace kinetum::common
