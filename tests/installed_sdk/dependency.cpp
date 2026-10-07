// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dependency.cpp
 * @brief Export-capable shared module dependency with consumed inline storage.
 * @author Fleming Patel
 */

/** ODR-used state must not gain process-lifetime GNU-unique ownership. */
inline unsigned kinetum_sdk_dependency_value = 0u;

/** @brief Export dependency state under Kinetum::ModuleDependency policy. */
extern "C" unsigned *kinetum_sdk_dependency_state(void)
{
	return &kinetum_sdk_dependency_value;
}
