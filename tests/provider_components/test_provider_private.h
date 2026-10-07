// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file test_provider_private.h
 * @brief Deliberate private dependency API for provider-loader conformance.
 * @author Fleming Patel
 */

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/** @return Fixed marker proving that the component resolved its private dependency. */
uint32_t kinetum_test_provider_private_marker(void);

#if defined(__cplusplus)
}
#endif
