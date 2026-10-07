// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_private.c
 * @brief Private dependency implementation for provider-loader conformance.
 * @author Fleming Patel
 */

#include "tests/provider_components/test_provider_private.h"

uint32_t kinetum_test_provider_private_marker(void)
{
	return UINT32_C(0x4b505256);
}
