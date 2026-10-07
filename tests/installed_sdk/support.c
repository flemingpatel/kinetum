// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file support.c
 * @brief Static-export and unresolved-import fixtures for installed SDK policy.
 * @author Fleming Patel
 */

#ifdef KINETUM_SDK_FIXTURE_UNRESOLVED
/**
 * @brief Intentionally absent strong import, resolved by neither SDK interface.
 * @return No runtime value; this deliberately undefined symbol must cause link rejection.
 */
extern unsigned kinetum_sdk_missing_import(void);
#endif

/** @brief Consume a real static-archive symbol, or an intentional unresolved import. */
unsigned kinetum_sdk_support_value(void)
{
#ifdef KINETUM_SDK_FIXTURE_UNRESOLVED
	return kinetum_sdk_missing_import();
#else
	return 0u;
#endif
}
