// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file module.c
 * @brief External installed-SDK module consumer fixture.
 * @author Fleming Patel
 */

#include <kinetum/kinetum_sdk.h>

/** @return Zero from the explicitly linked static fixture dependency. */
extern unsigned kinetum_sdk_support_value(void);

/**
 * @brief Consume a real static-archive symbol from the C callback.
 * @param batch Borrowed ABI batch; this link fixture does not inspect packet lanes.
 * @return Zero forwarding mask supplied by the static dependency.
 */
uint64_t canary_process(kinetum_batch_t *batch)
{
	(void)batch;
	return kinetum_sdk_support_value();
}

/** @brief Exact independent C11 module descriptor. */
static const kinetum_module CANARY_MODULE = {
	.module_id = "example.sdk.canary.c",
	.module_version = "1.0.0",
	.abi_version = KINETUM_MODULE_ABI_VERSION,
	.flags = 0u,
	.mode = KINETUM_MODULE_PASSIVE,
	.prepare_config = kinetum_noop_prepare_config,
	.activate_config = kinetum_noop_activate_config,
	.retire_config = kinetum_noop_retire_config,
	.process = canary_process,
	.ingest = NULL,
	.run = NULL,
	.on_control = NULL,
	.init = kinetum_noop_init,
	.fini = kinetum_noop_fini,
	.health_check = NULL,
	.select_contexts = NULL,
};

/** @return Immutable C11 descriptor borrowed until this module is unloaded. */
KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return &CANARY_MODULE;
}
