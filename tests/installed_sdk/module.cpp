// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file module.cpp
 * @brief External installed-SDK module consumer fixture.
 * @author Fleming Patel
 */

#include <kinetum/kinetum_sdk.hpp>
#include <kinetum/algo/algo.hpp>

/** @return Zero from the explicitly linked static dependency. */
extern "C" unsigned kinetum_sdk_support_value(void);
/** @return Shared inline storage borrowed until the explicit dependency is unloaded. */
extern "C" unsigned *kinetum_sdk_dependency_state(void);

namespace
{

/**
 * @brief Consume static-dependency code from the C++ callback.
 * @param batch Borrowed ABI batch; this link fixture does not inspect packet lanes.
 * @return Zero forwarding mask supplied by the static dependency.
 */
uint64_t canary_process(kinetum_batch_t *batch) noexcept
{
	(void)batch;
	return kinetum_sdk_support_value();
}

}  // namespace

/** @brief ODR-used inline descriptor; GNU-unique ownership would prevent unload. */
inline const kinetum_module CANARY_MODULE{
	.module_id = "example.sdk.canary.cpp",
	.module_version = "1.0.0",
	.abi_version = KINETUM_MODULE_ABI_VERSION,
	.flags = 0u,
	.mode = KINETUM_MODULE_PASSIVE,
	.prepare_config = kinetum_noop_prepare_config,
	.activate_config = kinetum_noop_activate_config,
	.retire_config = kinetum_noop_retire_config,
	.process = canary_process,
	.ingest = nullptr,
	.run = nullptr,
	.on_control = nullptr,
	.init = kinetum_noop_init,
	.fini = kinetum_noop_fini,
	.health_check = nullptr,
	.select_contexts = nullptr,
};

/** @return Borrowed C++20 descriptor for zero dependency state, otherwise null. */
extern "C" KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return *kinetum_sdk_dependency_state() == 0u ? &CANARY_MODULE : nullptr;
}
