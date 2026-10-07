// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_incompatible_module.cpp
 * @brief Otherwise-valid module fixture carrying one incompatible ABI version.
 * @author Fleming Patel
 *
 * Two shared-object targets compile this source with ABI values below and
 * above the host revision. Keeping every other descriptor field valid proves
 * that generation admission rejects exact-version mismatch itself rather than
 * a later descriptor-shape error.
 */

#include <kinetum/kinetum_sdk.h>

#include <cstddef>
#include <cstdint>
#include <exception>

#if !defined(KINETUM_TEST_INCOMPATIBLE_MODULE_ID)
#error "KINETUM_TEST_INCOMPATIBLE_MODULE_ID must identify this fixture"
#endif

#if !defined(KINETUM_TEST_INCOMPATIBLE_ABI_DIRECTION)
#error "KINETUM_TEST_INCOMPATIBLE_ABI_DIRECTION must be -1 or 1"
#endif

namespace
{

#if KINETUM_TEST_INCOMPATIBLE_ABI_DIRECTION < 0
/** Lower incompatible revision used by the below-host fixture. */
inline constexpr uint32_t TEST_ABI_VERSION = KINETUM_MODULE_ABI_VERSION - 1u;
#elif KINETUM_TEST_INCOMPATIBLE_ABI_DIRECTION > 0
/** Higher incompatible revision used by the above-host fixture. */
inline constexpr uint32_t TEST_ABI_VERSION = KINETUM_MODULE_ABI_VERSION + 1u;
#else
#error "KINETUM_TEST_INCOMPATIBLE_ABI_DIRECTION must be -1 or 1"
#endif

/**
 * @brief Prepare a valid explicit no-configuration result.
 * @param lifecycle Non-null borrowed PREPARE shell.
 * @param epoch Nonzero target epoch.
 * @param config Must be nullptr for this no-configuration fixture.
 * @param config_size Must be zero.
 * @param prepared Output receiving the explicit null/null artifact on success.
 * @return KINETUM_OK for valid input, otherwise INVALID_ARG.
 */
[[nodiscard]] kinetum_error prepare_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch, const void *config,
					   std::size_t config_size, kinetum_prepared_config *prepared) noexcept
{
	if (!lifecycle || epoch == 0 || config || config_size != 0 || !prepared) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*prepared = {};
	return KINETUM_OK;
}

/**
 * @brief Validate the explicit no-configuration activation record.
 * @param context Non-null live context.
 * @param epoch Nonzero activating epoch.
 * @param prepared Borrowed explicit null/null prepared record.
 */
void activate_config(kinetum_ctx *context, uint64_t epoch, const kinetum_prepared_config *prepared) noexcept
{
	if (!context || epoch == 0 || !prepared || prepared->owner_handle || prepared->packet_config) {
		std::terminate();
	}
}

/**
 * @brief Validate exact no-configuration retirement.
 * @param lifecycle Non-null borrowed RETIRE shell.
 * @param epoch Nonzero retired epoch.
 * @param prepared Explicit null/null record returned for retirement.
 */
void retire_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch, kinetum_prepared_config prepared) noexcept
{
	if (!lifecycle || epoch == 0 || prepared.owner_handle || prepared.packet_config) {
		std::terminate();
	}
}

/**
 * @brief Initialize an explicit stateless context.
 * @param lifecycle Non-null borrowed INIT shell.
 * @param state Output receiving a valid null state on success.
 * @return KINETUM_OK for valid input, otherwise INVALID_ARG.
 */
[[nodiscard]] kinetum_error init_context(const kinetum_lifecycle_ctx *lifecycle, void **state) noexcept
{
	if (!lifecycle || !state) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*state = nullptr;
	return KINETUM_OK;
}

/**
 * @brief Validate stateless context finalization.
 * @param lifecycle Non-null borrowed FINI shell.
 * @param state Valid null state returned by INIT.
 */
void fini_context(const kinetum_lifecycle_ctx *lifecycle, void *state) noexcept
{
	if (!lifecycle || state) {
		std::terminate();
	}
}

/**
 * @brief Preserve every packet in an otherwise-valid passive descriptor.
 * @param batch Borrowed callback batch, or nullptr.
 * @return Full occupied-prefix mask, or zero for a null batch.
 */
[[nodiscard]] uint64_t process_batch(kinetum_batch_t *batch) noexcept
{
	return batch ? KINETUM_FORWARD_MASK(batch->count) : 0;
}

/** @brief Exact descriptor apart from the intentionally incompatible version. */
const kinetum_module INCOMPATIBLE_MODULE{
	.module_id = KINETUM_TEST_INCOMPATIBLE_MODULE_ID,
	.module_version = "1.0.0",
	.abi_version = TEST_ABI_VERSION,
	.flags = KINETUM_MOD_F_REPLICABLE_CONTEXTS | KINETUM_MOD_F_LIVE_EPOCH_TRANSITION,
	.mode = KINETUM_MODULE_PASSIVE,
	.prepare_config = prepare_config,
	.activate_config = activate_config,
	.retire_config = retire_config,
	.process = process_batch,
	.ingest = nullptr,
	.run = nullptr,
	.on_control = nullptr,
	.init = init_context,
	.fini = fini_context,
	.health_check = nullptr,
	.select_contexts = nullptr,
};

}  // namespace

/** @return Immutable deliberately incompatible descriptor retained for the image lifetime. */
extern "C" KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return &INCOMPATIBLE_MODULE;
}
