// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_c_module.c
 * @brief Plain-C11 module and link-closure canary for the installed SDK ABI.
 * @author Fleming Patel
 *
 * This image includes no C++ facade and links no host SDK runtime library. Its
 * registration symbol is the sole public SDK symbol; every SDK mechanism it
 * exercises is compiled into the image from the public C header.
 */

#include <kinetum/kinetum_sdk.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__AVX2__)
_Static_assert(KINETUM_SIMD_WIDTH == 32, "AVX2 SDK images must report a 32-byte SIMD width");
#elif defined(__SSE2__) || (defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__)))
_Static_assert(KINETUM_SIMD_WIDTH == 16, "128-bit SDK images must report a 16-byte SIMD width");
#else
_Static_assert(KINETUM_SIMD_WIDTH == 1, "scalar SDK images must report a one-byte SIMD width");
#endif

/** @brief Context-local mutable state for one exact C module instance. */
typedef struct c_module_state {
	uint64_t active_epoch;		  ///< Exact epoch currently published to packet execution.
	const uint8_t *active_threshold;  ///< Borrowed immutable packet configuration for that epoch.
} c_module_state;

/**
 * @brief Exercise every formerly host-defined C mechanism inside this image.
 *
 * @return true only when every image-local helper has exact semantics.
 */
static bool c_module_mechanisms_are_exact(void)
{
	const uint8_t u8_values[8] = {0u, 1u, 63u, 64u, 127u, 128u, 254u, 255u};
	const uint16_t u16_values[8] = {0u, 1u, 22u, 443u, 444u, 445u, 65534u, 65535u};
	uint64_t histogram_counts[2] = {1u, 1u};
	kinetum_histogram histogram = {0};
	kinetum_percentiles percentiles = {0};

	histogram.highest_trackable_value = 1u;
	histogram.total_count = 2u;
	histogram.min_value = 0u;
	histogram.max_value = 1u;
	histogram.sum = 1u;
	histogram.counts = histogram_counts;
	histogram.counts_len = 2u;
	histogram.unit_magnitude = 0;
	histogram.sub_bucket_half_count = 1;
	kinetum_histogram_percentiles(&histogram, &percentiles);

	return strcmp(kinetum_strerror(KINETUM_OK), "Success") == 0 &&
	       strcmp(kinetum_strerror((kinetum_error)-1234), "Unknown error") == 0 && percentiles.p50 == 0u &&
	       percentiles.p90 == 1u && percentiles.p99 == 1u && percentiles.p999 == 1u && percentiles.max == 1u &&
	       percentiles.min == 0u && percentiles.count == 2u && percentiles.sum == 1u &&
	       kinetum_simd_cmp_u8_ge(u8_values, 8u, 128u) == UINT64_C(0xe0) &&
	       kinetum_simd_cmp_u8_gt(u8_values, 8u, 254u) == UINT64_C(0x80) &&
	       kinetum_simd_cmp_u8_lt(u8_values, 8u, 1u) == UINT64_C(0x01) &&
	       kinetum_simd_cmp_u8_eq(u8_values, 8u, 64u) == UINT64_C(0x08) &&
	       kinetum_simd_cmp_u16_eq(u16_values, 8u, 22u) == UINT64_C(0x04) &&
	       kinetum_simd_cmp_u16_range(u16_values, 8u, 443u, 444u) == UINT64_C(0x18);
}

/**
 * @brief Initialize one C context after proving the image-local helper contract.
 *
 * @param lifecycle Borrowed exact INIT lifecycle context.
 * @param out_state Output context state written only on success.
 * @return KINETUM_OK or a precise lifecycle/helper failure.
 */
static kinetum_error c_module_init(const kinetum_lifecycle_ctx *lifecycle, void **out_state)
{
	void *storage = NULL;
	kinetum_error error;

	if (lifecycle == NULL || out_state == NULL) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_state = NULL;
	if (!c_module_mechanisms_are_exact()) {
		return KINETUM_ERR_INTERNAL;
	}
	error = kinetum_lifecycle_allocate_context(lifecycle, sizeof(c_module_state), _Alignof(c_module_state),
						   KINETUM_LIFECYCLE_ALLOC_ZERO, &storage);
	if (error != KINETUM_OK) {
		return error;
	}
	*out_state = storage;
	return KINETUM_OK;
}

/**
 * @brief Release the exact context allocation after owner-worker join.
 *
 * @param lifecycle Borrowed exact FINI lifecycle context.
 * @param state Exact state returned by successful INIT.
 */
static void c_module_fini(const kinetum_lifecycle_ctx *lifecycle, void *state)
{
	if (lifecycle == NULL || state == NULL || kinetum_lifecycle_release_context(lifecycle, state) != KINETUM_OK) {
		abort();
	}
}

/**
 * @brief Prepare one immutable one-byte DSCP threshold in the exact epoch arena.
 *
 * @param lifecycle Borrowed exact PREPARE lifecycle context.
 * @param epoch Exact nonzero prepared epoch.
 * @param config Borrowed one-byte threshold.
 * @param config_len Exact configuration length.
 * @param out_prepared Output ownership record written only on success.
 * @return KINETUM_OK or a precise validation/allocation failure.
 */
static kinetum_error c_module_prepare(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch, const void *config,
				      size_t config_len, kinetum_prepared_config *out_prepared)
{
	void *storage = NULL;
	kinetum_error error;

	if (lifecycle == NULL || epoch == 0u || config == NULL || config_len != sizeof(uint8_t) ||
	    out_prepared == NULL) {
		return KINETUM_ERR_INVALID_ARG;
	}
	memset(out_prepared, 0, sizeof(*out_prepared));
	error = kinetum_lifecycle_allocate_epoch(lifecycle, sizeof(uint8_t), _Alignof(uint8_t),
						 KINETUM_LIFECYCLE_ALLOC_ZERO, &storage);
	if (error != KINETUM_OK) {
		return error;
	}
	memcpy(storage, config, sizeof(uint8_t));
	out_prepared->packet_config = storage;
	return KINETUM_OK;
}

/**
 * @brief Publish one exact prepared threshold on the sole owner worker.
 *
 * @param context Sole-owner live context.
 * @param epoch Exact nonzero activated epoch.
 * @param prepared Borrowed exact prepared ownership.
 */
static void c_module_activate(kinetum_ctx *context, uint64_t epoch, const kinetum_prepared_config *prepared)
{
	c_module_state *state;
	if (context == NULL || context->state == NULL || epoch == 0u || prepared == NULL ||
	    prepared->owner_handle != NULL || prepared->packet_config == NULL) {
		abort();
	}
	state = (c_module_state *)context->state;
	state->active_epoch = epoch;
	state->active_threshold = (const uint8_t *)prepared->packet_config;
}

/**
 * @brief Validate exact prepared ownership before platform arena reclamation.
 *
 * @param lifecycle Borrowed exact RETIRE lifecycle context.
 * @param epoch Exact nonzero retired epoch.
 * @param prepared Exact prepared ownership transferred for retirement.
 */
static void c_module_retire(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch, kinetum_prepared_config prepared)
{
	if (lifecycle == NULL || epoch == 0u || prepared.owner_handle != NULL || prepared.packet_config == NULL) {
		abort();
	}
}

/**
 * @brief Apply the exact threshold through the image-local SIMD mechanism.
 *
 * @param batch Exact-config packet batch owned by one worker.
 * @return Forward mask for DSCP values strictly below the active threshold.
 */
static uint64_t c_module_process(kinetum_batch_t *batch)
{
	c_module_state *state;
	uint64_t forward_mask;

	if (batch == NULL || batch->ctx == NULL || batch->ctx->state == NULL || batch->epoch_config == NULL ||
	    batch->count > KINETUM_MAX_BURST) {
		return 0;
	}
	state = (c_module_state *)batch->ctx->state;
	if (batch->epoch != state->active_epoch || batch->epoch_config != state->active_threshold) {
		return 0;
	}
	forward_mask = kinetum_simd_cmp_u8_lt(batch->dscp, batch->count, *state->active_threshold);
	return forward_mask;
}

/** @brief Exact plain-C passive module descriptor. */
static const kinetum_module C_MODULE = {
	.module_id = "kinetum.test.c",
	.module_version = "1.0.0",
	.abi_version = KINETUM_MODULE_ABI_VERSION,
	.flags = KINETUM_MOD_F_LIVE_EPOCH_TRANSITION,
	.mode = KINETUM_MODULE_PASSIVE,
	.prepare_config = c_module_prepare,
	.activate_config = c_module_activate,
	.retire_config = c_module_retire,
	.process = c_module_process,
	.ingest = NULL,
	.run = NULL,
	.on_control = NULL,
	.init = c_module_init,
	.fini = c_module_fini,
	.health_check = NULL,
	.select_contexts = NULL,
};

/**
 * @brief Export the sole descriptor symbol from the plain-C module image.
 *
 * @return Immutable descriptor borrowed while this image's loader handle
 *         remains open.
 */
KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return &C_MODULE;
}
