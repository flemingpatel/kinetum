// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_serialized_module.cpp
 * @brief Replicable module fixture for image-wide lifecycle serialization.
 * @author Fleming Patel
 *
 * The first PREPARE callback can be held inside foreign code while a second
 * context attempts PREPARE through another production adapter. Exported
 * observation functions let the host prove that both contexts share one
 * image-level callback domain and that a held callback observes cooperative
 * cancellation, without exposing synchronization through the module ABI.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <thread>

#include <kinetum/kinetum_sdk.h>

namespace
{

/** Callbacks currently executing inside this shared module image. */
std::atomic<uint32_t> active_callbacks{0};
/** Highest observed concurrent callback count. */
std::atomic<uint32_t> max_active_callbacks{0};
/** Number of PREPARE callbacks that entered the image. */
std::atomic<uint32_t> prepare_entries{0};
/** Owner-controlled gate retaining the first PREPARE callback. */
std::atomic<bool> hold_first_prepare{false};
/** Whether the held callback observed cooperative cancellation. */
std::atomic<bool> cancellation_observed{false};

/**
 * @brief Publish a new observed concurrency maximum without a lock.
 * @param candidate Observed simultaneous callback population.
 */
void publish_maximum(uint32_t candidate) noexcept
{
	uint32_t observed = max_active_callbacks.load(std::memory_order_relaxed);
	while (observed < candidate &&
	       !max_active_callbacks.compare_exchange_weak(observed, candidate, std::memory_order_relaxed,
							   std::memory_order_relaxed)) {
	}
}

/**
 * @brief Hold the first PREPARE callback until the host releases it.
 * @param lifecycle Borrowed lifecycle shell used to observe cancellation.
 * @param epoch Nonzero target epoch.
 * @param config Must be nullptr for this no-configuration fixture.
 * @param config_size Must be zero.
 * @param prepared Output receiving the explicit null/null prepared record.
 * @return KINETUM_OK after any hold is released, or INVALID_ARG for malformed input.
 */
[[nodiscard]] kinetum_error prepare_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch, const void *config,
					   std::size_t config_size, kinetum_prepared_config *prepared) noexcept
{
	if (!lifecycle || epoch == 0 || config || config_size != 0 || !prepared) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*prepared = {};
	const uint32_t active = active_callbacks.fetch_add(1, std::memory_order_acq_rel) + 1u;
	publish_maximum(active);
	const uint32_t entry = prepare_entries.fetch_add(1, std::memory_order_release) + 1u;
	if (entry == 1u) {
		while (hold_first_prepare.load(std::memory_order_acquire)) {
			if (kinetum_lifecycle_cancellation_requested(lifecycle)) {
				cancellation_observed.store(true, std::memory_order_release);
			}
			std::this_thread::yield();
		}
	}
	active_callbacks.fetch_sub(1, std::memory_order_acq_rel);
	return KINETUM_OK;
}

/**
 * @brief Validate one explicit no-configuration activation.
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
 * @brief Validate one explicit no-configuration retirement.
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
 * @brief Initialize one explicit stateless context.
 * @param lifecycle Non-null borrowed INIT shell.
 * @param state Output receiving a valid null state on success.
 * @return KINETUM_OK for a stateless context, or INVALID_ARG for absent arguments.
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
 * @brief Validate one explicit stateless context at finalization.
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
 * @brief Preserve every packet in the passive test descriptor.
 * @param batch Borrowed callback batch, or nullptr.
 * @return Full occupied-prefix mask, or zero for a null batch.
 */
[[nodiscard]] uint64_t process_batch(kinetum_batch_t *batch) noexcept
{
	return batch ? KINETUM_FORWARD_MASK(batch->count) : 0;
}

/** @brief Replicable exact descriptor sharing one code-image callback domain. */
const kinetum_module SERIALIZED_MODULE{
	.module_id = "kinetum.test.serialized",
	.module_version = "1.0.0",
	.abi_version = KINETUM_MODULE_ABI_VERSION,
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

/** @return Immutable serialization-test descriptor retained for the image lifetime. */
extern "C" KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return &SERIALIZED_MODULE;
}

/** @brief Reset all serialization observations before admitting test work. */
extern "C" KINETUM_MODULE_EXPORT void kinetum_test_serialized_reset(void)
{
	active_callbacks.store(0, std::memory_order_relaxed);
	max_active_callbacks.store(0, std::memory_order_relaxed);
	prepare_entries.store(0, std::memory_order_relaxed);
	hold_first_prepare.store(false, std::memory_order_relaxed);
	cancellation_observed.store(false, std::memory_order_relaxed);
}

/**
 * @brief Select whether the first PREPARE callback remains inside the module.
 * @param hold Keep the first callback held when true.
 */
extern "C" KINETUM_MODULE_EXPORT void kinetum_test_serialized_hold_first(bool hold)
{
	hold_first_prepare.store(hold, std::memory_order_release);
}

/** @return Number of PREPARE callbacks that entered foreign code. */
extern "C" KINETUM_MODULE_EXPORT uint32_t kinetum_test_serialized_prepare_entries(void)
{
	return prepare_entries.load(std::memory_order_acquire);
}

/** @return Maximum concurrent PREPARE callback count. */
extern "C" KINETUM_MODULE_EXPORT uint32_t kinetum_test_serialized_max_active(void)
{
	return max_active_callbacks.load(std::memory_order_acquire);
}

/** @return true when the held callback observed cooperative cancellation. */
extern "C" KINETUM_MODULE_EXPORT bool kinetum_test_serialized_cancellation_observed(void)
{
	return cancellation_observed.load(std::memory_order_acquire);
}
