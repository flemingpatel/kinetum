// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_staging_burst_module.cpp
 * @brief Originate a deterministic sequence through varying public active-module output extents.
 * @author Fleming Patel
 */

#include <array>
#include <exception>
#include <new>

#include <kinetum/kinetum_sdk.h>

namespace
{

/** Exact origin sequence used to distinguish loss, duplication and reordering. */
constexpr std::array<uint8_t, 17> PAYLOADS{0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u};
/** Origin request boundaries exercise large, short, then large scratch reuse. */
constexpr std::array<uint32_t, 3> ORIGIN_ENDS{8u, 9u, 17u};

/** @brief Context-local origin progress, written only by its owner worker. */
struct burst_state {
	uint32_t emitted{0u};  ///< Exact prefix already copied into platform-owned records.
};

/**
 * @brief Allocate one origin counter from the admitted context arena.
 * @param lifecycle Exact context allocation authority.
 * @param[out] state Receives the constructed state only after successful allocation.
 * @return The allocator's status or complete success.
 */
kinetum_error initialize(const kinetum_lifecycle_ctx *lifecycle, void **state) noexcept
{
	if (lifecycle == nullptr || state == nullptr) {
		return KINETUM_ERR_INVALID_ARG;
	}
	void *storage = nullptr;
	const auto status = kinetum_lifecycle_allocate_context(lifecycle, sizeof(burst_state), alignof(burst_state),
							       KINETUM_LIFECYCLE_ALLOC_ZERO, &storage);
	if (status != KINETUM_OK) {
		return status;
	}
	*state = new (storage) burst_state{};
	return KINETUM_OK;
}

/** @brief Retire the exact context allocation after worker join. @param lifecycle Allocation authority. @param state Sole state. */
void finalize(const kinetum_lifecycle_ctx *lifecycle, void *state) noexcept
{
	if (lifecycle == nullptr || state == nullptr) {
		std::terminate();
	}
	static_cast<burst_state *>(state)->~burst_state();
	if (kinetum_lifecycle_release_context(lifecycle, state) != KINETUM_OK) {
		std::terminate();
	}
}

/** @brief Reject ingress so replayed module execution cannot masquerade as a delivery retry. @return Zero forward mask. */
uint64_t ingest(kinetum_ctx *, kinetum_active_ctx *, kinetum_batch_t *) noexcept
{
	return 0u;
}

/**
 * @brief Offer at most three variable-sized origins, retaining any refused suffix.
 * @param context Exact owner-worker context.
 * @param active Borrowed runtime origin operation and processing time.
 */
void run(kinetum_ctx *context, kinetum_active_ctx *active, uint32_t) noexcept
{
	if (context == nullptr || context->state == nullptr || active == nullptr || active->emit == nullptr) {
		std::terminate();
	}
	auto &state = *static_cast<burst_state *>(context->state);
	if (state.emitted == PAYLOADS.size()) {
		return;
	}
	for (const uint32_t end : ORIGIN_ENDS) {
		if (state.emitted >= end) {
			continue;
		}
		kinetum_emit_batch_t batch{};
		batch.count = static_cast<uint16_t>(end - state.emitted);
		for (uint16_t index = 0u; index < batch.count; ++index) {
			batch.data[index] = &PAYLOADS[state.emitted + index];
			batch.len[index] = 1u;
			batch.input_port[index] = KINETUM_PORT_UNSET;
			batch.output_port[index] = KINETUM_PORT_UNSET;
			batch.next_stage[index] = KINETUM_NEXT_STAGE_UNSET;
		}
		const uint32_t accepted = active->emit(active, &batch);
		if (accepted > batch.count) {
			std::terminate();
		}
		state.emitted += accepted;
		if (accepted != batch.count) {
			return;
		}
	}
}

/** Complete live-epoch-capable active descriptor using explicit no-op configuration ownership. */
const kinetum_module MODULE{
	.module_id = "kinetum.test_staging_burst",
	.module_version = "1.0.0",
	.abi_version = KINETUM_MODULE_ABI_VERSION,
	.flags = KINETUM_MOD_F_REPLICABLE_CONTEXTS | KINETUM_MOD_F_LIVE_EPOCH_TRANSITION,
	.mode = KINETUM_MODULE_ACTIVE,
	.prepare_config = kinetum_noop_prepare_config,
	.activate_config = kinetum_noop_activate_config,
	.retire_config = kinetum_noop_retire_config,
	.process = nullptr,
	.ingest = ingest,
	.run = run,
	.on_control = nullptr,
	.init = initialize,
	.fini = finalize,
	.health_check = nullptr,
	.select_contexts = nullptr,
};

}  // namespace

/** @brief Export the deterministic burst generator. @return Its exact descriptor. */
extern "C" KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return &MODULE;
}
