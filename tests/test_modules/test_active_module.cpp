// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_active_module.cpp
 * @brief Exact-ABI active module for owner-worker dispatch tests.
 * @author Fleming Patel
 *
 * This synchronous active test module uses explicit no-op configuration
 * lifecycle callbacks. Every observation is context-local state reached
 * through the admitted packet context; no test symbol, image-global selector,
 * or second configuration authority is exported.
 */

#include "test_active_module_state.hpp"

#include <array>
#include <exception>
#include <new>

#include <kinetum/kinetum_sdk.h>

namespace
{

using kinetum::test::test_active_state;

/**
 * @brief Allocate and publish one exact context-local observation state.
 * @param lifecycle Exact context-lifetime allocation authority.
 * @param[out] out_state Published context-local state pointer.
 * @return KINETUM_OK on exact allocation and construction; otherwise an ABI error.
 */
[[nodiscard]] kinetum_error test_active_init(const kinetum_lifecycle_ctx *lifecycle, void **out_state) noexcept
{
	if (!lifecycle || !out_state) {
		return KINETUM_ERR_INVALID_ARG;
	}
	void *storage = nullptr;
	const auto allocated = kinetum_lifecycle_allocate_context(lifecycle, sizeof(test_active_state),
								  alignof(test_active_state),
								  KINETUM_LIFECYCLE_ALLOC_ZERO, &storage);
	if (allocated != KINETUM_OK) {
		return allocated;
	}
	try {
		*out_state = new (storage) test_active_state{};
	} catch (...) {
		(void)kinetum_lifecycle_release_context(lifecycle, storage);
		return KINETUM_ERR_INTERNAL;
	}
	return KINETUM_OK;
}

/**
 * @brief Validate detached fixed test state during FINI.
 * @param lifecycle Exact context-lifetime release authority.
 * @param state Exact context-local state to destroy.
 */
void test_active_fini(const kinetum_lifecycle_ctx *lifecycle, void *state) noexcept
{
	if (!lifecycle || state == nullptr) {
		std::terminate();
	}
	auto *active = static_cast<test_active_state *>(state);
	active->~test_active_state();
	if (kinetum_lifecycle_release_context(lifecycle, state) != KINETUM_OK) {
		std::terminate();
	}
}

/**
 * @brief Resolve exact active test state or fail the module contract.
 * @param ctx Exact owner-worker packet context.
 * @return Context-local active test state.
 */
[[nodiscard]] test_active_state &state_from(kinetum_ctx *ctx) noexcept
{
	if (!ctx || ctx->state == nullptr) {
		std::terminate();
	}
	return *static_cast<test_active_state *>(ctx->state);
}

/**
 * @brief Retain or forward one exact active-ingest batch and publish test counters.
 * @param ctx Exact owner-worker packet context.
 * @param active_ctx Exact callback-borrowed active services.
 * @param batch Exact active-ingest batch.
 * @return Sole forward mask after any provisional retain action.
 */
uint64_t test_active_ingest(kinetum_ctx *ctx, kinetum_active_ctx *active_ctx, kinetum_batch_t *batch) noexcept
{
	auto &state = state_from(ctx);
	state.ingest_call_count.fetch_add(1, std::memory_order_relaxed);
	if (!batch) {
		return 0;
	}
	state.ingest_total_packets.fetch_add(batch->count, std::memory_order_relaxed);
	state.last_ingest_epoch.store(batch->epoch, std::memory_order_relaxed);
	state.last_ingest_packet_config.store(reinterpret_cast<std::uintptr_t>(batch->epoch_config),
					      std::memory_order_relaxed);
	const uint64_t requested = state.retain_batch_mask.exchange(0u, std::memory_order_relaxed);
	if (requested != 0u) {
		if (state.retained_batch_mask.load(std::memory_order_relaxed) != 0u) {
			std::terminate();
		}
		uint64_t retained = 0u;
		for (uint16_t lane = 0u; lane < batch->count; ++lane) {
			if ((requested & (UINT64_C(1) << lane)) == 0u) {
				continue;
			}
			const auto handle = active_ctx->retain_input(active_ctx, lane);
			if (handle.value != KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE) {
				state.retained_batch_handles[lane].store(handle.value, std::memory_order_relaxed);
				retained |= UINT64_C(1) << lane;
			}
		}
		state.retained_batch_mask.store(retained, std::memory_order_relaxed);
		return KINETUM_FORWARD_MASK(batch->count) & ~retained;
	}
	if (state.retain_on_next_ingest.exchange(false, std::memory_order_relaxed) && active_ctx != nullptr &&
	    active_ctx->retain_input != nullptr) {
		const uint32_t lane = state.retain_lane.exchange(0u, std::memory_order_relaxed);
		const auto handle = active_ctx->retain_input(active_ctx, lane);
		state.retained_handle.store(handle.value, std::memory_order_relaxed);
		if (state.retain_twice_on_next_ingest.exchange(false, std::memory_order_relaxed)) {
			(void)active_ctx->retain_input(active_ctx, lane);
		}
		return lane < batch->count ? KINETUM_FORWARD_MASK(batch->count) & ~(UINT64_C(1) << lane) : 0u;
	}
	return KINETUM_FORWARD_MASK(batch->count);
}

/**
 * @brief Record trigger delivery and exercise exact active services.
 * @param ctx Exact owner-worker packet context.
 * @param active_ctx Exact callback-borrowed active services.
 * @param triggers Complete runtime trigger mask for this turn.
 */
void test_active_run(kinetum_ctx *ctx, kinetum_active_ctx *active_ctx, uint32_t triggers) noexcept
{
	auto &state = state_from(ctx);
	state.run_call_count.fetch_add(1, std::memory_order_relaxed);
	state.last_triggers.store(triggers, std::memory_order_relaxed);
	if ((triggers & KINETUM_TRIGGER_PULL_READY) != 0) {
		state.pull_ready_count.fetch_add(1, std::memory_order_relaxed);
	}
	if (!active_ctx) {
		return;
	}

	state.last_now_ns.store(active_ctx->now_ns, std::memory_order_relaxed);
	state.last_expired_count.store(active_ctx->expired_count, std::memory_order_relaxed);
	state.last_active_epoch.store(active_ctx->active_epoch, std::memory_order_relaxed);
	state.last_active_state_flags.store(active_ctx->state_flags, std::memory_order_relaxed);
	state.last_drain_target_epoch.store(active_ctx->drain_target_epoch, std::memory_order_relaxed);
	if (state.cancel_timer_on_next_run.exchange(false, std::memory_order_relaxed) &&
	    active_ctx->cancel_timer != nullptr) {
		const kinetum_active_timer_handle handle{
			state.timer_handle.load(std::memory_order_relaxed),
		};
		if (active_ctx->cancel_timer(active_ctx, handle)) {
			state.timer_handle.store(KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE, std::memory_order_relaxed);
			state.cancelled_timer_count.fetch_add(1u, std::memory_order_relaxed);
		}
	}
	if ((triggers & KINETUM_TRIGGER_TIMER) != 0u) {
		state.timer_trigger_count.fetch_add(1u, std::memory_order_relaxed);
		state.timer_handle.store(KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE, std::memory_order_relaxed);
	}
	if ((triggers & KINETUM_TRIGGER_DRAIN) != 0u) {
		state.drain_trigger_count.fetch_add(1u, std::memory_order_relaxed);
		uint64_t pending = state.retained_batch_mask.load(std::memory_order_relaxed);
		for (uint16_t lane = 0u; lane < KINETUM_MAX_BURST; ++lane) {
			const uint64_t bit = UINT64_C(1) << lane;
			if ((pending & bit) != 0u &&
			    active_ctx->drop_retained(
				    active_ctx, {state.retained_batch_handles[lane].load(std::memory_order_relaxed)})) {
				pending &= ~bit;
			}
		}
		state.retained_batch_mask.store(pending, std::memory_order_relaxed);
	}
	const uint64_t delay = state.arm_timer_delay_ns.exchange(0u, std::memory_order_relaxed);
	if (delay != 0u && active_ctx->arm_timer_after != nullptr) {
		const auto handle = active_ctx->arm_timer_after(active_ctx, delay);
		state.timer_handle.store(handle.value, std::memory_order_relaxed);
	}
	const auto retained = kinetum_retained_packet_handle{
		state.retained_handle.load(std::memory_order_relaxed),
	};
	if (state.emit_retained_on_next_run.exchange(false, std::memory_order_relaxed) &&
	    active_ctx->emit_retained != nullptr &&
	    active_ctx->emit_retained(active_ctx, retained,
				      state.retained_emit_next_stage.load(std::memory_order_relaxed))) {
		state.retained_handle.store(KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE, std::memory_order_relaxed);
	}
	if (((triggers & KINETUM_TRIGGER_DRAIN) != 0u ||
	     state.drop_retained_on_next_run.exchange(false, std::memory_order_relaxed)) &&
	    active_ctx->drop_retained != nullptr && retained.value != KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE &&
	    active_ctx->drop_retained(active_ctx, retained)) {
		state.retained_handle.store(KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE, std::memory_order_relaxed);
	}
	if (state.emit_on_next_run.exchange(false, std::memory_order_relaxed) && active_ctx->emit) {
		kinetum_emit_batch_t batch{};
		batch.count = 1;
		static const uint8_t emit_data[1] = {0x42};
		batch.data[0] = emit_data;
		batch.len[0] = 1;
		batch.dscp[0] = state.emit_dscp.load(std::memory_order_relaxed);
		batch.platform_flags[0] = state.emit_platform_flags.load(std::memory_order_relaxed);
		batch.proto[0] = state.emit_proto.load(std::memory_order_relaxed);
		batch.next_stage[0] = KINETUM_NEXT_STAGE_UNSET;
		const uint32_t emitted = active_ctx->emit(active_ctx, &batch);
		state.emit_call_count.fetch_add(1, std::memory_order_relaxed);
		state.emit_total_packets.fetch_add(emitted, std::memory_order_relaxed);
	}

	const uint16_t pull_target =
		state.pull_target_idx.exchange(KINETUM_NEXT_STAGE_UNSET, std::memory_order_relaxed);
	if (pull_target != KINETUM_NEXT_STAGE_UNSET && active_ctx->request_pull) {
		const uint32_t repeat = state.pull_repeat_count.exchange(1u, std::memory_order_relaxed);
		for (uint32_t index = 0u; index < repeat; ++index) {
			(void)active_ctx->request_pull(active_ctx, pull_target);
		}
	}
	const uint16_t control_target =
		state.post_control_target.exchange(KINETUM_NEXT_STAGE_UNSET, std::memory_order_relaxed);
	if (control_target != KINETUM_NEXT_STAGE_UNSET && active_ctx->post_control != nullptr) {
		const uint32_t repeat = state.post_control_repeat_count.exchange(1u, std::memory_order_relaxed);
		const uint32_t payload_len = state.post_control_payload_len.exchange(0u, std::memory_order_relaxed);
		std::array<uint8_t, 64> payload{};
		payload.fill(state.post_control_payload_value.load(std::memory_order_relaxed));
		const kinetum_control_msg message{
			.data = payload_len == 0u ? nullptr : payload.data(),
			.len = payload_len,
			.subtype = state.post_control_subtype.load(std::memory_order_relaxed),
		};
		for (uint32_t index = 0u; index < repeat; ++index) {
			if (active_ctx->post_control(active_ctx, control_target, &message)) {
				state.posted_control_count.fetch_add(1u, std::memory_order_relaxed);
			}
		}
		payload.fill(UINT8_C(0xff));
	}
}

/**
 * @brief Record one active control message on the owner worker.
 * @param ctx Exact owner-worker packet context.
 * @param active_ctx Fresh callback-borrowed active services.
 * @param message Complete borrowed copied-control message.
 */
void test_active_on_control(kinetum_ctx *ctx, kinetum_active_ctx *active_ctx,
			    const kinetum_control_msg *message) noexcept
{
	auto &state = state_from(ctx);
	state.control_call_count.fetch_add(1, std::memory_order_relaxed);
	if (active_ctx == nullptr || active_ctx->active_epoch == 0u || active_ctx->runtime_services == nullptr ||
	    active_ctx->post_control == nullptr) {
		state.invalid_control_context_count.fetch_add(1u, std::memory_order_relaxed);
	}
	if (message) {
		state.last_control_subtype.store(message->subtype, std::memory_order_relaxed);
		state.last_control_len.store(message->len, std::memory_order_relaxed);
		state.last_control_first_byte.store(message->len == 0u || message->data == nullptr ?
							    0u :
							    static_cast<const uint8_t *>(message->data)[0],
						    std::memory_order_relaxed);
	}
	if (active_ctx != nullptr && state.mutate_control_context_on_next.exchange(false, std::memory_order_relaxed)) {
		active_ctx->active_epoch = 0u;
		active_ctx->runtime_services = nullptr;
	}
}

/** @brief Exact fixed-epoch active test-module descriptor. */
const kinetum_module TEST_ACTIVE_MODULE{
	.module_id = "kinetum.test_active",
	.module_version = "1.0.0",
	.abi_version = KINETUM_MODULE_ABI_VERSION,
	.flags = KINETUM_MOD_F_REPLICABLE_CONTEXTS | KINETUM_MOD_F_LIVE_EPOCH_TRANSITION,
	.mode = KINETUM_MODULE_ACTIVE,
	.prepare_config = kinetum_noop_prepare_config,
	.activate_config = kinetum_noop_activate_config,
	.retire_config = kinetum_noop_retire_config,
	.process = nullptr,
	.ingest = test_active_ingest,
	.run = test_active_run,
	.on_control = test_active_on_control,
	.init = test_active_init,
	.fini = test_active_fini,
	.health_check = nullptr,
	.select_contexts = nullptr,
};

}  // namespace

/** @brief Export the exact active test-module descriptor. @return Sole descriptor address. */
extern "C" KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return &TEST_ACTIVE_MODULE;
}
