// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_active_async_module.cpp
 * @brief Exact active image exercising tracked foreign-work ownership.
 * @author Fleming Patel
 *
 * The canary begins standalone and packet-bound tokens, handles synchronous
 * submit refusal, consumes exact completion prefixes, and exercises drop,
 * same-instance recirculation, and completion-time resubmission through the
 * installed SDK surface. One bounded SPSC transfers copied tokens without an
 * owner-worker notification or syscall. The foreign thread invokes no module
 * callback.
 */

#include "test_active_async_module_state.hpp"

#include <exception>
#include <new>

#include <kinetum/kinetum_sdk.h>

namespace
{

using kinetum::test::async_completion_action;
using kinetum::test::test_active_async_state;

/**
 * @brief Poll one bounded token handoff until exact FINI.
 * @param state Exact context-local canary state.
 *
 * Only this foreign thread consumes the SPSC queue. It may spin on its own
 * execution resource, while the owner-worker producer performs one nonblocking
 * release publication and no wake syscall.
 */
void foreign_completion_loop(test_active_async_state *state) noexcept
{
	if (state == nullptr) {
		std::terminate();
	}
	kinetum_async_token pending = kinetum_invalid_async_token();
	for (;;) {
		if (!kinetum_async_token_valid(&pending)) {
			if (state->foreign_tokens.try_pop(pending)) {
				if (!kinetum_async_token_valid(&pending)) {
					std::terminate();
				}
				continue;
			}
			if (state->stop_foreign.load(std::memory_order_acquire)) {
				return;
			}
			KINETUM_PAUSE();
			continue;
		}
		const uint64_t observed = state->token_handle.load(std::memory_order_acquire);
		if (observed != pending.handle.value) {
			pending = kinetum_invalid_async_token();
			continue;
		}
		if (state->auto_complete.load(std::memory_order_acquire)) {
			if (!kinetum_async_complete(&pending,
						    state->automatic_outcome.load(std::memory_order_relaxed))) {
				std::terminate();
			}
		}
		while (state->token_handle.load(std::memory_order_acquire) == observed) {
			KINETUM_PAUSE();
		}
		pending = kinetum_invalid_async_token();
	}
}

/**
 * @brief Allocate one context-local async canary state.
 * @param lifecycle Exact context-lifetime allocation authority.
 * @param[out] out_state Published state pointer.
 * @return KINETUM_OK after exact construction, otherwise one ABI error.
 */
[[nodiscard]] kinetum_error test_async_init(const kinetum_lifecycle_ctx *lifecycle, void **out_state) noexcept
{
	if (lifecycle == nullptr || out_state == nullptr) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_state = nullptr;
	void *storage = nullptr;
	const auto result = kinetum_lifecycle_allocate_context(lifecycle, sizeof(test_active_async_state),
							       alignof(test_active_async_state),
							       KINETUM_LIFECYCLE_ALLOC_ZERO, &storage);
	if (result != KINETUM_OK) {
		return result;
	}
	test_active_async_state *state = nullptr;
	try {
		state = new (storage) test_active_async_state{};
		state->foreign_thread = std::thread(foreign_completion_loop, state);
		*out_state = state;
	} catch (...) {
		if (state != nullptr) {
			state->~test_active_async_state();
		}
		if (kinetum_lifecycle_release_context(lifecycle, storage) != KINETUM_OK) {
			std::terminate();
		}
		return KINETUM_ERR_INTERNAL;
	}
	return KINETUM_OK;
}

/**
 * @brief Destroy one fully drained context-local async canary state.
 * @param lifecycle Exact context-lifetime release authority.
 * @param state Exact detached state.
 */
void test_async_fini(const kinetum_lifecycle_ctx *lifecycle, void *state) noexcept
{
	if (lifecycle == nullptr || state == nullptr) {
		std::terminate();
	}
	auto *async = static_cast<test_active_async_state *>(state);
	if (async->token_handle.load(std::memory_order_relaxed) != KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE ||
	    async->retained_handle.load(std::memory_order_relaxed) != KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE) {
		std::terminate();
	}
	async->stop_foreign.store(true, std::memory_order_release);
	if (!async->foreign_thread.joinable()) {
		std::terminate();
	}
	async->foreign_thread.join();
	if (!async->foreign_tokens.empty()) {
		std::terminate();
	}
	async->~test_active_async_state();
	if (kinetum_lifecycle_release_context(lifecycle, state) != KINETUM_OK) {
		std::terminate();
	}
}

/** @param context Exact owner-worker context. @return Context-local canary state. */
[[nodiscard]] test_active_async_state &state_from(kinetum_ctx *context) noexcept
{
	if (context == nullptr || context->state == nullptr) {
		std::terminate();
	}
	return *static_cast<test_active_async_state *>(context->state);
}

/**
 * @brief Release-publish one token and its optional read-only packet view.
 * @param state Context-local publication owner.
 * @param token Exact newly transferred token.
 * @param view Optional packet view, or null for standalone work.
 */
void publish_token(test_active_async_state &state, kinetum_async_token token,
		   const kinetum_async_packet_view *view) noexcept
{
	if (!kinetum_async_token_valid(&token)) {
		std::terminate();
	}
	if (state.token_handle.load(std::memory_order_relaxed) != KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE) {
		std::terminate();
	}
	state.token_ops.store(token.ops, std::memory_order_relaxed);
	state.token_portal.store(token.platform_opaque, std::memory_order_relaxed);
	state.packet_view_data.store(view == nullptr ? nullptr : view->data, std::memory_order_relaxed);
	state.packet_view_length.store(view == nullptr ? 0u : view->len, std::memory_order_relaxed);
	state.token_handle.store(token.handle.value, std::memory_order_release);
	// Self-completion uses the module's sole SPSC engine. Host-driven component
	// tests deliberately own their copied token directly and leave this lane empty.
	if (state.auto_complete.load(std::memory_order_relaxed) && !state.foreign_tokens.try_push(token)) {
		std::terminate();
	}
	state.begin_success_count.fetch_add(1u, std::memory_order_relaxed);
}

/**
 * @brief Begin one requested standalone or packet-bound operation.
 * @param state Context-local action owner.
 * @param active Exact callback-borrowed runtime services.
 * @param packet_bound true to transfer the current retained handle.
 */
void begin_requested_token(test_active_async_state &state, kinetum_active_ctx *active, bool packet_bound) noexcept
{
	const uint64_t user_tag = state.next_user_tag.exchange(0u, std::memory_order_relaxed);
	kinetum_async_packet_view view{};
	kinetum_async_token token = kinetum_invalid_async_token();
	if (packet_bound) {
		const kinetum_retained_packet_handle retained{
			state.retained_handle.load(std::memory_order_relaxed),
		};
		state.last_begin_retained_handle.store(retained.value, std::memory_order_relaxed);
		token = kinetum_active_begin_async_retained(active, retained, user_tag, &view);
	} else {
		token = kinetum_active_begin_async(active, user_tag);
	}
	if (!kinetum_async_token_valid(&token)) {
		state.begin_failure_count.fetch_add(1u, std::memory_order_relaxed);
		return;
	}
	if (packet_bound) {
		state.retained_handle.store(KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE, std::memory_order_relaxed);
	}
	if (state.abort_token_on_begin.exchange(false, std::memory_order_relaxed)) {
		kinetum_retained_packet_handle restored{KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE};
		if (!kinetum_active_abort_async(active, token, &restored)) {
			std::terminate();
		}
		state.retained_handle.store(restored.value, std::memory_order_relaxed);
		state.abort_success_count.fetch_add(1u, std::memory_order_relaxed);
		return;
	}
	publish_token(state, token, packet_bound ? &view : nullptr);
}

/**
 * @brief Apply one exact owner-worker disposition to a restored packet.
 * @param state Context-local action owner.
 * @param active Exact callback-borrowed runtime services.
 * @param completion Exact packet-bound completion.
 */
void dispose_completed_packet(test_active_async_state &state, kinetum_active_ctx *active,
			      const kinetum_async_completion &completion) noexcept
{
	const kinetum_retained_packet_handle retained = completion.retained;
	const auto action = state.completion_action.load(std::memory_order_relaxed);
	switch (action) {
	case async_completion_action::HOLD:
		state.retained_handle.store(retained.value, std::memory_order_relaxed);
		return;
	case async_completion_action::DROP:
		if (active->drop_retained(active, retained)) {
			state.dropped_completion_count.fetch_add(1u, std::memory_order_relaxed);
			return;
		}
		break;
	case async_completion_action::RECIRCULATE:
		if (kinetum_active_recirculate_retained(active, retained)) {
			state.recirculated_completion_count.fetch_add(1u, std::memory_order_relaxed);
			return;
		}
		break;
	case async_completion_action::RESUBMIT: {
		kinetum_async_packet_view view{};
		const auto token =
			kinetum_active_begin_async_retained(active, retained, completion.user_tag + 1u, &view);
		if (kinetum_async_token_valid(&token)) {
			publish_token(state, token, &view);
			state.resubmitted_completion_count.fetch_add(1u, std::memory_order_relaxed);
			return;
		}
		break;
	}
	default:
		std::terminate();
	}
	state.retained_handle.store(retained.value, std::memory_order_relaxed);
}

/**
 * @brief Retain or forward one exact active input.
 * @param context Exact owner-worker packet context.
 * @param active Exact callback-borrowed active services.
 * @param batch Exact active-ingest batch.
 * @return Sole forward mask after any exact retain transfer.
 */
static uint64_t test_async_ingest(kinetum_ctx *context, kinetum_active_ctx *active, kinetum_batch_t *batch) noexcept
{
	auto &state = state_from(context);
	state.ingest_count.fetch_add(1u, std::memory_order_relaxed);
	if (batch == nullptr) {
		return 0u;
	}
	const uint64_t requested = state.inline_async_mask.exchange(0u, std::memory_order_relaxed);
	if (requested != 0u) {
		uint64_t retained_mask = 0u;
		for (uint16_t lane = 0u; lane < batch->count; ++lane) {
			if ((requested & (UINT64_C(1) << lane)) == 0u) {
				continue;
			}
			const auto retained = active->retain_input(active, lane);
			if (retained.value == KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE) {
				continue;
			}
			retained_mask |= UINT64_C(1) << lane;
			kinetum_async_packet_view view{};
			const auto token = kinetum_active_begin_async_retained(active, retained, lane, &view);
			if (!kinetum_async_token_valid(&token) || view.data != batch->data[lane] ||
			    view.len != batch->len[lane]) {
				std::terminate();
			}
			state.begin_success_count.fetch_add(1u, std::memory_order_relaxed);
			if (state.abort_token_on_begin.exchange(false, std::memory_order_relaxed)) {
				kinetum_retained_packet_handle restored{KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE};
				if (!kinetum_active_abort_async(active, token, &restored)) {
					std::terminate();
				}
				state.retained_handle.store(restored.value, std::memory_order_relaxed);
				state.abort_success_count.fetch_add(1u, std::memory_order_relaxed);
			} else if (!kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_SUCCESS)) {
				std::terminate();
			}
		}
		return KINETUM_FORWARD_MASK(batch->count) & ~retained_mask;
	}
	const bool autonomous_retain = state.autonomous.load(std::memory_order_relaxed) &&
				       !state.autonomous_retention_done.exchange(true, std::memory_order_relaxed);
	if ((state.retain_on_next_ingest.exchange(false, std::memory_order_relaxed) || autonomous_retain) &&
	    active != nullptr) {
		const auto retained = active->retain_input(active, 0u);
		if (retained.value != KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE) {
			state.retained_handle.store(retained.value, std::memory_order_relaxed);
			if (state.autonomous.load(std::memory_order_relaxed)) {
				state.next_user_tag.store(1u, std::memory_order_relaxed);
				begin_requested_token(state, active, true);
			}
			return KINETUM_FORWARD_MASK(batch->count) & ~UINT64_C(1);
		}
	}
	return KINETUM_FORWARD_MASK(batch->count);
}

/**
 * @brief Consume exact completion, cancellation-drain, and begin actions.
 * @param context Exact owner-worker packet context.
 * @param active Exact callback-borrowed active services.
 * @param triggers Complete runtime trigger mask for this turn.
 */
static void test_async_run(kinetum_ctx *context, kinetum_active_ctx *active, uint32_t triggers) noexcept
{
	auto &state = state_from(context);
	state.run_count.fetch_add(1u, std::memory_order_relaxed);
	if (active == nullptr || active->runtime_services == nullptr) {
		std::terminate();
	}
	if ((triggers & KINETUM_TRIGGER_ASYNC_COMPLETE) != 0u) {
		state.async_trigger_count.fetch_add(1u, std::memory_order_relaxed);
	}
	if ((triggers & KINETUM_TRIGGER_DRAIN) != 0u) {
		state.drain_trigger_count.fetch_add(1u, std::memory_order_relaxed);
	}

	uint32_t completion_count = 0u;
	const auto *completions = kinetum_active_async_completions(active, &completion_count);
	if ((completion_count == 0u) != (completions == nullptr) ||
	    ((triggers & KINETUM_TRIGGER_ASYNC_COMPLETE) != 0u) != (completion_count != 0u)) {
		std::terminate();
	}
	for (uint32_t index = 0u; index < completion_count; ++index) {
		const auto &completion = completions[index];
		if (completion.handle.value == KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE ||
		    completion.outcome <= KINETUM_ASYNC_OUTCOME_UNSPECIFIED ||
		    completion.outcome > KINETUM_ASYNC_OUTCOME_FAILED || completion._padding != 0u) {
			std::terminate();
		}
		state.token_handle.store(KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE, std::memory_order_release);
		state.last_completion_handle.store(completion.handle.value, std::memory_order_relaxed);
		state.last_completion_user_tag.store(completion.user_tag, std::memory_order_relaxed);
		state.last_completion_outcome.store(completion.outcome, std::memory_order_relaxed);
		state.last_completion_retained.store(completion.retained.value, std::memory_order_relaxed);
		state.completion_count.fetch_add(1u, std::memory_order_relaxed);
		if (completion.retained.value != KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE) {
			dispose_completed_packet(state, active, completion);
		} else if (state.completion_action.load(std::memory_order_relaxed) ==
			   async_completion_action::RESUBMIT) {
			const auto token = kinetum_active_begin_async(active, completion.user_tag + 1u);
			if (kinetum_async_token_valid(&token)) {
				publish_token(state, token, nullptr);
				state.resubmitted_completion_count.fetch_add(1u, std::memory_order_relaxed);
			}
		}
	}

	if (state.begin_standalone_on_next_run.exchange(false, std::memory_order_relaxed)) {
		begin_requested_token(state, active, false);
	}
	if (state.begin_retained_on_next_run.exchange(false, std::memory_order_relaxed)) {
		begin_requested_token(state, active, true);
	}
	if ((triggers & KINETUM_TRIGGER_DRAIN) != 0u) {
		const kinetum_retained_packet_handle retained{
			state.retained_handle.load(std::memory_order_relaxed),
		};
		if (retained.value != KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE &&
		    active->drop_retained(active, retained)) {
			state.retained_handle.store(KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE,
						    std::memory_order_relaxed);
			state.dropped_completion_count.fetch_add(1u, std::memory_order_relaxed);
		}
	}
}

/** @brief Descriptor proving the complete tracked-async active contract. */
static const kinetum_module TEST_ACTIVE_ASYNC_MODULE{
	.module_id = "kinetum.test_active_async",
	.module_version = "1.0.0",
	.abi_version = KINETUM_MODULE_ABI_VERSION,
	.flags = KINETUM_MOD_F_LIVE_EPOCH_TRANSITION | KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK,
	.mode = KINETUM_MODULE_ACTIVE,
	.prepare_config = kinetum_noop_prepare_config,
	.activate_config = kinetum_noop_activate_config,
	.retire_config = kinetum_noop_retire_config,
	.process = nullptr,
	.ingest = test_async_ingest,
	.run = test_async_run,
	.on_control = nullptr,
	.init = test_async_init,
	.fini = test_async_fini,
	.health_check = nullptr,
	.select_contexts = nullptr,
};

}  // namespace

/** @brief Export the sole exact active-async descriptor. @return Sole descriptor address. */
extern "C" KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return &TEST_ACTIVE_ASYNC_MODULE;
}
