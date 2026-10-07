// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file test_active_async_module_state.hpp
 * @brief Shared context-local state for the tracked-async module canary.
 * @author Fleming Patel
 *
 * The loaded image and host tests consume one exact C++ state type without
 * exporting an image symbol. Owner-worker callbacks publish token identity and
 * completion observations through release/acquire atomics. The module's
 * pre-created foreign engine consumes copied tokens through one bounded SPSC
 * handoff; host tests may reconstruct the same published token observation.
 *
 * @par Thread Safety
 * The module owner is the sole callback-state writer and SPSC producer. The
 * pre-created foreign engine is the sole SPSC consumer. Host test threads may
 * author actions and observe results through the atomics documented below.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>

#include <kinetum/algo/queue.hpp>
#include <kinetum/kinetum_sdk.h>

namespace kinetum::test
{

/** Exact owner action applied to one packet-bound async completion. */
enum class async_completion_action : uint8_t {
	HOLD = 0,     ///< Keep the restored retained handle live.
	DROP,	      ///< Transfer the restored packet to terminal drop.
	RECIRCULATE,  ///< Transfer the restored packet to same-instance staging.
	RESUBMIT,     ///< Transfer the restored packet into another async token.
};

/** @brief Context-local action and observation state for the async canary. */
struct test_active_async_state {
	/** Minimum legal SPSC capacity; the engine pops before completion can enable replacement. */
	static constexpr std::size_t FOREIGN_TOKEN_QUEUE_CAPACITY = 2u;

	std::atomic<bool> autonomous{true};		     ///< Enable the runtime integration scenario.
	std::atomic<bool> auto_complete{true};		     ///< Let the pre-created foreign thread complete tokens.
	std::atomic<bool> stop_foreign{false};		     ///< Exact FINI request for the foreign thread.
	std::atomic<bool> autonomous_retention_done{false};  ///< One-shot runtime packet retention.
	std::atomic<bool> retain_on_next_ingest{false};	     ///< Retain one next packet input.
	std::atomic<uint64_t> inline_async_mask{0};  ///< Ingest lanes to retain and complete before callback return.
	std::atomic<bool> begin_standalone_on_next_run{false};	///< Begin one standalone token.
	std::atomic<bool> begin_retained_on_next_run{false};	///< Transfer the retained packet.
	std::atomic<bool> abort_token_on_begin{false};		///< Abort the just-created token synchronously.
	std::atomic<uint64_t> next_user_tag{0};			///< Correlation value for the next token.
	std::atomic<async_completion_action> completion_action{
		async_completion_action::RECIRCULATE};				///< Packet completion disposition.
	std::atomic<int32_t> automatic_outcome{KINETUM_ASYNC_OUTCOME_SUCCESS};	///< Foreign-thread outcome.

	std::atomic<uint64_t> retained_handle{
		KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE};	///< Current module-owned retained handle.
	std::atomic<uint64_t> last_begin_retained_handle{
		KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE};	///< Handle invalidated by last packet begin.
	std::atomic<uint64_t> token_handle{
		KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE};  ///< Release-published transferred token identity.
	std::atomic<const kinetum_async_token_ops *> token_ops{nullptr};  ///< Token operation table.
	std::atomic<void *> token_portal{nullptr};			  ///< Token runtime portal.
	std::atomic<const void *> packet_view_data{nullptr};		  ///< Last read-only packet-view address.
	std::atomic<uint32_t> packet_view_length{0};			  ///< Last read-only packet-view length.
	kinetum::algo::spsc_ring_static<kinetum_async_token, FOREIGN_TOKEN_QUEUE_CAPACITY>
		foreign_tokens;	 ///< Owner-to-foreign copied-token handoff.

	std::atomic<uint32_t> ingest_count{0};		    ///< Exact INGEST callback count.
	std::atomic<uint32_t> run_count{0};		    ///< Exact RUN callback count.
	std::atomic<uint32_t> begin_success_count{0};	    ///< Successfully transferred tokens.
	std::atomic<uint32_t> begin_failure_count{0};	    ///< Bounded begin refusals.
	std::atomic<uint32_t> abort_success_count{0};	    ///< Exact synchronous aborts.
	std::atomic<uint32_t> completion_count{0};	    ///< Exact delivered completion count.
	std::atomic<uint32_t> async_trigger_count{0};	    ///< RUN calls carrying ASYNC_COMPLETE.
	std::atomic<uint32_t> drain_trigger_count{0};	    ///< RUN calls carrying DRAIN.
	std::atomic<uint64_t> last_completion_handle{0};    ///< Last delivered token identity.
	std::atomic<uint64_t> last_completion_user_tag{0};  ///< Last delivered correlation value.
	std::atomic<int32_t> last_completion_outcome{
		KINETUM_ASYNC_OUTCOME_UNSPECIFIED};  ///< Last exact foreign outcome.
	std::atomic<uint64_t> last_completion_retained{
		KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE};	 ///< Last restored packet handle.
	std::atomic<uint32_t> dropped_completion_count{0};	 ///< Completion packets transferred to drop.
	std::atomic<uint32_t> recirculated_completion_count{0};	 ///< Completion packets recirculated.
	std::atomic<uint32_t> resubmitted_completion_count{0};	 ///< Completion packets resubmitted.
	std::thread foreign_thread;				 ///< One pre-created foreign completion engine.
};

/**
 * @brief Reconstruct the exact release-published token for a foreign test thread.
 * @param state Shared canary state.
 * @return Exact SDK token, or the fixed invalid representation when absent.
 */
[[nodiscard]] inline kinetum_async_token load_test_async_token(const test_active_async_state &state) noexcept
{
	const uint64_t handle = state.token_handle.load(std::memory_order_acquire);
	if (handle == KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE) {
		return kinetum_invalid_async_token();
	}
	return kinetum_async_token{
		.handle = {handle},
		.ops = state.token_ops.load(std::memory_order_relaxed),
		.platform_opaque = state.token_portal.load(std::memory_order_relaxed),
	};
}

}  // namespace kinetum::test
