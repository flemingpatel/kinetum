// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file test_active_module_state.hpp
 * @brief Shared exact context-local state for the active test image and host tests.
 * @author Fleming Patel
 *
 * One header gives the loaded test image and the observing test executable the
 * same C++ type. The object remains context-local module state; sharing its type
 * for test inspection does not export a symbol or create runtime authority.
 *
 * @par Thread Safety
 * The module owner writes through relaxed atomics. Test control/observation
 * threads may read or author test actions through the same atomics.
 */

#include <array>
#include <atomic>
#include <cstdint>

#include <kinetum/kinetum_sdk.h>

namespace kinetum::test
{

/** @brief Context-local observation and action state for the exact active test module. */
struct test_active_state {
	std::atomic<uint32_t> ingest_call_count{0};		   ///< Ingest callback invocations.
	std::atomic<uint32_t> ingest_total_packets{0};		   ///< Total ingested packet records.
	std::atomic<uint64_t> last_ingest_epoch{0};		   ///< Most recent exact packet epoch.
	std::atomic<std::uintptr_t> last_ingest_packet_config{0};  ///< Most recent packet-config identity.
	std::atomic<uint32_t> run_call_count{0};		   ///< Active run callback invocations.
	std::atomic<uint32_t> last_triggers{0};			   ///< Most recent trigger mask.
	std::atomic<uint32_t> last_expired_count{0};		   ///< Most recent expired-timer count.
	std::atomic<uint64_t> last_now_ns{0};			   ///< Most recent owner-cached time.
	std::atomic<uint64_t> last_active_epoch{0};		   ///< Most recent exact active epoch.
	std::atomic<uint32_t> control_call_count{0};		   ///< Control callback invocations.
	std::atomic<uint32_t> last_control_subtype{0};		   ///< Most recent control subtype.
	std::atomic<uint32_t> last_control_len{0};		   ///< Most recent control payload length.
	std::atomic<uint8_t> last_control_first_byte{0};	   ///< First copied payload byte when present.
	std::atomic<uint32_t> emit_call_count{0};		   ///< Active emit calls attempted.
	std::atomic<uint32_t> emit_total_packets{0};		   ///< Origin records accepted by emit.
	std::atomic<uint32_t> pull_ready_count{0};		   ///< Pull-ready triggers observed.
	std::atomic<bool> emit_on_next_run{true};		   ///< Arm one origin batch on the next run.
	std::atomic<uint8_t> emit_dscp{0};			   ///< DSCP authored into the next origin.
	std::atomic<uint32_t> emit_platform_flags{0};		   ///< Parser facts authored into the next origin.
	std::atomic<uint8_t> emit_proto{0};			   ///< IP protocol authored into the next origin.
	std::atomic<uint16_t> pull_target_idx{KINETUM_NEXT_STAGE_UNSET};  ///< Requested upstream stage.
	std::atomic<uint32_t> pull_repeat_count{1};			  ///< Calls for one pending PULL request.
	std::atomic<bool> retain_on_next_ingest{true};			  ///< Retain one next ingest lane.
	std::atomic<uint32_t> retain_lane{0};				  ///< Exact lane supplied to retain_input.
	std::atomic<uint64_t> retain_batch_mask{0};    ///< Occupied lanes to retain in one invocation.
	std::atomic<uint64_t> retained_batch_mask{0};  ///< Lanes whose exact handles remain owned.
	std::array<std::atomic<uint64_t>, KINETUM_MAX_BURST> retained_batch_handles{};	///< Handles for owned mask bits.
	std::atomic<bool> retain_twice_on_next_ingest{false};  ///< Deliberately violate one-lane retention.
	std::atomic<uint64_t> retained_handle{KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE};  ///< Live handle.
	std::atomic<bool> emit_retained_on_next_run{false};  ///< Submit retained work for dispatch.
	std::atomic<uint16_t> retained_emit_next_stage{KINETUM_NEXT_STAGE_UNSET};  ///< Retained dispatch target.
	std::atomic<bool> drop_retained_on_next_run{false};			   ///< Submit retained work for drop.
	std::atomic<uint64_t> arm_timer_delay_ns{UINT64_C(1000000)};  ///< Relative timer delay for next run.
	std::atomic<uint64_t> timer_handle{KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE};	///< Live timer handle.
	std::atomic<bool> cancel_timer_on_next_run{false};		      ///< Cancel the exact live timer.
	std::atomic<uint32_t> cancelled_timer_count{0};			      ///< Successful exact cancellations.
	std::atomic<uint32_t> timer_trigger_count{0};			      ///< TIMER-triggered run count.
	std::atomic<uint32_t> drain_trigger_count{0};			      ///< DRAIN-triggered run count.
	std::atomic<uint32_t> last_active_state_flags{0};		      ///< Most recent active-context state.
	std::atomic<uint64_t> last_drain_target_epoch{0};		      ///< Most recent drain target.
	std::atomic<uint16_t> post_control_target{KINETUM_NEXT_STAGE_UNSET};  ///< Next control destination.
	std::atomic<uint32_t> post_control_subtype{0};			      ///< Next control subtype.
	std::atomic<uint32_t> post_control_repeat_count{1};		      ///< Messages in the next control prefix.
	std::atomic<uint32_t> post_control_payload_len{0};		      ///< Next borrowed control payload length.
	std::atomic<uint8_t> post_control_payload_value{0};		      ///< Byte repeated in the next payload.
	std::atomic<uint32_t> posted_control_count{0};			      ///< Accepted control publications.
	std::atomic<bool> mutate_control_context_on_next{false};	      ///< Corrupt one callback-local test copy.
	std::atomic<uint32_t> invalid_control_context_count{0};		      ///< Nonfresh active contexts observed.
};

}  // namespace kinetum::test
