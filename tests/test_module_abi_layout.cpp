// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_module_abi_layout.cpp
 * @brief Runtime evidence for every fixed-width module ABI layout contract.
 * @author Fleming Patel
 *
 * The SDK header carries compile-time assertions so every module translation
 * unit rejects offset drift. These tests mirror that public contract in the
 * platform gate, making the exact versioned layout visible as named evidence.
 */

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <kinetum/kinetum_sdk.hpp>

namespace kinetum::sdk
{

/** @brief Pin the complete SoA batch layout including exact-config tail fields. */
TEST(module_abi_layout, packet_batch)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_batch_t>);
	EXPECT_EQ(alignof(kinetum_batch_t), 64u);
	EXPECT_EQ(sizeof(kinetum_batch_t), 4224u);
	EXPECT_EQ(offsetof(kinetum_batch_t, data), 0u);
	EXPECT_EQ(offsetof(kinetum_batch_t, len), 512u);
	EXPECT_EQ(offsetof(kinetum_batch_t, l3_off), 768u);
	EXPECT_EQ(offsetof(kinetum_batch_t, l4_off), 896u);
	EXPECT_EQ(offsetof(kinetum_batch_t, src_ip), 1024u);
	EXPECT_EQ(offsetof(kinetum_batch_t, dst_ip), 1280u);
	EXPECT_EQ(offsetof(kinetum_batch_t, src_port), 1536u);
	EXPECT_EQ(offsetof(kinetum_batch_t, dst_port), 1664u);
	EXPECT_EQ(offsetof(kinetum_batch_t, proto), 1792u);
	EXPECT_EQ(offsetof(kinetum_batch_t, dscp), 1856u);
	EXPECT_EQ(offsetof(kinetum_batch_t, platform_flags), 1920u);
	EXPECT_EQ(offsetof(kinetum_batch_t, user_flags), 2176u);
	EXPECT_EQ(offsetof(kinetum_batch_t, flow_hash), 2432u);
	EXPECT_EQ(offsetof(kinetum_batch_t, input_port), 2688u);
	EXPECT_EQ(offsetof(kinetum_batch_t, output_port), 2816u);
	EXPECT_EQ(offsetof(kinetum_batch_t, next_stage), 2944u);
	EXPECT_EQ(offsetof(kinetum_batch_t, ts_ns), 3072u);
	EXPECT_EQ(offsetof(kinetum_batch_t, user_meta), 3584u);
	EXPECT_EQ(offsetof(kinetum_batch_t, user_meta_valid), 4096u);
	EXPECT_EQ(offsetof(kinetum_batch_t, count), 4160u);
	EXPECT_EQ(offsetof(kinetum_batch_t, region_id), 4162u);
	EXPECT_EQ(offsetof(kinetum_batch_t, padding), 4164u);
	EXPECT_EQ(offsetof(kinetum_batch_t, epoch), 4168u);
	EXPECT_EQ(offsetof(kinetum_batch_t, epoch_config), 4176u);
	EXPECT_EQ(offsetof(kinetum_batch_t, ctx), 4184u);
	uint32_t mask_count = 1;
	EXPECT_EQ(KINETUM_FORWARD_MASK(mask_count++), UINT64_C(1));
	EXPECT_EQ(mask_count, 2u);
	EXPECT_EQ(KINETUM_FORWARD_MASK(KINETUM_MAX_BURST), UINT64_MAX);

	kinetum_batch_t batch{};
	uint64_t disposition = 0;
	uint32_t forward_index = 2;
	KINETUM_FORWARD(disposition, &batch, forward_index++, 7);
	EXPECT_EQ(forward_index, 3u);
	EXPECT_EQ(disposition, UINT64_C(1) << 2);
	EXPECT_EQ(batch.output_port[2], 7u);
	uint32_t drop_index = 2;
	KINETUM_DROP(disposition, drop_index++);
	EXPECT_EQ(drop_index, 3u);
	EXPECT_EQ(disposition, 0u);
}

/** @brief Pin the provider-neutral active-origin batch and every field offset. */
TEST(module_abi_layout, emit_batch)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_emit_batch_t>);
	EXPECT_EQ(alignof(kinetum_emit_batch_t), 64u);
	EXPECT_EQ(sizeof(kinetum_emit_batch_t), 4224u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, data), 0u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, len), 512u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, l3_off), 768u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, l4_off), 896u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, src_ip), 1024u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, dst_ip), 1280u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, src_port), 1536u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, dst_port), 1664u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, proto), 1792u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, dscp), 1856u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, platform_flags), 1920u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, user_flags), 2176u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, flow_hash), 2432u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, input_port), 2688u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, output_port), 2816u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, next_stage), 2944u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, ts_ns), 3072u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, user_meta), 3584u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, user_meta_valid), 4096u);
	EXPECT_EQ(offsetof(kinetum_emit_batch_t, count), 4160u);
}

/** @brief Pin the owner-local counter layout. */
TEST(module_abi_layout, counter)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_counter>);
	EXPECT_EQ(alignof(kinetum_counter), 64u);
	EXPECT_EQ(sizeof(kinetum_counter), 64u);
	EXPECT_EQ(offsetof(kinetum_counter, value), 0u);
	EXPECT_EQ(offsetof(kinetum_counter, name), 8u);
}

/** @brief Pin the owner-local histogram layout. */
TEST(module_abi_layout, histogram)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_histogram>);
	EXPECT_EQ(alignof(kinetum_histogram), 64u);
	EXPECT_EQ(sizeof(kinetum_histogram), 192u);
	EXPECT_EQ(offsetof(kinetum_histogram, highest_trackable_value), 0u);
	EXPECT_EQ(offsetof(kinetum_histogram, total_count), 8u);
	EXPECT_EQ(offsetof(kinetum_histogram, min_value), 16u);
	EXPECT_EQ(offsetof(kinetum_histogram, max_value), 24u);
	EXPECT_EQ(offsetof(kinetum_histogram, sum), 32u);
	EXPECT_EQ(offsetof(kinetum_histogram, counts), 40u);
	EXPECT_EQ(offsetof(kinetum_histogram, counts_len), 48u);
	EXPECT_EQ(offsetof(kinetum_histogram, significant_digits), 52u);
	EXPECT_EQ(offsetof(kinetum_histogram, unit_magnitude), 56u);
	EXPECT_EQ(offsetof(kinetum_histogram, sub_bucket_half_count_magnitude), 60u);
	EXPECT_EQ(offsetof(kinetum_histogram, sub_bucket_count), 64u);
	EXPECT_EQ(offsetof(kinetum_histogram, sub_bucket_half_count), 68u);
	EXPECT_EQ(offsetof(kinetum_histogram, sub_bucket_mask), 72u);
	EXPECT_EQ(offsetof(kinetum_histogram, bucket_count), 76u);
	EXPECT_EQ(offsetof(kinetum_histogram, name), 80u);
}

/** @brief Pin the cold percentile-summary layout. */
TEST(module_abi_layout, percentiles)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_percentiles>);
	EXPECT_EQ(alignof(kinetum_percentiles), 8u);
	EXPECT_EQ(sizeof(kinetum_percentiles), 64u);
	EXPECT_EQ(offsetof(kinetum_percentiles, p50), 0u);
	EXPECT_EQ(offsetof(kinetum_percentiles, p90), 8u);
	EXPECT_EQ(offsetof(kinetum_percentiles, p99), 16u);
	EXPECT_EQ(offsetof(kinetum_percentiles, p999), 24u);
	EXPECT_EQ(offsetof(kinetum_percentiles, max), 32u);
	EXPECT_EQ(offsetof(kinetum_percentiles, min), 40u);
	EXPECT_EQ(offsetof(kinetum_percentiles, count), 48u);
	EXPECT_EQ(offsetof(kinetum_percentiles, sum), 56u);
}

/** @brief Pin the immutable lifecycle identity layout. */
TEST(module_abi_layout, lifecycle_identity)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_lifecycle_identity>);
	EXPECT_EQ(alignof(kinetum_lifecycle_identity), 8u);
	EXPECT_EQ(sizeof(kinetum_lifecycle_identity), 48u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_identity, module_id), 0u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_identity, context_instance_id), 8u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_identity, module_image_index), 16u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_identity, context_index), 20u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_identity, worker_index), 24u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_identity, cpu_core_id), 28u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_identity, numa_node), 32u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_identity, module_context_ordinal), 36u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_identity, module_context_count), 40u);
}

/** @brief Pin every lifecycle service-table callback offset. */
TEST(module_abi_layout, lifecycle_operations)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_lifecycle_ops>);
	EXPECT_EQ(alignof(kinetum_lifecycle_ops), 8u);
	EXPECT_EQ(sizeof(kinetum_lifecycle_ops), 72u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ops, get_identity), 0u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ops, allocate_context), 8u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ops, release_context), 16u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ops, allocate_epoch), 24u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ops, register_counter), 32u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ops, register_histogram), 40u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ops, log), 48u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ops, deadline_ns), 56u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ops, cancellation_requested), 64u);
}

/** @brief Pin the public two-pointer lifecycle shell. */
TEST(module_abi_layout, lifecycle_shell)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_lifecycle_ctx>);
	EXPECT_EQ(alignof(kinetum_lifecycle_ctx), 8u);
	EXPECT_EQ(sizeof(kinetum_lifecycle_ctx), 16u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ctx, ops), 0u);
	EXPECT_EQ(offsetof(kinetum_lifecycle_ctx, platform_opaque), 8u);
}

/** @brief Pin the one-cache-line live packet context. */
TEST(module_abi_layout, packet_context)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_ctx>);
	EXPECT_EQ(alignof(kinetum_ctx), 64u);
	EXPECT_EQ(sizeof(kinetum_ctx), 64u);
	EXPECT_EQ(offsetof(kinetum_ctx, state), 0u);
	EXPECT_EQ(offsetof(kinetum_ctx, numa_node), 8u);
	EXPECT_EQ(offsetof(kinetum_ctx, cpu_core_id), 12u);
	EXPECT_EQ(offsetof(kinetum_ctx, worker_index), 16u);
}

/** @brief Pin the explicit prepared-ownership record. */
TEST(module_abi_layout, prepared_config)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_prepared_config>);
	EXPECT_EQ(alignof(kinetum_prepared_config), 8u);
	EXPECT_EQ(sizeof(kinetum_prepared_config), 16u);
	EXPECT_EQ(offsetof(kinetum_prepared_config, owner_handle), 0u);
	EXPECT_EQ(offsetof(kinetum_prepared_config, packet_config), 8u);
}

/** @brief Pin module assessment and host publication layouts and composition. */
TEST(module_abi_layout, health_assessment_and_signal)
{
	EXPECT_EQ(KINETUM_HEALTH_REASON_CAPACITY, 40u);
	EXPECT_EQ(KINETUM_HEALTH_F_KNOWN_MASK,
		  KINETUM_HEALTH_F_DEGRADED | KINETUM_HEALTH_F_CRITICAL | KINETUM_HEALTH_F_CONFIG_ISSUE);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_health_assessment>);
	EXPECT_EQ(alignof(kinetum_health_assessment), 4u);
	EXPECT_EQ(sizeof(kinetum_health_assessment), 48u);
	EXPECT_EQ(offsetof(kinetum_health_assessment, health_score), 0u);
	EXPECT_EQ(offsetof(kinetum_health_assessment, _padding), 1u);
	EXPECT_EQ(offsetof(kinetum_health_assessment, flags), 4u);
	EXPECT_EQ(offsetof(kinetum_health_assessment, reason), 8u);

	EXPECT_TRUE(std::is_standard_layout_v<kinetum_health_signal>);
	EXPECT_EQ(alignof(kinetum_health_signal), 64u);
	EXPECT_EQ(sizeof(kinetum_health_signal), 64u);
	EXPECT_EQ(offsetof(kinetum_health_signal, assessment), 0u);
	EXPECT_EQ(offsetof(kinetum_health_signal, epoch), 48u);
	EXPECT_EQ(offsetof(kinetum_health_signal, timestamp_ns), 56u);

	kinetum_health_assessment assessment{};
	assessment.health_score = 75;
	assessment.flags = KINETUM_HEALTH_F_DEGRADED;
	set_health_reason_literal(assessment, "bounded owner assessment");

	kinetum_health_signal signal{};
	signal.assessment = assessment;
	signal.epoch = 17;
	signal.timestamp_ns = 23;
	EXPECT_EQ(signal.assessment.health_score, 75u);
	EXPECT_EQ(signal.assessment.flags, KINETUM_HEALTH_F_DEGRADED);
	EXPECT_STREQ(signal.assessment.reason, "bounded owner assessment");
	EXPECT_EQ(signal.epoch, 17u);
	EXPECT_EQ(signal.timestamp_ns, 23u);
}

/** @brief Pin the active-stage control message layout. */
TEST(module_abi_layout, control_message)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_control_msg>);
	EXPECT_EQ(alignof(kinetum_control_msg), 8u);
	EXPECT_EQ(sizeof(kinetum_control_msg), 16u);
	EXPECT_EQ(offsetof(kinetum_control_msg, data), 0u);
	EXPECT_EQ(offsetof(kinetum_control_msg, len), 8u);
	EXPECT_EQ(offsetof(kinetum_control_msg, subtype), 12u);
}

/** @brief Pin every owner-worker active scheduling service offset. */
TEST(module_abi_layout, active_context)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_retained_packet_handle>);
	EXPECT_EQ(alignof(kinetum_retained_packet_handle), 8u);
	EXPECT_EQ(sizeof(kinetum_retained_packet_handle), 8u);
	EXPECT_EQ(offsetof(kinetum_retained_packet_handle, value), 0u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_active_timer_handle>);
	EXPECT_EQ(alignof(kinetum_active_timer_handle), 8u);
	EXPECT_EQ(sizeof(kinetum_active_timer_handle), 8u);
	EXPECT_EQ(offsetof(kinetum_active_timer_handle, value), 0u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_async_work_handle>);
	EXPECT_EQ(alignof(kinetum_async_work_handle), 8u);
	EXPECT_EQ(sizeof(kinetum_async_work_handle), 8u);
	EXPECT_EQ(offsetof(kinetum_async_work_handle, value), 0u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_async_outcome>);
	EXPECT_EQ(alignof(kinetum_async_outcome), 4u);
	EXPECT_EQ(sizeof(kinetum_async_outcome), 4u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_async_packet_view>);
	EXPECT_EQ(alignof(kinetum_async_packet_view), 8u);
	EXPECT_EQ(sizeof(kinetum_async_packet_view), 16u);
	EXPECT_EQ(offsetof(kinetum_async_packet_view, data), 0u);
	EXPECT_EQ(offsetof(kinetum_async_packet_view, len), 8u);
	EXPECT_EQ(offsetof(kinetum_async_packet_view, _padding), 12u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_async_token_ops>);
	EXPECT_EQ(alignof(kinetum_async_token_ops), 8u);
	EXPECT_EQ(sizeof(kinetum_async_token_ops), 16u);
	EXPECT_EQ(offsetof(kinetum_async_token_ops, complete), 0u);
	EXPECT_EQ(offsetof(kinetum_async_token_ops, cancellation_requested), 8u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_async_token>);
	EXPECT_EQ(alignof(kinetum_async_token), 8u);
	EXPECT_EQ(sizeof(kinetum_async_token), 24u);
	EXPECT_EQ(offsetof(kinetum_async_token, handle), 0u);
	EXPECT_EQ(offsetof(kinetum_async_token, ops), 8u);
	EXPECT_EQ(offsetof(kinetum_async_token, platform_opaque), 16u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_async_completion>);
	EXPECT_EQ(alignof(kinetum_async_completion), 8u);
	EXPECT_EQ(sizeof(kinetum_async_completion), 32u);
	EXPECT_EQ(offsetof(kinetum_async_completion, handle), 0u);
	EXPECT_EQ(offsetof(kinetum_async_completion, retained), 8u);
	EXPECT_EQ(offsetof(kinetum_async_completion, user_tag), 16u);
	EXPECT_EQ(offsetof(kinetum_async_completion, outcome), 24u);
	EXPECT_EQ(offsetof(kinetum_async_completion, _padding), 28u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_active_runtime_services>);
	EXPECT_EQ(alignof(kinetum_active_runtime_services), 8u);
	EXPECT_EQ(sizeof(kinetum_active_runtime_services), 56u);
	EXPECT_EQ(offsetof(kinetum_active_runtime_services, completions), 0u);
	EXPECT_EQ(offsetof(kinetum_active_runtime_services, completion_count), 8u);
	EXPECT_EQ(offsetof(kinetum_active_runtime_services, _padding), 12u);
	EXPECT_EQ(offsetof(kinetum_active_runtime_services, begin_async), 16u);
	EXPECT_EQ(offsetof(kinetum_active_runtime_services, begin_async_retained), 24u);
	EXPECT_EQ(offsetof(kinetum_active_runtime_services, abort_async), 32u);
	EXPECT_EQ(offsetof(kinetum_active_runtime_services, recirculate_retained), 40u);
	EXPECT_EQ(offsetof(kinetum_active_runtime_services, platform_opaque), 48u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_active_ctx>);
	EXPECT_EQ(alignof(kinetum_active_ctx), 8u);
	EXPECT_EQ(sizeof(kinetum_active_ctx), 136u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, now_ns), 0u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, active_epoch), 8u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, active_packet_config), 16u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, drain_target_epoch), 24u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, expired), 32u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, drain_retained), 40u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, expired_count), 48u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, drain_retained_count), 52u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, region_id), 56u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, state_flags), 60u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, emit), 64u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, retain_input), 72u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, emit_retained), 80u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, drop_retained), 88u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, arm_timer_after), 96u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, cancel_timer), 104u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, post_control), 112u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, request_pull), 120u);
	EXPECT_EQ(offsetof(kinetum_active_ctx, runtime_services), 128u);
}

/** @brief Pin every exact module-descriptor field offset. */
TEST(module_abi_layout, module_descriptor)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_module>);
	EXPECT_EQ(alignof(kinetum_module), 8u);
	EXPECT_EQ(sizeof(kinetum_module), 120u);
	EXPECT_EQ(offsetof(kinetum_module, module_id), 0u);
	EXPECT_EQ(offsetof(kinetum_module, module_version), 8u);
	EXPECT_EQ(offsetof(kinetum_module, abi_version), 16u);
	EXPECT_EQ(offsetof(kinetum_module, flags), 20u);
	EXPECT_EQ(offsetof(kinetum_module, mode), 24u);
	EXPECT_EQ(offsetof(kinetum_module, prepare_config), 32u);
	EXPECT_EQ(offsetof(kinetum_module, activate_config), 40u);
	EXPECT_EQ(offsetof(kinetum_module, retire_config), 48u);
	EXPECT_EQ(offsetof(kinetum_module, process), 56u);
	EXPECT_EQ(offsetof(kinetum_module, ingest), 64u);
	EXPECT_EQ(offsetof(kinetum_module, run), 72u);
	EXPECT_EQ(offsetof(kinetum_module, on_control), 80u);
	EXPECT_EQ(offsetof(kinetum_module, init), 88u);
	EXPECT_EQ(offsetof(kinetum_module, fini), 96u);
	EXPECT_EQ(offsetof(kinetum_module, health_check), 104u);
	EXPECT_EQ(offsetof(kinetum_module, select_contexts), 112u);
}

/** @brief Pin the stateless selector's complete read-only ABI projection. */
TEST(module_abi_layout, context_selection_layout)
{
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_context_selection_batch>);
	EXPECT_TRUE(std::is_trivially_copyable_v<kinetum_context_selection_batch>);
	EXPECT_EQ(sizeof(kinetum_context_selection_batch), 1536u);
	EXPECT_EQ(alignof(kinetum_context_selection_batch), 64u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, src_ip), 0u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, dst_ip), 256u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, platform_flags), 512u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, flow_hash), 768u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, src_port), 1024u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, dst_port), 1152u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, input_port), 1280u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, proto), 1408u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, count), 1472u);
	EXPECT_EQ(offsetof(kinetum_context_selection_batch, padding), 1474u);
	EXPECT_TRUE(std::is_standard_layout_v<kinetum_context_selection_targets>);
	EXPECT_EQ(sizeof(kinetum_context_selection_targets), 24u);
	EXPECT_EQ(alignof(kinetum_context_selection_targets), 8u);
	EXPECT_EQ(offsetof(kinetum_context_selection_targets, context_count), 0u);
	EXPECT_EQ(offsetof(kinetum_context_selection_targets, permitted_count), 4u);
	EXPECT_EQ(offsetof(kinetum_context_selection_targets, permitted_ordinals), 8u);
	EXPECT_EQ(offsetof(kinetum_context_selection_targets, permitted_bitmap), 16u);
}

/** @brief Pin fixed scalar widths, exact version, and the declared flag set. */
TEST(module_abi_layout, scalar_version_and_flag_contract)
{
	EXPECT_EQ(sizeof(void *), 8u);
	EXPECT_EQ(sizeof(bool), 1u);
	EXPECT_EQ(sizeof(kinetum_error), 4u);
	EXPECT_EQ(sizeof(kinetum_module_mode), 4u);
	EXPECT_EQ(KINETUM_PKT_F_PLATFORM_MASK, 0x4du);
	EXPECT_EQ(KINETUM_MODULE_ABI_VERSION, 0x00010000u);
	EXPECT_EQ(KINETUM_MOD_F_KNOWN_MASK, 0xfu);
	EXPECT_EQ(KINETUM_MOD_F_CONTEXT_SELECTION, 0x8u);
	EXPECT_EQ(KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK, 0x4u);
	EXPECT_EQ(KINETUM_AUTHORED_ACTIVE_TRIGGER_MASK, 0x0fu);
	EXPECT_EQ(KINETUM_TRIGGER_DRAIN, 0x10u);
	EXPECT_EQ(KINETUM_TRIGGER_ASYNC_COMPLETE, 0x20u);
	EXPECT_EQ(KINETUM_CONTROL_SUBTYPE_GENERIC, 0u);
	EXPECT_EQ(KINETUM_CONTROL_SUBTYPE_FEEDBACK, 1u);
	EXPECT_EQ(KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE, UINT64_MAX);
	EXPECT_EQ(KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE, UINT64_MAX);
	EXPECT_EQ(KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE, UINT64_MAX);
	EXPECT_EQ(KINETUM_ASYNC_OUTCOME_UNSPECIFIED, 0);
	EXPECT_EQ(KINETUM_ASYNC_OUTCOME_SUCCESS, 1);
	EXPECT_EQ(KINETUM_ASYNC_OUTCOME_CANCELLED, 2);
	EXPECT_EQ(KINETUM_ASYNC_OUTCOME_FAILED, 3);
}

}  // namespace kinetum::sdk
