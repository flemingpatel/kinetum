// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dp_module_sdk.cpp
 * @brief Exact module ABI, lifecycle-service, and packet-contract tests.
 * @author Fleming Patel
 *
 * These tests exercise the deliberate exact ABI directly. Image/context
 * admission is generation-atomic, configuration ownership is represented by
 * PREPARE/ACTIVATE/RETIRE, packet batches carry explicit immutable config and
 * compact context pointers, and module-bearing component execution consumes
 * only exact epoch-tagged executable views.
 */

#include <gtest/gtest.h>

#include <chrono>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "src/dp/dp_engine.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/module/module_descriptor_admission.hpp"
#include <kinetum/kinetum_sdk.h>
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_record_test_harness.hpp"
#include "tests/test_active_helpers.hpp"
#include "tests/test_dp_helpers.hpp"

#ifndef KINETUM_TEST_MODULE_PATH
#error "KINETUM_TEST_MODULE_PATH must be defined by CMake"
#endif

namespace kinetum::dp
{
namespace
{

/** @brief Explicit lifecycle-memory authority for module SDK fixtures. */
constexpr test::module_test_resource_contract TEST_MODULE_RESOURCES{
	64u * 1024u * 1024u,
	2u * 1024u * 1024u,
};

/** @brief Fixed state used by synthetic descriptor callbacks. */
uint64_t DESCRIPTOR_TEST_STATE = 0;

/**
 * @brief Publish fixed descriptor-test state during INIT.
 * @param lifecycle Required non-null INIT shell.
 * @param out_state Output receiving the fixed fixture-state address.
 * @return KINETUM_OK with the fixed state, otherwise INVALID_ARG.
 */
[[nodiscard]] kinetum_error descriptor_init(const kinetum_lifecycle_ctx *lifecycle, void **out_state) noexcept
{
	if (lifecycle == nullptr || out_state == nullptr) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_state = &DESCRIPTOR_TEST_STATE;
	return KINETUM_OK;
}

/**
 * @brief Validate fixed descriptor-test state during FINI.
 * @param lifecycle Required non-null FINI shell.
 * @param state Exact fixed fixture-state address returned by INIT.
 */
void descriptor_fini(const kinetum_lifecycle_ctx *lifecycle, void *state) noexcept
{
	if (lifecycle == nullptr || state != &DESCRIPTOR_TEST_STATE) {
		std::terminate();
	}
}

/**
 * @brief Forward every synthetic passive packet.
 * @param batch Borrowed valid callback batch, or nullptr.
 * @return Occupied-prefix forwarding mask, or zero for a null batch.
 */
uint64_t descriptor_process(kinetum_batch_t *batch) noexcept
{
	return batch == nullptr ? 0 : KINETUM_FORWARD_MASK(batch->count);
}

/**
 * @brief Forward every synthetic active input packet.
 * @param context Exact synthetic packet context.
 * @param active_context Exact synthetic active services.
 * @param batch Exact active-ingest batch.
 * @return Sole forward mask, or zero for a null batch.
 */
uint64_t descriptor_ingest(kinetum_ctx *context, kinetum_active_ctx *active_context, kinetum_batch_t *batch) noexcept
{
	(void)context;
	(void)active_context;
	return batch == nullptr ? 0 : KINETUM_FORWARD_MASK(batch->count);
}

/**
 * @brief Consume one synthetic active scheduling turn.
 * @param context Exact synthetic packet context.
 * @param active_context Exact synthetic active services.
 * @param triggers Complete synthetic trigger mask.
 */
void descriptor_run(kinetum_ctx *context, kinetum_active_ctx *active_context, uint32_t triggers) noexcept
{
	(void)context;
	(void)active_context;
	(void)triggers;
}

/**
 * @brief Consume one synthetic active control message.
 * @param context Exact synthetic packet context.
 * @param active_context Exact synthetic active services.
 * @param message Exact borrowed control message.
 */
void descriptor_control(kinetum_ctx *context, kinetum_active_ctx *active_context,
			const kinetum_control_msg *message) noexcept
{
	(void)context;
	(void)active_context;
	(void)message;
}

/** @return Complete passive descriptor with the synthetic passive callbacks. */
[[nodiscard]] kinetum_module valid_passive_descriptor()
{
	return kinetum_module{
		.module_id = "kinetum.test.synthetic.passive",
		.module_version = "1.0.0",
		.abi_version = KINETUM_MODULE_ABI_VERSION,
		.flags = 0,
		.mode = KINETUM_MODULE_PASSIVE,
		.prepare_config = kinetum_noop_prepare_config,
		.activate_config = kinetum_noop_activate_config,
		.retire_config = kinetum_noop_retire_config,
		.process = descriptor_process,
		.ingest = nullptr,
		.run = nullptr,
		.on_control = nullptr,
		.init = descriptor_init,
		.fini = descriptor_fini,
		.health_check = nullptr,
		.select_contexts = nullptr,
	};
}

/** @return Complete active descriptor with the synthetic active callbacks. */
[[nodiscard]] kinetum_module valid_active_descriptor()
{
	return kinetum_module{
		.module_id = "kinetum.test.synthetic.active",
		.module_version = "1.0.0",
		.abi_version = KINETUM_MODULE_ABI_VERSION,
		.flags = 0,
		.mode = KINETUM_MODULE_ACTIVE,
		.prepare_config = kinetum_noop_prepare_config,
		.activate_config = kinetum_noop_activate_config,
		.retire_config = kinetum_noop_retire_config,
		.process = nullptr,
		.ingest = descriptor_ingest,
		.run = descriptor_run,
		.on_control = descriptor_control,
		.init = descriptor_init,
		.fini = descriptor_fini,
		.health_check = nullptr,
		.select_contexts = nullptr,
	};
}

/**
 * @brief Admit the exact passive test module with caller-selected context index.
 * @param context_index Compact context identity used by the production fixture factory.
 * @return Owned exact module context, or its admission failure.
 */
[[nodiscard]] common::status_or<std::unique_ptr<test::exact_module_test_context>>
admit_test_module(uint32_t context_index = 0)
{
	return test::exact_module_test_context::create("test_module", KINETUM_TEST_MODULE_PATH, TEST_MODULE_RESOURCES,
						       "module0@lane_0", context_index);
}

/**
 * @brief Populate one exact record with deterministic module-test metadata.
 * @param packet Exclusively owned record whose metadata is initialized.
 * @param dscp Initial six-bit DSCP value used by the selected test.
 */
void initialize_module_packet(packet_record &packet, uint8_t dscp = 0) noexcept
{
	packet.metadata.epoch = 1;
	packet.metadata.platform_flags |= packet_platform_flags::L3_IPV4 | packet_platform_flags::L4_UDP;
	packet.metadata.dscp = dscp;
	packet.metadata.src_ipv4 = 0x0a000001u;
	packet.metadata.dst_ipv4 = 0x08080808u;
	packet.metadata.src_port = 1234;
	packet.metadata.dst_port = 53;
	packet.metadata.l4_proto = 17;
}

/** @return Fixed module/context/worker identity used by lifecycle-shell tests. */
[[nodiscard]] lifecycle::lifecycle_context_identity test_lifecycle_identity()
{
	return lifecycle::lifecycle_context_identity{
		.module_id = "kinetum.test.lifecycle",
		.context_instance_id = "lifecycle0@lane_0",
		.module_image_index = 2,
		.context_index = 7,
		.worker_index = 3,
		.cpu_core_id = 11,
		.numa_node = 0,
		.module_context_ordinal = 0u,
		.module_context_count = 1u,
	};
}

// -----------------------------------------------------------------------------
// Exact module image, context, prepared artifact, and batch behavior (11)
// -----------------------------------------------------------------------------

/** @brief Prove an exact image and context admit and process one packet. */
TEST(module_sdk, admits_exact_image_context_and_processes_packet)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, "{}").is_ok());
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0));
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	EXPECT_TRUE(module->process(*packet.get()));
}

/** @brief Prove the exact drop policy clears every packet disposition. */
TEST(module_sdk, exact_drop_policy_drops_every_packet)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, R"({"drop":true})").is_ok());
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0));
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	EXPECT_FALSE(module->process(*packet.get()));
}

/** @brief Prove the DSCP policy drops only its exact configured value. */
TEST(module_sdk, exact_dscp_policy_drops_only_matching_value)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, R"({"dscp_drop":46})").is_ok());
	test::packet_record_test_owner denied(std::vector<uint8_t>(64, 0));
	test::packet_record_test_owner permitted(std::vector<uint8_t>(64, 0));
	ASSERT_TRUE(denied.valid()) << denied.error();
	ASSERT_TRUE(permitted.valid()) << permitted.error();
	initialize_module_packet(*denied.get(), 46);
	initialize_module_packet(*permitted.get(), 10);
	EXPECT_FALSE(module->process(*denied.get()));
	EXPECT_TRUE(module->process(*permitted.get()));
}

/** @brief Prove route policy publishes its exact compiled next-stage index. */
TEST(module_sdk, exact_route_policy_publishes_next_stage)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, R"({"route_to_stage":9})").is_ok());
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0));
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	ASSERT_TRUE(module->process(*packet.get()));
	EXPECT_EQ(packet.metadata().module_next_stage, 9u);
}

/** @brief Prove lifecycle context identity is exact rather than module-scoped. */
TEST(module_sdk, context_identity_is_exact_and_not_module_scoped)
{
	auto module_or = admit_test_module(7);
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	EXPECT_EQ(module->context().context_instance_id, "module0@lane_0");
	EXPECT_EQ(module->context().image->module_id, "test_module");
	EXPECT_NE(module->context().context_instance_id, module->context().image->module_id);
}

/** @brief Prove the compiled context index remains the callback authority. */
TEST(module_sdk, context_index_is_compiled_authority)
{
	auto module_or = admit_test_module(7);
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	EXPECT_EQ(module->context().context_index, 7u);
	ASSERT_NE(module->context().lifecycle_owner, nullptr);
	EXPECT_EQ(module->context().lifecycle_owner->identity().context_index, 7u);
}

/** @brief Prove manager indices resolve the same stable admitted objects. */
TEST(module_sdk, manager_indices_resolve_the_same_stable_objects)
{
	auto module_or = admit_test_module(7);
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	EXPECT_EQ(module->manager().image("test_module"), module->manager().image(0));
	EXPECT_EQ(module->manager().context("module0@lane_0"), module->manager().context(7));
}

/** @brief Prove activation publishes the prepared artifact's exact packet view. */
TEST(module_sdk, prepared_artifact_publishes_exact_packet_config)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_EQ(module->active_packet_config(), nullptr);
	ASSERT_TRUE(module->prepare_and_activate(3, "{}").is_ok());
	EXPECT_NE(module->active_packet_config(), nullptr);
	EXPECT_EQ(module->active_epoch(), 3u);
}

/** @brief Prove the batch bridge exposes exact L3 and L4 offsets. */
TEST(module_sdk, batch_exposes_l3_and_l4_offsets)
{
	kinetum_batch_t batch{};
	batch.l3_off[0] = 14;
	batch.l4_off[0] = 34;
	EXPECT_EQ(batch.l3_off[0], 14u);
	EXPECT_EQ(batch.l4_off[0], 34u);
}

/** @brief Prove batch protocol offsets remain relative to each packet. */
TEST(module_sdk, batch_offsets_are_packet_relative)
{
	kinetum_batch_t batch{};
	uint8_t packet[64]{};
	batch.data[0] = packet;
	batch.l3_off[0] = 14;
	batch.l4_off[0] = 34;
	auto *packet_data = static_cast<uint8_t *>(batch.data[0]);
	EXPECT_EQ(packet_data + batch.l3_off[0], packet + 14);
	EXPECT_EQ(packet_data + batch.l4_off[0], packet + 34);
}

/** @brief Prove each batch carries explicit immutable config and live context. */
TEST(module_sdk, batch_carries_explicit_config_and_context)
{
	kinetum_batch_t batch{};
	kinetum_ctx context{};
	uint64_t config = 0x1234;
	batch.ctx = &context;
	batch.epoch_config = &config;
	batch.epoch = 19;
	EXPECT_EQ(batch.ctx, &context);
	EXPECT_EQ(batch.epoch_config, &config);
	EXPECT_EQ(batch.epoch, 19u);
}

// -----------------------------------------------------------------------------
// Public lifecycle-shell telemetry behavior (3)
// -----------------------------------------------------------------------------

/** @brief Prove a registered counter is owner-local and directly updatable. */
TEST(sdk_telemetry, registered_counter_is_owner_local_and_directly_updatable)
{
	test::module_test_memory_provider memory;
	test::module_test_log_provider log;
	auto owner_or = lifecycle::lifecycle_context_owner::create(test_lifecycle_identity(),
								   TEST_MODULE_RESOURCES.context_memory_capacity_bytes,
								   TEST_MODULE_RESOURCES.epoch_arena_capacity_bytes,
								   memory, log);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	lifecycle::lifecycle_operation_control control(std::chrono::steady_clock::now() + std::chrono::seconds(1));
	auto operation_or = owner->begin_operation(lifecycle::lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();
	kinetum_counter_t counter = nullptr;
	ASSERT_EQ(kinetum_lifecycle_register_counter(&operation.context(), "module.checked", &counter), KINETUM_OK);
	ASSERT_NE(counter, nullptr);
	KINETUM_COUNTER_ADD(counter, 7);
	EXPECT_EQ(KINETUM_COUNTER_GET(counter), 7u);
}

/** @brief Prove a registered histogram records owner-local samples exactly. */
TEST(sdk_telemetry, registered_histogram_records_owner_local_samples)
{
	test::module_test_memory_provider memory;
	test::module_test_log_provider log;
	auto owner_or = lifecycle::lifecycle_context_owner::create(test_lifecycle_identity(),
								   TEST_MODULE_RESOURCES.context_memory_capacity_bytes,
								   TEST_MODULE_RESOURCES.epoch_arena_capacity_bytes,
								   memory, log);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	lifecycle::lifecycle_operation_control control(std::chrono::steady_clock::now() + std::chrono::seconds(1));
	auto operation_or = owner->begin_operation(lifecycle::lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();
	kinetum_histogram_t histogram = nullptr;
	ASSERT_EQ(kinetum_lifecycle_register_histogram(&operation.context(), "module.latency", 1000000, 3, &histogram),
		  KINETUM_OK);
	ASSERT_NE(histogram, nullptr);
	KINETUM_HISTOGRAM_RECORD_FAST(histogram, 73);
	EXPECT_EQ(histogram->total_count, 1u);
	EXPECT_EQ(histogram->max_value, 73u);
}

/** @brief Prove invalid telemetry names fail without consuming handle capacity. */
TEST(sdk_telemetry, duplicate_and_unbounded_names_fail_without_consuming_handles)
{
	test::module_test_memory_provider memory;
	test::module_test_log_provider log;
	auto owner_or = lifecycle::lifecycle_context_owner::create(test_lifecycle_identity(),
								   TEST_MODULE_RESOURCES.context_memory_capacity_bytes,
								   TEST_MODULE_RESOURCES.epoch_arena_capacity_bytes,
								   memory, log);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	lifecycle::lifecycle_operation_control control(std::chrono::steady_clock::now() + std::chrono::seconds(1));
	auto operation_or = owner->begin_operation(lifecycle::lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();
	kinetum_counter_t counter = nullptr;
	ASSERT_EQ(kinetum_lifecycle_register_counter(&operation.context(), "module.duplicate", &counter), KINETUM_OK);
	EXPECT_EQ(kinetum_lifecycle_register_counter(&operation.context(), "module.duplicate", &counter),
		  KINETUM_ERR_ALREADY_EXISTS);
	const std::string overlong(80, 'x');
	EXPECT_EQ(kinetum_lifecycle_register_counter(&operation.context(), overlong.c_str(), &counter),
		  KINETUM_ERR_INVALID_ARG);
	EXPECT_EQ(owner->telemetry_handle_count(), 1u);
}

// -----------------------------------------------------------------------------
// Public lifecycle-shell memory behavior (2)
// -----------------------------------------------------------------------------

/** @brief Prove context allocation is zeroed, aligned, and exactly releasable. */
TEST(sdk_memory, context_allocation_is_zeroed_aligned_and_exactly_releasable)
{
	test::module_test_memory_provider memory;
	test::module_test_log_provider log;
	auto owner_or = lifecycle::lifecycle_context_owner::create(test_lifecycle_identity(),
								   TEST_MODULE_RESOURCES.context_memory_capacity_bytes,
								   TEST_MODULE_RESOURCES.epoch_arena_capacity_bytes,
								   memory, log);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	lifecycle::lifecycle_operation_control control(std::chrono::steady_clock::now() + std::chrono::seconds(1));
	auto operation_or = owner->begin_operation(lifecycle::lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();
	void *pointer = nullptr;
	ASSERT_EQ(kinetum_lifecycle_allocate_context(
			  &operation.context(), 128, 64,
			  KINETUM_LIFECYCLE_ALLOC_ZERO | KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED, &pointer),
		  KINETUM_OK);
	ASSERT_NE(pointer, nullptr);
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(pointer) % 64u, 0u);
	const auto *bytes = static_cast<const uint8_t *>(pointer);
	EXPECT_EQ(bytes[0], 0u);
	EXPECT_EQ(bytes[127], 0u);
	EXPECT_EQ(kinetum_lifecycle_release_context(&operation.context(), pointer), KINETUM_OK);
}

/** @brief Prove epoch allocation requires and uses the exact prepare arena. */
TEST(sdk_memory, epoch_allocation_requires_and_uses_exact_prepare_arena)
{
	test::module_test_memory_provider memory;
	test::module_test_log_provider log;
	auto owner_or = lifecycle::lifecycle_context_owner::create(test_lifecycle_identity(),
								   TEST_MODULE_RESOURCES.context_memory_capacity_bytes,
								   TEST_MODULE_RESOURCES.epoch_arena_capacity_bytes,
								   memory, log);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	auto arena_or =
		lifecycle::epoch_arena_ownership::create(memory, 7, 9, 0, owner->epoch_arena_capacity_bytes(), 64);
	ASSERT_TRUE(arena_or.is_ok()) << arena_or.error().message();
	auto arena = std::move(arena_or).value();
	lifecycle::lifecycle_operation_control control(std::chrono::steady_clock::now() + std::chrono::seconds(1));
	auto operation_or = owner->begin_operation(lifecycle::lifecycle_phase::PREPARE, 9, control, &arena);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();
	void *pointer = nullptr;
	ASSERT_EQ(kinetum_lifecycle_allocate_epoch(&operation.context(), 96, 32, KINETUM_LIFECYCLE_ALLOC_ZERO,
						   &pointer),
		  KINETUM_OK);
	ASSERT_NE(pointer, nullptr);
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(pointer) % 32u, 0u);
	EXPECT_EQ(static_cast<const uint8_t *>(pointer)[95], 0u);
}

// -----------------------------------------------------------------------------
// Exact descriptor and engine/runtime behavior (28)
// -----------------------------------------------------------------------------

/** @brief Prove one complete passive descriptor validates. */
TEST(dp_module_sdk, exact_passive_descriptor_validates)
{
	auto descriptor = valid_passive_descriptor();
	EXPECT_TRUE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove one complete active descriptor validates. */
TEST(dp_module_sdk, exact_active_descriptor_validates)
{
	auto descriptor = valid_active_descriptor();
	EXPECT_TRUE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove an older module ABI identity is rejected. */
TEST(dp_module_sdk, older_abi_version_is_rejected)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.abi_version = KINETUM_MODULE_ABI_VERSION - 1u;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove a newer module ABI identity is rejected. */
TEST(dp_module_sdk, newer_abi_version_is_rejected)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.abi_version = KINETUM_MODULE_ABI_VERSION + 1u;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove an unknown module capability flag is rejected. */
TEST(dp_module_sdk, unknown_capability_flag_is_rejected)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.flags = 1u << 31;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove a passive descriptor requires its packet callback. */
TEST(dp_module_sdk, passive_descriptor_requires_process)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.process = nullptr;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove a passive descriptor cannot carry active callbacks. */
TEST(dp_module_sdk, passive_descriptor_rejects_active_callbacks)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.run = descriptor_run;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove an active descriptor requires its run callback. */
TEST(dp_module_sdk, active_descriptor_requires_run)
{
	auto descriptor = valid_active_descriptor();
	descriptor.run = nullptr;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove an active descriptor cannot carry a passive process callback. */
TEST(dp_module_sdk, active_descriptor_rejects_passive_process)
{
	auto descriptor = valid_active_descriptor();
	descriptor.process = descriptor_process;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove every descriptor requires a prepare callback. */
TEST(dp_module_sdk, descriptor_requires_prepare)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.prepare_config = nullptr;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove every descriptor requires an activate callback. */
TEST(dp_module_sdk, descriptor_requires_activate)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.activate_config = nullptr;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove every descriptor requires a retire callback. */
TEST(dp_module_sdk, descriptor_requires_retire)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.retire_config = nullptr;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove every descriptor requires an initialization callback. */
TEST(dp_module_sdk, descriptor_requires_init)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.init = nullptr;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove every descriptor requires a finalization callback. */
TEST(dp_module_sdk, descriptor_requires_fini)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.fini = nullptr;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove malformed module identity text is rejected. */
TEST(dp_module_sdk, descriptor_rejects_invalid_module_identity)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.module_id = "";
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());

	const char nonprintable[] = {'m', '\x1f', '\0'};
	descriptor.module_id = nonprintable;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());

	const std::string unbounded(KINETUM_MODULE_ABI_TEXT_CAPACITY, 'm');
	descriptor.module_id = unbounded.c_str();
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove malformed module release text is rejected. */
TEST(dp_module_sdk, descriptor_rejects_invalid_version)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.module_version = "";
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());

	const char nonprintable[] = {'1', '\n', '\0'};
	descriptor.module_version = nonprintable;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove an unknown execution mode is rejected. */
TEST(dp_module_sdk, descriptor_rejects_unknown_mode)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.mode = static_cast<kinetum_module_mode>(99);
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove an active descriptor may omit its ingest callback. */
TEST(dp_module_sdk, active_ingest_is_optional)
{
	auto descriptor = valid_active_descriptor();
	descriptor.ingest = nullptr;
	EXPECT_TRUE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove an active descriptor may omit its control callback. */
TEST(dp_module_sdk, active_control_is_optional)
{
	auto descriptor = valid_active_descriptor();
	descriptor.on_control = nullptr;
	EXPECT_TRUE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Prove an omitted health callback is valid and claims no health evidence. */
TEST(dp_module_sdk, null_health_is_valid_but_never_claims_health)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.health_check = nullptr;
	EXPECT_TRUE(module::validate_module_descriptor(&descriptor).is_ok());
	EXPECT_EQ(descriptor.health_check, nullptr);
}

/**
 * @brief Reject every selector lane without inspecting packet data.
 * @return Zero admission mask for this descriptor-only fixture.
 */
uint64_t descriptor_selection(const kinetum_context_selection_batch *, const kinetum_context_selection_targets *,
			      uint32_t *) noexcept
{
	return 0u;
}

/** @brief Prove the complete declared capability mask validates exactly. */
TEST(dp_module_sdk, complete_declared_capability_mask_validates)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.flags = KINETUM_MOD_F_KNOWN_MASK;
	descriptor.select_contexts = descriptor_selection;
	EXPECT_TRUE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Require exact agreement between context-selection capability and callback. */
TEST(dp_module_sdk, selector_capability_and_callback_must_agree)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.select_contexts = descriptor_selection;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
	descriptor.flags |= KINETUM_MOD_F_CONTEXT_SELECTION;
	EXPECT_TRUE(module::validate_module_descriptor(&descriptor).is_ok());
	descriptor.select_contexts = nullptr;
	EXPECT_FALSE(module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Process full and partial batches once, preserving each occupied lane's disposition. */
TEST(module_sdk, batch_masks_and_metadata_cover_every_occupied_lane)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1u, R"({"dscp_drop":46,"route_to_stage":9})").is_ok());
	std::array<std::unique_ptr<test::packet_record_test_owner>, KINETUM_MAX_BURST> owners;
	std::array<packet_record *, KINETUM_MAX_BURST> records{};
	uint64_t expected = 0u;
	for (uint16_t lane = 0u; lane < KINETUM_MAX_BURST; ++lane) {
		owners[lane] = std::make_unique<test::packet_record_test_owner>(std::vector<uint8_t>(64u + lane, 0u));
		ASSERT_TRUE(owners[lane]->valid()) << owners[lane]->error();
		records[lane] = owners[lane]->get();
		const bool drop = lane % 3u == 0u;
		initialize_module_packet(*records[lane], static_cast<uint8_t>(drop ? 46u : 10u));
		records[lane]->metadata.ingress_port = static_cast<uint16_t>(lane % KINETUM_MAX_PORTS);
		records[lane]->metadata.timestamp_ns = 1000u + lane;
		if (!drop) {
			expected |= UINT64_C(1) << lane;
		}
	}
	for (const uint16_t count : std::array<uint16_t, 6>{1u, 7u, 31u, 32u, 63u, 64u}) {
		const uint64_t occupied = count == 64u ? UINT64_MAX : (UINT64_C(1) << count) - 1u;
		EXPECT_EQ(module->process_batch({records.data(), count}), expected & occupied) << count;
		for (uint16_t lane = 0u; lane < count; ++lane) {
			EXPECT_EQ(records[lane]->metadata.ingress_port, lane % KINETUM_MAX_PORTS);
			EXPECT_EQ(records[lane]->metadata.timestamp_ns, 1000u + lane);
			EXPECT_EQ(records[lane]->metadata.module_next_stage,
				  lane % 3u == 0u ? KINETUM_NEXT_STAGE_UNSET : 9u);
		}
	}
	// A mismatched last lane rejects the whole prefix before the callback.
	records.back()->metadata.epoch = 2u;
	EXPECT_EQ(module->process_batch(records), 0u);
	EXPECT_EQ(module->context().epoch_store->diagnostics_after_quiescence().mismatch_count, 1u);
	bool found_batches = false;
	const auto &lifecycle_owner = *module->context().lifecycle_owner;
	for (uint32_t handle = 1u; handle <= lifecycle_owner.telemetry_handle_count(); ++handle) {
		const auto *descriptor = lifecycle_owner.telemetry_descriptor(
			static_cast<lifecycle::lifecycle_telemetry_handle>(handle));
		if (descriptor != nullptr && descriptor->kind == lifecycle::lifecycle_telemetry_kind::COUNTER &&
		    std::string_view(descriptor->counter.name) == "test_module.batches") {
			EXPECT_EQ(descriptor->counter.value, 6u);
			found_batches = true;
		}
	}
	EXPECT_TRUE(found_batches);
}

/** @brief Prove the mechanism-only engine rejects direct module-stage execution. */
TEST(dp_module_sdk, engine_rejects_direct_module_stage_execution)
{
	dp_engine engine;
	kinetum::axiom::v1::Stage stage;
	stage.set_stage_id("module0");
	stage.set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0));
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	EXPECT_FALSE(engine.execute_stage(&stage, packet.get()));
}

/** @brief Prove the mechanism-only engine accepts platform parser execution. */
TEST(dp_module_sdk, engine_accepts_platform_parser_execution)
{
	dp_engine engine;
	kinetum::axiom::v1::Stage stage;
	stage.set_stage_id("parse0");
	stage.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	auto bytes = build_eth_ipv4_udp(0x0a000001, 0x08080808, 1234, 53, 0, {1, 2});
	test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();
	EXPECT_TRUE(engine.execute_stage(&stage, packet.get()));
}

/** @brief Prove the packet mechanism accounting authority starts exactly empty. */
TEST(stage_counter, default_construction)
{
	dp_engine engine;
	const auto observed = engine.stats();
	EXPECT_EQ(observed.rx_packets, 0u);
	EXPECT_EQ(observed.tx_packets, 0u);
	EXPECT_EQ(observed.dropped_packets, 0u);
}

/** @brief Prove exact RX and TX mechanism outcomes initialize independent counters. */
TEST(stage_counter, initialization)
{
	dp_engine engine;
	kinetum::axiom::v1::Stage rx;
	rx.set_stage_id("rx0");
	rx.set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	kinetum::axiom::v1::Stage tx;
	tx.set_stage_id("tx0");
	tx.set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0));
	ASSERT_TRUE(packet.valid()) << packet.error();
	packet.metadata().ingress_port = 3;
	packet.metadata().egress_port = 5;
	ASSERT_TRUE(engine.execute_stage(&rx, packet.get()));
	ASSERT_TRUE(engine.execute_stage(&tx, packet.get()));

	const auto observed = engine.stats();
	EXPECT_EQ(observed.rx_packets, 1u);
	EXPECT_EQ(observed.tx_packets, 1u);
	EXPECT_EQ(observed.dropped_packets, 0u);
}

/** @brief Prove a forwarding module outcome does not fabricate RX, TX, or drop accounting. */
TEST(stage_counter, passthrough_stage)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(7, "{}").is_ok());

	dp_engine engine;
	module_batch_scratch scratch{};
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), 7);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	packet.metadata().epoch = 7;
	ASSERT_NE(module->context().epoch_store, nullptr);
	ASSERT_TRUE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));

	const auto observed = engine.stats();
	EXPECT_EQ(observed.rx_packets, 0u);
	EXPECT_EQ(observed.tx_packets, 0u);
	EXPECT_EQ(observed.dropped_packets, 0u);
}

/** @brief Prove one exact module rejection increments only the drop authority. */
TEST(stage_counter, filtering_stage)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(7, R"({"drop":true})").is_ok());

	dp_engine engine;
	module_batch_scratch scratch{};
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), 7);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	packet.metadata().epoch = 7;
	ASSERT_NE(module->context().epoch_store, nullptr);
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));

	const auto observed = engine.stats();
	EXPECT_EQ(observed.rx_packets, 0u);
	EXPECT_EQ(observed.tx_packets, 0u);
	EXPECT_EQ(observed.dropped_packets, 1u);
}

/** @brief Prove the live module path executes only its matching exact view. */
TEST(dp_module_sdk, engine_executes_matching_exact_module_view)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(7, R"({"route_to_stage":9})").is_ok());

	dp_engine engine;
	module_batch_scratch scratch{};
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), 7);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	packet.metadata().epoch = 7;
	packet.metadata().timestamp_ns = 1234;
	ASSERT_NE(module->context().epoch_store, nullptr);
	EXPECT_TRUE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));
	EXPECT_EQ(packet.metadata().module_next_stage, 9u);
	EXPECT_EQ(scratch.batch.epoch, 7u);
	EXPECT_EQ(scratch.batch.ts_ns[0], 1234u);
}

/** @brief Prove every documented mutable callback lane publishes back to the sole record. */
TEST(dp_module_sdk, engine_publishes_mutable_module_metadata_to_exact_record)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(7, R"({"rewrite_metadata":true})").is_ok());

	dp_engine engine;
	module_batch_scratch scratch{};
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), 7);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	packet.metadata().epoch = 7;
	packet.metadata().timestamp_ns = 1234;
	packet.metadata().ingress_port = 5;
	ASSERT_NE(module->context().epoch_store, nullptr);
	ASSERT_TRUE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));

	EXPECT_EQ(packet.metadata().ip_offset, 14u);
	EXPECT_EQ(packet.metadata().l4_offset, 34u);
	EXPECT_EQ(packet.metadata().src_ipv4, UINT32_C(0xc0000201));
	EXPECT_EQ(packet.metadata().dst_ipv4, UINT32_C(0xc6336402));
	EXPECT_EQ(packet.metadata().src_port, 4321u);
	EXPECT_EQ(packet.metadata().dst_port, 443u);
	EXPECT_EQ(packet.metadata().l4_proto, 6u);
	EXPECT_EQ(packet.metadata().dscp, 46u);
	EXPECT_EQ(packet.metadata().platform_flags, packet_platform_flags::L3_IPV4 | packet_platform_flags::L4_TCP);
	EXPECT_EQ(packet.metadata().user_flags, UINT32_C(0xa5a55a5a));
	EXPECT_EQ(packet.metadata().flow_hash, UINT32_C(0x10203040));
	EXPECT_EQ(packet.metadata().egress_port, 7u);
	EXPECT_EQ(packet.metadata().user_meta, UINT64_C(0x1122334455667788));
	EXPECT_EQ(packet.metadata().user_meta_valid, 1u);
	EXPECT_EQ(packet.metadata().ingress_port, 5u);
	EXPECT_EQ(packet.metadata().timestamp_ns, 1234u);
}

/** @brief Fail-stop when foreign code rewrites immutable owner-worker batch authority. */
TEST(dp_module_sdk, engine_rejects_module_batch_authority_corruption)
{
	using packet_owners = std::array<std::unique_ptr<test::packet_record_test_owner>, 64u>;
	using packet_records = std::array<packet_record *, 64u>;
	for (uint32_t corruption = 1; corruption <= 11; ++corruption) {
		for (const uint16_t size : std::array<uint16_t, 2>{1u, 64u}) {
			// A full uint64 mask has no out-of-prefix bit; use 63 for that fault.
			const uint16_t count = corruption == 11u && size == 64u ? 63u : size;
			EXPECT_DEATH(
				{
					auto module_or = admit_test_module();
					if (!module_or.is_ok()) {
						std::_Exit(0);
					}
					auto module = std::move(module_or).value();
					const std::string config =
						"{\"corrupt_authority\":" + std::to_string(corruption) + "}";
					if (!module->prepare_and_activate(7, config).is_ok()) {
						std::_Exit(0);
					}
					packet_owners owners;
					packet_records records{};
					for (uint16_t lane = 0u; lane < count; ++lane) {
						owners[lane] = std::make_unique<test::packet_record_test_owner>(
							std::vector<uint8_t>(64u, 0u), 7u);
						if (!owners[lane]->valid()) {
							std::_Exit(0);
						}
						records[lane] = owners[lane]->get();
						initialize_module_packet(*records[lane]);
						records[lane]->metadata.epoch = 7u;
					}
					if (module->context().epoch_store == nullptr) {
						std::_Exit(0);
					}
					dp_engine engine;
					module_batch_scratch scratch{};
					(void)engine.execute_module_stage(
						*module->context().epoch_store, 0u, 3,
						std::span<packet_record *const>(records.data(), count), scratch);
					std::_Exit(0);
				},
				"");
		}
	}
}

/** @brief Fail-stop before publishing contradictory module-authored parser facts. */
TEST(dp_module_sdk, engine_rejects_incoherent_module_packet_facts)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(7, R"({"corrupt_packet_facts":true})").is_ok());

	dp_engine engine;
	module_batch_scratch scratch{};
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), 7);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	packet.metadata().epoch = 7;
	ASSERT_NE(module->context().epoch_store, nullptr);
	EXPECT_DEATH((void)engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()},
						       scratch),
		     "");
}

/** @brief Prove reusable worker scratch carries no stale index-zero state. */
TEST(dp_module_sdk, engine_reuse_overwrites_every_index_zero_batch_field)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(7, "{}").is_ok());

	dp_engine engine;
	module_batch_scratch scratch{};
	std::memset(&scratch.batch, 0xa5, sizeof(scratch.batch));
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), 7);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	packet.metadata().epoch = 7;
	packet.metadata().timestamp_ns = 4321;
	ASSERT_NE(module->context().epoch_store, nullptr);
	ASSERT_TRUE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));

	ASSERT_NE(module->context().epoch_store->active_view(), nullptr);
	EXPECT_EQ(scratch.batch.data[0], packet.data());
	EXPECT_EQ(scratch.batch.len[0], 64u);
	EXPECT_EQ(scratch.batch.count, 1u);
	EXPECT_EQ(scratch.batch.epoch, 7u);
	EXPECT_EQ(scratch.batch.region_id, 3u);
	EXPECT_EQ(scratch.batch.l3_off[0], 0u);
	EXPECT_EQ(scratch.batch.l4_off[0], 0u);
	EXPECT_EQ(scratch.batch.src_ip[0], 0x0a000001u);
	EXPECT_EQ(scratch.batch.dst_ip[0], 0x08080808u);
	EXPECT_EQ(scratch.batch.src_port[0], 1234u);
	EXPECT_EQ(scratch.batch.dst_port[0], 53u);
	EXPECT_EQ(scratch.batch.proto[0], 17u);
	EXPECT_EQ(scratch.batch.dscp[0], 0u);
	EXPECT_EQ(scratch.batch.flow_hash[0], 0u);
	EXPECT_EQ(scratch.batch.input_port[0], INVALID_PORT);
	EXPECT_EQ(scratch.batch.output_port[0], INVALID_PORT);
	EXPECT_EQ(scratch.batch.platform_flags[0], KINETUM_PKT_F_L3_IPV4 | KINETUM_PKT_F_L4_UDP);
	EXPECT_EQ(scratch.batch.user_flags[0], 0u);
	EXPECT_EQ(scratch.batch.next_stage[0], KINETUM_NEXT_STAGE_UNSET);
	EXPECT_EQ(scratch.batch.ts_ns[0], 4321u);
	EXPECT_EQ(scratch.batch.user_meta[0], 0u);
	EXPECT_EQ(scratch.batch.user_meta_valid[0], 0u);
	EXPECT_EQ(scratch.batch.padding, 0u);
	EXPECT_EQ(scratch.batch.epoch_config, module->context().epoch_store->active_view()->packet_config);
	EXPECT_EQ(scratch.batch.ctx, &module->context().packet_context);
}

/** @brief Reject every unmaterialized CPU record shape before packet mechanisms. */
TEST(dp_module_sdk, engine_rejects_unmaterialized_cpu_record_shapes)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(7, R"({"route_to_stage":9})").is_ok());

	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), 7);
	ASSERT_TRUE(packet.valid()) << packet.error();
	auto *const storage_data = packet.data();
	initialize_module_packet(*packet.get());
	packet.metadata().epoch = 7;
	packet.get()->storage.segment_count = 2;

	dp_engine engine;
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	EXPECT_FALSE(engine.execute_stage(&parse, packet.get()));

	module_batch_scratch scratch{};
	ASSERT_NE(module->context().epoch_store, nullptr);
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));

	packet.get()->storage.segment_count = 1;
	packet.get()->storage.contiguous_length = 32;
	EXPECT_FALSE(engine.execute_stage(&parse, packet.get()));
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));

	packet.get()->storage.contiguous_length = 64;
	packet.get()->storage.data = nullptr;
	EXPECT_FALSE(engine.execute_stage(&parse, packet.get()));
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));

	packet.get()->storage.data = storage_data;
	const uint32_t storage_capabilities = packet.get()->storage.capabilities;
	packet.get()->storage.capabilities &= ~packet_storage_capabilities::CPU_CONTIGUOUS_READ;
	EXPECT_FALSE(engine.execute_stage(&parse, packet.get()));
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));

	packet.get()->storage.capabilities = storage_capabilities & ~packet_storage_capabilities::CPU_CONTIGUOUS_WRITE;
	EXPECT_FALSE(engine.execute_stage(&parse, packet.get()));
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));

	packet.get()->storage.capabilities = storage_capabilities & ~packet_storage_capabilities::WRITABLE_CLONE;
	EXPECT_TRUE(packet_record_has_current_cpu_shape(packet.get()));

	packet.get()->storage.capabilities = storage_capabilities | (UINT32_C(1) << 31);
	EXPECT_FALSE(engine.execute_stage(&parse, packet.get()));
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 3, std::array{packet.get()}, scratch));
	EXPECT_EQ(packet.metadata().module_next_stage, KINETUM_NEXT_STAGE_UNSET);
	EXPECT_EQ(module->context().epoch_store->diagnostics_after_quiescence().mismatch_count, 0u);
	EXPECT_EQ(engine.stats().rx_packets, 0u);
	EXPECT_EQ(engine.stats().dropped_packets, 12u);
	packet.get()->storage.capabilities = storage_capabilities;
}

/**
 * @brief Reject an exact-epoch mismatch before callback and retire without leaking.
 *
 * The execution helper preserves ownership on rejection. This test therefore
 * exercises the owning disposition path explicitly and proves that the packet
 * credit returns to its exact storage domain after bounded mismatch evidence is
 * recorded.
 */
TEST(dp_module_sdk, engine_rejects_exact_epoch_mismatch_with_bounded_evidence)
{
	constexpr uint16_t STAGE_INSTANCE_INDEX = 4u;
	constexpr uint32_t CONTEXT_INDEX = static_cast<uint32_t>(STAGE_INSTANCE_INDEX);
	auto module_or = admit_test_module(CONTEXT_INDEX);
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(7, R"({"route_to_stage":9})").is_ok());

	dp_engine engine;
	module_batch_scratch scratch{};
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), 6);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get());
	packet.metadata().epoch = 6;
	ASSERT_NE(module->context().epoch_store, nullptr);
	auto *record = packet.take();
	ASSERT_NE(record, nullptr);
	EXPECT_FALSE(engine.execute_module_stage(*module->context().epoch_store, STAGE_INSTANCE_INDEX, 2,
						 std::array{record}, scratch));
	EXPECT_EQ(record->metadata.module_next_stage, KINETUM_NEXT_STAGE_UNSET);
	const auto *operations = record->storage.operations;
	ASSERT_NE(operations, nullptr);
	operations->release_burst(operations->state, &record, 1);
	EXPECT_EQ(packet.outstanding(), 0u);

	const auto diagnostics = module->context().epoch_store->diagnostics_after_quiescence();
	EXPECT_EQ(diagnostics.mismatch_count, 1u);
	EXPECT_EQ(diagnostics.sticky_fault, 1u);
	ASSERT_EQ(diagnostics.first_fault_valid, 1u);
	EXPECT_EQ(diagnostics.first_fault.packet_epoch, 6u);
	EXPECT_EQ(diagnostics.first_fault.active_epoch, 7u);
	EXPECT_EQ(diagnostics.first_fault.context_index, CONTEXT_INDEX);
	EXPECT_EQ(diagnostics.first_fault.stage_instance_index, STAGE_INSTANCE_INDEX);
	EXPECT_EQ(diagnostics.first_fault.region_id, 2);

	// The execution helper never steals ownership. The owning disposition path
	// retires the rejected record exactly once through its storage domain.
}

/** @brief Prove an admitted active image reports its exact execution mode. */
TEST(dp_module_sdk, admitted_active_image_reports_exact_mode)
{
	auto harness = test::active_test_harness::create(TEST_MODULE_RESOURCES);
	ASSERT_TRUE(harness.valid()) << harness.error;
	EXPECT_EQ(harness.module->descriptor().mode, KINETUM_MODULE_ACTIVE);
	EXPECT_EQ(harness.module->descriptor().process, nullptr);
}

/** @brief Prove an admitted passive image reports its exact capabilities. */
TEST(dp_module_sdk, admitted_passive_image_reports_exact_capabilities)
{
	auto module_or = admit_test_module();
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	EXPECT_EQ(module->descriptor().mode, KINETUM_MODULE_PASSIVE);
	EXPECT_EQ(module->descriptor().flags, KINETUM_MOD_F_REPLICABLE_CONTEXTS | KINETUM_MOD_F_LIVE_EPOCH_TRANSITION);
}

}  // namespace
}  // namespace kinetum::dp
