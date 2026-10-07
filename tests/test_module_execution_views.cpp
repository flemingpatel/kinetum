// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_module_execution_views.cpp
 * @brief Exact compiled module ownership and direct active-callback tests.
 * @author Fleming Patel
 *
 * Compiled-ownership rows stop before provider admission or materialization
 * and exercise the production module-generation gate. Packet-view rows use
 * the exact module store and provider-neutral packet record. Active-origin
 * rows invoke the exact component callback with a bounded test service; they
 * do not construct or emulate an active-stage scheduler.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/dp_engine.hpp"
#include "src/dp/module/module_runtime_generation.hpp"
#include "src/dp/packet.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/quark/host_probe.hpp"
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_record_test_harness.hpp"
#include "tests/packet_runtime_test_fixture.hpp"
#include "tests/test_active_helpers.hpp"

#if !defined(KINETUM_TEST_MODULE_PATH) || !defined(KINETUM_TEST_ACTIVE_MODULE_PATH) || \
	!defined(KINETUM_TEST_ACTIVE_ASYNC_MODULE_PATH)
#error "Exact passive, active, and active-async test-module paths are required"
#endif

namespace kinetum::dp::module
{
namespace
{

/** Context-memory authority supplied to fixture modules. */
constexpr uint64_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = uint64_t{64} * 1024u;
/** Epoch-arena authority supplied to fixture modules. */
constexpr uint64_t TEST_EPOCH_ARENA_CAPACITY_BYTES = uint64_t{4} * 1024u;
/** Exact activated epoch used by execution-view fixtures. */
constexpr uint64_t TEST_ACTIVE_EPOCH = 7u;

using kinetum::common::status_code;
using kinetum::test::packet_runtime_fixture_detail::compiled_runtime_fixture;

/** @return Passive test-module identity and its compiled image path. */
[[nodiscard]] module_image_spec passive_image()
{
	return {"test_module", std::filesystem::path(KINETUM_TEST_MODULE_PATH)};
}

/** @return Active test-module identity and its compiled image path. */
[[nodiscard]] module_image_spec active_image()
{
	return {"kinetum.test_active", std::filesystem::path(KINETUM_TEST_ACTIVE_MODULE_PATH)};
}

/** @return Active-async test-module identity and its compiled image path. */
[[nodiscard]] module_image_spec active_async_image()
{
	return {"kinetum.test_active_async", std::filesystem::path(KINETUM_TEST_ACTIVE_ASYNC_MODULE_PATH)};
}

/**
 * @brief Compile one module graph without provider side effects.
 *
 * @param module_id Exact authored module image identity.
 * @param execution_mode Exact authored passive or active execution mode.
 * @return Canonical plan and sole compiled topology, or exact host/planner
 *         admission failure.
 */
[[nodiscard]] common::status_or<compiled_runtime_fixture>
compile_module_fixture(std::string module_id, kinetum::axiom::v1::ExecutionMode execution_mode)
{
	const bool tracked_async = module_id == "kinetum.test_active_async";
	const auto host = quark::probe_host();
	auto selection_or = test::packet_runtime_fixture_detail::select_host(host);
	if (!selection_or.is_ok()) {
		return selection_or.error();
	}
	auto rx_or = test::packet_runtime_fixture_detail::udp_port_reservation::create();
	if (!rx_or.is_ok()) {
		return rx_or.error();
	}
	auto rx = std::move(rx_or).value();
	auto tx_or = test::packet_runtime_fixture_detail::udp_port_reservation::create();
	if (!tx_or.is_ok()) {
		return tx_or.error();
	}
	auto tx = std::move(tx_or).value();
	auto pipeline =
		test::packet_runtime_fixture_detail::make_pipeline(std::optional<std::string>(std::move(module_id)));
	bool found_module_stage = false;
	for (auto &stage : *pipeline.mutable_stages()) {
		if (stage.kind() != kinetum::axiom::v1::STAGE_KIND_MODULE) {
			continue;
		}
		if (found_module_stage) {
			return common::status::internal_error(
				"module execution-view fixture has more than one module stage");
		}
		stage.set_execution_mode(execution_mode);
		if (execution_mode == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
			stage.set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));
			if (tracked_async) {
				stage.mutable_active_stage_limits()->set_async_work_capacity(4u);
				stage.mutable_active_stage_limits()->set_async_cancel_grace_ms(1000u);
			}
		}
		found_module_stage = true;
	}
	if (!found_module_stage) {
		return common::status::internal_error("module execution-view fixture lost its exact module stage");
	}
	return test::packet_runtime_fixture_detail::compile_runtime_fixture(pipeline, selection_or.value(), rx.port(),
									    tx.port(),
									    TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									    TEST_EPOCH_ARENA_CAPACITY_BYTES);
}

/** @return Fixed lifecycle-memory and timeout authority used by direct component fixtures. */
[[nodiscard]] constexpr test::module_test_resource_contract direct_module_resources() noexcept
{
	return {
		.context_memory_capacity_bytes = TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
		.epoch_arena_capacity_bytes = TEST_EPOCH_ARENA_CAPACITY_BYTES,
	};
}

/**
 * @brief Populate one coherent module-test packet under an exact epoch.
 * @param packet Exclusively owned record receiving deterministic parser and routing facts.
 * @param epoch Exact packet-admission epoch.
 */
void initialize_module_packet(packet_record &packet, uint64_t epoch) noexcept
{
	packet.metadata.epoch = epoch;
	packet.metadata.platform_flags = packet_platform_flags::L3_IPV4 | packet_platform_flags::L4_UDP;
	packet.metadata.src_ipv4 = UINT32_C(0x0a000001);
	packet.metadata.dst_ipv4 = UINT32_C(0x08080808);
	packet.metadata.src_port = 1234;
	packet.metadata.dst_port = 53;
	packet.metadata.l4_proto = 17;
}

/**
 * @brief Build one callback-only active view with no runtime service authority.
 *
 * @param harness Admitted and activated active-module component.
 * @return Exact fixed-epoch callback context.
 */
[[nodiscard]] kinetum_active_ctx make_active_context(const test::active_test_harness &harness) noexcept
{
	kinetum_active_ctx context{};
	context.now_ns = 1;
	context.active_epoch = harness.module->active_epoch();
	context.active_packet_config = harness.module->active_packet_config();
	context.region_id = 0;
	return context;
}

/** @brief Reject a compiled context absent from its owner-worker engine schedule. */
TEST(module_execution_views, rejects_missing_exact_engine_authority)
{
	auto fixture_or = compile_module_fixture("test_module", kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	ASSERT_EQ(fixture.topology.module_contexts.size(), 1u);
	const auto &context = fixture.topology.module_contexts.front();
	ASSERT_LT(context.worker_index, fixture.topology.worker_schedules.size());
	auto &stage_indices = fixture.topology.worker_schedules[context.worker_index].stage_instance_indices;
	const auto position =
		std::lower_bound(stage_indices.begin(), stage_indices.end(), context.stage_instance_index);
	ASSERT_NE(position, stage_indices.end());
	ASSERT_EQ(*position, context.stage_instance_index);
	stage_indices.erase(position);

	auto generation_or = module_runtime_generation::create(fixture.topology, {passive_image()});
	ASSERT_FALSE(generation_or.is_ok());
	EXPECT_EQ(generation_or.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(generation_or.error().message().find("exact owner placement"), std::string::npos);
}

/** @brief Reject module contexts when their complete image generation is absent. */
TEST(module_execution_views, rejects_missing_exact_module_generation)
{
	auto fixture_or = compile_module_fixture("test_module", kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();

	auto generation_or = module_runtime_generation::create(fixture.topology, {});
	ASSERT_FALSE(generation_or.is_ok());
	EXPECT_EQ(generation_or.error().code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(generation_or.error().message().find("exact image"), std::string::npos);
}

/** @brief A compiled selection policy requires the corresponding module-image capability. */
TEST(module_execution_views, selected_context_requires_image_selector_before_provider_materialization)
{
	auto fixture_or = compile_module_fixture("test_module", kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	auto logical = std::find_if(fixture.topology.logical_stages.begin(), fixture.topology.logical_stages.end(),
				    [](const auto &stage) { return stage.module_id == "test_module"; });
	ASSERT_NE(logical, fixture.topology.logical_stages.end());
	logical->context_selection = provider::compiled_module_context_selection::MODULE;
	auto generation_or = module_runtime_generation::create(fixture.topology, {passive_image()});
	ASSERT_FALSE(generation_or.is_ok());
	EXPECT_EQ(generation_or.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(generation_or.error().message().find("selector capability"), std::string::npos);
}

/** @brief Reject packet execution before an exact context view is activated. */
TEST(module_execution_views, rejects_context_without_exact_active_view)
{
	auto module_or = test::exact_module_test_context::create("test_module", KINETUM_TEST_MODULE_PATH,
								 direct_module_resources());
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_NE(module->context().epoch_store, nullptr);

	dp_engine engine;
	module_batch_scratch scratch{};
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), 1);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get(), 1);
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 0, std::array{packet.get()}, scratch));
	EXPECT_EQ(engine.stats().dropped_packets, 1u);
	const auto diagnostics = module->context().epoch_store->diagnostics_after_quiescence();
	EXPECT_EQ(diagnostics.mismatch_count, 1u);
	ASSERT_EQ(diagnostics.first_fault_valid, 1u);
	EXPECT_EQ(diagnostics.first_fault.active_epoch, 0u);
	EXPECT_EQ(module->context().lifecycle_owner->telemetry_active_epoch(), 0u);
	EXPECT_TRUE(module->context().lifecycle_owner->telemetry_empty());
}

/** @brief Reject a context identity that disagrees with its executable stage. */
TEST(module_execution_views, rejects_context_id_that_does_not_match_stage_instance)
{
	auto fixture_or = compile_module_fixture("test_module", kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	ASSERT_EQ(fixture.topology.module_contexts.size(), 1u);
	fixture.topology.module_contexts.front().context_instance_id = "different@lane_0";

	auto generation_or = module_runtime_generation::create(fixture.topology, {passive_image()});
	ASSERT_FALSE(generation_or.is_ok());
	EXPECT_EQ(generation_or.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(generation_or.error().message().find("exact owner placement"), std::string::npos);
}

/** @brief Reject a context whose CPU differs from its exact owner worker. */
TEST(module_execution_views, rejects_context_with_different_owner_placement)
{
	auto fixture_or = compile_module_fixture("test_module", kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	ASSERT_EQ(fixture.topology.module_contexts.size(), 1u);
	auto &context = fixture.topology.module_contexts.front();
	ASSERT_LT(context.worker_index, fixture.topology.transition_topology.workers.size());
	const auto &worker = fixture.topology.transition_topology.workers[context.worker_index];
	ASSERT_EQ(worker.cpu_core_ids.size(), 1u);
	context.cpu_core_id = worker.cpu_core_ids.front() == 0 ? 1 : 0;

	auto generation_or = module_runtime_generation::create(fixture.topology, {passive_image()});
	ASSERT_FALSE(generation_or.is_ok());
	EXPECT_EQ(generation_or.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(generation_or.error().message().find("exact owner placement"), std::string::npos);
}

/** @brief Reject an active image behind a stage authored as passive. */
TEST(module_execution_views, rejects_active_view_for_passive_authored_stage)
{
	auto fixture_or = compile_module_fixture("kinetum.test_active", kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();

	auto generation_or = module_runtime_generation::create(fixture.topology, {active_image()});
	ASSERT_FALSE(generation_or.is_ok());
	EXPECT_EQ(generation_or.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(generation_or.error().message().find("execution mode"), std::string::npos);
}

/** @brief Admit one complete synchronous active schedule before provider materialization. */
TEST(module_execution_views, active_schedule_admits_complete_synchronous_owner_before_materialization)
{
	auto fixture_or = compile_module_fixture("kinetum.test_active", kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	const auto active_stage_count = static_cast<std::size_t>(std::count_if(
		fixture.topology.logical_stages.begin(), fixture.topology.logical_stages.end(), [](const auto &stage) {
			return stage.execution_mode == provider::compiled_stage_execution_mode::ACTIVE;
		}));
	ASSERT_EQ(active_stage_count, 1u);
	ASSERT_FALSE(fixture.topology.worker_schedules.empty());
	ASSERT_FALSE(fixture.topology.worker_schedules.front().active_stage_instance_indices.empty());

	auto generation_or = module_runtime_generation::create(fixture.topology, {active_image()});
	ASSERT_TRUE(generation_or.is_ok()) << generation_or.error().message();
}

/** @brief Reject a CONTROL schedule whose exact active image lacks on_control. */
TEST(module_execution_views, active_control_requires_callback_before_provider_materialization)
{
	auto fixture_or =
		compile_module_fixture("kinetum.test_active_async", kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	auto logical = std::find_if(
		fixture.topology.logical_stages.begin(), fixture.topology.logical_stages.end(), [](const auto &stage) {
			return stage.execution_mode == provider::compiled_stage_execution_mode::ACTIVE;
		});
	ASSERT_NE(logical, fixture.topology.logical_stages.end());
	logical->trigger_mask |= static_cast<uint32_t>(provider::compiled_active_stage_trigger::CONTROL);
	logical->control_mailbox_capacity = 2u;
	logical->control_message_capacity_bytes = 8u;

	auto generation_or = module_runtime_generation::create(fixture.topology, {active_async_image()});
	ASSERT_FALSE(generation_or.is_ok());
	EXPECT_EQ(generation_or.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(generation_or.error().message().find("CONTROL ownership"), std::string::npos);
}

/** @brief Admit tracked async only when compiled resources exactly match the image capability. */
TEST(module_execution_views, active_async_capability_requires_exact_resources_before_provider_materialization)
{
	auto fixture_or =
		compile_module_fixture("kinetum.test_active_async", kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	auto logical = std::find_if(
		fixture.topology.logical_stages.begin(), fixture.topology.logical_stages.end(), [](const auto &stage) {
			return stage.execution_mode == provider::compiled_stage_execution_mode::ACTIVE &&
			       stage.module_id == "kinetum.test_active_async";
		});
	ASSERT_NE(logical, fixture.topology.logical_stages.end());
	auto generation_or = module_runtime_generation::create(fixture.topology, {active_async_image()});
	ASSERT_TRUE(generation_or.is_ok()) << generation_or.error().message();
	auto generation = std::move(generation_or).value();
	generation.reset();

	logical->async_work_capacity = 0u;
	logical->async_cancel_grace = {};
	auto missing_resources = module_runtime_generation::create(fixture.topology, {active_async_image()});
	ASSERT_FALSE(missing_resources.is_ok());
	EXPECT_EQ(missing_resources.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(missing_resources.error().message().find("tracked-async"), std::string::npos);

	logical->async_work_capacity = 4u;
	logical->async_cancel_grace = fixture.topology.transition_topology.policy.commit_timeout;
	auto unbounded_grace = module_runtime_generation::create(fixture.topology, {active_async_image()});
	ASSERT_FALSE(unbounded_grace.is_ok());
	EXPECT_EQ(unbounded_grace.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(unbounded_grace.error().message().find("tracked-async"), std::string::npos);
}

/** @brief Reject a packet whose snapshot epoch differs from the exact view. */
TEST(module_execution_views, rejects_view_from_a_different_exact_snapshot_epoch)
{
	auto module_or = test::exact_module_test_context::create("test_module", KINETUM_TEST_MODULE_PATH,
								 direct_module_resources());
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(TEST_ACTIVE_EPOCH, R"({"route_to_stage":9})").is_ok());

	dp_engine engine;
	module_batch_scratch scratch{};
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), TEST_ACTIVE_EPOCH - 1u);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get(), TEST_ACTIVE_EPOCH - 1u);
	ASSERT_NE(module->context().epoch_store, nullptr);
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 0, std::array{packet.get()}, scratch));
	const auto diagnostics = module->context().epoch_store->diagnostics_after_quiescence();
	EXPECT_EQ(diagnostics.mismatch_count, 1u);
	ASSERT_EQ(diagnostics.first_fault_valid, 1u);
	EXPECT_EQ(diagnostics.first_fault.packet_epoch, TEST_ACTIVE_EPOCH - 1u);
	EXPECT_EQ(diagnostics.first_fault.active_epoch, TEST_ACTIVE_EPOCH);
}

/** @brief Drop one mismatched packet, then execute the exact owner-local view. */
TEST(module_execution_views, exact_active_view_drops_mismatch_then_runs_on_owner_worker)
{
	auto module_or = test::exact_module_test_context::create("test_module", KINETUM_TEST_MODULE_PATH,
								 direct_module_resources());
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(TEST_ACTIVE_EPOCH, R"({"route_to_stage":9})").is_ok());

	dp_engine engine;
	module_batch_scratch scratch{};
	test::packet_record_test_owner packet(std::vector<uint8_t>(64, 0), TEST_ACTIVE_EPOCH - 1u);
	ASSERT_TRUE(packet.valid()) << packet.error();
	initialize_module_packet(*packet.get(), TEST_ACTIVE_EPOCH - 1u);
	ASSERT_NE(module->context().epoch_store, nullptr);
	EXPECT_FALSE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 0, std::array{packet.get()}, scratch));
	packet.metadata().epoch = TEST_ACTIVE_EPOCH;
	EXPECT_TRUE(
		engine.execute_module_stage(*module->context().epoch_store, 0, 0, std::array{packet.get()}, scratch));
	EXPECT_EQ(packet.metadata().module_next_stage, 9u);
	EXPECT_EQ(engine.stats().dropped_packets, 1u);
	EXPECT_EQ(module->context().epoch_store->diagnostics_after_quiescence().mismatch_count, 1u);
}

/** @brief Begin one exact active context with no fabricated callback observation. */
TEST(module_execution_views, active_callback_observation_state_starts_zero)
{
	auto harness = test::active_test_harness::create(direct_module_resources());
	ASSERT_TRUE(harness.valid()) << harness.error;
	EXPECT_EQ(harness.state->ingest_call_count.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(harness.state->ingest_total_packets.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(harness.state->last_ingest_epoch.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(harness.state->last_ingest_packet_config.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(harness.state->run_call_count.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(harness.state->control_call_count.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(harness.state->emit_call_count.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(harness.state->pull_ready_count.load(std::memory_order_relaxed), 0u);
}

/** @brief Deliver the exact context, epoch, and packet-config facts to INGEST. */
TEST(module_execution_views, active_callback_ingest_observes_exact_context_epoch_and_config)
{
	auto harness = test::active_test_harness::create(direct_module_resources());
	ASSERT_TRUE(harness.valid()) << harness.error;
	const uint64_t packet_config = UINT64_C(0xa5a55a5af00d1234);
	kinetum_batch_t batch{};
	batch.count = 2;
	batch.epoch = TEST_ACTIVE_EPOCH;
	batch.epoch_config = &packet_config;
	batch.ctx = &harness.module->context().packet_context;

	auto active_context = make_active_context(harness);
	EXPECT_EQ(harness.ingest(active_context, batch), KINETUM_FORWARD_MASK(batch.count));
	EXPECT_EQ(harness.state->ingest_call_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(harness.state->ingest_total_packets.load(std::memory_order_relaxed), batch.count);
	EXPECT_EQ(harness.state->last_ingest_epoch.load(std::memory_order_relaxed), TEST_ACTIVE_EPOCH);
	EXPECT_EQ(harness.state->last_ingest_packet_config.load(std::memory_order_relaxed),
		  reinterpret_cast<std::uintptr_t>(&packet_config));
}

/** @brief Deliver exact cached-time, epoch, expiry, and trigger facts to RUN. */
TEST(module_execution_views, active_callback_run_observes_exact_owner_turn)
{
	auto harness = test::active_test_harness::create(direct_module_resources());
	ASSERT_TRUE(harness.valid()) << harness.error;
	auto active_context = make_active_context(harness);
	const kinetum_active_timer_handle expired[]{{17u}, {29u}};
	active_context.now_ns = UINT64_C(987654321);
	active_context.active_epoch = TEST_ACTIVE_EPOCH;
	active_context.expired_count = 2;
	active_context.expired = expired;
	constexpr uint32_t TRIGGERS = KINETUM_TRIGGER_LOOP | KINETUM_TRIGGER_TIMER;

	harness.run(active_context, TRIGGERS);
	EXPECT_EQ(harness.state->run_call_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(harness.state->last_triggers.load(std::memory_order_relaxed), TRIGGERS);
	EXPECT_EQ(harness.state->last_expired_count.load(std::memory_order_relaxed), 2u);
	EXPECT_EQ(harness.state->last_now_ns.load(std::memory_order_relaxed), active_context.now_ns);
	EXPECT_EQ(harness.state->last_active_epoch.load(std::memory_order_relaxed), TEST_ACTIVE_EPOCH);
}

/** @brief Deliver one exact borrowed active-stage control message. */
TEST(module_execution_views, active_callback_control_observes_exact_message)
{
	auto harness = test::active_test_harness::create(direct_module_resources());
	ASSERT_TRUE(harness.valid()) << harness.error;
	const uint8_t payload[] = {0x11, 0x22, 0x33};
	const kinetum_control_msg message{
		.data = payload,
		.len = static_cast<uint32_t>(sizeof(payload)),
		.subtype = KINETUM_CONTROL_SUBTYPE_FEEDBACK,
	};

	auto active_context = make_active_context(harness);
	harness.deliver_control(active_context, message);
	EXPECT_EQ(harness.state->control_call_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(harness.state->last_control_subtype.load(std::memory_order_relaxed), message.subtype);
	EXPECT_EQ(harness.state->last_control_len.load(std::memory_order_relaxed), message.len);
}

/** @brief Prove a callback-only view cannot fabricate active-origin service authority. */
TEST(module_execution_views, active_callback_without_runtime_owner_cannot_claim_emit)
{
	auto harness = test::active_test_harness::create(direct_module_resources());
	ASSERT_TRUE(harness.valid()) << harness.error;
	auto active_context = make_active_context(harness);
	harness.state->emit_dscp.store(12, std::memory_order_relaxed);
	harness.state->emit_platform_flags.store(packet_platform_flags::L3_IPV4 | packet_platform_flags::L4_UDP,
						 std::memory_order_relaxed);
	harness.state->emit_proto.store(17, std::memory_order_relaxed);
	harness.state->emit_on_next_run.store(true, std::memory_order_relaxed);

	harness.run(active_context, KINETUM_TRIGGER_LOOP);
	EXPECT_EQ(harness.state->emit_call_count.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(harness.state->emit_total_packets.load(std::memory_order_relaxed), 0u);
}

/** @brief Observe PULL_READY without fabricating a runtime request authority. */
TEST(module_execution_views, active_callback_without_runtime_owner_cannot_publish_pull)
{
	auto harness = test::active_test_harness::create(direct_module_resources());
	ASSERT_TRUE(harness.valid()) << harness.error;
	auto active_context = make_active_context(harness);
	constexpr uint16_t PULL_TARGET = 23;
	harness.state->pull_target_idx.store(PULL_TARGET, std::memory_order_relaxed);

	harness.run(active_context, KINETUM_TRIGGER_PULL_READY);
	EXPECT_EQ(harness.state->pull_ready_count.load(std::memory_order_relaxed), 1u);
}

/** @brief Prove callback-only views cannot fabricate async or recirculation ownership. */
TEST(module_execution_views, active_callback_without_runtime_owner_cannot_publish_async_work)
{
	kinetum_active_ctx context{};
	kinetum_async_packet_view view{
		.data = reinterpret_cast<const void *>(std::uintptr_t{1}),
		.len = 9u,
		._padding = 7u,
	};
	kinetum_retained_packet_handle restored{0u};
	const kinetum_retained_packet_handle retained{1u};
	const auto standalone = kinetum_active_begin_async(&context, 3u);
	const auto packet = kinetum_active_begin_async_retained(&context, retained, 4u, &view);
	EXPECT_FALSE(kinetum_async_token_valid(&standalone));
	EXPECT_FALSE(kinetum_async_token_valid(&packet));
	EXPECT_EQ(view.data, nullptr);
	EXPECT_EQ(view.len, 0u);
	EXPECT_EQ(view._padding, 0u);
	EXPECT_FALSE(kinetum_active_abort_async(&context, standalone, &restored));
	EXPECT_EQ(restored.value, KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE);
	EXPECT_FALSE(kinetum_active_recirculate_retained(&context, retained));
	uint32_t completion_count = 9u;
	EXPECT_EQ(kinetum_active_async_completions(&context, &completion_count), nullptr);
	EXPECT_EQ(completion_count, 0u);
}

/** @brief Reject a module-originated invalid DSCP before test dispatch. */
TEST(module_execution_views, production_origin_validation_rejects_invalid_dscp_before_storage)
{
	uint8_t data = 0u;
	kinetum_emit_batch_t batch{};
	batch.data[0] = &data;
	batch.len[0] = 1u;
	batch.dscp[0] = 64u;
	batch.platform_flags[0] = packet_platform_flags::L3_IPV4 | packet_platform_flags::L4_UDP;
	batch.proto[0] = 17u;
	batch.count = 1u;
	EXPECT_FALSE(validate_active_origin_batch(&batch, 64u, 4u));
}

/** @brief Reject contradictory module-originated parser facts before dispatch. */
TEST(module_execution_views, production_origin_validation_rejects_incoherent_facts_before_storage)
{
	uint8_t data = 0u;
	kinetum_emit_batch_t batch{};
	batch.data[0] = &data;
	batch.len[0] = 1u;
	batch.platform_flags[0] = packet_platform_flags::L3_IPV4 | packet_platform_flags::L4_TCP;
	batch.proto[0] = 17u;
	batch.count = 1u;
	EXPECT_FALSE(validate_active_origin_batch(&batch, 64u, 4u));
}

}  // namespace
}  // namespace kinetum::dp::module
