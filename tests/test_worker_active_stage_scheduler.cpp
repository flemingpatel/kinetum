// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_active_stage_scheduler.cpp
 * @brief Exact synchronous and tracked-async active-stage ownership tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "src/dp/active/worker_active_stage_scheduler.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_record_test_harness.hpp"
#include "tests/test_active_helpers.hpp"
#include "tests/test_modules/test_active_async_module_state.hpp"

namespace kinetum::dp
{
namespace
{

/** Runtime generation shared by scheduler authorities. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 41u;
/** Initially activated module epoch. */
constexpr uint64_t TEST_ACTIVE_EPOCH = 7u;
/** Prepared replacement epoch used by drain tests. */
constexpr uint64_t TEST_TARGET_EPOCH = 11u;
/** Transition-command generation used to reject stale commands. */
constexpr uint64_t TEST_TRANSITION_GENERATION = 19u;
/** Context-memory authority supplied to the module fixture. */
constexpr uint64_t TEST_CONTEXT_BYTES = 64u * 1024u;
/** Per-epoch arena authority supplied to the module fixture. */
constexpr uint64_t TEST_EPOCH_BYTES = 4u * 1024u;
/** Bounded asynchronous cancellation grace used by deadline tests. */
constexpr uint64_t TEST_ASYNC_GRACE_MS = 5u;

/** @brief Minimal exact packet-operation owner used by the production scheduler surface. */
struct scheduler_packet_owner {
	worker_epoch_ledger *ledger{nullptr};	      ///< Exact test worker ledger.
	uint32_t emitted_origins{0};		      ///< Exact copied-origin observations.
	uint32_t retained_dispatches{0};	      ///< Accepted retained dispatches.
	uint32_t retained_drops{0};		      ///< Accepted retained drops.
	uint32_t recirculated{0};		      ///< Accepted same-instance recirculations.
	packet_record *recirculated_record{nullptr};  ///< Sole recirculated test ownership.

	/**
	 * @brief Reject test origins unless a row explicitly expects them.
	 * @param opaque Borrowed packet-owner observation state.
	 * @param batch Borrowed attempted origin batch.
	 * @param budget Maximum prefix offered by the scheduler.
	 * @return Zero; valid nonempty attempts increment the observation count but transfer no records.
	 */
	static uint32_t emit(void *opaque, uint32_t, uint64_t, uint64_t, const kinetum_emit_batch_t *batch,
			     uint32_t budget, std::span<packet_origin_view>, std::span<packet_record *>) noexcept
	{
		auto *owner = static_cast<scheduler_packet_owner *>(opaque);
		if (owner == nullptr || batch == nullptr || budget == 0u) {
			return 0u;
		}
		++owner->emitted_origins;
		return 0u;
	}

	/**
	 * @brief Consume one retained test record as terminal work.
	 * @param opaque Packet-owner state retaining the exact worker ledger.
	 * @param record Retained record whose epoch credit is retired.
	 * @param drop Whether to increment terminal-drop or dispatch evidence.
	 * @return true after retiring the ledger credit; malformed ownership fails stop.
	 */
	static bool publish(void *opaque, uint32_t, packet_record *record, uint16_t, bool drop) noexcept
	{
		auto *owner = static_cast<scheduler_packet_owner *>(opaque);
		if (owner == nullptr || owner->ledger == nullptr || record == nullptr) {
			std::terminate();
		}
		owner->ledger->retire(record->metadata.epoch);
		if (drop) {
			++owner->retained_drops;
		} else {
			++owner->retained_dispatches;
		}
		return true;
	}

	/**
	 * @brief Accept one same-instance recirculation without changing its ledger credit.
	 * @param opaque Packet-owner state retaining the ledger and one recirculation slot.
	 * @param record Candidate record transferred into that empty slot on success.
	 * @return true after retaining the record, or false without transfer on invalid/busy state.
	 */
	static bool recirculate(void *opaque, uint32_t, packet_record *record) noexcept
	{
		auto *owner = static_cast<scheduler_packet_owner *>(opaque);
		if (owner == nullptr || owner->ledger == nullptr || record == nullptr ||
		    owner->recirculated_record != nullptr) {
			return false;
		}
		owner->recirculated_record = record;
		++owner->recirculated;
		return true;
	}
};

/**
 * @brief Build one exact single-instance active compiled authority.
 * @return Compiled active-stage topology with fixed resource and ownership facts.
 */
provider::compiled_provider_topology make_active_topology()
{
	provider::compiled_provider_topology topology;
	topology.logical_stages.push_back({
		.logical_stage_id = "active0",
		.logical_stage_index = 0u,
		.kind = provider::compiled_stage_kind::MODULE,
		.execution_mode = provider::compiled_stage_execution_mode::ACTIVE,
		.trigger_mask = static_cast<uint32_t>(provider::compiled_active_stage_trigger::LOOP) |
				static_cast<uint32_t>(provider::compiled_active_stage_trigger::TIMER),
		.retained_packet_capacity = 4u,
		.retained_byte_capacity = 4096u,
		.timer_capacity = 1u,
		.control_mailbox_capacity = 0u,
		.control_message_capacity_bytes = 0u,
		.async_work_capacity = 0u,
		.async_cancel_grace = {},
		.schedule_order = 0,
		.module_id = "kinetum.test_active",
		.module_path = std::nullopt,
		.stage_instance_indices = {0u},
	});
	topology.execution_regions.push_back({
		.region_id = 0,
		.numa_node = 0,
		.logical_stage_indices = {0u},
		.stage_instance_indices = {0u},
		.worker_indices = {0u},
	});
	topology.stage_instances.push_back({
		.stage_instance_id = "active0@lane_0",
		.stage_instance_index = 0u,
		.logical_stage_id = "active0",
		.logical_stage_index = 0u,
		.lane_index = 0u,
		.region_index = 0u,
		.replica_index = 0u,
		.worker_index = 0u,
		.execution_provider_index = 0u,
		.module_context_index = 0u,
		.io_stream_index = std::nullopt,
		.active_origin_storage_domain_index = 0u,
		.reachable_storage_domain_indices = {0u},
		.dispatch_mode = provider::compiled_stage_dispatch_mode::TERMINAL,
		.packet_routes = {},
		.pull_source_stage_instance_indices = {},
	});
	topology.module_contexts.push_back({
		.context_instance_id = "active0@lane_0",
		.module_context_index = 0u,
		.stage_instance_index = 0u,
		.logical_stage_index = 0u,
		.worker_index = 0u,
		.cpu_core_id = 0,
		.region_id = 0,
		.numa_node = 0,
		.module_id = "kinetum.test_active",
		.context_memory_capacity_bytes = TEST_CONTEXT_BYTES,
		.epoch_arena_capacity_bytes = TEST_EPOCH_BYTES,
		.module_context_ordinal = 0u,
		.module_context_count = 1u,
	});
	topology.module_context_domains.push_back({"kinetum.test_active", {0u}});
	topology.storage_domains.resize(1u);
	topology.storage_domains[0].storage_domain_id = "storage_host_0";
	topology.storage_domains[0].storage_domain_index = 0u;
	topology.worker_schedules.push_back({
		.worker_index = 0u,
		.rx_stream_indices = {},
		.tx_stream_indices = {},
		.stage_instance_indices = {0u},
		.storage_transition_indices = {},
		.storage_domain_indices = {0u},
		.source_storage_domain_indices = {0u},
		.active_stage_instance_indices = {0u},
		.async_stage_instance_indices = {},
		.loop_trigger_stage_instance_indices = {0u},
		.timer_trigger_stage_instance_indices = {0u},
		.pull_trigger_stage_instance_indices = {},
		.control_trigger_stage_instance_indices = {},
		.inbound_control_edge_indices = {},
		.tx_stream_index_by_logical_port = {},
	});
	topology.transition_topology.workers.push_back({
		.worker_id = "worker_0",
		.worker_index = 0u,
		.worker_placement_index = 0u,
		.region_id = 0,
		.lane_id = "lane_0",
		.lane_index = 0u,
		.numa_node = 0,
		.cpu_core_ids = {0},
		.is_source = true,
		.is_sink = false,
		.owns_module_context = true,
		.source_epoch_staging_capacity = 8u,
		.health_poll_interval = {},
		.health_callback_budget = {},
		.stage_instance_indices = {0u},
		.io_stream_indices = {},
		.inbound_boundary_indices = {},
		.outbound_boundary_indices = {},
	});
	topology.transition_topology.source_worker_indices = {0u};
	topology.transition_topology.module_context_numa_nodes = {0};
	topology.transition_topology.policy.enabled = true;
	return topology;
}

/**
 * @brief Build one exact single-instance tracked-async compiled authority.
 * @return Active-async topology derived from the canonical active-stage fixture.
 */
provider::compiled_provider_topology make_async_topology()
{
	auto topology = make_active_topology();
	auto &logical = topology.logical_stages.front();
	logical.module_id = "kinetum.test_active_async";
	logical.trigger_mask = static_cast<uint32_t>(provider::compiled_active_stage_trigger::LOOP);
	logical.timer_capacity = 0u;
	logical.async_work_capacity = 1u;
	logical.async_cancel_grace = std::chrono::milliseconds(TEST_ASYNC_GRACE_MS);
	topology.module_contexts.front().module_id = "kinetum.test_active_async";
	topology.module_context_domains.front().module_id = "kinetum.test_active_async";
	auto &schedule = topology.worker_schedules.front();
	schedule.async_stage_instance_indices = {0u};
	schedule.timer_trigger_stage_instance_indices.clear();
	topology.transition_topology.policy.commit_timeout = std::chrono::milliseconds(100u);
	return topology;
}

/** @brief Own one activated module, ledger, scheduler, and exact test packet services. */
struct scheduler_fixture {
	std::unique_ptr<test::exact_module_test_context> module;   ///< Admitted module and lifecycle ownership.
	std::unique_ptr<worker_epoch_ledger> ledger;		   ///< Exact epoch-credit authority.
	std::unique_ptr<worker_active_stage_scheduler> scheduler;  ///< Production scheduler under test.
	scheduler_packet_owner packets;			///< Packet-operation observations and retained test ownership.
	provider::compiled_provider_topology topology;	///< Compiled facts borrowed by the scheduler.
	test::test_active_state *state{nullptr};	///< Borrowed active-module callback observations.

	/**
	 * @brief Build one exact active scheduler through production factories.
	 * @param retained_capacity Authored retained-packet population for this fixture.
	 * @param retained_bytes Authored aggregate retained-byte limit.
	 * @return Complete fixture or the first module, ledger, or scheduler admission error.
	 */
	static common::status_or<std::unique_ptr<scheduler_fixture>> create(uint32_t retained_capacity = 4u,
									    uint64_t retained_bytes = 4096u)
	{
		auto fixture = std::unique_ptr<scheduler_fixture>(new scheduler_fixture());
		auto module_or = test::exact_module_test_context::create(
			"kinetum.test_active", std::filesystem::path(KINETUM_TEST_ACTIVE_MODULE_PATH),
			{TEST_CONTEXT_BYTES, TEST_EPOCH_BYTES}, "active0@lane_0", 0u);
		if (!module_or.is_ok()) {
			return module_or.error();
		}
		fixture->module = std::move(module_or).value();
		if (const auto status = fixture->module->prepare_and_activate(TEST_ACTIVE_EPOCH, {}); !status.is_ok()) {
			return status;
		}
		fixture->state =
			static_cast<test::test_active_state *>(fixture->module->context().packet_context.state);
		if (fixture->state == nullptr) {
			return common::status::internal_error("active scheduler fixture lost context-local test state");
		}
		fixture->state->emit_on_next_run.store(false, std::memory_order_relaxed);
		fixture->state->arm_timer_delay_ns.store(0u, std::memory_order_relaxed);
		auto ledger_or = worker_epoch_ledger::create(0u, TEST_RUNTIME_GENERATION, 128u);
		if (!ledger_or.is_ok()) {
			return ledger_or.error();
		}
		fixture->ledger = std::move(ledger_or).value();
		fixture->ledger->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
		fixture->packets.ledger = fixture->ledger.get();
		fixture->topology = make_active_topology();
		fixture->topology.logical_stages.front().retained_packet_capacity = retained_capacity;
		fixture->topology.logical_stages.front().retained_byte_capacity = retained_bytes;
		const std::array<active_stage_context_binding, 1> contexts{{
			active_stage_context_binding{
				.stage_instance_index = 0u,
				.module_context_index = 0u,
				.store = fixture->module->context().epoch_store.get(),
				.descriptor = fixture->module->context().image->descriptor,
			},
		}};
		auto scheduler_or = worker_active_stage_scheduler::create(
			0u, fixture->topology, contexts, *fixture->ledger,
			active_stage_packet_operations{
				.state = &fixture->packets,
				.emit_origins = &scheduler_packet_owner::emit,
				.publish_retained = &scheduler_packet_owner::publish,
				.publish_recirculated = &scheduler_packet_owner::recirculate,
			});
		if (!scheduler_or.is_ok()) {
			return scheduler_or.error();
		}
		fixture->scheduler = std::move(scheduler_or).value();
		fixture->scheduler->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
		return fixture;
	}

	/** @brief Destroy scheduler before ledger and module ownership. */
	~scheduler_fixture()
	{
		scheduler.reset();
	}
};

/** @brief Own one exact tracked-async module, scheduler, ledger, and packet sink. */
struct async_scheduler_fixture {
	std::unique_ptr<test::exact_module_test_context> module;   ///< Exact async image/context.
	std::unique_ptr<worker_epoch_ledger> ledger;		   ///< Sole test credit authority.
	std::unique_ptr<worker_active_stage_scheduler> scheduler;  ///< Exact active owner.
	scheduler_packet_owner packets;				   ///< Narrow packet disposition owner.
	provider::compiled_provider_topology topology;		   ///< Complete compiled authority.
	test::test_active_async_state *state{nullptr};		   ///< Context-local canary state.

	/**
	 * @brief Construct one async scheduler with an exact caller-selected credit ceiling.
	 * @param maximum_unretired Exact test ledger ceiling.
	 * @param async_capacity Authored token-slot population for this fixture.
	 * @return Complete fixture or production-factory failure.
	 */
	static common::status_or<std::unique_ptr<async_scheduler_fixture>> create(uint64_t maximum_unretired = 16u,
										  uint32_t async_capacity = 1u)
	{
		auto fixture = std::unique_ptr<async_scheduler_fixture>(new async_scheduler_fixture());
		auto module_or = test::exact_module_test_context::create(
			"kinetum.test_active_async", std::filesystem::path(KINETUM_TEST_ACTIVE_ASYNC_MODULE_PATH),
			{TEST_CONTEXT_BYTES, TEST_EPOCH_BYTES}, "active0@lane_0", 0u);
		if (!module_or.is_ok()) {
			return module_or.error();
		}
		fixture->module = std::move(module_or).value();
		if (const auto status = fixture->module->prepare_and_activate(TEST_ACTIVE_EPOCH, {}); !status.is_ok()) {
			return status;
		}
		fixture->state =
			static_cast<test::test_active_async_state *>(fixture->module->context().packet_context.state);
		if (fixture->state == nullptr) {
			return common::status::internal_error(
				"async scheduler fixture lost context-local canary state");
		}
		fixture->state->autonomous.store(false, std::memory_order_relaxed);
		fixture->state->auto_complete.store(false, std::memory_order_relaxed);
		fixture->state->completion_action.store(test::async_completion_action::HOLD, std::memory_order_relaxed);
		auto ledger_or = worker_epoch_ledger::create(0u, TEST_RUNTIME_GENERATION, maximum_unretired);
		if (!ledger_or.is_ok()) {
			return ledger_or.error();
		}
		fixture->ledger = std::move(ledger_or).value();
		fixture->ledger->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
		fixture->packets.ledger = fixture->ledger.get();
		fixture->topology = make_async_topology();
		fixture->topology.logical_stages.front().async_work_capacity = async_capacity;
		const std::array<active_stage_context_binding, 1> contexts{{
			active_stage_context_binding{
				.stage_instance_index = 0u,
				.module_context_index = 0u,
				.store = fixture->module->context().epoch_store.get(),
				.descriptor = fixture->module->context().image->descriptor,
			},
		}};
		auto scheduler_or = worker_active_stage_scheduler::create(
			0u, fixture->topology, contexts, *fixture->ledger,
			active_stage_packet_operations{
				.state = &fixture->packets,
				.emit_origins = &scheduler_packet_owner::emit,
				.publish_retained = &scheduler_packet_owner::publish,
				.publish_recirculated = &scheduler_packet_owner::recirculate,
			});
		if (!scheduler_or.is_ok()) {
			return scheduler_or.error();
		}
		fixture->scheduler = std::move(scheduler_or).value();
		fixture->scheduler->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
		return fixture;
	}

	/** @brief Destroy scheduler before module, topology, and ledger ownership. */
	~async_scheduler_fixture()
	{
		scheduler.reset();
	}
};

/** @brief Exercise a repeated retain through the exact production service seam. */
void repeated_retain_child()
{
	auto fixture_or = scheduler_fixture::create();
	if (!fixture_or.is_ok()) {
		std::_Exit(0);
	}
	auto fixture = std::move(fixture_or).value();
	fixture->state->retain_on_next_ingest.store(true, std::memory_order_relaxed);
	fixture->state->retain_twice_on_next_ingest.store(true, std::memory_order_relaxed);
	test::packet_record_test_owner packet(std::vector<uint8_t>(64u, UINT8_C(0x37)), TEST_ACTIVE_EPOCH);
	if (!packet.valid()) {
		std::_Exit(0);
	}
	packet.metadata().current_stage = 0u;
	packet.metadata().current_stage_instance = 0u;
	fixture->ledger->acquire(TEST_ACTIVE_EPOCH);
	module_batch_scratch scratch{};
	(void)fixture->scheduler->ingest_synchronous(0u, std::array{packet.get()}, 0, scratch, UINT64_C(1000000));
	std::_Exit(0);
}

/** @brief Destroy one scheduler while an exact transition identity is live. */
void unresolved_transition_destruction_child()
{
	auto fixture_or = scheduler_fixture::create();
	if (!fixture_or.is_ok()) {
		std::_Exit(0);
	}
	auto fixture = std::move(fixture_or).value();
	if (!fixture->module->prepare(TEST_TARGET_EPOCH, {}).is_ok()) {
		std::_Exit(0);
	}
	fixture->ledger->bind_future_epoch(TEST_TARGET_EPOCH);
	if (!fixture->scheduler->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_TARGET_EPOCH)) {
		std::_Exit(0);
	}
	fixture->ledger->advance_source_epoch(TEST_TARGET_EPOCH);
	fixture.reset();
	std::_Exit(0);
}

/** @brief Exceed one exact tracked-async cancellation grace with live foreign work. */
void async_cancellation_deadline_child()
{
	auto fixture_or = async_scheduler_fixture::create(3u);
	if (!fixture_or.is_ok()) {
		std::_Exit(0);
	}
	auto fixture = std::move(fixture_or).value();
	fixture->state->begin_standalone_on_next_run.store(true, std::memory_order_relaxed);
	fixture->scheduler->service_turn_async(UINT64_C(1000000));
	if (!fixture->module->prepare(TEST_TARGET_EPOCH, {}).is_ok() ||
	    !fixture->scheduler->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
							    TEST_TARGET_EPOCH)) {
		std::_Exit(0);
	}
	fixture->ledger->bind_future_epoch(TEST_TARGET_EPOCH);
	if (!fixture->scheduler->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_TARGET_EPOCH)) {
		std::_Exit(0);
	}
	fixture->ledger->advance_source_epoch(TEST_TARGET_EPOCH);
	fixture->scheduler->service_turn_async(UINT64_C(2000000));
	fixture->scheduler->service_turn_async(UINT64_C(7000000));
	std::_Exit(0);
}

/** @brief Every retained batch lane owns one credit and drains through the same shutdown path. */
TEST(worker_active_stage_scheduler, full_ingest_batch_retains_each_lane_once)
{
	auto fixture_or = scheduler_fixture::create(64u, 4096u);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	std::array<std::unique_ptr<test::packet_record_test_owner>, 64u> owners;
	std::array<packet_record *, 64u> records{};
	for (std::size_t lane = 0u; lane < records.size(); ++lane) {
		owners[lane] = std::make_unique<test::packet_record_test_owner>(std::vector<uint8_t>(64u, 0u),
										TEST_ACTIVE_EPOCH);
		ASSERT_TRUE(owners[lane]->valid()) << owners[lane]->error();
		records[lane] = owners[lane]->get();
		records[lane]->metadata.current_stage = 0u;
		records[lane]->metadata.current_stage_instance = 0u;
	}
	for (std::size_t lane = 0u; lane < records.size(); ++lane) {
		fixture->ledger->acquire(TEST_ACTIVE_EPOCH);
	}
	fixture->state->retain_batch_mask.store(UINT64_MAX, std::memory_order_relaxed);
	module_batch_scratch scratch{};
	const auto result = fixture->scheduler->ingest_synchronous(0u, records, 0, scratch, UINT64_C(1000000));
	EXPECT_EQ(result, (active_ingest_result{0u, UINT64_MAX}));
	EXPECT_EQ(fixture->state->ingest_call_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(fixture->state->ingest_total_packets.load(std::memory_order_relaxed), 64u);
	for (std::size_t lane = 0u; lane < records.size(); ++lane) {
		if ((result.retained_mask & (UINT64_C(1) << lane)) == 0u) {
			fixture->ledger->retire(TEST_ACTIVE_EPOCH);
		}
	}
	fixture->scheduler->begin_shutdown();
	fixture->scheduler->service_turn_synchronous(UINT64_C(2000000));
	fixture->scheduler->service_turn_synchronous(UINT64_C(3000000));
	EXPECT_EQ(fixture->packets.retained_drops, 64u);
	EXPECT_TRUE(fixture->scheduler->empty());
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);
}

/** @brief Provisional lanes reserve bytes immediately and leave refused inputs forwarded. */
TEST(worker_active_stage_scheduler, ingest_prefix_cannot_overcommit_retained_bytes)
{
	auto fixture_or = scheduler_fixture::create(4u, 128u);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	std::array<std::unique_ptr<test::packet_record_test_owner>, 3u> owners;
	std::array<packet_record *, 3u> records{};
	for (std::size_t lane = 0u; lane < records.size(); ++lane) {
		owners[lane] = std::make_unique<test::packet_record_test_owner>(std::vector<uint8_t>(64u, 0u),
										TEST_ACTIVE_EPOCH);
		ASSERT_TRUE(owners[lane]->valid()) << owners[lane]->error();
		records[lane] = owners[lane]->get();
		records[lane]->metadata.current_stage = 0u;
		records[lane]->metadata.current_stage_instance = 0u;
	}
	for (std::size_t lane = 0u; lane < records.size(); ++lane) {
		fixture->ledger->acquire(TEST_ACTIVE_EPOCH);
	}
	fixture->state->retain_batch_mask.store(7u, std::memory_order_relaxed);
	module_batch_scratch scratch{};
	const auto result = fixture->scheduler->ingest_synchronous(0u, records, 0, scratch, UINT64_C(1000000));
	EXPECT_EQ(result, (active_ingest_result{4u, 3u}));
	for (std::size_t lane = 0u; lane < records.size(); ++lane) {
		if ((result.retained_mask & (UINT64_C(1) << lane)) == 0u) {
			fixture->ledger->retire(TEST_ACTIVE_EPOCH);
		}
	}
	fixture->scheduler->begin_shutdown();
	fixture->scheduler->service_turn_synchronous(UINT64_C(2000000));
	fixture->scheduler->service_turn_synchronous(UINT64_C(3000000));
	EXPECT_EQ(fixture->packets.retained_drops, 2u);
	EXPECT_TRUE(fixture->scheduler->empty());
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);
}

/** @brief Early async completion and synchronous abort preserve independent ingest-lane ownership. */
TEST(worker_active_stage_scheduler, ingest_batch_commits_completed_and_aborted_tokens_per_lane)
{
	auto fixture_or = async_scheduler_fixture::create(16u, 3u);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	std::array<std::unique_ptr<test::packet_record_test_owner>, 3u> owners;
	std::array<packet_record *, 3u> records{};
	for (std::size_t lane = 0u; lane < records.size(); ++lane) {
		owners[lane] = std::make_unique<test::packet_record_test_owner>(std::vector<uint8_t>(64u, 0u),
										TEST_ACTIVE_EPOCH);
		ASSERT_TRUE(owners[lane]->valid()) << owners[lane]->error();
		records[lane] = owners[lane]->get();
		records[lane]->metadata.current_stage = 0u;
		records[lane]->metadata.current_stage_instance = 0u;
	}
	for (std::size_t lane = 0u; lane < records.size(); ++lane) {
		fixture->ledger->acquire(TEST_ACTIVE_EPOCH);
	}
	fixture->state->inline_async_mask.store(7u, std::memory_order_relaxed);
	fixture->state->abort_token_on_begin.store(true, std::memory_order_relaxed);
	fixture->state->completion_action.store(test::async_completion_action::DROP, std::memory_order_relaxed);
	module_batch_scratch scratch{};
	const auto result = fixture->scheduler->ingest_async(0u, records, 0, scratch, UINT64_C(1000000));
	EXPECT_EQ(result, (active_ingest_result{0u, 7u}));
	for (std::size_t lane = 0u; lane < records.size(); ++lane) {
		if ((result.retained_mask & (UINT64_C(1) << lane)) == 0u) {
			fixture->ledger->retire(TEST_ACTIVE_EPOCH);
		}
	}
	fixture->scheduler->service_turn_async(UINT64_C(2000000));
	fixture->scheduler->service_turn_async(UINT64_C(3000000));
	EXPECT_EQ(fixture->state->begin_success_count.load(std::memory_order_relaxed), 3u);
	EXPECT_EQ(fixture->state->abort_success_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(fixture->state->completion_count.load(std::memory_order_relaxed), 2u);
	fixture->scheduler->begin_shutdown();
	fixture->scheduler->service_turn_async(UINT64_C(4000000));
	fixture->scheduler->service_turn_async(UINT64_C(5000000));
	EXPECT_EQ(fixture->packets.retained_drops, 3u);
	EXPECT_TRUE(fixture->scheduler->empty());
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);
}

/** @brief Prove retained ownership drains before exact target publication. */
TEST(worker_active_stage_scheduler, retained_packet_drain_preserves_one_credit_and_reuses_exact_slot)
{
	auto fixture_or = scheduler_fixture::create();
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	EXPECT_EQ(fixture->scheduler->numa_node(), 0);
	EXPECT_GT(fixture->scheduler->storage_bytes(), 0u);
	test::packet_record_test_owner invalid_lane_packet(std::vector<uint8_t>(64u, UINT8_C(0x20)), TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(invalid_lane_packet.valid()) << invalid_lane_packet.error();
	invalid_lane_packet.metadata().current_stage = 0u;
	invalid_lane_packet.metadata().current_stage_instance = 0u;
	fixture->state->retain_lane.store(1u, std::memory_order_relaxed);
	fixture->ledger->acquire(TEST_ACTIVE_EPOCH);
	module_batch_scratch scratch{};
	EXPECT_EQ(fixture->scheduler->ingest_synchronous(0u, std::array{invalid_lane_packet.get()}, 0, scratch,
							 UINT64_C(500000)),
		  (active_ingest_result{0u, 0u}));
	EXPECT_EQ(fixture->state->retained_handle.load(std::memory_order_relaxed),
		  KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE);
	fixture->ledger->retire(TEST_ACTIVE_EPOCH);

	test::packet_record_test_owner packet(std::vector<uint8_t>(64u, UINT8_C(0x21)), TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(packet.valid()) << packet.error();
	packet.metadata().current_stage = 0u;
	packet.metadata().current_stage_instance = 0u;
	fixture->state->retain_on_next_ingest.store(true, std::memory_order_relaxed);
	fixture->ledger->acquire(TEST_ACTIVE_EPOCH);
	EXPECT_EQ(fixture->scheduler->ingest_synchronous(0u, std::array{packet.get()}, 0, scratch, UINT64_C(1000000)),
		  (active_ingest_result{0u, 1u}));
	const uint64_t first_handle = fixture->state->retained_handle.load(std::memory_order_relaxed);
	ASSERT_NE(first_handle, KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE);
	EXPECT_FALSE(fixture->scheduler->empty());
	fixture->state->retained_emit_next_stage.store(UINT16_C(63), std::memory_order_relaxed);
	fixture->state->emit_retained_on_next_run.store(true, std::memory_order_relaxed);
	fixture->scheduler->service_turn_synchronous(UINT64_C(1500000));
	EXPECT_EQ(fixture->state->retained_handle.load(std::memory_order_relaxed), first_handle);
	EXPECT_EQ(fixture->packets.retained_dispatches, 0u);

	ASSERT_TRUE(fixture->module->prepare(TEST_TARGET_EPOCH, {}).is_ok());
	ASSERT_TRUE(fixture->scheduler->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
								   TEST_TARGET_EPOCH));
	fixture->ledger->bind_future_epoch(TEST_TARGET_EPOCH);
	ASSERT_TRUE(
		fixture->scheduler->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_TARGET_EPOCH));
	fixture->ledger->advance_source_epoch(TEST_TARGET_EPOCH);
	fixture->scheduler->service_turn_synchronous(UINT64_C(2000000));
	fixture->scheduler->service_turn_synchronous(UINT64_C(3000000));
	EXPECT_EQ(fixture->packets.retained_drops, 1u);
	EXPECT_TRUE(
		fixture->scheduler->activation_ready(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_TARGET_EPOCH));
	ASSERT_TRUE(fixture->module->context().epoch_store->activate_prepared(TEST_TARGET_EPOCH, 1u).is_ok());
	fixture->module->drain_telemetry_for_test();
	fixture->ledger->promote_future_epoch(TEST_TARGET_EPOCH);
	fixture->scheduler->activate(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_TARGET_EPOCH);
	EXPECT_EQ(fixture->scheduler->active_epoch(), TEST_TARGET_EPOCH);

	test::packet_record_test_owner reused_packet(std::vector<uint8_t>(64u, UINT8_C(0x22)), TEST_TARGET_EPOCH);
	ASSERT_TRUE(reused_packet.valid()) << reused_packet.error();
	reused_packet.metadata().current_stage = 0u;
	reused_packet.metadata().current_stage_instance = 0u;
	fixture->state->retain_on_next_ingest.store(true, std::memory_order_relaxed);
	fixture->ledger->acquire(TEST_TARGET_EPOCH);
	EXPECT_EQ(fixture->scheduler->ingest_synchronous(0u, std::array{reused_packet.get()}, 0, scratch,
							 UINT64_C(4000000)),
		  (active_ingest_result{0u, 1u}));
	const uint64_t reused_handle = fixture->state->retained_handle.load(std::memory_order_relaxed);
	EXPECT_NE(reused_handle, first_handle);
	fixture->state->drop_retained_on_next_run.store(true, std::memory_order_relaxed);
	fixture->scheduler->service_turn_synchronous(UINT64_C(5000000));
	fixture->scheduler->service_turn_synchronous(UINT64_C(6000000));
	EXPECT_EQ(fixture->packets.retained_drops, 2u);
	EXPECT_TRUE(fixture->scheduler->empty());
}

/** @brief Prove a second retain of one ingest lane is a module-contract violation. */
TEST(worker_active_stage_scheduler, repeated_retain_of_one_ingest_lane_fails_stop)
{
	EXPECT_DEATH(repeated_retain_child(), "");
}

/** @brief Prove a scheduler cannot retire with one unresolved transition generation. */
TEST(worker_active_stage_scheduler, unresolved_transition_destruction_fails_stop)
{
	EXPECT_DEATH(unresolved_transition_destruction_child(), "");
}

/** @brief Prove standalone completion-time resubmission fits the exact handoff ceiling. */
TEST(worker_active_stage_scheduler, async_standalone_completion_resubmits_with_exact_credit_handoff)
{
	auto fixture_or = async_scheduler_fixture::create(3u);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	ASSERT_TRUE(fixture->scheduler->has_async_work());
	fixture->state->completion_action.store(test::async_completion_action::RESUBMIT, std::memory_order_relaxed);
	fixture->state->next_user_tag.store(100u, std::memory_order_relaxed);
	fixture->state->begin_standalone_on_next_run.store(true, std::memory_order_relaxed);
	fixture->scheduler->service_turn_async(UINT64_C(1000000));
	const auto first = test::load_test_async_token(*fixture->state);
	ASSERT_TRUE(kinetum_async_token_valid(&first));
	EXPECT_EQ(fixture->ledger->active_unretired(), 1u);
	fixture->state->begin_standalone_on_next_run.store(true, std::memory_order_relaxed);
	fixture->scheduler->service_turn_async(UINT64_C(1500000));
	EXPECT_EQ(fixture->state->begin_failure_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(test::load_test_async_token(*fixture->state).handle.value, first.handle.value);
	EXPECT_EQ(fixture->ledger->active_unretired(), 1u);
	ASSERT_TRUE(kinetum_async_complete(&first, KINETUM_ASYNC_OUTCOME_SUCCESS));
	fixture->scheduler->service_turn_async(UINT64_C(2000000));
	EXPECT_EQ(fixture->state->completion_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(fixture->state->resubmitted_completion_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(fixture->ledger->active_unretired(), 1u);
	const auto second = test::load_test_async_token(*fixture->state);
	ASSERT_TRUE(kinetum_async_token_valid(&second));
	EXPECT_NE(second.handle.value, first.handle.value);
	EXPECT_EQ(fixture->state->last_completion_user_tag.load(std::memory_order_relaxed), 100u);
	fixture->state->completion_action.store(test::async_completion_action::HOLD, std::memory_order_relaxed);
	ASSERT_TRUE(kinetum_async_complete(&second, KINETUM_ASYNC_OUTCOME_CANCELLED));
	fixture->scheduler->service_turn_async(UINT64_C(3000000));
	EXPECT_EQ(fixture->state->completion_count.load(std::memory_order_relaxed), 2u);
	EXPECT_EQ(fixture->state->last_completion_user_tag.load(std::memory_order_relaxed), 101u);
	EXPECT_EQ(fixture->state->last_completion_outcome.load(std::memory_order_relaxed),
		  KINETUM_ASYNC_OUTCOME_CANCELLED);
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);
	EXPECT_TRUE(fixture->scheduler->empty());
}

/** @brief Prove packet-bound abort restores a fresh handle and completion drop retires once. */
TEST(worker_active_stage_scheduler, async_packet_abort_restores_then_completion_drops_exact_ownership)
{
	auto fixture_or = async_scheduler_fixture::create(3u);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	test::packet_record_test_owner packet(std::vector<uint8_t>(64u, UINT8_C(0x61)), TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(packet.valid()) << packet.error();
	packet.metadata().current_stage = 0u;
	packet.metadata().current_stage_instance = 0u;
	fixture->state->autonomous.store(true, std::memory_order_relaxed);
	fixture->state->abort_token_on_begin.store(true, std::memory_order_relaxed);
	fixture->ledger->acquire(TEST_ACTIVE_EPOCH);
	module_batch_scratch scratch{};
	ASSERT_EQ(fixture->scheduler->ingest_async(0u, std::array{packet.get()}, 0, scratch, UINT64_C(500000)),
		  (active_ingest_result{0u, 1u}));
	fixture->state->autonomous.store(false, std::memory_order_relaxed);
	const uint64_t restored = fixture->state->retained_handle.load(std::memory_order_relaxed);
	EXPECT_NE(restored, KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE);
	EXPECT_NE(restored, fixture->state->last_begin_retained_handle.load(std::memory_order_relaxed));
	EXPECT_EQ(fixture->state->abort_success_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(fixture->ledger->active_unretired(), 1u);

	fixture->state->next_user_tag.store(200u, std::memory_order_relaxed);
	fixture->state->begin_retained_on_next_run.store(true, std::memory_order_relaxed);
	fixture->scheduler->service_turn_async(UINT64_C(1000000));
	const auto token = test::load_test_async_token(*fixture->state);
	ASSERT_TRUE(kinetum_async_token_valid(&token));
	EXPECT_EQ(fixture->state->packet_view_data.load(std::memory_order_relaxed),
		  static_cast<const void *>(packet.get()->storage.data));
	EXPECT_EQ(fixture->state->packet_view_length.load(std::memory_order_relaxed), packet.get()->storage.length);
	fixture->state->completion_action.store(test::async_completion_action::DROP, std::memory_order_relaxed);
	ASSERT_TRUE(kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_FAILED));
	fixture->scheduler->service_turn_async(UINT64_C(2000000));
	fixture->scheduler->service_turn_async(UINT64_C(3000000));
	EXPECT_EQ(fixture->state->last_completion_outcome.load(std::memory_order_relaxed),
		  KINETUM_ASYNC_OUTCOME_FAILED);
	EXPECT_EQ(fixture->packets.retained_drops, 1u);
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);
	EXPECT_TRUE(fixture->scheduler->empty());
}

/** @brief Prove post-cancellation SUCCESS is delivered before exact target activation. */
TEST(worker_active_stage_scheduler, async_post_cancellation_success_drains_before_activation)
{
	auto fixture_or = async_scheduler_fixture::create(3u);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->state->next_user_tag.store(300u, std::memory_order_relaxed);
	fixture->state->begin_standalone_on_next_run.store(true, std::memory_order_relaxed);
	fixture->scheduler->service_turn_async(UINT64_C(1000000));
	const auto token = test::load_test_async_token(*fixture->state);
	ASSERT_TRUE(kinetum_async_token_valid(&token));
	ASSERT_TRUE(fixture->module->prepare(TEST_TARGET_EPOCH, {}).is_ok());
	ASSERT_TRUE(fixture->scheduler->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
								   TEST_TARGET_EPOCH));
	fixture->ledger->bind_future_epoch(TEST_TARGET_EPOCH);
	ASSERT_TRUE(
		fixture->scheduler->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_TARGET_EPOCH));
	fixture->ledger->advance_source_epoch(TEST_TARGET_EPOCH);
	EXPECT_TRUE(kinetum_async_cancellation_requested(&token));
	ASSERT_TRUE(kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_SUCCESS));
	fixture->scheduler->service_turn_async(UINT64_C(2000000));
	EXPECT_EQ(fixture->state->last_completion_outcome.load(std::memory_order_relaxed),
		  KINETUM_ASYNC_OUTCOME_SUCCESS);
	EXPECT_TRUE(
		fixture->scheduler->activation_ready(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_TARGET_EPOCH));
	ASSERT_TRUE(fixture->module->context().epoch_store->activate_prepared(TEST_TARGET_EPOCH, 1u).is_ok());
	fixture->module->drain_telemetry_for_test();
	fixture->ledger->promote_future_epoch(TEST_TARGET_EPOCH);
	fixture->scheduler->activate(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_TARGET_EPOCH);
	EXPECT_EQ(fixture->scheduler->active_epoch(), TEST_TARGET_EPOCH);
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);
	EXPECT_TRUE(fixture->scheduler->empty());
}

/** @brief Prove one packet-bound completion recirculates to its exact stage without another credit. */
TEST(worker_active_stage_scheduler, async_completion_recirculates_same_instance_with_one_credit)
{
	auto fixture_or = async_scheduler_fixture::create(3u);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	test::packet_record_test_owner packet(std::vector<uint8_t>(64u, UINT8_C(0x71)), TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(packet.valid()) << packet.error();
	packet.metadata().current_stage = 0u;
	packet.metadata().current_stage_instance = 0u;
	fixture->state->retain_on_next_ingest.store(true, std::memory_order_relaxed);
	fixture->ledger->acquire(TEST_ACTIVE_EPOCH);
	module_batch_scratch scratch{};
	ASSERT_EQ(fixture->scheduler->ingest_async(0u, std::array{packet.get()}, 0, scratch, UINT64_C(500000)),
		  (active_ingest_result{0u, 1u}));
	fixture->state->begin_retained_on_next_run.store(true, std::memory_order_relaxed);
	fixture->scheduler->service_turn_async(UINT64_C(1000000));
	const auto token = test::load_test_async_token(*fixture->state);
	ASSERT_TRUE(kinetum_async_token_valid(&token));
	fixture->state->completion_action.store(test::async_completion_action::RECIRCULATE, std::memory_order_relaxed);
	ASSERT_TRUE(kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_SUCCESS));
	fixture->scheduler->service_turn_async(UINT64_C(2000000));
	fixture->scheduler->service_turn_async(UINT64_C(3000000));
	EXPECT_EQ(fixture->packets.recirculated, 1u);
	EXPECT_EQ(fixture->packets.recirculated_record, packet.get());
	EXPECT_EQ(fixture->ledger->active_unretired(), 1u);
	fixture->packets.recirculated_record = nullptr;
	fixture->ledger->retire(TEST_ACTIVE_EPOCH);
	EXPECT_TRUE(fixture->scheduler->empty());
}

/** @brief Prove exact cancellation-grace expiry is worker fail-stop. */
TEST(worker_active_stage_scheduler, async_cancellation_grace_expiry_fails_stop)
{
	EXPECT_DEATH(async_cancellation_deadline_child(), "");
}

/** @brief Prove async specialization, shutdown cancellation, projection, and timeout admission. */
TEST(worker_active_stage_scheduler, async_projection_capability_and_grace_are_revalidated)
{
	auto fixture_or = async_scheduler_fixture::create(3u);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	EXPECT_TRUE(fixture->scheduler->has_async_work());
	fixture->scheduler->begin_shutdown();
	fixture->scheduler->service_turn_async(UINT64_C(1000000));
	EXPECT_TRUE(fixture->scheduler->empty());
	fixture->scheduler->service_turn_async(UINT64_C(2000000));
	EXPECT_TRUE(fixture->scheduler->empty());
	fixture->scheduler.reset();
	const std::array<active_stage_context_binding, 1> contexts{{
		active_stage_context_binding{
			.stage_instance_index = 0u,
			.module_context_index = 0u,
			.store = fixture->module->context().epoch_store.get(),
			.descriptor = fixture->module->context().image->descriptor,
		},
	}};
	const active_stage_packet_operations operations{
		.state = &fixture->packets,
		.emit_origins = &scheduler_packet_owner::emit,
		.publish_retained = &scheduler_packet_owner::publish,
		.publish_recirculated = &scheduler_packet_owner::recirculate,
	};

	auto missing_projection = fixture->topology;
	missing_projection.worker_schedules.front().async_stage_instance_indices.clear();
	auto projection_or =
		worker_active_stage_scheduler::create(0u, missing_projection, contexts, *fixture->ledger, operations);
	ASSERT_FALSE(projection_or.is_ok());
	EXPECT_NE(projection_or.error().message().find("trigger schedules"), std::string::npos);

	auto invalid_grace = fixture->topology;
	invalid_grace.logical_stages.front().async_cancel_grace =
		invalid_grace.transition_topology.policy.commit_timeout;
	auto grace_or =
		worker_active_stage_scheduler::create(0u, invalid_grace, contexts, *fixture->ledger, operations);
	ASSERT_FALSE(grace_or.is_ok());
	EXPECT_NE(grace_or.error().message().find("capability"), std::string::npos);

	auto inexact_grace = fixture->topology;
	inexact_grace.logical_stages.front().async_cancel_grace = std::chrono::nanoseconds(1u);
	auto inexact_or =
		worker_active_stage_scheduler::create(0u, inexact_grace, contexts, *fixture->ledger, operations);
	ASSERT_FALSE(inexact_or.is_ok());
	EXPECT_NE(inexact_or.error().message().find("capability"), std::string::npos);
}

/** @brief Prove timer quota, cancellation, expiry, and callback credit are exact. */
TEST(worker_active_stage_scheduler, timer_arm_and_expiry_use_one_exact_instance_credit)
{
	auto fixture_or = scheduler_fixture::create();
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->state->arm_timer_delay_ns.store(UINT64_C(1000000), std::memory_order_relaxed);
	fixture->scheduler->service_turn_synchronous(UINT64_C(1000000));
	EXPECT_FALSE(fixture->scheduler->empty());
	fixture->state->cancel_timer_on_next_run.store(true, std::memory_order_relaxed);
	fixture->scheduler->service_turn_synchronous(UINT64_C(1500000));
	EXPECT_EQ(fixture->state->cancelled_timer_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(fixture->state->timer_handle.load(std::memory_order_relaxed),
		  KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE);
	EXPECT_EQ(fixture->state->timer_trigger_count.load(std::memory_order_relaxed), 0u);
	EXPECT_TRUE(fixture->scheduler->empty());
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);

	fixture->state->arm_timer_delay_ns.store(UINT64_C(1000000), std::memory_order_relaxed);
	fixture->scheduler->service_turn_synchronous(UINT64_C(2000000));
	fixture->state->arm_timer_delay_ns.store(UINT64_C(1000000), std::memory_order_relaxed);
	fixture->scheduler->service_turn_synchronous(UINT64_C(4000000));
	EXPECT_EQ(fixture->state->timer_trigger_count.load(std::memory_order_relaxed), 1u);
	EXPECT_FALSE(fixture->scheduler->empty());
	fixture->scheduler->service_turn_synchronous(UINT64_C(6000000));
	EXPECT_EQ(fixture->state->timer_trigger_count.load(std::memory_order_relaxed), 2u);
	EXPECT_TRUE(fixture->scheduler->empty());
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);
}

/** @brief Prove copied control and deduplicated PULL remain exact per instance. */
TEST(worker_active_stage_scheduler, control_and_pull_use_exact_same_worker_instance_credits)
{
	auto first_or = test::exact_module_test_context::create("kinetum.test_active",
								std::filesystem::path(KINETUM_TEST_ACTIVE_MODULE_PATH),
								{TEST_CONTEXT_BYTES, TEST_EPOCH_BYTES},
								"active0@lane_0", 0u);
	auto second_or = test::exact_module_test_context::create("kinetum.test_active",
								 std::filesystem::path(KINETUM_TEST_ACTIVE_MODULE_PATH),
								 {TEST_CONTEXT_BYTES, TEST_EPOCH_BYTES},
								 "active1@lane_0", 1u);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto first = std::move(first_or).value();
	auto second = std::move(second_or).value();
	ASSERT_TRUE(first->prepare_and_activate(TEST_ACTIVE_EPOCH, {}).is_ok());
	ASSERT_TRUE(second->prepare_and_activate(TEST_ACTIVE_EPOCH, {}).is_ok());
	auto *first_state = static_cast<test::test_active_state *>(first->context().packet_context.state);
	auto *second_state = static_cast<test::test_active_state *>(second->context().packet_context.state);
	ASSERT_NE(first_state, nullptr);
	ASSERT_NE(second_state, nullptr);
	for (auto *state : {first_state, second_state}) {
		state->emit_on_next_run.store(false, std::memory_order_relaxed);
		state->arm_timer_delay_ns.store(0u, std::memory_order_relaxed);
		state->retain_on_next_ingest.store(false, std::memory_order_relaxed);
	}

	auto topology = make_active_topology();
	auto &source_logical = topology.logical_stages[0];
	source_logical.trigger_mask = static_cast<uint32_t>(provider::compiled_active_stage_trigger::LOOP) |
				      static_cast<uint32_t>(provider::compiled_active_stage_trigger::PULL_READY);
	source_logical.timer_capacity = 0u;
	auto destination_logical = source_logical;
	destination_logical.logical_stage_id = "active1";
	destination_logical.logical_stage_index = 1u;
	destination_logical.trigger_mask = static_cast<uint32_t>(provider::compiled_active_stage_trigger::LOOP) |
					   static_cast<uint32_t>(provider::compiled_active_stage_trigger::CONTROL);
	destination_logical.control_mailbox_capacity = 4u;
	destination_logical.control_message_capacity_bytes = 32u;
	destination_logical.stage_instance_indices = {1u};
	topology.logical_stages.push_back(std::move(destination_logical));
	auto destination_stage = topology.stage_instances[0];
	destination_stage.stage_instance_id = "active1@lane_0";
	destination_stage.stage_instance_index = 1u;
	destination_stage.logical_stage_id = "active1";
	destination_stage.logical_stage_index = 1u;
	destination_stage.module_context_index = 1u;
	destination_stage.pull_source_stage_instance_indices = {0u};
	topology.stage_instances.push_back(std::move(destination_stage));
	auto &source_stage = topology.stage_instances[0];
	source_stage.dispatch_mode = provider::compiled_stage_dispatch_mode::PRIORITY_ROUTE;
	source_stage.packet_routes.push_back({
		.destination_stage_instance_indices = {1u},
		.condition = {},
		.priority = 0,
		.authored_edge_index = 0u,
		.mode = provider::compiled_packet_edge_mode::PULL,
	});
	auto destination_context = topology.module_contexts[0];
	destination_context.context_instance_id = "active1@lane_0";
	destination_context.module_context_index = 1u;
	destination_context.stage_instance_index = 1u;
	destination_context.logical_stage_index = 1u;
	topology.module_contexts.push_back(std::move(destination_context));
	topology.execution_regions[0].logical_stage_indices = {0u, 1u};
	topology.execution_regions[0].stage_instance_indices = {0u, 1u};
	auto &schedule = topology.worker_schedules[0];
	schedule.stage_instance_indices = {0u, 1u};
	schedule.active_stage_instance_indices = {0u, 1u};
	schedule.loop_trigger_stage_instance_indices = {0u, 1u};
	schedule.timer_trigger_stage_instance_indices.clear();
	schedule.pull_trigger_stage_instance_indices = {0u};
	schedule.control_trigger_stage_instance_indices = {1u};
	schedule.inbound_control_edge_indices = {0u};
	topology.transition_topology.workers[0].stage_instance_indices = {0u, 1u};
	topology.control_edges.push_back({
		.control_edge_index = 0u,
		.authored_control_edge_index = 0u,
		.from_stage_instance_index = 0u,
		.to_stage_instance_index = 1u,
		.worker_index = 0u,
		.subtype = provider::compiled_control_edge_subtype::GENERIC,
	});

	auto ledger_or = worker_epoch_ledger::create(0u, TEST_RUNTIME_GENERATION, 128u);
	ASSERT_TRUE(ledger_or.is_ok()) << ledger_or.error().message();
	auto ledger = std::move(ledger_or).value();
	ledger->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	scheduler_packet_owner packets{.ledger = ledger.get()};
	const std::array<active_stage_context_binding, 2> contexts{{
		{0u, 0u, first->context().epoch_store.get(), first->context().image->descriptor},
		{1u, 1u, second->context().epoch_store.get(), second->context().image->descriptor},
	}};
	auto resource_residue = topology;
	resource_residue.logical_stages[0].control_mailbox_capacity = 1u;
	auto residue_or = worker_active_stage_scheduler::create(
		0u, resource_residue, contexts, *ledger,
		active_stage_packet_operations{&packets, &scheduler_packet_owner::emit,
					       &scheduler_packet_owner::publish, &scheduler_packet_owner::recirculate});
	ASSERT_FALSE(residue_or.is_ok());
	EXPECT_NE(residue_or.error().message().find("resource contract"), std::string::npos);

	auto unknown_trigger = topology;
	unknown_trigger.logical_stages[0].trigger_mask |= KINETUM_TRIGGER_DRAIN;
	auto unknown_trigger_or = worker_active_stage_scheduler::create(
		0u, unknown_trigger, contexts, *ledger,
		active_stage_packet_operations{&packets, &scheduler_packet_owner::emit,
					       &scheduler_packet_owner::publish, &scheduler_packet_owner::recirculate});
	ASSERT_FALSE(unknown_trigger_or.is_ok());
	EXPECT_NE(unknown_trigger_or.error().message().find("resource contract"), std::string::npos);

	auto duplicate_control = topology;
	duplicate_control.control_edges.push_back({
		.control_edge_index = 1u,
		.authored_control_edge_index = 1u,
		.from_stage_instance_index = 0u,
		.to_stage_instance_index = 1u,
		.worker_index = 0u,
		.subtype = provider::compiled_control_edge_subtype::FEEDBACK,
	});
	duplicate_control.worker_schedules[0].inbound_control_edge_indices = {0u, 1u};
	auto duplicate_or = worker_active_stage_scheduler::create(
		0u, duplicate_control, contexts, *ledger,
		active_stage_packet_operations{&packets, &scheduler_packet_owner::emit,
					       &scheduler_packet_owner::publish, &scheduler_packet_owner::recirculate});
	ASSERT_FALSE(duplicate_or.is_ok());
	EXPECT_NE(duplicate_or.error().message().find("control-edge schedule"), std::string::npos);

	auto invalid_subtype = topology;
	invalid_subtype.control_edges[0].subtype = static_cast<provider::compiled_control_edge_subtype>(UINT8_C(0xff));
	auto invalid_subtype_or = worker_active_stage_scheduler::create(
		0u, invalid_subtype, contexts, *ledger,
		active_stage_packet_operations{&packets, &scheduler_packet_owner::emit,
					       &scheduler_packet_owner::publish, &scheduler_packet_owner::recirculate});
	ASSERT_FALSE(invalid_subtype_or.is_ok());
	EXPECT_NE(invalid_subtype_or.error().message().find("invalid subtype"), std::string::npos);

	auto scheduler_or = worker_active_stage_scheduler::create(
		0u, topology, contexts, *ledger,
		active_stage_packet_operations{&packets, &scheduler_packet_owner::emit,
					       &scheduler_packet_owner::publish, &scheduler_packet_owner::recirculate});
	ASSERT_TRUE(scheduler_or.is_ok()) << scheduler_or.error().message();
	auto scheduler = std::move(scheduler_or).value();
	scheduler->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	test::packet_record_test_owner first_packet(std::vector<uint8_t>(32u, UINT8_C(0x51)), TEST_ACTIVE_EPOCH);
	test::packet_record_test_owner second_packet(std::vector<uint8_t>(32u, UINT8_C(0x52)), TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(first_packet.valid()) << first_packet.error();
	ASSERT_TRUE(second_packet.valid()) << second_packet.error();
	first_packet.metadata().current_stage = 0u;
	first_packet.metadata().current_stage_instance = 0u;
	second_packet.metadata().current_stage = 1u;
	second_packet.metadata().current_stage_instance = 1u;
	first_state->retain_on_next_ingest.store(true, std::memory_order_relaxed);
	second_state->retain_on_next_ingest.store(true, std::memory_order_relaxed);
	ledger->acquire(TEST_ACTIVE_EPOCH);
	ledger->acquire(TEST_ACTIVE_EPOCH);
	module_batch_scratch scratch{};
	ASSERT_EQ(scheduler->ingest_synchronous(0u, std::array{first_packet.get()}, 0, scratch, UINT64_C(500000)),
		  (active_ingest_result{0u, 1u}));
	ASSERT_EQ(scheduler->ingest_synchronous(1u, std::array{second_packet.get()}, 0, scratch, UINT64_C(500000)),
		  (active_ingest_result{0u, 1u}));
	const uint64_t first_handle = first_state->retained_handle.load(std::memory_order_relaxed);
	const uint64_t second_handle = second_state->retained_handle.load(std::memory_order_relaxed);
	ASSERT_NE(first_handle, second_handle);
	second_state->retained_handle.store(first_handle, std::memory_order_relaxed);
	second_state->drop_retained_on_next_run.store(true, std::memory_order_relaxed);
	scheduler->service_turn_synchronous(UINT64_C(750000));
	EXPECT_EQ(packets.retained_drops, 0u);
	second_state->retained_handle.store(second_handle, std::memory_order_relaxed);
	first_state->drop_retained_on_next_run.store(true, std::memory_order_relaxed);
	second_state->drop_retained_on_next_run.store(true, std::memory_order_relaxed);
	scheduler->service_turn_synchronous(UINT64_C(900000));
	scheduler->service_turn_synchronous(UINT64_C(950000));
	EXPECT_EQ(packets.retained_drops, 2u);
	EXPECT_TRUE(scheduler->empty());

	first_state->post_control_target.store(1u, std::memory_order_relaxed);
	first_state->post_control_subtype.store(KINETUM_CONTROL_SUBTYPE_FEEDBACK, std::memory_order_relaxed);
	second_state->pull_target_idx.store(0u, std::memory_order_relaxed);
	second_state->pull_repeat_count.store(2u, std::memory_order_relaxed);
	scheduler->service_turn_synchronous(UINT64_C(1000000));
	EXPECT_EQ(first_state->posted_control_count.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(second_state->control_call_count.load(std::memory_order_relaxed), 0u);
	first_state->post_control_target.store(1u, std::memory_order_relaxed);
	first_state->post_control_subtype.store(KINETUM_CONTROL_SUBTYPE_GENERIC, std::memory_order_relaxed);
	first_state->post_control_payload_len.store(1u, std::memory_order_relaxed);
	first_state->post_control_payload_value.store(UINT8_C(0x5a), std::memory_order_relaxed);
	scheduler->service_turn_synchronous(UINT64_C(2000000));
	EXPECT_EQ(first_state->posted_control_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(second_state->control_call_count.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(second_state->last_control_subtype.load(std::memory_order_relaxed), KINETUM_CONTROL_SUBTYPE_GENERIC);
	EXPECT_EQ(second_state->last_control_len.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(second_state->last_control_first_byte.load(std::memory_order_relaxed), UINT8_C(0x5a));
	EXPECT_EQ(first_state->pull_ready_count.load(std::memory_order_relaxed), 1u);
	EXPECT_TRUE(scheduler->empty());
	EXPECT_EQ(ledger->active_unretired(), 0u);

	second_state->mutate_control_context_on_next.store(true, std::memory_order_relaxed);
	first_state->post_control_repeat_count.store(2u, std::memory_order_relaxed);
	first_state->post_control_target.store(1u, std::memory_order_relaxed);
	first_state->post_control_subtype.store(KINETUM_CONTROL_SUBTYPE_GENERIC, std::memory_order_relaxed);
	scheduler->service_turn_synchronous(UINT64_C(3000000));
	EXPECT_EQ(first_state->posted_control_count.load(std::memory_order_relaxed), 3u);
	EXPECT_EQ(second_state->control_call_count.load(std::memory_order_relaxed), 3u);
	EXPECT_EQ(second_state->invalid_control_context_count.load(std::memory_order_relaxed), 0u);
	EXPECT_TRUE(scheduler->empty());

	first_state->post_control_target.store(1u, std::memory_order_relaxed);
	first_state->post_control_payload_len.store(33u, std::memory_order_relaxed);
	scheduler->service_turn_synchronous(UINT64_C(4000000));
	EXPECT_EQ(first_state->posted_control_count.load(std::memory_order_relaxed), 3u);
	EXPECT_EQ(second_state->control_call_count.load(std::memory_order_relaxed), 3u);
	EXPECT_TRUE(scheduler->empty());
	scheduler.reset();
}

}  // namespace
}  // namespace kinetum::dp
