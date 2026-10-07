// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_partitioned_runtime_construction.cpp
 * @brief Complete-generation construction, Bootstrap, and transaction-admission tests.
 * @author Fleming Patel
 *
 * Every executable test constructs the production host/UDP provider graph
 * through the real planner, compiler, signed component admission, materializer,
 * module lifecycle, worker kernel, command mailbox, and coordinator authorities.
 * No test-only runtime constructor, admission path, or capacity default exists.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <poll.h>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/unknown_field_set.h>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/transition/cpu/v1/cpu_transition.pb.h"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/status.hpp"
#include "src/dp/epoch/epoch_transition_coordinator.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/packet_runtime_generation.hpp"
#include "src/dp/partitioned_runtime.hpp"
#include "src/dp/dataplane_control_service.hpp"
#include "src/dp/runtime_status.hpp"
#include "tests/test_dp_helpers.hpp"
#include "tests/packet_runtime_test_fixture.hpp"

#if !defined(KINETUM_TEST_MODULE_PATH) || !defined(KINETUM_TEST_ACTIVE_MODULE_PATH) || \
	!defined(KINETUM_TEST_ACTIVE_ASYNC_MODULE_PATH)
#error "Exact passive, active, and tracked-async test-module paths are required"
#endif

namespace kinetum::dp
{
namespace
{

/** Context-memory authority supplied to admitted fixture modules. */
constexpr uint64_t TEST_MODULE_CONTEXT_CAPACITY_BYTES = uint64_t{64} * 1024u;
/** Epoch-arena authority supplied to admitted fixture modules. */
constexpr uint64_t TEST_MODULE_EPOCH_CAPACITY_BYTES = uint64_t{4} * 1024u;
/** Bounded wait for an expected fixture datagram. */
constexpr int TEST_PACKET_TIMEOUT_MS = 2000;
/** Observation window proving absence of an unexpected datagram. */
constexpr int TEST_NO_PACKET_TIMEOUT_MS = 100;
/** Bound on observing owner-published ledger state. */
constexpr auto TEST_LEDGER_OBSERVATION_TIMEOUT = std::chrono::seconds(1);

using kinetum::common::status_code;
using kinetum::test::packet_runtime_test_owner;

/**
 * @brief Inject one top-level unknown protobuf field into a request fixture.
 *
 * @tparam message_type Generated protobuf message type.
 * @param message Non-null mutable request.
 */
template <typename message_type>
void inject_unknown_field(message_type *message)
{
	auto *unknown = message->GetReflection()->MutableUnknownFields(message);
	unknown->AddVarint(127, 1u);
}

/** @brief Test fixture owning one production-shaped CONTROL_READY generation. */
class PacketRuntimeConstructionTest : public ::testing::Test {
    protected:
	/** @brief Construct one exact runtime with the required gate-host resources. */
	void SetUp() override
	{
		auto owner_or = packet_runtime_test_owner::create();
		ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
		owner_ = std::move(owner_or).value();
	}

	std::unique_ptr<packet_runtime_test_owner> owner_;  ///< Exact generation and fixture ownership.
};

/**
 * @brief Read and require the coherent runtime-status publication.
 *
 * @param runtime Complete runtime generation.
 * @return Exact observer-owned status snapshot.
 */
runtime_status_snapshot read_status(const partitioned_runtime &runtime)
{
	runtime_status_snapshot observed{};
	EXPECT_EQ(runtime.status_publication().try_read(observed), publication_read_result::AVAILABLE);
	return observed;
}

/**
 * @brief Read and require the coordinator's coherent progress publication.
 *
 * @param runtime Complete runtime generation.
 * @return Exact observer-owned transition progress.
 */
epoch_transition_progress_snapshot read_transition_progress(const partitioned_runtime &runtime)
{
	epoch_transition_progress_snapshot observed{};
	EXPECT_EQ(runtime.try_read_transition_progress(observed), publication_read_result::AVAILABLE);
	return observed;
}

/**
 * @brief Require every compiled worker ledger to remain unpublished before Bootstrap.
 *
 * @param runtime Complete CONTROL_READY runtime generation.
 */
void expect_worker_ownership_unpublished(const partitioned_runtime &runtime)
{
	const auto progress = read_transition_progress(runtime);
	ASSERT_NE(progress.execution_participant_count, 0u);
	for (uint32_t worker_index = 0; worker_index < progress.execution_participant_count; ++worker_index) {
		worker_epoch_ledger_snapshot observation{};
		EXPECT_EQ(runtime.try_read_worker_epoch_ownership(worker_index, observation),
			  publication_read_result::UNAVAILABLE);
	}
}

/**
 * @brief Require exact zero-credit Bootstrap publication from every compiled worker.
 *
 * @param runtime Complete runtime generation.
 * @param expected_epoch Exact active/source Bootstrap epoch.
 */
void expect_bootstrap_worker_ownership(const partitioned_runtime &runtime, uint64_t expected_epoch)
{
	const auto progress = read_transition_progress(runtime);
	ASSERT_NE(progress.execution_participant_count, 0u);
	for (uint32_t worker_index = 0; worker_index < progress.execution_participant_count; ++worker_index) {
		worker_epoch_ledger_snapshot observation{};
		bool exact_zero_observed = false;
		bool invalid_publication = false;
		const auto deadline = std::chrono::steady_clock::now() + TEST_LEDGER_OBSERVATION_TIMEOUT;
		do {
			const auto read = runtime.try_read_worker_epoch_ownership(worker_index, observation);
			invalid_publication = invalid_publication || (read != publication_read_result::AVAILABLE &&
								      read != publication_read_result::UNAVAILABLE);
			if (read == publication_read_result::AVAILABLE &&
			    observation.runtime_generation ==
				    kinetum::test::packet_runtime_fixture_detail::TEST_RUNTIME_GENERATION &&
			    observation.worker_index == worker_index && observation.active_epoch == expected_epoch &&
			    observation.source_epoch == expected_epoch && observation.active_unretired == 0u &&
			    observation.future_epoch == 0u && observation.future_unretired == 0u) {
				exact_zero_observed = true;
				break;
			}
			std::this_thread::yield();
		} while (std::chrono::steady_clock::now() < deadline);
		EXPECT_FALSE(invalid_publication) << "worker=" << worker_index;
		ASSERT_TRUE(exact_zero_observed)
			<< "worker=" << worker_index << " publication=" << observation.publication_generation
			<< " active=" << observation.active_epoch << " source=" << observation.source_epoch
			<< " active_unretired=" << observation.active_unretired
			<< " future=" << observation.future_epoch
			<< " future_unretired=" << observation.future_unretired;
		EXPECT_NE(observation.publication_generation, 0u);
		EXPECT_EQ(observation.runtime_generation,
			  kinetum::test::packet_runtime_fixture_detail::TEST_RUNTIME_GENERATION);
		EXPECT_EQ(observation.worker_index, worker_index);
		EXPECT_EQ(observation.active_epoch, expected_epoch);
		EXPECT_EQ(observation.source_epoch, expected_epoch);
		EXPECT_EQ(observation.active_unretired, 0u);
		EXPECT_EQ(observation.future_epoch, 0u);
		EXPECT_EQ(observation.future_unretired, 0u);
	}
	worker_epoch_ledger_snapshot out_of_range{};
	EXPECT_EQ(runtime.try_read_worker_epoch_ownership(progress.execution_participant_count, out_of_range),
		  publication_read_result::INVALID_IDENTITY);
}

/**
 * @brief Require one exact pre-Bootstrap coordinator publication.
 * @param runtime Constructed runtime whose coherent transition state is inspected.
 */
void expect_awaiting_bootstrap(const partitioned_runtime &runtime)
{
	const auto progress = read_transition_progress(runtime);
	EXPECT_EQ(progress.phase, epoch_transition_phase::AWAITING_BOOTSTRAP);
	EXPECT_EQ(progress.active_epoch, 0u);
	EXPECT_EQ(progress.target_epoch, 0u);
	EXPECT_EQ(progress.mutation_sequence, 0u);
	EXPECT_EQ(progress.allocated_epoch_high_watermark, 0u);
	EXPECT_EQ(progress.mutation_sequence_high_watermark, 0u);
	EXPECT_FALSE(progress.participants_frozen);
	EXPECT_NE(progress.execution_participant_count, 0u);
	EXPECT_EQ(progress.execution_participant_count, progress.quiescence_reader_count);
	EXPECT_EQ(progress.terminal_history_size, 0u);
	EXPECT_EQ(progress.last_terminal_outcome, epoch_transition_outcome::NONE);
}

/**
 * @brief Require one exact idle coordinator publication.
 *
 * @param runtime Complete runtime generation.
 * @param expected_epoch Exact globally active epoch.
 * @param expected_terminal_history_size Exact retained terminal population.
 * @param expected_last_terminal_outcome Exact latest terminal outcome.
 */
void expect_coordinator_idle(const partitioned_runtime &runtime, uint64_t expected_epoch,
			     uint32_t expected_terminal_history_size = 0u,
			     epoch_transition_outcome expected_last_terminal_outcome = epoch_transition_outcome::NONE)
{
	const auto progress = read_transition_progress(runtime);
	EXPECT_EQ(progress.phase, epoch_transition_phase::IDLE);
	EXPECT_EQ(progress.active_epoch, expected_epoch);
	EXPECT_EQ(progress.target_epoch, 0u);
	EXPECT_EQ(progress.mutation_sequence, 0u);
	EXPECT_EQ(progress.allocated_epoch_high_watermark, expected_epoch);
	EXPECT_EQ(progress.mutation_sequence_high_watermark, expected_epoch);
	EXPECT_FALSE(progress.participants_frozen);
	EXPECT_EQ(progress.terminal_history_size, expected_terminal_history_size);
	EXPECT_EQ(progress.last_terminal_outcome, expected_last_terminal_outcome);
}

/**
 * @brief Require the exact fixed-epoch CONTROL_READY publication.
 *
 * @param runtime Complete runtime generation.
 */
void expect_control_ready(const partitioned_runtime &runtime)
{
	const auto observed = read_status(runtime);
	EXPECT_EQ(observed.readiness, runtime_readiness::CONTROL_READY);
	EXPECT_NE(observed.publication_generation, 0u);
	EXPECT_EQ(observed.runtime_generation, kinetum::test::packet_runtime_fixture_detail::TEST_RUNTIME_GENERATION);
	EXPECT_EQ(observed.active_epoch, 0u);
	EXPECT_EQ(observed.minimum_retained_epoch, 0u);
	EXPECT_EQ(observed.last_activated_epoch, 0u);
	EXPECT_EQ(observed.active_workers, 0u);
	EXPECT_NE(observed.expected_workers, 0u);
}

/**
 * @brief Require one exact PACKET_READY publication.
 *
 * @param runtime Complete runtime generation.
 * @param expected_epoch Exact admitted bootstrap epoch.
 */
void expect_packet_ready(const partitioned_runtime &runtime, uint64_t expected_epoch)
{
	const auto observed = read_status(runtime);
	EXPECT_EQ(observed.readiness, runtime_readiness::PACKET_READY);
	EXPECT_EQ(observed.runtime_generation, kinetum::test::packet_runtime_fixture_detail::TEST_RUNTIME_GENERATION);
	EXPECT_EQ(observed.active_epoch, expected_epoch);
	EXPECT_EQ(observed.minimum_retained_epoch, expected_epoch);
	EXPECT_EQ(observed.last_activated_epoch, expected_epoch);
	EXPECT_NE(observed.expected_workers, 0u);
	EXPECT_EQ(observed.active_workers, observed.expected_workers);
}

/**
 * @brief Await one coherent internal telemetry sample through production surfaces.
 * @param runtime Exact packet-ready runtime and coordinator owner.
 * @param minimum_rx Minimum physical ingress records required.
 * @param minimum_tx Minimum provider-accepted TX records required.
 * @return First matching snapshot or a bounded unavailable status.
 */
common::status_or<runtime_telemetry_snapshot> await_packet_telemetry(partitioned_runtime &runtime, uint64_t minimum_rx,
								     uint64_t minimum_tx)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (std::chrono::steady_clock::now() < deadline) {
		const auto serviced = runtime.service_control_deadline();
		if (!serviced.is_ok()) {
			return serviced;
		}
		auto snapshot =
			runtime.collect_runtime_telemetry({.include_stage_stats = true, .include_stream_stats = true});
		if (snapshot.is_ok() && snapshot->engine.rx_packets >= minimum_rx &&
		    snapshot->engine.tx_packets >= minimum_tx) {
			return snapshot;
		}
		if (!snapshot.is_ok() && snapshot.error().code() != common::status_code::UNAVAILABLE) {
			return snapshot.error();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	return common::status::unavailable("packet telemetry did not reach its exact bounded sample");
}

/**
 * @brief Await one current exact module-health publication through the runtime source.
 * @param runtime Exact packet-ready runtime and coordinator owner.
 * @param module_id Exact expected module-image identity.
 * @param epoch Exact coherent runtime and signal epoch.
 * @return First snapshot carrying the current signal, or bounded unavailability.
 */
common::status_or<runtime_telemetry_snapshot> await_module_health(partitioned_runtime &runtime,
								  std::string_view module_id, uint64_t epoch)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
	while (std::chrono::steady_clock::now() < deadline) {
		const auto serviced = runtime.service_control_deadline();
		if (!serviced.is_ok()) {
			return serviced;
		}
		auto snapshot = runtime.collect_runtime_telemetry({
			.include_stage_stats = true,
			.include_module_health = true,
		});
		if (snapshot.is_ok()) {
			const auto found = std::find_if(snapshot->module_health.begin(), snapshot->module_health.end(),
							[&](const auto &row) {
								return row.module_id == module_id &&
								       row.callback_available && row.signal_available &&
								       row.observation_epoch == epoch &&
								       row.signal.epoch == epoch;
							});
			if (found != snapshot->module_health.end()) {
				return snapshot;
			}
		} else if (snapshot.error().code() != common::status_code::UNAVAILABLE) {
			return snapshot.error();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	return common::status::unavailable("module health did not reach its exact bounded sample");
}

/**
 * @brief Recompute the exact deterministic key after a scalar test mutation.
 *
 * @param request Mutable otherwise-canonical bootstrap request.
 */
void recompute_idempotency_key(kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &request)
{
	auto snapshot_hash_or =
		common::decode_sha256_digest_claim(request.snapshot().content_hash(), "ConfigSnapshot.content_hash");
	ASSERT_TRUE(snapshot_hash_or.is_ok()) << snapshot_hash_or.error().message();
	auto plan_hash_or = common::decode_sha256_digest_claim(request.plan_content_hash(), "plan_content_hash");
	ASSERT_TRUE(plan_hash_or.is_ok()) << plan_hash_or.error().message();
	auto key_or = common::derive_bootstrap_config_snapshot_idempotency_key(
		snapshot_hash_or.value(), plan_hash_or.value(), request.active_epoch(),
		request.allocated_epoch_high_watermark(), request.mutation_sequence_high_watermark());
	ASSERT_TRUE(key_or.is_ok()) << key_or.error().message();
	request.set_idempotency_key(std::move(key_or).value());
	ASSERT_TRUE(common::validate_bootstrap_config_snapshot_request(request).is_ok());
}

/**
 * @brief Construct explicit passive-module intent for rollback tests.
 * @return Passive-module intent carrying deliberately invalid policy bytes.
 */
kinetum::test::packet_runtime_test_module_intent invalid_module_intent()
{
	return {
		.module_id = "test_module",
		.canonical_path = std::filesystem::path(KINETUM_TEST_MODULE_PATH),
		.config_blob = R"({"drop":invalid})",
		.context_memory_capacity_bytes = TEST_MODULE_CONTEXT_CAPACITY_BYTES,
		.epoch_arena_capacity_bytes = TEST_MODULE_EPOCH_CAPACITY_BYTES,
	};
}

/**
 * @brief Construct explicit passive-module intent for packet-routing tests.
 * @param config_blob Exact policy bytes transferred into the intent.
 * @return Passive-module intent with fixed lifecycle resource authority.
 */
kinetum::test::packet_runtime_test_module_intent module_intent(std::string config_blob)
{
	return {
		.module_id = "test_module",
		.canonical_path = std::filesystem::path(KINETUM_TEST_MODULE_PATH),
		.config_blob = std::move(config_blob),
		.context_memory_capacity_bytes = TEST_MODULE_CONTEXT_CAPACITY_BYTES,
		.epoch_arena_capacity_bytes = TEST_MODULE_EPOCH_CAPACITY_BYTES,
	};
}

/**
 * @brief Construct exact synchronous active-module intent for scheduler integration.
 * @return Active-module intent with fixed trigger and resource authority.
 */
kinetum::test::packet_runtime_test_module_intent active_module_intent()
{
	return {
		.module_id = "kinetum.test_active",
		.canonical_path = std::filesystem::path(KINETUM_TEST_ACTIVE_MODULE_PATH),
		.config_blob = {},
		.context_memory_capacity_bytes = TEST_MODULE_CONTEXT_CAPACITY_BYTES,
		.epoch_arena_capacity_bytes = TEST_MODULE_EPOCH_CAPACITY_BYTES,
		.execution_mode = kinetum::axiom::v1::EXECUTION_MODE_ACTIVE,
		.trigger_mask = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP) |
				static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_TIMER),
		.retained_packet_capacity = 8u,
		.retained_byte_capacity = uint64_t{8} * 2048u,
		.timer_capacity = 8u,
		.control_mailbox_capacity = 0u,
		.control_message_capacity_bytes = 0u,
		.async_work_capacity = 0u,
		.async_cancel_grace_ms = 0u,
	};
}

/**
 * @brief Construct exact tracked-async active-module intent for runtime integration.
 * @return Tracked-async module intent with fixed trigger and resource authority.
 */
kinetum::test::packet_runtime_test_module_intent async_module_intent()
{
	return {
		.module_id = "kinetum.test_active_async",
		.canonical_path = std::filesystem::path(KINETUM_TEST_ACTIVE_ASYNC_MODULE_PATH),
		.config_blob = {},
		.context_memory_capacity_bytes = TEST_MODULE_CONTEXT_CAPACITY_BYTES,
		.epoch_arena_capacity_bytes = TEST_MODULE_EPOCH_CAPACITY_BYTES,
		.execution_mode = kinetum::axiom::v1::EXECUTION_MODE_ACTIVE,
		.trigger_mask = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP),
		.retained_packet_capacity = 4u,
		.retained_byte_capacity = uint64_t{4} * 2048u,
		.timer_capacity = 0u,
		.control_mailbox_capacity = 0u,
		.control_message_capacity_bytes = 0u,
		.async_work_capacity = 4u,
		.async_cancel_grace_ms = 1000u,
	};
}

/**
 * @brief Build one module-free fan-out and fan-in packet graph.
 * @return Unpinned pipeline graph exercising fan-out and reconvergence.
 */
kinetum::axiom::v1::Pipeline fanout_pipeline()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("packet_runtime_fanout");
	pipeline.set_allow_dag(true);

	auto *rx = pipeline.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->mutable_io()->set_interface("wan0");

	for (const char *stage_id : {"parse_a", "parse_b"}) {
		auto *parse = pipeline.add_stages();
		parse->set_stage_id(stage_id);
		parse->set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
		parse->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	}

	auto *tx = pipeline.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface("lan0");

	for (const char *parse_id : {"parse_a", "parse_b"}) {
		auto *fanout = pipeline.add_edges();
		fanout->set_from_stage_id("rx");
		fanout->set_to_stage_id(parse_id);
		fanout->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
		auto *fanin = pipeline.add_edges();
		fanin->set_from_stage_id(parse_id);
		fanin->set_to_stage_id("tx");
		fanin->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	}
	return pipeline;
}

/**
 * @brief Require both fan-out branches to forward an exact packet prefix and retire its credits.
 * @param owner Bootstrapped production fixture with two branches joining one TX stage.
 * @param epoch Exact active epoch expected after forwarding completes.
 */
void expect_fanout_forwarding(packet_runtime_test_owner &owner, uint64_t epoch)
{
	constexpr std::size_t INPUT_COUNT = 8u;
	const auto packet =
		build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10, {UINT8_C(0x5a)});
	for (std::size_t index = 0u; index < INPUT_COUNT; ++index) {
		const auto sent = owner.send_packet_to_rx(packet);
		ASSERT_TRUE(sent.is_ok()) << sent.message();
	}
	for (std::size_t index = 0u; index < INPUT_COUNT * 2u; ++index) {
		auto received = owner.receive_packet_from_tx(2048u, TEST_PACKET_TIMEOUT_MS);
		ASSERT_TRUE(received.is_ok()) << received.error().message();
		EXPECT_EQ(received.value(), packet);
	}
	const auto unexpected = owner.receive_packet_from_tx(2048u, TEST_NO_PACKET_TIMEOUT_MS);
	ASSERT_FALSE(unexpected.is_ok());
	EXPECT_EQ(unexpected.error().code(), status_code::UNAVAILABLE);
	expect_bootstrap_worker_ownership(owner.runtime(), epoch);
}

static_assert(!std::is_default_constructible_v<packet_runtime_generation_input>);
static_assert(!std::is_copy_constructible_v<packet_runtime_generation_input>);
static_assert(std::is_move_constructible_v<packet_runtime_generation_input>);
static_assert(!std::is_move_assignable_v<packet_runtime_generation_input>);
static_assert(!std::is_default_constructible_v<partitioned_runtime>);
static_assert(!std::is_copy_constructible_v<partitioned_runtime>);
static_assert(!std::is_move_constructible_v<partitioned_runtime>);

}  // namespace

/** @brief Pin one complete move-only factory input with no partial overload. */
TEST(packet_runtime_construction, complete_generation_input_is_the_only_factory_contract)
{
	using factory_type =
		common::status_or<std::unique_ptr<partitioned_runtime>> (*)(packet_runtime_generation_input);
	static_assert(std::is_same_v<decltype(&partitioned_runtime::create), factory_type>);
	SUCCEED();
}

/** @brief Prove a production-planned topology freezes every exact membership relation. */
TEST(packet_runtime_construction, production_planned_topology_freezes_exact_participant_membership)
{
	const kinetum::test::packet_runtime_fixture_detail::host_selection selection{
		.numa_node = 0,
		.cpu_cores = {0, 1, 2},
	};
	const auto pipeline = kinetum::test::packet_runtime_fixture_detail::make_pipeline(std::nullopt);
	auto compiled_or = kinetum::test::packet_runtime_fixture_detail::compile_runtime_fixture(
		pipeline, selection, uint16_t{41001}, uint16_t{41002}, 0u, 0u);
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	auto compiled = std::move(compiled_or).value();
	auto coordinator_or = epoch_transition_coordinator::create(compiled.topology);
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	auto coordinator = std::move(coordinator_or).value();
	const auto &participants = coordinator->participants();
	const auto &topology = compiled.topology;

	ASSERT_EQ(participants.execution_participant_count(), topology.transition_topology.workers.size());
	ASSERT_EQ(participants.quiescence_reader_count(), topology.transition_topology.workers.size());
	ASSERT_EQ(participants.quiescence_reader_indices().size(), topology.transition_topology.workers.size());
	EXPECT_TRUE(std::ranges::equal(participants.source_participant_indices(),
				       topology.transition_topology.source_worker_indices));
	EXPECT_TRUE(std::ranges::equal(participants.sink_participant_indices(),
				       topology.transition_topology.sink_worker_indices));
	for (std::size_t index = 0; index < topology.transition_topology.workers.size(); ++index) {
		const auto &worker = topology.transition_topology.workers[index];
		const auto *participant = participants.execution_participant(static_cast<uint32_t>(index));
		ASSERT_NE(participant, nullptr);
		EXPECT_EQ(participant->participant_index, index);
		EXPECT_EQ(participant->worker_index, worker.worker_index);
		EXPECT_EQ(participant->quiescence_reader_index, worker.worker_index);
		EXPECT_EQ(participants.quiescence_reader_indices()[index], worker.worker_index);
		EXPECT_EQ(participant->lane_index, worker.lane_index);
		EXPECT_EQ(participant->is_source, worker.is_source);
		EXPECT_EQ(participant->is_sink, worker.is_sink);
		EXPECT_TRUE(std::ranges::equal(participants.stage_indices(participant->participant_index),
					       worker.stage_instance_indices));
		EXPECT_TRUE(std::ranges::equal(participants.io_stream_indices(participant->participant_index),
					       worker.io_stream_indices));
		EXPECT_TRUE(std::ranges::equal(participants.inbound_boundary_indices(participant->participant_index),
					       worker.inbound_boundary_indices));
		EXPECT_TRUE(std::ranges::equal(participants.outbound_boundary_indices(participant->participant_index),
					       worker.outbound_boundary_indices));
	}
	ASSERT_EQ(participants.region_count(), topology.execution_regions.size());
	for (std::size_t index = 0; index < topology.execution_regions.size(); ++index) {
		EXPECT_TRUE(std::ranges::equal(participants.region_worker_indices(static_cast<uint32_t>(index)),
					       topology.execution_regions[index].worker_indices));
	}
}

/** @brief Prove production construction reaches one coherent control boundary. */
TEST_F(PacketRuntimeConstructionTest, construction_materializes_one_control_ready_generation)
{
	expect_control_ready(owner_->runtime());
	expect_awaiting_bootstrap(owner_->runtime());
	expect_worker_ownership_unpublished(owner_->runtime());
}

/** @brief Prove materialization cannot publish an active epoch or worker. */
TEST_F(PacketRuntimeConstructionTest, control_ready_keeps_packet_authority_inert)
{
	const auto observed = read_status(owner_->runtime());
	EXPECT_EQ(observed.active_epoch, 0u);
	EXPECT_EQ(observed.minimum_retained_epoch, 0u);
	EXPECT_EQ(observed.last_activated_epoch, 0u);
	EXPECT_EQ(observed.active_workers, 0u);
	EXPECT_GT(observed.expected_workers, observed.active_workers);
	expect_awaiting_bootstrap(owner_->runtime());
	expect_worker_ownership_unpublished(owner_->runtime());
}

/** @brief Prove owner-thread self-submission rejects before mailbox ownership. */
TEST_F(PacketRuntimeConstructionTest, coordinator_owner_cannot_submit_bootstrap_to_itself)
{
	const auto rejected = owner_->runtime().bootstrap(owner_->bootstrap_request());
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), status_code::FAILED_PRECONDITION);
	expect_awaiting_bootstrap(owner_->runtime());
}

/** @brief Prove shutdown closure resolves an accepted but unstarted wire command. */
TEST_F(PacketRuntimeConstructionTest, command_admission_close_completes_queued_bootstrap_unavailable)
{
	std::optional<common::status_or<fixed_epoch_bootstrap_result>> result;
	std::atomic<bool> completed{false};
	std::thread producer([&] {
		result.emplace(owner_->runtime().bootstrap(owner_->bootstrap_request()));
		completed.store(true, std::memory_order_release);
	});
	pollfd descriptor{
		.fd = owner_->runtime().command_notification_descriptor(),
		.events = POLLIN,
		.revents = 0,
	};
	int poll_result = 0;
	do {
		poll_result = ::poll(&descriptor, 1, 2000);
	} while (poll_result < 0 && errno == EINTR);
	if (poll_result <= 0 || (descriptor.revents & POLLIN) == 0) {
		owner_->runtime().close_command_admission();
		producer.join();
		FAIL() << "queued Bootstrap did not publish its command wake";
	}
	owner_->runtime().close_command_admission();
	producer.join();
	ASSERT_TRUE(completed.load(std::memory_order_acquire));
	ASSERT_TRUE(result.has_value());
	ASSERT_FALSE(result->is_ok());
	EXPECT_EQ(result->error().code(), status_code::UNAVAILABLE);
	expect_awaiting_bootstrap(owner_->runtime());
}

/** @brief Prove malformed bootstrap cannot bind retry identity or mutate status. */
TEST_F(PacketRuntimeConstructionTest, malformed_bootstrap_preserves_control_ready)
{
	auto malformed = owner_->bootstrap_request();
	malformed.clear_idempotency_key();
	const auto rejected = owner_->bootstrap(malformed);
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), status_code::DATA_LOSS);
	expect_control_ready(owner_->runtime());
	expect_awaiting_bootstrap(owner_->runtime());

	const auto accepted = owner_->bootstrap();
	ASSERT_TRUE(accepted.is_ok()) << accepted.error().message();
	expect_packet_ready(owner_->runtime(), owner_->bootstrap_request().active_epoch());
	expect_coordinator_idle(owner_->runtime(), owner_->bootstrap_request().active_epoch());
}

/** @brief Prove a valid foreign plan identity cannot activate this generation. */
TEST_F(PacketRuntimeConstructionTest, foreign_plan_identity_preserves_control_ready)
{
	auto foreign = owner_->bootstrap_request();
	foreign.set_plan_content_hash(std::string(common::SHA256_HEX_LENGTH, '0'));
	recompute_idempotency_key(foreign);

	const auto rejected = owner_->bootstrap(foreign);
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(rejected.error().message().find("plan identity"), std::string::npos);
	expect_control_ready(owner_->runtime());
	expect_awaiting_bootstrap(owner_->runtime());
}

/** @brief Prove exact bootstrap activates one complete fixed epoch. */
TEST_F(PacketRuntimeConstructionTest, exact_bootstrap_publishes_packet_ready)
{
	const auto result = owner_->bootstrap();
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	EXPECT_EQ(result->restored_epoch, owner_->bootstrap_request().active_epoch());
	EXPECT_EQ(result->allocated_epoch_high_watermark, owner_->bootstrap_request().allocated_epoch_high_watermark());
	EXPECT_EQ(result->mutation_sequence_high_watermark,
		  owner_->bootstrap_request().mutation_sequence_high_watermark());
	expect_packet_ready(owner_->runtime(), result->restored_epoch);
	expect_coordinator_idle(owner_->runtime(), result->restored_epoch);
	expect_bootstrap_worker_ownership(owner_->runtime(), result->restored_epoch);
}

/** @brief Prove the packet owner invokes health with its exact active module view. */
TEST(packet_runtime_construction, owner_worker_health_publishes_current_exact_view)
{
	auto owner_or = packet_runtime_test_owner::create(module_intent("{}"));
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());
	const uint64_t epoch = owner->bootstrap_request().active_epoch();
	auto telemetry_or = await_module_health(owner->runtime(), "test_module", epoch);
	ASSERT_TRUE(telemetry_or.is_ok()) << telemetry_or.error().message();
	const auto found = std::find_if(telemetry_or->module_health.begin(), telemetry_or->module_health.end(),
					[](const auto &row) { return row.module_id == "test_module"; });
	ASSERT_NE(found, telemetry_or->module_health.end());
	EXPECT_EQ(found->context_index, 0u);
	EXPECT_TRUE(found->callback_available);
	EXPECT_TRUE(found->signal_available);
	EXPECT_EQ(found->latest_fault_mask, 0u);
	EXPECT_EQ(found->signal.assessment.health_score, 100u);
	EXPECT_EQ(found->signal.assessment.flags, KINETUM_HEALTH_F_OK);
	EXPECT_STREQ(found->signal.assessment.reason, "ready");
	EXPECT_EQ(found->signal.epoch, epoch);
	EXPECT_GT(found->signal.timestamp_ns, 0u);
}

/** @brief Prove real RX, parse, and TX execute through pre-resolved kernel tables. */
TEST_F(PacketRuntimeConstructionTest, fixed_epoch_packet_path_preserves_exact_wire_bytes)
{
	const std::vector<uint8_t> packet =
		build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10,
				   {UINT8_C(0xde), UINT8_C(0xad), UINT8_C(0xbe), UINT8_C(0xef)});
	ASSERT_TRUE(owner_->bootstrap().is_ok());
	const auto send_status = owner_->send_packet_to_rx(packet);
	ASSERT_TRUE(send_status.is_ok()) << send_status.message();

	auto received_or = owner_->receive_packet_from_tx(2048u, TEST_PACKET_TIMEOUT_MS);
	ASSERT_TRUE(received_or.is_ok()) << received_or.error().message();
	EXPECT_EQ(received_or.value(), packet);
	auto telemetry_or = await_packet_telemetry(owner_->runtime(), 1u, 1u);
	ASSERT_TRUE(telemetry_or.is_ok()) << telemetry_or.error().message();
	EXPECT_EQ(telemetry_or->engine.rx_packets, 1u);
	EXPECT_EQ(telemetry_or->engine.tx_packets, 1u);
	EXPECT_EQ(telemetry_or->engine.dropped_packets, 0u);
	EXPECT_EQ(telemetry_or->engine.rx_bytes, packet.size());
	EXPECT_EQ(telemetry_or->engine.tx_bytes, packet.size());
	EXPECT_GT(telemetry_or->collection_monotonic_ns, 0u);
	EXPECT_EQ(telemetry_or->runtime_status.active_epoch, owner_->bootstrap_request().active_epoch());
	expect_bootstrap_worker_ownership(owner_->runtime(), owner_->bootstrap_request().active_epoch());
}

/** @brief Rejected-only RX work publishes a discard without transferring a record or epoch credit. */
TEST_F(PacketRuntimeConstructionTest, rejected_only_rx_preserves_admission_and_staging_ownership)
{
	ASSERT_TRUE(owner_->bootstrap().is_ok());
	const std::vector<uint8_t> oversized(test::packet_runtime_fixture_detail::MAX_UDP_DATAGRAM_BYTES, 0x5au);
	ASSERT_TRUE(owner_->send_packet_to_rx(oversized).is_ok());
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	bool observed_rejection = false;
	while (std::chrono::steady_clock::now() < deadline) {
		ASSERT_TRUE(owner_->runtime().service_control_deadline().is_ok());
		auto snapshot = owner_->runtime().collect_runtime_telemetry({.include_stream_stats = true});
		if (snapshot.is_ok()) {
			const auto rx =
				std::find_if(snapshot->streams.begin(), snapshot->streams.end(), [](const auto &row) {
					return row.direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX;
				});
			ASSERT_NE(rx, snapshot->streams.end());
			if (rx->rejected_packets == 1u) {
				EXPECT_EQ(rx->packets, 0u);
				EXPECT_EQ(rx->bytes, 0u);
				EXPECT_EQ(snapshot->engine.rx_packets, 0u);
				EXPECT_EQ(snapshot->engine.tx_packets, 0u);
				EXPECT_EQ(snapshot->engine.dropped_packets, 0u);
				observed_rejection = true;
				break;
			}
		} else {
			ASSERT_EQ(snapshot.error().code(), common::status_code::UNAVAILABLE)
				<< snapshot.error().message();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	ASSERT_TRUE(observed_rejection);
	expect_bootstrap_worker_ownership(owner_->runtime(), owner_->bootstrap_request().active_epoch());
	const auto packet = build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10, {0x5au});
	ASSERT_TRUE(owner_->send_packet_to_rx(packet).is_ok());
	auto received = owner_->receive_packet_from_tx(2048u, TEST_PACKET_TIMEOUT_MS);
	ASSERT_TRUE(received.is_ok()) << received.error().message();
	EXPECT_EQ(received.value(), packet);
	auto snapshot = await_packet_telemetry(owner_->runtime(), 1u, 1u);
	ASSERT_TRUE(snapshot.is_ok()) << snapshot.error().message();
	EXPECT_EQ(snapshot->engine.rx_packets, 1u);
	EXPECT_EQ(snapshot->engine.tx_packets, 1u);
	EXPECT_EQ(snapshot->engine.rx_bytes, packet.size());
	EXPECT_EQ(snapshot->engine.tx_bytes, packet.size());
}

/** @brief Prove real worker dispatch creates one independent record per fan-out edge. */
TEST(fanout_logic, runtime_dispatch_clones_payload_and_persistent_user_word)
{
	auto owner_or = packet_runtime_test_owner::create_with_pipeline(fanout_pipeline());
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());

	const std::vector<uint8_t> packet =
		build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10,
				   {UINT8_C(0xde), UINT8_C(0xad), UINT8_C(0xbe), UINT8_C(0xef)});
	ASSERT_TRUE(owner->send_packet_to_rx(packet).is_ok());
	for (std::size_t branch = 0; branch < 2u; ++branch) {
		auto received_or = owner->receive_packet_from_tx(2048u, TEST_PACKET_TIMEOUT_MS);
		ASSERT_TRUE(received_or.is_ok()) << "branch=" << branch << " error=" << received_or.error().message();
		EXPECT_EQ(received_or.value(), packet);
	}
	const auto unexpected = owner->receive_packet_from_tx(2048u, TEST_NO_PACKET_TIMEOUT_MS);
	ASSERT_FALSE(unexpected.is_ok());
	EXPECT_EQ(unexpected.error().code(), status_code::UNAVAILABLE);
	expect_bootstrap_worker_ownership(owner->runtime(), owner->bootstrap_request().active_epoch());
}

/** @brief Prove synchronous active ownership drains across two recurring public transitions. */
TEST(packet_runtime_construction, active_instance_scheduler_retains_emits_drains_and_reuses_exact_slots)
{
	auto owner_or = packet_runtime_test_owner::create(active_module_intent());
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());

	// The context-local test module emits one active origin on its first owner
	// turn. It must use the authored storage domain and common TX path.
	auto origin_or = owner->receive_packet_from_tx(64u, TEST_PACKET_TIMEOUT_MS);
	ASSERT_TRUE(origin_or.is_ok()) << origin_or.error().message();
	EXPECT_EQ(origin_or.value(), (std::vector<uint8_t>{UINT8_C(0x42)}));

	// The first ingested record is retained under one opaque context handle.
	const auto retained_packet =
		build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10, {UINT8_C(0x31)});
	ASSERT_TRUE(owner->send_packet_to_rx(retained_packet).is_ok());
	const auto premature = owner->receive_packet_from_tx(2048u, TEST_NO_PACKET_TIMEOUT_MS);
	ASSERT_FALSE(premature.is_ok());
	EXPECT_EQ(premature.error().code(), status_code::UNAVAILABLE);

	dataplane_control_service service(owner->runtime());
	for (uint64_t target_epoch = 2u; target_epoch <= 3u; ++target_epoch) {
		kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
		prepare.mutable_snapshot()->CopyFrom(owner->bootstrap_request().snapshot());
		prepare.mutable_snapshot()->set_snapshot_id("active-instance-e2e-" + std::to_string(target_epoch));
		prepare.mutable_snapshot()->set_revision(static_cast<int64_t>(target_epoch));
		prepare.mutable_snapshot()->set_created_unix_ms(static_cast<int64_t>(target_epoch));
		prepare.mutable_snapshot()->clear_content_hash();
		prepare.set_target_epoch(target_epoch);
		prepare.set_mutation_sequence(target_epoch);
		prepare.set_idempotency_key("active-instance-e2e-key-" + std::to_string(target_epoch));
		kinetum::dataplane::v1::PrepareConfigSnapshotResponse prepared;
		grpc::ServerContext prepare_context;
		const auto prepare_transport = owner->run_control_producer(
			[&]() { return service.PrepareConfigSnapshot(&prepare_context, &prepare, &prepared); });
		ASSERT_TRUE(prepare_transport.ok());
		ASSERT_EQ(prepared.status().code(), static_cast<int32_t>(status_code::OK));
		ASSERT_EQ(prepared.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_PREPARED);

		kinetum::dataplane::v1::ActivateConfigSnapshotRequest activate;
		activate.set_epoch(target_epoch);
		activate.set_validation_hash(prepared.validation_hash());
		activate.set_idempotency_key(prepare.idempotency_key());
		activate.set_mutation_sequence(target_epoch);
		kinetum::dataplane::v1::ActivateConfigSnapshotResponse activated;
		grpc::ServerContext activate_context;
		const auto activate_transport = owner->run_control_producer(
			[&]() { return service.ActivateConfigSnapshot(&activate_context, &activate, &activated); });
		ASSERT_TRUE(activate_transport.ok());
		ASSERT_EQ(activated.status().code(), static_cast<int32_t>(status_code::OK));
		EXPECT_EQ(activated.completed_epoch(), target_epoch);
		EXPECT_EQ(activated.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
		expect_coordinator_idle(owner->runtime(), target_epoch, static_cast<uint32_t>(target_epoch - 1u),
					epoch_transition_outcome::COMPLETE);
	}
}

/** @brief Prove tracked foreign completion and recirculation use the common runtime packet path. */
TEST(packet_runtime_construction, tracked_async_completion_recirculates_same_instance_without_credit_duplication)
{
	auto owner_or = packet_runtime_test_owner::create(async_module_intent());
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());

	const auto packet =
		build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10, {UINT8_C(0x7a)});
	ASSERT_TRUE(owner->send_packet_to_rx(packet).is_ok());
	auto received_or = owner->receive_packet_from_tx(2048u, TEST_PACKET_TIMEOUT_MS);
	ASSERT_TRUE(received_or.is_ok()) << received_or.error().message();
	EXPECT_EQ(received_or.value(), packet);
	const auto duplicate = owner->receive_packet_from_tx(2048u, TEST_NO_PACKET_TIMEOUT_MS);
	ASSERT_FALSE(duplicate.is_ok());
	EXPECT_EQ(duplicate.error().code(), status_code::UNAVAILABLE);
	expect_bootstrap_worker_ownership(owner->runtime(), owner->bootstrap_request().active_epoch());
}

/** @brief Prove an unset module egress consumes the exact stage-bound TX owner. */
TEST(tx_no_fallback, stage_bound_owner_local_lookup_for_unset)
{
	auto owner_or = packet_runtime_test_owner::create(module_intent("{}"));
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());

	const std::vector<uint8_t> packet =
		build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10, {UINT8_C(0x11)});
	ASSERT_TRUE(owner->send_packet_to_rx(packet).is_ok());
	auto received_or = owner->receive_packet_from_tx(2048u, TEST_PACKET_TIMEOUT_MS);
	ASSERT_TRUE(received_or.is_ok()) << received_or.error().message();
	EXPECT_EQ(received_or.value(), packet);
}

/** @brief Prove an unknown explicit logical egress drops without stage-bound fallback. */
TEST(tx_no_fallback, unknown_egress_drops)
{
	auto owner_or = packet_runtime_test_owner::create(module_intent(R"({"rewrite_metadata":true})"));
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());

	const auto packet =
		build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10, {UINT8_C(0x22)});
	ASSERT_TRUE(owner->send_packet_to_rx(packet).is_ok());
	const auto received = owner->receive_packet_from_tx(2048u, TEST_NO_PACKET_TIMEOUT_MS);
	ASSERT_FALSE(received.is_ok());
	EXPECT_EQ(received.error().code(), status_code::UNAVAILABLE);
	auto telemetry_or = await_packet_telemetry(owner->runtime(), 1u, 0u);
	ASSERT_TRUE(telemetry_or.is_ok()) << telemetry_or.error().message();
	EXPECT_EQ(telemetry_or->engine.rx_packets, 1u);
	EXPECT_EQ(telemetry_or->engine.tx_packets, 0u);
	EXPECT_EQ(telemetry_or->engine.dropped_packets, 1u);
	uint64_t stage_drops = 0u;
	for (const auto &stage : telemetry_or->stages) {
		stage_drops += stage.dropped_packets;
	}
	EXPECT_EQ(stage_drops, 1u);
	expect_bootstrap_worker_ownership(owner->runtime(), owner->bootstrap_request().active_epoch());
}

/** @brief Known alternate TX rejects an incompatible origin; mixed admission preserves both original owners. */
TEST(tx_no_fallback, explicit_egress_obeys_storage_admission_and_bound_edge_conversion)
{
	for (const bool admit_original : {false, true}) {
		SCOPED_TRACE(admit_original);
		auto pipeline = kinetum::test::packet_runtime_fixture_detail::make_pipeline("test_module");
		pipeline.set_allow_dag(true);
		auto *alternate = pipeline.add_stages();
		alternate->set_stage_id("tx_alternate");
		alternate->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
		alternate->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		alternate->mutable_io()->set_interface("lan1");
		auto *edge = pipeline.add_edges();
		edge->set_from_stage_id("module");
		edge->set_to_stage_id("tx_alternate");
		edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
		auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
		const auto original = bindings.packet_storage_domains(0);
		auto *destination = bindings.add_packet_storage_domains();
		destination->CopyFrom(original);
		destination->set_storage_domain_id("storage_host_1");
		for (auto &stream : *bindings.mutable_io_stream_bindings()) {
			if (stream.logical_name() == "lan1") {
				auto *accepted = stream.mutable_queues(0)->mutable_tx_storage();
				accepted->clear_storage_domain_ids();
				if (admit_original) {
					accepted->add_storage_domain_ids("storage_host_0");
				}
				accepted->add_storage_domain_ids("storage_host_1");
			}
		}
		auto *copy = bindings.add_storage_transition_bindings();
		copy->set_transition_id("alternate_egress_copy");
		copy->mutable_from_endpoint()->mutable_stage()->set_logical_stage_id("tx_alternate");
		copy->mutable_from_endpoint()->mutable_stage()->set_lane_id("lane_0");
		auto *to = copy->mutable_to_endpoint()->mutable_io();
		to->set_logical_name("lan1");
		to->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
		to->set_driver_queue_id(0);
		copy->set_from_storage_domain_id("storage_host_0");
		copy->set_to_storage_domain_id("storage_host_1");
		copy->set_staging_capacity(64);
		copy->set_staging_numa_node(0);
		copy->mutable_configuration()->PackFrom(kinetum::transition::cpu::v1::BoundedCopyConfig{});

		// Logical ports are assigned in canonical name order: lan0, lan1, wan0.
		auto owner_or = packet_runtime_test_owner::create(module_intent(R"({"output_port":1})"),
								  std::move(pipeline), bindings);
		ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
		auto owner = std::move(owner_or).value();
		ASSERT_TRUE(owner->bootstrap().is_ok());
		const auto packet =
			build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10, {UINT8_C(0x42)});
		ASSERT_TRUE(owner->send_packet_to_rx(packet).is_ok());
		const uint64_t expected_tx = admit_original ? 2u : 1u;
		for (uint64_t index = 0; index < expected_tx; ++index) {
			auto received = owner->receive_packet_from_tx(2048u, TEST_PACKET_TIMEOUT_MS);
			ASSERT_TRUE(received.is_ok()) << received.error().message();
			EXPECT_EQ(received.value(), packet);
		}
		const auto extra = owner->receive_packet_from_tx(2048u, TEST_NO_PACKET_TIMEOUT_MS);
		ASSERT_FALSE(extra.is_ok());
		EXPECT_EQ(extra.error().code(), status_code::UNAVAILABLE);
		auto stats = await_packet_telemetry(owner->runtime(), 1u, expected_tx);
		ASSERT_TRUE(stats.is_ok()) << stats.error().message();
		EXPECT_EQ(stats->engine.rx_packets, 1u);
		EXPECT_EQ(stats->engine.tx_packets, expected_tx);
		EXPECT_EQ(stats->engine.dropped_packets, admit_original ? 0u : 1u);
		ASSERT_EQ(stats->streams.size(), 3u);
		for (const auto &stream : stats->streams) {
			EXPECT_EQ(stream.rejected_packets, 0u);
			EXPECT_EQ(stream.bytes, stream.packets * packet.size());
			if (stream.direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_TX) {
				EXPECT_LE(stream.logical_port_id, 1u);
				EXPECT_EQ(stream.packets, stream.logical_port_id == 1u ? expected_tx : 0u);
			} else {
				EXPECT_EQ(stream.direction, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
				EXPECT_EQ(stream.logical_port_id, 2u);
				EXPECT_EQ(stream.packets, 1u);
			}
		}
		uint32_t observed_tx_stages = 0;
		for (const auto &stage : stats->stages) {
			if (stage.stage_id == "tx") {
				++observed_tx_stages;
				EXPECT_EQ(stage.out_packets, admit_original ? 1u : 0u);
				EXPECT_EQ(stage.dropped_packets, admit_original ? 0u : 1u);
			} else if (stage.stage_id == "tx_alternate") {
				++observed_tx_stages;
				EXPECT_EQ(stage.out_packets, 1u);
				EXPECT_EQ(stage.dropped_packets, 0u);
			}
		}
		EXPECT_EQ(observed_tx_stages, 2u);
		expect_bootstrap_worker_ownership(owner->runtime(), owner->bootstrap_request().active_epoch());
	}
}

/** @brief Prove an explicit module drop never falls through to stage-bound TX. */
TEST(tx_no_fallback, explicit_drop)
{
	auto owner_or = packet_runtime_test_owner::create(module_intent(R"({"drop":true})"));
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());

	const auto packet =
		build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234, 53, 10, {UINT8_C(0x33)});
	ASSERT_TRUE(owner->send_packet_to_rx(packet).is_ok());
	const auto received = owner->receive_packet_from_tx(2048u, TEST_NO_PACKET_TIMEOUT_MS);
	ASSERT_FALSE(received.is_ok());
	EXPECT_EQ(received.error().code(), status_code::UNAVAILABLE);
	expect_bootstrap_worker_ownership(owner->runtime(), owner->bootstrap_request().active_epoch());
}

/** @brief Prove Bootstrap is permanently unavailable after packet readiness. */
TEST_F(PacketRuntimeConstructionTest, bootstrap_is_unavailable_after_packet_ready)
{
	ASSERT_TRUE(owner_->bootstrap().is_ok());
	const auto retry = owner_->bootstrap();
	ASSERT_FALSE(retry.is_ok());
	EXPECT_EQ(retry.error().code(), status_code::UNAVAILABLE);
	EXPECT_NE(retry.error().message().find("PACKET_READY"), std::string::npos);
}

/** @brief Prove concurrent exact requests have one activation authority. */
TEST_F(PacketRuntimeConstructionTest, concurrent_bootstrap_serializes_one_activation)
{
	std::array<status_code, 2> codes{status_code::UNKNOWN, status_code::UNKNOWN};
	std::array<uint64_t, 2> epochs{};
	std::atomic<uint32_t> completed{0u};
	std::array<std::thread, 2> callers{
		std::thread([&] {
			auto result = owner_->runtime().bootstrap(owner_->bootstrap_request());
			codes[0] = result.is_ok() ? status_code::OK : result.error().code();
			epochs[0] = result.is_ok() ? result->restored_epoch : 0u;
			completed.fetch_add(1u, std::memory_order_release);
		}),
		std::thread([&] {
			auto result = owner_->runtime().bootstrap(owner_->bootstrap_request());
			codes[1] = result.is_ok() ? status_code::OK : result.error().code();
			epochs[1] = result.is_ok() ? result->restored_epoch : 0u;
			completed.fetch_add(1u, std::memory_order_release);
		}),
	};
	bool command_service_ok = true;
	while (completed.load(std::memory_order_acquire) != callers.size() && command_service_ok) {
		pollfd descriptor{
			.fd = owner_->runtime().command_notification_descriptor(),
			.events = POLLIN,
			.revents = 0,
		};
		const int poll_result = ::poll(&descriptor, 1, 10);
		if (poll_result < 0 && errno == EINTR) {
			continue;
		}
		if (poll_result < 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			command_service_ok = false;
			break;
		}
		if ((descriptor.revents & POLLIN) != 0) {
			command_service_ok = owner_->runtime().service_command_notifications().is_ok();
		}
	}
	if (!command_service_ok) {
		owner_->runtime().close_command_admission();
	}
	for (auto &caller : callers) {
		caller.join();
	}
	ASSERT_TRUE(command_service_ok);
	EXPECT_EQ(static_cast<int>(codes[0] == status_code::OK) + static_cast<int>(codes[1] == status_code::OK), 1);
	EXPECT_EQ(static_cast<int>(codes[0] == status_code::UNAVAILABLE) +
			  static_cast<int>(codes[1] == status_code::UNAVAILABLE),
		  1);
	EXPECT_EQ(epochs[0] + epochs[1], owner_->bootstrap_request().active_epoch());
	expect_packet_ready(owner_->runtime(), owner_->bootstrap_request().active_epoch());
	expect_coordinator_idle(owner_->runtime(), owner_->bootstrap_request().active_epoch());
}

/** @brief Prove Prepare, Status, and Abort share one mailbox and watermark owner. */
TEST_F(PacketRuntimeConstructionTest, internal_transaction_admission_is_exact_and_publication_coherent)
{
	ASSERT_TRUE(owner_->bootstrap().is_ok());
	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
	prepare.mutable_snapshot()->CopyFrom(owner_->bootstrap_request().snapshot());
	prepare.set_target_epoch(2u);
	prepare.set_mutation_sequence(2u);
	prepare.set_idempotency_key("packet-runtime-prepare-2");
	auto unknown_prepare = prepare;
	inject_unknown_field(&unknown_prepare);
	const auto malformed_prepare = owner_->run_control_producer(
		[&]() { return owner_->runtime().prepare_epoch_transition(unknown_prepare); });
	EXPECT_EQ(malformed_prepare.code, status_code::INVALID_ARGUMENT);
	EXPECT_EQ(malformed_prepare.observation.resolution, common::transition_identity_resolution::INVALID);
	expect_coordinator_idle(owner_->runtime(), owner_->bootstrap_request().active_epoch());
	const auto admitted =
		owner_->run_control_producer([&]() { return owner_->runtime().prepare_epoch_transition(prepare); });
	ASSERT_TRUE(admitted.is_ok());
	EXPECT_EQ(admitted.observation.resolution, common::transition_identity_resolution::ACTIVE_EXACT);
	EXPECT_EQ(admitted.observation.phase, epoch_transition_phase::PREPARED);
	EXPECT_EQ(admitted.observation.watermarks.allocated_epoch, 2u);
	EXPECT_EQ(admitted.observation.watermarks.mutation_sequence, 2u);
	EXPECT_EQ(admitted.observation.lease_state, epoch_transition_prepared_lease_state::ARMED);
	EXPECT_NE(admitted.observation.prepared_lease_deadline_monotonic_ns, 0u);
	EXPECT_NE(admitted.observation.prepared_lease_deadline_unix_ms, 0u);

	kinetum::dataplane::v1::GetEpochTransitionStatusRequest query;
	query.set_epoch(2u);
	query.set_mutation_sequence(2u);
	query.set_idempotency_key(prepare.idempotency_key());
	query.set_validation_hash(reinterpret_cast<const char *>(admitted.observation.identity.validation_hash.data()),
				  admitted.observation.identity.validation_hash.size());
	auto unknown_query = query;
	inject_unknown_field(&unknown_query);
	const auto malformed_query =
		owner_->run_control_producer([&]() { return owner_->runtime().query_epoch_transition(unknown_query); });
	EXPECT_EQ(malformed_query.code, status_code::INVALID_ARGUMENT);
	EXPECT_EQ(malformed_query.observation.resolution, common::transition_identity_resolution::INVALID);
	const auto active =
		owner_->run_control_producer([&]() { return owner_->runtime().query_epoch_transition(query); });
	ASSERT_TRUE(active.is_ok());
	EXPECT_EQ(active.observation.resolution, common::transition_identity_resolution::ACTIVE_EXACT);
	EXPECT_EQ(active.observation.phase, epoch_transition_phase::PREPARED);
	EXPECT_EQ(active.observation.lease_state, epoch_transition_prepared_lease_state::ARMED);
	EXPECT_EQ(active.observation.prepare_duration_ns, admitted.observation.prepare_duration_ns);

	kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest abort;
	abort.set_epoch(query.epoch());
	abort.set_mutation_sequence(query.mutation_sequence());
	abort.set_idempotency_key(query.idempotency_key());
	abort.set_validation_hash(query.validation_hash());
	auto unknown_abort = abort;
	inject_unknown_field(&unknown_abort);
	const auto malformed_abort =
		owner_->run_control_producer([&]() { return owner_->runtime().abort_epoch_transition(unknown_abort); });
	EXPECT_EQ(malformed_abort.code, status_code::INVALID_ARGUMENT);
	EXPECT_EQ(malformed_abort.observation.resolution, common::transition_identity_resolution::INVALID);
	const auto aborted =
		owner_->run_control_producer([&]() { return owner_->runtime().abort_epoch_transition(abort); });
	ASSERT_TRUE(aborted.is_ok());
	EXPECT_EQ(aborted.observation.outcome, epoch_transition_outcome::ABORTED);
	EXPECT_EQ(aborted.observation.failure_code, epoch_transition_failure_code::EXPLICIT_ABORT);
	EXPECT_EQ(aborted.observation.duration_presence, TRANSITION_PREPARE_DURATION_PRESENT);

	const auto terminal =
		owner_->run_control_producer([&]() { return owner_->runtime().query_epoch_transition(query); });
	ASSERT_TRUE(terminal.is_ok());
	EXPECT_EQ(terminal.observation.resolution, common::transition_identity_resolution::TERMINAL_EXACT);
	const auto repeated =
		owner_->run_control_producer([&]() { return owner_->runtime().prepare_epoch_transition(prepare); });
	ASSERT_TRUE(repeated.is_ok());
	EXPECT_EQ(repeated.observation.resolution, common::transition_identity_resolution::TERMINAL_EXACT);
	auto rebound = prepare;
	rebound.set_target_epoch(3u);
	rebound.set_mutation_sequence(3u);
	const auto key_conflict =
		owner_->run_control_producer([&]() { return owner_->runtime().prepare_epoch_transition(rebound); });
	EXPECT_EQ(key_conflict.code, status_code::FAILED_PRECONDITION);
	EXPECT_EQ(key_conflict.observation.resolution, common::transition_identity_resolution::IDENTITY_CONFLICT);
	expect_packet_ready(owner_->runtime(), owner_->bootstrap_request().active_epoch());
}

/** @brief Prove two inbound DATA inputs forward and drain across recurring public transitions. */
TEST(packet_runtime_construction, multi_region_e2e_epoch_transition)
{
	auto pipeline = fanout_pipeline();
	ASSERT_EQ(pipeline.stages_size(), 4);
	pipeline.mutable_stages(0)->set_preferred_region(0);
	pipeline.mutable_stages(1)->set_preferred_region(0);
	pipeline.mutable_stages(2)->set_preferred_region(0);
	pipeline.mutable_stages(3)->set_preferred_region(1);
	constexpr std::array<kinetum::test::packet_runtime_test_zero_copy_transition, 2> ZERO_COPY_TRANSITIONS{
		kinetum::test::packet_runtime_test_zero_copy_transition{
			.transition_id = "parse_a_to_tx_owner_handoff",
			.from_stage_id = "parse_a",
			.from_lane_id = "lane_0",
			.to_stage_id = "tx",
			.to_lane_id = "lane_0",
			.storage_domain_id = "storage_host_0",
		},
		kinetum::test::packet_runtime_test_zero_copy_transition{
			.transition_id = "parse_b_to_tx_owner_handoff",
			.from_stage_id = "parse_b",
			.from_lane_id = "lane_0",
			.to_stage_id = "tx",
			.to_lane_id = "lane_0",
			.storage_domain_id = "storage_host_0",
		},
	};
	static_assert(ZERO_COPY_TRANSITIONS.front().valid());
	static_assert(ZERO_COPY_TRANSITIONS.back().valid());
	auto owner_or = packet_runtime_test_owner::create_with_pipeline(std::move(pipeline), 2u, ZERO_COPY_TRANSITIONS);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());
	const auto initial_progress = read_transition_progress(owner->runtime());
	ASSERT_EQ(initial_progress.execution_participant_count, 2u);
	ASSERT_EQ(initial_progress.boundary_count, 2u);
	ASSERT_NO_FATAL_FAILURE(expect_fanout_forwarding(*owner, owner->bootstrap_request().active_epoch()));
	dataplane_control_service service(owner->runtime());

	for (uint64_t target_epoch = 2u; target_epoch <= 3u; ++target_epoch) {
		kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
		prepare.mutable_snapshot()->CopyFrom(owner->bootstrap_request().snapshot());
		prepare.mutable_snapshot()->set_snapshot_id("multi-region-e2e-" + std::to_string(target_epoch));
		prepare.mutable_snapshot()->set_revision(static_cast<int64_t>(target_epoch));
		prepare.mutable_snapshot()->set_created_unix_ms(static_cast<int64_t>(target_epoch));
		prepare.mutable_snapshot()->clear_content_hash();
		prepare.set_target_epoch(target_epoch);
		prepare.set_mutation_sequence(target_epoch);
		prepare.set_idempotency_key("multi-region-e2e-key-" + std::to_string(target_epoch));
		kinetum::dataplane::v1::PrepareConfigSnapshotResponse prepared;
		grpc::ServerContext prepare_context;
		const auto prepare_transport = owner->run_control_producer(
			[&]() { return service.PrepareConfigSnapshot(&prepare_context, &prepare, &prepared); });
		ASSERT_TRUE(prepare_transport.ok());
		ASSERT_EQ(prepared.status().code(), static_cast<int32_t>(status_code::OK));
		ASSERT_EQ(prepared.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_PREPARED);
		ASSERT_EQ(prepared.identity_resolution(),
			  kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_ACTIVE_EXACT);

		kinetum::dataplane::v1::ActivateConfigSnapshotRequest activate;
		activate.set_epoch(target_epoch);
		activate.set_validation_hash(prepared.validation_hash());
		activate.set_idempotency_key(prepare.idempotency_key());
		activate.set_mutation_sequence(target_epoch);
		kinetum::dataplane::v1::ActivateConfigSnapshotResponse activated;
		grpc::ServerContext activate_context;
		const auto activate_transport = owner->run_control_producer(
			[&]() { return service.ActivateConfigSnapshot(&activate_context, &activate, &activated); });
		ASSERT_TRUE(activate_transport.ok());
		ASSERT_EQ(activated.status().code(), static_cast<int32_t>(status_code::OK));
		EXPECT_EQ(activated.completed_epoch(), target_epoch);
		EXPECT_EQ(activated.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
		EXPECT_EQ(activated.identity_resolution(),
			  kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT);
		EXPECT_EQ(activated.failure_code(), kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);

		kinetum::dataplane::v1::GetEpochTransitionStatusRequest query;
		query.set_epoch(target_epoch);
		query.set_validation_hash(prepared.validation_hash());
		query.set_idempotency_key(prepare.idempotency_key());
		query.set_mutation_sequence(target_epoch);
		kinetum::dataplane::v1::GetEpochTransitionStatusResponse terminal;
		grpc::ServerContext query_context;
		const auto query_transport = owner->run_control_producer(
			[&]() { return service.GetEpochTransitionStatus(&query_context, &query, &terminal); });
		ASSERT_TRUE(query_transport.ok());
		ASSERT_EQ(terminal.status().code(), static_cast<int32_t>(status_code::OK));
		EXPECT_EQ(terminal.from_epoch(), target_epoch - 1u);
		EXPECT_EQ(terminal.to_epoch(), target_epoch);
		EXPECT_EQ(terminal.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
		expect_coordinator_idle(owner->runtime(), target_epoch, static_cast<uint32_t>(target_epoch - 1u),
					epoch_transition_outcome::COMPLETE);
		ASSERT_NO_FATAL_FAILURE(expect_fanout_forwarding(*owner, target_epoch));
	}
}

/** @brief Prove live PREPARE failure retires every partial artifact before ABORTED. */
TEST(packet_runtime_construction, live_module_prepare_failure_is_terminal_only_after_exact_cleanup)
{
	auto owner_or = packet_runtime_test_owner::create(module_intent("{}"));
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_TRUE(owner->bootstrap().is_ok());

	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
	prepare.mutable_snapshot()->CopyFrom(owner->bootstrap_request().snapshot());
	ASSERT_EQ(prepare.mutable_snapshot()->modules_size(), 1);
	prepare.mutable_snapshot()->mutable_modules(0)->set_config_blob(R"({"drop":invalid})");
	prepare.mutable_snapshot()->mutable_modules(0)->clear_content_hash();
	prepare.mutable_snapshot()->clear_content_hash();
	prepare.set_target_epoch(2u);
	prepare.set_mutation_sequence(2u);
	prepare.set_idempotency_key("live-prepare-failure");

	const auto failed =
		owner->run_control_producer([&]() { return owner->runtime().prepare_epoch_transition(prepare); });
	ASSERT_TRUE(failed.is_ok());
	EXPECT_EQ(failed.observation.resolution, common::transition_identity_resolution::TERMINAL_EXACT);
	EXPECT_EQ(failed.observation.outcome, epoch_transition_outcome::ABORTED);
	EXPECT_EQ(failed.observation.failure_code, epoch_transition_failure_code::PREPARE_FAILURE);
	EXPECT_EQ(failed.observation.duration_presence, TRANSITION_PREPARE_DURATION_PRESENT);

	const auto progress = read_transition_progress(owner->runtime());
	EXPECT_EQ(progress.phase, epoch_transition_phase::IDLE);
	EXPECT_EQ(progress.active_epoch, owner->bootstrap_request().active_epoch());
	EXPECT_EQ(progress.target_epoch, 0u);
	EXPECT_FALSE(progress.participants_frozen);
	EXPECT_EQ(progress.last_terminal_outcome, epoch_transition_outcome::ABORTED);
}

/** @brief Prove DP Prepare preserves canonical RESOURCE_EXHAUSTED size semantics. */
TEST_F(PacketRuntimeConstructionTest, oversized_internal_prepare_uses_canonical_resource_exhausted)
{
	ASSERT_TRUE(owner_->bootstrap().is_ok());
	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
	prepare.mutable_snapshot()->CopyFrom(owner_->bootstrap_request().snapshot());
	prepare.mutable_snapshot()->set_description(std::string(common::MAX_CONFIG_SNAPSHOT_BYTES + 1u, 'x'));
	prepare.set_target_epoch(2u);
	prepare.set_mutation_sequence(2u);
	prepare.set_idempotency_key("oversized-prepare");
	const auto rejected =
		owner_->run_control_producer([&]() { return owner_->runtime().prepare_epoch_transition(prepare); });
	EXPECT_EQ(rejected.code, status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(rejected.observation.resolution, common::transition_identity_resolution::INVALID);
	expect_coordinator_idle(owner_->runtime(), owner_->bootstrap_request().active_epoch());
}

/** @brief Prove owner shutdown retires one PREPARED candidate exactly. */
TEST_F(PacketRuntimeConstructionTest, shutdown_aborts_prepared_candidate_before_runtime_retirement)
{
	ASSERT_TRUE(owner_->bootstrap().is_ok());
	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare;
	prepare.mutable_snapshot()->CopyFrom(owner_->bootstrap_request().snapshot());
	prepare.set_target_epoch(2u);
	prepare.set_mutation_sequence(2u);
	prepare.set_idempotency_key("shutdown-prepared");
	const auto admitted =
		owner_->run_control_producer([&]() { return owner_->runtime().prepare_epoch_transition(prepare); });
	ASSERT_TRUE(admitted.is_ok());
	owner_->runtime().shutdown();
	const auto progress = read_transition_progress(owner_->runtime());
	EXPECT_EQ(progress.phase, epoch_transition_phase::IDLE);
	EXPECT_EQ(progress.allocated_epoch_high_watermark, 2u);
	EXPECT_EQ(progress.mutation_sequence_high_watermark, 2u);
	EXPECT_EQ(progress.terminal_history_size, 1u);
	EXPECT_EQ(progress.last_terminal_outcome, epoch_transition_outcome::ABORTED);
}

/** @brief Prove PREPARE failure rolls back enough for an identical retry. */
TEST(packet_runtime_construction, module_prepare_failure_allows_byte_identical_retry)
{
	auto owner_or = packet_runtime_test_owner::create(invalid_module_intent());
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();

	const auto first = owner->bootstrap();
	ASSERT_FALSE(first.is_ok());
	EXPECT_EQ(first.error().code(), status_code::MODULE_ERROR);
	expect_control_ready(owner->runtime());
	expect_awaiting_bootstrap(owner->runtime());

	const auto second = owner->bootstrap();
	ASSERT_FALSE(second.is_ok());
	EXPECT_EQ(second.error().code(), first.error().code());
	EXPECT_EQ(second.error().message(), first.error().message());
	expect_control_ready(owner->runtime());
	expect_awaiting_bootstrap(owner->runtime());
}

/** @brief Prove a failed PREPARE binds one exact retry identity. */
TEST(packet_runtime_construction, module_prepare_failure_rejects_a_different_retry)
{
	auto owner_or = packet_runtime_test_owner::create(invalid_module_intent());
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_FALSE(owner->bootstrap().is_ok());

	auto different = owner->bootstrap_request();
	different.set_allocated_epoch_high_watermark(different.allocated_epoch_high_watermark() + 1u);
	recompute_idempotency_key(different);
	const auto rejected = owner->bootstrap(different);
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(rejected.error().message().find("exact first admitted request"), std::string::npos);
	expect_control_ready(owner->runtime());
}

/** @brief Prove repeated owner-thread pre-bootstrap shutdown is idempotent. */
TEST_F(PacketRuntimeConstructionTest, shutdown_before_bootstrap_is_idempotent)
{
	owner_->runtime().shutdown();
	EXPECT_FALSE(owner_->runtime().lifecycle_notification_descriptor().has_value());
	EXPECT_EQ(owner_->runtime().service_lifecycle_notifications().code(), status_code::UNAVAILABLE);
	owner_->runtime().shutdown();
	const auto rejected = owner_->bootstrap();
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), status_code::UNAVAILABLE);
}

/** @brief Prove foreign-thread runtime teardown cannot steal coordinator ownership. */
TEST(packet_runtime_construction, foreign_shutdown_is_terminate_class)
{
	EXPECT_EXIT(
		{
			auto owner_or = packet_runtime_test_owner::create();
			if (!owner_or.is_ok()) {
				std::_Exit(71);
			}
			auto owner = std::move(owner_or).value();
			std::thread foreign([&owner] { owner->runtime().shutdown(); });
			foreign.join();
			std::_Exit(72);
		},
		::testing::KilledBySignal(SIGABRT), "");
}

/** @brief Prove packet-ready shutdown joins and retires exactly once. */
TEST_F(PacketRuntimeConstructionTest, shutdown_after_bootstrap_is_idempotent)
{
	ASSERT_TRUE(owner_->bootstrap().is_ok());
	owner_->runtime().shutdown();
	owner_->runtime().shutdown();
}

/** @brief Prove one retired generation leaves no process-level startup residue. */
TEST(packet_runtime_construction, successive_generation_owners_rematerialize_cleanly)
{
	for (std::size_t generation = 0; generation < 2u; ++generation) {
		auto owner_or = packet_runtime_test_owner::create();
		ASSERT_TRUE(owner_or.is_ok()) << "generation=" << generation << " error=" << owner_or.error().message();
		auto owner = std::move(owner_or).value();
		expect_control_ready(owner->runtime());
	}
}

}  // namespace kinetum::dp
