// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_epoch_transition_coordinator.cpp
 * @brief Component tests for sole transition coordination and frozen membership.
 * @author Fleming Patel
 *
 * These tests exercise the same admit/abort/query surface consumed by DP
 * admission. No test-only state path exists. They pin two-directional compact
 * membership, snapshot-store rollback, one-generation ownership, bounded
 * terminal history, coherent progress, and fail-stop destruction.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <initializer_list>
#include <memory>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/sha256_digest.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/config_snapshot_epoch_store.hpp"
#include "src/dp/epoch/epoch_transition_coordinator.hpp"
#include "src/provider/compiled_provider_topology.hpp"

namespace kinetum::dp
{
namespace
{

/** Exact initial packet-configuration epoch. */
constexpr uint64_t BOOTSTRAP_EPOCH = 1u;
/** Stable bootstrap request bytes retained for identity/retry tests. */
constexpr std::string_view BOOTSTRAP_REQUEST_BYTES = "bootstrap-wire";

static_assert(!std::is_copy_constructible_v<frozen_transition_participants>);
static_assert(!std::is_move_constructible_v<frozen_transition_participants>);
static_assert(!std::is_copy_constructible_v<epoch_transition_coordinator>);
static_assert(!std::is_move_constructible_v<epoch_transition_coordinator>);

/**
 * @brief Compare one immutable compact-index span with exact expected values.
 *
 * @param actual Participant-set span.
 * @param expected Exact ordered identities.
 */
void expect_indices(std::span<const uint32_t> actual, std::initializer_list<uint32_t> expected)
{
	EXPECT_TRUE(std::equal(actual.begin(), actual.end(), expected.begin(), expected.end()));
}

/**
 * @brief Build one exact compact topology with a boundary and module context.
 *
 * Integration tests separately construct the coordinator from production
 * Gluon/compiler output. This direct fixture keeps malformed ownership tests
 * independent from planner rejection and mutates one compact relation at a
 * time.
 *
 * @param history_capacity Exact enabled terminal-history capacity.
 * @return Complete two-worker source/module/sink topology.
 */
provider::compiled_provider_topology make_topology(uint32_t history_capacity = 2u)
{
	provider::compiled_provider_topology topology;
	topology.source_plan_content_hash = std::string(common::SHA256_HEX_LENGTH, 'a');
	topology.transition_topology.policy.enabled = true;
	topology.transition_topology.policy.result_history_capacity = history_capacity;
	topology.transition_topology.policy.prepared_lease_timeout = std::chrono::seconds(60);

	topology.execution_lanes.resize(1);
	topology.execution_lanes[0].lane_id = "lane_0";
	topology.execution_lanes[0].lane_index = 0;
	topology.execution_lanes[0].stage_instance_indices = {0, 1, 2};
	topology.execution_lanes[0].io_stream_indices = {0, 1};
	topology.logical_stages.resize(3);
	topology.logical_stages[0].logical_stage_id = "rx";
	topology.logical_stages[0].logical_stage_index = 0;
	topology.logical_stages[0].kind = provider::compiled_stage_kind::RX;
	topology.logical_stages[0].stage_instance_indices = {0};
	topology.logical_stages[1].logical_stage_id = "module";
	topology.logical_stages[1].logical_stage_index = 1;
	topology.logical_stages[1].kind = provider::compiled_stage_kind::MODULE;
	topology.logical_stages[1].module_id = "kinetum.test.module";
	topology.logical_stages[1].stage_instance_indices = {1};
	topology.logical_stages[2].logical_stage_id = "tx";
	topology.logical_stages[2].logical_stage_index = 2;
	topology.logical_stages[2].kind = provider::compiled_stage_kind::TX;
	topology.logical_stages[2].stage_instance_indices = {2};
	topology.execution_regions.resize(2);
	topology.execution_regions[0].region_id = 0;
	topology.execution_regions[0].numa_node = 0;
	topology.execution_regions[0].worker_indices = {0};
	topology.execution_regions[0].stage_instance_indices = {0};
	topology.execution_regions[1].region_id = 1;
	topology.execution_regions[1].numa_node = 0;
	topology.execution_regions[1].worker_indices = {1};
	topology.execution_regions[1].stage_instance_indices = {1, 2};

	topology.transition_topology.workers.resize(2);
	auto &source = topology.transition_topology.workers[0];
	source.worker_id = "worker_r0_lane_0";
	source.worker_index = 0;
	source.region_id = 0;
	source.lane_id = "lane_0";
	source.lane_index = 0;
	source.numa_node = 0;
	source.cpu_core_ids = {2};
	source.is_source = true;
	source.stage_instance_indices = {0};
	source.io_stream_indices = {0};
	source.outbound_boundary_indices = {0};

	auto &sink = topology.transition_topology.workers[1];
	sink.worker_id = "worker_r1_lane_0";
	sink.worker_index = 1;
	sink.region_id = 1;
	sink.lane_id = "lane_0";
	sink.lane_index = 0;
	sink.numa_node = 0;
	sink.cpu_core_ids = {3};
	sink.is_sink = true;
	sink.owns_module_context = true;
	sink.stage_instance_indices = {1, 2};
	sink.io_stream_indices = {1};
	sink.inbound_boundary_indices = {0};
	topology.transition_topology.source_worker_indices = {0};
	topology.transition_topology.sink_worker_indices = {1};

	topology.stage_instances.resize(3);
	topology.stage_instances[0].stage_instance_id = "rx@lane_0";
	topology.stage_instances[0].stage_instance_index = 0;
	topology.stage_instances[0].logical_stage_id = "rx";
	topology.stage_instances[0].logical_stage_index = 0;
	topology.stage_instances[0].worker_index = 0;
	topology.stage_instances[0].region_index = 0;
	topology.stage_instances[0].lane_index = 0;
	topology.stage_instances[0].io_stream_index = 0;
	topology.stage_instances[1].stage_instance_id = "module@lane_0";
	topology.stage_instances[1].stage_instance_index = 1;
	topology.stage_instances[1].logical_stage_id = "module";
	topology.stage_instances[1].logical_stage_index = 1;
	topology.stage_instances[1].worker_index = 1;
	topology.stage_instances[1].region_index = 1;
	topology.stage_instances[1].lane_index = 0;
	topology.stage_instances[1].module_context_index = 0;
	topology.stage_instances[2].stage_instance_id = "tx@lane_0";
	topology.stage_instances[2].stage_instance_index = 2;
	topology.stage_instances[2].logical_stage_id = "tx";
	topology.stage_instances[2].logical_stage_index = 2;
	topology.stage_instances[2].worker_index = 1;
	topology.stage_instances[2].region_index = 1;
	topology.stage_instances[2].lane_index = 0;
	topology.stage_instances[2].io_stream_index = 1;

	topology.io_streams.resize(2);
	topology.io_streams[0].io_stream_id = "rx_stream";
	topology.io_streams[0].io_stream_index = 0;
	topology.io_streams[0].stage_instance_index = 0;
	topology.io_streams[0].worker_index = 0;
	topology.io_streams[0].lane_index = 0;
	topology.io_streams[0].direction = provider::compiled_io_stream_direction::RX;
	topology.io_streams[1].io_stream_id = "tx_stream";
	topology.io_streams[1].io_stream_index = 1;
	topology.io_streams[1].stage_instance_index = 2;
	topology.io_streams[1].worker_index = 1;
	topology.io_streams[1].lane_index = 0;
	topology.io_streams[1].direction = provider::compiled_io_stream_direction::TX;

	topology.module_contexts.push_back(provider::compiled_module_context{
		.context_instance_id = "module@lane_0",
		.module_context_index = 0,
		.stage_instance_index = 1,
		.logical_stage_index = 1,
		.worker_index = 1,
		.cpu_core_id = 3,
		.region_id = 1,
		.numa_node = 0,
		.module_id = "kinetum.test.module",
		.context_memory_capacity_bytes = 4096,
		.epoch_arena_capacity_bytes = 4096,
		.module_context_ordinal = 0u,
		.module_context_count = 1u,
	});
	topology.module_context_domains.push_back({"kinetum.test.module", {0u}});

	topology.transition_topology.boundaries.push_back(common::compiled_transition_boundary{
		.boundary_id = "boundary_rx_module",
		.boundary_index = 0,
		.from_stage_instance_index = 0,
		.to_stage_instance_index = 1,
		.sender_worker_index = 0,
		.receiver_worker_index = 1,
		.data_ring_capacity = 64,
		.future_output_hold_capacity = 64,
		.data_ring_numa_node = 0,
	});
	topology.transition_topology.boundaries_by_source_stage_instance.resize(3);
	topology.transition_topology.boundaries_by_source_stage_instance[0].push_back(
		common::compiled_transition_edge{.to_stage_instance_index = 1, .boundary_index = 0});

	topology.worker_schedules.resize(2);
	topology.worker_schedules[0].worker_index = 0;
	topology.worker_schedules[0].stage_instance_indices = {0};
	topology.worker_schedules[0].rx_stream_indices = {0};
	topology.worker_schedules[1].worker_index = 1;
	topology.worker_schedules[1].stage_instance_indices = {1, 2};
	topology.worker_schedules[1].tx_stream_indices = {1};
	return topology;
}

/**
 * @brief Build one exact fixed-width transition identity.
 *
 * @param sequence Mutation sequence and digest seed.
 * @param epoch Exact target epoch.
 * @return Complete valid identity.
 */
common::epoch_transition_identity make_identity(uint64_t sequence, uint64_t epoch)
{
	common::epoch_transition_identity identity{};
	identity.mutation_sequence = sequence;
	identity.target_epoch = epoch;
	identity.validation_hash.fill(static_cast<uint8_t>(sequence));
	identity.idempotency_key_digest.fill(static_cast<uint8_t>(sequence + 1u));
	return identity;
}

/**
 * @brief Construct one canonical module-free snapshot artifact.
 *
 * @param epoch Revision and diagnostic identity suffix.
 * @return Exact immutable artifact.
 */
common::status_or<std::unique_ptr<const config_snapshot_artifact>> make_artifact(uint64_t epoch)
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	snapshot.set_snapshot_id("coordinator.snapshot." + std::to_string(epoch));
	snapshot.set_revision(static_cast<int64_t>(epoch));
	kinetum::gluon::v1::DeploymentPlan plan;
	auto canonical_or = common::canonicalize_config_snapshot(snapshot, plan);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	return config_snapshot_artifact::create(canonical_or.value());
}

/** @brief Exact identity and immutable candidate owned before PREPARE admission. */
struct prepare_candidate {
	common::epoch_transition_identity identity{};		   ///< Hash-matched complete transaction identity.
	std::unique_ptr<const config_snapshot_artifact> artifact;  ///< Sole candidate ownership.
};

/**
 * @brief Construct one candidate whose identity binds its canonical artifact.
 *
 * @param sequence Exact mutation and target allocation.
 * @return Complete candidate or canonical artifact failure.
 */
common::status_or<prepare_candidate> make_prepare_candidate(uint64_t sequence)
{
	auto artifact_or = make_artifact(sequence);
	if (!artifact_or.is_ok()) {
		return artifact_or.error();
	}
	auto artifact = std::move(artifact_or).value();
	auto identity = make_identity(sequence, sequence);
	identity.validation_hash = artifact->validation_hash();
	return prepare_candidate{.identity = identity, .artifact = std::move(artifact)};
}

/**
 * @brief Stage and publish one exact Bootstrap authority through the coordinator.
 *
 * @param coordinator Sole coordinator owner.
 * @param epoch Exact Bootstrap epoch.
 * @param watermarks Exact durable allocation high watermarks.
 * @return OK after exact publication, or the first recoverable setup failure.
 */
common::status bootstrap_with_watermarks(epoch_transition_coordinator &coordinator, uint64_t epoch,
					 common::epoch_transition_watermarks watermarks)
{
	const auto bound = coordinator.bind_bootstrap_request(
		BOOTSTRAP_REQUEST_BYTES, std::string(common::SHA256_HEX_LENGTH, 'a'), epoch, watermarks);
	if (!bound.is_ok()) {
		return bound;
	}
	auto artifact_or = make_artifact(epoch);
	if (!artifact_or.is_ok()) {
		return artifact_or.error();
	}
	auto artifact = std::move(artifact_or).value();
	const auto staged = coordinator.stage_bootstrap_snapshot(epoch, artifact);
	if (!staged.is_ok()) {
		return staged;
	}
	if (artifact != nullptr) {
		std::terminate();
	}
	const auto preflight = coordinator.preflight_bootstrap_publication(epoch);
	if (!preflight.is_ok()) {
		if (!coordinator.abort_bootstrap(epoch).is_ok()) {
			std::terminate();
		}
		return preflight;
	}
	coordinator.publish_bootstrap_or_terminate(epoch);
	return common::status::ok();
}

/**
 * @brief Stage and publish Bootstrap with allocation watermarks equal to epoch.
 *
 * @param coordinator Sole coordinator owner.
 * @param epoch Exact Bootstrap epoch and both test watermarks.
 * @return OK after exact publication, or the first setup failure.
 */
common::status bootstrap(epoch_transition_coordinator &coordinator, uint64_t epoch)
{
	return bootstrap_with_watermarks(coordinator, epoch, {epoch, epoch});
}

/**
 * @brief Resolve ordinary test ownership before the fail-stop destructor runs.
 *
 * Production deliberately terminates when a coordinator is destroyed with a
 * staged or published snapshot. Ordinary assertion failures must retain their
 * diagnostic, so this scoped test owner aborts BOOTSTRAPPING or retires the
 * published fixed epoch. A live transition generation, FAILED_STOP, or another
 * non-cleanable phase remains terminate-class. Intentional destructor tests use
 * raw coordinator ownership instead.
 */
class coordinator_test_owner final {
    public:
	/**
	 * @brief Adopt one coordinator for an ordinary component test.
	 *
	 * @param coordinator Sole coordinator ownership.
	 */
	explicit coordinator_test_owner(std::unique_ptr<epoch_transition_coordinator> coordinator) noexcept
		: coordinator_(std::move(coordinator))
	{
		if (!coordinator_) {
			std::terminate();
		}
	}

	/** @brief Test coordinator owners cannot be copied. */
	coordinator_test_owner(const coordinator_test_owner &) = delete;
	/** @brief Test coordinator owners cannot be copy-assigned. */
	coordinator_test_owner &operator=(const coordinator_test_owner &) = delete;
	/** @brief Test coordinator owners cannot be moved. */
	coordinator_test_owner(coordinator_test_owner &&) = delete;
	/** @brief Test coordinator owners cannot be move-assigned. */
	coordinator_test_owner &operator=(coordinator_test_owner &&) = delete;

	/** @brief Resolve test-owned Bootstrap state before coordinator destruction. */
	~coordinator_test_owner()
	{
		switch (coordinator_->phase()) {
		case epoch_transition_phase::AWAITING_BOOTSTRAP:
			if (!coordinator_->snapshot_store_empty()) {
				std::terminate();
			}
			return;
		case epoch_transition_phase::BOOTSTRAPPING:
			if (!coordinator_->abort_bootstrap(BOOTSTRAP_EPOCH).is_ok() ||
			    !coordinator_->snapshot_store_empty()) {
				std::terminate();
			}
			return;
		case epoch_transition_phase::IDLE:
			if (!coordinator_->snapshot_store_empty() &&
			    !coordinator_->retire_published_after_quiescence(coordinator_->active_epoch()).is_ok()) {
				std::terminate();
			}
			if (!coordinator_->snapshot_store_empty()) {
				std::terminate();
			}
			return;
		case epoch_transition_phase::PREPARING: {
			const auto aborted =
				coordinator_->abort_active_for_shutdown(std::numeric_limits<uint64_t>::max() - 1u);
			if (!aborted.is_ok() ||
			    !coordinator_->retire_published_after_quiescence(coordinator_->active_epoch()).is_ok() ||
			    !coordinator_->snapshot_store_empty()) {
				std::terminate();
			}
			return;
		}
		case epoch_transition_phase::PREPARED:
		case epoch_transition_phase::COMMITTING:
		case epoch_transition_phase::RETIRING:
		case epoch_transition_phase::FAILED_STOP:
			std::terminate();
		}
		std::terminate();
	}

	/** @return Borrowed coordinator for the test body. */
	[[nodiscard]] epoch_transition_coordinator *operator->() noexcept
	{
		return coordinator_.get();
	}

	/** @return Borrowed coordinator reference for helper calls. */
	[[nodiscard]] epoch_transition_coordinator &operator*() noexcept
	{
		return *coordinator_;
	}

    private:
	std::unique_ptr<epoch_transition_coordinator> coordinator_;  ///< Sole test ownership.
};

}  // namespace

/** @brief Freeze every exact compact membership relation once. */
TEST(epoch_transition_coordinator, frozen_participants_match_exact_compiled_ownership)
{
	auto topology = make_topology();
	auto coordinator_or = epoch_transition_coordinator::create(topology);
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	const auto &participants = coordinator->participants();

	EXPECT_EQ(participants.plan_content_hash(), topology.source_plan_content_hash);
	ASSERT_EQ(participants.execution_participant_count(), 2u);
	ASSERT_EQ(participants.region_count(), 2u);
	EXPECT_EQ(participants.boundary_count(), 1u);
	EXPECT_EQ(participants.module_context_count(), 1u);
	EXPECT_EQ(participants.quiescence_reader_count(), 2u);
	ASSERT_NE(participants.execution_participant(0), nullptr);
	ASSERT_NE(participants.execution_participant(1), nullptr);
	EXPECT_TRUE(participants.execution_participant(0)->is_source);
	EXPECT_TRUE(participants.execution_participant(1)->is_sink);
	EXPECT_EQ(participants.execution_participant(0)->lane_index, 0u);
	expect_indices(participants.source_participant_indices(), {0});
	expect_indices(participants.sink_participant_indices(), {1});
	expect_indices(participants.quiescence_reader_indices(), {0, 1});
	expect_indices(participants.stage_indices(0), {0});
	expect_indices(participants.stage_indices(1), {1, 2});
	expect_indices(participants.io_stream_indices(0), {0});
	expect_indices(participants.io_stream_indices(1), {1});
	expect_indices(participants.outbound_boundary_indices(0), {0});
	expect_indices(participants.inbound_boundary_indices(1), {0});
	expect_indices(participants.module_context_indices(1), {0});
	expect_indices(participants.region_worker_indices(0), {0});
	expect_indices(participants.region_worker_indices(1), {1});
}

/** @brief Reject invalid compact ownership and membership before publication. */
TEST(epoch_transition_coordinator, frozen_participants_reject_cross_owned_or_incomplete_membership)
{
	auto cross_owned = make_topology();
	cross_owned.stage_instances[1].worker_index = 0;
	auto cross_owned_or = epoch_transition_coordinator::create(cross_owned);
	ASSERT_FALSE(cross_owned_or.is_ok());
	EXPECT_EQ(cross_owned_or.error().code(), common::status_code::INVALID_ARGUMENT);

	auto incomplete = make_topology();
	incomplete.transition_topology.workers[1].inbound_boundary_indices.clear();
	auto incomplete_or = epoch_transition_coordinator::create(incomplete);
	ASSERT_FALSE(incomplete_or.is_ok());
	EXPECT_EQ(incomplete_or.error().code(), common::status_code::INVALID_ARGUMENT);

	auto lane_mismatch = make_topology();
	lane_mismatch.execution_lanes[0].io_stream_indices.pop_back();
	auto lane_mismatch_or = epoch_transition_coordinator::create(lane_mismatch);
	ASSERT_FALSE(lane_mismatch_or.is_ok());
	EXPECT_EQ(lane_mismatch_or.error().code(), common::status_code::INVALID_ARGUMENT);

	auto out_of_range = make_topology();
	ASSERT_EQ(out_of_range.transition_topology.boundaries.size(), 1u);
	out_of_range.transition_topology.workers[1].inbound_boundary_indices = {1};
	auto out_of_range_or = epoch_transition_coordinator::create(out_of_range);
	ASSERT_FALSE(out_of_range_or.is_ok());
	EXPECT_EQ(out_of_range_or.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(
		out_of_range_or.error().message(),
		"execution participant inbound boundary membership is noncompact, duplicate, unsorted, or cross-owned");

	auto duplicate = make_topology();
	duplicate.transition_topology.workers[1].inbound_boundary_indices = {0, 0};
	auto duplicate_or = epoch_transition_coordinator::create(duplicate);
	ASSERT_FALSE(duplicate_or.is_ok());
	EXPECT_EQ(duplicate_or.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(
		duplicate_or.error().message(),
		"execution participant inbound boundary membership is noncompact, duplicate, unsorted, or cross-owned");

	auto wrong_receiver = make_topology();
	wrong_receiver.transition_topology.workers[0].inbound_boundary_indices = {0};
	auto wrong_receiver_or = epoch_transition_coordinator::create(wrong_receiver);
	ASSERT_FALSE(wrong_receiver_or.is_ok());
	EXPECT_EQ(wrong_receiver_or.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(
		wrong_receiver_or.error().message(),
		"execution participant inbound boundary membership is noncompact, duplicate, unsorted, or cross-owned");
}

/** @brief Mutating the caller topology cannot alter already frozen membership. */
TEST(epoch_transition_coordinator, participant_set_is_constructed_once_and_generation_binds_its_identity)
{
	auto topology = make_topology();
	auto coordinator_or = epoch_transition_coordinator::create(topology);
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	const auto *frozen_identity = &coordinator->participants();

	topology.transition_topology.workers.clear();
	topology.stage_instances.clear();
	ASSERT_TRUE(bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok());
	auto candidate_or = make_prepare_candidate(2u);
	ASSERT_TRUE(candidate_or.is_ok()) << candidate_or.error().message();
	auto candidate = std::move(candidate_or).value();
	const auto identity = candidate.identity;
	const auto admitted = coordinator->admit_prepare(identity, candidate.artifact, 100u);
	ASSERT_TRUE(admitted.is_ok());
	EXPECT_EQ(admitted.observation.resolution, common::transition_identity_resolution::ADMISSIBLE);
	EXPECT_EQ(candidate.artifact, nullptr);
	EXPECT_EQ(&coordinator->participants(), frozen_identity);
	const auto aborted = coordinator->abort_before_commit(
		identity, 200u, epoch_transition_failure_code::EXPLICIT_ABORT, "test abort");
	ASSERT_TRUE(aborted.is_ok());
	EXPECT_EQ(&coordinator->participants(), frozen_identity);
}

/** @brief Publish only coherent AWAITING, BOOTSTRAPPING, and IDLE Bootstrap truth. */
TEST(epoch_transition_coordinator, bootstrap_progress_and_store_rollback_are_exact)
{
	auto coordinator_or = epoch_transition_coordinator::create(make_topology());
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	epoch_transition_progress_snapshot progress{};
	ASSERT_EQ(coordinator->try_read_progress(progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(progress.phase, epoch_transition_phase::AWAITING_BOOTSTRAP);
	EXPECT_EQ(progress.active_epoch, 0u);
	EXPECT_EQ(progress.active_validation_hash, common::sha256_digest{});
	EXPECT_EQ(progress.allocated_epoch_high_watermark, 0u);
	EXPECT_EQ(progress.mutation_sequence_high_watermark, 0u);
	EXPECT_TRUE(coordinator->snapshot_store_empty());

	ASSERT_TRUE(
		coordinator
			->bind_bootstrap_request(BOOTSTRAP_REQUEST_BYTES, std::string(common::SHA256_HEX_LENGTH, 'a'),
						 BOOTSTRAP_EPOCH,
						 common::epoch_transition_watermarks{BOOTSTRAP_EPOCH, BOOTSTRAP_EPOCH})
			.is_ok());
	auto artifact_or = make_artifact(BOOTSTRAP_EPOCH);
	ASSERT_TRUE(artifact_or.is_ok()) << artifact_or.error().message();
	auto artifact = std::move(artifact_or).value();
	ASSERT_TRUE(coordinator->stage_bootstrap_snapshot(BOOTSTRAP_EPOCH, artifact).is_ok());
	ASSERT_TRUE(coordinator->preflight_bootstrap_publication(BOOTSTRAP_EPOCH).is_ok());
	ASSERT_EQ(coordinator->try_read_progress(progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(progress.phase, epoch_transition_phase::BOOTSTRAPPING);
	EXPECT_EQ(progress.allocated_epoch_high_watermark, 0u);
	EXPECT_EQ(progress.mutation_sequence_high_watermark, 0u);
	ASSERT_TRUE(coordinator->abort_bootstrap(BOOTSTRAP_EPOCH).is_ok());
	ASSERT_EQ(coordinator->try_read_progress(progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(progress.phase, epoch_transition_phase::AWAITING_BOOTSTRAP);
	EXPECT_EQ(progress.active_epoch, 0u);
	EXPECT_EQ(progress.target_epoch, 0u);
	EXPECT_EQ(progress.allocated_epoch_high_watermark, 0u);
	EXPECT_EQ(progress.mutation_sequence_high_watermark, 0u);
	EXPECT_TRUE(coordinator->snapshot_store_empty());

	auto retry_or = make_artifact(BOOTSTRAP_EPOCH);
	ASSERT_TRUE(retry_or.is_ok()) << retry_or.error().message();
	auto retry = std::move(retry_or).value();
	const auto expected_validation_hash = retry->validation_hash();
	ASSERT_TRUE(coordinator->stage_bootstrap_snapshot(BOOTSTRAP_EPOCH, retry).is_ok());
	ASSERT_TRUE(coordinator->preflight_bootstrap_publication(BOOTSTRAP_EPOCH).is_ok());
	coordinator->publish_bootstrap_or_terminate(BOOTSTRAP_EPOCH);
	EXPECT_FALSE(coordinator->snapshot_store_empty());
	ASSERT_EQ(coordinator->try_read_progress(progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(progress.phase, epoch_transition_phase::IDLE);
	EXPECT_EQ(progress.active_epoch, BOOTSTRAP_EPOCH);
	EXPECT_EQ(progress.active_validation_hash, expected_validation_hash);
	EXPECT_EQ(progress.allocated_epoch_high_watermark, BOOTSTRAP_EPOCH);
	EXPECT_EQ(progress.mutation_sequence_high_watermark, BOOTSTRAP_EPOCH);
}

/** @brief Policy owns exact live-history capacity and fixed-epoch refusal. */
TEST(epoch_transition_coordinator, transition_policy_owns_history_capacity_and_live_admission)
{
	auto zero_enabled_or = epoch_transition_coordinator::create(make_topology(0));
	ASSERT_FALSE(zero_enabled_or.is_ok());
	EXPECT_EQ(zero_enabled_or.error().code(), common::status_code::OUT_OF_RANGE);

	auto oversized_or = epoch_transition_coordinator::create(
		make_topology(common::MAX_TRANSITION_RESULT_HISTORY_CAPACITY + 1u));
	ASSERT_FALSE(oversized_or.is_ok());
	EXPECT_EQ(oversized_or.error().code(), common::status_code::OUT_OF_RANGE);

	auto missing_lease = make_topology();
	missing_lease.transition_topology.policy.prepared_lease_timeout = std::chrono::steady_clock::duration::zero();
	auto missing_lease_or = epoch_transition_coordinator::create(missing_lease);
	ASSERT_FALSE(missing_lease_or.is_ok());
	EXPECT_EQ(missing_lease_or.error().code(), common::status_code::INVALID_ARGUMENT);

	auto disabled_with_history = make_topology(1);
	disabled_with_history.transition_topology.policy.enabled = false;
	auto disabled_with_history_or = epoch_transition_coordinator::create(disabled_with_history);
	ASSERT_FALSE(disabled_with_history_or.is_ok());
	EXPECT_EQ(disabled_with_history_or.error().code(), common::status_code::INVALID_ARGUMENT);

	auto topology = make_topology();
	topology.transition_topology.policy.enabled = false;
	topology.transition_topology.policy.result_history_capacity = 0;
	topology.transition_topology.policy.prepared_lease_timeout = std::chrono::steady_clock::duration::zero();
	auto coordinator_or = epoch_transition_coordinator::create(topology);
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	EXPECT_EQ(coordinator->terminal_history_capacity(), 0u);
	ASSERT_TRUE(bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok());
	auto candidate_or = make_prepare_candidate(2u);
	ASSERT_TRUE(candidate_or.is_ok()) << candidate_or.error().message();
	auto candidate = std::move(candidate_or).value();
	const auto result = coordinator->admit_prepare(candidate.identity, candidate.artifact, 100u);
	EXPECT_FALSE(result.is_ok());
	EXPECT_EQ(result.code, common::status_code::UNAVAILABLE);
	EXPECT_EQ(result.observation.resolution, common::transition_identity_resolution::POLICY_DISABLED);
	EXPECT_NE(candidate.artifact, nullptr);
}

/** @brief One generation token rejects overlap and exact identity substitution. */
TEST(epoch_transition_coordinator, one_generation_token_rejects_overlap_and_substitution)
{
	auto coordinator_or = epoch_transition_coordinator::create(make_topology());
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	const auto before_bootstrap = coordinator->query_transaction(make_identity(2u, 2u));
	EXPECT_EQ(before_bootstrap.code, common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(before_bootstrap.observation.resolution, common::transition_identity_resolution::STATE_UNAVAILABLE);
	ASSERT_TRUE(bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok());
	auto first_or = make_prepare_candidate(2u);
	auto second_or = make_prepare_candidate(3u);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto first = std::move(first_or).value();
	auto second = std::move(second_or).value();
	std::unique_ptr<const config_snapshot_artifact> missing_candidate;
	const auto missing = coordinator->admit_prepare(first.identity, missing_candidate, 100u);
	EXPECT_EQ(missing.code, common::status_code::INVALID_ARGUMENT);
	const auto missing_timestamp = coordinator->admit_prepare(first.identity, first.artifact, 0u);
	EXPECT_EQ(missing_timestamp.code, common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(first.artifact, nullptr);
	auto mismatched_identity = first.identity;
	mismatched_identity.validation_hash[0] ^= UINT8_C(0x1);
	const auto mismatched_candidate = coordinator->admit_prepare(mismatched_identity, first.artifact, 100u);
	EXPECT_EQ(mismatched_candidate.code, common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(first.artifact, nullptr);
	ASSERT_TRUE(coordinator->admit_prepare(first.identity, first.artifact, 100u).is_ok());
	const auto overlap = coordinator->admit_prepare(second.identity, second.artifact, 110u);
	EXPECT_FALSE(overlap.is_ok());
	EXPECT_EQ(overlap.observation.resolution, common::transition_identity_resolution::OVERLAP);
	const auto substituted_abort = coordinator->abort_before_commit(
		second.identity, 120u, epoch_transition_failure_code::EXPLICIT_ABORT, "substituted abort");
	EXPECT_FALSE(substituted_abort.is_ok());
	const auto regressed_time = coordinator->abort_before_commit(
		first.identity, 99u, epoch_transition_failure_code::EXPLICIT_ABORT, "regressed time");
	EXPECT_EQ(regressed_time.code, common::status_code::INVALID_ARGUMENT);
	const auto invalid_cause = coordinator->abort_before_commit(
		first.identity, 120u, static_cast<epoch_transition_failure_code>(UINT8_C(0xff)), "invalid cause");
	EXPECT_EQ(invalid_cause.code, common::status_code::INVALID_ARGUMENT);
	epoch_transition_progress_snapshot progress{};
	const auto progress_read = coordinator->try_read_progress(progress);
	EXPECT_EQ(progress_read, publication_read_result::AVAILABLE);
	if (progress_read == publication_read_result::AVAILABLE) {
		EXPECT_EQ(progress.phase, epoch_transition_phase::PREPARING);
		EXPECT_EQ(progress.mutation_sequence, first.identity.mutation_sequence);
		EXPECT_EQ(progress.allocated_epoch_high_watermark, first.identity.target_epoch);
		EXPECT_EQ(progress.mutation_sequence_high_watermark, first.identity.mutation_sequence);
		EXPECT_TRUE(progress.participants_frozen);
		EXPECT_EQ(progress.terminal_history_size, 0u);
	}
	ASSERT_TRUE(coordinator
			    ->abort_before_commit(first.identity, 200u, epoch_transition_failure_code::EXPLICIT_ABORT,
						  "exact abort")
			    .is_ok());
}

/** @brief Resolve exact retries, conflicts, stale values, and future identities by type. */
TEST(epoch_transition_coordinator, transaction_identity_resolution_is_exact_and_message_independent)
{
	auto coordinator_or = epoch_transition_coordinator::create(make_topology());
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	ASSERT_TRUE(bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok());

	auto first_or = make_prepare_candidate(2u);
	auto retry_or = make_prepare_candidate(2u);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(retry_or.is_ok()) << retry_or.error().message();
	auto first = std::move(first_or).value();
	auto retry = std::move(retry_or).value();
	ASSERT_TRUE(coordinator->admit_prepare(first.identity, first.artifact, 100u).is_ok());
	const auto exact_active = coordinator->admit_prepare(retry.identity, retry.artifact, 110u);
	ASSERT_TRUE(exact_active.is_ok());
	EXPECT_EQ(exact_active.observation.resolution, common::transition_identity_resolution::ACTIVE_EXACT);
	EXPECT_NE(retry.artifact, nullptr);

	auto conflict = first.identity;
	conflict.idempotency_key_digest[0] ^= UINT8_C(0x1);
	const auto conflicting = coordinator->query_transaction(conflict);
	EXPECT_EQ(conflicting.code, common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(conflicting.observation.resolution, common::transition_identity_resolution::IDENTITY_CONFLICT);

	const std::string long_diagnostic(common::MAX_TRANSITION_DIAGNOSTIC_BYTES + 41u, 'x');
	const auto aborted = coordinator->abort_before_commit(
		first.identity, 175u, epoch_transition_failure_code::EXPLICIT_ABORT, long_diagnostic);
	ASSERT_TRUE(aborted.is_ok());
	EXPECT_EQ(aborted.observation.resolution, common::transition_identity_resolution::TERMINAL_EXACT);
	EXPECT_EQ(aborted.observation.diagnostic.size, common::MAX_TRANSITION_DIAGNOSTIC_BYTES);
	EXPECT_EQ(aborted.observation.prepare_duration_ns, 75u);

	const auto exact_terminal = coordinator->query_transaction(first.identity);
	ASSERT_TRUE(exact_terminal.is_ok());
	EXPECT_EQ(exact_terminal.observation.resolution, common::transition_identity_resolution::TERMINAL_EXACT);
	epoch_transition_telemetry_snapshot terminal_telemetry{};
	ASSERT_EQ(coordinator->try_read_telemetry(terminal_telemetry), publication_read_result::AVAILABLE);
	EXPECT_FALSE(terminal_telemetry.active.present);
	ASSERT_TRUE(terminal_telemetry.latest_terminal.present);
	EXPECT_EQ(terminal_telemetry.latest_terminal.admitted_monotonic_ns, 100u);
	EXPECT_EQ(terminal_telemetry.latest_terminal.prepared_monotonic_ns, 175u);
	EXPECT_EQ(terminal_telemetry.latest_terminal.terminal_monotonic_ns, 175u);
	EXPECT_EQ(terminal_telemetry.latest_terminal.outcome, epoch_transition_outcome::ABORTED);
	auto reused_key_or = make_prepare_candidate(3u);
	ASSERT_TRUE(reused_key_or.is_ok()) << reused_key_or.error().message();
	auto reused_key = std::move(reused_key_or).value();
	reused_key.identity.idempotency_key_digest = first.identity.idempotency_key_digest;
	const auto key_conflict = coordinator->admit_prepare(reused_key.identity, reused_key.artifact, 180u);
	EXPECT_EQ(key_conflict.code, common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(key_conflict.observation.resolution, common::transition_identity_resolution::IDENTITY_CONFLICT);
	EXPECT_NE(reused_key.artifact, nullptr);
	const auto stale = coordinator->query_transaction(make_identity(1u, 1u));
	EXPECT_EQ(stale.observation.resolution, common::transition_identity_resolution::STALE);
	auto inconsistent_identity = make_identity(2u, 3u);
	inconsistent_identity.idempotency_key_digest.fill(UINT8_C(0x5a));
	ASSERT_NE(inconsistent_identity.idempotency_key_digest, first.identity.idempotency_key_digest);
	const auto inconsistent = coordinator->query_transaction(inconsistent_identity);
	EXPECT_EQ(inconsistent.observation.resolution, common::transition_identity_resolution::INCONSISTENT);
	const auto unknown = coordinator->query_transaction(make_identity(3u, 3u));
	EXPECT_EQ(unknown.code, common::status_code::NOT_FOUND);
	EXPECT_EQ(unknown.observation.resolution, common::transition_identity_resolution::UNKNOWN_FUTURE);

	auto terminal_retry_or = make_prepare_candidate(2u);
	ASSERT_TRUE(terminal_retry_or.is_ok()) << terminal_retry_or.error().message();
	auto terminal_retry = std::move(terminal_retry_or).value();
	const auto repeated = coordinator->admit_prepare(terminal_retry.identity, terminal_retry.artifact, 200u);
	ASSERT_TRUE(repeated.is_ok());
	EXPECT_EQ(repeated.observation.resolution, common::transition_identity_resolution::TERMINAL_EXACT);
	EXPECT_NE(terminal_retry.artifact, nullptr);
}

/** @brief Restored watermarks reject equal missing and older identities after restart. */
TEST(epoch_transition_coordinator, restored_watermarks_make_empty_journal_restart_safe)
{
	auto coordinator_or = epoch_transition_coordinator::create(make_topology());
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	ASSERT_TRUE(bootstrap_with_watermarks(*coordinator, BOOTSTRAP_EPOCH, {9u, 9u}).is_ok());

	const auto expired = coordinator->query_transaction(make_identity(9u, 9u));
	EXPECT_EQ(expired.code, common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(expired.observation.resolution, common::transition_identity_resolution::EXPIRED_RETRY);
	const auto stale = coordinator->query_transaction(make_identity(8u, 8u));
	EXPECT_EQ(stale.observation.resolution, common::transition_identity_resolution::STALE);

	auto next_or = make_prepare_candidate(10u);
	ASSERT_TRUE(next_or.is_ok()) << next_or.error().message();
	auto next = std::move(next_or).value();
	const auto admitted = coordinator->admit_prepare(next.identity, next.artifact, 100u);
	ASSERT_TRUE(admitted.is_ok());
	EXPECT_EQ(coordinator->prepared_snapshot_epoch(), 0u);
	EXPECT_EQ(admitted.observation.lease_state, epoch_transition_prepared_lease_state::NOT_ARMED);
	EXPECT_EQ(admitted.observation.prepared_lease_deadline_monotonic_ns, 0u);
	EXPECT_EQ(admitted.observation.prepared_lease_deadline_unix_ms, 0u);
	EXPECT_EQ(coordinator->prepared_lease_timeout(), std::chrono::seconds(60));
	ASSERT_TRUE(coordinator->arm_completion(next.identity).is_ok());
	const auto prepared = coordinator->mark_prepared(next.identity, 150u, 200u, 300u);
	ASSERT_TRUE(prepared.is_ok());
	EXPECT_EQ(prepared.observation.phase, epoch_transition_phase::PREPARED);
	EXPECT_EQ(prepared.observation.lease_state, epoch_transition_prepared_lease_state::ARMED);
	EXPECT_EQ(prepared.observation.prepared_lease_deadline_monotonic_ns, 200u);
	EXPECT_EQ(prepared.observation.prepared_lease_deadline_unix_ms, 300u);
	EXPECT_EQ(prepared.observation.prepare_duration_ns, 50u);
	EXPECT_EQ(prepared.observation.duration_presence, TRANSITION_PREPARE_DURATION_PRESENT);
	EXPECT_EQ(coordinator->prepared_snapshot_epoch(), next.identity.target_epoch);
	epoch_transition_progress_snapshot prepared_progress{};
	ASSERT_EQ(coordinator->try_read_progress(prepared_progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(prepared_progress.phase, epoch_transition_phase::PREPARED);
	EXPECT_EQ(prepared_progress.target_epoch, next.identity.target_epoch);
	ASSERT_TRUE(coordinator->begin_prepared_abort_cleanup(next.identity).is_ok());
	EXPECT_EQ(coordinator->try_read_progress(prepared_progress), publication_read_result::UNAVAILABLE);
	const auto shutdown_abort = coordinator->abort_active_for_shutdown(175u);
	ASSERT_TRUE(shutdown_abort.is_ok());
	EXPECT_EQ(shutdown_abort.observation.failure_code, epoch_transition_failure_code::SHUTDOWN_ABORT);
	EXPECT_EQ(shutdown_abort.observation.prepare_duration_ns, 50u);
	EXPECT_EQ(coordinator->prepared_snapshot_epoch(), 0u);
	ASSERT_EQ(coordinator->try_read_progress(prepared_progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(prepared_progress.phase, epoch_transition_phase::IDLE);
}

/** @brief Publish typed allocator exhaustion without poisoning active traffic. */
TEST(epoch_transition_coordinator, exhausted_restored_allocator_is_typed_and_non_poisoning)
{
	auto coordinator_or = epoch_transition_coordinator::create(make_topology());
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	epoch_protocol_fault_latch faults;
	ASSERT_TRUE(coordinator->bind_protocol_faults(7u, faults).is_ok());
	ASSERT_TRUE(bootstrap_with_watermarks(*coordinator, BOOTSTRAP_EPOCH,
					      {common::MAX_EPOCH_ID, common::MAX_MUTATION_SEQUENCE})
			    .is_ok());
	epoch_transition_telemetry_snapshot telemetry{};
	ASSERT_EQ(coordinator->try_read_telemetry(telemetry), publication_read_result::AVAILABLE);
	EXPECT_EQ(telemetry.protocol_fault_counts[epoch_protocol_fault_ordinal(
			  epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED)],
		  1u);
	epoch_protocol_first_fault first{};
	ASSERT_TRUE(faults.try_read(first));
	EXPECT_EQ(first.code, epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED);
	EXPECT_EQ(first.disposition, epoch_protocol_fault_disposition::RESOURCE_REFUSED);
	EXPECT_FALSE(faults.transition_success_blocked());
}

/** @brief Full history evicts only the oldest terminal result. */
TEST(epoch_transition_coordinator, terminal_history_is_bounded_and_chronological)
{
	auto coordinator_or = epoch_transition_coordinator::create(make_topology(2));
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	ASSERT_TRUE(bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok());
	std::array<common::epoch_transition_identity, 3> identities{};
	for (uint64_t sequence = 2; sequence <= 4; ++sequence) {
		auto candidate_or = make_prepare_candidate(sequence);
		ASSERT_TRUE(candidate_or.is_ok()) << candidate_or.error().message();
		auto candidate = std::move(candidate_or).value();
		identities[static_cast<std::size_t>(sequence - 2u)] = candidate.identity;
		ASSERT_TRUE(
			coordinator->admit_prepare(candidate.identity, candidate.artifact, sequence * 100u).is_ok());
		ASSERT_TRUE(coordinator
				    ->abort_before_commit(candidate.identity, sequence * 100u + 25u,
							  epoch_transition_failure_code::EXPLICIT_ABORT,
							  "bounded exact abort")
				    .is_ok());
	}
	ASSERT_EQ(coordinator->terminal_history_capacity(), 2u);
	ASSERT_EQ(coordinator->terminal_history_size(), 2u);
	ASSERT_NE(coordinator->terminal_result(0), nullptr);
	ASSERT_NE(coordinator->terminal_result(1), nullptr);
	const auto *first_result = coordinator->terminal_result(0);
	const auto *second_result = coordinator->terminal_result(1);
	EXPECT_EQ(first_result->identity, identities[1]);
	EXPECT_EQ(first_result->from_epoch, BOOTSTRAP_EPOCH);
	EXPECT_EQ(first_result->to_epoch, 3u);
	EXPECT_EQ(first_result->outcome, epoch_transition_outcome::ABORTED);
	EXPECT_EQ(first_result->prepare_duration_ns, 25u);
	EXPECT_EQ(first_result->duration_presence, TRANSITION_PREPARE_DURATION_PRESENT);
	EXPECT_EQ(first_result->failure_code, epoch_transition_failure_code::EXPLICIT_ABORT);
	EXPECT_EQ(second_result->identity, identities[2]);
	EXPECT_EQ(second_result->from_epoch, BOOTSTRAP_EPOCH);
	EXPECT_EQ(second_result->to_epoch, 4u);
	EXPECT_EQ(second_result->outcome, epoch_transition_outcome::ABORTED);
	EXPECT_EQ(second_result->prepare_duration_ns, 25u);
	EXPECT_EQ(coordinator->terminal_result(2), nullptr);
	epoch_transition_progress_snapshot progress{};
	ASSERT_EQ(coordinator->try_read_progress(progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(progress.terminal_history_size, 2u);
	EXPECT_EQ(progress.last_terminal_outcome, epoch_transition_outcome::ABORTED);
}

/** @brief Prove exact COMMITTING/RETIRING timing and COMPLETE journal publication. */
TEST(epoch_transition_coordinator, committed_snapshot_retires_before_complete_and_idle_publication)
{
	auto coordinator_or = epoch_transition_coordinator::create(make_topology());
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	ASSERT_TRUE(bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok());
	auto candidate_or = make_prepare_candidate(2u);
	ASSERT_TRUE(candidate_or.is_ok()) << candidate_or.error().message();
	auto candidate = std::move(candidate_or).value();
	const auto identity = candidate.identity;
	ASSERT_TRUE(coordinator->admit_prepare(identity, candidate.artifact, 100u).is_ok());
	ASSERT_TRUE(coordinator->arm_completion(identity).is_ok());
	ASSERT_TRUE(coordinator->mark_prepared(identity, 150u, 500u, 700u).is_ok());
	ASSERT_TRUE(coordinator->preflight_begin_commit(identity, 200u).is_ok());
	coordinator->begin_commit_or_terminate(identity, 200u);
	EXPECT_EQ(coordinator->phase(), epoch_transition_phase::COMMITTING);
	ASSERT_TRUE(coordinator->preflight_begin_retiring(identity, 250u).is_ok());
	coordinator->publish_target_snapshot_or_terminate(identity);
	coordinator->enter_retiring_or_terminate(identity, 250u);
	EXPECT_EQ(coordinator->phase(), epoch_transition_phase::RETIRING);
	EXPECT_EQ(coordinator->active_epoch(), BOOTSTRAP_EPOCH);
	EXPECT_EQ(coordinator->prepared_snapshot_epoch(), 0u);
	EXPECT_EQ(coordinator->retained_snapshot_epoch(), BOOTSTRAP_EPOCH);
	ASSERT_TRUE(coordinator->preflight_retained_snapshot(identity).is_ok());
	coordinator->retire_retained_snapshot_or_terminate(identity);
	coordinator->complete_retirement_or_terminate(identity, 325u);
	EXPECT_EQ(coordinator->phase(), epoch_transition_phase::IDLE);
	EXPECT_EQ(coordinator->active_epoch(), identity.target_epoch);
	ASSERT_EQ(coordinator->terminal_history_size(), 1u);
	const auto *terminal = coordinator->terminal_result(0u);
	ASSERT_NE(terminal, nullptr);
	EXPECT_EQ(terminal->outcome, epoch_transition_outcome::COMPLETE);
	EXPECT_EQ(terminal->prepare_duration_ns, 50u);
	EXPECT_EQ(terminal->commit_duration_ns, 50u);
	EXPECT_EQ(terminal->retirement_duration_ns, 75u);
	EXPECT_EQ(terminal->duration_presence, TRANSITION_PREPARE_DURATION_PRESENT |
						       TRANSITION_COMMIT_DURATION_PRESENT |
						       TRANSITION_RETIREMENT_DURATION_PRESENT);
	epoch_transition_telemetry_snapshot telemetry{};
	ASSERT_EQ(coordinator->try_read_telemetry(telemetry), publication_read_result::AVAILABLE);
	EXPECT_FALSE(telemetry.active.present);
	ASSERT_TRUE(telemetry.latest_terminal.present);
	EXPECT_EQ(telemetry.latest_terminal.prepared_monotonic_ns, 150u);
	EXPECT_EQ(telemetry.latest_terminal.commit_started_monotonic_ns, 200u);
	EXPECT_EQ(telemetry.latest_terminal.retiring_started_monotonic_ns, 250u);
	EXPECT_EQ(telemetry.latest_terminal.terminal_monotonic_ns, 325u);
	const auto exact = coordinator->query_transaction(identity);
	EXPECT_TRUE(exact.is_ok());
	EXPECT_EQ(exact.observation.resolution, common::transition_identity_resolution::TERMINAL_EXACT);
	EXPECT_EQ(exact.observation.outcome, epoch_transition_outcome::COMPLETE);
}

/** @brief Prove grace timeout latches RETIRING and later completion remains impossible. */
TEST(epoch_transition_coordinator, retirement_freeze_retains_old_snapshot_and_global_token)
{
	EXPECT_EXIT(
		{
			auto coordinator_or = epoch_transition_coordinator::create(make_topology());
			if (!coordinator_or.is_ok()) {
				std::_Exit(101);
			}
			auto coordinator = std::move(coordinator_or).value();
			if (!bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok()) {
				std::_Exit(102);
			}
			auto candidate_or = make_prepare_candidate(2u);
			if (!candidate_or.is_ok()) {
				std::_Exit(103);
			}
			auto candidate = std::move(candidate_or).value();
			const auto identity = candidate.identity;
			if (!coordinator->admit_prepare(identity, candidate.artifact, 100u).is_ok() ||
			    !coordinator->arm_completion(identity).is_ok() ||
			    !coordinator->mark_prepared(identity, 150u, 500u, 700u).is_ok() ||
			    !coordinator->preflight_begin_commit(identity, 200u).is_ok()) {
				std::_Exit(104);
			}
			coordinator->begin_commit_or_terminate(identity, 200u);
			if (!coordinator->preflight_begin_retiring(identity, 250u).is_ok()) {
				std::_Exit(105);
			}
			coordinator->publish_target_snapshot_or_terminate(identity);
			coordinator->enter_retiring_or_terminate(identity, 250u);
			coordinator->freeze_retirement_or_terminate(identity, 300u, "reader grace timed out");
			epoch_transition_progress_snapshot progress{};
			const auto active = coordinator->query_transaction(identity);
			if (coordinator->try_read_progress(progress) != publication_read_result::AVAILABLE ||
			    !progress.retirement_frozen || !coordinator->retirement_frozen() ||
			    progress.phase != epoch_transition_phase::RETIRING ||
			    coordinator->retained_snapshot_epoch() != BOOTSTRAP_EPOCH || !active.is_ok() ||
			    active.observation.failure_code !=
				    epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED) {
				std::_Exit(106);
			}
			(void)coordinator.release();
			std::_Exit(0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Concurrent readers accept only complete IDLE or PREPARING progress. */
TEST(epoch_transition_coordinator, concurrent_progress_readers_never_observe_torn_state)
{
	auto coordinator_or = epoch_transition_coordinator::create(make_topology());
	ASSERT_TRUE(coordinator_or.is_ok()) << coordinator_or.error().message();
	coordinator_test_owner coordinator(std::move(coordinator_or).value());
	ASSERT_TRUE(bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok());
	auto candidate_or = make_prepare_candidate(2u);
	ASSERT_TRUE(candidate_or.is_ok()) << candidate_or.error().message();
	auto candidate = std::move(candidate_or).value();
	const auto identity = candidate.identity;
	const auto begin_status = coordinator->admit_prepare(identity, candidate.artifact, 100u);
	if (!begin_status.is_ok()) {
		ADD_FAILURE() << static_cast<int32_t>(begin_status.code);
		return;
	}

	std::atomic<bool> reader_ready{false};
	std::atomic<bool> preparing_observed{false};
	std::atomic<bool> abort_completed{false};
	std::atomic<bool> idle_observed{false};
	std::atomic<bool> reader_done{false};
	std::atomic<uint64_t> legal{0};
	std::atomic<uint64_t> illegal{0};
	constexpr std::size_t READ_COUNT = 8192u;
	std::thread reader([&] {
		reader_ready.store(true, std::memory_order_release);
		auto sample = [&] {
			epoch_transition_progress_snapshot progress{};
			const auto read = coordinator->try_read_progress(progress);
			if (read == publication_read_result::UNAVAILABLE) {
				return;
			}
			if (read != publication_read_result::AVAILABLE) {
				illegal.fetch_add(1u, std::memory_order_relaxed);
				return;
			}
			const bool idle = progress.phase == epoch_transition_phase::IDLE &&
					  progress.active_epoch == BOOTSTRAP_EPOCH && progress.target_epoch == 0u &&
					  !progress.participants_frozen &&
					  ((progress.allocated_epoch_high_watermark == BOOTSTRAP_EPOCH &&
					    progress.mutation_sequence_high_watermark == BOOTSTRAP_EPOCH) ||
					   (progress.allocated_epoch_high_watermark == identity.target_epoch &&
					    progress.mutation_sequence_high_watermark == identity.mutation_sequence));
			const bool preparing =
				progress.phase == epoch_transition_phase::PREPARING &&
				progress.active_epoch == BOOTSTRAP_EPOCH && progress.target_epoch == 2u &&
				progress.mutation_sequence == 2u && progress.allocated_epoch_high_watermark == 2u &&
				progress.mutation_sequence_high_watermark == 2u && progress.participants_frozen;
			(idle || preparing ? legal : illegal).fetch_add(1u, std::memory_order_relaxed);
			if (preparing) {
				preparing_observed.store(true, std::memory_order_release);
			}
			if (idle) {
				idle_observed.store(true, std::memory_order_release);
			}
		};
		for (std::size_t read = 0; read < READ_COUNT && !preparing_observed.load(std::memory_order_acquire);
		     ++read) {
			sample();
		}
		while (preparing_observed.load(std::memory_order_acquire) &&
		       !abort_completed.load(std::memory_order_acquire)) {
			sample();
			std::this_thread::yield();
		}
		for (std::size_t read = 0; read < READ_COUNT && !idle_observed.load(std::memory_order_acquire);
		     ++read) {
			sample();
		}
		reader_done.store(true, std::memory_order_release);
	});
	while (!reader_ready.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}
	while (!preparing_observed.load(std::memory_order_acquire) && !reader_done.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}
	const auto abort_status = coordinator->abort_before_commit(
		identity, 200u, epoch_transition_failure_code::EXPLICIT_ABORT, "concurrent observation abort");
	abort_completed.store(true, std::memory_order_release);
	reader.join();
	ASSERT_TRUE(abort_status.is_ok()) << static_cast<int32_t>(abort_status.code);
	EXPECT_TRUE(preparing_observed.load(std::memory_order_relaxed));
	EXPECT_TRUE(idle_observed.load(std::memory_order_relaxed));
	EXPECT_GT(legal.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(illegal.load(std::memory_order_relaxed), 0u);
}

/** @brief FAILED_STOP cannot be recovered or destroyed as an idle coordinator. */
TEST(epoch_transition_coordinator, failed_stop_retains_live_generation_and_fails_stop_on_destruction)
{
	EXPECT_EXIT(
		{
			auto coordinator_or = epoch_transition_coordinator::create(make_topology());
			if (!coordinator_or.is_ok()) {
				std::_Exit(81);
			}
			auto coordinator = std::move(coordinator_or).value();
			if (!bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok()) {
				std::_Exit(82);
			}
			auto candidate_or = make_prepare_candidate(2u);
			if (!candidate_or.is_ok()) {
				std::_Exit(83);
			}
			auto candidate = std::move(candidate_or).value();
			const auto identity = candidate.identity;
			if (!coordinator->admit_prepare(identity, candidate.artifact, 100u).is_ok()) {
				std::_Exit(84);
			}
			coordinator->fail_active_or_terminate(identity, 110u,
							      epoch_transition_failure_code::COMMIT_DEADLINE_EXCEEDED,
							      "phase-inconsistent failure category");
			std::_Exit(85);
		},
		::testing::KilledBySignal(SIGABRT), "");

	EXPECT_EXIT(
		{
			auto coordinator_or = epoch_transition_coordinator::create(make_topology());
			if (!coordinator_or.is_ok()) {
				std::_Exit(61);
			}
			auto coordinator = std::move(coordinator_or).value();
			if (!bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok()) {
				std::_Exit(62);
			}
			auto candidate_or = make_prepare_candidate(2u);
			if (!candidate_or.is_ok()) {
				std::_Exit(63);
			}
			auto candidate = std::move(candidate_or).value();
			const auto identity = candidate.identity;
			if (!coordinator->admit_prepare(identity, candidate.artifact, 100u).is_ok() ||
			    !coordinator->arm_completion(identity).is_ok() ||
			    !coordinator->mark_prepared(identity, 150u, 200u, 300u).is_ok()) {
				std::_Exit(64);
			}
			coordinator->fail_active_or_terminate(identity, 175u,
							      epoch_transition_failure_code::PREPARE_FAILURE,
							      "prepared ownership became unprovable");
			const auto rejected = coordinator->abort_before_commit(
				identity, 175u, epoch_transition_failure_code::EXPLICIT_ABORT,
				"forbidden prepared abort");
			epoch_transition_progress_snapshot progress{};
			if (rejected.is_ok() ||
			    coordinator->try_read_progress(progress) != publication_read_result::AVAILABLE ||
			    progress.phase != epoch_transition_phase::FAILED_STOP ||
			    coordinator->prepared_snapshot_epoch() != identity.target_epoch) {
				std::_Exit(65);
			}
			(void)coordinator.release();
			std::_Exit(0);
		},
		::testing::ExitedWithCode(0), "");

	EXPECT_EXIT(
		{
			auto coordinator_or = epoch_transition_coordinator::create(make_topology());
			if (!coordinator_or.is_ok()) {
				std::_Exit(71);
			}
			auto coordinator = std::move(coordinator_or).value();
			if (!bootstrap(*coordinator, BOOTSTRAP_EPOCH).is_ok()) {
				std::_Exit(70);
			}
			auto candidate_or = make_prepare_candidate(2u);
			if (!candidate_or.is_ok()) {
				std::_Exit(72);
			}
			auto candidate = std::move(candidate_or).value();
			const auto identity = candidate.identity;
			if (!coordinator->admit_prepare(identity, candidate.artifact, 100u).is_ok()) {
				std::_Exit(72);
			}
			coordinator->fail_active_or_terminate(identity, 110u,
							      epoch_transition_failure_code::PREPARE_FAILURE,
							      "preparing ownership became unprovable");
			epoch_transition_progress_snapshot progress{};
			if (coordinator->try_read_progress(progress) != publication_read_result::AVAILABLE ||
			    progress.phase != epoch_transition_phase::FAILED_STOP ||
			    progress.last_terminal_outcome != epoch_transition_outcome::FAILED_STOP ||
			    !progress.participants_frozen || progress.mutation_sequence != identity.mutation_sequence ||
			    progress.allocated_epoch_high_watermark != identity.target_epoch ||
			    progress.mutation_sequence_high_watermark != identity.mutation_sequence) {
				std::_Exit(73);
			}
			auto competing_or = make_prepare_candidate(3u);
			if (!competing_or.is_ok()) {
				std::_Exit(74);
			}
			auto competing = std::move(competing_or).value();
			if (coordinator->admit_prepare(competing.identity, competing.artifact, 110u).is_ok() ||
			    coordinator
				    ->abort_before_commit(identity, 120u, epoch_transition_failure_code::EXPLICIT_ABORT,
							  "forbidden abort")
				    .is_ok()) {
				std::_Exit(74);
			}
			coordinator.reset();
			std::_Exit(75);
		},
		::testing::KilledBySignal(SIGABRT), "");
}

/** @brief Unresolved snapshot ownership is also terminate-class at destruction. */
TEST(epoch_transition_coordinator, unresolved_bootstrap_snapshot_fails_stop_on_destruction)
{
	EXPECT_EXIT(
		{
			auto coordinator_or = epoch_transition_coordinator::create(make_topology());
			if (!coordinator_or.is_ok()) {
				std::_Exit(81);
			}
			auto coordinator = std::move(coordinator_or).value();
			if (!coordinator
				     ->bind_bootstrap_request(
					     BOOTSTRAP_REQUEST_BYTES, std::string(common::SHA256_HEX_LENGTH, 'a'),
					     BOOTSTRAP_EPOCH,
					     common::epoch_transition_watermarks{BOOTSTRAP_EPOCH, BOOTSTRAP_EPOCH})
				     .is_ok()) {
				std::_Exit(82);
			}
			auto artifact_or = make_artifact(BOOTSTRAP_EPOCH);
			if (!artifact_or.is_ok()) {
				std::_Exit(83);
			}
			auto artifact = std::move(artifact_or).value();
			if (!coordinator->stage_bootstrap_snapshot(BOOTSTRAP_EPOCH, artifact).is_ok()) {
				std::_Exit(84);
			}
			if (artifact != nullptr || coordinator->snapshot_store_empty()) {
				std::_Exit(85);
			}
			coordinator.reset();
			std::_Exit(86);
		},
		::testing::KilledBySignal(SIGABRT), "");
}

}  // namespace kinetum::dp
