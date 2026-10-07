// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_runtime_authority_fence.cpp
 * @brief Exact CP-to-DP runtime-content fence tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include "gen/kinetum/telemetry/v1/telemetry.pb.h"
#include "src/cp/runtime_authority_fence.hpp"

namespace kinetum::cp
{
namespace
{

/** Exact durable epoch active before the fixture mutation. */
constexpr uint64_t ACTIVE_EPOCH = 1u;
/** Exact target of the pending durable mutation. */
constexpr uint64_t TARGET_EPOCH = 2u;
/** Mutation identity shared by durable and remote observations. */
constexpr uint64_t MUTATION_SEQUENCE = 2u;

/**
 * @brief Construct one complete durable runtime authority.
 * @return Active E plus one COMPLETION_PENDING E-to-N transition.
 */
durable_runtime_authority_view make_authority()
{
	durable_runtime_authority_view authority;
	authority.active.snapshot_id = "fence.active";
	authority.active.revision = 1;
	authority.active.active_epoch = ACTIVE_EPOCH;
	authority.active.allocated_epoch_high_watermark = TARGET_EPOCH;
	authority.active.mutation_sequence_high_watermark = MUTATION_SEQUENCE;
	authority.active.plan_content_hash.fill(UINT8_C(0x41));
	authority.active.active_validation_hash.fill(UINT8_C(0x42));

	durable_runtime_transition_view transition;
	transition.phase = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING;
	transition.identity.target_epoch = TARGET_EPOCH;
	transition.identity.mutation_sequence = MUTATION_SEQUENCE;
	transition.identity.validation_hash.fill(UINT8_C(0x52));
	transition.identity.idempotency_key_digest.fill(UINT8_C(0x63));
	authority.transition = transition;
	return authority;
}

/**
 * @brief Build telemetry sharing the durable plan and watermarks.
 * @param authority Exact durable source.
 * @return Minimal coherent identity projection for fence classification.
 */
kinetum::telemetry::v1::RuntimeTelemetry make_telemetry(const durable_runtime_authority_view &authority)
{
	kinetum::telemetry::v1::RuntimeTelemetry telemetry;
	telemetry.mutable_runtime()->set_runtime_generation(1u);
	auto *transition = telemetry.mutable_transition();
	transition->set_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE);
	transition->set_allocated_epoch_high_watermark(authority.active.allocated_epoch_high_watermark);
	transition->set_mutation_sequence_high_watermark(authority.active.mutation_sequence_high_watermark);
	transition->set_plan_content_hash(reinterpret_cast<const char *>(authority.active.plan_content_hash.data()),
					  authority.active.plan_content_hash.size());
	return telemetry;
}

/** @brief Stable DP truth must match the last durable COMPLETE content exactly. */
TEST(runtime_authority_fence, stable_active_content_is_exact)
{
	const auto authority = make_authority();
	auto telemetry = make_telemetry(authority);
	const auto hash = authority.active.active_validation_hash;
	telemetry.mutable_transition()->set_active_epoch(ACTIVE_EPOCH);
	telemetry.mutable_transition()->set_active_validation_hash(reinterpret_cast<const char *>(hash.data()),
								   hash.size());
	auto matched_or = classify_runtime_authority(authority, telemetry);
	ASSERT_TRUE(matched_or.is_ok()) << matched_or.error().message();
	EXPECT_EQ(matched_or.value(), runtime_authority_relation::ACTIVE_EXACT);
	telemetry.mutable_transition()->set_active_validation_hash(std::string(32u, '\x43'));
	auto mismatched_or = classify_runtime_authority(authority, telemetry);
	ASSERT_FALSE(mismatched_or.is_ok());
	EXPECT_EQ(mismatched_or.error().code(), kinetum::common::status_code::DATA_LOSS);
}

/** @brief Durable allocation may lead a surviving idle DP by one exact pair. */
TEST(runtime_authority_fence, allocated_identity_admits_only_the_adjacent_preadmission_lag)
{
	auto authority = make_authority();
	authority.transition->phase = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED;
	auto telemetry = make_telemetry(authority);
	telemetry.mutable_transition()->set_allocated_epoch_high_watermark(ACTIVE_EPOCH);
	telemetry.mutable_transition()->set_mutation_sequence_high_watermark(MUTATION_SEQUENCE - 1u);
	telemetry.mutable_transition()->set_active_epoch(ACTIVE_EPOCH);
	telemetry.mutable_transition()->set_active_validation_hash(
		reinterpret_cast<const char *>(authority.active.active_validation_hash.data()),
		authority.active.active_validation_hash.size());

	auto allocated_or = classify_runtime_authority(authority, telemetry);
	ASSERT_TRUE(allocated_or.is_ok()) << allocated_or.error().message();
	EXPECT_EQ(allocated_or.value(), runtime_authority_relation::ACTIVE_EXACT);
	authority.transition->phase = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING;
	auto abort_pending_or = classify_runtime_authority(authority, telemetry);
	ASSERT_TRUE(abort_pending_or.is_ok()) << abort_pending_or.error().message();
	authority.transition->phase = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED;
	auto aborted_or = classify_runtime_authority(authority, telemetry);
	ASSERT_TRUE(aborted_or.is_ok()) << aborted_or.error().message();

	authority.transition->phase = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED;
	auto rejected = classify_runtime_authority(authority, telemetry);
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), kinetum::common::status_code::DATA_LOSS);
	EXPECT_EQ(map_dataplane_response_validation_failure(kinetum::common::status::invalid_argument("remote shape"),
							    "malformed Data Plane test response")
			  .code(),
		  kinetum::common::status_code::DATA_LOSS);
	EXPECT_EQ(map_dataplane_response_validation_failure(
			  kinetum::common::status::resource_exhausted("bounded mapping"),
			  "malformed Data Plane test response")
			  .code(),
		  kinetum::common::status_code::RESOURCE_EXHAUSTED);
	kinetum::common::v1::Status unavailable;
	unavailable.set_code(static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
	unavailable.set_error_code(kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
	EXPECT_EQ(map_dataplane_application_status(unavailable, "remote application failure").code(),
		  kinetum::common::status_code::UNAVAILABLE);
	unavailable.set_code(0);
	EXPECT_EQ(map_dataplane_application_status(unavailable, "remote application failure").code(),
		  kinetum::common::status_code::DATA_LOSS);
	kinetum::common::v1::Status success_residue;
	success_residue.set_error_code(kinetum::common::v1::ERROR_CODE_OK);
	success_residue.set_message("residue");
	EXPECT_EQ(map_dataplane_application_status(success_residue, "remote application failure").code(),
		  kinetum::common::status_code::DATA_LOSS);
}

/** @brief Canonical DP rejection retains its cause separately from the caller's operation context. */
TEST(runtime_authority_fence, application_failure_preserves_bounded_remote_diagnostics)
{
	kinetum::common::v1::Status wire;
	wire.set_code(static_cast<int32_t>(kinetum::common::status_code::FAILED_PRECONDITION));
	wire.set_error_code(kinetum::common::v1::ERROR_CODE_FAILED_PRECONDITION);
	wire.set_message("worker is not running on its compiled CPU");
	wire.set_details("worker=2");
	const auto failure = map_dataplane_application_status(wire, "bootstrap rejected");
	EXPECT_EQ(failure.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(failure.message(), "bootstrap rejected");
	EXPECT_EQ(failure.details(), "worker is not running on its compiled CPU: worker=2");

	wire.set_message(std::string(1024u, 'm'));
	wire.set_details(std::string(1024u, 'd'));
	const auto bounded = map_dataplane_application_status(wire, "bootstrap rejected");
	EXPECT_EQ(bounded.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(bounded.details(), std::string(512u, 'm') + ": " + std::string(512u, 'd'));

	wire.clear_message();
	const auto details_only = map_dataplane_application_status(wire, "bootstrap rejected");
	EXPECT_EQ(details_only.details(), std::string(512u, 'd'));
	wire.clear_details();
	const auto empty = map_dataplane_application_status(wire, "bootstrap rejected");
	EXPECT_EQ(empty.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_TRUE(empty.details().empty());
}

/** @brief Reply loss may leave DP target COMPLETE before CP's atomic promotion. */
TEST(runtime_authority_fence, completion_pending_admits_one_exact_target_complete_window)
{
	const auto authority = make_authority();
	auto telemetry = make_telemetry(authority);
	auto *transition = telemetry.mutable_transition();
	transition->set_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE);
	transition->set_active_epoch(TARGET_EPOCH);
	transition->set_terminal_history_size(1u);
	transition->set_active_validation_hash(
		reinterpret_cast<const char *>(authority.transition->identity.validation_hash.data()),
		authority.transition->identity.validation_hash.size());
	auto *terminal = transition->mutable_latest_terminal();
	terminal->set_mutation_sequence(MUTATION_SEQUENCE);
	terminal->set_from_epoch(ACTIVE_EPOCH);
	terminal->set_to_epoch(TARGET_EPOCH);
	terminal->set_validation_hash(
		reinterpret_cast<const char *>(authority.transition->identity.validation_hash.data()),
		authority.transition->identity.validation_hash.size());
	terminal->set_idempotency_key_digest(
		reinterpret_cast<const char *>(authority.transition->identity.idempotency_key_digest.data()),
		authority.transition->identity.idempotency_key_digest.size());
	terminal->set_outcome(kinetum::telemetry::v1::EPOCH_TRANSITION_OUTCOME_COMPLETE);
	terminal->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);

	auto matched_or = classify_runtime_authority(authority, telemetry);
	ASSERT_TRUE(matched_or.is_ok()) << matched_or.error().message();
	EXPECT_EQ(matched_or.value(), runtime_authority_relation::TARGET_COMPLETE_EXACT);
}

/** @brief Target completion never admits a wrong mutation or key digest. */
TEST(runtime_authority_fence, target_complete_identity_disagreement_is_data_loss)
{
	const auto authority = make_authority();
	auto telemetry = make_telemetry(authority);
	auto *transition = telemetry.mutable_transition();
	transition->set_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE);
	transition->set_active_epoch(TARGET_EPOCH);
	transition->set_terminal_history_size(1u);
	transition->set_active_validation_hash(
		reinterpret_cast<const char *>(authority.transition->identity.validation_hash.data()),
		authority.transition->identity.validation_hash.size());
	auto *terminal = transition->mutable_latest_terminal();
	terminal->set_mutation_sequence(MUTATION_SEQUENCE);
	terminal->set_from_epoch(ACTIVE_EPOCH);
	terminal->set_to_epoch(TARGET_EPOCH);
	terminal->set_validation_hash(transition->active_validation_hash());
	terminal->set_idempotency_key_digest(std::string(32u, '\x7f'));
	terminal->set_outcome(kinetum::telemetry::v1::EPOCH_TRANSITION_OUTCOME_COMPLETE);
	terminal->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);

	auto rejected = classify_runtime_authority(authority, telemetry);
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), kinetum::common::status_code::DATA_LOSS);
}

/** @brief The active fence ignores phase-only movement but catches active-head movement. */
TEST(runtime_authority_fence, active_fence_compares_the_complete_bootstrap_authority_only)
{
	const auto before = make_authority();
	auto phase_only = before;
	phase_only.transition->phase = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE;
	EXPECT_TRUE(same_active_runtime_authority(before, phase_only));

	auto changed = before;
	changed.active.snapshot_id.push_back('x');
	EXPECT_FALSE(same_active_runtime_authority(before, changed));
	changed = before;
	++changed.active.revision;
	EXPECT_FALSE(same_active_runtime_authority(before, changed));
	changed = before;
	changed.active.active_epoch = TARGET_EPOCH;
	EXPECT_FALSE(same_active_runtime_authority(before, changed));
	changed = before;
	++changed.active.allocated_epoch_high_watermark;
	EXPECT_FALSE(same_active_runtime_authority(before, changed));
	changed = before;
	++changed.active.mutation_sequence_high_watermark;
	EXPECT_FALSE(same_active_runtime_authority(before, changed));
	changed = before;
	changed.active.plan_content_hash.front() ^= UINT8_C(1);
	EXPECT_FALSE(same_active_runtime_authority(before, changed));
	changed = before;
	changed.active.active_validation_hash.front() ^= UINT8_C(1);
	EXPECT_FALSE(same_active_runtime_authority(before, changed));
}

}  // namespace
}  // namespace kinetum::cp
