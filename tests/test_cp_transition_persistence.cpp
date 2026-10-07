// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_cp_transition_persistence.cpp
 * @brief Exact CP allocation, durable phase, and restart reconciliation tests.
 * @author Fleming Patel
 *
 * This suite proves the durable CP transition authority together with the live
 * typed DP boundary. It exercises the production store and reconciliation
 * surfaces consumed by the complete transition protocol; there is no test-only
 * state-machine API.
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/unknown_field_set.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gen/kinetum/control/internal/v1/transition_authority.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/control_plane_contract.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/version.hpp"
#include "src/cp/config_store.hpp"
#include "src/cp/control_loop.hpp"
#include "src/cp/cp_grpc.hpp"
#include "src/cp/dataplane_bootstrap.hpp"
#include "src/cp/transition_reconciliation.hpp"
#include "tests/test_grpc_helpers.hpp"
#include "tests/log_test_support.hpp"

namespace kinetum::cp
{
namespace
{

/** @brief Private durable authority schema inspected by these tests. */
using authority_message = kinetum::control::internal::v1::ControlPlaneTransitionAuthority;
/** @brief Durable phases used by persistence and reconciliation assertions. */
using durable_phase = kinetum::control::internal::v1::DurableEpochTransitionPhase;
using kinetum::common::status;
using kinetum::common::status_or;

/** @brief Process-local sequence for unique durable roots. */
std::atomic<uint64_t> TRANSITION_TEST_SEQUENCE{0u};

/**
 * @brief Write exact file bytes with the durable-store file mode.
 * @param path Exact fixture-owned file path.
 * @param bytes Complete file content.
 * @return true only after successful close and mode 0600.
 */
bool write_owned_file(const std::filesystem::path &path, std::string_view bytes)
{
	std::ofstream output(path, std::ios::binary | std::ios::trunc);
	if (!output) {
		return false;
	}
	output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
	output.close();
	return output.good() && ::chmod(path.c_str(), static_cast<mode_t>(0600)) == 0;
}

/**
 * @brief Read one complete fixture-owned file.
 * @param path Exact file path.
 * @return Complete bytes, or empty when opening fails.
 */
std::string read_file(const std::filesystem::path &path)
{
	std::ifstream input(path, std::ios::binary);
	return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

/**
 * @brief Build one module-free candidate without precomputed hash claims.
 * @param id Exact semantic snapshot identity.
 * @param revision Exact CP revision.
 * @param description Optional content difference.
 * @return Complete unhashed candidate.
 */
kinetum::control::v1::ConfigSnapshot make_candidate(std::string id, int64_t revision, std::string description = {})
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	snapshot.set_snapshot_id(std::move(id));
	snapshot.set_revision(revision);
	snapshot.set_created_unix_ms(1'000 + revision);
	snapshot.set_description(std::move(description));
	return snapshot;
}

/**
 * @brief Build one terminal module-free bootstrap authority.
 * @param id Exact bootstrap snapshot identity.
 * @param revision Exact bootstrap revision.
 * @return Canonical authority or shared canonicalization failure.
 */
status_or<bootstrap_startup_authority> make_authority(std::string id = "bootstrap", int64_t revision = 1)
{
	auto snapshot = make_candidate(std::move(id), revision);
	kinetum::gluon::v1::DeploymentPlan module_free_plan;
	auto canonical_or = kinetum::common::canonicalize_config_snapshot(snapshot, module_free_plan);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	bootstrap_startup_authority authority;
	authority.snapshot = std::move(canonical_or).value();
	authority.plan_content_hash_bytes.fill(0x5au);
	authority.plan_content_hash = kinetum::common::bytes_to_hex(authority.plan_content_hash_bytes.data(),
								    authority.plan_content_hash_bytes.size());
	return authority;
}

/**
 * @brief Reconstruct one fixed identity from a durable transition view.
 * @param view Exact admitted durable transition projection.
 * @return Fixed identity or terminal-snapshot/key admission failure.
 */
status_or<kinetum::common::epoch_transition_identity> transition_identity(const durable_epoch_transition_view &view)
{
	auto canonical_or = kinetum::common::canonical_config_snapshot_from_terminal(view.prepare_request.snapshot());
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	return kinetum::common::make_epoch_transition_identity(
		view.prepare_request.mutation_sequence(), view.prepare_request.target_epoch(),
		std::string_view(reinterpret_cast<const char *>(canonical_or->validation_hash.data()),
				 canonical_or->validation_hash.size()),
		view.prepare_request.idempotency_key());
}

/**
 * @brief Build one complete enabled threshold policy for persistence tests.
 * @return Exact no-default policy with bounded cadence, history, and attribution.
 */
kinetum::control::v1::GuardrailsPolicy make_guardrails_policy()
{
	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(true);
	policy.set_poll_interval_ms(100u);
	policy.set_evaluation_window_ms(1'000u);
	policy.set_telemetry_history_capacity(16u);
	policy.mutable_threshold()->set_max_drop_ratio(0.05);
	policy.mutable_threshold()->set_min_tx_ratio(0.70);
	policy.mutable_threshold()->set_min_packets_per_window(1u);
	policy.mutable_attribution()->set_auto_rollback_threshold(0.80);
	policy.mutable_attribution()->set_defer_threshold(0.50);
	policy.mutable_attribution()->set_baseline_samples(2u);
	policy.mutable_attribution()->set_degradation_threshold(0.30);
	return policy;
}

/** @brief Fake DP that returns one exact successful Bootstrap echo. */
class successful_bootstrap_service final : public kinetum::dataplane::v1::DataplaneService::Service {
    public:
	/**
	 * @brief Report exact CONTROL_READY before the one Bootstrap request.
	 * @param context Borrowed server context; unused.
	 * @param request Empty request; unused.
	 * @param response Destination for canonical success and readiness.
	 * @return Transport-level OK.
	 */
	grpc::Status Health(grpc::ServerContext *context, const kinetum::dataplane::v1::HealthRequest *request,
			    kinetum::dataplane::v1::HealthResponse *response) override
	{
		(void)context;
		(void)request;
		response->Clear();
		response->set_state(kinetum::dataplane::v1::HealthResponse::STATE_CONTROL_READY);
		response->mutable_status()->set_code(0);
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		response->set_version(kinetum::common::KINETUM_VERSION_STRING);
		auto *logging = response->mutable_logging();
		logging->set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_AVAILABLE);
		logging->set_accepted_records(0);
		logging->set_queue_rejections(0);
		logging->set_format_rejections(0);
		logging->set_unavailable_rejections(0);
		logging->set_undelivered_records(0);
		logging->set_write_failures(0);
		logging->set_console_failures(0);
		logging->set_truncated_records(0);
		logging->set_packet_thread_rejections(0);
		logging->set_delivery_timeouts(0);
		response->set_runtime_generation(1u);
		response->set_expected_workers(1u);
		return grpc::Status::OK;
	}

	/**
	 * @brief Return exact success for the received canonical request.
	 * @param context Borrowed server context; unused.
	 * @param request Exact Bootstrap request to echo.
	 * @param response Destination for complete success evidence.
	 * @return Transport-level OK; application status carries local failures.
	 */
	grpc::Status BootstrapConfigSnapshot(grpc::ServerContext *context,
					     const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest *request,
					     kinetum::dataplane::v1::BootstrapConfigSnapshotResponse *response) override
	{
		(void)context;
		++calls;
		auto hash_or = kinetum::common::hex_to_bytes(request->snapshot().content_hash());
		if (!hash_or.is_ok()) {
			response->mutable_status()->set_code(
				static_cast<int32_t>(kinetum::common::status_code::INVALID_ARGUMENT));
			return grpc::Status::OK;
		}
		response->mutable_status()->set_code(0);
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		response->set_restored_epoch(request->active_epoch());
		response->set_validation_hash(reinterpret_cast<const char *>(hash_or->data()), hash_or->size());
		response->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
		response->set_allocated_epoch_high_watermark(request->allocated_epoch_high_watermark());
		response->set_mutation_sequence_high_watermark(request->mutation_sequence_high_watermark());
		return grpc::Status::OK;
	}

	std::atomic<uint32_t> calls{0u};  ///< Exact Bootstrap call count.
};

/** @brief Fixture owning one exact private durable root. */
class CpTransitionPersistenceTest : public ::testing::Test {
    protected:
	/** @brief Select one unique absent root. */
	void SetUp() override
	{
		const uint64_t sequence = TRANSITION_TEST_SEQUENCE.fetch_add(1u, std::memory_order_relaxed) + 1u;
		root_ = std::filesystem::temp_directory_path() /
			("kinetum_cp_transition_" + std::to_string(static_cast<uint64_t>(::getpid())) + "_" +
			 std::to_string(sequence));
	}

	/** @brief Remove fixture-owned storage without throwing. */
	void TearDown() override
	{
		std::error_code error;
		std::filesystem::remove_all(root_, error);
	}

	/** @return Fresh store with one exact active bootstrap. */
	std::unique_ptr<config_store> open_bootstrapped_store()
	{
		auto authority_or = make_authority();
		if (!authority_or.is_ok()) {
			ADD_FAILURE() << authority_or.error().message();
			return nullptr;
		}
		auto store_or = config_store::open(root_);
		if (!store_or.is_ok()) {
			ADD_FAILURE() << store_or.error().message();
			return nullptr;
		}
		auto store = std::move(store_or).value();
		const auto reconcile_status = store->reconcile_bootstrap(&authority_or.value());
		if (!reconcile_status.is_ok()) {
			ADD_FAILURE() << reconcile_status.message();
			return nullptr;
		}
		return store;
	}

	std::filesystem::path root_;  ///< Exact fixture-owned durable root.
};

/** @brief Cold logs distinguish refusals, ambiguous replies, durable completion, and exact replay. */
TEST_F(CpTransitionPersistenceTest, mutation_logs_follow_durable_outcomes)
{
	kinetum::test_support::log_stderr_capture capture;
	ASSERT_TRUE(capture.valid());
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	kinetum::test::fake_dp_server server;
	server.service.complete_transitions = true;
	server.service.transition_plan_content_hash = active_or->plan_content_hash();
	server.service.fail_next_activate_transport_after_commit = true;
	server.start();
	{
		control_loop loop(store.get(), server.stub);
		control_service_impl service(store.get(), server.stub, loop);
		kinetum::control::v1::SetConfigSnapshotRequest request;
		request.mutable_snapshot()->CopyFrom(make_candidate("logging-target", 2));
		request.set_idempotency_key("logging-key");
		request.set_expected_revision(1);
		kinetum::control::v1::SetConfigSnapshotResponse response;
		EXPECT_TRUE(service.SetConfigSnapshot(nullptr, &request, &response).ok());
		EXPECT_EQ(response.status().code(), static_cast<int32_t>(common::status_code::UNAVAILABLE));
		ASSERT_TRUE(loop.start().is_ok());
		auto invalid = request;
		invalid.clear_idempotency_key();
		EXPECT_TRUE(service.SetConfigSnapshot(nullptr, &invalid, &response).ok());
		EXPECT_EQ(response.status().code(), static_cast<int32_t>(common::status_code::INVALID_ARGUMENT));
		ASSERT_TRUE(service.SetConfigSnapshot(nullptr, &request, &response).ok());
		ASSERT_EQ(response.status().code(), 0) << response.status().message();
		EXPECT_EQ(response.snapshot_id(), "logging-target");
		EXPECT_EQ(response.epoch(), 2u);
		ASSERT_TRUE(service.SetConfigSnapshot(nullptr, &request, &response).ok());
		EXPECT_EQ(response.status().code(), 0) << response.status().message();
		EXPECT_EQ(server.service.prepare_calls.load(std::memory_order_relaxed), 1);
		EXPECT_EQ(server.service.activate_calls.load(std::memory_order_relaxed), 1);
		request.mutable_snapshot()->CopyFrom(make_candidate("logging-rejected", 3));
		request.set_idempotency_key("stale-revision-key");
		EXPECT_TRUE(service.SetConfigSnapshot(nullptr, &request, &response).ok());
		EXPECT_EQ(response.status().code(), static_cast<int32_t>(common::status_code::FAILED_PRECONDITION));
		loop.stop();
	}
	server.shutdown();
	auto completed_or = store->epoch_transition();
	ASSERT_TRUE(completed_or.is_ok());
	EXPECT_EQ(completed_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE);
	auto completed_active_or = store->active_bootstrap();
	ASSERT_TRUE(completed_active_or.is_ok());
	EXPECT_EQ(completed_active_or->snapshot().snapshot_id(), "logging-target");
	EXPECT_EQ(completed_active_or->active_epoch(), 2u);
	std::string output;
	ASSERT_TRUE(capture.finish(output));
	EXPECT_NE(output.find("operation=SetConfigSnapshot snapshot=logging-target status=UNAVAILABLE"),
		  std::string::npos);
	EXPECT_NE(output.find("operation=SetConfigSnapshot snapshot=logging-target status=INVALID_ARGUMENT"),
		  std::string::npos);
	EXPECT_NE(output.find("cp.transition.reply_ambiguous"), std::string::npos) << output;
	EXPECT_NE(output.find("snapshot=logging-target revision=2 mutation_sequence=2 epoch=2"), std::string::npos)
		<< output;
	EXPECT_NE(output.find("operation=SetConfigSnapshot snapshot=logging-rejected status=FAILED_PRECONDITION"),
		  std::string::npos);
	const auto applied = output.find(" cp.snapshot.applied ");
	ASSERT_NE(applied, std::string::npos) << output;
	EXPECT_EQ(output.find(" cp.snapshot.applied ", applied + 1u), std::string::npos) << output;
	EXPECT_EQ(output.find(" cp.transition.failed "), std::string::npos) << output;
}

/** @brief A refused DP transition records its phase and never reports the candidate as applied. */
TEST_F(CpTransitionPersistenceTest, failed_transition_logs_preserve_active_snapshot)
{
	kinetum::test_support::log_stderr_capture capture;
	ASSERT_TRUE(capture.valid());
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	kinetum::test::fake_dp_server server;
	server.start();
	{
		control_loop loop(store.get(), server.stub);
		ASSERT_TRUE(loop.start().is_ok());
		control_service_impl service(store.get(), server.stub, loop);
		kinetum::control::v1::SetConfigSnapshotRequest request;
		request.mutable_snapshot()->CopyFrom(make_candidate("logging-failed", 2));
		request.set_idempotency_key("logging-failed-key");
		request.set_expected_revision(1);
		kinetum::control::v1::SetConfigSnapshotResponse response;
		EXPECT_TRUE(service.SetConfigSnapshot(nullptr, &request, &response).ok());
		EXPECT_EQ(response.status().code(), static_cast<int32_t>(common::status_code::UNAVAILABLE));
		loop.stop();
	}
	server.shutdown();
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	EXPECT_EQ(active_or->snapshot().snapshot_id(), "bootstrap");
	EXPECT_EQ(active_or->active_epoch(), 1u);
	std::string output;
	ASSERT_TRUE(capture.finish(output));
	EXPECT_NE(output.find(" [ERROR] "), std::string::npos) << output;
	EXPECT_NE(output.find(" cp.transition.failed "), std::string::npos) << output;
	EXPECT_NE(
		output.find(
			"snapshot=logging-failed mutation_sequence=2 target_epoch=2 cp_phase=ALLOCATED status=UNAVAILABLE"),
		std::string::npos)
		<< output;
	EXPECT_EQ(output.find(" cp.snapshot.applied "), std::string::npos) << output;
}

/** @brief Pin the complete private persistence schema and prove it has no service. */
TEST(cp_transition_persistence_schema, exact_private_messages_and_phases_are_compact)
{
	using google::protobuf::FieldDescriptor;
	const auto *authority = authority_message::descriptor();
	ASSERT_NE(authority, nullptr);
	ASSERT_EQ(authority->field_count(), 5);
	EXPECT_EQ(authority->field(0)->name(), "active_bootstrap");
	EXPECT_EQ(authority->field(0)->number(), 1);
	EXPECT_EQ(authority->field(0)->type(), FieldDescriptor::TYPE_MESSAGE);
	EXPECT_EQ(authority->field(1)->name(), "transition");
	EXPECT_EQ(authority->field(1)->number(), 2);
	EXPECT_EQ(authority->field(2)->name(), "pending_confirm");
	EXPECT_EQ(authority->field(2)->number(), 3);
	EXPECT_EQ(authority->field(3)->name(), "guardrails_policy");
	EXPECT_EQ(authority->field(3)->number(), 4);
	EXPECT_EQ(authority->field(4)->name(), "rollback_intent");
	EXPECT_EQ(authority->field(4)->number(), 5);
	EXPECT_EQ(authority->reserved_range_count(), 0);
	EXPECT_EQ(authority->reserved_name_count(), 0);
	EXPECT_EQ(authority->file()->package(), "kinetum.control.internal.v1");
	EXPECT_EQ(authority->file()->service_count(), 0);

	const auto *transition = kinetum::control::internal::v1::DurableEpochTransition::descriptor();
	ASSERT_NE(transition, nullptr);
	ASSERT_EQ(transition->field_count(), 9);
	constexpr std::array<const char *, 9> FIELD_NAMES{
		"snapshot_id",	   "target_epoch",	 "mutation_sequence",
		"idempotency_key", "validation_hash",	 "idempotency_key_digest",
		"phase",	   "confirm_timeout_ms", "terminal_status"};
	for (int index = 0; index < transition->field_count(); ++index) {
		EXPECT_EQ(transition->field(index)->name(), FIELD_NAMES[static_cast<std::size_t>(index)]);
		EXPECT_EQ(transition->field(index)->number(), index + 1);
	}

	const auto *phase = kinetum::control::internal::v1::DurableEpochTransitionPhase_descriptor();
	ASSERT_NE(phase, nullptr);
	ASSERT_EQ(phase->value_count(), 7);
	EXPECT_EQ(phase->value(0)->number(), 0);
	EXPECT_EQ(phase->value(6)->number(), 6);

	const auto *policy = kinetum::control::internal::v1::DurableGuardrailsPolicy::descriptor();
	ASSERT_NE(policy, nullptr);
	ASSERT_EQ(policy->field_count(), 4);
	EXPECT_EQ(policy->field(0)->name(), "policy");
	EXPECT_EQ(policy->field(1)->name(), "generation");
	EXPECT_EQ(policy->field(2)->name(), "policy_hash");
	EXPECT_EQ(policy->field(3)->name(), "idempotency_key_digest");
	EXPECT_TRUE(policy->field(0)->has_presence());
	for (int index = 0; index < policy->field_count(); ++index) {
		EXPECT_EQ(policy->field(index)->number(), index + 1);
	}

	const auto *intent = kinetum::control::internal::v1::DurableRollbackIntent::descriptor();
	ASSERT_NE(intent, nullptr);
	ASSERT_EQ(intent->field_count(), 14);
	constexpr std::array<const char *, 14> INTENT_FIELD_NAMES{"target_snapshot_id",
								  "guarded_snapshot_id",
								  "guarded_epoch",
								  "guarded_revision",
								  "guarded_validation_hash",
								  "wait_for_mutation_sequence",
								  "policy_generation",
								  "runtime_generation",
								  "idempotency_key",
								  "idempotency_key_digest",
								  "cause",
								  "observed_monotonic_ns",
								  "created_unix_ms",
								  "terminal_status"};
	for (int index = 0; index < intent->field_count(); ++index) {
		EXPECT_EQ(intent->field(index)->name(), INTENT_FIELD_NAMES[static_cast<std::size_t>(index)]);
		EXPECT_EQ(intent->field(index)->number(), index + 1);
	}
	const auto *cause = kinetum::control::internal::v1::DurableRollbackCause_descriptor();
	ASSERT_NE(cause, nullptr);
	EXPECT_EQ(cause->value_count(), 5);
	for (int index = 0; index < cause->value_count(); ++index) {
		EXPECT_EQ(cause->value(index)->number(), index);
	}
}

/** @brief Prove exact allocation, retry, conflict, and no-rewrite behavior. */
TEST_F(CpTransitionPersistenceTest, allocation_is_atomic_exact_and_idempotent)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	const auto candidate = make_candidate("candidate", 2);
	const std::string initial_authority = read_file(root_ / "TRANSITION_AUTHORITY.pb");
	constexpr std::array<std::string_view, 2> MALFORMED_KEYS{"", std::string_view("\x1f", 1u)};
	for (const auto key : MALFORMED_KEYS) {
		auto malformed_or = store->begin_epoch_transition(candidate, key, 0u);
		ASSERT_FALSE(malformed_or.is_ok());
		EXPECT_EQ(malformed_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	}
	auto oversized_key_or = store->begin_epoch_transition(
		candidate, std::string(kinetum::common::MAX_TRANSITION_IDEMPOTENCY_KEY_BYTES + 1u, 'x'), 0u);
	ASSERT_FALSE(oversized_key_or.is_ok());
	EXPECT_EQ(oversized_key_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(read_file(root_ / "TRANSITION_AUTHORITY.pb"), initial_authority);
	EXPECT_FALSE(store->load_snapshot("candidate").is_ok());

	auto first_or = store->begin_epoch_transition(candidate, "transition-key", 0u);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	EXPECT_FALSE(first_or->exact_retry);
	EXPECT_EQ(first_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED);
	EXPECT_EQ(first_or->prepare_request.target_epoch(), 2u);
	EXPECT_EQ(first_or->prepare_request.mutation_sequence(), 2u);
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	EXPECT_EQ(active_or->active_epoch(), 1u);
	EXPECT_EQ(active_or->allocated_epoch_high_watermark(), 2u);
	EXPECT_EQ(active_or->mutation_sequence_high_watermark(), 2u);

	const auto authority_path = root_ / "TRANSITION_AUTHORITY.pb";
	struct stat before{};
	ASSERT_EQ(::stat(authority_path.c_str(), &before), 0);
	auto retry_or = store->begin_epoch_transition(candidate, "transition-key", 0u);
	ASSERT_TRUE(retry_or.is_ok()) << retry_or.error().message();
	EXPECT_TRUE(retry_or->exact_retry);
	struct stat after{};
	ASSERT_EQ(::stat(authority_path.c_str(), &after), 0);
	EXPECT_EQ(after.st_ino, before.st_ino);
	EXPECT_EQ(after.st_mtim.tv_sec, before.st_mtim.tv_sec);
	EXPECT_EQ(after.st_mtim.tv_nsec, before.st_mtim.tv_nsec);

	const auto conflicting = make_candidate("candidate", 2, "different canonical content");
	auto conflict_or = store->begin_epoch_transition(conflicting, "transition-key", 0u);
	ASSERT_FALSE(conflict_or.is_ok());
	EXPECT_EQ(conflict_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	auto overlap_or = store->begin_epoch_transition(make_candidate("other", 3), "other-key", 0u);
	ASSERT_FALSE(overlap_or.is_ok());
	EXPECT_EQ(overlap_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
}

/** @brief Prove all six phases, legal edges, completion, and aborted-value gaps. */
TEST_F(CpTransitionPersistenceTest, phase_edges_and_terminal_publication_are_exact)
{
	constexpr auto LOCAL_ABORT = durable_abort_proof::LOCAL_PRECOMMIT_INTENT;
	constexpr auto DP_ABORT = durable_abort_proof::EXACT_DP_PRECOMMIT_TERMINAL;
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	auto first_or = store->begin_epoch_transition(make_candidate("complete", 2), "complete-key", 0u);
	ASSERT_TRUE(first_or.is_ok());
	auto first_identity_or = transition_identity(first_or.value());
	ASSERT_TRUE(first_identity_or.is_ok());
	EXPECT_EQ(store->advance_epoch_transition_phase(
			       first_identity_or.value(),
			       kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			  .code(),
		  kinetum::common::status_code::FAILED_PRECONDITION);
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 first_identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 first_identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 first_identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	ASSERT_TRUE(store->complete_epoch_transition(first_identity_or.value(), 20'000).is_ok());
	EXPECT_TRUE(store->complete_epoch_transition(first_identity_or.value(), 20'001).is_ok());
	EXPECT_EQ(store->abort_epoch_transition(first_identity_or.value(), status::aborted("too late"), LOCAL_ABORT)
			  .code(),
		  kinetum::common::status_code::FAILED_PRECONDITION);
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	EXPECT_EQ(active_or->snapshot().snapshot_id(), "complete");
	EXPECT_EQ(active_or->active_epoch(), 2u);
	auto terminal_or = store->epoch_transition();
	ASSERT_TRUE(terminal_or.is_ok());
	EXPECT_EQ(terminal_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE);
	{
		control_loop loop(store.get(), nullptr);
		ASSERT_TRUE(loop.start().is_ok());
		mutation retry("complete-key", std::optional<int64_t>{1},
			       set_config_payload{make_candidate("complete", 2), 0u});
		const auto retry_result = loop.submit(std::move(retry));
		EXPECT_TRUE(retry_result.ok()) << retry_result.status.message();
		EXPECT_EQ(retry_result.epoch, 2u);
		mutation conflict("complete-key", std::optional<int64_t>{1},
				  set_config_payload{make_candidate("complete", 2, "different canonical content"), 0u});
		const auto conflict_result = loop.submit(std::move(conflict));
		EXPECT_EQ(conflict_result.status.code(), kinetum::common::status_code::FAILED_PRECONDITION);
		loop.stop();
	}

	auto second_or = store->begin_epoch_transition(make_candidate("aborted", 3), "abort-key", 0u);
	ASSERT_TRUE(second_or.is_ok());
	EXPECT_EQ(second_or->prepare_request.target_epoch(), 3u);
	EXPECT_EQ(second_or->prepare_request.mutation_sequence(), 3u);
	auto second_identity_or = transition_identity(second_or.value());
	ASSERT_TRUE(second_identity_or.is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 second_identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING)
			    .is_ok());
	const std::string oversized(kinetum::common::MAX_TRANSITION_DIAGNOSTIC_BYTES + 1u, 'x');
	EXPECT_EQ(store->abort_epoch_transition(second_identity_or.value(), status::aborted(oversized), LOCAL_ABORT)
			  .code(),
		  kinetum::common::status_code::RESOURCE_EXHAUSTED);
	ASSERT_TRUE(
		store->abort_epoch_transition(second_identity_or.value(), status::aborted("exact abort"), LOCAL_ABORT)
			.is_ok());
	EXPECT_TRUE(
		store->abort_epoch_transition(second_identity_or.value(), status::aborted("exact abort"), LOCAL_ABORT)
			.is_ok());
	EXPECT_EQ(store->abort_epoch_transition(second_identity_or.value(), status::aborted("different abort"),
						LOCAL_ABORT)
			  .code(),
		  kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(store->abort_epoch_transition(second_identity_or.value(), status::aborted(oversized), LOCAL_ABORT)
			  .code(),
		  kinetum::common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(store->abort_epoch_transition(second_identity_or.value(),
						status(kinetum::common::status_code::ABORTED, "exact abort",
						       "unretained details"),
						LOCAL_ABORT)
			  .code(),
		  kinetum::common::status_code::INVALID_ARGUMENT);
	auto aborted_or = store->epoch_transition();
	ASSERT_TRUE(aborted_or.is_ok());
	EXPECT_EQ(aborted_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED);
	EXPECT_EQ(store->active_snapshot_id().value(), "complete");
	auto retry_or = store->begin_epoch_transition(make_candidate("aborted", 3), "abort-key", 0u);
	ASSERT_TRUE(retry_or.is_ok());
	EXPECT_TRUE(retry_or->exact_retry);
	EXPECT_EQ(retry_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED);

	auto third_or = store->begin_epoch_transition(make_candidate("later", 4), "later-key", 0u);
	ASSERT_TRUE(third_or.is_ok());
	EXPECT_EQ(third_or->prepare_request.target_epoch(), 4u);
	EXPECT_EQ(third_or->prepare_request.mutation_sequence(), 4u);
	auto third_identity_or = transition_identity(third_or.value());
	ASSERT_TRUE(third_identity_or.is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 third_identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 third_identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	EXPECT_EQ(store->abort_epoch_transition(third_identity_or.value(),
						status(kinetum::common::status_code::MODULE_ERROR,
						       "prepared module failure"),
						static_cast<durable_abort_proof>(UINT8_C(2)))
			  .code(),
		  kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(store->abort_epoch_transition(third_identity_or.value(),
						status(kinetum::common::status_code::MODULE_ERROR,
						       "prepared module failure"),
						LOCAL_ABORT)
			  .code(),
		  kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_TRUE(store->abort_epoch_transition(third_identity_or.value(),
						  status(kinetum::common::status_code::MODULE_ERROR,
							 "prepared module failure"),
						  DP_ABORT)
			    .is_ok());
	auto third_terminal_or = store->epoch_transition();
	ASSERT_TRUE(third_terminal_or.is_ok());
	EXPECT_EQ(third_terminal_or->terminal_status.code(),
		  static_cast<int32_t>(kinetum::common::status_code::MODULE_ERROR));
	EXPECT_EQ(third_terminal_or->terminal_status.error_code(), kinetum::common::v1::ERROR_CODE_INTERNAL);
	{
		control_loop loop(store.get(), nullptr);
		ASSERT_TRUE(loop.start().is_ok());
		mutation retry("later-key", std::optional<int64_t>{2},
			       set_config_payload{make_candidate("later", 4), 0u});
		const auto retry_result = loop.submit(std::move(retry));
		EXPECT_EQ(retry_result.status.code(), kinetum::common::status_code::MODULE_ERROR);
		EXPECT_EQ(retry_result.status.message(), "prepared module failure");
		loop.stop();
	}
}

/** @brief Prove each allocator rejects before corpus or authority mutation at wrap. */
TEST_F(CpTransitionPersistenceTest, approach_to_wrap_rejects_without_any_side_effect)
{
	constexpr std::array<std::pair<uint64_t, uint64_t>, 2> WATERMARKS{{
		{kinetum::common::MAX_EPOCH_ID, 1u},
		{1u, kinetum::common::MAX_MUTATION_SEQUENCE},
	}};
	for (const auto &[epoch_watermark, mutation_watermark] : WATERMARKS) {
		std::error_code error;
		std::filesystem::remove_all(root_, error);
		ASSERT_FALSE(error);
		auto store = open_bootstrapped_store();
		ASSERT_NE(store, nullptr);
		store.reset();

		authority_message authority;
		ASSERT_TRUE(authority.ParseFromString(read_file(root_ / "TRANSITION_AUTHORITY.pb")));
		auto *active = authority.mutable_active_bootstrap();
		active->set_allocated_epoch_high_watermark(epoch_watermark);
		active->set_mutation_sequence_high_watermark(mutation_watermark);
		auto canonical_or = kinetum::common::canonical_config_snapshot_from_terminal(active->snapshot());
		ASSERT_TRUE(canonical_or.is_ok());
		auto plan_hash_or =
			kinetum::common::decode_sha256_digest_claim(active->plan_content_hash(), "plan_content_hash");
		ASSERT_TRUE(plan_hash_or.is_ok());
		auto key_or = kinetum::common::derive_bootstrap_config_snapshot_idempotency_key(
			canonical_or->validation_hash, plan_hash_or.value(), active->active_epoch(), epoch_watermark,
			mutation_watermark);
		ASSERT_TRUE(key_or.is_ok());
		active->set_idempotency_key(std::move(key_or).value());
		auto bytes_or = kinetum::common::serialize_protobuf_deterministically(authority);
		ASSERT_TRUE(bytes_or.is_ok());
		ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", bytes_or.value()));

		auto reopened_or = config_store::open(root_);
		ASSERT_TRUE(reopened_or.is_ok()) << reopened_or.error().message();
		auto reopened = std::move(reopened_or).value();
		const std::string before = read_file(root_ / "TRANSITION_AUTHORITY.pb");
		auto result = reopened->begin_epoch_transition(make_candidate("must-not-stage", 2), "wrap-key", 0u);
		ASSERT_FALSE(result.is_ok());
		EXPECT_EQ(result.error().code(), kinetum::common::status_code::RESOURCE_EXHAUSTED);
		EXPECT_EQ(read_file(root_ / "TRANSITION_AUTHORITY.pb"), before);
		EXPECT_FALSE(reopened->load_snapshot("must-not-stage").is_ok());
	}
}

/** @brief Active/corpus identity equality is byte-exact across restart admission. */
TEST_F(CpTransitionPersistenceTest, active_and_corpus_disagreement_rejects_restart)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	store.reset();
	auto conflicting = make_candidate("bootstrap", 1, "different canonical bytes");
	kinetum::gluon::v1::DeploymentPlan module_free_plan;
	auto canonical_or = kinetum::common::canonicalize_config_snapshot(conflicting, module_free_plan);
	ASSERT_TRUE(canonical_or.is_ok()) << canonical_or.error().message();
	kinetum::control::v1::ConfigSnapshot terminal;
	ASSERT_TRUE(kinetum::common::admit_terminal_config_snapshot(canonical_or.value(), &terminal).is_ok());
	auto text_or = kinetum::common::print_pbtxt_text(terminal);
	auto digest_or = kinetum::common::sha256_hex(std::string_view{"bootstrap"});
	ASSERT_TRUE(text_or.is_ok());
	ASSERT_TRUE(digest_or.is_ok());
	ASSERT_TRUE(write_owned_file(root_ / ("snap_" + digest_or.value() + ".pbtxt"), text_or.value()));
	auto reopened_or = config_store::open(root_);
	ASSERT_FALSE(reopened_or.is_ok());
	EXPECT_EQ(reopened_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	std::error_code error;
	std::filesystem::remove_all(root_, error);
	ASSERT_FALSE(error);
	store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	store.reset();
	authority_message authority;
	ASSERT_TRUE(authority.ParseFromString(read_file(root_ / "TRANSITION_AUTHORITY.pb")));
	authority.GetReflection()->MutableUnknownFields(&authority)->AddVarint(19'001, 1u);
	auto bytes_or = kinetum::common::serialize_protobuf_deterministically(authority);
	ASSERT_TRUE(bytes_or.is_ok());
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", bytes_or.value()));
	auto unknown_or = config_store::open(root_);
	ASSERT_FALSE(unknown_or.is_ok());
	EXPECT_EQ(unknown_or.error().code(), kinetum::common::status_code::DATA_LOSS);
}

/** @brief Terminal and pending-confirm cross-record disagreement reject restart. */
TEST_F(CpTransitionPersistenceTest, terminal_and_pending_cross_record_disagreement_reject_restart)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	auto completed_or = store->begin_epoch_transition(make_candidate("pending-active", 2), "pending-key", 5'000u);
	ASSERT_TRUE(completed_or.is_ok());
	auto completed_identity_or = transition_identity(completed_or.value());
	ASSERT_TRUE(completed_identity_or.is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 completed_identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 completed_identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	ASSERT_TRUE(store->complete_epoch_transition(completed_identity_or.value(), 10'000).is_ok());
	const std::string exact_complete_bytes = read_file(root_ / "TRANSITION_AUTHORITY.pb");
	auto rollback_or = store->load_snapshot("bootstrap");
	ASSERT_TRUE(rollback_or.is_ok());
	auto aborted_rollback_or = store->begin_epoch_transition(rollback_or.value(), "rollback-key", 0u);
	ASSERT_TRUE(aborted_rollback_or.is_ok());
	auto aborted_identity_or = transition_identity(aborted_rollback_or.value());
	ASSERT_TRUE(aborted_identity_or.is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 aborted_identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING)
			    .is_ok());
	ASSERT_TRUE(store->abort_epoch_transition(aborted_identity_or.value(), status::aborted("rollback failed"),
						  durable_abort_proof::LOCAL_PRECOMMIT_INTENT)
			    .is_ok());
	auto unrelated_or = kinetum::common::canonicalize_config_snapshot(make_candidate("unrelated-rollback", 3),
									  rollback_or.value());
	ASSERT_TRUE(unrelated_or.is_ok());
	ASSERT_TRUE(store->stage_snapshot(unrelated_or.value()).is_ok());
	store.reset();
	const std::string exact_aborted_bytes = read_file(root_ / "TRANSITION_AUTHORITY.pb");
	authority_message mismatched_status;
	ASSERT_TRUE(mismatched_status.ParseFromString(exact_aborted_bytes));
	ASSERT_TRUE(mismatched_status.has_transition());
	mismatched_status.mutable_transition()->mutable_terminal_status()->set_error_code(
		kinetum::common::v1::ERROR_CODE_NOT_FOUND);
	auto mismatched_status_bytes_or = kinetum::common::serialize_protobuf_deterministically(mismatched_status);
	ASSERT_TRUE(mismatched_status_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", mismatched_status_bytes_or.value()));
	auto mismatched_status_or = config_store::open(root_);
	ASSERT_FALSE(mismatched_status_or.is_ok());
	EXPECT_EQ(mismatched_status_or.error().code(), kinetum::common::status_code::DATA_LOSS);
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", exact_aborted_bytes));

	authority_message mismatched_pending;
	ASSERT_TRUE(mismatched_pending.ParseFromString(read_file(root_ / "TRANSITION_AUTHORITY.pb")));
	ASSERT_TRUE(mismatched_pending.has_pending_confirm());
	ASSERT_TRUE(mismatched_pending.has_transition());
	mismatched_pending.mutable_pending_confirm()->set_rollback_snapshot_id("unrelated-rollback");
	auto mismatched_pending_bytes_or = kinetum::common::serialize_protobuf_deterministically(mismatched_pending);
	ASSERT_TRUE(mismatched_pending_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", mismatched_pending_bytes_or.value()));
	auto mismatched_pending_or = config_store::open(root_);
	ASSERT_FALSE(mismatched_pending_or.is_ok());
	EXPECT_EQ(mismatched_pending_or.error().code(), kinetum::common::status_code::DATA_LOSS);
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", exact_aborted_bytes));

	authority_message confirmed_without_owner;
	ASSERT_TRUE(confirmed_without_owner.ParseFromString(exact_aborted_bytes));
	auto *confirmed = confirmed_without_owner.mutable_pending_confirm();
	confirmed->set_confirmed(true);
	confirmed->set_confirmation_key_digest(std::string(kinetum::common::SHA256_DIGEST_SIZE, '\x5a'));
	confirmed->set_confirmed_time_remaining_ms(1u);
	auto confirmed_aborted_bytes_or =
		kinetum::common::serialize_protobuf_deterministically(confirmed_without_owner);
	ASSERT_TRUE(confirmed_aborted_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", confirmed_aborted_bytes_or.value()));
	auto confirmed_aborted_or = config_store::open(root_);
	ASSERT_FALSE(confirmed_aborted_or.is_ok());
	EXPECT_EQ(confirmed_aborted_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	authority_message nested_aborted_confirmation;
	ASSERT_TRUE(nested_aborted_confirmation.ParseFromString(exact_aborted_bytes));
	nested_aborted_confirmation.mutable_transition()->set_confirm_timeout_ms(1u);
	auto nested_aborted_bytes_or =
		kinetum::common::serialize_protobuf_deterministically(nested_aborted_confirmation);
	ASSERT_TRUE(nested_aborted_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", nested_aborted_bytes_or.value()));
	auto nested_aborted_or = config_store::open(root_);
	ASSERT_FALSE(nested_aborted_or.is_ok());
	EXPECT_EQ(nested_aborted_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	confirmed_without_owner.clear_transition();
	auto confirmed_orphan_bytes_or = kinetum::common::serialize_protobuf_deterministically(confirmed_without_owner);
	ASSERT_TRUE(confirmed_orphan_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", confirmed_orphan_bytes_or.value()));
	auto confirmed_orphan_or = config_store::open(root_);
	ASSERT_FALSE(confirmed_orphan_or.is_ok());
	EXPECT_EQ(confirmed_orphan_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	authority_message missing_pending;
	ASSERT_TRUE(missing_pending.ParseFromString(exact_complete_bytes));
	missing_pending.clear_pending_confirm();
	auto missing_pending_bytes_or = kinetum::common::serialize_protobuf_deterministically(missing_pending);
	ASSERT_TRUE(missing_pending_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", missing_pending_bytes_or.value()));
	auto missing_pending_or = config_store::open(root_);
	ASSERT_FALSE(missing_pending_or.is_ok());
	EXPECT_EQ(missing_pending_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	authority_message unexpected_pending;
	ASSERT_TRUE(unexpected_pending.ParseFromString(exact_complete_bytes));
	unexpected_pending.mutable_transition()->set_confirm_timeout_ms(0u);
	auto unexpected_pending_bytes_or = kinetum::common::serialize_protobuf_deterministically(unexpected_pending);
	ASSERT_TRUE(unexpected_pending_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_file(root_ / "TRANSITION_AUTHORITY.pb", unexpected_pending_bytes_or.value()));
	auto unexpected_pending_or = config_store::open(root_);
	ASSERT_FALSE(unexpected_pending_or.is_ok());
	EXPECT_EQ(unexpected_pending_or.error().code(), kinetum::common::status_code::DATA_LOSS);
}

/** @brief Prove typed reconciliation is total and rejects contradictory tuples. */
TEST(cp_transition_reconciliation, every_action_is_typed_and_message_independent)
{
	using action = transition_reconciliation_action;
	using resolution = kinetum::common::transition_identity_resolution;
	using state = kinetum::telemetry::v1::EpochTransitionState;
	using failure = kinetum::telemetry::v1::EpochTransitionFailureCode;
	constexpr failure NONE = failure::EPOCH_TRANSITION_FAILURE_CODE_NONE;
	constexpr durable_phase ALLOCATED = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED;
	constexpr durable_phase PREPARED = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED;
	constexpr durable_phase COMPLETION_PENDING =
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING;
	constexpr durable_phase ABORT_PENDING =
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING;
	constexpr durable_phase ABORTED = kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED;

	EXPECT_EQ(*classify_transition_reconciliation(ALLOCATED, resolution::UNKNOWN_FUTURE,
						      state::EPOCH_TRANSITION_STATE_UNSPECIFIED, NONE),
		  action::RETRY_PREPARE);
	EXPECT_EQ(*classify_transition_reconciliation(ALLOCATED, resolution::ACTIVE_EXACT,
						      state::EPOCH_TRANSITION_STATE_PREPARING, NONE),
		  action::WAIT_FOR_PREPARE);
	EXPECT_EQ(*classify_transition_reconciliation(ALLOCATED, resolution::ACTIVE_EXACT,
						      state::EPOCH_TRANSITION_STATE_PREPARED, NONE),
		  action::PERSIST_PREPARED);
	EXPECT_EQ(*classify_transition_reconciliation(PREPARED, resolution::ACTIVE_EXACT,
						      state::EPOCH_TRANSITION_STATE_PREPARED, NONE),
		  action::RETRY_ACTIVATE);
	EXPECT_EQ(*classify_transition_reconciliation(COMPLETION_PENDING, resolution::ACTIVE_EXACT,
						      state::EPOCH_TRANSITION_STATE_PREPARED, NONE),
		  action::RETRY_ACTIVATE);
	EXPECT_EQ(*classify_transition_reconciliation(ABORT_PENDING, resolution::ACTIVE_EXACT,
						      state::EPOCH_TRANSITION_STATE_PREPARING, NONE),
		  action::RETRY_ABORT);
	EXPECT_EQ(*classify_transition_reconciliation(COMPLETION_PENDING, resolution::ACTIVE_EXACT,
						      state::EPOCH_TRANSITION_STATE_RETIRING, NONE),
		  action::QUERY_COMPLETION);
	EXPECT_EQ(*classify_transition_reconciliation(COMPLETION_PENDING, resolution::TERMINAL_EXACT,
						      state::EPOCH_TRANSITION_STATE_COMPLETE, NONE),
		  action::PERSIST_COMPLETE);
	EXPECT_EQ(*classify_transition_reconciliation(ABORT_PENDING, resolution::TERMINAL_EXACT,
						      state::EPOCH_TRANSITION_STATE_ABORTED,
						      failure::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT),
		  action::PERSIST_ABORTED);
	EXPECT_EQ(*classify_transition_reconciliation(ABORTED, resolution::UNKNOWN_FUTURE,
						      state::EPOCH_TRANSITION_STATE_UNSPECIFIED, NONE),
		  action::PERSIST_ABORTED);
	EXPECT_EQ(*classify_transition_reconciliation(COMPLETION_PENDING, resolution::TERMINAL_EXACT,
						      state::EPOCH_TRANSITION_STATE_ABORTED,
						      failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED),
		  action::PERSIST_ABORTED);
	EXPECT_EQ(*classify_transition_reconciliation(COMPLETION_PENDING, resolution::ACTIVE_EXACT,
						      state::EPOCH_TRANSITION_STATE_FAILED_STOP,
						      failure::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED),
		  action::FAIL_CLOSED);
	EXPECT_EQ(*classify_transition_reconciliation(ALLOCATED, resolution::EXPIRED_RETRY,
						      state::EPOCH_TRANSITION_STATE_UNSPECIFIED, NONE),
		  action::REQUIRE_JOINT_RESTART);
	EXPECT_EQ(*classify_transition_reconciliation(ALLOCATED, resolution::POLICY_DISABLED,
						      state::EPOCH_TRANSITION_STATE_UNSPECIFIED, NONE),
		  action::PRESERVE_UNAVAILABLE);
	EXPECT_EQ(*classify_transition_reconciliation(ALLOCATED, resolution::IDENTITY_CONFLICT,
						      state::EPOCH_TRANSITION_STATE_UNSPECIFIED, NONE),
		  action::FAIL_CLOSED);
	EXPECT_EQ(*classify_transition_reconciliation(
			  COMPLETION_PENDING, resolution::ACTIVE_EXACT, state::EPOCH_TRANSITION_STATE_RETIRING,
			  failure::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED),
		  action::PRESERVE_UPDATE_FROZEN);
	EXPECT_FALSE(classify_transition_reconciliation(PREPARED, resolution::ACTIVE_EXACT,
							state::EPOCH_TRANSITION_STATE_COMMITTING, NONE)
			     .is_ok());
	EXPECT_FALSE(classify_transition_reconciliation(
			     kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_UNSPECIFIED,
			     resolution::STATE_UNAVAILABLE, state::EPOCH_TRANSITION_STATE_UNSPECIFIED, NONE)
			     .is_ok());
	EXPECT_FALSE(classify_transition_reconciliation(
			     kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MIN_SENTINEL_DO_NOT_USE_,
			     resolution::STATE_UNAVAILABLE, state::EPOCH_TRANSITION_STATE_UNSPECIFIED, NONE)
			     .is_ok());
	EXPECT_FALSE(classify_transition_reconciliation(
			     kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MAX_SENTINEL_DO_NOT_USE_,
			     resolution::STATE_UNAVAILABLE, state::EPOCH_TRANSITION_STATE_UNSPECIFIED, NONE)
			     .is_ok());
	EXPECT_FALSE(classify_transition_reconciliation(
			     ALLOCATED, resolution::STATE_UNAVAILABLE,
			     kinetum::telemetry::v1::EpochTransitionState_INT_MIN_SENTINEL_DO_NOT_USE_, NONE)
			     .is_ok());
	EXPECT_FALSE(classify_transition_reconciliation(
			     ALLOCATED, resolution::STATE_UNAVAILABLE,
			     kinetum::telemetry::v1::EpochTransitionState_INT_MAX_SENTINEL_DO_NOT_USE_, NONE)
			     .is_ok());
	EXPECT_FALSE(classify_transition_reconciliation(ALLOCATED, resolution::STATE_UNAVAILABLE,
							state::EPOCH_TRANSITION_STATE_UNSPECIFIED,
							failure::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED)
			     .is_ok());

	constexpr std::array<resolution, 12> ALL_RESOLUTIONS{
		resolution::INVALID,	     resolution::ADMISSIBLE,
		resolution::ACTIVE_EXACT,    resolution::TERMINAL_EXACT,
		resolution::STALE,	     resolution::INCONSISTENT,
		resolution::EXPIRED_RETRY,   resolution::IDENTITY_CONFLICT,
		resolution::UNKNOWN_FUTURE,  resolution::OVERLAP,
		resolution::POLICY_DISABLED, resolution::STATE_UNAVAILABLE};
	constexpr std::array<durable_phase, 6> ALL_LOCAL_PHASES{
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED,
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED,
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING,
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING,
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE,
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED,
	};
	constexpr std::array<state, 10> ALL_REMOTE_STATES{
		state::EPOCH_TRANSITION_STATE_UNSPECIFIED,   state::EPOCH_TRANSITION_STATE_AWAITING_BOOTSTRAP,
		state::EPOCH_TRANSITION_STATE_BOOTSTRAPPING, state::EPOCH_TRANSITION_STATE_PREPARING,
		state::EPOCH_TRANSITION_STATE_PREPARED,	     state::EPOCH_TRANSITION_STATE_COMMITTING,
		state::EPOCH_TRANSITION_STATE_RETIRING,	     state::EPOCH_TRANSITION_STATE_COMPLETE,
		state::EPOCH_TRANSITION_STATE_FAILED_STOP,   state::EPOCH_TRANSITION_STATE_ABORTED,
	};
	constexpr std::array<failure, 14> ALL_FAILURES{
		failure::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED,
		failure::EPOCH_TRANSITION_FAILURE_CODE_NONE,
		failure::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT,
		failure::EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT,
		failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE,
		failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED,
		failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED,
		failure::EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED,
		failure::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED,
		failure::EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION,
		failure::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED,
		failure::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE,
		failure::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED,
		failure::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN,
	};
	for (const auto local_phase : ALL_LOCAL_PHASES) {
		for (const auto typed_resolution : ALL_RESOLUTIONS) {
			for (const auto remote_phase : ALL_REMOTE_STATES) {
				for (const auto typed_failure : ALL_FAILURES) {
					const auto result = classify_transition_reconciliation(
						local_phase, typed_resolution, remote_phase, typed_failure);
					EXPECT_TRUE(result.is_ok() ||
						    result.error().code() == kinetum::common::status_code::DATA_LOSS);
				}
			}
		}
	}
}

/** @brief The durable authority alone selects the active listing row. */
TEST_F(CpTransitionPersistenceTest, list_snapshots_never_uses_a_stale_control_loop_projection_as_authority)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	control_loop loop(store.get(), nullptr);
	ASSERT_EQ(loop.published_state().snapshot_id, "bootstrap");

	auto transition_or = store->begin_epoch_transition(make_candidate("listed-active", 2), "listing-key", 0u);
	ASSERT_TRUE(transition_or.is_ok());
	auto identity_or = transition_identity(transition_or.value());
	ASSERT_TRUE(identity_or.is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	ASSERT_TRUE(store->complete_epoch_transition(identity_or.value(), 30'000).is_ok());
	ASSERT_EQ(loop.published_state().snapshot_id, "bootstrap");

	control_service_impl service(store.get(), nullptr, loop);
	kinetum::control::v1::ListSnapshotsRequest request;
	request.set_page_size(kinetum::common::MAX_SNAPSHOT_LIST_PAGE_SIZE);
	kinetum::control::v1::ListSnapshotsResponse response;
	grpc::ServerContext context;
	ASSERT_TRUE(service.ListSnapshots(&context, &request, &response).ok());
	ASSERT_EQ(response.status().code(), 0);
	ASSERT_EQ(response.snapshots_size(), 2);
	EXPECT_EQ(response.total_count(), 2u);
	EXPECT_TRUE(response.next_page_token().empty());
	uint32_t active_count = 0u;
	for (const auto &snapshot : response.snapshots()) {
		active_count += snapshot.is_active() ? 1u : 0u;
		if (snapshot.snapshot_id() == "bootstrap") {
			EXPECT_FALSE(snapshot.is_active());
		} else if (snapshot.snapshot_id() == "listed-active") {
			EXPECT_TRUE(snapshot.is_active());
		} else {
			ADD_FAILURE() << "unexpected snapshot identity: " << snapshot.snapshot_id();
		}
	}
	EXPECT_EQ(active_count, 1u);

	kinetum::control::v1::GetActiveSnapshotRequest active_request;
	kinetum::control::v1::GetActiveSnapshotResponse active_response;
	ASSERT_TRUE(service.GetActiveSnapshot(&context, &active_request, &active_response).ok());
	ASSERT_EQ(active_response.status().code(), 0);
	ASSERT_TRUE(active_response.has_snapshot());
	EXPECT_EQ(active_response.snapshot().snapshot_id(), "listed-active");
	EXPECT_EQ(active_response.snapshot().revision(), 2);
}

/** @brief Prove successful fresh Bootstrap discards one orphaned epoch allocation. */
TEST_F(CpTransitionPersistenceTest, successful_joint_bootstrap_discards_nonterminal_epoch_allocation)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	auto transition_or = store->begin_epoch_transition(make_candidate("orphan", 2), "orphan-key", 0u);
	ASSERT_TRUE(transition_or.is_ok());
	ASSERT_TRUE(store->epoch_transition().is_ok());
	auto source_or = make_authority();
	ASSERT_TRUE(source_or.is_ok());
	EXPECT_TRUE(store->reconcile_bootstrap(&source_or.value()).is_ok());

	successful_bootstrap_service service;
	kinetum::test::fake_dp_server server;
	server.start_with_service(&service);
	auto expired_or =
		bootstrap_dataplane_from_store(*store, *server.stub, nullptr, std::chrono::steady_clock::now());
	ASSERT_FALSE(expired_or.is_ok());
	EXPECT_EQ(expired_or.error().code(), kinetum::common::status_code::DEADLINE_EXCEEDED);
	EXPECT_EQ(service.calls.load(std::memory_order_relaxed), 0u);
	const auto startup_deadline = std::chrono::steady_clock::now() + DATAPLANE_STARTUP_RECONCILIATION_TIMEOUT;
	auto outcome_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr, startup_deadline);
	ASSERT_TRUE(outcome_or.is_ok()) << outcome_or.error().message();
	EXPECT_EQ(outcome_or.value(), dataplane_bootstrap_outcome::PACKET_READY);
	EXPECT_EQ(service.calls.load(std::memory_order_relaxed), 1u);
	EXPECT_FALSE(store->epoch_transition().is_ok());
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	EXPECT_EQ(active_or->snapshot().snapshot_id(), "bootstrap");
	EXPECT_EQ(active_or->active_epoch(), 1u);
	EXPECT_EQ(active_or->allocated_epoch_high_watermark(), 2u);
	EXPECT_EQ(active_or->mutation_sequence_high_watermark(), 2u);
	server.shutdown();
}

/** @brief A surviving packet-ready DP may be exactly one COMPLETE publication ahead of CP. */
TEST_F(CpTransitionPersistenceTest, packet_ready_rejoin_persists_exact_completion_reply_loss)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	auto transition_or =
		store->begin_epoch_transition(make_candidate("reply-loss-target", 2), "reply-loss-key", 0u);
	ASSERT_TRUE(transition_or.is_ok()) << transition_or.error().message();
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	auto plan_hash_or = kinetum::common::hex_to_bytes(active_or->plan_content_hash());
	ASSERT_TRUE(plan_hash_or.is_ok());

	kinetum::test::fake_dp_server server;
	server.service.readiness_state = kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY;
	server.service.complete_transitions = true;
	server.service.active_epoch = transition_or->identity.target_epoch;
	server.service.min_retained_epoch = transition_or->identity.target_epoch;
	server.service.allocated_epoch_high_watermark = transition_or->identity.target_epoch;
	server.service.mutation_sequence_high_watermark = transition_or->identity.mutation_sequence;
	server.service.plan_content_hash.assign(reinterpret_cast<const char *>(plan_hash_or->data()),
						plan_hash_or->size());
	server.service.active_validation_hash.assign(
		reinterpret_cast<const char *>(transition_or->identity.validation_hash.data()),
		transition_or->identity.validation_hash.size());
	server.service.latest_completed_transition = kinetum::test::fake_completed_transition_stats{
		.mutation_sequence = transition_or->identity.mutation_sequence,
		.from_epoch = active_or->active_epoch(),
		.to_epoch = transition_or->identity.target_epoch,
		.validation_hash = server.service.active_validation_hash,
		.idempotency_key_digest = std::string(
			reinterpret_cast<const char *>(transition_or->identity.idempotency_key_digest.data()),
			transition_or->identity.idempotency_key_digest.size()),
	};
	server.service.transition_plan_content_hash = active_or->plan_content_hash();
	server.service.transition_phase = kinetum::test::fake_dp_transition_phase::COMPLETE;
	server.service.transition_epoch = transition_or->identity.target_epoch;
	server.service.transition_sequence = transition_or->identity.mutation_sequence;
	server.service.transition_from_epoch = active_or->active_epoch();
	server.service.transition_validation_hash = server.service.active_validation_hash;
	server.service.transition_key = transition_or->prepare_request.idempotency_key();
	server.start();

	server.service.stats_transport_code = grpc::StatusCode::PERMISSION_DENIED;
	server.service.stats_transport_message = "injected nontransient startup refusal";
	const int denied_calls = server.service.get_stats_calls.load(std::memory_order_relaxed);
	auto denied_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr,
							std::chrono::steady_clock::now() + std::chrono::seconds(3));
	ASSERT_FALSE(denied_or.is_ok());
	EXPECT_EQ(denied_or.error().code(), kinetum::common::status_code::PERMISSION_DENIED);
	EXPECT_EQ(server.service.get_stats_calls.load(std::memory_order_relaxed), denied_calls + 1);
	server.service.stats_transport_code = grpc::StatusCode::OK;
	server.service.stats_transport_message.clear();
	// The first Health sample still sees E while the immediately following
	// telemetry sample sees the lawful completed N. The fake publishes N to
	// Health only after that Stats edge, so startup must refresh and converge.
	server.service.health_active_epoch_override = active_or->active_epoch();
	std::atomic<uint32_t> stats_observations{0u};
	server.service.stats_observer = [&]() {
		if (stats_observations.fetch_add(1u, std::memory_order_relaxed) == 0u) {
			server.service.health_active_epoch_override.reset();
		}
	};

	const auto startup_deadline = std::chrono::steady_clock::now() + DATAPLANE_STARTUP_RECONCILIATION_TIMEOUT;
	const int health_calls_before = server.service.health_calls.load(std::memory_order_relaxed);
	auto outcome_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr, startup_deadline);
	ASSERT_TRUE(outcome_or.is_ok()) << outcome_or.error().message();
	EXPECT_EQ(outcome_or.value(), dataplane_bootstrap_outcome::PACKET_READY_REJOINED);
	EXPECT_GE(server.service.health_calls.load(std::memory_order_relaxed), health_calls_before + 3);
	EXPECT_GE(stats_observations.load(std::memory_order_relaxed), 2u);
	EXPECT_EQ(server.service.bootstrap_calls.load(std::memory_order_relaxed), 0);
	control_loop loop(store.get(), server.stub);
	ASSERT_TRUE(loop.initialization_status().is_ok());
	ASSERT_TRUE(loop.reconcile_startup(true, startup_deadline).is_ok());
	auto completed_or = store->epoch_transition();
	ASSERT_TRUE(completed_or.is_ok());
	EXPECT_EQ(completed_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE);
	auto restored_active_or = store->active_bootstrap();
	ASSERT_TRUE(restored_active_or.is_ok());
	EXPECT_EQ(restored_active_or->active_epoch(), transition_or->identity.target_epoch);
	EXPECT_EQ(restored_active_or->snapshot().snapshot_id(), "reply-loss-target");
	server.shutdown();
}

/** @brief A COMMITTING-era intent survives reply loss and becomes E+2 after exact COMPLETE. */
TEST_F(CpTransitionPersistenceTest, packet_ready_rejoin_services_predecessor_bound_intent_after_complete)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	auto policy_or = store->configure_guardrails_policy(make_guardrails_policy(), "rejoin-intent-policy-key", 0u);
	ASSERT_TRUE(policy_or.is_ok());
	auto transition_or =
		store->begin_epoch_transition(make_candidate("rejoin-guarded", 2), "rejoin-guarded-key", 0u);
	ASSERT_TRUE(transition_or.is_ok()) << transition_or.error().message();
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	rollback_intent_request intent{
		.target_snapshot_id = "bootstrap",
		.guarded_snapshot_id = "rejoin-guarded",
		.guarded_epoch = transition_or->identity.target_epoch,
		.guarded_revision = 2,
		.guarded_validation_hash = transition_or->identity.validation_hash,
		.wait_for_mutation_sequence = transition_or->identity.mutation_sequence,
		.policy_generation = policy_or->generation,
		.runtime_generation = 1u,
		.idempotency_key = "rejoin-intent-key",
		.cause = rollback_intent_cause::THRESHOLD_DEGRADATION,
		.observed_monotonic_ns = 1u,
		.created_unix_ms = 1u,
	};
	ASSERT_TRUE(store->accept_rollback_intent(intent).is_ok());
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	auto plan_hash_or = kinetum::common::hex_to_bytes(active_or->plan_content_hash());
	ASSERT_TRUE(plan_hash_or.is_ok());

	kinetum::test::fake_dp_server server;
	server.service.readiness_state = kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY;
	server.service.complete_transitions = true;
	server.service.active_epoch = transition_or->identity.target_epoch;
	server.service.min_retained_epoch = transition_or->identity.target_epoch;
	server.service.allocated_epoch_high_watermark = transition_or->identity.target_epoch;
	server.service.mutation_sequence_high_watermark = transition_or->identity.mutation_sequence;
	server.service.plan_content_hash.assign(reinterpret_cast<const char *>(plan_hash_or->data()),
						plan_hash_or->size());
	server.service.active_validation_hash.assign(
		reinterpret_cast<const char *>(transition_or->identity.validation_hash.data()),
		transition_or->identity.validation_hash.size());
	server.service.latest_completed_transition = kinetum::test::fake_completed_transition_stats{
		.mutation_sequence = transition_or->identity.mutation_sequence,
		.from_epoch = active_or->active_epoch(),
		.to_epoch = transition_or->identity.target_epoch,
		.validation_hash = server.service.active_validation_hash,
		.idempotency_key_digest = std::string(
			reinterpret_cast<const char *>(transition_or->identity.idempotency_key_digest.data()),
			transition_or->identity.idempotency_key_digest.size()),
	};
	server.service.transition_plan_content_hash = active_or->plan_content_hash();
	server.service.transition_phase = kinetum::test::fake_dp_transition_phase::COMPLETE;
	server.service.transition_epoch = transition_or->identity.target_epoch;
	server.service.transition_sequence = transition_or->identity.mutation_sequence;
	server.service.transition_from_epoch = active_or->active_epoch();
	server.service.transition_validation_hash = server.service.active_validation_hash;
	server.service.transition_key = transition_or->prepare_request.idempotency_key();
	server.start();

	auto outcome_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr);
	ASSERT_TRUE(outcome_or.is_ok()) << outcome_or.error().message();
	EXPECT_EQ(outcome_or.value(), dataplane_bootstrap_outcome::PACKET_READY_REJOINED);
	control_loop loop(store.get(), server.stub);
	ASSERT_TRUE(loop.initialization_status().is_ok());
	ASSERT_TRUE(loop.reconcile_startup(true).is_ok());
	EXPECT_FALSE(store->rollback_intent().is_ok());
	auto restored_or = store->active_bootstrap();
	ASSERT_TRUE(restored_or.is_ok());
	EXPECT_EQ(restored_or->snapshot().snapshot_id(), "bootstrap");
	EXPECT_EQ(restored_or->active_epoch(), 3u);
	auto rollback_or = store->epoch_transition();
	ASSERT_TRUE(rollback_or.is_ok());
	EXPECT_EQ(rollback_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE);
	EXPECT_EQ(rollback_or->prepare_request.idempotency_key(), intent.idempotency_key);
	server.shutdown();
}

/** @brief A durable allocation may resume when surviving DP has not admitted it yet. */
TEST_F(CpTransitionPersistenceTest, packet_ready_rejoin_resumes_exact_preadmission_allocation)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	auto transition_or =
		store->begin_epoch_transition(make_candidate("preadmission-target", 2), "preadmission-key", 0u);
	ASSERT_TRUE(transition_or.is_ok()) << transition_or.error().message();
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	auto active_content_or = kinetum::common::canonical_config_snapshot_from_terminal(active_or->snapshot());
	ASSERT_TRUE(active_content_or.is_ok());
	auto plan_hash_or = kinetum::common::hex_to_bytes(active_or->plan_content_hash());
	ASSERT_TRUE(plan_hash_or.is_ok());

	kinetum::test::fake_dp_server server;
	server.service.readiness_state = kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY;
	server.service.complete_transitions = true;
	server.service.active_epoch = active_or->active_epoch();
	server.service.min_retained_epoch = active_or->active_epoch();
	server.service.allocated_epoch_high_watermark = active_or->active_epoch();
	server.service.mutation_sequence_high_watermark = 1u;
	server.service.plan_content_hash.assign(reinterpret_cast<const char *>(plan_hash_or->data()),
						plan_hash_or->size());
	server.service.active_validation_hash.assign(
		reinterpret_cast<const char *>(active_content_or->validation_hash.data()),
		active_content_or->validation_hash.size());
	server.service.transition_plan_content_hash = active_or->plan_content_hash();
	server.service.transition_from_epoch = active_or->active_epoch();
	server.start();

	auto outcome_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr);
	ASSERT_TRUE(outcome_or.is_ok()) << outcome_or.error().message();
	EXPECT_EQ(outcome_or.value(), dataplane_bootstrap_outcome::PACKET_READY_REJOINED);
	EXPECT_EQ(server.service.bootstrap_calls.load(std::memory_order_relaxed), 0);
	control_loop loop(store.get(), server.stub);
	ASSERT_TRUE(loop.initialization_status().is_ok());
	ASSERT_TRUE(loop.reconcile_startup(true).is_ok());
	auto completed_or = store->epoch_transition();
	ASSERT_TRUE(completed_or.is_ok());
	EXPECT_EQ(completed_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE);
	EXPECT_EQ(completed_or->identity, transition_or->identity);
	auto completed_active_or = store->active_bootstrap();
	ASSERT_TRUE(completed_active_or.is_ok());
	EXPECT_EQ(completed_active_or->active_epoch(), transition_or->identity.target_epoch);
	EXPECT_EQ(completed_active_or->snapshot().snapshot_id(), "preadmission-target");
	server.shutdown();
}

/** @brief Durable PREPARED resumes the exact already-prepared DP transaction. */
TEST_F(CpTransitionPersistenceTest, packet_ready_rejoin_resumes_exact_prepared_transaction)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	auto transition_or =
		store->begin_epoch_transition(make_candidate("prepared-rejoin", 2), "prepared-rejoin-key", 0u);
	ASSERT_TRUE(transition_or.is_ok()) << transition_or.error().message();
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	auto active_content_or = kinetum::common::canonical_config_snapshot_from_terminal(active_or->snapshot());
	ASSERT_TRUE(active_content_or.is_ok());
	auto plan_hash_or = kinetum::common::hex_to_bytes(active_or->plan_content_hash());
	ASSERT_TRUE(plan_hash_or.is_ok());

	kinetum::test::fake_dp_server server;
	server.service.readiness_state = kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY;
	server.service.complete_transitions = true;
	server.service.active_epoch = active_or->active_epoch();
	server.service.min_retained_epoch = active_or->active_epoch();
	server.service.allocated_epoch_high_watermark = transition_or->identity.target_epoch;
	server.service.mutation_sequence_high_watermark = transition_or->identity.mutation_sequence;
	server.service.plan_content_hash.assign(reinterpret_cast<const char *>(plan_hash_or->data()),
						plan_hash_or->size());
	server.service.active_validation_hash.assign(
		reinterpret_cast<const char *>(active_content_or->validation_hash.data()),
		active_content_or->validation_hash.size());
	server.service.transition_plan_content_hash = active_or->plan_content_hash();
	server.service.transition_phase = kinetum::test::fake_dp_transition_phase::PREPARED;
	server.service.transition_epoch = transition_or->identity.target_epoch;
	server.service.transition_sequence = transition_or->identity.mutation_sequence;
	server.service.transition_from_epoch = active_or->active_epoch();
	server.service.transition_validation_hash.assign(
		reinterpret_cast<const char *>(transition_or->identity.validation_hash.data()),
		transition_or->identity.validation_hash.size());
	server.service.transition_key = transition_or->prepare_request.idempotency_key();
	server.start();

	auto outcome_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr);
	ASSERT_TRUE(outcome_or.is_ok()) << outcome_or.error().message();
	EXPECT_EQ(outcome_or.value(), dataplane_bootstrap_outcome::PACKET_READY_REJOINED);
	control_loop loop(store.get(), server.stub);
	ASSERT_TRUE(loop.initialization_status().is_ok());
	ASSERT_TRUE(loop.reconcile_startup(true).is_ok());
	auto completed_or = store->epoch_transition();
	ASSERT_TRUE(completed_or.is_ok());
	EXPECT_EQ(completed_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE);
	EXPECT_EQ(completed_or->identity, transition_or->identity);
	server.shutdown();
}

/** @brief Pre-admission ABORT_PENDING converges locally and preserves active service. */
TEST_F(CpTransitionPersistenceTest, packet_ready_rejoin_completes_exact_preadmission_abort)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	auto transition_or =
		store->begin_epoch_transition(make_candidate("preadmission-abort", 2), "preadmission-abort-key", 0u);
	ASSERT_TRUE(transition_or.is_ok()) << transition_or.error().message();
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING)
			    .is_ok());
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	auto active_content_or = kinetum::common::canonical_config_snapshot_from_terminal(active_or->snapshot());
	ASSERT_TRUE(active_content_or.is_ok());
	auto plan_hash_or = kinetum::common::hex_to_bytes(active_or->plan_content_hash());
	ASSERT_TRUE(plan_hash_or.is_ok());

	kinetum::test::fake_dp_server server;
	server.service.readiness_state = kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY;
	server.service.complete_transitions = true;
	server.service.active_epoch = active_or->active_epoch();
	server.service.min_retained_epoch = active_or->active_epoch();
	server.service.allocated_epoch_high_watermark = active_or->active_epoch();
	server.service.mutation_sequence_high_watermark = 1u;
	server.service.plan_content_hash.assign(reinterpret_cast<const char *>(plan_hash_or->data()),
						plan_hash_or->size());
	server.service.active_validation_hash.assign(
		reinterpret_cast<const char *>(active_content_or->validation_hash.data()),
		active_content_or->validation_hash.size());
	server.service.transition_plan_content_hash = active_or->plan_content_hash();
	server.start();

	auto outcome_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr);
	ASSERT_TRUE(outcome_or.is_ok()) << outcome_or.error().message();
	EXPECT_EQ(outcome_or.value(), dataplane_bootstrap_outcome::PACKET_READY_REJOINED);
	control_loop loop(store.get(), server.stub);
	ASSERT_TRUE(loop.initialization_status().is_ok());
	ASSERT_TRUE(loop.reconcile_startup(true).is_ok());
	auto aborted_or = store->epoch_transition();
	ASSERT_TRUE(aborted_or.is_ok());
	EXPECT_EQ(aborted_or->phase, kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED);
	auto retained_active_or = store->active_bootstrap();
	ASSERT_TRUE(retained_active_or.is_ok());
	EXPECT_EQ(retained_active_or->active_epoch(), 1u);
	EXPECT_EQ(retained_active_or->snapshot().snapshot_id(), "bootstrap");
	auto repeated_outcome_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr);
	ASSERT_TRUE(repeated_outcome_or.is_ok()) << repeated_outcome_or.error().message();
	EXPECT_EQ(repeated_outcome_or.value(), dataplane_bootstrap_outcome::PACKET_READY_REJOINED);
	EXPECT_TRUE(loop.reconcile_startup(true).is_ok());
	server.shutdown();
}

/** @brief Fresh source imports only after CONTROL_READY and never adopts PACKET_READY. */
TEST_F(CpTransitionPersistenceTest, fresh_store_rejects_packet_ready_dataplane_without_mutation)
{
	auto store_or = config_store::open(root_);
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	auto source_or = make_authority();
	ASSERT_TRUE(source_or.is_ok());
	kinetum::test::fake_dp_server denied_health;
	denied_health.service.health_transport_code = grpc::StatusCode::PERMISSION_DENIED;
	denied_health.service.health_transport_message = "injected nontransient Health refusal";
	denied_health.start();
	auto denied_or = bootstrap_dataplane_from_store(*store, *denied_health.stub, &source_or.value(),
							std::chrono::steady_clock::now() + std::chrono::seconds(3));
	ASSERT_FALSE(denied_or.is_ok());
	EXPECT_EQ(denied_or.error().code(), kinetum::common::status_code::PERMISSION_DENIED);
	EXPECT_EQ(denied_health.service.health_calls.load(std::memory_order_relaxed), 1);
	EXPECT_EQ(denied_health.service.bootstrap_calls.load(std::memory_order_relaxed), 0);
	EXPECT_FALSE(store->active_bootstrap().is_ok());
	denied_health.shutdown();

	kinetum::test::fake_dp_server malformed_health;
	malformed_health.service.readiness_state = kinetum::dataplane::v1::HealthResponse::STATE_UNSPECIFIED;
	malformed_health.start();
	auto malformed_or = bootstrap_dataplane_from_store(*store, *malformed_health.stub, &source_or.value());
	ASSERT_FALSE(malformed_or.is_ok());
	EXPECT_EQ(malformed_or.error().code(), kinetum::common::status_code::DATA_LOSS);
	EXPECT_EQ(malformed_health.service.bootstrap_calls.load(std::memory_order_relaxed), 0);
	EXPECT_FALSE(store->active_bootstrap().is_ok());
	malformed_health.shutdown();

	kinetum::test::fake_dp_server server;
	server.service.readiness_state = kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY;
	server.service.active_epoch = 1u;
	server.service.min_retained_epoch = 1u;
	server.service.allocated_epoch_high_watermark = 1u;
	server.service.mutation_sequence_high_watermark = 1u;
	server.service.plan_content_hash.assign(
		reinterpret_cast<const char *>(source_or->plan_content_hash_bytes.data()),
		source_or->plan_content_hash_bytes.size());
	server.service.active_validation_hash.assign(
		reinterpret_cast<const char *>(source_or->snapshot.validation_hash.data()),
		source_or->snapshot.validation_hash.size());
	server.service.transition_plan_content_hash = source_or->plan_content_hash;
	server.start();
	auto outcome_or = bootstrap_dataplane_from_store(*store, *server.stub, &source_or.value());
	ASSERT_FALSE(outcome_or.is_ok());
	EXPECT_EQ(outcome_or.error().code(), kinetum::common::status_code::DATA_LOSS);
	EXPECT_EQ(server.service.bootstrap_calls.load(std::memory_order_relaxed), 0);
	EXPECT_EQ(server.service.get_stats_calls.load(std::memory_order_relaxed), 0);
	EXPECT_FALSE(store->active_bootstrap().is_ok());
	server.shutdown();

	kinetum::test::fake_dp_server failed_bootstrap;
	failed_bootstrap.service.readiness_state = kinetum::dataplane::v1::HealthResponse::STATE_CONTROL_READY;
	failed_bootstrap.service.bootstrap_transport_code = grpc::StatusCode::PERMISSION_DENIED;
	failed_bootstrap.service.bootstrap_transport_message = "injected first Bootstrap refusal";
	failed_bootstrap.start();
	auto failed_import_or = bootstrap_dataplane_from_store(*store, *failed_bootstrap.stub, &source_or.value());
	ASSERT_FALSE(failed_import_or.is_ok());
	EXPECT_EQ(failed_import_or.error().code(), kinetum::common::status_code::PERMISSION_DENIED);
	EXPECT_EQ(failed_bootstrap.service.bootstrap_calls.load(std::memory_order_relaxed), 1);
	EXPECT_TRUE(store->active_bootstrap().is_ok());
	failed_bootstrap.shutdown();

	successful_bootstrap_service bootstrap_service;
	kinetum::test::fake_dp_server control_ready;
	control_ready.start_with_service(&bootstrap_service);
	auto imported_or = bootstrap_dataplane_from_store(*store, *control_ready.stub, &source_or.value());
	ASSERT_TRUE(imported_or.is_ok()) << imported_or.error().message();
	EXPECT_EQ(imported_or.value(), dataplane_bootstrap_outcome::PACKET_READY);
	EXPECT_EQ(bootstrap_service.calls.load(std::memory_order_relaxed), 1u);
	EXPECT_TRUE(store->active_bootstrap().is_ok());
	control_ready.shutdown();
}

/** @brief Failed or uncertain Bootstrap cannot discard durable transition allocation. */
TEST_F(CpTransitionPersistenceTest, failed_bootstrap_preserves_nonterminal_epoch_allocation)
{
	auto store = open_bootstrapped_store();
	ASSERT_NE(store, nullptr);
	ASSERT_TRUE(store->begin_epoch_transition(make_candidate("retained", 2), "retained-key", 0u).is_ok());
	kinetum::test::fake_dp_server server;
	server.service.bootstrap_status_message = "packet-worker facility registration failed";
	server.start();
	auto outcome_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr);
	ASSERT_FALSE(outcome_or.is_ok());
	EXPECT_EQ(outcome_or.error().code(), kinetum::common::status_code::UNAVAILABLE);
	EXPECT_EQ(outcome_or.error().message(), "Data Plane rejected the durable fixed-epoch bootstrap");
	EXPECT_EQ(outcome_or.error().details(), "packet-worker facility registration failed");
	server.service.bootstrap_transport_code = grpc::StatusCode::PERMISSION_DENIED;
	server.service.bootstrap_transport_message = "injected nontransient Bootstrap refusal";
	auto denied_or = bootstrap_dataplane_from_store(*store, *server.stub, nullptr);
	ASSERT_FALSE(denied_or.is_ok());
	EXPECT_EQ(denied_or.error().code(), kinetum::common::status_code::PERMISSION_DENIED);
	EXPECT_EQ(server.service.bootstrap_calls.load(std::memory_order_relaxed), 2);
	EXPECT_TRUE(store->epoch_transition().is_ok());
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	EXPECT_EQ(active_or->active_epoch(), 1u);
	EXPECT_EQ(active_or->allocated_epoch_high_watermark(), 2u);
	EXPECT_EQ(active_or->mutation_sequence_high_watermark(), 2u);
	server.shutdown();
}

}  // namespace
}  // namespace kinetum::cp
