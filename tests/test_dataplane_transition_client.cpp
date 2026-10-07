// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dataplane_transition_client.cpp
 * @brief Exact CP transition-wire admission and normalization tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include "src/common/sha256.hpp"
#include "src/cp/dataplane_transition_client.hpp"
#include "src/cp/transition_reconciliation.hpp"
#include "tests/test_grpc_helpers.hpp"

namespace kinetum::cp
{
namespace
{

/** Exact idempotency-key bytes shared by client requests and expected digests. */
constexpr char TEST_KEY[] = "cp-transition-client-key";

/** @brief Build one exact request/identity pair for the fake DP. */
struct client_request_fixture {
	kinetum::dataplane::v1::PrepareConfigSnapshotRequest request;  ///< Exact Prepare request.
	kinetum::common::epoch_transition_identity identity{};	       ///< Matching fixed identity.
};

/** @return One exact target-2 request with a canonical hash claim. */
client_request_fixture make_client_request()
{
	client_request_fixture fixture;
	fixture.identity.mutation_sequence = 2u;
	fixture.identity.target_epoch = 2u;
	fixture.identity.validation_hash.fill(UINT8_C(0x2a));
	auto key_digest_or = kinetum::common::digest_transition_idempotency_key(TEST_KEY);
	if (!key_digest_or.is_ok()) {
		std::terminate();
	}
	fixture.identity.idempotency_key_digest = key_digest_or.value();
	fixture.request.mutable_snapshot()->set_snapshot_id("cp-client-target");
	fixture.request.mutable_snapshot()->set_revision(2);
	fixture.request.mutable_snapshot()->set_created_unix_ms(2);
	fixture.request.mutable_snapshot()->set_content_hash(kinetum::common::bytes_to_hex(
		fixture.identity.validation_hash.data(), fixture.identity.validation_hash.size()));
	fixture.request.set_target_epoch(fixture.identity.target_epoch);
	fixture.request.set_mutation_sequence(fixture.identity.mutation_sequence);
	fixture.request.set_idempotency_key(TEST_KEY);
	return fixture;
}

/** @brief Service returning one contradictory unspecified failure classification. */
class malformed_transition_service final : public kinetum::dataplane::v1::DataplaneService::Service {
    public:
	/**
	 * @brief Return ACTIVE_EXACT RETIRING with an omitted typed failure code.
	 * @param response Output deliberately lacking the required typed failure-code presence.
	 * @return Transport OK carrying the malformed application observation.
	 */
	grpc::Status
	GetEpochTransitionStatus(grpc::ServerContext *, const kinetum::dataplane::v1::GetEpochTransitionStatusRequest *,
				 kinetum::dataplane::v1::GetEpochTransitionStatusResponse *response) override
	{
		response->mutable_status()->set_code(0);
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		response->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_RETIRING);
		response->set_identity_resolution(
			kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_ACTIVE_EXACT);
		response->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED);
		return grpc::Status::OK;
	}
};

/** @brief Service returning one canonical non-retryable transport failure. */
class terminal_transport_service final : public kinetum::dataplane::v1::DataplaneService::Service {
    public:
	/**
	 * @brief Return a canonical non-retryable transport refusal.
	 * @return PERMISSION_DENIED without writing an application response.
	 */
	grpc::Status GetEpochTransitionStatus(grpc::ServerContext *,
					      const kinetum::dataplane::v1::GetEpochTransitionStatusRequest *,
					      kinetum::dataplane::v1::GetEpochTransitionStatusResponse *) override
	{
		return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "fake terminal transport refusal");
	}
};

/** @brief Service returning one exact PREPARED identity with retirement residue. */
class duration_residue_transition_service final : public kinetum::dataplane::v1::DataplaneService::Service {
    public:
	/**
	 * @brief Return exact PREPARED identity with impossible retirement duration.
	 * @param request Borrowed exact queried transaction identity.
	 * @param response Output echoing the identity with deliberately contradictory retirement timing.
	 * @return Transport OK carrying the malformed application observation.
	 */
	grpc::Status
	GetEpochTransitionStatus(grpc::ServerContext *,
				 const kinetum::dataplane::v1::GetEpochTransitionStatusRequest *request,
				 kinetum::dataplane::v1::GetEpochTransitionStatusResponse *response) override
	{
		response->mutable_status()->set_code(0);
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		response->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_PREPARED);
		response->set_identity_resolution(
			kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_ACTIVE_EXACT);
		response->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
		response->set_from_epoch(1u);
		response->set_to_epoch(request->epoch());
		response->set_validation_hash(request->validation_hash());
		response->set_plan_content_hash(std::string(64u, 'a'));
		response->set_mutation_sequence(request->mutation_sequence());
		response->set_retirement_duration_ns(1u);
		return grpc::Status::OK;
	}
};

}  // namespace

/** @brief Prove client construction requires one stub and a bounded positive timeout. */
TEST(dataplane_transition_client, construction_requires_stub_and_bounded_timeout)
{
	auto missing_stub_or = dataplane_transition_client::create(nullptr);
	ASSERT_FALSE(missing_stub_or.is_ok());
	EXPECT_EQ(missing_stub_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);

	kinetum::test::fake_dp_server server;
	server.start();
	ASSERT_NE(server.stub, nullptr);
	auto zero_or = dataplane_transition_client::create(server.stub, std::chrono::milliseconds::zero());
	ASSERT_FALSE(zero_or.is_ok());
	EXPECT_EQ(zero_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	auto maximum_or = dataplane_transition_client::create(server.stub, DATAPLANE_TRANSITION_RPC_TIMEOUT);
	ASSERT_TRUE(maximum_or.is_ok()) << maximum_or.error().message();
	auto oversized_or = dataplane_transition_client::create(server.stub, DATAPLANE_TRANSITION_RPC_TIMEOUT +
										     std::chrono::milliseconds(1));
	ASSERT_FALSE(oversized_or.is_ok());
	EXPECT_EQ(oversized_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	server.shutdown();
}

/** @brief Prove exact UNKNOWN -> PREPARED -> COMPLETE normalization. */
TEST(dataplane_transition_client, exact_prepare_activate_and_status_are_typed)
{
	kinetum::test::fake_dp_server server;
	server.service.complete_transitions = true;
	server.service.transition_plan_content_hash = std::string(64u, 'a');
	server.start();
	auto client_or = dataplane_transition_client::create(server.stub, std::chrono::seconds(1));
	ASSERT_TRUE(client_or.is_ok()) << client_or.error().message();
	auto client = std::move(client_or).value();
	const auto fixture = make_client_request();

	auto unknown_or = client->query(fixture.identity, TEST_KEY, server.service.transition_plan_content_hash);
	ASSERT_TRUE(unknown_or.is_ok()) << unknown_or.error().message();
	EXPECT_EQ(unknown_or->resolution, kinetum::common::transition_identity_resolution::UNKNOWN_FUTURE);
	EXPECT_EQ(unknown_or->failure_code, kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);

	auto prepared_or = client->prepare(fixture.request, fixture.identity);
	ASSERT_TRUE(prepared_or.is_ok()) << prepared_or.error().message();
	EXPECT_EQ(prepared_or->resolution, kinetum::common::transition_identity_resolution::ACTIVE_EXACT);
	EXPECT_EQ(prepared_or->state, kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_PREPARED);
	EXPECT_NE(prepared_or->prepared_lease_deadline_unix_ms, 0u);

	auto complete_or = client->activate(fixture.identity, TEST_KEY);
	ASSERT_TRUE(complete_or.is_ok()) << complete_or.error().message();
	EXPECT_EQ(complete_or->resolution, kinetum::common::transition_identity_resolution::TERMINAL_EXACT);
	EXPECT_EQ(complete_or->state, kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);

	auto terminal_or = client->query(fixture.identity, TEST_KEY, server.service.transition_plan_content_hash);
	ASSERT_TRUE(terminal_or.is_ok()) << terminal_or.error().message();
	EXPECT_EQ(terminal_or->resolution, kinetum::common::transition_identity_resolution::TERMINAL_EXACT);
	EXPECT_EQ(terminal_or->state, kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	EXPECT_EQ(terminal_or->identity, fixture.identity);
	EXPECT_EQ(terminal_or->plan_content_hash, server.service.transition_plan_content_hash);
	const int status_calls = server.service.transition_status_calls.load(std::memory_order_relaxed);
	auto expired_or = client->query(fixture.identity, TEST_KEY, server.service.transition_plan_content_hash,
					std::chrono::steady_clock::now());
	ASSERT_FALSE(expired_or.is_ok());
	EXPECT_EQ(expired_or.error().code(), kinetum::common::status_code::DEADLINE_EXCEEDED);
	EXPECT_EQ(server.service.transition_status_calls.load(std::memory_order_relaxed), status_calls);
	server.shutdown();
}

/** @brief Prove malformed wire and non-retryable transport failures stay exact. */
TEST(dataplane_transition_client, malformed_typed_response_fails_closed)
{
	malformed_transition_service service;
	kinetum::test::fake_dp_server server;
	server.start_with_service(&service);
	auto client_or = dataplane_transition_client::create(server.stub, std::chrono::seconds(1));
	ASSERT_TRUE(client_or.is_ok()) << client_or.error().message();
	auto client = std::move(client_or).value();
	const auto fixture = make_client_request();
	const auto result = client->query(fixture.identity, TEST_KEY, std::string(64u, 'a'));
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::DATA_LOSS);
	server.shutdown();

	terminal_transport_service terminal_service;
	kinetum::test::fake_dp_server terminal_server;
	terminal_server.start_with_service(&terminal_service);
	auto terminal_client_or = dataplane_transition_client::create(terminal_server.stub, std::chrono::seconds(1));
	ASSERT_TRUE(terminal_client_or.is_ok()) << terminal_client_or.error().message();
	auto terminal_client = std::move(terminal_client_or).value();
	const auto terminal = terminal_client->query(fixture.identity, TEST_KEY, std::string(64u, 'a'));
	ASSERT_FALSE(terminal.is_ok());
	EXPECT_EQ(terminal.error().code(), kinetum::common::status_code::PERMISSION_DENIED);
	terminal_server.shutdown();

	duration_residue_transition_service residue_service;
	kinetum::test::fake_dp_server residue_server;
	residue_server.start_with_service(&residue_service);
	auto residue_client_or = dataplane_transition_client::create(residue_server.stub, std::chrono::seconds(1));
	ASSERT_TRUE(residue_client_or.is_ok()) << residue_client_or.error().message();
	auto residue_client = std::move(residue_client_or).value();
	const auto residue = residue_client->query(fixture.identity, TEST_KEY, std::string(64u, 'a'));
	ASSERT_FALSE(residue.is_ok());
	EXPECT_EQ(residue.error().code(), kinetum::common::status_code::DATA_LOSS);
	residue_server.shutdown();
}

/** @brief Prove update-freeze selection depends on typed cause, never diagnostic text. */
TEST(dataplane_transition_client, update_frozen_reconciliation_is_message_independent)
{
	using phase = kinetum::control::internal::v1::DurableEpochTransitionPhase;
	const auto action_or = classify_transition_reconciliation(
		phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING,
		kinetum::common::transition_identity_resolution::ACTIVE_EXACT,
		kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_RETIRING,
		kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED);
	ASSERT_TRUE(action_or.is_ok()) << action_or.error().message();
	EXPECT_EQ(action_or.value(), transition_reconciliation_action::PRESERVE_UPDATE_FROZEN);
}

}  // namespace kinetum::cp
