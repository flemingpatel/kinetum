// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dataplane_control_service.cpp
 * @brief Fixed-epoch bootstrap, readiness, and fail-closed DP RPC tests.
 * @author Fleming Patel
 *
 * Every behavioral row binds the merged production service to one complete
 * materialized runtime generation. Bootstrap and Health consume final runtime
 * authorities and passive transitions traverse the final public RPC surface.
 * Complete operator telemetry becomes available only after exact packet
 * readiness; process-lifecycle operations retain their separate fence.
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/unknown_field_set.h>

#include "gen/kinetum/common/v1/common.pb.h"
#include "src/common/application_status.hpp"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/runtime_telemetry_contract.hpp"
#include "src/common/status.hpp"
#include "src/dp/dataplane_control_service.hpp"
#include "tests/packet_runtime_test_fixture.hpp"
#include "tests/log_test_support.hpp"

namespace kinetum::dp
{
namespace
{

using kinetum::common::status_code;
using kinetum::test::packet_runtime_test_owner;

/** @brief Expected refusal while runtime readiness remains CONTROL_READY. */
constexpr char PACKET_TELEMETRY_UNAVAILABLE[] = "runtime telemetry is not packet-ready";
/** @brief Maximum wait for the initial worker telemetry publication. */
constexpr auto STATS_BASELINE_TIMEOUT = std::chrono::seconds(3);
/** @brief Sampling interval while waiting for initial worker telemetry. */
constexpr auto STATS_BASELINE_POLL_INTERVAL = std::chrono::milliseconds(1);

/** @brief Fixture owning one exact production-shaped DP service generation. */
class DataplaneControlServiceTest : public ::testing::Test {
    protected:
	/** @brief Construct one exact runtime with the required gate-host resources. */
	void SetUp() override
	{
		auto owner_or = packet_runtime_test_owner::create();
		ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
		owner_ = std::move(owner_or).value();
	}

	std::unique_ptr<packet_runtime_test_owner> owner_;  ///< Runtime and all transitive owners.
};

/**
 * @brief Require canonical application success.
 *
 * @param status Response status to validate.
 */
void expect_application_success(const kinetum::common::v1::Status &status)
{
	EXPECT_EQ(status.code(), static_cast<int32_t>(status_code::OK)) << status.message();
	EXPECT_EQ(status.error_code(), kinetum::common::v1::ERROR_CODE_OK) << status.message();
	EXPECT_TRUE(status.message().empty()) << status.message();
	EXPECT_TRUE(status.details().empty()) << status.details();
}

/**
 * @brief Wait for the first complete owner-bank telemetry baseline.
 *
 * PACKET_READY may precede the cadence-driven owner-bank publication. Retry
 * only canonical UNAVAILABLE results and retain the last response for diagnostics.
 *
 * @param service Exact production service.
 * @param request Complete statistics selection.
 * @param response Replaced by each attempt and retained on return.
 * @return Assertion success after canonical application success, otherwise a
 *         bounded transport/application diagnostic.
 */
[[nodiscard]] ::testing::AssertionResult await_stats_baseline(dataplane_control_service &service,
							      const kinetum::dataplane::v1::StatsRequest &request,
							      kinetum::dataplane::v1::StatsResponse &response)
{
	const auto deadline = std::chrono::steady_clock::now() + STATS_BASELINE_TIMEOUT;
	for (;;) {
		grpc::ServerContext context;
		const auto transport = service.GetStats(&context, &request, &response);
		if (!transport.ok()) {
			return ::testing::AssertionFailure()
			       << "GetStats transport failed: code=" << transport.error_code()
			       << " message=" << transport.error_message();
		}
		status_code code{};
		if (!common::decode_exact_application_status(response.status(), code)) {
			return ::testing::AssertionFailure()
			       << "GetStats returned malformed application status: code=" << response.status().code()
			       << " error_code=" << response.status().error_code()
			       << " message=" << response.status().message();
		}
		if (code == status_code::OK) {
			return ::testing::AssertionSuccess();
		}
		if (code != status_code::UNAVAILABLE || std::chrono::steady_clock::now() >= deadline) {
			return ::testing::AssertionFailure()
			       << "GetStats baseline did not converge: code=" << response.status().code()
			       << " error_code=" << response.status().error_code()
			       << " message=" << response.status().message()
			       << " details=" << response.status().details();
		}
		std::this_thread::sleep_for(STATS_BASELINE_POLL_INTERVAL);
	}
}

/**
 * @brief Require one exact application-level unavailable result.
 *
 * @param status Response status to validate.
 * @param message Exact owning diagnostic.
 */
void expect_application_unavailable(const kinetum::common::v1::Status &status, const char *message)
{
	EXPECT_EQ(status.code(), static_cast<int32_t>(status_code::UNAVAILABLE));
	EXPECT_EQ(status.error_code(), kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
	EXPECT_EQ(status.message(), message);
	EXPECT_TRUE(status.details().empty());
}

/**
 * @brief Require transport rejection for one malformed direct invocation.
 *
 * @param status Transport status returned by the handler.
 */
void expect_null_rejection(const grpc::Status &status)
{
	EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
	EXPECT_EQ(status.error_message(), "null request or response");
}

/**
 * @brief Exercise every live-transition handler over one exact completed identity.
 *
 * @param owner Runtime owner that services the coordinator mailbox.
 * @param service Merged production service under test.
 */
void expect_live_transition_completion(packet_runtime_test_owner &owner, dataplane_control_service &service)
{
	grpc::ServerContext bootstrap_context;
	kinetum::dataplane::v1::BootstrapConfigSnapshotResponse bootstrap_response;
	const auto bootstrap_status = owner.run_control_producer([&]() {
		return service.BootstrapConfigSnapshot(&bootstrap_context, &owner.bootstrap_request(),
						       &bootstrap_response);
	});
	ASSERT_TRUE(bootstrap_status.ok());
	expect_application_success(bootstrap_response.status());

	grpc::ServerContext prepare_context;
	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare_request;
	kinetum::dataplane::v1::PrepareConfigSnapshotResponse prepare_response;
	prepare_request.mutable_snapshot()->CopyFrom(owner.bootstrap_request().snapshot());
	prepare_request.mutable_snapshot()->set_snapshot_id("service-transition-2");
	prepare_request.mutable_snapshot()->set_revision(2);
	prepare_request.mutable_snapshot()->set_created_unix_ms(2);
	prepare_request.mutable_snapshot()->clear_content_hash();
	prepare_request.set_target_epoch(2u);
	prepare_request.set_idempotency_key("service-transition-key");
	prepare_request.set_mutation_sequence(2u);
	prepare_response.set_prepared_epoch(99u);
	prepare_response.set_validation_hash("poison");
	prepare_response.set_prepared_lease_deadline_unix_ms(101u);
	prepare_response.set_mutation_sequence(103u);
	prepare_response.set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	prepare_response.set_identity_resolution(
		kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT);
	prepare_response.set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE);
	auto malformed_prepare = prepare_request;
	malformed_prepare.clear_idempotency_key();
	const auto malformed_prepare_status = owner.run_control_producer([&]() {
		return service.PrepareConfigSnapshot(&prepare_context, &malformed_prepare, &prepare_response);
	});
	ASSERT_TRUE(malformed_prepare_status.ok());
	EXPECT_EQ(prepare_response.status().code(), static_cast<int32_t>(status_code::INVALID_ARGUMENT));
	EXPECT_EQ(prepare_response.status().error_code(), kinetum::common::v1::ERROR_CODE_INVALID_ARGUMENT);
	EXPECT_EQ(prepare_response.prepared_epoch(), 0u);
	EXPECT_TRUE(prepare_response.validation_hash().empty());
	EXPECT_EQ(prepare_response.prepared_lease_deadline_unix_ms(), 0u);
	EXPECT_EQ(prepare_response.mutation_sequence(), 0u);
	EXPECT_EQ(prepare_response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED);
	EXPECT_EQ(prepare_response.identity_resolution(),
		  kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_INVALID);
	EXPECT_EQ(prepare_response.failure_code(), kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);

	const auto prepare_status = owner.run_control_producer(
		[&]() { return service.PrepareConfigSnapshot(&prepare_context, &prepare_request, &prepare_response); });
	ASSERT_TRUE(prepare_status.ok());
	expect_application_success(prepare_response.status());
	EXPECT_EQ(prepare_response.prepared_epoch(), 2u);
	EXPECT_EQ(prepare_response.validation_hash().size(), common::sha256_digest{}.size());
	EXPECT_NE(prepare_response.prepared_lease_deadline_unix_ms(), 0u);
	EXPECT_EQ(prepare_response.mutation_sequence(), 2u);
	EXPECT_EQ(prepare_response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_PREPARED);
	EXPECT_EQ(prepare_response.identity_resolution(),
		  kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_ACTIVE_EXACT);
	EXPECT_EQ(prepare_response.failure_code(), kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);

	grpc::ServerContext activate_context;
	kinetum::dataplane::v1::ActivateConfigSnapshotRequest activate_request;
	kinetum::dataplane::v1::ActivateConfigSnapshotResponse activate_response;
	activate_request.set_epoch(2u);
	activate_request.set_validation_hash(prepare_response.validation_hash());
	activate_request.set_idempotency_key(prepare_request.idempotency_key());
	activate_request.set_mutation_sequence(2u);
	activate_response.set_completed_epoch(99u);
	activate_response.set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	activate_response.set_transition_duration_ns(101u);
	activate_response.set_mutation_sequence(103u);
	activate_response.set_identity_resolution(kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_INVALID);
	activate_response.set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE);
	const auto activate_status = owner.run_control_producer([&]() {
		return service.ActivateConfigSnapshot(&activate_context, &activate_request, &activate_response);
	});
	ASSERT_TRUE(activate_status.ok());
	expect_application_success(activate_response.status());
	EXPECT_EQ(activate_response.completed_epoch(), 2u);
	EXPECT_EQ(activate_response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	EXPECT_EQ(activate_response.mutation_sequence(), 2u);
	EXPECT_EQ(activate_response.identity_resolution(),
		  kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT);
	EXPECT_EQ(activate_response.failure_code(), kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);

	grpc::ServerContext abort_context;
	kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest abort_request;
	kinetum::dataplane::v1::AbortPreparedConfigSnapshotResponse abort_response;
	abort_request.set_epoch(2u);
	abort_request.set_validation_hash(prepare_response.validation_hash());
	abort_request.set_idempotency_key(prepare_request.idempotency_key());
	abort_request.set_mutation_sequence(2u);
	abort_response.set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_ABORTED);
	abort_response.set_mutation_sequence(103u);
	abort_response.set_identity_resolution(kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_INVALID);
	abort_response.set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE);
	const auto abort_status = owner.run_control_producer(
		[&]() { return service.AbortPreparedConfigSnapshot(&abort_context, &abort_request, &abort_response); });
	ASSERT_TRUE(abort_status.ok());
	expect_application_success(abort_response.status());
	EXPECT_EQ(abort_response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	EXPECT_EQ(abort_response.mutation_sequence(), 2u);
	EXPECT_EQ(abort_response.identity_resolution(),
		  kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT);
	EXPECT_EQ(abort_response.failure_code(), kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);

	grpc::ServerContext status_context;
	kinetum::dataplane::v1::GetEpochTransitionStatusRequest status_request;
	kinetum::dataplane::v1::GetEpochTransitionStatusResponse status_response;
	status_request.set_epoch(2u);
	status_request.set_validation_hash(prepare_response.validation_hash());
	status_request.set_idempotency_key(prepare_request.idempotency_key());
	status_request.set_mutation_sequence(2u);
	status_response.set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	status_response.set_from_epoch(7u);
	status_response.set_to_epoch(13u);
	status_response.set_validation_hash("poison");
	status_response.set_plan_content_hash("poison");
	status_response.set_failure_reason("poison");
	status_response.set_mutation_sequence(103u);
	status_response.set_identity_resolution(kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_INVALID);
	status_response.set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE);
	const auto status_status = owner.run_control_producer(
		[&]() { return service.GetEpochTransitionStatus(&status_context, &status_request, &status_response); });
	ASSERT_TRUE(status_status.ok());
	expect_application_success(status_response.status());
	EXPECT_EQ(status_response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	EXPECT_EQ(status_response.from_epoch(), 1u);
	EXPECT_EQ(status_response.to_epoch(), 2u);
	EXPECT_EQ(status_response.validation_hash(), prepare_response.validation_hash());
	EXPECT_EQ(status_response.plan_content_hash(), owner.runtime().transition_plan_content_hash());
	EXPECT_TRUE(status_response.failure_reason().empty());
	EXPECT_EQ(status_response.mutation_sequence(), 2u);
	EXPECT_EQ(status_response.identity_resolution(),
		  kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT);
	EXPECT_EQ(status_response.failure_code(), kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);

	prepare_request.mutable_snapshot()->set_snapshot_id("service-abort-3");
	prepare_request.mutable_snapshot()->set_revision(3);
	prepare_request.mutable_snapshot()->set_created_unix_ms(3);
	prepare_request.set_target_epoch(3u);
	prepare_request.set_mutation_sequence(3u);
	prepare_request.set_idempotency_key("service-abort-key");
	ASSERT_TRUE(owner.run_control_producer([&]() {
				 return service.PrepareConfigSnapshot(&prepare_context, &prepare_request,
								      &prepare_response);
			 }).ok());
	ASSERT_EQ(prepare_response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_PREPARED);
	abort_request.set_epoch(3u);
	abort_request.set_mutation_sequence(3u);
	abort_request.set_validation_hash(prepare_response.validation_hash());
	abort_request.set_idempotency_key(prepare_request.idempotency_key());
	ASSERT_TRUE(owner.run_control_producer([&]() {
				 return service.AbortPreparedConfigSnapshot(&abort_context, &abort_request,
									    &abort_response);
			 }).ok());
	expect_application_success(abort_response.status());
	EXPECT_EQ(abort_response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_ABORTED);
	EXPECT_EQ(abort_response.failure_code(), kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT);
}

/**
 * @brief Require uniform null handling across every merged handler.
 *
 * @param service Merged production service under test.
 */
void expect_all_null_inputs_rejected(dataplane_control_service &service)
{
	kinetum::dataplane::v1::BootstrapConfigSnapshotRequest bootstrap_request;
	kinetum::dataplane::v1::BootstrapConfigSnapshotResponse bootstrap_response;
	expect_null_rejection(service.BootstrapConfigSnapshot(nullptr, nullptr, &bootstrap_response));
	expect_null_rejection(service.BootstrapConfigSnapshot(nullptr, &bootstrap_request, nullptr));

	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare_request;
	kinetum::dataplane::v1::PrepareConfigSnapshotResponse prepare_response;
	expect_null_rejection(service.PrepareConfigSnapshot(nullptr, nullptr, &prepare_response));
	expect_null_rejection(service.PrepareConfigSnapshot(nullptr, &prepare_request, nullptr));

	kinetum::dataplane::v1::ActivateConfigSnapshotRequest activate_request;
	kinetum::dataplane::v1::ActivateConfigSnapshotResponse activate_response;
	expect_null_rejection(service.ActivateConfigSnapshot(nullptr, nullptr, &activate_response));
	expect_null_rejection(service.ActivateConfigSnapshot(nullptr, &activate_request, nullptr));

	kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest abort_request;
	kinetum::dataplane::v1::AbortPreparedConfigSnapshotResponse abort_response;
	expect_null_rejection(service.AbortPreparedConfigSnapshot(nullptr, nullptr, &abort_response));
	expect_null_rejection(service.AbortPreparedConfigSnapshot(nullptr, &abort_request, nullptr));

	kinetum::dataplane::v1::GetEpochTransitionStatusRequest transition_request;
	kinetum::dataplane::v1::GetEpochTransitionStatusResponse transition_response;
	expect_null_rejection(service.GetEpochTransitionStatus(nullptr, nullptr, &transition_response));
	expect_null_rejection(service.GetEpochTransitionStatus(nullptr, &transition_request, nullptr));

	kinetum::dataplane::v1::StatsRequest stats_request;
	kinetum::dataplane::v1::StatsResponse stats_response;
	expect_null_rejection(service.GetStats(nullptr, nullptr, &stats_response));
	expect_null_rejection(service.GetStats(nullptr, &stats_request, nullptr));

	kinetum::dataplane::v1::HealthRequest health_request;
	kinetum::dataplane::v1::HealthResponse health_response;
	expect_null_rejection(service.Health(nullptr, nullptr, &health_response));
	expect_null_rejection(service.Health(nullptr, &health_request, nullptr));

	kinetum::dataplane::v1::DrainRequest drain_request;
	kinetum::dataplane::v1::DrainResponse drain_response;
	expect_null_rejection(service.Drain(nullptr, nullptr, &drain_response));
	expect_null_rejection(service.Drain(nullptr, &drain_request, nullptr));

	kinetum::dataplane::v1::DrainStatusRequest drain_status_request;
	kinetum::dataplane::v1::DrainStatusResponse drain_status_response;
	expect_null_rejection(service.DrainStatus(nullptr, nullptr, &drain_status_response));
	expect_null_rejection(service.DrainStatus(nullptr, &drain_status_request, nullptr));

	kinetum::dataplane::v1::ShutdownRequest shutdown_request;
	kinetum::dataplane::v1::ShutdownResponse shutdown_response;
	expect_null_rejection(service.Shutdown(nullptr, nullptr, &shutdown_response));
	expect_null_rejection(service.Shutdown(nullptr, &shutdown_request, nullptr));

	kinetum::dataplane::v1::DumpStateRequest dump_request;
	kinetum::dataplane::v1::DumpStateResponse dump_response;
	expect_null_rejection(service.DumpState(nullptr, nullptr, &dump_response));
	expect_null_rejection(service.DumpState(nullptr, &dump_request, nullptr));
}

/**
 * @brief Poison every semantic statistics field used by the fail-closed proof.
 *
 * @param response Mutable response to poison before invocation.
 */
void poison_stats_response(kinetum::dataplane::v1::StatsResponse &response)
{
	response.mutable_telemetry()->mutable_runtime()->set_active_epoch(17u);
	response.mutable_telemetry()->mutable_engine()->set_rx_packets(101u);
	response.mutable_telemetry()->add_stages()->set_stage_id("must-be-cleared");
	response.mutable_telemetry()->add_regions()->set_region_id(7);
	response.mutable_telemetry()->add_ports()->set_logical_name("must-be-cleared");
}

/** @brief Pin health-state identities and complete runtime/logging field types. */
TEST(dataplane_control_service, health_schema_preserves_control_and_packet_ready_states)
{
	/** @brief One required health-state wire identity. */
	struct expected_state {
		const char *name;  ///< Exact declared enum spelling.
		int number;	   ///< Stable wire number.
	};
	constexpr std::array<expected_state, 9> EXPECTED_STATES{{
		{"STATE_UNSPECIFIED", 0},
		{"STATE_STARTING", 1},
		{"STATE_CONTROL_READY", 2},
		{"STATE_PACKET_READY", 3},
		{"STATE_DRAINING", 4},
		{"STATE_DRAINED", 5},
		{"STATE_STOPPING", 6},
		{"STATE_STOPPED", 7},
		{"STATE_ERROR", 8},
	}};
	const auto *descriptor = kinetum::dataplane::v1::HealthResponse::descriptor()->FindEnumTypeByName("State");
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->value_count(), static_cast<int>(EXPECTED_STATES.size()));
	for (const auto &expected : EXPECTED_STATES) {
		const auto *value = descriptor->FindValueByName(expected.name);
		ASSERT_NE(value, nullptr) << expected.name;
		EXPECT_EQ(value->number(), expected.number) << expected.name;
	}
	EXPECT_EQ(descriptor->FindValueByName("STATE_RUNNING"), nullptr);
	const auto *health = kinetum::dataplane::v1::HealthResponse::descriptor();
	ASSERT_NE(health, nullptr);
	/** @brief One exact HealthResponse field projection. */
	struct expected_health_field {
		const char *name;			       ///< Exact field spelling.
		int number;				       ///< Exact non-reused wire number.
		google::protobuf::FieldDescriptor::Type type;  ///< Exact generated field type.
	};
	constexpr std::array<expected_health_field, 8> EXPECTED_FIELDS{{
		{"state", 1, google::protobuf::FieldDescriptor::TYPE_ENUM},
		{"status", 2, google::protobuf::FieldDescriptor::TYPE_MESSAGE},
		{"active_epoch", 3, google::protobuf::FieldDescriptor::TYPE_UINT64},
		{"active_workers", 4, google::protobuf::FieldDescriptor::TYPE_UINT32},
		{"expected_workers", 5, google::protobuf::FieldDescriptor::TYPE_UINT32},
		{"version", 9, google::protobuf::FieldDescriptor::TYPE_STRING},
		{"runtime_generation", 11, google::protobuf::FieldDescriptor::TYPE_UINT64},
		{"logging", 12, google::protobuf::FieldDescriptor::TYPE_MESSAGE},
	}};
	ASSERT_EQ(health->field_count(), static_cast<int>(EXPECTED_FIELDS.size()));
	for (const auto &expected_field : EXPECTED_FIELDS) {
		const auto *field = health->FindFieldByName(expected_field.name);
		ASSERT_NE(field, nullptr) << expected_field.name;
		EXPECT_EQ(field->number(), expected_field.number) << expected_field.name;
		EXPECT_EQ(field->type(), expected_field.type) << expected_field.name;
		EXPECT_FALSE(field->is_repeated()) << expected_field.name;
		google::protobuf::FieldDescriptorProto field_schema;
		field->CopyTo(&field_schema);
		EXPECT_FALSE(field_schema.proto3_optional()) << expected_field.name;
	}
	EXPECT_EQ(health->FindFieldByName("logging")->message_type(), kinetum::common::v1::LoggingStatus::descriptor());
	for (const char *removed :
	     {"last_epoch", "memory_used_bytes", "memory_limit_bytes", "uptime_seconds", "build_info"}) {
		EXPECT_EQ(health->FindFieldByName(removed), nullptr) << removed;
	}
	EXPECT_EQ(health->reserved_range_count(), 0);
	EXPECT_EQ(health->reserved_name_count(), 0);
}

/** @brief Prove Health reports only the coherent CONTROL_READY publication. */
TEST_F(DataplaneControlServiceTest, health_reports_exact_control_ready_generation)
{
	dataplane_control_service service(owner_->runtime());
	grpc::ServerContext context;
	kinetum::dataplane::v1::HealthRequest request;
	kinetum::dataplane::v1::HealthResponse response;
	ASSERT_TRUE(service.Health(&context, &request, &response).ok());
	expect_application_success(response.status());
	EXPECT_EQ(response.state(), kinetum::dataplane::v1::HealthResponse::STATE_CONTROL_READY);
	EXPECT_EQ(response.active_epoch(), 0u);
	EXPECT_NE(response.runtime_generation(), 0u);
	EXPECT_EQ(response.active_workers(), 0u);
	EXPECT_NE(response.expected_workers(), 0u);
	EXPECT_FALSE(response.version().empty());

	request.GetReflection()->MutableUnknownFields(&request)->AddVarint(99, 1u);
	response.set_active_epoch(17u);
	response.set_runtime_generation(19u);
	ASSERT_TRUE(service.Health(&context, &request, &response).ok());
	EXPECT_EQ(response.status().code(), static_cast<int32_t>(status_code::INVALID_ARGUMENT));
	EXPECT_EQ(response.state(), kinetum::dataplane::v1::HealthResponse::STATE_ERROR);
	EXPECT_EQ(response.active_epoch(), 0u);
	EXPECT_EQ(response.runtime_generation(), 0u);
	EXPECT_FALSE(response.version().empty());
}

/** @brief Prove wire bootstrap publishes the exact activated identity. */
TEST_F(DataplaneControlServiceTest, exact_bootstrap_maps_complete_packet_ready_result)
{
	dataplane_control_service service(owner_->runtime());
	grpc::ServerContext bootstrap_context;
	kinetum::dataplane::v1::BootstrapConfigSnapshotResponse bootstrap_response;
	const auto bootstrap_status = owner_->run_control_producer([&]() {
		return service.BootstrapConfigSnapshot(&bootstrap_context, &owner_->bootstrap_request(),
						       &bootstrap_response);
	});
	ASSERT_TRUE(bootstrap_status.ok());
	expect_application_success(bootstrap_response.status());
	EXPECT_EQ(bootstrap_response.restored_epoch(), owner_->bootstrap_request().active_epoch());
	EXPECT_EQ(bootstrap_response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	EXPECT_EQ(bootstrap_response.allocated_epoch_high_watermark(),
		  owner_->bootstrap_request().allocated_epoch_high_watermark());
	EXPECT_EQ(bootstrap_response.mutation_sequence_high_watermark(),
		  owner_->bootstrap_request().mutation_sequence_high_watermark());
	auto digest_or = common::decode_sha256_digest_claim(owner_->bootstrap_request().snapshot().content_hash(),
							    "ConfigSnapshot.content_hash");
	ASSERT_TRUE(digest_or.is_ok()) << digest_or.error().message();
	EXPECT_EQ(bootstrap_response.validation_hash(),
		  std::string(reinterpret_cast<const char *>(digest_or->data()), digest_or->size()));

	grpc::ServerContext health_context;
	kinetum::dataplane::v1::HealthRequest health_request;
	kinetum::dataplane::v1::HealthResponse health_response;
	ASSERT_TRUE(service.Health(&health_context, &health_request, &health_response).ok());
	expect_application_success(health_response.status());
	EXPECT_EQ(health_response.state(), kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY);
	EXPECT_EQ(health_response.active_epoch(), owner_->bootstrap_request().active_epoch());
	EXPECT_NE(health_response.runtime_generation(), 0u);
	EXPECT_NE(health_response.active_workers(), 0u);
	EXPECT_EQ(health_response.active_workers(), health_response.expected_workers());
}

/** @brief Prove malformed bootstrap maps status only and leaves control readiness. */
TEST_F(DataplaneControlServiceTest, malformed_bootstrap_clears_every_result_field)
{
	dataplane_control_service service(owner_->runtime());
	auto malformed = owner_->bootstrap_request();
	malformed.clear_idempotency_key();
	grpc::ServerContext context;
	kinetum::dataplane::v1::BootstrapConfigSnapshotResponse response;
	response.set_restored_epoch(17u);
	response.set_validation_hash("poison");
	response.set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	response.set_allocated_epoch_high_watermark(19u);
	response.set_mutation_sequence_high_watermark(23u);
	const auto malformed_status = owner_->run_control_producer(
		[&]() { return service.BootstrapConfigSnapshot(&context, &malformed, &response); });
	ASSERT_TRUE(malformed_status.ok());
	EXPECT_EQ(response.status().code(), static_cast<int32_t>(status_code::DATA_LOSS));
	EXPECT_EQ(response.status().error_code(), kinetum::common::v1::ERROR_CODE_DATA_LOSS);
	EXPECT_EQ(response.restored_epoch(), 0u);
	EXPECT_TRUE(response.validation_hash().empty());
	EXPECT_EQ(response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED);
	EXPECT_EQ(response.allocated_epoch_high_watermark(), 0u);
	EXPECT_EQ(response.mutation_sequence_high_watermark(), 0u);
}

/** @brief Prove a second Bootstrap maps permanent post-readiness refusal. */
TEST_F(DataplaneControlServiceTest, post_ready_bootstrap_is_status_only_unavailable)
{
	dataplane_control_service service(owner_->runtime());
	grpc::ServerContext first_context;
	kinetum::dataplane::v1::BootstrapConfigSnapshotResponse first_response;
	const auto first_status = owner_->run_control_producer([&]() {
		return service.BootstrapConfigSnapshot(&first_context, &owner_->bootstrap_request(), &first_response);
	});
	ASSERT_TRUE(first_status.ok());
	expect_application_success(first_response.status());

	grpc::ServerContext retry_context;
	kinetum::dataplane::v1::BootstrapConfigSnapshotResponse retry_response;
	retry_response.set_restored_epoch(99u);
	retry_response.set_validation_hash("poison");
	retry_response.set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
	const auto retry_status = owner_->run_control_producer([&]() {
		return service.BootstrapConfigSnapshot(&retry_context, &owner_->bootstrap_request(), &retry_response);
	});
	ASSERT_TRUE(retry_status.ok());
	EXPECT_EQ(retry_response.status().code(), static_cast<int32_t>(status_code::UNAVAILABLE));
	EXPECT_EQ(retry_response.status().error_code(), kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
	EXPECT_EQ(retry_response.restored_epoch(), 0u);
	EXPECT_TRUE(retry_response.validation_hash().empty());
	EXPECT_EQ(retry_response.transition_state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED);
}

/** @brief Map and log exact mutation outcomes while status reads remain quiet. */
TEST_F(DataplaneControlServiceTest, live_transition_rpcs_map_exact_runtime_observations)
{
	kinetum::test_support::log_stderr_capture capture;
	ASSERT_TRUE(capture.valid());
	dataplane_control_service service(owner_->runtime());
	expect_live_transition_completion(*owner_, service);
	std::string output;
	ASSERT_TRUE(capture.finish(output));
	EXPECT_NE(output.find("dp.bootstrap.completed"), std::string::npos) << output;
	EXPECT_NE(output.find("snapshot=service-transition-2 revision=2 mutation_sequence=2 target_epoch=2"),
		  std::string::npos)
		<< output;
	EXPECT_NE(
		output.find(
			"operation=prepare mutation_sequence=2 target_epoch=2 status=INVALID_ARGUMENT resolution=INVALID state=UNSPECIFIED"),
		std::string::npos)
		<< output;
	EXPECT_NE(
		output.find(
			"operation=prepare mutation_sequence=2 target_epoch=2 status=OK resolution=ACTIVE_EXACT state=PREPARED"),
		std::string::npos)
		<< output;
	EXPECT_NE(
		output.find(
			"operation=activate mutation_sequence=2 target_epoch=2 status=OK resolution=TERMINAL_EXACT state=COMPLETE"),
		std::string::npos)
		<< output;
	EXPECT_NE(
		output.find(
			"operation=abort mutation_sequence=2 target_epoch=2 status=OK resolution=TERMINAL_EXACT state=COMPLETE"),
		std::string::npos)
		<< output;
	std::size_t records = 0u;
	for (std::size_t position = output.find(" dp.transition.result "); position != std::string::npos;
	     position = output.find(" dp.transition.result ", position + 1u)) {
		++records;
	}
	EXPECT_EQ(records, 6u) << output;
	EXPECT_NE(
		output.find(
			"operation=abort mutation_sequence=3 target_epoch=3 status=OK resolution=TERMINAL_EXACT state=ABORTED failure=EXPLICIT_ABORT"),
		std::string::npos)
		<< output;
	EXPECT_EQ(output.find(" [ERROR] "), std::string::npos) << output;
}

/** @brief Prove every direct handler applies the same null-input contract. */
TEST_F(DataplaneControlServiceTest, all_rpc_handlers_reject_null_inputs_uniformly)
{
	dataplane_control_service service(owner_->runtime());
	expect_all_null_inputs_rejected(service);
}

/** @brief Prove statistics cannot fabricate success at CONTROL_READY. */
TEST_F(DataplaneControlServiceTest, stats_are_status_only_unavailable_at_control_ready)
{
	dataplane_control_service service(owner_->runtime());
	grpc::ServerContext context;
	kinetum::dataplane::v1::StatsRequest request;
	request.mutable_selection()->set_include_stage_stats(true);
	request.mutable_selection()->set_include_region_epoch_stats(true);
	request.mutable_selection()->set_include_port_stats(true);
	kinetum::dataplane::v1::StatsResponse response;
	poison_stats_response(response);
	ASSERT_TRUE(service.GetStats(&context, &request, &response).ok());
	expect_application_unavailable(response.status(), PACKET_TELEMETRY_UNAVAILABLE);
	EXPECT_FALSE(response.has_telemetry());
}

/** @brief Prove packet readiness publishes one complete mandatory observation. */
TEST_F(DataplaneControlServiceTest, stats_publish_complete_operator_telemetry_after_packet_ready)
{
	ASSERT_TRUE(owner_->bootstrap().is_ok());
	dataplane_control_service service(owner_->runtime());
	kinetum::dataplane::v1::StatsRequest request;
	request.mutable_selection();
	kinetum::dataplane::v1::StatsResponse response;
	poison_stats_response(response);
	ASSERT_TRUE(await_stats_baseline(service, request, response));
	expect_application_success(response.status());
	ASSERT_TRUE(response.has_telemetry());
	EXPECT_EQ(response.telemetry().runtime().active_epoch(), owner_->bootstrap_request().active_epoch());
	EXPECT_NE(response.telemetry().runtime().runtime_generation(), 0u);
	EXPECT_EQ(response.telemetry().transition().state(), kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE);
	EXPECT_EQ(response.telemetry().protocol_faults().counters_size(), 13);
	EXPECT_FALSE(response.telemetry().protocol_faults().transition_success_blocked());
}

/** @brief Prove every selected family is complete and availability-qualified. */
TEST_F(DataplaneControlServiceTest, stats_selected_families_use_one_generation_scoped_source)
{
	ASSERT_TRUE(owner_->bootstrap().is_ok());
	dataplane_control_service service(owner_->runtime());
	kinetum::dataplane::v1::StatsRequest request;
	auto *selection = request.mutable_selection();
	selection->set_include_stage_stats(true);
	selection->set_include_module_metrics(true);
	selection->set_include_module_health(true);
	selection->set_include_worker_epoch_stats(true);
	selection->set_include_region_epoch_stats(true);
	selection->set_include_boundary_epoch_stats(true);
	selection->set_include_stream_stats(true);
	selection->set_include_storage_domain_stats(true);
	selection->set_include_port_stats(true);
	selection->set_include_topology_stats(true);
	kinetum::dataplane::v1::StatsResponse response;
	ASSERT_TRUE(await_stats_baseline(service, request, response));
	expect_application_success(response.status());
	ASSERT_TRUE(common::validate_successful_dataplane_stats_response(response, *selection).is_ok());
	const auto &telemetry = response.telemetry();
	EXPECT_EQ(telemetry.workers_size(), static_cast<int>(telemetry.transition().execution_participant_count()));
	EXPECT_EQ(telemetry.regions_size(), static_cast<int>(telemetry.transition().region_count()));
	EXPECT_EQ(telemetry.boundaries_size(), static_cast<int>(telemetry.transition().boundary_count()));
	for (const auto &stream : telemetry.streams()) {
		EXPECT_NE(stream.published_monotonic_ns(), 0u);
		EXPECT_TRUE(stream.has_packets());
		EXPECT_TRUE(stream.has_bytes());
		EXPECT_TRUE(stream.has_rejected_packets());
	}
	for (const auto &storage : telemetry.storage_domains()) {
		const bool available = storage.observation_state() ==
					       kinetum::telemetry::v1::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT ||
				       storage.observation_state() ==
					       kinetum::telemetry::v1::PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE;
		EXPECT_EQ(storage.has_in_use(), available);
	}
}

}  // namespace
}  // namespace kinetum::dp
