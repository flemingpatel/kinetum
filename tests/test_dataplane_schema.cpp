// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dataplane_schema.cpp
 * @brief Descriptor-level contract tests for the exact DP transition wire.
 * @author Fleming Patel
 *
 * These tests pin the complete compact transition schema after its breaking
 * migration. They verify every transition field number, type, cardinality,
 * enum value, and service method, and prove that no retired activation-mode or
 * epoch-only response surface remains in generated descriptors.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>

#include <google/protobuf/descriptor.h>

#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "gen/kinetum/telemetry/v1/telemetry.pb.h"

namespace kinetum::dataplane
{

namespace
{

/** Generated descriptor interface inspected against independently authored wire-shape expectations. */
using field_descriptor = google::protobuf::FieldDescriptor;

/**
 * @brief Expected protobuf field identity and wire-shape metadata.
 */
struct expected_field {
	const char *name;	      ///< Exact protobuf field name.
	int number;		      ///< Compact protobuf field number.
	field_descriptor::Type type;  ///< Protobuf scalar/message/enum type.
	bool repeated;		      ///< Whether the field is repeated.
	const char *referenced_type;  ///< Full message/enum name, or nullptr for scalars.
};

/**
 * @brief Verify one message has exactly the expected compact field schema.
 *
 * @tparam field_count Number of fields in the expected schema.
 * @param descriptor Generated protobuf message descriptor.
 * @param expected Expected fields in compact field-number order.
 */
template <std::size_t field_count>
void expect_exact_message_schema(const google::protobuf::Descriptor *descriptor,
				 const std::array<expected_field, field_count> &expected)
{
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->field_count(), static_cast<int>(expected.size()));
	EXPECT_EQ(descriptor->reserved_range_count(), 0);
	EXPECT_EQ(descriptor->reserved_name_count(), 0);

	for (const auto &field_expectation : expected) {
		const auto *field = descriptor->FindFieldByName(field_expectation.name);
		ASSERT_NE(field, nullptr) << field_expectation.name;
		EXPECT_EQ(field->number(), field_expectation.number) << field_expectation.name;
		EXPECT_EQ(field->type(), field_expectation.type) << field_expectation.name;
		EXPECT_EQ(field->is_repeated(), field_expectation.repeated) << field_expectation.name;

		if (field_expectation.type == field_descriptor::TYPE_MESSAGE) {
			ASSERT_NE(field_expectation.referenced_type, nullptr) << field_expectation.name;
			ASSERT_NE(field->message_type(), nullptr) << field_expectation.name;
			EXPECT_EQ(field->message_type()->full_name(), field_expectation.referenced_type)
				<< field_expectation.name;
		} else if (field_expectation.type == field_descriptor::TYPE_ENUM) {
			ASSERT_NE(field_expectation.referenced_type, nullptr) << field_expectation.name;
			ASSERT_NE(field->enum_type(), nullptr) << field_expectation.name;
			EXPECT_EQ(field->enum_type()->full_name(), field_expectation.referenced_type)
				<< field_expectation.name;
		} else {
			EXPECT_EQ(field_expectation.referenced_type, nullptr) << field_expectation.name;
		}
	}
}

}  // namespace

/**
 * @brief Verify Bootstrap request and response carry exact restoration authority.
 */
TEST(dataplane_schema, bootstrap_messages_are_compact_and_complete)
{
	constexpr std::array<expected_field, 6> EXPECTED_REQUEST_FIELDS{{
		{"snapshot", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.control.v1.ConfigSnapshot"},
		{"active_epoch", 2, field_descriptor::TYPE_UINT64, false, nullptr},
		{"allocated_epoch_high_watermark", 3, field_descriptor::TYPE_UINT64, false, nullptr},
		{"mutation_sequence_high_watermark", 4, field_descriptor::TYPE_UINT64, false, nullptr},
		{"plan_content_hash", 5, field_descriptor::TYPE_STRING, false, nullptr},
		{"idempotency_key", 6, field_descriptor::TYPE_STRING, false, nullptr},
	}};
	constexpr std::array<expected_field, 6> EXPECTED_RESPONSE_FIELDS{{
		{"status", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.common.v1.Status"},
		{"restored_epoch", 2, field_descriptor::TYPE_UINT64, false, nullptr},
		{"validation_hash", 3, field_descriptor::TYPE_BYTES, false, nullptr},
		{"transition_state", 4, field_descriptor::TYPE_ENUM, false,
		 "kinetum.telemetry.v1.EpochTransitionState"},
		{"allocated_epoch_high_watermark", 5, field_descriptor::TYPE_UINT64, false, nullptr},
		{"mutation_sequence_high_watermark", 6, field_descriptor::TYPE_UINT64, false, nullptr},
	}};

	expect_exact_message_schema(v1::BootstrapConfigSnapshotRequest::descriptor(), EXPECTED_REQUEST_FIELDS);
	expect_exact_message_schema(v1::BootstrapConfigSnapshotResponse::descriptor(), EXPECTED_RESPONSE_FIELDS);
}

/**
 * @brief Verify Prepare request and response carry one exact transaction identity.
 */
TEST(dataplane_schema, prepare_messages_are_compact_and_complete)
{
	constexpr std::array<expected_field, 4> EXPECTED_REQUEST_FIELDS{{
		{"snapshot", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.control.v1.ConfigSnapshot"},
		{"target_epoch", 2, field_descriptor::TYPE_UINT64, false, nullptr},
		{"idempotency_key", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"mutation_sequence", 4, field_descriptor::TYPE_UINT64, false, nullptr},
	}};
	constexpr std::array<expected_field, 8> EXPECTED_RESPONSE_FIELDS{{
		{"status", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.common.v1.Status"},
		{"prepared_epoch", 2, field_descriptor::TYPE_UINT64, false, nullptr},
		{"validation_hash", 3, field_descriptor::TYPE_BYTES, false, nullptr},
		{"prepared_lease_deadline_unix_ms", 4, field_descriptor::TYPE_UINT64, false, nullptr},
		{"mutation_sequence", 5, field_descriptor::TYPE_UINT64, false, nullptr},
		{"transition_state", 6, field_descriptor::TYPE_ENUM, false,
		 "kinetum.telemetry.v1.EpochTransitionState"},
		{"identity_resolution", 7, field_descriptor::TYPE_ENUM, false,
		 "kinetum.dataplane.v1.EpochTransitionIdentityResolution"},
		{"failure_code", 8, field_descriptor::TYPE_ENUM, false,
		 "kinetum.telemetry.v1.EpochTransitionFailureCode"},
	}};

	expect_exact_message_schema(v1::PrepareConfigSnapshotRequest::descriptor(), EXPECTED_REQUEST_FIELDS);
	expect_exact_message_schema(v1::PrepareConfigSnapshotResponse::descriptor(), EXPECTED_RESPONSE_FIELDS);
}

/**
 * @brief Verify Activate request and response carry completion rather than convergence guesses.
 */
TEST(dataplane_schema, activate_messages_are_compact_and_complete)
{
	constexpr std::array<expected_field, 4> EXPECTED_REQUEST_FIELDS{{
		{"epoch", 1, field_descriptor::TYPE_UINT64, false, nullptr},
		{"validation_hash", 2, field_descriptor::TYPE_BYTES, false, nullptr},
		{"idempotency_key", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"mutation_sequence", 4, field_descriptor::TYPE_UINT64, false, nullptr},
	}};
	constexpr std::array<expected_field, 7> EXPECTED_RESPONSE_FIELDS{{
		{"status", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.common.v1.Status"},
		{"completed_epoch", 2, field_descriptor::TYPE_UINT64, false, nullptr},
		{"transition_state", 3, field_descriptor::TYPE_ENUM, false,
		 "kinetum.telemetry.v1.EpochTransitionState"},
		{"transition_duration_ns", 4, field_descriptor::TYPE_UINT64, false, nullptr},
		{"mutation_sequence", 5, field_descriptor::TYPE_UINT64, false, nullptr},
		{"identity_resolution", 6, field_descriptor::TYPE_ENUM, false,
		 "kinetum.dataplane.v1.EpochTransitionIdentityResolution"},
		{"failure_code", 7, field_descriptor::TYPE_ENUM, false,
		 "kinetum.telemetry.v1.EpochTransitionFailureCode"},
	}};

	expect_exact_message_schema(v1::ActivateConfigSnapshotRequest::descriptor(), EXPECTED_REQUEST_FIELDS);
	expect_exact_message_schema(v1::ActivateConfigSnapshotResponse::descriptor(), EXPECTED_RESPONSE_FIELDS);
}

/**
 * @brief Verify Abort request and response preserve the exact prepared identity.
 */
TEST(dataplane_schema, abort_messages_are_compact_and_complete)
{
	constexpr std::array<expected_field, 4> EXPECTED_REQUEST_FIELDS{{
		{"epoch", 1, field_descriptor::TYPE_UINT64, false, nullptr},
		{"validation_hash", 2, field_descriptor::TYPE_BYTES, false, nullptr},
		{"idempotency_key", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"mutation_sequence", 4, field_descriptor::TYPE_UINT64, false, nullptr},
	}};
	constexpr std::array<expected_field, 5> EXPECTED_RESPONSE_FIELDS{{
		{"status", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.common.v1.Status"},
		{"transition_state", 2, field_descriptor::TYPE_ENUM, false,
		 "kinetum.telemetry.v1.EpochTransitionState"},
		{"mutation_sequence", 3, field_descriptor::TYPE_UINT64, false, nullptr},
		{"identity_resolution", 4, field_descriptor::TYPE_ENUM, false,
		 "kinetum.dataplane.v1.EpochTransitionIdentityResolution"},
		{"failure_code", 5, field_descriptor::TYPE_ENUM, false,
		 "kinetum.telemetry.v1.EpochTransitionFailureCode"},
	}};

	expect_exact_message_schema(v1::AbortPreparedConfigSnapshotRequest::descriptor(), EXPECTED_REQUEST_FIELDS);
	expect_exact_message_schema(v1::AbortPreparedConfigSnapshotResponse::descriptor(), EXPECTED_RESPONSE_FIELDS);
}

/**
 * @brief Verify Status request and response expose one exact terminal journal record.
 */
TEST(dataplane_schema, status_messages_are_compact_and_complete)
{
	constexpr std::array<expected_field, 4> EXPECTED_REQUEST_FIELDS{{
		{"epoch", 1, field_descriptor::TYPE_UINT64, false, nullptr},
		{"validation_hash", 2, field_descriptor::TYPE_BYTES, false, nullptr},
		{"idempotency_key", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"mutation_sequence", 4, field_descriptor::TYPE_UINT64, false, nullptr},
	}};
	constexpr std::array<expected_field, 13> EXPECTED_RESPONSE_FIELDS{{
		{"status", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.common.v1.Status"},
		{"transition_state", 2, field_descriptor::TYPE_ENUM, false,
		 "kinetum.telemetry.v1.EpochTransitionState"},
		{"from_epoch", 3, field_descriptor::TYPE_UINT64, false, nullptr},
		{"to_epoch", 4, field_descriptor::TYPE_UINT64, false, nullptr},
		{"validation_hash", 5, field_descriptor::TYPE_BYTES, false, nullptr},
		{"plan_content_hash", 6, field_descriptor::TYPE_STRING, false, nullptr},
		{"prepare_duration_ns", 7, field_descriptor::TYPE_UINT64, false, nullptr},
		{"commit_duration_ns", 8, field_descriptor::TYPE_UINT64, false, nullptr},
		{"retirement_duration_ns", 9, field_descriptor::TYPE_UINT64, false, nullptr},
		{"failure_reason", 10, field_descriptor::TYPE_STRING, false, nullptr},
		{"mutation_sequence", 11, field_descriptor::TYPE_UINT64, false, nullptr},
		{"identity_resolution", 12, field_descriptor::TYPE_ENUM, false,
		 "kinetum.dataplane.v1.EpochTransitionIdentityResolution"},
		{"failure_code", 13, field_descriptor::TYPE_ENUM, false,
		 "kinetum.telemetry.v1.EpochTransitionFailureCode"},
	}};

	expect_exact_message_schema(v1::GetEpochTransitionStatusRequest::descriptor(), EXPECTED_REQUEST_FIELDS);
	expect_exact_message_schema(v1::GetEpochTransitionStatusResponse::descriptor(), EXPECTED_RESPONSE_FIELDS);
}

/**
 * @brief Verify EpochTransitionState has the complete exact state machine.
 */
TEST(dataplane_schema, transition_state_values_are_compact_and_complete)
{
	/** @brief Expected protobuf enum value identity. */
	struct expected_value {
		const char *name;  ///< Exact prefixed enum value name.
		int number;	   ///< Compact enum value number.
	};
	constexpr std::array<expected_value, 11> EXPECTED_VALUES{{
		{"EPOCH_TRANSITION_STATE_UNSPECIFIED", 0},
		{"EPOCH_TRANSITION_STATE_AWAITING_BOOTSTRAP", 1},
		{"EPOCH_TRANSITION_STATE_BOOTSTRAPPING", 2},
		{"EPOCH_TRANSITION_STATE_PREPARING", 3},
		{"EPOCH_TRANSITION_STATE_PREPARED", 4},
		{"EPOCH_TRANSITION_STATE_COMMITTING", 5},
		{"EPOCH_TRANSITION_STATE_RETIRING", 6},
		{"EPOCH_TRANSITION_STATE_COMPLETE", 7},
		{"EPOCH_TRANSITION_STATE_FAILED_STOP", 8},
		{"EPOCH_TRANSITION_STATE_ABORTED", 9},
		{"EPOCH_TRANSITION_STATE_IDLE", 10},
	}};

	const auto *descriptor = kinetum::telemetry::v1::RuntimeTelemetry::descriptor()->file()->FindEnumTypeByName(
		"EpochTransitionState");
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->value_count(), static_cast<int>(EXPECTED_VALUES.size()));
	for (const auto &expected : EXPECTED_VALUES) {
		const auto *value = descriptor->FindValueByName(expected.name);
		ASSERT_NE(value, nullptr) << expected.name;
		EXPECT_EQ(value->number(), expected.number) << expected.name;
	}
}

/** @brief Verify identity-resolution wire values mirror the complete internal relation. */
TEST(dataplane_schema, transition_identity_resolution_values_are_compact_and_complete)
{
	/** @brief Expected protobuf enum value identity. */
	struct expected_value {
		const char *name;  ///< Exact prefixed enum value name.
		int number;	   ///< Compact enum value number.
	};
	constexpr std::array<expected_value, 13> EXPECTED_VALUES{{
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_UNSPECIFIED", 0},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_INVALID", 1},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_ADMISSIBLE", 2},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_ACTIVE_EXACT", 3},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT", 4},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_STALE", 5},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_INCONSISTENT", 6},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_EXPIRED_RETRY", 7},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_IDENTITY_CONFLICT", 8},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_UNKNOWN_FUTURE", 9},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_OVERLAP", 10},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_POLICY_DISABLED", 11},
		{"EPOCH_TRANSITION_IDENTITY_RESOLUTION_STATE_UNAVAILABLE", 12},
	}};
	const auto *descriptor = v1::BootstrapConfigSnapshotRequest::descriptor()->file()->FindEnumTypeByName(
		"EpochTransitionIdentityResolution");
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->value_count(), static_cast<int>(EXPECTED_VALUES.size()));
	for (const auto &expected : EXPECTED_VALUES) {
		const auto *value = descriptor->FindValueByName(expected.name);
		ASSERT_NE(value, nullptr) << expected.name;
		EXPECT_EQ(value->number(), expected.number) << expected.name;
	}
}

/** @brief Verify failure-code wire values mirror every exact internal cause. */
TEST(dataplane_schema, transition_failure_code_values_are_compact_and_complete)
{
	/** @brief Expected protobuf enum value identity. */
	struct expected_value {
		const char *name;  ///< Exact prefixed enum value name.
		int number;	   ///< Compact enum value number.
	};
	constexpr std::array<expected_value, 15> EXPECTED_VALUES{{
		{"EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED", 0},
		{"EPOCH_TRANSITION_FAILURE_CODE_NONE", 1},
		{"EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT", 2},
		{"EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT", 3},
		{"EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE", 4},
		{"EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED", 5},
		{"EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED", 6},
		{"EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED", 7},
		{"EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED", 8},
		{"EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION", 9},
		{"EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED", 10},
		{"EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE", 11},
		{"EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED", 12},
		{"EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN", 13},
		{"EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT", 14},
	}};
	const auto *descriptor = kinetum::telemetry::v1::RuntimeTelemetry::descriptor()->file()->FindEnumTypeByName(
		"EpochTransitionFailureCode");
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->value_count(), static_cast<int>(EXPECTED_VALUES.size()));
	for (const auto &expected : EXPECTED_VALUES) {
		const auto *value = descriptor->FindValueByName(expected.name);
		ASSERT_NE(value, nullptr) << expected.name;
		EXPECT_EQ(value->number(), expected.number) << expected.name;
	}
}

/** @brief Verify DP statistics wrap the one shared telemetry authority only. */
TEST(dataplane_schema, stats_messages_wrap_shared_telemetry_exactly)
{
	constexpr std::array<expected_field, 1> EXPECTED_REQUEST_FIELDS{{
		{"selection", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.telemetry.v1.TelemetrySelection"},
	}};
	constexpr std::array<expected_field, 2> EXPECTED_RESPONSE_FIELDS{{
		{"status", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.common.v1.Status"},
		{"telemetry", 2, field_descriptor::TYPE_MESSAGE, false, "kinetum.telemetry.v1.RuntimeTelemetry"},
	}};
	expect_exact_message_schema(v1::StatsRequest::descriptor(), EXPECTED_REQUEST_FIELDS);
	expect_exact_message_schema(v1::StatsResponse::descriptor(), EXPECTED_RESPONSE_FIELDS);
}

/**
 * @brief Verify DataplaneService exposes the complete transition and runtime surface.
 */
TEST(dataplane_schema, service_methods_are_compact_and_complete)
{
	/** @brief Expected protobuf service method identity. */
	struct expected_method {
		const char *name;    ///< Exact RPC method name.
		const char *input;   ///< Full input message name.
		const char *output;  ///< Full output message name.
	};
	constexpr std::array<expected_method, 11> EXPECTED_METHODS{{
		{"BootstrapConfigSnapshot", "kinetum.dataplane.v1.BootstrapConfigSnapshotRequest",
		 "kinetum.dataplane.v1.BootstrapConfigSnapshotResponse"},
		{"PrepareConfigSnapshot", "kinetum.dataplane.v1.PrepareConfigSnapshotRequest",
		 "kinetum.dataplane.v1.PrepareConfigSnapshotResponse"},
		{"ActivateConfigSnapshot", "kinetum.dataplane.v1.ActivateConfigSnapshotRequest",
		 "kinetum.dataplane.v1.ActivateConfigSnapshotResponse"},
		{"AbortPreparedConfigSnapshot", "kinetum.dataplane.v1.AbortPreparedConfigSnapshotRequest",
		 "kinetum.dataplane.v1.AbortPreparedConfigSnapshotResponse"},
		{"GetEpochTransitionStatus", "kinetum.dataplane.v1.GetEpochTransitionStatusRequest",
		 "kinetum.dataplane.v1.GetEpochTransitionStatusResponse"},
		{"GetStats", "kinetum.dataplane.v1.StatsRequest", "kinetum.dataplane.v1.StatsResponse"},
		{"Health", "kinetum.dataplane.v1.HealthRequest", "kinetum.dataplane.v1.HealthResponse"},
		{"Drain", "kinetum.dataplane.v1.DrainRequest", "kinetum.dataplane.v1.DrainResponse"},
		{"DrainStatus", "kinetum.dataplane.v1.DrainStatusRequest", "kinetum.dataplane.v1.DrainStatusResponse"},
		{"Shutdown", "kinetum.dataplane.v1.ShutdownRequest", "kinetum.dataplane.v1.ShutdownResponse"},
		{"DumpState", "kinetum.dataplane.v1.DumpStateRequest", "kinetum.dataplane.v1.DumpStateResponse"},
	}};

	const auto *service =
		v1::BootstrapConfigSnapshotRequest::descriptor()->file()->FindServiceByName("DataplaneService");
	ASSERT_NE(service, nullptr);
	ASSERT_EQ(service->method_count(), static_cast<int>(EXPECTED_METHODS.size()));
	for (const auto &expected : EXPECTED_METHODS) {
		const auto *method = service->FindMethodByName(expected.name);
		ASSERT_NE(method, nullptr) << expected.name;
		ASSERT_NE(method->input_type(), nullptr) << expected.name;
		ASSERT_NE(method->output_type(), nullptr) << expected.name;
		EXPECT_EQ(method->input_type()->full_name(), expected.input) << expected.name;
		EXPECT_EQ(method->output_type()->full_name(), expected.output) << expected.name;
	}
}

/**
 * @brief Verify every retired transition wire surface is absent.
 */
TEST(dataplane_schema, removed_transition_surfaces_are_absent)
{
	const auto *file = v1::BootstrapConfigSnapshotRequest::descriptor()->file();
	ASSERT_NE(file, nullptr);
	EXPECT_EQ(file->FindEnumTypeByName("ActivationMode"), nullptr);

	const auto *prepare_response = v1::PrepareConfigSnapshotResponse::descriptor();
	const auto *activate_request = v1::ActivateConfigSnapshotRequest::descriptor();
	const auto *activate_response = v1::ActivateConfigSnapshotResponse::descriptor();
	ASSERT_NE(prepare_response, nullptr);
	ASSERT_NE(activate_request, nullptr);
	ASSERT_NE(activate_response, nullptr);
	EXPECT_EQ(prepare_response->FindFieldByName("validation_warnings"), nullptr);
	EXPECT_EQ(activate_request->FindFieldByName("mode"), nullptr);
	EXPECT_EQ(activate_response->FindFieldByName("activated_epoch"), nullptr);
	EXPECT_EQ(activate_response->FindFieldByName("converged"), nullptr);
	EXPECT_EQ(activate_response->FindFieldByName("activation_duration_ns"), nullptr);
	for (const char *removed :
	     {"StageStats", "RegionStats", "QueueStats", "NatSessionStats", "PortStats", "StreamStats",
	      "StorageDomainStats", "TrafficSteeringStats", "FlowAffinityDomainStats", "BoundaryTelemetry"}) {
		EXPECT_EQ(file->FindMessageTypeByName(removed), nullptr) << removed;
	}
}

}  // namespace kinetum::dataplane
