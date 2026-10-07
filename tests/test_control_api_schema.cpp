// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_control_api_schema.cpp
 * @brief Exact first-release ControlService and snapshot wire-schema tests.
 * @author Fleming Patel
 *
 * These tests pin the exact compact contract: removed producerless fields have
 * no descriptor, revision CAS uses presence, bounded pagination has one wire
 * shape, and the service exposes exactly nine RPCs.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <initializer_list>
#include <string>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>

#include "gen/kinetum/control/v1/control.pb.h"
#include "src/common/protobuf_contract.hpp"

namespace kinetum::cp
{
namespace
{

/** Generated protobuf field taxonomy used by independent schema expectations. */
using field_type = google::protobuf::FieldDescriptor::Type;

/** @brief One exact generated field projection. */
struct expected_field {
	const char *name;      ///< Exact field spelling.
	int number;	       ///< Exact non-reused wire number.
	field_type type;       ///< Exact protobuf wire-facing type.
	bool repeated;	       ///< Whether the field has repeated wire cardinality.
	bool proto3_optional;  ///< Whether proto3 optional owns presence.
};

/** @brief One exact generated RPC method projection. */
struct expected_method {
	const char *name;    ///< Exact method spelling.
	const char *input;   ///< Exact fully qualified request type.
	const char *output;  ///< Exact fully qualified response type.
};

/**
 * @brief Require one message to match an exact field projection.
 * @tparam count Number of expected fields.
 * @param descriptor Generated message descriptor.
 * @param expected Expected fields in declaration order.
 */
template <std::size_t count>
void expect_message(const google::protobuf::Descriptor *descriptor, const std::array<expected_field, count> &expected)
{
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->field_count(), static_cast<int>(expected.size()));
	EXPECT_EQ(descriptor->reserved_range_count(), 0);
	EXPECT_EQ(descriptor->reserved_name_count(), 0);
	for (std::size_t index = 0; index < expected.size(); ++index) {
		const auto *field = descriptor->field(static_cast<int>(index));
		ASSERT_NE(field, nullptr);
		EXPECT_EQ(field->name(), expected[index].name);
		EXPECT_EQ(field->number(), expected[index].number);
		EXPECT_EQ(field->type(), expected[index].type);
		EXPECT_EQ(field->is_repeated(), expected[index].repeated);
		google::protobuf::FieldDescriptorProto field_schema;
		field->CopyTo(&field_schema);
		EXPECT_EQ(field_schema.proto3_optional(), expected[index].proto3_optional);
	}
}

/** @brief Pin compact snapshot messages and removed state fields. */
TEST(control_api_schema, snapshot_messages_have_one_compact_state_free_authority)
{
	constexpr std::array<expected_field, 9> SNAPSHOT_FIELDS{{
		{"snapshot_id", 1, field_type::TYPE_STRING, false, false},
		{"revision", 2, field_type::TYPE_INT64, false, false},
		{"created_unix_ms", 3, field_type::TYPE_INT64, false, false},
		{"modules", 4, field_type::TYPE_MESSAGE, true, false},
		{"description", 7, field_type::TYPE_STRING, false, false},
		{"author", 8, field_type::TYPE_STRING, false, false},
		{"parent_snapshot_id", 9, field_type::TYPE_STRING, false, false},
		{"labels", 10, field_type::TYPE_MESSAGE, true, false},
		{"content_hash", 11, field_type::TYPE_STRING, false, false},
	}};
	constexpr std::array<expected_field, 6> INFO_FIELDS{{
		{"snapshot_id", 1, field_type::TYPE_STRING, false, false},
		{"revision", 2, field_type::TYPE_INT64, false, false},
		{"created_unix_ms", 3, field_type::TYPE_INT64, false, false},
		{"is_active", 4, field_type::TYPE_BOOL, false, false},
		{"description", 6, field_type::TYPE_STRING, false, false},
		{"author", 7, field_type::TYPE_STRING, false, false},
	}};
	expect_message(kinetum::control::v1::ConfigSnapshot::descriptor(), SNAPSHOT_FIELDS);
	expect_message(kinetum::control::v1::SnapshotInfo::descriptor(), INFO_FIELDS);
	EXPECT_EQ(kinetum::control::v1::ConfigSnapshot::descriptor()->FindFieldByName("state"), nullptr);
	EXPECT_EQ(kinetum::control::v1::SnapshotInfo::descriptor()->FindFieldByName("state"), nullptr);
	EXPECT_EQ(kinetum::control::v1::ConfigSnapshot::descriptor()->file()->FindEnumTypeByName("SnapshotState"),
		  nullptr);
}

/** @brief Pin pagination, removed request authority, and revision presence. */
TEST(control_api_schema, mutation_and_listing_requests_are_exact)
{
	constexpr std::array<expected_field, 2> LIST_REQUEST{{
		{"page_size", 1, field_type::TYPE_UINT32, false, false},
		{"page_token", 2, field_type::TYPE_STRING, false, false},
	}};
	constexpr std::array<expected_field, 4> LIST_RESPONSE{{
		{"snapshots", 1, field_type::TYPE_MESSAGE, true, false},
		{"status", 2, field_type::TYPE_MESSAGE, false, false},
		{"next_page_token", 3, field_type::TYPE_STRING, false, false},
		{"total_count", 4, field_type::TYPE_UINT64, false, false},
	}};
	constexpr std::array<expected_field, 4> SET_REQUEST{{
		{"snapshot", 1, field_type::TYPE_MESSAGE, false, false},
		{"idempotency_key", 3, field_type::TYPE_STRING, false, false},
		{"confirm_timeout_ms", 4, field_type::TYPE_UINT64, false, false},
		{"expected_revision", 5, field_type::TYPE_INT64, false, true},
	}};
	constexpr std::array<expected_field, 4> ROLLBACK_REQUEST{{
		{"snapshot_id", 1, field_type::TYPE_STRING, false, false},
		{"module_ids", 3, field_type::TYPE_STRING, true, false},
		{"idempotency_key", 4, field_type::TYPE_STRING, false, false},
		{"expected_revision", 5, field_type::TYPE_INT64, false, true},
	}};
	expect_message(kinetum::control::v1::ListSnapshotsRequest::descriptor(), LIST_REQUEST);
	expect_message(kinetum::control::v1::ListSnapshotsResponse::descriptor(), LIST_RESPONSE);
	expect_message(kinetum::control::v1::SetConfigSnapshotRequest::descriptor(), SET_REQUEST);
	expect_message(kinetum::control::v1::RollbackRequest::descriptor(), ROLLBACK_REQUEST);
	EXPECT_EQ(kinetum::control::v1::ListSnapshotsRequest::descriptor()->FindFieldByName("state_filter"), nullptr);
	EXPECT_EQ(kinetum::control::v1::SetConfigSnapshotRequest::descriptor()->FindFieldByName("activate"), nullptr);
	EXPECT_EQ(kinetum::control::v1::RollbackRequest::descriptor()->FindFieldByName("reason"), nullptr);

	kinetum::control::v1::SetConfigSnapshotRequest set_request;
	kinetum::control::v1::RollbackRequest rollback_request;
	EXPECT_FALSE(set_request.has_expected_revision());
	EXPECT_FALSE(rollback_request.has_expected_revision());
	set_request.set_expected_revision(0);
	rollback_request.set_expected_revision(0);
	EXPECT_TRUE(set_request.has_expected_revision());
	EXPECT_TRUE(rollback_request.has_expected_revision());

	const auto *file = kinetum::control::v1::ConfigSnapshot::descriptor()->file();
	ASSERT_NE(file, nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("Tuning"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("TuningPatch"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("PatchTuningRequest"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("PatchTuningResponse"), nullptr);
	EXPECT_EQ(file->FindEnumTypeByName("AclImplementation"), nullptr);
}

/** @brief Prove removed first-release wire fields reach the unknown-field wall. */
TEST(control_api_schema, removed_snapshot_and_mutation_wire_cannot_be_reinterpreted)
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	kinetum::control::v1::SnapshotInfo info;
	kinetum::control::v1::ListSnapshotsRequest list_request;
	kinetum::control::v1::SetConfigSnapshotRequest set_request;
	kinetum::control::v1::RollbackRequest rollback_request;
	ASSERT_TRUE(snapshot.ParseFromString(std::string("\x2a\x00\x30\x01", 4u)));
	ASSERT_TRUE(info.ParseFromString(std::string("\x28\x01", 2u)));
	ASSERT_TRUE(list_request.ParseFromString(std::string("\x18\x01", 2u)));
	ASSERT_TRUE(set_request.ParseFromString(std::string("\x10\x01", 2u)));
	ASSERT_TRUE(rollback_request.ParseFromString(std::string("\x12\x01x", 3u)));
	EXPECT_FALSE(kinetum::common::reject_unknown_protobuf_fields_recursive(snapshot, "ConfigSnapshot").is_ok());
	EXPECT_FALSE(kinetum::common::reject_unknown_protobuf_fields_recursive(info, "SnapshotInfo").is_ok());
	EXPECT_FALSE(
		kinetum::common::reject_unknown_protobuf_fields_recursive(list_request, "ListSnapshotsRequest").is_ok());
	EXPECT_FALSE(kinetum::common::reject_unknown_protobuf_fields_recursive(set_request, "SetConfigSnapshotRequest")
			     .is_ok());
	EXPECT_FALSE(
		kinetum::common::reject_unknown_protobuf_fields_recursive(rollback_request, "RollbackRequest").is_ok());
}

/** @brief Pin the nine-command ControlService method inventory. */
TEST(control_api_schema, control_service_has_exactly_nine_methods)
{
	const auto *service =
		kinetum::control::v1::ConfigSnapshot::descriptor()->file()->FindServiceByName("ControlService");
	ASSERT_NE(service, nullptr);
	constexpr std::array<expected_method, 9> METHODS{{
		{"SetConfigSnapshot", "kinetum.control.v1.SetConfigSnapshotRequest",
		 "kinetum.control.v1.SetConfigSnapshotResponse"},
		{"ListSnapshots", "kinetum.control.v1.ListSnapshotsRequest",
		 "kinetum.control.v1.ListSnapshotsResponse"},
		{"GetActiveSnapshot", "kinetum.control.v1.GetActiveSnapshotRequest",
		 "kinetum.control.v1.GetActiveSnapshotResponse"},
		{"Rollback", "kinetum.control.v1.RollbackRequest", "kinetum.control.v1.RollbackResponse"},
		{"ConfirmConfig", "kinetum.control.v1.ConfirmConfigRequest",
		 "kinetum.control.v1.ConfirmConfigResponse"},
		{"ConfigureGuardrails", "kinetum.control.v1.ConfigureGuardrailsRequest",
		 "kinetum.control.v1.ConfigureGuardrailsResponse"},
		{"GetGuardrails", "kinetum.control.v1.GetGuardrailsRequest",
		 "kinetum.control.v1.GetGuardrailsResponse"},
		{"GetStats", "kinetum.control.v1.StatsRequest", "kinetum.control.v1.StatsResponse"},
		{"HealthCheck", "kinetum.control.v1.HealthCheckRequest", "kinetum.control.v1.HealthCheckResponse"},
	}};
	ASSERT_EQ(service->method_count(), static_cast<int>(METHODS.size()));
	for (std::size_t index = 0; index < METHODS.size(); ++index) {
		const auto *method = service->method(static_cast<int>(index));
		ASSERT_NE(method, nullptr);
		ASSERT_NE(method->input_type(), nullptr);
		ASSERT_NE(method->output_type(), nullptr);
		EXPECT_EQ(method->name(), METHODS[index].name);
		EXPECT_EQ(method->input_type()->full_name(), METHODS[index].input);
		EXPECT_EQ(method->output_type()->full_name(), METHODS[index].output);
	}
}

/** @brief The surviving control health enum retains its exact wire numbers. */
TEST(control_api_schema, health_status_enum_numbers_are_exact)
{
	const auto *descriptor = kinetum::control::v1::HealthCheckResponse::descriptor()->FindEnumTypeByName("Status");
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->value_count(), 3);
	EXPECT_EQ(descriptor->FindValueByName("STATUS_UNSPECIFIED")->number(), 0);
	EXPECT_EQ(descriptor->FindValueByName("STATUS_SERVING")->number(), 1);
	EXPECT_EQ(descriptor->FindValueByName("STATUS_NOT_SERVING")->number(), 2);
}

}  // namespace
}  // namespace kinetum::cp
