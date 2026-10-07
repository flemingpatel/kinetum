// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_gluon_plan_schema.cpp
 * @brief Descriptor-level contract tests for the compact Gluon deployment plan.
 * @author Fleming Patel
 *
 * These tests pin the complete compact DeploymentPlan schema after its
 * breaking compact migration. They verify every owned field number, type, and
 * cardinality, presence, and oneof ownership. They also prove that neither the
 * removed global-backend schema nor a retired epoch-only control surface
 * remains in the generated descriptors.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <initializer_list>
#include <string>
#include <string_view>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>

#include "gen/kinetum/gluon/v1/bindings.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/protobuf_contract.hpp"

namespace kinetum::gluon
{

namespace
{

/** Generated descriptor interface inspected against independently authored wire-shape expectations. */
using field_descriptor = google::protobuf::FieldDescriptor;

/**
 * @brief Expected protobuf field identity and wire-shape metadata.
 */
struct expected_field {
	const char *name;		  ///< Exact protobuf field name.
	int number;			  ///< Compact protobuf field number.
	field_descriptor::Type type;	  ///< Protobuf scalar/message/enum type.
	bool repeated;			  ///< Whether the field is repeated.
	const char *referenced_type;	  ///< Full message/enum name, or nullptr for scalars.
	bool proto3_optional{false};	  ///< Whether proto3 optional owns scalar presence.
	const char *oneof_name{nullptr};  ///< Explicit oneof name, or nullptr.
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
		google::protobuf::FieldDescriptorProto field_schema;
		field->CopyTo(&field_schema);
		EXPECT_EQ(field_schema.proto3_optional(), field_expectation.proto3_optional) << field_expectation.name;
		const bool expected_presence = !field_expectation.repeated &&
					       (field_expectation.type == field_descriptor::TYPE_MESSAGE ||
						field_expectation.proto3_optional ||
						field_expectation.oneof_name != nullptr);
		EXPECT_EQ(field->has_presence(), expected_presence) << field_expectation.name;

		if (field_expectation.oneof_name != nullptr) {
			ASSERT_NE(field->containing_oneof(), nullptr) << field_expectation.name;
			EXPECT_EQ(field->containing_oneof()->name(), field_expectation.oneof_name)
				<< field_expectation.name;
		} else if (!field_expectation.proto3_optional) {
			EXPECT_EQ(field->containing_oneof(), nullptr) << field_expectation.name;
		}

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
 * @brief Verify DeploymentPlan preserves every live number and uses a fresh context-domain field.
 */
TEST(gluon_plan_schema, deployment_plan_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 20> EXPECTED_FIELDS{{
		{"plan_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"pipeline", 2, field_descriptor::TYPE_MESSAGE, false, "kinetum.axiom.v1.Pipeline"},
		{"regions", 3, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.Region"},
		{"boundaries", 4, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.BoundaryPlacement"},
		{"epoch_transition_plan", 5, field_descriptor::TYPE_MESSAGE, false,
		 "kinetum.gluon.v1.EpochTransitionPlan"},
		{"metadata", 6, field_descriptor::TYPE_MESSAGE, false, "kinetum.gluon.v1.PlanMetadata"},
		{"process_facility_instances", 7, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.ProcessFacilityInstance"},
		{"io_driver_instances", 8, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.IoDriverInstance"},
		{"packet_storage_domains", 9, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.PacketStorageDomain"},
		{"execution_provider_instances", 10, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.ExecutionProviderInstance"},
		{"storage_transitions", 11, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.StorageTransition"},
		{"ports", 12, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.PortConfig"},
		{"execution_lanes", 13, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.ExecutionLane"},
		{"stage_instances", 14, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.StageInstance"},
		{"io_streams", 15, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.IoStream"},
		{"traffic_steering_profiles", 16, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.TrafficSteeringProfile"},
		{"worker_placements", 18, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.WorkerPlacement"},
		{"content_hash", 19, field_descriptor::TYPE_STRING, false, nullptr},
		{"runtime_service_placements", 20, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.RuntimeServicePlacement"},
		{"module_context_domains", 21, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.ModuleContextDomain"},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::DeploymentPlan::descriptor(), EXPECTED_FIELDS);
	EXPECT_EQ(kinetum::gluon::v1::DeploymentPlan::descriptor()->FindFieldByNumber(17), nullptr);
}

/**
 * @brief Verify provider-instance records carry only exact typed ownership.
 */
TEST(gluon_plan_schema, provider_instance_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 2> FACILITY_FIELDS{{
		{"facility_instance_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"configuration", 2, field_descriptor::TYPE_MESSAGE, false, "google.protobuf.Any"},
	}};
	constexpr std::array<expected_field, 3> DRIVER_FIELDS{{
		{"io_driver_instance_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"facility_instance_ids", 2, field_descriptor::TYPE_STRING, true, nullptr},
		{"configuration", 3, field_descriptor::TYPE_MESSAGE, false, "google.protobuf.Any"},
	}};
	constexpr std::array<expected_field, 8> STORAGE_FIELDS{{
		{"storage_domain_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"facility_instance_ids", 2, field_descriptor::TYPE_STRING, true, nullptr},
		{"configuration", 3, field_descriptor::TYPE_MESSAGE, false, "google.protobuf.Any"},
		{"buffer_count", 4, field_descriptor::TYPE_UINT32, false, nullptr},
		{"data_room_bytes", 5, field_descriptor::TYPE_UINT32, false, nullptr},
		{"headroom_bytes", 6, field_descriptor::TYPE_UINT32, false, nullptr},
		{"alignment_bytes", 7, field_descriptor::TYPE_UINT32, false, nullptr},
		{"host_numa_node", 8, field_descriptor::TYPE_INT32, false, nullptr, true},
	}};
	constexpr std::array<expected_field, 3> EXECUTION_FIELDS{{
		{"execution_provider_instance_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"facility_instance_ids", 2, field_descriptor::TYPE_STRING, true, nullptr},
		{"configuration", 3, field_descriptor::TYPE_MESSAGE, false, "google.protobuf.Any"},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::ProcessFacilityInstance::descriptor(), FACILITY_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::IoDriverInstance::descriptor(), DRIVER_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::PacketStorageDomain::descriptor(), STORAGE_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::ExecutionProviderInstance::descriptor(), EXECUTION_FIELDS);
}

/**
 * @brief Verify plan transition endpoints have one explicit typed identity.
 */
TEST(gluon_plan_schema, packet_path_endpoint_fields_are_oneof_exact)
{
	constexpr std::array<expected_field, 2> EXPECTED_FIELDS{{
		{"io_stream_id", 1, field_descriptor::TYPE_STRING, false, nullptr, false, "endpoint"},
		{"stage_instance_id", 2, field_descriptor::TYPE_STRING, false, nullptr, false, "endpoint"},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::PacketPathEndpoint::descriptor(), EXPECTED_FIELDS);
}

/**
 * @brief Verify storage transitions carry the complete explicit handoff.
 */
TEST(gluon_plan_schema, storage_transition_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 9> EXPECTED_FIELDS{{
		{"transition_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"from_endpoint", 2, field_descriptor::TYPE_MESSAGE, false, "kinetum.gluon.v1.PacketPathEndpoint"},
		{"to_endpoint", 3, field_descriptor::TYPE_MESSAGE, false, "kinetum.gluon.v1.PacketPathEndpoint"},
		{"from_storage_domain_id", 4, field_descriptor::TYPE_STRING, false, nullptr},
		{"to_storage_domain_id", 5, field_descriptor::TYPE_STRING, false, nullptr},
		{"facility_instance_ids", 6, field_descriptor::TYPE_STRING, true, nullptr},
		{"configuration", 7, field_descriptor::TYPE_MESSAGE, false, "google.protobuf.Any"},
		{"staging_capacity", 8, field_descriptor::TYPE_UINT32, false, nullptr},
		{"staging_numa_node", 9, field_descriptor::TYPE_INT32, false, nullptr, true},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::StorageTransition::descriptor(), EXPECTED_FIELDS);
}

/**
 * @brief Verify logical ports use only exact generic and driver identities.
 */
TEST(gluon_plan_schema, port_config_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 8> EXPECTED_FIELDS{{
		{"logical_port_id", 1, field_descriptor::TYPE_UINT32, false, nullptr},
		{"logical_name", 2, field_descriptor::TYPE_STRING, false, nullptr},
		{"io_driver_instance_id", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"driver_port_id", 4, field_descriptor::TYPE_STRING, false, nullptr},
		{"direction", 5, field_descriptor::TYPE_ENUM, false, "kinetum.gluon.v1.PortDirection"},
		{"host_numa_node", 6, field_descriptor::TYPE_INT32, false, nullptr, true},
		{"mtu", 7, field_descriptor::TYPE_UINT32, false, nullptr},
		{"resolved_mac_address", 8, field_descriptor::TYPE_BYTES, false, nullptr},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::PortConfig::descriptor(), EXPECTED_FIELDS);
}

/**
 * @brief Verify stage and stream records bind exact provider ownership.
 */
TEST(gluon_plan_schema, stage_and_stream_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 10> STAGE_FIELDS{{
		{"stage_instance_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"logical_stage_id", 2, field_descriptor::TYPE_STRING, false, nullptr},
		{"lane_id", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"region_id", 4, field_descriptor::TYPE_INT32, false, nullptr},
		{"replica_index", 5, field_descriptor::TYPE_UINT32, false, nullptr},
		{"context_instance_id", 6, field_descriptor::TYPE_STRING, false, nullptr},
		{"execution_provider_instance_id", 8, field_descriptor::TYPE_STRING, false, nullptr},
		{"active_origin_storage_domain_id", 9, field_descriptor::TYPE_STRING, false, nullptr},
		{"context_memory_capacity_bytes", 10, field_descriptor::TYPE_UINT64, false, nullptr},
		{"epoch_arena_capacity_bytes", 11, field_descriptor::TYPE_UINT64, false, nullptr},
	}};
	constexpr std::array<expected_field, 11> STREAM_FIELDS{{
		{"io_stream_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"logical_port_id", 2, field_descriptor::TYPE_UINT32, false, nullptr},
		{"lane_id", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"direction", 4, field_descriptor::TYPE_ENUM, false, "kinetum.gluon.v1.IoStreamDirection"},
		{"stage_instance_id", 5, field_descriptor::TYPE_STRING, false, nullptr},
		{"steering_profile_id", 6, field_descriptor::TYPE_STRING, false, nullptr},
		{"driver_queue_id", 7, field_descriptor::TYPE_UINT32, false, nullptr},
		{"owning_worker_id", 8, field_descriptor::TYPE_STRING, false, nullptr},
		{"descriptor_count", 10, field_descriptor::TYPE_UINT32, false, nullptr},
		{"rx_storage_domain_id", 11, field_descriptor::TYPE_STRING, false, nullptr, false, "storage"},
		{"tx_storage", 12, field_descriptor::TYPE_MESSAGE, false, "kinetum.gluon.v1.TxStorageBinding", false,
		 "storage"},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::StageInstance::descriptor(), STAGE_FIELDS);
	EXPECT_EQ(kinetum::gluon::v1::StageInstance::descriptor()->FindFieldByNumber(7), nullptr);
	expect_exact_message_schema(kinetum::gluon::v1::IoStream::descriptor(), STREAM_FIELDS);
	EXPECT_EQ(kinetum::gluon::v1::IoStream::descriptor()->FindFieldByNumber(9), nullptr);
}

/** @brief Context populations replace lane-level session ownership without reusing retired fields. */
TEST(gluon_plan_schema, context_domain_and_lane_membership_are_exact)
{
	constexpr std::array<expected_field, 4> LANE_FIELDS{{
		{"lane_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"lane_index", 2, field_descriptor::TYPE_UINT32, false, nullptr},
		{"stage_instance_ids", 3, field_descriptor::TYPE_STRING, true, nullptr},
		{"io_stream_ids", 4, field_descriptor::TYPE_STRING, true, nullptr},
	}};
	constexpr std::array<expected_field, 2> DOMAIN_FIELDS{{
		{"module_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"context_instance_ids", 2, field_descriptor::TYPE_STRING, true, nullptr},
	}};
	expect_exact_message_schema(kinetum::gluon::v1::ExecutionLane::descriptor(), LANE_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::ModuleContextDomain::descriptor(), DOMAIN_FIELDS);
	EXPECT_EQ(kinetum::gluon::v1::ExecutionLane::descriptor()->FindFieldByNumber(5), nullptr);
}

/**
 * @brief Verify authoring port, queue, steering, and stream shapes are exact.
 */
TEST(gluon_plan_schema, deployment_binding_stream_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 6> PORT_FIELDS{{
		{"logical_name", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"io_driver_instance_id", 2, field_descriptor::TYPE_STRING, false, nullptr},
		{"driver_port_id", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"direction", 4, field_descriptor::TYPE_ENUM, false, "kinetum.gluon.v1.PortDirection"},
		{"host_numa_node", 5, field_descriptor::TYPE_INT32, false, nullptr, true},
		{"mtu", 6, field_descriptor::TYPE_UINT32, false, nullptr},
	}};
	constexpr std::array<expected_field, 4> QUEUE_FIELDS{{
		{"driver_queue_id", 1, field_descriptor::TYPE_UINT32, false, nullptr},
		{"descriptor_count", 2, field_descriptor::TYPE_UINT32, false, nullptr},
		{"rx_storage_domain_id", 3, field_descriptor::TYPE_STRING, false, nullptr, false, "storage"},
		{"tx_storage", 4, field_descriptor::TYPE_MESSAGE, false, "kinetum.gluon.v1.TxStorageBinding", false,
		 "storage"},
	}};
	constexpr std::array<expected_field, 4> STEERING_FIELDS{{
		{"kind", 1, field_descriptor::TYPE_ENUM, false, "kinetum.gluon.v1.TrafficSteeringKind"},
		{"symmetric", 2, field_descriptor::TYPE_BOOL, false, nullptr},
		{"hash_fields", 3, field_descriptor::TYPE_STRING, true, nullptr},
		{"hash_key", 4, field_descriptor::TYPE_BYTES, false, nullptr},
	}};
	constexpr std::array<expected_field, 4> STREAM_FIELDS{{
		{"logical_name", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"direction", 2, field_descriptor::TYPE_ENUM, false, "kinetum.gluon.v1.IoStreamDirection"},
		{"queues", 3, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.DriverQueueBinding"},
		{"steering", 5, field_descriptor::TYPE_MESSAGE, false, "kinetum.gluon.v1.TrafficSteeringBinding"},
	}};
	constexpr std::array<expected_field, 1> TX_STORAGE_FIELDS{{
		{"storage_domain_ids", 1, field_descriptor::TYPE_STRING, true, nullptr},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::LogicalPortBinding::descriptor(), PORT_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::DriverQueueBinding::descriptor(), QUEUE_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::TrafficSteeringBinding::descriptor(), STEERING_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::IoStreamBinding::descriptor(), STREAM_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::TxStorageBinding::descriptor(), TX_STORAGE_FIELDS);
	EXPECT_EQ(kinetum::gluon::v1::IoStreamBinding::descriptor()->FindFieldByNumber(4), nullptr);
}

/**
 * @brief Verify authoring stage and logical endpoint shapes are exact.
 */
TEST(gluon_plan_schema, deployment_binding_endpoint_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 2> STAGE_BINDING_FIELDS{{
		{"logical_stage_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"execution_provider_instance_id", 2, field_descriptor::TYPE_STRING, false, nullptr},
	}};
	constexpr std::array<expected_field, 3> ACTIVE_ORIGIN_FIELDS{{
		{"logical_stage_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"lane_id", 2, field_descriptor::TYPE_STRING, false, nullptr},
		{"storage_domain_id", 3, field_descriptor::TYPE_STRING, false, nullptr},
	}};
	constexpr std::array<expected_field, 4> MODULE_RESOURCE_FIELDS{{
		{"logical_stage_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"lane_id", 2, field_descriptor::TYPE_STRING, false, nullptr},
		{"context_memory_capacity_bytes", 3, field_descriptor::TYPE_UINT64, false, nullptr},
		{"epoch_arena_capacity_bytes", 4, field_descriptor::TYPE_UINT64, false, nullptr},
	}};
	constexpr std::array<expected_field, 3> IO_ENDPOINT_FIELDS{{
		{"logical_name", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"direction", 2, field_descriptor::TYPE_ENUM, false, "kinetum.gluon.v1.IoStreamDirection"},
		{"driver_queue_id", 3, field_descriptor::TYPE_UINT32, false, nullptr},
	}};
	constexpr std::array<expected_field, 2> STAGE_ENDPOINT_FIELDS{{
		{"logical_stage_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"lane_id", 2, field_descriptor::TYPE_STRING, false, nullptr},
	}};
	constexpr std::array<expected_field, 2> PACKET_ENDPOINT_FIELDS{{
		{"io", 1, field_descriptor::TYPE_MESSAGE, false, "kinetum.gluon.v1.LogicalIoEndpoint", false,
		 "endpoint"},
		{"stage", 2, field_descriptor::TYPE_MESSAGE, false, "kinetum.gluon.v1.LogicalStageEndpoint", false,
		 "endpoint"},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::StageExecutionBinding::descriptor(), STAGE_BINDING_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::ActiveOriginBinding::descriptor(), ACTIVE_ORIGIN_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::ModuleContextResourceBinding::descriptor(),
				    MODULE_RESOURCE_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::LogicalIoEndpoint::descriptor(), IO_ENDPOINT_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::LogicalStageEndpoint::descriptor(), STAGE_ENDPOINT_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::LogicalPacketPathEndpoint::descriptor(),
				    PACKET_ENDPOINT_FIELDS);
}

/**
 * @brief Verify authored transitions and the complete binding root are exact.
 */
TEST(gluon_plan_schema, deployment_binding_root_and_transition_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 9> TRANSITION_FIELDS{{
		{"transition_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"from_endpoint", 2, field_descriptor::TYPE_MESSAGE, false,
		 "kinetum.gluon.v1.LogicalPacketPathEndpoint"},
		{"to_endpoint", 3, field_descriptor::TYPE_MESSAGE, false, "kinetum.gluon.v1.LogicalPacketPathEndpoint"},
		{"from_storage_domain_id", 4, field_descriptor::TYPE_STRING, false, nullptr},
		{"to_storage_domain_id", 5, field_descriptor::TYPE_STRING, false, nullptr},
		{"facility_instance_ids", 6, field_descriptor::TYPE_STRING, true, nullptr},
		{"configuration", 7, field_descriptor::TYPE_MESSAGE, false, "google.protobuf.Any"},
		{"staging_capacity", 8, field_descriptor::TYPE_UINT32, false, nullptr},
		{"staging_numa_node", 9, field_descriptor::TYPE_INT32, false, nullptr, true},
	}};
	constexpr std::array<expected_field, 10> ROOT_FIELDS{{
		{"process_facility_instances", 1, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.ProcessFacilityInstance"},
		{"io_driver_instances", 2, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.IoDriverInstance"},
		{"packet_storage_domains", 3, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.PacketStorageDomain"},
		{"execution_provider_instances", 4, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.ExecutionProviderInstance"},
		{"logical_port_bindings", 5, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.LogicalPortBinding"},
		{"io_stream_bindings", 6, field_descriptor::TYPE_MESSAGE, true, "kinetum.gluon.v1.IoStreamBinding"},
		{"stage_execution_bindings", 7, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.StageExecutionBinding"},
		{"storage_transition_bindings", 8, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.StorageTransitionBinding"},
		{"active_origin_bindings", 9, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.ActiveOriginBinding"},
		{"module_context_resource_bindings", 10, field_descriptor::TYPE_MESSAGE, true,
		 "kinetum.gluon.v1.ModuleContextResourceBinding"},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::StorageTransitionBinding::descriptor(), TRANSITION_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::DeploymentBindings::descriptor(), ROOT_FIELDS);
}

/**
 * @brief Verify BoundaryPlacement carries exact executable ownership and bounds.
 */
TEST(gluon_plan_schema, boundary_placement_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 8> EXPECTED_FIELDS{{
		{"boundary_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"from_stage_instance_id", 2, field_descriptor::TYPE_STRING, false, nullptr},
		{"to_stage_instance_id", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"sender_worker_id", 4, field_descriptor::TYPE_STRING, false, nullptr},
		{"receiver_worker_id", 5, field_descriptor::TYPE_STRING, false, nullptr},
		{"data_ring_capacity", 6, field_descriptor::TYPE_UINT32, false, nullptr},
		{"future_output_hold_capacity", 7, field_descriptor::TYPE_UINT32, false, nullptr},
		{"data_ring_numa_node", 8, field_descriptor::TYPE_INT32, false, nullptr},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::BoundaryPlacement::descriptor(), EXPECTED_FIELDS);
}

/**
 * @brief Verify EpochTransitionPlan carries only bounded typed policy.
 */
TEST(gluon_plan_schema, epoch_transition_plan_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 8> EXPECTED_FIELDS{{
		{"coordinator_service_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"lifecycle_executor_service_ids", 2, field_descriptor::TYPE_STRING, true, nullptr},
		{"prepare_timeout_ms", 3, field_descriptor::TYPE_UINT64, false, nullptr},
		{"prepare_cancel_grace_ms", 4, field_descriptor::TYPE_UINT64, false, nullptr},
		{"prepared_lease_timeout_ms", 5, field_descriptor::TYPE_UINT64, false, nullptr},
		{"commit_timeout_ms", 6, field_descriptor::TYPE_UINT64, false, nullptr},
		{"retirement_timeout_ms", 7, field_descriptor::TYPE_UINT64, false, nullptr},
		{"result_history_capacity", 8, field_descriptor::TYPE_UINT32, false, nullptr},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::EpochTransitionPlan::descriptor(), EXPECTED_FIELDS);
}

/**
 * @brief Verify runtime-service placement has one explicit CPU/NUMA owner.
 */
TEST(gluon_plan_schema, runtime_service_placement_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 5> EXPECTED_FIELDS{{
		{"service_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"service_kind", 2, field_descriptor::TYPE_ENUM, false, "kinetum.gluon.v1.RuntimeServiceKind"},
		{"cpu_core_id", 3, field_descriptor::TYPE_INT32, false, nullptr},
		{"numa_node", 4, field_descriptor::TYPE_INT32, false, nullptr},
		{"command_mailbox_capacity", 5, field_descriptor::TYPE_UINT32, false, nullptr},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::RuntimeServicePlacement::descriptor(), EXPECTED_FIELDS);
}

/**
 * @brief Verify WorkerPlacement includes every transition-owned bound and cadence.
 */
TEST(gluon_plan_schema, worker_placement_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 8> EXPECTED_FIELDS{{
		{"worker_id", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"region_id", 2, field_descriptor::TYPE_INT32, false, nullptr},
		{"lane_id", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"worker_index", 4, field_descriptor::TYPE_UINT32, false, nullptr},
		{"cpu_core_ids", 5, field_descriptor::TYPE_INT32, true, nullptr},
		{"source_epoch_staging_capacity", 6, field_descriptor::TYPE_UINT32, false, nullptr},
		{"module_health_poll_interval_ms", 7, field_descriptor::TYPE_UINT64, false, nullptr},
		{"module_health_callback_budget_ns", 8, field_descriptor::TYPE_UINT64, false, nullptr},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::WorkerPlacement::descriptor(), EXPECTED_FIELDS);
}

/**
 * @brief Verify plan metadata and regions carry only current provenance.
 */
TEST(gluon_plan_schema, metadata_and_region_fields_are_compact_and_complete)
{
	constexpr std::array<expected_field, 4> METADATA_FIELDS{{
		{"planner_version", 1, field_descriptor::TYPE_STRING, false, nullptr},
		{"planned_unix_ms", 2, field_descriptor::TYPE_INT64, false, nullptr},
		{"algorithm", 3, field_descriptor::TYPE_STRING, false, nullptr},
		{"planning_duration_ms", 4, field_descriptor::TYPE_INT64, false, nullptr},
	}};
	constexpr std::array<expected_field, 4> REGION_FIELDS{{
		{"region_id", 1, field_descriptor::TYPE_INT32, false, nullptr},
		{"logical_stage_ids", 2, field_descriptor::TYPE_STRING, true, nullptr},
		{"cpu_core_ids", 3, field_descriptor::TYPE_INT32, true, nullptr},
		{"numa_node", 4, field_descriptor::TYPE_INT32, false, nullptr},
	}};

	expect_exact_message_schema(kinetum::gluon::v1::PlanMetadata::descriptor(), METADATA_FIELDS);
	expect_exact_message_schema(kinetum::gluon::v1::Region::descriptor(), REGION_FIELDS);
}

/**
 * @brief Verify RuntimeServiceKind has the complete prefixed zero-based values.
 */
TEST(gluon_plan_schema, runtime_service_kind_values_are_compact_and_complete)
{
	/** @brief Expected protobuf enum value identity. */
	struct expected_value {
		const char *name;  ///< Exact prefixed enum value name.
		int number;	   ///< Compact enum value number.
	};
	constexpr std::array<expected_value, 3> EXPECTED_VALUES{{
		{"RUNTIME_SERVICE_KIND_UNSPECIFIED", 0},
		{"RUNTIME_SERVICE_KIND_EPOCH_TRANSITION_COORDINATOR", 1},
		{"RUNTIME_SERVICE_KIND_CONFIG_LIFECYCLE_EXECUTOR", 2},
	}};

	const auto *descriptor =
		kinetum::gluon::v1::DeploymentPlan::descriptor()->file()->FindEnumTypeByName("RuntimeServiceKind");
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->value_count(), static_cast<int>(EXPECTED_VALUES.size()));
	for (const auto &expected : EXPECTED_VALUES) {
		const auto *value = descriptor->FindValueByName(expected.name);
		ASSERT_NE(value, nullptr) << expected.name;
		EXPECT_EQ(value->number(), expected.number) << expected.name;
	}
}

/** @brief Port and stream directions retain every surviving wire number. */
TEST(gluon_plan_schema, io_direction_enum_numbers_are_exact)
{
	const auto *port = kinetum::gluon::v1::PortDirection_descriptor();
	ASSERT_NE(port, nullptr);
	ASSERT_EQ(port->value_count(), 4);
	EXPECT_EQ(port->FindValueByName("PORT_DIRECTION_UNSPECIFIED")->number(), 0);
	EXPECT_EQ(port->FindValueByName("PORT_DIRECTION_RX_ONLY")->number(), 1);
	EXPECT_EQ(port->FindValueByName("PORT_DIRECTION_TX_ONLY")->number(), 2);
	EXPECT_EQ(port->FindValueByName("PORT_DIRECTION_BIDIRECTIONAL")->number(), 3);

	const auto *stream = kinetum::gluon::v1::IoStreamDirection_descriptor();
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(stream->value_count(), 3);
	EXPECT_EQ(stream->FindValueByName("IO_STREAM_DIRECTION_UNSPECIFIED")->number(), 0);
	EXPECT_EQ(stream->FindValueByName("IO_STREAM_DIRECTION_RX")->number(), 1);
	EXPECT_EQ(stream->FindValueByName("IO_STREAM_DIRECTION_TX")->number(), 2);
}

/**
 * @brief Verify traffic steering declares only currently materialized modes.
 */
TEST(gluon_plan_schema, traffic_steering_kind_values_are_compact_and_complete)
{
	/** @brief Expected protobuf enum value identity. */
	struct expected_value {
		const char *name;  ///< Exact prefixed enum value name.
		int number;	   ///< Compact enum value number.
	};
	constexpr std::array<expected_value, 3> EXPECTED_VALUES{{
		{"TRAFFIC_STEERING_KIND_UNSPECIFIED", 0},
		{"TRAFFIC_STEERING_KIND_NONE", 1},
		{"TRAFFIC_STEERING_KIND_RSS", 2},
	}};

	const auto *descriptor =
		kinetum::gluon::v1::DeploymentPlan::descriptor()->file()->FindEnumTypeByName("TrafficSteeringKind");
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->value_count(), static_cast<int>(EXPECTED_VALUES.size()));
	for (const auto &expected : EXPECTED_VALUES) {
		const auto *value = descriptor->FindValueByName(expected.name);
		ASSERT_NE(value, nullptr) << expected.name;
		EXPECT_EQ(value->number(), expected.number) << expected.name;
	}
}

/** @brief Removed steering numbers cannot become another current steering mode. */
TEST(gluon_plan_schema, removed_steering_numbers_reach_the_invalid_enum_wall)
{
	for (const int number : {3, 4}) {
		SCOPED_TRACE(number);
		kinetum::gluon::v1::TrafficSteeringBinding binding;
		binding.set_kind(static_cast<kinetum::gluon::v1::TrafficSteeringKind>(number));
		const auto status = kinetum::common::reject_invalid_protobuf_enum_values_recursive(
			binding, "TrafficSteeringBinding");
		EXPECT_FALSE(status.is_ok());
		EXPECT_NE(status.message().find("unknown enum number"), std::string::npos);
	}
}

/**
 * @brief Verify every removed global selector and epoch-only control surface is absent.
 */
TEST(gluon_plan_schema, removed_plan_messages_and_fields_are_absent)
{
	const auto *file = kinetum::gluon::v1::DeploymentPlan::descriptor()->file();
	ASSERT_NE(file, nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("BackendConfig"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("DpdkBackendConfig"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("BufferPoolProfile"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("RegionEdge"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("UpdatePlan"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("RuntimeConfig"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("PlanConstraints"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("RegionStats"), nullptr);
	EXPECT_EQ(file->FindEnumTypeByName("ExecutionBackend"), nullptr);
	EXPECT_EQ(file->FindEnumTypeByName("PortType"), nullptr);
	EXPECT_EQ(file->FindEnumTypeByName("BufferPoolScope"), nullptr);
	EXPECT_EQ(file->FindEnumTypeByName("BindingStatus"), nullptr);
	EXPECT_EQ(file->FindEnumTypeByName("ExecutionClass"), nullptr);
	EXPECT_EQ(file->FindEnumTypeByName("ModuleContextScope"), nullptr);

	constexpr std::array<std::string_view, 36> REMOVED_FIELD_NAMES{{
		"backend",
		"backend_config",
		"buffer_pool_profiles",
		"binding_status",
		"physical_target",
		"port_type",
		"physical_port_id",
		"backend_stream_index",
		"owning_region_id",
		"buffer_pool_id",
		"scope",
		"socket_id",
		"cache_size",
		"region_edges",
		"update_plan",
		"runtime_config",
		"epoch_marker_enabled",
		"require_all_incoming_markers",
		"region_topo_order",
		"boundary_ids",
		"epoch_timeout_ms",
		"timeout_strategy",
		"notes",
		"worker_count",
		"ring_size",
		"busy_poll",
		"channel_capacity",
		"backpressure_threshold",
		"constraints",
		"summary",
		"module_context_scope",
		"execution_class",
		"stats",
		"objective",
		"partition_algorithm",
		"description",
	}};

	for (int message_index = 0; message_index < file->message_type_count(); ++message_index) {
		const auto *message = file->message_type(message_index);
		ASSERT_NE(message, nullptr);
		for (const auto removed_name : REMOVED_FIELD_NAMES) {
			EXPECT_EQ(message->FindFieldByName(std::string(removed_name)), nullptr)
				<< message->full_name() << "." << removed_name;
		}
	}

	const auto *bindings_file = kinetum::gluon::v1::DeploymentBindings::descriptor()->file();
	ASSERT_NE(bindings_file, nullptr);
	EXPECT_EQ(bindings_file->FindMessageTypeByName("PortBindings"), nullptr);
	EXPECT_EQ(bindings_file->FindMessageTypeByName("PortBinding"), nullptr);
	EXPECT_EQ(bindings_file->FindEnumTypeByName("PortBindingType"), nullptr);

	constexpr std::array<std::string_view, 6> REMOVED_BINDING_FIELDS{{
		"physical_target",
		"vdev_args",
		"stream_count",
		"schema_version",
		"binding_type",
		"port_bindings",
	}};
	for (int message_index = 0; message_index < bindings_file->message_type_count(); ++message_index) {
		const auto *message = bindings_file->message_type(message_index);
		ASSERT_NE(message, nullptr);
		for (const auto removed_name : REMOVED_BINDING_FIELDS) {
			EXPECT_EQ(message->FindFieldByName(std::string(removed_name)), nullptr)
				<< message->full_name() << "." << removed_name;
		}
	}
}

/** @brief Removed plan records cannot be reinterpreted under compact field reuse. */
TEST(gluon_plan_schema, removed_plan_wire_reaches_the_recursive_unknown_field_wall)
{
	kinetum::gluon::v1::StageInstance stage;
	ASSERT_TRUE(stage.ParseFromString(std::string("\x30\x01", 2u)));
	EXPECT_FALSE(kinetum::common::reject_unknown_protobuf_fields_recursive(stage, "StageInstance").is_ok());

	kinetum::gluon::v1::PlanMetadata metadata;
	ASSERT_TRUE(metadata.ParseFromString(std::string("\x22\x01x", 3u)));
	EXPECT_FALSE(kinetum::common::reject_unknown_protobuf_fields_recursive(metadata, "PlanMetadata").is_ok());

	kinetum::gluon::v1::DeploymentPlan plan;
	ASSERT_TRUE(plan.ParseFromString(std::string("\x3a\x02\x08\x02", 4u)));
	EXPECT_FALSE(kinetum::common::reject_unknown_protobuf_fields_recursive(plan, "DeploymentPlan").is_ok());
}

}  // namespace kinetum::gluon
