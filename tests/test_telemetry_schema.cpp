// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_telemetry_schema.cpp
 * @brief Descriptor proofs for the sole shared runtime telemetry wire.
 * @author Fleming Patel
 */

#include <array>
#include <cstddef>
#include <string>

#include <google/protobuf/descriptor.h>
#include <gtest/gtest.h>

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "gen/kinetum/telemetry/v1/telemetry.pb.h"
#include "src/common/protobuf_contract.hpp"

namespace kinetum::telemetry
{
namespace
{

/** Generated descriptor interface inspected against independently authored wire-shape expectations. */
using field_descriptor = google::protobuf::FieldDescriptor;

/** @brief One exact protobuf field identity. */
struct expected_field {
	const char *name;	      ///< Exact source field name.
	int number;		      ///< Exact compact field number.
	field_descriptor::Type type;  ///< Exact scalar/message/enum type.
	bool repeated;		      ///< Whether the field is repeated.
	bool presence;		      ///< Whether generated presence is required.
	const char *referenced_type;  ///< Full message/enum identity, or null.
};

/**
 * @brief Require one message descriptor to equal an exact field table.
 * @tparam field_count Compile-time expected field count.
 * @param descriptor Generated message descriptor.
 * @param expected Exact compact field table.
 */
template <std::size_t field_count>
void expect_message(const google::protobuf::Descriptor *descriptor,
		    const std::array<expected_field, field_count> &expected)
{
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->field_count(), static_cast<int>(expected.size()));
	EXPECT_EQ(descriptor->reserved_name_count(), 0);
	EXPECT_EQ(descriptor->reserved_range_count(), 0);
	for (const auto &entry : expected) {
		const auto *field = descriptor->FindFieldByName(entry.name);
		ASSERT_NE(field, nullptr) << entry.name;
		EXPECT_EQ(field->number(), entry.number) << entry.name;
		EXPECT_EQ(field->type(), entry.type) << entry.name;
		EXPECT_EQ(field->is_repeated(), entry.repeated) << entry.name;
		EXPECT_EQ(field->has_presence(), entry.presence) << entry.name;
		if (entry.type == field_descriptor::TYPE_MESSAGE) {
			ASSERT_NE(field->message_type(), nullptr) << entry.name;
			EXPECT_STREQ(field->message_type()->full_name().c_str(), entry.referenced_type) << entry.name;
		} else if (entry.type == field_descriptor::TYPE_ENUM) {
			ASSERT_NE(field->enum_type(), nullptr) << entry.name;
			EXPECT_STREQ(field->enum_type()->full_name().c_str(), entry.referenced_type) << entry.name;
		} else {
			EXPECT_EQ(entry.referenced_type, nullptr) << entry.name;
		}
	}
}

/** @brief One exact protobuf enum value. */
struct expected_enum_value {
	const char *name;  ///< Exact prefixed name.
	int number;	   ///< Exact compact number.
};

/**
 * @brief Require one enum descriptor to equal an exact value table.
 * @tparam value_count Compile-time expected value count.
 * @param descriptor Generated enum descriptor.
 * @param expected Exact value table.
 */
template <std::size_t value_count>
void expect_enum(const google::protobuf::EnumDescriptor *descriptor,
		 const std::array<expected_enum_value, value_count> &expected)
{
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->value_count(), static_cast<int>(expected.size()));
	for (const auto &entry : expected) {
		const auto *value = descriptor->FindValueByName(entry.name);
		ASSERT_NE(value, nullptr) << entry.name;
		EXPECT_EQ(value->number(), entry.number) << entry.name;
	}
}

}  // namespace

/** @brief Pin every shared telemetry enum value without a compatibility alias. */
TEST(telemetry_schema, enum_values_are_compact_and_exact)
{
	const auto *file = v1::RuntimeTelemetry::descriptor()->file();
	ASSERT_NE(file, nullptr);
	constexpr std::array<expected_enum_value, 11> TRANSITION_STATES{{
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
	constexpr std::array<expected_enum_value, 15> FAILURE_CODES{{
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
	constexpr std::array<expected_enum_value, 5> OUTCOMES{{
		{"EPOCH_TRANSITION_OUTCOME_UNSPECIFIED", 0},
		{"EPOCH_TRANSITION_OUTCOME_NONE", 1},
		{"EPOCH_TRANSITION_OUTCOME_COMPLETE", 2},
		{"EPOCH_TRANSITION_OUTCOME_ABORTED", 3},
		{"EPOCH_TRANSITION_OUTCOME_FAILED_STOP", 4},
	}};
	constexpr std::array<expected_enum_value, 5> PROVIDER_STATES{{
		{"PROVIDER_OBSERVATION_STATE_UNSPECIFIED", 0},
		{"PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT", 1},
		{"PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE", 2},
		{"PROVIDER_OBSERVATION_STATE_UNSUPPORTED", 3},
		{"PROVIDER_OBSERVATION_STATE_READ_FAILED", 4},
	}};
	constexpr std::array<expected_enum_value, 5> CERTIFICATE_STATES{{
		{"EPOCH_CERTIFICATE_STATE_UNSPECIFIED", 0},
		{"EPOCH_CERTIFICATE_STATE_INCOMPLETE", 1},
		{"EPOCH_CERTIFICATE_STATE_EXECUTION_COMPLETE", 2},
		{"EPOCH_CERTIFICATE_STATE_RECLAMATION_READY", 3},
		{"EPOCH_CERTIFICATE_STATE_CONTRADICTION", 4},
	}};
	constexpr std::array<expected_enum_value, 9> CERTIFICATE_FAULTS{{
		{"EPOCH_CERTIFICATE_FAULT_UNSPECIFIED", 0},
		{"EPOCH_CERTIFICATE_FAULT_NONE", 1},
		{"EPOCH_CERTIFICATE_FAULT_REQUEST_IDENTITY", 2},
		{"EPOCH_CERTIFICATE_FAULT_EXECUTION_MEMBERSHIP", 3},
		{"EPOCH_CERTIFICATE_FAULT_EXECUTION_STATE", 4},
		{"EPOCH_CERTIFICATE_FAULT_BOUNDARY_MEMBERSHIP", 5},
		{"EPOCH_CERTIFICATE_FAULT_BOUNDARY_STATE", 6},
		{"EPOCH_CERTIFICATE_FAULT_CUT_IDENTITY", 7},
		{"EPOCH_CERTIFICATE_FAULT_READER_MEMBERSHIP", 8},
	}};
	constexpr std::array<expected_enum_value, 6> SENDER_PHASES{{
		{"BOUNDARY_SENDER_PHASE_UNSPECIFIED", 0},
		{"BOUNDARY_SENDER_PHASE_UNBOUND", 1},
		{"BOUNDARY_SENDER_PHASE_OPEN", 2},
		{"BOUNDARY_SENDER_PHASE_DRAINING", 3},
		{"BOUNDARY_SENDER_PHASE_CUT_PENDING", 4},
		{"BOUNDARY_SENDER_PHASE_WAITING_ACK", 5},
	}};
	constexpr std::array<expected_enum_value, 8> RECEIVER_PHASES{{
		{"BOUNDARY_RECEIVER_PHASE_UNSPECIFIED", 0},
		{"BOUNDARY_RECEIVER_PHASE_UNBOUND", 1},
		{"BOUNDARY_RECEIVER_PHASE_OPEN", 2},
		{"BOUNDARY_RECEIVER_PHASE_WAITING_CUT", 3},
		{"BOUNDARY_RECEIVER_PHASE_CUT_DRAINING", 4},
		{"BOUNDARY_RECEIVER_PHASE_CUT_DRAINED", 5},
		{"BOUNDARY_RECEIVER_PHASE_ACK_PENDING", 6},
		{"BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED", 7},
	}};
	constexpr std::array<expected_enum_value, 14> PROTOCOL_FAULTS{{
		{"EPOCH_PROTOCOL_FAULT_CODE_UNSPECIFIED", 0},
		{"EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH", 1},
		{"EPOCH_PROTOCOL_FAULT_CODE_OLD_DATA_AFTER_SEAL", 2},
		{"EPOCH_PROTOCOL_FAULT_CODE_FUTURE_DATA_BEFORE_ACK", 3},
		{"EPOCH_PROTOCOL_FAULT_CODE_CUT_IDENTITY_MISMATCH", 4},
		{"EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_ACTIVATION", 5},
		{"EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_CUT_DRAIN", 6},
		{"EPOCH_PROTOCOL_FAULT_CODE_RETIREMENT_BEFORE_QUIESCENCE", 7},
		{"EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_UNDERFLOW", 8},
		{"EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_OVERFLOW", 9},
		{"EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_DOUBLE_RETIRE", 10},
		{"EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_WRONG_SLOT", 11},
		{"EPOCH_PROTOCOL_FAULT_CODE_SEQUENCE_EXHAUSTED", 12},
		{"EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED", 13},
	}};
	constexpr std::array<expected_enum_value, 4> FAULT_DISPOSITIONS{{
		{"EPOCH_PROTOCOL_FAULT_DISPOSITION_UNSPECIFIED", 0},
		{"EPOCH_PROTOCOL_FAULT_DISPOSITION_DROP_AND_RETIRE", 1},
		{"EPOCH_PROTOCOL_FAULT_DISPOSITION_TERMINATE", 2},
		{"EPOCH_PROTOCOL_FAULT_DISPOSITION_RESOURCE_REFUSED", 3},
	}};
	constexpr std::array<expected_enum_value, 6> HEALTH_STATES{{
		{"MODULE_HEALTH_STATE_UNSPECIFIED", 0},
		{"MODULE_HEALTH_STATE_CALLBACK_UNAVAILABLE", 1},
		{"MODULE_HEALTH_STATE_AWAITING_OBSERVATION", 2},
		{"MODULE_HEALTH_STATE_SIGNAL_AVAILABLE", 3},
		{"MODULE_HEALTH_STATE_ATTEMPT_SUPPRESSED", 4},
		{"MODULE_HEALTH_STATE_STALE_EPOCH", 5},
	}};
	expect_enum(file->FindEnumTypeByName("EpochTransitionState"), TRANSITION_STATES);
	expect_enum(file->FindEnumTypeByName("EpochTransitionFailureCode"), FAILURE_CODES);
	expect_enum(file->FindEnumTypeByName("EpochTransitionOutcome"), OUTCOMES);
	expect_enum(file->FindEnumTypeByName("ProviderObservationState"), PROVIDER_STATES);
	expect_enum(file->FindEnumTypeByName("EpochCertificateState"), CERTIFICATE_STATES);
	expect_enum(file->FindEnumTypeByName("EpochCertificateFault"), CERTIFICATE_FAULTS);
	expect_enum(file->FindEnumTypeByName("BoundarySenderPhase"), SENDER_PHASES);
	expect_enum(file->FindEnumTypeByName("BoundaryReceiverPhase"), RECEIVER_PHASES);
	expect_enum(file->FindEnumTypeByName("EpochProtocolFaultCode"), PROTOCOL_FAULTS);
	expect_enum(file->FindEnumTypeByName("EpochProtocolFaultDisposition"), FAULT_DISPOSITIONS);
	expect_enum(file->FindEnumTypeByName("ModuleHealthState"), HEALTH_STATES);
}

/** @brief Pin the mandatory summaries and exact optional-row selector. */
TEST(telemetry_schema, core_message_fields_are_compact_and_exact)
{
	constexpr std::array<expected_field, 10> SELECTION{{
		{"include_stage_stats", 1, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"include_module_metrics", 2, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"include_module_health", 3, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"include_worker_epoch_stats", 4, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"include_region_epoch_stats", 5, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"include_boundary_epoch_stats", 6, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"include_stream_stats", 7, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"include_storage_domain_stats", 8, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"include_port_stats", 9, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"include_topology_stats", 10, field_descriptor::TYPE_BOOL, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 10> RUNTIME{{
		{"runtime_generation", 1, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"status_publication_generation", 2, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"active_epoch", 3, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"minimum_retained_epoch", 4, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"last_activated_epoch", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"active_workers", 6, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"expected_workers", 7, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"collection_monotonic_ns", 8, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"latest_bank_publication_monotonic_ns", 9, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"skipped_publications", 10, field_descriptor::TYPE_UINT64, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 6> ENGINE{{
		{"rx_packets", 1, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"tx_packets", 2, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"dropped_packets", 3, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"rx_bytes", 4, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"tx_bytes", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"fanout_overflow", 6, field_descriptor::TYPE_UINT64, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 17> COMPLETE{{
		{"runtime", 1, field_descriptor::TYPE_MESSAGE, false, true, "kinetum.telemetry.v1.RuntimeObservation"},
		{"engine", 2, field_descriptor::TYPE_MESSAGE, false, true, "kinetum.telemetry.v1.EngineStats"},
		{"transition", 3, field_descriptor::TYPE_MESSAGE, false, true,
		 "kinetum.telemetry.v1.EpochTransitionTelemetry"},
		{"protocol_faults", 4, field_descriptor::TYPE_MESSAGE, false, true,
		 "kinetum.telemetry.v1.EpochProtocolFaultSummary"},
		{"stages", 5, field_descriptor::TYPE_MESSAGE, true, false, "kinetum.telemetry.v1.StageStats"},
		{"module_counters", 6, field_descriptor::TYPE_MESSAGE, true, false,
		 "kinetum.telemetry.v1.ModuleCounterStats"},
		{"module_histograms", 7, field_descriptor::TYPE_MESSAGE, true, false,
		 "kinetum.telemetry.v1.ModuleHistogramStats"},
		{"module_epoch_mismatches", 8, field_descriptor::TYPE_MESSAGE, true, false,
		 "kinetum.telemetry.v1.ModuleEpochMismatchStats"},
		{"module_health", 9, field_descriptor::TYPE_MESSAGE, true, false,
		 "kinetum.telemetry.v1.ModuleHealthStats"},
		{"workers", 10, field_descriptor::TYPE_MESSAGE, true, false, "kinetum.telemetry.v1.WorkerEpochStats"},
		{"regions", 11, field_descriptor::TYPE_MESSAGE, true, false, "kinetum.telemetry.v1.RegionEpochStats"},
		{"boundaries", 12, field_descriptor::TYPE_MESSAGE, true, false,
		 "kinetum.telemetry.v1.BoundaryEpochStats"},
		{"streams", 13, field_descriptor::TYPE_MESSAGE, true, false, "kinetum.telemetry.v1.StreamStats"},
		{"storage_domains", 14, field_descriptor::TYPE_MESSAGE, true, false,
		 "kinetum.telemetry.v1.StorageDomainStats"},
		{"ports", 15, field_descriptor::TYPE_MESSAGE, true, false, "kinetum.telemetry.v1.PortStats"},
		{"steering_profiles", 16, field_descriptor::TYPE_MESSAGE, true, false,
		 "kinetum.telemetry.v1.TrafficSteeringStats"},
		{"module_context_domains", 18, field_descriptor::TYPE_MESSAGE, true, false,
		 "kinetum.gluon.v1.ModuleContextDomain"},
	}};
	expect_message(v1::TelemetrySelection::descriptor(), SELECTION);
	expect_message(v1::RuntimeObservation::descriptor(), RUNTIME);
	expect_message(v1::EngineStats::descriptor(), ENGINE);
	expect_message(v1::RuntimeTelemetry::descriptor(), COMPLETE);
}

/** @brief Pin exact transaction, certificate, grace, and fault field presence. */
TEST(telemetry_schema, transition_and_fault_fields_are_compact_and_exact)
{
	constexpr std::array<expected_field, 16> TRANSACTION{{
		{"mutation_sequence", 1, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"from_epoch", 2, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"to_epoch", 3, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"validation_hash", 4, field_descriptor::TYPE_BYTES, false, false, nullptr},
		{"idempotency_key_digest", 5, field_descriptor::TYPE_BYTES, false, false, nullptr},
		{"admitted_monotonic_ns", 6, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"prepared_monotonic_ns", 7, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"prepared_lease_deadline_monotonic_ns", 8, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"prepared_lease_deadline_unix_ms", 9, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"commit_started_monotonic_ns", 10, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"retiring_started_monotonic_ns", 11, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"failure_observed_monotonic_ns", 12, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"terminal_monotonic_ns", 13, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"outcome", 14, field_descriptor::TYPE_ENUM, false, false,
		 "kinetum.telemetry.v1.EpochTransitionOutcome"},
		{"failure_code", 15, field_descriptor::TYPE_ENUM, false, false,
		 "kinetum.telemetry.v1.EpochTransitionFailureCode"},
		{"retirement_frozen", 16, field_descriptor::TYPE_BOOL, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 14> CERTIFICATE{{
		{"evaluated_monotonic_ns", 1, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"runtime_generation", 2, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"transition_generation", 3, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"from_epoch", 4, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"to_epoch", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"execution_complete", 6, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"execution_total", 7, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"boundary_complete", 8, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"boundary_total", 9, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"reader_complete", 10, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"reader_total", 11, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"fault_index", 12, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"state", 13, field_descriptor::TYPE_ENUM, false, false, "kinetum.telemetry.v1.EpochCertificateState"},
		{"fault", 14, field_descriptor::TYPE_ENUM, false, false, "kinetum.telemetry.v1.EpochCertificateFault"},
	}};
	constexpr std::array<expected_field, 8> GRACE{{
		{"generation", 1, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"started_monotonic_ns", 2, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"completion_observed_monotonic_ns", 3, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"finished_monotonic_ns", 4, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"readers_complete", 5, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"readers_total", 6, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"active", 7, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"update_frozen", 8, field_descriptor::TYPE_BOOL, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 22> TRANSITION{{
		{"publication_generation", 1, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"state", 2, field_descriptor::TYPE_ENUM, false, false, "kinetum.telemetry.v1.EpochTransitionState"},
		{"active_epoch", 3, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"target_epoch", 4, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"allocated_epoch_high_watermark", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"mutation_sequence_high_watermark", 6, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"plan_content_hash", 7, field_descriptor::TYPE_BYTES, false, false, nullptr},
		{"participant_set_frozen", 8, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"execution_participant_count", 9, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"region_count", 10, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"boundary_count", 11, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"source_participant_count", 12, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"sink_participant_count", 13, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"module_context_count", 14, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"quiescence_reader_count", 15, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"terminal_history_size", 16, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"retirement_frozen", 17, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"active_transaction", 18, field_descriptor::TYPE_MESSAGE, false, true,
		 "kinetum.telemetry.v1.EpochTransactionTelemetry"},
		{"latest_terminal", 19, field_descriptor::TYPE_MESSAGE, false, true,
		 "kinetum.telemetry.v1.EpochTransactionTelemetry"},
		{"certificate", 20, field_descriptor::TYPE_MESSAGE, false, true,
		 "kinetum.telemetry.v1.EpochCertificateTelemetry"},
		{"grace", 21, field_descriptor::TYPE_MESSAGE, false, true, "kinetum.telemetry.v1.EpochGraceTelemetry"},
		{"active_validation_hash", 22, field_descriptor::TYPE_BYTES, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 2> FAULT_COUNTER{{
		{"code", 1, field_descriptor::TYPE_ENUM, false, false, "kinetum.telemetry.v1.EpochProtocolFaultCode"},
		{"count", 2, field_descriptor::TYPE_UINT64, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 14> FIRST_FAULT{{
		{"code", 1, field_descriptor::TYPE_ENUM, false, false, "kinetum.telemetry.v1.EpochProtocolFaultCode"},
		{"disposition", 2, field_descriptor::TYPE_ENUM, false, false,
		 "kinetum.telemetry.v1.EpochProtocolFaultDisposition"},
		{"runtime_generation", 3, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"transition_generation", 4, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"from_epoch", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"to_epoch", 6, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"observed_epoch", 7, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"worker_index", 8, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"boundary_index", 9, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"context_index", 10, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"stage_instance_index", 11, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"expected_value", 12, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"observed_value", 13, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"observed_monotonic_ns", 14, field_descriptor::TYPE_UINT64, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 3> FAULT_SUMMARY{{
		{"transition_success_blocked", 1, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"counters", 2, field_descriptor::TYPE_MESSAGE, true, false,
		 "kinetum.telemetry.v1.EpochProtocolFaultCounter"},
		{"first_fault", 3, field_descriptor::TYPE_MESSAGE, false, true,
		 "kinetum.telemetry.v1.EpochProtocolFirstFault"},
	}};
	expect_message(v1::EpochTransactionTelemetry::descriptor(), TRANSACTION);
	expect_message(v1::EpochCertificateTelemetry::descriptor(), CERTIFICATE);
	expect_message(v1::EpochGraceTelemetry::descriptor(), GRACE);
	expect_message(v1::EpochTransitionTelemetry::descriptor(), TRANSITION);
	expect_message(v1::EpochProtocolFaultCounter::descriptor(), FAULT_COUNTER);
	expect_message(v1::EpochProtocolFirstFault::descriptor(), FIRST_FAULT);
	expect_message(v1::EpochProtocolFaultSummary::descriptor(), FAULT_SUMMARY);
}

/** @brief Pin every optional row family and typed provider presence bit. */
TEST(telemetry_schema, selected_row_fields_are_compact_and_exact)
{
	constexpr std::array<expected_field, 6> STAGE{{
		{"stage_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"in_packets", 2, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"out_packets", 3, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"dropped_packets", 4, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"in_bytes", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"out_bytes", 6, field_descriptor::TYPE_UINT64, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 7> COUNTER{{
		{"module_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"context_instance_id", 2, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"context_index", 3, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"worker_index", 4, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"epoch", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"name", 6, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"value", 7, field_descriptor::TYPE_UINT64, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 14> HISTOGRAM{{
		{"module_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"context_instance_id", 2, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"context_index", 3, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"worker_index", 4, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"epoch", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"name", 6, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"sample_count", 7, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"sample_sum", 8, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"minimum", 9, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"maximum", 10, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"p50", 11, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"p90", 12, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"p99", 13, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"p999", 14, field_descriptor::TYPE_UINT64, false, true, nullptr},
	}};
	constexpr std::array<expected_field, 10> MISMATCH{{
		{"module_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"context_instance_id", 2, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"context_index", 3, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"worker_index", 4, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"observation_epoch", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"mismatch_count", 6, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"first_packet_epoch", 7, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"first_active_epoch", 8, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"first_stage_instance_index", 9, field_descriptor::TYPE_UINT32, false, true, nullptr},
		{"first_region_id", 10, field_descriptor::TYPE_INT32, false, true, nullptr},
	}};
	constexpr std::array<expected_field, 19> HEALTH{{
		{"module_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"context_instance_id", 2, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"context_index", 3, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"worker_index", 4, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"stage_instance_index", 5, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"state", 6, field_descriptor::TYPE_ENUM, false, false, "kinetum.telemetry.v1.ModuleHealthState"},
		{"publication_generation", 7, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"observation_epoch", 8, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"observed_at_ns", 9, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"callback_duration_ns", 10, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"contract_fault_count", 11, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"latest_fault_mask", 12, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"first_fault_mask", 13, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"first_fault_epoch", 14, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"first_fault_timestamp_ns", 15, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"first_fault_duration_ns", 16, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"health_score", 17, field_descriptor::TYPE_UINT32, false, true, nullptr},
		{"health_flags", 18, field_descriptor::TYPE_UINT32, false, true, nullptr},
		{"reason", 19, field_descriptor::TYPE_STRING, false, true, nullptr},
	}};
	constexpr std::array<expected_field, 16> WORKER{{
		{"worker_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"worker_index", 2, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"region_id", 3, field_descriptor::TYPE_INT32, false, false, nullptr},
		{"lane_id", 4, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"ledger_publication_generation", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"active_epoch", 6, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"source_epoch", 7, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"active_unretired", 8, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"future_epoch", 9, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"future_unretired", 10, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"activation_publication_generation", 11, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"transition_generation", 12, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"from_epoch", 13, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"to_epoch", 14, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"activation_monotonic_ns", 15, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"activation_complete", 16, field_descriptor::TYPE_BOOL, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 12> REGION{{
		{"region_id", 1, field_descriptor::TYPE_INT32, false, false, nullptr},
		{"worker_count", 2, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"minimum_active_epoch", 3, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"maximum_active_epoch", 4, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"minimum_source_epoch", 5, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"maximum_source_epoch", 6, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"active_unretired", 7, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"future_unretired", 8, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"activated_participants", 9, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"minimum_activation_monotonic_ns", 10, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"maximum_activation_monotonic_ns", 11, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"fanout_overflow", 12, field_descriptor::TYPE_UINT64, false, false, nullptr},
	}};
	expect_message(v1::StageStats::descriptor(), STAGE);
	expect_message(v1::ModuleCounterStats::descriptor(), COUNTER);
	expect_message(v1::ModuleHistogramStats::descriptor(), HISTOGRAM);
	expect_message(v1::ModuleEpochMismatchStats::descriptor(), MISMATCH);
	expect_message(v1::ModuleHealthStats::descriptor(), HEALTH);
	expect_message(v1::WorkerEpochStats::descriptor(), WORKER);
	expect_message(v1::RegionEpochStats::descriptor(), REGION);
}

/** @brief Pin boundary, provider, and compiled-topology row fields. */
TEST(telemetry_schema, boundary_provider_and_topology_fields_are_compact_and_exact)
{
	constexpr std::array<expected_field, 34> BOUNDARY{{
		{"boundary_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"boundary_index", 2, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"from_stage_instance_index", 3, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"to_stage_instance_index", 4, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"sender_worker_index", 5, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"receiver_worker_index", 6, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"from_region_id", 7, field_descriptor::TYPE_INT32, false, false, nullptr},
		{"to_region_id", 8, field_descriptor::TYPE_INT32, false, false, nullptr},
		{"data_ring_capacity", 9, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"future_output_hold_capacity", 10, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"data_enqueued_sequence", 11, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"data_dequeued_sequence", 12, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"data_backpressure_events", 13, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"pending_cut_epoch", 14, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"pending_cut_sequence", 15, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"pending_ack_epoch", 16, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"pending_ack_sequence", 17, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"transition_generation", 18, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"from_epoch", 19, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"to_epoch", 20, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"cut_sequence", 21, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"sender_phase", 22, field_descriptor::TYPE_ENUM, false, false,
		 "kinetum.telemetry.v1.BoundarySenderPhase"},
		{"receiver_phase", 23, field_descriptor::TYPE_ENUM, false, false,
		 "kinetum.telemetry.v1.BoundaryReceiverPhase"},
		{"duplicate_cut_count", 24, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"duplicate_ack_count", 25, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"cut_published_monotonic_ns", 27, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"cut_observed_monotonic_ns", 28, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"cut_drained_monotonic_ns", 29, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"activation_monotonic_ns", 30, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"ack_published_monotonic_ns", 31, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"ack_observed_monotonic_ns", 32, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"cut_delivery_duration_ns", 33, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"cut_drain_duration_ns", 34, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"ack_gate_duration_ns", 35, field_descriptor::TYPE_UINT64, false, true, nullptr},
	}};
	constexpr std::array<expected_field, 10> STREAM{{
		{"io_stream_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"logical_port_id", 2, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"direction", 3, field_descriptor::TYPE_ENUM, false, false, "kinetum.gluon.v1.IoStreamDirection"},
		{"owning_region_id", 4, field_descriptor::TYPE_INT32, false, false, nullptr},
		{"worker_index", 5, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"driver_queue_id", 6, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"packets", 9, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"bytes", 10, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"published_monotonic_ns", 12, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"rejected_packets", 13, field_descriptor::TYPE_UINT64, false, true, nullptr},
	}};
	constexpr std::array<expected_field, 9> STORAGE{{
		{"storage_domain_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"host_numa_node", 2, field_descriptor::TYPE_INT32, false, true, nullptr},
		{"buffer_count", 3, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"required_min_buffers", 4, field_descriptor::TYPE_UINT64, false, false, nullptr},
		{"safety_margin", 5, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"observation_state", 6, field_descriptor::TYPE_ENUM, false, false,
		 "kinetum.telemetry.v1.ProviderObservationState"},
		{"observed_monotonic_ns", 7, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"in_use", 8, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"available", 9, field_descriptor::TYPE_UINT64, false, true, nullptr},
	}};
	constexpr std::array<expected_field, 14> PORT{{
		{"logical_port_id", 1, field_descriptor::TYPE_UINT32, false, false, nullptr},
		{"logical_name", 2, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"io_driver_instance_id", 3, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"driver_port_id", 4, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"observation_state", 5, field_descriptor::TYPE_ENUM, false, false,
		 "kinetum.telemetry.v1.ProviderObservationState"},
		{"observed_monotonic_ns", 6, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"rx_packets", 7, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"tx_packets", 8, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"rx_bytes", 9, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"tx_bytes", 10, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"rx_missed", 11, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"rx_errors", 12, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"tx_errors", 13, field_descriptor::TYPE_UINT64, false, true, nullptr},
		{"rx_no_buffer", 14, field_descriptor::TYPE_UINT64, false, true, nullptr},
	}};
	constexpr std::array<expected_field, 4> STEERING{{
		{"steering_profile_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"kind", 2, field_descriptor::TYPE_ENUM, false, false, "kinetum.gluon.v1.TrafficSteeringKind"},
		{"symmetric", 3, field_descriptor::TYPE_BOOL, false, false, nullptr},
		{"io_stream_ids", 4, field_descriptor::TYPE_STRING, true, false, nullptr},
	}};
	constexpr std::array<expected_field, 2> CONTEXT_DOMAIN{{
		{"module_id", 1, field_descriptor::TYPE_STRING, false, false, nullptr},
		{"context_instance_ids", 2, field_descriptor::TYPE_STRING, true, false, nullptr},
	}};
	expect_message(v1::BoundaryEpochStats::descriptor(), BOUNDARY);
	expect_message(v1::StreamStats::descriptor(), STREAM);
	expect_message(v1::StorageDomainStats::descriptor(), STORAGE);
	expect_message(v1::PortStats::descriptor(), PORT);
	expect_message(v1::TrafficSteeringStats::descriptor(), STEERING);
	expect_message(kinetum::gluon::v1::ModuleContextDomain::descriptor(), CONTEXT_DOMAIN);
	EXPECT_EQ(v1::RuntimeTelemetry::descriptor()->FindFieldByNumber(17), nullptr);
}

/** @brief Prove CP and DP own wrappers only and no duplicate stats message. */
TEST(telemetry_schema, service_wrappers_share_one_payload_authority)
{
	constexpr std::array<expected_field, 1> REQUEST{{
		{"selection", 1, field_descriptor::TYPE_MESSAGE, false, true,
		 "kinetum.telemetry.v1.TelemetrySelection"},
	}};
	constexpr std::array<expected_field, 2> ACTIVE{{
		{"revision", 1, field_descriptor::TYPE_INT64, false, false, nullptr},
		{"snapshot_id", 2, field_descriptor::TYPE_STRING, false, false, nullptr},
	}};
	constexpr std::array<expected_field, 3> CP_RESPONSE{{
		{"status", 1, field_descriptor::TYPE_MESSAGE, false, true, "kinetum.common.v1.Status"},
		{"active_config", 2, field_descriptor::TYPE_MESSAGE, false, true,
		 "kinetum.control.v1.ActiveStatsConfiguration"},
		{"telemetry", 3, field_descriptor::TYPE_MESSAGE, false, true, "kinetum.telemetry.v1.RuntimeTelemetry"},
	}};
	constexpr std::array<expected_field, 2> DP_RESPONSE{{
		{"status", 1, field_descriptor::TYPE_MESSAGE, false, true, "kinetum.common.v1.Status"},
		{"telemetry", 2, field_descriptor::TYPE_MESSAGE, false, true, "kinetum.telemetry.v1.RuntimeTelemetry"},
	}};
	expect_message(kinetum::control::v1::StatsRequest::descriptor(), REQUEST);
	expect_message(kinetum::dataplane::v1::StatsRequest::descriptor(), REQUEST);
	expect_message(kinetum::control::v1::ActiveStatsConfiguration::descriptor(), ACTIVE);
	expect_message(kinetum::control::v1::StatsResponse::descriptor(), CP_RESPONSE);
	expect_message(kinetum::dataplane::v1::StatsResponse::descriptor(), DP_RESPONSE);

	kinetum::control::v1::ActiveStatsConfiguration old_active;
	ASSERT_TRUE(old_active.ParseFromString(std::string("\x1a\x00", 2u)));
	EXPECT_FALSE(kinetum::common::reject_unknown_protobuf_fields_recursive(old_active, "ActiveStatsConfiguration")
			     .is_ok());

	for (const auto *file : {kinetum::control::v1::StatsRequest::descriptor()->file(),
				 kinetum::dataplane::v1::StatsRequest::descriptor()->file()}) {
		for (const char *removed : {"StageStats", "RegionStats", "QueueStats", "NatSessionStats", "PortStats",
					    "StreamStats", "StorageDomainStats", "TrafficSteeringStats",
					    "FlowAffinityDomainStats", "BoundaryTelemetry", "ModuleHealth"}) {
			EXPECT_EQ(file->FindMessageTypeByName(removed), nullptr) << file->name() << ':' << removed;
		}
	}
}

}  // namespace kinetum::telemetry
