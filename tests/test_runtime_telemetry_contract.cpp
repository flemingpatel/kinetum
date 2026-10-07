// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_runtime_telemetry_contract.cpp
 * @brief Failure-oriented tests for shared runtime telemetry admission.
 * @author Fleming Patel
 */

#include <cstdint>
#include <string>

#include <gtest/gtest.h>

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "gen/kinetum/telemetry/v1/telemetry.pb.h"
#include "src/common/runtime_telemetry_contract.hpp"

namespace kinetum::common
{
namespace
{

namespace telemetry = kinetum::telemetry::v1;

/** @return One intrinsically valid mandatory telemetry observation. */
telemetry::RuntimeTelemetry valid_telemetry()
{
	telemetry::RuntimeTelemetry value;
	auto *runtime = value.mutable_runtime();
	runtime->set_runtime_generation(1u);
	runtime->set_status_publication_generation(1u);
	runtime->set_active_epoch(5u);
	runtime->set_minimum_retained_epoch(5u);
	runtime->set_last_activated_epoch(5u);
	runtime->set_active_workers(1u);
	runtime->set_expected_workers(1u);
	runtime->set_collection_monotonic_ns(100u);
	runtime->set_latest_bank_publication_monotonic_ns(90u);
	value.mutable_engine();
	auto *transition = value.mutable_transition();
	transition->set_publication_generation(1u);
	transition->set_state(telemetry::EPOCH_TRANSITION_STATE_IDLE);
	transition->set_active_epoch(5u);
	transition->set_allocated_epoch_high_watermark(5u);
	transition->set_mutation_sequence_high_watermark(1u);
	transition->set_plan_content_hash(std::string(32u, '\x01'));
	transition->set_active_validation_hash(std::string(32u, '\x02'));
	transition->set_participant_set_frozen(false);
	transition->set_execution_participant_count(1u);
	transition->set_region_count(1u);
	transition->set_source_participant_count(1u);
	transition->set_sink_participant_count(1u);
	transition->set_quiescence_reader_count(1u);
	for (int code = 1; code <= 13; ++code) {
		auto *counter = value.mutable_protocol_faults()->add_counters();
		counter->set_code(static_cast<telemetry::EpochProtocolFaultCode>(code));
	}
	return value;
}

}  // namespace

/** @brief Accept one exact mandatory observation and canonical wrappers. */
TEST(runtime_telemetry_contract, mandatory_families_and_service_wrappers_are_exact)
{
	telemetry::TelemetrySelection selection;
	auto telemetry = valid_telemetry();
	EXPECT_TRUE(validate_runtime_telemetry(telemetry, selection).is_ok());
	telemetry.mutable_transition()->clear_active_validation_hash();
	EXPECT_FALSE(validate_runtime_telemetry(telemetry, selection).is_ok());
	telemetry.mutable_transition()->set_active_validation_hash(std::string(31u, '\x02'));
	EXPECT_FALSE(validate_runtime_telemetry(telemetry, selection).is_ok());
	telemetry.mutable_transition()->set_active_validation_hash(std::string(32u, '\x02'));
	telemetry.mutable_transition()->set_participant_set_frozen(true);
	EXPECT_FALSE(validate_runtime_telemetry(telemetry, selection).is_ok());
	telemetry.mutable_transition()->set_participant_set_frozen(false);
	telemetry.mutable_runtime()->set_runtime_generation(UINT64_C(1) << 32u);
	EXPECT_FALSE(validate_runtime_telemetry(telemetry, selection).is_ok());
	telemetry.mutable_runtime()->set_runtime_generation(1u);
	telemetry.mutable_transition()->set_allocated_epoch_high_watermark(UINT64_MAX);
	EXPECT_FALSE(validate_runtime_telemetry(telemetry, selection).is_ok());
	telemetry.mutable_transition()->set_allocated_epoch_high_watermark(5u);
	telemetry.mutable_transition()->set_terminal_history_size(65u);
	EXPECT_FALSE(validate_runtime_telemetry(telemetry, selection).is_ok());
	telemetry.mutable_transition()->set_terminal_history_size(0u);
	EXPECT_TRUE(validate_runtime_telemetry(telemetry, selection).is_ok());

	kinetum::dataplane::v1::StatsResponse dataplane;
	dataplane.mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
	dataplane.mutable_telemetry()->CopyFrom(telemetry);
	EXPECT_TRUE(validate_successful_dataplane_stats_response(dataplane, selection).is_ok());

	kinetum::control::v1::StatsResponse control;
	control.mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
	control.mutable_active_config()->set_revision(3);
	control.mutable_active_config()->set_snapshot_id("snapshot.3");
	control.mutable_telemetry()->CopyFrom(telemetry);
	EXPECT_TRUE(validate_successful_control_stats_response(control, selection).is_ok());
	const std::string stale_response_scalar{"\x10\x01", 2u};
	auto stale_dataplane_response = dataplane;
	auto stale_control_response = control;
	ASSERT_TRUE(stale_dataplane_response.MergeFromString(stale_response_scalar));
	ASSERT_TRUE(stale_control_response.MergeFromString(stale_response_scalar));
	EXPECT_FALSE(validate_successful_dataplane_stats_response(stale_dataplane_response, selection).is_ok());
	EXPECT_FALSE(validate_successful_control_stats_response(stale_control_response, selection).is_ok());

	control.mutable_status()->set_message("success residue");
	EXPECT_FALSE(validate_successful_control_stats_response(control, selection).is_ok());

	kinetum::dataplane::v1::StatsRequest dataplane_request;
	kinetum::control::v1::StatsRequest control_request;
	EXPECT_FALSE(validate_dataplane_stats_request(dataplane_request).is_ok());
	EXPECT_FALSE(validate_control_stats_request(control_request).is_ok());
	dataplane_request.mutable_selection();
	control_request.mutable_selection();
	EXPECT_TRUE(validate_dataplane_stats_request(dataplane_request).is_ok());
	EXPECT_TRUE(validate_control_stats_request(control_request).is_ok());

	const std::string stale_bool_field{"\x08\x01", 2u};
	kinetum::dataplane::v1::StatsRequest stale_dataplane;
	kinetum::control::v1::StatsRequest stale_control;
	ASSERT_TRUE(stale_dataplane.ParseFromString(stale_bool_field));
	ASSERT_TRUE(stale_control.ParseFromString(stale_bool_field));
	EXPECT_FALSE(validate_dataplane_stats_request(stale_dataplane).is_ok());
	EXPECT_FALSE(validate_control_stats_request(stale_control).is_ok());
}

/** @brief Reject exhausted engine transfers even without selected stream detail. */
TEST(runtime_telemetry_contract, summary_transfer_counts_exclude_the_exhaustion_marker)
{
	telemetry::TelemetrySelection selection;
	using counter_setter = decltype(&telemetry::EngineStats::set_rx_packets);
	constexpr counter_setter COUNTER_SETTERS[]{
		&telemetry::EngineStats::set_rx_packets,
		&telemetry::EngineStats::set_tx_packets,
		&telemetry::EngineStats::set_rx_bytes,
		&telemetry::EngineStats::set_tx_bytes,
	};
	for (const auto setter : COUNTER_SETTERS) {
		auto value = valid_telemetry();
		auto *engine = value.mutable_engine();
		engine->set_rx_packets(UINT64_MAX - 1u);
		engine->set_tx_packets(UINT64_MAX - 1u);
		engine->set_rx_bytes(UINT64_MAX - 1u);
		engine->set_tx_bytes(UINT64_MAX - 1u);
		ASSERT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
		(engine->*setter)(UINT64_MAX);
		EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	}
}

/** @brief Require selected row membership and reject unrequested payload. */
TEST(runtime_telemetry_contract, optional_row_membership_is_selection_exact)
{
	telemetry::TelemetrySelection selection;
	auto value = valid_telemetry();
	auto *stage = value.add_stages();
	stage->set_stage_id("rx");
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());

	selection.set_include_stage_stats(true);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());

	selection.set_include_worker_epoch_stats(true);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	auto *worker = value.add_workers();
	worker->set_worker_id("worker_0");
	worker->set_lane_id("lane_0");
	worker->set_ledger_publication_generation(1u);
	worker->set_active_epoch(5u);
	worker->set_source_epoch(5u);
	worker->set_activation_publication_generation(1u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	worker->set_worker_index(1u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	worker->set_worker_index(0u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	selection.set_include_region_epoch_stats(true);
	auto *region = value.add_regions();
	region->set_worker_count(1u);
	region->set_minimum_active_epoch(5u);
	region->set_maximum_active_epoch(5u);
	region->set_minimum_source_epoch(5u);
	region->set_maximum_source_epoch(5u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	value.mutable_engine()->set_fanout_overflow(1u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	region->set_fanout_overflow(1u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());

	auto topology = valid_telemetry();
	telemetry::TelemetrySelection topology_selection;
	topology_selection.set_include_topology_stats(true);
	auto *profile = topology.add_steering_profiles();
	profile->set_steering_profile_id("steering.0");
	profile->set_kind(kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS);
	profile->add_io_stream_ids("stream.rx");
	auto *domain = topology.add_module_context_domains();
	domain->set_module_id("kinetum.test");
	domain->add_context_instance_ids("stage.0");
	EXPECT_FALSE(validate_runtime_telemetry(topology, topology_selection).is_ok());
	topology.mutable_transition()->set_module_context_count(1u);
	EXPECT_TRUE(validate_runtime_telemetry(topology, topology_selection).is_ok());
	profile->set_kind(static_cast<kinetum::gluon::v1::TrafficSteeringKind>(3));
	EXPECT_FALSE(validate_runtime_telemetry(topology, topology_selection).is_ok());
	profile->set_kind(kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS);
	EXPECT_TRUE(validate_runtime_telemetry(topology, topology_selection).is_ok());
}

/** @brief Require stream counters while preserving typed native port/storage availability. */
TEST(runtime_telemetry_contract, native_availability_and_stream_presence_are_distinct)
{
	telemetry::TelemetrySelection selection;
	selection.set_include_stream_stats(true);
	selection.set_include_storage_domain_stats(true);
	selection.set_include_port_stats(true);
	auto value = valid_telemetry();
	auto *stream = value.add_streams();
	stream->set_io_stream_id("wan0.rx.lane_0");
	stream->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	stream->set_published_monotonic_ns(90u);
	stream->set_packets(0u);
	stream->set_bytes(0u);
	stream->set_rejected_packets(0u);
	auto *port = value.add_ports();
	port->set_logical_name("wan0");
	port->set_io_driver_instance_id("io0");
	port->set_driver_port_id("port0");
	port->set_observation_state(telemetry::PROVIDER_OBSERVATION_STATE_UNSUPPORTED);
	auto *storage = value.add_storage_domains();
	storage->set_storage_domain_id("storage0");
	storage->set_buffer_count(10u);
	storage->set_required_min_buffers(8u);
	storage->set_safety_margin(2u);
	storage->set_observation_state(telemetry::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT);
	storage->set_observed_monotonic_ns(99u);
	storage->set_in_use(4u);
	storage->set_available(5u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	storage->set_available(6u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	storage->set_observation_state(telemetry::PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE);
	storage->set_available(5u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	storage->set_available(6u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());

	stream->clear_packets();
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	stream->set_packets(0u);
	stream->clear_bytes();
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	stream->set_bytes(0u);
	stream->clear_rejected_packets();
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	stream->set_rejected_packets(0u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	stream->set_published_monotonic_ns(101u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	stream->set_published_monotonic_ns(91u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	stream->set_published_monotonic_ns(90u);
	stream->set_logical_port_id(1u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
}

/** @brief Reject contradictory derived totals and exhausted software stream counters. */
TEST(runtime_telemetry_contract, stream_totals_preserve_exact_packet_and_byte_consistency)
{
	telemetry::TelemetrySelection selection;
	selection.set_include_stream_stats(true);
	auto value = valid_telemetry();
	auto *stream = value.add_streams();
	stream->set_io_stream_id("wan0.rx.lane_0");
	stream->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	stream->set_published_monotonic_ns(90u);
	stream->set_packets(7u);
	stream->set_bytes(448u);
	stream->set_rejected_packets(0u);
	value.mutable_engine()->set_rx_packets(7u);
	value.mutable_engine()->set_rx_bytes(448u);
	ASSERT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	value.mutable_engine()->set_rx_packets(8u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	value.mutable_engine()->set_rx_packets(7u);
	value.mutable_engine()->set_rx_bytes(447u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	value.mutable_engine()->set_rx_bytes(448u);
	value.mutable_engine()->set_tx_packets(1u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	value.mutable_engine()->set_tx_packets(0u);
	stream->set_rejected_packets(UINT64_MAX);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	stream->set_rejected_packets(0u);
	stream->set_packets(UINT64_MAX);
	stream->set_bytes(UINT64_MAX);
	value.mutable_engine()->set_rx_packets(UINT64_MAX);
	value.mutable_engine()->set_rx_bytes(UINT64_MAX);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
}

/** @brief Reject partial health, histogram, and first-fault presence. */
TEST(runtime_telemetry_contract, optional_evidence_is_all_or_none)
{
	telemetry::TelemetrySelection selection;
	selection.set_include_module_health(true);
	selection.set_include_module_metrics(true);
	auto value = valid_telemetry();
	value.mutable_transition()->set_module_context_count(1u);
	auto *health = value.add_module_health();
	health->set_module_id("kinetum.test");
	health->set_context_instance_id("stage@lane_0");
	health->set_state(telemetry::MODULE_HEALTH_STATE_CALLBACK_UNAVAILABLE);
	auto *mismatch = value.add_module_epoch_mismatches();
	mismatch->set_module_id("kinetum.test");
	mismatch->set_context_instance_id("stage@lane_0");
	mismatch->set_observation_epoch(5u);
	auto *histogram = value.add_module_histograms();
	histogram->set_module_id("kinetum.test");
	histogram->set_context_instance_id("stage@lane_0");
	histogram->set_epoch(5u);
	histogram->set_name("latency");
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());

	histogram->set_sample_count(1u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	histogram->set_sample_sum(1u);
	histogram->set_minimum(1u);
	histogram->set_maximum(1u);
	histogram->set_p50(1u);
	histogram->set_p90(1u);
	histogram->set_p99(1u);
	histogram->set_p999(1u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	histogram->set_minimum(2u);
	histogram->set_maximum(2u);
	histogram->set_p50(1u);
	histogram->set_p90(2u);
	histogram->set_p99(2u);
	histogram->set_p999(2u);
	histogram->set_sample_sum(2u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	histogram->set_minimum(1u);
	histogram->set_maximum(1u);
	histogram->set_p50(1u);
	histogram->set_p90(1u);
	histogram->set_p99(1u);
	histogram->set_p999(1u);
	histogram->set_sample_sum(1u);

	health->set_state(telemetry::MODULE_HEALTH_STATE_ATTEMPT_SUPPRESSED);
	health->set_publication_generation(1u);
	health->set_observation_epoch(5u);
	health->set_observed_at_ns(90u);
	health->set_callback_duration_ns(1u);
	health->set_contract_fault_count(1u);
	health->set_latest_fault_mask(1u);
	health->set_first_fault_mask(1u);
	health->set_first_fault_epoch(5u);
	health->set_first_fault_timestamp_ns(90u);
	health->set_first_fault_duration_ns(1u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	health->set_latest_fault_mask(1u << 4u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	health->set_latest_fault_mask(1u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	health->set_state(telemetry::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE);
	health->set_latest_fault_mask(0u);
	health->set_health_score(100u);
	health->set_health_flags(0u);
	health->set_reason(std::string(1u, static_cast<char>(0xc0)));
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	health->set_reason("healthy");
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	health->set_observation_epoch(4u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	health->set_state(telemetry::MODULE_HEALTH_STATE_STALE_EPOCH);
	health->clear_health_score();
	health->clear_health_flags();
	health->clear_reason();
	health->set_first_fault_epoch(4u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	health->set_first_fault_epoch(5u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	health->set_first_fault_epoch(4u);
	health->set_state(telemetry::MODULE_HEALTH_STATE_SIGNAL_AVAILABLE);
	health->set_observation_epoch(5u);
	health->set_health_score(100u);
	health->set_health_flags(0u);
	health->set_reason("healthy");
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());

	histogram->set_sample_sum(0u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	histogram->set_sample_sum(1u);

	auto allocator_only = valid_telemetry();
	allocator_only.mutable_protocol_faults()->mutable_counters(12)->set_count(1u);
	EXPECT_FALSE(validate_runtime_telemetry(allocator_only, telemetry::TelemetrySelection{}).is_ok());
	auto *allocator_first = allocator_only.mutable_protocol_faults()->mutable_first_fault();
	allocator_first->set_code(telemetry::EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED);
	allocator_first->set_disposition(telemetry::EPOCH_PROTOCOL_FAULT_DISPOSITION_RESOURCE_REFUSED);
	allocator_first->set_runtime_generation(1u);
	allocator_first->set_observed_monotonic_ns(99u);
	allocator_first->set_worker_index(UINT32_MAX);
	allocator_first->set_boundary_index(UINT32_MAX);
	allocator_first->set_context_index(UINT32_MAX);
	allocator_first->set_stage_instance_index(UINT32_MAX);
	EXPECT_TRUE(validate_runtime_telemetry(allocator_only, telemetry::TelemetrySelection{}).is_ok());

	auto duplicate_context = valid_telemetry();
	duplicate_context.mutable_transition()->set_module_context_count(2u);
	for (uint32_t index = 0u; index < 2u; ++index) {
		auto *row = duplicate_context.add_module_epoch_mismatches();
		row->set_module_id("kinetum.test");
		row->set_context_instance_id("duplicate.context");
		row->set_context_index(index);
		row->set_observation_epoch(5u);
	}
	telemetry::TelemetrySelection metrics_only;
	metrics_only.set_include_module_metrics(true);
	EXPECT_FALSE(validate_runtime_telemetry(duplicate_context, metrics_only).is_ok());

	value.mutable_protocol_faults()->mutable_counters(0)->set_count(1u);
	value.mutable_protocol_faults()->set_transition_success_blocked(true);
	auto *first = value.mutable_protocol_faults()->mutable_first_fault();
	first->set_code(telemetry::EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH);
	first->set_disposition(telemetry::EPOCH_PROTOCOL_FAULT_DISPOSITION_DROP_AND_RETIRE);
	first->set_runtime_generation(1u);
	first->set_observed_monotonic_ns(99u);
	first->set_worker_index(0u);
	first->set_boundary_index(UINT32_MAX);
	first->set_context_index(UINT32_MAX);
	first->set_stage_instance_index(UINT32_MAX);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	first->set_runtime_generation(2u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	first->set_runtime_generation(1u);
	first->set_disposition(telemetry::EPOCH_PROTOCOL_FAULT_DISPOSITION_RESOURCE_REFUSED);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	first->set_disposition(telemetry::EPOCH_PROTOCOL_FAULT_DISPOSITION_DROP_AND_RETIRE);
	value.mutable_protocol_faults()->set_transition_success_blocked(false);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	value.mutable_protocol_faults()->set_transition_success_blocked(true);
	first->set_transition_generation(UINT64_MAX);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	first->set_transition_generation(0u);
	first->set_from_epoch(5u);
	first->set_to_epoch(4u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	first->set_from_epoch(0u);
	first->set_to_epoch(0u);
	first->set_context_index(0u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
}

/** @brief Reject impossible transaction, certificate, grace, and boundary time order. */
TEST(runtime_telemetry_contract, causal_and_identity_contradictions_fail_closed)
{
	telemetry::TelemetrySelection selection;
	selection.set_include_boundary_epoch_stats(true);
	auto value = valid_telemetry();
	value.mutable_runtime()->set_active_workers(2u);
	value.mutable_runtime()->set_expected_workers(2u);
	value.mutable_transition()->set_execution_participant_count(2u);
	value.mutable_transition()->set_quiescence_reader_count(2u);
	value.mutable_transition()->set_boundary_count(1u);
	value.mutable_transition()->set_allocated_epoch_high_watermark(6u);
	value.mutable_transition()->set_mutation_sequence_high_watermark(2u);
	value.mutable_transition()->set_terminal_history_size(1u);
	auto *terminal = value.mutable_transition()->mutable_latest_terminal();
	terminal->set_mutation_sequence(2u);
	terminal->set_from_epoch(5u);
	terminal->set_to_epoch(6u);
	terminal->set_validation_hash(std::string(32u, '\x02'));
	terminal->set_idempotency_key_digest(std::string(32u, '\x03'));
	terminal->set_admitted_monotonic_ns(10u);
	terminal->set_terminal_monotonic_ns(20u);
	terminal->set_outcome(telemetry::EPOCH_TRANSITION_OUTCOME_ABORTED);
	terminal->set_failure_code(telemetry::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	terminal->set_prepared_monotonic_ns(15u);
	terminal->set_failure_observed_monotonic_ns(15u);
	terminal->set_terminal_monotonic_ns(101u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	terminal->set_terminal_monotonic_ns(20u);
	terminal->set_prepared_monotonic_ns(21u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	terminal->set_prepared_monotonic_ns(15u);
	terminal->set_failure_observed_monotonic_ns(14u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	terminal->set_failure_observed_monotonic_ns(15u);
	auto *boundary = value.add_boundaries();
	boundary->set_boundary_id("boundary.0");
	boundary->set_receiver_worker_index(1u);
	boundary->set_from_region_id(0);
	boundary->set_to_region_id(1);
	boundary->set_data_ring_capacity(2u);
	boundary->set_future_output_hold_capacity(2u);
	boundary->set_sender_phase(telemetry::BOUNDARY_SENDER_PHASE_OPEN);
	boundary->set_receiver_phase(telemetry::BOUNDARY_RECEIVER_PHASE_OPEN);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());

	boundary->set_transition_generation(2u);
	boundary->set_from_epoch(5u);
	boundary->set_to_epoch(6u);
	boundary->set_cut_sequence(1u);
	boundary->set_data_enqueued_sequence(1u);
	boundary->set_sender_phase(telemetry::BOUNDARY_SENDER_PHASE_WAITING_ACK);
	boundary->set_receiver_phase(telemetry::BOUNDARY_RECEIVER_PHASE_CUT_DRAINING);
	boundary->set_cut_published_monotonic_ns(80u);
	boundary->set_cut_observed_monotonic_ns(70u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	boundary->set_cut_observed_monotonic_ns(90u);
	boundary->set_cut_delivery_duration_ns(10u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	boundary->set_cut_sequence(2u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	boundary->set_cut_sequence(1u);
	boundary->set_data_enqueued_sequence(UINT64_MAX);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	boundary->set_data_enqueued_sequence(1u);
	EXPECT_TRUE(validate_runtime_telemetry(value, selection).is_ok());
	boundary->set_sender_phase(telemetry::BOUNDARY_SENDER_PHASE_OPEN);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	boundary->set_sender_phase(telemetry::BOUNDARY_SENDER_PHASE_WAITING_ACK);
	boundary->clear_cut_delivery_duration_ns();
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	boundary->set_cut_delivery_duration_ns(10u);
	boundary->set_cut_delivery_duration_ns(11u);
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());
	boundary->clear_cut_delivery_duration_ns();
	boundary->clear_cut_published_monotonic_ns();
	EXPECT_FALSE(validate_runtime_telemetry(value, selection).is_ok());

	telemetry::TelemetrySelection mandatory_only;
	auto committed = valid_telemetry();
	auto *committing = committed.mutable_transition();
	committing->set_state(telemetry::EPOCH_TRANSITION_STATE_COMMITTING);
	committing->set_participant_set_frozen(true);
	committing->set_target_epoch(6u);
	committing->set_allocated_epoch_high_watermark(6u);
	committing->set_mutation_sequence_high_watermark(2u);
	auto *active = committing->mutable_active_transaction();
	active->set_mutation_sequence(2u);
	active->set_from_epoch(5u);
	active->set_to_epoch(6u);
	active->set_validation_hash(std::string(32u, '\x04'));
	active->set_idempotency_key_digest(std::string(32u, '\x05'));
	active->set_admitted_monotonic_ns(10u);
	active->set_prepared_monotonic_ns(20u);
	active->set_commit_started_monotonic_ns(30u);
	active->set_outcome(telemetry::EPOCH_TRANSITION_OUTCOME_NONE);
	active->set_failure_code(telemetry::EPOCH_TRANSITION_FAILURE_CODE_NONE);
	EXPECT_FALSE(validate_runtime_telemetry(committed, mandatory_only).is_ok());
	auto *grace = committing->mutable_grace();
	grace->set_generation(1u);
	grace->set_started_monotonic_ns(30u);
	grace->set_readers_total(1u);
	grace->set_active(true);
	EXPECT_TRUE(validate_runtime_telemetry(committed, mandatory_only).is_ok());
	committing->set_participant_set_frozen(false);
	EXPECT_FALSE(validate_runtime_telemetry(committed, mandatory_only).is_ok());
	committing->set_participant_set_frozen(true);
	auto *certificate = committing->mutable_certificate();
	certificate->set_evaluated_monotonic_ns(29u);
	certificate->set_runtime_generation(1u);
	certificate->set_transition_generation(2u);
	certificate->set_from_epoch(5u);
	certificate->set_to_epoch(6u);
	certificate->set_execution_total(1u);
	certificate->set_reader_total(1u);
	certificate->set_fault_index(UINT32_MAX);
	certificate->set_state(telemetry::EPOCH_CERTIFICATE_STATE_INCOMPLETE);
	certificate->set_fault(telemetry::EPOCH_CERTIFICATE_FAULT_NONE);
	EXPECT_FALSE(validate_runtime_telemetry(committed, mandatory_only).is_ok());
	certificate->set_evaluated_monotonic_ns(30u);
	EXPECT_TRUE(validate_runtime_telemetry(committed, mandatory_only).is_ok());
	grace->set_started_monotonic_ns(31u);
	EXPECT_FALSE(validate_runtime_telemetry(committed, mandatory_only).is_ok());
	grace->set_started_monotonic_ns(30u);
	telemetry::TelemetrySelection worker_selection;
	worker_selection.set_include_worker_epoch_stats(true);
	auto *worker = committed.add_workers();
	worker->set_worker_id("worker_0");
	worker->set_lane_id("lane_0");
	worker->set_ledger_publication_generation(1u);
	worker->set_active_epoch(5u);
	worker->set_source_epoch(5u);
	worker->set_activation_publication_generation(1u);
	worker->set_transition_generation(3u);
	worker->set_from_epoch(4u);
	worker->set_to_epoch(5u);
	worker->set_activation_monotonic_ns(20u);
	worker->set_activation_complete(true);
	EXPECT_FALSE(validate_runtime_telemetry(committed, worker_selection).is_ok());
	worker->set_transition_generation(1u);
	EXPECT_TRUE(validate_runtime_telemetry(committed, worker_selection).is_ok());
}

}  // namespace kinetum::common
