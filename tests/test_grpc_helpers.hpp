// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file test_grpc_helpers.hpp
 * @brief Neutral, reusable fake Data Plane gRPC service and RAII server.
 * @author Fleming Patel
 *
 * Provides deterministic, configurable telemetry responses and an optional
 * exact passive transition state machine for CP-client integration tests.
 *
 * Design:
 * -------
 * - fake_dp_service: GetStats returns configurable fields; transition RPCs
 *   either return application unavailable or execute one exact serialized fake
 *   PREPARED-to-terminal transaction for CP integration tests.
 * - fake_dp_server: RAII wrapper that starts an in-process gRPC server
 *   on an OS-assigned port and creates a stub. Deterministic teardown.
 *
 * Thread Safety:
 * - Atomic call counters for concurrency-safe assertions.
 * - One mutex serializes the optional fake transition identity/state. Other
 *   configurable fields are set before start. Inline test observers may
 *   change a later-call fixture value only when that test serializes RPCs.
 *
 * @see tests/test_guardrails.cpp for policy-specific derived behavior
 * @see tests/test_cp_stats_forwarding.cpp for stats forwarding tests
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>

#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/status.hpp"
#include "src/common/version.hpp"

namespace kinetum::test
{

// ===============================================================================
// Configurable stage/region/boundary data for GetStats responses
// ===============================================================================

/** @brief Configurable stage-counter row emitted by the fake service. */
struct fake_stage_stats {
	std::string stage_id;	      ///< Exact logical-stage identity.
	uint64_t in_packets{0};	      ///< Cumulative admitted stage inputs.
	uint64_t out_packets{0};      ///< Cumulative stage outputs.
	uint64_t dropped_packets{0};  ///< Cumulative terminal stage drops.
};

/** @brief Configurable region epoch/accounting row emitted by the fake. */
struct fake_region_epoch_stats {
	int32_t region_id{0};		     ///< Exact logical-region identity.
	uint32_t worker_count{1};	     ///< Workers represented by the row.
	uint64_t active_epoch{5};	     ///< Uniform active epoch for the fake row.
	uint64_t source_epoch{5};	     ///< Uniform source epoch for the fake row.
	uint64_t active_unretired{0};	     ///< Aggregate active-slot ownership credits.
	uint64_t future_unretired{0};	     ///< Aggregate future-slot ownership credits.
	uint32_t activated_participants{0};  ///< Participants with a completed activation edge.
	uint64_t fanout_overflow{0};	     ///< Cumulative refused fan-out branches.
};

/** @brief Configurable exact boundary protocol row emitted by the fake. */
struct fake_boundary_epoch_stats {
	std::string boundary_id;		  ///< Exact compiled boundary identity.
	uint32_t boundary_index{0};		  ///< Compact boundary index.
	uint32_t from_stage_instance_index{0};	  ///< Compact sender stage-instance index.
	uint32_t to_stage_instance_index{1};	  ///< Compact receiver stage-instance index.
	uint32_t sender_worker_index{0};	  ///< Compact sender worker index.
	uint32_t receiver_worker_index{1};	  ///< Compact receiver worker index.
	int32_t from_region_id{0};		  ///< Sender logical-region identity.
	int32_t to_region_id{1};		  ///< Receiver logical-region identity.
	uint32_t data_ring_capacity{2};		  ///< Exact DATA-ring capacity.
	uint32_t future_output_hold_capacity{2};  ///< Exact future-output hold capacity.
	uint64_t data_enqueued_sequence{0};	  ///< Successful DATA enqueue sequence.
	uint64_t data_dequeued_sequence{0};	  ///< Credit-completed DATA dequeue sequence.
	uint64_t data_backpressure_events{0};	  ///< Cumulative DATA backpressure observations.
	uint64_t transition_generation{0};	  ///< Exact mutation sequence when transitioning.
	uint64_t from_epoch{0};			  ///< Exact transition source epoch.
	uint64_t to_epoch{0};			  ///< Exact transition target epoch.
	std::optional<uint64_t> cut_sequence;	  ///< Exact CUT watermark when present.
	/** Exact sender policy phase. */
	kinetum::telemetry::v1::BoundarySenderPhase sender_phase{kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_OPEN};
	/** Exact receiver policy phase. */
	kinetum::telemetry::v1::BoundaryReceiverPhase receiver_phase{
		kinetum::telemetry::v1::BOUNDARY_RECEIVER_PHASE_OPEN};
	uint64_t cut_delivery_duration_ns{0};  ///< CUT publication-to-observation duration.
	uint64_t cut_drain_duration_ns{0};     ///< CUT observation-to-drain duration.
	uint64_t ack_gate_duration_ns{0};      ///< Sender gate-closed duration.
};

/** @brief Configurable executable I/O-stream row emitted by the fake. */
struct fake_stream_stats {
	std::string io_stream_id;     ///< Exact compiled stream identity.
	uint32_t logical_port_id{0};  ///< Exact logical port identity.
	/** Exact stream direction. */
	kinetum::gluon::v1::IoStreamDirection direction{kinetum::gluon::v1::IO_STREAM_DIRECTION_UNSPECIFIED};
	int32_t owning_region_id{0};		      ///< Owning logical region.
	uint32_t worker_index{0};		      ///< Owning compact worker.
	uint32_t driver_queue_id{0};		      ///< Exact driver-local queue.
	uint64_t published_monotonic_ns{0};	      ///< Exact owner-bank publication time.
	std::optional<uint64_t> packets{0};	      ///< Explicit transferred-packet count.
	std::optional<uint64_t> bytes{0};	      ///< Explicit transferred-byte count.
	std::optional<uint64_t> rejected_packets{0};  ///< Explicit software rejection count.
};

/** @brief Configurable packet-storage observation emitted by the fake. */
struct fake_storage_domain_stats {
	std::string storage_domain_id;		///< Exact compiled storage identity.
	std::optional<int32_t> host_numa_node;	///< Proven host NUMA node when available.
	uint64_t buffer_count{0};		///< Exact authored physical capacity.
	uint64_t required_min_buffers{0};	///< Compiler-derived minimum population.
	uint32_t safety_margin{0};		///< Exact compiler safety margin.
	/** Typed provider-observation availability. */
	kinetum::telemetry::v1::ProviderObservationState observation_state{
		kinetum::telemetry::v1::PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE};
	std::optional<uint64_t> in_use{0};     ///< In-use population when available.
	std::optional<uint64_t> available{0};  ///< Available population when available.
};

/** @brief Configurable logical/driver port observation emitted by the fake. */
struct fake_port_stats {
	uint32_t logical_port_id{0};	    ///< Exact logical-port index.
	std::string logical_name;	    ///< Exact logical-port name.
	std::string io_driver_instance_id;  ///< Exact owning I/O-driver identity.
	std::string driver_port_id;	    ///< Exact driver-local port identity.
	/** Typed provider-observation availability. */
	kinetum::telemetry::v1::ProviderObservationState observation_state{
		kinetum::telemetry::v1::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT};
	std::optional<uint64_t> rx_packets{0};	  ///< Received packets when available.
	std::optional<uint64_t> tx_packets{0};	  ///< Transmitted packets when available.
	std::optional<uint64_t> rx_bytes{0};	  ///< Received bytes when available.
	std::optional<uint64_t> tx_bytes{0};	  ///< Transmitted bytes when available.
	std::optional<uint64_t> rx_missed{0};	  ///< Native missed ingress when available.
	std::optional<uint64_t> rx_errors{0};	  ///< Native ingress errors when available.
	std::optional<uint64_t> tx_errors{0};	  ///< Native egress errors when available.
	std::optional<uint64_t> rx_no_buffer{0};  ///< Native no-buffer count when available.
};

/** @brief Configurable traffic-steering identity emitted by the fake. */
struct fake_traffic_steering_stats {
	std::string steering_profile_id;  ///< Exact compiled profile identity.
	/** Exact steering kind. */
	kinetum::gluon::v1::TrafficSteeringKind kind{kinetum::gluon::v1::TRAFFIC_STEERING_KIND_UNSPECIFIED};
	bool symmetric{false};			 ///< Whether steering is symmetric.
	std::vector<std::string> io_stream_ids;	 ///< Exact ordered stream membership.
};

/** @brief Configurable module-context population emitted by the fake. */
struct fake_module_context_domain {
	std::string module_id;				///< Exact module identity.
	std::vector<std::string> context_instance_ids;	///< Canonical ordinal order.
};

/** @brief Exact latest COMPLETE transaction emitted by the fake telemetry source. */
struct fake_completed_transition_stats {
	uint64_t mutation_sequence{0};	     ///< Exact terminal mutation identity.
	uint64_t from_epoch{0};		     ///< Last durable active epoch.
	uint64_t to_epoch{0};		     ///< Newly completed Data Plane epoch.
	std::string validation_hash;	     ///< Raw target ConfigSnapshot hash.
	std::string idempotency_key_digest;  ///< Raw transition-key digest.
};

// ===============================================================================
// fake_dp_service - neutral, deterministic fake DP
// ===============================================================================

/** @brief Minimal exact fake transition phase used only by CP integration tests. */
enum class fake_dp_transition_phase : uint8_t {
	IDLE = 0,  ///< No identity has been admitted.
	PREPARED,  ///< One exact identity owns PREPARED state.
	COMPLETE,  ///< The same identity is terminal COMPLETE.
	ABORTED,   ///< The same identity is terminal ABORTED.
};

/** @brief Deterministic configurable Data Plane service for CP integration. */
class fake_dp_service : public kinetum::dataplane::v1::DataplaneService::Service {
    public:
	/** Enable the exact PREPARED-to-COMPLETE fake transition path. */
	bool complete_transitions{false};
	/** Exact frozen plan identity returned by successful Status. */
	std::string transition_plan_content_hash = std::string(std::size_t{32} * 2u, '0');
	std::function<void()> activate_observer;  ///< Optional pre-Activate test observation.
	std::atomic<bool> fail_next_activate_transport_before_commit{false};  ///< Simulate a lost request.
	std::atomic<bool> fail_next_activate_transport_after_commit{false};   ///< Simulate an ambiguous reply loss.
	// -------------------------------------------------------------------------
	// Configurable GetStats response data (set before server start)
	// -------------------------------------------------------------------------
	uint64_t rx_packets{1000};				 ///< Cumulative engine RX packets.
	uint64_t tx_packets{990};				 ///< Cumulative accepted engine TX packets.
	uint64_t dropped_packets{10};				 ///< Cumulative terminal packet retirements.
	uint64_t active_epoch{5};				 ///< Exact active runtime epoch.
	uint64_t min_retained_epoch{5};				 ///< Minimum retained runtime epoch.
	uint64_t rx_bytes{0};					 ///< Cumulative engine RX bytes.
	uint64_t tx_bytes{0};					 ///< Cumulative engine TX bytes.
	uint64_t runtime_generation{1};				 ///< Exact process-generation identity.
	uint64_t collection_monotonic_ns{UINT64_C(1000000000)};	 ///< Collection timestamp.
	uint64_t latest_bank_publication_monotonic_ns{UINT64_C(999999000)};  ///< Latest merged bank time.
	std::string plan_content_hash{32u, '\x01'};			     ///< Raw exact plan digest.
	std::string active_validation_hash{32u, '\x02'};		     ///< Raw hash paired with active_epoch.
	std::optional<uint64_t> allocated_epoch_high_watermark;	   ///< Override for an in-flight durable allocation.
	std::optional<uint64_t> mutation_sequence_high_watermark;  ///< Override for an in-flight durable allocation.
	std::optional<fake_completed_transition_stats> latest_completed_transition;  ///< Optional DP-ahead result.
	int32_t stats_status_code{0};						     ///< Embedded GetStats status code.
	kinetum::common::v1::ErrorCode stats_error_code{
		kinetum::common::v1::ERROR_CODE_OK};		       ///< Embedded GetStats error classification.
	std::string stats_status_message;			       ///< Embedded GetStats diagnostic.
	grpc::StatusCode stats_transport_code{grpc::StatusCode::OK};   ///< GetStats transport outcome.
	std::string stats_transport_message;			       ///< GetStats transport diagnostic.
	grpc::StatusCode health_transport_code{grpc::StatusCode::OK};  ///< Health transport outcome.
	std::string health_transport_message;			       ///< Health transport diagnostic.
	std::atomic<int> health_calls{0};			       ///< Exact Health call count.
	std::optional<uint64_t> health_active_epoch_override;	       ///< Optional stale Health-only epoch.
	std::function<void()> stats_observer;			       ///< Optional post-Stats test edge.
	std::function<void(grpc::ServerContext &, kinetum::dataplane::v1::StatsResponse &)> stats_response_observer;
	///< Optional transport-context and response inspection after normal response construction.
	grpc::StatusCode bootstrap_transport_code{grpc::StatusCode::OK};  ///< Bootstrap transport outcome.
	std::string bootstrap_transport_message;			  ///< Bootstrap transport diagnostic.
	std::string bootstrap_status_message;  ///< Application-level Bootstrap rejection diagnostic.
	kinetum::dataplane::v1::HealthResponse::State readiness_state{
		kinetum::dataplane::v1::HealthResponse::STATE_CONTROL_READY};  ///< Exact startup posture.

	std::vector<fake_stage_stats> stage_stats;			  ///< Selected stage rows.
	std::vector<fake_region_epoch_stats> region_epoch_stats;	  ///< Selected region rows.
	std::vector<fake_boundary_epoch_stats> boundary_epoch_stats;	  ///< Selected boundary rows.
	std::vector<fake_stream_stats> stream_stats;			  ///< Selected executable-stream rows.
	std::vector<fake_storage_domain_stats> storage_domain_stats;	  ///< Selected storage rows.
	std::vector<fake_port_stats> port_stats;			  ///< Selected driver-port rows.
	std::vector<fake_traffic_steering_stats> traffic_steering_stats;  ///< Selected steering rows.
	std::vector<fake_module_context_domain> module_context_domains;	  ///< Complete fixture context populations.

	// -------------------------------------------------------------------------
	// Call counters (atomic for thread safety)
	// -------------------------------------------------------------------------
	std::atomic<int> get_stats_calls{0};	      ///< Number of GetStats calls received.
	std::atomic<int> bootstrap_calls{0};	      ///< Number of Bootstrap calls received.
	std::atomic<int> prepare_calls{0};	      ///< Number of Prepare calls received.
	std::atomic<int> activate_calls{0};	      ///< Number of Activate calls received.
	std::atomic<int> abort_calls{0};	      ///< Number of Abort calls received.
	std::atomic<int> transition_status_calls{0};  ///< Number of transition Status calls received.
	std::mutex transition_mutex;		      ///< Protects exact fake transition identity below.
	fake_dp_transition_phase transition_phase{fake_dp_transition_phase::IDLE};  ///< Current fake phase.
	uint64_t transition_epoch{0};						    ///< Exact target epoch.
	uint64_t transition_sequence{0};					    ///< Exact mutation sequence.
	uint64_t transition_from_epoch{1};					    ///< Baseline active epoch.
	std::string transition_validation_hash;					    ///< Raw 32-byte validation digest.
	std::string transition_key;						    ///< Exact caller key.

	/**
	 * @brief Return the number of exact transition RPCs received by the fake.
	 *
	 * @return Sum of Bootstrap, Prepare, Activate, Abort, and Status calls.
	 *
	 * @par Thread Safety
	 * Safe during concurrent RPC dispatch; every counter is loaded with relaxed
	 * ordering because the aggregate is diagnostic only.
	 */
	[[nodiscard]] int transition_calls() const noexcept
	{
		return bootstrap_calls.load(std::memory_order_relaxed) + prepare_calls.load(std::memory_order_relaxed) +
		       activate_calls.load(std::memory_order_relaxed) + abort_calls.load(std::memory_order_relaxed) +
		       transition_status_calls.load(std::memory_order_relaxed);
	}

	// -------------------------------------------------------------------------
	// GetStats - returns configured data, respects request flags
	// -------------------------------------------------------------------------
	/**
	 * @brief Return the fake's configured telemetry with production flag gating.
	 *
	 * @param ctx Actual gRPC server context passed to the optional observation hook.
	 * @param req Detail-selection flags controlling optional telemetry groups.
	 * @param resp Response receiving the configured cumulative telemetry.
	 * @return Configured transport outcome after populating the response.
	 */
	grpc::Status GetStats(grpc::ServerContext *ctx, const kinetum::dataplane::v1::StatsRequest *req,
			      kinetum::dataplane::v1::StatsResponse *resp) override
	{
		get_stats_calls.fetch_add(1, std::memory_order_relaxed);
		resp->Clear();
		resp->mutable_status()->set_code(stats_status_code);
		resp->mutable_status()->set_error_code(stats_error_code);
		resp->mutable_status()->set_message(stats_status_message);
		uint32_t participant_count = 1u;
		for (const auto &boundary : boundary_epoch_stats) {
			participant_count = std::max(participant_count, boundary.sender_worker_index + 1u);
			participant_count = std::max(participant_count, boundary.receiver_worker_index + 1u);
		}
		uint64_t region_workers = 0u;
		uint64_t region_fanout_overflow = 0u;
		for (const auto &region : region_epoch_stats) {
			region_workers += region.worker_count;
			region_fanout_overflow = region.fanout_overflow > UINT64_MAX - region_fanout_overflow ?
							 UINT64_MAX :
							 region_fanout_overflow + region.fanout_overflow;
		}
		if (region_workers != 0u && region_workers <= UINT32_MAX) {
			participant_count = std::max(participant_count, static_cast<uint32_t>(region_workers));
		}
		auto *telemetry = resp->mutable_telemetry();
		auto *runtime = telemetry->mutable_runtime();
		runtime->set_runtime_generation(runtime_generation);
		runtime->set_status_publication_generation(1u);
		runtime->set_active_epoch(active_epoch);
		runtime->set_minimum_retained_epoch(min_retained_epoch);
		runtime->set_last_activated_epoch(active_epoch);
		runtime->set_active_workers(participant_count);
		runtime->set_expected_workers(participant_count);
		runtime->set_collection_monotonic_ns(collection_monotonic_ns);
		runtime->set_latest_bank_publication_monotonic_ns(latest_bank_publication_monotonic_ns);
		auto *engine = telemetry->mutable_engine();
		engine->set_rx_packets(rx_packets);
		engine->set_tx_packets(tx_packets);
		engine->set_dropped_packets(dropped_packets);
		engine->set_rx_bytes(rx_bytes);
		engine->set_tx_bytes(tx_bytes);
		engine->set_fanout_overflow(region_fanout_overflow);
		auto *transition = telemetry->mutable_transition();
		transition->set_publication_generation(1u);
		transition->set_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE);
		transition->set_active_epoch(active_epoch);
		transition->set_allocated_epoch_high_watermark(allocated_epoch_high_watermark.value_or(active_epoch));
		transition->set_mutation_sequence_high_watermark(mutation_sequence_high_watermark.value_or(1u));
		transition->set_plan_content_hash(plan_content_hash);
		transition->set_active_validation_hash(active_validation_hash);
		transition->set_participant_set_frozen(false);
		transition->set_execution_participant_count(participant_count);
		transition->set_region_count(
			static_cast<uint32_t>(std::max<std::size_t>(1u, region_epoch_stats.size())));
		transition->set_boundary_count(static_cast<uint32_t>(boundary_epoch_stats.size()));
		transition->set_source_participant_count(1u);
		transition->set_sink_participant_count(1u);
		transition->set_quiescence_reader_count(participant_count);
		uint32_t context_index = 0u;
		for (const auto &domain : module_context_domains) {
			for (const auto &identity : domain.context_instance_ids) {
				if (req != nullptr && req->selection().include_module_metrics()) {
					auto *row = telemetry->add_module_epoch_mismatches();
					row->set_module_id(domain.module_id);
					row->set_context_instance_id(identity);
					row->set_context_index(context_index);
					row->set_worker_index(0u);
					row->set_observation_epoch(active_epoch);
				}
				if (req != nullptr && req->selection().include_module_health()) {
					auto *row = telemetry->add_module_health();
					row->set_module_id(domain.module_id);
					row->set_context_instance_id(identity);
					row->set_context_index(context_index);
					row->set_worker_index(0u);
					row->set_stage_instance_index(context_index);
					row->set_state(
						kinetum::telemetry::v1::MODULE_HEALTH_STATE_CALLBACK_UNAVAILABLE);
				}
				++context_index;
			}
		}
		transition->set_module_context_count(context_index);
		if (latest_completed_transition.has_value()) {
			transition->set_terminal_history_size(1u);
			auto *terminal = transition->mutable_latest_terminal();
			terminal->set_mutation_sequence(latest_completed_transition->mutation_sequence);
			terminal->set_from_epoch(latest_completed_transition->from_epoch);
			terminal->set_to_epoch(latest_completed_transition->to_epoch);
			terminal->set_validation_hash(latest_completed_transition->validation_hash);
			terminal->set_idempotency_key_digest(latest_completed_transition->idempotency_key_digest);
			terminal->set_admitted_monotonic_ns(10u);
			terminal->set_prepared_monotonic_ns(20u);
			terminal->set_commit_started_monotonic_ns(30u);
			terminal->set_retiring_started_monotonic_ns(40u);
			terminal->set_terminal_monotonic_ns(50u);
			terminal->set_outcome(kinetum::telemetry::v1::EPOCH_TRANSITION_OUTCOME_COMPLETE);
			terminal->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
		}
		auto *faults = telemetry->mutable_protocol_faults();
		for (int code = 1; code <= 13; ++code) {
			auto *counter = faults->add_counters();
			counter->set_code(static_cast<kinetum::telemetry::v1::EpochProtocolFaultCode>(code));
			counter->set_count(0u);
		}

		// A successful fake response follows the stage-selection contract.
		if (req != nullptr && req->selection().include_stage_stats()) {
			for (const auto &ss : stage_stats) {
				auto *out = telemetry->add_stages();
				out->set_stage_id(ss.stage_id);
				out->set_in_packets(ss.in_packets);
				out->set_out_packets(ss.out_packets);
				out->set_dropped_packets(ss.dropped_packets);
			}
		}

		// A successful fake response follows the region-selection contract.
		if (req != nullptr && req->selection().include_region_epoch_stats()) {
			for (const auto &rs : region_epoch_stats) {
				auto *out = telemetry->add_regions();
				out->set_region_id(rs.region_id);
				out->set_worker_count(rs.worker_count);
				out->set_minimum_active_epoch(rs.active_epoch);
				out->set_maximum_active_epoch(rs.active_epoch);
				out->set_minimum_source_epoch(rs.source_epoch);
				out->set_maximum_source_epoch(rs.source_epoch);
				out->set_active_unretired(rs.active_unretired);
				out->set_future_unretired(rs.future_unretired);
				out->set_activated_participants(rs.activated_participants);
				out->set_fanout_overflow(rs.fanout_overflow);
			}
		}

		if (req != nullptr && req->selection().include_boundary_epoch_stats()) {
			for (const auto &bt : boundary_epoch_stats) {
				auto *out = telemetry->add_boundaries();
				out->set_boundary_id(bt.boundary_id);
				out->set_boundary_index(bt.boundary_index);
				out->set_from_stage_instance_index(bt.from_stage_instance_index);
				out->set_to_stage_instance_index(bt.to_stage_instance_index);
				out->set_sender_worker_index(bt.sender_worker_index);
				out->set_receiver_worker_index(bt.receiver_worker_index);
				out->set_from_region_id(bt.from_region_id);
				out->set_to_region_id(bt.to_region_id);
				out->set_data_ring_capacity(bt.data_ring_capacity);
				out->set_future_output_hold_capacity(bt.future_output_hold_capacity);
				out->set_data_enqueued_sequence(bt.data_enqueued_sequence);
				out->set_data_dequeued_sequence(bt.data_dequeued_sequence);
				out->set_data_backpressure_events(bt.data_backpressure_events);
				out->set_sender_phase(bt.sender_phase);
				out->set_receiver_phase(bt.receiver_phase);
				if (bt.transition_generation != 0u) {
					out->set_transition_generation(bt.transition_generation);
					out->set_from_epoch(bt.from_epoch);
					out->set_to_epoch(bt.to_epoch);
					if (bt.cut_sequence.has_value()) {
						out->set_cut_sequence(*bt.cut_sequence);
					}
					out->set_cut_published_monotonic_ns(10u);
					out->set_cut_observed_monotonic_ns(10u + bt.cut_delivery_duration_ns);
					out->set_cut_drained_monotonic_ns(10u + bt.cut_delivery_duration_ns +
									  bt.cut_drain_duration_ns);
					out->set_activation_monotonic_ns(10u + bt.cut_delivery_duration_ns +
									 bt.cut_drain_duration_ns);
					out->set_ack_published_monotonic_ns(10u + bt.cut_delivery_duration_ns +
									    bt.cut_drain_duration_ns);
					out->set_ack_observed_monotonic_ns(10u + bt.ack_gate_duration_ns);
					out->set_cut_delivery_duration_ns(bt.cut_delivery_duration_ns);
					out->set_cut_drain_duration_ns(bt.cut_drain_duration_ns);
					out->set_ack_gate_duration_ns(bt.ack_gate_duration_ns);
				}
			}
		}

		if (req != nullptr && req->selection().include_stream_stats()) {
			for (const auto &ss : stream_stats) {
				auto *out = telemetry->add_streams();
				out->set_io_stream_id(ss.io_stream_id);
				out->set_logical_port_id(ss.logical_port_id);
				out->set_direction(ss.direction);
				out->set_owning_region_id(ss.owning_region_id);
				out->set_worker_index(ss.worker_index);
				out->set_driver_queue_id(ss.driver_queue_id);
				out->set_published_monotonic_ns(ss.published_monotonic_ns);
				if (ss.packets.has_value()) {
					out->set_packets(*ss.packets);
				}
				if (ss.bytes.has_value()) {
					out->set_bytes(*ss.bytes);
				}
				if (ss.rejected_packets.has_value()) {
					out->set_rejected_packets(*ss.rejected_packets);
				}
			}
		}

		if (req != nullptr && req->selection().include_storage_domain_stats()) {
			for (const auto &storage : storage_domain_stats) {
				auto *out = telemetry->add_storage_domains();
				out->set_storage_domain_id(storage.storage_domain_id);
				if (storage.host_numa_node.has_value()) {
					out->set_host_numa_node(storage.host_numa_node.value());
				}
				out->set_buffer_count(storage.buffer_count);
				out->set_required_min_buffers(storage.required_min_buffers);
				out->set_safety_margin(storage.safety_margin);
				out->set_observation_state(storage.observation_state);
				if (storage.in_use.has_value() && storage.available.has_value()) {
					out->set_observed_monotonic_ns(collection_monotonic_ns - 1u);
					out->set_in_use(*storage.in_use);
					out->set_available(*storage.available);
				}
			}
		}

		if (req != nullptr && req->selection().include_port_stats()) {
			for (const auto &ps : port_stats) {
				auto *out = telemetry->add_ports();
				out->set_logical_port_id(ps.logical_port_id);
				out->set_logical_name(ps.logical_name);
				out->set_io_driver_instance_id(ps.io_driver_instance_id);
				out->set_driver_port_id(ps.driver_port_id);
				out->set_observation_state(ps.observation_state);
				if (ps.rx_packets.has_value() && ps.tx_packets.has_value() && ps.rx_bytes.has_value() &&
				    ps.tx_bytes.has_value() && ps.rx_missed.has_value() && ps.rx_errors.has_value() &&
				    ps.tx_errors.has_value() && ps.rx_no_buffer.has_value()) {
					out->set_observed_monotonic_ns(collection_monotonic_ns - 1u);
					out->set_rx_packets(*ps.rx_packets);
					out->set_tx_packets(*ps.tx_packets);
					out->set_rx_bytes(*ps.rx_bytes);
					out->set_tx_bytes(*ps.tx_bytes);
					out->set_rx_missed(*ps.rx_missed);
					out->set_rx_errors(*ps.rx_errors);
					out->set_tx_errors(*ps.tx_errors);
					out->set_rx_no_buffer(*ps.rx_no_buffer);
				}
			}
		}

		if (req != nullptr && req->selection().include_topology_stats()) {
			for (const auto &ts : traffic_steering_stats) {
				auto *out = telemetry->add_steering_profiles();
				out->set_steering_profile_id(ts.steering_profile_id);
				out->set_kind(ts.kind);
				out->set_symmetric(ts.symmetric);
				for (const auto &stream_id : ts.io_stream_ids) {
					out->add_io_stream_ids(stream_id);
				}
			}
			for (const auto &domain : module_context_domains) {
				auto *out = telemetry->add_module_context_domains();
				out->set_module_id(domain.module_id);
				for (const auto &identity : domain.context_instance_ids) {
					out->add_context_instance_ids(identity);
				}
			}
		}

		if (stats_status_code != 0) {
			resp->clear_telemetry();
		}
		if (stats_response_observer) {
			stats_response_observer(*ctx, *resp);
		}
		if (stats_observer) {
			stats_observer();
		}
		if (stats_transport_code != grpc::StatusCode::OK) {
			return grpc::Status(stats_transport_code, stats_transport_message);
		}
		return grpc::Status::OK;
	}

	/**
	 * @brief Return one exact configured readiness observation.
	 * @param ctx Borrowed server context; unused.
	 * @param req Empty request; unused.
	 * @param resp Destination for canonical application success and readiness.
	 * @return Transport-level OK.
	 */
	grpc::Status Health(grpc::ServerContext *ctx, const kinetum::dataplane::v1::HealthRequest *req,
			    kinetum::dataplane::v1::HealthResponse *resp) override
	{
		(void)ctx;
		(void)req;
		health_calls.fetch_add(1, std::memory_order_relaxed);
		if (health_transport_code != grpc::StatusCode::OK) {
			return grpc::Status(health_transport_code, health_transport_message);
		}
		resp->Clear();
		resp->set_state(readiness_state);
		resp->mutable_status()->set_code(0);
		resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		resp->set_version(kinetum::common::KINETUM_VERSION_STRING);
		auto *logging = resp->mutable_logging();
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
		uint32_t participant_count = 1u;
		for (const auto &boundary : boundary_epoch_stats) {
			participant_count = std::max(participant_count, boundary.sender_worker_index + 1u);
			participant_count = std::max(participant_count, boundary.receiver_worker_index + 1u);
		}
		uint64_t region_workers = 0u;
		for (const auto &region : region_epoch_stats) {
			region_workers += region.worker_count;
		}
		if (region_workers != 0u && region_workers <= UINT32_MAX) {
			participant_count = std::max(participant_count, static_cast<uint32_t>(region_workers));
		}
		if (readiness_state == kinetum::dataplane::v1::HealthResponse::STATE_CONTROL_READY) {
			resp->set_runtime_generation(runtime_generation);
			resp->set_expected_workers(participant_count);
		} else if (readiness_state == kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY) {
			resp->set_runtime_generation(runtime_generation);
			resp->set_active_epoch(health_active_epoch_override.value_or(active_epoch));
			resp->set_active_workers(participant_count);
			resp->set_expected_workers(participant_count);
		}
		return grpc::Status::OK;
	}

	// -------------------------------------------------------------------------
	// Exact transition methods - optional serialized state machine or unavailable
	// -------------------------------------------------------------------------
	/**
	 * @brief Record and reject an accidental bootstrap call.
	 *
	 * @param ctx gRPC server context; unused by the fake.
	 * @param req Bootstrap request; unused by the fake.
	 * @param resp Response receiving application-level `UNAVAILABLE`.
	 * @return Transport-level `grpc::Status::OK`.
	 */
	grpc::Status BootstrapConfigSnapshot(grpc::ServerContext *ctx,
					     const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest *req,
					     kinetum::dataplane::v1::BootstrapConfigSnapshotResponse *resp) override
	{
		(void)ctx;
		(void)req;
		bootstrap_calls.fetch_add(1, std::memory_order_relaxed);
		if (bootstrap_transport_code != grpc::StatusCode::OK) {
			return grpc::Status(bootstrap_transport_code, bootstrap_transport_message);
		}
		resp->Clear();
		resp->mutable_status()->set_code(static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
		resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
		resp->mutable_status()->set_message(bootstrap_status_message);
		return grpc::Status::OK;
	}

	/**
	 * @brief Execute configured fake preparation or reject it unavailable.
	 *
	 * @param ctx gRPC server context; unused by the fake.
	 * @param req Prepare request consumed by the enabled fake state machine.
	 * @param resp Response receiving exact PREPARED or application `UNAVAILABLE`.
	 * @return Transport-level `grpc::Status::OK`.
	 */
	grpc::Status PrepareConfigSnapshot(grpc::ServerContext *ctx,
					   const kinetum::dataplane::v1::PrepareConfigSnapshotRequest *req,
					   kinetum::dataplane::v1::PrepareConfigSnapshotResponse *resp) override
	{
		(void)ctx;
		prepare_calls.fetch_add(1, std::memory_order_relaxed);
		if (complete_transitions) {
			std::lock_guard<std::mutex> lock(transition_mutex);
			auto hash_or = req != nullptr ?
					       kinetum::common::decode_sha256_digest_claim(
						       req->snapshot().content_hash(), "fake Prepare snapshot hash") :
					       kinetum::common::status_or<kinetum::common::sha256_digest>(
						       kinetum::common::status::invalid_argument(
							       "fake Prepare request is null"));
			if (!hash_or.is_ok() || req->target_epoch() == 0u || req->mutation_sequence() == 0u ||
			    req->idempotency_key().empty()) {
				resp->mutable_status()->set_code(
					static_cast<int32_t>(kinetum::common::status_code::INVALID_ARGUMENT));
				resp->mutable_status()->set_error_code(
					kinetum::common::v1::ERROR_CODE_INVALID_ARGUMENT);
				resp->set_identity_resolution(
					kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_INVALID);
				resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
				return grpc::Status::OK;
			}
			if (transition_phase == fake_dp_transition_phase::COMPLETE) {
				transition_from_epoch = transition_epoch;
			}
			transition_epoch = req->target_epoch();
			transition_sequence = req->mutation_sequence();
			transition_key = req->idempotency_key();
			transition_validation_hash.assign(reinterpret_cast<const char *>(hash_or->data()),
							  hash_or->size());
			transition_phase = fake_dp_transition_phase::PREPARED;
			resp->mutable_status()->set_code(0);
			resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
			resp->set_prepared_epoch(transition_epoch);
			resp->set_validation_hash(transition_validation_hash);
			resp->set_prepared_lease_deadline_unix_ms(1u);
			resp->set_mutation_sequence(transition_sequence);
			resp->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_PREPARED);
			resp->set_identity_resolution(
				kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_ACTIVE_EXACT);
			resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
			return grpc::Status::OK;
		}
		resp->mutable_status()->set_code(static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
		resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
		resp->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED);
		resp->set_identity_resolution(
			kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_POLICY_DISABLED);
		resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
		return grpc::Status::OK;
	}

	/**
	 * @brief Execute configured fake activation or reject it unavailable.
	 *
	 * @param ctx gRPC server context; unused by the fake.
	 * @param req Exact Activate identity consumed by the enabled fake state machine.
	 * @param resp Response receiving exact COMPLETE or application `UNAVAILABLE`.
	 * @return Transport-level `grpc::Status::OK`.
	 */
	grpc::Status ActivateConfigSnapshot(grpc::ServerContext *ctx,
					    const kinetum::dataplane::v1::ActivateConfigSnapshotRequest *req,
					    kinetum::dataplane::v1::ActivateConfigSnapshotResponse *resp) override
	{
		(void)ctx;
		activate_calls.fetch_add(1, std::memory_order_relaxed);
		if (complete_transitions) {
			if (activate_observer) {
				activate_observer();
			}
			std::lock_guard<std::mutex> lock(transition_mutex);
			const bool exact = req != nullptr && req->epoch() == transition_epoch &&
					   req->mutation_sequence() == transition_sequence &&
					   req->validation_hash() == transition_validation_hash &&
					   req->idempotency_key() == transition_key;
			if (!exact || (transition_phase != fake_dp_transition_phase::PREPARED &&
				       transition_phase != fake_dp_transition_phase::COMPLETE)) {
				resp->mutable_status()->set_code(
					static_cast<int32_t>(kinetum::common::status_code::FAILED_PRECONDITION));
				resp->mutable_status()->set_error_code(
					kinetum::common::v1::ERROR_CODE_FAILED_PRECONDITION);
				resp->set_identity_resolution(
					kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_IDENTITY_CONFLICT);
				resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
				return grpc::Status::OK;
			}
			if (transition_phase == fake_dp_transition_phase::PREPARED &&
			    fail_next_activate_transport_before_commit.exchange(false, std::memory_order_acq_rel)) {
				return grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED,
						    "fake Activate request was lost before commit");
			}
			transition_phase = fake_dp_transition_phase::COMPLETE;
			if (fail_next_activate_transport_after_commit.exchange(false, std::memory_order_acq_rel)) {
				return grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED,
						    "fake Activate reply was lost after commit");
			}
			resp->mutable_status()->set_code(0);
			resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
			resp->set_completed_epoch(transition_epoch);
			resp->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
			resp->set_transition_duration_ns(3u);
			resp->set_mutation_sequence(transition_sequence);
			resp->set_identity_resolution(
				kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT);
			resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
			return grpc::Status::OK;
		}
		resp->mutable_status()->set_code(static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
		resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
		resp->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED);
		resp->set_identity_resolution(
			kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_POLICY_DISABLED);
		resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
		return grpc::Status::OK;
	}

	/**
	 * @brief Execute configured fake pre-commit abort or reject it unavailable.
	 *
	 * @param ctx gRPC server context; unused by the fake.
	 * @param req Exact Abort identity consumed by the enabled fake state machine.
	 * @param resp Response receiving exact ABORTED or application `UNAVAILABLE`.
	 * @return Transport-level `grpc::Status::OK`.
	 */
	grpc::Status
	AbortPreparedConfigSnapshot(grpc::ServerContext *ctx,
				    const kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest *req,
				    kinetum::dataplane::v1::AbortPreparedConfigSnapshotResponse *resp) override
	{
		(void)ctx;
		abort_calls.fetch_add(1, std::memory_order_relaxed);
		if (complete_transitions) {
			std::lock_guard<std::mutex> lock(transition_mutex);
			const bool exact = req != nullptr && req->epoch() == transition_epoch &&
					   req->mutation_sequence() == transition_sequence &&
					   req->validation_hash() == transition_validation_hash &&
					   req->idempotency_key() == transition_key;
			if (!exact) {
				resp->mutable_status()->set_code(
					static_cast<int32_t>(kinetum::common::status_code::FAILED_PRECONDITION));
				resp->mutable_status()->set_error_code(
					kinetum::common::v1::ERROR_CODE_FAILED_PRECONDITION);
				resp->set_identity_resolution(
					kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_IDENTITY_CONFLICT);
				resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
				return grpc::Status::OK;
			}
			if (transition_phase == fake_dp_transition_phase::PREPARED) {
				transition_phase = fake_dp_transition_phase::ABORTED;
			}
			resp->mutable_status()->set_code(0);
			resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
			resp->set_transition_state(transition_phase == fake_dp_transition_phase::ABORTED ?
							   kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_ABORTED :
							   kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE);
			resp->set_mutation_sequence(transition_sequence);
			resp->set_identity_resolution(
				kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT);
			resp->set_failure_code(
				transition_phase == fake_dp_transition_phase::ABORTED ?
					kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT :
					kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
			return grpc::Status::OK;
		}
		resp->mutable_status()->set_code(static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
		resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
		resp->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED);
		resp->set_identity_resolution(
			kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_POLICY_DISABLED);
		resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
		return grpc::Status::OK;
	}

	/**
	 * @brief Return configured fake transition status or application unavailability.
	 *
	 * @param ctx gRPC server context; unused by the fake.
	 * @param req Exact Status identity consumed by the enabled fake state machine.
	 * @param resp Response receiving typed current/terminal state or application `UNAVAILABLE`.
	 * @return Transport-level `grpc::Status::OK`.
	 */
	grpc::Status GetEpochTransitionStatus(grpc::ServerContext *ctx,
					      const kinetum::dataplane::v1::GetEpochTransitionStatusRequest *req,
					      kinetum::dataplane::v1::GetEpochTransitionStatusResponse *resp) override
	{
		(void)ctx;
		transition_status_calls.fetch_add(1, std::memory_order_relaxed);
		if (complete_transitions) {
			std::lock_guard<std::mutex> lock(transition_mutex);
			const bool exact = req != nullptr && req->epoch() == transition_epoch &&
					   req->mutation_sequence() == transition_sequence &&
					   req->validation_hash() == transition_validation_hash &&
					   req->idempotency_key() == transition_key;
			if (transition_phase == fake_dp_transition_phase::IDLE) {
				resp->mutable_status()->set_code(
					static_cast<int32_t>(kinetum::common::status_code::NOT_FOUND));
				resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_NOT_FOUND);
				resp->set_identity_resolution(
					kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_UNKNOWN_FUTURE);
				resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
				return grpc::Status::OK;
			}
			const bool advancing_future = req != nullptr &&
						      (transition_phase == fake_dp_transition_phase::COMPLETE ||
						       transition_phase == fake_dp_transition_phase::ABORTED) &&
						      req->epoch() > transition_epoch &&
						      req->mutation_sequence() > transition_sequence;
			if (advancing_future) {
				resp->mutable_status()->set_code(
					static_cast<int32_t>(kinetum::common::status_code::NOT_FOUND));
				resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_NOT_FOUND);
				resp->set_identity_resolution(
					kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_UNKNOWN_FUTURE);
				resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
				return grpc::Status::OK;
			}
			if (!exact) {
				resp->mutable_status()->set_code(
					static_cast<int32_t>(kinetum::common::status_code::FAILED_PRECONDITION));
				resp->mutable_status()->set_error_code(
					kinetum::common::v1::ERROR_CODE_FAILED_PRECONDITION);
				resp->set_identity_resolution(
					kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_IDENTITY_CONFLICT);
				resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
				return grpc::Status::OK;
			}
			resp->mutable_status()->set_code(0);
			resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
			resp->set_transition_state(transition_phase == fake_dp_transition_phase::PREPARED ?
							   kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_PREPARED :
						   transition_phase == fake_dp_transition_phase::COMPLETE ?
							   kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE :
							   kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_ABORTED);
			resp->set_from_epoch(transition_from_epoch);
			resp->set_to_epoch(transition_epoch);
			resp->set_validation_hash(transition_validation_hash);
			resp->set_plan_content_hash(transition_plan_content_hash);
			resp->set_prepare_duration_ns(1u);
			if (transition_phase == fake_dp_transition_phase::COMPLETE) {
				resp->set_commit_duration_ns(1u);
				resp->set_retirement_duration_ns(1u);
			}
			resp->set_mutation_sequence(transition_sequence);
			resp->set_identity_resolution(
				transition_phase == fake_dp_transition_phase::PREPARED ?
					kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_ACTIVE_EXACT :
					kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_TERMINAL_EXACT);
			resp->set_failure_code(
				transition_phase == fake_dp_transition_phase::ABORTED ?
					kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT :
					kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
			if (transition_phase == fake_dp_transition_phase::ABORTED) {
				resp->set_failure_reason("fake exact pre-commit abort");
			}
			return grpc::Status::OK;
		}
		resp->mutable_status()->set_code(static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
		resp->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
		resp->set_transition_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED);
		resp->set_identity_resolution(
			kinetum::dataplane::v1::EPOCH_TRANSITION_IDENTITY_RESOLUTION_POLICY_DISABLED);
		resp->set_failure_code(kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE);
		return grpc::Status::OK;
	}

	// -------------------------------------------------------------------------
	// Neutral lifecycle/debug RPC responses for tests that do not override them.
	// -------------------------------------------------------------------------
	/**
	 * @brief Return neutral success for the permanently separate drain surface.
	 * @param resp Response receiving canonical success.
	 * @return Transport success.
	 */
	grpc::Status Drain(grpc::ServerContext *, const kinetum::dataplane::v1::DrainRequest *,
			   kinetum::dataplane::v1::DrainResponse *resp) override
	{
		resp->mutable_status()->set_code(0);
		return grpc::Status::OK;
	}
	/**
	 * @brief Return neutral success for drain-status component callers.
	 * @param resp Response receiving canonical success.
	 * @return Transport success.
	 */
	grpc::Status DrainStatus(grpc::ServerContext *, const kinetum::dataplane::v1::DrainStatusRequest *,
				 kinetum::dataplane::v1::DrainStatusResponse *resp) override
	{
		resp->mutable_status()->set_code(0);
		return grpc::Status::OK;
	}
	/**
	 * @brief Return neutral success for shutdown component callers.
	 * @param resp Response receiving canonical success.
	 * @return Transport success.
	 */
	grpc::Status Shutdown(grpc::ServerContext *, const kinetum::dataplane::v1::ShutdownRequest *,
			      kinetum::dataplane::v1::ShutdownResponse *resp) override
	{
		resp->mutable_status()->set_code(0);
		return grpc::Status::OK;
	}
	/**
	 * @brief Return neutral success for dump-state component callers.
	 * @param resp Response receiving canonical success.
	 * @return Transport success.
	 */
	grpc::Status DumpState(grpc::ServerContext *, const kinetum::dataplane::v1::DumpStateRequest *,
			       kinetum::dataplane::v1::DumpStateResponse *resp) override
	{
		resp->mutable_status()->set_code(0);
		return grpc::Status::OK;
	}
};

// ===============================================================================
// fake_dp_server - RAII in-process gRPC server with stub
// ===============================================================================

/** @brief RAII in-process server owning one fake service and client stub. */
struct fake_dp_server {
	fake_dp_service service;					       ///< Built-in service used by `start()`.
	std::unique_ptr<grpc::Server> server;				       ///< Running server owner.
	std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> stub;  ///< Connected client stub.
	int port{0};							       ///< Kernel-selected loopback port.

	/**
	 * @brief Start the server with the built-in neutral service.
	 */
	void start()
	{
		start_with_service(&service);
	}

	/**
	 * @brief Start the server with an externally owned service.
	 *
	 * @param svc Service implementation to register. It must outlive this server.
	 */
	void start_with_service(kinetum::dataplane::v1::DataplaneService::Service *svc)
	{
		grpc::ServerBuilder builder;
		builder.AddListeningPort("localhost:0", grpc::InsecureServerCredentials(), &port);
		builder.RegisterService(svc);
		server = builder.BuildAndStart();
		ASSERT_NE(server, nullptr) << "Failed to start fake DP gRPC server";

		auto channel =
			grpc::CreateChannel("localhost:" + std::to_string(port), grpc::InsecureChannelCredentials());
		stub = kinetum::dataplane::v1::DataplaneService::NewStub(channel);
	}

	/**
	 * @brief Stop the server if it is running.
	 */
	void shutdown()
	{
		if (server) {
			server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
			server.reset();
		}
	}

	/**
	 * @brief Shut down the server before releasing owned gRPC objects.
	 */
	~fake_dp_server()
	{
		shutdown();
	}

	// Non-copyable (owns server)
	fake_dp_server() = default;
	fake_dp_server(const fake_dp_server &) = delete;
	fake_dp_server &operator=(const fake_dp_server &) = delete;
};

}  // namespace kinetum::test
