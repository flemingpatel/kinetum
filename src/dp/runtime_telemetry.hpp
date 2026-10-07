// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_telemetry.hpp
 * @brief Provider-neutral cold packet-runtime observation contract.
 * @author Fleming Patel
 *
 * This file owns the stable observation boundary between a materialized packet
 * runtime and the dataplane gRPC service. Identities are compiled provider
 * graph identities; provider-native lcores, physical port numbers, pool scopes,
 * and backend stream indices never cross this boundary.
 *
 * @par Thread Safety
 * A source must return one coherent generation-scoped snapshot and serialize
 * native observation according to its own ownership contract. The gRPC caller
 * holds no platform lock while invoking it.
 *
 * The packet runtime publishes one generation-scoped source from immutable
 * owner-completed banks, coherent transition/health snapshots, and typed cold
 * provider observations. GetStats consumes that source all-or-none; a missing,
 * stale, contradictory, or failed selected observation returns status only.
 *
 * @par Performance
 * Cold telemetry only. Collection may allocate, but no type or method in this
 * file is reachable from packet execution.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/epoch/epoch_transition_completion.hpp"
#include "src/dp/epoch/epoch_transition_coordinator.hpp"
#include "src/dp/runtime_status.hpp"
#include "src/provider/provider_component_abi.h"

namespace kinetum::dp
{

/** @brief Requested subsets for one coherent runtime observation. */
struct runtime_telemetry_request {
	bool include_stage_stats{false};	   ///< Include per-stage rows.
	bool include_module_metrics{false};	   ///< Include module counters/histograms/mismatches.
	bool include_module_health{false};	   ///< Include context-health rows.
	bool include_worker_epoch_stats{false};	   ///< Include exact worker rows.
	bool include_region_epoch_stats{false};	   ///< Include cold region derivations.
	bool include_boundary_epoch_stats{false};  ///< Include boundary protocol rows.
	bool include_stream_stats{false};	   ///< Include I/O-stream rows.
	bool include_storage_domain_stats{false};  ///< Include storage-domain rows.
	bool include_port_stats{false};		   ///< Include logical/driver-port rows.
	bool include_topology_stats{false};	   ///< Include steering and module-context membership.
};

/** @brief One stage's current packet counters. */
struct runtime_stage_statistics {
	std::string stage_id{};	      ///< Exact logical stage identity.
	uint64_t in_packets{0};	      ///< Packets entering the stage.
	uint64_t out_packets{0};      ///< Packets forwarded by the stage.
	uint64_t dropped_packets{0};  ///< Packets retired by the stage.
	uint64_t in_bytes{0};	      ///< Bytes entering the stage.
	uint64_t out_bytes{0};	      ///< Bytes forwarded by the stage.
};

/** @brief Exact aggregate engine counters from owner-published worker banks. */
struct runtime_engine_statistics {
	uint64_t rx_packets{0};	      ///< Exact admitted physical ingress records.
	uint64_t tx_packets{0};	      ///< Exact provider-accepted TX records.
	uint64_t dropped_packets{0};  ///< Exact terminal record retirements.
	uint64_t rx_bytes{0};	      ///< Bytes on admitted physical ingress.
	uint64_t tx_bytes{0};	      ///< Bytes in provider-accepted TX prefixes.
	uint64_t fanout_overflow{0};  ///< Refused additional fan-out branches.
};

/** @brief Latest absolute registered module counter/gauge observation. */
struct runtime_module_counter_statistics {
	std::string module_id{};	    ///< Exact module-image identity.
	std::string context_instance_id{};  ///< Exact context/stage-instance identity.
	uint32_t context_index{0};	    ///< Exact compact module-context identity.
	uint32_t worker_index{0};	    ///< Sole owner worker.
	uint64_t epoch{0};		    ///< Exact publication epoch.
	std::string name{};		    ///< Registered bounded metric identity.
	uint64_t value{0};		    ///< Absolute counter or gauge value.
};

/** @brief Cold aggregate of one registered module histogram. */
struct runtime_module_histogram_statistics {
	std::string module_id{};	    ///< Exact module-image identity.
	std::string context_instance_id{};  ///< Exact context/stage-instance identity.
	uint32_t context_index{0};	    ///< Exact compact module-context identity.
	uint32_t worker_index{0};	    ///< Sole owner worker.
	uint64_t epoch{0};		    ///< Exact active aggregate epoch.
	std::string name{};		    ///< Registered bounded metric identity.
	uint64_t count{0};		    ///< Merged sample count.
	uint64_t minimum{UINT64_MAX};	    ///< Minimum sample, or UINT64_MAX when empty.
	uint64_t maximum{0};		    ///< Maximum sample.
	uint64_t sum{0};		    ///< Saturating merged sample sum.
	uint64_t p50{0};		    ///< Cold merged 50th percentile.
	uint64_t p90{0};		    ///< Cold merged 90th percentile.
	uint64_t p99{0};		    ///< Cold merged 99th percentile.
	uint64_t p999{0};		    ///< Cold merged 99.9th percentile.
};

/** @brief Latest coherent absolute module epoch-mismatch observation. */
struct runtime_module_epoch_mismatch_statistics {
	std::string module_id{};	    ///< Exact module-image identity.
	std::string context_instance_id{};  ///< Exact context/stage-instance identity.
	uint32_t context_index{0};	    ///< Exact compact module-context identity.
	uint32_t worker_index{0};	    ///< Sole owner worker.
	uint64_t observation_epoch{0};	    ///< Exact epoch of the latest completed bank.
	uint64_t mismatch_count{0};	    ///< Saturating exact-mismatch count.
	uint64_t packet_epoch{0};	    ///< First rejected packet epoch.
	uint64_t active_epoch{0};	    ///< First exact active epoch.
	uint16_t stage_instance_index{0};   ///< First exact stage instance.
	int32_t region_id{-1};		    ///< First bounded region identity.
	bool first_fault_valid{false};	    ///< Whether first-fault fields are meaningful.
	bool sticky_fault{false};	    ///< Whether any mismatch has occurred.
};

/** @brief Latest coherent context-scoped owner-worker health observation. */
struct runtime_module_health_statistics {
	std::string module_id{};	       ///< Exact module-image identity.
	std::string context_instance_id{};     ///< Exact context/stage-instance identity.
	uint32_t context_index{0};	       ///< Exact compact module-context identity.
	uint32_t worker_index{0};	       ///< Sole owner worker.
	uint16_t stage_instance_index{0};      ///< Exact executable stage instance.
	bool callback_available{false};	       ///< Whether the admitted descriptor implements health.
	bool signal_available{false};	       ///< Whether @c signal is current and valid.
	uint64_t publication_generation{0};    ///< Latest coherent owner publication generation.
	uint64_t observation_epoch{0};	       ///< Exact epoch of the latest callback attempt.
	uint64_t observed_at_ns{0};	       ///< Platform-stamped latest attempt time.
	uint64_t callback_duration_ns{0};      ///< Measured latest callback duration.
	uint64_t contract_fault_count{0};      ///< Saturating malformed/over-budget attempt count.
	uint16_t latest_fault_mask{0};	       ///< Typed faults for the latest attempt.
	uint16_t first_fault_mask{0};	       ///< Immutable first-fault bit set.
	uint64_t first_fault_epoch{0};	       ///< Exact epoch of the first contract fault.
	uint64_t first_fault_timestamp_ns{0};  ///< Platform-stamped first-fault time.
	uint64_t first_fault_duration_ns{0};   ///< Measured first-fault callback duration.
	kinetum_health_signal signal{};	       ///< Exact current signal when available; otherwise zero.
};

/** @brief One exact worker ownership and activation row. */
struct runtime_worker_epoch_statistics {
	std::string worker_id{};			///< Stable compiled worker identity.
	uint32_t worker_index{0};			///< Compact worker identity.
	int32_t region_id{-1};				///< Exact logical region.
	std::string lane_id{};				///< Stable execution-lane identity.
	worker_epoch_ledger_snapshot ledger{};		///< Coherent ownership publication.
	worker_epoch_activation_snapshot activation{};	///< Coherent activation publication.
};

/** @brief One cold exact region derivation over worker observations. */
struct runtime_region_epoch_statistics {
	int32_t region_id{-1};					    ///< Exact compact logical-region identity.
	uint32_t worker_count{0};				    ///< Frozen worker population in this region.
	uint64_t minimum_active_epoch{0};			    ///< Minimum exact worker active epoch.
	uint64_t maximum_active_epoch{0};			    ///< Maximum exact worker active epoch.
	uint64_t minimum_source_epoch{0};			    ///< Minimum exact worker source epoch.
	uint64_t maximum_source_epoch{0};			    ///< Maximum exact worker source epoch.
	uint64_t active_unretired{0};				    ///< Saturating sum of active-slot worker credits.
	uint64_t future_unretired{0};				    ///< Saturating sum of future-slot worker credits.
	uint32_t activated_participants{0};			    ///< Workers with a current activation edge.
	std::optional<uint64_t> minimum_activation_monotonic_ns{};  ///< Earliest current worker activation.
	std::optional<uint64_t> maximum_activation_monotonic_ns{};  ///< Latest current worker activation.
	uint64_t fanout_overflow{0};				    ///< Saturating sum of refused fan-out branches.
};

/** @brief One exact ordered-boundary observation row. */
struct runtime_boundary_epoch_statistics {
	std::string boundary_id{};					  ///< Stable compiled boundary identity.
	uint32_t boundary_index{0};					  ///< Exact compact boundary identity.
	uint32_t from_stage_instance_index{0};				  ///< Exact sender stage instance.
	uint32_t to_stage_instance_index{0};				  ///< Exact receiver stage instance.
	uint32_t sender_worker_index{0};				  ///< Sole sender-worker identity.
	uint32_t receiver_worker_index{0};				  ///< Sole receiver-worker identity.
	int32_t from_region_id{-1};					  ///< Exact sender logical region.
	int32_t to_region_id{-1};					  ///< Exact receiver logical region.
	uint32_t data_ring_capacity{0};					  ///< Plan-owned DATA capacity.
	uint32_t future_output_hold_capacity{0};			  ///< Plan-owned future hold capacity.
	epoch_transition_certificate_boundary_observation observation{};  ///< Four coherent endpoint publications.
};

/** @brief One owner-published software I/O stream; TX acceptance is not delivery. */
struct runtime_io_stream_statistics {
	std::string io_stream_id{};   ///< Stable compiled executable-stream identity.
	uint32_t logical_port_id{0};  ///< Exact logical port identity.
	kinetum::gluon::v1::IoStreamDirection direction{
		kinetum::gluon::v1::IO_STREAM_DIRECTION_UNSPECIFIED};  ///< Exact RX or TX direction.
	int32_t owning_region_id{-1};				       ///< Sole logical-region owner.
	uint32_t worker_index{0};				       ///< Sole compact worker owner.
	uint32_t driver_queue_id{0};				       ///< Exact driver-local queue identity.
	uint64_t published_monotonic_ns{0};  ///< Cached timestamp of this owner's last completed bank.
	uint64_t packets{0};		     ///< Records transferred across the I/O boundary.
	uint64_t bytes{0};		     ///< Bytes in those transferred records.
	uint64_t rejected_packets{0};	     ///< Inputs discarded without an I/O transfer.
};

/** @brief One compiled storage domain plus provider occupancy observation. */
struct runtime_storage_domain_statistics {
	std::string storage_domain_id{};			  ///< Stable compiled storage-domain identity.
	std::optional<int32_t> host_numa_node{};		  ///< Exact host NUMA node when proven.
	uint64_t buffer_count{0};				  ///< Compiled physical record population.
	uint64_t required_min_buffers{0};			  ///< Exact computed admission floor.
	uint32_t safety_margin{0};				  ///< Plan-authored budget safety margin.
	kinetum_provider_observation_state observation_state{0};  ///< Typed provider availability.
	std::optional<uint64_t> observed_monotonic_ns{};	  ///< Platform post-callback sample when available.
	std::optional<uint64_t> in_use{};			  ///< Exact or approximate externally owned records.
	std::optional<uint64_t> available{};  ///< Exact or approximate immediately available records.
};

/** @brief One logical port plus provider-native counters. */
struct runtime_io_port_statistics {
	uint32_t logical_port_id{0};				  ///< Exact logical port identity.
	std::string logical_name{};				  ///< Stable operator-facing logical name.
	std::string io_driver_instance_id{};			  ///< Exact compiled I/O-driver identity.
	std::string driver_port_id{};				  ///< Exact driver-local port identity.
	kinetum_provider_observation_state observation_state{0};  ///< Typed provider availability.
	std::optional<uint64_t> observed_monotonic_ns{};	  ///< Platform post-callback sample when available.
	std::optional<uint64_t> rx_packets{};			  ///< Native cumulative receive packets.
	std::optional<uint64_t> tx_packets{};			  ///< Native cumulative transmit packets.
	std::optional<uint64_t> rx_bytes{};			  ///< Native cumulative receive bytes.
	std::optional<uint64_t> tx_bytes{};			  ///< Native cumulative transmit bytes.
	std::optional<uint64_t> rx_missed{};			  ///< Native cumulative receive misses.
	std::optional<uint64_t> rx_errors{};			  ///< Native cumulative receive errors.
	std::optional<uint64_t> tx_errors{};			  ///< Native cumulative transmit errors.
	std::optional<uint64_t> rx_no_buffer{};			  ///< Native cumulative receive-buffer exhaustion.
};

/** @brief One admitted materialized steering profile. */
struct runtime_traffic_steering_statistics {
	std::string steering_profile_id{};  ///< Stable compiled steering-profile identity.
	kinetum::gluon::v1::TrafficSteeringKind kind{
		kinetum::gluon::v1::TRAFFIC_STEERING_KIND_UNSPECIFIED};	 ///< Exact admitted mechanism.
	bool symmetric{false};						 ///< Hardware symmetry for an unchanged tuple.
	std::vector<std::string> io_stream_ids{};			 ///< Exact governed stream identities.
};

/** @brief One module's immutable generation-fixed context population. */
struct runtime_module_context_domain {
	std::string module_id{};			  ///< Exact module configuration identity.
	std::vector<std::string> context_instance_ids{};  ///< Canonical order defining context ordinals.
};

/** @brief One coherent generation-scoped runtime observation. */
struct runtime_telemetry_snapshot {
	runtime_engine_statistics engine{};				///< Complete aggregate engine counters.
	runtime_status_snapshot runtime_status{};			///< Coherent generation and epoch state.
	epoch_transition_progress_snapshot transition_progress{};	///< Coherent coordinator progress.
	epoch_transition_telemetry_snapshot transition_transactions{};	///< Active/latest transaction truth.
	std::string plan_content_hash{};				///< Exact lowercase compiled plan-content hash.
	std::optional<epoch_transition_completion_progress_snapshot> completion_progress{};  ///< Certificate/grace truth.
	std::array<uint64_t, EPOCH_PROTOCOL_FAULT_COUNT> protocol_fault_counts{};  ///< Cumulative typed faults.
	std::optional<epoch_protocol_first_fault> first_protocol_fault{};	   ///< Immutable first fault.
	bool transition_success_blocked{false};					   ///< Sticky protocol safety latch.
	uint64_t collection_monotonic_ns{0};					   ///< Cold collection sample.
	uint64_t latest_bank_publication_monotonic_ns{0};			   ///< Latest completed bank sample.
	uint64_t skipped_publications{0};					   ///< Visible owner cadence refusals.
	std::vector<runtime_stage_statistics> stages{};				   ///< Requested stage rows.
	std::vector<runtime_module_counter_statistics> module_counters{};      ///< Registered absolute module values.
	std::vector<runtime_module_histogram_statistics> module_histograms{};  ///< Registered distributions.
	std::vector<runtime_module_epoch_mismatch_statistics> module_epoch_mismatches{};  ///< Exact mismatch rows.
	std::vector<runtime_module_health_statistics> module_health{};	       ///< Context-scoped coherent health rows.
	std::vector<runtime_worker_epoch_statistics> workers{};		       ///< Requested worker rows.
	std::vector<runtime_region_epoch_statistics> regions{};		       ///< Requested region rows.
	std::vector<runtime_boundary_epoch_statistics> boundaries{};	       ///< Requested boundary rows.
	std::vector<runtime_io_stream_statistics> streams{};		       ///< Requested stream rows.
	std::vector<runtime_storage_domain_statistics> storage_domains{};      ///< Requested storage rows.
	std::vector<runtime_io_port_statistics> ports{};		       ///< Requested port rows.
	std::vector<runtime_traffic_steering_statistics> steering_profiles{};  ///< Requested steering rows.
	std::vector<runtime_module_context_domain> module_context_domains{};   ///< Requested context populations.
};

/**
 * @brief Retain the strongest failure from independent cold observations.
 * @param[in,out] current Collection verdict; initially OK.
 * @param candidate One complete producer or validation result.
 *
 * DATA_LOSS dominates every unavailable input. Other terminal errors also
 * dominate UNAVAILABLE. Equal-priority failures retain the first diagnostic;
 * the success/failure disposition is independent of observation order.
 */
inline void merge_runtime_telemetry_failure(kinetum::common::status &current,
					    kinetum::common::status candidate) noexcept
{
	using kinetum::common::status_code;
	if (candidate.is_ok()) {
		return;
	}
	if (current.is_ok() ||
	    (candidate.code() == status_code::DATA_LOSS && current.code() != status_code::DATA_LOSS) ||
	    (current.code() == status_code::UNAVAILABLE && candidate.code() != status_code::UNAVAILABLE)) {
		current = std::move(candidate);
	}
}

/**
 * @brief Cold observation authority for one materialized runtime generation.
 */
class runtime_telemetry_source {
    public:
	/** @brief Destroy the source only after its runtime generation quiesces. */
	virtual ~runtime_telemetry_source() = default;

	/**
	 * @brief Collect one coherent requested snapshot.
	 *
	 * @param request Exact requested row subsets.
	 * @return Snapshot or a provider-neutral observation failure.
	 */
	[[nodiscard]] virtual kinetum::common::status_or<runtime_telemetry_snapshot>
	collect(const runtime_telemetry_request &request) const = 0;
};

}  // namespace kinetum::dp
