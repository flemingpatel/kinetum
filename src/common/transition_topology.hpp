// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file transition_topology.hpp
 * @brief Shared compiler for exact epoch-transition deployment topology.
 * @author Fleming Patel
 *
 * Gluon, Quark, and the dataplane consume one compiled representation of
 * workers, boundaries, runtime services, sources, sinks, and bounded policy.
 * This prevents planner, host-admission, and runtime-admission
 * validators from evolving independent interpretations of the same plan.
 *
 * The compiler performs allocation-using cold-path work over protobuf input.
 * Returned indices are compact and deterministic and may be copied into
 * preallocated runtime structures before workers launch. No type in this file
 * owns packet queues, module artifacts, threads, or provider resources.
 *
 * @par Thread Safety
 * Compilation is stateless and thread-safe. Returned objects own their strings
 * and vectors and are immutable after publication by their caller.
 *
 * @par Performance
 * This component must not run on a packet worker. Its output exists to remove
 * string lookup and topology discovery from later worker paths.
 */

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/** @brief Least representable live-transition terminal-history capacity. */
inline constexpr uint32_t MIN_TRANSITION_RESULT_HISTORY_CAPACITY = 1u;

/** @brief Greatest representable live-transition terminal-history capacity. */
inline constexpr uint32_t MAX_TRANSITION_RESULT_HISTORY_CAPACITY = 64u;

/** @brief Least representable coordinator command-mailbox capacity. */
inline constexpr uint32_t MIN_COORDINATOR_COMMAND_MAILBOX_CAPACITY = 2u;

/** @brief Greatest representable coordinator command-mailbox capacity. */
inline constexpr uint32_t MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY = 64u;

/**
 * @brief Provider-neutral runtime-service role admitted by transition topology.
 */
enum class compiled_runtime_service_role : uint8_t {
	EPOCH_TRANSITION_COORDINATOR = 0,  ///< Sole writer of the global generation.
	CONFIG_LIFECYCLE_EXECUTOR,	   ///< NUMA-local cold lifecycle executor.
};

/**
 * @brief One compact execution participant compiled from WorkerPlacement.
 */
struct compiled_transition_worker {
	std::string worker_id;			    ///< Stable plan-owned worker identity.
	uint32_t worker_index{0};		    ///< Compact index equal to vector position.
	uint32_t worker_placement_index{0};	    ///< Plan-order WorkerPlacement index.
	int32_t region_id{-1};			    ///< Owning logical region.
	std::string lane_id;			    ///< Owning execution lane.
	uint32_t lane_index{0};			    ///< Compact plan-owned lane index.
	int32_t numa_node{-1};			    ///< Region-local NUMA ownership.
	std::vector<int32_t> cpu_core_ids;	    ///< Dedicated plan-owned CPU set.
	bool is_source{false};			    ///< Owns an RX or active packet-originating stage.
	bool is_sink{false};			    ///< Owns at least one TX stage instance.
	bool owns_module_context{false};	    ///< Owns at least one module stage instance.
	uint32_t source_epoch_staging_capacity{0};  ///< Per-queue source active/future staging capacity.
	std::chrono::steady_clock::duration health_poll_interval{};    ///< Owner observation/health cadence.
	std::chrono::steady_clock::duration health_callback_budget{};  ///< Exact owner-health callback bound.
	std::vector<uint32_t> stage_instance_indices;		       ///< Exact executable instances owned here.
	std::vector<uint32_t> io_stream_indices;		       ///< Exact executable streams owned here.
	std::vector<uint32_t> inbound_boundary_indices;		       ///< Exact inbound boundaries.
	std::vector<uint32_t> outbound_boundary_indices;	       ///< Exact outbound boundaries.
};

/**
 * @brief One exact directed cross-worker boundary descriptor.
 */
struct compiled_transition_boundary {
	std::string boundary_id;		  ///< Stable deterministic boundary identity.
	uint32_t boundary_index{0};		  ///< Compact index equal to vector position.
	uint32_t from_stage_instance_index{0};	  ///< Exact executable source endpoint.
	uint32_t to_stage_instance_index{0};	  ///< Exact executable destination endpoint.
	uint32_t sender_worker_index{0};	  ///< Sole DATA/CUT producer.
	uint32_t receiver_worker_index{0};	  ///< Sole DATA/CUT consumer and ACK producer.
	uint32_t data_ring_capacity{0};		  ///< Plan-owned DATA-ring capacity.
	uint32_t future_output_hold_capacity{0};  ///< Sender-owned future-output capacity.
	int32_t data_ring_numa_node{-1};	  ///< Receiver-local DATA storage node.
};

/**
 * @brief Exact boundary lookup entry for one executable source instance.
 */
struct compiled_transition_edge {
	uint32_t to_stage_instance_index{0};  ///< Exact executable destination.
	uint32_t boundary_index{0};	      ///< Owning boundary descriptor.
};

/**
 * @brief One validated coordinator or lifecycle-executor placement.
 */
struct compiled_runtime_service {
	std::string service_id;	    ///< Stable canonical service identity.
	uint32_t service_index{0};  ///< Plan-order index.
	/** Role determining which cold runtime operation may execute on this service CPU. */
	compiled_runtime_service_role role{compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR};
	int32_t cpu_core_id{-1};	       ///< Dedicated service CPU.
	int32_t numa_node{-1};		       ///< Service-local NUMA ownership.
	uint32_t command_mailbox_capacity{0};  ///< Coordinator command slots; zero for executors.
};

/**
 * @brief Exact cold-lifecycle service placement independent of transition policy.
 *
 * Every executable worker topology requires this complete artifact, including
 * fixed-epoch bootstrap. It proves coordinator cardinality and exact
 * lifecycle-executor NUMA coverage. Coverage contains every module-context
 * NUMA node, or the canonical lowest populated region node for a module-free
 * plan. A plan cannot publish a partial or unused service surface.
 */
struct compiled_lifecycle_service_topology {
	/** @brief Exact index of the sole epoch-transition coordinator placement. */
	uint32_t coordinator_service_index{0};

	/**
	 * @brief Lifecycle-executor indices in ascending required NUMA-node order.
	 *
	 * The vector contains the exact required executor set: every module-context
	 * NUMA node, or the canonical lowest populated region node for a module-free
	 * plan. The compiler validates already-authored service records; it does not
	 * synthesize an identity, CPU, NUMA placement, or missing owner.
	 */
	std::vector<uint32_t> lifecycle_executor_service_indices;
};

/**
 * @brief Bounded policy for one dataplane-wide transition generation.
 */
struct compiled_epoch_transition_policy {
	bool enabled{false};					///< False only when epoch_transition_plan is absent.
	std::chrono::steady_clock::duration prepare_timeout{};	///< Abortable prepare deadline.
	std::chrono::steady_clock::duration prepare_cancel_grace{};    ///< Cooperative cancellation grace.
	std::chrono::steady_clock::duration prepared_lease_timeout{};  ///< Pre-commit lease.
	std::chrono::steady_clock::duration commit_timeout{};	       ///< Completion-only commit deadline.
	std::chrono::steady_clock::duration retirement_timeout{};      ///< Update-freeze deadline.
	uint32_t result_history_capacity{0};			       ///< Bounded terminal-result journal capacity.
};

/**
 * @brief Complete shared result of transition-topology compilation.
 */
struct compiled_transition_topology {
	std::vector<compiled_transition_worker> workers;       ///< Indexed by compact worker index.
	std::vector<compiled_transition_boundary> boundaries;  ///< Canonical endpoint order.
	/** Outgoing transition edges indexed by exact source stage-instance ordinal. */
	std::vector<std::vector<compiled_transition_edge>> boundaries_by_source_stage_instance;
	std::vector<compiled_runtime_service> runtime_services;	 ///< Canonical plan order.
	std::vector<uint32_t> source_worker_indices;		 ///< Workers that originate packet epochs.
	std::vector<uint32_t> sink_worker_indices;		 ///< Workers that own terminal TX instances.
	std::vector<int32_t> module_context_numa_nodes;		 ///< Sorted exact lifecycle coverage set.
	/** @brief Exact lifecycle-service placement for every nonempty worker topology. */
	std::optional<compiled_lifecycle_service_topology> lifecycle_services;
	compiled_epoch_transition_policy policy;  ///< Fixed-epoch or live-transition policy.
};

/**
 * @brief Compile and validate one exact transition-topology plan.
 *
 * Validation is two-directional: every executable cross-worker edge requires
 * exactly one boundary and every boundary must implement one such edge. Source
 * participants derive from explicit RX or active-origin stage instances;
 * sinks derive from explicit TX stage instances. Neither derives from worker-
 * graph degree. Every nonempty worker topology requires exact lifecycle-
 * service placement, including fixed-epoch bootstrap; an empty worker topology
 * cannot carry unused service placements. Fixed-epoch plans keep source-epoch
 * staging disabled but still require the policy-independent observation cadence
 * and exact owner-health callback bound.
 *
 * @param plan Complete deployment plan to compile.
 * @return Compact deterministic topology, or a fail-closed status before any
 *         caller-owned output or provider resource is changed.
 */
[[nodiscard]] status_or<compiled_transition_topology>
compile_transition_topology(const kinetum::gluon::v1::DeploymentPlan &plan);

}  // namespace kinetum::common
