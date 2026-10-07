// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file compiled_provider_topology.hpp
 * @brief Sole semantic compiler output for the plan-owned provider graph.
 * @author Fleming Patel
 *
 * The compiler composes the existing transition-topology authority with exact
 * provider, facility, port, queue, storage, execution, transition, host-proof,
 * and packet-credit facts. Its output is immutable cold-path state: compact
 * indices, canonical payload bytes, compact access masks, and deterministic
 * worker schedules. Runtime materialization consumes this artifact without
 * reparsing protobufs or reconstructing graph closure.
 *
 * @par Thread Safety
 * Compilation is stateless and safe for concurrent calls. A returned artifact
 * owns all storage and is immutable after publication by its caller.
 *
 * @par Performance
 * Compilation performs allocation, sorting, and a finite monotone data-flow
 * analysis. It is forbidden from packet-worker call graphs. The emitted
 * schedules and indices exist to remove provider lookup from the hot path.
 */

#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/packet_route_condition.hpp"
#include "src/common/plan_buffer_budget.hpp"
#include "src/common/status_or.hpp"
#include "src/common/transition_topology.hpp"
#include "src/provider/provider_contract_catalog.hpp"

namespace kinetum::provider
{

/** @brief Sentinel for an absent compact provider-topology index. */
inline constexpr uint32_t INVALID_COMPILED_PROVIDER_INDEX = std::numeric_limits<uint32_t>::max();

/** @brief Sentinel for an absent lane-local stage-instance index. */
inline constexpr uint16_t INVALID_COMPILED_STAGE_INSTANCE_INDEX = std::numeric_limits<uint16_t>::max();

/** @brief Provider-neutral executable I/O direction. */
enum class compiled_io_stream_direction : uint8_t {
	RX = 1,	 ///< Receive queue transfers packets into a storage domain.
	TX = 2,	 ///< Transmit queue consumes packets from its declared storage domains.
};

/** @brief Provider-neutral logical-port direction contract. */
enum class compiled_io_port_direction : uint8_t {
	RX_ONLY = 1,	    ///< Port admits receive streams only.
	TX_ONLY = 2,	    ///< Port admits transmit streams only.
	BIDIRECTIONAL = 3,  ///< Port admits both directions.
};

/** @brief Provider-neutral steering mechanism admitted for one stream set. */
enum class compiled_steering_kind : uint8_t {
	NONE = 1,  ///< One explicit unsteered queue.
	RSS = 2,   ///< Exact multi-queue receive-side scaling profile.
};

/** @brief Canonical current native attachment kind after typed-config compilation. */
enum class compiled_driver_attachment_kind : uint8_t {
	PCI = 1,       ///< Exact lowercase PCI BDF.
	TAP = 2,       ///< Exact Linux TAP interface name.
	UDP_IPV4 = 3,  ///< Exact canonical numeric IPv4 endpoint.
};

/** @brief Provider-neutral CPU ownership role supplied to a process facility. */
enum class compiled_facility_cpu_owner_kind : uint8_t {
	PACKET_WORKER = 1,	     ///< Packet worker owns the CPU.
	TRANSITION_COORDINATOR = 2,  ///< Epoch-transition coordinator owns the CPU.
	LIFECYCLE_EXECUTOR = 3,	     ///< Configuration-lifecycle executor owns the CPU.
};

/** @brief Exact currently executable platform stage mechanism. */
enum class compiled_stage_kind : uint8_t {
	RX = 1,		 ///< Provider ingress boundary.
	TX = 2,		 ///< Provider egress boundary.
	PARSE_IPV4 = 3,	 ///< Ethernet/IPv4/L4 parser mechanism.
	MODULE = 4,	 ///< Exact public module-SDK execution.
};

/** @brief Exact owner-worker scheduling mode for one logical stage. */
enum class compiled_stage_execution_mode : uint8_t {
	PASSIVE = 1,  ///< Packet-driven execution.
	ACTIVE = 2,   ///< Owner-worker scheduled execution.
};

/** @brief Validated active-stage trigger bits independent of protobuf enums. */
enum class compiled_active_stage_trigger : uint32_t {
	LOOP = 1u,	  ///< Run on every owner-worker loop iteration.
	TIMER = 2u,	  ///< Run when one or more owner-local timers expire.
	PULL_READY = 4u,  ///< Run when a downstream pull consumer requests work.
	CONTROL = 8u,	  ///< Run when an owner-local control message arrives.
};

/** @brief Precompiled packet disposition algorithm for one stage instance. */
enum class compiled_stage_dispatch_mode : uint8_t {
	TERMINAL = 1,		   ///< No packet successor exists.
	UNCONDITIONAL_FANOUT = 2,  ///< Clone/dispatch to every authored successor in order.
	PRIORITY_ROUTE = 3,	   ///< Select the first matching priority-ordered route.
};

/** @brief Exact work-driving direction for one packet edge. */
enum class compiled_packet_edge_mode : uint8_t {
	PUSH = 1,  ///< Source packet execution drives the destination.
	PULL = 2,  ///< Destination requests work from the active source.
};

/** @brief Exact current control-path edge semantic. */
enum class compiled_control_edge_subtype : uint8_t {
	GENERIC = 1,   ///< General control message.
	FEEDBACK = 2,  ///< Latency-sensitive feedback message.
};

/** @brief One authored logical route and its exact concrete destination alternatives. */
struct compiled_stage_route {
	std::vector<uint16_t>
		destination_stage_instance_indices;  ///< Nonempty permitted set; exactly one receives a branch.
	common::compiled_packet_route_condition condition{};		  ///< Allocation-free predicate.
	int32_t priority{0};						  ///< Higher values are evaluated first.
	uint32_t authored_edge_index{0};				  ///< Stable tie-break and provenance.
	compiled_packet_edge_mode mode{compiled_packet_edge_mode::PUSH};  ///< Work-driving direction.
};

/** @brief Exact context-selection policy for an admitted module stage. */
enum class compiled_module_context_selection : uint8_t {
	SAME_LANE = 1,	///< The logical edge enters its already paired lane context.
	MODULE = 2,	///< The module selector chooses one declared reachable context.
};

/** @brief One logical stage's immutable execution semantics. */
struct compiled_logical_stage {
	std::string logical_stage_id;			    ///< Authored pipeline identity.
	uint16_t logical_stage_index{0};		    ///< Authored-order compact identity.
	compiled_stage_kind kind{compiled_stage_kind::RX};  ///< Exact executable mechanism.
	compiled_stage_execution_mode execution_mode{compiled_stage_execution_mode::PASSIVE};  ///< Schedule mode.
	uint32_t trigger_mask{0};				   ///< Validated active trigger bitmask.
	uint32_t retained_packet_capacity{0};			   ///< Exact per-instance retained-record capacity.
	uint64_t retained_byte_capacity{0};			   ///< Exact per-instance retained-byte capacity.
	uint32_t timer_capacity{0};				   ///< Exact per-instance owner-local timer capacity.
	uint32_t control_mailbox_capacity{0};			   ///< Exact per-instance queued-message capacity.
	uint32_t control_message_capacity_bytes{0};		   ///< Exact maximum copied control payload.
	uint32_t async_work_capacity{0};			   ///< Exact live foreign-work token capacity.
	std::chrono::steady_clock::duration async_cancel_grace{};  ///< Exact cancellation fail-stop bound.
	int32_t schedule_order{0};				   ///< Stable active-stage schedule key.
	std::string module_id;			 ///< Exact module image identity; empty for platform stages.
	std::optional<std::string> module_path;	 ///< Exact direct-development source identity when authored.
	/** @brief Exact authored module policy; platform stages carry no module operation. */
	compiled_module_context_selection context_selection{compiled_module_context_selection::SAME_LANE};
	std::vector<uint32_t> stage_instance_indices;  ///< Sorted concrete instances of this logical stage.
};

/** @brief One exact logical region and its executable ownership sets. */
struct compiled_execution_region {
	int32_t region_id{-1};			       ///< Compact index equal to vector position.
	int32_t numa_node{-1};			       ///< Exact owner-local NUMA node.
	std::vector<uint16_t> logical_stage_indices;   ///< Authored-order exact region membership.
	std::vector<uint32_t> stage_instance_indices;  ///< Sorted concrete stage membership.
	std::vector<uint32_t> worker_indices;	       ///< Sorted exact worker set.
};

/** @brief One exact execution lane and its two-directional membership. */
struct compiled_execution_lane {
	std::string lane_id;	 ///< Stable plan-owned lane identity.
	uint32_t lane_index{0};	 ///< Compact index equal to vector position.
	/** Exact lane-local instance indexed directly by logical_stage_index. */
	std::vector<uint16_t> stage_instance_indices;
	std::vector<uint32_t> io_stream_indices;  ///< Sorted exact stream set.
};

/** @brief One exact mutable module context required by the executable graph. */
struct compiled_module_context {
	std::string context_instance_id;	    ///< Stable module-manager context identity.
	uint32_t module_context_index{0};	    ///< Compact sorted stage-instance order.
	uint32_t stage_instance_index{0};	    ///< Exact executable stage owner.
	uint16_t logical_stage_index{0};	    ///< Exact module stage semantics.
	uint32_t worker_index{0};		    ///< Sole owner worker.
	int32_t cpu_core_id{-1};		    ///< Exact sole owner-worker CPU.
	int32_t region_id{-1};			    ///< Sole owner region.
	int32_t numa_node{-1};			    ///< Exact owner NUMA placement.
	std::string module_id;			    ///< Exact module image identity.
	uint64_t context_memory_capacity_bytes{0};  ///< Exact context-lifetime allocation bound.
	uint64_t epoch_arena_capacity_bytes{0};	    ///< Exact capacity of each epoch arena.
	uint32_t module_context_ordinal{0};	    ///< Ordinal within the exact module configuration population.
	uint32_t module_context_count{0};  ///< Positive generation-fixed population sharing that configuration.
};

/** @brief Checked aggregate lifecycle-memory authority for one NUMA node. */
struct compiled_module_memory_budget {
	int32_t numa_node{-1};			    ///< Exact host NUMA identity.
	uint32_t context_count{0};		    ///< Number of exact module contexts on this node.
	uint64_t context_memory_capacity_bytes{0};  ///< Sum of context-lifetime capacities.
	uint64_t epoch_arena_capacity_bytes{0};	    ///< Sum of one arena per context and epoch.
	/** Context memory plus every simultaneous exact epoch-slot arena. */
	uint64_t complete_memory_capacity_bytes{0};
};

/** @brief One lane-expanded, owner-local control edge. */
struct compiled_control_edge {
	uint32_t control_edge_index{0};		  ///< Compact stable index.
	uint32_t authored_control_edge_index{0};  ///< Authored control-edge provenance.
	uint32_t from_stage_instance_index{0};	  ///< Exact source context.
	uint32_t to_stage_instance_index{0};	  ///< Exact destination context.
	uint32_t worker_index{0};		  ///< Sole owner of both endpoints.
	compiled_control_edge_subtype subtype{compiled_control_edge_subtype::GENERIC};	///< Exact semantics.
};

/** @brief Role-correct canonical provider configuration bytes. */
struct compiled_provider_configuration {
	std::string type_url;		///< Complete exact provider contract identity.
	std::string canonical_payload;	///< Deterministically serialized concrete payload.
};

/** @brief One exact CPU role aggregated for a process facility. */
struct compiled_facility_cpu_assignment {
	uint32_t owner_index{0};  ///< Compact worker or runtime-service index.
	int32_t cpu_core_id{-1};  ///< Exact plan-owned logical CPU.
	int32_t numa_node{-1};	  ///< Exact plan-owned NUMA node.
	compiled_facility_cpu_owner_kind kind{compiled_facility_cpu_owner_kind::PACKET_WORKER};	 ///< Owner role.
};

/** @brief One canonical native attachment with no protobuf left to parse. */
struct compiled_driver_attachment {
	std::string driver_port_id;   ///< Exact driver-local port identity.
	uint32_t io_driver_index{0};  ///< Owning compact I/O-driver identity.
	compiled_driver_attachment_kind kind{compiled_driver_attachment_kind::PCI};  ///< Exact attachment kind.
	std::string attachment_identity;  ///< Canonical BDF, TAP name, or IPv4 text.
	uint32_t endpoint_port{0};	  ///< UDP port; zero for PCI and TAP.
};

/** @brief One storage memory requirement aggregated for a process facility. */
struct compiled_facility_memory_domain {
	uint32_t storage_domain_index{0};	///< Exact compact storage-domain identity.
	uint32_t buffer_count{0};		///< Exact admitted record population.
	uint32_t data_room_bytes{0};		///< Exact bytes reserved per payload slot.
	uint32_t headroom_bytes{0};		///< Exact bytes reserved before packet data.
	uint32_t alignment_bytes{0};		///< Exact record/payload alignment.
	uint32_t cache_size_per_worker{0};	///< Exact provider-local cache policy.
	std::optional<int32_t> host_numa_node;	///< Exact host placement when required.
};

/** @brief One exact process-facility instance. */
struct compiled_process_facility_instance {
	std::string facility_instance_id;		///< Stable plan-owned identity.
	uint32_t facility_index{0};			///< Compact sorted index.
	compiled_provider_configuration configuration;	///< Canonical facility contract.
	process_facility_projection capabilities{};	///< Exact scope and generation semantics.
	std::optional<int32_t> main_core_id;		///< Exact process coordinator CPU when required.
	std::vector<compiled_facility_cpu_assignment> cpu_assignments;	///< Exact stable CPU-role set.
	std::vector<compiled_driver_attachment> attachments;		///< Exact dependent native attachments.
	std::vector<compiled_facility_memory_domain> memory_domains;	///< Exact dependent memory domains.
};

/** @brief One exact I/O-driver instance and its declared native ports. */
struct compiled_io_driver_instance {
	std::string io_driver_instance_id;		      ///< Stable plan-owned identity.
	uint32_t io_driver_index{0};			      ///< Compact sorted index.
	std::vector<uint32_t> facility_indices;		      ///< Exact sorted facility dependencies.
	compiled_provider_configuration configuration;	      ///< Canonical I/O contract.
	io_driver_projection capabilities{};		      ///< Pure catalog transfer projection.
	std::vector<compiled_driver_attachment> attachments;  ///< Canonical configured attachment facts.
	std::vector<uint32_t> storage_domain_indices;	      ///< Sorted storage dependencies used by streams.
};

/** @brief One exact packet-storage domain and its compiled credit floor. */
struct compiled_packet_storage_domain {
	std::string storage_domain_id;			       ///< Stable plan-owned identity.
	uint32_t storage_domain_index{0};		       ///< Compact sorted index.
	std::vector<uint32_t> facility_indices;		       ///< Exact sorted facility dependencies.
	compiled_provider_configuration configuration;	       ///< Canonical storage contract.
	packet_storage_projection capabilities{};	       ///< Pure catalog access projection.
	uint32_t buffer_count{0};			       ///< Exact authored record population.
	uint32_t data_room_bytes{0};			       ///< Exact packet data-room bytes.
	uint32_t headroom_bytes{0};			       ///< Exact packet headroom bytes.
	uint32_t alignment_bytes{0};			       ///< Exact record/payload alignment.
	std::optional<int32_t> host_numa_node;		       ///< Exact host placement when required.
	uint32_t cache_size_per_worker{0};		       ///< Canonical provider-local cache policy.
	uint16_t maximum_packet_length{0};		       ///< Exact representable contiguous packet bound.
	common::compiled_storage_domain_buffer_budget budget;  ///< Shared checked credit result.
};

/** @brief One exact stage-execution provider instance. */
struct compiled_execution_provider_instance {
	std::string execution_provider_instance_id;	///< Stable plan-owned identity.
	uint32_t execution_provider_index{0};		///< Compact sorted index.
	std::vector<uint32_t> facility_indices;		///< Exact sorted facility dependencies.
	compiled_provider_configuration configuration;	///< Canonical execution contract.
	execution_projection capabilities{};		///< Required storage-access agents.
	std::vector<uint32_t> stage_instance_indices;	///< Sorted stages owned by this executor.
	std::vector<uint32_t> worker_indices;		///< Sorted workers hosting those stages.
	std::vector<uint32_t> storage_domain_indices;	///< Sorted reachable storage dependencies.
};

/** @brief One exact logical-to-driver-local port binding. */
struct compiled_io_port {
	uint32_t port_index{0};		///< Compact logical-name order.
	uint32_t logical_port_id{0};	///< Module-visible bounded identity.
	std::string logical_name;	///< Stable logical name.
	uint32_t io_driver_index{0};	///< Owning driver instance.
	uint32_t driver_port_index{0};	///< Compact index within that driver.
	compiled_io_port_direction direction{compiled_io_port_direction::RX_ONLY};  ///< Admitted directions.
	std::optional<int32_t> host_numa_node;		///< Exact resolved host placement when known.
	uint32_t mtu{0};				///< Exact nonzero MTU.
	std::array<uint8_t, 6> resolved_mac_address{};	///< Canonical hardware address bytes.
	bool has_resolved_mac_address{false};		///< Whether the six-byte value is present.
};

/** @brief One exact executable stage instance. */
struct compiled_provider_stage_instance {
	std::string stage_instance_id;				     ///< Stable executable identity.
	uint32_t stage_instance_index{0};			     ///< Compact sorted index.
	std::string logical_stage_id;				     ///< Authored pipeline-stage identity.
	uint16_t logical_stage_index{0};			     ///< Exact logical semantics index.
	uint32_t lane_index{0};					     ///< Exact compact execution-lane identity.
	uint32_t region_index{0};				     ///< Exact compact logical region.
	uint32_t replica_index{0};				     ///< Exact lane-local replica identity.
	uint32_t worker_index{0};				     ///< Exact compact owner worker.
	uint32_t execution_provider_index{0};			     ///< Exact execution implementation instance.
	std::optional<uint32_t> module_context_index;		     ///< Exact mutable context for module stages.
	std::optional<uint32_t> io_stream_index;		     ///< Exact RX/TX stream; absent for non-I/O stages.
	std::optional<uint32_t> active_origin_storage_domain_index;  ///< Exact active-origin owner domain.
	std::vector<uint32_t> reachable_storage_domain_indices;	     ///< Finite fixed-point domain set.
	compiled_stage_dispatch_mode dispatch_mode{compiled_stage_dispatch_mode::TERMINAL};  ///< Routing algorithm.
	std::vector<compiled_stage_route> packet_routes;	   ///< Authored fan-out order or total priority order.
	std::vector<uint16_t> pull_source_stage_instance_indices;  ///< Active sources this stage may pull.
};

/** @brief One exact executable driver queue stream. */
struct compiled_provider_io_stream {
	std::string io_stream_id;     ///< Stable executable stream identity.
	uint32_t io_stream_index{0};  ///< Compact sorted index.
	uint32_t port_index{0};	      ///< Exact logical/driver port binding.
	uint32_t lane_index{0};	      ///< Exact compact execution-lane identity.
	compiled_io_stream_direction direction{compiled_io_stream_direction::RX};  ///< Queue direction.
	uint32_t stage_instance_index{0};					   ///< Attached executable stage.
	uint32_t worker_index{0};						   ///< Sole queue owner worker.
	uint32_t rx_storage_domain_index{
		INVALID_COMPILED_PROVIDER_INDEX};	  ///< Exact RX allocation domain; absent for TX.
	std::vector<uint32_t> tx_storage_domain_indices;  ///< Sorted exact TX admission set; empty for RX.
	uint32_t driver_queue_id{0};			  ///< Driver-local queue identity.
	uint32_t descriptor_count{0};			  ///< Exact queue descriptor population.
	std::optional<uint32_t> steering_profile_index;	  ///< Exact steering profile when present.

	/**
	 * @brief Borrow this queue's exact RX allocation or TX admission domain indices.
	 * @return View valid while this compiled row remains unchanged and unmoved.
	 */
	[[nodiscard]] std::span<const uint32_t> storage_domain_indices() const noexcept
	{
		return direction == compiled_io_stream_direction::RX ?
			       std::span<const uint32_t>{&rx_storage_domain_index, 1u} :
			       std::span<const uint32_t>{tx_storage_domain_indices};
	}
};

/** @brief One exact normalized steering profile. */
struct compiled_traffic_steering_profile {
	std::string steering_profile_id;			    ///< Stable plan-owned identity.
	uint32_t steering_profile_index{0};			    ///< Compact sorted index.
	compiled_steering_kind kind{compiled_steering_kind::NONE};  ///< Exact mechanism.
	bool symmetric{false};					    ///< Hardware symmetry for an unchanged tuple.
	std::vector<std::string> hash_fields;			    ///< Order-contractual exact field set.
	std::string hash_key;					    ///< Exact deterministic key bytes.
	std::vector<uint32_t> io_stream_indices;		    ///< Exact sorted governed stream set.
};

/** @brief Complete generation-fixed population sharing one module configuration. */
struct compiled_module_context_domain {
	std::string module_id;			       ///< Exact configured module identity.
	std::vector<uint32_t> module_context_indices;  ///< Context indices ordered by module-scoped ordinal.
};

/** @brief Typed endpoint kind used by one compiled storage transition. */
enum class compiled_packet_path_endpoint_kind : uint8_t {
	IO_STREAM = 1,	     ///< Endpoint index addresses compiled I/O streams.
	STAGE_INSTANCE = 2,  ///< Endpoint index addresses compiled stage instances.
};

/** @brief One compact typed packet-path endpoint. */
struct compiled_packet_path_endpoint {
	compiled_packet_path_endpoint_kind kind{compiled_packet_path_endpoint_kind::IO_STREAM};	 ///< Namespace.
	uint32_t endpoint_index{0};  ///< Compact role-relative index.
};

/** @brief One exact storage/access transition on a directed packet edge. */
struct compiled_storage_transition {
	std::string transition_id;			///< Stable plan-owned identity.
	uint32_t transition_index{0};			///< Compact sorted index.
	compiled_packet_path_endpoint from_endpoint;	///< Exact directed source endpoint.
	compiled_packet_path_endpoint to_endpoint;	///< Exact directed destination endpoint.
	uint32_t from_storage_domain_index{0};		///< Required reachable source domain.
	uint32_t to_storage_domain_index{0};		///< Destination domain after success.
	std::vector<uint32_t> facility_indices;		///< Exact sorted facility dependencies.
	compiled_provider_configuration configuration;	///< Canonical transition contract.
	storage_transition_projection capabilities{};	///< Exact ownership/copy semantics.
	uint32_t staging_capacity{0};			///< Bounded destination credits for copy.
	std::optional<int32_t> staging_numa_node;	///< Exact host staging placement when required.
};

/** @brief One external fact assigned to exactly one proof phase. */
struct compiled_provider_host_requirement {
	provider_host_proof_phase phase{provider_host_proof_phase::QUARK_LIVE_HOST};  ///< Sole proof phase.
	provider_host_fact fact{provider_host_fact::CPU_WORKER_SET};		      ///< Exact required fact.
	provider_contract_role role{provider_contract_role::EXECUTION};		      ///< Owning role.
	uint32_t instance_index{0};  ///< Compact index in the owning role vector.
};

/** @brief Pre-resolved structural work owned by one compact worker. */
struct compiled_provider_worker_schedule {
	uint32_t worker_index{0};			      ///< Compact transition worker identity.
	std::vector<uint32_t> rx_stream_indices;	      ///< Sorted sole-owner receive streams.
	std::vector<uint32_t> tx_stream_indices;	      ///< Sorted sole-owner transmit streams.
	std::vector<uint32_t> stage_instance_indices;	      ///< Sorted executable stages.
	std::vector<uint32_t> storage_transition_indices;     ///< Sorted transitions executed by this worker.
	std::vector<uint32_t> storage_domain_indices;	      ///< Sorted stream/stage/transition domain dependencies.
	std::vector<uint32_t> source_storage_domain_indices;  ///< Sorted exact RX/active-origin domains.
	std::vector<uint32_t> active_stage_instance_indices;  ///< Stable complete active schedule.
	std::vector<uint32_t> async_stage_instance_indices;   ///< Stable tracked-async active subset.
	std::vector<uint32_t> loop_trigger_stage_instance_indices;     ///< LOOP-triggered active stages.
	std::vector<uint32_t> timer_trigger_stage_instance_indices;    ///< TIMER-triggered active stages.
	std::vector<uint32_t> pull_trigger_stage_instance_indices;     ///< PULL_READY active stages.
	std::vector<uint32_t> control_trigger_stage_instance_indices;  ///< CONTROL active stages.
	std::vector<uint32_t> inbound_control_edge_indices;	       ///< Owner-local control consumers.
	/**
	 * Exact TX stream indexed by logical_port_id.
	 *
	 * An absent worker-local egress is represented only by
	 * INVALID_COMPILED_PROVIDER_INDEX. Materialization replaces each present
	 * stream index with that stream's pre-resolved TX operation and never
	 * reconstructs ownership from plan records.
	 */
	std::vector<uint32_t> tx_stream_index_by_logical_port;
};

/**
 * @brief Complete immutable result of provider-topology compilation.
 *
 * Provider-instance, port, stage-instance, stream, steering, module-domain, and
 * transition vectors use stable lexicographic identity order. Logical stages
 * preserve authored pipeline order. Regions, lanes, workers, and their
 * schedules are indexed by their validated compact identities. Control edges
 * preserve deterministic authored-edge/lane expansion order. All
 * cross-references are compact indices into these vectors.
 */
struct compiled_provider_topology {
	/**
	 * Canonical source-plan identity when the compilation input was finalized.
	 *
	 * Gluon compiles once before it publishes the plan's self identity, so its
	 * isolated self-check legitimately leaves this field empty. Every runtime
	 * consumer compiles an already finalized plan and requires exact equality
	 * before materialization; the artifact can therefore never be paired with a
	 * different canonical plan by accident.
	 */
	std::string source_plan_content_hash;
	common::compiled_transition_topology transition_topology;	     ///< Composed ordered-transition structure.
	std::vector<compiled_logical_stage> logical_stages;		     ///< Authored-order exact stage semantics.
	std::vector<compiled_execution_region> execution_regions;	     ///< Indexed logical regions.
	std::vector<compiled_execution_lane> execution_lanes;		     ///< Indexed execution lanes.
	std::vector<compiled_process_facility_instance> process_facilities;  ///< Sorted facilities.
	std::vector<compiled_io_driver_instance> io_drivers;		     ///< Sorted I/O instances.
	std::vector<compiled_packet_storage_domain> storage_domains;	     ///< Sorted storage domains.
	std::vector<compiled_execution_provider_instance> execution_providers;	///< Sorted executors.
	std::vector<compiled_io_port> ports;					///< Sorted logical ports.
	std::vector<compiled_provider_stage_instance> stage_instances;		///< Sorted executable stages.
	std::vector<compiled_module_context> module_contexts;			///< Sorted exact module contexts.
	std::vector<compiled_module_memory_budget> module_memory_budgets;	///< Sorted exact NUMA budgets.
	std::vector<compiled_control_edge> control_edges;			///< Stable lane-expanded control edges.
	std::vector<compiled_provider_io_stream> io_streams;			///< Sorted executable streams.
	std::vector<compiled_traffic_steering_profile> steering_profiles;	///< Sorted steering profiles.
	std::vector<compiled_module_context_domain> module_context_domains;	///< Sorted exact context populations.
	std::vector<compiled_storage_transition> storage_transitions;		///< Sorted transitions.
	std::vector<compiled_provider_worker_schedule> worker_schedules;	///< Indexed worker schedules.
	std::vector<compiled_provider_host_requirement> host_requirements;	///< Stable phase/fact order.
	std::vector<std::string> required_contract_type_urls;			///< Sorted unique exact set.
};

/**
 * @brief Compile and validate one complete canonical provider graph.
 *
 * The operation first validates and compiles logical pipeline semantics, then
 * composes `compile_transition_topology` and validates every role-correct
 * configuration, exact dependency set, port/queue owner, storage/execution
 * access relation, transition-set equality, finite reachable-domain fixed
 * point, steering contract, credit budget, and host-proof phase. It mutates no
 * caller state and performs no provider or host side effect.
 *
 * Reachability uses a deterministic monotone worklist over the finite product
 * of packet endpoints and declared storage domains. Each pair is inserted at
 * most once, giving O(D * (V + E)) work and O(D * V) bits of state without
 * enumerating paths; cycles terminate at the finite fixed point.
 *
 * @param plan Canonical complete deployment plan.
 * @return Sole compact semantic artifact; a fail-closed validation status;
 *         RESOURCE_EXHAUSTED for host allocation failure; or OUT_OF_RANGE for
 *         an unrepresentable container extent. No caller-owned output, host
 *         probe, component load, or native resource precedes success.
 */
[[nodiscard]] common::status_or<compiled_provider_topology>
compile_provider_topology(const kinetum::gluon::v1::DeploymentPlan &plan);

}  // namespace kinetum::provider
