// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file compiled_provider_topology.cpp
 * @brief Shared provider-topology compiler implementation.
 * @author Fleming Patel
 */

#include "src/provider/compiled_provider_topology.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "gen/kinetum/io/dpdk/v1/dpdk_driver.pb.h"
#include "gen/kinetum/io/udp/v1/udp_driver.pb.h"
#include "gen/kinetum/storage/dpdk/v1/dpdk_storage.pb.h"
#include "src/axiom/axiom_contract.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"
#include "src/provider/provider_component_abi.h"
#include "src/sdk/module_abi_text.hpp"

namespace kinetum::provider
{

namespace
{

using common::status;
using common::status_code;
using common::status_or;

/** Authored active-stage triggers accepted by the compiler. */
constexpr uint32_t ALL_ACTIVE_TRIGGER_BITS = static_cast<uint32_t>(compiled_active_stage_trigger::LOOP) |
					     static_cast<uint32_t>(compiled_active_stage_trigger::TIMER) |
					     static_cast<uint32_t>(compiled_active_stage_trigger::PULL_READY) |
					     static_cast<uint32_t>(compiled_active_stage_trigger::CONTROL);

/** Maximum stage population preserving uint16_t's invalid-identity sentinel. */
constexpr std::size_t MAX_COMPILED_STAGE_INSTANCES = static_cast<std::size_t>(std::numeric_limits<uint16_t>::max());

/** Absence sentinel for a pre-resolved storage-transition index. */
constexpr uint32_t INVALID_COMPILED_TRANSITION = std::numeric_limits<uint32_t>::max();

/**
 * @brief Convert one positive millisecond policy into exact steady-clock duration.
 * @param milliseconds Exact authored nonzero millisecond count.
 * @return Representable exact duration, or fail-closed range status.
 */
[[nodiscard]] status_or<std::chrono::steady_clock::duration> compile_async_cancel_grace(uint64_t milliseconds) noexcept
{
	using milliseconds_type = std::chrono::milliseconds;
	const auto maximum = std::chrono::duration_cast<milliseconds_type>(std::chrono::steady_clock::duration::max());
	if (milliseconds == 0u || maximum.count() <= 0 || milliseconds > static_cast<uint64_t>(maximum.count())) {
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "async_cancel_grace_ms is outside the representable monotonic duration domain"));
	}
	const milliseconds_type authored{static_cast<milliseconds_type::rep>(milliseconds)};
	const auto converted = std::chrono::duration_cast<std::chrono::steady_clock::duration>(authored);
	if (converted <= std::chrono::steady_clock::duration::zero() ||
	    std::chrono::duration_cast<milliseconds_type>(converted) != authored) {
		return status(
			status_code::OUT_OF_RANGE,
			kinetum::common::static_status_text(
				"async_cancel_grace_ms does not convert exactly into the monotonic clock domain"));
	}
	return converted;
}

/** @brief Canonical configuration plus its immutable pure-catalog row. */
struct canonicalized_contract {
	compiled_provider_configuration configuration;		///< Exact normalized payload.
	const provider_contract_descriptor *contract{nullptr};	///< Static catalog authority.
};

/** @brief One directed executable packet-graph edge. */
struct graph_edge {
	uint32_t to_node{0};  ///< Unified destination endpoint index; source is the owning adjacency row.
	/**
	 * Direct transition index by source storage domain. An empty row means
	 * this edge declares no transition; otherwise every absent domain carries
	 * INVALID_COMPILED_TRANSITION. This makes fixed-point lookup strict O(1)
	 * without allocating a dense row for ordinary domain-preserving edges.
	 */
	std::vector<uint32_t> transition_by_source_domain;
};

/** @brief Stable logical-stage/lane key for executable edge expansion. */
using stage_lane_key = std::pair<std::string, std::string>;

/** @brief Stable native queue ownership key. */
using queue_owner_key = std::tuple<uint32_t, uint32_t, compiled_io_stream_direction, uint32_t>;

/** @brief Stable native queue-set key without one queue member. */
using queue_group_key = std::tuple<uint32_t, uint32_t, compiled_io_stream_direction>;

/**
 * @brief Check whether a nonzero unsigned value is a power of two.
 *
 * @param value Candidate bounded capacity or alignment.
 * @return true only for a nonzero power of two.
 */
[[nodiscard]] constexpr bool is_nonzero_power_of_two(uint32_t value) noexcept
{
	return value != 0u && (value & (value - 1u)) == 0u;
}

/**
 * @brief Validate one provider-graph identity under the shared grammar.
 *
 * @param value Candidate identity.
 * @param field_name Trusted diagnostic field name.
 * @return OK for a valid bounded identity; INVALID_ARGUMENT otherwise.
 */
[[nodiscard]] status validate_graph_id(std::string_view value, std::string_view field_name)
{
	if (value.size() > MAX_PROVIDER_ID_BYTES || !common::execution_topology::is_topology_identifier(value)) {
		return status::invalid_argument(std::string(field_name) + " must match [A-Za-z_][A-Za-z0-9_]* within " +
						std::to_string(MAX_PROVIDER_ID_BYTES) + " bytes");
	}
	return status::ok();
}

/**
 * @brief Add a term to an accumulated topology count with overflow checking.
 *
 * @param[in,out] total Running total, unchanged on failure.
 * @param term Nonnegative term to add.
 * @param name Trusted diagnostic identity.
 * @return OK after addition; OUT_OF_RANGE on overflow.
 */
[[nodiscard]] status add_count_checked(uint64_t &total, uint64_t term, const char *name)
{
	if (term > std::numeric_limits<uint64_t>::max() - total) {
		return status(status_code::OUT_OF_RANGE,
			      std::string("compiled provider topology overflows while accumulating ") + name);
	}
	total += term;
	return status::ok();
}

/**
 * @brief Multiply two topology counts with overflow checking.
 *
 * @param value Nonnegative multiplicand.
 * @param factor Nonnegative multiplier.
 * @param name Trusted diagnostic identity.
 * @return Exact product or OUT_OF_RANGE.
 */
[[nodiscard]] status_or<uint64_t> multiply_count_checked(uint64_t value, uint64_t factor, const char *name)
{
	if (factor != 0u && value > std::numeric_limits<uint64_t>::max() / factor) {
		return status(status_code::OUT_OF_RANGE,
			      std::string("compiled provider topology overflows while multiplying ") + name);
	}
	return value * factor;
}

/**
 * @brief Prove a vector cardinality is representable by compact indices.
 *
 * @param count Candidate cardinality.
 * @param name Trusted collection name.
 * @return Exact uint32 count or OUT_OF_RANGE.
 */
[[nodiscard]] status_or<uint32_t> compact_count(std::size_t count, const char *name)
{
	if (count > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
		return status(status_code::OUT_OF_RANGE,
			      std::string(name) + " exceeds compact provider-topology index range");
	}
	return static_cast<uint32_t>(count);
}

/**
 * @brief Compile one role-correct provider configuration.
 *
 * @param role Structural role owning the Any.
 * @param configuration Candidate canonical envelope.
 * @param required_contracts Accumulated exact required type-URL set.
 * @return Canonical bytes and immutable catalog row.
 */
[[nodiscard]] status_or<canonicalized_contract> compile_configuration(provider_contract_role role,
								      const google::protobuf::Any &configuration,
								      std::set<std::string> &required_contracts)
{
	auto canonical_or = canonicalize_provider_configuration(role, configuration);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	auto canonical = std::move(canonical_or).value();
	const auto &contract = canonical.contract.get();
	required_contracts.insert(std::string(contract.type_url));
	return canonicalized_contract{
		compiled_provider_configuration{canonical.configuration.type_url(), canonical.configuration.value()},
		&contract,
	};
}

/**
 * @brief Shared stateful implementation of one all-or-none cold compilation.
 *
 * The object owns only temporary maps and the not-yet-published result. A
 * failing phase destroys the candidate and cannot expose partial semantic
 * truth to a caller.
 */
class provider_topology_compiler {
    public:
	/**
	 * @brief Bind one immutable plan to a fresh compiler transaction.
	 *
	 * @param plan Canonical plan to compile.
	 */
	explicit provider_topology_compiler(const kinetum::gluon::v1::DeploymentPlan &plan)
		: plan_(plan)
	{
	}

	/**
	 * @brief Execute every semantic phase in dependency order.
	 *
	 * @return Complete artifact or the first fail-closed status.
	 */
	[[nodiscard]] status_or<compiled_provider_topology> run();

    private:
	/**
	 * @brief Compile the complete logical pipeline and stage semantics.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_pipeline_semantics_();

	/**
	 * @brief Compile the already-owned transition topology.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_transition_topology_();

	/**
	 * @brief Compile exact logical regions and worker ownership.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_execution_regions_();

	/**
	 * @brief Compile sorted process-facility rows.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_facilities_();

	/**
	 * @brief Compile sorted I/O-driver rows and native port facts.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_io_drivers_();

	/**
	 * @brief Compile sorted packet-storage rows.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_storage_domains_();

	/**
	 * @brief Compile sorted execution-provider rows.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_execution_providers_();

	/**
	 * @brief Resolve exact facility references against one contract row.
	 * @param owner_kind Trusted role name used in diagnostics.
	 * @param owner_id Authored instance identity.
	 * @param references Authored facility identity list.
	 * @param contract Catalog contract declaring allowed facility dependencies.
	 * @return Resolved facility indices satisfying the contract, or an admission failure.
	 */
	[[nodiscard]] status_or<std::vector<uint32_t>>
	resolve_facilities_(std::string_view owner_kind, std::string_view owner_id,
			    const google::protobuf::RepeatedPtrField<std::string> &references,
			    const provider_contract_descriptor &contract);

	/**
	 * @brief Compile exact logical and driver-local port ownership.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_ports_();

	/**
	 * @brief Compile exact execution-lane identities and declared membership.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_execution_lanes_();

	/**
	 * @brief Compile executable stage and worker ownership.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_stage_instances_();

	/**
	 * @brief Prove complete module populations and bind immutable context ordinals.
	 * @return OK only for exact canonical domain membership.
	 */
	[[nodiscard]] status compile_module_context_domains_();

	/**
	 * @brief Derive checked per-NUMA module lifecycle-memory budgets.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_module_memory_budgets_();

	/**
	 * @brief Compile exact driver queue streams.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_io_streams_();

	/**
	 * @brief Replace transition compiler plan-order indices with sole compact indices.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status remap_transition_topology_();

	/**
	 * @brief Compile lane-local packet routes and owner-local control edges.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_stage_routes_and_controls_();

	/**
	 * @brief Compile exact hardware steering membership and driver requirements.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_steering_();

	/**
	 * @brief Build the exact executable packet graph.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status build_packet_graph_();

	/**
	 * @brief Compile and key every explicit storage transition.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_storage_transitions_();

	/**
	 * @brief Compute the finite endpoint/domain fixed point.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_reachable_domains_();

	/**
	 * @brief Derive worker schedules and exact storage credit budgets.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_schedules_and_budgets_();

	/**
	 * @brief Derive exact role and facility facts consumed by component factories.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_component_facts_();

	/**
	 * @brief Emit and sort all external proof-phase requirements.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status compile_host_requirements_();

	/**
	 * @brief Prove every declared provider object is consumed.
	 * @return OK on successful completion of this compilation phase, or its first contract failure.
	 */
	[[nodiscard]] status validate_two_directional_consumption_();

	/**
	 * @brief Resolve one protobuf endpoint to a unified graph node.
	 * @param endpoint Authored typed stream or stage-instance endpoint.
	 * @return Exact unified graph ordinal, or a rejection for an unresolved endpoint.
	 */
	[[nodiscard]] status_or<uint32_t>
	resolve_endpoint_node_(const kinetum::gluon::v1::PacketPathEndpoint &endpoint) const;

	/**
	 * @brief Convert a unified graph node to the public typed endpoint.
	 * @param node Validated unified graph ordinal.
	 * @return Typed stream or stage-instance identity for that ordinal.
	 */
	[[nodiscard]] compiled_packet_path_endpoint public_endpoint_(uint32_t node) const noexcept;

	/**
	 * @brief Validate destination access for one propagated storage domain.
	 * @param node Destination graph ordinal.
	 * @param domain Propagated compact storage-domain identity.
	 * @param transition_was_present Whether an explicit storage transition reached this destination.
	 * @return OK when destination access and transition requirements are satisfied, or a contract failure.
	 */
	[[nodiscard]] status validate_destination_access_(uint32_t node, uint32_t domain,
							  bool transition_was_present) const;

	/**
	 * @brief Test whether one same-domain stage edge changes execution ownership.
	 * @param from_node Source graph ordinal.
	 * @param to_node Destination graph ordinal.
	 * @return true when the stage edge requires an explicit same-domain ownership transition.
	 */
	[[nodiscard]] bool requires_same_domain_transition_(uint32_t from_node, uint32_t to_node) const noexcept;

	/**
	 * @brief Append contract-owned proof requirements for one role instance.
	 * @param role Compiled provider role owning the requirements.
	 * @param instance_index Compact index within that role.
	 * @param contract Catalog contract supplying the proof facts and phases.
	 */
	void append_contract_requirements_(provider_contract_role role, uint32_t instance_index,
					   const provider_contract_descriptor &contract);

	const kinetum::gluon::v1::DeploymentPlan &plan_;  ///< Immutable compilation input.
	compiled_provider_topology out_;		  ///< Unpublished candidate result.
	std::set<std::string> required_contracts_;	  ///< Exact terminal type-URL set.

	std::map<std::string, uint32_t> facility_by_id_;   ///< Authored facility ID to compiled role index.
	std::map<std::string, uint32_t> driver_by_id_;	   ///< Authored driver ID to compiled role index.
	std::map<std::string, uint32_t> storage_by_id_;	   ///< Authored domain ID to compiled storage index.
	std::map<std::string, uint32_t> execution_by_id_;  ///< Authored execution-provider ID to compiled role index.
	std::map<std::string, uint16_t> logical_stage_by_id_;  ///< Authored logical stage to compact semantics index.
	std::map<std::string, uint16_t> topological_rank_by_id_;   ///< Canonical Axiom rank by logical stage.
	std::map<std::string, uint32_t> region_by_logical_stage_;  ///< Logical-stage ownership in compiled regions.
	std::map<std::string, uint32_t> lane_by_id_;		   ///< Authored lane ID to compiled lane index.
	std::map<std::string, uint32_t> worker_by_id_;		   ///< Authored worker ID to compiled worker index.
	std::map<std::pair<int32_t, std::string>, uint32_t> worker_by_owner_;  ///< Exact region/lane worker ownership.
	std::map<std::string, uint32_t> port_by_name_;	   ///< Logical port name to compiled port index.
	std::map<uint32_t, uint32_t> port_by_logical_id_;  ///< Authored logical port ID to compiled port index.
	std::map<std::string, uint32_t> stage_by_id_;	   ///< Executable stage-instance ID to compiled stage index.
	std::map<stage_lane_key, uint32_t> stage_by_logical_lane_;  ///< Logical-stage/lane to executable instance.
	std::map<std::string, uint32_t> stream_by_id_;		    ///< Authored stream ID to compiled queue index.
	std::map<std::string, uint32_t> steering_by_id_;	    ///< Authored steering ID to compiled profile index.

	std::vector<const provider_contract_descriptor *> facility_contracts_;	 ///< Catalog rows by compiled facility.
	std::vector<const provider_contract_descriptor *> driver_contracts_;	 ///< Catalog rows by compiled driver.
	std::vector<const provider_contract_descriptor *> storage_contracts_;	 ///< Catalog rows by compiled domain.
	std::vector<const provider_contract_descriptor *> execution_contracts_;	 ///< Catalog rows by compiled executor.
	std::vector<const provider_contract_descriptor *>
		transition_contracts_;	///< Catalog rows by compiled transition.
	std::map<std::pair<uint32_t, std::string>, uint32_t>
		driver_port_by_id_;			///< Driver/local-port ID to native-port row.
	std::vector<std::string> stream_steering_ids_;	///< Authored steering reference by compiled stream index.
	std::vector<std::string> logical_stage_io_port_names_;	///< Authored interface name by logical-stage index.
	std::vector<uint32_t> plan_stage_to_compiled_;	 ///< Source stage-instance row to canonical compiled index.
	std::vector<uint32_t> plan_stream_to_compiled_;	 ///< Source stream row to canonical compiled index.
	std::vector<const kinetum::gluon::v1::ExecutionLane *>
		plan_lane_by_index_;  ///< Borrowed source lanes by compiled index.

	std::vector<uint64_t> facility_use_counts_;    ///< Required-reference counts for unused-facility rejection.
	std::vector<uint64_t> driver_use_counts_;      ///< Bound-port counts for unused-driver rejection.
	std::vector<uint64_t> storage_use_counts_;     ///< Packet-path use counts for unused-domain rejection.
	std::vector<uint64_t> execution_use_counts_;   ///< Bound-stage counts for unused-executor rejection.
	std::vector<uint64_t> transition_use_counts_;  ///< Reachable-edge use counts for unused-transition rejection.

	std::set<std::pair<uint32_t, uint32_t>> graph_edges_;  ///< Unique packet-path node pairs in canonical order.
	std::vector<graph_edge> compiled_graph_edges_;	       ///< Packet edges with their exact storage transitions.
	std::map<std::pair<uint32_t, uint32_t>, uint32_t>
		graph_edge_index_by_nodes_;			     ///< Endpoint pair to compiled edge.
	std::vector<std::vector<uint32_t>> outgoing_edge_indices_;   ///< Compiled outgoing edges by packet-path node.
	std::vector<std::vector<uint64_t>> reachable_domain_words_;  ///< Fixed-point storage-domain bitsets by node.
};

status_or<compiled_provider_topology> provider_topology_compiler::run()
{
	if (const auto unknown_status = common::reject_unknown_protobuf_fields_recursive(plan_, "DeploymentPlan");
	    !unknown_status.is_ok()) {
		return unknown_status;
	}
	if (const auto enum_status = common::reject_invalid_protobuf_enum_values_recursive(plan_, "DeploymentPlan");
	    !enum_status.is_ok()) {
		return enum_status;
	}
	out_.source_plan_content_hash = plan_.content_hash();
	using phase_function = status (provider_topology_compiler::*)();
	static constexpr std::array<phase_function, 23> PHASES{
		&provider_topology_compiler::compile_pipeline_semantics_,
		&provider_topology_compiler::compile_transition_topology_,
		&provider_topology_compiler::compile_execution_regions_,
		&provider_topology_compiler::compile_facilities_,
		&provider_topology_compiler::compile_io_drivers_,
		&provider_topology_compiler::compile_storage_domains_,
		&provider_topology_compiler::compile_execution_providers_,
		&provider_topology_compiler::compile_ports_,
		&provider_topology_compiler::compile_execution_lanes_,
		&provider_topology_compiler::compile_stage_instances_,
		&provider_topology_compiler::compile_module_context_domains_,
		&provider_topology_compiler::compile_module_memory_budgets_,
		&provider_topology_compiler::compile_io_streams_,
		&provider_topology_compiler::remap_transition_topology_,
		&provider_topology_compiler::compile_stage_routes_and_controls_,
		&provider_topology_compiler::compile_steering_,
		&provider_topology_compiler::build_packet_graph_,
		&provider_topology_compiler::compile_storage_transitions_,
		&provider_topology_compiler::compile_reachable_domains_,
		&provider_topology_compiler::compile_schedules_and_budgets_,
		&provider_topology_compiler::validate_two_directional_consumption_,
		&provider_topology_compiler::compile_component_facts_,
		&provider_topology_compiler::compile_host_requirements_,
	};
	for (const auto phase : PHASES) {
		const auto phase_status = (this->*phase)();
		if (!phase_status.is_ok()) {
			return phase_status;
		}
	}
	out_.required_contract_type_urls.assign(required_contracts_.begin(), required_contracts_.end());
	return status_or<compiled_provider_topology>(std::in_place, std::move(out_));
}

status provider_topology_compiler::compile_pipeline_semantics_()
{
	auto contract_status = kinetum::axiom::verify_contract(plan_.pipeline(), kinetum::axiom::contract_options{});
	if (!contract_status.is_ok()) {
		return contract_status;
	}
	if (plan_.pipeline().stages_size() == 0) {
		return status::invalid_argument("provider topology requires a nonempty executable pipeline");
	}
	if (static_cast<std::size_t>(plan_.pipeline().stages_size()) > MAX_COMPILED_STAGE_INSTANCES) {
		return status(status_code::OUT_OF_RANGE,
			      "logical stage count exceeds the compact packet-stage namespace");
	}
	auto topological_order_or = kinetum::axiom::canonical_topological_order(plan_.pipeline());
	if (!topological_order_or.is_ok()) {
		return topological_order_or.error();
	}
	const auto &topological_order = topological_order_or.value();
	if (topological_order.size() != static_cast<std::size_t>(plan_.pipeline().stages_size())) {
		return status::internal_error("Axiom topological order cardinality disagrees with pipeline truth");
	}
	for (std::size_t rank = 0; rank < topological_order.size(); ++rank) {
		if (!topological_rank_by_id_.emplace(topological_order[rank], static_cast<uint16_t>(rank)).second) {
			return status::internal_error("Axiom topological order contains a duplicate stage identity");
		}
	}

	out_.logical_stages.reserve(static_cast<std::size_t>(plan_.pipeline().stages_size()));
	logical_stage_io_port_names_.reserve(static_cast<std::size_t>(plan_.pipeline().stages_size()));
	for (int plan_index = 0; plan_index < plan_.pipeline().stages_size(); ++plan_index) {
		const auto &stage = plan_.pipeline().stages(plan_index);
		if (const auto id_status = validate_graph_id(stage.stage_id(), "logical stage_id");
		    !id_status.is_ok()) {
			return id_status;
		}
		compiled_stage_kind kind;
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_RX) {
			kind = compiled_stage_kind::RX;
		} else if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_TX) {
			kind = compiled_stage_kind::TX;
		} else if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4) {
			kind = compiled_stage_kind::PARSE_IPV4;
		} else if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
			kind = compiled_stage_kind::MODULE;
		} else {
			return status::invalid_argument("logical stage has no current executable mechanism");
		}

		compiled_stage_execution_mode execution_mode;
		if (stage.execution_mode() == kinetum::axiom::v1::EXECUTION_MODE_PASSIVE) {
			execution_mode = compiled_stage_execution_mode::PASSIVE;
		} else if (stage.execution_mode() == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
			execution_mode = compiled_stage_execution_mode::ACTIVE;
		} else {
			return status::invalid_argument("logical stage has an invalid execution_mode");
		}
		if ((stage.trigger_mask() & ~ALL_ACTIVE_TRIGGER_BITS) != 0u) {
			return status::invalid_argument("active stage trigger_mask contains an unknown bit");
		}
		const auto &active_limits = stage.active_stage_limits();
		const bool retains_packets = active_limits.retained_packet_capacity() != 0u;
		const bool retains_bytes = active_limits.retained_byte_capacity() != 0u;
		const bool timer_triggered =
			(stage.trigger_mask() & static_cast<uint32_t>(compiled_active_stage_trigger::TIMER)) != 0u;
		const bool control_triggered =
			(stage.trigger_mask() & static_cast<uint32_t>(compiled_active_stage_trigger::CONTROL)) != 0u;
		const bool control_fields_present = active_limits.control_mailbox_capacity() != 0u ||
						    active_limits.control_message_capacity_bytes() != 0u;
		const bool control_capacity_valid = active_limits.control_mailbox_capacity() >= 2u &&
						    (active_limits.control_mailbox_capacity() &
						     (active_limits.control_mailbox_capacity() - 1u)) == 0u &&
						    active_limits.control_message_capacity_bytes() != 0u;
		const bool async_capacity_present = active_limits.async_work_capacity() != 0u;
		const bool async_grace_present = active_limits.async_cancel_grace_ms() != 0u;
		if (execution_mode == compiled_stage_execution_mode::PASSIVE) {
			if (stage.trigger_mask() != 0u || stage.schedule_order() != 0 || retains_packets ||
			    retains_bytes || active_limits.timer_capacity() != 0u ||
			    active_limits.control_mailbox_capacity() != 0u ||
			    active_limits.control_message_capacity_bytes() != 0u || async_capacity_present ||
			    async_grace_present) {
				return status::invalid_argument(
					"passive stage must not carry active triggers, schedule, or limits");
			}
		} else if (stage.trigger_mask() == 0u || retains_packets != retains_bytes ||
			   (retains_packets &&
			    active_limits.retained_byte_capacity() < active_limits.retained_packet_capacity()) ||
			   timer_triggered != (active_limits.timer_capacity() != 0u) ||
			   control_triggered != control_fields_present ||
			   (control_fields_present && !control_capacity_valid) ||
			   async_capacity_present != async_grace_present) {
			return status::invalid_argument(
				"active stage limits disagree with its trigger and tracked-work contract");
		}

		if (kind == compiled_stage_kind::MODULE) {
			if (!stage.has_module() || !kinetum::sdk::valid_module_abi_text(stage.module().module_id())) {
				return status::invalid_argument(
					"module stage requires one bounded printable module_id");
			}
			if (stage.module().has_module_path() && stage.module().module_path().empty()) {
				return status::invalid_argument("authored module_path must not be empty");
			}
		} else if (stage.has_module()) {
			return status::invalid_argument("platform mechanism stage must not carry module configuration");
		}
		std::string io_port_name;
		if (kind == compiled_stage_kind::RX || kind == compiled_stage_kind::TX) {
			if (!stage.has_io() || stage.io().interface().empty()) {
				return status::invalid_argument("I/O logical stage requires one exact typed interface");
			}
			if (const auto id_status = validate_graph_id(stage.io().interface(), "I/O interface");
			    !id_status.is_ok()) {
				return id_status;
			}
			io_port_name = stage.io().interface();
		} else if (stage.has_io()) {
			return status::invalid_argument("non-I/O logical stage must not carry an interface binding");
		}

		const uint16_t logical_index = static_cast<uint16_t>(plan_index);
		if (!logical_stage_by_id_.emplace(stage.stage_id(), logical_index).second) {
			return status::invalid_argument("pipeline contains a duplicate logical stage identity");
		}
		compiled_logical_stage compiled;
		compiled.logical_stage_id = stage.stage_id();
		compiled.logical_stage_index = logical_index;
		compiled.kind = kind;
		compiled.execution_mode = execution_mode;
		compiled.trigger_mask = stage.trigger_mask();
		compiled.retained_packet_capacity = active_limits.retained_packet_capacity();
		compiled.retained_byte_capacity = active_limits.retained_byte_capacity();
		compiled.timer_capacity = active_limits.timer_capacity();
		compiled.control_mailbox_capacity = active_limits.control_mailbox_capacity();
		compiled.control_message_capacity_bytes = active_limits.control_message_capacity_bytes();
		compiled.async_work_capacity = active_limits.async_work_capacity();
		if (active_limits.async_cancel_grace_ms() != 0u) {
			auto grace_or = compile_async_cancel_grace(active_limits.async_cancel_grace_ms());
			if (!grace_or.is_ok()) {
				return grace_or.error();
			}
			compiled.async_cancel_grace = grace_or.value();
		}
		compiled.schedule_order = stage.schedule_order();
		if (stage.has_module()) {
			compiled.module_id = stage.module().module_id();
			switch (stage.module().context_selection()) {
			case kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE:
				compiled.context_selection = compiled_module_context_selection::SAME_LANE;
				break;
			case kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_MODULE:
				compiled.context_selection = compiled_module_context_selection::MODULE;
				break;
			case kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_UNSPECIFIED:
			case kinetum::axiom::v1::ModuleContextSelection_INT_MIN_SENTINEL_DO_NOT_USE_:
			case kinetum::axiom::v1::ModuleContextSelection_INT_MAX_SENTINEL_DO_NOT_USE_:
				return status::invalid_argument("module stage requires explicit context selection");
			}
		}
		if (stage.has_module() && stage.module().has_module_path()) {
			compiled.module_path.emplace(stage.module().module_path());
		}
		out_.logical_stages.push_back(std::move(compiled));
		logical_stage_io_port_names_.push_back(std::move(io_port_name));
	}
	return status::ok();
}

status provider_topology_compiler::compile_transition_topology_()
{
	auto transition_or = common::compile_transition_topology(plan_);
	if (!transition_or.is_ok()) {
		return transition_or.error();
	}
	out_.transition_topology = std::move(transition_or).value();
	for (const auto &worker : out_.transition_topology.workers) {
		const auto poll_ms = std::chrono::duration_cast<std::chrono::milliseconds>(worker.health_poll_interval);
		const auto callback_ns =
			std::chrono::duration_cast<std::chrono::nanoseconds>(worker.health_callback_budget);
		if (poll_ms <= std::chrono::milliseconds::zero() || callback_ns <= std::chrono::nanoseconds::zero() ||
		    std::chrono::duration_cast<std::chrono::steady_clock::duration>(poll_ms) !=
			    worker.health_poll_interval ||
		    std::chrono::duration_cast<std::chrono::steady_clock::duration>(callback_ns) !=
			    worker.health_callback_budget ||
		    worker.health_callback_budget >= worker.health_poll_interval) {
			return status::invalid_argument(
				"compiled worker health cadence and callback budget are not exact");
		}
	}
	if (out_.transition_topology.policy.enabled) {
		for (const auto &stage : out_.logical_stages) {
			if (stage.async_work_capacity != 0u &&
			    stage.async_cancel_grace >= out_.transition_topology.policy.commit_timeout) {
				return status::invalid_argument(
					"async cancellation grace must be strictly shorter than commit_timeout_ms");
			}
		}
	}
	return status::ok();
}

status provider_topology_compiler::compile_execution_regions_()
{
	auto count_or = compact_count(static_cast<std::size_t>(plan_.regions_size()), "regions[]");
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	if (count_or.value() == 0u) {
		return status::invalid_argument("provider topology requires at least one execution region");
	}
	out_.execution_regions.resize(count_or.value());
	std::vector<bool> seen_region_indices(count_or.value(), false);
	for (const auto &worker : out_.transition_topology.workers) {
		if (!worker_by_id_.emplace(worker.worker_id, worker.worker_index).second ||
		    !worker_by_owner_.emplace(std::make_pair(worker.region_id, worker.lane_id), worker.worker_index)
			     .second) {
			return status::internal_error("transition topology contains duplicate worker ownership");
		}
		out_.execution_regions[static_cast<std::size_t>(worker.region_id)].worker_indices.push_back(
			worker.worker_index);
	}

	for (const auto &region : plan_.regions()) {
		if (region.region_id() < 0 || static_cast<uint32_t>(region.region_id()) >= count_or.value() ||
		    seen_region_indices[static_cast<std::size_t>(region.region_id())]) {
			return status::invalid_argument("regions[] contains duplicate or noncompact identity");
		}
		seen_region_indices[static_cast<std::size_t>(region.region_id())] = true;
		auto &compiled = out_.execution_regions[static_cast<std::size_t>(region.region_id())];
		compiled.region_id = region.region_id();
		compiled.numa_node = region.numa_node();
		std::optional<uint16_t> previous_rank;
		for (const auto &logical_stage_id : region.logical_stage_ids()) {
			const auto logical_it = logical_stage_by_id_.find(logical_stage_id);
			const auto rank_it = topological_rank_by_id_.find(logical_stage_id);
			if (logical_it == logical_stage_by_id_.end() || rank_it == topological_rank_by_id_.end() ||
			    (previous_rank.has_value() && previous_rank.value() >= rank_it->second) ||
			    !region_by_logical_stage_
				     .emplace(logical_stage_id, static_cast<uint32_t>(region.region_id()))
				     .second) {
				return status::invalid_argument(
					"region logical_stage_ids[] must be exact, unique, and in canonical topological order");
			}
			previous_rank = rank_it->second;
			compiled.logical_stage_indices.push_back(logical_it->second);
		}
		if (compiled.logical_stage_indices.empty() || compiled.worker_indices.empty()) {
			return status::invalid_argument("each execution region requires stages and worker ownership");
		}

		std::set<int32_t> expected_cpu_cores;
		for (const uint32_t worker_index : compiled.worker_indices) {
			const auto &worker = out_.transition_topology.workers[worker_index];
			expected_cpu_cores.insert(worker.cpu_core_ids.begin(), worker.cpu_core_ids.end());
		}
		const std::vector<int32_t> expected_cpu_vector(expected_cpu_cores.begin(), expected_cpu_cores.end());
		const std::vector<int32_t> authored_cpu_vector(region.cpu_core_ids().begin(),
							       region.cpu_core_ids().end());
		if (authored_cpu_vector != expected_cpu_vector) {
			return status::invalid_argument(
				"region cpu_core_ids[] must equal the exact worker-owned CPU union");
		}
	}
	if (region_by_logical_stage_.size() != out_.logical_stages.size()) {
		return status::invalid_argument("regions[] do not own every logical stage exactly once");
	}
	return status::ok();
}

status provider_topology_compiler::compile_facilities_()
{
	auto count_or = compact_count(static_cast<std::size_t>(plan_.process_facility_instances_size()),
				      "process_facility_instances[]");
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	std::vector<const kinetum::gluon::v1::ProcessFacilityInstance *> sorted;
	sorted.reserve(count_or.value());
	for (const auto &instance : plan_.process_facility_instances()) {
		sorted.push_back(&instance);
	}
	std::sort(sorted.begin(), sorted.end(), [](const auto *lhs, const auto *rhs) {
		return lhs->facility_instance_id() < rhs->facility_instance_id();
	});

	out_.process_facilities.reserve(sorted.size());
	facility_contracts_.reserve(sorted.size());
	std::map<std::string_view, uint32_t> counts_by_contract;
	std::map<std::string_view, std::string> first_configuration_by_contract;
	for (const auto *instance : sorted) {
		if (const auto id_status = validate_graph_id(instance->facility_instance_id(), "facility_instance_id");
		    !id_status.is_ok()) {
			return id_status;
		}
		if (facility_by_id_.contains(instance->facility_instance_id())) {
			return status::invalid_argument("duplicate process facility instance '" +
							instance->facility_instance_id() + "'");
		}
		auto canonical_or = compile_configuration(provider_contract_role::PROCESS_FACILITY,
							  instance->configuration(), required_contracts_);
		if (!canonical_or.is_ok()) {
			return canonical_or.error();
		}
		auto canonical = std::move(canonical_or).value();
		const auto *projection = std::get_if<process_facility_projection>(&canonical.contract->capabilities);
		if (projection == nullptr) {
			return status::internal_error("process-facility catalog row lost its role projection");
		}
		if (!canonical.contract->facility_dependencies.empty()) {
			return status::invalid_argument("process facility contract cannot depend on another facility");
		}
		auto [configuration_it, inserted] = first_configuration_by_contract.emplace(
			canonical.contract->type_url, canonical.configuration.canonical_payload);
		if (!inserted && projection->identical_configuration_required &&
		    configuration_it->second != canonical.configuration.canonical_payload) {
			return status::invalid_argument("process facility instances of contract '" +
							std::string(canonical.contract->type_url) +
							"' require byte-identical canonical configuration");
		}
		++counts_by_contract[canonical.contract->type_url];
		const uint32_t index = static_cast<uint32_t>(out_.process_facilities.size());
		facility_by_id_.emplace(instance->facility_instance_id(), index);
		facility_contracts_.push_back(canonical.contract);
		out_.process_facilities.push_back(compiled_process_facility_instance{
			.facility_instance_id = instance->facility_instance_id(),
			.facility_index = index,
			.configuration = std::move(canonical.configuration),
			.capabilities = *projection,
			.main_core_id = std::nullopt,
			.cpu_assignments = {},
			.attachments = {},
			.memory_domains = {},
		});
	}
	for (std::size_t index = 0; index < out_.process_facilities.size(); ++index) {
		const auto &facility = out_.process_facilities[index];
		if (facility.capabilities.exactly_one_per_process_generation &&
		    counts_by_contract.at(facility_contracts_[index]->type_url) != 1u) {
			return status::invalid_argument("process facility contract '" +
							facility.configuration.type_url +
							"' requires exactly one instance per runtime generation");
		}
	}
	facility_use_counts_.assign(out_.process_facilities.size(), 0u);
	return status::ok();
}

status_or<std::vector<uint32_t>>
provider_topology_compiler::resolve_facilities_(std::string_view owner_kind, std::string_view owner_id,
						const google::protobuf::RepeatedPtrField<std::string> &references,
						const provider_contract_descriptor &contract)
{
	std::vector<uint32_t> resolved;
	resolved.reserve(static_cast<std::size_t>(references.size()));
	std::map<std::string_view, uint32_t> counts_by_contract;
	std::optional<std::string_view> previous;
	for (const auto &reference : references) {
		if (previous.has_value() && previous.value() >= reference) {
			return status::invalid_argument(std::string(owner_kind) + " '" + std::string(owner_id) +
							"' facility references must be strictly sorted and unique");
		}
		previous = reference;
		const auto facility_it = facility_by_id_.find(reference);
		if (facility_it == facility_by_id_.end()) {
			return status::invalid_argument(std::string(owner_kind) + " '" + std::string(owner_id) +
							"' references unknown facility '" + reference + "'");
		}
		const uint32_t facility_index = facility_it->second;
		resolved.push_back(facility_index);
		++counts_by_contract[facility_contracts_[facility_index]->type_url];
	}

	std::size_t required_count = 0;
	for (const auto &dependency : contract.facility_dependencies) {
		required_count += dependency.exact_instance_count;
		if (counts_by_contract[dependency.type_url] != dependency.exact_instance_count) {
			return status::invalid_argument(
				std::string(owner_kind) + " '" + std::string(owner_id) +
				"' does not have the exact facility dependency cardinality for '" +
				std::string(dependency.type_url) + "'");
		}
	}
	if (resolved.size() != required_count || counts_by_contract.size() != contract.facility_dependencies.size()) {
		return status::invalid_argument(std::string(owner_kind) + " '" + std::string(owner_id) +
						"' has an extra or missing facility dependency");
	}
	for (const uint32_t facility_index : resolved) {
		++facility_use_counts_[facility_index];
	}
	return resolved;
}

status provider_topology_compiler::compile_io_drivers_()
{
	auto count_or =
		compact_count(static_cast<std::size_t>(plan_.io_driver_instances_size()), "io_driver_instances[]");
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	std::vector<const kinetum::gluon::v1::IoDriverInstance *> sorted;
	sorted.reserve(count_or.value());
	for (const auto &instance : plan_.io_driver_instances()) {
		sorted.push_back(&instance);
	}
	std::sort(sorted.begin(), sorted.end(), [](const auto *lhs, const auto *rhs) {
		return lhs->io_driver_instance_id() < rhs->io_driver_instance_id();
	});

	out_.io_drivers.reserve(sorted.size());
	driver_contracts_.reserve(sorted.size());
	for (const auto *instance : sorted) {
		if (const auto id_status =
			    validate_graph_id(instance->io_driver_instance_id(), "io_driver_instance_id");
		    !id_status.is_ok()) {
			return id_status;
		}
		if (driver_by_id_.contains(instance->io_driver_instance_id())) {
			return status::invalid_argument("duplicate I/O-driver instance '" +
							instance->io_driver_instance_id() + "'");
		}
		auto canonical_or = compile_configuration(provider_contract_role::IO_DRIVER, instance->configuration(),
							  required_contracts_);
		if (!canonical_or.is_ok()) {
			return canonical_or.error();
		}
		auto canonical = std::move(canonical_or).value();
		const auto *projection = std::get_if<io_driver_projection>(&canonical.contract->capabilities);
		if (projection == nullptr) {
			return status::internal_error("I/O-driver catalog row lost its role projection");
		}
		auto facilities_or = resolve_facilities_("I/O-driver instance", instance->io_driver_instance_id(),
							 instance->facility_instance_ids(), *canonical.contract);
		if (!facilities_or.is_ok()) {
			return facilities_or.error();
		}

		const uint32_t index = static_cast<uint32_t>(out_.io_drivers.size());
		std::vector<compiled_driver_attachment> attachments;
		if (canonical.configuration.type_url == DPDK_DRIVER_TYPE_URL) {
			kinetum::io::dpdk::v1::DpdkDriverConfig configuration;
			if (!configuration.ParseFromString(canonical.configuration.canonical_payload)) {
				return status::internal_error("canonical DPDK driver payload could not be decoded");
			}
			attachments.reserve(static_cast<std::size_t>(configuration.ports_size()));
			for (const auto &port : configuration.ports()) {
				compiled_driver_attachment attachment;
				attachment.driver_port_id = port.driver_port_id();
				attachment.io_driver_index = index;
				switch (port.attachment_case()) {
				case kinetum::io::dpdk::v1::DpdkDriverPort::kPci:
					attachment.kind = compiled_driver_attachment_kind::PCI;
					attachment.attachment_identity = port.pci().pci_address();
					break;
				case kinetum::io::dpdk::v1::DpdkDriverPort::kTap:
					attachment.kind = compiled_driver_attachment_kind::TAP;
					attachment.attachment_identity = port.tap().interface_name();
					break;
				case kinetum::io::dpdk::v1::DpdkDriverPort::ATTACHMENT_NOT_SET:
				default:
					return status::internal_error(
						"canonical DPDK driver payload lost its exact attachment");
				}
				attachments.push_back(std::move(attachment));
			}
		} else if (canonical.configuration.type_url == UDP_DRIVER_TYPE_URL) {
			kinetum::io::udp::v1::UdpDriverConfig configuration;
			if (!configuration.ParseFromString(canonical.configuration.canonical_payload)) {
				return status::internal_error("canonical UDP driver payload could not be decoded");
			}
			attachments.reserve(static_cast<std::size_t>(configuration.ports_size()));
			for (const auto &port : configuration.ports()) {
				attachments.push_back(compiled_driver_attachment{
					port.driver_port_id(), index, compiled_driver_attachment_kind::UDP_IPV4,
					port.ipv4_address(), port.port()});
			}
		} else {
			return status::internal_error("catalog I/O-driver row has no semantic compiler");
		}

		driver_by_id_.emplace(instance->io_driver_instance_id(), index);
		driver_contracts_.push_back(canonical.contract);
		for (std::size_t port_index = 0; port_index < attachments.size(); ++port_index) {
			driver_port_by_id_.emplace(std::make_pair(index, attachments[port_index].driver_port_id),
						   static_cast<uint32_t>(port_index));
		}
		compiled_io_driver_instance compiled;
		compiled.io_driver_instance_id = instance->io_driver_instance_id();
		compiled.io_driver_index = index;
		compiled.facility_indices = std::move(facilities_or).value();
		compiled.configuration = std::move(canonical.configuration);
		compiled.capabilities = *projection;
		compiled.attachments = std::move(attachments);
		out_.io_drivers.push_back(std::move(compiled));
	}
	driver_use_counts_.assign(out_.io_drivers.size(), 0u);
	return status::ok();
}

status provider_topology_compiler::compile_storage_domains_()
{
	auto count_or = compact_count(static_cast<std::size_t>(plan_.packet_storage_domains_size()),
				      "packet_storage_domains[]");
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	if (count_or.value() > KINETUM_INVALID_STORAGE_DOMAIN) {
		return status(status_code::OUT_OF_RANGE,
			      "packet_storage_domains[] exceeds the packet-record index namespace");
	}
	std::vector<const kinetum::gluon::v1::PacketStorageDomain *> sorted;
	sorted.reserve(count_or.value());
	for (const auto &domain : plan_.packet_storage_domains()) {
		sorted.push_back(&domain);
	}
	std::sort(sorted.begin(), sorted.end(),
		  [](const auto *lhs, const auto *rhs) { return lhs->storage_domain_id() < rhs->storage_domain_id(); });

	out_.storage_domains.reserve(sorted.size());
	storage_contracts_.reserve(sorted.size());
	for (const auto *domain : sorted) {
		if (const auto id_status = validate_graph_id(domain->storage_domain_id(), "storage_domain_id");
		    !id_status.is_ok()) {
			return id_status;
		}
		if (storage_by_id_.contains(domain->storage_domain_id())) {
			return status::invalid_argument("duplicate packet-storage domain '" +
							domain->storage_domain_id() + "'");
		}
		if (domain->buffer_count() == 0 || domain->data_room_bytes() == 0 ||
		    domain->headroom_bytes() >= domain->data_room_bytes() ||
		    !is_nonzero_power_of_two(domain->alignment_bytes()) ||
		    (domain->has_host_numa_node() && domain->host_numa_node() < 0)) {
			return status::invalid_argument("packet-storage domain '" + domain->storage_domain_id() +
							"' has invalid capacity, room, alignment, or NUMA facts");
		}
		auto canonical_or = compile_configuration(provider_contract_role::PACKET_STORAGE,
							  domain->configuration(), required_contracts_);
		if (!canonical_or.is_ok()) {
			return canonical_or.error();
		}
		auto canonical = std::move(canonical_or).value();
		const auto *projection = std::get_if<packet_storage_projection>(&canonical.contract->capabilities);
		if (projection == nullptr) {
			return status::internal_error("packet-storage catalog row lost its role projection");
		}
		if (domain->data_room_bytes() > projection->maximum_data_room_bytes) {
			return status::invalid_argument(
				"packet-storage domain '" + domain->storage_domain_id() +
				"' data room exceeds its provider contract's representable range");
		}
		const uint32_t maximum_packet_length = domain->data_room_bytes() - domain->headroom_bytes();
		if (maximum_packet_length > static_cast<uint32_t>(std::numeric_limits<uint16_t>::max())) {
			return status::invalid_argument("packet-storage domain '" + domain->storage_domain_id() +
							"' payload room exceeds packet-record length representation");
		}
		auto facilities_or = resolve_facilities_("packet-storage domain", domain->storage_domain_id(),
							 domain->facility_instance_ids(), *canonical.contract);
		if (!facilities_or.is_ok()) {
			return facilities_or.error();
		}

		uint32_t cache_size = 0;
		if (canonical.configuration.type_url == DPDK_STORAGE_TYPE_URL) {
			kinetum::storage::dpdk::v1::DpdkStorageConfig configuration;
			if (!configuration.ParseFromString(canonical.configuration.canonical_payload)) {
				return status::internal_error("canonical DPDK storage payload could not be decoded");
			}
			cache_size = configuration.cache_size();
		}
		const bool requires_host_numa = std::any_of(canonical.contract->host_requirements.begin(),
							    canonical.contract->host_requirements.end(),
							    [](const provider_host_requirement &requirement) {
								    return requirement.fact ==
									   provider_host_fact::HOST_NUMA_MEMORY;
							    });
		if (requires_host_numa != domain->has_host_numa_node()) {
			return status::invalid_argument(
				"packet-storage domain '" + domain->storage_domain_id() +
				"' host_numa_node presence must exactly match its provider contract");
		}

		const uint32_t index = static_cast<uint32_t>(out_.storage_domains.size());
		storage_by_id_.emplace(domain->storage_domain_id(), index);
		storage_contracts_.push_back(canonical.contract);
		compiled_packet_storage_domain compiled;
		compiled.storage_domain_id = domain->storage_domain_id();
		compiled.storage_domain_index = index;
		compiled.facility_indices = std::move(facilities_or).value();
		compiled.configuration = std::move(canonical.configuration);
		compiled.capabilities = *projection;
		compiled.buffer_count = domain->buffer_count();
		compiled.data_room_bytes = domain->data_room_bytes();
		compiled.headroom_bytes = domain->headroom_bytes();
		compiled.alignment_bytes = domain->alignment_bytes();
		compiled.host_numa_node =
			domain->has_host_numa_node() ? std::optional<int32_t>(domain->host_numa_node()) : std::nullopt;
		compiled.cache_size_per_worker = cache_size;
		compiled.maximum_packet_length = static_cast<uint16_t>(maximum_packet_length);
		out_.storage_domains.push_back(std::move(compiled));
	}
	storage_use_counts_.assign(out_.storage_domains.size(), 0u);
	return status::ok();
}

status provider_topology_compiler::compile_execution_providers_()
{
	auto count_or = compact_count(static_cast<std::size_t>(plan_.execution_provider_instances_size()),
				      "execution_provider_instances[]");
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	std::vector<const kinetum::gluon::v1::ExecutionProviderInstance *> sorted;
	sorted.reserve(count_or.value());
	for (const auto &instance : plan_.execution_provider_instances()) {
		sorted.push_back(&instance);
	}
	std::sort(sorted.begin(), sorted.end(), [](const auto *lhs, const auto *rhs) {
		return lhs->execution_provider_instance_id() < rhs->execution_provider_instance_id();
	});

	out_.execution_providers.reserve(sorted.size());
	execution_contracts_.reserve(sorted.size());
	for (const auto *instance : sorted) {
		if (const auto id_status = validate_graph_id(instance->execution_provider_instance_id(),
							     "execution_provider_instance_id");
		    !id_status.is_ok()) {
			return id_status;
		}
		if (execution_by_id_.contains(instance->execution_provider_instance_id())) {
			return status::invalid_argument("duplicate execution-provider instance '" +
							instance->execution_provider_instance_id() + "'");
		}
		auto canonical_or = compile_configuration(provider_contract_role::EXECUTION, instance->configuration(),
							  required_contracts_);
		if (!canonical_or.is_ok()) {
			return canonical_or.error();
		}
		auto canonical = std::move(canonical_or).value();
		const auto *projection = std::get_if<execution_projection>(&canonical.contract->capabilities);
		if (projection == nullptr) {
			return status::internal_error("execution catalog row lost its role projection");
		}
		auto facilities_or = resolve_facilities_("execution-provider instance",
							 instance->execution_provider_instance_id(),
							 instance->facility_instance_ids(), *canonical.contract);
		if (!facilities_or.is_ok()) {
			return facilities_or.error();
		}
		const uint32_t index = static_cast<uint32_t>(out_.execution_providers.size());
		execution_by_id_.emplace(instance->execution_provider_instance_id(), index);
		execution_contracts_.push_back(canonical.contract);
		compiled_execution_provider_instance compiled;
		compiled.execution_provider_instance_id = instance->execution_provider_instance_id();
		compiled.execution_provider_index = index;
		compiled.facility_indices = std::move(facilities_or).value();
		compiled.configuration = std::move(canonical.configuration);
		compiled.capabilities = *projection;
		out_.execution_providers.push_back(std::move(compiled));
	}
	execution_use_counts_.assign(out_.execution_providers.size(), 0u);
	return status::ok();
}

status provider_topology_compiler::compile_ports_()
{
	auto count_or = compact_count(static_cast<std::size_t>(plan_.ports_size()), "ports[]");
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	if (count_or.value() == 0u) {
		return status::invalid_argument("provider topology requires at least one logical port");
	}
	std::vector<const kinetum::gluon::v1::PortConfig *> sorted;
	sorted.reserve(count_or.value());
	std::set<std::string> declared_names;
	std::set<uint32_t> declared_logical_ids;
	for (const auto &port : plan_.ports()) {
		if (const auto id_status = validate_graph_id(port.logical_name(), "logical port name");
		    !id_status.is_ok()) {
			return id_status;
		}
		if (port.logical_port_id() >= KINETUM_MAX_PORTS || port.mtu() == 0 ||
		    port.mtu() > static_cast<uint32_t>(std::numeric_limits<uint16_t>::max()) ||
		    (port.has_host_numa_node() && port.host_numa_node() < 0) ||
		    (!port.resolved_mac_address().empty() && port.resolved_mac_address().size() != 6u)) {
			return status::invalid_argument("logical port '" + port.logical_name() +
							"' has invalid ID, MTU, NUMA, or MAC facts");
		}
		if (!declared_names.insert(port.logical_name()).second ||
		    !declared_logical_ids.insert(port.logical_port_id()).second) {
			return status::invalid_argument("ports[] contains duplicate logical name or logical_port_id");
		}
		sorted.push_back(&port);
	}
	std::sort(sorted.begin(), sorted.end(),
		  [](const auto *lhs, const auto *rhs) { return lhs->logical_name() < rhs->logical_name(); });
	std::set<std::pair<uint32_t, uint32_t>> claimed_driver_ports;
	out_.ports.reserve(sorted.size());
	for (const auto *port : sorted) {
		const auto driver_it = driver_by_id_.find(port->io_driver_instance_id());
		if (driver_it == driver_by_id_.end()) {
			return status::invalid_argument("logical port '" + port->logical_name() +
							"' references unknown I/O-driver instance");
		}
		const auto native_it = driver_port_by_id_.find({driver_it->second, port->driver_port_id()});
		if (native_it == driver_port_by_id_.end()) {
			return status::invalid_argument(
				"logical port '" + port->logical_name() +
				"' references a driver_port_id absent from canonical driver configuration");
		}
		if (!claimed_driver_ports.emplace(driver_it->second, native_it->second).second) {
			return status::invalid_argument("driver-local port is claimed by more than one logical port");
		}

		compiled_io_port_direction direction;
		switch (port->direction()) {
		case kinetum::gluon::v1::PORT_DIRECTION_RX_ONLY:
			direction = compiled_io_port_direction::RX_ONLY;
			break;
		case kinetum::gluon::v1::PORT_DIRECTION_TX_ONLY:
			direction = compiled_io_port_direction::TX_ONLY;
			break;
		case kinetum::gluon::v1::PORT_DIRECTION_BIDIRECTIONAL:
			direction = compiled_io_port_direction::BIDIRECTIONAL;
			break;
		case kinetum::gluon::v1::PORT_DIRECTION_UNSPECIFIED:
		case kinetum::gluon::v1::PortDirection_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::gluon::v1::PortDirection_INT_MAX_SENTINEL_DO_NOT_USE_:
			return status::invalid_argument("logical port has unspecified direction");
		}
		const uint32_t index = static_cast<uint32_t>(out_.ports.size());
		if (port->logical_port_id() != index) {
			return status::invalid_argument(
				"ports[] logical_port_id must equal canonical logical-name index");
		}
		compiled_io_port compiled;
		compiled.port_index = index;
		compiled.logical_port_id = port->logical_port_id();
		compiled.logical_name = port->logical_name();
		compiled.io_driver_index = driver_it->second;
		compiled.driver_port_index = native_it->second;
		compiled.direction = direction;
		compiled.host_numa_node = port->has_host_numa_node() ? std::optional<int32_t>(port->host_numa_node()) :
								       std::nullopt;
		compiled.mtu = port->mtu();
		compiled.has_resolved_mac_address = !port->resolved_mac_address().empty();
		if (compiled.has_resolved_mac_address) {
			// The first pass admitted present MACs as exactly six bytes.
			std::memcpy(compiled.resolved_mac_address.data(), port->resolved_mac_address().data(),
				    compiled.resolved_mac_address.size());
		}
		port_by_name_.emplace(compiled.logical_name, index);
		port_by_logical_id_.emplace(compiled.logical_port_id, index);
		++driver_use_counts_[compiled.io_driver_index];
		out_.ports.push_back(std::move(compiled));
	}
	for (std::size_t driver_index = 0; driver_index < out_.io_drivers.size(); ++driver_index) {
		for (std::size_t port_index = 0; port_index < out_.io_drivers[driver_index].attachments.size();
		     ++port_index) {
			if (!claimed_driver_ports.contains(
				    {static_cast<uint32_t>(driver_index), static_cast<uint32_t>(port_index)})) {
				return status::invalid_argument(
					"canonical driver configuration contains an unused driver port");
			}
		}
	}
	return status::ok();
}

status provider_topology_compiler::compile_execution_lanes_()
{
	auto count_or = compact_count(static_cast<std::size_t>(plan_.execution_lanes_size()), "execution_lanes[]");
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	if (count_or.value() == 0u) {
		return status::invalid_argument("provider topology requires at least one execution lane");
	}
	out_.execution_lanes.resize(count_or.value());
	plan_lane_by_index_.resize(count_or.value(), nullptr);
	std::vector<bool> seen_lane_indices(count_or.value(), false);
	for (const auto &lane : plan_.execution_lanes()) {
		if (lane.lane_index() >= count_or.value() || seen_lane_indices[lane.lane_index()] ||
		    lane.lane_id() != common::execution_topology::make_lane_id(lane.lane_index()) ||
		    !lane_by_id_.emplace(lane.lane_id(), lane.lane_index()).second) {
			return status::invalid_argument(
				"execution_lanes[] require canonical identity and compact unique indices");
		}
		auto is_strictly_sorted = [](const auto &values) {
			return std::adjacent_find(values.begin(), values.end(), [](const auto &lhs, const auto &rhs) {
				       return lhs >= rhs;
			       }) == values.end();
		};
		if (!is_strictly_sorted(lane.stage_instance_ids()) || !is_strictly_sorted(lane.io_stream_ids())) {
			return status::invalid_argument(
				"execution-lane membership arrays must be strictly sorted and unique");
		}
		seen_lane_indices[lane.lane_index()] = true;
		plan_lane_by_index_[lane.lane_index()] = &lane;
		auto &compiled = out_.execution_lanes[lane.lane_index()];
		compiled.lane_id = lane.lane_id();
		compiled.lane_index = lane.lane_index();
		compiled.stage_instance_indices.assign(out_.logical_stages.size(),
						       INVALID_COMPILED_STAGE_INSTANCE_INDEX);
	}
	if (std::any_of(plan_lane_by_index_.begin(), plan_lane_by_index_.end(),
			[](const auto *lane) { return lane == nullptr; })) {
		return status::invalid_argument("execution_lanes[] omit one compact lane index");
	}
	return status::ok();
}

status provider_topology_compiler::compile_stage_instances_()
{
	auto count_or = compact_count(static_cast<std::size_t>(plan_.stage_instances_size()), "stage_instances[]");
	if (!count_or.is_ok()) {
		return count_or.error();
	}
	if (static_cast<std::size_t>(count_or.value()) > MAX_COMPILED_STAGE_INSTANCES) {
		return status(status_code::OUT_OF_RANGE,
			      "stage_instances[] exceeds the compact packet-stage namespace");
	}
	const uint64_t expected_stage_instances =
		static_cast<uint64_t>(out_.logical_stages.size()) * out_.execution_lanes.size();
	if (expected_stage_instances != count_or.value()) {
		return status::invalid_argument(
			"stage_instances[] must contain the exact logical-stage by execution-lane product");
	}
	for (const auto &worker : out_.transition_topology.workers) {
		if (worker.cpu_core_ids.size() != 1u) {
			return status::invalid_argument("each packet worker requires exactly one dedicated CPU core");
		}
	}

	std::vector<std::pair<const kinetum::gluon::v1::StageInstance *, uint32_t>> sorted;
	sorted.reserve(count_or.value());
	for (int index = 0; index < plan_.stage_instances_size(); ++index) {
		sorted.emplace_back(&plan_.stage_instances(index), static_cast<uint32_t>(index));
	}
	std::sort(sorted.begin(), sorted.end(), [](const auto &lhs, const auto &rhs) {
		return lhs.first->stage_instance_id() < rhs.first->stage_instance_id();
	});
	plan_stage_to_compiled_.assign(sorted.size(), INVALID_COMPILED_PROVIDER_INDEX);
	out_.stage_instances.reserve(sorted.size());
	for (const auto &[instance, plan_index] : sorted) {
		const auto logical_it = logical_stage_by_id_.find(instance->logical_stage_id());
		const auto lane_it = lane_by_id_.find(instance->lane_id());
		if (logical_it == logical_stage_by_id_.end() || lane_it == lane_by_id_.end()) {
			return status::invalid_argument("stage instance references an unknown logical stage or lane");
		}
		const auto region_it = region_by_logical_stage_.find(instance->logical_stage_id());
		const auto execution_it = execution_by_id_.find(instance->execution_provider_instance_id());
		const auto worker_it = worker_by_owner_.find({instance->region_id(), instance->lane_id()});
		if (region_it == region_by_logical_stage_.end() || execution_it == execution_by_id_.end() ||
		    worker_it == worker_by_owner_.end()) {
			return status::invalid_argument(
				"stage instance '" + instance->stage_instance_id() +
				"' lacks exact region, execution-provider, or worker ownership");
		}
		const auto expected_id = common::execution_topology::make_stage_instance_id(
			instance->logical_stage_id(), instance->lane_id());
		if (instance->stage_instance_id() != expected_id ||
		    instance->region_id() != static_cast<int32_t>(region_it->second) ||
		    instance->replica_index() != lane_it->second) {
			return status::invalid_argument(
				"stage instance has noncanonical identity, region, or replica ownership");
		}
		if (stage_by_id_.contains(instance->stage_instance_id()) ||
		    stage_by_logical_lane_.contains({instance->logical_stage_id(), instance->lane_id()})) {
			return status::invalid_argument("stage_instances[] contains duplicate executable identity");
		}
		const uint32_t index = static_cast<uint32_t>(out_.stage_instances.size());
		stage_by_id_.emplace(instance->stage_instance_id(), index);
		stage_by_logical_lane_.emplace(stage_lane_key{instance->logical_stage_id(), instance->lane_id()},
					       index);
		plan_stage_to_compiled_[plan_index] = index;
		++execution_use_counts_[execution_it->second];

		auto &logical = out_.logical_stages[logical_it->second];
		const bool active = logical.execution_mode == compiled_stage_execution_mode::ACTIVE;
		const bool has_active_origin = !instance->active_origin_storage_domain_id().empty();
		if (active != has_active_origin) {
			return status::invalid_argument(
				active ? "active stage instance requires one exact origin storage domain" :
					 "passive stage instance must not carry an origin storage domain");
		}
		std::optional<uint32_t> active_origin_storage_domain_index;
		if (has_active_origin) {
			const auto storage_it = storage_by_id_.find(instance->active_origin_storage_domain_id());
			if (storage_it == storage_by_id_.end()) {
				return status::invalid_argument(
					"active stage instance references an unknown origin storage domain");
			}
			const auto &storage = out_.storage_domains[storage_it->second];
			const auto &execution = out_.execution_providers[execution_it->second];
			if (!packet_storage_supports_execution(storage.capabilities, execution.capabilities)) {
				return status::invalid_argument(
					"active-origin storage domain lacks the execution provider's exact access shape");
			}
			const auto &worker = out_.transition_topology.workers[worker_it->second];
			if (storage.host_numa_node.has_value() && storage.host_numa_node.value() != worker.numa_node) {
				return status::invalid_argument(
					"active-origin storage domain disagrees with the owner worker's host NUMA node");
			}
			active_origin_storage_domain_index = storage_it->second;
		}
		std::optional<uint32_t> module_context_index;
		if (logical.kind == compiled_stage_kind::MODULE) {
			if (instance->context_instance_id() != instance->stage_instance_id() ||
			    !kinetum::sdk::valid_module_abi_text(instance->context_instance_id()) ||
			    instance->context_memory_capacity_bytes() == 0u ||
			    instance->epoch_arena_capacity_bytes() == 0u) {
				return status::invalid_argument(
					"module stage instance lacks exact per-instance context ownership or memory capacity");
			}
			if (instance->context_memory_capacity_bytes() >
				    static_cast<uint64_t>(std::numeric_limits<std::size_t>::max()) ||
			    instance->epoch_arena_capacity_bytes() >
				    static_cast<uint64_t>(std::numeric_limits<std::size_t>::max())) {
				return status(status_code::OUT_OF_RANGE,
					      "module stage instance memory capacity exceeds runtime size_t");
			}
			module_context_index = static_cast<uint32_t>(out_.module_contexts.size());
			out_.module_contexts.push_back({
				.context_instance_id = instance->context_instance_id(),
				.module_context_index = module_context_index.value(),
				.stage_instance_index = index,
				.logical_stage_index = logical_it->second,
				.worker_index = worker_it->second,
				.cpu_core_id = out_.transition_topology.workers[worker_it->second].cpu_core_ids.front(),
				.region_id = instance->region_id(),
				.numa_node = out_.execution_regions[region_it->second].numa_node,
				.module_id = logical.module_id,
				.context_memory_capacity_bytes = instance->context_memory_capacity_bytes(),
				.epoch_arena_capacity_bytes = instance->epoch_arena_capacity_bytes(),
			});
		} else if (!instance->context_instance_id().empty() ||
			   instance->context_memory_capacity_bytes() != 0u ||
			   instance->epoch_arena_capacity_bytes() != 0u) {
			return status::invalid_argument(
				"platform stage instance must not declare mutable module context ownership or memory capacity");
		}

		compiled_provider_stage_instance compiled;
		compiled.stage_instance_id = instance->stage_instance_id();
		compiled.stage_instance_index = index;
		compiled.logical_stage_id = instance->logical_stage_id();
		compiled.logical_stage_index = logical_it->second;
		compiled.lane_index = lane_it->second;
		compiled.region_index = region_it->second;
		compiled.replica_index = instance->replica_index();
		compiled.worker_index = worker_it->second;
		compiled.execution_provider_index = execution_it->second;
		compiled.module_context_index = module_context_index;
		compiled.active_origin_storage_domain_index = active_origin_storage_domain_index;
		out_.stage_instances.push_back(std::move(compiled));
		logical.stage_instance_indices.push_back(index);
		out_.execution_regions[region_it->second].stage_instance_indices.push_back(index);
		auto &lane_stage_index =
			out_.execution_lanes[lane_it->second].stage_instance_indices[logical_it->second];
		if (lane_stage_index != INVALID_COMPILED_STAGE_INSTANCE_INDEX) {
			return status::internal_error(
				"execution-lane logical-stage table received duplicate ownership");
		}
		lane_stage_index = static_cast<uint16_t>(index);
	}

	for (const auto &logical : out_.logical_stages) {
		if (logical.stage_instance_indices.size() != out_.execution_lanes.size()) {
			return status::invalid_argument(
				"logical stage does not have one exact instance in every execution lane");
		}
	}
	for (const auto &lane : out_.execution_lanes) {
		std::vector<std::string> actual_ids;
		actual_ids.reserve(lane.stage_instance_indices.size());
		for (const uint16_t stage_index : lane.stage_instance_indices) {
			if (stage_index == INVALID_COMPILED_STAGE_INSTANCE_INDEX) {
				return status::internal_error(
					"execution-lane direct logical-stage table is incomplete");
			}
			actual_ids.push_back(out_.stage_instances[stage_index].stage_instance_id);
		}
		std::sort(actual_ids.begin(), actual_ids.end());
		const auto *declared = plan_lane_by_index_[lane.lane_index];
		if (!std::equal(actual_ids.begin(), actual_ids.end(), declared->stage_instance_ids().begin(),
				declared->stage_instance_ids().end()) ||
		    actual_ids.size() != static_cast<std::size_t>(declared->stage_instance_ids_size())) {
			return status::invalid_argument(
				"execution-lane stage membership is not exact and two-directional");
		}
	}
	std::set<int32_t> module_context_numa_nodes;
	for (const auto &context : out_.module_contexts) {
		module_context_numa_nodes.insert(context.numa_node);
	}
	if (std::vector<int32_t>(module_context_numa_nodes.begin(), module_context_numa_nodes.end()) !=
	    out_.transition_topology.module_context_numa_nodes) {
		return status::internal_error("module-context NUMA ownership disagrees between compiler phases");
	}
	return status::ok();
}

status provider_topology_compiler::compile_module_context_domains_()
{
	std::map<std::string, std::vector<uint32_t>> contexts_by_module;
	for (const auto &context : out_.module_contexts) {
		contexts_by_module[context.module_id].push_back(context.module_context_index);
	}
	if (static_cast<std::size_t>(plan_.module_context_domains_size()) != contexts_by_module.size()) {
		return status::invalid_argument("module context domains do not cover the exact configured module set");
	}
	out_.module_context_domains.reserve(contexts_by_module.size());
	int domain_index = 0;
	for (auto &[module_id, indices] : contexts_by_module) {
		std::sort(indices.begin(), indices.end(), [&](uint32_t lhs, uint32_t rhs) {
			return out_.module_contexts[lhs].context_instance_id <
			       out_.module_contexts[rhs].context_instance_id;
		});
		const auto &declared = plan_.module_context_domains(domain_index++);
		if (declared.module_id() != module_id ||
		    static_cast<std::size_t>(declared.context_instance_ids_size()) != indices.size()) {
			return status::invalid_argument(
				"module context domains require exact sorted module and context membership");
		}
		auto count_or = compact_count(indices.size(), "module context population");
		if (!count_or.is_ok()) {
			return count_or.error();
		}
		for (uint32_t ordinal = 0u; ordinal < count_or.value(); ++ordinal) {
			auto &context = out_.module_contexts[indices[ordinal]];
			if (declared.context_instance_ids(static_cast<int>(ordinal)) != context.context_instance_id) {
				return status::invalid_argument(
					"module context ordinal disagrees with canonical domain membership");
			}
			context.module_context_ordinal = ordinal;
			context.module_context_count = count_or.value();
		}
		out_.module_context_domains.push_back({module_id, std::move(indices)});
	}
	return status::ok();
}

status provider_topology_compiler::compile_module_memory_budgets_()
{
	const auto &numa_nodes = out_.transition_topology.module_context_numa_nodes;
	std::vector<compiled_module_memory_budget> budgets;
	budgets.reserve(numa_nodes.size());
	for (const int32_t numa_node : numa_nodes) {
		budgets.emplace_back();
		budgets.back().numa_node = numa_node;
	}
	for (const auto &context : out_.module_contexts) {
		const auto numa_it = std::lower_bound(numa_nodes.begin(), numa_nodes.end(), context.numa_node);
		if (numa_it == numa_nodes.end() || *numa_it != context.numa_node) {
			return status::internal_error("module context references an uncompiled NUMA memory budget");
		}
		auto &budget = budgets[static_cast<std::size_t>(numa_it - numa_nodes.begin())];
		if (budget.context_count == std::numeric_limits<uint32_t>::max()) {
			return status(status_code::OUT_OF_RANGE,
				      "module context count exceeds the compiled NUMA budget range");
		}
		++budget.context_count;
		auto add_status = add_count_checked(budget.context_memory_capacity_bytes,
						    context.context_memory_capacity_bytes,
						    "module context-lifetime memory");
		if (!add_status.is_ok()) {
			return add_status;
		}
		add_status = add_count_checked(budget.epoch_arena_capacity_bytes, context.epoch_arena_capacity_bytes,
					       "module per-epoch arena memory");
		if (!add_status.is_ok()) {
			return add_status;
		}
	}

	for (auto &budget : budgets) {
		auto epoch_slots_or = multiply_count_checked(budget.epoch_arena_capacity_bytes,
							     static_cast<uint64_t>(common::EXACT_EPOCH_SLOT_COUNT),
							     "module epoch-slot memory");
		if (!epoch_slots_or.is_ok()) {
			return epoch_slots_or.error();
		}
		budget.complete_memory_capacity_bytes = budget.context_memory_capacity_bytes;
		auto add_status = add_count_checked(budget.complete_memory_capacity_bytes, epoch_slots_or.value(),
						    "complete module lifecycle memory");
		if (!add_status.is_ok()) {
			return add_status;
		}
		if (budget.complete_memory_capacity_bytes >
		    static_cast<uint64_t>(std::numeric_limits<std::size_t>::max())) {
			return status(status_code::OUT_OF_RANGE,
				      "complete module lifecycle memory exceeds runtime size_t");
		}
	}
	out_.module_memory_budgets = std::move(budgets);
	return status::ok();
}

status provider_topology_compiler::compile_io_streams_()
{
	auto count_or = compact_count(static_cast<std::size_t>(plan_.io_streams_size()), "io_streams[]");
	if (!count_or.is_ok()) {
		return count_or.error();
	}

	std::vector<std::pair<const kinetum::gluon::v1::IoStream *, uint32_t>> sorted;
	sorted.reserve(count_or.value());
	std::set<std::string> declared_stream_ids;
	for (int index = 0; index < plan_.io_streams_size(); ++index) {
		if (!declared_stream_ids.insert(plan_.io_streams(index).io_stream_id()).second) {
			return status::invalid_argument("io_streams[] contains duplicate identity");
		}
		sorted.emplace_back(&plan_.io_streams(index), static_cast<uint32_t>(index));
	}
	std::sort(sorted.begin(), sorted.end(), [](const auto &lhs, const auto &rhs) {
		return lhs.first->io_stream_id() < rhs.first->io_stream_id();
	});
	plan_stream_to_compiled_.assign(sorted.size(), INVALID_COMPILED_PROVIDER_INDEX);
	stream_steering_ids_.reserve(sorted.size());
	std::set<queue_owner_key> queue_owners;
	std::map<queue_group_key, std::vector<uint32_t>> queue_ids_by_owner;
	std::vector<std::array<uint32_t, 2>> stream_counts_by_port(out_.ports.size());
	std::vector<uint32_t> stream_counts_by_stage(out_.stage_instances.size(), 0u);
	out_.io_streams.reserve(sorted.size());
	for (const auto &[stream, plan_index] : sorted) {
		const auto port_it = port_by_logical_id_.find(stream->logical_port_id());
		const auto stage_it = stage_by_id_.find(stream->stage_instance_id());
		const auto worker_it = worker_by_id_.find(stream->owning_worker_id());
		if (port_it == port_by_logical_id_.end() || stage_it == stage_by_id_.end() ||
		    worker_it == worker_by_id_.end()) {
			return status::invalid_argument("I/O stream '" + stream->io_stream_id() +
							"' has an unknown port, stage, or worker reference");
		}
		const auto &port = out_.ports[port_it->second];
		auto &stage = out_.stage_instances[stage_it->second];
		const auto &worker = out_.transition_topology.workers[worker_it->second];
		const auto lane_it = lane_by_id_.find(stream->lane_id());
		if (stage.worker_index != worker_it->second || stream->descriptor_count() == 0 ||
		    lane_it == lane_by_id_.end() || stage.lane_index != lane_it->second ||
		    worker.lane_id != stream->lane_id()) {
			return status::invalid_argument(
				"I/O stream '" + stream->io_stream_id() +
				"' disagrees with its lane/stage/worker ownership or has zero descriptors");
		}

		compiled_io_stream_direction direction;
		compiled_stage_kind required_stage_kind;
		std::string_view direction_suffix;
		switch (stream->direction()) {
		case kinetum::gluon::v1::IO_STREAM_DIRECTION_RX:
			direction = compiled_io_stream_direction::RX;
			required_stage_kind = compiled_stage_kind::RX;
			direction_suffix = "rx";
			if (port.direction == compiled_io_port_direction::TX_ONLY) {
				return status::invalid_argument("RX stream is bound to a TX-only logical port");
			}
			break;
		case kinetum::gluon::v1::IO_STREAM_DIRECTION_TX:
			direction = compiled_io_stream_direction::TX;
			required_stage_kind = compiled_stage_kind::TX;
			direction_suffix = "tx";
			if (port.direction == compiled_io_port_direction::RX_ONLY) {
				return status::invalid_argument("TX stream is bound to an RX-only logical port");
			}
			break;
		case kinetum::gluon::v1::IO_STREAM_DIRECTION_UNSPECIFIED:
		case kinetum::gluon::v1::IoStreamDirection_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::gluon::v1::IoStreamDirection_INT_MAX_SENTINEL_DO_NOT_USE_:
			return status::invalid_argument("I/O stream has unspecified direction");
		}
		if (out_.logical_stages[stage.logical_stage_index].kind != required_stage_kind) {
			return status::invalid_argument("I/O stream direction disagrees with its attached stage kind");
		}
		if (logical_stage_io_port_names_[stage.logical_stage_index] != port.logical_name) {
			return status::invalid_argument(
				"I/O stream port disagrees with its logical stage interface binding");
		}
		if (direction == compiled_io_stream_direction::TX && !stream->steering_profile_id().empty()) {
			return status::invalid_argument("TX I/O stream must not carry a receive-steering profile");
		}
		const auto expected_stream_id = common::execution_topology::make_io_stream_id(
			port.logical_name, direction_suffix, stream->lane_id());
		if (stream->io_stream_id() != expected_stream_id) {
			return status::invalid_argument("I/O stream has a noncanonical executable identity");
		}
		const auto &driver = out_.io_drivers[port.io_driver_index];
		if (stream->driver_queue_id() > driver.capabilities.maximum_driver_queue_id ||
		    stream->descriptor_count() > driver.capabilities.maximum_descriptor_count) {
			return status::invalid_argument("I/O stream '" + stream->io_stream_id() +
							"' exceeds its driver contract's queue or descriptor range");
		}
		const auto required_direction = direction == compiled_io_stream_direction::RX ? io_direction::RX :
												io_direction::TX;
		if ((driver.capabilities.directions & static_cast<io_direction_mask>(required_direction)) == 0u) {
			return status::invalid_argument("I/O-driver contract does not support the stream direction");
		}
		std::vector<uint32_t> storage_indices;
		if (direction == compiled_io_stream_direction::RX) {
			if (!stream->has_rx_storage_domain_id()) {
				return status::invalid_argument("RX stream requires its exact allocation domain");
			}
			const auto found = storage_by_id_.find(stream->rx_storage_domain_id());
			if (found == storage_by_id_.end()) {
				return status::invalid_argument("RX stream references an unknown storage domain");
			}
			storage_indices.push_back(found->second);
		} else {
			if (!stream->has_tx_storage() || stream->tx_storage().storage_domain_ids().empty()) {
				return status::invalid_argument("TX stream requires a nonempty storage admission set");
			}
			storage_indices.reserve(
				static_cast<std::size_t>(stream->tx_storage().storage_domain_ids_size()));
			for (const auto &domain_id : stream->tx_storage().storage_domain_ids()) {
				const auto found = storage_by_id_.find(domain_id);
				if (found == storage_by_id_.end()) {
					return status::invalid_argument(
						"TX stream references an unknown storage domain");
				}
				storage_indices.push_back(found->second);
			}
			std::sort(storage_indices.begin(), storage_indices.end());
			if (std::adjacent_find(storage_indices.begin(), storage_indices.end()) !=
			    storage_indices.end()) {
				return status::invalid_argument(
					"TX stream storage admission contains a duplicate domain");
			}
		}
		std::vector<io_storage_candidate> storage_candidates;
		storage_candidates.reserve(storage_indices.size());
		for (const uint32_t storage_index : storage_indices) {
			const auto &storage = out_.storage_domains[storage_index];
			const uint32_t payload_room = storage.data_room_bytes - storage.headroom_bytes;
			if (port.mtu > payload_room) {
				return status::invalid_argument(
					"I/O stream storage data room cannot hold its exact port MTU");
			}
			if (storage.host_numa_node.has_value() && storage.host_numa_node.value() != worker.numa_node) {
				return status::invalid_argument(
					"I/O stream worker and storage domain disagree on host NUMA ownership");
			}
			if (port.host_numa_node.has_value() &&
			    (!storage.host_numa_node.has_value() || port.host_numa_node.value() != worker.numa_node ||
			     port.host_numa_node.value() != storage.host_numa_node.value())) {
				return status::invalid_argument(
					"I/O stream port, storage domain, and worker NUMA facts disagree");
			}
			storage_candidates.push_back(
				{storage.configuration.type_url, storage.capabilities, storage.facility_indices});
		}
		if (const auto compatible = validate_io_storage_binding(
			    driver.capabilities, {required_direction, driver.facility_indices, storage_candidates});
		    !compatible.is_ok()) {
			return compatible;
		}
		const auto &native_port = driver.attachments[port.driver_port_index];
		if (native_port.kind == compiled_driver_attachment_kind::UDP_IPV4 && native_port.endpoint_port == 0) {
			return status::invalid_argument(
				"a materialized UDP stream requires a nonzero exact endpoint port");
		}
		const queue_owner_key queue_key{port.io_driver_index, port.driver_port_index, direction,
						stream->driver_queue_id()};
		if (!queue_owners.insert(queue_key).second) {
			return status::invalid_argument("two I/O streams claim the same driver queue and direction");
		}
		queue_ids_by_owner[{port.io_driver_index, port.driver_port_index, direction}].push_back(
			stream->driver_queue_id());
		const std::size_t direction_index = direction == compiled_io_stream_direction::RX ? 0u : 1u;
		++stream_counts_by_port[port.port_index][direction_index];
		++stream_counts_by_stage[stage.stage_instance_index];
		if (stage.io_stream_index.has_value()) {
			return status::invalid_argument(
				"one executable I/O stage instance is claimed by multiple streams");
		}
		const uint32_t index = static_cast<uint32_t>(out_.io_streams.size());
		stream_by_id_.emplace(stream->io_stream_id(), index);
		plan_stream_to_compiled_[plan_index] = index;
		stream_steering_ids_.push_back(stream->steering_profile_id());
		for (const uint32_t storage_index : storage_indices) {
			++storage_use_counts_[storage_index];
		}
		compiled_provider_io_stream compiled;
		compiled.io_stream_id = stream->io_stream_id();
		compiled.io_stream_index = index;
		compiled.port_index = port_it->second;
		compiled.lane_index = lane_it->second;
		compiled.direction = direction;
		compiled.stage_instance_index = stage_it->second;
		compiled.worker_index = worker_it->second;
		if (direction == compiled_io_stream_direction::RX) {
			compiled.rx_storage_domain_index = storage_indices.front();
		} else {
			compiled.tx_storage_domain_indices = std::move(storage_indices);
		}
		compiled.driver_queue_id = stream->driver_queue_id();
		compiled.descriptor_count = stream->descriptor_count();
		out_.io_streams.push_back(std::move(compiled));
		stage.io_stream_index = index;
		out_.execution_lanes[lane_it->second].io_stream_indices.push_back(index);
	}
	const uint32_t exact_streams_per_direction = static_cast<uint32_t>(out_.execution_lanes.size());
	for (const auto &port : out_.ports) {
		const uint32_t rx_count = stream_counts_by_port[port.port_index][0];
		const uint32_t tx_count = stream_counts_by_port[port.port_index][1];
		const bool requires_rx = port.direction != compiled_io_port_direction::TX_ONLY;
		const bool requires_tx = port.direction != compiled_io_port_direction::RX_ONLY;
		if ((requires_rx && rx_count != exact_streams_per_direction) || (!requires_rx && rx_count != 0u) ||
		    (requires_tx && tx_count != exact_streams_per_direction) || (!requires_tx && tx_count != 0u)) {
			return status::invalid_argument(
				"logical port stream coverage disagrees with its exact direction");
		}
	}
	for (const auto &stage : out_.stage_instances) {
		const auto kind = out_.logical_stages[stage.logical_stage_index].kind;
		const bool is_io_stage = kind == compiled_stage_kind::RX || kind == compiled_stage_kind::TX;
		if ((is_io_stage && stream_counts_by_stage[stage.stage_instance_index] != 1u) ||
		    (!is_io_stage && stream_counts_by_stage[stage.stage_instance_index] != 0u) ||
		    is_io_stage != stage.io_stream_index.has_value()) {
			return status::invalid_argument(
				"stage-instance and I/O-stream ownership is not exact and two-directional");
		}
	}
	for (auto &[owner, queue_ids] : queue_ids_by_owner) {
		const auto [driver_index, port_index, direction] = owner;
		(void)port_index;
		(void)direction;
		std::sort(queue_ids.begin(), queue_ids.end());
		if (!out_.io_drivers[driver_index].capabilities.dense_zero_based_queues) {
			continue;
		}
		for (std::size_t index = 0; index < queue_ids.size(); ++index) {
			if (queue_ids[index] != static_cast<uint32_t>(index)) {
				return status::invalid_argument(
					"driver queue IDs must form one dense zero-based range per port and direction");
			}
		}
	}
	for (const auto &lane : out_.execution_lanes) {
		std::vector<std::string> actual_ids;
		actual_ids.reserve(lane.io_stream_indices.size());
		for (const uint32_t stream_index : lane.io_stream_indices) {
			actual_ids.push_back(out_.io_streams[stream_index].io_stream_id);
		}
		const auto *declared = plan_lane_by_index_[lane.lane_index];
		if (!std::equal(actual_ids.begin(), actual_ids.end(), declared->io_stream_ids().begin(),
				declared->io_stream_ids().end()) ||
		    actual_ids.size() != static_cast<std::size_t>(declared->io_stream_ids_size())) {
			return status::invalid_argument(
				"execution-lane I/O-stream membership is not exact and two-directional");
		}
	}
	return status::ok();
}

status provider_topology_compiler::remap_transition_topology_()
{
	if (std::any_of(plan_stage_to_compiled_.begin(), plan_stage_to_compiled_.end(),
			[](uint32_t index) { return index == INVALID_COMPILED_PROVIDER_INDEX; }) ||
	    std::any_of(plan_stream_to_compiled_.begin(), plan_stream_to_compiled_.end(),
			[](uint32_t index) { return index == INVALID_COMPILED_PROVIDER_INDEX; })) {
		return status::internal_error("provider compiler index remap is incomplete");
	}

	auto remap_indices = [](std::vector<uint32_t> &indices, const std::vector<uint32_t> &mapping,
				const char *identity) -> status {
		for (uint32_t &index : indices) {
			if (index >= mapping.size()) {
				return status::internal_error(std::string(identity) +
							      " contains an out-of-range plan-order index");
			}
			index = mapping[index];
		}
		std::sort(indices.begin(), indices.end());
		if (std::adjacent_find(indices.begin(), indices.end()) != indices.end()) {
			return status::internal_error(std::string(identity) + " contains duplicate compact ownership");
		}
		return status::ok();
	};

	for (auto &worker : out_.transition_topology.workers) {
		if (const auto remap_status = remap_indices(worker.stage_instance_indices, plan_stage_to_compiled_,
							    "transition worker stage set");
		    !remap_status.is_ok()) {
			return remap_status;
		}
		if (const auto remap_status = remap_indices(worker.io_stream_indices, plan_stream_to_compiled_,
							    "transition worker stream set");
		    !remap_status.is_ok()) {
			return remap_status;
		}

		bool is_source = false;
		bool is_sink = false;
		bool owns_module_context = false;
		for (const uint32_t stage_index : worker.stage_instance_indices) {
			const auto &stage = out_.stage_instances[stage_index];
			if (stage.worker_index != worker.worker_index) {
				return status::internal_error(
					"transition worker stage ownership disagrees after compact remap");
			}
			const auto kind = out_.logical_stages[stage.logical_stage_index].kind;
			is_source = is_source || kind == compiled_stage_kind::RX ||
				    stage.active_origin_storage_domain_index.has_value();
			is_sink = is_sink || kind == compiled_stage_kind::TX;
			owns_module_context = owns_module_context || stage.module_context_index.has_value();
		}
		for (const uint32_t stream_index : worker.io_stream_indices) {
			if (out_.io_streams[stream_index].worker_index != worker.worker_index) {
				return status::internal_error(
					"transition worker stream ownership disagrees after compact remap");
			}
		}
		if (worker.is_source != is_source || worker.is_sink != is_sink ||
		    worker.owns_module_context != owns_module_context) {
			return status::internal_error(
				"transition worker role facts disagree with compiled stage semantics");
		}
	}

	for (auto &boundary : out_.transition_topology.boundaries) {
		if (boundary.from_stage_instance_index >= plan_stage_to_compiled_.size() ||
		    boundary.to_stage_instance_index >= plan_stage_to_compiled_.size()) {
			return status::internal_error("transition boundary contains an out-of-range plan stage index");
		}
		boundary.from_stage_instance_index = plan_stage_to_compiled_[boundary.from_stage_instance_index];
		boundary.to_stage_instance_index = plan_stage_to_compiled_[boundary.to_stage_instance_index];
		if (out_.stage_instances[boundary.from_stage_instance_index].worker_index !=
			    boundary.sender_worker_index ||
		    out_.stage_instances[boundary.to_stage_instance_index].worker_index !=
			    boundary.receiver_worker_index) {
			return status::internal_error(
				"transition boundary worker ownership disagrees after compact remap");
		}
	}

	out_.transition_topology.boundaries_by_source_stage_instance.assign(out_.stage_instances.size(), {});
	for (const auto &boundary : out_.transition_topology.boundaries) {
		out_.transition_topology.boundaries_by_source_stage_instance[boundary.from_stage_instance_index]
			.push_back(common::compiled_transition_edge{boundary.to_stage_instance_index,
								    boundary.boundary_index});
	}
	for (auto &edges : out_.transition_topology.boundaries_by_source_stage_instance) {
		std::sort(edges.begin(), edges.end(), [](const auto &lhs, const auto &rhs) {
			return std::tie(lhs.to_stage_instance_index, lhs.boundary_index) <
			       std::tie(rhs.to_stage_instance_index, rhs.boundary_index);
		});
	}
	return status::ok();
}

status provider_topology_compiler::compile_stage_routes_and_controls_()
{
	auto edge_count_or = compact_count(static_cast<std::size_t>(plan_.pipeline().edges_size()), "pipeline edges");
	if (!edge_count_or.is_ok()) {
		return edge_count_or.error();
	}
	std::vector<bool> has_conditional_route(out_.stage_instances.size(), false);
	std::vector<bool> has_outbound_pull(out_.logical_stages.size(), false);
	std::vector<bool> has_inbound_control(out_.logical_stages.size(), false);
	std::set<std::pair<uint16_t, uint16_t>> logical_pull_edges;
	for (int authored_index = 0; authored_index < plan_.pipeline().edges_size(); ++authored_index) {
		const auto &edge = plan_.pipeline().edges(authored_index);
		const auto source_logical_it = logical_stage_by_id_.find(edge.from_stage_id());
		const auto destination_logical_it = logical_stage_by_id_.find(edge.to_stage_id());
		if (source_logical_it == logical_stage_by_id_.end() ||
		    destination_logical_it == logical_stage_by_id_.end()) {
			return status::internal_error("verified pipeline edge lost its logical-stage endpoint");
		}
		auto condition_or = common::compile_packet_route_condition(edge.condition());
		if (!condition_or.is_ok()) {
			return condition_or.error();
		}
		const auto condition = std::move(condition_or).value();
		compiled_packet_edge_mode mode;
		switch (edge.mode()) {
		case kinetum::axiom::v1::EDGE_MODE_PUSH:
			mode = compiled_packet_edge_mode::PUSH;
			break;
		case kinetum::axiom::v1::EDGE_MODE_PULL:
			mode = compiled_packet_edge_mode::PULL;
			if (!logical_pull_edges.emplace(source_logical_it->second, destination_logical_it->second)
				     .second) {
				return status::invalid_argument(
					"pipeline contains competing PULL edges for one exact endpoint pair");
			}
			break;
		case kinetum::axiom::v1::EDGE_MODE_UNSPECIFIED:
		case kinetum::axiom::v1::EdgeMode_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::axiom::v1::EdgeMode_INT_MAX_SENTINEL_DO_NOT_USE_:
			return status::invalid_argument("packet edge has an unsupported work-driving mode");
		}

		for (const auto &lane : out_.execution_lanes) {
			const uint16_t source_index = lane.stage_instance_indices[source_logical_it->second];
			const uint16_t destination_index = lane.stage_instance_indices[destination_logical_it->second];
			auto &source = out_.stage_instances[source_index];
			auto &destination = out_.stage_instances[destination_index];
			if (mode == compiled_packet_edge_mode::PULL) {
				const auto &source_logical = out_.logical_stages[source.logical_stage_index];
				const auto &destination_logical = out_.logical_stages[destination.logical_stage_index];
				if (source_logical.execution_mode != compiled_stage_execution_mode::ACTIVE ||
				    destination_logical.execution_mode != compiled_stage_execution_mode::ACTIVE ||
				    (source_logical.trigger_mask &
				     static_cast<uint32_t>(compiled_active_stage_trigger::PULL_READY)) == 0u ||
				    source.region_index != destination.region_index ||
				    source.worker_index != destination.worker_index) {
					return status::invalid_argument(
						"PULL edge requires active endpoints, a PULL_READY source, and one owner worker");
				}
				has_outbound_pull[source.logical_stage_index] = true;
				destination.pull_source_stage_instance_indices.push_back(source_index);
			}
			std::vector<uint16_t> destinations;
			const auto &destination_logical = out_.logical_stages[destination.logical_stage_index];
			if (mode == compiled_packet_edge_mode::PUSH &&
			    destination_logical.context_selection == compiled_module_context_selection::MODULE) {
				destinations.reserve(destination_logical.stage_instance_indices.size());
				for (const uint32_t instance_index : destination_logical.stage_instance_indices) {
					destinations.push_back(static_cast<uint16_t>(instance_index));
				}
			} else {
				destinations.push_back(destination_index);
			}
			source.packet_routes.push_back(
				compiled_stage_route{std::move(destinations), condition, edge.priority(),
						     static_cast<uint32_t>(authored_index), mode});
			has_conditional_route[source_index] = has_conditional_route[source_index] ||
							      !condition.is_unconditional() ||
							      mode == compiled_packet_edge_mode::PULL;
		}
	}

	for (const auto &logical : out_.logical_stages) {
		const bool declares_pull =
			(logical.trigger_mask & static_cast<uint32_t>(compiled_active_stage_trigger::PULL_READY)) != 0u;
		if (declares_pull != has_outbound_pull[logical.logical_stage_index]) {
			return status::invalid_argument(
				"PULL_READY trigger and outbound PULL-edge ownership are not exact");
		}
	}
	for (auto &stage : out_.stage_instances) {
		if (stage.packet_routes.empty()) {
			stage.dispatch_mode = compiled_stage_dispatch_mode::TERMINAL;
		} else if (has_conditional_route[stage.stage_instance_index]) {
			stage.dispatch_mode = compiled_stage_dispatch_mode::PRIORITY_ROUTE;
			std::sort(stage.packet_routes.begin(), stage.packet_routes.end(),
				  [](const auto &lhs, const auto &rhs) {
					  if (lhs.priority != rhs.priority) {
						  return lhs.priority > rhs.priority;
					  }
					  return lhs.authored_edge_index < rhs.authored_edge_index;
				  });
		} else {
			stage.dispatch_mode = compiled_stage_dispatch_mode::UNCONDITIONAL_FANOUT;
		}
		std::sort(stage.pull_source_stage_instance_indices.begin(),
			  stage.pull_source_stage_instance_indices.end());
		stage.pull_source_stage_instance_indices.erase(
			std::unique(stage.pull_source_stage_instance_indices.begin(),
				    stage.pull_source_stage_instance_indices.end()),
			stage.pull_source_stage_instance_indices.end());
	}

	uint64_t expanded_control_edge_count = 0;
	if (const auto count_status = add_count_checked(expanded_control_edge_count,
							static_cast<uint64_t>(plan_.pipeline().control_edges_size()) *
								out_.execution_lanes.size(),
							"lane-expanded control edges");
	    !count_status.is_ok()) {
		return count_status;
	}
	if (expanded_control_edge_count > std::numeric_limits<uint32_t>::max()) {
		return status(status_code::OUT_OF_RANGE, "lane-expanded control edges exceed compact index range");
	}
	out_.control_edges.reserve(static_cast<std::size_t>(expanded_control_edge_count));
	std::set<std::pair<uint16_t, uint16_t>> logical_control_edges;
	for (int authored_index = 0; authored_index < plan_.pipeline().control_edges_size(); ++authored_index) {
		const auto &edge = plan_.pipeline().control_edges(authored_index);
		const auto source_logical_it = logical_stage_by_id_.find(edge.from_stage_id());
		const auto destination_logical_it = logical_stage_by_id_.find(edge.to_stage_id());
		if (source_logical_it == logical_stage_by_id_.end() ||
		    destination_logical_it == logical_stage_by_id_.end()) {
			return status::internal_error("verified control edge lost its logical-stage endpoint");
		}
		compiled_control_edge_subtype subtype;
		switch (edge.subtype()) {
		case kinetum::axiom::v1::CONTROL_EDGE_GENERIC:
			subtype = compiled_control_edge_subtype::GENERIC;
			break;
		case kinetum::axiom::v1::CONTROL_EDGE_FEEDBACK:
			subtype = compiled_control_edge_subtype::FEEDBACK;
			break;
		case kinetum::axiom::v1::CONTROL_EDGE_SUBTYPE_UNSPECIFIED:
		case kinetum::axiom::v1::ControlEdgeSubtype_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::axiom::v1::ControlEdgeSubtype_INT_MAX_SENTINEL_DO_NOT_USE_:
			return status::invalid_argument("control edge has an unsupported subtype");
		}
		if (!logical_control_edges.emplace(source_logical_it->second, destination_logical_it->second).second) {
			return status::invalid_argument(
				"pipeline contains competing control edges for one exact endpoint pair");
		}

		for (const auto &lane : out_.execution_lanes) {
			const uint32_t source_index = lane.stage_instance_indices[source_logical_it->second];
			const uint32_t destination_index = lane.stage_instance_indices[destination_logical_it->second];
			const auto &source = out_.stage_instances[source_index];
			const auto &destination = out_.stage_instances[destination_index];
			const auto &source_logical = out_.logical_stages[source.logical_stage_index];
			const auto &destination_logical = out_.logical_stages[destination.logical_stage_index];
			if (source.region_index != destination.region_index ||
			    source.worker_index != destination.worker_index ||
			    source_logical.execution_mode != compiled_stage_execution_mode::ACTIVE ||
			    destination_logical.execution_mode != compiled_stage_execution_mode::ACTIVE ||
			    (destination_logical.trigger_mask &
			     static_cast<uint32_t>(compiled_active_stage_trigger::CONTROL)) == 0u) {
				return status::invalid_argument(
					"control edge requires one same-worker CONTROL-triggered active destination");
			}
			const uint32_t control_index = static_cast<uint32_t>(out_.control_edges.size());
			out_.control_edges.push_back(
				compiled_control_edge{control_index, static_cast<uint32_t>(authored_index),
						      source_index, destination_index, source.worker_index, subtype});
			has_inbound_control[destination.logical_stage_index] = true;
		}
	}
	for (const auto &logical : out_.logical_stages) {
		const bool declares_control =
			(logical.trigger_mask & static_cast<uint32_t>(compiled_active_stage_trigger::CONTROL)) != 0u;
		if (declares_control != has_inbound_control[logical.logical_stage_index]) {
			return status::invalid_argument(
				"CONTROL trigger and inbound same-worker control-edge ownership are not exact");
		}
	}
	return status::ok();
}

status provider_topology_compiler::compile_steering_()
{
	auto steering_count_or = compact_count(static_cast<std::size_t>(plan_.traffic_steering_profiles_size()),
					       "traffic_steering_profiles[]");
	if (!steering_count_or.is_ok()) {
		return steering_count_or.error();
	}
	std::vector<const kinetum::gluon::v1::TrafficSteeringProfile *> sorted;
	sorted.reserve(steering_count_or.value());
	for (const auto &profile : plan_.traffic_steering_profiles()) {
		sorted.push_back(&profile);
	}
	std::sort(sorted.begin(), sorted.end(), [](const auto *lhs, const auto *rhs) {
		return lhs->steering_profile_id() < rhs->steering_profile_id();
	});
	std::vector<uint32_t> referenced_profile_counts(sorted.size(), 0u);
	out_.steering_profiles.reserve(sorted.size());
	for (const auto *profile : sorted) {
		if (const auto id_status = validate_graph_id(profile->steering_profile_id(), "steering_profile_id");
		    !id_status.is_ok()) {
			return id_status;
		}
		if (steering_by_id_.contains(profile->steering_profile_id())) {
			return status::invalid_argument("duplicate traffic-steering profile identity");
		}
		compiled_steering_kind kind;
		switch (profile->kind()) {
		case kinetum::gluon::v1::TRAFFIC_STEERING_KIND_NONE:
			kind = compiled_steering_kind::NONE;
			if (profile->symmetric() || !profile->hash_fields().empty() || !profile->hash_key().empty() ||
			    profile->stream_ids_size() != 1) {
				return status::invalid_argument("NONE steering requires one stream and no hash policy");
			}
			break;
		case kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS:
			kind = compiled_steering_kind::RSS;
			if (profile->hash_fields().empty() || profile->hash_key().empty() ||
			    profile->stream_ids_size() < 2) {
				return status::invalid_argument(
					"RSS steering requires fields, deterministic key, and multiple streams");
			}
			break;
		case kinetum::gluon::v1::TRAFFIC_STEERING_KIND_UNSPECIFIED:
		case kinetum::gluon::v1::TrafficSteeringKind_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::gluon::v1::TrafficSteeringKind_INT_MAX_SENTINEL_DO_NOT_USE_:
			return status::invalid_argument("traffic-steering profile has an unsupported kind");
		}
		std::set<std::string> fields;
		for (const auto &field : profile->hash_fields()) {
			if (!fields.insert(field).second) {
				return status::invalid_argument("traffic-steering hash_fields[] contains a duplicate");
			}
		}
		std::vector<uint32_t> streams;
		std::optional<std::string_view> previous_stream;
		for (const auto &stream_id : profile->stream_ids()) {
			if (previous_stream.has_value() && previous_stream.value() >= stream_id) {
				return status::invalid_argument(
					"traffic-steering stream_ids[] must be strictly sorted and unique");
			}
			previous_stream = stream_id;
			const auto stream_it = stream_by_id_.find(stream_id);
			if (stream_it == stream_by_id_.end()) {
				return status::invalid_argument(
					"traffic-steering profile references unknown I/O stream");
			}
			auto &stream = out_.io_streams[stream_it->second];
			if (stream.direction != compiled_io_stream_direction::RX) {
				return status::invalid_argument("traffic steering may govern receive streams only");
			}
			if (!streams.empty() && out_.io_streams[streams.front()].port_index != stream.port_index) {
				return status::invalid_argument(
					"one steering profile cannot span distinct logical ports");
			}
			streams.push_back(stream_it->second);
		}
		const auto &port = out_.ports[out_.io_streams[streams.front()].port_index];
		const auto &driver = out_.io_drivers[port.io_driver_index];
		const auto required_capability = kind == compiled_steering_kind::RSS ? steering_capability::RSS :
										       steering_capability::NONE;
		if ((driver.capabilities.steering & static_cast<steering_capability_mask>(required_capability)) == 0u) {
			return status::invalid_argument("I/O-driver contract cannot implement the steering profile");
		}
		if (kind == compiled_steering_kind::RSS) {
			if (profile->hash_fields_size() !=
				    static_cast<int>(driver.capabilities.rss_hash_fields.size()) ||
			    !std::equal(profile->hash_fields().begin(), profile->hash_fields().end(),
					driver.capabilities.rss_hash_fields.begin()) ||
			    profile->hash_key().size() > driver.capabilities.maximum_rss_key_bytes ||
			    (profile->symmetric() && !driver.capabilities.supports_symmetric_rss)) {
				return status::invalid_argument(
					"RSS field sequence, key size, or symmetry exceeds the exact driver contract");
			}
		}
		const uint32_t index = static_cast<uint32_t>(out_.steering_profiles.size());
		steering_by_id_.emplace(profile->steering_profile_id(), index);
		out_.steering_profiles.push_back(compiled_traffic_steering_profile{
			profile->steering_profile_id(), index, kind, profile->symmetric(),
			std::vector<std::string>(profile->hash_fields().begin(), profile->hash_fields().end()),
			profile->hash_key(), std::move(streams)});
	}

	std::map<uint32_t, std::vector<uint32_t>> rx_streams_by_port;
	for (auto &stream : out_.io_streams) {
		if (stream.direction == compiled_io_stream_direction::RX) {
			rx_streams_by_port[stream.port_index].push_back(stream.io_stream_index);
		}
		const auto &profile_id = stream_steering_ids_[stream.io_stream_index];
		if (profile_id.empty()) {
			continue;
		}
		const auto profile_it = steering_by_id_.find(profile_id);
		if (profile_it == steering_by_id_.end()) {
			return status::invalid_argument("I/O stream references unknown traffic-steering profile");
		}
		const auto &members = out_.steering_profiles[profile_it->second].io_stream_indices;
		if (!std::binary_search(members.begin(), members.end(), stream.io_stream_index)) {
			return status::invalid_argument("traffic-steering profile and stream references disagree");
		}
		stream.steering_profile_index = profile_it->second;
		++referenced_profile_counts[profile_it->second];
	}
	for (const auto &[port_index, streams] : rx_streams_by_port) {
		(void)port_index;
		std::optional<uint32_t> governing_profile;
		for (const uint32_t stream_index : streams) {
			const auto &stream = out_.io_streams[stream_index];
			if (!stream.steering_profile_index.has_value()) {
				return status::invalid_argument("every RX stream requires one exact steering profile");
			}
			const auto kind = out_.steering_profiles[stream.steering_profile_index.value()].kind;
			if ((streams.size() == 1u && kind != compiled_steering_kind::NONE) ||
			    (streams.size() > 1u && kind != compiled_steering_kind::RSS)) {
				return status::invalid_argument(
					"RX stream count disagrees with the exact NONE or RSS steering mechanism");
			}
			if (governing_profile.has_value() &&
			    governing_profile.value() != stream.steering_profile_index.value()) {
				return status::invalid_argument(
					"one logical RX port cannot have competing steering profiles");
			}
			governing_profile = stream.steering_profile_index;
		}
		if (!governing_profile.has_value() ||
		    out_.steering_profiles[governing_profile.value()].io_stream_indices != streams) {
			return status::invalid_argument("steering profile does not cover its logical RX port exactly");
		}
	}
	for (std::size_t index = 0; index < out_.steering_profiles.size(); ++index) {
		if (referenced_profile_counts[index] != out_.steering_profiles[index].io_stream_indices.size()) {
			return status::invalid_argument("traffic-steering profile coverage is not two-directional");
		}
	}

	return status::ok();
}

status provider_topology_compiler::build_packet_graph_()
{
	auto stream_count_or = compact_count(out_.io_streams.size(), "compiled I/O streams");
	auto stage_count_or = compact_count(out_.stage_instances.size(), "compiled stage instances");
	if (!stream_count_or.is_ok()) {
		return stream_count_or.error();
	}
	if (!stage_count_or.is_ok()) {
		return stage_count_or.error();
	}
	uint64_t node_count = stream_count_or.value();
	if (const auto add_status = add_count_checked(node_count, stage_count_or.value(), "packet-graph nodes");
	    !add_status.is_ok()) {
		return add_status;
	}
	if (node_count > std::numeric_limits<uint32_t>::max()) {
		return status(status_code::OUT_OF_RANGE, "packet graph exceeds compact endpoint index range");
	}
	const uint32_t stream_count = stream_count_or.value();
	outgoing_edge_indices_.resize(static_cast<std::size_t>(node_count));
	for (const auto &stream : out_.io_streams) {
		const uint32_t stream_node = stream.io_stream_index;
		const uint32_t stage_node = stream_count + stream.stage_instance_index;
		const auto edge = stream.direction == compiled_io_stream_direction::RX ?
					  std::make_pair(stream_node, stage_node) :
					  std::make_pair(stage_node, stream_node);
		if (!graph_edges_.insert(edge).second) {
			return status::invalid_argument("duplicate stream/stage packet edge");
		}
	}
	for (const auto &stage : out_.stage_instances) {
		const uint32_t source_node = stream_count + stage.stage_instance_index;
		for (const auto &route : stage.packet_routes) {
			for (const uint16_t destination : route.destination_stage_instance_indices) {
				// A route selects one candidate. Reachability proves every candidate;
				// duplicate authored branches still retain their dispatch multiplicity.
				graph_edges_.emplace(source_node, stream_count + destination);
			}
		}
	}
	auto edge_count_or = compact_count(graph_edges_.size(), "packet-graph edges");
	if (!edge_count_or.is_ok()) {
		return edge_count_or.error();
	}
	compiled_graph_edges_.reserve(edge_count_or.value());
	for (const auto &[from, to] : graph_edges_) {
		const uint32_t edge_index = static_cast<uint32_t>(compiled_graph_edges_.size());
		compiled_graph_edges_.push_back(graph_edge{to, {}});
		graph_edge_index_by_nodes_.emplace(std::make_pair(from, to), edge_index);
		outgoing_edge_indices_[from].push_back(edge_index);
	}
	return status::ok();
}

status_or<uint32_t>
provider_topology_compiler::resolve_endpoint_node_(const kinetum::gluon::v1::PacketPathEndpoint &endpoint) const
{
	switch (endpoint.endpoint_case()) {
	case kinetum::gluon::v1::PacketPathEndpoint::kIoStreamId: {
		const auto stream_it = stream_by_id_.find(endpoint.io_stream_id());
		if (stream_it == stream_by_id_.end()) {
			return status::invalid_argument("storage transition references unknown I/O-stream endpoint");
		}
		return stream_it->second;
	}
	case kinetum::gluon::v1::PacketPathEndpoint::kStageInstanceId: {
		const auto stage_it = stage_by_id_.find(endpoint.stage_instance_id());
		if (stage_it == stage_by_id_.end()) {
			return status::invalid_argument(
				"storage transition references unknown stage-instance endpoint");
		}
		return static_cast<uint32_t>(out_.io_streams.size()) + stage_it->second;
	}
	case kinetum::gluon::v1::PacketPathEndpoint::ENDPOINT_NOT_SET:
	default:
		return status::invalid_argument("storage transition has an unset packet-path endpoint");
	}
}

compiled_packet_path_endpoint provider_topology_compiler::public_endpoint_(uint32_t node) const noexcept
{
	const uint32_t stream_count = static_cast<uint32_t>(out_.io_streams.size());
	if (node < stream_count) {
		return compiled_packet_path_endpoint{compiled_packet_path_endpoint_kind::IO_STREAM, node};
	}
	return compiled_packet_path_endpoint{compiled_packet_path_endpoint_kind::STAGE_INSTANCE, node - stream_count};
}

bool provider_topology_compiler::requires_same_domain_transition_(uint32_t from_node, uint32_t to_node) const noexcept
{
	const uint32_t stream_count = static_cast<uint32_t>(out_.io_streams.size());
	if (from_node < stream_count || to_node < stream_count) {
		// The native I/O burst operation already owns the stream-adjacent
		// packet transfer. A same-domain transition there would duplicate it.
		return false;
	}
	const auto &source = out_.stage_instances[from_node - stream_count];
	const auto &destination = out_.stage_instances[to_node - stream_count];
	return source.worker_index != destination.worker_index ||
	       source.execution_provider_index != destination.execution_provider_index;
}

status provider_topology_compiler::compile_storage_transitions_()
{
	struct transition_candidate {
		const kinetum::gluon::v1::StorageTransition *input;
		uint32_t from_node;
		uint32_t to_node;
		uint32_t from_domain;
		uint32_t to_domain;
	};
	std::vector<transition_candidate> sorted;
	sorted.reserve(static_cast<std::size_t>(plan_.storage_transitions_size()));
	std::set<std::string> transition_ids;
	for (const auto &input : plan_.storage_transitions()) {
		if (const auto id_status = validate_graph_id(input.transition_id(), "transition_id");
		    !id_status.is_ok()) {
			return id_status;
		}
		if (!transition_ids.insert(input.transition_id()).second) {
			return status::invalid_argument("duplicate storage-transition identity");
		}
		auto from_or = resolve_endpoint_node_(input.from_endpoint());
		auto to_or = resolve_endpoint_node_(input.to_endpoint());
		if (!from_or.is_ok()) {
			return from_or.error();
		}
		if (!to_or.is_ok()) {
			return to_or.error();
		}
		if (!graph_edges_.contains({from_or.value(), to_or.value()})) {
			return status::invalid_argument("storage transition does not name a real directed packet edge");
		}
		const auto from_domain_it = storage_by_id_.find(input.from_storage_domain_id());
		const auto to_domain_it = storage_by_id_.find(input.to_storage_domain_id());
		if (from_domain_it == storage_by_id_.end() || to_domain_it == storage_by_id_.end()) {
			return status::invalid_argument("storage transition references an unknown storage domain");
		}
		sorted.push_back(transition_candidate{&input, from_or.value(), to_or.value(), from_domain_it->second,
						      to_domain_it->second});
	}
	std::sort(sorted.begin(), sorted.end(), [](const auto &lhs, const auto &rhs) {
		return std::tie(lhs.from_node, lhs.to_node, lhs.from_domain, lhs.to_domain,
				lhs.input->transition_id()) <
		       std::tie(rhs.from_node, rhs.to_node, rhs.from_domain, rhs.to_domain, rhs.input->transition_id());
	});
	out_.storage_transitions.reserve(sorted.size());
	transition_contracts_.reserve(sorted.size());
	for (const auto &candidate : sorted) {
		const auto &input = *candidate.input;
		auto canonical_or = compile_configuration(provider_contract_role::STORAGE_TRANSITION,
							  input.configuration(), required_contracts_);
		if (!canonical_or.is_ok()) {
			return canonical_or.error();
		}
		auto canonical = std::move(canonical_or).value();
		const auto *projection = std::get_if<storage_transition_projection>(&canonical.contract->capabilities);
		if (projection == nullptr) {
			return status::internal_error("storage-transition catalog row lost its role projection");
		}
		auto facilities_or = resolve_facilities_("storage transition", input.transition_id(),
							 input.facility_instance_ids(), *canonical.contract);
		if (!facilities_or.is_ok()) {
			return facilities_or.error();
		}
		if (!packet_access_agents_include(out_.storage_domains[candidate.from_domain].capabilities.access_agents,
						  projection->required_source_access_agents) ||
		    !packet_access_agents_include(out_.storage_domains[candidate.to_domain].capabilities.access_agents,
						  projection->required_destination_access_agents)) {
			return status::invalid_argument(
				"storage transition domains lack contract-required access agents");
		}
		if (projection->requires_host_staging_numa != input.has_staging_numa_node()) {
			return status::invalid_argument(
				"storage transition staging_numa_node presence must exactly match its provider contract");
		}
		if (projection->requires_nonzero_staging_capacity != (input.staging_capacity() != 0)) {
			return status::invalid_argument(
				"storage transition staging_capacity presence must exactly match its provider contract");
		}
		switch (projection->mode) {
		case storage_transition_mode::ZERO_COPY_SHARE:
			if (candidate.from_domain != candidate.to_domain || input.staging_capacity() != 0 ||
			    !requires_same_domain_transition_(candidate.from_node, candidate.to_node)) {
				return status::invalid_argument(
					"zero-copy transition requires one domain and zero staging");
			}
			break;
		case storage_transition_mode::BOUNDED_COPY:
			if (candidate.from_domain == candidate.to_domain ||
			    !is_nonzero_power_of_two(input.staging_capacity()) || input.staging_numa_node() < 0) {
				return status::invalid_argument(
					"bounded-copy transition requires distinct domains, power-of-two staging, and NUMA");
			}
			{
				const uint32_t stream_count = static_cast<uint32_t>(out_.io_streams.size());
				const uint32_t destination_worker =
					candidate.to_node < stream_count ?
						out_.io_streams[candidate.to_node].worker_index :
						out_.stage_instances[candidate.to_node - stream_count].worker_index;
				const int32_t destination_numa =
					out_.transition_topology.workers[destination_worker].numa_node;
				const auto &destination_storage = out_.storage_domains[candidate.to_domain];
				if (input.staging_numa_node() != destination_numa ||
				    (destination_storage.host_numa_node.has_value() &&
				     destination_storage.host_numa_node.value() != destination_numa)) {
					return status::invalid_argument(
						"bounded-copy staging, destination storage, and destination worker NUMA disagree");
				}
			}
			break;
		}
		const auto edge_it = graph_edge_index_by_nodes_.find({candidate.from_node, candidate.to_node});
		if (edge_it == graph_edge_index_by_nodes_.end()) {
			return status::internal_error("compiled packet edge lost its direct transition index");
		}
		auto &edge = compiled_graph_edges_[edge_it->second];
		if (edge.transition_by_source_domain.empty()) {
			edge.transition_by_source_domain.assign(out_.storage_domains.size(),
								INVALID_COMPILED_TRANSITION);
		}
		if (edge.transition_by_source_domain[candidate.from_domain] != INVALID_COMPILED_TRANSITION) {
			return status::invalid_argument("two storage transitions claim one edge/source-domain state");
		}
		const uint32_t index = static_cast<uint32_t>(out_.storage_transitions.size());
		edge.transition_by_source_domain[candidate.from_domain] = index;
		transition_contracts_.push_back(canonical.contract);
		out_.storage_transitions.push_back(compiled_storage_transition{
			input.transition_id(), index, public_endpoint_(candidate.from_node),
			public_endpoint_(candidate.to_node), candidate.from_domain, candidate.to_domain,
			std::move(facilities_or).value(), std::move(canonical.configuration), *projection,
			input.staging_capacity(),
			input.has_staging_numa_node() ? std::optional<int32_t>(input.staging_numa_node()) :
							std::nullopt});
	}
	transition_use_counts_.assign(out_.storage_transitions.size(), 0u);
	return status::ok();
}

status provider_topology_compiler::validate_destination_access_(uint32_t node, uint32_t domain,
								bool transition_was_present) const
{
	const uint32_t stream_count = static_cast<uint32_t>(out_.io_streams.size());
	const auto &storage = out_.storage_domains[domain];
	if (node < stream_count) {
		const auto &stream = out_.io_streams[node];
		if (stream.direction != compiled_io_stream_direction::TX ||
		    !std::binary_search(stream.tx_storage_domain_indices.begin(),
					stream.tx_storage_domain_indices.end(), domain)) {
			return status::invalid_argument(
				transition_was_present ?
					"storage transition does not produce a domain admitted by the TX stream" :
					"packet path requires a missing storage transition before TX");
		}
		return status::ok();
	}
	const auto &stage = out_.stage_instances[node - stream_count];
	const auto &execution = out_.execution_providers[stage.execution_provider_index];
	if (!packet_storage_supports_execution(storage.capabilities, execution.capabilities)) {
		return status::invalid_argument(
			transition_was_present ?
				"storage transition destination lacks the execution provider's exact access shape" :
				"packet path requires a storage transition to an execution-compatible domain");
	}
	if (storage.host_numa_node.has_value() &&
	    storage.host_numa_node.value() != out_.transition_topology.workers[stage.worker_index].numa_node) {
		return status::invalid_argument(
			transition_was_present ?
				"storage transition destination disagrees with the execution worker's host NUMA node" :
				"packet path requires a storage transition to the execution worker's host NUMA node");
	}
	return status::ok();
}

status provider_topology_compiler::compile_reachable_domains_()
{
	const uint32_t node_count = static_cast<uint32_t>(outgoing_edge_indices_.size());
	const uint32_t domain_count = static_cast<uint32_t>(out_.storage_domains.size());
	if (domain_count == 0u || node_count == 0u) {
		return status::invalid_argument("provider topology requires packet endpoints and storage domains");
	}
	const std::size_t word_count = (static_cast<std::size_t>(domain_count) + 63u) / 64u;
	reachable_domain_words_.assign(node_count, std::vector<uint64_t>(word_count, 0u));
	std::deque<std::pair<uint32_t, uint32_t>> worklist;
	auto insert_state = [&](uint32_t node, uint32_t domain) {
		const std::size_t word = domain / 64u;
		const uint64_t mask = uint64_t{1} << (domain % 64u);
		if ((reachable_domain_words_[node][word] & mask) != 0u) {
			return;
		}
		reachable_domain_words_[node][word] |= mask;
		worklist.emplace_back(node, domain);
	};
	for (const auto &stream : out_.io_streams) {
		if (stream.direction == compiled_io_stream_direction::RX) {
			insert_state(stream.io_stream_index, stream.rx_storage_domain_index);
		}
	}
	const uint32_t stream_count = static_cast<uint32_t>(out_.io_streams.size());
	for (const auto &stage : out_.stage_instances) {
		if (stage.active_origin_storage_domain_index.has_value()) {
			insert_state(stream_count + stage.stage_instance_index,
				     stage.active_origin_storage_domain_index.value());
		}
	}
	while (!worklist.empty()) {
		const auto [from_node, from_domain] = worklist.front();
		worklist.pop_front();
		for (const uint32_t edge_index : outgoing_edge_indices_[from_node]) {
			const auto &edge = compiled_graph_edges_[edge_index];
			const uint32_t transition_index = edge.transition_by_source_domain.empty() ?
								  INVALID_COMPILED_TRANSITION :
								  edge.transition_by_source_domain[from_domain];
			const bool has_transition = transition_index != INVALID_COMPILED_TRANSITION;
			const bool same_domain_transition_required =
				requires_same_domain_transition_(from_node, edge.to_node);
			if (!has_transition && same_domain_transition_required) {
				return status::invalid_argument(
					"packet path requires a missing same-domain execution-owner transition");
			}
			uint32_t to_domain = from_domain;
			if (has_transition) {
				to_domain = out_.storage_transitions[transition_index].to_storage_domain_index;
				++transition_use_counts_[transition_index];
			}
			if (const auto access_status =
				    validate_destination_access_(edge.to_node, to_domain, has_transition);
			    !access_status.is_ok()) {
				return access_status;
			}
			insert_state(edge.to_node, to_domain);
		}
	}
	for (auto &stage : out_.stage_instances) {
		const uint32_t node = stream_count + stage.stage_instance_index;
		for (uint32_t domain = 0; domain < domain_count; ++domain) {
			if ((reachable_domain_words_[node][domain / 64u] & (uint64_t{1} << (domain % 64u))) != 0u) {
				if (stage.dispatch_mode == compiled_stage_dispatch_mode::UNCONDITIONAL_FANOUT &&
				    !packet_storage_supports_fanout(out_.storage_domains[domain].capabilities,
								    stage.packet_routes.size())) {
					return status::invalid_argument(
						"unconditional fan-out requires independently writable storage clones");
				}
				stage.reachable_storage_domain_indices.push_back(domain);
				++storage_use_counts_[domain];
			}
		}
		if (stage.reachable_storage_domain_indices.empty()) {
			return status::invalid_argument(
				"executable stage instance is unreachable from every packet source");
		}
	}
	// Explicit egress may select another TX stream owned by this worker. Two
	// bitsets distinguish a domain present at one terminal from a domain also
	// present at another; the bound terminal's own authored conversion must not
	// make its unconverted source look like an independently executable path.
	const std::size_t worker_count = out_.transition_topology.workers.size();
	std::vector<std::vector<uint64_t>> terminal_domains(worker_count, std::vector<uint64_t>(word_count, 0u));
	std::vector<std::vector<uint64_t>> repeated_terminal_domains(worker_count,
								     std::vector<uint64_t>(word_count, 0u));
	for (const auto &stage : out_.stage_instances) {
		if (out_.logical_stages[stage.logical_stage_index].kind != compiled_stage_kind::TX) {
			continue;
		}
		const auto &source = reachable_domain_words_[stream_count + stage.stage_instance_index];
		auto &seen = terminal_domains[stage.worker_index];
		auto &repeated = repeated_terminal_domains[stage.worker_index];
		for (std::size_t word = 0; word < word_count; ++word) {
			repeated[word] |= seen[word] & source[word];
			seen[word] |= source[word];
		}
	}
	for (const auto &stream : out_.io_streams) {
		if (stream.direction != compiled_io_stream_direction::TX) {
			continue;
		}
		const auto &bound = reachable_domain_words_[stream.io_stream_index];
		if (std::none_of(bound.begin(), bound.end(), [](uint64_t word) { return word != 0u; })) {
			return status::invalid_argument("TX stream is unreachable through its bound terminal edge");
		}
		const auto &own_terminal = reachable_domain_words_[stream_count + stream.stage_instance_index];
		const auto &all_terminals = terminal_domains[stream.worker_index];
		const auto &repeated = repeated_terminal_domains[stream.worker_index];
		for (const uint32_t domain : stream.tx_storage_domain_indices) {
			const std::size_t word = domain / 64u;
			const uint64_t mask = uint64_t{1} << (domain % 64u);
			const uint64_t other_terminal = (all_terminals[word] & ~own_terminal[word]) | repeated[word];
			if (((bound[word] | other_terminal) & mask) == 0u) {
				return status::invalid_argument(
					"TX storage admission contains a domain with no bound or same-worker egress path");
			}
		}
	}
	for (std::size_t index = 0; index < transition_use_counts_.size(); ++index) {
		if (transition_use_counts_[index] != 1u) {
			return status::invalid_argument(
				"declared storage transition must map exactly one reachable edge/source-domain state");
		}
	}
	return status::ok();
}

status provider_topology_compiler::compile_schedules_and_budgets_()
{
	const std::size_t domain_count = out_.storage_domains.size();
	std::vector<uint64_t> rx_descriptors(domain_count, 0u);
	std::vector<uint64_t> tx_descriptors(domain_count, 0u);
	std::vector<uint64_t> worker_staging(domain_count, 0u);
	std::vector<uint64_t> handoff_staging(domain_count, 0u);
	std::vector<uint64_t> source_future_staging(domain_count, 0u);
	std::vector<uint64_t> future_output(domain_count, 0u);
	std::vector<uint64_t> active_retained(domain_count, 0u);
	std::vector<std::set<uint32_t>> workers_by_domain(domain_count);

	out_.worker_schedules.resize(out_.transition_topology.workers.size());
	for (const auto &worker : out_.transition_topology.workers) {
		auto &schedule = out_.worker_schedules[worker.worker_index];
		schedule.worker_index = worker.worker_index;
		schedule.tx_stream_index_by_logical_port.assign(out_.ports.size(), INVALID_COMPILED_PROVIDER_INDEX);
	}
	for (const auto &stream : out_.io_streams) {
		auto &schedule = out_.worker_schedules[stream.worker_index];
		// One physical TX queue can hold its entire descriptor population from
		// any admitted domain. Charge that complete floor to each domain once;
		// the queue and its owner schedule are still constructed only once.
		for (const uint32_t domain : stream.storage_domain_indices()) {
			auto &descriptors = stream.direction == compiled_io_stream_direction::RX ?
						    rx_descriptors[domain] :
						    tx_descriptors[domain];
			if (const auto add_status =
				    add_count_checked(descriptors, stream.descriptor_count, "descriptors");
			    !add_status.is_ok()) {
				return add_status;
			}
			workers_by_domain[domain].insert(stream.worker_index);
		}
		if (stream.direction == compiled_io_stream_direction::RX) {
			schedule.rx_stream_indices.push_back(stream.io_stream_index);
		} else {
			schedule.tx_stream_indices.push_back(stream.io_stream_index);
			const uint32_t logical_port_id = out_.ports[stream.port_index].logical_port_id;
			auto &tx_stream = schedule.tx_stream_index_by_logical_port[logical_port_id];
			if (tx_stream != INVALID_COMPILED_PROVIDER_INDEX) {
				return status::invalid_argument(
					"worker owns competing TX streams for one logical port");
			}
			tx_stream = stream.io_stream_index;
		}
	}
	for (const auto &stage : out_.stage_instances) {
		auto &schedule = out_.worker_schedules[stage.worker_index];
		schedule.stage_instance_indices.push_back(stage.stage_instance_index);
		const auto &logical = out_.logical_stages[stage.logical_stage_index];
		if (logical.execution_mode == compiled_stage_execution_mode::ACTIVE) {
			schedule.active_stage_instance_indices.push_back(stage.stage_instance_index);
			if (logical.async_work_capacity != 0u) {
				schedule.async_stage_instance_indices.push_back(stage.stage_instance_index);
			}
			for (const uint32_t domain : stage.reachable_storage_domain_indices) {
				if (domain >= domain_count) {
					return status::internal_error(
						"active stage retained capacity references an unknown storage domain");
				}
				if (const auto add_status = add_count_checked(active_retained[domain],
									      logical.retained_packet_capacity,
									      "active retained-packet credits");
				    !add_status.is_ok()) {
					return add_status;
				}
			}
		}
		for (const uint32_t domain : stage.reachable_storage_domain_indices) {
			workers_by_domain[domain].insert(stage.worker_index);
		}
	}
	for (const auto &transition : out_.storage_transitions) {
		uint32_t owner_worker = 0;
		switch (transition.from_endpoint.kind) {
		case compiled_packet_path_endpoint_kind::IO_STREAM:
			if (transition.from_endpoint.endpoint_index >= out_.io_streams.size()) {
				return status::internal_error("compiled storage transition lost its source I/O stream");
			}
			owner_worker = out_.io_streams[transition.from_endpoint.endpoint_index].worker_index;
			break;
		case compiled_packet_path_endpoint_kind::STAGE_INSTANCE:
			if (transition.from_endpoint.endpoint_index >= out_.stage_instances.size()) {
				return status::internal_error(
					"compiled storage transition lost its source stage instance");
			}
			owner_worker = out_.stage_instances[transition.from_endpoint.endpoint_index].worker_index;
			break;
		}
		if (owner_worker >= out_.worker_schedules.size() ||
		    transition.from_storage_domain_index >= domain_count ||
		    transition.to_storage_domain_index >= domain_count) {
			return status::internal_error("compiled storage transition lost its owner or storage domain");
		}
		out_.worker_schedules[owner_worker].storage_transition_indices.push_back(transition.transition_index);
		// The source owner invokes the transition before destination
		// publication. It therefore participates in both storage-domain
		// lifetimes and in any per-worker storage/cache budget.
		workers_by_domain[transition.from_storage_domain_index].insert(owner_worker);
		workers_by_domain[transition.to_storage_domain_index].insert(owner_worker);
	}
	for (const auto &edge : out_.control_edges) {
		out_.worker_schedules[edge.worker_index].inbound_control_edge_indices.push_back(
			edge.control_edge_index);
	}
	for (auto &schedule : out_.worker_schedules) {
		const auto active_order = [&](uint32_t lhs, uint32_t rhs) {
			const auto &lhs_logical = out_.logical_stages[out_.stage_instances[lhs].logical_stage_index];
			const auto &rhs_logical = out_.logical_stages[out_.stage_instances[rhs].logical_stage_index];
			return std::tie(lhs_logical.schedule_order, lhs) < std::tie(rhs_logical.schedule_order, rhs);
		};
		std::sort(schedule.active_stage_instance_indices.begin(), schedule.active_stage_instance_indices.end(),
			  active_order);
		std::sort(schedule.async_stage_instance_indices.begin(), schedule.async_stage_instance_indices.end(),
			  active_order);
		for (const uint32_t stage_index : schedule.active_stage_instance_indices) {
			const uint32_t trigger_mask =
				out_.logical_stages[out_.stage_instances[stage_index].logical_stage_index].trigger_mask;
			if ((trigger_mask & static_cast<uint32_t>(compiled_active_stage_trigger::LOOP)) != 0u) {
				schedule.loop_trigger_stage_instance_indices.push_back(stage_index);
			}
			if ((trigger_mask & static_cast<uint32_t>(compiled_active_stage_trigger::TIMER)) != 0u) {
				schedule.timer_trigger_stage_instance_indices.push_back(stage_index);
			}
			if ((trigger_mask & static_cast<uint32_t>(compiled_active_stage_trigger::PULL_READY)) != 0u) {
				schedule.pull_trigger_stage_instance_indices.push_back(stage_index);
			}
			if ((trigger_mask & static_cast<uint32_t>(compiled_active_stage_trigger::CONTROL)) != 0u) {
				schedule.control_trigger_stage_instance_indices.push_back(stage_index);
			}
		}
		std::sort(schedule.inbound_control_edge_indices.begin(), schedule.inbound_control_edge_indices.end());
		std::set<uint32_t> source_storage_domains;
		for (const uint32_t stream_index : schedule.rx_stream_indices) {
			if (stream_index >= out_.io_streams.size()) {
				return status::internal_error("compiled source worker lost one RX stream");
			}
			source_storage_domains.insert(out_.io_streams[stream_index].rx_storage_domain_index);
		}
		for (const uint32_t stage_index : schedule.stage_instance_indices) {
			if (stage_index >= out_.stage_instances.size()) {
				return status::internal_error("compiled source worker lost one stage instance");
			}
			const auto &stage = out_.stage_instances[stage_index];
			if (stage.active_origin_storage_domain_index.has_value()) {
				source_storage_domains.insert(stage.active_origin_storage_domain_index.value());
			}
		}
		schedule.source_storage_domain_indices.assign(source_storage_domains.begin(),
							      source_storage_domains.end());
		for (std::size_t domain = 0; domain < domain_count; ++domain) {
			if (workers_by_domain[domain].contains(schedule.worker_index)) {
				schedule.storage_domain_indices.push_back(static_cast<uint32_t>(domain));
			}
		}
		for (const uint32_t domain : schedule.source_storage_domain_indices) {
			if (domain >= domain_count || !workers_by_domain[domain].contains(schedule.worker_index)) {
				return status::internal_error(
					"compiled source storage domain is absent from worker ownership");
			}
		}
		const auto &transition_worker = out_.transition_topology.workers[schedule.worker_index];
		if (transition_worker.is_source != !schedule.source_storage_domain_indices.empty()) {
			return status::internal_error(
				"compiled worker source role disagrees with exact source storage domains");
		}
		if (schedule.stage_instance_indices != transition_worker.stage_instance_indices || [&] {
			    std::vector<uint32_t> all_streams = schedule.rx_stream_indices;
			    all_streams.insert(all_streams.end(), schedule.tx_stream_indices.begin(),
					       schedule.tx_stream_indices.end());
			    std::sort(all_streams.begin(), all_streams.end());
			    return all_streams != transition_worker.io_stream_indices;
		    }()) {
			return status::internal_error(
				"provider worker schedule disagrees with composed transition ownership");
		}
		for (const uint32_t domain : schedule.storage_domain_indices) {
			const bool source_domain = std::binary_search(schedule.source_storage_domain_indices.begin(),
								      schedule.source_storage_domain_indices.end(),
								      domain);
			const uint64_t capacity = source_domain && transition_worker.source_epoch_staging_capacity !=
									   0u ?
							  transition_worker.source_epoch_staging_capacity :
							  common::runtime_sizing::INTER_REGION_DATA_RING_CAPACITY;
			if (const auto add_status = add_count_checked(worker_staging[domain], capacity,
								      "active worker staging credits");
			    !add_status.is_ok()) {
				return add_status;
			}
		}
	}

	const uint32_t stream_count = static_cast<uint32_t>(out_.io_streams.size());
	for (const auto &boundary : out_.transition_topology.boundaries) {
		const uint32_t from_stage = boundary.from_stage_instance_index;
		const uint32_t to_stage = boundary.to_stage_instance_index;
		const uint32_t from_node = stream_count + from_stage;
		const uint32_t to_node = stream_count + to_stage;
		const auto edge_it = graph_edge_index_by_nodes_.find({from_node, to_node});
		if (edge_it == graph_edge_index_by_nodes_.end()) {
			return status::internal_error("compiled boundary lost its packet-graph edge");
		}
		const auto &edge = compiled_graph_edges_[edge_it->second];
		std::set<uint32_t> carried_domains;
		for (const uint32_t from_domain : out_.stage_instances[from_stage].reachable_storage_domain_indices) {
			uint32_t carried_domain = from_domain;
			const uint32_t transition_index = edge.transition_by_source_domain.empty() ?
								  INVALID_COMPILED_TRANSITION :
								  edge.transition_by_source_domain[from_domain];
			if (transition_index != INVALID_COMPILED_TRANSITION) {
				carried_domain = out_.storage_transitions[transition_index].to_storage_domain_index;
			}
			carried_domains.insert(carried_domain);
		}
		// One boundary owns one physical DATA ring. Each domain that can occupy
		// that ring needs the complete capacity floor, but several source-domain
		// states converging into the same carried domain do not create another
		// ring or another independently occupiable credit population.
		for (const uint32_t carried_domain : carried_domains) {
			if (const auto add_status = add_count_checked(handoff_staging[carried_domain],
								      boundary.data_ring_capacity,
								      "boundary DATA credits");
			    !add_status.is_ok()) {
				return add_status;
			}
			if (const auto add_status = add_count_checked(future_output[carried_domain],
								      boundary.future_output_hold_capacity,
								      "boundary future-output credits");
			    !add_status.is_ok()) {
				return add_status;
			}
		}
	}
	for (const auto &transition : out_.storage_transitions) {
		if (transition.capabilities.mode == storage_transition_mode::BOUNDED_COPY) {
			if (const auto add_status =
				    add_count_checked(handoff_staging[transition.to_storage_domain_index],
						      transition.staging_capacity, "bounded-copy destination credits");
			    !add_status.is_ok()) {
				return add_status;
			}
		}
	}
	for (const auto &worker : out_.transition_topology.workers) {
		if (!worker.is_source || worker.source_epoch_staging_capacity == 0u) {
			continue;
		}
		const auto &source_domains = out_.worker_schedules[worker.worker_index].source_storage_domain_indices;
		if (source_domains.empty()) {
			return status::internal_error(
				"compiled source worker has no exact RX or active-origin storage domain");
		}
		for (const uint32_t domain : source_domains) {
			if (const auto add_status = add_count_checked(source_future_staging[domain],
								      worker.source_epoch_staging_capacity,
								      "source future-staging credits");
			    !add_status.is_ok()) {
				return add_status;
			}
		}
	}
	for (std::size_t domain = 0; domain < domain_count; ++domain) {
		const uint64_t worker_count = static_cast<uint64_t>(workers_by_domain[domain].size());
		auto budget_or =
			common::compile_storage_domain_buffer_budget(common::storage_domain_buffer_budget_inputs{
				.storage_domain_id = out_.storage_domains[domain].storage_domain_id,
				.declared_buffer_count = out_.storage_domains[domain].buffer_count,
				.rx_descriptor_count = rx_descriptors[domain],
				.tx_descriptor_count = tx_descriptors[domain],
				.worker_count = worker_count,
				.worker_staging_capacity = worker_staging[domain],
				.handoff_staging_capacity = handoff_staging[domain],
				.source_future_staging_capacity = source_future_staging[domain],
				.future_output_capacity = future_output[domain],
				.active_retained_capacity = active_retained[domain],
				.cache_size_per_worker = out_.storage_domains[domain].cache_size_per_worker,
			});
		if (!budget_or.is_ok()) {
			return budget_or.error();
		}
		out_.storage_domains[domain].budget = std::move(budget_or).value();
	}
	return status::ok();
}

status provider_topology_compiler::compile_component_facts_()
{
	std::vector<std::set<uint32_t>> storage_by_driver(out_.io_drivers.size());
	for (const auto &stream : out_.io_streams) {
		const auto &port = out_.ports[stream.port_index];
		const auto domains = stream.storage_domain_indices();
		storage_by_driver[port.io_driver_index].insert(domains.begin(), domains.end());
	}
	for (std::size_t index = 0; index < out_.io_drivers.size(); ++index) {
		out_.io_drivers[index].storage_domain_indices.assign(storage_by_driver[index].begin(),
								     storage_by_driver[index].end());
		if (out_.io_drivers[index].storage_domain_indices.empty()) {
			return status::internal_error(
				"consumed I/O-driver instance has no compiled storage dependency");
		}
	}

	std::vector<std::set<uint32_t>> workers_by_execution(out_.execution_providers.size());
	std::vector<std::set<uint32_t>> storage_by_execution(out_.execution_providers.size());
	for (const auto &stage : out_.stage_instances) {
		auto &execution = out_.execution_providers[stage.execution_provider_index];
		execution.stage_instance_indices.push_back(stage.stage_instance_index);
		workers_by_execution[stage.execution_provider_index].insert(stage.worker_index);
		storage_by_execution[stage.execution_provider_index].insert(
			stage.reachable_storage_domain_indices.begin(), stage.reachable_storage_domain_indices.end());
	}
	for (std::size_t index = 0; index < out_.execution_providers.size(); ++index) {
		auto &execution = out_.execution_providers[index];
		execution.worker_indices.assign(workers_by_execution[index].begin(), workers_by_execution[index].end());
		execution.storage_domain_indices.assign(storage_by_execution[index].begin(),
							storage_by_execution[index].end());
		if (execution.stage_instance_indices.empty() || execution.worker_indices.empty() ||
		    execution.storage_domain_indices.empty()) {
			return status::internal_error(
				"consumed execution-provider instance has incomplete compiled facts");
		}
	}

	for (auto &facility : out_.process_facilities) {
		if (facility.configuration.type_url != DPDK_FACILITY_TYPE_URL) {
			return status::internal_error("catalog process-facility row has no semantic fact compiler");
		}
		if (!out_.transition_topology.lifecycle_services.has_value()) {
			return status::invalid_argument(
				"DPDK process facility requires complete lifecycle-service topology for its exact main core");
		}
		const auto &lifecycle = out_.transition_topology.lifecycle_services.value();
		if (lifecycle.coordinator_service_index >= out_.transition_topology.runtime_services.size()) {
			return status::internal_error("compiled lifecycle coordinator index is out of range");
		}
		facility.main_core_id =
			out_.transition_topology.runtime_services[lifecycle.coordinator_service_index].cpu_core_id;

		std::set<uint32_t> dependent_worker_indices;
		for (const auto &schedule : out_.worker_schedules) {
			bool depends_on_facility = false;
			for (const uint32_t storage_index : schedule.storage_domain_indices) {
				if (storage_index >= out_.storage_domains.size()) {
					return status::internal_error(
						"compiled worker schedule lost its storage-domain dependency");
				}
				const auto &storage = out_.storage_domains[storage_index];
				depends_on_facility = depends_on_facility ||
						      std::binary_search(storage.facility_indices.begin(),
									 storage.facility_indices.end(),
									 facility.facility_index);
			}
			const auto include_stream_dependency = [&](uint32_t stream_index) -> status {
				if (stream_index >= out_.io_streams.size()) {
					return status::internal_error(
						"compiled worker schedule lost its I/O-stream dependency");
				}
				const auto &stream = out_.io_streams[stream_index];
				if (stream.port_index >= out_.ports.size()) {
					return status::internal_error(
						"compiled worker stream lost its logical-port dependency");
				}
				const uint32_t driver_index = out_.ports[stream.port_index].io_driver_index;
				if (driver_index >= out_.io_drivers.size()) {
					return status::internal_error(
						"compiled worker stream lost its I/O-driver dependency");
				}
				const auto &driver = out_.io_drivers[driver_index];
				depends_on_facility = depends_on_facility ||
						      std::binary_search(driver.facility_indices.begin(),
									 driver.facility_indices.end(),
									 facility.facility_index);
				return status::ok();
			};
			for (const uint32_t stream_index : schedule.rx_stream_indices) {
				if (const auto include_status = include_stream_dependency(stream_index);
				    !include_status.is_ok()) {
					return include_status;
				}
			}
			for (const uint32_t stream_index : schedule.tx_stream_indices) {
				if (const auto include_status = include_stream_dependency(stream_index);
				    !include_status.is_ok()) {
					return include_status;
				}
			}
			if (depends_on_facility) {
				dependent_worker_indices.insert(schedule.worker_index);
			}
		}
		if (dependent_worker_indices.empty()) {
			return status::invalid_argument(
				"DPDK process facility has no packet worker that depends on its exact driver or storage set");
		}
		for (const uint32_t worker_index : dependent_worker_indices) {
			if (worker_index >= out_.transition_topology.workers.size() ||
			    out_.transition_topology.workers[worker_index].worker_index != worker_index) {
				return status::internal_error(
					"compiled DPDK facility lost its dependent packet worker");
			}
			const auto &worker = out_.transition_topology.workers[worker_index];
			for (const int32_t cpu_core_id : worker.cpu_core_ids) {
				facility.cpu_assignments.push_back(compiled_facility_cpu_assignment{
					worker.worker_index, cpu_core_id, worker.numa_node,
					compiled_facility_cpu_owner_kind::PACKET_WORKER});
			}
		}
		for (const auto &service : out_.transition_topology.runtime_services) {
			const auto kind =
				service.role == common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR ?
					compiled_facility_cpu_owner_kind::TRANSITION_COORDINATOR :
					compiled_facility_cpu_owner_kind::LIFECYCLE_EXECUTOR;
			facility.cpu_assignments.push_back(compiled_facility_cpu_assignment{
				service.service_index, service.cpu_core_id, service.numa_node, kind});
		}
		std::sort(facility.cpu_assignments.begin(), facility.cpu_assignments.end(),
			  [](const auto &lhs, const auto &rhs) {
				  return std::tie(lhs.cpu_core_id, lhs.kind, lhs.owner_index) <
					 std::tie(rhs.cpu_core_id, rhs.kind, rhs.owner_index);
			  });
		if (facility.cpu_assignments.empty() ||
		    std::adjacent_find(facility.cpu_assignments.begin(), facility.cpu_assignments.end(),
				       [](const auto &lhs, const auto &rhs) {
					       return lhs.cpu_core_id == rhs.cpu_core_id;
				       }) != facility.cpu_assignments.end()) {
			return status::internal_error("compiled DPDK facility CPU ownership is empty or overlapping");
		}

		for (const auto &driver : out_.io_drivers) {
			if (!std::binary_search(driver.facility_indices.begin(), driver.facility_indices.end(),
						facility.facility_index)) {
				continue;
			}
			if (driver.configuration.type_url != DPDK_DRIVER_TYPE_URL) {
				return status::invalid_argument(
					"DPDK process facility is referenced by a non-DPDK I/O-driver contract");
			}
			facility.attachments.insert(facility.attachments.end(), driver.attachments.begin(),
						    driver.attachments.end());
		}
		std::sort(facility.attachments.begin(), facility.attachments.end(),
			  [](const auto &lhs, const auto &rhs) {
				  return std::tie(lhs.io_driver_index, lhs.driver_port_id) <
					 std::tie(rhs.io_driver_index, rhs.driver_port_id);
			  });

		for (const auto &storage : out_.storage_domains) {
			if (!std::binary_search(storage.facility_indices.begin(), storage.facility_indices.end(),
						facility.facility_index)) {
				continue;
			}
			if (storage.configuration.type_url != DPDK_STORAGE_TYPE_URL) {
				return status::invalid_argument(
					"DPDK process facility is referenced by a non-DPDK storage contract");
			}
			facility.memory_domains.push_back(compiled_facility_memory_domain{
				storage.storage_domain_index, storage.buffer_count, storage.data_room_bytes,
				storage.headroom_bytes, storage.alignment_bytes, storage.cache_size_per_worker,
				storage.host_numa_node});
		}
		std::sort(facility.memory_domains.begin(), facility.memory_domains.end(),
			  [](const auto &lhs, const auto &rhs) {
				  return lhs.storage_domain_index < rhs.storage_domain_index;
			  });
		if (facility.attachments.empty() || facility.memory_domains.empty()) {
			return status::invalid_argument(
				"DPDK process facility requires exact dependent attachment and memory-domain sets");
		}
	}
	return status::ok();
}

void provider_topology_compiler::append_contract_requirements_(provider_contract_role role, uint32_t instance_index,
							       const provider_contract_descriptor &contract)
{
	for (const auto &requirement : contract.host_requirements) {
		out_.host_requirements.push_back(
			compiled_provider_host_requirement{requirement.phase, requirement.fact, role, instance_index});
	}
}

status provider_topology_compiler::compile_host_requirements_()
{
	for (std::size_t index = 0; index < facility_contracts_.size(); ++index) {
		append_contract_requirements_(provider_contract_role::PROCESS_FACILITY, static_cast<uint32_t>(index),
					      *facility_contracts_[index]);
	}
	for (std::size_t index = 0; index < driver_contracts_.size(); ++index) {
		append_contract_requirements_(provider_contract_role::IO_DRIVER, static_cast<uint32_t>(index),
					      *driver_contracts_[index]);
	}
	for (std::size_t index = 0; index < storage_contracts_.size(); ++index) {
		append_contract_requirements_(provider_contract_role::PACKET_STORAGE, static_cast<uint32_t>(index),
					      *storage_contracts_[index]);
	}
	for (std::size_t index = 0; index < execution_contracts_.size(); ++index) {
		append_contract_requirements_(provider_contract_role::EXECUTION, static_cast<uint32_t>(index),
					      *execution_contracts_[index]);
	}
	for (std::size_t index = 0; index < transition_contracts_.size(); ++index) {
		append_contract_requirements_(provider_contract_role::STORAGE_TRANSITION, static_cast<uint32_t>(index),
					      *transition_contracts_[index]);
	}
	std::sort(out_.host_requirements.begin(), out_.host_requirements.end(), [](const auto &lhs, const auto &rhs) {
		return std::tie(lhs.phase, lhs.fact, lhs.role, lhs.instance_index) <
		       std::tie(rhs.phase, rhs.fact, rhs.role, rhs.instance_index);
	});
	if (std::adjacent_find(out_.host_requirements.begin(), out_.host_requirements.end(),
			       [](const auto &lhs, const auto &rhs) {
				       return lhs.phase == rhs.phase && lhs.fact == rhs.fact && lhs.role == rhs.role &&
					      lhs.instance_index == rhs.instance_index;
			       }) != out_.host_requirements.end()) {
		return status::internal_error("compiled provider host requirements contain a duplicate owner");
	}
	return status::ok();
}

status provider_topology_compiler::validate_two_directional_consumption_()
{
	for (std::size_t index = 0; index < facility_use_counts_.size(); ++index) {
		if (facility_use_counts_[index] == 0u) {
			return status::invalid_argument(
				"declared process facility is not referenced by any provider instance");
		}
	}
	for (std::size_t index = 0; index < driver_use_counts_.size(); ++index) {
		if (driver_use_counts_[index] == 0u) {
			return status::invalid_argument("declared I/O-driver instance owns no logical port");
		}
	}
	for (std::size_t index = 0; index < storage_use_counts_.size(); ++index) {
		if (storage_use_counts_[index] == 0u) {
			return status::invalid_argument("declared packet-storage domain is unreachable");
		}
	}
	for (std::size_t index = 0; index < execution_use_counts_.size(); ++index) {
		if (execution_use_counts_[index] == 0u) {
			return status::invalid_argument("declared execution-provider instance owns no stage");
		}
	}
	return status::ok();
}

}  // namespace

status_or<compiled_provider_topology> compile_provider_topology(const kinetum::gluon::v1::DeploymentPlan &plan)
try {
	return provider_topology_compiler(plan).run();
} catch (const std::bad_alloc &) {
	return status::resource_exhausted(
		kinetum::common::static_status_text("provider topology compilation exhausted host memory"));
} catch (const std::length_error &) {
	return status(
		status_code::OUT_OF_RANGE,
		kinetum::common::static_status_text("provider topology compilation exceeded the host size domain"));
}

}  // namespace kinetum::provider
