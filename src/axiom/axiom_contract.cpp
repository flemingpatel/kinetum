// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file axiom_contract.cpp
 * @brief Implementation of Axiom Pipeline Semantic Contract and Validation
 * @author Fleming Patel
 *
 * This file implements the validation algorithms and semantic rule enforcement
 * for Axiom pipeline graphs. One shared validation context owns stage
 * membership, adjacency, degree, and RX/TX facts across every phase. Canonical
 * topological ordering uses stable stage-identity tie breaking; reachability
 * uses bounded graph traversals. Validation is deterministic and reentrant,
 * takes O(E + V log V) time, and retains O(V + E) temporary state.
 */

#include "src/axiom/axiom_contract.hpp"

#include <algorithm>
#include <cstdint>
#include <deque>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <kinetum/algo/condition_parse.hpp>
#include <kinetum/algo/graph.hpp>  // Canonical deterministic topological ordering

#include "src/common/execution_topology_ids.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/sdk/module_abi_text.hpp"

namespace kinetum::axiom
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

namespace
{

/** @brief Maximum exact logical-interface identity width. */
constexpr std::size_t MAX_INTERFACE_ID_LENGTH = 128u;

/**
 * @brief Validate one complete authored pipeline and stage vocabulary.
 *
 * This is the first semantic admission phase. It rejects omitted modes,
 * unknown enum values, and kind/configuration disagreement before graph state
 * is allocated, so later phases may operate on one closed stage model.
 *
 * @param pipeline Pipeline to validate without mutation.
 * @return OK for the exact current schema; INVALID_ARGUMENT otherwise.
 */
[[nodiscard]] status verify_authored_contract(const kinetum::axiom::v1::Pipeline &pipeline)
{
	if (pipeline.pipeline_id().size() > MAX_PIPELINE_ID_LENGTH ||
	    !kinetum::common::execution_topology::is_topology_identifier(pipeline.pipeline_id())) {
		return status::invalid_argument(
			"Pipeline validation failed: pipeline_id must match [A-Za-z_][A-Za-z0-9_]* within " +
			std::to_string(MAX_PIPELINE_ID_LENGTH) + " bytes");
	}

	for (const auto &stage : pipeline.stages()) {
		if (stage.execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_PASSIVE &&
		    stage.execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
			return status::invalid_argument("stage '" + stage.stage_id() +
							"' must declare PASSIVE or ACTIVE execution_mode");
		}

		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_RX ||
		    stage.kind() == kinetum::axiom::v1::STAGE_KIND_TX) {
			if (!stage.has_io() || stage.io().interface().size() > MAX_INTERFACE_ID_LENGTH ||
			    !kinetum::common::execution_topology::is_topology_identifier(stage.io().interface())) {
				return status::invalid_argument("I/O stage '" + stage.stage_id() +
								"' requires one bounded topology-identifier interface");
			}
			continue;
		}
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4) {
			if (stage.configuration_case() != kinetum::axiom::v1::Stage::CONFIGURATION_NOT_SET) {
				return status::invalid_argument("PARSE_IPV4 stage '" + stage.stage_id() +
								"' must not carry I/O or module configuration");
			}
			continue;
		}
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
			if (!stage.has_module() || !kinetum::sdk::valid_module_abi_text(stage.module().module_id())) {
				return status::invalid_argument("module stage '" + stage.stage_id() +
								"' requires one bounded printable module_id");
			}
			if (stage.module().has_module_path() &&
			    (stage.module().module_path().empty() ||
			     stage.module().module_path().find('\0') != std::string::npos)) {
				return status::invalid_argument("module stage '" + stage.stage_id() +
								"' has an invalid authored module_path");
			}
			switch (stage.module().context_selection()) {
			case kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE:
			case kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_MODULE:
				break;
			case kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_UNSPECIFIED:
			case kinetum::axiom::v1::ModuleContextSelection_INT_MIN_SENTINEL_DO_NOT_USE_:
			case kinetum::axiom::v1::ModuleContextSelection_INT_MAX_SENTINEL_DO_NOT_USE_:
				return status::invalid_argument("module stage '" + stage.stage_id() +
								"' requires explicit context selection");
			}
			continue;
		}
		return status::invalid_argument("stage '" + stage.stage_id() + "' must declare one current stage kind");
	}

	for (const auto &edge : pipeline.edges()) {
		if (edge.mode() != kinetum::axiom::v1::EDGE_MODE_PUSH &&
		    edge.mode() != kinetum::axiom::v1::EDGE_MODE_PULL) {
			return status::invalid_argument("packet edge '" + edge.from_stage_id() + "' -> '" +
							edge.to_stage_id() + "' must declare PUSH or PULL mode");
		}
	}
	for (const auto &edge : pipeline.control_edges()) {
		if (edge.subtype() != kinetum::axiom::v1::CONTROL_EDGE_GENERIC &&
		    edge.subtype() != kinetum::axiom::v1::CONTROL_EDGE_FEEDBACK) {
			return status::invalid_argument("control edge '" + edge.from_stage_id() + "' -> '" +
							edge.to_stage_id() +
							"' must declare GENERIC or FEEDBACK subtype");
		}
	}
	return status::ok();
}

}  // namespace

//==============================================================================
// SHARED VALIDATION CONTEXT
//==============================================================================

/**
 * @brief Shared context built once and reused across all validation phases.
 *
 * The canonical graph algorithms live in `algo/graph.hpp`. This Axiom-specific
 * context adds:
 * - Cached RX/TX stage IDs for fast lookup
 * - Semantic flags (has_parse_ipv4, needs_parse_ipv4)
 * - Stage type counts for RX/TX validation
 * - out_degree tracking (algo/graph.hpp only tracks indegree)
 *
 * For general-purpose graph algorithms, use algo/graph.hpp directly.
 * For pipeline validation with rich error messages, use this context.
 *
 * The build() method constructs a format compatible with algo::dag<> for
 * use with algo/graph.hpp algorithms when deterministic ordering is required.
 */
struct validation_context {
	std::unordered_set<std::string> stage_ids;				 ///< Exact stage-identity membership.
	std::unordered_map<std::string, uint32_t> stage_indices;		 ///< Compact index by stage identity.
	std::unordered_map<std::string, std::vector<std::string>> successors;	 ///< Forward adjacency.
	std::unordered_map<std::string, std::vector<std::string>> predecessors;	 ///< Reverse adjacency.
	std::unordered_map<std::string, int> out_degree;			 ///< Out-degree by stage identity.
	std::unordered_map<std::string, int> in_degree;				 ///< In-degree by stage identity.
	std::vector<std::string> rx_stage_ids;		       ///< Every RX identity for multi-source traversal.
	std::vector<std::string> tx_stage_ids;		       ///< Every TX identity for multi-sink traversal.
	std::unordered_set<std::string> rx_stage_id_set;       ///< Constant-time RX membership.
	std::unordered_set<std::string> tx_stage_id_set;       ///< Constant-time TX membership.
	std::unordered_set<std::string> parse_ipv4_stage_ids;  ///< Parser barriers in the packet graph.
	std::vector<std::string> ipv4_consumer_stage_ids;      ///< Built-in stages requiring parsed IPv4/L4 facts.
	int rx_count{0};				       ///< Number of RX stages.
	int tx_count{0};				       ///< Number of TX stages.

	/**
	 * @brief Build the context from a pipeline once at validation start.
	 * @param p Complete pipeline whose graph facts are indexed.
	 *
	 * Complexity: O(V + E) single pass.
	 */
	void build(const kinetum::axiom::v1::Pipeline &p)
	{
		const size_t stage_count = static_cast<size_t>(p.stages_size());

		// Reserve capacity for all containers
		stage_ids.reserve(stage_count);
		stage_indices.reserve(stage_count);
		successors.reserve(stage_count);
		predecessors.reserve(stage_count);
		out_degree.reserve(stage_count);
		in_degree.reserve(stage_count);
		parse_ipv4_stage_ids.reserve(stage_count);
		ipv4_consumer_stage_ids.reserve(stage_count);

		// Single pass over stages: collect IDs, initialize maps, cache RX/TX
		uint32_t stage_index = 0u;
		for (const auto &stage : p.stages()) {
			const auto &id = stage.stage_id();
			stage_ids.insert(id);
			stage_indices.emplace(id, stage_index++);
			successors.emplace(id, std::vector<std::string>{});
			predecessors.emplace(id, std::vector<std::string>{});
			out_degree[id] = 0;
			in_degree[id] = 0;

			// Cache every graph entry and exit stage.
			if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_RX) {
				rx_stage_ids.push_back(id);
				rx_stage_id_set.insert(id);
				++rx_count;
			}
			if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_TX) {
				tx_stage_ids.push_back(id);
				tx_stage_id_set.insert(id);
				++tx_count;
			}
			if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4) {
				parse_ipv4_stage_ids.insert(id);
			}
			// Built-in packet-policy modules consume parsed IPv4/L4 metadata.
			if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
				const std::string &module_id = stage.module().module_id();
				if (module_id == "kinetum.acl" || module_id == "kinetum.nat44" ||
				    module_id == "kinetum.qos") {
					ipv4_consumer_stage_ids.push_back(id);
				}
			}
		}

		// Single pass over edges: build adjacency lists and compute degrees
		for (const auto &edge : p.edges()) {
			successors[edge.from_stage_id()].push_back(edge.to_stage_id());
			predecessors[edge.to_stage_id()].push_back(edge.from_stage_id());
			++out_degree[edge.from_stage_id()];
			++in_degree[edge.to_stage_id()];
		}
	}

	/**
	 * @brief Build an algo::dag<> representation for use with canonical algorithms.
	 *
	 * This allows Axiom validation to leverage algo/graph.hpp's canonical
	 * topological sort while retaining the extended metadata used by
	 * diagnostics.
	 *
	 * @return Identity-only DAG with the same graph structure.
	 * @throws std::bad_alloc If graph storage cannot be allocated.
	 * @throws std::length_error If graph storage exceeds its representable size.
	 */
	[[nodiscard]] kinetum::algo::dag<std::string> to_algo_dag() const
	{
		kinetum::algo::dag<std::string> g;

		// Add all nodes
		for (const auto &id : stage_ids) {
			g.add_node(id);
		}

		// Add all edges
		for (const auto &[from_id, succs] : successors) {
			for (const auto &to_id : succs) {
				g.add_edge(from_id, to_id);
			}
		}

		return g;
	}
};

/**
 * @brief Reject an exact duplicate packet-edge declaration.
 *
 * Endpoint reuse remains lawful when mode, condition, or priority differs.
 * PULL ownership applies its stricter endpoint-unique rule later.
 *
 * @param pipeline Pipeline whose complete packet-edge records are compared.
 * @return OK when every complete edge record is unique; INVALID_ARGUMENT
 *         otherwise.
 */
[[nodiscard]] static status verify_packet_edge_uniqueness(const kinetum::axiom::v1::Pipeline &pipeline)
{
	using edge_identity =
		std::tuple<std::string_view, std::string_view, std::string_view, int32_t, kinetum::axiom::v1::EdgeMode>;
	std::set<edge_identity> edges;
	for (const auto &edge : pipeline.edges()) {
		const edge_identity identity{edge.from_stage_id(), edge.to_stage_id(), edge.condition(),
					     edge.priority(), edge.mode()};
		if (!edges.insert(identity).second) {
			return status(status_code::INVALID_ARGUMENT,
				      "packet edge is declared more than once with identical semantics",
				      edge.from_stage_id() + " -> " + edge.to_stage_id());
		}
	}
	return status::ok();
}

/**
 * @brief Validate the complete normalized stage-affinity relation set.
 *
 * Affinity is undirected. A pair may be authored from either endpoint, but it
 * may appear only once and cannot also be an anti-affinity pair.
 *
 * @param pipeline Pipeline carrying stage constraints.
 * @param ctx Validated stage identity and compact-index authority.
 * @return OK for exact relations; INVALID_ARGUMENT otherwise.
 */
[[nodiscard]] static status verify_stage_constraints(const kinetum::axiom::v1::Pipeline &pipeline,
						     const validation_context &ctx)
{
	std::unordered_set<uint64_t> affinity_pairs;
	std::unordered_set<uint64_t> anti_affinity_pairs;
	affinity_pairs.reserve(static_cast<std::size_t>(pipeline.stages_size()));
	anti_affinity_pairs.reserve(static_cast<std::size_t>(pipeline.stages_size()));

	for (const auto &stage : pipeline.stages()) {
		const auto source = ctx.stage_indices.find(stage.stage_id());
		if (source == ctx.stage_indices.end()) {
			return status::internal_error(
				"validated stage identity disappeared before constraint admission");
		}
		const auto admit = [&](const std::string &target_id, bool affinity) -> status {
			const auto target = ctx.stage_indices.find(target_id);
			if (target == ctx.stage_indices.end()) {
				return status::invalid_argument("stage '" + stage.stage_id() +
								"' constraint references unknown stage '" + target_id +
								"'");
			}
			if (source->second == target->second) {
				return status::invalid_argument("stage '" + stage.stage_id() +
								"' cannot constrain itself");
			}
			const uint32_t low = std::min(source->second, target->second);
			const uint32_t high = std::max(source->second, target->second);
			const uint64_t relation = (static_cast<uint64_t>(low) << 32u) | high;
			auto &same = affinity ? affinity_pairs : anti_affinity_pairs;
			const auto &opposite = affinity ? anti_affinity_pairs : affinity_pairs;
			if (opposite.contains(relation)) {
				return status::invalid_argument(
					"stage constraint pair is both affinity and anti-affinity");
			}
			if (!same.insert(relation).second) {
				return status::invalid_argument("stage constraint pair is declared more than once");
			}
			return status::ok();
		};

		for (const auto &target : stage.constraints().affinity_stages()) {
			if (auto relation_status = admit(target, true); !relation_status.is_ok()) {
				return relation_status;
			}
		}
		for (const auto &target : stage.constraints().anti_affinity_stages()) {
			if (auto relation_status = admit(target, false); !relation_status.is_ok()) {
				return relation_status;
			}
		}
	}
	return status::ok();
}

//==============================================================================
// PUBLIC API IMPLEMENTATION
//==============================================================================

//==============================================================================
// VALIDATION PHASE 1: STRUCTURAL INVARIANTS
//==============================================================================

/**
 * @brief Verifies that all stage IDs are unique and non-empty.
 *
 * Structural Requirement: Each stage must have a unique identifier for:
 * - Edge references (from_stage_id, to_stage_id)
 * - Runtime stage lookup and packet routing
 * - Debugging and observability
 *
 * Algorithm: O(V) single-pass with hash set for duplicate detection.
 *
 * @param p Pipeline to validate
 * @return ok() if all IDs unique and non-empty, otherwise invalid_argument error
 */
[[nodiscard]] static status verify_ids_unique(const kinetum::axiom::v1::Pipeline &p)
{
	std::unordered_set<std::string> ids;
	ids.reserve(static_cast<size_t>(p.stages_size()));

	for (const auto &s : p.stages()) {
		// A stage identity becomes a component of generated worker, stream, and
		// boundary IDs, so Axiom owns the delimiter-safe grammar at authoring.
		if (s.stage_id().size() > MAX_STAGE_ID_LENGTH ||
		    !kinetum::common::execution_topology::is_topology_identifier(s.stage_id())) [[unlikely]] {
			return status::invalid_argument(
				"Pipeline validation failed: stage_id must match [A-Za-z_][A-Za-z0-9_]* within " +
				std::to_string(MAX_STAGE_ID_LENGTH) + " bytes");
		}

		// Check 2: Uniqueness requirement
		if (!ids.insert(s.stage_id()).second) [[unlikely]] {
			return status(status_code::INVALID_ARGUMENT,
				      "Pipeline validation failed: duplicate stage_id found", s.stage_id());
		}
	}

	return status::ok();
}

/**
 * @brief Verifies that all edges reference existing stages (no dangling edges).
 *
 * Structural Requirement: Every edge must connect two valid stages. Dangling
 * edges indicate authoring errors or incomplete pipeline definitions.
 *
 * Algorithm: O(E) using pre-built stage ID set from context.
 *
 * @param p Pipeline to validate
 * @param ctx Shared validation context with cached stage IDs
 * @return ok() if all edges valid, otherwise invalid_argument error
 */
[[nodiscard]] static status verify_edges_refer(const kinetum::axiom::v1::Pipeline &p, const validation_context &ctx)
{
	// Use cached stage IDs from context for O(1) lookup
	for (const auto &e : p.edges()) {
		if (!ctx.stage_ids.count(e.from_stage_id())) [[unlikely]] {
			return status(status_code::INVALID_ARGUMENT,
				      "Pipeline validation failed: edge references unknown from_stage_id",
				      e.from_stage_id());
		}
		if (!ctx.stage_ids.count(e.to_stage_id())) [[unlikely]] {
			return status(status_code::INVALID_ARGUMENT,
				      "Pipeline validation failed: edge references unknown to_stage_id",
				      e.to_stage_id());
		}
	}

	return status::ok();
}

//==============================================================================
// VALIDATION PHASE 2: TOPOLOGICAL INVARIANTS
//==============================================================================

/**
 * @brief Compute the canonical order from one structurally validated context.
 *
 * @param ctx Shared validation context with exact stage and edge ownership.
 * @return Smallest-ready-stage-first order, or a deterministic cycle diagnostic.
 */
[[nodiscard]] static status_or<std::vector<std::string>>
canonical_topological_order_from_context(const validation_context &ctx)
{
	auto dag = ctx.to_algo_dag();
	auto result = kinetum::algo::topological_sort(dag);

	if (!result.success) [[unlikely]] {
		// Build one bounded diagnostic from the deterministic Kahn remainder.
		std::string msg = "Pipeline validation failed: cycle detected";
		if (!result.blocked_nodes.empty()) {
			msg += "; blocked stages [";
			// Show up to five blocked nodes for bounded deterministic evidence.
			for (size_t i = 0; i < result.blocked_nodes.size() && i < 5; ++i) {
				if (i > 0)
					msg += ", ";
				msg += result.blocked_nodes[i];
			}
			if (result.blocked_nodes.size() > 5) {
				msg += ", ... (" + std::to_string(result.blocked_nodes.size() - 5) + " more)";
			}
			msg += "]";
		}
		return status(status_code::INVALID_ARGUMENT, msg);
	}

	return std::move(result.order);
}

/**
 * @brief Verify that the pipeline graph is acyclic through the canonical order authority.
 *
 * @param ctx Shared validation context with cached adjacency lists.
 * @return OK if acyclic, otherwise the canonical cycle diagnostic.
 */
[[nodiscard]] static status verify_no_cycles(const validation_context &ctx)
{
	auto order_or = canonical_topological_order_from_context(ctx);
	if (!order_or.is_ok()) {
		return order_or.error();
	}
	return status::ok();
}

/**
 * @brief Verifies that the pipeline has required RX (ingress) and TX (egress) stages.
 *
 * Topological Requirement: A valid pipeline must have entry and exit points:
 * - RX stage: Packet ingress from network interface
 * - TX stage: Packet egress to network interface
 *
 * With `require_single_ingress_egress=false`, multiple RX and TX stages are
 * allowed, but at least one of each remains mandatory. Exact port, stream,
 * lane, and worker ownership is resolved later by Gluon.
 *
 * @param ctx Shared validation context with cached RX/TX counts
 * @param opt Contract options (controls single vs. multi RX/TX)
 * @return ok() if RX/TX requirements met, otherwise invalid_argument error
 */
[[nodiscard]] static status verify_has_rx_tx(const validation_context &ctx, const contract_options &opt)
{
	// Use cached counts from context (no re-iteration needed)
	if (opt.require_single_ingress_egress) {
		// Strict mode: exactly one RX and one TX (for simple pipelines)
		if (ctx.rx_count != 1 || ctx.tx_count != 1) [[unlikely]] {
			return status(status_code::INVALID_ARGUMENT,
				      "Pipeline validation failed: require_single_ingress_egress=true requires exactly "
				      "one RX and one TX stage (found " +
					      std::to_string(ctx.rx_count) + " RX, " + std::to_string(ctx.tx_count) +
					      " TX)");
		}
	} else {
		// Multi-core mode: at least one RX and one TX required
		if (ctx.rx_count < 1) [[unlikely]] {
			return status(status_code::INVALID_ARGUMENT,
				      "Pipeline validation failed: pipeline requires at least one RX (ingress) stage");
		}
		if (ctx.tx_count < 1) [[unlikely]] {
			return status(status_code::INVALID_ARGUMENT,
				      "Pipeline validation failed: pipeline requires at least one TX (egress) stage");
		}
	}

	return status::ok();
}

//==============================================================================
// VALIDATION PHASE 3: CONNECTIVITY INVARIANTS
//==============================================================================

/**
 * @brief Validates edge condition syntax for 3-tier dispatch.
 *
 * Edge Condition Syntax: "field op value"
 * - field: src_ip, dst_ip, src_port, dst_port, proto, dscp, flow_hash
 * - op: ==, !=, <, <=, >, >=
 * - value: unsigned integer
 *
 * Edge Priority: Reasonable bounds [-1000, 1000]
 *
 * Empty condition strings are valid (unconditional edge).
 *
 * Algorithm: O(E) string parsing for condition validation.
 *
 * @param p Pipeline to validate
 * @return ok() if all edge conditions valid, otherwise invalid_argument error
 */
[[nodiscard]] static status verify_edge_conditions(const kinetum::axiom::v1::Pipeline &p)
{
	auto is_valid_field = [](std::string_view field) noexcept {
		return field == "src_ip" || field == "dst_ip" || field == "src_port" || field == "dst_port" ||
		       field == "proto" || field == "dscp" || field == "flow_hash";
	};

	for (const auto &edge : p.edges()) {
		const std::string &cond = edge.condition();

		// DP sorts every outgoing edge by priority, so the authoring contract
		// applies the range to conditional and unconditional edges alike.
		if (edge.priority() < -1000 || edge.priority() > 1000) {
			return status(status_code::INVALID_ARGUMENT,
				      "Edge priority " + std::to_string(edge.priority()) +
					      " out of range [-1000, 1000]"
					      " for edge " +
					      edge.from_stage_id() + " -> " + edge.to_stage_id(),
				      edge.from_stage_id());
		}

		// Empty condition is valid (unconditional)
		if (cond.empty()) {
			continue;
		}

		kinetum::algo::condition_expression parsed;
		kinetum::algo::condition_parse_error parse_error = kinetum::algo::condition_parse_error::NONE;
		if (!kinetum::algo::parse_condition_expression(cond, parsed, &parse_error)) {
			if (parse_error == kinetum::algo::condition_parse_error::TRAILING_TEXT) {
				return status(status_code::INVALID_ARGUMENT,
					      "Invalid trailing text in edge condition '" + cond + "' for edge " +
						      edge.from_stage_id() + " -> " + edge.to_stage_id(),
					      edge.from_stage_id());
			}
			if (parse_error == kinetum::algo::condition_parse_error::INVALID_VALUE) {
				return status(status_code::INVALID_ARGUMENT,
					      "Invalid edge condition value in '" + cond + "' for edge " +
						      edge.from_stage_id() + " -> " + edge.to_stage_id() +
						      ". Value must be a decimal uint32",
					      edge.from_stage_id());
			}
			if (parse_error == kinetum::algo::condition_parse_error::INVALID_FIELD ||
			    parse_error == kinetum::algo::condition_parse_error::EMPTY_CONDITION) {
				return status(
					status_code::INVALID_ARGUMENT,
					"Invalid edge condition field in '" + cond + "' for edge " +
						edge.from_stage_id() + " -> " + edge.to_stage_id() +
						". Valid fields: src_ip, dst_ip, src_port, dst_port, proto, dscp, flow_hash",
					edge.from_stage_id());
			}
			return status(status_code::INVALID_ARGUMENT,
				      "Invalid edge condition operator in '" + cond + "' for edge " +
					      edge.from_stage_id() + " -> " + edge.to_stage_id() +
					      ". Valid operators: ==, !=, <, <=, >, >=",
				      edge.from_stage_id());
		}

		if (!is_valid_field(parsed.field)) {
			return status(
				status_code::INVALID_ARGUMENT,
				"Invalid edge condition field '" + std::string(parsed.field) + "' in condition '" +
					cond + "' for edge " + edge.from_stage_id() + " -> " + edge.to_stage_id() +
					". Valid fields: src_ip, dst_ip, src_port, dst_port, proto, dscp, flow_hash",
				edge.from_stage_id());
		}
	}

	return status::ok();
}

/**
 * @brief Verifies DAG connectivity: no orphans (except RX), no dead-ends (except TX).
 *
 * Orphan Detection: A stage with no incoming edges is an orphan unless it is an RX stage.
 * Orphans are unreachable from any RX and indicate incomplete pipeline wiring.
 *
 * Dead-End Detection: A stage with no outgoing edges is a dead-end unless it is a TX stage.
 * Dead-ends cannot forward packets to any TX and indicate incomplete pipeline wiring.
 *
 * With multiple RX stages, every RX may have no predecessor. With multiple TX
 * stages, every TX may have no successor. Membership checks use the cached
 * exact identity sets.
 *
 * Algorithm: O(V) using pre-computed degree maps and RX/TX sets from context.
 *
 * @param p Pipeline to validate (for iterating stages in proto order)
 * @param ctx Shared validation context with cached degree maps and RX/TX ID sets
 * @return ok() if no orphans or dead-ends, otherwise failed_precondition error
 */
[[nodiscard]] static status verify_no_orphans_or_dead_ends(const kinetum::axiom::v1::Pipeline &p,
							   const validation_context &ctx)
{
	for (const auto &stage : p.stages()) {
		const auto &id = stage.stage_id();

		// Check for orphan stages (no incoming edges, but not an RX stage)
		// Multi-core: Use O(1) set lookup to check if this is ANY RX stage
		auto in_it = ctx.in_degree.find(id);
		if (in_it != ctx.in_degree.end() && in_it->second == 0) {
			if (!ctx.rx_stage_id_set.count(id)) [[unlikely]] {
				return status(status_code::FAILED_PRECONDITION,
					      "Pipeline validation failed: orphan stage detected (no incoming edges). "
					      "Only RX stages are allowed to have no predecessors",
					      id);
			}
		}

		// Check for dead-end stages (no outgoing edges, but not a TX stage)
		// Multi-core: Use O(1) set lookup to check if this is ANY TX stage
		auto out_it = ctx.out_degree.find(id);
		if (out_it != ctx.out_degree.end() && out_it->second == 0) {
			if (!ctx.tx_stage_id_set.count(id)) [[unlikely]] {
				return status(
					status_code::FAILED_PRECONDITION,
					"Pipeline validation failed: dead-end stage detected (no outgoing edges). "
					"Only TX stages are allowed to have no successors",
					id);
			}
		}
	}

	return status::ok();
}

/**
 * @brief Verifies full connectivity: all stages must be on a path from some RX to some TX.
 *
 * With multiple RX/TX stages, the connectivity requirement is:
 * - Forward reachability: Every stage must be reachable from AT LEAST ONE RX
 * - Backward reachability: Every stage must reach AT LEAST ONE TX
 * - Combined: All stages must lie on at least one path from some RX to some TX
 *
 * This ensures:
 * - No orphaned stages (disconnected subgraphs)
 * - No dead-end paths (stages that can't reach any TX)
 * - No unreachable stages (stages that no RX can reach)
 *
 * Algorithm: Two multi-source breadth-first searches (BFS):
 * 1. Forward BFS from all RX stages (computes forward reachability set)
 * 2. Backward BFS from all TX stages (computes backward reachability set)
 * 3. Intersection check: every stage must be in both sets
 *
 * Complexity: O(V + E) using pre-built adjacency lists from context
 *
 * @param ctx Shared validation context with cached adjacency lists and RX/TX ID vectors
 * @return ok() if fully connected, otherwise failed_precondition error
 */
[[nodiscard]] static status verify_reachable_rx_to_tx(const validation_context &ctx)
{
	// Use cached RX/TX stage ID vectors from context
	if (ctx.rx_stage_ids.empty()) [[unlikely]] {
		return status(status_code::INVALID_ARGUMENT, "Pipeline validation failed: missing RX (ingress) stage");
	}
	if (ctx.tx_stage_ids.empty()) [[unlikely]] {
		return status(status_code::INVALID_ARGUMENT, "Pipeline validation failed: missing TX (egress) stage");
	}

	// Forward BFS: compute all stages reachable from any RX stage.
	std::unordered_set<std::string> reachable_from_rx;
	reachable_from_rx.reserve(ctx.stage_ids.size());
	std::deque<std::string> queue;

	// Seed with all RX stages.
	for (const auto &rx_id : ctx.rx_stage_ids) {
		queue.push_back(rx_id);
		reachable_from_rx.insert(rx_id);
	}

	while (!queue.empty()) {
		auto current = queue.front();
		queue.pop_front();
		auto succ_it = ctx.successors.find(current);
		if (succ_it != ctx.successors.end()) {
			for (const auto &next : succ_it->second) {
				if (reachable_from_rx.insert(next).second) {
					queue.push_back(next);
				}
			}
		}
	}

	// Check: at least one TX must be reachable from RX stages
	bool any_tx_reachable = false;
	for (const auto &tx_id : ctx.tx_stage_ids) {
		if (reachable_from_rx.count(tx_id)) {
			any_tx_reachable = true;
			break;
		}
	}
	if (!any_tx_reachable) [[unlikely]] {
		return status(status_code::FAILED_PRECONDITION,
			      "Pipeline validation failed: no TX stage is reachable from any RX stage");
	}

	// Backward BFS: compute all stages that reach any TX stage.
	std::unordered_set<std::string> reaching_tx;
	reaching_tx.reserve(ctx.stage_ids.size());
	queue.clear();

	// Seed with all TX stages.
	for (const auto &tx_id : ctx.tx_stage_ids) {
		queue.push_back(tx_id);
		reaching_tx.insert(tx_id);
	}

	while (!queue.empty()) {
		auto current = queue.front();
		queue.pop_front();
		auto pred_it = ctx.predecessors.find(current);
		if (pred_it != ctx.predecessors.end()) {
			for (const auto &prev : pred_it->second) {
				if (reaching_tx.insert(prev).second) {
					queue.push_back(prev);
				}
			}
		}
	}

	// Check: every stage must be on a path from some RX to some TX
	for (const auto &id : ctx.stage_ids) {
		const bool on_rx_to_tx_path = reachable_from_rx.count(id) && reaching_tx.count(id);

		if (!on_rx_to_tx_path) [[unlikely]] {
			return status(status_code::FAILED_PRECONDITION,
				      "Pipeline validation failed: stage is not on any path from any RX to any TX", id);
		}
	}

	return status::ok();
}

/**
 * @brief Verifies linear topology constraint (at most one successor/predecessor per stage).
 *
 * Linearity Requirement (optional, controlled by contract_options):
 * - Each stage must have at most 1 outgoing edge (successor)
 * - Each stage must have at most 1 incoming edge (predecessor)
 * - Result: strict linear chain RX -> S1 -> S2 -> ... -> TX
 *
 * Benefits of linearity:
 * - Simplified downstream graph lowering
 * - Easier debugging and visualization
 * - Reduced runtime complexity
 *
 * Algorithm: Uses pre-computed degree maps from context.
 * Complexity: O(V) - degrees already computed
 *
 * @param ctx Shared validation context with cached degree maps
 * @return ok() if linear, otherwise failed_precondition error
 */
[[nodiscard]] static status verify_linear_if_required(const validation_context &ctx)
{
	// Use cached degree maps from context (no re-computation needed)

	// Check out-degree constraint (no branching)
	for (const auto &[stage_id, degree] : ctx.out_degree) {
		if (degree > 1) [[unlikely]] {
			return status(status_code::FAILED_PRECONDITION,
				      "Pipeline validation failed: non-linear topology (out-degree > 1) at stage",
				      stage_id);
		}
	}

	// Check in-degree constraint (no merging)
	for (const auto &[stage_id, degree] : ctx.in_degree) {
		if (degree > 1) [[unlikely]] {
			return status(status_code::FAILED_PRECONDITION,
				      "Pipeline validation failed: non-linear topology (in-degree > 1) at stage",
				      stage_id);
		}
	}

	return status::ok();
}

//==============================================================================
// VALIDATION PHASE 4: SEMANTIC DEPENDENCY RULES
//==============================================================================

/**
 * @brief Verifies semantic dependency rules between stage types.
 *
 * Semantic Rule: every RX path to ACL, NAT44, or QoS crosses PARSE_IPV4.
 *
 * Rationale: These stages need parsed packet headers to function correctly:
 * - ACL: Access control based on IP 5-tuple (src/dst IP, port, protocol)
 * - NAT44: Network address translation requires IP header access
 * - QoS: Quality of service classification uses IP/transport headers
 *
 * PARSE_IPV4 extracts and validates IPv4 headers, making them available
 * to downstream stages for match-action processing.
 *
 * @param ctx Shared validation context with cached stage kind flags
 * @return ok() if dependencies satisfied, otherwise failed_precondition error
 */
[[nodiscard]] static status verify_semantic_dependencies(const validation_context &ctx)
{
	if (ctx.ipv4_consumer_stage_ids.empty()) {
		return status::ok();
	}

	// Traverse exactly the packet paths that have not crossed a parser. Parser
	// stages are barriers: their successors receive parsed metadata and do not
	// belong to this set unless another parser-free path reaches them.
	std::unordered_set<std::string> reachable_without_parse;
	reachable_without_parse.reserve(ctx.stage_ids.size());
	std::deque<std::string> pending;
	for (const auto &rx_id : ctx.rx_stage_ids) {
		reachable_without_parse.insert(rx_id);
		pending.push_back(rx_id);
	}
	while (!pending.empty()) {
		std::string current = std::move(pending.front());
		pending.pop_front();
		if (ctx.parse_ipv4_stage_ids.contains(current)) {
			continue;
		}
		const auto successors = ctx.successors.find(current);
		if (successors == ctx.successors.end()) {
			continue;
		}
		for (const auto &next : successors->second) {
			if (reachable_without_parse.insert(next).second) {
				pending.push_back(next);
			}
		}
	}

	for (const auto &stage_id : ctx.ipv4_consumer_stage_ids) {
		if (reachable_without_parse.contains(stage_id)) [[unlikely]] {
			return status(status_code::FAILED_PRECONDITION,
				      "Pipeline validation failed: built-in module is reachable from RX without "
				      "PARSE_IPV4",
				      stage_id);
		}
	}

	return status::ok();
}

//==============================================================================
// SIZE LIMIT VALIDATION
//==============================================================================

/**
 * @brief Verifies pipeline size limits.
 *
 * Prevents denial-of-service via excessively large pipelines and ensures
 * that pipelines fit within runtime capacity limits.
 *
 * @param p Pipeline to validate
 * @return ok() if within limits, otherwise invalid_argument error
 */
[[nodiscard]] static status verify_size_limits(const kinetum::axiom::v1::Pipeline &p)
{
	if (p.stages_size() > MAX_PIPELINE_STAGES) [[unlikely]] {
		return status(status_code::INVALID_ARGUMENT, "Pipeline validation failed: too many stages (" +
								     std::to_string(p.stages_size()) + " > " +
								     std::to_string(MAX_PIPELINE_STAGES) + ")");
	}

	const uint64_t total_edges =
		static_cast<uint64_t>(p.edges_size()) + static_cast<uint64_t>(p.control_edges_size());
	if (total_edges > static_cast<uint64_t>(MAX_PIPELINE_EDGES)) [[unlikely]] {
		return status(status_code::INVALID_ARGUMENT,
			      "Pipeline validation failed: packet and control edges exceed the shared bound (" +
				      std::to_string(total_edges) + " > " + std::to_string(MAX_PIPELINE_EDGES) + ")");
	}

	return status::ok();
}

//==============================================================================
// MAIN VALIDATION ORCHESTRATORS
//==============================================================================

status_or<std::vector<std::string>> canonical_topological_order(const kinetum::axiom::v1::Pipeline &p)
{
	try {
		if (auto size_status = verify_size_limits(p); !size_status.is_ok()) {
			return size_status;
		}
		if (auto identity_status = verify_ids_unique(p); !identity_status.is_ok()) {
			return identity_status;
		}

		validation_context ctx;
		ctx.build(p);
		if (auto edge_status = verify_edges_refer(p, ctx); !edge_status.is_ok()) {
			return edge_status;
		}
		return canonical_topological_order_from_context(ctx);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Axiom topological ordering exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Axiom topological ordering exceeds the host size domain");
	}
}

/**
 * @brief Validate one exact pipeline through a single shared graph context.
 *
 * @param p Pipeline to validate without mutation.
 * @param opt Caller-selected topology requirements.
 * @return OK or the first semantic validation failure.
 */
[[nodiscard]] static status verify_contract_impl(const kinetum::axiom::v1::Pipeline &p, const contract_options &opt)
{
	if (auto s = kinetum::common::reject_unknown_protobuf_fields_recursive(p, "Axiom Pipeline"); !s.is_ok())
		[[unlikely]] {
		return s;
	}
	if (auto s = kinetum::common::reject_invalid_protobuf_enum_values_recursive(p, "Axiom Pipeline"); !s.is_ok())
		[[unlikely]] {
		return s;
	}

	// Phase 0: Size limit validation (DoS prevention)
	// Done first, before building context, to reject oversized pipelines early
	if (auto s = verify_size_limits(p); !s.is_ok()) [[unlikely]] {
		return s;
	}
	if (auto s = verify_authored_contract(p); !s.is_ok()) [[unlikely]] {
		return s;
	}
	if (auto s = verify_packet_edge_uniqueness(p); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Phase 1: Structural validation (IDs must be unique)
	if (auto s = verify_ids_unique(p); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Build graph membership, adjacency, degree, and stage-kind facts once.
	validation_context ctx;
	ctx.build(p);
	if (auto s = verify_stage_constraints(p, ctx); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Phase 1 (continued): Edge validation using cached stage IDs
	if (auto s = verify_edges_refer(p, ctx); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Phase 1 (continued): Edge condition syntax validation (3-tier dispatch)
	if (auto s = verify_edge_conditions(p); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Phase 2: Topological validation using cached RX/TX counts
	if (auto s = verify_has_rx_tx(ctx, opt); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Phase 2 (continued): Cycle detection using cached adjacency list
	if (auto s = verify_no_cycles(ctx); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Phase 3: DAG connectivity - orphan and dead-end detection
	// This provides specific error messages before the general reachability check
	if (auto s = verify_no_orphans_or_dead_ends(p, ctx); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Phase 3 (continued): Full connectivity validation using cached adjacency lists
	if (auto s = verify_reachable_rx_to_tx(ctx); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Phase 2 (continued): Linearity constraint using cached degree maps
	const bool allow_dag = p.allow_dag();
	if (!allow_dag || opt.require_linear_pipeline) {
		if (auto s = verify_linear_if_required(ctx); !s.is_ok()) [[unlikely]] {
			return s;
		}
	}

	// Phase 4: Semantic dependency validation using cached flags
	if (auto s = verify_semantic_dependencies(ctx); !s.is_ok()) [[unlikely]] {
		return s;
	}

	// Phase 5: Active-stage validation
	// Validates execution mode, authored trigger mask, exact synchronous
	// resource capacities, control edges, and PULL ownership.
	constexpr uint32_t LOOP_TRIGGER = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP);
	constexpr uint32_t TIMER_TRIGGER = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_TIMER);
	constexpr uint32_t PULL_TRIGGER = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_PULL_READY);
	constexpr uint32_t CONTROL_TRIGGER = static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_CONTROL);
	constexpr uint32_t AUTHORED_TRIGGER_MASK = LOOP_TRIGGER | TIMER_TRIGGER | PULL_TRIGGER | CONTROL_TRIGGER;
	std::unordered_map<std::string_view, const kinetum::axiom::v1::Stage *> stage_by_id;
	std::unordered_map<std::string_view, uint32_t> stage_index_by_id;
	std::unordered_map<std::string_view, uint32_t> inbound_control_count;
	std::unordered_map<std::string_view, uint32_t> outbound_pull_count;
	stage_by_id.reserve(static_cast<std::size_t>(p.stages_size()));
	stage_index_by_id.reserve(static_cast<std::size_t>(p.stages_size()));
	inbound_control_count.reserve(static_cast<std::size_t>(p.stages_size()));
	outbound_pull_count.reserve(static_cast<std::size_t>(p.stages_size()));
	uint32_t compact_stage_index = 0u;
	for (const auto &stage : p.stages()) {
		stage_by_id.emplace(stage.stage_id(), &stage);
		stage_index_by_id.emplace(stage.stage_id(), compact_stage_index++);
	}
	std::unordered_set<uint64_t> pull_endpoint_pairs;
	pull_endpoint_pairs.reserve(static_cast<std::size_t>(p.edges_size()));
	for (const auto &edge : p.edges()) {
		if (edge.mode() != kinetum::axiom::v1::EDGE_MODE_PULL) {
			continue;
		}
		++outbound_pull_count[edge.from_stage_id()];
		const auto source = stage_by_id.find(edge.from_stage_id());
		const auto destination = stage_by_id.find(edge.to_stage_id());
		const auto source_index = stage_index_by_id.find(edge.from_stage_id());
		const auto destination_index = stage_index_by_id.find(edge.to_stage_id());
		if (source_index != stage_index_by_id.end() && destination_index != stage_index_by_id.end()) {
			const uint64_t pair = (static_cast<uint64_t>(source_index->second) << 32u) |
					      destination_index->second;
			if (!pull_endpoint_pairs.insert(pair).second) {
				return status(status_code::INVALID_ARGUMENT,
					      "PULL endpoint pair is declared more than once");
			}
		}
		if (source != stage_by_id.end() && destination != stage_by_id.end() &&
		    (source->second->execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE ||
		     destination->second->execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE)) {
			return status(status_code::INVALID_ARGUMENT,
				      "PULL edge '" + edge.from_stage_id() + "' -> '" + edge.to_stage_id() +
					      "' requires active source and destination stages");
		}
	}
	std::unordered_set<uint64_t> control_endpoint_pairs;
	control_endpoint_pairs.reserve(static_cast<std::size_t>(p.control_edges_size()));
	for (const auto &edge : p.control_edges()) {
		++inbound_control_count[edge.to_stage_id()];
		const auto source = stage_by_id.find(edge.from_stage_id());
		const auto destination = stage_by_id.find(edge.to_stage_id());
		const auto source_index = stage_index_by_id.find(edge.from_stage_id());
		const auto destination_index = stage_index_by_id.find(edge.to_stage_id());
		if (source_index != stage_index_by_id.end() && destination_index != stage_index_by_id.end()) {
			const uint64_t pair = (static_cast<uint64_t>(source_index->second) << 32u) |
					      destination_index->second;
			if (!control_endpoint_pairs.insert(pair).second) {
				return status(status_code::INVALID_ARGUMENT,
					      "control endpoint pair is declared more than once");
			}
		}
		if (source != stage_by_id.end() && destination != stage_by_id.end() &&
		    (source->second->execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE ||
		     destination->second->execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE)) {
			return status(status_code::INVALID_ARGUMENT,
				      "synchronous control edge '" + edge.from_stage_id() + "' -> '" +
					      edge.to_stage_id() + "' requires active source and destination stages");
		}
	}
	for (int i = 0; i < p.stages_size(); ++i) {
		const auto &stage = p.stages(i);
		const auto &limits = stage.active_stage_limits();

		if (stage.execution_mode() == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
			// Active stages must be MODULE kind (runtime drives via module descriptor)
			if (stage.kind() != kinetum::axiom::v1::STAGE_KIND_MODULE) {
				return status(status_code::INVALID_ARGUMENT,
					      "active stage '" + stage.stage_id() + "' must use STAGE_KIND_MODULE");
			}

			if (stage.trigger_mask() == 0 || (stage.trigger_mask() & ~AUTHORED_TRIGGER_MASK) != 0u) {
				return status(status_code::INVALID_ARGUMENT,
					      "active stage '" + stage.stage_id() +
						      "' must declare only known authored trigger modes");
			}

			const bool retains_packets = limits.retained_packet_capacity() != 0u;
			const bool retains_bytes = limits.retained_byte_capacity() != 0u;
			if (retains_packets != retains_bytes ||
			    (retains_packets && limits.retained_byte_capacity() < limits.retained_packet_capacity())) {
				return status(status_code::INVALID_ARGUMENT,
					      "active stage '" + stage.stage_id() +
						      "' requires both retained capacities and bytes >= packets");
			}

			const bool timer_triggered = (stage.trigger_mask() & TIMER_TRIGGER) != 0u;
			if (timer_triggered != (limits.timer_capacity() != 0u)) {
				return status(status_code::INVALID_ARGUMENT,
					      "active stage '" + stage.stage_id() +
						      "' TIMER trigger and timer_capacity must be present together");
			}

			const bool control_triggered = (stage.trigger_mask() & CONTROL_TRIGGER) != 0u;
			const bool control_fields_present = limits.control_mailbox_capacity() != 0u ||
							    limits.control_message_capacity_bytes() != 0u;
			const bool control_capacity_valid =
				limits.control_mailbox_capacity() >= 2u &&
				(limits.control_mailbox_capacity() & (limits.control_mailbox_capacity() - 1u)) == 0u &&
				limits.control_message_capacity_bytes() != 0u;
			if (control_triggered != control_fields_present ||
			    (control_fields_present && !control_capacity_valid) ||
			    control_triggered != (inbound_control_count[stage.stage_id()] != 0u)) {
				return status(
					status_code::INVALID_ARGUMENT,
					"active stage '" + stage.stage_id() +
						"' CONTROL trigger, mailbox/payload capacity, and inbound edge must be exact");
			}

			const bool pull_triggered = (stage.trigger_mask() & PULL_TRIGGER) != 0u;
			if (pull_triggered != (outbound_pull_count[stage.stage_id()] != 0u)) {
				return status(status_code::INVALID_ARGUMENT,
					      "active stage '" + stage.stage_id() +
						      "' PULL_READY trigger and outbound PULL edge must be exact");
			}

			const bool async_capacity_present = limits.async_work_capacity() != 0u;
			const bool async_grace_present = limits.async_cancel_grace_ms() != 0u;
			if (async_capacity_present != async_grace_present) {
				return status(
					status_code::INVALID_ARGUMENT,
					"active stage '" + stage.stage_id() +
						"' async capacity and cancellation grace must be present together");
			}
		} else {
			if (stage.trigger_mask() != 0 || stage.schedule_order() != 0 ||
			    limits.retained_packet_capacity() != 0u || limits.retained_byte_capacity() != 0u ||
			    limits.timer_capacity() != 0u || limits.control_mailbox_capacity() != 0u ||
			    limits.control_message_capacity_bytes() != 0u || limits.async_work_capacity() != 0u ||
			    limits.async_cancel_grace_ms() != 0u) {
				return status(status_code::INVALID_ARGUMENT,
					      "passive stage '" + stage.stage_id() +
						      "' must not declare active triggers, schedule, or limits");
			}
		}
	}

	// Validate control edges: both endpoints must exist in the packet graph.
	for (int i = 0; i < p.control_edges_size(); ++i) {
		const auto &ce = p.control_edges(i);

		if (ctx.stage_ids.find(ce.from_stage_id()) == ctx.stage_ids.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      "control edge from_stage_id '" + ce.from_stage_id() + "' not found");
		}
		if (ctx.stage_ids.find(ce.to_stage_id()) == ctx.stage_ids.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      "control edge to_stage_id '" + ce.to_stage_id() + "' not found");
		}
	}

	// PULL endpoint mode is validated above through the same O(1) stage index;
	// Gluon adds the post-partition same-region proof.

	return status::ok();
}

kinetum::common::status verify_contract(const kinetum::axiom::v1::Pipeline &p, const contract_options &opt)
{
	try {
		return verify_contract_impl(p, opt);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Axiom contract validation exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Axiom contract validation exceeds the host size domain");
	}
}

}  // namespace kinetum::axiom
