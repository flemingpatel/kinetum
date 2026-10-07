// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file axiom_contract.hpp
 * @brief Axiom Pipeline Semantic Contract and Validation Framework
 * @author Fleming Patel
 *
 * This module defines the semantic contract and validation framework for Axiom pipelines,
 * ensuring that pipeline graphs meet all requirements for correct compilation and execution.
 *
 * OVERVIEW:
 * =========
 * Axiom represents packet processing pipelines as directed acyclic graphs (DAGs) where:
 * - Vertices (stages) represent processing units (RX, PARSE_IPV4,
 *   STAGE_KIND_MODULE policy stages, TX, etc.)
 * - Edges represent data flow paths between stages
 *
 * The contract layer provides early validation to:
 * - Reject invalid graphs before expensive compilation or deployment
 * - Enforce runtime-independent graph and stage semantics
 * - Ensure deterministic behavior across compilation runs
 * - Provide clear error diagnostics for pipeline authors
 *
 * PIPELINE IR CONTRACT:
 * ====================
 * A valid Axiom pipeline must satisfy the following invariants:
 *
 * 1. STRUCTURAL INVARIANTS:
 *    - All stage_id fields must be non-empty and unique within the pipeline
 *    - All edges must reference existing stages (no dangling edges)
 *    - The graph must be acyclic (DAG property)
 *    - At least one RX (ingress) and one TX (egress) stage must exist.
 *      contract_options can tighten this to exactly one of each.
 *
 * 2. CONNECTIVITY INVARIANTS:
 *    - Every stage must be reachable from RX via forward traversal
 *    - Every stage must reach TX via forward traversal
 *    - No orphaned or disconnected subgraphs allowed
 *
 * 3. LINEARITY CONSTRAINT (optional, caller-selected):
 *    - When required, each stage must have at most one predecessor and one successor
 *    - Creates a strict linear chain: RX -> S1 -> S2 -> ... -> TX
 *    - Useful for deliberately linear deployment shapes and debugging scenarios
 *
 * 4. SEMANTIC DEPENDENCIES:
 *    - Certain stage types require other stages to be present
 *    - Every RX path to a built-in module stage (kinetum.acl,
 *      kinetum.nat44, kinetum.qos) crosses PARSE_IPV4.
 *
 * USAGE PATTERNS:
 * ==============
 * Pipeline authoring flow:
 *   1. Author pipeline in .pbtxt or .mlir format
 *   2. Load via load_pipeline_pbtxt() or load_pipeline_mlir()
 *   3. Validate the complete typed contract (fails fast with clear diagnostics)
 *   4. Lower through Gluon into an exact provider graph
 *   5. Deploy to runtime
 *
 * Example:
 *   contract_options opts;
 *   opts.require_linear_pipeline = false;  // Allow DAGs
 *   auto pipeline_or = load_pipeline_pbtxt("pipeline.pbtxt", opts);
 *   if (!pipeline_or.is_ok()) {
 *     // Handle validation error with clear diagnostic message
 *   }
 *
 * Thread Safety: All functions are thread-safe and reentrant.
 * Performance: Validation is O(E + V log V) where V=stages, E=edges.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "gen/kinetum/axiom/v1/axiom.pb.h"

namespace kinetum::axiom
{

// =============================================================================
// Constants
// =============================================================================

/** Maximum number of stages allowed in a pipeline. */
inline constexpr int32_t MAX_PIPELINE_STAGES = 256;

/** Maximum aggregate packet-edge and control-edge records in one pipeline. */
inline constexpr int32_t MAX_PIPELINE_EDGES = 1024;

/** Maximum byte length of one stage identity. */
inline constexpr std::size_t MAX_STAGE_ID_LENGTH = 128;

/** Maximum byte length of one pipeline identity. */
inline constexpr std::size_t MAX_PIPELINE_ID_LENGTH = 128;

/** Maximum admitted protobuf-text or MLIR pipeline source size: 10 MiB. */
inline constexpr std::size_t MAX_PIPELINE_SOURCE_BYTES = std::size_t{10} * 1024u * 1024u;

/**
 * @brief Contract validation options for pipeline verification.
 *
 * These options control which validation rules are enforced during contract verification.
 * Different authoring workflows may require different topology constraint sets.
 *
 * Thread Safety: Copyable and movable; instances are typically stack-allocated.
 */
struct contract_options {
	/**
	 * @brief Require a strict linear pipeline topology.
	 *
	 * When true, each stage has at most one predecessor and one successor and
	 * the admitted graph is one RX-to-TX chain. False admits general DAG
	 * topology subject to the remaining contract rules.
	 */
	bool require_linear_pipeline = false;

	/**
	 * @brief Require exactly one RX and one TX stage.
	 *
	 * False permits multiple explicit RX/TX stages. Gluon still resolves every
	 * admitted stage to exact ports, streams, lanes, regions, and workers.
	 */
	bool require_single_ingress_egress = false;

	/** @brief Construct with neither optional topology restriction enabled. */
	constexpr contract_options() noexcept = default;
};

/**
 * @brief Compute Axiom's canonical topological order for one structural pipeline graph.
 *
 * Validates the stage/edge size bounds, nonempty unique stage identities,
 * exact edge references, and acyclicity. Ready stages are selected by smallest
 * stage identity, making the result deterministic across input declaration
 * order and process runs. This structural operation deliberately does not
 * require RX/TX stages, connectivity, stage-kind support, or semantic
 * dependencies; callers needing the complete pipeline contract must also use
 * verify_contract().
 *
 * @param p Pipeline graph to validate and order without mutation.
 * @return Canonical stage identities, or the first structural validation error.
 *
 * Thread Safety: Thread-safe and reentrant (const access only).
 * Expected Complexity: O(E + V log V).
 * Allocation failure returns RESOURCE_EXHAUSTED; an unrepresentable container
 * extent returns OUT_OF_RANGE.
 */
[[nodiscard]] kinetum::common::status_or<std::vector<std::string>>
canonical_topological_order(const kinetum::axiom::v1::Pipeline &p);

/**
 * @brief Verifies that a pipeline satisfies the Axiom semantic contract.
 *
 * Performs complete validation of pipeline structure, connectivity, and semantics
 * according to the rules defined in the contract. Validation is performed in phases:
 *
 * Phase 1: Authored and structural validation
 *   - Explicit pipeline identity, stage kind/configuration, and modes
 *   - Unique, canonical stage IDs
 *   - Unique complete packet-edge records
 *   - Valid edge references (no dangling pointers)
 *
 * Phase 2: Topological Validation
 *   - Acyclicity (DAG property)
 *   - Single RX/TX (if required)
 *   - Linearity (if required)
 *
 * Phase 3: Connectivity Validation
 *   - All stages reachable from RX
 *   - All stages reach TX
 *   - No orphaned subgraphs
 *
 * Phase 4: Semantic Validation
 *   - Stage dependency rules (every RX path to a built-in module crosses
 *     PARSE_IPV4)
 *
 * @param p Pipeline to validate (passed by const reference, not modified)
 * @param opt Contract options controlling which rules to enforce
 *
 * @return status::ok() if pipeline is valid, otherwise error with diagnostic message
 *
 * Thread Safety: Thread-safe and reentrant (const access only).
 * Complexity: O(E + V log V) where V = stages and E = packet plus control edges
 *
 * Error Diagnostics:
 * - invalid_argument: Malformed pipeline structure (bad IDs, edges, cycles)
 * - failed_precondition: Violated semantic constraints (missing RX/TX, unreachable stages)
 * - resource_exhausted: Validation allocation failed
 * - out_of_range: A validation container extent is unrepresentable
 *
 * Example:
 *   contract_options opts;
 *   opts.require_linear_pipeline = true;
 *   if (auto s = verify_contract(pipeline, opts); !s.is_ok()) {
 *     std::cerr << "Validation failed: " << s.message() << "\n";
 *     return EXIT_FAILURE;
 *   }
 */
[[nodiscard]] kinetum::common::status verify_contract(const kinetum::axiom::v1::Pipeline &p,
						      const contract_options &opt);

}  // namespace kinetum::axiom
