// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file axiom_passes.hpp
 * @brief Axiom MLIR Optimization and Verification Passes
 * @author Fleming Patel
 *
 * OVERVIEW:
 * =========
 * This header declares MLIR passes for canonicalization and verification of
 * Axiom pipeline IR. These passes are intentionally lightweight and focused
 * on ensuring deterministic compilation and early error detection.
 *
 * PASS CATALOG:
 * ============
 *
 * **AxiomCanonicalizePass** (create_axiom_canonicalize_pass):
 *   Ensures deterministic ordering of pipeline elements for reproducible builds.
 *
 *   Transformations:
 *   - Sorts stage operations by stage_id (lexicographic order)
 *   - Sorts edge operations by (from, to) tuple (lexicographic order)
 *   - Orders operations as: stages first, then edges, then others
 *
 *   Benefits:
 *   - Reproducible IR output across compilation runs
 *   - Easier diffing and code review of generated IR
 *   - Consistent caching behavior in build systems
 *
 *   Complexity: O(S log S + E log E) where S=stages, E=edges
 *
 * **AxiomVerifyPass** (create_axiom_verify_pass):
 *   Validates semantic constraints on Axiom pipeline operations.
 *
 *   Checks Performed:
 *   - All stages have non-empty stage_id attribute
 *   - All stages have non-empty kind attribute
 *   - All stage_id values are unique within the module
 *   - All edges have non-empty from and to attributes
 *   - All edge endpoints reference existing stage_id values
 *
 *   Error Handling:
 *   - Emits MLIR diagnostics (op.emitError) on first failure
 *   - Signals pass failure to stop pipeline execution
 *
 *   Complexity: O(S + E) where S=stages, E=edges
 *
 * USAGE:
 * ======
 * These passes are typically run in sequence on a ModuleOp:
 *
 * @code
 * mlir::PassManager pm(&context);
 * pm.addPass(kinetum::axiom::axiom_mlir::create_axiom_canonicalize_pass());
 * pm.addPass(kinetum::axiom::axiom_mlir::create_axiom_verify_pass());
 *
 * if (mlir::failed(pm.run(module))) {
 *   // Handle verification failure
 * }
 * @endcode
 *
 * DESIGN RATIONALE:
 * ================
 * The passes are designed to be:
 * - **Composable**: Can be used standalone or in pass pipelines
 * - **Fast**: O(V + E) complexity suitable for interactive use
 * - **Informative**: Clear error diagnostics with source locations
 * - **Deterministic**: Same input always produces same output
 *
 * BUILD REQUIREMENTS:
 * ==================
 * Requires MLIR support enabled at build time:
 *   cmake -DKINETUM_ENABLE_MLIR=ON -DKINETUM_ENABLE_MLIR_DIALECT=ON ..
 *
 * @note These passes complement (not replace) the protobuf-level contract validation.
 * @warning Including this header without KINETUM_ENABLE_MLIR=ON triggers a compile error.
 *
 * @see axiom_dialect.hpp for dialect definition
 * @see axiom_ops.hpp for operation definitions
 * @see axiom_contract.hpp for protobuf-level validation
 */

#if !KINETUM_ENABLE_MLIR
#error "axiom_passes.hpp included but KINETUM_ENABLE_MLIR=0"
#endif

#include <memory>

#include "mlir/Pass/Pass.h"

namespace kinetum::axiom::axiom_mlir
{

/**
 * @brief Creates the Axiom canonicalization pass.
 *
 * This pass reorders operations within a ModuleOp to ensure deterministic
 * ordering of pipeline elements. Stages are sorted by stage_id, edges are
 * sorted by (from, to) tuple, and all stages precede all edges in the output.
 *
 * @return A unique pointer to the canonicalization pass instance.
 *
 * @note The pass operates on mlir::ModuleOp and modifies it in-place.
 * @note This pass signals no semantic failure. Allocation exceptions propagate
 *       to the frontend's owning boundary.
 *
 * @see create_axiom_verify_pass for semantic validation
 */
std::unique_ptr<mlir::Pass> create_axiom_canonicalize_pass();

/**
 * @brief Creates the Axiom verification pass.
 *
 * This pass validates semantic constraints on Axiom pipeline operations,
 * checking for required attributes, unique identifiers, and valid edge
 * references. On failure, emits MLIR diagnostics and signals pass failure.
 *
 * @return A unique pointer to the verification pass instance.
 *
 * @note The pass operates on mlir::ModuleOp and does not modify it.
 * @warning On verification failure, the PassManager will stop execution.
 *
 * @see create_axiom_canonicalize_pass for deterministic ordering
 * @see axiom_contract.hpp for protobuf-level validation
 */
std::unique_ptr<mlir::Pass> create_axiom_verify_pass();

}  // namespace kinetum::axiom::axiom_mlir
