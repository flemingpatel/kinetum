// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file axiom_mlir_frontend.hpp
 * @brief Axiom MLIR Frontend: Parse MLIR Dialect to Pipeline IR
 * @author Fleming Patel
 *
 * This module provides the optional MLIR authoring frontend for Axiom
 * pipelines. It accepts one closed passive-stage/PUSH-edge operation subset
 * and lowers through the same protobuf contract as the pbtxt frontend.
 *
 * OVERVIEW:
 * =========
 * The MLIR frontend supports two operational modes:
 *
 * 1. WITH AXIOM DIALECT (KINETUM_ENABLE_MLIR_DIALECT=ON):
 *    - Exact Axiom operation registration and type checking
 *    - Deterministic canonicalization and verification passes
 *
 * 2. WITHOUT AXIOM DIALECT (KINETUM_ENABLE_MLIR_DIALECT=OFF):
 *    - Generic parsing of the same exact operation and attribute vocabulary
 *    - Attribute-based extraction followed by the same protobuf contract
 *
 * BUILD CONFIGURATION:
 * ===================
 * The MLIR frontend requires KINETUM_ENABLE_MLIR=ON at build time.
 * Additionally, KINETUM_ENABLE_MLIR_DIALECT=ON enables the full Axiom dialect.
 *
 * CMake Configuration:
 *   cmake -DKINETUM_ENABLE_MLIR=ON -DKINETUM_ENABLE_MLIR_DIALECT=ON ..
 *
 * Without MLIR support, load_pipeline_mlir returns failed_precondition error.
 *
 * MLIR SYNTAX EXAMPLE:
 * ===================
 * Axiom pipelines in MLIR use the axiom.core dialect:
 *
 *   module attributes {pipeline_id = "minimal", allow_dag = false} {
 *     "axiom.core.stage"() { stage_id = "rx0", kind = "RX",
 *       execution_mode = "PASSIVE", interface = "wan0" } : () -> ()
 *     "axiom.core.stage"() { stage_id = "tx0", kind = "TX",
 *       execution_mode = "PASSIVE", interface = "lan0" } : () -> ()
 *     "axiom.core.edge"() { from = "rx0", to = "tx0", mode = "PUSH" } : () -> ()
 *   }
 *
 * COMPILATION PIPELINE:
 * ====================
 * MLIR -> Axiom Pipeline Proto -> later Gluon planning/runtime packaging
 *
 * 1. Parse .mlir file into MLIR module (mlir::ModuleOp)
 * 2. Run canonicalization passes (if dialect enabled)
 * 3. Run verification passes (if dialect enabled)
 * 4. Lower MLIR operations to Pipeline protobuf
 * 5. Validate the complete Axiom contract (same as pbtxt path)
 *
 * THREAD SAFETY:
 * =============
 * Thread-safe and reentrant. Each load operation uses isolated MLIR context.
 *
 * PERFORMANCE:
 * ===========
 * - Parsing: O(N) where N = input file size
 * - Passes: O(V + E) for canonicalization and verification
 * - Lowering: O(V + E) for proto construction
 */

#include <string>
#include <string_view>

#include "src/common/status_or.hpp"
#include "src/axiom/axiom_contract.hpp"
#include "gen/kinetum/axiom/v1/axiom.pb.h"

namespace kinetum::axiom
{

/**
 * @brief Loads an Axiom pipeline from an MLIR source file.
 *
 * This function parses MLIR input, optionally runs optimization and verification
 * passes, and lowers the result to an Axiom Pipeline protobuf message.
 *
 * Loading Steps:
 * 1. Create isolated MLIR context with dialect registry
 * 2. Parse .mlir file into mlir::ModuleOp
 * 3. Run canonicalization pass (if KINETUM_ENABLE_MLIR_DIALECT=ON)
 * 4. Run verification pass (if KINETUM_ENABLE_MLIR_DIALECT=ON)
 * 5. Lower MLIR operations to Pipeline protobuf
 * 6. Return one fully validated pipeline
 *
 * @param path Filesystem path to a readable source no larger than
 *        MAX_PIPELINE_SOURCE_BYTES.
 * @param opt Exact topology constraints applied during contract validation.
 *
 * @return status_or containing:
 *         - value: Pipeline protobuf lowered from MLIR (on success)
 *         - error: Detailed status with diagnostic message (on failure)
 *
 * Thread Safety: Thread-safe and reentrant (uses isolated MLIR context).
 * Complexity: O(N) for parsing, O(V + E) for passes and lowering
 *
 * Error Codes:
 * - failed_precondition: MLIR support not enabled (KINETUM_ENABLE_MLIR=OFF)
 * - not_found: File does not exist or cannot be read
 * - invalid_argument: Malformed MLIR syntax or verification failure
 * - resource_exhausted: Source or frontend allocation capacity was exceeded
 * - out_of_range: A frontend extent is not representable on the host
 *
 * Example:
 *   contract_options opts;
 *   auto result = load_pipeline_mlir("pipeline.mlir", opts);
 *   if (result.is_ok()) {
 *     auto pipeline = result.value();
 *   }
 */
[[nodiscard]] kinetum::common::status_or<kinetum::axiom::v1::Pipeline> load_pipeline_mlir(std::string_view path,
											  const contract_options &opt);

}  // namespace kinetum::axiom
