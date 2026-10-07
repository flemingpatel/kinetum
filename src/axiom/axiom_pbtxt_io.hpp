// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file axiom_pbtxt_io.hpp
 * @brief Axiom Pipeline Protocol Buffer Text I/O with Validation
 * @author Fleming Patel
 *
 * This module provides high-level I/O operations for Axiom pipeline definitions
 * in Protocol Buffer text format (.pbtxt), with integrated validation and
 * semantic contract enforcement.
 *
 * OVERVIEW:
 * =========
 * The pbtxt format is the primary authoring format for Axiom pipelines:
 * - Human-readable and version-control friendly
 * - Stable text suitable for review and manual editing
 * - Supports comments and documentation inline
 * - Direct mapping to protobuf schema (gen/kinetum/axiom/v1/axiom.proto)
 *
 * LOADING PIPELINE:
 * ================
 * The load operation performs these steps atomically:
 * 1. Parse .pbtxt file into Pipeline protobuf message
 * 2. Validate against the complete Axiom semantic contract
 * 3. Return the exact authored pipeline or a detailed error diagnostic
 *
 * Benefits of integrated validation:
 * - Fail-fast: Invalid pipelines rejected before compilation
 * - Clear diagnostics: Error messages include stage IDs and rule violations
 * - Consistency: All loaded pipelines guaranteed to satisfy contract
 *
 * EXAMPLE USAGE:
 * =============
 *   contract_options opts;
 *   auto pipeline_or = load_pipeline_pbtxt("my_pipeline.pbtxt", opts);
 *   if (!pipeline_or.is_ok()) {
 *     std::cerr << "Failed to load pipeline: " << pipeline_or.error().message() << "\n";
 *     return EXIT_FAILURE;
 *   }
 *   const auto& pipeline = pipeline_or.value();
 *
 *   // Load with custom contract options (allow DAGs, disable linearity check)
 *   contract_options custom_opts;
 *   custom_opts.require_linear_pipeline = false;
 *   auto dag_pipeline = load_pipeline_pbtxt("dag_pipeline.pbtxt", custom_opts);
 *
 * THREAD SAFETY:
 * =============
 * All functions are thread-safe and reentrant. Multiple threads can load
 * different pipeline files concurrently without synchronization.
 *
 * ERROR HANDLING:
 * ==============
 * Uses status_or<T> for error propagation with detailed diagnostics:
 * - not_found: File does not exist or cannot be opened
 * - invalid_argument: Malformed .pbtxt syntax or contract violation
 * - failed_precondition: Semantic constraint violation (e.g., missing RX/TX)
 */

#include <string>
#include <string_view>

#include "src/common/status_or.hpp"
#include "src/axiom/axiom_contract.hpp"
#include "gen/kinetum/axiom/v1/axiom.pb.h"

namespace kinetum::axiom
{

/**
 * @brief Loads an Axiom pipeline from a Protocol Buffer text file.
 *
 * This function provides integrated bounded parsing and validation in a single
 * operation. It never supplies an omitted identity, mode, or configuration.
 *
 * Loading Steps:
 * 1. Open and parse .pbtxt file (fails if file not found or malformed)
 * 2. Validate against contract rules specified in @p opt
 * 3. Return validated pipeline or detailed error
 *
 * @param path Filesystem path to a readable source no larger than
 *        MAX_PIPELINE_SOURCE_BYTES.
 * @param opt Exact topology constraints applied during contract validation.
 *
 * @return status_or containing:
 *         - value: Validated Pipeline protobuf message (on success)
 *         - error: Detailed status with diagnostic message (on failure)
 *
 * Thread Safety: Thread-safe and reentrant.
 * Complexity: O(V + E) for validation, plus file I/O overhead
 *
 * Error Codes:
 * - not_found: File does not exist or cannot be read
 * - invalid_argument: Malformed .pbtxt syntax or structural contract violation
 * - failed_precondition: Semantic constraint violation (connectivity, dependencies)
 * - resource_exhausted: Input bound or allocation capacity was exceeded
 * - out_of_range: A parser or validation extent is not representable
 *
 * Example:
 *   contract_options opts;
 *   opts.require_linear_pipeline = true;
 *   auto result = load_pipeline_pbtxt("/path/to/pipeline.pbtxt", opts);
 *   if (result.is_ok()) {
 *     const auto& pipeline = result.value();
 *     // Pipeline is guaranteed valid and ready for compilation
 *   } else {
 *     // Handle error: result.error().message() contains diagnostic
 *   }
 */
[[nodiscard]] kinetum::common::status_or<kinetum::axiom::v1::Pipeline> load_pipeline_pbtxt(std::string_view path,
											   const contract_options &opt);

}  // namespace kinetum::axiom
