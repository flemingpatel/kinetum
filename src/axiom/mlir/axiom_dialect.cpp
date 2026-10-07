// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file axiom_dialect.cpp
 * @brief Implementation of Axiom MLIR Dialect Registration
 * @author Fleming Patel
 *
 * IMPLEMENTATION NOTES:
 * ====================
 * This file provides the implementation for the Axiom MLIR dialect by including
 * TableGen-generated definitions. The actual dialect logic is primarily in the
 * generated files (AxiomDialect.cpp.inc, AxiomOps.cpp.inc).
 *
 * TABLEGEN INTEGRATION:
 * ====================
 * The implementation uses MLIR's TableGen infrastructure:
 *
 * 1. **GET_OP_LIST**: Expands to a comma-separated list of operation class names
 *    for dialect registration (e.g., StageOp, EdgeOp).
 *
 * 2. **GET_DIALECT_DEFINITIONS**: Expands to the dialect class implementation,
 *    including the initialize() method that registers all operations.
 *
 * CONDITIONAL COMPILATION:
 * =======================
 * This entire file is conditionally compiled based on KINETUM_ENABLE_MLIR.
 * When MLIR support is disabled, this file compiles to an empty translation unit.
 *
 * @note All operation-specific logic is in axiom_ops.cpp.
 * @see axiom_dialect.hpp for dialect declaration
 * @see axiom_ops.hpp for operation declarations
 */

#include "src/axiom/mlir/axiom_dialect.hpp"

#if KINETUM_ENABLE_MLIR

#include "src/axiom/mlir/axiom_ops.hpp"

#include "mlir/IR/DialectImplementation.h"

// Provide operation list to the generated dialect definitions.
// This macro expands to a comma-separated list of operation class names
// that will be registered with the dialect during initialization.
#define GET_OP_LIST
#include "AxiomOps.cpp.inc"

// Include the generated dialect implementation.
// This provides the AxiomDialect::initialize() method and other dialect mechanics.
#define GET_DIALECT_DEFINITIONS
#include "AxiomDialect.cpp.inc"

#endif	// KINETUM_ENABLE_MLIR
