// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file axiom_ops.cpp
 * @brief Implementation of Axiom MLIR Operations (TableGen Generated)
 * @author Fleming Patel
 *
 * IMPLEMENTATION NOTES:
 * ====================
 * This file includes the TableGen-generated operation implementations from
 * AxiomOps.cpp.inc. The generated code provides:
 *
 * - **Operation Builders**: Factory methods for creating operations
 * - **Attribute Accessors**: Getters/setters for operation attributes
 * - **Verification Logic**: Automatic verification based on ODS constraints
 * - **Printer/Parser**: MLIR syntax support for operations
 *
 * GENERATED CONTENT:
 * =================
 * The GET_OP_DEFINITIONS macro expands to:
 *
 * - CoreStageOp class implementation
 *   - build() methods for operation construction
 *   - getStageId(), getKind() attribute accessors
 *   - generated attribute presence/type verification
 *   - print()/parse() for MLIR serialization
 *
 * - CoreEdgeOp class implementation
 *   - build() methods for edge construction
 *   - getFrom(), getTo() attribute accessors
 *   - generated attribute presence/type verification
 *   - print()/parse() for MLIR serialization
 *
 * CUSTOM VERIFIERS:
 * ================
 * Stage-identity uniqueness and edge-reference checks are performed by the
 * `axiom_verify_pass`; the lowered protobuf then passes the complete Axiom
 * semantic contract.
 *
 * CONDITIONAL COMPILATION:
 * =======================
 * This file is conditionally compiled based on KINETUM_ENABLE_MLIR.
 * When MLIR is disabled, this compiles to an empty translation unit.
 *
 * @see axiom_ops.hpp for operation declarations
 * @see axiom_passes.hpp for additional verification passes
 */

#include "src/axiom/mlir/axiom_ops.hpp"

#if KINETUM_ENABLE_MLIR

// Include the generated operation implementations.
// GET_OP_DEFINITIONS expands to full class implementations for all operations
// defined in AxiomOps.td, including all interface methods.
#define GET_OP_DEFINITIONS
#include "AxiomOps.cpp.inc"

#endif	// KINETUM_ENABLE_MLIR
