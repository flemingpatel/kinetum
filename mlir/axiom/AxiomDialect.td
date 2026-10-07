// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Axiom dialect declaration.
//
// Axiom is the semantic IR for Kinetum pipelines. We model stages and edges as MLIR ops
// so the compiler can run deterministic canonicalization and verification passes.
//
// Build with:
//   -DKINETUM_ENABLE_MLIR=ON -DKINETUM_ENABLE_MLIR_DIALECT=ON
//
include "mlir/IR/Dialect.td"

def Axiom_Dialect : Dialect {
  let name = "axiom";
  let cppNamespace = "::kinetum::axiom::axiom_mlir";
}
