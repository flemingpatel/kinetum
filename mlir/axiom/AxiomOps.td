// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Exact Axiom MLIR operation declarations.
include "mlir/IR/OpBase.td"
include "AxiomDialect.td"

def Axiom_Core_StageOp : Op<Axiom_Dialect, "core.stage", []> {
  let cppClassName = "CoreStageOp";
  let summary = "Axiom stage declaration";
  let description = [{
    Declares one passive pipeline stage with exact typed configuration.
  }];

  let arguments = (ins
    StrAttr:$stage_id,
    StrAttr:$kind,
    StrAttr:$execution_mode,
    OptionalAttr<StrAttr>:$interface,
    OptionalAttr<StrAttr>:$module_id,
    OptionalAttr<StrAttr>:$module_path,
    OptionalAttr<StrAttr>:$context_selection
  );
}

def Axiom_Core_EdgeOp : Op<Axiom_Dialect, "core.edge", []> {
  let cppClassName = "CoreEdgeOp";
  let summary = "Axiom edge declaration";
  let arguments = (ins
    StrAttr:$from,
    StrAttr:$to,
    StrAttr:$mode
  );
}
