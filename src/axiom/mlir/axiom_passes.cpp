// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file axiom_passes.cpp
 * @brief Implementation of Axiom MLIR Optimization and Verification Passes
 * @author Fleming Patel
 *
 * IMPLEMENTATION NOTES:
 * ====================
 * This file implements two MLIR passes for Axiom pipeline IR:
 *
 * 1. **axiom_canonicalize_pass**: Deterministic ordering of pipeline elements
 * 2. **axiom_verify_pass**: Semantic validation of pipeline constraints
 *
 * Both passes operate on mlir::ModuleOp and use the MLIR PassWrapper infrastructure.
 *
 * PASS IMPLEMENTATION PATTERN:
 * ===========================
 * Each pass follows the MLIR pass pattern:
 * - Inherits from mlir::PassWrapper<PassClass, mlir::OperationPass<mlir::ModuleOp>>
 * - Implements runOnOperation() for pass logic
 * - Uses MLIR_DEFINE_EXPLICIT_INTERNAL_INLINE_TYPE_ID for RTTI
 *
 * ERROR HANDLING:
 * ==============
 * - Canonicalize pass: Performs no semantic rejection; allocation exceptions
 *   propagate to the frontend boundary
 * - Verify pass: Calls signalPassFailure() on first error, emits MLIR diagnostics
 *
 * ALGORITHM DETAILS:
 * =================
 *
 * Canonicalization Algorithm:
 *   1. Partition operations into stages, edges, others
 *   2. Sort stages by stage_id (lexicographic)
 *   3. Sort edges by (from, to) tuple (lexicographic)
 *   4. Reorder: stages first, then edges, then others
 *   5. Use moveBefore() to maintain IR validity
 *
 * Verification Algorithm:
 *   1. First pass: Collect all stage_id values, check for duplicates
 *   2. Second pass: Validate edge references against collected stage_ids
 *   3. Fail on first error with descriptive diagnostic
 *
 * CONDITIONAL COMPILATION:
 * =======================
 * This file is conditionally compiled based on KINETUM_ENABLE_MLIR.
 *
 * @see axiom_passes.hpp for pass declarations
 * @see axiom_contract.hpp for protobuf-level validation
 */

#include "src/axiom/mlir/axiom_passes.hpp"

#if KINETUM_ENABLE_MLIR

#include <algorithm>
#include <string>
#include <unordered_set>
#include <vector>

#include "src/axiom/mlir/axiom_ops.hpp"

#include "mlir/IR/BuiltinOps.h"
#include "mlir/IR/Diagnostics.h"
#include "mlir/IR/Operation.h"
#include "mlir/Pass/Pass.h"

namespace kinetum::axiom::axiom_mlir
{

namespace
{

/**
 * @brief Extracts a string attribute from an MLIR operation.
 *
 * Utility function for safely extracting StringAttr values from operations.
 * Returns empty string if the operation is null or the attribute is not found.
 *
 * @param op The MLIR operation to query (may be null).
 * @param name The attribute name to look up.
 * @return The attribute value as std::string, or empty string if not found.
 *
 * @note Attribute materialization allocates and propagates allocation failure
 *       to the frontend's owning exception boundary.
 */
static std::string attr_string(mlir::Operation *op, const char *name)
{
	if (!op)
		return "";
	if (auto a = op->getAttrOfType<mlir::StringAttr>(name))
		return a.getValue().str();
	return "";
}

/**
 * @brief MLIR pass that gives Axiom operations deterministic module order.
 */
class axiom_canonicalize_pass final
	: public mlir::PassWrapper<axiom_canonicalize_pass, mlir::OperationPass<mlir::ModuleOp>> {
    public:
	MLIR_DEFINE_EXPLICIT_INTERNAL_INLINE_TYPE_ID(axiom_canonicalize_pass)

	/**
	 * @brief Reorder stages, edges, and other operations in the current module.
	 */
	void runOnOperation() override
	{
		auto mod = getOperation();
		auto *body = mod.getBody();
		if (!body)
			return;

		std::vector<mlir::Operation *> stages;
		std::vector<mlir::Operation *> edges;
		std::vector<mlir::Operation *> others;

		for (auto &op : body->getOperations()) {
			auto name = op.getName().getStringRef();
			if (name == "axiom.core.stage") {
				stages.push_back(&op);
			} else if (name == "axiom.core.edge") {
				edges.push_back(&op);
			} else {
				others.push_back(&op);
			}
		}

		std::sort(stages.begin(), stages.end(), [](mlir::Operation *a, mlir::Operation *b) {
			return attr_string(a, "stage_id") < attr_string(b, "stage_id");
		});

		std::sort(edges.begin(), edges.end(), [](mlir::Operation *a, mlir::Operation *b) {
			auto af = attr_string(a, "from");
			auto bf = attr_string(b, "from");
			if (af != bf)
				return af < bf;
			return attr_string(a, "to") < attr_string(b, "to");
		});

		// Reorder deterministically: stages, edges, then others.
		std::vector<mlir::Operation *> ordered;
		ordered.reserve(stages.size() + edges.size() + others.size());
		ordered.insert(ordered.end(), stages.begin(), stages.end());
		ordered.insert(ordered.end(), edges.begin(), edges.end());
		ordered.insert(ordered.end(), others.begin(), others.end());

		for (auto *op : ordered) {
			op->moveBefore(body, body->end());
		}
	}
};

/**
 * @brief MLIR pass that validates stage identifiers and edge references.
 */
class axiom_verify_pass final : public mlir::PassWrapper<axiom_verify_pass, mlir::OperationPass<mlir::ModuleOp>> {
    public:
	MLIR_DEFINE_EXPLICIT_INTERNAL_INLINE_TYPE_ID(axiom_verify_pass)

	/**
	 * @brief Validate the current module and signal pass failure on the first error.
	 */
	void runOnOperation() override
	{
		auto mod = getOperation();
		auto *body = mod.getBody();
		if (!body)
			return;

		std::unordered_set<std::string> stage_ids;

		for (auto &op : body->getOperations()) {
			auto name = op.getName().getStringRef();
			if (name != "axiom.core.stage")
				continue;
			auto sid = attr_string(&op, "stage_id");
			auto kind = attr_string(&op, "kind");
			if (sid.empty()) {
				op.emitError("axiom.core.stage missing required attribute: stage_id");
				signalPassFailure();
				return;
			}
			if (kind.empty()) {
				op.emitError("axiom.core.stage missing required attribute: kind");
				signalPassFailure();
				return;
			}
			if (stage_ids.count(sid)) {
				op.emitError("duplicate stage_id: ") << sid;
				signalPassFailure();
				return;
			}
			stage_ids.insert(sid);
		}

		for (auto &op : body->getOperations()) {
			auto name = op.getName().getStringRef();
			if (name != "axiom.core.edge")
				continue;
			auto f = attr_string(&op, "from");
			auto t = attr_string(&op, "to");
			if (f.empty() || t.empty()) {
				op.emitError("axiom.core.edge requires attributes: from, to");
				signalPassFailure();
				return;
			}
			if (!stage_ids.count(f)) {
				op.emitError("edge refers to unknown stage (from): ") << f;
				signalPassFailure();
				return;
			}
			if (!stage_ids.count(t)) {
				op.emitError("edge refers to unknown stage (to): ") << t;
				signalPassFailure();
				return;
			}
		}
	}
};

}  // namespace

std::unique_ptr<mlir::Pass> create_axiom_canonicalize_pass()
{
	return std::make_unique<axiom_canonicalize_pass>();
}

std::unique_ptr<mlir::Pass> create_axiom_verify_pass()
{
	return std::make_unique<axiom_verify_pass>();
}

}  // namespace kinetum::axiom::axiom_mlir

#endif	// KINETUM_ENABLE_MLIR
