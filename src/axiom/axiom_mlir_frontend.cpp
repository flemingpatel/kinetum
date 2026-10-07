// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file axiom_mlir_frontend.cpp
 * @brief Implementation of Axiom MLIR Frontend
 * @author Fleming Patel
 *
 * The enabled implementation parses one module, optionally runs the registered
 * Axiom dialect passes, rejects every operation and attribute outside the
 * declared subset, lowers typed stage configuration, and invokes the ordinary
 * Axiom protobuf validator. A build without MLIR returns one capability error
 * before source discovery.
 */

#include "src/axiom/axiom_mlir_frontend.hpp"

#include <exception>
#include <initializer_list>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "src/common/file_io.hpp"
#include "src/common/status.hpp"

// MLIR headers (conditional on build configuration)
#if KINETUM_ENABLE_MLIR
#include "mlir/IR/BuiltinDialect.h"
#include "mlir/IR/BuiltinOps.h"
#include "mlir/IR/DialectRegistry.h"
#include "mlir/IR/MLIRContext.h"
#include "mlir/Parser/Parser.h"
#include "mlir/Pass/PassManager.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#endif	// KINETUM_ENABLE_MLIR

// Axiom dialect headers (conditional on dialect support)
#if KINETUM_ENABLE_MLIR && KINETUM_ENABLE_MLIR_DIALECT
#include "src/axiom/mlir/axiom_dialect.hpp"
#include "src/axiom/mlir/axiom_passes.hpp"
#endif	// KINETUM_ENABLE_MLIR && KINETUM_ENABLE_MLIR_DIALECT

namespace kinetum::axiom
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

//==============================================================================
// MLIR-ENABLED IMPLEMENTATION
//==============================================================================

#if KINETUM_ENABLE_MLIR

/**
 * @brief Parses stage kind string to StageKind enum value.
 *
 * This function maps MLIR attribute strings to protobuf enum values,
 * enabling lowering from MLIR operations to Pipeline protobuf.
 *
 * Supported Stage Kinds:
 * - RX: Packet ingress (receive)
 * - PARSE_IPV4: IPv4 header parsing
 * - TX: Packet egress (transmit)
 * - MODULE: SDK module stage (built-in or custom)
 *
 * @param kind_str Stage kind as string (extracted from MLIR attribute)
 * @return StageKind enum on success, invalid_argument error on unknown kind
 */
[[nodiscard]] static status_or<kinetum::axiom::v1::StageKind> parse_stage_kind(std::string_view kind_str)
{
	using kinetum::axiom::v1::StageKind;

	if (kind_str == "RX")
		return StageKind::STAGE_KIND_RX;
	if (kind_str == "TX")
		return StageKind::STAGE_KIND_TX;
	if (kind_str == "PARSE_IPV4")
		return StageKind::STAGE_KIND_PARSE_IPV4;
	if (kind_str == "MODULE")
		return StageKind::STAGE_KIND_MODULE;

	// Unknown stage kind - return error with diagnostic
	return status(status_code::INVALID_ARGUMENT, "MLIR lowering failed: unknown stage kind", std::string(kind_str));
}

/**
 * @brief Extracts string attribute from MLIR operation.
 *
 * This utility function safely extracts string attributes from MLIR operations,
 * handling null pointers and missing attributes gracefully.
 *
 * @param op MLIR operation to query (may be null)
 * @param attr_name Attribute name to extract
 * @return Attribute value as string, or empty string if not found
 */
[[nodiscard]] static std::string get_string_attribute(mlir::Operation *op, const char *attr_name)
{
	if (!op) [[unlikely]] {
		return "";
	}

	if (auto attr = op->getAttrOfType<mlir::StringAttr>(attr_name)) {
		return attr.getValue().str();
	}

	return "";
}

/**
 * @brief Extract one required boolean attribute.
 *
 * @param op Operation to inspect.
 * @param attr_name Exact attribute name.
 * @param output Non-null destination for the decoded value.
 * @return true only when the attribute exists with BoolAttr type.
 */
[[nodiscard]] static bool get_bool_attribute(mlir::Operation *op, const char *attr_name, bool *output)
{
	if (op == nullptr || output == nullptr) [[unlikely]] {
		return false;
	}
	if (auto attr = op->getAttrOfType<mlir::BoolAttr>(attr_name)) {
		*output = attr.getValue();
		return true;
	}
	return false;
}

/**
 * @brief Reject attributes outside one exact operation vocabulary.
 *
 * @param op Operation whose attribute dictionary is inspected.
 * @param allowed Complete accepted attribute-name set.
 * @param unexpected Non-null output receiving the first foreign name.
 * @return true when every attribute is declared by @p allowed.
 */
[[nodiscard]] static bool attributes_are_exact(mlir::Operation *op, std::initializer_list<std::string_view> allowed,
					       std::string *unexpected)
{
	if (op == nullptr || unexpected == nullptr) [[unlikely]] {
		return false;
	}
	for (const auto &attribute : op->getAttrs()) {
		const std::string name = attribute.getName().getValue().str();
		bool found = false;
		for (const std::string_view candidate : allowed) {
			if (name == candidate) {
				found = true;
				break;
			}
		}
		if (!found) {
			*unexpected = name;
			return false;
		}
	}
	return true;
}

#endif	// KINETUM_ENABLE_MLIR

//==============================================================================
// PUBLIC API IMPLEMENTATION
//==============================================================================

status_or<kinetum::axiom::v1::Pipeline> load_pipeline_mlir(std::string_view path, const contract_options &opt)
{
#if !KINETUM_ENABLE_MLIR
	// MLIR support disabled at build time - return error
	(void)path;
	(void)opt;
	return status(status_code::FAILED_PRECONDITION,
		      "MLIR support not enabled: rebuild with -DKINETUM_ENABLE_MLIR=ON");
#else
	// Wrap MLIR operations in try-catch to handle exceptions from external library
	try {
		// Step 1: Initialize MLIR context with dialect registry
		mlir::DialectRegistry registry;
		registry.insert<mlir::BuiltinDialect>();  // Always required

#if KINETUM_ENABLE_MLIR_DIALECT
		// Register Axiom dialect for full type checking and verification
		registry.insert<kinetum::axiom::axiom_mlir::AxiomDialect>();
#endif

		mlir::MLIRContext context(registry);

		// Step 2: Configure parsing strictness based on dialect availability
#if !KINETUM_ENABLE_MLIR_DIALECT
		// Without the generated dialect, exact Axiom operations parse through
		// MLIR's generic form and are validated below by name and attributes.
		context.allowUnregisteredDialects();
#endif

		// Step 3: Read the exact bounded source before MLIR parser allocation.
		const std::string source_name(path);
		auto source_bytes_or = kinetum::common::read_file_to_string(source_name, MAX_PIPELINE_SOURCE_BYTES);
		if (!source_bytes_or.is_ok()) [[unlikely]] {
			return std::move(source_bytes_or).error();
		}
		llvm::SourceMgr source_manager;
		auto input_file = llvm::MemoryBuffer::getMemBufferCopy(source_bytes_or.value(), source_name);
		if (!input_file) [[unlikely]] {
			return status::resource_exhausted("MLIR frontend could not allocate its bounded source buffer");
		}
		source_manager.AddNewSourceBuffer(std::move(input_file), llvm::SMLoc());

		auto module = mlir::parseSourceFile<mlir::ModuleOp>(source_manager, &context);
		if (!module) [[unlikely]] {
			return status(status_code::INVALID_ARGUMENT, "MLIR frontend failed: parse error in file",
				      std::string(path));
		}

		// Step 3b: Validate MLIR module structure before processing
		// This ensures the module is well-formed even without dialect verification
		if (mlir::failed(mlir::verify(*module))) [[unlikely]] {
			return status(status_code::INVALID_ARGUMENT, "MLIR frontend failed: module verification failed",
				      std::string(path));
		}

		// Step 4: Run optimization and verification passes (if dialect enabled)
#if KINETUM_ENABLE_MLIR_DIALECT
		mlir::PassManager pass_manager(&context);
		pass_manager.addPass(kinetum::axiom::axiom_mlir::create_axiom_canonicalize_pass());
		pass_manager.addPass(kinetum::axiom::axiom_mlir::create_axiom_verify_pass());

		if (mlir::failed(pass_manager.run(*module))) [[unlikely]] {
			return status(status_code::INVALID_ARGUMENT, "MLIR frontend failed: verification pass failed",
				      std::string(path));
		}
#endif

		// Step 5: Lower the exact supported MLIR surface to Pipeline protobuf.
		kinetum::axiom::v1::Pipeline pipeline;
		mlir::Operation *module_operation = module->getOperation();
		std::string unexpected_attribute;
		if (!attributes_are_exact(module_operation, {"pipeline_id", "allow_dag"}, &unexpected_attribute)) {
			return status(status_code::INVALID_ARGUMENT,
				      "MLIR frontend failed: module carries unknown attribute '" +
					      unexpected_attribute + "'",
				      std::string(path));
		}
		pipeline.set_pipeline_id(get_string_attribute(module_operation, "pipeline_id"));
		bool allow_dag = false;
		if (!get_bool_attribute(module_operation, "allow_dag", &allow_dag)) {
			return status(status_code::INVALID_ARGUMENT,
				      "MLIR frontend failed: module requires boolean allow_dag", std::string(path));
		}
		pipeline.set_allow_dag(allow_dag);

		for (mlir::Operation &operation : module->getBody()->getOperations()) {
			mlir::Operation *op = &operation;
			const std::string operation_name = op->getName().getStringRef().str();
			// ModuleOp owns this implicit structural terminator; it is not an
			// authored Axiom operation or an extension point.
			if (operation_name == "builtin.module_terminator") {
				continue;
			}
			if (operation_name == "axiom.core.stage") {
				unexpected_attribute.clear();
				if (!attributes_are_exact(op,
							  {"stage_id", "kind", "execution_mode", "interface",
							   "module_id", "module_path", "context_selection"},
							  &unexpected_attribute)) {
					return status(status_code::INVALID_ARGUMENT,
						      "MLIR frontend failed: stage carries unknown attribute '" +
							      unexpected_attribute + "'",
						      std::string(path));
				}

				auto *stage = pipeline.add_stages();
				stage->set_stage_id(get_string_attribute(op, "stage_id"));
				const std::string kind_text = get_string_attribute(op, "kind");
				auto kind_or = parse_stage_kind(kind_text);
				if (!kind_or.is_ok()) {
					return status(status_code::INVALID_ARGUMENT,
						      "MLIR frontend failed: unknown stage kind '" + kind_text + "'",
						      std::string(path));
				}
				stage->set_kind(kind_or.value());
				if (get_string_attribute(op, "execution_mode") != "PASSIVE") {
					return status(status_code::INVALID_ARGUMENT,
						      "MLIR frontend supports explicit PASSIVE stages only",
						      std::string(path));
				}
				stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);

				const std::string interface = get_string_attribute(op, "interface");
				const std::string module_id = get_string_attribute(op, "module_id");
				const std::string module_path = get_string_attribute(op, "module_path");
				const std::string selection = get_string_attribute(op, "context_selection");
				if (stage->kind() == kinetum::axiom::v1::STAGE_KIND_RX ||
				    stage->kind() == kinetum::axiom::v1::STAGE_KIND_TX) {
					if (interface.empty() || !module_id.empty() || !module_path.empty() ||
					    op->hasAttr("context_selection")) {
						return status(status_code::INVALID_ARGUMENT,
							      "MLIR I/O stage requires only one nonempty interface",
							      stage->stage_id());
					}
					stage->mutable_io()->set_interface(interface);
				} else if (stage->kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
					if (!interface.empty() || module_id.empty()) {
						return status(status_code::INVALID_ARGUMENT,
							      "MLIR module stage requires module_id and no interface",
							      stage->stage_id());
					}
					stage->mutable_module()->set_module_id(module_id);
					if (selection == "SAME_LANE") {
						stage->mutable_module()->set_context_selection(
							kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
					} else if (selection == "MODULE") {
						stage->mutable_module()->set_context_selection(
							kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_MODULE);
					} else {
						return status(
							status_code::INVALID_ARGUMENT,
							"MLIR module stage requires explicit SAME_LANE or MODULE context_selection",
							stage->stage_id());
					}
					if (op->hasAttr("module_path")) {
						stage->mutable_module()->set_module_path(module_path);
					}
				} else if (!interface.empty() || !module_id.empty() || !module_path.empty() ||
					   op->hasAttr("context_selection")) {
					return status(status_code::INVALID_ARGUMENT,
						      "MLIR PARSE_IPV4 stage must not carry configuration",
						      stage->stage_id());
				}
				continue;
			}

			if (operation_name == "axiom.core.edge") {
				unexpected_attribute.clear();
				if (!attributes_are_exact(op, {"from", "to", "mode"}, &unexpected_attribute)) {
					return status(status_code::INVALID_ARGUMENT,
						      "MLIR frontend failed: edge carries unknown attribute '" +
							      unexpected_attribute + "'",
						      std::string(path));
				}
				if (get_string_attribute(op, "mode") != "PUSH") {
					return status(status_code::INVALID_ARGUMENT,
						      "MLIR frontend supports explicit PUSH edges only",
						      std::string(path));
				}
				auto *edge = pipeline.add_edges();
				edge->set_from_stage_id(get_string_attribute(op, "from"));
				edge->set_to_stage_id(get_string_attribute(op, "to"));
				edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
				continue;
			}

			return status(status_code::INVALID_ARGUMENT,
				      "MLIR frontend failed: unsupported operation '" + operation_name + "'",
				      std::string(path));
		}

		if (const auto contract_status = verify_contract(pipeline, opt); !contract_status.is_ok()) {
			return contract_status;
		}
		return pipeline;

	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("MLIR frontend exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "MLIR frontend exceeds the host size domain");
	} catch (const std::exception &e) {
		// Catch exceptions from MLIR/LLVM libraries
		return status(status_code::INTERNAL_ERROR, "MLIR frontend failed: exception from MLIR library",
			      std::string(e.what()));
	} catch (...) {
		// Catch any other exceptions
		return status(status_code::INTERNAL_ERROR, "MLIR frontend failed: unknown exception from MLIR library");
	}
#endif	// KINETUM_ENABLE_MLIR
}

}  // namespace kinetum::axiom
