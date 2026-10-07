// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file axiom_main.cpp
 * @brief Axiom Compiler Command-Line Interface
 * @author Fleming Patel
 *
 * `kinetum_axiom` loads one protobuf-text or MLIR pipeline, applies the same
 * exact semantic contract to either source, and emits validated protobuf text.
 * It never supplies an omitted mode, identity, edge, or stage configuration.
 *
 * Functionality:
 * - Load pipeline definitions from Protocol Buffer text format (.pbtxt)
 * - Load pipeline definitions from MLIR format (.mlir)
 * - Validate pipelines against Axiom semantic contract
 * - Emit validated pipelines in canonical .pbtxt format
 *
 * USAGE:
 * ======
 *   kinetum_axiom --in `input` --out `output` [--format pbtxt|mlir]
 *
 * Arguments:
 *   --in `path`      Input pipeline file (.pbtxt or .mlir)
 *   --out `path`     Output pipeline file (.axiom.pbtxt)
 *   --format `fmt`   Input format (pbtxt|mlir), auto-detected if omitted
 *   -h, --help       Show usage information
 *
 * Examples:
 *   # Load pbtxt, validate, and emit canonical form
 *   kinetum_axiom --in my_pipeline.pbtxt --out my_pipeline.axiom.pbtxt
 *
 *   # Load MLIR, validate, and emit pbtxt
 *   kinetum_axiom --in my_pipeline.mlir --out my_pipeline.axiom.pbtxt
 *
 *   # Explicit format specification
 *   kinetum_axiom --in input.txt --out output.pbtxt --format pbtxt
 *
 * Validation:
 * All pipelines are validated against the semantic contract before output:
 * - Structural checks (unique IDs, valid edges)
 * - Topological checks (acyclic, RX/TX present)
 * - Connectivity checks (all stages on path from RX to TX)
 * - Semantic checks (every RX path to a built-in IPv4 module crosses PARSE_IPV4)
 *
 * By default the CLI enforces a linear, single-ingress/single-egress
 * contract. Use --allow-dag to relax both linearity and
 * single-ingress/egress constraints for DAG pipelines.
 *
 * Exit codes:
 * 0: Success (pipeline validated and written)
 * 1: Error (validation failed, file I/O error, etc.)
 * 2: Usage error (missing arguments, invalid flags)
 *
 * Input format is selected explicitly or from the `.mlir` suffix; every other
 * source is parsed as protobuf text. Unknown and incomplete options reject.
 */

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

#include "src/common/log.hpp"
#include "src/common/pbtxt.hpp"
#include "src/axiom/axiom_contract.hpp"
#include "src/axiom/axiom_mlir_frontend.hpp"
#include "src/axiom/axiom_pbtxt_io.hpp"

namespace
{

//==============================================================================
// COMMAND-LINE UTILITIES
//==============================================================================

/**
 * @brief Prints usage information to stderr.
 */
void print_usage()
{
	std::cerr << "Usage:\n"
		  << "  kinetum_axiom --in <input> --out <output> [--format pbtxt|mlir] [--allow-dag]\n"
		  << "\n"
		  << "Arguments:\n"
		  << "  --in <path>      Input pipeline file (.pbtxt or .mlir)\n"
		  << "  --out <path>     Output pipeline file (.axiom.pbtxt)\n"
		  << "  --format <fmt>   Input format (pbtxt|mlir), auto-detected if omitted\n"
		  << "  --allow-dag      Allow DAG pipelines (multi-ingress fan-in, fan-out)\n"
		  << "  -h, --help       Show this help message\n"
		  << "\n"
		  << "Examples:\n"
		  << "  kinetum_axiom --in pipeline.pbtxt --out pipeline.axiom.pbtxt\n"
		  << "  kinetum_axiom --in pipeline.mlir --out pipeline.axiom.pbtxt\n"
		  << "  kinetum_axiom --in fan_in.pbtxt --out fan_in.axiom.pbtxt --allow-dag\n";
}

}  // namespace

//==============================================================================
// MAIN ENTRY POINT
//==============================================================================

/**
 * @brief Axiom compiler main entry point.
 *
 * Parses command-line arguments, loads and validates pipeline, emits output.
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @return Exit code (0=success, 1=error, 2=usage error)
 */
int main(int argc, char **argv)
{
	kinetum::common::set_command_log_identity("kinetum_axiom");
	// Command-line argument storage
	std::string input_path;
	std::string output_path;
	std::string input_format;
	bool allow_dag = false;

	// Parse command-line arguments
	for (int i = 1; i < argc; ++i) {
		std::string_view arg = argv[i];

		if (arg == "--in" && i + 1 < argc) {
			input_path = argv[++i];
		} else if (arg == "--out" && i + 1 < argc) {
			output_path = argv[++i];
		} else if (arg == "--format" && i + 1 < argc) {
			input_format = argv[++i];
		} else if (arg == "--allow-dag") {
			allow_dag = true;
		} else if (arg == "-h" || arg == "--help") {
			print_usage();
			return EXIT_SUCCESS;
		} else {
			std::cerr << "kinetum_axiom: error: unknown argument: " << arg << "\n";
			print_usage();
			return 2;
		}
	}

	// Validate required arguments
	if (input_path.empty() || output_path.empty()) {
		std::cerr << "kinetum_axiom: error: missing required arguments\n";
		print_usage();
		return 2;
	}

	// Auto-detect input format if not specified
	if (input_format.empty()) {
		if (input_path.ends_with(".mlir")) {
			input_format = "mlir";
		} else {
			input_format = "pbtxt";
		}
	}

	// Load and validate pipeline based on input format
	kinetum::axiom::v1::Pipeline pipeline;

	if (input_format == "pbtxt") {
		// Load from Protocol Buffer text format
		kinetum::axiom::contract_options opts;
		opts.require_linear_pipeline = !allow_dag;
		opts.require_single_ingress_egress = !allow_dag;

		auto pipeline_or = kinetum::axiom::load_pipeline_pbtxt(input_path, opts);
		if (!pipeline_or.is_ok()) [[unlikely]] {
			const auto &error = pipeline_or.error();
			KINETUM_LOG_ERROR("kinetum_axiom", "axiom.pipeline.rejected", "{} ({})", error.message(),
					  error.details());
			return EXIT_FAILURE;
		}

		pipeline = pipeline_or.value();
	} else if (input_format == "mlir") {
		// Load from MLIR format
		kinetum::axiom::contract_options mlir_opts;
		mlir_opts.require_linear_pipeline = !allow_dag;
		mlir_opts.require_single_ingress_egress = !allow_dag;

		auto pipeline_or = kinetum::axiom::load_pipeline_mlir(input_path, mlir_opts);
		if (!pipeline_or.is_ok()) [[unlikely]] {
			const auto &error = pipeline_or.error();
			KINETUM_LOG_ERROR("kinetum_axiom", "axiom.pipeline.rejected", "{} ({})", error.message(),
					  error.details());
			return EXIT_FAILURE;
		}

		pipeline = pipeline_or.value();
	} else {
		std::cerr << "kinetum_axiom: error: unknown input format: " << input_format << "\n";
		std::cerr << "Supported formats: pbtxt, mlir\n";
		return 2;
	}

	// Write validated pipeline to output file
	auto write_status = kinetum::common::write_pbtxt_file(output_path, pipeline);
	if (!write_status.is_ok()) [[unlikely]] {
		KINETUM_LOG_ERROR("kinetum_axiom", "axiom.output.failed", "Failed to write output: {}",
				  write_status.message());
		return EXIT_FAILURE;
	}

	KINETUM_LOG_INFO("kinetum_axiom", "axiom.output.written", "Successfully compiled pipeline to: {}", output_path);
	return EXIT_SUCCESS;
}
