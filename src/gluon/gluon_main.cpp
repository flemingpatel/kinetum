// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file gluon_main.cpp
 * @brief kinetum_gluon: Axiom pipeline + hardware inventory -> deployment plan.
 * @author Fleming Patel
 *
 * Gluon is the "planner" layer:
 *   Axiom pipeline + hardware inventory + exact deployment bindings -> DeploymentPlan
 *
 * The plan is deterministic for a given input + options. That determinism is
 * a core product feature (bundles, reproducibility, rollback).
 */

#include <charconv>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

#include "src/axiom/axiom_pbtxt_io.hpp"
#include "src/common/file_io.hpp"
#include "src/common/log.hpp"
#include "src/common/pbtxt.hpp"
#include "gen/kinetum/gluon/v1/bindings.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "src/gluon/gluon_planner.hpp"

namespace
{

/**
 * @brief Display usage information for the kinetum_gluon CLI.
 *
 * Prints command-line usage, available options, and usage examples
 * to stderr. Called when --help is specified or when required
 * arguments are missing.
 *
 * @note This function outputs to stderr and does not return a value.
 */
void usage()
{
	std::cerr << "Usage:\n"
		  << "  kinetum_gluon --axiom <pipeline.axiom.pbtxt> --hw <hardware_inventory.pbtxt>\n"
		  << "                 --bindings <deployment_bindings.pbtxt> --out <plan.pbtxt>\n"
		  << "                 [--regions N] [--reserved-cores N]\n"
		  << "\n"
		  << "Notes:\n"
		  << "  - --bindings is complete deployment intent; no provider, queue, storage,\n"
		  << "    execution, or transition default is inferred.\n"
		  << "  - --reserved-cores excludes the lowest logical cores from packet workers;\n"
		  << "    runtime services consume that pool first and unused remainder stays unassigned.\n";
}

/**
 * @brief Parse a base-10 int argument without accepting trailing junk.
 *
 * @param value Complete argument bytes.
 * @param[out] out Parsed value on success; unchanged on failure.
 * @return true only when every byte forms one representable decimal integer.
 */
bool parse_int_arg(const std::string &value, int &out) noexcept
{
	if (value.empty()) {
		return false;
	}
	auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), out);
	return ec == std::errc{} && ptr == value.data() + value.size();
}

}  // namespace

/**
 * @brief Main entry point for the kinetum_gluon pipeline planner CLI.
 *
 * Gluon transforms an Axiom pipeline IR and hardware inventory into an
 * executable DeploymentPlan. The planning process implements deterministic
 * algorithms for multi-region partitioning.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 *
 * @return Exit code:
 *         - 0: Success, plan written to output file.
 *         - 1: Planning failed (invalid input, constraint violation, etc.).
 *         - 2: Invalid command-line arguments.
 *
 * @par Required Arguments
 * - `--axiom <path>`: Path to Axiom pipeline pbtxt file.
 * - `--hw <path>`: Path to hardware inventory pbtxt file.
 * - `--out <path>`: Path for output DeploymentPlan pbtxt file.
 *
 * @par Optional Arguments
 * - `--regions N`: Number of execution regions/threads (default: 2).
 * - `--reserved-cores N`: Lowest logical cores excluded from packet workers
 *   and preferred for runtime services; unused remainder remains unassigned
 *   (default: 1).
 *
 * @par Required Deployment Intent
 * - `--bindings <path>`: Complete exact DeploymentBindings pbtxt.
 *
 * @note The generated plan is deterministic for identical inputs.
 *
 * @see kinetum::gluon::plan For the core planning algorithm.
 */
int main(int argc, char **argv)
{
	kinetum::common::set_command_log_identity("kinetum_gluon");
	try {
		std::string axiom_path;
		std::string hw_path;
		std::string out_path;
		std::string bindings_path;
		int regions = 2;
		int reserved_cores = 1;

		for (int i = 1; i < argc; i++) {
			std::string a = argv[i];
			if (a == "--axiom" && i + 1 < argc)
				axiom_path = argv[++i];
			else if (a == "--hw" && i + 1 < argc)
				hw_path = argv[++i];
			else if (a == "--out" && i + 1 < argc)
				out_path = argv[++i];
			else if (a == "--regions" && i + 1 < argc) {
				const std::string value = argv[++i];
				if (!parse_int_arg(value, regions)) {
					std::cerr << "Error: --regions requires a base-10 integer, got: " << value
						  << "\n";
					return 2;
				}
			} else if (a == "--reserved-cores" && i + 1 < argc) {
				const std::string value = argv[++i];
				if (!parse_int_arg(value, reserved_cores)) {
					std::cerr
						<< "Error: --reserved-cores requires a base-10 integer, got: " << value
						<< "\n";
					return 2;
				}
			} else if (a == "--bindings" && i + 1 < argc)
				bindings_path = argv[++i];
			else if (a == "-h" || a == "--help") {
				usage();
				return 0;
			} else {
				std::cerr << "Error: unknown or incomplete argument: " << a << "\n";
				usage();
				return 2;
			}
		}

		if (axiom_path.empty() || hw_path.empty() || bindings_path.empty() || out_path.empty()) {
			usage();
			return 2;
		}

		// Load Axiom pipeline (allow DAG; Gluon does topo ordering from RX).
		kinetum::axiom::contract_options lo;
		lo.require_linear_pipeline = false;

		auto p_or = kinetum::axiom::load_pipeline_pbtxt(axiom_path, lo);
		if (!p_or.is_ok()) {
			KINETUM_LOG_ERROR("gluon", "gluon.pipeline.rejected", "{}", p_or.error().message());
			return 1;
		}

		// Load hardware inventory.
		kinetum::hw::v1::HardwareInventory hw;
		auto hs = kinetum::common::read_pbtxt_file(hw_path, kinetum::common::DEFAULT_MAX_FILE_SIZE, &hw);
		if (!hs.is_ok()) {
			KINETUM_LOG_ERROR("gluon", "gluon.hardware.rejected", "{}", hs.message());
			return 1;
		}

		kinetum::gluon::planner_options opt;
		opt.regions = regions;
		opt.reserved_cores = reserved_cores;

		auto bs = kinetum::common::read_pbtxt_file(bindings_path, kinetum::common::DEFAULT_MAX_FILE_SIZE,
							   &opt.deployment_bindings);
		if (!bs.is_ok()) {
			KINETUM_LOG_ERROR("gluon", "gluon.bindings.rejected", "failed to read bindings file: {}",
					  bs.message());
			return 1;
		}

		auto plan_or = kinetum::gluon::plan(p_or.value(), hw, opt);
		if (!plan_or.is_ok()) {
			KINETUM_LOG_ERROR("gluon", "gluon.plan.failed", "{}", plan_or.error().message());
			return 1;
		}

		auto ws = kinetum::common::write_pbtxt_file(out_path, plan_or.value());
		if (!ws.is_ok()) {
			KINETUM_LOG_ERROR("gluon", "gluon.output.failed", "{}", ws.message());
			return 1;
		}

		KINETUM_LOG_INFO("gluon", "gluon.output.written", "wrote: {}", out_path);
		return 0;

	} catch (const std::exception &e) {
		std::cerr << "Error: " << e.what() << "\n";
		return 1;
	}
}
