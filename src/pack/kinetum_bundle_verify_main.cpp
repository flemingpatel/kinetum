// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file kinetum_bundle_verify_main.cpp
 * @brief Runtime-bundle integrity and semantic verification tool.
 * @author Fleming Patel
 *
 * @section bundle_verify_overview Overview
 * kinetum_bundle_verify admits a runnable Kinetum bundle through the same
 * verifier used by the packer and Photon. It verifies every manifest-bound
 * file, rejects symlink indirection, verifies the canonical deployment-plan
 * identity, and validates the complete bootstrap snapshot against that plan.
 *
 * @section verification_process Verification Process
 * 1. **Verify Paths**: Reject symlinks in the root, components, and bundle tree
 * 2. **Verify Manifest**: Check every file's size/SHA-256 and reject extra files
 * 3. **Verify Plan**: Require the exact canonical plan path and content hash
 * 4. **Verify Bootstrap**: Require the exact snapshot path, module set, and canonical hash
 * 5. **Report Results**: Exit with code 0 on success, 1 on verification failure
 *
 * @section integrity_boundary Integrity and Authority Boundary
 * - **Hash and Size Verification**: Compares every declared file with the
 *   exact admitted manifest row
 * - **Extra Files Detection**: Rejects undeclared regular files
 * - **Path Identity**: Rejects symbolic-link indirection
 * - **Semantic Identity**: Binds the snapshot to the exact verified plan
 * - **Authenticity Boundary**: The unsigned manifest does not authenticate its
 *   producer; trusted delivery remains an external deployment requirement
 *
 * @section bundle_verify_usage Usage Examples
 * ```bash
 * # Basic verification
 * kinetum_bundle_verify --bundle /path/to/bundle
 *
 * # Verify from within bundle directory
 * cd /path/to/bundle
 * /opt/kinetum/bin/kinetum_bundle_verify --bundle .
 *
 * # Use in CI/CD pipeline
 * if kinetum_bundle_verify --bundle /deploy/bundle; then
 *   echo "Bundle integrity and semantic admission verified"
 * else
 *   echo "Verification failed; do not deploy"
 *   exit 1
 * fi
 * ```
 *
 * @section bundle_verify_exit_codes Exit Codes
 * - 0: Success - all files verified, bundle integrity confirmed
 * - 1: Verification failed
 * - 2: Usage error - invalid command-line arguments
 *
 * @section manifest_location Manifest File Location
 * The tool reads the manifest from: `<bundle_dir>/BUNDLE_MANIFEST.txt`
 *
 * @section failure_modes Failure Modes
 * Verification fails if:
 * - Bundle root or manifest is missing or malformed
 * - Manifest product version differs from the verifier's exact version
 * - A symlink occurs in the supplied path or bundle tree
 * - Any file declared in manifest is missing
 * - Any file has incorrect size
 * - Any file has incorrect SHA-256 hash
 * - Bundle contains an undeclared file (integrity contradiction)
 * - The canonical plan or bootstrap snapshot is absent, malformed, or semantically invalid
 * - Filesystem I/O errors occur
 *
 * @section performance Performance
 * - Time complexity: O(n) where n is total bytes in bundle (SHA-256 dominates)
 * - Memory usage: O(m) where m is number of files (manifest storage)
 * - Runtime depends on storage throughput and SHA-256 implementation
 *
 */

#include <locale>
#include <sstream>
#include <string>
#include <string_view>

#include "src/common/process_output.hpp"
#include "src/pack/runtime_bundle.hpp"

namespace
{

/** @brief Successful runtime-bundle verification. */
constexpr int EXIT_CODE_SUCCESS = 0;

/** @brief Runtime-bundle integrity or semantic-admission failure. */
constexpr int EXIT_CODE_VERIFICATION_FAILED = 1;

/** @brief Invalid command-line arguments. */
constexpr int EXIT_CODE_USAGE_ERROR = 2;

/** Complete bundle-verifier usage text. */
constexpr std::string_view USAGE = "kinetum_bundle_verify - Verify runnable Kinetum bundles\n\n"
				   "Usage:\n"
				   "  kinetum_bundle_verify --bundle <bundle_dir>\n"
				   "  kinetum_bundle_verify -h | --help\n"
				   "\n"
				   "Arguments:\n"
				   "  --bundle <dir>    Path to bundle root directory\n"
				   "  -h, --help        Display this help message\n"
				   "\n"
				   "Description:\n"
				   "  Verifies manifest integrity, symlink-free canonical paths, the plan\n"
				   "  content identity, and the complete plan-bound bootstrap snapshot.\n"
				   "\n"
				   "Verification steps:\n"
				   "  1. Reject symlink indirection in the bundle path and tree\n"
				   "  2. Verify every manifest-bound file and reject extra files\n"
				   "  3. Verify configs/plan.pbtxt canonical content identity\n"
				   "  4. Validate configs/config_snapshot.pbtxt against that plan\n"
				   "\n"
				   "Exit codes:\n"
				   "  0 - Success: Bundle verified\n"
				   "  1 - Failure: Integrity violation detected\n"
				   "  2 - Error: Invalid command-line usage\n"
				   "\n"
				   "Examples:\n"
				   "  kinetum_bundle_verify --bundle /var/lib/kinetum/bundles/edge-v1\n"
				   "  cd /path/to/bundle && /opt/kinetum/bin/kinetum_bundle_verify --bundle .\n"
				   "\n";

/**
 * @brief Render one complete verification failure report.
 *
 * @param error Exact runtime-bundle admission failure.
 * @return Complete stderr bytes.
 */
[[nodiscard]] std::string render_failure(const kinetum::common::status &error)
{
	std::ostringstream output;
	output.exceptions(std::ios::badbit | std::ios::failbit);
	output.imbue(std::locale::classic());
	output << "\n";
	output << "================================================================\n";
	output << "VERIFICATION FAILED\n";
	output << "================================================================\n";
	output << "Error: " << error.message() << "\n";
	if (!error.details().empty()) {
		output << "Details: " << error.details() << "\n";
	}
	output << "================================================================\n";
	output << "\n";

	if (error.message().find("extra file") != std::string_view::npos) {
		output << "INTEGRITY ALERT: Bundle contains an undeclared file!\n";
		output << "This could indicate:\n";
		output << "  - Undeclared content injection\n";
		output << "  - Bundle contents changed after manifest generation\n";
		output << "  - Manifest not regenerated after adding files\n";
		output << "\n";
		output << "Action required:\n";
		output << "  1. Inspect the undeclared path in Details\n";
		output << "  2. If legitimate, regenerate the manifest\n";
		output << "  3. Reject the bundle if the path is unexpected\n";
	} else {
		output << "Bundle admission failed. Do NOT deploy this bundle.\n";
	}
	output << "\n";
	return output.str();
}

/**
 * @brief Render one complete successful verification report.
 *
 * @param verified Exact admitted runtime-bundle projection.
 * @return Complete stdout bytes.
 */
[[nodiscard]] std::string render_success(const kinetum::pack::verified_runtime_bundle &verified)
{
	std::ostringstream output;
	output.exceptions(std::ios::badbit | std::ios::failbit);
	output.imbue(std::locale::classic());
	output << "\n";
	output << "================================================================\n";
	output << "VERIFICATION SUCCESSFUL\n";
	output << "================================================================\n";
	output << "Bundle: " << verified.bundle_root << "\n";
	output << "Plan: " << verified.plan_path << " (" << verified.plan.plan_id() << ")\n";
	output << "Bootstrap snapshot: " << verified.bootstrap_snapshot_path << " ("
	       << verified.bootstrap_snapshot.snapshot_id() << ")\n";
	output << "Manifest, canonical paths, plan identity, and snapshot identity verified.\n";
	output << "================================================================\n";
	output << "\n";
	return output.str();
}

}  // namespace

/**
 * @brief Main entry point for bundle verification tool.
 *
 * Orchestrates the verification workflow:
 * 1. Parse command-line arguments
 * 2. Run shared runtime-bundle admission
 * 3. Report canonical verified artifacts
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @return Exit code: 0=success, 1=verification failed, 2=usage error
 */
int main(int argc, char **argv)
{
	std::string bundle_dir;

	for (int i = 1; i < argc; i++) {
		const std::string a = argv[i];
		if (a == "--bundle" && i + 1 < argc) {
			bundle_dir = argv[++i];
		} else if (a == "-h" || a == "--help") {
			return kinetum::common::emit_process_output({
				.standard_output = {},
				.standard_error = USAGE,
				.complete_exit_code = EXIT_CODE_SUCCESS,
			});
		} else {
			std::string output = "Unknown argument: ";
			output += a;
			output += "\n\n";
			output += USAGE;
			return kinetum::common::emit_process_output({
				.standard_output = {},
				.standard_error = output,
				.complete_exit_code = EXIT_CODE_USAGE_ERROR,
			});
		}
	}

	if (bundle_dir.empty()) {
		std::string output = "Error: Missing required argument --bundle\n\n";
		output += USAGE;
		return kinetum::common::emit_process_output({
			.standard_output = {},
			.standard_error = output,
			.complete_exit_code = EXIT_CODE_USAGE_ERROR,
		});
	}

	auto verified_or = kinetum::pack::verify_runtime_bundle(bundle_dir);
	if (!verified_or.is_ok()) {
		const std::string output = render_failure(verified_or.error());
		return kinetum::common::emit_process_output({
			.standard_output = {},
			.standard_error = output,
			.complete_exit_code = EXIT_CODE_VERIFICATION_FAILED,
		});
	}

	const std::string output = render_success(verified_or.value());
	return kinetum::common::emit_process_output({
		.standard_output = output,
		.standard_error = {},
		.complete_exit_code = EXIT_CODE_SUCCESS,
	});
}
