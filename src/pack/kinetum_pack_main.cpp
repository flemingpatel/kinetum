// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file kinetum_pack_main.cpp
 * @brief Bundle creation tool for Kinetum deployment artifacts.
 * @author Fleming Patel
 *
 * @section pack_overview Overview
 * kinetum_pack creates portable, SHA-256 content-verifiable deployment
 * bundles. It runs the Gluon planner, canonicalizes the bootstrap snapshot,
 * admits the declared module-artifact closure, and publishes one deterministic
 * content manifest. Platform runtime installation is a separate release
 * authority and is never copied into a deployment bundle.
 *
 * @section bundle_structure Bundle Structure
 * A Kinetum bundle is a portable directory artifact containing:
 * ```
 * bundle/
 *   configs/
 *     pipeline.axiom.pbtxt
 *     hardware.pbtxt
 *     plan.pbtxt
 *     config_snapshot.pbtxt
 *   modules/
 *     <module_id>.so
 *     <dependency>.so[.<ver>]
 *     modules.json
 *   BUNDLE_MANIFEST.txt
 *   README_BUNDLE.md
 * ```
 * The modules directory is omitted when the plan has no module stage.
 *
 * @section workflow Workflow
 * 1. Parse and validate every explicit source artifact.
 * 2. Plan the pipeline against the supplied hardware and deployment bindings.
 * 3. Bind and normalize the bootstrap snapshot against the exact plan.
 * 4. Remove admitted source-only module paths before planning, then copy the
 *    retained module images and dependencies into the bundle.
 * 5. Write canonical configurations, metadata, and the SHA-256 manifest.
 * 6. Admit the complete result through the shared runtime-bundle verifier.
 *
 * @section pack_determinism Canonical Output Contract
 * - The manifest is sorted lexicographically by canonical relative path.
 * - Every declared file row carries its exact byte count and SHA-256 digest.
 * - Required output is all-or-nothing: a failed publication removes the exact
 *   output directory created by this invocation.
 * - The bundle records the source-controlled Kinetum platform version.
 *
 * @section security Security Considerations
 * - Every bundle-owned artifact is path- and content-bound by the manifest.
 * - The manifest excludes itself to avoid circular identity.
 * - The bundle manifest is not a release signature. Runtime/provider
 *   provenance remains owned by the separately installed signed inventory.
 * - Secrets must never be bundled.
 *
 * @section pack_usage Usage Example
 * ```bash
 * kinetum_pack --axiom pipeline.axiom.pbtxt --hw hardware.pbtxt \
 *   --bindings deployment_bindings.pbtxt \
 *   --bootstrap-snapshot config_snapshot.pbtxt \
 *   --modules-dir /opt/kinetum/lib/modules --out /tmp/bundle
 * ```
 *
 * @section pack_exit_codes Exit Codes
 * - 0: bundle created and self-verified.
 * - 1: planning, I/O, or verification failure.
 * - 2: invalid arguments.
 *
 * @section goals Goals and Non-Goals
 * The tool owns reproducible deployment intent and module closure for an
 * independently installed runtime. It does not package the runtime, choose a
 * provider implementation, add a bundle-signature authority, or archive the
 * resulting directory.
 */

#include <charconv>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <iostream>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "src/gluon/gluon_planner.hpp"
#include "src/common/file_io.hpp"
#include "src/common/log.hpp"
#include "src/common/path_admission.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/version.hpp"
#include "src/axiom/axiom_pbtxt_io.hpp"
#include "src/pack/bundle_manifest.hpp"
#include "src/pack/pack_source_admission.hpp"
#include "src/pack/runtime_bundle.hpp"
#include <kinetum/kinetum_sdk.h>  // For exact module ABI identity.

#include "gen/kinetum/gluon/v1/bindings.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"

namespace fs = std::filesystem;

namespace
{

// Stable process exit codes distinguish success, runtime failure, and misuse.
constexpr int EXIT_CODE_SUCCESS = 0;	    ///< Successful bundle creation
constexpr int EXIT_CODE_RUNTIME_ERROR = 1;  ///< Runtime error (planning, I/O, etc.)
constexpr int EXIT_CODE_USAGE_ERROR = 2;    ///< Invalid command-line arguments

/**
 * @brief Test whether a module identity belongs to the reserved built-in namespace.
 *
 * @param module_id Exact authored module identity.
 * @return true only when the identity begins with the reserved `kinetum.` prefix.
 */
[[nodiscard]] bool is_builtin_module_id(std::string_view module_id)
{
	return module_id.rfind("kinetum.", 0) == 0;
}

/**
 * @brief Parse one strictly positive base-10 command-line integer.
 *
 * @param value Complete argument bytes to parse without repair or trimming.
 * @param name Option name used in bounded diagnostics.
 * @return The positive integer, or INVALID_ARGUMENT for empty, malformed,
 *         non-positive, or out-of-range input.
 */
[[nodiscard]] kinetum::common::status_or<int> parse_positive_int(std::string_view value, std::string_view name)
{
	if (value.empty()) {
		return kinetum::common::status(kinetum::common::status_code::INVALID_ARGUMENT,
					       std::string(name) + " requires a positive integer");
	}

	int parsed = 0;
	const char *first = value.data();
	const char *last = value.data() + value.size();
	const auto [ptr, ec] = std::from_chars(first, last, parsed, 10);
	if (ec == std::errc::invalid_argument || ptr != last) {
		return kinetum::common::status(kinetum::common::status_code::INVALID_ARGUMENT,
					       std::string(name) + " must be a positive base-10 integer",
					       std::string(value));
	}
	if (ec == std::errc::result_out_of_range || parsed <= 0) {
		return kinetum::common::status(kinetum::common::status_code::INVALID_ARGUMENT,
					       std::string(name) + " is out of range or non-positive",
					       std::string(value));
	}

	return parsed;
}

/**
 * @brief Display command-line usage information.
 *
 * Prints the complete supported flags, options, and examples.
 */
void usage()
{
	std::cerr << "kinetum_pack - Create deployable Kinetum bundles with integrity verification\n\n";
	std::cerr << "Usage:\n";
	std::cerr << "  kinetum_pack --axiom <pipeline.axiom.pbtxt> --hw <hardware.pbtxt> \\\n";
	std::cerr << "              --bindings <deployment_bindings.pbtxt> \\\n";
	std::cerr << "              --bootstrap-snapshot <config_snapshot.pbtxt> --out <bundle_dir>\n";
	std::cerr << "              [--regions N] [--modules-dir <dir_with_module_sos>]\n";
	std::cerr << "\n";
	std::cerr << "Required arguments:\n";
	std::cerr << "  --axiom <file>    Path to Axiom pipeline definition (pbtxt format)\n";
	std::cerr << "  --hw <file>       Path to hardware inventory (pbtxt format)\n";
	std::cerr << "  --bindings <file> Complete exact DeploymentBindings (pbtxt format)\n";
	std::cerr << "  --bootstrap-snapshot <file>  Complete bootstrap ConfigSnapshot (pbtxt format)\n";
	std::cerr << "  --out <dir>       New bundle directory; exact parent must already exist\n";
	std::cerr << "\n";
	std::cerr << "Optional arguments:\n";
	std::cerr << "  --regions N       Number of logical regions (default: 2)\n";
	std::cerr << "  --modules-dir <dir> Flat main-image/dependency source (required for built-in modules)\n";
	std::cerr << "  -h, --help        Display this help message\n";
	std::cerr << "\n";
	std::cerr << "Examples:\n";
	std::cerr << "  # Basic bundle\n";
	std::cerr << "  kinetum_pack --axiom pipeline.axiom.pbtxt --hw hardware.pbtxt \\\n";
	std::cerr << "    --bindings deployment_bindings.pbtxt \\\n";
	std::cerr << "    --bootstrap-snapshot config_snapshot.pbtxt --out /tmp/bundle\n\n";
	std::cerr << "  # Production bundle with snapshot\n";
	std::cerr << "  kinetum_pack --axiom build/pipeline.axiom.pbtxt \\\n";
	std::cerr << "    --hw examples/fan_in_edge_gateway/hardware_inventory_tap.pbtxt \\\n";
	std::cerr << "    --bindings examples/fan_in_edge_gateway/fan_in_edge_gateway_tap_bindings.pbtxt \\\n";
	std::cerr << "    --modules-dir /opt/kinetum/lib/modules \\\n";
	std::cerr << "    --out /var/lib/kinetum/bundles/production_v1 \\\n";
	std::cerr << "    --regions 3 \\\n";
	std::cerr << "    --bootstrap-snapshot examples/fan_in_edge_gateway/config_snapshot.pbtxt\n";
	std::cerr << "\n";
	std::cerr << "Output structure:\n";
	std::cerr << "  bundle/\n";
	std::cerr << "    configs/      - Pipeline, hardware, plan configurations\n";
	std::cerr << "    modules/      - Module .so files (if pipeline uses modules)\n";
	std::cerr << "    BUNDLE_MANIFEST.txt  - SHA-256 integrity manifest\n";
	std::cerr << "    README_BUNDLE.md  - Bundle documentation\n";
	std::cerr << "\n";
}

/**
 * @brief Copy one required admitted file into the rollback-owned bundle.
 *
 * This required-file copy operation:
 * - Attempts the copy directly without a separate source-existence check
 * - Requires the destination parent to exist
 * - Rejects an existing destination rather than replacing it
 * - Returns detailed error status on failure
 *
 * @param src Source file path
 * @param dst Destination file path
 * @return OK status on success, error status otherwise
 * @throws std::bad_alloc If storage for a path or failure status cannot be allocated.
 * @throws std::length_error If required diagnostic storage exceeds its representable size.
 *
 * @retval status_code::NOT_FOUND Source file does not exist
 * @retval status_code::INTERNAL_ERROR Filesystem error during copy
 * @retval status_code::OK Copy successful
 *
 * @note Attempts the copy directly instead of pre-checking source existence
 */
[[nodiscard]] kinetum::common::status copy_required_file(const fs::path &src, const fs::path &dst)
{
	try {
		std::error_code copy_ec;
		fs::copy_file(src, dst, fs::copy_options::none, copy_ec);

		if (copy_ec) {
			if (copy_ec == std::errc::no_such_file_or_directory) {
				return kinetum::common::status(kinetum::common::status_code::NOT_FOUND,
							       "source file does not exist", src.string());
			}
			return kinetum::common::status(kinetum::common::status_code::INTERNAL_ERROR, "file copy failed",
						       std::string(src.string()) + " -> " + dst.string() + ": " +
							       copy_ec.message());
		}

		return kinetum::common::status::ok();
	} catch (const std::exception &e) {
		return kinetum::common::status(kinetum::common::status_code::INTERNAL_ERROR, "file copy failed",
					       std::string(src.string()) + " -> " + dst.string() + ": " + e.what());
	}
}

/**
 * @brief Generate and write README_BUNDLE.md documentation file.
 *
 * Creates a human-readable markdown file documenting:
 * - Bundle purpose and structure
 * - Version information
 * - Usage instructions
 * - Verification steps
 * - Deployment notes
 *
 * @param bundle_dir Path to bundle root directory
 * @return OK status on success, error status on write failure
 * @throws std::bad_alloc If storage for the output path or README text cannot be allocated.
 * @throws std::length_error If the output path or README text exceeds its representable size.
 *
 * @note README is informational only; integrity is enforced via BUNDLE_MANIFEST.txt
 */
[[nodiscard]] kinetum::common::status write_bundle_readme(const fs::path &bundle_dir)
{
	const auto p = bundle_dir / "README_BUNDLE.md";
	std::string md;

	md += "# Kinetum Bundle\n\n";
	md += "This directory is a **Kinetum bundle** - a portable, verifiable deployment artifact.\n\n";

	md += "**Bundle version:** ";
	md += kinetum::common::KINETUM_VERSION_STRING;
	md += "\n\n";

	md += "## Bundle Contents\n\n";
	md += "- `configs/` - Pipeline, hardware, plan, and canonical bootstrap snapshot\n";
	md += "- `modules/` - Module shared objects (.so files) if pipeline uses modules\n";
	md += "- `BUNDLE_MANIFEST.txt` - SHA-256 content-integrity manifest\n";
	md += "- `README_BUNDLE.md` - This file\n\n";

	md += "## Integrity Verification\n\n";
	md += "Verify bundle integrity before deployment.\n\n";
	md += "```bash\n";
	md += "# Use the installed verifier; replace the bundle path.\n";
	md += "/opt/kinetum/bin/kinetum_bundle_verify --bundle /path/to/this/bundle\n";
	md += "```\n\n";
	md += "This command:\n";
	md += "1. Reads `BUNDLE_MANIFEST.txt`\n";
	md += "2. Rejects symlink indirection and verifies every manifest-bound file\n";
	md += "3. Verifies the canonical deployment-plan content identity\n";
	md += "4. Validates and canonicalizes `configs/config_snapshot.pbtxt` against that plan\n\n";

	md += "## Deployment\n\n";
	md += "Install and verify the matching Kinetum runtime package separately. ";
	md += "This bundle contains deployment configuration and module artifacts only; ";
	md += "it is not a runtime distribution.\n\n";
	md += "### 1. Verify Integrity (Required)\n";
	md += "```bash\n";
	md += "/opt/kinetum/bin/kinetum_bundle_verify --bundle /path/to/this/bundle\n";
	md += "```\n\n";

	md += "### 2. Run Photon\n";
	md += "Launch the supervisor with the verified bundle rather than a detached plan.\n";
	md += "```bash\n";
	md += "/opt/kinetum/bin/kinetum_photon --bundle /path/to/this/bundle\n";
	md += "```\n\n";

	md += "## Important Notes\n\n";
	md += "- **Provider Prerequisites:** Satisfy the exact deployment bindings and host-proof requirements ";
	md += "before launch; this bundle does not configure host resources.\n";
	md += "- **Module Artifacts:** Every `modules/` entry is manifest-bound; runtime admission must "
	      "consume the exact bundle-owned artifact.\n";
	md += "- **Version Identity:** Bundle created with Kinetum " +
	      std::string(kinetum::common::KINETUM_VERSION_STRING) + ". ";
	md += "The verifier requires this exact version.\n\n";

	md += "## Manifest Format\n\n";
	md += "The `BUNDLE_MANIFEST.txt` file contains:\n";
	md += "```\n";
	md += "bundle_name=<name>\n";
	md += "bundle_version=<version>\n";
	md += "file <relative_path> <size_bytes> <sha256_hex>\n";
	md += "...\n";
	md += "```\n\n";

	md += "Metadata is required, the version must match the verifier exactly, and file paths are strictly "
	      "sorted for deterministic regeneration.\n\n";

	md += "## Integrity and Authority\n\n";
	md += "- SHA-256 binds each declared file to the admitted manifest bytes\n";
	md += "- Deployment-bundle verification is required before deployment\n";
	md += "- Bundle paths and contents must remain immutable after verification\n";
	md += "- The unsigned manifest does not authenticate its producer; trusted delivery remains external\n";
	md += "- Runtime/provider provenance is verified separately\n";
	md += "- Do not bundle secrets (.env, credentials.json, etc.)\n\n";

	md += "---\n";
	md += "*Generated by kinetum_pack - Kinetum Platform " + std::string(kinetum::common::KINETUM_VERSION_STRING) +
	      "*\n";

	return kinetum::common::write_string_to_file(p, md);
}

/**
 * @brief Own rollback of one newly created bundle directory.
 *
 * The guard is constructed before the first output side effect and armed only
 * after exact directory creation succeeds. Success calls release(); any other
 * armed exit removes the complete directory created by this invocation.
 * Cleanup failure is fatal because returning while retaining a partial output
 * would misrepresent the operation's failure.
 */
class bundle_publication final {
    public:
	/**
	 * @brief Bind rollback to one not-yet-created output path.
	 *
	 * @param root Exact bundle root this invocation may create.
	 */
	explicit bundle_publication(fs::path root)
		: root_(std::move(root))
	{
	}

	bundle_publication(const bundle_publication &) = delete;
	bundle_publication &operator=(const bundle_publication &) = delete;
	bundle_publication(bundle_publication &&) = delete;
	bundle_publication &operator=(bundle_publication &&) = delete;

	/** @brief Claim the successfully created directory as rollback-owned output. */
	void arm() noexcept
	{
		armed_ = true;
	}

	/** @brief Remove every rollback-owned byte, terminating if cleanup fails. */
	~bundle_publication() noexcept
	{
		if (!armed_) {
			return;
		}

		std::error_code ec;
		(void)fs::remove_all(root_, ec);
		if (ec) {
			std::fputs("Kinetum pack could not remove its incomplete bundle\n", stderr);
			(void)std::fflush(stderr);
			std::terminate();
		}
	}

	/** @brief Accept the exact completed bundle and relinquish rollback. */
	void release() noexcept
	{
		armed_ = false;
	}

    private:
	fs::path root_;	     ///< Exact output directory owned by this invocation.
	bool armed_{false};  ///< Whether destruction must roll back incomplete output.
};

}  // namespace

/**
 * @brief Main entry point for kinetum_pack bundle creation tool.
 *
 * Orchestrates the complete bundle creation workflow:
 * 1. Parse arguments and atomically admit every source artifact
 * 2. Load and validate Axiom pipeline
 * 3. Load hardware inventory
 * 4. Run Gluon planner to generate execution plan
 * 5. Validate and normalize the explicit bootstrap snapshot against that plan
 * 6. Create bundle directory structure
 * 7. Copy admitted module files
 * 8. Save canonical configurations and required documentation
 * 9. Generate the SHA-256 content-integrity manifest
 * 10. Verify and publish the completed bundle
 *
 * On error, cleans up partial bundle to prevent inconsistent state.
 * Expected allocation and representation-size exceptions are translated to a
 * runtime-error exit after automatic objects have unwound. Any other exception
 * remains process-fatal.
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @return Exit code: 0=success, 1=runtime error, 2=usage error
 */
int main(int argc, char **argv)
try {
	kinetum::common::set_command_log_identity("kinetum_pack");
	// Configuration from command line
	std::string axiom_path;
	std::string hw_path;
	std::string out_dir;
	std::string bindings_path;
	std::string modules_dir;
	std::string bootstrap_snapshot_path;
	int regions = 2;  // Default number of logical regions

	// Parse command-line arguments
	for (int i = 1; i < argc; i++) {
		const std::string a = argv[i];
		if (a == "--axiom" && i + 1 < argc) {
			axiom_path = argv[++i];
		} else if (a == "--hw" && i + 1 < argc) {
			hw_path = argv[++i];
		} else if (a == "--out" && i + 1 < argc) {
			out_dir = argv[++i];
		} else if (a == "--bindings" && i + 1 < argc) {
			bindings_path = argv[++i];
		} else if (a == "--modules-dir" && i + 1 < argc) {
			modules_dir = argv[++i];
		} else if (a == "--regions" && i + 1 < argc) {
			const std::string_view value(argv[++i]);
			auto parsed_or = parse_positive_int(value, "--regions");
			if (!parsed_or.is_ok()) {
				const auto &err = parsed_or.error();
				const std::string message = err.details().empty() ? std::string(err.message()) :
										    std::string(err.message()) + ": " +
											    std::string(err.details());
				KINETUM_LOG_ERROR("pack", "pack.arguments.invalid", "{}", message);
				return EXIT_CODE_USAGE_ERROR;
			}
			regions = parsed_or.value();
		} else if (a == "--bootstrap-snapshot" && i + 1 < argc) {
			bootstrap_snapshot_path = argv[++i];
		} else if (a == "-h" || a == "--help") {
			usage();
			return EXIT_CODE_SUCCESS;
		} else {
			std::cerr << "Unknown argument: " << a << "\n\n";
			usage();
			return EXIT_CODE_USAGE_ERROR;
		}
	}

	// Validate required arguments
	if (axiom_path.empty() || hw_path.empty() || bindings_path.empty() || bootstrap_snapshot_path.empty() ||
	    out_dir.empty()) {
		std::cerr << "Error: Missing required arguments\n\n";
		usage();
		return EXIT_CODE_USAGE_ERROR;
	}
	// Resolve the complete source-artifact contract transactionally. No raw CLI
	// path survives into parsing, copying, or output construction.
	kinetum::pack::pack_source_spec source_spec;
	source_spec.pipeline = fs::path(axiom_path);
	source_spec.hardware = fs::path(hw_path);
	source_spec.bootstrap_snapshot = fs::path(bootstrap_snapshot_path);
	source_spec.deployment_bindings = fs::path(bindings_path);
	if (!modules_dir.empty()) {
		source_spec.module_directory = fs::path(modules_dir);
	}
	auto sources_or = kinetum::pack::admit_pack_sources(source_spec);
	if (!sources_or.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.sources.rejected", "{}{}{}", sources_or.error().message(),
				  sources_or.error().details().empty() ? "" : ": ", sources_or.error().details());
		return EXIT_CODE_USAGE_ERROR;
	}
	auto admitted_sources = std::move(sources_or).value();
	axiom_path = admitted_sources.pipeline.string();
	hw_path = admitted_sources.hardware.string();
	bootstrap_snapshot_path = admitted_sources.bootstrap_snapshot.string();
	bindings_path = admitted_sources.deployment_bindings.string();
	if (admitted_sources.module_directory.has_value()) {
		modules_dir = admitted_sources.module_directory->string();
	} else {
		modules_dir.clear();
	}

	KINETUM_LOG_INFO("pack", "pack.begin", "Starting bundle creation");
	KINETUM_LOG_INFO("pack", "pack.input.axiom", "Axiom: {}", axiom_path);
	KINETUM_LOG_INFO("pack", "pack.input.hardware", "Hardware: {}", hw_path);
	KINETUM_LOG_INFO("pack", "pack.input.snapshot", "Bootstrap snapshot: {}", bootstrap_snapshot_path);
	KINETUM_LOG_INFO("pack", "pack.output", "Output: {}", out_dir);
	KINETUM_LOG_INFO("pack", "pack.regions", "Regions: {}", regions);
	KINETUM_LOG_INFO("pack", "pack.input.bindings", "Bindings: {}", bindings_path);
	if (!modules_dir.empty()) {
		KINETUM_LOG_INFO("pack", "pack.input.modules", "Modules dir: {}", modules_dir);
	}

	// ========================================================================
	// STEP 1: Load and validate Axiom pipeline
	// ========================================================================
	KINETUM_LOG_INFO("pack", "pack.pipeline.loading", "Loading Axiom pipeline...");

	kinetum::axiom::contract_options lo;
	lo.require_linear_pipeline = false;  // Allow DAG (Gluon uses topological ordering)

	auto p_or = kinetum::axiom::load_pipeline_pbtxt(axiom_path, lo);
	if (!p_or.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.pipeline.rejected", "Failed to load pipeline: {}",
				  p_or.error().message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	// Work with a mutable copy so we can rewrite bundle-relative details (e.g., module paths)
	kinetum::axiom::v1::Pipeline pipeline = p_or.value();
	KINETUM_LOG_INFO("pack", "pack.pipeline.loaded", "Pipeline loaded successfully ({} stages)",
			 pipeline.stages_size());

	// ========================================================================
	// STEP 2: Scan for module stages and collect module files
	// ========================================================================
	// Pack contract for modules:
	//  - Module stages carry one exact typed module_id and optional source path
	//  - The packed pipeline will contain module_id and omit module_path
	//  - Runtime resolves modules via: bundle_dir/modules/<id>.so
	//  - Reserved built-in IDs resolve through one exact source-image mapping
	//  - Built-in images and declared dependencies come from one explicit flat
	//    --modules-dir authority
	//  - This enables bundle portability without absolute path dependencies

	std::vector<std::pair<std::string, fs::path>> modules_to_copy;
	std::vector<kinetum::pack::admitted_module_dependency> module_dependencies_to_copy;
	std::unordered_map<std::string, fs::path> module_sources_by_id;

	for (int i = 0; i < pipeline.stages_size(); ++i) {
		const auto &st = pipeline.stages(i);
		if (st.kind() != kinetum::axiom::v1::STAGE_KIND_MODULE) {
			continue;
		}

		const std::string module_id = st.has_module() ? st.module().module_id() : std::string{};
		std::string module_path = st.has_module() && st.module().has_module_path() ? st.module().module_path() :
											     std::string{};

		// Axiom already validates this typed identity; retain a local backstop
		// before deriving a bundle filename.
		if (module_id.empty()) {
			KINETUM_LOG_ERROR("pack", "pack.module.missing_id",
					  "module stage requires typed module_id configuration");
			return EXIT_CODE_USAGE_ERROR;
		}
		if (!kinetum::pack::is_safe_bundle_module_atom(module_id)) {
			KINETUM_LOG_ERROR("pack", "pack.module.invalid_id",
					  "module_id '{}' is not safe for bundle filename (allowed: A-Z a-z 0-9 . _ -)",
					  module_id);
			return EXIT_CODE_USAGE_ERROR;
		}
		const bool builtin = is_builtin_module_id(module_id);
		kinetum::pack::builtin_module_image builtin_image;
		if (builtin && modules_dir.empty()) {
			KINETUM_LOG_ERROR("pack", "pack.module.missing_directory",
					  "built-in module '{}' requires --modules-dir for its exact source image",
					  module_id);
			return EXIT_CODE_USAGE_ERROR;
		}
		if (builtin) {
			auto image_or = kinetum::pack::resolve_builtin_module_image(module_id);
			if (!image_or.is_ok()) {
				KINETUM_LOG_ERROR("pack", "pack.module.image_rejected", "{}",
						  image_or.error().message());
				return EXIT_CODE_USAGE_ERROR;
			}
			builtin_image = std::move(image_or).value();
		}

		// Modules without module_path must be resolvable to an explicit .so source.
		if (module_path.empty()) {
			if (!builtin) {
				KINETUM_LOG_ERROR("pack", "pack.module.missing_path",
						  "module '{}' requires module_path parameter", module_id);
				return EXIT_CODE_USAGE_ERROR;
			}
			module_path = (fs::path(modules_dir) / builtin_image.source_filename).string();
			KINETUM_LOG_INFO("pack", "pack.module.resolved", "Resolved built-in module '{}' from {}",
					 module_id, module_path);
		}

		auto source_or = kinetum::common::admit_explicit_regular_file(fs::path(module_path), "module source");
		if (!source_or.is_ok()) {
			KINETUM_LOG_ERROR("pack", "pack.module.source_rejected", "{}{}{}", source_or.error().message(),
					  source_or.error().details().empty() ? "" : ": ", source_or.error().details());
			return EXIT_CODE_USAGE_ERROR;
		}
		const fs::path source = std::move(source_or).value();
		auto [it, inserted] = module_sources_by_id.emplace(module_id, source);
		if (!inserted) {
			if (it->second != source) {
				KINETUM_LOG_ERROR("pack", "pack.module.conflicting_paths",
						  "module_id '{}' resolves to multiple source paths ({} vs {})",
						  module_id, it->second.string(), source.string());
				return EXIT_CODE_USAGE_ERROR;
			}
			continue;
		}
		modules_to_copy.emplace_back(module_id, source);
	}

	if (!modules_to_copy.empty()) {
		KINETUM_LOG_INFO("pack", "pack.modules.collected", "Found {} module(s) to bundle",
				 modules_to_copy.size());
		if (!modules_dir.empty()) {
			auto dependencies_or =
				kinetum::pack::admit_module_dependencies(fs::path(modules_dir), module_sources_by_id);
			if (!dependencies_or.is_ok()) {
				KINETUM_LOG_ERROR("pack", "pack.dependencies.rejected", "{}{}{}",
						  dependencies_or.error().message(),
						  dependencies_or.error().details().empty() ? "" : ": ",
						  dependencies_or.error().details());
				return EXIT_CODE_USAGE_ERROR;
			}
			module_dependencies_to_copy = std::move(dependencies_or).value();
		}

		std::unordered_set<std::string> dependency_names;
		dependency_names.reserve(module_dependencies_to_copy.size());
		for (const auto &dependency : module_dependencies_to_copy) {
			dependency_names.insert(dependency.filename);
		}
		for (const auto &[module_id, source] : modules_to_copy) {
			(void)source;
			if (dependency_names.contains(module_id + ".so")) {
				KINETUM_LOG_ERROR("pack", "pack.dependencies.collision",
						  "module dependency filename collides with main image output: {}.so",
						  module_id);
				return EXIT_CODE_USAGE_ERROR;
			}
		}
	}

	// Source paths have served their only purpose once every module image is
	// admitted. Remove them before planning so the emitted plan and the copied
	// pipeline share one bundle-relative module authority.
	for (auto &stage : *pipeline.mutable_stages()) {
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
			stage.mutable_module()->clear_module_path();
		}
	}

	// ========================================================================
	// STEP 3: Load hardware inventory
	// ========================================================================
	KINETUM_LOG_INFO("pack", "pack.hardware.loading", "Loading hardware inventory...");

	kinetum::hw::v1::HardwareInventory hw;
	auto hs = kinetum::common::read_pbtxt_file(hw_path, kinetum::common::DEFAULT_MAX_FILE_SIZE, &hw);
	if (!hs.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.hardware.rejected", "Failed to load hardware inventory: {}",
				  hs.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	KINETUM_LOG_INFO("pack", "pack.hardware.loaded", "Hardware inventory loaded successfully");

	// ========================================================================
	// STEP 4: Run Gluon planner to generate execution plan
	// ========================================================================
	KINETUM_LOG_INFO("pack", "pack.planner.begin", "Running Gluon planner (regions: {})...", regions);

	kinetum::gluon::planner_options opt;
	opt.regions = regions;

	auto bs = kinetum::common::read_pbtxt_file(bindings_path, kinetum::common::DEFAULT_MAX_FILE_SIZE,
						   &opt.deployment_bindings);
	if (!bs.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.bindings.rejected", "Failed to load bindings file: {}", bs.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	auto plan_or = kinetum::gluon::plan(pipeline, hw, opt);
	if (!plan_or.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.planner.failed", "Gluon planning failed: {}",
				  plan_or.error().message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	KINETUM_LOG_INFO("pack", "pack.planner.complete", "Gluon planning completed successfully");

	// ========================================================================
	// STEP 5: Validate and normalize the bootstrap snapshot
	// ========================================================================
	// Validate all input-side semantic identities before the first output-path
	// side effect. A malformed or plan-incompatible snapshot must never leave a
	// directory that resembles a partially runnable bundle.
	KINETUM_LOG_INFO("pack", "pack.snapshot.validating", "Validating and normalizing bootstrap snapshot...");
	auto bootstrap_or =
		kinetum::pack::load_and_normalize_bootstrap_snapshot(bootstrap_snapshot_path, plan_or.value());
	if (!bootstrap_or.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.snapshot.rejected", "Bootstrap snapshot validation failed: {}{}{}",
				  bootstrap_or.error().message(), bootstrap_or.error().details().empty() ? "" : ": ",
				  bootstrap_or.error().details());
		return EXIT_CODE_RUNTIME_ERROR;
	}
	auto normalized_bootstrap = std::move(bootstrap_or).value();

	// ========================================================================
	// STEP 6: Acquire one rollback-owned bundle directory
	// ========================================================================
	KINETUM_LOG_INFO("pack", "pack.directory.creating", "Creating bundle directory structure...");

	std::error_code output_path_ec;
	fs::path requested_bundle = fs::absolute(fs::path(out_dir), output_path_ec);
	if (output_path_ec) {
		KINETUM_LOG_ERROR("pack", "pack.output.unresolved", "Failed to resolve output directory: {}",
				  output_path_ec.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}
	if (requested_bundle.filename().empty() || requested_bundle.filename() == "." ||
	    requested_bundle.filename() == ".." || requested_bundle != requested_bundle.lexically_normal()) {
		KINETUM_LOG_ERROR("pack", "pack.output.invalid",
				  "Output must identify one new directory below an existing parent");
		return EXIT_CODE_USAGE_ERROR;
	}
	if (!kinetum::pack::is_canonical_bundle_name(requested_bundle.filename().string())) {
		KINETUM_LOG_ERROR("pack", "pack.output.invalid_name",
				  "Output directory name is not a canonical bundle name");
		return EXIT_CODE_USAGE_ERROR;
	}
	const auto output_parent_status =
		kinetum::common::validate_exact_directory(requested_bundle.parent_path(), "bundle output parent");
	if (!output_parent_status.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.output.parent_rejected", "{}{}{}", output_parent_status.message(),
				  output_parent_status.details().empty() ? "" : ": ", output_parent_status.details());
		return EXIT_CODE_USAGE_ERROR;
	}
	const fs::path &bundle_dir = requested_bundle;
	const fs::path out_cfg = bundle_dir / "configs";
	bundle_publication publication(bundle_dir);

	std::error_code mkdir_ec;
	const bool created = fs::create_directory(bundle_dir, mkdir_ec);
	if (mkdir_ec) {
		KINETUM_LOG_ERROR("pack", "pack.directory.failed", "Failed to create bundle directory: {}",
				  mkdir_ec.message());
		return mkdir_ec == std::errc::file_exists ? EXIT_CODE_USAGE_ERROR : EXIT_CODE_RUNTIME_ERROR;
	}
	if (!created) {
		KINETUM_LOG_ERROR("pack", "pack.directory.exists", "Output directory already exists: {}",
				  bundle_dir.string());
		return EXIT_CODE_USAGE_ERROR;
	}
	publication.arm();

	if (!fs::create_directory(out_cfg, mkdir_ec) || mkdir_ec) {
		KINETUM_LOG_ERROR("pack", "pack.config_directory.failed", "Failed to create configs directory: {}",
				  mkdir_ec.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}
	// ========================================================================
	// STEP 7: Handle module files (Module SDK integration)
	// ========================================================================
	// Copy each admitted module image and dependency into the bundle-owned flat
	// module directory.
	if (!modules_to_copy.empty()) {
		KINETUM_LOG_INFO("pack", "pack.modules.copying", "Processing module files...");

		fs::path out_modules = bundle_dir / "modules";
		std::error_code mod_mkdir_ec;
		if (!fs::create_directory(out_modules, mod_mkdir_ec) || mod_mkdir_ec) {
			KINETUM_LOG_ERROR("pack", "pack.module_directory.failed",
					  "Failed to create modules directory: {}", mod_mkdir_ec.message());
			return EXIT_CODE_RUNTIME_ERROR;
		}

		// Copy module .so files into bundle
		for (const auto &[module_id, src_path] : modules_to_copy) {
			const fs::path dst = out_modules / (module_id + ".so");
			auto cs = copy_required_file(src_path, dst);
			if (!cs.is_ok()) {
				KINETUM_LOG_ERROR("pack", "pack.module.copy_failed", "Failed to copy module '{}': {}",
						  module_id, cs.message());
				return EXIT_CODE_RUNTIME_ERROR;
			}
			KINETUM_LOG_INFO("pack", "pack.module.copied", "Copied module: {}.so", module_id);
		}
		for (const auto &dependency : module_dependencies_to_copy) {
			const fs::path dst = out_modules / dependency.filename;
			auto copy_status = copy_required_file(dependency.source, dst);
			if (!copy_status.is_ok()) {
				KINETUM_LOG_ERROR("pack", "pack.dependency.copy_failed",
						  "Failed to copy module dependency '{}': {}", dependency.filename,
						  copy_status.message());
				return EXIT_CODE_RUNTIME_ERROR;
			}
			KINETUM_LOG_INFO("pack", "pack.dependency.copied", "Copied module dependency: {}",
					 dependency.filename);
		}

		// Write the required human-readable module inventory. The bundle
		// manifest remains its content-integrity authority.
		std::ostringstream pm;
		pm << "{\n  \"abi_version\": " << KINETUM_MODULE_ABI_VERSION << ",\n  \"modules\": [\n";
		for (std::size_t i = 0; i < modules_to_copy.size(); ++i) {
			pm << "    { \"module_id\": \"" << modules_to_copy[i].first << "\", \"so\": \"modules/"
			   << modules_to_copy[i].first << ".so\" }";
			pm << (i + 1 < modules_to_copy.size() ? ",\n" : "\n");
		}
		pm << "  ],\n  \"dependencies\": [\n";
		for (std::size_t i = 0; i < module_dependencies_to_copy.size(); ++i) {
			pm << "    \"modules/" << module_dependencies_to_copy[i].filename << "\"";
			pm << (i + 1 < module_dependencies_to_copy.size() ? ",\n" : "\n");
		}
		pm << "  ]\n}\n";

		auto ps = kinetum::common::write_string_to_file(out_modules / "modules.json", pm.str());
		if (!ps.is_ok()) {
			KINETUM_LOG_ERROR("pack", "pack.modules.write_failed", "Failed to write modules.json: {}",
					  ps.message());
			return EXIT_CODE_RUNTIME_ERROR;
		}
	}

	// ========================================================================
	// STEP 8: Save configuration files (pbtxt format)
	// ========================================================================
	KINETUM_LOG_INFO("pack", "pack.configuration.writing", "Writing configuration files...");

	// Write the already admitted pipeline.
	auto ws1 = kinetum::common::write_pbtxt_file((out_cfg / "pipeline.axiom.pbtxt").string(), pipeline);
	if (!ws1.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.pipeline.write_failed", "Failed to write pipeline.axiom.pbtxt: {}",
				  ws1.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	// Write hardware inventory
	auto ws2 = kinetum::common::write_pbtxt_file((out_cfg / "hardware.pbtxt").string(), hw);
	if (!ws2.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.hardware.write_failed", "Failed to write hardware.pbtxt: {}",
				  ws2.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	// Write the complete Gluon deployment plan.
	auto ws3 = kinetum::common::write_pbtxt_file((out_cfg / "plan.pbtxt").string(), plan_or.value());
	if (!ws3.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.plan.write_failed", "Failed to write plan.pbtxt: {}", ws3.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	// Write the normalized complete snapshot rather than copying caller text.
	// The bundle therefore contains the exact canonical claims the runtime
	// verifier and later bootstrap transaction will consume.
	auto ws4 = kinetum::common::write_pbtxt_file((out_cfg / "config_snapshot.pbtxt").string(),
						     normalized_bootstrap.snapshot);
	if (!ws4.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.snapshot.write_failed", "Failed to write config_snapshot.pbtxt: {}",
				  ws4.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	KINETUM_LOG_INFO("pack", "pack.configuration.written", "Configuration files written successfully");

	// ========================================================================
	// STEP 9: Write required metadata and the integrity manifest
	// ========================================================================
	KINETUM_LOG_INFO("pack", "pack.readme.generating", "Generating bundle README...");

	auto rds = write_bundle_readme(bundle_dir);
	if (!rds.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.readme.write_failed", "Failed to write README_BUNDLE.md: {}",
				  rds.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	KINETUM_LOG_INFO("pack", "pack.manifest.generating", "Generating integrity manifest (SHA-256)...");

	auto mtxt_or = kinetum::pack::generate_manifest_text(bundle_dir.string());
	if (!mtxt_or.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.manifest.failed", "Failed to generate manifest: {}",
				  mtxt_or.error().message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	const fs::path manifest_path = bundle_dir / "BUNDLE_MANIFEST.txt";
	auto ms = kinetum::common::write_string_to_file(manifest_path, mtxt_or.value());
	if (!ms.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.manifest.write_failed", "Failed to write BUNDLE_MANIFEST.txt: {}",
				  ms.message());
		return EXIT_CODE_RUNTIME_ERROR;
	}

	// ========================================================================
	// STEP 10: Self-verify and accept
	// ========================================================================
	// The producer passes its completed output through the same semantic gate
	// used by Photon and the standalone verifier. Success cannot depend on a
	// packer-only interpretation of manifest, plan, or snapshot identity.
	KINETUM_LOG_INFO("pack", "pack.bundle.verifying", "Self-verifying completed deployment bundle...");
	auto verified_or = kinetum::pack::verify_runtime_bundle(bundle_dir.string());
	if (!verified_or.is_ok()) {
		KINETUM_LOG_ERROR("pack", "pack.bundle.rejected", "Completed bundle verification failed: {}{}{}",
				  verified_or.error().message(), verified_or.error().details().empty() ? "" : ": ",
				  verified_or.error().details());
		return EXIT_CODE_RUNTIME_ERROR;
	}
	// ========================================================================
	// SUCCESS: Bundle created
	// ========================================================================
	KINETUM_LOG_INFO("pack", "pack.summary", "========================================");
	KINETUM_LOG_INFO("pack", "pack.bundle.created", "Bundle created successfully!");
	KINETUM_LOG_INFO("pack", "pack.bundle.location", "Location: {}", bundle_dir.string());
	KINETUM_LOG_INFO("pack", "pack.bundle.manifest", "Manifest: {}", manifest_path.string());
	KINETUM_LOG_INFO("pack", "pack.bundle.plan", "Plan: {}", verified_or.value().plan_path);
	KINETUM_LOG_INFO("pack", "pack.bundle.snapshot", "Bootstrap snapshot: {}",
			 verified_or.value().bootstrap_snapshot_path);
	KINETUM_LOG_INFO("pack", "pack.summary", "========================================");
	KINETUM_LOG_INFO("pack", "pack.bundle.verify_command",
			 "Verify with the installed runtime: kinetum_bundle_verify --bundle {}", bundle_dir.string());
	if (!kinetum::common::flush_logs()) {
		return EXIT_CODE_RUNTIME_ERROR;
	}

	// Nothing fallible may execute after release: exit success and bundle
	// existence linearize at this final nonthrowing edge.
	publication.release();
	return EXIT_CODE_SUCCESS;
} catch (const std::bad_alloc &) {
	std::fputs("Error: bundle creation exhausted available memory\n", stderr);
	return EXIT_CODE_RUNTIME_ERROR;
} catch (const std::length_error &) {
	std::fputs("Error: bundle creation exceeded a representation size limit\n", stderr);
	return EXIT_CODE_RUNTIME_ERROR;
}
