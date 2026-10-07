// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file kinetum_info.cpp
 * @brief Kinetum Platform SDK/Runtime Information and Diagnostics Tool
 * @author Fleming Patel
 *
 * This tool provides current information about the Kinetum Platform
 * installation, including version, paths, build configuration, and integrity
 * verification.
 *
 * ## Features
 *
 * - **Version Information**: Compiled product version display
 * - **Installed Components**: Independent runtime and SDK presence reporting
 * - **Installation Paths**: Prefix, headers, binaries, modules, examples
 * - **Build Configuration**: TLS, MLIR, and exact DPDK release identity
 * - **Platform Capabilities**: Exact descriptive first-release capability set
 * - **Integrity Check**: Verify exact runtime membership, hashes, and the
 *   signed provider closure
 * - **JSON Output**: Machine-readable output for scripting/automation
 *
 * ## Usage Examples
 *
 * ```bash
 * # Show all information (human-readable)
 * kinetum-info
 *
 * # Show version only
 * kinetum-info --version
 *
 * # Verify installation integrity
 * kinetum-info --check
 *
 * # JSON output for scripting
 * kinetum-info --json
 *
 * # Check specific prefix
 * kinetum-info --prefix /usr/local/kinetum --check
 * ```
 *
 * ## Exit Codes
 *
 * | Code | Meaning |
 * |------|---------|
 * | 0    | Success |
 * | 1    | Inspection or installation check failed |
 * | 2    | Usage error (invalid arguments) |
 *
 * ## Integration with Package Managers
 *
 * Machine-readable verification uses `--check --json`. Plain `--json`
 * reports component presence without claiming an integrity check. Missing,
 * incomplete, and uninspectable components are distinct observations:
 *
 * ```bash
 * # Check if installation is valid
 * if kinetum-info --check --prefix /opt/kinetum > /dev/null 2>&1; then
 *   echo "Kinetum is correctly installed"
 * fi
 *
 * # Get version for scripting
 * VERSION=$(kinetum-info --version)
 * ```
 *
 * @see docs/GETTING_STARTED.md for package installation and verification
 * @see docs/KINETUM_PACK.md for deployment-bundle production and verification
 */

#include <array>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <locale>
#include <new>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include "tooling/release/verification/runtime_verification.hpp"
#include "src/common/path_admission.hpp"
#include "src/common/process_output.hpp"
#include "src/common/process_image.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/version.hpp"
#include "src/common/utf8.hpp"
#include "src/provider/provider_installation.hpp"
#include "src/provider/provider_target_tuple.hpp"

namespace fs = std::filesystem;

namespace
{

// =============================================================================
// Build-Time Configuration
// =============================================================================

// TLS support is injected by CMake via -DKINETUM_ENABLE_TLS.
#ifndef KINETUM_ENABLE_TLS
#error "kinetum-info requires the exact CMake TLS build fact"
#endif

// Optional Axiom MLIR frontend is injected by CMake.
#ifndef KINETUM_ENABLE_MLIR
#error "kinetum-info requires the exact CMake MLIR frontend build fact"
#endif

// Effective Axiom MLIR dialect support is injected by CMake.
#ifndef KINETUM_ENABLE_MLIR_DIALECT
#error "kinetum-info requires the exact CMake MLIR dialect build fact"
#endif

static_assert(KINETUM_ENABLE_TLS == 0 || KINETUM_ENABLE_TLS == 1, "the TLS build fact must be boolean");
static_assert(KINETUM_ENABLE_MLIR == 0 || KINETUM_ENABLE_MLIR == 1, "the MLIR frontend build fact must be boolean");
static_assert(KINETUM_ENABLE_MLIR_DIALECT == 0 || KINETUM_ENABLE_MLIR_DIALECT == 1,
	      "the MLIR dialect build fact must be boolean");

/** Exact product version compiled into this information image. */
constexpr std::string_view VERSION = kinetum::common::KINETUM_VERSION_STRING;

/** Exact source-controlled DPDK dependency version selected by this release. */
constexpr std::string_view DPDK_VERSION = KINETUM_DPDK_VERSION;
static_assert(!DPDK_VERSION.empty(), "release verification requires an exact DPDK version identity");

/** Exact descriptive capabilities compiled into every complete platform image. */
constexpr std::array<std::string_view, 9> PLATFORM_CAPABILITIES = {
	"coherent_runtime_telemetry", "commit_confirmed",	    "durable_guardrails", "exact_bootstrap",
	"ordered_epoch_transitions",  "owner_worker_module_health", "selective_rollback", "synchronous_active_stages",
	"tracked_async_epoch_work",
};

static_assert(KINETUM_ENABLE_MLIR || !KINETUM_ENABLE_MLIR_DIALECT, "the Axiom MLIR dialect requires the MLIR frontend");

/**
 * @brief Prove one compile-time string-view array is strictly sorted.
 *
 * @tparam count Array element count.
 * @param values Values to compare in ascending byte order.
 * @return True only when every adjacent pair is strictly increasing.
 */
template <std::size_t count>
consteval bool strictly_sorted(const std::array<std::string_view, count> &values)
{
	for (std::size_t index = 1; index < values.size(); ++index) {
		if (values[index - 1] >= values[index]) {
			return false;
		}
	}
	return true;
}

static_assert(strictly_sorted(PLATFORM_CAPABILITIES), "descriptive platform capabilities must remain strictly sorted");

// =============================================================================
// Exit Codes (per platform convention)
// =============================================================================

/** Successful operation. */
constexpr int INFO_EXIT_SUCCESS = 0;

/** Component inspection or installation verification failed. */
constexpr int INFO_EXIT_CHECK_FAILED = 1;

/** Usage error for malformed command input. */
constexpr int INFO_EXIT_USAGE_ERROR = 2;

/**
 * @brief Own one complete process response before any output becomes visible.
 *
 * The result is fixed at construction and moves only as a complete stdout,
 * stderr, and intended-exit tuple. It is cold process-boundary state.
 */
class rendered_output final {
    public:
	/**
	 * @brief Construct one complete output transaction.
	 *
	 * @param standard_output Complete bytes intended for standard output.
	 * @param standard_error Complete bytes intended for standard error.
	 * @param exit_code Exit code permitted only after both streams are written.
	 */
	rendered_output(std::string standard_output, std::string standard_error, int exit_code) noexcept
		: standard_output_(std::move(standard_output))
		, standard_error_(std::move(standard_error))
		, exit_code_(exit_code)
	{
	}

	/** @brief Disable response aliasing. */
	rendered_output(const rendered_output &) = delete;

	/** @brief Disable replacement of a complete response. */
	rendered_output &operator=(const rendered_output &) = delete;

	/** @brief Transfer one complete response without changing its identity. */
	rendered_output(rendered_output &&) noexcept = default;

	/** @brief Disable replacement through move assignment. */
	rendered_output &operator=(rendered_output &&) = delete;

	/** @return Complete response borrowed for immediate process emission. */
	[[nodiscard]] kinetum::common::process_output_view view() const noexcept
	{
		return {
			.standard_output = standard_output_,
			.standard_error = standard_error_,
			.complete_exit_code = exit_code_,
		};
	}

    private:
	std::string standard_output_;  ///< Complete standard-output bytes.
	std::string standard_error_;   ///< Complete standard-error bytes.
	int exit_code_;		       ///< Exit intent after successful delivery.
};

static_assert(!std::is_default_constructible_v<rendered_output>);
static_assert(!std::is_copy_constructible_v<rendered_output>);
static_assert(!std::is_copy_assignable_v<rendered_output>);
static_assert(std::is_nothrow_move_constructible_v<rendered_output>);
static_assert(!std::is_move_assignable_v<rendered_output>);

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * @brief Return true when a filesystem path exists without throwing.
 *
 * @param path Filesystem path to probe.
 * @return True if the path exists, false on absence or filesystem error.
 */
bool path_exists(const fs::path &path)
{
	std::error_code ec;
	return fs::exists(path, ec);
}

/** @brief Structural component presence, independent of payload integrity. */
enum class component_presence : uint8_t {
	NOT_INSTALLED,	///< No component artifacts were observed.
	INSTALLED,	///< Required metadata and reported resources are present.
	INCOMPLETE,	///< Some required artifacts are absent, indirect, or the wrong type.
	UNAVAILABLE,	///< A filesystem error prevented inspection.
};

/** @brief One resource path exposed by the information tool. */
struct information_path {
	std::string_view key;	    ///< JSON field name.
	std::string_view relative;  ///< Fixed path below the selected installation prefix.
	fs::file_type type;	    ///< Required filesystem object type.
};

/** Runtime paths reported only for a structurally present installation. */
constexpr std::array<information_path, 2> RUNTIME_PATHS{{
	{"binaries", "bin", fs::file_type::directory},
	{"modules", "lib/modules", fs::file_type::directory},
}};

/** SDK resources whose presence permits SDK path and integration reporting. */
constexpr std::array<information_path, 4> SDK_PATHS{{
	{"headers", "sdk/include/kinetum", fs::file_type::directory},
	{"examples", "sdk/examples", fs::file_type::directory},
	{"pkgconfig", "sdk/lib/pkgconfig/kinetum.pc", fs::file_type::regular},
	{"cmake", "sdk/lib/cmake/Kinetum/KinetumConfig.cmake", fs::file_type::regular},
}};

/** @brief Accumulate bounded path observations for one independent component. */
class component_observation final {
    public:
	/**
	 * @brief Inspect one required path without following indirect components.
	 * @param prefix Already admitted canonical installation prefix.
	 * @param relative Fixed component-relative resource path.
	 * @param expected Required final object type; intermediate objects must be directories.
	 */
	void inspect(const fs::path &prefix, std::string_view relative, fs::file_type expected)
	{
		fs::path current = prefix;
		const fs::path suffix(relative);
		for (auto iterator = suffix.begin(); iterator != suffix.end();) {
			current /= *iterator;
			++iterator;
			std::error_code error;
			const auto observed = fs::symlink_status(current, error);
			if (error && error != std::errc::no_such_file_or_directory) {
				unavailable_ = true;
				return;
			}
			if (observed.type() == fs::file_type::not_found || error) {
				complete_ = false;
				return;
			}
			const auto required = iterator == suffix.end() ? expected : fs::file_type::directory;
			if (observed.type() != required) {
				present_ = true;
				complete_ = false;
				return;
			}
		}
		present_ = true;
	}

	/** @return Presence only; installed does not attest file contents or signatures. */
	[[nodiscard]] component_presence result() const noexcept
	{
		if (unavailable_) {
			return component_presence::UNAVAILABLE;
		}
		if (!present_) {
			return component_presence::NOT_INSTALLED;
		}
		return complete_ ? component_presence::INSTALLED : component_presence::INCOMPLETE;
	}

    private:
	bool present_{false};	   ///< At least one required object was observed.
	bool complete_{true};	   ///< Every inspected path has its required type.
	bool unavailable_{false};  ///< A filesystem failure takes precedence over absence.
};

/** @brief Independent component observations from the selected prefix. */
struct installation_presence {
	component_presence runtime;  ///< Runtime files and manifest presence.
	component_presence sdk;	     ///< SDK metadata and exposed resource presence.

	/** @return true when both observations completed, including absent or incomplete components. */
	[[nodiscard]] bool inspection_succeeded() const noexcept
	{
		return runtime != component_presence::UNAVAILABLE && sdk != component_presence::UNAVAILABLE;
	}
};

/**
 * @brief Inspect component presence without hashing payloads or loading code.
 * @param prefix Canonical installation prefix.
 * @return Independent runtime and SDK observations; SDK failure does not alter runtime status.
 */
[[nodiscard]] installation_presence inspect_installation(const fs::path &prefix)
{
	component_observation runtime;
	for (const auto &artifact : kinetum::release::expected_runtime_artifacts()) {
		runtime.inspect(prefix, artifact.relative_path, fs::file_type::regular);
	}
	runtime.inspect(prefix, kinetum::release::RUNTIME_PAYLOAD_MANIFEST, fs::file_type::regular);
	component_observation sdk;
	sdk.inspect(prefix, "sdk", fs::file_type::directory);
	sdk.inspect(prefix, "sdk/VERSION", fs::file_type::regular);
	sdk.inspect(prefix, "sdk/share/kinetum/release/sdk_payload_manifest.sha256", fs::file_type::regular);
	for (const auto &path : SDK_PATHS) {
		sdk.inspect(prefix, path.relative, path.type);
	}
	return {runtime.result(), sdk.result()};
}

/**
 * @brief Return the stable JSON spelling of a component observation.
 * @param presence Observed component state.
 * @return Fixed state name.
 */
[[nodiscard]] std::string_view presence_name(component_presence presence) noexcept
{
	switch (presence) {
	case component_presence::NOT_INSTALLED:
		return "not_installed";
	case component_presence::INSTALLED:
		return "installed";
	case component_presence::INCOMPLETE:
		return "incomplete";
	case component_presence::UNAVAILABLE:
		return "unavailable";
	}
	std::terminate();
}

/**
 * @brief Return the concise human-readable component observation.
 * @param presence Observed component state.
 * @return Human-readable state, without implying an integrity check.
 */
[[nodiscard]] std::string_view presence_label(component_presence presence) noexcept
{
	if (presence == component_presence::NOT_INSTALLED) {
		return "not installed";
	}
	if (presence == component_presence::UNAVAILABLE) {
		return "inspection failed";
	}
	return presence_name(presence);
}

/**
 * @brief Resolve one exact installation-prefix authority.
 *
 * An explicit --prefix must be an absolute canonical directory. Without that
 * input, the running image must be exactly `<prefix>/bin/kinetum-info` and the
 * prefix is derived from the kernel-authoritative /proc/self/exe result. No
 * PATH search, current-directory lookup, environment override, or /opt guess
 * is permitted.
 *
 * @param explicit_prefix Optional operator-supplied absolute prefix.
 * @return Canonical installation prefix, or an explicit fail-closed status.
 */
[[nodiscard]] kinetum::common::status_or<fs::path> resolve_install_prefix(const std::string &explicit_prefix)
{
	if (!explicit_prefix.empty()) {
		fs::path supplied(explicit_prefix);
		const auto prefix_status = kinetum::common::validate_exact_directory(supplied, "--prefix");
		if (!prefix_status.is_ok()) {
			return prefix_status;
		}
		return supplied;
	}

	auto image_or = kinetum::common::current_process_image();
	if (!image_or.is_ok()) {
		return image_or.error();
	}
	const fs::path bin_dir = image_or->parent_path();
	if (bin_dir.filename() != "bin") {
		return kinetum::common::status::failed_precondition(
			"kinetum-info is not running from <prefix>/bin; supply an explicit --prefix");
	}
	fs::path prefix = bin_dir.parent_path();
	const auto prefix_status = kinetum::common::validate_exact_directory(prefix, "derived installation prefix");
	if (!prefix_status.is_ok()) {
		return prefix_status;
	}
	return prefix;
}

/**
 * @brief Escapes a string for safe JSON output.
 *
 * Handles special characters per JSON specification (RFC 8259):
 * - Backslash, quotes, control characters
 *
 * @param s Input string
 * @return JSON-escaped bytes; the complete response receives UTF-8 admission before emission.
 */
std::string json_escape(const std::string &s)
{
	std::string result;
	result.reserve(s.size() + 8);
	for (char c : s) {
		switch (c) {
		case '\\':
			result += "\\\\";
			break;
		case '"':
			result += "\\\"";
			break;
		case '\n':
			result += "\\n";
			break;
		case '\r':
			result += "\\r";
			break;
		case '\t':
			result += "\\t";
			break;
		default:
			if (static_cast<unsigned char>(c) < 32) {
				// Control character - encode as a JSON Unicode escape.
				char buf[8];
				std::snprintf(buf, sizeof(buf), "\\u%04x",
					      static_cast<unsigned int>(static_cast<unsigned char>(c)));
				result += buf;
			} else {
				result += c;
			}
		}
	}
	return result;
}

/**
 * @brief Render usage information without publishing bytes.
 *
 * Displays all available command-line options with descriptions.
 * Format follows GNU conventions for CLI tools.
 *
 * @param diagnostic Complete diagnostic bytes for stderr, if any.
 * @param exit_code Exit intent after complete delivery.
 * @return Construction-fixed response containing usage on stdout.
 */
[[nodiscard]] rendered_output render_usage(std::string diagnostic, int exit_code)
{
	return rendered_output{
		"kinetum-info - Kinetum Platform SDK/Runtime information tool\n\n"
		"Usage:\n"
		"  kinetum-info [OPTIONS]\n\n"
		"Options:\n"
		"  --version, -v         Show version only\n"
		"  --check               Verify runtime installation integrity\n"
		"  --json                Output in JSON format\n"
		"  --prefix <path>       Use an exact absolute installation prefix\n"
		"  --help, -h            Show this help\n\n"
		"Exit Codes:\n"
		"  0   Success\n"
		"  1   Inspection or installation check failed\n"
		"  2   Usage error\n\n"
		"Examples:\n"
		"  kinetum-info                     # Show all info\n"
		"  kinetum-info --check             # Verify installation\n"
		"  kinetum-info --prefix /opt/foo   # Check custom prefix\n"
		"  kinetum-info --json | jq .       # JSON for scripting\n",
		std::move(diagnostic),
		exit_code,
	};
}

/**
 * @brief Render the version string without publishing bytes.
 *
 * Output is a single line suitable for scripting:
 * ```
 * 0.1.0
 * ```
 *
 * @return Construction-fixed successful response.
 */
[[nodiscard]] rendered_output render_version()
{
	std::string output(VERSION);
	output.push_back('\n');
	return rendered_output{std::move(output), {}, INFO_EXIT_SUCCESS};
}

/**
 * @brief Render build facts and independently observed runtime/SDK presence.
 *
 * Displays:
 * - Version, exact build facts, and descriptive capabilities
 * - Installation paths (prefix, headers, binaries, modules, examples)
 * - Integration instructions (pkg-config, CMake, environment)
 *
 * @param prefix Installation prefix path.
 * @param presence Component observations collected before rendering.
 * @return Complete presence report; a failed inspection has nonzero exit intent.
 */
[[nodiscard]] rendered_output render_all_info(const std::string &prefix, const installation_presence &presence)
{
	std::ostringstream output;
	output.exceptions(std::ios::badbit | std::ios::failbit);
	output.imbue(std::locale::classic());
	output << "Kinetum Platform\n";
	output << "================\n\n";

	// Version and build info
	output << "Version:     " << VERSION << "\n";
	output << "TLS:         " << (KINETUM_ENABLE_TLS ? "enabled" : "disabled") << "\n";
	output << "DPDK:        " << DPDK_VERSION << "\n\n";

	output << "Build Features:\n";
	output << "  axiom_mlir_frontend: " << (KINETUM_ENABLE_MLIR ? "enabled" : "disabled") << "\n";
	output << "  axiom_mlir_dialect:  " << (KINETUM_ENABLE_MLIR_DIALECT ? "enabled" : "disabled") << "\n\n";

	output << "Platform Capabilities:\n";
	for (const auto capability : PLATFORM_CAPABILITIES) {
		output << "  " << capability << "\n";
	}
	output << "\n";

	// Paths
	output << "Prefix:      " << prefix << "\n";
	output << "Runtime:     " << presence_label(presence.runtime) << "\n";
	output << "SDK:         " << presence_label(presence.sdk) << "\n";
	if (presence.runtime == component_presence::INSTALLED) {
		output << "Binaries:    " << prefix << "/" << RUNTIME_PATHS[0].relative << "/\n";
		output << "Modules:     " << prefix << "/" << RUNTIME_PATHS[1].relative << "/\n";
	}
	if (presence.sdk == component_presence::INSTALLED) {
		output << "SDK Headers: " << prefix << "/" << SDK_PATHS[0].relative << "/\n";
		output << "Examples:    " << prefix << "/" << SDK_PATHS[1].relative << "/\n\n";
		output << "Integration:\n";
		output << "  pkg-config: " << prefix << "/" << SDK_PATHS[2].relative << "\n";
		output << "  CMake:      " << prefix << "/" << SDK_PATHS[3].relative << "\n";
	}
	output << "\n";
	return rendered_output{
		output.str(), {}, presence.inspection_succeeded() ? INFO_EXIT_SUCCESS : INFO_EXIT_CHECK_FAILED};
}

/**
 * @brief Append the same compiled build facts to information and verification JSON.
 * @param output In-memory output transaction with checked stream state.
 * @param prefix Exact selected installation prefix.
 */
void append_json_build_facts(std::ostringstream &output, const std::string &prefix)
{
	output << "  \"version\": \"" << json_escape(std::string(VERSION)) << "\",\n";
	output << "  \"dpdk_version\": \"" << json_escape(std::string(DPDK_VERSION)) << "\",\n";
	output << "  \"tls_enabled\": " << (KINETUM_ENABLE_TLS ? "true" : "false") << ",\n";
	output << "  \"build_features\": {\n";
	output << "    \"axiom_mlir_frontend\": " << (KINETUM_ENABLE_MLIR ? "true" : "false") << ",\n";
	output << "    \"axiom_mlir_dialect\": " << (KINETUM_ENABLE_MLIR_DIALECT ? "true" : "false") << "\n";
	output << "  },\n";
	output << "  \"platform_capabilities\": [\n";
	for (std::size_t index = 0; index < PLATFORM_CAPABILITIES.size(); ++index) {
		output << "    \"" << PLATFORM_CAPABILITIES[index] << "\"";
		if (index + 1u != PLATFORM_CAPABILITIES.size()) {
			output << ",";
		}
		output << "\n";
	}
	output << "  ],\n";
	output << "  \"prefix\": \"" << json_escape(prefix) << "\",\n";
}

/**
 * @brief Append only the paths selected by component presence or runtime verification.
 * @param output In-memory output transaction with checked stream state.
 * @param prefix Exact selected installation prefix.
 * @param runtime_paths Runtime resources, or an empty view when unavailable.
 * @param sdk_paths SDK resources, or an empty view when absent or outside the operation's scope.
 */
void append_json_paths(std::ostringstream &output, const std::string &prefix,
		       std::span<const information_path> runtime_paths,
		       std::span<const information_path> sdk_paths = {})
{
	output << "  \"paths\": {";
	bool first = true;
	for (const auto paths : {runtime_paths, sdk_paths}) {
		for (const auto &path : paths) {
			output << (first ? "\n" : ",\n");
			first = false;
			std::string absolute = prefix;
			absolute.push_back('/');
			absolute.append(path.relative);
			output << "    \"" << path.key << "\": \"" << json_escape(absolute) << "\"";
		}
	}
	if (!first) {
		output << "\n  ";
	}
	output << "}\n";
}

/**
 * @brief Render build facts and component presence in JSON without publishing bytes.
 *
 * Output is a valid JSON object suitable for parsing with jq or
 * other JSON processors:
 * ```json
 * {
 *   "version": "0.1.0",
 *   "dpdk_version": "24.11.7",
 *   "tls_enabled": true,
 *   "build_features": {
 *     "axiom_mlir_frontend": false,
 *     "axiom_mlir_dialect": false
 *   },
 *   "platform_capabilities": [
 *     "coherent_runtime_telemetry",
 *     "commit_confirmed",
 *     "durable_guardrails",
 *     "exact_bootstrap",
 *     "ordered_epoch_transitions",
 *     "owner_worker_module_health",
 *     "selective_rollback",
 *     "synchronous_active_stages",
 *     "tracked_async_epoch_work"
 *   ],
 *   "prefix": "/opt/kinetum",
 *   "installation": {"runtime": "installed", "sdk": "not_installed"},
 *   "paths": {
 *     "binaries": "/opt/kinetum/bin",
 *     "modules": "/opt/kinetum/lib/modules"
 *   }
 * }
 * ```
 *
 * @param prefix Installation prefix path.
 * @param presence Independent component observations collected before rendering.
 * @return Complete presence report; a failed inspection has nonzero exit intent.
 */
[[nodiscard]] rendered_output render_json_info(const std::string &prefix, const installation_presence &presence)
{
	std::ostringstream output;
	output.exceptions(std::ios::badbit | std::ios::failbit);
	output.imbue(std::locale::classic());
	output << "{\n";
	append_json_build_facts(output, prefix);
	output << "  \"installation\": {\"runtime\": \"" << presence_name(presence.runtime) << "\", \"sdk\": \""
	       << presence_name(presence.sdk) << "\"},\n";
	append_json_paths(output, prefix,
			  presence.runtime == component_presence::INSTALLED ?
				  std::span<const information_path>(RUNTIME_PATHS) :
				  std::span<const information_path>{},
			  presence.sdk == component_presence::INSTALLED ? std::span<const information_path>(SDK_PATHS) :
									  std::span<const information_path>{});
	output << "}\n";
	return rendered_output{
		output.str(), {}, presence.inspection_succeeded() ? INFO_EXIT_SUCCESS : INFO_EXIT_CHECK_FAILED};
}

/**
 * @brief Verify exact installed runtime membership and the signed provider closure.
 *
 * Checks for presence of:
 * - Runtime metadata
 * - Runtime binaries
 * - Built-in module images
 * - Exact production provider components and signed inventory
 *
 * It then statically authenticates and reconstructs the installed provider
 * release under the production owner/mode/link policy. No component is loaded.
 * JSON includes the verified runtime's build facts and runtime paths; SDK
 * presence is outside this operation's scope.
 *
 * @param prefix Installation prefix to check.
 * @param json_output Whether to render the result as JSON.
 * @return Construction-fixed response whose exit intent is successful only
 * when all files and the signed closure verify.
 */
[[nodiscard]] rendered_output render_installation_check(const std::string &prefix, bool json_output)
{
	/** @brief One expected installation artifact reported by --check. */
	struct installation_component {
		std::string relative_path;  ///< Path relative to the installation root.
		std::string description;    ///< Human-readable artifact role.
	};

	std::vector<installation_component> components;
	const auto artifacts = kinetum::release::expected_runtime_artifacts();
	components.reserve(artifacts.size() + 1u);
	for (const auto &artifact : artifacts) {
		components.push_back({std::string(artifact.relative_path), std::string(artifact.description)});
	}
	components.push_back({std::string(kinetum::release::RUNTIME_PAYLOAD_MANIFEST), "Runtime payload manifest"});

	int errors = 0;
	std::vector<std::pair<std::string, bool>> results;
	results.reserve(components.size());

	for (const auto &comp : components) {
		const std::string path = prefix + "/" + comp.relative_path;
		const bool exists = path_exists(path);
		results.emplace_back(comp.description, exists);

		if (!exists) {
			++errors;
		}
	}

	const fs::path installation_root(prefix);
	const auto provider_policy = kinetum::provider::production_provider_file_policy(installation_root);
	const auto verification = kinetum::release::verify_installed_runtime(
		installation_root, kinetum::provider::native_provider_target_tuple(), provider_policy);
	const bool payload_verified = verification.payload.is_ok();
	const std::string payload_error = payload_verified ? std::string{} : verification.payload.to_string();
	if (!payload_verified) {
		++errors;
	}
	const bool provider_release_verified = verification.provider.is_ok();
	const std::string provider_release_error = provider_release_verified ? std::string{} :
									       verification.provider.to_string();
	if (!provider_release_verified) {
		++errors;
	}

	std::ostringstream standard_output;
	std::ostringstream standard_error;
	standard_output.exceptions(std::ios::badbit | std::ios::failbit);
	standard_error.exceptions(std::ios::badbit | std::ios::failbit);
	standard_output.imbue(std::locale::classic());
	standard_error.imbue(std::locale::classic());

	if (json_output) {
		standard_output << "{\n";
		append_json_build_facts(standard_output, prefix);
		standard_output << "  \"status\": \"" << (errors == 0 ? "ok" : "failed") << "\",\n";
		standard_output << "  \"errors\": " << errors << ",\n";
		standard_output << "  \"runtime_payload\": {\"verified\": " << (payload_verified ? "true" : "false");
		if (!payload_verified) {
			standard_output << ", \"error\": \"" << json_escape(payload_error) << "\"";
		}
		standard_output << "},\n";
		standard_output << "  \"provider_release\": {\"verified\": "
				<< (provider_release_verified ? "true" : "false");
		if (!provider_release_verified) {
			standard_output << ", \"error\": \"" << json_escape(provider_release_error) << "\"";
		}
		standard_output << "},\n";
		standard_output << "  \"components\": [\n";
		for (size_t i = 0; i < results.size(); ++i) {
			standard_output << "    {\"name\": \"" << json_escape(results[i].first)
					<< "\", \"present\": " << (results[i].second ? "true" : "false") << "}";
			if (i + 1 < results.size())
				standard_output << ",";
			standard_output << "\n";
		}
		standard_output << "  ],\n";
		append_json_paths(standard_output, prefix,
				  errors == 0 ? std::span<const information_path>(RUNTIME_PATHS) :
						std::span<const information_path>{});
		standard_output << "}\n";
	} else {
		standard_output << "Checking Kinetum installation at: " << prefix << "\n\n";

		for (size_t i = 0; i < components.size(); ++i) {
			if (results[i].second) {
				standard_output << "[OK]      " << results[i].first << "\n";
			} else {
				standard_error << "[MISSING] " << results[i].first << ": " << prefix << "/"
					       << components[i].relative_path << "\n";
			}
		}
		if (payload_verified) {
			standard_output << "[OK]      Complete runtime payload manifest\n";
		} else {
			standard_error << "[INVALID] Complete runtime payload manifest: " << payload_error << "\n";
		}
		if (provider_release_verified) {
			standard_output << "[OK]      Signed provider release closure\n";
		} else {
			standard_error << "[INVALID] Signed provider release closure: " << provider_release_error
				       << "\n";
		}

		standard_output << "\n";
		if (errors == 0) {
			standard_output << "Installation verified: OK\n";
		} else {
			standard_error << "Installation has " << errors << " integrity error(s)\n";
		}
	}

	return rendered_output{
		standard_output.str(),
		standard_error.str(),
		errors == 0 ? INFO_EXIT_SUCCESS : INFO_EXIT_CHECK_FAILED,
	};
}

}  // namespace

/**
 * @brief Parse and render one kinetum-info invocation.
 *
 * No output becomes visible until the returned transaction is emitted by the
 * process boundary.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Construction-fixed response for the complete invocation.
 */
[[nodiscard]] static rendered_output run_info(int argc, char **argv)
{
	bool json_output = false;
	bool do_check = false;
	std::string explicit_prefix;

	// Parse arguments
	for (int i = 1; i < argc; ++i) {
		const std::string_view arg = argv[i];

		if (arg == "--version" || arg == "-v") {
			return render_version();
		}

		if (arg == "--help" || arg == "-h") {
			return render_usage({}, INFO_EXIT_SUCCESS);
		}

		if (arg == "--json") {
			json_output = true;
			continue;
		}

		if (arg == "--check") {
			do_check = true;
			continue;
		}

		if (arg == "--prefix") {
			if (!explicit_prefix.empty() || i + 1 >= argc || argv[i + 1][0] == '\0') {
				return rendered_output{
					{}, "ERROR: --prefix requires one nonempty argument\n", INFO_EXIT_USAGE_ERROR};
			}
			explicit_prefix = argv[++i];
			continue;
		}

		std::string diagnostic = "Unknown option: ";
		diagnostic.append(arg);
		diagnostic.push_back('\n');
		return render_usage(std::move(diagnostic), INFO_EXIT_USAGE_ERROR);
	}

	// Resolve one exact prefix authority. argv[0], PATH, CWD, environment, and
	// default-prefix guesses are not part of installation identity.
	auto prefix_or = resolve_install_prefix(explicit_prefix);
	if (!prefix_or.is_ok()) {
		const auto &error = prefix_or.error();
		const int exit_code = error.code() == kinetum::common::status_code::INVALID_ARGUMENT ?
					      INFO_EXIT_USAGE_ERROR :
					      INFO_EXIT_CHECK_FAILED;
		if (json_output) {
			std::string output = "{\"status\": \"error\", \"message\": \"";
			output += json_escape(std::string(error.message()));
			output += "\"}\n";
			return rendered_output{std::move(output), {}, exit_code};
		}
		std::string diagnostic = "ERROR: ";
		diagnostic.append(error.message());
		if (!error.details().empty()) {
			diagnostic += ": ";
			diagnostic.append(error.details());
		}
		diagnostic.push_back('\n');
		return rendered_output{{}, std::move(diagnostic), exit_code};
	}
	const std::string prefix = std::move(prefix_or).value().string();

	auto output = [&]() {
		if (do_check) {
			return render_installation_check(prefix, json_output);
		}
		const auto presence = inspect_installation(prefix);
		return json_output ? render_json_info(prefix, presence) : render_all_info(prefix, presence);
	}();
	if (json_output && !kinetum::common::valid_utf8(output.view().standard_output)) {
		return rendered_output{"{\"status\": \"error\", \"message\": \"JSON output contains invalid UTF-8\"}\n",
				       {},
				       INFO_EXIT_CHECK_FAILED};
	}
	return output;
}

/**
 * @brief Main entry point for kinetum-info with total exception mapping.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit code (0=success, 1=inspection or check failed, 2=usage error).
 */
int main(int argc, char **argv)
{
	try {
		const auto output = run_info(argc, argv);
		return kinetum::common::emit_process_output(output.view());
	} catch (const std::bad_alloc &) {
		return kinetum::common::emit_process_output({
			.standard_output = {},
			.standard_error = "ERROR: kinetum-info exhausted memory\n",
			.complete_exit_code = INFO_EXIT_CHECK_FAILED,
		});
	} catch (const std::length_error &) {
		return kinetum::common::emit_process_output({
			.standard_output = {},
			.standard_error = "ERROR: kinetum-info exceeded host size limits\n",
			.complete_exit_code = INFO_EXIT_CHECK_FAILED,
		});
	} catch (const std::exception &) {
		return kinetum::common::emit_process_output({
			.standard_output = {},
			.standard_error = "ERROR: kinetum-info encountered an unexpected failure\n",
			.complete_exit_code = INFO_EXIT_CHECK_FAILED,
		});
	} catch (...) {
		return kinetum::common::emit_process_output({
			.standard_output = {},
			.standard_error = "ERROR: kinetum-info encountered an unknown failure\n",
			.complete_exit_code = INFO_EXIT_CHECK_FAILED,
		});
	}
}
