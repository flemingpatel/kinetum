// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file pack_source_admission.hpp
 * @brief Exact source-artifact admission for deployment-bundle production.
 * @author Fleming Patel
 *
 * Bundle source selection is resolved completely before parsing or output
 * construction. Required source files and the optional flat module-artifact
 * directory are canonicalized once. Runtime images are installed release
 * artifacts and are deliberately absent from this deployment-bundle contract.
 *
 * This component is cold-path only. It performs filesystem I/O and allocation
 * and must never execute on a packet-processing path.
 *
 * @par Thread Safety
 * The component owns no mutable state. Explicit relative inputs inherit the
 * stable-working-directory requirement of `path_admission.hpp`; pack invokes
 * this component before creating worker threads or output state.
 */

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "src/common/status_or.hpp"

namespace kinetum::pack
{

/** @brief Unresolved source authority supplied to one pack operation. */
struct pack_source_spec {
	std::filesystem::path pipeline;				///< Required Axiom pipeline source.
	std::filesystem::path hardware;				///< Required hardware-inventory source.
	std::filesystem::path bootstrap_snapshot;		///< Required bootstrap-snapshot source.
	std::filesystem::path deployment_bindings;		///< Required exact deployment-bindings source.
	std::optional<std::filesystem::path> module_directory;	///< Explicit `--modules-dir`, if supplied.
};

/** @brief Canonical source authority admitted for one pack operation. */
struct admitted_pack_sources {
	std::filesystem::path pipeline;				///< Canonical Axiom pipeline source.
	std::filesystem::path hardware;				///< Canonical hardware-inventory source.
	std::filesystem::path bootstrap_snapshot;		///< Canonical bootstrap-snapshot source.
	std::filesystem::path deployment_bindings;		///< Canonical deployment-bindings source.
	std::optional<std::filesystem::path> module_directory;	///< Present only for an explicit module source.
};

/** @brief One admitted auxiliary shared object copied beside a module image. */
struct admitted_module_dependency {
	/** @brief Bundle-local ELF basename retained from the source directory. */
	std::string filename;

	/** @brief Exact canonical source file. */
	std::filesystem::path source;
};

/** @brief Exact source-image naming contract for one built-in module. */
struct builtin_module_image {
	/** @brief Image basename looked up under `--modules-dir`. */
	std::string source_filename;
};

/**
 * @brief Test one value against the single-component module artifact grammar.
 *
 * Module identities and auxiliary ELF basenames become direct children of the
 * bundle's `modules/` directory. Both therefore use the same nonempty ASCII
 * atom grammar: letters, digits, period, underscore, and hyphen; `.` and `..`
 * are reserved.
 *
 * @param value Candidate module identity or dependency basename.
 * @return true only when the value is one safe bundle path component.
 */
[[nodiscard]] bool is_safe_bundle_module_atom(std::string_view value) noexcept;

/**
 * @brief Resolve one reserved built-in identity to its exact source image.
 *
 * @param module_id Exact `kinetum.*` module identity.
 * @return Source-image basename, or INVALID_ARGUMENT when the reserved
 *         identity is unknown.
 */
[[nodiscard]] kinetum::common::status_or<builtin_module_image> resolve_builtin_module_image(std::string_view module_id);

/**
 * @brief Admit all pack source authority atomically.
 *
 * @param spec Complete required and optional source specification.
 * @return Canonical source files and directories, or an exact
 *         file/directory-admission failure. No partial result is published.
 */
[[nodiscard]] kinetum::common::status_or<admitted_pack_sources> admit_pack_sources(const pack_source_spec &spec);

/**
 * @brief Admit every auxiliary shared object from one flat module directory.
 *
 * Main images are copied under semantic module IDs by the packer and are
 * excluded here by exact canonical identity. Every remaining direct-child
 * `.so` artifact is an explicit local dependency: symbolic links and
 * non-regular shared-object-shaped entries fail closed, nested contents are
 * never searched, basenames use `is_safe_bundle_module_atom()`, and the result
 * is sorted by basename for deterministic manifests.
 *
 * @param module_directory Exact canonical flat module source directory.
 * @param main_sources Canonical main-image sources keyed by module identity.
 * @return Deterministically sorted auxiliary artifacts, or the first exact
 *         directory, path, filename, or enumeration failure.
 */
[[nodiscard]] kinetum::common::status_or<std::vector<admitted_module_dependency>>
admit_module_dependencies(const std::filesystem::path &module_directory,
			  const std::unordered_map<std::string, std::filesystem::path> &main_sources);

}  // namespace kinetum::pack
