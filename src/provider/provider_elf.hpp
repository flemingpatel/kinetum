// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_elf.hpp
 * @brief Exact ELF contract inspection for provider artifacts.
 * @author Fleming Patel
 *
 * libelf/GElf inspects the already-held descriptor used later for dynamic
 * loading. Component images must match the caller's exact supported 64-bit
 * target tuple and satisfy immediate binding, RELRO, non-executable stack, no
 * text relocations, no RPATH/RUNPATH, no loader-redirection tags, and no
 * dynamic flags other than immediate binding. A component has exactly one
 * default-visible definition: the component query authority. Private
 * dependencies obey the same hardening contract and additionally echo one
 * exact SONAME.
 *
 * @par Thread Safety
 * Each inspection reopens the retained inode through `/proc/self/fd/N` into an
 * independent file description and owns its libelf handle. The retained source
 * descriptor must not be closed during inspection.
 */

#include <string>
#include <string_view>
#include <vector>

#include "src/common/held_file.hpp"
#include "src/common/status_or.hpp"
#include "src/provider/provider_target_tuple.hpp"

namespace kinetum::provider
{

/** Exact immutable ELF facts covered by one artifact identity. */
struct provider_elf_facts {
	std::string soname;			  ///< DT_SONAME, empty only for a component image.
	std::vector<std::string> needed_sonames;  ///< Strictly sorted direct DT_NEEDED set.
};

/**
 * @brief Inspect one runtime executable through its held descriptor.
 *
 * Runtime executables and provider shared objects have different ELF policy.
 * This operation proves only the architecture-neutral release facts shared by
 * both executable forms: ELF64, little-endian encoding, the exact target
 * machine, and an executable ELF type. It deliberately does not apply the
 * component export, SONAME, PT_INTERP, or dynamic-tag policy.
 *
 * @param file Exact held runtime artifact.
 * @param target Exact release target tuple expected from the ELF identity.
 * @return OK only for an ET_EXEC or PIE-style ET_DYN image of that tuple.
 */
[[nodiscard]] common::status inspect_provider_runtime_elf(const common::held_file &file, provider_target_tuple target);

/**
 * @brief Inspect one provider component image through its held descriptor.
 *
 * @param file Exact held component artifact.
 * @param target Exact release target tuple expected from the ELF identity.
 * @return Hardened ELF facts, or the first fail-closed structural error.
 */
[[nodiscard]] common::status_or<provider_elf_facts> inspect_provider_component_elf(const common::held_file &file,
										   provider_target_tuple target);

/**
 * @brief Inspect one private provider dependency and require its exact SONAME.
 *
 * @param file Exact held private artifact.
 * @param expected_soname Authenticated inventory SONAME.
 * @param target Exact release target tuple expected from the ELF identity.
 * @return Hardened ELF facts, or the first structural/SONAME error.
 */
[[nodiscard]] common::status_or<provider_elf_facts> inspect_provider_private_elf(const common::held_file &file,
										 std::string_view expected_soname,
										 provider_target_tuple target);

}  // namespace kinetum::provider
