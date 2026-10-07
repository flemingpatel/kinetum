// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_component_preflight.hpp
 * @brief Architecture-selectable static admission for provider artifacts.
 * @author Fleming Patel
 *
 * Preflight consumes authenticated inventory records, opens each exact staged
 * artifact through the held-descriptor authority, validates content identity,
 * inspects its target-tuple ELF contract, and proves the complete private
 * dependency closure. It never loads or executes an artifact.
 *
 * Native runtime admission and architecture-neutral release finalization share
 * this mechanism. Only native runtime admission may pass a completed proof to
 * the separate dynamic component-admission authority.
 *
 * @par Thread Safety
 * A proof token is a unique movable owner. Distinct artifact sets may be
 * preflighted concurrently when their files are immutable.
 *
 * @par Performance
 * Preflight performs filesystem traversal, hashing, and ELF inspection on the
 * cold path. It is absent from packet-worker call graphs.
 */

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "gen/kinetum/provider/v1/installed_provider_inventory.pb.h"
#include "src/common/held_file.hpp"
#include "src/common/status_or.hpp"
#include "src/provider/provider_elf.hpp"
#include "src/provider/provider_target_tuple.hpp"

namespace kinetum::provider
{

/** Private dynamic-admission bridge for an unforgeable preflight token. */
class provider_component_admission_access;

/**
 * @brief Classify one exact ELF dependency as part of the platform runtime.
 *
 * Platform-runtime SONAMEs are selected by the explicit target tuple and do
 * not appear as signed provider-private artifacts. Every other dependency in
 * a component's reachable `DT_NEEDED` graph must belong to that component's
 * exact private closure.
 *
 * @param soname Exact `DT_NEEDED` identity.
 * @param target Exact release target whose runtime closure is classified.
 * @return true only for the closed target-specific runtime SONAME set.
 */
[[nodiscard]] bool is_platform_runtime_soname(std::string_view soname, provider_target_tuple target) noexcept;

/**
 * @brief Unforgeable proof that one component and its closure passed preflight.
 *
 * Construction is private to preflight_provider_component(). Callers may
 * inspect authenticated identities but cannot manufacture a value that bypasses
 * held-file, content-identity, ELF, or dependency-closure admission.
 */
class preflighted_provider_component {
    public:
	/** @brief Disable proof-token duplication. */
	preflighted_provider_component(const preflighted_provider_component &) = delete;

	/** @brief Disable proof-token duplication by assignment. */
	preflighted_provider_component &operator=(const preflighted_provider_component &) = delete;

	/** @brief Transfer one complete preflight proof. */
	preflighted_provider_component(preflighted_provider_component &&) noexcept = default;

	/** @return This owner after transfer of one complete preflight proof. */
	preflighted_provider_component &operator=(preflighted_provider_component &&) noexcept = default;

	/** @return Borrowed authenticated component record retained by this proof. */
	[[nodiscard]] const kinetum::provider::v1::ProviderComponentArtifact &record() const noexcept;

	/** @return Number of private dependencies retained in children-before-parents order. */
	[[nodiscard]] std::size_t private_dependency_count() const noexcept;

	/**
	 * @brief Return one private dependency artifact basename.
	 *
	 * @param index Index in `[0, private_dependency_count())`.
	 * @return Stable authenticated basename view, or an empty view when out of range.
	 */
	[[nodiscard]] std::string_view private_dependency_file_name(std::size_t index) const noexcept;

	/**
	 * @brief Return one private dependency SONAME by load-order index.
	 *
	 * @param index Index in `[0, private_dependency_count())`.
	 * @return Stable SONAME view, or an empty view when out of range.
	 */
	[[nodiscard]] std::string_view private_dependency_soname(std::size_t index) const noexcept;

	/**
	 * @brief Return one private dependency content identity.
	 *
	 * @param index Index in `[0, private_dependency_count())`.
	 * @return Stable digest pointer, or null when out of range.
	 */
	[[nodiscard]] const common::sha256_digest *private_dependency_sha256(std::size_t index) const noexcept;

    private:
	/** One admitted private artifact retained through optional component loading. */
	struct private_artifact {
		std::string file_name;	 ///< Authenticated exact basename.
		std::string soname;	 ///< Authenticated exact DT_SONAME.
		common::held_file file;	 ///< Held and identity-verified artifact.
		provider_elf_facts elf;	 ///< Same-descriptor exact ELF facts.
	};

	friend common::status_or<preflighted_provider_component> preflight_provider_component(
		const std::filesystem::path &, const kinetum::provider::v1::ProviderComponentArtifact &,
		const google::protobuf::RepeatedPtrField<kinetum::provider::v1::PrivateProviderArtifact> &,
		provider_target_tuple, const common::held_file_policy &);
	friend class provider_component_admission_access;

	/**
	 * @brief Construct one proof after every static preflight predicate succeeds.
	 * @param record Authenticated component claims transferred into this proof.
	 * @param file Sole held component-file identity and descriptor.
	 * @param elf Facts inspected through that same descriptor.
	 * @param private_dependencies Held private closure in children-before-parents order.
	 */
	preflighted_provider_component(kinetum::provider::v1::ProviderComponentArtifact record, common::held_file file,
				       provider_elf_facts elf,
				       std::vector<private_artifact> private_dependencies) noexcept;

	kinetum::provider::v1::ProviderComponentArtifact record_;  ///< Authenticated artifact claims.
	common::held_file file_;				   ///< Held exact component artifact.
	provider_elf_facts elf_;				   ///< Same-descriptor component ELF facts.
	std::vector<private_artifact> private_dependencies_;	   ///< Children-before-parents closure.
};

/**
 * @brief Preflight one authenticated component and complete private closure.
 *
 * @param artifact_directory Exact absolute fixed provider artifact directory.
 * @param component Authenticated component record.
 * @param private_artifacts Complete authenticated release private-artifact set.
 * @param target Exact release target tuple expected from every ELF artifact.
 * @param file_policy Exact owner/mode/link and directory policy.
 * @return Held component plus children-before-parents private closure.
 */
[[nodiscard]] common::status_or<preflighted_provider_component> preflight_provider_component(
	const std::filesystem::path &artifact_directory,
	const kinetum::provider::v1::ProviderComponentArtifact &component,
	const google::protobuf::RepeatedPtrField<kinetum::provider::v1::PrivateProviderArtifact> &private_artifacts,
	provider_target_tuple target, const common::held_file_policy &file_policy);

/**
 * @brief Validate one complete preflighted component set without executing it.
 *
 * This is the final static proof shared by architecture-neutral release
 * finalization and native dynamic admission. It requires globally unique
 * component and contract ownership plus one consistent content identity for
 * every artifact basename and private SONAME.
 *
 * @param components Complete preflight proof set.
 * @return OK only when every global identity relation is exact.
 */
[[nodiscard]] common::status
validate_preflighted_provider_component_set(std::span<const preflighted_provider_component> components);

}  // namespace kinetum::provider
