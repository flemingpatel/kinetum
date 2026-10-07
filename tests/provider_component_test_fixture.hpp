// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_component_test_fixture.hpp
 * @brief Exact staged-artifact fixture for provider component tests.
 * @author Fleming Patel
 *
 * The fixture creates the same fixed installation shape consumed by the
 * runtime loader. It copies explicit completed test artifacts, derives raw
 * inventory records from their held descriptors and ELF facts, and can write
 * one canonical detached-signed inventory. It performs no discovery.
 */

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "gen/kinetum/provider/v1/installed_provider_inventory.pb.h"
#include "src/common/process_image.hpp"
#include "src/provider/provider_build_identity.hpp"
#include "src/provider/provider_component_admission.hpp"
#include "src/provider/provider_component_loader.hpp"
#include "src/provider/provider_elf.hpp"
#include "src/provider/provider_inventory.hpp"
#include "tests/provider_test_signing_key.hpp"

namespace kinetum::test
{

/**
 * @brief One unique fixed-layout provider installation owned by a test.
 */
class provider_component_test_fixture {
    public:
	/** @brief Create empty canonical staging directories. */
	provider_component_test_fixture()
	{
		static std::atomic<uint64_t> sequence{0};
		const uint64_t identity = sequence.fetch_add(1, std::memory_order_relaxed);
		root_ = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
			("kinetum_provider_component_" + std::to_string(static_cast<uint64_t>(::getpid())) + "_" +
			 std::to_string(identity));
		artifact_directory_ = root_ / std::filesystem::path(std::string(provider::PROVIDER_ARTIFACT_DIRECTORY));
		const std::filesystem::path inventory_directory = root_ / "share/kinetum/providers";
		create_exact_directories(artifact_directory_, "provider artifact");
		create_exact_directories(inventory_directory, "provider inventory");
	}

	/** @brief Remove every staged artifact. */
	~provider_component_test_fixture()
	{
		std::error_code ignored;
		std::filesystem::remove_all(root_, ignored);
	}

	/** @brief A second owner cannot share artifact cleanup. */
	provider_component_test_fixture(const provider_component_test_fixture &) = delete;
	/** @brief Copy assignment cannot replace owned artifacts. */
	provider_component_test_fixture &operator=(const provider_component_test_fixture &) = delete;
	/** @brief Keep borrowed artifact paths stable until cleanup. */
	provider_component_test_fixture(provider_component_test_fixture &&) = delete;
	/** @brief Move assignment cannot replace a live installation owner. */
	provider_component_test_fixture &operator=(provider_component_test_fixture &&) = delete;

	/** @return Borrowed fixture-owned installation root. */
	[[nodiscard]] const std::filesystem::path &root() const noexcept
	{
		return root_;
	}

	/** @return Borrowed fixed provider artifact directory. */
	[[nodiscard]] const std::filesystem::path &artifact_directory() const noexcept
	{
		return artifact_directory_;
	}

	/**
	 * @brief Materialize and return the exact staged runtime image.
	 *
	 * The copy is lazy because admission-only fixtures never consume runtime
	 * identity. A loader/release fixture creates it at most once.
	 *
	 * @return Exact staged runtime image.
	 */
	[[nodiscard]] const std::filesystem::path &runtime_image()
	{
		if (!runtime_image_.empty()) {
			return runtime_image_;
		}
		const std::filesystem::path runtime_directory = root_ / "bin";
		create_exact_directories(runtime_directory, "provider runtime");
		auto runtime_or = common::current_process_image();
		if (!runtime_or.is_ok()) {
			throw std::runtime_error(runtime_or.error().to_string());
		}
		const std::filesystem::path staged_runtime = runtime_directory / "kinetum_test_runtime";
		copy_exact_file(runtime_or.value(), staged_runtime, STAGED_EXECUTABLE_PERMISSIONS, "provider runtime");
		runtime_image_ = staged_runtime;
		return runtime_image_;
	}

	/**
	 * @return Current-user ownership, protected-mode, and single-link policy for fixture files.
	 * @throws std::bad_alloc if copying the policy's root path cannot allocate.
	 */
	[[nodiscard]] common::held_file_policy file_policy() const
	{
		const auto owner = static_cast<uint32_t>(::geteuid());
		const auto forbidden_modes = static_cast<uint32_t>(S_IWGRP | S_IWOTH);
		return common::held_file_policy{
			.required_owner_uid = owner,
			.forbidden_mode_bits = forbidden_modes,
			.require_single_link = true,
			.directories =
				common::held_directory_policy{
					.root = root_,
					.required_owner_uid = owner,
					.forbidden_mode_bits = forbidden_modes,
				},
			.maximum_size_bytes = std::nullopt,
		};
	}

	/**
	 * @brief Copy one explicit completed artifact into the fixed directory.
	 *
	 * @param source Exact source artifact path.
	 * @param file_name Exact destination basename.
	 * @return Exact staged path.
	 */
	[[nodiscard]] std::filesystem::path stage_artifact(const std::filesystem::path &source,
							   std::string_view file_name) const
	{
		const std::filesystem::path destination = artifact_directory_ / std::string(file_name);
		copy_exact_file(source, destination, STAGED_DATA_PERMISSIONS, "provider artifact");
		return destination;
	}

	/**
	 * @brief Derive one exact private-artifact inventory record.
	 *
	 * @param path Exact staged private artifact.
	 * @param soname Source-controlled expected SONAME.
	 * @return Complete canonical record.
	 */
	[[nodiscard]] provider::v1::PrivateProviderArtifact private_artifact_record(const std::filesystem::path &path,
										    std::string_view soname) const
	{
		auto file_or = common::open_held_regular_file(path, file_policy());
		if (!file_or.is_ok()) {
			throw std::runtime_error(file_or.error().to_string());
		}
		auto elf_or = provider::inspect_provider_private_elf(file_or.value(), soname,
								     provider::native_provider_target_tuple());
		if (!elf_or.is_ok()) {
			throw std::runtime_error(elf_or.error().to_string());
		}

		provider::v1::PrivateProviderArtifact artifact;
		artifact.set_file_name(path.filename().string());
		artifact.set_soname(std::string(soname));
		artifact.set_sha256(reinterpret_cast<const char *>(file_or->identity().sha256.data()),
				    file_or->identity().sha256.size());
		artifact.set_size_bytes(file_or->identity().size_bytes);
		for (const auto &needed : elf_or->needed_sonames) {
			artifact.add_needed_sonames(needed);
		}
		return artifact;
	}

	/**
	 * @brief Derive one exact component-artifact inventory record.
	 *
	 * @param path Exact staged component.
	 * @param component_id Source-controlled descriptor identity claim.
	 * @param contracts Complete exact contract set.
	 * @return Complete canonical record.
	 */
	[[nodiscard]] provider::v1::ProviderComponentArtifact component_record(const std::filesystem::path &path,
									       std::string_view component_id,
									       std::vector<std::string> contracts) const
	{
		auto file_or = common::open_held_regular_file(path, file_policy());
		if (!file_or.is_ok()) {
			throw std::runtime_error(file_or.error().to_string());
		}
		auto elf_or = provider::inspect_provider_component_elf(file_or.value(),
								       provider::native_provider_target_tuple());
		if (!elf_or.is_ok()) {
			throw std::runtime_error(elf_or.error().to_string());
		}

		provider::v1::ProviderComponentArtifact component;
		component.set_component_id(std::string(component_id));
		component.set_file_name(path.filename().string());
		component.set_sha256(reinterpret_cast<const char *>(file_or->identity().sha256.data()),
				     file_or->identity().sha256.size());
		component.set_size_bytes(file_or->identity().size_bytes);
		std::sort(contracts.begin(), contracts.end());
		for (auto &contract : contracts) {
			component.add_contract_type_urls(std::move(contract));
		}
		for (const auto &needed : elf_or->needed_sonames) {
			component.add_needed_sonames(needed);
		}
		return component;
	}

	/**
	 * @brief Construct a complete exact inventory around supplied records.
	 *
	 * @param components Explicit component records.
	 * @param private_artifacts Explicit private dependency records.
	 * @return Candidate inventory ready for canonical signing.
	 */
	[[nodiscard]] provider::v1::InstalledProviderInventory
	inventory(const std::vector<provider::v1::ProviderComponentArtifact> &components,
		  const std::vector<provider::v1::PrivateProviderArtifact> &private_artifacts)
	{
		auto runtime_or = common::open_held_regular_file(runtime_image(), file_policy());
		if (!runtime_or.is_ok()) {
			throw std::runtime_error(runtime_or.error().to_string());
		}
		provider::v1::InstalledProviderInventory inventory_value;
		inventory_value.set_product_version(KINETUM_VERSION_STR);
		inventory_value.set_provider_abi_identity(
			reinterpret_cast<const char *>(provider::PROVIDER_ABI_IDENTITY.data()),
			provider::PROVIDER_ABI_IDENTITY.size());
		inventory_value.set_runtime_sha256(reinterpret_cast<const char *>(runtime_or->identity().sha256.data()),
						   runtime_or->identity().sha256.size());
		inventory_value.set_runtime_size_bytes(runtime_or->identity().size_bytes);
		for (const auto &artifact : private_artifacts) {
			inventory_value.add_private_artifacts()->CopyFrom(artifact);
		}
		for (const auto &component : components) {
			inventory_value.add_components()->CopyFrom(component);
		}
		return inventory_value;
	}

	/**
	 * @brief Write canonical inventory and detached signature to fixed paths.
	 *
	 * @param inventory_value Candidate inventory.
	 * @return Exact signed bytes retained by the files.
	 */
	[[nodiscard]] provider::signed_provider_inventory
	write_signed_inventory(provider::v1::InstalledProviderInventory inventory_value) const
	{
		auto signed_or =
			provider::sign_provider_inventory(std::move(inventory_value), PROVIDER_TEST_PRIVATE_KEY);
		if (!signed_or.is_ok()) {
			throw std::runtime_error(signed_or.error().to_string());
		}
		auto signed_value = std::move(signed_or).value();
		write_bytes(root_ / std::filesystem::path(std::string(provider::PROVIDER_INVENTORY_RELATIVE_PATH)),
			    signed_value.canonical_bytes);
		write_bytes(root_ / std::filesystem::path(
					    std::string(provider::PROVIDER_INVENTORY_SIGNATURE_RELATIVE_PATH)),
			    std::string_view(reinterpret_cast<const char *>(signed_value.signature.data()),
					     signed_value.signature.size()));
		return signed_value;
	}

    private:
	/** Exact installation mode used by every staged directory. */
	static constexpr std::filesystem::perms STAGED_DIRECTORY_PERMISSIONS =
		std::filesystem::perms::owner_all | std::filesystem::perms::group_read |
		std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
		std::filesystem::perms::others_exec;

	/** Exact non-executable installation mode used by staged artifacts. */
	static constexpr std::filesystem::perms STAGED_DATA_PERMISSIONS =
		std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
		std::filesystem::perms::group_read | std::filesystem::perms::others_read;

	/** Exact executable installation mode used by the staged runtime image. */
	static constexpr std::filesystem::perms STAGED_EXECUTABLE_PERMISSIONS =
		STAGED_DATA_PERMISSIONS | std::filesystem::perms::owner_exec | std::filesystem::perms::group_exec |
		std::filesystem::perms::others_exec;

	/**
	 * @brief Apply one exact fixture installation mode.
	 *
	 * @param path Exact completed destination.
	 * @param permissions Complete replacement permission set.
	 * @param role Stable diagnostic role.
	 */
	static void set_exact_permissions(const std::filesystem::path &path, std::filesystem::perms permissions,
					  std::string_view role)
	{
		std::error_code error;
		std::filesystem::permissions(path, permissions, std::filesystem::perm_options::replace, error);
		if (error) {
			throw std::runtime_error("failed to set " + std::string(role) +
						 " fixture permissions: " + error.message());
		}
	}

	/**
	 * @brief Create one explicit fixture directory chain with exact modes.
	 *
	 * Every directory at or below the fixture root is normalized after
	 * creation, so admission evidence is independent of the process umask.
	 *
	 * @param path Exact descendant directory to create.
	 * @param role Stable diagnostic role.
	 */
	void create_exact_directories(const std::filesystem::path &path, std::string_view role) const
	{
		std::error_code error;
		std::filesystem::create_directories(path, error);
		if (error) {
			throw std::runtime_error("failed to create " + std::string(role) +
						 " fixture directory: " + error.message());
		}

		const std::filesystem::path relative = path.lexically_relative(root_);
		if (relative.empty() || relative.is_absolute()) {
			throw std::runtime_error("provider fixture directory is outside its exact root");
		}

		std::filesystem::path current = root_;
		set_exact_permissions(current, STAGED_DIRECTORY_PERMISSIONS, role);
		for (const auto &component : relative) {
			if (component.empty() || component == "." || component == ".." || component.has_parent_path()) {
				throw std::runtime_error("provider fixture directory has a noncanonical component");
			}
			current /= component;
			set_exact_permissions(current, STAGED_DIRECTORY_PERMISSIONS, role);
		}
		if (current != path) {
			throw std::runtime_error("provider fixture directory disagrees with its exact root");
		}
	}

	/**
	 * @brief Copy one completed file into exact fixture ownership.
	 *
	 * @param source Exact completed source.
	 * @param destination Exact absent destination.
	 * @param permissions Complete destination permission set.
	 * @param role Stable diagnostic role.
	 */
	static void copy_exact_file(const std::filesystem::path &source, const std::filesystem::path &destination,
				    std::filesystem::perms permissions, std::string_view role)
	{
		std::error_code error;
		std::filesystem::copy_file(source, destination, std::filesystem::copy_options::none, error);
		if (error) {
			throw std::runtime_error("failed to stage " + std::string(role) +
						 " fixture: " + error.message());
		}
		set_exact_permissions(destination, permissions, role);
	}

	/**
	 * @brief Write exact binary bytes to one pre-created parent directory.
	 * @param path Fixture-owned output path whose parent already exists.
	 * @param bytes Borrowed complete binary payload.
	 */
	static void write_bytes(const std::filesystem::path &path, std::string_view bytes)
	{
		std::ofstream output(path, std::ios::binary | std::ios::trunc);
		if (!output || !output.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
		    !output.flush()) {
			throw std::runtime_error("failed to write provider fixture bytes");
		}
		set_exact_permissions(path, STAGED_DATA_PERMISSIONS, "provider inventory");
	}

	std::filesystem::path root_;		    ///< Unique fixed installation root.
	std::filesystem::path artifact_directory_;  ///< Fixed component/private directory.
	std::filesystem::path runtime_image_;	    ///< Exact staged runtime image.
};

}  // namespace kinetum::test
