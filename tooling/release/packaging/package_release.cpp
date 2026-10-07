// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file package_release.cpp
 * @brief Native provider preparation and static release signing.
 * @author Fleming Patel
 */

#include "tooling/release/packaging/package_release.hpp"

#include <exception>
#include <string>
#include <string_view>
#include <utility>

#include "src/common/file_io.hpp"
#include "src/provider/provider_component_admission.hpp"
#include "src/provider/provider_installation.hpp"
#include "src/provider/provider_release.hpp"
#include "src/provider/provider_inventory.hpp"

namespace kinetum::release
{
namespace
{

/**
 * @brief Require one candidate output path not to exist in any file form.
 *
 * @param path Exact future output path.
 * @return OK only when no regular file, directory, or symbolic link exists.
 */
common::status require_absent(const std::filesystem::path &path)
{
	std::error_code error;
	const auto file_status = std::filesystem::symlink_status(path, error);
	if (error && error != std::errc::no_such_file_or_directory) {
		return common::status(common::status_code::INTERNAL_ERROR,
				      "failed to inspect provider release candidate output", error.message());
	}
	if (!error && file_status.type() != std::filesystem::file_type::not_found) {
		return common::status::already_exists(
			common::static_status_text("provider release candidate output already exists"));
	}
	return common::status::ok();
}

/**
 * @brief Reopen and compare one just-published candidate evidence file.
 *
 * @param path Exact output path.
 * @param expected Exact expected bytes.
 * @param maximum_size Exact read bound.
 * @param policy Candidate held-file policy.
 * @return OK only when metadata and bytes match through a retained descriptor.
 */
common::status verify_published_bytes(const std::filesystem::path &path, std::string_view expected,
				      uint64_t maximum_size, const common::held_file_policy &policy)
{
	auto file_or = common::open_held_regular_file(path, policy);
	if (!file_or.is_ok()) {
		return file_or.error();
	}
	auto bytes_or = common::read_held_file(file_or.value(), maximum_size);
	if (!bytes_or.is_ok()) {
		return bytes_or.error();
	}
	if (bytes_or.value() != expected) {
		return common::status::data_loss(
			common::static_status_text("published provider release evidence changed before verification"));
	}
	return common::status::ok();
}

/**
 * @brief Resolve one fixed child beneath an exact candidate root.
 *
 * @param root Exact candidate root.
 * @param relative Fixed provider-release path.
 * @return Lexically normalized exact child.
 */
std::filesystem::path candidate_path(const std::filesystem::path &root, std::string_view relative)
{
	return (root / std::filesystem::path(std::string(relative))).lexically_normal();
}

/**
 * @brief Read one exact candidate evidence file through its retained descriptor.
 *
 * @param path Exact fixed-layout path.
 * @param maximum_size Exact caller-owned bound.
 * @param policy Candidate held-file policy.
 * @return Exact immutable file bytes.
 */
common::status_or<std::string> read_candidate_file(const std::filesystem::path &path, uint64_t maximum_size,
						   const common::held_file_policy &policy)
{
	auto file_or = common::open_held_regular_file(path, policy);
	if (!file_or.is_ok()) {
		return file_or.error();
	}
	return common::read_held_file(file_or.value(), maximum_size);
}

}  // namespace

common::status prepare_provider_release_candidate(const std::filesystem::path &candidate_root,
						  provider::provider_target_tuple target, uint32_t candidate_owner_uid)
{
	if (target != provider::native_provider_target_tuple()) {
		return common::status::failed_precondition(common::static_status_text(
			"provider release preparation must execute on its exact target tuple"));
	}
	auto validation = provider::validate_provider_installation_root(candidate_root);
	if (!validation.is_ok()) {
		return validation;
	}
	const auto inventory_path =
		(candidate_root / std::filesystem::path(std::string(provider::PROVIDER_INVENTORY_RELATIVE_PATH)))
			.lexically_normal();
	const auto signature_path = (candidate_root / std::filesystem::path(std::string(
							      provider::PROVIDER_INVENTORY_SIGNATURE_RELATIVE_PATH)))
					    .lexically_normal();
	const auto receipt_path = (candidate_root / std::filesystem::path(std::string(
							    provider::PROVIDER_ADMISSION_RECEIPT_RELATIVE_PATH)))
					  .lexically_normal();
	for (const auto &path : {inventory_path, signature_path, receipt_path}) {
		validation = require_absent(path);
		if (!validation.is_ok()) {
			return validation;
		}
	}

	const auto policy = provider::release_candidate_file_policy(candidate_root, candidate_owner_uid);
	auto reconstructed_or = provider::reconstruct_production_provider_release(candidate_root, target, policy);
	if (!reconstructed_or.is_ok()) {
		return reconstructed_or.error();
	}
	auto reconstructed = std::move(reconstructed_or).value();
	auto receipt_bytes_or = provider::build_native_provider_admission_receipt(reconstructed, target);
	if (!receipt_bytes_or.is_ok()) {
		return receipt_bytes_or.error();
	}
	std::string inventory_bytes = reconstructed.canonical_bytes;
	std::string receipt_bytes = std::move(receipt_bytes_or).value();
	const std::size_t expected_component_count =
		static_cast<std::size_t>(reconstructed.inventory.components_size());

	auto admitted_or = provider::admit_preflighted_provider_components(std::move(reconstructed.components));
	if (!admitted_or.is_ok()) {
		return admitted_or.error();
	}

	// Foreign constructors have run. The helper exits after any later failure;
	// it never retries admission or publishes a candidate archive in-process.
	try {
		if (admitted_or->component_count() != expected_component_count) {
			std::terminate();
		}
		validation = common::publish_new_string_file(inventory_path, inventory_bytes);
		if (!validation.is_ok()) {
			return validation;
		}
		validation = common::publish_new_string_file(receipt_path, receipt_bytes);
		if (!validation.is_ok()) {
			return validation;
		}
		validation = verify_published_bytes(inventory_path, inventory_bytes,
						    provider::MAX_PROVIDER_INVENTORY_BYTES, policy);
		if (!validation.is_ok()) {
			return validation;
		}
		return verify_published_bytes(receipt_path, receipt_bytes,
					      provider::MAX_PROVIDER_ADMISSION_RECEIPT_BYTES, policy);
	} catch (...) {
		std::terminate();
	}
}

common::status finalize_provider_release_candidate(const std::filesystem::path &candidate_root,
						   provider::provider_target_tuple target, uint32_t candidate_owner_uid,
						   const provider_release_signing_key &signing_key,
						   const common::ed25519_public_key &expected_anchor)
{
	if (signing_key.public_key() != expected_anchor) {
		return common::status::permission_denied(
			common::static_status_text("release signing key is not bound to the finalizer trust anchor"));
	}
	auto validation = provider::validate_provider_installation_root(candidate_root);
	if (!validation.is_ok()) {
		return validation;
	}
	const auto inventory_path = candidate_path(candidate_root, provider::PROVIDER_INVENTORY_RELATIVE_PATH);
	const auto signature_path =
		candidate_path(candidate_root, provider::PROVIDER_INVENTORY_SIGNATURE_RELATIVE_PATH);
	const auto receipt_path = candidate_path(candidate_root, provider::PROVIDER_ADMISSION_RECEIPT_RELATIVE_PATH);
	validation = require_absent(signature_path);
	if (!validation.is_ok()) {
		return validation;
	}

	const auto policy = provider::release_candidate_file_policy(candidate_root, candidate_owner_uid);
	auto reconstructed_or = provider::reconstruct_production_provider_release(candidate_root, target, policy);
	if (!reconstructed_or.is_ok()) {
		return reconstructed_or.error();
	}
	auto reconstructed = std::move(reconstructed_or).value();
	auto inventory_bytes_or = read_candidate_file(inventory_path, provider::MAX_PROVIDER_INVENTORY_BYTES, policy);
	if (!inventory_bytes_or.is_ok()) {
		return inventory_bytes_or.error();
	}
	if (inventory_bytes_or.value() != reconstructed.canonical_bytes) {
		return common::status::failed_precondition(common::static_status_text(
			"native candidate inventory disagrees with independent release reconstruction"));
	}
	auto receipt_bytes_or =
		read_candidate_file(receipt_path, provider::MAX_PROVIDER_ADMISSION_RECEIPT_BYTES, policy);
	if (!receipt_bytes_or.is_ok()) {
		return receipt_bytes_or.error();
	}
	validation =
		provider::validate_native_provider_admission_receipt(receipt_bytes_or.value(), reconstructed, target);
	if (!validation.is_ok()) {
		return validation;
	}

	auto signed_or = provider::sign_provider_inventory(reconstructed.inventory, signing_key.key());
	if (!signed_or.is_ok()) {
		return signed_or.error();
	}
	if (signed_or->canonical_bytes != reconstructed.canonical_bytes) {
		return common::status::internal_error(common::static_status_text(
			"release finalizer signing bytes disagree with independent reconstruction"));
	}
	std::string signature_bytes(reinterpret_cast<const char *>(signed_or->signature.data()),
				    signed_or->signature.size());
	validation = common::publish_new_string_file(signature_path, signature_bytes);
	if (!validation.is_ok()) {
		return validation;
	}

	auto verified_or = provider::verify_installed_provider_release(candidate_root, target, expected_anchor, policy);
	if (!verified_or.is_ok()) {
		return verified_or.error();
	}
	if (verified_or->canonical_bytes != reconstructed.canonical_bytes) {
		return common::status::internal_error(common::static_status_text(
			"final signed release verification changed canonical inventory bytes"));
	}
	return common::status::ok();
}

}  // namespace kinetum::release
