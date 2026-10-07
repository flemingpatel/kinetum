// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_release.cpp
 * @brief Exact production provider aggregate and release evidence implementation.
 * @author Fleming Patel
 */

#include "src/provider/provider_release.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gen/kinetum/release/v1/provider_release.pb.h"
#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_installation.hpp"

namespace kinetum::provider
{
namespace
{

using common::status;
using kinetum::release::v1::NativeProviderAdmissionReceipt;

/** Exact production DPDK component identity. */
constexpr std::string_view DPDK_COMPONENT_ID = "kinetum.provider.dpdk";

/** Exact production host component identity. */
constexpr std::string_view HOST_COMPONENT_ID = "kinetum.provider.host";

/** Exact contracts implemented by the production DPDK component. */
constexpr std::array DPDK_COMPONENT_CONTRACTS{
	DPDK_FACILITY_TYPE_URL,
	DPDK_DRIVER_TYPE_URL,
	DPDK_STORAGE_TYPE_URL,
};

/** Exact contracts implemented by the production host component. */
constexpr std::array HOST_COMPONENT_CONTRACTS{
	CPU_EXECUTION_TYPE_URL,
	HOST_STORAGE_TYPE_URL,
	ZERO_COPY_SHARE_TYPE_URL,
	BOUNDED_COPY_TYPE_URL,
};

static_assert(std::ranges::is_sorted(DPDK_COMPONENT_CONTRACTS));
static_assert(std::ranges::is_sorted(HOST_COMPONENT_CONTRACTS));
static_assert(DPDK_COMPONENT_ID < HOST_COMPONENT_ID);

/**
 * @brief Copy one fixed digest into a protobuf bytes field.
 *
 * @param digest Exact digest.
 * @param output Non-null protobuf destination.
 */
void assign_digest(const common::sha256_digest &digest, std::string *output)
{
	output->assign(reinterpret_cast<const char *>(digest.data()), digest.size());
}

/**
 * @brief Convert a fixed string-view set to owned release input strings.
 *
 * @param values Exact source-controlled values.
 * @return Owned strings preserving canonical order.
 */
template <std::size_t count>
std::vector<std::string> own_strings(const std::array<std::string_view, count> &values)
{
	std::vector<std::string> output;
	output.reserve(values.size());
	for (const std::string_view value : values) {
		output.emplace_back(value);
	}
	return output;
}

/**
 * @brief Derive one fixed release path beneath an exact root.
 *
 * @param root Exact validated root.
 * @param relative Exact source-controlled relative path.
 * @return Lexically normalized absolute child path.
 */
std::filesystem::path release_path(const std::filesystem::path &root, std::string_view relative)
{
	return (root / std::filesystem::path(std::string(relative))).lexically_normal();
}

}  // namespace

common::status_or<reconstructed_provider_inventory>
reconstruct_production_provider_release(const std::filesystem::path &installation_root, provider_target_tuple target,
					const common::held_file_policy &file_policy)
{
	auto validation = validate_provider_installation_root(installation_root);
	if (!validation.is_ok()) {
		return validation;
	}
	const auto artifact_directory = release_path(installation_root, PROVIDER_ARTIFACT_DIRECTORY);
	std::vector<release_provider_component_input> components;
	components.reserve(2);
	components.push_back(release_provider_component_input{
		.component_id = std::string(DPDK_COMPONENT_ID),
		.path = artifact_directory / std::filesystem::path(std::string(PRODUCTION_DPDK_COMPONENT_FILE_NAME)),
		.contract_type_urls = own_strings(DPDK_COMPONENT_CONTRACTS),
	});
	components.push_back(release_provider_component_input{
		.component_id = std::string(HOST_COMPONENT_ID),
		.path = artifact_directory / std::filesystem::path(std::string(PRODUCTION_HOST_COMPONENT_FILE_NAME)),
		.contract_type_urls = own_strings(HOST_COMPONENT_CONTRACTS),
	});
	return reconstruct_provider_inventory(release_path(installation_root, PROVIDER_RUNTIME_RELATIVE_PATH),
					      artifact_directory, std::move(components), {}, target, file_policy);
}

common::status_or<std::string>
build_native_provider_admission_receipt(const reconstructed_provider_inventory &reconstructed,
					provider_target_tuple target)
{
	auto canonical_inventory_or = canonicalize_provider_inventory(reconstructed.inventory);
	if (!canonical_inventory_or.is_ok()) {
		return canonical_inventory_or.error();
	}
	if (canonical_inventory_or.value() != reconstructed.canonical_bytes) {
		return status::invalid_argument(
			"native provider receipt input disagrees with its canonical inventory bytes");
	}
	auto digest_or = common::sha256_raw(reconstructed.canonical_bytes);
	if (!digest_or.is_ok()) {
		return digest_or.error();
	}

	NativeProviderAdmissionReceipt receipt;
	receipt.set_format_version(PROVIDER_ADMISSION_RECEIPT_FORMAT_VERSION);
	const std::string_view target_name = provider_target_tuple_name(target);
	receipt.set_target_tuple(target_name.data(), target_name.size());
	assign_digest(digest_or.value(), receipt.mutable_inventory_sha256());
	receipt.set_inventory_size_bytes(static_cast<uint64_t>(reconstructed.canonical_bytes.size()));
	for (const auto &component : reconstructed.inventory.components()) {
		*receipt.add_admitted_components() = component;
	}
	for (const auto &artifact : reconstructed.inventory.private_artifacts()) {
		*receipt.add_admitted_private_artifacts() = artifact;
	}
	auto bytes_or = common::serialize_protobuf_deterministically(receipt);
	if (!bytes_or.is_ok()) {
		return bytes_or.error();
	}
	if (bytes_or->size() > MAX_PROVIDER_ADMISSION_RECEIPT_BYTES) {
		return status::resource_exhausted("native provider admission receipt exceeds its byte bound");
	}
	return bytes_or;
}

common::status validate_native_provider_admission_receipt(std::string_view bytes,
							  const reconstructed_provider_inventory &reconstructed,
							  provider_target_tuple target)
{
	if (bytes.size() > MAX_PROVIDER_ADMISSION_RECEIPT_BYTES) {
		return status::resource_exhausted("native provider admission receipt exceeds its byte bound");
	}
	NativeProviderAdmissionReceipt receipt;
	if (bytes.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
	    !receipt.ParseFromArray(bytes.data(), static_cast<int>(bytes.size()))) {
		return status::invalid_argument("native provider admission receipt is not valid protobuf");
	}
	auto validation =
		common::reject_unknown_protobuf_fields_recursive(receipt, "native provider admission receipt");
	if (!validation.is_ok()) {
		return validation;
	}
	if (receipt.format_version() != PROVIDER_ADMISSION_RECEIPT_FORMAT_VERSION) {
		return status::failed_precondition("native provider admission receipt version is unsupported");
	}
	if (std::string_view(receipt.target_tuple()) != provider_target_tuple_name(target)) {
		return status::failed_precondition("native provider admission receipt target tuple disagrees");
	}
	if (receipt.inventory_sha256().size() != static_cast<int>(common::SHA256_DIGEST_SIZE)) {
		return status::invalid_argument("native provider admission receipt inventory identity is malformed");
	}
	auto canonical_or = common::serialize_protobuf_deterministically(receipt);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	if (canonical_or.value() != bytes) {
		return status::invalid_argument("native provider admission receipt is not in canonical byte form");
	}
	auto expected_or = build_native_provider_admission_receipt(reconstructed, target);
	if (!expected_or.is_ok()) {
		return expected_or.error();
	}
	if (expected_or.value() != bytes) {
		return status::failed_precondition(
			"native provider admission receipt disagrees with independent release reconstruction");
	}
	return status::ok();
}

common::status_or<authenticated_provider_inventory>
verify_installed_provider_release(const std::filesystem::path &installation_root, provider_target_tuple target,
				  const common::ed25519_public_key &trust_anchor,
				  const common::held_file_policy &file_policy)
{
	auto validation = validate_provider_installation_root(installation_root);
	if (!validation.is_ok()) {
		return validation;
	}
	auto runtime_or = common::open_held_regular_file(
		release_path(installation_root, PROVIDER_RUNTIME_RELATIVE_PATH), file_policy);
	if (!runtime_or.is_ok()) {
		return runtime_or.error();
	}
	auto inventory_file_or = common::open_held_regular_file(
		release_path(installation_root, PROVIDER_INVENTORY_RELATIVE_PATH), file_policy);
	if (!inventory_file_or.is_ok()) {
		return inventory_file_or.error();
	}
	auto signature_file_or = common::open_held_regular_file(
		release_path(installation_root, PROVIDER_INVENTORY_SIGNATURE_RELATIVE_PATH), file_policy);
	if (!signature_file_or.is_ok()) {
		return signature_file_or.error();
	}
	auto inventory_bytes_or = common::read_held_file(inventory_file_or.value(), MAX_PROVIDER_INVENTORY_BYTES);
	if (!inventory_bytes_or.is_ok()) {
		return inventory_bytes_or.error();
	}
	auto signature_bytes_or = common::read_held_file(signature_file_or.value(), common::ED25519_SIGNATURE_SIZE);
	if (!signature_bytes_or.is_ok()) {
		return signature_bytes_or.error();
	}
	auto signature_or = parse_provider_inventory_signature(signature_bytes_or.value());
	if (!signature_or.is_ok()) {
		return signature_or.error();
	}
	auto authenticated_or =
		authenticate_provider_inventory(inventory_bytes_or.value(), signature_or.value(), trust_anchor);
	if (!authenticated_or.is_ok()) {
		return authenticated_or.error();
	}
	validation = validate_provider_inventory_runtime_binding(authenticated_or->inventory, runtime_or.value());
	if (!validation.is_ok()) {
		return validation;
	}
	auto reconstructed_or = reconstruct_production_provider_release(installation_root, target, file_policy);
	if (!reconstructed_or.is_ok()) {
		return reconstructed_or.error();
	}
	if (reconstructed_or->canonical_bytes != authenticated_or->canonical_bytes) {
		return status::failed_precondition(
			"signed provider inventory disagrees with the exact production release aggregate");
	}
	auto receipt_file_or = common::open_held_regular_file(
		release_path(installation_root, PROVIDER_ADMISSION_RECEIPT_RELATIVE_PATH), file_policy);
	if (!receipt_file_or.is_ok()) {
		return receipt_file_or.error();
	}
	auto receipt_bytes_or = common::read_held_file(receipt_file_or.value(), MAX_PROVIDER_ADMISSION_RECEIPT_BYTES);
	if (!receipt_bytes_or.is_ok()) {
		return receipt_bytes_or.error();
	}
	validation =
		validate_native_provider_admission_receipt(receipt_bytes_or.value(), reconstructed_or.value(), target);
	if (!validation.is_ok()) {
		return validation;
	}
	return authenticated_or;
}

}  // namespace kinetum::provider
