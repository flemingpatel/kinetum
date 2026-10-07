// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_inventory.cpp
 * @brief Canonical installed-provider inventory implementation.
 * @author Fleming Patel
 */

#include "src/provider/provider_inventory.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>

#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256_digest.hpp"
#include "src/common/status.hpp"
#include "src/provider/provider_build_identity.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_inventory_internal.hpp"

namespace kinetum::provider
{
namespace
{

using common::status;
using common::status_or;
using kinetum::provider::v1::InstalledProviderInventory;
using kinetum::provider::v1::PrivateProviderArtifact;
using kinetum::provider::v1::ProviderComponentArtifact;

/**
 * @brief Convert one exact validated bytes field to a digest.
 *
 * @param bytes Exact 32-byte field.
 * @return Fixed-width digest.
 */
common::sha256_digest digest_from_bytes(std::string_view bytes) noexcept
{
	common::sha256_digest digest{};
	std::memcpy(digest.data(), bytes.data(), digest.size());
	return digest;
}

/**
 * @brief Validate one stable component identity.
 *
 * @param value Candidate identity.
 * @return true only for lowercase dot/dash/underscore-delimited ASCII atoms.
 */
bool valid_component_id(std::string_view value) noexcept
{
	if (value.empty() || value.size() > MAX_PROVIDER_ID_BYTES || value.front() < 'a' || value.front() > 'z') {
		return false;
	}
	bool separator = false;
	for (const char character : value) {
		const bool alphanumeric = (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9');
		const bool current_separator = character == '.' || character == '-' || character == '_';
		if (!alphanumeric && !current_separator) {
			return false;
		}
		if (current_separator && separator) {
			return false;
		}
		separator = current_separator;
	}
	return !separator;
}

/**
 * @brief Validate one exact artifact basename or ELF SONAME.
 *
 * @param value Candidate single path component.
 * @return true only for one bounded safe ASCII basename.
 */
bool valid_artifact_name(std::string_view value) noexcept
{
	if (value.empty() || value == "." || value == ".." || value.size() > MAX_PROVIDER_ARTIFACT_NAME_BYTES) {
		return false;
	}
	for (const char character : value) {
		const bool alphanumeric = (character >= 'A' && character <= 'Z') ||
					  (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9');
		if (!alphanumeric && character != '.' && character != '_' && character != '-' && character != '+') {
			return false;
		}
	}
	return true;
}

/**
 * @brief Validate one exact three-part product version.
 *
 * @param value Candidate product version.
 * @return true only for canonical decimal MAJOR.MINOR.PATCH.
 */
bool valid_product_version(std::string_view value) noexcept
{
	if (value.empty()) {
		return false;
	}
	std::size_t atom_length = 0;
	uint8_t dot_count = 0;
	bool leading_zero = false;
	for (const char character : value) {
		if (character == '.') {
			if (atom_length == 0 || dot_count == 2) {
				return false;
			}
			++dot_count;
			atom_length = 0;
			leading_zero = false;
			continue;
		}
		if (character < '0' || character > '9') {
			return false;
		}
		if (atom_length == 0) {
			leading_zero = character == '0';
		} else if (leading_zero) {
			return false;
		}
		++atom_length;
	}
	return dot_count == 2 && atom_length != 0;
}

/**
 * @brief Require one repeated string field to be sorted and unique.
 *
 * @param values Repeated string field.
 * @param field_name Trusted diagnostic field name.
 * @return OK only for strict lexicographic order.
 */
template <typename repeated_strings>
status require_sorted_unique(const repeated_strings &values, std::string_view field_name)
{
	for (int index = 1; index < values.size(); ++index) {
		if (values.Get(index - 1) >= values.Get(index)) {
			return status::invalid_argument(std::string(field_name) +
							" must be strictly sorted and unique");
		}
	}
	return status::ok();
}

/**
 * @brief Sort one repeated string field and reject duplicates.
 *
 * @param values Mutable repeated string field.
 * @param field_name Trusted diagnostic field name.
 * @return OK after canonical sorting, or INVALID_ARGUMENT for duplicates.
 */
status sort_unique_strings(google::protobuf::RepeatedPtrField<std::string> *values, std::string_view field_name)
{
	std::sort(values->begin(), values->end());
	for (int index = 1; index < values->size(); ++index) {
		if (values->Get(index - 1) == values->Get(index)) {
			return status::invalid_argument(std::string(field_name) + " contains duplicate identities");
		}
	}
	return status::ok();
}

/**
 * @brief Validate one private artifact's declared fields after canonical sorting.
 *
 * @param artifact Candidate private artifact.
 * @return OK only for one complete exact record.
 */
status validate_private_artifact_fields(const PrivateProviderArtifact &artifact)
{
	if (!valid_artifact_name(artifact.file_name()) || !valid_artifact_name(artifact.soname())) {
		return status::invalid_argument("private provider artifact requires exact safe file_name and soname");
	}
	if (artifact.sha256().size() != static_cast<int>(common::SHA256_DIGEST_SIZE) || artifact.size_bytes() == 0) {
		return status::invalid_argument("private provider artifact requires exact nonempty SHA-256 identity");
	}
	if (artifact.needed_sonames_size() > static_cast<int>(MAX_PROVIDER_NEEDED_SONAMES)) {
		return status::resource_exhausted("private provider artifact dependency count exceeds its bound");
	}
	for (const auto &soname : artifact.needed_sonames()) {
		if (!valid_artifact_name(soname)) {
			return status::invalid_argument("private provider artifact contains an invalid needed SONAME");
		}
	}
	return require_sorted_unique(artifact.needed_sonames(), "private needed_sonames");
}

/**
 * @brief Validate one component's declared fields after canonical sorting.
 *
 * @param component Candidate component.
 * @return OK only for one complete exact artifact and descriptor claim.
 */
status validate_component_fields(const ProviderComponentArtifact &component)
{
	if (!valid_component_id(component.component_id())) {
		return status::invalid_argument("provider component_id is not canonical");
	}
	if (!valid_artifact_name(component.file_name())) {
		return status::invalid_argument("provider component file_name is not one safe basename");
	}
	if (component.sha256().size() != static_cast<int>(common::SHA256_DIGEST_SIZE) || component.size_bytes() == 0) {
		return status::invalid_argument("provider component requires exact nonempty SHA-256 identity");
	}
	if (component.contract_type_urls().empty()) {
		return status::invalid_argument("provider component must own at least one contract");
	}
	if (component.contract_type_urls_size() > static_cast<int>(provider_contract_count())) {
		return status::resource_exhausted("provider component contract count exceeds the pure catalog bound");
	}
	for (const auto &type_url : component.contract_type_urls()) {
		if (find_provider_contract(type_url) == nullptr) {
			return status::invalid_argument(
				"provider component claims a type URL absent from the pure catalog");
		}
	}
	auto order_status = require_sorted_unique(component.contract_type_urls(), "component contract_type_urls");
	if (!order_status.is_ok()) {
		return order_status;
	}
	if (component.needed_sonames_size() > static_cast<int>(MAX_PROVIDER_NEEDED_SONAMES)) {
		return status::resource_exhausted("provider component dependency count exceeds its bound");
	}
	for (const auto &soname : component.needed_sonames()) {
		if (!valid_artifact_name(soname)) {
			return status::invalid_argument("provider component contains an invalid needed SONAME");
		}
	}
	order_status = require_sorted_unique(component.needed_sonames(), "component needed_sonames");
	if (!order_status.is_ok()) {
		return order_status;
	}
	return status::ok();
}

/**
 * @brief Validate complete canonical inventory structure.
 *
 * @param inventory Candidate canonical inventory.
 * @return OK only for complete two-directionally unique authority.
 */
status validate_inventory(const InstalledProviderInventory &inventory)
{
	auto status_value = common::reject_unknown_protobuf_fields_recursive(inventory, "installed provider inventory");
	if (!status_value.is_ok()) {
		return status_value;
	}
	if (!valid_product_version(inventory.product_version())) {
		return status::invalid_argument("installed provider inventory product_version is not canonical");
	}
	if (inventory.provider_abi_identity().size() != static_cast<int>(common::SHA256_DIGEST_SIZE) ||
	    inventory.runtime_sha256().size() != static_cast<int>(common::SHA256_DIGEST_SIZE) ||
	    inventory.runtime_size_bytes() == 0) {
		return status::invalid_argument(
			"installed provider inventory requires exact ABI and runtime identities");
	}
	if (inventory.components().empty()) {
		return status::invalid_argument("installed provider inventory must contain at least one component");
	}
	if (inventory.components_size() > static_cast<int>(MAX_PROVIDER_COMPONENTS)) {
		return status::resource_exhausted("provider component count exceeds its inventory bound");
	}
	if (inventory.private_artifacts_size() > static_cast<int>(MAX_PROVIDER_PRIVATE_ARTIFACTS)) {
		return status::resource_exhausted("provider private-artifact count exceeds its bound");
	}

	std::unordered_set<std::string> contract_owners;
	std::unordered_set<std::string> artifact_names;
	std::unordered_set<std::string> private_sonames;
	for (int index = 0; index < inventory.private_artifacts_size(); ++index) {
		const auto &artifact = inventory.private_artifacts(index);
		if (index != 0 && inventory.private_artifacts(index - 1).file_name() >= artifact.file_name()) {
			return status::invalid_argument(
				"private provider artifacts must be strictly sorted by file_name");
		}
		status_value = validate_private_artifact_fields(artifact);
		if (!status_value.is_ok()) {
			return status_value;
		}
		if (!artifact_names.insert(artifact.file_name()).second ||
		    !private_sonames.insert(artifact.soname()).second) {
			return status::invalid_argument(
				"installed provider inventory contains a duplicate private artifact identity");
		}
	}
	for (int index = 0; index < inventory.components_size(); ++index) {
		const auto &component = inventory.components(index);
		if (index != 0 && inventory.components(index - 1).component_id() >= component.component_id()) {
			return status::invalid_argument("provider components must be strictly sorted by component_id");
		}
		status_value = validate_component_fields(component);
		if (!status_value.is_ok()) {
			return status_value;
		}
		if (!artifact_names.insert(component.file_name()).second) {
			return status::invalid_argument(
				"installed provider inventory contains a duplicate artifact file_name");
		}
		for (const auto &type_url : component.contract_type_urls()) {
			if (!contract_owners.insert(type_url).second) {
				return status::invalid_argument(
					"installed provider inventory contains duplicate contract ownership");
			}
		}
	}
	return status::ok();
}

/**
 * @brief Bound canonicalization work before sorting any repeated field.
 *
 * @param inventory Candidate release inventory.
 * @return OK only when serialized and repeated-field work is bounded.
 */
status validate_inventory_work_bounds(const InstalledProviderInventory &inventory)
{
	if (inventory.components_size() > static_cast<int>(MAX_PROVIDER_COMPONENTS)) {
		return status::resource_exhausted("provider component count exceeds its inventory bound");
	}
	if (inventory.private_artifacts_size() > static_cast<int>(MAX_PROVIDER_PRIVATE_ARTIFACTS)) {
		return status::resource_exhausted("provider private-artifact count exceeds its bound");
	}
	const auto contract_count = provider_contract_count();
	for (const auto &component : inventory.components()) {
		if (component.contract_type_urls_size() > static_cast<int>(contract_count) ||
		    component.needed_sonames_size() > static_cast<int>(MAX_PROVIDER_NEEDED_SONAMES)) {
			return status::resource_exhausted("provider component set cardinality exceeds its bound");
		}
	}
	for (const auto &artifact : inventory.private_artifacts()) {
		if (artifact.needed_sonames_size() > static_cast<int>(MAX_PROVIDER_NEEDED_SONAMES)) {
			return status::resource_exhausted(
				"provider private-artifact dependency count exceeds its bound");
		}
	}
	if (inventory.ByteSizeLong() > MAX_PROVIDER_INVENTORY_BYTES) {
		return status::resource_exhausted("provider inventory exceeds its canonicalization byte bound");
	}
	return status::ok();
}

/**
 * @brief Normalize every declared set-like inventory field.
 *
 * @param inventory Mutable release inventory.
 * @return OK after sorting, or INVALID_ARGUMENT for duplicate set identities.
 */
status normalize_inventory(InstalledProviderInventory *inventory)
{
	for (auto &component : *inventory->mutable_components()) {
		auto sort_status =
			sort_unique_strings(component.mutable_contract_type_urls(), "component contract_type_urls");
		if (!sort_status.is_ok()) {
			return sort_status;
		}
		sort_status = sort_unique_strings(component.mutable_needed_sonames(), "component needed_sonames");
		if (!sort_status.is_ok()) {
			return sort_status;
		}
	}
	for (auto &artifact : *inventory->mutable_private_artifacts()) {
		auto sort_status = sort_unique_strings(artifact.mutable_needed_sonames(), "private needed_sonames");
		if (!sort_status.is_ok()) {
			return sort_status;
		}
	}
	std::sort(inventory->mutable_private_artifacts()->begin(), inventory->mutable_private_artifacts()->end(),
		  [](const PrivateProviderArtifact &left, const PrivateProviderArtifact &right) {
			  return left.file_name() < right.file_name();
		  });
	std::sort(inventory->mutable_components()->begin(), inventory->mutable_components()->end(),
		  [](const ProviderComponentArtifact &left, const ProviderComponentArtifact &right) {
			  return left.component_id() < right.component_id();
		  });
	return status::ok();
}

}  // namespace

std::string provider_inventory_signature_preimage(std::string_view bytes)
{
	std::string preimage;
	preimage.reserve(PROVIDER_INVENTORY_SIGNATURE_DOMAIN.size() + bytes.size());
	preimage.append(PROVIDER_INVENTORY_SIGNATURE_DOMAIN.data(), PROVIDER_INVENTORY_SIGNATURE_DOMAIN.size());
	preimage.append(bytes.data(), bytes.size());
	return preimage;
}

status_or<std::string> canonicalize_provider_inventory(kinetum::provider::v1::InstalledProviderInventory inventory)
{
	auto bounds_status = validate_inventory_work_bounds(inventory);
	if (!bounds_status.is_ok()) {
		return bounds_status;
	}
	auto normalize_status = normalize_inventory(&inventory);
	if (!normalize_status.is_ok()) {
		return normalize_status;
	}
	auto validate_status = validate_inventory(inventory);
	if (!validate_status.is_ok()) {
		return validate_status;
	}
	return common::serialize_protobuf_deterministically(inventory);
}

status validate_canonical_provider_private_artifact(const kinetum::provider::v1::PrivateProviderArtifact &artifact)
{
	auto status_value = common::reject_unknown_protobuf_fields_recursive(artifact, "private provider artifact");
	if (!status_value.is_ok()) {
		return status_value;
	}
	return validate_private_artifact_fields(artifact);
}

status validate_canonical_provider_component_artifact(const kinetum::provider::v1::ProviderComponentArtifact &component)
{
	auto status_value = common::reject_unknown_protobuf_fields_recursive(component, "provider component artifact");
	if (!status_value.is_ok()) {
		return status_value;
	}
	return validate_component_fields(component);
}

status_or<common::ed25519_signature> parse_provider_inventory_signature(std::string_view bytes)
{
	if (bytes.size() != common::ED25519_SIGNATURE_SIZE) {
		return status::invalid_argument("provider inventory signature file must contain exactly 64 bytes");
	}
	common::ed25519_signature signature{};
	std::memcpy(signature.data(), bytes.data(), signature.size());
	return signature;
}

status validate_provider_inventory_runtime_binding(const kinetum::provider::v1::InstalledProviderInventory &inventory,
						   const common::held_file &runtime)
{
	if (inventory.runtime_sha256().size() != static_cast<int>(common::SHA256_DIGEST_SIZE) ||
	    inventory.runtime_size_bytes() == 0) {
		return status::invalid_argument("provider inventory runtime identity is malformed");
	}
	if (inventory.product_version() != KINETUM_VERSION_STR) {
		return status::failed_precondition("provider inventory product version disagrees with the runtime");
	}
	if (inventory.provider_abi_identity().size() != static_cast<int>(PROVIDER_ABI_IDENTITY.size()) ||
	    std::memcmp(inventory.provider_abi_identity().data(), PROVIDER_ABI_IDENTITY.data(),
			PROVIDER_ABI_IDENTITY.size()) != 0) {
		return status::failed_precondition("provider inventory ABI identity disagrees with the runtime");
	}
	return common::verify_held_file_identity(runtime, digest_from_bytes(inventory.runtime_sha256()),
						 inventory.runtime_size_bytes());
}

status_or<authenticated_provider_inventory>
authenticate_provider_inventory(std::string_view bytes, const common::ed25519_signature &signature,
				const common::ed25519_public_key &public_key)
{
	if (bytes.size() > MAX_PROVIDER_INVENTORY_BYTES) {
		return status::resource_exhausted("provider inventory exceeds its byte bound");
	}
	const std::string preimage = provider_inventory_signature_preimage(bytes);
	auto signature_status = common::ed25519_verify(
		public_key,
		std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(preimage.data()), preimage.size()),
		signature);
	if (!signature_status.is_ok()) {
		return signature_status;
	}

	InstalledProviderInventory inventory;
	if (bytes.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
	    !inventory.ParseFromArray(bytes.data(), static_cast<int>(bytes.size()))) {
		return status::invalid_argument("authenticated provider inventory is not valid protobuf");
	}
	auto validate_status = validate_inventory(inventory);
	if (!validate_status.is_ok()) {
		return validate_status;
	}
	auto canonical_or = common::serialize_protobuf_deterministically(inventory);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	if (canonical_or.value() != bytes) {
		return status::invalid_argument("authenticated provider inventory is not in canonical byte form");
	}
	return authenticated_provider_inventory{std::move(inventory), std::string(bytes)};
}

}  // namespace kinetum::provider
