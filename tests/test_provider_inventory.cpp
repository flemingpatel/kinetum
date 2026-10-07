// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_inventory.cpp
 * @brief Canonical signed installed-provider inventory tests.
 * @author Fleming Patel
 */

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/unknown_field_set.h>
#include <gtest/gtest.h>

#include "src/common/status.hpp"
#include "src/provider/provider_build_identity.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_inventory.hpp"
#include "tests/provider_test_signing_key.hpp"

namespace kinetum::provider
{
namespace
{

using kinetum::provider::v1::InstalledProviderInventory;
using kinetum::provider::v1::PrivateProviderArtifact;
using kinetum::provider::v1::ProviderComponentArtifact;

/**
 * @brief Return one deterministic nonzero fake digest.
 * @param seed Initial byte of the deterministic increasing fixture pattern.
 * @return Fixed-width fake digest bytes.
 */
std::string digest_bytes(uint8_t seed)
{
	std::string bytes(common::SHA256_DIGEST_SIZE, '\0');
	for (std::size_t index = 0; index < bytes.size(); ++index) {
		bytes[index] = static_cast<char>(static_cast<uint8_t>(seed + static_cast<uint8_t>(index)));
	}
	return bytes;
}

/**
 * @brief Construct one valid exact component record.
 * @param id Component identity transferred into the record.
 * @param file_name Component artifact basename transferred into the record.
 * @param type_url Implemented contract identity transferred into the record.
 * @param digest_seed Seed selecting the deterministic artifact digest.
 * @return Complete unsigned component fixture record.
 */
ProviderComponentArtifact component(std::string id, std::string file_name, std::string type_url, uint8_t digest_seed)
{
	ProviderComponentArtifact value;
	value.set_component_id(std::move(id));
	value.set_file_name(std::move(file_name));
	value.set_sha256(digest_bytes(digest_seed));
	value.set_size_bytes(4096);
	value.add_contract_type_urls(std::move(type_url));
	value.add_needed_sonames("libc.so.6");
	return value;
}

/**
 * @brief Construct one valid exact private-artifact record.
 * @return Fixed private-artifact identity, digest, size, and runtime dependency record.
 */
PrivateProviderArtifact private_artifact()
{
	PrivateProviderArtifact value;
	value.set_file_name("libkinetum_private.so");
	value.set_soname("libkinetum_private.so");
	value.set_sha256(digest_bytes(91));
	value.set_size_bytes(2048);
	value.add_needed_sonames("libc.so.6");
	return value;
}

/**
 * @brief Construct one minimal valid inventory.
 * @return Current-version inventory containing the exact ABI identity and one valid component.
 */
InstalledProviderInventory valid_inventory()
{
	InstalledProviderInventory inventory;
	inventory.set_product_version(KINETUM_VERSION_STR);
	inventory.set_provider_abi_identity(reinterpret_cast<const char *>(PROVIDER_ABI_IDENTITY.data()),
					    PROVIDER_ABI_IDENTITY.size());
	inventory.set_runtime_sha256(digest_bytes(7));
	inventory.set_runtime_size_bytes(8192);
	inventory.add_components()->CopyFrom(
		component("kinetum.test.provider", "libprovider.so", ZERO_COPY_SHARE_TYPE_URL.data(), 23));
	return inventory;
}

/**
 * @brief Sign exact arbitrary bytes under the inventory domain.
 * @param bytes Borrowed payload appended to the fixed inventory signing domain.
 * @return Signature under the test key; signing failure terminates the fixture.
 */
common::ed25519_signature sign_exact_bytes(std::string_view bytes)
{
	std::string preimage(PROVIDER_INVENTORY_SIGNATURE_DOMAIN);
	preimage.append(bytes.data(), bytes.size());
	auto signature_or = common::ed25519_sign(
		test::PROVIDER_TEST_PRIVATE_KEY,
		std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(preimage.data()), preimage.size()));
	if (!signature_or.is_ok()) {
		std::terminate();
	}
	return std::move(signature_or).value();
}

/**
 * @brief Walk one protobuf descriptor graph without revisiting a message.
 *
 * @param descriptor Current message descriptor.
 * @param visited Descriptor identities already inspected.
 * @return true when any reachable field is a protobuf map.
 */
bool descriptor_graph_has_map(const google::protobuf::Descriptor *descriptor,
			      std::unordered_set<const google::protobuf::Descriptor *> &visited)
{
	if (!visited.insert(descriptor).second) {
		return false;
	}
	for (int index = 0; index < descriptor->field_count(); ++index) {
		const auto *field = descriptor->field(index);
		if (field->is_map()) {
			return true;
		}
		if (field->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE &&
		    field->message_type()->file() == descriptor->file() &&
		    descriptor_graph_has_map(field->message_type(), visited)) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Return whether a protobuf message graph contains a map field.
 * @param descriptor Root generated descriptor to traverse.
 * @return true if any reachable descriptor contains a protobuf map field.
 */
bool descriptor_graph_has_map(const google::protobuf::Descriptor *descriptor)
{
	std::unordered_set<const google::protobuf::Descriptor *> visited;
	return descriptor_graph_has_map(descriptor, visited);
}

}  // namespace

/** @brief Prove the signing domain has exact bytes and two NUL separators. */
TEST(provider_inventory, signature_domain_is_byte_exact_and_nul_separated)
{
	static constexpr char EXPECTED_DOMAIN[] = "KINETUM-PROVIDER-INVENTORY\0v1\0";
	const std::string expected(EXPECTED_DOMAIN, sizeof(EXPECTED_DOMAIN) - 1u);
	ASSERT_EQ(expected.size(), 30u);
	EXPECT_EQ(PROVIDER_INVENTORY_SIGNATURE_DOMAIN, expected);
	EXPECT_EQ(PROVIDER_INVENTORY_SIGNATURE_DOMAIN.back(), '\0');
	EXPECT_EQ(std::count(PROVIDER_INVENTORY_SIGNATURE_DOMAIN.begin(), PROVIDER_INVENTORY_SIGNATURE_DOMAIN.end(),
			     '\0'),
		  2);
}

/** @brief Prove canonicalization sorts only fields whose contract is set-like. */
TEST(provider_inventory, canonicalization_sorts_only_declared_set_fields)
{
	auto inventory = valid_inventory();
	inventory.clear_components();
	auto later = component("kinetum.test.z", "libz.so", ZERO_COPY_SHARE_TYPE_URL.data(), 31);
	later.clear_needed_sonames();
	later.add_needed_sonames("libm.so.6");
	later.add_needed_sonames("libc.so.6");
	auto earlier = component("kinetum.test.a", "liba.so", CPU_EXECUTION_TYPE_URL.data(), 32);
	inventory.add_components()->CopyFrom(later);
	inventory.add_components()->CopyFrom(earlier);
	auto private_value = private_artifact();
	private_value.clear_needed_sonames();
	private_value.add_needed_sonames("libm.so.6");
	private_value.add_needed_sonames("libc.so.6");
	inventory.add_private_artifacts()->CopyFrom(private_value);

	auto bytes_or = canonicalize_provider_inventory(std::move(inventory));
	ASSERT_TRUE(bytes_or.is_ok()) << bytes_or.error().to_string();
	InstalledProviderInventory parsed;
	ASSERT_TRUE(parsed.ParseFromString(bytes_or.value()));
	ASSERT_EQ(parsed.components_size(), 2);
	EXPECT_EQ(parsed.components(0).component_id(), "kinetum.test.a");
	EXPECT_EQ(parsed.components(1).component_id(), "kinetum.test.z");
	EXPECT_EQ(parsed.components(1).needed_sonames(0), "libc.so.6");
	EXPECT_EQ(parsed.components(1).needed_sonames(1), "libm.so.6");
	EXPECT_EQ(parsed.private_artifacts(0).needed_sonames(0), "libc.so.6");
}

/** @brief Prove canonical inventory bytes are a serialization fixed point. */
TEST(provider_inventory, canonicalization_is_a_byte_fixed_point)
{
	auto first_or = canonicalize_provider_inventory(valid_inventory());
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().to_string();
	InstalledProviderInventory parsed;
	ASSERT_TRUE(parsed.ParseFromString(first_or.value()));
	auto second_or = canonicalize_provider_inventory(std::move(parsed));
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().to_string();
	EXPECT_EQ(first_or.value(), second_or.value());
}

/** @brief Prove signing and authentication retain identical canonical bytes. */
TEST(provider_inventory, signed_inventory_authenticates_to_the_same_canonical_bytes)
{
	auto signed_or = sign_provider_inventory(valid_inventory(), test::PROVIDER_TEST_PRIVATE_KEY);
	ASSERT_TRUE(signed_or.is_ok()) << signed_or.error().to_string();
	auto authenticated_or = authenticate_provider_inventory(signed_or->canonical_bytes, signed_or->signature,
								test::PROVIDER_TEST_PUBLIC_KEY);
	ASSERT_TRUE(authenticated_or.is_ok()) << authenticated_or.error().to_string();
	EXPECT_EQ(authenticated_or->canonical_bytes, signed_or->canonical_bytes);
	EXPECT_EQ(authenticated_or->inventory.product_version(), KINETUM_VERSION_STR);
}

/** @brief Prove signature rejection precedes malformed protobuf parsing. */
TEST(provider_inventory, signature_failure_precedes_malformed_protobuf_parsing)
{
	const std::string malformed(1, static_cast<char>(0xff));
	common::ed25519_signature signature{};
	const auto result = authenticate_provider_inventory(malformed, signature, test::PROVIDER_TEST_PUBLIC_KEY);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::UNAUTHENTICATED);
}

/** @brief Prove a valid signature cannot admit malformed protobuf bytes. */
TEST(provider_inventory, valid_signature_does_not_make_malformed_protobuf_admissible)
{
	const std::string malformed(1, static_cast<char>(0xff));
	const auto result =
		authenticate_provider_inventory(malformed, sign_exact_bytes(malformed), test::PROVIDER_TEST_PUBLIC_KEY);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::INVALID_ARGUMENT);
}

/** @brief Prove authenticated unknown wire fields still fail closed. */
TEST(provider_inventory, authenticated_unknown_wire_fields_fail_closed)
{
	auto canonical_or = canonicalize_provider_inventory(valid_inventory());
	ASSERT_TRUE(canonical_or.is_ok()) << canonical_or.error().to_string();
	std::string bytes = canonical_or.value();
	bytes.append("\xf8\x07\x01", 3);
	const auto result =
		authenticate_provider_inventory(bytes, sign_exact_bytes(bytes), test::PROVIDER_TEST_PUBLIC_KEY);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("unknown"), std::string::npos);

	auto nested = valid_inventory();
	auto *nested_component = nested.mutable_components(0);
	auto *unknown_fields = nested_component->GetReflection()->MutableUnknownFields(nested_component);
	unknown_fields->AddVarint(127, 1);
	const auto nested_result = validate_canonical_provider_component_artifact(nested.components(0));
	ASSERT_FALSE(nested_result.is_ok());
	EXPECT_EQ(nested_result.code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(nested_result.message().find("unknown"), std::string::npos);
}

/** @brief Prove authenticated noncanonical field order fails byte equality. */
TEST(provider_inventory, authenticated_noncanonical_wire_order_fails_byte_equality)
{
	auto canonical_or = canonicalize_provider_inventory(valid_inventory());
	ASSERT_TRUE(canonical_or.is_ok()) << canonical_or.error().to_string();
	const std::string version = KINETUM_VERSION_STR;
	ASSERT_LT(version.size(), 128u);
	std::string bytes;
	bytes.push_back('\x0a');
	bytes.push_back(static_cast<char>(version.size()));
	bytes.append(version);
	bytes.append(canonical_or.value());
	const auto result =
		authenticate_provider_inventory(bytes, sign_exact_bytes(bytes), test::PROVIDER_TEST_PUBLIC_KEY);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("canonical byte form"), std::string::npos);
}

/** @brief Prove component identities are unique within one inventory. */
TEST(provider_inventory, duplicate_component_identity_is_rejected)
{
	auto inventory = valid_inventory();
	auto duplicate = component("kinetum.test.provider", "libsecond.so", CPU_EXECUTION_TYPE_URL.data(), 41);
	inventory.add_components()->CopyFrom(duplicate);
	const auto result = canonicalize_provider_inventory(std::move(inventory));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("component_id"), std::string::npos);
}

/** @brief Prove each provider contract has one component owner. */
TEST(provider_inventory, duplicate_contract_ownership_is_rejected)
{
	auto inventory = valid_inventory();
	auto duplicate = component("kinetum.test.second", "libsecond.so", ZERO_COPY_SHARE_TYPE_URL.data(), 42);
	inventory.add_components()->CopyFrom(duplicate);
	const auto result = canonicalize_provider_inventory(std::move(inventory));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("contract ownership"), std::string::npos);
}

/** @brief Prove component and private-artifact file names are globally unique. */
TEST(provider_inventory, component_and_private_artifact_file_names_are_globally_unique)
{
	auto inventory = valid_inventory();
	auto artifact = private_artifact();
	artifact.set_file_name("libprovider.so");
	inventory.add_private_artifacts()->CopyFrom(artifact);
	const auto result = canonicalize_provider_inventory(std::move(inventory));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("artifact file_name"), std::string::npos);
}

/** @brief Prove exact identity widths and nonzero artifact sizes are mandatory. */
TEST(provider_inventory, exact_identity_widths_and_nonzero_sizes_are_required)
{
	auto inventory = valid_inventory();
	inventory.mutable_components(0)->set_sha256("short");
	const auto component_result = canonicalize_provider_inventory(inventory);
	ASSERT_FALSE(component_result.is_ok());
	EXPECT_NE(component_result.error().message().find("SHA-256"), std::string::npos);

	inventory = valid_inventory();
	inventory.set_runtime_size_bytes(0);
	const auto runtime_result = canonicalize_provider_inventory(std::move(inventory));
	ASSERT_FALSE(runtime_result.is_ok());
	EXPECT_NE(runtime_result.error().message().find("runtime identities"), std::string::npos);
}

/** @brief Prove dependency lists reject duplicate set members. */
TEST(provider_inventory, duplicate_dependency_set_members_are_rejected)
{
	auto inventory = valid_inventory();
	inventory.mutable_components(0)->add_needed_sonames("libc.so.6");
	const auto component_result = canonicalize_provider_inventory(inventory);
	ASSERT_FALSE(component_result.is_ok());
	EXPECT_NE(component_result.error().message().find("duplicate"), std::string::npos);

	inventory = valid_inventory();
	auto artifact = private_artifact();
	artifact.add_needed_sonames("libc.so.6");
	inventory.add_private_artifacts()->CopyFrom(artifact);
	const auto private_result = canonicalize_provider_inventory(std::move(inventory));
	ASSERT_FALSE(private_result.is_ok());
	EXPECT_NE(private_result.error().message().find("duplicate"), std::string::npos);
}

/** @brief Prove inventory schema and cardinality bounds remain compact and map-free. */
TEST(provider_inventory, schema_and_cardinality_bounds_are_compact_and_map_free)
{
	const auto *descriptor = InstalledProviderInventory::descriptor();
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->field_count(), 6);
	EXPECT_EQ(descriptor->FindFieldByName("product_version")->number(), 1);
	EXPECT_EQ(descriptor->FindFieldByName("provider_abi_identity")->number(), 2);
	EXPECT_EQ(descriptor->FindFieldByName("runtime_sha256")->number(), 3);
	EXPECT_EQ(descriptor->FindFieldByName("runtime_size_bytes")->number(), 4);
	EXPECT_EQ(descriptor->FindFieldByName("private_artifacts")->number(), 5);
	EXPECT_EQ(descriptor->FindFieldByName("components")->number(), 6);
	EXPECT_FALSE(descriptor_graph_has_map(descriptor));

	auto inventory = valid_inventory();
	inventory.clear_components();
	for (std::size_t index = 0; index <= MAX_PROVIDER_COMPONENTS; ++index) {
		auto value = component("kinetum.test." + std::to_string(index),
				       "libprovider_" + std::to_string(index) + ".so", ZERO_COPY_SHARE_TYPE_URL.data(),
				       static_cast<uint8_t>(index));
		inventory.add_components()->CopyFrom(value);
	}
	const auto result = canonicalize_provider_inventory(std::move(inventory));
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::RESOURCE_EXHAUSTED);

	inventory = valid_inventory();
	inventory.set_product_version(std::string(MAX_PROVIDER_INVENTORY_BYTES + 1u, '1'));
	const auto byte_bound_result = canonicalize_provider_inventory(std::move(inventory));
	ASSERT_FALSE(byte_bound_result.is_ok());
	EXPECT_EQ(byte_bound_result.error().code(), common::status_code::RESOURCE_EXHAUSTED);

	auto overbound_component = valid_inventory().components(0);
	for (std::size_t index = static_cast<std::size_t>(overbound_component.contract_type_urls_size());
	     index <= provider_contract_count(); ++index) {
		overbound_component.add_contract_type_urls("type.googleapis.com/kinetum.test." + std::to_string(index));
	}
	const auto contract_bound_result = validate_canonical_provider_component_artifact(overbound_component);
	ASSERT_FALSE(contract_bound_result.is_ok());
	EXPECT_EQ(contract_bound_result.code(), common::status_code::RESOURCE_EXHAUSTED);
}

}  // namespace kinetum::provider
