// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_component_loader.cpp
 * @brief Authenticated installed-provider loader and release-boundary tests.
 * @author Fleming Patel
 */

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "src/common/status.hpp"
#include "src/provider/provider_build_identity.hpp"
#include "src/provider/provider_component_loader.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_inventory.hpp"
#include "src/provider/provider_release_trust.hpp"
#include "tests/provider_component_test_fixture.hpp"
#include "tests/provider_test_signing_key.hpp"

#if !defined(KINETUM_TEST_PROVIDER_PRIVATE_PATH) || !defined(KINETUM_TEST_PROVIDER_COMPONENT_PATH) || \
	!defined(KINETUM_TEST_PROVIDER_COMPONENT_MULTI_PATH) ||                                       \
	!defined(KINETUM_TEST_PROVIDER_COMPONENT_SECOND_PATH) || !defined(KINETUM_TEST_PROVIDER_PRIVATE_SONAME)
#error "provider loader tests require exact CMake provider artifact paths"
#endif

#if !defined(KINETUM_PRODUCTION_AXIOM_PATH) || !defined(KINETUM_PRODUCTION_GLUON_PATH) ||              \
	!defined(KINETUM_PRODUCTION_DP_PATH) || !defined(KINETUM_PRODUCTION_CP_PATH) ||                \
	!defined(KINETUM_PRODUCTION_CTL_PATH) || !defined(KINETUM_PRODUCTION_PACK_PATH) ||             \
	!defined(KINETUM_PRODUCTION_BUNDLE_VERIFY_PATH) || !defined(KINETUM_PRODUCTION_PHOTON_PATH) || \
	!defined(KINETUM_PRODUCTION_INFO_PATH) || !defined(KINETUM_VALIDATION_TAP_SENDER_PATH) ||      \
	!defined(KINETUM_VALIDATION_TAP_ANALYZER_PATH) || !defined(KINETUM_PRODUCTION_PACKAGE_PATH) || \
	!defined(KINETUM_ACL_MODULE_PATH) || !defined(KINETUM_NAT44_MODULE_PATH) || !defined(KINETUM_QOS_MODULE_PATH)
#error "provider loader tests require the complete non-test image sweep"
#endif

namespace kinetum::provider
{
namespace
{

using kinetum::provider::v1::InstalledProviderInventory;
using kinetum::provider::v1::PrivateProviderArtifact;
using kinetum::provider::v1::ProviderComponentArtifact;

/** Exact primary conformance component identity. */
constexpr std::string_view TEST_COMPONENT_ID = "kinetum.test.provider";

/** Exact secondary conformance component identity. */
constexpr std::string_view TEST_SECOND_COMPONENT_ID = "kinetum.test.provider.second";

/** Exact multi-contract conformance component identity. */
constexpr std::string_view TEST_MULTI_COMPONENT_ID = "kinetum.test.provider.multi";

/**
 * @brief One fixed installation containing two explicit components.
 */
struct installed_provider_fixture {
	test::provider_component_test_fixture fixture;	///< Fixed installation and runtime.
	std::filesystem::path private_path;		///< Shared exact private dependency.
	std::filesystem::path primary_path;		///< Primary component artifact.
	std::filesystem::path second_path;		///< Unrequested/minimality component.
	PrivateProviderArtifact private_record;		///< Shared private identity.
	ProviderComponentArtifact primary_record;	///< Zero-copy-share implementation.
	ProviderComponentArtifact second_record;	///< CPU-execution implementation.

	/** @brief Stage exact completed artifacts and derive all inventory claims. */
	installed_provider_fixture()
	{
		const std::filesystem::path private_source = KINETUM_TEST_PROVIDER_PRIVATE_PATH;
		const std::filesystem::path primary_source = KINETUM_TEST_PROVIDER_COMPONENT_PATH;
		const std::filesystem::path second_source = KINETUM_TEST_PROVIDER_COMPONENT_SECOND_PATH;
		private_path = fixture.stage_artifact(private_source, private_source.filename().string());
		primary_path = fixture.stage_artifact(primary_source, primary_source.filename().string());
		second_path = fixture.stage_artifact(second_source, second_source.filename().string());
		private_record = fixture.private_artifact_record(private_path, KINETUM_TEST_PROVIDER_PRIVATE_SONAME);
		primary_record = fixture.component_record(primary_path, TEST_COMPONENT_ID,
							  {std::string(ZERO_COPY_SHARE_TYPE_URL)});
		second_record = fixture.component_record(second_path, TEST_SECOND_COMPONENT_ID,
							 {std::string(CPU_EXECUTION_TYPE_URL)});
	}

	/**
	 * @brief Construct a complete inventory with optional unrequested component.
	 *
	 * @param include_second Include the CPU implementation when true.
	 * @return Complete candidate inventory.
	 */
	[[nodiscard]] InstalledProviderInventory inventory(bool include_second)
	{
		std::vector<ProviderComponentArtifact> components{primary_record};
		if (include_second) {
			components.push_back(second_record);
		}
		return fixture.inventory(components, {private_record});
	}
};

/**
 * @brief One installed component implementing two exact contract rows.
 */
struct multi_contract_provider_fixture {
	test::provider_component_test_fixture fixture;	///< Fixed installation and runtime.
	std::filesystem::path private_path;		///< Shared private dependency.
	std::filesystem::path component_path;		///< Multi-contract component artifact.
	PrivateProviderArtifact private_record;		///< Exact private dependency identity.
	ProviderComponentArtifact component_record;	///< Exact two-row component identity.

	/** @brief Stage the complete two-row component closure. */
	multi_contract_provider_fixture()
	{
		const std::filesystem::path private_source = KINETUM_TEST_PROVIDER_PRIVATE_PATH;
		const std::filesystem::path component_source = KINETUM_TEST_PROVIDER_COMPONENT_MULTI_PATH;
		private_path = fixture.stage_artifact(private_source, private_source.filename().string());
		component_path = fixture.stage_artifact(component_source, component_source.filename().string());
		private_record = fixture.private_artifact_record(private_path, KINETUM_TEST_PROVIDER_PRIVATE_SONAME);
		component_record = fixture.component_record(component_path, TEST_MULTI_COMPONENT_ID,
							    {std::string(CPU_EXECUTION_TYPE_URL),
							     std::string(ZERO_COPY_SHARE_TYPE_URL)});
	}

	/** @return one complete exact inventory for the staged closure. */
	[[nodiscard]] InstalledProviderInventory inventory()
	{
		return fixture.inventory({component_record}, {private_record});
	}
};

/**
 * @brief Load one exact required set under the test trust anchor.
 *
 * @tparam installed_fixture_type Fixture exposing one fixed installation.
 * @param installed Fixed installed-provider fixture.
 * @param required Strictly sorted unique required type URLs.
 * @return Sealed catalog or exact admission failure.
 */
template <typename installed_fixture_type>
common::status_or<runtime_provider_catalog> load_catalog(installed_fixture_type &installed,
							 std::span<const std::string_view> required)
{
	return load_installed_provider_catalog(installed.fixture.root(), installed.fixture.runtime_image(), required,
					       test::PROVIDER_TEST_PUBLIC_KEY, installed.fixture.file_policy());
}

/**
 * @brief Read one completed binary exactly.
 *
 * @param path Exact build output.
 * @return Complete bytes.
 */
std::string read_binary(const std::filesystem::path &path)
{
	std::ifstream input(path, std::ios::binary);
	if (!input) {
		throw std::runtime_error("failed to open production image for test-key sweep");
	}
	return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

/**
 * @brief Return exact key bytes as a binary string.
 *
 * @tparam key_type Fixed key array type.
 * @param key Exact test key.
 * @return Binary string preserving every byte.
 */
template <typename key_type>
std::string key_bytes(const key_type &key)
{
	return std::string(reinterpret_cast<const char *>(key.data()), key.size());
}

}  // namespace

/** @brief An authenticated minimal inventory publishes exactly its requested row. */
TEST(provider_component_loader, authenticated_minimal_catalog_loads_exact_requested_row)
{
	installed_provider_fixture installed;
	(void)installed.fixture.write_signed_inventory(installed.inventory(false));
	const std::array required{ZERO_COPY_SHARE_TYPE_URL};
	auto catalog_or = load_catalog(installed, required);
	ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().to_string();
	ASSERT_EQ(catalog_or->size(), 1u);
	ASSERT_EQ(catalog_or->component_count(), 1u);
	const auto *implementation = catalog_or->find(ZERO_COPY_SHARE_TYPE_URL);
	ASSERT_NE(implementation, nullptr);
	EXPECT_EQ(implementation->component_id, TEST_COMPONENT_ID);
	EXPECT_NE(implementation->implementation, nullptr);
	EXPECT_EQ(catalog_or->at(0), implementation);
	EXPECT_EQ(catalog_or->at(1), nullptr);
}

/** @brief An installed component outside the required set remains unreachable. */
TEST(provider_component_loader, installed_unrequested_component_is_not_reachable)
{
	installed_provider_fixture installed;
	(void)installed.fixture.write_signed_inventory(installed.inventory(true));
	const std::array required{ZERO_COPY_SHARE_TYPE_URL};
	auto catalog_or = load_catalog(installed, required);
	ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().to_string();
	EXPECT_EQ(catalog_or->component_count(), 1u);
	EXPECT_EQ(catalog_or->size(), 1u);
	EXPECT_EQ(catalog_or->find(CPU_EXECUTION_TYPE_URL), nullptr);
}

/** @brief A multi-contract image publishes only the rows requested by the plan. */
TEST(provider_component_loader, multi_contract_component_publishes_only_requested_rows)
{
	multi_contract_provider_fixture installed;
	(void)installed.fixture.write_signed_inventory(installed.inventory());

	const std::array one_required{CPU_EXECUTION_TYPE_URL};
	{
		auto catalog_or = load_catalog(installed, one_required);
		ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().to_string();
		EXPECT_EQ(catalog_or->component_count(), 1u);
		ASSERT_EQ(catalog_or->size(), 1u);
		const auto *execution = catalog_or->find(CPU_EXECUTION_TYPE_URL);
		ASSERT_NE(execution, nullptr);
		EXPECT_EQ(execution->component_id, TEST_MULTI_COMPONENT_ID);
		EXPECT_EQ(catalog_or->at(0), execution);
		EXPECT_EQ(catalog_or->find(ZERO_COPY_SHARE_TYPE_URL), nullptr);
	}

	const std::array both_required{CPU_EXECUTION_TYPE_URL, ZERO_COPY_SHARE_TYPE_URL};
	auto catalog_or = load_catalog(installed, both_required);
	ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().to_string();
	EXPECT_EQ(catalog_or->component_count(), 1u);
	ASSERT_EQ(catalog_or->size(), 2u);
	const auto *execution = catalog_or->find(CPU_EXECUTION_TYPE_URL);
	const auto *transition = catalog_or->find(ZERO_COPY_SHARE_TYPE_URL);
	ASSERT_NE(execution, nullptr);
	ASSERT_NE(transition, nullptr);
	EXPECT_EQ(execution->component_id, TEST_MULTI_COMPONENT_ID);
	EXPECT_EQ(transition->component_id, TEST_MULTI_COMPONENT_ID);
	EXPECT_EQ(catalog_or->at(0), execution);
	EXPECT_EQ(catalog_or->at(1), transition);
}

/** @brief A required contract without an installed owner fails closed. */
TEST(provider_component_loader, required_contract_without_installed_owner_fails_closed)
{
	installed_provider_fixture installed;
	(void)installed.fixture.write_signed_inventory(installed.inventory(false));
	const std::array required{CPU_EXECUTION_TYPE_URL};
	const auto result = load_catalog(installed, required);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::NOT_FOUND);
}

/** @brief Required contracts must form one known sorted unique nonempty set. */
TEST(provider_component_loader, compiled_required_set_must_be_known_sorted_unique_and_nonempty)
{
	installed_provider_fixture installed;
	const std::array<std::string_view, 0> empty{};
	const auto empty_result = load_catalog(installed, empty);
	ASSERT_FALSE(empty_result.is_ok());
	EXPECT_EQ(empty_result.error().code(), common::status_code::INVALID_ARGUMENT);

	const std::array unsorted{ZERO_COPY_SHARE_TYPE_URL, CPU_EXECUTION_TYPE_URL};
	const auto unsorted_result = load_catalog(installed, unsorted);
	ASSERT_FALSE(unsorted_result.is_ok());
	EXPECT_NE(unsorted_result.error().message().find("sorted"), std::string::npos);

	const std::array duplicate{CPU_EXECUTION_TYPE_URL, CPU_EXECUTION_TYPE_URL};
	const auto duplicate_result = load_catalog(installed, duplicate);
	ASSERT_FALSE(duplicate_result.is_ok());
	EXPECT_NE(duplicate_result.error().message().find("sorted"), std::string::npos);

	const std::array<std::string_view, 1> unknown{"type.googleapis.com/kinetum.test.unknown.v1.Config"};
	const auto unknown_result = load_catalog(installed, unknown);
	ASSERT_FALSE(unknown_result.is_ok());
	EXPECT_NE(unknown_result.error().message().find("pure catalog"), std::string::npos);
}

/** @brief Inventory authentication fails before any component admission. */
TEST(provider_component_loader, inventory_signature_failure_precedes_component_admission)
{
	installed_provider_fixture installed;
	(void)installed.fixture.write_signed_inventory(installed.inventory(false));
	auto different_seed = test::PROVIDER_TEST_PRIVATE_KEY;
	different_seed.front() ^= UINT8_C(1);
	auto wrong_key_or = common::ed25519_derive_public_key(different_seed);
	ASSERT_TRUE(wrong_key_or.is_ok()) << wrong_key_or.error().to_string();
	const std::array required{ZERO_COPY_SHARE_TYPE_URL};
	const auto result = load_installed_provider_catalog(installed.fixture.root(), installed.fixture.runtime_image(),
							    required, wrong_key_or.value(),
							    installed.fixture.file_policy());
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::UNAUTHENTICATED);
}

/** @brief Runtime image hash and size bind the exact admitted process image. */
TEST(provider_component_loader, inventory_runtime_hash_and_size_bind_the_exact_process_image)
{
	installed_provider_fixture installed;
	const std::array required{ZERO_COPY_SHARE_TYPE_URL};

	auto wrong_hash = installed.inventory(false);
	char &hash_byte = wrong_hash.mutable_runtime_sha256()->front();
	hash_byte = static_cast<char>(static_cast<uint8_t>(hash_byte) ^ UINT8_C(1));
	(void)installed.fixture.write_signed_inventory(std::move(wrong_hash));
	const auto hash_result = load_catalog(installed, required);
	ASSERT_FALSE(hash_result.is_ok());
	EXPECT_NE(hash_result.error().message().find("SHA-256"), std::string::npos);

	auto wrong_size = installed.inventory(false);
	wrong_size.set_runtime_size_bytes(wrong_size.runtime_size_bytes() + 1u);
	(void)installed.fixture.write_signed_inventory(std::move(wrong_size));
	const auto size_result = load_catalog(installed, required);
	ASSERT_FALSE(size_result.is_ok());
	EXPECT_NE(size_result.error().message().find("size"), std::string::npos);
}

/** @brief Product and provider ABI identities bind the exact admitted build. */
TEST(provider_component_loader, inventory_product_and_abi_bind_the_exact_build)
{
	installed_provider_fixture installed;
	const std::array required{ZERO_COPY_SHARE_TYPE_URL};

	auto wrong_product = installed.inventory(false);
	wrong_product.set_product_version("0.1.1");
	(void)installed.fixture.write_signed_inventory(std::move(wrong_product));
	const auto product_result = load_catalog(installed, required);
	ASSERT_FALSE(product_result.is_ok());
	EXPECT_NE(product_result.error().message().find("product version"), std::string::npos);

	auto wrong_abi = installed.inventory(false);
	char &abi_byte = wrong_abi.mutable_provider_abi_identity()->front();
	abi_byte = static_cast<char>(static_cast<uint8_t>(abi_byte) ^ UINT8_C(1));
	(void)installed.fixture.write_signed_inventory(std::move(wrong_abi));
	const auto abi_result = load_catalog(installed, required);
	ASSERT_FALSE(abi_result.is_ok());
	EXPECT_NE(abi_result.error().message().find("ABI identity"), std::string::npos);
}

/** @brief Production and validation images contain no test signing-key bytes. */
TEST(provider_component_loader, non_test_images_contain_no_test_signing_key_bytes)
{
	const std::array<std::filesystem::path, 18> non_test_images{
		KINETUM_PRODUCTION_AXIOM_PATH,
		KINETUM_PRODUCTION_GLUON_PATH,
		KINETUM_PRODUCTION_DP_PATH,
		KINETUM_PRODUCTION_CP_PATH,
		KINETUM_PRODUCTION_CTL_PATH,
		KINETUM_PRODUCTION_PACK_PATH,
		KINETUM_PRODUCTION_BUNDLE_VERIFY_PATH,
		KINETUM_PRODUCTION_PHOTON_PATH,
		KINETUM_PRODUCTION_INFO_PATH,
		KINETUM_VALIDATION_TAP_SENDER_PATH,
		KINETUM_VALIDATION_TAP_ANALYZER_PATH,
		KINETUM_ACL_MODULE_PATH,
		KINETUM_NAT44_MODULE_PATH,
		KINETUM_QOS_MODULE_PATH,
		KINETUM_PROVIDER_HOST_COMPONENT_PATH,
		KINETUM_PROVIDER_UDP_COMPONENT_PATH,
		KINETUM_PROVIDER_DPDK_COMPONENT_PATH,
		KINETUM_PRODUCTION_PACKAGE_PATH,
	};
	const std::string private_key = key_bytes(test::PROVIDER_TEST_PRIVATE_KEY);
	const std::string public_key = key_bytes(test::PROVIDER_TEST_PUBLIC_KEY);
	for (const auto &path : non_test_images) {
		const std::string bytes = read_binary(path);
		EXPECT_EQ(bytes.find(private_key), std::string::npos) << path;
		EXPECT_EQ(bytes.find(public_key), std::string::npos) << path;
	}
}

/** @brief Every production verifier consumes the one exact source-controlled anchor. */
TEST(provider_component_loader, production_verifiers_embed_the_exact_release_anchor)
{
	const std::array<std::filesystem::path, 3> anchor_images{
		KINETUM_PRODUCTION_DP_PATH,
		KINETUM_PRODUCTION_PACKAGE_PATH,
		KINETUM_PRODUCTION_INFO_PATH,
	};
	const std::string anchor = key_bytes(provider_release_trust_anchor());
	for (const auto &path : anchor_images) {
		const std::string bytes = read_binary(path);
		EXPECT_NE(bytes.find(anchor), std::string::npos) << path;
	}
}

}  // namespace kinetum::provider
