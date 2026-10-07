// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_release.cpp
 * @brief Production provider-release preparation and finalization tests.
 * @author Fleming Patel
 *
 * These tests stage the exact production host/DPDK aggregate around the real
 * dataplane image. Native preparation exercises shared dynamic component
 * admission; finalization independently repeats static reconstruction before
 * accepting additive native evidence and publishing a detached signature.
 */

#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gen/kinetum/release/v1/provider_release.pb.h"
#include "tooling/release/packaging/package_release.hpp"
#include "tooling/release/packaging/provider_release_signing_key.hpp"
#include "src/common/file_io.hpp"
#include "src/provider/provider_component_preflight.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_installation.hpp"
#include "src/provider/provider_release.hpp"
#include "src/provider/provider_runtime_admission.hpp"
#include "src/provider/provider_target_tuple.hpp"
#include "tests/provider_component_test_fixture.hpp"
#include "tests/provider_test_signing_key.hpp"

#ifndef KINETUM_PRODUCTION_DP_PATH
#error "KINETUM_PRODUCTION_DP_PATH must identify the production dataplane image"
#endif

#ifndef KINETUM_PROVIDER_HOST_COMPONENT_PATH
#error "KINETUM_PROVIDER_HOST_COMPONENT_PATH must identify the production host component"
#endif

#ifndef KINETUM_PROVIDER_DPDK_COMPONENT_PATH
#error "KINETUM_PROVIDER_DPDK_COMPONENT_PATH must identify the production DPDK component"
#endif

#if !defined(KINETUM_TEST_PROVIDER_PRIVATE_PATH) || !defined(KINETUM_TEST_PROVIDER_PRIVATE_SONAME) || \
	!defined(KINETUM_TEST_PROVIDER_HOST_PROOF_FAILURE_PATH)
#error "provider runtime-admission tests require the exact failing component closure"
#endif

namespace kinetum::provider
{
namespace
{

/** Exact installed regular-file mode used by release candidates. */
constexpr mode_t RELEASE_DATA_MODE = 0644;

/** Exact installed executable mode used by the runtime image. */
constexpr mode_t RELEASE_EXECUTABLE_MODE = 0755;

/** Exact installed directory mode restored after a competing policy owner. */
constexpr mode_t RELEASE_DIRECTORY_MODE = 0755;

/** Group-writable directory mode forbidden by the production policy. */
constexpr mode_t GROUP_WRITABLE_DIRECTORY_MODE = 0775;

/** Exact private seed mode required by the signing-key authority. */
constexpr mode_t RELEASE_SEED_MODE = 0400;

/** Non-root owner used only when the test process itself runs as root. */
constexpr uid_t NON_ROOT_TEST_OWNER_UID = 1;

/** Exact identity of the deterministic host-proof failure component. */
constexpr std::string_view HOST_PROOF_FAILURE_COMPONENT_ID = "kinetum.test.provider.host_proof_failure";

/** @brief Close one test-owned descriptor exactly once. */
class descriptor_owner {
    public:
	/** @param descriptor Descriptor to adopt, or a negative failed-open value. */
	explicit descriptor_owner(int descriptor) noexcept
		: descriptor_(descriptor)
	{
	}

	/** @brief Close the descriptor when valid. */
	~descriptor_owner()
	{
		if (descriptor_ >= 0) {
			(void)::close(descriptor_);
		}
	}

	/** @brief Prevent two owners from closing the same descriptor. */
	descriptor_owner(const descriptor_owner &) = delete;
	/** @brief Prevent copy assignment of descriptor ownership. */
	descriptor_owner &operator=(const descriptor_owner &) = delete;
	/** @brief Keep the descriptor owner at one stable test scope. */
	descriptor_owner(descriptor_owner &&) = delete;
	/** @brief Prevent move assignment of descriptor ownership. */
	descriptor_owner &operator=(descriptor_owner &&) = delete;

	/** @return the borrowed descriptor. */
	[[nodiscard]] int get() const noexcept
	{
		return descriptor_;
	}

    private:
	int descriptor_{-1};  ///< Sole descriptor ownership.
};

/**
 * @brief Exact staged production-release fixture.
 *
 * Every path is explicit. No directory scan or build-output inference
 * participates in candidate construction.
 */
class ProviderReleaseTest : public ::testing::Test {
    protected:
	/** @brief Stage the exact production aggregate beneath one private root. */
	void SetUp() override
	{
		static std::atomic<uint64_t> sequence{0};
		const uint64_t identity = sequence.fetch_add(1, std::memory_order_relaxed);
		root_ = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
			("kinetum_provider_release_" + std::to_string(static_cast<uint64_t>(::getpid())) + "_" +
			 std::to_string(identity));
		artifact_directory_ = root_ / std::filesystem::path(std::string(PROVIDER_ARTIFACT_DIRECTORY));
		inventory_directory_ = root_ / "share/kinetum/providers";
		release_directory_ = root_ / "share/kinetum/release";
		create_directory(runtime_path().parent_path());
		create_directory(artifact_directory_);
		create_directory(inventory_directory_);
		create_directory(release_directory_);
		copy_exact_file(KINETUM_PRODUCTION_DP_PATH, runtime_path(), RELEASE_EXECUTABLE_MODE);
		copy_exact_file(KINETUM_PROVIDER_DPDK_COMPONENT_PATH, dpdk_component_path(), RELEASE_DATA_MODE);
		copy_exact_file(KINETUM_PROVIDER_HOST_COMPONENT_PATH, host_component_path(), RELEASE_DATA_MODE);
	}

	/** @brief Remove the complete private staged root. */
	void TearDown() override
	{
		std::error_code ignored;
		std::filesystem::remove_all(root_, ignored);
	}

	/** @return the exact current-user release-candidate policy. */
	[[nodiscard]] common::held_file_policy candidate_policy() const
	{
		return release_candidate_file_policy(root_, owner_uid());
	}

	/** @return this test process's representable effective UID. */
	[[nodiscard]] static uint32_t owner_uid()
	{
		return static_cast<uint32_t>(::geteuid());
	}

	/** @return the fixed installed runtime path. */
	[[nodiscard]] std::filesystem::path runtime_path() const
	{
		return root_ / std::filesystem::path(std::string(PROVIDER_RUNTIME_RELATIVE_PATH));
	}

	/** @return the fixed installed DPDK-component path. */
	[[nodiscard]] std::filesystem::path dpdk_component_path() const
	{
		return artifact_directory_ / std::string(PRODUCTION_DPDK_COMPONENT_FILE_NAME);
	}

	/** @return the fixed installed host-component path. */
	[[nodiscard]] std::filesystem::path host_component_path() const
	{
		return artifact_directory_ / std::string(PRODUCTION_HOST_COMPONENT_FILE_NAME);
	}

	/** @return the fixed unsigned inventory path. */
	[[nodiscard]] std::filesystem::path inventory_path() const
	{
		return root_ / std::filesystem::path(std::string(PROVIDER_INVENTORY_RELATIVE_PATH));
	}

	/** @return the fixed detached-signature path. */
	[[nodiscard]] std::filesystem::path signature_path() const
	{
		return root_ / std::filesystem::path(std::string(PROVIDER_INVENTORY_SIGNATURE_RELATIVE_PATH));
	}

	/** @return the fixed additive receipt path. */
	[[nodiscard]] std::filesystem::path receipt_path() const
	{
		return root_ / std::filesystem::path(std::string(PROVIDER_ADMISSION_RECEIPT_RELATIVE_PATH));
	}

	/** @return the private test seed path. */
	[[nodiscard]] std::filesystem::path seed_path() const
	{
		return root_ / "release_signing_seed";
	}

	/** @return Result of target-native preparation of this exact staged candidate. */
	[[nodiscard]] common::status prepare() const
	{
		return release::prepare_provider_release_candidate(root_, native_provider_target_tuple(), owner_uid());
	}

	/** @brief Publish the RFC test seed with exact release-key metadata. */
	void write_test_seed() const
	{
		write_exact_file(
			seed_path(),
			std::string_view(reinterpret_cast<const char *>(test::PROVIDER_TEST_PRIVATE_KEY.data()),
					 test::PROVIDER_TEST_PRIVATE_KEY.size()),
			RELEASE_SEED_MODE);
	}

	/** @return Admitted RFC test seed, or the production admission failure. */
	[[nodiscard]] common::status_or<release::provider_release_signing_key> admit_test_seed() const
	{
		const descriptor_owner descriptor(::open(seed_path().c_str(), O_RDONLY | O_CLOEXEC));
		if (descriptor.get() < 0) {
			return common::status::internal_error("failed to open test release seed");
		}
		return release::admit_provider_release_signing_key(descriptor.get(), owner_uid(),
								   test::PROVIDER_TEST_PUBLIC_KEY);
	}

	/**
	 * @brief Create one exact candidate directory chain or throw.
	 *
	 * Every directory at or below the candidate root receives the release
	 * directory mode explicitly, independent of the process umask.
	 *
	 * @param path Exact descendant directory to create.
	 */
	void create_directory(const std::filesystem::path &path) const
	{
		std::error_code error;
		std::filesystem::create_directories(path, error);
		if (error) {
			throw std::runtime_error("failed to create provider release fixture directory: " +
						 error.message());
		}

		const std::filesystem::path relative = path.lexically_relative(root_);
		if (relative.empty() || relative.is_absolute()) {
			throw std::runtime_error("provider release fixture directory is outside its exact root");
		}

		std::filesystem::path current = root_;
		set_mode(current, RELEASE_DIRECTORY_MODE);
		for (const auto &component : relative) {
			if (component.empty() || component == "." || component == ".." || component.has_parent_path()) {
				throw std::runtime_error(
					"provider release fixture directory has a noncanonical component");
			}
			current /= component;
			set_mode(current, RELEASE_DIRECTORY_MODE);
		}
		if (current != path) {
			throw std::runtime_error("provider release fixture directory disagrees with its exact root");
		}
	}

	/**
	 * @brief Replace one entry's mode or throw a focused fixture error.
	 * @param path Existing fixture entry.
	 * @param mode Exact permissions to apply.
	 */
	static void set_mode(const std::filesystem::path &path, mode_t mode)
	{
		if (::chmod(path.c_str(), mode) != 0) {
			throw std::runtime_error("failed to set provider release fixture mode");
		}
	}

	/**
	 * @brief Copy one completed artifact into the staged root or throw.
	 * @param source Completed input artifact.
	 * @param destination Absent path in the staged root.
	 * @param mode Exact destination permissions.
	 */
	static void copy_exact_file(const std::filesystem::path &source, const std::filesystem::path &destination,
				    mode_t mode)
	{
		std::error_code error;
		std::filesystem::copy_file(source, destination, std::filesystem::copy_options::none, error);
		if (error) {
			throw std::runtime_error("failed to stage provider release artifact: " +
						 std::string(error.message()));
		}
		set_mode(destination, mode);
	}

	/**
	 * @brief Write a fixture file and apply its exact mode, or throw.
	 * @param path Fixture file to create or replace.
	 * @param bytes Complete intended contents.
	 * @param mode Exact destination permissions.
	 */
	static void write_exact_file(const std::filesystem::path &path, std::string_view bytes, mode_t mode)
	{
		std::ofstream output(path, std::ios::binary | std::ios::trunc);
		if (!output || !output.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
		    !output.flush()) {
			throw std::runtime_error("failed to write provider release fixture bytes");
		}
		output.close();
		if (!output) {
			throw std::runtime_error("failed to close provider release fixture bytes");
		}
		set_mode(path, mode);
	}

	std::filesystem::path root_;		     ///< Exact private candidate root.
	std::filesystem::path artifact_directory_;   ///< Fixed provider-artifact directory.
	std::filesystem::path inventory_directory_;  ///< Fixed inventory directory.
	std::filesystem::path release_directory_;    ///< Fixed release-evidence directory.
};

/** @return Smallest valid ABI projection owning one UDP driver. */
compiled_provider_topology minimal_udp_topology()
{
	compiled_provider_topology topology;
	topology.io_drivers.push_back(compiled_io_driver_instance{
		.io_driver_instance_id = "udp_driver_0",
		.io_driver_index = 0,
		.facility_indices = {},
		.configuration =
			compiled_provider_configuration{
				.type_url = std::string(UDP_DRIVER_TYPE_URL),
				.canonical_payload = {},
			},
		.capabilities = {},
		.attachments = {},
		.storage_domain_indices = {},
	});
	topology.required_contract_type_urls.emplace_back(UDP_DRIVER_TYPE_URL);
	return topology;
}

/** @return Smallest valid ABI projection owning one DPDK facility. */
compiled_provider_topology minimal_dpdk_facility_topology()
{
	compiled_provider_topology topology;
	topology.process_facilities.push_back(compiled_process_facility_instance{
		.facility_instance_id = "dpdk_facility_0",
		.facility_index = 0,
		.configuration =
			compiled_provider_configuration{
				.type_url = std::string(DPDK_FACILITY_TYPE_URL),
				.canonical_payload = {},
			},
		.capabilities = process_facility_projection{true, true, true},
		.main_core_id = 0,
		.cpu_assignments = {},
		.attachments = {},
		.memory_domains = {},
	});
	topology.host_requirements = {
		compiled_provider_host_requirement{
			.phase = provider_host_proof_phase::COMPONENT_HOST_PROOF,
			.fact = provider_host_fact::DPDK_EAL_RUNTIME,
			.role = provider_contract_role::PROCESS_FACILITY,
			.instance_index = 0,
		},
		compiled_provider_host_requirement{
			.phase = provider_host_proof_phase::COMPONENT_HOST_PROOF,
			.fact = provider_host_fact::DPDK_HUGEPAGE_PAYLOAD_FLOOR,
			.role = provider_contract_role::PROCESS_FACILITY,
			.instance_index = 0,
		},
	};
	topology.required_contract_type_urls.emplace_back(DPDK_FACILITY_TYPE_URL);
	return topology;
}

/** @brief Pin the complete compact receipt descriptor and its map-free shape. */
TEST(provider_release, native_admission_receipt_schema_is_exact_and_map_free)
{
	using google::protobuf::FieldDescriptor;
	using ::kinetum::release::v1::NativeProviderAdmissionReceipt;

	const auto *descriptor = NativeProviderAdmissionReceipt::descriptor();
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->field_count(), 6);
	EXPECT_EQ(descriptor->oneof_decl_count(), 0);

	const auto *format_version = descriptor->FindFieldByName("format_version");
	const auto *target_tuple = descriptor->FindFieldByName("target_tuple");
	const auto *inventory_hash = descriptor->FindFieldByName("inventory_sha256");
	const auto *inventory_size = descriptor->FindFieldByName("inventory_size_bytes");
	const auto *components = descriptor->FindFieldByName("admitted_components");
	const auto *private_artifacts = descriptor->FindFieldByName("admitted_private_artifacts");
	ASSERT_NE(format_version, nullptr);
	ASSERT_NE(target_tuple, nullptr);
	ASSERT_NE(inventory_hash, nullptr);
	ASSERT_NE(inventory_size, nullptr);
	ASSERT_NE(components, nullptr);
	ASSERT_NE(private_artifacts, nullptr);

	EXPECT_EQ(format_version->number(), 1);
	EXPECT_EQ(format_version->type(), FieldDescriptor::TYPE_UINT32);
	EXPECT_FALSE(format_version->is_repeated());
	EXPECT_EQ(target_tuple->number(), 2);
	EXPECT_EQ(target_tuple->type(), FieldDescriptor::TYPE_STRING);
	EXPECT_FALSE(target_tuple->is_repeated());
	EXPECT_EQ(inventory_hash->number(), 3);
	EXPECT_EQ(inventory_hash->type(), FieldDescriptor::TYPE_BYTES);
	EXPECT_FALSE(inventory_hash->is_repeated());
	EXPECT_EQ(inventory_size->number(), 4);
	EXPECT_EQ(inventory_size->type(), FieldDescriptor::TYPE_UINT64);
	EXPECT_FALSE(inventory_size->is_repeated());
	EXPECT_EQ(components->number(), 5);
	EXPECT_EQ(components->type(), FieldDescriptor::TYPE_MESSAGE);
	EXPECT_TRUE(components->is_repeated());
	ASSERT_NE(components->message_type(), nullptr);
	EXPECT_EQ(components->message_type()->full_name(), "kinetum.provider.v1.ProviderComponentArtifact");
	EXPECT_EQ(private_artifacts->number(), 6);
	EXPECT_EQ(private_artifacts->type(), FieldDescriptor::TYPE_MESSAGE);
	EXPECT_TRUE(private_artifacts->is_repeated());
	ASSERT_NE(private_artifacts->message_type(), nullptr);
	EXPECT_EQ(private_artifacts->message_type()->full_name(), "kinetum.provider.v1.PrivateProviderArtifact");
	for (int index = 0; index < descriptor->field_count(); ++index) {
		EXPECT_FALSE(descriptor->field(index)->is_map());
		EXPECT_EQ(descriptor->field(index)->containing_oneof(), nullptr);
	}
}

/** @brief Prove both supported tuples own distinct exact runtime-loader identities. */
TEST(provider_release, target_tuple_and_runtime_loader_authorities_are_exact)
{
	auto aarch64_or = parse_provider_target_tuple(LINUX_GNU_AARCH64_TARGET_TUPLE);
	auto x86_64_or = parse_provider_target_tuple(LINUX_GNU_X86_64_TARGET_TUPLE);
	ASSERT_TRUE(aarch64_or.is_ok()) << aarch64_or.error();
	ASSERT_TRUE(x86_64_or.is_ok()) << x86_64_or.error();
	EXPECT_EQ(aarch64_or.value(), provider_target_tuple::LINUX_GNU_AARCH64);
	EXPECT_EQ(x86_64_or.value(), provider_target_tuple::LINUX_GNU_X86_64);
	EXPECT_EQ(provider_runtime_loader_soname(aarch64_or.value()), LINUX_GNU_AARCH64_RUNTIME_LOADER_SONAME);
	EXPECT_EQ(provider_runtime_loader_soname(x86_64_or.value()), LINUX_GNU_X86_64_RUNTIME_LOADER_SONAME);
	EXPECT_TRUE(is_platform_runtime_soname(LINUX_GNU_AARCH64_RUNTIME_LOADER_SONAME, aarch64_or.value()));
	EXPECT_FALSE(is_platform_runtime_soname(LINUX_GNU_X86_64_RUNTIME_LOADER_SONAME, aarch64_or.value()));
	EXPECT_TRUE(is_platform_runtime_soname(LINUX_GNU_X86_64_RUNTIME_LOADER_SONAME, x86_64_or.value()));
	EXPECT_FALSE(is_platform_runtime_soname(LINUX_GNU_AARCH64_RUNTIME_LOADER_SONAME, x86_64_or.value()));
	EXPECT_TRUE(is_platform_runtime_soname("libnuma.so.1", aarch64_or.value()));
	EXPECT_TRUE(is_platform_runtime_soname("libnuma.so.1", x86_64_or.value()));
	EXPECT_FALSE(is_platform_runtime_soname("libbsd.so.0", aarch64_or.value()));
	EXPECT_FALSE(is_platform_runtime_soname("libbsd.so.0", x86_64_or.value()));
	EXPECT_FALSE(parse_provider_target_tuple("aarch64").is_ok());
}

/** @brief Reject any signing seed whose custody facts or derived anchor differ. */
TEST_F(ProviderReleaseTest, signing_seed_requires_exact_custody_and_anchor)
{
	auto standard_stream_or =
		release::admit_provider_release_signing_key(STDIN_FILENO, owner_uid(), test::PROVIDER_TEST_PUBLIC_KEY);
	ASSERT_FALSE(standard_stream_or.is_ok());
	EXPECT_EQ(standard_stream_or.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(standard_stream_or.error().message().find("standard stream"), std::string::npos);

	write_test_seed();
	auto key_or = admit_test_seed();
	ASSERT_TRUE(key_or.is_ok()) << key_or.error();
	EXPECT_EQ(key_or->key(), test::PROVIDER_TEST_PRIVATE_KEY);

	{
		const descriptor_owner directory_descriptor(::open(root_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
		ASSERT_GE(directory_descriptor.get(), 0);
		auto nonregular_or = release::admit_provider_release_signing_key(
			directory_descriptor.get(), owner_uid(), test::PROVIDER_TEST_PUBLIC_KEY);
		ASSERT_FALSE(nonregular_or.is_ok());
		EXPECT_EQ(nonregular_or.error().code(), common::status_code::FAILED_PRECONDITION);
	}

	{
		const descriptor_owner wrong_owner_descriptor(::open(seed_path().c_str(), O_RDONLY | O_CLOEXEC));
		ASSERT_GE(wrong_owner_descriptor.get(), 0);
		auto wrong_owner_or = release::admit_provider_release_signing_key(
			wrong_owner_descriptor.get(), owner_uid() ^ 1u, test::PROVIDER_TEST_PUBLIC_KEY);
		ASSERT_FALSE(wrong_owner_or.is_ok());
		EXPECT_EQ(wrong_owner_or.error().code(), common::status_code::PERMISSION_DENIED);
	}

	set_mode(seed_path(), 0600);
	{
		const descriptor_owner writable_descriptor(::open(seed_path().c_str(), O_RDWR | O_CLOEXEC));
		ASSERT_GE(writable_descriptor.get(), 0);
		set_mode(seed_path(), RELEASE_SEED_MODE);
		auto writable_or = release::admit_provider_release_signing_key(writable_descriptor.get(), owner_uid(),
									       test::PROVIDER_TEST_PUBLIC_KEY);
		ASSERT_FALSE(writable_or.is_ok());
		EXPECT_EQ(writable_or.error().code(), common::status_code::PERMISSION_DENIED);
	}

	const std::filesystem::path seed_link = root_ / "release_signing_seed_link";
	std::error_code error;
	std::filesystem::create_hard_link(seed_path(), seed_link, error);
	ASSERT_FALSE(error) << error.message();
	{
		const descriptor_owner linked_descriptor(::open(seed_path().c_str(), O_RDONLY | O_CLOEXEC));
		ASSERT_GE(linked_descriptor.get(), 0);
		auto linked_or = release::admit_provider_release_signing_key(linked_descriptor.get(), owner_uid(),
									     test::PROVIDER_TEST_PUBLIC_KEY);
		ASSERT_FALSE(linked_or.is_ok());
		EXPECT_EQ(linked_or.error().code(), common::status_code::PERMISSION_DENIED);
	}
	ASSERT_TRUE(std::filesystem::remove(seed_link, error));
	ASSERT_FALSE(error) << error.message();

	set_mode(seed_path(), 0600);
	write_exact_file(seed_path(), std::string(common::ED25519_PRIVATE_KEY_SIZE - 1u, '\0'), RELEASE_SEED_MODE);
	{
		const descriptor_owner wrong_size_descriptor(::open(seed_path().c_str(), O_RDONLY | O_CLOEXEC));
		ASSERT_GE(wrong_size_descriptor.get(), 0);
		auto wrong_size_or = release::admit_provider_release_signing_key(
			wrong_size_descriptor.get(), owner_uid(), test::PROVIDER_TEST_PUBLIC_KEY);
		ASSERT_FALSE(wrong_size_or.is_ok());
		EXPECT_EQ(wrong_size_or.error().code(), common::status_code::INVALID_ARGUMENT);
	}

	set_mode(seed_path(), 0600);
	write_test_seed();
	common::ed25519_public_key wrong_anchor = test::PROVIDER_TEST_PUBLIC_KEY;
	wrong_anchor[0] ^= 0x01u;
	const descriptor_owner wrong_anchor_descriptor(::open(seed_path().c_str(), O_RDONLY | O_CLOEXEC));
	ASSERT_GE(wrong_anchor_descriptor.get(), 0);
	auto wrong_anchor_or =
		release::admit_provider_release_signing_key(wrong_anchor_descriptor.get(), owner_uid(), wrong_anchor);
	ASSERT_FALSE(wrong_anchor_or.is_ok());
	EXPECT_EQ(wrong_anchor_or.error().code(), common::status_code::PERMISSION_DENIED);

	set_mode(seed_path(), 0600);
	const descriptor_owner wrong_mode_descriptor(::open(seed_path().c_str(), O_RDONLY | O_CLOEXEC));
	ASSERT_GE(wrong_mode_descriptor.get(), 0);
	auto wrong_mode_or = release::admit_provider_release_signing_key(wrong_mode_descriptor.get(), owner_uid(),
									 test::PROVIDER_TEST_PUBLIC_KEY);
	ASSERT_FALSE(wrong_mode_or.is_ok());
	EXPECT_EQ(wrong_mode_or.error().code(), common::status_code::PERMISSION_DENIED);
}

/** @brief Prove native preparation emits only the exact unsigned production set. */
TEST_F(ProviderReleaseTest, native_prepare_emits_exact_unsigned_production_aggregate)
{
	const auto preparation = prepare();
	ASSERT_TRUE(preparation.is_ok()) << preparation;
	EXPECT_TRUE(std::filesystem::is_regular_file(inventory_path()));
	EXPECT_TRUE(std::filesystem::is_regular_file(receipt_path()));
	EXPECT_FALSE(std::filesystem::exists(signature_path()));

	auto reconstructed_or =
		reconstruct_production_provider_release(root_, native_provider_target_tuple(), candidate_policy());
	ASSERT_TRUE(reconstructed_or.is_ok()) << reconstructed_or.error();
	auto inventory_bytes_or = common::read_file_to_string(inventory_path().string(), MAX_PROVIDER_INVENTORY_BYTES);
	ASSERT_TRUE(inventory_bytes_or.is_ok()) << inventory_bytes_or.error();
	EXPECT_EQ(inventory_bytes_or.value(), reconstructed_or->canonical_bytes);
	ASSERT_EQ(reconstructed_or->inventory.components_size(), 2);
	EXPECT_EQ(reconstructed_or->inventory.components(0).component_id(), "kinetum.provider.dpdk");
	EXPECT_EQ(reconstructed_or->inventory.components(1).component_id(), "kinetum.provider.host");
	for (const auto &component : reconstructed_or->inventory.components()) {
		for (const auto &type_url : component.contract_type_urls()) {
			EXPECT_NE(type_url, UDP_DRIVER_TYPE_URL);
		}
	}
	auto receipt_bytes_or =
		common::read_file_to_string(receipt_path().string(), MAX_PROVIDER_ADMISSION_RECEIPT_BYTES);
	ASSERT_TRUE(receipt_bytes_or.is_ok()) << receipt_bytes_or.error();
	EXPECT_TRUE(validate_native_provider_admission_receipt(receipt_bytes_or.value(), reconstructed_or.value(),
							       native_provider_target_tuple())
			    .is_ok());
}

/** @brief Reject a foreign tuple, then sign only the exact statically verified candidate. */
TEST_F(ProviderReleaseTest, architecture_neutral_finalize_signs_and_statically_verifies_candidate)
{
	ASSERT_TRUE(prepare().is_ok());
	write_test_seed();
	auto key_or = admit_test_seed();
	ASSERT_TRUE(key_or.is_ok()) << key_or.error();
	const provider_target_tuple native_target = native_provider_target_tuple();
	const provider_target_tuple foreign_target = native_target == provider_target_tuple::LINUX_GNU_AARCH64 ?
							     provider_target_tuple::LINUX_GNU_X86_64 :
							     provider_target_tuple::LINUX_GNU_AARCH64;
	const auto foreign_finalization = release::finalize_provider_release_candidate(
		root_, foreign_target, owner_uid(), key_or.value(), test::PROVIDER_TEST_PUBLIC_KEY);
	ASSERT_FALSE(foreign_finalization.is_ok());
	EXPECT_EQ(foreign_finalization.code(), common::status_code::FAILED_PRECONDITION);
	EXPECT_FALSE(std::filesystem::exists(signature_path()));

	const auto finalization = release::finalize_provider_release_candidate(
		root_, native_target, owner_uid(), key_or.value(), test::PROVIDER_TEST_PUBLIC_KEY);
	ASSERT_TRUE(finalization.is_ok()) << finalization;
	EXPECT_TRUE(std::filesystem::is_regular_file(signature_path()));
	auto verified_or = verify_installed_provider_release(root_, native_target, test::PROVIDER_TEST_PUBLIC_KEY,
							     candidate_policy());
	ASSERT_TRUE(verified_or.is_ok()) << verified_or.error();
}

/** @brief Reject an anchor/key disagreement before inspecting candidate storage. */
TEST_F(ProviderReleaseTest, finalizer_binds_admitted_signing_key_before_candidate_access)
{
	write_test_seed();
	auto key_or = admit_test_seed();
	ASSERT_TRUE(key_or.is_ok()) << key_or.error();
	auto wrong_anchor = test::PROVIDER_TEST_PUBLIC_KEY;
	wrong_anchor.front() ^= 0x01u;

	const auto finalization = release::finalize_provider_release_candidate(
		root_ / "absent-candidate", native_provider_target_tuple(), owner_uid(), key_or.value(), wrong_anchor);
	EXPECT_FALSE(finalization.is_ok());
	EXPECT_EQ(finalization.code(), common::status_code::PERMISSION_DENIED);
	EXPECT_NE(finalization.message().find("not bound"), std::string::npos);
}

/** @brief Require native self-admission evidence before signature publication. */
TEST_F(ProviderReleaseTest, finalizer_requires_additive_native_receipt_before_signature)
{
	ASSERT_TRUE(prepare().is_ok());
	std::error_code error;
	ASSERT_TRUE(std::filesystem::remove(receipt_path(), error));
	ASSERT_FALSE(error);
	write_test_seed();
	auto key_or = admit_test_seed();
	ASSERT_TRUE(key_or.is_ok()) << key_or.error();
	const auto finalization = release::finalize_provider_release_candidate(
		root_, native_provider_target_tuple(), owner_uid(), key_or.value(), test::PROVIDER_TEST_PUBLIC_KEY);
	EXPECT_FALSE(finalization.is_ok());
	EXPECT_FALSE(std::filesystem::exists(signature_path()));
}

/** @brief Reject malformed native evidence without publishing a signature. */
TEST_F(ProviderReleaseTest, malformed_native_receipt_cannot_authorize_signature)
{
	ASSERT_TRUE(prepare().is_ok());
	write_exact_file(receipt_path(), "malformed-native-receipt", RELEASE_DATA_MODE);
	write_test_seed();
	auto key_or = admit_test_seed();
	ASSERT_TRUE(key_or.is_ok()) << key_or.error();
	const auto finalization = release::finalize_provider_release_candidate(
		root_, native_provider_target_tuple(), owner_uid(), key_or.value(), test::PROVIDER_TEST_PUBLIC_KEY);
	EXPECT_FALSE(finalization.is_ok());
	EXPECT_FALSE(std::filesystem::exists(signature_path()));
}

/** @brief Prove prior native evidence cannot suppress finalizer artifact reconstruction. */
TEST_F(ProviderReleaseTest, prior_native_receipt_cannot_subtract_static_artifact_reconstruction)
{
	ASSERT_TRUE(prepare().is_ok());
	std::ofstream append(dpdk_component_path(), std::ios::binary | std::ios::app);
	ASSERT_TRUE(append);
	append.put('\0');
	append.flush();
	ASSERT_TRUE(append);
	append.close();
	ASSERT_TRUE(append);
	write_test_seed();
	auto key_or = admit_test_seed();
	ASSERT_TRUE(key_or.is_ok()) << key_or.error();
	const auto finalization = release::finalize_provider_release_candidate(
		root_, native_provider_target_tuple(), owner_uid(), key_or.value(), test::PROVIDER_TEST_PUBLIC_KEY);
	EXPECT_FALSE(finalization.is_ok());
	EXPECT_FALSE(std::filesystem::exists(signature_path()));
}

/** @brief Pin production file and directory authority as independent requirements. */
TEST_F(ProviderReleaseTest, production_policy_rejects_untrusted_file_or_directory_authority)
{
	uint32_t staged_runtime_owner = owner_uid();
	if (::geteuid() == 0) {
		ASSERT_EQ(::chown(runtime_path().c_str(), NON_ROOT_TEST_OWNER_UID, static_cast<gid_t>(-1)), 0)
			<< "failed to establish a non-root-owned runtime fixture";
		staged_runtime_owner = static_cast<uint32_t>(NON_ROOT_TEST_OWNER_UID);
	}
	auto policy = production_provider_file_policy(root_);
	EXPECT_EQ(policy.required_owner_uid, 0u);
	ASSERT_TRUE(policy.directories.has_value());
	EXPECT_EQ(policy.directories->required_owner_uid, 0u);

	// Let the current-user fixture pass only the directory-authority leg. The
	// unmodified production file authority must still reject its runtime image.
	policy.directories->required_owner_uid = owner_uid();
	auto file_or = common::open_held_regular_file(runtime_path(), policy);
	ASSERT_FALSE(file_or.is_ok());
	EXPECT_EQ(file_or.error().code(), common::status_code::PERMISSION_DENIED);

	// Admit the staged file owner only for this second ownership change. A writable
	// directory must fail independently before the final artifact is accepted.
	policy.required_owner_uid = staged_runtime_owner;
	const auto runtime_directory = runtime_path().parent_path();
	set_mode(runtime_directory, GROUP_WRITABLE_DIRECTORY_MODE);
	auto directory_or = common::open_held_regular_file(runtime_path(), policy);
	set_mode(runtime_directory, RELEASE_DIRECTORY_MODE);
	ASSERT_FALSE(directory_or.is_ok());
	EXPECT_EQ(directory_or.error().code(), common::status_code::PERMISSION_DENIED);
}

/** @brief Reject embedded NUL bytes before held artifact path traversal. */
TEST_F(ProviderReleaseTest, held_artifact_paths_and_directory_roots_are_nul_free)
{
	auto policy = production_provider_file_policy(root_);
	policy.required_owner_uid = owner_uid();
	ASSERT_TRUE(policy.directories.has_value());
	policy.directories->required_owner_uid = owner_uid();

	std::string path_text = runtime_path().string();
	path_text.push_back('\0');
	path_text += "suffix";
	auto path_result = common::open_held_regular_file(std::filesystem::path(path_text), policy);
	ASSERT_FALSE(path_result.is_ok());
	EXPECT_EQ(path_result.error().code(), common::status_code::INVALID_ARGUMENT);

	std::string root_text = root_.string();
	root_text.push_back('\0');
	root_text += "suffix";
	policy.directories->root = std::filesystem::path(root_text);
	auto root_result = common::open_held_regular_file(runtime_path(), policy);
	ASSERT_FALSE(root_result.is_ok());
	EXPECT_EQ(root_result.error().code(), common::status_code::INVALID_ARGUMENT);
}

/** @brief Reject duplicate COMPONENT facts before installed-release access. */
TEST(provider_runtime_admission, duplicate_component_host_fact_rejects_before_loading)
{
	auto topology = minimal_udp_topology();
	const compiled_provider_host_requirement requirement{
		.phase = provider_host_proof_phase::COMPONENT_HOST_PROOF,
		.fact = provider_host_fact::LINUX_IPV4_DATAGRAM_SOCKET,
		.role = provider_contract_role::IO_DRIVER,
		.instance_index = 0,
	};
	topology.host_requirements = {requirement, requirement};
	const std::filesystem::path impossible_root = "/provider-release-test-must-not-be-read";
	auto result = admit_installed_provider_runtime(
		topology, impossible_root, impossible_root / "bin/kinetum_dp", test::PROVIDER_TEST_PUBLIC_KEY,
		release_candidate_file_policy(impossible_root, static_cast<uint32_t>(::geteuid())));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("duplicate fact"), std::string::npos);
}

/** @brief Reject a missing COMPONENT fact before installed-release access. */
TEST(provider_runtime_admission, missing_component_host_fact_rejects_before_loading)
{
	auto topology = minimal_udp_topology();
	const std::filesystem::path impossible_root = "/provider-release-test-must-not-be-read";
	auto result = admit_installed_provider_runtime(
		topology, impossible_root, impossible_root / "bin/kinetum_dp", test::PROVIDER_TEST_PUBLIC_KEY,
		release_candidate_file_policy(impossible_root, static_cast<uint32_t>(::geteuid())));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("not exact in both directions"), std::string::npos);
}

/** @brief Dispatch the exact COMPONENT fact and seal only its required implementation. */
TEST(provider_runtime_admission, exact_component_host_fact_dispatches_through_injected_installation)
{
	test::provider_component_test_fixture fixture;
	const auto component_path =
		fixture.stage_artifact(KINETUM_PROVIDER_UDP_COMPONENT_PATH, "libkinetum_provider_udp_component.so");
	const auto component =
		fixture.component_record(component_path, "kinetum.provider.udp", {std::string(UDP_DRIVER_TYPE_URL)});
	const auto inventory = fixture.inventory({component}, {});
	(void)fixture.write_signed_inventory(inventory);

	auto topology = minimal_udp_topology();
	topology.host_requirements.push_back(compiled_provider_host_requirement{
		.phase = provider_host_proof_phase::COMPONENT_HOST_PROOF,
		.fact = provider_host_fact::LINUX_IPV4_DATAGRAM_SOCKET,
		.role = provider_contract_role::IO_DRIVER,
		.instance_index = 0,
	});
	auto admitted_or = admit_installed_provider_runtime(topology, fixture.root(), fixture.runtime_image(),
							    test::PROVIDER_TEST_PUBLIC_KEY, fixture.file_policy());
	ASSERT_TRUE(admitted_or.is_ok()) << admitted_or.error();
	EXPECT_EQ(admitted_or->catalog().size(), 1u);
	EXPECT_NE(admitted_or->catalog().find(UDP_DRIVER_TYPE_URL), nullptr);
	EXPECT_EQ(admitted_or->instance_count(), 1u);
	EXPECT_NE(admitted_or->instance_facts(provider_contract_role::IO_DRIVER, 0), nullptr);
}

/** @brief Log and fail stop when a COMPONENT proof fails after loading. */
TEST(provider_runtime_admission, component_host_proof_failure_fails_stop_without_component_unload)
{
	test::provider_component_test_fixture fixture;
	const std::filesystem::path private_source = KINETUM_TEST_PROVIDER_PRIVATE_PATH;
	const auto private_path = fixture.stage_artifact(private_source, private_source.filename().string());
	const auto private_record = fixture.private_artifact_record(private_path, KINETUM_TEST_PROVIDER_PRIVATE_SONAME);
	const std::filesystem::path component_source = KINETUM_TEST_PROVIDER_HOST_PROOF_FAILURE_PATH;
	const auto component_path = fixture.stage_artifact(component_source, component_source.filename().string());
	const auto component_record = fixture.component_record(component_path, HOST_PROOF_FAILURE_COMPONENT_ID,
							       {std::string(DPDK_FACILITY_TYPE_URL)});
	const auto inventory = fixture.inventory({component_record}, {private_record});
	(void)fixture.write_signed_inventory(inventory);
	const auto topology = minimal_dpdk_facility_topology();

	EXPECT_DEATH(
		{
			(void)admit_installed_provider_runtime(topology, fixture.root(), fixture.runtime_image(),
							       test::PROVIDER_TEST_PUBLIC_KEY, fixture.file_policy());
		},
		"injected component host-proof failure");
}

}  // namespace
}  // namespace kinetum::provider
