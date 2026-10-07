// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_component_admission.cpp
 * @brief Held-artifact, ELF, closure, and exact provider-ABI admission tests.
 * @author Fleming Patel
 */

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <google/protobuf/repeated_field.h>
#include <gtest/gtest.h>

#include "src/common/status.hpp"
#include "src/provider/provider_component_admission.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_elf.hpp"
#include "tests/provider_component_test_fixture.hpp"
#include "tests/provider_log_capture.hpp"

#if !defined(KINETUM_TEST_PROVIDER_PRIVATE_PATH) || !defined(KINETUM_TEST_PROVIDER_COMPONENT_PATH) ||                 \
	!defined(KINETUM_TEST_PROVIDER_COMPONENT_CPP_PATH) || !defined(KINETUM_TEST_PROVIDER_COMPONENT_MULTI_PATH) || \
	!defined(KINETUM_TEST_PROVIDER_NODELETE_PATH) || !defined(KINETUM_TEST_PROVIDER_VERSIONED_PATH) ||            \
	!defined(KINETUM_TEST_PROVIDER_COMPONENT_OLDER_PATH) ||                                                       \
	!defined(KINETUM_TEST_PROVIDER_COMPONENT_NEWER_PATH) ||                                                       \
	!defined(KINETUM_TEST_PROVIDER_COMPONENT_WRONG_ABI_PATH) ||                                                   \
	!defined(KINETUM_TEST_PROVIDER_COMPONENT_WRONG_ROLE_PATH) || !defined(KINETUM_TEST_PROVIDER_PADDING_PATH) ||  \
	!defined(KINETUM_TEST_PROVIDER_COMPONENT_SECOND_PATH) || !defined(KINETUM_TEST_PROVIDER_PRIVATE_SONAME)
#error "provider component admission tests require exact CMake artifact paths"
#endif

namespace kinetum::provider
{
namespace
{

using kinetum::provider::v1::PrivateProviderArtifact;
using kinetum::provider::v1::ProviderComponentArtifact;

/** Exact primary conformance component identity. */
constexpr std::string_view TEST_COMPONENT_ID = "kinetum.test.provider";

/** Exact secondary conformance component identity. */
constexpr std::string_view TEST_SECOND_COMPONENT_ID = "kinetum.test.provider.second";

/** Exact C++ conformance component identity. */
constexpr std::string_view TEST_CPP_COMPONENT_ID = "kinetum.test.provider.cpp";

/** Exact multi-contract conformance component identity. */
constexpr std::string_view TEST_MULTI_COMPONENT_ID = "kinetum.test.provider.multi";

/** Marker exported by the deliberately private conformance dependency. */
constexpr uint32_t TEST_PRIVATE_MARKER = UINT32_C(0x4b505256);

/** Marker exposed as the conformance factory's immutable operation table. */
constexpr uint32_t TEST_OPERATION_MARKER = UINT32_C(0x4b4f5053);

/** Marker exposed through the ODR-used C++ operation-table canary. */
constexpr uint32_t TEST_CPP_OPERATION_MARKER = UINT32_C(0x4b435050);

/** Marker exposed by the multi-contract component's second row. */
constexpr uint32_t TEST_SECOND_OPERATION_MARKER = UINT32_C(0x4b4f5032);

/**
 * @brief One explicit staged component plus its exact private dependency.
 */
struct staged_provider_artifacts {
	test::provider_component_test_fixture fixture;	///< Fixed release/runtime layout.
	std::filesystem::path private_path;		///< Staged exact private dependency.
	std::filesystem::path component_path;		///< Staged exact component.
	PrivateProviderArtifact private_record;		///< Same-descriptor private identity.
	ProviderComponentArtifact component_record;	///< Same-descriptor component identity.

	/**
	 * @brief Stage one explicit component with a complete contract set.
	 *
	 * @param component_source Completed component source path.
	 * @param component_id Source-controlled descriptor identity.
	 * @param contract_type_urls Complete exact pure-catalog contract set.
	 */
	staged_provider_artifacts(const std::filesystem::path &component_source, std::string_view component_id,
				  std::vector<std::string> contract_type_urls)
	{
		const std::filesystem::path private_source = KINETUM_TEST_PROVIDER_PRIVATE_PATH;
		private_path = fixture.stage_artifact(private_source, private_source.filename().string());
		private_record = fixture.private_artifact_record(private_path, KINETUM_TEST_PROVIDER_PRIVATE_SONAME);
		component_path = fixture.stage_artifact(component_source, component_source.filename().string());
		component_record =
			fixture.component_record(component_path, component_id, std::move(contract_type_urls));
	}

	/**
	 * @brief Stage one explicit single-contract component.
	 *
	 * @param component_source Completed component source path.
	 * @param component_id Source-controlled descriptor identity.
	 * @param contract_type_url Exact pure-catalog contract identity.
	 */
	explicit staged_provider_artifacts(
		const std::filesystem::path &component_source = KINETUM_TEST_PROVIDER_COMPONENT_PATH,
		std::string_view component_id = TEST_COMPONENT_ID,
		std::string_view contract_type_url = ZERO_COPY_SHARE_TYPE_URL)
		: staged_provider_artifacts(component_source, component_id,
					    std::vector<std::string>{std::string(contract_type_url)})
	{
	}

	/** @return Owned repeated field containing the fixture's exact private-artifact record. */
	[[nodiscard]] google::protobuf::RepeatedPtrField<PrivateProviderArtifact> private_records() const
	{
		google::protobuf::RepeatedPtrField<PrivateProviderArtifact> records;
		records.Add()->CopyFrom(private_record);
		return records;
	}
};

/**
 * @brief Preflight the primary component from one staged fixture.
 *
 * @param artifacts Staged exact artifacts.
 * @return Unforgeable preflight proof or the first admission failure.
 */
common::status_or<preflighted_provider_component> preflight(staged_provider_artifacts &artifacts)
{
	auto private_records = artifacts.private_records();
	return preflight_provider_component(artifacts.fixture.artifact_directory(), artifacts.component_record,
					    private_records, native_provider_target_tuple(),
					    artifacts.fixture.file_policy());
}

/**
 * @brief Build one exact conformance factory request.
 *
 * @param implementation Exact admitted implementation row.
 * @param logging Cold diagnostic owner retained through result destruction.
 * @return Zero-padded request for that row.
 */
kinetum_provider_factory_request factory_request(const kinetum_provider_contract_implementation &implementation,
						 kinetum::test_support::provider_log_capture &logging)
{
	static constexpr char INSTANCE_ID[] = "test.instance";
	static constexpr kinetum_provider_process_facility_facts FACILITY_FACTS{
		.facility_index = 1,
		.main_core_id = 2,
		.cpu_assignments = nullptr,
		.cpu_assignment_count = 0,
		.cpu_assignment_padding = 0,
		.attachments = nullptr,
		.attachment_count = 0,
		.attachment_padding = 0,
		.memory_domains = nullptr,
		.memory_domain_count = 0,
		.padding = {0},
	};
	static constexpr kinetum_provider_io_driver_facts IO_DRIVER_FACTS{
		.io_driver_index = 3,
		.index_padding = 0,
		.attachments = nullptr,
		.attachment_count = 0,
		.attachment_padding = 0,
		.ports = nullptr,
		.port_count = 0,
		.port_padding = 0,
		.streams = nullptr,
		.stream_count = 0,
		.stream_padding = 0,
		.steering_profiles = nullptr,
		.steering_profile_count = 0,
		.steering_padding = 0,
	};
	static constexpr kinetum_provider_packet_storage_facts STORAGE_FACTS{
		.storage_domain_index = 4,
		.buffer_count = 64,
		.data_room_bytes = 2048,
		.headroom_bytes = 0,
		.alignment_bytes = 0,
		.cache_size_per_worker = 0,
		.required_buffer_count = 0,
		.safety_margin = 0,
		.host_numa_node = 0,
		.maximum_packet_length = 2048,
		.access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.has_host_numa_node = 0,
		.padding = {0},
	};
	static constexpr kinetum_provider_execution_facts EXECUTION_FACTS{
		.execution_provider_index = 5,
		.required_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.index_padding = {0},
		.stage_instance_indices = nullptr,
		.stage_instance_count = 0,
		.stage_padding = 0,
		.worker_indices = nullptr,
		.worker_count = 0,
		.worker_padding = 0,
	};
	static constexpr kinetum_provider_storage_transition_facts TRANSITION_FACTS{
		.transition_index = 6,
		.from_endpoint = {.kind = KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE, .padding = {0}, .endpoint_index = 1},
		.to_endpoint = {.kind = KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE, .padding = {0}, .endpoint_index = 2},
		.from_storage_domain_index = 4,
		.to_storage_domain_index = 4,
		.staging_capacity = 0,
		.staging_numa_node = 0,
		.mode = KINETUM_PROVIDER_TRANSITION_ZERO_COPY_SHARE,
		.has_staging_numa_node = 0,
		.padding = {0},
	};
	kinetum_provider_compiled_fact_record compiled_facts{};
	switch (implementation.role) {
	case KINETUM_PROVIDER_ROLE_PROCESS_FACILITY:
		compiled_facts.process_facility = &FACILITY_FACTS;
		break;
	case KINETUM_PROVIDER_ROLE_IO_DRIVER:
		compiled_facts.io_driver = &IO_DRIVER_FACTS;
		break;
	case KINETUM_PROVIDER_ROLE_PACKET_STORAGE:
		compiled_facts.packet_storage = &STORAGE_FACTS;
		break;
	case KINETUM_PROVIDER_ROLE_EXECUTION:
		compiled_facts.execution = &EXECUTION_FACTS;
		break;
	case KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION:
		compiled_facts.storage_transition = &TRANSITION_FACTS;
		break;
	default:
		break;
	}
	return kinetum_provider_factory_request{
		.instance_id =
			{
				.data = INSTANCE_ID,
				.size = static_cast<uint32_t>(sizeof(INSTANCE_ID) - 1u),
				.padding = 0,
			},
		.type_url = implementation.type_url,
		.canonical_configuration = {},
		.compiled_facts = compiled_facts,
		.dependencies = nullptr,
		.dependency_count = 0,
		.dependency_padding = 0,
		.runtime_generation = 1,
		.role = implementation.role,
		.padding = {0},
		.logging = logging.capability(),
	};
}

/**
 * @brief Resolve the sole role-matching factory from an admitted row.
 *
 * Descriptor admission has already proved the exactly-one-member law. This
 * helper deliberately repeats no policy; it only performs typed selection for
 * the conformance invocation.
 *
 * @param implementation Exact admitted implementation row.
 * @return Matching factory, or null for an impossible foreign role value.
 */
kinetum_provider_factory_fn admitted_factory(const kinetum_provider_contract_implementation &implementation) noexcept
{
	switch (implementation.role) {
	case KINETUM_PROVIDER_ROLE_PROCESS_FACILITY:
		return implementation.factories.process_facility;
	case KINETUM_PROVIDER_ROLE_IO_DRIVER:
		return implementation.factories.io_driver;
	case KINETUM_PROVIDER_ROLE_PACKET_STORAGE:
		return implementation.factories.packet_storage;
	case KINETUM_PROVIDER_ROLE_EXECUTION:
		return implementation.factories.execution;
	case KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION:
		return implementation.factories.storage_transition;
	default:
		return nullptr;
	}
}

/**
 * @brief Invoke one conformance factory and prove its private relocation.
 *
 * @param implementation Exact admitted implementation row.
 * @param expected_operation_marker Exact implementation-specific operation marker.
 */
void expect_factory_uses_private_dependency(const kinetum_provider_contract_implementation &implementation,
					    uint32_t expected_operation_marker = TEST_OPERATION_MARKER)
{
	kinetum::test_support::provider_log_capture logging;
	const auto request = factory_request(implementation, logging);
	kinetum_provider_factory_result result{};
	char diagnostic_bytes[64]{};
	kinetum_provider_diagnostic diagnostic{
		.data = diagnostic_bytes,
		.capacity = static_cast<uint32_t>(sizeof(diagnostic_bytes)),
		.size = 0,
	};
	const auto factory = admitted_factory(implementation);
	ASSERT_NE(factory, nullptr);
	ASSERT_EQ(factory(&request, &result, &diagnostic), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_NE(result.instance, nullptr);
	ASSERT_NE(result.destroy, nullptr);
	const auto *instance_words = static_cast<const uint32_t *>(result.instance);
	EXPECT_EQ(instance_words[0], TEST_PRIVATE_MARKER);
	EXPECT_EQ(instance_words[1], expected_operation_marker);
	if (implementation.role == KINETUM_PROVIDER_ROLE_PROCESS_FACILITY) {
		EXPECT_EQ(result.operations, nullptr);
	} else if (implementation.role == KINETUM_PROVIDER_ROLE_EXECUTION) {
		ASSERT_NE(result.operations, nullptr);
		const auto *operations = static_cast<const kinetum_provider_execution_operations *>(result.operations);
		EXPECT_EQ(operations->state, result.instance);
		EXPECT_EQ(operations->execution_provider_index,
			  request.compiled_facts.execution->execution_provider_index);
		EXPECT_EQ(operations->required_access_agents, request.compiled_facts.execution->required_access_agents);
	} else {
		ASSERT_EQ(implementation.role, KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION);
		ASSERT_NE(result.operations, nullptr);
		const auto *operations =
			static_cast<const kinetum_provider_storage_transition_operations *>(result.operations);
		EXPECT_EQ(operations->state, result.instance);
		EXPECT_EQ(operations->transition_index, request.compiled_facts.storage_transition->transition_index);
		EXPECT_EQ(operations->mode, request.compiled_facts.storage_transition->mode);
	}
	EXPECT_EQ(diagnostic.size, 0u);
	if (expected_operation_marker == TEST_CPP_OPERATION_MARKER) {
		const auto constructed = logging.read();
		EXPECT_EQ(constructed.records, 1u);
		EXPECT_STREQ(constructed.message.data(), "provider construction");
	}
	result.destroy(result.instance);
	if (expected_operation_marker == TEST_CPP_OPERATION_MARKER) {
		const auto retired = logging.read();
		EXPECT_EQ(retired.records, 2u);
		EXPECT_EQ(retired.malformed, 0u);
		EXPECT_STREQ(retired.message.data(), "provider destruction");
	}
}

/**
 * @brief Exercise one descriptor mismatch under a death-test subprocess.
 *
 * Returning normally exits successfully so EXPECT_DEATH fails; only the
 * admission mechanism's mandatory fail-stop satisfies the test.
 *
 * @param component_source Completed malformed-descriptor component.
 * @param component_id Authenticated inventory component identity.
 * @param contract_type_url Authenticated inventory contract identity.
 */
void admit_mismatched_descriptor(const std::filesystem::path &component_source, std::string_view component_id,
				 std::string_view contract_type_url)
{
	staged_provider_artifacts artifacts(component_source, component_id, contract_type_url);
	auto proof_or = preflight(artifacts);
	if (!proof_or.is_ok()) {
		std::_Exit(0);
	}
	std::vector<preflighted_provider_component> proofs;
	proofs.push_back(std::move(proof_or).value());
	(void)admit_preflighted_provider_components(std::move(proofs));
	std::_Exit(0);
}

/**
 * @brief Prove pathname substitution cannot replace one preflighted image.
 *
 * The malformed replacement carries the same basename but a different inode
 * and descriptor. Admission must query the original inode retained by the
 * proof token; reopening the pathname would fail stop in this subprocess.
 */
[[noreturn]] void admit_after_component_path_replacement()
{
	try {
		staged_provider_artifacts artifacts;
		auto proof_or = preflight(artifacts);
		if (!proof_or.is_ok() || !std::filesystem::remove(artifacts.component_path)) {
			std::_Exit(1);
		}
		const std::filesystem::path replacement_source = KINETUM_TEST_PROVIDER_COMPONENT_WRONG_ABI_PATH;
		(void)artifacts.fixture.stage_artifact(replacement_source,
						       artifacts.component_path.filename().string());

		std::vector<preflighted_provider_component> proofs;
		proofs.push_back(std::move(proof_or).value());
		auto admitted_or = admit_preflighted_provider_components(std::move(proofs));
		if (!admitted_or.is_ok() || admitted_or->component_count() != 1u) {
			std::_Exit(1);
		}
		const auto *component = admitted_or->component_at(0);
		if (component == nullptr || component->descriptor == nullptr ||
		    component->component_id != TEST_COMPONENT_ID) {
			std::_Exit(1);
		}
		std::_Exit(0);
	} catch (...) {
		std::_Exit(1);
	}
}

}  // namespace

/** @brief Prove a preflight proof is unforgeable move-only state. */
TEST(provider_component_admission, preflight_proof_is_unforgeable_move_only_state)
{
	static_assert(!std::is_default_constructible_v<preflighted_provider_component>);
	static_assert(!std::is_copy_constructible_v<preflighted_provider_component>);
	static_assert(!std::is_copy_assignable_v<preflighted_provider_component>);
	static_assert(std::is_nothrow_move_constructible_v<preflighted_provider_component>);
	SUCCEED();
}

/** @brief Prove symlinked component artifacts and path components fail closed. */
TEST(provider_component_admission, symlinked_artifact_or_path_component_fails_closed)
{
	staged_provider_artifacts artifacts;
	const std::filesystem::path link_path = artifacts.fixture.artifact_directory() / "libprovider_symlink.so";
	ASSERT_NO_THROW(std::filesystem::create_symlink(artifacts.component_path.filename(), link_path));
	auto record = artifacts.component_record;
	record.set_file_name(link_path.filename().string());
	auto private_records = artifacts.private_records();
	const auto artifact_result = preflight_provider_component(artifacts.fixture.artifact_directory(), record,
								  private_records, native_provider_target_tuple(),
								  artifacts.fixture.file_policy());
	ASSERT_FALSE(artifact_result.is_ok());
	EXPECT_NE(artifact_result.error().message().find("symlink-free"), std::string::npos);

	const std::filesystem::path directory_link = artifacts.fixture.root() / "provider-artifacts-link";
	ASSERT_NO_THROW(
		std::filesystem::create_directory_symlink(artifacts.fixture.artifact_directory(), directory_link));
	private_records = artifacts.private_records();
	const auto path_result = preflight_provider_component(directory_link, artifacts.component_record,
							      private_records, native_provider_target_tuple(),
							      artifacts.fixture.file_policy());
	ASSERT_FALSE(path_result.is_ok());
	EXPECT_NE(path_result.error().message().find("symlink-free"), std::string::npos);
}

/** @brief Prove a multiply linked component artifact fails closed. */
TEST(provider_component_admission, multiply_linked_component_artifact_fails_closed)
{
	staged_provider_artifacts artifacts;
	const auto second_name = artifacts.fixture.artifact_directory() / "libprovider_hardlink.so";
	ASSERT_NO_THROW(std::filesystem::create_hard_link(artifacts.component_path, second_name));
	const auto result = preflight(artifacts);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("exactly one filesystem link"), std::string::npos);
}

/** @brief Prove a group-writable component artifact fails closed. */
TEST(provider_component_admission, group_writable_component_artifact_fails_closed)
{
	staged_provider_artifacts artifacts;
	ASSERT_NO_THROW(std::filesystem::permissions(artifacts.component_path, std::filesystem::perms::group_write,
						     std::filesystem::perm_options::add));
	const auto result = preflight(artifacts);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("writable"), std::string::npos);
}

/** @brief Prove the component hash claim matches its held descriptor bytes. */
TEST(provider_component_admission, component_hash_claim_must_match_held_descriptor)
{
	staged_provider_artifacts artifacts;
	char &hash_byte = artifacts.component_record.mutable_sha256()->front();
	hash_byte = static_cast<char>(static_cast<uint8_t>(hash_byte) ^ UINT8_C(1));
	const auto result = preflight(artifacts);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("SHA-256"), std::string::npos);
}

/** @brief Prove the component size claim matches its held descriptor. */
TEST(provider_component_admission, component_size_claim_must_match_held_descriptor)
{
	staged_provider_artifacts artifacts;
	artifacts.component_record.set_size_bytes(artifacts.component_record.size_bytes() + 1u);
	const auto result = preflight(artifacts);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("size"), std::string::npos);
}

/** @brief Prove a component has no SONAME and names its exact private dependency. */
TEST(provider_component_admission, component_elf_has_no_soname_and_exact_private_dependency)
{
	staged_provider_artifacts artifacts;
	auto file_or = common::open_held_regular_file(artifacts.component_path, artifacts.fixture.file_policy());
	ASSERT_TRUE(file_or.is_ok()) << file_or.error().to_string();
	auto facts_or = inspect_provider_component_elf(file_or.value(), native_provider_target_tuple());
	ASSERT_TRUE(facts_or.is_ok()) << facts_or.error().to_string();
	EXPECT_TRUE(facts_or->soname.empty());
	EXPECT_TRUE(std::binary_search(facts_or->needed_sonames.begin(), facts_or->needed_sonames.end(),
				       std::string(KINETUM_TEST_PROVIDER_PRIVATE_SONAME)));

	std::atomic<bool> concurrent_inspection_ok{true};
	const auto inspect_repeatedly = [&]() {
		for (uint32_t iteration = 0; iteration < 32u; ++iteration) {
			if (!inspect_provider_component_elf(file_or.value(), native_provider_target_tuple()).is_ok()) {
				concurrent_inspection_ok.store(false, std::memory_order_relaxed);
				return;
			}
		}
	};
	std::thread first(inspect_repeatedly);
	std::thread second(inspect_repeatedly);
	first.join();
	second.join();
	EXPECT_TRUE(concurrent_inspection_ok.load(std::memory_order_relaxed));

	const std::filesystem::path versioned_source = KINETUM_TEST_PROVIDER_VERSIONED_PATH;
	const auto versioned_path =
		artifacts.fixture.stage_artifact(versioned_source, versioned_source.filename().string());
	auto versioned_file_or = common::open_held_regular_file(versioned_path, artifacts.fixture.file_policy());
	ASSERT_TRUE(versioned_file_or.is_ok()) << versioned_file_or.error().to_string();
	const auto versioned_result =
		inspect_provider_component_elf(versioned_file_or.value(), native_provider_target_tuple());
	ASSERT_FALSE(versioned_result.is_ok());
	EXPECT_NE(versioned_result.error().message().find("unversioned"), std::string::npos);

	const std::filesystem::path nodelete_source = KINETUM_TEST_PROVIDER_NODELETE_PATH;
	const auto nodelete_path =
		artifacts.fixture.stage_artifact(nodelete_source, nodelete_source.filename().string());
	auto nodelete_file_or = common::open_held_regular_file(nodelete_path, artifacts.fixture.file_policy());
	ASSERT_TRUE(nodelete_file_or.is_ok()) << nodelete_file_or.error().to_string();
	const auto nodelete_result =
		inspect_provider_component_elf(nodelete_file_or.value(), native_provider_target_tuple());
	ASSERT_FALSE(nodelete_result.is_ok());
	EXPECT_NE(nodelete_result.error().message().find("dynamic-loader behavior"), std::string::npos);
}

/** @brief Prove each private ELF echoes its exact declared SONAME. */
TEST(provider_component_admission, private_elf_echoes_exact_soname)
{
	staged_provider_artifacts artifacts;
	auto file_or = common::open_held_regular_file(artifacts.private_path, artifacts.fixture.file_policy());
	ASSERT_TRUE(file_or.is_ok()) << file_or.error().to_string();
	auto facts_or = inspect_provider_private_elf(file_or.value(), KINETUM_TEST_PROVIDER_PRIVATE_SONAME,
						     native_provider_target_tuple());
	ASSERT_TRUE(facts_or.is_ok()) << facts_or.error().to_string();
	EXPECT_EQ(facts_or->soname, KINETUM_TEST_PROVIDER_PRIVATE_SONAME);
}

/** @brief Prove a complete private dependency closure admits children first. */
TEST(provider_component_admission, complete_private_closure_is_proven_children_first)
{
	staged_provider_artifacts artifacts;
	auto proof_or = preflight(artifacts);
	ASSERT_TRUE(proof_or.is_ok()) << proof_or.error().to_string();
	ASSERT_EQ(proof_or->private_dependency_count(), 1u);
	EXPECT_EQ(proof_or->private_dependency_soname(0), KINETUM_TEST_PROVIDER_PRIVATE_SONAME);
	EXPECT_NE(proof_or->private_dependency_sha256(0), nullptr);
}

/** @brief Prove an undeclared private dependency fails preflight. */
TEST(provider_component_admission, undeclared_private_dependency_fails_preflight)
{
	staged_provider_artifacts artifacts;
	google::protobuf::RepeatedPtrField<PrivateProviderArtifact> no_private_artifacts;
	const auto result = preflight_provider_component(artifacts.fixture.artifact_directory(),
							 artifacts.component_record, no_private_artifacts,
							 native_provider_target_tuple(),
							 artifacts.fixture.file_policy());
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("undeclared private dependency"), std::string::npos);
}

/** @brief Prove authenticated dependency claims equal the component ELF set. */
TEST(provider_component_admission, authenticated_needed_set_must_equal_component_elf)
{
	staged_provider_artifacts artifacts;
	std::vector<std::string> retained;
	for (const auto &soname : artifacts.component_record.needed_sonames()) {
		if (soname != KINETUM_TEST_PROVIDER_PRIVATE_SONAME) {
			retained.push_back(soname);
		}
	}
	artifacts.component_record.clear_needed_sonames();
	for (auto &soname : retained) {
		artifacts.component_record.add_needed_sonames(std::move(soname));
	}
	const auto result = preflight(artifacts);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("DT_NEEDED set"), std::string::npos);
}

/** @brief Prove a private ELF rejects an incorrect SONAME claim. */
TEST(provider_component_admission, private_elf_rejects_wrong_soname_claim)
{
	staged_provider_artifacts artifacts;
	auto file_or = common::open_held_regular_file(artifacts.private_path, artifacts.fixture.file_policy());
	ASSERT_TRUE(file_or.is_ok()) << file_or.error().to_string();
	const auto result =
		inspect_provider_private_elf(file_or.value(), "libwrong.so", native_provider_target_tuple());
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("SONAME"), std::string::npos);
}

/** @brief Prove duplicate private SONAME ownership fails preflight. */
TEST(provider_component_admission, duplicate_private_soname_ownership_fails_preflight)
{
	staged_provider_artifacts artifacts;
	auto private_records = artifacts.private_records();
	private_records.Add()->CopyFrom(artifacts.private_record);
	const auto duplicate_result = preflight_provider_component(artifacts.fixture.artifact_directory(),
								   artifacts.component_record, private_records,
								   native_provider_target_tuple(),
								   artifacts.fixture.file_policy());
	ASSERT_FALSE(duplicate_result.is_ok());
	EXPECT_NE(duplicate_result.error().message().find("duplicate private SONAME"), std::string::npos);

	while (private_records.size() <= static_cast<int>(MAX_PROVIDER_PRIVATE_ARTIFACTS)) {
		private_records.Add()->CopyFrom(artifacts.private_record);
	}
	const auto bounded_result = preflight_provider_component(artifacts.fixture.artifact_directory(),
								 artifacts.component_record, private_records,
								 native_provider_target_tuple(),
								 artifacts.fixture.file_policy());
	ASSERT_FALSE(bounded_result.is_ok());
	EXPECT_EQ(bounded_result.error().code(), common::status_code::RESOURCE_EXHAUSTED);
}

/** @brief Prove a private dependency cycle fails before dynamic loading. */
TEST(provider_component_admission, private_dependency_cycle_fails_before_loading)
{
	staged_provider_artifacts artifacts;
	artifacts.private_record.add_needed_sonames(KINETUM_TEST_PROVIDER_PRIVATE_SONAME);
	std::sort(artifacts.private_record.mutable_needed_sonames()->begin(),
		  artifacts.private_record.mutable_needed_sonames()->end());
	const auto result = preflight(artifacts);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("cycle"), std::string::npos);
}

/** @brief Prove an empty component proof set is not an admission. */
TEST(provider_component_admission, empty_component_set_is_not_an_admission)
{
	std::vector<preflighted_provider_component> empty;
	const auto result = admit_preflighted_provider_components(std::move(empty));
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::INVALID_ARGUMENT);
}

/** @brief Prove duplicate component identity rejects before loading. */
TEST(provider_component_admission, duplicate_component_identity_rejects_before_loading)
{
	staged_provider_artifacts artifacts;
	auto first_or = preflight(artifacts);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().to_string();
	auto second_or = preflight(artifacts);
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().to_string();
	std::vector<preflighted_provider_component> proofs;
	proofs.push_back(std::move(first_or).value());
	proofs.push_back(std::move(second_or).value());
	const auto result = admit_preflighted_provider_components(std::move(proofs));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("duplicate component"), std::string::npos);
}

/** @brief Prove duplicate contract or component-file authority rejects before loading. */
TEST(provider_component_admission, duplicate_contract_and_component_file_authorities_reject_before_loading)
{
	{
		staged_provider_artifacts primary;
		staged_provider_artifacts secondary(KINETUM_TEST_PROVIDER_COMPONENT_SECOND_PATH,
						    TEST_SECOND_COMPONENT_ID, CPU_EXECUTION_TYPE_URL);
		secondary.component_record.set_contract_type_urls(0, ZERO_COPY_SHARE_TYPE_URL.data(),
								  ZERO_COPY_SHARE_TYPE_URL.size());
		auto first_or = preflight(primary);
		ASSERT_TRUE(first_or.is_ok()) << first_or.error().to_string();
		auto second_or = preflight(secondary);
		ASSERT_TRUE(second_or.is_ok()) << second_or.error().to_string();
		std::vector<preflighted_provider_component> proofs;
		proofs.push_back(std::move(first_or).value());
		proofs.push_back(std::move(second_or).value());
		const auto result = admit_preflighted_provider_components(std::move(proofs));
		ASSERT_FALSE(result.is_ok());
		EXPECT_NE(result.error().message().find("duplicate contract"), std::string::npos);
	}

	{
		staged_provider_artifacts primary;
		staged_provider_artifacts secondary(KINETUM_TEST_PROVIDER_COMPONENT_SECOND_PATH,
						    TEST_SECOND_COMPONENT_ID, CPU_EXECUTION_TYPE_URL);
		const auto same_name_path = secondary.fixture.stage_artifact(
			KINETUM_TEST_PROVIDER_COMPONENT_SECOND_PATH, primary.component_record.file_name());
		secondary.component_path = same_name_path;
		secondary.component_record = secondary.fixture.component_record(
			same_name_path, TEST_SECOND_COMPONENT_ID, {std::string(CPU_EXECUTION_TYPE_URL)});
		auto first_or = preflight(primary);
		ASSERT_TRUE(first_or.is_ok()) << first_or.error().to_string();
		auto second_or = preflight(secondary);
		ASSERT_TRUE(second_or.is_ok()) << second_or.error().to_string();
		std::vector<preflighted_provider_component> proofs;
		proofs.push_back(std::move(first_or).value());
		proofs.push_back(std::move(second_or).value());
		const auto result = admit_preflighted_provider_components(std::move(proofs));
		ASSERT_FALSE(result.is_ok());
		EXPECT_NE(result.error().message().find("artifact file identity"), std::string::npos);
	}
}

/** @brief Prove an exact component admits and its factory uses the held closure. */
TEST(provider_component_admission, exact_component_admits_and_factory_uses_private_closure)
{
	EXPECT_EXIT(admit_after_component_path_replacement(), ::testing::ExitedWithCode(0), "");

	staged_provider_artifacts artifacts;
	auto proof_or = preflight(artifacts);
	ASSERT_TRUE(proof_or.is_ok()) << proof_or.error().to_string();
	std::vector<preflighted_provider_component> proofs;
	proofs.push_back(std::move(proof_or).value());
	auto admitted_or = admit_preflighted_provider_components(std::move(proofs));
	ASSERT_TRUE(admitted_or.is_ok()) << admitted_or.error().to_string();
	ASSERT_EQ(admitted_or->component_count(), 1u);
	const auto *component = admitted_or->component_at(0);
	ASSERT_NE(component, nullptr);
	ASSERT_NE(component->descriptor, nullptr);
	EXPECT_EQ(component->component_id, TEST_COMPONENT_ID);
	ASSERT_EQ(component->descriptor->contract_count, 1u);
	expect_factory_uses_private_dependency(component->descriptor->contracts[0]);
}

/** @brief Prove a C++ component admits through the exact C provider ABI. */
TEST(provider_component_admission, cpp_component_admits_through_the_exact_c_abi)
{
	staged_provider_artifacts artifacts(KINETUM_TEST_PROVIDER_COMPONENT_CPP_PATH, TEST_CPP_COMPONENT_ID,
					    ZERO_COPY_SHARE_TYPE_URL);
	auto proof_or = preflight(artifacts);
	ASSERT_TRUE(proof_or.is_ok()) << proof_or.error().to_string();
	std::vector<preflighted_provider_component> proofs;
	proofs.push_back(std::move(proof_or).value());
	auto admitted_or = admit_preflighted_provider_components(std::move(proofs));
	ASSERT_TRUE(admitted_or.is_ok()) << admitted_or.error().to_string();
	ASSERT_EQ(admitted_or->component_count(), 1u);
	const auto *component = admitted_or->component_at(0);
	ASSERT_NE(component, nullptr);
	ASSERT_NE(component->descriptor, nullptr);
	EXPECT_EQ(component->component_id, TEST_CPP_COMPONENT_ID);
	ASSERT_EQ(component->descriptor->contract_count, 1u);
	expect_factory_uses_private_dependency(component->descriptor->contracts[0], TEST_CPP_OPERATION_MARKER);
}

/** @brief Prove a multi-contract component admits every exact declared row. */
TEST(provider_component_admission, multi_contract_component_admits_every_exact_row)
{
	staged_provider_artifacts artifacts(KINETUM_TEST_PROVIDER_COMPONENT_MULTI_PATH, TEST_MULTI_COMPONENT_ID,
					    std::vector<std::string>{std::string(CPU_EXECUTION_TYPE_URL),
								     std::string(ZERO_COPY_SHARE_TYPE_URL)});
	auto proof_or = preflight(artifacts);
	ASSERT_TRUE(proof_or.is_ok()) << proof_or.error().to_string();
	std::vector<preflighted_provider_component> proofs;
	proofs.push_back(std::move(proof_or).value());
	auto admitted_or = admit_preflighted_provider_components(std::move(proofs));
	ASSERT_TRUE(admitted_or.is_ok()) << admitted_or.error().to_string();
	ASSERT_EQ(admitted_or->component_count(), 1u);
	const auto *component = admitted_or->component_at(0);
	ASSERT_NE(component, nullptr);
	ASSERT_NE(component->descriptor, nullptr);
	EXPECT_EQ(component->component_id, TEST_MULTI_COMPONENT_ID);
	ASSERT_EQ(component->descriptor->contract_count, 2u);

	const auto &execution = component->descriptor->contracts[0];
	const auto &transition = component->descriptor->contracts[1];
	EXPECT_EQ(std::string_view(execution.type_url.data, execution.type_url.size), CPU_EXECUTION_TYPE_URL);
	EXPECT_EQ(execution.role, KINETUM_PROVIDER_ROLE_EXECUTION);
	EXPECT_EQ(std::string_view(transition.type_url.data, transition.type_url.size), ZERO_COPY_SHARE_TYPE_URL);
	EXPECT_EQ(transition.role, KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION);
	expect_factory_uses_private_dependency(execution);
	expect_factory_uses_private_dependency(transition, TEST_SECOND_OPERATION_MARKER);
}

/** @brief Prove shared private SONAME use requires one exact artifact identity. */
TEST(provider_component_admission, private_soname_sharing_requires_one_exact_artifact_identity)
{
	{
		staged_provider_artifacts primary;
		staged_provider_artifacts secondary(KINETUM_TEST_PROVIDER_COMPONENT_SECOND_PATH,
						    TEST_SECOND_COMPONENT_ID, CPU_EXECUTION_TYPE_URL);
		auto first_or = preflight(primary);
		ASSERT_TRUE(first_or.is_ok()) << first_or.error().to_string();
		auto second_or = preflight(secondary);
		ASSERT_TRUE(second_or.is_ok()) << second_or.error().to_string();
		std::vector<preflighted_provider_component> proofs;
		proofs.push_back(std::move(first_or).value());
		proofs.push_back(std::move(second_or).value());
		auto admitted_or = admit_preflighted_provider_components(std::move(proofs));
		ASSERT_TRUE(admitted_or.is_ok()) << admitted_or.error().to_string();
		ASSERT_EQ(admitted_or->component_count(), 2u);
		for (std::size_t index = 0; index < admitted_or->component_count(); ++index) {
			const auto *component = admitted_or->component_at(index);
			ASSERT_NE(component, nullptr);
			ASSERT_NE(component->descriptor, nullptr);
			ASSERT_EQ(component->descriptor->contract_count, 1u);
			expect_factory_uses_private_dependency(component->descriptor->contracts[0]);
		}
	}

	{
		staged_provider_artifacts primary;
		staged_provider_artifacts secondary(KINETUM_TEST_PROVIDER_COMPONENT_SECOND_PATH,
						    TEST_SECOND_COMPONENT_ID, CPU_EXECUTION_TYPE_URL);
		const std::filesystem::path private_source = KINETUM_TEST_PROVIDER_PRIVATE_PATH;
		secondary.private_path =
			secondary.fixture.stage_artifact(private_source, "libkinetum_test_provider_alias.so");
		secondary.private_record = secondary.fixture.private_artifact_record(
			secondary.private_path, KINETUM_TEST_PROVIDER_PRIVATE_SONAME);
		auto first_or = preflight(primary);
		ASSERT_TRUE(first_or.is_ok()) << first_or.error().to_string();
		auto second_or = preflight(secondary);
		ASSERT_TRUE(second_or.is_ok()) << second_or.error().to_string();
		std::vector<preflighted_provider_component> proofs;
		proofs.push_back(std::move(first_or).value());
		proofs.push_back(std::move(second_or).value());
		const auto result = admit_preflighted_provider_components(std::move(proofs));
		ASSERT_FALSE(result.is_ok());
		EXPECT_NE(result.error().message().find("private SONAME"), std::string::npos);
	}
}

/** @brief Prove an older component product version fails stop. */
TEST(provider_component_admission, older_component_product_version_fails_stop)
{
	EXPECT_DEATH(admit_mismatched_descriptor(KINETUM_TEST_PROVIDER_COMPONENT_OLDER_PATH, TEST_COMPONENT_ID,
						 ZERO_COPY_SHARE_TYPE_URL),
		     "");
}

/** @brief Prove a newer component product version fails stop. */
TEST(provider_component_admission, newer_component_product_version_fails_stop)
{
	EXPECT_DEATH(admit_mismatched_descriptor(KINETUM_TEST_PROVIDER_COMPONENT_NEWER_PATH, TEST_COMPONENT_ID,
						 ZERO_COPY_SHARE_TYPE_URL),
		     "");
}

/** @brief Prove a mismatched provider ABI identity fails stop. */
TEST(provider_component_admission, wrong_component_abi_identity_fails_stop)
{
	EXPECT_DEATH(admit_mismatched_descriptor(KINETUM_TEST_PROVIDER_COMPONENT_WRONG_ABI_PATH, TEST_COMPONENT_ID,
						 ZERO_COPY_SHARE_TYPE_URL),
		     "");
}

/** @brief Prove wrong role or nonzero padding fails stop. */
TEST(provider_component_admission, wrong_component_role_and_nonzero_padding_fail_stop)
{
	EXPECT_DEATH(admit_mismatched_descriptor(KINETUM_TEST_PROVIDER_COMPONENT_WRONG_ROLE_PATH, TEST_COMPONENT_ID,
						 ZERO_COPY_SHARE_TYPE_URL),
		     "");
	EXPECT_DEATH(admit_mismatched_descriptor(KINETUM_TEST_PROVIDER_PADDING_PATH, TEST_COMPONENT_ID,
						 ZERO_COPY_SHARE_TYPE_URL),
		     "");
}

/** @brief Prove descriptor and inventory component-ID disagreement fails stop. */
TEST(provider_component_admission, component_id_disagreement_fails_stop)
{
	EXPECT_DEATH(admit_mismatched_descriptor(KINETUM_TEST_PROVIDER_COMPONENT_PATH, "kinetum.test.different",
						 ZERO_COPY_SHARE_TYPE_URL),
		     "");
}

}  // namespace kinetum::provider
