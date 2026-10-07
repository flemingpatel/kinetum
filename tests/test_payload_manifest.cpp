// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_payload_manifest.cpp
 * @brief Exact installed-payload manifest verification tests.
 * @author Fleming Patel
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tooling/release/verification/payload_manifest.hpp"
#include "tooling/release/verification/runtime_verification.hpp"
#include "src/common/held_file.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"
#include "src/common/version.hpp"

namespace kinetum::release
{
namespace
{

namespace fs = std::filesystem;

/** Exact manifest path used by the representative payload fixture. */
constexpr std::string_view MANIFEST_PATH = "share/release/payload.sha256";

/** Exact sorted regular-file authority used by the representative fixture. */
constexpr std::array<std::string_view, 2> EXPECTED_PATHS = {
	"README.md",
	"bin/application",
};

/** Independently owned peer trees excluded from payload traversal. */
constexpr std::array<std::string_view, 2> EXCLUDED_ROOTS = {
	"dependencies",
	"sdk",
};

/** Paths whose distinct parents make the complete tree exceed 16,384 entries. */
constexpr std::size_t OVERBOUND_PATH_COUNT = 8'192;

/**
 * @brief Owner-controlled exact payload fixture.
 */
class PayloadManifestTest : public ::testing::Test {
    protected:
	/** @brief Construct one exact representative payload. */
	void SetUp() override
	{
		static std::atomic<uint64_t> sequence{0};
		root_ = fs::canonical(fs::temp_directory_path()) /
			("kinetum_payload_manifest_" + std::to_string(static_cast<uint64_t>(::getpid())) + "_" +
			 std::to_string(sequence.fetch_add(1, std::memory_order_relaxed)));
		ASSERT_TRUE(fs::create_directories(root_ / "bin"));
		ASSERT_TRUE(fs::create_directories(root_ / "share/release"));
		ASSERT_TRUE(fs::create_directories(root_ / "dependencies/dpdk"));
		ASSERT_TRUE(fs::create_directories(root_ / "sdk/include"));
		set_directory_modes();
		write_file("README.md", "runtime metadata\n", 0644);
		write_file("bin/application", "runtime executable\n", 0755);
		write_file("dependencies/dpdk/build_manifest.json", "build-only peer\n", 0644);
		write_file("sdk/include/customer.h", "peer package\n", 0644);
		write_valid_manifest();
	}

	/** @brief Remove the complete test-owned payload. */
	void TearDown() override
	{
		std::error_code ignored;
		if (!root_alias_.empty()) {
			fs::remove(root_alias_, ignored);
		}
		fs::remove_all(root_, ignored);
	}

	/** @return the current-owner held-file policy for this exact root. */
	[[nodiscard]] common::held_file_policy policy() const
	{
		constexpr uint32_t FORBIDDEN_MODE_BITS = S_IWGRP | S_IWOTH;
		const auto owner = static_cast<uint32_t>(::geteuid());
		return common::held_file_policy{
			.required_owner_uid = owner,
			.forbidden_mode_bits = FORBIDDEN_MODE_BITS,
			.require_single_link = true,
			.directories =
				common::held_directory_policy{
					.root = root_,
					.required_owner_uid = owner,
					.forbidden_mode_bits = FORBIDDEN_MODE_BITS,
				},
			.maximum_size_bytes = std::nullopt,
		};
	}

	/** @return the exact verifier contract for the representative tree. */
	[[nodiscard]] static payload_manifest_contract contract()
	{
		return payload_manifest_contract{
			.manifest_relative_path = MANIFEST_PATH,
			.expected_relative_paths = EXPECTED_PATHS,
			.excluded_directory_roots = EXCLUDED_ROOTS,
		};
	}

	/**
	 * @brief Write one fixture file and assign its intended mode.
	 * @param relative Path beneath the fixture root.
	 * @param bytes Complete intended contents.
	 * @param mode Exact file permissions.
	 */
	void write_file(std::string_view relative, std::string_view bytes, mode_t mode)
	{
		const fs::path path = root_ / relative;
		fs::create_directories(path.parent_path());
		std::ofstream output(path, std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(output.is_open());
		output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
		output.close();
		ASSERT_EQ(::chmod(path.c_str(), mode), 0);
		set_directory_modes();
	}

	/** @brief Restore exact non-writable modes on every fixture directory. */
	void set_directory_modes()
	{
		ASSERT_EQ(::chmod(root_.c_str(), 0755), 0);
		for (const auto &entry : fs::recursive_directory_iterator(root_)) {
			if (entry.is_directory()) {
				ASSERT_EQ(::chmod(entry.path().c_str(), 0755), 0);
			}
		}
	}

	/** @brief Emit the exact deterministic manifest for current fixture bytes. */
	void write_valid_manifest()
	{
		std::string rows;
		for (const auto relative : EXPECTED_PATHS) {
			auto digest_or = common::sha256_file_hex((root_ / relative).string());
			ASSERT_TRUE(digest_or.is_ok()) << digest_or.error().message();
			rows += digest_or.value();
			rows += "  ";
			rows += relative;
			rows += '\n';
		}
		write_file(MANIFEST_PATH, rows, 0644);
	}

	fs::path root_;	       ///< Exact test-owned payload root.
	fs::path root_alias_;  ///< Test-owned indirect spelling of the payload root.
};

/** @brief Prove a complete manifest admits while ignoring only an explicit peer tree. */
TEST_F(PayloadManifestTest, exact_manifest_admits_complete_owned_tree)
{
	const auto result = verify_payload_manifest(root_, contract(), policy());
	EXPECT_TRUE(result.is_ok()) << result.to_string();
}

/** @brief Installed peers are permitted only by the installed-runtime verification entrance. */
TEST_F(PayloadManifestTest, runtime_packages_do_not_admit_installed_peer_domains)
{
	const auto candidate = root_ / "runtime_scope";
	// Populate the required file domain to isolate the literal peer-disposition
	// expectations below. These bytes intentionally do not claim valid provider provenance.
	for (const auto &artifact : expected_runtime_artifacts()) {
		write_file("runtime_scope/" + std::string(artifact.relative_path), "payload fixture\n", 0644);
	}
	write_file("runtime_scope/VERSION", std::string(common::KINETUM_VERSION_STRING) + "\n", 0644);
	ASSERT_TRUE(generate_payload_manifest(candidate, RUNTIME_PAYLOAD_MANIFEST, policy()).is_ok());
	const auto target = provider::native_provider_target_tuple();
	const auto baseline = verify_runtime_payload(candidate, target, policy());
	ASSERT_TRUE(baseline.payload.is_ok()) << baseline.payload.to_string();
	EXPECT_FALSE(baseline.provider.is_ok());
	for (const std::string_view peer : {"sdk", "dependencies"}) {
		write_file("runtime_scope/" + std::string(peer) + "/independent", "peer-owned\n", 0644);
		const auto packaged = verify_runtime_payload(candidate, target, policy());
		EXPECT_EQ(packaged.payload.code(), common::status_code::DATA_LOSS);
		const auto installed = verify_installed_runtime(candidate, target, policy());
		EXPECT_TRUE(installed.payload.is_ok()) << installed.payload.to_string();
		EXPECT_FALSE(installed.provider.is_ok());
		ASSERT_GT(fs::remove_all(candidate / peer), 0u);
	}
	write_file("runtime_scope/unknown/independent", "unowned\n", 0644);
	EXPECT_EQ(verify_runtime_payload(candidate, target, policy()).payload.code(), common::status_code::DATA_LOSS);
	EXPECT_EQ(verify_installed_runtime(candidate, target, policy()).payload.code(), common::status_code::DATA_LOSS);
}

/** @brief Prove malformed, noncanonical, and nonexact rows fail before success. */
TEST_F(PayloadManifestTest, malformed_or_reordered_rows_fail_closed)
{
	write_file(MANIFEST_PATH, std::string(64, 'A') + "  README.md\n", 0644);
	auto malformed = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(malformed.is_ok());
	EXPECT_EQ(malformed.code(), common::status_code::DATA_LOSS);

	auto first_or = common::sha256_file_hex((root_ / EXPECTED_PATHS[0]).string());
	auto second_or = common::sha256_file_hex((root_ / EXPECTED_PATHS[1]).string());
	ASSERT_TRUE(first_or.is_ok());
	ASSERT_TRUE(second_or.is_ok());
	write_file(MANIFEST_PATH, second_or.value() + "  bin/application\n" + first_or.value() + "  README.md\n", 0644);
	auto reordered = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(reordered.is_ok());
	EXPECT_EQ(reordered.code(), common::status_code::DATA_LOSS);

	write_file(MANIFEST_PATH, first_or.value() + "  ../README.md\n", 0644);
	auto unsafe = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(unsafe.is_ok());
	EXPECT_EQ(unsafe.code(), common::status_code::DATA_LOSS);

	const std::string valid = first_or.value() + "  README.md\n" + second_or.value() + "  bin/application\n";
	for (const std::string_view separator :
	     std::array<std::string_view, 3>{" ", "\t\t", std::string_view("\0  ", 3)}) {
		const std::string malformed_rows = first_or.value() + std::string(separator) + "README.md\n" +
						   second_or.value() + std::string(separator) + "bin/application\n";
		write_file(MANIFEST_PATH, malformed_rows, 0644);
		EXPECT_EQ(verify_payload_manifest(root_, contract(), policy()).code(), common::status_code::DATA_LOSS);
	}
	write_file(MANIFEST_PATH, valid.substr(0, valid.size() - 1u), 0644);
	EXPECT_EQ(verify_payload_manifest(root_, contract(), policy()).code(), common::status_code::DATA_LOSS);
}

/** @brief Prove missing, changed, and extra files remain distinguishable failures. */
TEST_F(PayloadManifestTest, membership_and_hash_disagreement_fail_closed)
{
	write_file("bin/application", "changed bytes\n", 0755);
	auto changed = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(changed.is_ok());
	EXPECT_EQ(changed.code(), common::status_code::DATA_LOSS);

	write_file("bin/application", "runtime executable\n", 0755);
	write_file("bin/extra", "unexpected\n", 0755);
	auto extra = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(extra.is_ok());
	EXPECT_EQ(extra.code(), common::status_code::DATA_LOSS);

	ASSERT_TRUE(fs::remove(root_ / "bin/extra"));
	write_file("dependencies-old/ignored", "must remain runtime-owned\n", 0644);
	auto lookalike = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(lookalike.is_ok());
	EXPECT_EQ(lookalike.code(), common::status_code::DATA_LOSS);
	ASSERT_GT(fs::remove_all(root_ / "dependencies-old"), 0u);

	ASSERT_TRUE(fs::remove(root_ / "README.md"));
	auto missing = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(missing.is_ok());
	EXPECT_EQ(missing.code(), common::status_code::DATA_LOSS);
}

/** @brief Prove indirect or multiply linked bytes cannot satisfy a manifest row. */
TEST_F(PayloadManifestTest, symbolic_and_hard_linked_payloads_fail_closed)
{
	root_alias_ = root_.parent_path() / (root_.filename().string() + "_alias");
	fs::create_directory_symlink(root_, root_alias_);
	write_file("bin/unexpected", "must not be scanned through an alias\n", 0644);
	auto alias_policy = policy();
	ASSERT_TRUE(alias_policy.directories.has_value());
	alias_policy.directories->root = root_alias_;
	auto root_alias = verify_payload_manifest(root_alias_, contract(), alias_policy);
	ASSERT_FALSE(root_alias.is_ok());
	EXPECT_EQ(root_alias.code(), common::status_code::FAILED_PRECONDITION);
	ASSERT_TRUE(fs::remove(root_ / "bin/unexpected"));
	ASSERT_TRUE(fs::remove(root_alias_));
	root_alias_.clear();

	ASSERT_GT(fs::remove_all(root_ / "dependencies"), 0u);
	fs::create_directory_symlink("sdk", root_ / "dependencies");
	auto indirect_peer = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(indirect_peer.is_ok());
	EXPECT_EQ(indirect_peer.code(), common::status_code::DATA_LOSS);
	ASSERT_TRUE(fs::remove(root_ / "dependencies"));

	ASSERT_TRUE(fs::remove(root_ / "README.md"));
	fs::create_symlink("bin/application", root_ / "README.md");
	auto linked = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(linked.is_ok());
	EXPECT_EQ(linked.code(), common::status_code::DATA_LOSS);

	ASSERT_TRUE(fs::remove(root_ / "README.md"));
	write_file("README.md", "runtime metadata\n", 0644);
	fs::create_hard_link(root_ / "README.md", root_ / "sdk/retained-copy");
	auto multiply_linked = verify_payload_manifest(root_, contract(), policy());
	ASSERT_FALSE(multiply_linked.is_ok());
	EXPECT_EQ(multiply_linked.code(), common::status_code::FAILED_PRECONDITION);
}

/** @brief Prove contract paths must be exact, sorted, and non-overlapping. */
TEST_F(PayloadManifestTest, verifier_contract_rejects_aliases_and_domain_overlap)
{
	constexpr std::array<std::string_view, 2> REORDERED = {
		"bin/application",
		"README.md",
	};
	auto reordered_contract = contract();
	reordered_contract.expected_relative_paths = REORDERED;
	auto reordered = verify_payload_manifest(root_, reordered_contract, policy());
	ASSERT_FALSE(reordered.is_ok());
	EXPECT_EQ(reordered.code(), common::status_code::INVALID_ARGUMENT);

	constexpr std::array<std::string_view, 1> NESTED_EXCLUSION = {"sdk/include"};
	auto nested_contract = contract();
	nested_contract.excluded_directory_roots = NESTED_EXCLUSION;
	auto nested = verify_payload_manifest(root_, nested_contract, policy());
	ASSERT_FALSE(nested.is_ok());
	EXPECT_EQ(nested.code(), common::status_code::INVALID_ARGUMENT);

	constexpr std::array<std::string_view, 1> OVERLAPPING = {"bin"};
	auto overlapping_contract = contract();
	overlapping_contract.excluded_directory_roots = OVERLAPPING;
	auto overlapping = verify_payload_manifest(root_, overlapping_contract, policy());
	ASSERT_FALSE(overlapping.is_ok());
	EXPECT_EQ(overlapping.code(), common::status_code::INVALID_ARGUMENT);

	std::vector<std::string> overbound_path_storage;
	overbound_path_storage.reserve(OVERBOUND_PATH_COUNT);
	for (std::size_t index = 0; index < OVERBOUND_PATH_COUNT; ++index) {
		std::string ordinal = std::to_string(index);
		std::string path = "d";
		path.append(4 - ordinal.size(), '0');
		path += ordinal;
		path += "/payload";
		overbound_path_storage.push_back(std::move(path));
	}
	std::vector<std::string_view> overbound_paths;
	overbound_paths.reserve(overbound_path_storage.size());
	for (const auto &path : overbound_path_storage) {
		overbound_paths.emplace_back(path);
	}
	auto overbound_contract = contract();
	overbound_contract.expected_relative_paths = overbound_paths;
	auto overbound = verify_payload_manifest(root_, overbound_contract, policy());
	ASSERT_FALSE(overbound.is_ok());
	EXPECT_EQ(overbound.code(), common::status_code::RESOURCE_EXHAUSTED);
}

/** @brief Generation and installation read share exact rows with independently pinned digests. */
TEST_F(PayloadManifestTest, generated_manifest_is_exact_and_returns_the_complete_copy_set)
{
	write_file("candidate/A.md", "abc", 0644);
	write_file("candidate/bin/application", "", 0755);
	fs::create_directories(root_ / "candidate/share/release");
	set_directory_modes();
	const fs::path candidate = root_ / "candidate";
	const auto generated = generate_payload_manifest(candidate, MANIFEST_PATH, policy());
	ASSERT_TRUE(generated.is_ok()) << generated.to_string();
	std::ifstream input(candidate / MANIFEST_PATH, std::ios::binary);
	ASSERT_TRUE(input.is_open());
	const std::string bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	EXPECT_EQ(bytes, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  A.md\n"
			 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  bin/application\n");
	auto files = read_verified_payload(candidate, MANIFEST_PATH, policy());
	ASSERT_TRUE(files.is_ok()) << files.error().to_string();
	ASSERT_EQ(files->size(), 3u);
	EXPECT_EQ(files->at(0).relative_path, "A.md");
	EXPECT_EQ(files->at(0).identity.size_bytes, 3u);
	EXPECT_EQ(files->at(0).mode, 0644u);
	EXPECT_EQ(files->at(1).relative_path, "bin/application");
	EXPECT_EQ(files->at(1).identity.size_bytes, 0u);
	EXPECT_EQ(files->at(1).mode, 0755u);
	EXPECT_EQ(files->at(2).relative_path, MANIFEST_PATH);
	EXPECT_EQ(files->at(2).identity.size_bytes, bytes.size());

	const auto repeated = generate_payload_manifest(candidate, MANIFEST_PATH, policy());
	EXPECT_EQ(repeated.code(), common::status_code::ALREADY_EXISTS);
	write_file("candidate/A.md", "changed", 0644);
	const auto changed = read_verified_payload(candidate, MANIFEST_PATH, policy());
	ASSERT_FALSE(changed.is_ok());
	EXPECT_EQ(changed.error().code(), common::status_code::DATA_LOSS);
}

/** @brief An unowned empty directory cannot enter a generated package manifest. */
TEST_F(PayloadManifestTest, generation_rejects_unbound_directories_before_publication)
{
	write_file("candidate/A.md", "abc", 0644);
	fs::create_directories(root_ / "candidate/share/release");
	fs::create_directories(root_ / "candidate/unbound");
	set_directory_modes();
	const auto result = generate_payload_manifest(root_ / "candidate", MANIFEST_PATH, policy());
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.code(), common::status_code::DATA_LOSS);
	EXPECT_FALSE(fs::exists(root_ / "candidate" / MANIFEST_PATH));
}

/** @brief One generator/reader path grammar owns traversal and inclusive length limits. */
TEST_F(PayloadManifestTest, generation_requires_exact_paths_and_inclusive_file_bounds)
{
	write_file("candidate/A.md", "abc", 0644);
	fs::create_directories(root_ / "candidate/share/release");
	set_directory_modes();
	const auto candidate = root_ / "candidate";
	EXPECT_EQ(generate_payload_manifest("relative", MANIFEST_PATH, policy()).code(),
		  common::status_code::INVALID_ARGUMENT);
	for (const std::string_view path : {"/manifest", "../manifest", "a//b", "a/./b", "a/b/..", "a\\b", "a b"}) {
		EXPECT_EQ(generate_payload_manifest(candidate, path, policy()).code(),
			  common::status_code::INVALID_ARGUMENT);
	}
	EXPECT_TRUE(validate_payload_path(std::string(MAX_PAYLOAD_PATH_BYTES, 'a')).is_ok());
	EXPECT_FALSE(validate_payload_path(std::string(MAX_PAYLOAD_PATH_BYTES + 1u, 'a')).is_ok());
	auto limited = policy();
	limited.maximum_size_bytes = 2u;
	EXPECT_EQ(generate_payload_manifest(candidate, MANIFEST_PATH, limited).code(),
		  common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_FALSE(fs::exists(candidate / MANIFEST_PATH));
	limited.maximum_size_bytes = 3u;
	ASSERT_TRUE(generate_payload_manifest(candidate, MANIFEST_PATH, limited).is_ok());
	ASSERT_TRUE(fs::remove(candidate / MANIFEST_PATH));
	fs::resize_file(candidate / "A.md", MAX_PAYLOAD_FILE_BYTES + 1u);
	EXPECT_EQ(generate_payload_manifest(candidate, MANIFEST_PATH, policy()).code(),
		  common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_FALSE(fs::exists(candidate / MANIFEST_PATH));
}

/** @brief A staged link, FIFO, or mutable owner mode never reaches manifest publication. */
TEST_F(PayloadManifestTest, generation_rejects_indirect_special_and_unprotected_files)
{
	write_file("candidate/A.md", "abc", 0644);
	fs::create_directories(root_ / "candidate/share/release");
	set_directory_modes();
	const auto candidate = root_ / "candidate";
	const auto extra = candidate / "extra";
	fs::create_symlink("A.md", extra);
	EXPECT_EQ(generate_payload_manifest(candidate, MANIFEST_PATH, policy()).code(), common::status_code::DATA_LOSS);
	ASSERT_TRUE(fs::remove(extra));
	fs::create_hard_link(candidate / "A.md", extra);
	EXPECT_EQ(generate_payload_manifest(candidate, MANIFEST_PATH, policy()).code(),
		  common::status_code::FAILED_PRECONDITION);
	ASSERT_TRUE(fs::remove(extra));
	ASSERT_EQ(::mkfifo(extra.c_str(), 0600), 0);
	EXPECT_EQ(generate_payload_manifest(candidate, MANIFEST_PATH, policy()).code(), common::status_code::DATA_LOSS);
	ASSERT_TRUE(fs::remove(extra));
	ASSERT_EQ(::chmod((candidate / "A.md").c_str(), 0664), 0);
	EXPECT_EQ(generate_payload_manifest(candidate, MANIFEST_PATH, policy()).code(),
		  common::status_code::PERMISSION_DENIED);
	EXPECT_FALSE(fs::exists(candidate / MANIFEST_PATH));
}

/** @brief Staged headers and examples preserve complete source byte sets. */
TEST_F(PayloadManifestTest, staged_trees_are_exact_source_byte_projections)
{
	write_file("source/README.md", "module example\n", 0644);
	write_file("source/api/header.h", "void api(void);\n", 0644);
	write_file("stage/README.md", "module example\n", 0644);
	write_file("stage/api/header.h", "void api(void);\n", 0644);
	const auto source = root_ / "source";
	const auto stage = root_ / "stage";
	ASSERT_TRUE(verify_payload_projection(source, stage, policy(), policy()).is_ok());
	write_file("stage/extra.hpp", "extra\n", 0644);
	EXPECT_EQ(verify_payload_projection(source, stage, policy(), policy()).code(), common::status_code::DATA_LOSS);
	ASSERT_TRUE(fs::remove(stage / "extra.hpp"));
	write_file("stage/README.md", "changed\n", 0644);
	EXPECT_EQ(verify_payload_projection(source, stage, policy(), policy()).code(), common::status_code::DATA_LOSS);
	write_file("stage/README.md", "module example\n", 0644);
	ASSERT_TRUE(fs::remove(stage / "api/header.h"));
	EXPECT_FALSE(verify_payload_projection(source, stage, policy(), policy()).is_ok());
	EXPECT_EQ(verify_payload_projection(source, source, policy(), policy()).code(),
		  common::status_code::INVALID_ARGUMENT);
}

}  // namespace
}  // namespace kinetum::release
