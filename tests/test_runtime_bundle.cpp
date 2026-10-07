// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_runtime_bundle.cpp
 * @brief Failure-oriented tests for canonical runtime-bundle admission.
 * @author Fleming Patel
 *
 * The suite proves that manifest integrity, canonical artifact paths, symlink
 * rejection, deployment-plan identity, exact module-set admission, snapshot
 * normalization, and producer/consumer fixed-point behavior are one shared
 * startup contract. Low-level manifest grammar coverage remains in
 * test_bundle_manifest.cpp.
 */

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/execution/cpu/v1/cpu_execution.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/file_io.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/sha256.hpp"
#include "src/common/version.hpp"
#include "src/pack/bundle_manifest.hpp"
#include "src/pack/runtime_bundle.hpp"
#include "src/provider/deployment_plan_identity.hpp"
#include "src/gluon/gluon_planner.hpp"
#include "tests/gluon_test_deployment.hpp"

namespace kinetum::pack
{

namespace
{

namespace fs = std::filesystem;

using kinetum::control::v1::ConfigSnapshot;
using kinetum::gluon::v1::DeploymentPlan;

/** Context-memory authority supplied to module-bearing fixtures. */
constexpr uint64_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = 2u * 1024u * 1024u;
/** Epoch-arena authority supplied to module-bearing fixtures. */
constexpr uint64_t TEST_EPOCH_ARENA_CAPACITY_BYTES = 2u * 1024u * 1024u;

/**
 * @brief Fixture owning one isolated runtime-bundle directory per test.
 */
class RuntimeBundleTest : public ::testing::Test {
    protected:
	/** @brief Create one fresh private test directory. */
	void SetUp() override
	{
		std::string pattern = (fs::temp_directory_path() / "kinetum_runtime_bundle.XXXXXX").string();
		char *created = ::mkdtemp(pattern.data());
		ASSERT_NE(created, nullptr);
		root_ = created;
	}

	/** @brief Remove every filesystem object created by the test. */
	void TearDown() override
	{
		if (!root_.empty()) {
			std::error_code error;
			fs::remove_all(root_, error);
		}
	}

	/**
	 * @brief Construct a complete unhashed provider plan with an explicit module set.
	 *
	 * @param module_ids Module IDs in contractual pipeline order.
	 * @return Complete deployment plan suitable for bundle semantic tests.
	 * @throws std::runtime_error If production planning rejects the fixture.
	 */
	static DeploymentPlan make_unhashed_plan(const std::vector<std::string> &module_ids)
	{
		kinetum::axiom::v1::Pipeline pipeline;
		pipeline.set_pipeline_id("runtime_bundle_pipeline");
		auto *rx = pipeline.add_stages();
		rx->set_stage_id("rx");
		rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
		rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		rx->mutable_io()->set_interface("ingress");

		std::string predecessor = "rx";
		for (std::size_t index = 0; index < module_ids.size(); ++index) {
			auto *stage = pipeline.add_stages();
			stage->set_stage_id("module_stage_" + std::to_string(index));
			stage->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
			stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
			stage->mutable_module()->set_module_id(module_ids[index]);
			stage->mutable_module()->set_context_selection(
				kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
			auto *edge = pipeline.add_edges();
			edge->set_from_stage_id(predecessor);
			edge->set_to_stage_id(stage->stage_id());
			edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
			predecessor = stage->stage_id();
		}
		auto *tx = pipeline.add_stages();
		tx->set_stage_id("tx");
		tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
		tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		tx->mutable_io()->set_interface("egress");
		auto *tx_edge = pipeline.add_edges();
		tx_edge->set_from_stage_id(predecessor);
		tx_edge->set_to_stage_id("tx");
		tx_edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

		kinetum::hw::v1::HardwareInventory hardware;
		auto *cpu = hardware.mutable_node()->mutable_cpu();
		for (int32_t core_id = 0; core_id < 4; ++core_id) {
			auto *core = cpu->add_core_topology();
			core->set_core_id(core_id);
			core->set_numa_node(0);
			core->set_is_hyperthread(false);
		}

		kinetum::gluon::planner_options options;
		options.regions = 1;
		options.deployment_bindings = kinetum::test::make_udp_test_deployment_bindings(
			pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES, TEST_EPOCH_ARENA_CAPACITY_BYTES);
		auto planned_or = kinetum::gluon::plan(pipeline, hardware, options);
		if (!planned_or.is_ok()) {
			std::string diagnostic = "runtime-bundle fixture planning failed: ";
			diagnostic.append(planned_or.error().message());
			throw std::runtime_error(diagnostic);
		}
		auto plan = std::move(planned_or).value();
		plan.clear_content_hash();
		return plan;
	}

	/**
	 * @brief Construct a minimal plan with its exact canonical hash claim.
	 *
	 * @param module_ids Module IDs in contractual pipeline order.
	 * @return Deployment plan carrying a valid required content_hash.
	 * @throws std::runtime_error If planning or canonical identity construction fails.
	 */
	static DeploymentPlan make_plan(const std::vector<std::string> &module_ids)
	{
		auto plan = make_unhashed_plan(module_ids);
		auto hash_or = kinetum::provider::compute_deployment_plan_content_hash(plan);
		if (!hash_or.is_ok()) {
			std::string diagnostic = "runtime-bundle fixture identity failed: ";
			diagnostic.append(hash_or.error().message());
			throw std::runtime_error(diagnostic);
		}
		plan.set_content_hash(hash_or.value());
		return plan;
	}

	/**
	 * @brief Construct a complete snapshot with caller-selected module order.
	 *
	 * @param module_ids Module IDs to emit into the snapshot.
	 * @return Snapshot with stable opaque blobs and no supplied hash claims.
	 */
	static ConfigSnapshot make_snapshot(const std::vector<std::string> &module_ids)
	{
		ConfigSnapshot snapshot;
		snapshot.set_snapshot_id("runtime_bundle_snapshot");
		snapshot.set_revision(1);
		for (const auto &module_id : module_ids) {
			auto *module = snapshot.add_modules();
			module->set_module_id(module_id);
			module->set_revision(1);
			module->set_config_blob("opaque:" + module_id);
			module->set_content_type("application/octet-stream");
		}
		return snapshot;
	}

	/**
	 * @brief Return the canonical plan artifact path under the fixture root.
	 *
	 * @return Exact plan filesystem path.
	 */
	[[nodiscard]] fs::path plan_path() const
	{
		return root_ / std::string(RUNTIME_PLAN_RELATIVE_PATH);
	}

	/**
	 * @brief Return the canonical bootstrap artifact path under the fixture root.
	 *
	 * @return Exact bootstrap-snapshot filesystem path.
	 */
	[[nodiscard]] fs::path snapshot_path() const
	{
		return root_ / std::string(BOOTSTRAP_SNAPSHOT_RELATIVE_PATH);
	}

	/**
	 * @brief Write exact bytes after creating their parent directory.
	 *
	 * @param path Destination file path.
	 * @param bytes Exact bytes to write.
	 */
	static void write_text(const fs::path &path, const std::string &bytes)
	{
		std::error_code ec;
		fs::create_directories(path.parent_path(), ec);
		ASSERT_FALSE(ec) << ec.message();
		const auto write_status = kinetum::common::write_string_to_file(path, bytes);
		ASSERT_TRUE(write_status.is_ok()) << write_status.message();
	}

	/**
	 * @brief Write one protobuf message as human-readable text.
	 *
	 * @param path Destination protobuf-text path.
	 * @param message Message to serialize.
	 */
	static void write_message(const fs::path &path, const google::protobuf::Message &message)
	{
		std::error_code ec;
		fs::create_directories(path.parent_path(), ec);
		ASSERT_FALSE(ec) << ec.message();
		const auto write_status = kinetum::common::write_pbtxt_file(path.string(), message);
		ASSERT_TRUE(write_status.is_ok()) << write_status.message();
	}

	/**
	 * @brief Stage every plan-owned module image at its canonical bundle path.
	 *
	 * @param plan Exact plan whose module set owns the required image paths.
	 */
	void write_module_images(const DeploymentPlan &plan)
	{
		for (const auto &stage : plan.pipeline().stages()) {
			if (stage.kind() != kinetum::axiom::v1::STAGE_KIND_MODULE) {
				continue;
			}
			ASSERT_TRUE(stage.has_module());
			const std::string &module_id = stage.module().module_id();
			ASSERT_FALSE(module_id.empty());
			write_text(root_ / "modules" / (module_id + ".so"), "fixture module image:" + module_id + "\n");
		}
	}

	/** @brief Generate and write a manifest for the fixture's current files. */
	void write_manifest()
	{
		auto manifest_or = generate_manifest_text(root_.string());
		ASSERT_TRUE(manifest_or.is_ok()) << manifest_or.error().message();
		write_text(root_ / std::string(MANIFEST_FILENAME), manifest_or.value());
	}

	/**
	 * @brief Replace the fixture with one complete valid runtime bundle.
	 *
	 * @param plan Plan to write at the canonical path.
	 * @param snapshot Snapshot to write at the canonical path.
	 */
	void write_bundle(const DeploymentPlan &plan, const ConfigSnapshot &snapshot)
	{
		std::error_code ec;
		fs::remove_all(root_, ec);
		ASSERT_FALSE(ec) << ec.message();
		fs::create_directories(root_, ec);
		ASSERT_FALSE(ec) << ec.message();
		write_message(plan_path(), plan);
		write_message(snapshot_path(), snapshot);
		write_module_images(plan);
		write_manifest();
	}

	fs::path root_;	 ///< Fixture-owned bundle root.
};

/** @brief Verify an explicit module-free snapshot remains a real required input. */
TEST_F(RuntimeBundleTest, normalizer_accepts_explicit_module_free_snapshot)
{
	const auto plan = make_plan({});
	write_message(snapshot_path(), make_snapshot({}));

	auto normalized_or = load_and_normalize_bootstrap_snapshot(snapshot_path().string(), plan);
	ASSERT_TRUE(normalized_or.is_ok()) << normalized_or.error().message();
	EXPECT_EQ(normalized_or.value().snapshot.modules_size(), 0);
	EXPECT_FALSE(normalized_or.value().snapshot.content_hash().empty());
}

/** @brief Verify normalization sorts modules and materializes exact hash claims. */
TEST_F(RuntimeBundleTest, normalizer_canonicalizes_module_order_and_hash_claims)
{
	const auto plan = make_plan({"module.alpha", "module.beta"});
	write_message(snapshot_path(), make_snapshot({"module.beta", "module.alpha"}));

	auto normalized_or = load_and_normalize_bootstrap_snapshot(snapshot_path().string(), plan);
	ASSERT_TRUE(normalized_or.is_ok()) << normalized_or.error().message();
	const auto &normalized = normalized_or.value();
	ASSERT_EQ(normalized.snapshot.modules_size(), 2);
	EXPECT_EQ(normalized.snapshot.modules(0).module_id(), "module.alpha");
	EXPECT_EQ(normalized.snapshot.modules(1).module_id(), "module.beta");
	EXPECT_EQ(normalized.snapshot.content_hash(),
		  kinetum::common::bytes_to_hex(normalized.validation_hash.data(), normalized.validation_hash.size()));
	EXPECT_FALSE(normalized.snapshot.modules(0).content_hash().empty());
	EXPECT_FALSE(normalized.snapshot.modules(1).content_hash().empty());
}

/** @brief Verify one valid bundle returns owned messages and canonical paths. */
TEST_F(RuntimeBundleTest, valid_bundle_returns_canonical_artifacts)
{
	const auto plan = make_plan({"module.alpha"});
	write_bundle(plan, make_snapshot({"module.alpha"}));

	auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_TRUE(verified_or.is_ok()) << verified_or.error().message() << ": " << verified_or.error().details();
	const auto &verified = verified_or.value();
	EXPECT_TRUE(fs::path(verified.bundle_root).is_absolute());
	EXPECT_EQ(fs::path(verified.plan_path), fs::absolute(plan_path()).lexically_normal());
	EXPECT_EQ(fs::path(verified.bootstrap_snapshot_path), fs::absolute(snapshot_path()).lexically_normal());
	EXPECT_EQ(verified.plan.plan_id(), plan.plan_id());
	EXPECT_EQ(verified.bootstrap_snapshot.snapshot_id(), "runtime_bundle_snapshot");
}

/** @brief Verify normalization remains byte-stable across producer/consumer admission. */
TEST_F(RuntimeBundleTest, normalization_is_fixed_point_across_verification)
{
	const auto plan = make_plan({"module.alpha", "module.beta"});
	write_message(snapshot_path(), make_snapshot({"module.beta", "module.alpha"}));
	auto first_or = load_and_normalize_bootstrap_snapshot(snapshot_path().string(), plan);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	write_bundle(plan, first_or.value().snapshot);

	auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_TRUE(verified_or.is_ok()) << verified_or.error().message();
	auto second_or = kinetum::common::canonicalize_config_snapshot(verified_or.value().bootstrap_snapshot, plan);
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto first_canonical_or = kinetum::common::canonicalize_config_snapshot(first_or.value().snapshot, plan);
	ASSERT_TRUE(first_canonical_or.is_ok()) << first_canonical_or.error().message();
	EXPECT_EQ(second_or.value().serialized_bytes, first_canonical_or.value().serialized_bytes);
	EXPECT_EQ(second_or.value().validation_hash, first_or.value().validation_hash);
}

/** @brief Verify a directory without a manifest is not a runtime bundle. */
TEST_F(RuntimeBundleTest, rejects_missing_manifest)
{
	write_message(plan_path(), make_plan({}));
	write_message(snapshot_path(), make_snapshot({}));
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_EQ(verified_or.error().code(), kinetum::common::status_code::NOT_FOUND);
}

/** @brief Verify an otherwise valid manifest cannot omit the canonical plan. */
TEST_F(RuntimeBundleTest, rejects_missing_canonical_plan)
{
	write_message(snapshot_path(), make_snapshot({}));
	write_manifest();
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_NE(verified_or.error().details().find(RUNTIME_PLAN_RELATIVE_PATH), std::string::npos);
}

/** @brief Verify an otherwise valid manifest cannot omit the bootstrap snapshot. */
TEST_F(RuntimeBundleTest, rejects_missing_canonical_bootstrap_snapshot)
{
	write_message(plan_path(), make_plan({}));
	write_manifest();
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_NE(verified_or.error().details().find(BOOTSTRAP_SNAPSHOT_RELATIVE_PATH), std::string::npos);
}

/** @brief Verify semantically similar artifacts at alternate paths do not satisfy admission. */
TEST_F(RuntimeBundleTest, rejects_alternate_artifact_paths)
{
	write_message(root_ / "configs/deployment_plan.pbtxt", make_plan({}));
	write_message(snapshot_path(), make_snapshot({}));
	write_manifest();
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_NE(verified_or.error().details().find(RUNTIME_PLAN_RELATIVE_PATH), std::string::npos);
}

/** @brief Verify manifest integrity cannot make malformed plan text executable. */
TEST_F(RuntimeBundleTest, rejects_malformed_plan_pbtxt)
{
	write_text(plan_path(), "plan_id: { definitely-not-valid\n");
	write_message(snapshot_path(), make_snapshot({}));
	write_manifest();
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_EQ(verified_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/** @brief Verify strict parsing rejects null destinations and unknown fields. */
TEST_F(RuntimeBundleTest, strict_parser_rejects_null_and_unknown_snapshot_field)
{
	const auto null_status = kinetum::common::parse_pbtxt_text("snapshot_id: \"unused\"\n", "null-test", nullptr);
	EXPECT_EQ(null_status.code(), kinetum::common::status_code::INVALID_ARGUMENT);

	write_message(plan_path(), make_plan({}));
	write_text(snapshot_path(), "snapshot_id: \"unknown_field_test\"\nfuture_knob: 1\n");
	write_manifest();
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_EQ(verified_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/** @brief Verify an absent plan content hash never means skip verification. */
TEST_F(RuntimeBundleTest, rejects_missing_plan_content_hash)
{
	write_bundle(make_unhashed_plan({}), make_snapshot({}));
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_NE(verified_or.error().message().find("required"), std::string::npos);
}

/** @brief Verify a manifest-bound plan still fails when its identity claim is stale. */
TEST_F(RuntimeBundleTest, rejects_mismatched_plan_content_hash)
{
	auto plan = make_plan({});
	plan.mutable_execution_provider_instances(0)->set_execution_provider_instance_id("execution_cpu_1");
	write_bundle(plan, make_snapshot({}));
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_EQ(verified_or.error().code(), kinetum::common::status_code::DATA_LOSS);
}

/** @brief Verify the bootstrap snapshot must match the plan module set both ways. */
TEST_F(RuntimeBundleTest, rejects_snapshot_module_set_mismatch)
{
	write_bundle(make_plan({"module.alpha"}), make_snapshot({"module.beta"}));
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_EQ(verified_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/** @brief Verify a supplied snapshot content hash is checked rather than trusted. */
TEST_F(RuntimeBundleTest, rejects_snapshot_content_hash_mismatch)
{
	auto snapshot = make_snapshot({});
	snapshot.set_content_hash(std::string(kinetum::common::SHA256_HEX_LENGTH, '0'));
	write_bundle(make_plan({}), snapshot);
	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_EQ(verified_or.error().code(), kinetum::common::status_code::DATA_LOSS);
}

/** @brief Verify post-manifest mutation of either canonical artifact is detected. */
TEST_F(RuntimeBundleTest, rejects_manifest_bound_artifact_tampering)
{
	const auto plan = make_plan({});
	const auto snapshot = make_snapshot({});
	write_bundle(plan, snapshot);
	write_text(plan_path(), "tampered plan bytes\n");
	EXPECT_FALSE(verify_runtime_bundle(root_.string()).is_ok());

	write_bundle(plan, snapshot);
	write_text(snapshot_path(), "tampered snapshot bytes\n");
	EXPECT_FALSE(verify_runtime_bundle(root_.string()).is_ok());
}

/** @brief Verify a deployment bundle can never acquire a runtime binary tree. */
TEST_F(RuntimeBundleTest, rejects_runtime_binary_subtree_even_when_manifest_bound)
{
	write_bundle(make_plan({}), make_snapshot({}));
	write_text(root_ / "bin/kinetum_dp", "forbidden runtime image\n");
	write_manifest();

	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_EQ(verified_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
}

/** @brief Verify an undeclared empty directory cannot create unbounded tree work. */
TEST_F(RuntimeBundleTest, rejects_undeclared_empty_directory)
{
	write_bundle(make_plan({}), make_snapshot({}));
	std::error_code ec;
	fs::create_directories(root_ / "undeclared/empty", ec);
	ASSERT_FALSE(ec) << ec.message();

	const auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_EQ(verified_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_NE(verified_or.error().message().find("undeclared directory"), std::string::npos);
}

/** @brief Verify a manifest-listed artifact cannot be replaced by a symlink. */
TEST_F(RuntimeBundleTest, rejects_symlinked_artifact)
{
	write_bundle(make_plan({}), make_snapshot({}));
	const fs::path external = root_ / "external_snapshot.pbtxt";
	write_text(external, "snapshot_id: \"external\"\nrevision: 1\n");
	std::error_code ec;
	fs::remove(snapshot_path(), ec);
	ASSERT_FALSE(ec) << ec.message();
	fs::create_symlink(external, snapshot_path(), ec);
	ASSERT_FALSE(ec) << ec.message();
	auto verified_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(verified_or.is_ok());
	EXPECT_EQ(verified_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
}

/** @brief Verify supplied roots reject symlink indirection and invalid traversal. */
TEST_F(RuntimeBundleTest, rejects_symlinked_root_and_invalid_path_components)
{
	auto empty_or = verify_runtime_bundle("");
	ASSERT_FALSE(empty_or.is_ok());
	EXPECT_EQ(empty_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	std::string nul_root = root_.string();
	nul_root.push_back('\0');
	nul_root.append("ignored");
	auto nul_or = verify_runtime_bundle(nul_root);
	ASSERT_FALSE(nul_or.is_ok());
	EXPECT_EQ(nul_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);

	const fs::path real_configs = root_ / "real_configs";
	std::error_code ec;
	fs::create_directories(real_configs, ec);
	ASSERT_FALSE(ec) << ec.message();
	fs::create_directory_symlink(real_configs, root_ / "configs", ec);
	ASSERT_FALSE(ec) << ec.message();
	write_text(root_ / std::string(MANIFEST_FILENAME),
		   "bundle_name=test\nbundle_version=" + std::string(kinetum::common::KINETUM_VERSION_STRING) + "\n");
	auto component_or = verify_runtime_bundle(root_.string());
	ASSERT_FALSE(component_or.is_ok());
	EXPECT_EQ(component_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);

	fs::remove_all(root_, ec);
	ASSERT_FALSE(ec) << ec.message();
	fs::create_directories(root_ / "actual", ec);
	ASSERT_FALSE(ec) << ec.message();
	const fs::path linked_root = root_ / "linked";
	fs::create_directory_symlink(root_ / "actual", linked_root, ec);
	ASSERT_FALSE(ec) << ec.message();
	auto root_or = verify_runtime_bundle(linked_root.string());
	ASSERT_FALSE(root_or.is_ok());
	EXPECT_EQ(root_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);

	// A lexical ".." must not erase a supplied symlink component before the
	// verifier examines it.
	auto canceled_component_or = verify_runtime_bundle((linked_root / ".." / "actual").string());
	ASSERT_FALSE(canceled_component_or.is_ok());
	EXPECT_EQ(canceled_component_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);

	// A regular file is not a traversable component. Lexical cancellation
	// must not redirect verification to a different sibling directory.
	const fs::path regular_component = root_ / "regular_component";
	write_text(regular_component, "not a directory\n");
	auto invalid_traversal_or = verify_runtime_bundle((regular_component / ".." / "actual").string());
	ASSERT_FALSE(invalid_traversal_or.is_ok());
	EXPECT_EQ(invalid_traversal_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
}

}  // namespace

}  // namespace kinetum::pack
