// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_config_store.cpp
 * @brief Atomic CP transition-authority and immutable snapshot-corpus tests.
 * @author Fleming Patel
 *
 * These tests preserve every established config-store fate while proving the
 * final immutable-corpus/atomic-head model: exact bootstrap import, restart
 * fixed point, old-format rejection, active/corpus byte equality, one logical
 * listing projection, guardrails policy and rollback-intent identity, and
 * commit-confirmed state embedded in the same mutable authority as exact
 * transition completion.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "gen/kinetum/control/internal/v1/transition_authority.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/control_plane_contract.hpp"
#include "src/common/durable_directory.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/cp/config_store.hpp"
#include "src/cp/control_loop.hpp"
#include "src/cp/guardrails_policy.hpp"

namespace kinetum::cp
{
namespace
{

using kinetum::common::canonical_config_snapshot;
using kinetum::common::status;
using kinetum::common::status_or;

/** @brief Process-local sequence for collision-free test roots. */
std::atomic<uint64_t> TEST_ROOT_SEQUENCE{0u};

/**
 * @brief Build one canonical module-free snapshot.
 *
 * @param snapshot_id Exact semantic identity.
 * @param revision Exact CP revision.
 * @param description Optional content difference.
 * @return Terminal canonical representation or shared validation failure.
 */
status_or<canonical_config_snapshot> make_canonical_snapshot(const std::string &snapshot_id, int64_t revision,
							     const std::string &description = {})
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	snapshot.set_snapshot_id(snapshot_id);
	snapshot.set_revision(revision);
	snapshot.set_created_unix_ms(1'000 + revision);
	snapshot.set_description(description);
	kinetum::gluon::v1::DeploymentPlan module_free_plan;
	return kinetum::common::canonicalize_config_snapshot(snapshot, module_free_plan);
}

/**
 * @brief Parse one canonical representation into its terminal message.
 *
 * @param canonical Exact canonical value.
 * @return Terminal ConfigSnapshot or shared admission failure.
 */
status_or<kinetum::control::v1::ConfigSnapshot> terminal_snapshot(const canonical_config_snapshot &canonical)
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	const auto result = kinetum::common::admit_terminal_config_snapshot(canonical, &snapshot);
	if (!result.is_ok()) {
		return result;
	}
	return snapshot;
}

/**
 * @brief Build one terminal module-free bootstrap authority.
 *
 * @param snapshot_id Exact snapshot identity.
 * @param revision Snapshot revision.
 * @param plan_byte Byte repeated across the test plan identity.
 * @param description Optional content difference.
 * @return Fully canonical authority, or the shared canonicalization failure.
 */
status_or<bootstrap_startup_authority> make_bootstrap_authority(const std::string &snapshot_id, int64_t revision,
								uint8_t plan_byte = 0xaau,
								const std::string &description = {})
{
	auto canonical_or = make_canonical_snapshot(snapshot_id, revision, description);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	bootstrap_startup_authority authority;
	authority.snapshot = std::move(canonical_or).value();
	authority.plan_content_hash_bytes.fill(plan_byte);
	authority.plan_content_hash = kinetum::common::bytes_to_hex(authority.plan_content_hash_bytes.data(),
								    authority.plan_content_hash_bytes.size());
	return authority;
}

/**
 * @brief Write exact test bytes and apply the durable-store file mode.
 * @param path Exact fixture-owned file path.
 * @param bytes Complete file content.
 * @return true only after successful close and mode 0600.
 */
bool write_owned_test_file(const std::filesystem::path &path, std::string_view bytes)
{
	std::ofstream output(path, std::ios::binary | std::ios::trunc);
	if (!output) {
		return false;
	}
	output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
	output.close();
	return output.good() && ::chmod(path.c_str(), static_cast<mode_t>(0600)) == 0;
}

/**
 * @brief Read one complete fixture-owned file.
 * @param path Exact file path.
 * @return Complete bytes, or empty when the test file cannot be opened.
 */
std::string read_test_file(const std::filesystem::path &path)
{
	std::ifstream input(path, std::ios::binary);
	return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

/**
 * @brief Recreate one empty owner-only test root.
 * @param path Exact fixture-owned root.
 * @return true only after complete recreation with mode 0700.
 */
bool reset_owned_test_root(const std::filesystem::path &path)
{
	std::error_code error;
	std::filesystem::remove_all(path, error);
	if (error || !std::filesystem::create_directory(path, error) || error) {
		return false;
	}
	return ::chmod(path.c_str(), static_cast<mode_t>(0700)) == 0;
}

/**
 * @brief Construct identity using the raw validation hash encoded in snapshot content.
 *
 * @param view Exact durable transition view.
 * @return Fixed-width identity or digest-decoding failure.
 */
status_or<kinetum::common::epoch_transition_identity> exact_view_identity(const durable_epoch_transition_view &view)
{
	auto canonical_or = kinetum::common::canonical_config_snapshot_from_terminal(view.prepare_request.snapshot());
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	return kinetum::common::make_epoch_transition_identity(
		view.prepare_request.mutation_sequence(), view.prepare_request.target_epoch(),
		std::string_view(reinterpret_cast<const char *>(canonical_or->validation_hash.data()),
				 canonical_or->validation_hash.size()),
		view.prepare_request.idempotency_key());
}

/**
 * @brief Build one complete explicit threshold policy for durable-store tests.
 * @param max_drop_ratio Finite threshold ratio to place in the candidate.
 * @return Exact no-default policy with bounded cadence, history, and attribution.
 */
kinetum::control::v1::GuardrailsPolicy make_guardrails_policy(double max_drop_ratio = 0.05)
{
	kinetum::control::v1::GuardrailsPolicy policy;
	policy.set_enabled(true);
	policy.set_poll_interval_ms(100u);
	policy.set_evaluation_window_ms(1'000u);
	policy.set_telemetry_history_capacity(16u);
	policy.mutable_threshold()->set_max_drop_ratio(max_drop_ratio);
	policy.mutable_threshold()->set_min_tx_ratio(0.70);
	policy.mutable_threshold()->set_min_packets_per_window(1u);
	policy.mutable_attribution()->set_auto_rollback_threshold(0.80);
	policy.mutable_attribution()->set_defer_threshold(0.50);
	policy.mutable_attribution()->set_baseline_samples(2u);
	policy.mutable_attribution()->set_degradation_threshold(0.30);
	return policy;
}

/**
 * @brief Build one active-content-bound policy rollback intent.
 * @param store Bootstrapped exact store.
 * @param target_snapshot_id Existing corpus target.
 * @param policy_generation Exact enabled policy generation.
 * @param idempotency_key Retained transition retry identity.
 * @return Complete intent request or active-content validation failure.
 */
status_or<rollback_intent_request> make_policy_intent(config_store &store, std::string target_snapshot_id,
						      uint64_t policy_generation, std::string idempotency_key)
{
	auto active_or = store.active_bootstrap();
	if (!active_or.is_ok()) {
		return active_or.error();
	}
	auto canonical_or = kinetum::common::canonical_config_snapshot_from_terminal(active_or->snapshot());
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	return rollback_intent_request{
		.target_snapshot_id = std::move(target_snapshot_id),
		.guarded_snapshot_id = active_or->snapshot().snapshot_id(),
		.guarded_epoch = active_or->active_epoch(),
		.guarded_revision = active_or->snapshot().revision(),
		.guarded_validation_hash = canonical_or->validation_hash,
		.wait_for_mutation_sequence = 0u,
		.policy_generation = policy_generation,
		.runtime_generation = 1u,
		.idempotency_key = std::move(idempotency_key),
		.cause = rollback_intent_cause::THRESHOLD_DEGRADATION,
		.observed_monotonic_ns = 100u,
		.created_unix_ms = 1'000,
	};
}

/** @brief Fixture owning one unique durable root per test. */
class ConfigStoreTest : public ::testing::Test {
    protected:
	/** @brief Select one process-unique durable root without creating it. */
	void SetUp() override
	{
		const uint64_t sequence = TEST_ROOT_SEQUENCE.fetch_add(1u, std::memory_order_relaxed) + 1u;
		root_ = std::filesystem::temp_directory_path() /
			("kinetum_config_store_" + std::to_string(static_cast<uint64_t>(::getpid())) + "_" +
			 std::to_string(sequence));
	}

	/** @brief Remove every fixture-owned durable artifact without throwing. */
	void TearDown() override
	{
		std::error_code error;
		std::filesystem::remove_all(root_, error);
	}

	/** @return Newly admitted store at this fixture's exact root. */
	[[nodiscard]] status_or<std::unique_ptr<config_store>> open_store() const
	{
		return config_store::open(root_);
	}

	std::filesystem::path root_;  ///< Unique exact durable root.
};

/** @brief Verify a fresh control-only root has no fabricated authority. */
TEST_F(ConfigStoreTest, fresh_control_only_root_has_no_active_authority)
{
	auto relative_or = config_store::open(root_.filename());
	ASSERT_FALSE(relative_or.is_ok());
	EXPECT_EQ(relative_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);

	std::error_code error;
	std::filesystem::create_directory_symlink(root_.parent_path(), root_, error);
	ASSERT_FALSE(error) << error.message();
	auto symlink_or = open_store();
	ASSERT_FALSE(symlink_or.is_ok());
	EXPECT_EQ(symlink_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);

	ASSERT_TRUE(reset_owned_test_root(root_));
	ASSERT_EQ(::chmod(root_.c_str(), static_cast<mode_t>(0770)), 0);
	auto writable_or = open_store();
	ASSERT_FALSE(writable_or.is_ok());
	EXPECT_EQ(writable_or.error().code(), kinetum::common::status_code::PERMISSION_DENIED);

	ASSERT_TRUE(reset_owned_test_root(root_));
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok()) << store_or.error().message();
	auto store = std::move(store_or).value();
	EXPECT_TRUE(store->reconcile_bootstrap(nullptr).is_ok());
	EXPECT_FALSE(store->active_bootstrap().is_ok());
	EXPECT_FALSE(store->active_snapshot_id().is_ok());
	EXPECT_FALSE(store->epoch_transition().is_ok());
	EXPECT_FALSE(store->load_pending_confirm().is_ok());
	auto snapshots_or = store->list_snapshot_page(kinetum::common::MAX_SNAPSHOT_LIST_PAGE_SIZE, {});
	ASSERT_TRUE(snapshots_or.is_ok());
	EXPECT_TRUE(snapshots_or->snapshots.empty());
	EXPECT_TRUE(snapshots_or->next_page_token.empty());
	EXPECT_EQ(snapshots_or->total_count, 0u);
}

/** @brief Verify interrupted private publication recovery preserves strict admission. */
TEST_F(ConfigStoreTest, abandoned_private_publication_recovers_without_weakening_unknown_file_rejection)
{
	ASSERT_TRUE(reset_owned_test_root(root_));
	const auto complete_temporary = root_ / ".kinetum.tmp.4242.1";
	const auto pre_mode_temporary = root_ / ".kinetum.tmp.4242.2";
	ASSERT_TRUE(write_owned_test_file(complete_temporary, "complete but unpublished"));
	ASSERT_TRUE(write_owned_test_file(pre_mode_temporary, "created before exact mode"));
	ASSERT_EQ(::chmod(pre_mode_temporary.c_str(), static_cast<mode_t>(0000)), 0);

	auto recovered_or = open_store();
	ASSERT_TRUE(recovered_or.is_ok()) << recovered_or.error().message();
	EXPECT_FALSE(std::filesystem::exists(complete_temporary));
	EXPECT_FALSE(std::filesystem::exists(pre_mode_temporary));
	recovered_or.value().reset();
	{
		auto directory_or = kinetum::common::durable_directory::open(root_);
		ASSERT_TRUE(directory_or.is_ok());
		const auto reserved_status =
			directory_or->publish_new_file(".kinetum.tmp.4242.3", "caller-owned content");
		EXPECT_EQ(reserved_status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	}

	ASSERT_TRUE(reset_owned_test_root(root_));
	const auto malformed_private_name = root_ / ".kinetum.tmp.not-a-pid.1";
	ASSERT_TRUE(write_owned_test_file(malformed_private_name, "not a generated temporary"));
	auto malformed_or = open_store();
	ASSERT_FALSE(malformed_or.is_ok());
	EXPECT_EQ(malformed_or.error().code(), kinetum::common::status_code::DATA_LOSS);
	EXPECT_TRUE(std::filesystem::exists(malformed_private_name));
}

/** @brief Verify fresh import publishes one exact deterministic authority envelope. */
TEST_F(ConfigStoreTest, fresh_bootstrap_import_publishes_one_exact_atomic_record)
{
	auto authority_or = make_bootstrap_authority("bootstrap.alpha", 17);
	ASSERT_TRUE(authority_or.is_ok()) << authority_or.error().message();
	auto authority = std::move(authority_or).value();
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok()) << store_or.error().message();
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&authority).is_ok());

	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok()) << active_or.error().message();
	EXPECT_EQ(active_or->snapshot().snapshot_id(), "bootstrap.alpha");
	EXPECT_EQ(active_or->snapshot().revision(), 17);
	EXPECT_EQ(active_or->active_epoch(), 1u);
	EXPECT_EQ(active_or->allocated_epoch_high_watermark(), 1u);
	EXPECT_EQ(active_or->mutation_sequence_high_watermark(), 1u);
	EXPECT_EQ(active_or->plan_content_hash(), authority.plan_content_hash);
	auto admitted_active_or = kinetum::common::validate_bootstrap_config_snapshot_request(active_or.value());
	ASSERT_TRUE(admitted_active_or.is_ok()) << admitted_active_or.error().message();

	const auto bytes = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");
	ASSERT_FALSE(bytes.empty());
	kinetum::control::internal::v1::ControlPlaneTransitionAuthority persisted;
	ASSERT_TRUE(persisted.ParseFromString(bytes));
	EXPECT_TRUE(persisted.has_active_bootstrap());
	EXPECT_FALSE(persisted.has_transition());
	EXPECT_FALSE(persisted.has_pending_confirm());
	auto persisted_active_or = kinetum::common::serialize_protobuf_deterministically(persisted.active_bootstrap());
	ASSERT_TRUE(persisted_active_or.is_ok());
	EXPECT_EQ(persisted_active_or.value(), admitted_active_or->serialized_request);
	auto deterministic_or = kinetum::common::serialize_protobuf_deterministically(persisted);
	ASSERT_TRUE(deterministic_or.is_ok()) << deterministic_or.error().message();
	EXPECT_EQ(deterministic_or.value(), bytes);
}

/** @brief Verify restart recovers the exact deterministic authority bytes. */
TEST_F(ConfigStoreTest, restart_without_source_recovers_exact_atomic_record)
{
	std::string expected_bytes;
	{
		auto authority_or = make_bootstrap_authority("bootstrap.restart", 23);
		ASSERT_TRUE(authority_or.is_ok()) << authority_or.error().message();
		auto store_or = open_store();
		ASSERT_TRUE(store_or.is_ok()) << store_or.error().message();
		auto store = std::move(store_or).value();
		ASSERT_TRUE(store->reconcile_bootstrap(&authority_or.value()).is_ok());
		expected_bytes = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");
	}
	auto restarted_or = open_store();
	ASSERT_TRUE(restarted_or.is_ok()) << restarted_or.error().message();
	auto restarted = std::move(restarted_or).value();
	ASSERT_TRUE(restarted->reconcile_bootstrap(nullptr).is_ok());
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), expected_bytes);
	auto active_or = restarted->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	EXPECT_EQ(active_or->snapshot().snapshot_id(), "bootstrap.restart");
}

/** @brief Verify matching source reuse performs no authority rewrite. */
TEST_F(ConfigStoreTest, matching_bootstrap_source_is_idempotent_without_rewrite)
{
	auto authority_or = make_bootstrap_authority("bootstrap.retry", 31);
	ASSERT_TRUE(authority_or.is_ok());
	auto authority = std::move(authority_or).value();
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&authority).is_ok());
	const auto path = root_ / "TRANSITION_AUTHORITY.pb";
	struct stat before{};
	ASSERT_EQ(::stat(path.c_str(), &before), 0);
	ASSERT_TRUE(store->reconcile_bootstrap(&authority).is_ok());
	struct stat after{};
	ASSERT_EQ(::stat(path.c_str(), &after), 0);
	EXPECT_EQ(after.st_dev, before.st_dev);
	EXPECT_EQ(after.st_ino, before.st_ino);
	EXPECT_EQ(after.st_size, before.st_size);
	EXPECT_EQ(after.st_mtim.tv_sec, before.st_mtim.tv_sec);
	EXPECT_EQ(after.st_mtim.tv_nsec, before.st_mtim.tv_nsec);
}

/** @brief Verify conflicting source or plan cannot rewrite durable authority. */
TEST_F(ConfigStoreTest, conflicting_source_or_plan_rejects_without_rewrite)
{
	auto original_or = make_bootstrap_authority("bootstrap.original", 41);
	ASSERT_TRUE(original_or.is_ok());
	auto original = std::move(original_or).value();
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&original).is_ok());
	const std::string before = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");

	auto content_or = make_bootstrap_authority("bootstrap.original", 41, 0xaau, "different");
	ASSERT_TRUE(content_or.is_ok());
	EXPECT_EQ(store->reconcile_bootstrap(&content_or.value()).code(),
		  kinetum::common::status_code::FAILED_PRECONDITION);
	auto plan_or = make_bootstrap_authority("bootstrap.original", 41, 0xbbu);
	ASSERT_TRUE(plan_or.is_ok());
	EXPECT_EQ(store->reconcile_bootstrap(&plan_or.value()).code(),
		  kinetum::common::status_code::FAILED_PRECONDITION);
	auto representation_or = make_bootstrap_authority("bootstrap.original", 41);
	ASSERT_TRUE(representation_or.is_ok());
	representation_or->plan_content_hash_bytes[0] ^= 0xffu;
	EXPECT_EQ(store->reconcile_bootstrap(&representation_or.value()).code(),
		  kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), before);
}

/** @brief Verify malformed authority bytes and unsupported root entries reject. */
TEST_F(ConfigStoreTest, malformed_authority_and_store_entries_reject)
{
	ASSERT_TRUE(reset_owned_test_root(root_));
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", std::string("\xff", 1)));
	auto malformed_or = open_store();
	ASSERT_FALSE(malformed_or.is_ok());
	EXPECT_EQ(malformed_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	ASSERT_TRUE(reset_owned_test_root(root_));
	const auto mode_probe = root_ / "TRANSITION_AUTHORITY.pb";
	ASSERT_TRUE(write_owned_test_file(mode_probe, {}));
	ASSERT_EQ(::chmod(mode_probe.c_str(), static_cast<mode_t>(S_ISUID | S_IRUSR | S_IWUSR)), 0);
	auto forbidden_mode_or = open_store();
	ASSERT_FALSE(forbidden_mode_or.is_ok());
	EXPECT_EQ(forbidden_mode_or.error().code(), kinetum::common::status_code::PERMISSION_DENIED);

	ASSERT_TRUE(reset_owned_test_root(root_));
	const auto fifo = root_ / "TRANSITION_AUTHORITY.pb";
	ASSERT_EQ(::mkfifo(fifo.c_str(), static_cast<mode_t>(0600)), 0);
	auto fifo_or = open_store();
	ASSERT_FALSE(fifo_or.is_ok());
	EXPECT_EQ(fifo_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);

	ASSERT_TRUE(reset_owned_test_root(root_));
	ASSERT_TRUE(write_owned_test_file(root_ / "UNKNOWN.pb", "unknown"));
	auto unknown_or = open_store();
	ASSERT_FALSE(unknown_or.is_ok());
	EXPECT_EQ(unknown_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	ASSERT_TRUE(reset_owned_test_root(root_));
	const auto linked_source = root_ / "linked_source.pb";
	ASSERT_TRUE(write_owned_test_file(linked_source, "linked"));
	std::error_code link_error;
	std::filesystem::create_hard_link(linked_source, root_ / "linked_alias.pb", link_error);
	ASSERT_FALSE(link_error) << link_error.message();
	auto multiply_linked_or = open_store();
	ASSERT_FALSE(multiply_linked_or.is_ok());
	EXPECT_EQ(multiply_linked_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);

	ASSERT_TRUE(reset_owned_test_root(root_));
	const auto symlink_target = root_ / "symlink_target.pb";
	ASSERT_TRUE(write_owned_test_file(symlink_target, "target"));
	link_error.clear();
	std::filesystem::create_symlink(symlink_target.filename(), root_ / "symlink_alias.pb", link_error);
	ASSERT_FALSE(link_error) << link_error.message();
	auto symlink_or = open_store();
	ASSERT_FALSE(symlink_or.is_ok());
	EXPECT_EQ(symlink_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);

	kinetum::control::internal::v1::ControlPlaneTransitionAuthority exact_authority;
	std::string exact_authority_bytes;
	ASSERT_TRUE(reset_owned_test_root(root_));
	{
		auto bootstrap_or = make_bootstrap_authority("bootstrap.readmission", 47);
		ASSERT_TRUE(bootstrap_or.is_ok());
		auto store_or = open_store();
		ASSERT_TRUE(store_or.is_ok());
		auto store = std::move(store_or).value();
		ASSERT_TRUE(store->reconcile_bootstrap(&bootstrap_or.value()).is_ok());
		exact_authority_bytes = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");
		ASSERT_TRUE(exact_authority.ParseFromString(exact_authority_bytes));
	}

	ASSERT_TRUE(reset_owned_test_root(root_));
	auto reserved_epoch = exact_authority;
	reserved_epoch.mutable_active_bootstrap()->set_active_epoch(std::numeric_limits<uint64_t>::max());
	reserved_epoch.mutable_active_bootstrap()->set_allocated_epoch_high_watermark(
		std::numeric_limits<uint64_t>::max());
	auto reserved_epoch_bytes_or = kinetum::common::serialize_protobuf_deterministically(reserved_epoch);
	ASSERT_TRUE(reserved_epoch_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", reserved_epoch_bytes_or.value()));
	auto reserved_epoch_or = open_store();
	ASSERT_FALSE(reserved_epoch_or.is_ok());
	EXPECT_EQ(reserved_epoch_or.error().code(), kinetum::common::status_code::DATA_LOSS);
	EXPECT_NE(reserved_epoch_or.error().details().find("reserved wrap sentinel"), std::string::npos);

	ASSERT_TRUE(reset_owned_test_root(root_));
	auto reserved_mutation = exact_authority;
	reserved_mutation.mutable_active_bootstrap()->set_mutation_sequence_high_watermark(
		std::numeric_limits<uint64_t>::max());
	auto reserved_mutation_bytes_or = kinetum::common::serialize_protobuf_deterministically(reserved_mutation);
	ASSERT_TRUE(reserved_mutation_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", reserved_mutation_bytes_or.value()));
	auto reserved_mutation_or = open_store();
	ASSERT_FALSE(reserved_mutation_or.is_ok());
	EXPECT_EQ(reserved_mutation_or.error().code(), kinetum::common::status_code::DATA_LOSS);
	EXPECT_NE(reserved_mutation_or.error().details().find("reserved wrap sentinel"), std::string::npos);

	ASSERT_TRUE(reset_owned_test_root(root_));
	auto wrong_key = exact_authority;
	wrong_key.mutable_active_bootstrap()->set_idempotency_key("kinetum-bootstrap-v1-" + std::string(64u, '0'));
	auto wrong_key_bytes_or = kinetum::common::serialize_protobuf_deterministically(wrong_key);
	ASSERT_TRUE(wrong_key_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", wrong_key_bytes_or.value()));
	auto wrong_key_or = open_store();
	ASSERT_FALSE(wrong_key_or.is_ok());
	EXPECT_EQ(wrong_key_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	ASSERT_TRUE(reset_owned_test_root(root_));
	exact_authority_bytes.append("\x20\x01", 2u);
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", exact_authority_bytes));
	auto noncanonical_or = open_store();
	ASSERT_FALSE(noncanonical_or.is_ok());
	EXPECT_EQ(noncanonical_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	ASSERT_TRUE(reset_owned_test_root(root_));
	auto leaf_canonical_or = make_canonical_snapshot("leaf.bound", 1);
	ASSERT_TRUE(leaf_canonical_or.is_ok());
	auto leaf_snapshot_or = terminal_snapshot(leaf_canonical_or.value());
	ASSERT_TRUE(leaf_snapshot_or.is_ok());
	auto staged_text_or = kinetum::common::print_pbtxt_text(leaf_snapshot_or.value());
	ASSERT_TRUE(staged_text_or.is_ok());
	ASSERT_TRUE(
		write_owned_test_file(root_ / ("snap_" + std::string(64u, '0') + ".pbtxt"), staged_text_or.value()));
	auto mismatched_leaf_or = open_store();
	ASSERT_FALSE(mismatched_leaf_or.is_ok());
	EXPECT_EQ(mismatched_leaf_or.error().code(), kinetum::common::status_code::DATA_LOSS);
}

/** @brief Verify immutable corpus ordering and exact active deduplication. */
TEST_F(ConfigStoreTest, staged_history_is_create_only_sorted_and_does_not_advance_active_revision)
{
	auto authority_or = make_bootstrap_authority("active", 53);
	ASSERT_TRUE(authority_or.is_ok());
	auto authority = std::move(authority_or).value();
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&authority).is_ok());
	ASSERT_TRUE(store->stage_snapshot(authority.snapshot).is_ok());

	const std::array<std::string, 7> ids{
		"delta", "beta", "gamma", "alpha", std::string(256u, 'z'), ".", "tenant/../snapshot"};
	std::array<canonical_config_snapshot, 7> snapshots;
	for (std::size_t index = 0; index < snapshots.size(); ++index) {
		auto snapshot_or = make_canonical_snapshot(ids[index], 100 + static_cast<int64_t>(index));
		ASSERT_TRUE(snapshot_or.is_ok());
		snapshots[index] = std::move(snapshot_or).value();
	}
	std::array<status, 7> results;
	std::vector<std::thread> writers;
	for (std::size_t index = 0; index < snapshots.size(); ++index) {
		writers.emplace_back([&, index]() { results[index] = store->stage_snapshot(snapshots[index]); });
	}
	for (auto &writer : writers) {
		writer.join();
	}
	for (const auto &result : results) {
		EXPECT_TRUE(result.is_ok()) << result.message();
	}
	EXPECT_TRUE(store->stage_snapshot(snapshots[0]).is_ok());
	auto conflict_or = make_canonical_snapshot(ids[0], 100, "different bytes");
	ASSERT_TRUE(conflict_or.is_ok());
	EXPECT_EQ(store->stage_snapshot(conflict_or.value()).code(), kinetum::common::status_code::DATA_LOSS);
	auto active_after_staging_or = store->active_bootstrap();
	ASSERT_TRUE(active_after_staging_or.is_ok());
	EXPECT_EQ(active_after_staging_or->snapshot().revision(), 53);

	auto listed_or = store->list_snapshot_page(kinetum::common::MAX_SNAPSHOT_LIST_PAGE_SIZE, {});
	ASSERT_TRUE(listed_or.is_ok());
	ASSERT_EQ(listed_or->snapshots.size(), 8u);
	EXPECT_TRUE(listed_or->next_page_token.empty());
	EXPECT_EQ(listed_or->total_count, 8u);
	const std::array<std::string, 8> expected{".", "active", "alpha", "beta", "delta", "gamma", ids[6], ids[4]};
	for (std::size_t index = 0; index < expected.size(); ++index) {
		EXPECT_EQ(listed_or->snapshots.at(index).snapshot_id(), expected[index]);
		EXPECT_EQ(listed_or->snapshots.at(index).is_active(), index == 1u);
	}
	EXPECT_EQ(std::count_if(listed_or->snapshots.begin(), listed_or->snapshots.end(),
				[](const auto &info) { return info.is_active(); }),
		  1);

	auto directory_or = kinetum::common::durable_directory::open(root_);
	ASSERT_TRUE(directory_or.is_ok());
	auto first_files_or = directory_or->list_files();
	auto second_files_or = directory_or->list_files();
	ASSERT_TRUE(first_files_or.is_ok());
	ASSERT_TRUE(second_files_or.is_ok());
	EXPECT_EQ(second_files_or.value(), first_files_or.value());
	auto max_id_hash_or = kinetum::common::sha256_hex(ids[4]);
	ASSERT_TRUE(max_id_hash_or.is_ok());
	const std::string max_id_leaf = "snap_" + max_id_hash_or.value() + ".pbtxt";
	EXPECT_EQ(max_id_leaf.size(), 75u);
	EXPECT_NE(std::find(first_files_or->begin(), first_files_or->end(), max_id_leaf), first_files_or->end());
	auto path_id_hash_or = kinetum::common::sha256_hex(ids[6]);
	ASSERT_TRUE(path_id_hash_or.is_ok());
	const std::string path_id_leaf = "snap_" + path_id_hash_or.value() + ".pbtxt";
	EXPECT_NE(std::find(first_files_or->begin(), first_files_or->end(), path_id_leaf), first_files_or->end());

	store.reset();
	auto restarted_or = open_store();
	ASSERT_TRUE(restarted_or.is_ok());
	auto max_snapshot_or = restarted_or.value()->load_snapshot(ids[4]);
	auto dot_snapshot_or = restarted_or.value()->load_snapshot(".");
	auto path_snapshot_or = restarted_or.value()->load_snapshot(ids[6]);
	ASSERT_TRUE(max_snapshot_or.is_ok());
	ASSERT_TRUE(dot_snapshot_or.is_ok());
	ASSERT_TRUE(path_snapshot_or.is_ok());
	EXPECT_EQ(max_snapshot_or->revision(), 104);
	EXPECT_EQ(dot_snapshot_or->revision(), 105);
	EXPECT_EQ(path_snapshot_or->revision(), 106);
}

/** @brief Verify stateless pages bind exact corpus and active authority identity. */
TEST_F(ConfigStoreTest, snapshot_listing_token_is_bounded_stateless_and_invalidated_by_change)
{
	auto authority_or = make_bootstrap_authority("b", 1);
	ASSERT_TRUE(authority_or.is_ok());
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&authority_or.value()).is_ok());
	for (const auto &id : {"a", "c", "d"}) {
		auto canonical_or = make_canonical_snapshot(id, 2);
		ASSERT_TRUE(canonical_or.is_ok());
		ASSERT_TRUE(store->stage_snapshot(canonical_or.value()).is_ok());
	}

	auto first_or = store->list_snapshot_page(1u, {});
	ASSERT_TRUE(first_or.is_ok());
	ASSERT_EQ(first_or->snapshots.size(), 1u);
	EXPECT_EQ(first_or->snapshots[0].snapshot_id(), "a");
	EXPECT_EQ(first_or->total_count, 4u);
	ASSERT_FALSE(first_or->next_page_token.empty());
	EXPECT_LE(first_or->next_page_token.size(), kinetum::common::MAX_SNAPSHOT_LIST_PAGE_TOKEN_BYTES);

	auto second_or = store->list_snapshot_page(3u, first_or->next_page_token);
	ASSERT_TRUE(second_or.is_ok());
	ASSERT_EQ(second_or->snapshots.size(), 3u);
	EXPECT_EQ(second_or->snapshots[0].snapshot_id(), "b");
	EXPECT_EQ(second_or->snapshots[1].snapshot_id(), "c");
	EXPECT_EQ(second_or->snapshots[2].snapshot_id(), "d");
	EXPECT_TRUE(second_or->next_page_token.empty());

	std::string noncanonical = first_or->next_page_token;
	const auto lowercase = std::find_if(noncanonical.begin(), noncanonical.end(),
					    [](char value) { return value >= 'a' && value <= 'f'; });
	ASSERT_NE(lowercase, noncanonical.end());
	*lowercase = static_cast<char>(*lowercase - ('a' - 'A'));
	const auto noncanonical_or = store->list_snapshot_page(1u, noncanonical);
	ASSERT_FALSE(noncanonical_or.is_ok());
	EXPECT_EQ(noncanonical_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);

	std::string spliced = first_or->next_page_token;
	ASSERT_GE(spliced.size(), 2u);
	ASSERT_EQ(spliced.substr(spliced.size() - 2u), "61");
	spliced.replace(spliced.size() - 2u, 2u, "62");
	const auto spliced_or = store->list_snapshot_page(1u, spliced);
	ASSERT_FALSE(spliced_or.is_ok());
	EXPECT_EQ(spliced_or.error().code(), kinetum::common::status_code::ABORTED);

	auto added_or = make_canonical_snapshot("e", 3);
	ASSERT_TRUE(added_or.is_ok());
	ASSERT_TRUE(store->stage_snapshot(added_or.value()).is_ok());
	const auto stale_or = store->list_snapshot_page(1u, first_or->next_page_token);
	ASSERT_FALSE(stale_or.is_ok());
	EXPECT_EQ(stale_or.error().code(), kinetum::common::status_code::ABORTED);
}

/** @brief Verify pending-confirm retry and target completion preserve one authority. */
TEST_F(ConfigStoreTest, pending_confirm_replace_and_restart_preserve_one_exact_record)
{
	auto authority_or = make_bootstrap_authority("bootstrap.one", 70);
	ASSERT_TRUE(authority_or.is_ok());
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&authority_or.value()).is_ok());

	auto candidate_canonical_or = make_canonical_snapshot("candidate.one", 71);
	ASSERT_TRUE(candidate_canonical_or.is_ok()) << candidate_canonical_or.error().message();
	auto candidate_or = terminal_snapshot(candidate_canonical_or.value());
	ASSERT_TRUE(candidate_or.is_ok()) << candidate_or.error().message();
	auto transition_or = store->begin_epoch_transition(candidate_or.value(), "confirm-key", 5'000u);
	ASSERT_TRUE(transition_or.is_ok()) << transition_or.error().message();
	auto identity_or = exact_view_identity(transition_or.value());
	ASSERT_TRUE(identity_or.is_ok()) << identity_or.error().message();
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 identity_or.value(),
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	ASSERT_TRUE(store->complete_epoch_transition(identity_or.value(), 10'000).is_ok());
	EXPECT_TRUE(store->reconcile_bootstrap(&authority_or.value()).is_ok());
	auto wrong_plan_or = make_bootstrap_authority("bootstrap.one", 70, 0xbbu);
	ASSERT_TRUE(wrong_plan_or.is_ok());
	EXPECT_EQ(store->reconcile_bootstrap(&wrong_plan_or.value()).code(),
		  kinetum::common::status_code::FAILED_PRECONDITION);
	auto pending_or = store->load_pending_confirm();
	ASSERT_TRUE(pending_or.is_ok());
	EXPECT_EQ(pending_or->snapshot_id(), "candidate.one");
	EXPECT_EQ(pending_or->rollback_snapshot_id(), "bootstrap.one");
	EXPECT_EQ(pending_or->epoch(), 2u);
	EXPECT_EQ(pending_or->deadline_unix_ms(), 15'000);
	const std::string pending_bytes = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");
	auto nested_target_or = store->load_snapshot("bootstrap.one");
	ASSERT_TRUE(nested_target_or.is_ok());
	auto nested_confirm_or =
		store->begin_epoch_transition(nested_target_or.value(), "nested-confirm-rollback-key", 1'000u);
	ASSERT_FALSE(nested_confirm_or.is_ok());
	EXPECT_EQ(nested_confirm_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), pending_bytes);
	auto hybrid_canonical_or = make_canonical_snapshot("pending.hybrid", 72);
	ASSERT_TRUE(hybrid_canonical_or.is_ok());
	auto hybrid_or = terminal_snapshot(hybrid_canonical_or.value());
	ASSERT_TRUE(hybrid_or.is_ok());
	auto hybrid_rollback_or = store->begin_epoch_transition(hybrid_or.value(), "hybrid-rollback-key", 0u);
	ASSERT_FALSE(hybrid_rollback_or.is_ok());
	EXPECT_EQ(hybrid_rollback_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), pending_bytes);

	auto confirmed_or = store->confirm_pending_config("candidate.one", 2u, 71, "confirm-request-key", 11'000);
	ASSERT_TRUE(confirmed_or.is_ok());
	EXPECT_EQ(confirmed_or->time_remaining_ms, 4'000u);
	auto wrong_retry_or = store->confirm_pending_config("candidate.one", 2u, 71, "different-confirm-key", 11'001);
	ASSERT_FALSE(wrong_retry_or.is_ok());
	EXPECT_EQ(wrong_retry_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	store.reset();

	auto restarted_or = open_store();
	ASSERT_TRUE(restarted_or.is_ok()) << restarted_or.error().message();
	auto restarted = std::move(restarted_or).value();
	auto restored_pending_or = restarted->load_pending_confirm();
	ASSERT_TRUE(restored_pending_or.is_ok());
	EXPECT_TRUE(restored_pending_or->confirmed());
	auto retry_or = restarted->confirm_pending_config("candidate.one", 2u, 71, "confirm-request-key", 16'000);
	ASSERT_TRUE(retry_or.is_ok());
	EXPECT_TRUE(retry_or->exact_retry);
	EXPECT_EQ(retry_or->time_remaining_ms, 4'000u);
	auto policy_or =
		restarted->configure_guardrails_policy(make_guardrails_policy(), "concurrent-target-policy-key", 0u);
	ASSERT_TRUE(policy_or.is_ok());
	auto rollback_snapshot_or = restarted->load_snapshot("bootstrap.one");
	ASSERT_TRUE(rollback_snapshot_or.is_ok());
	auto rollback_or = restarted->begin_epoch_transition(rollback_snapshot_or.value(), "late-rollback", 0u);
	ASSERT_TRUE(rollback_or.is_ok());
	rollback_intent_request concurrent_intent{
		.target_snapshot_id = "bootstrap.one",
		.guarded_snapshot_id = "candidate.one",
		.guarded_epoch = identity_or->target_epoch,
		.guarded_revision = 71,
		.guarded_validation_hash = identity_or->validation_hash,
		.wait_for_mutation_sequence = rollback_or->identity.mutation_sequence,
		.policy_generation = policy_or->generation,
		.runtime_generation = 1u,
		.idempotency_key = "concurrent-target-intent-key",
		.cause = rollback_intent_cause::THRESHOLD_DEGRADATION,
		.observed_monotonic_ns = 1u,
		.created_unix_ms = 16'000,
	};
	ASSERT_TRUE(restarted->accept_rollback_intent(concurrent_intent).is_ok());
	ASSERT_TRUE(restarted
			    ->advance_epoch_transition_phase(
				    rollback_or->identity,
				    kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(restarted
			    ->advance_epoch_transition_phase(
				    rollback_or->identity,
				    kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	ASSERT_TRUE(restarted->complete_epoch_transition(rollback_or->identity, 17'000).is_ok());
	EXPECT_FALSE(restarted->load_pending_confirm().is_ok());
	EXPECT_FALSE(restarted->rollback_intent().is_ok());
	EXPECT_TRUE(restarted->epoch_transition().is_ok());
	auto final_active_or = restarted->active_bootstrap();
	ASSERT_TRUE(final_active_or.is_ok());
	EXPECT_EQ(final_active_or->snapshot().snapshot_id(), "bootstrap.one");
	EXPECT_EQ(final_active_or->active_epoch(), rollback_or->identity.target_epoch);
}

/** @brief Verify policy retry classification precedes generation CAS and survives restart. */
TEST_F(ConfigStoreTest, guardrails_policy_generation_hash_and_retry_identity_are_one_durable_record)
{
	auto bootstrap_or = make_bootstrap_authority("policy.active", 1);
	ASSERT_TRUE(bootstrap_or.is_ok());
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&bootstrap_or.value()).is_ok());

	const auto first_policy = make_guardrails_policy();
	auto first_or = store->configure_guardrails_policy(first_policy, "policy-key", 0u);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	EXPECT_EQ(first_or->generation, 1u);
	EXPECT_FALSE(first_or->exact_retry);
	const std::string first_bytes = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");

	auto retry_or = store->configure_guardrails_policy(first_policy, "policy-key", UINT64_MAX);
	ASSERT_TRUE(retry_or.is_ok()) << retry_or.error().message();
	EXPECT_TRUE(retry_or->exact_retry);
	EXPECT_EQ(retry_or->generation, first_or->generation);
	EXPECT_EQ(retry_or->policy_hash, first_or->policy_hash);
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), first_bytes);

	const auto different_policy = make_guardrails_policy(0.10);
	auto conflict_or = store->configure_guardrails_policy(different_policy, "policy-key", 1u);
	ASSERT_FALSE(conflict_or.is_ok());
	EXPECT_EQ(conflict_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	auto stale_or = store->configure_guardrails_policy(different_policy, "new-policy-key", 0u);
	ASSERT_FALSE(stale_or.is_ok());
	EXPECT_EQ(stale_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), first_bytes);

	auto second_or = store->configure_guardrails_policy(different_policy, "new-policy-key", 1u);
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	EXPECT_EQ(second_or->generation, 2u);
	store.reset();
	auto restarted_or = open_store();
	ASSERT_TRUE(restarted_or.is_ok()) << restarted_or.error().message();
	auto restarted = std::move(restarted_or).value();
	auto restored_or = restarted->guardrails_policy();
	ASSERT_TRUE(restored_or.is_ok());
	EXPECT_EQ(restored_or->generation, 2u);
	EXPECT_EQ(restored_or->policy_hash, second_or->policy_hash);
	EXPECT_EQ(restored_or->policy.SerializeAsString(), different_policy.SerializeAsString());
	restarted.reset();
	const std::string valid_policy_bytes = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");
	kinetum::control::internal::v1::ControlPlaneTransitionAuthority near_exhaustion;
	ASSERT_TRUE(near_exhaustion.ParseFromString(valid_policy_bytes));
	near_exhaustion.mutable_guardrails_policy()->set_generation(UINT64_MAX - 1u);
	auto near_exhaustion_bytes_or = kinetum::common::serialize_protobuf_deterministically(near_exhaustion);
	ASSERT_TRUE(near_exhaustion_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", near_exhaustion_bytes_or.value()));
	auto exhausted_store_or = open_store();
	ASSERT_TRUE(exhausted_store_or.is_ok());
	auto exhausted_store = std::move(exhausted_store_or).value();
	auto exhausted_or =
		exhausted_store->configure_guardrails_policy(first_policy, "exhausted-policy-key", UINT64_MAX - 1u);
	ASSERT_FALSE(exhausted_or.is_ok());
	EXPECT_EQ(exhausted_or.error().code(), kinetum::common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), near_exhaustion_bytes_or.value());
	exhausted_store.reset();
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", valid_policy_bytes));

	kinetum::control::internal::v1::ControlPlaneTransitionAuthority malformed;
	ASSERT_TRUE(malformed.ParseFromString(read_test_file(root_ / "TRANSITION_AUTHORITY.pb")));
	malformed.mutable_guardrails_policy()->clear_policy();
	kinetum::control::v1::GuardrailsPolicy disabled;
	auto disabled_or = canonicalize_guardrails_policy(disabled);
	ASSERT_TRUE(disabled_or.is_ok());
	malformed.mutable_guardrails_policy()->set_policy_hash(
		reinterpret_cast<const char *>(disabled_or->policy_hash.data()), disabled_or->policy_hash.size());
	auto malformed_bytes_or = kinetum::common::serialize_protobuf_deterministically(malformed);
	ASSERT_TRUE(malformed_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", malformed_bytes_or.value()));
	auto missing_policy_or = open_store();
	ASSERT_FALSE(missing_policy_or.is_ok());
	EXPECT_EQ(missing_policy_or.error().code(), kinetum::common::status_code::DATA_LOSS);
}

/** @brief Verify malformed policy, intent cause, and confirmation time fail before mutation. */
TEST_F(ConfigStoreTest, removed_policy_wire_and_confirmation_deadline_fail_closed)
{
	auto bootstrap_or = make_bootstrap_authority("confirm.active", 10);
	ASSERT_TRUE(bootstrap_or.is_ok());
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&bootstrap_or.value()).is_ok());

	kinetum::control::v1::GuardrailsPolicy removed_wire;
	std::string old_bytes("\x48\x01", 2u);
	ASSERT_TRUE(removed_wire.ParseFromString(old_bytes));
	auto removed_or = store->configure_guardrails_policy(removed_wire, "removed-policy-key", 0u);
	ASSERT_FALSE(removed_or.is_ok());
	EXPECT_EQ(removed_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_FALSE(store->guardrails_policy().is_ok());

	auto candidate_canonical_or = make_canonical_snapshot("confirm.target", 11);
	ASSERT_TRUE(candidate_canonical_or.is_ok());
	auto candidate_or = terminal_snapshot(candidate_canonical_or.value());
	ASSERT_TRUE(candidate_or.is_ok());
	auto transition_or = store->begin_epoch_transition(candidate_or.value(), "confirm-transition", 5'000u);
	ASSERT_TRUE(transition_or.is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 transition_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	ASSERT_TRUE(store->complete_epoch_transition(transition_or->identity, 10'000).is_ok());
	const std::string before = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");
	auto regressed_or = store->confirm_pending_config("confirm.target", 2u, 11, "regressed-confirm-key", 9'999);
	ASSERT_FALSE(regressed_or.is_ok());
	EXPECT_EQ(regressed_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	auto late_or = store->confirm_pending_config("confirm.target", 2u, 11, "late-confirm-key", 15'000);
	ASSERT_FALSE(late_or.is_ok());
	EXPECT_EQ(late_or.error().code(), kinetum::common::status_code::DEADLINE_EXCEEDED);
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), before);
	rollback_intent_request deadline_intent{
		.target_snapshot_id = "confirm.active",
		.guarded_snapshot_id = "confirm.target",
		.guarded_epoch = 2u,
		.guarded_revision = 11,
		.guarded_validation_hash = transition_or->identity.validation_hash,
		.wait_for_mutation_sequence = 0u,
		.policy_generation = 0u,
		.runtime_generation = 1u,
		.idempotency_key = "confirm-deadline-intent-key",
		.cause = rollback_intent_cause::COMMIT_CONFIRM_DEADLINE,
		.observed_monotonic_ns = 1u,
		.created_unix_ms = 15'000,
	};
	auto unspecified_cause = deadline_intent;
	unspecified_cause.cause = rollback_intent_cause::UNSPECIFIED;
	auto unspecified_cause_or = store->accept_rollback_intent(unspecified_cause);
	ASSERT_FALSE(unspecified_cause_or.is_ok());
	EXPECT_EQ(unspecified_cause_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), before);
	ASSERT_TRUE(store->accept_rollback_intent(deadline_intent).is_ok());
	const std::string intent_bytes = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");
	auto serialized_loser_or =
		store->confirm_pending_config("confirm.target", 2u, 11, "pre-deadline-sample-key", 14'999);
	ASSERT_FALSE(serialized_loser_or.is_ok());
	EXPECT_EQ(serialized_loser_or.error().code(), kinetum::common::status_code::DEADLINE_EXCEEDED);
	EXPECT_EQ(read_test_file(root_ / "TRANSITION_AUTHORITY.pb"), intent_bytes);
	auto pending_or = store->load_pending_confirm();
	ASSERT_TRUE(pending_or.is_ok());
	EXPECT_FALSE(pending_or->confirmed());
}

/** @brief Verify an orphaned rollback allocation preserves intent and reuses only its key. */
TEST_F(ConfigStoreTest, joint_restart_reallocates_unsatisfied_intent_and_clears_only_after_complete)
{
	auto bootstrap_or = make_bootstrap_authority("rollback.guarded", 20);
	ASSERT_TRUE(bootstrap_or.is_ok());
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&bootstrap_or.value()).is_ok());
	auto target_or = make_canonical_snapshot("rollback.target", 19);
	ASSERT_TRUE(target_or.is_ok());
	ASSERT_TRUE(store->stage_snapshot(target_or.value()).is_ok());
	auto policy_or = store->configure_guardrails_policy(make_guardrails_policy(), "rollback-policy-key", 0u);
	ASSERT_TRUE(policy_or.is_ok());
	auto intent_request_or =
		make_policy_intent(*store, "rollback.target", policy_or->generation, "rollback-intent-key");
	ASSERT_TRUE(intent_request_or.is_ok());
	ASSERT_TRUE(store->accept_rollback_intent(intent_request_or.value()).is_ok());

	auto target_snapshot_or = store->load_snapshot("rollback.target");
	ASSERT_TRUE(target_snapshot_or.is_ok());
	auto nested_confirm_or = store->begin_epoch_transition(target_snapshot_or.value(), "rollback-intent-key", 1u);
	ASSERT_FALSE(nested_confirm_or.is_ok());
	EXPECT_EQ(nested_confirm_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_FALSE(store->epoch_transition().is_ok());
	auto first_attempt_or = store->begin_epoch_transition(target_snapshot_or.value(), "rollback-intent-key", 0u);
	ASSERT_TRUE(first_attempt_or.is_ok());
	EXPECT_EQ(first_attempt_or->identity.target_epoch, 2u);
	auto owned_intent_or = store->rollback_intent();
	ASSERT_TRUE(owned_intent_or.is_ok());
	EXPECT_EQ(owned_intent_or->request.wait_for_mutation_sequence, first_attempt_or->identity.mutation_sequence);
	ASSERT_TRUE(store->discard_orphaned_epoch_transition_after_bootstrap().is_ok());
	EXPECT_FALSE(store->epoch_transition().is_ok());
	auto retained_intent_or = store->rollback_intent();
	ASSERT_TRUE(retained_intent_or.is_ok());
	EXPECT_EQ(retained_intent_or->request.idempotency_key, "rollback-intent-key");
	EXPECT_EQ(retained_intent_or->request.wait_for_mutation_sequence, 0u);

	auto second_attempt_or = store->begin_epoch_transition(target_snapshot_or.value(), "rollback-intent-key", 0u);
	ASSERT_TRUE(second_attempt_or.is_ok());
	EXPECT_EQ(second_attempt_or->identity.target_epoch, 3u);
	EXPECT_EQ(second_attempt_or->identity.mutation_sequence, 3u);
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 second_attempt_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 second_attempt_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	ASSERT_TRUE(store->complete_epoch_transition(second_attempt_or->identity, 20'000).is_ok());
	EXPECT_FALSE(store->rollback_intent().is_ok());
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	EXPECT_EQ(active_or->snapshot().snapshot_id(), "rollback.target");
	EXPECT_EQ(active_or->active_epoch(), 3u);
}

/** @brief A predecessor intent rejects post-abort staleness and allocates only after COMPLETE. */
TEST_F(ConfigStoreTest, predecessor_bound_intent_allocates_e_plus_two_only_after_exact_complete)
{
	auto bootstrap_or = make_bootstrap_authority("guarded.old", 50);
	ASSERT_TRUE(bootstrap_or.is_ok());
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&bootstrap_or.value()).is_ok());
	auto policy_or =
		store->configure_guardrails_policy(make_guardrails_policy(), "predecessor-wait-policy-key", 0u);
	ASSERT_TRUE(policy_or.is_ok());
	auto aborted_canonical_or = make_canonical_snapshot("guarded.aborted", 51);
	ASSERT_TRUE(aborted_canonical_or.is_ok());
	auto aborted_candidate_or = terminal_snapshot(aborted_canonical_or.value());
	ASSERT_TRUE(aborted_candidate_or.is_ok());
	auto aborted_predecessor_or =
		store->begin_epoch_transition(aborted_candidate_or.value(), "aborted-predecessor-key", 0u);
	ASSERT_TRUE(aborted_predecessor_or.is_ok());
	ASSERT_TRUE(store->abort_epoch_transition(aborted_predecessor_or->identity,
						  status::aborted("predecessor aborted before intent admission"),
						  durable_abort_proof::LOCAL_PRECOMMIT_INTENT)
			    .is_ok());
	rollback_intent_request stale_decision{
		.target_snapshot_id = "guarded.old",
		.guarded_snapshot_id = "guarded.aborted",
		.guarded_epoch = aborted_predecessor_or->identity.target_epoch,
		.guarded_revision = aborted_candidate_or->revision(),
		.guarded_validation_hash = aborted_predecessor_or->identity.validation_hash,
		.wait_for_mutation_sequence = aborted_predecessor_or->identity.mutation_sequence,
		.policy_generation = policy_or->generation,
		.runtime_generation = 1u,
		.idempotency_key = "stale-predecessor-intent-key",
		.cause = rollback_intent_cause::CORRELATED_DEGRADATION,
		.observed_monotonic_ns = 499u,
		.created_unix_ms = 4'999,
	};
	auto stale_decision_or = store->accept_rollback_intent(stale_decision);
	ASSERT_FALSE(stale_decision_or.is_ok());
	EXPECT_EQ(stale_decision_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_FALSE(store->rollback_intent().is_ok());

	auto guarded_canonical_or = make_canonical_snapshot("guarded.new", 51);
	ASSERT_TRUE(guarded_canonical_or.is_ok());
	auto guarded_or = terminal_snapshot(guarded_canonical_or.value());
	ASSERT_TRUE(guarded_or.is_ok());
	auto predecessor_or = store->begin_epoch_transition(guarded_or.value(), "guarded-transition-key", 0u);
	ASSERT_TRUE(predecessor_or.is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 predecessor_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 predecessor_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	rollback_intent_request intent{
		.target_snapshot_id = "guarded.old",
		.guarded_snapshot_id = "guarded.new",
		.guarded_epoch = predecessor_or->identity.target_epoch,
		.guarded_revision = guarded_or->revision(),
		.guarded_validation_hash = predecessor_or->identity.validation_hash,
		.wait_for_mutation_sequence = predecessor_or->identity.mutation_sequence,
		.policy_generation = policy_or->generation,
		.runtime_generation = 1u,
		.idempotency_key = "predecessor-wait-intent-key",
		.cause = rollback_intent_cause::CORRELATED_DEGRADATION,
		.observed_monotonic_ns = 500u,
		.created_unix_ms = 5'000,
	};
	ASSERT_TRUE(store->accept_rollback_intent(intent).is_ok());
	auto target_snapshot_or = store->load_snapshot("guarded.old");
	ASSERT_TRUE(target_snapshot_or.is_ok());
	auto early_or = store->begin_epoch_transition(target_snapshot_or.value(), intent.idempotency_key, 0u);
	ASSERT_FALSE(early_or.is_ok());
	EXPECT_EQ(early_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);

	store.reset();
	auto restarted_or = open_store();
	ASSERT_TRUE(restarted_or.is_ok()) << restarted_or.error().message();
	store = std::move(restarted_or).value();
	ASSERT_TRUE(store->rollback_intent().is_ok());
	ASSERT_TRUE(store->complete_epoch_transition(predecessor_or->identity, 6'000).is_ok());
	auto restarted_target_snapshot_or = store->load_snapshot("guarded.old");
	ASSERT_TRUE(restarted_target_snapshot_or.is_ok());
	auto rollback_or =
		store->begin_epoch_transition(restarted_target_snapshot_or.value(), intent.idempotency_key, 0u);
	ASSERT_TRUE(rollback_or.is_ok()) << rollback_or.error().message();
	EXPECT_EQ(rollback_or->identity.target_epoch, predecessor_or->identity.target_epoch + 1u);
	EXPECT_EQ(rollback_or->identity.mutation_sequence, predecessor_or->identity.mutation_sequence + 1u);
	auto rebound_intent_or = store->rollback_intent();
	ASSERT_TRUE(rebound_intent_or.is_ok());
	EXPECT_EQ(rebound_intent_or->request.wait_for_mutation_sequence, rollback_or->identity.mutation_sequence);
	const std::string rebound_bytes = read_test_file(root_ / "TRANSITION_AUTHORITY.pb");
	store.reset();
	kinetum::control::internal::v1::ControlPlaneTransitionAuthority nested_confirmation;
	ASSERT_TRUE(nested_confirmation.ParseFromString(rebound_bytes));
	nested_confirmation.mutable_transition()->set_confirm_timeout_ms(1u);
	auto nested_confirmation_bytes_or = kinetum::common::serialize_protobuf_deterministically(nested_confirmation);
	ASSERT_TRUE(nested_confirmation_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", nested_confirmation_bytes_or.value()));
	auto nested_confirmation_store_or = open_store();
	ASSERT_FALSE(nested_confirmation_store_or.is_ok());
	EXPECT_EQ(nested_confirmation_store_or.error().code(), kinetum::common::status_code::DATA_LOSS);
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", rebound_bytes));

	kinetum::control::internal::v1::ControlPlaneTransitionAuthority stale_wait;
	ASSERT_TRUE(stale_wait.ParseFromString(rebound_bytes));
	stale_wait.mutable_rollback_intent()->set_wait_for_mutation_sequence(
		predecessor_or->identity.mutation_sequence);
	auto stale_wait_bytes_or = kinetum::common::serialize_protobuf_deterministically(stale_wait);
	ASSERT_TRUE(stale_wait_bytes_or.is_ok());
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", stale_wait_bytes_or.value()));
	auto stale_wait_store_or = open_store();
	ASSERT_FALSE(stale_wait_store_or.is_ok());
	EXPECT_EQ(stale_wait_store_or.error().code(), kinetum::common::status_code::DATA_LOSS);
	ASSERT_TRUE(write_owned_test_file(root_ / "TRANSITION_AUTHORITY.pb", rebound_bytes));
	auto rebound_store_or = open_store();
	ASSERT_TRUE(rebound_store_or.is_ok()) << rebound_store_or.error().message();
	store = std::move(rebound_store_or).value();
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 rollback_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store->advance_epoch_transition_phase(
				 rollback_or->identity,
				 kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	ASSERT_TRUE(store->complete_epoch_transition(rollback_or->identity, 7'000).is_ok());
	EXPECT_FALSE(store->rollback_intent().is_ok());
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	EXPECT_EQ(active_or->snapshot().snapshot_id(), "guarded.old");
	EXPECT_EQ(active_or->active_epoch(), rollback_or->identity.target_epoch);
}

/** @brief Verify fresh Bootstrap resolves a predecessor intent only when its target is active. */
TEST_F(ConfigStoreTest, joint_restart_clears_already_satisfied_predecessor_intent_without_epoch)
{
	auto bootstrap_or = make_bootstrap_authority("predecessor.active", 30);
	ASSERT_TRUE(bootstrap_or.is_ok());
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&bootstrap_or.value()).is_ok());
	auto policy_or = store->configure_guardrails_policy(make_guardrails_policy(), "predecessor-policy-key", 0u);
	ASSERT_TRUE(policy_or.is_ok());
	auto candidate_canonical_or = make_canonical_snapshot("predecessor.candidate", 31);
	ASSERT_TRUE(candidate_canonical_or.is_ok());
	auto candidate_or = terminal_snapshot(candidate_canonical_or.value());
	ASSERT_TRUE(candidate_or.is_ok());
	auto transition_or = store->begin_epoch_transition(candidate_or.value(), "predecessor-key", 0u);
	ASSERT_TRUE(transition_or.is_ok());

	rollback_intent_request request{
		.target_snapshot_id = "predecessor.active",
		.guarded_snapshot_id = "predecessor.candidate",
		.guarded_epoch = transition_or->identity.target_epoch,
		.guarded_revision = candidate_or->revision(),
		.guarded_validation_hash = transition_or->identity.validation_hash,
		.wait_for_mutation_sequence = transition_or->identity.mutation_sequence,
		.policy_generation = policy_or->generation,
		.runtime_generation = 1u,
		.idempotency_key = "predecessor-intent-key",
		.cause = rollback_intent_cause::THRESHOLD_DEGRADATION,
		.observed_monotonic_ns = 200u,
		.created_unix_ms = 2'000,
	};
	ASSERT_TRUE(store->accept_rollback_intent(request).is_ok());
	ASSERT_TRUE(store->discard_orphaned_epoch_transition_after_bootstrap().is_ok());
	EXPECT_FALSE(store->epoch_transition().is_ok());
	EXPECT_FALSE(store->rollback_intent().is_ok());
	auto active_or = store->active_bootstrap();
	ASSERT_TRUE(active_or.is_ok());
	EXPECT_EQ(active_or->active_epoch(), 1u);
	EXPECT_EQ(active_or->allocated_epoch_high_watermark(), 2u);
}

/** @brief Verify a terminal intent survives orphan cleanup and cannot re-arm. */
TEST_F(ConfigStoreTest, terminal_intent_survives_joint_restart_without_rearming)
{
	auto bootstrap_or = make_bootstrap_authority("terminal.guarded", 40);
	ASSERT_TRUE(bootstrap_or.is_ok());
	auto store_or = open_store();
	ASSERT_TRUE(store_or.is_ok());
	auto store = std::move(store_or).value();
	ASSERT_TRUE(store->reconcile_bootstrap(&bootstrap_or.value()).is_ok());
	auto target_or = make_canonical_snapshot("terminal.target", 39);
	ASSERT_TRUE(target_or.is_ok());
	ASSERT_TRUE(store->stage_snapshot(target_or.value()).is_ok());
	auto policy_or = store->configure_guardrails_policy(make_guardrails_policy(), "terminal-policy-key", 0u);
	ASSERT_TRUE(policy_or.is_ok());
	auto intent_request_or =
		make_policy_intent(*store, "terminal.target", policy_or->generation, "terminal-intent-key");
	ASSERT_TRUE(intent_request_or.is_ok());
	ASSERT_TRUE(store->accept_rollback_intent(intent_request_or.value()).is_ok());
	auto target_snapshot_or = store->load_snapshot("terminal.target");
	ASSERT_TRUE(target_snapshot_or.is_ok());
	ASSERT_TRUE(store->begin_epoch_transition(target_snapshot_or.value(), "terminal-intent-key", 0u).is_ok());
	ASSERT_TRUE(store->fail_rollback_intent("terminal-intent-key",
						status::data_loss("retained terminal safety failure"))
			    .is_ok());
	{
		control_loop blocked_reconciliation(store.get(), nullptr);
		const auto blocked = blocked_reconciliation.reconcile_startup(false);
		EXPECT_EQ(blocked.code(), kinetum::common::status_code::FAILED_PRECONDITION);
		auto still_allocated_or = store->epoch_transition();
		ASSERT_TRUE(still_allocated_or.is_ok());
		EXPECT_EQ(still_allocated_or->phase,
			  kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED);
	}
	ASSERT_TRUE(store->discard_orphaned_epoch_transition_after_bootstrap().is_ok());
	EXPECT_FALSE(store->epoch_transition().is_ok());
	store.reset();
	auto restarted_or = open_store();
	ASSERT_TRUE(restarted_or.is_ok()) << restarted_or.error().message();
	auto restarted = std::move(restarted_or).value();
	auto retained_or = restarted->rollback_intent();
	ASSERT_TRUE(retained_or.is_ok());
	EXPECT_EQ(retained_or->terminal_failure.code(), kinetum::common::status_code::DATA_LOSS);
	auto restarted_target_or = restarted->load_snapshot("terminal.target");
	ASSERT_TRUE(restarted_target_or.is_ok());
	auto blocked_or = restarted->begin_epoch_transition(restarted_target_or.value(), "terminal-intent-key", 0u);
	ASSERT_FALSE(blocked_or.is_ok());
	EXPECT_EQ(blocked_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	control_loop loop(restarted.get(), nullptr);
	const auto startup = loop.reconcile_startup(false);
	EXPECT_EQ(startup.code(), kinetum::common::status_code::FAILED_PRECONDITION);
}

}  // namespace
}  // namespace kinetum::cp
