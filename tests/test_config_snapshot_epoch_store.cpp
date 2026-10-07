// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_config_snapshot_epoch_store.cpp
 * @brief Exact canonical-snapshot slot ownership and retirement tests.
 * @author Fleming Patel
 *
 * These tests prove explicit CP-assigned epoch admission, exact two-slot
 * publication, retained ownership, no-nearby lookup, linear claim resolution,
 * slot reuse without ABA, and fail-stop destruction of unresolved claims.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include <google/protobuf/unknown_field_set.h>

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/config_snapshot_epoch_store.hpp"

namespace kinetum::dp
{
namespace
{

using kinetum::common::status;
using kinetum::common::status_or;

/**
 * @brief Produce one genuinely canonical module-free snapshot artifact.
 *
 * @param snapshot_id Stable snapshot identity.
 * @param revision Test revision carried by the snapshot.
 * @return Exact immutable artifact, or the shared canonicalization failure.
 */
[[nodiscard]] status_or<std::unique_ptr<const config_snapshot_artifact>> make_artifact(const std::string &snapshot_id,
										       int64_t revision)
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	snapshot.set_snapshot_id(snapshot_id);
	snapshot.set_revision(revision);
	kinetum::gluon::v1::DeploymentPlan module_free_plan;
	auto canonical_or = kinetum::common::canonicalize_config_snapshot(snapshot, module_free_plan);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	return config_snapshot_artifact::create(canonical_or.value());
}

/**
 * @brief Build and stage one canonical test artifact.
 *
 * @param store Sole store owner.
 * @param epoch Exact caller-assigned epoch.
 * @param snapshot_id Stable artifact identity.
 * @return Exact construction or staging result.
 */
[[nodiscard]] status stage_snapshot(config_snapshot_epoch_store &store, uint64_t epoch, const std::string &snapshot_id)
{
	auto artifact_or = make_artifact(snapshot_id, static_cast<int64_t>(epoch));
	if (!artifact_or.is_ok()) {
		return artifact_or.error();
	}
	auto artifact = std::move(artifact_or).value();
	return store.stage_prepared(epoch, artifact);
}

/**
 * @brief Test owner that resolves every exact slot before store destruction.
 *
 * Ordinary assertion failures must not obscure their diagnostic by triggering
 * the production store's fail-stop destructor. This owner drains only after a
 * test body returns; it is not an alternate production retirement path.
 */
class exact_store_test_owner {
    public:
	exact_store_test_owner() noexcept = default;
	exact_store_test_owner(const exact_store_test_owner &) = delete;
	exact_store_test_owner &operator=(const exact_store_test_owner &) = delete;
	~exact_store_test_owner()
	{
		if (const uint64_t prepared = store_.prepared_epoch(); prepared != 0) {
			auto discarded_or = store_.discard_prepared(prepared);
			if (!discarded_or.is_ok()) {
				std::terminate();
			}
		}
		if (const uint64_t retained = store_.retained_epoch(); retained != 0) {
			auto claim_or = store_.claim_retained(retained);
			if (!claim_or.is_ok()) {
				std::terminate();
			}
			auto claim = std::move(claim_or).value();
			if (!store_.complete_retirement(claim).is_ok()) {
				std::terminate();
			}
		}
		if (const uint64_t active = store_.active_epoch(); active != 0) {
			auto claim_or = store_.claim_published_for_shutdown(active);
			if (!claim_or.is_ok()) {
				std::terminate();
			}
			auto claim = std::move(claim_or).value();
			if (!store_.complete_retirement(claim).is_ok()) {
				std::terminate();
			}
		}
		if (!store_.empty()) {
			std::terminate();
		}
	}

	/** @return Sole exact store used by one test body. */
	[[nodiscard]] config_snapshot_epoch_store &store() noexcept
	{
		return store_;
	}

    private:
	config_snapshot_epoch_store store_;  ///< Exact store under test.
};

/**
 * @brief Verify canonical artifact construction binds identity and rejects nested wire residue.
 */
TEST(config_snapshot_epoch_store, canonical_artifact_binds_exact_identity_and_rejects_mismatch)
{
	auto artifact_or = make_artifact("snapshot.alpha", 17);
	ASSERT_TRUE(artifact_or.is_ok()) << artifact_or.error().message();
	EXPECT_EQ(artifact_or->get()->snapshot().snapshot_id(), "snapshot.alpha");
	EXPECT_EQ(artifact_or->get()->snapshot().revision(), 17);
	EXPECT_FALSE(artifact_or->get()->snapshot().content_hash().empty());

	kinetum::control::v1::ConfigSnapshot snapshot;
	snapshot.set_snapshot_id("snapshot.mismatch");
	kinetum::gluon::v1::DeploymentPlan plan;
	auto canonical_or = kinetum::common::canonicalize_config_snapshot(snapshot, plan);
	ASSERT_TRUE(canonical_or.is_ok()) << canonical_or.error().message();
	canonical_or->validation_hash[0] = static_cast<uint8_t>(canonical_or->validation_hash[0] ^ 0x1u);
	auto mismatched_or = config_snapshot_artifact::create(canonical_or.value());
	ASSERT_FALSE(mismatched_or.is_ok());
	EXPECT_EQ(mismatched_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	auto forged = canonical_or.value();
	kinetum::control::v1::ConfigSnapshot forged_snapshot;
	ASSERT_TRUE(forged_snapshot.ParseFromString(forged.serialized_bytes));
	forged.validation_hash.fill(0);
	forged_snapshot.set_content_hash(std::string(64, '0'));
	auto forged_bytes_or = kinetum::common::serialize_protobuf_deterministically(forged_snapshot);
	ASSERT_TRUE(forged_bytes_or.is_ok()) << forged_bytes_or.error().message();
	forged.serialized_bytes = std::move(forged_bytes_or).value();
	auto forged_or = config_snapshot_artifact::create(forged);
	ASSERT_FALSE(forged_or.is_ok());
	EXPECT_EQ(forged_or.error().code(), kinetum::common::status_code::DATA_LOSS);

	auto unknown = canonical_or.value();
	kinetum::control::v1::ConfigSnapshot unknown_snapshot;
	ASSERT_TRUE(unknown_snapshot.ParseFromString(unknown.serialized_bytes));
	unknown_snapshot.GetReflection()->MutableUnknownFields(&unknown_snapshot)->AddLengthDelimited(5, "");
	auto unknown_bytes_or = kinetum::common::serialize_protobuf_deterministically(unknown_snapshot);
	ASSERT_TRUE(unknown_bytes_or.is_ok()) << unknown_bytes_or.error().message();
	unknown.serialized_bytes = std::move(unknown_bytes_or).value();
	auto unknown_or = config_snapshot_artifact::create(unknown);
	ASSERT_FALSE(unknown_or.is_ok());
	EXPECT_EQ(unknown_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify the store starts as exactly two empty slots with no inferred epoch.
 */
TEST(config_snapshot_epoch_store, starts_empty_with_exact_two_slot_layout)
{
	exact_store_test_owner owner;
	auto &store = owner.store();
	EXPECT_TRUE(store.empty());
	EXPECT_EQ(store.active_epoch(), 0u);
	EXPECT_EQ(store.prepared_epoch(), 0u);
	EXPECT_EQ(store.retained_epoch(), 0u);
	EXPECT_EQ(store.active_artifact(), nullptr);
	EXPECT_EQ(store.find_exact(1), nullptr);
	for (std::size_t slot_index = 0; slot_index < EXACT_EPOCH_SLOT_COUNT; ++slot_index) {
		const auto *slot = store.slot(slot_index);
		ASSERT_NE(slot, nullptr);
		EXPECT_EQ(slot->epoch, 0u);
		EXPECT_EQ(slot->state, epoch_slot_state::EMPTY);
	}
}

/**
 * @brief Verify zero epoch rejects without consuming caller artifact ownership.
 */
TEST(config_snapshot_epoch_store, stage_requires_nonzero_epoch_and_preserves_failed_ownership)
{
	exact_store_test_owner owner;
	auto artifact_or = make_artifact("snapshot.zero", 1);
	ASSERT_TRUE(artifact_or.is_ok()) << artifact_or.error().message();
	auto artifact = std::move(artifact_or).value();
	const auto *identity = artifact.get();

	const auto staged = owner.store().stage_prepared(0, artifact);
	EXPECT_FALSE(staged.is_ok());
	EXPECT_EQ(staged.code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(artifact.get(), identity);
	EXPECT_TRUE(owner.store().empty());
}

/**
 * @brief Verify explicit PREPARE is observable without changing active ownership.
 */
TEST(config_snapshot_epoch_store, stage_publishes_exact_prepared_artifact_without_activation)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 7, "snapshot.prepared").is_ok());
	EXPECT_EQ(owner.store().prepared_epoch(), 7u);
	EXPECT_EQ(owner.store().active_epoch(), 0u);
	ASSERT_NE(owner.store().find_exact(7), nullptr);
	EXPECT_EQ(owner.store().find_exact(7)->snapshot().snapshot_id(), "snapshot.prepared");
	EXPECT_EQ(owner.store().find_exact(6), nullptr);
}

/**
 * @brief Verify pre-commit discard returns exact ownership and reopens the slot.
 */
TEST(config_snapshot_epoch_store, discard_returns_exact_artifact_and_reopens_slot)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 9, "snapshot.abort").is_ok());
	auto discarded_or = owner.store().discard_prepared(9);
	ASSERT_TRUE(discarded_or.is_ok()) << discarded_or.error().message();
	EXPECT_EQ(discarded_or->get()->snapshot().snapshot_id(), "snapshot.abort");
	EXPECT_TRUE(owner.store().empty());
	EXPECT_TRUE(stage_snapshot(owner.store(), 13, "snapshot.replacement").is_ok());
}

/**
 * @brief Verify bootstrap publication owns one explicit active slot and artifact.
 */
TEST(config_snapshot_epoch_store, bootstrap_publication_owns_exact_active_slot)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 11, "snapshot.bootstrap").is_ok());
	ASSERT_TRUE(owner.store().preflight_publish_prepared(11).is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(11).is_ok());
	EXPECT_EQ(owner.store().prepared_epoch(), 0u);
	EXPECT_EQ(owner.store().active_epoch(), 11u);
	EXPECT_EQ(owner.store().retained_epoch(), 0u);
	ASSERT_NE(owner.store().active_artifact(), nullptr);
	EXPECT_EQ(owner.store().active_artifact()->snapshot().snapshot_id(), "snapshot.bootstrap");
}

/**
 * @brief Verify gaps are legal while duplicate and older exact epochs fail closed.
 */
TEST(config_snapshot_epoch_store, gaps_are_valid_but_duplicate_and_older_epochs_reject)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 17, "snapshot.active").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(17).is_ok());

	auto duplicate_or = make_artifact("snapshot.duplicate", 17);
	ASSERT_TRUE(duplicate_or.is_ok()) << duplicate_or.error().message();
	auto duplicate = std::move(duplicate_or).value();
	const auto duplicate_status = owner.store().stage_prepared(17, duplicate);
	EXPECT_FALSE(duplicate_status.is_ok());
	EXPECT_NE(duplicate, nullptr);

	auto older_or = make_artifact("snapshot.older", 3);
	ASSERT_TRUE(older_or.is_ok()) << older_or.error().message();
	auto older = std::move(older_or).value();
	const auto older_status = owner.store().stage_prepared(3, older);
	EXPECT_FALSE(older_status.is_ok());
	EXPECT_NE(older, nullptr);

	EXPECT_TRUE(stage_snapshot(owner.store(), 29, "snapshot.gapped").is_ok());
	EXPECT_EQ(owner.store().prepared_epoch(), 29u);
}

/**
 * @brief Verify a second publication retains the prior exact snapshot.
 */
TEST(config_snapshot_epoch_store, second_publication_retains_prior_exact_artifact)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 5, "snapshot.old").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(5).is_ok());
	ASSERT_TRUE(owner.store().preflight_future_preparation(5, 8).is_ok());
	ASSERT_TRUE(stage_snapshot(owner.store(), 8, "snapshot.new").is_ok());
	ASSERT_TRUE(owner.store().preflight_future_retained(5, 8).is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(8).is_ok());
	ASSERT_TRUE(owner.store().preflight_claim_retained(5).is_ok());

	EXPECT_EQ(owner.store().active_epoch(), 8u);
	EXPECT_EQ(owner.store().retained_epoch(), 5u);
	ASSERT_NE(owner.store().find_exact(5), nullptr);
	ASSERT_NE(owner.store().find_exact(8), nullptr);
	EXPECT_EQ(owner.store().find_exact(5)->snapshot().snapshot_id(), "snapshot.old");
	EXPECT_EQ(owner.store().find_exact(8)->snapshot().snapshot_id(), "snapshot.new");
}

/**
 * @brief Verify an unknown epoch never resolves to current, previous, or nearest.
 */
TEST(config_snapshot_epoch_store, exact_lookup_never_maps_unknown_epoch_to_nearby_artifact)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 101, "snapshot.101").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(101).is_ok());
	ASSERT_TRUE(stage_snapshot(owner.store(), 1001, "snapshot.1001").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(1001).is_ok());

	EXPECT_EQ(owner.store().find_exact(0), nullptr);
	EXPECT_EQ(owner.store().find_exact(100), nullptr);
	EXPECT_EQ(owner.store().find_exact(102), nullptr);
	EXPECT_EQ(owner.store().find_exact(1000), nullptr);
	EXPECT_EQ(owner.store().find_exact(1002), nullptr);
}

/**
 * @brief Verify two owned slots block a third PREPARE until exact retirement.
 */
TEST(config_snapshot_epoch_store, third_preparation_waits_for_retained_retirement)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 1, "snapshot.one").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(1).is_ok());
	ASSERT_TRUE(stage_snapshot(owner.store(), 2, "snapshot.two").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(2).is_ok());

	auto third_or = make_artifact("snapshot.three", 3);
	ASSERT_TRUE(third_or.is_ok()) << third_or.error().message();
	auto third = std::move(third_or).value();
	const auto rejected = owner.store().stage_prepared(3, third);
	EXPECT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.code(), kinetum::common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_NE(third, nullptr);
}

/**
 * @brief Verify restoring a retained claim preserves exact state and identity.
 */
TEST(config_snapshot_epoch_store, retained_claim_restore_preserves_exact_slot_and_artifact)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 31, "snapshot.retained").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(31).is_ok());
	ASSERT_TRUE(stage_snapshot(owner.store(), 47, "snapshot.active").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(47).is_ok());

	auto claim_or = owner.store().claim_retained(31);
	ASSERT_TRUE(claim_or.is_ok()) << claim_or.error().message();
	auto claim = std::move(claim_or).value();
	EXPECT_NE(claim.claim_id(), 0u);
	EXPECT_EQ(claim.epoch(), 31u);
	EXPECT_EQ(claim.slot_state(), epoch_slot_state::RETAINED);
	ASSERT_NE(claim.artifact(), nullptr);
	EXPECT_EQ(claim.artifact()->snapshot().snapshot_id(), "snapshot.retained");
	EXPECT_EQ(owner.store().find_exact(31), nullptr);

	ASSERT_TRUE(owner.store().restore_retirement(claim).is_ok());
	EXPECT_EQ(claim.claim_id(), 0u);
	ASSERT_NE(owner.store().find_exact(31), nullptr);
	EXPECT_EQ(owner.store().retained_epoch(), 31u);
}

/**
 * @brief Verify retained completion reopens one slot for a later exact epoch.
 */
TEST(config_snapshot_epoch_store, retained_completion_reopens_slot_for_later_epoch)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 2, "snapshot.retained").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(2).is_ok());
	ASSERT_TRUE(stage_snapshot(owner.store(), 9, "snapshot.active").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(9).is_ok());
	auto claim_or = owner.store().claim_retained(2);
	ASSERT_TRUE(claim_or.is_ok()) << claim_or.error().message();
	auto claim = std::move(claim_or).value();
	ASSERT_TRUE(owner.store().complete_retirement(claim).is_ok());

	EXPECT_EQ(owner.store().retained_epoch(), 0u);
	EXPECT_EQ(owner.store().find_exact(2), nullptr);
	EXPECT_TRUE(stage_snapshot(owner.store(), 15, "snapshot.later").is_ok());
	EXPECT_EQ(owner.store().prepared_epoch(), 15u);
}

/**
 * @brief Verify published shutdown claims can restore or empty the exact store.
 */
TEST(config_snapshot_epoch_store, published_shutdown_claim_restores_or_empties_exact_store)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 23, "snapshot.shutdown").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(23).is_ok());

	auto restore_or = owner.store().claim_published_for_shutdown(23);
	ASSERT_TRUE(restore_or.is_ok()) << restore_or.error().message();
	auto restored = std::move(restore_or).value();
	EXPECT_EQ(owner.store().active_epoch(), 0u);
	EXPECT_EQ(owner.store().active_artifact(), nullptr);
	ASSERT_TRUE(owner.store().restore_retirement(restored).is_ok());
	EXPECT_EQ(owner.store().active_epoch(), 23u);

	auto complete_or = owner.store().claim_published_for_shutdown(23);
	ASSERT_TRUE(complete_or.is_ok()) << complete_or.error().message();
	auto completed = std::move(complete_or).value();
	ASSERT_TRUE(owner.store().complete_retirement(completed).is_ok());
	EXPECT_TRUE(owner.store().empty());
}

/**
 * @brief Verify claims are bound to one issuing store and one outstanding nonce.
 */
TEST(config_snapshot_epoch_store, claims_are_store_bound_and_single_outstanding)
{
	exact_store_test_owner first_owner;
	exact_store_test_owner second_owner;
	ASSERT_TRUE(stage_snapshot(first_owner.store(), 41, "snapshot.first").is_ok());
	ASSERT_TRUE(first_owner.store().publish_prepared(41).is_ok());
	ASSERT_TRUE(stage_snapshot(second_owner.store(), 43, "snapshot.second").is_ok());
	ASSERT_TRUE(second_owner.store().publish_prepared(43).is_ok());

	auto claim_or = first_owner.store().claim_published_for_shutdown(41);
	ASSERT_TRUE(claim_or.is_ok()) << claim_or.error().message();
	auto claim = std::move(claim_or).value();
	EXPECT_FALSE(first_owner.store().claim_published_for_shutdown(41).is_ok());
	EXPECT_FALSE(second_owner.store().restore_retirement(claim).is_ok());
	EXPECT_NE(claim.claim_id(), 0u);
	EXPECT_TRUE(first_owner.store().restore_retirement(claim).is_ok());
}

/**
 * @brief Verify an unresolved linear retirement claim cannot disappear silently.
 */
TEST(config_snapshot_epoch_store, unresolved_claim_fails_stop)
{
	EXPECT_DEATH(
		{
			config_snapshot_epoch_store store;
			auto artifact_or = make_artifact("snapshot.unresolved", 1);
			if (!artifact_or.is_ok()) {
				std::terminate();
			}
			auto artifact = std::move(artifact_or).value();
			if (!store.stage_prepared(1, artifact).is_ok() || !store.publish_prepared(1).is_ok()) {
				std::terminate();
			}
			auto claim_or = store.claim_published_for_shutdown(1);
			if (!claim_or.is_ok()) {
				std::terminate();
			}
		},
		"");
}

/**
 * @brief Verify slot reuse never revives a retired epoch or stale artifact.
 */
TEST(config_snapshot_epoch_store, publish_retain_retire_reuse_has_no_aba)
{
	exact_store_test_owner owner;
	ASSERT_TRUE(stage_snapshot(owner.store(), 11, "snapshot.A").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(11).is_ok());
	ASSERT_TRUE(stage_snapshot(owner.store(), 23, "snapshot.B").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(23).is_ok());

	auto retired_or = owner.store().claim_retained(11);
	ASSERT_TRUE(retired_or.is_ok()) << retired_or.error().message();
	auto retired = std::move(retired_or).value();
	ASSERT_TRUE(owner.store().complete_retirement(retired).is_ok());
	ASSERT_TRUE(stage_snapshot(owner.store(), 41, "snapshot.C").is_ok());
	ASSERT_TRUE(owner.store().publish_prepared(41).is_ok());

	EXPECT_EQ(owner.store().find_exact(11), nullptr);
	ASSERT_NE(owner.store().find_exact(23), nullptr);
	ASSERT_NE(owner.store().find_exact(41), nullptr);
	EXPECT_EQ(owner.store().find_exact(23)->snapshot().snapshot_id(), "snapshot.B");
	EXPECT_EQ(owner.store().find_exact(41)->snapshot().snapshot_id(), "snapshot.C");
	EXPECT_EQ(owner.store().retained_epoch(), 23u);
	EXPECT_EQ(owner.store().active_epoch(), 41u);
}

}  // namespace
}  // namespace kinetum::dp
