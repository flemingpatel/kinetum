// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_content_identity.cpp
 * @brief Unit tests for canonical snapshot and deployment-plan identities.
 * @author Fleming Patel
 *
 * The suite pins set-like ConfigSnapshot normalization, opaque blob handling,
 * exact module-set admission, recursive unknown-field rejection, snapshot
 * bounds, plan volatile fields, contractual repeated order, required hash
 * verification, and exact public degradation-fixture deltas.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory_resource>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/message.h>
#include <google/protobuf/unknown_field_set.h>
#include <google/protobuf/util/message_differencer.h>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/execution/cpu/v1/cpu_execution.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "gen/kinetum/storage/host/v1/host_storage.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/file_io.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_service_ids.hpp"
#include "src/common/sha256.hpp"
#include "src/modules/acl/acl_impl.hpp"
#include "src/provider/deployment_plan_identity.hpp"

namespace kinetum::common
{

namespace
{

using kinetum::control::v1::ConfigSnapshot;
using kinetum::gluon::v1::DeploymentPlan;

/** Distinctive context capacity included in the independently pinned identity vector. */
constexpr uint64_t KNOWN_ANSWER_CONTEXT_CAPACITY_BYTES = 4097u;
/** Distinctive epoch capacity included in the independently pinned identity vector. */
constexpr uint64_t KNOWN_ANSWER_EPOCH_CAPACITY_BYTES = 8193u;

/**
 * @brief Construct a minimal plan whose module set is explicit and stable.
 *
 * @param module_ids Module IDs emitted in pipeline repeated-field order.
 * @return Minimal DeploymentPlan suitable for cold identity tests.
 */
DeploymentPlan make_module_plan(const std::vector<std::string> &module_ids)
{
	DeploymentPlan plan;
	plan.set_plan_id("plan_identity_v5");
	plan.mutable_pipeline()->set_pipeline_id("identity_pipeline");
	for (std::size_t index = 0; index < module_ids.size(); ++index) {
		auto *stage = plan.mutable_pipeline()->add_stages();
		stage->set_stage_id("module_stage_" + std::to_string(index));
		stage->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
		stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		stage->mutable_module()->set_module_id(module_ids[index]);
		stage->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	}
	kinetum::execution::cpu::v1::CpuExecutionConfig execution_configuration;
	auto *execution = plan.add_execution_provider_instances();
	execution->set_execution_provider_instance_id("execution_cpu_0");
	execution->mutable_configuration()->PackFrom(execution_configuration);
	return plan;
}

/**
 * @brief Add one exact lane-local module context to an identity-test plan.
 *
 * @param plan Mutable plan containing the corresponding logical module stage.
 * @param module_index Logical module-stage index in @p plan.
 * @param context_capacity Exact nonzero context-lifetime byte capacity.
 * @param epoch_capacity Exact nonzero byte capacity of each epoch arena.
 * @return Mutable stage-instance record for optional test-specific facts.
 */
kinetum::gluon::v1::StageInstance *add_module_stage_instance(DeploymentPlan &plan, std::size_t module_index,
							     uint64_t context_capacity, uint64_t epoch_capacity)
{
	const std::string stage_id = "module_stage_" + std::to_string(module_index);
	const std::string instance_id = stage_id + "@lane_0";
	auto *instance = plan.add_stage_instances();
	instance->set_stage_instance_id(instance_id);
	instance->set_logical_stage_id(stage_id);
	instance->set_lane_id("lane_0");
	instance->set_region_id(0);
	instance->set_context_instance_id(instance_id);
	instance->set_execution_provider_instance_id("execution_cpu_0");
	instance->set_context_memory_capacity_bytes(context_capacity);
	instance->set_epoch_arena_capacity_bytes(epoch_capacity);
	return instance;
}

/**
 * @brief Construct a snapshot with caller-selected module emission order.
 *
 * @param modules Ordered pairs of module ID and exact opaque blob bytes.
 * @return Complete ConfigSnapshot candidate with no supplied hash claims.
 */
ConfigSnapshot make_snapshot(const std::vector<std::pair<std::string, std::string>> &modules)
{
	ConfigSnapshot snapshot;
	snapshot.set_snapshot_id("snapshot_identity_v5");
	snapshot.set_revision(7);
	for (const auto &[module_id, blob] : modules) {
		auto *module = snapshot.add_modules();
		module->set_module_id(module_id);
		module->set_revision(3);
		module->set_config_blob(blob);
		module->set_content_type("application/protobuf");
		module->set_schema_id("test.schema.v1");
	}
	return snapshot;
}

/**
 * @brief Inject one unknown wire field into an owned protobuf message.
 *
 * @param message Message whose unknown-field set is mutated for rejection
 *                testing.
 */
void inject_unknown_field(google::protobuf::Message *message)
{
	ASSERT_NE(message, nullptr);
	message->GetReflection()->MutableUnknownFields(message)->AddVarint(19'001, 1);
}

/**
 * @brief Parse canonical bytes and require one complete ConfigSnapshot.
 *
 * @param bytes Deterministic bytes returned by the canonicalizer.
 * @return Parsed ConfigSnapshot; the helper records a test failure when parsing
 *         fails.
 */
ConfigSnapshot parse_canonical_snapshot(const std::string &bytes)
{
	ConfigSnapshot parsed;
	EXPECT_TRUE(parsed.ParseFromString(bytes));
	return parsed;
}

/**
 * @brief Construct the service-bearing plan pinned by the mailbox-capacity KAT.
 *
 * @param capacity Exact coordinator command slots.
 * @return Minimal deterministic plan carrying one coordinator placement.
 */
DeploymentPlan make_service_capacity_plan(uint32_t capacity)
{
	DeploymentPlan plan;
	plan.set_plan_id("service_capacity_identity_v1");
	auto *service = plan.add_runtime_service_placements();
	service->set_service_id(std::string(runtime_services::EPOCH_TRANSITION_COORDINATOR_ID));
	service->set_service_kind(kinetum::gluon::v1::RUNTIME_SERVICE_KIND_EPOCH_TRANSITION_COORDINATOR);
	service->set_cpu_core_id(7);
	service->set_numa_node(2);
	service->set_command_mailbox_capacity(capacity);
	return plan;
}

/**
 * @brief Construct one source-staging plan identity at the permanent field-6 shape.
 *
 * @param capacity Exact per-queue source epoch-staging capacity.
 * @return Minimal deterministic plan carrying one source worker.
 */
DeploymentPlan make_source_staging_capacity_plan(uint32_t capacity)
{
	DeploymentPlan plan;
	plan.set_plan_id("source_staging_capacity_identity_v1");
	auto *worker = plan.add_worker_placements();
	worker->set_worker_id("worker_r0_lane_0");
	worker->set_region_id(0);
	worker->set_lane_id("lane_0");
	worker->set_worker_index(0u);
	worker->add_cpu_core_ids(2);
	worker->set_source_epoch_staging_capacity(capacity);
	return plan;
}

}  // namespace

/**
 * @brief Pin byte-exact canonical plan and snapshot identities against future drift.
 *
 * The plan vector includes explicit module-context selection, lifecycle
 * capacities, and the CPU provider envelope. Snapshot bytes and their hash
 * are pinned independently.
 */
TEST(content_identity, canonical_plan_and_snapshot_match_known_answer_vectors)
{
	auto plan = make_module_plan({"module.alpha"});
	(void)add_module_stage_instance(plan, 0u, KNOWN_ANSWER_CONTEXT_CAPACITY_BYTES,
					KNOWN_ANSWER_EPOCH_CAPACITY_BYTES);
	auto plan_hash_or = kinetum::provider::compute_deployment_plan_content_hash(plan);
	ASSERT_TRUE(plan_hash_or.is_ok()) << plan_hash_or.error().message();
	EXPECT_EQ(plan_hash_or.value(), "d60a9a70c94a7e72d0a1a2aaa8cb32ced5ae021963a884a7e3c9538431415dbd");
	auto plan_bytes_or = serialize_protobuf_deterministically(plan);
	ASSERT_TRUE(plan_bytes_or.is_ok()) << plan_bytes_or.error().message();
	EXPECT_EQ(bytes_to_hex(reinterpret_cast<const uint8_t *>(plan_bytes_or->data()), plan_bytes_or->size()),
		  "0a10706c616e5f6964656e746974795f7635123b0a116964656e746974795f706970656c696e6512260a0e"
		  "6d6f64756c655f73746167655f30100b22100a0c6d6f64756c652e616c7068611801480252540a0f657865"
		  "637574696f6e5f6370755f301a410a3f747970652e676f6f676c65617069732e636f6d2f6b696e6574756d"
		  "2e657865637574696f6e2e6370752e76312e437075457865637574696f6e436f6e666967725d0a156d6f6475"
		  "6c655f73746167655f30406c616e655f30120e6d6f64756c655f73746167655f301a066c616e655f3032156d"
		  "6f64756c655f73746167655f30406c616e655f30420f657865637574696f6e5f6370755f30508120588140");

	const auto snapshot = make_snapshot({{"module.alpha", "known-answer-config"}});
	auto snapshot_or = canonicalize_config_snapshot(snapshot, plan);
	ASSERT_TRUE(snapshot_or.is_ok()) << snapshot_or.error().message();
	EXPECT_EQ(bytes_to_hex(snapshot_or.value().validation_hash.data(), snapshot_or.value().validation_hash.size()),
		  "0341d86890bb7d5fd53c428be12d0ad24c29480c1c6daf9c0ecb6139a482f4d7");
	EXPECT_EQ(bytes_to_hex(reinterpret_cast<const uint8_t *>(snapshot_or.value().serialized_bytes.data()),
			       snapshot_or.value().serialized_bytes.size()),
		  "0a14736e617073686f745f6964656e746974795f76351007228d010a0c6d6f64756c652e616c7068611003"
		  "1a136b6e6f776e2d616e737765722d636f6e66696722146170706c69636174696f6e2f70726f746f627566"
		  "2a40386139326564633233653434393162306435363639336432633835666632626635306462336434643562"
		  "33306637616138343862393730343561323961353930320e746573742e736368656d612e76315a4030333431"
		  "6438363839306262376435666435336334323862653132643061643234633239343830633163366461663963"
		  "30656362363133396134383266346437");
}

/** @brief Pin one exact service-bearing plan identity including mailbox capacity. */
TEST(content_identity, runtime_service_mailbox_capacity_matches_known_answer_vector)
{
	const auto hash_or = kinetum::provider::compute_deployment_plan_content_hash(make_service_capacity_plan(64u));
	ASSERT_TRUE(hash_or.is_ok()) << hash_or.error().message();
	EXPECT_EQ(hash_or.value(), "581259da0d9318defde1fd7a1c828cc59574e531e980b0eb15881b02303bc7c1");
}

/** @brief Verify coordinator command capacity is part of canonical plan identity. */
TEST(content_identity, runtime_service_mailbox_capacity_changes_plan_identity)
{
	const auto baseline_or =
		kinetum::provider::compute_deployment_plan_content_hash(make_service_capacity_plan(64u));
	const auto changed_or =
		kinetum::provider::compute_deployment_plan_content_hash(make_service_capacity_plan(32u));
	ASSERT_TRUE(baseline_or.is_ok()) << baseline_or.error().message();
	ASSERT_TRUE(changed_or.is_ok()) << changed_or.error().message();
	EXPECT_NE(baseline_or.value(), changed_or.value());
}

/** @brief Prove source epoch-staging capacity remains hash-sensitive at field 6. */
TEST(content_identity, source_epoch_staging_capacity_changes_plan_identity)
{
	const auto baseline_or =
		kinetum::provider::compute_deployment_plan_content_hash(make_source_staging_capacity_plan(1024u));
	const auto changed_or =
		kinetum::provider::compute_deployment_plan_content_hash(make_source_staging_capacity_plan(2048u));
	ASSERT_TRUE(baseline_or.is_ok()) << baseline_or.error().message();
	ASSERT_TRUE(changed_or.is_ok()) << changed_or.error().message();
	EXPECT_NE(baseline_or.value(), changed_or.value());
}

/**
 * @brief Verify set-like module/label construction order cannot change identity.
 */
TEST(content_identity, snapshot_normalizes_set_like_construction_order)
{
	const auto plan = make_module_plan({"module.alpha", "module.beta"});
	auto first = make_snapshot({{"module.beta", "beta-blob"}, {"module.alpha", "alpha-blob"}});
	(*first.mutable_labels())["zeta"] = "last";
	(*first.mutable_labels())["alpha"] = "first";
	auto second = make_snapshot({{"module.alpha", "alpha-blob"}, {"module.beta", "beta-blob"}});
	(*second.mutable_labels())["alpha"] = "first";
	(*second.mutable_labels())["zeta"] = "last";

	auto first_or = canonicalize_config_snapshot(first, plan);
	auto second_or = canonicalize_config_snapshot(second, plan);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	EXPECT_EQ(first_or.value().validation_hash, second_or.value().validation_hash);
	EXPECT_EQ(first_or.value().serialized_bytes, second_or.value().serialized_bytes);

	const auto canonical = parse_canonical_snapshot(first_or.value().serialized_bytes);
	ASSERT_EQ(canonical.modules_size(), 2);
	EXPECT_EQ(canonical.modules(0).module_id(), "module.alpha");
	EXPECT_EQ(canonical.modules(1).module_id(), "module.beta");
	EXPECT_EQ(canonical.content_hash(),
		  bytes_to_hex(first_or.value().validation_hash.data(), first_or.value().validation_hash.size()));
	for (const auto &module : canonical.modules()) {
		auto expected_hash_or = sha256_hex(module.config_blob());
		ASSERT_TRUE(expected_hash_or.is_ok()) << expected_hash_or.error().message();
		EXPECT_EQ(module.content_hash(), expected_hash_or.value());
	}
}

/** @brief Prove live CP module-set admission delegates to the plan canonicalizer. */
TEST(content_identity, active_snapshot_module_set_uses_the_same_canonicalizer)
{
	const auto plan = make_module_plan({"module.alpha", "module.beta"});
	auto active_input = make_snapshot({{"module.beta", "beta-old"}, {"module.alpha", "alpha-old"}});
	auto active_or = canonicalize_config_snapshot(active_input, plan);
	ASSERT_TRUE(active_or.is_ok()) << active_or.error().message();
	const auto active = parse_canonical_snapshot(active_or->serialized_bytes);

	auto candidate = make_snapshot({{"module.beta", "beta-new"}, {"module.alpha", "alpha-new"}});
	candidate.set_snapshot_id("snapshot_live_candidate");
	candidate.set_revision(8);
	auto plan_or = canonicalize_config_snapshot(candidate, plan);
	auto active_shape_or = canonicalize_config_snapshot(candidate, active);
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	ASSERT_TRUE(active_shape_or.is_ok()) << active_shape_or.error().message();
	EXPECT_EQ(active_shape_or->serialized_bytes, plan_or->serialized_bytes);
	EXPECT_EQ(active_shape_or->validation_hash, plan_or->validation_hash);

	auto missing = make_snapshot({{"module.alpha", "alpha-new"}});
	missing.set_snapshot_id("snapshot_live_missing");
	EXPECT_FALSE(canonicalize_config_snapshot(missing, active).is_ok());
	auto extra =
		make_snapshot({{"module.alpha", "alpha-new"}, {"module.beta", "beta-new"}, {"module.gamma", "gamma"}});
	extra.set_snapshot_id("snapshot_live_extra");
	EXPECT_FALSE(canonicalize_config_snapshot(extra, active).is_ok());

	auto malformed_active = active;
	malformed_active.mutable_modules(0)->set_content_hash(std::string(SHA256_HEX_LENGTH, '0'));
	auto malformed_or = canonicalize_config_snapshot(candidate, malformed_active);
	ASSERT_FALSE(malformed_or.is_ok());
	EXPECT_EQ(malformed_or.error().code(), status_code::DATA_LOSS);
}

/**
 * @brief Verify missing, unknown, and duplicate snapshot modules all fail closed.
 */
TEST(content_identity, snapshot_requires_exact_two_directional_module_set)
{
	const auto plan = make_module_plan({"module.alpha", "module.beta"});

	auto missing_or = canonicalize_config_snapshot(make_snapshot({{"module.alpha", "a"}}), plan);
	ASSERT_FALSE(missing_or.is_ok());
	EXPECT_NE(missing_or.error().message().find("missing required module_id"), std::string::npos);

	auto unknown_or = canonicalize_config_snapshot(
		make_snapshot({{"module.alpha", "a"}, {"module.beta", "b"}, {"module.gamma", "c"}}), plan);
	ASSERT_FALSE(unknown_or.is_ok());
	EXPECT_NE(unknown_or.error().message().find("outside the expected set"), std::string::npos);

	auto duplicate_or = canonicalize_config_snapshot(
		make_snapshot({{"module.alpha", "a"}, {"module.alpha", "b"}, {"module.beta", "c"}}), plan);
	ASSERT_FALSE(duplicate_or.is_ok());
	EXPECT_NE(duplicate_or.error().message().find("duplicate module_id"), std::string::npos);
}

/**
 * @brief Verify blob bytes resembling an unknown wire tag remain opaque and exact.
 */
TEST(content_identity, snapshot_never_parses_opaque_module_blob_bytes)
{
	const auto plan = make_module_plan({"module.alpha"});
	const std::string opaque_blob("\xf8\x07\x01\x00\xff", 5);
	const auto snapshot = make_snapshot({{"module.alpha", opaque_blob}});

	auto canonical_or = canonicalize_config_snapshot(snapshot, plan);
	ASSERT_TRUE(canonical_or.is_ok()) << canonical_or.error().message();
	const auto canonical = parse_canonical_snapshot(canonical_or.value().serialized_bytes);
	ASSERT_EQ(canonical.modules_size(), 1);
	EXPECT_EQ(canonical.modules(0).config_blob(), opaque_blob);
}

/**
 * @brief Verify supplied module and snapshot hashes are claims, never authority.
 */
TEST(content_identity, snapshot_hash_claims_must_match_recomputation)
{
	const auto plan = make_module_plan({"module.alpha"});
	auto initial_or = canonicalize_config_snapshot(make_snapshot({{"module.alpha", "alpha-blob"}}), plan);
	ASSERT_TRUE(initial_or.is_ok()) << initial_or.error().message();
	const auto canonical_claims = parse_canonical_snapshot(initial_or.value().serialized_bytes);

	auto exact_retry_or = canonicalize_config_snapshot(canonical_claims, plan);
	ASSERT_TRUE(exact_retry_or.is_ok()) << exact_retry_or.error().message();
	EXPECT_EQ(exact_retry_or.value().serialized_bytes, initial_or.value().serialized_bytes);
	EXPECT_EQ(exact_retry_or.value().validation_hash, initial_or.value().validation_hash);

	auto bad_module = make_snapshot({{"module.alpha", "alpha-blob"}});
	bad_module.mutable_modules(0)->set_content_hash(std::string(SHA256_HEX_LENGTH, '0'));
	auto bad_module_or = canonicalize_config_snapshot(bad_module, plan);
	ASSERT_FALSE(bad_module_or.is_ok());
	EXPECT_EQ(bad_module_or.error().code(), status_code::DATA_LOSS);

	auto malformed_module = make_snapshot({{"module.alpha", "alpha-blob"}});
	malformed_module.mutable_modules(0)->set_content_hash(std::string(SHA256_HEX_LENGTH, 'A'));
	auto malformed_module_or = canonicalize_config_snapshot(malformed_module, plan);
	ASSERT_FALSE(malformed_module_or.is_ok());
	EXPECT_EQ(malformed_module_or.error().code(), status_code::INVALID_ARGUMENT);

	auto bad_snapshot = make_snapshot({{"module.alpha", "alpha-blob"}});
	bad_snapshot.set_content_hash(std::string(SHA256_HEX_LENGTH, '0'));
	auto bad_snapshot_or = canonicalize_config_snapshot(bad_snapshot, plan);
	ASSERT_FALSE(bad_snapshot_or.is_ok());
	EXPECT_EQ(bad_snapshot_or.error().code(), status_code::DATA_LOSS);

	auto malformed_snapshot = make_snapshot({{"module.alpha", "alpha-blob"}});
	malformed_snapshot.set_content_hash(std::string(SHA256_HEX_LENGTH, 'A'));
	auto malformed_snapshot_or = canonicalize_config_snapshot(malformed_snapshot, plan);
	ASSERT_FALSE(malformed_snapshot_or.is_ok());
	EXPECT_EQ(malformed_snapshot_or.error().code(), status_code::INVALID_ARGUMENT);

	auto forged_terminal = initial_or.value();
	auto forged_snapshot = canonical_claims;
	forged_snapshot.set_content_hash(std::string(SHA256_HEX_LENGTH, '0'));
	auto forged_bytes_or = serialize_protobuf_deterministically(forged_snapshot);
	ASSERT_TRUE(forged_bytes_or.is_ok()) << forged_bytes_or.error().message();
	forged_terminal.serialized_bytes = std::move(forged_bytes_or).value();
	ConfigSnapshot terminal_output;
	terminal_output.set_snapshot_id("poison");
	const auto terminal_status = admit_terminal_config_snapshot(forged_terminal, &terminal_output);
	EXPECT_FALSE(terminal_status.is_ok());
	EXPECT_EQ(terminal_status.code(), status_code::DATA_LOSS);
	EXPECT_EQ(terminal_output.ByteSizeLong(), 0u);
}

/**
 * @brief Verify unknown fields are rejected in the protobuf tree, including nesting.
 */
TEST(content_identity, snapshot_rejects_recursive_unknown_protobuf_fields)
{
	const auto plan = make_module_plan({"module.alpha"});
	auto top_level = make_snapshot({{"module.alpha", "blob"}});
	inject_unknown_field(&top_level);
	EXPECT_FALSE(canonicalize_config_snapshot(top_level, plan).is_ok());

	auto nested = make_snapshot({{"module.alpha", "blob"}});
	inject_unknown_field(nested.mutable_modules(0));
	EXPECT_FALSE(canonicalize_config_snapshot(nested, plan).is_ok());
}

/**
 * @brief Verify admitted input scalars and both serialized representations are bounded.
 */
TEST(content_identity, snapshot_enforces_input_and_canonical_size_bounds)
{
	const auto plan = make_module_plan({"module.alpha"});
	{
		auto missing_id = make_snapshot({{"module.alpha", "blob"}});
		missing_id.clear_snapshot_id();
		auto missing_id_or = canonicalize_config_snapshot(missing_id, plan);
		ASSERT_FALSE(missing_id_or.is_ok());
		EXPECT_EQ(missing_id_or.error().code(), status_code::INVALID_ARGUMENT);

		auto oversized_id = make_snapshot({{"module.alpha", "blob"}});
		oversized_id.set_snapshot_id(std::string(MAX_CONFIG_SNAPSHOT_ID_BYTES + 1u, 'x'));
		auto oversized_id_or = canonicalize_config_snapshot(oversized_id, plan);
		ASSERT_FALSE(oversized_id_or.is_ok());
		EXPECT_EQ(oversized_id_or.error().code(), status_code::INVALID_ARGUMENT);

		auto negative_revision = make_snapshot({{"module.alpha", "blob"}});
		negative_revision.set_revision(-1);
		auto negative_revision_or = canonicalize_config_snapshot(negative_revision, plan);
		ASSERT_FALSE(negative_revision_or.is_ok());
		EXPECT_EQ(negative_revision_or.error().code(), status_code::INVALID_ARGUMENT);

		auto oversized_revision = make_snapshot({{"module.alpha", "blob"}});
		oversized_revision.set_revision(MAX_CONFIG_SNAPSHOT_REVISION + 1);
		auto oversized_revision_or = canonicalize_config_snapshot(oversized_revision, plan);
		ASSERT_FALSE(oversized_revision_or.is_ok());
		EXPECT_EQ(oversized_revision_or.error().code(), status_code::INVALID_ARGUMENT);
	}
	{
		auto oversized = make_snapshot(
			{{"module.alpha", std::string(MAX_CONFIG_SNAPSHOT_BYTES, static_cast<char>(0x5a))}});
		auto oversized_or = canonicalize_config_snapshot(oversized, plan);
		ASSERT_FALSE(oversized_or.is_ok());
		EXPECT_EQ(oversized_or.error().code(), status_code::RESOURCE_EXHAUSTED);
	}

	// Fill the admitted representation to the exact shared bound. Canonical
	// module hashes then add bytes, which must be rejected rather than retained
	// as an oversized transaction identity.
	auto canonical_growth = make_snapshot({{"module.alpha", ""}});
	auto *blob = canonical_growth.mutable_modules(0)->mutable_config_blob();
	blob->assign(MAX_CONFIG_SNAPSHOT_BYTES, static_cast<char>(0x5a));
	constexpr int MAX_BOUND_ADJUSTMENTS = 8;
	for (int attempt = 0; attempt < MAX_BOUND_ADJUSTMENTS; ++attempt) {
		const std::size_t serialized_size = canonical_growth.ByteSizeLong();
		if (serialized_size == MAX_CONFIG_SNAPSHOT_BYTES) {
			break;
		}
		if (serialized_size > MAX_CONFIG_SNAPSHOT_BYTES) {
			blob->resize(blob->size() - (serialized_size - MAX_CONFIG_SNAPSHOT_BYTES));
		} else {
			blob->append(MAX_CONFIG_SNAPSHOT_BYTES - serialized_size, static_cast<char>(0x5a));
		}
	}
	ASSERT_EQ(canonical_growth.ByteSizeLong(), MAX_CONFIG_SNAPSHOT_BYTES);

	auto canonical_growth_or = canonicalize_config_snapshot(canonical_growth, plan);
	ASSERT_FALSE(canonical_growth_or.is_ok());
	EXPECT_EQ(canonical_growth_or.error().code(), status_code::RESOURCE_EXHAUSTED);
	EXPECT_NE(canonical_growth_or.error().message().find("canonical"), std::string::npos);
}

/**
 * @brief Verify declared planner timing fields are excluded from plan identity.
 */
TEST(content_identity, plan_hash_ignores_only_declared_volatile_timing)
{
	auto first = make_module_plan({"module.alpha"});
	first.mutable_metadata()->set_planner_version("gluon-test");
	first.mutable_metadata()->set_planned_unix_ms(100);
	first.mutable_metadata()->set_planning_duration_ms(4);
	auto second = first;
	second.mutable_metadata()->set_planned_unix_ms(9'999);
	second.mutable_metadata()->set_planning_duration_ms(800);

	auto first_or = kinetum::provider::compute_deployment_plan_content_hash(first);
	auto second_or = kinetum::provider::compute_deployment_plan_content_hash(second);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	EXPECT_EQ(first_or.value(), second_or.value());
}

/**
 * @brief Verify repeated plan-field order remains part of the plan contract.
 */
TEST(content_identity, plan_hash_preserves_contractual_repeated_order)
{
	auto first = make_module_plan({"module.alpha", "module.beta"});
	auto second = first;
	second.mutable_pipeline()->mutable_stages()->SwapElements(0, 1);

	auto first_or = kinetum::provider::compute_deployment_plan_content_hash(first);
	auto second_or = kinetum::provider::compute_deployment_plan_content_hash(second);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	EXPECT_NE(first_or.value(), second_or.value());
}

/**
 * @brief Verify plan verification rejects empty, malformed, and mismatched claims.
 */
TEST(content_identity, plan_hash_verification_never_treats_empty_as_skip)
{
	auto plan = make_module_plan({"module.alpha"});
	auto missing_status = kinetum::provider::verify_deployment_plan_content_hash(plan);
	EXPECT_EQ(missing_status.code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(missing_status.message().find("required"), std::string::npos);

	plan.set_content_hash("abc");
	EXPECT_EQ(kinetum::provider::verify_deployment_plan_content_hash(plan).code(), status_code::INVALID_ARGUMENT);
	plan.set_content_hash(std::string(SHA256_HEX_LENGTH, 'A'));
	EXPECT_EQ(kinetum::provider::verify_deployment_plan_content_hash(plan).code(), status_code::INVALID_ARGUMENT);

	plan.clear_content_hash();
	auto hash_or = kinetum::provider::compute_deployment_plan_content_hash(plan);
	ASSERT_TRUE(hash_or.is_ok()) << hash_or.error().message();
	plan.set_content_hash(hash_or.value());
	EXPECT_TRUE(kinetum::provider::verify_deployment_plan_content_hash(plan).is_ok());

	plan.mutable_execution_provider_instances(0)->set_execution_provider_instance_id("execution_cpu_1");
	EXPECT_EQ(kinetum::provider::verify_deployment_plan_content_hash(plan).code(), status_code::DATA_LOSS);
}

/**
 * @brief Verify plan identity rejects unknown fields at top-level and nesting.
 */
TEST(content_identity, plan_hash_rejects_recursive_unknown_protobuf_fields)
{
	auto top_level = make_module_plan({"module.alpha"});
	inject_unknown_field(&top_level);
	EXPECT_FALSE(kinetum::provider::compute_deployment_plan_content_hash(top_level).is_ok());

	auto nested = make_module_plan({"module.alpha"});
	inject_unknown_field(nested.mutable_pipeline()->mutable_stages(0));
	EXPECT_FALSE(kinetum::provider::compute_deployment_plan_content_hash(nested).is_ok());
}

/**
 * @brief Verify plan identity rejects invalid enum numbers in the message tree.
 */
TEST(content_identity, plan_hash_rejects_recursive_invalid_enum_values)
{
	auto plan = make_module_plan({"module.alpha"});
	plan.mutable_pipeline()->mutable_stages(0)->set_kind(static_cast<kinetum::axiom::v1::StageKind>(999));

	const auto result = kinetum::provider::compute_deployment_plan_content_hash(plan);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("unknown enum number"), std::string::npos);
}

/**
 * @brief Verify late stable planner metadata remains hash-sensitive.
 */
TEST(content_identity, late_stable_planner_field_changes_plan_identity)
{
	auto before = make_module_plan({"module.alpha"});
	before.mutable_metadata()->set_planner_version("gluon-test");
	auto after = before;
	after.mutable_metadata()->set_algorithm("linear_dp_v2");

	auto before_or = kinetum::provider::compute_deployment_plan_content_hash(before);
	auto after_or = kinetum::provider::compute_deployment_plan_content_hash(after);
	ASSERT_TRUE(before_or.is_ok()) << before_or.error().message();
	ASSERT_TRUE(after_or.is_ok()) << after_or.error().message();
	EXPECT_NE(before_or.value(), after_or.value());
}

/** @brief TX admission order normalizes before hashing while changed membership changes identity. */
TEST(content_identity, tx_storage_admission_is_a_canonical_identity_set)
{
	auto first = make_module_plan({"module.alpha"});
	auto *stream = first.add_io_streams();
	stream->set_io_stream_id("lan0.tx.lane_0");
	stream->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	stream->mutable_tx_storage()->add_storage_domain_ids("storage_b");
	stream->mutable_tx_storage()->add_storage_domain_ids("storage_a");
	auto reordered = first;
	reordered.mutable_io_streams(0)->mutable_tx_storage()->mutable_storage_domain_ids()->SwapElements(0, 1);
	const auto first_hash = kinetum::provider::compute_deployment_plan_content_hash(first);
	const auto reordered_hash = kinetum::provider::compute_deployment_plan_content_hash(reordered);
	ASSERT_TRUE(first_hash.is_ok()) << first_hash.error().message();
	ASSERT_TRUE(reordered_hash.is_ok()) << reordered_hash.error().message();
	EXPECT_EQ(first_hash.value(), reordered_hash.value());
	ASSERT_TRUE(kinetum::provider::finalize_deployment_plan_identity(&first).is_ok());
	EXPECT_EQ(first.io_streams(0).tx_storage().storage_domain_ids(0), "storage_a");
	EXPECT_EQ(first.io_streams(0).tx_storage().storage_domain_ids(1), "storage_b");
	EXPECT_TRUE(kinetum::provider::verify_deployment_plan_content_hash(first).is_ok());
	first.mutable_io_streams(0)->mutable_tx_storage()->mutable_storage_domain_ids()->RemoveLast();
	const auto changed = kinetum::provider::compute_deployment_plan_content_hash(first);
	ASSERT_TRUE(changed.is_ok()) << changed.error().message();
	EXPECT_NE(first_hash.value(), changed.value());
}

/** @brief Identity canonicalization never repairs empty, duplicate, or wrong-direction storage. */
TEST(content_identity, malformed_stream_storage_rejects_before_hashing)
{
	auto baseline = make_module_plan({"module.alpha"});
	auto *stream = baseline.add_io_streams();
	stream->set_io_stream_id("lan0.tx.lane_0");
	stream->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	stream->mutable_tx_storage()->add_storage_domain_ids("storage_a");

	auto empty = baseline;
	empty.mutable_io_streams(0)->mutable_tx_storage()->clear_storage_domain_ids();
	EXPECT_FALSE(kinetum::provider::compute_deployment_plan_content_hash(empty).is_ok());
	auto duplicate = baseline;
	duplicate.mutable_io_streams(0)->mutable_tx_storage()->add_storage_domain_ids("storage_a");
	EXPECT_FALSE(kinetum::provider::compute_deployment_plan_content_hash(duplicate).is_ok());
	auto wrong_direction = baseline;
	wrong_direction.mutable_io_streams(0)->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	EXPECT_FALSE(kinetum::provider::compute_deployment_plan_content_hash(wrong_direction).is_ok());
	auto retired = baseline;
	auto *retired_stream = retired.mutable_io_streams(0);
	retired_stream->GetReflection()->MutableUnknownFields(retired_stream)->AddLengthDelimited(9, "storage_a");
	EXPECT_FALSE(kinetum::provider::compute_deployment_plan_content_hash(retired).is_ok());
}

/** @brief Verify exact active-origin storage ownership is plan identity. */
TEST(content_identity, active_origin_storage_domain_changes_plan_identity)
{
	auto first = make_module_plan({"module.alpha"});
	first.mutable_pipeline()->mutable_stages(0)->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	for (const auto *storage_id : {"storage_host_0", "storage_host_1"}) {
		kinetum::storage::host::v1::HostStorageConfig configuration;
		auto *storage = first.add_packet_storage_domains();
		storage->set_storage_domain_id(storage_id);
		storage->mutable_configuration()->PackFrom(configuration);
		storage->set_buffer_count(4096);
		storage->set_data_room_bytes(2048);
		storage->set_headroom_bytes(128);
		storage->set_alignment_bytes(64);
		storage->set_host_numa_node(0);
	}
	auto *instance = add_module_stage_instance(first, 0u, uint64_t{2} * 1024u * 1024u, uint64_t{2} * 1024u * 1024u);
	instance->set_active_origin_storage_domain_id("storage_host_0");

	auto second = first;
	second.mutable_stage_instances(0)->set_active_origin_storage_domain_id("storage_host_1");
	const auto first_or = kinetum::provider::compute_deployment_plan_content_hash(first);
	const auto second_or = kinetum::provider::compute_deployment_plan_content_hash(second);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	EXPECT_NE(first_or.value(), second_or.value());
}

/** @brief Verify every compact active-stage limit independently changes plan identity. */
TEST(content_identity, active_stage_limits_are_independent_plan_identity)
{
	auto baseline = make_module_plan({"module.alpha"});
	auto *stage = baseline.mutable_pipeline()->mutable_stages(0);
	stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	stage->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));

	const auto baseline_or = kinetum::provider::compute_deployment_plan_content_hash(baseline);
	ASSERT_TRUE(baseline_or.is_ok()) << baseline_or.error().message();
	std::set<std::string> identities{baseline_or.value()};
	for (uint32_t field = 0u; field < 7u; ++field) {
		auto changed = baseline;
		auto *limits = changed.mutable_pipeline()->mutable_stages(0)->mutable_active_stage_limits();
		switch (field) {
		case 0u:
			limits->set_retained_packet_capacity(2u);
			break;
		case 1u:
			limits->set_retained_byte_capacity(128u);
			break;
		case 2u:
			limits->set_timer_capacity(4u);
			break;
		case 3u:
			limits->set_control_mailbox_capacity(8u);
			break;
		case 4u:
			limits->set_control_message_capacity_bytes(64u);
			break;
		case 5u:
			limits->set_async_work_capacity(4u);
			break;
		case 6u:
			limits->set_async_cancel_grace_ms(1000u);
			break;
		default:
			FAIL() << "unreachable active-limit field";
		}
		auto identity_or = kinetum::provider::compute_deployment_plan_content_hash(changed);
		ASSERT_TRUE(identity_or.is_ok()) << identity_or.error().message();
		EXPECT_TRUE(identities.insert(identity_or.value()).second);
	}
}

/** @brief Verify each authored module lifecycle-memory bound changes plan identity. */
TEST(content_identity, module_context_resource_capacities_change_plan_identity)
{
	auto baseline = make_module_plan({"module.alpha"});
	(void)add_module_stage_instance(baseline, 0u, uint64_t{2} * 1024u * 1024u, uint64_t{2} * 1024u * 1024u);

	auto context_changed = baseline;
	context_changed.mutable_stage_instances(0)->set_context_memory_capacity_bytes(uint64_t{2} * 1024u * 1024u + 1u);
	auto epoch_changed = baseline;
	epoch_changed.mutable_stage_instances(0)->set_epoch_arena_capacity_bytes(uint64_t{2} * 1024u * 1024u + 1u);

	const auto baseline_or = kinetum::provider::compute_deployment_plan_content_hash(baseline);
	const auto context_or = kinetum::provider::compute_deployment_plan_content_hash(context_changed);
	const auto epoch_or = kinetum::provider::compute_deployment_plan_content_hash(epoch_changed);
	ASSERT_TRUE(baseline_or.is_ok()) << baseline_or.error().message();
	ASSERT_TRUE(context_or.is_ok()) << context_or.error().message();
	ASSERT_TRUE(epoch_or.is_ok()) << epoch_or.error().message();
	EXPECT_NE(baseline_or.value(), context_or.value());
	EXPECT_NE(baseline_or.value(), epoch_or.value());
}

/**
 * @brief Prove each guardrails fixture is one exact ACL-only delta from v2.
 */
TEST(content_identity, guardrails_degradation_fixtures_are_exact_acl_only_deltas)
{
	const std::array<std::string, 1> EXAMPLE_DIRECTORIES{{"fan_in_edge_gateway"}};
	const std::string EXPECTED_ACL_BLOB =
		"{ \"default_action\": 2, \"rules\": [ { \"priority\": 2000, \"src_cidr\": "
		"\"10.0.0.100/32\", \"dst_cidr\": \"192.168.1.1/32\", \"dst_port_min\": 9999, "
		"\"dst_port_max\": 9999, \"protocol\": 17, \"action\": 2, \"enabled\": true }, { "
		"\"priority\": 1000, \"src_cidr\": \"0.0.0.0/0\", \"dst_cidr\": \"0.0.0.0/0\", "
		"\"action\": 1, \"enabled\": true } ] }";
	auto plan = make_module_plan({"kinetum.acl", "kinetum.nat44", "kinetum.qos"});

	for (const auto &directory : EXAMPLE_DIRECTORIES) {
		const std::filesystem::path root =
			std::filesystem::path(KINETUM_TEST_SOURCE_ROOT) / "examples" / directory;
		ConfigSnapshot baseline;
		ConfigSnapshot degraded;
		const auto baseline_status =
			read_pbtxt_file((root / "config_snapshot_v2.pbtxt").string(), DEFAULT_MAX_FILE_SIZE, &baseline);
		const auto degraded_status =
			read_pbtxt_file((root / "config_snapshot_guardrails_degradation.pbtxt").string(),
					DEFAULT_MAX_FILE_SIZE, &degraded);
		ASSERT_TRUE(baseline_status.is_ok()) << baseline_status.message();
		ASSERT_TRUE(degraded_status.is_ok()) << degraded_status.message();
		ASSERT_EQ(baseline.modules_size(), 3);
		ASSERT_EQ(degraded.modules_size(), 3);
		ASSERT_EQ(baseline.modules(0).module_id(), "kinetum.acl");
		ASSERT_EQ(degraded.modules(0).module_id(), "kinetum.acl");
		EXPECT_EQ(degraded.modules(0).config_blob(), EXPECTED_ACL_BLOB);
		auto expected_hash_or = sha256_hex(EXPECTED_ACL_BLOB);
		ASSERT_TRUE(expected_hash_or.is_ok()) << expected_hash_or.error().message();
		EXPECT_EQ(degraded.modules(0).content_hash(), expected_hash_or.value());
		std::pmr::monotonic_buffer_resource acl_memory;
		kinetum::modules::acl::acl_compiled compiled_acl(acl_memory);
		const auto acl_result = kinetum::modules::acl::compile_acl_from_json(
			EXPECTED_ACL_BLOB.data(), EXPECTED_ACL_BLOB.size(), &acl_memory, &compiled_acl);
		ASSERT_EQ(acl_result, kinetum::modules::config::compile_result::OK);
		EXPECT_EQ(kinetum::modules::acl::eval_acl_5tuple(compiled_acl, UINT32_C(0x0A000064),
								 UINT32_C(0xC0A80101), UINT8_C(17), UINT16_C(10000),
								 UINT16_C(9999)),
			  kinetum::modules::acl::acl_action::DENY);
		EXPECT_EQ(kinetum::modules::acl::eval_acl_5tuple(compiled_acl, UINT32_C(0x0A000064),
								 UINT32_C(0xC0A80101), UINT8_C(17), UINT16_C(10000),
								 UINT16_C(9998)),
			  kinetum::modules::acl::acl_action::PERMIT);

		auto only_allowed_delta = degraded;
		only_allowed_delta.set_snapshot_id(baseline.snapshot_id());
		only_allowed_delta.set_description(baseline.description());
		*only_allowed_delta.mutable_modules(0) = baseline.modules(0);
		EXPECT_TRUE(google::protobuf::util::MessageDifferencer::Equals(baseline, only_allowed_delta));

		auto baseline_or = canonicalize_config_snapshot(baseline, plan);
		auto degraded_or = canonicalize_config_snapshot(degraded, plan);
		ASSERT_TRUE(baseline_or.is_ok()) << baseline_or.error().message();
		ASSERT_TRUE(degraded_or.is_ok()) << degraded_or.error().message();
		EXPECT_NE(baseline_or->validation_hash, degraded_or->validation_hash);

		auto stale_hash = degraded;
		auto old_acl_hash_or = sha256_hex(baseline.modules(0).config_blob());
		ASSERT_TRUE(old_acl_hash_or.is_ok()) << old_acl_hash_or.error().message();
		stale_hash.mutable_modules(0)->set_content_hash(old_acl_hash_or.value());
		auto rejected = canonicalize_config_snapshot(stale_hash, plan);
		ASSERT_FALSE(rejected.is_ok());
		EXPECT_EQ(rejected.error().code(), status_code::DATA_LOSS);
	}
}

}  // namespace kinetum::common
