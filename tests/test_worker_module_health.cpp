// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_module_health.cpp
 * @brief Exact owner-worker module-health claim and publication tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>

#include "src/common/status.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/module/worker_module_health.hpp"
#include "tests/module_abi_test_harness.hpp"

#if !defined(KINETUM_TEST_MODULE_PATH)
#error "Exact passive test-module path is required"
#endif

#if !defined(KINETUM_TEST_ACTIVE_MODULE_PATH)
#error "Exact active test-module path is required"
#endif

namespace kinetum::dp::module
{
namespace
{

/** Packet worker owning the health callback. */
constexpr uint32_t TEST_WORKER_INDEX = 0u;
/** Exact module context whose health is observed. */
constexpr uint32_t TEST_CONTEXT_INDEX = 0u;
/** Compiled stage instance bound to the health context. */
constexpr uint32_t TEST_STAGE_INSTANCE_INDEX = 0u;
/** Runtime identity shared by health and ledger owners. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 1u;
/** Initially active module epoch. */
constexpr uint64_t TEST_EPOCH = 11u;
/** Prepared target epoch used to test health/transition exclusion. */
constexpr uint64_t TEST_FUTURE_EPOCH = 13u;
/** Authored callback execution budget in nanoseconds. */
constexpr uint64_t TEST_CALLBACK_BUDGET_NS = 100u;
/** Explicit lifecycle-memory authority for the health fixture's module. */
constexpr test::module_test_resource_contract TEST_MODULE_RESOURCES{
	.context_memory_capacity_bytes = std::size_t{1024} * 1024u,
	.epoch_arena_capacity_bytes = std::size_t{64} * 1024u,
};

/**
 * @brief Complete real-image health owner and every authority it borrows.
 *
 * Teardown retires the active module while health still owns its context, then
 * releases health before the ledger and real module generation are destroyed.
 */
class worker_health_fixture final {
    public:
	/**
	 * @brief Admit, activate, and bind one exact module health owner.
	 * @param module_id Exact image descriptor identity.
	 * @param module_path Exact real-image path.
	 * @param configuration Exact module-owned PREPARE payload.
	 * @param context_index Exact context identity for this fixture.
	 * @param stage_instance_index Exact stage identity for this fixture.
	 * @return Complete fixture or the first production admission failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_health_fixture>>
	create(std::string module_id, std::filesystem::path module_path, std::string_view configuration = "{}",
	       uint32_t context_index = TEST_CONTEXT_INDEX, uint32_t stage_instance_index = TEST_STAGE_INSTANCE_INDEX)
	{
		std::unique_ptr<worker_health_fixture> fixture;
		try {
			fixture.reset(new worker_health_fixture());
		} catch (const std::bad_alloc &) {
			return common::status::resource_exhausted("failed to allocate module-health fixture");
		}
		auto module_or = test::exact_module_test_context::create(std::move(module_id), std::move(module_path),
									 TEST_MODULE_RESOURCES, "module@lane_0",
									 context_index, stage_instance_index);
		if (!module_or.is_ok()) {
			return module_or.error();
		}
		fixture->module_ = std::move(module_or).value();
		fixture->context_index_ = context_index;
		fixture->stage_instance_index_ = stage_instance_index;
		auto ledger_or = worker_epoch_ledger::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, 8u);
		if (!ledger_or.is_ok()) {
			return ledger_or.error();
		}
		fixture->ledger_ = std::move(ledger_or).value();
		auto &context = fixture->module_->context();
		const worker_module_health_binding binding{
			.stage_instance_index = stage_instance_index,
			.context_index = context_index,
			.context = &context.packet_context,
			.store = context.epoch_store.get(),
			.descriptor = context.image->descriptor,
			.publication = context.lifecycle_owner.get(),
		};
		auto health_or = worker_module_health::create(
			TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, TEST_CALLBACK_BUDGET_NS,
			std::span<const worker_module_health_binding>(&binding, 1u), *fixture->ledger_);
		if (!health_or.is_ok()) {
			return health_or.error();
		}
		fixture->health_ = std::move(health_or).value();
		const auto activated = fixture->module_->prepare_and_activate(TEST_EPOCH, configuration);
		if (!activated.is_ok()) {
			return activated;
		}
		fixture->ledger_->bind_bootstrap_epoch(TEST_EPOCH);
		fixture->health_->bind_bootstrap_epoch(TEST_EPOCH);
		return fixture;
	}

	worker_health_fixture(const worker_health_fixture &) = delete;
	worker_health_fixture &operator=(const worker_health_fixture &) = delete;
	worker_health_fixture(worker_health_fixture &&) = delete;
	worker_health_fixture &operator=(worker_health_fixture &&) = delete;
	/** @brief Retire module ownership, then release health before context teardown. */
	~worker_health_fixture()
	{
		if (module_ != nullptr && health_ != nullptr) {
			if (module_->context().epoch_store->active_epoch() != 0u && !module_->retire().is_ok()) {
				std::terminate();
			}
			health_.reset();
		}
	}

	/** @return Exact worker health owner. */
	[[nodiscard]] worker_module_health &health() noexcept
	{
		return *health_;
	}

	/** @return Sole exact worker epoch ledger. */
	[[nodiscard]] worker_epoch_ledger &ledger() noexcept
	{
		return *ledger_;
	}

	/** @return Exact bound lifecycle publication owner. */
	[[nodiscard]] lifecycle::lifecycle_context_owner &publication() noexcept
	{
		return *module_->context().lifecycle_owner;
	}

	/** @return Result of exact final artifact retirement under the live health borrow. */
	[[nodiscard]] common::status retire_module() noexcept
	{
		return module_->retire();
	}

	/** @return Whether the exact module store reports complete ownership release. */
	[[nodiscard]] bool store_empty() const noexcept
	{
		return module_->context().epoch_store->empty();
	}

	/** @return One immutable binding equivalent to the production row. */
	[[nodiscard]] worker_module_health_binding binding() noexcept
	{
		auto &context = module_->context();
		return worker_module_health_binding{
			.stage_instance_index = stage_instance_index_,
			.context_index = context_index_,
			.context = &context.packet_context,
			.store = context.epoch_store.get(),
			.descriptor = context.image->descriptor,
			.publication = context.lifecycle_owner.get(),
		};
	}

    private:
	/** @brief Construct an empty fixture before exact real-image admission. */
	worker_health_fixture() = default;

	std::unique_ptr<test::exact_module_test_context> module_;   ///< Real image/context/store owner.
	std::unique_ptr<worker_epoch_ledger> ledger_;		    ///< Sole worker credit authority.
	std::unique_ptr<worker_module_health> health_;		    ///< Linear health scheduler claim.
	uint32_t context_index_{TEST_CONTEXT_INDEX};		    ///< Exact fixture context identity.
	uint32_t stage_instance_index_{TEST_STAGE_INSTANCE_INDEX};  ///< Exact fixture stage identity.
};

/** @brief Trigger unresolved-claim destruction through the production method. */
void unresolved_claim_child()
{
	auto fixture_or = worker_health_fixture::create("test_module", KINETUM_TEST_MODULE_PATH);
	if (!fixture_or.is_ok()) {
		std::_Exit(81);
	}
	auto fixture = std::move(fixture_or).value();
	{
		auto invocation = fixture->health().begin(0u);
		if (!invocation.has_value()) {
			std::_Exit(82);
		}
	}
	std::_Exit(83);
}

/** @brief Trigger a regressing post-callback monotonic sample. */
void regressing_clock_child()
{
	auto fixture_or = worker_health_fixture::create("test_module", KINETUM_TEST_MODULE_PATH);
	if (!fixture_or.is_ok()) {
		std::_Exit(91);
	}
	auto fixture = std::move(fixture_or).value();
	auto invocation = fixture->health().begin(0u);
	if (!invocation.has_value()) {
		std::_Exit(92);
	}
	invocation->invoke(10u);
	invocation->complete(9u);
	std::_Exit(93);
}

/** @brief Publish valid module output with exact context, epoch, and credit bracketing. */
TEST(worker_module_health, exact_callback_uses_one_credit_and_publishes_platform_provenance)
{
	auto fixture_or = worker_health_fixture::create("test_module", KINETUM_TEST_MODULE_PATH);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	EXPECT_EQ(fixture->health().size(), 1u);
	EXPECT_EQ(fixture->health().callback_count(), 1u);
	EXPECT_TRUE(fixture->health().owns_ledger(fixture->ledger()));
	EXPECT_TRUE(fixture->publication().module_health_owner_claimed());

	auto invocation = fixture->health().begin(0u);
	if (!invocation.has_value()) {
		ADD_FAILURE() << "exact callback did not produce its linear invocation";
		return;
	}
	EXPECT_EQ(fixture->ledger().active_unretired(), 1u);
	invocation.value().invoke(10u);
	invocation.value().complete(13u);
	EXPECT_EQ(fixture->ledger().active_unretired(), 0u);
	EXPECT_TRUE(fixture->health().quiescent());

	lifecycle::lifecycle_module_health_observation observation{};
	ASSERT_TRUE(fixture->publication().try_read_module_health(observation));
	EXPECT_EQ(observation.runtime_generation, TEST_RUNTIME_GENERATION);
	EXPECT_EQ(observation.worker_index, TEST_WORKER_INDEX);
	EXPECT_EQ(observation.context_index, TEST_CONTEXT_INDEX);
	EXPECT_EQ(observation.stage_instance_index, TEST_STAGE_INSTANCE_INDEX);
	EXPECT_EQ(observation.observation_epoch, TEST_EPOCH);
	EXPECT_EQ(observation.observed_at_ns, 10u);
	EXPECT_EQ(observation.callback_duration_ns, 3u);
	EXPECT_EQ(observation.signal_available, 1u);
	EXPECT_EQ(observation.signal.assessment.health_score, 100u);
	EXPECT_STREQ(observation.signal.assessment.reason, "ready");
	EXPECT_EQ(observation.signal.epoch, TEST_EPOCH);
	EXPECT_EQ(observation.signal.timestamp_ns, 10u);
}

/** @brief Suppress old-epoch health after source advancement without acquiring credit. */
TEST(worker_module_health, source_advance_suppresses_callback_and_publication)
{
	auto fixture_or = worker_health_fixture::create("test_module", KINETUM_TEST_MODULE_PATH);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->ledger().bind_future_epoch(TEST_FUTURE_EPOCH);
	fixture->ledger().advance_source_epoch(TEST_FUTURE_EPOCH);
	EXPECT_FALSE(fixture->health().begin(0u).has_value());
	EXPECT_EQ(fixture->ledger().active_unretired(), 0u);
	EXPECT_TRUE(fixture->ledger().empty());
	lifecycle::lifecycle_module_health_observation observation{};
	EXPECT_FALSE(fixture->publication().try_read_module_health(observation));
}

/** @brief Keep null callbacks explicit and prevent a second owner claim. */
TEST(worker_module_health, null_callback_is_unavailable_and_context_claim_is_linear)
{
	auto fixture_or = worker_health_fixture::create("kinetum.test_active", KINETUM_TEST_ACTIVE_MODULE_PATH,
							std::string_view{});
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	EXPECT_EQ(fixture->health().callback_count(), 0u);
	EXPECT_FALSE(fixture->health().begin(0u).has_value());
	EXPECT_EQ(fixture->ledger().active_unretired(), 0u);
	lifecycle::lifecycle_module_health_observation observation{};
	EXPECT_FALSE(fixture->publication().try_read_module_health(observation));

	const auto binding = fixture->binding();
	auto contender_ledger_or = worker_epoch_ledger::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, 8u);
	ASSERT_TRUE(contender_ledger_or.is_ok()) << contender_ledger_or.error().message();
	auto contender_ledger = std::move(contender_ledger_or).value();
	auto duplicate = worker_module_health::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION,
						      TEST_CALLBACK_BUDGET_NS,
						      std::span<const worker_module_health_binding>(&binding, 1u),
						      *contender_ledger);
	ASSERT_FALSE(duplicate.is_ok());
	EXPECT_EQ(duplicate.error().code(), common::status_code::FAILED_PRECONDITION);
	EXPECT_TRUE(fixture->publication().module_health_owner_claimed());
	ASSERT_TRUE(fixture->retire_module().is_ok());
	EXPECT_FALSE(fixture->store_empty());
}

/** @brief Reject malformed binding before claiming any context publication. */
TEST(worker_module_health, malformed_binding_rejects_without_claim_or_credit)
{
	auto fixture_or = worker_health_fixture::create("test_module", KINETUM_TEST_MODULE_PATH);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	auto malformed = fixture->binding();
	malformed.context = nullptr;
	auto contender_ledger_or = worker_epoch_ledger::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, 8u);
	ASSERT_TRUE(contender_ledger_or.is_ok()) << contender_ledger_or.error().message();
	auto contender_ledger = std::move(contender_ledger_or).value();
	auto rejected = worker_module_health::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION,
						     TEST_CALLBACK_BUDGET_NS,
						     std::span<const worker_module_health_binding>(&malformed, 1u),
						     *contender_ledger);
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(fixture->ledger().active_unretired(), 0u);
	const auto valid = fixture->binding();
	auto late = worker_module_health::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, TEST_CALLBACK_BUDGET_NS,
						 std::span<const worker_module_health_binding>(&valid, 1u),
						 fixture->ledger());
	ASSERT_FALSE(late.is_ok());
	EXPECT_EQ(late.error().code(), common::status_code::FAILED_PRECONDITION);
	EXPECT_NE(late.error().message().find("before Bootstrap"), std::string::npos);
}

/** @brief Roll back every earlier context claim when a later row is already owned. */
TEST(worker_module_health, partial_context_claim_failure_releases_complete_prefix)
{
	auto claimed_or = worker_health_fixture::create("test_module", KINETUM_TEST_MODULE_PATH, "{}", 1u, 1u);
	ASSERT_TRUE(claimed_or.is_ok()) << claimed_or.error().message();
	auto claimed = std::move(claimed_or).value();
	auto unclaimed_or = test::exact_module_test_context::create("test_module", KINETUM_TEST_MODULE_PATH,
								    TEST_MODULE_RESOURCES, "module@lane_0", 0u, 0u);
	ASSERT_TRUE(unclaimed_or.is_ok()) << unclaimed_or.error().message();
	auto unclaimed = std::move(unclaimed_or).value();
	auto &context = unclaimed->context();
	const std::array<worker_module_health_binding, 2> bindings{{
		{
			.stage_instance_index = 0u,
			.context_index = 0u,
			.context = &context.packet_context,
			.store = context.epoch_store.get(),
			.descriptor = context.image->descriptor,
			.publication = context.lifecycle_owner.get(),
		},
		claimed->binding(),
	}};
	auto contender_ledger_or = worker_epoch_ledger::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, 8u);
	ASSERT_TRUE(contender_ledger_or.is_ok()) << contender_ledger_or.error().message();
	auto contender_ledger = std::move(contender_ledger_or).value();
	auto rejected = worker_module_health::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION,
						     TEST_CALLBACK_BUDGET_NS, bindings, *contender_ledger);
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), common::status_code::FAILED_PRECONDITION);
	EXPECT_FALSE(context.lifecycle_owner->module_health_owner_claimed());
	EXPECT_TRUE(claimed->publication().module_health_owner_claimed());
}

/** @brief Fail stop rather than lose a live claim or accept clock regression. */
TEST(worker_module_health, unresolved_claim_and_regressing_completion_are_fatal)
{
	EXPECT_EXIT(unresolved_claim_child(), ::testing::KilledBySignal(SIGABRT), "");
	EXPECT_EXIT(regressing_clock_child(), ::testing::KilledBySignal(SIGABRT), "");
}

}  // namespace
}  // namespace kinetum::dp::module
