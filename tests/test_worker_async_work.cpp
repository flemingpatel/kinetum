// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_async_work.cpp
 * @brief Exact foreign-token, cancellation, and completion ownership tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstdlib>
#include <memory>
#include <thread>
#include <utility>

#include <kinetum/kinetum_sdk.h>

#include "src/dp/active/worker_async_work.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"

namespace kinetum::dp
{
namespace
{

/** Runtime identity shared by ledger and foreign-work tracker. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 17u;
/** Epoch charged for fixture asynchronous ownership. */
constexpr uint64_t TEST_EPOCH = 5u;
/** Exact packet-worker identity owning the tracker. */
constexpr uint32_t TEST_WORKER_INDEX = 0u;
/** Exact active-context owner identity carried by tokens. */
constexpr uint32_t TEST_OWNER_INDEX = 3u;
/** Fixed logical token and completion-cell population. */
constexpr std::size_t TEST_SLOT_COUNT = 4u;

/** @brief Own one exact ledger, logical slot set, MPMC cells, and tracker. */
struct async_work_fixture {
	std::unique_ptr<worker_epoch_ledger> ledger;			       ///< Exact test credit authority.
	std::array<worker_async_work::slot_storage, TEST_SLOT_COUNT> slots{};  ///< Logical token slots.
	std::array<worker_async_work::completion_queue_storage, TEST_SLOT_COUNT> queue{};  ///< Physical cells.
	std::unique_ptr<worker_async_work> tracker;					   ///< Sole foreign-work owner.

	/**
	 * @brief Construct one exact bound fixture.
	 * @return Complete ledger/tracker fixture, or nullptr on admission failure.
	 */
	static std::unique_ptr<async_work_fixture> create()
	{
		auto fixture = std::make_unique<async_work_fixture>();
		auto ledger_or = worker_epoch_ledger::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, 16u);
		if (!ledger_or.is_ok()) {
			return nullptr;
		}
		fixture->ledger = std::move(ledger_or).value();
		fixture->ledger->bind_bootstrap_epoch(TEST_EPOCH);
		fixture->tracker = std::make_unique<worker_async_work>(worker_async_work::construction_binding{
			.runtime_generation = TEST_RUNTIME_GENERATION,
			.worker_index = TEST_WORKER_INDEX,
			.ledger = fixture->ledger.get(),
			.slots = fixture->slots.data(),
			.slot_count = static_cast<uint32_t>(fixture->slots.size()),
			.queue_storage = fixture->queue.data(),
			.queue_capacity = fixture->queue.size(),
		});
		return fixture;
	}

	/**
	 * @brief Transfer one free logical slot into scheduler ownership.
	 * @param index In-range free slot to claim; assertions reject an already claimed slot.
	 */
	void claim(uint32_t index)
	{
		ASSERT_LT(index, slots.size());
		ASSERT_FALSE(slots[index].owner_claimed);
		slots[index].owner_claimed = true;
	}

	/**
	 * @brief Return one completion/abort-resolved slot to scheduler free ownership.
	 * @param index In-range owned slot whose tracker release predicate must be satisfied.
	 */
	void release(uint32_t index)
	{
		ASSERT_LT(index, slots.size());
		ASSERT_TRUE(slots[index].owner_claimed);
		ASSERT_TRUE(tracker->slot_release_ready(index));
		slots[index].owner_claimed = false;
	}

	/** @brief Destroy tracker before its borrowed storage and ledger. */
	~async_work_fixture()
	{
		tracker.reset();
	}
};

/** @brief Destroy one tracker while a foreign token remains live. */
void unresolved_token_destruction_child()
{
	auto fixture = async_work_fixture::create();
	if (fixture == nullptr) {
		std::_Exit(0);
	}
	fixture->claim(0u);
	(void)fixture->tracker->begin({
		.slot_index = 0u,
		.owner_index = TEST_OWNER_INDEX,
		.epoch = TEST_EPOCH,
		.user_tag = 1u,
		.retained_slot = UINT32_MAX,
		.standalone = true,
	});
	fixture.reset();
	std::_Exit(0);
}

/** @brief Construct one tracker with a valid but non-derived physical queue capacity. */
void inexact_completion_capacity_child()
{
	auto ledger_or = worker_epoch_ledger::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, 16u);
	if (!ledger_or.is_ok()) {
		std::_Exit(0);
	}
	auto ledger = std::move(ledger_or).value();
	ledger->bind_bootstrap_epoch(TEST_EPOCH);
	std::array<worker_async_work::slot_storage, TEST_SLOT_COUNT> slots{};
	std::array<worker_async_work::completion_queue_storage, TEST_SLOT_COUNT * 2u> queue{};
	worker_async_work tracker({
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.worker_index = TEST_WORKER_INDEX,
		.ledger = ledger.get(),
		.slots = slots.data(),
		.slot_count = static_cast<uint32_t>(slots.size()),
		.queue_storage = queue.data(),
		.queue_capacity = queue.size(),
	});
	std::_Exit(0);
}

/** @brief Construct one tracker over semantically dirty token-slot storage. */
void dirty_slot_construction_child()
{
	auto ledger_or = worker_epoch_ledger::create(TEST_WORKER_INDEX, TEST_RUNTIME_GENERATION, 16u);
	if (!ledger_or.is_ok()) {
		std::_Exit(0);
	}
	auto ledger = std::move(ledger_or).value();
	ledger->bind_bootstrap_epoch(TEST_EPOCH);
	std::array<worker_async_work::slot_storage, TEST_SLOT_COUNT> slots{};
	std::array<worker_async_work::completion_queue_storage, TEST_SLOT_COUNT> queue{};
	slots.front().user_tag = 1u;
	worker_async_work tracker({
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.worker_index = TEST_WORKER_INDEX,
		.ledger = ledger.get(),
		.slots = slots.data(),
		.slot_count = static_cast<uint32_t>(slots.size()),
		.queue_storage = queue.data(),
		.queue_capacity = queue.size(),
	});
	std::_Exit(0);
}

/** @brief Prove the physical completion ring is one derived power-of-two bound. */
TEST(worker_async_work, completion_capacity_is_derived_from_live_slots)
{
	ASSERT_TRUE(worker_async_work::queue_capacity_for(1u).is_ok());
	EXPECT_EQ(worker_async_work::queue_capacity_for(1u).value(), 2u);
	EXPECT_EQ(worker_async_work::queue_capacity_for(2u).value(), 2u);
	EXPECT_EQ(worker_async_work::queue_capacity_for(3u).value(), 4u);
	EXPECT_EQ(worker_async_work::queue_capacity_for(4u).value(), 4u);
	EXPECT_FALSE(worker_async_work::queue_capacity_for(0u).is_ok());
	EXPECT_DEATH(inexact_completion_capacity_child(), "");
	EXPECT_DEATH(dirty_slot_construction_child(), "");
}

/** @brief Prove one standalone token retains credit through owner callback completion. */
TEST(worker_async_work, standalone_completion_is_exact_once_and_credit_complete)
{
	auto fixture = async_work_fixture::create();
	ASSERT_NE(fixture, nullptr);
	fixture->claim(0u);
	const auto token = fixture->tracker->begin({
		.slot_index = 0u,
		.owner_index = TEST_OWNER_INDEX,
		.epoch = TEST_EPOCH,
		.user_tag = 91u,
		.retained_slot = UINT32_MAX,
		.standalone = true,
	});
	ASSERT_TRUE(kinetum_async_token_valid(&token));
	EXPECT_EQ(fixture->ledger->active_unretired(), 1u);
	EXPECT_FALSE(kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_UNSPECIFIED));
	EXPECT_TRUE(kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_SUCCESS));
	EXPECT_FALSE(kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_FAILED));

	worker_async_delivery delivery{};
	ASSERT_TRUE(fixture->tracker->try_take(delivery));
	EXPECT_EQ(delivery.completion.handle.value, token.handle.value);
	EXPECT_EQ(delivery.completion.user_tag, 91u);
	EXPECT_EQ(delivery.completion.outcome, KINETUM_ASYNC_OUTCOME_SUCCESS);
	EXPECT_TRUE(delivery.standalone);
	EXPECT_EQ(fixture->ledger->active_unretired(), 1u);
	auto malformed = delivery;
	malformed.epoch = TEST_EPOCH + 1u;
	EXPECT_DEATH(fixture->tracker->complete_delivery(malformed), "");
	malformed = delivery;
	++malformed.completion.user_tag;
	EXPECT_DEATH(fixture->tracker->complete_delivery(malformed), "");
	malformed = delivery;
	malformed.padding[0] = 1u;
	EXPECT_DEATH(fixture->tracker->complete_delivery(malformed), "");
	fixture->release(delivery.released_slot);
	fixture->tracker->complete_delivery(delivery);
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);
	EXPECT_TRUE(fixture->tracker->empty());
	EXPECT_TRUE(kinetum_async_cancellation_requested(&token));
}

/** @brief Prove wrong-owner abort is nonmutating and reuse rejects the stale token. */
TEST(worker_async_work, packet_abort_restores_exact_slot_and_reuse_generation)
{
	auto fixture = async_work_fixture::create();
	ASSERT_NE(fixture, nullptr);
	fixture->claim(1u);
	const auto first = fixture->tracker->begin({
		.slot_index = 1u,
		.owner_index = TEST_OWNER_INDEX,
		.epoch = TEST_EPOCH,
		.user_tag = 7u,
		.retained_slot = 12u,
		.standalone = false,
	});
	EXPECT_FALSE(fixture->tracker->abort(first, TEST_OWNER_INDEX + 1u).has_value());
	auto aborted = fixture->tracker->abort(first, TEST_OWNER_INDEX);
	ASSERT_TRUE(aborted.has_value());
	EXPECT_EQ(aborted->retained_slot, 12u);
	EXPECT_FALSE(aborted->standalone);
	fixture->release(aborted->released_slot);
	EXPECT_FALSE(kinetum_async_complete(&first, KINETUM_ASYNC_OUTCOME_SUCCESS));
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);

	fixture->claim(1u);
	const auto second = fixture->tracker->begin({
		.slot_index = 1u,
		.owner_index = TEST_OWNER_INDEX,
		.epoch = TEST_EPOCH,
		.user_tag = 8u,
		.retained_slot = UINT32_MAX,
		.standalone = true,
	});
	EXPECT_NE(second.handle.value, first.handle.value);
	EXPECT_FALSE(kinetum_async_complete(&first, KINETUM_ASYNC_OUTCOME_FAILED));
	auto second_abort = fixture->tracker->abort(second, TEST_OWNER_INDEX);
	ASSERT_TRUE(second_abort.has_value());
	fixture->release(second_abort->released_slot);
	EXPECT_EQ(fixture->ledger->active_unretired(), 0u);
}

/** @brief Prove cancellation never rewrites a post-cancellation SUCCESS outcome. */
TEST(worker_async_work, cancellation_is_orthogonal_to_exact_terminal_outcome)
{
	auto fixture = async_work_fixture::create();
	ASSERT_NE(fixture, nullptr);
	fixture->claim(2u);
	const auto token = fixture->tracker->begin({
		.slot_index = 2u,
		.owner_index = TEST_OWNER_INDEX,
		.epoch = TEST_EPOCH,
		.user_tag = 44u,
		.retained_slot = UINT32_MAX,
		.standalone = true,
	});
	EXPECT_FALSE(kinetum_async_cancellation_requested(&token));
	fixture->tracker->begin_cancellation(TEST_EPOCH);
	EXPECT_TRUE(kinetum_async_cancellation_requested(&token));
	ASSERT_TRUE(kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_SUCCESS));
	worker_async_delivery delivery{};
	ASSERT_TRUE(fixture->tracker->try_take(delivery));
	EXPECT_EQ(delivery.completion.outcome, KINETUM_ASYNC_OUTCOME_SUCCESS);
	fixture->release(delivery.released_slot);
	fixture->tracker->complete_delivery(delivery);
	fixture->tracker->finish_cancellation(TEST_EPOCH);
	EXPECT_TRUE(fixture->tracker->empty());
}

/** @brief Prove completion release/acquire orders prior module-owned result writes. */
TEST(worker_async_work, completion_publication_orders_module_owned_result_storage)
{
	auto fixture = async_work_fixture::create();
	ASSERT_NE(fixture, nullptr);
	fixture->claim(0u);
	const auto token = fixture->tracker->begin({
		.slot_index = 0u,
		.owner_index = TEST_OWNER_INDEX,
		.epoch = TEST_EPOCH,
		.user_tag = 77u,
		.retained_slot = UINT32_MAX,
		.standalone = true,
	});
	uint64_t module_owned_result = 0u;
	std::thread producer([&]() {
		module_owned_result = UINT64_C(0x1122334455667788);
		if (!kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_SUCCESS)) {
			std::terminate();
		}
	});
	worker_async_delivery delivery{};
	while (!fixture->tracker->try_take(delivery)) {
		std::this_thread::yield();
	}
	const uint64_t observed = module_owned_result;
	producer.join();
	EXPECT_EQ(observed, UINT64_C(0x1122334455667788));
	fixture->release(delivery.released_slot);
	fixture->tracker->complete_delivery(delivery);
}

/** @brief Prove one of many foreign publishers wins the sole terminal CAS. */
TEST(worker_async_work, concurrent_terminal_publishers_have_one_winner)
{
	auto fixture = async_work_fixture::create();
	ASSERT_NE(fixture, nullptr);
	fixture->claim(3u);
	const auto token = fixture->tracker->begin({
		.slot_index = 3u,
		.owner_index = TEST_OWNER_INDEX,
		.epoch = TEST_EPOCH,
		.user_tag = 55u,
		.retained_slot = UINT32_MAX,
		.standalone = true,
	});
	std::atomic<uint32_t> winners{0u};
	std::array<std::thread, 8> publishers;
	for (std::size_t index = 0u; index < publishers.size(); ++index) {
		publishers[index] = std::thread([&, index]() {
			const auto outcome = static_cast<kinetum_async_outcome>(KINETUM_ASYNC_OUTCOME_SUCCESS +
										static_cast<int32_t>(index % 3u));
			if (kinetum_async_complete(&token, outcome)) {
				winners.fetch_add(1u, std::memory_order_relaxed);
			}
		});
	}
	for (auto &publisher : publishers) {
		publisher.join();
	}
	EXPECT_EQ(winners.load(std::memory_order_relaxed), 1u);
	worker_async_delivery delivery{};
	ASSERT_TRUE(fixture->tracker->try_take(delivery));
	EXPECT_GE(delivery.completion.outcome, KINETUM_ASYNC_OUTCOME_SUCCESS);
	EXPECT_LE(delivery.completion.outcome, KINETUM_ASYNC_OUTCOME_FAILED);
	fixture->release(delivery.released_slot);
	fixture->tracker->complete_delivery(delivery);
}

/** @brief Prove foreign tracker/context abort cannot mutate the token's real owner. */
TEST(worker_async_work, foreign_portal_abort_rejects_without_mutation)
{
	auto first = async_work_fixture::create();
	auto second = async_work_fixture::create();
	ASSERT_NE(first, nullptr);
	ASSERT_NE(second, nullptr);
	second->claim(0u);
	const auto token = second->tracker->begin({
		.slot_index = 0u,
		.owner_index = TEST_OWNER_INDEX,
		.epoch = TEST_EPOCH,
		.user_tag = 66u,
		.retained_slot = UINT32_MAX,
		.standalone = true,
	});
	EXPECT_FALSE(first->tracker->abort(token, TEST_OWNER_INDEX).has_value());
	auto foreign_portal = token;
	foreign_portal.platform_opaque = first->tracker.get();
	EXPECT_FALSE(kinetum_async_complete(&foreign_portal, KINETUM_ASYNC_OUTCOME_SUCCESS));
	EXPECT_TRUE(kinetum_async_cancellation_requested(&foreign_portal));
	ASSERT_TRUE(kinetum_async_complete(&token, KINETUM_ASYNC_OUTCOME_CANCELLED));
	worker_async_delivery delivery{};
	ASSERT_TRUE(second->tracker->try_take(delivery));
	second->release(delivery.released_slot);
	second->tracker->complete_delivery(delivery);
}

/** @brief Prove unresolved foreign ownership cannot cross tracker destruction. */
TEST(worker_async_work, unresolved_token_destruction_fails_stop)
{
	EXPECT_DEATH(unresolved_token_destruction_child(), "");
}

}  // namespace
}  // namespace kinetum::dp
