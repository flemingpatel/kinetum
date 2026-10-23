// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_packet_staging.cpp
 * @brief Shared packet capacity, bounded key service, role rotation and construction ownership.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <limits>
#include <optional>
#include <random>
#include <span>
#include <utility>
#include <vector>

#include "src/common/status.hpp"
#include "src/dp/worker_packet_staging.hpp"
#include "src/quark/host_probe.hpp"
#include "tests/packet_staging_test_harness.hpp"

namespace kinetum::dp
{
namespace
{

/** @brief Require actual process-allocatable NUMA evidence for the production allocator. */
class WorkerPacketStagingTest : public ::testing::Test {
    protected:
	/** @brief Resolve one exact host node without a skipped allocation gate. */
	void SetUp() override
	{
		const auto host = quark::probe_host();
		ASSERT_TRUE(host.valid);
		ASSERT_FALSE(host.memory_numa_nodes.empty());
		numa_node_ = host.memory_numa_nodes.front();
	}
	int32_t numa_node_{-1};	 ///< Proven node used by every region in this fixture.
};

/** @brief Closed ownership contradictions exercised before any destructor can mask the target. */
enum class staging_violation {
	ACTIVE_ROTATION,    ///< Rotate while queued old work remains.
	RESERVED_ROTATION,  ///< Rotate with an outstanding capacity claim.
	ABSENT_ROTATION,    ///< Rotate a fixed/non-source domain.
	NON_RX_FUTURE,	    ///< Publish executable work into an inert future role.
	UNKNOWN_KEY,	    ///< Commit through an ordinal absent from the compiled key set.
	RECURSIVE_SERVICE,  ///< Re-enter ready service from its callback.
	LIVE_DESTRUCTION,   ///< Reclaim backing storage while a future pointer remains owned.
};

/**
 * @brief Require a typed construction rejection without observing error() on success.
 * @param domains Complete candidate domain population.
 * @param numa_node Candidate allocation node.
 * @param expected Required refusal class.
 */
void expect_rejection(std::span<const worker_packet_staging_domain> domains, int32_t numa_node,
		      common::status_code expected)
{
	auto result = worker_packet_staging::create(domains, numa_node);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), expected);
}

/**
 * @brief Reject extra capacity and retire any unexpectedly granted claim before cleanup.
 * @param domain Fixture role expected to have no admission capacity.
 */
void expect_no_capacity(packet_epoch_input_staging &domain)
{
	const bool reserved = domain.reserve_active();
	EXPECT_FALSE(reserved);
	if (reserved) {
		domain.release_active_reservation();
	}
}

/**
 * @brief Trigger one exact contradiction after successful construction, then exit if it was not enforced.
 * @param numa_node Proven node inherited from the parent fixture.
 * @param violation Target ownership edge.
 */
void violate_staging(int32_t numa_node, staging_violation violation)
{
	constexpr std::array<packet_work_key, 2> KEYS{{
		{0u, packet_work_phase::RX_DELIVER, {}},
		{1u, packet_work_phase::EXECUTE, {}},
	}};
	const std::array<worker_packet_staging_domain, 1> DOMAINS{{
		{0u, 4u,
		 violation == staging_violation::ABSENT_ROTATION ? std::nullopt : std::optional<std::size_t>(4u), KEYS},
	}};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node);
	if (!owner_or.is_ok()) {
		const auto message = owner_or.error().message();
		std::fprintf(stderr, "staging fixture construction failed: %.*s\n", static_cast<int>(message.size()),
			     message.data());
		std::_Exit(EXIT_SUCCESS);
	}
	auto owner = std::move(owner_or).value();
	auto &domain = owner->domains().front();
	packet_record record{};
	record.metadata.epoch = 1u;
	std::array<packet_record *, 4> scratch{};
	switch (violation) {
	case staging_violation::ACTIVE_ROTATION:
		if (!domain.reserve_active()) {
			std::_Exit(EXIT_SUCCESS);
		}
		domain.commit_active(0u, &record);
		domain.rotate_after_activation();
		break;
	case staging_violation::RESERVED_ROTATION:
		if (!domain.reserve_active()) {
			std::_Exit(EXIT_SUCCESS);
		}
		domain.rotate_after_activation();
		break;
	case staging_violation::ABSENT_ROTATION:
		domain.rotate_after_activation();
		break;
	case staging_violation::NON_RX_FUTURE:
		if (!domain.reserve_future()) {
			std::_Exit(EXIT_SUCCESS);
		}
		record.metadata.epoch = 2u;
		record.metadata.current_stage = 1u;
		record.metadata.current_stage_instance = 1u;
		domain.commit_future(1u, &record);
		break;
	case staging_violation::UNKNOWN_KEY:
		if (!domain.reserve_active()) {
			std::_Exit(EXIT_SUCCESS);
		}
		domain.commit_active(2u, &record);
		break;
	case staging_violation::RECURSIVE_SERVICE:
		if (!domain.reserve_active()) {
			std::_Exit(EXIT_SUCCESS);
		}
		domain.commit_active(0u, &record);
		domain.service_active(scratch, [&](const packet_work_key &, std::span<packet_record *const>) noexcept {
			domain.service_active(scratch,
					      [](const packet_work_key &, std::span<packet_record *const>) noexcept {});
		});
		break;
	case staging_violation::LIVE_DESTRUCTION:
		if (!domain.reserve_future()) {
			std::_Exit(EXIT_SUCCESS);
		}
		record.metadata.epoch = 2u;
		domain.commit_future(0u, &record);
		owner.reset();
		break;
	}
	std::_Exit(EXIT_SUCCESS);
}

}  // namespace

/** @brief Reject invalid identity, capacity, key and extent input before acquiring any NUMA storage. */
TEST(worker_packet_staging, malformed_construction_rejects_before_mapping)
{
	constexpr std::array<packet_work_key, 1> KEYS{{{0u, packet_work_phase::RX_DELIVER, {}}}};
	worker_packet_staging_domain domain{0u, 4u, 4u, KEYS};
	expect_rejection({&domain, 1u}, -1, common::status_code::INVALID_ARGUMENT);
	for (const std::size_t capacity : {0u, 1u, 3u, 1000u}) {
		domain.capacity = capacity;
		domain.future_capacity = capacity;
		expect_rejection({&domain, 1u}, 0, common::status_code::INVALID_ARGUMENT);
	}
	domain.capacity = 4u;
	domain.future_capacity = 8u;
	expect_rejection({&domain, 1u}, 0, common::status_code::INVALID_ARGUMENT);
	domain.future_capacity = 4u;
	const std::array<worker_packet_staging_domain, 2> DUPLICATES{domain, domain};
	expect_rejection(DUPLICATES, 0, common::status_code::INVALID_ARGUMENT);
	std::array<packet_work_key, 2> keys{{KEYS.front(), KEYS.front()}};
	domain.keys = keys;
	expect_rejection({&domain, 1u}, 0, common::status_code::INVALID_ARGUMENT);
	for (const packet_work_key key : std::array<packet_work_key, 3>{{
		     {UINT32_MAX, packet_work_phase::EXECUTE, {}},
		     {0u, static_cast<packet_work_phase>(0u), {}},
		     {0u, packet_work_phase::EXECUTE, {1u, 0u, 0u}},
	     }}) {
		domain.keys = {&key, 1u};
		expect_rejection({&domain, 1u}, 0, common::status_code::INVALID_ARGUMENT);
	}
	domain.keys = KEYS;
	domain.capacity = std::size_t{1u} << (std::numeric_limits<std::size_t>::digits - 2u);
	domain.future_capacity = domain.capacity;
	expect_rejection({&domain, 1u}, 0, common::status_code::OUT_OF_RANGE);
}

/** @brief Placement failure publishes no partial domain owner and a fresh valid construction starts empty. */
TEST_F(WorkerPacketStagingTest, failed_region_construction_retires_unpublished_ownership)
{
	constexpr std::array<packet_work_key, 1> KEYS{{{0u, packet_work_phase::RX_DELIVER, {}}}};
	const std::array<worker_packet_staging_domain, 2> DOMAINS{{{0u, 4u, 4u, KEYS}, {1u, 8u, std::nullopt, KEYS}}};
	// This passes staging shape admission but exceeds the native allocator's
	// Linux nodemask extent after mapping, exercising its guarded unwind.
	expect_rejection(DOMAINS, std::numeric_limits<int32_t>::max(), common::status_code::OUT_OF_RANGE);
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	ASSERT_EQ(owner_or.value()->domains().size(), 2u);
	for (const auto &domain : owner_or.value()->domains()) {
		EXPECT_TRUE(domain.empty());
		EXPECT_EQ(domain.active_available(), domain.active_capacity());
	}
}

/** @brief Source pairs, active-only domains and transient-only roles retain their exact capacities and identities. */
TEST_F(WorkerPacketStagingTest, source_pairs_and_transient_roles_keep_exact_capacities)
{
	constexpr std::array<packet_work_key, 1> KEYS{{{0u, packet_work_phase::RX_DELIVER, {}}}};
	const std::array<worker_packet_staging_domain, 3> DOMAINS{{
		{0u, 2u, 2u, KEYS},
		{3u, 4u, std::nullopt, KEYS},
		{7u, 8u, std::nullopt, {}},
	}};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	ASSERT_EQ(owner->domains().size(), 3u);
	EXPECT_GT(owner->storage_bytes(), 0u);
	for (std::size_t index = 0u; index < DOMAINS.size(); ++index) {
		auto &domain = owner->domains()[index];
		EXPECT_EQ(domain.storage_domain_index(), DOMAINS[index].storage_domain_index);
		EXPECT_EQ(domain.numa_node(), numa_node_);
		EXPECT_EQ(domain.active_capacity(), DOMAINS[index].capacity);
		EXPECT_EQ(domain.future_capacity(), DOMAINS[index].future_capacity.value_or(0u));
		EXPECT_EQ(domain.keys().size(), DOMAINS[index].keys.size());
		EXPECT_EQ(reinterpret_cast<std::uintptr_t>(&domain) % algo::CACHE_LINE_SIZE, 0u);
		ASSERT_TRUE(domain.reserve_active());
		EXPECT_EQ(domain.active_available(), domain.active_capacity() - 1u);
		domain.release_active_reservation();
		EXPECT_TRUE(domain.empty());
	}
	EXPECT_TRUE(owner->domains()[0].activation_ready());
	EXPECT_FALSE(owner->domains()[1].activation_ready());
	auto empty_or = worker_packet_staging::create({}, numa_node_);
	ASSERT_TRUE(empty_or.is_ok());
	EXPECT_TRUE(empty_or.value()->domains().empty());
	EXPECT_EQ(empty_or.value()->storage_bytes(), 0u);
}

/** @brief Dequeue retains shared capacity until requeue or final release, even when the selected ring has room. */
TEST_F(WorkerPacketStagingTest, queued_and_outstanding_ownership_share_one_capacity)
{
	constexpr std::array<packet_work_key, 2> KEYS{{
		{0u, packet_work_phase::EXECUTE, {}},
		{1u, packet_work_phase::EXECUTE, {}},
	}};
	const std::array<worker_packet_staging_domain, 1> DOMAINS{{{0u, 4u, std::nullopt, KEYS}}};
	std::array<packet_record, 5> records{};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	test::packet_staging_cleanup cleanup(*owner);
	auto &domain = owner->domains().front();
	for (uint32_t index = 0u; index < 4u; ++index) {
		ASSERT_TRUE(domain.reserve_active());
		records[index].metadata.current_stage_instance = static_cast<uint16_t>(index / 2u);
		domain.commit_active(index / 2u, &records[index]);
	}
	EXPECT_EQ(domain.active_available(), 0u);
	expect_no_capacity(domain);
	std::array<packet_record *, 2> scratch{};
	std::size_t calls = 0u;
	domain.service_active(scratch, [&](const packet_work_key &key, std::span<packet_record *const> batch) noexcept {
		++calls;
		EXPECT_EQ(key.stage_instance_index, 0u);
		EXPECT_EQ(batch.size(), 2u);
		if (batch.size() != 2u) {
			for (std::size_t index = 0u; index < batch.size(); ++index) {
				domain.release_active_reservation();
			}
			return;
		}
		EXPECT_EQ(batch[0], &records[0]);
		EXPECT_EQ(batch[1], &records[1]);
		expect_no_capacity(domain);
		batch[0]->metadata.current_stage_instance = 1u;
		domain.commit_active(1u, batch[0]);
		domain.release_active_reservation();
		EXPECT_EQ(domain.active_available(), 1u);
		const bool reserved = domain.reserve_active();
		EXPECT_TRUE(reserved);
		if (reserved) {
			domain.commit_active(0u, &records[4]);
		}
	});
	EXPECT_EQ(calls, 1u);
	EXPECT_EQ(domain.active_available(), 0u);
}

/** @brief Service defers new keys and self-retries while preserving FIFO appends to an already waiting key. */
TEST_F(WorkerPacketStagingTest, service_defers_new_keys_and_same_key_retries)
{
	constexpr std::array<packet_work_key, 3> KEYS{{
		{0u, packet_work_phase::EXECUTE, {}},
		{1u, packet_work_phase::EXECUTE, {}},
		{2u, packet_work_phase::EXECUTE, {}},
	}};
	const std::array<worker_packet_staging_domain, 1> DOMAINS{{{0u, 8u, std::nullopt, KEYS}}};
	std::array<packet_record, 3> records{};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	test::packet_staging_cleanup cleanup(*owner);
	auto &domain = owner->domains().front();
	for (uint32_t index = 0u; index < 3u; ++index) {
		const uint32_t key = index == 2u ? 1u : 0u;
		records[index].metadata.current_stage_instance = static_cast<uint16_t>(key);
		ASSERT_TRUE(domain.reserve_active());
		domain.commit_active(key, &records[index]);
	}
	std::array<packet_record *, 64> scratch{};
	std::vector<uint32_t> visits;
	visits.reserve(KEYS.size());
	domain.service_active(scratch, [&](const packet_work_key &key, std::span<packet_record *const> batch) noexcept {
		visits.push_back(key.stage_instance_index);
		if (key.stage_instance_index == 0u) {
			EXPECT_EQ(batch.size(), 2u);
			if (batch.size() != 2u) {
				for (std::size_t index = 0u; index < batch.size(); ++index) {
					domain.release_active_reservation();
				}
				return;
			}
			batch[0]->metadata.current_stage_instance = 2u;
			domain.commit_active(2u, batch[0]);
			domain.commit_active(0u, batch[1]);
		} else {
			for (auto *record : batch) {
				(void)record;
				domain.release_active_reservation();
			}
		}
	});
	EXPECT_EQ(visits, (std::vector<uint32_t>{0u, 1u}));
	visits.clear();
	domain.service_active(scratch, [&](const packet_work_key &key, std::span<packet_record *const> batch) noexcept {
		visits.push_back(key.stage_instance_index);
		for (std::size_t index = 0u; index < batch.size(); ++index) {
			domain.release_active_reservation();
		}
	});
	EXPECT_EQ(visits, (std::vector<uint32_t>{2u, 0u}));
	ASSERT_TRUE(domain.empty());

	for (uint32_t key = 0u; key < 2u; ++key) {
		records[key].metadata.current_stage_instance = static_cast<uint16_t>(key);
		ASSERT_TRUE(domain.reserve_active());
		domain.commit_active(key, &records[key]);
	}
	visits.clear();
	domain.service_active(scratch, [&](const packet_work_key &key, std::span<packet_record *const> batch) noexcept {
		visits.push_back(key.stage_instance_index);
		if (key.stage_instance_index == 0u) {
			EXPECT_EQ(batch.size(), 1u);
			for (auto *record : batch) {
				record->metadata.current_stage_instance = 1u;
				domain.commit_active(1u, record);
			}
		} else {
			EXPECT_EQ(batch.size(), 2u);
			if (batch.size() == 2u) {
				EXPECT_EQ(batch[0], &records[1]);
				EXPECT_EQ(batch[1], &records[0]);
			}
			for (std::size_t index = 0u; index < batch.size(); ++index) {
				domain.release_active_reservation();
			}
		}
	});
	EXPECT_EQ(visits, (std::vector<uint32_t>{0u, 1u}));
	EXPECT_TRUE(domain.empty());
}

/** @brief A ready population larger than the record budget preserves waiting-key order across turns. */
TEST_F(WorkerPacketStagingTest, sixty_four_records_bound_a_turn_with_more_ready_keys)
{
	std::array<packet_work_key, 70> keys{};
	std::array<packet_record, 70> records{};
	for (uint32_t index = 0u; index < keys.size(); ++index) {
		keys[index] = {index, packet_work_phase::EXECUTE, {}};
		records[index].metadata.current_stage_instance = static_cast<uint16_t>(index);
	}
	const std::array<worker_packet_staging_domain, 1> DOMAINS{{{0u, 128u, std::nullopt, keys}}};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	test::packet_staging_cleanup cleanup(*owner);
	auto &domain = owner->domains().front();
	for (uint32_t index = 0u; index < keys.size(); ++index) {
		ASSERT_TRUE(domain.reserve_active());
		domain.commit_active(index, &records[index]);
	}
	std::array<packet_record *, 64> scratch{};
	uint32_t next = 0u;
	const auto consume = [&](const packet_work_key &key, std::span<packet_record *const> batch) noexcept {
		EXPECT_EQ(key.stage_instance_index, next);
		EXPECT_EQ(batch.size(), 1u);
		EXPECT_LT(next, records.size());
		if (next < records.size() && !batch.empty()) {
			EXPECT_EQ(batch.front(), &records[next]);
		}
		++next;
		for (std::size_t index = 0u; index < batch.size(); ++index) {
			domain.release_active_reservation();
		}
	};
	domain.service_active(scratch, consume);
	EXPECT_EQ(next, 64u);
	domain.service_active(scratch, consume);
	EXPECT_EQ(next, 70u);
	EXPECT_TRUE(domain.empty());
}

/** @brief Future RX stays inert, preserves FIFO pointers and becomes executable through complete role exchange. */
TEST_F(WorkerPacketStagingTest, future_rx_is_inert_until_role_rotation)
{
	constexpr std::array<packet_work_key, 2> KEYS{{
		{0u, packet_work_phase::RX_DELIVER, {}},
		{1u, packet_work_phase::EXECUTE, {}},
	}};
	const std::array<worker_packet_staging_domain, 1> DOMAINS{{{0u, 4u, 4u, KEYS}}};
	std::array<packet_record, 3> records{};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	test::packet_staging_cleanup cleanup(*owner);
	auto &domain = owner->domains().front();
	for (auto &record : records) {
		record.metadata.epoch = 17u;
		ASSERT_TRUE(domain.reserve_future());
		domain.commit_future(0u, &record);
	}
	std::array<packet_record *, 4> scratch{};
	std::size_t observed = 0u;
	const auto consume = [&](const packet_work_key &key, std::span<packet_record *const> batch) noexcept {
		EXPECT_EQ(key.phase, packet_work_phase::RX_DELIVER);
		for (auto *record : batch) {
			EXPECT_LT(observed, records.size());
			if (observed < records.size()) {
				EXPECT_EQ(record, &records[observed]);
			}
			++observed;
			EXPECT_EQ(record->metadata.epoch, 17u);
			domain.release_active_reservation();
		}
	};
	domain.service_active(scratch, consume);
	EXPECT_EQ(observed, 0u);
	EXPECT_TRUE(domain.active_empty());
	EXPECT_FALSE(domain.future_empty());
	ASSERT_TRUE(domain.activation_ready());
	domain.rotate_after_activation();
	EXPECT_TRUE(domain.future_empty());
	EXPECT_EQ(domain.active_available(), 1u);
	domain.service_active(scratch, consume);
	EXPECT_EQ(observed, 3u);
	EXPECT_TRUE(domain.empty());
}

/** @brief Dequeued capacity stays occupied after callback return until foreign ownership finishes. */
TEST_F(WorkerPacketStagingTest, outstanding_batch_claim_survives_service_return)
{
	constexpr std::array<packet_work_key, 1> KEYS{{{0u, packet_work_phase::EXECUTE, {}}}};
	const std::array<worker_packet_staging_domain, 1> DOMAINS{{{0u, 2u, 2u, KEYS}}};
	std::array<packet_record, 2> records{};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	test::packet_staging_cleanup cleanup(*owner);
	auto &domain = owner->domains().front();
	for (auto &record : records) {
		ASSERT_TRUE(domain.reserve_active());
		domain.commit_active(0u, &record);
	}
	std::array<packet_record *, 1> scratch{};
	packet_record *retained = nullptr;
	domain.service_active(scratch, [&](const packet_work_key &, std::span<packet_record *const> batch) noexcept {
		EXPECT_EQ(batch.size(), 1u);
		if (!batch.empty()) {
			retained = batch.front();
		}
		for (std::size_t index = 1u; index < batch.size(); ++index) {
			domain.release_active_reservation();
		}
	});
	EXPECT_EQ(retained, &records[0]);
	EXPECT_EQ(domain.active_available(), 0u);
	expect_no_capacity(domain);
	EXPECT_FALSE(domain.activation_ready());
	if (retained != nullptr) {
		domain.release_active_reservation();
	}
	EXPECT_EQ(domain.active_available(), 1u);
}

/** @brief A deque reference conserves records and key FIFO through random admission, retry and retirement. */
TEST_F(WorkerPacketStagingTest, randomized_reference_preserves_capacity_and_key_order)
{
	constexpr std::size_t CAPACITY = 32u;
	constexpr std::size_t KEY_COUNT = 7u;
	std::array<packet_work_key, KEY_COUNT> keys{};
	std::array<packet_record, CAPACITY> records{};
	std::vector<std::size_t> free;
	for (std::size_t index = 0u; index < CAPACITY; ++index) {
		free.push_back(index);
		records[index].metadata.user_meta = index;
	}
	for (std::size_t key = 0u; key < KEY_COUNT; ++key) {
		keys[key] = {static_cast<uint32_t>(key), packet_work_phase::EXECUTE, {}};
	}
	const std::array<worker_packet_staging_domain, 1> DOMAINS{{{0u, CAPACITY, std::nullopt, keys}}};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	test::packet_staging_cleanup cleanup(*owner);
	auto &domain = owner->domains().front();
	std::array<std::deque<std::size_t>, KEY_COUNT> pending;
	std::deque<uint32_t> ready;
	std::mt19937 random(0x62b4d1u);
	std::array<packet_record *, 64> scratch{};
	std::size_t total_admitted = 0u;
	std::size_t total_retired = 0u;
	for (uint32_t turn = 0u; turn < 1200u; ++turn) {
		SCOPED_TRACE(turn);
		/** @brief Model membership by sequence search, independently of ring positions and claimed bits. */
		const auto enqueue = [&](uint32_t key, std::size_t record, uint32_t servicing) {
			if (key != servicing && std::find(ready.begin(), ready.end(), key) == ready.end()) {
				ready.push_back(key);
			}
			pending[key].push_back(record);
		};
		const std::size_t arrivals = std::min<std::size_t>(free.size(), random() % 17u);
		for (std::size_t arrival = 0u; arrival < arrivals; ++arrival) {
			const std::size_t record = free.back();
			free.pop_back();
			const uint32_t key = static_cast<uint32_t>(random() % KEY_COUNT);
			enqueue(key, record, UINT32_MAX);
			records[record].metadata.current_stage_instance = static_cast<uint16_t>(key);
			ASSERT_TRUE(domain.reserve_active());
			domain.commit_active(key, &records[record]);
			++total_admitted;
		}
		/** @brief Deterministic workload policy applied to both the reference and the real callback. */
		const auto destination = [turn](uint32_t key, std::size_t record) noexcept -> uint32_t {
			return (record + turn) % 5u == 0u ?
				       UINT32_MAX :
				       static_cast<uint32_t>((key + 1u + (record & 1u)) % KEY_COUNT);
		};
		/** @brief Expected semantic callback independent of physical queue storage. */
		struct expected_batch {
			uint32_t key;			   ///< Expected stage/phase queue.
			std::vector<std::size_t> records;  ///< Exact FIFO packet identities.
		};
		std::vector<expected_batch> expected;
		const std::size_t allowance = 1u + random() % scratch.size();
		std::size_t remaining = allowance;
		const std::size_t ready_prefix = ready.size();
		for (std::size_t service = 0u; service < ready_prefix && remaining != 0u; ++service) {
			const uint32_t key = ready.front();
			ready.pop_front();
			const std::size_t count = std::min(remaining, pending[key].size());
			expected_batch batch{key, {}};
			for (std::size_t lane = 0u; lane < count; ++lane) {
				batch.records.push_back(pending[key].front());
				pending[key].pop_front();
			}
			const bool requeued = !pending[key].empty();
			if (requeued) {
				ready.push_back(key);
			}
			for (const std::size_t record : batch.records) {
				const uint32_t next = destination(key, record);
				if (next == UINT32_MAX) {
					free.push_back(record);
					++total_retired;
				} else {
					enqueue(next, record, key);
				}
			}
			if (!requeued && !pending[key].empty()) {
				ready.push_back(key);
			}
			remaining -= count;
			expected.push_back(std::move(batch));
		}
		std::size_t observed = 0u;
		scratch.fill(reinterpret_cast<packet_record *>(std::uintptr_t{0xa5a5a5a5u}));
		domain.service_active(
			std::span<packet_record *>(scratch).first(allowance),
			[&](const packet_work_key &key, std::span<packet_record *const> batch) noexcept {
				EXPECT_LT(observed, expected.size());
				if (observed < expected.size()) {
					EXPECT_EQ(key.stage_instance_index, expected[observed].key);
					EXPECT_EQ(batch.size(), expected[observed].records.size());
				}
				for (std::size_t lane = 0u; lane < batch.size(); ++lane) {
					auto *record = batch[lane];
					const auto found = std::find_if(records.begin(), records.end(),
									[record](const packet_record &candidate) {
										return &candidate == record;
									});
					EXPECT_NE(found, records.end());
					if (found == records.end()) {
						domain.release_active_reservation();
						continue;
					}
					const std::size_t identity = static_cast<std::size_t>(found - records.begin());
					if (observed < expected.size() && lane < expected[observed].records.size()) {
						EXPECT_EQ(identity, expected[observed].records[lane]);
					}
					const uint32_t next = destination(key.stage_instance_index, identity);
					if (next == UINT32_MAX) {
						domain.release_active_reservation();
					} else {
						record->metadata.current_stage_instance = static_cast<uint16_t>(next);
						domain.commit_active(next, record);
					}
				}
				++observed;
			});
		EXPECT_EQ(observed, expected.size());
		EXPECT_EQ(domain.active_available(), free.size());
		EXPECT_EQ(total_admitted - total_retired, CAPACITY - free.size());
		if (HasFailure()) {
			return;
		}
	}
	EXPECT_GT(total_admitted, CAPACITY);
	EXPECT_GT(total_retired, CAPACITY);
}

/** @brief Every two-prefix startup heals fragmentation without changing FIFO, conservation or turn bounds. */
TEST_F(WorkerPacketStagingTest, partial_startups_converge_under_the_same_record_budget)
{
	constexpr std::size_t CAPACITY = 1024u;
	constexpr std::size_t BURST = 64u;
	constexpr std::size_t TURNS = 160u;
	constexpr std::array<packet_work_key, 3> KEYS{{
		{0u, packet_work_phase::EXECUTE, {}},
		{1u, packet_work_phase::EXECUTE, {}},
		{2u, packet_work_phase::EXECUTE, {}},
	}};
	const std::array<worker_packet_staging_domain, 1> DOMAINS{{{0u, CAPACITY, std::nullopt, KEYS}}};
	std::array<packet_record, CAPACITY> records{};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	test::packet_staging_cleanup cleanup(*owner);
	auto &domain = owner->domains().front();
	std::array<packet_record *, BURST> scratch{};
	std::vector<packet_record *> free;
	free.reserve(CAPACITY);
	for (std::size_t first = 0u; first <= BURST; ++first) {
		for (std::size_t second = 0u; second <= BURST; ++second) {
			SCOPED_TRACE(::testing::Message() << first << ',' << second);
			ASSERT_TRUE(domain.empty());
			free.clear();
			for (auto &record : records) {
				free.push_back(&record);
			}
			std::array<uint64_t, KEYS.size()> next{};
			uint64_t admitted = 0u;
			std::size_t visits = 0u;
			uint32_t serviced = 0u;
			bool valid = true;
			bool measure_full = false;
			std::size_t full_calls = 0u;
			/** @brief Check packet identity and route each record once without modeling scheduler order. */
			const auto execute = [&](const packet_work_key &key,
						 std::span<packet_record *const> batch) noexcept {
				const uint32_t stage = key.stage_instance_index;
				if (stage >= KEYS.size()) {
					valid = false;
					domain.release_active_reservation(batch.size());
					return;
				}
				valid = valid && (serviced & (1u << stage)) == 0u && !batch.empty();
				serviced |= 1u << stage;
				visits += batch.size();
				if (measure_full) {
					valid = valid && batch.size() == BURST;
					++full_calls;
				}
				for (auto *record : batch) {
					valid = valid && record->metadata.user_meta == next[stage] &&
						record->metadata.current_stage_instance == stage;
					++next[stage];
					if (stage + 1u < KEYS.size()) {
						record->metadata.current_stage_instance =
							static_cast<uint16_t>(stage + 1u);
						domain.commit_active(stage + 1u, record);
					} else {
						domain.release_active_reservation();
						if (free.size() == CAPACITY) {
							valid = false;
						} else {
							free.push_back(record);
						}
					}
				}
			};
			for (std::size_t turn = 0u; turn < TURNS; ++turn) {
				const std::size_t offered = turn == 0u ? first : turn == 1u ? second : BURST;
				const std::size_t count = std::min(offered, free.size());
				ASSERT_TRUE(domain.reserve_active(count));
				for (std::size_t lane = 0u; lane < count; ++lane) {
					auto *record = free.back();
					free.pop_back();
					record->metadata.user_meta = admitted++;
					record->metadata.current_stage_instance = 0u;
					domain.commit_active(0u, record);
				}
				measure_full = turn >= TURNS - 32u;
				visits = 0u;
				serviced = 0u;
				domain.service_active(scratch, execute);
				ASSERT_TRUE(valid);
				ASSERT_LE(visits, BURST);
				ASSERT_EQ(domain.active_available(), free.size());
				ASSERT_EQ(admitted - next.back(), CAPACITY - free.size());
			}
			measure_full = false;
			for (std::size_t turn = 0u; !domain.empty() && turn < CAPACITY * KEYS.size(); ++turn) {
				visits = 0u;
				serviced = 0u;
				domain.service_active(scratch, execute);
				ASSERT_TRUE(valid);
				ASSERT_GT(visits, 0u);
				ASSERT_LE(visits, BURST);
			}
			ASSERT_TRUE(domain.empty());
			EXPECT_EQ(free.size(), CAPACITY);
			EXPECT_GT(full_calls, 0u);
			for (const auto completed : next) {
				EXPECT_EQ(completed, admitted);
			}
		}
	}
}

/** @brief A counted reservation shares its bound with queued work and permits exact unused-prefix release. */
TEST_F(WorkerPacketStagingTest, counted_reservations_preserve_shared_capacity)
{
	constexpr std::array<packet_work_key, 1> KEYS{{{0u, packet_work_phase::RX_DELIVER, {}}}};
	const std::array<worker_packet_staging_domain, 1> DOMAINS{{{0u, 4u, 4u, KEYS}}};
	auto owner_or = worker_packet_staging::create(DOMAINS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	test::packet_staging_cleanup cleanup(*owner);
	auto &domain = owner->domains().front();
	EXPECT_TRUE(domain.reserve_active(0u));
	EXPECT_EQ(domain.active_available(), 4u);
	ASSERT_TRUE(domain.reserve_active(3u));
	EXPECT_FALSE(domain.reserve_active(2u));
	EXPECT_FALSE(domain.reserve_active(std::numeric_limits<std::size_t>::max()));
	EXPECT_EQ(domain.active_available(), 1u);
	domain.release_active_reservation(2u);
	EXPECT_EQ(domain.active_available(), 3u);
	domain.release_active_reservation(0u);
	domain.release_active_reservation();
	ASSERT_TRUE(domain.reserve_future(4u));
	EXPECT_FALSE(domain.reserve_future(1u));
	domain.release_future_reservation(4u);
	EXPECT_TRUE(domain.empty());
}

/** @brief Contradictory publication, service, rotation and destruction fail at their own ownership edge. */
TEST_F(WorkerPacketStagingTest, ownership_contradictions_fail_stop)
{
	for (const auto violation :
	     {staging_violation::ACTIVE_ROTATION, staging_violation::RESERVED_ROTATION,
	      staging_violation::ABSENT_ROTATION, staging_violation::NON_RX_FUTURE, staging_violation::UNKNOWN_KEY,
	      staging_violation::RECURSIVE_SERVICE, staging_violation::LIVE_DESTRUCTION}) {
		SCOPED_TRACE(static_cast<int>(violation));
		EXPECT_DEATH(violate_staging(numa_node_, violation), "");
	}
}

}  // namespace kinetum::dp
