// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_runtime_status.cpp
 * @brief Exact immutable packet-runtime status publication tests.
 * @author Fleming Patel
 *
 * These tests pin the sole legal fixed-epoch publication sequence and prove
 * that invalid writer operations leave the prior coherent observation intact.
 * Concurrent readers accept only complete CONTROL_READY or PACKET_READY
 * snapshots; no reader observes mutable worker or store state.
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <type_traits>

#include "src/common/epoch_transition_contract.hpp"
#include "src/dp/runtime_status.hpp"

namespace kinetum::dp
{
namespace
{

/** Materialized runtime identity shared by status publications. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 17u;
/** Initial packet-ready epoch. */
constexpr uint64_t TEST_BOOTSTRAP_EPOCH = 23u;
/** Replacement epoch used by transition observations. */
constexpr uint64_t TEST_TARGET_EPOCH = 29u;
/** Exact compiled worker population. */
constexpr uint32_t TEST_WORKER_COUNT = 3u;

/**
 * @brief Require one exact CONTROL_READY observation.
 *
 * @param observed Observer-owned status value.
 */
void expect_control_ready(const runtime_status_snapshot &observed)
{
	EXPECT_NE(observed.publication_generation, 0u);
	EXPECT_EQ(observed.readiness, runtime_readiness::CONTROL_READY);
	EXPECT_EQ(observed.runtime_generation, TEST_RUNTIME_GENERATION);
	EXPECT_EQ(observed.active_epoch, 0u);
	EXPECT_EQ(observed.minimum_retained_epoch, 0u);
	EXPECT_EQ(observed.last_activated_epoch, 0u);
	EXPECT_EQ(observed.active_workers, 0u);
	EXPECT_EQ(observed.expected_workers, TEST_WORKER_COUNT);
}

/**
 * @brief Require one exact PACKET_READY observation.
 *
 * @param observed Observer-owned status value.
 */
void expect_packet_ready(const runtime_status_snapshot &observed)
{
	EXPECT_NE(observed.publication_generation, 0u);
	EXPECT_EQ(observed.readiness, runtime_readiness::PACKET_READY);
	EXPECT_EQ(observed.runtime_generation, TEST_RUNTIME_GENERATION);
	EXPECT_EQ(observed.active_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observed.minimum_retained_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observed.last_activated_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observed.active_workers, TEST_WORKER_COUNT);
	EXPECT_EQ(observed.expected_workers, TEST_WORKER_COUNT);
}

static_assert(!std::is_copy_constructible_v<runtime_status_publication>);
static_assert(!std::is_move_constructible_v<runtime_status_publication>);

}  // namespace

/** @brief Prove no status exists before the generation owner publishes it. */
TEST(runtime_status, starts_without_an_observable_publication)
{
	runtime_status_publication publication;
	runtime_status_snapshot observed{
		.publication_generation = 101u,
		.readiness = runtime_readiness::PACKET_READY,
		.runtime_generation = 103u,
		.active_epoch = 107u,
		.minimum_retained_epoch = 109u,
		.last_activated_epoch = 113u,
		.active_workers = 3u,
		.expected_workers = 5u,
	};
	EXPECT_FALSE(publication.owns_runtime_generation(TEST_RUNTIME_GENERATION));
	EXPECT_EQ(publication.try_read(observed), publication_read_result::UNAVAILABLE);
	EXPECT_EQ(observed.publication_generation, 101u);
	EXPECT_EQ(observed.active_epoch, 107u);
}

/** @brief Prove one exact initial CONTROL_READY publication. */
TEST(runtime_status, publishes_exact_control_ready_once)
{
	runtime_status_publication publication;
	ASSERT_TRUE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, TEST_WORKER_COUNT));
	EXPECT_TRUE(publication.owns_runtime_generation(TEST_RUNTIME_GENERATION));
	EXPECT_FALSE(publication.owns_runtime_generation(TEST_RUNTIME_GENERATION + 1u));
	runtime_status_snapshot observed{};
	ASSERT_EQ(publication.try_read(observed), publication_read_result::AVAILABLE);
	expect_control_ready(observed);
}

/** @brief Coherent out-of-domain identities reject without replacing the caller's prior observation. */
TEST(runtime_status, reader_checks_admitted_generation_and_epoch_ranges)
{
	/** @brief One representable publication and its domain-validation result. */
	struct identity_case {
		uint64_t generation;		   ///< Published runtime-generation identity.
		uint64_t epoch;			   ///< Published bootstrap epoch.
		publication_read_result expected;  ///< Exact reader disposition.
	};
	constexpr std::array CASES{
		identity_case{UINT32_MAX, common::MAX_EPOCH_ID, publication_read_result::AVAILABLE},
		identity_case{uint64_t{UINT32_MAX} + 1u, common::MAX_EPOCH_ID,
			      publication_read_result::INVALID_IDENTITY},
		identity_case{UINT32_MAX, UINT64_MAX, publication_read_result::INVALID_STATE},
	};
	for (const auto &row : CASES) {
		SCOPED_TRACE(row.generation);
		SCOPED_TRACE(row.epoch);
		runtime_status_publication publication;
		ASSERT_TRUE(publication.publish_control_ready(row.generation, TEST_WORKER_COUNT));
		runtime_status_snapshot observed{};
		const auto control_result = row.expected == publication_read_result::INVALID_IDENTITY ?
						    row.expected :
						    publication_read_result::AVAILABLE;
		ASSERT_EQ(publication.try_read(observed), control_result);
		const auto before = observed;
		// The writer consumes admitted inputs; deliberately violate that precondition
		// to prove the observer rejects a coherent value, not merely a torn read.
		ASSERT_TRUE(publication.publish_packet_ready(row.epoch, TEST_WORKER_COUNT));
		ASSERT_EQ(publication.try_read(observed), row.expected);
		if (row.expected == publication_read_result::AVAILABLE) {
			EXPECT_EQ(observed.runtime_generation, row.generation);
			EXPECT_EQ(observed.active_epoch, row.epoch);
			EXPECT_EQ(observed.minimum_retained_epoch, row.epoch);
			EXPECT_EQ(observed.last_activated_epoch, row.epoch);
		} else {
			EXPECT_EQ(observed.publication_generation, before.publication_generation);
			EXPECT_EQ(observed.readiness, before.readiness);
			EXPECT_EQ(observed.runtime_generation, before.runtime_generation);
			EXPECT_EQ(observed.active_epoch, before.active_epoch);
			EXPECT_EQ(observed.minimum_retained_epoch, before.minimum_retained_epoch);
			EXPECT_EQ(observed.last_activated_epoch, before.last_activated_epoch);
			EXPECT_EQ(observed.active_workers, before.active_workers);
			EXPECT_EQ(observed.expected_workers, before.expected_workers);
		}
	}
}

/** @brief Prove malformed or repeated initial publication cannot mutate truth. */
TEST(runtime_status, rejects_invalid_or_repeated_control_ready_without_mutation)
{
	runtime_status_publication publication;
	EXPECT_FALSE(publication.publish_control_ready(0u, TEST_WORKER_COUNT));
	EXPECT_FALSE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, 0u));
	runtime_status_snapshot absent{};
	EXPECT_EQ(publication.try_read(absent), publication_read_result::UNAVAILABLE);

	ASSERT_TRUE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, TEST_WORKER_COUNT));
	runtime_status_snapshot before{};
	ASSERT_EQ(publication.try_read(before), publication_read_result::AVAILABLE);
	EXPECT_FALSE(publication.publish_control_ready(TEST_RUNTIME_GENERATION + 1u, TEST_WORKER_COUNT + 1u));
	runtime_status_snapshot after{};
	ASSERT_EQ(publication.try_read(after), publication_read_result::AVAILABLE);
	EXPECT_EQ(after.publication_generation, before.publication_generation);
	EXPECT_EQ(after.runtime_generation, before.runtime_generation);
	EXPECT_EQ(after.expected_workers, before.expected_workers);
}

/** @brief Prove PACKET_READY cannot precede the initial generation publication. */
TEST(runtime_status, packet_ready_requires_control_ready)
{
	runtime_status_publication publication;
	EXPECT_FALSE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, TEST_WORKER_COUNT));
	runtime_status_snapshot observed{};
	EXPECT_EQ(publication.try_read(observed), publication_read_result::UNAVAILABLE);
}

/** @brief Prove invalid epoch or worker evidence preserves CONTROL_READY. */
TEST(runtime_status, invalid_packet_ready_attempts_preserve_control_ready)
{
	runtime_status_publication publication;
	ASSERT_TRUE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, TEST_WORKER_COUNT));
	EXPECT_FALSE(publication.publish_packet_ready(0u, TEST_WORKER_COUNT));
	EXPECT_FALSE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, TEST_WORKER_COUNT - 1u));
	EXPECT_FALSE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, TEST_WORKER_COUNT + 1u));
	runtime_status_snapshot observed{};
	ASSERT_EQ(publication.try_read(observed), publication_read_result::AVAILABLE);
	expect_control_ready(observed);
}

/** @brief Prove bootstrap publishes all epoch and worker facts atomically. */
TEST(runtime_status, publishes_exact_packet_ready_once)
{
	runtime_status_publication publication;
	ASSERT_TRUE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, TEST_WORKER_COUNT));
	ASSERT_TRUE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, TEST_WORKER_COUNT));
	runtime_status_snapshot observed{};
	ASSERT_EQ(publication.try_read(observed), publication_read_result::AVAILABLE);
	expect_packet_ready(observed);
	const uint64_t generation = observed.publication_generation;
	EXPECT_FALSE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH + 1u, TEST_WORKER_COUNT));
	ASSERT_EQ(publication.try_read(observed), publication_read_result::AVAILABLE);
	EXPECT_EQ(observed.publication_generation, generation);
	expect_packet_ready(observed);
}

/** @brief Prove concurrent observers see only complete legal publications. */
TEST(runtime_status, concurrent_readers_never_observe_a_torn_transition)
{
	runtime_status_publication publication;
	ASSERT_TRUE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, TEST_WORKER_COUNT));
	std::atomic<bool> begin{false};
	std::atomic<uint32_t> legal_reads{0u};
	std::atomic<uint32_t> invalid_reads{0u};
	constexpr std::size_t READER_COUNT = 4u;
	constexpr std::size_t READS_PER_READER = 4096u;
	std::array<std::thread, READER_COUNT> readers;
	for (auto &reader : readers) {
		reader = std::thread([&] {
			while (!begin.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			for (std::size_t attempt = 0; attempt < READS_PER_READER; ++attempt) {
				runtime_status_snapshot observed{};
				const auto read = publication.try_read(observed);
				if (read == publication_read_result::UNAVAILABLE) {
					continue;
				}
				if (read != publication_read_result::AVAILABLE) {
					invalid_reads.fetch_add(1u, std::memory_order_relaxed);
					continue;
				}
				const bool control_ready =
					observed.readiness == runtime_readiness::CONTROL_READY &&
					observed.runtime_generation == TEST_RUNTIME_GENERATION &&
					observed.active_epoch == 0u && observed.minimum_retained_epoch == 0u &&
					observed.last_activated_epoch == 0u && observed.active_workers == 0u &&
					observed.expected_workers == TEST_WORKER_COUNT;
				const bool packet_ready = observed.readiness == runtime_readiness::PACKET_READY &&
							  observed.runtime_generation == TEST_RUNTIME_GENERATION &&
							  observed.active_epoch == TEST_BOOTSTRAP_EPOCH &&
							  observed.minimum_retained_epoch == TEST_BOOTSTRAP_EPOCH &&
							  observed.last_activated_epoch == TEST_BOOTSTRAP_EPOCH &&
							  observed.active_workers == TEST_WORKER_COUNT &&
							  observed.expected_workers == TEST_WORKER_COUNT;
				if (control_ready || packet_ready) {
					legal_reads.fetch_add(1u, std::memory_order_relaxed);
				} else {
					invalid_reads.fetch_add(1u, std::memory_order_relaxed);
				}
			}
		});
	}
	begin.store(true, std::memory_order_release);
	const bool published = publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, TEST_WORKER_COUNT);
	for (auto &reader : readers) {
		reader.join();
	}
	ASSERT_TRUE(published);
	EXPECT_GT(legal_reads.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(invalid_reads.load(std::memory_order_relaxed), 0u);
}

/** @brief Prove fixed bootstrap publishes one exact epoch without deriving a minimum. */
TEST(runtime_status, fixed_bootstrap_publishes_one_exact_epoch_without_derivation)
{
	runtime_status_publication publication;
	ASSERT_TRUE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, TEST_WORKER_COUNT));
	ASSERT_TRUE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, TEST_WORKER_COUNT));
	runtime_status_snapshot observed{};
	ASSERT_EQ(publication.try_read(observed), publication_read_result::AVAILABLE);
	EXPECT_EQ(observed.active_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observed.minimum_retained_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(observed.last_activated_epoch, TEST_BOOTSTRAP_EPOCH);
}

/** @brief Prove packet readiness requires the complete compiled worker population. */
TEST(runtime_status, packet_ready_requires_complete_compiled_worker_population)
{
	runtime_status_publication publication;
	ASSERT_TRUE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, TEST_WORKER_COUNT));
	EXPECT_FALSE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, TEST_WORKER_COUNT - 1u));
	runtime_status_snapshot observed{};
	ASSERT_EQ(publication.try_read(observed), publication_read_result::AVAILABLE);
	expect_control_ready(observed);
	ASSERT_TRUE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, TEST_WORKER_COUNT));
	ASSERT_EQ(publication.try_read(observed), publication_read_result::AVAILABLE);
	expect_packet_ready(observed);
}

/** @brief Prove incomplete bootstrap epoch evidence cannot alter published readiness. */
TEST(runtime_status, incomplete_bootstrap_evidence_preserves_control_ready)
{
	runtime_status_publication publication;
	ASSERT_TRUE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, TEST_WORKER_COUNT));
	runtime_status_snapshot before{};
	ASSERT_EQ(publication.try_read(before), publication_read_result::AVAILABLE);
	EXPECT_FALSE(publication.publish_packet_ready(0u, TEST_WORKER_COUNT));
	runtime_status_snapshot after{};
	ASSERT_EQ(publication.try_read(after), publication_read_result::AVAILABLE);
	EXPECT_EQ(after.publication_generation, before.publication_generation);
	expect_control_ready(after);
}

/** @brief Prove Bootstrap begins one recurring exact N/E/N then N/N/N sequence. */
TEST(runtime_status, fixed_bootstrap_begins_one_recurring_exact_epoch_sequence)
{
	runtime_status_publication publication;
	ASSERT_TRUE(publication.publish_control_ready(TEST_RUNTIME_GENERATION, TEST_WORKER_COUNT));
	runtime_status_snapshot control{};
	ASSERT_EQ(publication.try_read(control), publication_read_result::AVAILABLE);
	ASSERT_TRUE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, TEST_WORKER_COUNT));
	runtime_status_snapshot packet{};
	ASSERT_EQ(publication.try_read(packet), publication_read_result::AVAILABLE);
	EXPECT_GT(packet.publication_generation, control.publication_generation);
	EXPECT_FALSE(publication.publish_packet_ready(TEST_BOOTSTRAP_EPOCH + 1u, TEST_WORKER_COUNT));
	ASSERT_TRUE(publication.can_publish_transition(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH));
	EXPECT_FALSE(publication.can_publish_transition(TEST_BOOTSTRAP_EPOCH, TEST_BOOTSTRAP_EPOCH));
	EXPECT_FALSE(publication.publish_transition_activated(TEST_BOOTSTRAP_EPOCH + 1u, TEST_TARGET_EPOCH));
	ASSERT_TRUE(publication.publish_transition_activated(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH));
	runtime_status_snapshot retiring{};
	ASSERT_EQ(publication.try_read(retiring), publication_read_result::AVAILABLE);
	EXPECT_GT(retiring.publication_generation, packet.publication_generation);
	EXPECT_EQ(retiring.readiness, runtime_readiness::PACKET_READY);
	EXPECT_EQ(retiring.active_epoch, TEST_TARGET_EPOCH);
	EXPECT_EQ(retiring.minimum_retained_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(retiring.last_activated_epoch, TEST_TARGET_EPOCH);
	EXPECT_FALSE(publication.can_publish_transition(TEST_TARGET_EPOCH, TEST_TARGET_EPOCH + 1u));
	EXPECT_FALSE(publication.publish_transition_complete(TEST_BOOTSTRAP_EPOCH));
	ASSERT_TRUE(publication.publish_transition_complete(TEST_TARGET_EPOCH));
	runtime_status_snapshot complete{};
	ASSERT_EQ(publication.try_read(complete), publication_read_result::AVAILABLE);
	EXPECT_GT(complete.publication_generation, retiring.publication_generation);
	EXPECT_EQ(complete.active_epoch, TEST_TARGET_EPOCH);
	EXPECT_EQ(complete.minimum_retained_epoch, TEST_TARGET_EPOCH);
	EXPECT_EQ(complete.last_activated_epoch, TEST_TARGET_EPOCH);
}

}  // namespace kinetum::dp
