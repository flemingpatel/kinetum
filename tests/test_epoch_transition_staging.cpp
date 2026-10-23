// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_epoch_transition_staging.cpp
 * @brief Exact NUMA SPSC and boundary-hold tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <utility>

#include "src/common/status.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/numa_spsc_ring.hpp"
#include "src/dp/packet.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::dp
{
namespace
{

/** Compact boundary identity used by staging-role fixtures. */
constexpr uint32_t TEST_BOUNDARY_INDEX = 7u;
/** Exact sending worker identity. */
constexpr uint32_t TEST_SENDER_WORKER_INDEX = 2u;
/** Exact receiving worker identity. */
constexpr uint32_t TEST_RECEIVER_WORKER_INDEX = 3u;

/**
 * @brief Select one exact process-allocatable NUMA node.
 *
 * @return Lowest available node, or -1 when the host cannot prove one.
 */
[[nodiscard]] int32_t test_numa_node()
{
	const auto host = quark::probe_host();
	if (!host.valid || host.memory_numa_nodes.empty()) {
		return -1;
	}
	return host.memory_numa_nodes.front();
}

/**
 * @brief Build one complete boundary descriptor with exact future-hold capacity.
 *
 * @param numa_node Exact DATA-ring NUMA node retained in the descriptor.
 * @param capacity Exact future-output hold capacity.
 * @return Complete compact boundary facts.
 */
[[nodiscard]] common::compiled_transition_boundary boundary_facts(int32_t numa_node, uint32_t capacity = 2u)
{
	return {
		.boundary_id = "boundary_7",
		.boundary_index = TEST_BOUNDARY_INDEX,
		.from_stage_instance_index = 11u,
		.to_stage_instance_index = 13u,
		.sender_worker_index = TEST_SENDER_WORKER_INDEX,
		.receiver_worker_index = TEST_RECEIVER_WORKER_INDEX,
		.data_ring_capacity = 2u,
		.future_output_hold_capacity = capacity,
		.data_ring_numa_node = numa_node,
	};
}

/**
 * @brief Destroy one NUMA ring while it retains an element.
 *
 * @param numa_node Exact process-allocatable host NUMA node.
 */
void destroy_live_numa_ring(int32_t numa_node)
{
	auto ring_or = numa_spsc_ring<int>::create(2u, numa_node);
	if (!ring_or.is_ok() || !ring_or.value()->try_push(7)) {
		std::_Exit(EXIT_SUCCESS);
	}
}

/**
 * @brief Destroy one boundary hold while it retains packet ownership.
 *
 * @param numa_node Exact process-allocatable host NUMA node.
 */
void destroy_live_future_hold(int32_t numa_node)
{
	auto hold_or = boundary_future_output_hold::create(boundary_facts(numa_node), numa_node);
	packet_record record{};
	if (!hold_or.is_ok() || hold_or.value()->try_hold(std::array{&record}) != 1u) {
		std::_Exit(EXIT_SUCCESS);
	}
}

/**
 * @brief Publish a null packet into one exact future hold.
 *
 * @param numa_node Exact process-allocatable host NUMA node.
 */
void hold_null_packet(int32_t numa_node)
{
	auto hold_or = boundary_future_output_hold::create(boundary_facts(numa_node), numa_node);
	if (!hold_or.is_ok()) {
		std::_Exit(EXIT_SUCCESS);
	}
	(void)hold_or.value()->try_hold(std::array<packet_record *, 1>{nullptr});
	std::_Exit(EXIT_SUCCESS);
}

}  // namespace

/** @brief Prove exact NUMA placement, runtime capacity, FIFO, and batch arithmetic. */
TEST(numa_spsc_ring, exact_capacity_fifo_batch_and_numa_are_composed_once)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto ring_or = numa_spsc_ring<int>::create(4u, numa_node);
	ASSERT_TRUE(ring_or.is_ok()) << ring_or.error().message();
	auto ring = std::move(ring_or).value();
	EXPECT_EQ(ring->capacity(), 4u);
	EXPECT_EQ(ring->numa_node(), numa_node);

	const std::array input{3, 5, 7, 11, 13};
	EXPECT_EQ(ring->push_batch(input.data(), input.size()), 4u);
	EXPECT_TRUE(ring->full());
	ASSERT_NE(ring->peek(), nullptr);
	EXPECT_EQ(*ring->peek(), 3);

	std::array<int, 4> output{};
	std::size_t consumed = 0u;
	EXPECT_EQ(ring->consume_prefix(4u,
				       [&](const int &value) noexcept {
					       if (value == 7) {
						       return false;
					       }
					       output[consumed++] = value;
					       return true;
				       }),
		  2u);
	EXPECT_EQ(consumed, 2u);
	EXPECT_EQ(output[0], 3);
	EXPECT_EQ(output[1], 5);
	EXPECT_TRUE(ring->try_push(13));
	EXPECT_EQ(ring->pop_batch(output.data(), output.size()), 3u);
	EXPECT_EQ(output[0], 7);
	EXPECT_EQ(output[1], 11);
	EXPECT_EQ(output[2], 13);
	EXPECT_TRUE(ring->empty());
}

/** @brief Reject malformed capacity/NUMA and fail stop on retained destruction. */
TEST(numa_spsc_ring, malformed_shape_and_live_destruction_fail_closed)
{
	EXPECT_EQ(numa_spsc_ring<int>::create(1u, 0).error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(numa_spsc_ring<int>::create(3u, 0).error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(numa_spsc_ring<int>::create(2u, -1).error().code(), common::status_code::INVALID_ARGUMENT);
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	EXPECT_DEATH(destroy_live_numa_ring(numa_node), "");
}

/** @brief Preserve exact boundary identity, FIFO pointers, and bounded backpressure. */
TEST(boundary_future_output_hold, exact_identity_fifo_and_backpressure_conserve_ownership)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto facts = boundary_facts(numa_node);
	facts.data_ring_numa_node = numa_node == 0 ? 1 : 0;
	auto hold_or = boundary_future_output_hold::create(facts, numa_node);
	ASSERT_TRUE(hold_or.is_ok()) << hold_or.error().message();
	auto hold = std::move(hold_or).value();
	EXPECT_EQ(hold->boundary_index(), TEST_BOUNDARY_INDEX);
	EXPECT_EQ(hold->sender_worker_index(), TEST_SENDER_WORKER_INDEX);
	EXPECT_EQ(hold->numa_node(), numa_node);
	EXPECT_NE(hold->numa_node(), facts.data_ring_numa_node);
	EXPECT_EQ(hold->capacity(), 2u);

	std::array<packet_record, 3> records{};
	EXPECT_EQ(hold->try_hold({}), 0u);
	EXPECT_EQ(hold->try_hold(std::array{&records[0], &records[1], &records[2]}), 2u);
	EXPECT_EQ(hold->try_hold(std::array{&records[2]}), 0u);
	EXPECT_EQ(hold->size_approx(), 2u);
	EXPECT_EQ(hold->peek(), &records[0]);
	packet_record *released = nullptr;
	ASSERT_TRUE(hold->try_release(released));
	EXPECT_EQ(released, &records[0]);
	ASSERT_TRUE(hold->try_release(released));
	EXPECT_EQ(released, &records[1]);
	EXPECT_FALSE(hold->try_release(released));
	EXPECT_TRUE(hold->empty());
}

/** @brief Reject malformed holds and fail stop on null/live ownership. */
TEST(boundary_future_output_hold, malformed_shape_and_live_ownership_fail_closed)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto facts = boundary_facts(numa_node, 0u);
	EXPECT_EQ(boundary_future_output_hold::create(facts, numa_node).error().code(),
		  common::status_code::INVALID_ARGUMENT);
	facts = boundary_facts(numa_node);
	facts.receiver_worker_index = facts.sender_worker_index;
	EXPECT_EQ(boundary_future_output_hold::create(facts, numa_node).error().code(),
		  common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(boundary_future_output_hold::create(boundary_facts(numa_node), -1).error().code(),
		  common::status_code::FAILED_PRECONDITION);
	EXPECT_DEATH(hold_null_packet(numa_node), "");
	EXPECT_DEATH(destroy_live_future_hold(numa_node), "");
}

}  // namespace kinetum::dp
