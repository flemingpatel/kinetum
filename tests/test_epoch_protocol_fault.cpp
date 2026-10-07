// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_epoch_protocol_fault.cpp
 * @brief Exact write-once ordered-transition fault-authority tests.
 * @author Fleming Patel
 */

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "src/dp/epoch/epoch_protocol_fault.hpp"

namespace kinetum::dp
{
namespace
{

/**
 * @brief Construct one complete immutable test fault.
 * @param code Exact fault class to publish.
 * @param observed Distinguishing observed value and timestamp suffix.
 * @return One complete immutable test fault.
 */
epoch_protocol_first_fault test_fault(epoch_protocol_fault_code code, uint64_t observed) noexcept
{
	return epoch_protocol_first_fault{
		.runtime_generation = 7u,
		.transition_generation = 3u,
		.from_epoch = 11u,
		.to_epoch = 12u,
		.observed_epoch = 12u,
		.expected_value = 10u,
		.observed_value = observed,
		.observed_monotonic_ns = 100u + observed,
		.worker_index = 1u,
		.boundary_index = 2u,
		.context_index = UINT32_MAX,
		.stage_instance_index = UINT32_MAX,
		.code = code,
		.disposition = epoch_protocol_fault_disposition::TERMINATE,
		.padding = {},
	};
}

}  // namespace

/** @brief Preserve exact fixed layout and one immutable first writer. */
TEST(epoch_protocol_fault, first_writer_is_immutable_and_transition_success_block_is_sticky)
{
	EXPECT_EQ(sizeof(epoch_protocol_first_fault), 128u);
	EXPECT_EQ(alignof(epoch_protocol_first_fault), 64u);
	EXPECT_EQ(offsetof(epoch_protocol_first_fault, code), 80u);
	EXPECT_EQ(offsetof(epoch_protocol_first_fault, disposition), 81u);
	EXPECT_EQ(offsetof(epoch_protocol_first_fault, padding), 82u);
	EXPECT_EQ(sizeof(epoch_protocol_fault_latch), 256u);
	epoch_protocol_fault_latch latch;
	epoch_protocol_first_fault observed{};
	EXPECT_FALSE(latch.try_read(observed));
	EXPECT_FALSE(latch.transition_success_blocked());
	const auto first = test_fault(epoch_protocol_fault_code::CUT_IDENTITY_MISMATCH, 11u);
	EXPECT_TRUE(latch.record(first));
	EXPECT_TRUE(latch.transition_success_blocked());
	ASSERT_TRUE(latch.try_read(observed));
	EXPECT_EQ(observed.code, first.code);
	EXPECT_EQ(observed.observed_value, 11u);
	EXPECT_FALSE(latch.record(test_fault(epoch_protocol_fault_code::OWNERSHIP_OVERFLOW, 12u)));
	ASSERT_TRUE(latch.try_read(observed));
	EXPECT_EQ(observed.code, first.code);
	EXPECT_EQ(observed.observed_value, 11u);
}

/** @brief Keep allocator exhaustion observable without blocking a transaction. */
TEST(epoch_protocol_fault, resource_refusal_does_not_fabricate_transition_success_block)
{
	epoch_protocol_fault_latch latch;
	auto fault = test_fault(epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED, UINT64_MAX - 1u);
	fault.transition_generation = 0u;
	fault.to_epoch = 0u;
	fault.disposition = epoch_protocol_fault_disposition::RESOURCE_REFUSED;
	EXPECT_TRUE(latch.record(fault));
	EXPECT_FALSE(latch.transition_success_blocked());
	epoch_protocol_first_fault observed{};
	ASSERT_TRUE(latch.try_read(observed));
	EXPECT_EQ(observed.disposition, epoch_protocol_fault_disposition::RESOURCE_REFUSED);
}

/** @brief Prove concurrent fault reporters publish exactly one complete record. */
TEST(epoch_protocol_fault, concurrent_reporters_publish_one_complete_identity)
{
	epoch_protocol_fault_latch latch;
	std::atomic<uint32_t> winners{0u};
	std::vector<std::thread> reporters;
	for (uint64_t index = 1u; index <= 8u; ++index) {
		reporters.emplace_back([&latch, &winners, index]() {
			if (latch.record(test_fault(epoch_protocol_fault_code::OWNERSHIP_WRONG_SLOT, index))) {
				winners.fetch_add(1u, std::memory_order_relaxed);
			}
		});
	}
	for (auto &reporter : reporters) {
		reporter.join();
	}
	EXPECT_EQ(winners.load(std::memory_order_relaxed), 1u);
	epoch_protocol_first_fault observed{};
	ASSERT_TRUE(latch.try_read(observed));
	EXPECT_EQ(observed.code, epoch_protocol_fault_code::OWNERSHIP_WRONG_SLOT);
	EXPECT_GE(observed.observed_value, 1u);
	EXPECT_LE(observed.observed_value, 8u);
}

/** @brief Reject malformed fixed records before publication. */
TEST(epoch_protocol_fault, malformed_first_fault_is_terminate_class)
{
	EXPECT_DEATH(
		{
			epoch_protocol_fault_latch latch;
			auto fault = test_fault(epoch_protocol_fault_code::SEQUENCE_EXHAUSTED, 1u);
			fault.runtime_generation = 0u;
			(void)latch.record(fault);
		},
		"");
	EXPECT_DEATH(
		{
			epoch_protocol_fault_latch latch;
			auto fault = test_fault(epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED, 1u);
			(void)latch.record(fault);
		},
		"");
	EXPECT_DEATH(
		{
			epoch_protocol_fault_latch latch;
			auto fault = test_fault(epoch_protocol_fault_code::OWNERSHIP_UNDERFLOW, 1u);
			fault.disposition = epoch_protocol_fault_disposition::RESOURCE_REFUSED;
			(void)latch.record(fault);
		},
		"");
	EXPECT_DEATH(
		{
			epoch_protocol_fault_latch latch;
			auto fault = test_fault(epoch_protocol_fault_code::CUT_IDENTITY_MISMATCH, 1u);
			fault.disposition = epoch_protocol_fault_disposition::DROP_AND_RETIRE;
			(void)latch.record(fault);
		},
		"");
}

}  // namespace kinetum::dp
