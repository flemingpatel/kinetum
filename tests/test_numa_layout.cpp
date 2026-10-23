// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_numa_layout.cpp
 * @brief Checked layout geometry and typed NUMA ownership lifetimes.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <type_traits>
#include <utility>

#include "src/dp/numa_layout.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::dp
{
namespace
{

/** @brief Select an actually permitted node without treating an unavailable probe as node zero. */
class NumaLayoutTest : public ::testing::Test {
    protected:
	/** @brief Establish the native allocation precondition before any owner is constructed. */
	void SetUp() override
	{
		const auto host = quark::probe_host();
		ASSERT_TRUE(host.valid);
		ASSERT_FALSE(host.memory_numa_nodes.empty());
		node_ = host.memory_numa_nodes.front();
	}
	int32_t node_{-1};  ///< Exact permitted native node.
};

/** @brief Expose construction and destruction without reading reclaimed mapped memory. */
struct alignas(64) tracked_root {
	/** @param live External live-object count that outlives the mapping. */
	explicit tracked_root(uint32_t &live) noexcept
		: live_(&live)
	{
		++*live_;
	}
	/** @brief Retire one live object while its mapping still exists. */
	~tracked_root()
	{
		--*live_;
	}
	uint32_t *live_;  ///< Caller-owned lifetime observation.
};

}  // namespace

/** @brief Independently pin aligned scalar and repeated-row extents, including zero populations. */
TEST(numa_layout, exact_extents_and_row_padding)
{
	numa_layout layout;
	std::size_t prefix = 99u;
	std::size_t scalar = 99u;
	std::size_t rows = 99u;
	std::size_t stride = 99u;
	ASSERT_TRUE(layout.append<uint8_t>(7u, prefix));
	ASSERT_TRUE(layout.append<uint32_t>(1u, scalar));
	ASSERT_TRUE(layout.append_rows<uint64_t>(2u, 3u, rows, stride, 64u));
	EXPECT_EQ(prefix, 0u);
	EXPECT_EQ(scalar, 8u);
	EXPECT_EQ(rows, 64u);
	EXPECT_EQ(stride, 64u);
	EXPECT_EQ(layout.size(), 192u);
	ASSERT_TRUE(layout.append_rows<uint64_t>(0u, 3u, rows, stride, 64u));
	EXPECT_EQ(rows, 192u);
	EXPECT_EQ(stride, 0u);
	EXPECT_EQ(layout.size(), 192u);
	ASSERT_TRUE(layout.append_rows<uint64_t>(5u, 0u, rows, stride, 64u));
	EXPECT_EQ(layout.size(), 192u);
}

/** @brief Reject invalid alignment and every arithmetic overflow without publishing partial geometry. */
TEST(numa_layout, rejected_extents_leave_all_outputs_unchanged)
{
	numa_layout layout;
	std::size_t offset = 31u;
	std::size_t stride = 37u;
	EXPECT_FALSE(layout.append<uint64_t>(1u, offset, 4u));
	EXPECT_FALSE(layout.append<uint8_t>(1u, offset, 3u));
	EXPECT_FALSE(layout.append<uint64_t>(std::numeric_limits<std::size_t>::max(), offset));
	EXPECT_FALSE(layout.append_rows<uint64_t>(std::numeric_limits<std::size_t>::max(), 1u, offset, stride, 64u));
	EXPECT_EQ(offset, 31u);
	EXPECT_EQ(stride, 37u);
	EXPECT_EQ(layout.size(), 0u);
	ASSERT_TRUE(layout.append<uint8_t>(std::numeric_limits<std::size_t>::max() - 3u, offset));
	const std::size_t before = layout.size();
	offset = 31u;
	EXPECT_FALSE(layout.append<uint64_t>(1u, offset));
	EXPECT_EQ(layout.size(), before);
	EXPECT_EQ(offset, 31u);
}

/** @brief Placement rejection creates no object and never replaces an unavailable node with another one. */
TEST(numa_layout, invalid_node_and_empty_layout_fail_before_construction)
{
	static_assert(noexcept(numa_memory_region::allocate(numa_memory_options{})));
	static_assert(noexcept(std::declval<const numa_layout &>().allocate(-1)));
	numa_layout empty;
	EXPECT_FALSE(empty.allocate(0).is_ok());
	uint32_t live = 0u;
	const auto invalid = make_numa_owner<tracked_root>(-1, [&](void *storage) noexcept {
		return new (storage) tracked_root(live);
	});
	ASSERT_FALSE(invalid.is_ok());
	EXPECT_EQ(invalid.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(live, 0u);
}

/** @brief Typed ownership keeps its aligned root alive through moves and destroys it exactly once. */
TEST_F(NumaLayoutTest, root_and_mapping_have_one_retirement_owner)
{
	static_assert(!std::is_copy_constructible_v<numa_owner<tracked_root>>);
	static_assert(std::is_nothrow_move_constructible_v<numa_owner<tracked_root>>);
	uint32_t live = 0u;
	auto owner_or = make_numa_owner<tracked_root>(node_, [&](void *storage) noexcept {
		return new (storage) tracked_root(live);
	});
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	const auto *address = owner.get();
	EXPECT_TRUE(numa_layout::contains(owner.get_deleter().region, address));
	EXPECT_EQ(owner.get_deleter().region.host_numa_node(), node_);
	EXPECT_EQ(live, 1u);
	auto moved = std::move(owner);
	EXPECT_EQ(owner, nullptr);
	EXPECT_EQ(moved.get(), address);
	EXPECT_EQ(live, 1u);
	moved.reset();
	EXPECT_EQ(live, 0u);
	EXPECT_FALSE(moved.get_deleter().region);
}

/** @brief Repeated rows are disjoint and resolve only inside their declared matrix and mapping. */
TEST_F(NumaLayoutTest, typed_rows_preserve_contents_and_reject_outside_rows)
{
	numa_layout layout;
	std::size_t offset = 0u;
	std::size_t stride = 0u;
	ASSERT_TRUE(layout.append_rows<uint32_t>(2u, 3u, offset, stride, 64u));
	auto region_or = layout.allocate(node_);
	ASSERT_TRUE(region_or.is_ok()) << region_or.error().message();
	auto region = std::move(region_or).value();
	for (std::size_t row = 0u; row < 2u; ++row) {
		auto values = numa_layout::row<uint32_t>(region, offset, stride, row, 2u, 3u);
		for (std::size_t column = 0u; column < values.size(); ++column) {
			std::construct_at(&values[column], static_cast<uint32_t>(10u * row + column));
		}
	}
	const auto first = numa_layout::row<uint32_t>(region, offset, stride, 0u, 2u, 3u);
	const auto second = numa_layout::row<uint32_t>(region, offset, stride, 1u, 2u, 3u);
	EXPECT_EQ(first[2], 2u);
	EXPECT_EQ(second[0], 10u);
	EXPECT_TRUE(numa_layout::contains_extent(region, std::as_bytes(first)));
	EXPECT_TRUE(numa_layout::contains_extent(region, std::as_bytes(second)));
	EXPECT_TRUE(numa_layout::disjoint(std::as_bytes(first), std::as_bytes(second)));
	EXPECT_FALSE(numa_layout::disjoint(std::as_bytes(first), std::as_bytes(first.subspan(1u))));
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(second.data()) - reinterpret_cast<std::uintptr_t>(first.data()),
		  64u);
	EXPECT_DEATH((void)numa_layout::row<uint32_t>(region, offset, stride, 2u, 2u, 3u), "");
	EXPECT_DEATH((void)numa_layout::storage<uint64_t>(region, 1u, 1u), "");
	EXPECT_DEATH((void)numa_layout::storage<uint32_t>(region, region.size(), 1u), "");
}

/** @brief Swap and replacement preserve root/mapping identity and retire each replaced root exactly once. */
TEST_F(NumaLayoutTest, owner_transfers_preserve_root_and_mapping_identity)
{
	uint32_t live = 0u;
	const auto construct = [&](void *storage) noexcept { return new (storage) tracked_root(live); };
	auto first_or = make_numa_owner<tracked_root>(node_, construct);
	auto second_or = make_numa_owner<tracked_root>(node_, construct);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto first = std::move(first_or).value();
	auto second = std::move(second_or).value();
	const auto *first_address = first.get();
	const auto *second_address = second.get();
	first.swap(second);
	EXPECT_EQ(first.get(), second_address);
	EXPECT_EQ(second.get(), first_address);
	EXPECT_TRUE(numa_layout::contains(first.get_deleter().region, first.get()));
	EXPECT_TRUE(numa_layout::contains(second.get_deleter().region, second.get()));
	const auto *address = second.get();
	EXPECT_EQ(live, 2u);
	first = std::move(second);
	EXPECT_EQ(live, 1u);
	EXPECT_EQ(first.get(), address);
	EXPECT_EQ(second.get(), nullptr);
	EXPECT_FALSE(second.get_deleter().region);
	first.reset();
	EXPECT_EQ(live, 0u);
}

/** @brief A cold allocator adapter receives exact checked geometry and its failure remains authoritative. */
TEST(numa_layout, adapter_failure_does_not_publish_an_owner_or_retry_placement)
{
	numa_layout layout;
	std::size_t offset = 0u;
	ASSERT_TRUE(layout.append<uint64_t>(3u, offset, 128u));
	uint32_t calls = 0u;
	const auto refuse = [&](const numa_memory_options &options) -> common::status_or<numa_memory_region> {
		++calls;
		EXPECT_EQ(options.usable_bytes, 24u);
		EXPECT_EQ(options.alignment_bytes, 128u);
		EXPECT_EQ(options.host_numa_node, 7);
		return common::status::resource_exhausted("declared allocation refused");
	};
	const auto invalid = layout.allocate(-1, refuse);
	EXPECT_EQ(invalid.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(calls, 0u);
	const auto refused = layout.allocate(7, refuse);
	ASSERT_FALSE(refused.is_ok());
	EXPECT_EQ(refused.error().code(), common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(refused.error().message(), "declared allocation refused");
	EXPECT_EQ(calls, 1u);
}

}  // namespace kinetum::dp
