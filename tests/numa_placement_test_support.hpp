// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file numa_placement_test_support.hpp
 * @brief Independent native page-residency evidence for exact worker placement.
 * @author Fleming Patel
 *
 * The allocation mechanism proves placement with mbind. These tests query
 * resident pages through move_pages with no target-node array, which cannot
 * migrate them. No production allocator result or node getter supplies the
 * observed node.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <vector>

#include <sys/syscall.h>
#include <unistd.h>

#include "src/dp/numa_layout.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::test
{

/**
 * @brief Query every page covering one real object/storage extent without migration.
 * @param extent Live, completely prefaulted range; an empty range proves nothing.
 * @param expected_node Compiled placement, independent of the allocation's recorded node.
 * @return Success only when every resident page reports that exact node.
 */
[[nodiscard]] inline ::testing::AssertionResult resident_on_node(std::span<const std::byte> extent,
								 int32_t expected_node)
{
	if (extent.empty() || extent.data() == nullptr || expected_node < 0) {
		return ::testing::AssertionFailure() << "residency evidence requires a real extent and exact node";
	}
	const long page_result = ::sysconf(_SC_PAGESIZE);
	if (page_result <= 0) {
		return ::testing::AssertionFailure() << "page-size evidence unavailable";
	}
	const auto page_size = static_cast<std::uintptr_t>(page_result);
	const auto begin = reinterpret_cast<std::uintptr_t>(extent.data());
	if (extent.size() - 1u > std::numeric_limits<std::uintptr_t>::max() - begin) {
		return ::testing::AssertionFailure() << "residency extent overflows";
	}
	const auto first = begin - begin % page_size;
	const auto last = begin + extent.size() - 1u;
	const auto count = (last - first) / page_size + 1u;
	std::vector<void *> pages(count);
	std::vector<int> status(count, std::numeric_limits<int>::min());
	for (std::size_t index = 0u; index < pages.size(); ++index) {
		pages[index] = reinterpret_cast<void *>(first + index * page_size);
	}
	errno = 0;
	const long result = ::syscall(SYS_move_pages, 0, static_cast<unsigned long>(pages.size()), pages.data(),
				      nullptr, status.data(), 0);
	const int error = errno;
	if (result != 0) {
		return ::testing::AssertionFailure()
		       << "resident-page evidence unavailable: move_pages result=" << result << " errno=" << error
		       << " (" << std::strerror(error) << ")";
	}
	for (std::size_t index = 0u; index < status.size(); ++index) {
		if (status[index] != expected_node) {
			return ::testing::AssertionFailure() << "page " << pages[index] << " reports " << status[index]
							     << ", expected node " << expected_node;
		}
	}
	return ::testing::AssertionSuccess();
}

/**
 * @brief Inspect the actual complete allocation retained by a typed owner.
 * @tparam value_type Root type whose nested arrays share its mapping.
 * @param owner Live mapped root.
 * @param expected_node Compiled node to compare with native evidence.
 * @return Complete root containment and page-residency result.
 */
template <typename value_type>
[[nodiscard]] ::testing::AssertionResult resident_owner_on_node(const dp::numa_owner<value_type> &owner,
								int32_t expected_node)
{
	const auto &region = owner.get_deleter().region;
	if (!dp::numa_layout::contains(region, owner.get())) {
		return ::testing::AssertionFailure() << "root lies outside its retained allocation";
	}
	return resident_on_node({static_cast<const std::byte *>(region.data()), region.size()}, expected_node);
}

/** @brief Require two real CPU/memory nodes; a single-node host cannot pass this qualification. */
class NumaPlacementTest : public ::testing::Test {
    protected:
	/** @brief Select allowed CPUs on distinct memory nodes before any allocation or pinning. */
	void SetUp() override
	{
		const auto host = quark::probe_host();
		ASSERT_TRUE(host.valid);
		std::size_t count = 0u;
		for (const auto node : host.memory_numa_nodes) {
			const auto cpu = std::find_if(host.cpus.begin(), host.cpus.end(),
						      [node](const auto &value) { return value.numa_node == node; });
			if (cpu != host.cpus.end()) {
				cpus_[count++] = *cpu;
				if (count == cpus_.size()) {
					break;
				}
			}
		}
		if (count != cpus_.size()) {
			GTEST_SKIP()
				<< "multi-node placement evidence unavailable: two allowed CPU/memory nodes required";
		}
		ASSERT_NE(cpus_[0].numa_node, cpus_[1].numa_node);
		ASSERT_NE(cpus_[0].core_id, cpus_[1].core_id);
	}

	std::array<quark::host_cpu, 2> cpus_{};	 ///< Distinct real placement authorities.
};

}  // namespace kinetum::test
