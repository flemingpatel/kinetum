// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_numa_memory.cpp
 * @brief Native advice, placement, failure and lifetime proofs for NUMA mappings.
 * @author Fleming Patel
 *
 * VMA flags witness accepted advice independently of physical huge backing.
 * Syscall refusal and process THP policy are confined to exit-test children;
 * no production hook or host setting supplies a different allocation path.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <barrier>
#include <bit>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <linux/filter.h>
#include <linux/mempolicy.h>
#include <linux/seccomp.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "src/common/status.hpp"
#include "src/dp/numa_layout.hpp"
#include "src/dp/numa_memory.hpp"
#include "tests/memory_mapping_test_support.hpp"
#include "tests/numa_placement_test_support.hpp"
#include "tests/numa_test_support.hpp"

namespace kinetum::dp
{
namespace
{

using common::status_code;

/** Caller alignment smaller than every supported Linux base page. */
constexpr std::size_t TEST_ALIGNMENT = 64u;

/** @brief Establish the real node and base-page geometry before constructing any owner. */
class NumaMemoryTest : public ::testing::Test {
    protected:
	/** @brief Require native placement and representable geometry for the syscall fixtures. */
	void SetUp() override
	{
		node_ = test::required_memory_numa_node();
		ASSERT_GE(node_, 0);
		const long page = ::sysconf(_SC_PAGESIZE);
		ASSERT_GT(page, 0);
		page_bytes_ = static_cast<std::size_t>(page);
		ASSERT_TRUE(std::has_single_bit(page_bytes_));
		ASSERT_GE(page_bytes_, TEST_ALIGNMENT);
		ASSERT_LE(page_bytes_, std::numeric_limits<uint32_t>::max() / 8u);
	}

	int32_t node_{-1};	      ///< Proved process-allowed memory node.
	std::size_t page_bytes_{0u};  ///< Observed Linux base-page size.
};

/**
 * @brief Fail an expected-success child without hiding the original fixture error in cleanup.
 * @param condition Required native or ownership observation.
 * @param message Static diagnostic identifying the failed proof.
 */
void require_child(bool condition, const char *message) noexcept
{
	if (!condition) {
		std::fprintf(stderr, "NUMA memory fixture failed: %s\n", message);
		std::_Exit(EXIT_FAILURE);
	}
}

/** @brief One independently specified native-operation refusal and expected outcome. */
struct native_operation_refusal {
	const char *name;      ///< Diagnostic label, never behavior selection.
	long number;	       ///< Native syscall to reject.
	std::size_t argument;  ///< Syscall argument identifying the exact operation.
	uint32_t value;	       ///< Matching low argument word.
	status_code expected;  ///< Expected production status; OK admits the region.
};

/**
 * @brief Deny one native syscall/argument pair only in the current isolated child.
 * @param operation Native syscall and matching argument on the supported little-endian targets.
 * @param error Positive Linux errno returned for a matching call.
 * @return true after the kernel copies the complete process-local filter.
 */
[[nodiscard]] bool deny_syscall(const native_operation_refusal &operation, int error) noexcept
{
	const auto number = operation.number;
	const auto argument = operation.argument;
	const auto value = operation.value;
	static_assert(std::endian::native == std::endian::little);
	if (number < 0 || static_cast<unsigned long>(number) > UINT32_MAX || argument >= 6u || error <= 0 ||
	    error > 4095) {
		return false;
	}
	const auto offset = static_cast<uint32_t>(offsetof(seccomp_data, args) + argument * sizeof(uint64_t));
	std::array<sock_filter, 6> instructions{{
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(seccomp_data, nr))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(number), 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | static_cast<uint32_t>(error)),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	}};
	sock_fprog program{static_cast<unsigned short>(instructions.size()), instructions.data()};
	return ::prctl(PR_SET_NO_NEW_PRIVS, 1ul, 0ul, 0ul, 0ul) == 0 &&
	       ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0ul, 0ul) == 0;
}

/** @return Kernel-reported virtual page count; observation failure exits the child unsuccessfully. */
[[nodiscard]] std::size_t virtual_page_count()
{
	std::FILE *input = std::fopen("/proc/self/statm", "r");
	require_child(input != nullptr, "statm unavailable");
	std::array<char, 128> line{};
	const auto *read = std::fgets(line.data(), static_cast<int>(line.size()), input);
	const int closed = std::fclose(input);
	require_child(read != nullptr && closed == 0, "statm observation incomplete");
	const auto end = std::find(line.begin(), line.end(), ' ');
	require_child(end != line.end(), "statm page count has no delimiter");
	const auto *last = line.data() + std::distance(line.begin(), end);
	std::size_t count = 0u;
	const auto parsed = std::from_chars(line.data(), last, count);
	require_child(parsed.ec == std::errc{} && parsed.ptr == last && count != 0u, "statm page count is invalid");
	return count;
}

/**
 * @brief Observe that the page containing an expired address no longer has a mapping.
 * @param address Retained integer address, never dereferenced after retirement.
 * @param page_bytes Observed base-page size.
 * @return true only for the kernel's unmapped-range result.
 */
[[nodiscard]] bool page_is_unmapped(std::uintptr_t address, std::size_t page_bytes) noexcept
{
	unsigned char residency = 0u;
	errno = 0;
	const int result = ::mincore(reinterpret_cast<void *>(address - address % page_bytes), page_bytes, &residency);
	return result == -1 && errno == ENOMEM;
}

/**
 * @brief Check repeated native refusals without changing a previously published owner.
 * @param node Proved memory node inherited from the parent fixture.
 * @param page_bytes Observed base-page geometry.
 * @param operation Exact denied syscall and argument.
 * @param error Injected errno.
 */
void check_refusal(int32_t node, std::size_t page_bytes, const native_operation_refusal &operation, int error)
{
	auto prefix_or = numa_memory_region::allocate({page_bytes, TEST_ALIGNMENT, node});
	require_child(prefix_or.is_ok(), "retained-prefix construction");
	auto prefix = std::move(prefix_or).value();
	std::memset(prefix.data(), 0x47, prefix.size());
	const numa_memory_options options{3u * page_bytes + 1u, TEST_ALIGNMENT, node, true};
	{
		auto warm_or = numa_memory_region::allocate(options);
		require_child(warm_or.is_ok(), "native observation warmup allocation");
		auto warm = std::move(warm_or).value();
		require_child(static_cast<bool>(test::has_hugepage_advice(warm.data(), warm.size(), true)),
			      "accepted advice unavailable before refusal");
		require_child(static_cast<bool>(test::resident_on_node(
				      {static_cast<const std::byte *>(warm.data()), warm.size()}, node)),
			      "native placement observation unavailable");
	}
	const auto before = virtual_page_count();
	require_child(deny_syscall(operation, error), "syscall refusal filter installation");
	for (unsigned int trial = 0u; trial < 4u; ++trial) {
		auto result = numa_memory_region::allocate(options);
		if (operation.expected == status_code::OK) {
			require_child(result.is_ok(), "advice refusal rejected a valid mapping");
			auto region = std::move(result).value();
			require_child(region.size() == options.usable_bytes &&
					      reinterpret_cast<std::uintptr_t>(region.data()) % TEST_ALIGNMENT == 0u,
				      "advice refusal changed geometry");
			const auto bytes = std::span(static_cast<std::byte *>(region.data()), region.size());
			require_child(static_cast<bool>(test::resident_on_node(bytes, node)),
				      "advice refusal weakened resident placement");
			require_child(std::all_of(bytes.begin(), bytes.end(),
						  [](std::byte value) { return value == std::byte{0}; }),
				      "advice refusal skipped initialization");
			require_child(static_cast<bool>(test::has_hugepage_advice(region.data(), region.size(), false)),
				      "denied advice changed VMA flags");
			std::fill(bytes.begin(), bytes.end(), std::byte{0x31});
			require_child(std::all_of(bytes.begin(), bytes.end(),
						  [](std::byte value) { return value == std::byte{0x31}; }),
				      "advice refusal left unusable bytes");
		} else {
			require_child(!result.is_ok(), "required native failure published an owner");
			require_child(result.error().code() == operation.expected, "wrong native failure category");
		}
		const auto retained = std::span(static_cast<const std::byte *>(prefix.data()), prefix.size());
		require_child(std::all_of(retained.begin(), retained.end(),
					  [](std::byte value) { return value == std::byte{0x47}; }),
			      "native failure damaged retained ownership");
	}
	const auto after = virtual_page_count();
	if (before != after) {
		std::fprintf(stderr, "virtual pages before=%zu after=%zu\n", before, after);
	}
	require_child(before == after, "native failure leaked a mapping");
}

/**
 * @brief Exercise advice while all THP is prohibited in this isolated child.
 * @param node Proved memory node.
 * @param page_bytes Observed base-page size.
 */
void check_process_prohibition(int32_t node, std::size_t page_bytes)
{
	require_child(::prctl(PR_SET_THP_DISABLE, 1ul, 0ul, 0ul, 0ul) == 0, "process THP prohibition");
	require_child(::prctl(PR_GET_THP_DISABLE, 0ul, 0ul, 0ul, 0ul) == 1, "process THP policy readback");
	auto result = numa_memory_region::allocate({3u * page_bytes + 1u, TEST_ALIGNMENT, node, true});
	require_child(result.is_ok(), "process prohibition rejected required allocation properties");
	auto region = std::move(result).value();
	std::vector<test::memory_mapping_observation> observations;
	require_child(static_cast<bool>(test::observe_memory_mapping(region.data(), region.size(), observations)),
		      "process-prohibited mapping evidence");
	for (const auto &entry : observations) {
		require_child(entry.hugepage_advice && entry.anon_huge_kb == 0u,
			      "advice and prohibited PMD backing were conflated");
	}
	const auto bytes = std::span(static_cast<const std::byte *>(region.data()), region.size());
	require_child(static_cast<bool>(test::resident_on_node(bytes, node)), "process prohibition changed placement");
	require_child(std::all_of(bytes.begin(), bytes.end(), [](std::byte value) { return value == std::byte{0}; }),
		      "process prohibition skipped initialization");
}

/** @brief Invalid requests reject before mapping, independent of the optional preference. */
TEST(numa_memory, rejects_invalid_geometry)
{
	static_assert(!numa_memory_options{}.prefer_large_pages);
	static_assert(!numa_memory_options{1u, TEST_ALIGNMENT, 0}.prefer_large_pages);
	const std::array invalid{
		numa_memory_options{0u, TEST_ALIGNMENT, std::nullopt},
		numa_memory_options{1u, 0u, std::nullopt},
		numa_memory_options{1u, 3u, std::nullopt},
		numa_memory_options{1u, TEST_ALIGNMENT, -1},
	};
	for (auto options : invalid) {
		for (const bool preference : {false, true}) {
			options.prefer_large_pages = preference;
			const auto result = numa_memory_region::allocate(options);
			ASSERT_FALSE(result.is_ok());
			EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);
		}
	}
	const auto overflowing = numa_memory_region::allocate(
		{std::numeric_limits<std::size_t>::max(), TEST_ALIGNMENT, std::nullopt, true});
	ASSERT_FALSE(overflowing.is_ok());
	EXPECT_EQ(overflowing.error().code(), status_code::OUT_OF_RANGE);
}

/** @brief Accepted advice is observed independently while byte geometry and exact-node residency stay unchanged. */
TEST_F(NumaMemoryTest, advice_scope_preserves_geometry_initialization_and_placement)
{
	for (const bool preference : {false, true}) {
		for (const auto size : {std::size_t{1u}, page_bytes_ - 1u, page_bytes_, page_bytes_ + 1u}) {
			for (const auto alignment : {TEST_ALIGNMENT, page_bytes_, 2u * page_bytes_}) {
				SCOPED_TRACE(::testing::Message() << "preference=" << preference << " size=" << size
								  << " alignment=" << alignment);
				auto result = numa_memory_region::allocate({size, alignment, node_, preference});
				ASSERT_TRUE(result.is_ok()) << result.error().message();
				auto region = std::move(result).value();
				EXPECT_EQ(region.size(), size);
				EXPECT_EQ(region.host_numa_node(), node_);
				EXPECT_EQ(reinterpret_cast<std::uintptr_t>(region.data()) % alignment, 0u);
				const auto bytes = std::span(static_cast<std::byte *>(region.data()), region.size());
				EXPECT_TRUE(test::resident_on_node(bytes, node_));
				EXPECT_TRUE(std::all_of(bytes.begin(), bytes.end(),
							[](std::byte value) { return value == std::byte{0}; }));
				EXPECT_TRUE(test::has_hugepage_advice(region.data(), region.size(), preference));
				std::fill(bytes.begin(), bytes.end(), std::byte{0x53});
				EXPECT_TRUE(std::all_of(bytes.begin(), bytes.end(),
							[](std::byte value) { return value == std::byte{0x53}; }));
			}
		}
	}
}

/** @brief The default layout adapter does not request page-size advice. */
TEST_F(NumaMemoryTest, default_layout_does_not_request_advice)
{
	numa_layout layout;
	std::size_t offset = 0u;
	ASSERT_TRUE(layout.append<std::byte>(page_bytes_ + 1u, offset, TEST_ALIGNMENT));
	auto result = layout.allocate(node_);
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	auto region = std::move(result).value();
	EXPECT_TRUE(test::has_hugepage_advice(region.data(), region.size(), false));
}

/** @brief Simultaneous true and false requests retain their own advice flags and mapping ownership. */
TEST_F(NumaMemoryTest, concurrent_preferences_are_isolated)
{
	constexpr std::size_t THREAD_COUNT = 4u;
	std::array<numa_memory_region, THREAD_COUNT> regions;
	std::array<std::thread, THREAD_COUNT> threads;
	std::barrier start(static_cast<std::ptrdiff_t>(THREAD_COUNT));
	std::size_t launched = 0u;
	try {
		for (; launched < THREAD_COUNT; ++launched) {
			const auto index = launched;
			threads[index] = std::thread([&, index] {
				start.arrive_and_wait();
				auto result = numa_memory_region::allocate(
					{page_bytes_ + index + 1u, TEST_ALIGNMENT, node_, index % 2u != 0u});
				if (result.is_ok()) {
					regions[index] = std::move(result).value();
				}
			});
		}
	} catch (...) {
		for (std::size_t index = launched; index < THREAD_COUNT; ++index) {
			start.arrive_and_drop();
		}
		for (std::size_t index = 0u; index < launched; ++index) {
			threads[index].join();
		}
		throw;
	}
	for (auto &thread : threads) {
		thread.join();
	}
	for (std::size_t index = 0u; index < THREAD_COUNT; ++index) {
		SCOPED_TRACE(index);
		ASSERT_TRUE(regions[index]) << "concurrent mapping construction failed";
		const auto &region = regions[index];
		EXPECT_EQ(region.size(), page_bytes_ + index + 1u);
		EXPECT_TRUE(test::has_hugepage_advice(region.data(), region.size(), index % 2u != 0u));
		EXPECT_TRUE(
			test::resident_on_node({static_cast<const std::byte *>(region.data()), region.size()}, node_));
		for (std::size_t earlier = 0u; earlier < index; ++earlier) {
			EXPECT_TRUE(numa_layout::disjoint(
				{static_cast<const std::byte *>(region.data()), region.size()},
				{static_cast<const std::byte *>(regions[earlier].data()), regions[earlier].size()}));
		}
	}
}

/** @brief Move construction and replacement preserve one live owner and retire the replaced mapping. */
TEST_F(NumaMemoryTest, moves_preserve_advice_and_retire_exact_ownership)
{
	static_assert(!std::is_copy_constructible_v<numa_memory_region>);
	static_assert(std::is_nothrow_move_constructible_v<numa_memory_region>);
	static_assert(std::is_nothrow_move_assignable_v<numa_memory_region>);
	auto first_or = numa_memory_region::allocate({page_bytes_ + 1u, TEST_ALIGNMENT, node_, true});
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	auto first = std::move(first_or).value();
	const auto address = reinterpret_cast<std::uintptr_t>(first.data());
	auto moved = std::move(first);
	EXPECT_FALSE(first);
	EXPECT_EQ(first.data(), nullptr);
	EXPECT_EQ(first.size(), 0u);
	EXPECT_FALSE(first.host_numa_node().has_value());
	auto second_or = numa_memory_region::allocate({page_bytes_, TEST_ALIGNMENT, node_});
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto second = std::move(second_or).value();
	const auto replaced_address = reinterpret_cast<std::uintptr_t>(second.data());
	second = std::move(moved);
	EXPECT_TRUE(page_is_unmapped(replaced_address, page_bytes_));
	EXPECT_FALSE(moved);
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(second.data()), address);
	EXPECT_TRUE(test::has_hugepage_advice(second.data(), second.size(), true));
	second = {};
	EXPECT_TRUE(page_is_unmapped(address, page_bytes_));
}

/** @brief A refused performance hint preserves initialized, writable, exactly placed memory and complete reclamation. */
TEST_F(NumaMemoryTest, advice_refusal_preserves_required_properties)
{
	const native_operation_refusal operation{"advice", SYS_madvise, 2u, MADV_HUGEPAGE, status_code::OK};
	for (const int error : {EINVAL, ENOMEM, EAGAIN, EINTR, EPERM, ENOSYS, EIO}) {
		SCOPED_TRACE(error);
		EXPECT_EXIT(
			{
				check_refusal(node_, page_bytes_, operation, error);
				std::_Exit(EXIT_SUCCESS);
			},
			::testing::ExitedWithCode(EXIT_SUCCESS), "");
	}
}

/** @brief Mandatory mapping, binding and resident proofs still reject and reclaim their unpublished allocations. */
TEST_F(NumaMemoryTest, required_native_refusals_preserve_retained_prefix)
{
	const std::array operations{
		native_operation_refusal{"mapping", SYS_mmap, 1u, static_cast<uint32_t>(4u * page_bytes_),
					 status_code::RESOURCE_EXHAUSTED},
		native_operation_refusal{"binding", SYS_mbind, 5u, 0u, status_code::FAILED_PRECONDITION},
		native_operation_refusal{"residency", SYS_mbind, 5u, MPOL_MF_STRICT, status_code::FAILED_PRECONDITION},
	};
	for (const auto &operation : operations) {
		SCOPED_TRACE(operation.name);
		EXPECT_EXIT(
			{
				check_refusal(node_, page_bytes_, operation, EIO);
				std::_Exit(EXIT_SUCCESS);
			},
			::testing::ExitedWithCode(EXIT_SUCCESS), "");
	}
}

/** @brief Process-local THP prohibition changes no required allocation property and never changes host policy. */
TEST_F(NumaMemoryTest, process_thp_prohibition_preserves_allocation)
{
	EXPECT_EXIT(
		{
			check_process_prohibition(node_, page_bytes_);
			std::_Exit(EXIT_SUCCESS);
		},
		::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

}  // namespace
}  // namespace kinetum::dp
