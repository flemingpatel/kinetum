// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_numa_lifecycle_memory_provider.cpp
 * @brief Exact ownership proofs for the production lifecycle NUMA allocator.
 * @author Fleming Patel
 *
 * The tests exercise the allocator directly rather than inferring behavior
 * through a module generation. They pin compiled-budget validation, exact byte
 * and derived-slot bounds, mapping-failure rollback, unlocked NUMA work under
 * concurrent callers, and fail-stop release/lifetime contracts.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <thread>
#include <utility>
#include <vector>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/lifecycle/numa_lifecycle_memory_provider.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::dp::lifecycle
{
namespace
{

using kinetum::common::status_code;

/** Cache-line alignment required by fixture allocations. */
constexpr std::size_t TEST_ALIGNMENT = 64u;
/** Maximum simultaneously tracked context, telemetry, and epoch-arena blocks per context. */
constexpr std::size_t LIVE_BLOCKS_PER_CONTEXT = LIFECYCLE_MAX_LONG_LIVED_ALLOCATIONS +
						LIFECYCLE_MAX_INTERNAL_TELEMETRY_ALLOCATIONS +
						common::EXACT_EPOCH_SLOT_COUNT;

/** @brief Release one successful test allocation even when a later assertion returns. */
class lifecycle_block_owner final {
    public:
	/**
	 * @brief Adopt the exact block returned by a successful allocation.
	 * @param provider Allocator that outlives this guard.
	 * @param block Exact live allocation transferred to this guard.
	 */
	lifecycle_block_owner(lifecycle_memory_provider &provider, lifecycle_memory_block block) noexcept
		: provider_(&provider)
		, block_(block)
	{
	}

	lifecycle_block_owner(const lifecycle_block_owner &) = delete;
	lifecycle_block_owner &operator=(const lifecycle_block_owner &) = delete;
	lifecycle_block_owner &operator=(lifecycle_block_owner &&) = delete;

	/**
	 * @brief Transfer release responsibility and leave the source empty.
	 * @param other Source allocation guard whose provider borrow and block ownership are transferred.
	 */
	lifecycle_block_owner(lifecycle_block_owner &&other) noexcept
		: provider_(std::exchange(other.provider_, nullptr))
		, block_(other.block_)
	{
	}

	/** @brief Return the unchanged block to its exact allocator once. */
	~lifecycle_block_owner()
	{
		if (provider_ != nullptr) {
			provider_->release(block_);
		}
	}

    private:
	lifecycle_memory_provider *provider_;  ///< Non-null only while this guard owns the block.
	lifecycle_memory_block block_;	       ///< Exact provider token and geometry returned by allocate().
};

/**
 * @brief Check an allocation refusal without leaking an unexpected successful block.
 * @param provider Exact allocator under test.
 * @param numa_node Requested NUMA identity.
 * @param size Requested byte count.
 * @param alignment Requested alignment.
 * @param expected Expected refusal category.
 */
void expect_allocation_failure(lifecycle_memory_provider &provider, int32_t numa_node, std::size_t size,
			       std::size_t alignment, status_code expected)
{
	auto result = provider.allocate(numa_node, size, alignment, true);
	if (result.is_ok()) {
		const lifecycle_block_owner unexpected(provider, result.value());
		ADD_FAILURE() << "allocation unexpectedly succeeded";
		return;
	}
	EXPECT_EQ(result.error().code(), expected);
}

/**
 * @brief Select one process-allowed memory NUMA node.
 *
 * @return Lowest exact allocatable node, or null when the host cannot prove one.
 */
[[nodiscard]] std::optional<int32_t> live_numa_node()
{
	const auto host = quark::probe_host();
	if (!host.valid || host.memory_numa_nodes.empty()) {
		return std::nullopt;
	}
	return host.memory_numa_nodes.front();
}

/**
 * @brief Build one exact single-node provider or abort inside a death child.
 *
 * @param numa_node Exact host NUMA node.
 * @param capacity Exact byte budget for the node.
 * @return One empty provider owning the derived fixed slot population.
 */
[[nodiscard]] std::unique_ptr<numa_lifecycle_memory_provider> make_death_test_provider(int32_t numa_node,
										       std::size_t capacity)
{
	const std::array budgets{numa_lifecycle_memory_budget{
		.numa_node = numa_node,
		.context_count = 1,
		.complete_memory_capacity_bytes = capacity,
	}};
	auto provider_or = numa_lifecycle_memory_provider::create(budgets);
	if (!provider_or.is_ok()) {
		std::abort();
	}
	return std::move(provider_or).value();
}

/**
 * @brief Trigger fail-stop by releasing an empty block.
 *
 * @param numa_node Exact host NUMA node.
 */
void release_empty_block(int32_t numa_node)
{
	auto provider = make_death_test_provider(numa_node, 1u);
	provider->release({});
}

/**
 * @brief Trigger fail-stop by releasing one exact block twice.
 *
 * @param numa_node Exact host NUMA node.
 */
void release_block_twice(int32_t numa_node)
{
	auto provider = make_death_test_provider(numa_node, 1u);
	auto block_or = provider->allocate(numa_node, 1u, TEST_ALIGNMENT, true);
	if (!block_or.is_ok()) {
		std::abort();
	}
	const auto block = block_or.value();
	provider->release(block);
	provider->release(block);
}

/**
 * @brief Trigger fail-stop by changing one released block's exact extent.
 *
 * @param numa_node Exact host NUMA node.
 */
void release_mismatched_block(int32_t numa_node)
{
	auto provider = make_death_test_provider(numa_node, 2u);
	auto block_or = provider->allocate(numa_node, 1u, TEST_ALIGNMENT, true);
	if (!block_or.is_ok()) {
		std::abort();
	}
	auto block = block_or.value();
	block.size = 2u;
	provider->release(block);
}

/**
 * @brief Trigger fail-stop with a token retained across exact slot reuse.
 *
 * @param numa_node Exact host NUMA node.
 */
void release_stale_block_after_slot_reuse(int32_t numa_node)
{
	auto provider = make_death_test_provider(numa_node, 2u);
	auto first_or = provider->allocate(numa_node, 1u, TEST_ALIGNMENT, true);
	if (!first_or.is_ok()) {
		std::abort();
	}
	const auto stale = first_or.value();
	provider->release(stale);
	auto replacement_or = provider->allocate(numa_node, 1u, TEST_ALIGNMENT, true);
	if (!replacement_or.is_ok()) {
		std::abort();
	}
	const auto replacement = replacement_or.value();
	if (replacement.provider_token.opaque_identity != stale.provider_token.opaque_identity ||
	    replacement.provider_token.reuse_nonce == stale.provider_token.reuse_nonce) {
		std::abort();
	}
	provider->release(stale);
}

/**
 * @brief Trigger fail-stop by destroying an owner with one live mapping.
 *
 * @param numa_node Exact host NUMA node.
 */
void destroy_provider_with_live_block(int32_t numa_node)
{
	auto provider = make_death_test_provider(numa_node, 1u);
	auto block_or = provider->allocate(numa_node, 1u, TEST_ALIGNMENT, true);
	if (!block_or.is_ok()) {
		std::abort();
	}
	provider.reset();
}

/** @brief Reject malformed, duplicate, and unordered compiled budgets. */
TEST(numa_lifecycle_memory_provider, compiled_budget_validation_is_exact)
{
	EXPECT_EQ(
		numa_lifecycle_memory_provider::create(std::span<const numa_lifecycle_memory_budget>{}).error().code(),
		status_code::INVALID_ARGUMENT);

	const std::array negative_node{numa_lifecycle_memory_budget{-1, 1, 1}};
	EXPECT_EQ(numa_lifecycle_memory_provider::create(negative_node).error().code(), status_code::INVALID_ARGUMENT);
	const std::array zero_context{numa_lifecycle_memory_budget{0, 0, 1}};
	EXPECT_EQ(numa_lifecycle_memory_provider::create(zero_context).error().code(), status_code::INVALID_ARGUMENT);
	const std::array zero_capacity{numa_lifecycle_memory_budget{0, 1, 0}};
	EXPECT_EQ(numa_lifecycle_memory_provider::create(zero_capacity).error().code(), status_code::INVALID_ARGUMENT);
	const std::array duplicate{
		numa_lifecycle_memory_budget{0, 1, 1},
		numa_lifecycle_memory_budget{0, 1, 1},
	};
	EXPECT_EQ(numa_lifecycle_memory_provider::create(duplicate).error().code(), status_code::INVALID_ARGUMENT);
	const std::array unordered{
		numa_lifecycle_memory_budget{1, 1, 1},
		numa_lifecycle_memory_budget{0, 1, 1},
	};
	EXPECT_EQ(numa_lifecycle_memory_provider::create(unordered).error().code(), status_code::INVALID_ARGUMENT);
}

/** @brief Reject malformed allocation requests before any NUMA mapping. */
TEST(numa_lifecycle_memory_provider, allocation_requires_exact_compiled_node_size_and_alignment)
{
	const auto numa_node = live_numa_node();
	ASSERT_TRUE(numa_node.has_value()) << "host must expose a process-allocatable NUMA node";
	const std::array budgets{numa_lifecycle_memory_budget{numa_node.value(), 1, 64}};
	auto provider_or = numa_lifecycle_memory_provider::create(budgets);
	ASSERT_TRUE(provider_or.is_ok()) << provider_or.error().message();
	auto provider = std::move(provider_or).value();
	expect_allocation_failure(*provider, -1, 1, TEST_ALIGNMENT, status_code::INVALID_ARGUMENT);
	expect_allocation_failure(*provider, numa_node.value(), 0, TEST_ALIGNMENT, status_code::INVALID_ARGUMENT);
	expect_allocation_failure(*provider, numa_node.value(), 1, 3, status_code::INVALID_ARGUMENT);
	const int32_t unknown_node = numa_node.value() == std::numeric_limits<int32_t>::max() ? numa_node.value() - 1 :
												numa_node.value() + 1;
	expect_allocation_failure(*provider, unknown_node, 1, TEST_ALIGNMENT, status_code::FAILED_PRECONDITION);
}

/** @brief Derive one exact ownership slot for every context and epoch arena. */
TEST(numa_lifecycle_memory_provider, ownership_slots_derive_from_context_and_exact_epoch_counts)
{
	const auto numa_node = live_numa_node();
	ASSERT_TRUE(numa_node.has_value()) << "host must expose a process-allocatable NUMA node";
	const std::array budgets{numa_lifecycle_memory_budget{numa_node.value(), 1, LIVE_BLOCKS_PER_CONTEXT + 1u}};
	auto provider_or = numa_lifecycle_memory_provider::create(budgets);
	ASSERT_TRUE(provider_or.is_ok()) << provider_or.error().message();
	auto provider = std::move(provider_or).value();
	std::vector<lifecycle_block_owner> blocks;
	blocks.reserve(LIVE_BLOCKS_PER_CONTEXT);
	for (std::size_t index = 0; index < LIVE_BLOCKS_PER_CONTEXT; ++index) {
		auto block_or = provider->allocate(numa_node.value(), 1u, TEST_ALIGNMENT, true);
		ASSERT_TRUE(block_or.is_ok()) << block_or.error().message();
		blocks.emplace_back(*provider, block_or.value());
	}
	expect_allocation_failure(*provider, numa_node.value(), 1u, TEST_ALIGNMENT, status_code::RESOURCE_EXHAUSTED);
}

/** @brief Enforce exact compiled byte capacity independently of free slots. */
TEST(numa_lifecycle_memory_provider, byte_capacity_is_reserved_and_released_exactly)
{
	const auto numa_node = live_numa_node();
	ASSERT_TRUE(numa_node.has_value()) << "host must expose a process-allocatable NUMA node";
	const std::array budgets{numa_lifecycle_memory_budget{numa_node.value(), 1, 16}};
	auto provider_or = numa_lifecycle_memory_provider::create(budgets);
	ASSERT_TRUE(provider_or.is_ok()) << provider_or.error().message();
	auto provider = std::move(provider_or).value();
	auto first_or = provider->allocate(numa_node.value(), 9u, TEST_ALIGNMENT, true);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	const lifecycle_block_owner first(*provider, first_or.value());
	expect_allocation_failure(*provider, numa_node.value(), 8u, TEST_ALIGNMENT, status_code::RESOURCE_EXHAUSTED);
	auto second_or = provider->allocate(numa_node.value(), 7u, TEST_ALIGNMENT, false);
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	const lifecycle_block_owner second(*provider, second_or.value());
	const auto *bytes = static_cast<const uint8_t *>(second_or->data);
	EXPECT_TRUE(std::all_of(bytes, bytes + second_or->size, [](uint8_t value) { return value == 0; }));
}

/** @brief A post-reservation mapping failure restores both slot and byte claims. */
TEST(numa_lifecycle_memory_provider, failed_numa_mapping_rolls_back_reservation_for_retry)
{
	constexpr int32_t UNREPRESENTABLE_NODE = std::numeric_limits<int32_t>::max();
	const std::array budgets{numa_lifecycle_memory_budget{UNREPRESENTABLE_NODE, 1, 1}};
	auto provider_or = numa_lifecycle_memory_provider::create(budgets);
	ASSERT_TRUE(provider_or.is_ok()) << provider_or.error().message();
	auto provider = std::move(provider_or).value();
	for (int attempt = 0; attempt < 2; ++attempt) {
		auto block_or = provider->allocate(UNREPRESENTABLE_NODE, 1u, TEST_ALIGNMENT, true);
		ASSERT_FALSE(block_or.is_ok());
		EXPECT_EQ(block_or.error().code(), status_code::OUT_OF_RANGE);
	}
}

/** @brief Concurrent callers retain exact independent mapping ownership. */
TEST(numa_lifecycle_memory_provider, concurrent_allocate_and_release_conserve_every_claim)
{
	const auto numa_node = live_numa_node();
	ASSERT_TRUE(numa_node.has_value()) << "host must expose a process-allocatable NUMA node";
	constexpr std::size_t THREAD_COUNT = 4u;
	constexpr std::size_t BLOCK_BYTES = 32u;
	const std::array budgets{numa_lifecycle_memory_budget{numa_node.value(), 1, THREAD_COUNT * BLOCK_BYTES}};
	auto provider_or = numa_lifecycle_memory_provider::create(budgets);
	ASSERT_TRUE(provider_or.is_ok()) << provider_or.error().message();
	auto provider = std::move(provider_or).value();
	std::barrier allocation_start(static_cast<std::ptrdiff_t>(THREAD_COUNT));
	std::barrier release_start(static_cast<std::ptrdiff_t>(THREAD_COUNT));
	std::atomic<bool> succeeded{true};
	std::array<std::thread, THREAD_COUNT> threads;
	std::size_t launched = 0;
	try {
		for (; launched < threads.size(); ++launched) {
			const std::size_t index = launched;
			threads[index] = std::thread([&, index] {
				allocation_start.arrive_and_wait();
				auto block_or =
					provider->allocate(numa_node.value(), BLOCK_BYTES, TEST_ALIGNMENT, true);
				if (!block_or.is_ok()) {
					succeeded.store(false, std::memory_order_relaxed);
				}
				release_start.arrive_and_wait();
				if (block_or.is_ok()) {
					std::memset(block_or->data, static_cast<int>(index + 1u), block_or->size);
					provider->release(block_or.value());
				}
			});
		}
	} catch (...) {
		// Started threads must cross both barriers and release their blocks
		// before the original launch failure leaves the fixture.
		for (std::size_t index = launched; index < threads.size(); ++index) {
			allocation_start.arrive_and_drop();
			release_start.arrive_and_drop();
		}
		for (std::size_t index = 0; index < launched; ++index) {
			threads[index].join();
		}
		throw;
	}
	for (auto &thread : threads) {
		thread.join();
	}
	EXPECT_TRUE(succeeded.load(std::memory_order_relaxed));
	auto final_or = provider->allocate(numa_node.value(), THREAD_COUNT * BLOCK_BYTES, TEST_ALIGNMENT, true);
	ASSERT_TRUE(final_or.is_ok()) << final_or.error().message();
	provider->release(final_or.value());
}

/** @brief Malformed, mismatched, and duplicate release attempts fail stop. */
TEST(numa_lifecycle_memory_provider, release_requires_one_exact_live_block)
{
	const auto numa_node = live_numa_node();
	ASSERT_TRUE(numa_node.has_value()) << "host must expose a process-allocatable NUMA node";
	auto canary = make_death_test_provider(numa_node.value(), 1u);
	auto block_or = canary->allocate(numa_node.value(), 1u, TEST_ALIGNMENT, true);
	ASSERT_TRUE(block_or.is_ok()) << block_or.error().message();
	canary->release(block_or.value());
	EXPECT_DEATH(release_empty_block(numa_node.value()), "");
	EXPECT_DEATH(release_block_twice(numa_node.value()), "");
	EXPECT_DEATH(release_mismatched_block(numa_node.value()), "");
	EXPECT_DEATH(release_stale_block_after_slot_reuse(numa_node.value()), "");
}

/** @brief Provider destruction refuses to hide one leaked lifecycle mapping. */
TEST(numa_lifecycle_memory_provider, destruction_with_live_ownership_fails_stop)
{
	const auto numa_node = live_numa_node();
	ASSERT_TRUE(numa_node.has_value()) << "host must expose a process-allocatable NUMA node";
	auto canary = make_death_test_provider(numa_node.value(), 1u);
	auto block_or = canary->allocate(numa_node.value(), 1u, TEST_ALIGNMENT, true);
	ASSERT_TRUE(block_or.is_ok()) << block_or.error().message();
	canary->release(block_or.value());
	EXPECT_DEATH(destroy_provider_with_live_block(numa_node.value()), "");
}

}  // namespace
}  // namespace kinetum::dp::lifecycle
