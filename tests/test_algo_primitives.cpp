// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_algo_primitives.cpp
 * @brief Unit tests for shared algorithm primitives used across the platform.
 * @author Fleming Patel
 *
 * Covers parser edge cases, cache and queue contracts, cuckoo-map failure
 * atomicity, and fail-closed rate-limit behavior. These tests are intentionally
 * small because each primitive has component-level coverage in its primary
 * caller as well.
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory_resource>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <kinetum/algo/aligned_atomic.hpp>
#include <kinetum/algo/atomic_index_pool.hpp>
#include <kinetum/algo/bits.hpp>
#include <kinetum/algo/bounded_index_pool.hpp>
#include <kinetum/algo/cache.hpp>
#include <kinetum/algo/cidr.hpp>
#include <kinetum/algo/compact_index_set.hpp>
#include <kinetum/algo/condition_parse.hpp>
#include <kinetum/algo/cuckoo.hpp>
#include <kinetum/algo/graph.hpp>
#include <kinetum/algo/hash.hpp>
#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/queue.hpp>
#include <kinetum/algo/ratelimit.hpp>
#include <kinetum/kinetum_sdk.hpp>

namespace kinetum::algo
{

namespace
{

/** @brief Count live fixture objects while queue ownership moves them. */
struct counted_object {
	static inline int live_count = 0;  ///< Number of explicitly constructed fixture objects still alive.

	/** @param v Observable value carried by the new object. */
	explicit counted_object(int v)
		: value(v)
	{
		++live_count;
	}

	/** @brief Retire this object's contribution to the live-object count. */
	~counted_object()
	{
		--live_count;
	}

	int value;  ///< Observable payload used to prove queue ownership transfer.
};

/** @brief Exercise queue storage with a move-only non-default value. */
struct move_only_no_default {
	/** @param v Initial observable fixture value. */
	explicit move_only_no_default(int v)
		: value(v)
	{
	}

	move_only_no_default(const move_only_no_default &) = delete;
	move_only_no_default &operator=(const move_only_no_default &) = delete;
	/** @param other Source whose observable value is transferred and replaced by the moved-from sentinel. */
	move_only_no_default(move_only_no_default &&other) noexcept
		: value(other.value)
	{
		other.value = -1;
	}
	/**
	 * @param other Source whose value is copied before it receives the moved-from sentinel.
	 * @return This destination after assignment.
	 */
	move_only_no_default &operator=(move_only_no_default &&other) noexcept
	{
		value = other.value;
		other.value = -1;
		return *this;
	}

	int value;  ///< Observable queue payload; -1 marks a moved-from object.
};

/** @brief Type whose batch copy and move-assignment operations may throw. */
struct throwing_batch_value {
	/** @brief Construct one zero value. */
	throwing_batch_value() = default;
	/** @brief Copy through a deliberately potentially-throwing operation. */
	throwing_batch_value(const throwing_batch_value &) noexcept(false)
	{
	}
	/** @brief Move-construct without failure so the ring itself remains admissible. */
	throwing_batch_value(throwing_batch_value &&) noexcept = default;
	/**
	 * @brief Copy-assign one test value.
	 * @return This destination after the defaulted assignment.
	 */
	throwing_batch_value &operator=(const throwing_batch_value &) = default;
	/**
	 * @brief Move-assign through a deliberately potentially-throwing operation.
	 * @return This unchanged destination; the signature deliberately lacks a no-throw guarantee.
	 */
	throwing_batch_value &operator=(throwing_batch_value &&) noexcept(false)
	{
		return *this;
	}
};

/** @brief Nothrow value with an exact live-object counter for batch proofs. */
struct tracked_batch_value {
	static inline std::size_t live_count = 0;  ///< Number of currently live objects.
	static inline const tracked_batch_value *last_move_destination =
		nullptr;  ///< Observed placement of the last move construction.

	/** @brief Construct one tracked zero-valued output destination. */
	tracked_batch_value() noexcept
		: tracked_batch_value(0)
	{
	}

	/**
	 * @brief Construct one tracked value.
	 *
	 * @param initial_value Exact test payload.
	 */
	explicit tracked_batch_value(int initial_value) noexcept
		: value(initial_value)
	{
		++live_count;
	}

	/**
	 * @brief Copy one tracked value and claim one new lifetime.
	 *
	 * @param other Existing tracked value to copy.
	 */
	tracked_batch_value(const tracked_batch_value &other) noexcept
		: value(other.value)
	{
		++live_count;
	}

	/**
	 * @brief Move one tracked value and claim one new lifetime.
	 *
	 * @param other Existing tracked value whose payload is copied for the test.
	 */
	tracked_batch_value(tracked_batch_value &&other) noexcept
		: value(other.value)
	{
		++live_count;
		last_move_destination = this;
	}

	/**
	 * @brief Replace this value from one moved source without changing lifetimes.
	 *
	 * @param other Existing tracked value whose payload replaces this payload.
	 * @return This tracked value.
	 */
	tracked_batch_value &operator=(tracked_batch_value &&other) noexcept
	{
		value = other.value;
		return *this;
	}

	/** @brief Retire exactly one tracked lifetime. */
	~tracked_batch_value()
	{
		--live_count;
	}

	int value{0};  ///< Exact test payload.
};

/** @brief Detect the public nothrow batch-push surface of one SPSC ring. */
template <typename ring_type>
concept supports_batch_push = requires(ring_type &ring, const typename ring_type::value_type *items) {
	{ ring.push_batch(items, std::size_t{1}) } -> std::same_as<std::size_t>;
};

/** @brief Detect the public nothrow batch-pop surface of one SPSC ring. */
template <typename ring_type>
concept supports_batch_pop = requires(ring_type &ring, typename ring_type::value_type *items) {
	{ ring.pop_batch(items, std::size_t{1}) } -> std::same_as<std::size_t>;
};

/** @brief Detect one initialized-destination pop operation. */
template <typename ring_type>
concept supports_output_pop = requires(ring_type &ring, typename ring_type::value_type &item) {
	{ ring.try_pop(item) } -> std::same_as<bool>;
};

/** @brief Detect whether one value type can instantiate the MPMC reservation contract. */
template <typename value_type>
concept supports_mpmc_queue_value = requires { typename mpmc_queue_view<value_type>; };

static_assert(supports_batch_push<spsc_ring_static<int, 2>>);
static_assert(supports_batch_pop<spsc_ring_static<int, 2>>);
static_assert(supports_batch_push<spsc_ring<int>>);
static_assert(supports_batch_pop<spsc_ring<int>>);
static_assert(supports_batch_push<spsc_ring_view<int>>);
static_assert(supports_batch_pop<spsc_ring_view<int>>);
static_assert(!supports_batch_push<spsc_ring_static<throwing_batch_value, 2>>);
static_assert(!supports_batch_pop<spsc_ring_static<throwing_batch_value, 2>>);
static_assert(!supports_batch_push<spsc_ring<throwing_batch_value>>);
static_assert(!supports_batch_pop<spsc_ring<throwing_batch_value>>);
static_assert(!supports_batch_push<spsc_ring_view<throwing_batch_value>>);
static_assert(!supports_batch_pop<spsc_ring_view<throwing_batch_value>>);
static_assert(!supports_output_pop<spsc_ring_static<throwing_batch_value, 2>>);
static_assert(!supports_output_pop<spsc_ring_view<throwing_batch_value>>);
static_assert(!supports_mpmc_queue_value<throwing_batch_value>);

/** @brief Force every cuckoo key into one bucket pair for displacement tests. */
struct constant_hash {
	/** @return Zero for every key, forcing all fixture keys into one bucket pair. */
	std::size_t operator()(uint32_t) const noexcept
	{
		return 0;
	}
};

/** Collision-forced cuckoo-map type used by constructor and rollback tests. */
using test_cuckoo_map = cuckoo_map<uint32_t, uint32_t, constant_hash>;
static_assert(!std::is_default_constructible_v<test_cuckoo_map>);
static_assert(!std::is_constructible_v<test_cuckoo_map, std::size_t>);
static_assert(!std::is_copy_constructible_v<test_cuckoo_map>);
static_assert(!std::is_copy_assignable_v<test_cuckoo_map>);
static_assert(!std::is_move_constructible_v<test_cuckoo_map>);
static_assert(!std::is_move_assignable_v<test_cuckoo_map>);

/** @brief Count cold defaults and forbid moves while retaining the map's existing key requirements. */
struct copy_only_key {
	static inline uint32_t defaults = 0;  ///< Default constructions, which query preparation must not perform.
	uint32_t value{0};		      ///< Semantic identity.
	/** @brief Record a permitted cold default construction. */
	copy_only_key() noexcept(false)
	{
		++defaults;
	}
	/** @brief Copy the semantic key without throwing. */
	copy_only_key(const copy_only_key &) noexcept = default;
	/** @brief Replace the semantic key without throwing. @return This destination. */
	copy_only_key &operator=(const copy_only_key &) noexcept = default;
	copy_only_key(copy_only_key &&) = delete;
	copy_only_key &operator=(copy_only_key &&) = delete;
	/** @return Equality of the semantic value. */
	bool operator==(const copy_only_key &) const noexcept = default;
};

/** @brief Hash only the copied semantic value. */
struct copy_only_key_hash {
	/** @param key Borrowed semantic key. @return Semantic hash with no key construction. */
	std::size_t operator()(const copy_only_key &key) const noexcept
	{
		return key.value;
	}
};

/** @brief Deterministic semantic hash for the independent mutation oracle. */
struct integer_key_hash {
	/** @param key Semantic integer identity. @return Its mixed value. */
	std::size_t operator()(uint32_t key) const noexcept
	{
		return splitmix64(key);
	}
};

/** @brief Caller-owned node used to prove exact intrusive-list membership. */
struct test_lru_node final : lru_node {
	/**
	 * @brief Construct one detached node with an observable identity.
	 * @param initial_value Value retained through list operations.
	 */
	explicit test_lru_node(int initial_value) noexcept
		: value(initial_value)
	{
	}

	int value{0};  ///< Exact test identity.
};

static_assert(!std::is_copy_constructible_v<lru_node>);
static_assert(!std::is_move_constructible_v<lru_node>);
static_assert(!std::is_copy_constructible_v<lru_list>);
static_assert(!std::is_move_constructible_v<lru_list>);
static_assert(!std::is_copy_constructible_v<bounded_index_pool>);
static_assert(!std::is_move_constructible_v<bounded_index_pool>);

}  // namespace

/** @brief Prove each 64-bit atomic begins on its own cache line. */
TEST(aligned_atomic, has_64_byte_alignment)
{
	EXPECT_EQ(alignof(aligned_atomic<uint64_t>), CACHE_LINE_SIZE);
	aligned_atomic<uint64_t> value;
	EXPECT_EQ(reinterpret_cast<uintptr_t>(&value) % CACHE_LINE_SIZE, 0u);
}

/** @brief Prove default construction publishes exact zero. */
TEST(aligned_atomic, default_constructs_to_zero)
{
	aligned_atomic<uint64_t> value;
	EXPECT_EQ(value.load(), 0u);
}

/** @brief Prove value construction preserves the authored initial value. */
TEST(aligned_atomic, value_constructor)
{
	aligned_atomic<uint64_t> value(42u);
	EXPECT_EQ(value.load(), 42u);
}

/** @brief Prove ordered and relaxed load/store operations. */
TEST(aligned_atomic, load_store)
{
	aligned_atomic<uint64_t> value;
	value.store(100u);
	EXPECT_EQ(value.load(), 100u);
	value.store(200u, std::memory_order_relaxed);
	EXPECT_EQ(value.load(std::memory_order_relaxed), 200u);
}

/** @brief Prove atomic addition returns the exact preceding value. */
TEST(aligned_atomic, fetch_add)
{
	aligned_atomic<uint64_t> value(100u);
	EXPECT_EQ(value.fetch_add(50u), 100u);
	EXPECT_EQ(value.load(), 150u);
	EXPECT_EQ(value.fetch_add(50u, std::memory_order_relaxed), 150u);
	EXPECT_EQ(value.load(), 200u);
}

/** @brief Prove the explicit owner-counter convenience operations. */
TEST(aligned_atomic, relaxed_methods)
{
	aligned_atomic<uint64_t> value;
	value.store_relaxed(100u);
	EXPECT_EQ(value.load_relaxed(), 100u);
	EXPECT_EQ(value.fetch_add_relaxed(50u), 100u);
	value.inc_relaxed();
	value.inc_relaxed();
	EXPECT_EQ(value.load_relaxed(), 152u);
}

/** @brief Prove cold relocation preserves the observed value. */
TEST(aligned_atomic, move_constructor)
{
	aligned_atomic<uint64_t> source(42u);
	aligned_atomic<uint64_t> destination(std::move(source));
	EXPECT_EQ(destination.load(), 42u);
}

/** @brief Prove cold move assignment replaces the destination value. */
TEST(aligned_atomic, move_assignment)
{
	aligned_atomic<uint64_t> source(100u);
	aligned_atomic<uint64_t> destination;
	destination = std::move(source);
	EXPECT_EQ(destination.load(), 100u);
}

/** @brief Prove standard-container relocation retains per-element isolation. */
TEST(aligned_atomic, vector_alignment)
{
	std::vector<aligned_atomic<uint64_t>> values(8u);
	for (const auto &value : values) {
		EXPECT_EQ(reinterpret_cast<uintptr_t>(&value) % CACHE_LINE_SIZE, 0u);
	}
}

/** @brief Prove concurrent relaxed increments conserve every update. */
TEST(aligned_atomic, concurrent_increment)
{
	constexpr int THREAD_COUNT = 4;
	constexpr int INCREMENTS_PER_THREAD = 10000;
	aligned_atomic<uint64_t> value;
	std::vector<std::thread> threads;
	threads.reserve(THREAD_COUNT);
	for (int thread_index = 0; thread_index < THREAD_COUNT; ++thread_index) {
		threads.emplace_back([&value]() {
			for (int increment = 0; increment < INCREMENTS_PER_THREAD; ++increment) {
				value.inc_relaxed();
			}
		});
	}
	for (auto &thread : threads) {
		thread.join();
	}
	EXPECT_EQ(value.load(), static_cast<uint64_t>(THREAD_COUNT * INCREMENTS_PER_THREAD));
}

/**
 * @brief Verify trailing slash is invalid.
 */
TEST(algo_cidr, trailing_slash_is_invalid)
{
	EXPECT_FALSE(parse_cidr("10.0.0.1/").valid);
	EXPECT_TRUE(parse_cidr("10.0.0.1").valid);
}

/** @brief Verify the header-owned parser and formatter share one strict round-trip contract. */
TEST(algo_cidr, header_owned_parse_and_format_round_trip)
{
	constexpr std::string_view INPUT = "203.0.113.7/24";
	const cidr parsed = parse_cidr(INPUT);
	ASSERT_TRUE(parsed.valid);
	EXPECT_EQ(parsed.prefix_len, 24u);
	EXPECT_TRUE(match_cidr(0xcb0071feu, parsed));
	EXPECT_FALSE(match_cidr(0xcb0072feu, parsed));

	char cidr_text[19]{};
	EXPECT_EQ(format_cidr(parsed, cidr_text, sizeof(cidr_text)), INPUT.size());
	EXPECT_EQ(std::string_view(cidr_text), INPUT);

	char address_text[16]{};
	EXPECT_EQ(format_ipv4(parsed.network, address_text, sizeof(address_text)),
		  std::string_view("203.0.113.7").size());
	EXPECT_EQ(std::string_view(address_text), "203.0.113.7");

	uint32_t address = 0;
	EXPECT_FALSE(parse_ipv4("203.00.113.7", &address));
	EXPECT_FALSE(parse_cidr("203.0.113.7/024").valid);
	EXPECT_FALSE(parse_cidr("203.0.113.7/24/1").valid);

	// The SDK accepts an exact string_view rather than assuming a trailing NUL,
	// and it shares this primitive's canonical grammar in both directions.
	constexpr char NON_TERMINATED_ADDRESS[]{'2', '0', '3', '.', '0', '.', '1', '1', '3', '.', '7'};
	uint32_t sdk_address = 0;
	EXPECT_TRUE(::kinetum::sdk::string_to_ipv4(
		std::string_view(NON_TERMINATED_ADDRESS, sizeof(NON_TERMINATED_ADDRESS)), sdk_address));
	EXPECT_EQ(sdk_address, parsed.network);
	EXPECT_EQ(::kinetum::sdk::ipv4_to_string(sdk_address), "203.0.113.7");
	EXPECT_FALSE(::kinetum::sdk::string_to_ipv4("203.00.113.7", sdk_address));
	EXPECT_FALSE(::kinetum::sdk::string_to_ipv4("203.0.113.7junk", sdk_address));
}

/** @brief Bit extraction and power logarithms reject malformed domains without shifting. */
TEST(algo_bits, malformed_ranges_and_nonpowers_return_exact_sentinels)
{
	EXPECT_EQ(log2_of_power_of_2(0u), -1);
	EXPECT_EQ(log2_of_power_of_2(3u), -1);
	EXPECT_EQ(log2_of_power_of_2(1u), 0);
	EXPECT_EQ(log2_of_power_of_2(uint64_t{1} << 63u), 63);
	EXPECT_EQ(extract_bits(0xf0u, 4, 8), 0x0fu);
	EXPECT_EQ(extract_bits(0xf0u, -1, 8), 0u);
	EXPECT_EQ(extract_bits(0xf0u, 4, 65), 0u);
	EXPECT_EQ(extract_bits(0xf0u, 8, 4), 0u);
	EXPECT_EQ(extract_bits(0xf0u, 64, 64), 0u);
}

/** @brief The condition grammar is ASCII-defined and independent of process locale. */
TEST(algo_condition_parse, non_ascii_bytes_never_form_space_digit_or_identifier_tokens)
{
	condition_expression expression{};
	condition_parse_error error = condition_parse_error::NONE;
	EXPECT_TRUE(parse_condition_expression("  dst_port <= 65535\t", expression, &error));
	EXPECT_EQ(expression.field, "dst_port");
	EXPECT_EQ(expression.op, condition_op::LE);
	EXPECT_EQ(expression.value, 65535u);

	constexpr char NON_ASCII_PREFIX[]{static_cast<char>(0xa0), 'd', 's', 't', ' ', '=', '=', ' ', '1'};
	EXPECT_FALSE(parse_condition_expression(std::string_view(NON_ASCII_PREFIX, sizeof(NON_ASCII_PREFIX)),
						expression, &error));
	EXPECT_EQ(error, condition_parse_error::INVALID_FIELD);
}

/** @brief Kahn failure evidence names every blocked node without calling each one cyclic. */
TEST(algo_graph, failed_topology_reports_cycle_and_downstream_nodes_as_blocked)
{
	dag<int> graph;
	for (int node = 0; node < 4; ++node) {
		ASSERT_TRUE(graph.add_node(node));
	}
	ASSERT_TRUE(graph.add_edge(0, 1));
	ASSERT_TRUE(graph.add_edge(1, 0));
	ASSERT_TRUE(graph.add_edge(1, 2));
	ASSERT_TRUE(graph.add_edge(2, 3));

	const auto result = topological_sort(graph);
	EXPECT_FALSE(result.success);
	EXPECT_TRUE(result.order.empty());
	EXPECT_EQ(result.blocked_nodes, (std::vector<int>{0, 1, 2, 3}));
}

/** @brief Acquire every partial-word index once and recycle without affecting held leases. */
TEST(algo_atomic_index_pool, exact_population_and_independent_release)
{
	atomic_index_pool<65> pool;
	std::array<bool, 65> seen{};
	for (uint32_t count = 0; count < seen.size(); ++count) {
		uint32_t index = UINT32_MAX;
		ASSERT_TRUE(pool.try_acquire(index));
		ASSERT_LT(index, seen.size());
		EXPECT_FALSE(seen[index]);
		seen[index] = true;
	}
	uint32_t index = UINT32_MAX;
	EXPECT_FALSE(pool.try_acquire(index));
	EXPECT_EQ(index, UINT32_MAX);
	for (uint32_t turn = 0; turn < 1024; ++turn) {
		pool.release(64);
		ASSERT_TRUE(pool.try_acquire(index));
		EXPECT_EQ(index, 64u);
	}
	for (uint32_t returned = 0; returned < seen.size(); ++returned) {
		pool.release(returned);
	}
	EXPECT_DEATH(pool.release(64), "");
	EXPECT_DEATH(pool.release(65), "");
}

/** @brief Concurrent leases never alias and all published objects return to the complete pool. */
TEST(algo_atomic_index_pool, concurrent_exclusive_ownership_and_publication)
{
	atomic_index_pool<65> pool;
	std::array<std::atomic<bool>, 65> occupied{};
	std::array<uint64_t, 65> touches{};
	std::atomic<bool> collision{false};
	std::atomic<uint64_t> admissions{0};
	std::array<std::thread, 8> callers;
	for (auto &caller : callers) {
		caller = std::thread([&] {
			for (uint32_t turn = 0; turn < 4096; ++turn) {
				uint32_t index = 0;
				if (!pool.try_acquire(index)) {
					continue;
				}
				if (occupied[index].exchange(true, std::memory_order_relaxed)) {
					collision.store(true, std::memory_order_relaxed);
					return;
				}
				++touches[index];
				admissions.fetch_add(1, std::memory_order_relaxed);
				occupied[index].store(false, std::memory_order_relaxed);
				pool.release(index);
			}
		});
	}
	for (auto &caller : callers) {
		caller.join();
	}
	ASSERT_FALSE(collision.load(std::memory_order_relaxed));
	uint64_t total = 0;
	for (uint32_t count = 0; count < touches.size(); ++count) {
		uint32_t index = 0;
		ASSERT_TRUE(pool.try_acquire(index));
		total += touches[index];
	}
	EXPECT_GT(total, 0u);
	EXPECT_EQ(total, admissions.load(std::memory_order_relaxed));
	for (uint32_t index = 0; index < touches.size(); ++index) {
		pool.release(index);
	}
}

/** @brief Verify compact membership across word boundaries without growth or aliasing. */
TEST(algo_compact_index_set, fixed_universe_membership_is_exact)
{
	compact_index_set empty;
	EXPECT_EQ(empty.value_limit(), 0u);
	EXPECT_FALSE(empty.insert(0));
	EXPECT_FALSE(empty.contains(0));

	compact_index_set set(130);
	EXPECT_EQ(set.value_limit(), 130u);
	for (const std::size_t value : {0u, 63u, 64u, 129u}) {
		EXPECT_TRUE(set.insert(value));
		EXPECT_FALSE(set.insert(value));
		EXPECT_TRUE(set.contains(value));
	}
	EXPECT_FALSE(set.contains(1));
	EXPECT_FALSE(set.contains(62));
	EXPECT_FALSE(set.contains(65));
	EXPECT_FALSE(set.insert(130));
	EXPECT_FALSE(set.contains(130));
}

/** @brief Prove fixed index ownership, exhaustion, recycling, and invalid-release fail-stop. */
TEST(algo_bounded_index_pool, fixed_capacity_recycling_is_exact_and_nonthrowing)
{
	EXPECT_THROW((bounded_index_pool(1u, nullptr)), std::invalid_argument);

	bounded_index_pool empty(0u, std::pmr::new_delete_resource());
	uint32_t unchanged = 99u;
	EXPECT_FALSE(empty.try_acquire(unchanged));
	EXPECT_EQ(unchanged, 99u);
	EXPECT_EQ(empty.capacity(), 0u);
	EXPECT_EQ(empty.available(), 0u);
	EXPECT_EQ(empty.in_use(), 0u);
	EXPECT_DEATH(empty.release(0u), "bounded_index_pool invalid release");

	bounded_index_pool pool(3u, std::pmr::new_delete_resource());
	EXPECT_EQ(pool.capacity(), 3u);
	EXPECT_EQ(pool.available(), 3u);
	EXPECT_EQ(pool.in_use(), 0u);
	uint32_t first = UINT32_MAX;
	uint32_t second = UINT32_MAX;
	uint32_t third = UINT32_MAX;
	ASSERT_TRUE(pool.try_acquire(first));
	ASSERT_TRUE(pool.try_acquire(second));
	ASSERT_TRUE(pool.try_acquire(third));
	EXPECT_EQ(first, 0u);
	EXPECT_EQ(second, 1u);
	EXPECT_EQ(third, 2u);
	EXPECT_EQ(pool.available(), 0u);
	EXPECT_EQ(pool.in_use(), 3u);
	EXPECT_FALSE(pool.try_acquire(unchanged));
	EXPECT_EQ(unchanged, 99u);
	EXPECT_DEATH(pool.release(3u), "bounded_index_pool invalid release");

	pool.release(second);
	EXPECT_EQ(pool.available(), 1u);
	uint32_t recycled = UINT32_MAX;
	ASSERT_TRUE(pool.try_acquire(recycled));
	EXPECT_EQ(recycled, second);
	pool.release(first);
	pool.release(recycled);
	pool.release(third);
	EXPECT_EQ(pool.available(), pool.capacity());
	EXPECT_EQ(pool.in_use(), 0u);
	EXPECT_DEATH(pool.release(first), "bounded_index_pool invalid release");
}

/**
 * @brief Verify LRU cache rejects zero capacity.
 */
TEST(algo_cache, lru_cache_rejects_zero_capacity)
{
	EXPECT_THROW((lru_cache<int, int>(0)), std::invalid_argument);
}

/** @brief Intrusive nodes transfer only from detached to one exact list owner. */
TEST(algo_cache, intrusive_lru_membership_is_linear_and_clear_detaches)
{
	test_lru_node first(1);
	test_lru_node second(2);
	lru_list left;
	lru_list right;
	EXPECT_FALSE(left.push_front(nullptr));
	ASSERT_TRUE(left.push_front(&first));
	ASSERT_TRUE(left.push_front(&second));
	EXPECT_FALSE(left.push_front(&first));
	EXPECT_FALSE(right.touch(&first));
	EXPECT_FALSE(right.unlink(&first));
	ASSERT_TRUE(left.touch(&first));
	EXPECT_EQ(left.head(), &first);
	EXPECT_EQ(left.tail(), &second);
	left.clear();
	EXPECT_TRUE(left.empty());
	EXPECT_TRUE(right.push_front(&first));
	EXPECT_TRUE(right.push_front(&second));
	auto *evicted = static_cast<test_lru_node *>(right.pop_back());
	ASSERT_NE(evicted, nullptr);
	EXPECT_EQ(evicted->value, 1);
	EXPECT_TRUE(right.unlink(&second));
	EXPECT_TRUE(right.empty());
}

/** @brief A throwing eviction callback leaves cache membership structurally unchanged. */
TEST(algo_cache, eviction_callback_failure_precedes_membership_mutation)
{
	lru_cache<int, int> cache(1u, [](const int &, int &) { throw std::runtime_error("eviction failed"); });
	ASSERT_TRUE(cache.put(1, 11));
	EXPECT_THROW((void)cache.put(2, 22), std::runtime_error);
	EXPECT_EQ(cache.size(), 1u);
	EXPECT_TRUE(cache.contains(1));
	EXPECT_FALSE(cache.contains(2));
	ASSERT_NE(cache.peek(1), nullptr);
	EXPECT_EQ(*cache.peek(1), 11);
}

/**
 * @brief Verify make aligned runs destructor.
 */
TEST(algo_cache, make_aligned_runs_destructor)
{
	counted_object::live_count = 0;
	{
		auto ptr = make_aligned<counted_object>(42);
		ASSERT_NE(ptr, nullptr);
		EXPECT_EQ(ptr->value, 42);
		EXPECT_EQ(counted_object::live_count, 1);
	}
	EXPECT_EQ(counted_object::live_count, 0);
}

/** @brief Alignment helpers reject null, zero allocation, and rounded-size overflow. */
TEST(algo_cache, cacheline_alignment_is_total_at_size_boundaries)
{
	EXPECT_FALSE(is_cache_aligned(nullptr));
	alignas(CACHE_LINE_SIZE) std::array<std::byte, CACHE_LINE_SIZE> storage{};
	EXPECT_TRUE(is_cache_aligned(storage.data()));
	EXPECT_EQ(align_to_cache_line(1u), CACHE_LINE_SIZE);
	EXPECT_EQ(align_to_cache_line(CACHE_LINE_SIZE), CACHE_LINE_SIZE);
	EXPECT_EQ(align_to_cache_line(std::numeric_limits<std::size_t>::max()), 0u);
	EXPECT_EQ(aligned_alloc_cacheline(0u), nullptr);
	EXPECT_EQ(aligned_alloc_cacheline(std::numeric_limits<std::size_t>::max()), nullptr);
}

/**
 * @brief Verify runtime SPSC uses full advertised capacity.
 */
TEST(algo_queue, runtime_spsc_uses_full_advertised_capacity)
{
	constexpr std::size_t AMBIGUOUS_MODULAR_CAPACITY = (std::numeric_limits<std::size_t>::max() / 2u) + 1u;
	EXPECT_THROW((spsc_ring<int>(AMBIGUOUS_MODULAR_CAPACITY)), std::invalid_argument);
	EXPECT_THROW((void)spsc_ring_storage_bytes<int>(AMBIGUOUS_MODULAR_CAPACITY), std::invalid_argument);

	spsc_ring<int> ring(4);
	const std::array input{1, 2, 3, 4, 5};
	EXPECT_EQ(ring.push_batch(input.data(), input.size()), 4u);
	EXPECT_FALSE(ring.push(5));

	std::array<int, 4> output{};
	EXPECT_EQ(ring.pop_batch(output.data(), 2u), 2u);
	EXPECT_EQ(output[0], 1);
	EXPECT_EQ(output[1], 2);
	EXPECT_TRUE(ring.push(5));
	EXPECT_EQ(ring.pop_batch(output.data(), output.size()), 3u);
	EXPECT_EQ(output[0], 3);
	EXPECT_EQ(output[1], 4);
	EXPECT_EQ(output[2], 5);
	EXPECT_FALSE(ring.pop().has_value());
}

/**
 * @brief Verify static SPSC full capacity and atomic batch lifetime publication.
 */
TEST(algo_queue, static_spsc_uses_full_advertised_capacity)
{
	spsc_ring_static<int, 2> ring;
	EXPECT_TRUE(ring.try_push(1));
	EXPECT_TRUE(ring.try_push(2));
	EXPECT_FALSE(ring.try_push(3));

	auto first = ring.try_pop();
	auto second = ring.try_pop();
	ASSERT_TRUE(first.has_value());
	ASSERT_TRUE(second.has_value());
	EXPECT_EQ(*first, 1);
	EXPECT_EQ(*second, 2);
	EXPECT_FALSE(ring.try_pop().has_value());

	tracked_batch_value::live_count = 0;
	{
		std::array<tracked_batch_value, 3> input{
			tracked_batch_value(7),
			tracked_batch_value(11),
			tracked_batch_value(13),
		};
		std::array<tracked_batch_value, 3> output{};
		EXPECT_EQ(tracked_batch_value::live_count, 6u);
		{
			spsc_ring_static<tracked_batch_value, 2> batch_ring;
			EXPECT_EQ(batch_ring.push_batch(nullptr, 0), 0u);
			EXPECT_EQ(batch_ring.push_batch(input.data(), input.size()), 2u);
			EXPECT_EQ(tracked_batch_value::live_count, 8u);
			EXPECT_EQ(batch_ring.pop_batch(output.data(), 1), 1u);
			EXPECT_EQ(output[0].value, 7);
			EXPECT_EQ(tracked_batch_value::live_count, 7u);
			EXPECT_EQ(batch_ring.push_batch(input.data() + 2, 1), 1u);
			EXPECT_EQ(batch_ring.pop_batch(output.data() + 1, 2), 2u);
			EXPECT_EQ(output[1].value, 11);
			EXPECT_EQ(output[2].value, 13);
			EXPECT_EQ(batch_ring.pop_batch(nullptr, 0), 0u);
			EXPECT_TRUE(batch_ring.empty());
			EXPECT_EQ(tracked_batch_value::live_count, 6u);
		}
		EXPECT_EQ(tracked_batch_value::live_count, 6u);
	}
	EXPECT_EQ(tracked_batch_value::live_count, 0u);
}

/** @brief Verify borrowed-storage SPSC peek preserves exact FIFO ownership. */
TEST(algo_queue, borrowed_spsc_peek_does_not_consume_front)
{
	constexpr std::size_t CAPACITY = 4;
	alignas(int) std::array<std::byte, sizeof(int) * CAPACITY> storage{};
	ASSERT_EQ(storage.size(), spsc_ring_storage_bytes<int>(CAPACITY));

	spsc_ring_view<int> ring(storage.data(), storage.size(), CAPACITY);
	EXPECT_EQ(ring.peek(), nullptr);
	const std::array input{7, 11, 13, 17, 19};
	ASSERT_EQ(ring.push_batch(input.data(), input.size()), CAPACITY);

	const int *front = ring.peek();
	ASSERT_NE(front, nullptr);
	EXPECT_EQ(*front, 7);
	EXPECT_EQ(ring.size_approx(), CAPACITY);

	std::array<int, CAPACITY> output{};
	ASSERT_EQ(ring.pop_batch(output.data(), 2u), 2u);
	EXPECT_EQ(output[0], 7);
	EXPECT_EQ(output[1], 11);
	front = ring.peek();
	ASSERT_NE(front, nullptr);
	EXPECT_EQ(*front, 13);
	EXPECT_EQ(ring.size_approx(), 2u);
	ASSERT_TRUE(ring.try_push(19));
	ASSERT_EQ(ring.pop_batch(output.data(), output.size()), 3u);
	EXPECT_EQ(output[0], 13);
	EXPECT_EQ(output[1], 17);
	EXPECT_EQ(output[2], 19);
	EXPECT_TRUE(ring.empty());
}

/** @brief Every SPSC composition inherits the core's four cursor lines without changing element capacity. */
TEST(algo_queue, spsc_cursor_layout_is_owned_by_the_shared_core)
{
	using static_core = detail::spsc_ring_core<uint64_t, 8u>;
	using dynamic_core = detail::spsc_ring_core<uint64_t, 0u>;
	static_assert(alignof(static_core) == CACHE_LINE_SIZE);
	static_assert(alignof(dynamic_core) == CACHE_LINE_SIZE);
	static_assert(sizeof(static_core) == 5u * CACHE_LINE_SIZE);
	static_assert(sizeof(dynamic_core) == sizeof(static_core));
	static_assert(sizeof(spsc_ring_view<uint64_t>) == sizeof(dynamic_core));
	static_assert(sizeof(spsc_ring_static<uint64_t, 8u>) == sizeof(static_core) + CACHE_LINE_SIZE);
	EXPECT_EQ(spsc_ring_storage_bytes<uint64_t>(8u), 8u * sizeof(uint64_t));
}

/** @brief Conditional consumption retains a refused head and suffix across wrap in every storage form. */
TEST(algo_queue, conditional_prefix_preserves_refused_head_across_wrap)
{
	/** @brief Exercise one semantic FIFO sequence without inspecting ring indices. */
	const auto exercise = [](auto &ring) {
		const std::array input{7, 11, 13, 17, 19, 23};
		ASSERT_EQ(ring.push_batch(input.data(), 4u), 4u);
		std::array<int, 6> visited{};
		std::size_t visits = 0u;
		bool overflow = false;
		bool refuse_thirteen = true;
		/** @brief Record borrowed values, refusing one head without touching later values. */
		const auto accept = [&](const int &value) noexcept {
			if (visits == visited.size()) {
				overflow = true;
				return false;
			}
			visited[visits++] = value;
			return !refuse_thirteen || value != 13;
		};
		EXPECT_EQ(ring.consume_prefix(0u, accept), 0u);
		EXPECT_EQ(visits, 0u);
		ASSERT_EQ(ring.consume_prefix(4u, accept), 2u);
		EXPECT_EQ(visits, 3u);
		EXPECT_EQ(ring.size_approx(), 2u);
		ASSERT_EQ(ring.push_batch(input.data() + 4u, 2u), 2u);
		refuse_thirteen = false;
		ASSERT_EQ(ring.consume_prefix(3u, accept), 3u);
		EXPECT_FALSE(overflow);
		EXPECT_EQ(visited, (std::array{7, 11, 13, 13, 17, 19}));
		std::array<int, 4> remaining{};
		ASSERT_EQ(ring.pop_batch(remaining.data(), remaining.size()), 1u);
		EXPECT_EQ(remaining[0], 23);
		EXPECT_TRUE(ring.empty());
		EXPECT_EQ(ring.consume_prefix(4u, accept), 0u);
		EXPECT_EQ(visits, 6u);
	};
	spsc_ring_static<int, 4u> embedded;
	exercise(embedded);
	spsc_ring<int> allocated(4u);
	exercise(allocated);
	alignas(int) std::array<std::byte, 4u * sizeof(int)> storage{};
	spsc_ring_view<int> borrowed(storage.data(), storage.size(), 4u);
	exercise(borrowed);
}

/** @brief Refusal preserves a live value; acceptance destroys each value only after its callback returns. */
TEST(algo_queue, conditional_prefix_preserves_nontrivial_lifetimes)
{
	ASSERT_EQ(tracked_batch_value::live_count, 0u);
	spsc_ring_static<tracked_batch_value, 2u> ring;
	ASSERT_TRUE(ring.try_emplace(7));
	ASSERT_TRUE(ring.try_emplace(11));
	const auto refused = ring.consume_prefix(2u, [](const tracked_batch_value &) noexcept { return false; });
	EXPECT_EQ(refused, 0u);
	EXPECT_EQ(tracked_batch_value::live_count, 2u);
	std::array<std::size_t, 2> live_during{};
	std::array<int, 2> values{};
	std::size_t visits = 0u;
	const auto consumed = ring.consume_prefix(2u, [&](const tracked_batch_value &value) noexcept {
		if (visits == values.size()) {
			return false;
		}
		live_during[visits] = tracked_batch_value::live_count;
		values[visits++] = value.value;
		return true;
	});
	EXPECT_EQ(consumed, 2u);
	EXPECT_EQ(live_during, (std::array<std::size_t, 2>{2u, 1u}));
	EXPECT_EQ(values, (std::array{7, 11}));
	EXPECT_EQ(tracked_batch_value::live_count, 0u);
	EXPECT_TRUE(ring.empty());
}

/** @brief Producer bursts and conditional consumer prefixes publish exact ordered values across repeated wrap. */
TEST(algo_queue, conditional_prefix_preserves_cross_thread_publication)
{
	constexpr uint64_t TOTAL = 100000u;
	spsc_ring_static<uint64_t, 8u> ring;
	std::atomic<bool> failed{false};
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
	std::thread producer([&] {
		uint64_t next = 0u;
		std::array<uint64_t, 7> values{};
		while (next < TOTAL && !failed.load(std::memory_order_relaxed)) {
			const std::size_t count =
				static_cast<std::size_t>(std::min<uint64_t>(values.size(), TOTAL - next));
			for (std::size_t index = 0u; index < count; ++index) {
				values[index] = next + index;
			}
			next += ring.push_batch(values.data(), count);
			if (std::chrono::steady_clock::now() >= deadline) {
				failed.store(true, std::memory_order_relaxed);
			}
		}
	});
	uint64_t expected = 0u;
	while (expected < TOTAL && !failed.load(std::memory_order_relaxed)) {
		(void)ring.consume_prefix(5u, [&](const uint64_t &value) noexcept {
			if (value != expected) {
				failed.store(true, std::memory_order_relaxed);
			}
			++expected;
			return true;
		});
		if (std::chrono::steady_clock::now() >= deadline) {
			failed.store(true, std::memory_order_relaxed);
		}
	}
	producer.join();
	EXPECT_FALSE(failed.load(std::memory_order_relaxed));
	EXPECT_EQ(expected, TOTAL);
	EXPECT_TRUE(ring.empty());
}

/**
 * @brief Verify optional pop supports move only non default values.
 */
TEST(algo_queue, optional_pop_supports_move_only_non_default_values)
{
	spsc_ring_static<move_only_no_default, 2> static_ring;
	EXPECT_TRUE(static_ring.try_push(move_only_no_default(7)));
	auto static_value = static_ring.try_pop();
	ASSERT_TRUE(static_value.has_value());
	EXPECT_EQ(static_value->value, 7);
}

/** @brief Owning and borrowed membership preserve the same exact universe against an independent set. */
TEST(algo_compact_index_set, borrowed_and_owning_sets_match_the_reference_universe)
{
	for (const std::size_t limit : {0u, 1u, 63u, 64u, 65u, 130u, 1024u}) {
		SCOPED_TRACE(limit);
		std::vector<uint64_t> words(compact_index_set_view::storage_word_count(limit), UINT64_MAX);
		compact_index_set_view borrowed(words, limit);
		compact_index_set owned(limit);
		std::set<std::size_t> reference;
		EXPECT_EQ(borrowed.value_limit(), limit);
		for (std::size_t value = 0u; value < limit + 3u; ++value) {
			EXPECT_FALSE(borrowed.contains(value));
			if (value % 3u == 0u) {
				const bool admitted = value < limit && reference.insert(value).second;
				EXPECT_EQ(borrowed.insert(value), admitted);
				EXPECT_EQ(owned.insert(value), admitted);
				EXPECT_FALSE(borrowed.insert(value));
				EXPECT_FALSE(owned.insert(value));
			}
		}
		for (std::size_t value = 0u; value < limit + 3u; ++value) {
			EXPECT_EQ(borrowed.contains(value), reference.contains(value));
			EXPECT_EQ(owned.contains(value), reference.contains(value));
		}
		EXPECT_FALSE(borrowed.contains(std::numeric_limits<std::size_t>::max()));
	}
}

/** @brief Owning membership moves its bound with storage and leaves every source safely empty. */
TEST(algo_compact_index_set, copy_and_move_preserve_complete_universe_ownership)
{
	compact_index_set source(130u);
	ASSERT_TRUE(source.insert(0u));
	ASSERT_TRUE(source.insert(129u));
	compact_index_set copied(source);
	ASSERT_TRUE(copied.insert(64u));
	EXPECT_FALSE(source.contains(64u));
	compact_index_set moved(std::move(source));
	EXPECT_EQ(source.value_limit(), 0u);
	EXPECT_FALSE(source.contains(0u));
	EXPECT_FALSE(source.contains(129u));
	EXPECT_FALSE(source.insert(0u));
	EXPECT_EQ(moved.value_limit(), 130u);
	EXPECT_TRUE(moved.contains(0u));
	EXPECT_TRUE(moved.contains(129u));
	compact_index_set target(1024u);
	ASSERT_TRUE(target.insert(1000u));
	target = std::move(moved);
	EXPECT_EQ(target.value_limit(), 130u);
	EXPECT_FALSE(target.contains(1000u));
	EXPECT_TRUE(target.contains(129u));
	EXPECT_EQ(moved.value_limit(), 0u);
	EXPECT_FALSE(moved.contains(129u));
	EXPECT_FALSE(moved.insert(0u));
	auto *alias = &target;
	target = std::move(*alias);
	EXPECT_EQ(target.value_limit(), 130u);
	EXPECT_TRUE(target.contains(129u));
	source = copied;
	EXPECT_EQ(source.value_limit(), 130u);
	EXPECT_TRUE(source.contains(64u));
}

/** @brief A borrowed set rejects both short and excess backing extents without changing the caller's words. */
TEST(algo_compact_index_set, borrowed_extent_must_equal_the_complete_universe)
{
	std::array<uint64_t, 2> words{UINT64_MAX, UINT64_MAX};
	EXPECT_THROW((compact_index_set_view(words, 64u)), std::invalid_argument);
	EXPECT_THROW((compact_index_set_view(std::span<uint64_t>(words).first(1u), 65u)), std::invalid_argument);
	EXPECT_EQ(words, (std::array<uint64_t, 2>{UINT64_MAX, UINT64_MAX}));
	compact_index_set_view view(words, 65u);
	EXPECT_EQ(words, (std::array<uint64_t, 2>{0u, 0u}));
	EXPECT_TRUE(view.insert(64u));
	EXPECT_EQ(words[1], 1u);
	EXPECT_FALSE(view.insert(65u));
	EXPECT_FALSE(view.contains(127u));
}

/** @brief Verify caller-storage owner queues retain exact runtime FIFO capacity. */
TEST(algo_queue, borrowed_work_queue_uses_exact_single_owner_arithmetic)
{
	std::array<work_queue_view<uint32_t>::storage_type, 4> storage{};
	work_queue_view<uint32_t> queue(storage.data(), storage.size());
	EXPECT_EQ(queue.capacity(), 4u);
	for (uint32_t value = 1u; value <= 4u; ++value) {
		EXPECT_TRUE(queue.try_push(value));
	}
	EXPECT_TRUE(queue.full());
	EXPECT_FALSE(queue.try_push(5u));
	for (uint32_t expected = 1u; expected <= 2u; ++expected) {
		uint32_t value = 0u;
		ASSERT_TRUE(queue.try_pop(value));
		EXPECT_EQ(value, expected);
	}
	EXPECT_TRUE(queue.try_push(5u));
	EXPECT_TRUE(queue.try_push(6u));
	EXPECT_TRUE(queue.full());
	for (uint32_t expected = 3u; expected <= 6u; ++expected) {
		uint32_t value = 0u;
		ASSERT_TRUE(queue.try_pop(value));
		EXPECT_EQ(value, expected);
	}
	EXPECT_TRUE(queue.empty());
}

/** @brief Consume partial and wrapped work-queue batches in FIFO order without touching the output suffix. */
TEST(algo_queue, work_queue_batches_preserve_wrapped_prefixes)
{
	std::array<work_queue_view<uint32_t>::storage_type, 4> storage{};
	work_queue_view<uint32_t> queue(storage.data(), storage.size());
	std::array<uint32_t, 6> output{};
	output.fill(UINT32_MAX);
	EXPECT_EQ(queue.pop_batch(nullptr, 0u), 0u);
	EXPECT_EQ(queue.pop_batch(output.data(), output.size()), 0u);
	for (uint32_t value = 1u; value <= 4u; ++value) {
		ASSERT_TRUE(queue.try_push(value));
	}
	ASSERT_EQ(queue.pop_batch(output.data(), 3u), 3u);
	EXPECT_EQ(output, (std::array<uint32_t, 6>{1u, 2u, 3u, UINT32_MAX, UINT32_MAX, UINT32_MAX}));
	for (uint32_t value = 5u; value <= 7u; ++value) {
		ASSERT_TRUE(queue.try_push(value));
	}
	EXPECT_TRUE(queue.full());
	EXPECT_FALSE(queue.try_push(8u));
	output.fill(UINT32_MAX);
	ASSERT_EQ(queue.pop_batch(output.data(), output.size()), 4u);
	EXPECT_EQ(output, (std::array<uint32_t, 6>{4u, 5u, 6u, 7u, UINT32_MAX, UINT32_MAX}));
	EXPECT_TRUE(queue.empty());
	EXPECT_EQ(queue.pop_batch(output.data(), output.size()), 0u);
}

/** @brief Batch movement uses caller slots and retires each lifetime exactly once through wrap and clear. */
TEST(algo_queue, work_queue_batch_lifetimes_are_exact)
{
	ASSERT_EQ(tracked_batch_value::live_count, 0u);
	{
		std::array<work_queue_view<tracked_batch_value>::storage_type, 4> storage{};
		work_queue_view<tracked_batch_value> queue(storage.data(), storage.size());
		std::array<tracked_batch_value, 3> output{};
		for (int value = 1; value <= 4; ++value) {
			ASSERT_TRUE(queue.try_push(tracked_batch_value(value)));
			const auto placed =
				reinterpret_cast<std::uintptr_t>(tracked_batch_value::last_move_destination);
			const auto first = reinterpret_cast<std::uintptr_t>(storage.data());
			EXPECT_GE(placed, first);
			EXPECT_LT(placed, first + sizeof(storage));
		}
		EXPECT_EQ(tracked_batch_value::live_count, 7u);
		ASSERT_EQ(queue.pop_batch(output.data(), output.size()), 3u);
		EXPECT_EQ(tracked_batch_value::live_count, 4u);
		for (std::size_t index = 0u; index < output.size(); ++index) {
			EXPECT_EQ(output[index].value, static_cast<int>(index + 1u));
		}
		for (int value = 5; value <= 7; ++value) {
			ASSERT_TRUE(queue.try_push(tracked_batch_value(value)));
			const auto placed =
				reinterpret_cast<std::uintptr_t>(tracked_batch_value::last_move_destination);
			const auto first = reinterpret_cast<std::uintptr_t>(storage.data());
			EXPECT_GE(placed, first);
			EXPECT_LT(placed, first + sizeof(storage));
		}
		ASSERT_EQ(queue.pop_batch(output.data(), output.size()), 3u);
		EXPECT_EQ(tracked_batch_value::live_count, 4u);
		for (std::size_t index = 0u; index < output.size(); ++index) {
			EXPECT_EQ(output[index].value, static_cast<int>(index + 4u));
		}
		queue.clear();
		EXPECT_EQ(tracked_batch_value::live_count, 3u);
		ASSERT_TRUE(queue.try_push(tracked_batch_value(8)));
	}
	EXPECT_EQ(tracked_batch_value::live_count, 0u);
}

/** @brief Work batches preserve nothrow constraints and the existing modular capacity wall. */
TEST(algo_queue, work_queue_batch_type_and_capacity_contracts_are_exact)
{
	static_assert(supports_batch_pop<work_queue_view<move_only_no_default>>);
	static_assert(!supports_batch_pop<work_queue_view<throwing_batch_value>>);
	using queue_type = work_queue_view<move_only_no_default>;
	EXPECT_FALSE(queue_type::valid_capacity(0u));
	EXPECT_FALSE(queue_type::valid_capacity(1u));
	EXPECT_FALSE(queue_type::valid_capacity(3u));
	EXPECT_FALSE(queue_type::valid_capacity(std::numeric_limits<std::size_t>::max() / 2u + 1u));
	EXPECT_TRUE(queue_type::valid_capacity(2u));
	std::array<queue_type::storage_type, 2> storage{};
	queue_type queue(storage.data(), storage.size());
	ASSERT_TRUE(queue.try_push(move_only_no_default(17)));
	ASSERT_TRUE(queue.try_push(move_only_no_default(23)));
	std::array<move_only_no_default, 2> output{move_only_no_default(0), move_only_no_default(0)};
	ASSERT_EQ(queue.pop_batch(output.data(), output.size()), 2u);
	EXPECT_EQ(output[0].value, 17);
	EXPECT_EQ(output[1].value, 23);
	EXPECT_TRUE(queue.empty());
}

/** @brief Pin construction-time MPMC capacity validation and full-capacity use. */
TEST(algo_queue, dynamic_mpmc_uses_exact_validated_capacity)
{
	EXPECT_THROW((mpmc_queue_dynamic<uint32_t>(1)), std::invalid_argument);
	EXPECT_THROW((mpmc_queue_dynamic<uint32_t>(3)), std::invalid_argument);
	constexpr std::size_t AMBIGUOUS_MODULAR_CAPACITY = (std::numeric_limits<std::size_t>::max() / 2) + 1;
	EXPECT_THROW((mpmc_queue_dynamic<uint32_t>(AMBIGUOUS_MODULAR_CAPACITY)), std::invalid_argument);

	mpmc_queue_dynamic<uint32_t> queue(4);
	EXPECT_EQ(queue.capacity(), 4u);
	for (uint32_t value = 0; value < 4; ++value) {
		EXPECT_TRUE(queue.try_enqueue(value));
	}
	EXPECT_EQ(queue.size_approx(), queue.capacity());
	EXPECT_FALSE(queue.try_enqueue(4));
	for (uint32_t expected = 0; expected < 4; ++expected) {
		uint32_t value = UINT32_MAX;
		ASSERT_TRUE(queue.try_dequeue(value));
		EXPECT_EQ(value, expected);
	}
	uint32_t value = 0;
	EXPECT_FALSE(queue.try_dequeue(value));
	EXPECT_EQ(queue.size_approx(), 0u);
}

/** @brief Prove static, dynamic, and caller-storage MPMC forms share one exact core. */
TEST(algo_queue, caller_storage_mpmc_and_owning_forms_share_exact_arithmetic)
{
	using view_type = mpmc_queue_view<uint32_t>;
	static_assert(sizeof(view_type::storage_type) % CACHE_LINE_SIZE == 0u);
	std::array<view_type::storage_type, 4> storage{};
	view_type borrowed(storage.data(), storage.size());
	mpmc_queue<uint32_t, 4> embedded;
	mpmc_queue_dynamic<uint32_t> dynamic(4u);
	EXPECT_TRUE(view_type::valid_capacity(4u));
	EXPECT_FALSE(view_type::valid_capacity(3u));
	EXPECT_EQ(borrowed.capacity(), 4u);

	for (uint32_t value = 10u; value < 14u; ++value) {
		EXPECT_TRUE(borrowed.try_enqueue(value));
		EXPECT_TRUE(embedded.try_enqueue(value));
		EXPECT_TRUE(dynamic.try_enqueue(value));
	}
	EXPECT_FALSE(borrowed.try_enqueue(14u));
	EXPECT_FALSE(embedded.try_enqueue(14u));
	EXPECT_FALSE(dynamic.try_enqueue(14u));
	for (uint32_t expected = 10u; expected < 14u; ++expected) {
		uint32_t borrowed_value = 0u;
		uint32_t embedded_value = 0u;
		uint32_t dynamic_value = 0u;
		ASSERT_TRUE(borrowed.try_dequeue(borrowed_value));
		ASSERT_TRUE(embedded.try_dequeue(embedded_value));
		ASSERT_TRUE(dynamic.try_dequeue(dynamic_value));
		EXPECT_EQ(borrowed_value, expected);
		EXPECT_EQ(embedded_value, expected);
		EXPECT_EQ(dynamic_value, expected);
	}
	EXPECT_TRUE(borrowed.empty());
	EXPECT_TRUE(embedded.empty());
	EXPECT_EQ(dynamic.size_approx(), 0u);
}

/** @brief Prove concurrent producers and consumers transfer every value exactly once. */
TEST(algo_queue, dynamic_mpmc_conserves_values_under_contention)
{
	constexpr uint32_t VALUE_COUNT = 512;
	constexpr uint32_t VALUES_PER_PRODUCER = VALUE_COUNT / 2;
	mpmc_queue_dynamic<uint32_t> queue(64);
	std::array<std::atomic<uint8_t>, VALUE_COUNT> seen{};
	std::atomic<uint32_t> consumed{0};
	std::atomic<uint32_t> producers_done{0};
	std::atomic<bool> observed_invalid_size{false};

	auto produce = [&queue, &producers_done](uint32_t begin) {
		for (uint32_t value = begin; value < begin + VALUES_PER_PRODUCER; ++value) {
			while (!queue.try_enqueue(value)) {
				std::this_thread::yield();
			}
		}
		producers_done.fetch_add(1, std::memory_order_release);
	};
	auto consume = [&queue, &seen, &consumed, &producers_done]() {
		for (;;) {
			uint32_t value = 0;
			if (!queue.try_dequeue(value)) {
				if (producers_done.load(std::memory_order_acquire) == 2) {
					break;
				}
				std::this_thread::yield();
				continue;
			}
			if (value < VALUE_COUNT) {
				seen[value].fetch_add(1, std::memory_order_relaxed);
			}
			consumed.fetch_add(1, std::memory_order_release);
		}
	};

	std::thread first_consumer(consume);
	std::thread second_consumer(consume);
	std::thread first_producer(produce, 0);
	std::thread second_producer(produce, VALUES_PER_PRODUCER);
	std::thread observer([&queue, &consumed, &producers_done, &observed_invalid_size]() {
		while (consumed.load(std::memory_order_acquire) != VALUE_COUNT ||
		       producers_done.load(std::memory_order_acquire) != 2) {
			if (queue.size_approx() > queue.capacity()) {
				observed_invalid_size.store(true, std::memory_order_relaxed);
			}
			std::this_thread::yield();
		}
	});
	first_producer.join();
	second_producer.join();
	first_consumer.join();
	second_consumer.join();
	observer.join();

	EXPECT_EQ(consumed.load(std::memory_order_acquire), VALUE_COUNT);
	EXPECT_FALSE(observed_invalid_size.load(std::memory_order_relaxed));
	for (const auto &count : seen) {
		EXPECT_EQ(count.load(std::memory_order_relaxed), 1u);
	}
	EXPECT_EQ(queue.size_approx(), 0u);
}

/**
 * @brief Verify bucket population and storage ownership are explicit inputs.
 */
TEST(algo_cuckoo, construction_requires_positive_population_and_explicit_storage)
{
	EXPECT_THROW((test_cuckoo_map(0u, std::pmr::new_delete_resource())), std::invalid_argument);
	EXPECT_THROW((test_cuckoo_map(1u, nullptr)), std::invalid_argument);
	test_cuckoo_map map(1u, std::pmr::new_delete_resource());
	EXPECT_EQ(map.size(), 0u);
}

/**
 * @brief Verify failed insert preserves existing entries.
 */
TEST(algo_cuckoo, failed_insert_preserves_existing_entries)
{
	test_cuckoo_map map(1u, std::pmr::new_delete_resource());
	for (uint32_t i = 0; i < 8; ++i) {
		ASSERT_TRUE(map.insert(i, i + 100));
	}
	ASSERT_EQ(map.size(), 8u);

	EXPECT_FALSE(map.insert(99, 199));
	EXPECT_EQ(map.size(), 8u);
	EXPECT_EQ(map.find(99), nullptr);

	for (uint32_t i = 0; i < 8; ++i) {
		const auto *value = map.find(i);
		ASSERT_NE(value, nullptr) << "lost key " << i;
		EXPECT_EQ(*value, i + 100);
	}
}

/**
 * @brief Verify map object does not embed displacement log.
 */
TEST(algo_cuckoo, map_object_does_not_embed_displacement_log)
{
	EXPECT_LT(sizeof(test_cuckoo_map), 1024u);
}

/** @brief Prepared queries observe updates, erasure, reinsertions and failed displacement without cached results. */
TEST(algo_cuckoo, prepared_queries_observe_current_collision_bucket_contents)
{
	test_cuckoo_map map(1u, std::pmr::new_delete_resource());
	std::vector<test_cuckoo_map::prepared_query> queries;
	queries.reserve(9u);
	for (uint32_t key = 0; key < 9u; ++key) {
		queries.push_back(map.prepare(key));
		EXPECT_EQ(map.find(queries.back()), nullptr);
	}
	for (uint32_t key = 0; key < 8u; ++key) {
		ASSERT_TRUE(map.insert(key, key + 100u));
	}
	EXPECT_FALSE(map.insert(8u, 108u));
	for (uint32_t key = 0; key < 8u; ++key) {
		ASSERT_NE(map.find(queries[key]), nullptr);
		EXPECT_EQ(*map.find(queries[key]), key + 100u);
	}
	ASSERT_TRUE(map.erase(3u));
	EXPECT_EQ(map.find(queries[3]), nullptr);
	ASSERT_TRUE(map.insert(8u, 108u));
	ASSERT_TRUE(map.insert(2u, 999u));
	EXPECT_EQ(*std::as_const(map).find(queries[8]), 108u);
	EXPECT_EQ(*map.find(queries[2]), 999u);
	test_cuckoo_map other(1u, std::pmr::new_delete_resource());
	EXPECT_DEATH((void)other.find(queries[0]), "");
	EXPECT_DEATH((void)std::as_const(other).find(queries[0]), "");
}

/** @brief Query creation and copying require neither a key default construction nor a move. */
TEST(algo_cuckoo, prepared_query_preserves_the_nothrow_copy_key_contract)
{
	cuckoo_map<copy_only_key, uint32_t, copy_only_key_hash> map(2u, std::pmr::new_delete_resource());
	copy_only_key key;
	key.value = 37u;
	const auto defaults = copy_only_key::defaults;
	const auto query = map.prepare(key);
	const auto copied = query;
	EXPECT_EQ(copy_only_key::defaults, defaults);
	EXPECT_EQ(map.find(query), nullptr);
	ASSERT_TRUE(map.insert(key, 73u));
	ASSERT_NE(map.find(copied), nullptr);
	EXPECT_EQ(*map.find(copied), 73u);
	EXPECT_EQ(copy_only_key::defaults, defaults);
}

/** @brief Long-lived queries and scalar lookup agree with an independent map after every mutation. */
TEST(algo_cuckoo, prepared_queries_match_independent_mutation_oracle)
{
	using map_type = cuckoo_map<uint32_t, uint32_t, integer_key_hash>;
	constexpr uint32_t KEY_COUNT = 96u;
	map_type map(8u, std::pmr::new_delete_resource());
	std::vector<map_type::prepared_query> queries;
	queries.reserve(KEY_COUNT);
	for (uint32_t key = 0; key < KEY_COUNT; ++key) {
		queries.push_back(map.prepare(key));
	}
	std::map<uint32_t, uint32_t> reference;
	uint32_t state = 0x4b1d5u;
	for (uint32_t step = 0; step < 4096u; ++step) {
		state = state * 1664525u + 1013904223u;
		const uint32_t key = (state >> 8u) % KEY_COUNT;
		if ((state & 3u) == 0u) {
			EXPECT_EQ(map.erase(key), reference.erase(key) != 0u);
		} else if (map.insert(key, step)) {
			reference[key] = step;
		}
		ASSERT_EQ(map.size(), reference.size());
		for (uint32_t candidate = 0; candidate < KEY_COUNT; ++candidate) {
			const auto expected = reference.find(candidate);
			const auto *prepared = map.find(queries[candidate]);
			EXPECT_EQ(prepared, map.find(candidate));
			ASSERT_EQ(prepared != nullptr, expected != reference.end());
			if (prepared != nullptr) {
				EXPECT_EQ(*prepared, expected->second);
			}
		}
	}
}

/**
 * @brief Verify oversized packet cost is fail closed.
 */
TEST(algo_ratelimit, oversized_packet_cost_is_fail_closed)
{
	token_bucket token(0, 64);
	EXPECT_FALSE(token.allow(1, std::numeric_limits<std::size_t>::max()));

	leaky_bucket leaky(0, 64);
	EXPECT_FALSE(leaky.allow(1, std::numeric_limits<std::size_t>::max()));
}

/** @brief Timestamp zero is ordinary identity and never reinitializes consumed credit. */
TEST(algo_ratelimit, zero_timestamp_binds_one_exact_initial_baseline)
{
	token_bucket token(1u, 1u);
	EXPECT_TRUE(token.allow(0u, 1u));
	EXPECT_FALSE(token.allow(1u, 1u));
	EXPECT_TRUE(token.allow(1'000'000'000u, 1u));

	leaky_bucket leaky(1u, 1u);
	EXPECT_TRUE(leaky.allow(0u, 1u));
	EXPECT_FALSE(leaky.allow(1u, 1u));
	EXPECT_TRUE(leaky.allow(1'000'000'000u, 1u));
}

/** @brief Sub-byte accrual survives every observation until one exact byte exists. */
TEST(algo_ratelimit, low_rates_accumulate_fractional_credit_without_truncation)
{
	token_bucket token(1u, 1u);
	ASSERT_TRUE(token.allow(0u, 1u));
	for (uint64_t now_ns : {250'000'000u, 500'000'000u, 750'000'000u}) {
		EXPECT_FALSE(token.allow(now_ns, 1u));
	}
	EXPECT_TRUE(token.allow(1'000'000'000u, 1u));

	leaky_bucket leaky(1u, 1u);
	ASSERT_TRUE(leaky.allow(0u, 1u));
	for (uint64_t now_ns : {250'000'000u, 500'000'000u, 750'000'000u}) {
		EXPECT_FALSE(leaky.allow(now_ns, 1u));
	}
	EXPECT_TRUE(leaky.allow(1'000'000'000u, 1u));
}

/** @brief Full-width capacities and costs retain exact arithmetic without saturation aliases. */
TEST(algo_ratelimit, complete_unsigned_byte_domain_is_exact)
{
	constexpr uint64_t MAX_BYTES = std::numeric_limits<uint64_t>::max();
	token_bucket token(0u, MAX_BYTES);
	if constexpr (sizeof(std::size_t) == sizeof(uint64_t)) {
		EXPECT_TRUE(token.allow(0u, std::numeric_limits<std::size_t>::max()));
		EXPECT_EQ(token.tokens(), 0u);
	}

	leaky_bucket leaky(0u, MAX_BYTES);
	EXPECT_TRUE(leaky.allow(0u, std::numeric_limits<std::size_t>::max()));
	EXPECT_EQ(leaky.level(), static_cast<uint64_t>(std::numeric_limits<std::size_t>::max()));
}

/** @brief Regressing time and reconfiguration cannot mint rate credit. */
TEST(algo_ratelimit, regression_and_reconfiguration_preserve_exact_credit)
{
	token_bucket token(1u, 2u);
	ASSERT_TRUE(token.allow(100u, 1u));
	EXPECT_FALSE(token.allow(99u, 1u));
	EXPECT_EQ(token.tokens(), 1u);
	EXPECT_TRUE(token.allow(100u, 1u));

	token_bucket reconfigured(1u, 10u);
	ASSERT_TRUE(reconfigured.allow(0u, 10u));
	EXPECT_FALSE(reconfigured.allow(500'000'000u, 1u));
	reconfigured.reconfigure(2u, 10u);
	EXPECT_FALSE(reconfigured.allow(1'000'000'000u, 1u));
	EXPECT_TRUE(reconfigured.allow(1'500'000'000u, 1u));

	leaky_bucket leaky(0u, 2u);
	ASSERT_TRUE(leaky.allow(100u, 1u));
	EXPECT_FALSE(leaky.allow(99u, 1u));
	EXPECT_EQ(leaky.level(), 1u);
}

/** @brief Exact credit retains every subdivision and caps before a full-width refill. */
TEST(algo_ratelimit, byte_credit_preserves_subdivisions_and_saturates_before_addition)
{
	byte_credit divided;
	byte_credit combined;
	// 512,000 microseconds at 125 bytes/s earn exactly 64 bytes.
	for (uint32_t interval = 0; interval < 512000u; ++interval) {
		ASSERT_TRUE(divided.consume(1000u, 125u, 1024u, 0u));
	}
	ASSERT_TRUE(combined.consume(512000000u, 125u, 1024u, 0u));
	EXPECT_EQ(divided.tokens(), 64u);
	EXPECT_EQ(combined.tokens(), 64u);
	EXPECT_TRUE(divided.consume(0u, 125u, 1024u, 64u));
	EXPECT_TRUE(combined.consume(0u, 125u, 1024u, 64u));
	EXPECT_FALSE(divided.consume(0u, 125u, 1024u, 1u));

	constexpr uint64_t MAX = std::numeric_limits<uint64_t>::max();
	byte_credit full(MAX);
	EXPECT_TRUE(full.consume(MAX, MAX, MAX, MAX));
	EXPECT_EQ(full.tokens(), 0u);
	full.reset(1024u);
	EXPECT_FALSE(full.consume(0u, MAX, 100u, 101u));
	EXPECT_EQ(full.tokens(), 100u);
	EXPECT_TRUE(full.consume(0u, 0u, 100u, 100u));
}

/** @brief Sliding windows reject zero duration and never reset on regressing time. */
TEST(algo_ratelimit, sliding_window_requires_positive_monotonic_time)
{
	EXPECT_THROW((sliding_window(1u, 0u)), std::invalid_argument);
	sliding_window window(2u, 100u);
	EXPECT_TRUE(window.allow(100u));
	EXPECT_TRUE(window.allow(101u));
	EXPECT_FALSE(window.allow(99u));
	EXPECT_EQ(window.count(), 2u);
	EXPECT_FALSE(window.allow(102u));
	EXPECT_TRUE(window.allow(200u));
}

}  // namespace kinetum::algo
