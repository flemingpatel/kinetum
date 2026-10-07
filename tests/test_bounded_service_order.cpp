// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_bounded_service_order.cpp
 * @brief Deterministic service bounds, interrupted quanta, and lifetime coverage.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>

#include <kinetum/algo/bounded_service_order.hpp>

namespace kinetum::algo
{
namespace
{

/** Existing packet-sized quantum used in exact capacity vectors. */
constexpr uint16_t TEST_QUANTUM = 64u;
/** Caller-storage cell type; each test binds only one live owner at a time. */
using service_entry = bounded_service_order::entry;

}  // namespace

/** @brief Input-free and unary owners invoke no unnecessary service or carried fragment. */
TEST(bounded_service_order, empty_and_single_input_have_direct_bounded_service)
{
	bounded_service_order empty(std::span<service_entry>{});
	uint32_t calls = 0u;
	empty.service([&](uint32_t, uint16_t) noexcept {
		++calls;
		return service_result{};
	});
	EXPECT_EQ(calls, 0u);
	std::array<service_entry, 1> entries{service_entry{TEST_QUANTUM}};
	bounded_service_order single(entries);
	for (uint32_t turn = 0u; turn < 8u; ++turn) {
		single.service([&](uint32_t index, uint16_t offered) noexcept {
			EXPECT_EQ(index, 0u);
			EXPECT_EQ(offered, TEST_QUANTUM);
			++calls;
			return service_result{3u, service_disposition::RETAINED};
		});
	}
	EXPECT_EQ(calls, 8u);
}

/** @brief A zero quantum rejects the complete order before service is possible. */
TEST(bounded_service_order, zero_quantum_is_rejected)
{
	std::array<service_entry, 2> entries{service_entry{TEST_QUANTUM}, service_entry{0u}};
	EXPECT_THROW((void)bounded_service_order(entries), std::invalid_argument);
}

/** @brief Capacity interrupted at 80 slots preserves both the second input and the first input's return. */
TEST(bounded_service_order, partial_quantum_preserves_both_service_directions)
{
	std::array<service_entry, 2> entries{service_entry{TEST_QUANTUM}, service_entry{TEST_QUANTUM}};
	bounded_service_order order(entries);
	std::array<uint32_t, 2> totals{};
	constexpr std::array<std::array<uint16_t, 2>, 3> EXPECTED_WORK{{{64u, 16u}, {32u, 48u}, {32u, 48u}}};
	constexpr std::array<uint32_t, 3> EXPECTED_FIRST{0u, 1u, 0u};
	for (std::size_t turn = 0u; turn < EXPECTED_WORK.size(); ++turn) {
		uint16_t capacity = 80u;
		std::array<uint16_t, 2> work{};
		uint32_t first = 2u;
		order.service([&](uint32_t index, uint16_t offered) noexcept {
			if (first == 2u) {
				first = index;
			}
			const uint16_t accepted = std::min(capacity, offered);
			capacity = static_cast<uint16_t>(capacity - accepted);
			work[index] = static_cast<uint16_t>(work[index] + accepted);
			totals[index] += accepted;
			return service_result{accepted, service_disposition::RETAINED};
		});
		EXPECT_EQ(first, EXPECTED_FIRST[turn]);
		EXPECT_EQ(work, EXPECTED_WORK[turn]);
		EXPECT_EQ(capacity, 0u);
	}
	EXPECT_EQ(totals, (std::array<uint32_t, 2>{128u, 112u}));
}

/** @brief Every continuously waiting input reaches its exact opposing-quantum bound, never beyond it. */
TEST(bounded_service_order, continuously_eligible_inputs_have_two_direction_exact_bounds)
{
	constexpr std::array<uint16_t, 3> QUANTA{4u, 7u, 3u};
	constexpr uint32_t TOTAL_QUANTUM = 14u;
	std::array<service_entry, 3> entries{service_entry{QUANTA[0]}, service_entry{QUANTA[1]},
					     service_entry{QUANTA[2]}};
	bounded_service_order order(entries);
	std::array<uint32_t, 3> waiting_work{};
	std::array<uint32_t, 3> longest_wait{};
	std::array<uint32_t, 3> totals{};
	for (uint32_t turn = 0u; turn < TOTAL_QUANTUM * 16u; ++turn) {
		uint16_t capacity = 1u;
		order.service([&](uint32_t index, uint16_t offered) noexcept {
			EXPECT_GT(offered, 0u);
			EXPECT_LE(offered, QUANTA[index]);
			const uint16_t accepted = std::min(capacity, offered);
			capacity = static_cast<uint16_t>(capacity - accepted);
			if (accepted != 0u) {
				++totals[index];
				waiting_work[index] = 0u;
				for (std::size_t other = 0u; other < QUANTA.size(); ++other) {
					if (other != index) {
						++waiting_work[other];
						longest_wait[other] =
							std::max(longest_wait[other], waiting_work[other]);
					}
				}
			}
			return service_result{accepted, service_disposition::RETAINED};
		});
		EXPECT_EQ(capacity, 0u);
		for (std::size_t index = 0u; index < QUANTA.size(); ++index) {
			EXPECT_LE(waiting_work[index], TOTAL_QUANTUM - QUANTA[index]);
		}
	}
	for (std::size_t index = 0u; index < QUANTA.size(); ++index) {
		EXPECT_EQ(longest_wait[index], TOTAL_QUANTUM - QUANTA[index]);
		EXPECT_EQ(totals[index], 16u * QUANTA[index]);
	}
}

/** @brief An unavailable storage domain cannot impose fixed priority on another domain's contenders. */
TEST(bounded_service_order, blocked_domain_preserves_independent_domain_fairness)
{
	std::array<service_entry, 3> entries{service_entry{TEST_QUANTUM}, service_entry{TEST_QUANTUM},
					     service_entry{TEST_QUANTUM}};
	bounded_service_order order(entries);
	std::array<uint32_t, 3> totals{};
	for (uint32_t turn = 0u; turn < 128u; ++turn) {
		uint16_t capacity = 80u;
		std::array<uint16_t, 3> work{};
		std::array<uint32_t, 3> visits{};
		order.service([&](uint32_t index, uint16_t offered) noexcept {
			++visits[index];
			const uint16_t accepted = index == 0u ? uint16_t{0} : std::min(capacity, offered);
			capacity = static_cast<uint16_t>(capacity - accepted);
			work[index] = static_cast<uint16_t>(work[index] + accepted);
			totals[index] += accepted;
			return service_result{accepted, service_disposition::RETAINED};
		});
		EXPECT_EQ(capacity, 0u);
		for (std::size_t index = 0u; index < entries.size(); ++index) {
			EXPECT_LE(visits[index], 2u);
			EXPECT_LE(work[index], TEST_QUANTUM);
		}
		EXPECT_LE(std::max(totals[1], totals[2]) - std::min(totals[1], totals[2]), TEST_QUANTUM);
	}
	EXPECT_EQ(totals[0], 0u);
	EXPECT_EQ(totals[1], 5120u);
	EXPECT_EQ(totals[2], 5120u);
}

/** @brief Yield discards a carried remainder and forbids a second empty poll that turn. */
TEST(bounded_service_order, yielding_input_discards_carry)
{
	std::array<service_entry, 2> entries{service_entry{TEST_QUANTUM}, service_entry{TEST_QUANTUM}};
	bounded_service_order order(entries);
	order.service([](uint32_t index, uint16_t) noexcept {
		return service_result{index == 0u ? uint16_t{16} : uint16_t{0}, service_disposition::RETAINED};
	});
	std::array<uint32_t, 2> visits{};
	order.service([&](uint32_t index, uint16_t offered) noexcept {
		++visits[index];
		if (index == 0u) {
			EXPECT_EQ(offered, 48u);
		}
		return service_result{0u, service_disposition::YIELDED};
	});
	EXPECT_EQ(visits, (std::array<uint32_t, 2>{1u, 1u}));
	order.service([](uint32_t, uint16_t offered) noexcept {
		EXPECT_EQ(offered, TEST_QUANTUM);
		return service_result{0u, service_disposition::YIELDED};
	});
}

/** @brief Finishing a carried prefix uses the remaining turn allowance without exceeding either bound. */
TEST(bounded_service_order, second_visit_uses_only_the_unused_turn_allowance)
{
	std::array<service_entry, 2> entries{service_entry{TEST_QUANTUM}, service_entry{TEST_QUANTUM}};
	bounded_service_order order(entries);
	order.service([](uint32_t index, uint16_t) noexcept {
		return index == 0u ? service_result{60u, service_disposition::RETAINED} : service_result{};
	});
	std::array<uint16_t, 2> offered_prefixes{};
	uint32_t visits = 0u;
	order.service([&](uint32_t index, uint16_t offered) noexcept {
		if (index != 0u) {
			return service_result{};
		}
		if (visits < offered_prefixes.size()) {
			offered_prefixes[visits] = offered;
		}
		++visits;
		return service_result{offered, service_disposition::RETAINED};
	});
	EXPECT_EQ(visits, 2u);
	EXPECT_EQ(offered_prefixes, (std::array<uint16_t, 2>{4u, 60u}));
}

/** @brief Rejected input consumes its complete work allowance without repeated service in the same turn. */
TEST(bounded_service_order, rejected_work_consumes_the_quantum)
{
	std::array<service_entry, 2> entries{service_entry{TEST_QUANTUM}, service_entry{TEST_QUANTUM}};
	bounded_service_order order(entries);
	std::array<uint32_t, 2> visits{};
	order.service([&](uint32_t index, uint16_t offered) noexcept {
		++visits[index];
		return service_result{offered, service_disposition::RETAINED};
	});
	EXPECT_EQ(visits, (std::array<uint32_t, 2>{1u, 1u}));
}

/** @brief Rebinding caller storage for a new owner cannot retain the previous generation's allowance. */
TEST(bounded_service_order, new_owner_discards_previous_lifetime_carry)
{
	std::array<service_entry, 2> entries{service_entry{TEST_QUANTUM}, service_entry{TEST_QUANTUM}};
	{
		bounded_service_order first(entries);
		first.service(
			[](uint32_t, uint16_t) noexcept { return service_result{1u, service_disposition::RETAINED}; });
	}
	bounded_service_order replacement(entries);
	replacement.service([](uint32_t, uint16_t offered) noexcept {
		EXPECT_EQ(offered, TEST_QUANTUM);
		return service_result{};
	});
}

/** @brief Invalid progress and undeclared dispositions fail before corrupting the order. */
TEST(bounded_service_order, invalid_callback_results_fail_stop)
{
	ASSERT_DEATH(([] {
			     std::array<service_entry, 2> entries{service_entry{1u}, service_entry{1u}};
			     bounded_service_order order(entries);
			     order.service([](uint32_t, uint16_t) noexcept {
				     return service_result{2u, service_disposition::RETAINED};
			     });
		     }()),
		     "");
	ASSERT_DEATH(([] {
			     std::array<service_entry, 1> entries{service_entry{1u}};
			     bounded_service_order order(entries);
			     order.service([](uint32_t, uint16_t) noexcept {
				     return service_result{0u, static_cast<service_disposition>(0u)};
			     });
		     }()),
		     "");
}

}  // namespace kinetum::algo
