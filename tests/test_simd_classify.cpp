// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_simd_classify.cpp
 * @brief Cross-architecture semantic tests for public SIMD classifiers.
 * @author Fleming Patel
 *
 * Every selected SIMD implementation is compared with independent scalar
 * predicates at vector boundaries and at the complete public 64-lane bound.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

#include <kinetum/algo/net.hpp>
#include <kinetum/algo/simd_classify.hpp>

namespace kinetum::algo
{
namespace
{

/** Counts spanning every scalar and architecture-selected vector boundary. */
constexpr std::array<std::size_t, 12> TEST_COUNTS{0u,  1u,  3u,	 7u,  15u, 16u,
						  17u, 31u, 32u, 64u, 65u, std::numeric_limits<std::size_t>::max()};

/**
 * @brief Derive one bounded mask from an independent scalar predicate.
 *
 * @tparam predicate_type Callable accepting one lane index.
 * @param count Requested public batch count.
 * @param predicate Independent scalar lane predicate.
 * @return Exact low-bit mask for the first at most 64 lanes.
 */
template <typename predicate_type>
[[nodiscard]] classify_mask_t scalar_mask(std::size_t count, predicate_type predicate)
{
	const uint32_t bounded_count = static_cast<uint32_t>(std::min(count, MAX_BATCH_SIZE));
	classify_mask_t result = 0u;
	for (uint32_t index = 0u; index < bounded_count; ++index) {
		if (predicate(index)) {
			result |= classify_mask_t{1} << index;
		}
	}
	return result;
}

/**
 * @brief Evaluate one SIMD-rule lane through the established scalar ACL law.
 *
 * @param batch Complete packet batch.
 * @param rule Prevalidated rule under test.
 * @param index Lane to inspect.
 * @return True exactly when scalar ACL semantics match the lane.
 */
[[nodiscard]] bool scalar_rule_matches(const packet_batch_soa &batch, const acl_rule_simd &rule,
				       std::size_t index) noexcept
{
	if ((batch.src_ips[index] & rule.src_mask) != (rule.src_network & rule.src_mask) ||
	    (batch.dst_ips[index] & rule.dst_mask) != (rule.dst_network & rule.dst_mask)) {
		return false;
	}
	if (rule.protocol != 0u && batch.protocols[index] != rule.protocol) {
		return false;
	}
	if (batch.protocols[index] == net::protocol::TCP || batch.protocols[index] == net::protocol::UDP) {
		if (batch.src_ports[index] < rule.src_port_min || batch.src_ports[index] > rule.src_port_max ||
		    batch.dst_ports[index] < rule.dst_port_min || batch.dst_ports[index] > rule.dst_port_max) {
			return false;
		}
	}
	return true;
}

/** @brief Prove a zero-count ACL batch touches neither rules nor output storage. */
TEST(simd_classify, zero_count_accepts_null_storage_without_access)
{
	packet_batch_soa batch{};
	classify_batch_acl(batch, nullptr, 1u, nullptr, UINT8_C(7));
	SUCCEED();
}

/** @brief Noncanonical CIDR host bits never change batch matching semantics. */
TEST(simd_classify, cidr_masks_both_operands_at_every_vector_boundary)
{
	std::array<uint32_t, MAX_BATCH_SIZE + 1u> addresses{};
	for (std::size_t index = 0u; index < addresses.size(); ++index) {
		addresses[index] = index % 3u == 0u ? 0x0a000001u + static_cast<uint32_t>(index) :
						      0xc0000201u + static_cast<uint32_t>(index);
	}
	constexpr uint32_t NONCANONICAL_NETWORK = 0x0a010203u;
	constexpr uint32_t MASK = 0xff000000u;
	for (const std::size_t count : TEST_COUNTS) {
		const classify_mask_t expected = scalar_mask(count, [&](std::size_t index) {
			return (addresses[index] & MASK) == (NONCANONICAL_NETWORK & MASK);
		});
		EXPECT_EQ(match_cidr_batch(addresses.data(), count, NONCANONICAL_NETWORK, MASK), expected)
			<< "count=" << count;
	}
}

/** @brief Inclusive uint16 ranges remain exact at both representational endpoints. */
TEST(simd_classify, unsigned_port_ranges_are_exact_without_endpoint_wrap)
{
	std::array<uint16_t, MAX_BATCH_SIZE + 1u> ports{};
	for (std::size_t index = 0u; index < ports.size(); ++index) {
		constexpr std::array<uint16_t, 8> VALUES{0u, 1u, 1023u, 1024u, 32767u, 32768u, 65534u, 65535u};
		ports[index] = VALUES[index % VALUES.size()];
	}
	constexpr std::array<std::array<uint16_t, 2>, 5> RANGES{{
		{0u, 1024u},
		{1024u, UINT16_MAX},
		{0u, UINT16_MAX},
		{32768u, 32768u},
		{UINT16_MAX, UINT16_MAX},
	}};
	for (const auto &range : RANGES) {
		for (const std::size_t count : TEST_COUNTS) {
			const classify_mask_t expected = scalar_mask(count, [&](std::size_t index) {
				return ports[index] >= range[0] && ports[index] <= range[1];
			});
			EXPECT_EQ(match_port_range_batch(ports.data(), count, range[0], range[1]), expected)
				<< "min=" << range[0] << " max=" << range[1] << " count=" << count;
		}
	}
	EXPECT_EQ(match_port_range_batch(ports.data(), ports.size(), 1024u, 1023u), 0u);
}

/** @brief Port ranges constrain TCP and UDP only, matching scalar ACL evaluation. */
TEST(simd_classify, rule_ports_ignore_non_transport_lanes_exactly)
{
	packet_batch_soa batch{};
	batch.count = MAX_BATCH_SIZE;
	for (std::size_t index = 0u; index < batch.count; ++index) {
		batch.src_ips[index] = 0x0a000001u + static_cast<uint32_t>(index);
		batch.dst_ips[index] = 0xc0000201u + static_cast<uint32_t>(index);
		batch.protocols[index] = index % 3u == 0u ? net::protocol::TCP :
					 index % 3u == 1u ? net::protocol::UDP :
							    net::protocol::ICMP;
		batch.src_ports[index] = index % 2u == 0u ? 80u : 5000u;
		batch.dst_ports[index] = index % 5u == 0u ? 443u : 9000u;
	}

	acl_rule_simd rule{};
	rule.src_network = 0x0a010203u;
	rule.src_mask = 0xff000000u;
	rule.dst_network = 0xc00002feu;
	rule.dst_mask = 0xffffff00u;
	rule.src_port_min = 0u;
	rule.src_port_max = 1024u;
	rule.dst_port_min = 443u;
	rule.dst_port_max = UINT16_MAX;
	rule.protocol = 0u;

	const classify_mask_t expected =
		scalar_mask(batch.count, [&](std::size_t index) { return scalar_rule_matches(batch, rule, index); });
	EXPECT_EQ(classify_batch_rule(batch, rule), expected);
}

/** @brief ACL priority composition preserves the independent scalar first-match law. */
TEST(simd_classify, acl_batch_actions_match_scalar_priority_composition)
{
	packet_batch_soa batch{};
	batch.count = MAX_BATCH_SIZE;
	for (std::size_t index = 0u; index < batch.count; ++index) {
		batch.src_ips[index] = index % 2u == 0u ? 0x0a010203u : 0xcb007101u;
		batch.dst_ips[index] = 0xc0000201u;
		batch.protocols[index] = index % 3u == 0u ? net::protocol::ICMP : net::protocol::UDP;
		batch.src_ports[index] = static_cast<uint16_t>(index * 1000u);
		batch.dst_ports[index] = index % 4u == 0u ? 53u : 9000u;
	}

	std::array<acl_rule_simd, 2> rules{};
	rules[0].src_network = 0x0aabcdefu;
	rules[0].src_mask = 0xff000000u;
	rules[0].dst_port_min = 0u;
	rules[0].dst_port_max = 1024u;
	rules[0].action = 7u;
	rules[1].action = 11u;
	constexpr uint8_t DEFAULT_ACTION = 13u;

	std::array<uint8_t, MAX_BATCH_SIZE> actions{};
	classify_batch_acl(batch, rules.data(), rules.size(), actions.data(), DEFAULT_ACTION);
	for (std::size_t index = 0u; index < batch.count; ++index) {
		uint8_t expected = DEFAULT_ACTION;
		for (const auto &rule : rules) {
			if (scalar_rule_matches(batch, rule, index)) {
				expected = rule.action;
				break;
			}
		}
		EXPECT_EQ(actions[index], expected) << "lane=" << index;
	}
}

}  // namespace
}  // namespace kinetum::algo
