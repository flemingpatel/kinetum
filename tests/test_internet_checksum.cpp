// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_internet_checksum.cpp
 * @brief Independent arithmetic and mutable-byte tests for network checksum updates.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>

#include <kinetum/algo/net.hpp>

namespace
{

/**
 * @brief Recompute a complete checksum independently of the incremental helper.
 * @param words Complete network words in host-order integer representation.
 * @return Full one's-complement checksum.
 */
uint16_t reference_checksum(std::span<const uint16_t> words) noexcept
{
	uint64_t sum = 0u;
	for (const uint16_t word : words) {
		sum += word;
	}
	while (sum > UINT16_MAX) {
		sum = (sum & UINT16_MAX) + (sum >> 16u);
	}
	return static_cast<uint16_t>(~sum);
}

/** @brief Pin the positive-zero result that an incorrect incremental formula turns into negative zero. */
TEST(internet_checksum, positive_zero_boundary_matches_full_recomputation)
{
	EXPECT_EQ(kinetum::algo::net::update_internet_checksum(0xdd2f, 0x5555, 0x3285), 0u);
}

/** @brief Every old 16-bit word agrees with a full oracle across replacement carry boundaries. */
TEST(internet_checksum, replacement_matches_independent_complete_sum)
{
	constexpr std::array<uint16_t, 6> REPLACEMENTS{0u, 1u, 0x3285u, 0x8000u, 0xfffeu, 0xffffu};
	std::array<uint16_t, 4> words{0x4500u, 0x0011u, 0xcd7au, 0u};
	for (uint32_t previous = 0u; previous <= UINT16_MAX; ++previous) {
		words.back() = static_cast<uint16_t>(previous);
		const uint16_t before = reference_checksum(words);
		for (const uint16_t replacement : REPLACEMENTS) {
			words.back() = replacement;
			ASSERT_EQ(kinetum::algo::net::update_internet_checksum(before, static_cast<uint16_t>(previous),
									       replacement),
				  reference_checksum(words))
				<< "old word=" << previous << " replacement=" << replacement;
		}
	}
}

/** @brief Replacing both address words and one port matches complete transport-header arithmetic. */
TEST(internet_checksum, endpoint_update_composes_without_payload_access)
{
	std::array<uint16_t, 8> words{0x0011u, 0x0017u, 0x0a00u, 0x0001u, 12345u, 0x0808u, 0x0808u, 9999u};
	uint16_t checksum = reference_checksum(words);
	constexpr std::array<uint16_t, 3> REPLACEMENTS{0xc000u, 0x0201u, 10000u};
	for (std::size_t index = 0u; index < REPLACEMENTS.size(); ++index) {
		const std::size_t offset = index + 2u;
		checksum = kinetum::algo::net::update_internet_checksum(checksum, words[offset], REPLACEMENTS[index]);
		words[offset] = REPLACEMENTS[index];
	}
	EXPECT_EQ(checksum, reference_checksum(words));
}

/** @brief Byte readers observe intervening mutations rather than advertising memory-independent results. */
TEST(internet_checksum, network_reads_observe_intervening_writes)
{
	std::array<uint8_t, 8> bytes{};
	const uint16_t first16 = kinetum::algo::net::read_be16(bytes.data());
	kinetum::algo::net::write_be16(bytes.data(), 0xabcd);
	EXPECT_NE(first16, kinetum::algo::net::read_be16(bytes.data()));
	EXPECT_EQ(kinetum::algo::net::read_be16(bytes.data()), 0xabcdu);
	const uint32_t first32 = kinetum::algo::net::read_be32(bytes.data());
	kinetum::algo::net::write_be32(bytes.data(), 0x12345678);
	EXPECT_NE(first32, kinetum::algo::net::read_be32(bytes.data()));
	EXPECT_EQ(kinetum::algo::net::read_be32(bytes.data()), 0x12345678u);
	const uint64_t first64 = kinetum::algo::net::read_be64(bytes.data());
	kinetum::algo::net::write_be64(bytes.data(), UINT64_C(0x0123456789abcdef));
	EXPECT_NE(first64, kinetum::algo::net::read_be64(bytes.data()));
	EXPECT_EQ(kinetum::algo::net::read_be64(bytes.data()), UINT64_C(0x0123456789abcdef));
}

}  // namespace
