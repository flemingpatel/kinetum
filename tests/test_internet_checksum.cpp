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
#include <vector>

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

/**
 * @brief Sum network bytes independently, padding an odd final byte in the high position.
 * @param bytes Complete readable byte extent.
 * @return Full one's-complement checksum in host integer representation.
 */
uint16_t reference_byte_checksum(std::span<const uint8_t> bytes) noexcept
{
	uint64_t sum = 0;
	for (std::size_t index = 0; index < bytes.size(); ++index) {
		sum += static_cast<uint64_t>(bytes[index]) << (index % 2u == 0u ? 8u : 0u);
	}
	while (sum > UINT16_MAX) {
		sum = (sum & UINT16_MAX) + (sum >> 16u);
	}
	return static_cast<uint16_t>(~sum);
}

/** @brief Full checksums match the byte oracle at every small extent, alignment and maximum carry boundary. */
TEST(internet_checksum, full_sum_matches_byte_oracle_for_unaligned_and_odd_extents)
{
	using kinetum::algo::net::internet_checksum;
	EXPECT_EQ(internet_checksum(nullptr, 0u), UINT16_MAX);
	std::vector<uint8_t> bytes(UINT16_MAX + 16u);
	for (const bool all_ones : {false, true}) {
		for (std::size_t index = 0; index < bytes.size(); ++index) {
			bytes[index] = all_ones ? 0xffu : static_cast<uint8_t>((index * 251u + 17u) & 0xffu);
		}
		for (std::size_t offset = 0; offset < 16u; ++offset) {
			for (uint16_t length = 0; length <= 257u; ++length) {
				EXPECT_EQ(internet_checksum(bytes.data() + offset, length),
					  reference_byte_checksum({bytes.data() + offset, length}));
			}
			for (const uint16_t length : {uint16_t{65534}, uint16_t{65535}}) {
				EXPECT_EQ(internet_checksum(bytes.data() + offset, length),
					  reference_byte_checksum({bytes.data() + offset, length}));
			}
		}
	}
}

/** @brief Full recomputation sees byte mutations and a written checksum verifies to zero. */
TEST(internet_checksum, full_sum_observes_mutation_and_verifies_network_representation)
{
	std::array<uint8_t, 20> header{0x45u, 0x03u, 0u, 20u, 0u, 1u, 0u, 0u, 64u, 17u};
	const auto first = kinetum::algo::net::internet_checksum(header.data(), header.size());
	header[1] = 0xbbu;
	const auto second = kinetum::algo::net::internet_checksum(header.data(), header.size());
	EXPECT_NE(first, second);
	kinetum::algo::net::write_be16(header.data() + 10u, second);
	EXPECT_EQ(reference_byte_checksum(header), 0u);
	EXPECT_EQ(kinetum::algo::net::internet_checksum(header.data(), header.size()), 0u);
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
