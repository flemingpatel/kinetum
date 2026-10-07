// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_sdk_c_mechanisms.cpp
 * @brief Independent semantic proofs for image-local C SDK mechanisms.
 * @author Fleming Patel
 *
 * SIMD expectations come from plain scalar predicates in this test, never
 * from another SDK implementation path. The same oracle therefore verifies
 * AVX2, baseline x86, AArch64 NEON, and scalar builds on their owning hosts.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

#include <kinetum/kinetum_sdk.h>

namespace
{

/** Lane counts spanning empty, vector-width, mask-width, and out-of-range boundaries. */
constexpr std::array<uint16_t, 14> EDGE_COUNTS{0u, 1u, 7u, 8u, 9u, 15u, 16u, 17u, 31u, 32u, 33u, 63u, 64u, 65u};

/**
 * @brief Build unsigned-byte values spanning every comparison boundary.
 *
 * @return Fixed 65-lane input including one deliberately unrepresentable tail.
 */
[[nodiscard]] constexpr std::array<uint8_t, 65> make_u8_values() noexcept
{
	constexpr std::array<uint8_t, 10> pattern{0u, 1u, 2u, 63u, 64u, 127u, 128u, 254u, 255u, 42u};
	std::array<uint8_t, 65> values{};
	for (std::size_t index = 0; index < values.size(); ++index) {
		values[index] = pattern[index % pattern.size()];
	}
	return values;
}

/**
 * @brief Build unsigned-word values spanning signed and unsigned boundaries.
 *
 * @return Fixed 65-lane input including one deliberately unrepresentable tail.
 */
[[nodiscard]] constexpr std::array<uint16_t, 65> make_u16_values() noexcept
{
	constexpr std::array<uint16_t, 12> pattern{0u,	 1u,	 22u,	 442u,	 443u,	 444u,
						   445u, 32767u, 32768u, 65534u, 65535u, 12345u};
	std::array<uint16_t, 65> values{};
	for (std::size_t index = 0; index < values.size(); ++index) {
		values[index] = pattern[index % pattern.size()];
	}
	return values;
}

/** Fixed unsigned-byte comparison corpus. */
constexpr auto U8_VALUES = make_u8_values();
/** Fixed unsigned-word comparison corpus. */
constexpr auto U16_VALUES = make_u16_values();

/**
 * @brief Evaluate one array comparison with an implementation-independent loop.
 *
 * @tparam value_type Unsigned lane type.
 * @tparam predicate_type Scalar relation to evaluate.
 * @param values Input array or null.
 * @param count Requested lane count; only the first 64 lanes are representable.
 * @param predicate Scalar relation.
 * @return Exact low-64-bit predicate mask.
 */
template <typename value_type, typename predicate_type>
[[nodiscard]] uint64_t scalar_mask(const value_type *values, uint16_t count, predicate_type predicate) noexcept
{
	if (values == nullptr || count == 0u) {
		return 0;
	}
	const uint16_t bounded_count = std::min<uint16_t>(count, 64u);
	uint64_t mask = 0;
	for (uint16_t index = 0; index < bounded_count; ++index) {
		if (predicate(values[index])) {
			mask |= UINT64_C(1) << index;
		}
	}
	return mask;
}

/**
 * @brief Resolve one inclusive percentile from an ordered scalar sample set.
 *
 * @param samples Ascending exact scalar samples.
 * @param per_mille Percentile in the inclusive range 1..1000.
 * @return Sample at the one-based inclusive rank, or zero when empty.
 */
[[nodiscard]] uint64_t scalar_percentile(const std::vector<uint64_t> &samples, uint32_t per_mille)
{
	if (samples.empty()) {
		return 0;
	}
	const uint64_t count = samples.size();
	const uint64_t rank = (count * per_mille + 999u) / 1000u;
	return samples[static_cast<std::size_t>(rank - 1u)];
}

/** @brief Verify fixed SDK diagnostics require no runtime implementation. */
TEST(sdk_c_mechanisms, strerror_matches_independent_error_table)
{
	struct error_case {
		kinetum_error error;	///< Exact input error value.
		std::string_view text;	///< Expected immutable diagnostic.
	};
	constexpr std::array<error_case, 13> cases{{
		{KINETUM_OK, "Success"},
		{KINETUM_ERR_INVALID_ARG, "Invalid argument"},
		{KINETUM_ERR_NO_MEMORY, "Memory allocation failed"},
		{KINETUM_ERR_NOT_FOUND, "Resource not found"},
		{KINETUM_ERR_ALREADY_EXISTS, "Resource already exists"},
		{KINETUM_ERR_LIMIT_EXCEEDED, "Limit exceeded"},
		{KINETUM_ERR_NOT_SUPPORTED, "Operation not supported"},
		{KINETUM_ERR_BUSY, "Resource busy"},
		{KINETUM_ERR_TIMEOUT, "Operation timed out"},
		{KINETUM_ERR_CONFIG_INVALID, "Invalid configuration"},
		{KINETUM_ERR_CANCELLED, "Operation cancelled"},
		{KINETUM_ERR_INTERNAL, "Internal error"},
		{1234, "Unknown error"},
	}};
	for (const auto &entry : cases) {
		EXPECT_EQ(std::string_view(kinetum_strerror(entry.error)), entry.text);
	}
}

/** @brief Verify percentile extraction against an expanded scalar sample set. */
TEST(sdk_c_mechanisms, histogram_percentiles_match_scalar_order_statistics)
{
	std::array<uint64_t, 6> counts{1u, 2u, 3u, 4u, 5u, 6u};
	constexpr std::array<uint64_t, 6> represented_values{0u, 1u, 2u, 4u, 8u, 16u};
	std::vector<uint64_t> samples;
	uint64_t sum = 0;
	for (std::size_t index = 0; index < counts.size(); ++index) {
		for (uint64_t occurrence = 0; occurrence < counts[index]; ++occurrence) {
			samples.push_back(represented_values[index]);
			sum += represented_values[index];
		}
	}

	kinetum_histogram histogram{};
	histogram.highest_trackable_value = represented_values.back();
	histogram.total_count = samples.size();
	histogram.min_value = samples.front();
	histogram.max_value = samples.back();
	histogram.sum = sum;
	histogram.counts = counts.data();
	histogram.counts_len = static_cast<uint32_t>(counts.size());
	histogram.unit_magnitude = 0;
	histogram.sub_bucket_half_count = 1;

	kinetum_percentiles actual{};
	kinetum_histogram_percentiles(&histogram, &actual);
	EXPECT_EQ(actual.p50, scalar_percentile(samples, 500u));
	EXPECT_EQ(actual.p90, scalar_percentile(samples, 900u));
	EXPECT_EQ(actual.p99, scalar_percentile(samples, 990u));
	EXPECT_EQ(actual.p999, scalar_percentile(samples, 999u));
	EXPECT_EQ(actual.max, samples.back());
	EXPECT_EQ(actual.min, samples.front());
	EXPECT_EQ(actual.count, samples.size());
	EXPECT_EQ(actual.sum, sum);

	kinetum_histogram empty{};
	actual = kinetum_percentiles{1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u};
	kinetum_histogram_percentiles(&empty, &actual);
	EXPECT_EQ(actual.p50, 0u);
	EXPECT_EQ(actual.p90, 0u);
	EXPECT_EQ(actual.p99, 0u);
	EXPECT_EQ(actual.p999, 0u);
	EXPECT_EQ(actual.max, 0u);
	EXPECT_EQ(actual.min, 0u);
	EXPECT_EQ(actual.count, 0u);
	EXPECT_EQ(actual.sum, 0u);
}

/** @brief Verify unsigned-byte greater-or-equal semantics on every build path. */
TEST(sdk_c_mechanisms, u8_ge_matches_scalar_reference)
{
	constexpr std::array<uint8_t, 6> thresholds{0u, 1u, 127u, 128u, 254u, 255u};
	EXPECT_EQ(kinetum_simd_cmp_u8_ge(nullptr, 64u, 0u), 0u);
	for (const uint16_t count : EDGE_COUNTS) {
		for (const uint8_t threshold : thresholds) {
			const uint64_t expected = scalar_mask(U8_VALUES.data(), count, [threshold](uint8_t value) {
				return value >= threshold;
			});
			EXPECT_EQ(kinetum_simd_cmp_u8_ge(U8_VALUES.data(), count, threshold), expected)
				<< "count=" << count << " threshold=" << static_cast<uint32_t>(threshold);
		}
	}
}

/** @brief Verify unsigned-byte greater-than semantics on every build path. */
TEST(sdk_c_mechanisms, u8_gt_matches_scalar_reference)
{
	constexpr std::array<uint8_t, 6> thresholds{0u, 1u, 127u, 128u, 254u, 255u};
	EXPECT_EQ(kinetum_simd_cmp_u8_gt(nullptr, 64u, 0u), 0u);
	for (const uint16_t count : EDGE_COUNTS) {
		for (const uint8_t threshold : thresholds) {
			const uint64_t expected = scalar_mask(U8_VALUES.data(), count,
							      [threshold](uint8_t value) { return value > threshold; });
			EXPECT_EQ(kinetum_simd_cmp_u8_gt(U8_VALUES.data(), count, threshold), expected)
				<< "count=" << count << " threshold=" << static_cast<uint32_t>(threshold);
		}
	}
}

/** @brief Verify unsigned-byte less-than semantics on every build path. */
TEST(sdk_c_mechanisms, u8_lt_matches_scalar_reference)
{
	constexpr std::array<uint8_t, 6> thresholds{0u, 1u, 127u, 128u, 254u, 255u};
	EXPECT_EQ(kinetum_simd_cmp_u8_lt(nullptr, 64u, 0u), 0u);
	for (const uint16_t count : EDGE_COUNTS) {
		for (const uint8_t threshold : thresholds) {
			const uint64_t expected = scalar_mask(U8_VALUES.data(), count,
							      [threshold](uint8_t value) { return value < threshold; });
			EXPECT_EQ(kinetum_simd_cmp_u8_lt(U8_VALUES.data(), count, threshold), expected)
				<< "count=" << count << " threshold=" << static_cast<uint32_t>(threshold);
		}
	}
}

/** @brief Verify unsigned-byte equality semantics on every build path. */
TEST(sdk_c_mechanisms, u8_eq_matches_scalar_reference)
{
	constexpr std::array<uint8_t, 6> targets{0u, 1u, 64u, 128u, 254u, 255u};
	EXPECT_EQ(kinetum_simd_cmp_u8_eq(nullptr, 64u, 0u), 0u);
	for (const uint16_t count : EDGE_COUNTS) {
		for (const uint8_t target : targets) {
			const uint64_t expected = scalar_mask(U8_VALUES.data(), count,
							      [target](uint8_t value) { return value == target; });
			EXPECT_EQ(kinetum_simd_cmp_u8_eq(U8_VALUES.data(), count, target), expected)
				<< "count=" << count << " target=" << static_cast<uint32_t>(target);
		}
	}
}

/** @brief Verify unsigned-word equality semantics on every build path. */
TEST(sdk_c_mechanisms, u16_eq_matches_scalar_reference)
{
	constexpr std::array<uint16_t, 8> targets{0u, 1u, 22u, 443u, 32767u, 32768u, 65534u, 65535u};
	EXPECT_EQ(kinetum_simd_cmp_u16_eq(nullptr, 64u, 0u), 0u);
	for (const uint16_t count : EDGE_COUNTS) {
		for (const uint16_t target : targets) {
			const uint64_t expected = scalar_mask(U16_VALUES.data(), count,
							      [target](uint16_t value) { return value == target; });
			EXPECT_EQ(kinetum_simd_cmp_u16_eq(U16_VALUES.data(), count, target), expected)
				<< "count=" << count << " target=" << target;
		}
	}
}

/** @brief Verify inclusive unsigned-word range semantics on every build path. */
TEST(sdk_c_mechanisms, u16_range_matches_scalar_reference)
{
	struct range {
		uint16_t lo;  ///< Inclusive lower bound.
		uint16_t hi;  ///< Inclusive upper bound.
	};
	constexpr std::array<range, 8> ranges{{
		{0u, 0u},
		{0u, 65535u},
		{1u, 22u},
		{443u, 444u},
		{32767u, 32768u},
		{65534u, 65535u},
		{12345u, 12345u},
		{444u, 443u},
	}};
	EXPECT_EQ(kinetum_simd_cmp_u16_range(nullptr, 64u, 0u, 65535u), 0u);
	for (const uint16_t count : EDGE_COUNTS) {
		for (const auto candidate : ranges) {
			const uint64_t expected = scalar_mask(U16_VALUES.data(), count, [candidate](uint16_t value) {
				return candidate.lo <= candidate.hi && value >= candidate.lo && value <= candidate.hi;
			});
			EXPECT_EQ(kinetum_simd_cmp_u16_range(U16_VALUES.data(), count, candidate.lo, candidate.hi),
				  expected)
				<< "count=" << count << " lo=" << candidate.lo << " hi=" << candidate.hi;
		}
	}
}

}  // namespace
