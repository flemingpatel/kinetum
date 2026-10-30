// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file memory_mapping_test_support.hpp
 * @brief Independent Linux VMA evidence for live allocation ranges.
 * @author Fleming Patel
 *
 * Advice flags and PMD backing are separate observations. A containing VMA
 * may span several allocations; its backing count is not an allocation count.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace kinetum::test
{

/** @brief One kernel-reported VMA intersecting the inspected allocation. */
struct memory_mapping_observation {
	std::uintptr_t begin{0u};      ///< Inclusive VMA start, possibly before the allocation.
	std::uintptr_t end{0u};	       ///< Exclusive VMA end, possibly after the allocation.
	std::size_t anon_huge_kb{0u};  ///< PMD backing for this whole VMA, not smaller THPs.
	bool hugepage_advice{false};   ///< Kernel hg flag, independent of actual backing.
	bool flags_observed{false};    ///< VmFlags was read rather than inferred absent.
	bool backing_observed{false};  ///< AnonHugePages was read rather than inferred zero.
};

/**
 * @brief Read every VMA covering one live range without inferring flags from its owner.
 * @param data First usable byte of the live allocation.
 * @param size Positive usable extent that remains alive throughout inspection.
 * @param[out] observations Complete covering VMAs, replaced only on success.
 * @return Success after contiguous coverage and both kernel fields are observed.
 */
[[nodiscard]] inline ::testing::AssertionResult
observe_memory_mapping(const void *data, std::size_t size, std::vector<memory_mapping_observation> &observations)
{
	const auto begin = reinterpret_cast<std::uintptr_t>(data);
	if (data == nullptr || size == 0u || size > std::numeric_limits<std::uintptr_t>::max() - begin) {
		return ::testing::AssertionFailure() << "mapping evidence requires a live representable extent";
	}
	const auto end = begin + size;
	std::ifstream input("/proc/self/smaps");
	if (!input.is_open()) {
		return ::testing::AssertionFailure() << "native mapping evidence unavailable: cannot open smaps";
	}
	std::vector<memory_mapping_observation> candidate;
	std::optional<std::size_t> current;
	std::string line;
	while (std::getline(input, line)) {
		std::uintptr_t vma_begin = 0u;
		std::uintptr_t vma_end = 0u;
		const auto dash = line.find('-');
		const auto separator = line.find(' ');
		if (dash != std::string::npos && separator != std::string::npos && dash < separator) {
			const auto first = std::from_chars(line.data(), line.data() + dash, vma_begin, 16);
			const auto last =
				std::from_chars(line.data() + dash + 1u, line.data() + separator, vma_end, 16);
			if (first.ec != std::errc{} || first.ptr != line.data() + dash || last.ec != std::errc{} ||
			    last.ptr != line.data() + separator || vma_begin >= vma_end) {
				return ::testing::AssertionFailure() << "smaps contains an invalid VMA extent";
			}
			current.reset();
			if (vma_begin < end && vma_end > begin) {
				current = candidate.size();
				candidate.push_back({vma_begin, vma_end});
			}
		} else if (current.has_value()) {
			auto &entry = candidate[*current];
			if (line.starts_with("VmFlags:")) {
				std::istringstream fields(line.substr(8u));
				std::string flag;
				while (fields >> flag) {
					entry.hugepage_advice = entry.hugepage_advice || flag == "hg";
				}
				entry.flags_observed = true;
			} else if (line.starts_with("AnonHugePages:")) {
				std::istringstream fields(line.substr(14u));
				std::string unit;
				if (!(fields >> entry.anon_huge_kb >> unit) || unit != "kB") {
					return ::testing::AssertionFailure() << "smaps contains malformed PMD backing";
				}
				entry.backing_observed = true;
			}
		}
	}
	if (input.bad()) {
		return ::testing::AssertionFailure() << "native mapping evidence unavailable: smaps read failed";
	}
	auto cursor = begin;
	for (const auto &entry : candidate) {
		if (entry.begin > cursor || entry.end <= cursor || !entry.flags_observed || !entry.backing_observed) {
			return ::testing::AssertionFailure() << "smaps does not completely describe the live range";
		}
		cursor = std::min(end, entry.end);
	}
	if (cursor != end) {
		return ::testing::AssertionFailure() << "live allocation is not fully covered by smaps";
	}
	observations = std::move(candidate);
	return ::testing::AssertionSuccess();
}

/**
 * @brief Compare accepted huge-page advice over the complete live range.
 * @param data First usable byte whose allocation remains owned.
 * @param size Exact usable extent.
 * @param expected Required hg value for every covering VMA.
 * @return Success only when native evidence matches throughout the range.
 */
[[nodiscard]] inline ::testing::AssertionResult has_hugepage_advice(const void *data, std::size_t size, bool expected)
{
	std::vector<memory_mapping_observation> observations;
	const auto observed = observe_memory_mapping(data, size, observations);
	if (!observed) {
		return observed;
	}
	for (const auto &entry : observations) {
		if (entry.hugepage_advice != expected) {
			return ::testing::AssertionFailure()
			       << "VMA [" << entry.begin << ", " << entry.end << ") hg=" << entry.hugepage_advice
			       << ", expected " << expected;
		}
	}
	return ::testing::AssertionSuccess();
}

}  // namespace kinetum::test
