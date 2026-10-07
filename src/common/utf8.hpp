// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file utf8.hpp
 * @brief Shared source-private UTF-8 admission for wire text and JSON output.
 * @author Fleming Patel
 *
 * This predicate validates encoding without allocating, repairing bytes, or
 * consulting locale. Callers own input lifetime and the field's byte bound.
 */

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace kinetum::common
{

/**
 * @brief Validate UTF-8 without replacement decoding or normalization.
 * @param value Borrowed complete byte sequence.
 * @return True only for shortest-form Unicode scalar encodings, including empty input.
 * @details Work is linear in bytes and uses constant space. No shared mutable state exists.
 */
[[nodiscard]] inline bool valid_utf8(std::string_view value) noexcept
{
	const auto *bytes = reinterpret_cast<const uint8_t *>(value.data());
	std::size_t index = 0u;
	while (index < value.size()) {
		const uint8_t first = bytes[index++];
		if (first <= 0x7fu) {
			continue;
		}
		std::size_t continuation_count = 0u;
		uint8_t second_minimum = 0x80u;
		uint8_t second_maximum = 0xbfu;
		if (first >= 0xc2u && first <= 0xdfu) {
			continuation_count = 1u;
		} else if (first >= 0xe0u && first <= 0xefu) {
			continuation_count = 2u;
			second_minimum = first == 0xe0u ? 0xa0u : 0x80u;
			second_maximum = first == 0xedu ? 0x9fu : 0xbfu;
		} else if (first >= 0xf0u && first <= 0xf4u) {
			continuation_count = 3u;
			second_minimum = first == 0xf0u ? 0x90u : 0x80u;
			second_maximum = first == 0xf4u ? 0x8fu : 0xbfu;
		} else {
			return false;
		}
		if (continuation_count > value.size() - index || bytes[index] < second_minimum ||
		    bytes[index] > second_maximum) {
			return false;
		}
		++index;
		for (std::size_t remaining = 1u; remaining < continuation_count; ++remaining, ++index) {
			if ((bytes[index] & 0xc0u) != 0x80u) {
				return false;
			}
		}
	}
	return true;
}

}  // namespace kinetum::common
