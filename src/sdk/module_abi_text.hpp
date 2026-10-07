// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_abi_text.hpp
 * @brief Shared validation for text crossing the exact module C ABI.
 * @author Fleming Patel
 *
 * Module descriptors expose NUL-terminated strings while generation and
 * lifecycle ownership use length-bearing C++ strings. Both representations
 * must enforce one contract or an embedded NUL could admit one identity and
 * expose a different identity to foreign module code.
 */

#include <cstddef>
#include <string_view>

#include <kinetum/kinetum_sdk.h>

namespace kinetum::sdk
{

/**
 * @brief Validate one length-bearing string crossing the module ABI.
 *
 * @param value Candidate bytes without an implicit terminator.
 * @return true for 1..255 printable-ASCII bytes.
 */
[[nodiscard]] constexpr bool valid_module_abi_text(std::string_view value) noexcept
{
	if (value.empty() || value.size() >= KINETUM_MODULE_ABI_TEXT_CAPACITY) {
		return false;
	}
	for (const char character : value) {
		const auto byte = static_cast<unsigned char>(character);
		if (byte < 0x20u || byte > 0x7eu) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Validate one NUL-terminated string crossing the module ABI.
 *
 * @param value Candidate C string.
 * @return true for 1..255 printable-ASCII bytes followed by NUL.
 */
[[nodiscard]] constexpr bool valid_module_abi_text(const char *value) noexcept
{
	if (value == nullptr) {
		return false;
	}
	for (std::size_t index = 0; index < KINETUM_MODULE_ABI_TEXT_CAPACITY; ++index) {
		const auto byte = static_cast<unsigned char>(value[index]);
		if (byte == 0u) {
			return index != 0;
		}
		if (byte < 0x20u || byte > 0x7eu) {
			return false;
		}
	}
	return false;
}

}  // namespace kinetum::sdk
