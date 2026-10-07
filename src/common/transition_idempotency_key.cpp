// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file transition_idempotency_key.cpp
 * @brief Cryptographic transition-idempotency key implementation.
 * @author Fleming Patel
 */

#include "src/common/transition_idempotency_key.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <new>

#include <openssl/rand.h>

#include "src/common/epoch_transition_contract.hpp"

namespace kinetum::common
{

status_or<std::string> generate_transition_idempotency_key(std::string_view producer_prefix)
{
	constexpr std::size_t RANDOM_BYTES = 32u;
	constexpr char HEX[] = "0123456789abcdef";
	if (producer_prefix.empty() || producer_prefix.size() > 64u ||
	    !std::all_of(producer_prefix.begin(), producer_prefix.end(), [](char character) {
		    const auto value = static_cast<unsigned char>(character);
		    return (value >= static_cast<unsigned char>('a') && value <= static_cast<unsigned char>('z')) ||
			   (value >= static_cast<unsigned char>('0') && value <= static_cast<unsigned char>('9')) ||
			   character == '.' || character == '_' || character == '-';
	    })) {
		return status::invalid_argument(
			"transition idempotency producer prefix must be 1..64 lowercase domain bytes");
	}
	std::array<uint8_t, RANDOM_BYTES> random{};
	if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
		return status::internal_error("OpenSSL failed to generate transition idempotency entropy");
	}
	try {
		std::string result;
		result.reserve(producer_prefix.size() + 1u + random.size() * 2u);
		result.append(producer_prefix);
		result.push_back('-');
		for (const uint8_t byte : random) {
			result.push_back(HEX[byte >> 4u]);
			result.push_back(HEX[byte & UINT8_C(0x0f)]);
		}
		const auto admitted = validate_transition_idempotency_key(result);
		if (!admitted.is_ok()) {
			return status::internal_error(
				"generated transition idempotency key violated its shared grammar");
		}
		return result;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("transition idempotency key allocation failed");
	}
}

}  // namespace kinetum::common
