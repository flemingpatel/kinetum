// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file publication_read_result.hpp
 * @brief Availability and validation outcomes for cold domain-publication readers.
 * @author Fleming Patel
 *
 * Coherence failure carries no domain evidence. A coherent invalid publication
 * retains its identity/state classification and dominates unavailable inputs.
 * These observer-owned values neither publish nor retain worker state.
 */

#include <cstdint>
#include <exception>

namespace kinetum::dp
{

/** @brief Exact read outcome; the two invalid cases refine one terminal disposition. */
enum class publication_read_result : uint8_t {
	UNAVAILABLE = 0,   ///< No usable publication was obtained; caller output is unchanged.
	AVAILABLE,	   ///< One coherent and valid value was copied to the caller.
	INVALID_STATE,	   ///< Coherent fields violate the publication's state contract.
	INVALID_IDENTITY,  ///< Coherent fields name a foreign generation or participant.
};

/**
 * @brief Combine independent reads without allowing unavailability to hide invalidity.
 * @param left First bounded read result.
 * @param right Second bounded read result.
 * @return Order-independent result, with identity invalidity preceding state invalidity.
 */
[[nodiscard]] constexpr publication_read_result combine_publication_reads(publication_read_result left,
									  publication_read_result right) noexcept
{
	if (static_cast<uint8_t>(left) > static_cast<uint8_t>(publication_read_result::INVALID_IDENTITY) ||
	    static_cast<uint8_t>(right) > static_cast<uint8_t>(publication_read_result::INVALID_IDENTITY)) {
		std::terminate();
	}
	if (left == publication_read_result::INVALID_IDENTITY || right == publication_read_result::INVALID_IDENTITY) {
		return publication_read_result::INVALID_IDENTITY;
	}
	if (left == publication_read_result::INVALID_STATE || right == publication_read_result::INVALID_STATE) {
		return publication_read_result::INVALID_STATE;
	}
	if (left == publication_read_result::UNAVAILABLE || right == publication_read_result::UNAVAILABLE) {
		return publication_read_result::UNAVAILABLE;
	}
	return publication_read_result::AVAILABLE;
}

}  // namespace kinetum::dp
