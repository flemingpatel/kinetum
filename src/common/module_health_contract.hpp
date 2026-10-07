// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_health_contract.hpp
 * @brief Shared typed module-health contract-fault vocabulary.
 * @author Fleming Patel
 *
 * Owner-worker validation produces these bits, lifecycle publication preserves
 * them, and the final wire validator admits only their exact union. The values
 * are internal platform evidence and do not change the public module ABI.
 *
 * @par Thread Safety
 * Immutable value declarations with no mutable state.
 *
 * @par Performance
 * Compile-time vocabulary only; it adds no runtime operation.
 */

#include <cstdint>

namespace kinetum::common
{

/** @brief Typed owner-worker health contract-fault bits. */
enum class module_health_contract_fault : uint16_t {
	NONE = 0u,			      ///< Valid callback result within its budget.
	SCORE_OUT_OF_RANGE = 1u,	      ///< Health score exceeded 100.
	UNKNOWN_FLAGS = 1u << 1u,	      ///< Assessment carried an unknown flag bit.
	UNTERMINATED_REASON = 1u << 2u,	      ///< Reason lacked a bounded terminating NUL.
	CALLBACK_BUDGET_EXCEEDED = 1u << 3u,  ///< Callback duration exceeded compiled policy.
};

/** @brief Complete admitted module-health contract-fault mask. */
inline constexpr uint16_t MODULE_HEALTH_CONTRACT_FAULT_KNOWN_MASK =
	static_cast<uint16_t>(static_cast<uint16_t>(module_health_contract_fault::SCORE_OUT_OF_RANGE) |
			      static_cast<uint16_t>(module_health_contract_fault::UNKNOWN_FLAGS) |
			      static_cast<uint16_t>(module_health_contract_fault::UNTERMINATED_REASON) |
			      static_cast<uint16_t>(module_health_contract_fault::CALLBACK_BUDGET_EXCEEDED));

}  // namespace kinetum::common
