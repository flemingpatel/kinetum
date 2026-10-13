// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file guardrails_evaluation_contract.hpp
 * @brief Shared cold validation of read-only guardrails evaluation evidence.
 * @author Fleming Patel
 *
 * The producer and operator client use the same intrinsic checks. Durable
 * policy/content fencing remains with CP; these functions authorize no action.
 */

#include <cstdint>

#include "gen/kinetum/control/v1/control.pb.h"
#include "src/common/status.hpp"

namespace kinetum::common
{

/**
 * @brief Validate one bounded evaluator projection beside its admitted policy.
 * @param value Complete observation, including any retained attribution proof.
 * @param policy Admitted durable policy, or null for an unconfigured owner.
 * @param generation Exact enclosing durable policy generation.
 * @return OK for exact intrinsic evidence, otherwise typed rejection.
 *
 * Stateless and thread-safe for immutable inputs. All work is cold and linear
 * in the worker population; no history or live bank is borrowed.
 */
[[nodiscard]] status validate_guardrails_evaluation(const kinetum::control::v1::GuardrailsEvaluation &value,
						    const kinetum::control::v1::GuardrailsPolicy *policy,
						    uint64_t generation);

}  // namespace kinetum::common
