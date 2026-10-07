// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file transition_idempotency_key.hpp
 * @brief Fail-closed random identity generation for operator transitions.
 * @author Fleming Patel
 *
 * Producers that originate a mutation generate one 256-bit random identity
 * before their first transport attempt and retain the resulting printable key
 * for every retry of that semantic command. The mechanism has no clock, PID,
 * hostname, weak-random, or deterministic fallback.
 *
 * @par Thread Safety
 * Stateless apart from OpenSSL's process-wide cryptographic provider, whose
 * RAND_bytes entry point is thread-safe.
 *
 * @par Performance
 * Cold command-authoring work. This API is never reachable from packet workers.
 */

#include <string>
#include <string_view>

#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Generate one bounded printable transition idempotency key.
 * @param producer_prefix Stable lowercase producer domain using `[a-z0-9._-]`
 *        and containing 1..64 bytes.
 * @return `<prefix>-<64 lowercase hex digits>`, or exact prefix, OpenSSL, or
 *         allocation failure.
 */
[[nodiscard]] status_or<std::string> generate_transition_idempotency_key(std::string_view producer_prefix);

}  // namespace kinetum::common
