// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file logging_status.hpp
 * @brief Cold RPC projection and strict admission of diagnostic delivery evidence.
 * @author Fleming Patel
 */

#include "gen/kinetum/common/v1/common.pb.h"
#include "src/common/status.hpp"

namespace kinetum::common
{

/**
 * @brief Write one process logging observation with explicit counter presence.
 * @param output Cleared and completely replaced on success.
 * @note Allocates protobuf storage on the cold RPC caller only.
 */
void project_process_logging_status(kinetum::common::v1::LoggingStatus &output);

/**
 * @brief Admit a complete logging observation without using it as readiness policy.
 * @param input Candidate received observation; default/missing fields reject.
 * @return OK for available, unavailable, or closed truth; DATA_LOSS for malformed evidence.
 */
[[nodiscard]] status validate_logging_status(const kinetum::common::v1::LoggingStatus &input);

}  // namespace kinetum::common
