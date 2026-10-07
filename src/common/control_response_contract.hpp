// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file control_response_contract.hpp
 * @brief Exact shared admission for Control Plane RPC response envelopes.
 * @author Fleming Patel
 *
 * Every in-tree ControlService client uses this contract before interpreting
 * operation-specific payload fields. It rejects unknown fields, undeclared
 * enum values, noncanonical application status, and success diagnostics rather
 * than allowing individual clients to infer a weaker result.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent use.
 *
 * @par Performance
 * Cold-path protobuf validation; never called by a packet worker.
 */

#include <string_view>

#include <google/protobuf/message.h>

#include "src/common/status_or.hpp"
#include "gen/kinetum/common/v1/common.pb.h"

namespace kinetum::common
{

/**
 * @brief Validate one complete ControlService response envelope.
 * @param response Candidate generated response message.
 * @param application Embedded application status owned by @p response.
 * @param message_name Stable protobuf message name used for validation.
 * @return Exact application status code, or DATA_LOSS for malformed wire
 *         state.
 */
[[nodiscard]] status_or<status_code> validate_control_response_envelope(const google::protobuf::Message &response,
									const kinetum::common::v1::Status &application,
									std::string_view message_name);

}  // namespace kinetum::common
