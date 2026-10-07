// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_telemetry_contract.hpp
 * @brief Shared strict validation for the final runtime telemetry wire.
 * @author Fleming Patel
 *
 * The Data Plane validates immediately before publication and the Control Plane
 * validates again before forwarding. These functions own intrinsic wire shape;
 * compiled-topology membership remains with the generation-scoped runtime
 * source and is never reconstructed here.
 *
 * @par Thread Safety
 * Stateless cold-path functions. The caller must not mutate an input message
 * concurrently.
 *
 * @par Performance
 * Reflection, strings, and bounded linear scans are permitted. No function in
 * this file is reachable from a packet worker or provider packet operation.
 */

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "gen/kinetum/telemetry/v1/telemetry.pb.h"
#include "src/common/status.hpp"

namespace kinetum::common
{

/**
 * @brief Validate one exact Data Plane statistics request wrapper.
 * @param request Candidate request with an explicitly present selection.
 * @return OK only when the wrapper and nested selection contain no unknown or
 *         undeclared values; otherwise the exact validation, allocation,
 *         representation, or protobuf-library failure.
 */
[[nodiscard]] status validate_dataplane_stats_request(const kinetum::dataplane::v1::StatsRequest &request);

/**
 * @brief Validate one exact Control Plane statistics request wrapper.
 * @param request Candidate request with an explicitly present selection.
 * @return OK only when the wrapper and nested selection contain no unknown or
 *         undeclared values; otherwise the exact validation, allocation,
 *         representation, or protobuf-library failure.
 */
[[nodiscard]] status validate_control_stats_request(const kinetum::control::v1::StatsRequest &request);

/**
 * @brief Validate one complete telemetry row-selection request.
 * @param selection Candidate shared selection message.
 * @return OK for a known exact selection; otherwise the exact validation,
 *         allocation, representation, or protobuf-library failure.
 */
[[nodiscard]] status validate_telemetry_selection(const kinetum::telemetry::v1::TelemetrySelection &selection);

/**
 * @brief Validate one complete successful runtime telemetry message.
 * @param telemetry Candidate generation-scoped observation.
 * @param selection Exact request that governed optional row membership.
 * @return OK only when required families, presence, enums, identities, and
 *         selected-row absence are intrinsically coherent; otherwise the exact
 *         validation, allocation, representation, or protobuf-library failure.
 */
[[nodiscard]] status validate_runtime_telemetry(const kinetum::telemetry::v1::RuntimeTelemetry &telemetry,
						const kinetum::telemetry::v1::TelemetrySelection &selection);

/**
 * @brief Validate a failed Data Plane statistics envelope before classifying retry.
 * @param response Candidate failure containing one canonical status and no telemetry.
 * @return OK for an exact status-only failure; malformed or unknown fields reject.
 */
[[nodiscard]] status validate_failed_dataplane_stats_response(const kinetum::dataplane::v1::StatsResponse &response);

/**
 * @brief Validate one successful Data Plane statistics response.
 * @param response Candidate response with canonical application success.
 * @param selection Exact request that governed optional row membership.
 * @return OK only when status and the complete shared payload are exact;
 *         otherwise the exact validation, allocation, representation, or
 *         protobuf-library failure.
 */
[[nodiscard]] status
validate_successful_dataplane_stats_response(const kinetum::dataplane::v1::StatsResponse &response,
					     const kinetum::telemetry::v1::TelemetrySelection &selection);

/**
 * @brief Validate one successful operator-facing statistics response.
 * @param response Candidate CP response with active configuration and telemetry.
 * @param selection Exact request that governed optional row membership.
 * @return OK only when wrapper identity, status, and shared payload are exact;
 *         otherwise the exact validation, allocation, representation, or
 *         protobuf-library failure.
 */
[[nodiscard]] status
validate_successful_control_stats_response(const kinetum::control::v1::StatsResponse &response,
					   const kinetum::telemetry::v1::TelemetrySelection &selection);

}  // namespace kinetum::common
