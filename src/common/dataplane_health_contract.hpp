// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dataplane_health_contract.hpp
 * @brief Exact DP startup-readiness response admission.
 * @author Fleming Patel
 *
 * CP and Photon consume the same normalized Health response relation. The
 * helper admits no packet state and performs no polling; it validates one
 * already received cold-path protobuf value.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent use.
 */

#include <cstdint>

#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/** @brief Complete identity carried by one valid startup Health success. */
struct dataplane_health_identity {
	kinetum::dataplane::v1::HealthResponse::State state{
		kinetum::dataplane::v1::HealthResponse::STATE_UNSPECIFIED};  ///< Exact readiness state.
	uint64_t runtime_generation{0};	 ///< Zero only while the process reports STARTING.
	uint64_t active_epoch{0};	 ///< Zero at CONTROL_READY; nonzero at PACKET_READY.
	uint32_t active_workers{0};	 ///< Workers proven active by this publication.
	uint32_t expected_workers{0};	 ///< Exact compiled worker population.
};

/**
 * @brief Validate and normalize one DP startup Health response.
 *
 * Application failure is returned with its exact declared status category.
 * Success is admitted only for STARTING, CONTROL_READY, or PACKET_READY with
 * the state-qualified runtime-generation, epoch, worker, version, and
 * payload-clearing relation.
 *
 * @param response Candidate wire response.
 * @return Exact normalized identity, or the first malformed/application
 *         failure without inferred defaults.
 */
[[nodiscard]] status_or<dataplane_health_identity>
validate_dataplane_startup_health(const kinetum::dataplane::v1::HealthResponse &response);

}  // namespace kinetum::common
