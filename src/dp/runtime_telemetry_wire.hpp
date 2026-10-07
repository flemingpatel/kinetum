// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_telemetry_wire.hpp
 * @brief Total mapping from internal runtime observation to shared wire truth.
 * @author Fleming Patel
 *
 * @par Thread Safety
 * Cold stateless mapping over caller-owned immutable input and output.
 *
 * @par Performance
 * May allocate protobuf/string storage and perform bounded cold derivations.
 * It is never reachable from a packet worker or provider packet operation.
 */

#include "gen/kinetum/telemetry/v1/telemetry.pb.h"
#include "src/common/status.hpp"
#include "src/dp/runtime_telemetry.hpp"

namespace kinetum::dp
{

/**
 * @brief Populate and validate one complete shared runtime telemetry message.
 * @param snapshot Complete generation-scoped internal observation.
 * @param selection Exact row selection that governed @p snapshot.
 * @param[out] output Cleared destination populated only on success.
 * @return OK for one structurally complete message; INVALID_ARGUMENT for a
 *         null destination, UNAVAILABLE or DATA_LOSS for incoherent source
 *         truth, RESOURCE_EXHAUSTED or OUT_OF_RANGE for representation
 *         limits, and INTERNAL_ERROR for another protobuf-library failure.
 */
[[nodiscard]] common::status
populate_runtime_telemetry_wire(const runtime_telemetry_snapshot &snapshot,
				const kinetum::telemetry::v1::TelemetrySelection &selection,
				kinetum::telemetry::v1::RuntimeTelemetry *output);

}  // namespace kinetum::dp
