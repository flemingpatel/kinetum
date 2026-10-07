// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dataplane_bootstrap.hpp
 * @brief Exact Control Plane bootstrap or rejoin of one Data Plane runtime.
 * @author Fleming Patel
 *
 * A supervised Control Plane first reads Data Plane Health. CONTROL_READY may
 * durably reconcile an admitted fresh source and then receive the exact
 * Bootstrap once. PACKET_READY never imports that source or receives Bootstrap:
 * authority must predate the observation, and mandatory telemetry must prove
 * its active epoch, validation hash, plan hash, both watermarks, and runtime
 * generation before typed transition reconciliation continues. A fresh store
 * beside PACKET_READY is data loss, not an inferred bootstrap.
 *
 * Read-only transient readiness and telemetry observations retry under one
 * named startup bound. Bootstrap itself remains one-shot because an uncertain
 * mutation result cannot be replayed as observation.
 *
 * @par Thread Safety
 * One startup thread owns the store and generated stub for the duration of the
 * call. The operation performs no concurrent store mutation.
 *
 * @par Performance
 * Cold startup work. Read-only Health/Stats probes are bounded by one overall
 * deadline; CONTROL_READY performs at most one mutating Bootstrap call.
 */

#include <chrono>
#include <cstdint>

#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "src/common/status_or.hpp"

namespace kinetum::cp
{

class config_store;
struct bootstrap_startup_authority;

/** @brief Production bound shared by complete DP/CP startup reconciliation. */
inline constexpr std::chrono::milliseconds DATAPLANE_STARTUP_RECONCILIATION_TIMEOUT{30'000};

static_assert(DATAPLANE_STARTUP_RECONCILIATION_TIMEOUT.count() > 0,
	      "Data Plane startup reconciliation timeout must be positive");

/** @brief Exact startup posture established by the bootstrap owner. */
enum class dataplane_bootstrap_outcome : uint8_t {
	CONTROL_ONLY = 0,	    ///< Fresh store had no active bootstrap authority; no RPC was sent.
	PACKET_READY = 1,	    ///< DP accepted and exactly echoed the durable bootstrap authority.
	PACKET_READY_REJOINED = 2,  ///< Existing packet-ready DP matched mandatory telemetry.
};

/**
 * @brief Bootstrap or rejoin the Data Plane from exact readiness truth.
 *
 * The nested active request is re-admitted through the shared six-field
 * validator before transmission. A successful response must have exact application
 * success, COMPLETE state, active epoch, canonical validation hash, and both
 * allocator watermarks. Application failure, malformed status or protobuf,
 * transport uncertainty, timeout, or any echo mismatch fails startup without
 * a second RPC.
 *
 * @param store Sole durable Control Plane state authority.
 * @param dataplane Generated client bound to the control-ready Data Plane.
 * @param bootstrap_authority Optional already-admitted source used to create a
 *        fresh durable authority only after CONTROL_READY. PACKET_READY requires
 *        authority that existed before this call and never imports this source.
 * @param startup_deadline One absolute steady deadline shared with subsequent
 *        typed transition and safety-intent reconciliation. The default starts
 *        a fresh production-bound interval for direct component callers.
 * @return CONTROL_ONLY for a fresh store, PACKET_READY after exact Bootstrap,
 *         PACKET_READY_REJOINED after exact surviving-runtime proof, or the
 *         first durable-state, validation, transport, application,
 *         response-identity, or orphan-publication failure.
 */
[[nodiscard]] kinetum::common::status_or<dataplane_bootstrap_outcome> bootstrap_dataplane_from_store(
	config_store &store, kinetum::dataplane::v1::DataplaneService::Stub &dataplane,
	const bootstrap_startup_authority *bootstrap_authority,
	std::chrono::steady_clock::time_point startup_deadline = std::chrono::steady_clock::now() +
								 DATAPLANE_STARTUP_RECONCILIATION_TIMEOUT);

}  // namespace kinetum::cp
