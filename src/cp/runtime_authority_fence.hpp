// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_authority_fence.hpp
 * @brief Exact Control Plane to Data Plane runtime-content reconciliation.
 * @author Fleming Patel
 *
 * The Control Plane's durable active content and the Data Plane's coherent
 * telemetry are independent publications. This cold-path contract recognizes
 * the stable exact-active relation and the one lawful reply-loss window where
 * Data Plane completion precedes the Control Plane's atomic COMPLETE record.
 * Every other coherent semantic disagreement is data loss. The same boundary
 * normalizes malformed transport-success Data Plane responses so caller-input
 * validation categories cannot leak across the remote-producer seam.
 *
 * @par Thread Safety
 * The functions are stateless. Callers must obtain each
 * `durable_runtime_authority_view` through one config-store read.
 *
 * @par Performance
 * Fixed identity comparisons are bounded Control Plane work. The success path
 * allocates nothing, and no function may execute on a packet worker.
 */

#include <cstdint>
#include <string_view>

#include "gen/kinetum/common/v1/common.pb.h"
#include "gen/kinetum/telemetry/v1/telemetry.pb.h"
#include "src/common/sha256_digest.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/cp/config_store.hpp"

namespace kinetum::cp
{

/** @brief Lawful relation between durable CP content and coherent DP truth. */
enum class runtime_authority_relation : uint8_t {
	ACTIVE_EXACT = 0,	    ///< DP still names the last durable COMPLETE content.
	TARGET_COMPLETE_EXACT = 1,  ///< DP completed the durable target before CP publication.
};

static_assert(sizeof(runtime_authority_relation) == sizeof(uint8_t), "runtime authority relation must remain one byte");

/**
 * @brief Normalize failure from validating a transport-success DP response.
 *
 * Resource exhaustion and host-size overflow retain their exact categories.
 * Every other validation failure identifies malformed remote producer data and
 * becomes DATA_LOSS rather than caller INVALID_ARGUMENT.
 *
 * @param failure Non-OK shared contract-validation result.
 * @param malformed_message Fixed diagnostic for malformed remote producer data.
 * @return Exact bounded resource failure or canonical DATA_LOSS.
 */
[[nodiscard]] kinetum::common::status map_dataplane_response_validation_failure(const kinetum::common::status &failure,
										std::string_view malformed_message);

/**
 * @brief Decode one transport-success Data Plane application status.
 *
 * Canonical residue-free success returns OK. A declared nonzero numeric
 * category returns that failure without consuming response payload. Its
 * message and details are retained as diagnostic details, each capped at 512
 * bytes; they never select behavior. Contradictory, undeclared, or
 * success-with-residue status is DATA_LOSS, so it cannot enter a
 * successful-response validator.
 *
 * @param wire Embedded Data Plane application status.
 * @param failure_message Fixed diagnostic used for a declared failure.
 * @return OK, the declared application failure, or DATA_LOSS.
 */
[[nodiscard]] kinetum::common::status map_dataplane_application_status(const kinetum::common::v1::Status &wire,
								       std::string_view failure_message);

/**
 * @brief Compare the active portions of two coherent durable views.
 *
 * Transition phase may advance while the active content remains unchanged, so
 * only the compact active projection participates in this fence. Its raw
 * validation hash commits the complete canonical snapshot content.
 *
 * @param before Durable view obtained before a remote observation.
 * @param after Durable view obtained after that observation.
	 * @return true only when every active identity field is equal.
 */
[[nodiscard]] bool same_active_runtime_authority(const durable_runtime_authority_view &before,
						 const durable_runtime_authority_view &after) noexcept;

/**
 * @brief Classify coherent Data Plane telemetry against one durable CP view.
 *
 * `TARGET_COMPLETE_EXACT` is admitted only for durable
 * COMPLETION_PENDING plus an exact latest COMPLETE record for that same
 * mutation, epoch, validation hash, and idempotency-key digest. It permits
 * restart reconciliation but never permits CP to publish the old active
 * configuration beside target telemetry as an ordinary successful sample.
 * `ACTIVE_EXACT` also admits the one adjacent ALLOCATED/ABORT_PENDING/ABORTED
 * startup edge where CP durably consumed both values before a surviving idle
 * DP saw Prepare; the exact Status classifier then resumes or verifies that
 * retained result.
 *
 * @param authority One lock-coherent durable active/transition view.
 * @param telemetry Intrinsically validated Data Plane runtime telemetry.
 * @return Exact relation, DATA_LOSS for malformed or unexplained disagreement,
 *         or RESOURCE_EXHAUSTED if failure classification cannot allocate.
 */
[[nodiscard]] kinetum::common::status_or<runtime_authority_relation>
classify_runtime_authority(const durable_runtime_authority_view &authority,
			   const kinetum::telemetry::v1::RuntimeTelemetry &telemetry);

}  // namespace kinetum::cp
