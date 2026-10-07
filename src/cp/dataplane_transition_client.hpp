// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dataplane_transition_client.hpp
 * @brief Exact typed Control Plane client for Data Plane epoch transitions.
 * @author Fleming Patel
 *
 * This cold component constructs exact identity requests, bounds every unary
 * transport attempt, rejects malformed response trees and field residue, and
 * converts the public identity-resolution enum back to the shared internal
 * classification. Diagnostic text is retained only after typed state has been
 * admitted and is never used to select a reconciliation action.
 *
 * @par Thread Safety
 * One control-loop thread owns an instance and invokes one method at a time.
 * The generated stub remains shared with read-only CP RPC forwarding.
 *
 * @par Performance
 * Cold control-path work. Every call performs one bounded unary RPC and bounded
 * protobuf validation; no method is reachable from packet workers.
 */

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::cp
{

/** @brief Maximum per-attempt transport deadline; never a DP behavior deadline. */
inline constexpr std::chrono::milliseconds DATAPLANE_TRANSITION_RPC_TIMEOUT{5'000};

/** @brief One normalized typed DP response consumed by durable reconciliation. */
struct dataplane_transition_observation {
	kinetum::common::status application_status;  ///< Exact embedded operation status.
	kinetum::common::transition_identity_resolution resolution{
		kinetum::common::transition_identity_resolution::INVALID};  ///< Typed identity relation.
	kinetum::telemetry::v1::EpochTransitionState state{
		kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_UNSPECIFIED};  ///< Exact active/terminal state.
	kinetum::telemetry::v1::EpochTransitionFailureCode failure_code{
		kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED};  ///< Typed cause.
	kinetum::common::epoch_transition_identity identity{};	///< Exact caller-owned identity when resolved.
	uint64_t prepared_lease_deadline_unix_ms{0};		///< PREPARED informational projection.
	uint64_t prepare_duration_ns{0};			///< Status PREPARING duration, when produced.
	uint64_t commit_duration_ns{0};				///< Status COMMITTING duration, when produced.
	uint64_t retirement_duration_ns{0};			///< Status RETIRING duration, when produced.
	uint64_t transition_duration_ns{0};			///< Activate COMPLETE total duration.
	std::string plan_content_hash;				///< Exact frozen plan hash from Status.
	std::string failure_reason;				///< Bounded diagnostic-only bytes.
};

/** @brief One exact generated-stub transition client. */
class dataplane_transition_client final {
    public:
	/**
	 * @brief Bind one generated stub and positive per-attempt transport deadline.
	 * @param stub Shared exact DP service stub.
	 * @param timeout Transport observation bound in `(0, 5000]` milliseconds.
	 * @return Unique client or exact dependency/deadline/allocation failure.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<dataplane_transition_client>>
	create(std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> stub,
	       std::chrono::milliseconds timeout = DATAPLANE_TRANSITION_RPC_TIMEOUT);

	dataplane_transition_client(const dataplane_transition_client &) = delete;
	dataplane_transition_client &operator=(const dataplane_transition_client &) = delete;
	dataplane_transition_client(dataplane_transition_client &&) = delete;
	dataplane_transition_client &operator=(dataplane_transition_client &&) = delete;
	~dataplane_transition_client() = default;

	/**
	 * @brief Attempt or exactly observe one Prepare operation.
	 * @param request Complete canonical candidate request retained by CP.
	 * @param identity Exact durable identity reconstructed from @p request.
	 * @param operation_deadline Optional overall steady deadline that may only
	 *        shorten this client's configured per-attempt timeout.
	 * @return One exact Prepare observation or transport/protocol failure.
	 */
	[[nodiscard]] kinetum::common::status_or<dataplane_transition_observation>
	prepare(const kinetum::dataplane::v1::PrepareConfigSnapshotRequest &request,
		const kinetum::common::epoch_transition_identity &identity,
		std::chrono::steady_clock::time_point operation_deadline =
			std::chrono::steady_clock::time_point::max()) const;

	/**
	 * @brief Attempt or exactly observe one Activate operation.
	 * @param identity Exact durable transition identity.
	 * @param idempotency_key Original key whose digest belongs to @p identity.
	 * @param operation_deadline Optional overall steady deadline that may only
	 *        shorten this client's configured per-attempt timeout.
	 * @return One exact Activate observation or transport/protocol failure.
	 */
	[[nodiscard]] kinetum::common::status_or<dataplane_transition_observation>
	activate(const kinetum::common::epoch_transition_identity &identity, std::string_view idempotency_key,
		 std::chrono::steady_clock::time_point operation_deadline =
			 std::chrono::steady_clock::time_point::max()) const;

	/**
	 * @brief Attempt or exactly observe one pre-commit Abort operation.
	 * @param identity Exact durable transition identity.
	 * @param idempotency_key Original key whose digest belongs to @p identity.
	 * @param operation_deadline Optional overall steady deadline that may only
	 *        shorten this client's configured per-attempt timeout.
	 * @return One exact Abort observation or transport/protocol failure.
	 */
	[[nodiscard]] kinetum::common::status_or<dataplane_transition_observation>
	abort(const kinetum::common::epoch_transition_identity &identity, std::string_view idempotency_key,
	      std::chrono::steady_clock::time_point operation_deadline =
		      std::chrono::steady_clock::time_point::max()) const;

	/**
	 * @brief Query one exact active, terminal, or rejected transition identity.
	 * @param identity Exact durable transition identity.
	 * @param idempotency_key Original key whose digest belongs to @p identity.
	 * @param plan_content_hash Exact canonical plan hash expected in the response.
	 * @param operation_deadline Optional overall steady deadline that may only
	 *        shorten this client's configured per-attempt timeout.
	 * @return One exact Status observation or transport/protocol failure.
	 */
	[[nodiscard]] kinetum::common::status_or<dataplane_transition_observation>
	query(const kinetum::common::epoch_transition_identity &identity, std::string_view idempotency_key,
	      std::string_view plan_content_hash,
	      std::chrono::steady_clock::time_point operation_deadline =
		      std::chrono::steady_clock::time_point::max()) const;

    private:
	/**
	 * @brief Adopt one validated stub and deadline.
	 * @param stub Shared exact DP service stub.
	 * @param timeout Positive per-attempt transport observation bound.
	 */
	dataplane_transition_client(std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> stub,
				    std::chrono::milliseconds timeout) noexcept;

	std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> stub_;	///< Exact generated client.
	std::chrono::milliseconds timeout_;  ///< Per-call transport observation bound.
};

}  // namespace kinetum::cp
