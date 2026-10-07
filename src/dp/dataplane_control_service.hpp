// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dataplane_control_service.hpp
 * @brief Data Plane gRPC adapter for one complete packet-runtime generation.
 * @author Fleming Patel
 *
 * The production DP host constructs one complete CONTROL_READY runtime before
 * exposing this service. Bootstrap delegates to that runtime's sole startup
 * owner, while Health observes only its immutable status publication. The
 * service never reads mutable workers, provider state, or configuration slots.
 * Prepare, Activate, Abort, and Status submit to the sole transition
 * coordinator and return typed identity, state, and failure observations.
 * GetStats delegates to the generation-scoped all-or-none telemetry source.
 * Drain, shutdown, and state dump return application-level UNAVAILABLE;
 * process shutdown is signal-owned and 0.1.0 has no coordinated drain or
 * state-dump execution owner.
 * Response-allocation or representation-size failure returns transport
 * UNAVAILABLE without publishing a partial application response. Mutation
 * callers retain and reconcile the same exact request identity. Any other
 * exception at this process boundary is terminate-class.
 *
 * @par Thread Safety
 * gRPC may invoke handlers concurrently. Bootstrap and all four transition
 * operations submit through the bounded runtime mailbox and wait
 * unconditionally for the sole coordinator consumer. Health reads only the
 * immutable runtime-status publication. GetStats claims the runtime's
 * serialized cold source without holding a platform lock across provider
 * callbacks. Unavailable handlers write only caller-owned response memory.
 * The runtime must outlive the service.
 */

#include <grpcpp/grpcpp.h>

#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"

namespace kinetum::dp
{
class partitioned_runtime;

/**
 * @brief Serve one exact materialized packet-runtime generation.
 *
 * Health reports the generation's coherent CONTROL_READY or PACKET_READY
 * publication. Bootstrap owns fixed startup, while passive, synchronous-active,
 * and tracked-async live transitions consume the exact coordinator and ordered
 * worker protocol. A plan without
 * transition policy and surfaces without a final coherent owner return typed
 * application-level refusal.
 *
 * @invariant runtime_ denotes one complete runtime that outlives the service.
 *
 * @par Thread Safety
 * Immutable and safe for concurrent gRPC dispatch.
 */
class dataplane_control_service final : public kinetum::dataplane::v1::DataplaneService::Service {
    public:
	/**
	 * @brief Bind the wire adapter to one complete runtime generation.
	 *
	 * @param runtime Sole runtime generation owner. It must outlive this service.
	 *
	 * @post Health observes only @p runtime's immutable status publication.
	 */
	explicit dataplane_control_service(partitioned_runtime &runtime) noexcept;

	/**
	 * @brief Restore one exact fixed bootstrap epoch before packet admission.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Exact bootstrap restoration request.
	 * @param response Response receiving the exact bootstrap result on success,
	 *                 or an application status and no result fields on failure.
	 * @return `grpc::Status::OK` when @p request and @p response are valid;
	 *         `INVALID_ARGUMENT` for a null request or response; `UNAVAILABLE`
	 *         when the response cannot be represented.
	 */
	grpc::Status
	BootstrapConfigSnapshot(grpc::ServerContext *context,
				const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest *request,
				kinetum::dataplane::v1::BootstrapConfigSnapshotResponse *response) override;

	/**
	 * @brief Prepare one exact admitted configuration transition.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Configuration snapshot preparation request.
	 * @param response Response receiving typed identity/state/failure and
	 *                 PREPARED fields only when that state is exact.
	 * @return `grpc::Status::OK` when @p request and @p response are valid;
	 *         `INVALID_ARGUMENT` for a null request or response; `UNAVAILABLE`
	 *         when the response cannot be represented.
	 */
	grpc::Status PrepareConfigSnapshot(grpc::ServerContext *context,
					   const kinetum::dataplane::v1::PrepareConfigSnapshotRequest *request,
					   kinetum::dataplane::v1::PrepareConfigSnapshotResponse *response) override;

	/**
	 * @brief Activate one exact PREPARED configuration transition.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Configuration snapshot activation request.
	 * @param response Response receiving typed identity/state/failure and
	 *                 COMPLETE fields only after exact reclamation.
	 * @return `grpc::Status::OK` when @p request and @p response are valid;
	 *         `INVALID_ARGUMENT` for a null request or response; `UNAVAILABLE`
	 *         when the response cannot be represented.
	 */
	grpc::Status ActivateConfigSnapshot(grpc::ServerContext *context,
					    const kinetum::dataplane::v1::ActivateConfigSnapshotRequest *request,
					    kinetum::dataplane::v1::ActivateConfigSnapshotResponse *response) override;

	/**
	 * @brief Abort one exact transaction only before its commit edge.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Exact pre-commit abort request.
	 * @param response Response receiving one typed exact or rejected observation.
	 * @return `grpc::Status::OK` when @p request and @p response are valid;
	 *         `INVALID_ARGUMENT` for a null request or response; `UNAVAILABLE`
	 *         when the response cannot be represented.
	 */
	grpc::Status
	AbortPreparedConfigSnapshot(grpc::ServerContext *context,
				    const kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest *request,
				    kinetum::dataplane::v1::AbortPreparedConfigSnapshotResponse *response) override;

	/**
	 * @brief Query one exact active, terminal, or rejected transition identity.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Exact transition identity to query.
	 * @param response Response receiving typed identity/state/failure and exact
	 *                 status fields only for an active or terminal identity.
	 * @return `grpc::Status::OK` when @p request and @p response are valid;
	 *         `INVALID_ARGUMENT` for a null request or response; `UNAVAILABLE`
	 *         when the response cannot be represented.
	 */
	grpc::Status
	GetEpochTransitionStatus(grpc::ServerContext *context,
				 const kinetum::dataplane::v1::GetEpochTransitionStatusRequest *request,
				 kinetum::dataplane::v1::GetEpochTransitionStatusResponse *response) override;

	/**
	 * @brief Publish one all-or-none coherent runtime telemetry snapshot.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Statistics request with one explicit shared selection.
	 * @param response Response receiving status and the selected telemetry rows.
	 * @return `grpc::Status::OK` when @p request and @p response are valid;
	 *         `INVALID_ARGUMENT` for a null request or response; `UNAVAILABLE`
	 *         when the response cannot be represented.
	 */
	grpc::Status GetStats(grpc::ServerContext *context, const kinetum::dataplane::v1::StatsRequest *request,
			      kinetum::dataplane::v1::StatsResponse *response) override;

	/**
	 * @brief Report coherent runtime-generation readiness and worker ownership.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Health request.
	 * @param response Response receiving one immutable status observation.
	 * @return `grpc::Status::OK` when @p request and @p response are valid;
	 *         `INVALID_ARGUMENT` for a null request or response; `UNAVAILABLE`
	 *         when the response cannot be represented.
	 */
	grpc::Status Health(grpc::ServerContext *context, const kinetum::dataplane::v1::HealthRequest *request,
			    kinetum::dataplane::v1::HealthResponse *response) override;

	/**
	 * @brief Reject drain until an exact runtime drain owner exists.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Exact drain request.
	 * @param response Response receiving only application-level unavailability.
	 * @return `grpc::Status::OK` for non-null inputs; `INVALID_ARGUMENT` for a
	 *         null input; `UNAVAILABLE` when the response cannot be represented.
	 */
	grpc::Status Drain(grpc::ServerContext *context, const kinetum::dataplane::v1::DrainRequest *request,
			   kinetum::dataplane::v1::DrainResponse *response) override;

	/**
	 * @brief Reject drain observation until an exact runtime drain owner exists.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Exact drain-status request.
	 * @param response Response receiving only application-level unavailability.
	 * @return `grpc::Status::OK` for non-null inputs; `INVALID_ARGUMENT` for a
	 *         null input; `UNAVAILABLE` when the response cannot be represented.
	 */
	grpc::Status DrainStatus(grpc::ServerContext *context,
				 const kinetum::dataplane::v1::DrainStatusRequest *request,
				 kinetum::dataplane::v1::DrainStatusResponse *response) override;

	/**
	 * @brief Reject RPC-driven shutdown until it owns complete process teardown.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Exact shutdown request.
	 * @param response Response receiving only application-level unavailability.
	 * @return `grpc::Status::OK` for non-null inputs; `INVALID_ARGUMENT` for a
	 *         null input; `UNAVAILABLE` when the response cannot be represented.
	 */
	grpc::Status Shutdown(grpc::ServerContext *context, const kinetum::dataplane::v1::ShutdownRequest *request,
			      kinetum::dataplane::v1::ShutdownResponse *response) override;

	/**
	 * @brief Reject state dump until an exact bounded publication exists.
	 *
	 * @param context gRPC server context supplied by the transport.
	 * @param request Exact state-dump request.
	 * @param response Response receiving only application-level unavailability.
	 * @return `grpc::Status::OK` for non-null inputs; `INVALID_ARGUMENT` for a
	 *         null input; `UNAVAILABLE` when the response cannot be represented.
	 */
	grpc::Status DumpState(grpc::ServerContext *context, const kinetum::dataplane::v1::DumpStateRequest *request,
			       kinetum::dataplane::v1::DumpStateResponse *response) override;

    private:
	partitioned_runtime &runtime_;	///< Sole complete generation owner; never nullable.
};

}  // namespace kinetum::dp
