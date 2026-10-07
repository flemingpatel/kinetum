// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file cp_grpc.hpp
 * @brief Control plane gRPC service implementation.
 * @author Fleming Patel
 *
 * This module implements the Control Plane's gRPC API, which provides configuration
 * management, snapshot operations, and guardrails for the Kinetum platform.
 *
 * Core Responsibilities:
 * - Configuration snapshot lifecycle (apply, list, inspect, rollback)
 * - Fail-closed admission for exact Data Plane transitions
 * - Guardrails policy configuration and monitoring
 * - Health and statistics reporting
 *
 * Exact Transition Boundary:
 * ==========================
 * The permanent CP-to-DP wire carries a CP-allocated epoch, mutation sequence,
 * validation hash, and idempotency identity through Prepare, Activate, Abort,
 * and Status. Exact Bootstrap restores a fresh CONTROL_READY runtime;
 * surviving PACKET_READY startup instead requires a durable-content telemetry
 * fence before typed Status reconciliation.
 *
 * The CP host starts its mutation authority only after exact DP PACKET_READY.
 * A control-only host keeps it stopped and rejects before queue, persistence,
 * or transport effects. A started authority advances durable phases and active
 * content only from typed exact DP observations.
 * If allocation or representation limits prevent construction of a final
 * response, the handler returns transport `UNAVAILABLE` without publishing a
 * partial application payload. Mutation callers reconcile the same retained
 * idempotency identity. Any other exception at this process boundary is
 * terminate-class.
 *
 * Thread Safety:
 * - All RPC handlers are thread-safe (gRPC may invoke handlers concurrently)
 * - All config mutations are serialized through the shared control_loop
 * - Guardrails policy is propagated via versioned_rcu_buffer (lock-free reads)
 * - config_store write operations are serialized through control_loop
 *
 */

#include <chrono>
#include <memory>
#include <string>

#include "gen/kinetum/control/v1/control.grpc.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "src/common/status.hpp"
#include "src/cp/config_store.hpp"
#include "src/cp/control_loop.hpp"

namespace kinetum::cp
{

/**
 * @brief Control Plane gRPC service implementation.
 *
 * Implements the ControlService interface defined in control.proto, providing
 * all configuration management and monitoring capabilities for the platform.
 *
 * @par Service Responsibilities
 * The service holds:
 * - Reference to persistent config_store for snapshot storage
 * - gRPC stub to Data Plane for applying configuration updates
 * - Reference to the shared control_loop for all mutations
 *
 * Mutation handlers require the shared control loop to be running. When the
 * host exposes only its control surface, they return `UNAVAILABLE` before
 * constructing or enqueueing a mutation. Read-only RPCs remain independent of
 * that packet-configuration admission boundary.
 *
 * @par Snapshot/Epoch Lifecycle
 * Packet-ready production starts the shared control loop. Snapshot mutations
 * canonicalize and allocate one durable identity, persist PREPARED only after
 * exact DP preparation, persist COMPLETION_PENDING before Activate, and
 * publish active content only after typed DP COMPLETE. Control-only startup
 * keeps the loop stopped and rejects before mutation construction.
 *
 * @par Lifecycle
 * 1. Construct with config_store and DP stub
 * 2. Register with gRPC ServerBuilder
 * 3. Handle RPCs (gRPC manages threading)
 * 4. Shutdown automatically when server stops
 *
 * @warning The config_store pointer must remain valid for the entire service
 *          lifetime. A non-null DP stub is shared-owned; a null stub
 *          deliberately makes DP-backed reads fail closed.
 *
 * @invariant store_ is non-null and valid for the lifetime of the service
 * @invariant dp_ either owns a valid stub or is null, in which case DP-backed
 *            reads return application UNAVAILABLE
 *
 * @see config_store For snapshot persistence
 * @see guardrails_runner For automatic rollback monitoring
 */
class control_service_impl final : public kinetum::control::v1::ControlService::Service {
    public:
	// ---------------------------------------------------------------------------
	// Construction
	// ---------------------------------------------------------------------------

	/**
	 * @brief Construct the control service.
	 *
	 * @param store Pointer to config_store; must outlive this object.
	 * @param dp_stub Shared pointer to the Data Plane gRPC stub.
	 * @param loop Sole control_loop; must outlive this object and serializes all
	 *             mutations without an owned fallback.
	 */
	control_service_impl(config_store *store,
			     std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> dp_stub,
			     control_loop &loop);

	// ---------------------------------------------------------------------------
	// Configuration Snapshot Operations
	// ---------------------------------------------------------------------------

	/**
	 * @brief Set (or create) a configuration snapshot and make it active.
	 *
	 * The request is admitted before one exact mutation is transferred to the
	 * control loop. That sole writer persists the transition before contacting
	 * DP and returns only after exact convergence.
	 *
	 * @param context Borrowed gRPC server context.
	 * @param request Complete ConfigSnapshot mutation request.
	 * @param response Cleared destination for status and exact success identity.
	 * @return Transport OK with application status in @p response, transport
	 *         INVALID_ARGUMENT for a null direct invocation, or transport
	 *         UNAVAILABLE when the response cannot be represented.
	 *
	 * @par Thread Safety
	 * Concurrent gRPC calls serialize mutation through the one control loop.
	 */
	grpc::Status SetConfigSnapshot(grpc::ServerContext *context,
				       const kinetum::control::v1::SetConfigSnapshotRequest *request,
				       kinetum::control::v1::SetConfigSnapshotResponse *response) override;

	/**
	 * @brief Return one bounded immutable page of configuration snapshots.
	 *
	 * The opaque continuation binds the exact corpus and active authority. A
	 * changed listing invalidates the token rather than returning an empty or
	 * mixed page.
	 *
	 * @param context Borrowed gRPC server context.
	 * @param request Positive page bound and optional exact continuation token.
	 * @param response One sorted page, total count, continuation, and status.
	 * @return Transport OK with application status in @p response, transport
	 *         INVALID_ARGUMENT for a null direct invocation, or transport
	 *         UNAVAILABLE when the response cannot be represented.
	 *
	 * @par Thread Safety
	 * Thread-safe. Reads one coherent store authority under its shared lock.
	 */
	grpc::Status ListSnapshots(grpc::ServerContext *context,
				   const kinetum::control::v1::ListSnapshotsRequest *request,
				   kinetum::control::v1::ListSnapshotsResponse *response) override;

	/**
	 * @brief Get the currently active configuration snapshot.
	 *
	 * @param context Borrowed gRPC server context.
	 * @param request Empty request.
	 * @param response Cleared destination for the coherent active snapshot.
	 * @return Transport OK with application status in @p response, transport
	 *         INVALID_ARGUMENT for a null direct invocation, or transport
	 *         UNAVAILABLE when the response cannot be represented. NOT_FOUND is
	 *         an application result when no active authority exists.
	 *
	 * @par Thread Safety
	 * Thread-safe. The complete snapshot is copied under one store read lock.
	 */
	grpc::Status GetActiveSnapshot(grpc::ServerContext *context,
				       const kinetum::control::v1::GetActiveSnapshotRequest *request,
				       kinetum::control::v1::GetActiveSnapshotResponse *response) override;

	/**
	 * @brief Roll back to retained content through a new monotonic epoch.
	 *
	 * Epoch 1 content may become active again at Epoch 3 after Epoch 2, but no
	 * old epoch or pointer is restored in place. Exact retained content enters
	 * the same durable Prepare/Activate path as every other mutation.
	 *
	 * @param context Borrowed gRPC server context.
	 * @param request Target snapshot, optional module subset, key, and CAS.
	 * @param response Cleared destination for status and exact success identity.
	 * @return Transport OK with application status in @p response, transport
	 *         INVALID_ARGUMENT for a null direct invocation, or transport
	 *         UNAVAILABLE when the response cannot be represented.
	 *
	 * @par Thread Safety
	 * Thread-safe. Mutation is serialized through the one control loop.
	 *
	 * @see guardrails_runner For automatic rollback based on health metrics.
	 */
	grpc::Status Rollback(grpc::ServerContext *context, const kinetum::control::v1::RollbackRequest *request,
			      kinetum::control::v1::RollbackResponse *response) override;

	// ---------------------------------------------------------------------------
	// Commit-Confirmed Pattern
	// ---------------------------------------------------------------------------

	/**
	 * @brief Confirm a pending configuration, preventing auto-rollback.
	 *
	 * When a configuration is applied with confirm_timeout_ms > 0, it enters
	 * a "pending confirm" state. This RPC confirms the config is working correctly
	 * and durably retains one exact success result until the next successful
	 * epoch allocation clears it atomically.
	 *
	 * @par Usage Pattern
	 * 1. Apply config with SetConfigSnapshot(..., confirm_timeout_ms=300000)
	 * 2. Verify the configuration is working as expected
	 * 3. Call ConfirmConfig with exact snapshot, epoch, revision, and one retry key
	 * 4. If not confirmed before timeout, guardrails triggers auto-rollback
	 *
	 * @param context Borrowed gRPC server context.
	 * @param request Complete snapshot, epoch, revision, and retry identity.
	 * @param response Cleared destination for status, exact echo, and remaining time.
	 * @return Transport OK with application status in @p response, transport
	 *         INVALID_ARGUMENT for a null direct invocation, or transport
	 *         UNAVAILABLE when the response cannot be represented. Application
	 *         FAILED_PRECONDITION identifies absent/mismatched confirmation;
	 *         DEADLINE_EXCEEDED means the durable deadline or intent won.
	 *
	 * @par Thread Safety
	 * Thread-safe. Confirmation is serialized through the one control loop.
	 */
	grpc::Status ConfirmConfig(grpc::ServerContext *context,
				   const kinetum::control::v1::ConfirmConfigRequest *request,
				   kinetum::control::v1::ConfirmConfigResponse *response) override;

	// ---------------------------------------------------------------------------
	// Guardrails Operations
	// ---------------------------------------------------------------------------

	/**
	 * @brief Configure the guardrails policy for automatic rollback.
	 *
	 * Guardrails consume coherent Data Plane observations. The request carries
	 * one complete nested policy, exact expected generation, and one retained
	 * retry key; the control loop persists and publishes it as one mutation.
	 *
	 * @param context Borrowed gRPC server context.
	 * @param request Complete policy, expected generation, and retry identity.
	 * @param response Cleared destination for status and exact policy identity.
	 * @return Transport OK with application status in @p response, transport
	 *         INVALID_ARGUMENT for a null direct invocation, or transport
	 *         UNAVAILABLE when the response cannot be represented.
	 *
	 * @note This RPC submits one set_guardrails_policy mutation to the shared
	 *       control loop, whose versioned publication is consumed by
	 *       guardrails_runner.
	 *
	 * @warning Setting overly aggressive thresholds (e.g., max_drop_ratio=0.001)
	 *          may cause false-positive rollbacks during normal traffic bursts.
	 *
	 * @par Thread Safety
	 * Thread-safe. Policy mutation is serialized through the control loop.
	 *
	 * @see guardrails_runner For the monitoring implementation
	 */
	grpc::Status ConfigureGuardrails(grpc::ServerContext *context,
					 const kinetum::control::v1::ConfigureGuardrailsRequest *request,
					 kinetum::control::v1::ConfigureGuardrailsResponse *response) override;

	/**
	 * @brief Get current guardrails policy via gRPC.
	 *
	 * Returns the current guardrails configuration including:
	 * - Whether guardrails are enabled
	 * - Polling and evaluation intervals
	 * - Threshold values for rollback
	 *
	 * @param context Borrowed gRPC server context.
	 * @param request Empty request.
	 * @param response Cleared destination for optional policy and exact identity.
	 * @return Transport OK with application status in @p response, transport
	 *         INVALID_ARGUMENT for a null direct invocation, or transport
	 *         UNAVAILABLE when the response cannot be represented.
	 *
	 * @par Thread Safety
	 * Thread-safe. Reads the config store's coherent durable record.
	 */
	grpc::Status GetGuardrails(grpc::ServerContext *context,
				   const kinetum::control::v1::GetGuardrailsRequest *request,
				   kinetum::control::v1::GetGuardrailsResponse *response) override;

	// ---------------------------------------------------------------------------
	// Health Check
	// ---------------------------------------------------------------------------

	/**
	 * @brief Check control-plane service health and readiness.
	 *
	 * Serving means the gRPC surface can answer; it does not attest mutation
	 * authority or Data Plane packet readiness.
	 *
	 * @param context Borrowed gRPC server context.
	 * @param request Empty request.
	 * @param response Destination for serving state, version, and uptime.
	 * @return Transport OK with one exact health projection, transport
	 *         INVALID_ARGUMENT for a null direct invocation, or transport
	 *         UNAVAILABLE when the response cannot be represented.
	 *
	 * @par Thread Safety
	 * Thread-safe. Only immutable identity and monotonic elapsed time are read.
	 */
	grpc::Status HealthCheck(grpc::ServerContext *context, const kinetum::control::v1::HealthCheckRequest *request,
				 kinetum::control::v1::HealthCheckResponse *response) override;

	// ---------------------------------------------------------------------------
	// Monitoring and Statistics
	// ---------------------------------------------------------------------------

	/**
	 * @brief Get one all-or-none Control Plane and Data Plane observation.
	 *
	 * @param context Live incoming gRPC context carrying deadline and cancellation.
	 * @param request Explicit shared selection forwarded exactly to Data Plane.
	 * @param response Cleared destination for status, active identity, and
	 *                 selected telemetry.
	 * @return Transport OK with the aggregate application outcome, transport
	 *         INVALID_ARGUMENT for a null direct invocation, or transport
	 *         UNAVAILABLE when the response cannot be represented.
	 *
	 * CP and DP fields are published only when transport, DP application status,
	 * runtime telemetry, and both active-authority fence reads all agree. Every
	 * failure leaves a status-only response. One downstream call inherits caller
	 * cancellation and the earlier of its deadline and the local 30-second cap.
	 *
	 * @par Thread Safety
	 * Thread-safe. No platform lock is held across the Data Plane callback.
	 */
	grpc::Status GetStats(grpc::ServerContext *context, const kinetum::control::v1::StatsRequest *request,
			      kinetum::control::v1::StatsResponse *response) override;

    private:
	// ---------------------------------------------------------------------------
	// Member Variables
	// ---------------------------------------------------------------------------

	config_store *store_{nullptr};					      ///< Persistent snapshot storage.
	std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> dp_;  ///< Data Plane stub.

	// ---------------------------------------------------------------------------
	// Single Shared Authority (eliminates split-brain)
	// ---------------------------------------------------------------------------
	// All config mutations AND guardrails policy changes go through this single
	// shared control_loop. No owned loop fallback - single mutation authority.
	// The runner reads the loop's RCU projection; GetGuardrails reads durable truth.
	control_loop &loop_;  ///< Sole shared semantic mutation authority.

	// Service startup time (for uptime tracking)
	std::chrono::steady_clock::time_point start_time_{
		std::chrono::steady_clock::now()};  ///< Monotonic service start for uptime projection.
};

}  // namespace kinetum::cp
