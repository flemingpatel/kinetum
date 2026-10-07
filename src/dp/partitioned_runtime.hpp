// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file partitioned_runtime.hpp
 * @brief Complete bootstrap and live configuration-transition runtime owner.
 * @author Fleming Patel
 *
 * Construction consumes one move-only authority containing the canonical plan,
 * its sole compiled topology, the exact admitted provider catalog, the exact
 * module images, and one generation identity. It transactionally materializes
 * providers, the sole transition coordinator and frozen participants,
 * lifecycle services, DATA/CUT/ACK boundary channels, role-correct endpoint-
 * policy claims, local activation projections, and pre-resolved workers,
 * then publishes CONTROL_READY without enabling RX or launching packet work.
 *
 * Concurrent control producers submit fixed records through one plan-sized
 * mailbox to the main/coordinator thread. One exact Bootstrap request binds the
 * retry identity, stages its canonical snapshot, prepares every module context,
 * activates each context on its sole packet owner, publishes the fixed epoch,
 * proves every worker RUNNING, activates complete cold ingress, and only then
 * releases packet bodies. Prepare, Activate, Abort, and Status own exact
 * transaction admission, asynchronous cold preparation, cancellation,
 * prepared-lease expiry, ordered worker switching, journaling, and exact
 * reclamation through the same coordinator.
 *
 * @par Thread Safety
 * Foreign producers wait unconditionally after successful mailbox enqueue,
 * including while Prepare and the original Activate context remain
 * consumer-owned across lifecycle and transition-completion turns.
 * Only the runtime-service-bound coordinator thread consumes commands, closes
 * admission, or calls shutdown(); self-submission rejects before enqueue and a
 * foreign shutdown is terminate-class. Runtime-status, transition-progress,
 * and worker-ownership reads are lock-free. The caller closes command
 * admission and stops serving RPCs before destruction begins. Internal
 * telemetry collection is cold and serialized against aggregate commits; it
 * never locks or reads a packet-worker owner line.
 *
 * @par Performance
 * All graph resolution, allocation, module lifecycle, and provider validation
 * are cold. Packet workers execute only pre-resolved kernels and bounded SPSC
 * ownership transfers after bootstrap.
 */

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include "src/common/sha256.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_transition_coordinator.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/publication_read_result.hpp"
#include "src/dp/packet_runtime_generation.hpp"
#include "src/dp/runtime_status.hpp"
#include "src/dp/runtime_telemetry.hpp"

namespace kinetum::dataplane::v1
{
class BootstrapConfigSnapshotRequest;
class PrepareConfigSnapshotRequest;
class ActivateConfigSnapshotRequest;
class AbortPreparedConfigSnapshotRequest;
class GetEpochTransitionStatusRequest;
}  // namespace kinetum::dataplane::v1

namespace kinetum::dp
{

/** @brief Exact successful fixed-epoch bootstrap observation. */
struct fixed_epoch_bootstrap_result {
	uint64_t restored_epoch{0};			   ///< Exact activated bootstrap epoch.
	kinetum::common::sha256_digest validation_hash{};  ///< Canonical snapshot validation identity.
	uint64_t allocated_epoch_high_watermark{0};	   ///< Echoed durable CP allocator watermark.
	uint64_t mutation_sequence_high_watermark{0};	   ///< Echoed durable CP mutation watermark.
};

/** @brief Sole owner of one complete materialized packet-runtime generation. */
class partitioned_runtime final {
    public:
	/**
	 * @brief Construct one complete control-ready packet generation.
	 *
	 * No partial/default constructor exists. Validation and module INIT failures
	 * before provider materialization are recoverable. Once a process facility
	 * has materialized, every later construction failure performs exact reverse
	 * cleanup and terminates so the process cannot reuse foreign runtime state.
	 *
	 * @param input Complete move-only generation authority.
	 * @return Unique CONTROL_READY runtime, or a pre-materialization failure.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<partitioned_runtime>>
	create(packet_runtime_generation_input input);

	/** @brief Runtime generations cannot be copied. */
	partitioned_runtime(const partitioned_runtime &) = delete;
	/** @brief Runtime generations cannot be copy-assigned. */
	partitioned_runtime &operator=(const partitioned_runtime &) = delete;
	/** @brief Runtime generations cannot be moved. */
	partitioned_runtime(partitioned_runtime &&) = delete;
	/** @brief Runtime generations cannot be move-assigned. */
	partitioned_runtime &operator=(partitioned_runtime &&) = delete;

	/** @brief Stop and retire the complete generation before releasing its code. */
	~partitioned_runtime();

	/**
	 * @brief Restore one exact durable bootstrap request and admit packet work.
	 *
	 * @param request Complete six-field durable CP authority.
	 * @return Exact activated identity, validation hash, and watermarks; otherwise
	 *         a pre-activation failure with no packet admission. A retry after a
	 *         bound attempt must serialize byte-for-byte identically. The bound
	 *         coordinator consumer cannot call this producer method.
	 */
	[[nodiscard]] kinetum::common::status_or<fixed_epoch_bootstrap_result>
	bootstrap(const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &request);

	/**
	 * @brief Submit one plan-bound immutable candidate for exact preparation.
	 *
	 * @param request Exact CP-allocated candidate request.
	 * @return Fixed typed admission, retry, conflict, or capacity result.
	 */
	[[nodiscard]] epoch_transition_operation_result
	prepare_epoch_transition(const kinetum::dataplane::v1::PrepareConfigSnapshotRequest &request) noexcept;

	/**
	 * @brief Commit one exact PREPARED transaction through ordered worker activation.
	 *
	 * The first exact caller waits unconditionally through COMPLETE or
	 * update-frozen RETIRING. Exact retries during COMMITTING/RETIRING observe the
	 * existing transaction and never publish another worker command.
	 *
	 * @param request Exact PREPARED transaction identity.
	 * @return Fixed typed active, terminal, conflict, or state result.
	 */
	[[nodiscard]] epoch_transition_operation_result
	activate_epoch_transition(const kinetum::dataplane::v1::ActivateConfigSnapshotRequest &request) noexcept;

	/**
	 * @brief Submit one exact pre-commit Abort transaction.
	 *
	 * @param request Exact transaction identity to abort.
	 * @return Fixed typed terminal, retry, conflict, or state result.
	 */
	[[nodiscard]] epoch_transition_operation_result
	abort_epoch_transition(const kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest &request) noexcept;

	/**
	 * @brief Submit one exact transition-status lookup.
	 *
	 * @param request Exact transaction identity to resolve.
	 * @return Fixed typed active, terminal, stale, expired, or unknown result.
	 */
	[[nodiscard]] epoch_transition_operation_result
	query_epoch_transition(const kinetum::dataplane::v1::GetEpochTransitionStatusRequest &request) noexcept;

	/** @return Nonblocking mailbox event descriptor consumed by the process owner. */
	[[nodiscard]] int command_notification_descriptor() const noexcept;
	/**
	 * @brief Borrow the aggregate lifecycle-result wake descriptor while services exist.
	 * @return Live nonblocking descriptor, or nullopt after generation teardown.
	 */
	[[nodiscard]] std::optional<int> lifecycle_notification_descriptor() const noexcept;

	/**
	 * @brief Consume one wake, execute one command, and re-arm the bounded remainder.
	 *
	 * Only the exact coordinator thread may call this method.
	 *
	 * @return OK after one command turn or a descriptor-read error.
	 */
	[[nodiscard]] kinetum::common::status service_command_notifications() noexcept;
	/**
	 * @brief Consume one wake and drain every currently available lifecycle result.
	 * @return OK after bounded advancement, or the exact descriptor/orchestration failure.
	 */
	[[nodiscard]] kinetum::common::status service_lifecycle_notifications() noexcept;

	/**
	 * @brief Apply a due preparation, cancellation-grace, or prepared-lease timer.
	 *
	 * Only the exact coordinator thread may call this method.
	 *
	 * @return OK after bounded coordinator advancement. An unresponsive foreign
	 *         callback is terminate-class and does not return FAILED_STOP as an
	 *         ordinary reusable status.
	 */
	[[nodiscard]] kinetum::common::status service_control_deadline() noexcept;

	/**
	 * @brief Return the current behavior-driving control deadline.
	 *
	 * Only the exact coordinator thread may call this method.
	 *
	 * @return Exact steady-clock deadline, or nullopt when no transition timer is armed.
	 */
	[[nodiscard]] std::optional<std::chrono::steady_clock::time_point> next_control_deadline() const noexcept;

	/**
	 * @brief Permanently close submission and complete all queued commands unavailable.
	 *
	 * Only the exact coordinator thread may call this method. It is idempotent.
	 */
	void close_command_admission() noexcept;

	/**
	 * @brief Stop workers, prove provider ingress cold, then retire bootstrap state and services.
	 *
	 * Repeated calls on the bound coordinator thread after complete shutdown are
	 * harmless. A foreign-thread call terminates. Any ownership or
	 * native-retirement violation fails stop rather than releasing a dependency
	 * still reachable from foreign code.
	 */
	void shutdown() noexcept;

	/** @return Sole immutable runtime-status publication. */
	[[nodiscard]] const runtime_status_publication &status_publication() const noexcept;

	/**
	 * @brief Collect one coherent internal telemetry snapshot for this generation.
	 *
	 * This is the same production source the final operator mapping consumes. It
	 * exposes no live owner state and does not change the current GetStats fence.
	 *
	 * @param request Exact requested internal row subsets.
	 * @return Complete owner-bank aggregate or a fail-closed availability error.
	 */
	[[nodiscard]] kinetum::common::status_or<runtime_telemetry_snapshot>
	collect_runtime_telemetry(const runtime_telemetry_request &request) const;

	/**
	 * @brief Read the coordinator's coherent internal transition progress.
	 *
	 * This is the sole read-only seam for status admission. It does not expose
	 * mutable state or enable a live transition.
	 *
	 * @param out Observer-owned value updated only on success.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result
	try_read_transition_progress(epoch_transition_progress_snapshot &out) const noexcept;

	/**
	 * @brief Read one exact worker's coherent epoch ownership publication.
	 *
	 * This bounded accessor is the sole runtime observation seam for worker
	 * ownership. The accessor itself neither reads owner-local counters nor
	 * authorizes capacity, activation, quiescence, or retirement.
	 *
	 * @param worker_index Exact compact worker identity.
	 * @param[out] out Observer-owned value updated only on success.
	 * @return Availability or a coherent identity/state violation; an unknown worker is invalid identity.
	 */
	[[nodiscard]] publication_read_result
	try_read_worker_epoch_ownership(uint32_t worker_index, worker_epoch_ledger_snapshot &out) const noexcept;

	/** @return Exact frozen plan content hash used by transition status responses. */
	[[nodiscard]] std::string_view transition_plan_content_hash() const noexcept;

    private:
	class implementation;

	/**
	 * @brief Adopt one completely constructed control-ready implementation.
	 *
	 * @param implementation Sole complete runtime-generation owner.
	 */
	explicit partitioned_runtime(std::unique_ptr<implementation> implementation) noexcept;

	std::unique_ptr<implementation> implementation_;  ///< Sole complete runtime generation owner.
};

}  // namespace kinetum::dp
