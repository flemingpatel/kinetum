// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_worker_kernel.hpp
 * @brief Pre-resolved generation-scoped provider-neutral packet worker.
 * @author Fleming Patel
 *
 * One kernel owns one compiled packet worker. Cold construction resolves every
 * RX source, TX sink, storage operation, storage transition, route, boundary,
 * module context, and provider-facility registration dependency into compact
 * array indices and immutable function targets. The running loop consequently
 * performs provider dispatch once per burst, never once per packet.
 *
 * Packet metadata remains the sole writable epoch and stage authority. The
 * bounded owner-local work item carries only a packet pointer and an execution
 * phase; it never duplicates epoch, stage, port, storage, or provider identity.
 * One formula-sized canonical SPSC ring per reachable storage domain owns local
 * staging. One cache-line-separated worker epoch ledger counts logical packet
 * work by the record's exact epoch; local slot reservations remain capacity
 * proofs and never become quiescence evidence. Transition, TX, and release
 * calls are grouped into bounded bursts.
 *
 * Every cross-worker route resolves one direct ordinal in the worker's sole
 * `worker_boundary_sender`. A mirrored `worker_boundary_receiver` owns CUT
 * drain and ACK policy, while one immutable local activation projection orders
 * module publication, queue-role rotation, and ledger promotion. One immutable
 * runtime-command publication carries RUN, TRANSITION, and STOP. Fixed
 * Bootstrap remains on the predicted OPEN DATA path, while a changed command
 * pointer enters the complete transition arm at a worker-turn boundary.
 * Worker entry selects passive, synchronous-active, or tracked-async loop
 * code once from the constructed stage resources. Only the tracked-async form
 * polls completion/cancellation state; the synchronous form contains no async
 * token or queue operation.
 *
 * @par Thread Safety
 * A kernel is constructed and destroyed by the generation coordinator and run
 * exactly once by its sole packet-worker thread. Packet counters and epoch
 * credits are plain owner-local values. Ordinary counters may be inspected only
 * after join; foreign epoch observers consume only the coherent ledger
 * publication. Cross-worker ownership uses exact sender/receiver policy owners
 * over compiled boundary epoch channels; fixed Bootstrap exercises DATA while
 * typed control and future holds remain empty outside a committed transition.
 *
 * @par Performance
 * After construction the loop performs no allocation, lock, exception,
 * protobuf access, string operation, provider lookup, RTTI, virtual dispatch,
 * logging, or per-packet atomic accounting. Cold construction selects the
 * homogeneous source callback once and compiles storage reachability into a
 * fixed-universe membership set, so source dispatch is not repeated and each
 * executable-domain check is O(1). The fixed boundary path adds one predicted
 * owner-local OPEN/epoch branch. One cached monotonic timestamp is refreshed per
 * worker turn and stamped on every RX record admitted in it. The command
 * publication is the same sole acquire load that owns shutdown observation.
 * RX streams and inbound DATA share bounded fair admission. A capacity-limited
 * input retains its unfinished allowance while independent inputs may proceed;
 * service never scans queued packet depth or adds a packet-holding owner.
 */

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "src/common/status_or.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/publication_read_result.hpp"

namespace kinetum::algo
{
class quiescence_reader;
}  // namespace kinetum::algo

namespace kinetum::provider
{
class materialized_provider_runtime;
struct compiled_provider_topology;
}  // namespace kinetum::provider

namespace kinetum::dp
{

class boundary_epoch_channel;
struct epoch_transition_certificate_worker_source;
class worker_boundary_receiver;
class worker_boundary_sender;
class worker_runtime_command_publication;
class worker_runtime_telemetry;

namespace lifecycle
{
class lifecycle_context_owner;
}  // namespace lifecycle

namespace module
{
class module_manager;
}  // namespace module

/** @brief One nonmovable pre-resolved packet-worker generation kernel. */
class packet_worker_kernel final {
    public:
	/**
	 * @brief Construct one complete worker kernel without starting packet work.
	 *
	 * @param worker_index Exact compact worker identity.
	 * @param topology Sole compiled provider/transition topology authority.
	 * @param providers Complete materialized provider generation.
	 * @param modules Complete module generation; it may be empty only when the
	 *        worker owns no module stage.
	 * @param commands Sole process-generation transition/stop publication.
	 * @param boundaries Complete compact-indexed epoch-channel pointer table.
	 * @param boundary_sender Sole complete outbound sender-policy authority.
	 * @param boundary_receiver Sole complete inbound receiver-policy authority.
	 * @param telemetry Exact worker-local telemetry banks.
	 * @param protocol_faults Process-generation transition-safety fault authority.
	 * @param module_telemetry Exact module-context telemetry owners for this worker.
	 * @return Unique complete kernel, or a fail-closed cold validation status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<packet_worker_kernel>>
	create(uint32_t worker_index, const provider::compiled_provider_topology &topology,
	       const provider::materialized_provider_runtime &providers, module::module_manager &modules,
	       worker_runtime_command_publication &commands, const std::vector<boundary_epoch_channel *> &boundaries,
	       std::unique_ptr<worker_boundary_sender> boundary_sender,
	       std::unique_ptr<worker_boundary_receiver> boundary_receiver, worker_runtime_telemetry &telemetry,
	       epoch_protocol_fault_latch &protocol_faults,
	       std::span<lifecycle::lifecycle_context_owner *const> module_telemetry);

	/** @brief Destroy only after run() has returned or before it starts. */
	~packet_worker_kernel();

	/** @brief Worker kernels cannot be copied. */
	packet_worker_kernel(const packet_worker_kernel &) = delete;
	/** @brief Worker kernels cannot be copy-assigned. */
	packet_worker_kernel &operator=(const packet_worker_kernel &) = delete;
	/** @brief Worker kernels cannot be moved after pointer resolution. */
	packet_worker_kernel(packet_worker_kernel &&) = delete;
	/** @brief Worker kernels cannot be move-assigned after pointer resolution. */
	packet_worker_kernel &operator=(packet_worker_kernel &&) = delete;

	/**
	 * @brief Bind the already activated bootstrap epoch on the sole owner worker.
	 *
	 * Every module ACTIVATE callback must have completed before this call. The
	 * method validates all exact owner-local executable views and then publishes
	 * the immutable epoch used by RX stamping and packet execution. It performs
	 * no allocation, lock, I/O, parsing, logging, or foreign callback. Calling it
	 * with incomplete or competing activation state terminates because the first
	 * module ACTIVATE has already crossed the irreversible boundary.
	 *
	 * @param bootstrap_epoch Exact valid epoch activated for every owned module
	 *        context, below the reserved wrap sentinel.
	 * @param now_ns Sole owner-worker cached monotonic publication timestamp.
	 */
	void bind_bootstrap_epoch(uint64_t bootstrap_epoch, uint64_t now_ns) noexcept;

	/**
	 * @brief Run packet work until generation shutdown drains the worker DAG.
	 *
	 * The sole runtime-command publication closes RX admission with STOP. The
	 * worker then drains its local staging and every inbound boundary, waits for every
	 * inbound producer to close, closes its outbound producers exactly once,
	 * flushes each owned TX queue, and returns.
	 *
	 */
	void run() noexcept;

	/** @return Exact compact worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept;

	/**
	 * @brief Read one coherent worker-owned epoch-accounting publication.
	 *
	 * The output remains unchanged when the worker has not bound Bootstrap or a
	 * coherent observation is unavailable. No foreign reader accesses mutable
	 * owner counters through this method.
	 *
	 * @param[out] out Observer-owned value updated only on success.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result
	try_read_epoch_ownership(worker_epoch_ledger_snapshot &out) const noexcept;

	/**
	 * @brief Expose one stable unbound reader record during cold construction.
	 *
	 * The runtime binds the address into its exact domain before worker launch.
	 * No caller may retain mutable access after CONTROL_READY.
	 *
	 * @return Stable caller-owned reader storage for this worker.
	 */
	[[nodiscard]] kinetum::algo::quiescence_reader &quiescence_reader_registration() noexcept;

	/**
	 * @brief Return the complete immutable certificate publication source set.
	 *
	 * @return Exact const-only ledger, activation, endpoint-owner, and reader pointers.
	 */
	[[nodiscard]] epoch_transition_certificate_worker_source transition_certificate_source() const noexcept;

    private:
	class implementation;

	/**
	 * @brief Adopt one completely validated cold implementation.
	 *
	 * @param implementation Sole pre-resolved worker implementation owner.
	 */
	explicit packet_worker_kernel(std::unique_ptr<implementation> implementation) noexcept;

	std::unique_ptr<implementation> implementation_;  ///< Stable pre-resolved owner-local state.
};

}  // namespace kinetum::dp
