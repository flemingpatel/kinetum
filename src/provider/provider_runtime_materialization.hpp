// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_runtime_materialization.hpp
 * @brief Transactional ownership of one exact materialized provider graph.
 * @author Fleming Patel
 *
 * This cold authority consumes the sole compiled provider topology and one
 * already admitted provider runtime. It preallocates every platform-owned
 * owner slot and dependency recipe, invokes exact role factories in dependency
 * order, validates every returned operation table, and publishes direct
 * compact-index lookups only after the complete graph agrees in both
 * directions.
 *
 * Construction publishes no partial result. Recoverable failures before a
 * process facility succeeds return a status after exact rollback. A failure
 * after a process facility succeeds first destroys every materialized owner in
 * reverse dependency order and then terminates; a foreign process runtime is
 * never reused for another in-process materialization attempt. The admitted
 * component catalog is retained until every materialized instance is gone.
 *
 * @par Thread Safety
 * Creation and destruction are single-coordinator cold-path operations. A
 * completed object is immutable and its operation-table accessors are safe for
 * concurrent owner-worker reads while the object remains alive. Queue tables
 * retain their separately compiled single-owner calling contracts.
 *
 * @par Performance
 * Factory invocation, diagnostics, and allocation are startup-only. Dependency
 * recipes preserve and linearly verify the compiler's canonical order rather
 * than sorting the same authority again.
 * Accessors perform one bounds check and vector load; packet workers cache the
 * returned pointers before launch and never call a provider catalog.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "src/common/status_or.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_component_abi.h"
#include "src/provider/provider_runtime_admission.hpp"

namespace kinetum::provider
{

/**
 * @brief Complete immutable owner of one materialized provider generation.
 */
class materialized_provider_runtime final {
    public:
	/** @brief Retire every provider instance before releasing component code. */
	~materialized_provider_runtime() noexcept;

	/** @brief Materialized generations have one linear owner. */
	materialized_provider_runtime(const materialized_provider_runtime &) = delete;

	/** @brief Materialized generations cannot be copy-assigned. */
	materialized_provider_runtime &operator=(const materialized_provider_runtime &) = delete;

	/** @brief Stable published operation addresses prohibit moving a generation. */
	materialized_provider_runtime(materialized_provider_runtime &&) = delete;

	/** @brief Stable published operation addresses prohibit move assignment. */
	materialized_provider_runtime &operator=(materialized_provider_runtime &&) = delete;

	/**
	 * @brief Materialize one complete provider graph without partial publication.
	 *
	 * @param admitted Complete requested-only component and C-ABI fact owner.
	 * @param topology Sole immutable compiled provider-topology authority used to
	 *        produce @p admitted.
	 * @param runtime_generation Exact nonzero generation identity representable
	 *        by the packet/provider operation ABI.
	 * @return Unique immutable owner after complete validation, or a recoverable
	 *         pre-facility status. A post-facility failure does not return.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<materialized_provider_runtime>>
	create(admitted_provider_runtime admitted, const compiled_provider_topology &topology,
	       uint64_t runtime_generation);

	/** @return Exact nonzero materialized generation identity. */
	[[nodiscard]] uint64_t runtime_generation() const noexcept;

	/**
	 * @param facility_index Exact compact process-facility index.
	 * @return Exact process-facility operation record, or null when out of range.
	 */
	[[nodiscard]] const kinetum_provider_process_facility_operations *
	process_facility(uint32_t facility_index) const noexcept;

	/**
	 * @param storage_domain_index Exact compact packet-storage-domain index.
	 * @return Exact packet-storage operation record, or null when out of range.
	 */
	[[nodiscard]] const kinetum_packet_storage_domain_operations *
	storage_domain(uint32_t storage_domain_index) const noexcept;

	/**
	 * @param io_driver_index Exact compact I/O-driver index.
	 * @return Exact I/O-driver operation record, or null when out of range.
	 */
	[[nodiscard]] const kinetum_provider_io_driver_operations *io_driver(uint32_t io_driver_index) const noexcept;

	/**
	 * @param execution_provider_index Exact compact execution-provider index.
	 * @return Exact execution-provider operation record, or null when out of range.
	 */
	[[nodiscard]] const kinetum_provider_execution_operations *
	execution_provider(uint32_t execution_provider_index) const noexcept;

	/**
	 * @param transition_index Exact compact storage-transition index.
	 * @return Exact storage-transition operation record, or null when out of range.
	 */
	[[nodiscard]] const kinetum_provider_storage_transition_operations *
	storage_transition(uint32_t transition_index) const noexcept;

	/**
	 * @param io_stream_index Exact compact I/O-stream index.
	 * @return Pre-resolved RX table, or null for TX/out-of-range streams.
	 */
	[[nodiscard]] const kinetum_packet_rx_burst_operations *rx_stream(uint32_t io_stream_index) const noexcept;

	/**
	 * @param io_stream_index Exact compact I/O-stream index.
	 * @return Pre-resolved TX table, or null for RX/out-of-range streams.
	 */
	[[nodiscard]] const kinetum_packet_tx_burst_operations *tx_stream(uint32_t io_stream_index) const noexcept;

	/** @return Exact number of pre-resolved I/O-stream slots. */
	[[nodiscard]] std::size_t io_stream_count() const noexcept;

	/**
	 * @brief Activate every materialized I/O driver in canonical index order.
	 *
	 * Each foreign callback runs without a platform lock. A valid callback
	 * failure leaves its driver cold; this method then deactivates the already
	 * activated prefix in reverse order. A rollback failure is process-fatal
	 * because at least one receive source retains unresolved live ownership.
	 *
	 * @return OK only when the complete driver set is live, or a valid callback
	 *         failure after the complete set has been restored cold.
	 */
	[[nodiscard]] common::status activate_packet_io() noexcept;

	/**
	 * @brief Deactivate every live I/O driver in reverse canonical order.
	 *
	 * A callback failure retains the exact unresolved live prefix and returns a
	 * failure so the generation owner can fail stop without reclaiming provider
	 * dependencies. No callback runs while a platform lock is held.
	 *
	 * @return OK only when every materialized driver is cold.
	 */
	[[nodiscard]] common::status deactivate_packet_io() noexcept;

	/**
	 * @brief Register one exact packet-worker thread with every owning facility.
	 *
	 * The caller must be the exact compact worker thread. Facility callbacks run
	 * in canonical facility-index order. A failure releases every registration
	 * already established by this call in reverse order before returning. An
	 * out-of-domain callback status fails stop because current-thread native
	 * ownership cannot then be classified as acquired or rejected.
	 *
	 * @param worker_index Exact compact packet-worker identity.
	 * @return OK after complete registration, or a bounded callback/identity
	 *         failure with no retained registration from this call.
	 */
	[[nodiscard]] common::status register_worker_thread(uint32_t worker_index) const noexcept;

	/**
	 * @brief Release every facility registration owned by one packet worker.
	 *
	 * The same exact worker thread that completed register_worker_thread() calls
	 * this once after its packet body returns. Callbacks execute in reverse
	 * facility-index order.
	 *
	 * @param worker_index Exact compact packet-worker identity.
	 */
	void unregister_worker_thread(uint32_t worker_index) const noexcept;

	/**
	 * @brief Return whether one worker has a process-facility thread owner.
	 *
	 * A worker without a facility must use the provider-neutral native affinity
	 * mechanism. A worker with one or more facilities delegates thread setup to
	 * the exact facility callbacks.
	 *
	 * @param worker_index Exact compact packet-worker identity.
	 * @return true when the compiled graph assigns at least one facility.
	 */
	[[nodiscard]] bool worker_uses_process_facility(uint32_t worker_index) const noexcept;

    private:
	/** One preallocated stable owner shell; definition remains private to the implementation. */
	class provider_instance_owner;

	/**
	 * @brief Adopt the admitted code/fact authority before any factory call.
	 *
	 * @param admitted Complete requested-only component and C-ABI fact owner.
	 * @param runtime_generation Exact nonzero generation identity.
	 */
	explicit materialized_provider_runtime(admitted_provider_runtime admitted,
					       uint64_t runtime_generation) noexcept;

	/** @brief Destroy every live instance in exact reverse dependency order. */
	void rollback_instances_() noexcept;

	/**
	 * @brief Log one bounded post-facility failure and terminate without retry.
	 *
	 * @param failure Exact failure observed after foreign facility ownership.
	 */
	[[noreturn]] void fail_stop_after_facility_(const common::status &failure) noexcept;

	// Declaration order is lifetime order: all later members retire before the
	// admitted catalog and its component handles.
	admitted_provider_runtime admitted_;	 ///< Exact component-code and compiled-fact lifetime authority.
	uint64_t runtime_generation_{0};	 ///< Exact nonzero generation identity.
	bool facility_materialized_{false};	 ///< Whether any process facility has successfully returned.
	std::size_t active_io_driver_count_{0};	 ///< Canonical live prefix; zero outside packet readiness.

	std::vector<std::unique_ptr<provider_instance_owner>> process_facilities_;   ///< Facility owner shells.
	std::vector<std::unique_ptr<provider_instance_owner>> storage_domains_;	     ///< Storage owner shells.
	std::vector<std::unique_ptr<provider_instance_owner>> io_drivers_;	     ///< Driver owner shells.
	std::vector<std::unique_ptr<provider_instance_owner>> execution_providers_;  ///< Execution owner shells.
	std::vector<std::unique_ptr<provider_instance_owner>> storage_transitions_;  ///< Transition owner shells.

	std::vector<const kinetum_provider_process_facility_operations *> facility_operations_;	 ///< Direct facilities.
	std::vector<const kinetum_packet_storage_domain_operations *> storage_operations_;	 ///< Direct storage.
	std::vector<const kinetum_provider_io_driver_operations *> driver_operations_;		 ///< Direct drivers.
	std::vector<const kinetum_provider_execution_operations *> execution_operations_;	 ///< Direct execution.
	std::vector<const kinetum_provider_storage_transition_operations *> transition_operations_;  ///< Transitions.
	std::vector<const kinetum_packet_rx_burst_operations *> rx_stream_operations_;	///< Direct RX by stream.
	std::vector<const kinetum_packet_tx_burst_operations *> tx_stream_operations_;	///< Direct TX by stream.
	/** Exact canonical facility-index sequence for every compact packet worker. */
	std::vector<std::vector<uint32_t>> worker_facility_indices_;
	std::vector<kinetum_provider_dependency_handle> dependency_scratch_;  ///< Reused cold factory-call array.
};

}  // namespace kinetum::provider
