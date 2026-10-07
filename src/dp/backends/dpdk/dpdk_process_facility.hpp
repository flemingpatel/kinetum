// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dpdk_process_facility.hpp
 * @brief Exact DPDK EAL process-facility ownership.
 * @author Fleming Patel
 *
 * The facility is the sole owner of one DPDK EAL generation. It renders EAL
 * arguments from compiled provider-neutral facts, resolves every declared
 * native attachment, registers externally launched packet-worker threads, and
 * launches exact lifecycle-service lcores. Packet storage and I/O instances
 * borrow this owner through the provider-component dependency relation and
 * must be destroyed before it.
 *
 * Native function pointers exist only for cold deterministic conformance
 * tests. Packet RX/TX and storage operations do not dispatch through this
 * table.
 */

#include <cstdint>
#include <cstdio>
#include <memory>

#include "src/provider/provider_component_abi.h"

namespace kinetum::provider::dpdk_component
{

/** @brief Native DPDK process-facility calls, all cold-path only. */
struct dpdk_process_facility_api {
	void *state;						       ///< Optional injected native state.
	int (*eal_init)(void *state, int argc, char **argv) noexcept;  ///< Initialize one EAL generation.
	int (*eal_cleanup)(void *state) noexcept;		       ///< Retire the owned EAL generation.
	int (*open_log_stream)(void *state,
			       FILE *stream) noexcept;	     ///< Register or detach the caller-owned native log stream.
	int (*current_log_level)(void *state) noexcept;	     ///< Exact current native message severity.
	int (*thread_register)(void *state) noexcept;	     ///< Register the calling external packet thread.
	void (*thread_unregister)(void *state) noexcept;     ///< Unregister the calling packet thread.
	uint32_t (*current_lcore_id)(void *state) noexcept;  ///< Return the calling thread's native lcore.
	uint32_t (*main_lcore_id)(void *state) noexcept;     ///< Return EAL's exact main lcore.
	int (*lcore_is_enabled)(void *state, uint32_t lcore_id) noexcept;  ///< Test one exact EAL lcore.
	int (*remote_launch)(void *state, int (*entry)(void *), void *argument,
			     uint32_t lcore_id) noexcept;  ///< Launch one EAL service callback.
	/** Wait for one launched EAL lcore and return its callback result. */
	int (*wait_lcore)(void *state, uint32_t lcore_id) noexcept;
	int (*current_cpu)(void *state) noexcept;  ///< Return the calling Linux CPU.
	/** Resolve one admitted ethdev name. */
	int (*eth_port_by_name)(void *state, const char *name, uint16_t *port_id) noexcept;
	const char *(*runtime_version)(void *state) noexcept;  ///< Return linked DPDK runtime version text.
	uint32_t unassigned_lcore_id;			       ///< Exact native unassigned-lcore sentinel.
};

/**
 * @brief Return the complete production DPDK facility API.
 *
 * @return Immutable value table over the linked DPDK and Linux APIs.
 */
[[nodiscard]] dpdk_process_facility_api default_dpdk_process_facility_api() noexcept;

/**
 * @brief Process-generation owner for one exact DPDK EAL facility.
 *
 * Construction allocates and validates all host-owned state before EAL is
 * invoked. Destruction requires every packet-thread registration and remote
 * lifecycle service to be retired, then calls EAL cleanup exactly once. Any
 * unresolved native ownership fails stop before dependent memory can be
 * reclaimed.
 *
 * @par Thread Safety
 * Packet-worker registration slots and native-lcore claims are independent
 * atomics. Runtime-service operations are single-coordinator cold-path calls.
 * Attachment lookup is immutable after construction.
 */
class dpdk_process_facility final {
    public:
	/** @brief Disable copying because one object owns one EAL generation. */
	dpdk_process_facility(const dpdk_process_facility &) = delete;
	/** @brief Disable copy assignment because EAL ownership is linear. */
	dpdk_process_facility &operator=(const dpdk_process_facility &) = delete;
	/** @brief Disable moves because published operation state retains this address. */
	dpdk_process_facility(dpdk_process_facility &&) = delete;
	/** @brief Disable move assignment because published operation state is stable. */
	dpdk_process_facility &operator=(dpdk_process_facility &&) = delete;

	/** @brief Retire one quiescent EAL generation exactly once. */
	~dpdk_process_facility() noexcept;

	/**
	 * @brief Construct and initialize one exact DPDK process facility.
	 *
	 * @param request Empty canonical DPDK facility request and complete facts.
	 * @param api Complete cold native mechanism; copied into the owner.
	 * @param[out] output Empty owner receiving the initialized facility.
	 * @param diagnostic Optional caller-owned bounded diagnostic.
	 * @return OK only after EAL and every compiled attachment are resolved.
	 *
	 * Validation and host-state allocation failures before the EAL call are
	 * recoverable. Once EAL initialization is attempted, a failed native return
	 * terminates the process because clean rollback of partial process-global
	 * state is not a supported DPDK contract.
	 */
	[[nodiscard]] static kinetum_provider_status create(const kinetum_provider_factory_request &request,
							    const dpdk_process_facility_api &api,
							    std::unique_ptr<dpdk_process_facility> &output,
							    kinetum_provider_diagnostic *diagnostic) noexcept;

	/** @return Borrowed immutable process-facility operations, valid for this owner's lifetime. */
	[[nodiscard]] const kinetum_provider_process_facility_operations &operations() const noexcept;

	/**
	 * @brief Resolve one exact driver attachment to its EAL-owned ethdev port.
	 *
	 * @param attachment Canonical driver attachment from the dependent request.
	 * @param[out] physical_port Exact resolved ethdev ID.
	 * @return true only when every attachment identity field matches one facility row.
	 */
	[[nodiscard]] bool resolve_physical_port(const kinetum_provider_driver_attachment_fact &attachment,
						 uint16_t &physical_port) const noexcept;

	/**
	 * @brief Prove one storage request matches an aggregated facility memory row.
	 *
	 * @param facts Exact packet-storage facts from the dependent factory.
	 * @return true only when all memory, cache, and NUMA fields match one row.
	 */
	[[nodiscard]] bool contains_memory_domain(const kinetum_provider_packet_storage_facts &facts) const noexcept;

	/** @return true while this object owns its initialized EAL generation. */
	[[nodiscard]] bool active() const noexcept;

    private:
	struct implementation;

	/**
	 * @brief Adopt one fully preallocated implementation before EAL initialization.
	 * @param state Sole implementation owner transferred into this facility.
	 */
	explicit dpdk_process_facility(std::unique_ptr<implementation> state) noexcept;

	/**
	 * @brief Reclaim the owned EAL generation and terminate after a post-init failure.
	 *
	 * Once EAL initialization succeeds, foreign helper state may survive cleanup.
	 * Claiming cleanup before the native call guarantees one attempt, while
	 * termination makes the operating system the final reclamation boundary.
	 */
	[[noreturn]] void fail_stop_after_eal_() noexcept;

	/**
	 * @brief Register the calling packet worker with this EAL generation.
	 * @param state Borrowed live facility.
	 * @param worker_index Exact compiled worker identity assigned to the caller.
	 * @param diagnostic Optional caller-owned bounded failure diagnostic.
	 * @return OK after registration and placement proof, or an explicit admission or native failure.
	 */
	static kinetum_provider_status register_worker_thread_(void *state, uint32_t worker_index,
							       kinetum_provider_diagnostic *diagnostic) noexcept;
	/**
	 * @brief Retire the calling worker's exact EAL registration.
	 * @param state Borrowed live facility.
	 * @param worker_index Exact registered worker identity; inconsistent ownership fails stop.
	 */
	static void unregister_worker_thread_(void *state, uint32_t worker_index) noexcept;
	/**
	 * @brief Prove the caller is the compiled coordinator on the EAL main lcore.
	 * @param state Borrowed live facility.
	 * @param service_index Compiled coordinator service index.
	 * @param cpu_core_id Exact assigned CPU and EAL lcore identity.
	 * @param diagnostic Optional caller-owned bounded failure diagnostic.
	 * @return OK for exact placement; INVALID_ARGUMENT or FAILED_PRECONDITION otherwise.
	 */
	static kinetum_provider_status
	bind_runtime_service_coordinator_(void *state, uint32_t service_index, int32_t cpu_core_id,
					  kinetum_provider_diagnostic *diagnostic) noexcept;
	/**
	 * @brief Launch one compiled lifecycle executor on its EAL lcore.
	 * @param state Borrowed live facility.
	 * @param service_index Compiled executor service index.
	 * @param cpu_core_id Exact assigned CPU and EAL lcore identity.
	 * @param entry Non-null callback retained until the matching join completes.
	 * @param argument Non-null callback state borrowed through that join.
	 * @param diagnostic Optional caller-owned bounded failure diagnostic.
	 * @return OK after launch; failure leaves no launched callback ownership.
	 */
	static kinetum_provider_status launch_runtime_service_(void *state, uint32_t service_index, int32_t cpu_core_id,
							       kinetum_provider_runtime_service_entry_fn entry,
							       void *argument,
							       kinetum_provider_diagnostic *diagnostic) noexcept;
	/**
	 * @brief Join one owned lifecycle executor before releasing its callback borrows.
	 * @param state Borrowed live facility.
	 * @param service_index Exact launched executor index.
	 * @param cpu_core_id Exact assigned CPU and EAL lcore identity.
	 * @param diagnostic Optional caller-owned bounded failure diagnostic.
	 * @return OK after native join, or an argument/ownership error before waiting.
	 */
	static kinetum_provider_status join_runtime_service_(void *state, uint32_t service_index, int32_t cpu_core_id,
							     kinetum_provider_diagnostic *diagnostic) noexcept;
	/**
	 * @param state Launched service slot retaining its callback and argument; malformed state fails stop.
	 * @return Exact executor callback result converted to the EAL entry's int representation.
	 */
	static int runtime_service_entry_(void *state) noexcept;

	std::unique_ptr<implementation> state_;			     ///< Complete process-generation state.
	kinetum_provider_process_facility_operations operations_{};  ///< Published exact operations.
};

}  // namespace kinetum::provider::dpdk_component
