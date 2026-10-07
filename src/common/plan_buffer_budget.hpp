// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file plan_buffer_budget.hpp
 * @brief Provider-neutral packet-storage credit budget authority.
 * @author Fleming Patel
 *
 * This component preserves the one checked ten-term packet-credit formula
 * independently from any provider schema or native pool. The shared provider
 * topology compiler supplies already-proven ownership terms for one storage
 * domain; no driver, storage implementation, planner, or materializer may
 * reconstruct this arithmetic.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent calls.
 *
 * @par Performance
 * Allocation-using cold-path validation only. It is unreachable from packet
 * workers and provider burst operations.
 */

#include <cstdint>
#include <string>

#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Proven topology inputs for one storage-domain credit budget.
 *
 * Descriptor, worker-staging, boundary, and future-hold counts are complete
 * sums for the domain. `worker_count` selects only the formula-owned burst-
 * slack and per-worker cache terms; active queue capacity is supplied as one
 * exact independently checked aggregate.
 */
struct storage_domain_buffer_budget_inputs {
	std::string storage_domain_id;		     ///< Exact plan-owned domain identity.
	uint64_t declared_buffer_count{0};	     ///< Exact authored physical capacity.
	uint64_t rx_descriptor_count{0};	     ///< RX descriptors retaining domain credits.
	uint64_t tx_descriptor_count{0};	     ///< TX descriptors retaining caller credits.
	uint64_t worker_count{0};		     ///< Exact workers staging this domain.
	uint64_t worker_staging_capacity{0};	     ///< Exact aggregate active worker-queue credits.
	uint64_t handoff_staging_capacity{0};	     ///< Boundary and bounded-copy credits for this domain.
	uint64_t source_future_staging_capacity{0};  ///< Source-worker future-role credits.
	uint64_t future_output_capacity{0};	     ///< Boundary future-output credits.
	uint64_t active_retained_capacity{0};	     ///< Active-instance retained-record credits.
	uint64_t cache_size_per_worker{0};	     ///< Provider-local cache reservation.
};

/**
 * @brief Validated minimum packet population for one storage domain.
 */
struct compiled_storage_domain_buffer_budget {
	std::string storage_domain_id;	   ///< Exact plan-owned domain identity.
	uint64_t required_min_buffers{0};  ///< Complete checked ten-term floor.
	uint32_t safety_margin{0};	   ///< Formula-owned packet-burst safety term.
};

/**
 * @brief Validate and compile one exact storage-domain packet-credit floor.
 *
 * The ten additive terms are RX descriptors, TX descriptor slack,
 * exact active worker staging, handoff staging capacity, source-future staging,
 * future-output capacity, active-instance retained records, worker burst slack,
 * per-worker provider caches, and one formula-owned `PACKET_MAX_BURST_SIZE`
 * safety margin. Multiplication and addition are checked before mutation. A
 * declared capacity below the result rejects. Callers cannot scale or replace
 * the safety policy.
 *
 * The caller must first prove that all counts belong to this exact domain.
 * This function owns arithmetic, not graph reachability.
 *
 * @param inputs Complete compiled terms for one storage domain.
 * @return Exact budget, or a fail-closed status for malformed identity,
 *         missing ownership/capacity, overflow, or insufficient capacity.
 */
[[nodiscard]] status_or<compiled_storage_domain_buffer_budget>
compile_storage_domain_buffer_budget(const storage_domain_buffer_budget_inputs &inputs);

}  // namespace kinetum::common
