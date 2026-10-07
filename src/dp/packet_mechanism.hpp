// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_mechanism.hpp
 * @brief Sole provider-neutral platform and module packet mechanism.
 * @author Fleming Patel
 *
 * The mechanism executes already selected RX admission, IPv4 parsing, TX
 * admission, or one exact module view over the dataplane's sole packet record.
 * It owns no topology, provider catalog, protobuf object, shared counter, or
 * routing policy. The component-facing `dp_engine` and production worker
 * kernels compose this same implementation with their distinct accounting
 * owners.
 *
 * @par Thread Safety
 * Platform mechanisms are stateless. Module execution mutates only the exact
 * packet, owner-local epoch store, and owner-local scratch supplied by one
 * worker. Callers must preserve those sole-writer contracts.
 *
 * @par Performance
 * Every operation is packet-path code: no allocation, lock, shared ownership,
 * exception propagation, virtual dispatch, RTTI, string, logging, or system
 * call is permitted.
 */

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "src/dp/module/module_epoch_store.hpp"
#include "src/dp/packet.hpp"

namespace kinetum::dp
{

/** @brief Pre-resolved platform packet mechanism kind. */
enum class packet_mechanism_kind : uint8_t {
	RX = 1,		 ///< Validate one exact ingress record.
	PARSE_IPV4 = 2,	 ///< Parse contiguous Ethernet/IPv4/L4 facts.
	TX = 3,		 ///< Validate one exact egress disposition.
};

/** @brief Exact accounting classification returned by one mechanism call. */
enum class packet_mechanism_outcome : uint8_t {
	FORWARDED = 1,	   ///< Mechanism admitted the packet without RX/TX accounting.
	FORWARDED_RX = 2,  ///< RX admission succeeded.
	FORWARDED_TX = 3,  ///< TX admission succeeded.
	REJECTED = 4,	   ///< Caller retains the record and must retire it once.
};

/**
 * @brief Reusable owner-worker storage for one module ABI batch.
 *
 * Dispatch overwrites every observable element at each occupied index. It
 * never clears the complete multi-kilobyte batch on the packet path.
 */
struct alignas(64) module_batch_scratch {
	kinetum_batch_t batch{};  ///< Reused exact public-ABI projection.
};

static_assert(alignof(module_batch_scratch) == 64, "module batch scratch alignment changed");
static_assert(sizeof(module_batch_scratch) == sizeof(kinetum_batch_t),
	      "module batch scratch must add no storage overhead");
static_assert(std::is_standard_layout_v<module_batch_scratch>, "module batch scratch must be standard-layout");
static_assert(std::is_trivially_copyable_v<module_batch_scratch>, "module batch scratch must be trivially copyable");

/**
 * @brief Execute one already selected platform packet mechanism.
 *
 * @param kind Exact pre-resolved mechanism.
 * @param packet Sole mutable packet record.
 * @return Exact forwarded/rejected accounting outcome.
 */
[[nodiscard]] packet_mechanism_outcome execute_packet_mechanism(packet_mechanism_kind kind,
								packet_record *packet) noexcept;

/**
 * @brief Validate one complete active-origin batch before storage effects.
 *
 * @param batch Candidate borrowed origin batch.
 * @param maximum_packet_length Exact destination-domain contiguous byte bound.
 * @param logical_stage_count Exact representable module-selected stage namespace.
 * @return true only when every occupied lane is complete and coherent.
 */
[[nodiscard]] bool validate_active_origin_batch(const kinetum_emit_batch_t *batch, uint16_t maximum_packet_length,
						std::size_t logical_stage_count) noexcept;

/**
 * @brief Execute one occupied packet prefix through an exact module context.
 *
 * Every packet/view epoch equality precedes the single foreign callback. A mismatch
 * records bounded owner-local evidence and rejects without invoking module
 * code. A callback ABI violation terminates because foreign state and packet
 * authority can no longer be proved.
 *
 * @param store Exact context-local slot and executable-view authority.
 * @param stage_instance_index Exact executable stage-instance index.
 * @param region_id Sole-owner runtime region.
 * @param packets Borrowed prefix of caller-owned records, at most KINETUM_MAX_BURST.
 * @param scratch Owner-worker reusable ABI batch.
 * @return Sole forward mask. Empty or invalid input rejects before callback effects.
 */
[[nodiscard]] uint64_t execute_module_batch_mechanism(module::module_epoch_store &store, uint16_t stage_instance_index,
						      int32_t region_id, std::span<packet_record *const> packets,
						      module_batch_scratch &scratch) noexcept;

/**
 * @brief Execute one pre-resolved ACTIVE context through exact scheduler services.
 *
 * This is distinct from the passive entry so a passive-only production worker
 * retains its original direct call shape and no active-context argument.
 *
 * @param store Exact context-local slot and executable-view authority.
 * @param stage_instance_index Exact executable stage-instance index.
 * @param region_id Sole-owner runtime region.
 * @param packets Borrowed prefix of caller-owned records for this exact invocation.
 * @param active_ctx Exact callback-borrowed active services.
 * @param scratch Owner-worker reusable ABI batch.
 * @return Sole forward mask; the scheduler resolves each clear lane's retention or drop.
 */
[[nodiscard]] uint64_t execute_active_module_batch_mechanism(module::module_epoch_store &store,
							     uint16_t stage_instance_index, int32_t region_id,
							     std::span<packet_record *const> packets,
							     kinetum_active_ctx &active_ctx,
							     module_batch_scratch &scratch) noexcept;

}  // namespace kinetum::dp
