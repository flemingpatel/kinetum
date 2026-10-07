// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dp_engine.hpp
 * @brief Provider-neutral owner-worker packet mechanism execution.
 * @author Fleming Patel
 *
 * The engine consumes the dataplane's sole packet_record representation. It
 * never includes a provider header, branches on a provider kind, discovers a
 * module, or resolves mutable configuration on the packet path.
 *
 * @par Thread Safety
 * One engine belongs to one serialized component-test owner. Packet records, module
 * stores, scratch, and counters remain single-writer for the complete call.
 *
 * @par Performance
 * Platform and module dispatch perform no allocation, locking, shared
 * ownership, RTTI, virtual dispatch, or string lookup.
 */

#include <cstdint>
#include <span>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "src/dp/module/module_manager.hpp"
#include "src/dp/packet_mechanism.hpp"

namespace kinetum::dp
{

/** @brief Engine-wide packet counters. */
struct engine_stats {
	uint64_t rx_packets{0};	      ///< Records admitted by RX mechanisms.
	uint64_t tx_packets{0};	      ///< Records admitted by TX mechanisms.
	uint64_t dropped_packets{0};  ///< Records rejected by platform/module mechanisms.
};

/** @brief Owner-worker packet mechanism engine. */
class dp_engine {
    public:
	/** @brief Construct an engine with no admitted module generation. */
	dp_engine() = default;
	dp_engine(const dp_engine &) = delete;
	dp_engine &operator=(const dp_engine &) = delete;
	dp_engine(dp_engine &&) = delete;
	dp_engine &operator=(dp_engine &&) = delete;
	/** @brief Destroy the engine after all packet and lifecycle owners stop. */
	~dp_engine() = default;

	/**
	 * @brief Return the cold exact module-generation owner.
	 *
	 * @return Mutable manager for pre-worker image/context admission.
	 */
	[[nodiscard]] module::module_manager &modules() noexcept
	{
		return modules_;
	}

	/**
	 * @brief Return the cold exact module-generation owner read-only.
	 *
	 * @return Immutable admitted-generation authority.
	 */
	[[nodiscard]] const module::module_manager &modules() const noexcept
	{
		return modules_;
	}

	/**
	 * @brief Execute one platform mechanism against one exact packet record.
	 *
	 * @param stage Immutable Axiom stage descriptor.
	 * @param packet Sole mutable packet record.
	 * @return true when the record may continue; false when it must be retired.
	 */
	[[nodiscard]] bool execute_stage(const kinetum::axiom::v1::Stage *stage, packet_record *packet);

	/**
	 * @brief Execute one pre-resolved module context on an occupied packet prefix.
	 *
	 * Every packet must match the executable epoch before the one callback.
	 * Rejection records bounded owner-local evidence; the caller retains every
	 * record and resolves its returned disposition exactly once.
	 *
	 * @param store Exact context-local slot and executable-view authority.
	 * @param stage_instance_index Exact executable stage-instance index.
	 * @param region_id Sole-owner runtime region.
	 * @param packets Borrowed occupied prefix of caller-owned packet records.
	 * @param scratch Owner-worker reusable ABI batch.
	 * @return Sole callback forward mask over the occupied prefix.
	 */
	[[nodiscard]] uint64_t execute_module_stage(module::module_epoch_store &store, uint16_t stage_instance_index,
						    int32_t region_id, std::span<packet_record *const> packets,
						    module_batch_scratch &scratch) noexcept;

	/**
	 * @brief Return the exact counters owned by this engine's sole caller.
	 *
	 * The caller must serialize this observation with packet execution; this
	 * component engine publishes no live cross-thread telemetry.
	 *
	 * @return Plain owner-local platform-stage admissions and rejections.
	 */
	[[nodiscard]] engine_stats stats() const noexcept;

    private:
	/**
	 * @brief Record one exact mechanism outcome in aggregate test counters.
	 *
	 * @param outcome Provider-neutral mechanism result.
	 * @return true when @p outcome keeps the record live.
	 */
	[[nodiscard]] bool account_outcome_(packet_mechanism_outcome outcome) noexcept;

	module::module_manager modules_;  ///< Cold exact generation owner.
	engine_stats counters_{};	  ///< Plain single-owner component-test accounting.
};

}  // namespace kinetum::dp
