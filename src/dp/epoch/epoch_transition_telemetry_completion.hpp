// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_telemetry_completion.hpp
 * @brief Narrow observation-only telemetry-bank retirement seam.
 * @author Fleming Patel
 */

#include <cstdint>

namespace kinetum::dp
{

/**
 * @brief Cold completion view of telemetry aggregation and grace-bound reuse.
 *
 * Implementations are coordinator-thread-owned and observation-only until the
 * existing reclamation boundary calls an explicit retirement method.
 */
class epoch_transition_telemetry_completion {
    public:
	/** @brief Destroy after every bank and transfer is resolved. */
	virtual ~epoch_transition_telemetry_completion() = default;
	/**
	 * @param epoch Exact candidate old epoch.
	 * @return true only when every worker bank for @p epoch is aggregated.
	 */
	[[nodiscard]] virtual bool worker_epoch_aggregated(uint64_t epoch) const noexcept = 0;
	/**
	 * @param epoch Exact candidate old epoch.
	 * @return true only when every module-context bank for @p epoch is aggregated.
	 */
	[[nodiscard]] virtual bool module_epoch_aggregated(uint64_t epoch) const noexcept = 0;
	/**
	 * @brief Reconcile module-bank retirement and target-bank transfer.
	 * @param epoch Exact old epoch already retired from module stores.
	 * @param active_epoch Exact target epoch, or zero for final shutdown.
	 */
	virtual void complete_module_epoch_retirement(uint64_t epoch, uint64_t active_epoch) noexcept = 0;
	/**
	 * @brief Reclaim every old worker bank after exact reader grace.
	 * @param epoch Exact old epoch.
	 * @param active_epoch Exact target epoch, or zero for final shutdown.
	 */
	virtual void retire_worker_epoch(uint64_t epoch, uint64_t active_epoch) noexcept = 0;
};

}  // namespace kinetum::dp
