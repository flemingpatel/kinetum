// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_telemetry_source_owner.hpp
 * @brief Exact generation claims for one cold runtime-telemetry source.
 * @author Fleming Patel
 *
 * This owner serializes cold observations of one published runtime generation.
 * A caller names the exact generation it intends to observe. Retirement closes
 * admission, fences callers waiting behind an active claim, waits for that
 * claim to finish, and destroys the source without holding the ownership mutex.
 * A later source must carry a strictly newer generation, so a delayed caller
 * can never cross an ABA-shaped publication boundary.
 *
 * @par Thread Safety
 * All methods are thread-safe. At most one foreign collection callback runs at
 * a time. No platform mutex is held while collection or source destruction
 * executes.
 *
 * @par Performance
 * This is a cold observation mechanism. It is unreachable from packet workers
 * and may block an observer or retirement owner while another observation is
 * active.
 */

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/runtime_telemetry.hpp"

namespace kinetum::dp
{

/** @brief Sole generation and lifetime owner for one telemetry source. */
class runtime_telemetry_source_owner final {
    public:
	/** @brief Construct one empty telemetry-source publication authority. */
	runtime_telemetry_source_owner() = default;

	/** @brief Close observation admission and retire any published source. */
	~runtime_telemetry_source_owner() noexcept;

	/** @brief Telemetry-source owners cannot be copied. */
	runtime_telemetry_source_owner(const runtime_telemetry_source_owner &) = delete;
	/** @brief Telemetry-source owners cannot be copy-assigned. */
	runtime_telemetry_source_owner &operator=(const runtime_telemetry_source_owner &) = delete;
	/** @brief Telemetry-source owners cannot be moved. */
	runtime_telemetry_source_owner(runtime_telemetry_source_owner &&) = delete;
	/** @brief Telemetry-source owners cannot be move-assigned. */
	runtime_telemetry_source_owner &operator=(runtime_telemetry_source_owner &&) = delete;

	/**
	 * @brief Publish one complete source under an exact generation identity.
	 *
	 * Publication is valid only while no source or active claim exists. A source
	 * retired from this owner cannot be replaced by the same or an older
	 * generation.
	 *
	 * @param runtime_generation Exact nonzero monotonically increasing identity.
	 * @param source Complete source whose dependencies already exist.
	 * @return OK after publication, otherwise a side-effect-free admission error.
	 */
	[[nodiscard]] common::status publish(uint64_t runtime_generation,
					     std::unique_ptr<runtime_telemetry_source> source);

	/**
	 * @brief Collect through one exact serialized generation claim.
	 *
	 * A caller waiting behind another collection is rejected if retirement
	 * closes that publication. It never continues through a later source.
	 * Foreign exceptions are converted to provider-neutral status results after
	 * releasing the claim.
	 *
	 * @param runtime_generation Exact generation the caller intends to observe.
	 * @param request Requested provider-neutral observation subsets.
	 * @return One coherent snapshot or an exact admission/collection failure.
	 */
	[[nodiscard]] common::status_or<runtime_telemetry_snapshot>
	collect(uint64_t runtime_generation, const runtime_telemetry_request &request) const;

	/**
	 * @brief Detach, quiesce, and destroy the current source.
	 *
	 * Waiting claims are fenced immediately. An active foreign callback is
	 * allowed to finish before its source is destroyed outside the mutex.
	 * Repeated retirement with no source is harmless.
	 */
	void retire() noexcept;

	/**
	 * @brief Observe the currently admitted generation for cold diagnostics.
	 *
	 * @return Published generation, or no value while detached.
	 */
	[[nodiscard]] std::optional<uint64_t> published_generation() const noexcept;

    private:
	/** @brief Release the one active claim and wake retirement or a waiter. */
	void release_claim_() const noexcept;

	mutable std::mutex mutex_;			    ///< Serializes publication and claims.
	mutable std::condition_variable cv_;		    ///< Wakes claims and retirement.
	std::unique_ptr<runtime_telemetry_source> source_;  ///< Current foreign source.
	uint64_t published_generation_{0};		    ///< Current exact generation, or zero.
	uint64_t last_generation_{0};			    ///< Highest generation ever admitted.
	mutable bool claim_active_{false};		    ///< Whether foreign collection is active.
	bool accepting_claims_{false};			    ///< Whether the current source admits claims.
};

}  // namespace kinetum::dp
