// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_staging_test_harness.hpp
 * @brief Retire test-owned staged records without masking an earlier assertion failure.
 * @author Fleming Patel
 *
 * Fixtures retain packet storage themselves and use real staging operations.
 * A guard may also retire exact ledger credits when the fixture acquired them.
 * No provider, module callback, or runtime transition is synthesized here.
 */

#include <array>
#include <exception>

#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/worker_packet_staging.hpp"

namespace kinetum::dp::test
{

/** @brief Drain only a fixture's queued pointers; outstanding claims must already have an explicit owner. */
class packet_staging_cleanup final {
    public:
	/**
	 * @brief Borrow staging, optional credits, and their caller-owned record lifetimes.
	 * @param staging Owner that outlives this guard.
	 * @param ledger Exact ledger credited for every queued record, or null for storage-only fixtures.
	 */
	explicit packet_staging_cleanup(worker_packet_staging &staging, worker_epoch_ledger *ledger = nullptr) noexcept
		: staging_(staging)
		, ledger_(ledger)
	{
	}
	/** @brief Cleanup authority cannot be duplicated. */
	packet_staging_cleanup(const packet_staging_cleanup &) = delete;
	/** @brief Cleanup authority cannot be replaced. */
	packet_staging_cleanup &operator=(const packet_staging_cleanup &) = delete;
	/** @brief Retire queued test ownership in both roles before the storage owner is destroyed. */
	~packet_staging_cleanup()
	{
		for (auto &domain : staging_.domains()) {
			drain_(domain);
			if (domain.has_future()) {
				domain.rotate_after_activation();
				drain_(domain);
			}
		}
	}

    private:
	/**
	 * @brief Release each queued pointer's reservation and optional exact epoch credit.
	 * @param domain Fixture-owned domain with no outstanding foreign reservation.
	 */
	void drain_(packet_epoch_input_staging &domain) noexcept
	{
		std::array<packet_record *, common::runtime_sizing::PACKET_MAX_BURST_SIZE> records{};
		while (!domain.active_empty()) {
			bool progressed = false;
			domain.service_active(records, [&](const packet_work_key &,
							   std::span<packet_record *const> batch) noexcept {
				for (auto *record : batch) {
					if (ledger_ != nullptr) {
						ledger_->retire(record->metadata.epoch);
					}
					domain.release_active_reservation();
					progressed = true;
				}
			});
			if (!progressed) {
				std::terminate();
			}
		}
	}

	worker_packet_staging &staging_;  ///< Sole test-owned staging population.
	worker_epoch_ledger *ledger_;	  ///< Optional exact credited ledger, never inferred.
};

}  // namespace kinetum::dp::test
