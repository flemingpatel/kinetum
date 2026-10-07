// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_status.hpp
 * @brief Coherent owner-published status for one packet-runtime generation.
 * @author Fleming Patel
 *
 * The packet-runtime owner publishes one immutable fixed-width observation at
 * each readiness or exact transition boundary. Foreign gRPC threads read only
 * this publication; they never inspect mutable workers, configuration stores,
 * or provider state.
 *
 * @par Thread Safety
 * Exactly one runtime-service-bound coordinator thread may publish. Any number
 * of foreign threads may call try_read(). Publication and observation are
 * bounded, lock-free, and allocation-free.
 */

#include <cstddef>
#include <cstdint>

#include <kinetum/algo/single_writer_snapshot.hpp>

#include "src/dp/publication_read_result.hpp"

namespace kinetum::dp
{

/**
 * @brief Readiness states representable by one packet-runtime generation.
 */
enum class runtime_readiness : uint64_t {
	CONTROL_READY = 1,  ///< Control RPCs are serving; packet admission is closed.
	PACKET_READY = 2,   ///< One exact epoch is active and all packet workers are live.
};

/**
 * @brief One coherent observer-owned runtime-status value.
 */
struct runtime_status_snapshot {
	uint64_t publication_generation{0};				///< Monotonic publication sequence.
	runtime_readiness readiness{runtime_readiness::CONTROL_READY};	///< Exact readiness boundary.
	uint64_t runtime_generation{0};					///< Nonzero owner generation identity.
	uint64_t active_epoch{0};					///< Exact active configuration epoch.
	uint64_t minimum_retained_epoch{0};				///< Oldest configuration epoch still retained.
	uint64_t last_activated_epoch{0};  ///< Most recently activated configuration epoch.
	uint32_t active_workers{0};	   ///< Workers proven live in this publication.
	uint32_t expected_workers{0};	   ///< Complete compiled worker population.
};

/**
 * @brief Publish coherent status for one packet-runtime generation.
 *
 * CONTROL_READY precedes one PACKET_READY Bootstrap publication. Each later
 * exact transition publishes participant activation as N/E/N, then stable
 * completion as N/N/N. Invalid, overlapping, or nonadvancing transitions
 * perform no publication.
 *
 * @par Ownership
 * The sole bound coordinator owns every publication and writer-preflight
 * method. Observers own only the values returned through try_read().
 */
class runtime_status_publication final {
    public:
	/** @brief Construct one unpublished runtime-status authority. */
	runtime_status_publication() noexcept = default;

	/** @brief Runtime-status publication authorities cannot be copied. */
	runtime_status_publication(const runtime_status_publication &) = delete;
	/** @brief Runtime-status publication authorities cannot be copy-assigned. */
	runtime_status_publication &operator=(const runtime_status_publication &) = delete;
	/** @brief Runtime-status publication authorities cannot be moved. */
	runtime_status_publication(runtime_status_publication &&) = delete;
	/** @brief Runtime-status publication authorities cannot be move-assigned. */
	runtime_status_publication &operator=(runtime_status_publication &&) = delete;

	/**
	 * @brief Publish the initial control-ready status.
	 *
	 * @param runtime_generation Admitted runtime-generation identity in 1..UINT32_MAX.
	 * @param expected_workers Nonzero complete compiled worker population.
	 * @return true on the sole legal initial publication; false without mutation
	 *         for zero identities/population or repeated publication.
	 */
	[[nodiscard]] bool publish_control_ready(uint64_t runtime_generation, uint32_t expected_workers) noexcept;

	/**
	 * @brief Publish successful exact fixed-epoch bootstrap.
	 *
	 * @param bootstrap_epoch Exact nonzero admitted bootstrap epoch.
	 * @param active_workers Proven live worker population; must equal the
	 *        CONTROL_READY publication's expected population.
	 * @return true on the sole legal transition; false without mutation for an
	 *         invalid identity, incomplete worker set, or repeated publication.
	 */
	[[nodiscard]] bool publish_packet_ready(uint64_t bootstrap_epoch, uint32_t active_workers) noexcept;

	/**
	 * @brief Verify the exact runtime generation bound by CONTROL_READY.
	 * @param runtime_generation Candidate nonzero generation identity.
	 * @return true only after CONTROL_READY bound the same exact generation.
	 */
	[[nodiscard]] bool owns_runtime_generation(uint64_t runtime_generation) const noexcept;

	/**
	 * @brief Prove two later transition publications remain representable.
	 *
	 * @param from_epoch Exact stable globally complete baseline.
	 * @param to_epoch Exact advancing prepared target.
	 * @return true only when current N/N/N truth equals @p from_epoch and two
	 *         coherent publication generations remain available.
	 */
	[[nodiscard]] bool can_publish_transition(uint64_t from_epoch, uint64_t to_epoch) const noexcept;

	/**
	 * @brief Publish globally completed participant activation with old retention.
	 *
	 * @param from_epoch Exact old epoch still retained.
	 * @param to_epoch Exact epoch active on every participant.
	 * @return true after N/E/N publication; false without mutation on mismatch.
	 */
	[[nodiscard]] bool publish_transition_activated(uint64_t from_epoch, uint64_t to_epoch) noexcept;

	/**
	 * @brief Publish exact stable completion after old ownership is empty.
	 *
	 * @param epoch Exact active and sole retained epoch.
	 * @return true after N/N/N publication; false without mutation on mismatch.
	 */
	[[nodiscard]] bool publish_transition_complete(uint64_t epoch) noexcept;

	/**
	 * @brief Read one coherent completed runtime-status publication.
	 *
	 * Validate the admitted runtime-generation and epoch ranges before exposing
	 * the readiness, worker population, and retention relationship.
	 *
	 * @param out Observer-owned value updated only on success.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result try_read(runtime_status_snapshot &out) const noexcept;

    private:
	/** @brief Fixed indices in the generic publication payload. */
	enum field_index : std::size_t {
		READINESS = 0,
		RUNTIME_GENERATION = 1,
		ACTIVE_EPOCH = 2,
		MINIMUM_RETAINED_EPOCH = 3,
		LAST_ACTIVATED_EPOCH = 4,
		ACTIVE_WORKERS = 5,
		EXPECTED_WORKERS = 6,
	};

	static constexpr std::size_t FIELD_COUNT = EXPECTED_WORKERS + 1u;  ///< Complete fixed payload width.
	static constexpr std::size_t OBSERVATION_ATTEMPTS = 8u;	 ///< Bounded coherent-read attempts per observation.

	kinetum::algo::single_writer_snapshot<FIELD_COUNT> publication_;  ///< Sole foreign observation channel.
	uint64_t owner_runtime_generation_{0};				  ///< Writer-local generation identity.
	uint64_t owner_active_epoch_{0};				  ///< Current participant-active epoch.
	uint64_t owner_minimum_retained_epoch_{0};			  ///< Oldest still-owned epoch.
	uint64_t owner_last_activated_epoch_{0};			  ///< Most recent complete activation edge.
	uint32_t owner_expected_workers_{0};				  ///< Writer-local compiled population.
	bool control_ready_published_{false};				  ///< Whether the initial state is complete.
	bool packet_ready_published_{false};  ///< Whether bootstrap publication is complete.
};

}  // namespace kinetum::dp
