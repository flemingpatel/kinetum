// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file frozen_transition_participants.hpp
 * @brief Immutable compact participant membership for one runtime generation.
 * @author Fleming Patel
 *
 * The participant projection is constructed once from the sole compiled
 * provider topology before provider materialization. It validates every
 * logical-stage, lane, worker, region, concrete-stage, stream, boundary,
 * module-context, source, sink, and current config-reader relation in both
 * directions, then publishes only compact indices and immutable flat ranges.
 * A transition generation binds this object by identity; it never copies or
 * reconstructs membership.
 *
 * @par Thread Safety
 * Construction has one cold owner. After create() succeeds the object is
 * immutable and may be read concurrently for the lifetime of its owning
 * runtime generation.
 *
 * @par Performance
 * Construction is allocation-using O(V + E + M) cold work. All accessors are
 * O(1) or return a precomputed span and are unreachable from packet execution.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "src/common/status_or.hpp"

namespace kinetum::provider
{
struct compiled_provider_topology;
}  // namespace kinetum::provider

namespace kinetum::dp
{

/** @brief One immutable range inside a participant-set flat index array. */
struct frozen_index_range {
	uint32_t offset{0};  ///< First flat-array position.
	uint32_t count{0};   ///< Number of consecutive owned identities.
};

/** @brief One exact worker/lane execution participant. */
struct frozen_execution_participant {
	uint32_t participant_index{0};		   ///< Compact index equal to worker_index.
	uint32_t worker_index{0};		   ///< Sole compiled packet-worker identity.
	uint32_t region_index{0};		   ///< Compact logical-region identity.
	uint32_t lane_index{0};			   ///< Compact execution-lane identity.
	uint32_t quiescence_reader_index{0};	   ///< Current config-reader identity.
	bool is_source{false};			   ///< Owns at least one originating stream.
	bool is_sink{false};			   ///< Owns at least one terminal stream.
	frozen_index_range stages{};		   ///< Exact stage-instance membership.
	frozen_index_range io_streams{};	   ///< Exact I/O-stream membership.
	frozen_index_range inbound_boundaries{};   ///< Exact inbound boundary set.
	frozen_index_range outbound_boundaries{};  ///< Exact outbound boundary set.
	frozen_index_range module_contexts{};	   ///< Exact mutable-context set.
};

/** @brief One exact logical region and its compact execution participants. */
struct frozen_region_membership {
	uint32_t region_index{0};      ///< Compact index equal to region vector position.
	frozen_index_range workers{};  ///< Exact worker membership in flat storage.
};

/**
 * @brief Immutable process-generation participant authority.
 *
 * Compact participant identities are not remapped: worker, boundary, module-
 * context, and config-reader indices retain their sole compiled identities.
 * The object owns its projection so later mutation of a caller-owned test
 * topology cannot alter already frozen membership.
 */
class frozen_transition_participants final {
    public:
	/**
	 * @brief Construct and fully audit one immutable participant projection.
	 *
	 * @param topology Sole compiled provider topology for the runtime generation.
	 * @return Immutable participant owner, or the first identity, ownership,
	 *         range, plan-hash, allocation, or representability failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<const frozen_transition_participants>>
	create(const provider::compiled_provider_topology &topology);

	/** @brief Participant authorities cannot be copied. */
	frozen_transition_participants(const frozen_transition_participants &) = delete;
	/** @brief Participant authorities cannot be copy-assigned. */
	frozen_transition_participants &operator=(const frozen_transition_participants &) = delete;
	/** @brief Participant authorities cannot be moved after publication. */
	frozen_transition_participants(frozen_transition_participants &&) = delete;
	/** @brief Participant authorities cannot be move-assigned. */
	frozen_transition_participants &operator=(frozen_transition_participants &&) = delete;
	/** @brief Destroy immutable participant storage after every generation releases it. */
	~frozen_transition_participants() = default;

	/** @return Exact canonical source-plan content hash. */
	[[nodiscard]] std::string_view plan_content_hash() const noexcept;

	/** @return Number of execution participants. */
	[[nodiscard]] std::size_t execution_participant_count() const noexcept;
	/** @return Number of logical-region membership records. */
	[[nodiscard]] std::size_t region_count() const noexcept;
	/** @return Number of exact boundary participants. */
	[[nodiscard]] std::size_t boundary_count() const noexcept;
	/** @return Number of exact module contexts. */
	[[nodiscard]] std::size_t module_context_count() const noexcept;
	/** @return Number of current config-reader identities. */
	[[nodiscard]] std::size_t quiescence_reader_count() const noexcept;

	/**
	 * @brief Return one exact execution participant.
	 *
	 * @param participant_index Compact participant identity.
	 * @return Immutable participant, or null when out of range.
	 */
	[[nodiscard]] const frozen_execution_participant *
	execution_participant(uint32_t participant_index) const noexcept;

	/**
	 * @brief Return one exact region membership record.
	 *
	 * @param region_index Compact region identity.
	 * @return Immutable region record, or null when out of range.
	 */
	[[nodiscard]] const frozen_region_membership *region(uint32_t region_index) const noexcept;

	/** @return Strictly sorted exact source participant indices. */
	[[nodiscard]] std::span<const uint32_t> source_participant_indices() const noexcept;
	/** @return Strictly sorted exact sink participant indices. */
	[[nodiscard]] std::span<const uint32_t> sink_participant_indices() const noexcept;
	/** @return Current config-reader indices, equal to compact worker indices. */
	[[nodiscard]] std::span<const uint32_t> quiescence_reader_indices() const noexcept;

	/**
	 * @param participant_index Compact execution participant index; out-of-range input terminates.
	 * @return Borrowed exact stage indices for the participant.
	 */
	[[nodiscard]] std::span<const uint32_t> stage_indices(uint32_t participant_index) const noexcept;
	/**
	 * @param participant_index Compact execution participant index; out-of-range input terminates.
	 * @return Borrowed exact I/O stream indices for the participant.
	 */
	[[nodiscard]] std::span<const uint32_t> io_stream_indices(uint32_t participant_index) const noexcept;
	/**
	 * @param participant_index Compact execution participant index; out-of-range input terminates.
	 * @return Borrowed exact inbound boundary indices for the participant.
	 */
	[[nodiscard]] std::span<const uint32_t> inbound_boundary_indices(uint32_t participant_index) const noexcept;
	/**
	 * @param participant_index Compact execution participant index; out-of-range input terminates.
	 * @return Borrowed exact outbound boundary indices for the participant.
	 */
	[[nodiscard]] std::span<const uint32_t> outbound_boundary_indices(uint32_t participant_index) const noexcept;
	/**
	 * @param participant_index Compact execution participant index; out-of-range input terminates.
	 * @return Borrowed exact module-context indices for the participant.
	 */
	[[nodiscard]] std::span<const uint32_t> module_context_indices(uint32_t participant_index) const noexcept;
	/**
	 * @param region_index Compact logical region index; out-of-range input terminates.
	 * @return Borrowed exact worker indices for the region.
	 */
	[[nodiscard]] std::span<const uint32_t> region_worker_indices(uint32_t region_index) const noexcept;

    private:
	/**
	 * @brief Adopt one fully audited immutable projection.
	 *
	 * @param plan_content_hash Exact canonical source-plan identity.
	 * @param participants Compact execution participants.
	 * @param regions Compact region memberships.
	 * @param source_indices Exact source participants.
	 * @param sink_indices Exact sink participants.
	 * @param reader_indices Exact config readers.
	 * @param stage_indices Flat stage ownership.
	 * @param stream_indices Flat stream ownership.
	 * @param inbound_indices Flat inbound-boundary ownership.
	 * @param outbound_indices Flat outbound-boundary ownership.
	 * @param context_indices Flat module-context ownership.
	 * @param region_worker_indices Flat region worker membership.
	 */
	frozen_transition_participants(std::string plan_content_hash,
				       std::vector<frozen_execution_participant> participants,
				       std::vector<frozen_region_membership> regions,
				       std::vector<uint32_t> source_indices, std::vector<uint32_t> sink_indices,
				       std::vector<uint32_t> reader_indices, std::vector<uint32_t> stage_indices,
				       std::vector<uint32_t> stream_indices, std::vector<uint32_t> inbound_indices,
				       std::vector<uint32_t> outbound_indices, std::vector<uint32_t> context_indices,
				       std::vector<uint32_t> region_worker_indices) noexcept;

	/**
	 * @param values Immutable indexed storage owning the returned elements.
	 * @param range Compiled offset/count pair; an out-of-bounds range terminates.
	 * @return Borrowed span over the exact compiled range.
	 */
	[[nodiscard]] static std::span<const uint32_t> range_(const std::vector<uint32_t> &values,
							      frozen_index_range range) noexcept;

	std::string plan_content_hash_;				  ///< Exact immutable plan identity.
	std::vector<frozen_execution_participant> participants_;  ///< Indexed execution participants.
	std::vector<frozen_region_membership> regions_;		  ///< Indexed logical regions.
	std::vector<uint32_t> source_indices_;			  ///< Strictly sorted source workers.
	std::vector<uint32_t> sink_indices_;			  ///< Strictly sorted sink workers.
	std::vector<uint32_t> reader_indices_;			  ///< One current reader per worker.
	std::vector<uint32_t> stage_indices_;			  ///< Flat participant stage sets.
	std::vector<uint32_t> stream_indices_;			  ///< Flat participant stream sets.
	std::vector<uint32_t> inbound_indices_;			  ///< Flat inbound boundary sets.
	std::vector<uint32_t> outbound_indices_;		  ///< Flat outbound boundary sets.
	std::vector<uint32_t> context_indices_;			  ///< Flat participant context sets.
	std::vector<uint32_t> region_worker_indices_;		  ///< Flat region worker sets.
};

}  // namespace kinetum::dp
