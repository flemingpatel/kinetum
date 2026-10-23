// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_work_key.hpp
 * @brief Immutable execution identity for worker-local packet queues.
 * @author Fleming Patel
 *
 * A key binds one compiled executable stage to one continuation mechanism.
 * Queues carry packet pointers only; each record retains its authoritative
 * epoch, stage, route and storage identity, validated against the key at service.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace kinetum::dp
{

/** @brief Continuation mechanism selected once for one exact local work queue. */
enum class packet_work_phase : uint8_t {
	RX_DELIVER = 1,	    ///< Apply the exact stream-to-RX-stage storage edge.
	EXECUTE = 2,	    ///< Execute metadata.current_stage_instance.
	STAGE_DELIVER = 3,  ///< Apply current-to-next stage storage ownership.
	BOUNDARY_SEND = 4,  ///< Retry one already transitioned cross-worker DATA send.
	TX_DELIVER = 5,	    ///< Apply the exact TX-stage-to-stream storage edge.
};

/** @brief Immutable expected stage and continuation within one worker/storage role. */
struct packet_work_key {
	uint32_t stage_instance_index{std::numeric_limits<uint32_t>::max()};  ///< Exact compiled executable stage.
	packet_work_phase phase{packet_work_phase::EXECUTE};		      ///< Bounded mechanism to resume.
	std::array<uint8_t, 3> padding{};				      ///< Zeroed fixed geometry.

	/** @param other Candidate key. @return Semantic stage/phase equality, excluding padding. */
	[[nodiscard]] constexpr bool operator==(const packet_work_key &other) const noexcept
	{
		return stage_instance_index == other.stage_instance_index && phase == other.phase;
	}
	/** @param other Candidate key. @return Canonical stage-major, phase-minor ordering. */
	[[nodiscard]] constexpr bool operator<(const packet_work_key &other) const noexcept
	{
		return stage_instance_index < other.stage_instance_index ||
		       (stage_instance_index == other.stage_instance_index && phase < other.phase);
	}
};

static_assert(sizeof(packet_work_key) == 8u && alignof(packet_work_key) == alignof(uint32_t),
	      "packet work key must retain its compact immutable layout");
static_assert(offsetof(packet_work_key, stage_instance_index) == 0u && offsetof(packet_work_key, phase) == 4u &&
		      offsetof(packet_work_key, padding) == 5u,
	      "packet work key offsets changed");
static_assert(std::is_standard_layout_v<packet_work_key> && std::is_trivially_copyable_v<packet_work_key>,
	      "packet work key must retain value semantics");

}  // namespace kinetum::dp
