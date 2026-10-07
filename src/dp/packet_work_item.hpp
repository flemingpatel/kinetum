// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_work_item.hpp
 * @brief Fixed owner-local packet-work staging value.
 * @author Fleming Patel
 *
 * Epoch, stage, port, storage, and provider facts remain solely in the packet
 * record and immutable compiled topology. This value adds only bounded
 * execution phase, allowing the same exact staging owner to participate in an
 * O(1) epoch-role rotation without exposing packet-kernel internals.
 */

#include <array>
#include <cstdint>
#include <type_traits>

#include "src/dp/packet.hpp"

namespace kinetum::dp
{

/** @brief Sole extra state carried beside one packet pointer in local staging. */
enum class packet_work_phase : uint8_t {
	RX_DELIVER = 1,	    ///< Apply the exact stream-to-RX-stage storage edge.
	EXECUTE = 2,	    ///< Execute metadata.current_stage_instance.
	STAGE_DELIVER = 3,  ///< Apply current-to-next stage storage ownership.
	BOUNDARY_SEND = 4,  ///< Retry one already transitioned cross-worker DATA send.
	TX_DELIVER = 5,	    ///< Apply the exact TX-stage-to-stream storage edge.
};

/** @brief Bounded local queue item without a second packet identity authority. */
struct packet_work_item {
	packet_record *record{nullptr};			      ///< Sole packet ownership.
	packet_work_phase phase{packet_work_phase::EXECUTE};  ///< Next bounded mechanism.
	std::array<uint8_t, 7> padding{};		      ///< Explicit fixed layout.
};

static_assert(sizeof(packet_work_item) == 16, "packet work item layout changed");
static_assert(alignof(packet_work_item) == alignof(packet_record *), "packet work item alignment changed");
static_assert(std::is_standard_layout_v<packet_work_item>, "packet work item must be standard-layout");
static_assert(std::is_trivially_copyable_v<packet_work_item>, "packet work item must be trivially copyable");

}  // namespace kinetum::dp
