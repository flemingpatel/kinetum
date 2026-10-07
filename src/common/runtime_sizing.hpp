// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_sizing.hpp
 * @brief Shared runtime-capacity defaults for generated plans and dataplane admission.
 * @author Fleming Patel
 *
 * These values are implementation defaults, not benchmark claims. The packet
 * rate math is anchored to a 10GbE minimum-frame physical validation profile:
 *
 *   10,000,000,000 bit/s / ((64B frame + 8B preamble/SFD + 12B IFG) * 8)
 *     = 14,880,952 packets/s per ingress port.
 *
 * Software DATA and ordinary worker-staging depth is 1024. Deeper staging
 * increases retained work and possible queueing delay; it does not increase
 * the bounded work performed before the next input/control service. At a
 * service rate of 500 kpps, 1024 queued packets represents about 2.05 ms of
 * work; 4096 would be about 8.19 ms.
 * A transition source instead consumes the independently plan-authored exact
 * capacity for both roles of each source-domain staging pair. Native driver
 * and storage sizing belongs to the provider implementation rather than this
 * provider-neutral authority.
 */

#include <cstddef>
#include <cstdint>
#include <limits>

namespace kinetum::common::runtime_sizing
{

/** DATA-ring and ordinary local packet-staging depth charged once per exact owner. */
inline constexpr std::size_t INTER_REGION_DATA_RING_CAPACITY = 1024;

/**
 * @brief Sender-owned future-epoch output hold capacity for one executable boundary.
 *
 * This queue is distinct from the cross-worker DATA ring. Gluon
 * seeds both plan fields with the same depth, but runtime admission and buffer
 * budgeting must validate and account them independently.
 */
inline constexpr std::size_t BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY = 1024;

static_assert(INTER_REGION_DATA_RING_CAPACITY >= 2, "INTER_REGION_DATA_RING_CAPACITY must contain at least two slots");
static_assert((INTER_REGION_DATA_RING_CAPACITY & (INTER_REGION_DATA_RING_CAPACITY - 1u)) == 0,
	      "INTER_REGION_DATA_RING_CAPACITY must be a power of two");
static_assert(INTER_REGION_DATA_RING_CAPACITY <= std::numeric_limits<uint32_t>::max(),
	      "INTER_REGION_DATA_RING_CAPACITY must fit BoundaryPlacement.data_ring_capacity");
static_assert(BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY >= 2,
	      "BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY must contain at least two slots");
static_assert((BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY & (BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY - 1u)) == 0,
	      "BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY must be a power of two");
static_assert(BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY <= std::numeric_limits<uint32_t>::max(),
	      "BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY must fit BoundaryPlacement.future_output_hold_capacity");

/** Typed CUT-control ring capacity; one global transition permits one outstanding record. */
inline constexpr std::size_t BOUNDARY_CUT_RING_CAPACITY = 2;

/** Typed ACK-control ring capacity; one global transition permits one outstanding record. */
inline constexpr std::size_t BOUNDARY_ACK_RING_CAPACITY = 2;

static_assert(BOUNDARY_CUT_RING_CAPACITY >= 2u &&
		      (BOUNDARY_CUT_RING_CAPACITY & (BOUNDARY_CUT_RING_CAPACITY - 1u)) == 0u,
	      "BOUNDARY_CUT_RING_CAPACITY must satisfy the exact SPSC capacity contract");
static_assert(BOUNDARY_ACK_RING_CAPACITY >= 2u &&
		      (BOUNDARY_ACK_RING_CAPACITY & (BOUNDARY_ACK_RING_CAPACITY - 1u)) == 0u,
	      "BOUNDARY_ACK_RING_CAPACITY must satisfy the exact SPSC capacity contract");

/** Maximum provider-neutral packet burst carried by one worker operation. */
inline constexpr uint32_t PACKET_MAX_BURST_SIZE = 64;
static_assert(PACKET_MAX_BURST_SIZE <= std::numeric_limits<uint16_t>::max(),
	      "PACKET_MAX_BURST_SIZE must fit provider burst-operation counts");

}  // namespace kinetum::common::runtime_sizing
