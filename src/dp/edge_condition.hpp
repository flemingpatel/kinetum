// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file edge_condition.hpp
 * @brief Provider-neutral compiled packet-route predicates.
 * @author Fleming Patel
 *
 * Route predicates are parsed on the cold path and evaluated against the sole
 * packet metadata authority without allocation, strings, or provider lookup.
 * The cold topology compiler supplies the compact representation after Axiom
 * admission; this header owns only packet-path evaluation.
 *
 * @par Thread Safety
 * Compiled values are immutable and may be evaluated concurrently.
 *
 * @par Performance
 * Evaluation is a bounded pair of switch statements on the packet path.
 */

#include <cstdint>

#include "src/common/packet_route_condition.hpp"
#include "src/dp/packet.hpp"

namespace kinetum::dp
{

/**
 * @brief Evaluate a compiled condition against exact packet metadata.
 *
 * @param condition Immutable compiled condition.
 * @param metadata Exact packet metadata, required for conditional predicates.
 * @return true on a match. Unknown compiled enum values, malformed
 *         unconditional encodings, and missing metadata fail closed.
 */
[[nodiscard]] inline bool evaluate_condition(const common::compiled_packet_route_condition &condition,
					     const packet_private *metadata) noexcept
{
	using compiled_condition = common::compiled_packet_route_condition;

	if (condition.is_unconditional()) {
		return true;
	}
	if (KINETUM_UNLIKELY(metadata == nullptr)) {
		return false;
	}

	uint32_t field_value = 0;
	switch (condition.field) {
	case compiled_condition::field_id::SRC_IP:
		field_value = metadata->src_ipv4;
		break;
	case compiled_condition::field_id::DST_IP:
		field_value = metadata->dst_ipv4;
		break;
	case compiled_condition::field_id::SRC_PORT:
		field_value = metadata->src_port;
		break;
	case compiled_condition::field_id::DST_PORT:
		field_value = metadata->dst_port;
		break;
	case compiled_condition::field_id::PROTO:
		field_value = metadata->l4_proto;
		break;
	case compiled_condition::field_id::DSCP:
		field_value = metadata->dscp;
		break;
	case compiled_condition::field_id::FLOW_HASH:
		field_value = metadata->flow_hash;
		break;
	case compiled_condition::field_id::NONE:
	default:
		return false;
	}

	switch (condition.op) {
	case compiled_condition::op_id::EQ:
		return field_value == condition.value;
	case compiled_condition::op_id::NE:
		return field_value != condition.value;
	case compiled_condition::op_id::LT:
		return field_value < condition.value;
	case compiled_condition::op_id::LE:
		return field_value <= condition.value;
	case compiled_condition::op_id::GT:
		return field_value > condition.value;
	case compiled_condition::op_id::GE:
		return field_value >= condition.value;
	default:
		return false;
	}
}

}  // namespace kinetum::dp
