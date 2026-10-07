// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_route_condition.hpp
 * @brief Provider-neutral compiled packet-route predicates.
 * @author Fleming Patel
 *
 * Authored Axiom edge conditions are parsed once on the cold path into this
 * compact representation. One shared condition grammar parses the text; this
 * compiler is the sole mapper into the packet representation consumed by
 * provider topology. Dataplane code adds only evaluation against its exact
 * packet metadata authority.
 *
 * @par Thread Safety
 * Compilation is stateless. Compiled values are immutable and may be read by
 * any number of workers.
 *
 * @par Performance
 * The type is trivially copyable and contains no dynamic state. Compilation is
 * cold path only; packet-path evaluation is owned by the dataplane facade.
 */

#include <cstdint>
#include <string_view>
#include <type_traits>

#include "src/common/status_or.hpp"

namespace kinetum::common
{

/** @brief Compact allocation-free route predicate. */
struct compiled_packet_route_condition {
	/** @brief Packet metadata field selected by one predicate. */
	enum class field_id : uint8_t {
		NONE = 0,   ///< Canonical unconditional predicate.
		SRC_IP,	    ///< IPv4 source address.
		DST_IP,	    ///< IPv4 destination address.
		SRC_PORT,   ///< TCP/UDP source port.
		DST_PORT,   ///< TCP/UDP destination port.
		PROTO,	    ///< IP protocol number.
		DSCP,	    ///< Differentiated Services Code Point.
		FLOW_HASH,  ///< Five-tuple flow hash.
	};

	/** @brief Comparison operation selected by one predicate. */
	enum class op_id : uint8_t {
		EQ = 0,	 ///< Equal.
		NE,	 ///< Not equal.
		LT,	 ///< Less than.
		LE,	 ///< Less than or equal.
		GT,	 ///< Greater than.
		GE,	 ///< Greater than or equal.
	};

	field_id field{field_id::NONE};	 ///< Field to match.
	op_id op{op_id::EQ};		 ///< Comparison operation.
	uint32_t value{0};		 ///< Right-hand unsigned value.

	/**
	 * @brief Check whether this is the sole unconditional encoding.
	 *
	 * @return true only for `{NONE, EQ, 0}`.
	 */
	[[nodiscard]] constexpr bool is_unconditional() const noexcept
	{
		return field == field_id::NONE && op == op_id::EQ && value == 0u;
	}
};

static_assert(std::is_standard_layout_v<compiled_packet_route_condition>,
	      "compiled packet-route conditions must be standard-layout");
static_assert(std::is_trivially_copyable_v<compiled_packet_route_condition>,
	      "compiled packet-route conditions must be trivially copyable");
static_assert(sizeof(compiled_packet_route_condition) == 8u, "compiled packet-route condition layout changed");

/**
 * @brief Compile one complete authored packet-route condition.
 *
 * Empty input produces the sole unconditional encoding. Nonempty input must
 * use the exact `field op decimal_uint32` grammar and one supported packet
 * field. The function does not log or echo the complete untrusted expression.
 *
 * @param condition Authored condition text.
 * @return Compact predicate, or INVALID_ARGUMENT for malformed syntax or an
 *         unsupported field.
 */
[[nodiscard]] status_or<compiled_packet_route_condition> compile_packet_route_condition(std::string_view condition);

}  // namespace kinetum::common
