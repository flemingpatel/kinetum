// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file packet_route_condition.cpp
 * @brief Provider-neutral packet-route predicate compilation.
 * @author Fleming Patel
 */

#include "src/common/packet_route_condition.hpp"

#include <string>

#include <kinetum/algo/condition_parse.hpp>

namespace kinetum::common
{

status_or<compiled_packet_route_condition> compile_packet_route_condition(std::string_view condition)
{
	compiled_packet_route_condition out;
	if (condition.empty()) {
		return out;
	}

	kinetum::algo::condition_expression parsed;
	kinetum::algo::condition_parse_error parse_error = kinetum::algo::condition_parse_error::NONE;
	if (!kinetum::algo::parse_condition_expression(condition, parsed, &parse_error)) {
		return status::invalid_argument("invalid packet-route condition syntax: " +
						std::string(kinetum::algo::condition_parse_error_name(parse_error)));
	}

	if (parsed.field == "src_ip") {
		out.field = compiled_packet_route_condition::field_id::SRC_IP;
	} else if (parsed.field == "dst_ip") {
		out.field = compiled_packet_route_condition::field_id::DST_IP;
	} else if (parsed.field == "src_port") {
		out.field = compiled_packet_route_condition::field_id::SRC_PORT;
	} else if (parsed.field == "dst_port") {
		out.field = compiled_packet_route_condition::field_id::DST_PORT;
	} else if (parsed.field == "proto") {
		out.field = compiled_packet_route_condition::field_id::PROTO;
	} else if (parsed.field == "dscp") {
		out.field = compiled_packet_route_condition::field_id::DSCP;
	} else if (parsed.field == "flow_hash") {
		out.field = compiled_packet_route_condition::field_id::FLOW_HASH;
	} else {
		return status::invalid_argument("packet-route condition names an unsupported field");
	}

	switch (parsed.op) {
	case kinetum::algo::condition_op::EQ:
		out.op = compiled_packet_route_condition::op_id::EQ;
		break;
	case kinetum::algo::condition_op::NE:
		out.op = compiled_packet_route_condition::op_id::NE;
		break;
	case kinetum::algo::condition_op::LT:
		out.op = compiled_packet_route_condition::op_id::LT;
		break;
	case kinetum::algo::condition_op::LE:
		out.op = compiled_packet_route_condition::op_id::LE;
		break;
	case kinetum::algo::condition_op::GT:
		out.op = compiled_packet_route_condition::op_id::GT;
		break;
	case kinetum::algo::condition_op::GE:
		out.op = compiled_packet_route_condition::op_id::GE;
		break;
	}

	out.value = parsed.value;
	return out;
}

}  // namespace kinetum::common
