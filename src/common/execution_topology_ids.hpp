// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file execution_topology_ids.hpp
 * @brief Shared deterministic ID helpers for resolved execution topology.
 * @author Fleming Patel
 *
 * Gluon emits execution topology and the dataplane validates/consumes it. Both
 * sides must agree on identifier grammar and generated-ID construction, or a
 * plan could pass one phase and fail another for reasons unrelated to runtime
 * correctness. This header is the single authority for the default lane and
 * delimiter-based stage-instance, stream, worker, and boundary IDs.
 */

#include <cstdint>
#include <string>
#include <string_view>

namespace kinetum::common::execution_topology
{

/**
 * @brief Default execution identity emitted when no stream intent requests extra lanes.
 */
inline constexpr std::string_view DEFAULT_LANE_ID = "lane_0";

/**
 * @brief Check whether a character may start a topology ID component.
 *
 * @param value Character to validate.
 * @return true when value is an ASCII letter or underscore.
 */
[[nodiscard]] constexpr bool is_identifier_first_char(char value) noexcept
{
	return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || value == '_';
}

/**
 * @brief Check whether a character may appear after the first component byte.
 *
 * @param value Character to validate.
 * @return true when value is an ASCII letter, digit, or underscore.
 */
[[nodiscard]] constexpr bool is_identifier_char(char value) noexcept
{
	return is_identifier_first_char(value) || (value >= '0' && value <= '9');
}

/**
 * @brief Validate a source component used in generated topology IDs.
 *
 * Generated IDs use delimiter-separated stable components. The admitted input
 * grammar excludes delimiters so IDs remain deterministic and injective without
 * an escaping layer.
 *
 * @param value Candidate identifier.
 * @return true when value matches [A-Za-z_][A-Za-z0-9_]*.
 */
[[nodiscard]] constexpr bool is_topology_identifier(std::string_view value) noexcept
{
	if (value.empty()) {
		return false;
	}
	if (!is_identifier_first_char(value.front())) {
		return false;
	}
	value.remove_prefix(1u);
	for (const char c : value) {
		if (!is_identifier_char(c)) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Build the deterministic execution-lane ID for one compact lane index.
 *
 * @param lane_index Compact lane index emitted by topology lowering.
 * @return Lane ID in `lane_<lane_index>` form.
 */
[[nodiscard]] inline std::string make_lane_id(uint32_t lane_index)
{
	return "lane_" + std::to_string(lane_index);
}

/**
 * @brief Build the deterministic stage-instance ID for one lane.
 *
 * @param logical_stage_id Logical stage ID from the authored pipeline.
 * @param lane_id Execution lane ID.
 * @return Stage-instance ID in `<logical_stage_id>@<lane_id>` form.
 */
[[nodiscard]] inline std::string make_stage_instance_id(std::string_view logical_stage_id, std::string_view lane_id)
{
	std::string out;
	out.reserve(logical_stage_id.size() + 1u + lane_id.size());
	out.append(logical_stage_id.data(), logical_stage_id.size());
	out.push_back('@');
	out.append(lane_id.data(), lane_id.size());
	return out;
}

/**
 * @brief Build the deterministic stream ID for one logical port and lane.
 *
 * @param logical_port_name Logical port name from plan.ports[].
 * @param direction_suffix Canonical stream direction suffix, usually `rx` or `tx`.
 * @param lane_id Execution lane ID.
 * @return Stream ID in `<logical_port_name>.<direction_suffix>.<lane_id>` form.
 */
[[nodiscard]] inline std::string make_io_stream_id(std::string_view logical_port_name,
						   std::string_view direction_suffix, std::string_view lane_id)
{
	std::string out;
	out.reserve(logical_port_name.size() + 1u + direction_suffix.size() + 1u + lane_id.size());
	out.append(logical_port_name.data(), logical_port_name.size());
	out.push_back('.');
	out.append(direction_suffix.data(), direction_suffix.size());
	out.push_back('.');
	out.append(lane_id.data(), lane_id.size());
	return out;
}

/**
 * @brief Build the deterministic runtime-worker ID for one region/lane owner.
 *
 * @param region_id Runtime region ID.
 * @param lane_id Execution lane ID.
 * @return Worker ID in `worker_r<region_id>_<lane_id>` form.
 */
[[nodiscard]] inline std::string make_worker_id(int32_t region_id, std::string_view lane_id)
{
	std::string out = "worker_r";
	out += std::to_string(region_id);
	out.push_back('_');
	out.append(lane_id.data(), lane_id.size());
	return out;
}

/**
 * @brief Build the deterministic ID for one directed executable boundary.
 *
 * Both endpoint IDs must be canonical stage-instance IDs built from topology
 * identifier atoms. Those atoms exclude `.` and each stage-instance ID has the
 * fixed `<logical_stage_id>@<lane_id>` shape, so the two dot-delimited endpoint
 * components remain injective without escaping or an order-dependent suffix.
 * Direction is part of the identity: A-to-B and B-to-A are distinct boundaries.
 *
 * @param from_stage_instance_id Canonical source stage-instance ID.
 * @param to_stage_instance_id Canonical destination stage-instance ID.
 * @return Boundary ID in `boundary.<from>.<to>` form.
 */
[[nodiscard]] inline std::string make_boundary_id(std::string_view from_stage_instance_id,
						  std::string_view to_stage_instance_id)
{
	std::string out("boundary.");
	out.reserve(out.size() + from_stage_instance_id.size() + 1u + to_stage_instance_id.size());
	out.append(from_stage_instance_id.data(), from_stage_instance_id.size());
	out.push_back('.');
	out.append(to_stage_instance_id.data(), to_stage_instance_id.size());
	return out;
}

}  // namespace kinetum::common::execution_topology
