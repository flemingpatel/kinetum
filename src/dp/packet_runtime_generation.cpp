// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file packet_runtime_generation.cpp
 * @brief Complete packet-runtime generation input admission.
 * @author Fleming Patel
 */

#include "src/dp/packet_runtime_generation.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

#include "src/common/status.hpp"
#include "src/provider/deployment_plan_identity.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;

packet_runtime_generation_input::packet_runtime_generation_input(
	kinetum::gluon::v1::DeploymentPlan plan, provider::compiled_provider_topology topology,
	std::unique_ptr<epoch_transition_command_mailbox> command_mailbox, provider::admitted_provider_runtime admitted,
	std::vector<module::module_image_spec> module_images, uint64_t runtime_generation) noexcept
	: plan_(std::move(plan))
	, topology_(std::move(topology))
	, command_mailbox_(std::move(command_mailbox))
	, admitted_(std::move(admitted))
	, module_images_(std::move(module_images))
	, runtime_generation_(runtime_generation)
{
}

common::status_or<packet_runtime_generation_input> packet_runtime_generation_input::create(
	kinetum::gluon::v1::DeploymentPlan plan, provider::compiled_provider_topology topology,
	std::unique_ptr<epoch_transition_command_mailbox> command_mailbox, provider::admitted_provider_runtime admitted,
	std::vector<module::module_image_spec> module_images, uint64_t runtime_generation)
{
	try {
		if (runtime_generation == 0 || runtime_generation > std::numeric_limits<uint32_t>::max()) {
			return status::invalid_argument(
				"packet runtime generation is outside the exact provider ABI range");
		}
		const auto plan_status = provider::verify_deployment_plan_content_hash(plan);
		if (!plan_status.is_ok()) {
			return plan_status;
		}
		if (topology.source_plan_content_hash.empty() ||
		    topology.source_plan_content_hash != plan.content_hash()) {
			return status::failed_precondition(
				"compiled provider topology does not belong to the exact canonical plan");
		}
		if (command_mailbox == nullptr || !command_mailbox->ready_for_generation_adoption() ||
		    !topology.transition_topology.lifecycle_services.has_value()) {
			return status::invalid_argument(
				"packet runtime generation requires one pre-materialized coordinator command mailbox");
		}
		const auto coordinator_index =
			topology.transition_topology.lifecycle_services->coordinator_service_index;
		if (coordinator_index >= topology.transition_topology.runtime_services.size() ||
		    command_mailbox->capacity() !=
			    topology.transition_topology.runtime_services[coordinator_index].command_mailbox_capacity) {
			return status::failed_precondition(
				"coordinator command mailbox does not match the exact compiled service capacity");
		}

		std::vector<std::string> expected_module_ids;
		expected_module_ids.reserve(topology.logical_stages.size());
		for (const auto &logical_stage : topology.logical_stages) {
			if (!logical_stage.module_id.empty()) {
				expected_module_ids.push_back(logical_stage.module_id);
			}
		}
		std::sort(expected_module_ids.begin(), expected_module_ids.end());
		expected_module_ids.erase(std::unique(expected_module_ids.begin(), expected_module_ids.end()),
					  expected_module_ids.end());
		for (const auto &context : topology.module_contexts) {
			if (!std::binary_search(expected_module_ids.begin(), expected_module_ids.end(),
						context.module_id)) {
				return status::internal_error(
					"compiled module context references an absent logical module identity");
			}
		}

		std::string previous_module_id;
		for (const auto &image : module_images) {
			if (image.module_id.empty() || image.canonical_path.empty()) {
				return status::invalid_argument(
					"module image authority requires identity and canonical path");
			}
			if (!previous_module_id.empty() && previous_module_id >= image.module_id) {
				return status::invalid_argument(
					"module image authority must be strictly sorted and unique by module identity");
			}
			if (!image.canonical_path.is_absolute() ||
			    image.canonical_path != image.canonical_path.lexically_normal()) {
				return status::invalid_argument(
					"module image authority requires a normalized absolute path");
			}
			previous_module_id = image.module_id;
		}
		if (module_images.size() != expected_module_ids.size() ||
		    !std::equal(module_images.begin(), module_images.end(), expected_module_ids.begin(),
				[](const auto &image, const auto &expected) { return image.module_id == expected; })) {
			return status::invalid_argument(
				"module image authority must equal the exact compiled module identity set");
		}

		return packet_runtime_generation_input(std::move(plan), std::move(topology), std::move(command_mailbox),
						       std::move(admitted), std::move(module_images),
						       runtime_generation);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("packet runtime generation admission exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      "packet runtime generation admission exceeds a bounded host container");
	}
}

}  // namespace kinetum::dp
