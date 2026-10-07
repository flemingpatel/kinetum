// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file module_lifecycle_adapter.cpp
 * @brief Exact module lifecycle adapter implementation.
 * @author Fleming Patel
 */

#include "src/dp/module/module_lifecycle_adapter.hpp"

#include <exception>

#include "src/dp/module/module_manager.hpp"

namespace kinetum::dp::module
{

using kinetum::dp::lifecycle::lifecycle_prepare_callback_code;
using kinetum::dp::lifecycle::prepared_config_record;

namespace
{

/**
 * @brief Read cancellation from one borrowed lifecycle callback context.
 *
 * @param opaque Borrowed non-null kinetum_lifecycle_ctx pointer.
 * @return true when the owning operation has requested cancellation.
 */
[[nodiscard]] bool lifecycle_cancelled_probe(const void *opaque) noexcept
{
	const auto *context = static_cast<const kinetum_lifecycle_ctx *>(opaque);
	return kinetum_lifecycle_cancellation_requested(context);
}

/**
 * @brief Convert any fixed-width module error into a non-overflowing diagnostic.
 *
 * @param error Module callback result.
 * @return Unsigned magnitude preserving the complete int32_t domain.
 */
[[nodiscard]] uint32_t module_error_diagnostic(kinetum_error error) noexcept
{
	const auto widened = static_cast<int64_t>(error);
	return static_cast<uint32_t>(widened < 0 ? -widened : widened);
}

}  // namespace

module_lifecycle_adapter::module_lifecycle_adapter(
	loaded_module_image &image, const kinetum::dp::lifecycle::lifecycle_context_identity &identity) noexcept
	: image_(image)
	, identity_(identity)
{
}

bool module_lifecycle_adapter::matches_(const ::kinetum_lifecycle_ctx &context) const noexcept
{
	kinetum_lifecycle_identity identity{};
	if (kinetum_lifecycle_get_identity(&context, &identity) != KINETUM_OK || identity.module_id == nullptr ||
	    identity.context_instance_id == nullptr) {
		return false;
	}
	return identity.module_id == identity_.module_id &&
	       identity.context_instance_id == identity_.context_instance_id &&
	       identity.module_image_index == identity_.module_image_index &&
	       identity.context_index == identity_.context_index && identity.worker_index == identity_.worker_index &&
	       identity.cpu_core_id == identity_.cpu_core_id && identity.numa_node == identity_.numa_node &&
	       identity.module_image_index == image_.module_image_index && identity.module_id == image_.module_id;
}

kinetum::dp::lifecycle::lifecycle_prepare_callback_result
module_lifecycle_adapter::prepare(const ::kinetum_lifecycle_ctx &context, const void *payload,
				  std::size_t payload_size) noexcept
{
	if (!matches_(context) || !kinetum::dp::lifecycle::valid_lifecycle_payload_span(payload, payload_size) ||
	    !image_.descriptor || !image_.descriptor->prepare_config) {
		return {lifecycle_prepare_callback_code::FAILURE, module_error_diagnostic(KINETUM_ERR_INVALID_ARG), {}};
	}

	auto turn_or = image_.lifecycle_serialization.acquire(kinetum::dp::lifecycle::lifecycle_deadline(context),
							      lifecycle_cancelled_probe, &context);
	if (!turn_or.is_ok()) {
		const auto code = turn_or.error().code() == kinetum::common::status_code::CANCELLED ?
					  lifecycle_prepare_callback_code::CANCELLED :
					  lifecycle_prepare_callback_code::FAILURE;
		const auto diagnostic = turn_or.error().code() == kinetum::common::status_code::CANCELLED ?
						module_error_diagnostic(KINETUM_ERR_CANCELLED) :
						module_error_diagnostic(KINETUM_ERR_TIMEOUT);
		return {code, diagnostic, {}};
	}
	auto turn = std::move(turn_or).value();

	kinetum_prepared_config prepared{};
	kinetum_error result = KINETUM_ERR_INTERNAL;
	try {
		result = image_.descriptor->prepare_config(&context,
							   kinetum::dp::lifecycle::lifecycle_current_epoch(context),
							   payload, payload_size, &prepared);
	} catch (...) {
		if (prepared.owner_handle != nullptr || prepared.packet_config != nullptr) {
			std::terminate();
		}
		return {lifecycle_prepare_callback_code::FAILURE, module_error_diagnostic(KINETUM_ERR_INTERNAL), {}};
	}

	if (result != KINETUM_OK) {
		// Failure transfers no ownership. Returning partial pointers would make it
		// impossible for the platform to retire the artifact exactly once.
		if (prepared.owner_handle != nullptr || prepared.packet_config != nullptr) {
			std::terminate();
		}
		const auto code = result == KINETUM_ERR_CANCELLED ? lifecycle_prepare_callback_code::CANCELLED :
								    lifecycle_prepare_callback_code::FAILURE;
		return {code, module_error_diagnostic(result), {}};
	}

	return {lifecycle_prepare_callback_code::SUCCESS, 0,
		prepared_config_record{prepared.owner_handle, prepared.packet_config}};
}

void module_lifecycle_adapter::retire(const ::kinetum_lifecycle_ctx &context,
				      kinetum::dp::lifecycle::prepared_config_record prepared) noexcept
{
	if (!matches_(context) || !image_.descriptor || !image_.descriptor->retire_config) {
		std::terminate();
	}

	auto turn_or = image_.lifecycle_serialization.acquire(kinetum::dp::lifecycle::lifecycle_deadline(context),
							      lifecycle_cancelled_probe, &context);
	if (!turn_or.is_ok()) {
		// Once RETIRE owns the token, abandoning the callback would leak exact
		// ownership. The coordinator may avoid dispatch before a deadline, but an
		// admitted retire cannot be converted back into an ignorable failure.
		std::terminate();
	}
	auto turn = std::move(turn_or).value();
	try {
		image_.descriptor->retire_config(&context, kinetum::dp::lifecycle::lifecycle_current_epoch(context),
						 kinetum_prepared_config{prepared.owner_handle,
									 prepared.packet_config});
	} catch (...) {
		std::terminate();
	}
}

}  // namespace kinetum::dp::module
