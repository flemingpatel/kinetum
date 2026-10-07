// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file module_descriptor_admission.cpp
 * @brief Private exact module-descriptor admission implementation.
 * @author Fleming Patel
 */

#include "src/dp/module/module_descriptor_admission.hpp"

#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include "src/sdk/module_abi_text.hpp"

namespace kinetum::dp::module
{
namespace
{

using kinetum::common::status;
using kinetum::common::status_code;

/**
 * @brief Construct one exact descriptor-admission failure.
 *
 * @param message Precise violated contract.
 * @return FAILED_PRECONDITION carrying @p message.
 */
[[nodiscard]] status descriptor_failure(std::string message)
{
	return status(status_code::FAILED_PRECONDITION, std::move(message));
}

/**
 * @brief Construct one missing-mandatory-callback failure.
 *
 * @param module_id Already validated descriptor identity.
 * @param callback Human-readable exact callback role.
 * @return FAILED_PRECONDITION naming the image and missing callback.
 */
[[nodiscard]] status missing_callback(std::string_view module_id, std::string_view callback)
{
	return descriptor_failure("module descriptor lacks mandatory " + std::string(callback) +
				  " callback: module_id=" + std::string(module_id));
}

}  // namespace

status validate_module_descriptor(const kinetum_module *descriptor)
{
	if (descriptor == nullptr) {
		return descriptor_failure("module descriptor is null");
	}
	if (!kinetum::sdk::valid_module_abi_text(descriptor->module_id)) {
		return descriptor_failure(
			"module descriptor module_id violates the bounded printable-ASCII ABI contract");
	}
	if (!kinetum::sdk::valid_module_abi_text(descriptor->module_version)) {
		return descriptor_failure(
			"module descriptor module_version violates the bounded printable-ASCII ABI contract: module_id=" +
			std::string(descriptor->module_id));
	}
	if (descriptor->abi_version != KINETUM_MODULE_ABI_VERSION) {
		std::ostringstream message;
		message << "module ABI version mismatch: module_id=" << descriptor->module_id
			<< " module=" << descriptor->abi_version << " host=" << KINETUM_MODULE_ABI_VERSION;
		return descriptor_failure(message.str());
	}
	if ((descriptor->flags & ~KINETUM_MOD_F_KNOWN_MASK) != 0u) {
		return descriptor_failure("module descriptor declares unknown capability flags: module_id=" +
					  std::string(descriptor->module_id));
	}
	const bool selects_contexts = (descriptor->flags & KINETUM_MOD_F_CONTEXT_SELECTION) != 0u;
	if (selects_contexts != (descriptor->select_contexts != nullptr)) {
		return descriptor_failure("module context-selection flag and callback disagree: module_id=" +
					  std::string(descriptor->module_id));
	}
	if (descriptor->prepare_config == nullptr) {
		return missing_callback(descriptor->module_id, "PREPARE");
	}
	if (descriptor->activate_config == nullptr) {
		return missing_callback(descriptor->module_id, "ACTIVATE");
	}
	if (descriptor->retire_config == nullptr) {
		return missing_callback(descriptor->module_id, "RETIRE");
	}
	if (descriptor->init == nullptr) {
		return missing_callback(descriptor->module_id, "INIT");
	}
	if (descriptor->fini == nullptr) {
		return missing_callback(descriptor->module_id, "FINI");
	}

	switch (descriptor->mode) {
	case KINETUM_MODULE_PASSIVE:
		if (descriptor->process == nullptr) {
			return missing_callback(descriptor->module_id, "PASSIVE process");
		}
		if (descriptor->ingest != nullptr || descriptor->run != nullptr || descriptor->on_control != nullptr) {
			return descriptor_failure("PASSIVE module descriptor declares ACTIVE callbacks: module_id=" +
						  std::string(descriptor->module_id));
		}
		break;
	case KINETUM_MODULE_ACTIVE:
		if (descriptor->process != nullptr) {
			return descriptor_failure(
				"ACTIVE module descriptor declares a PASSIVE process callback: module_id=" +
				std::string(descriptor->module_id));
		}
		if (descriptor->run == nullptr) {
			return missing_callback(descriptor->module_id, "ACTIVE run");
		}
		break;
	default:
		return descriptor_failure("module descriptor declares an unknown execution mode: module_id=" +
					  std::string(descriptor->module_id));
	}

	return status::ok();
}

}  // namespace kinetum::dp::module
