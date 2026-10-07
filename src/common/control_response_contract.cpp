// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file control_response_contract.cpp
 * @brief Exact shared Control Plane response admission implementation.
 * @author Fleming Patel
 */

#include "src/common/control_response_contract.hpp"

#include <new>
#include <stdexcept>

#include "src/common/application_status.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/status.hpp"

namespace kinetum::common
{

status_or<status_code> validate_control_response_envelope(const google::protobuf::Message &response,
							  const kinetum::common::v1::Status &application,
							  std::string_view message_name)
{
	try {
		const auto unknown = reject_unknown_protobuf_fields_recursive(response, message_name);
		if (!unknown.is_ok()) {
			return status::data_loss("control response contains unknown fields");
		}
		const auto enums = reject_invalid_protobuf_enum_values_recursive(response, message_name);
		if (!enums.is_ok()) {
			return status::data_loss("control response contains an undeclared enum value");
		}

		status_code code{};
		if (!decode_exact_application_status(application, code)) {
			return status::data_loss("control response contains a malformed application status");
		}
		if (code == status_code::OK && (!application.message().empty() || !application.details().empty())) {
			return status::data_loss("control success contains diagnostic residue");
		}
		return code;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("control response validation exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "control response validation exceeded host size limits");
	}
}

}  // namespace kinetum::common
