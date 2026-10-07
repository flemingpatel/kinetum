// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dataplane_health_contract.cpp
 * @brief Exact DP startup-readiness response admission implementation.
 * @author Fleming Patel
 */

#include "src/common/dataplane_health_contract.hpp"

#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>

#include "src/common/application_status.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/logging_status.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/version.hpp"

namespace kinetum::common
{
namespace
{

/**
 * @brief Normalize validation of one transport-successful Health response.
 * @param failure Exact failure from a shared protobuf validator.
 * @param malformed_message Fixed diagnostic for malformed remote data.
 * @return Resource/size failure unchanged; DATA_LOSS for malformed wire data.
 */
[[nodiscard]] status map_health_response_validation_failure(const status &failure, std::string_view malformed_message)
{
	if (failure.is_ok() || malformed_message.empty()) {
		return status::internal_error("Health response validation mapping requires one failure and diagnostic");
	}
	if (failure.code() == status_code::RESOURCE_EXHAUSTED || failure.code() == status_code::OUT_OF_RANGE) {
		return failure;
	}
	return status::data_loss(std::string(malformed_message));
}

}  // namespace

status_or<dataplane_health_identity>
validate_dataplane_startup_health(const kinetum::dataplane::v1::HealthResponse &response)
{
	try {
		const auto unknown = reject_unknown_protobuf_fields_recursive(response, "HealthResponse");
		if (!unknown.is_ok()) {
			return map_health_response_validation_failure(
				unknown, "Data Plane Health returned unknown protobuf fields");
		}
		const auto enums = reject_invalid_protobuf_enum_values_recursive(response, "HealthResponse");
		if (!enums.is_ok()) {
			return map_health_response_validation_failure(
				enums, "Data Plane Health returned an undeclared enum value");
		}
		status_code application_code{};
		if (!decode_exact_application_status(response.status(), application_code)) {
			return status::data_loss("Data Plane Health returned a malformed application status");
		}
		if (response.version() != KINETUM_VERSION_STRING) {
			return status::data_loss("Data Plane Health returned a foreign runtime version");
		}
		const auto logging = validate_logging_status(response.logging());
		if (!logging.is_ok()) {
			return logging;
		}
		if (application_code != status_code::OK) {
			if (response.state() != kinetum::dataplane::v1::HealthResponse::STATE_ERROR ||
			    response.runtime_generation() != 0u || response.active_epoch() != 0u ||
			    response.active_workers() != 0u || response.expected_workers() != 0u) {
				return status::data_loss("Data Plane Health failure retained readiness identity");
			}
			return status(application_code, response.status().message(), response.status().details());
		}
		if (!response.status().message().empty() || !response.status().details().empty()) {
			return status::data_loss("Data Plane Health success carried diagnostic residue");
		}

		switch (response.state()) {
		case kinetum::dataplane::v1::HealthResponse::STATE_STARTING:
			if (response.runtime_generation() != 0u || response.active_epoch() != 0u ||
			    response.active_workers() != 0u || response.expected_workers() != 0u) {
				return status::data_loss("Data Plane STARTING Health retained runtime identity");
			}
			break;
		case kinetum::dataplane::v1::HealthResponse::STATE_CONTROL_READY:
			if (response.runtime_generation() == 0u ||
			    response.runtime_generation() > std::numeric_limits<uint32_t>::max() ||
			    response.active_epoch() != 0u || response.active_workers() != 0u ||
			    response.expected_workers() == 0u) {
				return status::data_loss("Data Plane CONTROL_READY Health retained packet identity");
			}
			break;
		case kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY:
			if (response.runtime_generation() == 0u ||
			    response.runtime_generation() > std::numeric_limits<uint32_t>::max() ||
			    response.expected_workers() == 0u || !valid_epoch_id(response.active_epoch()) ||
			    response.active_workers() != response.expected_workers()) {
				return status::data_loss("Data Plane PACKET_READY Health identity is incomplete");
			}
			break;
		case kinetum::dataplane::v1::HealthResponse::STATE_UNSPECIFIED:
			return status::data_loss("Data Plane Health omitted its required readiness state");
		case kinetum::dataplane::v1::HealthResponse::STATE_DRAINING:
		case kinetum::dataplane::v1::HealthResponse::STATE_DRAINED:
		case kinetum::dataplane::v1::HealthResponse::STATE_STOPPING:
		case kinetum::dataplane::v1::HealthResponse::STATE_STOPPED:
		case kinetum::dataplane::v1::HealthResponse::STATE_ERROR:
			return status::failed_precondition("Data Plane Health is not a startup-ready state");
		case kinetum::dataplane::v1::HealthResponse_State_HealthResponse_State_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::dataplane::v1::HealthResponse_State_HealthResponse_State_INT_MAX_SENTINEL_DO_NOT_USE_:
			return status::data_loss("Data Plane Health returned an invalid protobuf readiness sentinel");
		}

		return dataplane_health_identity{
			.state = response.state(),
			.runtime_generation = response.runtime_generation(),
			.active_epoch = response.active_epoch(),
			.active_workers = response.active_workers(),
			.expected_workers = response.expected_workers(),
		};
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane Health validation exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane Health validation exceeded host size limits");
	}
}

}  // namespace kinetum::common
