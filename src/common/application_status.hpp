// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file application_status.hpp
 * @brief Single application-level RPC status classification authority.
 * @author Fleming Patel
 *
 * Unary Kinetum RPCs return transport status and an embedded
 * `kinetum.common.v1.Status`. This header gives every in-tree consumer one
 * exact interpretation of that embedded result so a transport-successful
 * error cannot be laundered into data success.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent use.
 *
 * @par Performance
 * Constant-time field inspection with no allocation. The helper is suitable
 * for cold control, supervision, and tooling paths; it is not a packet-path
 * contract.
 */

#include <cstdint>

#include "gen/kinetum/common/v1/common.pb.h"
#include "src/common/status.hpp"

namespace kinetum::common
{

/** @brief Complete classification of one embedded application status. */
enum class application_status_outcome : uint8_t {
	SUCCESS = 0,	///< Numeric success with no contradictory error classification.
	FAILURE = 1,	///< Explicit nonzero application failure.
	MALFORMED = 2,	///< Contradictory or undeclared status representation.
};

/**
 * @brief Map one declared platform status to its exact wire classification.
 * @param code Platform status category.
 * @return Canonical application error enum for @p code.
 */
[[nodiscard]] constexpr kinetum::common::v1::ErrorCode application_error_code(status_code code) noexcept
{
	using kinetum::common::v1::ErrorCode;
	switch (code) {
	case status_code::OK:
		return ErrorCode::ERROR_CODE_OK;
	case status_code::CANCELLED:
		return ErrorCode::ERROR_CODE_CANCELLED;
	case status_code::UNKNOWN:
		return ErrorCode::ERROR_CODE_UNKNOWN;
	case status_code::INVALID_ARGUMENT:
		return ErrorCode::ERROR_CODE_INVALID_ARGUMENT;
	case status_code::DEADLINE_EXCEEDED:
		return ErrorCode::ERROR_CODE_DEADLINE_EXCEEDED;
	case status_code::NOT_FOUND:
		return ErrorCode::ERROR_CODE_NOT_FOUND;
	case status_code::ALREADY_EXISTS:
		return ErrorCode::ERROR_CODE_ALREADY_EXISTS;
	case status_code::PERMISSION_DENIED:
		return ErrorCode::ERROR_CODE_PERMISSION_DENIED;
	case status_code::RESOURCE_EXHAUSTED:
	case status_code::POOL_EXHAUSTED:
		return ErrorCode::ERROR_CODE_RESOURCE_EXHAUSTED;
	case status_code::FAILED_PRECONDITION:
		return ErrorCode::ERROR_CODE_FAILED_PRECONDITION;
	case status_code::ABORTED:
		return ErrorCode::ERROR_CODE_ABORTED;
	case status_code::OUT_OF_RANGE:
		return ErrorCode::ERROR_CODE_OUT_OF_RANGE;
	case status_code::UNIMPLEMENTED:
		return ErrorCode::ERROR_CODE_UNIMPLEMENTED;
	case status_code::INTERNAL_ERROR:
	case status_code::MODULE_ERROR:
		return ErrorCode::ERROR_CODE_INTERNAL;
	case status_code::UNAVAILABLE:
		return ErrorCode::ERROR_CODE_UNAVAILABLE;
	case status_code::DATA_LOSS:
		return ErrorCode::ERROR_CODE_DATA_LOSS;
	case status_code::UNAUTHENTICATED:
		return ErrorCode::ERROR_CODE_UNAUTHENTICATED;
	}
	return ErrorCode::ERROR_CODE_UNKNOWN;
}

/**
 * @brief Decode one exact declared numeric application status.
 * @param value Candidate wire integer.
 * @param[out] code Replaced only for one declared value.
 * @return true when @p value exactly names a platform status code.
 */
[[nodiscard]] constexpr bool decode_application_status_code(int32_t value, status_code &code) noexcept
{
	const auto candidate = static_cast<status_code>(value);
	switch (candidate) {
	case status_code::OK:
	case status_code::CANCELLED:
	case status_code::UNKNOWN:
	case status_code::INVALID_ARGUMENT:
	case status_code::DEADLINE_EXCEEDED:
	case status_code::NOT_FOUND:
	case status_code::ALREADY_EXISTS:
	case status_code::PERMISSION_DENIED:
	case status_code::RESOURCE_EXHAUSTED:
	case status_code::FAILED_PRECONDITION:
	case status_code::ABORTED:
	case status_code::OUT_OF_RANGE:
	case status_code::UNIMPLEMENTED:
	case status_code::INTERNAL_ERROR:
	case status_code::UNAVAILABLE:
	case status_code::DATA_LOSS:
	case status_code::UNAUTHENTICATED:
	case status_code::POOL_EXHAUSTED:
	case status_code::MODULE_ERROR:
		code = candidate;
		return true;
	}
	return false;
}

/**
 * @brief Decode one application status under the exact code/error relation.
 * @param wire Candidate embedded application status.
 * @param[out] code Replaced only for one canonical representation.
 * @return true when both numeric and semantic classifications agree exactly.
 */
[[nodiscard]] inline bool decode_exact_application_status(const kinetum::common::v1::Status &wire,
							  status_code &code) noexcept
{
	status_code decoded{};
	if (!decode_application_status_code(wire.code(), decoded) ||
	    wire.error_code() != application_error_code(decoded)) {
		return false;
	}
	code = decoded;
	return true;
}

/**
 * @brief Classify one embedded application status without inference.
 *
 * Code zero succeeds only with `ERROR_CODE_UNSPECIFIED` (the proto3 default)
 * or `ERROR_CODE_OK` (the explicit-success spelling used by DP). A non-success
 * error classification beside code zero, `ERROR_CODE_OK` beside a nonzero code,
 * or an undeclared enum number is malformed. Other nonzero codes are failures
 * whether or not their optional semantic classification is present.
 *
 * @param status Candidate embedded status.
 * @return SUCCESS, FAILURE, or MALFORMED under the exact relation above.
 */
[[nodiscard]] inline application_status_outcome
classify_application_status(const kinetum::common::v1::Status &status) noexcept
{
	const auto error_code = status.error_code();
	if (!kinetum::common::v1::ErrorCode_IsValid(static_cast<int>(error_code))) {
		return application_status_outcome::MALFORMED;
	}
	if (status.code() == 0) {
		const bool success_classification = error_code == kinetum::common::v1::ERROR_CODE_UNSPECIFIED ||
						    error_code == kinetum::common::v1::ERROR_CODE_OK;
		return success_classification ? application_status_outcome::SUCCESS :
						application_status_outcome::MALFORMED;
	}
	return error_code == kinetum::common::v1::ERROR_CODE_OK ? application_status_outcome::MALFORMED :
								  application_status_outcome::FAILURE;
}

/**
 * @brief Return whether one embedded application status is exact success.
 *
 * @param status Candidate embedded status.
 * @return true only when `classify_application_status()` returns SUCCESS.
 */
[[nodiscard]] inline bool application_status_succeeded(const kinetum::common::v1::Status &status) noexcept
{
	return classify_application_status(status) == application_status_outcome::SUCCESS;
}

}  // namespace kinetum::common
