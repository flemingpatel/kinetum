// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_logging_status.cpp
 * @brief Logging counter presence, exact schema projection, and readiness independence.
 * @author Fleming Patel
 */

#include <array>
#include <string>

#include <gtest/gtest.h>

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/dataplane_health_contract.hpp"
#include "src/common/logging_status.hpp"
#include "src/common/version.hpp"

namespace kinetum::common
{
namespace
{

/** @return Complete measured-zero evidence authored independently of the production projector. */
kinetum::common::v1::LoggingStatus available_logging()
{
	kinetum::common::v1::LoggingStatus result;
	result.set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_AVAILABLE);
	result.set_accepted_records(0);
	result.set_queue_rejections(0);
	result.set_format_rejections(0);
	result.set_unavailable_rejections(0);
	result.set_undelivered_records(0);
	result.set_write_failures(0);
	result.set_console_failures(0);
	result.set_truncated_records(0);
	result.set_packet_thread_rejections(0);
	result.set_delivery_timeouts(0);
	return result;
}

/** All counter presences are independently required, including zero. */
constexpr std::array<const char *, 10> COUNTERS{
	"accepted_records", "queue_rejections", "format_rejections", "unavailable_rejections",	 "undelivered_records",
	"write_failures",   "console_failures", "truncated_records", "packet_thread_rejections", "delivery_timeouts"};

}  // namespace

/** @brief Health extensions use fresh numbers and share one logging observation message. */
TEST(logging_status, health_extensions_keep_their_exact_fresh_field_numbers)
{
	const auto *cp = kinetum::control::v1::HealthCheckResponse::descriptor()->FindFieldByName("logging");
	const auto *dp = kinetum::dataplane::v1::HealthResponse::descriptor()->FindFieldByName("logging");
	ASSERT_NE(cp, nullptr);
	ASSERT_NE(dp, nullptr);
	EXPECT_EQ(cp->number(), 4);
	EXPECT_EQ(dp->number(), 12);
	EXPECT_EQ(cp->message_type(), kinetum::common::v1::LoggingStatus::descriptor());
	EXPECT_EQ(dp->message_type(), cp->message_type());
	EXPECT_EQ(cp->message_type()->FindFieldByName("packet_thread_rejections")->number(), 11);
	EXPECT_EQ(cp->message_type()->FindFieldByName("delivery_timeouts")->number(), 12);
	for (const char *name : COUNTERS) {
		const auto *field = cp->message_type()->FindFieldByName(name);
		ASSERT_NE(field, nullptr) << name;
		EXPECT_TRUE(field->has_presence()) << name;
	}
}

/** @brief Missing evidence never becomes a fabricated measured zero. */
TEST(logging_status, every_zero_counter_requires_explicit_presence)
{
	const auto complete = available_logging();
	ASSERT_TRUE(validate_logging_status(complete).is_ok());
	for (const char *name : COUNTERS) {
		SCOPED_TRACE(name);
		auto missing = complete;
		missing.GetReflection()->ClearField(&missing, missing.GetDescriptor()->FindFieldByName(name));
		EXPECT_FALSE(validate_logging_status(missing).is_ok());
	}
	EXPECT_FALSE(validate_logging_status(kinetum::common::v1::LoggingStatus{}).is_ok());
}

/** @brief Availability and first-cause evidence must agree without live counter-sum assumptions. */
TEST(logging_status, unavailable_and_recovered_observations_are_exact)
{
	auto observation = available_logging();
	observation.set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_UNAVAILABLE);
	EXPECT_FALSE(validate_logging_status(observation).is_ok());
	observation.set_failure("append: errno=28");
	EXPECT_FALSE(validate_logging_status(observation).is_ok());
	observation.set_write_failures(1);
	observation.set_accepted_records(3);
	observation.set_undelivered_records(3);
	EXPECT_TRUE(validate_logging_status(observation).is_ok());
	observation.set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_AVAILABLE);
	EXPECT_FALSE(validate_logging_status(observation).is_ok());
	observation.clear_failure();
	EXPECT_TRUE(validate_logging_status(observation).is_ok());
}

/** @brief Unknown fields, states, and unbounded diagnostic text reject as malformed evidence. */
TEST(logging_status, malformed_remote_evidence_rejects)
{
	auto observation = available_logging();
	observation.GetReflection()->MutableUnknownFields(&observation)->AddVarint(99, 1);
	EXPECT_FALSE(validate_logging_status(observation).is_ok());
	observation = available_logging();
	observation.set_destination(static_cast<kinetum::common::v1::LoggingStatus::DestinationState>(99));
	EXPECT_FALSE(validate_logging_status(observation).is_ok());
	observation = available_logging();
	observation.set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_UNAVAILABLE);
	observation.set_write_failures(1);
	observation.set_failure(std::string(256, 'x'));
	EXPECT_FALSE(validate_logging_status(observation).is_ok());
	observation.set_failure("unexpected\nrecord");
	EXPECT_FALSE(validate_logging_status(observation).is_ok());
}

/** @brief An unavailable logging destination does not revoke valid packet readiness. */
TEST(logging_status, logging_degradation_is_not_packet_readiness_authority)
{
	kinetum::dataplane::v1::HealthResponse response;
	response.set_state(kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY);
	response.mutable_status()->set_code(0);
	response.mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
	response.set_version(KINETUM_VERSION_STRING);
	response.set_runtime_generation(1);
	response.set_active_epoch(2);
	response.set_active_workers(3);
	response.set_expected_workers(3);
	*response.mutable_logging() = available_logging();
	response.mutable_logging()->set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_UNAVAILABLE);
	response.mutable_logging()->set_write_failures(1);
	response.mutable_logging()->set_failure("append: errno=28");
	EXPECT_TRUE(validate_dataplane_startup_health(response).is_ok());
	response.clear_logging();
	EXPECT_FALSE(validate_dataplane_startup_health(response).is_ok());
}

/** @brief The producer clears reused payloads and writes every measured-zero presence. */
TEST(logging_status, projection_writes_complete_process_observation)
{
	auto observation = available_logging();
	observation.GetReflection()->MutableUnknownFields(&observation)->AddVarint(99, 1);
	project_process_logging_status(observation);
	EXPECT_TRUE(validate_logging_status(observation).is_ok());
	for (const char *name : COUNTERS) {
		const auto *field = observation.GetDescriptor()->FindFieldByName(name);
		EXPECT_TRUE(observation.GetReflection()->HasField(observation, field)) << name;
	}
}

}  // namespace kinetum::common
