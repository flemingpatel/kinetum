// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dp_lifecycle.cpp
 * @brief Fail-closed DP lifecycle RPC contract tests.
 * @author Fleming Patel
 *
 * Drain, DrainStatus, Shutdown, and DumpState have stable wire surfaces but no
 * fixed-epoch runtime mutation owner. These tests prove that the merged
 * production service returns transport success with one exact application-
 * level unavailable result, clears every synthetic output, and cannot mutate
 * the sole runtime readiness publication.
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <google/protobuf/descriptor.h>

#include "gen/kinetum/common/v1/common.pb.h"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/dataplane_control_service.hpp"
#include "tests/packet_runtime_test_fixture.hpp"

namespace kinetum::dp
{
namespace
{

using kinetum::common::status_code;
using kinetum::test::packet_runtime_test_owner;

/** Expected public diagnostic when lifecycle authority is unavailable. */
constexpr char RUNTIME_LIFECYCLE_UNAVAILABLE[] = "Data Plane runtime lifecycle operation is unavailable";

/** @brief Per-test fixture owning one isolated CONTROL_READY runtime. */
class DpLifecycleTest : public ::testing::Test {
    protected:
	/** @brief Materialize one fresh runtime without inheriting prior-test affinity. */
	void SetUp() override
	{
		auto owner_or = packet_runtime_test_owner::create();
		ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
		owner_ = std::move(owner_or).value();
	}

	/** @brief Retire the runtime and restore calling-thread affinity after each row. */
	void TearDown() override
	{
		owner_.reset();
	}

	/** @return Exact fixture-owned runtime. */
	[[nodiscard]] partitioned_runtime &runtime() noexcept
	{
		return owner_->runtime();
	}

	/** @return Exact canonical request belonging to the fixture runtime. */
	[[nodiscard]] const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &bootstrap_request() const noexcept
	{
		return owner_->bootstrap_request();
	}

	/** @return Mailbox-serviced Bootstrap result for the exact fixture request. */
	[[nodiscard]] common::status_or<fixed_epoch_bootstrap_result> bootstrap()
	{
		return owner_->bootstrap();
	}

    private:
	std::unique_ptr<packet_runtime_test_owner> owner_;  ///< One isolated runtime and affinity owner.
};

/**
 * @brief Require the final lifecycle application-level refusal.
 *
 * @param status Response status to validate.
 */
void expect_lifecycle_unavailable(const kinetum::common::v1::Status &status)
{
	EXPECT_EQ(status.code(), static_cast<int32_t>(status_code::UNAVAILABLE));
	EXPECT_EQ(status.error_code(), kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
	EXPECT_EQ(status.message(), RUNTIME_LIFECYCLE_UNAVAILABLE);
	EXPECT_TRUE(status.details().empty());
}

/**
 * @brief Require canonical transport rejection for a null direct invocation.
 *
 * @param status Handler transport status.
 */
void expect_null_rejection(const grpc::Status &status)
{
	EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
	EXPECT_EQ(status.error_message(), "null request or response");
}

/**
 * @brief Poison one drain response before testing clear-before-refusal.
 *
 * @param response Mutable response to poison.
 */
void poison_drain_response(kinetum::dataplane::v1::DrainResponse &response)
{
	response.set_state(kinetum::dataplane::v1::HealthResponse::STATE_DRAINED);
	response.set_packets_remaining(101u);
	response.set_drain_started_unix_ms(103);
	response.set_drain_completed_unix_ms(107);
	response.set_drain_id("must-be-cleared");
}

/**
 * @brief Require one drain response to contain no synthetic lifecycle state.
 *
 * @param response Exact handler output.
 */
void expect_empty_drain_result(const kinetum::dataplane::v1::DrainResponse &response)
{
	expect_lifecycle_unavailable(response.status());
	EXPECT_EQ(response.state(), kinetum::dataplane::v1::HealthResponse::STATE_UNSPECIFIED);
	EXPECT_EQ(response.packets_remaining(), 0u);
	EXPECT_EQ(response.drain_started_unix_ms(), 0);
	EXPECT_EQ(response.drain_completed_unix_ms(), 0);
	EXPECT_TRUE(response.drain_id().empty());
}

/**
 * @brief Poison one drain-status response before refusal.
 *
 * @param response Mutable response to poison.
 */
void poison_drain_status_response(kinetum::dataplane::v1::DrainStatusResponse &response)
{
	response.set_state(kinetum::dataplane::v1::HealthResponse::STATE_DRAINING);
	response.set_packets_remaining(109u);
	response.set_drain_started_unix_ms(113);
	response.set_drain_completed_unix_ms(127);
}

/**
 * @brief Require one drain-status response to carry no observation.
 *
 * @param response Exact handler output.
 */
void expect_empty_drain_status_result(const kinetum::dataplane::v1::DrainStatusResponse &response)
{
	expect_lifecycle_unavailable(response.status());
	EXPECT_EQ(response.state(), kinetum::dataplane::v1::HealthResponse::STATE_UNSPECIFIED);
	EXPECT_EQ(response.packets_remaining(), 0u);
	EXPECT_EQ(response.drain_started_unix_ms(), 0);
	EXPECT_EQ(response.drain_completed_unix_ms(), 0);
}

/**
 * @brief Read and require exact CONTROL_READY service state.
 *
 * @param service Merged service bound to a live runtime.
 */
void expect_control_ready(dataplane_control_service &service)
{
	grpc::ServerContext context;
	kinetum::dataplane::v1::HealthRequest request;
	kinetum::dataplane::v1::HealthResponse response;
	ASSERT_TRUE(service.Health(&context, &request, &response).ok());
	EXPECT_EQ(response.status().code(), static_cast<int32_t>(status_code::OK));
	EXPECT_EQ(response.status().error_code(), kinetum::common::v1::ERROR_CODE_OK);
	EXPECT_EQ(response.state(), kinetum::dataplane::v1::HealthResponse::STATE_CONTROL_READY);
	EXPECT_EQ(response.active_epoch(), 0u);
	EXPECT_NE(response.runtime_generation(), 0u);
	EXPECT_EQ(response.active_workers(), 0u);
	EXPECT_NE(response.expected_workers(), 0u);
}

}  // namespace

/** @brief Pin the lifecycle state vocabulary retained by the stable wire API. */
TEST_F(DpLifecycleTest, wire_states_remain_complete_without_a_lifecycle_owner)
{
	constexpr std::array<int, 9> EXPECTED_VALUES{0, 1, 2, 3, 4, 5, 6, 7, 8};
	const auto *descriptor = kinetum::dataplane::v1::HealthResponse::descriptor()->FindEnumTypeByName("State");
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->value_count(), static_cast<int>(EXPECTED_VALUES.size()));
	for (int index = 0; index < descriptor->value_count(); ++index) {
		EXPECT_EQ(descriptor->value(index)->number(), EXPECTED_VALUES[static_cast<std::size_t>(index)]);
	}
}

/** @brief Prove unavailable handlers publish no lifecycle-state substitute. */
TEST_F(DpLifecycleTest, unavailable_handlers_never_publish_a_lifecycle_state)
{
	dataplane_control_service service(runtime());
	grpc::ServerContext drain_context;
	kinetum::dataplane::v1::DrainRequest drain_request;
	kinetum::dataplane::v1::DrainResponse drain_response;
	ASSERT_TRUE(service.Drain(&drain_context, &drain_request, &drain_response).ok());
	expect_empty_drain_result(drain_response);

	grpc::ServerContext status_context;
	kinetum::dataplane::v1::DrainStatusRequest status_request;
	kinetum::dataplane::v1::DrainStatusResponse status_response;
	ASSERT_TRUE(service.DrainStatus(&status_context, &status_request, &status_response).ok());
	expect_empty_drain_status_result(status_response);
}

/** @brief Prove Drain clears every stale result field before refusal. */
TEST_F(DpLifecycleTest, drain_clears_every_synthetic_result_field)
{
	dataplane_control_service service(runtime());
	grpc::ServerContext context;
	kinetum::dataplane::v1::DrainRequest request;
	request.set_drain_id("maintenance");
	request.set_deadline_unix_ms(1775174400000LL);
	request.set_force(true);
	kinetum::dataplane::v1::DrainResponse response;
	poison_drain_response(response);
	ASSERT_TRUE(service.Drain(&context, &request, &response).ok());
	expect_empty_drain_result(response);
}

/** @brief Prove DrainStatus clears every stale observation before refusal. */
TEST_F(DpLifecycleTest, drain_status_clears_every_synthetic_result_field)
{
	dataplane_control_service service(runtime());
	grpc::ServerContext context;
	kinetum::dataplane::v1::DrainStatusRequest request;
	request.set_drain_id("maintenance");
	kinetum::dataplane::v1::DrainStatusResponse response;
	poison_drain_status_response(response);
	ASSERT_TRUE(service.DrainStatus(&context, &request, &response).ok());
	expect_empty_drain_status_result(response);
}

/** @brief Prove a first drain request cannot start hidden lifecycle state. */
TEST_F(DpLifecycleTest, drain_request_cannot_start_a_runtime_transition)
{
	dataplane_control_service service(runtime());
	grpc::ServerContext context;
	kinetum::dataplane::v1::DrainRequest request;
	request.set_drain_id("first");
	kinetum::dataplane::v1::DrainResponse response;
	ASSERT_TRUE(service.Drain(&context, &request, &response).ok());
	expect_empty_drain_result(response);
	expect_control_ready(service);
}

/** @brief Prove repeated or conflicting drain IDs create no idempotency store. */
TEST_F(DpLifecycleTest, repeated_drain_ids_never_create_idempotency_state)
{
	dataplane_control_service service(runtime());
	for (const char *drain_id : {"same", "same", "different"}) {
		grpc::ServerContext context;
		kinetum::dataplane::v1::DrainRequest request;
		request.set_drain_id(drain_id);
		kinetum::dataplane::v1::DrainResponse response;
		ASSERT_TRUE(service.Drain(&context, &request, &response).ok());
		expect_empty_drain_result(response);
	}
}

/** @brief Prove DrainStatus never resolves an empty or named operation. */
TEST_F(DpLifecycleTest, drain_status_identity_never_selects_an_operation)
{
	dataplane_control_service service(runtime());
	for (const char *drain_id : {"", "maintenance"}) {
		grpc::ServerContext context;
		kinetum::dataplane::v1::DrainStatusRequest request;
		request.set_drain_id(drain_id);
		kinetum::dataplane::v1::DrainStatusResponse response;
		ASSERT_TRUE(service.DrainStatus(&context, &request, &response).ok());
		expect_empty_drain_status_result(response);
	}
}

/** @brief Prove force cannot bypass the missing shutdown authority. */
TEST_F(DpLifecycleTest, shutdown_force_flag_cannot_bypass_unavailable)
{
	dataplane_control_service service(runtime());
	for (const bool force : {false, true}) {
		grpc::ServerContext context;
		kinetum::dataplane::v1::ShutdownRequest request;
		request.set_force(force);
		kinetum::dataplane::v1::ShutdownResponse response;
		ASSERT_TRUE(service.Shutdown(&context, &request, &response).ok());
		expect_lifecycle_unavailable(response.status());
	}
}

/** @brief Prove a reason string cannot manufacture shutdown audit state. */
TEST_F(DpLifecycleTest, shutdown_reason_cannot_create_process_state)
{
	dataplane_control_service service(runtime());
	for (const char *reason : {"", "operator-maintenance"}) {
		grpc::ServerContext context;
		kinetum::dataplane::v1::ShutdownRequest request;
		request.set_reason(reason);
		kinetum::dataplane::v1::ShutdownResponse response;
		ASSERT_TRUE(service.Shutdown(&context, &request, &response).ok());
		expect_lifecycle_unavailable(response.status());
	}
}

/** @brief Prove DumpState emits neither NAT nor ACL partial output. */
TEST_F(DpLifecycleTest, dump_state_flags_cannot_expose_partial_runtime_state)
{
	dataplane_control_service service(runtime());
	grpc::ServerContext context;
	kinetum::dataplane::v1::DumpStateRequest request;
	request.set_include_nat_table(true);
	request.set_include_acl_cache(true);
	request.set_max_entries(100);
	kinetum::dataplane::v1::DumpStateResponse response;
	response.add_nat_sessions()->set_packets(101u);
	response.set_acl_cache_json("must-be-cleared");
	ASSERT_TRUE(service.DumpState(&context, &request, &response).ok());
	expect_lifecycle_unavailable(response.status());
	EXPECT_EQ(response.nat_sessions_size(), 0);
	EXPECT_TRUE(response.acl_cache_json().empty());
}

/** @brief Prove no deadline value creates drain timing state. */
TEST_F(DpLifecycleTest, deadline_values_cannot_create_drain_timing)
{
	dataplane_control_service service(runtime());
	for (const int64_t deadline : {INT64_C(0), INT64_C(1775174400000), INT64_C(-1)}) {
		grpc::ServerContext context;
		kinetum::dataplane::v1::DrainRequest request;
		request.set_deadline_unix_ms(deadline);
		kinetum::dataplane::v1::DrainResponse response;
		ASSERT_TRUE(service.Drain(&context, &request, &response).ok());
		expect_empty_drain_result(response);
	}
}

/** @brief Prove packet readiness does not silently enable lifecycle RPCs. */
TEST_F(DpLifecycleTest, lifecycle_surface_remains_unavailable_after_bootstrap)
{
	auto bootstrap_or = bootstrap();
	ASSERT_TRUE(bootstrap_or.is_ok()) << bootstrap_or.error().message();
	dataplane_control_service service(runtime());

	grpc::ServerContext drain_context;
	kinetum::dataplane::v1::DrainRequest drain_request;
	kinetum::dataplane::v1::DrainResponse drain_response;
	ASSERT_TRUE(service.Drain(&drain_context, &drain_request, &drain_response).ok());
	expect_empty_drain_result(drain_response);

	grpc::ServerContext shutdown_context;
	kinetum::dataplane::v1::ShutdownRequest shutdown_request;
	kinetum::dataplane::v1::ShutdownResponse shutdown_response;
	ASSERT_TRUE(service.Shutdown(&shutdown_context, &shutdown_request, &shutdown_response).ok());
	expect_lifecycle_unavailable(shutdown_response.status());
}

/** @brief Prove all four lifecycle methods use transport-OK/application-failure. */
TEST_F(DpLifecycleTest, lifecycle_refusal_is_transport_ok_and_application_unavailable)
{
	dataplane_control_service service(runtime());
	grpc::ServerContext drain_context;
	kinetum::dataplane::v1::DrainRequest drain_request;
	kinetum::dataplane::v1::DrainResponse drain_response;
	EXPECT_TRUE(service.Drain(&drain_context, &drain_request, &drain_response).ok());
	expect_lifecycle_unavailable(drain_response.status());

	grpc::ServerContext status_context;
	kinetum::dataplane::v1::DrainStatusRequest status_request;
	kinetum::dataplane::v1::DrainStatusResponse status_response;
	EXPECT_TRUE(service.DrainStatus(&status_context, &status_request, &status_response).ok());
	expect_lifecycle_unavailable(status_response.status());

	grpc::ServerContext shutdown_context;
	kinetum::dataplane::v1::ShutdownRequest shutdown_request;
	kinetum::dataplane::v1::ShutdownResponse shutdown_response;
	EXPECT_TRUE(service.Shutdown(&shutdown_context, &shutdown_request, &shutdown_response).ok());
	expect_lifecycle_unavailable(shutdown_response.status());

	grpc::ServerContext dump_context;
	kinetum::dataplane::v1::DumpStateRequest dump_request;
	kinetum::dataplane::v1::DumpStateResponse dump_response;
	EXPECT_TRUE(service.DumpState(&dump_context, &dump_request, &dump_response).ok());
	expect_lifecycle_unavailable(dump_response.status());
}

/** @brief Prove every lifecycle handler rejects a null request uniformly. */
TEST_F(DpLifecycleTest, lifecycle_methods_reject_null_requests)
{
	dataplane_control_service service(runtime());
	kinetum::dataplane::v1::DrainResponse drain_response;
	kinetum::dataplane::v1::DrainStatusResponse status_response;
	kinetum::dataplane::v1::ShutdownResponse shutdown_response;
	kinetum::dataplane::v1::DumpStateResponse dump_response;
	expect_null_rejection(service.Drain(nullptr, nullptr, &drain_response));
	expect_null_rejection(service.DrainStatus(nullptr, nullptr, &status_response));
	expect_null_rejection(service.Shutdown(nullptr, nullptr, &shutdown_response));
	expect_null_rejection(service.DumpState(nullptr, nullptr, &dump_response));
}

/** @brief Prove every lifecycle handler rejects a null response uniformly. */
TEST_F(DpLifecycleTest, lifecycle_methods_reject_null_responses)
{
	dataplane_control_service service(runtime());
	kinetum::dataplane::v1::DrainRequest drain_request;
	kinetum::dataplane::v1::DrainStatusRequest status_request;
	kinetum::dataplane::v1::ShutdownRequest shutdown_request;
	kinetum::dataplane::v1::DumpStateRequest dump_request;
	expect_null_rejection(service.Drain(nullptr, &drain_request, nullptr));
	expect_null_rejection(service.DrainStatus(nullptr, &status_request, nullptr));
	expect_null_rejection(service.Shutdown(nullptr, &shutdown_request, nullptr));
	expect_null_rejection(service.DumpState(nullptr, &dump_request, nullptr));
}

/** @brief Prove concurrent lifecycle calls remain independent status-only refusals. */
TEST_F(DpLifecycleTest, concurrent_lifecycle_calls_remain_status_only)
{
	dataplane_control_service service(runtime());
	std::atomic<uint32_t> exact_refusals{0};
	std::array<std::thread, 4> callers{
		std::thread([&] {
			grpc::ServerContext context;
			kinetum::dataplane::v1::DrainRequest request;
			kinetum::dataplane::v1::DrainResponse response;
			const auto transport = service.Drain(&context, &request, &response);
			if (transport.ok() &&
			    response.status().code() == static_cast<int32_t>(status_code::UNAVAILABLE)) {
				exact_refusals.fetch_add(1u, std::memory_order_relaxed);
			}
		}),
		std::thread([&] {
			grpc::ServerContext context;
			kinetum::dataplane::v1::DrainStatusRequest request;
			kinetum::dataplane::v1::DrainStatusResponse response;
			const auto transport = service.DrainStatus(&context, &request, &response);
			if (transport.ok() &&
			    response.status().code() == static_cast<int32_t>(status_code::UNAVAILABLE)) {
				exact_refusals.fetch_add(1u, std::memory_order_relaxed);
			}
		}),
		std::thread([&] {
			grpc::ServerContext context;
			kinetum::dataplane::v1::ShutdownRequest request;
			kinetum::dataplane::v1::ShutdownResponse response;
			const auto transport = service.Shutdown(&context, &request, &response);
			if (transport.ok() &&
			    response.status().code() == static_cast<int32_t>(status_code::UNAVAILABLE)) {
				exact_refusals.fetch_add(1u, std::memory_order_relaxed);
			}
		}),
		std::thread([&] {
			grpc::ServerContext context;
			kinetum::dataplane::v1::DumpStateRequest request;
			kinetum::dataplane::v1::DumpStateResponse response;
			const auto transport = service.DumpState(&context, &request, &response);
			if (transport.ok() &&
			    response.status().code() == static_cast<int32_t>(status_code::UNAVAILABLE)) {
				exact_refusals.fetch_add(1u, std::memory_order_relaxed);
			}
		}),
	};
	for (auto &caller : callers) {
		caller.join();
	}
	EXPECT_EQ(exact_refusals.load(std::memory_order_relaxed), static_cast<uint32_t>(callers.size()));
}

/** @brief Prove lifecycle attempts cannot alter the runtime-status authority. */
TEST_F(DpLifecycleTest, lifecycle_attempts_do_not_change_runtime_readiness)
{
	dataplane_control_service service(runtime());
	expect_control_ready(service);

	grpc::ServerContext drain_context;
	kinetum::dataplane::v1::DrainRequest drain_request;
	kinetum::dataplane::v1::DrainResponse drain_response;
	ASSERT_TRUE(service.Drain(&drain_context, &drain_request, &drain_response).ok());

	grpc::ServerContext shutdown_context;
	kinetum::dataplane::v1::ShutdownRequest shutdown_request;
	kinetum::dataplane::v1::ShutdownResponse shutdown_response;
	ASSERT_TRUE(service.Shutdown(&shutdown_context, &shutdown_request, &shutdown_response).ok());

	expect_control_ready(service);
}

}  // namespace kinetum::dp
