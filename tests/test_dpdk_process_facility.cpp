// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dpdk_process_facility.cpp
 * @brief Exact DPDK EAL process-facility ownership tests.
 * @author Fleming Patel
 */

#include <array>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "src/dp/backends/dpdk/dpdk_process_facility.hpp"
#include "src/common/packet_thread_log_guard.hpp"
#include "tests/dpdk_component_test_harness.hpp"

namespace kinetum::provider::dpdk_component
{
namespace
{

using test_support::facility_fixture;

/** @brief Child-only cleanup observation state for the fail-stop exit handler. */
test_support::facility_api_state *fail_stop_state = nullptr;

/** @brief Exit a death-test child only when post-EAL cleanup ran exactly once. */
[[noreturn]] void exit_after_exact_cleanup() noexcept
{
	std::_Exit(fail_stop_state != nullptr && fail_stop_state->eal_cleanup_calls == 1 ? 73 : 74);
}

/** @brief Exit only when a failed EAL attempt did not fabricate cleanup ownership. */
[[noreturn]] void exit_after_failed_eal_attempt() noexcept
{
	const bool ownership_was_not_fabricated = fail_stop_state != nullptr && fail_stop_state->eal_init_calls == 1 &&
						  fail_stop_state->eal_cleanup_calls == 0;
	std::_Exit(ownership_was_not_fabricated ? 76 : 77);
}

/**
 * @brief Exact lifecycle callback used by the injected remote-launch path.
 * @param opaque Borrowed invocation counter incremented by this callback.
 * @return Negative test result proving callback failure is distinct from native join failure.
 */
int32_t lifecycle_entry(void *opaque) noexcept
{
	auto &calls = *static_cast<uint32_t *>(opaque);
	++calls;
	return -17;
}

}  // namespace

/** @brief Pin deterministic EAL marshaling and exclusion of external workers. */
TEST(dpdk_process_facility, renders_exact_eal_arguments_from_compiled_service_and_attachment_facts)
{
	facility_fixture fixture;

	const auto status = fixture.create();

	ASSERT_EQ(status, KINETUM_PROVIDER_STATUS_OK);
	ASSERT_NE(fixture.facility(), nullptr);
	const std::vector<std::string> expected{
		"kinetum_dp", "-l", "3,5", "--main-lcore", "3", "--no-telemetry", "-a", "0000:01:00.0",
	};
	EXPECT_EQ(fixture.api_state().eal_arguments, expected);
	EXPECT_EQ(fixture.api_state().eal_init_calls, 1u);
	EXPECT_TRUE(fixture.facility()->active());
	uint16_t physical_port = 0;
	EXPECT_TRUE(fixture.facility()->resolve_physical_port(fixture.attachment(), physical_port));
	EXPECT_EQ(physical_port, 7u);
	auto malformed_attachment = fixture.attachment();
	malformed_attachment.endpoint_port = 1;
	EXPECT_FALSE(fixture.facility()->resolve_physical_port(malformed_attachment, physical_port));
	fixture.facility().reset();
	EXPECT_EQ(fixture.api_state().eal_cleanup_calls, 1u);
}

/** @brief Native capture begins before EAL initialization and survives through EAL cleanup. */
TEST(dpdk_process_facility, native_logs_are_captured_before_eal_and_through_cleanup)
{
	facility_fixture fixture;
	fixture.api_state().emit_lifecycle_logs = true;
	ASSERT_EQ(fixture.create(), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_NE(fixture.api_state().log_stream, nullptr);
	auto initialized = fixture.logs();
	EXPECT_EQ(initialized.records, 1u);
	EXPECT_EQ(initialized.malformed, 0u);
	EXPECT_EQ(initialized.level, KINETUM_PROVIDER_LOG_INFO);
	EXPECT_STREQ(initialized.message.data(), "EAL initialization");
	fixture.facility().reset();
	EXPECT_EQ(fixture.api_state().log_stream, nullptr);
	const auto retired = fixture.logs();
	EXPECT_EQ(retired.records, 2u);
	EXPECT_EQ(retired.malformed, 0u);
	EXPECT_STREQ(retired.message.data(), "EAL cleanup");
}

/** @brief Native severity and fragment boundaries are preserved without fabricated function names. */
TEST(dpdk_process_facility, native_log_fragments_preserve_severity_and_owned_text)
{
	facility_fixture fixture;
	ASSERT_EQ(fixture.create(), KINETUM_PROVIDER_STATUS_OK);
	fixture.api_state().log_level = 4;
	ASSERT_EQ(std::fputc('x', fixture.api_state().log_stream), 'x');
	const auto observed = fixture.logs();
	EXPECT_EQ(observed.records, 1u);
	EXPECT_EQ(observed.level, KINETUM_PROVIDER_LOG_ERROR);
	EXPECT_STREQ(observed.event.data(), "dpdk.write");
	EXPECT_STREQ(observed.function.data(), "");
	EXPECT_STREQ(observed.message.data(), "x");
}

/** @brief A packet-thread native write is rejected before the host capture takes its cold mutex. */
TEST(dpdk_process_facility, native_packet_thread_log_is_counted_and_not_captured)
{
	facility_fixture fixture;
	ASSERT_EQ(fixture.create(), KINETUM_PROVIDER_STATUS_OK);
	fixture.api_state().log_level = 4;
	const auto before = kinetum::common::packet_thread_log_rejections();
	{
		kinetum::common::packet_thread_log_guard scope;
		EXPECT_EQ(std::fputc('x', fixture.api_state().log_stream), 'x');
	}
	EXPECT_EQ(kinetum::common::packet_thread_log_rejections(), before + 1);
	EXPECT_EQ(fixture.logs().records, 0u);
}

/** @brief Required stream registration rejects before any irreversible EAL initialization. */
TEST(dpdk_process_facility, native_log_registration_failure_precedes_eal)
{
	facility_fixture fixture;
	fixture.api_state().log_registration_result = -1;
	EXPECT_EQ(fixture.create(), KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR);
	EXPECT_EQ(fixture.api_state().eal_init_calls, 0u);
	EXPECT_EQ(fixture.api_state().eal_cleanup_calls, 0u);
	EXPECT_EQ(fixture.facility(), nullptr);
}

/** @brief A post-EAL main-lcore mismatch cleans once and makes the process non-reusable. */
TEST(dpdk_process_facility, main_lcore_disagreement_cleans_once_and_fails_stop)
{
	EXPECT_EXIT(
		{
			facility_fixture fixture;
			fixture.api_state().main_lcore = 4;
			fail_stop_state = &fixture.api_state();
			std::set_terminate(exit_after_exact_cleanup);
			(void)fixture.create();
			std::_Exit(75);
		},
		::testing::ExitedWithCode(73), "");
}

/** @brief A failed EAL attempt cannot return a potentially contaminated process. */
TEST(dpdk_process_facility, failed_eal_initialization_fails_stop_without_cleanup_claim)
{
	EXPECT_EXIT(
		{
			facility_fixture fixture;
			fixture.api_state().eal_init_result = -1;
			fail_stop_state = &fixture.api_state();
			std::set_terminate(exit_after_failed_eal_attempt);
			(void)fixture.create();
			std::_Exit(78);
		},
		::testing::ExitedWithCode(76), "");
}

/** @brief Duplicate compact storage ownership rejects before EAL side effects. */
TEST(dpdk_process_facility, duplicate_memory_domain_identity_rejects_before_eal)
{
	facility_fixture fixture;
	fixture.add_memory_domain(fixture.memory_domain().storage_domain_index);

	const auto status = fixture.create();

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_EQ(fixture.facility(), nullptr);
	EXPECT_EQ(fixture.api_state().eal_init_calls, 0u);
	EXPECT_EQ(fixture.api_state().eal_cleanup_calls, 0u);
}

/** @brief External packet-worker registration is exact, linear, and reusable after retirement. */
TEST(dpdk_process_facility, external_worker_registration_preserves_exact_cpu_and_native_lcore_ownership)
{
	facility_fixture fixture;
	ASSERT_EQ(fixture.create(), KINETUM_PROVIDER_STATUS_OK);
	fixture.api_state().current_lcore = 9;
	const auto &operations = fixture.facility()->operations();

	std::array<char, 128> diagnostic_bytes{};
	kinetum_provider_diagnostic diagnostic{
		.data = diagnostic_bytes.data(),
		.capacity = static_cast<uint32_t>(diagnostic_bytes.size()),
		.size = 0,
	};
	EXPECT_EQ(operations.register_worker_thread(operations.state, 0, &diagnostic),
		  KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	ASSERT_LE(diagnostic.size, diagnostic.capacity);
	EXPECT_EQ(std::string_view(diagnostic.data, diagnostic.size),
		  "DPDK worker is not running on its exact compiled CPU");
	EXPECT_EQ(fixture.api_state().thread_register_calls, 0u);
	EXPECT_EQ(fixture.api_state().thread_unregister_calls, 0u);

	fixture.api_state().current_cpu = 2;
	EXPECT_EQ(operations.register_worker_thread(operations.state, 0, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(operations.register_worker_thread(operations.state, 0, nullptr),
		  KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_EQ(fixture.api_state().thread_register_calls, 1u);
	operations.unregister_worker_thread(operations.state, 0);
	EXPECT_EQ(fixture.api_state().thread_unregister_calls, 1u);
	EXPECT_EQ(operations.register_worker_thread(operations.state, 0, nullptr), KINETUM_PROVIDER_STATUS_OK);
	operations.unregister_worker_thread(operations.state, 0);
	EXPECT_EQ(fixture.api_state().thread_register_calls, 2u);
	EXPECT_EQ(fixture.api_state().thread_unregister_calls, 2u);
}

/** @brief Distinct workers cannot claim the same registered native lcore. */
TEST(dpdk_process_facility, external_workers_reject_duplicate_native_lcore_identity)
{
	facility_fixture fixture;
	fixture.add_packet_worker(1, 4);
	ASSERT_EQ(fixture.create(), KINETUM_PROVIDER_STATUS_OK);
	const auto &operations = fixture.facility()->operations();
	fixture.api_state().current_cpu = 2;
	fixture.api_state().current_lcore = 9;
	ASSERT_EQ(operations.register_worker_thread(operations.state, 0, nullptr), KINETUM_PROVIDER_STATUS_OK);

	fixture.api_state().current_cpu = 4;
	EXPECT_EQ(operations.register_worker_thread(operations.state, 1, nullptr),
		  KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	fixture.api_state().current_cpu = 2;
	operations.unregister_worker_thread(operations.state, 0);
	fixture.api_state().current_cpu = 4;
	EXPECT_EQ(operations.register_worker_thread(operations.state, 1, nullptr), KINETUM_PROVIDER_STATUS_OK);
	operations.unregister_worker_thread(operations.state, 1);
}

/** @brief External packet workers cannot claim an EAL runtime-service lcore. */
TEST(dpdk_process_facility, external_worker_rejects_runtime_service_native_lcore)
{
	facility_fixture fixture;
	ASSERT_EQ(fixture.create(), KINETUM_PROVIDER_STATUS_OK);
	const auto &operations = fixture.facility()->operations();
	fixture.api_state().current_cpu = 2;
	fixture.api_state().current_lcore = 5;

	EXPECT_EQ(operations.register_worker_thread(operations.state, 0, nullptr),
		  KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_EQ(fixture.api_state().thread_register_calls, 1u);
	EXPECT_EQ(fixture.api_state().thread_unregister_calls, 1u);
}

/** @brief Coordinator and executor operations accept only their exact compiled roles. */
TEST(dpdk_process_facility, runtime_service_operations_bind_launch_and_join_exact_roles)
{
	facility_fixture fixture;
	ASSERT_EQ(fixture.create(), KINETUM_PROVIDER_STATUS_OK);
	const auto &operations = fixture.facility()->operations();
	uint32_t callback_calls = 0;

	EXPECT_EQ(operations.bind_runtime_service_coordinator(operations.state, 0, 3, nullptr),
		  KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(operations.launch_runtime_service(operations.state, 0, 3, lifecycle_entry, &callback_calls, nullptr),
		  KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_EQ(operations.launch_runtime_service(operations.state, 1, 5, lifecycle_entry, &callback_calls, nullptr),
		  KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(callback_calls, 1u);
	EXPECT_EQ(fixture.api_state().launched_entry_result, -17);
	EXPECT_EQ(fixture.api_state().launched_lcore, 5u);
	EXPECT_EQ(operations.join_runtime_service(operations.state, 1, 5, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(operations.launch_runtime_service(operations.state, 1, 5, lifecycle_entry, &callback_calls, nullptr),
		  KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(operations.join_runtime_service(operations.state, 1, 5, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(callback_calls, 2u);
	EXPECT_EQ(fixture.api_state().remote_launch_calls, 2u);
	EXPECT_EQ(fixture.api_state().wait_lcore_calls, 2u);
}

/** @brief A rejected native launch restores the slot for one exact retry. */
TEST(dpdk_process_facility, rejected_runtime_service_launch_does_not_strand_ownership)
{
	facility_fixture fixture;
	ASSERT_EQ(fixture.create(), KINETUM_PROVIDER_STATUS_OK);
	const auto &operations = fixture.facility()->operations();
	uint32_t callback_calls = 0;
	fixture.api_state().remote_launch_result = -1;

	EXPECT_EQ(operations.launch_runtime_service(operations.state, 1, 5, lifecycle_entry, &callback_calls, nullptr),
		  KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_EQ(callback_calls, 0u);
	fixture.api_state().remote_launch_result = 0;
	EXPECT_EQ(operations.launch_runtime_service(operations.state, 1, 5, lifecycle_entry, &callback_calls, nullptr),
		  KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(operations.join_runtime_service(operations.state, 1, 5, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(callback_calls, 1u);
}

}  // namespace kinetum::provider::dpdk_component
