// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_photon_startup.cpp
 * @brief Failure-oriented tests for exact Photon readiness and startup ordering.
 * @author Fleming Patel
 *
 * The tests pin strict state classification, bounded retry semantics,
 * post-response liveness checking, exact DP/CP argv construction, and complete
 * dependency-ordered rollback without creating real gRPC servers or children.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "gen/kinetum/common/v1/common.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/version.hpp"
#include "src/photon/readiness.hpp"
#include "src/photon/startup.hpp"

namespace kinetum::photon
{
namespace
{

/** DP health response used by scripted startup observations. */
using health_response = kinetum::dataplane::v1::HealthResponse;
using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

/**
 * @brief Construct one application-success Health response.
 *
 * @param state Exact state to publish.
 * @return Complete response with canonical application OK status.
 */
health_response healthy(health_response::State state)
{
	health_response response;
	response.set_state(state);
	response.mutable_status()->set_code(static_cast<int32_t>(status_code::OK));
	response.mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
	response.set_version(kinetum::common::KINETUM_VERSION_STRING);
	auto *logging = response.mutable_logging();
	logging->set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_AVAILABLE);
	logging->set_accepted_records(0);
	logging->set_queue_rejections(0);
	logging->set_format_rejections(0);
	logging->set_unavailable_rejections(0);
	logging->set_undelivered_records(0);
	logging->set_write_failures(0);
	logging->set_console_failures(0);
	logging->set_truncated_records(0);
	logging->set_packet_thread_rejections(0);
	logging->set_delivery_timeouts(0);
	if (state == health_response::STATE_CONTROL_READY) {
		response.set_runtime_generation(1u);
		response.set_expected_workers(1u);
	} else if (state == health_response::STATE_PACKET_READY) {
		response.set_runtime_generation(1u);
		response.set_active_epoch(1u);
		response.set_active_workers(1u);
		response.set_expected_workers(1u);
	}
	return response;
}

/**
 * @brief Deterministic Health observer with an optional repeated fallback.
 */
class scripted_health_observer final : public dp_health_observer {
    public:
	/**
	 * @brief Construct one ordered observer script.
	 *
	 * @param script Finite sequence returned by successive observations.
	 * @param fallback Result repeated after the finite sequence is exhausted.
	 * @param events Optional shared event trace for ordering assertions.
	 */
	explicit scripted_health_observer(std::vector<status_or<health_response>> script,
					  status_or<health_response> fallback = status::unavailable("no response"),
					  std::vector<std::string> *events = nullptr)
		: script_(std::move(script))
		, fallback_(std::move(fallback))
		, events_(events)
	{
	}

	/**
	 * @brief Return the next scripted health observation.
	 * @param rpc_timeout Per-attempt bound recorded for the assertion ledger.
	 * @return Next finite result, then the retained fallback result.
	 */
	[[nodiscard]] status_or<health_response> observe(std::chrono::milliseconds rpc_timeout) override
	{
		observed_timeouts_.push_back(rpc_timeout);
		if (events_ != nullptr) {
			events_->emplace_back("health");
		}
		++calls_;
		if (next_ < script_.size()) {
			return script_[next_++];
		}
		return fallback_;
	}

	/**
	 * @brief Return the number of completed observations.
	 *
	 * @return Number of calls made through `observe()`.
	 */
	[[nodiscard]] std::size_t calls() const noexcept
	{
		return calls_;
	}

	/**
	 * @brief Return every per-RPC timeout supplied by the caller.
	 *
	 * @return Observation-order timeout values.
	 */
	[[nodiscard]] const std::vector<std::chrono::milliseconds> &observed_timeouts() const noexcept
	{
		return observed_timeouts_;
	}

    private:
	std::vector<status_or<health_response>> script_;  ///< Finite ordered observation sequence.
	status_or<health_response> fallback_;	     ///< Explicit fixture response repeated after the sequence ends.
	std::vector<std::string> *events_{nullptr};  ///< Optional borrowed shared event trace.
	std::vector<std::chrono::milliseconds> observed_timeouts_;  ///< Per-call timeout evidence.
	std::size_t next_{0};					    ///< Next scripted observation ordinal.
	std::size_t calls_{0};					    ///< Completed observer call count.
};

/**
 * @brief Observer that deliberately returns a target after its caller's budget.
 */
class delayed_ready_observer final : public dp_health_observer {
    public:
	/**
	 * @brief Construct an observer with one deterministic response delay.
	 *
	 * @param delay Wall-clock delay before returning the target response.
	 */
	explicit delayed_ready_observer(std::chrono::milliseconds delay)
		: delay_(delay)
	{
	}

	/**
	 * @brief Return CONTROL_READY after a deliberate caller-budget violation.
	 * @param rpc_timeout Caller bound deliberately ignored by this test double.
	 * @return One delayed CONTROL_READY observation.
	 */
	[[nodiscard]] status_or<health_response> observe(std::chrono::milliseconds rpc_timeout) override
	{
		(void)rpc_timeout;
		std::this_thread::sleep_for(delay_);
		return healthy(health_response::STATE_CONTROL_READY);
	}

    private:
	std::chrono::milliseconds delay_;  ///< Deliberate contract-violation delay.
};

/** @brief One fake spawn record retained for exact argv assertions. */
struct spawn_record {
	std::string name;		///< Stable child role.
	std::vector<std::string> argv;	///< Direct executable and arguments.
};

/**
 * @brief Deterministic child controller that records every startup operation.
 */
class fake_startup_process_controller final : public startup_process_controller {
    public:
	/**
	 * @brief Record and emulate one direct child spawn.
	 * @param name Stable child role.
	 * @param argv Exact executable and argument vector.
	 * @return Running synthetic child or the configured spawn failure.
	 */
	[[nodiscard]] status_or<child_proc> spawn_argv(const std::string &name,
						       const std::vector<std::string> &argv) override
	{
		events.emplace_back("spawn:" + name);
		spawns.push_back({name, argv});
		if (name == fail_spawn_name) {
			return status::internal_error(name + " spawn failed");
		}

		child_proc child;
		child.pid = next_pid++;
		child.name = name;
		child.state = process_state::RUNNING;
		child.exit_code = -1;
		return child;
	}

	/**
	 * @brief Observe or inject one synthetic child exit.
	 * @param child Mutable child record owned by the startup transaction.
	 * @return true while the child remains running.
	 */
	[[nodiscard]] status_or<bool> check(child_proc &child) override
	{
		events.emplace_back("check:" + child.name);
		if (child.name == exit_on_check_name && child.is_running()) {
			child.state = process_state::EXITED;
			child.exit_code = exit_on_check_code;
			exit_on_check_name.clear();
			return false;
		}
		return child.is_running();
	}

	/**
	 * @brief Record and emulate one bounded child retirement.
	 * @param child Mutable child record to retire.
	 * @param timeout_ms Positive termination bound supplied by the owner.
	 * @return Configured failure or exact synthetic retirement success.
	 */
	[[nodiscard]] status terminate(child_proc &child, int timeout_ms) override
	{
		events.emplace_back("terminate:" + child.name);
		termination_timeouts.push_back(timeout_ms);
		termination_attempt_names.push_back(child.name);
		if (std::find(fail_terminate_names.begin(), fail_terminate_names.end(), child.name) !=
		    fail_terminate_names.end()) {
			return status::internal_error(child.name + " termination failed");
		}
		terminated_names.push_back(child.name);
		if (child.is_running()) {
			child.state = process_state::TERMINATED;
			child.exit_code = 143;
		}
		return status::ok();
	}

	std::vector<std::string> events;		     ///< Complete operation trace.
	std::vector<spawn_record> spawns;		     ///< Spawn inputs in call order.
	std::vector<std::string> termination_attempt_names;  ///< Attempted child roles in call order.
	std::vector<std::string> terminated_names;	     ///< Terminated child roles in call order.
	std::vector<int> termination_timeouts;		     ///< Termination bounds in call order.
	std::string fail_spawn_name;			     ///< Child role whose spawn must fail.
	std::vector<std::string> fail_terminate_names;	     ///< Child roles whose termination must fail.
	std::string exit_on_check_name;			     ///< Child role whose next check reports exit.
	int exit_on_check_code{73};			     ///< Synthetic retained child exit code.
	int next_pid{1000};				     ///< Deterministic fake PID allocator.
};

/**
 * @return Valid startup specification with deterministic executable, bundle, and endpoint authority.
 */
supervised_startup_spec valid_startup_spec()
{
	supervised_startup_spec spec;
	spec.dp_executable = "/opt/kinetum/bin/kinetum_dp";
	spec.cp_executable = "/opt/kinetum/bin/kinetum_cp";
	spec.bundle_root = "/verified";
	spec.dp_endpoint = "127.0.0.1:50052";
	spec.cp_listen = "127.0.0.1:50051";
	spec.config_store_dir = "/var/lib/kinetum/config";
	spec.bootstrap_snapshot_path = "/verified/configs/config_snapshot.pbtxt";
	spec.plan_content_hash = std::string(64, 'a');
	spec.control_wait = {std::chrono::milliseconds(1), std::chrono::milliseconds(1), std::chrono::milliseconds(10)};
	spec.packet_wait = spec.control_wait;
	spec.termination_timeout_ms = 37;
	return spec;
}

/** @brief Child role observed terminal by pair-scoped supervision. */
enum class terminal_child_role {
	DP,  ///< Data Plane child exited.
	CP,  ///< Control Plane child exited.
};

/**
 * @brief Construct one supervised pair with exactly one terminal child.
 *
 * @param role Child role that has already been reaped.
 * @param exit_code Exact retained exit code.
 * @return Sole pair authority ready for exit resolution.
 */
supervised_children observed_terminal_pair(terminal_child_role role, int exit_code)
{
	child_proc dp;
	dp.pid = 901;
	dp.name = "dp";
	dp.state = role == terminal_child_role::DP ? process_state::EXITED : process_state::RUNNING;
	dp.exit_code = role == terminal_child_role::DP ? exit_code : -1;

	child_proc cp;
	cp.pid = 902;
	cp.name = "cp";
	cp.state = role == terminal_child_role::CP ? process_state::EXITED : process_state::RUNNING;
	cp.exit_code = role == terminal_child_role::CP ? exit_code : -1;
	return supervised_children{std::move(dp), std::move(cp), 0u};
}

/**
 * @brief Construct one synthetic packet-ready pair with two live authorities.
 * @return Synthetic running DP/CP pair with fixed nonzero process identities.
 */
supervised_children running_pair()
{
	child_proc dp;
	dp.pid = 901;
	dp.name = "dp";
	dp.state = process_state::RUNNING;

	child_proc cp;
	cp.pid = 902;
	cp.name = "cp";
	cp.state = process_state::RUNNING;
	return supervised_children{std::move(dp), std::move(cp), 0u};
}

/** @brief Trigger final startup-transaction cleanup failure in a death-test child. */
void fail_startup_rollback_reaping()
{
	auto spec = valid_startup_spec();
	fake_startup_process_controller processes;
	processes.fail_spawn_name = "cp";
	processes.fail_terminate_names = {"dp"};
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY)});
	(void)start_supervised_children(spec, observer, processes);
}

/** @brief Trigger final packet-ready pair cleanup failure in a death-test child. */
void fail_pair_owner_reaping()
{
	auto spec = valid_startup_spec();
	fake_startup_process_controller processes;
	processes.fail_terminate_names = {"cp", "dp"};
	supervised_pair_owner owner(running_pair(), std::move(spec), restart_policy::NEVER, processes);
}

/** @brief Attempt to overwrite one live process authority in a death-test child. */
void overwrite_live_child_authority()
{
	auto first = running_pair();
	auto second = running_pair();
	first.dp = std::move(second.dp);
}

/**
 * @param events Ordered shared startup/shutdown event trace.
 * @param needle Exact event spelling to locate.
 * @return First matching ordinal, or events.size() when absent.
 */
std::size_t event_index(const std::vector<std::string> &events, const std::string &needle)
{
	const auto found = std::find(events.begin(), events.end(), needle);
	return static_cast<std::size_t>(std::distance(events.begin(), found));
}

}  // namespace

/**
 * @brief Verify the named production timing policy is relationally coherent.
 */
TEST(photon_readiness, production_policies_are_coherent)
{
	EXPECT_TRUE(validate_readiness_wait_policy(CONTROL_READY_WAIT_POLICY).is_ok());
	EXPECT_TRUE(validate_readiness_wait_policy(PACKET_READY_WAIT_POLICY).is_ok());
	EXPECT_LT(READINESS_RPC_TIMEOUT, CONTROL_READY_TIMEOUT);
	EXPECT_LT(READINESS_POLL_INTERVAL, PACKET_READY_TIMEOUT);
}

/**
 * @brief Verify nonpositive and gate-consuming timing values fail closed.
 */
TEST(photon_readiness, malformed_timing_policy_is_rejected)
{
	readiness_wait_policy nonpositive{std::chrono::milliseconds(0), std::chrono::milliseconds(1),
					  std::chrono::milliseconds(5)};
	EXPECT_EQ(validate_readiness_wait_policy(nonpositive).code(), status_code::INVALID_ARGUMENT);

	readiness_wait_policy rpc_consumes_gate{std::chrono::milliseconds(5), std::chrono::milliseconds(1),
						std::chrono::milliseconds(5)};
	EXPECT_EQ(validate_readiness_wait_policy(rpc_consumes_gate).code(), status_code::INVALID_ARGUMENT);

	readiness_wait_policy poll_consumes_gate{std::chrono::milliseconds(1), std::chrono::milliseconds(5),
						 std::chrono::milliseconds(5)};
	EXPECT_EQ(validate_readiness_wait_policy(poll_consumes_gate).code(), status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify the control gate retries only STARTING and accepts exact CONTROL_READY.
 */
TEST(photon_readiness, control_gate_has_one_prestate_and_one_target)
{
	auto waiting = classify_readiness_state(readiness_gate::CONTROL, health_response::STATE_STARTING);
	ASSERT_TRUE(waiting.is_ok());
	EXPECT_EQ(waiting.value(), readiness_progress::WAIT);

	auto ready = classify_readiness_state(readiness_gate::CONTROL, health_response::STATE_CONTROL_READY);
	ASSERT_TRUE(ready.is_ok());
	EXPECT_EQ(ready.value(), readiness_progress::READY);
}

/**
 * @brief Verify the packet gate retries only CONTROL_READY and accepts exact PACKET_READY.
 */
TEST(photon_readiness, packet_gate_has_one_prestate_and_one_target)
{
	auto waiting = classify_readiness_state(readiness_gate::PACKET, health_response::STATE_CONTROL_READY);
	ASSERT_TRUE(waiting.is_ok());
	EXPECT_EQ(waiting.value(), readiness_progress::WAIT);

	auto ready = classify_readiness_state(readiness_gate::PACKET, health_response::STATE_PACKET_READY);
	ASSERT_TRUE(ready.is_ok());
	EXPECT_EQ(ready.value(), readiness_progress::READY);
}

/**
 * @brief Verify skipped phases, regressions, and terminal states never retry.
 */
TEST(photon_readiness, known_non_prestate_values_are_terminal)
{
	for (const auto state :
	     {health_response::STATE_UNSPECIFIED, health_response::STATE_PACKET_READY, health_response::STATE_DRAINING,
	      health_response::STATE_DRAINED, health_response::STATE_STOPPING, health_response::STATE_STOPPED,
	      health_response::STATE_ERROR}) {
		auto result = classify_readiness_state(readiness_gate::CONTROL, state);
		ASSERT_FALSE(result.is_ok());
		EXPECT_EQ(result.error().code(), status_code::FAILED_PRECONDITION);
	}
	for (const auto state :
	     {health_response::STATE_UNSPECIFIED, health_response::STATE_STARTING, health_response::STATE_DRAINING,
	      health_response::STATE_DRAINED, health_response::STATE_STOPPING, health_response::STATE_STOPPED,
	      health_response::STATE_ERROR}) {
		auto result = classify_readiness_state(readiness_gate::PACKET, state);
		ASSERT_FALSE(result.is_ok());
		EXPECT_EQ(result.error().code(), status_code::FAILED_PRECONDITION);
	}
}

/**
 * @brief Verify an unrecognized future wire enum is an immediate terminal state.
 */
TEST(photon_readiness, unknown_health_state_is_terminal)
{
	auto result = classify_readiness_state(readiness_gate::CONTROL, static_cast<health_response::State>(1234));
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(result.error().message().find("UNKNOWN_STATE(1234)"), std::string::npos);
}

/**
 * @brief Verify only transient transport failures are retried to exact readiness.
 */
TEST(photon_readiness, transient_transport_failures_retry)
{
	scripted_health_observer observer({status::unavailable("not listening"),
					   status::deadline_exceeded("rpc expired"),
					   healthy(health_response::STATE_CONTROL_READY)});
	const readiness_wait_policy policy{std::chrono::milliseconds(1), std::chrono::milliseconds(1),
					   std::chrono::milliseconds(20)};
	const auto result = wait_for_exact_readiness(observer, readiness_gate::CONTROL, policy);
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	EXPECT_EQ(result->state, health_response::STATE_CONTROL_READY);
	EXPECT_EQ(result->runtime_generation, 1u);
	EXPECT_EQ(result->active_epoch, 0u);
	EXPECT_EQ(result->active_workers, 0u);
	EXPECT_EQ(result->expected_workers, 1u);
	EXPECT_EQ(observer.calls(), 3U);
	ASSERT_EQ(observer.observed_timeouts().size(), 3U);
	for (const auto timeout : observer.observed_timeouts()) {
		EXPECT_GT(timeout.count(), 0);
		EXPECT_LE(timeout, policy.rpc_timeout);
	}
}

/**
 * @brief Verify application and nontransient transport failures are never retried.
 */
TEST(photon_readiness, application_and_nontransient_transport_errors_are_terminal)
{
	auto response = healthy(health_response::STATE_CONTROL_READY);
	response.set_state(health_response::STATE_ERROR);
	response.clear_runtime_generation();
	response.clear_expected_workers();
	response.mutable_status()->set_code(static_cast<int32_t>(status_code::FAILED_PRECONDITION));
	response.mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_FAILED_PRECONDITION);
	response.mutable_status()->set_message("bootstrap dependency missing");
	scripted_health_observer observer({response}, healthy(health_response::STATE_CONTROL_READY));
	const readiness_wait_policy policy{std::chrono::milliseconds(1), std::chrono::milliseconds(1),
					   std::chrono::milliseconds(10)};
	const auto result = wait_for_exact_readiness(observer, readiness_gate::CONTROL, policy);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_EQ(observer.calls(), 1U);

	scripted_health_observer denied_observer({status::permission_denied("denied")},
						 healthy(health_response::STATE_CONTROL_READY));
	const auto denied_result = wait_for_exact_readiness(denied_observer, readiness_gate::CONTROL, policy);
	ASSERT_FALSE(denied_result.is_ok());
	EXPECT_EQ(denied_result.error().code(), status_code::PERMISSION_DENIED);
	EXPECT_EQ(denied_observer.calls(), 1U);
}

/**
 * @brief Verify contradictory or undeclared application status cannot authorize readiness.
 */
TEST(photon_readiness, malformed_application_status_is_terminal_before_state_classification)
{
	scripted_health_observer unspecified_observer({healthy(health_response::STATE_UNSPECIFIED)},
						      healthy(health_response::STATE_CONTROL_READY));
	const readiness_wait_policy policy{std::chrono::milliseconds(1), std::chrono::milliseconds(1),
					   std::chrono::milliseconds(10)};
	const auto unspecified_result = wait_for_exact_readiness(unspecified_observer, readiness_gate::CONTROL, policy);
	ASSERT_FALSE(unspecified_result.is_ok());
	EXPECT_EQ(unspecified_result.error().code(), status_code::DATA_LOSS);
	EXPECT_EQ(unspecified_observer.calls(), 1U);

	auto contradictory = healthy(health_response::STATE_CONTROL_READY);
	contradictory.mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
	scripted_health_observer contradictory_observer({contradictory}, healthy(health_response::STATE_CONTROL_READY));
	const auto contradictory_result =
		wait_for_exact_readiness(contradictory_observer, readiness_gate::CONTROL, policy);
	ASSERT_FALSE(contradictory_result.is_ok());
	EXPECT_EQ(contradictory_result.error().code(), status_code::DATA_LOSS);
	EXPECT_EQ(contradictory_observer.calls(), 1U);

	auto undeclared = healthy(health_response::STATE_CONTROL_READY);
	undeclared.mutable_status()->set_error_code(static_cast<kinetum::common::v1::ErrorCode>(1234));
	scripted_health_observer undeclared_observer({undeclared}, healthy(health_response::STATE_CONTROL_READY));
	const auto undeclared_result = wait_for_exact_readiness(undeclared_observer, readiness_gate::CONTROL, policy);
	ASSERT_FALSE(undeclared_result.is_ok());
	EXPECT_EQ(undeclared_result.error().code(), status_code::DATA_LOSS);
	EXPECT_EQ(undeclared_observer.calls(), 1U);

	const std::array<std::string, 4> removed_fields{
		std::string("\x30\x01", 2u),
		std::string("\x38\x01", 2u),
		std::string("\x40\x01", 2u),
		std::string("\x52\x01x", 3u),
	};
	for (const auto &removed_field : removed_fields) {
		auto removed_wire = healthy(health_response::STATE_CONTROL_READY);
		std::string removed_bytes = removed_wire.SerializeAsString();
		removed_bytes.append(removed_field);
		ASSERT_TRUE(removed_wire.ParseFromString(removed_bytes));
		scripted_health_observer removed_observer({removed_wire},
							  healthy(health_response::STATE_CONTROL_READY));
		const auto removed_result = wait_for_exact_readiness(removed_observer, readiness_gate::CONTROL, policy);
		ASSERT_FALSE(removed_result.is_ok());
		EXPECT_EQ(removed_result.error().code(), status_code::DATA_LOSS);
		EXPECT_EQ(removed_observer.calls(), 1U);
	}
}

/**
 * @brief Verify overall timeout retains the last exact state observation.
 */
TEST(photon_readiness, overall_timeout_reports_last_observation)
{
	const auto starting = healthy(health_response::STATE_STARTING);
	scripted_health_observer observer({starting}, starting);
	const readiness_wait_policy policy{std::chrono::milliseconds(1), std::chrono::milliseconds(1),
					   std::chrono::milliseconds(5)};
	const auto result = wait_for_exact_readiness(observer, readiness_gate::CONTROL, policy);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::DEADLINE_EXCEEDED);
	EXPECT_NE(result.error().details().find("STATE_STARTING"), std::string::npos);
}

/**
 * @brief Verify a target returned after the overall deadline cannot succeed.
 */
TEST(photon_readiness, late_target_response_is_deadline_exceeded)
{
	delayed_ready_observer observer(std::chrono::milliseconds(8));
	const readiness_wait_policy policy{std::chrono::milliseconds(1), std::chrono::milliseconds(1),
					   std::chrono::milliseconds(4)};
	const auto result = wait_for_exact_readiness(observer, readiness_gate::CONTROL, policy);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::DEADLINE_EXCEEDED);
	EXPECT_NE(result.error().details().find("after the overall readiness deadline"), std::string::npos);
}

/**
 * @brief Verify liveness/cancellation is rechecked after a target response.
 */
TEST(photon_readiness, target_response_does_not_bypass_final_progress_check)
{
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY)});
	const readiness_wait_policy policy{std::chrono::milliseconds(1), std::chrono::milliseconds(1),
					   std::chrono::milliseconds(10)};
	int checks = 0;
	const auto result = wait_for_exact_readiness(observer, readiness_gate::CONTROL, policy, [&checks]() {
		++checks;
		return checks == 1 ? status::ok() : status::cancelled("cancelled after response");
	});
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::CANCELLED);
	EXPECT_EQ(checks, 2);
}

/**
 * @brief Verify exact gates, handoff argv, and scope-bound pair cleanup.
 */
TEST(photon_startup, exact_gate_order_and_bootstrap_handoff_succeed)
{
	auto spec = valid_startup_spec();
	const std::vector<std::string> expected_dp{
		"/opt/kinetum/bin/kinetum_dp",
		"--bundle",
		"/verified",
		"--listen",
		"127.0.0.1:50052",
		"--log-dir",
		"/var/log/kinetum",
		"--log-level",
		"info",
		"--log-max-bytes",
		"16777216",
		"--log-keep-files",
		"8",
	};
	const std::vector<std::string> expected_cp{
		"/opt/kinetum/bin/kinetum_cp",
		"--listen-addr",
		"127.0.0.1:50051",
		"--dp-addr",
		"127.0.0.1:50052",
		"--config-store-dir",
		"/var/lib/kinetum/config",
		"--bootstrap-snapshot",
		"/verified/configs/config_snapshot.pbtxt",
		"--bootstrap-plan-content-hash",
		std::string(64, 'a'),
		"--log-dir",
		"/var/log/kinetum",
		"--log-level",
		"info",
		"--log-max-bytes",
		"16777216",
		"--log-keep-files",
		"8",
	};
	fake_startup_process_controller processes;
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY),
					   healthy(health_response::STATE_PACKET_READY)},
					  status::unavailable("unexpected observation"), &processes.events);

	auto result = start_supervised_children(spec, observer, processes);
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	{
		supervised_pair_owner pair_owner(std::move(result).value(), std::move(spec), restart_policy::NEVER,
						 processes);
		const auto &children = pair_owner.children();
		EXPECT_EQ(processes.spawns.size(), 2U);
		EXPECT_TRUE(processes.terminated_names.empty());
		EXPECT_EQ(children.dp.name, "dp");
		EXPECT_EQ(children.cp.name, "cp");
		EXPECT_EQ(processes.spawns[0].argv, expected_dp);
		EXPECT_EQ(processes.spawns[1].argv, expected_cp);

		const auto first_health = event_index(processes.events, "health");
		const auto cp_spawn = event_index(processes.events, "spawn:cp");
		const auto cp_spawn_event = std::find(processes.events.cbegin(), processes.events.cend(), "spawn:cp");
		ASSERT_NE(cp_spawn_event, processes.events.cend());
		const auto second_health_event =
			std::find(std::next(cp_spawn_event), processes.events.cend(), "health");
		ASSERT_NE(second_health_event, processes.events.cend());
		const auto second_health =
			static_cast<std::size_t>(std::distance(processes.events.cbegin(), second_health_event));
		EXPECT_LT(event_index(processes.events, "spawn:dp"), first_health);
		EXPECT_LT(first_health, cp_spawn);
		EXPECT_LT(cp_spawn, second_health);
	}
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"cp", "dp"}));
	EXPECT_EQ(processes.termination_timeouts, (std::vector<int>{37, 37}));
}

/** @brief Verify moving one child transfers rather than duplicates live authority. */
TEST(photon_startup, child_moves_transfer_one_live_process_authority)
{
	auto children = running_pair();
	child_proc moved(std::move(children.dp));
	EXPECT_EQ(moved.pid, 901);
	EXPECT_TRUE(moved.is_running());
	EXPECT_EQ(moved.name, "dp");
	EXPECT_EQ(children.dp.pid, -1);
	EXPECT_FALSE(children.dp.is_running());
	EXPECT_TRUE(children.dp.name.empty());

	fake_startup_process_controller processes;
	const auto cp_cleanup = processes.terminate(children.cp, 0);
	const auto dp_cleanup = processes.terminate(moved, 0);
	EXPECT_TRUE(cp_cleanup.is_ok()) << cp_cleanup.message();
	EXPECT_TRUE(dp_cleanup.is_ok()) << dp_cleanup.message();
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"cp", "dp"}));

	EXPECT_DEATH(overwrite_live_child_authority(),
		     "Photon process ownership violation: unreaped child name='dp' pid=901");
}

/** @brief Verify aggregate cleanup attempts every child and retains each failure. */
TEST(photon_startup, pair_cleanup_attempts_both_children_before_reporting_failure)
{
	auto spec = valid_startup_spec();
	fake_startup_process_controller processes;
	processes.fail_terminate_names = {"cp", "dp"};

	{
		supervised_pair_owner owner(running_pair(), std::move(spec), restart_policy::NEVER, processes);
		const auto result = owner.stop();
		EXPECT_EQ(result.code(), status_code::INTERNAL_ERROR);
		EXPECT_NE(result.details().find("cp: cp termination failed"), std::string::npos);
		EXPECT_NE(result.details().find("dp: dp termination failed"), std::string::npos);
		EXPECT_EQ(processes.termination_attempt_names, (std::vector<std::string>{"cp", "dp"}));
		EXPECT_TRUE(processes.terminated_names.empty());
		EXPECT_TRUE(owner.children().cp.is_running());
		EXPECT_TRUE(owner.children().dp.is_running());

		// A failed explicit stop leaves the owner armed. Let its final attempt
		// prove the same CP-before-DP path after the injected failures clear.
		processes.fail_terminate_names.clear();
	}
	EXPECT_EQ(processes.termination_attempt_names, (std::vector<std::string>{"cp", "dp", "cp", "dp"}));
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"cp", "dp"}));
}

/** @brief Verify no scope can discard a child after final reaping proof fails. */
TEST(photon_startup, final_cleanup_failure_fails_stop_before_authority_loss)
{
	EXPECT_DEATH(fail_startup_rollback_reaping(), "Photon cannot prove complete child reaping");
	EXPECT_DEATH(fail_pair_owner_reaping(), "Photon cannot prove complete child reaping");
}

/**
 * @brief Verify malformed startup authority fails before process or Health I/O.
 */
TEST(photon_startup, malformed_authority_fails_before_startup_side_effects)
{
	auto spec = valid_startup_spec();
	spec.plan_content_hash = std::string(64, 'A');
	fake_startup_process_controller processes;
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY)});

	auto result = start_supervised_children(spec, observer, processes);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);
	EXPECT_TRUE(processes.spawns.empty());
	EXPECT_TRUE(processes.events.empty());
	EXPECT_EQ(observer.calls(), 0U);

	const std::array<std::string supervised_startup_spec::*, 7> text_fields{
		&supervised_startup_spec::dp_executable,
		&supervised_startup_spec::cp_executable,
		&supervised_startup_spec::bundle_root,
		&supervised_startup_spec::dp_endpoint,
		&supervised_startup_spec::cp_listen,
		&supervised_startup_spec::config_store_dir,
		&supervised_startup_spec::bootstrap_snapshot_path,
	};
	for (const auto field : text_fields) {
		auto nul_spec = valid_startup_spec();
		(nul_spec.*field).push_back('\0');
		auto nul_result = start_supervised_children(nul_spec, observer, processes);
		ASSERT_FALSE(nul_result.is_ok());
		EXPECT_EQ(nul_result.error().code(), status_code::INVALID_ARGUMENT);
		EXPECT_TRUE(processes.events.empty());
		EXPECT_EQ(observer.calls(), 0U);
	}
}

/**
 * @brief Verify CWD-relative executable and durable-state paths fail before I/O.
 */
TEST(photon_startup, relative_process_or_store_paths_fail_before_startup_side_effects)
{
	auto spec = valid_startup_spec();
	fake_startup_process_controller processes;
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY)});

	spec.dp_executable = "./bin/kinetum_dp";
	auto relative_process = start_supervised_children(spec, observer, processes);
	ASSERT_FALSE(relative_process.is_ok());
	EXPECT_EQ(relative_process.error().code(), status_code::INVALID_ARGUMENT);
	EXPECT_TRUE(processes.events.empty());
	EXPECT_EQ(observer.calls(), 0U);

	spec = valid_startup_spec();
	spec.config_store_dir = ".kinetum_config_store";
	auto relative_store = start_supervised_children(spec, observer, processes);
	ASSERT_FALSE(relative_store.is_ok());
	EXPECT_EQ(relative_store.error().code(), status_code::INVALID_ARGUMENT);
	EXPECT_TRUE(processes.events.empty());
	EXPECT_EQ(observer.calls(), 0U);
}

/**
 * @brief Verify DP exit is reaped before any readiness RPC or CP spawn.
 */
TEST(photon_startup, dp_exit_during_control_gate_rolls_back_only_dp)
{
	auto spec = valid_startup_spec();
	fake_startup_process_controller processes;
	processes.exit_on_check_name = "dp";
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY)});

	auto result = start_supervised_children(spec, observer, processes);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(result.error().message().find("exit_code=73"), std::string::npos);
	EXPECT_EQ(observer.calls(), 0U);
	EXPECT_EQ(processes.spawns.size(), 1U);
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"dp"}));
}

/**
 * @brief Verify CP spawn failure cannot orphan the already-ready DP.
 */
TEST(photon_startup, cp_spawn_failure_rolls_back_dp)
{
	auto spec = valid_startup_spec();
	fake_startup_process_controller processes;
	processes.fail_spawn_name = "cp";
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY)});

	auto result = start_supervised_children(spec, observer, processes);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::INTERNAL_ERROR);
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"dp"}));
}

/**
 * @brief Verify CP exit during gate two is reported and cleanup remains ordered.
 */
TEST(photon_startup, cp_exit_during_packet_gate_rolls_back_cp_before_dp)
{
	auto spec = valid_startup_spec();
	fake_startup_process_controller processes;
	processes.exit_on_check_name = "cp";
	scripted_health_observer observer(
		{healthy(health_response::STATE_CONTROL_READY), healthy(health_response::STATE_PACKET_READY)});

	auto result = start_supervised_children(spec, observer, processes);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(result.error().message().find("cp exited during PACKET_READY readiness"), std::string::npos);
	EXPECT_NE(result.error().message().find("exit_code=73"), std::string::npos);
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"cp", "dp"}));
	EXPECT_EQ(processes.termination_timeouts, (std::vector<int>{37, 37}));
}

/**
 * @brief Verify packet-readiness timeout reaps CP before DP.
 */
TEST(photon_startup, packet_gate_timeout_rolls_back_cp_before_dp)
{
	auto spec = valid_startup_spec();
	spec.packet_wait = {std::chrono::milliseconds(1), std::chrono::milliseconds(1), std::chrono::milliseconds(4)};
	fake_startup_process_controller processes;
	const auto control_ready = healthy(health_response::STATE_CONTROL_READY);
	scripted_health_observer observer({control_ready}, control_ready);

	auto result = start_supervised_children(spec, observer, processes);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::DEADLINE_EXCEEDED);
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"cp", "dp"}));
	EXPECT_EQ(processes.termination_timeouts, (std::vector<int>{37, 37}));
}

/**
 * @brief Verify signal cancellation is checked before readiness I/O and cleans DP.
 */
TEST(photon_startup, shutdown_cancellation_rolls_back_before_health_observation)
{
	auto spec = valid_startup_spec();
	fake_startup_process_controller processes;
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY)});

	auto result = start_supervised_children(spec, observer, processes, []() { return true; });
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::CANCELLED);
	EXPECT_EQ(observer.calls(), 0U);
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"dp"}));
}

/**
 * @brief Verify a failed DP replaces the complete pair through both readiness gates.
 */
TEST(photon_startup, dp_failure_restarts_complete_pair_through_bundle_and_readiness)
{
	auto spec = valid_startup_spec();
	const auto expected_dp = std::vector<std::string>{spec.dp_executable,
							  "--bundle",
							  spec.bundle_root,
							  "--listen",
							  spec.dp_endpoint,
							  "--log-dir",
							  "/var/log/kinetum",
							  "--log-level",
							  "info",
							  "--log-max-bytes",
							  "16777216",
							  "--log-keep-files",
							  "8"};
	auto children = observed_terminal_pair(terminal_child_role::DP, 71);
	fake_startup_process_controller processes;
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY),
					   healthy(health_response::STATE_PACKET_READY)},
					  status::unavailable("unexpected observation"), &processes.events);

	supervised_pair_owner owner(std::move(children), std::move(spec), restart_policy::ON_FAILURE, processes);
	const auto result = owner.resolve_observed_exit(observer);
	ASSERT_TRUE(result.is_ok()) << result.message();
	const auto &replacement = owner.children();
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"cp", "dp"}));
	ASSERT_EQ(processes.spawns.size(), 2u);
	EXPECT_EQ(processes.spawns[0].argv, expected_dp);
	EXPECT_EQ(processes.spawns[1].name, "cp");
	EXPECT_EQ(replacement.restart_count, 1u);
	EXPECT_TRUE(replacement.dp.is_running());
	EXPECT_TRUE(replacement.cp.is_running());
	EXPECT_TRUE(owner.stop().is_ok());
}

/**
 * @brief Verify a failed CP cannot enter a child-only restart loop.
 */
TEST(photon_startup, cp_failure_restarts_complete_pair_through_bundle_and_readiness)
{
	auto spec = valid_startup_spec();
	auto children = observed_terminal_pair(terminal_child_role::CP, 72);
	fake_startup_process_controller processes;
	scripted_health_observer observer(
		{healthy(health_response::STATE_CONTROL_READY), healthy(health_response::STATE_PACKET_READY)});

	supervised_pair_owner owner(std::move(children), std::move(spec), restart_policy::ON_FAILURE, processes);
	const auto result = owner.resolve_observed_exit(observer);
	ASSERT_TRUE(result.is_ok()) << result.message();
	const auto &replacement = owner.children();
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"cp", "dp"}));
	ASSERT_EQ(processes.spawns.size(), 2u);
	EXPECT_EQ(processes.spawns[0].name, "dp");
	EXPECT_EQ(processes.spawns[1].name, "cp");
	EXPECT_EQ(observer.calls(), 2u);
	EXPECT_EQ(replacement.restart_count, 1u);
	EXPECT_TRUE(replacement.dp.is_running());
	EXPECT_TRUE(replacement.cp.is_running());
	EXPECT_TRUE(owner.stop().is_ok());
}

/**
 * @brief Verify default policy reports service loss after complete pair cleanup.
 */
TEST(photon_startup, never_policy_reports_unexpected_exit_after_pair_cleanup)
{
	auto spec = valid_startup_spec();
	auto children = observed_terminal_pair(terminal_child_role::DP, 71);
	fake_startup_process_controller processes;
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY)});

	supervised_pair_owner owner(std::move(children), std::move(spec), restart_policy::NEVER, processes);
	const auto result = owner.resolve_observed_exit(observer);
	EXPECT_EQ(result.code(), status_code::FAILED_PRECONDITION);
	EXPECT_EQ(result.message(), "supervised child exit is not eligible for pair replacement");
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"cp", "dp"}));
	EXPECT_TRUE(processes.spawns.empty());
	EXPECT_EQ(observer.calls(), 0u);
}

/** @brief Verify a zero exit cannot satisfy the nonzero-exit restart policy. */
TEST(photon_startup, on_failure_policy_reports_zero_exit_after_pair_cleanup)
{
	auto spec = valid_startup_spec();
	auto children = observed_terminal_pair(terminal_child_role::CP, 0);
	fake_startup_process_controller processes;
	scripted_health_observer observer({healthy(health_response::STATE_CONTROL_READY)});

	supervised_pair_owner owner(std::move(children), std::move(spec), restart_policy::ON_FAILURE, processes);
	const auto result = owner.resolve_observed_exit(observer);
	EXPECT_EQ(result.code(), status_code::FAILED_PRECONDITION);
	EXPECT_EQ(result.message(), "supervised child exit is not eligible for pair replacement");
	EXPECT_EQ(processes.terminated_names, (std::vector<std::string>{"cp", "dp"}));
	EXPECT_TRUE(processes.spawns.empty());
	EXPECT_EQ(observer.calls(), 0u);
}

}  // namespace kinetum::photon
