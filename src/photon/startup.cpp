// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file startup.cpp
 * @brief Implementation of transactional exact-readiness Photon startup.
 * @author Fleming Patel
 */

#include "src/photon/startup.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "src/common/canonical_content_identity.hpp"
#include "src/common/status.hpp"

namespace kinetum::photon
{
namespace
{

namespace fs = std::filesystem;

using kinetum::common::status;

static_assert(std::is_nothrow_move_constructible_v<supervised_startup_spec>,
	      "live pair adoption requires non-throwing startup-spec transfer");
static_assert(std::is_nothrow_move_constructible_v<supervised_children>,
	      "startup commit requires non-throwing child-authority transfer");
static_assert(std::is_nothrow_move_assignable_v<supervised_children>,
	      "pair replacement requires non-throwing child-authority transfer");

/**
 * @brief Build DP argv after the complete startup spec has been admitted.
 *
 * @param spec Valid startup specification.
 * @return Direct executable and argument vector.
 */
std::vector<std::string> make_dp_argv(const supervised_startup_spec &spec)
{
	std::vector<std::string> result{
		spec.dp_executable, "--bundle", spec.bundle_root, "--listen", spec.dp_endpoint,
	};
	const auto logging = kinetum::common::log_arguments(spec.logging);
	result.insert(result.end(), logging.begin(), logging.end());
	return result;
}

/**
 * @brief Build CP argv after the complete startup spec has been admitted.
 *
 * @param spec Valid startup specification.
 * @return Direct executable and argument vector carrying exact bootstrap
 *         authority.
 */
std::vector<std::string> make_cp_argv(const supervised_startup_spec &spec)
{
	std::vector<std::string> result{
		spec.cp_executable,
		"--listen-addr",
		spec.cp_listen,
		"--dp-addr",
		spec.dp_endpoint,
		"--config-store-dir",
		spec.config_store_dir,
		"--bootstrap-snapshot",
		spec.bootstrap_snapshot_path,
		"--bootstrap-plan-content-hash",
		spec.plan_content_hash,
	};
	const auto logging = kinetum::common::log_arguments(spec.logging);
	result.insert(result.end(), logging.begin(), logging.end());
	return result;
}

/**
 * @brief Render an exited child as a terminal startup error.
 *
 * @param child Reaped child authority.
 * @param gate Human-readable startup gate that was in progress.
 * @return FAILED_PRECONDITION carrying the actual retained exit code.
 */
status child_exited_during_startup(const child_proc &child, const std::string &gate)
{
	return status::failed_precondition(child.name + " exited during " + gate +
					   " readiness (exit_code=" + std::to_string(child.exit_code) + ")");
}

/**
 * @brief Decide whether one observed pair exit authorizes replacement.
 *
 * @param policy Sole pair-wide restart policy.
 * @param dp_exited Whether the DP child was terminal before pair cleanup.
 * @param dp_exit_code Retained DP exit code when terminal.
 * @param cp_exited Whether the CP child was terminal before pair cleanup.
 * @param cp_exit_code Retained CP exit code when terminal.
 * @return Replacement decision, or DATA_LOSS for an undeclared policy value.
 */
kinetum::common::status_or<bool> classify_pair_restart(restart_policy policy, bool dp_exited, int dp_exit_code,
						       bool cp_exited, int cp_exit_code)
{
	switch (policy) {
	case restart_policy::NEVER:
		return false;
	case restart_policy::ON_FAILURE:
		return (dp_exited && dp_exit_code != 0) || (cp_exited && cp_exit_code != 0);
	}
	return status::data_loss("supervised pair carries an undeclared restart policy");
}

/**
 * @brief Fail stop before relinquishing an unproven child/reaping authority.
 *
 * The diagnostic is fixed and bounded so this final ownership guard neither
 * allocates nor depends on the ordinary logging subsystem.
 */
[[noreturn]] void fail_stop_unreaped_child_authority() noexcept
{
	std::fputs("Photon cannot prove complete child reaping; terminating without relinquishing process authority\n",
		   stderr);
	std::terminate();
}

/**
 * @brief Fail stop before accessing an absent transaction child authority.
 *
 * @param role Fixed DP or CP role whose required child is absent.
 */
[[noreturn]] void fail_stop_missing_startup_child(const char *role) noexcept
{
	std::fprintf(stderr, "Photon startup ownership violation: missing %s child authority\n", role);
	std::terminate();
}

/**
 * @brief Own incomplete children and guarantee dependency-ordered rollback.
 *
 * One startup thread transfers each spawned child into this transaction. Until
 * commit, destruction or explicit rollback terminates and reaps CP before DP.
 * The type is deliberately non-copyable so an incomplete transaction has one
 * cleanup authority.
 */
class startup_transaction {
    public:
	/**
	 * @brief Construct an armed transaction with no children.
	 *
	 * @param processes Sole process-operation authority used for rollback.
	 * @param timeout_ms Nonnegative graceful termination interval.
	 */
	startup_transaction(startup_process_controller &processes, int timeout_ms)
		: processes_(processes)
		, timeout_ms_(timeout_ms)
	{
	}

	/** @brief Transactions cannot share child-cleanup authority. */
	startup_transaction(const startup_transaction &) = delete;

	/** @brief Transactions cannot replace child-cleanup authority. */
	startup_transaction &operator=(const startup_transaction &) = delete;

	/** @brief Roll back owned children when an armed scope is abandoned. */
	~startup_transaction() noexcept
	{
		if (!armed_) {
			return;
		}
		try {
			if (!cleanup().is_ok()) {
				fail_stop_unreaped_child_authority();
			}
		} catch (...) {
			fail_stop_unreaped_child_authority();
		}
	}

	/**
	 * @brief Transfer the newly spawned DP child into the transaction.
	 *
	 * @param child Sole DP child authority.
	 */
	void set_dp(child_proc child)
	{
		dp_.emplace(std::move(child));
	}

	/**
	 * @brief Transfer the newly spawned CP child into the transaction.
	 *
	 * @param child Sole CP child authority.
	 */
	void set_cp(child_proc child)
	{
		cp_.emplace(std::move(child));
	}

	/**
	 * @brief Access the transaction-owned DP child.
	 *
	 * @return Mutable DP child authority after `set_dp()`.
	 */
	[[nodiscard]] child_proc &dp()
	{
		if (!dp_.has_value()) {
			fail_stop_missing_startup_child("DP");
		}
		return *dp_;
	}

	/**
	 * @brief Access the transaction-owned CP child.
	 *
	 * @return Mutable CP child authority after `set_cp()`.
	 */
	[[nodiscard]] child_proc &cp()
	{
		if (!cp_.has_value()) {
			fail_stop_missing_startup_child("CP");
		}
		return *cp_;
	}

	/**
	 * @brief Preserve a startup failure after attempting complete rollback.
	 *
	 * @param failure Original startup failure.
	 * @return Original status code/message with cleanup failures appended to
	 *         details.
	 */
	[[nodiscard]] status rollback(status failure)
	{
		const auto cleanup_status = cleanup();
		if (cleanup_status.is_ok()) {
			armed_ = false;
		} else {
			std::string details(failure.details());
			if (!details.empty()) {
				details += "; ";
			}
			details.append(cleanup_status.message());
			if (!cleanup_status.details().empty()) {
				details += ": ";
				details.append(cleanup_status.details());
			}
			failure.set_details(std::move(details));
		}
		return failure;
	}

	/**
	 * @brief Transfer both ready child authorities to ordinary supervision.
	 *
	 * @return DP and CP child authorities after disarming rollback.
	 */
	[[nodiscard]] supervised_children commit() noexcept
	{
		if (!dp_.has_value()) {
			fail_stop_missing_startup_child("DP");
		}
		if (!cp_.has_value()) {
			fail_stop_missing_startup_child("CP");
		}
		supervised_children result{std::move(*dp_), std::move(*cp_), 0u};
		armed_ = false;
		return result;
	}

    private:
	/**
	 * @brief Terminate CP before DP and retain every cleanup failure.
	 *
	 * @return OK after complete cleanup, or INTERNAL_ERROR whose details contain
	 *         every failed child termination.
	 */
	[[nodiscard]] status cleanup()
	{
		std::string errors;
		auto terminate_one = [&](std::optional<child_proc> &child) {
			if (!child.has_value()) {
				return;
			}
			const auto result = processes_.terminate(*child, timeout_ms_);
			if (!result.is_ok()) {
				if (!errors.empty()) {
					errors += "; ";
				}
				errors += child->name + ": " + std::string(result.message());
			}
		};

		terminate_one(cp_);
		terminate_one(dp_);
		if (errors.empty()) {
			return status::ok();
		}
		auto failure = status::internal_error("startup rollback could not reap every child");
		failure.set_details(std::move(errors));
		return failure;
	}

	startup_process_controller &processes_;	 ///< Sole process-operation authority.
	int timeout_ms_;			 ///< Graceful rollback interval.
	std::optional<child_proc> dp_;		 ///< Transaction-owned DP child.
	std::optional<child_proc> cp_;		 ///< Transaction-owned CP child.
	bool armed_{true};			 ///< Whether destruction must roll back.
};

/**
 * @brief Build a gate callback that checks shutdown and every live child.
 *
 * @param transaction Incomplete startup transaction.
 * @param processes Child liveness/reaping authority.
 * @param include_cp Whether the second gate owns a CP child.
 * @param gate_name Stable diagnostic phase name.
 * @param shutdown_requested Optional synchronized cancellation predicate.
 * @return Callback suitable for `wait_for_exact_readiness()`.
 */
readiness_progress_check make_progress_check(startup_transaction &transaction, startup_process_controller &processes,
					     bool include_cp, std::string gate_name,
					     const startup_shutdown_check &shutdown_requested)
{
	return [&transaction, &processes, include_cp, gate_name = std::move(gate_name),
		shutdown_requested]() -> status {
		if (shutdown_requested && shutdown_requested()) {
			return status::cancelled("Photon startup cancelled during " + gate_name + " readiness");
		}
		auto dp_alive_or = processes.check(transaction.dp());
		if (!dp_alive_or.is_ok()) {
			return dp_alive_or.error();
		}
		if (!dp_alive_or.value()) {
			return child_exited_during_startup(transaction.dp(), gate_name);
		}
		if (include_cp) {
			auto cp_alive_or = processes.check(transaction.cp());
			if (!cp_alive_or.is_ok()) {
				return cp_alive_or.error();
			}
			if (!cp_alive_or.value()) {
				return child_exited_during_startup(transaction.cp(), gate_name);
			}
		}
		return status::ok();
	};
}

}  // namespace

kinetum::common::status_or<child_proc>
posix_startup_process_controller::spawn_argv(const std::string &name, const std::vector<std::string> &argv)
{
	return spawn_process_argv(name, argv);
}

kinetum::common::status_or<bool> posix_startup_process_controller::check(child_proc &child)
{
	return check_process(child);
}

status posix_startup_process_controller::terminate(child_proc &child, int timeout_ms)
{
	return terminate_process(child, timeout_ms);
}

status validate_supervised_startup_spec(const supervised_startup_spec &spec)
{
	auto logging_status = kinetum::common::validate_log_options(spec.logging);
	if (!logging_status.is_ok()) {
		return logging_status;
	}
	const std::array<std::string_view, 7> textual_inputs{
		spec.dp_executable,    spec.cp_executable,	     spec.bundle_root, spec.dp_endpoint, spec.cp_listen,
		spec.config_store_dir, spec.bootstrap_snapshot_path,
	};
	if (std::ranges::any_of(textual_inputs,
				[](std::string_view value) { return value.find('\0') != std::string_view::npos; })) {
		return status::invalid_argument("startup text inputs must not contain embedded NUL bytes");
	}
	if (spec.dp_executable.empty() || spec.cp_executable.empty()) {
		return status::invalid_argument("startup executable paths must be nonempty");
	}
	const fs::path dp_executable(spec.dp_executable);
	const fs::path cp_executable(spec.cp_executable);
	if (!dp_executable.is_absolute() || !cp_executable.is_absolute()) {
		return status::invalid_argument("startup executable paths must be absolute");
	}
	if (dp_executable != dp_executable.lexically_normal() || cp_executable != cp_executable.lexically_normal()) {
		return status::invalid_argument("startup executable paths must be lexically normalized");
	}
	if (spec.bundle_root.empty() || !fs::path(spec.bundle_root).is_absolute()) {
		return status::invalid_argument("startup bundle_root must be an absolute verified path");
	}
	if (spec.bootstrap_snapshot_path.empty() || !fs::path(spec.bootstrap_snapshot_path).is_absolute()) {
		return status::invalid_argument("startup bootstrap_snapshot_path must be an absolute verified path");
	}
	if (fs::path(spec.bundle_root) != fs::path(spec.bundle_root).lexically_normal() ||
	    fs::path(spec.bootstrap_snapshot_path) != fs::path(spec.bootstrap_snapshot_path).lexically_normal()) {
		return status::invalid_argument("startup bundle and artifact paths must be lexically normalized");
	}
	if (spec.dp_endpoint.empty() || spec.cp_listen.empty() || spec.config_store_dir.empty()) {
		return status::invalid_argument("startup endpoints and config-store path must be nonempty");
	}
	const fs::path config_store_dir(spec.config_store_dir);
	if (!config_store_dir.is_absolute() || config_store_dir != config_store_dir.lexically_normal()) {
		return status::invalid_argument("startup config_store_dir must be absolute and lexically normalized");
	}
	auto hash_status = kinetum::common::validate_sha256_hex_claim(spec.plan_content_hash,
								      "supervised_startup_spec.plan_content_hash");
	if (!hash_status.is_ok()) {
		return hash_status;
	}
	const auto control_policy_status = validate_readiness_wait_policy(spec.control_wait);
	if (!control_policy_status.is_ok()) {
		return status::invalid_argument("invalid CONTROL readiness policy: " +
						std::string(control_policy_status.message()));
	}
	const auto packet_policy_status = validate_readiness_wait_policy(spec.packet_wait);
	if (!packet_policy_status.is_ok()) {
		return status::invalid_argument("invalid PACKET readiness policy: " +
						std::string(packet_policy_status.message()));
	}
	if (spec.termination_timeout_ms <= 0) {
		return status::invalid_argument("startup termination timeout must be positive");
	}
	return status::ok();
}

kinetum::common::status_or<supervised_children>
start_supervised_children(const supervised_startup_spec &spec, dp_health_observer &observer,
			  startup_process_controller &processes, const startup_shutdown_check &shutdown_requested)
{
	const auto validation_status = validate_supervised_startup_spec(spec);
	if (!validation_status.is_ok()) {
		return validation_status;
	}

	startup_transaction transaction(processes, spec.termination_timeout_ms);
	auto dp_or = processes.spawn_argv("dp", make_dp_argv(spec));
	if (!dp_or.is_ok()) {
		return transaction.rollback(dp_or.error());
	}
	transaction.set_dp(std::move(dp_or).value());

	const auto control_status = wait_for_exact_readiness(observer, readiness_gate::CONTROL, spec.control_wait,
							     make_progress_check(transaction, processes, false,
										 "CONTROL_READY", shutdown_requested));
	if (!control_status.is_ok()) {
		return transaction.rollback(control_status.error());
	}

	auto cp_or = processes.spawn_argv("cp", make_cp_argv(spec));
	if (!cp_or.is_ok()) {
		return transaction.rollback(cp_or.error());
	}
	transaction.set_cp(std::move(cp_or).value());

	const auto packet_status = wait_for_exact_readiness(observer, readiness_gate::PACKET, spec.packet_wait,
							    make_progress_check(transaction, processes, true,
										"PACKET_READY", shutdown_requested));
	if (!packet_status.is_ok()) {
		return transaction.rollback(packet_status.error());
	}
	if (packet_status->runtime_generation != control_status->runtime_generation ||
	    packet_status->expected_workers != control_status->expected_workers) {
		return transaction.rollback(
			status::data_loss("DP readiness identity changed across CONTROL_READY and PACKET_READY"));
	}

	return transaction.commit();
}

namespace
{

/**
 * @brief Terminate and reap one complete pair in dependency order.
 *
 * @param children Sole DP/CP child authorities.
 * @param processes Process termination authority.
 * @param timeout_ms Nonnegative graceful termination interval per child.
 * @return OK after both children are reaped, or one aggregate cleanup failure.
 */
status stop_supervised_children(supervised_children &children, startup_process_controller &processes, int timeout_ms)
{
	if (timeout_ms < 0) {
		return status::invalid_argument("supervised pair termination timeout must be nonnegative");
	}

	std::string failures;
	auto stop_one = [&](child_proc &child) {
		const auto stopped = processes.terminate(child, timeout_ms);
		if (!stopped.is_ok()) {
			if (!failures.empty()) {
				failures += "; ";
			}
			failures += child.name + ": " + std::string(stopped.message());
			if (!stopped.details().empty()) {
				failures += ": ";
				failures.append(stopped.details());
			}
		}
	};

	stop_one(children.cp);
	stop_one(children.dp);
	if (failures.empty()) {
		return status::ok();
	}
	auto failure = status::internal_error("failed to terminate the complete supervised pair");
	failure.set_details(std::move(failures));
	return failure;
}

}  // namespace

supervised_pair_owner::supervised_pair_owner(supervised_children &&children, supervised_startup_spec &&startup_spec,
					     restart_policy policy, startup_process_controller &processes) noexcept
	: children_(std::move(children))
	, startup_spec_(std::move(startup_spec))
	, policy_(policy)
	, processes_(processes)
{
}

supervised_pair_owner::~supervised_pair_owner() noexcept
{
	if (!armed_) {
		return;
	}
	try {
		if (!stop_supervised_children(children_, processes_, startup_spec_.termination_timeout_ms).is_ok()) {
			fail_stop_unreaped_child_authority();
		}
	} catch (...) {
		fail_stop_unreaped_child_authority();
	}
}

supervised_children &supervised_pair_owner::children() noexcept
{
	return children_;
}

status supervised_pair_owner::stop()
{
	if (!armed_) {
		return status::ok();
	}
	auto stopped = stop_supervised_children(children_, processes_, startup_spec_.termination_timeout_ms);
	if (stopped.is_ok()) {
		armed_ = false;
	}
	return stopped;
}

status supervised_pair_owner::resolve_observed_exit(dp_health_observer &observer,
						    const startup_shutdown_check &shutdown_requested)
{
	const bool dp_exited = !children_.dp.is_running();
	const bool cp_exited = !children_.cp.is_running();
	if (!dp_exited && !cp_exited) {
		return status::failed_precondition(
			"supervised pair exit resolution requires at least one terminal child");
	}
	const auto restart_or =
		classify_pair_restart(policy_, dp_exited, children_.dp.exit_code, cp_exited, children_.cp.exit_code);

	auto stopped = stop_supervised_children(children_, processes_, startup_spec_.termination_timeout_ms);
	if (!stopped.is_ok()) {
		return stopped;
	}
	if (!restart_or.is_ok()) {
		armed_ = false;
		return restart_or.error();
	}
	if (!restart_or.value()) {
		armed_ = false;
		return status::failed_precondition("supervised child exit is not eligible for pair replacement");
	}
	if (children_.restart_count == std::numeric_limits<uint32_t>::max()) {
		armed_ = false;
		return status::resource_exhausted("supervised pair restart count reached its exact limit");
	}

	const uint32_t next_restart_count = children_.restart_count + 1u;
	auto replacement_or = start_supervised_children(startup_spec_, observer, processes_, shutdown_requested);
	if (!replacement_or.is_ok()) {
		armed_ = false;
		return replacement_or.error();
	}
	auto replacement = std::move(replacement_or).value();
	replacement.restart_count = next_restart_count;
	children_ = std::move(replacement);
	return status::ok();
}

}  // namespace kinetum::photon
