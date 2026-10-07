// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file photon_main.cpp
 * @brief Photon: Exact single-node DP/CP supervisor.
 * @author Fleming Patel
 *
 * Photon serves as the single-node supervisor for the Kinetum platform:
 * - Admits one complete runtime bundle before child-process setup
 * - Spawns and monitors Data Plane (DP) and Control Plane (CP) processes
 * - Handles graceful shutdown on SIGTERM/SIGINT
 * - Implements process restart policies
 *
 * Signal Handling:
 * - SIGTERM/SIGINT: Graceful shutdown of all processes
 * - SIGUSR1: Reopen the supervisor log and forward to its owned pair
 * Signals remain blocked in every thread and are consumed on the main thread.
 */

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <pthread.h>

#include "src/common/log.hpp"
#include "src/common/grpc_logging.hpp"
#include "src/common/log_service.hpp"
#include "src/common/process_image.hpp"
#include "src/common/status.hpp"
#include "src/pack/runtime_bundle.hpp"
#include "src/photon/startup.hpp"

namespace
{

// =============================================================================
// Constants
// =============================================================================

/** @brief Interval between child-process liveness observations. */
constexpr auto SUPERVISION_POLL_INTERVAL = std::chrono::seconds(1);

/** @brief Absolute durable-state location for supervised control-plane runs. */
constexpr std::string_view DEFAULT_CONFIG_STORE_DIR = "/var/lib/kinetum/config";

/**
 * @brief Block process-control signals before any writer or gRPC thread starts.
 * @return Exact process-lifetime set, or an explicit startup error.
 */
kinetum::common::status_or<sigset_t> block_control_signals()
{
	sigset_t signals{};
	if (::sigemptyset(&signals) != 0 || ::sigaddset(&signals, SIGINT) != 0 || ::sigaddset(&signals, SIGTERM) != 0 ||
	    ::sigaddset(&signals, SIGUSR1) != 0) {
		return kinetum::common::status::internal_error("failed to construct supervisor signal set");
	}
	const int blocked = ::pthread_sigmask(SIG_BLOCK, &signals, nullptr);
	if (blocked != 0) {
		return kinetum::common::status::internal_error("failed to block supervisor signals: " +
							       std::string(std::strerror(blocked)));
	}
	if (::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		return kinetum::common::status::internal_error("failed to ignore SIGPIPE: " +
							       std::string(std::strerror(errno)));
	}
	return signals;
}

/**
 * @brief Consume one main-thread signal within a bounded wait.
 * @param signals Exact blocked process-control set.
 * @param timeout Maximum wait, including interruption retries.
 * @return Consumed signal, zero on timeout, or the observation failure.
 */
kinetum::common::status_or<int> poll_control_signal(const sigset_t &signals, std::chrono::milliseconds timeout)
{
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	for (;;) {
		const auto now = std::chrono::steady_clock::now();
		const auto remaining = now < deadline ? deadline - now : std::chrono::steady_clock::duration::zero();
		const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(remaining);
		const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(remaining - seconds);
		const timespec wait{static_cast<time_t>(seconds.count()), static_cast<long>(nanoseconds.count())};
		const int signal = ::sigtimedwait(&signals, nullptr, &wait);
		if (signal < 0 && errno == EINTR) {
			continue;
		}
		if (signal < 0 && errno == EAGAIN) {
			return 0;
		}
		if (signal != SIGINT && signal != SIGTERM && signal != SIGUSR1) {
			return kinetum::common::status::internal_error("supervisor signal observation failed");
		}
		return signal;
	}
}

// =============================================================================
// Usage
// =============================================================================

/** @brief Print the complete finite invocation and logging option surface. */
void usage()
{
	std::cerr << "Photon: Kinetum Platform Supervisor\n"
		  << "\n"
		  << "Usage:\n"
		  << "  kinetum_photon --bundle <bundle_dir> [options]\n"
		  << "\n"
		  << "Options:\n"
		  << "  --bundle <dir>          Path to verified runtime bundle (required)\n"
		  << "  --cp-listen <addr>      CP gRPC listen address (default: 127.0.0.1:50051)\n"
		  << "  --dp-endpoint <addr>    DP gRPC endpoint (default: 127.0.0.1:50052)\n"
		  << "  --config-store-dir <dir>  Absolute config-store directory (default: /var/lib/kinetum/config)\n"
		  << "  --restart-on-failure    Restart processes if they exit with non-zero code\n"
		  << "  -h, --help              Show this help message\n"
		  << "\n"
		  << "Example:\n"
		  << "  kinetum_photon --bundle /var/lib/kinetum/bundles/prod\n";
	std::cerr << kinetum::common::log_option_help();
}

}  // namespace

/**
 * @brief Run the Photon supervisor.
 * @param argc Number of command-line arguments.
 * @param argv Argument vector owned by the process runtime.
 * @return Zero after help or signal-requested clean shutdown; nonzero on
 *         admission, startup, service-loss, or supervision failure.
 */
int main(int argc, char **argv)
{
	std::unique_ptr<kinetum::common::log_service> logging;
	std::unique_ptr<kinetum::common::grpc_logging> grpc_logging;
	try {
		kinetum::common::set_command_log_identity("kinetum_photon");
		kinetum::common::log_options logging_options;
		kinetum::common::log_option_parser logging_parser(logging_options);
		// Parse command line arguments
		std::string bundle_path;
		std::string store_dir(DEFAULT_CONFIG_STORE_DIR);
		std::string cp_listen = "127.0.0.1:50051";
		std::string dp_endpoint = "127.0.0.1:50052";
		bool restart_on_failure = false;

		for (int i = 1; i < argc; i++) {
			auto log_option = logging_parser.consume(i, argc, argv);
			if (!log_option.is_ok()) {
				std::cerr << log_option.error().message() << '\n';
				return 2;
			}
			if (log_option.value()) {
				continue;
			}
			std::string a = argv[i];
			if ((a == "--bundle") && i + 1 < argc) {
				bundle_path = argv[++i];
			} else if ((a == "--config-store-dir") && i + 1 < argc) {
				store_dir = argv[++i];
			} else if ((a == "--cp-listen") && i + 1 < argc) {
				cp_listen = argv[++i];
			} else if ((a == "--dp-endpoint") && i + 1 < argc) {
				dp_endpoint = argv[++i];
			} else if (a == "--restart-on-failure") {
				restart_on_failure = true;
			} else if (a == "-h" || a == "--help") {
				usage();
				return 0;
			} else {
				std::cerr << "Unknown option: " << a << "\n";
				usage();
				return 2;
			}
		}

		if (bundle_path.empty()) {
			std::cerr << "Error: --bundle is required\n";
			usage();
			return 2;
		}
		const auto logging_status = kinetum::common::validate_log_options(logging_options);
		if (!logging_status.is_ok()) {
			std::cerr << logging_status.message() << '\n';
			return 2;
		}

		// Process-image provenance is admitted before bundle I/O or process state.
		// Linux /proc/self/exe is the sole authority; child discovery never depends
		// on argv[0], PATH, the current working directory, or an install-prefix guess.
		auto photon_image_or = kinetum::common::current_process_image();
		if (!photon_image_or.is_ok()) {
			KINETUM_LOG_ERROR("photon", "photon.image.rejected", "process-image admission failed: {}{}{}",
					  photon_image_or.error().message(),
					  photon_image_or.error().details().empty() ? "" : ": ",
					  photon_image_or.error().details());
			return 1;
		}
		const auto photon_image = std::move(photon_image_or).value();
		auto dp_image_or = kinetum::common::resolve_sibling_process_image(photon_image, "kinetum_dp");
		if (!dp_image_or.is_ok()) {
			KINETUM_LOG_ERROR("photon", "photon.dp_image.rejected",
					  "DP process-image admission failed: {}{}{}", dp_image_or.error().message(),
					  dp_image_or.error().details().empty() ? "" : ": ",
					  dp_image_or.error().details());
			return 1;
		}
		auto cp_image_or = kinetum::common::resolve_sibling_process_image(photon_image, "kinetum_cp");
		if (!cp_image_or.is_ok()) {
			KINETUM_LOG_ERROR("photon", "photon.cp_image.rejected",
					  "CP process-image admission failed: {}{}{}", cp_image_or.error().message(),
					  cp_image_or.error().details().empty() ? "" : ": ",
					  cp_image_or.error().details());
			return 1;
		}
		const std::string dp_executable = std::move(dp_image_or).value().string();
		const std::string cp_executable = std::move(cp_image_or).value().string();
		const auto signals_or = block_control_signals();
		if (!signals_or.is_ok()) {
			KINETUM_LOG_ERROR("photon", "photon.signals.failed", "{}", signals_or.error().message());
			return 1;
		}
		const auto signals = signals_or.value();
		auto logging_or = kinetum::common::log_service::start(logging_options, "kinetum_photon");
		if (!logging_or.is_ok()) {
			KINETUM_LOG_ERROR("photon", "photon.logging.failed", "{}", logging_or.error().message());
			return 1;
		}
		logging = std::move(logging_or).value();
		auto grpc_logging_or = kinetum::common::grpc_logging::create();
		if (!grpc_logging_or.is_ok()) {
			KINETUM_LOG_ERROR("photon", "photon.grpc_logging.failed", "{}",
					  grpc_logging_or.error().message());
			return 1;
		}
		grpc_logging = std::move(grpc_logging_or).value();
		int received_signal = 0;
		bool signal_failed = false;
		bool child_reopen_requested = false;
		/** Consume at most one pending record per declared signal before returning to control work. */
		auto observe_signals = [&](std::chrono::milliseconds timeout) {
			for (int count = 0; count < 3; ++count) {
				auto observed = poll_control_signal(signals, count == 0 ? timeout :
											  std::chrono::milliseconds(0));
				if (!observed.is_ok()) {
					KINETUM_LOG_ERROR("photon", "photon.signals.failed", "{}",
							  observed.error().message());
					signal_failed = true;
					break;
				}
				if (observed.value() == 0) {
					break;
				}
				if (observed.value() == SIGUSR1) {
					logging->request_reopen();
					child_reopen_requested = true;
				} else if (received_signal == 0) {
					received_signal = observed.value();
				}
			}
			return received_signal != 0 || signal_failed;
		};
		/** Startup and replacement poll the same main-thread signal authority. */
		auto shutdown_requested = [&] { return observe_signals(std::chrono::milliseconds(0)); };

		// =========================================================================
		// Runtime-Bundle Validation (Production Enforcement)
		// =========================================================================

		// Manifest/path integrity and plan/snapshot identity are unconditional
		// startup correctness authorities.
		auto verified_bundle_or = kinetum::pack::verify_runtime_bundle(bundle_path);
		if (!verified_bundle_or.is_ok()) {
			KINETUM_LOG_ERROR("photon", "photon.bundle.rejected",
					  "runtime bundle verification failed: {}{}{}",
					  verified_bundle_or.error().message(),
					  verified_bundle_or.error().details().empty() ? "" : ": ",
					  verified_bundle_or.error().details());
			return 1;
		}
		auto verified_bundle = std::move(verified_bundle_or).value();
		const auto &plan = verified_bundle.plan;

		KINETUM_LOG_INFO("photon", "photon.bundle.verified", "verified bundle: {}",
				 verified_bundle.bundle_root);
		KINETUM_LOG_INFO("photon", "photon.plan.loaded", "loaded plan: {}", plan.plan_id());
		KINETUM_LOG_INFO("photon", "photon.snapshot.loaded", "bootstrap snapshot: {}",
				 verified_bundle.bootstrap_snapshot_path);

		// Build and admit the complete child authority before spawning. The
		// production process controller revalidates each exact image
		// at posix_spawn(), closing the component-embedding path as well.
		kinetum::photon::supervised_startup_spec startup_spec;
		startup_spec.dp_executable = dp_executable;
		startup_spec.cp_executable = cp_executable;
		startup_spec.bundle_root = verified_bundle.bundle_root;
		startup_spec.dp_endpoint = dp_endpoint;
		startup_spec.cp_listen = cp_listen;
		startup_spec.config_store_dir = store_dir;
		startup_spec.bootstrap_snapshot_path = verified_bundle.bootstrap_snapshot_path;
		startup_spec.plan_content_hash = plan.content_hash();
		startup_spec.logging = logging_options;
		const auto pair_restart_policy = restart_on_failure ? kinetum::photon::restart_policy::ON_FAILURE :
								      kinetum::photon::restart_policy::NEVER;
		const auto startup_validation = kinetum::photon::validate_supervised_startup_spec(startup_spec);
		if (!startup_validation.is_ok()) {
			KINETUM_LOG_ERROR("photon", "photon.startup.invalid",
					  "supervised startup authority is invalid: {}", startup_validation.message());
			return 2;
		}

		KINETUM_LOG_INFO("photon", "photon.starting", "starting supervisor");
		KINETUM_LOG_INFO("photon", "photon.bundle.path", "bundle={}", verified_bundle.bundle_root);
		KINETUM_LOG_INFO("photon", "photon.plan.path", "plan={}", verified_bundle.plan_path);
		KINETUM_LOG_INFO("photon", "photon.store.path", "config_store_dir={}", store_dir);

		// Startup is one dependency-ordered transaction. DP must prove exact
		// CONTROL_READY before CP receives the verified bootstrap authority, and
		// ordinary supervision remains unreachable until DP proves exact
		// PACKET_READY. Every failed gate reaps CP before DP.
		KINETUM_LOG_INFO("photon", "photon.dp.startup", "DP startup: {} --bundle {} --listen {} --log-dir {}",
				 startup_spec.dp_executable, startup_spec.bundle_root, dp_endpoint,
				 logging_options.directory);
		KINETUM_LOG_INFO(
			"photon", "photon.cp.startup",
			"CP startup: {} --listen-addr {} --dp-addr {} --config-store-dir {} --bootstrap-snapshot {} --bootstrap-plan-content-hash {} --log-dir {}",
			startup_spec.cp_executable, cp_listen, dp_endpoint, store_dir,
			startup_spec.bootstrap_snapshot_path, startup_spec.plan_content_hash,
			logging_options.directory);

		kinetum::photon::grpc_dp_health_observer health_observer(dp_endpoint);
		kinetum::photon::posix_startup_process_controller process_controller;
		auto children_or = kinetum::photon::start_supervised_children(startup_spec, health_observer,
									      process_controller, shutdown_requested);
		if (!children_or.is_ok()) {
			if (received_signal != 0 && !signal_failed &&
			    children_or.error().code() == kinetum::common::status_code::CANCELLED) {
				return 0;
			}
			KINETUM_LOG_ERROR("photon", "photon.startup.failed", "supervised startup failed: {}{}{}",
					  children_or.error().message(),
					  children_or.error().details().empty() ? "" : ": ",
					  children_or.error().details());
			return 1;
		}
		kinetum::photon::supervised_pair_owner pair_owner(std::move(children_or).value(),
								  std::move(startup_spec), pair_restart_policy,
								  process_controller);
		auto &children = pair_owner.children();
		bool supervision_failed = false;

		logging->startup_complete();
		KINETUM_LOG_INFO("photon", "photon.ready", "supervisor running, press Ctrl+C to stop");

		// Main supervision loop
		while (!shutdown_requested()) {
			if (child_reopen_requested) {
				for (const auto *child : {&children.dp, &children.cp}) {
					const auto requested = kinetum::photon::request_process_log_reopen(*child);
					if (!requested.is_ok()) {
						KINETUM_LOG_ERROR("photon", "photon.child.reopen_failed", "{}: {}",
								  child->name, requested.message());
					}
				}
				child_reopen_requested = false;
			}
			// Observe both members before making one pair-scoped decision.
			auto dp_alive_or = process_controller.check(children.dp);
			if (!dp_alive_or.is_ok()) {
				KINETUM_LOG_ERROR("photon", "photon.dp.observation_failed",
						  "DP liveness observation failed: {}", dp_alive_or.error().message());
				supervision_failed = true;
				break;
			}
			auto cp_alive_or = process_controller.check(children.cp);
			if (!cp_alive_or.is_ok()) {
				KINETUM_LOG_ERROR("photon", "photon.cp.observation_failed",
						  "CP liveness observation failed: {}", cp_alive_or.error().message());
				supervision_failed = true;
				break;
			}
			if (!dp_alive_or.value() || !cp_alive_or.value()) {
				const char *role = !dp_alive_or.value() ? "DP" : "CP";
				const auto &exited = !dp_alive_or.value() ? children.dp : children.cp;
				KINETUM_LOG_WARN(
					"photon", "photon.child.exited",
					"{} process exited (exit_code={}); resolving the complete supervised pair",
					role, exited.exit_code);

				if (shutdown_requested()) {
					break;
				}
				const auto resolution_status =
					pair_owner.resolve_observed_exit(health_observer, shutdown_requested);
				if (!resolution_status.is_ok()) {
					if (received_signal != 0 && !signal_failed &&
					    resolution_status.code() == kinetum::common::status_code::CANCELLED) {
						break;
					}
					KINETUM_LOG_ERROR("photon", "photon.pair.failed",
							  "supervised pair cannot continue: {}{}{}",
							  resolution_status.message(),
							  resolution_status.details().empty() ? "" : ": ",
							  resolution_status.details());
					supervision_failed = true;
					break;
				}
				KINETUM_LOG_INFO("photon", "photon.pair.restarted",
						 "supervised pair restart completed through PACKET_READY (count={})",
						 children.restart_count);
				continue;
			}

			(void)observe_signals(
				std::chrono::duration_cast<std::chrono::milliseconds>(SUPERVISION_POLL_INTERVAL));
		}

		// Graceful shutdown
		const int sig = received_signal;
		if (sig != 0) {
			KINETUM_LOG_INFO("photon", "photon.shutdown.signal", "received signal {}, shutting down", sig);
		}

		KINETUM_LOG_INFO("photon", "photon.pair.stopping", "stopping supervised pair (CP before DP)");
		const auto pair_status = pair_owner.stop();
		if (!pair_status.is_ok()) {
			KINETUM_LOG_ERROR("photon", "photon.pair.stop_failed", "error stopping supervised pair: {}{}{}",
					  pair_status.message(), pair_status.details().empty() ? "" : ": ",
					  pair_status.details());
			return 1;
		}

		KINETUM_LOG_INFO("photon", "photon.shutdown.complete", "supervisor shutdown complete");
		return supervision_failed || signal_failed ? 1 : 0;
	} catch (const std::exception &error) {
		if (logging != nullptr) {
			KINETUM_LOG_ERROR(
				"photon", "photon.exception", "unexpected supervisor exception: {}",
				std::string_view(error.what(),
						 ::strnlen(error.what(), kinetum::common::LOG_MESSAGE_BYTES + 1)));
		} else {
			std::fputs("Photon startup failed before logging admission\n", stderr);
		}
		return 1;
	} catch (...) {
		if (logging != nullptr) {
			KINETUM_LOG_ERROR("photon", "photon.exception", "unknown supervisor exception");
		} else {
			std::fputs("Photon startup failed before logging admission\n", stderr);
		}
		return 1;
	}
}
