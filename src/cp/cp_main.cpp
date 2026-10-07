// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file cp_main.cpp
 * @brief Control plane entry point.
 * @author Fleming Patel
 *
 * This is the main entry point for the Kinetum Control Plane server. It:
 * 1. Parses command-line arguments for configuration
 * 2. Blocks SIGINT/SIGTERM and creates their sole signalfd before effects
 * 3. Admits an optional exact bootstrap snapshot/plan identity pair
 * 4. Initializes the config_store for snapshot persistence
 * 5. Establishes gRPC connection to the Data Plane
 * 6. Bootstraps CONTROL_READY or content-fences and reconciles PACKET_READY
 * 7. Starts packet-configuration mutation only after exact PACKET_READY
 * 8. Starts the read/control gRPC service
 * 9. Consumes termination and orders shutdown on the main thread
 *
 * A stopped control_loop remains the control-only capability boundary.
 * Packet-ready startup starts the commit-confirmed and telemetry guardrails
 * owner after durable transition and safety-intent reconciliation.
 *
 * Architecture:
 * -------------
 * The complete Control Plane architecture provides:
 * - Configuration publication, listing, inspection, and rollback
 * - Epoch-consistent updates to the Data Plane
 * - Automatic rollback via guardrails monitoring
 * - Health and statistics aggregation
 *
 * Process readiness is narrower than API availability. The gRPC read/control
 * surface may serve while packet-configuration mutation remains unavailable.
 *
 * TLS Configuration:
 * ------------------
 * The CP supports flexible TLS configurations:
 * - Server TLS: Secure the CP gRPC endpoint (--tls-cert, --tls-key, --tls-ca)
 * - Client TLS: Secure connection to DP (--client-tls-*)
 * - mTLS: Require client certificates (--tls-require-client-auth)
 * - Plaintext: Run without TLS on an explicitly isolated development or
 *   validation network (omit all TLS flags)
 *
 * Guardrails:
 * -----------
 * The runner owns commit-confirmed deadlines and enabled telemetry policy after
 * packet readiness. An explicit --guardrails artifact is fully admitted before
 * store or Data Plane effects, then persisted only after startup reconciliation.
 *
 * Production Deployment:
 * ----------------------
 * Recommended flags for production:
 * - Use TLS for both server and client (mTLS strongly recommended)
 * - Author every guardrails threshold, cadence, history, and attribution value explicitly
 * - Use persistent storage directory for --config-store-dir
 * - Run with process supervision (systemd, k8s, etc.)
 * - Monitor logs for automatic rollback events
 *
 */

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <utility>

#include <grpcpp/grpcpp.h>

#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "src/common/file_io.hpp"
#include "src/common/grpc_logging.hpp"
#include "src/common/log.hpp"
#include "src/common/log_service.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/tls.hpp"
#include "src/common/version.hpp"
#include "src/cp/bootstrap_startup.hpp"
#include "src/cp/config_store.hpp"
#include "src/cp/control_loop.hpp"
#include "src/cp/cp_grpc.hpp"
#include "src/cp/cp_termination_signal.hpp"
#include "src/cp/dataplane_bootstrap.hpp"
#include "src/cp/guardrails.hpp"
#include "src/cp/guardrails_policy.hpp"

namespace fs = std::filesystem;

// =============================================================================
// Command-Line Interface
// =============================================================================

/**
 * @brief Print usage information and exit.
 * @param argv0 Invoked program name rendered in command examples.
 * @param exit_code Process result after complete usage emission.
 */
[[noreturn]] static void usage(const char *argv0, int exit_code)
{
	std::cerr << "Kinetum Control Plane Server - " << kinetum::common::KINETUM_VERSION_STRING << "\n"
		  << "============================================\n\n"
		  << "Usage: " << argv0 << " [options]\n\n"
		  << "Core Options:\n"
		  << "  --listen-addr <addr>       CP listen address (default: 0.0.0.0:50051)\n"
		  << "  --dp-addr <addr>           Data Plane address (default: 127.0.0.1:50052)\n"
		  << "  --config-store-dir <dir>   Snapshot storage directory (default: /tmp/kinetum_cp_store)\n"
		  << "  --bootstrap-snapshot <path> Canonical bootstrap ConfigSnapshot path\n"
		  << "  --bootstrap-plan-content-hash <hex>  Exact bootstrap DeploymentPlan SHA-256\n"
		  << "  --guardrails <pbtxt>       Explicit GuardrailsPolicy pbtxt file\n"
		  << "\n"
		  << "Server TLS Options:\n"
		  << "  --tls-cert <pem>           Server certificate chain (PEM format)\n"
		  << "  --tls-key <pem>            Server private key (PEM format)\n"
		  << "  --tls-ca <pem>             Client CA certificate (for client auth)\n"
		  << "  --tls-require-client-auth  Require client certificate (mTLS)\n"
		  << "\n"
		  << "Client TLS Options (for DP connection):\n"
		  << "  --client-tls-ca <pem>      Root CA certificate for DP\n"
		  << "  --client-tls-cert <pem>    Client certificate for DP\n"
		  << "  --client-tls-key <pem>     Client private key for DP\n"
		  << "\n"
		  << "Examples:\n"
		  << "  # Plaintext on an isolated development or validation network:\n"
		  << "  " << argv0 << " --listen-addr 0.0.0.0:50051 --dp-addr localhost:50052\n"
		  << "\n"
		  << "  # Production with mTLS:\n"
		  << "  " << argv0 << " \\\n"
		  << "    --listen-addr 0.0.0.0:50051 \\\n"
		  << "    --tls-cert /etc/kinetum/cp_cert.pem \\\n"
		  << "    --tls-key /etc/kinetum/cp_key.pem \\\n"
		  << "    --tls-ca /etc/kinetum/ca.pem \\\n"
		  << "    --tls-require-client-auth \\\n"
		  << "    --dp-addr dp.kinetum.internal:50052 \\\n"
		  << "    --client-tls-ca /etc/kinetum/ca.pem \\\n"
		  << "    --client-tls-cert /etc/kinetum/cp_cert.pem \\\n"
		  << "    --client-tls-key /etc/kinetum/cp_key.pem \\\n"
		  << "    --guardrails /etc/kinetum/guardrails.pbtxt\n";
	std::cerr << kinetum::common::log_option_help();
	std::exit(exit_code);
}

// =============================================================================
// Main Entry Point
// =============================================================================

/**
 * @brief Run the complete Control Plane process lifecycle.
 * @param argc Command-line argument count.
 * @param argv Command-line argument vector.
 * @return Zero after clean service shutdown; nonzero on admission/startup failure.
 */
int main(int argc, char **argv)
{
	kinetum::common::set_command_log_identity("kinetum_cp");
	kinetum::common::log_options logging_options;
	kinetum::common::log_option_parser logging_parser(logging_options);
	// ---------------------------------------------------------------------------
	// Configuration Defaults
	// ---------------------------------------------------------------------------
	std::string listen_addr = "0.0.0.0:50051";
	std::string dp_addr = "127.0.0.1:50052";
	std::string config_store_dir = "/tmp/kinetum_cp_store";
	std::string bootstrap_snapshot_path;
	std::string bootstrap_plan_content_hash;
	std::string guardrails_path;

	// Server TLS configuration (for CP gRPC endpoint)
	kinetum::common::tls_server_config tls_server_cfg;
	bool tls_server_enabled = false;
	bool tls_require_client_auth = false;

	// Client TLS configuration (for connecting to DP)
	kinetum::common::tls_client_config tls_client_cfg;
	bool tls_client_enabled = false;

	// ---------------------------------------------------------------------------
	// Argument Parsing
	// ---------------------------------------------------------------------------
	int i = 1;  // Declare before lambda so it can be captured by reference

	auto require_value = [&](const char *flag) -> std::string {
		if (i + 1 >= argc) {
			std::cerr << "ERROR: Missing value for " << flag << "\n\n";
			usage(argv[0], 2);
		}
		return argv[++i];
	};

	for (; i < argc; ++i) {
		auto log_option = logging_parser.consume(i, argc, argv);
		if (!log_option.is_ok()) {
			std::cerr << log_option.error().message() << '\n';
			return 2;
		}
		if (log_option.value()) {
			continue;
		}
		const std::string arg = argv[i];

		// Core options
		if (arg == "--listen-addr") {
			listen_addr = require_value("--listen-addr");
		} else if (arg == "--dp-addr") {
			dp_addr = require_value("--dp-addr");
		} else if (arg == "--config-store-dir") {
			config_store_dir = require_value("--config-store-dir");
		} else if (arg == "--bootstrap-snapshot") {
			bootstrap_snapshot_path = require_value("--bootstrap-snapshot");
		} else if (arg == "--bootstrap-plan-content-hash") {
			bootstrap_plan_content_hash = require_value("--bootstrap-plan-content-hash");
		} else if (arg == "--guardrails") {
			guardrails_path = require_value("--guardrails");

			// Server TLS options
		} else if (arg == "--tls-cert") {
			tls_server_cfg.cert_pem_path = require_value("--tls-cert");
			tls_server_enabled = true;
		} else if (arg == "--tls-key") {
			tls_server_cfg.key_pem_path = require_value("--tls-key");
			tls_server_enabled = true;
		} else if (arg == "--tls-ca") {
			tls_server_cfg.ca_pem_path = require_value("--tls-ca");
			tls_server_enabled = true;
		} else if (arg == "--tls-require-client-auth") {
			tls_require_client_auth = true;
			tls_server_enabled = true;

			// Client TLS options
		} else if (arg == "--client-tls-ca") {
			tls_client_cfg.ca_pem_path = require_value("--client-tls-ca");
			tls_client_enabled = true;
		} else if (arg == "--client-tls-cert") {
			tls_client_cfg.cert_pem_path = require_value("--client-tls-cert");
			tls_client_enabled = true;
		} else if (arg == "--client-tls-key") {
			tls_client_cfg.key_pem_path = require_value("--client-tls-key");
			tls_client_enabled = true;

			// Help
		} else if (arg == "--help" || arg == "-h") {
			usage(argv[0], 0);

			// Unknown argument
		} else {
			std::cerr << "ERROR: Unknown argument: " << arg << "\n\n";
			usage(argv[0], 2);
		}
	}

	tls_server_cfg.require_client_auth = tls_require_client_auth;
	const auto logging_status = kinetum::common::validate_log_options(logging_options);
	if (!logging_status.is_ok()) {
		std::cerr << logging_status.message() << '\n';
		return 2;
	}

	// Establish process termination ownership before any persistent, remote, or
	// thread-producing effect. Every later thread inherits the blocked mask.
	auto termination_or = kinetum::cp::cp_termination_signal::create();
	if (!termination_or.is_ok()) {
		std::cerr << "FATAL: Failed to establish Control Plane termination authority: "
			  << termination_or.error().message() << "\n";
		return 1;
	}
	auto termination = std::move(termination_or).value();
	auto logging_or = kinetum::common::log_service::start(logging_options, "kinetum_cp");
	if (!logging_or.is_ok()) {
		std::cerr << "Failed to initialize logging: " << logging_or.error().message() << '\n';
		return 1;
	}
	auto logging = std::move(logging_or).value();
	auto grpc_logging_or = kinetum::common::grpc_logging::create();
	if (!grpc_logging_or.is_ok()) {
		KINETUM_LOG_ERROR("cp", "cp.grpc_logging.failed", "{}", grpc_logging_or.error().message());
		return 1;
	}
	auto grpc_logging = std::move(grpc_logging_or).value();

	// ---------------------------------------------------------------------------
	// Admit Bootstrap Process-Boundary Authority Before Store Side Effects
	// ---------------------------------------------------------------------------
	auto bootstrap_authority_or =
		kinetum::cp::admit_bootstrap_startup_authority(bootstrap_snapshot_path, bootstrap_plan_content_hash);
	if (!bootstrap_authority_or.is_ok()) {
		KINETUM_LOG_ERROR("cp", "cp.bootstrap.invalid", "Invalid bootstrap startup authority: {}",
				  bootstrap_authority_or.error().message());
		return 2;
	}
	auto bootstrap_authority = std::move(bootstrap_authority_or).value();
	if (bootstrap_authority.has_value()) {
		KINETUM_LOG_INFO("cp", "cp.bootstrap.snapshot", "Bootstrap snapshot designated: {}",
				 bootstrap_authority->snapshot_source.path().string());
		KINETUM_LOG_INFO("cp", "cp.bootstrap.plan", "Bootstrap plan identity: {}",
				 bootstrap_authority->plan_content_hash);
	} else {
		KINETUM_LOG_INFO("cp", "cp.control_only", "Control-only startup: no bootstrap authority supplied");
	}

	// ---------------------------------------------------------------------------
	// Admit Optional Startup Guardrails Policy Before Persistent/Remote Effects
	// ---------------------------------------------------------------------------
	std::optional<kinetum::control::v1::GuardrailsPolicy> startup_guardrails_policy;
	if (!guardrails_path.empty()) {
		KINETUM_LOG_INFO("cp", "cp.guardrails.loading", "Loading guardrails policy: {}", guardrails_path);
		kinetum::control::v1::GuardrailsPolicy guardrails_policy;
		const auto status = kinetum::common::read_pbtxt_file(
			guardrails_path, kinetum::common::DEFAULT_MAX_FILE_SIZE, &guardrails_policy);
		if (!status.is_ok()) {
			KINETUM_LOG_ERROR("cp", "cp.guardrails.parse_failed",
					  "Failed to parse guardrails policy {}: {}", guardrails_path,
					  status.message());
			return 2;
		}
		auto canonical_or = kinetum::cp::canonicalize_guardrails_policy(guardrails_policy);
		if (!canonical_or.is_ok()) {
			KINETUM_LOG_ERROR("cp", "cp.guardrails.invalid", "Invalid guardrails policy: {}",
					  canonical_or.error().message());
			return 2;
		}
		startup_guardrails_policy = std::move(guardrails_policy);
	}

	// ---------------------------------------------------------------------------
	// Initialize Configuration Store
	// ---------------------------------------------------------------------------
	KINETUM_LOG_INFO("cp", "cp.store.opening", "Initializing config store: {}", config_store_dir);
	auto store_or = kinetum::cp::config_store::open(fs::path(config_store_dir));
	if (!store_or.is_ok()) {
		KINETUM_LOG_ERROR("cp", "cp.store.failed", "Failed to initialize config store: {}",
				  store_or.error().message());
		return 1;
	}
	auto store = std::move(store_or).value();

	// ---------------------------------------------------------------------------
	// Create Data Plane Client
	// ---------------------------------------------------------------------------
	KINETUM_LOG_INFO("cp", "cp.dataplane.connecting", "Connecting to Data Plane: {} ({})", dp_addr,
			 tls_client_enabled ? "TLS" : "insecure");

	std::shared_ptr<grpc::ChannelCredentials> dp_creds;
	if (tls_client_enabled) {
		dp_creds = kinetum::common::make_channel_credentials(tls_client_cfg);
		if (!dp_creds) {
			KINETUM_LOG_ERROR("cp", "cp.dataplane.tls_failed",
					  "Failed to configure client TLS credentials for DP connection");
			return 1;
		}
	} else {
		dp_creds = grpc::InsecureChannelCredentials();
	}
	auto dp_channel = grpc::CreateChannel(dp_addr, dp_creds);

	// Shared DP read-backchannel stub for the control service.
	auto dp_stub = std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub>(
		kinetum::dataplane::v1::DataplaneService::NewStub(dp_channel));
	if (!dp_stub) {
		KINETUM_LOG_ERROR("cp", "cp.dataplane.client_failed", "Failed to construct Data Plane client");
		return 1;
	}

	// ---------------------------------------------------------------------------
	// Restore Exact Fixed-Epoch Data Plane Authority Before CP Publication
	// ---------------------------------------------------------------------------
	const auto startup_reconciliation_deadline =
		std::chrono::steady_clock::now() + kinetum::cp::DATAPLANE_STARTUP_RECONCILIATION_TIMEOUT;
	auto restored_or = kinetum::cp::bootstrap_dataplane_from_store(
		*store, *dp_stub, bootstrap_authority.has_value() ? &*bootstrap_authority : nullptr,
		startup_reconciliation_deadline);
	if (!restored_or.is_ok()) {
		KINETUM_LOG_ERROR("cp", "cp.bootstrap.failed", "Failed to restore Data Plane bootstrap: {}{}{}",
				  restored_or.error().message(), restored_or.error().details().empty() ? "" : ": ",
				  restored_or.error().details());
		return 1;
	}
	bootstrap_authority.reset();
	if (restored_or.value() != kinetum::cp::dataplane_bootstrap_outcome::CONTROL_ONLY) {
		KINETUM_LOG_INFO("cp", "cp.bootstrap.ready",
				 "Data Plane and durable Control Plane authority are packet-ready");
	} else {
		KINETUM_LOG_INFO("cp", "cp.control_only",
				 "Control-only startup: durable store has no active bootstrap");
	}

	// ---------------------------------------------------------------------------
	// Create and Reconcile the Single Shared Control-Loop Authority
	// ---------------------------------------------------------------------------
	kinetum::cp::control_loop loop(store.get(), dp_stub);
	if (!loop.initialization_status().is_ok()) {
		KINETUM_LOG_ERROR("cp", "cp.control.initialization_failed",
				  "Failed to initialize control-loop state: {}",
				  loop.initialization_status().message());
		return 1;
	}
	const bool packet_configuration_available = restored_or.value() !=
						    kinetum::cp::dataplane_bootstrap_outcome::CONTROL_ONLY;
	if (packet_configuration_available) {
		const auto startup_status = loop.reconcile_startup(
			restored_or.value() == kinetum::cp::dataplane_bootstrap_outcome::PACKET_READY_REJOINED,
			startup_reconciliation_deadline);
		if (!startup_status.is_ok()) {
			KINETUM_LOG_ERROR("cp", "cp.control.reconciliation_failed",
					  "Failed to reconcile durable transition state: {}", startup_status.message());
			return 1;
		}
	}
	if (startup_guardrails_policy.has_value()) {
		const auto policy_status = loop.configure_startup_guardrails_policy(*startup_guardrails_policy);
		if (!policy_status.is_ok()) {
			KINETUM_LOG_ERROR("cp", "cp.guardrails.persist_failed",
					  "Failed to persist startup guardrails policy: {}", policy_status.message());
			return 1;
		}
	}

	if (packet_configuration_available) {
		const auto start_status = loop.start();
		if (!start_status.is_ok()) {
			KINETUM_LOG_ERROR("cp", "cp.control.start_failed",
					  "Failed to start packet-configuration mutation authority: {}",
					  start_status.message());
			return 1;
		}
		KINETUM_LOG_INFO("cp", "cp.mutation.available", "Packet-configuration mutation authority available");
	} else {
		KINETUM_LOG_INFO("cp", "cp.mutation.unavailable",
				 "Packet-configuration mutation authority unavailable in control-only mode");
	}

	std::unique_ptr<kinetum::cp::guardrails_runner> guardrails;
	if (packet_configuration_available) {
		try {
			guardrails = std::make_unique<kinetum::cp::guardrails_runner>(store.get(), dp_stub, loop);
		} catch (const std::bad_alloc &) {
			KINETUM_LOG_ERROR("cp", "cp.guardrails.allocation_failed",
					  "Failed to allocate the guardrails owner");
			loop.stop();
			return 1;
		}
		const auto guardrails_status = guardrails->start();
		if (!guardrails_status.is_ok()) {
			KINETUM_LOG_ERROR("cp", "cp.guardrails.start_failed",
					  "Failed to start guardrails and commit-confirmed owner: {}",
					  guardrails_status.message());
			loop.stop();
			return 1;
		}
	}

	// ---------------------------------------------------------------------------
	// Create Control Plane Service (shared loop reference)
	// ---------------------------------------------------------------------------
	kinetum::cp::control_service_impl control_service(store.get(), dp_stub, loop);

	// ---------------------------------------------------------------------------
	// Start Control Plane gRPC Server
	// ---------------------------------------------------------------------------
	KINETUM_LOG_INFO("cp", "cp.server.starting", "Starting Control Plane server: {} ({}{})", listen_addr,
			 tls_server_enabled ? "TLS" : "insecure", tls_require_client_auth ? " + mTLS" : "");

	grpc::ServerBuilder builder;
	std::shared_ptr<grpc::ServerCredentials> server_creds;
	if (tls_server_enabled) {
		server_creds = kinetum::common::make_server_credentials(tls_server_cfg);
		if (!server_creds) {
			KINETUM_LOG_ERROR(
				"cp", "cp.server.tls_failed",
				"Failed to configure CP server TLS credentials; check cert/key paths, CA material, and permissions");
			return 1;
		}
	} else {
		server_creds = grpc::InsecureServerCredentials();
	}

	builder.AddListeningPort(listen_addr, server_creds);
	builder.RegisterService(&control_service);

	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
	if (!server) {
		KINETUM_LOG_ERROR("cp", "cp.server.start_failed", "Failed to start Control Plane gRPC server");
		return 1;
	}

	logging->startup_complete();
	KINETUM_LOG_INFO("cp", "cp.server.ready", "Control Plane ready and listening on {} (packet_configuration={})",
			 listen_addr, packet_configuration_available ? "available" : "unavailable");
	KINETUM_LOG_INFO("cp", "cp.shutdown.instructions", "Press Ctrl+C to shutdown");

	// ---------------------------------------------------------------------------
	// Consume termination on the main thread, then close gRPC admission there.
	// ---------------------------------------------------------------------------
	int termination_signal = 0;
	kinetum::common::status signal_status;
	for (;;) {
		auto signal_or = termination->wait();
		if (!signal_or.is_ok()) {
			signal_status = std::move(signal_or).error();
			break;
		}
		if (signal_or.value() == SIGUSR1) {
			logging->request_reopen();
			continue;
		}
		termination_signal = signal_or.value();
		break;
	}
	server->Shutdown();
	server->Wait();

	// ---------------------------------------------------------------------------
	// Graceful Shutdown Sequence
	// ---------------------------------------------------------------------------
	if (guardrails != nullptr) {
		guardrails->stop();
	}
	loop.stop();

	if (signal_status.is_ok()) {
		KINETUM_LOG_INFO("cp", "cp.shutdown.complete", "received signal {}, Control Plane shutdown complete",
				 termination_signal);
	} else {
		KINETUM_LOG_ERROR("cp", "cp.shutdown.signal_failed",
				  "termination signal observation failed after Control Plane shutdown: {}",
				  signal_status.message());
	}
	return signal_status.is_ok() ? 0 : 1;
}
