// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dp_main.cpp
 * @brief Data Plane host entry point for one verified runtime bundle.
 * @author Fleming Patel
 *
 * Startup admits one complete bundle, compiles no second topology, proves the
 * exact host, authenticates the installed provider closure, and transfers all
 * resulting authorities into one materialized runtime generation. The gRPC
 * service is exposed only after that runtime has published CONTROL_READY.
 * Exact Bootstrap later activates the fixed epoch and publishes PACKET_READY.
 *
 * SIGINT, SIGTERM, and SIGUSR1 are blocked before any runtime, provider, or gRPC thread
 * exists. The main thread polls blocked signals, the bounded command and
 * lifecycle wake descriptors, and the current monotonic control deadline. On
 * termination it closes admission, initiates bounded server shutdown, retires
 * the runtime in reverse dependency order, then waits for handlers.
 */

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <pthread.h>

#include <grpcpp/grpcpp.h>

#include "src/common/log.hpp"
#include "src/common/grpc_logging.hpp"
#include "src/common/log_service.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/tls.hpp"
#include "src/dp/dataplane_control_service.hpp"
#include "src/dp/dp_control_event_loop.hpp"
#include "src/dp/epoch/epoch_transition_command_mailbox.hpp"
#include "src/dp/module/module_manager.hpp"
#include "src/dp/packet_runtime_generation.hpp"
#include "src/dp/partitioned_runtime.hpp"
#include "src/pack/runtime_bundle.hpp"
#include "src/provider/provider_installation.hpp"
#include "src/provider/provider_release_trust.hpp"
#include "src/provider/provider_runtime_admission.hpp"
#include "src/quark/host_probe.hpp"
#include "src/quark/runtime_compat.hpp"

namespace
{

using kinetum::common::status;
using kinetum::common::status_or;

/** @brief Complete provider-neutral DP command-line authority. */
struct args {
	std::string bundle_root;		   ///< Exact runtime-bundle root to re-admit.
	std::string listen_addr{"0.0.0.0:50052"};  ///< gRPC listen endpoint.
	bool tls_enabled{false};		   ///< Whether any TLS option was supplied.
	kinetum::common::tls_server_config tls;	   ///< Exact TLS file authority.
	bool help_requested{false};		   ///< Whether usage was requested.
	kinetum::common::log_options logging;	   ///< Immutable cold logging settings.
};

/**
 * @brief Print the complete Data Plane command-line contract.
 * @param program Invocation name used only in the usage display.
 */
void usage(const char *program)
{
	std::cerr << "Usage: " << program << " --bundle <dir> [options]\n\n";
	std::cerr << "Options:\n";
	std::cerr << "  --bundle <dir>                 Complete verified runtime bundle (required)\n";
	std::cerr << "  --listen <addr:port>           Dataplane gRPC listen address (default 0.0.0.0:50052)\n";
	std::cerr << "\nTLS options (gRPC):\n";
	std::cerr << "  --tls-cert <path>               TLS server certificate chain PEM\n";
	std::cerr << "  --tls-key <path>                TLS server private key PEM\n";
	std::cerr << "  --tls-ca <path>                 TLS client CA PEM (optional)\n";
	std::cerr << "  --tls-require-client-auth       Require mTLS client certificates\n";
	std::cerr << kinetum::common::log_option_help();
}

/**
 * @brief Parse the exact provider-neutral startup CLI.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param parsed Destination updated on success.
 * @return true for one complete command or help request.
 */
bool parse_args(int argc, char **argv, args &parsed)
{
	kinetum::common::log_option_parser logging(parsed.logging);
	for (int i = 1; i < argc; ++i) {
		auto log_option = logging.consume(i, argc, argv);
		if (!log_option.is_ok()) {
			std::cerr << log_option.error().message() << '\n';
			return false;
		}
		if (log_option.value()) {
			continue;
		}
		const std::string value = argv[i];
		auto need = [&](const char *name) -> const char * {
			if (i + 1 >= argc) {
				std::cerr << "Missing value for " << name << "\n";
				return nullptr;
			}
			return argv[++i];
		};

		if (value == "--bundle") {
			const char *path = need("--bundle");
			if (path == nullptr) {
				return false;
			}
			parsed.bundle_root = path;
		} else if (value == "--listen") {
			const char *endpoint = need("--listen");
			if (endpoint == nullptr) {
				return false;
			}
			parsed.listen_addr = endpoint;
		} else if (value == "--tls-cert") {
			const char *path = need("--tls-cert");
			if (path == nullptr) {
				return false;
			}
			parsed.tls.cert_pem_path = path;
			parsed.tls_enabled = true;
		} else if (value == "--tls-key") {
			const char *path = need("--tls-key");
			if (path == nullptr) {
				return false;
			}
			parsed.tls.key_pem_path = path;
			parsed.tls_enabled = true;
		} else if (value == "--tls-ca") {
			const char *path = need("--tls-ca");
			if (path == nullptr) {
				return false;
			}
			parsed.tls.ca_pem_path = path;
			parsed.tls_enabled = true;
		} else if (value == "--tls-require-client-auth") {
			parsed.tls.require_client_auth = true;
			parsed.tls_enabled = true;
		} else if (value == "--help" || value == "-h") {
			parsed.help_requested = true;
			return true;
		} else {
			std::cerr << "Unknown arg: " << value << "\n";
			return false;
		}
	}
	const auto log_status = kinetum::common::validate_log_options(parsed.logging);
	if (!log_status.is_ok()) {
		std::cerr << log_status.message() << '\n';
		return false;
	}
	return parsed.help_requested || !parsed.bundle_root.empty();
}

/**
 * @brief Block termination signals before the process creates any thread.
 *
 * @param blocked_set Exact set later consumed through signalfd.
 * @return OK after process-thread mask publication, or an explicit error.
 */
status block_termination_signals(sigset_t &blocked_set)
{
	if (::sigemptyset(&blocked_set) != 0 || ::sigaddset(&blocked_set, SIGINT) != 0 ||
	    ::sigaddset(&blocked_set, SIGTERM) != 0 || ::sigaddset(&blocked_set, SIGUSR1) != 0) {
		return status::internal_error("failed to construct the DP termination signal set: " +
					      std::string(std::strerror(errno)));
	}
	const int mask_result = ::pthread_sigmask(SIG_BLOCK, &blocked_set, nullptr);
	if (mask_result != 0) {
		return status::internal_error("failed to block DP termination signals: " +
					      std::string(std::strerror(mask_result)));
	}
	return status::ok();
}

/**
 * @brief Convert verified module paths into the runtime's exact image authority.
 *
 * @param verified Sorted bundle-owned image set.
 * @return Sorted module image specifications, or allocation failure.
 */
status_or<std::vector<kinetum::dp::module::module_image_spec>>
make_module_image_specs(const std::vector<kinetum::pack::verified_module_image> &verified)
{
	try {
		std::vector<kinetum::dp::module::module_image_spec> result;
		result.reserve(verified.size());
		for (const auto &image : verified) {
			result.push_back({.module_id = image.module_id, .canonical_path = image.image_path});
		}
		return result;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate exact runtime module-image authority");
	}
}

/**
 * @brief Log one complete startup status with bounded source-owned details.
 * @param subject Static operation description.
 * @param failure Borrowed non-OK status whose message and details are formatted by the cold logger.
 */
void log_startup_failure(const char *subject, const status &failure)
{
	KINETUM_LOG_ERROR("dp", "dp.operation.failed", "{}: {}{}{}{}", subject, failure.message(),
			  failure.details().empty() ? "" : " (", failure.details(),
			  failure.details().empty() ? "" : ")");
}

}  // namespace

/**
 * @brief Run the Data Plane process from exact command-line authority.
 * @param argc Number of command-line arguments.
 * @param argv Argument vector owned by the process runtime.
 * @return Zero on clean shutdown; nonzero on admission, startup, or teardown failure.
 */
int main(int argc, char **argv)
{
	kinetum::common::set_command_log_identity("kinetum_dp");
	args parsed;
	if (!parse_args(argc, argv, parsed)) {
		usage(argv[0]);
		return 1;
	}
	if (parsed.help_requested) {
		usage(argv[0]);
		return 0;
	}

	sigset_t termination_signals{};
	const auto signal_mask_status = block_termination_signals(termination_signals);
	if (!signal_mask_status.is_ok()) {
		log_startup_failure("termination-signal admission failed", signal_mask_status);
		return 1;
	}
	auto control_events_or = kinetum::dp::dp_control_event_loop::create(termination_signals);
	if (!control_events_or.is_ok()) {
		log_startup_failure("control-event admission failed", control_events_or.error());
		return 1;
	}
	auto control_events = std::move(control_events_or).value();

	auto bundle_or = kinetum::pack::verify_runtime_bundle(parsed.bundle_root);
	if (!bundle_or.is_ok()) {
		log_startup_failure("runtime-bundle admission failed", bundle_or.error());
		return 1;
	}
	auto bundle = std::move(bundle_or).value();

	const auto host_topology = kinetum::quark::probe_host();
	const auto compatibility = kinetum::quark::validate_runtime_compat(bundle.compiled_topology, host_topology);
	if (!compatibility.compatible) {
		KINETUM_LOG_ERROR("quark", "quark.runtime.incompatible", "runtime compat: {}", compatibility.summary);
		for (const auto &diagnostic : compatibility.diagnostics) {
			KINETUM_LOG_ERROR("quark", "quark.runtime.diagnostic", "{}", diagnostic);
		}
		return 1;
	}
	KINETUM_LOG_INFO("quark", "quark.runtime.compatible", "runtime compat: {}", compatibility.summary);

	const auto &transition = bundle.compiled_topology.transition_topology;
	if (!transition.lifecycle_services.has_value() ||
	    transition.lifecycle_services->coordinator_service_index >= transition.runtime_services.size()) {
		KINETUM_LOG_ERROR("dp", "dp.coordinator.missing", "compiled coordinator placement is missing");
		return 1;
	}
	const auto coordinator_cpu =
		transition.runtime_services[transition.lifecycle_services->coordinator_service_index].cpu_core_id;
	auto logging_or = kinetum::common::log_service::start(parsed.logging, "kinetum_dp", coordinator_cpu);
	if (!logging_or.is_ok()) {
		log_startup_failure("logging admission failed", logging_or.error());
		return 1;
	}
	auto logging = std::move(logging_or).value();
	auto grpc_logging_or = kinetum::common::grpc_logging::create();
	if (!grpc_logging_or.is_ok()) {
		log_startup_failure("gRPC logging admission failed", grpc_logging_or.error());
		return 1;
	}
	auto grpc_logging = std::move(grpc_logging_or).value();

	std::shared_ptr<grpc::ServerCredentials> server_credentials;
	if (parsed.tls_enabled) {
		server_credentials = kinetum::common::make_server_credentials(parsed.tls);
		if (!server_credentials) {
			KINETUM_LOG_ERROR("dp", "dp.tls.failed", "failed to configure DP server TLS credentials");
			return 1;
		}
	} else {
		server_credentials = grpc::InsecureServerCredentials();
	}
	grpc::ServerBuilder server_builder;
	server_builder.AddListeningPort(parsed.listen_addr, server_credentials);

	auto module_images_or = make_module_image_specs(bundle.module_images);
	if (!module_images_or.is_ok()) {
		log_startup_failure("module-image admission failed", module_images_or.error());
		return 1;
	}
	auto command_mailbox_or =
		kinetum::dp::epoch_transition_command_mailbox::create(bundle.compiled_topology.transition_topology);
	if (!command_mailbox_or.is_ok()) {
		log_startup_failure("coordinator command-mailbox admission failed", command_mailbox_or.error());
		return 1;
	}

	auto installation_or = kinetum::provider::current_provider_process_installation();
	if (!installation_or.is_ok()) {
		log_startup_failure("provider installation admission failed", installation_or.error());
		return 1;
	}
	const auto provider_file_policy = kinetum::provider::production_provider_file_policy(installation_or->root);
	auto admitted_or = kinetum::provider::admit_installed_provider_runtime(
		bundle.compiled_topology, installation_or->root, installation_or->runtime_image,
		kinetum::provider::provider_release_trust_anchor(), provider_file_policy);
	if (!admitted_or.is_ok()) {
		log_startup_failure("installed provider admission failed", admitted_or.error());
		return 1;
	}

	auto generation_input_or = kinetum::dp::packet_runtime_generation_input::create(
		std::move(bundle.plan), std::move(bundle.compiled_topology), std::move(command_mailbox_or).value(),
		std::move(admitted_or).value(), std::move(module_images_or).value(), uint64_t{1});
	if (!generation_input_or.is_ok()) {
		log_startup_failure("packet-runtime generation admission failed", generation_input_or.error());
		return 1;
	}
	auto runtime_or = kinetum::dp::partitioned_runtime::create(std::move(generation_input_or).value());
	if (!runtime_or.is_ok()) {
		log_startup_failure("packet-runtime materialization failed", runtime_or.error());
		return 1;
	}
	auto runtime = std::move(runtime_or).value();

	kinetum::dp::dataplane_control_service service(*runtime);
	server_builder.RegisterService(&service);
	std::unique_ptr<grpc::Server> server(server_builder.BuildAndStart());
	if (!server) {
		runtime->shutdown();
		KINETUM_LOG_ERROR("dp", "dp.server.failed", "failed to start DP gRPC server");
		return 1;
	}

	logging->startup_complete();
	KINETUM_LOG_INFO(
		"dp", "dp.control.ready",
		"dataplane server listening on {} (readiness=CONTROL_READY, bootstrap=awaiting exact CP authority)",
		parsed.listen_addr);
	int received_signal = 0;
	status control_result = status::ok();
	try {
		for (;;) {
			const auto lifecycle_descriptor = runtime->lifecycle_notification_descriptor();
			if (!lifecycle_descriptor.has_value()) {
				control_result = status::internal_error(
					"packet runtime lost lifecycle notification authority before shutdown");
				break;
			}
			auto event_or = control_events->wait(runtime->command_notification_descriptor(),
							     *lifecycle_descriptor, runtime->next_control_deadline());
			if (!event_or.is_ok()) {
				control_result = std::move(event_or).error();
				break;
			}
			if (event_or->kind == kinetum::dp::dp_control_event_kind::TERMINATE) {
				received_signal = event_or->signal_number;
				break;
			}
			status serviced = status::ok();
			switch (event_or->kind) {
			case kinetum::dp::dp_control_event_kind::COMMAND:
				serviced = runtime->service_command_notifications();
				break;
			case kinetum::dp::dp_control_event_kind::LIFECYCLE:
				serviced = runtime->service_lifecycle_notifications();
				break;
			case kinetum::dp::dp_control_event_kind::DEADLINE:
				serviced = runtime->service_control_deadline();
				break;
			case kinetum::dp::dp_control_event_kind::REOPEN_LOG:
				logging->request_reopen();
				break;
			case kinetum::dp::dp_control_event_kind::TERMINATE:
				std::terminate();
			}
			if (!serviced.is_ok()) {
				control_result = std::move(serviced);
				break;
			}
		}
	} catch (const std::bad_alloc &) {
		control_result = status::resource_exhausted(
			kinetum::common::static_status_text("dataplane control loop exhausted memory"));
	} catch (const std::length_error &) {
		control_result = status(
			kinetum::common::status_code::OUT_OF_RANGE,
			kinetum::common::static_status_text("dataplane control loop exceeded a representation bound"));
	}
	runtime->close_command_admission();
	server->Shutdown(std::chrono::system_clock::now());
	runtime->shutdown();
	server->Wait();
	if (!control_result.is_ok()) {
		log_startup_failure("dataplane control loop failed", control_result);
	}
	if (control_result.is_ok()) {
		KINETUM_LOG_INFO("dp", "dp.shutdown.complete", "dataplane shutdown complete after signal {}",
				 received_signal);
	} else {
		KINETUM_LOG_INFO("dp", "dp.shutdown.complete",
				 "dataplane shutdown complete after control-loop failure");
	}
	return control_result.is_ok() ? 0 : 1;
}
