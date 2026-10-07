// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dataplane_bootstrap.cpp
 * @brief Implementation of exact Control Plane Data Plane bootstrap or rejoin.
 * @author Fleming Patel
 */

#include "src/cp/dataplane_bootstrap.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <exception>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <grpcpp/grpcpp.h>

#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/application_status.hpp"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/dataplane_health_contract.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_telemetry_contract.hpp"
#include "src/common/status.hpp"
#include "src/cp/config_store.hpp"
#include "src/cp/runtime_authority_fence.hpp"

namespace kinetum::cp
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

namespace
{

/** @brief Maximum untrusted diagnostic bytes retained from a DP response. */
constexpr std::size_t MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES = 512u;

/** @brief Observation cadence inside the bounded startup reconciliation window. */
constexpr std::chrono::milliseconds STARTUP_OBSERVATION_INTERVAL{10};

/** @brief Maximum transport deadline assigned to one read-only startup probe. */
constexpr std::chrono::seconds STARTUP_PROBE_RPC_TIMEOUT{5};

/**
 * @brief Classify one read-only startup observation failure as retryable.
 * @param failure Exact Health or Stats failure.
 * @return true only for UNAVAILABLE or DEADLINE_EXCEEDED.
 */
[[nodiscard]] bool transient_startup_observation(const status &failure) noexcept
{
	return failure.code() == status_code::UNAVAILABLE || failure.code() == status_code::DEADLINE_EXCEEDED;
}

/**
 * @brief Bound one untrusted remote diagnostic before retaining it.
 *
 * @param message Candidate Data Plane or transport diagnostic.
 * @return At most MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES bytes.
 */
std::string bounded_remote_diagnostic(std::string_view message)
{
	return std::string(message.substr(0, MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES));
}

/**
 * @brief Convert one failed gRPC call into its exact bounded startup failure.
 *
 * @param transport Failed transport result.
 * @param operation Fixed operation-specific failure diagnostic.
 * @return Declared canonical transport category with bounded remote details.
 */
status transport_failure(const grpc::Status &transport, std::string_view operation) noexcept
{
	status_code code{};
	if (transport.ok() || operation.empty() ||
	    !kinetum::common::decode_application_status_code(static_cast<int32_t>(transport.error_code()), code) ||
	    code == status_code::OK) {
		code = status_code::UNKNOWN;
	}
	try {
		status failure(code, std::string(operation));
		failure.set_details(bounded_remote_diagnostic(transport.error_message()));
		return failure;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(
			kinetum::common::static_status_text("Data Plane transport diagnostic exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "Data Plane transport diagnostic exceeded host size limits"));
	}
}

/**
 * @brief Validate every successful bootstrap response field against its request.
 *
 * @param request Fully re-admitted durable request.
 * @param canonical_request Canonical nested snapshot and request identities.
 * @param response Candidate successful wire response.
 * @return OK only for one exact COMPLETE echo.
 */
status validate_success_response(const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &request,
				 const kinetum::common::validated_bootstrap_config_snapshot &canonical_request,
				 const kinetum::dataplane::v1::BootstrapConfigSnapshotResponse &response)
{
	const auto unknown_status =
		kinetum::common::reject_unknown_protobuf_fields_recursive(response, "BootstrapConfigSnapshotResponse");
	if (!unknown_status.is_ok()) {
		return map_dataplane_response_validation_failure(unknown_status,
								 "Data Plane returned malformed Bootstrap response");
	}
	const auto enum_status = kinetum::common::reject_invalid_protobuf_enum_values_recursive(
		response, "BootstrapConfigSnapshotResponse");
	if (!enum_status.is_ok()) {
		return map_dataplane_response_validation_failure(enum_status,
								 "Data Plane returned malformed Bootstrap response");
	}

	const auto application = map_dataplane_application_status(
		response.status(), "Data Plane rejected the durable fixed-epoch bootstrap");
	if (!application.is_ok()) {
		return application;
	}

	const auto &expected_hash = canonical_request.snapshot.validation_hash;
	const bool exact_hash =
		response.validation_hash().size() == expected_hash.size() &&
		std::equal(expected_hash.begin(), expected_hash.end(), response.validation_hash().begin(),
			   [](uint8_t expected, char observed) { return expected == static_cast<uint8_t>(observed); });
	if (response.restored_epoch() != request.active_epoch() || !exact_hash ||
	    response.transition_state() != kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_COMPLETE ||
	    response.allocated_epoch_high_watermark() != request.allocated_epoch_high_watermark() ||
	    response.mutation_sequence_high_watermark() != request.mutation_sequence_high_watermark()) {
		return status::data_loss("Data Plane bootstrap response does not exactly echo durable authority");
	}
	return status::ok();
}

/**
 * @brief Read and validate one Data Plane readiness observation.
 * @param dataplane Generated Data Plane client.
 * @param timeout Positive per-attempt transport deadline.
 * @return Exact declared readiness or retryable/terminal failure.
 */
status_or<kinetum::common::dataplane_health_identity>
read_health(kinetum::dataplane::v1::DataplaneService::Stub &dataplane, std::chrono::milliseconds timeout)
{
	grpc::ClientContext context;
	context.set_deadline(std::chrono::system_clock::now() + timeout);
	kinetum::dataplane::v1::HealthRequest request;
	kinetum::dataplane::v1::HealthResponse response;
	grpc::Status transport;
	try {
		transport = dataplane.Health(&context, request, &response);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane Health observation exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane Health observation exceeded host size limits");
	} catch (const std::exception &) {
		return status::internal_error("Data Plane Health call raised an exception");
	} catch (...) {
		return status::internal_error("Data Plane Health call raised a non-standard exception");
	}
	if (!transport.ok()) {
		return transport_failure(transport, "Data Plane Health transport did not complete");
	}
	auto identity_or = kinetum::common::validate_dataplane_startup_health(response);
	if (identity_or.is_ok() && identity_or->state == kinetum::dataplane::v1::HealthResponse::STATE_STARTING) {
		return status::unavailable("Data Plane is still starting");
	}
	return identity_or;
}

/**
 * @brief Validate packet-ready DP content against the durable CP authority.
 * @param store Sole durable CP authority.
 * @param dataplane Generated Data Plane client.
 * @param timeout Positive per-attempt transport deadline.
 * @param health Coherent Health identity sampled before this telemetry call.
 * @return OK only for exact epoch, content, plan, watermarks, and generation truth.
 */
status validate_packet_ready_content(config_store &store, kinetum::dataplane::v1::DataplaneService::Stub &dataplane,
				     std::chrono::milliseconds timeout,
				     const kinetum::common::dataplane_health_identity &health)
{
	auto authority_or = store.runtime_authority();
	if (!authority_or.is_ok()) {
		return authority_or.error().code() == status_code::NOT_FOUND ?
			       status::data_loss("packet-ready Data Plane has no durable Control Plane authority") :
			       authority_or.error();
	}
	grpc::ClientContext context;
	context.set_deadline(std::chrono::system_clock::now() + timeout);
	kinetum::dataplane::v1::StatsRequest request;
	request.mutable_selection();
	kinetum::dataplane::v1::StatsResponse response;
	grpc::Status transport;
	try {
		transport = dataplane.GetStats(&context, request, &response);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane startup telemetry exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane startup telemetry exceeded host size limits");
	} catch (const std::exception &) {
		return status::internal_error("Data Plane startup telemetry call raised an exception");
	} catch (...) {
		return status::internal_error("Data Plane startup telemetry call raised a non-standard exception");
	}
	if (!transport.ok()) {
		return transport_failure(transport, "Data Plane startup telemetry transport did not complete");
	}
	const auto application =
		map_dataplane_application_status(response.status(), "Data Plane startup telemetry application failed");
	if (!application.is_ok()) {
		const auto envelope = kinetum::common::validate_failed_dataplane_stats_response(response);
		if (!envelope.is_ok()) {
			return map_dataplane_response_validation_failure(
				envelope, "Data Plane returned a malformed startup telemetry failure");
		}
		return application;
	}
	const auto telemetry_status =
		kinetum::common::validate_successful_dataplane_stats_response(response, request.selection());
	if (!telemetry_status.is_ok()) {
		return map_dataplane_response_validation_failure(telemetry_status,
								 "Data Plane returned malformed runtime telemetry");
	}
	const auto &runtime = response.telemetry().runtime();
	if (runtime.runtime_generation() != health.runtime_generation ||
	    runtime.active_workers() != health.active_workers ||
	    runtime.expected_workers() != health.expected_workers) {
		return status::data_loss("Data Plane Health and telemetry runtime identities disagree");
	}
	if (runtime.active_epoch() < health.active_epoch) {
		return status::data_loss("Data Plane active epoch regressed between Health and telemetry");
	}
	if (runtime.active_epoch() > health.active_epoch) {
		return status::unavailable("Data Plane active epoch changed between Health and telemetry");
	}
	auto relation_or = classify_runtime_authority(authority_or.value(), response.telemetry());
	return relation_or.is_ok() ? status::ok() : relation_or.error();
}

/**
 * @brief Wait until one bounded read-only startup retry point.
 * @param deadline Overall steady startup deadline.
 */
void wait_for_startup_probe(std::chrono::steady_clock::time_point deadline)
{
	const auto wake = std::min(deadline, std::chrono::steady_clock::now() + STARTUP_OBSERVATION_INTERVAL);
	std::this_thread::sleep_until(wake);
}

}  // namespace

status_or<dataplane_bootstrap_outcome>
bootstrap_dataplane_from_store(config_store &store, kinetum::dataplane::v1::DataplaneService::Stub &dataplane,
			       const bootstrap_startup_authority *bootstrap_authority,
			       std::chrono::steady_clock::time_point startup_deadline)
{
	const auto startup_started = std::chrono::steady_clock::now();
	if (startup_deadline <= startup_started) {
		return status::deadline_exceeded("Data Plane startup deadline expired before readiness observation");
	}
	if (startup_deadline - startup_started > DATAPLANE_STARTUP_RECONCILIATION_TIMEOUT) {
		return status::invalid_argument("Data Plane startup deadline exceeds the production bound");
	}
	status last_readiness_failure = status::unavailable("Data Plane readiness has not been observed");
	auto readiness_or = [&]() -> status_or<kinetum::common::dataplane_health_identity> {
		while (std::chrono::steady_clock::now() < startup_deadline) {
			const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
				startup_deadline - std::chrono::steady_clock::now());
			if (remaining.count() <= 0) {
				break;
			}
			auto attempt_or = read_health(
				dataplane, std::min(remaining, std::chrono::duration_cast<std::chrono::milliseconds>(
								       STARTUP_PROBE_RPC_TIMEOUT)));
			if (attempt_or.is_ok()) {
				return std::move(attempt_or).value();
			}
			if (!transient_startup_observation(attempt_or.error())) {
				return std::move(attempt_or).error();
			}
			last_readiness_failure = std::move(attempt_or).error();
			wait_for_startup_probe(startup_deadline);
		}
		if (transient_startup_observation(last_readiness_failure) &&
		    std::chrono::steady_clock::now() >= startup_deadline) {
			return status::deadline_exceeded("Data Plane startup readiness deadline expired");
		}
		return std::move(last_readiness_failure);
	}();
	if (!readiness_or.is_ok()) {
		return readiness_or.error();
	}

	const bool packet_ready = readiness_or->state == kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY;
	if (packet_ready) {
		// A source admitted by this process is desired input, not evidence that it
		// owns an already-running Data Plane. Require durable authority that
		// predated this first DP observation before any source import can occur.
		auto existing_or = store.active_snapshot_id();
		if (!existing_or.is_ok()) {
			return existing_or.error().code() == status_code::NOT_FOUND ?
				       status::data_loss(
					       "packet-ready Data Plane has no preexisting durable Control Plane authority") :
				       existing_or.error();
		}
	}

	const auto reconcile_status = store.reconcile_bootstrap(bootstrap_authority);
	if (!reconcile_status.is_ok()) {
		return reconcile_status;
	}

	if (packet_ready) {
		auto last_packet_health = readiness_or.value();
		for (;;) {
			auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
				startup_deadline - std::chrono::steady_clock::now());
			if (remaining.count() <= 0) {
				return status::deadline_exceeded("Data Plane startup telemetry deadline expired");
			}
			auto refreshed_health_or = read_health(
				dataplane, std::min(remaining, std::chrono::duration_cast<std::chrono::milliseconds>(
								       STARTUP_PROBE_RPC_TIMEOUT)));
			if (!refreshed_health_or.is_ok()) {
				if (!transient_startup_observation(refreshed_health_or.error())) {
					return refreshed_health_or.error();
				}
				wait_for_startup_probe(startup_deadline);
				continue;
			}
			if (refreshed_health_or->state != kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY) {
				return status::failed_precondition(
					"Data Plane regressed from PACKET_READY during startup reconciliation");
			}
			if (refreshed_health_or->runtime_generation != last_packet_health.runtime_generation ||
			    refreshed_health_or->expected_workers != last_packet_health.expected_workers ||
			    refreshed_health_or->active_epoch < last_packet_health.active_epoch) {
				return status::data_loss(
					"Data Plane Health identity regressed during startup reconciliation");
			}
			last_packet_health = refreshed_health_or.value();
			remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
				startup_deadline - std::chrono::steady_clock::now());
			if (remaining.count() <= 0) {
				return status::deadline_exceeded("Data Plane startup telemetry deadline expired");
			}
			const auto observed = validate_packet_ready_content(
				store, dataplane,
				std::min(remaining, std::chrono::duration_cast<std::chrono::milliseconds>(
							    STARTUP_PROBE_RPC_TIMEOUT)),
				refreshed_health_or.value());
			if (observed.is_ok()) {
				return dataplane_bootstrap_outcome::PACKET_READY_REJOINED;
			}
			if (!transient_startup_observation(observed)) {
				return observed;
			}
			wait_for_startup_probe(startup_deadline);
		}
	}

	auto request_or = store.active_bootstrap();
	if (!request_or.is_ok()) {
		if (request_or.error().code() == status_code::NOT_FOUND) {
			return dataplane_bootstrap_outcome::CONTROL_ONLY;
		}
		return request_or.error();
	}
	auto request = std::move(request_or).value();
	auto canonical_or = kinetum::common::validate_bootstrap_config_snapshot_request(request);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}

	grpc::ClientContext context;
	const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(startup_deadline -
										     std::chrono::steady_clock::now());
	if (remaining.count() <= 0) {
		return status::deadline_exceeded("Data Plane bootstrap startup deadline expired");
	}
	context.set_deadline(std::chrono::system_clock::now() + remaining);
	kinetum::dataplane::v1::BootstrapConfigSnapshotResponse response;
	grpc::Status transport;
	try {
		transport = dataplane.BootstrapConfigSnapshot(&context, request, &response);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane bootstrap call exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane bootstrap call exceeded host size limits");
	} catch (const std::exception &) {
		return status::internal_error("Data Plane bootstrap call raised an exception");
	} catch (...) {
		return status::internal_error("Data Plane bootstrap call raised a non-standard exception");
	}
	if (!transport.ok()) {
		return transport_failure(transport, "Data Plane bootstrap transport did not complete");
	}

	const auto response_status = validate_success_response(request, canonical_or.value(), response);
	if (!response_status.is_ok()) {
		return response_status;
	}
	const auto orphan_status = store.discard_orphaned_epoch_transition_after_bootstrap();
	if (!orphan_status.is_ok()) {
		return status(orphan_status.code(),
			      "Data Plane bootstrap succeeded but orphaned transition publication failed",
			      std::string(orphan_status.message()));
	}
	return dataplane_bootstrap_outcome::PACKET_READY;
}

}  // namespace kinetum::cp
