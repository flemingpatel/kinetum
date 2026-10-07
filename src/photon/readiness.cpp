// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file readiness.cpp
 * @brief Implementation of Photon exact bounded readiness observation.
 * @author Fleming Patel
 */

#include "src/photon/readiness.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>

#include <grpcpp/grpcpp.h>

#include "src/common/dataplane_health_contract.hpp"
#include "src/common/status.hpp"

namespace kinetum::photon
{
namespace
{

/** DP health wire record admitted by the supervised startup gate. */
using health_response = kinetum::dataplane::v1::HealthResponse;
using kinetum::common::status;
using kinetum::common::status_code;

/**
 * @brief Render every known state and preserve unknown numeric wire values.
 *
 * @param state Health enum value received from protobuf.
 * @return Stable diagnostic name, including the integer for an unknown value.
 */
std::string health_state_name(health_response::State state)
{
	switch (state) {
	case health_response::STATE_UNSPECIFIED:
		return "STATE_UNSPECIFIED";
	case health_response::STATE_STARTING:
		return "STATE_STARTING";
	case health_response::STATE_CONTROL_READY:
		return "STATE_CONTROL_READY";
	case health_response::STATE_PACKET_READY:
		return "STATE_PACKET_READY";
	case health_response::STATE_DRAINING:
		return "STATE_DRAINING";
	case health_response::STATE_DRAINED:
		return "STATE_DRAINED";
	case health_response::STATE_STOPPING:
		return "STATE_STOPPING";
	case health_response::STATE_STOPPED:
		return "STATE_STOPPED";
	case health_response::STATE_ERROR:
		return "STATE_ERROR";
	case kinetum::dataplane::v1::HealthResponse_State_HealthResponse_State_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::dataplane::v1::HealthResponse_State_HealthResponse_State_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
	return "UNKNOWN_STATE(" + std::to_string(static_cast<int32_t>(state)) + ")";
}

/**
 * @brief Map one failed gRPC Health call into the common status domain.
 *
 * @param wire Failed transport status.
 * @param endpoint DP endpoint used for the call.
 * @return Common status preserving the canonical gRPC code and diagnostic.
 */
status map_grpc_failure(const grpc::Status &wire, const std::string &endpoint)
{
	const auto code = static_cast<status_code>(wire.error_code());
	return status(code, "DP Health RPC to " + endpoint + " failed: " + wire.error_message());
}

/**
 * @brief Determine whether one transport failure may be retried by readiness.
 *
 * @param value Common transport-derived status.
 * @return true only for unavailable transport or an expired per-RPC deadline.
 */
bool retryable_transport_failure(const status &value) noexcept
{
	return value.code() == status_code::UNAVAILABLE || value.code() == status_code::DEADLINE_EXCEEDED;
}

/**
 * @brief Build the canonical exact-readiness overall-deadline failure.
 *
 * @param last_observation Last transport or application observation made
 *        before the deadline was detected.
 * @return DEADLINE_EXCEEDED with the observation retained in details.
 */
status readiness_deadline_exceeded(const std::string &last_observation)
{
	auto timeout = status::deadline_exceeded("timed out waiting for exact DP readiness");
	timeout.set_details(last_observation);
	return timeout;
}

}  // namespace

status validate_readiness_wait_policy(const readiness_wait_policy &policy)
{
	if (policy.rpc_timeout.count() <= 0 || policy.poll_interval.count() <= 0 ||
	    policy.overall_timeout.count() <= 0) {
		return status::invalid_argument("readiness timing durations must all be positive");
	}
	if (policy.rpc_timeout >= policy.overall_timeout) {
		return status::invalid_argument("readiness rpc_timeout must be shorter than overall_timeout");
	}
	if (policy.poll_interval >= policy.overall_timeout) {
		return status::invalid_argument("readiness poll_interval must be shorter than overall_timeout");
	}
	return status::ok();
}

kinetum::common::status_or<readiness_progress>
classify_readiness_state(readiness_gate gate, kinetum::dataplane::v1::HealthResponse::State observed)
{
	switch (gate) {
	case readiness_gate::CONTROL:
		if (observed == health_response::STATE_STARTING) {
			return readiness_progress::WAIT;
		}
		if (observed == health_response::STATE_CONTROL_READY) {
			return readiness_progress::READY;
		}
		return status::failed_precondition("CONTROL readiness gate rejected DP state " +
						   health_state_name(observed));
	case readiness_gate::PACKET:
		if (observed == health_response::STATE_CONTROL_READY) {
			return readiness_progress::WAIT;
		}
		if (observed == health_response::STATE_PACKET_READY) {
			return readiness_progress::READY;
		}
		return status::failed_precondition("PACKET readiness gate rejected DP state " +
						   health_state_name(observed));
	default:
		return status::invalid_argument("unknown Photon readiness gate");
	}
}

grpc_dp_health_observer::grpc_dp_health_observer(std::string endpoint)
	: endpoint_(std::move(endpoint))
{
	auto channel = grpc::CreateChannel(endpoint_, grpc::InsecureChannelCredentials());
	stub_ = kinetum::dataplane::v1::DataplaneService::NewStub(channel);
}

kinetum::common::status_or<health_response> grpc_dp_health_observer::observe(std::chrono::milliseconds rpc_timeout)
{
	if (endpoint_.empty() || !stub_) {
		return status::invalid_argument("DP Health observer requires a nonempty endpoint and stub");
	}
	if (rpc_timeout.count() <= 0) {
		return status::invalid_argument("DP Health RPC timeout must be positive");
	}

	grpc::ClientContext context;
	context.set_deadline(std::chrono::system_clock::now() + rpc_timeout);
	health_response response;
	kinetum::dataplane::v1::HealthRequest request;
	const auto wire = stub_->Health(&context, request, &response);
	if (!wire.ok()) {
		return map_grpc_failure(wire, endpoint_);
	}
	return response;
}

kinetum::common::status_or<kinetum::common::dataplane_health_identity>
wait_for_exact_readiness(dp_health_observer &observer, readiness_gate gate, const readiness_wait_policy &policy,
			 const readiness_progress_check &progress_check)
{
	const auto policy_status = validate_readiness_wait_policy(policy);
	if (!policy_status.is_ok()) {
		return policy_status;
	}

	const auto deadline = std::chrono::steady_clock::now() + policy.overall_timeout;
	std::string last_observation = "no DP Health response observed";

	for (;;) {
		if (progress_check) {
			const auto progress_status = progress_check();
			if (!progress_status.is_ok()) {
				return progress_status;
			}
		}

		const auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			return readiness_deadline_exceeded(last_observation);
		}
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
		if (remaining.count() <= 0) {
			return readiness_deadline_exceeded(last_observation);
		}
		const auto rpc_timeout = std::min(policy.rpc_timeout, remaining);

		auto observed_or = observer.observe(rpc_timeout);
		// The per-RPC deadline bounds the transport, while this steady-clock
		// check remains the authority for the complete gate. A late target
		// response is not readiness evidence.
		if (std::chrono::steady_clock::now() >= deadline) {
			if (observed_or.is_ok()) {
				last_observation = "observed " + health_state_name(observed_or->state()) +
						   " after the overall readiness deadline";
			} else {
				last_observation = observed_or.error().message();
			}
			return readiness_deadline_exceeded(last_observation);
		}
		if (!observed_or.is_ok()) {
			if (!retryable_transport_failure(observed_or.error())) {
				return observed_or.error();
			}
			last_observation = observed_or.error().message();
		} else {
			const auto &observed = observed_or.value();
			auto identity_or = kinetum::common::validate_dataplane_startup_health(observed);
			if (!identity_or.is_ok()) {
				return identity_or.error();
			}
			auto classification_or = classify_readiness_state(gate, identity_or->state);
			if (!classification_or.is_ok()) {
				return classification_or.error();
			}
			if (classification_or.value() == readiness_progress::READY) {
				// Readiness and child liveness form one startup gate. Recheck
				// after the target response so an exit concurrent with the RPC
				// cannot be reported as a successful startup phase.
				if (progress_check) {
					const auto progress_status = progress_check();
					if (!progress_status.is_ok()) {
						return progress_status;
					}
				}
				if (std::chrono::steady_clock::now() >= deadline) {
					return readiness_deadline_exceeded(
						"exact target observed, but the final liveness check completed after "
						"the overall readiness deadline");
				}
				return identity_or.value();
			}
			last_observation = "observed " + health_state_name(identity_or->state);
		}

		if (progress_check) {
			const auto progress_status = progress_check();
			if (!progress_status.is_ok()) {
				return progress_status;
			}
		}

		const auto after_observation = std::chrono::steady_clock::now();
		if (after_observation >= deadline) {
			continue;
		}
		const auto sleep_budget =
			std::chrono::duration_cast<std::chrono::milliseconds>(deadline - after_observation);
		if (sleep_budget.count() > 0) {
			std::this_thread::sleep_for(std::min(policy.poll_interval, sleep_budget));
		}
	}
}

}  // namespace kinetum::photon
