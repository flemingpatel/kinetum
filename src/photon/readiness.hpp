// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file readiness.hpp
 * @brief Exact bounded Data Plane readiness observation for Photon startup.
 * @author Fleming Patel
 *
 * Photon uses two ordered readiness gates. A newly spawned DP must report
 * exactly CONTROL_READY before CP starts, and must later report exactly
 * PACKET_READY before ordinary supervision begins. Elapsed time,
 * channel connectivity, and a numerically later enum value are never readiness
 * evidence.
 *
 * The observer is a cold-path interface. Its virtual dispatch, protobuf
 * messages, gRPC calls, strings, and sleeps are prohibited from packet workers.
 *
 * @par Thread Safety
 * A readiness wait and its observer have one startup-thread owner. Distinct
 * observers may run concurrently. A progress callback may safely inspect
 * atomics or independently synchronized child state.
 */

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "src/common/dataplane_health_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::photon
{

/** @brief Maximum duration of one DP Health RPC attempt. */
inline constexpr std::chrono::milliseconds READINESS_RPC_TIMEOUT{250};

/** @brief Delay between incomplete or transient readiness observations. */
inline constexpr std::chrono::milliseconds READINESS_POLL_INTERVAL{100};

/** @brief Overall deadline for newly spawned DP control readiness. */
inline constexpr std::chrono::milliseconds CONTROL_READY_TIMEOUT{30'000};

/** @brief Overall deadline for exact bootstrap and packet readiness. */
inline constexpr std::chrono::milliseconds PACKET_READY_TIMEOUT{60'000};

static_assert(READINESS_RPC_TIMEOUT.count() > 0, "readiness RPC timeout must be positive");
static_assert(READINESS_POLL_INTERVAL.count() > 0, "readiness poll interval must be positive");
static_assert(READINESS_RPC_TIMEOUT < CONTROL_READY_TIMEOUT,
	      "readiness RPC timeout must be shorter than the CONTROL_READY deadline");
static_assert(READINESS_POLL_INTERVAL < CONTROL_READY_TIMEOUT,
	      "readiness poll interval must be shorter than the CONTROL_READY deadline");
static_assert(READINESS_RPC_TIMEOUT < PACKET_READY_TIMEOUT,
	      "readiness RPC timeout must be shorter than the PACKET_READY deadline");
static_assert(READINESS_POLL_INTERVAL < PACKET_READY_TIMEOUT,
	      "readiness poll interval must be shorter than the PACKET_READY deadline");

/**
 * @brief Ordered DP readiness gate owned by Photon startup.
 */
enum class readiness_gate : uint8_t {
	CONTROL,  ///< Wait for exact CONTROL_READY before CP construction.
	PACKET,	  ///< Wait for exact PACKET_READY before packet supervision.
};

/**
 * @brief Result of classifying one valid application-level Health response.
 */
enum class readiness_progress : uint8_t {
	WAIT,	///< The sole declared pre-state was observed; poll again.
	READY,	///< The exact gate state was observed.
};

/**
 * @brief Coherent timing policy for one exact readiness gate.
 *
 * Every duration is positive. `rpc_timeout` and `poll_interval` must each be
 * strictly shorter than `overall_timeout` so no individual action can consume
 * the complete startup budget.
 */
struct readiness_wait_policy {
	std::chrono::milliseconds rpc_timeout;	    ///< Deadline applied to each Health RPC.
	std::chrono::milliseconds poll_interval;    ///< Delay between retryable observations.
	std::chrono::milliseconds overall_timeout;  ///< Steady-clock deadline for the complete gate.
};

/** @brief Production policy for the first exact readiness gate. */
inline constexpr readiness_wait_policy CONTROL_READY_WAIT_POLICY{
	READINESS_RPC_TIMEOUT,
	READINESS_POLL_INTERVAL,
	CONTROL_READY_TIMEOUT,
};

/** @brief Production policy for the second exact readiness gate. */
inline constexpr readiness_wait_policy PACKET_READY_WAIT_POLICY{
	READINESS_RPC_TIMEOUT,
	READINESS_POLL_INTERVAL,
	PACKET_READY_TIMEOUT,
};

/**
 * @brief Validate one complete readiness timing policy.
 *
 * @param policy Candidate timing relations.
 * @return OK when all durations are positive and each individual operation is
 *         shorter than the overall timeout; INVALID_ARGUMENT otherwise.
 *
 * @par Thread Safety
 * Pure function with no shared state.
 */
[[nodiscard]] kinetum::common::status validate_readiness_wait_policy(const readiness_wait_policy &policy);

/**
 * @brief Classify one exact DP Health state for an ordered startup gate.
 *
 * Gate one retries only STARTING and accepts only CONTROL_READY. Gate two
 * retries only CONTROL_READY and accepts only PACKET_READY. Every other known
 * state, an unknown future enum value, a skipped phase, or a regression is an
 * immediate FAILED_PRECONDITION result.
 *
 * @param gate Ordered readiness gate currently owned by Photon.
 * @param observed Exact Health state received from DP.
 * @return WAIT for the gate's sole declared pre-state, READY for its exact
 *         target, or FAILED_PRECONDITION for every other value.
 *
 * @par Thread Safety
 * Pure function with no shared state.
 */
[[nodiscard]] kinetum::common::status_or<readiness_progress>
classify_readiness_state(readiness_gate gate, kinetum::dataplane::v1::HealthResponse::State observed);

/**
 * @brief Abstract one bounded DP Health observation.
 *
 * Test observers may return deterministic responses without a socket. The
 * production implementation performs one unary gRPC call with the supplied
 * deadline.
 */
class dp_health_observer {
    public:
	/** @brief Release observer-owned transport resources. */
	virtual ~dp_health_observer() = default;

	/**
	 * @brief Observe one DP Health response.
	 *
	 * @param rpc_timeout Positive per-call deadline.
	 * @return Complete Health response, or a transport-derived status.
	 */
	[[nodiscard]] virtual kinetum::common::status_or<kinetum::dataplane::v1::HealthResponse>
	observe(std::chrono::milliseconds rpc_timeout) = 0;
};

/**
 * @brief Production unary-gRPC DP Health observer.
 *
 * One startup thread owns the generated stub. Each call creates a fresh
 * ClientContext because gRPC contexts are single-use.
 */
class grpc_dp_health_observer final : public dp_health_observer {
    public:
	/**
	 * @brief Construct an insecure local-process Health client.
	 *
	 * @param endpoint Nonempty DP endpoint used by Photon and CP.
	 */
	explicit grpc_dp_health_observer(std::string endpoint);

	/**
	 * @brief Perform one bounded unary Health RPC.
	 *
	 * @param rpc_timeout Positive per-call deadline.
	 * @return Complete response on wire success, or a mapped transport status.
	 */
	[[nodiscard]] kinetum::common::status_or<kinetum::dataplane::v1::HealthResponse>
	observe(std::chrono::milliseconds rpc_timeout) override;

    private:
	std::string endpoint_;	///< Stable endpoint retained for diagnostics.
	std::unique_ptr<kinetum::dataplane::v1::DataplaneService::Stub> stub_;	///< Single-owner generated client.
};

/**
 * @brief Callback that verifies startup may continue before and after an RPC.
 *
 * Returning an error cancels the wait immediately. Photon uses this hook to
 * observe shutdown intent and reap any DP/CP child that exits during startup.
 */
using readiness_progress_check = std::function<kinetum::common::status()>;

/**
 * @brief Wait for one exact DP readiness state under a bounded policy.
 *
 * Only transport UNAVAILABLE/DEADLINE_EXCEEDED and the gate's declared
 * pre-state are retried. Application-level Health errors, unknown states,
 * terminal states, skipped phases, regressions, and progress-check failures are
 * terminal. The overall deadline uses `steady_clock`; each gRPC attempt is
 * capped to the remaining budget.
 *
 * @param observer Single-owner Health observation source.
 * @param gate Exact ordered gate to satisfy.
 * @param policy Coherent per-RPC, polling, and overall timing policy.
 * @param progress_check Optional child-liveness/cancellation check. An empty
 *        callback means no external cancellation source.
 * @return Exact target readiness identity, or the first terminal,
 *         cancellation, liveness, policy, or DEADLINE_EXCEEDED result.
 *
 * @par Thread Safety
 * One startup thread owns the wait and observer. The callback owns any
 * synchronization needed for state it reads.
 *
 * @par Performance
 * Cold startup path. This function performs gRPC, protobuf, string, and sleep
 * operations and must never execute on a packet worker.
 */
[[nodiscard]] kinetum::common::status_or<kinetum::common::dataplane_health_identity>
wait_for_exact_readiness(dp_health_observer &observer, readiness_gate gate, const readiness_wait_policy &policy,
			 const readiness_progress_check &progress_check = {});

}  // namespace kinetum::photon
