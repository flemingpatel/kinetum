// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file guardrails.cpp
 * @brief Durable evidence-fenced guardrails runner implementation.
 * @author Fleming Patel
 */

#include "src/cp/guardrails.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

#include <grpcpp/grpcpp.h>

#include "gen/kinetum/control/internal/v1/transition_authority.pb.h"
#include "src/common/application_status.hpp"
#include "src/common/runtime_telemetry_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/time.hpp"
#include "src/common/transition_idempotency_key.hpp"
#include "src/cp/config_store.hpp"
#include "src/cp/control_loop.hpp"
#include "src/cp/runtime_authority_fence.hpp"

namespace kinetum::cp
{
namespace
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

/** @brief Maximum delay before the runner rechecks policy/confirm ownership. */
constexpr std::chrono::milliseconds CONTROL_SERVICE_INTERVAL{100};

/** @brief Maximum transport deadline for one telemetry observation. */
constexpr std::chrono::milliseconds MAX_STATS_RPC_TIMEOUT{5'000};

/**
 * @brief Collect one telemetry response between two durable active observations.
 * @param store Sole durable CP authority.
 * @param dataplane Generated Data Plane client.
 * @param selection Exact optional telemetry families.
 * @param timeout Positive transport deadline no greater than five seconds.
 * @return One fenced observation, or exact unavailable/contradiction failure.
 */
[[nodiscard]] status_or<guardrails_runtime_observation>
collect_fenced_observation(config_store &store, kinetum::dataplane::v1::DataplaneService::Stub &dataplane,
			   const kinetum::telemetry::v1::TelemetrySelection &selection,
			   std::chrono::milliseconds timeout)
{
	if (timeout.count() <= 0 || timeout > MAX_STATS_RPC_TIMEOUT) {
		return status::invalid_argument("guardrails stats deadline is outside its exact bound");
	}
	auto before_or = store.runtime_authority();
	if (!before_or.is_ok()) {
		return before_or.error();
	}
	kinetum::dataplane::v1::StatsRequest request;
	request.mutable_selection()->CopyFrom(selection);
	kinetum::dataplane::v1::StatsResponse response;
	grpc::ClientContext context;
	context.set_deadline(std::chrono::system_clock::now() + timeout);
	grpc::Status transport;
	try {
		transport = dataplane.GetStats(&context, request, &response);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("Data Plane telemetry call exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "Data Plane telemetry call exceeded host size limits");
	} catch (const std::exception &) {
		return status::internal_error("Data Plane telemetry call raised an exception");
	} catch (...) {
		return status::internal_error("Data Plane telemetry call raised a non-standard exception");
	}
	if (!transport.ok()) {
		status_code code{};
		if (!kinetum::common::decode_application_status_code(static_cast<int32_t>(transport.error_code()),
								     code) ||
		    static_cast<int32_t>(code) > static_cast<int32_t>(status_code::UNAUTHENTICATED)) {
			return status::data_loss("Data Plane telemetry transport returned an unknown status");
		}
		return status(code, "Data Plane telemetry transport failed");
	}
	const auto application =
		map_dataplane_application_status(response.status(), "Data Plane telemetry application failed");
	if (!application.is_ok()) {
		const auto envelope = kinetum::common::validate_failed_dataplane_stats_response(response);
		if (!envelope.is_ok()) {
			return map_dataplane_response_validation_failure(
				envelope, "Data Plane returned a malformed telemetry failure");
		}
		return application;
	}
	const auto response_status = kinetum::common::validate_successful_dataplane_stats_response(response, selection);
	if (!response_status.is_ok()) {
		return map_dataplane_response_validation_failure(response_status,
								 "Data Plane returned malformed runtime telemetry");
	}
	auto after_or = store.runtime_authority();
	if (!after_or.is_ok()) {
		return after_or.error();
	}
	if (!same_active_runtime_authority(before_or.value(), after_or.value())) {
		return status::unavailable("Control Plane active authority changed during telemetry collection");
	}
	auto relation_or = classify_runtime_authority(after_or.value(), response.telemetry());
	if (!relation_or.is_ok()) {
		return relation_or.error();
	}
	if (relation_or.value() != runtime_authority_relation::ACTIVE_EXACT) {
		return status::unavailable("Data Plane completion is awaiting durable Control Plane publication");
	}
	const bool protocol_faulted = response.telemetry().protocol_faults().transition_success_blocked();
	auto authority = std::move(after_or).value();
	return guardrails_runtime_observation{
		.active_authority = std::move(authority.active),
		.stats = std::move(response),
		.transition = std::move(authority.transition),
		.protocol_faulted = protocol_faulted,
	};
}

/**
 * @brief Test whether one private transition phase remains unresolved.
 * @param phase Candidate durable phase.
 * @return true only for one nonterminal phase.
 */
[[nodiscard]] bool nonterminal_phase(kinetum::control::internal::v1::DurableEpochTransitionPhase phase) noexcept
{
	using phase_type = kinetum::control::internal::v1::DurableEpochTransitionPhase;
	switch (phase) {
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING:
		return true;
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_UNSPECIFIED:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE:
	case phase_type::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Convert enabled policy cadence to an exact bounded transport deadline.
 * @param evaluator Configured evaluator.
 * @return Positive deadline no greater than five seconds.
 */
[[nodiscard]] std::chrono::milliseconds stats_timeout(const guardrails_evaluator &evaluator) noexcept
{
	return std::min(evaluator.poll_interval(), MAX_STATS_RPC_TIMEOUT);
}

}  // namespace

/** @brief Runner-private deterministic evaluator storage. */
struct guardrails_runner::runtime_state {
	guardrails_evaluator evaluator;	 ///< Sole policy and evidence-window owner.
};

guardrails_runner::guardrails_runner(config_store *store,
				     std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> dp_stub,
				     control_loop &loop) noexcept
	: store_(store)
	, dp_(std::move(dp_stub))
	, loop_(loop)
{
}

guardrails_runner::~guardrails_runner()
{
	stop();
}

status guardrails_runner::start()
{
	if (store_ == nullptr) {
		return status::invalid_argument("guardrails runner requires a configuration store");
	}
	if (!loop_.is_running()) {
		return status::failed_precondition("guardrails runner requires the active Control Plane writer");
	}
	bool expected = false;
	if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
		return status::ok();
	}
	try {
		if (thread_.joinable()) {
			thread_.join();
		}
		state_ = std::make_unique<runtime_state>();
		thread_ = std::thread([this]() { thread_main_(); });
		return status::ok();
	} catch (const std::bad_alloc &) {
		running_.store(false, std::memory_order_release);
		state_.reset();
		return status::resource_exhausted("guardrails runner allocation failed");
	} catch (const std::system_error &error) {
		running_.store(false, std::memory_order_release);
		state_.reset();
		return status(status_code::RESOURCE_EXHAUSTED, "guardrails worker creation failed", error.what());
	}
}

void guardrails_runner::stop() noexcept
{
	{
		std::lock_guard<std::mutex> lock(wait_mutex_);
		running_.store(false, std::memory_order_release);
	}
	wait_cv_.notify_all();
	if (thread_.joinable()) {
		thread_.join();
	}
}

void guardrails_runner::thread_main_() noexcept
{
	try {
		auto submit_intent = [&](rollback_intent_request request, int64_t created_unix_ms) {
			// An observation not yet published owns no shutdown-time action. This
			// load orders admission against stop; a subsequently published safety
			// context remains unconditional through durable completion.
			if (!running_.load(std::memory_order_acquire)) {
				return;
			}
			if (!request.idempotency_key.empty() || request.created_unix_ms != 0 || created_unix_ms < 0) {
				std::terminate();
			}
			auto key_or = kinetum::common::generate_transition_idempotency_key("kinetum-guardrails");
			if (!key_or.is_ok()) {
				std::terminate();
			}
			request.idempotency_key = std::move(key_or).value();
			request.created_unix_ms = created_unix_ms;
			const auto accepted = loop_.submit_safety_intent(std::move(request));
			if (accepted.is_ok()) {
				state_->evaluator.mark_rollback_pending();
				return;
			}
			if (accepted.code() != status_code::FAILED_PRECONDITION &&
			    accepted.code() != status_code::RESOURCE_EXHAUSTED &&
			    !(accepted.code() == status_code::UNAVAILABLE &&
			      !running_.load(std::memory_order_acquire))) {
				std::terminate();
			}
		};

		auto check_confirm_deadline = [&]() {
			auto pending_or = store_->load_pending_confirm();
			if (!pending_or.is_ok()) {
				if (pending_or.error().code() != status_code::NOT_FOUND) {
					std::terminate();
				}
				return false;
			}
			if (pending_or->confirmed()) {
				return false;
			}
			const int64_t observed_unix_ms = kinetum::common::unix_time_ms();
			const bool clock_regressed = observed_unix_ms < pending_or->created_unix_ms();
			if (!clock_regressed && observed_unix_ms < pending_or->deadline_unix_ms()) {
				return false;
			}
			// A backward wall-clock step cannot manufacture a fresh confirmation
			// interval. The already-durable deadline is the conservative audit
			// projection when the current wall sample precedes creation.
			const int64_t intent_created_unix_ms = clock_regressed ? pending_or->deadline_unix_ms() :
										 observed_unix_ms;
			auto retained_intent_or = store_->rollback_intent();
			if (retained_intent_or.is_ok()) {
				state_->evaluator.mark_rollback_pending();
				return true;
			}
			if (retained_intent_or.error().code() != status_code::NOT_FOUND) {
				std::terminate();
			}
			if (dp_ == nullptr) {
				return true;
			}
			kinetum::telemetry::v1::TelemetrySelection selection;
			auto observation_or =
				collect_fenced_observation(*store_, *dp_, selection, MAX_STATS_RPC_TIMEOUT);
			if (!observation_or.is_ok() ||
			    observation_or->active_authority.snapshot_id != pending_or->snapshot_id() ||
			    observation_or->active_authority.active_epoch != pending_or->epoch() ||
			    observation_or->active_authority.revision != pending_or->revision()) {
				return true;
			}
			uint64_t wait_sequence = 0u;
			if (observation_or->transition.has_value() &&
			    nonterminal_phase(observation_or->transition->phase)) {
				wait_sequence = observation_or->transition->identity.mutation_sequence;
			}
			rollback_intent_request request;
			request.target_snapshot_id = pending_or->rollback_snapshot_id();
			request.guarded_snapshot_id = pending_or->snapshot_id();
			request.guarded_epoch = pending_or->epoch();
			request.guarded_revision = pending_or->revision();
			request.guarded_validation_hash = observation_or->active_authority.active_validation_hash;
			request.wait_for_mutation_sequence = wait_sequence;
			request.runtime_generation = observation_or->stats.telemetry().runtime().runtime_generation();
			request.cause = rollback_intent_cause::COMMIT_CONFIRM_DEADLINE;
			request.observed_monotonic_ns =
				observation_or->stats.telemetry().runtime().collection_monotonic_ns();
			submit_intent(std::move(request), intent_created_unix_ms);
			return true;
		};

		auto next_telemetry = std::chrono::steady_clock::now();
		while (running_.load(std::memory_order_acquire)) {
			const bool confirmation_due = check_confirm_deadline();
			if (confirmation_due) {
				state_->evaluator.pause_observation();
			}

			const auto &published = loop_.guardrails_state().policy;
			if (published.has_value() && published.version() != state_->evaluator.policy_generation()) {
				auto policy = published.borrow();
				const auto applied = state_->evaluator.apply_policy(policy.get(), policy.epoch());
				if (!applied.is_ok()) {
					std::terminate();
				}
				next_telemetry = std::chrono::steady_clock::now();
			} else if (!published.has_value() && state_->evaluator.policy_generation() != 0u) {
				std::terminate();
			}

			auto retained_intent_or = store_->rollback_intent();
			if (retained_intent_or.is_ok()) {
				state_->evaluator.mark_rollback_pending();
			} else if (retained_intent_or.error().code() == status_code::NOT_FOUND) {
				if (state_->evaluator.state() == guardrails_evaluator_state::ROLLBACK_PENDING) {
					state_->evaluator.resume_after_intent();
					next_telemetry = std::chrono::steady_clock::now();
				}
			} else {
				std::terminate();
			}

			const auto now = std::chrono::steady_clock::now();
			if (state_->evaluator.enabled() &&
			    state_->evaluator.state() != guardrails_evaluator_state::ROLLBACK_PENDING &&
			    !confirmation_due && dp_ != nullptr && now >= next_telemetry) {
				kinetum::telemetry::v1::TelemetrySelection selection;
				selection.set_include_module_health(state_->evaluator.requires_module_health());
				selection.set_include_boundary_epoch_stats(state_->evaluator.requires_boundary_rows());
				auto observation_or = collect_fenced_observation(*store_, *dp_, selection,
										 stats_timeout(state_->evaluator));
				if (observation_or.is_ok()) {
					auto decision_or = state_->evaluator.observe(observation_or.value());
					if (!decision_or.is_ok()) {
						std::terminate();
					}
					auto decision = std::move(decision_or).value();
					if (decision.has_value()) {
						submit_intent(std::move(decision).value(),
							      kinetum::common::unix_time_ms());
					}
				} else {
					state_->evaluator.pause_observation();
				}
				next_telemetry = std::chrono::steady_clock::now() + state_->evaluator.poll_interval();
			}

			auto wake_deadline = std::chrono::steady_clock::now() + CONTROL_SERVICE_INTERVAL;
			if (state_->evaluator.enabled() && next_telemetry < wake_deadline) {
				wake_deadline = next_telemetry;
			}
			std::unique_lock<std::mutex> lock(wait_mutex_);
			wait_cv_.wait_until(lock, wake_deadline,
					    [this]() { return !running_.load(std::memory_order_acquire); });
		}
	} catch (const std::exception &) {
		std::terminate();
	} catch (...) {
		std::terminate();
	}
	running_.store(false, std::memory_order_release);
}

}  // namespace kinetum::cp
