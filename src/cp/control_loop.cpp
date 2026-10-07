// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file control_loop.cpp
 * @brief Implement the bounded single-writer Control Plane mutation owner.
 * @author Fleming Patel
 *
 * This file implements the control_loop class, which transfers complete
 * mutation contexts through a fixed-capacity mailbox and serializes semantic
 * state changes on one worker thread.
 *
 * @par Key Implementation Details
 *
 * **Worker Thread**: A dedicated thread consumes the 64-cell pointer mailbox.
 * Callers block on a future until their mutation completes, while a full
 * mailbox rejects before semantic mutation.
 *
 * **Idempotency Ownership**: Every retry-sensitive mutation resolves through
 * the one durable transition authority; no volatile success cache exists.
 *
 * **CAS Revision Check**: Mutations with a present expected revision fail if
 * the current revision differs, including an exact comparison against zero.
 *
 * **Durable Transition Allocation**: Component-started mutation paths use the
 * atomic config-store authority to canonicalize, stage, allocate, prepare,
 * commit, and publish exact terminal state. Production starts the mutation
 * worker only after DP PACKET_READY.
 *
 * @see control_loop.hpp for the public interface
 * @see docs/PLATFORM_ENGINEERING_GUIDE.md Deterministic control loop for design rationale
 *
 */

#include "src/cp/control_loop.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "gen/kinetum/control/internal/v1/transition_authority.pb.h"
#include "src/common/application_status.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/generated_snapshot_identity.hpp"
#include "src/common/log.hpp"
#include "src/common/sha256.hpp"
#include "src/common/time.hpp"
#include "src/common/transition_idempotency_key.hpp"
#include "src/cp/dataplane_bootstrap.hpp"
#include "src/cp/dataplane_transition_client.hpp"
#include "src/cp/guardrails_policy.hpp"
#include "src/cp/transition_reconciliation.hpp"

namespace kinetum::cp
{

static_assert(std::is_nothrow_move_constructible_v<cp_published_state> &&
		      std::is_nothrow_move_assignable_v<cp_published_state>,
	      "Control Plane publication requires a nonthrowing ownership handoff");
static_assert(std::is_nothrow_move_constructible_v<kinetum::control::v1::GuardrailsPolicy> &&
		      std::is_nothrow_move_assignable_v<kinetum::control::v1::GuardrailsPolicy>,
	      "guardrails publication requires a nonthrowing protobuf ownership handoff");

namespace
{

/**
 * @brief Record one failed cold transition attempt without inferring DP rollback.
 * @param snapshot Requested content identity, borrowed for this emission.
 * @param transition Exact retained CP allocation and durable phase.
 * @param failure Unchanged operation status and diagnostic.
 */
void log_transition_failure(std::string_view snapshot, const durable_epoch_transition_view &transition,
			    const common::status &failure) noexcept
{
	KINETUM_LOG_ERROR(
		"cp", "cp.transition.failed",
		"snapshot={} mutation_sequence={} target_epoch={} cp_phase={} status={} reason={} details={}", snapshot,
		transition.identity.mutation_sequence, transition.identity.target_epoch,
		std::string_view(kinetum::control::internal::v1::DurableEpochTransitionPhase_Name(transition.phase))
			.substr(sizeof("DURABLE_EPOCH_TRANSITION_PHASE_") - 1u),
		common::status_code_name(failure.code()), failure.message(), failure.details());
}

/**
 * @brief Record a transport outage, ambiguous reply, or recovered observation.
 * @param level Exact event severity.
 * @param event Stable transport-event identity selected by the control owner.
 * @param identity Retained allocation used to correlate the outcome query.
 * @param result Exact transport observation; success is transport recovery only.
 */
void log_transition_transport(common::log_level level, std::string_view event,
			      const common::epoch_transition_identity &identity, const common::status &result) noexcept
{
	KINETUM_LOG(level, "cp", event, "mutation_sequence={} target_epoch={} status={} reason={}",
		    identity.mutation_sequence, identity.target_epoch, common::status_code_name(result.code()),
		    result.message());
}

/**
 * @brief Return the canonical candidate retained by one exact retry key.
 *
 * Generated rollback metadata must be reconstructed byte-identically after a
 * retry or CP restart. The durable transition, not a second clock read, owns
 * those generated fields once allocation succeeds.
 *
 * @param store Sole durable transition authority.
 * @param idempotency_key Candidate caller retry identity.
 * @return Retained canonical candidate for the same key, nullopt for absence or
 *         another key, or the store failure.
 */
[[nodiscard]] kinetum::common::status_or<std::optional<kinetum::control::v1::ConfigSnapshot>>
retained_candidate_for_key(config_store &store, std::string_view idempotency_key)
{
	try {
		auto retained_or = store.epoch_transition();
		if (!retained_or.is_ok()) {
			if (retained_or.error().code() == kinetum::common::status_code::NOT_FOUND) {
				return std::optional<kinetum::control::v1::ConfigSnapshot>{};
			}
			return retained_or.error();
		}
		if (retained_or->prepare_request.idempotency_key() != idempotency_key) {
			return std::optional<kinetum::control::v1::ConfigSnapshot>{};
		}
		return std::optional<kinetum::control::v1::ConfigSnapshot>{retained_or->prepare_request.snapshot()};
	} catch (const std::bad_alloc &) {
		return kinetum::common::status::resource_exhausted("retained transition retry copy exhausted memory");
	}
}

/**
 * @brief Allocate one generated snapshot revision without signed overflow.
 * @param current_revision Current active CP revision.
 * @param content_revision Revision carried by the source snapshot.
 * @return One greater than both values, or RESOURCE_EXHAUSTED at the shared maximum.
 */
[[nodiscard]] kinetum::common::status_or<int64_t> next_generated_revision(int64_t current_revision,
									  int64_t content_revision)
{
	if (!kinetum::common::valid_config_snapshot_revision(current_revision) ||
	    !kinetum::common::valid_config_snapshot_revision(content_revision)) {
		return kinetum::common::status::invalid_argument("generated snapshot revision source is invalid");
	}
	const int64_t base = std::max(current_revision, content_revision);
	if (base >= kinetum::common::MAX_CONFIG_SNAPSHOT_REVISION) {
		return kinetum::common::status::resource_exhausted("generated snapshot revision is exhausted");
	}
	return base + 1;
}

/**
 * @brief Identify payloads backed by one durable DP transition key.
 * @param payload Construction-fixed operation identity.
 * @return true only for SetConfig and Rollback.
 */
[[nodiscard]] bool uses_snapshot_transition_identity(const mutation_payload &payload) noexcept
{
	return std::visit(
		[](const auto &value) noexcept {
			using payload_type = std::remove_cvref_t<decltype(value)>;
			if constexpr (std::is_same_v<payload_type, set_config_payload> ||
				      std::is_same_v<payload_type, rollback_payload>) {
				return true;
			} else {
				static_assert(std::is_same_v<payload_type, confirm_config_payload> ||
					      std::is_same_v<payload_type, set_guardrails_policy_payload>);
				return false;
			}
		},
		payload);
}

/**
 * @brief Identify retained-result payloads classified before a safety intent.
 * @param payload Construction-fixed operation identity.
 * @return true only for ConfirmConfig and ConfigureGuardrails.
 */
[[nodiscard]] bool retained_retry_precedes_safety_intent(const mutation_payload &payload) noexcept
{
	return std::visit(
		[](const auto &value) noexcept {
			using payload_type = std::remove_cvref_t<decltype(value)>;
			if constexpr (std::is_same_v<payload_type, confirm_config_payload> ||
				      std::is_same_v<payload_type, set_guardrails_policy_payload>) {
				return true;
			} else {
				static_assert(std::is_same_v<payload_type, set_config_payload> ||
					      std::is_same_v<payload_type, rollback_payload>);
				return false;
			}
		},
		payload);
}

/** @brief Observation-only cadence for a retained in-progress DP transaction. */
constexpr std::chrono::milliseconds TRANSITION_STATUS_POLL_INTERVAL{10};

/** @brief Scope guard that always closes startup reconciliation mode. */
class startup_reconciliation_scope {
    public:
	/**
	 * @brief Bind one owner flag already set true.
	 * @param active Sole-thread mode flag cleared on scope exit.
	 */
	explicit startup_reconciliation_scope(bool &active) noexcept
		: active_(active)
	{
	}

	startup_reconciliation_scope(const startup_reconciliation_scope &) = delete;
	startup_reconciliation_scope &operator=(const startup_reconciliation_scope &) = delete;

	/** @brief Clear the mode before any startup result escapes. */
	~startup_reconciliation_scope()
	{
		active_ = false;
	}

    private:
	bool &active_;	///< Borrowed sole-thread mode flag.
};

/**
 * @brief Convert one typed pre-commit terminal cause into durable application status.
 * @param failure Exact wire failure enum already admitted by reconciliation.
 * @param diagnostic Bounded diagnostic copied only after typed classification.
 * @return Non-OK status suitable for exact ABORTED persistence.
 */
[[nodiscard]] kinetum::common::status durable_abort_status(kinetum::telemetry::v1::EpochTransitionFailureCode failure,
							   std::string_view diagnostic)
{
	using wire = kinetum::telemetry::v1::EpochTransitionFailureCode;
	kinetum::common::status_code code{};
	const char *default_message = nullptr;
	switch (failure) {
	case wire::EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT:
		code = kinetum::common::status_code::ABORTED;
		default_message = "Data Plane preparation was explicitly aborted";
		break;
	case wire::EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT:
		code = kinetum::common::status_code::ABORTED;
		default_message = "Data Plane shutdown aborted preparation";
		break;
	case wire::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE:
		code = kinetum::common::status_code::MODULE_ERROR;
		default_message = "Data Plane module preparation failed";
		break;
	case wire::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED:
		code = kinetum::common::status_code::CANCELLED;
		default_message = "Data Plane preparation was cancelled";
		break;
	case wire::EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED:
		code = kinetum::common::status_code::DEADLINE_EXCEEDED;
		default_message = "Data Plane preparation deadline expired";
		break;
	case wire::EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED:
		code = kinetum::common::status_code::ABORTED;
		default_message = "Data Plane prepared lease expired before commit";
		break;
	case wire::EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED:
	case wire::EPOCH_TRANSITION_FAILURE_CODE_NONE:
	case wire::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED:
	case wire::EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION:
	case wire::EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED:
	case wire::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE:
	case wire::EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED:
	case wire::EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN:
	case wire::EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT:
	case kinetum::telemetry::v1::EpochTransitionFailureCode_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::telemetry::v1::EpochTransitionFailureCode_INT_MAX_SENTINEL_DO_NOT_USE_:
		return kinetum::common::status::internal_error("typed DP terminal cause is not a pre-commit abort");
	}
	return kinetum::common::status(code,
				       diagnostic.empty() ? std::string(default_message) : std::string(diagnostic));
}

/**
 * @brief Remove nonpersistent details and bound one intent terminal diagnostic.
 * @param failure Exact non-OK control-path failure.
 * @return Same typed code with one compact message and no auxiliary details.
 */
[[nodiscard]] kinetum::common::status compact_intent_failure(const kinetum::common::status &failure)
{
	if (failure.is_ok()) {
		return kinetum::common::status::internal_error(
			"rollback intent cannot retain a successful terminal outcome");
	}
	return kinetum::common::status(failure.code(), std::string(failure.message().substr(
							       0u, kinetum::common::MAX_TRANSITION_DIAGNOSTIC_BYTES)));
}

}  // namespace

// =============================================================================
// Construction and Lifecycle
// =============================================================================

control_loop::control_loop(config_store *store, std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> dp_stub)
	: store_(store)
{
	if (store_ == nullptr) {
		init_status_ = kinetum::common::status::invalid_argument("control loop requires a configuration store");
		publish_state_();
		return;
	}
	if (dp_stub != nullptr) {
		auto client_or = dataplane_transition_client::create(std::move(dp_stub));
		if (!client_or.is_ok()) {
			init_status_ = client_or.error();
			publish_state_();
			return;
		}
		transition_client_ = std::move(client_or).value();
	}

	// The store has already fully re-admitted its sole atomic authority.
	// Consume its nested active request once so identity and revision cannot be
	// observed from separate persistence authorities.
	const auto active_or = store_->active_bootstrap();
	if (active_or.is_ok()) {
		active_snapshot_id_ = active_or->snapshot().snapshot_id();
		current_revision_ = active_or->snapshot().revision();
	} else if (active_or.error().code() != kinetum::common::status_code::NOT_FOUND) {
		init_status_ = kinetum::common::status(active_or.error().code(),
						       "Storage read failure during control-loop initialization",
						       std::string(active_or.error().message()));
	}
	if (init_status_.is_ok()) {
		auto policy_or = store_->guardrails_policy();
		if (policy_or.is_ok()) {
			guardrails_generation_ = policy_or->generation;
			guardrails_state_.policy.store(std::move(policy_or->policy), guardrails_generation_);
		} else if (policy_or.error().code() != kinetum::common::status_code::NOT_FOUND) {
			init_status_ = kinetum::common::status(policy_or.error().code(),
							       "Guardrails policy restoration failed",
							       std::string(policy_or.error().message()));
		}
	}

	// Publish initial state for external readers (coherent pair via RCU).
	publish_state_();
}

control_loop::~control_loop()
{
	stop();
	std::lock_guard<std::mutex> lock(queue_mu_);
	if (!queue_.empty() || safety_intent_ != nullptr) {
		std::terminate();
	}
}

const kinetum::common::status &control_loop::initialization_status() const noexcept
{
	return init_status_;
}

kinetum::common::status control_loop::reconcile_startup(bool packet_ready_rejoin,
							std::chrono::steady_clock::time_point startup_deadline)
{
	if (!init_status_.is_ok()) {
		return init_status_;
	}
	if (running_.load(std::memory_order_acquire) || startup_reconciliation_) {
		return kinetum::common::status::failed_precondition(
			"startup reconciliation requires one stopped control-loop owner");
	}
	const auto now = std::chrono::steady_clock::now();
	if (startup_deadline == std::chrono::steady_clock::time_point::max()) {
		startup_deadline = now + DATAPLANE_STARTUP_RECONCILIATION_TIMEOUT;
	} else if (startup_deadline <= now) {
		return kinetum::common::status::deadline_exceeded(
			"Control Plane startup reconciliation deadline expired");
	} else if (startup_deadline - now > DATAPLANE_STARTUP_RECONCILIATION_TIMEOUT) {
		return kinetum::common::status::invalid_argument(
			"Control Plane startup reconciliation deadline exceeds its production bound");
	}
	startup_reconciliation_ = true;
	startup_reconciliation_deadline_ = startup_deadline;
	startup_reconciliation_scope scope(startup_reconciliation_);
	auto initial_intent_or = store_->rollback_intent();
	if (initial_intent_or.is_ok() && initial_intent_or->terminal_failure.is_error()) {
		auto blocked = kinetum::common::status::failed_precondition(
			"durable rollback intent requires operator recovery");
		blocked.set_details(std::string(initial_intent_or->terminal_failure.message()));
		return blocked;
	}
	if (!initial_intent_or.is_ok() && initial_intent_or.error().code() != kinetum::common::status_code::NOT_FOUND) {
		return initial_intent_or.error();
	}

	auto transition_or = store_->epoch_transition();
	if (transition_or.is_ok() &&
	    (transition_or->phase == kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED ||
	     transition_or->phase == kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED ||
	     transition_or->phase ==
		     kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING ||
	     transition_or->phase == kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING)) {
		const auto [epoch, result] = apply_to_dp_(transition_or->prepare_request.snapshot(),
							  transition_or->prepare_request.idempotency_key(),
							  transition_or->confirm_timeout_ms);
		(void)epoch;
		if (!result.is_ok()) {
			auto reconciled_or = store_->epoch_transition();
			if (!reconciled_or.is_ok() ||
			    reconciled_or->phase !=
				    kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED) {
				return result;
			}
		}
	} else if (transition_or.is_ok() && packet_ready_rejoin) {
		if (transition_client_ == nullptr) {
			return kinetum::common::status::unavailable(
				"startup transition reconciliation requires a Data Plane client");
		}
		auto active_or = store_->active_bootstrap();
		if (!active_or.is_ok()) {
			return active_or.error();
		}
		auto observed_or = [&]() -> kinetum::common::status_or<dataplane_transition_observation> {
			for (;;) {
				auto attempt_or = transition_client_->query(
					transition_or->identity, transition_or->prepare_request.idempotency_key(),
					active_or->plan_content_hash(), startup_reconciliation_deadline_);
				if (attempt_or.is_ok() ||
				    (attempt_or.error().code() != kinetum::common::status_code::UNAVAILABLE &&
				     attempt_or.error().code() != kinetum::common::status_code::DEADLINE_EXCEEDED)) {
					return attempt_or;
				}
				if (std::chrono::steady_clock::now() >= startup_reconciliation_deadline_) {
					return kinetum::common::status::deadline_exceeded(
						"Control Plane startup reconciliation deadline expired");
				}
				(void)wait_for_transition_poll_(std::chrono::steady_clock::now() +
								TRANSITION_STATUS_POLL_INTERVAL);
			}
		}();
		if (!observed_or.is_ok()) {
			return observed_or.error();
		}
		auto action_or = classify_transition_reconciliation(transition_or->phase, observed_or->resolution,
								    observed_or->state, observed_or->failure_code);
		const bool complete = transition_or->phase ==
				      kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE;
		const bool exact_terminal =
			action_or.is_ok() &&
			((complete && action_or.value() == transition_reconciliation_action::PERSIST_COMPLETE) ||
			 (!complete && action_or.value() == transition_reconciliation_action::PERSIST_ABORTED));
		if (!exact_terminal) {
			return action_or.is_ok() ?
				       kinetum::common::status::data_loss(
					       "durable terminal transition contradicts Data Plane Status") :
				       action_or.error();
		}
	} else if (!transition_or.is_ok() && transition_or.error().code() != kinetum::common::status_code::NOT_FOUND) {
		return transition_or.error();
	}

	for (;;) {
		auto intent_or = store_->rollback_intent();
		if (!intent_or.is_ok()) {
			return intent_or.error().code() == kinetum::common::status_code::NOT_FOUND ?
				       kinetum::common::status::ok() :
				       intent_or.error();
		}
		if (intent_or->terminal_failure.is_error()) {
			auto blocked = kinetum::common::status::failed_precondition(
				"durable rollback intent requires operator recovery");
			blocked.set_details(std::string(intent_or->terminal_failure.message()));
			return blocked;
		}
		const bool retry = service_durable_rollback_intent_();
		if (!retry) {
			continue;
		}
		if (std::chrono::steady_clock::now() >= startup_reconciliation_deadline_) {
			return kinetum::common::status::deadline_exceeded(
				"Control Plane startup reconciliation deadline expired");
		}
		(void)wait_for_transition_poll_(
			std::min(startup_reconciliation_deadline_,
				 std::chrono::steady_clock::now() + TRANSITION_STATUS_POLL_INTERVAL));
	}
}

kinetum::common::status
control_loop::configure_startup_guardrails_policy(const kinetum::control::v1::GuardrailsPolicy &policy)
{
	if (!init_status_.is_ok()) {
		return init_status_;
	}
	if (running_.load(std::memory_order_acquire) || startup_reconciliation_) {
		return kinetum::common::status::failed_precondition(
			"startup guardrails policy requires one stopped control-loop owner");
	}
	auto canonical_or = canonicalize_guardrails_policy(policy);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	auto retained_or = store_->guardrails_policy();
	if (retained_or.is_ok() && retained_or->policy_hash == canonical_or->policy_hash) {
		return kinetum::common::status::ok();
	}
	if (!retained_or.is_ok() && retained_or.error().code() != kinetum::common::status_code::NOT_FOUND) {
		return retained_or.error();
	}
	auto key_or = kinetum::common::generate_transition_idempotency_key("kinetum-cp-startup-guardrails");
	if (!key_or.is_ok()) {
		return key_or.error();
	}
	auto configured_or = store_->configure_guardrails_policy(policy, key_or.value(),
								 retained_or.is_ok() ? retained_or->generation : 0u);
	if (!configured_or.is_ok()) {
		return configured_or.error();
	}
	guardrails_generation_ = configured_or->generation;
	guardrails_state_.policy.store(std::move(configured_or->policy), guardrails_generation_);
	return kinetum::common::status::ok();
}

kinetum::common::status control_loop::start()
{
	// Refuse to start if startup integrity check failed
	if (init_status_.is_error()) {
		return init_status_;
	}

	// Idempotent: no-op if already running
	bool expected = false;
	if (!running_.compare_exchange_strong(expected, true)) {
		return kinetum::common::status::ok();
	}

	stop_requested_.store(false);

	// Launch worker thread. Packet-ready startup now depends on this owner, so a
	// native thread-creation failure must restore the stopped gate and return a
	// status rather than escaping from a status-returning lifecycle method.
	try {
		worker_thread_ = std::thread([this]() { run_(); });
	} catch (const std::bad_alloc &) {
		stop_requested_.store(true, std::memory_order_release);
		running_.store(false, std::memory_order_release);
		return kinetum::common::status::resource_exhausted(
			"failed to allocate the Control Plane mutation worker");
	} catch (const std::system_error &error) {
		stop_requested_.store(true, std::memory_order_release);
		running_.store(false, std::memory_order_release);
		return kinetum::common::status(kinetum::common::status_code::RESOURCE_EXHAUSTED,
					       "failed to start the Control Plane mutation worker", error.what());
	}

	return kinetum::common::status::ok();
}

void control_loop::stop()
{
	// Idempotent: no-op if not running
	bool expected = true;
	if (!running_.compare_exchange_strong(expected, false)) {
		return;
	}

	// Publish the condition-variable predicate under its owning mutex so a
	// submitter cannot enqueue after the worker's final empty-queue decision.
	{
		std::lock_guard<std::mutex> lock(queue_mu_);
		stop_requested_.store(true, std::memory_order_release);
	}
	queue_cv_.notify_all();

	// Wait for worker thread to finish
	if (worker_thread_.joinable()) {
		worker_thread_.join();
	}
}

bool control_loop::is_running() const noexcept
{
	return running_.load();
}

// =============================================================================
// Mutation Submission
// =============================================================================

control_loop::mailbox_publication_result control_loop::try_publish_pending_(pending_mutation *pending) noexcept
{
	if (pending == nullptr) {
		std::terminate();
	}
	std::lock_guard<std::mutex> lock(queue_mu_);
	if (!running_.load(std::memory_order_acquire) || stop_requested_.load(std::memory_order_acquire)) {
		return mailbox_publication_result::STOPPING;
	}
	return queue_.try_enqueue(pending) ? mailbox_publication_result::PUBLISHED : mailbox_publication_result::FULL;
}

mutation_result control_loop::submit(mutation m)
{
	// Check if control loop is running
	if (!running_.load()) {
		mutation_result result;
		result.status = kinetum::common::status::unavailable("Control loop is not running");
		return result;
	}

	std::unique_ptr<pending_mutation> pending;
	try {
		pending = std::make_unique<pending_mutation>(std::move(m), nullptr);
	} catch (const std::bad_alloc &) {
		mutation_result result;
		result.status = kinetum::common::status::resource_exhausted(
			"control-loop mutation submission exhausted memory");
		return result;
	}
	auto future = pending->result_promise.get_future();

	const auto publication = try_publish_pending_(pending.get());
	switch (publication) {
	case mailbox_publication_result::STOPPING: {
		mutation_result result;
		result.status = kinetum::common::status::unavailable("Control loop is stopping");
		return result;
	}
	case mailbox_publication_result::FULL: {
		mutation_result result;
		result.status = kinetum::common::status::resource_exhausted("control-loop mutation mailbox is full");
		return result;
	}
	case mailbox_publication_result::PUBLISHED:
		(void)pending.release();
		break;
	}
	queue_cv_.notify_one();

	// Wait for the exact worker result.
	return future.get();
}

mutation_result control_loop::submit(mutation m, std::chrono::milliseconds timeout)
{
	if (timeout < std::chrono::milliseconds::zero()) {
		mutation_result result;
		result.status =
			kinetum::common::status::invalid_argument("control-loop mutation timeout must be nonnegative");
		return result;
	}
	// Check if control loop is running
	if (!running_.load()) {
		mutation_result result;
		result.status = kinetum::common::status::unavailable("Control loop is not running");
		return result;
	}

	std::shared_ptr<std::atomic<request_state>> state;
	std::unique_ptr<pending_mutation> pending;
	try {
		// The submitter and worker both retain this cancel-safe state.
		state = std::make_shared<std::atomic<request_state>>(request_state::QUEUED);
		pending = std::make_unique<pending_mutation>(std::move(m), state);
	} catch (const std::bad_alloc &) {
		mutation_result result;
		result.status = kinetum::common::status::resource_exhausted(
			"control-loop mutation submission exhausted memory");
		return result;
	}
	auto future = pending->result_promise.get_future();

	const auto publication = try_publish_pending_(pending.get());
	switch (publication) {
	case mailbox_publication_result::STOPPING: {
		mutation_result result;
		result.status = kinetum::common::status::unavailable("Control loop is stopping");
		return result;
	}
	case mailbox_publication_result::FULL: {
		mutation_result result;
		result.status = kinetum::common::status::resource_exhausted("control-loop mutation mailbox is full");
		return result;
	}
	case mailbox_publication_result::PUBLISHED:
		(void)pending.release();
		break;
	}
	queue_cv_.notify_one();

	// Wait with timeout
	if (future.wait_for(timeout) == std::future_status::timeout) {
		// Attempt to cancel: CAS queued -> canceled.
		// If the mutation is still queued, this succeeds and the worker will
		// skip it. No mutation executes after the caller receives timeout.
		request_state expected = request_state::QUEUED;
		if (state->compare_exchange_strong(expected, request_state::CANCELED)) {
			mutation_result result;
			result.status = kinetum::common::status::deadline_exceeded(
				"Mutation timed out after " + std::to_string(timeout.count()) + "ms");
			return result;
		}

		// CAS failed - mutation is already executing (or completed).
		// Wait for the real result instead of fabricating a synthetic timeout.
		return future.get();
	}

	return future.get();
}

kinetum::common::status control_loop::submit_safety_intent(rollback_intent_request request)
{
	if (!running_.load(std::memory_order_acquire)) {
		return kinetum::common::status::unavailable("Control loop is not running");
	}
	try {
		safety_intent_context context{
			.request = std::move(request),
			.result = {},
		};
		auto future = context.result.get_future();
		{
			std::lock_guard<std::mutex> lock(queue_mu_);
			if (!running_.load(std::memory_order_acquire) ||
			    stop_requested_.load(std::memory_order_acquire)) {
				return kinetum::common::status::unavailable("Control loop is stopping");
			}
			if (safety_intent_ != nullptr) {
				return kinetum::common::status::resource_exhausted(
					"one safety intent context is already unresolved");
			}
			safety_intent_ = &context;
		}
		queue_cv_.notify_one();
		return future.get();
	} catch (const std::bad_alloc &) {
		return kinetum::common::status::resource_exhausted("safety intent context allocation exhausted memory");
	}
}

// =============================================================================
// Statistics
// =============================================================================

std::size_t control_loop::queue_depth() const
{
	std::lock_guard<std::mutex> lock(queue_mu_);
	return queue_.size_approx();
}

cp_published_state control_loop::published_state() const
{
	auto guard = published_state_.borrow();
	return cp_published_state{guard->revision, guard->snapshot_id};
}

const guardrails_runtime_state &control_loop::guardrails_state() const noexcept
{
	return guardrails_state_;
}

void control_loop::publish_state_() noexcept
{
	try {
		cp_published_state next{current_revision_, active_snapshot_id_};
		if (published_generation_ == std::numeric_limits<uint64_t>::max()) {
			std::fputs("control_loop: active-state publication generation is exhausted\n", stderr);
			(void)std::fflush(stderr);
			std::terminate();
		}
		const uint64_t next_generation = published_generation_ + 1u;
		published_state_.store(std::move(next), next_generation);
		published_generation_ = next_generation;
	} catch (...) {
		std::fputs("control_loop: active-state publication could not retain exact identity\n", stderr);
		(void)std::fflush(stderr);
		std::terminate();
	}
}

void control_loop::publish_completed_snapshot_(kinetum::control::v1::ConfigSnapshot &snapshot) noexcept
{
	current_revision_ = snapshot.revision();
	active_snapshot_id_.swap(*snapshot.mutable_snapshot_id());
	publish_state_();
}

// =============================================================================
// Worker Thread
// =============================================================================

void control_loop::run_()
{
	for (;;) {
		(void)service_safety_intent_submission_();
		const bool intent_needs_retry = !stop_requested_.load(std::memory_order_acquire) &&
						service_durable_rollback_intent_();
		std::unique_ptr<pending_mutation> pending;

		{
			std::unique_lock<std::mutex> lock(queue_mu_);
			const auto ready = [this]() {
				return !queue_.empty() || safety_intent_ != nullptr ||
				       stop_requested_.load(std::memory_order_acquire);
			};
			if (!ready()) {
				if (intent_needs_retry) {
					queue_cv_.wait_until(lock,
							     std::chrono::steady_clock::now() +
								     TRANSITION_STATUS_POLL_INTERVAL,
							     ready);
				} else {
					queue_cv_.wait(lock, ready);
				}
			}
			if (safety_intent_ != nullptr) {
				continue;
			}
			if (!queue_.empty()) {
				pending_mutation *published = nullptr;
				if (!queue_.try_dequeue(published) || published == nullptr) {
					std::terminate();
				}
				pending.reset(published);
			} else if (stop_requested_.load(std::memory_order_acquire)) {
				break;
			}
		}

		if (pending != nullptr) {
			auto &pm = *pending;
			// For timeout submissions: CAS queued -> executing before dispatch.
			// If the CAS fails, the submitter already canceled this request.
			if (pm.state) {
				request_state expected = request_state::QUEUED;
				if (!pm.state->compare_exchange_strong(expected, request_state::EXECUTING)) {
					// State was canceled - skip this mutation entirely.
					// The submitter already returned deadline_exceeded to the caller.
					// Destroy the promise without fulfilling it; the future is abandoned.
					continue;
				}
			}

			auto result = process_(pm.request);

			// Mark completed (for timeout submissions)
			if (pm.state) {
				pm.state->store(request_state::COMPLETED, std::memory_order_release);
			}

			// Response publication precedes durable safety-intent execution. The
			// next loop iteration services that intent before dequeuing another
			// ordinary mutation.
			pm.result_promise.set_value(std::move(result));
		}
	}
}

bool control_loop::service_safety_intent_submission_()
{
	safety_intent_context *context = nullptr;
	{
		std::lock_guard<std::mutex> lock(queue_mu_);
		context = safety_intent_;
	}
	if (context == nullptr) {
		return false;
	}
	auto accepted_or = store_->accept_rollback_intent(context->request);
	kinetum::common::status result = accepted_or.is_ok() ? kinetum::common::status::ok() : accepted_or.error();
	{
		std::lock_guard<std::mutex> lock(queue_mu_);
		if (safety_intent_ != context) {
			std::terminate();
		}
		safety_intent_ = nullptr;
	}
	context->result.set_value(std::move(result));
	return true;
}

bool control_loop::service_durable_rollback_intent_()
{
	auto intent_or = store_->rollback_intent();
	if (!intent_or.is_ok()) {
		if (intent_or.error().code() != kinetum::common::status_code::NOT_FOUND) {
			std::terminate();
		}
		return false;
	}
	const auto &intent = intent_or->request;
	if (intent_or->terminal_failure.is_error()) {
		return false;
	}
	auto authority_or = store_->runtime_authority();
	if (!authority_or.is_ok()) {
		std::terminate();
	}
	if (intent.wait_for_mutation_sequence != 0u) {
		auto intent_key_digest_or = kinetum::common::digest_transition_idempotency_key(intent.idempotency_key);
		if (!intent_key_digest_or.is_ok()) {
			std::terminate();
		}
		const auto *transition = authority_or->transition.has_value() ? &*authority_or->transition : nullptr;
		const bool owns_rollback = transition != nullptr &&
					   transition->snapshot_id == intent.target_snapshot_id &&
					   transition->identity.idempotency_key_digest == intent_key_digest_or.value();
		if (transition == nullptr ||
		    transition->identity.mutation_sequence != intent.wait_for_mutation_sequence) {
			const auto failed = store_->fail_rollback_intent(
				intent.idempotency_key, kinetum::common::status::data_loss(
								"rollback intent transition identity is unavailable"));
			if (!failed.is_ok()) {
				std::terminate();
			}
			return false;
		}
		if (!owns_rollback &&
		    transition->phase == kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED) {
			auto transition_or = store_->epoch_transition();
			if (!transition_or.is_ok() || transition_or->identity != transition->identity ||
			    transition_or->phase != transition->phase) {
				std::terminate();
			}
			kinetum::common::status_code code{};
			const auto failure =
				kinetum::common::decode_exact_application_status(transition_or->terminal_status,
										 code) &&
						code != kinetum::common::status_code::OK ?
					kinetum::common::status(code, transition_or->terminal_status.message()) :
					kinetum::common::status::data_loss(
						"rollback predecessor retained malformed terminal failure");
			const auto failed = store_->fail_rollback_intent(intent.idempotency_key, failure);
			if (!failed.is_ok()) {
				std::terminate();
			}
			return false;
		}
		if (!owns_rollback &&
		    transition->phase != kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE) {
			return true;
		}
	}
	if (authority_or->active.snapshot_id == intent.target_snapshot_id) {
		const auto cleared = store_->clear_completed_rollback_intent(intent.idempotency_key,
									     authority_or->active.active_epoch);
		if (!cleared.is_ok()) {
			std::terminate();
		}
		return false;
	}

	rollback_payload payload;
	payload.target_snapshot_id = intent.target_snapshot_id;
	auto result = handle_rollback_(payload, intent.idempotency_key);
	if (result.ok()) {
		return false;
	}
	auto retained_or = store_->rollback_intent();
	if (!retained_or.is_ok()) {
		std::terminate();
	}
	if (retained_or->terminal_failure.is_error()) {
		return false;
	}
	if (result.status.code() == kinetum::common::status_code::UNAVAILABLE ||
	    result.status.code() == kinetum::common::status_code::DEADLINE_EXCEEDED) {
		return true;
	}
	const auto failed = store_->fail_rollback_intent(intent.idempotency_key, compact_intent_failure(result.status));
	if (!failed.is_ok()) {
		std::terminate();
	}
	return false;
}

bool control_loop::wait_for_transition_poll_(std::chrono::steady_clock::time_point deadline)
{
	if (startup_reconciliation_) {
		deadline = std::min(deadline, startup_reconciliation_deadline_);
	}
	for (;;) {
		{
			std::unique_lock<std::mutex> lock(queue_mu_);
			queue_cv_.wait_until(lock, deadline, [this]() {
				return safety_intent_ != nullptr || stop_requested_.load(std::memory_order_acquire);
			});
			if (stop_requested_.load(std::memory_order_acquire)) {
				return false;
			}
			if (startup_reconciliation_ &&
			    std::chrono::steady_clock::now() >= startup_reconciliation_deadline_) {
				return false;
			}
			if (safety_intent_ == nullptr) {
				return true;
			}
		}
		(void)service_safety_intent_submission_();
		if (std::chrono::steady_clock::now() >= deadline) {
			return true;
		}
	}
}

mutation_result control_loop::process_(const mutation &m)
{
	const auto &payload = m.payload();
	auto safety_intent_or = store_->rollback_intent();
	// Confirm and policy stores classify a retained terminal/exact retry before
	// their intent gate. Let only those two operations reach that classifier;
	// every new mutation still rejects while desired rollback is unresolved.
	const bool retry_record_may_precede_intent = retained_retry_precedes_safety_intent(payload);
	if (safety_intent_or.is_ok() && !retry_record_may_precede_intent) {
		mutation_result result;
		result.status = kinetum::common::status::failed_precondition(
			"a durable safety intent must converge before another ordinary mutation");
		return result;
	}
	if (!safety_intent_or.is_ok() && safety_intent_or.error().code() != kinetum::common::status_code::NOT_FOUND) {
		mutation_result result;
		result.status = safety_intent_or.error();
		return result;
	}
	bool retained_durable_retry = false;
	if (!m.idempotency_key().empty() && uses_snapshot_transition_identity(payload)) {
		auto retained_or = store_->epoch_transition_key_matches(m.idempotency_key());
		if (!retained_or.is_ok()) {
			mutation_result result;
			result.status = retained_or.error();
			return result;
		}
		retained_durable_retry = retained_or.value();
	}

	// CAS revision check
	if (!retained_durable_retry && m.expected_revision().has_value() &&
	    *m.expected_revision() != current_revision_) {
		mutation_result result;
		result.status = kinetum::common::status::failed_precondition(
			"Revision mismatch: expected=" + std::to_string(*m.expected_revision()) +
			" current=" + std::to_string(current_revision_));
		result.revision = current_revision_;
		result.snapshot_id = active_snapshot_id_;

		// CAS mismatch is transient (revision changes) - never cache.
		// Retry with same key re-evaluates CAS with current revision.
		return result;
	}

	return std::visit(
		[this, &m](const auto &value) -> mutation_result {
			using payload_type = std::remove_cvref_t<decltype(value)>;
			if constexpr (std::is_same_v<payload_type, set_config_payload>) {
				return handle_set_config_(value, m.idempotency_key());
			} else if constexpr (std::is_same_v<payload_type, confirm_config_payload>) {
				return handle_confirm_config_(value, m.idempotency_key());
			} else if constexpr (std::is_same_v<payload_type, rollback_payload>) {
				return handle_rollback_(value, m.idempotency_key());
			} else {
				static_assert(std::is_same_v<payload_type, set_guardrails_policy_payload>);
				return handle_set_guardrails_policy_(value, m.idempotency_key());
			}
		},
		payload);
}

// =============================================================================
// Mutation Handlers
// =============================================================================

mutation_result control_loop::handle_set_config_(const set_config_payload &p, const std::string &idem_key)
{
	mutation_result result;
	const auto &snap = p.snapshot;

	// -------------------------------------------------------------------------
	// Phase 1: Validation
	// -------------------------------------------------------------------------

	if (snap.snapshot_id().empty()) {
		result.status = kinetum::common::status::invalid_argument("snapshot_id required");
		return result;
	}

	if (snap.snapshot_id().size() > kinetum::common::MAX_CONFIG_SNAPSHOT_ID_BYTES) {
		result.status = kinetum::common::status::invalid_argument("snapshot_id exceeds maximum length");
		return result;
	}

	if (snap.ByteSizeLong() > kinetum::common::MAX_CONFIG_SNAPSHOT_BYTES) {
		result.status = kinetum::common::status::resource_exhausted(
			"input ConfigSnapshot exceeds the 10 MiB admission bound");
		return result;
	}

	if (!kinetum::common::valid_config_snapshot_revision(snap.revision())) {
		result.status = kinetum::common::status::invalid_argument("revision out of valid range");
		return result;
	}
	const auto key_status = kinetum::common::validate_transition_idempotency_key(idem_key);
	if (!key_status.is_ok()) {
		result.status = key_status;
		return result;
	}

	if (p.confirm_timeout_ms > 0 && active_snapshot_id_.empty()) {
		result.status = kinetum::common::status::failed_precondition(
			"commit-confirmed requires an existing active snapshot as rollback target");
		return result;
	}

	// -------------------------------------------------------------------------
	// Phase 2: Durable Allocation and Typed DP Convergence
	// -------------------------------------------------------------------------
	// Canonical corpus staging and both allocations are one store-owned
	// transaction. Exact DP completion remains the only authority that may move
	// the active snapshot.

	const auto [epoch, dp_status] = apply_to_dp_(snap, idem_key, p.confirm_timeout_ms);
	result.status = dp_status;
	if (dp_status.is_ok()) {
		result.revision = current_revision_;
		result.epoch = epoch;
		result.snapshot_id = active_snapshot_id_;
	}
	return result;
}

mutation_result control_loop::handle_confirm_config_(const confirm_config_payload &p,
						     const std::string &idempotency_key)
{
	mutation_result result;
	auto confirmed_or = store_->confirm_pending_config(p.snapshot_id, p.epoch, p.revision, idempotency_key,
							   kinetum::common::unix_time_ms());
	if (!confirmed_or.is_ok()) {
		result.status = confirmed_or.error();
		return result;
	}
	result.status = kinetum::common::status::ok();
	result.snapshot_id = confirmed_or->snapshot_id;
	result.epoch = confirmed_or->epoch;
	result.revision = confirmed_or->revision;
	result.time_remaining_ms = static_cast<int64_t>(confirmed_or->time_remaining_ms);
	return result;
}

mutation_result control_loop::handle_rollback_(const rollback_payload &p, const std::string &idem_key)
{
	mutation_result result;
	const auto key_status = kinetum::common::validate_transition_idempotency_key(idem_key);
	if (!key_status.is_ok()) {
		result.status = key_status;
		return result;
	}

	// -------------------------------------------------------------------------
	// Phase 1: Load Target Snapshot
	// -------------------------------------------------------------------------

	const auto target_snap_or = store_->load_snapshot(p.target_snapshot_id);
	if (!target_snap_or.is_ok()) {
		result.status = target_snap_or.error();
		return result;
	}

	const auto &target_snap = target_snap_or.value();
	auto retained_or = retained_candidate_for_key(*store_, idem_key);
	if (!retained_or.is_ok()) {
		result.status = retained_or.error();
		return result;
	}
	const auto &retained_candidate = retained_or.value();

	// -------------------------------------------------------------------------
	// Phase 2: Full vs Selective Rollback
	// -------------------------------------------------------------------------

	kinetum::control::v1::ConfigSnapshot snap_to_apply;

	if (p.module_ids.empty()) {
		// Full rollback.
		snap_to_apply = target_snap;
	} else {
		// Selective rollback.
		// Load current active snapshot
		if (active_snapshot_id_.empty()) {
			result.status = kinetum::common::status::failed_precondition(
				"Selective rollback requires active snapshot");
			return result;
		}

		const std::string current_snapshot_id =
			retained_candidate.has_value() && !retained_candidate->parent_snapshot_id().empty() ?
				retained_candidate->parent_snapshot_id() :
				active_snapshot_id_;
		const auto current_snap_or = store_->load_snapshot(current_snapshot_id);
		if (!current_snap_or.is_ok()) {
			result.status = current_snap_or.error();
			return result;
		}

		const auto &current_snap = current_snap_or.value();

		// Build module indexes
		std::unordered_set<std::string> current_module_ids;
		for (const auto &mod : current_snap.modules()) {
			current_module_ids.insert(mod.module_id());
		}

		std::unordered_map<std::string, const kinetum::control::v1::ModuleConfig *> target_modules;
		std::unordered_set<std::string> target_module_ids;
		for (const auto &mod : target_snap.modules()) {
			target_modules[mod.module_id()] = &mod;
			target_module_ids.insert(mod.module_id());
		}

		// -----------------------------------------------------------------------
		// MODULE-SET COMPATIBILITY CHECK
		// -----------------------------------------------------------------------
		// ConfigSnapshot carries module configs, not the full Gluon plan graph.
		// Selective rollback therefore enforces the concrete invariant available
		// here: both snapshots must have the same module ID set.
		if (current_module_ids != target_module_ids) {
			std::string missing_in_current;
			std::string missing_in_target;

			for (const auto &mod_id : target_module_ids) {
				if (current_module_ids.count(mod_id) == 0) {
					if (!missing_in_current.empty())
						missing_in_current += ", ";
					missing_in_current += mod_id;
				}
			}
			for (const auto &mod_id : current_module_ids) {
				if (target_module_ids.count(mod_id) == 0) {
					if (!missing_in_target.empty())
						missing_in_target += ", ";
					missing_in_target += mod_id;
				}
			}

			std::string details = "Pipeline topology mismatch: ";
			if (!missing_in_current.empty()) {
				details += "modules in target but not current: [" + missing_in_current + "]; ";
			}
			if (!missing_in_target.empty()) {
				details += "modules in current but not target: [" + missing_in_target + "]; ";
			}
			details += "Use full rollback instead.";

			result.status = kinetum::common::status::failed_precondition(details);
			return result;
		}

		// Validate requested modules exist
		for (const auto &mod_id : p.module_ids) {
			if (target_modules.find(mod_id) == target_modules.end()) {
				result.status = kinetum::common::status::not_found("Module '" + mod_id +
										   "' not found in target snapshot");
				return result;
			}
		}

		// Build rollback set
		std::unordered_set<std::string> modules_to_rollback(p.module_ids.begin(), p.module_ids.end());

		// Preserve current metadata and replace only selected module content plus
		// the generated identity fields owned by this new hybrid.
		snap_to_apply = current_snap;
		snap_to_apply.clear_modules();
		snap_to_apply.clear_content_hash();

		// Create hybrid snapshot identity.
		int64_t generated_revision = 0;
		if (retained_candidate.has_value()) {
			generated_revision = retained_candidate->revision();
		} else {
			auto revision_or = next_generated_revision(current_revision_, current_snap.revision());
			if (!revision_or.is_ok()) {
				result.status = revision_or.error();
				return result;
			}
			generated_revision = revision_or.value();
		}
		const int64_t generated_unix_ms = retained_candidate.has_value() ?
							  retained_candidate->created_unix_ms() :
							  kinetum::common::unix_time_ms();
		std::string generated_snapshot_id;
		if (retained_candidate.has_value()) {
			generated_snapshot_id = retained_candidate->snapshot_id();
		} else {
			auto id_or = kinetum::common::derive_generated_snapshot_id({
				.domain = "kinetum-selective-rollback-snapshot-v1",
				.prefix = "selective_",
				.idempotency_key = idem_key,
			});
			if (!id_or.is_ok()) {
				result.status = id_or.error();
				return result;
			}
			generated_snapshot_id = std::move(id_or).value();
		}
		snap_to_apply.set_created_unix_ms(generated_unix_ms);
		snap_to_apply.set_snapshot_id(generated_snapshot_id);
		snap_to_apply.set_revision(generated_revision);
		snap_to_apply.set_parent_snapshot_id(current_snap.snapshot_id());

		// Set metadata description for audit trail
		std::string module_list;
		for (std::size_t i = 0; i < p.module_ids.size(); ++i) {
			if (i > 0)
				module_list += ", ";
			module_list += p.module_ids[i];
		}
		snap_to_apply.set_description("Selective rollback of modules [" + module_list + "] from " +
					      p.target_snapshot_id);

		// Merge modules
		for (const auto &current_mod : current_snap.modules()) {
			auto *merged_mod = snap_to_apply.add_modules();
			if (modules_to_rollback.count(current_mod.module_id()) > 0) {
				*merged_mod = *target_modules[current_mod.module_id()];
				merged_mod->set_revision(generated_revision);
			} else {
				*merged_mod = current_mod;
			}
		}
	}

	// -------------------------------------------------------------------------
	// Phase 3: Apply the Snapshot
	// -------------------------------------------------------------------------

	// Exact durable allocation precedes every DP transition attempt.
	const auto [epoch, dp_status] = apply_to_dp_(snap_to_apply, idem_key);
	result.status = dp_status;
	if (dp_status.is_ok()) {
		result.revision = current_revision_;
		result.epoch = epoch;
		result.snapshot_id = active_snapshot_id_;
	}
	return result;
}

// =============================================================================
// Guardrails Policy Handler
// =============================================================================

mutation_result control_loop::handle_set_guardrails_policy_(const set_guardrails_policy_payload &p,
							    const std::string &idempotency_key)
{
	mutation_result result;
	auto durable_or = store_->configure_guardrails_policy(p.policy, idempotency_key, p.expected_generation);
	if (!durable_or.is_ok()) {
		result.status = durable_or.error();
		return result;
	}
	guardrails_generation_ = durable_or->generation;
	if (!durable_or->exact_retry || !guardrails_state_.policy.has_value()) {
		guardrails_state_.policy.store(std::move(durable_or->policy), guardrails_generation_);
	}

	result.status = kinetum::common::status::ok();
	result.revision = current_revision_;
	result.snapshot_id = active_snapshot_id_;
	result.policy_generation = durable_or->generation;
	result.policy_hash = durable_or->policy_hash;
	return result;
}

// =============================================================================
// Exact DP Transition Choreography
// =============================================================================

std::pair<uint64_t, kinetum::common::status>
control_loop::apply_to_dp_(const kinetum::control::v1::ConfigSnapshot &snap, const std::string &idem_key,
			   uint32_t confirm_timeout_ms)
{
	auto transition_or = store_->begin_epoch_transition(snap, idem_key, confirm_timeout_ms);
	if (!transition_or.is_ok()) {
		KINETUM_LOG_WARN("cp", "cp.transition.rejected",
				 "snapshot={} revision={} status={} reason={} details={}", snap.snapshot_id(),
				 snap.revision(), common::status_code_name(transition_or.error().code()),
				 transition_or.error().message(), transition_or.error().details());
		return {0u, transition_or.error()};
	}
	auto transition = std::move(transition_or).value();
	/**
	 * @brief Record the retained CP phase and return zero completed epoch with the unchanged failure.
	 */
	const auto failed = [&](common::status failure) {
		log_transition_failure(snap.snapshot_id(), transition, failure);
		return std::pair<uint64_t, common::status>{0u, std::move(failure)};
	};
	if (transition.phase == kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE) {
		publish_completed_snapshot_(*transition.prepare_request.mutable_snapshot());
		KINETUM_LOG_DEBUG("cp", "cp.transition.replayed",
				  "snapshot={} mutation_sequence={} epoch={} outcome=COMPLETE", active_snapshot_id_,
				  transition.identity.mutation_sequence, transition.identity.target_epoch);
		return {transition.prepare_request.target_epoch(), kinetum::common::status::ok()};
	}
	if (transition.phase == kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED) {
		kinetum::common::status_code code{};
		if (!kinetum::common::decode_exact_application_status(transition.terminal_status, code) ||
		    code == kinetum::common::status_code::OK) {
			return failed(kinetum::common::status::data_loss(
				"durable ABORTED transition has malformed terminal status"));
		}
		KINETUM_LOG_DEBUG(
			"cp", "cp.transition.replayed",
			"snapshot={} mutation_sequence={} target_epoch={} outcome=ABORTED status={} reason={}",
			snap.snapshot_id(), transition.identity.mutation_sequence, transition.identity.target_epoch,
			common::status_code_name(code), transition.terminal_status.message());
		return {0u, kinetum::common::status(code, transition.terminal_status.message())};
	}
	KINETUM_LOG(transition.exact_retry ? common::log_level::DEBUG : common::log_level::INFO, "cp",
		    transition.exact_retry ? "cp.transition.resuming" : "cp.transition.allocated",
		    "snapshot={} revision={} mutation_sequence={} target_epoch={}", snap.snapshot_id(), snap.revision(),
		    transition.identity.mutation_sequence, transition.identity.target_epoch);
	if (transition_client_ == nullptr) {
		return failed(kinetum::common::status::unavailable(
			"Data Plane transition client is unavailable for this control authority"));
	}
	auto active_or = store_->active_bootstrap();
	if (!active_or.is_ok()) {
		return failed(active_or.error());
	}
	const std::string plan_content_hash = active_or->plan_content_hash();
	const auto transient_transport_failure = [](const kinetum::common::status &failure) noexcept {
		return failure.code() == kinetum::common::status_code::UNAVAILABLE ||
		       failure.code() == kinetum::common::status_code::DEADLINE_EXCEEDED;
	};
	const auto operation_active = [this]() noexcept {
		return running_.load(std::memory_order_acquire) ||
		       (startup_reconciliation_ && std::chrono::steady_clock::now() < startup_reconciliation_deadline_);
	};
	const auto operation_deadline = [this]() noexcept {
		return startup_reconciliation_ ? startup_reconciliation_deadline_ :
						 std::chrono::steady_clock::time_point::max();
	};
	const auto query_until_transport_observed =
		[&]() -> kinetum::common::status_or<dataplane_transition_observation> {
		bool reported_transport_failure = false;
		for (;;) {
			auto queried_or = transition_client_->query(transition.identity,
								    transition.prepare_request.idempotency_key(),
								    plan_content_hash, operation_deadline());
			if (startup_reconciliation_ &&
			    std::chrono::steady_clock::now() >= startup_reconciliation_deadline_) {
				return kinetum::common::status::deadline_exceeded(
					"Control Plane startup reconciliation deadline expired");
			}
			if (queried_or.is_ok() || !transient_transport_failure(queried_or.error()) ||
			    !operation_active()) {
				if (reported_transport_failure && queried_or.is_ok()) {
					log_transition_transport(common::log_level::INFO,
								 "cp.transition.query_recovered", transition.identity,
								 common::status::ok());
				}
				return queried_or;
			}
			if (!reported_transport_failure) {
				log_transition_transport(common::log_level::WARN, "cp.transition.query_unavailable",
							 transition.identity, queried_or.error());
				reported_transport_failure = true;
			}
			if (!wait_for_transition_poll_(std::chrono::steady_clock::now() +
						       TRANSITION_STATUS_POLL_INTERVAL)) {
				return startup_reconciliation_ ?
					       kinetum::common::status::deadline_exceeded(
						       "Control Plane startup reconciliation deadline expired") :
					       kinetum::common::status::unavailable(
						       "Control Plane shutdown interrupted transition reconciliation");
			}
		}
	};
	const auto reconcile_ambiguous_attempt =
		[&](kinetum::common::status_or<dataplane_transition_observation> attempted_or)
		-> kinetum::common::status_or<dataplane_transition_observation> {
		if (attempted_or.is_ok() || !transient_transport_failure(attempted_or.error())) {
			return attempted_or;
		}
		if (!operation_active()) {
			return attempted_or;
		}
		log_transition_transport(common::log_level::WARN, "cp.transition.reply_ambiguous", transition.identity,
					 attempted_or.error());
		return query_until_transport_observed();
	};

	auto observation_or = query_until_transport_observed();
	if (!observation_or.is_ok()) {
		return failed(observation_or.error());
	}
	auto observation = std::move(observation_or).value();
	for (;;) {
		auto action_or = classify_transition_reconciliation(transition.phase, observation.resolution,
								    observation.state, observation.failure_code);
		if (!action_or.is_ok()) {
			return failed(action_or.error());
		}
		switch (action_or.value()) {
		case transition_reconciliation_action::RETRY_PREPARE: {
			KINETUM_LOG_DEBUG("cp", "cp.transition.prepare",
					  "snapshot={} mutation_sequence={} target_epoch={}", snap.snapshot_id(),
					  transition.identity.mutation_sequence, transition.identity.target_epoch);
			auto prepared_or = reconcile_ambiguous_attempt(transition_client_->prepare(
				transition.prepare_request, transition.identity, operation_deadline()));
			if (!prepared_or.is_ok()) {
				return failed(prepared_or.error());
			}
			observation = std::move(prepared_or).value();
			break;
		}
		case transition_reconciliation_action::WAIT_FOR_PREPARE: {
			if (!wait_for_transition_poll_(std::chrono::steady_clock::now() +
						       TRANSITION_STATUS_POLL_INTERVAL)) {
				return failed(
					startup_reconciliation_ ?
						kinetum::common::status::deadline_exceeded(
							"Control Plane startup reconciliation deadline expired") :
						kinetum::common::status::unavailable(
							"Control Plane shutdown interrupted transition preparation"));
			}
			auto queried_or = query_until_transport_observed();
			if (!queried_or.is_ok()) {
				return failed(queried_or.error());
			}
			observation = std::move(queried_or).value();
			break;
		}
		case transition_reconciliation_action::PERSIST_PREPARED: {
			const auto persisted = store_->advance_epoch_transition_phase(
				transition.identity,
				kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED);
			if (!persisted.is_ok()) {
				return failed(persisted);
			}
			auto refreshed_or = store_->epoch_transition();
			if (!refreshed_or.is_ok()) {
				return failed(refreshed_or.error());
			}
			transition = std::move(refreshed_or).value();
			KINETUM_LOG_DEBUG("cp", "cp.transition.prepared",
					  "snapshot={} mutation_sequence={} target_epoch={}", snap.snapshot_id(),
					  transition.identity.mutation_sequence, transition.identity.target_epoch);
			break;
		}
		case transition_reconciliation_action::RETRY_ACTIVATE: {
			constexpr auto PREPARED_PHASE =
				kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED;
			constexpr auto COMPLETION_PENDING_PHASE =
				kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING;
			if (transition.phase == PREPARED_PHASE) {
				const auto persisted = store_->advance_epoch_transition_phase(transition.identity,
											      COMPLETION_PENDING_PHASE);
				if (!persisted.is_ok()) {
					return failed(persisted);
				}
				auto refreshed_or = store_->epoch_transition();
				if (!refreshed_or.is_ok()) {
					return failed(refreshed_or.error());
				}
				transition = std::move(refreshed_or).value();
			} else if (transition.phase != COMPLETION_PENDING_PHASE) {
				return failed(kinetum::common::status::data_loss(
					"Activate retry selected from an impossible durable phase"));
			}
			KINETUM_LOG_DEBUG("cp", "cp.transition.activate",
					  "snapshot={} mutation_sequence={} target_epoch={}", snap.snapshot_id(),
					  transition.identity.mutation_sequence, transition.identity.target_epoch);
			auto activated_or = reconcile_ambiguous_attempt(transition_client_->activate(
				transition.identity, transition.prepare_request.idempotency_key(),
				operation_deadline()));
			if (!activated_or.is_ok()) {
				return failed(activated_or.error());
			}
			observation = std::move(activated_or).value();
			break;
		}
		case transition_reconciliation_action::QUERY_COMPLETION: {
			if (!wait_for_transition_poll_(std::chrono::steady_clock::now() +
						       TRANSITION_STATUS_POLL_INTERVAL)) {
				return failed(
					startup_reconciliation_ ?
						kinetum::common::status::deadline_exceeded(
							"Control Plane startup reconciliation deadline expired") :
						kinetum::common::status::unavailable(
							"Control Plane shutdown interrupted transition completion"));
			}
			auto queried_or = query_until_transport_observed();
			if (!queried_or.is_ok()) {
				return failed(queried_or.error());
			}
			observation = std::move(queried_or).value();
			break;
		}
		case transition_reconciliation_action::RETRY_ABORT: {
			KINETUM_LOG_DEBUG("cp", "cp.transition.abort",
					  "snapshot={} mutation_sequence={} target_epoch={}", snap.snapshot_id(),
					  transition.identity.mutation_sequence, transition.identity.target_epoch);
			auto aborted_or = reconcile_ambiguous_attempt(transition_client_->abort(
				transition.identity, transition.prepare_request.idempotency_key(),
				operation_deadline()));
			if (!aborted_or.is_ok()) {
				return failed(aborted_or.error());
			}
			observation = std::move(aborted_or).value();
			break;
		}
		case transition_reconciliation_action::PERSIST_COMPLETE: {
			const auto persisted =
				store_->complete_epoch_transition(transition.identity, kinetum::common::unix_time_ms());
			if (!persisted.is_ok()) {
				std::fputs("control_loop: DP transition completed but durable CP publication failed\n",
					   stderr);
				(void)std::fflush(stderr);
				std::terminate();
			}
			publish_completed_snapshot_(*transition.prepare_request.mutable_snapshot());
			KINETUM_LOG_INFO("cp", "cp.snapshot.applied",
					 "snapshot={} revision={} mutation_sequence={} epoch={}", active_snapshot_id_,
					 current_revision_, transition.identity.mutation_sequence,
					 transition.identity.target_epoch);
			return {transition.identity.target_epoch, kinetum::common::status::ok()};
		}
		case transition_reconciliation_action::PERSIST_ABORTED: {
			const bool local_abort_before_admission =
				transition.phase ==
					kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING &&
				observation.resolution == common::transition_identity_resolution::UNKNOWN_FUTURE &&
				observation.failure_code == kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE;
			if (!local_abort_before_admission && observation.failure_reason.empty()) {
				auto terminal_or = query_until_transport_observed();
				if (!terminal_or.is_ok()) {
					return failed(terminal_or.error());
				}
				observation = std::move(terminal_or).value();
				auto terminal_action_or =
					classify_transition_reconciliation(transition.phase, observation.resolution,
									   observation.state, observation.failure_code);
				if (!terminal_action_or.is_ok() ||
				    terminal_action_or.value() != transition_reconciliation_action::PERSIST_ABORTED) {
					return failed(kinetum::common::status::data_loss(
						"DP terminal Abort observation changed during exact reconciliation"));
				}
			}
			const auto failure =
				local_abort_before_admission ?
					kinetum::common::status::aborted(
						"durable abort intent preceded Data Plane admission") :
					durable_abort_status(observation.failure_code, observation.failure_reason);
			if (failure.code() == kinetum::common::status_code::INTERNAL_ERROR) {
				return failed(failure);
			}
			const auto persisted = store_->abort_epoch_transition(
				transition.identity, failure,
				local_abort_before_admission ? durable_abort_proof::LOCAL_PRECOMMIT_INTENT :
							       durable_abort_proof::EXACT_DP_PRECOMMIT_TERMINAL);
			if (!persisted.is_ok()) {
				std::fputs("control_loop: DP transition aborted but durable CP publication failed\n",
					   stderr);
				(void)std::fflush(stderr);
				std::terminate();
			}
			KINETUM_LOG_WARN("cp", "cp.transition.aborted",
					 "snapshot={} mutation_sequence={} target_epoch={} status={} reason={}",
					 snap.snapshot_id(), transition.identity.mutation_sequence,
					 transition.identity.target_epoch, common::status_code_name(failure.code()),
					 failure.message());
			return {0u, failure};
		}
		case transition_reconciliation_action::REQUIRE_JOINT_RESTART:
			if (startup_reconciliation_) {
				auto intent_or = store_->rollback_intent();
				auto active_or = store_->active_bootstrap();
				if (intent_or.is_ok() && active_or.is_ok() &&
				    intent_or->request.wait_for_mutation_sequence ==
					    transition.identity.mutation_sequence &&
				    intent_or->request.target_snapshot_id == active_or->snapshot().snapshot_id()) {
					const auto resolved =
						store_->discard_orphaned_epoch_transition_after_bootstrap();
					if (!resolved.is_ok()) {
						return failed(resolved);
					}
					publish_completed_snapshot_(*active_or->mutable_snapshot());
					return {active_or->active_epoch(), kinetum::common::status::ok()};
				}
			}
			return failed(kinetum::common::status::failed_precondition(
				"transition identity expired from DP history; joint restart is required"));
		case transition_reconciliation_action::PRESERVE_UNAVAILABLE:
			return failed(observation.application_status.is_ok() ?
					      kinetum::common::status::unavailable(
						      "Data Plane cannot currently reconcile this durable transition") :
					      observation.application_status);
		case transition_reconciliation_action::PRESERVE_UPDATE_FROZEN: {
			auto frozen = kinetum::common::status::failed_precondition(
				"Data Plane transition is update-frozen in RETIRING and requires recovery");
			frozen.set_details(observation.failure_reason);
			auto intent_or = store_->rollback_intent();
			if (intent_or.is_ok() &&
			    (intent_or->request.wait_for_mutation_sequence == transition.identity.mutation_sequence ||
			     intent_or->request.idempotency_key == transition.prepare_request.idempotency_key())) {
				const auto retained = store_->fail_rollback_intent(intent_or->request.idempotency_key,
										   compact_intent_failure(frozen));
				if (!retained.is_ok()) {
					std::terminate();
				}
			}
			return failed(frozen);
		}
		case transition_reconciliation_action::FAIL_CLOSED: {
			auto contradiction = kinetum::common::status::data_loss(
				"typed Data Plane transition evidence contradicts durable Control Plane intent");
			contradiction.set_details(observation.failure_reason);
			auto intent_or = store_->rollback_intent();
			if (intent_or.is_ok() &&
			    (intent_or->request.wait_for_mutation_sequence == transition.identity.mutation_sequence ||
			     intent_or->request.idempotency_key == transition.prepare_request.idempotency_key())) {
				const auto retained = store_->fail_rollback_intent(
					intent_or->request.idempotency_key, compact_intent_failure(contradiction));
				if (!retained.is_ok()) {
					std::terminate();
				}
			}
			return failed(contradiction);
		}
		}
	}
}

}  // namespace kinetum::cp
