// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_preparation.hpp
 * @brief Transient cold orchestration for one abortable epoch preparation.
 * @author Fleming Patel
 *
 * The coordinator owns durable transaction identity and phase. This component
 * owns only the transient PREPARE/RETIRE schedule needed to turn one immutable
 * candidate into exact per-context module artifacts. It dispatches at most one
 * callback per loaded image and per NUMA executor, retains every successful
 * token until the complete prepare set succeeds, and retires all partial state
 * before reporting ABORTED.
 *
 * Result eventfd notifications are wake-only. service_results() drains every
 * currently available executor result regardless of the observed wake count.
 * Cancellation is cooperative: a callback still outstanding after the
 * compiled grace deadline changes the component to FAILED_STOP and leaves all
 * foreign ownership intact for process termination.
 *
 * @par Thread Safety
 * Every method belongs to the sole runtime coordinator thread. Executor
 * threads touch only lifecycle task/result channels and stable operation
 * controls. The immutable candidate snapshot and module generation must
 * outlive this object while an operation is active.
 *
 * @par Performance
 * This is cold-path code. begin() allocates the complete bounded operation
 * table and every exact epoch arena before dispatching the first callback.
 * No method is reachable from packet execution.
 */

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/epoch/epoch_transition_coordinator.hpp"
#include "src/dp/epoch/epoch_transition_module_completion.hpp"
#include "src/dp/lifecycle/config_lifecycle_executor.hpp"

namespace kinetum::control::v1
{
class ConfigSnapshot;
}  // namespace kinetum::control::v1

namespace kinetum::dp::module
{
class module_runtime_generation;
}  // namespace kinetum::dp::module

namespace kinetum::dp
{

/**
 * @brief Add one positive duration without overflowing steady-clock time.
 * @param base Exact starting sample.
 * @param duration Exact positive compiled duration.
 * @return Exact future deadline or OUT_OF_RANGE.
 */
[[nodiscard]] common::status_or<std::chrono::steady_clock::time_point>
checked_transition_deadline(std::chrono::steady_clock::time_point base,
			    std::chrono::steady_clock::duration duration) noexcept;

/** @brief Exact transient preparation phase under coordinator ownership. */
enum class epoch_transition_preparation_phase : uint8_t {
	IDLE = 0,     ///< No transaction or module ownership is retained.
	PREPARING,    ///< PREPARE callbacks are pending or being dispatched.
	CANCELLING,   ///< No new PREPARE starts; outstanding callbacks must return.
	RETIRING,     ///< Successful partial artifacts are retiring in reverse order.
	PREPARED,     ///< Every module store owns the exact target epoch.
	ABORTED,      ///< Cleanup is complete and coordinator abort may publish.
	FAILED_STOP,  ///< Foreign ownership cannot be proven safe to unwind.
};

/**
 * @brief Own one transient module preparation beneath the global coordinator.
 */
class epoch_transition_preparation final : public epoch_transition_prepared_completion {
    public:
	/**
	 * @brief Create one idle operation owner from exact compiled policy.
	 *
	 * @param modules Stable module/lifecycle generation authority.
	 * @param policy Exact compiled transition timeout policy.
	 * @return Idle owner, or invalid/disabled policy or allocation failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<epoch_transition_preparation>>
	create(module::module_runtime_generation &modules, const common::compiled_epoch_transition_policy &policy);

	/** @brief Transient operation ownership cannot be copied. */
	epoch_transition_preparation(const epoch_transition_preparation &) = delete;
	/** @brief Transient operation ownership cannot be copy-assigned. */
	epoch_transition_preparation &operator=(const epoch_transition_preparation &) = delete;
	/** @brief Published operation identity cannot move. */
	epoch_transition_preparation(epoch_transition_preparation &&) = delete;
	/** @brief Published operation identity cannot be move-assigned. */
	epoch_transition_preparation &operator=(epoch_transition_preparation &&) = delete;

	/** @brief Destroy only an idle owner with no retained lifecycle state. */
	~epoch_transition_preparation() override;

	/**
	 * @brief Preallocate and dispatch one exact candidate preparation.
	 *
	 * All controls, table storage, and epoch arenas are created before the
	 * first foreign callback. Failure before dispatch leaves module stores
	 * unchanged. A post-dispatch failure enters cancellation/retirement and is
	 * observed through phase().
	 *
	 * @param identity Exact active coordinator identity.
	 * @param snapshot Immutable canonical candidate retained by the coordinator.
	 * @param admitted_at Coordinator steady-clock admission time.
	 * @return OK after the operation is live (possibly already PREPARED for an
	 *         empty module set), or failure with no foreign callback executed.
	 */
	[[nodiscard]] common::status begin(const common::epoch_transition_identity &identity,
					   const kinetum::control::v1::ConfigSnapshot &snapshot,
					   std::chrono::steady_clock::time_point admitted_at);

	/**
	 * @brief Drain every currently available lifecycle result and advance work.
	 *
	 * The caller may invoke this after a spurious or coalesced wake. Queue
	 * contents, never eventfd counts, determine ownership progress.
	 *
	 * @return OK unless an internal submission/storage operation fails; such a
	 *         failure starts exact cancellation and cleanup before return.
	 */
	[[nodiscard]] common::status service_results() noexcept;

	/**
	 * @brief Apply the currently due prepare, cancellation, or lease deadline.
	 *
	 * @param now Current coordinator steady-clock sample.
	 * @return OK after deterministic state advancement. FAILED_STOP is reported
	 *         through phase() so the caller can publish coordinator failure and
	 *         terminate without unwinding foreign ownership.
	 */
	[[nodiscard]] common::status service_deadline(std::chrono::steady_clock::time_point now) noexcept;

	/**
	 * @brief Request exact pre-commit cancellation or PREPARED retirement.
	 *
	 * Repeated requests preserve the first cause. PREPARING cancellation stops
	 * new dispatch, notifies every in-flight control, and waits for their exact
	 * results. PREPARED abort first withdraws each prepared store token, then
	 * retires in reverse context order.
	 *
	 * @param failure_code Exact non-NONE pre-commit terminal cause.
	 * @param diagnostic Bounded later by the coordinator terminal record.
	 * @param now Current coordinator steady-clock sample.
	 * @return OK after cancellation/retirement begins, or an exact state error.
	 */
	[[nodiscard]] common::status request_abort(epoch_transition_failure_code failure_code,
						   std::string_view diagnostic,
						   std::chrono::steady_clock::time_point now) noexcept;

	/**
	 * @brief Arm the behavior-driving prepared lease after coordinator publication.
	 *
	 * @param deadline Exact monotonic lease deadline published by the coordinator.
	 */
	void arm_prepared_lease(std::chrono::steady_clock::time_point deadline) noexcept;

	/** @copydoc epoch_transition_prepared_completion::completion_prepared */
	[[nodiscard]] bool
	completion_prepared(const common::epoch_transition_identity &identity) const noexcept override;
	/** @copydoc epoch_transition_prepared_completion::release_completion_preparation */
	void release_completion_preparation(const common::epoch_transition_identity &identity) noexcept override;

	/**
	 * @brief Reset one fully journaled ABORTED operation to IDLE.
	 *
	 * The coordinator must consume failure_code()/diagnostic() first. No module
	 * ownership remains at this point.
	 */
	void reset_after_abort() noexcept;

	/** @return Current exact transient phase. */
	[[nodiscard]] epoch_transition_preparation_phase phase() const noexcept;
	/** @return Whether one non-IDLE operation retains identity. */
	[[nodiscard]] bool active() const noexcept;
	/** @return Exact active identity, or nullptr while IDLE. */
	[[nodiscard]] const common::epoch_transition_identity *identity() const noexcept;
	/** @return First exact abort/failure cause, or NONE. */
	[[nodiscard]] epoch_transition_failure_code failure_code() const noexcept;
	/** @return First retained failure diagnostic, empty before abort. */
	[[nodiscard]] std::string_view diagnostic() const noexcept;

	/**
	 * @brief Return the next behavior-driving monotonic deadline.
	 *
	 * PREPARING returns its prepare deadline, CANCELLING with an outstanding
	 * callback returns its cancellation-grace deadline. PREPARED returns the
	 * original prepare deadline until the coordinator accepts completion, then
	 * its armed lease. RETIRING returns the current foreign RETIRE callback's
	 * grace deadline; no deadline is armed between reverse-order callbacks.
	 *
	 * @return Exact deadline, or nullopt when no timer is armed.
	 */
	[[nodiscard]] std::optional<std::chrono::steady_clock::time_point> next_deadline() const noexcept;

    private:
	/** @brief Per-context transient ownership state. */
	enum class context_phase : uint8_t {
		WAITING_PREPARE = 0,  ///< Arena is preallocated; callback not submitted.
		PREPARE_IN_FLIGHT,    ///< Executor owns one PREPARE task.
		PREPARED_TOKEN,	      ///< Coordinator table owns one successful token.
		STAGED,		      ///< Exact module store owns the prepared token.
		RETIRE_READY,	      ///< Table owns token withdrawn for RETIRE.
		RETIRE_IN_FLIGHT,     ///< Executor borrows token for exact RETIRE.
		RETIRED,	      ///< Callback and token retirement completed.
		EMPTY,		      ///< No artifact was ever created for this context.
	};

	/** @brief One fixed operation-table row indexed by exact module context. */
	struct context_operation {
		uint32_t module_image_index{0};		    ///< Exact loaded-image serialization owner.
		std::size_t executor_index{0};		    ///< Exact NUMA executor ordinal.
		context_phase phase{context_phase::EMPTY};  ///< Current linear ownership phase.
		uint64_t task_sequence{0};		    ///< Exact in-flight task identity, or zero.
		std::unique_ptr<lifecycle::lifecycle_operation_control> prepare_control;  ///< Stable cancel state.
		std::unique_ptr<lifecycle::lifecycle_operation_control> retire_control;	  ///< Stable RETIRE state.
		std::optional<lifecycle::epoch_arena_ownership> arena;			  ///< Pre-dispatch exact arena.
		std::optional<lifecycle::prepared_config_ownership> prepared;		  ///< Unstaged/withdrawn token.
	};

	/**
	 * @brief Adopt validated policy and one stable module generation.
	 * @param modules Exact generation authority.
	 * @param prepare_timeout Compiled positive timeout.
	 * @param cancellation_grace Compiled positive grace.
	 */
	epoch_transition_preparation(module::module_runtime_generation &modules,
				     std::chrono::steady_clock::duration prepare_timeout,
				     std::chrono::steady_clock::duration cancellation_grace) noexcept;

	/** @return OK after dispatching eligible contexts in canonical order, or the first submission failure. */
	[[nodiscard]] common::status dispatch_eligible_prepare_() noexcept;
	/**
	 * @brief Consume and validate one exact executor result.
	 * @param result Completed operation and any artifact ownership transferred by the executor.
	 * @return OK after reconciling the result with its submitted operation, or a validation failure.
	 */
	[[nodiscard]] common::status consume_result_(lifecycle::config_lifecycle_result &&result) noexcept;
	/**
	 * @return OK after staging successful tokens and completing preflight,
	 *         or the first staging/preflight failure.
	 */
	[[nodiscard]] common::status stage_complete_prepare_() noexcept;
	/**
	 * @brief Enter one-way cancellation while preserving the first cause.
	 * @param failure_code Typed cause of the cancellation.
	 * @param diagnostic Failure text copied into bounded owner storage when recording the first cause.
	 * @param now Current monotonic time used to establish cancellation grace.
	 */
	void begin_cancellation_(epoch_transition_failure_code failure_code, std::string_view diagnostic,
				 std::chrono::steady_clock::time_point now) noexcept;
	/**
	 * @brief Begin reverse retirement once every PREPARE result is owned.
	 * @return OK after first RETIRE dispatch or immediate clean ABORTED.
	 */
	[[nodiscard]] common::status begin_retirement_() noexcept;
	/**
	 * @brief Dispatch the next exact reverse-order RETIRE callback.
	 * @return OK after dispatch or clean ABORTED; otherwise ownership remains held.
	 */
	[[nodiscard]] common::status dispatch_next_retire_() noexcept;
	/** @brief Publish ABORTED only after every context owns no prepared state. */
	void publish_aborted_if_clean_() noexcept;
	/** @brief Enter terminal fail-stop without releasing uncertain ownership. */
	void enter_failed_stop_() noexcept;
	/** @return Whether any PREPARE callback remains in flight. */
	[[nodiscard]] bool prepare_in_flight_() const noexcept;
	/** @return Whether every context owns a successful PREPARE token. */
	[[nodiscard]] bool all_prepare_succeeded_() const noexcept;
	/** @return Whether every row, busy domain, and deadline owns zero cleanup state. */
	[[nodiscard]] bool all_contexts_clean_() const noexcept;

	module::module_runtime_generation *modules_{nullptr};		   ///< Stable exact lifecycle backend.
	std::chrono::steady_clock::duration prepare_timeout_{};		   ///< Exact plan-authored timeout.
	std::chrono::steady_clock::duration cancellation_grace_{};	   ///< Exact plan-authored grace.
	std::vector<context_operation> contexts_;			   ///< Complete preallocated transient table.
	std::vector<uint8_t> image_busy_;				   ///< One in-flight callback per image.
	std::vector<uint8_t> executor_busy_;				   ///< One in-flight callback per executor.
	common::epoch_transition_identity identity_{};			   ///< Exact active transaction identity.
	const kinetum::control::v1::ConfigSnapshot *snapshot_{nullptr};	   ///< Borrowed immutable candidate.
	std::chrono::steady_clock::time_point prepare_deadline_{};	   ///< Initial behavior deadline.
	std::chrono::steady_clock::time_point cancellation_deadline_{};	   ///< Non-returning callback bound.
	std::chrono::steady_clock::time_point retire_deadline_{};	   ///< Current RETIRE callback bound.
	std::chrono::steady_clock::time_point prepared_lease_deadline_{};  ///< Armed only after PREPARED.
	epoch_transition_preparation_phase phase_{epoch_transition_preparation_phase::IDLE};  ///< Exact phase.
	epoch_transition_failure_code failure_code_{epoch_transition_failure_code::NONE};     ///< First cause.
	epoch_transition_diagnostic diagnostic_{};  ///< First fixed-width cold-path diagnostic.
	bool module_prepared_published_{false};	    ///< Whether module stores published complete PREPARED identity.
};

}  // namespace kinetum::dp
