// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_completion.hpp
 * @brief Exact cold COMMITTING, RETIRING, and reclamation orchestration.
 * @author Fleming Patel
 *
 * One completion owner composes the sole coordinator phase authority, immutable
 * certificate, exact reader domain, module-generation claims, transient
 * preparation owner, and runtime-status publication. It owns only linear
 * completion resources and deadlines; it has no second global phase machine or
 * participant graph.
 *
 * Every per-context row, busy/frontier/ready set, lifecycle control, and claim
 * container is allocated before CONTROL_READY. Arming occurs before PREPARED
 * and performs no allocation. Commit starts reader grace before COMMITTING.
 * Reclamation begins only after exact execution/boundary and reader completion.
 * The process-generation safety latch is rechecked before ownership withdrawal,
 * result consumption, and terminal success, so a late nonfatal packet fault
 * cannot cross a reclamation edge as COMPLETE.
 *
 * @par Thread Safety
 * Every method belongs to the sole runtime coordinator thread. Lifecycle
 * executors access only accepted task/control borrows and publish results through
 * their existing bounded queues. Packet workers publish coherent observations
 * but never call this owner.
 *
 * @par Performance
 * Fixed execution performs no work. During COMMITTING or RETIRING, the
 * coordinator evaluates the existing allocation-free O(V+E) certificate at a
 * bounded one-millisecond cadence. No worker syscall, notification, shared
 * completion atomic, allocation, lock, or new descriptor is introduced.
 */

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <type_traits>
#include <vector>

#include <kinetum/algo/quiescence.hpp>
#include <kinetum/algo/single_writer_snapshot.hpp>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/epoch/epoch_transition_certificate.hpp"
#include "src/dp/epoch/epoch_transition_coordinator.hpp"
#include "src/dp/epoch/epoch_transition_module_completion.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/runtime_status.hpp"
#include "src/dp/publication_read_result.hpp"

namespace kinetum::dp
{

class epoch_transition_telemetry_completion;

/** @brief Coherent last active or completed certificate/grace observation. */
struct alignas(64) epoch_transition_completion_progress_snapshot {
	uint64_t publication_generation{0};	 ///< Coherent publication generation.
	uint64_t runtime_generation{0};		 ///< Exact materialized runtime generation.
	uint64_t transition_generation{0};	 ///< Exact mutation generation.
	uint64_t from_epoch{0};			 ///< Exact old epoch.
	uint64_t to_epoch{0};			 ///< Exact target epoch.
	uint64_t evaluated_monotonic_ns{0};	 ///< Last exact certificate evaluation; zero before one occurs.
	uint64_t grace_generation{0};		 ///< Exact reader-grace generation.
	uint64_t grace_started_monotonic_ns{0};	 ///< Exact grace publication time.
	uint64_t grace_completion_observed_monotonic_ns{0};  ///< First complete reader observation.
	uint64_t grace_finished_monotonic_ns{0};	     ///< Exact domain finish time.
	uint32_t execution_complete{0};			     ///< Exact complete execution participants.
	uint32_t execution_total{0};			     ///< Frozen execution participant count.
	uint32_t boundary_complete{0};			     ///< Exact complete boundaries.
	uint32_t boundary_total{0};			     ///< Frozen boundary count.
	uint32_t reader_complete{0};			     ///< Exact complete grace readers.
	uint32_t reader_total{0};			     ///< Frozen reader count.
	uint32_t fault_index{UINT32_MAX};		     ///< Compact contradiction index or sentinel.
	epoch_transition_certificate_state certificate_state{
		epoch_transition_certificate_state::INCOMPLETE};  ///< Last exact certificate state.
	epoch_transition_certificate_fault certificate_fault{
		epoch_transition_certificate_fault::NONE};  ///< Last exact certificate fault.
	bool transaction_active{false};			    ///< Whether completion still owns the transaction.
	bool ownership_withdrawn{false};		    ///< Whether old ownership withdrawal began.
	bool update_frozen{false};			    ///< Whether reader grace froze later updates.
	std::array<uint8_t, 15> padding{};		    ///< Explicit two-cache-line completion.
};

static_assert(sizeof(epoch_transition_completion_progress_snapshot) == 128u,
	      "completion progress observation must occupy two cache lines");
static_assert(alignof(epoch_transition_completion_progress_snapshot) == 64u,
	      "completion progress observation must retain cache-line alignment");
static_assert(std::is_standard_layout_v<epoch_transition_completion_progress_snapshot> &&
		      std::is_trivially_copyable_v<epoch_transition_completion_progress_snapshot>,
	      "completion progress observation must retain value semantics");

/**
 * @brief Validate one decoded completion record before projecting its transaction membership.
 * @param value Decoded record; the caller separately admits raw representation and source membership.
 * @return AVAILABLE for coherent certificate/grace state, otherwise INVALID_STATE.
 */
[[nodiscard]] publication_read_result
validate_epoch_completion_progress(const epoch_transition_completion_progress_snapshot &value) noexcept;

/** @brief One preallocated completion owner for an enabled runtime generation. */
class epoch_transition_completion final {
    public:
	/**
	 * @brief Construct and audit every exact borrowed completion authority.
	 *
	 * @param runtime_generation Exact materialized runtime generation.
	 * @param coordinator Sole global phase/snapshot/journal authority.
	 * @param certificate Immutable exact source graph.
	 * @param domain Exact reader grace domain borrowed by @p certificate.
	 * @param preparation Sole transient PREPARE owner.
	 * @param modules Sole module/context/lifecycle generation.
	 * @param runtime_status Sole readiness and epoch projection writer.
	 * @param telemetry Sole completed-bank aggregation and retirement owner.
	 * @param protocol_faults Process-generation protocol safety-fault authority.
	 * @param policy Exact enabled commit/retirement policy.
	 * @return Idle preallocated owner or exact membership/policy/allocation failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<epoch_transition_completion>>
	create(uint64_t runtime_generation, epoch_transition_coordinator &coordinator,
	       const epoch_transition_certificate &certificate, kinetum::algo::quiescence_domain &domain,
	       epoch_transition_prepared_completion &preparation, epoch_transition_module_completion &modules,
	       runtime_status_publication &runtime_status, epoch_transition_telemetry_completion &telemetry,
	       epoch_protocol_fault_latch &protocol_faults, const common::compiled_epoch_transition_policy &policy);

	epoch_transition_completion(const epoch_transition_completion &) = delete;
	epoch_transition_completion &operator=(const epoch_transition_completion &) = delete;
	epoch_transition_completion(epoch_transition_completion &&) = delete;
	epoch_transition_completion &operator=(epoch_transition_completion &&) = delete;
	/** @brief Destroy only an idle owner with no claim, control, grace, or failure state. */
	~epoch_transition_completion();

	/**
	 * @brief Arm every post-commit resource before coordinator PREPARED publication.
	 *
	 * @param identity Exact active PREPARING transaction.
	 * @return OK after complete all-or-none arming; failure leaves this owner idle.
	 */
	[[nodiscard]] common::status arm_before_prepared(const common::epoch_transition_identity &identity) noexcept;

	/**
	 * @brief Disarm one transaction only after coordinator ABORTED and preparation cleanup.
	 * @param identity Exact aborted transaction identity.
	 */
	void disarm_after_abort(const common::epoch_transition_identity &identity) noexcept;

	/**
	 * @brief Start grace and COMMITTING after complete preflight.
	 *
	 * It starts no worker transition itself; the owning command path invokes the
	 * worker trigger only after this method succeeds.
	 *
	 * @param identity Exact PREPARED transaction.
	 * @param now Exact coordinator steady-clock sample.
	 * @return OK after grace-before-COMMITTING publication; otherwise PREPARED is unchanged.
	 */
	[[nodiscard]] common::status begin_commit(const common::epoch_transition_identity &identity,
						  std::chrono::steady_clock::time_point now) noexcept;

	/**
	 * @brief Evaluate current certificate progress and advance bounded completion.
	 * @param now Exact coordinator steady-clock sample.
	 * @return OK after a not-yet-due no-op, progress, frozen RETIRING, or
	 *         COMPLETE; non-OK after typed fail-stop.
	 */
	[[nodiscard]] common::status service_progress(std::chrono::steady_clock::time_point now) noexcept;

	/**
	 * @brief Drain every available claimed RETIRE result and advance dispatch.
	 *
	 * The exact callback deadline is applied before any result ownership is
	 * consumed, so a late notification cannot turn expired work into COMPLETE.
	 *
	 * @param now Exact coordinator steady-clock sample.
	 * @return OK after bounded advancement; non-OK after typed fail-stop.
	 */
	[[nodiscard]] common::status service_results(std::chrono::steady_clock::time_point now) noexcept;

	/**
	 * @brief Apply one due commit, grace, or callback deadline.
	 * @param now Exact coordinator steady-clock sample.
	 * @return OK after freeze or no-op; non-OK after typed fail-stop.
	 */
	[[nodiscard]] common::status service_deadline(std::chrono::steady_clock::time_point now) noexcept;

	/** @return Next coordinator probe/behavior deadline, or nullopt while inactive/frozen. */
	[[nodiscard]] std::optional<std::chrono::steady_clock::time_point> next_deadline() const noexcept;
	/** @return true while one armed or committed identity owns completion resources. */
	[[nodiscard]] bool active() const noexcept;
	/** @return true after reclamation crosses its first-withdrawal boundary. */
	[[nodiscard]] bool ownership_withdrawn() const noexcept;
	/** @return Exact bound identity, or nullptr while idle. */
	[[nodiscard]] const common::epoch_transition_identity *identity() const noexcept;
	/**
	 * @brief Read the last coherent certificate and grace progress.
	 * @param[out] out Observer-owned value updated only on success.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result
	try_read_progress(epoch_transition_completion_progress_snapshot &out) const noexcept;

    private:
	/** @brief Linear state of one exact module-context retirement row. */
	enum class context_phase : uint8_t {
		IDLE = 0,   ///< Stable row has no transaction control or claim.
		ARMED,	    ///< Precommit control exists; no old claim is withdrawn.
		CLAIMED,    ///< Exact retained claim awaits eligible dispatch.
		READY,	    ///< Both reverse-domain predecessors are retired; row is queued.
		IN_FLIGHT,  ///< Executor owns one claimed RETIRE task.
		RETIRED,    ///< Exact SUCCESS consumed and issuing store is empty for E.
	};
	/** @brief Sentinel for a serialization domain with no unfinished context. */
	static constexpr std::size_t INVALID_CONTEXT_ORDINAL = std::numeric_limits<std::size_t>::max();

	/** @brief One stable preallocated module-retirement operation row. */
	struct context_operation {
		uint32_t context_index{UINT32_MAX};			      ///< Exact compiled context identity.
		uint32_t module_image_index{UINT32_MAX};		      ///< Exact image serialization owner.
		std::size_t executor_index{0};				      ///< Exact NUMA executor ordinal.
		std::size_t previous_image_ordinal{INVALID_CONTEXT_ORDINAL};  ///< Next lower context in this image.
		std::size_t previous_executor_ordinal{
			INVALID_CONTEXT_ORDINAL};	   ///< Next lower context on this executor.
		context_phase phase{context_phase::IDLE};  ///< Current linear row state.
		uint64_t task_sequence{0};		   ///< In-flight task identity, or zero.
		std::optional<lifecycle::lifecycle_operation_control> control;	///< Stable one-shot deadline.
		std::optional<module::module_retirement_claim> claim;		///< Exact store-bound claim.
	};

	/** @brief Exact active completion observation interval; never a behavior deadline. */
	static constexpr auto OBSERVATION_INTERVAL = std::chrono::milliseconds(1);
	/** @brief Pair of role-typed compiled behavior durations. */
	struct behavior_timeouts {
		std::chrono::steady_clock::duration commit{};	   ///< Completion-only execution deadline.
		std::chrono::steady_clock::duration retirement{};  ///< Reader/callback retirement deadline.
	};
	/** @brief Role-typed preallocated callback serialization and ready state. */
	struct serialization_state {
		std::vector<uint8_t> image_busy;	     ///< One in-flight callback per image.
		std::vector<uint8_t> executor_busy;	     ///< One in-flight task per executor.
		std::vector<std::size_t> image_frontier;     ///< Highest unfinished context per image.
		std::vector<std::size_t> executor_frontier;  ///< Highest unfinished context per executor.
		std::vector<std::size_t> ready_ordinals;     ///< Preallocated LIFO of independent ready contexts.
	};

	/**
	 * @brief Adopt one completely audited preallocated owner.
	 * @param runtime_generation Exact materialized generation.
	 * @param coordinator Sole global phase/store/journal authority.
	 * @param certificate Immutable exact source graph.
	 * @param domain Exact reader grace owner.
	 * @param preparation Sole PREPARED bookkeeping handoff.
	 * @param modules Sole module completion authority.
	 * @param runtime_status Sole status projection writer.
	 * @param telemetry Sole completed-bank aggregation and retirement owner.
	 * @param protocol_faults Process-generation protocol safety-fault authority.
	 * @param contexts Stable preallocated context rows.
	 * @param context_count Complete context population.
	 * @param serialization Preallocated image/executor busy/frontier/ready state.
	 * @param timeouts Role-typed compiled commit and retirement durations.
	 */
	epoch_transition_completion(
		uint64_t runtime_generation, epoch_transition_coordinator &coordinator,
		const epoch_transition_certificate &certificate, kinetum::algo::quiescence_domain &domain,
		epoch_transition_prepared_completion &preparation, epoch_transition_module_completion &modules,
		runtime_status_publication &runtime_status, epoch_transition_telemetry_completion &telemetry,
		epoch_protocol_fault_latch &protocol_faults, std::unique_ptr<context_operation[]> contexts,
		std::size_t context_count, serialization_state serialization, behavior_timeouts timeouts) noexcept;

	/** @return OK after dispatching every currently independent reverse-canonical claim. */
	[[nodiscard]] common::status dispatch_eligible_() noexcept;
	/**
	 * @brief Queue one context exactly when both reverse-domain frontiers reach it.
	 * @param ordinal Candidate dense context ordinal or the invalid sentinel.
	 */
	void enqueue_if_ready_(std::size_t ordinal) noexcept;
	/**
	 * @brief Consume one exact claimed RETIRE result.
	 * @param result Sole executor result ownership.
	 * @param now Exact coordinator clock sample.
	 * @return OK after exact claim completion; non-OK after typed fail-stop.
	 */
	[[nodiscard]] common::status consume_result_(lifecycle::config_lifecycle_result &&result,
						     std::chrono::steady_clock::time_point now) noexcept;
	/**
	 * @brief Begin module claim transfer only after exact reader completion.
	 * @param now Exact coordinator clock sample.
	 * @return OK after claim/dispatch or immediate module-free completion.
	 */
	[[nodiscard]] common::status begin_reclamation_(std::chrono::steady_clock::time_point now) noexcept;
	/**
	 * @brief Publish terminal ownership or fail stop on a newly latched protocol fault.
	 * @param now Exact terminal coordinator clock sample.
	 * @return OK after COMPLETE, or the typed fail-stop status selected before
	 *         final publication.
	 */
	[[nodiscard]] common::status publish_complete_or_fail_stop_(std::chrono::steady_clock::time_point now) noexcept;
	/**
	 * @brief Enter typed fail-stop without resolving any uncertain claim.
	 * @param failure_code Exact non-freeze failure classification.
	 * @param diagnostic Compile-time-proven static diagnostic.
	 * @param now Exact failure observation time.
	 * @return Stable non-OK status after coordinator FAILED_STOP publication.
	 */
	[[nodiscard]] common::status fail_stop_(epoch_transition_failure_code failure_code,
						common::static_status_text diagnostic,
						std::chrono::steady_clock::time_point now) noexcept;
	/**
	 * @brief Enter typed fail-stop while preserving one owned failure diagnostic.
	 * @param failure_code Exact non-freeze failure classification.
	 * @param failure Complete non-OK status transferred from the failed operation.
	 * @param now Exact failure observation time.
	 * @return Reclassified failure after coordinator FAILED_STOP publication.
	 */
	[[nodiscard]] common::status fail_stop_(epoch_transition_failure_code failure_code, common::status failure,
						std::chrono::steady_clock::time_point now) noexcept;
	/** @return true only while the exact preallocated module projection remains unchanged. */
	[[nodiscard]] bool module_membership_exact_() const noexcept;
	/** @return true only when every module row reached exact RETIRED ownership. */
	[[nodiscard]] bool all_contexts_retired_() const noexcept;
	/** @brief Reset a clean armed/complete transaction to reusable IDLE storage. */
	void reset_clean_() noexcept;
	/**
	 * @brief Convert one exact nonzero steady sample to coordinator nanoseconds.
	 * @param now Exact steady-clock sample.
	 * @return Positive nanoseconds or zero for an invalid representation.
	 */
	[[nodiscard]] static uint64_t monotonic_nanoseconds_(std::chrono::steady_clock::time_point now) noexcept;
	/**
	 * @brief Advance the next observation point without exceeding behavior deadline.
	 * @param now Exact current coordinator sample.
	 */
	void schedule_next_probe_(std::chrono::steady_clock::time_point now) noexcept;
	/** @brief Publish last_progress_ or terminate on sequence exhaustion. */
	void publish_progress_or_terminate_() noexcept;

	/** @brief Fixed completion-progress field count excluding publication generation. */
	static constexpr std::size_t PROGRESS_FIELD_COUNT = 21u;
	/** @brief Bounded coherent read attempts. */
	static constexpr std::size_t PROGRESS_OBSERVATION_ATTEMPTS = 8u;

	uint64_t runtime_generation_{0};			       ///< Exact materialized generation.
	epoch_transition_coordinator *coordinator_{nullptr};	       ///< Sole global phase/store owner.
	const epoch_transition_certificate *certificate_{nullptr};     ///< Immutable proof graph.
	kinetum::algo::quiescence_domain *domain_{nullptr};	       ///< Exact grace owner.
	epoch_transition_prepared_completion *preparation_{nullptr};   ///< Sole PREPARED handoff owner.
	epoch_transition_module_completion *modules_{nullptr};	       ///< Module/lifecycle authority.
	runtime_status_publication *runtime_status_{nullptr};	       ///< Sole epoch projection writer.
	epoch_transition_telemetry_completion *telemetry_{nullptr};    ///< Observation-only bank aggregation owner.
	epoch_protocol_fault_latch *protocol_faults_{nullptr};	       ///< Transition-safety fault authority.
	std::unique_ptr<context_operation[]> contexts_;		       ///< Stable exact context rows.
	std::size_t context_count_{0};				       ///< Complete context population.
	std::vector<uint8_t> image_busy_;			       ///< One callback per loaded image.
	std::vector<uint8_t> executor_busy_;			       ///< One task per NUMA executor.
	std::vector<std::size_t> image_frontier_;		       ///< Highest unfinished image context.
	std::vector<std::size_t> executor_frontier_;		       ///< Highest unfinished executor context.
	std::vector<std::size_t> ready_ordinals_;		       ///< Fixed ready-context storage.
	std::size_t ready_count_{0};				       ///< Occupied ready prefix.
	std::size_t in_flight_count_{0};			       ///< Exact submitted callback population.
	std::size_t retired_count_{0};				       ///< Exact completed context population.
	std::chrono::steady_clock::duration commit_timeout_{};	       ///< Compiled completion deadline.
	std::chrono::steady_clock::duration retirement_timeout_{};     ///< Compiled update-freeze deadline.
	common::epoch_transition_identity identity_{};		       ///< Exact bound transaction identity.
	uint64_t grace_generation_{0};				       ///< Exact active reader grace.
	std::chrono::steady_clock::time_point commit_deadline_{};      ///< COMMITTING fail-stop deadline.
	std::chrono::steady_clock::time_point retirement_deadline_{};  ///< RETIRING deadline.
	std::chrono::steady_clock::time_point latest_retirement_deadline_{};	///< Precommit overflow proof.
	std::chrono::steady_clock::time_point next_probe_{};			///< Coordinator-only observation wake.
	bool ownership_withdrawn_{false};					///< Irreversible withdrawal has begun.
	bool failed_stop_{false};						///< Coordinator failure is terminal.
	epoch_transition_completion_progress_snapshot last_progress_{};		///< Sole owner progress staging.
	kinetum::algo::single_writer_snapshot<PROGRESS_FIELD_COUNT> progress_;	///< Foreign progress publication.
};

}  // namespace kinetum::dp
