// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_coordinator.hpp
 * @brief Sole cold owner of one dataplane epoch-transition generation.
 * @author Fleming Patel
 *
 * The coordinator composes the exact phase machine, immutable participant
 * projection, complete ConfigSnapshot two-slot store, one generation token,
 * bounded terminal history, allocator high watermarks, one immutable live
 * candidate, and coherent observer publication. Fixed Bootstrap is the first
 * wire operation serialized by the runtime command mailbox. Public passive
 * Prepare, Activate, Abort, and Status consume these same coordinator methods;
 * no test-only state path exists.
 *
 * @par Thread Safety
 * Exactly one bound coordinator thread invokes mutating and journal-query
 * methods. Any number of foreign observers may call try_read_progress() or
 * read the immutable participant set concurrently. No packet worker or gRPC
 * producer calls this class directly.
 *
 * @par Performance
 * Creation performs all structural and capacity allocation. The first exact
 * Bootstrap identity retention may allocate once as bounded cold-path work.
 * Phase changes, participant binding, history insertion, and progress
 * publication are bounded and allocate no memory.
 */

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <kinetum/algo/single_writer_snapshot.hpp>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/config_snapshot_epoch_store.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/epoch/frozen_transition_participants.hpp"
#include "src/dp/epoch/transition_state_machine.hpp"
#include "src/dp/epoch/transition_types.hpp"
#include "src/dp/publication_read_result.hpp"

namespace kinetum::control::v1
{
class ConfigSnapshot;
}

namespace kinetum::provider
{
struct compiled_provider_topology;
}  // namespace kinetum::provider

namespace kinetum::dp
{

enum class epoch_transition_failure_code : uint8_t;

/** @brief One coherent observer-owned coordinator progress value. */
struct epoch_transition_progress_snapshot {
	uint64_t publication_generation{0};  ///< Monotonic observation generation.
	epoch_transition_phase phase{epoch_transition_phase::AWAITING_BOOTSTRAP};  ///< Exact global phase.
	uint64_t active_epoch{0};			 ///< Last globally completed active epoch.
	common::sha256_digest active_validation_hash{};	 ///< Content paired with the globally completed epoch.
	uint64_t target_epoch{0};			 ///< Current bootstrap or transition target.
	uint64_t mutation_sequence{0};			 ///< Frozen mutation identity, or zero.
	uint64_t allocated_epoch_high_watermark{0};	 ///< Greatest admitted epoch allocation.
	uint64_t mutation_sequence_high_watermark{0};	 ///< Greatest admitted mutation allocation.
	bool participants_frozen{false};		 ///< Whether one live generation binds membership.
	uint32_t execution_participant_count{0};	 ///< Immutable worker/lane population.
	uint32_t region_count{0};			 ///< Immutable logical-region population.
	uint32_t boundary_count{0};			 ///< Immutable boundary population.
	uint32_t source_participant_count{0};		 ///< Immutable source-worker population.
	uint32_t sink_participant_count{0};		 ///< Immutable sink-worker population.
	uint32_t module_context_count{0};		 ///< Immutable mutable-context population.
	uint32_t quiescence_reader_count{0};		 ///< Current exact config-reader population.
	uint32_t terminal_history_size{0};		 ///< Retained terminal-result population.
	epoch_transition_outcome last_terminal_outcome{epoch_transition_outcome::NONE};	 ///< Latest terminal result.
	bool retirement_frozen{false};	///< Whether RETIRING timed out before ownership withdrawal.
};

static_assert(std::is_trivially_copyable_v<epoch_transition_progress_snapshot>,
	      "transition progress snapshots must remain fixed-width values");
static_assert(std::is_standard_layout_v<epoch_transition_progress_snapshot>,
	      "transition progress snapshots must retain standard layout");

/** @brief One active or retained transaction projected without diagnostic prose. */
struct epoch_transition_telemetry_transaction_snapshot {
	bool present{false};						   ///< Whether remaining fields are semantic.
	common::epoch_transition_identity identity{};			   ///< Complete transaction identity.
	uint64_t from_epoch{0};						   ///< Exact admission baseline.
	uint64_t to_epoch{0};						   ///< Exact target epoch.
	uint64_t admitted_monotonic_ns{0};				   ///< Exact admission timestamp.
	uint64_t prepared_monotonic_ns{0};				   ///< Exact PREPARED edge, or zero.
	uint64_t prepared_lease_deadline_monotonic_ns{0};		   ///< Active lease deadline, or zero.
	uint64_t prepared_lease_deadline_unix_ms{0};			   ///< Informational lease projection, or zero.
	uint64_t commit_started_monotonic_ns{0};			   ///< Exact COMMITTING edge, or zero.
	uint64_t retiring_started_monotonic_ns{0};			   ///< Exact RETIRING edge, or zero.
	uint64_t failure_observed_monotonic_ns{0};			   ///< Exact failure observation, or zero.
	uint64_t terminal_monotonic_ns{0};				   ///< Exact terminal edge, or zero.
	epoch_transition_outcome outcome{epoch_transition_outcome::NONE};  ///< Exact terminal outcome.
	epoch_transition_failure_code failure_code{};			   ///< Typed cause.
	bool retirement_frozen{false};					   ///< Whether reader timeout froze updates.
};

static_assert(std::is_standard_layout_v<epoch_transition_telemetry_transaction_snapshot> &&
		      std::is_trivially_copyable_v<epoch_transition_telemetry_transaction_snapshot>,
	      "transition telemetry transaction snapshots must retain value semantics");

/** @brief Coherent current and latest-terminal transaction publication. */
struct epoch_transition_telemetry_snapshot {
	uint64_t publication_generation{0};					   ///< Coherent publication generation.
	epoch_transition_telemetry_transaction_snapshot active{};		   ///< Current generation, if any.
	epoch_transition_telemetry_transaction_snapshot latest_terminal{};	   ///< Latest bounded terminal, if any.
	std::array<uint64_t, EPOCH_PROTOCOL_FAULT_COUNT> protocol_fault_counts{};  ///< Cold-owner typed faults.
};

static_assert(std::is_standard_layout_v<epoch_transition_telemetry_snapshot> &&
		      std::is_trivially_copyable_v<epoch_transition_telemetry_snapshot>,
	      "transition telemetry snapshots must retain value semantics");

/** @brief Current prepared-lease representation owned by one transaction. */
enum class epoch_transition_prepared_lease_state : uint8_t {
	NOT_ARMED = 0,	///< PREPARING has no prepared lease or deadline.
	ARMED,		///< PREPARED state owns exact monotonic and Unix projections.
};

static_assert(sizeof(epoch_transition_prepared_lease_state) == sizeof(uint8_t),
	      "prepared lease state must remain one byte");

/** @brief Fixed diagnostic categories produced by abort, freeze, and fail-stop paths. */
enum class epoch_transition_failure_code : uint8_t {
	NONE = 0,			     ///< No failure or abort diagnostic exists.
	EXPLICIT_ABORT,			     ///< Exact pre-commit abort request ended preparation.
	SHUTDOWN_ABORT,			     ///< Owner shutdown ended an admitted pre-commit transaction.
	PREPARE_FAILURE,		     ///< Module preparation failed before commit.
	PREPARE_CANCELLED,		     ///< Cooperative cancellation completed exact cleanup.
	PREPARE_DEADLINE_EXCEEDED,	     ///< Compiled preparation deadline expired.
	PREPARED_LEASE_EXPIRED,		     ///< PREPARED lease expired before commit.
	COMMIT_DEADLINE_EXCEEDED,	     ///< Completion-only execution/boundary deadline expired.
	CERTIFICATE_CONTRADICTION,	     ///< Coherent completion evidence contradicted exact identity.
	RETIREMENT_GRACE_DEADLINE_EXCEEDED,  ///< Reader grace froze updates before ownership withdrawal.
	RETIRE_CALLBACK_FAILURE,	     ///< One claimed module RETIRE callback failed.
	RETIRE_CALLBACK_DEADLINE_EXCEEDED,   ///< One claimed RETIRE callback remained unresolved.
	COMMIT_SHUTDOWN,		     ///< Shutdown interrupted completion-only COMMITTING.
	PROTOCOL_FAULT,			     ///< A witnessed ordered-transition safety fault blocked success.
};

static_assert(sizeof(epoch_transition_failure_code) == sizeof(uint8_t), "transition failure code must remain one byte");

/**
 * @brief Classify one exact abortable pre-commit terminal cause.
 * @param code Candidate fixed failure classification.
 * @return true only for a real non-NONE pre-commit cause.
 */
[[nodiscard]] constexpr bool is_precommit_failure(epoch_transition_failure_code code) noexcept
{
	switch (code) {
	case epoch_transition_failure_code::EXPLICIT_ABORT:
	case epoch_transition_failure_code::SHUTDOWN_ABORT:
	case epoch_transition_failure_code::PREPARE_FAILURE:
	case epoch_transition_failure_code::PREPARE_CANCELLED:
	case epoch_transition_failure_code::PREPARE_DEADLINE_EXCEEDED:
	case epoch_transition_failure_code::PREPARED_LEASE_EXPIRED:
		return true;
	case epoch_transition_failure_code::COMMIT_DEADLINE_EXCEEDED:
	case epoch_transition_failure_code::CERTIFICATE_CONTRADICTION:
	case epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED:
	case epoch_transition_failure_code::RETIRE_CALLBACK_FAILURE:
	case epoch_transition_failure_code::RETIRE_CALLBACK_DEADLINE_EXCEEDED:
	case epoch_transition_failure_code::COMMIT_SHUTDOWN:
	case epoch_transition_failure_code::PROTOCOL_FAULT:
	case epoch_transition_failure_code::NONE:
		return false;
	}
	return false;
}

/** @brief Fixed-width bounded diagnostic retained without dynamic ownership. */
struct epoch_transition_diagnostic {
	std::array<char, common::MAX_TRANSITION_DIAGNOSTIC_BYTES> bytes{};  ///< Exact retained prefix bytes.
	uint16_t size{0};						    ///< Number of semantic bytes in the array.
};

static_assert(std::is_trivially_copyable_v<epoch_transition_diagnostic>,
	      "transition diagnostics must remain fixed-width trivially copyable values");
static_assert(std::is_standard_layout_v<epoch_transition_diagnostic>,
	      "transition diagnostics must retain standard layout");
static_assert(sizeof(epoch_transition_diagnostic) == 258u, "transition diagnostics must remain exactly 258 bytes");

/** @brief Presence bit for a real PREPARING duration producer. */
inline constexpr uint8_t TRANSITION_PREPARE_DURATION_PRESENT = UINT8_C(1) << 0u;
/** @brief Presence bit for a real completion-only commit duration producer. */
inline constexpr uint8_t TRANSITION_COMMIT_DURATION_PRESENT = UINT8_C(1) << 1u;
/** @brief Presence bit for a real retirement duration producer. */
inline constexpr uint8_t TRANSITION_RETIREMENT_DURATION_PRESENT = UINT8_C(1) << 2u;
/** @brief Complete legal phase-duration presence mask. */
inline constexpr uint8_t TRANSITION_DURATION_PRESENCE_MASK = TRANSITION_PREPARE_DURATION_PRESENT |
							     TRANSITION_COMMIT_DURATION_PRESENT |
							     TRANSITION_RETIREMENT_DURATION_PRESENT;

/** @brief One fixed terminal result retained in chronological history. */
struct epoch_transition_terminal_result {
	common::epoch_transition_identity identity{};			   ///< Exact transaction identity.
	uint64_t from_epoch{0};						   ///< Active baseline at admission.
	uint64_t to_epoch{0};						   ///< Exact transaction target.
	uint64_t admitted_monotonic_ns{0};				   ///< Exact admission timestamp.
	uint64_t terminal_monotonic_ns{0};				   ///< Exact terminal timestamp.
	uint64_t prepare_duration_ns{0};				   ///< Real PREPARING duration.
	uint64_t commit_duration_ns{0};					   ///< Real COMMITTING duration.
	uint64_t retirement_duration_ns{0};				   ///< Real RETIRING duration.
	uint8_t duration_presence{0};					   ///< Explicit valid-duration bits.
	epoch_transition_outcome outcome{epoch_transition_outcome::NONE};  ///< Terminal state.
	epoch_transition_failure_code failure_code{epoch_transition_failure_code::NONE};  ///< Exact cause.
	epoch_transition_diagnostic diagnostic{};					  ///< Bounded failure text.
};

static_assert(std::is_trivially_copyable_v<epoch_transition_terminal_result>,
	      "terminal transition results must remain fixed-width values");
static_assert(std::is_standard_layout_v<epoch_transition_terminal_result>,
	      "terminal transition results must retain standard layout");
static_assert(sizeof(epoch_transition_terminal_result) == 400u,
	      "terminal transition results must remain exactly 400 bytes");

/**
 * @brief Fixed observation returned by Prepare, Activate, Abort, and Status.
 *
 * Coordinator-resolved results populate the complete state projection.
 * Producer-side validation or mailbox failure occurs before a coordinator
 * observation exists; only its typed resolution, bounded diagnostic, and an
 * identity when validation reached that point are semantic. Remaining default
 * fields on such a non-OK result are not state observations.
 */
struct epoch_transition_transaction_observation {
	common::transition_identity_resolution resolution{
		common::transition_identity_resolution::INVALID};  ///< Exact typed lookup/admission result.
	common::epoch_transition_identity identity{};		   ///< Exact queried or admitted identity.
	common::epoch_transition_watermarks watermarks{};	   ///< Current durable allocation high watermarks.
	epoch_transition_phase phase{
		epoch_transition_phase::AWAITING_BOOTSTRAP};  ///< Active phase; IDLE for a terminal identity.
	epoch_transition_outcome outcome{epoch_transition_outcome::NONE};  ///< Retained terminal outcome.
	uint64_t from_epoch{0};		     ///< Active baseline at transaction admission.
	uint64_t to_epoch{0};		     ///< Exact target epoch.
	uint64_t admitted_monotonic_ns{0};   ///< Exact admission timestamp when retained.
	uint64_t terminal_monotonic_ns{0};   ///< Exact terminal timestamp when retained.
	uint64_t prepare_duration_ns{0};     ///< Real PREPARING duration when terminal.
	uint64_t commit_duration_ns{0};	     ///< Real COMMITTING duration when terminal.
	uint64_t retirement_duration_ns{0};  ///< Real RETIRING duration when terminal.
	uint8_t duration_presence{0};	     ///< Explicit valid-duration bits.
	epoch_transition_prepared_lease_state lease_state{
		epoch_transition_prepared_lease_state::NOT_ARMED};  ///< Discriminates deadline fields.
	uint64_t prepared_lease_deadline_monotonic_ns{0};	    ///< Valid only for ARMED.
	uint64_t prepared_lease_deadline_unix_ms{0};		    ///< Valid only for ARMED.
	epoch_transition_failure_code failure_code{epoch_transition_failure_code::NONE};  ///< Exact cause.
	epoch_transition_diagnostic diagnostic{};					  ///< Bounded cause text.
};

static_assert(std::is_trivially_copyable_v<epoch_transition_transaction_observation>,
	      "transition observations must remain fixed-width trivially copyable values");
static_assert(std::is_standard_layout_v<epoch_transition_transaction_observation>,
	      "transition observations must retain standard layout");

/** @brief Allocation-free coordinator operation result and typed classification. */
struct epoch_transition_operation_result {
	common::status_code code{common::status_code::INTERNAL_ERROR};	///< Explicitly replaced application outcome.
	epoch_transition_transaction_observation observation{};		///< Exact typed result.

	/** @return true when the operation resolved an admissible, active, or terminal observation. */
	[[nodiscard]] constexpr bool is_ok() const noexcept
	{
		return code == common::status_code::OK;
	}
};

static_assert(std::is_trivially_copyable_v<epoch_transition_operation_result>,
	      "transition operation results must remain fixed-width trivially copyable values");
static_assert(std::is_standard_layout_v<epoch_transition_operation_result>,
	      "transition operation results must retain standard layout");
static_assert(!epoch_transition_operation_result{}.is_ok(),
	      "an unproduced transition operation result must fail closed");

/**
 * @brief Own one globally serialized epoch-transition generation.
 *
 * The coordinator is created before provider materialization. Its participant
 * set and terminal storage never change capacity. A live generation borrows
 * the state machine's exact identity and the immutable participant object by
 * address, proving both bindings without copying either authority or repeating
 * the topology audit.
 */
class epoch_transition_coordinator final {
    public:
	/**
	 * @brief Create one empty AWAITING_BOOTSTRAP coordinator.
	 *
	 * @param topology Sole compiled runtime topology and transition policy.
	 * @return Coordinator with a complete frozen participant projection and
	 *         initial coherent progress, or a pre-materialization failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<epoch_transition_coordinator>>
	create(const provider::compiled_provider_topology &topology);

	/** @brief Coordinator authorities cannot be copied. */
	epoch_transition_coordinator(const epoch_transition_coordinator &) = delete;
	/** @brief Coordinator authorities cannot be copy-assigned. */
	epoch_transition_coordinator &operator=(const epoch_transition_coordinator &) = delete;
	/** @brief Coordinator authorities cannot be moved after publication. */
	epoch_transition_coordinator(epoch_transition_coordinator &&) = delete;
	/** @brief Coordinator authorities cannot be move-assigned. */
	epoch_transition_coordinator &operator=(epoch_transition_coordinator &&) = delete;

	/**
	 * @brief Destroy an idle coordinator with no snapshot or live generation.
	 *
	 * Destruction in BOOTSTRAPPING, PREPARING, PREPARED, COMMITTING,
	 * RETIRING, FAILED_STOP, with a live generation token, or with unresolved
	 * snapshot ownership terminates.
	 */
	~epoch_transition_coordinator();

	/** @return Immutable participant authority constructed once at startup. */
	[[nodiscard]] const frozen_transition_participants &participants() const noexcept;
	/** @return Exact current global phase. */
	[[nodiscard]] epoch_transition_phase phase() const noexcept;
	/** @return Last globally completed active epoch, or zero before Bootstrap. */
	[[nodiscard]] uint64_t active_epoch() const noexcept;
	/** @return Store emptiness under sole coordinator ownership; not a foreign observation seam. */
	[[nodiscard]] bool snapshot_store_empty() const noexcept;
	/** @return Exact PREPARED snapshot-store epoch, or zero while candidate preparation is incomplete. */
	[[nodiscard]] uint64_t prepared_snapshot_epoch() const noexcept;

	/**
	 * @brief Bind the sole byte-exact startup retry identity.
	 *
	 * Binding is the first coordinator mutation and precedes snapshot staging or
	 * foreign activation. Every later command after a clean admitted failure must
	 * match the retained bytes exactly.
	 *
	 * @param serialized_request Deterministic complete Bootstrap request bytes.
	 * @param plan_content_hash Exact canonical plan hash from the request.
	 * @param epoch Exact active Bootstrap epoch named by the request.
	 * @param watermarks Exact durable allocator authority carried by the request.
	 * @return OK for the first or an exact repeated identity; otherwise an exact
	 *         malformed, foreign-plan, conflicting-retry, allocation, or state
	 *         status without changing the phase or snapshot store.
	 */
	[[nodiscard]] common::status bind_bootstrap_request(std::string_view serialized_request,
							    std::string_view plan_content_hash, uint64_t epoch,
							    common::epoch_transition_watermarks watermarks);

	/**
	 * @brief Begin Bootstrap and stage its exact snapshot artifact atomically.
	 *
	 * A staging failure returns the state machine to AWAITING_BOOTSTRAP and
	 * preserves caller ownership of @p artifact.
	 *
	 * @param epoch Exact bound Bootstrap epoch.
	 * @param artifact Sole immutable artifact ownership, consumed only on success.
	 * @return OK after BOOTSTRAPPING and PREPARED-slot publication; otherwise no
	 *         phase or store mutation survives.
	 */
	[[nodiscard]] common::status
	stage_bootstrap_snapshot(uint64_t epoch, std::unique_ptr<const config_snapshot_artifact> &artifact);

	/**
	 * @brief Preflight the complete non-failing Bootstrap snapshot publication.
	 *
	 * @param epoch Exact staged Bootstrap epoch.
	 * @return OK after exact state/store preflight; otherwise no mutation.
	 */
	[[nodiscard]] common::status preflight_bootstrap_publication(uint64_t epoch);

	/**
	 * @brief Publish the preflighted Bootstrap snapshot and enter IDLE exactly.
	 *
	 * Fallible pre-activation work may follow preflight while the sole owner
	 * leaves the snapshot store unchanged; such failure must call
	 * abort_bootstrap(). Once owner activation begins, this preflight makes the
	 * snapshot/phase commit non-failing. Any impossible state/store disagreement
	 * terminates instead of publishing split truth.
	 *
	 * @param epoch Exact staged Bootstrap epoch.
	 */
	void publish_bootstrap_or_terminate(uint64_t epoch) noexcept;

	/**
	 * @brief Discard one recoverably failed pre-activation Bootstrap attempt.
	 *
	 * @param epoch Exact staged Bootstrap epoch.
	 * @return OK only after the prepared snapshot slot is empty and global phase
	 *         is AWAITING_BOOTSTRAP; malformed ownership performs no mutation.
	 */
	[[nodiscard]] common::status abort_bootstrap(uint64_t epoch);

	/**
	 * @brief Retire the sole published snapshot after final worker quiescence.
	 *
	 * @param epoch Exact globally active epoch.
	 * @return OK after the store is empty; a pre-claim mismatch performs no
	 *         mutation, while an impossible post-claim mismatch terminates.
	 */
	[[nodiscard]] common::status retire_published_after_quiescence(uint64_t epoch);

	/**
	 * @brief Preflight every coordinator-owned post-commit resource.
	 * @param identity Exact active PREPARED transaction.
	 * @param commit_started_monotonic_ns Exact prospective commit start.
	 * @return OK only when snapshot publication/claim and phase transition are complete.
	 */
	[[nodiscard]] common::status preflight_begin_commit(const common::epoch_transition_identity &identity,
							    uint64_t commit_started_monotonic_ns) const noexcept;

	/**
	 * @brief Cross the irreversible commit edge after exact external preflight.
	 * @param identity Exact active PREPARED transaction.
	 * @param commit_started_monotonic_ns Exact preflighted commit start.
	 */
	void begin_commit_or_terminate(const common::epoch_transition_identity &identity,
				       uint64_t commit_started_monotonic_ns) noexcept;

	/**
	 * @brief Preflight global target publication and RETIRING entry.
	 * @param identity Exact COMMITTING transaction.
	 * @param retiring_started_monotonic_ns Exact prospective RETIRING start.
	 * @return OK only when snapshot N/E publication can no longer fail.
	 */
	[[nodiscard]] common::status preflight_begin_retiring(const common::epoch_transition_identity &identity,
							      uint64_t retiring_started_monotonic_ns) const noexcept;

	/**
	 * @brief Publish target snapshot while retaining the old epoch.
	 * @param identity Exact COMMITTING transaction.
	 */
	void publish_target_snapshot_or_terminate(const common::epoch_transition_identity &identity) noexcept;

	/**
	 * @brief Publish RETIRING last after every target-activation projection.
	 * @param identity Exact COMMITTING transaction.
	 * @param retiring_started_monotonic_ns Exact preflighted RETIRING start.
	 */
	void enter_retiring_or_terminate(const common::epoch_transition_identity &identity,
					 uint64_t retiring_started_monotonic_ns) noexcept;

	/**
	 * @brief Revalidate the exact retained snapshot before module retirement starts.
	 * @param identity Exact RETIRING transaction.
	 * @return OK only when later snapshot claim/completion is bounded and exact.
	 */
	[[nodiscard]] common::status
	preflight_retained_snapshot(const common::epoch_transition_identity &identity) const noexcept;

	/**
	 * @brief Claim and complete the exact retained old snapshot.
	 * @param identity Exact RETIRING transaction.
	 */
	void retire_retained_snapshot_or_terminate(const common::epoch_transition_identity &identity) noexcept;

	/**
	 * @brief Latch nonfatal update-frozen RETIRING before any ownership withdrawal.
	 * @param identity Exact RETIRING transaction.
	 * @param observed_monotonic_ns Exact timeout observation.
	 * @param diagnostic Bounded trusted source diagnostic.
	 */
	void freeze_retirement_or_terminate(const common::epoch_transition_identity &identity,
					    uint64_t observed_monotonic_ns, std::string_view diagnostic) noexcept;

	/**
	 * @brief Enter active-generation fail-stop with one typed retained cause.
	 * @param identity Exact active transaction.
	 * @param observed_monotonic_ns Exact nonzero failure observation.
	 * @param failure_code Exact completion-only failure category.
	 * @param diagnostic Bounded trusted source diagnostic.
	 */
	void fail_active_or_terminate(const common::epoch_transition_identity &identity, uint64_t observed_monotonic_ns,
				      epoch_transition_failure_code failure_code, std::string_view diagnostic) noexcept;

	/**
	 * @brief Journal COMPLETE and publish IDLE after all old ownership and grace are gone.
	 * @param identity Exact RETIRING transaction.
	 * @param terminal_monotonic_ns Exact completion timestamp.
	 */
	void complete_retirement_or_terminate(const common::epoch_transition_identity &identity,
					      uint64_t terminal_monotonic_ns) noexcept;

	/**
	 * @brief Admit one exact immutable candidate and freeze participant identity.
	 *
	 * @param identity Exact already validated transition identity.
	 * @param candidate Sole immutable plan-bound candidate; consumed only on
	 *        successful new admission and retained outside the snapshot store.
	 * @param admitted_monotonic_ns Exact nonzero coordinator clock sample.
	 * @return Typed active, terminal, conflict, watermark, or admission result.
	 */
	[[nodiscard]] epoch_transition_operation_result
	admit_prepare(const common::epoch_transition_identity &identity,
		      std::unique_ptr<const config_snapshot_artifact> &candidate,
		      uint64_t admitted_monotonic_ns) noexcept;

	/**
	 * @brief Borrow the immutable candidate for one exact PREPARING identity.
	 * @param identity Exact active transaction identity.
	 * @return Immutable candidate snapshot, or nullptr unless identity and phase
	 *         both match the sole active generation.
	 */
	[[nodiscard]] const kinetum::control::v1::ConfigSnapshot *
	preparing_candidate_snapshot(const common::epoch_transition_identity &identity) const noexcept;

	/**
	 * @brief Preflight future snapshot publication and retained claim before PREPARED.
	 * @param identity Exact active PREPARING transaction.
	 * @return OK only when candidate ownership and the empty exact slot can later
	 *         publish N and retain E without an undiscovered claim failure.
	 */
	[[nodiscard]] common::status
	preflight_completion_arm(const common::epoch_transition_identity &identity) const noexcept;

	/**
	 * @brief Record completion-resource arming after exact external preflight.
	 * @param identity Exact active PREPARING transaction.
	 * @return OK after the sole arm edge; otherwise no mutation.
	 */
	[[nodiscard]] common::status arm_completion(const common::epoch_transition_identity &identity) noexcept;

	/**
	 * @brief Stage snapshot ownership, arm its lease, and publish PREPARED last.
	 * @param identity Exact active PREPARING identity.
	 * @param prepared_monotonic_ns Exact completed module-PREPARE timestamp.
	 * @param lease_deadline_monotonic_ns Nonzero behavior-driving deadline.
	 * @param lease_deadline_unix_ms Nonzero informational deadline projection.
	 * @return Exact PREPARED observation or pre-publication rejection.
	 */
	[[nodiscard]] epoch_transition_operation_result mark_prepared(const common::epoch_transition_identity &identity,
								      uint64_t prepared_monotonic_ns,
								      uint64_t lease_deadline_monotonic_ns,
								      uint64_t lease_deadline_unix_ms) noexcept;

	/**
	 * @brief Suppress foreign progress while PREPARED ownership is withdrawn.
	 *
	 * The global phase remains PREPARED until cleanup completes, but its complete
	 * ownership claim stops being observable before the first module token is
	 * withdrawn. Internal commands return status-only unavailable during this
	 * interval. The exact held Abort/Prepare contexts receive the later terminal
	 * result.
	 *
	 * @param identity Exact active PREPARED transaction identity.
	 * @return OK after first or exact idempotent suppression; otherwise no change.
	 */
	[[nodiscard]] common::status
	begin_prepared_abort_cleanup(const common::epoch_transition_identity &identity) noexcept;

	/**
	 * @brief Abort the exact PREPARING or PREPARED generation and record one terminal result.
	 *
	 * @param identity Exact active generation identity.
	 * @param terminal_monotonic_ns Exact nonzero coordinator clock sample.
	 * @param failure_code Exact explicit-abort or shutdown cause.
	 * @param diagnostic Bounded source diagnostic retained as a fixed prefix.
	 * @return Typed terminal, conflict, stale, expired, or state result.
	 */
	[[nodiscard]] epoch_transition_operation_result
	abort_before_commit(const common::epoch_transition_identity &identity, uint64_t terminal_monotonic_ns,
			    epoch_transition_failure_code failure_code, std::string_view diagnostic) noexcept;

	/**
	 * @brief Abort the exact active pre-commit transaction for owner shutdown.
	 *
	 * @param terminal_monotonic_ns Exact nonzero coordinator clock sample.
	 * @return Typed terminal result, or state failure when no abortable
	 *         transaction exists.
	 */
	[[nodiscard]] epoch_transition_operation_result
	abort_active_for_shutdown(uint64_t terminal_monotonic_ns) noexcept;

	/**
	 * @brief Resolve one exact identity without creating or mutating work.
	 *
	 * @param identity Exact already validated transaction identity.
	 * @return Typed active, terminal, stale, inconsistent, expired, conflict,
	 *         or unknown-future observation.
	 */
	[[nodiscard]] epoch_transition_operation_result
	query_transaction(const common::epoch_transition_identity &identity) const noexcept;

	/** @return Exact retained old snapshot epoch, or zero outside RETIRING. */
	[[nodiscard]] uint64_t retained_snapshot_epoch() const noexcept;
	/** @return Whether reader-grace timeout latched update-frozen RETIRING. */
	[[nodiscard]] bool retirement_frozen() const noexcept;

	/**
	 * @brief Read one coherent coordinator progress publication.
	 *
	 * @param out Observer-owned value updated only on success.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result try_read_progress(epoch_transition_progress_snapshot &out) const noexcept;

	/**
	 * @brief Read one coherent active/latest-terminal transaction publication.
	 * @param[out] out Observer-owned value updated only on success.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result
	try_read_telemetry(epoch_transition_telemetry_snapshot &out) const noexcept;

	/**
	 * @brief Bind the process-generation first-fault authority once.
	 * @param runtime_generation Exact nonzero materialized runtime identity.
	 * @param faults Exact latch shared with workers and completion.
	 * @return OK for first or exact repeated binding; FAILED_PRECONDITION otherwise.
	 */
	[[nodiscard]] common::status bind_protocol_faults(uint64_t runtime_generation,
							  epoch_protocol_fault_latch &faults) noexcept;

	/**
	 * @brief Test exact process-generation protocol-fault ownership.
	 * @param runtime_generation Candidate materialized runtime identity.
	 * @param faults Candidate latch object identity.
	 * @return true only when both values name the bound process authority.
	 */
	[[nodiscard]] bool owns_protocol_faults(uint64_t runtime_generation,
						const epoch_protocol_fault_latch &faults) const noexcept;

	/** @return Immutable terminal-result capacity fixed from plan policy. */
	[[nodiscard]] std::size_t terminal_history_capacity() const noexcept;
	/** @return Current retained terminal-result count. */
	[[nodiscard]] std::size_t terminal_history_size() const noexcept;
	/** @return Exact compiled prepared-lease policy retained for PREPARED arming. */
	[[nodiscard]] std::chrono::steady_clock::duration prepared_lease_timeout() const noexcept;

	/**
	 * @brief Return one terminal result in oldest-to-newest order.
	 *
	 * The sole coordinator owner may call this only under serialized ownership.
	 * Foreign RPC readers consume a copied command result rather than reading
	 * mutable history directly.
	 *
	 * @param ordinal Chronological zero-based ordinal.
	 * @return Immutable record, or null when out of range.
	 */
	[[nodiscard]] const epoch_transition_terminal_result *terminal_result(std::size_t ordinal) const noexcept;

    private:
	/** @brief Exact active generation token bound to immutable participants. */
	struct active_generation {
		const common::epoch_transition_identity *identity{nullptr};   ///< State-machine identity binding.
		const frozen_transition_participants *participants{nullptr};  ///< Identity-bound membership.
		std::unique_ptr<const config_snapshot_artifact> candidate;    ///< Immutable PREPARING candidate.
		uint64_t admitted_monotonic_ns{0};			      ///< Exact monotonic admission timestamp.
		uint64_t prepared_monotonic_ns{0};			      ///< Exact module-PREPARE completion time.
		epoch_transition_prepared_lease_state lease_state{
			epoch_transition_prepared_lease_state::NOT_ARMED};  ///< PREPARING owns no deadline.
		uint64_t prepared_lease_deadline_monotonic_ns{0};	    ///< Valid only when ARMED.
		uint64_t prepared_lease_deadline_unix_ms{0};		    ///< Valid only when ARMED.
		uint64_t commit_started_monotonic_ns{0};		    ///< Exact irreversible commit start.
		uint64_t retiring_started_monotonic_ns{0};		    ///< Exact RETIRING phase start.
		uint64_t failure_observed_monotonic_ns{0};		    ///< Exact frozen/fail-stop observation.
		epoch_transition_failure_code failure_code{
			epoch_transition_failure_code::NONE};  ///< Active frozen/fail-stop cause.
		epoch_transition_diagnostic diagnostic{};      ///< Active bounded cause text.
		bool retirement_frozen{false};		       ///< Update-frozen RETIRING latch.
	};

	/** @brief Fixed fields published through one generic coherent snapshot. */
	enum progress_field : std::size_t {
		PHASE = 0,			   ///< Exact global coordinator phase.
		ACTIVE_EPOCH,			   ///< Last globally completed active epoch.
		ACTIVE_VALIDATION_HASH_0,	   ///< First lossless active-content word.
		ACTIVE_VALIDATION_HASH_1,	   ///< Second lossless active-content word.
		ACTIVE_VALIDATION_HASH_2,	   ///< Third lossless active-content word.
		ACTIVE_VALIDATION_HASH_3,	   ///< Fourth lossless active-content word.
		TARGET_EPOCH,			   ///< Current bootstrap or transition target.
		MUTATION_SEQUENCE,		   ///< Current live mutation identity.
		ALLOCATED_EPOCH_HIGH_WATERMARK,	   ///< Greatest admitted epoch allocation.
		MUTATION_SEQUENCE_HIGH_WATERMARK,  ///< Greatest admitted mutation allocation.
		PARTICIPANTS_FROZEN,		   ///< Whether one generation binds membership.
		EXECUTION_PARTICIPANT_COUNT,	   ///< Immutable execution-participant population.
		REGION_COUNT,			   ///< Immutable logical-region population.
		BOUNDARY_COUNT,			   ///< Immutable boundary population.
		SOURCE_COUNT,			   ///< Immutable source-participant population.
		SINK_COUNT,			   ///< Immutable sink-participant population.
		MODULE_CONTEXT_COUNT,		   ///< Immutable mutable-context population.
		QUIESCENCE_READER_COUNT,	   ///< Current exact config-reader population.
		TERMINAL_HISTORY_SIZE,		   ///< Retained terminal-result population.
		LAST_TERMINAL_OUTCOME,		   ///< Latest terminal result.
		ABORT_CLEANUP_IN_PROGRESS,	   ///< Suppress false PREPARED observation.
		RETIREMENT_FROZEN,		   ///< Nonfatal reader-grace timeout latch.
	};

	static constexpr std::size_t PROGRESS_FIELD_COUNT = RETIREMENT_FROZEN + 1u;  ///< Fixed payload width.
	static constexpr std::size_t OBSERVATION_ATTEMPTS = 8u;	 ///< Bounded coherent-read attempts.
	/** @brief Fields per active/latest transaction in the telemetry publication. */
	static constexpr std::size_t TELEMETRY_TRANSACTION_FIELD_COUNT = 24u;
	/** @brief Complete two-transaction telemetry publication width. */
	static constexpr std::size_t TELEMETRY_FIELD_COUNT =
		2u * TELEMETRY_TRANSACTION_FIELD_COUNT + EPOCH_PROTOCOL_FAULT_COUNT;

	/**
	 * @brief Adopt complete immutable and preallocated coordinator state.
	 *
	 * @param participants Sole frozen participant authority.
	 * @param transitions_enabled Exact compiled policy enablement.
	 * @param history_capacity Exact zero or plan-authored terminal capacity.
	 * @param prepared_lease_timeout Exact compiled live-transition lease policy.
	 */
	epoch_transition_coordinator(std::unique_ptr<const frozen_transition_participants> participants,
				     bool transitions_enabled, uint32_t history_capacity,
				     std::chrono::steady_clock::duration prepared_lease_timeout);

	/**
	 * @brief Map one primitive state rejection without changing coordinator state.
	 * @param result Exact state-machine result.
	 * @param operation Stable operation identity.
	 * @return Mapped platform status.
	 */
	[[nodiscard]] static common::status state_error_(epoch_state_result result, const char *operation);
	/** @brief Publish the complete current progress or terminate on sequence exhaustion. */
	void publish_progress_or_terminate_() noexcept;

	/**
	 * @brief Capture one cold protocol fault and its typed cumulative count.
	 * @param fault Complete immutable numeric first-fault candidate.
	 */
	void record_protocol_fault_(const epoch_protocol_first_fault &fault) noexcept;

	friend class epoch_transition_completion;
	/**
	 * @brief Append one non-failing terminal record with deterministic eviction.
	 * @param result Exact fixed-width terminal record.
	 */
	void append_terminal_result_(const epoch_transition_terminal_result &result) noexcept;
	/**
	 * @brief Resolve exact active/journal/watermark identity without mutation.
	 * @param identity Exact queried transaction identity.
	 * @param status_query Whether an advancing unknown identity is a lookup rather than admission.
	 * @return Typed current, terminal, conflict, watermark, or unknown observation.
	 */
	[[nodiscard]] epoch_transition_operation_result
	resolve_identity_(const common::epoch_transition_identity &identity, bool status_query) const noexcept;
	/**
	 * @brief Build one current active-transaction observation.
	 * @param resolution Exact typed identity classification.
	 * @return Complete fixed-width active observation.
	 */
	[[nodiscard]] epoch_transition_transaction_observation
	active_observation_(common::transition_identity_resolution resolution) const noexcept;
	/**
	 * @brief Build one retained terminal observation.
	 * @param result Exact journal record.
	 * @return Complete fixed-width terminal observation.
	 */
	[[nodiscard]] epoch_transition_transaction_observation
	terminal_observation_(const epoch_transition_terminal_result &result) const noexcept;
	/**
	 * @brief Build one bounded diagnostic prefix without allocation.
	 * @param diagnostic Candidate trusted diagnostic bytes.
	 * @return Fixed-width retained prefix.
	 */
	[[nodiscard]] static epoch_transition_diagnostic bounded_diagnostic_(std::string_view diagnostic) noexcept;

	std::unique_ptr<const frozen_transition_participants> participants_;  ///< Immutable generation membership.
	config_snapshot_epoch_store snapshots_;		      ///< Sole complete-snapshot lifecycle authority.
	epoch_transition_state_machine state_;		      ///< Sole global phase authority.
	std::optional<active_generation> active_generation_;  ///< One global live-generation token.
	std::vector<epoch_transition_terminal_result> terminal_history_;	    ///< Preallocated circular storage.
	std::size_t terminal_history_begin_{0};					    ///< Oldest retained history slot.
	std::size_t terminal_history_size_{0};					    ///< Retained history population.
	kinetum::algo::single_writer_snapshot<PROGRESS_FIELD_COUNT> progress_;	    ///< Foreign observation channel.
	kinetum::algo::single_writer_snapshot<TELEMETRY_FIELD_COUNT> telemetry_;    ///< Exact transaction observations.
	std::array<uint64_t, EPOCH_PROTOCOL_FAULT_COUNT> protocol_fault_counts_{};  ///< Coordinator-owned faults.
	epoch_protocol_fault_latch *protocol_faults_{nullptr};	///< Shared immutable first-fault authority.
	uint64_t protocol_runtime_generation_{0};  ///< Exact materialized generation for cold fault identity.
	std::string bound_bootstrap_request_;	   ///< Pre-publication startup retry identity.
	uint64_t bound_bootstrap_epoch_{0};	   ///< Epoch carried by the bound request.
	common::epoch_transition_watermarks bound_bootstrap_watermarks_{};  ///< Bound durable startup authority.
	common::epoch_transition_watermarks watermarks_{};  ///< Published durable allocation high watermarks.
	common::sha256_digest active_validation_hash_{};    ///< Content of the last globally COMPLETE epoch.
	std::chrono::steady_clock::duration prepared_lease_timeout_{};	///< Exact prepared-lease plan policy.
	epoch_transition_outcome last_terminal_outcome_{epoch_transition_outcome::NONE};  ///< Latest result.
	bool transitions_enabled_{false};		 ///< Exact compiled policy authority.
	bool bootstrap_publication_preflighted_{false};	 ///< Whether commit is proven non-failing.
	bool abort_cleanup_in_progress_{false};		 ///< Whether PREPARED ownership is being withdrawn.
	bool completion_armed_{false};			 ///< Whether all post-commit resources are preflighted.
};

}  // namespace kinetum::dp
