// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file config_store.hpp
 * @brief Descriptor-rooted immutable snapshot corpus and atomic CP authority.
 * @author Fleming Patel
 *
 * The Control Plane store has two persistence domains:
 *
 * - `snap_<sha256(snapshot_id)>.pbtxt` is an append-only corpus of terminal
 *   canonical snapshots. Active content may coexist with its exact corpus
 *   object; projection deduplicates that byte-identical pair.
 * - `TRANSITION_AUTHORITY.pb` is the sole mutable record. Its deterministic
 *   private protobuf atomically binds the exact active Bootstrap wire request,
 *   at most one current/latest transition, optional commit-confirmed state,
 *   one exact guardrails policy, and one durable rollback intent.
 *
 * Every other root entry fails the closed file grammar. Durable state
 * replacement is one descriptor-relative rename; corpus objects are
 * create-only and remain semantically valid if publication stops before a
 * later authority replacement.
 *
 * @par Thread Safety
 * All public operations participate in one shared-mutex domain. Readers take
 * shared ownership. Canonicalization, corpus publication, authority replacement,
 * and corresponding in-memory publication take exclusive ownership. Production
 * live allocation is invoked by the CP single-writer control loop.
 *
 * @par Performance
 * Persistence, protobuf validation, hashing, and fsync are bounded cold-path
 * work. Corpus lookup uses binary search over a sorted contiguous vector. No
 * method may execute on a packet worker or module callback.
 */

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#include "gen/kinetum/control/internal/v1/transition_authority.pb.h"
#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/durable_directory.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/cp/bootstrap_startup.hpp"

namespace kinetum::cp
{

/** @brief Exact reconstructed view of one durable CP transition record. */
struct durable_epoch_transition_view {
	kinetum::dataplane::v1::PrepareConfigSnapshotRequest prepare_request;  ///< Exact future DP request.
	kinetum::common::epoch_transition_identity identity{};	///< Reconstructed complete fixed identity.
	kinetum::control::internal::v1::DurableEpochTransitionPhase phase{
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_UNSPECIFIED};  ///< Durable CP phase.
	kinetum::common::v1::Status terminal_status;  ///< Present only for terminal phases.
	uint32_t confirm_timeout_ms{0};		      ///< Exact retained commit-confirmed policy.
	bool exact_retry{false};		      ///< True when no new allocation was published.
};

/** @brief Compact last-COMPLETE content and allocation authority. */
struct durable_active_runtime_view {
	std::string snapshot_id;				  ///< Exact active semantic identity.
	int64_t revision{0};					  ///< Exact active snapshot revision.
	uint64_t active_epoch{0};				  ///< Last globally COMPLETE epoch.
	uint64_t allocated_epoch_high_watermark{0};		  ///< Greatest consumed epoch allocation.
	uint64_t mutation_sequence_high_watermark{0};		  ///< Greatest consumed mutation allocation.
	kinetum::common::sha256_digest plan_content_hash{};	  ///< Raw admitted plan identity.
	kinetum::common::sha256_digest active_validation_hash{};  ///< Raw active snapshot identity.
};

/** @brief Compact current/latest transition facts needed by a runtime fence. */
struct durable_runtime_transition_view {
	kinetum::common::epoch_transition_identity identity{};	///< Exact fixed transition identity.
	kinetum::control::internal::v1::DurableEpochTransitionPhase phase{
		kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_UNSPECIFIED};  ///< Durable phase.
	std::string snapshot_id;  ///< Exact target content identity.
	int64_t revision{0};	  ///< Exact target content revision.
};

/** @brief One lock-coherent compact active authority plus optional transition. */
struct durable_runtime_authority_view {
	durable_active_runtime_view active;			    ///< Last durable COMPLETE truth.
	std::optional<durable_runtime_transition_view> transition;  ///< Current/latest transition, when retained.
};

/** @brief Exact durable guardrails policy and retry result. */
struct durable_guardrails_policy_view {
	kinetum::control::v1::GuardrailsPolicy policy;	///< Canonical policy bytes.
	uint64_t generation{0};				///< Exact nonzero policy generation.
	kinetum::common::sha256_digest policy_hash{};	///< SHA-256 of deterministic policy bytes.
	bool exact_retry{false};			///< Whether no durable replacement occurred.
};

/** @brief Exact terminal result of one commit-confirmed mutation. */
struct durable_confirmation_result {
	std::string snapshot_id;	///< Exact confirmed active snapshot.
	uint64_t epoch{0};		///< Exact confirmed active epoch.
	int64_t revision{0};		///< Exact confirmed active revision.
	uint64_t time_remaining_ms{0};	///< Nonnegative time retained by first success.
	bool exact_retry{false};	///< Whether the retained success was returned.
};

/** @brief One bounded immutable projection of the snapshot corpus. */
struct snapshot_listing_page {
	std::vector<kinetum::control::v1::SnapshotInfo> snapshots;  ///< Strictly sorted bounded page rows.
	std::string next_page_token;  ///< Empty at the exact end; otherwise the next-page authority.
	uint64_t total_count{0};      ///< Complete logical row count for this listing identity.
};

/** @brief Typed source of one durable rollback safety intent. */
enum class rollback_intent_cause : uint8_t {
	UNSPECIFIED = 0,	  ///< Rejecting sentinel; every producer authors a cause.
	COMMIT_CONFIRM_DEADLINE,  ///< Restart-stable operator-confirmation deadline.
	THRESHOLD_DEGRADATION,	  ///< Exact threshold detector decision.
	CORRELATED_DEGRADATION,	  ///< Exact correlation plus attribution decision.
	BOUNDARY_ACK_TIMEOUT,	  ///< Exact generation-local ACK wait violation.
};

static_assert(sizeof(rollback_intent_cause) == sizeof(uint8_t), "rollback intent cause must remain one byte");

/** @brief Complete immutable input for one durable rollback intent. */
struct rollback_intent_request {
	std::string target_snapshot_id;				   ///< Exact retained rollback content.
	std::string guarded_snapshot_id;			   ///< Configuration whose evidence triggered intent.
	uint64_t guarded_epoch{0};				   ///< Exact guarded active epoch.
	int64_t guarded_revision{0};				   ///< Exact guarded active revision.
	kinetum::common::sha256_digest guarded_validation_hash{};  ///< Exact guarded content hash.
	uint64_t wait_for_mutation_sequence{0};			   ///< Owning transition to converge, or zero.
	uint64_t policy_generation{0};				   ///< Exact detector policy; zero for confirm timeout.
	uint64_t runtime_generation{0};				   ///< Exact observed DP process generation.
	std::string idempotency_key;				   ///< Retained transition key for every retry.
	rollback_intent_cause cause{rollback_intent_cause::UNSPECIFIED};  ///< Required typed cause.
	uint64_t observed_monotonic_ns{0};				  ///< Exact collection-time observation.
	int64_t created_unix_ms{0};					  ///< Bounded durable audit projection.
};

/** @brief Durable rollback intent plus optional terminal failure latch. */
struct durable_rollback_intent_view {
	rollback_intent_request request;	   ///< Complete immutable desired action.
	kinetum::common::status terminal_failure;  ///< Non-OK only after terminal failure.
};

/** @brief Exact evidence authorizing one durable ABORTED publication. */
enum class durable_abort_proof : uint8_t {
	LOCAL_PRECOMMIT_INTENT = 0,	  ///< CP authored abort before attempting commit.
	EXACT_DP_PRECOMMIT_TERMINAL = 1,  ///< Typed DP terminal proves commit never began.
};

static_assert(sizeof(durable_abort_proof) == sizeof(uint8_t), "durable abort proof must remain one byte");

/**
 * @brief Durable active/transition authority and immutable snapshot-corpus owner.
 *
 * Construction is available only through `open()`, so an instance always owns
 * an admitted directory and a fully cross-validated in-memory projection. The
 * class never repairs malformed persistent state or infers one identity field
 * from another.
 */
class config_store {
    public:
	/** @brief Disable store aliasing. */
	config_store(const config_store &) = delete;

	/** @brief Disable store aliasing by assignment. */
	config_store &operator=(const config_store &) = delete;

	/** @brief Disable movement because callers retain the store address. */
	config_store(config_store &&) = delete;

	/** @brief Disable movement by assignment. */
	config_store &operator=(config_store &&) = delete;

	/** @brief Destroy the store after all borrowers have stopped. */
	~config_store() = default;

	/**
	 * @brief Admit one durable root and fully load its exact state.
	 *
	 * The root is admitted through `durable_directory`. Exact abandoned private
	 * publications are durably discarded before ordinary enumeration. Unknown
	 * files, links, special objects, malformed records, corpus
	 * identity disagreement, and invalid cross-record state reject the store.
	 *
	 * @param absolute_root Exact absolute durable store directory.
	 * @return Unique initialized store, or the first admission, allocation,
	 *         parsing, canonical-form, cross-record, or integrity failure.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<config_store>>
	open(const std::filesystem::path &absolute_root);

	/**
	 * @brief Reconcile optional admitted bootstrap content with durable truth.
	 *
	 * A fresh authority publishes epoch/allocation/mutation identities 1/1/1.
	 * Pristine 1/1/1 state requires exact canonical snapshot and plan agreement.
	 * After any durable allocation, the validated store is sole active-content
	 * truth while the supplied plan identity must still match exactly; the
	 * deployment's initial snapshot cannot overwrite a later COMPLETE state. An
	 * exact corpus object with the same snapshot ID is admitted only when its
	 * canonical bytes are equal.
	 *
	 * @param authority Admitted source authority, or null for control-only or
	 *        durable-restart startup.
	 * @return OK after exact import/reuse; otherwise the first conflict,
	 *         validation, publication, or identity failure.
	 */
	[[nodiscard]] kinetum::common::status reconcile_bootstrap(const bootstrap_startup_authority *authority);

	/**
	 * @brief Return the exact nested active Bootstrap wire request.
	 *
	 * @return Copy of the sole active request, or NOT_FOUND on a fresh
	 *         control-only store.
	 */
	[[nodiscard]] kinetum::common::status_or<kinetum::dataplane::v1::BootstrapConfigSnapshotRequest>
	active_bootstrap() const;

	/**
	 * @brief Read compact active and transition identity under one store lock.
	 *
	 * This is the Control Plane half of a runtime observation fence. It prevents
	 * callers from combining an active record from one authority replacement
	 * with transition phase or identity from another. Canonical hashes replace
	 * bulk snapshot copying; only bounded identities cross the read boundary.
	 *
	 * @return One coherent durable view, or NOT_FOUND without active authority.
	 */
	[[nodiscard]] kinetum::common::status_or<durable_runtime_authority_view> runtime_authority() const;

	/**
	 * @brief Publish one immutable terminal canonical snapshot corpus object.
	 *
	 * An exact retry performs no I/O. The same semantic ID with different
	 * canonical bytes rejects. Exact equality with active content is valid and
	 * creates one logical snapshot projected once by `list_snapshot_page()`.
	 *
	 * @param canonical Fully admitted terminal canonical content.
	 * @return OK after first publication or exact retry; otherwise the first
	 *         canonical, collision, serialization, allocation, or I/O failure.
	 */
	[[nodiscard]] kinetum::common::status
	stage_snapshot(const kinetum::common::canonical_config_snapshot &canonical);

	/**
	 * @brief Canonicalize, stage, allocate, and atomically persist one transition.
	 *
	 * Candidate canonicalization uses the active snapshot's exact module set and
	 * the shared plan/candidate implementation. Both allocation values advance
	 * together before a DP request can be sent. An exact retained retry returns
	 * the same reconstructed request without rewriting state. A conflicting key,
	 * content identity, terminal result, or nonterminal overlap fails closed.
	 * When one durable safety intent owns this exact target and key, allocation
	 * atomically rebinds its wait identity from any completed predecessor to the
	 * newly allocated rollback mutation and requires a zero confirmation timeout.
	 * No safety rollback may arm a nested confirmation deadline; an unconfirmed
	 * configuration additionally admits only its exact rollback target.
	 *
	 * @param candidate Candidate complete live ConfigSnapshot.
	 * @param idempotency_key Required 1..256-byte printable-ASCII identity.
	 * @param confirm_timeout_ms Zero, or the commit-confirmed timeout retained
	 *        until exact completion.
	 * @return Exact durable transition view, or the first canonicalization,
	 *         identity, overlap, wrap, corpus, or authority-publication failure.
	 */
	[[nodiscard]] kinetum::common::status_or<durable_epoch_transition_view>
	begin_epoch_transition(const kinetum::control::v1::ConfigSnapshot &candidate, std::string_view idempotency_key,
			       uint32_t confirm_timeout_ms);

	/**
	 * @brief Return the exact current/latest durable transition record.
	 *
	 * @return Reconstructed view, or NOT_FOUND when no record is retained.
	 */
	[[nodiscard]] kinetum::common::status_or<durable_epoch_transition_view> epoch_transition() const;

	/**
	 * @brief Canonicalize and durably configure one exact guardrails policy.
	 *
	 * Retry classification precedes the generation compare. Same key and same
	 * canonical hash returns retained success; same key with different content
	 * conflicts; a new key must name the exact current generation.
	 *
	 * @param policy Complete candidate policy.
	 * @param idempotency_key Required bounded printable retry identity.
	 * @param expected_generation Exact current policy generation, including zero.
	 * @return Durable policy identity and retry classification, or the first
	 *         validation, identity, generation, hash, or publication failure.
	 */
	[[nodiscard]] kinetum::common::status_or<durable_guardrails_policy_view>
	configure_guardrails_policy(const kinetum::control::v1::GuardrailsPolicy &policy,
				    std::string_view idempotency_key, uint64_t expected_generation);

	/**
	 * @brief Return the current durable guardrails policy.
	 * @return Exact policy identity, or NOT_FOUND when never configured.
	 */
	[[nodiscard]] kinetum::common::status_or<durable_guardrails_policy_view> guardrails_policy() const;

	/**
	 * @brief Test whether one key names the current/latest durable transaction.
	 * @param idempotency_key Candidate exact caller key.
	 * @return true only for byte-exact key equality; false for no record or a
	 *         different key. The operation performs no protobuf copy.
	 */
	[[nodiscard]] kinetum::common::status_or<bool>
	epoch_transition_key_matches(std::string_view idempotency_key) const;

	/**
	 * @brief Persist one legal nonterminal CP phase edge.
	 *
	 * Legal edges are ALLOCATED->PREPARED/ABORT_PENDING,
	 * PREPARED->COMPLETION_PENDING/ABORT_PENDING. Terminal phases have no
	 * outgoing edge. The exact fixed-width identity must match every retained
	 * transaction field. Repeating the current phase is an I/O-free exact retry.
	 *
	 * @param identity Exact retained transition identity.
	 * @param next_phase Requested successor phase.
	 * @return OK after one authority replacement; otherwise exact mismatch,
	 *         illegal-edge, validation, allocation, or publication failure.
	 */
	[[nodiscard]] kinetum::common::status
	advance_epoch_transition_phase(const kinetum::common::epoch_transition_identity &identity,
				       kinetum::control::internal::v1::DurableEpochTransitionPhase next_phase);

	/**
	 * @brief Atomically promote one exact COMPLETE transition.
	 *
	 * The candidate becomes the nested active Bootstrap snapshot, its target
	 * becomes active_epoch, both consumed watermarks remain unchanged, the
	 * Bootstrap key is recomputed through the shared derivation, terminal
	 * success is retained, and optional pending-confirm state is created in the
	 * same authority replacement. Completion of any exact transition to one
	 * unresolved intent's target satisfies and clears that intent, even when a
	 * concurrently started operator transition owns a different key. Terminal
	 * intent failure is never cleared by this path.
	 *
	 * @param identity Exact retained transition identity.
	 * @param completed_unix_ms Nonnegative completion wall-clock projection used
	 *        only to author an optional restart-stable confirmation deadline.
	 * @return OK after one replacement, or the first phase, identity, time,
	 *         corpus, validation, allocation, or publication failure.
	 */
	[[nodiscard]] kinetum::common::status
	complete_epoch_transition(const kinetum::common::epoch_transition_identity &identity,
				  int64_t completed_unix_ms);

	/**
	 * @brief Retain exact ABORTED terminal status without reusing allocations.
	 *
	 * COMPLETION_PENDING is admitted only when typed DP terminal evidence proves
	 * that the prepared lease or another pre-commit cause won before Activate's
	 * commit edge. Diagnostic text is never that proof.
	 *
	 * @param identity Exact retained transition identity.
	 * @param failure Required non-OK bounded failure with no unstructured
	 *        details. An exact retry must reproduce the retained compact outcome.
	 * @param proof Exact authority for the terminal edge. COMPLETION_PENDING
	 *        requires EXACT_DP_PRECOMMIT_TERMINAL.
	 * @return OK after one authority replacement, or the identity, phase,
	 *         diagnostic, status, allocation, or publication failure.
	 * @post An unresolved rollback intent waiting on this exact mutation retains
	 *       the same terminal failure in the replacement.
	 */
	[[nodiscard]] kinetum::common::status
	abort_epoch_transition(const kinetum::common::epoch_transition_identity &identity,
			       const kinetum::common::status &failure, durable_abort_proof proof);

	/**
	 * @brief Discard a nonterminal transaction proven orphaned by fresh Bootstrap.
	 *
	 * Active content and both advanced watermarks are preserved. COMPLETE and
	 * ABORTED records are terminal retry evidence and are not discarded. An
	 * already-satisfied pending intent clears without allocating an epoch; an
	 * unsatisfied intent that owned the orphaned rollback keeps its key and loses
	 * only the process-local wait identity so a fresh allocation can serve it.
	 * Terminal intent failure remains durable.
	 *
	 * @return OK after absence/terminal no-op or one authority replacement.
	 */
	[[nodiscard]] kinetum::common::status discard_orphaned_epoch_transition_after_bootstrap();

	/**
	 * @brief Return one bounded page of active/corpus metadata in ID order.
	 *
	 * An empty token starts a listing. A nonempty token must have been returned
	 * by the immediately preceding page and must still match both the immutable
	 * corpus and active authority. The store keeps no server-side cursor state.
	 *
	 * @param page_size Positive requested row bound.
	 * @param page_token Empty first-page input or exact opaque continuation.
	 * @return One immutable page, or the first size, token, identity,
	 *         allocation, serialization, or hashing failure.
	 */
	[[nodiscard]] kinetum::common::status_or<snapshot_listing_page>
	list_snapshot_page(uint32_t page_size, std::string_view page_token) const;

	/**
	 * @brief Load one exact active or corpus snapshot by semantic identity.
	 *
	 * @param snapshot_id Exact bounded snapshot identity.
	 * @return Snapshot copy, INVALID_ARGUMENT for malformed identity, or
	 *         NOT_FOUND when no exact record exists.
	 */
	[[nodiscard]] kinetum::common::status_or<kinetum::control::v1::ConfigSnapshot>
	load_snapshot(std::string_view snapshot_id) const;

	/**
	 * @brief Copy the active snapshot under one coherent store read.
	 * @return Exact active snapshot, or NOT_FOUND without active authority.
	 */
	[[nodiscard]] kinetum::common::status_or<kinetum::control::v1::ConfigSnapshot> active_snapshot() const;

	/** @return Active snapshot ID, or NOT_FOUND without active authority. */
	[[nodiscard]] kinetum::common::status_or<std::string> active_snapshot_id() const;

	/**
	 * @brief Confirm one exact pending configuration in one durable replacement.
	 *
	 * The first success retains the confirmation-key digest and terminal result.
	 * A response-loss retry with the same complete identity returns that result
	 * without another write. The deadline comparison and replacement occur under
	 * the store's sole mutation lock, so late confirmation cannot race timeout
	 * intent admission into success. A retained success remains retryable beside
	 * a later safety intent; an unconfirmed record cannot cross any durable
	 * rollback intent. A sample before durable creation rejects rather than
	 * manufacturing additional confirmation time.
	 *
	 * @param snapshot_id Exact pending snapshot identity.
	 * @param epoch Exact pending epoch.
	 * @param revision Exact pending revision.
	 * @param idempotency_key Required bounded printable retry identity.
	 * @param now_unix_ms Current nonnegative durable wall-clock projection.
	 * @return Exact retained/new success, DEADLINE_EXCEEDED at or after the
	 *         durable deadline, or an identity/publication failure.
	 */
	[[nodiscard]] kinetum::common::status_or<durable_confirmation_result>
	confirm_pending_config(std::string_view snapshot_id, uint64_t epoch, int64_t revision,
			       std::string_view idempotency_key, int64_t now_unix_ms);

	/** @return Embedded pending-confirm copy, or NOT_FOUND when absent. */
	[[nodiscard]] kinetum::common::status_or<kinetum::control::v1::PendingConfirm> load_pending_confirm() const;

	/**
	 * @brief Durably accept one exact safety intent without allocating an epoch.
	 *
	 * A decision whose named predecessor is already ABORTED is stale and rejects
	 * before publication. If the intent was already durable, the predecessor's
	 * ABORTED replacement instead terminalizes it atomically.
	 *
	 * @param request Complete observation-bound desired rollback.
	 * @return Exact retained/new intent, or identity, policy, transition,
	 *         deadline, corpus, or publication failure.
	 */
	[[nodiscard]] kinetum::common::status_or<durable_rollback_intent_view>
	accept_rollback_intent(const rollback_intent_request &request);

	/** @return Current exact intent, or NOT_FOUND when no intent is retained. */
	[[nodiscard]] kinetum::common::status_or<durable_rollback_intent_view> rollback_intent() const;

	/**
	 * @brief Retain one typed terminal intent failure exactly once.
	 * @param idempotency_key Exact retained intent key.
	 * @param failure Required non-OK bounded terminal failure.
	 * @return OK after exact retry or one durable replacement.
	 */
	[[nodiscard]] kinetum::common::status fail_rollback_intent(std::string_view idempotency_key,
								   const kinetum::common::status &failure);

	/**
	 * @brief Clear an intent after exact target content is globally COMPLETE.
	 * @param idempotency_key Exact retained intent key.
	 * @param completed_epoch Exact active epoch after convergence or joint restart.
	 * @return OK after one replacement, or exact identity/content disagreement.
	 */
	[[nodiscard]] kinetum::common::status clear_completed_rollback_intent(std::string_view idempotency_key,
									      uint64_t completed_epoch);

    private:
	/** @brief One exact immutable corpus object. */
	struct staged_snapshot_record {
		kinetum::control::v1::ConfigSnapshot snapshot;	   ///< Exact admitted terminal snapshot.
		kinetum::common::sha256_digest validation_hash{};  ///< Exact raw terminal identity.
	};

	/**
	 * @brief Adopt one admitted directory before loading persistent state.
	 * @param directory Exact descriptor-rooted durable directory owner.
	 */
	explicit config_store(kinetum::common::durable_directory directory) noexcept;

	/**
	 * @brief Fully load and cross-validate every durable record.
	 * @return OK after complete publication, or the first admission failure.
	 */
	[[nodiscard]] kinetum::common::status load_existing_state_();

	/**
	 * @brief Return first corpus record whose ID is not less than @p id.
	 * @param id Exact lookup identity.
	 * @return Mutable lower-bound iterator.
	 */
	[[nodiscard]] std::vector<staged_snapshot_record>::iterator lower_bound_(std::string_view id) noexcept;

	/**
	 * @brief Return first const corpus record whose ID is not less than @p id.
	 * @param id Exact lookup identity.
	 * @return Immutable lower-bound iterator.
	 */
	[[nodiscard]] std::vector<staged_snapshot_record>::const_iterator
	lower_bound_(std::string_view id) const noexcept;

	/**
	 * @brief Derive the immutable identity of the corpus and active authority.
	 *
	 * The caller must hold this store's shared or exclusive mutex ownership.
	 *
	 * @return Lowercase SHA-256 identity or the hash-provider failure.
	 */
	[[nodiscard]] kinetum::common::status_or<std::string> snapshot_listing_identity_locked_() const;

	/**
	 * @brief Stage one canonical object while exclusive store ownership is held.
	 * @param canonical Exact terminal content.
	 * @return OK after exact retry or create-only publication.
	 */
	[[nodiscard]] kinetum::common::status
	stage_snapshot_locked_(const kinetum::common::canonical_config_snapshot &canonical);

	/**
	 * @brief Validate and deterministically serialize one complete authority.
	 * @param authority Candidate complete private message.
	 * @return Deterministic bytes or the first self/cross-record failure.
	 */
	[[nodiscard]] kinetum::common::status_or<std::string>
	validate_authority_(const kinetum::control::internal::v1::ControlPlaneTransitionAuthority &authority) const;

	/**
	 * @brief Reconstruct one exact transition view while store ownership is held.
	 * @param transition Exact admitted private transition.
	 * @param exact_retry Whether the caller reused retained allocation.
	 * @return Complete Prepare projection plus phase and terminal status.
	 */
	[[nodiscard]] kinetum::common::status_or<durable_epoch_transition_view>
	transition_view_locked_(const kinetum::control::internal::v1::DurableEpochTransition &transition,
				bool exact_retry) const;

	kinetum::common::durable_directory directory_;	///< Sole filesystem authority.
	mutable std::shared_mutex mutex_;		///< One synchronization domain for all state.
	std::unique_ptr<kinetum::control::internal::v1::ControlPlaneTransitionAuthority>
		authority_;			      ///< Sole mutable authority; null for control-only.
	std::vector<staged_snapshot_record> staged_;  ///< Strictly ID-sorted immutable corpus.
};

}  // namespace kinetum::cp
