// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file control_loop.hpp
 * @brief Bounded single-writer Control Plane mutation owner.
 * @author Fleming Patel
 *
 * This module implements the single-writer control loop that handles all
 * configuration mutations in the Control Plane. By funneling all mutations
 * through a fixed-capacity mailbox to one thread, semantic state has one
 * writer while the mailbox retains an explicit predicate mutex protocol.
 *
 * @par Design Philosophy (Deterministic control loop)
 *
 * **Single-Writer Discipline**: All state-mutating CP operations
 * (SetConfigSnapshot, Rollback, ConfirmConfig, and ConfigureGuardrails) go
 * through a single control loop thread. This
 * eliminates concurrent semantic mutation by design.
 *
 * **Idempotency Ownership**: SetConfig and Rollback bind their keys to
 * canonical durable transition identity. Guardrails policy and Confirm
 * bind their own durable key digests and exact result identities. No volatile
 * response cache, TTL, or FIFO participates in mutation truth.
 *
 * **CAS Revision Check**: Mutations can explicitly provide
 * `expected_revision`, including zero, for Compare-And-Swap semantics. If the
 * current revision does not match, the mutation fails before application.
 *
 * **DP Completion Ordering**: The control loop marks config active in the store
 * only after exact Data Plane completion. PREPARED is persisted only after DP
 * PREPARED, and COMPLETION_PENDING is durable before Activate can cross the
 * irreversible commit edge. Typed Status reconciliation never parses prose.
 *
 * **Synchronous completion**: `submit()` blocks until the mutation completes
 * and returns the result.
 * This is appropriate for CP (not high-frequency) and simplifies
 * error handling for callers.
 *
 * @par Thread Model
 *
 * @code
 *   [gRPC Thread 1] --+
 *                      \
 *   [gRPC Thread 2] ----+---> [64-cell mailbox] ---> [Control Loop Thread]
 *                      /                                      |       \
 *   [gRPC Thread N] --+                                       v        +-> [Data Plane]
 *                                                        [config_store]
 * @endcode
 *
 * Multiple gRPC threads submit mutations concurrently, but they are
 * serialized through the single control loop thread. Each submitter
 * blocks until its mutation completes.
 *
 * @par Usage Example
 * @code
 *   control_loop loop(&config_store, dp_stub);
 *   assert(loop.start().is_ok());
 *
 *   // Submit a set_config mutation (blocks until complete)
 *   mutation m("txn_12345", std::optional<int64_t>{5},
 *              set_config_payload{snapshot, confirm_timeout_ms});
 *
 *   auto result = loop.submit(std::move(m));
 *   // Exact retries reuse the durable allocation and terminal result.
 *   assert(result.ok());
 *
 *   loop.stop();  // Graceful shutdown
 * @endcode
 *
 * @see docs/PLATFORM_ENGINEERING_GUIDE.md for the single-writer and bounded-queue doctrine.
 *
 */

#include <atomic>
#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include <kinetum/algo/queue.hpp>
#include <kinetum/algo/rcu_buffer.hpp>
#include "src/common/status.hpp"
#include "src/cp/config_store.hpp"

namespace kinetum::cp
{

class dataplane_transition_client;

// =============================================================================
// Mutation Payloads
// =============================================================================

/**
 * @brief Payload for set_config operation.
 */
struct set_config_payload {
	kinetum::control::v1::ConfigSnapshot snapshot;	///< Complete candidate snapshot.
	uint32_t confirm_timeout_ms{0};			///< 0 = no commit-confirmed
};

/**
 * @brief Payload for confirm_config operation.
 */
struct confirm_config_payload {
	std::string snapshot_id;  ///< Exact pending snapshot identity.
	uint64_t epoch{0};	  ///< Exact pending epoch.
	int64_t revision{0};	  ///< Exact pending revision.
};

/**
 * @brief Payload for rollback operation.
 */
struct rollback_payload {
	std::string target_snapshot_id;	      ///< Exact retained rollback target.
	std::vector<std::string> module_ids;  ///< Empty = full rollback
};

/**
 * @brief Payload for set_guardrails_policy operation.
 */
struct set_guardrails_policy_payload {
	kinetum::control::v1::GuardrailsPolicy policy;	///< Completely validated policy.
	uint64_t expected_generation{0};		///< Exact durable policy CAS input.
};

/**
 * @brief Union of all mutation payloads.
 */
using mutation_payload =
	std::variant<set_config_payload, confirm_config_payload, rollback_payload, set_guardrails_policy_payload>;

/** @brief True only for one concrete control-loop payload alternative. */
template <typename payload_type>
concept mutation_payload_type =
	std::same_as<payload_type, set_config_payload> || std::same_as<payload_type, confirm_config_payload> ||
	std::same_as<payload_type, rollback_payload> || std::same_as<payload_type, set_guardrails_policy_payload>;

// =============================================================================
// Mutation Request and Result
// =============================================================================

/**
 * @brief A configuration mutation request.
 *
 * The construction-fixed payload alternative is the operation identity.
 * Callers cannot default-construct, replace, or separately label it. The
 * request also owns its retry key and optional snapshot-revision CAS input.
 */
class mutation final {
    public:
	/**
	 * @brief Construct one complete immutable operation request.
	 *
	 * @tparam payload_type Exact concrete mutation payload type.
	 * @param idempotency_key Complete retry identity.
	 * @param expected_revision Present snapshot-revision CAS, including zero.
	 * @param payload Complete operation payload fixed as the active alternative.
	 */
	template <mutation_payload_type payload_type>
	explicit mutation(std::string idempotency_key, std::optional<int64_t> expected_revision, payload_type payload)
		: idempotency_key_(std::move(idempotency_key))
		, expected_revision_(expected_revision)
		, payload_(std::in_place_type<payload_type>, std::move(payload))
	{
	}

	/** @brief Reject construction without one concrete payload identity. */
	mutation() = delete;
	/** @brief Copy one complete immutable request before publication. */
	mutation(const mutation &) = default;
	/** @brief Transfer one complete immutable request without throwing. */
	mutation(mutation &&) = default;
	/** @brief Reject replacement of a constructed request by copying. */
	mutation &operator=(const mutation &) = delete;
	/** @brief Reject replacement of a constructed request by moving. */
	mutation &operator=(mutation &&) = delete;

	/** @return Immutable retry identity. */
	[[nodiscard]] const std::string &idempotency_key() const noexcept
	{
		return idempotency_key_;
	}

	/** @return Optional exact snapshot-revision CAS input. */
	[[nodiscard]] const std::optional<int64_t> &expected_revision() const noexcept
	{
		return expected_revision_;
	}

	/** @return Construction-fixed operation payload. */
	[[nodiscard]] const mutation_payload &payload() const noexcept
	{
		return payload_;
	}

    private:
	std::string idempotency_key_;		    ///< Complete retry identity.
	std::optional<int64_t> expected_revision_;  ///< Present exact CAS revision, including zero.
	mutation_payload payload_;		    ///< Sole operation identity and payload.
};

static_assert(!std::is_default_constructible_v<mutation>);
static_assert(!std::is_copy_assignable_v<mutation>);
static_assert(!std::is_move_assignable_v<mutation>);
static_assert(std::is_nothrow_move_constructible_v<mutation>);

/** Maximum number of ordinary mutation contexts owned by the CP mailbox. */
inline constexpr std::size_t CONTROL_LOOP_MUTATION_QUEUE_CAPACITY = 64u;
static_assert(CONTROL_LOOP_MUTATION_QUEUE_CAPACITY >= 2u &&
	      (CONTROL_LOOP_MUTATION_QUEUE_CAPACITY & (CONTROL_LOOP_MUTATION_QUEUE_CAPACITY - 1u)) == 0u);

/**
 * @brief Result of a configuration mutation.
 *
 * Returned by `submit()` after the mutation completes.
 */
struct mutation_result {
	kinetum::common::status status;		       ///< Operation status (ok or error)
	int64_t revision{0};			       ///< New revision after mutation
	uint64_t epoch{0};			       ///< Exact CP-allocated epoch completed by Data Plane
	std::string snapshot_id;		       ///< Active/new snapshot ID
	uint64_t policy_generation{0};		       ///< Exact configured guardrails generation.
	kinetum::common::sha256_digest policy_hash{};  ///< Exact configured policy identity.

	// Confirm-specific fields
	int64_t time_remaining_ms{0};  ///< Time remaining for pending confirm

	/**
	 * @brief Check if the mutation succeeded.
	 * @return true only for exact application success.
	 */
	[[nodiscard]] bool ok() const noexcept
	{
		return status.is_ok();
	}
};

// =============================================================================
// Guardrails Runtime State (versioned_rcu_buffer propagation)
// =============================================================================

/**
 * @brief Runtime state for guardrails policy propagation.
 *
 * Uses versioned_rcu_buffer for lock-free writer->reader publishing
 * per Platform Engineering Guide. The control_loop worker
 * thread writes policy via store(), the guardrails_runner reads via borrow().
 */
struct guardrails_runtime_state {
	kinetum::algo::versioned_rcu_buffer<kinetum::control::v1::GuardrailsPolicy> policy;  ///< Coherent policy.
};

/**
 * @brief Published CP state for coherent external reads.
 *
 * Bundles revision and active snapshot ID into a single atomically-published
 * object via versioned_rcu_buffer. Eliminates split publication where
 * readers could observe revision from one mutation and snapshot_id from another.
 *
 * Writer: control_loop worker thread (single writer)
 * Readers: gRPC handlers, guardrails runner, diagnostics
 */
struct cp_published_state {
	int64_t revision{0};	  ///< Exact active snapshot revision.
	std::string snapshot_id;  ///< Exact active semantic snapshot identity.
};

// =============================================================================
// Control Loop
// =============================================================================

/**
 * @brief Single-writer control loop for all CP configuration mutations.
 *
 * Every configuration mutation crosses a fixed 64-cell pointer mailbox. One
 * worker thread is therefore the sole semantic writer.
 *
 * @par Thread Safety
 * - submit() is thread-safe (can be called from any thread)
 * - start()/stop() should be called from a single thread (typically main)
 * - Mailbox publication and its wait predicate share one mutex protocol
 * - Mutable semantic state belongs only to the worker thread
 *
 * @par Lifecycle
 * 1. Construct with dependencies (config_store, DP stub)
 * 2. Require initialization_status() to be OK
 * 3. Call start() when packet-configuration mutation is admitted
 * 4. Submit mutations via submit() (blocks until complete)
 * 5. Call stop() for graceful shutdown (completes pending mutations)
 *
 * @invariant Worker thread is running between start() and stop()
 * @invariant At most one mutation is being processed at any time
 */
class control_loop {
    public:
	// ---------------------------------------------------------------------------
	// Cancel-Safe Timeout State Machine
	// ---------------------------------------------------------------------------

	/**
	 * @brief Explicit state for cancel-safe timeout submissions.
	 *
	 * State machine:
	 * `QUEUED -> EXECUTING -> COMPLETED` or `QUEUED -> CANCELED`.
	 * Transitions use CAS on shared atomic state. A timeout may cancel only
	 * QUEUED; EXECUTING always delivers its real result.
	 */
	enum class request_state : uint8_t {
		QUEUED = 0,	///< In queue, not yet picked up by worker
		EXECUTING = 1,	///< Worker has dequeued and is processing
		CANCELED = 2,	///< Timeout fired while still queued - worker will skip
		COMPLETED = 3,	///< Worker finished - result delivered via promise
	};

	// ---------------------------------------------------------------------------
	// Construction and Lifecycle
	// ---------------------------------------------------------------------------

	/**
	 * @brief Construct the control loop with dependencies.
	 *
	 * @param store Pointer to config_store, which must outlive this object. A
	 *              null pointer records an initialization failure.
	 * @param dp_stub Shared pointer to Data Plane gRPC stub. A null pointer is
	 *                valid only for control-only/component use whose mutation
	 *                worker remains stopped or resolves an already-terminal retry.
	 *
	 * @note Construction does not start the worker thread. Call `start()` after
	 *       checking `initialization_status()`.
	 */
	control_loop(config_store *store, std::shared_ptr<kinetum::dataplane::v1::DataplaneService::Stub> dp_stub);

	/**
	 * @brief Stop the worker and require every published context to be resolved.
	 *
	 * Destruction fails stop if ordinary or safety-channel ownership remains
	 * after the worker has joined.
	 */
	~control_loop();

	// Non-copyable, non-movable (owns thread)
	control_loop(const control_loop &) = delete;
	control_loop &operator=(const control_loop &) = delete;
	control_loop(control_loop &&) = delete;
	control_loop &operator=(control_loop &&) = delete;

	/**
	 * @brief Return immutable constructor-time storage admission status.
	 *
	 * Production hosts must require this status to be OK even when they
	 * deliberately keep the mutation worker stopped. The returned reference is
	 * valid for this control_loop's lifetime and never changes after construction.
	 *
	 * @return OK after exact active-record restoration or deliberate
	 *         no-active control-only startup; otherwise the retained
	 *         storage/allocation failure.
	 */
	[[nodiscard]] const kinetum::common::status &initialization_status() const noexcept;

	/**
	 * @brief Reconcile retained transition and rollback intent before service publication.
	 *
	 * This cold startup operation is called only after Health and content proof
	 * establish PACKET_READY: exact Bootstrap does so for a new CONTROL_READY
	 * runtime, while mandatory telemetry does so for a surviving PACKET_READY
	 * runtime. It resumes the exact retained transaction through the ordinary
	 * typed classifier and then services any durable safety intent.
	 * A terminal intent rejects before transition resumption. Only transient
	 * observations retry, and every RPC attempt is capped by one fixed steady
	 * startup deadline.
	 *
	 * @param packet_ready_rejoin True when DP survived CP and retained terminal
	 *        records require Status proof; false after one fresh Bootstrap.
	 * @param startup_deadline Absolute steady deadline already consumed by
	 *        Health/Stats startup, or max to start a fresh component-test bound.
	 * @return OK after durable convergence, or the exact contradiction, frozen
	 *         generation, terminal intent, transport, or startup-deadline failure.
	 */
	[[nodiscard]] kinetum::common::status reconcile_startup(
		bool packet_ready_rejoin,
		std::chrono::steady_clock::time_point startup_deadline = std::chrono::steady_clock::time_point::max());

	/**
	 * @brief Reconcile one explicit startup policy before worker launch.
	 * @param policy Complete policy admitted from the operator's startup file.
	 * @return OK after exact no-op or one durable generation and coherent local
	 *         publication; otherwise validation, identity, or persistence failure.
	 */
	[[nodiscard]] kinetum::common::status
	configure_startup_guardrails_policy(const kinetum::control::v1::GuardrailsPolicy &policy);

	/**
	 * @brief Start the control loop worker thread.
	 *
	 * Safe to call repeatedly; an already-running loop is unchanged.
	 *
	 * @return OK after the worker is running, or the launch failure.
	 * @post Worker thread is running and ready to process mutations.
	 */
	[[nodiscard]] kinetum::common::status start();

	/**
	 * @brief Stop the control loop worker thread.
	 *
	 * Signals the worker thread to stop and waits for it to complete.
	 * Pending executable mutations complete; canceled contexts are dequeued and
	 * destroyed without dispatch. Safe to call multiple times (no-op if not
	 * running).
	 *
	 * @post Worker thread has stopped.
	 * @post No ordinary or safety-channel context remains published.
	 */
	void stop();

	/**
	 * @brief Check if the control loop is running.
	 * @return True if the worker thread is active.
	 */
	[[nodiscard]] bool is_running() const noexcept;

	// ---------------------------------------------------------------------------
	// Mutation Submission
	// ---------------------------------------------------------------------------

	/**
	 * @brief Submit a mutation and wait for completion.
	 *
	 * This is the primary interface for configuration mutations. The call
	 * blocks until the worker processes the request and returns its exact result.
	 *
	 * @param m The mutation to submit
	 * @return The exact mutation result, RESOURCE_EXHAUSTED when all 64 mailbox
	 *         cells are occupied, or UNAVAILABLE when shutdown closes admission
	 *         before queue publication.
	 *
	 * @par Idempotency
	 * Snapshot transitions resolve through durable epoch/hash/key/sequence
	 * identity. Guardrails policy and Confirm use their own exact durable retry
	 * records. No mutation result is sourced from volatile process memory.
	 *
	 * @par CAS Revision Check
	 * A present `expected_revision` mismatch returns FAILED_PRECONDITION before
	 * mutation.
	 *
	 * @par Error Handling
	 * On error, `result.status` is authoritative; success fields are
	 * non-authoritative.
	 *
	 * @par Thread Safety
	 * Concurrent submitters are serialized by the bounded mailbox.
	 */
	[[nodiscard]] mutation_result submit(mutation m);

	/**
	 * @brief Submit a mutation with a cancel-safe timeout.
	 *
	 * A timeout cancels only a request still in QUEUED. An EXECUTING request
	 * remains owned by the worker and this call waits for its real result.
	 *
	 * @param m The mutation to submit.
	 * @param timeout Nonnegative maximum wait; zero attempts immediate queued
	 *        cancellation.
	 * @return The exact mutation result, DEADLINE_EXCEEDED if canceled,
	 *         RESOURCE_EXHAUSTED when all 64 mailbox cells are occupied, or
	 *         UNAVAILABLE when shutdown closes admission before publication.
	 *
	 * @par Thread Safety
	 * Concurrent submitters are serialized by the bounded mailbox.
	 */
	[[nodiscard]] mutation_result submit(mutation m, std::chrono::milliseconds timeout);

	/**
	 * @brief Durably submit one internal safety intent without cancellation.
	 *
	 * Exactly one caller-owned context may be published at a time. Successful
	 * publication transfers a linear stack borrow to the control-loop worker;
	 * this call waits unconditionally until that worker has either durably
	 * accepted the intent or returned a pre-publication rejection. The channel
	 * has no timeout because a published stack address cannot be revoked.
	 *
	 * @param request Complete observation-bound rollback intent.
	 * @return Durable acceptance or the exact pre-publication/store failure.
	 */
	[[nodiscard]] kinetum::common::status submit_safety_intent(rollback_intent_request request);

	// ---------------------------------------------------------------------------
	// Statistics and Monitoring
	// ---------------------------------------------------------------------------

	/**
	 * @brief Get the exact number of mutation contexts currently queued.
	 *
	 * Serializing this observation with mailbox publication and consumption makes
	 * the otherwise observational MPMC count exact at the protected instant.
	 *
	 * @return Number of occupied mailbox cells in `[0, 64]`.
	 */
	[[nodiscard]] std::size_t queue_depth() const;

	/**
	 * @brief Get the coherent revision and snapshot identity in one borrow.
	 *
	 * Callers that need both values use this method so they observe one
	 * publication from the same mutation.
	 * No separate half-identity accessor is exposed.
	 *
	 * @return Coherent revision and snapshot identity.
	 */
	[[nodiscard]] cp_published_state published_state() const;

	/**
	 * @brief Access guardrails runtime state for policy propagation.
	 *
	 * The guardrails runner reads policy through the versioned RCU publication;
	 * ConfigureGuardrails writes through a control-loop mutation.
	 *
	 * @return Immutable guardrails runtime state owner.
	 */
	[[nodiscard]] const guardrails_runtime_state &guardrails_state() const noexcept;

    private:
	// ---------------------------------------------------------------------------
	// Internal Types
	// ---------------------------------------------------------------------------

	/**
	 * @brief Heap-owned mutation context transferred through one pointer cell.
	 *
	 * For timeout submissions, `state` is a shared atomic accessed by both the
	 * submitter thread (CAS queued->canceled on timeout) and the worker thread
	 * (CAS queued->executing before dispatch). For non-timeout submissions,
	 * `state` is null and the worker processes unconditionally. Cancellation does
	 * not revoke queue ownership; the worker dequeues and destroys the context.
	 */
	struct pending_mutation {
		/**
		 * @brief Own one complete request before bounded pointer publication.
		 * @param request_value Construction-fixed mutation to own.
		 * @param state_value Optional cancel-safe state shared with the submitter.
		 */
		explicit pending_mutation(mutation request_value,
					  std::shared_ptr<std::atomic<request_state>> state_value)
			: request(std::move(request_value))
			, state(std::move(state_value))
		{
		}

		/** @brief Reject copying linear request and promise ownership. */
		pending_mutation(const pending_mutation &) = delete;
		/** @brief Transfer one unpublished complete context without throwing. */
		pending_mutation(pending_mutation &&) = default;
		/** @brief Reject replacement of linear context ownership by copying. */
		pending_mutation &operator=(const pending_mutation &) = delete;
		/** @brief Reject replacement of linear context ownership by moving. */
		pending_mutation &operator=(pending_mutation &&) = delete;

		mutation request;			       ///< Complete immutable request after queue publication.
		std::promise<mutation_result> result_promise;  ///< One-shot producer completion.
		std::shared_ptr<std::atomic<request_state>> state;  ///< Null for unconditional submissions.
	};
	static_assert(!std::is_default_constructible_v<pending_mutation>);
	static_assert(!std::is_copy_assignable_v<pending_mutation>);
	static_assert(!std::is_move_assignable_v<pending_mutation>);
	static_assert(std::is_nothrow_move_constructible_v<pending_mutation>);

	/** Result of one nonthrowing mailbox publication attempt. */
	enum class mailbox_publication_result : uint8_t {
		PUBLISHED = 0,	///< Queue owns the supplied pointer.
		STOPPING,	///< Admission closed before publication.
		FULL,		///< Every preallocated cell is occupied.
	};

	/**
	 * @brief Try to publish one complete pending context under the predicate mutex.
	 * @param pending Non-null context still owned by the caller.
	 * @return Exact publication disposition; PUBLISHED transfers ownership.
	 */
	[[nodiscard]] mailbox_publication_result try_publish_pending_(pending_mutation *pending) noexcept;

	/** @brief Caller-owned context borrowed by the one-slot safety channel. */
	struct safety_intent_context {
		rollback_intent_request request;	       ///< Immutable request after publication.
		std::promise<kinetum::common::status> result;  ///< One-shot durable-acceptance result.
	};

	// ---------------------------------------------------------------------------
	// Worker Thread
	// ---------------------------------------------------------------------------

	/**
	 * @brief Run the sole mutation worker until stop is requested.
	 */
	void run_();

	/**
	 * @brief Process a single mutation.
	 *
	 * Dispatches exhaustively from the construction-fixed payload alternative.
	 *
	 * @param m Mutation to process.
	 * @return Exact mutation result.
	 */
	[[nodiscard]] mutation_result process_(const mutation &m);

	// ---------------------------------------------------------------------------
	// Mutation Handlers
	// ---------------------------------------------------------------------------

	/**
	 * @brief Validate and apply one complete snapshot mutation.
	 * @param p Exact set-config payload.
	 * @param idem_key Required durable transition key.
	 * @return Exact terminal mutation result.
	 */
	[[nodiscard]] mutation_result handle_set_config_(const set_config_payload &p, const std::string &idem_key);

	/**
	 * @brief Durably confirm one exact pending-confirm record.
	 * @param p Exact snapshot/epoch/revision confirmation identity.
	 * @param idempotency_key Required exact confirmation retry key.
	 * @return Exact confirmation result.
	 */
	[[nodiscard]] mutation_result handle_confirm_config_(const confirm_config_payload &p,
							     const std::string &idempotency_key);

	/**
	 * @brief Build and apply one full or selective rollback snapshot.
	 * @param p Exact rollback target and optional module subset.
	 * @param idem_key Required durable transition key.
	 * @return Exact terminal rollback result.
	 */
	[[nodiscard]] mutation_result handle_rollback_(const rollback_payload &p, const std::string &idem_key);

	/**
	 * @brief Publish one already validated guardrails policy.
	 * @param p Exact policy payload.
	 * @param idempotency_key Required exact policy retry key.
	 * @return Exact local publication result.
	 */
	[[nodiscard]] mutation_result handle_set_guardrails_policy_(const set_guardrails_policy_payload &p,
								    const std::string &idempotency_key);

	/**
	 * @brief Persist one published safety-channel context if present.
	 * @return true when one context was consumed and completed.
	 */
	[[nodiscard]] bool service_safety_intent_submission_();

	/**
	 * @brief Advance one already-durable rollback intent through transition truth.
	 * @return true only while the unresolved intent needs another bounded retry;
	 *         false after absence, exact completion, or terminal failure.
	 */
	[[nodiscard]] bool service_durable_rollback_intent_();

	/**
	 * @brief Wait for a transition poll deadline while servicing safety input.
	 * @param deadline Exact steady observation deadline.
	 * @return false after shutdown or the enclosing startup deadline; true at an
	 *         ordinary poll point.
	 */
	[[nodiscard]] bool wait_for_transition_poll_(std::chrono::steady_clock::time_point deadline);

	// ---------------------------------------------------------------------------
	// Exact DP Transition Client
	// ---------------------------------------------------------------------------

	/**
	 * @brief Apply configuration through the exact DP transition client.
	 *
	 * Canonical corpus staging and exact epoch/mutation allocation complete
	 * before transport. The allocation is restart-safe and exact retries reuse
	 * it. Typed reconciliation persists PREPARED and COMPLETION_PENDING in order,
	 * polls observation-only Status, and promotes durable active content only
	 * after exact terminal COMPLETE.
	 *
	 * @param snap Configuration snapshot that would be transitioned.
	 * @param idem_key Idempotency key that would identify the transaction.
	 * @param confirm_timeout_ms Optional commit-confirmed intent retained until
	 *        exact completion.
	 * @return Pair of epoch and status. Epoch is valid only when status is OK;
	 *         failures retain zero and leave the durable phase restart-reconcilable.
	 */
	[[nodiscard]] std::pair<uint64_t, kinetum::common::status>
	apply_to_dp_(const kinetum::control::v1::ConfigSnapshot &snap, const std::string &idem_key,
		     uint32_t confirm_timeout_ms = 0u);

	/**
	 * @brief Adopt and publish one exact snapshot after durable completion.
	 * @param snapshot Local mutable copy of the now-active terminal snapshot.
	 * @post Revision and snapshot identity publish coherently without a
	 *       fallible post-commit store read.
	 */
	void publish_completed_snapshot_(kinetum::control::v1::ConfigSnapshot &snapshot) noexcept;

	/**
	 * @brief Publish worker-private state to external readers via RCU.
	 *
	 * Called after every mutation that changes revision or active snapshot.
	 * Publishes both values in one `cp_published_state` generation.
	 */
	void publish_state_() noexcept;

	// ---------------------------------------------------------------------------
	// Member Variables
	// ---------------------------------------------------------------------------

	config_store *store_;						  ///< Sole durable config authority.
	std::unique_ptr<dataplane_transition_client> transition_client_;  ///< Exact typed DP mutation client.

	// Worker thread state
	std::thread worker_thread_;		   ///< Sole semantic mutation writer.
	std::atomic<bool> running_{false};	   ///< Submission-admission observation.
	std::atomic<bool> stop_requested_{false};  ///< Queue/CV shutdown predicate.

	// Mutation mailbox
	mutable std::mutex queue_mu_;	    ///< Owns queue and shutdown admission edge.
	std::condition_variable queue_cv_;  ///< Wakes the sole mutation consumer.
	/** Preallocated bounded FIFO pointer ownership. */
	kinetum::algo::mpmc_queue<pending_mutation *, CONTROL_LOOP_MUTATION_QUEUE_CAPACITY> queue_;
	safety_intent_context *safety_intent_{nullptr};	 ///< One unresolved caller-owned context.

	kinetum::common::status init_status_;  ///< Immutable constructor-time admission status.

	// Worker-private state (single-writer thread only - NOT for external reads)
	int64_t current_revision_{0};	  ///< Sole-writer active durable revision.
	std::string active_snapshot_id_;  ///< Sole-writer active semantic identity.

	// Published state for external readers (coherent via versioned_rcu_buffer)
	kinetum::algo::versioned_rcu_buffer<cp_published_state> published_state_;  ///< Coherent active projection.
	uint64_t published_generation_{0};  ///< Adjacent active-publication generation.

	// Guardrails policy state (propagated via versioned_rcu_buffer)
	guardrails_runtime_state guardrails_state_;  ///< Coherent policy publication owner.
	uint64_t guardrails_generation_{0};	     ///< Adjacent policy-publication generation.
	bool startup_reconciliation_{false};	     ///< Sole-thread pre-service reconciliation mode.
	std::chrono::steady_clock::time_point startup_reconciliation_deadline_{};  ///< Exact startup bound.
};

}  // namespace kinetum::cp
