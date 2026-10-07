# Control Plane, Guardrails, and Rollback

This document covers two subsystems that share the `kinetum_cp` process:

- The **control plane** itself: the gRPC server, the single-writer mutation
  engine (`control_loop`), the snapshot store, and the exact transition-client
  boundary for pushing config to the dataplane.
- The **guardrails** subsystem hosted inside the same process: a packet-ready
  runner, deterministic evaluator, durable policy, commit-confirmed deadline
  owner, and observation-bound rollback-intent producer.

Both share one writer and atomic durable authority for active configuration,
policy, and rollback intent. The control loop publishes policy through RCU;
guardrails RPCs sit alongside snapshot management.

For the architectural framing, read [`CONCEPTS.md`](CONCEPTS.md) first.
For the wire contract this process implements, see
[`GRPC_API.md`](GRPC_API.md). For pipeline authoring, see
[`AXIOM.md`](AXIOM.md). For planning, see [`GLUON.md`](GLUON.md). For
the runtime that consumes the snapshots this doc describes, see
[`DATA_PLANE.md`](DATA_PLANE.md).

## Table of Contents

**Part 1: Control Plane Host Process**

1. [What CP+GR Is](#1-what-cpgr-is)
2. [Authoring Model](#2-authoring-model)
3. [Process Lifecycle](#3-process-lifecycle)
4. [Control Loop](#4-control-loop)
5. [Durable Retry Identity and CAS](#5-durable-retry-identity-and-cas)
6. [Exact DP Transition Client Boundary](#6-exact-dp-transition-client-boundary)
7. [Mutation Handlers](#7-mutation-handlers)
8. [Config Store](#8-config-store)
9. [gRPC Service](#9-grpc-service)
10. [Authentication and TLS](#10-authentication-and-tls)
11. [Validation Constants and Limits](#11-validation-constants-and-limits)

**Part 2: CP/Guardrails Integration Boundary**

12. [CP/Guardrails Integration Boundary](#12-cpguardrails-integration-boundary)

**Part 3: Guardrails Subsystem**

13. [What Guardrails Is](#13-what-guardrails-is)
14. [Runner Lifecycle](#14-runner-lifecycle)
15. [Guardrails Policy](#15-guardrails-policy)
16. [Health Correlator](#16-health-correlator)
17. [Telemetry History](#17-telemetry-history)
18. [Attribution Scorer](#18-attribution-scorer)
19. [Commit-Confirmed Pattern](#19-commit-confirmed-pattern)
20. [Selective Rollback](#20-selective-rollback)
21. [Boundary Telemetry Monitoring](#21-boundary-telemetry-monitoring)
22. [Runtime Generation and Counter Regression](#22-runtime-generation-and-counter-regression)

**Part 4: Cross-Cutting**

23. [Source-Tree Integration Surfaces](#23-source-tree-integration-surfaces)
24. [CP vs DP vs Quark vs Photon Responsibilities](#24-cp-vs-dp-vs-quark-vs-photon-responsibilities)
25. [Where to Go Next](#25-where-to-go-next)

---

## Part 1: Control Plane Host Process

### 1. What CP+GR Is

The `kinetum_cp` process owns three responsibilities:

1. **Configuration management.** Receives configuration snapshots over
   gRPC, owns their durable storage, and drives exact DP transitions
   after packet-ready startup. Control-only startup rejects before mutation
   construction.
2. **Mutation serialization.** One `control_loop` worker orders all
   state-changing operations.
3. **Commit-confirmed recovery and regression detection.** A packet-ready
   runner services durable confirmation deadlines and one explicit guardrails
   policy. It consumes coherent operator telemetry rather than live DP/module
   state and delegates desired rollback through the control loop.

Inside the process, the execution owners are:

- The **main process-owner thread** - establishes descriptor-owned termination
  before other threads, closes gRPC admission, and orders teardown.
- The **control_loop worker** thread - packet-ready single writer for all
  mutations.
- The **guardrails_runner** thread - packet-ready commit-confirmed owner and
  telemetry-policy evaluator.
- One or more **gRPC server threads** - call into both of the above.
- The **logging writer** - owns file delivery and rotation without mutation authority.

The runner reads the control loop's versioned policy buffer and submits
rollback through its sole mutation channel.

Source layout: `src/cp/`. The relevant files:

| File                              | Role                                                            |
| --------------------------------- | --------------------------------------------------------------- |
| `cp_main.cpp`                     | Entry point, CLI, lifecycle, signal handling                    |
| `bootstrap_startup.hpp/cpp`       | Held bootstrap-source admission and canonical terminal snapshot |
| `cp_grpc.hpp/cpp`                 | gRPC service implementation (`control_service_impl`)            |
| `cp_termination_signal.hpp/cpp`   | Main-thread blocked SIGINT/SIGTERM/SIGUSR1 and exact signalfd ownership  |
| `control_loop.hpp/cpp`            | Single-writer mutation engine                                   |
| `config_store.hpp/cpp`            | Immutable snapshot corpus and atomic transition persistence     |
| `transition_reconciliation.hpp/cpp` | Typed CP restart-action classification                        |
| `dataplane_transition_client.hpp/cpp` | Bounded exact DP wire construction, admission, and normalization |
| `proto/kinetum/control/internal/v1/transition_authority.proto` | Private durable-state schema; never an RPC or SDK contract |
| `guardrails.hpp/cpp`              | Runner I/O, cadence, commit deadline, safety-intent submission  |
| `guardrails_evaluator.hpp/cpp`    | Six-state baseline/window/detector/attribution owner             |
| `guardrails_policy.hpp/cpp`       | Exact nested policy validation, serialization, and SHA-256       |
| `runtime_authority_fence.hpp/cpp` | Compact CP-active vs coherent-DP content classifier               |
| `dataplane_bootstrap.hpp/cpp`     | Health-first Bootstrap or surviving PACKET_READY reconciliation  |
| `health_correlator.hpp/cpp`       | EWMA + hysteresis + multi-signal degradation score              |
| `telemetry_snapshot.hpp`          | Per-config telemetry history (ring buffer)                      |
| `attribution_scorer.hpp`          | Confidence scoring for rollback attribution                     |
| `../common/durable_directory.hpp/cpp` | Descriptor-rooted create/read/replace/remove durability mechanism |
| `../common/application_status.hpp` | Shared embedded-RPC-status success classification               |
| `../common/log_service.hpp` | Bounded diagnostic writer and process-lifetime ownership; see [Logging](LOGGING.md) |

### 2. Authoring Model

Vocabulary you'll see throughout this doc:

| Term                  | Meaning                                                                                 |
| --------------------- | --------------------------------------------------------------------------------------- |
| **Mutation**          | A construction-fixed request to change CP state. Its payload variant alternative is the sole operation identity; the same object owns its idempotency key and optional expected revision. |
| **Payload alternative** | One of `set_config_payload`, `confirm_config_payload`, `rollback_payload`, or `set_guardrails_policy_payload`. No parallel operation enum can disagree with it. |
| **Single-writer**     | One worker executes mutations in order; RPC threads submit through its shared mailbox. |
| **Synchronous submission** | `submit()` blocks until the worker finishes the mutation and returns the result. |
| **Idempotency key**   | Caller identity. Snapshot, policy, Confirm, and safety-intent retries bind it to their exact durable content/result identity. No volatile key cache exists. |
| **CAS check**         | Presence of `expected_revision`, including zero, causes `failed_precondition` if current revision differs. Absence skips CAS. |
| **Exact transition identity** | CP-allocated epoch, mutation sequence, validation hash, and idempotency key shared by Prepare, Activate, Abort, and Status. CP durably constructs it and the exact DP client carries it unchanged through every retry. |
| **RCU buffer**        | `versioned_rcu_buffer` - lock-free single-writer/many-reader publishing primitive, used for `cp_published_state` and `GuardrailsPolicy`. |
| **Pending confirm**   | Optional state embedded in `TRANSITION_AUTHORITY.pb`, created atomically with exact COMPLETE promotion. Confirmation retains one keyed success until the next allocation. |
| **Rollback intent**   | One durable desired action carrying guarded/target content, cause, policy/runtime generation, optional predecessor sequence, retained key, and observation times. It is not a second transition state machine. |
| **Evaluator state**   | `UNCONFIGURED`, `DISABLED`, `BASELINE_BUILDING`, `ARMED`, `EVALUATING`, or `ROLLBACK_PENDING`. |
| **Attribution score** | Confidence value [0,1] that a configuration change caused observed degradation. Drives the `AUTO_ROLLBACK` / `DEFER_TO_HUMAN` / `LOG_ONLY` decision. |

### 3. Process Lifecycle

> **Visual reference:** [`diagrams/platform_architecture.md` Section 6 (Control Plane)](diagrams/platform_architecture.md#6-control-plane) shows mutation ownership and publication. [`Section 5 (Photon Supervision)`](diagrams/platform_architecture.md#5-photon-supervision) shows the exact DP-control-ready -> CP -> DP-packet-ready startup order.

`cp_main` runs through these steps in order:

1. **Parse CLI** - including the optional exact bootstrap snapshot/plan-hash
   pair, TLS material, guardrails-policy path, and shared logging options.
2. **Establish termination authority before effects or threads** - the main
   process owner blocks `SIGINT`, `SIGTERM`, and `SIGUSR1`, retains its prior mask, and
   creates one close-on-exec nonblocking `signalfd`. Failure restores the prior
   mask and fails startup. Every later Kinetum and gRPC thread inherits the
   blocked set; no asynchronous handler, foreign call, log, allocation, or
   atomic operation executes in signal context. It then admits the logger and
   native gRPC capture before other service threads or RPC objects exist.
3. **Admit all startup files before config-store or remote effects** - both
   bootstrap values absent selects the explicit control-only posture. Otherwise
   both must be present. CP opens the exact absolute, lexically normalized
   snapshot path without following symbolic links, requires a regular
   single-linked file without group/world write permission, and retains that
   descriptor. Owner enforcement is deliberately absent for this imported
   deployment artifact; every provider/release artifact keeps its stricter
   owner policy. Descriptor metadata rejects a source above 64 MiB before its
   initial SHA-256. CP then rereads and rehashes the held descriptor, strictly
   parses the protobuf text, enforces the terminal snapshot's 1..256-byte
   identity, closed 0..2^48 revision range, and decoded 10 MiB bound, and
   requires the embedded content hash and supplied lowercase plan SHA-256 to
   decode to exact 32-byte values. It then re-admits the deterministic terminal
   snapshot representation. The optional `--guardrails` protobuf-text file is
   also strictly parsed, recursively rejects unknown fields/enums, and passes
   the complete no-default policy validator. No epoch or policy generation is
   allocated yet.
4. **Open config_store without manufacturing restart history** -
   `config_store::open()` admits or creates one exact absolute durable root and
   fully re-admits every existing record. A fresh root remains without active
   authority until DP Health proves `CONTROL_READY`; the already-admitted
   source is retained in memory but is not yet imported. Existing durable state
   remains sole active truth.
5. **Connect to dataplane** - build a gRPC channel and stub for
   `DataplaneService`. Uses TLS if `--client-tls-*` flags are set.
6. **Observe DP Health before choosing startup behavior.** Read-only transient
   Health failures retry under one 30-second overall bound. `CONTROL_READY`
   first calls `reconcile_bootstrap()`: a fresh source becomes one atomic
   transition-authority envelope with epoch/allocation/mutation identities all
   equal to one. An existing authority requires the same plan and, while still
   pristine, the same snapshot; later history retains its durable active content.
   Only after reconciliation may CP send the retained Bootstrap request;
   every echo is checked. `PACKET_READY` requires active
   authority that existed before this first DP observation and never imports a
   fresh source. CP refreshes Health immediately before each mandatory
   telemetry attempt. A transition completing between those two coherent reads
   makes active-epoch skew `UNAVAILABLE` and retries from a new Health sample;
   runtime-generation or worker-membership disagreement is `DATA_LOSS`. A
   stable pair must then have exact plan hash, active epoch, active validation
   hash, and the lawful watermark relation. Watermarks are normally exact. The
   one exception is
   durable `ALLOCATED`, pre-admission
   `ABORT_PENDING`, or its terminal `ABORTED` result leading an idle surviving
   DP by one adjacent pair because CP persists allocation before its first
   Prepare attempt. A DP exactly one COMPLETE publication ahead of durable
   `COMPLETION_PENDING` is likewise admitted only for typed reconciliation. A
   fresh CP store beside PACKET_READY is `DATA_LOSS` with no durable import.
   Every Health, Stats, and later transition Status RPC deadline is capped by
   the remaining steady startup budget, so an in-flight five-second transport
   attempt cannot extend the overall bound.
7. **Resolve fresh-generation orphan state.** Successful CONTROL_READY
   Bootstrap removes the nonterminal epoch allocation while preserving both
   watermarks. An already-satisfied pending rollback intent clears without a
   manufactured epoch. An unsatisfied intent whose own rollback allocation was
   orphaned keeps its key and desired target so a fresh epoch can serve it.
   Terminal intent failure remains durable.
8. **Construct and admit control_loop** - CP requires the loop's immutable
   constructor-time storage status and exact DP transition client construction
   to succeed before exposing any service. The loop remains stopped while all
   optional startup input is admitted.
9. **Reconcile retained transition and safety intent.** On surviving
   PACKET_READY, terminal records are re-proven through typed Status and any
   nonterminal phase resumes through the same classifier used during ordinary
   mutation. A terminal rollback intent rejects startup before any retained
   transition can be resumed. An ordinary exact ABORTED convergence preserves
   active content and permits service publication; an intent-owned abort remains
   a typed terminal intent and blocks startup. On fresh Bootstrap, orphan
   handling above runs first. The durable intent is then either already
   satisfied, advanced through an exact rollback after its named predecessor
   completes, or retained with one typed terminal failure. Only transient
   observations retry, under the same bounded startup interval.
10. **Persist optional startup policy.** After transition/intent reconciliation,
   an explicit policy either matches the durable hash exactly or allocates one
   new policy generation and publishes it to the runner's RCU view.
11. **Start packet-ready authorities** - start the control-loop worker, then
    the guardrails/commit-confirmed runner. A control-only outcome leaves both
    stopped and constructs no runner.
12. **Construct gRPC service** - `control_service_impl service(&store, dp_stub, loop)`.
13. **Build and start the gRPC server** - `ServerBuilder` registers the
    control service and the listen address.
14. **Wait for control signals on the main thread.** `SIGUSR1` requests checked
    log reopen and leaves termination authority live. `SIGINT` or `SIGTERM`
    ends the wait. Short records and invalid descriptor states fail closed.
    The main thread then calls `server->Shutdown()` and `server->Wait()` from
    ordinary execution context.
15. **Graceful shutdown** stops and joins the guardrails runner, then drains,
    stops, and joins the mutation worker. Native emitters retire before the
    logging writer's bounded final drain and join. The signal owner retires
    pending control records and restores the main thread's prior mask only
    after all inheriting threads are gone.

Notable defaults when CP is launched standalone (Photon overrides these
when supervising):

| Flag                  | Default                         |
| --------------------- | ------------------------------- |
| `--listen-addr`       | `0.0.0.0:50051`                 |
| `--dp-addr`           | `127.0.0.1:50052`               |
| `--config-store-dir`  | `/tmp/kinetum_cp_store`         |
| `--bootstrap-snapshot` | absent (control-only posture)   |
| `--bootstrap-plan-content-hash` | absent (control-only posture) |
| `--guardrails`        | absent (retain durable policy or remain unconfigured) |
| `--log-dir`           | `/var/log/kinetum` |

The shared level, component override, file-size/count, and console options are
specified in [Logging](LOGGING.md). Photon forwards the complete admitted
settings. An unprivileged standalone CP can select its own protected absolute
log directory instead of the production default.

When [`PHOTON.md`](PHOTON.md) launches CP, it also supplies the canonical
runtime-bundle snapshot path and exact verified plan hash as one inseparable
pair. CP revalidates their process-boundary representation before initializing
the store. It imports pristine content or verifies the exact plan around the
store's later durable active state; the supplied initial snapshot never repairs
or overwrites a non-pristine authority. Active content, plan hash, allocation
watermarks, and deterministic Bootstrap key remain one nested request.

### 4. Control Loop

> **Visual reference:** [`diagrams/platform_architecture.md` Section 6 (Control Plane)](diagrams/platform_architecture.md#6-control-plane) shows the end-to-end mutation authority. The exact cancel-safe timeout race remains specified in section 4.4 below.

`control_loop` (declared in `src/cp/control_loop.hpp`) is the single
writer for all CP state mutations. It owns one worker thread, a fixed 64-cell
mutation mailbox, one caller-owned safety-intent slot, the guardrails policy
RCU buffer, and the `cp_published_state` RCU buffer. Durable retry truth lives
only in `config_store`.

#### 4.1 Mutation alternatives

The active alternative of `mutation_payload` is both the operation identity
and its data. The worker visits that variant exhaustively; adding another
alternative therefore requires every identity classifier and dispatch site to
handle it at compile time.

| Payload struct                  | Carries                                                              |
| ------------------------------- | -------------------------------------------------------------------- |
| `set_config_payload`            | `ConfigSnapshot` plus `confirm_timeout_ms` (0 = no commit-confirmed) |
| `confirm_config_payload`        | Required exact `snapshot_id`, `epoch`, and `revision`                |
| `rollback_payload`              | `target_snapshot_id`, optional `module_ids[]` (empty = full rollback)|
| `set_guardrails_policy_payload` | Complete `GuardrailsPolicy` plus expected policy generation          |

#### 4.2 The `mutation` and `mutation_result` types

```cpp
using mutation_payload = std::variant<
    set_config_payload,
    confirm_config_payload,
    rollback_payload,
    set_guardrails_policy_payload>;

class mutation final {
  public:
    template <mutation_payload_type payload_type>
    explicit mutation(std::string idempotency_key,
                      std::optional<int64_t> expected_revision,
                      payload_type payload);

    mutation() = delete;
    mutation& operator=(const mutation&) = delete;
    mutation& operator=(mutation&&) = delete;

    const std::string& idempotency_key() const noexcept;
    const std::optional<int64_t>& expected_revision() const noexcept;
    const mutation_payload& payload() const noexcept;

  private:
    std::string idempotency_key_;
    std::optional<int64_t> expected_revision_;  // Absence alone skips CAS
    mutation_payload payload_;                  // Sole operation identity
};

struct mutation_result {
    kinetum::common::status status;
    int64_t revision = 0;
    uint64_t epoch = 0;
    std::string snapshot_id;
    uint64_t policy_generation = 0;
    sha256_digest policy_hash{};
    int64_t time_remaining_ms = 0;     // ConfirmConfig only
    bool ok() const noexcept { return status.is_ok(); }
};
```

`mutation` cannot be default-constructed or assigned, so a constructed request
cannot become valueless or change operation identity while it moves to the
worker. `mutation_result.epoch` is the CP-allocated epoch that DP completed.
`confirm_config_payload` does not touch DP, but its result returns the pending
record's epoch. `set_guardrails_policy_payload` does not touch DP and leaves
the epoch at `0`.

#### 4.3 `submit(mutation)` - Wait-to-Complete

```cpp
mutation_result submit(mutation m);
```

The submitter allocates one complete `pending_mutation` before acquiring the
mailbox mutex. That context owns the construction-fixed request, one
`std::promise<mutation_result>`, and optional cancellation state. Under the
mutex, the submitter tries to copy its raw pointer into one of 64 preallocated
`mpmc_queue` cells. Success transfers linear ownership to the worker and the
submitter waits on the future. A stopped loop returns `UNAVAILABLE`; a full
mailbox returns `RESOURCE_EXHAUSTED`. Either rejection leaves ownership with
the submitter, destroys the context, and occurs before revision CAS, durable
store work, DP contact, or idempotency-key consumption.

Every enqueue and dequeue participates in the same mutex protocol as the
condition-variable predicate. The generic MPMC primitive supplies bounded,
allocation-free cell publication; the mutex closes the check-to-wait edge and
makes `queue_depth()` exact. These are distinct responsibilities, not two
competing queue authorities. Multiple gRPC threads may submit concurrently,
but the worker remains the sole semantic writer.

#### 4.4 `submit(mutation, timeout)` - cancel-safe deadline

```cpp
mutation_result submit(mutation m, std::chrono::milliseconds timeout);
```

Implements an explicit per-mutation state machine. The submitter and
worker both hold a `shared_ptr<atomic<request_state>>`. Transitions:

```
QUEUED ---(worker dequeues, CAS)---> EXECUTING ---> COMPLETED
   |
   +--(timeout fires, CAS)---> CANCELED   (worker will skip this entry)
```

Once a mutation is `EXECUTING`, timeout cannot CAS it to `CANCELED`; the
submitter waits for the actual result. This prevents a false timeout from
inviting a second apply while the first still runs.

Successful cancellation changes only the request state. It does not revoke the
pointer already owned by the mailbox: the worker later dequeues, recognizes,
and destroys that context without dispatching it. Queue storage, context
ownership, cancellation, and durable retry identity are therefore separate
facts.

Safety intents use `submit_safety_intent(request)`, which borrows one stack
context and waits unconditionally. The worker releases the borrow only after
`accept_rollback_intent()` durably publishes the intent or rejects it before
publication. A timed return could leave the worker holding a dead stack address.

The same worker services this slot between DP Status observations and services
an accepted intent before dequeuing another ordinary mutation. Shutdown resolves
published contexts and leaves accepted durable intent for restart. DP's compiled
transition deadlines still govern rollback behavior.

An intent carrying `wait_for_mutation_sequence` resolves that predecessor
before testing whether its target content is active. During COMMITTING the old
target is still CP's last COMPLETE content; that fact cannot clear a rollback
which exists precisely in case the named successor completes. Predecessor
COMPLETE permits E+2 allocation; predecessor ABORTED terminally fails the
already-durable intent in that same authority replacement. A decision reaching
admission only after ABORTED is a stale prepublication request and returns
`FAILED_PRECONDITION` without creating an intent. Only orphan reconciliation
may declare the already-restored target satisfied without another epoch. The
E+2 allocation replacement rebinds
`wait_for_mutation_sequence` from the completed predecessor to E+2 itself.
A joint restart that discards that orphaned allocation can therefore clear the
wait back to zero while preserving the same desired target and transition key.

#### 4.5 Statistics

Read-only accessors (thread-safe):

| Method                    | What it returns                                                  |
| ------------------------- | ---------------------------------------------------------------- |
| `queue_depth()`           | Exact occupied mailbox-cell count at the mutex-protected observation, from 0 through 64. |
| `initialization_status()` | Immutable constructor-time active-record restoration result.     |
| `published_state()`       | Coherent `(revision, snapshot_id)` pair from a single RCU borrow.|
| `guardrails_state()`      | Const reference to the guardrails RCU buffer wrapper.            |

`published_state()` is the only active revision/snapshot projection, so a
caller cannot split that identity across two borrows.

### 5. Durable Retry Identity and CAS

There is no CP-local idempotency map, TTL, FIFO, or cache-hit counter. Each
mutation class has one durable identity law:

| Operation | Durable retry identity |
| --------- | ---------------------- |
| Set / rollback | Canonical snapshot hash, full retained key, allocated epoch, mutation sequence, and durable phase. |
| ConfigureGuardrails | Current canonical policy hash, policy generation, and caller-key digest. |
| ConfirmConfig | Exact snapshot/epoch/revision plus confirmation-key digest and retained first-success result. |
| Internal safety rollback | Complete guarded/target observation, typed cause, policy/runtime generation, optional predecessor sequence, and one retained full transition key. |

Snapshot mutations first ask whether the key names the current/latest durable
transition. An exact retained retry proceeds even when its original revision
CAS is now stale. A new key then passes the ordinary revision CAS before its
handler executes.

#### 5.1 Guardrails policy retry matrix

`configure_guardrails_policy()` canonicalizes and hashes the complete policy,
then classifies retry before comparing `expected_policy_generation`:

1. Same key digest and same policy hash returns the retained generation and
   hash without a write.
2. Same key digest and different hash is an identity conflict.
3. A new key with stale expected generation is `FAILED_PRECONDITION`.
4. A new key with the exact current generation performs one durable
   replacement and advances the nonzero generation once.

`expected_policy_generation` uses proto3 optional presence. Generation zero is
a real first-write CAS value; omitting the field is malformed rather than an
implicit request for zero.

The current policy record is bounded retry memory. Once a later policy replaces
it, an old request cannot succeed because its expected generation is stale.

#### 5.2 Confirm and producer key lifetime

The first valid Confirm before its durable deadline atomically records the key
digest and exact remaining time. Same identity and key returns those bytes even
after the deadline and even beside a later safety intent; wrong identity or key
fails. An unconfirmed record cannot cross a durable safety intent. The confirmed
record remains until the next successful epoch allocation clears it in that
allocation's authority replacement. This closes ambiguous response loss without
a second state file.

In-tree producers make key lifetime structural. `kinetumctl` generates one
32-byte OpenSSL random value per set, rollback, guardrails, or Confirm command
before the first RPC and captures the complete request across
`execute_with_retry`. The guardrails runner generates one key before an exact
desired action crosses the unconditional safety channel; after durable
acceptance that same key drives every transition retry and survives restart.
None uses clock, PID, hostname, or an empty-key fallback.

#### 5.3 CAS revision check

```cpp
if (m.expected_revision().has_value() &&
    *m.expected_revision() != current_revision_) {
    return failed_precondition("Revision mismatch: ...");
}
```

An absent field skips the check. Exact zero remains a real CAS value.

CAS is enforced for SetConfigSnapshot and Rollback (the mutating RPCs that
accept `expected_revision` on the wire - see [`GRPC_API.md`](GRPC_API.md)
section 4). ConfirmConfig and ConfigureGuardrails do not pass an
`expected_revision` from their RPC handlers.

### 6. Exact DP Transition Client Boundary

> **Visual reference:** [`diagrams/platform_architecture.md` Section 7
> (Transition RPC Boundary)](diagrams/platform_architecture.md#7-transition-rpc-boundary)
> shows the durable CP and ordered DP transaction as one sequence.

`apply_to_dp_(snapshot, idem_key, confirm_timeout_ms)` is reached by packet-
ready `set_config_payload` and `rollback_payload` alternatives. It first invokes the
durable CP epoch allocator:

1. Re-admit the exact active Bootstrap request.
2. Canonicalize the candidate against the active snapshot's plan-proven module
   set through the same implementation used by plan-based canonicalization.
3. Validate the required 1..256-byte printable-ASCII key.
4. Reject allocator approach-to-wrap or nonexact overlap before corpus effects.
5. Create-only stage the active and candidate terminal snapshots in the
   immutable corpus.
6. Advance target epoch and mutation sequence together.
7. Recompute the nested Bootstrap key through the shared derivation.
8. Replace `TRANSITION_AUTHORITY.pb` once with both watermarks and the exact
   `ALLOCATED` transition record.

An exact retained retry returns the same reconstructed Prepare request without
rewriting the authority. Same-key/nonexact content, a different nonterminal
transaction, stale durable state, or one-sided advancement fails closed.

The exact `dataplane_transition_client` then drives only typed observations:

```
CP control_loop                                             DP coordinator / workers
 |                                                          |
 | canonicalize + create-only corpus                        |
 | persist HWM + ALLOCATED                                  |
 |-- Status(exact identity) ------------------------------->|
 |<-- UNKNOWN_FUTURE / active / terminal -------------------|
 |-- Prepare when unknown --------------------------------->| cold module/snapshot staging
 |<-- PREPARING / PREPARED / ABORTED -----------------------|
 | persist PREPARED                                         |
 | persist COMPLETION_PENDING                               |
 |-- Activate(exact identity) ----------------------------->| grace -> COMMITTING -> worker command
 |<-- COMPLETE or update-frozen RETIRING -------------------| CUT/ACK -> certificate -> retirement
 | persist terminal/active truth                            |
```

Status reconciles both restart and transport retry. For an `ALLOCATED`
transaction, `UNKNOWN_FUTURE` permits Prepare; for `ABORT_PENDING` or `ABORTED`,
it records ABORTED without preparing. PREPARING is polled; PREPARED is persisted
before Activate. COMMITTING/RETIRING are observation-only polls; exact COMPLETE
promotes active content; exact ABORTED retains active content and consumed
watermarks. A typed retirement-grace deadline freezes updates and requires
recovery. `UNAVAILABLE` or `DEADLINE_EXCEEDED` transport ambiguity is followed
by Status with the same durable identity until one typed observation is available;
non-retryable transport and malformed response failures return without changing
the durable phase. The 10 ms CP poll cadence schedules observation only; DP's
compiled lease/commit/retirement deadlines remain the sole behavior authority.
During startup, each transition-client attempt is additionally shortened to
the remaining 30-second reconciliation budget; ordinary operation retains the
client's five-second per-attempt ceiling.

Because COMPLETION_PENDING is durable before the Activate attempt,
COMPLETION_PENDING plus exact remote PREPARED means retry the same Activate; it
is the expected CP-restart or lost-request state, not a contradiction.

`COMPLETION_PENDING` records intent before the network send, not proof that DP
crossed commit. If the prepared lease or another typed pre-commit cause wins in
that interval, exact terminal ABORTED is a legal durable successor and active
content remains unchanged. No text or CP wall clock may manufacture that edge.

A control-only CP host retains the stronger outer fence: it does not start the
control-loop mutation worker, so public mutation handlers reject before queue,
durable retry, persistence, or transport effects. This does not affect startup
Bootstrap, which is sent directly from the already reconciled durable store.
Read-only CP RPCs remain available.

Bootstrap, Prepare, Activate, pre-commit Abort, and Status share exact
epoch/hash/idempotency/mutation identity ([`GRPC_API.md`](GRPC_API.md), Section
5.1). DP owns admission, asynchronous cold preparation through PREPARED, ordered
worker switching, monotonic lease/abort cleanup, reclamation, and bounded
terminal history.

Snapshot input and canonical output are each bounded to 10 MiB. Module IDs must
match the plan set, modules and label keys have canonical order, recursive
unknown fields reject, and opaque module blobs remain unparsed bytes. Supplied
hashes are verified; the transaction uses the recomputed 32-byte SHA-256. Caller
keys contain 1..256 printable ASCII bytes and enter bounded DP state as digests.

Equal epoch/mutation watermarks require an existing journal match. A retained
key digest cannot name different allocation or content.
`classify_transition_reconciliation()` uses local durable phase, identity
resolution, DP state, and failure code together. Unknown, `UNSPECIFIED`, or
contradictory tuples return `DATA_LOSS`; diagnostics never choose an action.
Before reconciliation the client rejects unknown fields/enums, noncanonical
status, field residue, inexact plan/hash/sequence echoes, and invalid epoch pairs.

### 7. Mutation Handlers

The four `handle_<op>_(payload, idem_key)` handlers in `control_loop.cpp`
execute serially on its worker thread.

#### 7.1 `handle_set_config_` (full walkthrough)

The handler has three phases, each failing closed:

**Phase 1: Validation** (synchronous, no side effects).

| Check                                | Failure status         |
| ------------------------------------ | ---------------------- |
| `snapshot_id` non-empty              | `invalid_argument`     |
| `snapshot_id.size() <= 256`          | `invalid_argument`     |
| `ByteSizeLong() <= 10 MiB`           | `resource_exhausted`   |
| `revision >= 0 && revision <= 2^48`  | `invalid_argument`     |
| idempotency key is 1..256 printable ASCII | `invalid_argument` |
| `confirm_timeout_ms == 0` or a previous active snapshot exists | `failed_precondition` |

Commit-confirmed requires an active rollback target before any snapshot write
or DP call. Production establishes that baseline through bundle bootstrap;
subsequent changes may use `confirm_timeout_ms > 0`.

**Phase 2: Canonicalize and durably allocate** -
`apply_to_dp_(snap, idem_key, confirm_timeout_ms)` delegates to
`store.begin_epoch_transition(...)`. Raw and canonical-output size overflow use
`resource_exhausted`; syntax and scalar errors remain `invalid_argument`.
Create-only corpus writes are semantically inert until the one authority
replacement references the candidate. On success, both watermarks and the
exact transition identity become durable together.

**Phase 3: Typed DP choreography** - Status/Prepare drive the exact transaction
to PREPARED, CP persists that phase, CP persists COMPLETION_PENDING, and
Activate/Status converge to terminal truth. Exact COMPLETE promotes active
content and optional pending-confirm state in one authority replacement.
Exact ABORTED records a canonical terminal failure without moving active
content. Update-frozen RETIRING preserves the durable pending phase for
operator recovery.

Wire range: `SetConfigSnapshotRequest.confirm_timeout_ms` is `uint64`
in the proto, while the control-loop payload stores the accepted value
as `uint32_t`. `cp_grpc.cpp` rejects values above the `uint32_t` range
with `invalid_argument` before submitting the mutation.

Returns `mutation_result{status=OK, epoch=target}` only after exact COMPLETE,
or the typed transport/application/persistence failure with epoch zero. Exact
retries reuse the retained allocation and generated snapshot fields. A control-
only host's stopped loop rejects before this path.

#### 7.2 `handle_rollback_` (full walkthrough)

Both forms load the target and use `apply_to_dp_` for canonicalization,
durable allocation, and typed DP transition. Full rollback selects the target's
content. Selective rollback first constructs a hybrid snapshot using selected
target modules and the remaining current modules. Section 20 defines its
module-set checks, generated fields, and retry rules. Active content changes
only after DP reports COMPLETE.

#### 7.3 `handle_confirm_config_`

Calls `confirm_pending_config()` once with required snapshot ID, epoch,
presence-qualified revision, key, and the current Unix deadline sample. Under the store's sole
mutation lock, the method:

- requires exact pending identity;
- returns a retained same-key confirmation before consulting the clock;
- rejects a first confirmation at or after `deadline_unix_ms` with
  `DEADLINE_EXCEEDED`;
- rejects a regressed clock sample that would manufacture more than the
  original interval; and
- otherwise writes `confirmed`, key digest, and exact remaining milliseconds
  in one authority replacement.

It does not clear the record. The next successful epoch allocation clears the
terminal confirmation atomically, so a lost Confirm response remains retryable.

#### 7.4 `handle_set_guardrails_policy_`

Delegates the complete policy, retained key, and expected generation to
`config_store::configure_guardrails_policy()`. Only after durable success does
it publish the returned policy at that exact generation through the RCU buffer:

```cpp
guardrails_state_.policy.store(durable.policy, durable.generation);
```

The runner thread polls `policy.version()` for changes (see section 14).

An exact durable retry performs no RCU publication when the same value is
already present. The result returns policy generation and raw SHA-256 together
with unchanged active revision/snapshot; policy updates do not allocate a DP
epoch.

### 8. Config Store

`config_store` (declared in `src/cp/config_store.hpp`) is the durable
persistence authority. `config_store::open()` admits one exact absolute root,
retains its directory descriptor, and fully loads every record before an
instance becomes visible. No later store operation re-resolves the root through
the current working directory or a caller-supplied pathname.

CP retains durable history and allocates epochs. DP's coordinator instead owns
two snapshot lifecycle slots and bounded transition state; packet workers read
module views, not this store. Rollback sends historical CP content through the
same monotonic transition path. See [DP snapshot storage](DATA_PLANE.md#6-exact-snapshot-epoch-store).

#### 8.1 File layout

| File                                      | Purpose                                                                 |
| ----------------------------------------- | ----------------------------------------------------------------------- |
| `TRANSITION_AUTHORITY.pb`                 | Sole mutable deterministic private envelope: exact active Bootstrap, optional current/latest transition, optional PendingConfirm, optional canonical guardrails policy, and optional durable rollback intent. |
| `snap_<sha256(snapshot_id)>.pbtxt`         | Immutable terminal canonical corpus object. The embedded 1..256-byte snapshot ID is semantic authority; the fixed digest leaf is rederived on restart. |

Any file outside the two declared classes, malformed protobuf, unknown field, invalid enum,
noncanonical authority bytes, corpus filename/content disagreement, or any
cross-record identity mismatch also reject startup.

The active snapshot may also exist in the corpus. Exact canonical byte equality
makes that one logical snapshot and `list_snapshot_page()` projects it once as
active. The same ID with different bytes is `DATA_LOSS` whether the collision
is corpus/corpus, corpus/active, or staging/existing. Promotion changes only
the atomic authority; it never deletes, renames, or rewrites a corpus object.

The durable root may be created only as the missing terminal component beneath
an existing exact parent. It must belong to the current effective UID and may
not be group- or world-writable. Store files are regular, single-linked,
current-UID-owned, and mode `0600`; traversal uses `openat` plus `O_NOFOLLOW`.
One CP process owns one root; there is no lockfile or multi-process writer
protocol.

Every publication first writes and fsyncs complete bytes under an unrelated
private same-directory `.kinetum.tmp.<pid>.<sequence>` name. That prefix is
reserved from caller-owned records. Immutable corpus objects and the initial
authority use Linux rename-without-replacement; every later observable mutable
state change is exactly one admitted authority replacement. The retained
directory is fsynced after every
namespace mutation. An ordinary failure before rename cleans the private
temporary file. If the sole prior CP owner stops first, the next open validates
and durably unlinks every exact abandoned private temporary before admitting
ordinary store state; malformed reserved names and unknown ordinary files still
reject. A directory-fsync failure after rename or unlink terminates the process
because the durable commit outcome can no longer be reported truthfully.

#### 8.2 Public API

| Method                                      | Use                                                                |
| ------------------------------------------- | ------------------------------------------------------------------ |
| `open(absolute_root)`                       | Admit/create the descriptor-rooted directory and fully re-admit all existing state before returning a unique store. |
| `reconcile_bootstrap(authority)`            | Import one fresh authority, require exact snapshot/plan agreement while pristine, and thereafter preserve durable active content while requiring the same exact plan. |
| `active_bootstrap()`                        | Return the exact nested six-field wire request; `NOT_FOUND` for a fresh control-only store. |
| `active_snapshot_id()` | Read the active snapshot ID; corpus writes cannot change it. Active revision is carried by `runtime_authority()`. |
| `runtime_authority()`                       | Return a lock-coherent compact active/transition fence: IDs, revision, raw hashes, epochs, watermarks, and optional target identity without copying snapshot blobs. |
| `stage_snapshot(canonical)`                 | Create-only publish one terminal canonical corpus object. Exact retry is I/O-free; same ID/different bytes is `DATA_LOSS`. |
| `begin_epoch_transition(...)`               | Canonicalize against active module shape, stage corpus closure, allocate both values, recompute the Bootstrap key, and publish one `ALLOCATED` record atomically. |
| `epoch_transition()` / `epoch_transition_key_matches(key)` | Reconstruct current/latest transition state or test exact retained-key identity without copying protobuf content. |
| `advance_epoch_transition_phase(...)`       | Publish only one legal CP intent edge after exact fixed-identity matching. |
| `complete_epoch_transition(...)` / `abort_epoch_transition(...)` | Retain exact terminal outcome; an ABORTED retry must reproduce the compact code/error-classification/message and cannot smuggle unretained details. COMPLETE also promotes active content and creates optional pending-confirm state in the same write. |
| `discard_orphaned_epoch_transition_after_bootstrap()` | After proven fresh Bootstrap, discard only the orphaned allocation; resolve an already-satisfied intent, preserve an unsatisfied intent/key for fresh allocation, and retain terminal intent failure. |
| `list_snapshot_page(size, token)` / `load_snapshot(id)` | Page or binary-search the active-plus-corpus logical snapshot set. |
| `confirm_pending_config(...)` / `load_pending_confirm()` | Atomically enforce deadline and exact retry; confirmation remains until the next successful allocation. |
| `configure_guardrails_policy(...)` / `guardrails_policy()` | Canonical policy generation/hash/key-digest retry authority. |
| `accept_rollback_intent(...)` / `rollback_intent()` / `fail_rollback_intent(...)` / `clear_completed_rollback_intent(...)` | Persist, inspect, terminally fail, or exactly complete the one desired safety action. |

#### 8.3 In-memory index and listing projection

After restart admission, corpus snapshots live in one strictly ID-sorted
contiguous vector. Exact lookup and insertion use binary search; a write builds
the complete next vector before durable publication and swaps it into memory
only after the create-only file commit succeeds. One owned authority message
contains all mutable active, transition, pending-confirm, policy, and intent
truth. One shared mutex covers the complete filesystem/in-memory transaction:
readers never observe a half-published projection or a split active
identity/revision.

`list_snapshot_page(page_size, page_token)` first parses a nonempty bounded
token completely before taking the store lock. Under one shared lock it derives
the active row's sorted position, projects an exact active/corpus match once or
inserts distinct active content at that position, and hashes the complete
listing identity. That hash covers every corpus ID and canonical validation
hash plus the active snapshot ID, revision, epoch, allocation watermarks, plan
hash, and content hash. A continuation also binds the final ID emitted by the
preceding page. Malformed tokens are `INVALID_ARGUMENT`; a valid token against
changed listing truth is `ABORTED`, never an empty page.

The store then locates the continuation ID by binary search and returns at most
`page_size` rows. Each row contains exactly the six owned `SnapshotInfo`
fields: `snapshot_id`, `revision`, `created_unix_ms`, `is_active`,
`description`, and `author`. `total_count` names the complete logical set, and
`next_page_token` is empty only at its exact end. The server keeps no cursor,
performs no directory scan after `open()`, and rederives the O(n) listing hash
for each request; page materialization itself is O(page_size).

`ControlService.ListSnapshots` forwards one such page. `kinetumctl` follows
every continuation, requires stable total count, strictly increasing unique
IDs, at most one active row, bounded nonempty progress, and an empty terminal
token, then emits the complete response once. The control-loop RCU snapshot is
a downstream observation and never overrides the durable active row.

### 9. gRPC Service

`control_service_impl` in `src/cp/cp_grpc.hpp` extends the generated
`ControlService::Service`. It borrows the store and control loop, which must
outlive the service, and shares ownership of the DP stub:

```cpp
config_store *store_;
std::shared_ptr<DataplaneService::Stub> dp_;
control_loop &loop_;        // single shared mutation authority
```

Plus a `start_time_` for uptime reporting in `HealthCheck`.

#### 9.1 Handler patterns

Handlers fall into two patterns:

**Mutating RPCs** (`SetConfigSnapshot`, `Rollback`, `ConfirmConfig`,
`ConfigureGuardrails`):

```
1. Require the shared mutation authority before materializing a mutation.
   A control-only stopped loop returns application UNAVAILABLE here.
   ConfigureGuardrails additionally validates its complete nested policy.
2. Construct a `mutation` from the request. Its concrete payload alternative
   is the operation identity; the same object owns the idempotency key and
   optional expected revision.
3. Call `loop_.submit(std::move(m))`.
4. Map `mutation_result.status` -> canonical response status (numeric code,
   exact semantic error classification, message, and details).
5. Copy operation-specific success fields into the response.
   `SetConfigSnapshot` and `Rollback` return revision/epoch/snapshot IDs.
   `ConfirmConfig` returns exact
   snapshot/epoch/revision plus retained remaining time.
   `ConfigureGuardrails` returns policy generation and raw hash.
6. Return `grpc::Status::OK`; the embedded application status carries the
   ordinary operation outcome.
```

**Read RPCs** (`ListSnapshots`, `GetActiveSnapshot`, `GetGuardrails`,
`HealthCheck`, `GetStats`):

```
ListSnapshots     -> store_->list_snapshot_page(page_size, page_token)
GetActiveSnapshot -> store_->active_snapshot()
GetGuardrails     -> store_->guardrails_policy()
HealthCheck       -> SERVING + version + uptime + independent logging observation
GetStats          -> clear output; require DP transport + application success;
                     then aggregate coherent CP state plus the complete DP observation
```

All nine handlers share one representation boundary. Allocation or size
failure while constructing the final response returns transport
`UNAVAILABLE`; a partially populated response is not authoritative and a
mutation caller retries with the same retained idempotency identity. An
unexpected exception at this process boundary terminates rather than escaping
through gRPC or being mislabeled as an application result. A null direct
invocation is transport `INVALID_ARGUMENT`.

`GetStats` has an intentionally strict all-or-nothing boundary. A missing DP
stub, transport failure, exception, explicit DP application failure, or
contradictory `code == 0` plus error classification returns application
failure with status only. No CP identity, epoch, counter, or repeated row is
mapped on those paths, so protobuf zero values cannot become observations. The
DP diagnostic is bounded to 512 bytes. Only exact DP application success maps
the coherent CP `(revision, snapshot_id)` publication. CP reads a
compact durable authority before and after the DP call, validates shared
`RuntimeTelemetry`, and classifies active content through one exact fence. A
lawful DP-COMPLETE/CP-COMPLETION_PENDING reply-loss window is `UNAVAILABLE`
until CP promotes the target; an unexplained coherent mismatch is `DATA_LOSS`.
No full ConfigSnapshot blob is copied at telemetry cadence.

CP makes one downstream call per statistics attempt. Its child context inherits
caller cancellation and the earlier of the incoming deadline and a local
30-second cap; an expired call starts no DP read. Transport categories retain
their meanings, and application failures must contain a canonical status with
no telemetry or unknown fields. CP performs no statistics retry.

`ListSnapshots` requires a positive bounded page size and one empty or exact
opaque continuation. Each stateless token binds corpus plus active authority;
a listing change returns `ABORTED`. `GetActiveSnapshot` copies complete active
content under one store lock rather than composing two independently mutable
reads.

#### 9.2 Status code mapping

All mutation handlers populate the canonical numeric-code/semantic-error
relation. Aggregate statistics
populate semantic `error_code` on locally produced failures and preserve the
DP's exact nonzero code/classification on a valid application failure. One shared
exact response admission defines success for CP aggregation, `kinetumctl`, and
guardrails: code zero requires `ERROR_CODE_OK`; an
UNSPECIFIED, contradictory, or undeclared representation is malformed. Numeric platform status values are carried as
`int32_t` and align with gRPC canonical codes for the used subset.

The exact DP transition client uses the stricter canonical decoder: every code,
including success, must carry its one exact semantic `ErrorCode`; diagnostic
residue beside success, oversized messages, unknown fields, or unknown enums
reject before durable reconciliation.

These embedded-status mappings apply only when transport is OK. Transport
`UNAVAILABLE` from response construction carries no trustworthy application
body and is handled as retryable transport ambiguity, not decoded as an
application status.

The in-tree statistics consumers close the same boundary by role: CP and
`kinetumctl` use the shared full-response validator; guardrails consumes only
typed final fields after that validation; and the Python
validation wrapper requires a successful `kinetumctl` exit before strictly
parsing protobuf JSON without Boolean or integer coercion.

### 10. Authentication and TLS

All TLS is at the transport layer; the proto contract has no auth
fields. `cp_main` exposes flags grouped two ways.

#### 10.1 Server TLS (CP listening)

| Flag                          | Effect                                                               |
| ----------------------------- | -------------------------------------------------------------------- |
| `--tls-cert <pem>`            | Server certificate chain.                                            |
| `--tls-key <pem>`             | Server private key.                                                  |
| `--tls-ca <pem>`              | CA cert for verifying client certs (mTLS).                           |
| `--tls-require-client-auth`   | Enforce mTLS - reject clients without a verified cert.               |

If none of the TLS flags are passed, CP listens with
`InsecureServerCredentials`. If any server TLS flag is supplied, CP
requires a readable, nonempty certificate and key; mTLS additionally requires
a readable, nonempty CA file. `make_server_credentials()` returns `nullptr` on
missing, partial, empty, or unreadable TLS material, and `cp_main` aborts
startup. Supplied certificates also pass the fixed validity-window and key-
strength checks before credential construction; leaf certificates cannot be
self-signed, while root CA material may be. Photon does not forward these
flags, so its supervised child path is
plaintext. A TLS deployment must launch CP and DP through an external process
owner with the complete matching binary flags.

#### 10.2 Client TLS (CP -> DP)

| Flag                       | Effect                                                              |
| -------------------------- | ------------------------------------------------------------------- |
| `--client-tls-ca <pem>`    | Root CA for verifying DP's certificate.                             |
| `--client-tls-cert <pem>`  | Client cert presented to DP (for DP-side mTLS).                     |
| `--client-tls-key <pem>`   | Client private key.                                                 |

If all client TLS fields are unset, the channel uses
`InsecureChannelCredentials`. If any client TLS field is supplied,
`make_channel_credentials()` requires a complete readable TLS
configuration for the requested mode. A supplied CA path that cannot be read,
an incomplete client cert/key pair, or an empty supplied TLS file aborts CP
startup before it connects to DP. Certificate prevalidation uses the same fixed strict
policy, and gRPC owns peer-hostname verification. DP must be launched with matching server-side
TLS flags for the secure path to work.

### 11. Validation Constants and Limits

These are constants compiled into the CP binary. Changing them requires
a rebuild.

| Constant                  | Value          | Defined in                | Purpose                                                |
| ------------------------- | -------------- | ------------------------- | ------------------------------------------------------ |
| `MAX_BOOTSTRAP_SNAPSHOT_SOURCE_BYTES` | 64 MiB | `bootstrap_startup.cpp` | Bootstrap pbtxt source ceiling checked before its initial SHA-256. |
| `MAX_CONFIG_SNAPSHOT_BYTES` | 10 MiB       | `epoch_transition_contract.hpp` | Shared snapshot input/canonical-output bound.     |
| `MAX_CONFIG_SNAPSHOT_ID_BYTES` | 256 bytes | `epoch_transition_contract.hpp` | Shared snapshot ID semantic-width bound.          |
| `MAX_CONFIG_SNAPSHOT_REVISION` | 2^48      | `epoch_transition_contract.hpp` | Shared closed revision-domain upper bound.        |
| `MAX_TRANSITION_IDEMPOTENCY_KEY_BYTES` | 256 bytes | `epoch_transition_contract.hpp` | Required printable-ASCII live key bound. |
| `MAX_TRANSITION_DIAGNOSTIC_BYTES` | 256 bytes | `epoch_transition_contract.hpp` | Shared terminal diagnostic bound. |
| `MAX_EPOCH_ID` / `MAX_MUTATION_SEQUENCE` | `UINT64_MAX-1` | `epoch_transition_contract.hpp` | Greatest allocatable values; terminal uint64 is the wrap sentinel. |
| `MAX_TRANSITION_AUTHORITY_BYTES` | Bootstrap bound + 64 KiB | `config_store.cpp` | Active wire request plus bounded transition/confirm/policy/intent metadata. |
| `CONTROL_LOOP_MUTATION_QUEUE_CAPACITY` | 64 contexts | `control_loop.hpp` | Fixed ordinary-mutation mailbox population; no runtime override. |
| `MAX_POLL_INTERVAL_MS`    | 1 hour         | `guardrails_policy.cpp`   | Maximum explicit policy observation cadence.          |
| `MAX_EVALUATION_WINDOW_MS`| 24 hours       | `guardrails_policy.cpp`   | Maximum valid-observation evaluation window.          |
| `MAX_HISTORY_CAPACITY`    | 100,000        | `guardrails_policy.cpp`   | Maximum explicit interval-history bound.              |
| `CONTROL_SERVICE_INTERVAL`| 100 ms         | `guardrails.cpp`          | Maximum condition-variable sleep between ownership rechecks; bounded RPC work may extend wall time. |

The operator-mutation boundary rejects malformed snapshot identity/revision
syntax with `invalid_argument`; raw input or canonical output above 10 MiB is
`resource_exhausted` before corpus or authority mutation. Bootstrap source files
above 64 MiB use the same resource category before parsing. Allocator
approach-to-wrap rejects before corpus publication and never consumes one side
of the pair. Policy cadence, window, history, detector, and attribution values
are explicit durable input; no compiled constant fills a zero field.

---

## Part 2: CP/Guardrails Integration Boundary

### 12. CP/Guardrails Integration Boundary

Guardrails uses the following CP interfaces under the same mutation and
persistence authority.

#### 12.1 Guardrails policy in the mutation taxonomy

`set_guardrails_policy_payload` carries the complete policy and expected
generation. Its enclosing mutation owns the key and uses the same submit path
and writer as snapshot changes (Section 4.1).

#### 12.2 `versioned_rcu_buffer<GuardrailsPolicy>` owned by `control_loop`

The control_loop owns the policy buffer:

```cpp
struct guardrails_runtime_state {
    versioned_rcu_buffer<GuardrailsPolicy> policy;
};
```

The `handle_set_guardrails_policy_` mutation handler is the only writer. It
publishes only after the config store durably commits the same generation and
hash. The guardrails runner reads this low-cost process-local view;
`GetGuardrails` reads the durable record directly. There is one semantic writer
and no service-local policy copy.

#### 12.3 `validate_guardrails_policy()` shared free function

Declared in `src/cp/guardrails_policy.hpp`. Called by:

- `cp_main` at startup, before submitting the initial policy mutation.
- `cp_grpc.cpp::ConfigureGuardrails` handler, before submitting the
  RPC-driven mutation.
- `config_store::configure_guardrails_policy()`, before hashing or persistence.
- `guardrails_evaluator::apply_policy()`, as a final internal backstop.

This is the single authority for policy-shape validation. See section
15 for the rules it enforces.

#### 12.4 The three guardrails-related RPCs

| RPC                      | What it does                                                                |
| ------------------------ | --------------------------------------------------------------------------- |
| `ConfigureGuardrails`    | Require packet-ready mutation authority; submit complete policy, key, and expected generation; return exact durable generation/hash. |
| `GetGuardrails`          | Return unconfigured absence or the exact durable policy/generation/hash. |
| `ConfirmConfig`          | Submit required snapshot/epoch/revision/key; atomically enforce deadline and retain exact success for retry. |

`ConfirmConfig` serves commit-confirmed updates (Section 19); it does not
configure telemetry policy.

---

## Part 3: Guardrails Subsystem

### 13. What Guardrails Is

Guardrails is split into two narrow owners. `guardrails_runner` owns the one
packet-ready thread, gRPC observations, condition-variable cadence, policy RCU
read, commit-confirm deadline service, random key creation, and the linear
safety-intent submission. `guardrails_evaluator` owns the deterministic
six-state baseline/window/detector/attribution machine. It performs no I/O and
cannot mutate configuration.

Guardrails owns:

- A monitoring thread (always alive once `start()` succeeds).
- An optional explicitly configured `health_correlator`.
- One bounded valid-interval `telemetry_history`.
- An `attribution_scorer` over an explicit frozen baseline and current window.
- The state machine that may emit one observation-bound desired action.

Guardrails does not own:

- Mutation execution. Rollbacks go through `submit_safety_intent()` and the
  control loop's existing durable transition choreography.
- Configuration storage. Reads come from `config_store` (the immutable corpus
  and atomic active/transition/pending authority); writes happen via the control
  loop.
- Policy publication. The policy lives in the control_loop's RCU buffer.

The detector and attribution formulas are policy, not transition safety.
Missing evidence is inconclusive and suppresses action; no heuristic can
authorize DP sealing, activation, certificate, grace, or reclamation.

### 14. Runner Lifecycle

> **Visual reference:**
> [Section 9: Guardrails and Rollback](diagrams/platform_architecture.md#9-guardrails-and-rollback)
> shows the six-state evaluator.
> [Guardrails evaluation flow](diagrams/platform_architecture.md#guardrails-evaluation-flow)
> follows one observation through detection and attribution.

`guardrails_runner` starts only after packet-ready CP startup calls `start()`.
It stays alive until `stop()`. Control-only startup constructs no runner thread.
The control loop must already be running, so a published safety context always
has a live unconditional consumer. `stop()` wakes the condition variable and
joins; it never cancels a context already transferred to the control loop.

#### 14.1 Six evaluator states

| State | Meaning |
| ----- | ------- |
| `UNCONFIGURED` | No durable policy exists. Commit-confirmed service remains active. |
| `DISABLED` | An explicit empty `enabled=false` policy exists. No telemetry RPC is issued. |
| `BASELINE_BUILDING` | Valid same-generation intervals are accumulated for one stable content identity. |
| `ARMED` | The baseline is complete; continued stable samples refresh it. |
| `EVALUATING` | New content has frozen the prior baseline and opened one valid-time window. |
| `ROLLBACK_PENDING` | One durable safety intent exists; no second decision is emitted. |

To evaluate a planned content change, enable policy while representative
traffic still runs on the prior content and allow the evaluator to reach
`ARMED`. A change observed during `BASELINE_BUILDING` conservatively starts a
new baseline; it cannot attribute that change without prior evidence.

#### 14.2 Runner service cadence

The runner's condition-variable sleep is at most 100 ms before it rechecks
durable confirmation, intent, and policy ownership. That interval is not
telemetry cadence. An enabled policy has a separate steady deadline equal to
its exact `poll_interval_ms`; only that deadline issues GetStats. A policy
interval below 100 ms therefore wakes at the policy deadline, while a one-hour
policy does not overpoll DP. One in-flight telemetry or confirmation probe may
occupy the sole runner for up to `min(poll_interval_ms, 5 seconds)` or the fixed
five-second confirmation-probe bound. Confirm's serialized store deadline still
prevents that bounded observation delay from admitting a late success. Every
wait is condition-variable/steady-deadline based; there is no `sleep_for`.

#### 14.3 One fenced observation

Each due telemetry attempt performs:

1. Read compact durable active/transition identity under one store lock.
2. Issue one selected DP GetStats with timeout `min(poll_interval, 5 seconds)`.
3. Validate the complete response through the shared telemetry contract.
4. Read the compact durable authority again and require active identity
   unchanged.
5. Require exact plan, active epoch, active validation hash, and either exact
   watermarks or the one adjacent pre-Prepare allocation relation.

The adjacent allocation relation is accepted only while durable phase is
`ALLOCATED`, pre-admission `ABORT_PENDING`, or the resulting `ABORTED`; DP is
IDLE with no active transaction; and both DP values are exactly one behind the
durable pair. This lets restart issue the retained Status/Prepare request or
verify the local terminal abort. Every DP-admitted phase requires exact
equality.
DP target COMPLETE while CP remains durable COMPLETION_PENDING is a recognized
reply-loss relation, but it is not a policy sample; collection returns
`UNAVAILABLE` until CP promotion. Every unexplained coherent mismatch is
`DATA_LOSS`. A malformed transport-success DP Health, Bootstrap, transition,
or Stats payload is likewise `DATA_LOSS` at startup, reconciliation, public
Stats, and guardrails; only bounded host-resource and size failures retain
their exact categories. A
sticky protocol fault is returned as a safety fact: telemetry
policy pauses, while an independently expired commit-confirm deadline may still
create an intent that later terminally records the blocked transition.

Missing transport/application data, non-IDLE transition state, unavailable
required module health, protocol fault, or same-generation regression breaks
interval continuity. The cumulative high watermark remains; the next valid
nonregressing point seeds a fresh interval. Consequently the missing time is
not added to `evaluation_elapsed_ns` and cannot expire a window or fabricate a
healthy baseline.

#### 14.4 Policy replacement

The runner observes the RCU version. A new durable generation constructs the
complete history, scorer, and optional correlator before replacing evaluator
state, then returns to `DISABLED` or `BASELINE_BUILDING`. No weight or bound is
defaulted, and old EWMA/history cannot cross a policy generation. A durable
intent forces `ROLLBACK_PENDING`; after exact completion clears it, the
evaluator rebuilds a fresh baseline against the resulting active content.

### 15. Guardrails Policy

`GuardrailsPolicy` is defined in `proto/kinetum/control/v1/control.proto` and
listed in [`GRPC_API.md`](GRPC_API.md), section 8. These rules govern its durable,
no-default contract.

#### 15.1 Disabled means explicitly empty

Source: `src/cp/guardrails_policy.cpp::validate_guardrails_policy`.

```cpp
if (!policy.enabled()) {
    require every cadence, history, detector, attribution, and boundary field absent/zero;
    return ok();
}
```

A disabled policy cannot stage residue for later activation. Enabling is one
new complete policy generation, never a Boolean flip over hidden old values.

#### 15.2 Per-field ranges (when `enabled = true`)

| Field                                       | Required range                                    |
| ------------------------------------------- | ------------------------------------------------- |
| `poll_interval_ms`                          | `(0, 3,600,000]` (1 ms to 1 hour)                  |
| `evaluation_window_ms`                      | `[poll_interval_ms, 86,400,000]` (>= poll, <= 24 hours) |
| `threshold.max_drop_ratio`                  | finite `[0.0, 1.0]`                                |
| `threshold.min_tx_ratio`                    | finite `[0.0, 1.0]`                                |
| `threshold.min_packets_per_window`          | full `uint64`; zero is literal                      |
| `correlation.drop_ratio_weight`             | finite `[0.0, 1.0]`                                |
| `correlation.throughput_ratio_weight`       | finite `[0.0, 1.0]`                                |
| `correlation.module_health_weight`          | finite `[0.0, 1.0]`                                |
| `correlation.config_issue_boost`            | finite `[0.0, 1.0]`                                |
| `correlation.ewma_alpha`                    | finite `(0.0, 1.0]`                                |
| `correlation.degradation_threshold`         | finite `(0.0, 1.0]`                                |
| `correlation.hysteresis_band`               | finite `[0.0, 0.5]`                                |
| `correlation.min_samples`                   | positive, within history and reachable window intervals |
| `correlation.normalization_max_drop_ratio`  | finite `(0.0, 1.0]`                                |
| `correlation.normalization_min_tx_ratio`    | finite `(0.0, 1.0)`                                |
| `attribution.auto_rollback_threshold`       | finite `(0.0, 1.0]`                                |
| `attribution.defer_threshold`               | finite `(0.0, 1.0]`                                |
| `attribution.baseline_samples`              | positive and no greater than history capacity      |
| `attribution.degradation_threshold`         | finite `(0.0, 1.0]`                                |
| `telemetry_history_capacity`                | `[1, 100000]`                                      |
| `boundary.ack_timeout_ms` (when present)    | positive, no greater than evaluation window, ns-representable |

#### 15.3 Cross-field constraints

- Exactly one detector (`threshold` or `correlation`) must be present.
- `ceil(evaluation_window_ms / poll_interval_ms)` must fit the explicit
  interval-history capacity. The cumulative seed is separate fixed state and
  is not an interval row.
- `correlation.min_samples` cannot exceed the number of valid intervals the
  evaluation window can produce.
- At least one base correlation weight is positive, and base weights plus the
  maximum CONFIG_ISSUE boost cannot exceed 1.0.
- `correlation.hysteresis_band < correlation.degradation_threshold`.
- `attribution.defer_threshold <= attribution.auto_rollback_threshold`.
- A present boundary policy has one positive ACK timeout within the evaluation
  window and safe nanosecond multiplication.

#### 15.4 Zero is never a request for a default

Enabled policy supplies every cadence, history, detector, normalization,
sample, and attribution value. The runner does not repair zero, borrow a value
from the threshold detector, consult an environment variable, or use a CLI
default. The canonical CLI's threshold command explicitly serializes its
chosen attribution values (0.80, 0.50, 10, 0.30) and history capacity 100;
those bytes are ordinary policy, not hidden runner authority.

Individual threshold ratios and `min_packets_per_window` may be literal zero.
In contrast, fields whose range is strictly positive reject zero. Correlation
weights and CONFIG_ISSUE boost may individually be zero under the table's rules.
`CONFIG_ISSUE` boost is a module-health consumer even when
`module_health_weight` is zero, so the runner requests and requires a complete
current health row set for either nonzero field.

#### 15.5 Policy schema closure

The nested policy in sections 15.1 through 15.4 is the complete accepted
shape. Unknown active wire fields reach the recursive unknown-field gate; no
parallel selector, runtime default, or alternate reader changes the policy.

### 16. Health Correlator

`health_correlator` (declared in `src/cp/health_correlator.hpp`, with
computation in `.cpp`) is constructed from one complete explicit
`health_correlation_config`. There is no default constructor or silently
ignored zero setter.

#### 16.1 Inputs and signals

The evaluator first validates cumulative identity and computes one interval
from monotonic nanoseconds. Both threshold and correlation modes consume that
same result. The correlator owns no cumulative counters, first-sample seed,
runtime-generation reset, elapsed-time conversion, or clock truncation. Each
correlation update receives:

- `drop_ratio_raw = dropped_delta / (tx_delta + dropped_delta)`, with exact
  zero-population result `0.0`.
- `throughput_ratio_raw = tx_pps / baseline_tx_pps`. Correlation begins only
  after a positive real baseline exists.
- **`module_health_avg`** is the average of typed `SIGNAL_AVAILABLE` health
  scores (in [0, 100]). Callback-unavailable, awaiting, stale, and suppressed rows are not
  relabeled healthy. When policy consumes health, an incomplete or empty set
  suppresses the whole sample before correlation rather than contributing zero.
- `config_issue_count` and `total_modules` for the boost term.

Each scalar signal is smoothed with a per-signal EWMA. EWMA alpha is
shared across the three (`drop`, `throughput`, `module_health`).

#### 16.2 Normalization

Each smoothed signal is normalized into [0, 1] where 1 = bad:

```
drop_normalized        = clamp(drop_smoothed, 0, max_drop_ratio) / max_drop_ratio

throughput_normalized:
    if throughput_smoothed >= 1.0:        0.0   (no degradation)
    elif throughput_smoothed <= min_throughput:  1.0
    else: (1.0 - throughput_smoothed) / (1.0 - min_throughput)

module_health_normalized = (100 - clamp(module_health_smoothed, 0, 100)) / 100
```

Both normalization bounds are exact policy values. Above the drop bound the
contribution is capped; at or below the throughput bound it is fully bad.

#### 16.3 Weighted sum

```
degradation_score = drop_normalized      * drop_ratio_weight
                  + throughput_normalized * throughput_ratio_weight
                  + module_health_normalized * module_health_weight
                  + (config_issue_count / total_modules) * config_issue_boost
```

The complete maximum contribution, including the boost, is validated not to
exceed 1.0. The computed result is still clamped defensively.

`health_score = (1.0 - degradation_score) * 100`.

#### 16.4 Hysteresis

The runner does not act on `degradation_score` directly. It feeds the
score into a `hysteresis` filter with the exact configured threshold and band:

```
if previously is_degraded:
    is_degraded = degradation_score > (threshold - band/2)
else:
    is_degraded = degradation_score > (threshold + band/2)
```

This prevents oscillation when the score hovers near the threshold.

#### 16.5 The `signal_breakdown` returned each iteration

```cpp
struct signal_breakdown {
    // Raw, smoothed, normalized, contribution per signal.
    double drop_ratio_raw, drop_ratio_smoothed, drop_ratio_normalized,
           drop_ratio_contribution;
    double throughput_ratio_raw, throughput_ratio_smoothed,
           throughput_ratio_normalized, throughput_ratio_contribution;
    double module_health_avg, module_health_normalized,
           module_health_contribution;
    uint32_t config_issue_count, total_modules;

    // Final values.
    double health_score, degradation_score;
    bool is_degraded;       // Post-hysteresis.

    // Sample tracking.
    uint64_t samples_since_config_change;
    std::string config_snapshot_id;
};
```

The evaluator uses `samples_since_config_change >= min_samples` as an exact
statistical-validity gate before triggering rollback even if
`is_degraded` is true.

The correlator logs the full breakdown to `cp.health`: WARN for every degraded
sample; otherwise INFO when the total sample count is a multiple of 30.
Cadence follows accepted samples and `poll_interval_ms`, not a fixed
30-second timer.

#### 16.6 Lifecycle

- `on_config_change(snapshot_id)`: requires a nonempty identity and resets all
  EWMAs, hysteresis, and sample count before binding it, so no
  old policy sample can cross content.
- `reset()`: clears EWMAs, hysteresis state, sample count, and content
  identity. Policy replacement, content change, and
  post-intent convergence all rebuild from real intervals.

The evaluator, not the correlator, retains the first cumulative point and the
first point after runtime-generation replacement as seeds. Those points never
call `health_correlator::update()`. Every real baseline and candidate interval
does, so attribution compares the same correlated-health formula on both sides
of a content change. Each interval increments
`samples_since_config_change` exactly once within its bound content identity.

### 17. Telemetry History

`telemetry_history` in `src/cp/telemetry_snapshot.hpp` is a header-only bounded
per-config ring. The runner's `guardrails_evaluator` owns it; access is confined
to that thread, with no internal synchronization.

#### 17.1 `telemetry_snapshot` schema

| Group           | Fields                                                                 |
| --------------- | ---------------------------------------------------------------------- |
| Metadata        | `config_snapshot_id`, `epoch`, `runtime_generation`, `timestamp_ms` (audit), `timestamp_mono_ns` (behavior) |
| Infrastructure  | `rx_packets`, `tx_packets`, `dropped_packets`, `tx_pps`, `drop_pps`, `drop_ratio`, `throughput_ratio` |
| Module health   | `module_health_count` (zero = unavailable), `module_health_avg`, `config_issue_count` |
| Derived signals | `health_score`, `degradation_score`, `is_degraded`                     |

The evaluator reduces the already-validated complete wire rows to those five
fixed aggregates once. Module IDs and reason strings are not copied into every
history sample because no detector or attribution factor consumes them.

In correlation mode, each real baseline and candidate correlator breakdown is
copied into its interval before history or attribution. Cumulative seeds do not
enter history, and previous-iteration health is never relabeled as current
evidence.

#### 17.2 Storage and queries

| Method                              | Use                                                       |
| ----------------------------------- | --------------------------------------------------------- |
| `record(snapshot)`                  | Append to the exact content ring, then evict its oldest row if above the immutable bound. |
| `get_for_config(config_id)`         | Return only that content's rows in oldest-first order.    |
| `summary_for_config(config_id)`     | Read retained count and mean TX rate in constant time without copying rows. |
| `take_for_config(config_id)`        | Transfer the armed baseline once, preserving order and removing its map entry. |
| `clear()`                           | Drop all retained intervals at one evaluator reset edge.  |

The history does not discover a predecessor, order configurations globally,
or resize after construction. It maintains the stable baseline TX mean in O(1)
per admitted interval. `guardrails_evaluator` explicitly transfers the armed
content before it adopts a different content identity; that moved vector is
the only attribution baseline and is not duplicated in the map. Storage
admits at most two identities for direct component use; a third without a
transfer or `clear()` is an internal contract violation rather than unbounded
map growth.

#### 17.3 Capacity

`telemetry_history_capacity` is required policy and is validated up to 100,000.
The evaluator retains stable baseline rows, moves them once into its frozen
baseline on content change, and then retains current-window rows. It clears the
structure on policy/runtime reset, overlapping content change, completed
evaluation, or resolved intent. Capacity is storage, never a target number of
samples to process in one turn. Frozen baseline plus current history therefore
remain bounded by twice the authored per-content capacity without keeping two
copies of the baseline.

### 18. Attribution Scorer

`attribution_scorer` (declared in `src/cp/attribution_scorer.hpp`,
header-only inline implementation) computes a confidence value [0, 1]
that a configuration change caused observed degradation. It receives the
previous baseline and current window explicitly; it never discovers a baseline
from config ordering or substitutes neutral evidence.

#### 18.1 Factors

Each factor returns a `confidence_factor` with `value` in [0, 1] plus
an explanation string. The four factors:

**`timing_correlation`** (fixed weight 0.30)

Compares average health and drop ratio in snapshots before vs after
the config change.

```
health_signal = clamp((health_before - health_after) / 50.0, 0, 1)
drop_signal   = clamp((drop_after - drop_before) / 0.1, 0, 1)
value = (health_signal + drop_signal) / 2
```

A 50-point health drop saturates `health_signal` at 1.0; a 10% drop
ratio increase saturates `drop_signal`. Missing either side makes the complete
attribution result inconclusive before factor computation.

**`magnitude_match`** (fixed weight 0.20)

```
degradation = (health_before - health_current) / 100

if degradation < attribution.degradation_threshold:
    value = 0.3        // not significant
elif degradation >= 0.5:
    value = 0.4        // extreme degradation suggests external cause
else:
    value = 0.8 + 0.2 * (degradation - 0.10) / 0.40    // moderate is high confidence
```

This fixed heuristic assigns greater confidence to moderate degradation. It
does not establish that severe loss has an external cause.

**`baseline_deviation`** (fixed weight 0.20)

Computes a z-score of `current.health_score` against the mean and
standard deviation of the explicitly frozen baseline, after the configured
`baseline_samples` floor is met.

```
z = (baseline_health_mean - current_health) / max(baseline_health_stddev, 1.0)

if z > 3:   value = 1.0
elif z > 2: value = 0.8
elif z > 1: value = 0.5
else:       value = 0.2
```

An incomplete baseline produces `evidence_complete=false`; no score is emitted.

**`config_issue_flags`** (fixed weight 0.30 when module evidence is required)

```
ratio = config_issue_count / total_modules
value = min(1.0, ratio * 2.0)         // 50% of modules reporting saturates
```

Missing module rows make attribution inconclusive when either correlation's
module-health weight or CONFIG_ISSUE boost consumes that evidence.

#### 18.2 Final confidence and decision

```
confidence = sum(factor.value * factor.weight)
```

The four fixed factors sum to 1.0. When policy does not consume module health,
the remaining 0.30/0.20/0.20 factors are renormalized by their selected 0.70
weight. The selected factors can still span the full confidence range without
fabricating a zero module factor.

Decision thresholds are exact `attribution` policy values. For the canonical
CLI-authored 0.80/0.50 example:

| Confidence range          | Verdict   | `recommended_action`  |
| ------------------------- | --------- | --------------------- |
| `>= 0.80`                 | "high"    | `AUTO_ROLLBACK`       |
| `[0.50, 0.80)`            | "medium"  | `DEFER_TO_HUMAN`      |
| `< 0.50`                  | "low"     | `LOG_ONLY`            |

#### 18.3 How the runner uses the recommendation

For non-boundary rollback paths:

- **`AUTO_ROLLBACK`**: emit one desired action to the safety-intent channel.
- **`DEFER_TO_HUMAN`** and **`LOG_ONLY`**: emit no automatic mutation.
- **Attribution unavailable**: `evidence_complete=false`; emit no mutation and
  continue only when enough valid evidence exists. Missing data never becomes
  a neutral factor.

Commit-confirmed deadline rollback is independent of these recommendations.
It is enforced from the durable PendingConfirm record, not inferred from a
medium attribution score.

> These factors are operational heuristics, not proofs of causation or
> transition safety. Policy selects the decision thresholds; factor formulas
> and weights are fixed in the scorer.

### 19. Commit-Confirmed Pattern

> **Visual reference:**
> [Commit-confirmed and selective rollback](diagrams/platform_architecture.md#guardrails-commit-confirmed-and-selective-rollback)
> sequences the operator Confirm path against the runner deadline path and its
> one serialized store winner.

Commit-confirmed rolls back an applied configuration unless the operator
confirms before its deadline.

#### 19.1 Lifecycle

The RPC and durable pending-record surface are live after packet readiness:

```
1. Operator calls SetConfigSnapshot(snapshot, confirm_timeout_ms = 5*60*1000).
2. Packet-ready CP validates the existing rollback target, canonicalizes and
   stages the snapshot, and atomically retains `confirm_timeout_ms` beside one
   exact allocation.
3. CP drives typed Prepare/Activate convergence. Exact COMPLETE atomically
   promotes active content and creates `PendingConfirm` with the old active
   snapshot as rollback target. No rollback deadline is armed before COMPLETE.
```

The confirm and runner mechanics then continue:

```
4. A started guardrails runner reads the optional pending-confirm record each
   control-service turn, independently of policy state.
5. When `pending.confirmed == false` and either
   `now_unix_ms >= deadline_unix_ms` or the wall clock has regressed before
   `created_unix_ms`:
   - Collect one mandatory CP-fenced DP observation.
   - Persist one commit-confirm rollback intent with exact active hash, epoch,
     revision, runtime generation, target, cause, and retained random key.
   - The control loop services that intent through the ordinary transition
     authority before another mutation.
   - Exact completion of the intent's target clears an unresolved intent and
     pending confirmation in the same active-promotion replacement, including
     when an already-running operator rollback used a different key.
   - A terminal transition failure is retained on the intent and never re-arms.
6. Operator path: ConfirmConfig RPC arrives before deadline.
   - the store atomically writes one keyed terminal confirmation result.
```

A prior active snapshot is required as the rollback target. Without it, CP
returns `failed_precondition` before staging or DP contact. COMPLETE promotes
active content and creates the pending confirmation in one authority
replacement. That write preserves both watermarks, recomputes the Bootstrap
key, and retains terminal success.

While confirmation is pending, only a full rollback to that exact target with
`confirm_timeout_ms == 0` is allowed. A selective hybrid has a different
identity, and safety rollback cannot start another confirmation window.

#### 19.2 Deadline and Confirm share one serialization point

The control loop is the sole caller of both `confirm_pending_config()` and
`accept_rollback_intent()`. Each method enforces the pending record under the
same config-store mutation lock. A first Confirm at or after the durable
deadline always returns `DEADLINE_EXCEEDED`, even if the runner has not yet
polled. If Confirm wins before the deadline, later timeout intent admission
sees `confirmed=true` and rejects. If timeout intent wins, the ordinary Confirm
mutation reaches the store's serialized intent gate and rejects before
confirmation. A confirmation already made durable is different: its exact
same-key response-loss retry is returned before the intent gate, preserving the
retained terminal result. No poll-timing race can create late first success or
erase an earlier exact success. A wall-clock sample before durable creation is
also never treated as extra confirmation time: the runner conservatively uses
the already-persisted deadline as the intent's audit projection and starts the
same rollback path.

#### 19.3 Wall-clock deadlines survive CP restart

`PendingConfirm.deadline_unix_ms` stores an absolute Unix timestamp. Restarting
CP retains that expiry instead of starting a new timeout: a five-minute
confirmation window still ends at its original wall-clock deadline.

#### 19.4 Idempotent confirm retries

Snapshot ID, epoch, revision, and idempotency key are all required. The first
success stores only the key digest and exact nonzero remaining milliseconds.
An exact response-loss retry returns the same success before checking the
current clock; another key or identity fails. The confirmed record is retained
through CP restart and cleared only by the next successful epoch allocation.
Thus confirmation is one durable replacement, not a mark-then-clear pair.

### 20. Selective Rollback

> **Visual reference:** [`diagrams/platform_architecture.md` Section 9](diagrams/platform_architecture.md#9-guardrails-and-rollback) places selective rollback under the one durable mutation authority. The exact module-set and hybrid-snapshot rules remain below.

`Rollback` accepts `repeated string module_ids`. Empty means full
rollback. Non-empty means a hybrid snapshot: take the listed modules'
configs from the target snapshot, keep everything else from the current
active snapshot.

#### 20.1 The module-set compatibility check

The current and target snapshots must have equal *module-ID sets*, and every
requested ID must belong to that set:

```cpp
unordered_set<string> current_module_ids = {modules in active snapshot};
unordered_set<string> target_module_ids  = {modules in target snapshot};
if (current_module_ids != target_module_ids) {
    return failed_precondition("Pipeline topology mismatch: ...");
}
```

`ConfigSnapshot` (`proto/kinetum/control/v1/control.proto`) carries
`repeated ModuleConfig modules`, not stages or edges. The graph belongs to
Gluon's `DeploymentPlan` ([`GLUON.md`](GLUON.md)), loaded once at DP startup.
Adding or removing module IDs therefore fails rollback compatibility;
changing an existing module's `config_blob` does not.

#### 20.2 Opaque module validation

`schema_id` and `content_type` remain informational module-authored metadata;
neither selects rollback behavior or substitutes for module admission. The
exact target `config_blob` reaches the module's PREPARE callback, whose typed
result decides whether that configuration can enter the prepared epoch.

#### 20.3 Hybrid snapshot construction

The handler builds a fresh `ConfigSnapshot` with:

| Field                   | Value                                                          |
| ----------------------- | -------------------------------------------------------------- |
| `snapshot_id`           | `selective_<sha256(domain,key)>` unless an exact retry already owns generated identity |
| `revision`              | One checked value greater than current and source revisions    |
| `created_unix_ms`       | now                                                            |
| `parent_snapshot_id`    | The current active snapshot's ID                               |
| `description`           | `"Selective rollback of modules [<list>] from <target_id>"`    |
| `author`, `labels`      | Preserved byte-for-byte from the current active snapshot       |
| `modules[]`             | For each current module: if selected, use the target's version with the checked generated revision; otherwise preserve current. |
| `content_hash`          | Cleared before shared canonicalization recomputes exact content identity |

Exact retries reuse the generated identity, revision, and timestamp and rebuild
from the retained parent snapshot, rather than a later active snapshot.

Then the standard Set-like path canonicalizes, stages corpus closure, allocates
both values atomically, and drives the same typed DP transition. The hybrid is
marked active only after exact COMPLETE.

### 21. Boundary Telemetry Monitoring

The DP publishes exact DATA sequences, sender/receiver phases, CUT/ACK identity,
and presence-qualified timing through the shared response. Boundary policy is
enabled only by presence of `GuardrailsBoundaryPolicy`; there is no parallel
Boolean or marker-derived duration.

When `policy.has_boundary()` is true, the evaluator inspects DP's
`telemetry.boundaries[]` array (one entry per compiled cross-worker boundary, see
[`DATA_PLANE.md`](DATA_PLANE.md) and [`GRPC_API.md`](GRPC_API.md)
Section 7.6) on every monitoring iteration.

#### 21.1 ACK stall detection

For each boundary entry, the runner derives a stall only when all of these are
true:

- `sender_phase == BOUNDARY_SENDER_PHASE_WAITING_ACK`;
- `cut_published_monotonic_ns` is present and `ack_observed_monotonic_ns` is
  absent; and
- `runtime.collection_monotonic_ns - cut_published_monotonic_ns` is
  representable and reaches `boundary.ack_timeout_ms * 1,000,000`.

The resulting intent bypasses attribution because the exact transition edge is
already its cause. It binds the active old content as target, the in-flight
candidate as guarded content, and the exact durable mutation sequence to wait
for. A durable predecessor ABORTED or completion-only failure terminally latches
the intent even if old content remains active; it never re-arms. Only fresh
Bootstrap orphan reconciliation may clear an unresolved intent whose target was
actually restored without a terminal predecessor result. When both epochs
intentionally name the same snapshot content, there is no distinct rollback
target: the evaluator suppresses automatic rollback and leaves transition
progress to the Data Plane's compiled safety deadlines.

Only a fault-free exact telemetry generation can produce this policy intent. A
sticky protocol-fault generation pauses telemetry policy; it can never report a
successful guardrail action over poisoned transition evidence.

#### 21.2 Backpressure is observation only

Backpressure remains exact cumulative operator telemetry. The evaluator does
not compare it directly with an interval threshold or silently turn it into a
rollback detector.

### 22. Runtime Generation and Counter Regression

DP packet counters are uint64 and cumulative inside one exact
`runtime_generation`. An epoch transition does not reset them. The runner keeps
the generation beside its baseline:

- A different nonzero generation is an explicit namespace replacement. The
  evaluator clears baseline/history and uses the new absolute counters only as
  a seed. It does not invoke the correlator for that point.
- A lower TX or dropped value inside the same generation is a coherent
  contradiction, including when it coincides with a content-identity change.
  The evaluator retains the prior high watermark, breaks interval continuity,
  and performs no attribution or rollback decision. A later nonregressing
  point may establish the new content seed before another delta is allowed.

This distinction prevents a process restart from fabricating a delta and
prevents an in-generation regression from being laundered as an ordinary
counter reset. Threshold-mode `delta_tx + delta_dropped` saturates at the
uint64 maximum, so a valid high-count interval cannot wrap below the configured
minimum-packet gate.

---

## Part 4: Cross-Cutting

### 23. Source-Tree Integration Surfaces

Both subsystems expose repository-internal C++ integration surfaces under
`src/cp/`. They are available to in-tree hosts and tests; they are not part of
the installed module SDK.

#### 23.1 CP-side source-tree API (host process)

| Header                    | Type / function                                                | Use                                                                    |
| ------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `config_store.hpp` | `config_store` | Durable snapshot, transition, confirmation, policy, and rollback-intent authority. Full method contract in [Section 8.2](#82-public-api). |
| `transition_reconciliation.hpp` | `classify_transition_reconciliation`                     | Total typed DP-observation to CP-action mapping; never parses text.    |
| `dataplane_transition_client.hpp` | `dataplane_transition_client::{prepare,activate,abort,query}` | Exact bounded gRPC attempts, request reconstruction, response-tree admission, and typed normalization. |
| `control_loop.hpp`        | `control_loop(store, dp_stub)` + `initialization_status()` + `start()` + `stop()` + `is_running()` | Single-writer mutation engine. Packet-ready production starts it; control-only production keeps it stopped. `is_running()` returns only the atomic `running_` flag. |
| `control_loop.hpp`        | `reconcile_startup(...)` / `configure_startup_guardrails_policy(...)` | Stopped-owner transition/intent convergence and exact optional startup-policy publication before service launch. |
| `control_loop.hpp`        | `submit(mutation)` and `submit(mutation, timeout)`             | Wait for the result. Timed submission may cancel queued work but waits once execution starts. |
| `control_loop.hpp`        | `submit_safety_intent(request)`                                | One unconditional caller-owned context acknowledged only after durable intent admission. |
| `control_loop.hpp`        | `mutation`, `mutation_payload`, `mutation_result`, `*_payload` | Construction-fixed mutation taxonomy.                                  |
| `control_loop.hpp`        | `published_state()`                                                | Coherent active revision and snapshot identity from one RCU borrow.  |
| `control_loop.hpp`        | `guardrails_state()`                                           | Const reference to the guardrails RCU buffer wrapper. Used by the runner; usable by other readers if you embed CP without guardrails. |
| `cp_grpc.hpp`             | `control_service_impl(store, dp_stub, loop)`                   | gRPC service implementation. Register with `ServerBuilder`.            |

Error categories returned by control-loop admission or
`mutation_result.status`:

| Status                  | When                                                              |
| ----------------------- | ----------------------------------------------------------------- |
| `invalid_argument`      | Syntax/shape failures (snapshot ID, revision range, malformed payload). |
| `resource_exhausted`    | Full 64-cell mutation mailbox, raw/canonical snapshot size, diagnostic bound, allocator wrap, or memory exhaustion. |
| `failed_precondition`   | CAS revision mismatch; selective-rollback module-set mismatch; rollback before active snapshot exists. |
| `not_found`             | Target snapshot or read-only durable record lookup missing.       |
| `unavailable`           | Control-only mutation gate, transient DP transport/capability state, or observation crossing a lawful publication edge. |
| `internal_error`        | Unexpected client/runtime failure or another internal invariant failure. |
| `data_loss`             | Malformed or contradictory durable/remote runtime authority; startup and policy action fail closed. |

#### 23.2 Guardrails-side source-tree API

| Header                         | Type / function                                                              | Use                                                  |
| ------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------- |
| `guardrails.hpp`               | `guardrails_runner(store, dp_stub, loop)` + `start()` + `stop()`             | Runner thread. Always-alive once started; stop is the only way to terminate. |
| `guardrails_policy.hpp`        | `validate_guardrails_policy`, `canonicalize_guardrails_policy`               | One exact no-default policy and SHA-256 authority.   |
| `guardrails_evaluator.hpp`     | `guardrails_evaluator::{apply_policy,observe,pause_observation,...}`          | Deterministic six-state production evaluator.        |
| `runtime_authority_fence.hpp`  | `same_active_runtime_authority`, `classify_runtime_authority`                 | Active-exact, adjacent preadmission, and target-complete reply-loss classifier. |
| `health_correlator.hpp`        | `health_correlator(config)`, `on_config_change`, `update`, `reset`              | Explicit signal smoothing + scoring engine. Not thread-safe. |
| `health_correlator.hpp`        | `correlation_weights`, `signal_breakdown`                                    | Configuration and result types.                      |
| `telemetry_snapshot.hpp`       | `telemetry_snapshot`, `telemetry_history`                                     | Fixed aggregate interval plus bounded exact-content history. |
| `telemetry_snapshot.hpp`       | `telemetry_history(max_per_config)` + `record`/`get`/`summary`/`take`/`clear` | Bounded ring buffer and O(1) stable-baseline rate summary. Not thread-safe. |
| `attribution_scorer.hpp`       | `attribution_scorer(config)` + `compute(current, baseline, current_window)`  | Explicit-evidence confidence scoring.                |
| `attribution_scorer.hpp`       | `attribution_config`, `attribution_result`, `confidence_factor`              | Configuration and result types.                      |

The correlator, telemetry history, and attribution scorer are single-threaded.
An embedding caller must retain one owner or provide external synchronization.

#### 23.3 Determinism and test seams

The CP side is *not* deterministic in the Gluon sense - wall-clock time
appears in `created_unix_ms`, `deadline_unix_ms`, and `time_remaining_ms`.
Generated patch/selective IDs are domain-separated hashes of the required
idempotency key, and an exact retry reuses the retained first-attempt timestamp
and revision. Mutation ordering is deterministic for a given input sequence.

Guardrails behavior windows use DP collection-monotonic time. Wall time is
restricted to restart-stable Confirm deadlines and durable audit projection.
Deterministic tests drive `guardrails_evaluator::observe()` directly with exact
synthetic fenced observations; runner tests cover the real channel and gRPC
boundaries.

### 24. CP vs DP vs Quark vs Photon Responsibilities

| Concern                                                       | Owner                                          |
| ------------------------------------------------------------- | ---------------------------------------------- |
| Process lifecycle, CLI, signal handling                       | CP (`cp_main`)                                 |
| gRPC server for `ControlService`                              | CP (`control_service_impl`)                    |
| Single-writer mutation discipline                             | CP (`control_loop`)                            |
| Descriptor-rooted immutable corpus plus atomic active/transition/confirm/policy/intent authority | CP (`config_store`) |
| Exact transition coordinator and two-slot snapshot lifecycle (no epoch allocation) | DP (`epoch_transition_coordinator` + `config_snapshot_epoch_store`) |
| Durable retry matrices, retained-retry-aware CAS, snapshot/policy/Confirm identity | CP (`control_loop` + `config_store`) |
| Exact transition wire contract                               | `dataplane.proto`                              |
| Exact typed transition choreography after durable allocation | CP (`control_loop::apply_to_dp_` + `dataplane_transition_client`) |
| Live-transition RPC mapping                                   | DP control service and coordinator/runtime owner |
| Immutable participants, global phase, restored watermarks, PREPARING/PREPARED identity, bounded terminal journal, monotonic lease, worker command, coherent completion | DP coordinator, preparation/completion owners, and packet workers |
| Durable epoch/mutation allocation and typed pending-transaction reconciliation | CP (`config_store` + `transition_reconciliation`) |
| Snapshot validation rules (size, identity, revision, module-set, hashes) | Shared canonical-content authority, consumed by CP |
| Module config schema validation                               | Module - CP routes opaque blobs without parsing |
| `GuardrailsPolicy` validation                                 | CP (`validate_guardrails_policy`)              |
| Guardrails runner thread lifecycle                            | CP (the same `kinetum_cp` process)             |
| Decision: AUTO_ROLLBACK / DEFER_TO_HUMAN / LOG_ONLY           | Guardrails (`guardrails_evaluator` + `attribution_scorer`) |
| Rollback intent                                               | Guardrails publishes one linear safety context; CP persists desired action and services it through the existing transition authority |
| Shared runtime telemetry collection and validation             | DP final snapshot source; CP validates active identity and forwards one unchanged payload |
| Boundary ACK timeout decision                                 | Guardrails evaluator over exact generation-local phase/CUT/collection time |
| Plan-vs-host CPU compatibility check                          | Quark, invoked by DP at startup (see [`QUARK.md`](QUARK.md)) |
| Verified runtime-bundle plan identity before child spawn      | Photon, through the shared bundle verifier (see [`PHOTON.md`](PHOTON.md)) |
| TLS / mTLS configuration                                      | Binaries (`cp_main` flags, similar in DP and `kinetumctl`) |

### 25. Where to Go Next

| If you want to...                                                | Read                                                       |
| ---------------------------------------------------------------- | ---------------------------------------------------------- |
| Use the gRPC contract from a custom client                       | [`GRPC_API.md`](GRPC_API.md)                               |
| Use the canonical operator CLI                                   | [`KINETUMCTL.md`](KINETUMCTL.md)                           |
| Understand the dataplane that consumes snapshots                 | [`DATA_PLANE.md`](DATA_PLANE.md)                           |
| Understand the supervisor that launches CP and DP                | [`PHOTON.md`](PHOTON.md)                                   |
| Understand strict host CPU/NUMA compatibility evidence           | [`QUARK.md`](QUARK.md)                                     |
| Plan a deployment                                                | [`GLUON.md`](GLUON.md)                                     |
| Author a pipeline                                                | [`AXIOM.md`](AXIOM.md)                                     |
| Write a custom module (including the `health_check()` SDK hook)  | [`MODULE_SDK.md`](MODULE_SDK.md)                           |
| Run the platform end-to-end                                      | [`GETTING_STARTED.md`](GETTING_STARTED.md)                 |
| See the CP host process and mutation pipeline                    | [`diagrams/platform_architecture.md` Section 6](diagrams/platform_architecture.md#6-control-plane) |
| See the exact DP transition boundary                             | [`diagrams/platform_architecture.md` Section 7](diagrams/platform_architecture.md#7-transition-rpc-boundary) |
| See configuration publication                                    | [`diagrams/platform_architecture.md` Section 8](diagrams/platform_architecture.md#8-configuration-publication) |
| See guardrails, attribution, and rollback flows                  | [`diagrams/platform_architecture.md` Section 9](diagrams/platform_architecture.md#9-guardrails-and-rollback) |
| See the full diagram set                                         | [`diagrams/README.md`](diagrams/README.md)                 |
| Read the architectural overview                                  | [`CONCEPTS.md`](CONCEPTS.md)                               |
