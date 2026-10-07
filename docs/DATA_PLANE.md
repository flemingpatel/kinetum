# Data Plane

The Kinetum Data Plane (DP) is the fast-path packet processor. Its packet
runtime consumes the canonical deployment plan selected by `kinetum_photon`,
compiles its exact provider graph once, passes that same immutable artifact to
Quark for live host proof, admits the required signed provider components,
materializes one runtime generation transactionally, and runs busy-poll
workers over pre-resolved execution kernels. Live transitions require exact
ownership accounting for every admitted work class.

This reference covers DP structure, module admission, packet dispatch, and CP
statistics/lifecycle access. Module descriptors, callbacks, contexts, SoA
batches, configuration views, telemetry, and health are documented in
[`MODULE_SDK.md`](MODULE_SDK.md). Provider roles, the C ABI, native resources,
and component integration are documented in [Providers](PROVIDERS.md).

For the boundary protocol and proof that an epoch-only marker cannot implement
an ordered cut, see
[`diagrams/ordered_cut_boundary_protocol.md`](diagrams/ordered_cut_boundary_protocol.md).
For the wire-format DataplaneService proto, see
[`GRPC_API.md`](GRPC_API.md). For the Quark runtime compatibility gate
that runs at DP startup, see [`QUARK.md`](QUARK.md).

## Table of Contents

**Part 1: DP Host Process**

1. [What the Data Plane Is](#1-what-the-data-plane-is)
2. [Authoring Model and Vocabulary](#2-authoring-model-and-vocabulary)
3. [Process Lifecycle (dp_main)](#3-process-lifecycle-dp_main)
4. [Threading Model](#4-threading-model)
5. [Provider Graph Compilation and Materialization](#5-provider-graph-compilation-and-materialization)
6. [Exact Snapshot Epoch Store](#6-exact-snapshot-epoch-store)
7. [Exact Transition RPC Admission (DP-side)](#7-exact-transition-rpc-admission-dp-side)

**Part 2: Runtime Worker Internals**

8. [Runtime Worker Architecture](#8-runtime-worker-architecture)
9. [RX Path](#9-rx-path)
10. [Stage Dispatch](#10-stage-dispatch)
11. [TX and Egress](#11-tx-and-egress)
12. [Cross-Region Boundary Integration](#12-cross-region-boundary-integration)
13. [Active Stage Dispatch](#13-active-stage-dispatch)

**Part 3: Module Lifecycle and Telemetry**

14. [Exact Module Generation and Lifecycle](#14-exact-module-generation-and-lifecycle)
15. [Stats Collection](#15-stats-collection)
16. [Provider Observation Lifetime](#16-provider-observation-lifetime)

**Part 4: gRPC and Lifecycle**

17. [gRPC Service (DataplaneService)](#17-grpc-service-dataplaneservice)
18. [Authentication and TLS](#18-authentication-and-tls)
19. [Drain and Shutdown Protocol](#19-drain-and-shutdown-protocol)

**Part 5: Cross-Cutting**

20. [Source-Tree Integration Surfaces](#20-source-tree-integration-surfaces)
21. [Determinism](#21-determinism)
22. [CP vs DP vs Quark vs Photon Responsibilities](#22-cp-vs-dp-vs-quark-vs-photon-responsibilities)
23. [Where to Go Next](#23-where-to-go-next)

---

## Part 1: DP Host Process

### 1. What the Data Plane Is

`kinetum_dp` is the sole deployment forwarding process and executes Gluon's
`DeploymentPlan`. Axiom, Gluon, Photon, CP, and Guardrails supply plans,
snapshots, process ownership, and policy without accessing live packet state.
Validation instruments generate or capture test traffic separately.

The DP hosts a fixed number of runtime workers derived from the compiled
`(region, lane)` execution topology. A single-lane plan has one worker per
region; RSS multi-lane plans may create multiple workers inside one logical
region. Each worker runs a tight busy-poll loop: receives packets from its
assigned RX sources, executes pipeline
stages, dispatches results either locally (next stage) or across a
region boundary (the ordered-CUT protocol), and either drops, forwards to
a TX operation, or hands off to a downstream worker.

The cold compiler resolves worker ownership, source schedules, storage/access
proofs, transitions, and lifecycle-service placement. Materialization selects
each worker's fixed RX callback target or bounded heterogeneous source schedule.
Providers may register workers with admitted facilities, but native thread
identity stays private. Core lifecycle, callbacks, logs, and statistics use
compact worker indices. Packet loops are provider-neutral and non-virtual,
with no per-packet provider lookup; native observations use generation-scoped
statistics.

The cold `epoch_transition_coordinator` serializes Bootstrap and live
Prepare/Activate/Abort/Status commands through one bounded mailbox. It owns
exact snapshot identity, allocator watermarks, transition phase, prepared
leases, and terminal results. At most one published snapshot and one prepared
or retained snapshot coexist. Preparation stages every fallible resource;
completion coordinates worker activation, reader grace, and old-artifact
retirement. [Section 7](#7-exact-transition-rpc-admission-dp-side) defines these
transactions and their failure paths.

Each `worker_epoch_ledger` creates exact-epoch credits on source/inbound admission
and independent fan-out, and retires them on boundary transfer, TX acceptance,
or terminal disposition. Workers update cache-line-private plain integers and
publish one coherent generation-tagged snapshot per bounded turn. Runtime
accessors only observe it. The certificate combines ledger, activation,
boundary-policy, boundary-transport, and reader-grace evidence; none alone
authorizes quiescence or reclamation.

Packet processing begins only after Bootstrap has activated every module,
bound every worker, activated I/O, and published `PACKET_READY`. Each packet
then keeps its admitted epoch through processing, retained work, and tracked
asynchronous work, including across live transitions.

### 2. Authoring Model and Vocabulary

| Term                    | Meaning                                                                                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- |
| **Bootstrap epoch**     | Exact nonzero epoch from the nested Bootstrap request in CP's durable `TRANSITION_AUTHORITY.pb`. The snapshot store, every module store, every worker kernel, packet metadata, and runtime-status publication must agree on it before `PACKET_READY`. |
| **Runtime-status publication** | Immutable single-writer observation of runtime generation, readiness, active/minimum-retained/last-activated epochs, and expected/active workers. Epoch triples use that field order: Bootstrap E/E/E, participant activation N/E/N, stable completion N/N/N. It is Health's sole runtime-readiness source. |
| **Transition coordinator** | Sole cold owner of global epoch phase, exact two-slot snapshot state, CP-supplied allocation high watermarks, immutable compact participant membership, one generation token, immutable PREPARING/PREPARED transaction identity, bounded terminal journal, prepared lease, and coherent internal progress. Fixed Bootstrap and live Prepare/Activate/Abort/Status share the plan-sized mailbox; lifecycle and worker publications feed the same owner. |
| **Worker runtime command** | One release-published pointer to immutable RUN, alternating TRANSITION, or STOP records. The sole coordinator writes it; each packet worker performs exactly the existing one acquire load plus a predicted pointer comparison per turn. A changed TRANSITION record binds one exact generation all-or-none. STOP remains level-triggered on every drain turn and is never consumed as a one-shot edge. |
| **Transition preparation owner** | Transient coordinator-thread schedule for one candidate's module PREPARE/RETIRE work. It preallocates every control and epoch arena before the first callback, permits at most one callback per image and executor, treats result eventfd counts as wake-only, and reports ABORTED only after zero prepared module ownership remains. |
| **Transition completion owner** | Preallocated coordinator-thread owner of one exact post-commit identity, reader grace, behavior deadlines, module claims/results, snapshot retirement, and runtime-status projection. It owns no second global phase or participant graph. Before the first retirement claim, a reader-grace deadline freezes RETIRING with E retained; after ownership withdrawal, callback failure, identity mismatch, result loss, or deadline expiry is fail-stop. |
| **Boundary epoch channel** | Compiled cross-worker transport: plan-sized pointer-only DATA with successful endpoint sequences, capacity-2 typed CUT/ACK lanes, bounded pending control, and coherent endpoint publication. Worker-local slabs place hot state/publication with its owner and control rings with their pollers. |
| **Worker boundary sender** | Sole worker-owned policy composer for its exact outbound set. It routes fixed OPEN DATA, seals every cut only after source admission moves to the exact target and old credit reaches zero, admits only exact ACK identity, owns future-hold ordering, and preserves the sequence/hold/ledger conservation matrix. Its sender-NUMA policy and transition-timing lines are private; a disjoint two-cache-line snapshot publishes Bootstrap baseline and each real DRAINING/CUT-owned/ACK-observed edge coherently. |
| **Worker boundary receiver** | Sole worker-owned CUT/fan-in/ACK policy for its exact inbound set. It latches one exact CUT per edge, classifies only successful dequeue sequence, requires all inbound cuts plus zero old local credit, and submits ACK only after complete local activation. Its receiver-NUMA policy and transition-timing lines are private; a disjoint two-cache-line snapshot publishes Bootstrap baseline and each CUT-observed/drained/activation/ACK-owned edge coherently. |
| **Worker epoch activation** | Immutable owner-worker projection of exact module stores and source queue-role pairs. One complete nonmutating preflight precedes module ACTIVATE, O(1) role rotation, and whole future-to-active ledger promotion; a separate one-shot publication records Bootstrap baseline or completed live activation without owning global progress. |
| **Quiescence domain** | Backend-neutral immutable binding of one caller-owned cache-line reader record per frozen worker. One adjacent grace generation is active at a time; readers publish it exactly once after their final old read. It owns no epoch, timeout, phase, or reclamation policy. |
| **Transition certificate** | Immutable cold O(V+E) aggregator over frozen membership and coherent activation, ledger, boundary-policy, boundary-transport, and reader publications. Missing or older input underestimates; exact contradictions are typed. It observes but never starts grace, changes phase, or retires ownership. |
| **Region**              | Logical partition slice in the deployment plan. Defined by `plan.regions[i]`.                              |
| **Runtime worker**       | One busy-poll execution owner for a populated `(region,lane)` slice. Single-lane plans have one worker per region; RSS multi-lane plans may have more. |
| **Boundary**            | An exact cross-worker handoff defined by `plan.boundaries[i]`, including endpoint stage instances, owner workers, capacities, and NUMA placement. |
| **Dispatch core**       | The pre-resolved `packet_worker_kernel` dispatch methods route one owned `packet_record *` to its next stage, TX operation, boundary, fan-out branch, or burst retirement without a provider or string lookup. |
| **Snapshot epoch store** | Cold coordinator-owned two-slot owner of exact canonical `ConfigSnapshot` artifacts in EMPTY, PREPARED, PUBLISHED, or RETAINED state. It has no history map, nearby-epoch lookup, allocator, lock, shared ownership, or packet-path reader. |
| **Module image**        | One canonical, link-closed `.so` loaded by exact path with local symbol scope and exporting one exact `kinetum_module` descriptor. |
| **Module context**      | One executable stage-instance state object with a sole owner worker and exact compiled placement.         |
| **Context-lifetime capacity** | Exact nonzero plan-authored byte limit for one module context's INIT-backed lifetime resource. No runtime default or heap fallback supplies it. |
| **Per-epoch arena capacity** | Exact nonzero plan-authored byte limit for each PREPARE arena owned by one module context. Complete epoch memory is checked using `EXACT_EPOCH_SLOT_COUNT`. |
| **Module epoch store**  | Per-context two-slot owner of exact PREPARED, PUBLISHED, and RETAINED artifacts plus the active executable view. It never maps an unknown epoch to a nearby slot. |
| **Module executable view** | One cache-line owner-local callback/config authority pre-resolved before worker launch. Packet execution performs one exact packet/view epoch equality and no slot or manager lookup. |
| **Worker ownership record** | Compiled runtime-worker record containing the RX sources, inbound/outbound boundaries, I/O streams, and stage instances that one worker owns. |
| **Worker epoch ledger** | One owner-worker two-slot logical-work counter. `packet_private.epoch` selects the exact active/future slot; packet operations use plain arithmetic, while foreign readers consume only the coherent per-turn publication. Local queue-slot reservations and physical storage credits remain separate capacity/record authorities. |
| **Worker epoch input staging** | One cache-line-isolated owner with an exact-NUMA active queue for every worker/storage-domain relation plus an equal-capacity future role for each transition-enabled source domain with nonzero authored capacity. Queue roles exchange by pointer in O(1); reservations remain capacity-only. |
| **Boundary future-output hold** | One sender-NUMA, pointer-only queue per boundary. It is preallocated and empty until ordered commit allows local future execution while that boundary's exact ACK gate is closed. |
| **`packet_private`**    | 128-byte, two-cache-line sole metadata authority embedded in every provider-neutral packet record. |
| **`packet_record`**     | Exact 192-byte, three-cache-line core packet representation physically declared by the provider C ABI: `packet_private` plus one provider-backed storage descriptor. Every packet-path owner transfers only `packet_record *`. |
| **Provider contract**   | One exact typed configuration schema plus canonicalization and capability semantics, identified by its complete canonical type URL. |
| **Provider component**  | One exact-release, signed-inventory ELF image that realizes one or more provider contracts behind the C provider ABI. |
| **Compiled provider topology** | Sole semantic result containing compact facilities, drivers, storage, execution, transitions, worker schedules, access proofs, and required component contracts. |
| **Process facility**    | Native process/device environment such as DPDK EAL, owned once per exact compiled scope rather than by the first port that initializes. |
| **I/O driver instance** | Exact ingress/egress implementation instance and its driver-local endpoints and queues. |
| **Packet storage domain** | Bounded population of packet records and payload backing with exact capacity, access-agent, NUMA, generation, and reclamation semantics. |
| **Execution provider instance** | Exact owner of stage execution; the current catalog contains CPU execution. |
| **Storage transition**  | Explicit zero-copy-share or bounded-copy operation for one directed endpoint/domain handoff. |
| **Storage operation table** | Immutable clone/origination/release authority for one storage domain. Release is burst-only; writable clone is singular because compiled plan fan-out is statically bounded. |
| **RX/TX operation tables** | Distinct immutable I/O-driver burst authorities copied from cold port owners before worker launch. They are intentionally separate from storage ownership even when one implementation supplies both roles. |

**Limits** the DP enforces at startup or runtime:

| Constant                 | Value | Where                                  | What it bounds                                                                 |
| ------------------------ | ----- | -------------------------------------- | ------------------------------------------------------------------------------ |
| `EXACT_EPOCH_SLOT_COUNT` | `2`   | `epoch/exact_slot_table.hpp`           | Exact lifecycle slots composed by both module and complete-snapshot epoch stores. See [Section 6](#6-exact-snapshot-epoch-store). |
| `PACKET_PRIVATE_SIZE`    | `128` | `provider_component_abi.h` / `packet.hpp` | Exact sole packet-metadata bytes; the C ABI is physical authority and the C++ header provides aliases/helpers. |
| `PACKET_RECORD_SIZE`     | `192` | `provider_component_abi.h` / `packet.hpp` | Exact provider-neutral record bytes, including the storage descriptor.          |
| `PACKET_MAX_BURST_SIZE`  | `64`  | `runtime_sizing.hpp`                  | Shared RX, TX, release, active-origin, and worker scratch burst ceiling.         |
| `INTER_REGION_DATA_RING_CAPACITY` | `1024` | `runtime_sizing.hpp` / `boundary_epoch_channel.hpp` | Default boundary DATA and ordinary active-only staging capacity. It bounds retained work; per-turn service limits independently bound polling cadence. Source-domain pairs use their exact plan field. |
| `BOUNDARY_FUTURE_OUTPUT_HOLD_CAPACITY` | `1024` | `runtime_sizing.hpp` | Sender-owned future-epoch output hold per executable boundary; independent from the DATA ring and worker input staging. |
| `BOUNDARY_CUT_RING_CAPACITY` | `2` | `runtime_sizing.hpp` / `boundary_epoch_storage.hpp` | Compile-time typed CUT transport placed with the receiver poller. One global transition permits one outstanding record; two is the minimum lawful SPSC capacity. |
| `BOUNDARY_ACK_RING_CAPACITY` | `2` | `runtime_sizing.hpp` / `boundary_epoch_storage.hpp` | Compile-time typed ACK transport placed with the sender poller under the same one-outstanding-record law. |

Every plan-authored SPSC usable capacity (source queue roles, boundary DATA, and
future-output hold) is a power of two and at least two. The shared topology
compiler enforces that physical queue contract before NUMA allocation.

Packet storage counts, data-room size, headroom, alignment, stream descriptor
counts, and transition staging capacities are exact plan fields rather than
global runtime constants. The checked `plan_buffer_budget` authority derives
the minimum safe population from ten terms: RX descriptors, TX descriptor
slack, exact aggregate active worker queues, handoff staging, source future-
role queues, boundary future-output holds, active-instance retained records,
worker burst slack, per-worker caches, and one safety margin. The connected
provider compiler supplies one
exact domain composition to that authority: `worker_staging_capacity` is the
sum of physically materialized active queues, `handoff_staging_capacity` is the
sum of boundary DATA and bounded-copy staging, and future-output capacity is
charged to the post-transition carried domain. Multiple source domains that
converge into one carried domain are deduplicated before one physical boundary
capacity is charged. The formula adds one shared `PACKET_MAX_BURST_SIZE` safety
margin, emits the floor with the compiled domain, and rejects under-sized or
overflowing plans. Zero bounded-copy staging preserves the established budget
answers; no provider or materializer maintains a parallel sizing formula.

Each worker ledger's ceiling covers packet and non-packet work. Checked
addition combines the reachable domains' `buffer_count` values, one transient
active/health callback credit when needed, copied-control mailbox capacities,
PULL relations, and timer/async capacities. Timer and async delivery each add
up to one burst of handoff credits, bounded by that class's capacity. This
accounting bound allocates nothing and grants no storage or event capacity.

Module lifecycle memory follows the same plan-authority law. Every module
stage instance carries exact nonzero context-lifetime and per-epoch arena
capacities lowered from one lane-local deployment binding. The shared compiler
rejects missing, extra, zero, narrowing, and overflowing facts, derives checked
per-NUMA context, one-epoch, and complete epoch totals, and multiplies the
per-epoch term by `EXACT_EPOCH_SLOT_COUNT` rather than a copied literal. The
lifecycle allocator enforces both the per-context limits and compiled NUMA
totals. Its fixed ownership table is also the sole free-slot authority:
allocation pops one intrusive free slot in O(1), and release uses an opaque
one-based slot identity plus a nonzero reuse nonce to validate and return that
exact slot in O(1). Stale, foreign, modified, or duplicate release fails stop;
there is no pointer scan or second lookup map. NUMA-budget selection remains a
binary search over the strictly sorted compiled node rows, while mapping and
unmapping run outside the ownership mutex with their slot and byte claims
reserved. Platform stages carry zero for both fields; zero never selects a
default. The provider-private token is internal lifecycle ownership and does
not enter the plan, module ABI, provider ABI, or telemetry.

**Hot-path invariants** (Platform Engineering Guide):

- No `malloc`, no `new`, no `shared_ptr`, and no provider-native type in any
  packet-processing path.
- Flat arrays indexed by compact IDs for worker-owned stage runtimes
  (`stages_`), streams, boundaries, storage batches, and precompiled route
  targets. No packet-path table uses a string identity.
- Plain owner-local stream, stage, and terminal-disposition counters update through one
  pre-resolved active telemetry bank. Completed banks cross to the cold
  aggregator through bounded SPSC ownership; no foreign reader touches a live
  counter. Epoch credits remain separate plain owner state and publish through
  one cache-line coherent snapshot per bounded turn. The separate embedding
  engine also uses plain counters under its single-caller contract.
- Fixed cross-worker DATA handoff is one bounded SPSC pointer transfer through
  the exact sender's predicted OPEN/epoch gate. The packet loop contains no
  epoch-only marker. One runtime-command pointer load owns both transition and
  stop observation. A changed command binds the transition; subsequent bounded
  turns service sender gates and receiver CUT drain, fan-in, and activation.
- Each worker copies pre-resolved RX/TX/storage operation tables before launch;
  provider choice is never a per-packet branch or virtual call.
- Drops and provider TX are grouped into bounded bursts. Storage ownership
  retires exactly once even when the native TX operation transmits only a
  prefix.

### 3. Process Lifecycle (`dp_main`)

Startup is one ordered transaction. All fallible construction precedes packet
admission; failure returns nonzero or fails stop without publishing a partial
generation. Signals are blocked before runtime, provider, or gRPC threads.
`dp_main` admits the bundle, consumes its compiled topology, proves the host,
admits installed providers, and materializes a generation before publishing
`CONTROL_READY` and exposing its service.

| # | Step | Notes |
|---|------|-------|
| 1 | Parse provider-neutral CLI and establish control-signal authority | Accept `--bundle`, `--listen`, TLS, shared logging options, and help. Block SIGINT/SIGTERM/SIGUSR1 before any thread starts, then create the sole nonblocking `signalfd`. |
| 2 | Verify the runtime bundle | `verify_runtime_bundle()` requires the manifest and canonical plan/snapshot/module paths, verifies every file identity, canonical plan hash, exact snapshot, and provider-topology semantics, and returns the sole compiled topology. |
| 3 | Strict Quark runtime compat gate | `probe_host()` then `validate_runtime_compat(compiled_topology, host)` verifies exact compiled CPU, service, NUMA, and host-memory facts without a second plan walk, filtering, repair, or provider inference. |
| 4 | Admit cold diagnostics and the gRPC endpoint | Admit the role files, bind the logging writer to the compiled coordinator CPU, and install native gRPC capture. Validate TLS material and register only the requested listen endpoint; no server thread starts yet. |
| 5 | Preallocate coordinator command authority | Independently validate the coordinator's plan-authored power-of-two capacity in `2..64`, require zero on every lifecycle executor, and allocate the complete MPMC queue plus nonblocking `eventfd` before provider components load. |
| 6 | Admit exact provider installation | Derive `<root>/bin/kinetum_dp` from `/proc/self/exe`, authenticate the fixed signed inventory with the production anchor, load only the compiled required component set, run exact COMPONENT-phase proofs, and seal the catalog. A post-load failure emits a bounded diagnostic and fails stop. |
| 7 | Build the complete generation input | Move the canonical plan, sole compiled topology, unbound command mailbox, admitted catalog, exact verified module-image set, and nonzero generation identity into one move-only input. |
| 8 | Materialize transactionally | Freeze the exact coordinator participants, construct its empty state, and allocate the stable RUN/TRANSITION/STOP worker-command publication; admit module images/contexts and pre-create lifecycle executors; materialize facilities, storage, I/O, execution, and transitions; then construct exact-NUMA DATA rings, source queue pairs, boundary future holds, pre-resolved kernels, worker state, and lifecycle services. The launcher binds the calling thread to the planned coordinator CPU; the mailbox then binds that same thread as sole consumer. Recoverable failure unwinds in reverse order; an unprovable foreign-runtime rollback fails stop. |
| 9 | Publish `CONTROL_READY` | Publish one immutable runtime graph and status record while packet workers remain behind the closed bootstrap gate. |
| 10 | Start the control service | Build the TLS or insecure gRPC server around the complete runtime. Control readiness is not packet permission. |
| 11 | Restore exact bootstrap | A gRPC producer validates CP's durable canonical request, publishes one fixed mailbox record, and waits unconditionally. The main/coordinator thread orchestrates lifecycle-executor preparation for every context, launches workers behind the activation gate, owner-activates every view, commits the complete snapshot plus allocator watermarks, and waits for every worker to publish `RUNNING` while packet bodies remain closed. |
| 12 | Activate packet I/O and publish `PACKET_READY` | Invoke the mandatory whole-driver activation callbacks in canonical order, publish one coherent runtime-status snapshot, and only then release every worker into its exact active-epoch packet loop. |
| 13 | Serve and supervise | The main/coordinator thread blocks in `poll()` over `signalfd`, command and lifecycle `eventfd`s, and the current monotonic transition deadline. It gives termination first priority and due deadlines priority over ordinary work, executes at most one command per command turn, drains lifecycle result rings independently of wake counts, alternates simultaneously ready command/lifecycle sources, and probes committed certificate progress at the existing bounded cadence. |
| 14 | Teardown in dependency order | Close command admission and complete queued callers, initiate bounded gRPC shutdown, cancel and drain held pre-commit Prepare/Abort contexts, apply COMMITTING/RETIRING shutdown law to any held Activate, release-publish STOP, drain and join workers, deactivate provider I/O in reverse order, and finish a provable RETIRING generation (including exact worker-command completion after STOP) before retiring module/snapshot ownership. Then stop lifecycle services, destroy kernels, future holds, DATA boundaries, modules, and providers, release the admitted catalog last, and wait for handler exit. |

The host process connects signal, RPC, and supervisor shutdown to that one
ordered teardown authority. A process-level SIGKILL remains the supervisor's
last-resort reclamation boundary; it is not a substitute for clean packet,
module, provider, or child-process retirement.

**CLI flags** (see `dp_main.cpp::usage` for the full surface):

| Flag                              | Default            | Purpose                                                       |
| --------------------------------- | ------------------ | ------------------------------------------------------------- |
| `--bundle <dir>`                  | (required)         | Complete verified runtime bundle root.                        |
| `--listen <addr:port>`            | `0.0.0.0:50052`    | gRPC listen address for the DataplaneService.                 |
| `--tls-cert <path>`               | (insecure)         | Server TLS cert chain PEM.                                    |
| `--tls-key <path>`                | (insecure)         | Server TLS private key PEM.                                   |
| `--tls-ca <path>`                 | (insecure)         | Client CA PEM (for mTLS).                                     |
| `--tls-require-client-auth`       | false              | Enforce mTLS.                                                 |
| `--log-dir <absolute-dir>`       | `/var/log/kinetum` | Select protected process log storage. |

The shared level, component override, byte/count retention, and console options
are specified in [Logging](LOGGING.md). They do not change plan wiring.

TLS for the DP is set via the four kebab-case TLS flags above. If any are
set, `tls_enabled=true` and `make_server_credentials(tls_cfg)` is used.
TLS credential construction is fail-closed: missing, partial, or
unreadable TLS material makes `dp_main` abort before the gRPC server is
started.

### 4. Threading Model

A materialized DP process owns the plan-authoritative runtime roles below.
Packet workers and lifecycle services become reachable only as members of one
fully published generation.

| Thread                     | Count                | Lifecycle                                                                            |
| -------------------------- | -------------------- | ------------------------------------------------------------------------------------ |
| Main/coordinator thread    | 1                    | Runs ordered admission, consumes the plan-sized command mailbox, blocks in descriptor-driven `poll()` for command or termination events, and owns server/runtime teardown. |
| Merged gRPC server thread pool | managed by gRPC | Serves one `dataplane_control_service` backed by the complete runtime. Bootstrap and transition producers wait unconditionally after successful enqueue; the original Activate context remains owned through COMPLETE or update freeze; Health reads immutable status. |
| Runtime workers | one per compiled `(region,lane)` execution owner | Materialized before `CONTROL_READY`, launched behind an all-or-none activation gate during exact bootstrap, and released into their pre-resolved execution/RX schedule only at `PACKET_READY`. |
| Cold lifecycle coordinator | exactly one role on the main/coordinator thread | Remains on the planned caller-owned native thread or exact provider-facility main thread; the launcher never creates a second coordinator thread. |
| Cold lifecycle executors | exactly one per required lifecycle NUMA node | Pre-created bounded service loops on exact compiled CPUs. They are not packet workers and never infer placement from a provider default. |
| Logging writer | 1, on the compiled coordinator CPU | Owns bounded diagnostic encoding, file append, rotation, and reopen. It has no packet or epoch authority. |

There is no health aggregator or link-monitor thread. Provider observations run
through an exclusive generation claim with no platform lock held; packet
workers never poll native occupancy or link diagnostics. Cold lifecycle
executors are explicit planned service loops, not monitoring threads.

For a materialized runtime generation, CPU placement is worker-scoped:
each runtime worker is backed by one
`DeploymentPlan.worker_placements[]` entry, and Quark validates that entry's
`cpu_core_ids` and exact NUMA ownership before the launcher pins the worker.
Region-level `cpu_core_ids` remain plan provenance only.
`runtime_service_placements[]` owns a disjoint control-service core set; Quark
validates each service core/NUMA pair and includes those cores in process
initialization without classifying them as packet workers. The coordinator also
owns one power-of-two `command_mailbox_capacity` in `2..64`; every lifecycle
executor owns exactly zero. Shared compilation, launch validation, and mailbox
construction each enforce that relation independently, and no CLI, environment,
or runtime default can repair it.

Host discovery, packet-worker pinning, and native lifecycle-service pinning
share one dynamically allocated Linux CPU-set mechanism. Affinity capture grows
its extent only when the kernel reports that the query buffer is too small;
pinning allocates the exact extent required by the authored CPU identity.
Neither `CPU_SETSIZE` nor an online/configured CPU count is a generic placement
ceiling. A provider-native range such as DPDK's lcore limit remains an exact
provider capability check.

#### Cold Lifecycle Service Substrate

The shared transition-topology compiler stores service placement independently
from live-transition policy. Every nonempty worker topology, fixed-epoch or
transition-enabled, requires the complete exact shape: one coordinator plus one
lifecycle executor for every module-context NUMA node, or one executor on the
canonical lowest populated region node for a module-free plan. An empty worker
topology cannot carry unused service records. Partial service surfaces fail
closed; the compiler validates authored records and never synthesizes a service
identity, CPU, NUMA placement, or coordinator.

`runtime_service_launcher` accepts a non-optional compiled service topology, a
matching pre-created executor set, and one provider placement authority. A
native CPU launcher pins the caller-owned coordinator and dedicated executor
threads. A DPDK facility implementation additionally verifies that the caller
already owns the compiled EAL main lcore and remote-launches only executor
lcores. All executors wait behind one
all-or-none gate. The complete idle executor set is reserved before the first
provider effect, so concurrent/repeated launch fails before affinity, native
facility, or thread ownership changes; a topology, binding, or partial-launch failure joins
every created service and cancels every reservation before any lifecycle
callback can execute.

Each `config_lifecycle_executor` uses bounded SPSC task and result channels.
The executor does not consume a task unless it can preserve the corresponding
result, and shutdown closes admission before draining every accepted task and
result. Before result publication, unsuccessful PREPARE arenas are released;
successful arenas remain owned by the returned prepared token. Allocator
cleanup and callbacks run outside queue/wake locks.
PREPARE and RETIRE run through a platform-internal
`kinetum_lifecycle_ctx` that exposes exact identity, one bounded epoch arena,
bounded long-lived allocation and telemetry registration, logging, deadline,
and cooperative cancellation. It never exposes live `kinetum_ctx`. ACTIVATE is
deliberately absent because activation belongs to the packet-context owner and
must be a bounded publication of already prepared state.

Prepared state is transferred in a move-only `prepared_config_ownership`
token. Success is explicit token state, so null module ownership and null
packet-config pointers remain valid prepared results; destruction or overwrite
without exact retirement is fatal. Lifecycle callbacks execute with no
platform ownership lock held. The module lifecycle adapter consumes this
substrate and invokes the exact descriptor PREPARE/RETIRE callbacks under
image-wide logical serialization. The owner-worker path can transfer a
prepared token into its context store and perform bounded ACTIVATE. Bootstrap,
live preparation, quiescence-gated retirement, and transition activation share
these owners. Active scheduling and tracked foreign work use the same worker
ledger and drain contract, with no provider-specific quiescence exception.

- **Module health is owner-worker work.** The descriptor callback accepts the
  same live context, active epoch, and immutable config view used by packet
  execution. No gRPC, stats, manager, or lifecycle thread calls it, and a null
  callback means unavailable rather than healthy. The existing module-bank
  cadence services at most one context per turn; a real callback holds one
  exact epoch credit and publishes one validated latest-value signal. The cold
  telemetry source maps one typed row per context without calling module code;
  null, missing, suppressed, and stale observations remain unavailable states.
- **Link state is not a core packet authority.** Live ethdev readiness is
  validated during transactional materialization. Diagnostic publication is
  generation-owned and provider-private until projected through an exact
  generic telemetry contract. No packet path reintroduces an asynchronously
  sampled link gate.
- **Mempool occupancy is cold diagnostics only.** The generation-scoped DPDK
  statistics source may project exact native counts into generic storage-domain
  identity during a cold request. The RX path relies on the native burst result
  and never scans per-lcore mempool caches.

**`worker_lifecycle_state` enum** (`worker_lifecycle.hpp`) is the
provider-neutral state machine for one compact runtime worker:

| Value      | Meaning                                                     |
| ---------- | ----------------------------------------------------------- |
| `INIT`     | Default state; not yet started.                             |
| `STARTING` | Launch reserved; worker entry has not yet completed.         |
| `RUNNING`  | Worker entered; packet execution may still await the bootstrap gate. |
| `DRAINING` | Retiring admitted work without new RX admission.             |
| `REQ_EXIT` | Exit requested; admitted work still requires retirement.    |
| `EXITED`   | Worker body returned; the launcher must still join it.       |

Production shutdown publishes the immutable STOP command and requests
`REQ_EXIT`. A worker cancelled before entry performs no packet work. Running
kernels observe STOP, close RX admission, and retire their worker-owned queued,
retained, and asynchronous work before returning. The launcher then publishes
`EXITED`. The generation owner services final telemetry while waiting, joins
every worker, and deactivates I/O before reverse-order provider teardown.
`REQ_EXIT` does not interrupt a kernel or bypass its drain.

Materialization, graceful-shutdown request, and generation stop must be
externally serialized. Runtime observation APIs remain thread-safe, but
lifecycle mutation deliberately has one generation owner rather than a
competing internal orchestration authority.
Health reads worker counts from the coherent runtime-status publication, never
from mutable lifecycle records or a launcher-owned thread vector. Bootstrap
publishes the complete active count only after every owner reports RUNNING.

The runtime owns the packet-thread vector passed to the bootstrap launcher.
Partial launch joins every created thread before returning failure; successful
launch leaves the complete set with the runtime for ordered drain and join.
The main/coordinator thread also owns retirement; no separate retirement thread
is launched.

Worker entry first binds the thread to its compiled CPU, then registers it
with each required process facility before any activation. Inherited thread
affinity does not satisfy that placement contract. A binding or registration
failure rolls back the launch before packet admission.

Worker entry uses `try_enter_worker_running` as the single
`STARTING`-to-`RUNNING` transition. If stop or startup rollback publishes
`REQ_EXIT` before a launched worker reaches its body, the worker publishes
`EXITED` and returns instead of overwriting the exit request with
`RUNNING`.

This matters because:

- Before packet bootstrap, the materialized lifecycle services and managed
  gRPC pool may exist, and each packet worker is either not launched or blocked
  behind the activation gate. No worker executes RX or packet callbacks before
  the complete bootstrap commit; owner-worker ACTIVATE is part of that commit.
- All packet hot-path work happens on a runtime worker. TLS and packet-runtime
  telemetry/lifecycle RPC handlers run on the applicable gRPC pool thread.
  Explicit cold lifecycle callbacks run on their planned lifecycle executor,
  never on a packet worker or gRPC handler thread.

### 5. Provider Graph Compilation and Materialization

DP consumes the compiled provider graph and an admitted component catalog as
part of one runtime generation. The [Providers reference](PROVIDERS.md) owns
the role model, C ABI, native implementations, and provider resource lifecycle.
This section describes how those resources join the DP's module, worker, and
configuration owners.

#### 5.1 Verified generation inputs

Bundle verification returns the canonical plan and its immutable compiled
topology. DP passes that same topology to Quark for CPU/NUMA and host-memory
checks, then to installed-provider admission. It does not recompile provider
relationships or choose a backend from a runtime flag.

The resulting admission object owns the required component code and C-ABI fact
storage. Its lifetime covers every instance and operation pointer later
constructed by the [provider materializer](PROVIDERS.md#10-construction-and-activation).
Verified module images, the complete bootstrap snapshot, the matching command
mailbox, and a nonzero runtime generation complete the runtime input.

#### 5.2 Generation construction

The runtime constructs the complete generation before exposing packet work:

1. Validate generation facts, freeze the participant projection, and construct
   the transition coordinator before provider effects.
2. Admit module images and contexts with their compiled lifecycle-memory
   capacities; create lifecycle-executor owners without launching them.
3. Materialize the admitted provider graph with ingress disabled.
4. Allocate each worker's NUMA-local endpoint slab, then DATA/CUT/ACK channels,
   sender future-output holds, and sender/receiver policy state.
5. Prove complete slab coverage before constructing worker input queues,
   activation projections, stage/stream tables, kernels, and lifecycle state.
6. Launch planned lifecycle services over the complete provider generation.
7. Revalidate ownership, callback targets, memory totals, and dependencies,
   then publish `CONTROL_READY` while packet sources remain gated.
8. During exact bootstrap, launch workers behind the packet-body barrier,
   activate every module view, commit the snapshot, and wait for all workers
   to report `RUNNING`.
9. Activate the complete provider-I/O set, publish `PACKET_READY`, and release
   packet work.

No partial runtime is published. Recoverable construction failures retire the
owned prefix in reverse dependency order; irreversible native failures follow
the [provider failure contract](PROVIDERS.md#12-shutdown-and-failure).

#### 5.3 Resolved worker operations

Workers receive immutable RX/TX, storage, and transition tables before launch.
Homogeneous RX sources share one fixed callback target; heterogeneous sources
use their pre-resolved stream targets. The packet loop performs no catalog
lookup, protobuf parsing, native capability discovery, or inferred conversion.

The runtime keeps logical work credits separate from provider storage
ownership. Storage conversion preserves the packet's epoch and one credit;
boundary transfer, TX acceptance, or terminal disposition retires that credit.
The [burst ownership rules](PROVIDERS.md#11-packet-ownership-and-storage-changes)
define the provider's accepted prefix and the caller's retained suffix.

Whole-driver activation/deactivation remains cold work. Shutdown drains and
joins packet workers before deactivating I/O; backing storage and component code
remain alive until their dependents have retired. Section 19 describes the
complete DP shutdown order.

### 6. Exact Snapshot Epoch Store

`config_snapshot_epoch_store`
(`src/dp/config_snapshot_epoch_store.{hpp,cpp}`) is the cold DP owner for
complete canonical `ConfigSnapshot` artifacts. It composes the same
`exact_epoch_slot_table` mechanism used by module epoch stores, while keeping
complete-snapshot validation and ownership policy in its own type. It is not a
history database, RCU publication, packet cache, or epoch allocator.

**Artifact identity:**

- `config_snapshot_artifact::create()` accepts only the terminal bytes and raw
  validation hash returned by the shared canonical-content authority.
- It enforces the 10 MiB bound, parses the exact bytes, rejects recursive
  unknown fields, deterministically reserializes, and requires byte equality.
- It clears only `ConfigSnapshot.content_hash`, recomputes the exact SHA-256
  preimage, and requires both the supplied raw digest and restored lowercase
  embedded claim to agree. The store never reimplements plan-dependent module
  normalization.
- The completed artifact is immutable and solely owned; no `shared_ptr` or
  second writable representation exists.

**Exact two-slot state:**

- The store starts `EMPTY/EMPTY`, with no active, prepared, or retained epoch.
- The only slot states are `EMPTY`, `PREPARED`, `PUBLISHED`, and `RETAINED`.
  At most one slot occupies each non-empty role.
- A caller supplies an explicit nonzero epoch to `stage_prepared()`. Gaps are
  valid because CP owns durable allocation; duplicate or non-advancing epochs
  reject, and failure leaves artifact ownership with the caller.
- `preflight_publish_prepared()` proves the bounded publication can no longer
  fail while the sole owner leaves the store unchanged.
  `publish_prepared()` then promotes that exact slot and, when present, marks
  the prior publication RETAINED. The active slot index is explicit rather
  than inferred from numeric order.
- `discard_prepared()` is the only pre-publication abort and returns the exact
  artifact. A third preparation cannot displace a retained slot; retirement
  must first reopen that slot.

**Lookup and retirement:**

- `find_exact(epoch)` returns only that exact owned artifact. It never maps an
  unknown, stale, skipped, or newer identity to current or previous content.
  An artifact temporarily withdrawn into a retirement claim is not borrowable.
- `claim_retained()` withdraws one exact RETAINED artifact after external
  quiescence proof. `claim_published_for_shutdown()` does the same for the
  final PUBLISHED artifact after packet ownership has ended.
- Each claim is move-only, bound to its issuing store, fixed slot, original
  state, exact epoch, and nonzero nonce. It lends only a read-only artifact.
  The issuer must either restore it to the same slot or complete retirement;
  destroying an unresolved claim terminates.
- Completion clears only the exact claimed slot. Store destruction likewise
  terminates unless both slots and the claim ledger are empty, so teardown
  cannot silently discard a live snapshot.

Store lifecycle operations inspect at most two slots in cold-path O(1), with
no map, lock, shared ownership, implicit search, or packet-path atomic. Artifact
validation is bounded by snapshot size. The coordinator is the sole reader and
writer; workers use per-context epoch views, and Health uses the separate
immutable runtime-status publication.

`partitioned_runtime` prepares modules and activates their workers before the
coordinator publishes the bootstrap snapshot in the all-worker commit.
Shutdown joins workers and retires module artifacts before snapshot retirement.
For live updates, ledger observations alone are insufficient: the certificate
also proves boundary drain and activation, followed by reader grace. Completion
preflights all claims, retires modules before the retained snapshot, and finishes
grace only when every old slot is EMPTY.

### 7. Exact Transition RPC Admission (DP-side)

The internal CP-to-DP wire exposes five exact lifecycle operations:
`BootstrapConfigSnapshot`, `PrepareConfigSnapshot`,
`ActivateConfigSnapshot`, `AbortPreparedConfigSnapshot`, and
`GetEpochTransitionStatus`. The complete field-level contract is in
[`GRPC_API.md`](GRPC_API.md); the end-to-end implementation boundary is shown
in [`diagrams/platform_architecture.md` Section 7](diagrams/platform_architecture.md#7-transition-rpc-boundary).

`dataplane_control_service` compiles against the generated
interface and borrows the complete `partitioned_runtime`. It is registered only
after transactional materialization has published `CONTROL_READY`; the service
does not own workers, provider instances, module images, or snapshot storage.
The runtime contains one transaction-admission coordinator with immutable
participant membership, exact allocator watermarks, one immutable PREPARING
candidate, bounded terminal journal, prepared lease, and coherent progress.
Prepare, Activate, pre-commit Abort, and Status all use the runtime command
methods. Prepare and the first exact Activate context may remain mailbox-owned
across event-loop turns; their producers have no timed or cancellable return
after enqueue. Planned lifecycle executors build and retire module artifacts;
their aggregate eventfd is wake-only and the coordinator drains every result
ring independently of its count. Its borrowed descriptor projection exists
exactly while the lifecycle generation exists; after teardown the projection is
absent and direct lifecycle-result service returns `UNAVAILABLE`. Due deadlines
precede ordinary runtime work, while simultaneously ready command/lifecycle
sources alternate so neither bounded source starves.

For a non-null Bootstrap request/response the gRPC
producer clears the response, validates CP's complete durable bootstrap tuple,
requires exact plan identity, canonicalizes the snapshot against the
independently verified plan, constructs one immutable artifact, and enqueues a
fixed kind-plus-context-pointer record. The producer has no timed or cancellable
post-enqueue return and waits until the exact coordinator thread resolves its
stack context. That consumer binds the deterministic request bytes as the sole
retry identity and then:

1. stages the exact snapshot artifact under the authored nonzero epoch;
2. prepares every exact module context through the lifecycle executors;
3. launches every packet worker behind the all-or-none activation barrier;
4. owner-activates every module view and binds every kernel to that epoch;
5. publishes the module and snapshot stores, active epoch, and both durable
   allocator high watermarks in one non-failing coherent commit;
6. waits for every owner thread to publish `RUNNING` while all packet bodies
   remain blocked;
7. activates the complete provider-I/O set in canonical order;
8. publishes `PACKET_READY` and releases worker packet bodies; and
9. returns the exact restored epoch, raw validation hash, and CP high-watermarks.

Before `PACKET_READY`, a retry must be byte-identical to the first admitted
request. A clean pre-commit failure returns the state to
`AWAITING_BOOTSTRAP`; no different request may repair or supplement partial
state. After `PACKET_READY`, Bootstrap is permanently application-level
`UNAVAILABLE` for that process generation. Photon treats CP bootstrap failure
as pair-scoped startup failure and retires both CP and DP; any later supervised
start creates a fresh pair. A separately owned CP restart against a surviving
packet-ready DP follows the reconciliation path instead of calling Bootstrap.

Transition handlers clear responses and use the
[gRPC application-status contract](GRPC_API.md#51-exact-configuration-transition-lifecycle).

**Prepare** canonicalizes the candidate, requires both CP allocations to
advance, and holds it outside the two-slot store during PREPARING. Preparation
preallocates controls and arenas, dispatches image-serialized work across
planned NUMA executors, retains successful tokens, preflights/stages module
stores, then stages the snapshot. Completion proves all future claims, frozen
membership, per-context controls, both status publications, and timeout bounds
before PREPARED. Status reports measured preparation duration and lease.

**Abort and preparation cleanup** stop dispatch, collect accepted results,
and RETIRE owned artifacts in reverse order before journaling ABORTED. This
also handles failure, timeout, lease expiry, and shutdown. Post-cancellation
SUCCESS remains owned. A callback exceeding cancellation grace enters
FAILED_STOP without reclaiming uncertain ownership. During preparation's
CANCELLING/RETIRING phases, retries/Status return status-only `UNAVAILABLE`;
held Prepare/Abort calls receive terminal results after cleanup. The progress
projection is unavailable during PREPARED withdrawal and resumes at IDLE.

**Activate** resolves the PREPARED identity and preflights an inactive worker
command record. Completion proves deadline representation, starts reader grace
before COMMITTING, disarms the lease, and releases transient preparation
bookkeeping. Only then is TRANSITION published. RETIRING later binds its
deadline within the preflighted upper bound. The coordinator evaluates the
allocation-free certificate every millisecond.

**Completion** publishes module aggregate N, snapshot N with E retained,
runtime N/E/N, then RETIRING. Reader completion permits reverse-canonical
RETIRE with exact task/image/context/epoch/claim results, old snapshot retirement,
grace finish, runtime N/N/N, measured-duration COMPLETE, and IDLE last.
A RETIRING timeout before the first claim freezes updates; after withdrawal,
uncertain ownership fails stop. The original Activate context remains held
through COMPLETE or typed update freeze. Retries observe that transaction
without another command, which retires only after terminal publication.

The permanent content-identity contract is independent of handler availability.
ConfigSnapshot wire input and canonical output are each bounded to 10 MiB;
unknown protobuf fields fail recursively; the plan-derived module set must match
in both directions; modules are canonicalized by `module_id`; label maps use
deterministic key order; and opaque module blobs are hashed as exact bytes but
never parsed by the platform. Supplied module/snapshot hashes are claims to
verify, not authority. The transition authority is the exact raw 32-byte
canonical snapshot SHA-256 plus nonzero CP allocations and a 1..256-byte
printable-ASCII idempotency key. Equal epoch/mutation watermarks require an
exact active/journal match and never create work by themselves. An equal
missing record is typed `EXPIRED_RETRY`, an older pair is `STALE`, and a
one-equal/one-advanced pair is `INCONSISTENT`; no consumer parses diagnostic
prose to distinguish them. Oversized DP Prepare input or canonical output
returns `RESOURCE_EXHAUSTED`. Internal request envelopes reject unknown fields
recursively before mailbox admission, and a retained idempotency-key digest
cannot name a different identity. These rules are owned by
`canonical_content_identity` and `epoch_transition_contract`; lifecycle
admission may consume them but may not reimplement or weaken them.

CP durably retains the same transaction identity across transport retries. It
persists PREPARED after DP confirms preparation and COMPLETION_PENDING before
Activate. COMPLETE promotes active content; ABORTED preserves the active
snapshot and consumed allocator values. Fresh Bootstrap discards an orphaned
nonterminal transition allocation, retaining its watermarks and any unsatisfied
rollback intent. See the
[CP persistence contract](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md#8-config-store)
for corpus ownership and restart reconciliation.

`Drain`, `DrainStatus`, `Shutdown`, and `DumpState` are explicit
application-level `UNAVAILABLE` operations. They clear their responses and
publish no lifecycle or dump state. Runtime shutdown is signal-driven as
described in Section 19.

## Part 2: Runtime Worker Internals

### 8. Runtime Worker Architecture

> **Visual reference:** [`diagrams/platform_architecture.md` Section 12
> (Worker Hot Path)](diagrams/platform_architecture.md#12-worker-hot-path)
> shows each worker's queues, input order, and execution turn.
> [`Section 13 (Packet Lifecycle)`](diagrams/platform_architecture.md#13-packet-lifecycle)
> shows a single packet's path through the same loop.

Every runtime worker follows one provider-neutral execution contract. Before
the loop starts, it selects RX dispatch: homogeneous sources share a fixed
callback target; heterogeneous sources use each stream's pre-resolved target.
The same packet model serves ingress, interior, and egress workers. Behavior
comes from the compiled worker ownership records:

- `rx_stream_indices`: the worker polls only its assigned RX streams.
- `inbound_boundary_indices`: the worker receives only from its assigned exact DATA
  channels.
- `outbound_boundary_indices`: the worker sends and seals only the exact DATA/CUT/ACK
  channels it produces.

A worker with RX sources and no inbound boundaries is the typical ingress
owner. A worker with inbound boundaries and no RX sources is a typical
interior or egress owner. A worker can own both RX sources and inbound
boundaries in fan-in topologies. The compiled graph can represent an
active-only worker with neither packet input; its exact active-origin binding
and active-stage scheduler are then the sole packet source. A passive traffic
lane still needs at least one RX source or inbound boundary. Neither shape
receives an inferred source or default storage domain.

Before launch, runtime materialization copies every cold driver endpoint's
immutable RX/TX table and every storage-domain table into stable arrays. The
worker loop therefore has one provider-neutral packet path regardless of the
provider instances present in the plan. Every provider-specific call target is
already resolved; a worker invokes it once per scheduled burst, never once per
packet.

#### Stage modes and worker loops

The pipeline author sets each stage's `execution_mode`, triggers, and active
limits in [Axiom](AXIOM.md#9-active-stages). Gluon places stage instances on
workers, and the shared compiler records each worker's active and async stage
sets. Runtime construction checks module descriptors against those requirements
and allocates the required scheduler state before launch.

`packet_worker_kernel::run()` selects one loop from the complete owned stage
set, once after bootstrap and startup gates:

| Worker loop | Selected when | Work performed |
|-------------|---------------|----------------|
| Passive | No owned stage is ACTIVE. | Poll inputs and process arriving packets. |
| Synchronous-active | ACTIVE stages are present; all have zero async capacity. | Also service declared loop, timer, PULL, and control triggers on the worker. |
| Tracked-async | At least one ACTIVE stage has admitted async capacity and matching module capability. | Also handle work that can finish later, delivering completed results in bounded batches. |

Passive workers keep polling their assigned inputs. Control, telemetry, and
applicable health work remain present in every loop. All three use the same
fair input admission. The loop choice stays fixed for the runtime generation;
applying a configuration snapshot does not change it.

#### Input admission and worker turns

Each packet worker owns one `worker_input_scheduler` and calls it from its
existing loop to choose among its assigned RX streams and inbound DATA
boundaries. The nonempty order's endpoints, links, and allowances occupy one
prefaulted worker-NUMA mapping. Each input has a quantum of at most 64 records,
further bounded by an RX provider's admitted maximum. Completed quanta move
behind waiting inputs; capacity-limited inputs keep their unfinished allowance
and position. Empty or yielding inputs clear their allowance. A blocked storage
domain does not prevent service to an input whose required storage is available.

An input consumes at most its quantum per turn. Completing a carried quantum
permits one second visit for its unused turn allowance: at most two visits per
input, independent of queued depth. A unary input receives its full allowance
once per turn. RX rejections consume service allowance but acquire no packet
credit. Fairness applies to admission opportunities for eligible inputs; it
does not promise equal bandwidth or create capacity when storage remains full.
This schedule holds only input identities and service state. The existing
queues, reservations, and ledger remain the packet-ownership authorities.

The loop owns cold-sized exact-NUMA local work staging, fixed burst scratch,
fan-out clone scratch, transition/TX batches, and release batches. Every
reachable storage domain has one active queue. Each exact source domain in a
transition-enabled worker also has one equal-capacity future queue sized by
`source_epoch_staging_capacity`; a transition-disabled source and every non-
source domain have no future role. No packet container grows after launch.
Before the loop starts, the sole owner ACTIVATEs every exact module context and
`bind_bootstrap_epoch()` proves that each pre-resolved view has the same nonzero
epoch. Every worker then publishes
`RUNNING` while its body remains blocked; the generation owner activates
complete provider ingress and publishes `PACKET_READY` before releasing the
body gate. Each iteration then:

1. acquire-loads the sole immutable runtime-command pointer; the predicted same-
   pointer path changes no state, while one changed TRANSITION record performs
   complete nonmutating local preflight then binds future ledger, sender,
   receiver, and source state without packet interleaving. CUT-lane occupancy
   is not a begin predicate because a remote sender may have observed the same
   command first; begin consumes nothing, and bounded receiver service later
   validates the queued record against the exact bound target epoch. STOP stays
   level-triggered on every drain turn;
2. services required telemetry-bank returns before any owner can reuse them and
   suppresses unfinished cadence sweeps when stopping;
3. refreshes the one worker-cached timestamp. During an existing module sweep,
   at most one context may run its due owner-health callback and only an actual
   callback return permits the one additional budget/publication sample;
4. on a transition turn, services receiver then sender control; then services
   the selected synchronous or tracked-async scheduler when present;
5. fairly admits RX and inbound DATA, processes bounded owner-local active
   queue prefixes, and flushes compiled storage-transition, grouped TX,
   grouped storage-release, and provider-local pending work. Transition turns
   then advance cuts, activation, ACKs, and held output. RX stamps the source
   epoch and uses future staging while source and active differ; future work
   remains inert until the existing activation and role swap;
6. services telemetry cadence when not stopping, then publishes the exact
   ledger and boundary-transport observations once; and
7. on STOP, keeps source admission closed on every later turn, drains local and
   inbound work, waits for every inbound
   producer closure, closes every outbound producer once, and performs final TX
   flush before returning.

The loop contains no DPDK/UDP packet-representation branch and no global
provider selection. The canonical plan, compiled topology, and sealed catalog
resolve every source, storage, execution, transition, and sink before launch.
The complete-snapshot store header is deliberately absent from worker and
engine translation units: bootstrap binds exact executable views before
release, so the hot path needs neither a snapshot lookup nor a publication
bridge.

### 9. RX Path

Each compiled RX stream names its owner worker, stage instance, port, and
allocation domain. Cold construction binds and validates its receive operation
before the stream joins fair input admission:

```text
operations.state != null
operations.receive_burst != null
operations.logical_port == ports[stream.port_index].logical_port_id
0 < operations.maximum_burst <= PACKET_MAX_BURST_SIZE
```

The worker requests at most its current service allowance and free
staging capacity. The allowance is bounded by the operation's maximum burst
and the shared 64-record scratch ceiling. RX returns
`transferred_count` and `rejected_count`; their widened sum must not exceed the
request. Only the transferred prefix grants record ownership. Rejected native
inputs are already retired by the provider. Both counts zero means no input
was consumed; violating the input bound fails stop.

The I/O/storage implementation has already constructed every returned
`packet_record`: DPDK recovers the record from the mbuf private area; UDP
acquires one from its fixed host pool. Core code then stamps only generic
metadata authority:

- `timestamp_ns = worker_now_ns`
- `epoch = worker_epoch_ledger.source_epoch`
- `ingress_port = operations.logical_port`
- `egress_port = INVALID_PORT`
- exact logical and executable RX stage identities
- `module_next_stage = INVALID_STAGE_ID`

Once per provider burst, the worker compares its owner-local source and active
epochs and selects exactly one queue role. Records enter that role of the exact
storage-domain staging owner. The worker reserves a slot before asking the
provider for a record and never requests more than available capacity slots,
the provider's maximum burst, or `PACKET_MAX_BURST_SIZE`. A returned-prefix
record receives one logical worker credit after its exact epoch is stamped and
before local work publication. Rejected and unconsumed input creates no credit;
every unused staging reservation is released, including a rejected-only burst.
The role-local reservation remains a capacity rollback proof and is never read
as epoch ownership or quiescence.

At IDLE, source and active epochs are equal, so the predicted active branch is
selected and every future queue is empty. A committed TRANSITION command binds
the exact target, advances source admission once, and selects the separate
future role for new RX while old active work drains. Local activation exchanges
queue owners in O(1) and promotes the complete future-credit slot without a
scan or copy. Every boundary receive and stage execution still requires exact
equality with the ledger's active epoch. A zero, reserved-wrap, or otherwise
unbound packet epoch is an ownership invariant violation and terminates; the
bounded packet/view mismatch path below applies only to a credited bound-slot
packet whose exact module view disagrees.

### 10. Stage Dispatch

The worker consumes available queue prefixes at the exact active epoch:

```text
while bounded local work is available:
    stage = stages_[record.current_stage_instance]         # O(1) executable lookup
    if work is MODULE execution:
        records = contiguous same-stage, same-epoch prefix # At most 64; never wait or sort
        if worker has tracked-async scheduler and stage is ACTIVE:
            masks = scheduler.ingest_async(..., records, ..., cached_time)
        else if worker has synchronous active scheduler and stage is ACTIVE:
            masks = scheduler.ingest_synchronous(..., records, ..., cached_time)
        else:
            forward_mask = execute_module_batch_mechanism(
                *stage.module_store, stage_instance, region, records, worker_scratch)
        resolve each lane's forward, retained, or drop ownership
    else:
        execute the platform mechanism or resume the already-selected delivery
    dispatch forwarded records through precompiled logical routes
    finish any pending context-selection prefix before the next ownership gate
```

`stages_` is a flat `vector` indexed by executable stage-instance identity.
Each owned entry carries direct immutable compiled stage and logical-stage
facts, its exact module store when applicable, and its precompiled routing
tables. There are no string-keyed lookups on the hot path. Generic engine
entry points remain available to controlled embedders and fail closed for
module or unspecified kinds that lack runtime-generation authority;
the production worker invokes only the pre-resolved packet mechanisms above.
After the worker ownership gate, a packet/module-view epoch mismatch invokes no
module callback, records one bounded owner-local fault, and appends the packet
to burst retirement through its exact storage-domain table. Because the packet
still belongs to an exact bound ledger slot, that terminal disposition retires
its worker credit before grouped physical storage reclamation. Worker RX, TX,
drop, fan-out-overflow, stage, and epoch-credit state are plain single-writer
values. Counter readers consume immutable completed telemetry banks; epoch-
credit observers consume their separate coherent per-turn publication. Neither
reader touches the owner's mutable line.

`packet_worker_kernel::{dispatch_stage_result_,dispatch_one_target_,dispatch_fanout_}`
apply the same three routing tiers to every storage and I/O implementation:

1. **Explicit SDK route.** A non-invalid `module_next_stage` resolves an
   authored logical destination and is cleared after instance selection. An invalid or unsafe target
   retires the packet; no nearby instance is inferred.
2. **Conditional edge.** The precompiled edge vector is walked in priority
   order and the first matching edge wins. Equal priorities preserve authored
   edge order through the compiler's explicit source-index tie break. A
   conditional set with no match drops. Invalid condition syntax is rejected
   during cold route compilation, never repaired into an unconditional edge.
3. **Unconditional fan-out.** The first compiled successor receives the
   original record. Each additional successor invokes that record's singular
   `clone_writable` operation. The operation must create an independent
   writable payload and metadata snapshot; DPDK uses a deep mbuf copy and the
   fixed host pool copies into a distinct record/payload slot. Independence is
   required because NAT44 or another byte-mutating downstream branch must not
   change bytes observed by a sibling branch. Each successfully validated clone
   acquires one additional logical work credit before branch dispatch; clone
   failure creates neither a record owner nor a credit.

Fan-out is broadcast, not per-packet successor selection. When its successors
are distinct TX stages and `output_port` remains `KINETUM_PORT_UNSET`, each
record resolves through its destination TX stage's own bound stream. An
explicit logical output port instead resolves through the owner worker's dense
port table. Neither form can make one broadcast branch select another branch's
TX-stage binding.

Each logical destination has a cold-resolved instance set. SAME_LANE uses its
matching replica. MODULE selection invokes the target image's stateless
selector on an available contiguous flow prefix, then validates every occupied
lane before dispatch. The module domain supplies fixed ordinals; a dense table
maps only permitted ordinals to executable targets. Context alternatives do not
create fan-out copies. PULL and control keep their explicit same-worker owner.

Selection precedes storage transition and boundary delivery. The record retains
its selected instance across retries, so backpressure cannot choose another
context. The worker never consults live module state, provider RSS, or a registry
to resolve ownership. Selector input and callback contracts are in
[Module SDK](MODULE_SDK.md#module-context-selection).

The compiled fan-out vector statically bounds singular clone invocations. A
clone failure or full fan-out staging array increments the owner worker's
active telemetry bank's `fanout_overflow`. Capacity is checked before a clone
is requested, so the runtime never creates a clone it cannot stage; a storage-
domain clone failure increments the same owner-local field and that successor
receives no packet. There is no shared payload, heap fallback, provider
conversion, or unbounded module-selected clone loop.

**TX-stage handling** (`stage->kind() == STAGE_KIND_TX`) is described
in [Section 11](#11-tx-and-egress).

**Cross-region handling** is described in
[Section 12](#12-cross-region-boundary-integration).

**Drop semantics:** rejected mechanisms and fail-closed route outcomes append
the exact record to its storage domain's bounded grouped release burst and
retire its exact worker credit once, then increment the owner worker's
`dropped_packets`. Contract violations such as an
invalid internal index, null owned record, or missing compiled boundary are
fail-stop rather than reported as packet drops. For the per-packet view,
including ordinary retirement points, see
[`diagrams/platform_architecture.md` Section 13 (Packet Lifecycle)](diagrams/platform_architecture.md#13-packet-lifecycle).

### 11. TX and Egress

Terminal TX dispatch is a grouped scatter pattern with no fallback:

- `KINETUM_PORT_DROP` makes the TX mechanism reject the packet and routes it to
  storage retirement.
- `KINETUM_PORT_UNSET` selects the operation through the owner worker's dense
  TX-stage-instance table.
- Any explicit logical egress resolves through the precompiled
  worker-local 64-entry `logical_to_tx_index` dense table. Packet dispatch
  performs one bounds check and one indexed load; it never hashes a logical
  port or reaches another worker's TX queue. Both forms are owner-local indexed
  lookups; neither terminal path consults the global materialization tables.
- An unknown logical port, absent stage binding, or invalid TX index retires the
  packet. There is no first-port, UDP, copy, or provider fallback.
- An authored conversion on the resolved stage-to-stream edge executes first,
  even when TX also admits the original domain. Otherwise direct TX requires
  membership in that stream's accepted-domain set. An incompatible original
  domain follows the same stage-drop and original-owner release path; an
  explicit alternate egress cannot borrow another edge's conversion.

The worker accumulates records in order for each exact
`packet_tx_burst_operations` table. A full accumulator or the iteration boundary
invokes one `transmit_burst`; records are never sorted or split by pool.
Before the foreign call, the worker saves every record's original domain,
length, epoch, and executed TX stage. Accepted records may already be freed or
reused when the call returns. The operation consumes every record in its
returned accepted prefix, and only that exact prefix retires its
worker credits after the provider reports acceptance. The worker retains the
untouched suffix and appends it to the existing grouped storage-domain release
path, where terminal disposition retires each remaining credit exactly once;
each worker polls, conditionally flushes, and finally flushes only the TX
operation indices compiled from its exact I/O-stream ownership. Startup rejects a stream
referenced by multiple workers or an RX/TX operation aliased by multiple
streams; table immutability never implies multi-producer queue safety.
Providers may neither free nor translate that suffix. Packet ownership is
therefore explicit in both directions without a retry queue or provider
fallback.

After grouped submission, each TX table's `maybe_flush` operation may publish a
provider-local pending burst. The exact owner worker invokes unconditional
`flush` after all accepted records and inbound boundary records have been
drained, then exits. After every worker joins, cold provider teardown reclaims
its remaining native resources and accepted ownership; it does not invoke the
packet operation table a second time.

### 12. Cross-Region Boundary Integration

When the next stage instance belongs to another worker, dispatch requires an
exact executable boundary. Gluon emits and
hashes one `BoundaryPlacement` for every distinct directed cross-worker
stage-instance endpoint pair and none for same-worker edges. Each placement
owns exact endpoint and worker identities, independent DATA/future-output
capacities, and receiver-NUMA DATA placement.

`compile_provider_topology()` composes the existing
`compile_transition_topology()` authority, which continues to own the exact
two-directional boundary set, compact worker ownership, explicit source/sink
participants, fan-in indices, participant DAG, runtime-service cardinality and
NUMA coverage, bounded transition policy, and transition-only worker fields.
The provider compiler correlates those results with reachable storage domains,
explicit transition rows, exact handoff credits, and packet-buffer floors and
emits their compact indices directly. Runtime materialization consumes those
indices rather than recompiling boundary semantics elsewhere.

A missing or extra boundary descriptor fails structural compilation.
Transactional materialization first allocates one stable endpoint slab for
every compiled worker on that worker's exact NUMA node. A nonempty slab uses
one checked, prefaulted mapping for all of the worker's inbound and outbound
slots; a worker with no boundary role owns an empty slab and no mapping. The
compiled inbound/outbound boundary order assigns every channel slot exactly
once. Each outbound slot also receives one linear sender-policy claim and each
inbound slot one mirrored receiver-policy claim before the complete role-
correct claim set seals and kernel construction begins. Kernel teardown retires
both policy claims before hold and channel teardown; channels still retire
before slab destruction. Slabs own bytes and lifetime only: they expose no
transport or policy operation and no mutable-state accessor.

Materialization then allocates one `boundary_epoch_channel` and one separate
`boundary_future_output_hold` for each compiled cross-worker edge. A shared DP
NUMA-SPSC owner places the plan-sized DATA extent on the receiver node, CUT
storage lives in the receiver slab because that worker polls it, ACK storage
lives in the sender slab because that worker polls it, and the hold remains on
the sender node. Each endpoint's mutable sequence/pending state and coherent
publication live in its owning worker's slab. The channel remains the sole
semantic owner of pointer-only DATA, successful enqueue/dequeue sequences,
typed capacity-2 CUT/ACK transport, one exact pending control record per
producer, coherent observations, and terminal process-sender closure. It
contains no marker kind, generic control message, seal/gate/activation policy,
provider lookup, or fallback capacity. The future-output hold remains a
distinct pointer-only owner with its own plan capacity.

Each kernel adopts one complete `worker_boundary_sender` after slab sealing.
That owner is the only production caller of channel DATA/CUT/ACK sender
operations and future-hold push/pop. Its per-boundary gate facts occupy one
additional sender-local cache line in the existing slab mapping. The line has
no pointer, clock, container, string, or telemetry publication. Route
compilation stores one direct worker-local sender ordinal, so packet dispatch
performs no boundary search.

The same kernel adopts one complete `worker_boundary_receiver`. It is the only
production caller of CUT receive and ACK submit/retry, and its receiver-local
policy line carries only active epoch, accepted CUT, duplicate count,
and phase. The channel remains the sole successful dequeue-sequence authority.
DATA receive itself remains kernel-owned in the established
order: peek and reserve destination capacity, pop the exact pointer, acquire
receiver ledger credit, complete the channel sequence, then publish local
execution. Receiver policy neither wraps nor replaces that hot path.

Cross-worker dispatch first applies any exact compiled storage transition, then
passes the exact record to that sender owner. In fixed `OPEN(E)`, only E can
attempt DATA. During a committed E-to-N sender generation, E remains
eligible only while DRAINING, N transfers to the exact future hold before ACK,
and the worker invokes sealing only after every inbound cut is drained, source
admission is N, and all old credit reaches zero.
After that exact cut, E becomes terminate-class. A full DATA ring or full hold
returns BACKPRESSURED and leaves record, local reservation, and ledger credit
with the caller. HELD transfers
the pointer to the hold, releases only the local reservation, and keeps the
worker credit live. A successful direct enqueue transfers the pointer, advances
the sender sequence, and then retires that credit.
Sender or receiver approach to the reserved sequence terminal returns one typed
`SEQUENCE_EXHAUSTED` result to the owning worker before mutation. That worker
captures the fixed first-fault identity and terminates; neither endpoint wraps
or loses the queued record inside the transport.

An exact ACK must equal both the target epoch and captured cut sequence;
monotonic or greater-than progress is never accepted. Exact duplicates are
idempotent and counted, while every different, stale, skipped, or early ACK is
terminate-class. Once the gate opens, older held output remains FIFO authority:
the sender borrows its front, publishes DATA and advances the channel sequence,
removes that exact pointer, and only then retires its worker credit. While that
finite held prefix is nonempty, newly produced target output returns
BACKPRESSURED with record, reservation, and credit still at the caller; it is
never appended behind the prefix. Sustained traffic therefore cannot postpone
hold drain and the next generation indefinitely. DATA or hold pressure never
prevents the bounded owner turn from polling every active CUT/ACK endpoint.
Held service spends one exact attempt budget: each selected endpoint drains
until DATA is full, its hold is empty, or the budget expires, and the cursor
already names the following endpoint for the next turn.

The receiver peeks and validates the record's active epoch, endpoint, and
storage domain before reserving destination staging. It then consumes that
exact pointer, acquires one receiver credit, and completes the dequeue sequence
before publishing local execution. A second receive, receiver publication, or destruction while
that completion is unresolved terminates. The DATA ring owns the physical
record between the two endpoint transfers; no worker claims it. During shutdown, a worker stops source
admission, drains all local and inbound work, waits until every inbound sender
is closed and every DATA/control/completion owner is empty, then closes each
outbound producer exactly once. Channel destruction with retained ownership
fails stop.

During a committed transition, independently scheduled workers may observe the
immutable command on different turns. A remote sender with no old work can
therefore publish the target CUT before this receiver begins. Receiver begin
neither inspects nor consumes that queued record; its first bounded control
service accepts only the exact target CUT. The first valid record latches;
exact duplicates are idempotent and counted; duplicate-different, stale,
skipped, malformed, or unrelated records terminate. `classify_sequence_cut()`
is the sole PENDING/REACHED/CONTRADICTION rule. Consuming beyond the sender's
final old-DATA enqueue is a CUT identity contradiction; the receiver records
the typed fault and terminates without activation. The ACK side remains strict
at begin: an ACK returning to a
sender necessarily follows that same sender's begin, seal, CUT publication,
remote drain, and remote activation. ACK-lane, pending-control, and policy
cleanliness therefore remain required rather than being timing assumptions.
Worker fan-in becomes ready only when every inbound edge is CUT_DRAINED,
source admission names the exact target, and active-epoch credit is zero. A
worker with no inbound edge receives the same zero-credit/source proof before
vacuous fan-in; logical-region aggregate state is never consulted.

After all outbound CUTs have entered channel ownership, one local activation
owner performs a complete nonmutating preflight over every worker-owned module
store, source-domain queue pair, and ledger identity. Only then, with no packet
work interleaved, it activates module stores, exchanges active/future queue
owners in O(1), and moves the complete future credit count into active while
clearing the future slot. Every inbound receiver line is marked activated
before the first exact ACK submission. A full ACK lane retains one pending
record for a later bounded turn; a published ACK is never resubmitted. Because
the target sender gate opens only from that ACK, no target DATA can arrive
before receiver activation; because every old cut is drained at activation,
the existing `record.epoch == ledger.active_epoch()` receive admission remains
correct without a transition-specific packet branch.

Every kernel also owns one caller-placed `quiescence_reader`. Runtime
construction binds the complete reader set in frozen-worker order, then creates
one immutable certificate graph over exact activation, ledger, sender/receiver
policy, boundary-transport, and reader publications. Construction proves that
every worker owner borrows the same exact ledger and that both endpoint owners
borrow the exact channel used for transport observation. Evaluation is a cold
O(workers + boundaries + readers) scan. Missing, torn, or older observations
remain incomplete; a coherent future generation, owner mismatch, or cut
disagreement is a typed contradiction. Region aggregates and mutable owner
lines are never inputs.
Legal current-transition draining, CUT, and ACK-pending phases also remain
incomplete. Cuts are compared only after both endpoints captured them, including
a valid zero cut; completion still requires both ACK edges and transport retirement.

The final grace sequence is two-legged. Commit starts the exact reader grace
before triggering workers, so a worker can publish once from its existing rare
transition arm after its final old-config read. Exact execution and boundary
completion permit RETIRING. RETIRING waits for the reader leg if necessary;
only completed old-object retirement may finish the grace generation.
A stalled reader therefore retains old state and freezes later updates under
the RETIRING timeout law. Fixed Bootstrap starts no grace and performs no
certificate evaluation.

The three-channel contract in PEG Pat-10 combines DATA order, out-of-band
progress, exact CUT/ACK identity, future-output ownership, and old-work
quiescence. The
[`ordered_cut_boundary_protocol.md`](diagrams/ordered_cut_boundary_protocol.md)
guide proves why an epoch-only marker cannot satisfy it. Fixed Bootstrap keeps
endpoints OPEN, publishes baseline observations, and leaves the reader domain
and completion owner inactive. Live Activate starts grace before the immutable
worker command; the completion owner uses the coherent certificate to reclaim
old ownership. Neither an empty control lane nor an open sender proves completion.

### 13. Active Stage Dispatch

The exact module ABI supports ACTIVE images through `ingest`, `run`, and
`on_control` callbacks under one `worker_active_stage_scheduler` per worker with
active instances. Every row is keyed by exact `stage_instance_id` and binds one
module context, epoch store, origin storage domain, schedule order, trigger
mask, active limits, control/PULL edges, and owner worker. Replicated lanes
never share scheduler state.

All mutable rows, retained/free/pending lists, copied payloads, queue storage,
timer entries, origin-copy scratch, and relation bits occupy one checked
prefaulted mapping on the worker's exact NUMA node. A dense global-stage-to-row
index plus checked active-row bit matrices gives O(1) control/PULL edge
admission without a topology search or an active-row-by-global-stage quadratic
table. The slab exposes no routing or provider operation.

The synchronous owner-worker foundation is:

- loop, timer, control, and pull-ready trigger bits;
- one plan-sized copied control mailbox per executable active instance;
- one runtime-capacity caller-storage timer wheel per active worker, with exact
  per-instance quotas, a 1 ms quantum, and a maximum accepted rounded delay of
  65,535 ms; expired ownership keeps its credit through callback return while
  the released wheel slot may accept the next arm;
- inline `active_ctx->emit` through the worker's exact storage-domain
  origination operation and common dispatch core;
- generation-checked retained packet handles with exact packet and byte bounds;
- batched ACTIVE ingest gives every occupied lane independent provisional
  retention and async ownership; an out-of-prefix lane returns invalid;
- retained emit/drop that transfers decision ownership to the platform and
  survives backpressure without duplicate dispatch;
- one deduplicated PULL bit per compiled edge, serviced through an owner-local
  burst-bounded round-robin cursor rather than a capacity-sized scan;
- worker-ledger credit for every timer, control message, PULL request, or
  synchronous callback that may generate packet work;
- no foreign thread calling `run`, `ingest`, `on_control`, or
  `health_check`.

Control and PULL endpoints are active and same-worker in both directions.
Cross-worker active control/PULL authoring rejects; it never receives a hidden
boundary or mailbox. Each control message must retain its one authored edge
classification; competing edges or per-message relabeling reject. One
schedule-ordered pass runs each active row directly,
and RUN/control callbacks receive the common burst-class service budget.
INGEST preserves that allowance per input, bounded by the 64-record batch;
packet/byte and token quotas still apply to the complete context population.
The [loop selected at worker entry](#stage-modes-and-worker-loops) determines
which active mechanisms are present. The passive specialization contains no
active-stage scheduler branch, active context construction, or active timestamp store;
the synchronous-active form contains no completion poll, cancellation atomic, token
slot operation, or completion scan; the tracked-async form polls one bounded
completion prefix once per turn. That prefix is derived as half the shared
burst-class work budget, preserving same-turn retained/timer/control/PULL
progress without becoming a capacity authority.

Tracked async storage is part of the same one-mapping-per-worker slab. Each
authored token contributes one cache-line slot. One caller-storage
`mpmc_queue_view` carries terminal cells from any foreign producer to the sole
worker consumer. Its physical capacity is derived as
`max(2, next_power_of_two(sum(async_work_capacity)))`; it is never an authored
or independently tunable policy. Since every live slot can publish at most one
terminal cell and cells are at least as numerous as slots, a winning completion
never needs a caller retry loop. The only mutable platform state touched from a
foreign thread is the token slot, completion queue, and cache-line-isolated
cancellation publication. Result bytes remain in module-owned token-associated
storage and become visible through the completion queue's release/acquire edge.
Packet-bound begin may consume the provisional retained handle in the same
INGEST callback; the existing whole-batch validation remains the sole commit
gate and publishes either that exact token ownership or nothing.

The public ABI is the exact `0.1.0` contract. INGEST and
on_control receive the same runtime-written `kinetum_active_ctx` as run. The
module sees opaque handles only; no service exposes `packet_record`, provider
storage, route tables, or a mutable epoch selector. Retaining an input preserves
its existing packet credit. A copied origin acquires one credit before local
publication and then uses the ordinary transition, boundary, TX, sink, and
drop paths.

Storage for active origination is never inferred from the worker, provider, or
first domain. Deployment bindings contain exactly one
`ActiveOriginBinding(logical_stage_id, lane_id, storage_domain_id)` for each
active stage/lane and none for passive stages. Lowering writes that exact
domain onto the stage instance; the shared compiler proves write access, NUMA
agreement, worker ownership, reachable-domain propagation, and budget impact.
Missing, duplicate, extra, passive, or unknown rows reject before the plan is
published. `ActiveStageLimits` additionally authors retained packet/byte,
timer, and copied-control capacities per emitted stage/lane. No capacity comes
from a module blob or runtime default. Tracked-async instances additionally
author an exact token capacity and positive cancellation grace; both are
present together, the grace is strictly below the plan's commit timeout, and
the module capability flag agrees in both directions.

Commit places each scheduler into drain before source admission advances. New
LOOP work, origins, timers, control, PULL, new async submissions, and new
recirculation stop; already owned E packets may retain, emit, or drop without
creating a new credit. Cancellation is release-published before DRAIN, and a
post-cancellation SUCCESS remains an exact SUCCESS delivery. Armed timers,
queued control, pending PULL, retained handles, foreign tokens, completion
callbacks, and pending dispositions drain in bounded turns. Activation requires
all of them empty, then executes module ACTIVATE, source-role rotation, whole
ledger promotion, scheduler N publication,
worker activation proof, receiver marking, and ACK without packet interleaving.
Shutdown uses the same drain owner and cannot reach FINI or provider retirement
with unresolved active ownership.

`KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK` is admitted only with exact nonzero
token capacity and cancellation grace. A foreign thread can publish one typed
terminal result or read cancellation; it never invokes module code, updates the
ledger, or reads scheduler rows. Same-instance recirculation is OPEN-only and
uses the ordinary bounded local staging path without another packet credit. A
single already-pending disposition may publish after DRAIN begins, but the
resulting callback cannot recirculate again; this one-pending closure makes old
local work finite without admitting an authored cycle.

## Part 3: Module Lifecycle and Telemetry

### 14. Exact Module Generation and Lifecycle

The module subsystem has one exact C ABI and one atomic generation owner.
It does not expose a current/previous configuration selector, lazy image load,
relative-path search, stage-section discovery, or foreign-thread health path.
The module-author side of this contract is documented in
[`MODULE_SDK.md`](MODULE_SDK.md); this section describes platform ownership.

#### Atomic generation admission

`module_manager::admit_generation` receives three explicit authorities:

| Authority | Exact content |
|---|---|
| `module_image_spec[]` | Expected 1..255-byte printable-ASCII semantic `module_id` and canonical absolute regular-file path for every image. |
| `module_context_spec[]` | Bounded printable-ASCII executable context identity, module identity, compiled context index, sole worker index, CPU, NUMA node, exact context-lifetime capacity, and exact per-epoch arena capacity. |
| Lifecycle providers | Tracked context/epoch memory, owner-local telemetry registration, bounded logging, deadline, and cancellation authority. |

Admission is a transaction:

1. Normalize the input order by sorting unique image IDs and context indices.
   Image input order is not authority; the sorted IDs define deterministic
   zero-based `module_image_index` values.
2. Reject empty, unbounded, non-printable, duplicate, conflicting,
   unreferenced, or cross-linked identities before invoking module code.
3. Require every image path to be canonical, absolute, symlink-free, and a
   regular file. The loader never searches CWD, `PATH`,
   `LD_LIBRARY_PATH`, install directories, or aliases.
4. Require a link-closed module image: implementation and static-archive
   symbols are hidden, `kinetum_module_register` is the sole deliberate SDK
   export, and every non-weak import resolves from an explicitly linked
   dependency. GNU C++ module-owned code does not emit `STB_GNU_UNIQUE`
   definitions that escape exact unload ownership. Header-defined SDK mechanisms
   never depend on host exports.
5. Pass each admitted canonical path directly to
   `dlopen(RTLD_NOW | RTLD_LOCAL)`, resolve only
   `kinetum_module_register`, and pass the returned descriptor to the
   loader-private admission authority. Immediate local binding is a runtime
   backstop for the earlier link-closure gate. An unloadable image cannot own a
   process-global registration mechanism without an exact deregistration
   protocol. Built-in generated protobuf models therefore remain in host/test
   authoring code; runtime images own strict JSON parsers and register no
   protobuf descriptors. Any explicit auxiliary DSO is colocated with the main
   image and integrity-covered by the bundle.
6. Require exact `KINETUM_MODULE_ABI_VERSION` equality, a known flag set,
   mandatory lifecycle callbacks, and the exact PASSIVE or ACTIVE callback
   shape. Older and newer ABI versions both reject.
7. Require `KINETUM_MOD_F_REPLICABLE_CONTEXTS` before one image may own
   multiple contexts.
8. Construct every cold lifecycle owner and invoke INIT under the image's
   logical serialization domain. No manager mutex is held across foreign code.
9. Publish all image/context lookup tables only after every INIT succeeds. A
   failure finalizes already initialized staged contexts and unloads all staged
   images before returning.

After publication, stable image and context pointers remain valid until manager
destruction. An exact repeated admission is a no-op; any different second
generation fails. Loaded image handles and their declared shared dependencies
remain generation-owned resources. Host/offline schema evolution does not
create a runtime descriptor-sharing relationship: each image remains
link-closed and owns the exact parser for the config bytes admitted to that
generation. This gives one authoritative generation without a partially
visible prefix or speculative compatibility path.

Cold lifecycle callback serialization is scoped to one admitted code image.
Two contexts sharing that image cannot overlap INIT, PREPARE, RETIRE, or FINI,
while an unrelated image retains its own serialization domain and may progress
in parallel. ACTIVATE, packet, active, and health callbacks use sole-worker
ownership and never acquire that cold image turn. The manager never uses a
global foreign-callback mutex.

#### Cold and live state are structurally separate

| Object | Owner and purpose | Packet-path reachability |
|---|---|---|
| `kinetum_lifecycle_ctx` | Borrowed shell for one cold operation; points to the tracked lifecycle service table and opaque platform operation state. | Unreachable |
| `lifecycle_context_owner` | Platform owner of exact identity, allocation arenas, telemetry registrations, deadline, and cancellation state. | Unreachable |
| `kinetum_ctx` | One cache-line live object containing context-local mutable state plus NUMA, CPU, and worker identity. | Direct owner-worker pointer |
| `kinetum_prepared_config` | Exact transferred ownership record: module `owner_handle` plus immutable borrowed `packet_config` view. | Only `packet_config` is read |
| `kinetum_batch_t::epoch_config` | Immutable view selected from the exact epoch-tagged runtime slot. | Direct batch field |

There is no pointer from `kinetum_ctx` back to lifecycle services. Packet
callbacks therefore cannot accidentally allocate from a cold arena, register
telemetry, log, or inspect lifecycle cancellation. Packet execution caches
stable descriptor/context/config pointers and performs no manager lookup.

#### Callback placement and ownership

| Callback | Calling context | Required contract |
|---|---|---|
| INIT | Cold setup before owner-worker launch, image-serialized | Allocate tracked context state from the exact context arena and register owner-local telemetry; transfer state only on success. |
| PREPARE | Lifecycle executor, image-serialized | Build one immutable exact-epoch artifact in the exact epoch arena; may be expensive and cancellable; transfer one prepared record only on success. |
| ACTIVATE | Sole packet owner worker | Bounded and infallible publication only; no parse, allocation, blocking, logging, or reclamation. |
| `process` / `ingest` / `run` | Sole packet owner worker | Bounded hot-path work against the exact live context and exact immutable packet view. |
| `health_check` | Sole packet owner worker | Return one bounded module assessment against the same active epoch/config view; null means unavailable. The owner stamps exact epoch/cached time, measures callback duration with one post-return sample, and publishes only a valid result. |
| RETIRE | Lifecycle executor after quiescence and grace, image-serialized | Consume the exact prepared ownership record once and reclaim it. |
| FINI | Cold teardown after workers/executors join, image-serialized | Finalize detached context state before its image unloads. |

`module_lifecycle_adapter` is the production bridge between the lifecycle
executor and the C ABI. It validates the executor's exact image/context
identity, acquires one logical image turn, invokes PREPARE or RETIRE without a
platform ownership lock, and preserves explicit success state even when both
prepared pointers are null. Image serialization prevents unsafe concurrent
foreign lifecycle calls for contexts backed by the same code image while
allowing unrelated images to progress in parallel.

The C++ SDK exposes `context_memory_resource` and
`epoch_memory_resource` adapters over those lifecycle allocators. The C++ INIT
trampoline seals the context resource after success; a prepared-artifact owner
must seal its epoch resource before transferring success. All built-ins do so,
and post-publication container growth then fails instead of selecting the
process default allocator. RETIRE and FINI receive the same exact ownership for
destruction and reclamation only. Production module constructors require an
explicit memory resource, so omission cannot silently reintroduce heap-backed
state.

Neither resource has a runtime sizing constant. Deployment bindings author one
nonzero context-lifetime and one nonzero per-epoch capacity for each logical
module-stage lane. Gluon lowers them into the exact `StageInstance`; the shared
compiler emits them in `compiled_module_context` and proves checked per-NUMA
totals, including one epoch arena for every `EXACT_EPOCH_SLOT_COUNT` slot.
Generation admission narrows only after those checks. The lifecycle owner
allocates and seals exactly those byte limits, so `KINETUM_ERR_NO_MEMORY` is
the existing module-visible result when a callback exceeds its authored
capacity. The production NUMA provider acquires and releases ledger slots in
O(1) through an intrusive free list and an opaque slot/reuse token carried only
by the internal lifecycle block. It validates the complete block on release,
so exact slot reuse cannot make an old token current; no pointer scan or
parallel ownership map exists. Mapping and unmapping remain outside the ledger
mutex while the corresponding slot and byte claims stay reserved. The module
ABI carries no capacity field or internal token identity.

#### Exact two-slot artifact ownership

Every admitted `module_context_instance` owns one `module_epoch_store`. The
store composes the shared exact-slot state machine with the move-only prepared
token; slot metadata and artifact ownership cannot diverge. Its legal path is:

1. A lifecycle producer moves one identity-matched token into an EMPTY slot,
   marks it PREPARED, then release-publishes the exact epoch.
2. The sole owner worker acquire-observes that epoch, preflights slot promotion,
   borrows the exact token, and constructs a complete prospective executable
   view before invoking foreign code.
3. ACTIVATE runs on that same owner. Packet callbacks cannot interleave while
   the owner is inside ACTIVATE. After the callback begins, only bounded,
   preflight-proven non-failing assignments remain: promote PREPARED to
   PUBLISHED, move the former PUBLISHED slot to RETAINED, and commit the
   one-cache-line view.
4. After quiescence, one store-bound nonce may claim a RETAINED slot. Final
   shutdown may withdraw and claim the PUBLISHED slot only after every RETAINED
   artifact is gone; this idle-layout condition is preflighted before ownership
   moves. The claim exposes only a read-only token borrow to RETIRE, so ownership
   cannot escape the claim. Restore is legal only while that exact token remains
   live; after the callback, claim-scoped consumption records RETIRE exactly
   once, and only then may the issuing store complete the slot transition.

Null `owner_handle` and null `packet_config` remain valid successful artifacts;
the occupied slot and live token carry success. Staging may overlap ordinary
packet reads of the immutable active view, but slot-mutating lifecycle phases
are coordinator-serialized. The release/acquire pair publishes complete
PREPARE state; it is not a general concurrent-mutation shortcut.

`KINETUM_MOD_F_LIVE_EPOCH_TRANSITION` declares the exact
PREPARE/ACTIVATE/RETIRE contract. The
`KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK` bit is also part of this ABI: a module
setting it promises that every asynchronous reference will participate in the
platform work ledger through the exact token surface. The worker accounts RX,
local work, clones, boundary transfer, TX, sink, drop, retained handles,
timers, copied control, PULL bits, active origins, foreign tokens, completion
callbacks, recirculation, and synchronous callbacks in its exact slots. A
packet-bound token moves the retained packet's existing credit; standalone work
acquires one before publication. The completion queue and owner callback retire
that ownership exactly, so the global certificate needs no second async leg.

#### Exact packet execution and health publication boundary

Before bootstrap may launch a worker, shared topology compilation
and exact module-generation admission must prove the module-stage set in both
directions: every module stage instance maps to one admitted context at the
same compact index, string identity, image identity, worker/CPU/NUMA placement,
execution mode, and exact memory capacities; every admitted context is consumed
exactly once. Bootstrap then prepares the fixed snapshot epoch and validates
the resulting executable view before release. The immutable execution table stores one direct
`module_epoch_store*` per module stage instance, and each owner worker gets one
preallocated reusable `module_batch_scratch`.

Generic `dp_engine::execute_stage` remains the component-test adapter over the
same packet mechanism; it rejects module and unspecified kinds. This keeps
isolated mechanism tests from reaching a module without the additional
authorities. Within an admitted runtime generation, only the
pre-resolved owner-worker kernel calls the passive
`execute_module_batch_mechanism` or scheduler-only
`execute_active_module_batch_mechanism` with a contiguous compatible prefix,
prevalidated store, stage-instance identity, owner region, and worker scratch.
The hot module path borrows the stable view once, checks every
`packet_epoch == view.epoch`, fully overwrites the occupied SoA lanes, and
invokes the pre-resolved callback once. The prefix has one context and epoch,
contains at most 64 records, and never waits for more input or sorts work.
It performs no slot search,
manager lookup, allocation, lock, string operation, logging, clock read, or
provider branch. The common entry rejects non-contiguous, multi-segment,
length-inconsistent, CPU-inaccessible, or unknown-capability storage before
constructing the module batch, regardless of which provider owns the native
backing.
Exact store/view selection and mismatch evidence add no shared atomic update.
The same sole write site copies cumulative mismatch count and sticky first-fault
identity into the context's active telemetry projection; only an immutable
completed bank can carry it to the cold aggregator. Stream and stage accounting
uses the worker's parallel owner-local bank described in
[Section 15](#15-stats-collection).

An epoch mismatch invokes no foreign callback and cannot select another slot.
It sets one sticky owner-local fault, increments a saturating owner-local count,
captures the first bounded mismatch record, updates that bank projection at the
same site, and returns a zero forward mask. The common
dispatch appends the record to its exact storage-domain release group; the
burst operation returns the native backing once. No foreign thread reads these
plain diagnostics while the owner can write them.

Module health follows the same owner rule as packet state. The ABI callback is
`health_check(ctx, active_epoch, active_packet_config)` and may run only on the
context's sole owner worker. A null callback means health is unavailable, never
healthy. A gRPC, stats, manager, or lifecycle thread cannot call module health.
The callback returns only score/flags/reason in a fixed
`kinetum_health_assessment`; it performs no clock read or formatting.

`worker_module_health` owns one immutable row for every module context on the
worker and linearly claims the context's existing exact-NUMA telemetry block.
The due-context path verifies `active_epoch == source_epoch` and the exact
store view, acquires one ordinary worker-ledger credit, invokes the pre-resolved
callback, publishes the completed result, then retires the credit last. Source
advancement suppresses new old-epoch health. A live claim blocks local
activation and ordinary teardown; no separate health quiescence counter exists.

The signal's epoch and timestamp come from the exact active epoch and original
cached turn time. Command/source admission and prior telemetry returns execute
before the turn refresh; one already-scheduled context then runs immediately
after that refresh and immediately before its bank service. Only after a real
callback returns, the owner takes one additional sample from the same platform
monotonic authority. Their difference is the callback duration, and the second
sample may timestamp that context's completed bank. It never replaces the
turn's cached packet/callback time. Null, suppressed, non-due, and module-free
turns perform no extra read. Release qualification inspects and traces every
authorized worker clock class: the ordinary turn refresh, the health-return
sample, and the four transition-edge samples. A syscall-backed worker sample or
an unacceptable measured regression fails the target tuple.

The owner validates score `0..100`, known flags, bounded NUL termination, and
duration together. A fresh zeroed `kinetum_health_signal` copies no module
padding or reason tail. Any malformed or over-budget attempt suppresses the
signal, saturating-increments one context-local fault count, and preserves one
immutable first-fault mask/epoch/time/duration. It does not log, format, drop,
reroute, fail stop, or trigger rollback. One coherent latest-value snapshot is
the only foreign-reader surface. The cold aggregator emits one context row,
accepts a signal only at the coherent runtime-status active epoch, and leaves
missing, null, torn, or stale observations unavailable rather than fabricating
health. A selected `GetStats.telemetry.module_health[]` maps every exact context to typed
callback-unavailable, awaiting, signal-available, attempt-suppressed, or stale
state; only signal-available carries score, flags, and reason.

#### Teardown

Manager destruction is legal only after packet workers and lifecycle executors
have joined. Before FINI, every PREPARED token must be discarded and retired,
every RETAINED slot must complete exact retirement, and the final PUBLISHED
slot must be withdrawn after owner quiescence and retired. A nonempty store at
destruction is a process-fatal ownership violation. Contexts then receive FINI
in reverse context-index order. Each image is
unloaded only after every context backed by that image has finalized and every
image-serialization claim has ended. The descriptor and dynamic-loader handle
remain stable for the entire admitted generation; closing the image handles
releases their loader ownership. Failure to close an exact image is a violated
ownership invariant and terminates the process. Successful teardown releases
all owned loader handles; it does not prove that the loader unmapped the code.
The in-tree dependency closure must obey the same ownership lifetime.

Exact prepared artifacts and tagged executable views are the sole module
configuration authority. Snapshot storage remains a separate DP mechanism
described in [Section 6](#6-exact-snapshot-epoch-store); it cannot select a module
configuration.

### 15. Stats Collection

The packet runtime publishes one coherent generation-scoped source from
immutable owner-completed banks, context health snapshots, exact transition
publications, compiled topology, and cold provider observations. The shared
`kinetum.telemetry.v1.RuntimeTelemetry` message is the sole wire payload for
both DP and CP statistics. A successful response is structurally complete for
the request; no service owns a field-by-field duplicate schema or mapper.

- **Component engine counters:** `dp_engine` owns plain RX, TX, and rejected
  counters under one serialized component-test caller. It publishes no live
  cross-thread source and is not production worker accounting.
- **Worker I/O and stage banks:** each `packet_worker_kernel` updates one
  pre-resolved stream row per burst using plain owner-local operations. RX
  counts the records and bytes admitted from a provider; TX counts only the
  provider-accepted prefix, using lengths saved before ownership transfer.
  RX `rejected_packets` counts input consumed and discarded before admission;
  TX `rejected_packets` counts the unaccepted suffix actually retired by core.
  Rejected-only RX is work without a record or epoch-credit transfer. Engine
  RX/TX totals are cold sums of these stream rows, with no duplicate packet-path
  accumulator. Terminal release counts one engine drop; stage input/output/drop
  follows the exact ownership-transfer sites, including fan-out, active origins,
  retained resolution, async restoration, and recirculation. Logical-stage
  aggregation is cold only. TX acceptance is not wire delivery: UDP can retain an accepted
  record in its deferred queue and reclaim it unsent at shutdown. Sending,
  flushing, or reclaiming that record does not count another transfer.
  Hardware misses/errors remain native port observations.
- **Module banks:** INIT admits counters and histograms independently up to 64
  and 16, with names unique across both kinds. Counter/gauge values are absolute.
  Histograms are interval banks backed by one transactional three-bank bucket
  allocation charged to the context's authored memory ceiling. Exact epoch
  mismatch count and sticky first-fault identity enter the same immutable bank
  from their sole owner write site.
- **Module health snapshots:** each module context owns one disjoint plain fault
  line and one typed `single_writer_snapshot` in the same exact-NUMA telemetry
  allocation. A cadence schedules rows for following turns; each selected row
  invokes health immediately after the turn refresh and before its bank service.
  The cold aggregator reads only this coherent snapshot
  and emits one identity row even when the callback or current signal is
  unavailable; health is latest-value state, never an interval bank.
- **Three-bank publication:** every worker and module context has active,
  ordinary-standby, and activation-reserve banks. Ordinary cadence publishes
  only with a clean standby and completed-ring capacity; otherwise it
  saturating-increments skipped publication and continues without waiting or
  borrowing the reserve. Activation publishes final E truth, retains the clean
  E companion, and switches to the pre-reserved N bank before the remaining
  module/queue/ledger/scheduler activation order. Shutdown stops ordinary
  cadence first and cannot exit while a same-epoch return is unresolved. One
  due worker cadence starts a bounded module-context sweep; at most one context
  publishes per following turn, one overlap coalesces, and further overlap is
  a visible skip rather than unbounded work debt.
  The serialized generation owner carries one explicit free-slot identity for
  each bank set; PREPARE never searches bank state concurrently with cadence.
  Bootstrap, activation, and shutdown prove the complete worker-plus-context
  token prefix fits the shared channel before their first publication.
- **Cold aggregation and lifetime:** one `worker_telemetry_channel` per worker
  places the completed ring on coordinator NUMA and the return ring on worker
  NUMA. Fixed tokens bind runtime, worker, owner, stage, epoch, bank generation,
  slot, reason, and any clean retained companion. The sole cold
  `runtime_telemetry_aggregator` validates and merges each bank once, returns
  cleared ordinary banks, and publishes through
  `runtime_telemetry_source_owner`. Return retention is acknowledged through
  the same SPSC ownership path. Each physical bank retains the complete issued
  token while publication or return ownership is live, so no consumer can
  reconstruct or alter reason, companion, timestamp, or owner identity from
  partial bank metadata. The coordinator never reads a live owner line.
  Incremental histogram inputs are pre-resolved before workers launch. The cold
  owner merges and clears one 64-bucket prefix at a time, proves each interval's
  bucket mass equals its summary count, and keeps a module bank unavailable to
  readers and ineligible for return until every prefix and absolute row commits
  together. Retained epoch is tracked per
  physical bank, so two old E banks and one final N bank coexist exactly during
  RETIRING shutdown.
  Stream rows retain their own worker's last publication timestamp and
  cumulative values across configuration epochs. They are available only after
  a complete initial owner-bank baseline. Exhausted stream counters or engine
  transfer sums produce `DATA_LOSS`; bank return and retirement still complete.
  Final E banks must be aggregated before the first retirement claim. Their
  storage remains retained through the existing certificate and reader grace,
  and is reclaimed by that exact retirement path. Telemetry authorizes no CUT,
  ACK, activation, certificate, grace, or phase decision.
- **Boundary channels:** `boundary_epoch_channel` owns successful DATA
  sequences, plain sender backpressure, capacity-2 typed CUT/ACK transport,
  bounded pending control, and separate coherent endpoint snapshots. The
  physical endpoint slots live in exact worker-local slabs, but only the
  channel can mutate or publish their transport state. Separate worker-owned
  policy lines and publications retain the policy named below. Fixed Bootstrap
  leaves every control lane and pending record empty. The immutable certificate
  graph is their sole correctness consumer and the telemetry source reuses that
  same frozen membership rather than constructing another boundary graph.
- **Boundary sender policy:** `worker_boundary_sender` owns plain exact
  generation/from/to/cut/duplicate-ACK state in the sender slab plus bounded
  future-hold ownership. Fixed Bootstrap exercises only OPEN. Every real
  DRAINING/CUT-owned/ACK-observed/gate-open transition edge publishes one
  coherent proof. The telemetry source reads that publication through the
  immutable certificate graph; it never reads the mutable policy line.
- **Boundary receiver policy:** `worker_boundary_receiver` owns plain active-
  epoch/CUT/duplicate/phase state in the receiver slab. The exact ACK
  channel-ownership edge and each preceding CUT-observed/drained/activation
  edge publish coherent proofs. The telemetry source reads those publications
  through the immutable certificate graph; the mutable line remains
  owner-private. Fixed Bootstrap exercises only OPEN.

`runtime_telemetry_snapshot_source` starts from immutable compiled identity and
may never replace generic identity with a native lcore, physical port number,
pool scope, or provider-native stream index. One
`runtime_telemetry_source_owner` serializes generation claims. Collection
captures runtime and transition publications before work, copies the cold bank
aggregate, observes selected worker/boundary/topology rows, invokes selected
provider callbacks with no platform lock held, and then rechecks runtime,
transition, completion, and first-fault generations. An activation crossing,
torn publication, incomplete bank merge, activation-leading-ledger worker edge,
or temporarily misaligned endpoint snapshot returns `UNAVAILABLE`; a coherent
identity contradiction or malformed producer result returns `DATA_LOSS`.
Each domain reader distinguishes unavailable publication from invalid contents.
The collection inspects every selected source: invalid evidence wins over
unavailability regardless of read order. Coordinator-relative comparisons use
matching opening and closing authority, while legal publication lag remains
unavailable even when the coordinator generation is unchanged. Intrinsic
invalidity is never downgraded by movement elsewhere.
Completion evidence belongs only to the active or latest terminal transaction;
an older retired proof is no longer part of that projection. Every available
completion record is validated before that selection. Failure before completion
is armed creates no new certificate or grace evidence.

`dataplane_control_service::GetStats` clears first, validates the shared
selection, collects once, maps once, validates the complete result again, and
publishes canonical application success last. An ordinary application failure
leaves a status-only response; failure to construct that final representation
returns transport `UNAVAILABLE` and makes the response body non-authoritative.
Client cancellation or timeout does not retire an accepted collection claim.
The callback and its dependencies remain owned until return; source retirement
fences new and waiting readers, waits for the active claim, then destroys outside
the ownership mutex.
CP repeats shared payload validation, fences its active configuration
before and after the DP call, verifies exact snapshot/revision/epoch,
active-validation-hash, plan-hash, and the lawful allocation-watermark
relation, and copies the shared telemetry message without reconstructing its
fields. The compact CP fence carries hashes and bounded identity rather
than copying complete snapshot blobs at policy cadence. During RETIRING,
coordinator active epoch and
active hash remain the last globally COMPLETE E pair even though participant
runtime status is N/E/N. Exact watermarks are normal; only durable ALLOCATED,
pre-admission ABORT_PENDING, or its terminal ABORTED result may lead an idle
surviving DP by one pair because CP persists allocation before Prepare.
`kinetumctl` validates the successful CP wrapper before either protobuf
text or JSON formatting. A failed observation therefore cannot become a
zero-valued report at any layer.

The observation shape carries each steering profile and each module's canonical
context population; both declared `buffer_count` and the compiler's
`required_min_buffers` floor for each storage domain; and exact
`io_driver_instance_id` plus `driver_port_id` for each logical port. A DPDK
source reads ethdev counters and approximate concurrent mempool occupancy, but
only their generic projections may cross the telemetry boundary. PMD-specific
storage samples still partition the compiled buffer count exactly; approximate
means the complete sample may become stale immediately after callback return.
PMD-specific xstats do not cross the generic observation contract. Provider
state is one of `AVAILABLE_EXACT`,
`AVAILABLE_APPROXIMATE`, `UNSUPPORTED`, or `READ_FAILED`. Only the two
available states carry a complete counter tuple and platform post-callback
monotonic timestamp; the other states carry no numeric values.

Ordered-transition timing is sampled only at four rare endpoint edge classes:
before sender CUT publication, after the receiver's complete same-turn CUT/data
drain service, before receiver ACK publication, and after sender ACK
consumption. Each class takes one sample for the complete endpoint batch, never
one per boundary. The receiver batch can stamp CUT observation and immediate
drain from one sample; a later turn takes one new receiver-batch sample only
when the sequence cut first drains. Ordinary turns and packets gain no clock
read.

Protocol first-fault state is correctness authority, not telemetry policy. A
rare fault records one fixed numeric identity through a write-once CAS and
sets a sticky transition-success latch for every safety fault except allocator
exhaustion. Immediate dispositions are exactly `DROP_AND_RETIRE` for a safely
rejected module epoch mismatch, `TERMINATE` for structural protocol faults,
and `RESOURCE_REFUSED` for allocator exhaustion. Telemetry observes the latch,
the immutable first record, and cumulative typed counters; it does not create
or clear them. Completion acquire-checks the latch before commit, at every
certificate probe, before ownership withdrawal and result consumption, and at
the final success linearization point. A fault observed before that last check
therefore cannot race old-object retirement into `COMPLETE`; a later fault is
sticky for the next admission.

### 16. Provider Observation Lifetime

The runtime telemetry source invokes selected storage and port callbacks under
a claim on the admitted generation. No platform lock is held across the native
callback. Returned rows must match the compiled identities and requested
membership before they enter a successful snapshot.

Shutdown stops new observations and waits for existing claims before destroying
the source and provider instances. The source never lends native pointers
to RPC callers. These are cold observations; they do not create packet-path
watermark or link-state gates.

[Provider observations](PROVIDERS.md#8-diagnostics-and-observations) define the
callback rows and availability states. [DPDK](PROVIDERS.md#13-dpdk) describes
native pool sampling and device-readiness checks.

## Part 4: gRPC and Lifecycle

### 17. gRPC Service (DataplaneService)

`kinetum.dataplane.v1.DataplaneService` listens at `--listen` (default
`0.0.0.0:50052`). Its mutation surface is the **internal CP-to-DP backchannel**;
operators use `kinetum.control.v1.ControlService`. The read-only `Health` RPC is
also available through `kinetumctl health --service dp`. See
[`GRPC_API.md`](GRPC_API.md) for the wire contract.

Production registers one `dataplane_control_service` that borrows the complete
`partitioned_runtime`. The runtime outlives the service and remains the sole
owner of compiled topology, provider/module instances, snapshot stores,
workers, fixed boundaries, kernels, and immutable status. The adapter clears
each response before mapping a result and never owns a competing readiness or
epoch field.

Concurrent producers publish fixed records to one plan-sized MPMC mailbox.
Successful enqueue linearly borrows the stack completion context, and the
producer has only one unconditional wait operation; deadlines and cancellation
cannot abandon it. The runtime-service-bound main/coordinator thread is the sole
consumer and executes module/provider/worker callbacks without the mailbox
submission gate held. Signal-driven shutdown closes admission, completes every
accepted but unstarted context `UNAVAILABLE`, initiates bounded gRPC shutdown,
cancels and drains held pre-commit Prepare/Abort contexts through exact
lifecycle cleanup, and applies state-specific completion/fail-stop rules to a
held Activate before retiring the runtime and waiting for handler exit. Only
that coordinator thread may call `shutdown()`; a foreign-thread
teardown attempt is terminate-class.

**RPCs and implementation status:**

| RPC | Production behavior |
| --- | --- |
| `BootstrapConfigSnapshot` | Transport `OK`; exact runtime result in application status. A successful first bootstrap returns restored epoch/hash/high-watermarks and `COMPLETE`, after publishing `PACKET_READY`. Pre-commit failures publish no partial success; a different retry rejects; every call after `PACKET_READY` returns application `UNAVAILABLE`. |
| Prepare/Activate/Abort/Status | Transport `OK` with canonical application status plus explicit identity-resolution and failure-code enums. Prepare returns PREPARED identity/lease only after complete cold staging. Activate commits one exact PREPARED transaction and its first caller waits through COMPLETE or update-frozen RETIRING; exact retries never retrigger workers. Abort can mutate only PREPARING/PREPARED. Status returns exact identity, plan hash, produced durations, and bounded diagnostic only for active/terminal truth. |
| `GetStats` | Transport `OK` plus either canonical application success and one complete selected `RuntimeTelemetry`, or a status-only failure. Mandatory runtime/engine/transition/protocol-fault summaries are always present on success; optional row families are selected explicitly. See [Section 15](#15-stats-collection). |
| `Health` | Reads readiness from the immutable runtime-status publication and adds independent logging observations. Reports application success with exact `STATE_CONTROL_READY` or `STATE_PACKET_READY`, last activated epoch, and active/expected workers. An unavailable read reports `STATE_ERROR` plus `UNAVAILABLE`; invalid published contents report `STATE_ERROR` plus `DATA_LOSS`. |
| `Drain`, `DrainStatus`, `Shutdown`, `DumpState` | Transport `OK` plus application `UNAVAILABLE`; responses are cleared and carry no synthetic lifecycle, packet, NAT, or ACL state. |

The table describes responses that can be represented. Allocation or
representation-size failure while constructing any final response returns
transport `UNAVAILABLE`, and the response body is not authoritative. Unexpected
exceptions at the server boundary are process-fatal.

Implemented handlers use the dual-status pattern documented in
[`GRPC_API.md`](GRPC_API.md) Section 3: transport status reports RPC dispatch,
while application status is carried in the response. A null request or response
in a direct invocation is transport `INVALID_ARGUMENT`; supported dispatch with
an unavailable capability is transport `OK` plus explicit application status.

### 18. Authentication and TLS

The DP exposes four TLS flags via `dp_main.cpp`:

| Flag                          | Meaning                                                                  |
| ----------------------------- | ------------------------------------------------------------------------ |
| `--tls-cert <pem>`            | Server certificate chain (PEM).                                          |
| `--tls-key <pem>`             | Server private key (PEM).                                                |
| `--tls-ca <pem>`              | Client CA certificate (PEM). Used for mTLS verification.                 |
| `--tls-require-client-auth`   | Enforce mTLS: reject clients that do not present a verified certificate. |

If any of the four flags is set, `tls_enabled = true` and the gRPC
listening port is built with
`make_server_credentials(tls_cfg)`. If none of the flags is set, the
listening port is built with `grpc::InsecureServerCredentials()`.

TLS credential construction is fail-closed. If any DP TLS flag is
provided, the certificate and key must be readable and nonempty; if
`--tls-require-client-auth` is provided, `--tls-ca` must also be
readable and nonempty. `make_server_credentials()` returns `nullptr` on invalid TLS
configuration, certificate validity or key-strength failure, or a self-signed
leaf certificate, and `dp_main` exits before binding the gRPC service. Root CA
material may be self-signed; gRPC owns peer-hostname verification. For
DP process flags, this section is the authority; [`GRPC_API.md`](GRPC_API.md)
documents the wire-level RPC contract.

For the DP, mTLS configuration on the server side requires all of
`--tls-cert`, `--tls-key`, `--tls-ca`, and `--tls-require-client-auth`.
Without `--tls-ca`, client certificates cannot be verified.

### 19. Drain and Shutdown Protocol

Runtime shutdown is process-owned and signal-driven. Before any runtime,
provider, logging, gRPC, lifecycle, or packet thread exists, `dp_main` blocks SIGINT,
SIGTERM, and SIGUSR1 and creates a nonblocking `signalfd`. Every subsequently created thread
inherits that mask. After the service is running, the main/coordinator
thread blocks in `poll()` over that descriptor, the command and lifecycle
`eventfd` sources, and the current transition deadline; a selected signal
therefore cannot asynchronously interrupt a provider or packet owner.

SIGUSR1 requests checked log reopen without entering runtime teardown. A due
transition deadline retains priority, and reopen cannot starve ready command or
lifecycle work. On SIGINT or SIGTERM, `dp_main` first closes command admission and
completes every queued but unstarted producer with application `UNAVAILABLE`.
Previously accepted Prepare/Abort/Activate contexts may still be held across
coordinator turns. DP initiates gRPC shutdown with an immediate deadline, then
resolves those owners through runtime shutdown before `server->Wait()` joins
handlers. State-specific ownership precedes ordinary teardown:

- PREPARING or PREPARED cancels, collects, and retires every partial artifact,
  journals ABORTED, and disarms completion.
- COMMITTING records typed fail-stop and terminates without ordinary
  retirement because execution/boundary ownership is incomplete.
- RETIRING first closes and joins workers and deactivates packet I/O. It may
  finish exact reader/callback/claim reclamation only while every identity
  remains provable; frozen or uncertain ownership terminates without FINI or
  dependency retirement beneath it.

For AWAITING_BOOTSTRAP or clean IDLE, and after a provably completed RETIRING
transaction, the generation's one owner-thread-idempotent reverse teardown is:

1. release-publish worker source-poll closure and request every packet worker
   to exit;
2. let each worker cease RX polling, drain local work and every inbound DATA
   boundary, wait for inbound producer closure, close its outbound producers,
   and perform final TX flush;
3. join the exact launched worker set;
4. invoke mandatory whole-driver deactivation in reverse materialized order;
5. retire the published module generation artifacts and exact snapshot claim;
6. stop and join lifecycle services;
7. destroy kernels, boundary views and rings, and worker state;
8. finalize module contexts and unload module images;
9. destroy cold provider instances and facilities in reverse dependency order;
   and
10. release the admitted provider catalog and component handles last.

After runtime and gRPC emitters retire, the process closes native diagnostic
capture, drains accepted logging records, and joins the file writer. Logging
loss cannot change runtime teardown ordering. See [Logging](LOGGING.md) for the
two-second final drain and explicit unavailable/reopen behavior.

Any disagreement after irreversible activation or an unprovable native
retirement fails stop rather than unwinding through live foreign ownership.
DPDK is never rematerialized in the same process. Photon supervises DP and CP
as one pair: a CP bootstrap failure terminates the pair and exits with failure;
any later supervised start creates a fresh DP generation rather than retrying
CP against an already `PACKET_READY` process.

The stable Drain, DrainStatus, Shutdown, and DumpState RPCs are not a second
teardown authority. Each returns transport `OK` plus
application `UNAVAILABLE`, publishes no synthetic timestamps or zero-packet
claim, and mutates no service-local lifecycle state. A coordinated operator
drain must compose the generation owner above; an independent service state
machine is not part of the runtime.

## Part 5: Cross-Cutting

### 20. Source-Tree Integration Surfaces

The DP exposes narrow repository-internal mechanisms for in-tree hosts and
tests. Except for explicitly named algorithm/SDK types under
`include/kinetum/`, these `src/dp/` surfaces are not installed APIs. They do
not expose a provider-specific constructor or a sequence of native `start_*`
methods. Packet-runtime creation has one factory boundary. It publishes one
complete admitted generation or returns no object after provable rollback;
uncertainty after an irreversible native effect is fail-stop.

| Type / function | Use |
|---|---|
| `config_snapshot_epoch_store` | Coordinator-owned canonical snapshot slots: stage, publish, exact lookup, and claimed retirement. |
| `frozen_transition_participants` | Immutable, bidirectionally validated membership projected once from compiled topology and retained by identity. |
| `epoch_transition_command_mailbox` | Plan-sized MPMC queue of borrowed command contexts; one wake-only eventfd and unconditional producer completion. Destroying an unresolved context terminates. |
| `epoch_transition_coordinator` | Sole transition phase, snapshot, Bootstrap retry, allocator watermark, transaction identity, lease, terminal-journal, and progress owner. |
| `epoch_transition_preparation` | Candidate controls/arenas, image/executor dispatch, result collection, reverse partial retirement, cancellation grace, and lease timer. No packet commit or independent phase. |
| `epoch_transition_completion` | Preallocated COMMITTING/RETIRING owner of certificate, reader grace, retirement claims, deadlines, and final status. COMPLETE requires all old slots empty. |
| `worker_runtime_command_publication` | One release/acquire pointer to RUN, alternating TRANSITION, or STOP. COMPLETE gates record reuse; STOP remains visible throughout drain. |
| `worker_epoch_ledger` | Owner-local active/future work credits, including foreign tokens and completion handoff, with one coherent publication per turn. It cannot alone prove quiescence. |
| `worker_boundary_sender` | Outbound DATA, CUT/ACK validation, future-hold ordering, and credit ownership; private state stays on sender NUMA. |
| `worker_boundary_receiver` | Inbound CUT identity, sequence-derived drain, local activation, and ACK publication. |
| `worker_active_stage_scheduler` | Owner-local active contexts, slab, retained/timer/control/PULL work, origin storage, drain, and ledger integration. |
| `worker_async_work` | Token slots, MPMC completion, cancellation, callback claims, and stale/reuse rejection. Foreign threads may complete or query cancellation only. |
| `worker_epoch_activation` | Nonmutating preflight, module activation, queue-role rotation, ledger promotion, scheduler epoch, and completed-activation publication. |
| `kinetum::algo::quiescence_domain` | Reader-grace generation and exact reader publication over caller-owned cache-line records; no epoch or reclamation policy. |
| `epoch_transition_certificate` | Pure O(V+E) evaluation of frozen membership and coherent publications; no grace, phase, timeout, or reclamation mutation. |
| `dp_engine` | Generic stages and exact module execution with admitted context stores and owner scratch. Missing module authority rejects. |
| `packet_runtime_generation_input::create(...)` | Adopts the canonical plan, its compiled topology, matching command mailbox, admitted provider catalog, verified module images, and nonzero generation identity as one complete input. |
| `partitioned_runtime::create(input)` | Transactionally returns one `CONTROL_READY` runtime or no object after rollback. Uncertainty after irreversible effects fails stop. |
| `partitioned_runtime::try_read_transition_progress(out)` | Bounded read of coherent coordinator progress; no mutable store or transition authority. |
| `partitioned_runtime::try_read_worker_epoch_ownership(index, out)` | Bounded read of a worker ledger publication; no owner-local reference or capacity/activation/retirement authority. |
| `partitioned_runtime::collect_runtime_telemetry(request)` | Generation-claimed, all-or-none observation consumed by GetStats; see Section 15. |
| `partitioned_runtime::{prepare,activate,abort,query}_epoch_transition(...)` | Exact command submission. Successful enqueue waits unconditionally; the first Activate spans completion or update freeze. |
| `runtime_status_publication` | Readiness and worker counts with epoch triples E/E/E at Bootstrap, N/E/N at activation, and N/N/N after retirement. Health reads this publication. |
| `worker_telemetry_channel` | Completed/return bank tokens only. Ring memory lives with each poller: coordinator for completion, worker for returns. |
| `worker_runtime_telemetry` | Exact-NUMA three-bank stream/stage counters and drop/fan-out totals, with owner-local updates and explicit publication/return/retirement states. |
| `runtime_telemetry_aggregator` | Sole cold bank consumer: validates tokens, merges interval/absolute forms once, tracks retirement, and returns cleared storage. |
| `runtime_telemetry_snapshot_source` | Composes aggregate, runtime, transition, fault, topology, and provider observations after fencing their identities. |
| `runtime_telemetry_request` | Selects row sets for one cold coherent observation. |
| `runtime_telemetry_source` | Coherent generation snapshot and active/expected worker counts; must outlive borrowing services. |
| `dataplane_control_service(runtime)` | gRPC adapter for Bootstrap, live transitions, Health, and telemetry. Drain, DrainStatus, Shutdown, and DumpState return UNAVAILABLE. |

The packet-runtime factory owns provider selection through plan truth. An
embedder cannot pass a provider enum, native EAL argument list, UDP endpoint
override, component path, or fallback order. It also cannot construct only a
pool, port, or worker prefix and publish it as a runtime. Those resources
remain inside the all-or-none materialization transaction.

Observability types in `runtime_telemetry.hpp` deliberately contain only
compiled provider-neutral identities:

| Type | What it carries |
|---|---|
| `runtime_telemetry_snapshot` | One coherent generation observation containing engine, stage, registered module, mismatch, health, cadence, and any requested rows whose exact producers are complete. |
| `runtime_engine_statistics` | Cumulative ingress and accepted-TX packet/byte totals derived from stream rows, plus worker terminal-retirement and fan-out-overflow counters. |
| `runtime_stage_statistics` | Exact stage identity and packet/byte counters with current producers. |
| `runtime_module_counter_statistics` | Latest absolute counter/gauge value for one exact module context and epoch. |
| `runtime_module_histogram_statistics` | Cold merged interval distribution for one exact module context and epoch. |
| `runtime_module_epoch_mismatch_statistics` | Latest cumulative exact-epoch mismatch count and sticky first-fault identity from one context's coherent bank. |
| `runtime_module_health_statistics` | One exact context identity, callback/signal availability, current or stale attempt epoch/time, bounded callback duration, fault evidence, and a current coherent signal only when its epoch equals runtime-status active truth. |
| `runtime_worker_epoch_statistics` | Exact worker identity plus coherent ledger and completed-activation publications. |
| `runtime_region_epoch_statistics` | Cold derivation of worker epoch ranges, credits, activation range, and the sole `fanout_overflow` subtype. |
| `runtime_boundary_epoch_statistics` | Exact compiled boundary identity/capacity plus coherent DATA sequences, pending control, sender/receiver phases, CUT/ACK identity, duplicate counts, and presence-qualified edge timing. |
| `runtime_io_stream_statistics` | Exact stream/logical-port/driver-queue identity, compact worker ownership, owner-bank publication time, and cumulative software packet/byte/rejection counters. |
| `runtime_storage_domain_statistics` | Exact storage-domain/NUMA identity, declared capacity, shared-compiler floor, safety margin, typed availability, and complete optional occupancy tuple. |
| `runtime_io_port_statistics` | Exact logical port, I/O-driver instance, driver-local port, typed availability, and complete optional native counter tuple. |
| `runtime_traffic_steering_statistics` | Exact admitted steering profile, mechanism, symmetry, and stable stream membership. |
| `runtime_module_context_domain` | Exact module identity and canonical context membership defining fixed ordinals. |
| `engine_stats` | Plain component-test counters exposed by `dp_engine::stats()` under one serialized caller; not a live runtime source. |

Tests can exercise RPC behavior without opening a listening socket by
constructing a complete fixture runtime and `dataplane_control_service`, then
calling handlers with `grpc::ServerContext` stubs. Provider mechanism tests may
substitute exact operation tables inside their owned compile domain, but they
do not get a second packet representation, partial runtime constructor, or
provider-selection bypass.

### 21. Determinism

**Deterministic within a region:**

- Stage execution order per packet (`stages_` compact-index lookup on one
  owner worker).
- Epoch admission at every RX, boundary, and module seam (exact equality with
  the worker's current source or active epoch, as required by that seam).
- 3-tier dispatch resolution per packet (Tier 1 wins over Tier 2 wins
  over Tier 3; first conditional edge match wins; first successor takes
  the original record).
- Owner-local worker/module counters change in the same deterministic ownership
  order as packet outcomes; immutable bank merge is exact once per token.

**Non-deterministic across regions and across iterations:**

- Cross-region timing: busy-poll cadence, bounded DATA backpressure, and the
  order in which independent workers process available input vary.
- Boundary order between regions: fan-in DATA can arrive in any inter-worker
  timing consistent with each SPSC channel's order. Every record still carries
  one immutable exact epoch, and execution admits it only at that same epoch;
  a live cut may therefore have old and target records in different owned tiers
  without permitting mixed-epoch execution.
- Timing: worker scheduling, provider completion, cached monotonic packet
  timestamps, bank collection time, and skipped cadence publications vary
  between runs. `GetStats` publishes their exact observed values and provenance;
  it does not make those values deterministic across runs.

For one fixed complete execution trace, including packet order, module state,
foreign completion order, and transition-command interleaving, stage and route
selection follow deterministic rules. The platform does not claim that
independently scheduled workers reproduce the same global packet order or that
stateful policy produces byte-identical outcomes under a different order. Its
cross-schedule safety guarantee is narrower and stronger: every admitted
execution uses the packet's one exact epoch, and reclamation cannot overtake
the certified old-work and reader-grace boundary.

### 22. CP vs DP vs Quark vs Photon Responsibilities

| Concern                                                             | Owner                                                  |
| ------------------------------------------------------------------- | ------------------------------------------------------ |
| Pipeline authoring + structural validation                          | Axiom (see [`AXIOM.md`](AXIOM.md))                     |
| Region partitioning, complete deployment-binding lowering, worker/service NUMA core selection, canonical plan generation | Gluon (see [`GLUON.md`](GLUON.md)) |
| Provider contract meaning and canonical typed configuration | Pure immutable provider contract catalog |
| Canonical provider-aware plan identity | Deployment-plan identity authority consumed by Gluon, pack, bundle verification, Photon, and DP |
| Exact provider/facility/port/queue/storage/execution/transition closure | One shared provider-topology compiler consumed by Gluon, runtime-bundle verification, and DP; DP passes the same artifact to Quark |
| Host CPU/NUMA and compiled external-requirement evidence | Quark consumes the immutable compiled artifact without filtering, repair, provider inference, or a second plan walk (see [`QUARK.md`](QUARK.md)) |
| Runtime-bundle semantic admission (manifest, canonical paths, plan identity, bootstrap snapshot) | Photon before child-process construction (delegates to `kinetum::pack::verify_runtime_bundle`) |
| Spawning DP and CP plus pair supervision                            | Photon (see [`PHOTON.md`](PHOTON.md))                  |
| Signed installed-provider inventory and exact component admission | Native release preparation self-admits exact target artifacts; architecture-neutral finalization independently reconstructs and signs the canonical inventory; DP derives its fixed installed root and admits only the compiled required exact set before `CONTROL_READY` |
| Native facility/device/queue/storage reservations and capability results | DP transactional materializer through exact provider factories |
| DPDK EAL arguments, main-lcore role, devices, memory, and NUMA | DPDK facility implementation renders them from compiled generic facts; no CLI or duplicate plan authority |
| Mandatory runtime-bundle admission                                  | Shared `verify_runtime_bundle`; Photon verifies before spawn and DP independently re-admits the exact `--bundle` root. No direct-plan or optional-manifest path exists. |
| Complete ConfigSnapshot lifecycle for fixed bootstrap               | DP `epoch_transition_coordinator`, composing `config_snapshot_epoch_store` and consumed by the one fixed-bootstrap transaction and reverse teardown |
| Snapshot persistence (durable, audit history)                       | CP (`config_store`, see [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md)) |
| Exact snapshot lifecycle (prepared/published/retained ownership)    | DP cold coordinator store; workers consume pre-resolved module views, never the store itself |
| Mutation serialization and revision/policy CAS                      | CP (`control_loop`); exact retry truth is durable in `config_store`, never a volatile cache |
| Exact fixed-bootstrap request and application result | CP durably authors and sends it; DP validates, activates, and publishes one fixed epoch. |
| Live configuration transitions | DP coordinator and worker owners execute the transition, certify completion, and retire after reader grace. The gRPC service maps their typed observations. |
| Fixed Bootstrap, allocator watermarks, current/latest transition, pending Confirm, guardrails policy, and rollback-intent authority | CP `config_store` owns one atomically replaced private envelope; DP validates and coherently publishes the nested Bootstrap epoch/watermarks/content hash |
| Live epoch/mutation allocation and pending-transition reconciliation | CP durably allocates both values, persists PREPARED/COMPLETION_PENDING before their irreversible edges, and classifies only typed DP identity/state/failure |
| Exact executable boundary declarations                              | Gluon (`boundary_topology_lowering.cpp`)                    |
| Boundary protocol materialization and execution                     | DP compiled provider topology, transactional worker-local endpoint slabs plus channel materialization, and owner-worker kernels |
| Boundary telemetry collection                                       | DP final snapshot source over the immutable certificate graph and exact endpoint publications; exposed only inside a successful all-or-none shared telemetry response |
| Boundary ACK-stall observation and rollback-intent submission      | CP guardrails evaluator consumes exact generation-local boundary rows and persists one desired action before the existing transition authority executes it |
| Atomic module image/context admission and cold lifecycle serialization | DP (`module_manager` + `module_lifecycle_adapter`)  |
| Exact module packet-view installation and owner activation              | DP packet owner after complete compiled-topology and exact module-generation proof |
| Runtime readiness publication                                            | DP bootstrap owner publishes one immutable generation snapshot; Health consumes only that snapshot |
| Module health publication                                                | DP packet owner publishes one context-scoped coherent signal/fault row; the cold source maps typed current/stale/suppressed/unavailable state without invoking module code |
| Module SDK contract (exact descriptor, lifecycle shell, live context, batch layout) | SDK (see [`MODULE_SDK.md`](MODULE_SDK.md))         |
| Provider artifact provenance and exact ABI admission                     | Signed installed inventory + shared held-descriptor admission |
| Requested implementation availability                                   | Sealed runtime provider catalog containing exactly the compiled required contract set |
| TLS configuration                                                   | Each binary owns its own flags (CP, DP, kinetumctl)    |

### 23. Where to Go Next

| If you want to...                                                | Read                                                       |
| ---------------------------------------------------------------- | ---------------------------------------------------------- |
| See the DP host process and threading visually                   | [`diagrams/platform_architecture.md` Section 11 (Data-Plane Host)](diagrams/platform_architecture.md#11-data-plane-host) |
| See the runtime worker loop visually                              | [`diagrams/platform_architecture.md` Section 12 (Worker Hot Path)](diagrams/platform_architecture.md#12-worker-hot-path) |
| See a single packet's lifecycle                                  | [`diagrams/platform_architecture.md` Section 13 (Packet Lifecycle)](diagrams/platform_architecture.md#13-packet-lifecycle) |
| Inspect the current boundary transport                           | [Section 12 (Cross-Region Boundary Integration)](#12-cross-region-boundary-integration) |
| Understand the ordered-CUT proof and alternatives                | [`diagrams/ordered_cut_boundary_protocol.md`](diagrams/ordered_cut_boundary_protocol.md) |
| See the exact transition RPC boundary                            | [`diagrams/platform_architecture.md` Section 7 (Transition RPC Boundary)](diagrams/platform_architecture.md#7-transition-rpc-boundary) |
| See exact DP snapshot lifecycle and CP reader publication        | [`diagrams/platform_architecture.md` Section 8 (Configuration Publication)](diagrams/platform_architecture.md#8-configuration-publication) |
| Author or maintain a module                                      | [`MODULE_SDK.md`](MODULE_SDK.md)                           |
| Use the proto contract from a custom client                      | [`GRPC_API.md`](GRPC_API.md)                               |
| Plan a deployment                                                | [`GLUON.md`](GLUON.md)                                     |
| Author a pipeline                                                | [`AXIOM.md`](AXIOM.md)                                     |
| Understand the supervisor that launches DP                       | [`PHOTON.md`](PHOTON.md)                                   |
| Understand strict host evidence and compatibility                | [`QUARK.md`](QUARK.md)                                     |
| Understand the control plane and guardrails                      | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| Run the platform end-to-end                                      | [`GETTING_STARTED.md`](GETTING_STARTED.md)                 |
| Read the architectural overview                                  | [`CONCEPTS.md`](CONCEPTS.md)                               |
