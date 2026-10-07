# Platform Engineering Guide

Read this guide before changing the data plane, control plane, modules, planner,
or hot-path code in `include/kinetum/algo/`. Re-read it before introducing a
primitive, fallback, configuration surface, or optimization outside an existing
pattern.

**Principles** define rules that survive implementation changes. **Patterns**
define shared ownership, publication, synchronization, and release mechanisms.
The application matrix and delegation index point to their component references;
[`TECHNICAL_REFERENCES.md`](TECHNICAL_REFERENCES.md) collects normative
specifications and technical background.

---

## Table of Contents

**Part 1: Principles**

- [P-1: Mechanism vs Policy](#p-1-mechanism-vs-policy)
- [P-2: Code Is the Source of Truth](#p-2-code-is-the-source-of-truth)
- [P-3: Fail-Closed by Default](#p-3-fail-closed-by-default)
- [P-4: No Latent Fallback or Unowned Compatibility](#p-4-no-latent-fallback-or-unowned-compatibility)
- [P-5: Plan Is the Source of Truth for Runtime Wiring](#p-5-plan-is-the-source-of-truth-for-runtime-wiring)
- [P-6: Single-Writer Authority for Mutation Ordering](#p-6-single-writer-authority-for-mutation-ordering)
- [P-7: Platform Primitives Only](#p-7-platform-primitives-only)
- [P-8: Deterministic Boundary Semantics Over Best-Effort](#p-8-deterministic-boundary-semantics-over-best-effort)
- [P-9: Two-Phase Apply Over In-Place Mutation](#p-9-two-phase-apply-over-in-place-mutation)
- [P-10: Severity-Driven Defect Model](#p-10-severity-driven-defect-model)
- [P-11: Every Declared Surface Has an Owner](#p-11-every-declared-surface-has-an-owner)

**Part 2: Patterns**

- [Pat-1: No Hot-Path Allocation](#pat-1-no-hot-path-allocation)
- [Pat-2: No Hot-Path Locks](#pat-2-no-hot-path-locks)
- [Pat-3: No Hot-Path shared_ptr, Exceptions, Virtual, or RTTI](#pat-3-no-hot-path-shared_ptr-exceptions-virtual-or-rtti)
- [Pat-4: SoA Over AoS (Batch Model)](#pat-4-soa-over-aos-batch-model)
- [Pat-5: Cache-Line Alignment and False-Sharing Avoidance](#pat-5-cache-line-alignment-and-false-sharing-avoidance)
- [Pat-6: NUMA and Hugepages](#pat-6-numa-and-hugepages)
- [Pat-7: Context-Local State with Exact Generation Ownership](#pat-7-context-local-state-with-exact-generation-ownership)
- [Pat-8: RCU and versioned_rcu_buffer](#pat-8-rcu-and-versioned_rcu_buffer)
- [Pat-9: Aligned Atomics and Lock-Free Primitives](#pat-9-aligned-atomics-and-lock-free-primitives)
- [Pat-10: Epoch Sequencing and Ordered CUT/ACK Barrier](#pat-10-epoch-sequencing-and-ordered-cutack-barrier)
- [Pat-11: Bounded Queues and SPSC Rings](#pat-11-bounded-queues-and-spsc-rings)
- [Pat-12: Cuckoo Map for Hot-Path Hash Lookups](#pat-12-cuckoo-map-for-hot-path-hash-lookups)
- [Pat-13: Token Bucket and Leaky Bucket for Rate Limiting](#pat-13-token-bucket-and-leaky-bucket-for-rate-limiting)
- [Pat-14: Timer Wheel for Active Stages](#pat-14-timer-wheel-for-active-stages)
- [Pat-15: Health and Guardrails as Feedback Loop, Not In-Band Checks](#pat-15-health-and-guardrails-as-feedback-loop-not-in-band-checks)
- [Pat-16: Profiling and Regression Discipline](#pat-16-profiling-and-regression-discipline)
- [Pat-17: Content Identity and Verification Before Activation](#pat-17-content-identity-and-verification-before-activation)
- [Pat-18: Plan-Owned I/O Topology and Capability Gates](#pat-18-plan-owned-io-topology-and-capability-gates)
- [Pat-19: Link-Closed Module Images](#pat-19-link-closed-module-images)
- [Pat-20: Provider Dependency Firewall](#pat-20-provider-dependency-firewall)
- [Pat-21: Linear Ownership Across Foreign Calls](#pat-21-linear-ownership-across-foreign-calls)
- [Pat-22: Predicate-Closed Waiting](#pat-22-predicate-closed-waiting)
- [Pat-23: Release Projection Ownership](#pat-23-release-projection-ownership)

**Closing**

- [Pattern Application Matrix](#pattern-application-matrix)
- [Delegation Index](#delegation-index)
- [Technical References](#technical-references)

---

## Part 1: Principles

These principles govern every implementation and survive rewrites. When code
violates a principle, the code changes.

### P-1: Mechanism vs Policy

**Why.** Separating runtime mechanisms from policy lets applications change
packet behavior without changing the platform.

**Rule.** Platform code supplies primitives, lifecycle hooks, contracts, and
typed channels. Modules and operator policy own ACL rules, NAT mappings, QoS
profiles, and other domain decisions without reaching into platform internals.

**Where this appears.** `MODULE_SDK.md` (the canonical mechanism surface for
module authors), `src/modules/README.md` (the built-in ACL/NAT44/QoS modules
are policy that exercises that surface end to end via the same SDK customers
use), `AXIOM.md` (pipeline IR as mechanism), `GLUON.md` (planning is
mechanism, deployment choices are policy).

### P-2: Code Is the Source of Truth

**Why.** Behavioral claims need source and executable evidence; prose alone
cannot establish what the platform does.

**Rule.** Source and executable evidence establish what the platform currently
does; prose cannot override that fact. They do not make a defective behavior
correct. Compare every disagreement with the accepted contract: if the
implementation violates it, stop the documentation edit and correct the code
through the owning change process; if only the prose is stale, correct the
prose. Never make documentation agree with a known defect or change behavior
silently under a documentation cleanup. Source comments must describe the
function they sit above, and tests verify behavior rather than commentary.

**Where this appears.** Every reference doc traces behavioral claims to
the owning production source. Verify those claims against executable evidence;
public guides do not list test files as references.

### P-3: Fail-Closed by Default

**Why.** Silent downgrades and unintended fallbacks hide failures. Reject bad
input at admission.

**Rule.** Reject unknown input, unavailable capabilities, and violated
invariants with an explicit error. Validate at entry (RPC, CLI, plan admission)
and at the runtime boundary that can observe the condition. Partial input must
never produce silent success.

**Where this appears.** Axiom and Gluon admission (unknown stage kinds, missing
explicit modes, and kind/configuration disagreement reject before planning),
provider-graph authoring (unknown contracts and incomplete
port/queue/storage bindings reject before plan publication), the DP generic
engine (module or unspecified execution without runtime-generation authority
rejects), CP guardrails policy
validation (advanced knobs validated fail-closed at both RPC entry and
control-loop mutation), and bundle manifest verification (required exact
product identity, canonical text, unknown directives, and non-increasing paths
are rejected at parse time).

### P-4: No Latent Fallback or Unowned Compatibility

**Why.** Unowned compatibility and accidental compensation hide defects as
apparently working behavior.

**Rule.** Retain only paths with defined semantics and owners. Remove hidden
legacy branches, unversioned compatibility, and silent downgrades. Explicit
compatibility requires an owned relation, validator, and retirement policy.
The module ABI requires exact `KINETUM_MODULE_ABI_VERSION` equality.

A production Linux process resolves its own image through `/proc/self/exe`
and launches admitted absolute sibling paths from that directory. `argv[0]`,
`PATH`, the working directory, environment guesses, and reconstructed shell
commands never establish executable identity. Caller-supplied artifact paths
may be canonicalized at admission; failure rejects before later filesystem or
loader use. Artifact paths do not select executable identity or durable roots.

**Where this appears.** Gluon has one linear-DP planner and no alternate
algorithm selector. CP mutation retry resolves through one
durable canonical authority: snapshot transitions retain full exact identity,
policy and Confirm retain bounded keyed results, and no process-local TTL/FIFO
cache can outlive or contradict restart truth.
The boundary protocol requires an exact ordered CUT/ACK barrier instead of an
epoch-only best-effort marker. Photon resolves DP/CP from its canonical Linux
process image and launches them with exact-path `posix_spawn()`; the packer and
installation-info tool consume the same process-image authority instead of
inferring from invocation context. Every 0.1.0 path must therefore have a
current owner; remembered behavior without one is not a compatibility policy.

### P-5: Plan Is the Source of Truth for Runtime Wiring

**Why.** Wiring assembled from CLI flags, environment, ad-hoc files, and
embedded defaults cannot be reproduced from one deployment artifact and can
silently drift between development and production.

**Rule.** Every aspect of runtime wiring that matters for correctness must
come from the plan: region and boundary topology; exact process facilities;
I/O-driver, packet-storage, and execution-provider instances; logical and
driver-local ports; queues and stream ownership; storage transitions; module
IDs and load order; worker ownership; runtime-service CPU/NUMA ownership; and
every bounded capacity. The runtime may compile these records into compact
indices, but it must not synthesize a provider, queue zero, CPU execution,
storage domain, missing lane boundary, worker placement, process-service role,
native attachment, or transition. The plan carries deterministic identity
fields and is the single artifact a deployment is built around. CLI flags may
select process-control endpoints or physical validation infrastructure; they
must not repair, override, or duplicate runtime wiring.

Release metadata follows the same authority boundary. A fixed
`platform_capabilities` inventory may describe mechanisms compiled into the
complete product, but no runtime, planner, validation verdict, or fallback may
use it to admit behavior. Exact plan, component, and live observations remain
the only behavior authorities.

**Where this appears.** `AXIOM.md` (pipeline definition), `GLUON.md` (planner
output is the plan), `QUARK.md` (runtime validates plan against host
topology), `GETTING_STARTED.md` (plan-first deployment lifecycle),
`KINETUM_PACK.md` (production bundles wrap the plan with manifest-level
content identity).

### P-6: Single-Writer Authority for Mutation Ordering

**Why.** Concurrent writers make mutation order nondeterministic even when
each individual write is correct.

**Rule.** Every mutable state in the platform has exactly one writer at a
time. The writer may be a single thread, a single control loop, or a
single ownership token, but it is not multiple threads writing concurrently.
Other code reads through an explicit publication mechanism (RCU snapshots,
versioned buffers, atomic pointer swaps). Publication readers never take a lock or
wait on the writer; writers may wait at the publication boundary for an
RCU grace period. No reader observes a partially-written value.

**Where this appears.** CP `control_loop` is the single semantic writer
for snapshot and policy mutations (apply, confirm, rollback, guardrails). DP workers
each own their context-local state exclusively. Module PREPARE creates
immutable ownership off-worker; the sole owner performs bounded ACTIVATE and
reads the exact tagged packet view directly. Each packet worker also owns one
two-slot epoch ledger: packet dispositions update plain owner-local credits and
foreign readers consume only its coherent per-turn publication. See
`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md` for CP ordering,
`DATA_PLANE.md` for worker ownership, and `MODULE_SDK.md` for exact module
configuration ownership.

### P-7: Platform Primitives Only

**Why.** Duplicate queues, hash maps, and rate limiters develop different
invariants, defects, and performance. Each variant makes consolidation harder.

**Rule.** When you need a primitive, use what is in `include/kinetum/algo/`. If
`include/kinetum/algo/` does not have what you need, add it there (with tests and
documentation), then use it. Do not roll a one-off implementation inside
your component just because the shared primitive does not yet exist.

`include/kinetum/algo/` owns reusable queues, publications, hash tables, and
quiescence mechanisms. DP epoch states, CUT/ACK identity, module lifecycle, and
CP mutation policy remain with their subsystems and compose those primitives.
Shared primitives must not depend on DP, CP, protobuf, gRPC, or provider-native
types.

**Where this appears.** `docs/ALGORITHM_LIBRARY.md` (the canonical primitive
index: cuckoo_map, versioned_rcu_buffer, single_writer_snapshot,
quiescence_domain, spsc_ring_static, token_bucket, timer_wheel, simd_classify,
CIDR helpers, signal smoothing). Anything new built outside this directory and
then re-implemented later is a code smell.

### P-8: Deterministic Boundary Semantics Over Best-Effort

**Why.** Best-effort region or epoch transitions permit silent drops and
reordering, violating the boundary protocol's correctness contract.

**Rule.** Cross-region and cross-epoch handoff uses a lossless, sequence-defined
CUT/ACK barrier with bounded data backpressure. The CUT identifies the final
successful old-epoch DATA enqueue. The sender seals old DATA at that cut and
holds future DATA. The receiver drains through the exact cut, retires all local
old work, activates the exact prepared configuration, and only then ACKs the
same cut. Configuration storage remains retained until every possible old
reader is quiescent. An epoch-only marker on an independent control channel is
not an ordered cut and does not satisfy this principle.

**Where this appears.** `DATA_PLANE.md` owns transport, worker activation, and
completion.
`diagrams/ordered_cut_boundary_protocol.md` traces the protocol and the
epoch-only marker counterexample. Pat-10 specifies its publication and
reclamation rules. Physical evidence requires measured traffic from the
qualified release under the host and instrument conditions recorded by
`VALIDATION_GUIDE.md`; scenario code alone is not evidence.

### P-9: Two-Phase Apply Over In-Place Mutation

**Why.** In-place mutation can leave configuration partly applied. Validate,
hash, and stage before activation; rollback uses the same path with prior
content.

**Rule.** Configuration apply is two phases: Prepare validates the complete
snapshot, builds immutable execution artifacts under the exact next epoch,
computes its hash, and signals readiness without changing live execution.
Activate commits that prepared transaction through the ordered boundary
protocol; no fallible compilation remains after commit. The active config and
prepared config coexist until activation, and the old config remains retained
through the global quiescence/grace point. Rollback prepares the desired prior
content as a new monotonically increasing epoch through the same path; it never
decrements the epoch or restores an old pointer in place.

**Where this appears.** `DATA_PLANE.md` (two-phase apply internals in DP),
`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md` (CP-side orchestration,
commit-confirmed pattern, selective rollback that produces hybrid
snapshots).

### P-10: Severity-Driven Defect Model

**Why.** Severity keeps correctness and safety failures ahead of lesser work.

**Rule.** Every defect, design decision, and open work item is classified
as Critical, Major, or Minor:

- **Critical** is a correctness or safety failure (mixed-revision risk,
  silent loss, corruption, unsafe rollback).
- **Major** is a production behavior gap with operational or performance
  impact.
- **Minor** is a non-blocking quality, documentation, or tooling issue.

**Where this appears.** Code review, release gates, physical-I/O validation
review, and defect triage. PEG defines the classification; project governance
owns the live list.

### P-11: Every Declared Surface Has an Owner

**Why.** A proto field, CLI flag, enum value, callback, or configuration member
without one current producer, consumer, validator, and behavior owner is not a
capability. It is ambiguous input that can drift into a silent fallback or a
false operator claim.

**Rule.** Every declared surface has one current meaning and a complete
ownership chain. Implemented behavior is documented as the product contract.
A deliberately unavailable surface remains only when callers need the typed
refusal; its rejection point and reason are explicit. Speculative, ignored,
write-only, placeholder, and "reserved for later" declarations do not enter an
unreleased schema or CLI.

**Where this appears.** Component capability-boundary sections map every
retained field, flag, callback, and command to its current owner. Descriptor
tests prove removed wire members are absent; CLI and runtime tests prove typed
unavailability where that refusal is part of the current contract.

---

## Part 2: Patterns

These reusable mechanisms apply across components. Each pattern's
"Where this appears" entry points to component-specific mechanics.

### Pat-1: No Hot-Path Allocation

**Rule.** Hot-path code (per-packet, per-batch, per-tick) must not allocate
heap memory. No `malloc`, `new`, `std::vector::push_back` past reserved
capacity, no `std::string` construction, no implicit container growth.

**Rationale.** Allocator locks and free-list state, demand-page faults, cold
cache lines, and allocation failure introduce latency and failure paths that
violate bounded packet work.

**Use instead.**

- Exact lifecycle allocation: context-lifetime storage is allocated during
  INIT and immutable per-epoch storage during PREPARE. C++ modules use
  `context_memory_resource` and `epoch_memory_resource`; C modules use the
  corresponding lifecycle allocation functions.
- Per-owner-worker state allocated at startup, sized from plan.
- `bounded_index_pool` for owner-local recycling of a runtime-sized slab's
  compact indices without changing container size after construction.
- Bounded rings sized at construction (`spsc_ring_static<T, Capacity>`).
- Fixed-size batch buffers carried on `kinetum_batch_t`.
- `std::array<T, N>` instead of `std::vector<T>` when N is bounded.

**Where this appears.** `DATA_PLANE.md` (the DP hot path is zero-allocation
by construction), `MODULE_SDK.md` (the module ABI passes pre-allocated
batches and pre-allocated user_meta lanes), `docs/ALGORITHM_LIBRARY.md`
(hot-path operations use storage acquired during cold construction).

### Pat-2: No Hot-Path Locks

**Rule.** Hot-path code must not acquire mutexes, spinlocks, condition
variables, or any other blocking synchronization primitive. This includes
reader/writer locks where the reader path is non-trivial.

**Rationale.** Shared locks serialize workers and add workload-dependent
contention. Throughput, tail latency, and per-turn bounds then depend on another
owner rather than the compiled work budget.

**Use instead.**

- Per-owner-worker sharding: each compact worker owns its slice; merges happen on the cold
  path.
- Lock-free atomics with explicit memory ordering for the rare cases where
  cross-worker state matters (counters, telemetry).
- RCU publication (Pat-8) for any state the cold path needs to mutate while
  the hot path reads.
- SPSC rings (Pat-11) for cross-worker handoff.

**Where this appears.** `DATA_PLANE.md` and `src/modules/README.md` describe
worker-local packet state. CP readers borrow control-loop publications through
`versioned_rcu_buffer`; packet workers use their admitted module views directly.

### Pat-3: No Hot-Path shared_ptr, Exceptions, Virtual, or RTTI

**Rule.** The production hot path uses raw pointers with explicit lifetime,
no exception throwing, no virtual function calls, and no `dynamic_cast` or
`typeid`. The SDK's module ABI and provider operation tables use explicit
function pointers resolved before workers launch. Test harnesses may use
heavier mechanics outside the measured packet path; no provider receives a
hot-path exemption.

**Rationale.** `shared_ptr` reference counts add atomic traffic and possible
cross-core contention. Exceptions add unwind machinery and must never cross
the C ABI. Virtual dispatch and RTTI add indirection or type discovery where
the target is already known.

**Use instead.**

- Raw pointers with epoch-bound lifetime (the epoch arena owns the memory).
- Return codes (`bool`, `kinetum::common::status_or<T>`) instead of
  throwing.
- CRTP (curiously recurring template pattern) for static polymorphism;
  `module_base<T>` in the SDK is the canonical example.
- One explicit SDK ABI function-pointer call at the runtime/module
  boundary (`process`, `ingest`, or `run`), populated during module
  registration. Do not add secondary per-packet virtual dispatch inside
  modules or stage internals.

**Where this appears.** `MODULE_SDK.md` (the module ABI: INIT, PREPARE,
ACTIVATE, RETIRE, FINI, `do_process`, and optional owner health dispatched
through an exact descriptor), `include/kinetum/kinetum_sdk.hpp` (the CRTP
`module_base<T>`),
`src/common/status_or.hpp` (explicit error returns), `CODING_GUIDELINES.md`
Section 6 (hot-path rules listed).

### Pat-4: SoA Over AoS (Batch Model)

**Rule.** A module packet callback operates over a transient SoA
(struct-of-arrays) projection (`kinetum_batch_t`), not over a
packet-at-a-time AoS stream or a provider-native handle. The runtime remains
the owner of one exact `packet_record` per packet and projects its bounded
prefix into worker-local SoA scratch. Each callback-visible attribute (data
pointer, length, parsed addresses/ports, output port, next stage, persistent
user word) is a separate array indexed by packet lane.

**Rationale.** Contiguous fields permit SIMD loads without gathers and linear
access with predictable prefetch addresses.

**Use instead.**

- `kinetum_batch_t` carries exact lanes for bytes/length, parsed offsets and
  tuple, DSCP, platform/user flags, flow hash, input/output ports, next stage,
  timestamp, and persistent user metadata. Immutable authority lanes are
  validated after the callback; only documented mutable lanes publish back to
  the record.
- The callback's `uint64_t` return mask is the sole disposition authority: bit
  `i` set forwards lane `i`; bit `i` clear retires it. There is no parallel
  disposition array or native-provider disposition field.
- Packet bytes and parsed lanes are one coherence contract. A module that
  mutates bytes updates every parsed field it invalidates; the runtime does not
  reparse between stages.
- Active modules originate a separately validated `kinetum_emit_batch_t`.
  The owner storage domain copies the complete accepted prefix into exact
  records before dispatch; borrowed origin pointers never become packet
  ownership.
- SIMD primitives in `include/kinetum/algo/simd_classify.hpp` consume SoA lanes
  directly.
- Every architecture-selected classifier is checked against one independent
  scalar predicate at counts crossing its vector width. Unsigned inclusive
  comparisons do not synthesize `min - 1` or `max + 1` in the lane type, CIDR
  masks apply to both operands, and protocol-specific fields retain the same
  applicability in scalar and vector paths.

**Where this appears.** `DATA_PLANE.md` (batch lifecycle and the lanes
the runtime owns), `MODULE_SDK.md` (the SoA batch is the module ABI),
`include/kinetum/algo/simd_classify.hpp` (SIMD primitives that exercise SoA).

### Pat-5: Cache-Line Alignment and False-Sharing Avoidance

**Rule.** Hot-path data structures are aligned to the cache line. State
that is written by different cores does not share a cache line. State that
is read together is colocated on the same cache line when possible.

**Rationale.** Writes invalidate other cores' copies of the same cache line.
Placing unrelated writers on one line creates false sharing and unnecessary
coherence traffic.

**Use instead.**

- `alignas(CACHE_LINE_SIZE)` on per-core state (`CACHE_LINE_SIZE` is
  defined in `include/kinetum/algo/cache.hpp`).
- Explicit padding between per-core fields in shared structs.
- `kinetum::algo::cuckoo_bucket` uses `alignas(CACHE_LINE_SIZE)` so each
  bucket begins on its own line. Generic key/value size determines whether its
  complete four-entry extent spans additional lines.
- `spsc_ring_static<T, N>` puts producer head and consumer tail on
  separate cache lines via `alignas(64)`.

**Where this appears.** `docs/ALGORITHM_LIBRARY.md` (per-primitive notes on
alignment), `DATA_PLANE.md` (region state alignment), `MODULE_SDK.md`
(guidance for module-author state structs).

### Pat-6: NUMA and Hugepages

**Rule.** Per-core state and packet storage are allocated on the exact NUMA
node selected for their owner. A provider whose admitted memory contract uses
hugepages must use and prove that backing; an explicit host-storage provider
does not acquire a hugepage requirement by implication.
For a cross-worker channel, each ring lives with the endpoint that polls it,
while endpoint-mutable state and its coherent publication live with the worker
that owns those writes; cache-line separation never substitutes for placement.

**Rationale.** Remote-NUMA access adds topology-dependent latency and consumes
interconnect bandwidth on every affected batch. Hugepages reduce page count
and TLB pressure for providers that use them: one 2 MiB page spans the same
address range as 512 standard 4 KiB pages. Neither NUMA placement nor page size
is a substitute for target measurement, and neither implies zero cache or TLB
misses.

**Use instead.**

- A packet storage domain carries exact bounded population, data-room,
  headroom, alignment, facility references, and optional proven host NUMA
  ownership. Its provider component may realize those facts through DPDK
  hugepage mempools, host storage, UMEM, or a future device-visible domain,
  but the native mechanism cannot invent a different placement.
- The plan carries `worker_placements[].cpu_core_ids` and
  `runtime_service_placements[]`. Gluon places each region's worker group on one
  NUMA node, keeps coordinator/executor cores pairwise disjoint from packet
  workers, and emits their exact process union. Quark validates every selected
  core and its exact NUMA node against host truth without filtering, repair, or
  a lenient mode. The shared provider compiler derives any native facility
  core role, including a DPDK main lcore, from those generic placements; a
  free-form EAL argument list is not plan or CLI authority. Unknown NUMA
  ownership is not treated as node 0. Region-level `cpu_core_ids` are
  provenance only. Hugepage, NIC, IOMMU, and native facility facts are proved
  by their exact provider contract and host-proof/materialization boundary.
- Linux CPU discovery and thread pinning share one dynamically allocated
  affinity-set mechanism. A query starts with the libc extent and grows only
  when the kernel reports that the supplied buffer is too small; an authored
  CPU identity allocates the exact representable extent needed for that bit.
  `CPU_SETSIZE`, the configured CPU count, and a fixed `cpu_set_t` are never
  generic identity ceilings. Provider-native limits such as DPDK lcore range
  remain provider-private capability checks.
- `reserved_cores` means the lowest logical core IDs are excluded from packet
  workers, preferred by runtime services in ascending ID order, and left
  unassigned when services do not consume them. A reserved core is never
  returned to packet ownership as a convenience fallback. If that pool cannot
  satisfy a service, the coordinator and lifecycle executors both consume the
  least packet-preferred non-reserved candidate: hyperthreads before physical
  cores when physical preference is enabled, then descending logical core ID.
- A development path that intentionally avoids hugepages selects an explicit
  host-storage contract in deployment bindings. It does not turn absence of
  hugepages into an inferred DPDK mode or add a parallel CLI memory override.

**Where this appears.** `GLUON.md` (NUMA-aware core selection and exact
storage-domain placement from hardware inventory), `DATA_PLANE.md` (provider
facility, storage, and execution placement), `GETTING_STARTED.md` (preparing
the host resources required by the selected provider graph).

### Pat-7: Context-Local State with Exact Generation Ownership

**Rule.** Mutable module state belongs to one explicit context object in one
admitted generation, and that context has exactly one owner worker. Module
state must not live in an unqualified `thread_local`, process-global map, or
code-image singleton. Every new generation constructs new contexts; every old
context is finalized only after its worker and lifecycle work are quiescent.

**Rationale.** A core or thread ID does not identify a module instance. Explicit
contexts keep image generations, replicas, lifetimes, NUMA placement, and writers
separate.

**Use instead.**

- Allocate the concrete module object and long-lived state during exact INIT;
  publish it as `kinetum_ctx::state` only after complete success.
- Route every context container through the INIT lifecycle resource and every
  prepared container through the exact PREPARE arena. Seal both before
  publication; no module state may grow by falling back to the process heap.
- Give every stage-instance replica its own context-local cache, session table,
  policer, counters, and histograms.
- Keep immutable policy in an exact prepared artifact and pass only its
  `packet_config` view to the owner worker.
- Before provider effects, prove a two-way equality between compiled module
  stage instances and admitted contexts: compact/string identity, image,
  owner placement, and execution mode. Bootstrap additionally proves the exact
  prepared epoch and installs every active store view before packet release.
- On the packet path, borrow the already prevalidated owner-local view and
  perform one `packet_epoch == view_epoch` comparison. Mismatch invokes no
  module code, selects no alternate slot, releases packet ownership, and writes
  only bounded owner-local evidence. A foreign reader must consume a coherent
  owner publication rather than adding a contended per-packet atomic.
- Prove that both directions of a stateful flow reach the same context, including
  after address or port translation. Hardware RSS symmetry alone does not prove
  that ownership. Module context ordinals and population stay fixed for the
  admitted generation; retained contexts cannot be remapped during an update.
- Destroy contexts in a defined order after workers and lifecycle executors
  join; unload the image only after its last context finalizes.

**Where this appears.** `MODULE_SDK.md` (image/context/generation identities),
`src/dp/module/module_manager.hpp` (atomic generation and context ownership),
`src/dp/module/module_epoch_store.hpp` (exact artifact/view ownership),
`src/modules/README.md` (ACL, NAT44, and QoS context-local state), and
`DATA_PLANE.md` (worker admission and exact module execution).

### Pat-8: RCU and versioned_rcu_buffer

**Rule.** State that the cold path mutates and the hot path reads is
published through `versioned_rcu_buffer<T>` (or `rcu_buffer<T>` when
epoch tracking is not needed). Readers borrow a guard, get a stable view,
and release on scope exit. Writers wait for readers to drain on the
inactive slot before writing.

**Rationale.** Readers need a stable object, not a torn read followed by a
retry. A slot guard preserves that object while the writer waits to reuse the
inactive slot. Publication ordering and pin revalidation prevent reuse beneath
a reader.

**Use instead.**

- `kinetum::algo::rcu_buffer<T>` for the basic two-slot RCU buffer.
- `kinetum::algo::versioned_rcu_buffer<T>` adds epoch tracking for platform
  control-state publication.
- `borrow()` returns a RAII `read_guard` that pins the slot until
  destruction; `try_borrow()` is the non-blocking variant. Every guard resolves
  before its buffer; buffer destruction with a live pin fails stop before
  reclaiming reader state.
- `store()` waits for readers on the inactive slot to drain (via
  `spin_backoff(iteration)`), then writes and swaps `active_` atomically.
- Active-slot publication, reader pinning and revalidation, and the writer's
  zero-reader check use sequentially consistent ordering. These operations
  span separate atomics: they must prevent a writer from missing a pin while
  its reader still accepts the old active index. Pin release uses release
  ordering; the writer's acquiring zero check observes completed reads.
- Do not wrap module policy in a second module-local RCU selector. The module
  runtime owns exact tagged slots and passes the selected immutable
  `packet_config` directly to packet execution.
- Use `kinetum::algo::quiescence_domain` instead when a fixed reader set must
  publish one safe point per grace generation without pinning every read. Its
  adjacent exact generations are QSBR, not a numeric minimum or replacement
  for `rcu_buffer` slot guards.

**Where this appears.** `include/kinetum/algo/rcu_buffer.hpp` and
`include/kinetum/algo/quiescence.hpp` (the distinct pin-per-read and
publish-per-grace primitives),
`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md` (CP-side publication), and
`MODULE_SDK.md` (why module packet policy instead uses exact platform-owned
slots).

### Pat-9: Aligned Atomics and Lock-Free Primitives

**Rule.** Cross-core counters, sequence numbers, and flags use
`std::atomic<T>` with explicit memory ordering. Acquire/release pairing
is the default for publication; sequentially-consistent ordering is used
only when absolutely required and documented as such. Aligned atomic
types live on their own cache line (`alignas(CACHE_LINE_SIZE)` for
contended atomics).

**Rationale.** Sequential consistency provides one total order across the
participating atomics. Its instruction cost depends on the operation and
architecture; it does not require a separate full fence for every operation.
Use acquire/release for a publication pair and relaxed ordering where no
cross-thread ordering is needed. A protocol spanning separate atomics must
prove their joint ordering; the RCU pin/reuse protocol requires sequential
consistency to close its publication-versus-pin race.

**Use instead.**

- Owner-worker counters: plain increments in cache-line-private state, followed
  by one coherent release publication at a bounded turn boundary. Foreign
  readers never sum mutable owner state directly.
- Cross-worker flags (e.g., shutdown signal): release on the writer side,
  acquire on the readers.
- The SPSC ring's head/tail uses acquire/release for the producer/consumer
  publication pair; see `include/kinetum/algo/queue.hpp`.
- RCU active-slot publication, reader pin acquisition/revalidation, and writer
  drain checks share sequentially consistent ordering. Initial slot selection
  uses acquire ordering; completed pins use release ordering.
- A quiescence reader acquire-observes one active grace and release-publishes
  exactly that adjacent generation through its own cache-line atomic. The cold
  coordinator never accepts a skipped generation through monotonic maximum.
- Choose process-signal ownership by execution shape. An event-loop host blocks
  its signals before thread creation and consumes them through one descriptor
  on the owning loop. A tight single-thread child may instead install a
  `sigaction` handler that writes only one `volatile sig_atomic_t` flag, then
  observe that flag in its existing loop. When such a signal triggers a
  post-spawn edge, the spawning owner blocks it before child creation, the
  child installs the handler before unblocking, and the parent restores its
  exact prior mask on every spawn outcome. A signal handler never invokes a
  runtime, allocator, logger, lock, or general atomic operation.

**Where this appears.** `include/kinetum/algo/queue.hpp` (spsc_ring head/tail),
`include/kinetum/algo/rcu_buffer.hpp` (active_ and readers_),
`include/kinetum/algo/quiescence.hpp` (exact reader grace), `DATA_PLANE.md`
(counter sharding model and aggregation), `MODULE_SDK.md`
(`kinetum_counter_t` and related atomics).

### Pat-10: Epoch Sequencing and Ordered CUT/ACK Barrier

**Rule.** Every originated packet receives one immutable epoch. A
cross-worker boundary uses a sequence-defined CUT that is physically carried
on the control channel but logically positioned after the last successful
old-epoch DATA enqueue. The sender seals old DATA at that sequence and gates
future DATA. The receiver may observe the CUT early, but it cannot activate or
ACK until it has dequeued through the cut and retired every local old-epoch
work item. ACK echoes the exact epoch and cut sequence. Execution uses only an
exact epoch-tagged configuration, and reclamation waits for a global
quiescence certificate and grace period.

Receiver activation preserves one DATA admission law rather than adding a
transition exception. Before ACK, target DATA cannot cross the sender gate;
before activation, every admitted DATA record is therefore old. At activation,
all inbound cuts are drained and the rings contain no old prefix; only after
the receiver is switched may its ACK open target DATA. The permanent receive
predicate remains `record_epoch == active_epoch` in every phase.

The reader grace request starts when commit becomes completion-only and before
the worker trigger. Each worker can therefore publish its safe point once from
the existing transition arm after its final old read, with no fixed-turn request
poll. Completion has two explicit legs: exact execution/boundary completion
permits RETIRING, while RETIRING waits for every reader in the same active grace.
A stalled reader retains old objects and freezes later updates; it is never
reclassified as a successful grace or a COMMITTING rollback.

Transition timing is observation, never ordering authority. A worker may take
supplemental monotonic samples only at four real edge classes: immediately
before one sender CUT-publication batch, after one receiver CUT/data-drain
batch, immediately before one receiver ACK-publication batch, and after one
sender ACK-consumption batch. Each edge takes one sample for the complete
same-turn endpoint batch, never one sample per boundary. Ordinary turns, fixed
execution, packet work, and provider burst operations gain no clock read;
incomplete timestamp pairs remain absent rather than manufacturing a duration.

Every post-commit resource is preallocated and audited before PREPARED. Once
both certificate legs complete, reclamation first preflights the complete old
module/snapshot claim set, then withdraws exact store-bound claims and dispatches
reverse-canonical RETIRE while overlapping only independent image/executor
pairs. Exact task, image, context, epoch, and claim identity plus SUCCESS are
required before claim consumption and issuing-store completion. The old
snapshot retires after every old module slot is empty; only then may the grace
finish, runtime status publish stable target truth, the terminal journal record
COMPLETE, and the global phase return IDLE. A timeout before the first claim
freezes RETIRING with every old object owned. Any uncertainty after withdrawal
is fail-stop because the retain-all-old-state guarantee is no longer
representable.

**Rationale.** Without both halves, an epoch transition admits two correctness
failures: forward leak (future DATA reaches a receiver still executing the old
configuration) and backward leak (old DATA or retained work executes after the
receiver activates the new configuration). An epoch-only marker on a separate
ring can overtake DATA and proves neither channel drain nor config retention.
Either leak is a mixed-revision bug that later stages cannot repair.

**Use instead.** The required three-ring contract is:

- `data_ring` carries pointer-only packet ownership in SPSC order and counts
  successful enqueue/dequeue sequences;
- `ctrl_ring` carries a typed CUT with the next epoch and final old-DATA
  enqueue sequence;
- `ack_ring` carries the exact activated epoch and consumed cut sequence;
- worker-local ownership ledgers cover queued packets, retained handles,
  timers, copied control, PULL bits, clones, callbacks, tracked foreign tokens,
  completion delivery, recirculation, and pending-output work outside the DATA
  ring;
- one dataplane-wide transition generation prevents a later epoch from
  invalidating the two exact configuration slots before old work is quiescent.
- one immutable global certificate reads frozen membership plus coherent
  activation, ledger, boundary-policy, boundary-transport, and exact reader
  publications. Missing observations may delay progress; region aggregates,
  monotonic minima, and current target-epoch credit never authorize reclamation.

Tracked foreign work does not add another certificate. A standalone token
acquires one ledger credit before foreign visibility; a packet-bound token
moves the retained packet's existing credit. Exactly one terminal CAS publishes
through a caller-storage MPMC queue, and the owner retires only after callback
delivery. Cancellation publishes before DRAIN and never fabricates an outcome;
grace expiry is fail-stop. Same-instance OPEN-only recirculation preserves the
credit and becomes finite because DRAIN forbids another cycle.

Control may remain physically out of band for progress, but the sequence CUT
makes its position logically in band with DATA. A marker that carries only an
epoch, a monotonic-max ACK, timeout-based quiescence, or inequality-based
"current/previous" config lookup does not conform. Implementation conformance
is release-gated; component docs and tests must trace each predicate to code.

**Where this appears.** `DATA_PLANE.md` owns transport, ledgers, activation,
certificate, grace, and reclamation. `diagrams/ordered_cut_boundary_protocol.md`
shows their ordering; `VALIDATION_GUIDE.md` Section 10 defines physical
qualification evidence.

### Pat-11: Bounded Queues and SPSC Rings

**Rule.** Inter-thread and inter-region communication uses bounded,
fixed-capacity queues, sized at construction. Unbounded queues are
forbidden in the platform: they trade observable backpressure for hidden
memory growth and silent latency.

**Rationale.** A full bounded queue forces the producer to block, count a drop,
or backpressure upstream. An unbounded queue hides overload as growing memory
use, eventual OOM, or unpredictable tail latency.

**Use instead.**

- `kinetum::algo::spsc_ring_static<T, Capacity>` for the SPSC case
  (single producer, single consumer, compile-time capacity).
- `kinetum::algo::spsc_ring_view<T>` when an owning subsystem supplies the
  exact storage extent and placement. Every SPSC usable capacity is a power of
  two and at least two. The DP composes this one arithmetic core with its
  checked prefaulted NUMA owner for DATA rings, worker queue roles, and boundary
  future-output holds; it does not copy the state machine into a placement-
  specific queue.
- `kinetum::algo::mpmc_queue<T, Capacity>` for the multi-producer case
  (cold path or low-rate paths).
- `kinetum::algo::mpmc_queue_dynamic<T>` when the MPMC physical capacity is
  plan-derived at construction. It allocates once, requires a power-of-two
  physical capacity, and exposes only observational `size_approx()`; successful
  enqueue/dequeue remains the ownership authority.
- `kinetum::algo::mpmc_queue_view<T>` when one subsystem supplies exact
  cache-line cell storage and placement. Static, dynamic, and caller-storage
  forms delegate to one sequence/publication core.
- MPMC cell copy and move assignment are non-throwing type requirements: a
  reserved producer or consumer cursor has no rollback operation.
- `try_push`/`try_pop` (SPSC/work queues) and
  `try_enqueue`/`try_dequeue` (MPMC queues) are non-blocking; full or empty is
  a normal condition the caller handles, not an error.
- Treat a notification descriptor as wake-only. A coalesced count, spurious
  wake, or already-drained descriptor cannot be an ownership or completion
  count; after a wake, the sole consumer drains the bounded owning queues until
  they are empty. Queue publication and exact result identity remain the only
  work authority.
- A full CUT/ACK control lane retains exactly one endpoint-local typed record
  and returns to the worker loop. Retry performs one later bounded push; it does
  not spin, sleep, yield, read a clock, or reinterpret another record as
  progress.

**Where this appears.** `include/kinetum/algo/queue.hpp` owns queue arithmetic.
`DATA_PLANE.md` defines NUMA placement, active/future queues, boundary holds,
capacity-2 CUT/ACK rings, coordinator admission, lifecycle results, and async
completions. Transition-disabled sources remain active-only; fixed bootstrap
uses active queues and DATA only.

`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md` defines the CP's 64-cell MPMC
pointer mailbox. Allocate ordinary contexts before the predicate mutex, then
publish and consume cells under it. Full admission returns `RESOURCE_EXHAUSTED`
before semantic or durable mutation. Cancellation leaves accepted contexts for
the worker to drain. The separate caller-owned safety-intent borrow permits
neither cancellation nor timeout.

### Pat-12: Cuckoo Map for Hot-Path Hash Lookups

**Rule.** Hot-path associative maps (flow tables and NAT session
maps) use `kinetum::algo::cuckoo_map<Key, Value, Hash>`, not
`std::unordered_map` or any open-addressing alternative.

**Rationale.** Node allocation and pointer chains make `std::unordered_map`
unsuitable here. Cuckoo lookup reads at most two preallocated, cache-aligned
buckets.

**Use instead.** Brief surface; full API in `docs/ALGORITHM_LIBRARY.md`.

- Construction requires a positive bucket count and the exact non-null PMR
  resource that owns all table and displacement-log storage. The resource must
  outlive the map; no process-heap default exists.
- Every instantiation supplies an explicit nonthrowing semantic hasher. No
  default may inspect object representation or padding.
- Buckets are `alignas(CACHE_LINE_SIZE)` with `CUCKOO_BUCKET_SIZE = 4`
  entries each.
- Inserts may evict (kick) up to `CUCKOO_MAX_KICKS = 500` times before
  failing; failure restores the prior table and returns `false`.
- Two hash functions index two candidate buckets; lookups read both.
- Hash invocation and key equality are non-throwing, and compound keys hash
  semantic fields rather than padding or raw object representation.

**Where this appears.** `docs/ALGORITHM_LIBRARY.md` (full API and tuning),
`src/modules/README.md` (NAT44 session maps and QoS flow tables use
`cuckoo_map`; ACL instead has a fixed direct-mapped decision cache).

### Pat-13: Token Bucket and Leaky Bucket for Rate Limiting

**Rule.** New generic rate-limited operations (ingress shaping, control
plane throttles, tenant limits) use the platform's `token_bucket`,
`leaky_bucket`, or `sliding_window` primitives from
`include/kinetum/algo/ratelimit.hpp`. Specialized hot-path policers may be
module-owned only when their state layout is part of the module's
performance contract.

**Rationale.** Burst handling, exact fractional-byte accrual, and monotonic
time are easy to get wrong, silently losing or creating credit. Shared integer
math gives consumers one tested implementation of these edge cases.

**Use instead.** Brief surface; full API in `docs/ALGORITHM_LIBRARY.md`.

- `token_bucket(rate_bytes_per_sec, burst_bytes)`: standard token bucket with
  an exact integer numerator over the nanosecond denominator.
- `leaky_bucket`: meters bytes against a bounded level that drains at a fixed
  rate. It permits bursts up to capacity; it does not queue or pace packets.
- `sliding_window`: for positive-duration time-window counters.
- All three are stateful and operated on per-flow or per-tenant; storage
  is the caller's responsibility.
- Timestamp zero is ordinary input. A timestamp regression rejects without
  resetting credit or event count, and no rate is pre-divided into a zero
  low-rate representation.

**Where this appears.** `docs/ALGORITHM_LIBRARY.md` (the primitives),
`src/modules/README.md` (QoS uses a module-specific per-flow policer for
its hot path; the generic `token_bucket` remains the reusable primitive
for new consumers).

### Pat-14: Timer Wheel for Active Stages

**Rule.** Active-stage scheduled callbacks use the platform's
`kinetum::algo::timer_wheel` or its caller-storage `timer_wheel_view`, not
ad-hoc per-component timer logic.
Future generic timed work should use the same primitive unless a
component can justify a specialized owner-local structure.

**Rationale.** The shared hierarchical wheel provides O(1) arming and amortized
O(1) expiry per timer, with the tick and cascade bounds listed below. One
implementation keeps those bounds consistent across consumers.

**Use instead.** Brief surface; full API in `docs/ALGORITHM_LIBRARY.md`.

- `timer_wheel<MaxTimers, FineSlots, CoarseSlots>` is the
  hierarchical-wheel template (defaults: 4096, 256, 256).
- `timer_wheel_view<FineSlots, CoarseSlots>` binds exact caller-owned entries
  and slot heads; the static form is a wrapper over this same arithmetic.
- `arm(delay_ticks, user_key)` is O(1).
- `advance()` returns a bounded expiration batch. Tick work also includes any
  coarse bucket being cascaded; the output limit does not bound that bucket's
  population.
- A far absolute-time advance rebuilds from the intrusive armed-entry list,
  so work is O(current occupancy), never O(elapsed ticks) or empty capacity.
- One timer wheel belongs to each packet worker with active instances. Exact
  per-instance quotas are plan-authored inside that worker-wide pool; no
  cross-thread arm exists.
- Timer publication acquires one exact epoch credit, cancellation/expiry retires
  it exactly, and transition/shutdown drain cancels in bounded batches. Expiry
  releases the armed quota before callback entry but retains its credit through
  callback completion; the cold ledger ceiling includes the bounded handoff.

**Where this appears.** `docs/ALGORITHM_LIBRARY.md` owns the shared primitive.
`DATA_PLANE.md` and `MODULE_SDK.md` own the production active scheduler, exact
timer and foreign-work handles, quotas, ledger credits, cancellation, and drain
contract.

### Pat-15: Health and Guardrails as Feedback Loop, Not In-Band Checks

**Rule.** Module health is computed on the context's sole owner worker against
the exact active epoch/config view, copied into completed publication storage,
and consumed out of band by CP. A foreign stats/gRPC/lifecycle thread must not
call into mutable module state. The packet loop never branches on a health
verdict, and modules never invoke guardrails policy from `do_process`.

**Rationale.** Per-packet health decisions would make forwarding depend on
operator thresholds and add policy work to the hot path. Health informs CP
policy; the authored pipeline determines packet disposition.

**Use instead.**

- Modules may implement bounded `do_health_check` owner-worker work that
  returns a fixed `kinetum_health_assessment` with score, flags, and a literal
  bounded reason. Null means unavailable; the platform never synthesizes
  healthy.
- The callback does not format, read a clock, or stamp provenance. The owner
  worker composes `kinetum_health_signal` from the assessment, its exact active
  epoch, and its cached loop time. Command/source admission precedes the turn
  refresh; one already-scheduled callback runs immediately after that refresh
  and before its context-bank service. Only after an actual non-null callback
  returns, the worker takes one additional platform monotonic sample to measure
  the callback against the compiled budget and optionally timestamp that
  context's completed telemetry bank. The fresher sample never replaces the
  turn's cached packet/callback time. The owner then publishes the immutable
  signal without exposing live context state to telemetry readers. Target
  qualification traces every authorized worker clock path and rejects a
  syscall fallback or unacceptable measured regression.
- The owner validates the fixed assessment bounds before publication. Unknown
  flags, a score above 100, or a nonterminated reason are module-contract faults,
  never implicit healthy output.
- A contract fault suppresses that attempt's signal, saturating-increments one
  context-local count, and preserves immutable first-fault epoch/time/duration
  evidence. It does not drop a packet, alter routing, fail stop, or authorize a
  transition decision.
- The CP guardrails runner samples published signals plus DP-side telemetry
  through one active-content fence. Missing, stale, unavailable, faulted, or
  regressing evidence pauses valid-observation time and never contributes a
  zero or neutral sample.
- Cumulative counter identity and monotonic elapsed time are reduced to one
  exact interval before detector selection. Threshold and correlation modes
  consume that same delta; a correlator does not keep another counter seed or
  truncate the behavior clock.
- Auto-rollback is a CP decision based on explicit attribution confidence, not
  a DP-side reaction. The desired action is persisted with its observed
  content/policy/runtime identity before the existing transition authority
  allocates or contacts DP; it is not a second mutation state machine.

**Where this appears.** `CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`
(the full guardrails model: detection, attribution, decision, scope,
intent, composition), `MODULE_SDK.md` (the `do_health_check` callback
contract), `KINETUMCTL.md` (operator surface for enabling guardrails
policy).

### Pat-16: Profiling and Regression Discipline

**Rule.** Every hot-path change is measured. Performance is part of the
correctness contract: a change that regresses throughput or tail latency
is treated as a defect, not a tradeoff. Benchmarks are reproducible, run on a
declared qualified reference host, and gate sign-off through the benchmark
harness.

**Rationale.** Measure protocol safety and capacity separately. A correct
transition can still exhaust staging, backpressure RX, and cause hardware
misses when processing falls behind. Throughput and polling regressions are
release defects; they do not justify weakening safety bounds.

**Use instead.**

- `validation/kinetum_benchmark` for multi-run distributions; see
  `VALIDATION_GUIDE.md` Section 18.
- `perf stat` with `cache-misses`, `cache-references`, `branch-misses`,
  `branches`, `cycles`, `instructions` for low-level CPU behavior.
- `perf record` / `perf report` for hotspot identification.
- The physical-I/O validation harness's transition telemetry
  (`transition_metrics.jsonl`) is the canonical regression source for boundary
  protocol behavior.
- Target qualification traces the ordinary turn refresh, the health-return
  sample, and all four transition-edge sample classes. It rejects a
  syscall-backed worker call path, a per-boundary sampling loop, or a sample
  reachable from ordinary fixed/packet/provider execution.

**Where this appears.** `VALIDATION_GUIDE.md` Section 18 (benchmarks) and
Section 17 (structured result artifacts).

### Pat-17: Content Identity and Verification Before Activation

**Rule.** Every production artifact that crosses a trust or activation
boundary has an identity derived from canonical validated content and checked
before the artifact becomes live. Cryptographic identity has one mandatory
provider; a build-dependent non-cryptographic substitute is not the same
mechanism. Supplied hashes are claims to verify, never trusted inputs. When the
implementation has an active verifier, the verifier runs before activation.
When an identity field exists but no runtime verifier exists yet, the owning
doc must say so explicitly (P-11).

**Rationale.** Comparing content with a trusted expected hash detects both
corruption and substitution before runtime use. An unsigned manifest cannot
authenticate a publisher: an attacker could replace both manifest and payload.

**Use instead.**

- Deployment bundles: `BUNDLE_MANIFEST.txt` requires the exact compiled product
  version, strictly increasing paths, shortest-form sizes, and lowercase
  SHA-256 values. Producer and parser share count/byte ceilings and reject
  missing metadata or alternate spellings. One verifier rejects path
  indirection, requires canonical plan/snapshot paths, verifies plan identity,
  and canonicalizes the snapshot against that plan. Pack self-verifies its
  output; the verification tool, Photon, and DP use the same gate. DP accepts
  only `--bundle`, including for build-tree images, and always checks installed
  provider provenance. After CONTROL_READY, Photon passes CP the snapshot path
  and verified plan hash together. CP revalidates both before store admission:
  pristine content must match; after durable allocation, the last COMPLETE
  snapshot remains active and the plan must still match. DP verifies and
  activates that authority before PACKET_READY. OpenSSL::Crypto is mandatory
  independently of TLS; no non-cryptographic substitute is allowed.
- Configuration snapshots: the compact DP wire carries one exact 32-byte
  `validation_hash` through Prepare, Activate, Abort, and Status. Shared
  canonicalization rejects recursive unknown fields, enforces the exact
  plan module set and 10 MiB bound, normalizes set-like module/label order,
  preserves opaque blob bytes, verifies supplied hash claims, and emits one raw
  32-byte SHA-256. Bootstrap and live transitions share that contract and the
  two-slot ownership model. Readiness requires coherent owner activation;
  transition replies carry typed identity, state, and failure observations.
  CP persists a create-only canonical snapshot corpus plus one atomically replaced
  private authority. The authority embeds the exact active Bootstrap wire
  request, both allocator watermarks, current/latest transaction, optional
  pending-confirm state, one canonical guardrails policy, and at most one
  observation-bound rollback intent. Active/corpus equality is byte-exact and
  projects one logical snapshot; equal ID with different bytes is data loss.
  Allocation publishes both watermarks and transaction together. COMPLETE
  atomically promotes active content and its rollback promise. Neither operation
  may split dependent identities across sidecars or delete-then-promote steps.
- Plans: Gluon emits deterministic `plan_id` and a canonical `content_hash`
  after every stable field and every role-correct provider configuration is
  populated. The provider-owned deployment-plan identity authority
  canonicalizes each exact `Any`, rejects duplicate facility references,
  preserves order-contractual plan arrays, and clears only the self hash and
  declared timing volatility before deterministic serialization. Gluon, pack,
  bundle verification, Photon, and DP consume that same authority. Empty,
  malformed, noncanonical, or mismatched claims fail before provider loading or
  packet-runtime construction; no direct plan path exists to create a weaker
  verifier.
- Typed provider configuration: one pure catalog accepts only complete exact
  `type.googleapis.com/<fully.qualified.Message>` identities. It bounds URL and
  payload work, requires role agreement, decodes the generated type, rejects
  outer-envelope and recursive concrete-message unknown fields plus invalid
  enum values, validates provider policy, normalizes only declared set-like
  fields, deterministically serializes, and repacks one exact `Any`. Provider
  contract graphs contain no protobuf maps or nested `Any`; repeated fields
  preserve authored order unless their owning contract declares and tests set
  normalization. The catalog exposes normalized bytes but no hash operation;
  the deployment-plan identity authority composes and hashes those terminal
  bytes exactly once for all plan consumers.
- Installed provider artifacts: one canonical inventory binds the exact
  runtime image, generated provider ABI identity, component set, and complete
  redistributable private-dependency closure. Native release preparation
  reconstructs that inventory from the complete staged candidate, self-admits
  every component, and emits additive evidence. An architecture-neutral
  finalizer independently reconstructs every inventory-covered static fact,
  requires exact inventory and evidence agreement, and signs the inventory
  with Ed25519 over a versioned domain-separated preimage. The native evidence
  is deterministic and unsigned, not cryptographic builder attestation; it may
  add rejection but can never replace or skip a finalizer check. Runtime derives
  one fixed root from `/proc/self/exe`, verifies the detached signature with the
  one embedded release anchor before protobuf parsing, requires deterministic
  reserialization to reproduce the exact signed bytes, then verifies every
  artifact through the retained descriptor identity later used for ELF
  inspection and loading. There is no archive-level signature, root/key
  override, directory scan, or unsigned bypass. Semantic provider meaning
  remains in the pure contract catalog; the inventory is provenance, not a
  second registry.
- Release authority: the DP runtime, architecture-neutral finalizer, and
  installation verifier consume one source-controlled public-anchor
  definition. Official binaries verify the platform owner's key. A downstream
  source builder who replaces that single definition and signs with the
  corresponding private seed becomes the release authority for those binaries.
  The inventory signature authenticates the exact `kinetum_dp` and provider
  closure only when a trusted verifier carrying that anchor evaluates it. It
  does not authenticate delivery of the runtime archive or verifier because
  the archive has no signature leg; the release channel owns that bootstrap.
  It also does not prevent a machine owner from building a different verifier.
  Provider components release as one platform unit, with no third-party
  component-signing leg.
- Release payloads and installation follow [Pat-23](#pat-23-release-projection-ownership).
  `kinetum_package` owns preparation, signing, installation, and private-seed
  generation. Producer and verifier share one manifest grammar; `kinetum-info`
  independently checks expected runtime membership. Every archived ELF carries
  the root-injected release marker. Native preparation runs in a disposable
  process without signing inputs. Signing reaps decoding before opening the
  protected seed, executes no target code, and retires the secret before writing
  the final runtime manifest. Archive checksums provide integrity under the
  release channel, not publisher authentication.
  Each generated installer binds one archive, checks host architecture and
  digest, and invokes that archive's native installer. The native owner retains
  old objects until installed verification and reports cleanup/restoration
  failures. Runtime owns root metadata and `bin/`, `lib/`, and `share/`; SDK owns
  only `sdk/`. Runtime preserves those SDK files and the separately owned
  build-only `dependencies/` peer, rejecting other unowned roots. Dependencies
  are neither a release component nor a runtime input.
  The private validation kit stays outside the prefix, explicitly selects a
  runtime, requires its protected `kinetum-info --check` result, and records
  strict metadata. No compatibility subset or kit attestation is implied.
  Deployment bundles contain configuration and modules, never platform
  binaries or provider releases.
- Two-phase apply (Pat-9): Prepare is the fallible validation/construction step;
  Activate commits only an exact prepared transaction.

**Where this appears.** `KINETUM_PACK.md` (deployment-bundle format and
verification), `GETTING_STARTED.md` (runtime/SDK package production and
installation), `DATA_PLANE.md` (snapshot identity),
`PROVIDERS.md` (typed configuration and installed component admission),
`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md` (CP-side hashing and
verification), `GLUON.md` (plan `plan_id` and `content_hash` identity
fields).

### Pat-18: Plan-Owned I/O Topology and Capability Gates

**Rule.** Process facilities, I/O-driver instances, packet-storage domains,
execution-provider instances, ports, streams, traffic steering, module-context populations,
and storage transitions are deployment-plan facts. A provider component may
map those facts to queues, rings, hardware steering tables, UMEMs, mempools, or
device work queues, but it must execute the exact compiled graph or reject it.
Runtime must not infer, downgrade, repair, or silently reshape provider
topology at startup.

**Rationale.** Inferred queues, execution, storage, facility sharing, or copies
can change the authored topology. Gluon lowers complete bindings; the shared
compiler validates the graph; providers reserve and construct native resources.

**Use instead.**

- Gluon emits explicit `process_facility_instances[]`,
  `io_driver_instances[]`, `packet_storage_domains[]`,
  `execution_provider_instances[]`, `storage_transitions[]`, `ports[]`,
  `stage_instances[]`, `io_streams[]`, `traffic_steering_profiles[]`,
  `module_context_domains[]`, worker/service placements, and cross-worker
  `boundaries[]`.
- Every provider configuration is a role-correct canonical `Any` under the
  pure contract catalog. Provider instance and facility-reference arrays are
  exact, deterministic, and validated in both directions; no provider enum,
  target-string inference, free-form native argument list, or installation
  order supplies missing meaning.
- One shared cold-path compiler validates exact facilities, workers, streams,
  queues, sources, sinks, reachable storage domains, execution access,
  transition-set equality, participant DAG, runtime-service and lifecycle NUMA
  coverage, steering, bounded transition policy, and packet-buffer floors.
  Gluon self-checks its emission through that compiler; Quark and DP consume
  the same compact artifact instead of rebuilding structural truth.
- Access-agent identity does not imply packet shape. Storage and execution
  projections state contiguous CPU read and write independently, and the
  compiler proves the exact requirement for every reachable domain. Writable
  cloning is a separate graph fact required only by unconditional fan-out with
  more than one successor; a linear path carries no speculative clone gate.
- RX allocation belongs to the individual queue; TX admission is an explicit
  nonempty domain set validated by the owning provider. Original storage owns
  reclamation across workers and mixed TX bursts. An explicit edge conversion
  takes precedence over direct admission; no missing compatibility proof may
  trigger an inferred copy or alternate egress.
- Runtime materialization publishes role-separated immutable hot tables:
  driver RX bursts, driver TX bursts, storage-domain clone/originate/release
  operations, and explicit transition operations. Core routing and boundaries
  carry one `packet_record*`; provider-native handles stay inside its opaque
  storage descriptor. One component may implement several roles, but the plan
  and hot contracts remain separate.
- An I/O-driver factory reserves and configures one cold complete driver; it
  cannot make ingress live. The exact ABI supplies mandatory whole-driver
  activation and deactivation. After every module owner activates and every
  worker reports `RUNNING` behind the closed packet-body gate, the generation
  owner activates the canonical driver set, publishes `PACKET_READY`, and only
  then releases packet execution. Shutdown closes worker source polling,
  drains and joins the worker DAG, then deactivates drivers in reverse order
  before retiring their storage, facility, or component dependencies. A
  partial activation rolls back its exact prefix; unprovable rollback or
  retirement fails stop.
- Every packet-storage and bounded-copy capacity is derived through the shared
  checked `plan_buffer_budget` authority. The compiler supplies the exact
  aggregate active worker queues, source future-role queues, boundary DATA and
  future-output populations, bounded-copy staging, descriptor, burst, cache,
  and safety terms. A boundary term is charged to each post-transition carried
  storage domain once, even when several source-domain paths converge. No
  provider or development transport earns a parallel capacity formula.
- Every module context carries one exact nonzero context-lifetime capacity and
  one exact nonzero per-epoch arena capacity lowered from its lane-local
  deployment binding. The shared compiler derives overflow-checked per-NUMA
  totals and multiplies epoch memory by `EXACT_EPOCH_SLOT_COUNT`; lifecycle
  allocation enforces those compiled limits. Zero is rejection, not a default,
  and neither module configuration nor the runtime may manufacture a missing
  value.
- An authored queue descriptor count is also a physical ownership bound, not
  budget-only metadata. A provider allocates the exact bounded descriptor
  structure before publication, reserves any queue-held packet credits
  transactionally, consumes only an accepted prefix, and returns every retained
  credit at teardown. A narrower operation ABI bounds each call, not the plan's
  wider queue population: providers split cold reservation, release, and native
  I/O into exact checked chunks and never narrow the aggregate count.
- Host validation consumes compiled external requirements only. It rejects
  unknown or mismatched CPU/NUMA/device evidence and never filters placements,
  reconstructs native arguments, or repairs the graph. Native capability
  checks that require initialized facility state remain inside the
  transactional materializer.
- A development provider uses the same contract, compiler, component,
  materialization, and ownership path as every production provider. Simpler
  mechanics do not create a simpler truth model.

**Where this appears.** `GLUON.md` (lowering and deterministic plan
shape), `PROVIDERS.md` (compiled provider topology and transactional
materialization), `DATA_PLANE.md` (worker integration), `QUARK.md` (strict
host-evidence gates),
`VALIDATION_GUIDE.md` (physical-I/O validation artifacts).

### Pat-19: Link-Closed Module Images

**Rule.** A module shared object is a closed image, not a partial program that
expects the host to complete its SDK implementation. Compile implementation
symbols hidden by default, expose only deliberate ABI entry points, keep
static-archive symbols out of the dynamic export surface, and reject every
unresolved non-weak import at link time. Load each canonical main image with
immediate local binding. An unloadable image must not publish constructor-owned
process-global registrations that retain pointers into the image after
`dlclose` without an exact unregister protocol.

**Rationale.** Accidental host imports make module loading depend on the
executable's export table. Process-global registries can retain pointers after
image unload. Link closure and image-local mechanisms remove those dependencies
and give C and C++ modules the same lifetime contract without cloning runtime
state or moving the registry into a sidecar.

**Use instead.**

- Keep fixed C SDK mechanisms image-local in the C11-compatible ABI header.
- Keep one canonical public header tree under `include/kinetum/`; repository
  and installed consumers use the same `<kinetum/...>` spelling, and packaging
  copies rather than rewrites that authority.
- Use hidden visibility by default and explicit default visibility only for
  `kinetum_module_register`.
- Apply `-z defs` and archive-export exclusion through one module-target
  helper and through both installed discovery mechanisms.
- Disable GNU-unique binding for module-owned C++ implementation and shared
  dependency objects so exact loader ownership remains reclaimable.
- Require every additional module dependency to preserve that generation
  lifetime; process-lifetime dependency ownership is not an unload strategy.
- Load only canonical main-image paths with `RTLD_NOW | RTLD_LOCAL`.
- Keep generated protobuf registries in host/offline authoring tools when the
  runtime image is unloadable; use a strict image-local parser for its opaque
  configuration contract.
- Make every module-facing algorithm function header-owned or an explicit
  installed dependency. Never depend on a symbol supplied only by an in-tree
  host executable or archive.
- Include main images and all shared dependencies in package/bundle integrity
  manifests; missing or symlinked declared artifacts fail before output
  construction.
- Keep descriptor validation private to the loader; modules return descriptors
  but do not decide host admission policy.
- Link and load a genuine C11 canary module, then compare architecture-selected
  SIMD behavior against an independent scalar oracle.
- Require built-in modules to use this same public path. An in-tree module is a
  conformance target, not permission for a host-only shortcut.
- Apply the same link-closure law, through a distinct stricter ABI, to provider
  components. One C11-compatible header owns every provider layout and C
  callback; the exact ABI identity is generated from that header and the
  complete provider-contract schema set. A hardened component exports only
  unversioned `kinetum_provider_component_query`, has no SONAME, loader search
  path, executable interpreter, loader-redirection/interposition tag, or
  dynamic flag other than immediate binding, and echoes the exact
  product/ABI/component/contract identities.
- Admit provider code only from the release-signed installed inventory. Open
  and hash an exact fixed-layout artifact through a retained symlink-free
  descriptor, inspect the same inode with libelf/GElf, preload its verified
  private dependency graph children before parents, and load through
  `/proc/self/fd/N` with `RTLD_NOW | RTLD_LOCAL`. Finish every global duplicate
  and closure check before the first foreign load; a failure after that point
  is process-fatal because constructor and loader state cannot be rolled back.
- Keep provider semantics, artifact provenance, and requested implementation
  availability in three separate immutable authorities: the pure contract
  catalog, authenticated installed inventory, and sealed runtime catalog.
  Neither static registration nor filesystem discovery may connect them.

**Where this appears.** `MODULE_SDK.md` (author and installed-build contract),
`DATA_PLANE.md` (canonical module loading), `PROVIDERS.md` (provider-component
provenance and admission),
`include/kinetum/kinetum_sdk.h` (C11 image-local mechanisms),
`src/provider/provider_component_abi.h` (exact provider ABI),
`src/provider/provider_inventory.cpp` and
`src/provider/provider_component_admission.cpp` (signed provenance and
held-descriptor admission),
`cmake/KinetumModulePolicy.cmake` and
`cmake/KinetumProviderComponentPolicy.cmake` (shared in-tree/installed image
policies),
`kinetum_configure_module_target` / `Kinetum::ModuleDependency`, and the built-in
module CMake targets.

### Pat-20: Provider Dependency Firewall

**Rule.** Platform core and generic tests must compile without any
provider-native header, compile definition, library, or native identity. One
provider-owned implementation target owns the complete native dependency
closure. Production component membership is source-controlled and never
changes common C/C++ semantics; runtime provider choice comes from admitted
plan truth, not a preprocessor branch or reduced build. Immutable direction,
queue ownership, and capability facts are proved once during cold
materialization and consumed as pre-resolved burst tables.

**Rationale.** Native headers in common code make one provider's types, macros,
and link requirements platform-wide dependencies. Cold admission and private
targets keep those dependencies local. Rechecking direction or sampled link
state per packet adds a stale gate that can contradict the admitted queue.

**Use instead.**

- Put native source, headers, definitions, and libraries in one provider-owned
  implementation or exact component target. Use a canonical imported target
  for the native dependency closure. Produce that target from verified source,
  exact release/path-normalized configuration, declared archive/driver
  membership, and the native headers' forced-include/ISA contract; never infer
  a closure by parsing package-manager linker strings or coercing every
  external dependency to static linkage.
- Keep provider-neutral records, lifecycle state, statistics shapes, and
  operation contracts in core. Core may hold an opaque native handle but may
  neither name nor interpret it.
- Express source, compile, and link ownership in the build graph. Do not make
  production provider membership a cache option or spread an enabled-provider
  macro through common translation units.
- Resolve direction, enabledness, physical queue ownership, and native
  capabilities before publication. Packet execution performs only compact
  bounds checks and pre-resolved grouped operations; it does not poll a
  provider registry or link-state gate.
- Keep driver construction and packet admission distinct. Provider factories
  publish cold operation records; one provider-neutral generation owner calls
  the exact whole-driver lifecycle only at the set-wide startup and shutdown
  boundaries. RX/TX burst operations remain branch-free and carry no dormant
  lifecycle selector on the packet path.
- Claim each successfully established native resource in non-failing
  provider-local state before the next fallible native operation. Unwind failed
  startup in reverse dependency order, and fail stop before reclaiming backing
  storage when exact device/queue retirement cannot be proven.
- Use compact compiled worker identity in generic logs, RPCs, statistics, and
  lifecycle state. Native thread/lcore/queue identities stay in
  provider-private diagnostics.
- Publish a provider observation source only after its complete borrowed
  generation. Invoke it under an explicit generation claim but with no
  platform lock held; retirement detaches the source, fences old waiters,
  quiesces the active claim, and destroys it before the generation owners.
  Observation identity comes from immutable compiled facts, not launch-mutated
  worker containers.
- Compile generic test translation units without native usage requirements and
  native tests in the provider component's private compile domain. They may
  share one executable; process count is not compile-domain evidence. Split a
  process only for a declared process-state precondition. DPDK native tests use
  `kinetum_provider_dpdk_tests` because EAL, ethdev, mempool, and PMD
  registration are process-global; that image links the exact component
  closure and never loads the component, while generic `kinetum_tests` carries
  no DPDK usage requirement.
- Keep the dependency firewall compiler-enforced in the one complete build:
  native include/link requirements remain PRIVATE to component and native-test
  targets, the production dataplane final link carries no provider component or
  native-library closure, and ELF/`DT_NEEDED` audits reject forbidden
  implementation edges across the runtime, test, and component boundaries.
  Source sweeps are secondary evidence, not a substitute for those structural
  gates.
- A provider component is the sole implementation owner. Do not retain an
  incumbent linked copy beside it or create a reduced-runtime configuration as
  a firewall test.

**Where this appears.** `PROVIDERS.md` (target graph and materialization),
`DATA_PLANE.md` (worker identity and statistics lifetime), `CODING_GUIDELINES.md`
(source/target ownership rules), root `CMakeLists.txt`, exact provider-component targets,
private generic/native test compile domains, and the production ELF firewall
audit.

### Pat-21: Linear Ownership Across Foreign Calls

**Rule.** A call into module, provider, allocator, logger, or other foreign code
must have one explicit owner before entry and one exact terminal disposition
after return. Do not hold a platform mutex, queue gate, launch lock, or
condition-variable lock across the call. Stage immutable inputs under the
platform lock, release it, invoke foreign code, then reacquire only to validate
and publish the result.

When a callback spans time, represent the transfer with a move-only claim or
token. The claim identifies its issuing store, operation, generation, and
resource. Only the issuing owner may resolve it; unresolved destruction is
terminate-class. A borrowed foreign view is read-only. Successful callback
completion is an explicit claim transition, never inferred from an empty nested
value after the callee had permission to move it.

Cooperative cancellation closes new admission but does not erase an accepted
call. Publish cancellation through stable operation state, collect every
accepted result, and retire any state produced by a success after cancellation.
If the plan-authored grace expires while ownership is uncertain, fail stop
without reclaiming the dependency.

**Where this appears.** Module PREPARE/RETIRE claims, active asynchronous
tokens, health invocation claims, provider observation claims, package helper
process ownership, and CP queue contexts all use this pattern. Their mechanics
live in `MODULE_SDK.md`, `DATA_PLANE.md`, and
`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`.

### Pat-22: Predicate-Closed Waiting

**Rule.** A condition-variable predicate and every update that can make it true
participate in one mutex protocol. Check the predicate while holding that
mutex, publish predicate-changing queue or state updates under the same mutex,
then notify. An atomic store followed by notification does not close the
check-to-wait gap.

Foreign calls remain outside the predicate mutex. Reacquire only to publish the
completed result. A bounded queue carrying a pointer to caller-owned context
transfers one linear borrow on successful enqueue; the consumer resolves it
under the predicate protocol, and the producer waits unconditionally. A timed
or cancellable return requires separately owned context that outlives the
caller.

An `eventfd` or similar descriptor is wake-only. Its coalesced count is not an
ownership or completion count. On every wake, including a spurious one, the
sole consumer drains the bounded owning queues until empty.

**Where this appears.** CP mutation submission, data-plane command mailboxes,
lifecycle executor result service, and release helper process coordination use
this pattern. Focused tests cover publication-before-wait, backpressure,
shutdown, spurious wake, and terminal drain.

### Pat-23: Release Projection Ownership

**Rule.** Declare shipped target and file membership once, then derive every
build aggregate, install component, generated path list, manifest, verifier,
archive, and documentation projection from that authority. A package verifier
may carry an independent expected-set assertion, but it is a consumer check,
not another producer list.

Runtime and SDK are the public products. The private validation kit is separate
integration tooling outside the installed runtime prefix. Install components
are explicit and excluded from an unqualified install. Before replacement, the
native installer verifies a complete private package tree and exact manifest;
after replacement it verifies the installed destination. The POSIX download
entry owns prerequisite/download custody, a complete-before-effects script
body, and child input detached from that script. Its native child receives a
closed command, locale, and loader environment.

Third-party notices follow bytes, not build-graph proximity. A package receives
the license material required by what it redistributes. A build-only tool or a
dynamically consumed system dependency is inventoried centrally but is not
copied into an unrelated payload. Generated documentation is a separate website:
its static assets, license material, version, and complete page-time reference
closure are verified by the documentation producer. Independent adversarial
expectations test that semantic contract, and its build manifest binds source
and complete output identities before website publication. Remote, root-relative, escaping,
missing, malformed, and alternate-base references reject; every local asset
resolves from its containing file to one regular member of the same admitted
site. An existing generated directory is replaced only by atomically
exchanging it with a completely validated same-parent candidate;
published-identity failure restores the prior validated tree before the
producer returns its original error.

CMake owns build creation, configuration, and compilation. Package preparation
consumes one explicitly selected existing build and uses CMake's package
staging admission. The staged packager must match the invoking image before
compiled projections authorize native preparation. The source location comes
from that build; signing consumes an explicit candidate and key
without a source or build input. Archive output defaults to invocation-relative
`./dist`, with an explicit directory override and creation of missing parents.
This container is distinct from the committed archive; an empty output directory
may remain after failure. A supplied installation digest is always checked,
while the download bootstrap always supplies its published expected digest.

CPU targeting is a build contract. Native builds and builds for a declared
instruction-set baseline both use the same packaging and integrity mechanisms.
Public distribution qualifies the exact baseline build; a locally produced
native package retains its machine-specific CPU requirements. Package creation,
an architecture label, and a download URL do not establish CPU compatibility.
Changing the instruction set can change compile-time SIMD selection, so release
qualification includes generated-code inspection and performance measurement
for those exact bytes. Installed SDK interfaces leave the module author's CPU
target under that author's build authority. Compiler semantics and the related
packet-processing build patterns are indexed in `TECHNICAL_REFERENCES.md`.

Final release archives follow the file form of the same law. Each preparation
or signing operation produces one archive. Every final archive has its own
checksum and package-specific installer from one template by
identity/URL/digest substitution only. An optional publisher URL enables
downloads; its absence requires an explicit local archive directory. The same
installer serves released and locally built packages. No package requires
another product, architecture, or rendered site. A changed URL changes the
installer's identity and cannot replace an existing different output.

The producer completes and bounds all private files before any public name.
It preflights existing requested outputs and reports intended paths before
publishing companions. Private-work cleanup precedes the final archive commit.
All publications use no-replacement semantics: byte-exact existing or
race-created outputs converge, while foreign bytes remain untouched and fail.
An interrupted operation can leave complete companions without its archive;
an exact retry completes that prefix. Existing valid archives remain owned by
their prior successful operation. Success requires every output requested by
the current invocation, with nothing fallible after its final archive commit.
No transaction across independent packages or remote uploads is implied.
Secret-file generation always refuses an existing target, including a
byte-identical one.

**Where this appears.** Root `CMakeLists.txt`,
`tooling/release/packaging/kinetum_package.cpp`, the shared C++ manifest/runtime
verifiers, and standalone SDK consumer fixtures consume this rule. The package
workflow is in `GETTING_STARTED.md`; the website workflow is in
`DOCUMENTATION_GUIDE.md`.

---

## Pattern Application Matrix

An `X` marks a pattern required by that component's hot path or correctness
contract. A blank means it does not apply, typically on a cold-path surface.

| Pattern | SDK | DP | Modules | Algo | CP | Gluon | Quark | Photon |
|---------|-----|----|---------|------|----|----|----|----|
| Pat-1: No hot-path allocation | X | X | X | X | | | | |
| Pat-2: No hot-path locks | X | X | X | X | | | | |
| Pat-3: No hot-path shared_ptr/exceptions/virtual/RTTI | X | X | X | X | | | | |
| Pat-4: SoA batch | X | X | X | | | | | |
| Pat-5: Cache-line alignment | X | X | X | X | | | | |
| Pat-6: NUMA / hugepages | | X | | | | X | X | |
| Pat-7: Owner-local + generation scoping | X | X | X | | | | | |
| Pat-8: RCU / versioned RCU / exact QSBR | X | X | X | X | X | | | |
| Pat-9: Aligned atomics / lock-free | X | X | X | X | X | | | |
| Pat-10: Epoch sequencing / ordered CUT-ACK barrier | X | X | X | | X | X | X | |
| Pat-11: Bounded queues / SPSC rings | | X | | X | X | | | |
| Pat-12: Cuckoo map | | | X | X | | | | |
| Pat-13: Token / leaky bucket | | | X | X | | | | |
| Pat-14: Timer wheel | X | X | X | X | | | | |
| Pat-15: Health as feedback loop | X | X | X | | X | | | |
| Pat-16: Profiling discipline | X | X | X | X | X | X | X | X |
| Pat-17: Content identity / verification | | X | | | X | X | | X |
| Pat-18: Plan-owned I/O topology / capability gates | | X | | | | X | X | |
| Pat-19: Link-closed module images | X | X | X | | | | | |
| Pat-20: Provider dependency firewall | | X | | | | | X | X |
| Pat-21: Linear ownership across foreign calls | X | X | X | | X | | | X |
| Pat-22: Predicate-closed waiting | | X | | X | X | | | X |
| Pat-23: Release projection ownership | X | X | X | | | | | X |

Notes:

- Hot-path patterns (Pat-1 through Pat-5) apply to SDK, DP, Modules, and
  Algo. Cold-path components (CP, Gluon, Quark, Photon) do not pay the
  same cost and the patterns are not load-bearing for them.
- `Modules` covers built-in modules (ACL, NAT44, QoS) and customer
  modules. Both use the same SDK surface (mechanism vs policy, P-1).
- Pat-13 applies to modules through the rate-limiting discipline. QoS uses
  a module-specific policer with the same token-bucket semantics rather
  than the generic `token_bucket` helper.
- Pat-14's SDK/DP/module cells name the exact active-scheduler
  contract. Production active workers consume one caller-storage timer wheel;
  the built-in ACL/NAT44/QoS modules remain passive and do not use it for
  internal maintenance.
- Pat-17 also applies to `KINETUM_PACK.md`; the matrix has no packer column, so
  pack's producer self-gate and standalone verification are named in the
  delegation index instead. Photon's cell records its pre-spawn runtime-bundle
  admission.
- Pat-16 applies to every component: every change is measured.
- Pat-18 applies to validation tooling through `VALIDATION_GUIDE.md`; the
  matrix names the runtime and planning surfaces that own the mechanism.
- Pat-19's DP cell is the private loader/admission side of the contract; its
  SDK and Modules cells are the header, image, and build-link sides.
- Pat-20 applies to Quark and Photon because their host-validation and startup
  contracts remain provider-neutral; native implementation closure remains a
  provider-component and release-aggregate responsibility.
- Pat-21 and Pat-22 apply wherever a thread or process temporarily transfers
  work while retaining ultimate lifetime authority.
- Pat-23's cells name product bytes. Release tooling and validation are its
  owning cold mechanisms even though they are not separate matrix columns.

---

## Delegation Index

PEG owns the principles and patterns; these component references own their
mechanics, behavior, and operator detail.

| Topic | Owner doc |
|-------|-----------|
| Pipeline IR, validation, embedding API | `AXIOM.md` |
| Planning algorithms, region partitioning, plan format | `GLUON.md` |
| Host CPU/NUMA and process-allowed memory evidence; strict runtime compatibility | `QUARK.md` |
| Supervisor boot, readiness, restart policy, and pair cleanup | `PHOTON.md` |
| Cold diagnostics, record format, file ownership, rotation, and logging health | `LOGGING.md` |
| DP process lifecycle, hot path, boundary protocol, two-phase apply (DP side), module hosting | `DATA_PLANE.md` |
| CP process lifecycle, mutation pipeline, snapshot store, guardrails runner, commit-confirmed, rollback | `CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md` |
| Module ABI, descriptor, batch layout, telemetry, health, lifecycle hooks | `MODULE_SDK.md` |
| Module-image symbol closure and installed SDK build policy | `MODULE_SDK.md`, `CODING_GUIDELINES.md` |
| Typed provider configuration, pure contract catalog, and capability projections | `PROVIDERS.md` |
| Exact provider ABI, signed installed inventory, held-artifact admission, and sealed runtime catalog | `PROVIDERS.md` |
| Provider target firewall, materialization, native identity, and ELF link audit | `PROVIDERS.md`, `CODING_GUIDELINES.md` |
| Bundle format, manifest, packer, verifier | `KINETUM_PACK.md` |
| Operator CLI: apply, confirm, rollback, guardrails, stats | `KINETUMCTL.md` |
| gRPC wire format and schemas | `GRPC_API.md` |
| Physical-I/O validation runner, benchmark harness, boundary validation under load | `VALIDATION_GUIDE.md` |
| Onboarding and Day 0-4 deployment lifecycle | `GETTING_STARTED.md` |
| Plan-owned facilities, I/O, storage, execution, transitions, steering, and capability gates | `GLUON.md`, `PROVIDERS.md`, `QUARK.md` |
| Vocabulary and component model | `CONCEPTS.md` |
| Algorithm primitives (cuckoo, RCU/QSBR, SPSC, token bucket, timer wheel, SIMD) | `docs/ALGORITHM_LIBRARY.md` |
| Built-in modules (ACL, NAT44, QoS) implementation, config schema, hot path | `src/modules/README.md` |
| End-to-end and ordered-CUT diagrams | `docs/diagrams/README.md`, `docs/diagrams/ordered_cut_boundary_protocol.md` |
| Coding conventions: naming, comments, file structure, error handling | `CODING_GUIDELINES.md` |
| Foreign-callback claims, cancellation, and predicate-safe waits | `MODULE_SDK.md`, `DATA_PLANE.md`, `CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md` |
| Runtime/SDK package production, installation, roots, and manifests | `GETTING_STARTED.md`, root `CMakeLists.txt`, release packaging sources |
| Website production and asset attribution | `DOCUMENTATION_GUIDE.md`, documentation producer |

---

## Technical References

[`TECHNICAL_REFERENCES.md`](TECHNICAL_REFERENCES.md) collects normative
specifications and technical background. Pattern sections own Kinetum's rules.
