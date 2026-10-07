# Kinetum Algorithm Library

`include/kinetum/algo/` provides public C++ algorithms and utilities for the
platform, modules, tests, and C++ SDK. C++ modules obtain them through
`<kinetum/kinetum_sdk.hpp>`; the C SDK, `<kinetum/kinetum_sdk.h>`, remains
self-contained. This guide covers header ownership, usage, correctness, and
packet hot-path safety.

## Table of Contents

1. [Design Rules](#design-rules)
2. [SDK Boundary](#sdk-boundary)
3. [Header Index](#header-index)
4. [Include Pattern](#include-pattern)
5. [Hot-Path Classification](#hot-path-classification)
6. [Core Primitives](#core-primitives)
7. [Source Usage](#source-usage)
8. [Module Linking Notes](#module-linking-notes)
9. [Duplicate And Local-Code Rules](#duplicate-and-local-code-rules)
10. [Where To Read Next](#where-to-read-next)

---

## Design Rules

1. Public primitives for Kinetum's little-endian x86-64 and AArch64 targets
   live in `include/kinetum/algo/`.
2. Hot-path primitives are header-only or inline where practical.
3. Hot-path containers must avoid allocation after construction.
4. Cold-path helpers may use STL storage and heap allocation when the cost is
   explicit in this document.
5. Header contracts and this guide change together; neither is a compatibility
   layer for the other.

## SDK Boundary

| Consumer | Include path | Notes |
|----------|--------------|-------|
| Pure C module | `<kinetum/kinetum_sdk.h>` | Self-contained C ABI; does not include C++ algorithm headers. |
| C++ module | `<kinetum/kinetum_sdk.hpp>` | Includes `<kinetum/algo/algo.hpp>` and makes algorithm utilities available. |
| Built-in module | Direct `<kinetum/algo/...>` includes | ACL, NAT44, and QoS use the same primitives as customer C++ modules. |
| Platform runtime | Direct `<kinetum/algo/...>` includes | DP, CP, Gluon, Photon, Quark, and tests include the headers they need. |

The C SDK defines the C-compatible branch hints and image-local ABI mechanisms
it needs because it cannot depend on C++ headers. Hash algorithms remain in the
C++ algorithm surface or in exact module-owned implementations.

## Header Index

| Header | Owns | Hot-path status | Owner and use |
|--------|------|-----------------|------------------------|
| `algo.hpp` | Master include for all algo headers. | Depends on included header. | C++ SDK wrapper and convenience includes. |
| `aligned_atomic.hpp` | Cache-line-isolated lock-free integral atomics and explicit relaxed counter operations. | Hot-path safe. | Installed reusable API with direct primitive evidence; no platform-runtime dependency. |
| `platform.hpp` | Architecture detection, cache-line constants, branch hints, inline/hot/cold attributes. | Hot-path safe. | DP, Gluon, built-in modules, and public algorithm headers. |
| `hash.hpp` | FNV-1a constants and SplitMix64 integer mixing. | Hot-path safe. | Built-in modules use FNV constants for field-wise hashes; cuckoo candidate selection consumes SplitMix64. |
| `bits.hpp` | `popcount`, `clz`, `ctz`, power-of-two helpers, bit masks. | Hot-path safe. | Cuckoo capacity rounding and direct SDK consumers. |
| `atomic_index_pool.hpp` | Fixed concurrent index leases with independent atomic-bit release. | Bounded acquisition; one atomic RMW per release; no allocation. | Cold logging record arena. |
| `bounded_index_pool.hpp` | Fixed-capacity owner-local recycling for zero-based uint32 indices. | Acquire/release are O(1), allocation-free, and nonthrowing after construction. | NAT44 session slabs and QoS flow slabs. |
| `compact_index_set.hpp` | Fixed-universe dense membership for zero-based compact identities. | `contains()` is hot-path safe after cold construction. | DP pre-resolved stage/storage reachability. |
| `prefetch.hpp` | Five fixed-cost compiler prefetch macros. | Each macro is hot-path safe. | ACL, NAT44, QoS, cuckoo map, SIMD classifiers. |
| `signal.hpp` | Finite-input EWMA, hysteresis, and explicit-time rate calculator. | Cold/control path. | CP consumes EWMA/hysteresis; the rate calculator is an installed tested primitive. |
| `control.hpp` | Finite-input PID controller with derivative options and transactional anti-windup. | Cold/control path. | Installed reusable API; no platform runtime consumer. |
| `rcu_buffer.hpp` | `rcu_buffer<T>` and `versioned_rcu_buffer<T>`. | Reader side is hot-path friendly; writer side is cold path. | CP published state and guardrails policy buffer. |
| `single_writer_snapshot.hpp` | Fixed-width coherent publication from one owner to foreign observers. | Publish only at a bounded owner boundary; never per packet. | DP runtime-status, transition-coordinator progress, and packet-worker epoch-ledger publications. |
| `quiescence.hpp` | Caller-placed exact readers plus one immutable backend-neutral grace domain. | One reader-local atomic publication per requested grace; domain scans are cold path. | DP global transition certificate and completion owner; fixed Bootstrap leaves the domain grace-inactive until the live trigger. |
| `cache.hpp` | Intrusive LRU list, heap-backed LRU cache, cache-line allocation. | `lru_list` can be allocation-free; `lru_cache` is cold/read-mostly only. | Available through C++ SDK; no packet hot-path production dependency. |
| `queue.hpp` | Static, owning-runtime, and caller-storage SPSC rings; static/runtime-capacity MPMC queues; caller-storage single-owner work queues. | All queue operations are allocation-free after construction under their exact ownership model. | NUMA-composed DATA boundaries, worker active/future staging, active control mailboxes, boundary future holds, lifecycle channels, fixed host packet-pool credits, and UDP/development queues. |
| `bounded_service_order.hpp` | Caller-storage fair service with bounded carried allowances. | Single owner; O(1) order updates and input-count-bounded turns. | Worker RX and inbound DATA admission. |
| `ratelimit.hpp` | Exact-rational token bucket, leaky bucket, and sliding window. | Hot-path safe after construction. | Available to modules; built-in QoS uses one context-local module policer. |
| `net.hpp` | Big-endian reads/writes, protocol constants, and RFC 1918 classification. | Hot-path safe. | DP IPv4 parsing and NAT44/QoS packet work. |
| `cidr.hpp` | Header-owned IPv4/CIDR parsing, formatting, and matching. | `match_cidr` is hot-path safe; parsing/formatting are cold path. | ACL and NAT44 config parsing; ACL matching; installed C++ SDK. |
| `condition_parse.hpp` | Shared parser for `field op decimal_uint32` edge-condition syntax. | Cold path. | Axiom authoring-time validation and DP route compilation. |
| `graph.hpp` | Identity-only DAG and deterministic topological sort with exact blocked-node evidence. | Cold path. | Axiom cycle checks and canonical order consumed by Gluon. |
| `cuckoo.hpp` | Bucketed cuckoo map requiring an explicit semantic hasher. | Lookup is hot-path safe after construction; writes require external synchronization. | NAT44 session maps, QoS bucket map, available to modules. |
| `simd_classify.hpp` | SoA packet batch format and SIMD/scalar batch classifiers. | Hot-path safe. | ACL SIMD batch path for large rule sets. |
| `timer_wheel.hpp` | Static and caller-storage runtime-capacity hierarchical timer wheel. | Hot-path safe for one owner after construction. | One exact timer wheel per packet worker with active instances. |

## Include Pattern

Use the narrow header when possible:

```cpp
#include <kinetum/algo/cuckoo.hpp>
#include <kinetum/algo/net.hpp>
#include <kinetum/algo/queue.hpp>
```

Use the master include only for SDK-facing C++ module code or tests that need
the whole set:

```cpp
#include <kinetum/algo/algo.hpp>
```

## Hot-Path Classification

| Primitive | Hot-path use | Constraint |
|-----------|--------------|------------|
| `aligned_atomic` operations | Yes | Value type is integral and always lock-free; relocation is cold and exclusive. |
| `platform.hpp` macros | Yes | Compile-time helpers only. |
| `hash.hpp` constants and `splitmix64` | Yes | Caller owns semantic field selection and collision policy. |
| `bits.hpp` helpers | Yes | Inline/constexpr. |
| `atomic_index_pool` | Cold/control use in the platform | Bounded concurrent acquisition can reject under contention; packet workers retain their admitted owner-local storage. |
| `bounded_index_pool` | Yes | Complete PMR index storage is fixed during construction; one owner acquires and releases exact slab indices. |
| `bounded_service_order` | Yes | Caller-owned cells, one owner, at most two visits and one quantum of work per input per turn. |
| `compact_index_set::contains` | Yes | Complete storage is allocated and populated before publication. |
| `prefetch.hpp` macros | Yes | One caller-selected address per hint; correctness and ordering cannot depend on prefetch. |
| `queue.hpp` SPSC rings | Yes | Exactly one producer and one consumer. |
| `queue.hpp` dynamic MPMC queue | Yes | Construction-time power-of-two storage; `size_approx()` is observation, never reservation. |
| `work_queue_view` | Yes, within one owner thread | Caller-owned storage; not a cross-thread queue. |
| `cuckoo_map::find` | Yes | Safe only when concurrent writers are excluded. |
| `ratelimit` buckets | Yes | Caller passes monotonic `now_ns`; regression rejects without credit mutation. |
| `net.hpp` byte-order helpers | Yes | Caller guarantees buffer length. |
| `algo::match_cidr` | Yes | CIDR must already be parsed and valid. |
| `condition_parse.hpp` | No | Route predicates are compiled before runtime packet admission. |
| `simd_classify` batch functions | Yes | Caller owns batch construction and result buffers. |
| `timer_wheel` | Yes | Single owner; not thread-safe. The runtime uses one per active worker. |
| `rcu_buffer` reader guard | Usually | Reader cost is atomic pin/unpin; writer waits for grace period. |
| `single_writer_snapshot` | At loop/batch boundaries only | Exactly one writer; payload fields are atomic and observations have bounded retries. |
| `quiescence_reader::publish_quiescent` | Transition safe points only | One exact active grace generation; never call per packet or on the fixed steady turn. |
| `cache.hpp::lru_cache` | No | Uses `std::unordered_map` and heap allocation on insert/evict. |
| `graph.hpp` | No | Planning/validation only. |
| `signal.hpp` / `control.hpp` | No | Telemetry, health, and explicit control-loop use only. |

## Core Primitives

### `aligned_atomic.hpp`

`aligned_atomic<T>` owns one always-lock-free integral atomic on one complete
cache line. Its ordinary load, store, add, and exchange methods preserve the
caller's memory-order choice; `load_relaxed`, `store_relaxed`,
`fetch_add_relaxed`, and `inc_relaxed` make owner-counter intent explicit.
Cold move construction and assignment sample an unpublished source without
changing it so a standard container can relocate a counter array. Relocation
is not a concurrent operation and must complete before publication.

### `platform.hpp`

`platform.hpp` admits only GNU-compatible little-endian x86-64 and AArch64
compilation, then provides shared branch hints, alignment constants,
architecture-selected SIMD feature macros, and function attributes. It is the
C++ runtime counterpart to the pure C SDK's local macros. Scalar SIMD code
remains a valid compile-time ISA selection within those architectures; it is
not a generic target fallback.

C++ runtime and modules use `<kinetum/algo/platform.hpp>`; pure C modules use
`<kinetum/kinetum_sdk.h>`.

### `hash.hpp`

`hash.hpp` provides only the FNV-1a offset/prime constants and `splitmix64`
integer mixing. It owns no generic object, flow, shard, or hash-combine policy.

ACL and NAT44 use the FNV constants with field-wise hashers that respect their
protocol-specific keys and exclude padding.

### `bits.hpp`

`bits.hpp` owns small integer primitives:

- `popcount32`, `popcount64`.
- `clz32`, `clz64`, `ctz32`, `ctz64`.
- `is_power_of_2`.
- `next_power_of_2_32`, `next_power_of_2_64`.
- `bitmask` and `extract_bits`.

These are inline/constexpr helpers used by cuckoo capacity rounding and direct
SDK consumers.

### `atomic_index_pool.hpp`

`atomic_index_pool<Capacity>` owns one availability bit for each compact index.
Acquisition scans at most `ceil(Capacity/64)` cache-line-separated words and
attempts one CAS per nonempty word. It may reject under contention without
waiting. Release publishes prior object access through one atomic RMW;
returning one index never depends on another consumer completing a queue
operation. Releasing an out-of-range or already-free index terminates. Each lease's caller
owns object lifetime, and every caller retires before pool destruction.

The cold logger composes this arena ownership with the existing MPMC queue for
completed record indices. Packet-worker pools retain their own admitted
ownership mechanisms.

### `bounded_index_pool.hpp`

`bounded_index_pool` owns availability for one fixed zero-based uint32 index
population. Its constructor requires an explicit PMR resource, allocates and
reverse-initializes the complete array once, and permits zero capacity as an
always-exhausted pool. One owner then uses `try_acquire()` and `release()` by
moving a plain stack cursor; the vector never changes size after construction.

Invalid release or release into a full pool emits a fixed bounded diagnostic
and terminates. The caller's preallocated slab owns objects and occupancy;
the pool tracks available indices without a second occupancy bitmap. NAT44 and
QoS check each recycled slab entry before reuse.

### `compact_index_set.hpp`

`compact_index_set` owns fixed-universe dense membership for zero-based compact
identities. Its constructor allocates the complete `ceil(value_limit / 64)`
word array. One cold owner inserts each exact identity before publication;
duplicate or out-of-range insertion rejects. Published `contains()` calls use
one bounds check and one word-mask test without allocation or search.

The DP compiles each stage's sorted reachable-storage set into this O(1) gate.
The sorted vector remains compiler and cold-validation authority; the compact
set is an immutable runtime projection.

### `bounded_service_order.hpp`

`bounded_service_order` borrows fixed caller storage containing one positive
quantum per input. A nonthrowing visitor receives the input index and allowance,
then reports work and `YIELDED` or `RETAINED`. Yield clears unused allowance;
an interrupted quantum retains precedence while other inputs may proceed.
Completed quanta move to the back through O(1) index-link updates. Invalid
progress or an undeclared disposition terminates before changing order.

Each turn permits at most one quantum of work per input and two visits when
finishing a carried prefix leaves unused turn allowance. Empty and unary
populations have direct paths. The primitive owns no packets, capacity, clocks,
or synchronization. DP composes it with exact NUMA storage and the admission
rules in [Data Plane](DATA_PLANE.md#8-runtime-worker-architecture).

### `prefetch.hpp`

`prefetch.hpp` owns the C++ prefetch surface:

- `KINETUM_PREFETCH_L1`
- `KINETUM_PREFETCH_L2`
- `KINETUM_PREFETCH_L3`
- `KINETUM_PREFETCH_NTA`
- `KINETUM_PREFETCH_WRITE`

Built-in modules, the cuckoo map, and SIMD classifiers place these single-address
hints directly at bounded loop positions. The header owns no range loop, memory
fence, packet-ahead arithmetic, or epoch-specific operation. Code must remain
correct if the compiler or CPU ignores every hint.

### `signal.hpp`

`signal.hpp` owns three control-path signal helpers:

- `ewma`
- `hysteresis`
- `rate_calculator`

CP guardrails uses EWMA and hysteresis in the health correlator. The explicit-
time rate calculator is an installed reusable API with direct conformance tests;
it reads no clock itself.
Constructors reject non-finite or out-of-domain parameters instead of repairing
them. Updates validate finite samples before mutation. `rate_calculator` treats
counter and timestamp regression as baseline-reset events and emits zero for
the unmeasurable interval; timestamp zero is ordinary input, not an
initialization sentinel.

### `control.hpp`

`control.hpp` owns `pid_controller`, including:

- configurable `kp`, `ki`, `kd`
- setpoint tracking
- output limits
- integral clamping
- conditional-integration anti-windup
- optional derivative-on-measurement

Configuration and samples must be finite, output bounds must be ordered, and
the integral bound must be nonnegative. A call derives every term into local
state first. Invalid arithmetic preserves the prior controller, while accepted
conditional integration can never move the retained integral outside its
configured bound. The PID controller is an installed reusable API with direct
conformance tests. No current platform runtime owns a PID loop, and this is not
packet hot-path code.

### `rcu_buffer.hpp`

`rcu_buffer<T>` is a double-buffered publishing primitive. Readers pin the
active slot with a guard. Before reusing the inactive slot, the writer waits
for its readers to drain, writes the replacement, then publishes that slot.
A guard is linear:
destroying its buffer while either slot remains pinned emits one fixed bounded
diagnostic and terminates before reclaiming the reader counters.

`versioned_rcu_buffer<T>` carries one caller-authored version beside each
publication. CP is the sole owner of monotonic control-loop and guardrails
generations; the generic buffer neither allocates nor infers that policy. The header
is available through the C++ SDK's algorithm umbrella, but it is not module
configuration authority: Kinetum modules consume the exact immutable view
carried in `kinetum_batch_t::epoch_config`.

The public primitive exposes coherent values, caller-authored versions, and
guard ownership. It does not expose active-slot identity, reader-count
internals, a rollback-ready bit, or a seqlock-shaped diagnostic sequence.

This is not the DP complete-snapshot store. That cold coordinator owner uses an
exact two-slot lifecycle with no reader publication, map fallback, or hot-path
cache; see `docs/DATA_PLANE.md`. CP continues to use RCU where it publishes
read-mostly control state.

### `single_writer_snapshot.hpp`

`single_writer_snapshot<field_count>` publishes a small fixed array of integer
fields from one owner to foreign observers. The writer publishes an odd marker,
uses a release fence before relaxed atomic payload stores, and release-publishes
the next even sequence. A reader accepts values only when its two acquire
sequence observations around the payload and acquire fence see the same nonzero
even value, and it retries no more than the explicit bound supplied by its
caller.

Use it to export coherent runtime, coordinator, worker, boundary, or module
observations without a foreign thread reading unrelated owner-local writable
state. Publication is bounded and allocation-free, but it is not a per-packet
operation: the owner publishes at one lifecycle edge, loop, batch, or health
cadence. Sequence exhaustion fails closed before wrap can make an old
observation appear current.

The live dataplane uses this primitive for its immutable runtime-status
publication, the transition coordinator's internal progress channel, and each
packet worker's epoch-ledger observation. Worker credit increments/decrements
remain plain owner-local arithmetic; the worker touches the atomic publication
line exactly once per bounded turn. Boundary and module publications join
only with their actual owner-produced fields; the primitive does not authorize
placeholder telemetry.

### `quiescence.hpp`

`quiescence_reader` is one stable caller-owned cache line. A
`quiescence_domain` borrows a complete nonempty ordered set of those records and
binds each array position as its exact reader identity. This keeps placement
with the caller and prevents the generic primitive from acquiring a backend,
NUMA, thread, eventfd, timeout, or reclamation policy.

The sole coordinator starts one adjacent nonzero grace generation. Each reader
publishes that exact generation once after its owning read-side safe point. The
publication uses one reader-local compare/exchange; an exact duplicate is
idempotent, while skipped, stale, regressing, overlapping, or wrapping
generations cannot be converted into progress through numeric maximum logic.
Missing publication leaves the grace incomplete. `grace_period_complete()` is
pure observation, and `finish_grace_period()` clears the active generation only
after every immutable reader matches exactly.

The DP completion owner supplies the subsystem policy: it starts grace before
COMMITTING, evaluates the separate immutable certificate on the coordinator,
and finishes grace only after every old module and snapshot slot is empty. A
reader timeout cannot make this primitive complete; before ownership withdrawal
it freezes updates with the grace active, and after withdrawal the DP fails
stop rather than clearing an uncertain generation.

This is QSBR-style grace machinery, not `rcu_buffer`. `rcu_buffer` pins one of
two value slots on every borrow and makes its writer wait for that slot's reader
count. `quiescence_domain` adds no per-access pin: readers publish once per
requested grace, so subsystem policy must prove where its final old read ends.

### Related DP-local exact-slot mechanism

`src/dp/epoch/exact_slot_table.hpp` is deliberately outside the public
algorithm catalog. It is a DP-local, fixed-size lifecycle mechanism shared by
`module_epoch_store` and `config_snapshot_epoch_store`: exactly two slots, each
in `EMPTY`, `PREPARED`, `PUBLISHED`, or `RETAINED` state, with exact epoch tags
and validated state transitions. The table owns no artifact, callback,
retirement policy, allocator, synchronization, protobuf knowledge, or reader
publication. Each consuming store supplies that subsystem policy itself.

This composition avoids copying the four-state mechanism while preserving the
public-library boundary: an exact DP epoch lifecycle is subsystem policy, not a
general SDK primitive. Both stores are cold/single-owner except for the module
store's separately specified release/acquire publication to its owner worker;
the complete-snapshot store has no packet-path reader.

### `cache.hpp`

`cache.hpp` provides two storage models:

- `lru_node` and `lru_list` are intrusive and allocation-free after the caller
  provides nodes. A linked node carries one exact list owner; duplicate,
  detached, and foreign operations reject without mutation, and `clear()`
  detaches the complete list.
- `lru_cache<K,V>` is heap-backed. It uses `std::unordered_map`, allocates
  entries on insert, mutates LRU order on `get`, and calls an optional eviction
  callback.

Use `lru_cache` for bounded cold-path or read-mostly metadata caches. Do not use
it for per-packet flow/session tables. For hot-path session state, use
`cuckoo_map` plus preallocated slab or pool storage. A zero-capacity
`lru_cache` is rejected at construction.

An eviction callback runs before membership mutation. If it throws, list and
map membership remain structurally unchanged. Hash-dependent cache operations
retain the hash/equality exception contract of `std::unordered_map`; they are
not falsely marked `noexcept`.

### `queue.hpp`
`queue.hpp` exposes seven queue families:

| Type | Shape | Use |
|------|-------|-------------|
| `spsc_ring_static<T, Capacity>` | Fixed-capacity SPSC ring with exactly `Capacity` usable slots. | Lifecycle channels and the boundary channel's capacity-2 typed CUT/ACK lanes. |
| `spsc_ring<T>` | Runtime-capacity owning SPSC ring with exactly constructor `capacity` usable slots. | Available when ordinary heap-backed ownership is the admitted cold-path mechanism. |
| `spsc_ring_view<T>` | Runtime-capacity SPSC arithmetic over one exact caller-owned storage extent. | The DP-local NUMA owner composes it once for DATA boundaries, worker queue roles, and boundary future-output holds. |
| `mpmc_queue<T, Capacity>` | Fixed-capacity MPMC queue. | Available for bounded cold/control paths; packet workers use the caller-storage form where MPMC is required. |
| `mpmc_queue_dynamic<T>` | Construction-time power-of-two MPMC storage; no enqueue/dequeue allocation. | Exact free-credit authority for `fixed_packet_pool`, and plan-sized fixed-record admission for the DP coordinator command mailbox. |
| `mpmc_queue_view<T>` | Runtime-capacity MPMC arithmetic over exact caller-owned cache-line cells. | Tracked-async completion delivery inside each eligible active worker's exact-NUMA slab. |
| `work_queue_view<T>` | Runtime-capacity single-owner queue over exact caller storage. | Copied active-control mailboxes inside each active worker's exact-NUMA slab. |

Every SPSC usable capacity is a power of two and at least two. Static forms
enforce that relation at compile time; runtime and borrowed forms reject it at
construction before adopting storage.

SPSC requires one producer and one consumer. DP's `numa_spsc_ring<T>` places
`spsc_ring_view<T>` and its elements in one checked, prefaulted NUMA mapping.
Active/future queue roles exchange stable owners without copying or resizing
entries.

All MPMC forms use `mpmc_queue_core`, with isolated cells and separate
producer/consumer cursors. Fixed queues embed storage, dynamic queues allocate
once during construction, and views borrow caller storage. None grows later.
`size_approx()` samples the consumer before the producer, returns zero for an
inverted weakly ordered observation, and never exceeds capacity. It supports
telemetry and quiescent checks, not credit claims; only successful
enqueue/dequeue transfers ownership.

The active scheduler derives its completion-ring capacity as the smallest
power of two, at least two, that covers the complete logical async-token slot
population. That physical value is mechanism, not another authored capacity.
Since one live slot can publish at most one terminal cell, a winning foreign
completion never needs a caller retry loop.

The single-owner work-queue view composes one `work_queue_indices` arithmetic
core over a power-of-two caller extent. It allocates no storage, takes no lock,
and keeps circular head/tail semantics out of its subsystem consumer.

The coordinator mailbox composes `mpmc_queue_dynamic` with subsystem-owned
linear completion contexts and an `eventfd` wake source. Queue cells store only
a fixed command kind and context pointer; successful enqueue borrows that stack
context until the sole consumer publishes completion. The event descriptor
coalesces wakeups but owns neither capacity nor command order. Context lifetime,
shutdown cancellation, and coordinator-thread identity remain DP policy rather
than additions to the generic queue primitive.

All SPSC forms share batch arithmetic and keep capacity below the modular
counter half-range. A producer constructs an accepted prefix before one
release store; a consumer move-assigns and destroys its prefix before one
release store. Batch APIs require nothrow copy construction or move assignment,
respectively. Single-element push may use a throwing constructor because it
publishes only after construction; pop still requires nonthrowing move.
MPMC requires default construction and nonthrowing copy/move assignment because
reserved cursors cannot roll back. Batch pointers may be null only at count zero.

### `ratelimit.hpp`

`ratelimit.hpp` provides standalone rate-limiting helpers:

- `token_bucket`
- `leaky_bucket`
- `sliding_window`

All public rate limiter APIs take explicit monotonic nanosecond timestamps
(`now_ns`). They do not read a clock internally. Token and leak balances retain
an exact unsigned numerator with denominator 1,000,000,000: elapsed nanoseconds
times integer bytes per second therefore preserves every fractional byte
without a pre-divided low-rate floor. Full-width `uint64_t` capacities and
costs remain distinct rather than saturating to one representation. Timestamp
zero is valid; regression rejects the operation without changing credit. A
positive sliding-window duration is required, and reconfiguration cannot apply
a new rate retroactively.
Built-in QoS uses one context-local module-specific policer, not the generic
`token_bucket`, because it needs preallocated per-flow bucket storage.

### `net.hpp`

`net.hpp` owns byte-order and lightweight IP utilities:

- `read_be16`, `read_be32`, `read_be64`
- `write_be16`, `write_be32`, `write_be64`
- `protocol::ICMP`, `protocol::TCP`, `protocol::UDP`
- `is_private_ip`

Checksum algorithms are not a shared SDK or DP service. Packet-mutating modules
keep the required inline checksum arithmetic inside their link-closed images.

### `cidr.hpp`

`cidr.hpp` owns CIDR representation, strict string parsing/formatting, and
hot-path matching. Every function is header-defined so an SDK module remains
link-closed under the installed no-undefined policy.

Important details:

- `parse_ipv4` rejects leading zeroes, whitespace, missing octets, and trailing
  characters.
- `parse_cidr` defaults to `/32` when no slash is present.
- `parse_cidr` rejects a trailing slash with no explicit prefix.
- `parse_cidr` does not canonicalize host bits in `cidr.network`.
- `match_cidr` masks both `ip` and `network`, so non-canonical host bits do not
  affect matching.

ACL uses this header for rule parsing and matching; NAT44 uses `parse_ipv4` for
public-address ranges. External modules receive the same implementation through
`Kinetum::SDK` without host runtime imports. The C++ SDK's `string_to_ipv4` and
`ipv4_to_string` delegate to these strict functions, with no separate C-library
parser.

### `condition_parse.hpp`

`condition_parse.hpp` owns the shared syntax parser for route conditions:

```text
field op decimal_uint32
```

It accepts leading/trailing ASCII whitespace, the operators `==`, `!=`, `<`,
`<=`, `>`, and `>=`, and complete decimal `uint32_t` literals only. It rejects
empty expressions, malformed fields, missing/unknown operators, negative
values, overflow, suffix text such as `46junk`, and other trailing non-space
content.

The parser does not own the field whitelist. Axiom validates syntax and DP
compiles route matchers from the same parsed expression, keeping admission and
execution aligned without adding component dependencies to the algorithm layer.

### `graph.hpp`

`graph.hpp` owns one identity-only DAG and its canonical ordering:

- `dag<NodeId>`
- `topological_sort`

The topological order is deterministic: zero-indegree nodes are sorted before
processing. On failure, `blocked_nodes` contains the sorted Kahn remainder,
which can include both cycle members and downstream nodes; it never overclaims
exact cycle membership. One node record owns its successor list and indegree;
there is no unused node-data or predecessor projection. Axiom uses this for
cycle validation. Gluon consumes Axiom's canonical order for planning.

### `cuckoo.hpp`

`cuckoo_map<K,V,Hash>` provides bucketed cuckoo hashing:

- construction requires a positive bucket count and an explicit non-null PMR
  resource that outlives the map
- every instantiation supplies a nonthrowing semantic hasher; no default or
  raw-object representation hash exists
- two hash locations per lookup
- four entries per bucket
- cache-line-aligned buckets
- bounded displacement chain on insert
- failure-atomic insertion: if the displacement chain cannot place the new
  entry, existing entries are restored before `insert` returns `false`
- preallocated displacement undo log stored with the map, so insert does not
  allocate and does not place the full undo log on the caller's stack
- prefetch of both candidate buckets

Each bucket starts on a cache-line boundary. Its extent depends on `K` and `V`
and may span more than one line. Hash invocation, key equality, and mutation
assignment must be non-throwing because lookup and insertion are hot-path
`noexcept` operations. Arbitrary object-representation hashing is absent:
padding is not semantic key identity, so callers provide a field-wise hasher.

Lookups are allocation-free and lock-free when writers are excluded. Inserts
and erases mutate buckets and `size_`. Use an owner-local map; shared read/write
access requires external synchronization.

NAT44 uses `cuckoo_map` for inside/outside session maps. QoS uses it for
flow-key to bucket-index mapping. Gluon uses a cold `std::unordered_map` for
stage metadata and computes weights once into a vector.

### `simd_classify.hpp`

`simd_classify.hpp` owns packet-batch classification:

- `packet_batch_soa`
- `acl_rule_simd`
- `match_cidr_batch`
- `match_port_range_batch`
- `match_protocol_batch`
- `classify_batch_rule`
- `classify_batch_acl`

ACL compilation populates `acl_compiled::simd_rules`, and the ACL module selects
the SIMD batch strategy for more than 256 rules. Unit tests compare every selected implementation with
an independent scalar oracle at vector boundaries. Batch CIDR matching masks
both the packet and authored network, inclusive AVX2 port comparisons never use
wrapping endpoint arithmetic, and port ranges constrain TCP/UDP lanes only.
Public batch counts are clamped to `MAX_BATCH_SIZE` before classification-action
writes, so a malformed caller-provided count cannot write past the fixed output
lanes. Modules translate those actions into the SDK callback's sole forward mask.

CIDR matching selects its implementation at compile time:

| SIMD level | IPv4 values per vector | Selection without that ISA feature |
|------------|-------------|------------------------------------|
| AVX-512 | 16 | Next compiled lower-width implementation. |
| AVX2 | 8 | Next compiled lower-width implementation. |
| SSE4.2 | 4 | Scalar implementation. |
| NEON | 4 | Scalar implementation. |
| Scalar | 1 | Baseline on both supported architectures. |

Port and protocol matching use 16 and 32 lanes respectively when AVX2 is
compiled, and scalar loops otherwise. These vector widths do not change the
64-lane maximum batch size.

### `timer_wheel.hpp`

`timer_wheel_view` is the caller-storage two-level hierarchical arithmetic core.
`timer_wheel<...>` is its compile-time owning wrapper. The active scheduler
placement-constructs one runtime-capacity view in the worker's exact-NUMA slab:

- no internal clock reads
- caller advances time explicitly by ticks
- O(1) arm/cancel
- bounded batch expiry per `advance`
- exact caller-authored preallocated timer population
- no dynamic allocation after construction
- elapsed jumps larger than the fine wheel rebuild from the exact armed-entry
  population instead of iterating empty ticks or unused capacity

The active-stage scheduler uses a 1 ms owner-time quantum over the
default 256 x 256 geometry. `arm_timer_after` rounds a positive delay up and
returns the invalid handle for a delay at or beyond 65,536 ms; the largest
accepted rounded delay is 65,535 ms. This fixed horizon is scheduler mechanism,
not a plan capacity or a callback-side clock authority.
Per-instance capacity bounds armed wheel slots. Expiry releases a slot before
the callback so periodic work can re-arm at capacity one, while the expired
handle's epoch credit remains live through callback return; the worker's cold
credit ceiling includes that bounded handoff overlap.

`user_key` is caller metadata returned with the timer entry. The wheel does not
maintain a key-to-handle map. If a caller wants per-key deduplication, it must
store the returned handle and call `rearm`. Timer handles are opaque
generation-checked values; a stale handle from a previously freed pool slot does
not cancel or rearm a newly allocated timer in the same slot. The generation
field is 32 bits, so handle-staleness protection is bounded by generation
wraparound per pool slot.

## Source Usage

| Area | Headers | Notes |
|------|---------|-------|
| Axiom | `graph.hpp` | Deterministic topological ordering and exact blocked-node failure evidence. |
| Gluon | `platform.hpp` | Branch hints; planning order comes from Axiom's canonical graph result. Stage metadata uses a cold `std::unordered_map`; weights are computed once into a vector. |
| CP | `rcu_buffer.hpp`, `signal.hpp` | Published state, guardrails policy, and health correlation. |
| DP runtime | `compact_index_set.hpp`, `platform.hpp`, `queue.hpp`, `timer_wheel.hpp`, `net.hpp`, `single_writer_snapshot.hpp`, `quiescence.hpp` | Pre-resolved storage membership, packet parsing, coherent epoch-credit publication, exact readers, source queues, active control mailboxes, and one runtime-capacity timer wheel per active worker. The immutable certificate composes exact owner publications with the reader domain; fixed Bootstrap starts no grace. Module and complete-snapshot stores separately compose `src/dp/epoch/exact_slot_table.hpp`; their epoch policy remains outside this public catalog. |
| Boundary protocol | `queue.hpp`, `platform.hpp`, `single_writer_snapshot.hpp` | `boundary_epoch_channel` composes one plan-sized receiver-NUMA DATA ring with per-worker exact-NUMA endpoint slabs: CUT lives with its receiver poller, ACK with its sender poller, and mutable endpoint state/publication with its owner. The channel alone owns successful DATA sequences, bounded pending control, and coherent observation. `worker_boundary_sender` composes exact sealing/gating with the ledger and sender-NUMA hold; `worker_boundary_receiver` composes exact CUT drain/fan-in/ACK policy without wrapping DATA receive; `worker_epoch_activation` preflights module stores and swappable queue roles before whole ledger promotion. Their disjoint event-edge policy publications and one-shot activation publication feed the immutable certificate; fixed Bootstrap publishes only baselines and keeps both endpoint policies OPEN. |
| ACL module | `cidr.hpp`, `hash.hpp`, `simd_classify.hpp`, `platform.hpp`, `prefetch.hpp` | Rule parsing, FNV constants, SIMD batch path, and hot-path hints. |
| NAT44 module | `bounded_index_pool.hpp`, `net.hpp`, `hash.hpp`, `cuckoo.hpp`, `platform.hpp`, `prefetch.hpp` | Fixed slab-index recycling, packet edits, FNV constants, session maps, and hot-path hints. |
| QoS module | `bounded_index_pool.hpp`, `net.hpp`, `cuckoo.hpp`, `platform.hpp`, `prefetch.hpp` | Fixed slab-index recycling, packet parsing/editing, explicit scalar flow identity, bucket map, and hot-path hints. |
| C++ SDK | `algo.hpp`, `aligned_atomic.hpp`, `quiescence.hpp`, `rcu_buffer.hpp`, `signal.hpp` | Module-facing convenience include and shared algorithms; the staged SDK carries the complete byte-identical public header tree, while exact module config comes from the batch view. |

## Module Linking Notes

Customer modules are loaded as `.so` files. Module-facing algorithm APIs are
header-owned unless the installed SDK names an explicit dependency target.
Built-ins do not gain an undeclared `kinetum_common` implementation. External
modules using `Kinetum::SDK` get the same include directory, hidden-symbol
policy, archive-export exclusion, and no-undefined link gate.

Examples:

| Need | Use |
|------|-----|
| Byte-order reads/writes | `algo::net::read_be*` / `write_be*` |
| CIDR matching | `algo::match_cidr` |
| CIDR parsing/formatting | Header-owned `algo::parse_cidr`, `algo::format_cidr`, and `algo::format_ipv4`. |
| Session table | `algo::cuckoo_map` plus `algo::bounded_index_pool` over preallocated value storage |
| Cold metadata cache | `algo::lru_cache` |
| Packet-batch ACL-style matching | `algo::packet_batch_soa` and `classify_batch_acl` |
| Single-owner active-stage timers | `algo::timer_wheel` |

Checksum updates are module-owned policy. A module that needs them must carry a
link-closed implementation or declare an explicit installed dependency; no DP
checksum service completes an unloadable image.

## Duplicate And Local-Code Rules

Some local code remains intentional:

| Location | Why it stays local |
|----------|--------------------|
| `kinetum_sdk.h` branch and attribute macros | Pure C SDK cannot include C++ algorithm headers. |
| NAT44 local checksum helpers | The link-closed module image owns every checksum symbol it calls. |
| Module-specific hashers | ACL/NAT44 keys need exact field-wise hashing and padding avoidance. |

If new reusable C++ primitives are added, put them in
`include/kinetum/algo/` first and have callers include them through the
canonical `<kinetum/algo/...>` spelling. If the primitive must be pure C ABI,
add it to `kinetum_sdk.h` deliberately and document the boundary.

## Where To Read Next

| Need | Read |
|------|------|
| Module author API | `docs/MODULE_SDK.md` |
| Dataplane hosting behavior | `docs/DATA_PLANE.md` |
| Control-plane RCU usage | `docs/CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md` |
| Planning graph behavior | `docs/GLUON.md` |
| Pipeline validation graph behavior | `docs/AXIOM.md` |
| Runtime diagrams | `docs/diagrams/platform_architecture.md` |
