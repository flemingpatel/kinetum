# Module SDK

The SDK defines the binary and behavioral contract for dynamically loaded
packet-processing modules. Modules supply policy; the platform owns image
admission, contexts, immutable configuration, packet batches, telemetry, and
bounded callbacks. `include/kinetum/kinetum_sdk.h` supports C11 and C++20 with
image-local utilities and no host SDK library dependency.
`include/kinetum/kinetum_sdk.hpp` adds header-only C++ conveniences to that ABI.

This document is the module-author contract. Runtime hosting and packet
execution live in [`DATA_PLANE.md`](DATA_PLANE.md); native I/O and storage
ownership live in [Providers](PROVIDERS.md); pipeline authoring
lives in [`AXIOM.md`](AXIOM.md); placement and stage-instance identities live in
[`GLUON.md`](GLUON.md); configuration transaction semantics live in
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md).
The visual lifecycle and dispatch reference is
[`diagrams/platform_architecture.md`](diagrams/platform_architecture.md). Built-in
module schemas, limits, and counters are summarized in
[`../src/modules/README.md`](../src/modules/README.md).

## Table of Contents

**Part 1: Concepts and Quick Start**

1. [What the Module SDK Is](#1-what-the-module-sdk-is)
2. [Authoring Model and Vocabulary](#2-authoring-model-and-vocabulary)
3. [Module Lifecycle](#3-module-lifecycle)
4. [Quick Start: A Minimal Passive Module](#4-quick-start-a-minimal-passive-module)

**Part 2: The C SDK**

5. [The `kinetum_module` Descriptor](#5-the-kinetum_module-descriptor)
6. [Mode-Aware Validation](#6-mode-aware-validation)
7. [Cold Lifecycle and Live Contexts](#7-cold-lifecycle-and-live-contexts)
8. [The `kinetum_batch_t` SoA Layout](#8-the-kinetum_batch_t-soa-layout)
9. [Accessor Macros](#9-accessor-macros)
10. [Disposition and Routing Macros](#10-disposition-and-routing-macros)
11. [Exact Prepared Ownership](#11-exact-prepared-ownership)
12. [Telemetry Registration](#12-telemetry-registration)
13. [Health Assessment and Owner-Worker Publication](#13-health-assessment-and-owner-worker-publication)

**Part 3: Exact Configuration**

14. [Exact Configuration Ownership](#14-exact-configuration-ownership)

**Part 4: The C++ Wrappers**

15. [C++ Wrappers](#15-c-wrappers)

**Part 5: Active Modules**

16. [Active Modules](#16-active-modules)

**Part 6: Built-in Modules as Exemplars**

17. [ACL Module (`kinetum.acl`)](#17-acl-module-kinetumacl)
18. [NAT44 Module (`kinetum.nat44`)](#18-nat44-module-kinetumnat44)
19. [QoS Module (`kinetum.qos`)](#19-qos-module-kinetumqos)

**Part 7: Safety and Build**

20. [Safety Contract](#20-safety-contract)
21. [Building Modules](#21-building-modules)

**Part 8: Cross-Cutting**

22. [Module Author vs DP Platform Responsibilities](#22-module-author-vs-dp-platform-responsibilities)
23. [Determinism for Modules](#23-determinism-for-modules)
24. [Embedding and Testing Notes](#24-embedding-and-testing-notes)
25. [Where to Go Next](#25-where-to-go-next)

---

## Part 1: Concepts and Quick Start

### 1. What the Module SDK Is

A Kinetum module is one canonical absolute regular-file image exporting one
symbol:

```c
const kinetum_module *kinetum_module_register(void);
```

The loader opens the verified path with `RTLD_NOW | RTLD_LOCAL`, resolves that
symbol, validates the returned descriptor against the exact ABI revision, and
admits a complete deployment generation atomically. A successfully loaded code
image is not a mutable execution instance. Each executable stage instance owns
an explicit context identity, placement, long-lived state, telemetry handles,
and, when allowed by the descriptor, its own mutable packet-processing state.

Responsibilities:

- **Authors** implement exact lifecycle callbacks and packet policy. They own
  config parsing, immutable artifact construction, context-local state,
  forwarding/disposition decisions, and bounded health logic.
- **The platform** owns canonical image identity, context placement, callback
  ordering, exact epoch slots, worker affinity, lifecycle arenas, retirement,
  and failure containment.

The runtime ships ACL, NAT44, and QoS module images built through the same SDK
as customer modules. Their source is the implementation reference for Sections
17-19; the SDK package supplies development headers and examples.

### 2. Authoring Model and Vocabulary

| Term | Exact meaning |
|---|---|
| **Module image** | One canonical `.so` and immutable `kinetum_module` descriptor admitted under one semantic `module_id`. |
| **Deployment generation** | One atomic set of module images and context bindings. A retry must describe the same generation; a different second generation is not silently merged. |
| **Context instance** | Mutable state and owner-worker placement for one executable module stage, identified by `context_instance_id`. |
| **Stage instance** | The executable form of one authored Axiom stage on one lane. It resolves to exactly one context when the stage is module-backed. |
| **Passive module** | Packet-driven descriptor with `process(batch)` and no active callbacks. |
| **Active module** | Owner-loop-driven descriptor with required `run()` and optional `ingest()` / `on_control()`. |
| **Prepared artifact** | Immutable exact-epoch state returned by PREPARE as `{owner_handle, packet_config}`. |
| **Packet config** | Borrowed immutable view selected by the platform's exact tagged slot and passed in `batch->epoch_config` or `active_ctx->active_packet_config`. |
| **Live context** | One cache-line `kinetum_ctx` containing only context-local state and immutable placement facts. |
| **Cold lifecycle context** | Opaque `kinetum_lifecycle_ctx` exposing bounded allocation, registration, logging, deadline, and cancellation services. It is unreachable from packet callbacks. |
| **Owner worker** | The sole thread allowed to mutate a live context or invoke packet, ACTIVATE, active, control, and health callbacks for it. |
| **Hot path** | `process`, `ingest`, `run`, `on_control`, ACTIVATE, and owner-worker health. These paths are bounded and allocation-free. |
| **Cold path** | Image admission, INIT, PREPARE, RETIRE, and FINI. Lifecycle services enforce each phase's allocation, release, logging, deadline, and cancellation permissions. |
| **Opaque config blob** | Exact bytes routed to the matching module. The platform validates identity and bounds but does not interpret the module-owned schema. |

Image identity and context identity must never be conflated. Multiple contexts
for one image require `KINETUM_MOD_F_REPLICABLE_CONTEXTS`; without that explicit
capability, generation admission rejects before INIT. Every module ABI identity
or version string contains 1..255 printable-ASCII bytes; the public
`KINETUM_MODULE_ABI_TEXT_CAPACITY` includes the required terminating NUL.

### 3. Module Lifecycle

The lifecycle separates code-image authority, cold artifact ownership, and
owner-worker publication:

```{uml}
@startuml
    participant "Verified bundle/source authority" as B
    participant "Module manager" as M
    participant "Lifecycle executor" as L
    participant "Owner worker" as W
    participant "Module image" as X
    participant "Versioned shared dependency" as S

    note over B,S: Main image hidden-by-default; dependencies explicit and link-closed; registration exported
    B->M: canonical absolute image path + verified colocated artifact set
    M->X: dlopen(exact path, RTLD_NOW|RTLD_LOCAL)
    X->S: resolve declared DT_NEEDED from colocated artifact set
    M->X: kinetum_module_register()
    M->M: exact ABI, flags, mode, identity validation
    M->X: INIT(lifecycle, out_state)
    note over M,X: publish generation only after every image/context succeeds
    L->X: PREPARE(lifecycle, E, blob, out_prepared)
    X-->L: Exact owner_handle + immutable packet_config
    W->X: ACTIVATE(ctx, E, prepared)
    note over W: Bootstrap commits every context before packet bodies open
    W->X: Admitted packet, active, and health callbacks at E
    par Cold preparation of a live update
        L->X: PREPARE(lifecycle, N, blob, out_prepared)
        X-->L: Exact prepared N ownership
    else Existing owner work
        W->X: Continue callbacks against immutable E
    end
    alt Update cancelled before commit
        L->X: RETIRE(lifecycle, N, never-activated prepared record)
        note over W: E remains active
    else Exact N commits
        note over W: Drain E packets, retained work, timers, control,\nPULL, callbacks, and foreign tokens through ordered CUTs
        W->X: ACTIVATE(ctx, N, prepared)
        note over W: Publish N view and activation, then acknowledge inbound CUTs
        W->X: Admitted callbacks against immutable N
        note over L,W: Global execution certificate, reader grace,\nand old telemetry retirement preconditions hold
        L->X: RETIRE(lifecycle, E, exact old record)
    end
    note over M,W: Shutdown drains and joins every owner worker
    L->X: RETIRE(lifecycle, active epoch, final published record)
    note over M,L: All artifact claims and executor work have retired
    M->X: FINI(lifecycle, state)
    M->X: dlclose after all contexts are gone
@enduml
```

Required order:

1. **Link-closed image construction.** Build the module and its dependencies
   under the [image requirements](#exact-image-requirements) in Section 21.
2. **Canonical image admission.** The manager accepts only an absolute,
   canonical, non-symlink regular file supplied by verified authority and
   passes that exact path to `dlopen(RTLD_NOW | RTLD_LOCAL)`. Declared shared
   dependencies are colocated and integrity-covered with the main image.
3. **Exact descriptor admission.** ABI version equality, known flags, identity,
   lifecycle callbacks, and mode shape are validated before any context exists.
4. **Atomic generation admission.** Module IDs are sorted and assigned stable
   image indices; context identities are validated globally; INIT runs for
   every context. Any failure finalizes successful partial work and publishes
   none of the candidate generation.
5. **PREPARE.** A cold lifecycle executor compiles one exact epoch artifact.
   PREPARE receives no live `kinetum_ctx`. Successful null/null output is valid
   for a no-config module because success is token state, not pointer truth.
6. **ACTIVATE.** The owner worker performs a bounded, infallible publication.
   It cannot parse, allocate, block, log, or reclaim.
7. **Execute.** An admitted callback receives both the sole-owner context and
   the exact immutable config view selected by the platform. Passive `process`
   and active `ingest` / `run` / `on_control` use the
   [loop selected once at worker entry](DATA_PLANE.md#stage-modes-and-worker-loops).
8. **Health.** The owner worker invokes optional bounded health against the
   exact active epoch/config. Null means unavailable, never synthetic healthy.
9. **RETIRE.** After quiescence and the platform grace rule, a cold executor
   receives the exact ownership record once. Modules cannot reclaim arenas
   independently.
10. **FINI and unload.** FINI runs after owner-worker join. The image remains
   loaded until every context and prepared ownership record is gone.

INIT, PREPARE, RETIRE, and FINI are serialized per module image. Different
images may run concurrently, but the platform does not assume one image's
foreign constructor, compiler, destructor, or finalizer code is reentrant.
ACTIVATE, packet, active, and health callbacks use sole-worker ownership rather
than the cold image turn.

A live-transition plan requires `KINETUM_MOD_F_LIVE_EPOCH_TRANSITION` on every
image. The platform allocates operation controls and epoch arenas before
PREPARE callbacks, then reserves all completion and retirement resources before
publishing PREPARED. Commit cannot discover a new allocation requirement. The
[DP lifecycle reference](DATA_PLANE.md#14-exact-module-generation-and-lifecycle)
describes executor scheduling and result ownership.

**Do I need a custom module?**

```{uml}
@startuml
start
:Identify the pipeline behavior;
if (Covered by built-in policy?) then (yes)
    :Use kinetum.acl, kinetum.nat44,
    and/or kinetum.qos;
else (no)
    :Implement the custom packet policy;
    :Build its .so against the SDK;
    :Reference its module_id and module_path
    in the pipeline;
endif
:Package the complete pipeline;
stop
@enduml
```

Use built-ins for ACL, NAT44, and QoS. For other behavior, build an SDK module
and reference its `module_id` and `module_path` in a `STAGE_KIND_MODULE` stage.
The quick start below shows that path; both choices produce a bundle through
[`kinetum_pack`](KINETUM_PACK.md).

### 4. Quick Start: A Minimal Passive Module

This counted forwarder uses the C++ wrapper over the C module ABI. It has no
policy blob, so PREPARE succeeds with a null/null result.

```cpp
#include <kinetum/kinetum_sdk.hpp>

namespace example {

class counted_forwarder final
    : public kinetum::sdk::module_base<counted_forwarder> {
    public:
    [[nodiscard]] static constexpr const char *module_id() noexcept
    {
        return "example.counted_forwarder";
    }

    [[nodiscard]] static constexpr const char *module_version() noexcept
    {
        return "1.0.0";
    }

    [[nodiscard]] static constexpr uint32_t flags() noexcept
    {
        return KINETUM_MOD_F_REPLICABLE_CONTEXTS |
               KINETUM_MOD_F_LIVE_EPOCH_TRANSITION;
    }

    [[nodiscard]] kinetum_error
    do_init(const kinetum_lifecycle_ctx *lifecycle) noexcept
    {
        packets_ = kinetum::sdk::counter::create(
            lifecycle, "example.packets");
        return packets_ ? KINETUM_OK : KINETUM_ERR_LIMIT_EXCEEDED;
    }

    void do_fini(const kinetum_lifecycle_ctx *) noexcept {}

    [[nodiscard]] static kinetum_error do_prepare_config(
        const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
        const void *config, size_t config_len,
        kinetum_prepared_config *out_prepared) noexcept
    {
        return kinetum_noop_prepare_config(
            lifecycle, epoch, config, config_len, out_prepared);
    }

    void do_activate_config(
        uint64_t, const kinetum_prepared_config *) noexcept
    {
    }

    static void do_retire_config(
        const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
        kinetum_prepared_config retired) noexcept
    {
        kinetum_noop_retire_config(lifecycle, epoch, retired);
    }

    [[nodiscard]] uint64_t do_process(kinetum_batch_t *batch) noexcept
    {
        uint64_t forward_mask = KINETUM_FORWARD_MASK(batch->count);
        for (uint16_t i = 0; i < batch->count; ++i) {
            KINETUM_FORWARD(forward_mask, batch, i, KINETUM_PORT_UNSET);
        }
        packets_.add(batch->count);
        return forward_mask;
    }

    [[nodiscard]] kinetum_health_assessment do_health_check(
        uint64_t, const void *) noexcept
    {
        kinetum_health_assessment assessment{};
        assessment.health_score = 100;
        assessment.flags = KINETUM_HEALTH_F_OK;
        return assessment;
    }

    private:
    kinetum::sdk::counter packets_;
};

}  // namespace example

KINETUM_MODULE_REGISTER(example::counted_forwarder)
```

Key properties:

- `module_base` generates the exact passive descriptor and C export.
- `do_init` obtains a direct owner-local telemetry handle through the cold
  lifecycle shell; packet code has no registration table.
- `do_prepare_config` is mandatory even for a no-config module. The explicit
  no-op helper validates that the payload is empty and writes null/null.
- `do_activate_config` is bounded and infallible.
- `do_process` returns the sole forward mask for every occupied batch lane.
- Omitting `do_health_check` would emit a null callback. The platform would
  report health unavailable; it would not manufacture score 100.

---

## Part 2: The C SDK

### 5. The `kinetum_module` Descriptor

`kinetum_module` is the sole code-image descriptor:

```c
typedef struct kinetum_module {
    const char *module_id;
    const char *module_version;
    uint32_t abi_version;
    uint32_t flags;
    kinetum_module_mode mode;

    kinetum_prepare_config_fn  prepare_config;
    kinetum_activate_config_fn activate_config;
    kinetum_retire_config_fn   retire_config;

    kinetum_process_batch_fn process;
    kinetum_ingest_fn        ingest;
    kinetum_run_fn           run;
    kinetum_on_control_fn    on_control;

    kinetum_init_fn         init;
    kinetum_fini_fn         fini;
    kinetum_health_check_fn health_check;
    kinetum_select_contexts_fn select_contexts;
} kinetum_module;
```

| Field | Admission contract |
|---|---|
| `module_id` | Required 1..255-byte printable-ASCII semantic identity; must match the generation's requested image identity. |
| `module_version` | Required 1..255-byte printable-ASCII release string. It is descriptive and independent from ABI identity. |
| `abi_version` | Must equal `KINETUM_MODULE_ABI_VERSION` exactly. Older and newer images both reject. |
| `flags` | May contain only `KINETUM_MOD_F_KNOWN_MASK`. Capability is explicit; callback presence never substitutes for a flag. |
| `mode` | Exactly `KINETUM_MODULE_PASSIVE` or `KINETUM_MODULE_ACTIVE`. |
| `prepare_config` | Mandatory cold exact-artifact constructor. |
| `activate_config` | Mandatory bounded owner-worker publication callback. |
| `retire_config` | Mandatory cold exact-artifact destructor. |
| `process` | Required only for passive mode; forbidden for active mode. |
| `ingest` | Optional active push-input callback; forbidden for passive mode. |
| `run` | Required only for active mode; forbidden for passive mode. |
| `on_control` | Optional active owner-worker callback; forbidden for passive mode. |
| `init` / `fini` | Mandatory matched context lifecycle. |
| `health_check` | Optional owner-worker health callback. Null means unavailable. |
| `select_contexts` | Stateless batched entry selector, present exactly with `KINETUM_MOD_F_CONTEXT_SELECTION`. |

Mode is never inferred from callback presence.

The platform owns process drain, worker quiescence, and generation teardown;
the descriptor exposes no Drain- or Shutdown-RPC callbacks.

#### Module flags (`KINETUM_MOD_F_*`)

| Flag | Meaning |
|---|---|
| `KINETUM_MOD_F_REPLICABLE_CONTEXTS` | One image safely supports multiple context-local mutable instances. Required before a generation binds more than one context to the image. |
| `KINETUM_MOD_F_LIVE_EPOCH_TRANSITION` | PREPARE, ACTIVATE, and RETIRE satisfy the exact live-transition contract. A module without it can bootstrap at one fixed epoch but cannot join a live-transition plan. |
| `KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK` | Every foreign/asynchronous epoch reference uses exact platform tokens, bounded completion delivery, cancellation, and worker-ledger ownership. The flag must agree exactly with nonzero authored async capacity/grace on every bound active instance. Synchronous retained/timer work does not require it. |
| `KINETUM_MOD_F_CONTEXT_SELECTION` | The module selects one permitted destination context for each admitted input. Bound stages explicitly author `MODULE_CONTEXT_SELECTION_MODULE`. |

Unknown bits fail descriptor validation. Flags are not locks, scheduling hints,
or compatibility switches.

#### Exact ABI version

`KINETUM_MODULE_ABI_VERSION` packs major, minor, and patch into a fixed
`uint32_t`. The descriptor value must be exactly equal to the runtime header's
value. The initial ABI is `0.1.0`, encoded as `0x00010000`. It begins with the
same number as Kinetum 0.1.0 but is an independent version domain: product
releases do not change the ABI unless its binary contract changes. There is no
same-major or lower-minor acceptance rule.

Both module modes, including ACTIVE modules with tracked async work, share
that same ABI and descriptor layout.

Each module authors its own bounded printable `module_version`; the SDK does
not provide a product-version substitute. Kinetum's built-in modules derive
that descriptive value from root `VERSION` because they ship as one platform
release. An independently released module chooses its own value.

Every ABI-facing structure has compile-time assertions for standard layout,
alignment, total size, and every field offset. Those checks detect accidental
layout drift in the platform build; exact version admission detects a module
compiled against a different declared ABI.

#### Errors

`kinetum_error` is an `int32_t`. Success is `KINETUM_OK`; errors use the
`KINETUM_ERR_` prefix: `INVALID_ARG`, `NO_MEMORY`, `NOT_FOUND`, `ALREADY_EXISTS`,
`LIMIT_EXCEEDED`, `NOT_SUPPORTED`, `BUSY`, `TIMEOUT`, `CONFIG_INVALID`,
`INTERNAL`, and `CANCELLED`. PREPARE and INIT transfer no ownership on error.
`kinetum_strerror()` renders an error value for cold diagnostics.

### 6. Mode-Aware Validation

The module author declares `kinetum_module::mode` in the exported descriptor.
The C++ `module_base<T>` sets `KINETUM_MODULE_PASSIVE` and supplies `process`;
an [ACTIVE module](#16-active-modules) declares `KINETUM_MODULE_ACTIVE` with
its active callbacks. The pipeline author requests the corresponding
[`Stage.execution_mode`](AXIOM.md#9-active-stages). Runtime construction
rejects a stage whose requested mode differs from its module descriptor.

The loader-private `validate_module_descriptor()` authority rejects before
INIT unless all of these are true:

- descriptor is non-null, and `module_id` / `module_version` each contain
  1..255 printable-ASCII bytes followed by NUL;
- `abi_version == KINETUM_MODULE_ABI_VERSION`;
- `flags` contains no unknown bit;
- PREPARE, ACTIVATE, RETIRE, INIT, and FINI are all present;
- passive mode has `process` and has no `ingest`, `run`, or `on_control`;
- active mode has `run`, has no `process`, and may have `ingest` /
  `on_control`;
- mode is one of the two declared values.

An omitted `health_check` stays unavailable in telemetry. `select_contexts`
instead follows its explicit capability flag and authored selection mode;
neither callback is inferred from the other's presence.

The manager then applies generation-level validation that cannot be expressed
by one descriptor: requested ID equality, bounded printable-ASCII context
identity, unique image/context identities, replication capability,
deterministic indices, and canonical file authority.

Modules return immutable descriptors; only the loader decides admission.

### 7. Cold Lifecycle and Live Contexts

The ABI uses two intentionally disjoint context shapes.

#### `kinetum_lifecycle_ctx`: cold services

```c
typedef struct kinetum_lifecycle_ctx {
    const kinetum_lifecycle_ops *ops;
    void *platform_opaque;
} kinetum_lifecycle_ctx;
```

`platform_opaque` is borrowed and uninterpreted. Authors use only the typed
helpers, which validate the operation shell:

| Helper | Allowed ownership |
|---|---|
| `kinetum_lifecycle_get_identity` | Resolve exact module/context/image/worker/core/NUMA identity. |
| `kinetum_lifecycle_allocate_context` | INIT-only long-lived tracked allocation. |
| `kinetum_lifecycle_release_context` | Release the exact context allocation once during INIT rollback or FINI. |
| `kinetum_lifecycle_allocate_epoch` | PREPARE-only immutable arena allocation. Individual allocations are not freeable. |
| `kinetum_lifecycle_register_counter` | INIT-only owner-local counter registration. |
| `kinetum_lifecycle_register_histogram` | INIT-only owner-local histogram registration. |
| `kinetum_lifecycle_log` | Already-formatted cold diagnostic publication. |
| `kinetum_lifecycle_deadline_ns` | Absolute monotonic operation deadline. |
| `kinetum_lifecycle_cancellation_requested` | Cooperative cancellation; invalid shell fails closed as cancelled. |

The lifecycle shell never exposes `kinetum_ctx`. PREPARE and RETIRE can run on
dedicated service cores while the owner worker processes another immutable
epoch without creating two writers to live state.

#### `kinetum_ctx`: one cache-line owner state

```c
struct KINETUM_ALIGNED kinetum_ctx {
    void *state;
    int32_t numa_node;
    int32_t cpu_core_id;
    uint32_t worker_index;
};
```

`state` is the exact pointer returned by successful INIT. The placement fields
are immutable facts for the context's sole owner worker. Padding is implicit;
the ABI asserts a 64-byte size and alignment.

The live context deliberately contains no epoch mirrors, backend-native
resources, allocator/logger/telemetry-registration function tables, capability
fallbacks, or reserved pointers. Packet code receives config through its
execution view, updates pre-registered handles directly, and cannot reach cold
services by construction.


### 8. The `kinetum_batch_t` SoA Layout

`kinetum_batch_t` in `include/kinetum/kinetum_sdk.h` projects packet records into
a transient SoA batch, with no storage-provider objects or native handles.

```c
typedef struct KINETUM_ALIGNED kinetum_batch {
    KINETUM_ALIGNAS(64) void     *data[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint32_t  len[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint16_t  l3_off[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint16_t  l4_off[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint32_t  src_ip[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint32_t  dst_ip[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint16_t  src_port[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint16_t  dst_port[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint8_t   proto[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint8_t   dscp[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint32_t  platform_flags[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint32_t  user_flags[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint32_t  flow_hash[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint16_t  input_port[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint16_t  output_port[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint16_t  next_stage[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint64_t  ts_ns[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint64_t  user_meta[KINETUM_MAX_BURST];
    KINETUM_ALIGNAS(64) uint8_t   user_meta_valid[KINETUM_MAX_BURST];
    uint16_t count;
    uint16_t region_id;
    uint32_t padding;
    uint64_t epoch;
    const void *epoch_config;
    struct kinetum_ctx *ctx;
} kinetum_batch_t;
```

Layout invariants:

- `KINETUM_MAX_BURST = 64`; `count` is the immutable occupied prefix. A
  callback must never inspect or publish a lane at or above `count`.
- The struct is exactly 4224 bytes with 64-byte alignment. Every array column
  begins on a cache-line boundary, and the C ABI pins every member offset.
- `data[i]` points at the complete contiguous L2 packet and `len[i]` is its
  immutable logical length. The callback may mutate bytes but cannot replace
  the backing or resize the packet. `l3_off[i]` and `l4_off[i]` are offsets
  from `data[i]` and must remain within `len[i]`.
- Bytes and parsed fields are one coherence contract. A module that rewrites
  bytes must update every mutable parsed lane invalidated by the rewrite. The
  runtime deliberately does not reparse between module stages.
- `data`, `len`, `input_port`, `ts_ns`, `count`, `region_id`, `epoch`,
  `epoch_config`, and `ctx` are borrowed immutable runtime authority.
  `padding` remains zero.
- Parsed addresses, ports, protocol, DSCP, offsets, platform flags, flow hash,
  output port, next stage, and user metadata are mutable. Runtime validates
  bounds, unsupported bits, and parser-fact relations before publishing them
  back to the sole packet record. TCP and UDP facts are exclusive and agree
  with `proto` in both directions; every L4 or fragment fact requires IPv4,
  and an unparsed packet carries neither parsed flags nor a protocol. Authority
  corruption is a module-contract fault.
- `epoch` is the config epoch the batch belongs to. All packets in one batch
  share that epoch. This is a batch-construction invariant, not by itself a
  proof of cross-region per-packet consistency; see
  [`DATA_PLANE.md`](DATA_PLANE.md).
- `ctx` is the sole-owner live context for this callback. Its `state` pointer
  reaches context-local mutable state; it exposes no cold service table.
- `epoch_config` is the exact immutable view selected by the platform's tagged
  epoch slot. C modules validate the pointer and cast it directly to their
  image-owned configuration type; C++ modules use
  `kinetum::sdk::exact_config<T>(batch)`. A required null view is an invariant
  failure and must drop/fail closed.
- `user_meta`, `user_meta_valid`, and `user_flags` are persistent module-owned
  packet state. Runtime copies them from the packet record into the batch and
  copies them back after successful validation. A fan-out clone receives an
  independent snapshot at clone time, so later branch writes cannot become
  visible to another branch.
- No scatter/gather chain, provider-native handle, or per-callback scratch area
  crosses the ABI. Current module execution requires one contiguous CPU-
  readable/writable packet. A multi-segment or inaccessible storage shape
  rejects before module code rather than masquerading as a partial packet.

`process(batch)` mutates only the permitted batch lanes and returns one
`uint64_t` forward mask. Bit `i` set forwards packet `i`; bit `i` clear drops
it. Bits outside `[0, count)` are invalid. No other packet disposition exists,
and callbacks cannot access provider-native objects.

Active origination uses the separate `kinetum_emit_batch_t`. It has the same
4224-byte, 64-byte-aligned SoA columns but contains only origin values and
`count`: it does not borrow `epoch_config` or `ctx`. `emit()` validates the
complete occupied prefix before acquiring the first storage credit, copies the
accepted prefix into the active stage's exact storage domain, and returns the
number accepted.

### 9. Accessor Macros

`KINETUM_PKT_*` macros in `include/kinetum/kinetum_sdk.h` expand to indexed SoA
array access.

| Macro | Field |
|---|---|
| `KINETUM_PKT_DATA(b, i)` | `b->data[i]` (provider-neutral packet bytes) |
| `KINETUM_PKT_LEN(b, i)` | `b->len[i]` |
| `KINETUM_PKT_L3_OFF(b, i)` | `b->l3_off[i]` |
| `KINETUM_PKT_L4_OFF(b, i)` | `b->l4_off[i]` |
| `KINETUM_PKT_SRC_IP(b, i)` | `b->src_ip[i]` (host byte order) |
| `KINETUM_PKT_DST_IP(b, i)` | `b->dst_ip[i]` |
| `KINETUM_PKT_SRC_PORT(b, i)` | `b->src_port[i]` |
| `KINETUM_PKT_DST_PORT(b, i)` | `b->dst_port[i]` |
| `KINETUM_PKT_PROTO(b, i)` | `b->proto[i]` |
| `KINETUM_PKT_DSCP(b, i)` | `b->dscp[i]` |
| `KINETUM_PKT_HASH(b, i)` | `b->flow_hash[i]` |
| `KINETUM_PKT_PLATFORM_FLAGS(b, i)` | `b->platform_flags[i]` |
| `KINETUM_PKT_TS(b, i)` | `b->ts_ns[i]` |

Input/output ports, user flags, and persistent user metadata use their direct
indexed fields. Read `user_meta[i]` only when `user_meta_valid[i]` is nonzero;
setting or clearing the word updates both fields together.

Two flag namespaces apply to packets:

- **`platform_flags[i]`** carries only facts the parser produces:
  `KINETUM_PKT_F_L3_IPV4`, `KINETUM_PKT_F_L4_TCP`,
  `KINETUM_PKT_F_L4_UDP`, and `KINETUM_PKT_F_FRAGMENT`. Their exact union is
  `KINETUM_PKT_F_PLATFORM_MASK`. A module may update those parsed facts but
  cannot advertise VLAN, tunnel, checksum/offload, IPv6, or another mechanism
  the runtime does not materialize.
- **`user_flags[i]`** is the full independent 32-bit module-owned word. It is
  persistent across callbacks and copied independently at fan-out.

`KINETUM_PKT_DATA` is appropriate for bounded packet-byte reads and writes,
including checksum repair. It never returns a DPDK, AF_XDP, or other native
handle. A module may link its own third-party library under the image-closure
rules, but it receives no access to platform-owned provider objects.

### 10. Disposition and Routing Macros

Disposition has one authority: the callback's returned forward mask.

| Macro | Effect |
|---|---|
| `KINETUM_FORWARD_MASK(count)` | Set exactly the low `count` bits. |
| `KINETUM_DROP(mask, i)` | Clear bit `i` in the caller-owned mask. |
| `KINETUM_FORWARD(mask, batch, i, port)` | Set bit `i` and write `output_port[i]`. |

The disposition helpers evaluate each argument exactly once. Lane indices must
still name the occupied prefix; invalid indices are a module contract fault.

Reserved port sentinels:

- `KINETUM_PORT_UNSET = 0xFFFF` - use the exact egress bound to the TX stage
  reached by this packet.
- `KINETUM_PORT_DROP = 0xFFFE` - discard at terminal TX dispatch. Clear the
  forward-mask bit for an immediate module-stage drop; the port sentinel does
  not replace the return-mask contract.

The normal permit-unless-denied shape initializes
`uint64_t mask = KINETUM_FORWARD_MASK(batch->count)`, clears rejected lanes,
and returns `mask`. Returning zero drops the complete occupied prefix. A module
must not set a bit at or above `batch->count`; runtime treats that as an ABI
contract fault rather than masking it away.

Routing semantics:

- The runtime owns dispatch fanout. Writing `batch->next_stage[i]` selects the
  compiled logical-stage index used by Tier-1 dispatch; the destination's
  authored selection mode resolves its executable context. It is not a module-local successor
  ordinal. Authors should write it only when their
  module/config contract is explicitly bound to the compiled stage table.
- For the canonical 3-tier dispatch the data plane uses
  (`module_next_stage`, conditional edges, broadcast fanout), see
  [`DATA_PLANE.md`](DATA_PLANE.md).

#### Module context selection

`MODULE_CONTEXT_SELECTION_SAME_LANE` keeps the matching replica.
`MODULE_CONTEXT_SELECTION_MODULE` calls the registered selector before a PUSH
packet enters the target stage or changes storage ownership:

```c
uint64_t select_contexts(const kinetum_context_selection_batch *batch,
                         const kinetum_context_selection_targets *targets,
                         uint32_t *selected_contexts);
```

The input carries up to 64 occupied lanes of parsed addresses, ports, protocol,
platform flags, flow hash, and ingress port. It carries no packet-byte pointer,
mutable context, policy view, or lifecycle service. `targets` supplies the
complete module population, sorted permitted ordinals, and their membership
bitmap. `kinetum_context_is_permitted()` performs a bounded membership check.

Set bit `i` only after writing one permitted ordinal to `selected_contexts[i]`;
clear it to reject that input. Out-of-prefix mask bits, changed input authority,
and admitted ordinals outside the permitted set are ABI violations. The runtime
validates the complete result before dispatching any lane. Rejected inputs drop
and release through their original storage owner. A selected destination stays
attached to its record through backpressure and storage-transition retries.
Explicit `next_stage`, active origins, and retained forwarding use this same
selection. PULL, control, and same-instance recirculation keep their explicit
owners.

The selector may run concurrently on different packet workers. It is stateless
and bounded: no allocation, lock, clock, logging,
context/config lookup, or provider access. The C++ wrapper binds a static
`select_contexts` method with the same arguments when the flag is declared.

### 11. Exact Prepared Ownership

Every module configuration is represented by one exact ownership record:

```c
typedef struct kinetum_prepared_config {
    void       *owner_handle;
    const void *packet_config;
} kinetum_prepared_config;
```

The two pointers have different roles:

- `owner_handle` identifies the module-owned artifact transferred from
  successful PREPARE and returned exactly once to RETIRE.
- `packet_config` is the immutable borrowed view placed in the platform's exact
  slot and supplied to packet, active, and health callbacks.

Neither pointer is a success bit. A valid no-config module returns `{NULL,
NULL}` with `KINETUM_OK`; the platform's linear prepared token carries the
ownership state. Conversely, an error must leave both pointers null and
transfers nothing.

#### Lifecycle arena allocation

`kinetum_lifecycle_allocate_epoch()` allocates immutable bytes from the exact
PREPARE operation's bounded arena. The platform owns that arena as part of the
prepared token:

```c
void *storage = NULL;
kinetum_error error = kinetum_lifecycle_allocate_epoch(
    lifecycle, sizeof(struct compiled_policy),
    _Alignof(struct compiled_policy),
    KINETUM_LIFECYCLE_ALLOC_ZERO |
        KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED,
    &storage);
```

Rules:

- call it only during PREPARE;
- treat published bytes as immutable;
- do not retain the lifecycle shell;
- do not free individual epoch allocations;
- on successful PREPARE, the platform retains the complete arena;
- on failed/aborted PREPARE, the platform reclaims partial arena state;
- RETIRE receives the exact prepared record only after platform quiescence and
  grace conditions allow reclamation.

Long-lived context state uses `kinetum_lifecycle_allocate_context()` during
INIT and the matching exact `kinetum_lifecycle_release_context()` during FINI.
`module_base` performs that allocation for the concrete C++ object itself. A
failed INIT transfers no state, receives no FINI, and is rolled back through
the lifecycle owner's tracked allocations plus the concrete-object destructor.

Each lane-local module stage requires one `ModuleContextResourceBinding`;
platform stages have none. Both `context_memory_capacity_bytes` and
`epoch_arena_capacity_bytes` must be nonzero. Absent proto3 values are zero and
reject, with no allocator default. Gluon lowers them into `StageInstance`, and
the topology compiler carries them into `compiled_module_context` before
runtime construction.

`kinetum_lifecycle_get_identity()` also supplies `module_context_ordinal` and
`module_context_count`. Context IDs sort within one `ModuleContextDomain`,
across every logical stage using that module ID. These values stay fixed for
the admitted generation. A retry that retains contexts while changing either
value rejects before mutation; configuration updates cannot remap live state.

Admission also proves the complete NUMA-local reservation with checked
arithmetic. For each module context, the reserved term is the context-lifetime
capacity plus the per-epoch capacity multiplied by
`EXACT_EPOCH_SLOT_COUNT`; the slot count is the shared two-slot contract, not a
duplicated literal. Runtime generation construction rechecks the compiled
totals and gives INIT and PREPARE only their authored bounds. Crossing either
bound returns the existing `KINETUM_ERR_NO_MEMORY` result through the module
ABI. Modules observe allocation results through lifecycle functions; the ABI
exposes no capacity field.

#### Bounded cold execution

PREPARE may parse, compile, allocate from its epoch arena, and log. RETIRE
destroys the exact supplied artifact; it cannot allocate another epoch or
context. Both run under an absolute monotonic deadline. Long loops must
periodically call `kinetum_lifecycle_cancellation_requested()`. Cancellation is cooperative;
modules must return without publishing partial ownership. A callback that
ignores cancellation is a module fault, not a reason to run foreign code on a
packet worker or detach a thread. The platform stops new dispatch and collects
every accepted result. If a callback reports success after cancellation, that
success is an owned artifact and is RETIREd before ABORTED can publish. A
callback still executing after the plan-authored cancellation grace makes the
process fail stop; the platform does not unload or report clean abort while
foreign ownership is uncertain.

### 12. Telemetry Registration

Telemetry handles are registered during INIT through the cold lifecycle shell
and updated only by the context's owner worker. This ownership removes shared
atomics and name lookup from the packet path.

```cpp
kinetum_error do_init(const kinetum_lifecycle_ctx *lifecycle) noexcept
{
    packets_ = kinetum::sdk::counter::create(lifecycle, "example.packets");
    if (!packets_) {
        return KINETUM_ERR_LIMIT_EXCEEDED;
    }
    return kinetum_lifecycle_register_histogram(
        lifecycle, "example.latency_ticks", 60000000000ULL, 3, &latency_);
}
```

Here `packets_` is a `kinetum::sdk::counter` and `latency_` is the direct
`kinetum_histogram_t` ABI handle.

#### Counters

`kinetum_counter_t` is a borrowed owner-lifetime handle. Packet updates are
direct single-writer operations:

| C surface | C++ surface | Meaning |
|---|---|---|
| `KINETUM_COUNTER_INC(h)` | `counter::inc()` | Add one. |
| `KINETUM_COUNTER_ADD(h, n)` | `counter::add(n)` | Add a nonnegative bounded delta. |
| `KINETUM_COUNTER_GET(h)` | `counter::get()` | Owner-local read. |
| `KINETUM_COUNTER_SET(h, n)` | -- | Owner-local assignment. |

These are not cross-thread synchronization primitives. Stats readers consume a
coherent owner publication rather than reading a mutating counter bank.
Packet callbacks accumulate into ordinary local integer variables and apply
one bounded `KINETUM_COUNTER_ADD` per counter after the loop. Gauges use
`KINETUM_COUNTER_SET`; counter addition never accepts a negative delta.

#### Histograms

`kinetum_histogram_t` owns a preallocated HDR-style bucket array. Registration
specifies a positive `highest_trackable_value` and `significant_digits` in the
supported range. `KINETUM_HISTOGRAM_RECORD_FAST()` performs bounded owner-local
updates in both C and C++ modules.

`kinetum_histogram_percentiles()` is a cold helper that requires a stable
histogram bank. It returns `p50`, `p90`, `p99`, `p999`, minimum, maximum,
count, and sum. It must not race the owner worker's active bank.

Each context admits up to 64 counters and 16 histograms independently. Names
are unique across both kinds. Histogram registration allocates all three bucket
banks as one transaction against the context's authored memory ceiling; a
failure consumes neither a handle nor a partial bank.

The platform publishes completed banks at the plan-owned cadence without
blocking the worker. If publication capacity is unavailable, updates continue
in the active bank and the skipped publication is counted. Activation closes
the old interval before target-epoch packet execution, so histograms never mix
epochs. [DP statistics](DATA_PLANE.md#15-stats-collection) describes the
three-bank exchange, reserved activation capacity, and cold aggregation.

#### Registration and naming rules

- Registration is INIT-only; packet code cannot reach the registry.
- Names are nonempty, bounded printable ASCII and unique within one context.
- Registration failure is explicit; a missing handle is not auto-created on
  first update.
- Metric handles are context-local. Replicas therefore publish distinct
  observations even when they share one module image.
- Logging is cold lifecycle output. Do not format or log per packet.

The existing lifecycle log callback copies a bounded diagnostic before it
returns. The platform supplies module/context identity, worker placement,
phase, and epoch; modules do not format or cache those identities themselves.
Messages beyond 8 KiB are explicitly marked as truncated. Cold ERROR records
bypass suppression and allow a 100 ms file-confirmation wait; failure or timeout
attempts best-effort emergency stderr. Filtering, file
delivery, rotation, and loss evidence follow [Logging](LOGGING.md); delivery
never changes the lifecycle operation's result. Activation and owner-health
callbacks remain packet work and cannot use this service.

#### Operator projection

`GetStats` never reads a live handle or active bank. A successful request with
`include_module_metrics` maps the aggregator's stable state into three exact
row families:

- `ModuleCounterStats` carries the latest absolute value with module, context,
  worker, and epoch identity.
- `ModuleHistogramStats` carries one cold-merged context/epoch interval. An
  empty histogram has `sample_count == 0`, `sample_sum == 0`, and no minimum,
  maximum, or percentile fields.
- `ModuleEpochMismatchStats` carries the cumulative mismatch count and optional
  first-fault identity copied from the sole owner store.

Rows are selected as a family and validated with the complete runtime
observation. A malformed identity, torn aggregate, or unavailable mandatory
source rejects the whole response; the service never substitutes a partial
module list or numeric defaults. Stats collection invokes no module callback.

### 13. Health Assessment and Owner-Worker Publication

The module returns policy; the platform owns publication provenance. The two
fixed records make that boundary structural:

```c
typedef struct kinetum_health_assessment {
    uint8_t  health_score;
    uint8_t  _padding[3];
    uint32_t flags;
    char     reason[40];
} kinetum_health_assessment;

typedef struct KINETUM_ALIGNED kinetum_health_signal {
    kinetum_health_assessment assessment;
    uint64_t epoch;
    uint64_t timestamp_ns;
} kinetum_health_signal;
```

Health flags are `KINETUM_HEALTH_F_OK`, `DEGRADED`, `CRITICAL`, and
`CONFIG_ISSUE`. The callback receives the same exact active authority as packet
execution:

```c
kinetum_health_assessment (*health_check)(
    kinetum_ctx *ctx,
    uint64_t active_epoch,
    const void *active_packet_config);
```

The contract is strict:

- only the context's owner worker invokes it;
- it is bounded, allocation-free, nonblocking, and exception-free;
- it reads context-local state and the borrowed exact active config;
- it returns only `health_score`, flags, and a bounded reason;
- it performs no clock read, string formatting, or logging;
- `health_score` is in `0..100`, flags contain only
  `KINETUM_HEALTH_F_KNOWN_MASK`, and `reason` contains a NUL within its fixed
  capacity;
- after return, the owner worker stamps the exact active epoch and its cached
  monotonic loop time into `kinetum_health_signal`;
- only after an actual callback returns, the owner takes one additional sample
  from the same platform monotonic authority to measure the compiled callback
  budget and optionally timestamp that context's completed telemetry bank; the
  fresher sample never replaces cached packet or callback time, and release
  qualification must reject a target tuple whose generated path falls back to
  a packet-worker syscall or exceeds its measured budget;
- one ordinary worker-ledger credit spans exact-view verification, callback,
  validation, publication, and claim resolution, then retires last;
- a null callback means **health unavailable**, never implicit health score
  100;
- `reason` is bounded, NUL-terminated, and valid UTF-8 when projected through
  the shared protobuf telemetry string. Invalid bytes make the selected
  all-or-none stats result malformed; the platform never replacement-decodes
  or sanitizes module evidence.

`set_health_reason_literal(assessment, "reason")` copies one compile-time
literal, including its NUL, into the fixed field without formatting. The helper
rejects an oversized literal at compile time. Dynamic diagnostic construction
does not belong in this callback.

Malformed or over-budget callback output suppresses the signal, increments a
saturating context-local fault count, and preserves the first fault's mask,
epoch, time, and duration. It never becomes healthy output or changes packet
disposition.

Foreign gRPC, stats, and guardrail threads must never invoke module code. One
stage/context owner invokes at most one due callback per worker turn, immediately
after the turn refresh and before that context's telemetry-bank service.
Command/source admission precedes the refresh,
so source advancement suppresses old-epoch health; a live invocation
credit blocks the zero-old-work proof; local activation requires no live claim.
The cold runtime source reads only the coherent latest-value publication and
maps null, missing, torn, faulted, and stale observations to explicit
`ModuleHealthState` rows. A successful request with `include_module_health`
returns one predeclared row per exact context; only
`MODULE_HEALTH_STATE_SIGNAL_AVAILABLE` carries score, flags, and reason.
Malformed cross-identity or regressing publications reject the complete stats
response. CP, CLI, and guardrails consume this shared typed result and never
fall back to foreign-thread polling or partial output.

The health row's contract-fault masks preserve the platform validator's exact
four bits: `0x1` score out of range, `0x2` unknown assessment flags, `0x4`
unterminated reason, and `0x8` callback budget exceeded. Every other bit is
malformed. These are platform evidence, not flags a module may author.

---

## Part 3: Exact Configuration

### 14. Exact Configuration Ownership

The configuration lifecycle is a three-phase ownership protocol, not a mutable
`configure()` callback:

#### PREPARE: construct immutable state

```c
kinetum_error prepare_config(
    const kinetum_lifecycle_ctx *lifecycle,
    uint64_t epoch,
    const void *config,
    size_t config_len,
    kinetum_prepared_config *out_prepared);
```

PREPARE may parse the opaque blob and build immutable tables. It receives no
live context, cannot mutate packet state, and writes `out_prepared` only after
complete success. The input bytes are borrowed for the call. Successful
artifacts must remain immutable until RETIRE.

#### ACTIVATE: bounded owner publication

```c
void activate_config(
    kinetum_ctx *ctx,
    uint64_t epoch,
    const kinetum_prepared_config *prepared);
```

ACTIVATE runs on the sole owner worker. It is infallible and bounded. A module
may reset context-local caches or publish a context-local pointer, but it may
not allocate, parse, block, log, or reclaim. The platform separately publishes
`prepared->packet_config` in the exact tagged execution slot.

Live activation requires all old packet, retained, timer, control, PULL,
callback, and async work to have drained. Packet callbacks cannot interleave
with ACTIVATE. The platform owns queue rotation, ledger promotion, and ordered
acknowledgement; see [DP boundary integration](DATA_PLANE.md#12-cross-region-boundary-integration).

#### RETIRE: exact reclamation

```c
void retire_config(
    const kinetum_lifecycle_ctx *lifecycle,
    uint64_t epoch,
    kinetum_prepared_config retired);
```

RETIRE receives ownership once after no packet, callback, retained work item,
or platform reader may still reference the artifact. It must reclaim only the
record it receives. The module cannot choose a retirement floor, map an older
epoch to a nearby config, or garbage-collect platform slots itself.

#### Platform slot and view ownership

Each context has exactly two platform-owned tagged slots. A successful PREPARE
token moves into an EMPTY slot as PREPARED. The owner worker acquire-observes
that complete publication, constructs the prospective callback/config view,
runs bounded ACTIVATE, then promotes the slot to PUBLISHED; a prior PUBLISHED
slot becomes RETAINED. The active executable view is one cache-line copy of the
exact context, callback set, packet config, context index, mode, and epoch.

The platform retires a RETAINED artifact only after execution/boundary
completion and reader grace. At shutdown it also retires the final PUBLISHED
artifact after owner quiescence. Each record reaches RETIRE once; the slot
becomes EMPTY only after that callback completes. A null/null record still
owns a slot and receives RETIRE.

A reader deadline before artifact withdrawal retains the old artifacts and
freezes updates. Uncertain ownership after withdrawal is fail-stop.
The module ABI exposes no reader-registration or grace callback. Store claims,
dispatch order, and result validation belong to the
[DP lifecycle](DATA_PLANE.md#14-exact-module-generation-and-lifecycle).

#### Exact packet lookup

`batch->epoch` and `batch->epoch_config` are a matched pair selected by the
platform. Modules cast the already-selected view:

```cpp
const auto *policy =
    kinetum::sdk::exact_config<compiled_policy>(batch);
if (KINETUM_UNLIKELY(policy == nullptr)) {
    return UINT64_C(0);
}
```

The supplied exact view is the sole configuration authority. A missing exact
view is a visible invariant failure; choosing another slot would silently
execute under the wrong policy. Before worker launch, the runtime proves the
stage-instance/context/image/placement/mode/epoch relation in both directions
and stores a direct pointer to the context's active view. Packet execution then
performs one exact epoch equality and no slot search. Mismatch means no callback,
one bounded owner-local fault record, and leak-free packet retirement by the
owning dispatch path.

#### Concurrency and capability

- INIT, PREPARE, RETIRE, and FINI for one image share one platform
  serialization domain.
- Different images may compile concurrently on different lifecycle executors.
- ACTIVATE and packet callbacks are serialized by sole-worker ownership.
- Immutable prepared data may be read by packet execution while another epoch
  is prepared.
- Mutable packet/session/cache state is context-local unless a separate
  admitted sharing contract says otherwise.
- `KINETUM_MOD_F_LIVE_EPOCH_TRANSITION` is required for live transition use.
- Foreign/asynchronous completion is admitted only through exact platform
  tokens. One terminal CAS publishes a bounded result, the owner callback
  consumes it under the original ledger credit, and transition/shutdown
  cancellation must drain before activation or teardown. Synchronous retained
  handles continue to use the same ledger without the async flag.

---

## Part 4: The C++ Wrappers

### 15. C++ Wrappers

`include/kinetum/kinetum_sdk.hpp` is header-only and adds no alternative ABI.

#### `module_base<Derived>`

The CRTP base generates an exact passive descriptor. `Derived` supplies:

```cpp
static const char *module_id() noexcept;
static const char *module_version() noexcept;
static uint32_t flags() noexcept;

kinetum_error do_init(const kinetum_lifecycle_ctx *) noexcept;
void do_fini(const kinetum_lifecycle_ctx *) noexcept;

static kinetum_error do_prepare_config(
    const kinetum_lifecycle_ctx *, uint64_t,
    const void *, size_t, kinetum_prepared_config *) noexcept;
void do_activate_config(
    uint64_t, const kinetum_prepared_config *) noexcept;
static void do_retire_config(
    const kinetum_lifecycle_ctx *, uint64_t,
    kinetum_prepared_config) noexcept;

uint64_t do_process(kinetum_batch_t *) noexcept;
```

`do_health_check(uint64_t, const void *) -> kinetum_health_assessment` is the
only optional shared lifecycle method. Omission produces a null callback and
unavailable health, never a healthy default.

The base allocates the concrete object through lifecycle context ownership,
calls INIT before publishing state, invokes FINI and the destructor after
worker join, and releases the exact allocation. Descriptor construction
compile-time verifies the exact return type and `noexcept` contract of every
mandatory module method, the optional health method, and the concrete
destructor. A throwing concrete-object constructor is contained by INIT and
reported as `KINETUM_ERR_INTERNAL`; no module callback may throw.

`KINETUM_MODULE_REGISTER(ModuleClass)` emits the sole C export.

#### `exact_config<T>`

`exact_config<T>(batch)` is a direct typed cast of `batch->epoch_config`; the
runtime has already selected the exact immutable view before the callback.

#### `counter` and the direct telemetry ABI

`counter::create(lifecycle, name)` registers during INIT. Subsequent `inc` and
`add` calls are direct owner-local operations; `native()` returns the exact C
handle. C++ modules use `kinetum_lifecycle_register_histogram`,
`KINETUM_HISTOGRAM_RECORD_FAST`, and the percentile helpers directly from the C
ABI. The C++ wrapper does not introduce a second histogram authority.

#### Indexed packet access

C and C++ modules use the direct `KINETUM_PKT_*` accessors with an indexed loop
to read or update SoA lanes. The explicit index keeps vectorizable access and
the callback's bounded forward mask visible in packet code.

#### Utility helpers

- `ipv4_to_string` / `string_to_ipv4`: cold canonical dotted-decimal
  conversion through the same header-owned IPv4 authority used by built-in
  modules; parsing rejects whitespace, leading zeros, and trailing data.
- `set_health_reason_literal()`: bounded compile-time health-reason copy with no
  formatting.
- `kinetum::algo`: fixed-capacity rings, cuckoo maps, token buckets, CIDR
  matching, and other shared bounded packet-processing mechanisms.

Packet policy consumes the runtime-stamped `batch->ts_ns`; active callbacks
consume the worker-cached `active_ctx.now_ns`. Health receives only context,
active epoch, and active configuration. The platform timestamps its publication
from the worker's cached turn time and may take the one documented post-return
budget sample. The module ABI exposes no independent clock or cycle-counter
helper.

Active modules construct the C descriptor explicitly; `module_base` is
passive-only so active callback presence cannot be inferred.


## Part 5: Active Modules

### 16. Active Modules

Active modules are owner-loop driven. They have no passive `process` callback;
the descriptor requires `run()` and may provide `ingest()` and `on_control()`.
INIT, PREPARE, ACTIVATE, RETIRE, FINI, exact ABI admission, and context
ownership are identical to passive modules.

> **Active admission:** Bootstrap and live-transition plans admit
> synchronous and tracked-async ACTIVE instances when exact plan limits,
> context ownership, origin storage, callbacks, and capability flags agree.
> Missing or contradictory async capacity/grace rejects before provider
> effects; no synchronous mechanism stands in for foreign completion.

#### Exact active execution view

```c
typedef struct kinetum_active_ctx {
    uint64_t now_ns;
    uint64_t active_epoch;
    const void *active_packet_config;
    uint64_t drain_target_epoch;
    const kinetum_active_timer_handle *expired;
    const kinetum_retained_packet_handle *drain_retained;
    uint32_t expired_count;
    uint32_t drain_retained_count;
    uint32_t region_id;
    uint32_t state_flags;

    kinetum_active_emit_fn emit;
    kinetum_active_retain_input_fn retain_input;
    kinetum_active_emit_retained_fn emit_retained;
    kinetum_active_drop_retained_fn drop_retained;
    kinetum_active_arm_timer_fn arm_timer_after;
    kinetum_active_cancel_timer_fn cancel_timer;
    kinetum_active_post_control_fn post_control;
    kinetum_active_request_pull_fn request_pull;
    kinetum_active_runtime_services *runtime_services;
} kinetum_active_ctx;
```

`now_ns` is the platform's monotonic time cached once for the owner-worker
turn. It is the active module's time authority; it is not a cycle count and
does not authorize a module-local clock read.

`active_epoch` and `active_packet_config` are a matched exact pair for every
active callback. `state_flags` identifies normal, transition-drain, or
shutdown-drain execution. `drain_target_epoch` is nonzero only for transition
drain. Every pointer is callback-borrowed; only opaque retained/timer handles
and copied async tokens may survive callback return. `runtime_services` is a
typed callback-borrowed shell; its `platform_opaque` field is private and must
not be inspected or retained.

#### Triggers

| Constant | Meaning |
|---|---|
| `KINETUM_TRIGGER_LOOP` | Ordinary owner-loop turn. |
| `KINETUM_TRIGGER_TIMER` | One or more opaque timer handles appear in `expired[]`. |
| `KINETUM_TRIGGER_PULL_READY` | A downstream consumer requested work. |
| `KINETUM_TRIGGER_CONTROL` | Control/feedback input is available. |
| `KINETUM_TRIGGER_DRAIN` | Resolve already-owned active work; never authorable in Axiom. |
| `KINETUM_TRIGGER_ASYNC_COMPLETE` | One or more exact foreign completions appear in the RUN completion prefix; never authorable in Axiom. |

Multiple bits may be set on one bounded turn.

#### Callbacks

```c
uint64_t ingest(kinetum_ctx *ctx, kinetum_active_ctx *active,
                kinetum_batch_t *batch);
void run(kinetum_ctx *ctx, kinetum_active_ctx *active, uint32_t triggers);
void on_control(kinetum_ctx *ctx, kinetum_active_ctx *active,
                const kinetum_control_msg *message);
```

- `ingest` is optional only when no packet path reaches the instance. A set bit
  forwards; a clear bit drops unless `retain_input` provisionally transferred
  that lane. Forward plus retain and repeated retain are contract violations.
  The callback never receives packet-record ownership.
- `run` is required and executes one bounded scheduling turn.
- `on_control` is required when CONTROL is authored and runs on the same owner.
  It receives the same epoch/state/services but empty timer/retained event
  prefixes; `run` is the sole consumer of those batched trigger inputs.
- `emit` returns the origin prefix copied into platform-owned records and
  dispatched. The module continues to own its borrowed source buffers and any
  unaccepted origin work; the runtime does not invent a retry.
- `retain_input` returns a generation-checked context-bound handle or the fixed
  invalid value without transfer on packet/byte-capacity exhaustion. Every
  occupied ingest lane may be retained once. Provisional retention reserves
  both packet and byte capacity immediately; each lane commits independently
  after the callback returns. An index at or above `batch->count` returns invalid.
- `emit_retained` and `drop_retained` consume a valid handle into platform-owned
  pending state. Backpressure cannot return or duplicate that handle.
- `arm_timer_after` rounds a positive relative nanosecond delay up to the 1 ms
  owner-wheel quantum. The largest accepted rounded delay is 65,535 ms; a
  larger delay or exhausted per-instance quota returns the invalid handle.
  `cancel_timer` consumes one exact live timer.
- `post_control` copies the complete message into the destination's exact
  plan-sized mailbox and may fail on edge, payload, or queue admission;
  `peer_idx` is the exact destination stage-instance index and `subtype` must
  equal that authored edge's `KINETUM_CONTROL_SUBTYPE_GENERIC` or
  `KINETUM_CONTROL_SUBTYPE_FEEDBACK` classification.
- `request_pull` returns whether one exact same-worker pending bit was admitted;
  `upstream_idx` is the source stage-instance index and a duplicate while
  pending is idempotent. The runtime inspects at most one burst-class
  round-robin edge prefix per turn, so a large authored edge set cannot become
  an unbounded recurring scan or starve its later identities.

Tracked-async instances receive the following fixed-width mechanism through
`runtime_services`:

```c
kinetum_async_token kinetum_active_begin_async(
    kinetum_active_ctx *ctx, uint64_t user_tag);
kinetum_async_token kinetum_active_begin_async_retained(
    kinetum_active_ctx *ctx, kinetum_retained_packet_handle retained,
    uint64_t user_tag, kinetum_async_packet_view *out_view);
bool kinetum_active_abort_async(
    kinetum_active_ctx *ctx, kinetum_async_token token,
    kinetum_retained_packet_handle *out_retained);
bool kinetum_async_complete(
    const kinetum_async_token *token, kinetum_async_outcome outcome);
bool kinetum_async_cancellation_requested(
    const kinetum_async_token *token);
const kinetum_async_completion *kinetum_active_async_completions(
    const kinetum_active_ctx *ctx, uint32_t *out_count);
bool kinetum_active_recirculate_retained(
    kinetum_active_ctx *ctx, kinetum_retained_packet_handle retained);
```

`begin_async` acquires one standalone worker credit before returning a valid
token. `begin_async_retained` invalidates the supplied retained handle and
moves its existing packet credit; it exposes only a read-only contiguous byte
view. It may consume the provisional handle created earlier in the same INGEST
callback; complete batch validation then commits that token ownership exactly
once. If a synchronous foreign submit refuses ownership, `abort_async` either
retires standalone work or restores packet ownership under a fresh retained
handle. Once a token is transferred, at most one foreign caller may win
`kinetum_async_complete`; duplicate, stale, malformed, wrong-context, and reused
identities reject without mutation. Handle, operation table, and portal are one
opaque capability and must never be mixed across tokens. The foreign engine
writes any mutable result into module-owned token-associated storage before
completion; the completion queue's release/acquire publication makes those
bytes visible to the later owner callback.

Transition or shutdown drain release-publishes cancellation before delivering
`KINETUM_TRIGGER_DRAIN`. Cancellation is cooperative and never fabricates an
outcome: a SUCCESS published after cancellation is still delivered as SUCCESS.
The plan-authored grace bounds exact cancellation completion; expiry is
fail-stop. A completion restores packet-bound ownership before RUN and keeps
standalone credit live through callback return. FINI, image unload, and slab
destruction are forbidden while any token, queued completion, callback
delivery, or restored retained handle remains.

Recirculation is deliberately narrow: same worker, same active stage instance,
and OPEN only. It transfers one retained packet through the existing bounded
pending-disposition path without creating another credit. A recirculation
already pending when DRAIN starts may publish once, but its resulting callback
cannot recirculate again; the bounded retained population therefore closes.
Authored cycles, cross-worker recirculation, and alternate stage targets remain
unsupported.

Every handle in `expired[]` is callback-borrowed and becomes stale when that
callback returns. During transition or shutdown drain, the same array also
delivers timers cancelled by the platform so their module policy can resolve
without a second cancellation path. Expiry releases the armed quota before
callback entry while retaining the old timer's work credit through return, so
a capacity-one periodic timer may arm its next occurrence in that callback.

The platform ledger represents retained packets, timers, queued control, PULL,
origin records, foreign tokens, completion callbacks, recirculation, and
ordinary callback execution. Drain prevents every new old-work source, exposes
bounded retained/timer/completion prefixes, and requires their exact resolution
before ACTIVATE. No timeout or synchronous handle is interpreted as a foreign
completion.

#### Exact active descriptor

```cpp
const kinetum_module active_descriptor{
    .module_id = "example.active",
    .module_version = "1.0.0",
    .abi_version = KINETUM_MODULE_ABI_VERSION,
    .flags = KINETUM_MOD_F_LIVE_EPOCH_TRANSITION,
    .mode = KINETUM_MODULE_ACTIVE,
    .prepare_config = kinetum_noop_prepare_config,
    .activate_config = kinetum_noop_activate_config,
    .retire_config = kinetum_noop_retire_config,
    .process = nullptr,
    .ingest = example_ingest,
    .run = example_run,
    .on_control = example_on_control,
    .init = example_init,
    .fini = example_fini,
    .health_check = nullptr,
};
```

Multiple contexts for one image additionally require
`KINETUM_MOD_F_REPLICABLE_CONTEXTS`. A callback table alone remains
insufficient: exact authored limits, instance bindings, storage, and worker
ownership must all agree before provider effects.

#### Hot-path contract

`ingest`, `run`, `on_control`, ACTIVATE, and health execute on the owner worker.
They must not allocate, block, take a mutex, log, throw, or perform unbounded
work. Foreign threads may only complete a copied token or query cancellation;
they never invoke module callbacks or mutate worker/scheduler/ledger state.
Active control and PULL endpoints are permanently same-worker in this
contract; a cross-worker relation rejects instead of receiving an inferred
channel or mailbox.


## Part 6: Built-in Modules as Exemplars

The three built-ins under `src/modules/` demonstrate production structure and
conformance through the same SDK path as customer modules.

### 17. ACL Module (`kinetum.acl`)

**Purpose.** Stateless 5-tuple permit/deny classifier and the canonical
SDK classifier example.

**Files.**

- `src/modules/acl/acl.proto` - typed host/offline authoring model for the
  module-owned strict JSON contract.
- `src/modules/acl/acl_impl.hpp` / `acl_impl.cpp` - CIDR parsing,
  rule evaluator, hash cache.
- `src/modules/acl/acl_module.hpp` / `acl_module.cpp` - SDK glue.
  `KINETUM_MODULE_REGISTER(acl_module)` at the end of `acl_module.cpp`.

**Config shape (`kinetum.module.acl.v1.AclRuleset`).** The proto is the
host/offline authoring model. The runtime `config_blob` is strict snake-case
JSON with the same compact shape. `default_action` is a required nonzero
`PERMIT` or `DENY`; `rules` is an optional collection and `max_rules` is an
optional nonnegative limit. Every authored rule requires a nonzero `action`;
its priority, CIDRs, protocol, port ranges, and enabled state retain their
documented proto3 defaults. Enum values are integers. Unknown, duplicate,
removed, zero, or aliased action values; malformed UTF-8;
fractional/exponent numbers; text-proto; binary-proto; and trailing data all
reject rather than selecting another parser.

The compiler rejects negative `max_rules`, a populated rule count above a
nonzero limit, protocols outside `0..255`, invalid CIDRs, missing or unknown
actions, and negative, reversed, or out-of-range port ranges.
`ACL_ACTION_UNSPECIFIED` always rejects. PREPARE allocates and compiles one immutable
`acl_prepared_artifact` in the platform-provided epoch arena. Its
`acl_packet_config` points at the exact compiled ruleset and records the
preselected evaluator strategy. The prepared artifact seals its epoch-resource
adapter before returning success; the platform then publishes the packet view
through its tagged slot and returns
the ownership record to RETIRE exactly once.

**Hot-path algorithm.** `do_process` iterates `batch->count` packets.
For each, it reads `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`
from the SoA arrays and evaluates against the compiled ruleset:

1. Rules are compiled and **sorted by priority (descending)** during
   PREPARE, with authored order as the explicit equal-priority tie-breaker, so
   evaluation walks one deterministic order without a per-packet sort.
2. **First match wins.** The evaluator returns the matched rule's
   action and stops scanning.
3. **If no rule matches**, the explicitly authored `default_action` applies.
   An absent or zero value rejects. An absent or empty rule collection is
   lawful, so `{ "default_action": 2 }` is the explicit deny-all form. A
   zero-length blob or empty JSON object is invalid.

The evaluator strategy is declared by `enum class acl_eval_strategy {
LINEAR, HASH_CACHE, SIMD_BATCH }` in `acl_impl.hpp`. Current selection
is source-defined by ruleset size: `<= 16` rules uses linear scan,
`17..256` uses the context-local hash cache, and `> 256` uses
`classify_batch_acl()` over the precomputed SIMD rule representation.
Every strategy consumes the same rule semantics. CIDR matching masks both the
packet and the authored network, so accepted host bits outside the prefix do
not change meaning. Source and destination port ranges constrain TCP and UDP
only; ICMP and other protocols ignore those fields. SIMD unsigned inclusive
port comparisons preserve both `0` and `65535` without wrapping endpoint
arithmetic. Architecture-selected implementations are checked against one
independent scalar oracle at every vector boundary.
The forward-mask bit remains set for permit and is cleared with
`KINETUM_DROP` for deny actions.

The hash cache is a member of `acl_module`: one cache per admitted context,
owned by that context's sole worker and allocated from the platform-provided
INIT arena. A new context or generation receives a fresh object, so stale
decisions cannot cross context or image ownership. Each entry is tagged by the
exact platform packet epoch; epoch changes therefore invalidate lookup
authority in O(1) without scanning the cache.

**Health behavior.** `acl_module::do_health_check` runs on the owner worker
against the exact active `acl_packet_config` and checks two conditions:

- If no rules are configured, `health_score = 80`,
  `KINETUM_HEALTH_F_CONFIG_ISSUE`, with a reason that names the exact
  configured default (`deny-all` or `permit-all`). An unavailable active
  configuration is reported separately.
- If `packets_evaluated > 1000` and `denied/evaluated > 95%`,
  `health_score = 60`, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason
  "Deny ratio > 95% - check rules". Above 80% through 95%, score
  drops to 75 without setting the config-issue flag.

The `KINETUM_HEALTH_F_CONFIG_ISSUE` flag is the Guardrails-relevant
output: it signals "a recent config change is the suspect."

**Counters registered.** `acl.packets_evaluated`,
`acl.packets_permitted`, `acl.packets_denied`, `acl.cache_hits`,
`acl.cache_misses`. Updates are owner-local and batched; the module does not
read a clock or publish an image-local latency source.

**Runtime note.** ACL strategy selection is module-owned and derives from the compiled ruleset;
no platform-level strategy hint overrides it.

### 18. NAT44 Module (`kinetum.nat44`)

**Purpose.** Stateful IPv4 NAT (NAPT) with bidirectional session
tracking, multiple public-IP pools, and incremental garbage collection.
The canonical use of the SDK for a stateful policy.

**Files.**

- `src/modules/nat44/nat44.proto` - typed host/offline authoring model for the
  module-owned strict JSON contract.
- `src/modules/nat44/nat44_impl.hpp` / `nat44_impl.cpp` - session
  table, pool allocator, GC.
- `src/modules/nat44/nat44_module.hpp` / `nat44_module.cpp` - SDK
  glue. `KINETUM_MODULE_REGISTER(nat44_module)` at the end of
  `nat44_module.cpp`.

**Config shape (`kinetum.module.nat44.v1.NatPools`).** The proto is the
host/offline authoring model. Runtime `config_blob` bytes are strict
snake-case JSON containing top-level `pools`, `session_timeout_s`, and
`max_total_sessions`; each pool contains `public_ip_ranges`, `port_min`, and
`port_max`. Unknown, duplicate, removed, or aliased fields and every non-JSON
encoding reject. `public_ip_ranges` must contain dotted IPv4 addresses or
ascending inclusive dotted-IPv4 ranges such as
`"203.0.113.10-203.0.113.20"`; CIDR notation is not accepted. Ranges are
sorted by address during PREPARE, and duplicate or overlapping address
authority rejects rather than overstating the bounded allocation space. The
module uses the public header-owned `kinetum::algo::parse_ipv4` authority, so
the built-in image does not import a host implementation symbol for address
parsing.

The PREPARE compiler rejects configs with no pools, pools with no public
ranges, invalid or reversed IP ranges, negative `session_timeout_s`,
negative `max_total_sessions`, `max_total_sessions` larger than the
per-context slab capacity (`NAT_DEFAULT_MAX_SESSIONS = 65536`), and
invalid port ranges. `port_min` and `port_max` must be `1..65535` with
`port_min <= port_max`. A top-level `session_timeout_s` of `0` uses
`NAT_DEFAULT_TIMEOUT_S`; `max_total_sessions` of `0` uses
`NAT_DEFAULT_MAX_SESSIONS`. A successful `nat44_prepared_artifact` owns the
compiled pools in the sealed PREPARE arena and exposes a compact immutable
`nat44_packet_config` containing the pool pointer.

**Hot-path algorithm.** `nat44_module::do_process` resolves the already-selected
`nat44_packet_config` from `batch->epoch_config`. A missing exact view or pool
drops the whole batch fail-closed. Per packet:

1. Skip non-TCP/UDP and non-IPv4 traffic by forwarding it as-is. Drop
   fragments because NAT needs L4 ports.
2. Classify direction by `is_private_ip(src_ip)`: private source means
   outbound/SNAT, otherwise inbound/DNAT.
3. Validate the packet buffer, IPv4/TCP/UDP header bounds, and IPv4/UDP
   length fields. Malformed or truncated input drops before session lookup,
   creation, or byte mutation.
4. Build the direction-specific 5-tuple key and look up the session in
   `out_map_` (outbound direction) or `in_map_`
   (inbound direction). Both are `kinetum::algo::cuckoo_map` instances
   mapping keys to slab indices.
5. If inbound and no session exists, drop. If outbound and no session exists,
   allocate a public IP + port from the context's eligible pool residues
   using deterministic round-robin/counter selection.
   PREPARE records cumulative address ordinals, so range selection is an
   allocation-free binary search rather than a packet-path linear rescan. The
   fixed `NAT_MAX_ALLOC_ATTEMPTS` cap bounds collision work. On success,
   install the session in both maps; on failure, drop.
6. Rewrite the mapped source or destination IP and port in both SoA metadata
   and packet bytes. Adjust IPv4 and L4 checksums from the changed words.
   IPv4 UDP checksum absence stays zero; a computed UDP zero becomes `0xffff`,
   while TCP zero remains an ordinary checksum. This neither scans the payload
   nor validates or repairs an incoming checksum.

The session table and telemetry baseline are **per admitted context** members of
`nat44_module`, owned by one worker. There is no thread-local generation fence
and no mutable state shared across replicas. Sessions live
in a contiguous pre-sized PMR slab allocated from the platform INIT arena,
with a `bounded_index_pool` for O(1) non-growing acquisition/release. The `out_map_` and `in_map_`
map 5-tuples to slab indices, not to session pointers. No default heap fallback
exists in the production constructors.

Garbage collection is **incremental and cursor-based**: the table walks
a bounded slice of the slab every `NAT_GC_TRIGGER_MASK + 1` translation calls,
reclaiming sessions whose idle age exceeds the compiled
top-level `session_timeout_s` (default `NAT_DEFAULT_TIMEOUT_S = 300`).
Session activity consumes the platform-stamped monotonic packet-arrival
timestamp from `batch->ts_ns[i]`; module code does not read a clock. A delayed
packet cannot move the session high-watermark backward.

#### Session ownership across ingress queues

For a module population of `N`, context `i` allocates only public ports with
`port % N == i`. PREPARE compiles each pool's eligible range, and allocation
steps directly through that range. Contexts keep independent session tables;
public endpoints cannot collide between owners for the same remote tuple.

The stateless selector hashes the complete original outbound tuple into the
permitted context set. Return traffic derives its owner from the translated
destination port. Fragments and traffic outside IPv4 TCP/UDP are classified
before port arithmetic; the packet callback retains its fragment-drop and
non-NAT forwarding rules. An unavailable return owner rejects the packet.

Existing sessions keep their endpoints across pool updates until expiration or
context destruction. Hardware RSS chooses an ingress queue; it does not prove
ownership after NAT rewrites a tuple. Custom stateful modules must likewise
provide a proven same-context rule when using multiple owners.

**Health behavior.** `nat44_module::do_health_check` runs on the owner worker
against the exact active `nat44_packet_config`:

- If no pools configured: `health_score = 60`,
  `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason "No NAT pools - traffic
  dropped" (early return).
- If `translated + alloc_failures > 1000` and `alloc_failures/total >
  10%`: `health_score = 50`, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason
  "Alloc fail >10% - pool exhausted".
- Above 1% through 10%: `health_score = 80` (no config-issue flag).
- If `translated + dropped > 1000` and `dropped/total > 30%`:
  `health_score = 60`, no additional flag, reason "Drop >30% - check NAT
  config". When conditions overlap, the lowest score and its corresponding
  reason remain authoritative.

**Counters registered.** `nat44.packets_translated`,
`nat44.packets_dropped`, `nat44.sessions_created`,
`nat44.sessions_expired`, `nat44.inbound_misses`, and
`nat44.allocation_failures`. Current `do_process()` updates translated and
dropped counters, and mirrors cumulative owner-local table deltas for
`total_created`, `total_expired`, `inbound_misses`, and
`allocation_failures` into the registered module counters. Those cumulative
table values are monotonic under one context owner; regression is an ownership
contradiction and terminates instead of being normalized as a reset.

The compact schema has no mode, per-pool timeout/capacity, priority, or
connection-tracking switches. Such fields are rejected as unknown rather than
accepted and ignored.

### 19. QoS Module (`kinetum.qos`)

**Purpose.** Token-bucket rate limiting with DSCP-name-based profile
selection and optional DSCP remarking for conforming packets. The
canonical use of the SDK for a policer.

**Files.**

- `src/modules/qos/qos.proto` - typed host/offline authoring model for the
  module-owned strict JSON contract.
- `src/modules/qos/qos_impl.hpp` / `qos_impl.cpp` - profile compiler,
  token bucket, and preallocated flow table.
- `src/modules/qos/qos_module.hpp` / `qos_module.cpp` - SDK glue.
  `KINETUM_MODULE_REGISTER(qos_module)` at the end of `qos_module.cpp`.

**Config shape (`kinetum.module.qos.v1.QosProfiles`).** The proto is the
host/offline authoring model. Runtime `config_blob` bytes are strict
snake-case JSON containing `profiles`, `default_profile`, `gc_trigger_mask`,
`gc_max_evictions`, and `idle_timeout_s`; each profile contains `name`,
`cir_kbps`, `cbs_kb`, and `conform_dscp`. Unknown, duplicate, removed, or
aliased fields and every non-JSON encoding reject. Profiles are mapped to packets by
convention: a profile named `dscp_46` is used for DSCP 46; otherwise
packets use the configured `default_profile`. The default profile name
must be non-empty and must match a compiled profile. Empty profile
lists, empty profile names, duplicate profile names, invalid numeric
limits, and invalid `conform_dscp` values reject the epoch
configuration during PREPARE. An authored `gc_max_evictions` is bounded by
the fixed 1,024-entry GC scan prefix, so no accepted value is silently
reduced. The prepared artifact and all profile strings
and arrays live in the sealed platform PREPARE arena. It resolves the default
profile and all 64 DSCP profile pointers once. An explicit unlimited profile
is valid by setting that named profile's `cir_kbps` to `0`; the module does not
create an implicit fallback for empty or missing defaults.

**Hot-path algorithm.** `qos_module::do_process` in `qos_module.cpp`:

1. Cast the exact active `qos_packet_config` from `batch->epoch_config`.
   If no exact config is published, the module
   drops all packets fail-closed. **The table is a 64-entry array
   indexed by DSCP byte (0-63), built during PREPARE from
   `dscp_N` profile names, plus a direct pointer to the configured
   default profile.** Lookup is a single indexed array read followed by
   that pre-resolved default pointer when the DSCP slot is empty; no
   hashing and no string lookup occur in `do_process()`.
2. For each packet, read `dscp[i]`, index into the precomputed
   profile array.
3. Apply the token bucket using the platform-stamped monotonic packet-arrival
   timestamp in `batch->ts_ns[i]`: compute tokens accumulated since the bucket
   high-watermark using fixed-point Q20 arithmetic, cap at `cbs_kb`, and compare
   against packet length. A delayed timestamp never moves the bucket backward.
   When an exact replacement profile lowers `cbs_kb`, retained flow credit is
   capped to the new burst before refill or consumption; old-policy credit
   cannot escape the new ceiling. `cir_kbps == 0` means unlimited.
4. Before policing a profile that requires remarking, validate the complete
   IPv4 header so malformed bytes cannot consume tokens or flow capacity.
   Allowed: keep `FORWARD`, optionally remark DSCP to `conform_dscp`
   if configured (both the SoA `dscp[i]`
   field and the on-wire IPv4 DS byte are updated, and the IPv4 header
   checksum is recomputed). Malformed packet buffers are dropped before
   policer-state or byte mutation. Not enough tokens: `DROP`.

The flow policer is a member of each admitted `qos_module` context and has one
owner worker. A new context/generation receives a fresh policer, so token
buckets cannot bleed between replicas or image generations. Each policer uses a
preallocated slab plus
`cuckoo_map` from `flow_hash` to slab index. Each context owns one such policer,
not a shard array. The slab, map, and `bounded_index_pool` are allocated from
the platform INIT arena. New-flow admission acquires one fixed pool index;
exhaustion fails closed and drops. No default heap fallback exists in the
production constructors.

**Health behavior.** `qos_module::do_health_check` runs on the owner worker
against the exact active `qos_packet_config`:

- If no profiles configured: `health_score = 70`,
  `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason "No QoS profiles
  configured" (early return).
- If `allowed + dropped > 1000` and `dropped/total > 50%`:
  `health_score = 50`, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason "Drop
  >50% - check rate limits".
- Above 25% through 50%: `health_score = 75` (no config-issue
  flag).

**Counters registered.** `qos.packets_allowed`, `qos.packets_dropped`,
`qos.bytes_allowed`, `qos.bytes_dropped`, and `qos.active_flows`. Updates are
owner-local and batched; the module uses platform packet timestamps for policy
and does not read a clock or publish an image-local latency source.

The compact schema has no scheduler, peak-rate, weight, priority, exceed-color,
or description surface. Such fields are rejected as unknown rather than
accepted and ignored. The module is exactly the single-tier token-bucket
policer described above.

---

## Part 7: Safety and Build

### 20. Safety Contract

The owner-worker paths are `process`, `ingest`, `run`, `on_control`,
ACTIVATE, and health. Health is low cadence, but it still runs on the packet
owner and obeys the same bounded-execution discipline.

#### Owner-worker rules

- **No locks:** no mutex, shared mutex, condition variable, or lock-backed
  container operation.
- **No allocation or reclamation:** no `new`, `delete`, `malloc`, `free`,
  container growth, shared-pointer reference count, or arena operation.
- **No exceptions:** `module_base` compile-time enforces exact `noexcept`
  metadata, lifecycle, PROCESS, ACTIVATE, optional-health methods, and a
  non-throwing destructor. A direct C-ABI implementation must provide the same
  guarantee; no exception may cross the shared-object ABI.
- **No formatting or logging:** packet callbacks cannot reach lifecycle log
  services; do not call `printf`, stream formatting, or mutate strings.
- **No system calls or blocking:** no file/socket I/O, sleep, scheduler wait,
  or synchronous foreign-device completion.
- **Bounded work:** precompile unbounded policy structure in PREPARE. Packet
  work uses direct arrays, bounded probes, or explicitly bounded scans.
- **Context-local mutable state:** use the live context's sole-worker state.
  Shared writable image globals require a separate admitted synchronization
  design and are not implied by module flags.
- **Exact immutable policy:** cast `epoch_config`; never load a module-global
  current pointer or choose a nearby epoch.
- **Complete disposition and ownership:** every input packet is forwarded,
  retained, or retired exactly once.

ACTIVATE is stricter: it is an O(1) publication point with no failure return.
It may reset bounded context-local metadata and publish exact pointers, but it
cannot perform work that could fail after commit begins.

INIT, PREPARE, RETIRE, and FINI are cold. They may allocate and log only
through lifecycle services and must honor deadlines/cancellation. INIT receives
the exact context-lifetime arena; PREPARE receives the exact epoch-artifact
arena. C++ modules adapt those allocators through `context_memory_resource` and
`epoch_memory_resource`, respectively. The C++ INIT trampoline seals the
context resource after successful initialization. A prepared-artifact owner
must seal its epoch resource before returning success; all built-ins do so. A
sealed resource rejects growth instead of falling back to the process heap.
RETIRE and FINI reattach or reclaim the matching ownership solely to destroy
the owned objects and return exact allocations. PREPARE and RETIRE still must
not mutate live context state.

#### Hot-path utility surface

| Macro/helper | Purpose |
|---|---|
| `KINETUM_LIKELY` / `KINETUM_UNLIKELY` | Branch probability hints. |
| `KINETUM_PREFETCH_L1/L2/L3/NTA/WRITE` | Explicit cache prefetch. |
| `KINETUM_ALIGNED`, `KINETUM_CACHE_LINE` | Cache-line layout authority. |
| `KINETUM_ALWAYS_INLINE` | Force a tiny ABI helper inline. |
| `KINETUM_SIMD_WIDTH` | Width actually compiled into this image: 32-byte AVX2, 16-byte SSE2/AArch64 NEON, or 1-byte scalar. |
| `KINETUM_FORWARD_MASK`, `KINETUM_FORWARD`, `KINETUM_DROP` | Construct and update the callback's sole packet-disposition mask. |

The pure C header and C++ algorithm umbrella expose the same five direct
prefetch classes. Neither surface adds a range loop, ordering fence, or
epoch-specific prefetch operation; callers place each hint at an already
bounded address calculation.

Generic fixed-cost helpers include SIMD comparisons over contiguous `uint8_t`
and `uint16_t` columns. They inspect at most 64 lanes because their result is
one `uint64_t` mask; null input and count zero return zero, excess lanes are
ignored, and the `uint16_t` range is inclusive. AVX2, SSE2, AArch64 NEON, and
scalar tails implement that same contract. Fixed diagnostics, histogram
summaries, comparisons, and explicit no-op lifecycle callbacks have internal
linkage in the ABI header, so using them adds no host SDK runtime dependency or
dynamic export. `batch->flow_hash[]` remains the platform-supplied packet field;
this utility surface neither recomputes that identity nor supplies shared
mutable synchronization.

### 21. Building Modules

Built-in modules are ordinary shared libraries under
`src/modules/{acl,nat44,qos}`. An in-tree custom module should follow the same
top-level CMake ownership pattern:

```cmake
add_library(kinetum_my_module SHARED
  my_module.cpp
  my_impl.cpp
  my_config_parser.cpp
)
kinetum_configure_owned_target(kinetum_my_module)
kinetum_configure_module_target(kinetum_my_module)

set_target_properties(kinetum_my_module PROPERTIES
  PREFIX "lib"
  OUTPUT_NAME "kinetum_my_module"
)
```

Do not add a target-local `install()` rule. If this image is an official
built-in, add its target name to the top-level
`KINETUM_BUILTIN_MODULE_TARGETS` release declaration; that one declaration
drives release build ordering, runtime staging, version-marker verification,
and payload membership. An ordinary in-tree or out-of-tree customer module is
instead supplied through the explicit bundle `--modules-dir` and never gains
runtime-package membership by where its target happens to be defined.

An out-of-tree module uses `find_package(Kinetum CONFIG REQUIRED)` and links
the image to `Kinetum::SDK`. A proto may still define a typed host/offline
authoring model, but its generated code belongs in the authoring or test target,
not in the unloadable module image. The built-ins encode that model as strict
JSON and compile it with an image-local parser. A custom module may define a
different opaque wire format, but it must own one exact parser and must not
probe alternate encodings as fallback interpretations.

#### Exact image requirements

- Build position-independent Linux shared-object code for little-endian x86-64 or AArch64
  with GCC or Clang against the exact `kinetum_sdk.h` ABI revision shipped with
  the target platform. CMake and both public SDK headers reject every other
  compiler or target architecture rather than weakening attributes, alignment,
  export visibility, or spin hints.
- Compile implementation symbols hidden and export only the required
  `kinetum_module_register` authority. The SDK registration macro carries the
  deliberate default-visibility annotation. Symbols pulled from static
  dependency archives remain local to the module image.
- Link with no undefined non-weak imports (`-z defs`). Immediate local binding
  is the runtime backstop, not the first dependency-completeness check.
- GNU C++ implementation and shared-dependency objects use `-fno-gnu-unique`
  so `STB_GNU_UNIQUE` definitions cannot prevent generation-owned unloading.
  Added static and dynamic dependencies must obey the same unload-safe lifetime.
- Do not depend on another module's `RTLD_LOCAL` symbols.
- Do not place a process-global registration mechanism in an unloadable image
  unless it has an exact deregistration protocol that completes before
  `dlclose`. Generated protobuf descriptor registration has no such image
  lifetime contract, so built-in runtime images do not link generated protobuf
  code. Protobuf remains available to host/offline authoring and tests.
- Algorithms used by the image must be header-owned or linked through an
  explicit unload-safe dependency. A declaration in an installed header plus a
  definition in the host executable is not an SDK contract. The public CIDR
  and IPv4 parsing helpers are header-owned examples of this rule.
- Avoid mutable static initialization for context/session state. Static
  immutable descriptors and tables are acceptable.
- Rebuild the module when the exact ABI version changes. There is no
  same-major compatibility promise.

The header-only `Kinetum::SDK` CMake target serves C++ modules; `kinetum.pc`
serves C11. Both supply installed headers, hidden-symbol compilation,
archive-export exclusion, and the no-undefined linker gate.
`Kinetum::ModuleDependency` applies the same import/unload rules to an auxiliary
DSO while preserving its exported API. Link module implementation and the final
image to `Kinetum::SDK`; use `Kinetum::ModuleDependency` only for declared shared
dependencies with safe registration and lifetime.

No SDK runtime library or host helper is implied. No-op lifecycle helpers have
internal linkage in each consuming image. Explicitly link all other owned
implementation dependencies; `-z defs` rejects accidental host imports at link
time.

Release preparation byte-compares staged public headers with `include/kinetum`
and verifies metadata, legal files, examples, and manifest membership. It rejects
private headers and path indirection; it does not compile consumers.

The CTest SDK gate separately stages those install components and builds and
loads C11/pkg-config and C++20/CMake consumers under GNU and Clang.
The C++ consumer uses `find_package(Kinetum CONFIG REQUIRED)` and `Kinetum::SDK`.
Both canaries must
export exactly `kinetum_module_register`, have no unresolved imports, carry no
DPDK dependency, source-tree include path, or provider compile definition, and
obey the same hidden-symbol, no-undefined, and unload-safe image policy as the
built-ins. Independent qualification repeats those consumer checks against the
distributed SDK on a native host without platform source. These
consumer gates complement package-integrity checks and in-tree module tests.

#### Bundle workflow

A real module-bearing deployment is assembled as one verified bundle:

1. Build every required custom and built-in module for the target platform.
2. Place all required main images and versioned `.so` dependencies in one
   explicit flat module source directory. `--modules-dir` is one directory,
   not an overlay stack; a missing image or declared auxiliary dependency is a
   pack error. Built-in module schemas are host-authoring inputs, not runtime
   sidecars.
3. Author the Axiom pipeline, hardware inventory, mandatory complete bindings,
   and one
   complete bootstrap `ConfigSnapshot` whose module set exactly matches the
   plan.
4. Run `kinetum_pack` with the explicit sources:

   First create or admit the exact `/absolute/output` parent and choose an
   absent `my_bundle` leaf; pack never repairs a missing parent or reuses an
   existing output.

   ```sh
   kinetum_pack \
     --axiom /absolute/input/pipeline.axiom.pbtxt \
     --hw /absolute/input/hardware.pbtxt \
     --bindings /absolute/input/bindings.pbtxt \
     --modules-dir /absolute/input/all_modules \
     --bootstrap-snapshot /absolute/input/config_snapshot.pbtxt \
     --out /absolute/output/my_bundle
   ```

5. The packer resolves each module, copies canonical artifacts, normalizes the
   snapshot, writes the manifest, and runs the shared runtime-bundle verifier
   over its own completed output. Partial output is not a success.
6. Run the same consumer gate explicitly where useful:

   ```sh
   kinetum_bundle_verify --bundle /absolute/output/my_bundle
   ```

A bundle is a **directory tree**. External tools may archive, sign, upload,
replicate, or atomically install it; transport and fleet deployment are outside
the format. Verify the extracted tree before startup.

`kinetum_bundle_verify` proves manifest-listed file integrity, canonical
symlink-free paths, plan identity, exact module set, and canonical snapshot
identity. The current format does not prove publisher authenticity; pin or sign
the bundle through an external supply-chain authority when that property is
required.

The production loader consumes each main-image path derived from verified
artifact authority; it never searches CWD, `PATH`, `LD_LIBRARY_PATH`, `/opt`
fallbacks, or an author's original source directory for that image. Declared
shared dependencies are bundle artifacts, retain their ELF basenames beside
the image, and are integrity-covered by the same manifest.

---

## Part 8: Cross-Cutting

### 22. Module Author vs DP Platform Responsibilities

| Concern | Owner |
|---|---|
| Exact C ABI, layout assertions, and flags | SDK |
| Descriptor interpretation and admission | Loader-private DP authority |
| `kinetum_module_register` and complete descriptor | Module author |
| Canonical image path and atomic generation admission | Module manager / verified bundle authority |
| Module-owned config schema and parsing | Module author |
| Snapshot identity, module-set equality, config-blob routing | CP/DP platform |
| Immutable artifact construction and destruction | Module PREPARE/RETIRE |
| Exact two-slot retention and packet-view selection | DP platform |
| Bounded owner publication | Module ACTIVATE on platform owner worker |
| Context state allocation and finalization | Module INIT/FINI through lifecycle services |
| Lifecycle arenas, deadlines, cancellation | DP lifecycle substrate |
| Counter/histogram naming and owner-local updates | Module author |
| Telemetry registration and coherent reader publication | DP platform |
| Packet parsing fields, batch delivery, epoch/config pair | DP platform |
| Verdict, transformation, retained-work disposition | Module author |
| Worker/core/NUMA placement | Gluon selects it, Quark proves host agreement, and DP binds it. |
| Same-context ownership for stateful flows | The plan fixes context membership and permitted destinations; module selection preserves ownership across tuple translation. Hardware RSS only selects receive queues. |
| Active emit/control/pull channels and work credits | DP runtime |
| Health assessment content | Module author |
| Health epoch/time provenance, cadence, and coherent foreign-reader publication | DP owner worker / observer path |
| Bundle construction and semantic/integrity verification | `kinetum_pack` / runtime-bundle verifier |
| Fleet transport, registry, signing, rollout | External deployment system |

The platform never fixes an author defect by guessing a callback, config,
epoch, image path, or state-sharing rule. The author never takes over worker,
slot, or artifact authority through an SDK pointer.

### 23. Determinism for Modules

For each callback the platform supplies one exact tuple:

```text
(module image, context instance, owner worker, packet epoch, packet config)
```

`batch->epoch` and `batch->epoch_config` match. All packets in a batch share
that pair. Active-originated work uses the matching fields in
`kinetum_active_ctx`. Authors must preserve those identities across retained or
emitted work.

Author obligations:

- identical packet + exact immutable config + relevant context state produces
  the same disposition and byte mutation;
- config parsing/compilation is deterministic for identical opaque bytes;
- rule/profile ordering is explicit and stable;
- hash seeds come from plan/config/packet authority, not process entropy;
- wall-clock time is not policy input; a module may consume only the
  platform-supplied monotonic timestamp declared by its packet or active
  callback contract;
- no stale image-global mutable state crosses context or generation identity;
- a missing exact config drops/fails closed rather than choosing current or
  previous;
- packet processing order may affect a single flow's state only where the
  module's flow semantics explicitly require it.

Telemetry timestamps and observation timing may differ between runs; they do
not alter packet policy. A compiler may parallelize cold work only if the
resulting immutable artifact is semantically deterministic.

### 24. Embedding and Testing Notes

The SDK headers define module callbacks; they are not a substitute for the
runtime host.

Use three test layers:

1. **Pure policy tests** call parser/compiler and table algorithms directly.
2. **Exact ABI component tests** load a real `.so` through `module_manager`,
   create a lifecycle context, INIT, PREPARE, ACTIVATE, execute a batch with
   explicit `epoch_config`, RETIRE, and FINI.
3. **Runtime integration tests** prove exact slot selection, owner-worker
   dispatch, active scheduling, provider/boundary behavior, and shutdown.

Do not construct a synthetic live context with fake allocator/logger tables;
those tables are intentionally absent. Component tests construct the cold
lifecycle shell and live owner context separately, exactly as production does.

### 25. Where to Go Next

| Goal | Read |
|---|---|
| See lifecycle and exact config publication visually | [`diagrams/platform_architecture.md`](diagrams/platform_architecture.md#10-module-lifecycle) |
| Understand the module host and packet runtime | [`DATA_PLANE.md`](DATA_PLANE.md) |
| Understand native I/O, storage, and provider integration | [`PROVIDERS.md`](PROVIDERS.md) |
| Author pipeline module stages | [`AXIOM.md`](AXIOM.md) |
| Understand stage-instance/context placement | [`GLUON.md`](GLUON.md) |
| Understand configuration transactions and guardrails | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| Package and verify a runnable bundle | [`KINETUM_PACK.md`](KINETUM_PACK.md) |
| Read built-in module schemas and counters | [`../src/modules/README.md`](../src/modules/README.md) |
| Use shared bounded algorithms | [`ALGORITHM_LIBRARY.md`](ALGORITHM_LIBRARY.md) |
| Follow source and hot-path conventions | [`CODING_GUIDELINES.md`](CODING_GUIDELINES.md), [`PLATFORM_ENGINEERING_GUIDE.md`](PLATFORM_ENGINEERING_GUIDE.md) |
