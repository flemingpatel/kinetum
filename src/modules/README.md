# Built-in Policy Modules

`src/modules/` contains the three built-in policy modules:

- ACL: `kinetum.acl`
- NAT44: `kinetum.nat44`
- QoS: `kinetum.qos`

These `.so` images use the same SDK and module manager as customer modules,
without special configuration or callback handling. This reference covers
their identities, policy, hot-path state, telemetry, and loading rules.

For the module author contract, read
[`docs/MODULE_SDK.md`](../../docs/MODULE_SDK.md). For the runtime that admits
images and contexts, drives exact lifecycle callbacks, and dispatches packets,
read
[`docs/DATA_PLANE.md`](../../docs/DATA_PLANE.md).

> **Runtime contract:** ACL, NAT44, and QoS implement the exact
> INIT/PREPARE/ACTIVATE/RETIRE/FINI lifecycle and execute only against the
> immutable view for the current packet epoch. They use the same link-closed
> image, context ownership, worker placement, telemetry, health, transition,
> and teardown path required of an external module. No built-in-only loader or
> configuration fallback exists.

## Mechanism vs Policy

The platform provides mechanism:

- Link-closed module images: hidden implementation symbols, local static-archive
  symbols, one deliberate registration export, and no unresolved non-weak
  imports.
- Unload-safe image-local runtime mechanisms. Generated protobuf schemas remain
  host/offline authoring models and are never linked into unloadable built-in
  images.
- `dlopen(RTLD_NOW | RTLD_LOCAL)` and `dlsym("kinetum_module_register")`.
- Exact descriptor validation, including ABI-version equality, known flags,
  mandatory lifecycle callbacks, and PASSIVE/ACTIVE mode rules.
- Atomic admission of one canonical image/context generation with deterministic
  image indices and compiled context/worker placement.
- A cold `kinetum_lifecycle_ctx` for tracked allocation, telemetry
  registration, logging, deadlines, and cooperative cancellation.
- A one-cache-line live `kinetum_ctx` containing only context-local mutable
  state and immutable owner-worker placement.
- Opaque `ConfigSnapshot.modules[].config_blob` delivery.
- PREPARE of immutable exact-epoch artifacts, bounded owner-worker ACTIVATE,
  exact owner publications plus backend-neutral reader grace, and exact RETIRE
  only after the global certificate.
- Packet-batch dispatch through `process(batch)` for PASSIVE modules.
- Owner-worker health assessment through
  `health_check(ctx, active_epoch, active_packet_config)`. The module returns
  score/flags/reason; the platform owns publication epoch and time.

Each module provides policy:

- Its own strict JSON runtime contract and host/offline protobuf authoring
  model.
- Its own image-local config parser/compiler.
- Its own hot-path state layout.
- Its own packet forwarding/disposition decisions.
- Its own health score and `KINETUM_HEALTH_F_*` flags.

The platform never parses `AclRuleset`, `NatPools`, or `QosProfiles`. It routes
the bytes and lets the module interpret them.

## Modules At A Glance

| Module | Link-closed image | Bundle image | Host authoring model | Mode |
|--------|-------------------|--------------|----------------------|------|
| ACL | `libkinetum_acl.so` | `modules/kinetum.acl.so` | `kinetum.module.acl.v1.AclRuleset` | PASSIVE |
| NAT44 | `libkinetum_nat44.so` | `modules/kinetum.nat44.so` | `kinetum.module.nat44.v1.NatPools` | PASSIVE |
| QoS | `libkinetum_qos.so` | `modules/kinetum.qos.so` | `kinetum.module.qos.v1.QosProfiles` | PASSIVE |

All three use the C++ [passive module base](../../docs/MODULE_SDK.md#6-mode-aware-validation).
They implement:

- `module_id()`
- `module_version()`
- `flags()`
- `do_init`
- `do_fini`
- `do_prepare_config`
- `do_activate_config`
- `do_retire_config`
- `do_process`
- `do_health_check`

All three return `KINETUM_MOD_F_REPLICABLE_CONTEXTS |
KINETUM_MOD_F_LIVE_EPOCH_TRANSITION` from `flags()`. Replication means one
loaded image may own distinct stage-instance contexts; each context keeps all
mutable cache/session/policer state under one worker. Live-transition support
means PREPARE constructs immutable ownership off-worker, ACTIVATE is bounded
and infallible, and RETIRE reclaims the transferred artifact exactly once.
Image-wide logical serialization orders foreign INIT, PREPARE, RETIRE, and
FINI callbacks without placing a lock on packet execution.

No built-in module claims tracked asynchronous epoch work.

## Loading And Paths

CMake builds these shared objects:

```text
build/src/modules/acl/libkinetum_acl.so
build/src/modules/nat44/libkinetum_nat44.so
build/src/modules/qos/libkinetum_qos.so
```

The runtime tarball installs the same file names under:

```text
/opt/kinetum/lib/modules/
```

Those installed names are not the bundle runtime names. `kinetum_pack` resolves
built-in IDs from `--modules-dir` like this:

| `module_id` | Source lookup under `--modules-dir` | Copied into bundle as |
|-------------|--------------------------------------|------------------------|
| `kinetum.acl` | `libkinetum_acl.so` | `modules/kinetum.acl.so` |
| `kinetum.nat44` | `libkinetum_nat44.so` | `modules/kinetum.nat44.so` |
| `kinetum.qos` | `libkinetum_qos.so` | `modules/kinetum.qos.so` |

The three built-ins are link-closed and need no runtime schema sidecars.
`kinetum_pack` still admits genuine auxiliary `.so` dependencies from the
explicit flat source as exact, symlink-free direct children, preserves each
basename under `modules/`, and covers it in the bundle manifest. A custom
module may use that mechanism only for a dependency whose complete state is
unload-safe under the same generation lifetime.

The verified bundle contract stores module images at:

```text
<bundle_dir>/modules/<module_id>.so
```

Exact generation admission receives canonical absolute regular-file paths. It
does not search the current directory, `PATH`, `LD_LIBRARY_PATH`, install
search semantics, or aliases. Bundle/bootstrap integration is responsible for
deriving those canonical authorities from the verified artifact. DP has no
direct-plan or source-development module-path authority: every runnable
generation receives module identities only from one verified runtime bundle.

## Config Blob Format

All three built-ins accept one runtime format: strict RFC-8259 JSON using exact
snake-case field names and integer enum values. Duplicate fields, unknown
fields, camel-case aliases, floating-point/exponent numbers, malformed UTF-8,
trailing content, protobuf text, and protobuf binary all reject. Parsing builds
no DOM and uses only the exact PREPARE arena for variable storage. Cooperative
cancellation is observed during bounded cold work.

The `*.proto` files are typed host/offline authoring models for tests and
tools. They do not select a second runtime reader and their generated objects
are not linked into the unloadable images. A parse failure makes PREPARE return
`KINETUM_ERR_CONFIG_INVALID` without transferring ownership. Empty input has
an explicit per-module contract.

Empty config behavior differs by module:

| Module | Empty `config_blob` behavior |
|--------|------------------------------|
| ACL | Rejected. ACL requires an explicitly authored nonzero default action. |
| NAT44 | Rejected. NAT requires pools. |
| QoS | Rejected. QoS requires at least one named profile and a matching `default_profile`. |

## ACL (`kinetum.acl`)

ACL is a stateless 5-tuple permit/deny module. It expects parsed packet metadata
from the upstream parse stage and returns the sole per-lane forward mask.

### ACL Source Files

| File | Role |
|------|------|
| `acl.proto` | Host/offline authoring model for the exact runtime fields. |
| `acl_impl.hpp` / `acl_impl.cpp` | Config parsing, rule compilation, CIDR matching, cache, SIMD rule conversion. |
| `acl_module.hpp` / `acl_module.cpp` | SDK wrapper, telemetry, epoch config, packet processing, health. |

### ACL Exact Runtime Config Fields

| Field | Behavior |
|-------|----------|
| `AclRuleset.rules` | Compiled, filtered, sorted by descending priority. |
| `AclRuleset.default_action` | Required nonzero PERMIT or DENY used when no rule matches; omitted, UNSPECIFIED, removed, or unknown values reject. |
| `AclRuleset.max_rules` | If positive, rejects configs with more rules than the limit; negative values reject the config. |
| `AclRule.priority` | Sort key, higher priority first. |
| `AclRule.src_cidr` / `dst_cidr` | Parsed through the header-owned `include/kinetum/algo/cidr.hpp` contract; empty means `0.0.0.0/0`. |
| `AclRule.action` | Required nonzero PERMIT or DENY; omitted, UNSPECIFIED, removed, or unknown values reject. |
| `AclRule.protocol` | 0 = any, 1 = ICMP, 6 = TCP, 17 = UDP, other values match exact protocol number. Values outside `0..255` reject the config. |
| `AclRule.src_port_min/max` / `dst_port_min/max` | Used for TCP/UDP only; negative, out-of-range, or reversed ranges reject the config. |
| `AclRule.enabled` | Disabled rules are skipped. |

### Evaluation Strategy

ACL chooses the strategy during PREPARE from the number of enabled compiled
rules:

| Rule count | Strategy | Notes |
|------------|----------|-------|
| `<= 16` | `LINEAR` | No cache overhead. |
| `17..256` | `HASH_CACHE` | Context-local direct-mapped flow cache. |
| `> 256` | `SIMD_BATCH` | Builds `packet_batch_soa` and calls `classify_batch_acl`. |

All three strategies implement one predicate. CIDR matching masks both the
packet and rule network; port ranges apply only to TCP and UDP; and inclusive
unsigned endpoints retain exact `0..65535` meaning in scalar, AVX2, AVX-512,
SSE, and NEON builds. Cross-architecture tests compare complete masks with an
independent scalar oracle at vector boundaries.

The cache belongs to one admitted context and its sole owner worker. A new
context generation receives a new cache object, so decisions cannot survive
generation replacement. Within one context, every cache entry carries the
exact platform packet epoch. An epoch change invalidates lookup authority in
O(1); module-authored ruleset revisions are never trusted as epoch identity.

### ACL Packet Behavior

| Condition | Result |
|-----------|--------|
| No config published | Drop all packets. |
| Empty rule collection with explicit DENY default | Deny all. |
| Matching PERMIT rule | Retain the lane in the forward mask. |
| Matching DENY rule | Clear the lane from the forward mask. |
| No matching rule | Apply `default_action`. |

### ACL Telemetry

`do_init` registers:

- `acl.packets_evaluated`
- `acl.packets_permitted`
- `acl.packets_denied`
- `acl.cache_hits`
- `acl.cache_misses`

### ACL Health

| Condition | Score / flags |
|-----------|---------------|
| ACL configuration unavailable | Score 80, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason `ACL configuration unavailable`. |
| No ACL rules configured | Score 80, `KINETUM_HEALTH_F_CONFIG_ISSUE`, with the exact `default deny-all` or `default permit-all` reason. |
| More than 95 percent denied after 1000 evaluated packets | Score at most 60, `KINETUM_HEALTH_F_CONFIG_ISSUE`. |
| More than 80 percent denied after 1000 evaluated packets | Score at most 75, no config flag added by that branch. |
| Otherwise | Score 100. |

## NAT44 (`kinetum.nat44`)

NAT44 is a stateful IPv4 NAPT module. It rewrites SoA metadata and packet bytes,
then adjusts IPv4 and TCP/UDP checksums from the changed address and port words.
It does not scan payloads, validate incoming checksums, or repair corrupt input.
IPv4 UDP checksum absence stays zero; a computed UDP zero is encoded as
`0xffff`. TCP zero remains an ordinary checksum.

### NAT44 Source Files

| File | Role |
|------|------|
| `nat44.proto` | Host/offline authoring model for the exact runtime fields. |
| `nat44_impl.hpp` / `nat44_impl.cpp` | Config parsing, pool compilation, session table, GC, address/port allocation. |
| `nat44_module.hpp` / `nat44_module.cpp` | SDK wrapper, telemetry, epoch config, packet processing, health. |

### NAT44 Exact Runtime Config Fields

| Field | Behavior |
|-------|----------|
| `NatPools.pools` | Required; empty pool list rejects config. |
| `NatPools.session_timeout_s` | Global timeout. `0` uses `NAT_DEFAULT_TIMEOUT_S`; negative values reject the config. |
| `NatPools.max_total_sessions` | `0` uses `NAT_DEFAULT_MAX_SESSIONS`; a positive value is enforced against per-context slab capacity and active session count, and negative values reject. |
| `NatPool.public_ip_ranges` | Required; each entry is a single IP or an ascending inclusive `start-end` range. PREPARE sorts the set by address; reversed, duplicate, or overlapping ranges reject the config. |
| `NatPool.port_min` / `port_max` | Used for deterministic public-port allocation. Values must be `1..65535` with `port_min <= port_max`. |

PREPARE sorts each admitted disjoint range set and records cumulative
public-address ordinals for each pool. New-session
allocation selects a range with an allocation-free binary search and retains
the fixed `NAT_MAX_ALLOC_ATTEMPTS` collision bound; it does not linearly rescan
all configured ranges on the packet path.

### NAT44 Hot-Path State

Each admitted NAT44 context owns one preallocated `nat44_table`; exactly one
worker mutates it.

`nat44_table` contains:

- A contiguous session slab.
- A `bounded_index_pool` that recycles slab indexes without container growth.
- `out_map_`: outbound 5-tuple to slab index.
- `in_map_`: public-side inbound 5-tuple to slab index.
- Cursor-based incremental GC.

The session keeps one canonical `last_seen_ns` high-watermark updated by both
directions from the platform-stamped packet-arrival timestamp. A delayed packet
cannot move it backward. GC walks a bounded slab window and removes expired
sessions from both maps.

### Session Ownership

Every NAT stage authors module context selection. Outbound packets hash their
original tuple into the permitted context set. Context `i` in population `N`
allocates only ports with `port % N == i`, and return packets select that owner
from the translated destination port. PREPARE compiles the eligible residues;
allocation never walks another context's ports. Hardware RSS chooses ingress
queues independently of this session rule. Context identity stays fixed for
the generation, including across pool updates.

### NAT44 Packet Behavior

| Condition | Result |
|-----------|--------|
| No config published | Drop all packets. |
| Empty config | Reject PREPARE. |
| IPv6 packet | Forward unchanged. |
| Non-TCP/UDP packet | Forward unchanged. |
| Fragmented packet | Drop. |
| Outbound private-source TCP/UDP | Create or reuse SNAT session and rewrite source IP/port. |
| Inbound public-side TCP/UDP with session | Rewrite destination IP/port. |
| Inbound public-side TCP/UDP without session | Drop and increment `inbound_misses`. |
| Malformed packet buffer, truncated IPv4/TCP/UDP header, or inconsistent IPv4/UDP length fields | Drop before creating a session or rewriting bytes. |
| Slab, map, or pool exhausted | Drop and increment allocation failure counters. |

### NAT44 Telemetry

`do_init` registers:

- `nat44.packets_translated`
- `nat44.packets_dropped`
- `nat44.sessions_created`
- `nat44.sessions_expired`
- `nat44.inbound_misses`
- `nat44.allocation_failures`
Session-table counters are read from the context-local table and converted to
deltas before being added to module telemetry.

### NAT44 Health

| Condition | Score / flags |
|-----------|---------------|
| No NAT pools configured | Score 60, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason `No NAT pools - traffic dropped`. |
| Allocation failures are more than 10 percent of translated+failures after 1000 samples | Score at most 50, `KINETUM_HEALTH_F_CONFIG_ISSUE`. |
| Allocation failures are more than 1 percent after 1000 samples | Score at most 80, no config flag added by that branch. |
| Drop ratio is more than 30 percent after 1000 samples | Score at most 60, no config flag added by that branch, reason `Drop >30% - check NAT config`. |
| Otherwise | Score 100. |

When conditions overlap, the lowest score and its corresponding reason remain
authoritative; a later, less-severe check cannot overwrite the diagnosis.

## QoS (`kinetum.qos`)

QoS is a per-flow token-bucket policer keyed by `batch->flow_hash[i]`. It uses
precomputed DSCP profile lookup and one context-local policer per replica.

### QoS Source Files

| File | Role |
|------|------|
| `qos.proto` | Host/offline authoring model for the exact runtime fields. |
| `qos_impl.hpp` / `qos_impl.cpp` | Config parsing, profile compilation, per-flow policer, GC. |
| `qos_module.hpp` / `qos_module.cpp` | SDK wrapper, telemetry, epoch config, packet processing, health. |

### QoS Exact Runtime Config Fields

| Field | Behavior |
|-------|----------|
| `QosProfiles.profiles` | Required. Compiled into named profiles. Empty or duplicate profile names reject the config. |
| `QosProfiles.default_profile` | Required default profile identity. It must match one compiled profile; missing or empty default profile rejects the config. |
| `QosProfiles.gc_trigger_mask` | Overrides GC trigger mask when positive. |
| `QosProfiles.gc_max_evictions` | Overrides max evictions per GC cycle when positive; values above the fixed 1,024-entry scan bound reject. |
| `QosProfiles.idle_timeout_s` | Overrides flow idle timeout when positive. |
| `QosProfile.name` | Profile key. Names of the form `dscp_<n>` populate the O(1) DSCP lookup table. |
| `QosProfile.cir_kbps` | Converted to bytes per second. `0` means unlimited for that named profile; negative or overflowing values reject the config. |
| `QosProfile.cbs_kb` | Converted to bytes. Negative or overflowing values reject the config. |
| `QosProfile.conform_dscp` | If 1..63, rewrites IPv4 DSCP for allowed packets and recomputes IPv4 header checksum. Values outside `0..63` reject the config. |

There is no three-color marker. The result is binary: allow or drop.
`conform_dscp` is the only DSCP rewrite performed.

### QoS Hot-Path State

Each admitted QoS context owns one preallocated `qos_policer`; exactly one
worker mutates it.

`qos_policer` contains:

- A contiguous bucket slab.
- A `bounded_index_pool` that recycles bucket indexes without container growth.
- A `cuckoo_map<flow_hash, slab_index, flow_identity_hash>`.
- Q20 fixed-point token arithmetic.
- Cursor-based incremental GC.

Token refill and idle timeout use the platform-stamped monotonic arrival time,
with no module clock read. A per-flow high-watermark prevents delayed packets
from creating credit. Lowering the configured burst caps existing credit before
refill or consumption.

### QoS Packet Behavior

| Condition | Result |
|-----------|--------|
| No config published | Drop all packets. |
| Empty config | Reject PREPARE. |
| Missing configured default profile | Reject PREPARE. |
| `dscp_<n>` profile exists | Packets with DSCP `n` use that profile. |
| No matching DSCP profile | Uses the default profile pointer resolved during PREPARE. |
| Profile CIR is 0 | Allow all for that profile. |
| Enough tokens | Allow, optionally rewrite conform DSCP for IPv4 after validating packet bounds. |
| Not enough tokens | Drop. |
| Policer slab/map exhausted | Drop; existing flow ownership is unchanged. |

### QoS Telemetry

`do_init` registers:

- `qos.packets_allowed`
- `qos.packets_dropped`
- `qos.bytes_allowed`
- `qos.bytes_dropped`
- `qos.active_flows`

Current occupancy comes directly from the bounded index pool; the policer keeps
no parallel statistics authority.

### QoS Health

| Condition | Score / flags |
|-----------|---------------|
| No QoS profiles configured | Score 70, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason `No QoS profiles configured`. |
| Drop ratio is more than 50 percent after 1000 samples | Score at most 50, `KINETUM_HEALTH_F_CONFIG_ISSUE`. |
| Drop ratio is more than 25 percent after 1000 samples | Score at most 75, no config flag added by that branch. |
| Otherwise | Score 100. |

## Lifecycle Summary

The exact built-in module path is:

1. The verified deployment authority supplies the complete set of canonical
   absolute module-image paths and compiled context placements.
2. `module_manager::admit_generation` sorts unique module IDs, assigns stable
   image indices, opens every image with `RTLD_NOW | RTLD_LOCAL`, and resolves
   the sole `kinetum_module_register` symbol. Module, version, and context text
   crossing the ABI contains 1..255 printable-ASCII bytes.
3. Each image was linked hidden-by-default with closed imports and one
   deliberate SDK export. The loader-private descriptor-admission authority
   requires exact ABI equality, known capability bits, mandatory
   INIT/PREPARE/ACTIVATE/RETIRE/FINI callbacks, and an exact PASSIVE or ACTIVE
   callback shape.
4. Admission validates all image/context relations before invoking foreign
   code. Multiple contexts for one image require
   `KINETUM_MOD_F_REPLICABLE_CONTEXTS`.
5. Each context receives a cold `kinetum_lifecycle_ctx`. INIT allocates its C++
   module object and all context containers through the tracked context PMR
   resource, then seals allocation before publication. It also registers
   owner-local counters/histograms. Only after every staged context succeeds
   does the manager publish the generation atomically.
6. A lifecycle executor calls PREPARE through the context adapter. PREPARE
   parses strict JSON into the exact epoch-arena PMR resource, seals allocation,
   and transfers one immutable `{owner_handle, packet_config}` record on
   success. Calls targeting one image are logically serialized; different
   images may prepare in parallel.
7. The context's owner worker performs bounded, infallible ACTIVATE. Packet
   batches then carry that exact immutable `packet_config`; `do_process` never
   performs an epoch lookup or manager lookup.
8. Owner-worker health uses the same live context and exact active packet view.
   A null callback means unavailable; the platform never fabricates healthy
   state for an image that did not publish health.
9. The immutable global certificate requires exact worker activation,
   boundary completion, and every frozen reader's safe-point publication. Only
   after that grace completes may the lifecycle executor transfer the ownership
   record once to RETIRE.
10. After owner workers and lifecycle executors join, FINI reattaches the exact
    context allocator and runs in reverse context-index order. Images unload
    only after all dependent contexts finalize; an impossible `dlclose`
    failure is process-fatal rather than silently abandoning loader ownership.

Before packet readiness, DP verifies the bundle/provider graph, admits and
materializes providers, and proves stage-instance/context/placement relations,
bootstrap epoch, and active views. Live transitions reuse those stores and
executors, starting grace before the worker command and retiring old artifacts
after certificate and reader completion. Active/async work shares the worker
ledger. Owner-health callbacks publish validated signals or bounded fault
snapshots; operator telemetry remains all-or-none. Packet execution always uses
the exact tagged view.

All canonical deployment snapshots must contain exactly the module set bound by
the plan. Missing or extra module config is an identity error at bundle/content
verification; neither the manager nor a built-in module invents a configuration
entry.

## Build

Complete the [source-build setup](../../docs/GETTING_STARTED.md#1-build) first.
Module builds are gated by `KINETUM_BUILD_MODULES`, default `ON`:

```sh
cmake -S . -B build -DKINETUM_BUILD_MODULES=ON
cmake --build build --parallel
```

Built-in and customer module targets are provider-neutral. They consume the
same public SDK and module-link policy and do not require a DPDK build option,
header, compile definition, or library edge.

Outputs:

- `build/src/modules/acl/libkinetum_acl.so`
- `build/src/modules/nat44/libkinetum_nat44.so`
- `build/src/modules/qos/libkinetum_qos.so`

Install destination:

```text
lib/modules/
```

The runtime package copies all three link-closed images to
`/opt/kinetum/lib/modules/`.

## Where To Read Next

| Need | Read |
|------|------|
| Module author API and descriptor fields | [`docs/MODULE_SDK.md`](../../docs/MODULE_SDK.md) |
| Built-in module deep exemplars | [`docs/MODULE_SDK.md`](../../docs/MODULE_SDK.md) Sections 17-19 |
| Dataplane module loading and dispatch | [`docs/DATA_PLANE.md`](../../docs/DATA_PLANE.md) |
| Bundle module rewriting and runtime paths | [`docs/KINETUM_PACK.md`](../../docs/KINETUM_PACK.md) |
| Operator-side config pushes | [`docs/KINETUMCTL.md`](../../docs/KINETUMCTL.md) |
| Deployment walkthrough | [`docs/GETTING_STARTED.md`](../../docs/GETTING_STARTED.md) |
| Shared hot-path primitives | [`docs/ALGORITHM_LIBRARY.md`](../../docs/ALGORITHM_LIBRARY.md) |
