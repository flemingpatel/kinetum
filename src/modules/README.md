# Built-in Policy Modules

`src/modules/` contains the three built-in policy modules:

- ACL: `kinetum.acl`
- NAT44: `kinetum.nat44`
- QoS: `kinetum.qos`

These `.so` images use the same SDK and module manager as customer modules.
This reference covers their identities, policy, hot-path state, telemetry, and
loading rules.

For the module author contract, read
[`docs/MODULE_SDK.md`](../../docs/MODULE_SDK.md). For the runtime that admits
images and contexts, drives exact lifecycle callbacks, and dispatches packets,
read
[`docs/DATA_PLANE.md`](../../docs/DATA_PLANE.md).

## Mechanism vs Policy

The platform owns image admission, worker placement, memory and packet
ownership, configuration lifetimes, and telemetry publication. The
[lifecycle summary](#lifecycle-summary) shows how built-ins use those mechanisms;
the SDK defines their callback and service contracts.

Each module owns its configuration schema and compiler, packet decisions,
mutable policy state, and health assessment. Health callbacks return a score,
flags, and reason; the platform supplies the observation's epoch and time.

The platform never parses `AclRuleset`, `NatPools`, or `QosProfiles`. It routes
the bytes and lets the module interpret them.

## Modules At A Glance

| Module | Host authoring model | Mode |
|--------|----------------------|------|
| ACL | `kinetum.module.acl.v1.AclRuleset` | PASSIVE |
| NAT44 | `kinetum.module.nat44.v1.NatPools` | PASSIVE |
| QoS | `kinetum.module.qos.v1.QosProfiles` | PASSIVE |

All three use the C++ [passive module base](../../docs/MODULE_SDK.md#6-mode-aware-validation)
and declare `KINETUM_MOD_F_REPLICABLE_CONTEXTS` and
`KINETUM_MOD_F_LIVE_EPOCH_TRANSITION`. NAT44 also declares
`KINETUM_MOD_F_CONTEXT_SELECTION` for its [session ownership](#session-ownership).
Each replica has its own context and worker-owned mutable state. The
[SDK flags](../../docs/MODULE_SDK.md#module-flags-kinetum_mod_f_) define these
capabilities; no built-in claims tracked asynchronous epoch work.

Health ratios below use cumulative counters from the context's lifetime, and
ratio checks require a denominator greater than 1,000. A
`KINETUM_HEALTH_F_CONFIG_ISSUE` flag reports a suspected configuration problem;
[CP guardrails](../../docs/CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) own
attribution and rollback decisions.

## Loading And Paths

The runtime package installs the module images under:

```text
/opt/kinetum/lib/modules/
```

`kinetum_pack` maps the installed source names to bundle identities:

| `module_id` | Source lookup under `--modules-dir` | Copied into bundle as |
|-------------|--------------------------------------|------------------------|
| `kinetum.acl` | `libkinetum_acl.so` | `modules/kinetum.acl.so` |
| `kinetum.nat44` | `libkinetum_nat44.so` | `modules/kinetum.nat44.so` |
| `kinetum.qos` | `libkinetum_qos.so` | `modules/kinetum.qos.so` |

The three built-ins are link-closed and need no runtime schema sidecars. DP
loads them from the verified bundle. Shared-dependency and image-admission
requirements are defined in the
[SDK image contract](../../docs/MODULE_SDK.md#exact-image-requirements);
[`kinetum_pack`](../../docs/KINETUM_PACK.md) owns bundle construction and verification.

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
`KINETUM_ERR_CONFIG_INVALID` without transferring ownership. All three reject
an empty blob or empty JSON object; their required fields are listed below.

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
| `AclRuleset.rules` | Optional collection. All authored rules are validated; enabled rules are compiled in descending priority order, with authored order breaking ties. |
| `AclRuleset.default_action` | Required integer action: `1` = PERMIT, `2` = DENY. Used when no rule matches; omitted, zero, or unknown values reject. |
| `AclRuleset.max_rules` | Positive values limit the authored rule count, including disabled rules. `0` adds no count limit; negative values reject. |
| `AclRule.priority` | Higher priority first; defaults to `0`. |
| `AclRule.src_cidr` / `dst_cidr` | Parsed through the header-owned `include/kinetum/algo/cidr.hpp` contract; empty means `0.0.0.0/0`. |
| `AclRule.action` | Required integer action: `1` = PERMIT, `2` = DENY; omitted, zero, or unknown values reject. |
| `AclRule.protocol` | 0 = any, 1 = ICMP, 6 = TCP, 17 = UDP, other values match exact protocol number. Values outside `0..255` reject the config. |
| `AclRule.src_port_min/max` / `dst_port_min/max` | Constrain TCP/UDP only. `(0, 0)` means any port; a nonzero minimum with maximum `0` selects that single port. Otherwise the inclusive bounds must be ordered within `0..65535`. |
| `AclRule.enabled` | Defaults to `false`. Disabled rules are validated but omitted from evaluation. |

An empty rule collection is valid with an explicit default action:
`{ "default_action": 2 }` is the complete deny-all configuration.

### Evaluation Strategy

ACL chooses the strategy during PREPARE from the number of enabled compiled
rules:

| Rule count | Strategy | Notes |
|------------|----------|-------|
| `<= 16` | `LINEAR` | No cache overhead. |
| `17..256` | `HASH_CACHE` | Context-local direct-mapped flow cache. |
| `> 256` | `SIMD_BATCH` | Builds `packet_batch_soa` and calls `classify_batch_acl`. |

All three strategies use the first matching rule, then the default action if
none matches. CIDR matching masks both the packet and rule network; port ranges
apply only to TCP and UDP; and inclusive unsigned endpoints retain exact
`0..65535` meaning in scalar, AVX2, AVX-512,
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
| `packets_denied / packets_evaluated > 95%` | Score at most 60, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason `Deny ratio > 95% - check rules`. |
| Deny ratio above 80% through 95% | Score at most 75, no config flag added by that branch, reason `Deny ratio > 80% - review config`. |
| Otherwise | Score 100. |

The ratio check follows the configuration check. It may lower the score and
replace the reason while retaining an already-set configuration flag.

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
| `NatPools.pools` | Required. PREPARE retains pools with ports owned by this context and rejects if none remain. |
| `NatPools.session_timeout_s` | Idle timeout shared by the pools. `0` uses 300 seconds; negative values reject. |
| `NatPools.max_total_sessions` | Per-context limit across all pools. `0` uses 65,536; positive values must fit that slab capacity. Negative or larger values reject. |
| `NatPool.public_ip_ranges` | Required; each entry is a dotted IPv4 address or an ascending inclusive `start-end` range. CIDR notation rejects. PREPARE sorts each pool's set by address; reversed, duplicate, or overlapping ranges within that pool reject. |
| `NatPool.port_min` / `port_max` | Used for deterministic public-port allocation. Values must be `1..65535` with `port_min <= port_max`. |

PREPARE sorts each admitted disjoint range set and records cumulative
public-address ordinals for each pool. New-session allocation selects a pool
in round-robin order, then selects address ranges with an allocation-free
binary search. The fixed `NAT_MAX_ALLOC_ATTEMPTS` cap bounds collision attempts
within that pool; allocation does not linearly rescan all configured ranges.

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
directions from `batch->ts_ns[i]`, the platform-stamped packet-origin timestamp.
A delayed packet cannot move it backward. Every `NAT_GC_TRIGGER_MASK + 1`
translation calls, GC walks a bounded slab window and removes sessions idle
longer than `session_timeout_s` from both maps.

### Session Ownership

Every NAT stage authors module context selection. Outbound packets hash their
original tuple into the permitted context set. Context `i` in population `N`
allocates only ports with `port % N == i`, and return packets select that owner
from the translated destination port. PREPARE compiles the eligible residues;
allocation never walks another context's ports. Hardware RSS chooses ingress
queues independently of this session rule. Context identity stays fixed for
the generation, including across pool updates. Existing sessions keep their
translated endpoints until expiration or context destruction.

### NAT44 Packet Behavior

| Condition | Result |
|-----------|--------|
| No config published | Drop all packets. |
| IPv4 metadata flag absent | Forward unchanged. |
| Non-TCP/UDP packet | Forward unchanged. |
| IPv4 TCP/UDP fragment | Drop. |
| Outbound private-source TCP/UDP | Create or reuse SNAT session and rewrite source IP/port. |
| Inbound public-side TCP/UDP with session | Rewrite destination IP/port. |
| Inbound public-side TCP/UDP without session | Drop and increment `inbound_misses`. |
| IPv4 TCP/UDP with a malformed buffer, truncated header, or inconsistent IPv4/UDP length fields | Drop before session lookup, creation, or byte mutation. |
| Slab, map, or pool exhausted | Drop and increment allocation failure counters. |

These are module-callback predicates. The canonical gateway's upstream IPv4
parser rejects non-IPv4 frames before they reach NAT44.

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
| `allocation_failures / (packets_translated + allocation_failures) > 10%` | Score at most 50, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason `Alloc fail >10% - pool exhausted`. |
| Allocation-failure ratio above 1% through 10% | Score at most 80, no config flag added by that branch, reason `Alloc fail >1% - monitor pool`. |
| `packets_dropped / (packets_translated + packets_dropped) > 30%` | Score at most 60, no config flag added by that branch, reason `Drop >30% - check NAT config`. |
| Otherwise | Score 100. |

When conditions overlap, the lowest score and its corresponding reason remain
authoritative; a later, less-severe check cannot overwrite the diagnosis.

## QoS (`kinetum.qos`)

QoS is a token-bucket policer keyed by the packet's post-rewrite IPv4 identity.
It uses precomputed DSCP profile lookup and one context-local policer per replica.

### QoS Source Files

| File | Role |
|------|------|
| `qos.proto` | Host/offline authoring model for the exact runtime fields. |
| `qos_impl.hpp` / `qos_impl.cpp` | Config parsing, profile compilation, per-flow policer, GC. |
| `qos_module.hpp` / `qos_module.cpp` | SDK wrapper, telemetry, epoch config, packet processing, health. |

### QoS Exact Runtime Config Fields

| Field | Behavior |
|-------|----------|
| `QosProfiles.profiles` | Required nonempty collection. Empty or duplicate profile names reject the config. |
| `QosProfiles.default_profile` | Required default profile identity. It must match one compiled profile; missing or empty default profile rejects the config. |
| `QosProfiles.gc_trigger_mask` | GC runs when the valid-policing-operation counter satisfies `(counter & mask) == 0`. Omitted or `0` uses `0xffff`, once every 65,536 operations. |
| `QosProfiles.gc_max_evictions` | Maximum evictions per GC cycle. Omitted or `0` uses 256; positive values above the fixed 1,024-entry scan bound reject. |
| `QosProfiles.idle_timeout_s` | Flow idle timeout in seconds. Omitted or `0` uses 30; values above `UINT32_MAX` reject. |
| `QosProfile.name` | Profile key. Exact names `dscp_0` through `dscp_63` populate the O(1) DSCP lookup table. |
| `QosProfile.cir_kbps` | Multiplied by 125 to obtain bytes per second. `0` means unlimited for that named profile; negative or overflowing values reject the config. |
| `QosProfile.cbs_kb` | Burst allowance in KiB, multiplied by 1024 to obtain bytes. Negative or overflowing values reject the config. |
| `QosProfile.conform_dscp` | `0` leaves DSCP unchanged. Values `1..63` remark allowed IPv4 packets, preserve ECN, and recompute the IPv4 header checksum. Values outside `0..63` reject. |

There is no three-color marker. The result is binary: allow or drop.
`conform_dscp` is the only DSCP rewrite performed.

### QoS Hot-Path State

Each admitted QoS context owns one preallocated `qos_policer`; exactly one
worker mutates it.

`qos_policer` contains:

- A contiguous slab of 32-byte credit/time/occupancy rows and a separate 16-byte
  reclamation-key array sharing each slab index's lifetime.
- A `bounded_index_pool` that recycles bucket indexes without container growth.
- A `cuckoo_map<flow_key, slab_index, flow_identity_hash>` with semantic field equality.
- Shared `algo::byte_credit` state retaining exact fractional bytes.
- Cursor-based incremental GC.

Callback scratch holds copied keys and bucket ordinals, with no retained
packet or policy pointers. Policing and GC preserve packet order.

Token refill and idle timeout use `batch->now_ns`, the worker's once-per-turn
processing time, with no module clock read. A decreasing value terminates before
mutation. This context-wide clock history survives policy changes and an empty
flow table. Lowering the configured burst caps existing credit before refill or
consumption; the supplied profile's rate governs that observation.

Unfragmented IPv4 TCP/UDP keys contain directional addresses, protocol, and
ports from the SoA lanes, including zero-valued ports. Eligibility comes from
the IPv4 version, IHL, and four port bytes within the declared on-wire extent.
Fragments, including first fragments, and other IPv4 protocols use an explicit
address/protocol aggregate with zero ports in its key.
The parser's steering hash and mutable offset lanes never establish identity
or prove that port bytes exist. These checks precede flow-state mutation. An
unlimited profile with no remarking needs neither a flow key nor IPv4 bytes.

### QoS Packet Behavior

| Condition | Result |
|-----------|--------|
| No config published | Drop all packets as unconfigured. |
| Present prepared view with null `profiles` or `default_profile` | Terminate in packet or health execution. |
| Regressed processing time | Terminate before packet or flow mutation. |
| `dscp_<n>` profile exists | Packets with DSCP `n` use that profile. |
| No matching DSCP profile | Uses the default profile pointer resolved during PREPARE. |
| Profile CIR is 0 | No bucket required; still validate required remarking bytes and service GC. |
| Bounded or remarking profile with missing required IPv4 bytes, or bounded unfragmented TCP/UDP traffic missing port bytes | Drop as invalid input before policing. |
| Enough tokens | Allow, optionally rewrite conform DSCP for IPv4 after validating packet bounds. |
| Not enough tokens | Drop as rate limited. |
| Policer slab/map exhausted | Drop as flow capacity; the new flow is not admitted. |

### QoS Telemetry

`do_init` registers:

- `qos.packets_allowed`
- `qos.packets_dropped`
- `qos.bytes_allowed`
- `qos.bytes_dropped`
- `qos.active_flows`
- `qos.unconfigured_drops`
- `qos.rate_limit_drops`
- `qos.flow_capacity_drops`
- `qos.invalid_input_drops`

Current occupancy comes directly from the bounded index pool; the policer keeps
no parallel statistics authority. The four cause counters sum exactly to
`qos.packets_dropped`; each rejection contributes once.

### QoS Health

| Condition | Score / flags |
|-----------|---------------|
| Absent configuration view | Score 70, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason `No QoS profiles configured`. |
| `packets_dropped / (packets_allowed + packets_dropped) > 50%` | Score at most 50, `KINETUM_HEALTH_F_CONFIG_ISSUE`, reason `Drop >50% - check rate limits`. |
| Drop ratio above 25% through 50% | Score at most 75, no config flag added by that branch, reason `Drop >25% - review QoS config`. |
| Otherwise | Score 100. |

## Lifecycle Summary

The built-ins follow the [SDK lifecycle](../../docs/MODULE_SDK.md#3-module-lifecycle):

| Phase | Built-in module work |
|-------|----------------------|
| INIT | Construct the module object and its cache, session table, or policer using the context memory resource; register counters. |
| PREPARE | Parse and compile policy in the epoch arena, seal its resource, and return the artifact owner plus immutable packet view. |
| ACTIVATE | Validate the prepared owner/view pairing. The platform publishes that view for the exact epoch. |
| Packet and health callbacks | Use the context's mutable state and the supplied immutable configuration. |
| RETIRE | Destroy the exact prepared artifact transferred back by the platform, including a successfully prepared but never-activated artifact. |
| FINI | Destroy context state after packet work and prepared artifacts are retired. |

[DP admission and lifecycle](../../docs/DATA_PLANE.md#14-exact-module-generation-and-lifecycle)
own image validation, callback scheduling, quiescence, and unload ordering.

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

## Where To Read Next

| Need | Read |
|------|------|
| Module author API and descriptor fields | [`docs/MODULE_SDK.md`](../../docs/MODULE_SDK.md) |
| How built-ins use the SDK | [SDK Part 6](../../docs/MODULE_SDK.md#part-6-built-in-modules-as-exemplars) |
| Dataplane module loading and dispatch | [`docs/DATA_PLANE.md`](../../docs/DATA_PLANE.md) |
| Bundle module rewriting and runtime paths | [`docs/KINETUM_PACK.md`](../../docs/KINETUM_PACK.md) |
| Operator-side config pushes | [`docs/KINETUMCTL.md`](../../docs/KINETUMCTL.md) |
| Deployment walkthrough | [`docs/GETTING_STARTED.md`](../../docs/GETTING_STARTED.md) |
| Shared hot-path primitives | [`docs/ALGORITHM_LIBRARY.md`](../../docs/ALGORITHM_LIBRARY.md) |
