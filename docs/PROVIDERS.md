# Providers

Providers connect Kinetum's packet runtime to native I/O, packet storage, and
execution resources. This reference follows that connection from deployment
bindings through component admission, construction, packet ownership, and
shutdown. It also explains the C ABI and the work required to integrate another
provider into the source tree.

The provider ABI is an exact-release platform interface. Its headers are not
part of the installed [Module SDK](MODULE_SDK.md). Providers supply runtime
mechanisms; modules implement packet policy such as ACL, NAT, and QoS.

## Table of Contents

**Part 1: Model and Configuration**

1. [Roles, Contracts, and Instances](#1-roles-contracts-and-instances)
2. [Contracts, Artifacts, and Implementations](#2-contracts-artifacts-and-implementations)
3. [Typed Configuration](#3-typed-configuration)
4. [Compiled Topology and Host Proof](#4-compiled-topology-and-host-proof)

**Part 2: Component ABI**

5. [Descriptor and Identity](#5-descriptor-and-identity)
6. [Factory Calls and Borrowed Data](#6-factory-calls-and-borrowed-data)
7. [Operation Tables and Packet Records](#7-operation-tables-and-packet-records)
8. [Diagnostics and Observations](#8-diagnostics-and-observations)

**Part 3: Runtime Lifecycle**

9. [Installed Component Admission](#9-installed-component-admission)
10. [Construction and Activation](#10-construction-and-activation)
11. [Packet Ownership and Storage Changes](#11-packet-ownership-and-storage-changes)
12. [Shutdown and Failure](#12-shutdown-and-failure)

**Part 4: Current Implementations**

13. [DPDK](#13-dpdk)
14. [Host Storage, CPU Execution, and UDP](#14-host-storage-cpu-execution-and-udp)

**Part 5: Integration and Reference**

15. [Adding a Provider](#15-adding-a-provider)
16. [Build and Release Ownership](#16-build-and-release-ownership)
17. [Source Map](#17-source-map)
18. [Where to Go Next](#18-where-to-go-next)

---

## Part 1: Model and Configuration

### 1. Roles, Contracts, and Instances

Kinetum separates five responsibilities. A component may implement several,
but each role has its own configuration, lifetime, and operation record.

| Role | Responsibility | Current example |
|---|---|---|
| Process facility | Shared native environment and its thread/service lifecycle. | DPDK EAL. |
| I/O driver | Native ports, RX/TX queues, and whole-driver activation. | DPDK ethdev or Linux UDP sockets. |
| Packet storage | Packet records, payload backing, allocation, cloning, and release. | DPDK mbuf pool or host-memory pool. |
| Execution provider | Execution-instance identity and required storage access. | CPU execution supplied by the host component. |
| Storage transition | An authored handoff between storage/access requirements. | Same-domain sharing or bounded CPU copy. |

A **contract** defines a role's configuration and capabilities. A **component**
is the ELF image implementing one or more contracts. An **instance** is one
configured use of a contract in a deployment. For example, one DPDK component
can construct a single EAL facility, an I/O driver, and several independent
packet-storage domains.

The plan connects instances explicitly. Each RX queue selects one allocation
domain; each TX queue declares a nonempty set of accepted domains. A worker
change transfers packet ownership without changing the storage domain. A
storage change requires a declared transition.

The composition is fixed for the runtime generation. Changing provider
instances, attachments, queues, or storage topology requires a new plan/bundle
and process restart. Live configuration snapshots do not replace that graph.

CPU execution remains in the platform's stage and module mechanisms. Its
provider record binds an execution identity and access requirements; it does
not add another callback around every stage invocation.

The [provider architecture diagrams](diagrams/platform_architecture.md#3-providers-and-packet-storage)
show the dependencies and packet transfers. [Gluon](GLUON.md#7-deployment-binding-resolution)
owns the binding schema and its lowering into a plan.

### 2. Contracts, Artifacts, and Implementations

Provider meaning, installed artifacts, and available implementations have
separate owners:

| Authority | Question answered | Contents |
|---|---|---|
| Pure contract catalog | What does this configuration mean? | Exact type URL, role, validation, normalization, capabilities, dependencies, and host requirements. |
| Signed installed inventory | Which artifacts belong to this runtime release? | Runtime and ABI identity, component descriptors, file hashes/sizes, and private dependency closure. |
| Runtime provider catalog | Which verified implementations does this plan require? | Immutable implementation rows for the compiled required-contract set. |

The pure catalog owns no native objects, factories, artifact paths, or hashing
API. The installed inventory does not choose a deployment. The runtime catalog
does not discover libraries or repair missing plan facts. An installed
component may expose several contracts; only requested rows become reachable.

This separation lets Gluon validate a deployment without initializing EAL,
opening packet devices, or loading provider code.

### 3. Typed Configuration

Every provider configuration uses a complete protobuf `Any` type URL:
`type.googleapis.com/<fully.qualified.Message>`. The current catalog is:

| Role | Configuration message | Component |
|---|---|---|
| Process facility | `kinetum.facility.dpdk.v1.DpdkFacilityConfig` | DPDK |
| I/O driver | `kinetum.io.dpdk.v1.DpdkDriverConfig` | DPDK |
| Packet storage | `kinetum.storage.dpdk.v1.DpdkStorageConfig` | DPDK |
| I/O driver | `kinetum.io.udp.v1.UdpDriverConfig` | UDP |
| Packet storage | `kinetum.storage.host.v1.HostStorageConfig` | Host |
| Execution provider | `kinetum.execution.cpu.v1.CpuExecutionConfig` | Host |
| Storage transition | `kinetum.transition.core.v1.ZeroCopyShareConfig` | Host |
| Storage transition | `kinetum.transition.cpu.v1.BoundedCopyConfig` | Host |

#### Payload fields

| Message | Authored fields and bounds |
|---|---|
| `DpdkDriverConfig` | Nonempty `ports[]`. Each `driver_port_id` selects exactly one `pci { pci_address }` or `tap { interface_name }` attachment. |
| `DpdkStorageConfig` | `cache_size` in `0..512` entries per lcore; zero disables caching. Capacity and placement remain plan facts. |
| `UdpDriverConfig` | Nonempty `ports[]` with `driver_port_id`, canonical numeric `ipv4_address`, and `port` in `0..65535`. Direction-specific endpoint legality is checked when the plan consumes it. |
| `DpdkFacilityConfig`, `HostStorageConfig`, `CpuExecutionConfig`, `ZeroCopyShareConfig`, `BoundedCopyConfig` | Empty messages selecting their complete current policy; resource quantities and relationships remain in the plan. |

Driver port IDs match `[A-Za-z_][A-Za-z0-9_]*` within 128 bytes. PCI addresses
use lowercase `dddd:bb:ss.f`, with device and function values in PCI range.
TAP names match `[A-Za-z_][A-Za-z0-9_.-]{0,14}`. UDP addresses must match their
Linux IPv4 parse/render spelling; DNS, IPv6, and alternate textual forms reject.

#### Canonicalization

Admission applies these steps in order:

1. Bound the type URL to 256 bytes.
2. Require its complete canonical spelling.
3. Resolve one catalog row.
4. Require the expected role.
5. Bound the serialized payload to 65536 bytes.
6. Decode the row's generated message.
7. Reject unknown fields in the outer envelope and recursively in the payload,
   including undeclared enum values.
8. Validate provider policy and normalize only declared set-like fields.
9. Serialize the normalized message deterministically.
10. Repack those bytes under the same canonical type URL.

DPDK and UDP driver port lists are duplicate-free sets sorted by
`driver_port_id`. Other repeated fields preserve authored order unless their
contract explicitly defines set normalization. Provider configuration graphs
contain neither protobuf maps nor nested `Any` messages.

The deployment-plan identity owner hashes the completed canonical plan once.
Components do not compute independent configuration hashes or reinterpret
unknown configuration types.

### 4. Compiled Topology and Host Proof

`compile_provider_topology()` combines the canonical plan with the pure
catalog. Gluon self-checks its completed plan through this compiler; bundle
verification uses the same entry point. DP retains the verifier's compiled
artifact and passes it to Quark and provider admission.

| Compiled relation | Required proof |
|---|---|
| Instances and references | Unique bounded identities, complete references, and deterministic compact indices. |
| Facilities | Contract-defined cardinality, scope, sharing, and coexistence. |
| I/O queues | Exact driver, port, direction, owner worker, descriptor count, and steering. RX has one domain; TX has its complete accepted set. |
| Execution | Every stage has an execution provider. Every active stage/lane has one origin domain; passive stages have none. |
| Storage access | Every reachable domain satisfies its executor and I/O requirements. CPU/NIC access bits alone do not prove contiguous CPU bytes or native compatibility. |
| Fan-out | Multiple unconditional successors require independently writable clones. Linear and selected paths do not acquire that requirement. |
| Transitions | Every declared transition matches a real directed handoff, and every required conversion has an authored mechanism. |
| Lanes and contexts | Queue steering, executable replicas, fixed module-context populations, worker ownership, and boundaries agree. |
| Placement and capacity | NUMA, native indices, packet lengths, descriptors, staging, and aggregate capacities fit their representations and budgets. |

Storage reachability uses a worklist over `(node, domain)` pairs. Each pair
enters once: at most `V * D` states and `E * D` edge visits, with binary-search
membership checks at TX. Here `V` is the packet-graph node count, `E` its edge
count, and `D` the storage-domain count. The compiler does not enumerate paths.

The shared `plan_buffer_budget` assigns physical credits to their storage
owners, using the post-transition domain for each handoff. It accounts for
descriptors, worker queues, active/future staging, boundary holds, bounded
copies, retained records, bursts, caches, and safety capacity. Paths converging
on one physical boundary population are charged once per carried domain.
Each TX queue charges its full descriptor population to every accepted domain
because all descriptors may temporarily hold records from that domain. The
queue itself is created once.

Host checks run where the required facts are available:

| Phase | Owner | Evidence |
|---|---|---|
| `QUARK_LIVE_HOST` | Quark, before provider loading. | Planned worker/service CPUs, exact NUMA ownership, and process-allowed host-memory nodes. |
| `COMPONENT_HOST_PROOF` | Admitted component, before factories. | DPDK runtime/hugepage requirements or Linux UDP socket support. |
| `MATERIALIZATION_PROOF` | Component factory/lifecycle. | Native device and queue capabilities requiring initialized resources. |

A component host proof receives immutable compiled facts and may inspect native
state ephemerally. It cannot reserve resources, initialize a facility, create a
persistent thread, or publish operations. Each required instance proof runs
once. Quark does not call these native proofs or reinterpret their results.

The compiled result contains indices, normalized payloads, dependency recipes,
access proofs, routes, budgets, and bounded schedules. Packet workers consume
resolved operations, with no protobuf parsing or component discovery.

---

## Part 2: Component ABI

### 5. Descriptor and Identity

`src/provider/provider_component_abi.h` owns the physical C11/C++20 contract.
It uses fixed-width values, byte/text views, opaque handles, and function
pointers. Protobuf and native provider types do not cross this ABI.

Every component exports one query:

```c
const kinetum_provider_component_descriptor *
kinetum_provider_component_query(void);
```

The query returns an immutable descriptor without allocation, initialization,
registration, or resource acquisition. C++ callbacks are `noexcept`; an
exception may not cross the ABI.

| Descriptor member | Meaning |
|---|---|
| `product_version_major/minor/patch` | Exact Kinetum product version. |
| `abi_identity` | Generated 32-byte identity of the ABI header and provider contract schemas. |
| `component_id` | Stable identity of this implementation image. |
| `contracts` / `contract_count` | Type-URL-sorted, unique contract implementation rows. |

Each row declares its role, exactly one matching factory, and a host-proof
callback when required by the pure catalog. The descriptor must agree with the
authenticated inventory and catalog before any row becomes callable.
Explicit padding is zero, and counted arrays obey their declared pointer/count
shape. Unknown roles, status values, or capability bits reject.

Product version, ABI identity, and file SHA-256 answer different questions:
release identity, declaration identity, and artifact identity. The ABI has no
size negotiation or extension area. Changed declarations regenerate its
identity; the runtime and components rebuild together. C11 and C++20 assertions
pin sizes, alignments, and offsets. `CMakeLists.txt` declares the provider schema
inputs and generates `provider_build_identity.h` during configuration.

### 6. Factory Calls and Borrowed Data

One factory constructs one instance of its declared role. The materializer
supplies a `kinetum_provider_factory_request` containing:

| Input | Lifetime and authority |
|---|---|
| Instance ID, type URL, canonical configuration | Borrowed for the callback; copy any needed values into instance-owned storage. |
| `compiled_facts` | Exactly one role-matching C fact tree. It and subordinate arrays are borrowed for the callback. |
| Dependencies | Already constructed instances and immutable operation records. Their handles may be retained until the dependent instance is destroyed. |
| Runtime generation | Nonzero identity shared by the constructed generation. |
| Cold logging capability | May be copied; valid through destruction after every provider emitter has stopped. |

Dependencies arrive with declared facilities first in stable instance order,
then compiler-derived dependencies in role/instance order. Text views and the
dependency array remain call-borrowed even though the instance and operation
handles have longer lifetimes.

The caller zero-initializes `kinetum_provider_factory_result`:

| Outcome | Required result |
|---|---|
| Success | Non-null instance, complete immutable role operation record, and destroy callback. |
| Failure | All three fields null; the factory has released its partial resources. |

The materializer validates callback/result shape, claims the complete instance,
then checks its operation record against compiled facts before publication.
It calls foreign code without holding a platform lock. Dependency instances and
component code outlive every dependent.

### 7. Operation Tables and Packet Records

Role operation records are immutable and cache-line aligned. Their opaque
`state` can be mutable, subject to the role's calling contract.

Packet callbacks follow the [PEG hot-path rules](PLATFORM_ENGINEERING_GUIDE.md#pat-1-no-hot-path-allocation).
Pool operations consume preallocated credits. A provider may use only system
calls intrinsic to its admitted I/O mechanism, such as UDP socket transfers.

| Operation record | Responsibilities | Caller |
|---|---|---|
| `kinetum_provider_process_facility_operations` | Worker registration; coordinator binding; lifecycle-service launch/join. | Startup/shutdown owners. |
| `kinetum_provider_io_driver_operations` | Whole-driver activation/deactivation, queue arrays, and native port observations. | Cold coordinator/observer. |
| `kinetum_packet_rx_burst_operations` | Transfer an RX prefix and count provider-side rejections. | Sole compiled RX worker. |
| `kinetum_packet_tx_burst_operations` | Accept a TX prefix and service provider-deferred output. | Sole compiled TX worker. |
| `kinetum_packet_storage_domain_operations` | Acquire, clone, originate, release, and observe occupancy. | Admitted owners; sharing requires proven concurrent-storage support. |
| `kinetum_provider_execution_operations` | Bind execution identity and required access agents. | Cold runtime binding; no extra stage callback. |
| `kinetum_provider_storage_transition_operations` | Transfer an accepted prefix through one authored storage mechanism. | Compiled handoff owner. |

Driver queue arrays preserve compiled order: the kth RX table corresponds to
the kth RX row in the ascending stream-fact array, and likewise for TX.
Components cannot reorder these arrays by native queue number.

`kinetum_packet_record` is the sole packet representation: 128 bytes of
metadata followed by a 64-byte storage descriptor, aligned to 64 bytes.

| Record area | Contents |
|---|---|
| Metadata | Immutable admission epoch and ingress, routing fields, parsed packet facts, and module-persistent data. |
| Storage descriptor | Native handle, CPU byte view, length/segment shape, domain/generation identity, capabilities, and original storage operations. |

Only the creating provider interprets `native_handle`. Modules receive a
transient SoA projection through the Module SDK, never an mbuf or native
storage handle. Byte mutations must update the parsed fields they invalidate.

Current CPU execution requires one coherent contiguous segment, sufficient
contiguous length, and proven CPU read/write access. Malformed native chains
reject before runtime admission. The ABI does not imply scatter/gather support.

### 8. Diagnostics and Observations

Cold callbacks return one declared `kinetum_provider_status`: `OK`,
`INVALID_ARGUMENT`, `FAILED_PRECONDITION`, `RESOURCE_EXHAUSTED`, or
`IMPLEMENTATION_ERROR`. The caller supplies bounded diagnostic storage. A
callback may fill its bytes and length but cannot replace the buffer, change
capacity, or retain it. Successful callbacks leave diagnostic length zero.
Unexpected result shape or diagnostic residue is a contract violation, handled
according to the ownership boundary in Section 12.

Provider logging uses the host's cold capability and the same service log as
other platform diagnostics. Query and host-proof callbacks receive no logging
capability. Authored packet callbacks do not log; foreign native hooks reached
on a packet owner are rejected and counted. Delivery and fatal-path behavior
belong to [Logging](LOGGING.md#8-native-integration-and-source-map).

Native observations cover storage occupancy and logical-port counters. The
host supplies the complete row set in canonical order; callbacks cannot
replace, resize, retain, or reorder it. Every row echoes its compact identity
and declares one state:

| State | Numeric meaning |
|---|---|
| `AVAILABLE_EXACT` | Complete exact native observation. |
| `AVAILABLE_APPROXIMATE` | Complete concurrent estimate. |
| `UNSUPPORTED` | No implemented observation. |
| `READ_FAILED` | A supported observation failed. |

Available storage observations satisfy `in_use + available == buffer_count`.
For `UNSUPPORTED` and `READ_FAILED`, numeric ABI members remain zero; the wire
response omits those values and their timestamp. They are not measured zeros.
The platform stamps available observations after callback return. Native
handles, physical port numbers, PMD names, and lcore IDs do not become generic
telemetry keys.

Stream packet, byte, and rejection counters come from runtime ownership
transfers and worker telemetry banks. They do not come from assumed native
per-queue statistics. TX acceptance is an ownership result; it does not prove
wire delivery. [Data Plane statistics](DATA_PLANE.md#15-stats-collection) owns
collection and publication to CP.

---

## Part 3: Runtime Lifecycle

### 9. Installed Component Admission

Production DP derives its installation root from `/proc/self/exe`, whose shape
must be `<root>/bin/kinetum_dp`. The inventory and signature live under
`<root>/share/kinetum/providers/`; component artifacts live under
`<root>/lib/kinetum/providers/`. A deployment bundle contains configuration and
modules, not provider images.

Admission proceeds before factories:

1. Project and validate the compiled graph's C-ABI facts and host-proof schedule.
2. Authenticate inventory bytes with the release's Ed25519 anchor before
   protobuf parsing; deterministic reserialization must reproduce those bytes.
3. Open required artifacts through retained, symlink-free descriptors. Validate
   ownership, permissions, link count, size, SHA-256, and ELF structure on the
   same inode.
4. Preflight the complete acyclic private `DT_NEEDED` dependency graph and reject
   duplicate component, contract, file, and SONAME ownership.
5. Load verified dependencies children-first and requested components with
   `RTLD_NOW | RTLD_LOCAL`; query and validate their descriptors.
6. Seal the requested implementation catalog and run required component host
   proofs before passing the admitted result to materialization.

The installation root, traversed directories beneath it, and admitted artifact
files must be root-owned and not group/world writable. Files also have one link;
path traversal is symlink-free. Component images export only the unversioned
query symbol. They have hidden implementation symbols, immediate binding,
RELRO, a non-executable stack, and no unresolved non-weak imports. Component
SONAMEs, loader search paths, executable interpreters, text relocations,
GNU-unique definitions, and loader redirection/interposition are rejected.

One source-controlled public anchor is consumed by DP, `kinetum_package sign`,
and `kinetum-info --check`. Native preparation produces unsigned evidence; the
signing finalizer independently reconstructs the covered inventory and ELF
facts before signing. The signature binds the runtime image and provider
closure when evaluated by a trusted verifier. Runtime-archive delivery still
depends on the release channel; the inventory does not authenticate delivery
of its own verifier.

Provider components release together with the platform. A source builder who
replaces the anchor and signs with its matching seed owns that release lineage.
There is no separate third-party component-signing path. Package commands are
documented in [Getting Started](GETTING_STARTED.md#build-packages-from-source).

### 10. Construction and Activation

The admitted catalog owns code and compiled facts. The materializer
preallocates owner slots and dependency recipes, then creates facilities,
storage domains, I/O drivers, execution providers, and transitions in dependency
order. It validates every returned operation record and resolves each compact
stream to its queue table before publishing the complete provider generation.

Factories reserve/configure resources while ingress remains disabled. The DP
then constructs worker storage, boundary channels, module bindings, and cold
lifecycle services before `CONTROL_READY`. Exact configuration bootstrap makes
the generation packet-ready:

```{uml}
@startuml
participant "DP generation owner" as DP
participant "Provider materializer" as M
participant "Provider components" as P
participant "Packet workers" as W

group Construct with ingress disabled
    DP->M: admitted catalog + compiled topology + generation
    M->M: allocate owner slots and dependency recipes
    loop facility, storage, I/O, execution, transition
        M->P: create(role facts, dependencies)
        P-->M: instance + immutable operations + destroy
        M->M: validate result, claim instance, verify compiled facts
    end
    M-->DP: complete provider generation
    DP->DP: construct worker/boundary state and lifecycle services
    DP->DP: publish CONTROL_READY
end
group Exact configuration bootstrap
    DP->DP: admit bootstrap identity and complete module PREPARE
    DP->W: register and activate prepared module views
    W-->DP: all owner activations complete
    DP->DP: commit bootstrap snapshot and phase
    DP->W: enter RUNNING, keep packet body gate closed
    W-->DP: all workers RUNNING
    DP->M: activate_packet_io()
    M->P: activate drivers in canonical order
    P-->M: complete set live
    M-->DP: success
    DP->DP: publish PACKET_READY
    DP->W: release packet body gate
end
@enduml
```

The sequence shows successful startup. Module preparation and bootstrap
authority are detailed in [Data Plane](DATA_PLANE.md#3-process-lifecycle-dp_main).
Activation failure and teardown follow Section 12.

A facility registers each packet worker on that worker's own thread. Successful
registration is released exactly once by the same thread after packet work
ends. Facility-backed lifecycle services retain their entry/argument storage
until join proves callback completion. A callback's integer return value is
not the join result; a failed join retains the borrow.

### 11. Packet Ownership and Storage Changes

| Operation | Successful ownership transfer | Unaccepted work |
|---|---|---|
| Storage acquire | Returned prefix becomes caller-owned. | Untouched output suffix transfers nothing. |
| RX burst | `transferred_count` records become worker-owned; `rejected_count` inputs were already retired by the provider. | The sum cannot exceed requested capacity. Both zero means no consumed input. |
| TX burst | Returned prefix becomes provider-owned. | Worker keeps the untouched suffix; the provider cannot free or translate it. |
| Writable clone | A new record owns independent bytes and metadata. | Exhaustion returns no clone and preserves the source. |
| Active-origin copy | Validated borrowed bytes become storage-owned records for the returned prefix. | Malformed input transfers nothing; valid input may be capacity-limited. |
| Storage transition | Returned prefix becomes destination-owned; each consumed source is preserved or retired according to the declared mechanism. | Caller retains the source suffix. |
| Storage release | Every supplied owned record is retired through its original domain. | A null record in a nonempty release burst violates the contract. |

Rejected-only RX is consumed input, but transfers no records or epoch credits.

The runtime saves lengths, metadata, and original storage identity before a TX
callback because accepted records may already be reclaimed when it returns.
Mixed-domain TX preserves stream order and uses one queue operation; Kinetum
does not sort or split bursts by pool. Native completion returns backing to its
original owner.

Storage transitions preserve the immutable packet epoch and one logical work
credit. Zero-copy sharing requires the same storage domain. Bounded copy
requires distinct domains and authored staging: it creates destination backing,
copies bytes and metadata, then retires the consumed source. Input/output
pointer arrays may overlap; transfer acts as if the attempted input prefix was
captured before writing destinations.

On a resolved TX edge, an authored conversion takes precedence even when TX
also accepts the original domain. Without conversion, direct TX requires
membership in the admitted set. Otherwise the runtime drops and releases the
record through its original domain. Moving between workers alone never
authorizes a copy or a replacement pool.

Workers cache resolved tables before launch. Homogeneous RX uses one fixed
callback target; heterogeneous RX uses each stream's pre-resolved target.
Queue direction and native compatibility are established during construction,
not rediscovered per packet. RX retains its logical-port bounds check before
indexing core arrays. TX follows the native accepted prefix without consulting
an asynchronous link-state gate.

### 12. Shutdown and Failure

Shutdown follows resource dependencies:

1. Close worker source polling and drain local and boundary packet ownership.
2. Run final queue flushes and join the worker DAG, releasing each worker's
   facility registration on its owning thread.
3. Deactivate live I/O drivers in reverse canonical order.
4. Retire module/lifecycle work while its provider dependencies remain alive.
5. Destroy provider instances in reverse dependency order: transitions,
   execution, I/O, storage, then facilities.
6. Release the admitted fact and component-code owners after their dependents.

An I/O driver cannot be destroyed with unresolved live queues. Backing storage
cannot be reclaimed while a native device might still reference it.

| Failure boundary | Disposition |
|---|---|
| Plan, fact projection, provenance, or preflight before foreign loading | Return a typed failure without a partial runtime. |
| Component loading/query/admission after foreign loading begins | Terminate; constructors and loader state make recoverable rollback unprovable. |
| Component-phase host proof after loading | Diagnose and terminate without unloading uncertain component state. |
| Recoverable factory failure before any facility succeeds | Retire the constructed prefix and return failure. |
| Construction failure after a facility reports success or an undeclared status | Retire materialized instances in reverse order, then terminate; do not reuse the foreign process runtime. |
| Driver activation failure | The failed driver remains cold; deactivate the activated prefix in reverse order. Unproven rollback terminates. |
| Driver deactivation or native retirement failure | Preserve unresolved ownership and fail stop before reclaiming dependencies. |

An invalid factory result is reclaimed only when its ownership can be identified
completely. Ambiguous partial ownership is fail-stop. DPDK's irreversible EAL
initialization boundary adds the native constraints described next.

---

## Part 4: Current Implementations

### 13. DPDK

`kinetum_provider_dpdk_component` implements three contracts:

| Instance | Native resources | Dependencies |
|---|---|---|
| DPDK facility | One process-scoped EAL environment, worker registration, and lifecycle-service launch. | Compiled CPU, device, memory, and NUMA requirements. |
| DPDK storage | One mbuf population with embedded Kinetum packet records. | Its declared facility. |
| DPDK I/O driver | Ethdev ports, queues, descriptors, and steering. | Its facility and every RX/TX storage domain. |

The host component supplies CPU execution and storage transitions for these
deployments. DPDK does not become the implementation of unrelated roles merely
because the process uses DPDK I/O.

In the canonical fan-in PCI bindings, `facility_dpdk_0` supplies EAL,
`io_dpdk_0` owns `wan0`, `wan1`, and `lan0`, `storage_dpdk_0` backs the queues,
and `execution_cpu_0` supplies CPU execution. These are instance identities,
not component filenames. The [fan-in walkthrough](GLUON.md#14-fan-in-edge-gateway-walkthrough)
shows their authored bindings; per-RX-queue storage profiles change the domain
bindings while using the same components and ABI.

#### Native construction and ownership

The facility derives EAL setup from compiled requirements. There is no EAL argv
in the plan or a command-line override. Its packet-worker set contains only
workers whose I/O or storage depends on that facility; unrelated UDP workers
are not registered as DPDK lcores. The complete runtime-service set includes
the exact coordinator main core. Native identities are reserved before workers
register, and worker/service aliasing rejects.

The storage factory places the 192-byte packet record in each mbuf's private
area and retains the mbuf pointer only in `native_handle`. It proves both
private-area capacity and every record's 64-byte alignment before publishing
operations.

The driver resolves canonical lowercase PCI BDFs or TAP names from its typed
configuration. Generic ports retain logical/driver identity, direction, MTU,
resolved MAC, and optional proven NUMA placement. RX and TX use
`rte_eth_rx_burst` and `rte_eth_tx_burst` through the admitted tables.

Each RX queue binds its declared mempool. A TX queue may accept several DPDK
pools from the same facility with proven NUMA compatibility. The native driver
reclaims each completed mbuf through its own pool. Multi-pool TX rejects
`RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE` before device configuration because that
mode requires one pool per queue. Writable fan-out uses `rte_pktmbuf_copy`;
exhaustion never selects host storage.

Port configuration immediately records ownership before another fallible
native call. The factory leaves ports cold. Activation starts ports, programs
the compiled RETA, and installs requested symmetric RSS flows while worker
bodies remain closed. Even a single RX queue carries an explicit NONE steering
row. A live PMD mismatch rejects before packet readiness. Hardware RSS symmetry
does not establish NAT session ownership; that belongs to
[module context selection](MODULE_SDK.md#session-ownership-across-ingress-queues).

Deactivation destroys RSS flows and stops ports in reverse order. Destruction
then closes configured cold ports before pools and EAL retire. Invocation of
`rte_eal_init()` is the native irreversible boundary: failure terminates rather
than assuming cleanup ownership. After successful initialization, later failure
claims one cleanup attempt and terminates regardless of its outcome. EAL helper
state is not proven reusable for another in-process DPDK generation.

#### Native observations

`rte_mempool_in_use_count()` is exposed only through the cold storage-observation
API. Concurrent pool activity makes its complete occupancy tuple
`AVAILABLE_APPROXIMATE`. No RX, TX, dispatch, or worker-loop path scans the pool
or applies a second watermark gate. Packet pressure is observed through actual
burst results and allocation failures.

Ethdev checks requiring an initialized port belong to materialization.
Asynchronous link state never supplies a second packet-admission decision.
Native diagnostic identities remain inside the provider.

#### Dependency build

The component consumes the verified source-produced
`KinetumDPDK::StaticComponentClosure` for DPDK 24.11.7. The package pins the
Meson producer, supported architecture/ISA tuples, generated configuration,
forced `rte_config.h` include, consumer ISA flags, and the PCI/vdev buses, ring
mempool, i40e, and TAP archive set.

Static-PIC implementation and PMD archives are whole-archived into this one
component so registration and DPDK global state have one image owner. libnuma
and declared GNU runtime prerequisites remain dynamic. Matching hidden
visibility permits direct-address relaxation to component-owned
`rte_eth_fp_ops`. The dynamic-PMD path is unusable and EAL performs no default
PMD-directory scan. Load-time constructors register built-in drivers without
initializing EAL, devices, threads, or pools.

The dependency producer downloads bounded source archives into private cache
candidates, verifies their SHA-256, and publishes without replacement. It
validates archive/PMD symbols, configuration, headers, licenses, attribution,
and complete package bytes before publishing the tuple package. Concurrent
producers converge only on an independently identical winner. CMake verifies
the package before loading its imported target. Malformed or duplicate JSON
members reject; package-manager linker strings and distro DPDK do not supply an
alternate dependency closure.

#### Capacity example

Capacity proves bounded ownership, not throughput. At 10 Gb/s, a minimum
64-byte Ethernet frame plus 8-byte preamble/SFD and 12-byte inter-frame gap
gives `10,000,000,000 / (84 * 8) = 14,880,952` packets/s per ingress.

| Authored capacity | At minimum-frame line rate | At 500 kpps |
|---|---|---|
| 4096 RX descriptors | About 275 us. | About 8.19 ms. |
| 1024 boundary or staging records | About 68 us. | About 2.05 ms. |
| Independent 4096 + 1024 + 1024 tiers | About 413 us. | About 12.29 ms. |

A 131071-record pool across two line-rate ingress ports represents about
4.4 ms of aggregate record capacity. These are illustrative deployment facts,
not global defaults. The checked budget still includes every applicable term;
additional buffering cannot make an oversubscribed worker process faster.

### 14. Host Storage, CPU Execution, and UDP

`kinetum_provider_host_component` supplies host storage, CPU execution,
zero-copy sharing, and bounded copy. `kinetum_provider_udp_component` supplies
development UDP I/O and is outside the public runtime package. Both use the
same ABI, admission, and ownership rules as DPDK.

| Mechanism | Implementation |
|---|---|
| Host storage | One fixed record/payload mapping sized from the plan and shared budget. Exact NUMA binding precedes first touch; the mapping is prefaulted before publication. Cache-line-rounded payload strides prevent adjacent writable slots sharing a line. |
| CPU execution | Execution identity and CPU access proof; platform workers execute the stages. |
| Zero-copy share | Same-domain handoff preserving the original record. |
| Bounded copy | Preallocated staging plus destination storage, with exact source retirement after accepted copies. |
| UDP I/O | Typed numeric IPv4 endpoints and bounded queue-owned records using Linux datagram sockets. |

UDP requires contiguous CPU-readable storage, also writable for RX; the storage
domain remains an explicit binding rather than an implicit part of the driver.
Each RX queue pre-acquires its entire uint32 descriptor population from that
domain. Acquire/release and I/O calls split that population into checked uint16
bursts. Partial reservation returns every credit. `recvmmsg`
fills the queue-owned records; a truncated datagram is never published.

Before bind, each RX socket installs a drop-all filter. Activation replaces all
filters with accept-all only after workers are ready. Deactivation restores
drop-all in reverse order and drains the finite admitted backlog, so another
live interval cannot receive old queued traffic.

Each TX queue has a bounded deferred-record ring. `sendmmsg` retires only its
successful prefix through each original storage owner. The ring can hold
several admitted domains in stream order; exhaustion leaves the caller's
suffix untouched. Shutdown releases any accepted-but-unsent records without
reclassifying them as rejected transfers or delivered packets.

Interrupt/would-block and TX kernel-buffer exhaustion give bounded no-progress
with ownership retained. Other negative native results fail stop. The private
TAP validation profile uses DPDK's TAP driver, not this UDP component.

---

## Part 5: Integration and Reference

### 15. Adding a Provider

A provider is integrated into the platform source and release. Adding a shared
object alone does not define its configuration meaning or authorize its use.

| Work | Owning surface |
|---|---|
| Define the role-specific configuration and capabilities. | Provider schema and pure catalog row, with strict validation and normalization. |
| Include the schema in generated ABI identity. | `KINETUM_PROVIDER_CONTRACT_PROTOS` in `CMakeLists.txt`; all runtime/component consumers rebuild together. |
| Express deployment intent and required relationships. | Bindings, Gluon lowering, and the shared topology compiler. |
| Prove native prerequisites at the correct phase. | Catalog requirements, Quark where applicable, component host proof, and materialization. |
| Implement the role through the existing ABI. | Descriptor, factories, operation records, lifetime, and reverse teardown. |
| Isolate native dependencies. | Private component target and declared dependency closure. |
| Ship matching trusted artifacts. | Release aggregate, inventory reconstruction, signing, and installed admission. |
| Verify the contract. | C11/C++20 layouts, malformed-input rejection, partial-failure cleanup, ownership transfer, concurrency, and native qualification. |

Reuse the existing packet record and role boundaries. New storage backing must
state its real shape and access capabilities; new execution or transfer
mechanisms must have implemented callbacks, consumers, and validation. A
future provider name is not an implemented capability.

For an implementation example, follow `dpdk_component.cpp` from its sorted
contract rows to the three role factories and their native owners. The host
and UDP components show the same contracts with separate storage/execution and
I/O images. These production implementations are the reference; there is no
parallel sample ABI.

### 16. Build and Release Ownership

`kinetum_configure_provider_component_target()` applies the shared ELF policy
and sole query export. Native implementation objects compile with hidden
symbols and private usage requirements. Generic runtime, SDK, and generic test
translation units do not inherit native headers, macros, or libraries.

The production DP has no link dependency on a provider implementation. It
loads the required signed components through the installed admission path.
DPDK's process-global EAL/PMD state requires separate native test processes;
those link the component's exact static closure and do not also load another
copy of the component.

CMake stages declared release members. The runtime archive includes the host
and DPDK components; the SDK contains public module development files. The
provider ABI remains in the platform source tree. Package preparation,
installation, and trust-anchor commands remain in
[Getting Started](GETTING_STARTED.md#build-packages-from-source).

### 17. Source Map

| Responsibility | Source |
|---|---|
| Physical C ABI, borrowed lifetimes, layouts | `src/provider/provider_component_abi.h` |
| Configuration semantics and projections | `src/provider/provider_contract_catalog.hpp`, `provider_contract_catalog.cpp` |
| Plan lowering and shared compilation | `src/gluon/deployment_bindings_lowering.cpp`, `src/provider/compiled_provider_topology.cpp` |
| Canonical plan identity | `src/provider/deployment_plan_identity.cpp` |
| Checked storage budgets | `src/common/plan_buffer_budget.cpp` |
| Signed inventory and reconstruction | `src/provider/provider_inventory.cpp`, `provider_inventory_reconstruction.cpp`, `provider_inventory_signing.cpp` |
| Held-file ELF checks and component loading | `src/provider/provider_component_preflight.cpp`, `provider_component_loader.cpp`, `provider_component_admission.cpp`, `provider_elf.cpp` |
| C-ABI projection and host-proof scheduling | `src/provider/provider_runtime_admission.cpp` |
| Factory ownership, validation, and teardown | `src/provider/provider_runtime_materialization.cpp` |
| DPDK component and native mechanics | `src/provider/components/dpdk/dpdk_component.cpp`, `src/dp/backends/dpdk/` |
| Host and UDP implementations | `src/provider/components/host/host_component.cpp`, `src/provider/components/udp/udp_component.cpp`, `src/dp/backends/udp/udp_io.cpp` |
| Worker burst dispatch and original-owner release | `src/dp/packet_worker_kernel.cpp` |
| Dependency build and component policy | `tooling/environment/build_kinetum_dpdk.py`, `third_party/dpdk/dependency_manifest.json`, `cmake/KinetumProviderComponentPolicy.cmake` |

### 18. Where to Go Next

| Task | Reference |
|---|---|
| Author provider instances, queues, and lanes | [Gluon](GLUON.md#7-deployment-binding-resolution) |
| Follow provider, storage, and worker relationships visually | [Platform Architecture](diagrams/platform_architecture.md#3-providers-and-packet-storage) |
| Understand CPU and NUMA host proof | [Quark](QUARK.md#3-authority-boundary) |
| Follow worker execution and epoch transitions | [Data Plane](DATA_PLANE.md) |
| Implement packet policy | [Module SDK](MODULE_SDK.md) |
| Build and install runtime packages | [Getting Started](GETTING_STARTED.md) |
| Apply platform ownership and performance rules | [Platform Engineering Guide](PLATFORM_ENGINEERING_GUIDE.md) |
