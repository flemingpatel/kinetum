# Quark

Quark checks whether compiled worker, service, and storage placement matches
the process's available CPU/NUMA and host-memory resources. This reference
covers host discovery, compatibility checks, and source-tree integration.

For the architectural framing, read [`CONCEPTS.md`](CONCEPTS.md) first.
Quark is consumed by the dataplane process described in
[`DATA_PLANE.md`](DATA_PLANE.md). Gluon does not depend on Quark; planning uses
hardware inventory plus the pure provider-contract catalog.

## Table of Contents

**Part 1: Concepts and Authority**

1. [What Quark Is](#1-what-quark-is)
2. [Authoring Model](#2-authoring-model)
3. [Authority Boundary](#3-authority-boundary)

**Part 2: Host Proof**

4. [CPU Host Topology](#4-cpu-host-topology)
5. [Runtime Compatibility Gate](#5-runtime-compatibility-gate)
6. [Failure Surfaces and Diagnostics](#6-failure-surfaces-and-diagnostics)

**Part 3: Embedding and Determinism**

7. [Calling Quark from Source (Programmatic API)](#7-calling-quark-from-source-programmatic-api)
8. [Determinism](#8-determinism)

**Part 4: Cross-Cutting**

9. [Quark vs Gluon vs DP vs Photon](#9-quark-vs-gluon-vs-dp-vs-photon)
10. [Where to Go Next](#10-where-to-go-next)

---

## Part 1: Concepts and Authority

### 1. What Quark Is

Quark is a C++ library, not a process. It owns two tightly bounded concerns:

1. **Host CPU/NUMA discovery.** `probe_host()` captures the exact logical CPUs
   available to this process, each CPU's proven NUMA node when available, and
   the sorted NUMA nodes with positive OS-reported host memory.
2. **Strict runtime placement proof.** `validate_runtime_compat()` first
   consumes the already-built `compiled_provider_topology`, then proves that
   every compiled packet-worker and runtime-service core exists and exact-
   matches host NUMA truth and that every QUARK-phase host-memory requirement
   names a live memory-bearing NUMA node. It returns one decision and bounded
   diagnostics; the original compiled topology remains the sole placement
   authority.

Every mismatch is terminal for the admission attempt. Quark never filters,
repairs, supplements, floats, or reassigns a planned core.

**What Quark does not do.** It does not interpret provider `Any` values,
resolve components, inspect PCI/TAP/UDP attachment syntax, build EAL arguments,
probe hugepages or NIC queues, reserve a device, or materialize provider state.
Provider meaning belongs to the pure contract catalog. Complete
facility/access/transition semantics belong to the shared provider compiler.
DPDK runtime/hugepage and UDP socket facts belong to component-phase proof;
native facts requiring initialized facility state belong to transactional
materialization. Unknown NUMA is represented as unknown, never node zero.

**Architecture rationale.** Quark checks OS evidence after structural planning.
Separating host proof from planning preserves the canonical plan and keeps
provider semantics in their owning catalog.

Source: `src/quark/`. Two headers form the source-tree library surface:
`host_probe.hpp` and `runtime_compat.hpp`.

### 2. Authoring Model

Four concepts:

| Term | What it is |
| ---- | ---------- |
| **Plan placement** | Immutable worker and runtime-service CPU/NUMA ownership emitted by Gluon. |
| **Compiled provider topology** | Sole semantic artifact containing exact workers, services, provider graph, host requirements, storage reachability, transitions, schedules, and budgets. |
| **Host topology** | Process-available CPU/NUMA facts returned by `probe_host()`. |
| **Compatibility report** | One strict decision, summary, and bounded diagnostics. It contains no replacement placement. |

Who calls what:

- **Gluon** emits exact placement and self-checks the complete provider
  topology. It never asks Quark to select or describe a provider.
- **Dataplane** (the DP process) calls `probe_host()` then
  `validate_runtime_compat(compiled_provider, host)` with the exact artifact it
  compiled once at startup, before provider loading, materialization, or worker
  launch.
- **Photon** verifies and supervises the runtime bundle but does not link or
  invoke Quark.

Quark has no command-line tool of its own. The source-tree C++ API in section
7 is its complete callable surface; it is not part of the installed module SDK.

### 3. Authority Boundary

#### 3.1 Provider meaning

The [provider contract catalog](PROVIDERS.md#3-typed-configuration) and shared
compiler resolve provider semantics before Quark runs. Quark consumes their
compiled host requirements rather than decoding provider configuration.

Quark receives no provider enum, provider ID string, native argv, component
path, or implementation registry. It cannot choose an I/O, execution, storage,
or transition provider, and it cannot select a fallback.

#### 3.2 Structural input

Quark accepts only `compiled_provider_topology`, with no plan overload or local
compiler. Its transition topology already proves:

- exact worker identity/index and CPU ownership;
- exact runtime-service identity, kind, ordering, and cardinality;
- worker/service and service/service CPU disjointness;
- source/sink, boundary, participant-DAG, lifecycle-NUMA, and transition-policy
  structure.

Quark consumes the resulting compact workers and services. It does not walk
logical regions to recreate those facts.

The same artifact carries facilities, ports, queues, storage, execution,
transitions, component requirements, access compatibility, and exact phased
host requirements. Quark evaluates only rows tagged `QUARK_LIVE_HOST` and
fails if such a row names a non-Quark fact or malformed owner. It never
acquires a local provider capability table and never evaluates COMPONENT or
MATERIALIZATION rows.

#### 3.3 Host evidence

Quark proves only these host facts:

| Evidence | Rule |
| -------- | ---- |
| Process CPU availability | Every planned worker/service CPU is in `sched_getaffinity()` truth. |
| Core NUMA ownership | Every selected CPU has a proven nonnegative node and equals the plan. |
| Host topology shape | CPU rows are nonempty, sorted, duplicate-free, and contain valid values. |
| Planned process cores | Every compiled worker and service core is checked in place; Quark returns no replacement core inventory. |
| Host-memory NUMA availability | Every compiled QUARK-phase host-storage or bounded-copy staging node appears in the sorted, duplicate-free live memory-node set. |

Advisory minimums, priorities, throughput hints, and compatibility scores cannot
replace proof. Any unproven required fact makes the report incompatible.

## Part 2: Host Proof

### 4. CPU Host Topology

`probe_host()` in `host_probe.hpp` returns the process's allowed CPUs as
`host_topology`.

#### 4.1 Detection method

`probe_host()` uses Linux `sched_getaffinity(2)`. This reflects the
CPU affinity mask currently allowed for the process. It respects:

- cgroup `cpuset` constraints (container deployments).
- `taskset` restrictions.
- any CPU isolation policy reflected in the process affinity mask.

The process affinity mask determines available CPUs. Quark does not parse
`isolcpus`; isolation excludes a CPU only when the kernel's process affinity or
cpuset excludes it. The shared affinity helper starts with the libc CPU-set
extent and doubles it only on `sched_getaffinity()` `EINVAL`, then scans the
accepted extent. Sparse/high IDs are not truncated by `CPU_SETSIZE`, fixed
`cpu_set_t`, or CPU counts. Worker/service pinning uses the same helper, sized
for the authored CPU ID.

The complete build requires libnuma. Quark asks `numa_node_of_cpu()` for every
CPU admitted by the affinity mask. If the running kernel cannot prove a CPU's
node, that CPU carries `numa_node = -1`. A plan that requires CPU/NUMA ownership
therefore fails compatibility instead of assuming node 0. Kinetum's top-level
build rejects non-Linux targets or an absent libnuma development dependency;
Quark has no approximate topology fallback.

The same probe obtains the current process's cpuset-allowed memory mask through
`numa_get_mems_allowed()`, intersects it with globally memory-bearing nodes,
and records only the positive-memory result. A node that exists on the machine
but is unavailable to this process cannot satisfy host packet storage or CPU
bounded-copy staging. This is generic allocation eligibility, not a hugepage
count or completed native allocation; the exact host-storage component binds
and prefaults its record/payload mapping during materialization.

#### 4.2 `host_topology` schema

| Field          | Type               | Purpose                                                                |
| -------------- | ------------------ | ---------------------------------------------------------------------- |
| `cpus`         | `vector<host_cpu>` | Process-available CPUs, sorted by `core_id` and duplicate-free. Each record carries `core_id` plus exact `numa_node`, or `-1` when ownership is unknown. |
| `memory_numa_nodes` | `vector<int32_t>` | Sorted duplicate-free nonnegative NUMA nodes with positive memory that the current process cpuset permits. |
| `online_count` | `int32_t`          | Total online CPUs on the system. May exceed `cpus.size()` if cgroup or taskset restricts the process. |
| `valid`        | `bool`             | Whether CPU-set discovery succeeded.                                   |

Five helper methods:

| Method                           | Purpose                                                            |
| -------------------------------- | ------------------------------------------------------------------ |
| `summary()`                      | Human-readable CPU range plus an explicit `NUMA unknown` suffix when any record lacks ownership. |
| `has_core(int32_t core_id)`      | Binary search against `cpus[].core_id`. O(log n).                  |
| `numa_node_for_core(core_id)`    | Exact nonnegative host NUMA node, or no value for an unavailable/unknown CPU. |
| `has_complete_numa_topology()`   | True only when every process-available CPU has proven NUMA ownership. |
| `has_memory_numa_node(node)`     | Binary search proving that an exact NUMA node has positive OS-reported host memory. |

#### 4.3 Explicit limitations

`host_topology` does **not** carry:

- Physical-vs-hyperthread classification.
- Hugepage page sizes, counts, pinning, or allocator availability.
- NIC inventory, driver state, or queue depths.
- Cache topology.
- Hardware offload feature detection.

Those facts remain explicit provider-compiler or materialization requirements.
They come from canonical plan/provider configuration plus live provider-owned
proof; no caller should query a native subsystem and then mutate the plan.
Quark's core-to-NUMA probe proves only that selected process cores match plan
truth.

### 5. Runtime Compatibility Gate

`validate_runtime_compat()` (declared in `runtime_compat.hpp`) is the compiled-
topology/host compatibility gate. The dataplane calls it once at startup after
the sole semantic compilation and before any component, native resource, or
worker thread.

#### 5.1 Signature

```cpp
[[nodiscard]] compat_report
validate_runtime_compat(const compiled_provider_topology& topology,
                        const host_topology& host);
```

#### 5.2 What it validates

Four checks over one already-compiled artifact:

1. **Host topology shape is valid.** Discovery must be valid; `cpus` must be
   nonempty, sorted by core ID, duplicate-free, and contain only nonnegative
   core IDs with NUMA values of `-1` or greater. `memory_numa_nodes` must be
   sorted, duplicate-free, and nonnegative. The lookup helpers rely on these
   exact binary-search shapes.
2. **Compiled packet-worker cores exist and exact-match host NUMA.** For every
   compiled worker, each requested core must exist in `host.cpus` and its proven
   node must equal the worker's region-local NUMA ownership. Unknown or
   mismatched live NUMA fails here; empty, negative, or shared ownership has
   already failed in the sole compiler and is not revalidated into a Quark
   projection.
3. **Compiled runtime services have exact host ownership.** The shared compiler
   already proves canonical IDs/kinds, cardinality, ordering, worker/service
   separation, service/service separation, and lifecycle-executor NUMA
   coverage. Quark proves each dedicated core exists and its host NUMA node
   exact-matches the plan. It never filters or floats a control service.
4. **Every Quark-phase host requirement is understood and satisfied.** CPU
   worker-set rows must belong to a real compiled execution provider. Host-NUMA
   memory rows must belong to a placed host-storage domain or bounded-copy
   transition and the exact node must appear in `memory_numa_nodes`. DPDK EAL,
   hugepage, ethdev, and UDP socket facts are invalid if mislabeled as Quark
   work.

What it does **not** validate:

- Provider configuration meaning or component availability.
- Hugepage, IOMMU, privilege, firmware, NIC, driver, queue, or device state.
- Storage access, steering, facility dependency, or transition compatibility.
- Native process arguments or provider object construction.

The shared compiler owns service cardinality, lifecycle-executor coverage, and
all structural plan relations. Quark owns the host proof for their selected
cores. Unknown NUMA and proven mismatch are hard failures. The gate returns
a decision and bounded diagnostics; it does not republish placement, launch
services, render provider-native arguments, or materialize state.

#### 5.3 Exactness and no repair

There is one behavior, with no mode enum:

| Condition | Result |
| --------- | ------ |
| Every planned worker/service core exists and exact-matches NUMA | `compatible=true`; startup continues with the original compiled topology. |
| A core is unavailable | `compatible=false`; no replacement set is published. |
| NUMA ownership is unknown | `compatible=false`; unknown never means node zero. |
| NUMA ownership mismatches | `compatible=false`; no reassignment is attempted. |
| A Quark-phase requirement has an invalid owner, unavailable memory node, or non-Quark fact | `compatible=false`; no other proof phase is executed. |

Development uses the same exact contract. A smaller host requires a different
canonical plan, not a runtime flag that edits the plan after hashing.

### 6. Failure Surfaces and Diagnostics

`validate_runtime_compat()` reports compatibility through `compat_report`,
rather than a status/error-code API.

#### 6.1 `compat_report`

| Field                | Type                       | Purpose                                                                     |
| -------------------- | -------------------------- | --------------------------------------------------------------------------- |
| `compatible`         | `bool`                     | Whether the exact planned CPU/NUMA ownership matches this host.              |
| `summary`            | `string`                   | Human-readable one-line outcome for logging.                                |
| `diagnostics`        | `vector<string>`           | Detail strings for structural, host-shape, CPU, or NUMA mismatch.            |

#### 6.2 How callers should consume this

The dataplane process (cold path):

1. Obtain the sole compiled topology from `verify_runtime_bundle()`.
2. Call `validate_runtime_compat(compiled_provider, host)` with that exact
   result.
3. If `report.compatible == false`: log `report.summary` and every
   `report.diagnostics` line, then exit with non-zero status.
4. Otherwise: log `report.summary` once and continue with the same
   `compiled_provider_topology`; the report is not a substitute placement
   artifact.
5. Do not launch or initialize anything merely because Quark returned
   compatible. Component admission and transactional
   materialization remain separate gates.

There is no mismatch exception, retry loop, or wait: an ordinary host
contradiction returns one report. The report owns strings and a bounded vector,
so standard allocation failure may still propagate from this cold C++ API; a
caller must fail startup rather than treating that as compatibility.

## Part 3: Embedding and Determinism

### 7. Calling Quark from Source (Programmatic API)

Quark has no command-line tool. The C++ API in `src/quark/` is the
complete source-tree surface. These headers are internal to the platform build
and are not installed under `include/kinetum/`.

#### 7.1 Host probe (`host_probe.hpp`)

| API                              | Purpose                                                                |
| -------------------------------- | ---------------------------------------------------------------------- |
| `probe_host()` -> `host_topology`| Discover the process-available CPU set and proven core-to-NUMA ownership. Cold-path only. Call once before worker launch so all participants use the same affinity view. |
| `host_topology` struct           | See section 4.2.                                                        |
| `host_topology::summary()`       | Logging-friendly string.                                                |
| `host_topology::has_core(id)`    | Binary search against `cpus[].core_id`.                                 |
| `host_topology::numa_node_for_core(id)` | Proven host NUMA node, or no value when unavailable/unknown.     |
| `host_topology::has_complete_numa_topology()` | Whether every process-available CPU has proven ownership.   |
| `host_topology::has_memory_numa_node(node)` | Whether live OS truth reports positive host memory on the exact node. |

#### 7.2 Runtime compat (`runtime_compat.hpp`)

| API                                                    | Purpose                                                       |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| `compat_report` struct                                 | Decision, summary, and bounded diagnostics. See section 6.1.   |
| `validate_runtime_compat(compiled_provider, host)` -> `compat_report` | The strict gate function. See section 5.                       |

#### 7.3 Walkthrough: DP startup compatibility gate

Within startup, `bundle_root` is the explicit deployment directory:

```cpp
#include <cstdlib>
#include <utility>

#include "src/pack/runtime_bundle.hpp"
#include "src/quark/host_probe.hpp"
#include "src/quark/runtime_compat.hpp"
using namespace kinetum;

// 1. Bundle admission compiles the provider topology once.
auto bundle_or = pack::verify_runtime_bundle(bundle_root);
if (!bundle_or.is_ok()) {
    return EXIT_FAILURE;
}
auto bundle = std::move(bundle_or).value();

// 2. Probe the host and validate the retained compiled artifact.
const auto host = quark::probe_host();
const auto report = quark::validate_runtime_compat(bundle.compiled_topology, host);

if (!report.compatible) {
    // Log report.summary and every report.diagnostics line; exit non-zero.
    return EXIT_FAILURE;
}

// 3. Continue with bundle.compiled_topology. It remains the sole placement input
//    to component admission, provider materialization, and runtime launch.
```

This mirrors the cold gate in `dp_main.cpp`. It does not itself load a
component, initialize a facility, or launch a worker. See
[`DATA_PLANE.md`](DATA_PLANE.md) for the surrounding startup sequence and
packet-runtime admission contract.

#### 7.4 Error categories

Discovery failure sets `host_topology.valid` false; mismatch sets
`compat_report.compatible` false. DP fails startup on either, with no partial
success or warning-only result. These expected failures use neither
`status_or<T>` nor exceptions, though report allocation may throw.

### 8. Determinism

Quark's deterministic behavior:

- **Host probe** (`probe_host()`) is deterministic given the kernel, process
  CPU affinity, process memory-node cpuset, and libnuma state at the moment of
  the call. Returned `cpus` and `memory_numa_nodes` records are sorted. Repeated
  calls within the same process return the same result unless one of those host
  authorities changed externally.
- **Compatibility gate** (`validate_runtime_compat`) is deterministic given
  the same compiled topology and host. Diagnostics follow stable host-shape,
  worker, service, then phased host-requirement validation.

## Part 4: Cross-Cutting

### 9. Quark vs Gluon vs DP vs Photon

| Concern                                                  | Owner                  |
| -------------------------------------------------------- | ---------------------- |
| Stage-kind and typed stage-configuration admission         | **Axiom**              |
| Provider contract meaning/canonicalization                | Pure provider catalog  |
| Complete provider graph semantic compilation              | Shared provider compiler |
| Host CPU set discovery (`sched_getaffinity`)              | **Quark** (`probe_host`) |
| Plan vs host CPU compatibility                            | **Quark** (`validate_runtime_compat`); **DP** invokes |
| Host-proof decision and bounded diagnostics               | **Quark** |
| Runtime-bundle pre-spawn admission and process supervision | **Photon**; DP independently readmits the bundle |
| Host-memory NUMA availability for host storage/copy       | **Quark**, from compiled QUARK-phase requirements |
| DPDK runtime/hugepage and UDP socket evidence             | Exact COMPONENT-phase provider proof; not Quark |
| NIC presence, driver state, queues, and steering          | Exact MATERIALIZATION-phase provider proof; not Quark |
| NUMA-aware core selection                                 | **Gluon** (using `hardware_inventory.pbtxt`) |
| Selected core-to-NUMA host proof                          | **Quark** (`probe_host` + `validate_runtime_compat`) |

#### 9.1 Hardware inventory split

Quark probes process CPU/NUMA and host-memory availability. Providers own native
device and allocator evidence:

The planning inventory contains one host node, a complete explicit selectable
CPU-row set, and DPDK PCI facts. Every NIC row is validated; only rows referenced
by deployment bindings enter the plan. Counts do not synthesize CPUs, and no
second host's device rows can be merged with the selected CPU set.

| Resource    | Planning source                                     | Runtime validation                                                          | Owner                                                  |
| ----------- | --------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------ |
| CPU cores   | `hardware_inventory.pbtxt`                          | Live probed by Quark (`probe_host` + `validate_runtime_compat`)              | Gluon plans, shared compiler freezes, Quark validates |
| Core NUMA ownership | `hardware_inventory.pbtxt` CPU topology       | Live probed by Quark through libnuma; unknown/mismatch fails selected placement | Gluon plans, shared compiler freezes, Quark validates |
| Host-memory NUMA nodes | Storage/transition placement in the canonical plan | Live positive-memory nodes allowed by the process cpuset; missing exact node fails | Shared compiler emits QUARK-phase rows, Quark validates |
| DPDK hugepages/runtime and UDP sockets | Provider configuration plus compiled facility/storage requirements | Not probed by Quark; exact component-phase proof owns live evidence | Shared provider compiler + provider component |
| DPDK PCI ports/driver queues | Exact single-node PCI inventory plus typed driver configuration and plan ports/streams; TAP/UDP identity lives only in typed bindings | Not probed by Quark; initialized materialization validates live device truth | Gluon resolves authored facts; provider compiler/component proves use |

Provider-specific evidence follows compiled contract requirements through
component host proof and materialization; it does not extend Quark's scope.

### 10. Where to Go Next

| If you want to...                                | Read                                           |
| ------------------------------------------------ | ---------------------------------------------- |
| Author a pipeline                                | [`AXIOM.md`](AXIOM.md)                         |
| Plan a deployment                                | [`GLUON.md`](GLUON.md)                         |
| Run a deployment (DP invokes the compat gate)    | [`DATA_PLANE.md`](DATA_PLANE.md)                 |
| Understand the supervisor                        | [`PHOTON.md`](PHOTON.md)                       |
| Read the architectural overview                  | [`CONCEPTS.md`](CONCEPTS.md)                   |
| End-to-end walkthrough                           | [`GETTING_STARTED.md`](GETTING_STARTED.md)     |
| See the runtime in motion                        | [`diagrams/README.md`](diagrams/README.md)     |
