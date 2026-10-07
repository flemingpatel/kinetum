# Gluon

This reference covers planner inputs, plan schema, algorithms, validation,
and the `kinetum_gluon` CLI and embedding API.

For the architectural framing, read [`CONCEPTS.md`](CONCEPTS.md) first.
For pipeline authoring, see [`AXIOM.md`](AXIOM.md). Provider roles, configuration
contracts, and runtime implementations are documented in [Providers](PROVIDERS.md).

## Table of Contents

**Part 1: Concepts and Artifacts**

1. [What Gluon Is](#1-what-gluon-is)
2. [Authoring Model](#2-authoring-model)
3. [Inputs](#3-inputs)
4. [Outputs: The Plan](#4-outputs-the-plan)

**Part 2: Planning and Lowering**

5. [Region Partitioning](#5-region-partitioning)
6. [Placement Constraints and Pins](#6-placement-constraints-and-pins)
7. [Deployment Binding Resolution](#7-deployment-binding-resolution)
8. [Provider Contracts and Binding Requirements](#8-provider-contracts-and-binding-requirements)
9. [Executable Boundary Ownership](#9-executable-boundary-ownership)

**Part 3: Validation and Determinism**

10. [Validation Rules](#10-validation-rules)
11. [Determinism](#11-determinism)

**Part 4: Operation and Embedding**

12. [CLI](#12-cli)
13. [Embedding Gluon (Programmatic API)](#13-embedding-gluon-programmatic-api)
14. [Fan-In Edge Gateway Walkthrough](#14-fan-in-edge-gateway-walkthrough)

**Part 5: Cross-Cutting**

15. [Axiom vs Gluon vs Runtime Responsibilities](#15-axiom-vs-gluon-vs-runtime-responsibilities)
16. [Where to Go Next](#16-where-to-go-next)

---

## Part 1: Concepts and Artifacts

### 1. What Gluon Is

Gluon is the deployment planner. It takes three inputs:

1. A validated **pipeline** from Axiom (`.axiom.pbtxt`).
2. A **hardware inventory** containing exact selectable CPU rows and any
   DPDK PCI facts referenced by the bindings.
3. Complete **deployment bindings** describing provider instances, ports,
   queues, storage, execution, and storage transitions.

It produces a **deployment plan** (`plan.pbtxt`) consumed by Photon and the
dataplane. The plan answers the following runtime questions:

| Question                                      | Plan field                                               |
| --------------------------------------------- | -------------------------------------------------------- |
| Which CPU core runs which runtime worker?      | `worker_placements[].cpu_core_ids` |
| Which process facilities and providers exist? | `process_facility_instances[]`, `io_driver_instances[]`, `execution_provider_instances[]` |
| Which storage owns each packet population?     | `packet_storage_domains[]` |
| Which driver port and queue serves each stream? | `ports[]`, `io_streams[]` |
| Which provider executes each stage instance?  | `stage_instances[].execution_provider_instance_id` |
| Which storage originates packets from an active stage? | `stage_instances[].active_origin_storage_domain_id` |
| Where do storage and worker ownership change? | `storage_transitions[]`, `boundaries[]` |
| How are transition services and policy placed? | `runtime_service_placements[]`, `epoch_transition_plan` |

Gluon is **deterministic**: for the same pipeline, hardware inventory,
deployment bindings, and planner options, it produces the same placement,
provider graph, executable topology, and content identity. Runtime metadata
such as `planned_unix_ms` is time-varying. See section 11.

Source: `src/gluon/`. Inputs: `proto/kinetum/axiom/v1/axiom.proto`,
`proto/kinetum/hw/v1/hardware.proto`, `proto/kinetum/gluon/v1/bindings.proto`.
Output: `proto/kinetum/gluon/v1/plan.proto`.

### 2. Authoring Model

Five concepts:

| Term                    | What it is |
| ----------------------- | ---------- |
| **Region**              | Logical partition provenance. One region may contain multiple lane-local runtime workers. |
| **Boundary**            | A `BoundaryPlacement` naming exact stage instances, workers, and bounded handoff storage. |
| **Provider instance**   | One exact process facility, I/O driver, storage domain, or execution target selected by typed configuration. |
| **Storage transition**  | One explicit storage/access change between typed packet-path endpoints. |
| **Plan**                | The complete `DeploymentPlan`: logical placement, provider graph, executable topology, services, and identity. |

The mental model:

- **Axiom** validates the pipeline graph.
- **Gluon** decides placement and deterministically resolves complete
  deployment intent into provider, stream, transition, and boundary facts.
- **Photon and the dataplane** execute the plan.

Gluon produces plans; it never executes packets.

### 3. Inputs

#### 3.1 Axiom Pipeline (`--axiom`)

The CLI uses Axiom's strict pbtxt loader; `plan()` runs the same complete
contract first. Neither supplies missing identity, stage configuration, or
stage/edge modes, and Gluon adds no competing structural validator.
See [`AXIOM.md`](AXIOM.md) for pipeline authoring.

#### 3.2 Hardware Inventory (`--hw`)

`HardwareInventory` (`proto/kinetum/hw/v1/hardware.proto`) describes exactly
one runtime host through the singular `node` field. Its complete shape is:

| Record | Fields | Meaning |
| ------ | ------ | ------- |
| `HardwareInventory` | `node` | Required single planning host. |
| `Node` | `cpu`, `nics[]` | Exact CPU candidates and DPDK-owned PCI attachments. |
| `CpuInfo` | `core_topology[]` | Complete selectable logical-CPU set; an empty set rejects. |
| `CpuCore` | `core_id`, `numa_node`, `is_hyperthread` | Unique nonnegative CPU identity, exact NUMA owner, and sibling classification. |
| `NicPort` | `pci_address`, `max_mtu`, optional `mac_address`, `numa_node`, `driver` | Exact physical fact for one referenced DPDK PCI attachment. |

`NicDriver` contains only `NIC_DRIVER_UNSPECIFIED` and
`NIC_DRIVER_DPDK`; an admitted PCI row requires DPDK. Count-only CPU
synthesis, host labels, memory summaries, generic capability lists, and
unconsumed device classes are not part of the planning schema. TAP and UDP
identity remains in typed deployment bindings and requires no synthetic NIC
row. Quark and the chosen provider later prove live host truth; inventory
admission is not materialization evidence.

Examples: `examples/fan_in_edge_gateway/hardware_inventory_tap.pbtxt`,
`examples/fan_in_edge_gateway/hardware_inventory_cloudlab_d430.pbtxt`,
and `examples/passthrough/hardware_inventory_tap.pbtxt`.

#### 3.3 Deployment Bindings (`--bindings`)

`DeploymentBindings` (`proto/kinetum/gluon/v1/bindings.proto`) names provider
instances and binds every logical endpoint to ports, queues, storage,
execution, and transitions. It contains no process-wide backend selector.

The root contains ten arrays:

| Field | Purpose |
| ----- | ------- |
| `process_facility_instances[]` | Exact process- or device-scoped facility configurations. |
| `io_driver_instances[]` | Exact I/O-driver configurations and facility references. |
| `packet_storage_domains[]` | Exact bounded storage populations, placement, and facility references. |
| `execution_provider_instances[]` | Exact stage-execution targets and facility references. |
| `logical_port_bindings[]` | Logical interface to driver-instance/driver-port identity, direction, optional NUMA constraint, and MTU. |
| `io_stream_bindings[]` | Every requested RX/TX queue, descriptor count, per-queue storage binding, and steering contract. |
| `stage_execution_bindings[]` | Every logical stage to one explicit execution-provider instance. |
| `storage_transition_bindings[]` | Exact logical endpoint pair, source/destination domains, facilities, typed mechanism, capacity, and optional NUMA. |
| `active_origin_bindings[]` | Exact active logical-stage/lane to packet-storage-domain ownership; passive stages have no row. |
| `module_context_resource_bindings[]` | Exact context-lifetime and per-epoch arena capacities for every module stage/lane; platform stages have no row. |

The first four arrays reuse plan messages, keeping one provider-configuration
schema. Each canonical `google.protobuf.Any` identifies its contract by the
complete `type.googleapis.com/<fully.qualified.Message>` URL. Gluon decodes
through the pure catalog, never inferring a provider from attachments or
installed components.

`LogicalPortBinding` names an Axiom interface, exact
`io_driver_instance_id`, exact `driver_port_id`, allowed direction, optional
host-NUMA constraint, and exact nonzero MTU. PCI BDF, TAP interface, or numeric
UDP endpoint syntax remains inside the selected driver's typed configuration.

`IoStreamBinding.queues[]` is mandatory and explicit. A single-queue
deployment carries queue `0`; omission never means one stream. Every queue has
an exact descriptor count and a direction-specific storage arm: RX selects
`rx_storage_domain_id`; TX declares the nonempty accepted set in
`tx_storage.storage_domain_ids[]`. RX queues on the same port may select
different domains. TX sets reject duplicates and are sorted before plan
identity is computed. A wrong or missing arm rejects. RSS carries exact fields
and a nonempty deterministic key. The current producer copies authored key bytes
unchanged; it never samples entropy or selects a driver default. Multi-queue RX
lowering emits a complete lane-local pipeline and matching TX streams. Active
stages are replicated only with one exact context-resource binding and one
active-origin binding per emitted lane; runtime scheduling state remains keyed
by `stage_instance_id`, never logical stage ID.

`StageExecutionBinding` covers every logical stage exactly once. CPU execution
is an explicit provider instance, not an absent-field default.

`ActiveOriginBinding` covers every active `(logical_stage_id, lane_id)` exactly
once and names the storage domain from which that instance originates packets.
Passive stages must have no row. The planner never substitutes the first host
domain, the worker's ingress domain, or a provider default. Missing, duplicate,
extra, passive-stage, unknown-lane, and unknown-domain rows reject.

`StorageTransitionBinding` keeps I/O and stage endpoint namespaces distinct
while authoring. Gluon resolves logical interface/direction/queue and
logical-stage/lane references into final `PacketPathEndpoint` IDs. It does not
invent transitions. A stage-to-stage change of worker or execution provider
requires one authored transition per reachable source domain, including when
that domain stays unchanged. Use `ZeroCopyShareConfig` for a same-domain
handoff; the boundary supplies transport between workers.

The design separation is:

- `hardware.proto` = physical facts (what exists);
- `bindings.proto` = complete deployment intent (what is requested);
- provider contracts = typed meaning and canonicalization;
- `plan.proto` = resolved, deterministic runtime truth.

`--bindings` is required for every plan. Missing or incomplete intent fails
with `INVALID_ARGUMENT`; there is no unbound or development repair mode.

### 4. Outputs: The Plan

`DeploymentPlan` (`proto/kinetum/gluon/v1/plan.proto`) is the contract
between Gluon and the runtime. Top-level fields:

| Number | Field | Purpose |
| ------ | ----- | ------- |
| 1 | `plan_id` | Human-scale deterministic structural identity. |
| 2 | `pipeline` | Embedded validated pipeline. |
| 3 | `regions[]` | Logical partition provenance. |
| 4 | `boundaries[]` | Exact cross-worker executable handoffs. |
| 5 | `epoch_transition_plan` | Bounded ordered-transition policy. |
| 6 | `metadata` | Planner provenance and timing. |
| 7 | `process_facility_instances[]` | Exact process/device facilities. |
| 8 | `io_driver_instances[]` | Exact packet-I/O implementations. |
| 9 | `packet_storage_domains[]` | Exact bounded packet populations. |
| 10 | `execution_provider_instances[]` | Exact stage-execution implementations. |
| 11 | `storage_transitions[]` | Exact directed storage/access changes. |
| 12 | `ports[]` | Exact logical-to-driver-port bindings. |
| 13 | `execution_lanes[]` | Resolved execution groupings. |
| 14 | `stage_instances[]` | Resolved executable stage ownership. |
| 15 | `io_streams[]` | Resolved queue, worker, storage, and stage ownership. |
| 16 | `traffic_steering_profiles[]` | Exact stream steering contracts. |
| 18 | `worker_placements[]` | Runtime worker and CPU ownership. |
| 19 | `content_hash` | Canonical lowercase SHA-256 semantic identity. |
| 20 | `runtime_service_placements[]` | Coordinator/lifecycle-service CPU, NUMA, and role-correct command-capacity ownership. |
| 21 | `module_context_domains[]` | Complete module populations in canonical context-ordinal order. |

After finalizing workers, services, providers, and boundaries, Gluon emits the
baseline `epoch_transition_plan`, assigns per-queue epoch-staging capacity only
to source workers, and assigns every worker a policy-independent observation
cadence and health-callback budget. It validates the candidate through the
shared transition-topology compiler, then the provider-topology compiler, before
publishing metadata and identity. The latter composes transition validation,
proves the provider graph and buffer floors, and emits the artifact consumed by
DP and Quark. Gluon does not reconstruct host or native capability evidence.

**`plan_id`** is `"plan_"` plus the first 16 hexadecimal characters of a
canonical structural hash computed with both self-identities absent.
`content_hash` is then computed over the complete plan containing that
`plan_id`. The provider-owned identity authority canonicalizes every
role-correct provider `Any`, rejects duplicate facility-reference claims,
preserves every order-contractual plan array, clears `content_hash` and the
declared volatile fields `metadata.planned_unix_ms` and
`metadata.planning_duration_ms`, and uses deterministic protobuf serialization
plus mandatory SHA-256. Unknown fields reject. The result is semantic plan
identity, not a byte hash of rendered pbtxt.

Canonicalization uses the pinned protobuf runtime shared by binaries from one
source tree; it promises no cross-version serialization format. New fields are
hash-covered and order-contractual unless explicitly declared volatile or
set-like. An empty `content_hash` fails verification.

Every emitted plan is complete by construction. Provider instances, stage
execution, ports, queues, storage, transitions, workers, and services have no
unbound form. Completeness does not itself initialize facilities or allocate
DATA/CUT/ACK transport; those side effects belong to transactional dataplane
materialization, not the pure provider compiler.

#### 4.1 Region

`Region` (`proto/kinetum/gluon/v1/plan.proto`):

| Field                 | Purpose                                                                                                        |
| --------------------- | -------------------------------------------------------------------------------------------------------------- |
| `region_id`           | 0-based, contiguous.                                                                                           |
| `logical_stage_ids[]` | Logical stages assigned to this region in canonical Axiom topological order; executable ownership is lowered into `stage_instances[]`. |
| `cpu_core_ids[]`      | Region-level core provenance. Runtime worker affinity is owned by `worker_placements[]`.                       |
| `numa_node`           | NUMA node for memory allocation.                                                                               |

#### 4.2 Worker Placement

`WorkerPlacement` (`proto/kinetum/gluon/v1/plan.proto`) is the resolved
scheduling truth for runtime workers:

| Field            | Purpose                                                                    |
| ---------------- | -------------------------------------------------------------------------- |
| `worker_id`      | Stable ID in `worker_r<region>_<lane_id>` form.                            |
| `region_id`      | Region containing this worker's lane-local slice.                          |
| `lane_id`        | Execution lane owned by this worker inside the region.                     |
| `worker_index`   | Compact launch, telemetry, and worker-ledger identity.                      |
| `cpu_core_ids[]` | Dedicated CPU ownership. Gluon emits exactly one core per worker; empty ownership fails host admission. |
| `source_epoch_staging_capacity` | Power-of-two capacity of at least two for each active/future queue in a source worker's swappable pair, applied independently to every exact source storage domain. It is distinct from every boundary's sender-owned future-output hold. |
| `module_health_poll_interval_ms` | Policy-independent owner-worker telemetry cadence and, when enabled, module-health cadence. |
| `module_health_callback_budget_ns` | Policy-independent maximum admitted owner-worker health callback duration; telemetry does not consume it as a work budget. |

One logical region can contain multiple runtime workers when RSS stream
intent creates multiple lanes, so CPU affinity is worker-owned rather than
region-owned.

The current planner assigns source epoch-staging capacity only to workers that
own an RX stage instance or an explicit active-origin domain. The value is a
power of two and at least two; non-source workers carry zero and own no future
queue. The provider compiler preserves the exact sorted source storage-domain
projection in each
worker schedule. Runtime materialization gives every projected source domain an
equal-capacity active/future pair, while every other reachable domain owns one
active queue only. Every worker also receives the plan-owned,
policy-independent observation cadence and exact owner-health callback budget.
The shared compiler rejects an inverted source-capacity assignment, zero or
unrepresentable cadence values, or a callback budget that is not strictly
shorter than its poll interval.

#### 4.3 BoundaryPlacement

`BoundaryPlacement` (`proto/kinetum/gluon/v1/plan.proto`) is executable
topology. It names one exact cross-worker stage-instance edge and the bounded
storage assigned to it; logical region IDs are not sufficient ownership.

| Field                          | Purpose                                                  |
| ------------------------------ | -------------------------------------------------------- |
| `boundary_id`                  | Deterministic identity derived from the endpoint stage-instance IDs. |
| `from_stage_instance_id`, `to_stage_instance_id` | Exact executable pipeline edge.                |
| `sender_worker_id`, `receiver_worker_id` | Sole producer/consumer ownership for the boundary. |
| `data_ring_capacity`           | Power-of-two DATA-ring capacity of at least two.          |
| `future_output_hold_capacity`  | Power-of-two sender-owned future-output capacity of at least two. |
| `data_ring_numa_node`          | Explicit NUMA placement of DATA-ring storage.            |

The DATA ring is placed on the receiver's NUMA node because drain-through-cut
and downstream admission are the ordered handoff's consumer-side operations.
`future_output_hold_capacity` instead budgets the sender-owned queue that holds
future-epoch output until that boundary is acknowledged. It is not the same
queue or budget as `WorkerPlacement.source_epoch_staging_capacity`: the worker
field sizes both roles of every source-domain input pair, while the boundary
field sizes one independently owned output hold.

The schema has no marker-enable switch, inferred join flag, generic threshold,
or default capacity. Gluon emits and hashes these records; the shared compiler
admits them only after proving exact two-directional set equality with the
cross-worker executable graph, canonical endpoint/worker ownership,
power-of-two capacities, receiver-local DATA NUMA, and an acyclic participant
graph.

#### 4.4 EpochTransitionPlan

`EpochTransitionPlan` carries typed, bounded policy for one dataplane-wide
ordered transition:

| Field                              | Purpose                                                  |
| ---------------------------------- | -------------------------------------------------------- |
| `coordinator_service_id`           | Runtime service owning the serialized transition generation. |
| `lifecycle_executor_service_ids[]` | NUMA-local services eligible for prepare/retire work.    |
| `prepare_timeout_ms`               | Cold preparation deadline before cooperative cancellation. |
| `prepare_cancel_grace_ms`          | Bounded grace for a canceled callback to return.         |
| `prepared_lease_timeout_ms`        | Lease before an abandoned pre-commit transaction aborts. |
| `commit_timeout_ms`                | Completion-only ordered-cut commit deadline.             |
| `retirement_timeout_ms`            | Deadline that freezes later updates while retaining old state; it never authorizes reclamation. |
| `result_history_capacity`          | Fixed terminal-result journal size, admitted in `1..64`. |

Absence means fixed-epoch and requires every transition-only worker field to be
zero. Gluon emits presence for runnable plans and the shared compiler resolves
all service references and durations into compact monotonic-clock policy. It
requires positive representable values, cancellation grace no longer than
prepare timeout, prepared lease at least as large as the prepare and commit
budgets, retirement timeout no shorter than commit timeout, and terminal
history in `1..64`. There is no free-form timeout strategy or runtime default.

The current generated profile is planner-owned rather than CLI-tunable:

| Policy fact | Emitted value |
| ----------- | ------------- |
| `prepare_timeout_ms` | `30000` |
| `prepare_cancel_grace_ms` | `1000` |
| `prepared_lease_timeout_ms` | `60000` |
| `commit_timeout_ms` | `5000` |
| `retirement_timeout_ms` | `5000` |
| `result_history_capacity` | `16` |
| coordinator `command_mailbox_capacity` | `64` |
| source `source_epoch_staging_capacity` | `1024` per queue role and source domain |
| worker `module_health_poll_interval_ms` | `1000` |
| worker `module_health_callback_budget_ns` | `10000` |

These are one coherent target profile. The worker cadence/budget pair is
required even when live transition policy is absent; only source staging is
transition-conditional. Both durations must convert exactly to the runtime
monotonic clock, and the callback budget must remain strictly shorter than the
cadence. A changed value must be emitted by the planner and pass the same
relational validator; it cannot appear as a runtime default or a second mutable
config surface.

#### 4.5 Runtime Services and Provider Graph

`RuntimeServicePlacement` gives each provider-neutral coordinator or lifecycle
executor one stable identity, service kind, CPU core, NUMA node, and explicit
role-owned command-mailbox capacity. Gluon emits exactly one
`epoch_transition_coordinator` with capacity `64` plus one
`config_lifecycle_executor_numa_<node>` for every NUMA node containing a module
context. Every executor carries zero mailbox capacity. A module-free plan still
receives one executor on its lowest populated region's node so fixed-epoch
Bootstrap has both a lifecycle owner and the same coordinator mailbox used by a
transition-enabled plan. Service cores are pairwise disjoint and never overlap
packet-worker cores.

The shared compiler independently requires the coordinator capacity to be a
power of two in `2..64` and every executor capacity to equal zero. The field
belongs to service placement rather than `EpochTransitionPlan` because fixed
Bootstrap uses it even when transition policy is absent. Zero is not a default,
and no CLI, CMake option, environment value, or runtime repair can replace it.

Runtime service placement is one transactional cold-path pass:

1. The singular node's explicit `cpu.core_topology[]` is the complete
   candidate set. Missing or duplicate rows reject; no count creates a core.
2. The lowest `reserved_cores` logical IDs are excluded from packet workers and
   preferred for services. Reserved remainder stays unused.
3. Every worker group belonging to one logical region is placed as an
   indivisible NUMA-local unit. Module-bearing regions are placed before
   mechanism-only regions, then larger worker groups, then region ID.
4. With `numa_aware=true`, eligible nodes are selected by current assigned
   worker count then NUMA ID. With it disabled, lower NUMA IDs fill first.
5. The coordinator consumes the first feasible reserved core in ascending ID
   order. Without one, both coordinator and lifecycle-executor fallback preserve
   the strongest packet candidates: with physical preference enabled they take
   hyperthreads before physical cores and use descending core ID within a
   thread class; with it disabled they use descending core ID. A lifecycle
   executor applies that rule within its required NUMA node. Packet workers
   consume the remaining candidates in physical-first, then logical-ID order
   unless `prefer_physical_cores=false` requests plain logical-core ordering.
6. Gluon validates the complete temporary assignment and only then replaces
   worker, region-provenance, and service placement fields.

The shared transition-topology compiler admits canonical IDs, supported kinds,
nonnegative CPU/NUMA facts, worker/service disjointness, exact coordinator
cardinality, canonical executor order, and exact executor coverage for every
module-context NUMA node. Quark consumes that compiled artifact, validates each
selected core and its NUMA node against the host, and returns only a decision,
summary, and bounded diagnostics. The compiled artifact remains sole placement
truth. Runtime service launch is a separate lifecycle operation; admission
never treats a placement record as an already launched thread.

`RuntimeServiceKind` is closed over three prefixed values:

| Value | Meaning |
| ----- | ------- |
| `RUNTIME_SERVICE_KIND_UNSPECIFIED` | Invalid when a placement is admitted. |
| `RUNTIME_SERVICE_KIND_EPOCH_TRANSITION_COORDINATOR` | Sole writer of global transition state. |
| `RUNTIME_SERVICE_KIND_CONFIG_LIFECYCLE_EXECUTOR` | NUMA-local cold prepare/retire executor. |

Runtime cardinality and polling remain under their current owners:

- worker count is exactly `worker_placements_size()`;
- each executable boundary owns its DATA and future-output capacities;
- polling strategy is an implementation property, not a mutable plan switch.

The provider graph keeps each runtime fact under its owning record:

| Plan record | Owns |
| ----------- | ---- |
| `ProcessFacilityInstance` | One canonical process/device facility configuration. |
| `IoDriverInstance` | One canonical I/O implementation plus exact facility references. |
| `PacketStorageDomain` | Buffer count, data room, headroom, alignment, optional host NUMA, and exact storage configuration. |
| `ExecutionProviderInstance` | One canonical stage-execution implementation plus exact facility references. |
| `StorageTransition` | One exact directed storage/access change and its bounded staging facts. |

Facility-reference arrays are sorted, unique sets. Empty has contract-defined
meaning and never means infer a default facility. The typed DPDK facility
configuration deliberately carries no free-form EAL arguments. The shared
provider compiler derives native process-core, device, memory, and NUMA
requirements from generic plan truth; materialization renders and validates
the native configuration once.

Each storage domain's authored `buffer_count` must satisfy the floor emitted by
the shared compiler's checked `plan_buffer_budget`. Gluon rejects insufficient
capacity before publishing the plan. [Provider capacity validation](PROVIDERS.md#4-compiled-topology-and-host-proof)
defines the per-domain terms, handoff attribution, and multi-domain TX charge.

Module lifecycle memory follows the same plan-authoritative rule through a
separate exact authoring fact. `module_context_resource_bindings[]` contains
one row for every `(logical module stage, lane)` and no row for a platform
stage. Each row carries a nonzero context-lifetime byte capacity and a nonzero
per-epoch arena byte capacity. Gluon requires exact two-directional coverage,
lowers both values into the matching `StageInstance` before plan hashing, and
never derives either value from module configuration or a runtime default. The
shared compiler checks narrowing and aggregate overflow, groups the totals by
NUMA owner, and multiplies the per-epoch term by
`EXACT_EPOCH_SLOT_COUNT`. Runtime lifecycle allocation enforces those exact
compiled limits.

#### 4.6 PlanMetadata

`PlanMetadata` (`proto/kinetum/gluon/v1/plan.proto`) records planner provenance:

| Field                  | Value written by Gluon                                      |
| ---------------------- | ----------------------------------------------------------- |
| `planner_version`      | `"gluon-0.1.0"` (`PLANNER_VERSION_PREFIX` plus the injected product version). |
| `planned_unix_ms`      | Wall-clock planning timestamp; time-varying.                |
| `algorithm`            | Stable algorithm identity. Current plans use `linear_dp_v2`. |
| `planning_duration_ms` | Measured steady-clock planning duration.                    |

## Part 2: Planning and Lowering

### 5. Region Partitioning

Region partitioning is the core decision: which stages run in which logical
region before executable workers receive exact CPU ownership.

#### 5.1 Algorithm flow

| Phase | Step                                                   | Source                                         |
| ----- | ------------------------------------------------------ | ---------------------------------------------- |
| 1     | Complete Axiom contract admission                      | `axiom::verify_contract`                       |
| 2     | Planner option and size validation                     | `plan_impl` early returns                      |
| 3     | Canonical topological order with smallest-ready ID tie-break | `axiom::canonical_topological_order`      |
| 4     | Preferred-region and affinity relation resolution      | `compute_pinning` plus the constraint loop     |
| 5     | Stage weight computation and linear dynamic programming | `get_stage_weight` plus `partition_linear_dp` |
| 6     | Region assembly and exact provider/topology lowering   | deployment, core, boundary, and transition lowering owners |
| 7     | Provider-topology self-check, metadata, `plan_id`, and canonical `content_hash` | shared compiler plus deployment-plan identity |

For the visual sequence, see [`diagrams/platform_architecture.md`](diagrams/platform_architecture.md)
section 2.

#### 5.2 Stage weights

Partitioning balances *weight* across regions, not stage count. Default
weights (per stage kind) come from `default_stage_weight()`
(`src/gluon/gluon_planner.hpp`):

| Stage kind   | Default weight |
| ------------ | -------------- |
| `RX`, `TX`   | 0              |
| `PARSE_IPV4` | 1              |
| `MODULE` (ACL) | 3            |
| `MODULE` (QOS) | 3            |
| `MODULE` (NAT44) | 4          |
| `MODULE` (other admitted identity) | 5  |

Weight sources are checked in this order:

1. `Stage.cost_weight > 0`.
2. `default_stage_weight()` for an exact admitted current kind.

There is no callback, free-form parameter, or alternate weight authority.
Calling the internal default-weight helper with an invalid stage is a
programmer contract violation and fails stop.

#### 5.3 Partition algorithm

Gluon has one partition implementation: exact linear dynamic programming over
the canonical Axiom order, reported as `linear_dp_v2`. No algorithm enum,
fallback selector, or dormant solver surface exists.

#### 5.4 Pinning and `--regions`

`Stage.preferred_region` is honored as a hard placement request. The value
must be in `[0, regions)`; negative or out-of-range values return
`INVALID_ARGUMENT`. Pinning takes priority over weight balance; the
balancer fills the remaining stages. Pins must also be monotonic in
topological order, otherwise planning fails.

`--regions N` is an integer (default 2). There is no auto-sizing:
`kinetum_gluon` requires you to choose `N` based on your hardware. The
upper bound is `MAX_REGIONS = 256` (`src/gluon/gluon_planner.cpp`). Pipeline
population is already bounded by Axiom's shared contract to
`MAX_PIPELINE_STAGES = 256`; Gluon has no second stage-count ceiling.

### 6. Placement Constraints and Pins

Two kinds of pipeline constraint govern the partitioning described in section 5:

1. **Pipeline-level pins**: `Stage.preferred_region`.
2. **Pipeline-level affinities**: `StageConstraints.affinity_stages` and
   `anti_affinity_stages`.

Planner options separately constrain eligible NUMA nodes and core-selection
policy; they do not restate graph affinity.

#### 6.1 Enforced constraints

| Constraint                              | Source                          | Effect                                  |
| --------------------------------------- | ------------------------------- | --------------------------------------- |
| `Stage.preferred_region`                | Pipeline (Axiom field)          | Hard placement request; invalid values fail. |
| `StageConstraints.affinity_stages`      | Pipeline (Axiom field)          | Translated to `must_colocate` pairs and validated after partitioning. |
| `StageConstraints.anti_affinity_stages` | Pipeline (Axiom field)          | Translated to `must_separate` pairs and validated after partitioning. |
| `planner_options.allowed_numa_nodes`    | Source-tree C++ API             | Restricts core selection to listed NUMA nodes. |
| `planner_options.reserved_cores`        | Source-tree C++ API / CLI       | Excludes the lowest N logical cores from packet workers, prefers them for runtime services, and leaves unused remainder unassigned. |
| `planner_options.numa_aware`            | Source-tree C++ API             | Balances indivisible region worker groups across eligible NUMA nodes. |
| `planner_options.prefer_physical_cores` | Source-tree C++ API             | Prefers physical packet cores within each NUMA node; false restores logical-ID ordering. |

#### 6.2 Closed constraint surface

No unconsumed constraint message or planner option is retained. A new
constraint must acquire an author, validator, planning effect, plan projection,
and tests in the same contract change.

Axiom has already validated every relation as one unique, non-self,
noncontradictory pair. Gluon sorts those exact pairs for deterministic
partition input and treats any missing post-admission assignment as an internal
contradiction.

### 7. Deployment Binding Resolution

Binding resolves logical interfaces (`wan0`, `lan0`) into the provider graph.
Gluon validates a candidate and swaps it into the plan only after every authoring
stage succeeds.

#### 7.1 Inputs

- Every pipeline RX/TX stage carries one typed `IoStageConfig.interface`.
- Interface, provider, facility, storage, transition, and stage identities
  obey the shared bounded topology grammar.
- `DeploymentBindings` declares all four provider-role instance sets, every
  logical port, every required queue, every stage execution target, and every
  storage transition, one exact origin storage domain for every active
  stage/lane, and one exact resource row for every module stage/lane.
- Driver attachment data lives only in typed driver configuration.
- Hardware inventory supplies independent physical facts. It does not select a
  provider or fill an omitted binding.

#### 7.2 Stable authoring ladder

Gluon applies this order so diagnostics and side-effect boundaries remain
stable:

1. Reject recursive unknown fields and invalid enum values.
2. Validate identifier grammar, duplicate identities, scalar presence, and
   exact bounds.
3. Canonicalize every provider `Any` through the exact role-specific catalog.
4. Validate local provider, facility, port, storage, execution, and active-
   origin references.
5. Prove two-directional pipeline coverage: every logical I/O interface is
   bound exactly once, no unused logical-port or stream binding exists, every
   required direction has explicit queues, every logical stage has one
   execution binding, every active stage/lane has one origin-domain binding,
   and passive stages have none.
6. Resolve typed physical attachments and prove authored constraints against
   hardware inventory.
7. Resolve logical transition endpoints to exact stream/stage-instance IDs.
8. Emit deterministic arrays, canonical provider payloads, and final plan
   identity.

An input crafted to fail several stages reports the earliest stage. Validation
never proceeds to hardware resolution after incomplete pipeline coverage or to
transition lowering after a hardware contradiction.

#### 7.3 Physical fact resolution

A typed DPDK PCI attachment contains one canonical lowercase BDF. Gluon
matches that exact BDF against inventory and copies proven six-byte MAC and
NUMA facts into `PortConfig`. An authored NUMA constraint must equal the proven
fact.

A typed DPDK TAP attachment carries its interface name in the driver
configuration and needs no NIC-inventory row. A typed UDP attachment similarly
carries a canonical numeric IPv4 address and exact port. Neither proves host
NUMA ownership, so an authored NUMA constraint rejects instead of becoming
node zero.

No target string is inspected to infer PCI, TAP, UDP, DPDK, or another
provider. There is no free-form VDEV/EAL argument surface.

#### 7.4 Final port and executable topology

`PortConfig` contains:

| Field | Purpose |
| ----- | ------- |
| `logical_port_id` | Stage-visible ID assigned by sorted `logical_name`. |
| `logical_name` | Exact Axiom `interface` identity. |
| `io_driver_instance_id` | Exact I/O-driver owner. |
| `driver_port_id` | Exact driver-local port identity. |
| `direction` | Explicit `RX_ONLY`, `TX_ONLY`, or `BIDIRECTIONAL`. |
| `host_numa_node` | Optional proven host NUMA fact; absence is not node zero. |
| `mtu` | Exact nonzero MTU. |
| `resolved_mac_address` | Empty or exactly six hardware-resolved bytes. |

Executable topology records are:

| Record | Purpose |
| ------ | ------- |
| `execution_lanes[]` | Deterministic lane grouping. Single-queue plans emit `lane_0`; multi-queue RX emits one lane per queue. |
| `stage_instances[]` | Logical stage, lane, region, replica, module-context identity and capacities, exact execution provider, and exact active-origin storage domain when active. |
| `io_streams[]` | Logical port, lane, direction, stage, steering profile, driver queue, owner worker, RX allocation domain or TX accepted-domain set, and descriptor count. |
| `traffic_steering_profiles[]` | Exact steering kind, symmetry request, fields, key bytes, and governed streams. |
| `module_context_domains[]` | Sorted context identities sharing one module configuration; position defines the generation-fixed ordinal. |
| `storage_transitions[]` | Exact typed endpoint pair and source/destination storage ownership. |

`TrafficSteeringKind` is closed over `NONE` and `RSS`, plus the rejecting
`UNSPECIFIED` sentinel. A different steering mechanism requires a complete
typed driver contract and plan change; no placeholder enum value is retained.

Every module stage instance owns one context whose `context_instance_id` equals
its `stage_instance_id`, plus explicit nonzero context-lifetime and per-epoch
arena capacities. Platform stages carry none of those facts. Multiple
per-instance contexts for one image require
`KINETUM_MOD_F_REPLICABLE_CONTEXTS`.

An active stage instance additionally carries one nonempty
`active_origin_storage_domain_id`; a passive instance carries the empty value.
Topology lowering derives this field only from the exact authored
`ActiveOriginBinding`. The shared compiler then proves execution-provider
write access, placement/NUMA agreement, worker ownership, reachable-domain
propagation, and exact buffer-budget impact before the plan can be published.
The authored pipeline's `ActiveStageLimits` are copied semantically to every
instance: retained packet/byte, timer, and control capacities remain exact
per-lane bounds rather than one shared logical-stage pool.

PULL and control relations require active endpoints in one logical region and
one declaration per exact endpoint pair. Lane lowering preserves matching
replicas, and the shared provider compiler then requires each expanded pair to
have one exact worker owner. No cross-worker active mailbox or request bit is
synthesized.

Single-queue bindings explicitly carry driver queue `0`. Multi-queue RX
requires a complete RSS contract and equal queue shape across the replicated
pipeline. Gluon emits lane-local stage instances, matching TX streams,
and one RSS profile per ingress port. Each profile carries its own nonempty
key. Module-context selection owns session routing independently of hardware
RSS. A PUSH edge into a MODULE-selected stage expands to every permitted
destination context; SAME_LANE, PULL, and control retain their matching replica.
Explicit multi-queue TX-only authoring remains rejected. Active
replication is admitted only when all per-lane origin/context bindings exist;
module-image `REPLICABLE_CONTEXTS` is checked later during exact image/context
admission.

Drivers and test harnesses consume final `io_driver_instance_id`,
`driver_port_id`, `driver_queue_id`, `rx_storage_domain_id` or
`tx_storage.storage_domain_ids[]`, and `resolved_mac_address` facts. They do not
duplicate physical target or textual MAC authorities.

### 8. Provider Contracts and Binding Requirements

Gluon does not choose a process-wide backend and does not depend on Quark.
Provider meaning comes from the pure contract catalog; deployment choice comes
from `DeploymentBindings`; hardware facts come from `HardwareInventory`.

#### 8.1 Current contract vocabulary

Bindings select the exact type URLs listed in
[Typed Configuration](PROVIDERS.md#3-typed-configuration). Gluon consumes their
pure capability and dependency projections; installed component availability
and native host capability are checked later at startup.

#### 8.2 What Gluon checks

Gluon:

1. Re-runs Axiom's exact current-kind, typed-configuration, explicit-mode, and
   graph contract before examining planner options.
2. Requires complete `DeploymentBindings`; there is no optional or unbound
   case.
3. Enforces the stable authoring ladder in section 7, including role-correct
   provider canonicalization, local references, two-directional pipeline
   coverage, exact active-origin and module-resource coverage, typed hardware
   resolution, and transition endpoint resolution.

Gluon does not initialize a facility, open a device, probe a PMD, reserve a
queue, or prove a provider component is installed. Quark proves only compiled
CPU, runtime-service, and host-memory requirements. Native DPDK runtime/
hugepage and UDP socket facts are component-phase proofs; live ethdev checks
that require initialized facility state belong to transactional dataplane
materialization.

#### 8.3 No native argument synthesis

The plan contains no EAL argv, UDP endpoint override, provider enum, or
backend-specific singleton. DPDK facility requirements are derived later from
the exact worker/service core union, typed PCI/TAP attachments, storage
domains, and NUMA facts. UDP endpoints remain in typed UDP driver
configuration. Neither can be repaired or overridden through a startup flag.

### 9. Executable Boundary Ownership

A boundary is an exact handoff between two runtime workers. The final Gluon
lowering owns `BoundaryPlacement`; the dataplane materializes only those
records. Neither side may infer a boundary from logical regions.

#### 9.1 Required lowering rule

For every resolved stage-instance edge:

- If both instances have the same worker owner, no boundary is emitted.
- If their worker owners differ, exactly one `BoundaryPlacement` is required.
- Repeated authored edges with the same directed executable endpoints collapse
  to that one placement; reverse direction is a distinct SPSC boundary.

Therefore `boundaries[]` is exactly the set of distinct directed cross-worker
stage-instance endpoint pairs: no missing record, no extra record, and no
same-worker record. `boundary_id` has the deterministic form
`boundary.<from_stage_instance_id>.<to_stage_instance_id>`. The ID remains
injective because authored logical-stage and lane atoms must match
`[A-Za-z_][A-Za-z0-9_]*` (and therefore exclude `.` and `@`), while every
stage-instance ID has the fixed `<logical_stage_id>@<lane_id>` arity. Boundary
lowering reconstructs canonical endpoint/worker IDs and fails closed on any
grammar or ownership mismatch. The placement carries exact worker IDs, DATA
capacity, future-output hold capacity, and receiver-local DATA-ring NUMA
placement.

#### 9.2 Shared compilation and runtime materialization

Executable boundary emission precedes transition-policy lowering and final plan
hashing. Gluon submits the complete candidate to
`compile_provider_topology()` before publishing it. That compiler composes the
transition authority and produces compact workers, exact inbound/outbound
boundary indices, source/sink sets, sorted source storage-domain projections,
runtime-service indices, lifecycle NUMA coverage, monotonic policy durations,
reachable storage domains, transition schedules, and buffer floors. DP passes
that same representation to Quark before checking exact host CPU/NUMA truth.

DP allocates the endpoint slabs, rings, active/future queues, and reader records
from these compiled sets before worker launch. It derives certificate membership
from the same worker/boundary graph rather than introducing another plan
capacity or cycle validator. Allocation does not authorize a transition: each
worker must drain every inbound CUT and its local old work before activation.
[Data Plane boundary integration](DATA_PLANE.md#12-cross-region-boundary-integration)
owns the queue placement, transition sequence, and reclamation mechanics.

#### 9.3 What lives in the plan vs. the dataplane

| Concern                                       | Owner          |
| --------------------------------------------- | -------------- |
| Endpoint stage instances and worker owners    | Gluon `BoundaryPlacement` |
| DATA and future-output capacities, DATA NUMA  | Gluon `BoundaryPlacement` |
| Source active/future queue capacity            | Gluon `WorkerPlacement.source_epoch_staging_capacity` |
| Fixed-epoch DATA-ring materialization          | Dataplane, exactly from admitted placement |
| Source queue-pair and future-hold materialization | Dataplane, exactly from compiled worker/boundary ownership |
| DATA pointer ownership, successful sequences, and typed control transport | Dataplane boundary endpoint owners |
| Sender sealing, future-output gating, and exact ACK interpretation | Dataplane ordered-transition protocol |
| CUT drain, fan-in activation, and exact ACK publication | Dataplane ordered-transition protocol |
| Reader grace and global certificate evaluation | Dataplane, exactly from frozen worker/boundary membership |

## Part 3: Validation and Determinism

### 10. Validation Rules

Gluon enforces these rules after Axiom's topology validation
([`AXIOM.md`](AXIOM.md), section 10).

#### Size limits

- Axiom's shared source contract admits at most 256 stages and 1024 packet plus
  control edges. Violation returns `INVALID_ARGUMENT` before partition state.
- The aggregate authored/default stage weight must fit `uint64_t`; overflow
  returns `OUT_OF_RANGE` before the recurrence.
- `regions > 0`. Violation returns `INVALID_ARGUMENT`.
- `regions <= MAX_REGIONS (256)`. Violation returns `INVALID_ARGUMENT`.
- `reserved_cores >= 0`. Violation returns `INVALID_ARGUMENT`.
- Entries in `planner_options.allowed_numa_nodes` must be
  non-negative. Violation returns `INVALID_ARGUMENT`.

#### Stage and provider authoring

- Axiom admission requires RX, TX, PARSE_IPV4, or MODULE with exact typed
  configuration and explicit stage/edge modes. Unspecified and unknown values
  reject before planning.
- Every provider `Any` must use a known canonical type URL in the correct
  role and canonical payload bytes.
- Provider/facility identities and declared set references must be
  duplicate-free and satisfy the shared bounded identifier grammar.

#### Algorithm

- `linear_dp_v2` is the sole implementation and plan-metadata identity.
- No algorithm selector or fallback is accepted.

#### Constraints

- Axiom affinity and anti-affinity relations are validated after partitioning.
  If the resulting assignment violates them, planning fails.
- `Stage.preferred_region` values must be in `[0, regions)` and monotonic in
  topological order.

#### Edges

- `PULL` edges require active endpoints and must not cross regions. Axiom owns
  endpoint mode; Gluon owns the post-partition region proof; the shared
  compiler owns exact same-worker lane expansion.
- Control edges must not cross regions. Same enforcement.

#### Bindings

- `--bindings` is required for every plan. Missing or empty
  `DeploymentBindings` returns `INVALID_ARGUMENT`.
- Every RX/TX `interface` has exactly one logical-port binding and explicit
  queue binding for each required direction; unused or duplicate bindings
  reject.
- Every logical stage has exactly one execution-provider binding.
- Every active logical stage/lane has exactly one origin-storage binding, and
  every passive stage/lane has none.
- Every module logical stage/lane has exactly one nonzero context-resource
  binding, and every platform stage/lane has none.
- Every queue has explicit descriptor count, direction-correct storage binding,
  and steering contract; a single queue still names queue zero.
- Typed PCI attachments must resolve exact inventory facts. TAP and UDP
  attachments do not prove host NUMA, so a NUMA constraint on either rejects.
- Every logical storage-transition endpoint must resolve to one exact final
  stream or stage-instance identity.

### 11. Determinism

For the same pipeline, hardware inventory, deployment bindings, and planner
options, Gluon produces the same placement, canonical provider graph,
executable topology, and identity. Runtime metadata such as
`planned_unix_ms` is time-varying. Deterministic provider, stream, transition,
boundary, and runtime-service identity is part of the compact contract.

The mechanisms that enforce this:

- **Topological order** comes from Axiom's single structural graph authority,
  which uses Kahn's algorithm with smallest-`stage_id` tie-breaking
  (`axiom::canonical_topological_order`).
- **Constraints are sorted** by canonical pair representation before
  partitioning, so different proto orderings of the same logical
  constraints produce identical plans.
- **Core selection** keeps a region's worker group NUMA-local, orders physical
  packet candidates first when requested, balances region groups by assigned
  worker count and NUMA ID, and emits services in coordinator-then-NUMA order.
- **Logical port IDs** are assigned by sorted `logical_name`.
- **Deployment-binding sets** normalize by stable identity after duplicates
  reject; facility references are sorted unique sets, and active-origin rows
  sort by `(logical_stage_id, lane_id)`.
- **Executable membership sets** sort execution-lane stage/stream identities,
  steering-profile stream identities, and each module's context identities
  before plan publication. Module domains sort by module ID.
- **Provider payloads** pass through the exact catalog and are repacked from
  deterministic concrete-message bytes.
- **Queues and stream IDs** come from explicit driver queue IDs rather than
  emission order or an omitted default.
- **RSS keys** are exact authored bytes; no entropy source or driver default
  participates in planning.
- **`boundary_id`** is derived from canonical directed executable endpoints,
  while a sorted endpoint map makes record order independent of authored edge
  order.

What is **not** part of byte-identical plan-file determinism:

- `metadata.planned_unix_ms` (wall-clock time).
- `metadata.planning_duration_ms` (measured steady-clock duration).

`content_hash` is stable across changes to the two declared timing fields and
sensitive to all other emitted fields, including the exact planner version,
canonical provider payloads, and stable metadata populated at the end of
planning. Final plan arrays retain their emitted order in the identity.
Provider contract graphs contain no maps; only fields explicitly declared
set-like are sorted during authoring.

If you need byte-identical plan files, strip the time-varying metadata
fields before comparison. If you need semantic identity, verify
`content_hash` through the canonical plan helper rather than hashing pbtxt text.

## Part 4: Operation and Embedding

### 12. CLI

```
kinetum_gluon --axiom <pipeline.axiom.pbtxt> --hw <hardware_inventory.pbtxt> --out <plan.pbtxt>
              --bindings <deployment_bindings.pbtxt>
              [--regions N] [--reserved-cores N]
```

| Flag                 | Default          | Purpose                                               |
| -------------------- | ---------------- | ----------------------------------------------------- |
| `--axiom <path>`     | -                | Validated Axiom pipeline. **Required.**               |
| `--hw <path>`        | -                | Hardware inventory. **Required.**                     |
| `--out <path>`       | -                | Output plan path. **Required.**                       |
| `--regions N`        | `2`              | Number of regions (integer; no auto).                 |
| `--reserved-cores N` | `1`              | Lowest logical cores excluded from packet workers, preferred by runtime services, with unused remainder left unassigned. |
| `--bindings <path>`  | -                | Complete `DeploymentBindings`. **Required.**          |
| `-h`, `--help`       | -                | Show usage.                                           |

Unknown or incomplete arguments fail with exit code 2. There is no provider
selector or provider-listing command: exact provider instances are input data,
not compiled-in CLI choices.

Examples:

```bash
# Fan-in edge gateway DAG pipeline, 3 regions, typed TAP deployment
kinetum_gluon --axiom build/fan_in.axiom.pbtxt \
              --hw examples/fan_in_edge_gateway/hardware_inventory_tap.pbtxt \
              --bindings examples/fan_in_edge_gateway/fan_in_edge_gateway_tap_bindings.pbtxt \
              --regions 3 \
              --out build/fan_in_plan.pbtxt

# Same pipeline, exact CloudLab d430 PCI deployment
kinetum_gluon --axiom build/fan_in.axiom.pbtxt \
              --hw examples/fan_in_edge_gateway/hardware_inventory_cloudlab_d430.pbtxt \
              --bindings examples/fan_in_edge_gateway/fan_in_edge_gateway_cloudlab_d430_bindings.pbtxt \
              --regions 3 \
              --out build/fan_in_pci_plan.pbtxt

# Passthrough with its complete typed TAP deployment
kinetum_gluon --axiom build/pipeline.axiom.pbtxt \
              --hw examples/passthrough/hardware_inventory_tap.pbtxt \
              --bindings examples/passthrough/passthrough_tap_bindings.pbtxt \
              --regions 1 \
              --out build/passthrough_plan.pbtxt
```

### 13. Embedding Gluon (Programmatic API)

CI tools, deployment automation, and validators can embed Gluon directly.
Its `src/gluon/` headers and libraries are source-tree interfaces, outside the
installed module SDK.

#### 13.1 Primary Source-Tree API

| API                                                                             | Header                            | Use                                                  |
| ------------------------------------------------------------------------------- | --------------------------------- | ---------------------------------------------------- |
| `plan(Pipeline, HardwareInventory, planner_options)` -> `status_or<DeploymentPlan>` | `src/gluon/gluon_planner.hpp`     | Primary entry point. Generates a deployment plan.    |
| `default_stage_weight(Stage)` -> `uint64_t`                                     | `src/gluon/gluon_planner.hpp`     | Weight for an already admitted current stage kind; malformed input fails stop. |
| `planner_options`                                                               | `src/gluon/gluon_planner.hpp`     | Configuration struct (see section 13.2).             |

#### 13.2 `planner_options` fields

| Field                  | Type                                          | Default            |
| ---------------------- | --------------------------------------------- | ------------------ |
| `regions`              | `int32_t`                                     | `2`                |
| `reserved_cores`       | `int32_t`                                     | `1`                |
| `numa_aware`           | `bool`                                        | `true`             |
| `prefer_physical_cores`| `bool`                                        | `true`             |
| `allowed_numa_nodes`   | `std::vector<int32_t>`                         | empty (all represented NUMA nodes) |
| `deployment_bindings`  | `DeploymentBindings`                          | empty (rejected by `plan()`) |

#### 13.3 Error codes

| Code                  | Typical causes                                                               |
| --------------------- | ---------------------------------------------------------------------------- |
| `INVALID_ARGUMENT`    | Invalid Axiom input, `regions <= 0`, `regions > MAX_REGIONS`, negative `reserved_cores` or NUMA IDs, malformed deployment bindings, unknown/wrong-role/noncanonical provider configuration, incomplete pipeline or module-resource coverage, invalid hardware agreement or transition endpoint, PULL/control edge crossing regions, unsatisfied affinity, or invalid `preferred_region` pins. |
| `OUT_OF_RANGE`        | A compact identity, capacity, aggregate stage weight, or host representation exceeds its runtime type. |
| `RESOURCE_EXHAUSTED`  | Provider URL/payload bounds, insufficient NUMA-local cores for workers/services, or bounded cold-table allocation failure. |
| `INTERNAL_ERROR`      | Internal planner invariant failure, such as a cyclic region graph after partitioning. |

#### 13.4 Determinism guarantee

Same as section 11. Embedding callers can assert plan reproducibility by
running `plan()` twice and comparing everything except
`metadata.planned_unix_ms` and `metadata.planning_duration_ms` under the same
planner version.

#### 13.5 Internal primitives (test surface, not stable)

`kinetum::gluon` exposes cold-path lowering components, while
`kinetum::gluon::internal` exposes algorithm building blocks. They exist for
focused tests and advanced validation:

Canonical graph ordering is not a Gluon-internal primitive. It belongs to
Axiom's embedding API as `axiom::canonical_topological_order()` and is shared
by planning and provider-topology compilation.

| Primitive                                   | Purpose                                              |
| ------------------------------------------- | ---------------------------------------------------- |
| `lower_deployment_bindings(DeploymentBindings, HardwareInventory, Plan)` | Transactional eight-stage provider/packet-path authoring ladder. |
| `lower_runtime_core_placement(Plan, HardwareInventory, options)` | Transactional region-local packet-worker and runtime-service CPU placement. |
| `lower_boundary_topology(Plan)` | Transactional exact cross-worker boundary placement after worker ownership and NUMA are final. |

These are implementation primitives rather than the primary source-tree
integration surface. Tests and platform analysis may call them directly;
production source consumers call `plan()`.

### 14. Fan-In Edge Gateway Walkthrough

`examples/fan_in_edge_gateway/` is the canonical multi-ingress DAG:

```
wan0 -> rx0 -> parse0 -> acl0 --+
                              +--> nat -> qos -> tx -> lan0
wan1 -> rx1 -> parse1 -> acl1 --+
```

The pipeline declares `allow_dag: true` and pins ingress stages with
`preferred_region`: `rx0/parse0/acl0 -> 0`, `rx1/parse1/acl1 -> 1`,
and `nat/qos/tx -> 2`.

Run:

```bash
kinetum_gluon --axiom examples/fan_in_edge_gateway/fan_in_edge_gateway.axiom.pbtxt \
              --hw   examples/fan_in_edge_gateway/hardware_inventory_tap.pbtxt \
              --bindings examples/fan_in_edge_gateway/fan_in_edge_gateway_tap_bindings.pbtxt \
              --regions 3 \
              --out  build/fan_in_plan.pbtxt
```

What Gluon decides:

- **Pinning resolves first**: each ingress owns its RX/parse/ACL chain;
  NAT, QoS, and TX occupy region 2.
- **Weight balance** is constrained by the pins; balancer fills around them.
- **Cross-region edges**: `acl0 -> nat` (region 0 -> 2) and `acl1 -> nat`
  (region 1 -> 2). Module selection gives each source access to every NAT
  context; each packet enters one selected context.
- **Boundary construction**: the planner emits two exact worker-owned
  `BoundaryPlacement` records, including capacity and receiver-NUMA facts. The
  shared compiler admits the complete fan-in set and gives the receiving worker
  both inbound indices. RSS2 has six workers and eight boundaries, with four
  inputs per NAT worker. The dataplane never infers a logical-region channel.
- **No boundary inside a region lane**: each ingress chain stays local, as
  does `nat -> qos -> tx` on the selected owner.

The plan's identity covers the authored provider and transition topology.
Execution requires complete compilation and materialization of the provider
graph and plan-sized boundaries, with every worker bound to the same bootstrap
epoch. No plan field selects the epoch-only marker counterexample in
[`diagrams/ordered_cut_boundary_protocol.md`](diagrams/ordered_cut_boundary_protocol.md).

If you change `allow_dag` to `false`, Axiom rejects the multi-ingress graph.
Removing the preferred-region pins leaves a valid DAG but returns placement to
Gluon's weight balancer, so the illustrated three-region fan-in ownership is
no longer guaranteed. See [`AXIOM.md`](AXIOM.md) section 12.

The same pipeline can be planned for the captured CloudLab d430 PCI
profile by swapping only `--hw` and `--bindings`:

```bash
kinetum_gluon --axiom examples/fan_in_edge_gateway/fan_in_edge_gateway.axiom.pbtxt \
              --hw   examples/fan_in_edge_gateway/hardware_inventory_cloudlab_d430.pbtxt \
              --bindings examples/fan_in_edge_gateway/fan_in_edge_gateway_cloudlab_d430_bindings.pbtxt \
              --regions 3 \
              --out  build/fan_in_pci_plan.pbtxt
```

The pipeline and config snapshots stay unchanged. Typed driver configuration
changes from TAP attachment to exact PCI BDF. Gluon resolves inventory MAC and
NUMA facts and writes them into `plan.ports[]`; queues, descriptor counts,
storage, execution, facilities, and transition facts remain explicit in their
own plan records. It does not synthesize EAL arguments.

## Part 5: Cross-Cutting

### 15. Axiom vs Gluon vs Runtime Responsibilities

| Concern                                       | Owner                       |
| --------------------------------------------- | --------------------------- |
| Pipeline graph shape (cycles, reachability, kinds) | Axiom                       |
| Typed stage configuration and edge-condition grammar | Axiom                     |
| Active / passive stage rules                       | Axiom                       |
| Current executable stage-kind closure                      | **Axiom** validates the closed kind set; Gluon consumes that admitted result |
| Region partitioning (which logical stages remain together) | **Gluon**             |
| Cross-worker `BoundaryPlacement` declarations      | **Gluon** (exact deterministic emission) |
| Fan-in inbound-boundary ownership                  | **Gluon** placement + shared transition compiler |
| Provider `Any` role and canonical payload          | Pure provider catalog, consumed by **Gluon** |
| Provider/facility/port/queue/stage binding coverage | **Gluon** authoring ladder |
| Active-stage origin storage binding                 | **Gluon** exact active-stage/lane coverage + shared provider compiler access/budget proof |
| Typed attachment-to-hardware resolution            | **Gluon**                   |
| Resolved runtime port metadata (driver identity, direction, MAC) | **Gluon** |
| Complete provider/facility/access/transition semantics | Shared provider compiler |
| `worker_placements[].cpu_core_ids` selection (NUMA, physical/HT) | **Gluon**       |
| `runtime_service_placements[]` identity, CPU/NUMA, and command-capacity selection | **Gluon**       |
| Native facility arguments and device capability proof | Shared compiler requirements, exact component-phase proof, then materializer; never a Gluon CLI override |
| Determinism of placement and bindings              | **Gluon**                   |
| Plan-vs-host CPU/NUMA topology gate at startup     | DP passes its one compiled artifact to strict Quark runtime compatibility |
| DATA, CUT, ACK, source-role, and future-output storage materialization | Dataplane, exactly from compiled ownership |
| CUT drain, exact ACK handling, epoch transitions   | Dataplane + control plane   |
| Native device/queue/storage capability matching    | Exact provider host proof and materialization |
| Snapshot durability and transition orchestration   | Control plane               |
| Snapshot revalidation, preparation, activation, and retirement | Dataplane              |

### 16. Where to Go Next

| If you want to...                                | Read                                           |
| ------------------------------------------------ | ---------------------------------------------- |
| Author a pipeline                                | [`AXIOM.md`](AXIOM.md)                         |
| Run an end-to-end deployment                     | [`GETTING_STARTED.md`](GETTING_STARTED.md)     |
| Understand the supervisor and runtime gates      | [`PHOTON.md`](PHOTON.md)                       |
| Understand the dataplane that consumes the plan  | [`DATA_PLANE.md`](DATA_PLANE.md)                 |
| Understand the control plane, guardrails, rollback | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| Write a custom module                            | [`MODULE_SDK.md`](MODULE_SDK.md)               |
| See the planning algorithm sequence diagram      | [`diagrams/platform_architecture.md`](diagrams/platform_architecture.md) |
| Read the architectural overview                  | [`CONCEPTS.md`](CONCEPTS.md)                   |
