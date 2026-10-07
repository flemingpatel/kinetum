# Concepts

This guide introduces the concepts and terminology used throughout Kinetum's
documentation. It is intended for developers and operators who want to
understand the architecture before defining a pipeline, preparing a deployment,
or writing a module. The linked component guides provide the detailed APIs,
configuration rules, and operating procedures.

## Deployment Model

| Concern        | Owner                                       |
| -------------- | ------------------------------------------- |
| What to do     | Pipeline definition (`.axiom.pbtxt`)        |
| Where to run   | Plan (`.plan.pbtxt`, produced by Gluon)     |
| Which deployment artifacts belong together | Verified plan/snapshot/module bundle (`kinetum_pack`) |
| Which platform artifacts ship together | Runtime package (runtime, components, inventory, private closure) |
| How to run     | Photon supervisor (`kinetum_photon`) over the verified bundle and CP/DP pair |
| When to change | Control plane (`kinetum_cp`) + snapshots    |

## Vocabulary

**Pipeline** - A directed graph of stages with at least one ingress (`RX`)
and one egress (`TX`). Defined in `proto/kinetum/axiom/v1/axiom.proto`
(`message Pipeline`).

**Stage** - One processing step. Each stage has a `stage_id` and a `kind`
(`STAGE_KIND_RX`, `STAGE_KIND_PARSE_IPV4`, `STAGE_KIND_MODULE`, or
`STAGE_KIND_TX`). `STAGE_KIND_MODULE` is the extension point: ACL, NAT, QoS,
and custom logic are modules. Its [execution mode](AXIOM.md#9-active-stages)
declares whether it can run from active triggers independently of packet arrival.

**Region** - Logical partition provenance: a group of stages that Gluon keeps
together for planning and aggregate telemetry. A region may contain multiple
lane-local runtime workers, but every worker in that region is placed on one
NUMA node.

**Runtime worker** - One schedulable packet owner for a region/lane slice.
`WorkerPlacement` gives it a stable ID, compact index, lane, region, and exact
CPU affinity. Packet-worker cores are distinct from control-service cores.
Its [loop is selected from the stages it owns](DATA_PLANE.md#stage-modes-and-worker-loops).

**Runtime service** - A plan-owned cold control role on cores distinct from
packet workers. Gluon assigns stable IDs and dedicated cores to one transition
coordinator and NUMA-local lifecycle executors. The coordinator orders DP
configuration transitions; executors perform module preparation and retirement.
[Data Plane threading](DATA_PLANE.md#4-threading-model) describes their mailbox,
ownership, and scheduling contracts.

**Plan** - The output of Gluon: logical regions, executable workers/lanes,
runtime services, process facilities, I/O drivers, packet-storage domains,
execution providers, exact ports/streams, storage transitions, and the exact
cross-worker **boundaries** the dataplane must set up.

**Process facility** - A generation-scoped process service required by one or
more providers, such as DPDK EAL. Its configuration and dependent instances are
explicit plan facts.

**I/O driver** - The provider role that owns native RX/TX endpoints and queue
transfer. It binds driver-local ports to native attachments and owns their
activation and deactivation.

**Packet-storage domain** - The owner of packet bytes and records. Its contract
declares access and allocation capabilities. RX chooses one allocation domain;
TX accepts a declared domain set. Each record retains its storage owner across
worker handoffs.

**Execution provider** - The owner of stage execution resources. CPU execution
is explicit; an absent provider is never interpreted as CPU.

**Active-origin binding** - The exact `(logical stage, lane, storage domain)`
authoring fact for a stage that originates packets without RX input. Every
active stage/lane has one row and every passive stage/lane has none.

**Active-stage limits** - Exact per-instance capacities authored on the logical
stage and replicated to every emitted lane: retained records, retained bytes,
owner-local timers, copied control messages, message payload bytes, foreign
token slots, and cancellation grace. The
[active-module contract](MODULE_SDK.md#16-active-modules) defines the handles,
callbacks, and ownership within those limits.

**Module-context resource binding** - The exact `(logical module stage, lane)`
authoring fact for lifecycle memory. It carries one nonzero context-lifetime
capacity and one nonzero per-epoch arena capacity. Gluon lowers these into each
stage instance; the lifecycle allocator enforces them.

**Storage transition** - One explicit mechanism between storage-domain facts:
zero-copy sharing or bounded copy. A bounded copy requires plan-owned staging
capacity and placement; no mode silently falls back to another.

**Provider contract catalog** - A pure immutable cold-path table keyed by the
complete protobuf type URL. It validates configuration and defines its role,
capabilities, dependencies, and host requirements without loading native code.

**Provider component** - One link-closed exact-release ELF image implementing
one or more provider contracts through the C11-compatible provider component
ABI. It exports `kinetum_provider_component_query`; native objects remain
inside the component.

**Installed provider inventory** - Canonical Ed25519-signed provenance for one
Kinetum installation, binding its runtime image, provider ABI, components, and
private dependencies.

**Release trust anchor** - The source-controlled Ed25519 public key used to
authenticate the installed provider inventory. Its private signing seed is
not part of the runtime package.

**Runtime provider catalog** - An immutable requested-only table assembled
after component authentication and admission. It exposes only the
implementations required by the compiled plan.

**Compiled provider topology** - The sole semantic artifact produced from the
canonical plan and pure contract catalog. It composes transition topology and
contains resolved instances, workers, routes, storage relationships, host
requirements, and resource budgets. Gluon self-checks through it; DP retains
the bundle verifier's compiled result and passes that same object to Quark.

**Boundary** - A handoff between two runtime workers, including lane-local
workers in the same region. DATA transfers packet-record ownership; separate
CUT and ACK lanes order configuration changes. The
[boundary protocol](#boundary-protocol) below explains their sequence and placement.

**Worker epoch activation** - One immutable owner-worker projection of exact
module stores and source-domain queue pairs. It validates the old state, then
activates module views, swaps queue roles, and promotes future work to the
active epoch in one bounded owner operation.

**Quiescence domain** - Tracks when every bound worker has finished reading old
configuration. The coordinator starts a grace generation; each worker reports
completion after its final old read. Missing publication delays reclamation.

**Transition certificate** - Evaluates coherent worker, boundary, and reader
publications against fixed membership. It establishes execution completion
and reclamation readiness without owning transition policy or retiring objects.

**Transition completion owner** - Coordinator-thread logic that uses the
certificate and reader grace to retire old module/snapshot objects and publish
the terminal transition result. [Data Plane](DATA_PLANE.md#12-cross-region-boundary-integration)
defines its ordering and timeout behavior.

**Worker epoch ledger** - The sole logical-work accounting authority for one
packet worker. RX/inbound admission and independent clones create credits under
the packet's immutable epoch; successful boundary transfer, TX acceptance, and
terminal disposition retire them. Local queue movement and storage conversion
preserve the credit. Logical work, queue slots, and physical storage capacity
remain separate counts.

**Runtime telemetry** - One shared
`proto/kinetum/telemetry/v1/telemetry.proto` contract consumed by both DP and
CP. Every successful observation carries runtime, engine, transition, and
protocol-fault summaries; selection flags add complete stage, module, health,
worker, region, boundary, stream, storage-domain, port, steering, and module-context
families. The generation-scoped source reads only completed banks and coherent
publications, invokes selected provider callbacks under an exact generation
claim with no platform lock held, and fences status before and after collection.
A transiently unavailable or crossing observation returns `UNAVAILABLE`; a
coherent identity contradiction or malformed producer returns `DATA_LOSS`.
Provider values carry exact, approximate, unsupported, or read-failed state,
so absent evidence is never represented by a numeric zero. The sticky protocol
fault latch is transition-safety authority observed by telemetry, not telemetry
policy.

**Epoch** - A nonzero monotonic configuration identity. Bootstrap activates one
exact epoch across every worker before provider ingress activates and packet
worker bodies are released. Every executing packet uses exactly its assigned
epoch's configuration; the live ordered-CUT protocol changes that identity
without forward or backward leakage.

**Snapshot** - A configuration state pushed to the running dataplane:
`message ConfigSnapshot` in `proto/kinetum/control/v1/control.proto`.
CP durably owns its identity and epoch. DP prepares and activates that authority;
CP publishes a live update as active only after the transition completes.

**Bundle** - A manifest-bound deployment directory produced by
`kinetum_pack`, containing the plan, bootstrap snapshot, and module artifacts.
Platform executables and providers come from the separately installed runtime.
[Kinetum Pack](KINETUM_PACK.md) defines the format and verification rules.

**Runtime payload manifest** - The sorted SHA-256 membership record at
`share/kinetum/release/runtime_payload_manifest.sha256`.
`kinetum-info --check` uses it to verify installed runtime membership and file
integrity. It is distinct from the signed provider inventory.

**Release and build ownership domains** - CMake stages two public products:
runtime and SDK. Runtime owns its root metadata and `bin/`, `lib/`, and
`share/` trees. SDK owns `sdk/`. The source-build dependency producer owns the
separate literal `dependencies/` peer, which is never a runtime input or
public archive member. Runtime replacement preserves the SDK and dependency
peers. [Getting Started](GETTING_STARTED.md#build-packages-from-source) owns
package production and installation; the documentation website is independent.

**Private validation kit** - Internal integration and CloudLab tooling staged
through its own CMake target, outside public runtime and SDK ownership. It
contains scripts, deployment inputs, and native traffic helpers. Live runs name
and verify a separate installed runtime; report generation can consume saved
evidence without one. See [Validation Guide](VALIDATION_GUIDE.md).

## Provider Authority Chain

The contract catalog defines meaning; the signed inventory authenticates
artifacts; the runtime catalog exposes the implementations required by the
plan. Startup checks these relationships before constructing native resources.
[Providers](PROVIDERS.md) follows the complete ABI and resource lifecycle;
the [architecture diagrams](diagrams/platform_architecture.md#3-providers-and-packet-storage)
show how the authorities and packet-storage owners connect.

## Components

| Component  | Responsibility                                                                             |
| ---------- | ------------------------------------------------------------------------------------------ |
| **Axiom**  | Validates the pipeline definition and derives canonical graph order. Rejects cycles, missing edges, and unsupported kinds. |
| **Gluon**  | Takes pipeline + hardware + complete deployment bindings; emits the deterministic provider graph and worker/service topology. |
| **Quark**  | Probes CPU/NUMA plus host-memory evidence and validates exact compiled worker, service, and memory requirements without republishing placement. |
| **Pack**   | Binds the plan, complete bootstrap snapshot, modules, and other artifacts into one verified bundle. |
| **Photon** | Admits the runtime bundle, launches `kinetum_dp` and `kinetum_cp`, and owns their lifecycle. |
| **DP**     | Owns dataplane execution, exact component admission and materialization, boundary rings, workers, and epoch advancement. |
| **CP**     | Validates and durably applies snapshots, exposes the gRPC API, and forwards telemetry only after exact DP application success. |
| **kinetumctl** | CLI client for the control plane (`set-config`, `stats`, `rollback`, etc.).            |

## End-to-End Flow

Axiom validates the pipeline; Gluon builds and checks its deployment plan.
Pack binds the plan, bootstrap snapshot, and modules into a verified bundle.
Photon verifies that bundle and starts DP. DP independently verifies it, passes
the compiled topology to Quark, then admits and constructs provider resources
before `CONTROL_READY`. Photon starts CP, which supplies durable bootstrap
authority. DP activates configuration and I/O before `PACKET_READY` releases
packet execution. The [end-to-end sequence](diagrams/platform_architecture.md#1-end-to-end-overview)
shows those owners and readiness gates together.

## Boundary Protocol

### Current ordered transition transport

Each cross-worker placement materializes three bounded lock-free lanes:

```{uml}
@startuml
skinparam linetype ortho
node "Sender worker A\nSender NUMA node" as S {
    component "DATA send\nTransfer packet records" as SD
    component "CUT send\nSeal old output at q" as SC
    queue "ACK ring\nCapacity 2; polled by A" as ACK
    card "N output hold\nOpen after ACK(N, q)\nHeld prefix before newer output" as HOLD
    SD -[hidden]down- SC
    SC -[hidden]down- ACK
    ACK -[hidden]down- HOLD
}
node "Receiver worker B\nReceiver NUMA node" as R {
    queue "DATA ring\nPlan-sized capacity; polled by B\nPointers only; endpoint sequence counters" as DATA
    queue "CUT ring\nCapacity 2; polled by B\nTarget N + final old DATA sequence q" as CUT
    component "ACK send\nDrain through q + retire local E work\nActivate N, echo (N, q)" as RA
    card "Fan-in rule\nEvery inbound CUT must be drained\nCUT arrival alone proves no DATA drain" as FANIN
    DATA -[hidden]down- CUT
    CUT -[hidden]down- RA
    RA -[hidden]down- FANIN
}
SD -right-> DATA
SC -right-> CUT
ACK <-right- RA
@enduml
```

Each ring lives on the NUMA node of its polling endpoint: DATA and CUT at the
receiver, ACK at the sender. Successful DATA transfers advance endpoint
sequences; receiver credit must exist before dequeue completion. Endpoints
publish coherent state once per turn.

Transition-enabled sources have equal-capacity active/future input queues;
each boundary also has a sender-local future-output hold. These are allocated
before launch. In IDLE, only active queues and DATA carry work. A committed
TRANSITION command opens the future roles and drives the handoff below.
Transition-disabled sources remain active-only.

Bootstrap prepares and activates epoch *E* for every exact module context,
waits for all workers to report `RUNNING` behind the closed body gate, activates
the complete provider-I/O set, publishes `PACKET_READY`, and only then releases
all workers into packet execution. RX stamps that same immutable epoch.
Shutdown closes worker source polling, drains local and boundary ownership,
propagates terminal sender closure through the worker DAG, joins workers,
deactivates provider I/O, and only then retires the published generation
artifacts and provider dependencies.

### Live ordered-CUT behavior

During a live transition, boundary-connected workers can reach the activation
point at different times. A packet processed
under epoch *E+1* in worker A must not arrive at worker B before B has applied
*E+1*; old epoch *E* work must also not execute after B activates *E+1*. The
final protocol composes three bounded channels over the same exact boundary
ownership:

```{uml}
@startuml
    participant "Sender worker A" as A
    participant "Receiver worker B" as B
    A->B: DATA(E), through successful enqueue sequence q
    A->B: CUT(E to N, q)
    note over A: Seal old output and hold future DATA(N)
    note over B: Drain DATA through q and all local E work\nAlign every inbound CUT and seal outbound old output
    B->B: Activate N and publish local activation
    B-->A: ACK(N, q)
    A->B: Release held DATA(N) in FIFO order
@enduml
```

- **DATA** preserves pointer ownership and successful enqueue/dequeue sequence.
- **CUT** carries a typed record positioned after the final successful old-epoch
  DATA enqueue.
- **ACK** echoes the exact activated epoch and consumed cut sequence.

CUT may arrive before old DATA drains. The receiver waits for every inbound
cut and all local old work before switching module views, queue roles, and
ledger in one bounded turn. It then ACKs, allowing the sender's held prefix to
resume in order.

Commit starts reader grace before publishing the immutable worker command.
The global certificate proves handoff completion; reader grace protects old
objects until reclamation. Activate retains its caller through COMPLETE or a
typed grace timeout that freezes updates with old objects retained. A
COMMITTING timeout or uncertainty after ownership withdrawal is fail-stop.

[`diagrams/ordered_cut_boundary_protocol.md`](diagrams/ordered_cut_boundary_protocol.md)
traces the live protocol and uses an epoch-only marker as a negative proof. A
marker without a DATA sequence cut cannot establish old-data drain and does not
satisfy the runtime contract.

## Where to Go Next

| If you want to...                                     | Read                                                       |
| --------------------------------------------------- | ---------------------------------------------------------- |
| Run the platform end-to-end                         | [`GETTING_STARTED.md`](GETTING_STARTED.md)                 |
| Author a pipeline                                   | [`AXIOM.md`](AXIOM.md)                                     |
| Understand planning                                 | [`GLUON.md`](GLUON.md)                                     |
| Understand provider contracts and integration       | [`PROVIDERS.md`](PROVIDERS.md)                             |
| Understand strict host evidence and compatibility   | [`QUARK.md`](QUARK.md)                                     |
| Understand the dataplane runtime                    | [`DATA_PLANE.md`](DATA_PLANE.md)                             |
| Understand the control plane, guardrails, rollback   | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| Write a custom module                               | [`MODULE_SDK.md`](MODULE_SDK.md)                           |
| Use the gRPC API directly                           | [`GRPC_API.md`](GRPC_API.md)                               |
| Use `kinetumctl`                                    | [`KINETUMCTL.md`](KINETUMCTL.md)                           |
| Bundle deployments                                  | [`KINETUM_PACK.md`](KINETUM_PACK.md)                       |
| See the runtime in motion                           | [`diagrams/README.md`](diagrams/README.md)                 |
