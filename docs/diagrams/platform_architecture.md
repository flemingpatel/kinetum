# Platform Architecture

Follow Kinetum 0.1.0 from pipeline authoring to packet processing, configuration
changes, and shutdown. Diagrams show ownership and event order; component guides
own APIs, schemas, limits, and error tables. Source anchors identify each
implementation.

Read [`CONCEPTS.md`](../CONCEPTS.md) first if the platform vocabulary is new.
For the boundary proof in depth, use
[`ordered_cut_boundary_protocol.md`](ordered_cut_boundary_protocol.md).

## Reading Order

1. [End-to-end overview](#1-end-to-end-overview)
2. [Gluon planning](#2-gluon-planning)
3. [Providers and packet storage](#3-providers-and-packet-storage)
4. [Execution lanes and RSS](#4-execution-lanes-and-rss)
5. [Photon supervision](#5-photon-supervision)
6. [Control plane](#6-control-plane)
7. [Transition RPC boundary](#7-transition-rpc-boundary)
8. [Configuration publication](#8-configuration-publication)
9. [Guardrails and rollback](#9-guardrails-and-rollback)
10. [Module lifecycle](#10-module-lifecycle)
11. [Data-plane host](#11-data-plane-host)
12. [Worker hot path](#12-worker-hot-path)
13. [Packet lifecycle](#13-packet-lifecycle)

## 1. End-to-End Overview

This sequence follows the canonical `examples/fan_in_edge_gateway/` deployment
with three regions and one lane. W0 owns `rx0/parse0/acl0`, W1 owns
`rx1/parse1/acl1`, and W2 owns NAT44, QoS, and TX. Both boundaries converge on W2;
all three workers use `storage_dpdk_0`. The coordinator and lifecycle executor
have separate cores.
The runtime is already installed, the CP store starts empty, and shutdown begins
from clean IDLE. E is the bootstrap epoch; N is the next configuration epoch.

```{uml}
@startuml
skinparam linetype ortho
queue "wan0 / RX queue 0" as WAN0
queue "wan1 / RX queue 0" as WAN1
node "W0 / region 0 / lane_0" as W0 {
    component "rx0" as RX0
    component "parse0 -> ACL0" as INPUT0
    RX0 --> INPUT0
}
node "W1 / region 1 / lane_0" as W1 {
    component "rx1" as RX1
    component "parse1 -> ACL1" as INPUT1
    RX1 --> INPUT1
}
node "W2 / region 2 / lane_0" as W2 {
    queue "DATA B0\nfrom W0" as B0
    queue "DATA B1\nfrom W1" as B1
    component "NAT44 -> QoS" as MODULES
    component "tx" as TX
    B0 --> MODULES
    B1 --> MODULES
    MODULES --> TX
}
storage "storage_dpdk_0\nShared packet records and payloads" as STORAGE
queue "lan0 / TX queue 0" as LAN
WAN0 --> RX0
WAN1 --> RX1
INPUT0 --> B0
INPUT1 --> B1
TX --> LAN
STORAGE .. W0
STORAGE .. W1
STORAGE .. W2
note bottom of STORAGE
  RX allocates from this domain.
  Boundaries transfer the original record.
  TX accepts it with the same storage owner.
end note
@enduml
```

The same participants remain visible from bundle creation through shutdown.
Workers observe commands independently; their order below is one possible
execution, not a global worker barrier. The packet example follows a permitted
record; [Section 13](#13-packet-lifecycle) expands drops and backpressure.

```{uml}
@startuml
    autonumber
    participant "Operator" as O
    participant "Bundle producer" as PK
    participant "Photon" as PH
    participant "CP writer / store" as CP
    participant "DP coordinator / completion" as DP
    participant "Lifecycle executor" as L
    participant "Provider generation" as PR
    participant "wan0 RX queue 0" as RX0
    participant "W0 / rx0 - parse0 - ACL0" as W0
    participant "Boundary B0 / W0 to W2" as B0
    participant "wan1 RX queue 0" as RX1
    participant "W1 / rx1 - parse1 - ACL1" as W1
    participant "Boundary B1 / W1 to W2" as B1
    participant "W2 / NAT44 - QoS - TX" as W2
    participant "lan0 TX queue 0" as TX
    participant "storage_dpdk_0" as S

    note over O,S: BUILD THE BUNDLE
    O->PK: pipeline + hardware + bindings + bootstrap snapshot
    PK->PK: validate Axiom and resolve module images
    PK->PK: Gluon placement and provider-graph compilation
    PK->PK: canonical plan/snapshot, module files, and manifest
    PK->PK: verify completed bundle
    PK-->O: verified bundle

    note over O,S: START THE SUPERVISED PAIR
    O->PH: bundle + durable CP-store path
    PH->PH: admit sibling images, signals, logging, and bundle
    PH->DP: spawn with verified bundle root
    DP->DP: block termination/reopen signals and create control event loop
    DP->DP: independently verify bundle and retain compiled topology
    DP->DP: Quark proves CPU, NUMA, and memory requirements
    DP->DP: admit logging, native capture, and TLS
    DP->PR: authenticate and load required provider components
    PR-->DP: sealed component catalog
    DP->DP: create coordinator, module contexts, INIT, lifecycle owners
    DP->PR: materialize facilities, storage, cold I/O, execution, transitions
    PR->S: allocate bounded packet storage
    PR->RX0: configure queue with ingress disabled
    PR->RX1: configure queue with ingress disabled
    PR->TX: configure queue and accepted storage set
    PR-->DP: complete provider generation
    DP->DP: construct worker kernels, queues, boundaries, and telemetry
    DP->DP: start cold services and publish CONTROL_READY
    PH->DP: bounded Health polling
    DP-->PH: CONTROL_READY with admitted runtime identity
    PH->CP: spawn with verified snapshot path and plan hash

    note over O,S: BOOTSTRAP EPOCH E
    CP->CP: admit startup files, signals, logging, and durable store
    CP->DP: Health before fresh import
    DP-->CP: CONTROL_READY
    CP->CP: persist Bootstrap content, epoch E, and allocator watermarks
    CP->DP: Bootstrap exact durable request
    DP->DP: validate identity and stage snapshot
    DP->L: PREPARE every module context at E
    L-->DP: prepared tokens and immutable views
    DP->W0: launch behind gate, bind source and ACTIVATE ACL0 at E
    DP->W1: launch behind gate, bind source and ACTIVATE ACL1 at E
    DP->W2: launch behind gate, ACTIVATE NAT44 and QoS at E
    W0-->DP: activated
    W1-->DP: activated
    W2-->DP: activated
    DP->DP: commit snapshot, allocator, and runtime-status publication
    W0-->DP: RUNNING with packet body blocked
    W1-->DP: RUNNING with packet body blocked
    W2-->DP: RUNNING with packet body blocked
    DP->PR: activate complete driver set
    PR-->DP: ingress activated
    DP->DP: publish PACKET_READY
    DP->W0: release packet body
    DP->W1: release packet body
    DP->W2: release packet body
    DP-->CP: Bootstrap COMPLETE with restored identity
    CP->CP: start mutation worker, guardrails, and RPC service
    PH->DP: bounded Health polling
    DP-->PH: PACKET_READY with same runtime identity
    PH->PH: supervise pair

    note over O,S: FORWARD A WAN0 PACKET AT EPOCH E
    W0->W0: reserve local queue capacity
    W0->RX0: receive bounded burst
    RX0-->W0: record P backed by storage_dpdk_0
    W0->W0: stamp E, ingress, time, and stage\nacquire E credit and stage P
    W0->W0: execute RX and parse0, batch ACL0 against view E\nselect NAT owner before the exact SHARE handoff
    W0->B0: enqueue P to DATA
    B0-->W0: accepted, enqueue sequence advanced
    W0->W0: retire sender credit and queue reservation
    note over B0: DATA ring owns P between workers
    W2->B0: peek P
    W2->W2: validate epoch, endpoint, domain\nreserve local queue capacity
    W2->B0: pop exact P
    B0-->W2: transfer P
    W2->W2: acquire E credit, then complete DATA dequeue sequence
    W2->W2: batch NAT44, then QoS, against exact view E\nresolve TX and retain original owner, length, epoch
    W2->TX: submit records in order
    TX-->W2: accepted prefix
    W2->W2: retire accepted credits and queue reservations
    TX->S: reclaim original storage after native completion or teardown
    opt Concurrent wan1 traffic
        W1->RX1: reserve capacity and receive bounded burst
        RX1-->W1: record Q backed by the same domain
        W1->W1: stamp E and acquire local credit\nexecute RX, parse1, and ACL1; select NAT owner
        W1->B1: transfer Q, then retire sender credit
        W2->B1: reserve, pop Q, acquire credit, complete dequeue
        W2->W2: same NAT44 / QoS / TX path
    end
    note over RX0,S: Each boundary preserves the original record and storage owner\nTX acceptance transfers ownership; external observation proves delivery

    note over O,S: PREPARE CONFIGURATION N WHILE E TRAFFIC CONTINUES
    O->CP: set-config with retained retry key
    CP->CP: canonicalize and durably allocate N and mutation identity
    CP->DP: Status, then Prepare for that identity
    DP->L: PREPARE all N artifacts off-worker
    L-->DP: complete prepared tokens
    DP->DP: preflight every post-commit resource
    DP-->CP: PREPARED, hash, and lease
    CP->CP: persist PREPARED, then COMPLETION_PENDING
    CP->DP: Activate exact identity
    DP->DP: start reader grace, enter COMMITTING\npublish immutable TRANSITION command

    note over O,S: DRAIN BOTH E INPUTS, ACTIVATE N, AND ACKNOWLEDGE BOTH CUTS
    W0->W0: acquire-observe command at turn boundary\nstamp new RX as N and hold it in future input queue
    W0->B0: finish E DATA through final enqueue sequence q0
    W0->W0: require zero old local credit and seal outbound
    W0->B0: publish CUT(N, q0)
    W0->W0: ACTIVATE ACL0 at N, switch banks/queues, promote ledger\npublish activation and reader safe point
    W1->W1: independently observe command\nstamp new RX as N and stage future input
    W1->B1: finish E DATA through final enqueue sequence q1
    W1->W1: require zero old local credit and seal outbound
    W1->B1: publish CUT(N, q1)
    W1->W1: ACTIVATE ACL1 at N, switch banks/queues, promote ledger\npublish activation and reader safe point
    note over W0,B1: Each sender holds its N output until its own exact ACK
    W2->W2: acquire-observe the same command
    W2->B0: consume CUT(N, q0) and drain E DATA through q0
    W2->B1: consume CUT(N, q1) and drain E DATA through q1
    W2->W2: require both cuts drained and all local E work retired\nACTIVATE NAT44 and QoS once at N\npublish views, banks, ledger, activation, and receiver state
    W2->B0: publish ACK(N, q0)
    W2->B1: publish ACK(N, q1)
    W2->W2: publish reader safe point
    W0->B0: consume ACK(N, q0), send held N prefix before newer output
    W1->B1: consume ACK(N, q1), send held N prefix before newer output
    B0-->W2: N records from wan0 may execute
    B1-->W2: N records from wan1 may execute

    note over O,S: RETIRE E AND COMPLETE THE UPDATE
    DP->DP: prove worker and boundary completion\npublish target runtime/configuration and enter RETIRING
    DP->DP: require every reader safe point and final E telemetry
    DP->L: withdraw checked claims and RETIRE old artifacts
    L-->DP: exact retirement results
    DP->DP: retire E snapshot, finish grace\npublish COMPLETE, then IDLE
    DP-->CP: terminal result for retained identity
    CP->CP: durably promote N and publish active content
    CP-->O: applied snapshot, revision, and epoch
    note over W0,W2: N packet work continues during cold retirement

    note over O,S: SHUT DOWN FROM CLEAN IDLE
    O->PH: SIGTERM
    PH->CP: SIGTERM
    CP->CP: close RPCs, join guardrails/mutation worker, drain logging
    CP-->PH: exit, then Photon reaps CP
    PH->DP: SIGTERM
    DP->DP: close command/RPC admission and publish STOP
    W0->W0: stop RX, drain local work, close outbound producer\nflush final output and telemetry
    W1->W1: stop RX, drain local work, close outbound producer\nflush final output and telemetry
    W2->B0: drain DATA until W0 sender is closed
    W2->B1: drain DATA until W1 sender is closed
    W2->W2: finish all local work
    W2->TX: final TX flush
    W2->W2: publish final telemetry
    W0-->DP: exit
    W1-->DP: exit
    W2-->DP: exit
    DP->DP: join all three workers
    DP->PR: deactivate driver set in reverse order
    DP->L: RETIRE remaining published artifacts
    L-->DP: retirement complete
    DP->DP: retire snapshot and join lifecycle services\ndestroy kernels/boundaries, FINI contexts, unload modules
    DP->PR: retire instances and their dependencies
    PR->S: release packet-storage backing
    PR-->DP: storage, facilities, and components retired
    DP->DP: retire native emitters and join logging writer
    DP-->PH: exit, then Photon reaps DP
    PH-->O: retire own logging and exit
@enduml
```

Photon and DP verify the bundle independently. CP owns durable configuration;
DP owns packet execution; Photon owns process supervision. A pair restart
repeats the same readiness gates after stopping CP before DP. Photon uses its
configured plaintext endpoints, with loopback defaults; direct CP/DP launch
exposes the documented TLS options.

### End-to-end source anchors and detail

`src/pack/runtime_bundle.cpp::verify_runtime_bundle`,
`src/photon/startup.cpp::start_supervised_children`,
`src/dp/partitioned_runtime.cpp::partitioned_runtime::create`,
`src/cp/dataplane_bootstrap.cpp::bootstrap_dataplane_from_store`,
`src/dp/packet_worker_kernel.cpp`, and
`src/dp/epoch/epoch_transition_completion.cpp` own this sequence. See
[`PHOTON.md`](../PHOTON.md), [`DATA_PLANE.md`](../DATA_PLANE.md), and
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](../CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md).

## 2. Gluon Planning

Gluon lowers a validated Axiom pipeline, a hardware inventory, and complete
deployment bindings into one deterministic `DeploymentPlan`. It resolves the
graph, placement, providers, storage, and resource limits before runtime.
Workers consume compiled indices and operation tables without topology search.

### Gluon planning authorities

| Input or stage | Authority |
|----------------|-----------|
| Pipeline graph and stage policy | Axiom `Pipeline`. |
| Physical facts | `HardwareInventory`; unknown facts remain unknown. |
| Provider and lane intent | `DeploymentBindings`; no runtime default completes it. |
| Graph order | Deterministic topological sort. |
| Region assignment | Sole linear-DP partitioner plus explicit pins and affinity relations. |
| Executable closure | Shared provider-topology compiler. |
| Plan identity | Canonical provider-aware deterministic serialization and SHA-256. |

### Gluon planning flow

```{uml}
@startuml
skinparam linetype ortho
left to right direction
package "Authored deployment" {
    artifact "Pipeline\nDAG, kinds, modes, pins, affinity" as PIPE
    artifact "DeploymentBindings\nProvider instances + typed configs\nPorts, queues, storage, lanes\nExecution and memory bounds" as BIND
    artifact "HardwareInventory\nOne host\nCPU / NUMA / PCI facts" as HW
    PIPE -[hidden]left-> BIND
    BIND -[hidden]left-> HW
}

package "Gluon planner" {
    component LOGICAL [
      Logical graph
      ----
      Axiom validates the pipeline contract
      Unknown fields / enums and invalid options reject
      Smallest-ready stage ID orders the DAG
      Resolve RX/TX pins and normalize affinity relations
      Linear DP minimizes maximum region weight
      Affinity, anti-affinity, PULL/control checks close it
    ]
    component EXECUTABLE [
      Executable topology
      ----
      Lower complete bindings and canonical provider configs
      Resolve lanes, stage instances, contexts, and streams
      Place packet workers and cold services on disjoint cores
      Prove exact NUMA placement
      Derive cross-worker boundaries from endpoint ownership
      Emit DATA / future-hold capacity and transition policy
    ]
    LOGICAL -left-> EXECUTABLE
}

package "Shared compilation and publication" {
    component "Provider-topology compiler\nContracts, dependencies, access\nSteering, context domains, buffer floors" as PROVE
    artifact PLAN [
      DeploymentPlan
      ----
      Logical regions and stage membership
      Providers, storage, streams, lanes, contexts
      Workers, services, and exact boundaries
      ----
      Structural hash -> plan_id
      Complete stable plan -> content hash
      Planner timing remains volatile metadata
    ]
    PROVE -left-> PLAN
}

PIPE --> LOGICAL
BIND --> LOGICAL
HW --> LOGICAL
BIND --> EXECUTABLE
HW --> EXECUTABLE
EXECUTABLE --> PROVE
@enduml
```

Any failed step returns an error without publishing a plan. Native host and
device proofs occur later at their owning runtime boundaries.

### Gluon planning cross-component invariants

- Every executable stage, provider role, port, queue, storage domain, module
  context, boundary, and worker appears in both directions of its owning
  relation.
- Hardware planning facts belong to one node with explicit selectable CPU rows
  and exact referenced DPDK PCI facts; no count or extra host record is merged.
- Region workers are NUMA coherent; packet workers and runtime-service cores
  are pairwise disjoint.
- Cross-worker boundaries derive from exact stage-instance ownership, not from
  logical-region guesses.
- Active-stage capacities, transition capacities, module memory, and telemetry
  cadence are explicit plan facts; zero never asks the runtime for a default.
- Gluon submits its completed candidate to the same provider compiler consumed
  by DP before publishing plan identity.
- Stable arrays are order-contractual unless their schema explicitly owns
  canonical set normalization.

Canonical topological sorting is `O(E + V log V)` because its ready set is
ordered. The linear dynamic partitioner is `O(n^2 r)`. Reachable storage-domain
closure is a finite monotone fixed point over the declared graph, not path
enumeration.

### Gluon planning source anchors and detail

`src/gluon/gluon_planner.cpp::plan_impl`,
`src/gluon/deployment_bindings_lowering.cpp`,
`src/gluon/runtime_core_placement.cpp`,
`src/gluon/boundary_topology_lowering.cpp`,
`src/gluon/transition_plan_lowering.cpp`,
`src/provider/compiled_provider_topology.cpp::compile_provider_topology`, and
`src/provider/deployment_plan_identity.cpp`. See [`GLUON.md`](../GLUON.md),
[`AXIOM.md`](../AXIOM.md), and [`QUARK.md`](../QUARK.md).

## 3. Providers and Packet Storage

The plan separates process facilities, I/O drivers, packet-storage domains,
execution providers, and storage transitions. Drivers transfer packets; storage
owns their records and bytes. The CPU execution provider binds an execution
identity and storage-access proof; packet workers run stages. A component may
implement several roles, each with its own configuration. Native types stay
inside that component. Changing workers does not change storage; a domain
change requires an authored transition.

### Provider authority chain

```{uml}
@startuml
box "Release production"
    participant "Native preparation" as P
    participant "Signing finalizer" as S
end box
collections "Installed release\ninventory + artifacts" as I
box "Runtime admission"
    participant "DP / pure contract compiler" as D
    participant "Provider loader" as L
    participant "Sealed implementation catalog" as C
end box

group Prepare the declared native release aggregate
    P->P: reconstruct canonical inventory and private dependency closure
    P->P: perform native component self-admission
    P-->S: candidate + deterministic unsigned native receipt
end
group Independently verify and sign
    S->S: reconstruct artifacts, ELF closure, runtime binding, and inventory
    S->S: require byte-exact agreement with the additive receipt
    S->S: retire archive decoder before opening the protected seed
    S->S: require the matching source-controlled public anchor
    S->I: canonical inventory + detached Ed25519 signature
    note over S,I: Receipt is not a signature; inventory signature binds the exact runtime and provider closure
end
group Admit only providers required by the plan
    D->D: pure catalog validates, normalizes, and projects typed configurations
    D->L: compiled required-contract set + exact runtime image + public anchor
    L->I: hold inventory and signature bytes
    L->L: authenticate before parsing inventory metadata
    L->I: hold and hash exact ELF / private dependency files
    L->L: validate identity and complete private closure with libelf
    L->L: load verified dependencies and requested components
    L->C: publish only the admitted requested implementations
    C-->D: sealed catalog for transactional materialization
end
note over I,C: Archive / installer trust still comes from the release channel; the inventory does not authenticate its own verifier
@enduml
```

### Provider admission and runtime roles

```{uml}
@startuml
title From bindings to a materialized provider generation\nSingle-lane PCI fan-in with shared packet storage
skinparam linetype ortho

rectangle "Deployment planning" as PLAN {
    object "Gluon" as GLUON {
        inputs = pipeline + hardware + bindings
        resolves = instances, ports, queues, storage
        proves = access, placement, capacity
        output = canonical deployment plan
    }
}

rectangle "DP startup" as STARTUP {
    object "Provider materializer" as MATERIALIZER {
        input = compiled topology from bundle verification
        requires = admitted components + host proofs
        calls = C ABI factories in order 1 through 5
        checks = instance + operations + destroy callback
    }
}

GLUON -right-> MATERIALIZER

package "DPDK component" as DPDK {
    object "1. Process facility\nfacility_dpdk_0" as FACILITY {
        contract = DpdkFacilityConfig
        creates = EAL process environment
        exposes = worker registration + service lifecycle
    }
    object "2. Packet storage\nstorage_dpdk_0" as STORAGE {
        contract = DpdkStorageConfig
        uses = facility_dpdk_0
        creates = one mbuf pool, 131071 buffers
        exposes = acquire, clone, originate, release
    }
    object "3. I/O driver\nio_dpdk_0" as DRIVER {
        contract = DpdkDriverConfig
        uses = facility_dpdk_0 + storage_dpdk_0
        native path = DPDK ethdev + device PMD
        configures = wan0 RX0, wan1 RX0, lan0 TX0
        descriptors = 1024 per queue
        exposes = RX/TX burst + driver lifecycle
    }
    FACILITY -[hidden]down-> STORAGE
    STORAGE -[hidden]down-> DRIVER
}

package "Host component" as HOST {
    object "4. CPU execution\nexecution_cpu_0" as EXECUTION {
        contract = CpuExecutionConfig
        uses = storage_dpdk_0
        creates = execution identity + CPU access record
        validates = contiguous packet read/write access
    }
    object "5. Storage transitions\nacl0 to nat / acl1 to nat" as TRANSITIONS {
        contract = ZeroCopyShareConfig
        uses = storage_dpdk_0 on both sides
        creates = two transfer operations
        packet backing = same domain, no payload copy
    }
    EXECUTION -[hidden]down-> TRANSITIONS
}

MATERIALIZER -down-> FACILITY
MATERIALIZER -down-> EXECUTION
FACILITY -[hidden]right-> EXECUTION
STORAGE -[hidden]right-> TRANSITIONS

object "Complete provider generation" as GENERATION {
    owns = all instances and their dependency lifetimes
    resolves = compiled streams to RX/TX operation tables
    publishes = only after every factory and validation succeeds
    next = DP constructs workers, boundaries and module bindings
    activation = exact bootstrap, then driver activation and packet release
}

DRIVER -down-> GENERATION
TRANSITIONS -down-> GENERATION

legend bottom left
  Each numbered card connects the binding ID and configuration type to its constructed resource.
  Host and DPDK cooperate in this deployment. HostStorageConfig is not selected: there is no Host packet pool.
  Driver construction configures ports and queues; packet I/O is activated later by DP bootstrap.
endlegend
@enduml
```

The host component also implements host packet storage and bounded-copy
transitions; the UDP component supplies UDP I/O. These
[contracts](../PROVIDERS.md#3-typed-configuration) are selected explicitly.
Workers use resolved operation tables without component discovery.

### RX allocation, shared TX, and reclamation

The canonical d430 shared-storage and per-RX-queue bindings keep the same worker
graph. Their storage bindings select each RX queue's pool and the domains
accepted by TX.

```{uml}
@startuml
title Change storage bindings, keep the worker graph
skinparam linetype ortho

frame "Shared RX storage" as SHARED {
    storage "S: storage_dpdk_0\n131071 buffers" as S
    node "W0 / region 0 / lane_0\nwan0 RX q0\nrx0 -> parse0 -> acl0" as SA
    node "W1 / region 1 / lane_0\nwan1 RX q0\nrx1 -> parse1 -> acl1" as SB
    node "W2 / region 2 / lane_0\nNAT -> QoS -> TX\nlan0 TX q0 accepts {S}" as SJ
    S .down.> SA : allocate S
    S .down.> SB : allocate S
    SA -down-> SJ : record in S
    SB -down-> SJ : record in S
    SA -[hidden]right-> SB
}

frame "One pool per RX queue" as SPLIT {
    storage "A: storage_wan0_q0\n65535 buffers" as A
    storage "B: storage_wan1_q0\n65535 buffers" as B
    node "W0 / region 0 / lane_0\nwan0 RX q0\nrx0 -> parse0 -> acl0" as PA
    node "W1 / region 1 / lane_0\nwan1 RX q0\nrx1 -> parse1 -> acl1" as PB
    node "W2 / region 2 / lane_0\nNAT -> QoS -> TX\nlan0 TX q0 accepts {A, B}" as PJ
    A .down.> PA : allocate A
    B .down.> PB : allocate B
    PA -down-> PJ : record in A
    PB -down-> PJ : record in B
    A -[hidden]right-> B
    PA -[hidden]right-> PB
}

SHARED -[hidden]right-> SPLIT

legend bottom left
  Both plans: 3 packet workers, 2 boundaries, 2 RX queues, 1 TX queue.
  Solid arrows: DATA handoffs, with CUT forward and ACK back at transitions.
  Dotted arrows: RX allocation. Both plans use explicit zero-copy sharing.
  TX completion returns each buffer to its original pool; no TX-only pool.
endlegend
@enduml
```

The sequence follows the per-RX-queue case through TX acceptance and reclamation.

```{uml}
@startuml
participant "Ingress worker A" as A
participant "Ingress worker B" as B
queue "DATA boundaries" as D
participant "Join / TX worker" as W
participant "I/O provider" as P
collections "Original storage domains\nA and B" as S

A->P: receive from wan0 RX queue 0
P-->A: transfer record P backed by domain A
B->P: receive from wan1 RX queue 0
P-->B: transfer record Q backed by domain B
note over P,S: Each RX queue uses its configured allocation domain
A->D: transfer P without changing its domain
B->D: transfer Q without changing its domain
D-->W: P(A), Q(B) retain their original storage owners
W->W: process records under the exact epoch view
W->W: resolve one TX stream accepting {A, B}
W->W: append in stream order; save each record's original facts
W->P: one bounded mixed-domain TX burst
note over W,P: No sorting by pool, no split burst, no TX-only allocation
opt Native completion inside the provider call
    P->S: reclaim completed accepted records through their original domains
end
P-->W: accepted prefix length
W->W: count accepted transfers from saved facts\nretire accepted worker credits
opt Unaccepted suffix
    W->S: retire rejected records through their original domains
end
opt Accepted backing remains provider-owned
    P->S: later native completion or teardown returns remaining records\nto their original domains
end
note over W,S: Acceptance is an ownership transfer. External observation alone proves wire delivery.
@enduml
```

The arrows describe ownership, not wire-delivery acknowledgements. TX acceptance
retires the worker's logical credit; external observation proves delivery.
Storage ownership remains attached to each record even in a mixed-domain burst.

### Explicit storage conversion

```{uml}
@startuml
!pragma useVerticalIf on
start
:Resolve the packet-path edge
and original storage domain;
if (Authored zero-copy share?) then (yes)
    :Preserve record, bytes, domain,
    immutable epoch, and work credit;
elseif (Authored bounded copy?) then (yes)
    :Reserve destination record
    and compiled staging;
    if (Capacity available?) then (yes)
        :Copy bytes and metadata;
        :Transfer to the destination owner,
        then release source storage;
        :Preserve immutable epoch
        and one logical work credit;
    else (backpressure)
        :Caller keeps the record,
        reservation, and credit;
    endif
else (no conversion on the resolved TX edge)
    if (Original domain in TX accepted set?) then (yes)
        :Admit direct TX;
    else (no)
        :Stage drop;
        :Release through the original domain;
    endif
endif
stop
@enduml
```

An authored conversion takes precedence even if TX accepts the original domain.
Zero-copy sharing requires the same domain; bounded copy requires different
domains and explicit staging. The compiler checks declared access, domain
compatibility, NUMA requirements, and capacity. Quark and provider materialization
verify the host and native resources before workers launch. Each TX queue's
full descriptor population is charged to every accepted domain.

### Provider and storage source anchors and detail

`proto/kinetum/gluon/v1/bindings.proto::DriverQueueBinding`,
`proto/kinetum/gluon/v1/plan.proto::PacketStorageDomain`,
`src/provider/provider_contract_catalog.cpp`,
`src/provider/compiled_provider_topology.cpp::compile_provider_topology`,
`src/provider/provider_runtime_materialization.cpp`, and
`src/dp/packet_worker_kernel.cpp::deliver_tx_` own these relationships.
The single-lane examples use `fan_in_edge_gateway_cloudlab_d430_bindings.pbtxt`
and `fan_in_edge_gateway_cloudlab_d430_per_rx_queue_bindings.pbtxt` under
`examples/fan_in_edge_gateway/`.
[Providers](../PROVIDERS.md) owns the full ABI, admission, and resource-lifetime
contract; [Gluon](../GLUON.md#7-deployment-binding-resolution) owns the authored
bindings.

## 4. Execution Lanes and RSS

A logical region groups stages. A lane identifies one executable replica of
the pipeline across regions. Each region/lane slice has one packet worker and
its own stage instances, module contexts, queues, and CPU placement. Storage
may be shared across workers.

RSS selects an RX queue; the compiled stream binds it to a lane and worker.
Module-context selection then chooses the session owner independently of that
ingress lane. A selected PUSH edge can cross lanes through exact boundaries.

### From authored queues to executable ownership

```{uml}
@startuml
skinparam linetype ortho
object "Pipeline" as PIPE {
    stages and edges
}
object "Region partition" as REGION {
    complete stage-to-region assignment
}
object "Queue and steering bindings" as Q {
    driver / port / queue
    RSS fields and exact key
    RX allocation domain
    TX accepted-domain set
}
object "Execution lane" as LANE {
    replica identity across regions
    exact stage and stream membership
}
object "Stage instance" as STAGE {
    logical stage + lane
    execution provider
}
object "Packet worker" as WORKER {
    region + lane
    exact CPU + NUMA
}
object "Module context" as CONTEXT {
    one owner worker
    one stage instance
    module-scoped ordinal and population
    exact context / epoch memory bounds
}
object "Module context domain" as DOMAIN {
    one module configuration identity
    complete sorted context population
    fixed ordinals for the generation
}
object "I/O stream" as STREAM {
    driver / port / queue / direction
    lane and owner worker
    direction-specific storage contract
}
object "Boundary" as BOUND {
    exact stage-instance endpoint pair
    sender and receiver workers
    DATA / CUT / ACK ownership
}
PIPE --> REGION
REGION --> STAGE
Q --> LANE
Q --> STREAM
LANE --> STAGE
LANE --> STREAM
STAGE --> WORKER
STAGE --> CONTEXT
DOMAIN --> CONTEXT
WORKER --> CONTEXT
STREAM --> WORKER
WORKER --> BOUND
STAGE --> BOUND
note bottom of LANE
  Regions group logical stages.
  Lanes replicate execution across regions.
  Storage choice does not create a worker or a lane.
end note
@enduml
```

### Two RSS lanes through the fan-in gateway

The shipped d430 `rx-rss-2` profile has three regions and two lanes: six packet
workers, plus separately placed cold services. Each ingress contributes one
stream to each lane. Ingress workers own parsing and ACL. Each join worker owns
one NAT44 context followed by QoS and TX; every ACL context can select either NAT owner.

```{uml}
@startuml
skinparam linetype ortho
component "wan0\nRSS with authored key" as WAN0
component "wan1\nRSS with authored key" as WAN1
queue "wan0 RX q0" as Q00
queue "wan0 RX q1" as Q01
queue "wan1 RX q0" as Q10
queue "wan1 RX q1" as Q11
package "lane_0" {
    node "Region 0 worker\nrx0 -> parse0 -> ACL0" as R00
    node "Region 1 worker\nrx1 -> parse1 -> ACL1" as R10
    node "Region 2 worker" as J0 {
        component "NAT44 -> QoS -> TX\nNAT context ordinal 0" as BODY0
    }
    R00 --> J0
    R10 --> J0
}
package "lane_1" {
    node "Region 0 worker\nrx0 -> parse0 -> ACL0" as R01
    node "Region 1 worker\nrx1 -> parse1 -> ACL1" as R11
    node "Region 2 worker" as J1 {
        component "NAT44 -> QoS -> TX\nNAT context ordinal 1" as BODY1
    }
    R01 --> J1
    R11 --> J1
}
R00 --> J1
R10 --> J1
R01 --> J0
R11 --> J0
queue "lan0 TX q0" as TX0
queue "lan0 TX q1" as TX1
WAN0 --> Q00
WAN0 --> Q01
WAN1 --> Q10
WAN1 --> Q11
Q00 --> R00
Q10 --> R10
Q01 --> R01
Q11 --> R11
J0 --> TX0
J1 --> TX1
@enduml
```

The eight edges are permitted destinations, not packet fan-out. Each packet
selects one NAT context before its storage handoff. Each boundary also carries
CUT forward and ACK back. Both lanes share one global epoch transition, and
each NAT worker requires all four inbound cuts.
Replicated contexts never share mutable session or policer state.

### Queue storage is independent of lane replication

The shared-storage profile binds every stream to one domain. The per-queue
profile keeps the same six workers and eight boundaries but uses this mapping:

| Lane | wan0 RX allocation | wan1 RX allocation | lan0 TX accepted domains |
|------|--------------------|--------------------|--------------------------|
| `lane_0` | `storage_wan0_q0` | `storage_wan1_q0` | All four RX domains. |
| `lane_1` | `storage_wan0_q1` | `storage_wan1_q1` | All four RX domains. |

Each selected owner forwards original records through its NAT/QoS/TX chain without
payload conversion. Extra pools do not create workers, and extra lanes do not
implicitly create pools. Module images must admit replication; the planner and
provider gates prove the complete queue, steering, context, and storage mapping.

### Lane and RSS source anchors and detail

`proto/kinetum/gluon/v1/plan.proto::ExecutionLane`, `WorkerPlacement`,
`StageInstance`, `IoStream`, and `ModuleContextDomain`,
`src/gluon/deployment_bindings_lowering.cpp`, and
`src/provider/compiled_provider_topology.cpp` own lane expansion. The concrete
profiles are `fan_in_edge_gateway_cloudlab_d430_rx_rss_2_bindings.pbtxt` and
`fan_in_edge_gateway_cloudlab_d430_rx_rss_2_per_rx_queue_bindings.pbtxt` under
`examples/fan_in_edge_gateway/`. See
[`GLUON.md`](../GLUON.md#74-final-port-and-executable-topology),
[`MODULE_SDK.md`](../MODULE_SDK.md#session-ownership-across-ingress-queues), and
[`VALIDATION_GUIDE.md`](../VALIDATION_GUIDE.md#83-dpdkpcibackend).

## 5. Photon Supervision

Photon admits a bundle, resolves sibling DP/CP images from its Linux process
identity, and owns their startup, supervision, restart, and shutdown. Each
child validates its own state; Photon does not choose configuration or providers.

### Photon authorities and flow

```{uml}
@startuml
skinparam linetype ortho
skinparam nodesep 60
skinparam ranksep 60
state "Start one supervised pair" as STARTUP {
    state "Admit sibling images, bundle,\nsignals, logging, and native capture" as ADMIT
    state "Spawn DP\nStartup transaction owns it" as DP
    state "Wait for exact CONTROL_READY" as CONTROL
    CONTROL : STARTING / retryable transport: keep waiting
    state "Spawn CP\nVerified snapshot + plan hash + store" as CP
    state "Wait for exact PACKET_READY\nCheck both children and runtime identity" as PACKET
    PACKET : CONTROL_READY / retryable transport: keep waiting
    PACKET : Require the same runtime and worker population
    [*] --> ADMIT
    ADMIT --> DP
    DP --> CONTROL
    CONTROL --> CP : exact CONTROL_READY
    CP --> PACKET
}
state "Pair owner\nCheck children and wait for signal / interval" as RUNNING
RUNNING : SIGINT / SIGTERM or process-observation error: cleanup
state "Reopen own logs\nForward SIGUSR1 to both children" as REOPEN
state "Retain child status\nStop and reap the complete pair" as RETIRE
RETIRE : If cleanup fails, retain ownership
RETIRE : for the final cleanup attempt
RETIRE : Complete reap permits the restart decision
state RESTART <<choice>>
state "Terminate and reap owned CP before DP" as CLEAN
state REAP <<choice>>
state "Exit 0 for requested cancellation\nOtherwise exit 1" as EXIT
state "Fail stop with raw diagnostic" as FATAL
state "Exit 1" as FAIL

[*] --> STARTUP
PACKET ---> RUNNING : exact PACKET_READY
STARTUP --> CLEAN : spawn failure or gate error\nchild exit or cancellation\ndeadline expired
RUNNING --> REOPEN : SIGUSR1
REOPEN -[norank]-> RUNNING
RUNNING -right-> CLEAN
RUNNING --> RETIRE : observed child exit
RETIRE --> RESTART
RETIRE --> CLEAN
RESTART -[norank]left-> STARTUP : ON_FAILURE\nnonzero exit\nrestart budget\navailable
RESTART --> FAIL : otherwise
CLEAN --> REAP
REAP --> EXIT : final reap proven
REAP --> FATAL : unproved final reap
EXIT --> [*]
FAIL --> [*]
@enduml
```

Photon strips loader interposition variables from each child environment and
uses `posix_spawn` with absolute images. It passes no provider selector, EAL
command, loose plan, or module path. Each readiness gate has per-RPC and total
deadlines; unknown or regressing states fail it.

### Photon cross-component invariants

- `CONTROL_READY` starts CP; `PACKET_READY` starts steady pair
  ownership. Neither gate is inferred from time.
- Any incomplete startup cleans up CP before DP.
- A restart replaces the complete pair; CP is never restarted alone against an
  unowned live DP generation.
- A final unproved child reap terminates Photon rather than discarding process
  authority.
- The supervised child command has no TLS forwarding surface. Operators needing
  CP/DP TLS use direct process orchestration and the exact binary flags.

### Photon source anchors and detail

`src/photon/photon_main.cpp::main`,
`src/photon/startup.cpp::start_supervised_children`,
`src/photon/startup.cpp::supervised_pair_owner`,
`src/photon/readiness.cpp::wait_for_exact_readiness`,
and `src/photon/process.cpp`. See
[`PHOTON.md`](../PHOTON.md).

## 6. Control Plane

The control plane serializes configuration changes into one durable history.
gRPC threads validate and submit work; the control-loop thread updates the store
and calls DP. The guardrails thread observes telemetry and submits rollback
intent. Readers consume immutable publications. This ordering survives response
loss, restart, confirmation deadlines, and automatic rollback.

### Control-plane ownership layout

```{uml}
@startuml
title Control-plane ownership, durable files, and configuration checks
skinparam linetype ortho

package "Single-writer mutation path" {
    component "Mutation RPCs\nValidate before admission" as WRITE
    queue "64-cell request mailbox" as Q
    component LOOP [
      Control-loop thread
      ----
      set / rollback: canonical content,
      durable allocation, DP transition
      confirm: identity, key, deadline, first result
      policy: canonical hash + generation CAS
    ]
    component "Typed DP transition client\nPrepare / Activate / Abort / Status" as DP
    WRITE -right-> Q
    Q -right-> LOOP
    LOOP <-right-> DP
}

folder "Durable store / --config-store-dir" as FILES {
    artifact HEAD [
      TRANSITION_AUTHORITY.pb
      ----
      Binary protobuf; one mutable head
      active: full snapshot + epoch + plan hash
      epoch / mutation allocation watermarks
      current/latest transition: identity + phase
      pending confirm / guardrails policy / rollback intent
      ----
      Atomically replaced on each committed update
    ]
    artifact CORPUS [
      snap_<sha256(snapshot_id)>.pbtxt
      ----
      Immutable canonical snapshot corpus
      snapshot ID + revision + module configurations
      embedded content_hash verifies canonical content
      ----
      Create only; promotion never rewrites these files
    ]
    HEAD -[hidden]right-> CORPUS
}

package "Admitted in-memory state" {
    component STORE [
      config_store::runtime_authority()
      ----
      snapshot ID + revision + last COMPLETE epoch
      snapshot hash + plan hash + allocation watermarks
      optional retained transition identity
    ]
    component PUB [
      Control-loop publications
      ----
      Active snapshot ID + revision
      Versioned guardrails policy
    ]
    STORE -[hidden]right-> PUB
}

package "Read and guardrails paths" {
    component FENCE [
      CP / DP configuration check
      ----
      Read CP view -> DP telemetry -> read CP view
      Require unchanged CP active identity
      Check plan, completed epoch, snapshot hash,
      and the permitted watermark relationship
      ----
      CP changed during the read: UNAVAILABLE
      DP COMPLETE awaiting CP promotion: UNAVAILABLE
      Unexplained identity conflict: DATA_LOSS
    ]
    artifact "DP telemetry\nValidated complete observation" as TELEMETRY
    component "Read RPC responses\nSnapshot / policy / GetStats" as READ
    component "Guardrails runner / evaluator" as GUARD
    queue "One safety-intent borrow\nReturned to the control-loop writer" as INTENT
    FENCE -[hidden]right-> TELEMETRY
    READ -[hidden]right-> GUARD
    TELEMETRY -left-> FENCE
    FENCE -down-> READ : GetStats
    FENCE -down-> GUARD
    GUARD -down-> INTENT
}

LOOP -down-> HEAD
LOOP -down-> CORPUS
LOOP -down-> PUB
HEAD -down-> STORE
CORPUS -down-> STORE
STORE -down-> FENCE
PUB -down-> FENCE
PUB -down-> GUARD
STORE -[norank]left-> READ : snapshot / policy

legend bottom left
  .pb is binary protobuf; .pbtxt is protobuf text. The filename hash covers the snapshot ID only.
  Snapshot content_hash covers deterministic protobuf bytes with its own top-level hash field cleared.
  Persistence writes complete bytes, fsyncs the file, renames, and fsyncs the directory before updating memory.
  Stats reads the admitted in-memory view. Read RPCs bypass the mutation mailbox.
  Confirmation and policy changes allocate no DP epoch and make no DP mutation call.
  Accepted mutation requests remain owned until the control loop resolves them.
  Guardrails submits its safety intent to the same writer and retains the borrow until acknowledgement.
endlegend
@enduml
```

File formats, restart admission, and store APIs are detailed in
[Config Store](../CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md#8-config-store).

The mailbox holds up to 64 heap-owned request contexts. Full admission rejects
before mutation; cancellation leaves accepted contexts for the worker to drain
and destroy. The separate safety-intent channel borrows its caller's context
until durable acknowledgement.

### Control-plane mutation lifecycle

1. The handler validates unknown fields, enums, presence, identity, and command
   shape before queue publication.
2. The control loop applies the exact retry-key and expected-generation matrix.
3. A snapshot mutation publishes its durable allocation before any DP transition
   call; confirmation and policy mutations use their own exact store operation.
4. For snapshot changes, typed DP results and reconciliation determine the next
   durable state.
5. The loop persists terminal truth before completing the caller's result.
6. A durable safety intent is serviced after the owning mutation result and
   before another queued ordinary mutation can be dispatched.

### Control-plane cross-component invariants

- The control loop is the sole semantic and durable writer. Store transaction
  serialization does not create another authority.
- Mailbox synchronization ends before durable-store work or DP calls. Each
  filesystem-and-memory transaction stays coherent, and no platform
  synchronization owner crosses a module or provider callback.
- Successful ambiguous retries require the same key and canonical request
  identity; conflicts fail before another mutation.
- Ordinary RPC outcomes use the embedded application status. A final response
  representation failure returns transport `UNAVAILABLE` with no authoritative
  partial body; unexpected boundary exceptions terminate.
- `PACKET_READY` restart reconciliation validates active epoch, snapshot hash,
  plan hash, watermarks, and runtime generation. A fresh store cannot adopt a
  running DP.
- A mutation result names that completed operation. A later serialized
  rollback can replace active content; read RPCs report the current identity.

### Control-plane source anchors and detail

`src/cp/cp_main.cpp::main`, `src/cp/cp_grpc.cpp::control_service_impl`,
`src/cp/control_loop.cpp::control_loop`, `src/cp/config_store.cpp::config_store`,
`src/cp/runtime_authority_fence.cpp::classify_runtime_authority`,
`src/common/canonical_content_identity.cpp`, `src/common/durable_directory.cpp`,
`src/cp/transition_reconciliation.cpp`, and
`proto/kinetum/control/internal/v1/transition_authority.proto`. See
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](../CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md).

## 7. Transition RPC Boundary

Bootstrap restores durable active configuration before packet admission. Live
updates use Prepare, Activate, optional pre-commit Abort, and Status through one
plan-sized coordinator mailbox. Parsing, allocation, and preparation finish
before commit. After commit, DP must complete worker handoff and reclamation.

### Live transition RPC flow

```{uml}
@startuml
    autonumber
    participant "CP control loop" as CP
    participant "Durable authority" as Store
    participant "DP gRPC handler" as RPC
    participant "Coordinator mailbox" as Q
    participant "Coordinator / preparation / completion" as C
    participant "Lifecycle executors" as L
    participant "Packet workers W0, W1, W2" as W
    participant "Immutable owner publications" as P

    CP->Store: allocate epoch and mutation identity
    CP->RPC: Status for the retained exact identity
    RPC-->CP: UNKNOWN_FUTURE for a new allocation
    CP->RPC: Prepare(snapshot, epoch, key, mutation)
    RPC->RPC: reject malformed envelope and canonicalize candidate
    RPC->Q: enqueue fixed kind plus context pointer
    note over RPC,Q: Successful enqueue borrows caller context until completion
    Q->C: sole consumer resolves identity and admits PREPARING
    C->C: reserve controls, epoch arenas, and target telemetry banks
    C->L: dispatch canonical context order, one turn per image/executor
    L-->C: exact result and owned token through bounded result ring
    C->C: stage module slots and complete snapshot, arm completion resources
    C->C: publish PREPARED and monotonic lease
    C->Q: complete retained Prepare context
    Q-->RPC: typed result
    RPC-->CP: typed PREPARED result
    CP->Store: persist PREPARED
    CP->Store: persist COMPLETION_PENDING
    CP->RPC: Activate(exact identity)
    RPC->Q: enqueue admitted identity with a new caller context
    Q->C: exact PREPARED and inactive-command preflight
    C->P: start reader grace, enter COMMITTING, publish TRANSITION
    W->P: acquire-observe command independently
    W->W: source staging, drain, CUT/ACK, local activation
    W->P: publish ledger, boundary, activation, and reader progress
    C->P: evaluate frozen certificate membership
    P-->C: execution and boundary leg complete
    C->C: publish target snapshot and runtime N/E/N, enter RETIRING
    C->P: require reader grace and final E telemetry
    C->L: withdraw exact claims and dispatch reverse RETIRE
    L-->C: exact successful claim results
    C->C: retire E snapshot, finish grace, publish N/N/N
    C->C: journal COMPLETE, publish IDLE, retire worker command
    C->Q: complete original Activate context
    Q-->RPC: exact terminal result
    RPC-->CP: typed response
    CP->Store: promote exact active content
@enduml
```

N/E/N denotes active, minimum-retained, and last-activated runtime epochs.
Executor eventfd notifications only wake the coordinator; result rings own
completion. A client deadline never revokes a context already borrowed by DP.

```{uml}
@startuml
participant "CP transition client" as CP
participant "DP RPC / Status" as DP
participant "Reconciliation classifier" as R
database "Durable CP authority" as S

loop Retain the same epoch, hash, key, and mutation sequence
    CP->DP: current lifecycle operation or Status query
    DP-->CP: transport outcome + optional typed response
    alt Retryable transport ambiguity
        CP->CP: next operation is Status for the same identity
    else Non-retryable transport or malformed response
        CP-->CP: return failure; retain durable phase
    else Authoritative response
        CP->R: local durable phase + identity resolution\n+ remote state + typed failure code
        R-->CP: one classified action
        alt Retry Prepare
            CP->DP: Prepare the same allocation
        else Wait for Prepare / query completion
            CP->DP: Status for the same identity
        else Persist PREPARED
            CP->S: durably record PREPARED
            CP->DP: Status for the same identity
        else Retry Activate
            CP->S: persist completion intent
            CP->DP: Activate the same identity
        else Retry pre-commit Abort
            CP->DP: Abort the same identity
        else Persist COMPLETE
            CP->S: record or reuse terminal success; promote active content
        else Persist ABORTED
            CP->S: keep prior active content and consumed watermarks
        else Preserve update freeze
            CP->CP: retain the durable transition phase; require recovery
            note over DP: DP retains the old runtime artifacts
        else Expired retry
            CP->CP: require joint CP/DP restart
        else Unavailable or rejected classification
            CP->CP: return failure; retain durable phase
        end
    end
    note over CP,S: Only nonterminal actions continue the loop. A remote state alone never selects the action.
end
@enduml
```

The classifier uses all four inputs together. A remote state alone cannot
authorize an action: for example, `UNKNOWN_FUTURE` retries Prepare for a durable
allocation but closes an already aborting allocation as ABORTED.

Prepare may span cold lifecycle turns and has cooperative cancellation plus a
plan-authored lease. Abort is legal only before commit. Exact retries observe
the existing transaction and do not publish a second worker command. Status is
the ambiguity-resolution authority after retryable transport failure.

The transaction is shared by every [worker loop variant](../DATA_PLANE.md#stage-modes-and-worker-loops).
Each worker resolves its own packet, active, and async ownership during drain.

### Transition RPC cross-component invariants

- Every handled response has a non-unspecified identity resolution and failure
  classification; diagnostic prose selects no action.
- CP persists PREPARED and COMPLETION_PENDING before attempting Activate.
- Activate starts reader grace before the worker command becomes observable.
- The original Activate caller remains owned through `COMPLETE` or update
  freeze; a transport retry cannot create a duplicate commit.
- Post-commit timeout is not Abort. COMMITTING timeout is fail-stop; a RETIRING
  grace timeout before withdrawal freezes with old objects retained, and any
  uncertainty after withdrawal is fail-stop.
- Drain, DrainStatus, Shutdown, and DumpState remain explicit application-level
  unavailable surfaces; they never fabricate lifecycle success.

### Transition RPC source anchors and detail

`src/cp/dataplane_transition_client.cpp`,
`src/dp/dataplane_control_service.cpp`,
`src/dp/epoch/epoch_transition_command_mailbox.cpp`,
`src/dp/epoch/epoch_transition_coordinator.cpp`,
`src/dp/epoch/epoch_transition_preparation.cpp`, and
`src/dp/epoch/epoch_transition_completion.cpp`. See
[`GRPC_API.md`](../GRPC_API.md), [`DATA_PLANE.md`](../DATA_PLANE.md), and the
[`ordered-CUT guide`](ordered_cut_boundary_protocol.md).

## 8. Configuration Publication

CP stores durable history and publishes immutable reader views. DP has two
snapshot slots and a matching two-slot artifact store per module context.
Workers execute only their published epoch view; cold threads prepare and
reclaim artifacts without mutating live context state.

### Configuration-publication ownership flow

```{uml}
@startuml
participant "CP durable authority" as CP
participant "DP coordinator / snapshot store" as D
participant "Lifecycle executor" as L
collections "Exact module stores\nACL0 / ACL1 / NAT44 / QoS" as M
participant "Ingress workers W0 and W1\nRX / parse / ACL" as RX
participant "Join worker W2" as W

CP->D: exact Prepare identity for canonical snapshot N
D->L: PREPARE all four module contexts
L-->D: return exact prepared ownership tokens
D->M: stage tokens and release-publish PREPARED
note over M: Each store: PUBLISHED E + PREPARED N
D->D: stage complete snapshot E + PREPARED N
CP->CP: retain active E and transaction N\nreaders consume versioned immutable publication
D->D: preflight commit; start reader grace
D->RX: publish TRANSITION E to N
D->W: same immutable command
RX->RX: independently close E source admission and drain old ownership\neach sender seals its own outbound cut
RX->W: CUT(N, q0) and CUT(N, q1) on separate boundaries
RX->M: ACTIVATE each owned ACL context and publish its N view
RX->RX: activate source queues, banks, and ledgers\npublish activation and reader safe points
W->W: drain both cuts and all local E work
W->M: acquire exact NAT44/QoS artifacts, preflight owned stores
note over L,W: PREPARE and RETIRE run off-worker; each ACTIVATE runs on its context's owner
W->M: ACTIVATE NAT44/QoS; publish exact N views
note over M: Each store: RETAINED E + PUBLISHED N
W->RX: ACK each exact input after complete local activation
RX->D: coherent ledger / boundary / activation / reader publications
W->D: coherent ledger / boundary / activation / reader publications
D->D: certify execution and boundaries\npublish snapshot N with E retained; enter RETIRING
D->D: require reader grace and final E telemetry
D->M: preflight every retained claim, then withdraw exact ownership
D->L: RETIRE module artifacts in reverse canonical order
L-->D: exact successful claim results
D->M: complete retired slots to EMPTY
D->D: retire snapshot E, finish grace\npublish COMPLETE, then IDLE
D-->CP: exact terminal result
CP->CP: atomically promote active N and refresh reader projection
@enduml
```

The DP snapshot store is coordinator-owned and has no packet reader. Module
stores release-publish prepared ownership to the sole worker, which preflights
all fallible state before calling bounded ACTIVATE. After that infallible callback,
slot/index/view publication is non-failing. A packet must match the one active
view exactly; there is no current/previous search.

### Configuration-publication cross-component invariants

- Canonical snapshot bytes and SHA-256 identity are verified before any slot
  becomes prepared.
- Context memory is allocated during INIT; epoch arenas are allocated during
  PREPARE. Their budgets are separate, and published packet-configuration views
  are immutable.
- At most one retirement claim may withdraw an exact old slot; destroying an
  unresolved claim terminates.
- Foreign lifecycle threads receive immutable/cold inputs, never a live
  worker-owned context.
- CP's `versioned_rcu_buffer` and DP's exact slots solve different ownership
  problems and do not substitute for one another.

### Configuration-publication source anchors and detail

`src/cp/config_store.cpp`, `include/kinetum/algo/rcu_buffer.hpp`,
`src/dp/config_snapshot_epoch_store.cpp`,
`src/dp/epoch/exact_slot_table.hpp`,
`src/dp/module/module_epoch_store.cpp`, and
`src/dp/module/module_runtime_generation.cpp`. See
[`DATA_PLANE.md`](../DATA_PLANE.md) and [`MODULE_SDK.md`](../MODULE_SDK.md).

## 9. Guardrails and Rollback

Guardrails compares a changed configuration with a prior-content baseline using
coherent DP telemetry. An attributed regression may produce one durable
rollback intent, executed through the ordinary mutation path at a new epoch.
Missing or contradictory evidence pauses or fails evaluation; it is never a
healthy zero or a packet-path decision.

### Guardrails evaluation flow

```{uml}
@startuml
!pragma useVerticalIf on
start
partition "Guardrails observer" {
:Read enabled durable policy identity;
:Read CP authority, collect DP telemetry,
then re-read and fence CP authority;
if (Complete, coherent, fault-free observation?) then (yes)
else (no)
    :Break interval continuity;
    :Do not advance valid observation time;
    stop
endif
if (Enabled ACK timeout with exact in-flight
identity and a distinct rollback target?) then (yes)
    :Select the timeout rollback target;
else (ordinary evaluation)
    if (IDLE and required module health available?) then (yes)
    else (no)
        :Break interval continuity;
        stop
    endif
    :Check runtime/content identity
    and cumulative counter high watermarks;
    if (Counters regress?) then (yes)
        :Break interval continuity;
        stop
    elseif (New baseline or broken interval?) then (yes)
        :Seed without a fabricated delta;
        stop
    endif
    :Compute one elapsed-time and counter delta;
    if (Baseline window?) then (yes)
        :Accumulate valid samples;
        :Arm only with positive baseline TX;
        stop
    else (candidate with frozen baseline)
        :Apply the threshold or correlation detector;
        if (Triggered?) then (yes)
            :Score attribution against the real baseline and window;
            if (Automatic rollback selected?) then (yes)
            else (inconclusive, defer, or log only)
                :Keep observing until the valid window ends;
                stop
            endif
        else (no)
            :Keep observing until the valid window ends;
            stop
        endif
    endif
endif
:Bind desired rollback to content,
runtime, policy, and observation identity;
:Generate one retry key;
:Submit a safety-intent borrow;
}
partition "Control-loop writer" {
:Revalidate and persist the exact intent;
:Use the ordinary transition at a new epoch
after any named predecessor resolves;
}
stop
@enduml
```

The evaluator has six exact states:

```{uml}
@startuml
skinparam linetype ortho
skinparam nodesep 180
skinparam ranksep 90
state UNCONFIGURED
UNCONFIGURED : After intent: no policy
state DISABLED
DISABLED : After intent: disabled policy
state BASELINE_BUILDING
BASELINE_BUILDING : Enabled policy
BASELINE_BUILDING : Disable policy: DISABLED
BASELINE_BUILDING : After intent: enabled policy
state ARMED
ARMED : Disable policy: DISABLED
state EVALUATING
EVALUATING : Disable policy: DISABLED
BASELINE_BUILDING -right-> ARMED : sufficient stable\nbaseline
ARMED -right-> EVALUATING : active content\nchanges
EVALUATING -[norank]-> BASELINE_BUILDING : valid window ends\nwithout action
state ROLLBACK_PENDING
ROLLBACK_PENDING : Failed terminal intent stays pending
ROLLBACK_PENDING : until explicit recovery
state CONVERGED <<choice>>

[*] --> UNCONFIGURED
UNCONFIGURED -right-> DISABLED : explicit disabled policy
UNCONFIGURED --> BASELINE_BUILDING
DISABLED --> BASELINE_BUILDING : enable
BASELINE_BUILDING -[norank]-> DISABLED
ARMED -[norank]-> DISABLED
EVALUATING -[norank]-> DISABLED
EVALUATING --> ROLLBACK_PENDING : intent accepted durably
ROLLBACK_PENDING --> CONVERGED : intent converges\nselect current policy state
CONVERGED -[norank]-> UNCONFIGURED
CONVERGED -[norank]-> DISABLED
CONVERGED -[norank]-> BASELINE_BUILDING
@enduml
```

The following events override or pause the ordinary evaluation path:

| Event | Effect |
|-------|--------|
| New policy generation | Reconstruct `DISABLED` or `BASELINE_BUILDING` from the complete policy. |
| Runtime replacement, overlapping content change, or same-content epoch change | Rebuild the enabled evaluator's baseline. |
| Missing, faulted, or regressing evidence | Break interval continuity without advancing valid time. |
| Independently durable safety intent, including commit-confirmed expiry | Enter `ROLLBACK_PENDING`; no second decision is admitted. |
| Exact intent convergence | Rebuild according to current policy presence and enabledness. |

### Guardrails commit-confirmed and selective rollback

```{uml}
@startuml
    autonumber
    participant "Operator" as O
    participant "CP writer" as CP
    participant "Durable authority" as S
    participant "DP transition" as DP
    participant "Deadline runner" as R

    O->CP: apply N with confirmation timeout and exact retry key
    CP->DP: ordinary Prepare / Activate
    DP-->CP: exact COMPLETE
    CP->S: atomically publish active N, rollback E, and absolute deadline
    CP-->O: snapshot, revision, and epoch
    alt first exact Confirm wins before deadline
        O->CP: Confirm snapshot, epoch, revision, and retained key
        CP->S: check identity and deadline under sole mutation order
        S-->CP: retain confirmed result and first remaining time
        CP-->O: exact success, reusable by same-key retry
        R->S: read pending record
        S-->R: already confirmed, no timeout intent
    else unconfirmed deadline wins
        R->S: read expired pending identity
        R->DP: collect mandatory telemetry under a CP-content fence
        DP-->R: exact runtime/content observation
        R->CP: submit identity-bound timeout intent
        CP->S: revalidate and persist intent
        CP->DP: ordinary rollback of E content at new epoch
        DP-->CP: exact COMPLETE
        CP->S: atomically promote rollback and resolve intent
        O->CP: later first Confirm
        CP-->O: reject, never manufacture late success
    end
@enduml
```

Confirm and expiry share the control loop's serialization point. Response-loss
retry uses the retained key and first result.

Selective rollback creates a new canonical snapshot containing named module
entries from the target snapshot and every other module from the current
snapshot. Module membership must match. The result is ordinary new
content and follows the same Prepare/Activate path; epochs never move backward.

```{uml}
@startuml
start
:Read current snapshot and rollback target;
note right
  Current: ACL N, NAT44 N, QoS N
  Target: ACL E, NAT44 E, QoS E
end note
if (Selective rollback admitted
and no unconfirmed promise?) then (yes)
else (no)
    :Reject without mutation;
    stop
endif
if (Same module set
and all requested IDs present?) then (yes)
else (no)
    :Reject without mutation;
    stop
endif
partition "Example: roll back ACL only" {
    :Construct canonical hybrid content
    ACL E, NAT44 N, QoS N;
    :Derive identity from the retained retry key;
    :Retain the first revision and timestamp;
    :Allocate a new monotonic epoch;
    :Ordinary Prepare / Activate / retirement;
    :Publish hybrid content as active
    after exact COMPLETE;
}
stop
@enduml
```

### Guardrails cross-component invariants

- Each evaluated DP observation is fenced by durable active-identity reads
  before and after its response.
- Observation time advances only across valid, same-generation samples.
- Module health is current only at the coherent active epoch; unavailable rows
  suppress evaluation when the policy requires that evidence.
- The sticky protocol-fault latch is transition-safety authority, not
  telemetry policy. A faulted generation cannot report transition success.
- A rollback decision binds active content, policy generation, runtime
  generation, epoch, revision, hash, and observation time before durability.
- Guardrails never calls routing, packet, or DP ownership code directly.

### Guardrails source anchors and detail

`src/cp/guardrails.cpp::guardrails_runner`,
`src/cp/guardrails_evaluator.cpp`, `src/cp/guardrails_policy.cpp`,
`src/cp/runtime_authority_fence.cpp`, `src/cp/health_correlator.cpp`,
`src/cp/attribution_scorer.hpp`, and
`src/cp/control_loop.cpp::service_durable_rollback_intent_`. See
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](../CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md)
and [`KINETUMCTL.md`](../KINETUMCTL.md).

## 10. Module Lifecycle

One module image may own several stage-instance contexts. Cold owners admit
the image, construct contexts, prepare configuration, and reclaim it. Each
context's packet worker owns activation and live callbacks. Image unload waits
for every dependent context, artifact, callback, packet, timer, async token,
telemetry bank, and claim.

### Module lifecycle flow

```{uml}
@startuml
    autonumber
    participant "Module loader and manager" as L
    participant "Coordinator preparation / completion" as C
    participant "Lifecycle executor + adapter" as E
    participant "Per-context artifact store" as S
    participant "Sole owner worker" as W
    participant "Module image" as M

    L->L: admit complete image/context identities and canonical paths
    L->M: dlopen local/now, resolve sole registration export
    M-->L: immutable descriptor
    L->L: validate ABI, modes, flags, replication, and callbacks
    L->M: INIT cold lifecycle context
    M-->L: exact context state
    L->L: publish generation only after every context succeeds
    C->E: dispatch exact context/E PREPARE under image serialization
    E->M: PREPARE immutable E config in epoch arena
    M-->E: status and prepared owner/view pair
    E->E: bind successful artifact and arena into ownership token
    E-->C: exact result and token through owned result ring
    C->S: transfer token into EMPTY slot and publish PREPARED
    note over E,S: Null/null pointers may still represent successful owned state
    C->W: launch behind the bootstrap activation gate
    W->W: complete all local activation preconditions
    W->S: acquire exact target artifact
    W->M: bounded infallible ACTIVATE E
    W->S: publish E view
    note over C,W: Complete generation bootstrap before packet bodies open
    alt passive descriptor
        W->M: process borrowed SoA batch and exact config
        M-->W: forward mask and proposed mutable lanes
        W->W: validate authority, bounds, and parsed-field coherence
    else active descriptor
        W->M: admitted ingest, run, and control callbacks
        M->W: bounded requests through active runtime services
        M-->W: callback returns
    end
    opt health callback admitted and due
        W->M: health against same active view
        M-->W: bounded assessment, no epoch or time authority
        W->W: validate and publish typed health
    end
    C->E: PREPARE N while owner continues E work
    E->M: compile immutable N artifact
    M-->E: successful owner/view pair
    E-->C: exact N ownership token
    C->S: stage PREPARED N beside PUBLISHED E
    C->C: preflight all contexts and commit exact transition
    C->W: publish TRANSITION E to N
    W->W: drain E work and seal outbound CUTs
    W->M: bounded infallible ACTIVATE N
    W->S: publish N view and retain E artifact
    W->W: publish activation, inbound ACKs, and reader safe point
    C->C: require certificate, reader grace, and final E telemetry
    C->S: claim exact retained old artifact
    C->E: dispatch RETIRE claim
    E->M: RETIRE claimed old artifact
    M-->E: callback returns
    E-->C: exact successful task/image/context/epoch/claim result
    C->S: complete exact retirement claim
    note over L,M: Final generation shutdown follows a separate lifetime edge
    C->W: stop source admission, drain, and join owner
    W-->C: no live callback or retained packet work
    C->S: claim final PUBLISHED artifact
    C->E: dispatch final RETIRE
    E->M: RETIRE final artifact
    E-->C: exact successful claim result
    C->S: complete final claim, slots empty
    C->C: join lifecycle executors and retire telemetry ownership
    L->L: require all workers/executors joined and artifacts/banks/claims empty
    L->M: FINI each detached context in reverse order
    L->L: unload image after its final context and image claim retire
@enduml
```

Both module modes share descriptor, context, slot, lifecycle, and reclamation
ownership. Active workers additionally
bind exact origin, retained, timer, control, pull, recirculation, and ledger
rows. Tracked async adds fixed token slots and a caller-storage completion queue;
foreign threads publish completion only and never invoke a module callback.

INIT registers module counters and histograms in stable worker-NUMA storage.
The descriptor supplies the optional health callback; the runtime constructs
its worker-owned state. The owner updates the active bank and invokes health
against the exact active view. Cold readers consume completed banks or coherent
snapshots, never the mutable context.

### Module-lifecycle cross-component invariants

- Module ABI equality is exact in both version directions; no descriptor-size
  compatibility reader exists.
- The image exports only `kinetum_module_register` and has no unresolved
  non-weak dependency.
- Every context belongs to one image, generation, stage instance, worker, CPU,
  NUMA node, store, and ledger, validated in both directions before launch.
- PREPARE and RETIRE are cold; ACTIVATE and every live callback are sole-worker
  operations.
- No platform lock crosses a module callback.
- Image unload is forbidden beneath any live context, artifact, callback,
  async token, telemetry bank, health claim, or returned retained handle.

### Module-lifecycle source anchors and detail

`include/kinetum/kinetum_sdk.h::kinetum_module`,
`src/dp/module/module_descriptor_admission.cpp`,
`src/dp/module/module_manager.cpp::module_manager`,
`src/dp/module/module_lifecycle_adapter.cpp`,
`src/dp/module/module_epoch_store.cpp`,
`src/dp/active/worker_active_stage_scheduler.cpp`, and
`src/dp/active/worker_async_work.cpp`. See [`MODULE_SDK.md`](../MODULE_SDK.md)
and [`../src/modules/README.md`](../../src/modules/README.md).

## 11. Data-Plane Host

The data-plane host constructs a runtime generation from a verified bundle and
authenticated providers. Its main thread runs the coordinator and control event
loop; lifecycle executors perform cold module work; packet workers own live
state. gRPC threads submit commands or read coherent publications. Construction
finishes before packet ingress; recoverable failures unwind acquired resources.

### Data-plane construction and publication

```{uml}
@startuml
participant "DP main / coordinator" as D
participant "Bundle and host admission" as V
participant "Provider generation" as P
participant "Module generation" as M
participant "Lifecycle executors" as L
participant "Packet workers" as W
participant "Control plane" as CP

group Verify inputs and admit provider components
    D->D: block termination/reopen signals\ncreate control event loop and wake descriptor
    D->V: verify manifest, paths, plan, and bootstrap snapshot
    V-->D: sole compiled topology
    D->V: Quark live CPU / NUMA and host-memory proof
    D->D: admit coordinator-CPU logging, native capture, and TLS\npreallocate coordinator mailbox
    D->P: authenticate inventory before parsing metadata
    P->P: hold and inspect exact ELF / dependencies\nprove private closure before loading
    P->P: load required components\nvalidate descriptors and host-proof results
    P-->D: required components, validated descriptors, and host-proof results
end
group Construct the complete cold generation
    D->D: create coordinator and immutable command owner
    D->M: admit images and INIT exact contexts
    D->L: pre-create bounded lifecycle executors
    D->P: reserve resources; construct facilities in dependency order
    P->P: construct storage, cold drivers, execution, and transitions
    D->D: allocate NUMA-local endpoint slabs, DATA/CUT/ACK,\ninput/future queues, holds, telemetry, and active state
    D->D: bind kernels, activation owners, readers, and certificate graph
    D->L: start planned services
    D->D: revalidate complete generation; publish CONTROL_READY
    note over D,W: No packet source or worker packet body is open
end
group Bootstrap exact durable epoch E
    CP->D: exact Bootstrap identity
    D->L: PREPARE every module context at E
    L-->D: exact owned artifacts
    D->W: launch behind the bootstrap gate
    W->M: owner-worker ACTIVATE of each owned context
    W->W: bind exact views and worker state to E
    W-->D: complete activation population
    D->D: commit snapshot, allocator identity, and runtime status
    W-->D: all RUNNING, with packet bodies still blocked
    D->P: activate the complete driver set
    P-->D: native ingress activation complete
    D->D: publish PACKET_READY
    D->W: release packet bodies
end
@enduml
```

Failure disposition depends on the completed ownership edge. Pre-load rejection
returns without foreign code; unprovable loader/native state fails stop.
Recoverable construction failure unwinds its exact acquired prefix in reverse
dependency order. No partial generation is published.

### Data-plane runtime ownership

```{uml}
@startuml
participant "gRPC threads" as RPC
participant "Main thread / coordinator CPU" as C
participant "NUMA-local lifecycle executors" as L
collections "Immutable worker command" as CMD
participant "Packet workers / planned CPUs" as W
participant "Materialized providers" as P
collections "Completed banks / coherent publications" as OBS
participant "Claimed telemetry source" as S

group Cold commands and lifecycle work
    RPC->C: plan-sized MPMC mailbox: fixed command + borrowed context
    C->C: service signalfd and compiled monotonic deadlines
    C->L: bounded task channels
    L-->C: bounded result rings; eventfd only wakes
    C->P: whole-driver activation / deactivation at lifecycle boundaries
end
group Packet-owner execution
    C->CMD: publish immutable RUN / TRANSITION / STOP
    W->CMD: one acquire pointer observation per turn
    CMD-->W: exact published command
    W->P: pre-resolved burst operations
    W->OBS: publish completed telemetry banks
    W->OBS: publish coherent ledger, activation, boundary, and reader state
    C->OBS: consume completed banks and coherent evidence
    C->C: cold telemetry aggregation; certificate / completion
    C->OBS: publish immutable aggregates and runtime / transition views
    C-->W: return cleared or retained banks through owned channels
end
group Read-only statistics
    RPC->S: claim generation-scoped collection
    S->OBS: read immutable aggregates and coherent publications
    S->P: cold provider observations
    P-->S: typed native facts
    S->S: validate one complete coherent result
    S-->RPC: complete result or typed failure
end
note over C,W: Mutable packet state has one worker owner. Cold readers never inspect the worker's active mutable bank.
@enduml
```

The contract catalog validates configuration, the signed inventory authenticates
bytes, and the runtime catalog supplies the plan's required implementations.

### Data-plane host cross-component invariants

- The verified bundle produces the sole compiled topology. Quark and runtime
  construction consume it rather than walking plan structure independently.
- Fixed mailboxes, lifecycle channels, boundaries, worker queues, telemetry,
  packet storage, and module contexts exist before `CONTROL_READY`. Epoch arenas
  and prepared artifacts are built during cold PREPARE, before commit.
- Provider factories construct cold drivers; only the generation owner may
  activate or deactivate the complete set.
- Once the first foreign component load begins, later loader/query failure is
  process-fatal because constructor state cannot be rolled back safely.
- Shutdown closes command and source admission, drains and joins workers,
  deactivates drivers in reverse order, retires coherent telemetry and active
  module artifacts, tears down kernels/channels/slabs, then releases the module
  generation and provider graph.
- Internal telemetry collection never holds a platform lock across provider
  observation callbacks and never reads mutable owner lines.

### Data-plane host source anchors and detail

`src/dp/dp_main.cpp::main`, `src/dp/dp_control_event_loop.cpp`,
`src/dp/packet_runtime_generation.cpp`,
`src/dp/partitioned_runtime.cpp::partitioned_runtime`,
`src/provider/provider_runtime_admission.cpp`,
`src/provider/provider_runtime_materialization.cpp`,
`src/dp/lifecycle/runtime_service_launcher.cpp`, and
`src/dp/runtime_telemetry_snapshot_source.cpp`. See
[`DATA_PLANE.md`](../DATA_PLANE.md), [`QUARK.md`](../QUARK.md), and
[`KINETUM_PACK.md`](../KINETUM_PACK.md).

## 12. Worker Hot Path

Each worker runs a compiled kernel over its RX sources, local queues, stages,
boundaries, TX sinks, module contexts, ledger, and telemetry banks. Construction
resolves its operations and allocates its state. After bootstrap and startup
gates, `run()` selects the [worker loop](../DATA_PLANE.md#stage-modes-and-worker-loops)
once from the admitted stage resources.

### Worker ownership and input admission

```{uml}
@startuml
!pragma layout elk
title Default fan-in gateway: fair admission inside each running worker
skinparam linetype ortho
top to bottom direction

queue "wan0 RX queue" as RX0
queue "wan1 RX queue" as RX1

node "W0 / CPU" as W0 {
    rectangle "W0 input-order state\nRX0: one input, quantum 64" as ORDER0
    component "Admit input" as ADMIT0
    queue "Local active staging" as LOCAL0
    component "Packet work\nrx0 -> parse0 -> acl0" as EXEC0
    ORDER0 .right.> ADMIT0 : allowance
    RX0 -down-> ADMIT0 : RX prefix
    ADMIT0 -down-> LOCAL0 : admitted pointers
    LOCAL0 -down-> EXEC0 : bounded work prefix
}

node "W1 / CPU" as W1 {
    rectangle "W1 input-order state\nRX1: one input, quantum 64" as ORDER1
    component "Admit input" as ADMIT1
    queue "Local active staging" as LOCAL1
    component "Packet work\nrx1 -> parse1 -> acl1" as EXEC1
    ORDER1 .right.> ADMIT1 : allowance
    RX1 -down-> ADMIT1 : RX prefix
    ADMIT1 -down-> LOCAL1 : admitted pointers
    LOCAL1 -down-> EXEC1 : bounded work prefix
}

node "W2 / CPU" as W2 {
    queue "Inbound DATA A\nFrom W0" as A
    queue "Inbound DATA B\nFrom W1" as B
    rectangle ORDER2 [
        W2 input-order state
        ----
        Inputs: A and B
        Quantum: up to 64 packets per input per turn
        Next input + unfinished allowances
    ]
    note right of ORDER2
        Both inputs stay ready. Free slots are as shown:
        |= Free slots |= Admit in order |= Next input |
        | 80 | A: 64, then B: 16 | B, with 48 left |
        | Later, 64 | B: 48, then A: 16 | A, with 48 left |
        ----
        Quantum completed: move to the back.
        No staging space: keep the remainder.
        Empty input: clear the remainder and move on.
    end note
    component "Admit inputs\nRead the selected DATA prefix" as ADMIT2
    queue "Local active staging\nReceives both input prefixes" as LOCAL2
    component "Packet work\nNAT -> QoS -> TX" as EXEC2
    ORDER2 .right.> ADMIT2 : next input and allowance
    A -down-> ADMIT2
    B -down-> ADMIT2
    ADMIT2 -down-> LOCAL2 : admitted pointers
    LOCAL2 -down-> EXEC2 : bounded work prefix
}

queue "lan0 TX queue" as TX
EXEC0 -down-> A : packet pointers
EXEC1 -down-> B : packet pointers
EXEC2 -down-> TX : accepted TX prefix

legend bottom
    Ordinary forwarding in the default shared-storage profile; one RX queue per ingress port.
    Each CPU box contains one continuously running packet-worker thread.
    Each worker repeats: control work -> input admission -> packet work -> flush / publish.
    Solid arrows: packet path. Dashed arrows: input-order state controls the worker's reads.
    Input-order state holds input identities and allowances, never packets or threads.
endlegend
@enduml
```

### One worker hot-path turn

Optional active and async work appears only in the selected loop. Input
admission shares that worker thread and owns only service order and allowances;
the existing queues and ledger retain packet ownership.

```{uml}
@startuml
    autonumber
    participant "Runtime command" as CMD
    participant "RX operations" as RX
    participant "Worker kernel" as K
    participant "Input admission order\n(worker-owned)" as IN
    participant "Compiled active scheduler" as A
    participant "Stages and module callbacks" as ST
    participant "Boundary channels and policies" as B
    participant "TX and release operations" as TX
    participant "Owner publications" as PUB

    K->CMD: one acquire pointer load
    alt changed TRANSITION
        K->K: preflight, bind future state, drain active admission, advance source
    else level-triggered STOP
        K->K: keep source polling closed and active shutdown drain enabled
    else unchanged RUN
        K->K: retain existing owner state
    end
    K->PUB: service requested telemetry returns before reuse
    alt one scheduled module-context sweep row
        K->ST: preflight owner-health claim before time refresh
        K->K: refresh cached turn time once
        opt a non-null health callback was admitted
            K->ST: invoke bounded health with exact view and cached time
            ST-->K: assessment
            K->K: one post-return budget sample, validate and publish health
        end
        K->PUB: service this context bank and advance sweep cursor
    else no context sweep
        K->K: refresh cached turn time once
    end
    opt transition active
        K->B: receiver CUT service, then sender ACK service
    end
    opt compiled active worker
        K->A: selected synchronous or tracked-async turn
    end
    loop bounded input service; at most two visits per input
        K->IN: next input and remaining allowance
        IN-->K: exact RX or boundary ordinal
        alt RX input and source polling open
            K->K: select active/future role and reserve available prefix
            K->RX: receive within the service allowance
            RX-->K: transferred records and rejected count
            K->K: stamp source epoch, acquire transferred credits,\nstage prefix and release unused reservations
        else inbound DATA
            K->B: peek DATA head
            K->K: admit exact-active-epoch DATA:\nreserve, receive, credit, complete dequeue, stage
        else RX input during STOP
            K->K: yield without polling
        end
        K->IN: account work including rejections\nkeep unfinished allowance or rotate completed/yielding input
    end
    K->ST: process bounded active queue prefixes\nbatch contiguous same-context/epoch module work, at most 64
    ST-->K: forward, drop, retain, emit, async, or recirculate
    K->TX: finish context selection, then flush transition, TX, and release prefixes
    opt transition active
        K->B: refresh cuts and seal outbound only after old work drains
        opt all cuts published and local activation preflight passes
            K->ST: infallible ACTIVATE for all prepared module views
            K->K: switch telemetry, rotate source queues, promote ledger/scheduler
            K->PUB: publish exact local activation
            K->B: mark receivers activated and submit exact ACKs
            K->PUB: publish reader safe point
        end
        K->B: service finite held output and complete empty endpoint generation
    end
    opt not stopping
        K->PUB: worker telemetry cadence, schedule next context sweep
    end
    K->PUB: publish ledger, then boundary transport once
    opt STOP, local work empty, inbound closed/empty, final banks ready
        K->K: require zero ledger credits
        K->B: close every outbound producer
        K->TX: final owned TX flush
        K->PUB: publish final context and worker banks
        K->K: exit loop
    end
@enduml
```

Each worker refreshes its cached time once per ordinary turn. An actual non-null
module health callback permits one additional post-return sample solely for its
budget and bank timestamp. Four transition-edge classes permit one sample per
complete endpoint batch. All other packet work uses the cached time. Target
qualification must prove that these clock calls avoid system-call fallback;
the source-level API alone does not establish that.

### Worker hot-path cross-component invariants

- The normal command path is one acquire load plus a predicted pointer-equality
  branch shared with shutdown observation.
- Each record carries one immutable epoch and exact storage owner; stage and
  routing metadata change only through their owning packet operations.
- A transfer secures destination capacity before releasing source ownership.
  A receiving worker acquires its credit before completing the DATA dequeue
  sequence.
- Local queue reservations, physical storage records, and logical epoch credits
  remain distinct accounting classes.
- Ordinary owned packet work does not allocate, lock, log, format strings,
  throw exceptions, use RTTI or virtual dispatch, search providers/topology,
  or issue control/discovery syscalls. A provider burst may invoke only the
  system call intrinsic to its admitted I/O mechanism.
- Packet transfers and event delivery use burst-bounded prefixes. Total turn
  work also depends on the compiled schedule and timer maintenance; capacity
  is never a scheduling target.

### Worker hot-path source anchors and detail

`src/dp/packet_worker_kernel.cpp::run`,
`src/dp/worker_input_scheduler.cpp`,
`include/kinetum/algo/bounded_service_order.hpp`,
`src/dp/packet_mechanism.cpp`, `src/dp/worker_runtime_command.cpp`,
`src/dp/epoch/worker_epoch_ledger.cpp`,
`src/dp/epoch/worker_boundary_sender.cpp`,
`src/dp/epoch/worker_boundary_receiver.cpp`,
`src/dp/active/worker_active_stage_scheduler.cpp`, and
`src/dp/active/worker_async_work.cpp`. See [`DATA_PLANE.md`](../DATA_PLANE.md)
and [`PLATFORM_ENGINEERING_GUIDE.md`](../PLATFORM_ENGINEERING_GUIDE.md).

## 13. Packet Lifecycle

One `packet_record` owns physical packet storage. Metadata carries epoch, stage,
route, and port; the storage descriptor identifies the owner and carries a
provider-private native handle. Each worker-owned branch holds one ledger credit
until retirement or transfer. Storage, queue capacity, and work credits have
separate lifetimes.

### Packet lifecycle flow

**Admission and execution.** Only transferred records acquire packet credits.
Rejected native input and unused receive capacity do not become worker-owned
packets.

```{uml}
@startuml
participant "RX provider / origin module" as P
participant "Owner worker / scheduler" as W
collections "Local staging + epoch ledger" as L
participant "Parser / module stage" as M
participant "Original storage domain" as S

alt Physical RX
    W->L: reserve bounded local capacity
    W->P: receive burst, limited by free capacity and burst bound
    P-->W: transferred prefix + rejected count
    note over P,W: Provider already reclaimed rejected native inputs; they acquire no worker credit
    W->W: stamp source epoch, time, ingress, and stage on transferred records
    W->L: acquire one credit per record; publish active / future input
    W->L: release every unused reservation
    W->W: account transferred packets/bytes and native rejections once per burst
else Active origin
    P->W: borrowed payloads and origin facts
    W->W: validate the complete origin batch
    W->S: copy accepted prefix into the authored origin domain
    W->L: acquire active-epoch credits; publish accepted origin work
    W-->P: accepted prefix; remaining origin work stays module-owned
end
W->L: take staged work only at the exact active epoch
alt Platform stage
    W->M: execute the exact RX, parser, or TX mechanism
    M-->W: outcome and parsed fields
else Module stage
    W->W: take available contiguous work for one context and epoch\nproject at most 64 occupied SoA lanes, without waiting or sorting
    W->M: invoke one pre-resolved callback with its exact view
    M-->W: occupied-prefix forward mask and mutable fields
    W->W: validate callback authority, bounds, and field coherence
end
alt Drop
    W->L: retire credit once
    W->S: append to the original domain's release burst
else Forward
    W->W: resolve compiled routing
else Retained by ACTIVE ingest
    W->L: preserve the existing credit under an opaque retained handle
end
@enduml
```

**Routing.** Explicit module routing, priority routing, and unconditional fan-out
are distinct choices. Priority routing does not fall through to broadcast.

```{uml}
@startuml
!pragma useVerticalIf on
start
:Forwarded record;
if (TX stage?) then (yes)
    :Resolve terminal egress;
    stop
endif
partition "Choose logical successors" {
    if (Module supplied next stage?) then (yes)
        if (Valid authored logical target?) then (yes)
            :Select that destination group;
        else (no)
            :Stage drop; release through original owner;
            stop
        endif
    elseif (Priority routing?) then (yes)
        :Evaluate compiled conditions in priority order;
        note right: Equal priorities retain authored order.
        if (A condition matches?) then (yes)
            :Select the first matching route;
        else (no)
            :Stage drop; release through original owner;
            stop
        endif
    elseif (Unconditional fan-out?) then (yes)
        :Assign the original to the first successor;
        :For each additional successor,
        reserve capacity before cloning independent
        bytes and metadata;
        note right
          Successful clone: acquire a new work credit.
          Capacity/clone failure: count fan-out overflow;
          no clone ownership or credit is created.
        end note
    else (terminal)
        :Stage drop; release through original owner;
        stop
    endif
}
partition "Dispatch each admitted output" {
    if (Module context selection applies?) then (yes)
        :Project the contiguous read-only flow prefix;
        :Call the selector with the exact permitted contexts;
        if (Input lane admitted?) then (yes)
            :Validate and retain its selected context;
        else (no)
            :Stage drop; release through original owner;
            stop
        endif
    else (same lane or PULL)
        :Bind the exact pre-resolved destination;
    endif
    :Stamp the selected executable target
    and apply any authored storage transition;
    if (Target worker is the current owner?) then (yes)
        :Stage in the bounded local queue,
        preserving the same credit;
        :Execute the next stage at the exact active epoch;
    else (no)
        :Use the worker boundary handoff;
    endif
}
stop
@enduml
```

**Worker handoff.** A full queue preserves source ownership. Successful DATA
publication and completed dequeue are separate transfer edges.

```{uml}
@startuml
    autonumber
    participant "Sender worker" as S
    participant "Sender future-output hold" as H
    participant "DATA ring" as D
    participant "Receiver worker" as R

    alt target output waits for exact ACK
        S->H: try transfer record to bounded hold
        alt accepted
            S->S: release local reservation, retain epoch credit
        else hold full
            S->S: queue local retry with record, reservation, and credit
        end
    else gate open with no earlier held prefix
        S->D: try enqueue record
        alt accepted
            S->S: sequence advanced, retire credit and local reservation
        else DATA full
            S->S: queue local retry with unchanged ownership
        end
    end
    opt exact ACK received and held prefix remains
        H-->S: borrow oldest held record
        S->D: try publish before any newer target output
        alt DATA space available
            D-->S: successful enqueue and sequence advance
            S->H: remove that exact front record
            S->S: retire its credit
        else DATA full
            S->S: keep hold ownership and return to next bounded turn
        end
    end
    note over D: Ring owns records until receiver transfer
    R->D: peek exact front record
    R->R: validate epoch/route/domain and reserve destination slot
    R->D: pop record
    D-->R: transfer exact pointer
    R->R: acquire receiver credit
    R->D: complete dequeue sequence
    R->R: publish local next-stage work
@enduml
```

**Egress and storage return.** The worker preserves pre-call metadata because
accepted records may already be freed when the provider returns.

```{uml}
@startuml
start
partition "Resolve an owner-local TX stream" {
    if (Egress is UNSET?) then (yes)
        :Use the exact stage-bound TX stream;
    else (explicit selection)
        if (Known logical port and owned TX stream?) then (yes)
            :Use the dense worker-local port table;
        else (DROP, invalid, or missing)
            :Count stage drop;
            :Retire credit and release original storage;
            stop
        endif
    endif
    :Apply the authored edge conversion first;
    note right
      Without a conversion, the original domain
      must belong to the stream's accepted set.
    end note
    if (Storage admitted?) then (yes)
    else (incompatible)
        :Count stage drop;
        :Retire credit and release original storage;
        stop
    endif
}
partition "Transfer one bounded burst" {
    :Append in stream order;
    :Save original domain, length, epoch,
    and executed TX stage before the provider call;
    :Invoke one bounded provider TX operation;
    split
        :Accepted prefix;
        :Count acceptance from saved facts;
        :Retire worker credits and reservations;
        note right
          The provider already owns accepted records.
          Native completion or teardown returns their
          original storage; reclamation may even occur
          before the TX call returns.
        end note
    split again
        :Unaccepted suffix remains worker-owned;
        :Count stage drops;
        :Retire credits and release original storage;
    end split
}
stop
@enduml
```

**Retained and foreign work.** Packet-bound async moves an existing credit;
standalone async creates its own. Completion is delivered on the owner worker.

```{uml}
@startuml
participant "Owner-worker module callback" as M
participant "Active scheduler / work ledger" as A
participant "Ordinary packet dispatch" as D
participant "Foreign engine" as F
queue "Bounded completion queue" as Q

alt ACTIVE INGEST forwards or drops
    M->A: callback returns its disposition
    A->D: forward on the compiled path, or retire packet credit and storage
else Retain an input
    M->A: retain_input
    A-->M: opaque handle carrying the existing packet credit
    note over M,A: Complete batch validation commits provisional ownership,\nincluding any async begin using that handle inside the same INGEST
    alt Synchronous retained disposition
        M->A: emit_retained or drop_retained
        A->A: consume handle into pending disposition\nownership survives backpressure
        A->D: emit on the ordinary path, or retire credit and original storage
    else Same-instance recirculation while OPEN
        M->A: recirculate_retained
        A->A: pending recirculation keeps the same credit
        A->M: deliver the same-instance INGEST callback
    else Packet-bound async
        M->A: begin_async_retained
        A->A: invalidate handle; move its credit into the exact token
        A-->M: token + read-only packet view
        M->F: transfer copied token and module-owned work
    end
else Standalone async
    M->A: begin_async
    A->A: acquire a nonpacket credit before foreign visibility
    A-->M: exact token
    M->F: transfer copied token and module-owned work
end

group For a transferred async token
    opt Transition or shutdown DRAIN
        A->F: publish cooperative cancellation
        note over M,A: DRAIN forbids new async and recirculation\none already-pending recirculation may finish, but cannot repeat
    end
    F->Q: one winning terminal publication
    note over F,Q: Foreign code cannot mutate worker state or invoke module callbacks
    A->Q: consume bounded completion prefix on the owner worker
    Q-->A: exact token and outcome
    alt Packet-bound completion
        A->A: restore fresh retained handle with the same packet credit
        A->M: RUN receives completion and restored ownership
        M->A: keep retained, or emit/drop into pending disposition
    else Standalone completion
        A->M: RUN receives completion
        M-->A: callback returns
        A->A: retire standalone credit
    end
end
note over M,Q: No FINI, unload, or reclamation while accepted foreign ownership remains unresolved
@enduml
```

An already pending recirculation may finish once after DRAIN; its callback cannot
start another cycle. A synchronous foreign-submit refusal can abort the token
before transfer, retiring standalone credit or restoring a fresh packet handle.
Unresolved foreign work cannot be erased by a timeout.

```{uml}
@startuml
start
if (Foreign owner accepted the token?) then (no)
    :Abort the exact pre-transfer token;
    if (Packet-bound?) then (yes)
        :Restore a fresh retained handle
        with the same packet and credit;
    else (standalone)
        :Retire the token's work credit;
    endif
else (yes)
    :Require terminal completion,
    even after cooperative cancellation;
    if (Cancellation grace expires unresolved?) then (yes)
        :Fail stop without reclaiming uncertain ownership;
        stop
    else (completion received)
        :Deliver completion through the owner worker;
    endif
endif
stop
@enduml
```

### Packet-lifecycle cross-component invariants

- A module receives SoA packet views or opaque handles, never `packet_record *`.
- A packet executes only when its immutable epoch equals the worker's sole
  active view.
- Forward, drop, retain, clone, async transfer, recirculation, TX, and release
  each have one exact credit fate.
- A successful boundary enqueue advances sequence before sender credit retires;
  a receive acquires destination credit before dequeue ownership completes.
- Bounded-copy transition copies before source release; zero-copy sharing
  preserves the record. Neither infers a fallback.
- Telemetry follows semantic ownership events and never authorizes them.

### Packet-lifecycle source anchors and detail

`src/provider/provider_component_abi.h::kinetum_packet_record`,
`src/dp/packet.hpp::packet_record`, `src/dp/packet_work_item.hpp`,
`src/dp/packet_mechanism.cpp`, `src/dp/fixed_packet_pool.cpp`,
`src/dp/epoch/boundary_epoch_channel.cpp`, and
`src/dp/packet_worker_kernel.cpp`. See [`DATA_PLANE.md`](../DATA_PLANE.md),
[`MODULE_SDK.md`](../MODULE_SDK.md), and the
[`ordered-CUT guide`](ordered_cut_boundary_protocol.md).
