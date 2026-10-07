# Ordered-CUT Boundary Protocol

Kinetum changes live configuration by draining each worker's old work before
activating its new view. These diagrams show the boundary and reclamation
proof. Data-plane and wire contracts are in
[`DATA_PLANE.md`](../DATA_PLANE.md) and [`GRPC_API.md`](../GRPC_API.md).

## 1. What the Ordered-CUT Protocol Is

Every packet enters the data plane with one immutable epoch. Cross-worker DATA
travels through a bounded SPSC ring. A separate control lane carries a `CUT`
record whose sequence identifies the position immediately after the sender's
last successful old-epoch DATA enqueue. The receiver activates the target epoch
only after it has consumed DATA through that sequence and retired all of its
other old-epoch work. It then returns an `ACK` containing the same epoch and cut
sequence.

The result is an epoch-exclusive owner handoff:

- old source admission closes before the sender seals its cut;
- every old DATA prefix is drained exactly;
- retained packets, timers, control work, pull readiness, callbacks, and
  tracked asynchronous work remain visible through the same worker ledger;
- each worker publishes one bounded activation edge with no packet callback
  interleaving;
- new DATA crosses a boundary only after the destination has activated;
- old configuration remains owned until the global certificate and reader
  grace are complete.

This is a completion protocol after commit. A timeout is evidence of a stalled
or contradicted transition, not authority to restore an old pointer.

## 2. Scope and Non-Goals

The protocol applies to one already materialized runtime generation and one
configuration-only transition. The pipeline graph, module images, provider
instances, worker placement, queues, and storage domains do not change during
that transition.

It does not provide:

- restartless graph or module-image replacement;
- concurrent overlapping configuration transitions;
- cross-worker active control or pull edges;
- a timeout-based approximation of quiescence;
- a second packet-version lookup path.

A runtime-shape change requires a newly verified bundle and a supervised
runtime restart. All [worker loop variants](../DATA_PLANE.md#stage-modes-and-worker-loops)
use this protocol for configuration transitions admitted by the current plan.

## 3. Vocabulary and Authorities

| Term | Meaning | Sole authority |
|------|---------|----------------|
| Epoch | Nonzero configuration identity stamped on packet ownership. | Durable CP allocation, admitted by DP and published to workers. |
| DATA sequence | Count of successful DATA enqueue or dequeue transfers on one boundary. | The corresponding SPSC endpoint. |
| CUT | Target epoch plus final old-DATA enqueue sequence. | The boundary's sole sender worker. |
| ACK | Target epoch plus the consumed cut sequence. | The boundary's sole receiver worker. |
| Source epoch | Epoch assigned to newly originated packet work. | Owner worker command state. |
| Active epoch | Epoch accepted by packet execution and module views. | Owner worker activation state. |
| Worker ledger | Exact old/current logical work that may still execute or produce output. | One packet worker. |
| Certificate | Cold all-participant proof assembled only from coherent publications. | Transition completion owner. |
| Reader grace | Exact-generation quiescent-state proof for every registered worker. | One `quiescence_domain`. |

No region aggregate, queue occupancy estimate, elapsed timeout, or nearby epoch
can substitute for these authorities.

## 4. Boundary Memory and Ownership Placement

One compiled cross-worker edge owns three bounded rings and two owner-local
policy rows. The DATA capacity comes from the plan. CUT and ACK each use the
compile-time capacity `2`, the minimum lawful SPSC capacity; one global
transition permits only one outstanding record in either lane. The physical
rings are transport; sender and receiver policy remain with their packet
workers.

```{uml}
@startuml
skinparam linetype ortho
node "Sender worker / sender NUMA" {
    queue "Source-domain input queues\nActive and future roles" as INPUT
    component "Sender kernel\nStage execution + owner-local ledger" as SK
    component "Sender policy\nSeal old DATA, exact ACK gate\nDrain held prefix before newer output" as SP
    queue "Future-output hold\nN output before ACK\nOldest prefix after ACK\nSender-owned packet records" as HOLD
    queue "ACK ring\nCapacity 2; sender polls" as ACK
    INPUT --> SK
    SK --> SP
    SP --> HOLD
    HOLD --> SP
    ACK --> SP
}
node "Receiver worker / receiver NUMA" {
    queue "DATA ring\nPlan capacity; receiver polls\npacket_record pointer ownership" as DATA
    queue "CUT ring\nCapacity 2; receiver polls\nTarget epoch + final old DATA sequence" as CUT
    component K [
      Receiver kernel
      ----
      Peek and reserve destination capacity
      Pop record and acquire receiver credit
      Complete successful dequeue sequence
      Publish next-stage work
      Own the local epoch ledger
    ]
    component R [
      Receiver policy
      ----
      Validate and latch each exact CUT
      Drain gate: every cut drained + zero old credit
      ACK gate: whole local activation complete
      Publish exact ACK only after both gates
    ]
    queue "Destination staging\nand stage execution" as NEXT
    DATA --> K
    CUT --> R
    K --> R
    R --> K
    K --> NEXT
}
SP --> DATA : packet_record transfer
SP --> CUT
R --> ACK
note bottom of HOLD
  Ring placement follows the polling endpoint.
  Mutable owner rows occupy separate cache lines.
  Both workers may be on the same NUMA node.
  Moving a record does not change its storage domain.
end note
@enduml
```

Each ring is placed with the endpoint that polls it. Mutable sender and receiver
state is cache-line separated and worker-NUMA local. Construction binds stable
addresses and validates boundary, worker, stage-instance, storage-domain, and
ledger membership in both directions. Packet execution performs no provider or
topology lookup.
The boxes may occupy the same NUMA node. Ring placement does not move packet
payloads between pools; the record retains its admitted storage owner.

## 5. One Complete Single-Boundary Transition

The coordinator completes every fallible PREPARE action before commit. Activate
starts the exact reader grace, enters the completion-only state, and publishes
one immutable transition command. Workers observe that command independently at
turn boundaries; there is no global worker barrier.
The sequence follows a passive source worker and a passive TX worker. Active
and asynchronous drain use the additional ownership paths in Section 7.

```{uml}
@startuml
    autonumber
    participant "Coordinator" as C
    participant "Immutable command" as CMD
    participant "Sender worker" as S
    participant "Sender active/future input queues" as I
    participant "Sender future-output hold" as H
    participant "DATA ring" as D
    participant "CUT ring" as K
    participant "Receiver worker" as R
    participant "ACK ring" as A

    C->C: prove PREPARED identity\nstart exact reader grace
    C->CMD: enter COMMITTING and publish TRANSITION E to N
    S->CMD: acquire-observe at a turn boundary
    S->S: preflight and bind target state\nclose old source admission
    S->I: admit new N records to future input queue
    S->D: finish successful E enqueues from old active work
    S->S: require zero old local credit\ncapture final enqueue sequence q
    S->K: publish CUT(N, q)
    S->S: preflight every module, source queue, ledger, and telemetry owner
    S->S: ACTIVATE N and switch telemetry banks
    S->I: rotate future input queue into active role
    S->S: promote ledger and publish activation
    S->S: publish reader safe point after final E read
    S->H: stage N output in finite hold while ACK is absent

    note over K,R: CUT may arrive before R observes the command
    R->CMD: acquire-observe TRANSITION E to N
    R->R: preflight and bind exact target
    R->K: consume CUT only in bounded service
    R->R: validate target N and sequence q
    loop until DATA dequeued through q
        R->D: peek, reserve destination, pop exact record
        D-->R: transfer E record
        R->R: acquire receiver credit before completing dequeue
        R->D: complete exact successful sequence
        R->R: execute and retire E ownership
    end
    R->R: require every inbound cut drained\nand zero old worker credit
    note over R: No outbound boundary in this two-worker sink example
    R->R: activate module views, switch telemetry banks,\npromote ledger, publish activation, mark receiver
    R->A: publish ACK(N, q)
    R->R: publish reader safe point after final E read
    R->R: complete receiver state after ACK ownership transfer

    S->A: consume exact ACK(N, q)
    S->H: borrow oldest held N record
    S->D: enqueue held prefix before newer N output
    S->H: remove each exact accepted record
    S->S: retire transferred N credits
    R->D: receive N under the unchanged exact-active-epoch predicate
    S->S: publish completed sender state after gate open and hold empty
@enduml
```

At receiver begin, a target CUT may already be queued. Only bounded control
service consumes it and validates its target/sequence; stale, skipped,
malformed, foreign, or conflicting CUTs are faults.

The ACK lane must be empty at sender begin: a matching ACK requires that
sender's CUT followed by receiver drain and activation. CUT has no such
precondition because its sender may observe the command first.

## 6. Fan-In Activation

A worker with several inbound boundaries activates once, after every input has
proved the same target transition and its own exact DATA cut.

```{uml}
@startuml
start
partition "Join worker: bounded service turn" {
    :Service DATA from both inputs;
    note right
      Sender A: CUT(N, qA)
      Sender B: CUT(N, qB)
      Each input has its own completed dequeue sequence.
    end note
    :Resolve local E packets, retained work,
    timers, control, PULL, callbacks, and async work;
    if (Both cuts drained, old ledger zero,
    and source admission already N?) then (yes)
        :Seal every outbound E prefix
        and publish every outbound CUT;
        :Preflight and perform one local activation;
        :Mark every inbound receiver activated;
        :Publish ACK(N, qA) to A
        and ACK(N, qB) to B;
    else (not yet)
        :Return to the next bounded turn;
    endif
}
stop
@enduml
```

Arrival order is irrelevant. A receiver records at most one pending CUT per
input and advances only when all inputs agree with the transition. It marks all
inbound receivers activated before publishing the first ACK, so no upstream can
open target DATA against a partially activated fan-in owner.

The worker ledger closes work that is not visible in a DATA ring. A drained ring
alone does not prove that a packet retained by a module, an expired timer callback,
or a pending asynchronous completion has retired.

## 7. Worker Ownership and Active/Async Drain

Each worker changes active-stage admission from `OPEN` to `DRAIN` when it
observes TRANSITION, before advancing its source epoch. DRAIN forbids new loop
origins, timers, copied control messages, pull
readiness, asynchronous begins, and recirculation. Already owned work continues
under its exact epoch until it reaches one terminal disposition.

```{uml}
@startuml
participant "Owner worker" as W
participant "Active scheduler" as A
participant "Module callback" as M
participant "Foreign owner" as F
queue "Completion queue" as Q
participant "Worker ledger / activation" as L

W->A: observe TRANSITION or STOP; enter DRAIN
A->A: close new origins, timers, control, PULL, async begins, and recirculation
A->F: release-publish cancellation for exact live tokens\nforeign owner may query the flag
note over A,M: Already-owned E work remains live\nEach turn services bounded prefixes
loop Bounded owner turns until old work is resolved
    break Cancellation grace expires with unresolved foreign ownership
        A->A: fail stop before collecting another completion prefix
    end
    opt Tracked async work is admitted
        opt Foreign terminal result is ready
            F->Q: publish one terminal outcome
            note over F,Q: SUCCESS after cancellation remains SUCCESS
        end
        A->Q: consume a bounded completion prefix
        Q-->A: exact results; prefix may be empty
        loop Each completion in that prefix
            alt Packet-bound token
                A->A: restore a fresh retained handle before delivery
            else Standalone token
                A->L: retain standalone credit through the callback
            end
        end
    end
    A->A: collect a bounded drain-timer prefix
    loop Active instances in compiled schedule order
        A->W: service pending retained emit / drop / one pending recirculation
        A->A: collect drain handles, queued control, and pending PULL
        opt Queued control messages
            A->M: on_control under exact E\nwithout timer, retained, or async-completion prefixes
        end
        opt At least one trigger remains
            A->M: one RUN with exact E and combined triggers\nbounded timer, retained, and completion prefixes
            M-->A: resolve already-owned work
            A->L: retire callback, completed standalone async,\ntimer, control, and PULL credits after return
            note over A,L: Packet credit stays live while retained or pending disposition owns it
        end
    end
    alt Old work or required inbound cut remains
        W->W: return for the next bounded turn
    else All old work and required cuts are drained
        W->L: permit local activation or continue ordered shutdown
    end
end
@enduml
```

The same ledger credit follows ownership:

- retaining an ingested packet preserves its existing credit;
- emitting transfers the existing credit into ordinary dispatch, dropping
  retires it, and restoring an async packet preserves it under a fresh handle;
- timer, control, pull, and callback work hold a credit through callback return;
- packet-bound asynchronous begin moves the retained credit into a token;
- standalone asynchronous begin acquires before foreign visibility;
- standalone completion retires its credit after owner-worker callback return;
- same-instance recirculation preserves the credit and transfers through the
  bounded pending-disposition path.

Foreign threads can publish only one token completion and may query the
owner-to-foreign cancellation publication. They never publish cancellation,
mutate the ledger, scheduler rows, module context, packet record, or telemetry
bank, and never invoke module callbacks. A completion queue has at least as
many cells as live token slots, so the one winning terminal publisher does not
need a retry loop.

One pending recirculation may enter DRAIN, but DRAIN forbids another cycle.
Capacity bounds outstanding ownership and each turn services bounded prefixes;
neither guarantees that a module or foreign owner finishes. Unresolved work
blocks activation. An expired commit deadline or asynchronous cancellation
grace fails stop without inventing completion.

## 8. Certificate, Grace, and Reclamation

Local ACK completion is necessary but not sufficient to reclaim epoch E. The
global transition completion owner waits for two independent proof legs:

```{uml}
@startuml
start
partition "Observe coherent owner publications" {
    :Read worker activation and zero-old ledgers,
    boundary sender/receiver state, and reader grace;
    if (Coherent contradiction?) then (yes)
        :Fail stop with typed protocol evidence;
        stop
    endif
    if (Execution and boundary leg complete?) then (yes)
        :Publish target activation and enter RETIRING;
    else (missing or older evidence)
        :Return for another bounded probe;
        stop
    endif
    if (Exact reader grace complete
    and final E telemetry aggregated?) then (yes)
    else (not yet)
        :Retain E; return for another bounded probe;
        stop
    endif
}
partition "Reclaim exact old ownership" {
    :Preflight every module and snapshot claim;
    :Claim and RETIRE old module slots
    in reverse canonical order;
    :Retire the old snapshot;
    :Finish grace and publish
    target / target / target;
    :Journal COMPLETE, then publish IDLE;
}
stop
@enduml
```

The certificate reads only frozen membership and coherent owner publications.
Missing or older observations delay progress. They never authorize progress by
minimum, maximum, region aggregation, or inferred equality. The grace is exact
generation QSBR: each registered worker publishes the one adjacent grace after
its final old read.

Entering `RETIRING` does not permit reclamation. Reader grace and old telemetry
aggregation must finish before claim withdrawal. Module retirement follows
reverse canonical context order; snapshot retirement waits for every old module
slot to be empty. No image, provider, or slab is destroyed under unresolved work.

## 9. Backpressure, Timeout, and Shutdown

Backpressure preserves ownership instead of spinning:

- a full DATA ring returns `BACKPRESSURED` with the packet, reservation, and
  credit still together;
- a full CUT or ACK lane retains exactly one pending control record and retries
  once in a later bounded turn;
- target output behind a sealed boundary enters a finite preallocated hold;
- after ACK, the held prefix drains before new target output can overtake it.

Capacity is a memory and liveness bound, never a work-per-turn target. Each turn
services only a burst-bounded prefix in compiled order.

PREPARING and PREPARED may abort without changing live execution. Once commit
publishes, elapsed time never invents completion or restores epoch E. A
COMMITTING deadline failure is fail-stop. A RETIRING grace deadline reached
before the first old-resource claim retains every old object and freezes later
updates. Uncertainty after withdrawal is fail-stop because the complete old
ownership set is no longer representable.

```{uml}
@startuml
!pragma useVerticalIf on
start
:Observe failure, timeout, or shutdown;
if (PREPARING or PREPARED?) then (yes)
    partition "Abort before commit" {
        :Close dispatch and publish cancellation;
        :Collect every accepted result;
        note right: SUCCESS after cancellation is still owned.
        if (Callbacks returned within cancellation grace?) then (yes)
            :RETIRE successful artifacts in reverse ownership order;
            if (Every result and owner is proven?) then (yes)
                :Journal ABORTED;
                :Keep active E and consumed watermarks;
            else (failure or uncertainty)
                :Fail stop; retain uncertain state;
            endif
        else (grace expired)
            :Fail stop; retain uncertain state;
        endif
    }
elseif (COMMITTING deadline or shutdown?) then (yes)
    :Fail stop; do not restore E or reclaim uncertain state;
elseif (RETIRING grace deadline?) then (yes)
    if (Any old ownership already withdrawn?) then (yes)
        :Fail stop;
    else (no)
        :Freeze later updates and retain every old object;
    endif
elseif (RETIRING shutdown?) then (yes)
    :Close and join workers;
    :Deactivate provider I/O;
    if (Reader, callback, and claim ownership
    provable and retirement not frozen?) then (yes)
        :Finish exact retirement;
        :Continue reverse-order teardown;
    else (no)
        :Fail stop without uncertain reclamation;
    endif
else (clean IDLE shutdown)
    :Close sources and drain the worker DAG;
    :Join workers, then retire dependencies;
endif
stop
@enduml
```

Normal shutdown publishes level-triggered `STOP`, closes source polling, and
drains local, boundary, async, and pending-control work. PREPARING/PREPARED
first completes abort; COMMITTING terminates with its evidence intact;
RETIRING can finish only with provable reader/callback/claim ownership. Every
clean path joins workers before I/O deactivation, module finalization, image
unload, or slab destruction.

## 10. Why an Epoch-Only Marker Is Insufficient

An epoch marker on an independent control ring can overtake old DATA queued on a
different ring. If receipt alone activates the receiver, the receiver can run at
N while an epoch-E packet remains behind in DATA. Holding future DATA until an
ACK closes only the forward direction; it does not prove the old prefix drained.

The CUT fixes that missing relation by carrying the final successful old-DATA
enqueue sequence. The receiver cannot activate until its completed dequeue
sequence reaches that exact value and its ledger reports no other old work.

The following is the rejected marker-only design, not a Kinetum execution path:

```{uml}
@startuml
    autonumber
    participant "Sender" as S
    participant "DATA ring" as D
    participant "Independent marker ring" as M
    participant "Hypothetical receiver" as R

    S->D: enqueue packet P at E
    S->M: enqueue marker for N
    note over D: P remains queued
    R->M: observe marker before draining DATA
    R->R: incorrectly activate N from marker alone
    R->D: dequeue P later
    D-->R: packet still belongs to E
    note over R: E packet now meets N execution\nACK-gating future packets did not prevent this
@enduml
```

Separate control lanes permit progress under DATA backpressure. The sequence
watermark orders CUT against DATA without sharing their storage.

## 11. Dual-Version Execution as a Valid Alternative

Packet versioning is a valid way to provide ordinary per-packet configuration
consistency. A packet carries version V, and every stage looks up and executes
`slot[V]`. Old and new packets may interleave at one stage, but one packet still
uses one version end to end.

```{uml}
@startuml
skinparam linetype ortho
package "Dual-version dispatch" as DV {
    component "Packet E" as PE
    component "Lookup packet tag" as L1
    component "Packet N" as PN
    component "Executable slot E" as SE
    component "Executable slot N" as SN
}
package "Ordered-CUT dispatch" as OC {
    component "Drain all owner work at E" as OLD
    component "Bounded quiescent handoff" as HANDOFF
    component "Publish the sole executable view N" as NEW
}

PE --> L1
PN --> L1
L1 --> SE : epoch E
L1 --> SN : epoch N
OLD --> HANDOFF
HANDOFF --> NEW
@enduml
```

Kinetum requires one execution epoch per owner: all E work finishes before N
execution begins. Its two slots hold PREPARED, PUBLISHED, or RETAINED artifacts,
not two selectable packet views. A packet/view epoch mismatch is a fault.

Supporting dual execution here would require every mutable module context,
timer, retained handle, control message, pull bit, asynchronous token,
recirculation path, callback, telemetry publication, and reclamation rule to be
version-aware. Stateful tables such as NAT would also need an explicit rule for
coexisting writes and later merge or retirement. Those are different ownership
semantics, not a small lookup substitution.

For immutable, stateless forwarding on a fixed graph, dual-version dispatch may
be the better trade because it avoids a quiescent owner handoff. Kinetum does
not claim that versioning is incorrect or impossible. Live topology replacement
is outside both the ordered-CUT protocol and the Kinetum 0.1.0 product
contract.

## 12. Invariants, Proof Sketch, and Evidence Map

The safety argument reduces to these invariants:

1. Every worker-owned packet and nonpacket work item has one exact epoch
   credit; a DATA ring owns transferred records between worker handoffs.
2. A sender seals only after old source admission is closed and its own old
   credit is zero.
3. `CUT(N, q)` names the final successful old-DATA enqueue sequence.
4. A receiver activates only after every inbound dequeue sequence reaches its
   exact cut and its old ledger is zero.
5. Every inbound receiver is marked active before the first ACK is published.
6. Target DATA crosses only after the exact ACK opens its sender.
7. The certificate accepts only complete frozen membership and coherent exact
   publications.
8. Old configuration is reclaimed only after the execution/boundary
   certificate leg and the exact reader grace.
9. Old worker and module telemetry is aggregated before the first old-resource
   ownership withdrawal.

From 2 and 3, no old DATA can appear after the cut. From 4, no queued or local
old work remains when the owner publishes N. From 5 and 6, no target DATA reaches
an owner before it has published N. From 1, work outside DATA cannot disappear
from the proof. From 7 and 8, no old object is reclaimed while a participant or
reader can still use it. From 9, the final old-epoch observation is retained
before its underlying banks or module slots can retire.

Primary source anchors:

| Concern | File and symbol |
|---------|-----------------|
| Typed records and validation | `src/dp/epoch/ordered_cut.hpp` |
| Three-ring transport and sequence ownership | `src/dp/epoch/boundary_epoch_channel.hpp::boundary_epoch_channel` |
| Sender seal, ACK gate, and held prefix | `src/dp/epoch/worker_boundary_sender.hpp::worker_boundary_sender` |
| Receiver cut drain and fan-in | `src/dp/epoch/worker_boundary_receiver.hpp::worker_boundary_receiver` |
| Local activation order | `src/dp/epoch/worker_epoch_activation.hpp::worker_epoch_activation` |
| Worker work conservation | `src/dp/epoch/worker_epoch_ledger.hpp::worker_epoch_ledger` |
| Immutable RUN/TRANSITION/STOP command | `src/dp/worker_runtime_command.hpp::worker_runtime_command_publication` |
| Active and tracked-async drain | `src/dp/active/worker_active_stage_scheduler.hpp`, `src/dp/active/worker_async_work.hpp` |
| Global certificate and reader grace | `src/dp/epoch/epoch_transition_certificate.hpp`, `include/kinetum/algo/quiescence.hpp` |
| Reclamation and terminal publication | `src/dp/epoch/epoch_transition_completion.hpp::epoch_transition_completion` |

Physical packet and timing evidence belongs to the release campaign described in
[`VALIDATION_GUIDE.md`](../VALIDATION_GUIDE.md); source and unit evidence do not
substitute for that campaign.
