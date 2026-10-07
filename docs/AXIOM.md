# Axiom

This reference covers pipeline formats, schema, validation, and the
`kinetum_axiom` CLI.

For the architectural framing (how Axiom fits with Gluon and the dataplane),
read [`CONCEPTS.md`](CONCEPTS.md) first.

## Table of Contents

**Part 1: Concepts and Quick Start**

1. [What Axiom Is](#1-what-axiom-is)
2. [Authoring Model](#2-authoring-model)
3. [Pipeline File Formats](#3-pipeline-file-formats)
4. [Minimal Pipeline](#4-minimal-pipeline)

**Part 2: Pipeline Contract**

5. [Schema Reference](#5-schema-reference)
6. [Stage Kinds and Status](#6-stage-kinds-and-status)
7. [Stage Fields](#7-stage-fields)
8. [Edge Fields](#8-edge-fields)
9. [Active Stages](#9-active-stages)
10. [Validation Rules](#10-validation-rules)

**Part 3: Pipeline Examples**

11. [Gateway Stage Roles](#11-gateway-stage-roles)
12. [DAG Pipelines](#12-dag-pipelines)

**Part 4: CLI and Embedding**

13. [CLI](#13-cli)
14. [Embedding Axiom (Programmatic API)](#14-embedding-axiom-programmatic-api)

**Part 5: Cross-Cutting**

15. [Axiom vs Gluon vs Runtime Responsibilities](#15-axiom-vs-gluon-vs-runtime-responsibilities)
16. [Where to Go Next](#16-where-to-go-next)

---

## Part 1: Concepts and Quick Start

### 1. What Axiom Is

Axiom validates declarative pipelines against the platform contract and emits
protobuf text for [`Gluon`](GLUON.md) to plan.

`kinetum_axiom` supplies no missing required contract fields. Pipeline
identity, every stage kind and execution mode, each kind-specific
configuration, and every edge mode must be authored explicitly. Ordinary
protobuf defaults remain part of optional policy fields such as `allow_dag`
and `cost_weight`; missing or foreign required input fails before output is
written.

Axiom validates graph shape, stage kinds, and declaration consistency.
Placement, provider compatibility, host evidence, and runtime configuration
belong to Gluon, the shared provider compiler, Quark, and DP (section 15).

Source: `src/axiom/`. Schema: `proto/kinetum/axiom/v1/axiom.proto`.
Validation rules: `src/axiom/axiom_contract.cpp`.

### 2. Authoring Model

A Kinetum pipeline is a directed graph. Five concepts:

| Term            | What it is                                                                          |
| --------------- | ----------------------------------------------------------------------------------- |
| **Pipeline**    | The top-level container. Has stages, edges, optional control edges, and metadata.   |
| **Stage**       | One packet-processing step. Identified by `stage_id`, typed by `kind`.              |
| **Edge**        | A directed packet-flow connection between two stages.                               |
| **Control edge**| A non-packet directed connection (commands, feedback). Same-region only.      |
| **DAG flag**    | `allow_dag = true` permits multi-ingress / fan-in / fan-out shapes.                 |

The mental model:

- **Axiom** validates that the pipeline graph is shaped correctly.
- **Gluon** binds every stage and logical interface to explicit deployment
  resources, then determines CPU placement and cross-worker boundaries.
- **Dataplane** executes the plan and applies snapshots.

Axiom only sees the pipeline, never the hardware or the snapshots.

### 3. Pipeline File Formats

Axiom accepts two input formats:

| Format    | Extension       | Status                                                                |
| --------- | --------------- | --------------------------------------------------------------------- |
| Protobuf text | `.axiom.pbtxt` | **Primary, recommended for all authoring.**                          |
| MLIR text | `.axiom.mlir`   | Optional. Loaded only when MLIR support is built (`KINETUM_ENABLE_MLIR=ON`). |

The canonical output is always `.axiom.pbtxt`. Author your pipeline as
pbtxt unless you have a specific reason to use MLIR.

Both source forms are read completely under the same 10 MiB ceiling before
their parser allocates.

The dialect option is subordinate to the frontend. On a fresh configure its
default follows `KINETUM_ENABLE_MLIR`: enabling the frontend enables the
dialect unless `KINETUM_ENABLE_MLIR_DIALECT=OFF` is explicit. A frontend-only
build is supported; a dialect-on/frontend-off pair is rejected at configure
time rather than normalized into a different build.

The MLIR frontend is deliberately narrower than the protobuf model. It accepts
only module attributes `pipeline_id` and `allow_dag`, `axiom.core.stage` with
the exact typed attributes for a passive current stage, and
`axiom.core.edge` with explicit `mode = "PUSH"`. Unknown operations or
attributes, active execution, and omitted modes reject. A build without MLIR
returns `FAILED_PRECONDITION` before opening the source path; it does not use a
second parser or approximate conversion.

### 4. Minimal Pipeline

The smallest valid pipeline is RX -> TX:

```protobuf
pipeline_id: "passthrough_v1"

stages {
  stage_id: "rx"
  kind: STAGE_KIND_RX
  execution_mode: EXECUTION_MODE_PASSIVE
  io { interface: "wan0" }
}

stages {
  stage_id: "tx"
  kind: STAGE_KIND_TX
  execution_mode: EXECUTION_MODE_PASSIVE
  io { interface: "lan0" }
}

edges { from_stage_id: "rx" to_stage_id: "tx" mode: EDGE_MODE_PUSH }
```

This is `examples/passthrough/passthrough.axiom.pbtxt` (abbreviated). It
has one ingress, one egress, one edge, and no policy. Useful for baseline
forwarding and integration testing.

RX/TX `interface` values name logical ports resolved by Gluon bindings. Use
identifier-style names such as `wan0` and `lan0`; runtime I/O stream lowering
rejects delimiter-unsafe names before plan publication. See `GLUON.md` for the
deployment-binding contract.

## Part 2: Pipeline Contract

### 5. Schema Reference

The full schema lives in `proto/kinetum/axiom/v1/axiom.proto`. The
top-level message is `Pipeline`:

| Field                  | Type                | Purpose                                                       |
| ---------------------- | ------------------- | ------------------------------------------------------------- |
| `pipeline_id`          | `string`            | Required topology identifier, up to 128 bytes.                 |
| `stages`               | `repeated Stage`    | The processing stages in this pipeline.                       |
| `edges`                | `repeated Edge`     | Directed packet-flow connections.                             |
| `allow_dag`            | `bool`              | Must be true for fan-in or fan-out; false requires a linear graph. |
| `metadata`             | `PipelineMetadata`  | Documentation: display name, description, author, and version. |
| `control_edges`        | `repeated ControlEdge` | Non-packet edges (control / feedback).                     |

### 6. Stage Kinds and Status

Every stage has one current `StageKind`. The enum contains no speculative
future operations.

| Kind                   | Status                                                            |
| ---------------------- | ----------------------------------------------------------------- |
| `STAGE_KIND_RX`        | **Usable.** Packet ingress from a NIC or interface.               |
| `STAGE_KIND_TX`        | **Usable.** Packet egress to a NIC or interface.                  |
| `STAGE_KIND_PARSE_IPV4`| **Usable.** Parses Ethernet/IPv4 facts and available TCP/UDP ports. |
| `STAGE_KIND_MODULE`    | **Usable.** All policy stages (ACL, NAT, QoS, custom) use this.   |
| `STAGE_KIND_UNSPECIFIED`| Required-field sentinel; rejected by Axiom.                     |

Module stages are the extension point. All built-in policies (ACL, NAT,
QoS) and all customer modules use `STAGE_KIND_MODULE` with a typed
`ModuleStageConfig`.

### 7. Stage Fields

The full `Stage` schema:

| Field              | Type              | Purpose                                                                          |
| ------------------ | ----------------- | -------------------------------------------------------------------------------- |
| `stage_id`         | `string`          | Unique topology identifier within the pipeline, up to 128 bytes.                  |
| `kind`             | `StageKind`       | The stage type (see section 6).                                                  |
| `io`               | `IoStageConfig`   | Required oneof member for RX/TX; owns one logical `interface`.                    |
| `module`           | `ModuleStageConfig` | Required oneof member for MODULE; owns `module_id` and optional authoring-time `module_path`. |
| `preferred_region` | `optional int32`  | Hard region pin when present; otherwise Gluon selects placement.                |
| `cost_weight`      | `uint32`          | Relative partition weight. `0` selects the default for the stage kind/module ID. |
| `constraints`      | `StageConstraints`| Exact affinity and anti-affinity relations.                                      |
| `description`      | `string`          | Free-form documentation.                                                         |
| `execution_mode`   | `ExecutionMode`   | Required `PASSIVE` or `ACTIVE`. See section 9.                                   |
| `trigger_mask`     | `uint32`          | Bitmask of `TriggerMode` values. Active stages only. See section 9.              |
| `schedule_order`   | `int32`           | Order within the owning worker's active schedule. Lower = earlier.               |
| `active_stage_limits` | `ActiveStageLimits` | Exact per-instance retained, timer, copied-control, and tracked-async resources. See section 9. |

The configuration oneof is exact: RX/TX require `io`, MODULE requires
`module`, and PARSE_IPV4 requires neither. A configuration belonging to another
kind is rejected; there is no free-form parameter map or alias reader.

Every module configuration also declares `context_selection`:
`MODULE_CONTEXT_SELECTION_SAME_LANE` preserves the matching replica, while
`MODULE_CONTEXT_SELECTION_MODULE` invokes the module's stateless selector on
PUSH entry. The latter selects one permitted context before any storage
transition. The descriptor must declare that selector capability and callback.
PULL and control remain explicit same-worker relations.

`StageConstraints` (placement and resources):

| Field                     | Purpose                                                  |
| ------------------------- | -------------------------------------------------------- |
| `affinity_stages`         | Stages that must be co-located in the same region.       |
| `anti_affinity_stages`    | Stages that must **not** be co-located.                  |

Each target must exist and differ from the declaring stage. Relations are
undirected normalized pairs: a pair is authored once and cannot appear in both
lists.

### 8. Edge Fields

An `Edge` defines packet flow between two stages:

| Field           | Type        | Purpose                                                              |
| --------------- | ----------- | -------------------------------------------------------------------- |
| `from_stage_id` | `string`    | Source stage. Must reference an existing stage.                      |
| `to_stage_id`   | `string`    | Destination stage. Must reference an existing stage.                 |
| `condition`     | `string`    | Optional conditional forwarding expression.                          |
| `priority`      | `int32`     | Order of evaluation when multiple edges leave the same stage.        |
| `mode`          | `EdgeMode`  | Required `PUSH` or `PULL`.                                           |

**Condition syntax**: `<field> <op> <value>`

| Field        | Meaning                                  |
| ------------ | ---------------------------------------- |
| `dscp`       | DSCP field of the IP header.             |
| `src_ip`     | IPv4 source address as an integer.       |
| `dst_ip`     | IPv4 destination address as an integer.  |
| `src_port`   | L4 source port.                          |
| `dst_port`   | L4 destination port.                     |
| `proto`      | L4 protocol number.                      |
| `flow_hash`  | Flow hash value.                         |

| Op   | Meaning                |
| ---- | ---------------------- |
| `==` | Equal to               |
| `!=` | Not equal to           |
| `<`  | Less than              |
| `<=` | Less than or equal     |
| `>`  | Greater than           |
| `>=` | Greater than or equal  |

The value must be a complete decimal `uint32` literal. Negative values,
overflow, mixed-format values, and trailing non-whitespace text are rejected.

Example: `dscp >= 46` routes Expedited Forwarding traffic.

Edge `priority` must be in the range `[-1000, 1000]` for both conditional
and unconditional edges.

**Edge mode**:

- `PUSH` means the upstream stage drives work.
- `PULL` means the downstream stage requests work from the upstream.
- `EDGE_MODE_UNSPECIFIED` is rejected; omission is not interpreted as PUSH.
- `PULL` edges must be **same-region only**. Cross-region edges are
  always `PUSH`.
- Both ends of a `PULL` edge must be active stages. The downstream active
  callback requests work from the upstream active callback.
- One exact endpoint pair has at most one `PULL` relation; the runtime owns one
  deduplicated request bit for that relation.

**Control edges** (`ControlEdge`) are separate from packet edges. They
carry commands or feedback, not packets, and do not participate in the
packet-DAG topological sort.

| Field           | Type                  | Purpose                                                |
| --------------- | --------------------- | ------------------------------------------------------ |
| `from_stage_id` | `string`              | Source of the control message.                         |
| `to_stage_id`   | `string`              | Consumer of the control message.                       |
| `subtype`       | `ControlEdgeSubtype`  | `CONTROL_EDGE_GENERIC` or `CONTROL_EDGE_FEEDBACK`.     |

Control edges must remain in the same region.

An exact endpoint pair has one control edge. Its subtype maps directly to the
SDK message classification (`KINETUM_CONTROL_SUBTYPE_GENERIC` or
`KINETUM_CONTROL_SUBTYPE_FEEDBACK`); a sender cannot relabel that edge per
message.

### 9. Active Stages

Set `execution_mode` on each `stages { ... }` entry in the pipeline's
`.axiom.pbtxt` file. The two values are `EXECUTION_MODE_PASSIVE` and
`EXECUTION_MODE_ACTIVE`; an omitted or unspecified mode rejects. The canonical
`examples/fan_in_edge_gateway/fan_in_edge_gateway.axiom.pbtxt`
sets every stage to `EXECUTION_MODE_PASSIVE`.

Most stages are **passive**: they run only when a packet reaches them.
**Active stages** are scheduled by their sole owner worker when an authored
LOOP, timer, PULL, or control trigger is present. This enables timer-driven
emitters, queue-owning schedulers, aggregators, and modules that hand bounded
work to a foreign completion engine under exact tokens. An active stage without
LOOP is event-driven rather than invoked on every worker turn.

**Required for active stages**:

- `execution_mode = EXECUTION_MODE_ACTIVE`
- `kind = STAGE_KIND_MODULE` (active stages must be module-backed)
- `module` must carry a non-empty `module_id`
- `trigger_mask` must include at least one `TriggerMode` value

`TriggerMode` is a bitmask:

| Mode                         | Value | Meaning                                                  |
| ---------------------------- | ----- | -------------------------------------------------------- |
| `TRIGGER_MODE_LOOP`          | 1     | Run on every owner-worker turn.                          |
| `TRIGGER_MODE_TIMER`         | 2     | Run when one or more timers expire.                      |
| `TRIGGER_MODE_PULL_READY`    | 4     | Run when a downstream PULL consumer requests data.       |
| `TRIGGER_MODE_CONTROL`       | 8     | Run when a control message arrives.                      |

If a stage declares `TRIGGER_MODE_PULL_READY`, it must also have at least
one outbound `PULL` edge.

`ActiveStageLimits` is replicated exactly for each emitted stage/lane instance:

| Field                            | Purpose                                                  |
| -------------------------------- | -------------------------------------------------------- |
| `retained_packet_capacity`       | Maximum records owned through opaque retained handles.  |
| `retained_byte_capacity`         | Aggregate payload bytes represented by those handles.   |
| `timer_capacity`                 | Maximum owner-local timers for the instance.             |
| `control_mailbox_capacity`       | Power-of-two copied-message count for one instance.      |
| `control_message_capacity_bytes` | Maximum copied payload bytes in each control message.    |
| `async_work_capacity`            | Maximum simultaneously live foreign-work tokens.         |
| `async_cancel_grace_ms`          | Monotonic fail-stop grace after transition/shutdown cancellation. |

Retained packet and byte capacities are either both zero or both nonzero;
nonzero byte capacity is at least packet capacity. TIMER is present exactly
when timer capacity is nonzero. CONTROL is present exactly when both control
capacities are valid and an inbound active-to-active control edge exists.
PULL_READY is present exactly when an outbound PULL edge exists. Both PULL
endpoints are active, and current control and PULL execution is same-worker
only; Gluon and runtime compilation prove that placement after partitioning.
Async capacity and cancellation grace are either both zero or both nonzero.
When live transitions are enabled, Gluon and runtime compilation require the
grace to be strictly shorter than `EpochTransitionPlan.commit_timeout_ms`.
The module image must declare `KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK` exactly
when its active instance carries those resources; capability without resources,
or resources without capability, rejects before provider effects.

**Passive stages** must be the symmetric opposite:

- `trigger_mask` must be `0`
- `schedule_order` must be `0`
- All `active_stage_limits` fields must be `0`

Axiom rejects any passive stage that declares active-only fields.

The runtime derives each [worker loop](DATA_PLANE.md#stage-modes-and-worker-loops)
from the stages assigned to it. Synchronous-active and tracked-async name those
loop variants; they are not additional `execution_mode` values.

### 10. Validation Rules

Axiom runs multiple validation passes and fails on the first violation.
Grouped logically (the actual execution order is in `verify_contract` at
`src/axiom/axiom_contract.cpp`):

#### Identity and limits

- `pipeline_id` and every `stage_id` match the shared topology-identifier
  grammar and stay within 128 bytes.
- Total stages <= **256**.
- Packet edges plus control edges <= **1024** in aggregate.

#### Topology

- Every edge's `from_stage_id` and `to_stage_id` resolves to a defined stage.
- At least one stage with `STAGE_KIND_RX` and at least one with `STAGE_KIND_TX`.
- **No cycles.** Always rejected, regardless of `allow_dag`.
- No orphan stages (every stage has at least one inbound or outbound edge,
  excluding the obvious RX/TX terminals).
- Every stage is reachable from some RX, and every stage can reach some TX.
- If `allow_dag = false`: the pipeline must be a single linear chain with
  exactly one ingress and one egress. `--allow-dag` relaxes this; cycles
  and connectivity rules are not relaxed.

#### Edge semantics

- Each `condition` parses against the grammar in section 8.
- Every edge has `priority` checked in the range `[-1000, 1000]`, including
  unconditional edges.
- An exact duplicate of all five packet-edge fields rejects. An endpoint pair
  may repeat only when its mode, condition, or priority carries distinct
  semantics.
- `PULL` edges require active source and destination stages.
- A `PULL` endpoint pair is unique.

#### Stage semantics

- Every stage declares one current kind, explicit execution mode, and the exact
  kind-owned configuration described in section 7.
- Unknown numeric kinds and every `*_UNSPECIFIED` sentinel reject before graph
  state is allocated.
- Affinity targets exist, self-relations reject, and duplicate or contradictory
  normalized pairs reject.
- Every path from an RX stage to a stage whose `module_id` is in
  `{kinetum.acl, kinetum.nat44, kinetum.qos}` must cross a
  `STAGE_KIND_PARSE_IPV4` stage. A parser on an unrelated branch is not
  sufficient. Custom modules do not trigger this dependency.

#### Active-stage rules

- Active stages must use `STAGE_KIND_MODULE`.
- Active stages must have a non-empty typed `module_id`.
- Active stages must declare a non-zero `trigger_mask`.
- `TRIGGER_MODE_PULL_READY` requires at least one outbound `PULL` edge.
- Retained packet/byte capacities obey both-or-neither and bytes-at-least-packets.
- TIMER exactly matches nonzero timer capacity.
- CONTROL exactly matches a power-of-two mailbox, nonzero payload bound, and an inbound active control edge.

#### Passive-stage rules

- Passive stages must have `trigger_mask = 0`.
- Passive stages must have `schedule_order = 0` and all active limits zero.

#### Control edges

- Both endpoints must reference defined active stages.
- Axiom validates exact endpoint identity, active mode, subtype, and one edge
  per endpoint pair. Gluon enforces same-region placement after partitioning;
  the shared runtime compiler then proves one same-worker lane-local owner.
- Control edges are not part of the packet-DAG cycle check.

## Part 3: Pipeline Examples

### 11. Gateway Stage Roles

The canonical `examples/fan_in_edge_gateway/fan_in_edge_gateway.axiom.pbtxt`
uses three logical regions:

| Stages | Kind | Placement and purpose |
| --- | --- | --- |
| `rx0`, `rx1` | RX | Receive `wan0` and `wan1` in regions 0 and 1. |
| `parse0`, `parse1` | PARSE_IPV4 | Parse each ingress before its ACL. |
| `acl0`, `acl1` | MODULE | Independent `kinetum.acl` contexts on the ingress workers. |
| `nat` | MODULE | Select the `kinetum.nat44` session owner in region 2. |
| `qos` | MODULE | Apply `kinetum.qos` on the selected NAT lane. |
| `tx` | TX | Send through that lane's `lan0` queue. |

Axiom requires every RX path to the built-in ACL, NAT44, and QoS modules to
cross an IPv4 parser. A missing parser or an unparsed bypass fails admission.
The two ACL stages share one configuration identity but own separate state.

### 12. DAG Pipelines

`allow_dag = true` permits non-linear topologies - multi-ingress fan-in,
multi-egress fan-out, conditional branches. Cycles and connectivity rules
are still enforced.

`examples/fan_in_edge_gateway/fan_in_edge_gateway.axiom.pbtxt` is the canonical
fan-in edge gateway example:

```{uml}
@startuml
skinparam linetype ortho
left to right direction

rectangle "wan0\nLogical ingress" as WAN0
rectangle "wan1\nLogical ingress" as WAN1
package "Region 0" {
    component "rx0\nRX\n----\nRegion 0" as RX0
    component "parse0\nPARSE_IPV4" as PARSE0
    component "acl0\nkinetum.acl" as ACL0
    RX0 -left-> PARSE0
    PARSE0 -left-> ACL0
}
package "Region 1" {
    component "rx1\nRX\n----\nRegion 1" as RX1
    component "parse1\nPARSE_IPV4" as PARSE1
    component "acl1\nkinetum.acl" as ACL1
    RX1 -left-> PARSE1
    PARSE1 -left-> ACL1
}
package "Region 2" {
    component "nat\nkinetum.nat44\n----\nSelected session owner" as NAT
    component "qos\nkinetum.qos" as QOS
    component "tx\nTX" as TX
    NAT -left-> QOS
    QOS -left-> TX
}
rectangle "lan0\nLogical egress" as LAN

WAN0 --> RX0
WAN1 --> RX1
ACL0 --> NAT
ACL1 --> NAT
TX -left-> LAN
@enduml
```

The `allow_dag: true` pipeline joins the two ingress chains at NAT. The default
profile has three workers and two boundaries. RSS2 replicates each region and
connects all four ACL contexts to both NAT contexts: six workers and eight
boundaries. Each packet selects one NAT owner. Live updates drain every inbound
CUT and all local old work before activation and ACK; fixed bootstrap uses DATA
only.

To compile a DAG pipeline, pass `--allow-dag` to `kinetum_axiom`.

## Part 4: CLI and Embedding

### 13. CLI

```
kinetum_axiom --in <input> --out <output> [--format pbtxt|mlir] [--allow-dag]
```

| Flag             | Purpose                                                                    |
| ---------------- | -------------------------------------------------------------------------- |
| `--in <path>`    | Input pipeline file (`.pbtxt` or `.mlir`). **Required.**                   |
| `--out <path>`   | Output validated pipeline (`.axiom.pbtxt`). **Required.**                  |
| `--format <fmt>` | Force input format (`pbtxt` or `mlir`). Auto-detected from extension.       |
| `--allow-dag`    | Permit non-linear topologies (multi-ingress, fan-out). Cycles still rejected. |
| `-h`, `--help`   | Show usage.                                                                |

Exit codes: `0` success, `1` validation error, `2` usage error.

Examples:

```bash
# Linear pipeline
kinetum_axiom --in pipeline.pbtxt --out pipeline.axiom.pbtxt

# DAG pipeline
kinetum_axiom --in fan_in.pbtxt --out fan_in.axiom.pbtxt --allow-dag

# Force MLIR input (only when KINETUM_ENABLE_MLIR=ON)
kinetum_axiom --in pipeline.mlir --out pipeline.axiom.pbtxt --format mlir
```

### 14. Embedding Axiom (Programmatic API)

CI tools, IDEs, and custom validators can embed Axiom directly. Its `src/axiom/`
headers and libraries are source-tree interfaces, outside the installed SDK.

| API | Header | Use |
| --- | --- | --- |
| `canonical_topological_order(const Pipeline&)` | `src/axiom/axiom_contract.hpp` | Validates bounded stage/edge structure, exact references, and acyclicity, then returns the deterministic smallest-ready-stage-first order. |
| `verify_contract(const Pipeline&, const contract_options&)` | `src/axiom/axiom_contract.hpp` | Runs contract validation and returns a `Status`. |
| `load_pipeline_pbtxt(path, contract_options)` | `src/axiom/axiom_pbtxt_io.hpp` | Strictly parses pbtxt and returns only a fully verified exact pipeline. |
| `load_pipeline_mlir(path, contract_options)` | `src/axiom/axiom_mlir_frontend.hpp` | Parses the enabled exact MLIR subset, lowers typed fields, and returns only a fully verified pipeline. |

`canonical_topological_order()` is the single graph-order authority consumed by
Gluon partitioning and provider-topology compilation. It is deliberately
structural: callers that require ingress/egress, connectivity, supported stage
kinds, active/passive rules, or semantic dependencies also call
`verify_contract()`.

`contract_options` exposes the two topology gates separately:

| Option | Meaning |
| --- | --- |
| `require_linear_pipeline` | Reject DAG shape when true. |
| `require_single_ingress_egress` | Reject multi-ingress or multi-egress shape when true. |

Default-constructed `contract_options` leaves both gates false. The CLI tightens
both requirements to true by default; passing `--allow-dag` sets both to false.
Library callers can set the two options independently. For DAG authoring, the pipeline
should also set `allow_dag: true`; the CLI supplies the relaxed contract options
with `--allow-dag`.

Both file loaders preserve authored values. They never inject an identity,
execution mode, edge mode, stage configuration, or graph relation.

Validation status codes are intentionally coarse:

| Code | Typical causes |
| --- | --- |
| `INVALID_ARGUMENT` | Malformed structure: empty or duplicate IDs, duplicate complete packet edges, dangling edges, cycles, missing RX/TX, multi-ingress/egress when forbidden, size limits, invalid edge conditions, edge priority outside `[-1000, 1000]`, invalid active/passive fields, or invalid pull/control references. |
| `FAILED_PRECONDITION` | The graph is well-formed but unsuitable for the requested contract: unreachable stages, dead ends, non-linear shape when linearity is required, or a built-in module dependency such as ACL/NAT44/QoS without `PARSE_IPV4`. |
| `RESOURCE_EXHAUSTED` | Allocation failed while building bounded validation or topological-order state. |
| `OUT_OF_RANGE` | A validation or graph container extent is not representable on the host. |
| `NOT_FOUND` | The requested input file cannot be opened. |

Validation returns one typed pass/fail status. There is no parallel statistics
API, serialized validation cache, or warning message in the Axiom schema.

## Part 5: Cross-Cutting

### 15. Axiom vs Gluon vs Runtime Responsibilities

Use the rejecting component to locate a validation failure:

| Concern                                       | Owner    |
| --------------------------------------------- | -------- |
| Pipeline graph shape (cycles, reachability, kinds) | Axiom    |
| Typed stage configuration and edge-condition grammar | Axiom    |
| Active / passive stage rules                       | Axiom    |
| Built-in module dependencies (e.g., PARSE_IPV4)    | Axiom    |
| Unknown or unspecified stage-kind rejection             | Axiom    |
| Region placement, CPU core assignment              | Gluon    |
| Cross-worker boundary computation                  | Gluon    |
| Exact stage, logical-port, queue, storage, and provider binding | Gluon |
| Provider-graph structural and access compatibility | Shared provider compiler |
| CPU/NUMA host compatibility evidence               | Quark    |
| Module loading and configuration                   | Dataplane |
| Snapshot validation and epoch transitions          | Control plane + dataplane |

Axiom is intentionally narrow. It does not know which CPU cores you have,
which provider instances and driver-local ports are bound, or what your
snapshot looks like. Those checks happen in Gluon, the shared provider
compiler, Quark, and the runtime.

### 16. Where to Go Next

| If you want to...                                | Read                                           |
| ------------------------------------------------ | ---------------------------------------------- |
| Plan a pipeline                                  | [`GLUON.md`](GLUON.md)                         |
| Run an end-to-end deployment                     | [`GETTING_STARTED.md`](GETTING_STARTED.md)     |
| Write a custom module                            | [`MODULE_SDK.md`](MODULE_SDK.md)               |
| Understand the dataplane that runs the pipeline  | [`DATA_PLANE.md`](DATA_PLANE.md)                 |
| Read the architectural overview                  | [`CONCEPTS.md`](CONCEPTS.md)                   |
