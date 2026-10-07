# gRPC API

This reference covers `ControlService` for external clients and
`DataplaneService` for CP-to-DP communication: message schemas, idempotency, CAS,
transition identity, authentication, and client generation.

For the architectural framing, read [`CONCEPTS.md`](CONCEPTS.md) first.
For the implementation behaviors behind each RPC, see
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md)
and [`DATA_PLANE.md`](DATA_PLANE.md). For the canonical operator tool
that uses this contract, see [`KINETUMCTL.md`](KINETUMCTL.md).

## Table of Contents

**Part 1: Wire Model and Common Types**

1. [What gRPC API Is](#1-what-grpc-api-is)
2. [Authoring Model](#2-authoring-model)
3. [Common Types (`common.proto`)](#3-common-types-commonproto)

**Part 2: Service References**

4. [ControlService Reference](#4-controlservice-reference)
5. [DataplaneService Reference](#5-dataplaneservice-reference)

**Part 3: Message Schemas**

6. [Configuration Schema](#6-configuration-schema)
7. [Telemetry Schemas](#7-telemetry-schemas)
8. [Guardrails Policy Schema](#8-guardrails-policy-schema)

**Part 4: Cross-Cutting**

9. [Idempotency, CAS, and Exact Transition Identity](#9-idempotency-cas-and-exact-transition-identity)
10. [Authentication and TLS](#10-authentication-and-tls)
11. [Source-Tree Client Generation](#11-source-tree-client-generation)
12. [Owner Map](#12-owner-map)
13. [Where to Go Next](#13-where-to-go-next)

---

## Part 1: Wire Model and Common Types

### 1. What gRPC API Is

Kinetum's wire surface is two gRPC services plus a small set of shared
common types:

| Service           | Where it runs            | Who calls it                                                   |
| ----------------- | ------------------------ | -------------------------------------------------------------- |
| `ControlService`  | Inside `kinetum_cp`      | `kinetumctl` and explicit custom clients                       |
| `DataplaneService`| Inside `kinetum_dp`      | CP owns mutations and telemetry consumption; `kinetumctl health --service dp` may inspect typed readiness directly. |

The two service protos that define them are
`proto/kinetum/control/v1/control.proto` and
`proto/kinetum/dataplane/v1/dataplane.proto`. Shared status types live in
`proto/kinetum/common/v1/common.proto`, and the one shared observation schema
lives in `proto/kinetum/telemetry/v1/telemetry.proto`.

This reference describes schemas and populated fields. Implementation guides
cover mutation ordering, snapshot apply, guardrails decisions, and DP transitions:

> **Wire contract:** `ControlService` exposes nine operator RPCs over durable CP
> authority. `DataplaneService` exposes startup Bootstrap, exact
> Prepare/Activate/pre-commit-Abort/Status transitions, complete telemetry,
> Health, and typed unavailable lifecycle/debug calls. Successful responses are
> application-status canonical and identity-complete; failures retain no
> success payload. All [worker loop variants](DATA_PLANE.md#stage-modes-and-worker-loops)
> share one transition wire; execution and drain remain worker-owned.

| Behavior question                                | Read                                                                    |
| ------------------------------------------------ | ----------------------------------------------------------------------- |
| What does the CP single-writer thread do?        | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| What does guardrails do with `GuardrailsPolicy`? | Same                                                                    |
| What does DP do during transition RPC admission? | [`DATA_PLANE.md`](DATA_PLANE.md)                                       |
| Boundary protocol semantics                      | [`DATA_PLANE.md`](DATA_PLANE.md) + [`diagrams/ordered_cut_boundary_protocol.md`](diagrams/ordered_cut_boundary_protocol.md) |

#### 1.1 Schema roles

Not all protobuf messages appear on the wire:

| Class                      | Examples                                                                                       | Where they live                                                  |
| -------------------------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| **Wire and shared RPC protos** | `control.proto`, `dataplane.proto`, `common.proto`, `telemetry.proto`                        | On the wire. **This doc covers these.**                          |
| **Artifact messages** | `axiom.proto` (`Pipeline`), `gluon/plan.proto` (`DeploymentPlan`), `gluon/bindings.proto` (`DeploymentBindings`), `hw/hardware.proto` | Pipeline, plan, binding, and inventory files. Telemetry imports plan enums, but does not transmit the deployment messages. See [`AXIOM.md`](AXIOM.md), [`GLUON.md`](GLUON.md). |
| **Module authoring protos** | `src/modules/{acl,nat44,qos}/*.proto`                                                         | Host/offline authoring models. Built-in runtime images parse strict JSON `config_blob` bytes without linking generated descriptor registries. Documented in [`MODULE_SDK.md`](MODULE_SDK.md). |
| **Private persistence** | `control/internal/v1/transition_authority.proto` | CP's durable authority envelope; no RPC or installed SDK surface. |

Two seams matter:

- `plan.pipeline` (a `Pipeline` from `axiom.proto`) is embedded inside
  `DeploymentPlan` and read from disk by tooling. It does not transit
  any gRPC RPC.
- `ModuleConfig.config_blob` (in `control.proto`) carries module-owned
  configuration bytes through `SetConfigSnapshot`. The platform preserves
  their exact identity without parsing; each image owns its strict parser and
  compiler.

### 2. Authoring Model

A few concepts shape every RPC in this contract:

| Term                  | Meaning                                                                                              |
| --------------------- | ---------------------------------------------------------------------------------------------------- |
| **Service**           | A named collection of RPCs. We have two: `ControlService` and `DataplaneService`.                    |
| **RPC**               | A request/response method. All RPCs in v1 are **unary** (single request -> single response). v1 has no streaming RPC. |
| **Message**           | A typed proto message used as request, response, or embedded payload.                                |
| **Wire status**       | The gRPC transport status (e.g., `OK`, `UNAVAILABLE`, `DEADLINE_EXCEEDED`). Reflects whether the call reached the server and returned a response. |
| **Application status**| The embedded `kinetum.common.v1.Status` field inside most response messages. Reflects whether the **operation** succeeded. |
| **Idempotency key**   | A caller-chosen string that lets the server safely deduplicate retries. See section 9.1.             |
| **CAS check**         | `expected_revision` field on mutating RPCs; rejects the mutation if the current revision does not match. See section 9.2. |
| **Exact transition identity** | CP-allocated epoch, mutation sequence, validation hash, and idempotency key carried through the `DataplaneService` lifecycle. See section 9.3. |

**All RPCs are unary in v1.** Server-streaming, client-streaming, and
bidirectional streaming are outside this contract.

### 3. Common Types (`common.proto`)

`proto/kinetum/common/v1/common.proto` defines types shared by both
services.

#### 3.1 `Status`

Operation responses carry a common `Status` field. CP `HealthCheck` is the one
deliberate exception: it returns its own serving-state enum rather than an
operation envelope. The common struct is:

| Field         | Type            | Purpose                                                                                                  |
| ------------- | --------------- | -------------------------------------------------------------------------------------------------------- |
| `code`        | `int32`         | Numeric outcome. `0` is success; non-zero is an error. Values `0-16` align with gRPC canonical codes; platform internals may also carry Kinetum-specific `100+` codes. |
| `error_code`  | `ErrorCode`     | Semantic classification paired exactly with `code` in first-party responses. `UNSPECIFIED` is a rejecting sentinel. |
| `message`     | `string`        | Human-readable bounded error summary. Clients sanitize it before terminal or log emission.                |
| `details`     | `string`        | Optional bounded operation-specific diagnostic context. Its text never selects behavior.                 |

Three precise notes for SDK implementers:

- After validating the code/error pair, `code == 0` means success. Values
  `1..16` use gRPC's numeric meanings. The declared platform codes
  `POOL_EXHAUSTED=102` and `MODULE_ERROR=104` pair with
  `ERROR_CODE_RESOURCE_EXHAUSTED` and `ERROR_CODE_INTERNAL`, respectively.
- Current CP and DP producers populate the canonical code/error relation,
  including `ERROR_CODE_OK` for success. Exact clients reject UNSPECIFIED,
  unknown fields/enums, or diagnostics beside
  success before reading operation payload.
- `message` and `details` carry bounded diagnostics only on failure. A success
  carrying either is malformed at exact first-party boundaries.

#### 3.2 `ErrorCode` enum

`ErrorCode` enumerates 18 values total. The first
(`ERROR_CODE_UNSPECIFIED`) is the proto3 default and is **not** an
error in itself; the remaining 17 names semantically correspond to the
gRPC canonical codes:

| Value                              | Meaning                                                                |
| ---------------------------------- | ---------------------------------------------------------------------- |
| `ERROR_CODE_UNSPECIFIED` (0)       | Default sentinel with no semantic outcome; invalid in an exact first-party response. |
| `ERROR_CODE_OK` (1)                | Success.                                                               |
| `ERROR_CODE_CANCELLED` (2)         | Operation cancelled by the caller.                                     |
| `ERROR_CODE_UNKNOWN` (3)           | Unknown error.                                                         |
| `ERROR_CODE_INVALID_ARGUMENT` (4)  | Bad request shape.                                                     |
| `ERROR_CODE_DEADLINE_EXCEEDED` (5) | Operation timed out.                                                   |
| `ERROR_CODE_NOT_FOUND` (6)         | Requested resource missing.                                            |
| `ERROR_CODE_ALREADY_EXISTS` (7)    | Resource already exists.                                               |
| `ERROR_CODE_PERMISSION_DENIED` (8) | Caller lacks authorization.                                            |
| `ERROR_CODE_RESOURCE_EXHAUSTED` (9)| Quota or capacity exhausted.                                           |
| `ERROR_CODE_FAILED_PRECONDITION` (10) | Operation cannot proceed in current state.                          |
| `ERROR_CODE_ABORTED` (11)          | Operation aborted (e.g., concurrent modification).                     |
| `ERROR_CODE_OUT_OF_RANGE` (12)     | Argument out of valid range.                                           |
| `ERROR_CODE_UNIMPLEMENTED` (13)    | RPC or feature not implemented.                                        |
| `ERROR_CODE_INTERNAL` (14)         | Server-side internal error.                                            |
| `ERROR_CODE_UNAVAILABLE` (15)      | Service temporarily unavailable; retry may help.                       |
| `ERROR_CODE_DATA_LOSS` (16)        | Unrecoverable data loss.                                               |
| `ERROR_CODE_UNAUTHENTICATED` (17)  | Caller's credentials missing or invalid.                               |

Do not cast `ErrorCode` enum numbers to `Status.code` numbers. The
`ErrorCode` enum reserves zero for `UNSPECIFIED`, so its numeric values
are shifted by one from gRPC canonical code numbers. Snapshot mutations
and DP transitions populate both fields through the shared canonical mapper.
Aggregate statistics also populate `ErrorCode` on locally produced failures and
preserve a valid DP failure classification. First-party clients require the
exact numeric/semantic relation, so success is `code == 0` with
`ERROR_CODE_OK`; UNSPECIFIED, contradictory, or undeclared combinations are
malformed rather than successful.

#### 3.3 Response Status Pattern

RPCs with an application envelope have **two status layers**. CP `HealthCheck`
uses the serving-state exception described above:

| Layer              | Source                                              | What it tells you                                                           |
| ------------------ | --------------------------------------------------- | --------------------------------------------------------------------------- |
| Wire (gRPC) status | `grpc::Status` returned by the stub call            | Did the RPC reach the server and return a response, or fail in transport?   |
| Application status | `Status` field embedded in the response message     | Did the **operation** succeed, or did the server reject it semantically?    |

Transport `OK` may carry application rejection, such as invalid snapshot, CAS
mismatch, or missing snapshot. Admit the response envelope and check **both**:

```cpp
auto wire_status = stub->SetConfigSnapshot(&ctx, req, &resp);
if (!wire_status.ok()) {
    // Wire-level failure (network, deadline, server crash).
    return wire_status.error_message();
}
auto application = kinetum::common::validate_control_response_envelope(
    resp, resp.status(), "SetConfigSnapshotResponse");
if (!application.is_ok()) {
    return std::string(application.error().message()); // Malformed response.
}
if (application.value() != kinetum::common::status_code::OK) {
    // First require every operation-specific success field to be clear.
    return std::string(resp.status().message());
}
// Both layers are canonical; now validate the operation-specific success identity.
```

`validate_control_response_envelope` is the in-tree C++ mechanism, not a
generated wire method. Other clients must enforce the same code/error-class,
unknown-field, success-diagnostic, and operation-field rules in their language.

When wire status is non-OK, the response body may not be populated at all.
Every non-null ControlService handler clears its response first. A wire-OK
application failure therefore carries status only; success fields are absent or
default and are not observations. Clients must also reject unknown fields,
undeclared enum values, noncanonical status, and success diagnostics before
interpreting operation-specific payload.

CP and DP treat allocation or representation-size failure while constructing a
final response as transport `UNAVAILABLE`; any partially built response body is
not authoritative. A mutation client retains the complete request and its
idempotency key, then follows the same retry/status reconciliation rules as any
other ambiguous transport result. Unexpected exceptions at either server
boundary are process-fatal rather than being converted into a fabricated
application response.

#### 3.4 Schema closure

`common.proto` owns `ErrorCode`, the four-field `Status` message, and
`LoggingStatus` shared by both health responses.
RPC-specific empty requests, pagination tokens, identities, timestamps, and
durations live in their owning service schema instead of a generic utility
vocabulary.

#### 3.5 `LoggingStatus`

| Field | Number | Type | Contract |
| --- | --- | --- | --- |
| `destination` | 1 | `DestinationState` | Required non-UNSPECIFIED availability observation. |
| `accepted_records` | 2 | optional uint64 | Owned diagnostic admissions. |
| `queue_rejections` | 3 | optional uint64 | Refusals under capacity or admission contention. |
| `format_rejections` | 4 | optional uint64 | Construction or native-input refusals. |
| `unavailable_rejections` | 5 | optional uint64 | Refusals while the file destination is unavailable. |
| `undelivered_records` | 6 | optional uint64 | Accepted records without complete file delivery. |
| `write_failures` | 7 | optional uint64 | Failed file operations. |
| `console_failures` | 8 | optional uint64 | Failed mirror or emergency stderr delivery. |
| `truncated_records` | 9 | optional uint64 | Accepted diagnostics with marked truncation. |
| `failure` | 10 | string | First current outage cause, at most 255 printable ASCII bytes. |
| `packet_thread_rejections` | 11 | optional uint64 | Native records refused before cold work on packet-owner threads. |
| `delivery_timeouts` | 12 | optional uint64 | Expired file-confirmation waits; does not imply undelivered bytes. |

Every counter requires explicit presence, including zero. Unknown fields,
undeclared states, and inconsistent destination/cause evidence reject.
`AVAILABLE` carries no current cause; `UNAVAILABLE` requires a cause and a
positive write-failure count. `CLOSED` records retired file ownership. Counters
are sampled independently while emitters run, so clients must not impose a live
sum equation. Destination availability does not change service readiness.
See [Logging](LOGGING.md) for file, rotation, and loss semantics.

## Part 2: Service References

### 4. ControlService Reference

`ControlService` (declared in `control.proto`) is implemented by the CP
process (`src/cp/cp_grpc.cpp`). It listens on the address configured
by Photon's `--cp-listen` flag (default `127.0.0.1:50051`).

The nine RPCs group into five purposes:

#### 4.1 Snapshot management

| RPC                  | Request -> Response                                                                                  |
| -------------------- | ---------------------------------------------------------------------------------------------------- |
| `SetConfigSnapshot`  | `SetConfigSnapshotRequest` -> `SetConfigSnapshotResponse`. Submit a new snapshot with a required idempotency key and optional commit-confirmed timeout and revision CAS. |
| `ListSnapshots`      | `ListSnapshotsRequest` -> `ListSnapshotsResponse`. Stateless bounded listing bound to exact corpus and active authority. |
| `GetActiveSnapshot`  | `GetActiveSnapshotRequest` -> `GetActiveSnapshotResponse`. Retrieve the currently active snapshot.   |
| `Rollback`           | `RollbackRequest` -> `RollbackResponse`. Roll back to a target snapshot. Supports per-module selective rollback. |

Key request fields:

**`SetConfigSnapshotRequest`**:

| Field                 | Type              | Purpose                                                                  |
| --------------------- | ----------------- | ------------------------------------------------------------------------ |
| `snapshot`            | `ConfigSnapshot`  | The snapshot to apply. See section 6.                                    |
| `idempotency_key`     | `string`          | Required 1..256-byte printable-ASCII retry identity for a live snapshot mutation. See section 9.1. |
| `confirm_timeout_ms`  | `uint64`          | Commit-confirmed timeout. `0` (default) disables. CP rejects values above the current `uint32_t` control-loop limit. See section 4.2. |
| `expected_revision`   | `optional int64`  | Presence-qualified CAS, including exact zero. Absence skips. See section 9.2. |

**`SetConfigSnapshotResponse`**:

| Field         | Type     | Purpose                                                          |
| ------------- | -------- | ---------------------------------------------------------------- |
| `status`      | `Status` | Operation outcome.                                               |
| `snapshot_id` | `string` | Echo of the applied snapshot ID.                                 |
| `revision`    | `int64`  | Exact active snapshot content revision.                           |
| `epoch`       | `uint64` | Exact CP-allocated epoch completed by the dataplane.             |

Snapshot identity/revision syntax errors are `INVALID_ARGUMENT`. Raw input or
canonical output above the shared 10 MiB bound is `RESOURCE_EXHAUSTED` before
corpus publication, allocator advancement, or DP transport. The production
control-only stopped-loop gate returns `UNAVAILABLE` before inspecting an
operator payload; packet-ready production drives the mutation to exact terminal
DP truth.

**`ListSnapshotsRequest`**:

| Field          | Type            | Purpose                                      |
| -------------- | --------------- | -------------------------------------------- |
| `page_size`    | `uint32`        | Required bound in `1..256`. |
| `page_token`   | `string`        | Empty first-page input or bounded opaque continuation returned by the prior page. |

**`ListSnapshotsResponse`**:

| Field             | Type                    | Purpose                                      |
| ----------------- | ----------------------- | -------------------------------------------- |
| `snapshots`       | `repeated SnapshotInfo` | Snapshot summaries.                          |
| `status`          | `Status`                | Operation outcome.                           |
| `next_page_token` | `string`                | Empty at the exact end; otherwise the next-page authority. |
| `total_count`     | `uint64`                | Complete logical corpus-plus-active projection count. |

**`SnapshotInfo`**:

| Field             | Type            | Purpose                                      |
| ----------------- | --------------- | -------------------------------------------- |
| `snapshot_id`     | `string`        | Snapshot identifier.                         |
| `revision`        | `int64`         | Snapshot content revision.                   |
| `created_unix_ms` | `int64`         | Creation timestamp.                          |
| `is_active`       | `bool`          | Whether this is the active snapshot.         |
| `description`     | `string`        | Human-readable change notes.                 |
| `author`          | `string`        | Operator or tool that created the snapshot.  |

`config_store::list_snapshot_page()` derives strict ID order under one shared
store lock and marks the active row from the atomic durable authority. The
versioned token binds immutable corpus content, active identity, both
watermarks, plan hash, and last emitted key. Malformed/noncanonical tokens
reject before store work; a changed listing returns `ABORTED`, never an empty
or mixed page. The server retains no cursor state.

**`RollbackRequest`** has selective rollback support:

| Field                 | Type              | Purpose                                                                  |
| --------------------- | ----------------- | ------------------------------------------------------------------------ |
| `snapshot_id`         | `string`          | Target snapshot to roll back to.                                         |
| `module_ids`          | `repeated string` | Per-module rollback. Empty = roll back all modules. Listed = hybrid snapshot using target's config for those modules and current's config for the rest. **Constraint**: current and target snapshots must contain the same module ID set, and every requested module must exist in the target. The handler does not compare the full pipeline graph because `ConfigSnapshot` carries module configs, not the Gluon plan graph. |
| `idempotency_key`     | `string`          | Required 1..256-byte printable-ASCII durable retry identity.             |
| `expected_revision`   | `optional int64`  | Presence-qualified active-revision CAS.                                  |

While an unconfirmed PendingConfirm exists, only a full rollback to its exact
retained rollback snapshot is admissible. A selective rollback creates a new
hybrid snapshot identity and therefore cannot satisfy that promise.

#### 4.2 Commit-confirmed pattern

| RPC             | Request -> Response                                                                          |
| --------------- | -------------------------------------------------------------------------------------------- |
| `ConfirmConfig` | `ConfirmConfigRequest` -> `ConfirmConfigResponse`. Confirms a pending configuration, preventing auto-rollback. |

With an active baseline, apply using `confirm_timeout_ms > 0`, verify behavior,
and call `ConfirmConfig` before the deadline. Otherwise CP rolls back to the
previous snapshot. Without an active snapshot, there is no rollback target and
the apply rejects.
See [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md)
for the full lifecycle.

`ConfirmConfigRequest`:

| Field         | Type     | Purpose                                                                |
| ------------- | -------- | ---------------------------------------------------------------------- |
| `snapshot_id` | `string` | Snapshot to confirm; must match the pending confirm record.            |
| `epoch`       | `uint64` | Required exact epoch assigned at apply time.                           |
| `revision`    | `optional int64` | Required exact active revision. Presence distinguishes valid zero from omission. |
| `idempotency_key` | `string` | Required 1..256-byte printable-ASCII retry identity.               |

`ConfirmConfigResponse`:

| Field                | Type     | Purpose                                                          |
| -------------------- | -------- | ---------------------------------------------------------------- |
| `status`             | `Status` | Operation outcome.                                               |
| `snapshot_id`        | `string` | Echo of confirmed snapshot.                                      |
| `time_remaining_ms`  | `uint64` | Positive first-success remainder, replayed exactly on retry.     |
| `epoch`              | `uint64` | Exact confirmed epoch.                                           |
| `revision`           | `optional int64` | Exact confirmed revision; success retains presence at zero. |

A first call at or after the durable deadline returns `DEADLINE_EXCEEDED`.
The first success is one durable replacement retaining key digest and remaining
time; an exact response-loss retry returns the same fields even after the
deadline or beside a later safety intent. Another key or identity fails. An
unconfirmed record cannot cross a durable rollback intent. The terminal
confirmation remains until the next successful epoch allocation clears it
atomically.

#### 4.3 Guardrails

| RPC                   | Request -> Response                                                                  |
| --------------------- | ------------------------------------------------------------------------------------ |
| `ConfigureGuardrails` | `ConfigureGuardrailsRequest` -> `ConfigureGuardrailsResponse`. Push a new policy.    |
| `GetGuardrails`       | `GetGuardrailsRequest` -> `GetGuardrailsResponse`. Retrieve the current policy.      |

`ConfigureGuardrailsRequest` carries the complete `policy`, a required bounded
`idempotency_key`, and presence-qualified `expected_policy_generation` (zero
before the first policy). Omission is malformed rather than another spelling
of generation zero. Retry classification precedes generation CAS: same key/hash returns
retained success, same key/different hash conflicts, a new stale generation
fails, and an exact next generation performs one durable replacement.
`ConfigureGuardrailsResponse` returns `policy_generation` plus the raw SHA-256
of deterministic validated policy bytes only on success.

`GetGuardrailsResponse` represents unconfigured state as success with no policy,
generation zero, and no hash. A configured enabled or explicitly disabled
policy is present with nonzero generation and exact 32-byte hash. The runner
reads a coherent RCU projection published only after that durable write. See
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md)
for the runner state machine.

#### 4.4 Observability

| RPC        | Request -> Response                                                                       |
| ---------- | ----------------------------------------------------------------------------------------- |
| `GetStats` | `StatsRequest` -> `StatsResponse`. CP validates active configuration against one successful DP observation and forwards the shared telemetry payload unchanged. |

`StatsRequest`:

| Field                           | Type   | Purpose                                                   |
| ------------------------------- | ------ | --------------------------------------------------------- |
| `selection`                     | `TelemetrySelection` | Shared optional-row selection forwarded byte-for-byte to DP. |

`TelemetrySelection` is defined once in `telemetry.proto`; Section 7.1 lists
its ten flags. CP implements an all-or-nothing aggregate boundary. It clears
its response, forwards that message, and maps fields only after both the DP
transport and the shared DP application-status classifier report success. A
missing channel, transport failure, caught DP-call exception, explicit application failure,
or malformed `code == 0` plus a non-success error classification returns status only; CP
does not publish even its own active snapshot identity on that path. Failure to
represent that status-only result instead returns transport `UNAVAILABLE`. On
success, `active_config` carries CP-owned revision and snapshot ID;
`telemetry` is the one validated `RuntimeTelemetry` received from DP. CP
requires active snapshot/revision/epoch and plan-hash agreement before copying
it. See Section 7 for the complete shared schema.

#### 4.5 Health

| RPC           | Request -> Response                                                                  |
| ------------- | ------------------------------------------------------------------------------------ |
| `HealthCheck` | `HealthCheckRequest` -> `HealthCheckResponse`. Liveness check for orchestrators.     |

`HealthCheckResponse` carries a `Status` enum (`STATUS_UNSPECIFIED`,
`STATUS_SERVING`, `STATUS_NOT_SERVING`), the CP `version` string,
`uptime_seconds`, and required `logging` at field 4. This is a CP-side health probe, distinct from
`DataplaneService.Health` (section 5.3).

Both health responses use `kinetum.common.v1.LoggingStatus`. It carries the
destination state, accepted/rejected/undelivered record counts, file and console
failures, truncation counts, and the bounded first outage cause. Every counter
requires presence, including zero. Unknown or missing evidence rejects; a valid
unavailable logging destination does not change serving or packet readiness.
See [Logging](LOGGING.md#6-failure-and-health) for the complete field meanings.

### 5. DataplaneService Reference

> **Internal CP-to-DP backchannel.** `src/dp/dataplane_control_service.cpp`
> implements `DataplaneService`, registered only after complete runtime
> materialization. Mutation remains internal to CP. Operators use `ControlService`;
> the read-only `Health` RPC is also exposed by `kinetumctl health --service dp`
> at an explicitly supplied DP endpoint.

`DataplaneService` listens on the address configured by Photon's
`--dp-endpoint` flag (default `127.0.0.1:50052`). Its 11 RPCs group into
transition lifecycle, telemetry, process lifecycle, and diagnostics.

#### 5.1 Exact configuration-transition lifecycle

| RPC | Request -> Response |
| --- | --- |
| `BootstrapConfigSnapshot` | `BootstrapConfigSnapshotRequest` -> `BootstrapConfigSnapshotResponse`. Restore CP's exact durable active state before packet admission. |
| `PrepareConfigSnapshot` | `PrepareConfigSnapshotRequest` -> `PrepareConfigSnapshotResponse`. Prepare one CP-allocated transition without changing live execution. |
| `ActivateConfigSnapshot` | `ActivateConfigSnapshotRequest` -> `ActivateConfigSnapshotResponse`. Commit the exact prepared transaction; completion includes retirement. |
| `AbortPreparedConfigSnapshot` | `AbortPreparedConfigSnapshotRequest` -> `AbortPreparedConfigSnapshotResponse`. Cancel only the matching pre-commit transaction. |
| `GetEpochTransitionStatus` | `GetEpochTransitionStatusRequest` -> `GetEpochTransitionStatusResponse`. Reconcile one exact transaction identity. |

All five responses carry application `Status`. Valid request/response pointers
normally produce gRPC `OK`; null direct-handler inputs produce transport-level
`INVALID_ARGUMENT`, and response-construction exhaustion produces transport
`UNAVAILABLE` with no authoritative body. `BootstrapConfigSnapshot` is implemented against the one
materialized runtime. It validates CP's durable record against the exact
verified plan and snapshot on the producer, enqueues one fixed command record,
and waits unconditionally while the main/coordinator thread prepares and
owner-activates every module context. That consumer publishes the fixed epoch
and both allocator high watermarks coherently, then returns `COMPLETE` with the
exact restored epoch and raw validation hash. A retry before completion must be
byte-identical to the first admitted request; after `PACKET_READY`, every
Bootstrap call returns application `UNAVAILABLE` for that process generation.

Every handled non-null transition response carries canonical status
and non-`UNSPECIFIED` `identity_resolution` and `failure_code`. Only
`ACTIVE_EXACT`/`TERMINAL_EXACT` carry transition state and operation-specific
identity/results; rejection clears them.

PREPARED means all artifacts and post-commit resources passed admission. Status
reports the measured prepare duration and an informational Unix projection of
the monotonic lease. Pre-commit abort, failure, timeout, lease expiry, and
shutdown retire owned results before ABORTED. During preparation cleanup,
Status/retries return status-only `UNAVAILABLE`; held Prepare/Abort calls get
the terminal result. The progress projection resumes at terminal IDLE.

Activate starts reader grace before COMMITTING and publishes one worker
command. RETIRING reports active/last-activated N while retaining E; COMPLETE
requires retirement and N for all three runtime epochs, followed by IDLE.
The first Activate context remains held through COMPLETE or update freeze;
exact retries observe the same transaction without another trigger.

Cancellation never erases a successful callback result. Exceeded cancellation
grace fails stop. A RETIRING grace timeout before ownership withdrawal freezes
updates with E retained; uncertainty after withdrawal fails stop. Preparation,
certificate, and reclamation mechanics are specified in
[DP transition admission](DATA_PLANE.md#7-exact-transition-rpc-admission-dp-side).

`EpochTransitionState` is the exact externally observable state machine:

| Value | Number | Meaning |
| --- | ---: | --- |
| `EPOCH_TRANSITION_STATE_UNSPECIFIED` | 0 | Required zero sentinel; not a valid materialized transition state. |
| `EPOCH_TRANSITION_STATE_AWAITING_BOOTSTRAP` | 1 | Control surface is ready and durable bootstrap has not completed. |
| `EPOCH_TRANSITION_STATE_BOOTSTRAPPING` | 2 | Exact startup restoration is in progress. |
| `EPOCH_TRANSITION_STATE_PREPARING` | 3 | Fallible immutable preparation is in progress. |
| `EPOCH_TRANSITION_STATE_PREPARED` | 4 | Preparation completed and remains abortable. |
| `EPOCH_TRANSITION_STATE_COMMITTING` | 5 | Ordered commit is completion-only. |
| `EPOCH_TRANSITION_STATE_RETIRING` | 6 | Activation completed; old exact state remains retained. |
| `EPOCH_TRANSITION_STATE_COMPLETE` | 7 | Retirement completed and the transaction is terminal-successful. |
| `EPOCH_TRANSITION_STATE_FAILED_STOP` | 8 | A completion-only safety fault stopped forwarding. |
| `EPOCH_TRANSITION_STATE_ABORTED` | 9 | A pre-commit transaction ended without activation. |
| `EPOCH_TRANSITION_STATE_IDLE` | 10 | Bootstrap or the latest transaction is complete; no transition owns the global token. |

`EpochTransitionIdentityResolution` is the message-independent relation between
the requested identity and DP truth:

| Value | Number | Meaning |
| --- | ---: | --- |
| `..._UNSPECIFIED` | 0 | Malformed sentinel; never emitted by a handled call. |
| `..._INVALID` | 1 | Request identity or wire shape is malformed. |
| `..._ADMISSIBLE` | 2 | Both allocations advance and no generation conflicts. |
| `..._ACTIVE_EXACT` | 3 | Identity names the active transaction. |
| `..._TERMINAL_EXACT` | 4 | Identity names one retained terminal result. |
| `..._STALE` | 5 | At least one allocation is below its high watermark. |
| `..._INCONSISTENT` | 6 | One allocation equals while the other advances. |
| `..._EXPIRED_RETRY` | 7 | Equal watermarks have no retained journal identity. |
| `..._IDENTITY_CONFLICT` | 8 | Allocation/key is retained for different exact content. |
| `..._UNKNOWN_FUTURE` | 9 | Status queried a never-admitted advancing identity. |
| `..._OVERLAP` | 10 | Another transaction owns the global token. |
| `..._POLICY_DISABLED` | 11 | The compiled runtime has no live-transition policy. |
| `..._STATE_UNAVAILABLE` | 12 | Current phase cannot admit/resolve the attempted operation. |

`EpochTransitionFailureCode` supplies the typed cause. `UNSPECIFIED` is always
malformed; `NONE` is explicit success/no-failure. The remaining values are
`EXPLICIT_ABORT`, `SHUTDOWN_ABORT`, `PREPARE_FAILURE`, `PREPARE_CANCELLED`,
`PREPARE_DEADLINE_EXCEEDED`, `PREPARED_LEASE_EXPIRED`,
`COMMIT_DEADLINE_EXCEEDED`, `CERTIFICATE_CONTRADICTION`,
`RETIREMENT_GRACE_DEADLINE_EXCEEDED`, `RETIRE_CALLBACK_FAILURE`,
`RETIRE_CALLBACK_DEADLINE_EXCEEDED`, `COMMIT_SHUTDOWN`, and
`PROTOCOL_FAULT`, at compact numbers 2 through 14 in that order. Only the
retirement-grace code is an update-frozen RETIRING outcome; the other
post-commit causes are fail-stop.

`BootstrapConfigSnapshotRequest`:

| Field | Type | Purpose |
| --- | --- | --- |
| `snapshot` | `ConfigSnapshot` | CP's durable active snapshot; serialized input is bounded to 10 MiB. |
| `active_epoch` | `uint64` | Exact nonzero active epoch to restore. |
| `allocated_epoch_high_watermark` | `uint64` | Greatest epoch identity CP has durably allocated. |
| `mutation_sequence_high_watermark` | `uint64` | Greatest durable mutation sequence. |
| `plan_content_hash` | `string` | Required 64-character lowercase canonical plan SHA-256. |
| `idempotency_key` | `string` | Exact bootstrap retry identity: 1..256 printable ASCII bytes. |

`BootstrapConfigSnapshotResponse` carries `status`, `restored_epoch`, an exact
raw 32-byte `validation_hash`, `transition_state`, and both restored high
watermarks.

`PrepareConfigSnapshotRequest`:

| Field | Type | Purpose |
| --- | --- | --- |
| `snapshot` | `ConfigSnapshot` | Complete snapshot to validate and prepare; serialized input is bounded to 10 MiB. |
| `target_epoch` | `uint64` | Exact nonzero CP-allocated target epoch; zero is never auto-assignment. |
| `idempotency_key` | `string` | Exact retry identity bound to this content: 1..256 printable ASCII bytes. |
| `mutation_sequence` | `uint64` | Exact nonzero CP-allocated mutation sequence. |

`PrepareConfigSnapshotResponse` carries `status`, `prepared_epoch`, an exact raw
32-byte `validation_hash`, `prepared_lease_deadline_unix_ms`, and the echoed
`mutation_sequence`, followed by `transition_state` (field 6),
`identity_resolution` (7), and `failure_code` (8). Prepared-only fields are
nonzero/nonempty only for exact PREPARED.

Activate, Abort, and Status requests all carry the same exact identity tuple:

| Field | Type | Purpose |
| --- | --- | --- |
| `epoch` | `uint64` | Exact target epoch returned by Prepare. |
| `validation_hash` | `bytes` | Exact raw 32-byte canonical snapshot SHA-256 digest. |
| `idempotency_key` | `string` | Original 1..256-byte printable-ASCII retry identity. |
| `mutation_sequence` | `uint64` | Original CP-allocated mutation sequence. |

`ActivateConfigSnapshotResponse` carries `status`, `completed_epoch`,
`transition_state`, `transition_duration_ns`, `mutation_sequence`,
`identity_resolution` (field 6), and `failure_code` (7). Completion-only fields
exist only for exact COMPLETE. `AbortPreparedConfigSnapshotResponse` carries
`status`, `transition_state`, `mutation_sequence`, `identity_resolution` (4),
and `failure_code` (5). `GetEpochTransitionStatusResponse` carries `status`,
`transition_state`, `from_epoch`, `to_epoch`, an exact raw 32-byte
`validation_hash`, `plan_content_hash`, prepare/commit/retirement durations,
bounded diagnostic-only `failure_reason`, `mutation_sequence`,
`identity_resolution` (12), and `failure_code` (13).

Canonical hashing and identity bounds are shared contracts across CP and DP.
Bootstrap and live transitions consume the same
exact canonical representation. Oversized DP Prepare input/canonical output is
`RESOURCE_EXHAUSTED`. Request envelopes reject unknown fields recursively before
mailbox admission, and a retained idempotency-key digest cannot name a different
identity. CP response admission independently rejects unknown fields/enums,
UNSPECIFIED typed values, status mismatch, field residue, or inexact identity
echoes before reconciliation.

#### 5.2 Telemetry

| RPC        | Request -> Response                                                              |
| ---------- | -------------------------------------------------------------------------------- |
| `GetStats` | `StatsRequest` -> `StatsResponse`. DP-side telemetry. CP calls this for `ControlService.GetStats`. |

The merged DP service clears first and validates `selection`. It claims the
exact generation-scoped source, collects one coherent snapshot, maps the shared
payload, validates that payload again, and publishes application success last.
A missing/torn/temporally misaligned observation returns `UNAVAILABLE`; a
coherent identity contradiction or malformed provider/publication result
returns `DATA_LOSS`; bounded mapping allocation returns
`RESOURCE_EXHAUSTED`. Every failure is status-only.

Runtime, engine, transition, and protocol-fault summaries are mandatory in
every successful response. The ten optional families are emitted exactly when
selected. Stream rows carry owner-published software transfer/rejection counters
with required explicit presence, including measured zero. Port and storage
observations carry typed availability and use optional
presence: `UNSUPPORTED` and `READ_FAILED` are complete observations with no
numeric tuple, never zero counters. Collection invokes no provider callback
from a packet worker and holds no platform lock across foreign code.

#### 5.3 Lifecycle (Health, Drain, DrainStatus, Shutdown)

| RPC           | Request -> Response                                                              |
| ------------- | -------------------------------------------------------------------------------- |
| `Health`      | `HealthRequest` -> `HealthResponse`. DP health probe with state, worker counts, and version fields. |
| `Drain`       | Declared `DrainRequest` -> `DrainResponse`; returns application `UNAVAILABLE` without acting. |
| `DrainStatus` | Declared `DrainStatusRequest` -> `DrainStatusResponse`; returns application `UNAVAILABLE` without selecting an operation. |
| `Shutdown`    | Declared `ShutdownRequest` -> `ShutdownResponse`; returns application `UNAVAILABLE`; process shutdown is signal-owned. |

`HealthResponse.State` distinguishes process readiness from drain/shutdown
lifecycle state:

| Value                 | Meaning                                                        |
| --------------------- | -------------------------------------------------------------- |
| `STATE_UNSPECIFIED`   | Default; not a real state.                                     |
| `STATE_STARTING`      | Process initialization is in progress.                        |
| `STATE_CONTROL_READY` | Control RPCs are serving, but packet execution is unavailable. |
| `STATE_PACKET_READY`  | Exact bootstrap and packet-runtime admission are complete.     |
| `STATE_DRAINING`      | Graceful drain is in progress.                                |
| `STATE_DRAINED`       | All queues drained; ready for shutdown.                        |
| `STATE_STOPPING`      | Shutdown is in progress.                                      |
| `STATE_STOPPED`       | Shutdown is complete.                                         |
| `STATE_ERROR`         | Fatal/error posture, including inability to report valid packet-runtime health. |

`STATE_CONTROL_READY` is not packet readiness. Supervisors and packet-test
entry points must wait for `STATE_PACKET_READY` before admitting traffic.
The current service emits `STATE_CONTROL_READY`, `STATE_PACKET_READY`, or
`STATE_ERROR`. The other declared lifecycle states do not become synthetic
observations while coordinated drain and RPC-driven shutdown are unavailable.

The one merged service implements `Health` from the runtime's immutable
single-writer status publication. It reports application success with exact
`STATE_CONTROL_READY` before bootstrap or `STATE_PACKET_READY` after the
complete fixed-epoch commit. If a coherent read is temporarily unavailable, it
reports `STATE_ERROR` plus application `UNAVAILABLE`; it never repairs a
partial observation from mutable worker or store state.
Coherent invalid contents instead report `STATE_ERROR` plus `DATA_LOSS`.

`HealthResponse` contains state, application status, `active_epoch`,
active/expected workers, product version, `runtime_generation`, and required
`logging` at field 12. At
`CONTROL_READY`, the exact nonzero process generation and expected worker
population are known while active workers and active epoch are zero. At
`PACKET_READY`, active equals expected and `active_epoch` is exact nonzero
runtime truth. A failed response retains only `STATE_ERROR`, canonical status,
product version, and the independent process logging observation.

`DrainRequest` carries an absolute Unix-millisecond `deadline_unix_ms`. The
current merged service clears the response and returns transport `OK` plus
application `UNAVAILABLE`; it does not read, store, echo, or act on the
request. Runtime teardown is signal-driven and owned by `dp_main`, not by a
service-local state machine. The exact module ABI declares no Drain/Shutdown
RPC callbacks; module-generation coordination is platform-owned.

`DrainRequest`:

| Field              | Type     | Purpose                                      |
| ------------------ | -------- | -------------------------------------------- |
| `drain_id`         | `string` | Caller-supplied correlation/idempotency key. |
| `deadline_unix_ms` | `int64`  | Absolute wall-clock deadline reserved by the unavailable coordinated-drain request; the merged service does not consume it. |
| `force`            | `bool`   | Force-drain request bit; the merged service does not consume it. |

`DrainResponse`:

| Field                       | Type                   | Purpose                                      |
| --------------------------- | ---------------------- | -------------------------------------------- |
| `status`                    | `Status`               | Operation outcome.                           |
| `state`                     | `HealthResponse.State` | Current lifecycle state.                     |
| `packets_remaining`         | `uint64`               | Packets left to drain. Default and nonsemantic on the current non-OK response. |
| `drain_started_unix_ms`     | `int64`                | Drain start timestamp.                       |
| `drain_completed_unix_ms`   | `int64`                | Completion timestamp, or `0` if incomplete. |
| `drain_id`                  | `string`               | Echo of the request `drain_id`.              |

`DrainStatusRequest` declares a `drain_id` field for querying a specific drain
operation. While coordinated drain is unavailable, the handler does not inspect
that value and returns the same explicit application-level refusal.

`ShutdownRequest.force` and `reason` are likewise unconsumed. `Shutdown`
clears its response and returns transport `OK` plus application `UNAVAILABLE`;
RPC input cannot bypass the signal-owned process teardown path.

#### 5.4 Debugging

| RPC         | Request -> Response                                                                       |
| ----------- | ----------------------------------------------------------------------------------------- |
| `DumpState` | Declared `DumpStateRequest` -> `DumpStateResponse`; returns application `UNAVAILABLE` without inspecting or emitting debug state. |

The request schema declares `include_nat_table`, `include_acl_cache`, and
`max_entries`, and the response schema declares `nat_sessions[]` plus
`acl_cache_json`. The merged service clears the response and returns transport
`OK` plus application `UNAVAILABLE`; empty fields are not a successful empty
dump.

## Part 3: Message Schemas

### 6. Configuration Schema

Configuration on the wire is the `ConfigSnapshot` message in
`control.proto`. Every snapshot is the **atomic unit** of
configuration update: all module configurations within a snapshot are
applied together at one epoch boundary.

#### 6.1 `ConfigSnapshot`

| Field                | Type                       | Purpose                                                  |
| -------------------- | -------------------------- | -------------------------------------------------------- |
| `snapshot_id`        | `string`                   | Unique snapshot identifier.                              |
| `revision`           | `int64`                    | Snapshot content revision. Generated selective rollback advances the current revision; full rollback retains the target revision and advances only the DP epoch. |
| `created_unix_ms`    | `int64`                    | Creation timestamp.                                      |
| `modules`            | `repeated ModuleConfig`    | Exact plan module set; canonical order is `module_id`.    |
| `description`        | `string`                   | Human-readable change notes.                             |
| `author`             | `string`                   | Operator who created the snapshot.                       |
| `parent_snapshot_id` | `string`                   | Content ancestry; selective rollback retains the original active snapshot here for exact retry reconstruction. |
| `labels`             | `map<string, string>`      | Arbitrary labels; deterministic serialization orders keys. |
| `content_hash`       | `string`                   | Optional lowercase SHA-256 claim; canonical output normalizes it. |

Canonical transition identity rejects an input or canonical output above
10 MiB and rejects unknown fields anywhere in the protobuf message tree. The
expected module set comes from `DeploymentPlan.pipeline`: a missing, unknown,
or duplicate module ID is invalid. `modules[]` is the one explicitly set-like
repeated field and is sorted by `module_id`; label-map keys use deterministic
protobuf order. Other repeated fields preserve their authored order. New fields
are hash-covered and order-contractual by default unless their owning contract
explicitly declares them volatile or set-like.

The snapshot's supplied `content_hash`, when nonempty, is a claim to verify. The
canonical preimage clears that self-referential field, recomputes every module
hash, and uses mandatory SHA-256 over deterministic protobuf bytes. Canonical
output stores the recomputed lowercase claim, while the raw 32-byte
`validation_hash` carried by the transition lifecycle remains transaction
authority. Deterministic serialization assumes Kinetum's pinned protobuf
runtime and one-tree CP/DP build; it is not a cross-version wire canonical form.

Snapshot lifecycle is not mirrored inside immutable content. Active and
transition state live in CP's atomic durable authority; `SnapshotInfo.is_active`
is its read projection.

#### 6.2 `ModuleConfig` (pure mechanism)

| Field          | Type     | Purpose                                                                                       |
| -------------- | -------- | --------------------------------------------------------------------------------------------- |
| `module_id`    | `string` | Matches `Stage.module.module_id` in the pipeline definition.                                  |
| `revision`     | `int64`  | Module-policy revision carried by this snapshot.                                              |
| `config_blob`  | `bytes`  | Opaque configuration. The platform routes exact bytes; the module owns parsing and compilation. |
| `content_type` | `string` | Type hint (e.g., `"application/json"`). Informational only - platform does not parse. |
| `content_hash` | `string` | Optional 64-character lowercase SHA-256 claim over exact `config_blob` bytes; canonical output recomputes it. |
| `schema_id`    | `string` | Schema identifier hint (e.g., `"kinetum.module.acl.v1.AclRuleset"`). Informational only.      |

The platform hashes `config_blob` bytes without parsing them, even if they
resemble protobuf unknown-field tags. Each module owns its runtime parser and
optional host/offline authoring schema. Built-ins in 0.1.0:
`kinetum.acl`, `kinetum.nat44`, `kinetum.qos`. See
[`MODULE_SDK.md`](MODULE_SDK.md) for the module-side schema and
loading contract.

#### 6.3 Configuration authority boundaries

`ConfigSnapshot` contains module policy and snapshot metadata only. It has no
generic runtime-knob message. Provider burst limits, attachment behavior, and
I/O configuration are compiled plan facts; ACL strategy and other module policy
belong inside the exact module `config_blob`; worker and transition capacities
belong in the deployment plan.

A client changes module policy by submitting a complete snapshot through
`SetConfigSnapshot` or by selecting retained content through `Rollback`.
Changing provider topology requires a newly planned deployment artifact, not a
partial ControlService patch.

### 7. Telemetry Schemas

`proto/kinetum/telemetry/v1/telemetry.proto` owns observations;
`control.proto` and `dataplane.proto` only wrap that payload. Every field has a
producer, and unavailable optional evidence stays absent rather than zero-filled.

#### 7.1 Selection and service wrappers

Both `StatsRequest` wrappers contain exactly one field:

| Field | Number | Type | Meaning |
| --- | ---: | --- | --- |
| `selection` | 1 | `TelemetrySelection` | Explicit exact optional-row selection. Missing selection and unknown fields reject. |

`TelemetrySelection` has ten independent booleans:

| Field | Number | Selected rows |
| --- | ---: | --- |
| `include_stage_stats` | 1 | `stages[]` |
| `include_module_metrics` | 2 | `module_counters[]`, `module_histograms[]`, and `module_epoch_mismatches[]` |
| `include_module_health` | 3 | `module_health[]` |
| `include_worker_epoch_stats` | 4 | `workers[]` |
| `include_region_epoch_stats` | 5 | `regions[]` |
| `include_boundary_epoch_stats` | 6 | `boundaries[]` |
| `include_stream_stats` | 7 | `streams[]` |
| `include_storage_domain_stats` | 8 | `storage_domains[]` |
| `include_port_stats` | 9 | `ports[]` |
| `include_topology_stats` | 10 | `steering_profiles[]` and `module_context_domains[]` |

The DP `StatsResponse` is `{status=1, telemetry=2}`. The CP response is
`{status=1, active_config=2, telemetry=3}`; `active_config` contains
`revision=1` and `snapshot_id=2`. A non-OK status makes
every payload unavailable and the producer clears it. Mandatory summary
families do not need selection flags.

#### 7.2 Mandatory runtime and engine summaries

`RuntimeTelemetry` always carries `runtime`, `engine`, `transition`, and
`protocol_faults`. `RuntimeObservation` contains exact runtime/status
publication generations, active/minimum-retained/last-activated epochs,
active/expected worker counts, collection time, latest completed-bank time,
and cumulative skipped-publication count. A successful row requires packet
readiness, all expected workers, and causal timestamps.

`EngineStats` contains only counters with real owner-worker producers:

| Field | Meaning |
| --- | --- |
| `rx_packets`, `rx_bytes` | Physical provider ingress prefix admitted into runtime ownership. |
| `tx_packets`, `tx_bytes` | Provider-accepted transmit prefix only; retries cannot double-count. |
| `dropped_packets` | Exactly-once terminal record retirement. |
| `fanout_overflow` | Refused additional fan-out branches for which no record was created. |

All are cumulative within `runtime_generation`. A generation change resets a
consumer's delta baseline; regression inside one generation is malformed.

#### 7.3 Transition, certificate, and grace summaries

`EpochTransitionTelemetry` carries the coordinator publication generation,
typed phase, last globally complete active epoch, current target, both allocation
high watermarks, exact 32-byte plan hash, exact 32-byte
`active_validation_hash`, frozen participant counts, terminal history size,
retirement-freeze state, and optional current/latest transaction, certificate,
and grace records. The active hash is paired with the coordinator active epoch:
both remain E throughout RETIRING and change to N only at exact COMPLETE.

CP and DP watermarks are normally equal at a stable observation. One startup
relation is intentionally adjacent: CP persists a new epoch/mutation pair before
its first Prepare, so durable `ALLOCATED`, pre-admission `ABORT_PENDING`, or its
terminal `ABORTED` result may lead an idle surviving DP by exactly one pair.
Status then resumes the request or verifies the local terminal abort. Every
DP-admitted phase requires equality; no general lag or greater-than comparison
is accepted.

During `RETIRING`, this coordinator active epoch remains E while
`RuntimeObservation.active_epoch` is N and `minimum_retained_epoch` is E. Only
complete reclamation permits the stable N/N projection and coordinator `IDLE`.

`EpochTransactionTelemetry` binds mutation sequence, from/to epochs, exact
validation and idempotency-key digests, admission time, and presence-qualified
PREPARED/lease/COMMITTING/RETIRING/failure/terminal timestamps. `outcome` and
`failure_code` are typed; diagnostic prose is not part of this shared message.
An active transaction has outcome `NONE` and no terminal time; typed
`FAILED_STOP` remains on that active record. Retained history
contains exact `COMPLETE` or pre-commit `ABORTED` transactions with the matching
timestamp and failure shape.

`EpochCertificateTelemetry` exposes current execution, boundary, and reader
counts plus typed state/fault and the compact fault index selected by that
fault namespace. `EpochGraceTelemetry` carries exact grace generation,
start/completion-observed/finish times, reader counts, and active/frozen flags.
Missing progress may return `UNAVAILABLE`; coherent future identity or an
impossible count/fault relation is `DATA_LOSS`, never optimistic progress.

#### 7.4 Protocol-fault summary

`EpochProtocolFaultSummary` carries one cumulative counter for every declared
fault code in exact enum order, optional immutable first-fault identity, and
the sticky `transition_success_blocked` safety latch. The fault codes cover
execution epoch mismatch, old/future boundary violations, CUT/ACK ordering,
retirement before quiescence, ownership accounting, sequence exhaustion, and
epoch allocator exhaustion.

The immediate disposition enum is compact and total:

| Value | Meaning |
| --- | --- |
| `DROP_AND_RETIRE` | A safely rejected module epoch mismatch was retired exactly. |
| `TERMINATE` | A structural protocol/ownership violation requires process fail-stop. |
| `RESOURCE_REFUSED` | Epoch allocation reached its reserved terminal identity; transition success remains unblocked. |

The separate sticky latch, not the disposition enum or telemetry reader,
prevents a witnessed safety fault from completing a later transition. The
first-fault record contains only fixed numeric runtime/transition/epoch,
worker/boundary/context/stage, expected/observed value, code, disposition, and
monotonic time. Completion checks it before commit, at certificate probes,
before retirement/result progress, and at final success publication. Fault-free
packet execution performs no CAS or telemetry load.

#### 7.5 Stage, module metric, mismatch, and health rows

`StageStats` contains exact logical-stage identity plus input/output/drop
packet counts and input/output bytes. There is no latency percentile, generic
parse/policy/resource split, or active-control discard field because no exact
producer exists for those meanings.

Module metric rows are context-scoped:

| Message | Meaning |
| --- | --- |
| `ModuleCounterStats` | Latest absolute registered counter/gauge value with module, context, worker, epoch, and name identity. |
| `ModuleHistogramStats` | Cold merged interval count/sum and optional complete min/max/p50/p90/p99/p999 distribution. Empty means count/sum zero and no distribution fields. |
| `ModuleEpochMismatchStats` | Absolute exact-epoch mismatch count plus all-or-none first packet/active/stage/region identity. |
| `ModuleHealthStats` | One typed callback-unavailable, awaiting, signal-available, attempt-suppressed, or stale-epoch row per context, including bounded callback/fault evidence and signal fields only when valid. |

The two health contract-fault masks have one exact four-bit vocabulary:

| Bit | Meaning |
| --- | --- |
| `0x1` | Callback returned a score above 100. |
| `0x2` | Callback returned assessment flags outside `KINETUM_HEALTH_F_KNOWN_MASK`. |
| `0x4` | The fixed reason buffer contained no terminating NUL. |
| `0x8` | Measured callback duration exceeded the compiled worker budget. |

Any other bit is malformed. `latest_fault_mask` describes the latest attempt;
`first_fault_mask` and its three presence-qualified identity fields preserve the
first bad attempt once `contract_fault_count` is nonzero. A published reason is
bounded, NUL-free on the wire, and valid UTF-8; invalid module bytes make the
selected all-or-none response malformed rather than being replacement-decoded.

Stats collection never invokes module code. Owner workers publish module banks
and health snapshots; the cold source validates identity and current epoch. A
null callback and a stale or malformed attempt never become score 100.

#### 7.6 Worker, region, and boundary rows

`WorkerEpochStats` carries stable worker/lane/region identity, coherent ledger
publication generation, active/source/future epochs and credits, and the
completed activation publication with optional transition identity/time.

`RegionEpochStats` is a cold derivation over the complete worker set. It
contains worker count, min/max active and source epochs, summed active/future
credits, activated participant count, optional min/max activation times, and
the sole retained overflow subtype `fanout_overflow`. Region state authorizes
no activation or reclamation decision.

`BoundaryEpochStats` contains exact boundary/endpoints/workers/regions,
plan-owned DATA and hold capacities, successful enqueue/dequeue sequences,
DATA backpressure, optional pending CUT/ACK identity, typed sender/receiver
phase, exact transition and cut identity, duplicate counts, and
presence-qualified edge timestamps. Derived durations are:

| Field | Exact endpoints |
| --- | --- |
| `cut_delivery_duration_ns` | CUT observed minus CUT published. |
| `cut_drain_duration_ns` | DATA sequence cut drained minus CUT observed. |
| `ack_gate_duration_ns` | Sender ACK observed minus CUT published. |

The timestamps come from four rare batch-edge sample classes, never one clock
read per boundary or packet. Missing endpoint publication or the legal
activation-before-next-ledger worker window is `UNAVAILABLE`; causally inverted
coherent times are `DATA_LOSS`.

Before ACK publication, receiver dequeue progress is strictly below the cut
while draining and exactly equal at drained/ACK-pending. A dequeue sequence
above that final successful old-DATA enqueue is a protocol contradiction and
terminates at the owner; it is not normalized into a drained state or exposed
as an overshoot counter.

#### 7.7 Provider observations and admitted topology

`ProviderObservationState` is `AVAILABLE_EXACT`,
`AVAILABLE_APPROXIMATE`, `UNSUPPORTED`, or `READ_FAILED`. The first two require
the complete optional value tuple and platform post-callback timestamp. The
last two require every optional value absent. `UNSUPPORTED` is successful
evidence that the provider lacks the observation; it is not a read error and
does not imply zero. Native lcores, physical port numbers, pool scopes, and
provider-local row positions never replace compiled generic identity.

`StreamStats`:

| Field                  | Type                | Purpose                                      |
| ---------------------- | ------------------- | -------------------------------------------- |
| `io_stream_id`         | `string`            | Exact executable I/O-stream identifier.      |
| `logical_port_id`      | `uint32`            | Logical port ID visible in packet metadata.  |
| `direction`            | `IoStreamDirection` | Exact RX or TX direction.                    |
| `owning_region_id`     | `int32`             | Region that owns the stream.                 |
| `worker_index`         | `uint32`            | Compact runtime worker identity, never a native lcore/thread ID. |
| `driver_queue_id`      | `uint32`            | Exact driver-local queue identity.           |
| `packets`              | `optional uint64`   | Records admitted on RX or accepted by the provider on TX. Presence is required. |
| `bytes`                | `optional uint64`   | Bytes in those transferred records. Presence is required. |
| `published_monotonic_ns` | `uint64`          | Positive cached timestamp of this stream owner's last completed bank. |
| `rejected_packets`     | `optional uint64`   | RX input discarded before admission or an unaccepted TX suffix retired by core. Presence is required. |

Stream counters are cumulative within the runtime generation. TX acceptance
does not prove delivery. Hardware errors remain port observations. The three
stream counters and derived engine transfer totals reserve `UINT64_MAX` for
exhausted accounting; collection then returns `DATA_LOSS`. A selected stream
family must sum to the corresponding engine RX/TX packet and byte totals.

`StorageDomainStats`:

| Field                  | Type             | Purpose                                      |
| ---------------------- | ---------------- | -------------------------------------------- |
| `storage_domain_id`    | `string`         | Exact packet-storage-domain identifier.      |
| `host_numa_node`       | `optional int32` | Exact host NUMA fact when applicable; absence remains absence. |
| `buffer_count`         | `uint64`         | Declared bounded record population.          |
| `required_min_buffers` | `uint64`         | Shared compiled admission floor.             |
| `safety_margin`        | `uint32`         | Explicit safety term in the checked budget.  |
| `observation_state`    | `ProviderObservationState` | Typed occupancy availability.        |
| `observed_monotonic_ns` | `optional uint64` | Platform post-callback sample when values exist. |
| `in_use`               | `optional uint64` | Exact or approximate externally owned records. |
| `available`            | `optional uint64` | Exact or approximate immediately available records. |

For both available states, `in_use + available == buffer_count` in the one
returned sample. Approximation describes concurrent staleness after return; it
does not permit an unaccounted record.

`TrafficSteeringStats`:

| Field                 | Type                  | Purpose                                      |
| --------------------- | --------------------- | -------------------------------------------- |
| `steering_profile_id` | `string`              | Stable steering profile identifier.          |
| `kind`                | `TrafficSteeringKind` | Steering mechanism.                          |
| `symmetric`           | `bool`                | Hardware symmetry for an unchanged tuple. |
| `io_stream_ids`       | `repeated string`     | Exact stable governed stream identities.     |

`RuntimeTelemetry.module_context_domains[]` (field 18) uses the plan's
`ModuleContextDomain` message:

| Field                     | Type     | Purpose                                      |
| ------------------------- | -------- | -------------------------------------------- |
| `module_id` | `string` | Exact module configuration identity. |
| `context_instance_ids` | `repeated string` | Sorted complete population; position defines its generation-fixed ordinal. |

`PortStats` carries `logical_port_id`, `logical_name`,
`io_driver_instance_id`, `driver_port_id`, `observation_state`, and the
presence-qualified tuple `observed_monotonic_ns`, RX/TX packets and bytes, RX
misses/errors/no-buffer, and TX errors.

The provider ABI exposes one cold storage-statistics callback and one
whole-driver statistics callback over caller-owned arrays. Every row echoes
compact identity; no native type, retained buffer, or string is returned.
Packet workers never invoke these observation callbacks. Steering and context-domain
rows are admitted compiled topology, not provider-authored validation strings
or another plan authority.

#### 7.8 Collection availability and failure semantics

The source is generation-claimed and serialized. It samples coherent runtime
and transition status before work, copies only completed banks and immutable
publications, invokes selected provider callbacks without a platform lock, and
rechecks status, completion, and first-fault identity afterward.

| Result | Meaning |
| --- | --- |
| Application `OK` | Every mandatory family and selected row is complete, validated, and belongs to one generation. |
| `UNAVAILABLE` | Readiness is absent, an atomic publication is torn/missing, a bank merge is in progress, endpoint snapshots are temporally misaligned, activation crossed collection, or a coordinator-relative mismatch is not stable across a fresh read. Retry may obtain a later coherent snapshot. |
| `DATA_LOSS` | Coherent identities, counts, enum relations, causal times, or producer output contradict each other. Retrying cannot reinterpret those bytes as success. |
| `RESOURCE_EXHAUSTED` / `OUT_OF_RANGE` | Bounded cold mapping could not represent the requested result. No partial payload is retained. |
| Exact provider status | A selected foreign callback rejected or failed the complete observation operation. |
| Transport `UNAVAILABLE` | The server could not construct the final response representation. The response body is not an observation. |

Invalid evidence outranks unavailable evidence across the collection attempt.
Stable authority permits relative checks but does not prove that every owner
publication has caught up. Client timeout leaves the accepted collection claim
alive until its callback returns.

CP repeats shared validation and adds its durable active-config fence. It
preserves downstream transport categories, validates status-only failures, and
propagates cancellation and the earlier of the incoming deadline and 30 seconds.
Text and JSON clients validate the successful CP wrapper before formatting.
Diagnostic text never selects availability, transition, or guardrail action.

#### 7.9 Debug dataplane message type

Runtime statistics use the shared telemetry contract. The separate debug RPC
declares `NatSessionEntry` for `DumpStateResponse`; `DumpState` remains
independently unavailable and returns no entries.

| Type | Fields / purpose | Current status |
| --- | --- | --- |
| `NatSessionEntry` | Protocol, internal/public/remote tuple, last-seen timestamp, packets, bytes. | Declared only under `DumpStateResponse.nat_sessions[]`; non-OK DumpState makes the default list nonsemantic. |

### 8. Guardrails Policy Schema

`GuardrailsPolicy` is one compact nested evaluation contract. It holds
cadence/history, exactly one detector, required attribution, and optional
boundary monitoring. The full schema lives in
`control.proto`; behavioral semantics live in
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md).

Production persists it inside the one private transition authority, publishes
the exact generation to the runner, and evaluates only CP-fenced telemetry.
Commit-confirmed timeout rollback remains independent and does not infer policy
from these fields. Runtime generation, counter monotonicity, and nanosecond
elapsed time are reduced to one interval before detector selection; threshold
and correlation modes never compute competing deltas.

#### 8.1 Basic policy

| Field | Type | Purpose |
| ----- | ---- | ------- |
| `enabled` | `bool` | False is valid only with every other field absent/zero. |
| `poll_interval_ms` | `uint64` | Exact monotonic observation cadence. |
| `evaluation_window_ms` | `uint64` | Valid-observation time allowed after content change. |
| `telemetry_history_capacity` | `uint32` | Explicit bounded interval-history capacity. |
| `threshold` | `GuardrailsThresholdPolicy` | One simple interval detector (oneof). |
| `correlation` | `GuardrailsCorrelationPolicy` | One EWMA/hysteresis detector (oneof). |
| `attribution` | `GuardrailsAttributionPolicy` | Required confidence gate for either detector. |
| `boundary` | `GuardrailsBoundaryPolicy` | Optional exact WAITING_ACK age detector. |

Enabled policy requires exactly one detector and complete attribution. Disabled
policy is explicitly empty; fields cannot be staged behind `enabled=false`.

#### 8.2 Multi-signal correlation weights

`GuardrailsCorrelationPolicy` carries every value explicitly:

| Field | Type | Purpose |
| ----- | ---- | ------- |
| `drop_ratio_weight` | `double` | Normalized drop contribution. |
| `throughput_ratio_weight` | `double` | Normalized accepted-TX contribution. |
| `module_health_weight` | `double` | Complete current module-health contribution. |
| `config_issue_boost` | `double` | Additive contribution from CONFIG_ISSUE rows. |
| `ewma_alpha` | `double` | Smoothing factor in `(0,1]`. |
| `degradation_threshold` | `double` | Hysteresis entry threshold in `(0,1]`. |
| `hysteresis_band` | `double` | Band in `[0,0.5]`, strictly below threshold. |
| `min_samples` | `uint32` | Positive valid-sample floor reachable within the window. |
| `normalization_max_drop_ratio` | `double` | Positive drop ratio mapped to full degradation. |
| `normalization_min_tx_ratio` | `double` | Throughput ratio in `(0,1)` mapped to full degradation. |

At least one base weight is positive. Base weights plus the maximum boost may
not exceed 1.0. A nonzero module weight or boost requires complete current
module-health evidence; absence suppresses the sample rather than contributing
zero.

#### 8.3 Boundary protocol monitoring

`GuardrailsBoundaryPolicy` contains one `uint64 ack_timeout_ms`. Message
presence enables the detector; absence disables it. The value is positive,
does not exceed `evaluation_window_ms`, and must convert to nanoseconds without
overflow. The evaluator requires exact transition generation, sender
`WAITING_ACK`, present CUT time, absent ACK-observed time, and collection time
at or beyond the bound.

There is no parallel enable Boolean and no cumulative backpressure threshold.
Backpressure remains operator telemetry, not a policy value compared against a
process-lifetime counter.

#### 8.4 Threshold and attribution messages

`GuardrailsThresholdPolicy` carries finite `max_drop_ratio` and
`min_tx_ratio` in `[0,1]` plus literal `uint64 min_packets_per_window`.
The detector requires all three interval conditions: sufficient
accepted-TX-plus-drop population, drop ratio above its bound, and throughput
ratio below the frozen baseline fraction.

`GuardrailsAttributionPolicy` carries finite positive
`auto_rollback_threshold`, `defer_threshold`, and
`degradation_threshold`, plus positive `baseline_samples` within history
capacity. Defer cannot exceed auto rollback. These are required bytes, not
runner defaults.

The fixed attribution factors are timing 0.30, magnitude 0.20, baseline
deviation 0.20, and CONFIG_ISSUE 0.30 when module evidence is required. Without
module evidence the first three are renormalized, so supported evidence still
spans the full confidence range.

#### 8.5 Schema closure

The nested policy messages above are the complete accepted field set. Recursive
unknown-field admission rejects any other active wire data; no alias or
defaulting reader changes that policy.

## Part 4: Cross-Cutting

### 9. Idempotency, CAS, and Exact Transition Identity

Mutating RPCs share these three identity rules.

#### 9.1 Idempotency keys

Mutating RPCs that carry an `idempotency_key` string use it for retry safety.
Snapshot-changing RPCs resolve through canonical durable transaction identity
and never consult a key-only cache. Policy and Confirm have their own durable
digest/result records. No volatile mutation cache exists.

Used by:
- `SetConfigSnapshot.idempotency_key`
- `Rollback.idempotency_key`
- `ConfigureGuardrails.idempotency_key`
- `ConfirmConfig.idempotency_key`
- `BootstrapConfigSnapshot.idempotency_key`
- `PrepareConfigSnapshot.idempotency_key`
- `ActivateConfigSnapshot.idempotency_key`
- `AbortPreparedConfigSnapshot.idempotency_key`
- `GetEpochTransitionStatus.idempotency_key`

The CP-side single-writer `control_loop` honors idempotency keys at the mutation
level. Its durable store also retains the exact current/latest transaction:
canonical snapshot hash, original bounded key, key digest, both allocated
values, CP phase, commit-confirm intent, and bounded terminal status. An exact
retry reuses the allocation without another authority write; the same retained
key with nonexact canonical content conflicts. DP admission retains only the
fixed key digest inside the active transaction or bounded
journal, so no epoch-only or key-only lookup exists. Configure policy persists
canonical policy hash, generation, and key digest. Confirm persists exact
snapshot/epoch/revision, key digest, and first-success remaining time.
One rollback intent persists the guarded/target content, typed cause,
policy/runtime generation, optional predecessor mutation, monotonic
observation, and retained full transition key before the ordinary rollback
handler can allocate or contact DP.

`kinetumctl` generates one domain-prefixed key from 32 bytes of OpenSSL
`RAND_bytes` for each set-config, rollback, guardrails, or Confirm command
before its first transport attempt and reuses the complete request across
retries. There is no time/PID/hostname/empty-key fallback. A custom client is
the producer authority for its own key and must follow the same one-key-per-
semantic-command rule.

The internal Bootstrap/Prepare/Activate/Abort/Status identity uses the same
bounded key grammar: 1..256 printable ASCII bytes, and bounded runtime
state retains only its SHA-256 digest. Equality of epoch and mutation high
watermarks is only a retry candidate; a journal must still exact-match the key
digest, validation hash, epoch, and mutation sequence. Equal watermarks never
authorize construction of a new transaction. While retained, one key digest
cannot bind a different allocation or content identity. An equal missing record
is typed `EXPIRED_RETRY`; stale, inconsistent, conflict, and unknown-future
outcomes are also typed and never inferred from diagnostic text.

#### 9.2 CAS (Compare-And-Swap) revision check

Snapshot-mutating CP RPCs accept an optional `expected_revision` field.
When present, including an exact value of zero, the server fails the mutation
with `FAILED_PRECONDITION` when current revision does not match. Absence alone
skips CAS. An exact key naming the current/latest durable transaction is a
retry of already admitted work, not a new overwrite; it proceeds to full
canonical identity comparison even when the original expected revision is now
older.

Used by:
- `SetConfigSnapshot.expected_revision`
- `Rollback.expected_revision`

`ConfigureGuardrails.expected_policy_generation` is a distinct exact CAS. Zero
means no policy has yet been configured; it does not skip comparison, and
proto3 presence is mandatory even at zero. Exact same-key/same-hash retry is
classified before this CAS.

#### 9.3 Exact transition lifecycle

The compact CP-DP contract carries one identity through startup restoration,
preparation, activation, pre-commit abort, and status reconciliation:

```
CP                                                                      DP
 |                                                                      |
 |-- Bootstrap(snapshot, E, epoch/sequence HWMs, plan hash) ----------->|
 |<-- {restored_epoch=E, hash, state, restored HWMs} -------------------|
 |                                                                      |
 |-- Prepare(snapshot, target=E+1, key, mutation=N) ------------------->|
 | {status, PREPARED, ACTIVE_EXACT, NONE,                               |
 |<-- prepared_epoch=E+1, hash=H, lease, mutation=N} -------------------|
 |                                                                      |
 |-- Activate(E+1, H, key, N) ----------------------------------------->|
 |-- GetEpochTransitionStatus(E+1, H, key, N) ------------------------->|
 | {status, state, resolution, failure_code,                            |
 |<-- from/to, durations, diagnostic, mutation=N} ----------------------|
```

Properties:

- **CP-allocated authority.** Epoch and mutation sequence are nonzero durable CP
  allocations. DP does not auto-assign either value.
- **Exact correlation.** Epoch, canonical 32-byte hash, idempotency key, and
  mutation sequence identify one transaction; epoch alone is insufficient.
- **Bounded identity.** Snapshot input is at most 10 MiB, lifecycle hashes are
  exactly 32 raw bytes, and lifecycle idempotency keys are 1..256 printable
  ASCII bytes. Supplied hashes are claims verified against canonical content.
- **Status-driven convergence.** An Activate deadline is not rollback. CP queries
  the same transaction until it reaches a terminal state.
- **Pre-commit-only abort.** Abort addresses the same exact identity and cannot
  represent rollback after commit.
- **Durable intent is not remote proof.** CP writes COMPLETION_PENDING before
  Activate. Exact typed ABORTED remains legal if lease expiry or another
  pre-commit cause wins before DP publishes COMMITTING.
- **Transport ambiguity preserves identity.** CP follows transient
  `UNAVAILABLE`/`DEADLINE_EXCEEDED` attempts with exact Status observations;
  COMPLETION_PENDING plus remote PREPARED retries the same Activate. A
  non-retryable transport code remains terminal to that attempt.
- **Active-record ordering.** CP promotes active content only after exact
  terminal completion, including retirement; active Bootstrap, terminal record,
  and optional pending-confirm state change in one authority replacement.

CP opens its durable store and observes DP Health before importing a fresh
bootstrap source. `CONTROL_READY` permits one durable source import followed by
Bootstrap; `PACKET_READY` requires authority that predated that observation and
rejects a fresh store without importing the source. CP executes Bootstrap from
the exact nested request in `TRANSITION_AUTHORITY.pb`, then starts mutation only
after `PACKET_READY`. Surviving-PACKET_READY reconciliation refreshes Health
before each mandatory Stats attempt. Active-epoch skew from a transition that
completed between those coherent reads is retryable `UNAVAILABLE`; stable
runtime-generation or worker-membership disagreement is `DATA_LOSS`.
Set and rollback canonicalize, stage, and durably allocate one Prepare
identity; typed reconciliation drives it through PREPARED,
COMPLETION_PENDING, and exact terminal publication. A control-only CP keeps the
loop stopped. Neither partial component state nor default response fields are
reported as a successful observation.
The behavioral mechanism and runtime ownership boundary are in
[`DATA_PLANE.md`](DATA_PLANE.md) and the boundary protocol diagram.

### 10. Authentication and TLS

CP, DP, and kinetumctl configure **transport-level** authentication through gRPC,
outside the protobuf contract.

CP supports three inbound server configurations via `cp_main.cpp` flags:

| Configuration       | Flags                                                                                   |
| ------------------- | --------------------------------------------------------------------------------------- |
| Plaintext           | Omit all TLS flags. This is the fixed Photon-supervised child shape.                    |
| Server TLS          | `--tls-cert`, `--tls-key`. Optional `--tls-ca` for client-CA pinning.                   |
| mTLS                | `--tls-cert`, `--tls-key`, `--tls-ca`, `--tls-require-client-auth`.                     |

If TLS flags are provided, credential construction is fail-closed:
missing, partial, or unreadable TLS material aborts process startup
before the service binds its port.

CP's connection to DP also supports TLS via `--client-tls-ca`,
`--client-tls-cert`, `--client-tls-key`; DP must be launched with
matching server-side TLS flags. See
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md)
for production deployment guidance and Photon's role in launching CP
and DP. Photon itself exposes no child TLS passthrough; the TLS flags apply to
direct process orchestration under another process owner.

`kinetumctl` exposes mirrored client-side flags
(`--tls-ca`, `--tls-cert`, `--tls-key`) for connecting to a
TLS-enabled CP. See [`KINETUMCTL.md`](KINETUMCTL.md).

There is no auth token, API key, or session concept in the proto. All
authentication is at the TLS / mTLS layer.

### 11. Source-Tree Client Generation

The repository proto files are language-agnostic. Runtime, SDK, and validation
packages do not install the proto tree or generated client libraries. A source
consumer may generate a `ControlService` client for any language with a gRPC
implementation. The in-tree reference client is C++ via `grpcpp`.

#### 11.1 C++ client (source-tree plaintext loopback example)

```cpp
#include <chrono>
#include <grpcpp/grpcpp.h>
#include "gen/kinetum/control/v1/control.grpc.pb.h"
#include "src/common/control_response_contract.hpp"
#include "src/common/transition_idempotency_key.hpp"

int main()
{
	auto channel = grpc::CreateChannel("127.0.0.1:50051",
					   grpc::InsecureChannelCredentials());
	auto stub = kinetum::control::v1::ControlService::NewStub(channel);

	kinetum::control::v1::SetConfigSnapshotRequest req;
	req.mutable_snapshot()->set_snapshot_id("my_snapshot");
	// ... populate snapshot ...
	auto key = kinetum::common::generate_transition_idempotency_key(
		"custom-control-client");
	if (!key.is_ok()) {
		return 1;
	}
	req.set_idempotency_key(key.value());
	// Retain this complete request unchanged across ambiguous transport retries.

	kinetum::control::v1::SetConfigSnapshotResponse resp;
	grpc::ClientContext ctx;
	ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(30));
	auto wire_status = stub->SetConfigSnapshot(&ctx, req, &resp);

	if (!wire_status.ok()) {
		// Wire-level failure.
		return 1;
	}
	auto application = kinetum::common::validate_control_response_envelope(
		resp, resp.status(), "SetConfigSnapshotResponse");
	if (!application.is_ok()) {
		// Malformed first-party response.
		return 1;
	}
	if (application.value() != kinetum::common::status_code::OK) {
		if (!resp.snapshot_id().empty() || resp.revision() != 0 || resp.epoch() != 0) {
			// Failure retained success fields: malformed response.
			return 1;
		}
		// Canonical operation-level rejection.
		return 1;
	}
	if (resp.snapshot_id() != req.snapshot().snapshot_id() ||
	    resp.revision() != req.snapshot().revision() || resp.epoch() == 0) {
		// Success identity disagrees with the exact request.
		return 1;
	}
	return 0;
}
```

#### 11.2 Other languages

Generate client stubs with `protoc` against the four RPC/shared protos in
`proto/kinetum/`:

- `proto/kinetum/common/v1/common.proto`
- `proto/kinetum/telemetry/v1/telemetry.proto`
- `proto/kinetum/control/v1/control.proto`
- `proto/kinetum/dataplane/v1/dataplane.proto`

Most external clients need `control.proto` and its import closure. Telemetry
imports `gluon/v1/plan.proto` for shared enums, which in turn imports
`axiom/v1/axiom.proto` and `google/protobuf/any.proto`. Generate the required
language bindings for those dependencies as well; compiling only the service
file does not generate bindings for its imports.
`dataplane.proto` serves the CP-to-DP backchannel; its mutation surface is not a
second operator endpoint.

#### 11.3 External and internal seams

| Surface                                                   | Ownership boundary |
| --------------------------------------------------------- | ------------------ |
| `ControlService` RPCs and request/response messages       | External current source contract. Field-number compatibility begins only when an owned release gate declares it. |
| `DataplaneService` RPCs (CP-to-DP backchannel)            | CP owns mutations and stats consumption; Photon and `kinetumctl health --service dp` also read Health. |
| `Status` numeric/semantic outcome and bounded diagnostics | Shared four-field contract; exact first-party clients reject malformed relations or success residue. |
| `ModuleConfig.config_blob` opaque-bytes channel           | Platform-owned opaque transport; each module owns its blob shape. See [`MODULE_SDK.md`](MODULE_SDK.md). |

### 12. Owner Map

| Concern                                                            | Owner                          |
| ------------------------------------------------------------------ | ------------------------------ |
| `ControlService` server implementation                             | CP (`src/cp/cp_grpc.cpp`)      |
| `DataplaneService` server implementation                           | DP (`src/dp/dataplane_control_service.cpp`) |
| Single-writer mutation discipline                                  | CP (`src/cp/control_loop.cpp`) |
| Snapshot persistence                                               | CP (`src/cp/config_store.cpp`) |
| Private persistence schema                                         | `proto/kinetum/control/internal/v1/transition_authority.proto`; no RPC or installed SDK surface |
| Exact transition wire shape                                       | `dataplane.proto`              |
| Fixed-bootstrap execution and immutable runtime-status publication | DP `partitioned_runtime`; exposed by the merged DP service |
| Live-transition RPC mapping | DP merged service; Prepare/Activate/Abort/Status map the sole runtime's typed observations |
| Fixed Bootstrap, allocator watermarks, current/latest transition, pending Confirm, guardrails policy, and rollback intent | One atomically replaced CP `config_store` envelope; DP validates the nested Bootstrap request and coherently publishes epoch, watermarks, and active content hash |
| Live epoch/mutation allocation and pending-transition reconciliation | CP durable allocator, exact DP client, and total typed action classifier |
| Canonical bootstrap hash, fixed epoch, and shutdown retirement     | DP; materialized for the one bootstrap generation |
| Live transaction admission, cold PREPARED ownership, prepared lease, and bounded terminal journal | DP coordinator plus transient preparation owner, consumed by the public transition RPCs |
| Worker-local ordered activation                                  | One immutable RUN/TRANSITION/STOP publication plus DP sender/receiver/local-activation owners |
| Global quiescence certificate                                    | DP immutable O(V+E) certificate graph plus backend-neutral exact reader domain; fixed Bootstrap leaves them inactive and live Activate consumes them |
| Old-epoch retirement                                             | One preallocated DP completion owner composes exact module claims/results, snapshot retirement, grace finish, runtime-status publication, and COMPLETE/IDLE ordering |
| Idempotency authority                                             | CP atomic authority retains exact snapshot-transition, policy, Confirm, and safety-intent retry identity; DP active/journal state retains transition keys only through fixed digests. No volatile CP mutation cache exists |
| CAS revision tracking                                              | CP                             |
| Guardrails policy storage and runner thread                        | CP (see [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md)) |
| Module config opaque routing                                       | Fixed bootstrap and live Prepare pass each verified `config_blob` through exact PREPARE, owner ACTIVATE, packet-view publication, and certified retirement |
| TLS / mTLS configuration                                           | Binaries (CP, DP, kinetumctl) - proto does not define auth |
| Runtime readiness observation                                      | One immutable `runtime_status_publication`; Bootstrap makes all three epoch fields E, live activation publishes active/last-activated N with minimum-retained E, exact reclamation makes all three N, and DP Health plus `RuntimeTelemetry` are read-only wire projections |
| Owner-completed engine, stage, registered-module, histogram, mismatch, and health collection | DP three-bank/latest-value publication plus one generation-scoped cold aggregator |
| Region, boundary, stream, storage-domain, steering, module context, and port operator rows | DP final snapshot source over compiled identities, coherent endpoint publications, and typed cold provider callbacks |
| Protocol first-fault and transition-success latch                  | DP protocol machinery; telemetry is a read-only projection and never creates safety authority |
| Telemetry forwarding to external clients                           | Shared `telemetry.proto` payload mapped by DP and validated/forwarded unchanged by CP |
| Health probe                                                       | CP and DP each implement their own (`HealthCheck` and `Health`) |

### 13. Where to Go Next

| If you want to...                                          | Read                                                                                          |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Understand CP's transactional behavior + guardrails        | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| Understand DP's transition contract and capability gates   | [`DATA_PLANE.md`](DATA_PLANE.md)                                                              |
| Use `kinetumctl` against this contract                     | [`KINETUMCTL.md`](KINETUMCTL.md)                                                              |
| Write a custom module that ships in `ModuleConfig.config_blob` | [`MODULE_SDK.md`](MODULE_SDK.md)                                                          |
| Author a pipeline (`Pipeline` is in `axiom.proto`, not on the wire) | [`AXIOM.md`](AXIOM.md)                                                                |
| Plan a deployment (`DeploymentPlan` is in `gluon/plan.proto`, not on the wire) | [`GLUON.md`](GLUON.md)                                                       |
| Understand the supervisor that launches CP and DP          | [`PHOTON.md`](PHOTON.md)                                                                      |
| Read the architectural overview                            | [`CONCEPTS.md`](CONCEPTS.md)                                                                  |
| End-to-end walkthrough                                     | [`GETTING_STARTED.md`](GETTING_STARTED.md)                                                    |
| See the runtime in motion                                  | [`diagrams/README.md`](diagrams/README.md)                                                    |
