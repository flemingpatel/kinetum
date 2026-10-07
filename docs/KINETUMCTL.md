# kinetumctl

`kinetumctl` is the operator-facing command-line client for the Kinetum
control plane. It opens a gRPC channel, executes one command, and exits. There
is no daemon mode or local state. Commands use `ControlService` in
`proto/kinetum/control/v1/control.proto`; `health --service dp` instead calls
`DataplaneService.Health` directly at an explicit endpoint.

This reference covers commands, flags, output, RPC mappings, and fields that
require a custom client. Related references cover
[module authoring](MODULE_SDK.md), [bundles](KINETUM_PACK.md), and the
[client-independent wire contract](GRPC_API.md). CP request handling is in
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md).
For the runtime that consumes the snapshots `kinetumctl` pushes, see
[`DATA_PLANE.md`](DATA_PLANE.md). For visual references on the apply
and rollback flows, see
[`diagrams/platform_architecture.md`](diagrams/platform_architecture.md).

> **CLI contract:** Every `ControlService` RPC has one complete kebab-case
> command. Mutations create one 256-bit idempotency key before the first
> attempt, retain the complete request across retryable ambiguity, and validate
> exact success identity before output. Read commands validate unknown fields,
> enums, application status, identity, and residue before one TextFormat or
> protobuf-JSON stdout emission. Failure leaves stdout empty.

Source: `src/ctl/kinetumctl_main.cpp`, the `ControlService` proto, and
`src/common/`. Field-level CLI limits are identified below.

## Table of Contents

**Part 1: Concepts and Quick Start**

1. [What kinetumctl Is](#1-what-kinetumctl-is)
2. [Operator Model and Vocabulary](#2-operator-model-and-vocabulary)
3. [Connection Model](#3-connection-model)
4. [Quick Start: First Commands](#4-quick-start-first-commands)

**Part 2: Connection and Global Options**

5. [Endpoint and TLS](#5-endpoint-and-tls)
6. [Retry and Timeout Behavior](#6-retry-and-timeout-behavior)
7. [Exit Codes and Error Output](#7-exit-codes-and-error-output)

**Part 3: Snapshot Management**

8. [`set-config <pbtxt>`](#8-set-config-pbtxt)
9. [`confirm <snapshot_id>`](#9-confirm-snapshot_id)
10. [`list-snapshots` and `get-active`](#10-list-snapshots-and-get-active)
11. [`rollback <snapshot_id>`](#11-rollback-snapshot_id)
12. [The Commit-Confirmed Workflow](#12-the-commit-confirmed-workflow)

**Part 4: Configuration Ownership**

13. [Where Runtime Configuration Lives](#13-where-runtime-configuration-lives)

**Part 5: Guardrails**

14. [`guardrails on|off|show`](#14-guardrails-onoffshow)

**Part 6: Stats**

15. [`stats`: Surface and Modes](#15-stats-surface-and-modes)
16. [`stats` Text Format](#16-stats-text-format)
17. [`stats` JSON Format](#17-stats-json-format)

**Part 7: Health and Wire-Only Fields**

18. [`health` and Fields Without Dedicated Flags](#18-health-and-fields-without-dedicated-flags)

**Part 8: Cross-Cutting**

19. [Operator Workflows](#19-operator-workflows)
20. [Scripting kinetumctl](#20-scripting-kinetumctl)
21. [Where kinetumctl Lives](#21-where-kinetumctl-lives)
22. [Where to Go Next](#22-where-to-go-next)

---

## Part 1: Concepts and Quick Start

### 1. What kinetumctl Is

Each invocation opens a gRPC channel, sends typed RPCs, prints the response, and
exits. No background loop, snapshot cache, session, or reconnection state
survives the command.

Three things `kinetumctl` is not:

- **Not the control plane.** The CP is a separate process
  (`kinetum_cp`) that receives, persists, and applies config snapshots.
  See [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md).
- **Not a bundle builder.** Deployment bundles (the directory with
  `BUNDLE_MANIFEST.txt`, the pipeline pbtxt, and module shared
  objects) are produced by `kinetum_pack`. See
  [`KINETUM_PACK.md`](KINETUM_PACK.md).
- **Not a planner or pipeline author.** The DAG and region partitioning
  come from Axiom and Gluon. See [`AXIOM.md`](AXIOM.md) and
  [`GLUON.md`](GLUON.md).

What `kinetumctl` covers: snapshot apply/list/read/rollback, exact
confirmation, guardrails write/read, stats, and service health. Eight top-level
commands expose all nine `ControlService` RPCs: `guardrails on|off` invokes
`ConfigureGuardrails`, `guardrails show` invokes `GetGuardrails`, and each
other command maps to one RPC. The health selector also exposes DP's read-only
Health RPC without adding a mutation path around CP.

### 2. Operator Model and Vocabulary

These terms recur throughout the CLI and this document.

| Term | Definition |
|---|---|
| **Snapshot** | An immutable `ConfigSnapshot` with a bounded semantic ID and revision, exact module configuration, and metadata. CP persists exact content and generates revisions for selective rollback snapshots. |
| **Revision** | Bounded snapshot revision carried by active CP truth. Generated selective rollback advances it; set-config admits the snapshot's exact revision. `--expected-revision` supplies an optional presence-qualified CAS, including zero. |
| **Epoch** | Monotonically increasing 64-bit identity durably allocated by CP and admitted/activated by DP. Successful `set-config` and `rollback` operations advance it; `confirm` records exact terminal confirmation without an epoch allocation. Gaps from aborted or orphaned allocations are valid and never reused. |
| **Active snapshot** | The snapshot currently in force on the data plane. There is exactly one. |
| **Commit-confirmed** | A pattern where `set-config --confirm-timeout <ms>` applies a snapshot, but CP auto-rolls back unless `confirm <snapshot_id> --epoch <E> --revision <R>` supplies the exact returned identity before the timeout. See Section 12. |
| **Selective rollback** | A `rollback` that targets a subset of modules (`--modules m1,m2`) rather than the whole pipeline. The CP synthesizes a hybrid snapshot whose `snapshot_id` is `selective_<sha256(domain,key)>`; exact retries reuse that identity and the first generated metadata. See Section 11. |
| **Guardrails** | The CP runner services commit-confirmed deadlines and one durable explicit telemetry policy. Missing, stale, faulted, or regressing evidence pauses rather than authorizing rollback. See [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md). |

### 3. Connection Model

Every `kinetumctl` invocation:

1. Parses global options (`--endpoint`, TLS flags, retry flags) until
   it hits the command name.
2. Opens a gRPC channel via `grpc::CreateChannel(endpoint, creds)`.
   With no TLS flags, `creds` is `grpc::InsecureChannelCredentials()`.
   With any TLS flag, `creds` is built by
   `kinetum::common::make_channel_credentials` in `src/common/tls.cpp`
   from a `tls_client_config` populated from the kebab-case TLS flags.
3. Constructs a `ControlService::Stub`, or a `DataplaneService::Stub` for DP health.
4. Executes the command's RPC sequence, including pagination or policy-generation
   reads when required.
5. Prints the result and exits.

Each RPC runs under a fresh `ClientContext` whose deadline is set to
`now() + 30 seconds` by `set_deadline()`. Transient failures
(`UNAVAILABLE`, `DEADLINE_EXCEEDED`) are retried with exponential
backoff doubling on each attempt; non-transient failures return
immediately. Defaults are 3 retries with 1 second initial delay. See
Section 6 for the retry semantics in full.

There is no streaming, persistent client session, or client-side
notification path. Snapshot mutation RPCs are wait-to-complete and return
only after exact terminal DP convergence. `stats` is not a transition wait
mechanism; it is a point-in-time coherent observation.

### 4. Quick Start: First Commands

The current runtime starts from exactly one snapshot in a verified bundle.
Photon supervises the CP/DP pair, CP durably reconciles that snapshot, and DP
activates it as the fixed bootstrap epoch before Photon publishes pair-wide
readiness. With `kinetum_cp` reachable on `127.0.0.1:50051`, the current CLI
inspection sequence is:

```sh
# 1. See the bundle's active bootstrap snapshot and any retained history.
kinetumctl --endpoint 127.0.0.1:50051 list-snapshots

# 2. Read the complete active snapshot.
kinetumctl --endpoint 127.0.0.1:50051 get-active

# 3. Read the mandatory runtime/engine/transition/fault summaries.
kinetumctl --endpoint 127.0.0.1:50051 stats
```

Later packet-configuration changes use the commands in Sections 8, 11, and 12
against the running generation. They do not replace the deployment
plan, provider graph, module image set, or bundle identity; those still require
a new verified bundle and supervised pair.

---

## Part 2: Connection and Global Options

### 5. Endpoint and TLS

#### `--endpoint <host:port>`

Default: `127.0.0.1:50051`. Standard gRPC `host:port` format. IPv6
addresses must be bracketed (`[::1]:50051`).

`health --service dp` requires an explicit `--endpoint`; it never guesses a
DP address from the CP default.

#### TLS flags

Three flags configure the channel's TLS:

| Flag | Field on `tls_client_config` | Purpose |
|---|---|---|
| `--tls-ca <ca.pem>` | `ca_pem_path` | Trusted CA certificate(s). |
| `--tls-cert <cert.pem>` | `cert_pem_path` | Client certificate chain (mTLS). |
| `--tls-key <key.pem>` | `key_pem_path` | Client private key (mTLS). |

If all three are empty, the channel uses
`grpc::InsecureChannelCredentials()` (plaintext). If any are set, the
client reads them from disk and constructs SSL credentials. TLS
credential construction is fail-closed: unreadable or empty files, a cert
without a key, or a key without a cert exits before any RPC is sent. Every
supplied certificate is prevalidated for its validity window and minimum key
strength; leaf certificates must not be self-signed, while root CA material may
be. Hostname verification remains part of the gRPC handshake. A
pinned-CA mTLS deployment normally supplies all three: CA material for
server trust, plus client certificate and key for client
authentication.

#### `--help`

`--help` prints the usage text and exits 0 before opening a gRPC
channel.

#### Plaintext default

No TLS flags means plaintext. This is intended for localhost smoke
tests and controlled dev harnesses. Production deployments should pass
TLS material and run CP with matching server-side TLS configuration.

#### Channel reuse

Each invocation creates its own channel; scripts pay setup cost per command.

### 6. Retry and Timeout Behavior

#### Per-attempt deadline

Every RPC runs under a `ClientContext` with deadline `now() + 30
seconds` (the constant `DEFAULT_TIMEOUT` in `src/ctl/kinetumctl_main.cpp`).
The deadline is **per attempt**; total time also includes retries and backoff.

#### Retry rule

`execute_with_retry` retries only when the gRPC status code is
`UNAVAILABLE` or `DEADLINE_EXCEEDED` (these are the codes
`is_transient_error` returns true for). Every other code, including
`PERMISSION_DENIED`, `UNAUTHENTICATED`, `NOT_FOUND`,
`INVALID_ARGUMENT`, `INTERNAL`, and `FAILED_PRECONDITION`, is returned
immediately.

`stats` also retries validated application `UNAVAILABLE` and
`DEADLINE_EXCEEDED` within that same attempt budget. Unknown fields, malformed
status, or a failure carrying telemetry reject before retry classification.
Every attempt uses a fresh context and response with the same selection.
Recovered statistics retries are silent; final failure emits one bounded line
and leaves stdout empty. Other commands retain transport-only retries.

#### Backoff

Default initial delay is 1000 ms (`DEFAULT_RETRY_DELAY_MS`). The delay
**doubles** before each subsequent retry and saturates at
`MAX_RETRY_DELAY_MS` (3600000 ms). With defaults (3 retries, 1000 ms
initial), the inter-attempt waits are 1000 ms, 2000 ms, 4000 ms; total
budget is roughly four 30-second deadlines plus seven seconds of
backoff in the worst case (around 127 seconds).

#### Flags

- `--retries N` (default 3): maximum retry attempts for transient
  errors. `N` must be in `[0, 100]`; `--retries 0` disables retries.
- `--retry-delay <ms>` (default 1000): initial inter-attempt delay.
  The value must be in `[0, 3600000]`.

Both retry flags use strict decimal parsing: signs, trailing junk, and
out-of-range values are usage errors.

#### Mutating commands and retry safety

`kinetumctl` retries **all** commands on transient errors, including
mutating ones (`set-config`, `rollback`, `guardrails`, and
`confirm`). Before the first transport attempt, the CLI obtains 32 bytes from
OpenSSL `RAND_bytes`, renders
one bounded `kinetumctl-<64 lowercase hex>` key, and stores it in the request
captured by `execute_with_retry`. Every attempt therefore carries byte-identical
durable identity. Entropy failure exits before transport; there is no clock,
PID, hostname, empty-key, or retry-time regeneration fallback. Guardrails first
reads its exact current policy generation; Confirm also binds required snapshot,
epoch, and revision.

### 7. Exit Codes and Error Output

| Exit code | Meaning |
|---|---|
| `0` | Command succeeded. |
| `1` | Operational failure: gRPC call failed, file read failed, or the server returned a non-zero status code in the response body. |
| `2` | Usage failure: unknown command, missing required argument, malformed numeric argument. |

Diagnostic records on `stderr` use the bounded readable format described in
[Logging](LOGGING.md). Usage and command-result errors remain finite command
output. On success, every command
builds one complete response before writing stdout and emits either protobuf
TextFormat (default) or protobuf JSON (`--format json`). No command prints a
hand-built success banner or a partial response.
Native gRPC diagnostics admit ERROR and higher; ordinary library startup
messages are suppressed.

#### gRPC error messages

When a ControlService RPC fails, `format_error_message` composes context and
hints keyed on the gRPC status code. Statistics emit one sanitized finite
diagnostic; other commands use the logger's escaped record. The "How to fix" hints are taken
verbatim from `src/ctl/kinetumctl_main.cpp`:

| Status | Diagnostic theme |
|---|---|
| `UNAVAILABLE` | "Control plane unavailable". Preserves the bounded server/transport detail and suggests checking service reachability or response-construction failure. |
| `DEADLINE_EXCEEDED` | "Request timed out". Suggests checking service health, network latency, and service load. |
| `PERMISSION_DENIED` | "Permission denied". Suggests verifying TLS certs and access permissions. |
| `UNAUTHENTICATED` | "Authentication failed". Suggests providing valid TLS certs. |
| `NOT_FOUND` | "Not found". Suggests checking the resource ID and using `list-snapshots`. |
| `INVALID_ARGUMENT` | "Invalid argument". Echoes the server's `error_message` and points at `--help`. |
| `INTERNAL` | "Internal error". Echoes the server message and suggests checking CP logs. |
| Any other code | Generic "gRPC error [N]: <message>". |

Application-level failures and malformed response envelopes exit 1 with empty
stdout. One shared admission ladder recursively rejects unknown fields and
undeclared enum values, requires canonical code/error classification, and
forbids diagnostic residue beside success. Each command then validates its
operation-specific identity and the absence of success fields on failure.
Remote diagnostic bytes are length-bounded and non-printable bytes are replaced
before stderr emission.

DP health failures identify the selected DP endpoint and native transport
detail. Diagnostic delivery never changes the remote operation's outcome.

---

## Part 3: Snapshot Management

`list-snapshots`, `set-config`, `confirm`, and `rollback` are operational after
packet-ready CP startup. The read command reports exact active/corpus truth;
mutations serialize through one durable CP identity and exact DP completion. A
control-only CP keeps the same loop stopped and returns application
`UNAVAILABLE` before payload validation, queueing, persistence, or DP transport.

### 8. `set-config <pbtxt>`

Pushes a `ConfigSnapshot` to the control plane.

**Wire**: `ControlService.SetConfigSnapshot(SetConfigSnapshotRequest)`.

**Synopsis**:

```sh
kinetumctl set-config <path-to-pbtxt> [--confirm-timeout <ms>] \
  [--expected-revision <n>] [--format text|json]
```

**Argument**:

- `<path-to-pbtxt>`: path to a text-format protobuf file representing
  a `kinetum.control.v1.ConfigSnapshot`. Read by
  `kinetum::common::read_pbtxt_file` with an explicit 64 MiB whole-file
  bound. A read or parse error prints the failure on stderr and exits 1.

**Flag**:

- `--confirm-timeout <ms>`: enables commit-confirmed mode. The CP
  drives the snapshot to exact COMPLETE before returning and creates the
  pending-confirm deadline in that same durable publication; if
  exact `confirm <snapshot_id> --epoch <E> --revision <R>` is not called
  within `<ms>` milliseconds,
  the CP auto-rolls back to the previous active snapshot. With
  `--confirm-timeout 0` (the default), commit-confirmed is disabled
   and the apply is permanent immediately. Commit-confirmed requires the
   existing active bootstrap snapshot (or another active live snapshot) as its
   rollback target; bootstrap itself is not a `kinetumctl set-config`
   operation. Values above the CP's current
  `uint32_t` timeout limit are rejected before apply. See Section 12
  for the end-to-end workflow.
- `--expected-revision <n>`: optional exact CAS against current active
  revision. Presence is preserved even for zero.
- `--format text|json`: select complete protobuf TextFormat or protobuf JSON.

**Successful live-transition output**:

```text
status {
  error_code: ERROR_CODE_OK
}
snapshot_id: "edge_gw_baseline_v1"
revision: 7
epoch: 12
```

The response is the CP/DP accepted identity. Commit-confirmed intent is
represented by the request and durable CP state, not by an extra stdout banner;
scripts retain the emitted snapshot, revision, and epoch for `confirm`.

#### Where the pbtxt comes from

Operators do not hand-write `ConfigSnapshot` pbtxts in production. The
typical flow:

1. A pipeline author writes an Axiom pipeline pbtxt (the static DAG) and
   module-owned configuration payloads. See [`AXIOM.md`](AXIOM.md) and
   [`MODULE_SDK.md`](MODULE_SDK.md).
2. Gluon plans the pipeline into regions and emits a deployment plan.
   See [`GLUON.md`](GLUON.md).
3. `kinetum_pack` validates and normalizes the mandatory bootstrap snapshot
   into `configs/config_snapshot.pbtxt`. Photon verifies the complete bundle
   and supplies that artifact to the bootstrap path. See
   [`KINETUM_PACK.md`](KINETUM_PACK.md) and [`PHOTON.md`](PHOTON.md).
4. Later module-policy changes use another complete approved snapshot through
   `kinetumctl set-config`; they do not replace the bundle's deployment plan,
   provider graph, module-image closure, or installation identity in place.

Hand-edited pbtxt is fine for development and testing; for production,
treat the pbtxt as a build artifact.

#### Set-config example

```sh
kinetumctl --endpoint cp.internal:50051 \
  --tls-ca /etc/kinetum/ca.pem \
  --tls-cert /etc/kinetum/client.pem \
  --tls-key /etc/kinetum/client.key \
  set-config /var/lib/kinetum/bundles/fan_in_edge_v2/configs/config_snapshot.pbtxt
```

### 9. `confirm <snapshot_id>`

Confirms a previously-applied snapshot through one exact durable terminal
result, preventing its commit-confirmed rollback.

**Wire**: `ControlService.ConfirmConfig(ConfirmConfigRequest)`.

**Synopsis**:

```sh
kinetumctl confirm <snapshot_id> --epoch <n> --revision <n> [--format text|json]
```

**Argument**:

- `<snapshot_id>`: the snapshot to confirm. Must match the snapshot
  the operator pushed with `set-config --confirm-timeout`. Mismatched
  IDs result in a server-side error.

**Required flags**:

- `--epoch <n>`: nonzero exact CP-allocated epoch from the successful apply.
- `--revision <n>`: exact active revision. Revision zero is valid if it is the
  pending record's actual revision; the CLI still sets wire presence explicitly.

The CLI creates one random key and retains the complete four-field request
across transport retries. Neither identity field can be omitted or treated as a
wildcard.

**Output**:

```text
status { error_code: ERROR_CODE_OK }
snapshot_id: "fan_in_edge_gw_baseline_v2"
time_remaining_ms: 29975
epoch: 12
revision: 7
```

`time_remaining_ms` belongs only to exact success. A first Confirm at or
after the durable deadline returns `DEADLINE_EXCEEDED`; polling latency cannot
create late success. The CP retains the first key digest and remaining time so
a response-loss retry returns the same result even after the deadline.

#### Confirm example

```sh
kinetumctl confirm fan_in_edge_gw_baseline_v2 --epoch 12 --revision 2
```

#### Idempotency

An exact retry in the same invocation is idempotent. Another invocation creates
a new key and therefore cannot claim the retained first success; once the next
epoch allocation clears confirmation state, later Confirm calls fail because no
pending record exists.

### 10. `list-snapshots` and `get-active`

`list-snapshots` returns the complete canonical snapshot-ID-ordered corpus and
marks at most one active row. `get-active` returns the complete currently active
`ConfigSnapshot` under one coherent store read.

**Wire**:

- `ControlService.ListSnapshots(ListSnapshotsRequest)`
- `ControlService.GetActiveSnapshot(GetActiveSnapshotRequest)`

**Synopsis**:

```sh
kinetumctl list-snapshots [--page-size <1..256>] [--format text|json]
kinetumctl get-active [--format text|json]
```

The list command authors a positive page size (default 100), follows every
opaque versioned continuation, and emits only after the complete listing has
validated. It requires one total count across all pages, strict snapshot-ID
order, no duplicate row, at most one active row, bounded continuation tokens,
and an empty final continuation. The server binds each token to corpus plus
active-authority identity; a concurrent listing change returns a typed failure
rather than a mixed or empty page. The CLI's final response carries all rows,
the exact `total_count`, and an empty `next_page_token`.

`SnapshotInfo` contains `snapshot_id`, revision, creation time, active flag,
description, and author. There is no state filter or lifecycle-state mirror.
`get-active` re-admits the returned terminal snapshot and refuses a missing or
malformed success payload.

#### Snapshot-query example

```sh
kinetumctl list-snapshots --format json | jq '.snapshots[] | select(.is_active)'
kinetumctl get-active --format json | jq '.snapshot'
```

### 11. `rollback <snapshot_id>`

Rolls back to a prior snapshot. Two modes: full rollback (default)
and selective rollback (with `--modules`).

**Wire**: `ControlService.Rollback(RollbackRequest)`.

**Synopsis**:

```sh
kinetumctl rollback <snapshot_id> [--modules <m1,m2,...>] \
  [--expected-revision <n>] [--format text|json]
```

**Argument**:

- `<snapshot_id>`: the target snapshot. Must exist on the CP. Use
  `list-snapshots` to find candidates.

**Flags**:

- `--modules <m1,m2,...>`: comma-separated module IDs. With this
  flag, the CP creates a **hybrid snapshot** named
  `selective_<sha256(domain,key)>` whose listed modules are taken from
  the target snapshot and whose other modules keep their current
  configuration. An exact retry reuses the first identity, timestamp, and
  checked revision. Empty entries, duplicate module IDs, and whitespace
  inside entries are usage errors. The flag may be provided only once.
  Without this flag, the rollback is full and the active snapshot becomes the
  target content at a newly allocated epoch.
- `--expected-revision <n>`: optional presence-qualified active-revision CAS.
- `--format text|json`: complete protobuf output encoding.

**Output (full rollback)**:

```text
status { error_code: ERROR_CODE_OK }
new_snapshot_id: "fan_in_edge_gw_baseline_v1"
new_revision: 8
epoch: 13
```

**Output (selective rollback)**:

```text
status { error_code: ERROR_CODE_OK }
new_snapshot_id: "selective_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
new_revision: 8
epoch: 13
```

#### Selective rollback constraint

`control_loop` requires matching active/target module sets and verifies every
requested module exists in the target. It does not compare pipeline edges or
graph isomorphism. A mismatched set or missing module produces nonzero status
and CLI exit 1.

Visual reference:
[`diagrams/platform_architecture.md` Section 9 (Guardrails and Rollback)](diagrams/platform_architecture.md#9-guardrails-and-rollback).

#### Rollback example

```sh
# Full rollback to a known-good snapshot.
kinetumctl rollback fan_in_edge_gw_baseline_v1

# Selective rollback: only revert ACL and QoS modules.
kinetumctl rollback fan_in_edge_gw_baseline_v1 --modules kinetum.acl,kinetum.qos
```

### 12. The Commit-Confirmed Workflow

Commit-confirmed applies a snapshot provisionally and requires confirmation
before its deadline; otherwise CP rolls back to the previous active snapshot.
It requires an active baseline as the rollback target. A fresh deployment
establishes that baseline through bundle bootstrap.

#### End-to-end script

```bash
set -euo pipefail
SNAPSHOT=/var/lib/kinetum/bundles/fan_in_edge_v2/configs/config_snapshot.pbtxt

# 1. Apply with a 5-minute deadline.
APPLY_RESULT=$(kinetumctl set-config "${SNAPSHOT}" \
  --confirm-timeout 300000 --format json)
printf '%s\n' "${APPLY_RESULT}"
SNAP_ID=$(printf '%s\n' "${APPLY_RESULT}" | jq -er '.snapshot_id')
APPLY_EPOCH=$(printf '%s\n' "${APPLY_RESULT}" | jq -er '.epoch')
APPLY_REVISION=$(printf '%s\n' "${APPLY_RESULT}" | jq -er '.revision')

# 2. Verify exact active identity and collect coherent packet evidence.
test "$(kinetumctl get-active --format json | jq -r '.snapshot.snapshot_id')" = "${SNAP_ID}"
kinetumctl stats --format json --stage-stats --boundary-epoch-stats > stats.json

# 3a. If healthy, confirm the exact epoch/revision printed by set-config.
kinetumctl confirm "${SNAP_ID}" \
  --epoch "${APPLY_EPOCH}" --revision "${APPLY_REVISION}"

# 3b. If something is wrong, do nothing. After 5 minutes the CP
#     auto-rolls back. Or roll back explicitly to short-circuit the
#     wait.
kinetumctl rollback fan_in_edge_gw_baseline_v1
```

#### What the CP does

The CP-side mechanics (condition-variable-driven runner, deadline persistence
across CP restarts, and the ordinary rollback path) are documented in
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md).
The contract `kinetumctl` exposes is:

- `set-config --confirm-timeout <ms>` returns only after exact DP COMPLETE and
  the pending-confirm result are durable; it does not return from an
  intermediate PREPARED or COMMITTING phase.
- `confirm <snapshot_id> --epoch <E> --revision <R>` succeeds only for the
  exact pending identity and a first call before the deadline. It records one
  retryable terminal confirmation; polling latency cannot admit late success.
- `rollback` can short-circuit an unconfirmed timer only as a full rollback
  naming its exact retained rollback snapshot. A selective/hybrid rollback or
  another target is rejected while that safety promise remains live.
- Doing nothing past the deadline causes CP to persist one rollback intent and
  service it through the same epoch-transition authority. A failed transition
  becomes a typed terminal intent requiring recovery; it does not loop.
- A fresh CP with no active snapshot rejects commit-confirmed applies
  because embedded pending-confirm authority cannot be created without a
  rollback target. On exact completion, active promotion and that rollback
  promise become visible through the same atomic CP authority replacement.

Visual reference:
[`diagrams/platform_architecture.md` Section 7 (Transition RPC Boundary)](diagrams/platform_architecture.md#7-transition-rpc-boundary).

#### When to use which timeout

- **30 to 60 seconds**: smoke-test a known-good change (e.g., a
  rule-list update).
- **5 to 10 minutes**: a meaningful module-policy change where you want to
  watch real production traffic before committing.
- **Never `--confirm-timeout 0` for a risky change**: that is
  immediate-permanent, no auto-rollback safety.

---

## Part 4: Configuration Ownership

Kinetum does not expose a generic partial runtime-knob mutation. Each value is
authored through the component that owns its semantics and validation.

### 13. Where Runtime Configuration Lives

| Desired change | Owning input | Operator path |
|---|---|---|
| ACL, NAT44, QoS, or customer-module policy | Exact module `config_blob` in a complete `ConfigSnapshot` | Author the snapshot, then use `set-config` |
| Restore retained module policy | Retained canonical snapshot content | Use `rollback`, optionally with `--modules` |
| Driver attachment, queue shape, burst bounds, storage, steering, or CPU placement | Typed deployment bindings and the compiled plan | Build and verify a new bundle, then restart the supervised pair |
| Automatic regression response | Durable `GuardrailsPolicy` | Use `guardrails on|off|show` |

A snapshot mutation cannot alter provider topology or execution ownership. A
provider setting cannot be smuggled through snapshot metadata, and an omitted
plan fact is never repaired by the CLI. Module policy changes still use the
same exact Prepare, ordered activation, and certified retirement path as every
other snapshot.

For a guarded module-policy rollout:

```sh
kinetumctl set-config candidate.pbtxt \
  --expected-revision 12 \
  --confirm-timeout 300000

# Use the exact snapshot, epoch, and revision returned above.
kinetumctl confirm candidate_v13 --epoch 41 --revision 13
```

For a provider or placement change, follow the bundle workflow in
[`KINETUM_PACK.md`](KINETUM_PACK.md); no ControlService command mutates those
authorities in place.

## Part 5: Guardrails

Packet-ready CP persists guardrails policy and runs the telemetry evaluator.
Control-only CP still returns `UNAVAILABLE` before mutation construction.

### 14. `guardrails on|off|show`

Configures CP's telemetry-based regression detection, attribution, and automatic
rollback policy. CP runs the evaluator; the CLI only configures it.

**Wire**: `ControlService.ConfigureGuardrails(ConfigureGuardrailsRequest)`.

**Synopsis**:

```sh
kinetumctl guardrails on --poll-ms <ms> --window-ms <ms> \
  --max-drop-ratio <r> --min-tx-ratio <r> [--min-packets <n>] \
  [--format text|json]
kinetumctl guardrails off [--format text|json]
kinetumctl guardrails show [--format text|json]
```

**Argument**: literal `on`, `off`, or `show`. Any other value is a usage error
and exits 2. `guardrails off` accepts no policy flags; passing policy
flags with `off` is a usage error.

**Flags** (all map directly onto `GuardrailsPolicy` fields):

| Flag | `GuardrailsPolicy` field | Meaning |
|---|---|---|
| `--poll-ms <ms>` | `poll_interval_ms` | How often the guardrails loop samples DP telemetry. |
| `--window-ms <ms>` | `evaluation_window_ms` | Window over which drops and TX are aggregated post-apply. |
| `--max-drop-ratio <r>` | `threshold.max_drop_ratio` | Drop ratio above which the threshold detector fires. |
| `--min-tx-ratio <r>` | `threshold.min_tx_ratio` | TX rate relative to frozen baseline below which it fires. |
| `--min-packets <n>` | `threshold.min_packets_per_window` | Minimum interval TX-plus-drop population. |

`guardrails on` requires `--poll-ms`, `--window-ms`,
`--max-drop-ratio`, and `--min-tx-ratio` so the CLI never submits an
enabled-but-ineffective zero-valued basic policy. The CLI validates the
same basic ranges before RPC that the CP validator enforces later:
poll in `[1, 3600000]`, window in `[1, 86400000]`,
window greater than or equal to poll, and both ratios in `[0.0, 1.0]`.

The CLI also serializes explicit attribution values `0.80`, `0.50`, `10`,
`0.30` and history capacity `100`. These are request bytes, not runner defaults.
It requires `ceil(window / poll) <= 100` before any policy RPC, so the
fixed authored history can retain one complete evaluation window.
Before Configure it calls GetGuardrails, reads exact generation (zero when
unconfigured), explicitly sets generation presence, generates one random key,
and retains the request across retries.

**Output**:

```text
status { error_code: ERROR_CODE_OK }
policy_generation: 2
policy_hash: "...raw SHA-256 bytes..."
```

`guardrails show` returns exact unconfigured absence or the complete validated
policy, generation, and matching SHA-256. It never manufactures a disabled
policy for an unconfigured store.

#### Guardrails example

```sh
# Enable guardrails with a 250ms poll, 5s window, and 5% drop threshold.
kinetumctl guardrails on \
  --poll-ms 250 \
  --window-ms 5000 \
  --max-drop-ratio 0.05 \
  --min-tx-ratio 0.95 \
  --min-packets 10000

# Disable guardrails entirely.
kinetumctl guardrails off
kinetumctl guardrails show --format json
```

For a planned update, enable the policy while representative traffic is still
running on the prior content and allow at least the configured baseline sample
count to complete before `set-config`. A policy first enabled after the update
cannot retroactively construct the previous-content baseline.

#### Policy fields without command flags

The CLI intentionally authors the simple threshold detector. The full wire
also supports correlation and boundary policy:

| Policy field | CLI behavior |
|---|---|
| `enabled` | Positional `on\|off`. |
| `poll_interval_ms`, `evaluation_window_ms` | Explicit required flags for `on`. |
| `telemetry_history_capacity` | Explicitly serialized as 100 by this command. |
| `threshold.*` | Ratios required; `min_packets` optional and literal zero when omitted. |
| `attribution.*` | Explicitly serialized as 0.80 / 0.50 / 10 / 0.30. |
| `correlation.*` | No CLI flags; use a custom client or startup policy file. |
| `boundary.ack_timeout_ms` | No CLI flag; message absence disables boundary policy. |

The table above is the complete policy shape. To author the unexposed fields,
write a custom client or supply CP's explicit
`--guardrails` protobuf-text file. For what
guardrails actually evaluates, see
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md).

Visual reference:
[`diagrams/platform_architecture.md` Section 9 (Guardrails and Rollback)](diagrams/platform_architecture.md#9-guardrails-and-rollback).

---

## Part 6: Stats

### 15. `stats`: Surface and Modes

`stats` returns one coherent generation snapshot: mandatory runtime, engine,
transition, and protocol-fault summaries plus selected details. Missing, torn,
or activation-crossing evidence returns application `UNAVAILABLE`; coherent
contradiction returns `DATA_LOSS`. Neither emits partial or zero-filled output.
The CLI checks application status before formatting. Failure or malformed status
exits 1 with empty stdout and at most 512 response-message bytes in diagnostics.
Non-printable bytes become `?`, preventing terminal-control or newline injection.

**Wire**: `ControlService.GetStats(StatsRequest)`.

**Synopsis**:

```sh
kinetumctl stats [--format text|json] [--stage-stats]
             [--module-metrics] [--module-health]
             [--worker-epoch-stats] [--region-epoch-stats]
             [--boundary-epoch-stats] [--stream-stats]
             [--storage-domain-stats] [--port-stats] [--topology-stats]
```

**Flags**:

- `--format text` (default): protobuf text for the validated complete CP
  response.
- `--format json`: pretty protobuf JSON with source field names preserved.
- `--stage-stats`: also include per-stage counters in the response
  and output.
- `--module-metrics`: include registered counters, histograms, and exact-epoch
  mismatch rows.
- `--module-health`: include one typed health row per module context.
- `--worker-epoch-stats`: include exact worker ledger/activation rows.
- `--region-epoch-stats`: include cold region derivations.
- `--boundary-epoch-stats`: include exact DATA/CUT/ACK progress and timing.
- `--stream-stats`: also include compiled executable I/O stream stats.
- `--storage-domain-stats`: also include compiled packet-storage-domain
  statistics.
- `--port-stats`: also include exact logical-port/I/O-driver statistics.
- `--topology-stats`: include admitted traffic-steering and module-context
  membership rows.

Unknown `stats` flags or formats other than `text` and `json` exit 2.

The flags map onto request fields:

```cpp
auto *selection = req.mutable_selection();
selection->set_include_stage_stats(include_stage_stats);
selection->set_include_module_metrics(include_module_metrics);
selection->set_include_module_health(include_module_health);
selection->set_include_worker_epoch_stats(include_worker_epoch_stats);
selection->set_include_region_epoch_stats(include_region_epoch_stats);
selection->set_include_boundary_epoch_stats(include_boundary_epoch_stats);
selection->set_include_stream_stats(include_stream_stats);
selection->set_include_storage_domain_stats(include_storage_domain_stats);
selection->set_include_port_stats(include_port_stats);
selection->set_include_topology_stats(include_topology_stats);
```

CP forwards this one shared selection to DP. It validates and copies the shared
`RuntimeTelemetry` only after its durable active snapshot/revision/epoch and
plan identity agree. A failed response carries no semantic payload.

#### Output sections

On application success, both text and JSON modes contain:

1. **Aggregate counters and active snapshot** (always present in a successful
   rendering): `active_config` with revision and snapshot identity, plus mandatory
   `telemetry.runtime`, `engine`, `transition`, and `protocol_faults`.
2. **Owner detail rows**: `stages`, registered module counters/histograms,
   module epoch mismatches, typed module health, exact workers, and cold regions
   under their matching flags. Stage rows contain only packet/byte counters
   with real producers; region rows retain only `fanout_overflow` as a drop
   subtype.
3. **Ordered-boundary rows**: selected `boundaries` carry exact capacities,
   DATA sequences/backpressure, pending CUT/ACK, sender/receiver phases,
   transition/cut identity, duplicate counts, six edge timestamps,
   and three checked durations.
4. **I/O and storage rows**: streams carry compiled identity, software
   transfer/rejection counters, and their owner's bank-publication time.
   Storage domains and ports carry static compiled identity plus
   `AVAILABLE_EXACT`, `AVAILABLE_APPROXIMATE`,
   `UNSUPPORTED`, or `READ_FAILED`. Numeric values are present only for an
   available state; unsupported never means zero.
5. **Admitted topology**: `--topology-stats` returns steering and module-context
   membership using stable IDs. Provider-native lcores, physical port numbers,
   pool scopes, and validation prose do not cross this generic boundary.

### 16. `stats` Text Format

Only validated application success produces TextFormat output. The abridged
example marks repeated rows with a comment that the CLI does not emit.

```text
status {
  error_code: ERROR_CODE_OK
}
active_config {
  revision: 2
  snapshot_id: "fan_in_edge_gw_baseline_v2"
}
telemetry {
  runtime {
    runtime_generation: 9
    active_epoch: 8
    minimum_retained_epoch: 8
    last_activated_epoch: 8
    active_workers: 3
    expected_workers: 3
    collection_monotonic_ns: 1778446450956000
  }
  engine { rx_packets: 3201328 tx_packets: 3201274 dropped_packets: 54 }
  transition {
    state: EPOCH_TRANSITION_STATE_IDLE
    active_epoch: 8
    allocated_epoch_high_watermark: 8
    mutation_sequence_high_watermark: 11
  }
  protocol_faults {
    counters { code: EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH }
    # ...one ordered row for every declared fault code...
  }
}
```

#### Field reading guide

- `active_config.revision` and `snapshot_id`: CP's exact durable
  active configuration. CP emits them only after proving DP epoch and plan
  identity agree.
- `telemetry.runtime.active_epoch` and `minimum_retained_epoch`: the live DP
  epoch and oldest retained epoch. `active_epoch`
  advances on every successful apply (`set-config` or `rollback`); during
  exact retirement, active and last-activated carry the target epoch while
  minimum-retained still carries the old epoch. Only certified old-object
  reclamation permits all three to agree on the target.
- `telemetry.engine`: aggregate cumulative counters within one exact runtime
  generation. RX/TX packet and byte totals derive from software stream
  transfers; TX measures provider acceptance, not wire delivery.
  To compute a rate, sample twice in the same generation and
  divide; a generation replacement resets the baseline.
- `telemetry.runtime.collection_monotonic_ns` is the cold source's final
  platform monotonic sample. `latest_bank_publication_monotonic_ns` identifies
  the latest immutable bank included; neither is Unix wall time.
- `telemetry.transition.active_epoch` and `active_validation_hash` are one
  last-globally-COMPLETE content witness. They remain on the old epoch and hash
  while runtime participant truth has active/last-activated at the target but
  minimum-retained at the old epoch in RETIRING. They move to the target only
  at exact COMPLETE.
  The CP requires this pair, plan hash, and the lawful allocation-watermark
  relation before it publishes a successful aggregate.
- `stages`: present only with `--stage-stats`. Input, output, and drop counts
  describe exact stage ownership transfer. A pass-through stage may expect
  `in == out` and zero drops, while a policy module may intentionally retire
  traffic. `parse` can drop malformed or non-IP frames. No generic health or
  subtype is inferred from these counters alone.
- `boundaries`: present only with `--boundary-epoch-stats`. Compare exact
  transition/cut identity and typed phases before interpreting durations;
  optional timing is absent until both endpoint timestamps exist.
- `regions`: present only with `--region-epoch-stats`. Epoch ranges and credits
  show convergence; `fanout_overflow` is the sole retained drop subtype.
- `streams`: present only with `--stream-stats`. The topology
  fields identify the executable stream, logical port, owner region,
  compact runtime worker, and exact driver queue. `packets`, `bytes`, and
  `rejected_packets` are always present, including measured zero.
  `published_monotonic_ns` identifies that owner's last completed bank rather
  than the later collection time. Hardware errors remain in port rows.
- `storage_domains`: present only with `--storage-domain-stats`.
  `storage_domain_id`, optional `host_numa_node`, `buffer_count`,
  `required_min_buffers`, and `safety_margin` are compiled plan facts.
  `required_min_buffers` is the checked admission floor enforced before
  storage construction.
  `in_use` and `available` are exact or approximate only when their typed state
  says so.
- `ports`: present only with `--port-stats`. `logical_port_id`
  and `logical_name` come from the deployment plan;
  `io_driver_instance_id` and `driver_port_id` identify its exact generic
  driver owner. `rx_missed`, `rx_errors`, `rx_no_buffer`, and `tx_errors` are
  provider-reported only in an available tuple.
- `steering_profiles` and `module_context_domains`: selected together under
  `--topology-stats`. Each context-domain row contains `module_id` and its
  sorted `context_instance_ids`. These are admitted topology, not live provider
  validation prose.

### 17. `stats` JSON Format

`--format json` prints the complete validated `StatsResponse` using protobuf
JSON, with snake_case names and whitespace. Parse it as JSON; 64-bit integers
are decimal strings. Application failure leaves stdout empty.

#### Schema

The abridged object below shows the permanent nesting. Optional row families
appear only when selected, and optional scalar timestamps/counters appear only
when their producer state makes them meaningful.

```json
{
  "status": {"error_code": "ERROR_CODE_OK"},
  "active_config": {
    "revision": "2",
    "snapshot_id": "fan_in_edge_gw_baseline_v2"
  },
  "telemetry": {
    "runtime": {
      "runtime_generation": "9",
      "status_publication_generation": "21",
      "active_epoch": "8",
      "minimum_retained_epoch": "8",
      "last_activated_epoch": "8",
      "active_workers": 3,
      "expected_workers": 3,
      "collection_monotonic_ns": "1778446450956000",
      "latest_bank_publication_monotonic_ns": "1778446450955000"
    },
    "engine": {
      "rx_packets": "3201328",
      "tx_packets": "3201274",
      "dropped_packets": "54",
      "rx_bytes": "204884992",
      "tx_bytes": "204881536"
    },
    "transition": {
      "publication_generation": "17",
      "state": "EPOCH_TRANSITION_STATE_IDLE",
      "active_epoch": "8",
      "allocated_epoch_high_watermark": "8",
      "mutation_sequence_high_watermark": "11",
      "plan_content_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "active_validation_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "participant_set_frozen": false,
      "execution_participant_count": 3,
      "region_count": 3,
      "boundary_count": 2,
      "source_participant_count": 2,
      "sink_participant_count": 1,
      "module_context_count": 4,
      "quiescence_reader_count": 3,
      "terminal_history_size": 1,
      "latest_terminal": {
        "mutation_sequence": "11",
        "from_epoch": "7",
        "to_epoch": "8",
        "validation_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "idempotency_key_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "admitted_monotonic_ns": "1778446450000000",
        "prepared_monotonic_ns": "1778446450100000",
        "commit_started_monotonic_ns": "1778446450200000",
        "retiring_started_monotonic_ns": "1778446450500000",
        "terminal_monotonic_ns": "1778446450900000",
        "outcome": "EPOCH_TRANSITION_OUTCOME_COMPLETE",
        "failure_code": "EPOCH_TRANSITION_FAILURE_CODE_NONE"
      }
    },
    "protocol_faults": {
      "counters": [
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_OLD_DATA_AFTER_SEAL", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_FUTURE_DATA_BEFORE_ACK", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_CUT_IDENTITY_MISMATCH", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_ACTIVATION", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_CUT_DRAIN", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_RETIREMENT_BEFORE_QUIESCENCE", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_UNDERFLOW", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_OVERFLOW", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_DOUBLE_RETIRE", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_WRONG_SLOT", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_SEQUENCE_EXHAUSTED", "count": "0"},
        {"code": "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED", "count": "0"}
      ]
    },
    "stages": [
      {
        "stage_id": "parse",
        "in_packets": "3201328",
        "out_packets": "3201274",
        "dropped_packets": "54",
        "in_bytes": "204884992",
        "out_bytes": "204881536"
      }
    ],
    "boundaries": [
      {
        "boundary_id": "boundary.acl1@lane_0.nat@lane_0",
        "boundary_index": 1,
        "from_stage_instance_index": 1,
        "to_stage_instance_index": 2,
        "sender_worker_index": 1,
        "receiver_worker_index": 2,
        "from_region_id": 1,
        "to_region_id": 2,
        "data_ring_capacity": 1024,
        "future_output_hold_capacity": 1024,
        "data_enqueued_sequence": "1600661",
        "data_dequeued_sequence": "1600661",
        "sender_phase": "BOUNDARY_SENDER_PHASE_OPEN",
        "receiver_phase": "BOUNDARY_RECEIVER_PHASE_OPEN",
        "transition_generation": "11",
        "from_epoch": "7",
        "to_epoch": "8",
        "cut_sequence": "1600600",
        "cut_published_monotonic_ns": "1778446450300000",
        "cut_observed_monotonic_ns": "1778446450301200",
        "cut_drained_monotonic_ns": "1778446450343200",
        "activation_monotonic_ns": "1778446450345000",
        "ack_published_monotonic_ns": "1778446450345100",
        "ack_observed_monotonic_ns": "1778446450383779",
        "cut_delivery_duration_ns": "1200",
        "cut_drain_duration_ns": "42000",
        "ack_gate_duration_ns": "83779"
      }
    ],
    "regions": [
      {
        "region_id": 0,
        "worker_count": 1,
        "minimum_active_epoch": "8",
        "maximum_active_epoch": "8",
        "minimum_source_epoch": "8",
        "maximum_source_epoch": "8",
        "fanout_overflow": "0"
      },
      {
        "region_id": 1,
        "worker_count": 1,
        "minimum_active_epoch": "8",
        "maximum_active_epoch": "8",
        "minimum_source_epoch": "8",
        "maximum_source_epoch": "8",
        "fanout_overflow": "0"
      },
      {
        "region_id": 2,
        "worker_count": 1,
        "minimum_active_epoch": "8",
        "maximum_active_epoch": "8",
        "minimum_source_epoch": "8",
        "maximum_source_epoch": "8",
        "fanout_overflow": "0"
      }
    ],
    "streams": [
      {
        "io_stream_id": "wan0.rx.lane_0",
        "logical_port_id": 1,
        "direction": "IO_STREAM_DIRECTION_RX",
        "owning_region_id": 0,
        "worker_index": 0,
        "driver_queue_id": 0,
        "packets": "1600667",
        "bytes": "102442688",
        "published_monotonic_ns": "1778446450955000",
        "rejected_packets": "0"
      },
      {
        "io_stream_id": "wan1.rx.lane_0",
        "logical_port_id": 2,
        "direction": "IO_STREAM_DIRECTION_RX",
        "owning_region_id": 1,
        "worker_index": 1,
        "driver_queue_id": 0,
        "packets": "1600661",
        "bytes": "102442304",
        "published_monotonic_ns": "1778446450954800",
        "rejected_packets": "0"
      },
      {
        "io_stream_id": "lan0.tx.lane_0",
        "logical_port_id": 0,
        "direction": "IO_STREAM_DIRECTION_TX",
        "owning_region_id": 2,
        "worker_index": 2,
        "driver_queue_id": 0,
        "packets": "3201274",
        "bytes": "204881536",
        "published_monotonic_ns": "1778446450955000",
        "rejected_packets": "0"
      }
    ],
    "storage_domains": [
      {
        "storage_domain_id": "storage_dpdk_0",
        "host_numa_node": 0,
        "buffer_count": "131071",
        "required_min_buffers": "12288",
        "safety_margin": 64,
        "observation_state": "PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE",
        "observed_monotonic_ns": "1778446450955300",
        "in_use": "1024",
        "available": "130047"
      }
    ],
    "ports": [
      {
        "logical_port_id": 1,
        "logical_name": "wan0",
        "io_driver_instance_id": "io_dpdk_0",
        "driver_port_id": "wan0",
        "observation_state": "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT",
        "observed_monotonic_ns": "1778446450955400",
        "rx_packets": "1600667",
        "tx_packets": "0",
        "rx_bytes": "102442688",
        "tx_bytes": "0",
        "rx_missed": "0",
        "rx_errors": "0",
        "tx_errors": "0",
        "rx_no_buffer": "0"
      },
      {
        "logical_port_id": 2,
        "logical_name": "wan1",
        "io_driver_instance_id": "io_dpdk_0",
        "driver_port_id": "wan1",
        "observation_state": "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT",
        "observed_monotonic_ns": "1778446450955400",
        "rx_packets": "1600661",
        "tx_packets": "0",
        "rx_bytes": "102442304",
        "tx_bytes": "0",
        "rx_missed": "0",
        "rx_errors": "0",
        "tx_errors": "0",
        "rx_no_buffer": "0"
      },
      {
        "logical_port_id": 0,
        "logical_name": "lan0",
        "io_driver_instance_id": "io_dpdk_0",
        "driver_port_id": "lan0",
        "observation_state": "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT",
        "observed_monotonic_ns": "1778446450955400",
        "rx_packets": "0",
        "tx_packets": "3201274",
        "rx_bytes": "0",
        "tx_bytes": "204881536",
        "rx_missed": "0",
        "rx_errors": "0",
        "tx_errors": "0",
        "rx_no_buffer": "0"
      }
    ],
    "steering_profiles": [
      {
        "steering_profile_id": "steering_none_wan0",
        "kind": "TRAFFIC_STEERING_KIND_NONE",
        "symmetric": false,
        "io_stream_ids": ["wan0.rx.lane_0"]
      }
    ],
    "module_context_domains": [
      {
        "module_id": "kinetum.acl",
        "context_instance_ids": ["acl0@lane_0", "acl1@lane_0"]
      },
      {
        "module_id": "kinetum.nat44",
        "context_instance_ids": ["nat@lane_0"]
      },
      {
        "module_id": "kinetum.qos",
        "context_instance_ids": ["qos@lane_0"]
      }
    ]
  }
}
```

#### Conditional arrays

Detailed arrays are **conditional** in the JSON output:

- `stages`, `module_counters`, `module_histograms`,
  `module_epoch_mismatches`, `module_health`, `workers`, `regions`,
  `boundaries`, `streams`, `storage_domains`, and `ports` follow their exact
  selection flags.
- `steering_profiles` and `module_context_domains` are selected together under
  `--topology-stats`.
- Optional transaction, certificate, grace, health, boundary-timing, and
  provider-value fields are emitted only with protobuf presence. Selected
  stream counters always have explicit presence, including zero. Numeric zero
  is not a substitute for absent evidence. The CLI deliberately emits
  non-optional primitive defaults, so a selected successful row has a stable
  scalar shape; optional evidence still appears only when present.

A robust JSON consumer must first require exit code zero, then check key
presence rather than assume the optional-array shape. Within a successful JSON
object, `status`, `active_config`, and all four mandatory telemetry summaries
are unconditional. String values are JSON-escaped by protobuf's printer.

#### Pretty-printing and field names

The CLI enables protobuf JSON whitespace and preserves source field names.
Consumers may therefore use snake_case paths such as
`.telemetry.protocol_faults.transition_success_blocked`. Do not assume one
JSON object per line, and do not coerce protobuf's decimal-string uint64 values
through floating point.

---

## Part 7: Health and Wire-Only Fields

### 18. `health` and Fields Without Dedicated Flags

`health` defaults to `--service cp`, maps `ControlService.HealthCheck`, and
requires exact serving state, the compiled product version, nonnegative
service uptime, and complete logging observations:

```sh
kinetumctl health [--service cp] [--format text|json]
kinetumctl --endpoint 127.0.0.1:50052 health --service dp --format json
```

```text
status: STATUS_SERVING
version: "0.1.0"
uptime_seconds: 42
logging {
  destination: DESTINATION_STATE_AVAILABLE
  accepted_records: 12
  queue_rejections: 0
  format_rejections: 0
  unavailable_rejections: 0
  undelivered_records: 0
  write_failures: 0
  console_failures: 0
  truncated_records: 0
  packet_thread_rejections: 0
  delivery_timeouts: 0
}
```

DP health returns the typed readiness state, runtime generation, active epoch,
active/expected workers, application status, version, and logging observation.
It uses the same strict Health admission as CP and Photon. A valid unavailable
logging destination remains visible in the response and does not turn an
otherwise valid readiness observation into failure. Missing counter presence
or contradictory logging evidence is malformed transport data and rejects.

All nine ControlService RPCs are exposed. The remaining wire-only surface is at
field granularity, not hidden command reachability.

#### Mutating-request fields generated by the CLI

| Field | Type | Purpose |
|---|---|---|
| `idempotency_key` | string | Required exact durable identity for all four mutation commands. The CLI generates one 256-bit random key per command and retains it across every transport attempt; it is intentionally not user-selectable. |

`expected_revision` is exposed on `set-config` and `rollback`. No additional
lifecycle selector or free-form rollback reason
is part of these requests.

The CLI intentionally does not author the correlation detector or boundary
guardrails policy. Those are implemented wire contracts for custom clients;
`guardrails show` still renders them when present.

#### Why field-level gaps exist

Every wire field is implemented, though not every field has a CLI flag. For an
unexposed field:

1. Use generated protobuf/gRPC bindings from your scripting language. Best for
   production tooling.
2. Edit a complete snapshot and reapply module policy with `set-config`.
   Deployment-plan, provider, topology, or module-image changes still require
   a new verified bundle.
3. Open a CLI feature request with the workflow you need.

---

## Part 8: Cross-Cutting

### 19. Operator Workflows

#### Deploy a new pipeline

```sh
# 1. Build a bundle with kinetum_pack (see KINETUM_PACK.md).
/usr/bin/sudo /usr/bin/install -d -m 0755 -- /var/lib/kinetum
/usr/bin/sudo /usr/bin/install -d -m 0755 \
  -o "$(/usr/bin/id -u)" -g "$(/usr/bin/id -g)" -- \
  /var/lib/kinetum/bundles
kinetum_pack \
  --axiom pipeline.axiom.pbtxt \
  --hw hardware_inventory.pbtxt \
  --bindings deployment_bindings.pbtxt \
  --modules-dir ./modules \
  --bootstrap-snapshot config_snapshot.pbtxt \
  --regions 3 \
  --out /var/lib/kinetum/bundles/fan_in_edge_v1

# 2. Launch the complete bundle; its snapshot is the bootstrap authority.
/usr/bin/sudo /opt/kinetum/bin/kinetum_photon \
  --bundle /var/lib/kinetum/bundles/fan_in_edge_v1

# 3. Inspect durable active identity and the coherent runtime generation.
kinetumctl list-snapshots
kinetumctl stats --format json | jq '.telemetry.runtime'
```

#### Change module policy safely

```sh
# 1. Apply one complete module-policy snapshot under CAS and confirmation.
kinetumctl set-config \
  /var/lib/kinetum/bundles/fan_in_edge_v2/configs/config_snapshot.pbtxt \
  --expected-revision 1 --confirm-timeout 300000

# 2. Confirm durable active identity and inspect runtime truth.
kinetumctl list-snapshots --format json | jq '.snapshots[] | select(.is_active)'
kinetumctl stats --format json | jq '{active_config, runtime: .telemetry.runtime}'

# 3. If the policy regressed, roll back to the prior active snapshot.
kinetumctl list-snapshots
kinetumctl rollback fan_in_edge_gw_baseline_v1
```

#### Investigate a stall

Localize stopped traffic or transitions to a region, boundary, or stage:

```bash
# 1. Snapshot the DP state.
kinetumctl stats --format json --stage-stats --worker-epoch-stats \
  --region-epoch-stats --boundary-epoch-stats > before.json
sleep 5
kinetumctl stats --format json --stage-stats --worker-epoch-stats \
  --region-epoch-stats --boundary-epoch-stats > after.json

# 2. With independently proven live ingress, compare aggregate progress.
diff <(jq '.telemetry.engine, .telemetry.runtime.active_epoch' before.json) \
     <(jq '.telemetry.engine, .telemetry.runtime.active_epoch' after.json)

# 3. Find exact sender gates still waiting for ACK and compute age from the
#    collection timestamp and CUT-publication timestamp.
jq '.telemetry.boundaries[] |
    select(.sender_phase == "BOUNDARY_SENDER_PHASE_WAITING_ACK") |
    {boundary_id, transition_generation, cut_sequence,
     cut_published_monotonic_ns}' before.json

# 4. Look at region stats for fan-out overflow or epoch
#    divergence (some regions stuck on an older epoch).
jq '.telemetry.regions' before.json
```

`WAITING_ACK`, absent exact ACK timing, nonzero old credits, and min/max epoch
divergence are the most actionable signals. Protocol-fault counters and the
sticky success-block latch distinguish a safety violation from ordinary
backpressure. For deeper investigation, see
[`DATA_PLANE.md`](DATA_PLANE.md).

#### Guarded rollout via commit-confirmed

For changes that touch ACL rules, NAT pools, or QoS profiles in ways
that could regress traffic:

```bash
set -euo pipefail

# Push with a 10-minute durable auto-rollback window.
ROLLOUT_RESULT=$(kinetumctl set-config \
  /var/lib/kinetum/bundles/fan_in_edge_v2/configs/config_snapshot.pbtxt \
  --confirm-timeout 600000 --format json)
ROLLOUT_ID=$(printf '%s\n' "${ROLLOUT_RESULT}" | jq -er '.snapshot_id')
ROLLOUT_EPOCH=$(printf '%s\n' "${ROLLOUT_RESULT}" | jq -er '.epoch')
ROLLOUT_REVISION=$(printf '%s\n' "${ROLLOUT_RESULT}" | jq -er '.revision')

# Validate with deployment-owned traffic plus one coherent stats snapshot.
test "$(kinetumctl get-active --format json | jq -r '.snapshot.snapshot_id')" = \
  "${ROLLOUT_ID}"
kinetumctl stats --format json --module-health --boundary-epoch-stats > rollout.json

# Confirm only after operator validation passes.
kinetumctl confirm "${ROLLOUT_ID}" \
  --epoch "${ROLLOUT_EPOCH}" --revision "${ROLLOUT_REVISION}"
```

### 20. Scripting kinetumctl

#### Exit codes and stdout/stderr separation

`stdout` carries structured output (text or JSON). `stderr` carries
diagnostics, log lines, and retry messages. Scripts that consume
`kinetumctl` output should only parse `stdout`. The exit code
distinguishes the three failure classes (Section 7); use it to
decide whether to retry, roll back, or escalate.

For `stats`, exit status is the admission gate for stdout: application failure
and malformed embedded status both return 1 with empty stdout. A wrapper must
check that status before parsing text or JSON; protobuf defaults from a failed
aggregate are never observations.

#### Parsing stats JSON

`kinetumctl stats --format json` is the parser-friendly form. Three caveats:

- Output is pretty protobuf JSON, not JSON Lines. Parse one complete JSON value.
- Protobuf JSON represents uint64 values as decimal strings. Convert them with
  checked integer parsing, never binary floating point.
- Conditional arrays follow the ten selection flags. Use paths such as
  `jq '.telemetry.stages // []'`; optional provider values and edge timestamps
  remain absent when their typed state has no observation.

#### Retry safety on mutating commands

`kinetumctl` retries every command on transient errors
(`UNAVAILABLE`, `DEADLINE_EXCEEDED`), including mutating ones. One invocation of
`set-config`, `rollback`, `guardrails`, or `confirm` generates a
key once and captures the same request for every attempt, so in-process retries
are exact. Entropy failure occurs before transport. Confirm retains its first
success result; response loss cannot turn an exact retry into a missing-record
failure.

Each CLI invocation creates a new key and therefore a new command. After an
ambiguous transport failure exhausts retries, let CP converge; an old active
snapshot does not prove the first command absent or terminal. Do not relaunch
the mutation automatically.

If joint recovery is needed, restart the supervised pair. Bootstrap restores
CP's last durable COMPLETE state, discards the orphan allocation, resolves a
satisfied intent, and retains an unsatisfied intent/key for fresh allocation.
Check the resulting active identity before issuing another command. CLI keys
are neither exposed nor persisted across invocations.

For read-only commands (`stats`, `list-snapshots`, `get-active`,
`guardrails show`, and `health`), default retry
behavior is safe. Treat `confirm` as a mutating command for retry
policy, even though its intended effect is idempotent at the operator
level.

#### Sequencing multiple mutations

Separate `set-config` invocations are distinct mutations; another client may
interleave a rollback. For one atomic change, apply a single composite snapshot.

#### Long-running watches

Use `watch`, a shell loop, or monitoring to sample state. Bound the interval:
each invocation creates a gRPC channel and request, so a tight loop can overload
CP.

### 21. Where kinetumctl Lives

#### Build target

```
add_executable(kinetumctl src/ctl/kinetumctl_main.cpp)
target_link_libraries(kinetumctl PRIVATE kinetum_common kinetum_guardrails_contract)
```

(in the top-level `CMakeLists.txt`). The single executable links shared common
mechanisms plus the same guardrails-policy validator as CP; generated gRPC,
TLS, protobuf-text, and policy admission are not reimplemented in the CLI.

#### Source structure

Command parsing, dispatch, result admission, and JSON encoding live in
`src/ctl/kinetumctl_main.cpp`. JSON preserves field names, zero-value output,
and protobuf integer encodings. Shared RPC/status admission and logging remain
in `src/common/`.

#### Packaging and installation

The root CMake project has no standalone `install(TARGETS kinetumctl ...)`
rule. The source-controlled release aggregate and packaging workflow stage the
binary with the complete runtime, and the runtime installer places it at
`<runtime-root>/bin/kinetumctl` (normally
`/opt/kinetum/bin/kinetumctl`). Operators run that installed regular file; a
build-tree binary is development output, not an installed-runtime substitute.

#### No persistent state

`kinetumctl` writes no disk state and reads only CLI-supplied pbtxt and TLS PEMs.
State lives in CP; the client has no config file, endpoint/credential environment
settings, or secret cache.

### 22. Where to Go Next

| If you want to... | Read |
| --- | --- |
| Understand the wire contract that backs `kinetumctl` | [`GRPC_API.md`](GRPC_API.md) |
| Understand what the CP does with `set-config`, `rollback`, `confirm` | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| See the apply flow visually | [`diagrams/platform_architecture.md` Section 7 (Transition RPC Boundary)](diagrams/platform_architecture.md#7-transition-rpc-boundary) |
| See guardrails and rollback visually | [`diagrams/platform_architecture.md` Section 9 (Guardrails and Rollback)](diagrams/platform_architecture.md#9-guardrails-and-rollback) |
| Understand the data plane that `kinetumctl stats` reads from | [`DATA_PLANE.md`](DATA_PLANE.md) |
| Build the bundle that `set-config` consumes | [`KINETUM_PACK.md`](KINETUM_PACK.md) |
| Author a pipeline | [`AXIOM.md`](AXIOM.md) |
| Plan a deployment | [`GLUON.md`](GLUON.md) |
| Write a custom module | [`MODULE_SDK.md`](MODULE_SDK.md) |
| Understand the supervisor that launches CP and DP | [`PHOTON.md`](PHOTON.md) |
| Locate service files and inspect diagnostic delivery | [`LOGGING.md`](LOGGING.md) |
| Run the platform end-to-end | [`GETTING_STARTED.md`](GETTING_STARTED.md) |
| Read the architectural overview | [`CONCEPTS.md`](CONCEPTS.md) |
