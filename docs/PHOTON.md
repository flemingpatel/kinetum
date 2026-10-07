# Photon

This reference covers Kinetum's single-node supervisor: bundle admission,
child layout, readiness, restart, shutdown, the `kinetum_photon` CLI, and
the embedding API.

For the architectural framing, read [`CONCEPTS.md`](CONCEPTS.md) first.
For pipeline authoring, see [`AXIOM.md`](AXIOM.md). For planning, see
[`GLUON.md`](GLUON.md).

> **Contract:** Bundle admission, exact child spawn, readiness gates, signal
> handling, pair-scoped cleanup, and pair restart are one implemented
> supervision path. Photon owns no telemetry policy or configuration mutation
> path. Every admitted deployment uses this same supervision contract.

## Table of Contents

**Part 1: Concepts and Startup**

1. [What Photon Is](#1-what-photon-is)
2. [Authoring Model](#2-authoring-model)
3. [Boot Sequence](#3-boot-sequence)
4. [Production Runtime Requirements](#4-production-runtime-requirements)
5. [One Exact Startup Mode](#5-one-exact-startup-mode)
6. [Runtime-Bundle Loading and Validation](#6-runtime-bundle-loading-and-validation)

**Part 2: Process Ownership and Supervision**

7. [Process Layout, Command Construction, and IPC](#7-process-layout-command-construction-and-ipc)
8. [Process Supervision](#8-process-supervision)
9. [Supervision Scope and Policy Boundary](#9-supervision-scope-and-policy-boundary)
10. [Logging and Observability](#10-logging-and-observability)

**Part 3: Operation and Embedding**

11. [CLI](#11-cli)
12. [Embedding Photon](#12-embedding-photon)
13. [Walkthroughs](#13-walkthroughs)

**Part 4: Cross-Cutting**

14. [Photon vs DP vs CP vs Quark Responsibilities](#14-photon-vs-dp-vs-cp-vs-quark-responsibilities)
15. [Where to Go Next](#15-where-to-go-next)

---

## Part 1: Concepts and Startup

### 1. What Photon Is

Photon is the single-node supervisor that runs a Kinetum deployment. It
takes a complete runtime bundle (output of
[`kinetum_pack`](KINETUM_PACK.md)) and:

- Verifies manifest integrity, canonical artifact paths, plan content identity,
  and the plan-bound bootstrap snapshot before constructing either child.
- Retains the verifier-returned canonical plan, snapshot, and plan-hash
  authorities without interpreting or repairing the plan's provider graph.
- Spawns the dataplane (`kinetum_dp`) and control plane (`kinetum_cp`)
  as one ordered transaction: DP must report exact control readiness before CP
  starts, and exact packet readiness before ordinary supervision begins.
- Handles signal-driven graceful shutdown and (when enabled) child
  process restart on failure.

DP checks host/core compatibility through Quark at startup (sections 4 and 14).

Source: `src/photon/`. CLI entry: `src/photon/photon_main.cpp`.
Process supervision: `src/photon/process.{hpp,cpp}`.
Exact startup/readiness: `src/photon/startup.{hpp,cpp}` and
`src/photon/readiness.{hpp,cpp}`.

### 2. Authoring Model

Five concepts:

| Term            | What it is                                                                |
| --------------- | ------------------------------------------------------------------------- |
| **Bundle**      | Mandatory manifest-bound deployment payload. Photon's sole deployment artifact input. |
| **Plan**        | Canonical `configs/plan.pbtxt` selected by bundle admission.              |
| **Supervisor**  | The `kinetum_photon` process itself. Owns child lifecycle and signals.    |
| **Child**       | `kinetum_dp` or `kinetum_cp`, launched as subprocesses by the supervisor. |
| **Runtime gates** | Process-image identity, bundle/plan identity (Photon), and strict host compatibility (DP+Quark). |

The mental model:

- **Bundle** proves *which plan and bootstrap snapshot belong together*; the
  **plan** says *what to run*; Photon says *how to launch and supervise it*.
- **DP** owns packet processing; **CP** owns configuration apply and gRPC.
Photon never processes packets.

### 3. Boot Sequence

```{uml}
@startuml
    autonumber
    participant "User / shell" as User
    participant "kinetum_photon\n(supervisor)" as Photon
    participant "canonical sibling kinetum_dp\n(child)" as DP
    participant "canonical sibling kinetum_cp\n(child)" as CP

    User->Photon: launch with ~--bundle DIR [flags]
    Photon->Photon: resolve /proc/self/exe;\nadmit exact DP/CP sibling images
    Photon->Photon: block SIGTERM/SIGINT/SIGUSR1;\nadmit logging and native diagnostic capture
    Photon->Photon: verify symlink-free bundle tree,\nmanifest, plan identity, snapshot identity
    Photon->Photon: select canonical configs/plan.pbtxt
    Photon->Photon: retain exact plan/snapshot/hash authority;\nbuild and validate child startup specification
    Photon->DP: posix_spawn exact DP image\nsanitized environment\n~--bundle VERIFIED_ROOT ~--listen DP_ENDPOINT\nexplicit shared logging settings
    note right of DP: DP independently re-admits the bundle,\nconsumes its sole compiled topology,\nproves that artifact through Quark,\nauthenticates required components,\nmaterializes one complete generation,\nthen publishes CONTROL_READY
    loop bounded CONTROL_READY gate
        Photon->DP: Health() with per-RPC deadline
        DP-->Photon: STARTING or exact CONTROL_READY
    end
    Photon->CP: posix_spawn exact CP image\n~--listen-addr CP_LISTEN\n~--dp-addr DP_ENDPOINT\n~--config-store-dir STORE_DIR\n~--bootstrap-snapshot VERIFIED_SNAPSHOT\n~--bootstrap-plan-content-hash VERIFIED_PLAN_SHA256\nexplicit shared logging settings
    CP->CP: Admit durable store and establish exact restoration authority
    CP->DP: Health(), then Bootstrap against this CONTROL_READY generation
    note over CP,DP: DP prepares and activates every worker behind the body gate,\nactivates provider I/O, publishes PACKET_READY, then releases workers\nCP reconciles retained mutation state before publishing its service
    loop bounded PACKET_READY gate
        Photon->DP: Health() with per-RPC deadline
        DP-->Photon: CONTROL_READY or exact PACKET_READY
    end
    alt either startup gate fails or a child exits
        Photon->CP: terminate and reap if started
        Photon->DP: terminate and reap
        Photon->Photon: retire native emitters;\ndrain and join its logging writer
        Photon-->User: exit 1
    else shutdown is requested during startup
        Photon->CP: terminate and reap if started
        Photon->DP: terminate and reap
        Photon->Photon: retire native emitters;\ndrain and join its logging writer
        Photon-->User: exit 0
    else both readiness gates succeed
        Photon->Photon: enter supervision loop
        loop every 1 second (SUPERVISION_POLL_INTERVAL)
            Photon->DP: check_process()
            Photon->CP: check_process()
            opt a child exits or waitpid observation fails
                alt nonzero exit and ~--restart-on-failure
                    Photon->Photon: stop and reap the complete pair;\nrepeat DP -> CONTROL_READY -> CP -> PACKET_READY
                else replacement is not authorized or fails
                    Photon->Photon: stop and reap the complete pair;\nrecord supervision failure
                end
            end
        end
        note over Photon: SIGTERM/SIGINT requests clean shutdown;\nunrecovered child loss is failure
        Photon->CP: terminate and reap
        Photon->DP: terminate and reap
        Photon->Photon: retire native emitters;\ndrain and join its logging writer
        Photon-->User: exit 0 after signal, otherwise exit 1 on failure
    end
@enduml
```

`main()` in `src/photon/photon_main.cpp` establishes logging and blocked signals,
admits the bundle, then constructs children. Every startup follows this order.

Readiness is state-based, not elapsed-time-based. The control gate retries only
transport `UNAVAILABLE`/`DEADLINE_EXCEEDED` and application `STATE_STARTING`;
it accepts only exact `STATE_CONTROL_READY`. The packet gate retries only those
transport failures and exact `STATE_CONTROL_READY`; it accepts only exact
`STATE_PACKET_READY`. Unknown enum values, skipped phases, regressions,
application errors, child exits, and cancellation are terminal. Each RPC and
each complete gate has a named bounded deadline in `readiness.hpp`.

The supervision loop checks child liveness every 1 second
(`SUPERVISION_POLL_INTERVAL` in `src/photon/photon_main.cpp`). The main thread
consumes blocked signals with `sigtimedwait`; startup and replacement waits poll
the same owner. No asynchronous handler invokes logging or C++ code.

### 4. Production Runtime Requirements

All deployments, including development providers, require:

| Requirement                                          | Where enforced                                |
| ---------------------------------------------------- | --------------------------------------------- |
| Canonical Linux Photon image with exact executable DP/CP siblings | **Photon** before bundle I/O (`current_process_image`, `resolve_sibling_process_image`) |
| Complete symlink-free bundle with valid manifest, canonical plan hash, and exact plan-bound bootstrap snapshot | **Photon** at startup (`verify_runtime_bundle`) |
| Every provider `Any` role-correct and byte-canonical under the exact plan identity | **Shared bundle verifier**, through the deployment-plan identity authority |
| Exact facilities, I/O drivers, storage domains, execution providers, ports, queues, streams, transitions, and placements form one complete graph | **Shared provider-topology compiler**, consumed by Gluon, runtime-bundle admission, and DP |
| Worker and runtime-service CPU ownership populated, disjoint, and valid on this host | **DP** at startup, via strict Quark `probe_host()` + `validate_runtime_compat()` |
| Fixed root-owned installed release, authenticated inventory, exact required components, and non-materializing component host proofs | **DP** before `CONTROL_READY` |
| Native packet-provider construction | **DP transactional materializer** before `CONTROL_READY`; ingress activates only during Bootstrap |
| No provider, queue, storage, execution, attachment, or native-argument CLI repair | **Photon and DP CLI shape**; runtime wiring comes only from the verified plan |
| Owned protected log directory and exclusive role-file ownership | **Each process**, before its service startup |

**Three-gate model**: Photon admits its process image and DP/CP siblings, then
the immutable bundle's canonical plan/snapshot identities. After spawn, DP
checks host compatibility through Quark. Executable and artifact checks precede
child side effects; host/plan checks run in the process that owns the selected
cores. See [`QUARK.md`](QUARK.md) for proof scope and `compat_report`.

Photon proves that the plan and bootstrap snapshot are the canonical artifacts
declared by the manifest. The shared verifier also runs the same provider-
topology compiler used by DP, but Photon does not inspect its compact result,
select a provider, derive a native argument, or reconstruct graph semantics.
Live host evidence, exact component provenance, and native capability checks
remain their owning DP startup stages.

### 5. One Exact Startup Mode

Photon has no development escape hatch. A development deployment selects
explicit development provider contracts and exact deployment bindings; it does
not weaken admission or ask Photon to repair an incomplete plan.

Both use complete bindings, verified bundles, and strict host validation.
[Providers](PROVIDERS.md) describes how the selected graph becomes native
resources; Photon uses the same readiness and supervision gates for each graph.

A development provider must also be present in an authenticated installed
inventory rooted beside the exact DP image. The production release
aggregate contains the host and DPDK components; UDP remains a
development/conformance component and is not an unsigned source-tree bypass.
DP and CP are spawned by the same transaction, and signal handling, readiness,
supervision, and pair cleanup are identical for every admitted graph.

### 6. Runtime-Bundle Loading and Validation

Photon's artifact handling has four steps:

1. **Admit** - call `verify_runtime_bundle(--bundle)`. The shared verifier
   rejects symlink indirection and undeclared tree entries, validates every
   manifest entry, and requires the exact canonical plan and bootstrap-snapshot
   paths.
2. **Verify semantics** - strictly parse those exact manifest-bound bytes,
   canonicalize every role-correct provider configuration, verify the complete
   plan's canonical content hash, compile the complete provider topology, and
   canonicalize the snapshot against the plan's exact module set.
3. **Retain authority** - use only the verifier-returned canonical plan path,
   canonical snapshot path, and exact lowercase plan hash. Photon does not
   reopen a caller-selected substitute.
4. **Construct** - validate child-startup inputs, then build the exact DP/CP
   argv from those retained authorities.

These steps finish before child-process construction. Photon passes the
verifier's canonical bundle root to DP, with no direct-plan or substitute path.
DP independently re-admits it and uses the compiled artifact for Quark and
materialization. DP startup also owns component availability and native
capability checks; Photon cannot duplicate or repair them.

## Part 2: Process Ownership and Supervision

### 7. Process Layout, Command Construction, and IPC

Photon's children run as separate processes. Every runnable layout keeps the
three process images as canonical siblings:

```
<image-directory>/
+-- kinetum_dp
+-- kinetum_cp
+-- kinetum_photon
```

Photon resolves its running Linux image from `/proc/self/exe`, canonicalizes
that kernel-owned identity, and admits `kinetum_dp` and `kinetum_cp` as exact
executable siblings. It never derives child identity from `argv[0]`, `PATH`,
the current working directory, an environment prefix, or a hardcoded install
prefix. A symlinked Photon invocation still resolves the real Photon image;
the child images themselves must be canonical, regular, executable files.

The production layout is exact:

| Context | Canonical Photon image | Canonical sibling images |
| ------- | ---------------------- | ------------------------ |
| Packaged runtime install | `/opt/kinetum/bin/kinetum_photon` | `/opt/kinetum/bin/kinetum_dp`, `/opt/kinetum/bin/kinetum_cp` |

The launch directory is irrelevant. A build tree can exercise binaries and
unit tests, but its loose DP image is not a finalized installation root and
fails provider provenance admission. Local development therefore uses the
same prepare, sign, install, and sibling-image contract as deployment. See
[`GETTING_STARTED.md`](GETTING_STARTED.md) and section 13.

Children inherit Photon's standard I/O and environment except all `LD_`-prefixed
variables, removed before `posix_spawn()`. This excludes preload, library-path,
audit, and other dynamic-loader controls without a name-by-name list.
Each process owns its file writer under the admitted log directory. With
`--log-console`, the same records are also mirrored to the inherited stderr
stream. Photon forwards settings; it does not collect or rewrite child records.
See [Logging](LOGGING.md) for file ownership, rotation, loss accounting, and format.

#### 7.1 DP child command

Composed inside `start_supervised_children()` after `photon_main.cpp` prepares
the validated startup specification:

```
<canonical-image-directory>/kinetum_dp --bundle <ROOT> --listen <DP_ENDPOINT> <LOGGING_ARGS>
```

| Argument        | Source                                                    |
| --------------- | --------------------------------------------------------- |
| `--bundle`      | Canonical absolute root returned by runtime-bundle admission. DP independently re-admits the complete root. |
| `--listen`      | Photon's `--dp-endpoint` flag (default `127.0.0.1:50052`).|
| `<LOGGING_ARGS>` | Explicit directory, default/component levels, file size/count, and optional console mirror from the admitted shared settings. |

Photon launches DP with `spawn_process_argv()` from
`src/photon/process.cpp`. The process boundary revalidates the exact image and
calls `posix_spawn()` with the absolute path. The bundle root and endpoint are
argv entries; there is no shell or PATH search.

Photon deliberately does not inspect provider contracts. The verified plan is
the sole provider-selection authority; DP's shared compiler owns semantic
truth. DP authenticates the exact required component set, seals its
implementation catalog, and materializes the compiled graph before it may
publish packet readiness.

DP is launched **first**, before CP. Photon polls `DataplaneService.Health`
until the DP reports exact `STATE_CONTROL_READY`; no elapsed-time delay is used
as readiness evidence. A DP exit or readiness timeout terminates startup before
CP construction.

#### 7.2 CP child command

Composed inside `start_supervised_children()` from the same retained
specification after DP reaches exact control readiness:

```
<canonical-image-directory>/kinetum_cp --listen-addr <CP_LISTEN> --dp-addr <DP_ENDPOINT> \
  --config-store-dir <STORE_DIR> \
  --bootstrap-snapshot <VERIFIED_SNAPSHOT> \
  --bootstrap-plan-content-hash <VERIFIED_PLAN_SHA256> <LOGGING_ARGS>
```

| Argument             | Source                                                       |
| -------------------- | ------------------------------------------------------------ |
| `--listen-addr`      | Photon's `--cp-listen` flag (default `127.0.0.1:50051`).      |
| `--dp-addr`          | Photon's `--dp-endpoint` flag (default `127.0.0.1:50052`).    |
| `--config-store-dir` | Photon's absolute `--config-store-dir` flag (default `/var/lib/kinetum/config`). CP stores snapshots there. |
| `--bootstrap-snapshot` | Canonical absolute snapshot path returned by the shared runtime-bundle verifier. |
| `--bootstrap-plan-content-hash` | Exact lowercase `DeploymentPlan.content_hash` independently verified during bundle admission. |
| `<LOGGING_ARGS>` | The same explicit logging settings supplied to DP. |

Photon launches CP through the same exact-image `posix_spawn()` path, so
endpoint and config-store path arguments are not shell-expanded. Photon rejects
a relative or non-normalized durable-state path before child construction.

CP reads DP Health before restoration. Photon's new DP is `CONTROL_READY`, so
CP sends its durable Bootstrap request. A separately restarted CP may rejoin a
surviving `PACKET_READY` DP only after matching durable and live identity and
reconciling pending work; a fresh store is rejected. The full watermark,
reply-loss, and observation rules belong to
[CP startup](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md#3-process-lifecycle).

Photon starts supervision only after DP reports `STATE_PACKET_READY`. Spawn
failure, child exit, or timeout terminates and reaps CP before DP, then exits
`1`. SIGINT/SIGTERM cancellation follows the same cleanup and exits `0` after
reaping.

A scope-bound pair owner covers early returns and exceptions. Failed explicit
cleanup leaves it armed for a final attempt. If reaping still cannot be proved,
Photon emits a bounded raw diagnostic and terminates without discarding child
ownership.

Photon always passes `--config-store-dir` to CP, so Photon's default
(`/var/lib/kinetum/config`) is the one that matters in supervised runs.
When `kinetum_cp` is launched directly, its standalone default is
`/tmp/kinetum_cp_store` (`src/cp/cp_main.cpp`).

#### 7.3 IPC

Two gRPC channels at well-known endpoints:

| Channel                  | Endpoint                          | Direction       |
| ------------------------ | --------------------------------- | --------------- |
| External -> CP           | `127.0.0.1:50051` (default)       | `kinetumctl` and explicit external clients call CP |
| CP -> DP                 | `127.0.0.1:50052` (default)       | CP applies snapshots, DP exposes stats             |

Override defaults with `--cp-listen` and `--dp-endpoint`.

Photon does not expose or forward child TLS flags. Its supervised DP/CP pair
therefore uses plaintext on the configured endpoints and is intended for a
host-local or otherwise isolated control network. The DP, CP, and `kinetumctl`
binaries have direct-invocation TLS surfaces, but using them requires an
external process owner rather than this Photon child-command path.

### 8. Process Supervision

#### 8.1 Signal handling

Photon admits its signal set in `src/photon/photon_main.cpp` before creating
logging or gRPC threads. Those threads inherit the blocked control signals:

| Signal     | Handler                                                       |
| ---------- | ------------------------------------------------------------- |
| `SIGTERM`  | Consumed by the main thread; requests dependency-ordered shutdown. |
| `SIGINT`   | Same as `SIGTERM`.                                            |
| `SIGUSR1`  | Requests checked reopen of Photon's files and forwards reopen to the owned DP/CP pair. |
| `SIGPIPE`  | Ignored (`SIG_IGN`). Prevents broken-pipe writes from killing the process. |

Other signals retain their default disposition.

A reopen received during startup is forwarded after the complete pair is
admitted. Reopen does not reload configuration, change levels, or authorize
replacement of a process. A failed reopen leaves the destination unavailable
and its losses observable; supervision continues under the existing policy.

#### 8.2 Restart policy

`--restart-on-failure` selects between two CLI-visible policies
(`src/photon/photon_main.cpp`):

| Policy                       | Behavior                                                       |
| ---------------------------- | -------------------------------------------------------------- |
| `restart_policy::NEVER` (default) | An observed child exit causes CP-before-DP pair cleanup and Photon exits `1`; no replacement pair is started. |
| `restart_policy::ON_FAILURE` (`--restart-on-failure`) | If either observed child exited nonzero, Photon reaps the complete pair and reruns the full DP CONTROL_READY -> CP bootstrap -> DP PACKET_READY transaction. A zero-exit child does not authorize replacement and Photon exits `1` after pair cleanup. |

The scope-bound pair owner holds the sole policy; child records contain no
policy copy. There is no per-child restart: CP cannot be retried against an
already `PACKET_READY` DP, and a replacement pair becomes supervisable only
after both readiness gates close.

`--restart-on-failure` performs immediate whole-pair replacement after an
eligible exit. Photon supplies neither exponential backoff nor an
operator-configured retry-count ceiling; exhaustion of the fixed pair counter
is terminal. An external service manager must own any fleet-level crash-loop
policy.

#### 8.3 Failure modes

| Scenario                                          | Behavior                                                          |
| ------------------------------------------------- | ----------------------------------------------------------------- |
| Photon image cannot resolve, or an exact DP/CP sibling is missing, symlinked, non-regular, or non-executable | Photon exits `1` before bundle I/O, signal installation, or child construction. |
| Logging destination cannot be admitted | Photon reports the startup failure on stderr and exits `1` before child construction. |
| Bundle missing, symlinked, manifest-invalid, or semantically inconsistent | Photon exits `1` before child construction. |
| `--config-store-dir` is relative or non-normalized | Photon exits `2` before child construction. |
| DP fails to spawn                                 | Photon exits `1`.                                                 |
| DP rejects host or provider-graph requirements | Photon observes failure during the control-readiness gate, reaps every started child in dependency order, and exits `1`. |
| DP rejects installed provenance, a required component, or a COMPONENT-phase proof | Photon observes failure during the control-readiness gate, reaps every started child in dependency order, and exits `1`. |
| DP rejects provider materialization | Photon observes failure before packet readiness, reaps every started child in dependency order, and exits `1`. |
| DP does not reach exact `CONTROL_READY`            | Photon terminates and reaps DP, then exits `1`.                   |
| CP fails to spawn                                 | Photon terminates and reaps DP, then exits `1`.                   |
| DP does not reach exact `PACKET_READY`             | Photon terminates and reaps CP before DP, then exits `1`.         |
| Unknown/skipped/regressed DP readiness state       | Immediate startup rejection and dependency-ordered child cleanup. |
| `SIGINT` or `SIGTERM` received during startup        | Startup cancellation; CP (if present) and DP are reaped in dependency order. |
| Child `waitpid` observation fails during supervision | Photon logs the explicit liveness error, reaps CP then DP, and exits `1`. |
| Either child exits, restart disabled              | Photon reaps CP before DP and exits `1`; complete cleanup does not turn service loss into success. |
| Either child exits non-zero, `--restart-on-failure` | Photon reaps CP before DP and reruns the complete pair startup transaction. Failure to reach both gates is terminal. |
| Either child exits zero, `--restart-on-failure`   | Photon reaps the pair and exits `1`; a zero exit does not authorize replacement. |
| `SIGTERM` or `SIGINT`                             | Loop breaks; CP then DP are sent `SIGTERM` and reaped. |
| Unexpected exception after packet-ready handoff   | The scope-bound pair owner performs CP-before-DP cleanup, then Photon exits `1` if reaping is proven. |
| Final startup-rollback or pair-owner cleanup cannot prove complete reaping | Photon emits one fixed bounded diagnostic and terminates before relinquishing either retained child authority. |

#### 8.4 Shutdown order

On loop exit (`src/photon/photon_main.cpp`):

1. `supervised_pair_owner::stop()` invokes its one internal pair-cleanup path,
   which terminates and reaps CP with the configured timeout.
2. The same pair authority terminates and reaps DP with that timeout. Its
   destructor remains armed until complete cleanup succeeds. An explicit
   cleanup failure is therefore retryable only by the still-owning scope; if
   the scope-final attempt also fails or throws, Photon emits the fixed bounded
   reaping diagnostic and terminates instead of unwinding an unproven PID
   authority.
3. After the pair and gRPC emitters retire, Photon drains accepted diagnostics
   for up to two seconds and joins its writer. An unresolved writer is a
   terminal ownership failure; it is never detached.

`terminate_process` sends `SIGTERM`, waits for graceful exit, and
escalates to `SIGKILL` if the timeout expires. Success means the child was
reaped with `waitpid()` or was already reaped; accepted SIGKILL is followed by
a mandatory blocking reap
(`src/photon/process.cpp`).

### 9. Supervision Scope and Policy Boundary

Photon retains and observes the packet-ready pair, applies its restart policy,
and cleans up CP before DP. It neither interprets packet telemetry nor originates
configuration mutations.

#### 9.1 Observed state

Each supervision turn checks DP and CP through the process controller. A
successful observation says only whether the exact retained child is still
running and, after exit, which wait status the owner collected. It does not
treat a healthy process as proof of packet correctness; readiness and runtime
telemetry keep their own authorities.

When either child exits, `supervised_pair_owner::resolve_observed_exit()`
evaluates its one retained pair policy:

- a policy-declined replacement retires the complete pair and returns a
  non-OK result;
- an eligible on-failure restart first retires both children, then repeats the
  full DP control-ready, CP bootstrap, and DP packet-ready transaction;
- a failed observation, cleanup, spawn, or readiness gate ends supervision with
  an error and leaves no silently detached child.

The operation returns OK only when the replacement pair reaches packet readiness.

#### 9.2 Policy boundary

Photon has no statistics poller, health-policy evaluator, adaptive controller,
or configuration RPC client. CP guardrails owns evidence-based automatic
rollback through its durable mutation authority. Operators and explicit clients
use `kinetumctl` or the ControlService directly. This separation keeps process
liveness, observation, and configuration policy as distinct contracts.

The public EWMA, hysteresis, rate, and PID utilities remain reusable algorithms
under `include/kinetum/algo/`; their presence does not imply a Photon policy
loop.

#### 9.3 Recurring work and shutdown

The ordinary loop performs one bounded DP check followed by one bounded CP
check, then waits up to `SUPERVISION_POLL_INTERVAL` before the next turn.
The signal wait can wake earlier for termination or log reopen.
`supervised_pair_owner::stop()` then terminates and reaps CP before DP. If
final scope cleanup still cannot prove both child authorities retired, Photon
terminates rather than discard ownership.

### 10. Logging and Observability

Photon writes bounded readable text records to
`/var/log/kinetum/kinetum_photon.log` by default. DP and CP own
`kinetum_dp.log` and `kinetum_cp.log` in the same directory. The optional
`--log-console` mirror uses the identical format. Startup errors remain visible
on stderr. [Logging](LOGGING.md) owns the complete record and retention contract.
Notable lines:

| Log message                                       | When                                                |
| ------------------------------------------------- | --------------------------------------------------- |
| `"verified bundle: <root>"` / `"bootstrap snapshot: <path>"` | Complete runtime-bundle admission succeeded before runtime setup. |
| `"starting supervisor"` / `"plan=..."`            | After runtime-bundle and startup-spec validation, before spawn. |
| `"DP startup: ..."` / `"CP startup: ..."`         | Bounded summaries carrying actual admitted paths and endpoints. |
| `"supervised startup failed: ..."`                | Spawn, readiness, cancellation, or startup cleanup failed. |
| `"supervisor running, press Ctrl+C to stop"`      | Entering the supervision loop.                      |
| `"<role> process exited (exit_code=N); resolving the complete supervised pair"` | A DP or CP exit selected pair-scoped resolution. |
| `"supervised pair cannot continue: ..."`          | Policy declined replacement, pair retirement failed, or the replacement did not reach packet readiness. |
| `"supervised pair restart completed through PACKET_READY (count=N)"` | A fresh DP/CP generation completed exact bootstrap. |
| `"received signal N, shutting down"`              | SIGTERM/SIGINT path.                                |
| `"stopping supervised pair (CP before DP)"`       | Ordered pair retirement begins.                     |
| `"supervisor shutdown complete"`                  | Both retained child authorities were resolved.      |

#### 10.1 Child log ownership

Photon validates the shared settings once and passes them explicitly to each
child, which independently admits its own role files. Each process owns a
separate queue, writer, file lock, and rotation sequence. Logging availability
never selects readiness, configuration behavior, or restart policy.

## Part 3: Operation and Embedding

### 11. CLI

```
kinetum_photon --bundle <bundle_dir> [options]
```

| Flag                                  | Default                  | Purpose                                                           |
| ------------------------------------- | ------------------------ | ----------------------------------------------------------------- |
| `--bundle <dir>`                      | -                        | Complete runtime bundle. **Required.**                             |
| `--config-store-dir <dir>`            | `/var/lib/kinetum/config` | Absolute directory for CP's durable config store.                  |
| `--cp-listen <addr>`                  | `127.0.0.1:50051`        | CP gRPC listen address.                                            |
| `--dp-endpoint <addr>`                | `127.0.0.1:50052`        | DP gRPC listen address.                                            |
| `--restart-on-failure`                | off                      | Restart children on non-zero exit.                                 |
| `--log-dir <absolute-dir>`            | `/var/log/kinetum`        | Shared parent directory for the three independently owned role files. |
| `--log-level <level>`                 | `info`                   | Minimum severity: `debug`, `info`, `warn`, `error`, or `fatal`. |
| `--log-component-level <name>=<level>` | none                     | Override one known component; duplicate components reject. |
| `--log-max-bytes <bytes>`             | `16777216`               | Maximum complete-record file size before rotation. |
| `--log-keep-files <count>`            | `8`                      | Total files per role including active; range `2..32`. |
| `--log-console`                      | off                      | Mirror the same records to inherited stderr. |
| `-h`, `--help`                        | -                        | Show usage.                                                        |

Exit codes:

| Code | Meaning                                                                |
| ---- | ---------------------------------------------------------------------- |
| `0`  | Help completed, or SIGINT/SIGTERM during startup or supervision completed exact CP-before-DP shutdown. |
| `1`  | Process-image or runtime-bundle admission failure, startup/readiness failure, child spawn failure, unrecovered child exit, or supervision/cleanup failure. |
| `2`  | CLI usage error: invalid durable-state path, malformed or duplicate option, or missing `--bundle`. |

`-h` and `--help` print usage and return `0`.

### 12. Embedding Photon

Photon exposes one process/readiness supervision surface. It is an internal C++
library contract, not an installed public SDK ABI.

#### 12.1 Process supervision (`src/photon/process.hpp`)

| API                                                | Use                                                          |
| -------------------------------------------------- | ------------------------------------------------------------ |
| `spawn_process_argv(name, argv)` -> `status_or<child_proc>` | Admit an exact canonical executable and launch it with direct `posix_spawn()` argv. |
| `check_process(child_proc&)` -> `status_or<bool>`  | Update child state from `waitpid`; distinguish running/exited from observation failure. |
| `terminate_process(child_proc&, timeout_ms)` -> `status` | Send `SIGTERM`, wait up to the required nonnegative graceful timeout, then escalate. |
| `request_process_log_reopen(child_proc)` -> `status` | Send `SIGUSR1` only through a retained child identity; never changes restart policy. |
| `validate_readiness_wait_policy(policy)` -> `status` | Validate positive, relationally coherent RPC/poll/overall bounds. |
| `classify_readiness_state(gate, state)` -> `status_or<readiness_progress>` | Accept only a gate's exact target or sole declared pre-state. |
| `wait_for_exact_readiness(observer, gate, policy, progress)` -> `status_or<dataplane_health_identity>` | Run one bounded, cancellation- and liveness-aware readiness gate and return the exact target identity. |
| `start_supervised_children(spec, observer, processes, shutdown)` -> `status_or<supervised_children>` | Execute transactional DP-then-CP startup and transfer both child authorities only after exact packet readiness. |
| `supervised_pair_owner`                              | Hold the packet-ready pair, exact startup specification, and sole restart policy; resolve an observed exit, or perform final ordered cleanup without relinquishing unproven child authority. |
| `supervised_pair_owner::resolve_observed_exit(observer, shutdown)` -> `status` | Clean the observed pair and return OK only after an authorized replacement completes both readiness gates. |
| `restart_policy` enum                              | Exact `NEVER` or `ON_FAILURE` policy. |
| `process_state` enum                               | `NOT_STARTED`, `RUNNING`, `TERMINATED`, `KILLED`, or `EXITED`. Spawn failure returns status and creates no record. |
| `child_proc` struct                                | Owns one PID/reaping obligation plus its bounded name, owner-observed state, and retained exit code. |

Photon and its component tests consume this internal surface.

`child_proc::is_running()` reports its conservative owner state. Parent-side
path admission or spawn failure returns an error instead of manufacturing a
child record. Moving a record transfers its sole PID/reaping authority and
leaves the source explicitly non-owning; move-assignment refuses to overwrite a
live destination. One owner accesses a record; its state and exit code are
plain fields rather than a false partial thread-safety mechanism.

Destroying a record still classified `RUNNING` emits its bounded name/PID
identity and aborts. That classification deliberately includes a child that
has exited but whose wait status the owner has not consumed. A caller of the
low-level spawn API must therefore reap the record or transfer it immediately
to the startup/pair owner.

There is one spawn path. It rejects relative, non-normalized, symlinked,
non-regular, or non-executable `argv[0]`, then calls `posix_spawn()` with that
exact path (`src/photon/process.cpp`). There is no shell-based embedding API and
no `posix_spawnp()`/`execvp()` PATH search. The child inherits the parent's
standard I/O and every ordinary environment entry, while all `LD_*` entries
are omitted. Pair replacement reconstructs and revalidates both exact argv
vectors and repeats the same environment sanitation.

`readiness.hpp` exposes strict state classification, coherent bounded wait
policies, the `dp_health_observer` interface, and the production gRPC observer.
`startup.hpp` exposes `supervised_startup_spec`, exact DP/CP argv builders, the
testable `startup_process_controller`, `start_supervised_children()`, and the
scope-bound `supervised_pair_owner`. The startup call transfers two
`child_proc` authorities only after both exact gates; all earlier exits roll
back CP before DP. Ordinary supervision immediately moves those authorities,
the admitted startup specification, and one policy into the owner. The owner
alone may replace the complete pair; no single-child restart API exists.

#### 12.2 Error categories

The `process.hpp` embedding surface returns platform `status` values:

| Code               | Typical causes                                      |
| ------------------ | --------------------------------------------------- |
| `INVALID_ARGUMENT` | Empty process name, empty command, or overlong name. |
| `NOT_FOUND` / `PERMISSION_DENIED` | Exact image admission or `posix_spawn()` could not access the image. |
| `RESOURCE_EXHAUSTED` | `posix_spawn()` reported an argument, process, or memory resource limit. |
| `INTERNAL_ERROR`   | Another `posix_spawn()`, `kill()`, or `waitpid()` failure. |

Photon CLI failures such as malformed arguments or runtime-bundle admission
errors are process exit codes, not `status` values returned from this
embedding API. `posix_spawn()` image-execution failure is returned
synchronously to the parent and creates no `child_proc` authority.

#### 12.3 Determinism

Health responses and deadlines determine startup timing; signals trigger
shutdown, and child exits select restart policy. The same observations produce
the same accepted states and cleanup order, but wall-clock completion is
not deterministic.

### 13. Walkthroughs

Both workflows enforce bundle, host, provider, bootstrap, and readiness checks.

#### 13.1 Production walkthrough (edge gateway)

Production deployments install Kinetum from the runtime tarball produced
by `kinetum_package prepare` and `kinetum_package sign`. The default install prefix is
`/opt/kinetum`, which lays out runtime binaries under `/opt/kinetum/bin`
and built-in modules under `/opt/kinetum/lib/modules`.

The final runtime tarball includes `kinetum_photon`, `kinetum_dp`, and
`kinetum_cp` together with the exact host/DPDK production components,
canonical installed inventory, detached Ed25519 signature, and native
self-admission receipt. Its final payload manifest defines exact runtime-owned
membership and hashes every other runtime artifact. Native installation and
`kinetum-info --check` share exact manifest and provider verification.
Candidate archives have neither the signature nor final payload manifest and
are deliberately not installable.

The release channel authenticates archive delivery. Choose the runtime entry
for the target architecture. That package-specific POSIX-sh script checks the
host match, verifies its bound archive digest, and invokes the native installer
inside the tar. With `RELEASE_URL` set to the actual release's HTTPS asset
directory, the x86-64 command is:

```bash
set -o pipefail
curl -fsSL "$RELEASE_URL/kinetum-runtime-0.1.0-x86_64.install.sh" | sudo /bin/sh
```

For AArch64, select `kinetum-runtime-0.1.0-aarch64.install.sh`. Neither entry
requires an SDK, website, or another architecture's package.

The default prefix is `/opt/kinetum`. The installer validates a complete private
candidate before replacement and checks installed bytes before success. Failed
replacement restores prior entries; incomplete restoration reports both the
original failure and recovery state and retains the recovery tree. It
does not start Photon or coordinate a live update. Runtime replacement preserves
only the independent `sdk/` and `dependencies/` peers. Private validation kits
remain outside the runtime prefix.

Continue only after the installation transaction exits successfully:

```bash
# 2) Build a complete runtime bundle. The snapshot is explicit and mandatory.
/usr/bin/sudo /usr/bin/install -d -m 0755 -- /var/lib/kinetum
/usr/bin/sudo /usr/bin/install -d -m 0755 \
  -o "$(/usr/bin/id -u)" -g "$(/usr/bin/id -g)" -- \
  /var/lib/kinetum/bundles
/opt/kinetum/bin/kinetum_pack \
  --axiom /path/to/fan_in_edge_gateway.axiom.pbtxt \
  --hw /path/to/hardware_inventory_cloudlab_d430.pbtxt \
  --bindings /path/to/fan_in_edge_gateway_cloudlab_d430_bindings.pbtxt \
  --modules-dir /opt/kinetum/lib/modules \
  --bootstrap-snapshot /path/to/config_snapshot.pbtxt \
  --regions 3 \
  --out /var/lib/kinetum/bundles/fan_in_edge_v1

# Optional handoff check; pack already self-verified the completed output.
/opt/kinetum/bin/kinetum_bundle_verify \
  --bundle /var/lib/kinetum/bundles/fan_in_edge_v1

# 3) Run Photon from any working directory. Its own canonical image selects
#    the exact DP/CP sibling images.
sudo /opt/kinetum/bin/kinetum_photon \
  --bundle /var/lib/kinetum/bundles/fan_in_edge_v1
```

The working directory has no effect on child identity. The default durable
store is `/var/lib/kinetum/config`; use an explicit absolute
`--config-store-dir` when a deployment owns another location.

Inspect the default files with:

```bash
sudo tail -f /var/log/kinetum/kinetum_photon.log /var/log/kinetum/kinetum_cp.log /var/log/kinetum/kinetum_dp.log
```

The records include:

- `starting supervisor`
- `DP startup: ...` with the admitted bundle path and endpoint
- `CP startup: ...` with the admitted snapshot path and plan content hash
- `supervisor running, press Ctrl+C to stop`
- (After Ctrl+C) `received signal N, shutting down` ->
  `stopping supervised pair (CP before DP)` -> `supervisor shutdown complete`

#### 13.2 Local development walkthrough (finalized install, DPDK TAP)

Development bundles require a finalized installation; a loose build-tree DP
cannot bypass signed provider admission. This example uses an existing AArch64
`build/` with the release settings in Getting Started and a release seed whose
reviewed public anchor is compiled into those artifacts. Invoke that build's
`kinetum_package` or a byte-identical copy. Preparation creates
invocation-relative `dist/` without another build or documentation input.
Signing produces the archive, checksum, and the same installer used by downloaded
releases. See
[`GETTING_STARTED.md`](GETTING_STARTED.md#build-packages-from-source) for key
generation, independent package publication, and separate SDK qualification.

```bash
./build/kinetum_package prepare --product runtime --build-dir build
./build/kinetum_package sign --candidate dist/kinetum-runtime-0.1.0-aarch64.candidate.tar.gz --key "$HOME/.kinetum-release/provider-ed25519.seed"
sudo /bin/sh dist/kinetum-runtime-0.1.0-aarch64.install.sh --offline-directory "$PWD/dist"
```

Preparation reports the candidate path; signing consumes that explicit file
and produces the final archive consumed by that package's script. On x86-64
use the reported `x86_64` filenames. `--output-dir` selects another archive
output directory and creates it if absent. The script checks its embedded
digest and passes it to native installation. Local mode skips network and APT
use, so the system prerequisites must already be installed; the source
bootstrap supplies them on the build host.
Signing opens its protected key only after decoding has completed and its child
has been reaped; held-descriptor admission and derived-anchor equality precede
static signing, with no target-code execution.

Continue only after prepare, sign, and installation all exit successfully:

```bash
# 4) Build a module-free but explicit runtime bundle. The TAP bindings select
#    the DPDK facility, DPDK TAP I/O, DPDK storage, CPU execution, and queues.
test ! -e build/dev_bundle
/opt/kinetum/bin/kinetum_pack \
  --axiom examples/passthrough/passthrough.axiom.pbtxt \
  --hw examples/passthrough/hardware_inventory_tap.pbtxt \
  --bindings examples/passthrough/passthrough_tap_bindings.pbtxt \
  --bootstrap-snapshot examples/passthrough/config_snapshot.pbtxt \
  --regions 1 \
  --out build/dev_bundle

# 5) Run the installed Photon from any working directory. Use an exact
#    development store instead of the production /var/lib default.
sudo /opt/kinetum/bin/kinetum_photon \
  --bundle "$PWD/build/dev_bundle" \
  --config-store-dir /tmp/kinetum_dev_config
```

Use a separate absolute `--log-dir` for another instance. Add `--log-console`
when an interactive run should also show ordinary records in the terminal.

What does not change:

- Deployment bindings remain complete; queue zero, storage, and CPU execution
  are explicit rather than inferred.
- Bundle verification and strict host compatibility are identical to the
  production flow.
- Photon passes no provider selector to DP. The verified plan remains the sole
  provider graph authority.
- The runtime authenticates the same fixed installed inventory and loads only
  the contracts required by the local plan.

## Part 4: Cross-Cutting

### 14. Photon vs DP vs CP vs Quark Responsibilities

| Concern                                                 | Owner                |
| ------------------------------------------------------- | -------------------- |
| Runtime-bundle path, manifest, plan, and bootstrap-snapshot admission | **Photon**, through shared pack verifier |
| Canonical plan-path selection and pbtxt parsing         | **Photon**, through shared pack verifier |
| Provider-configuration canonicalization during plan verification | **Shared deployment-plan identity authority**, consumed by Photon through bundle verification |
| Spawning DP and CP children                             | **Photon**           |
| Constructing DP and CP argv                             | **Photon**           |
| Signal handling and graceful shutdown ordering          | **Photon**           |
| Restart policy (`--restart-on-failure`)                 | **Photon**           |
| Runtime host vs worker/service process-core compatibility gate | **DP** (via Quark) |
| Complete provider/facility/I/O/storage/execution/transition semantics | **Shared provider-topology compiler**, consumed by bundle admission, Gluon, and DP |
| Live CPU/NUMA host proof over the exact compiled artifact | **DP**, through Quark |
| Installed component provenance and sealed implementation availability | **DP startup provenance authority** |
| Native facility, device, and queue capability proof     | **DP transactional materializer** |
| Plan execution (packet processing, regions)             | **DP**               |
| Snapshot apply, rollback, gRPC server                   | **CP**               |
| Evidence-based automatic rollback policy                | **CP guardrails**    |
| Owner-completed packet, transition, health, and provider telemetry | **DP**, through one generation-scoped source |
| Shared telemetry validation and `GetStats` forwarding   | **CP**               |
| Queueing, file delivery, rotation, and diagnostic loss accounting | **Each emitting process**, through the common logger |

Photon's bundle verifier checks plan identity and provider-graph semantics.
DP compiles the same plan once at startup and passes that artifact to Quark's
`probe_host()` / `validate_runtime_compat()` boundary. DP also owns component
provenance and native capability checks. Photon neither interprets the topology
nor duplicates or repairs those decisions.

### 15. Where to Go Next

| If you want to...                                  | Read                                                       |
| -------------------------------------------------- | ---------------------------------------------------------- |
| Run an end-to-end deployment                       | [`GETTING_STARTED.md`](GETTING_STARTED.md)                 |
| Author a pipeline                                  | [`AXIOM.md`](AXIOM.md)                                     |
| Plan a deployment                                  | [`GLUON.md`](GLUON.md)                                     |
| Understand the dataplane runtime and the compat gate | [`DATA_PLANE.md`](DATA_PLANE.md)                             |
| Understand the control plane, guardrails, rollback   | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| Use `kinetumctl` for operations                     | [`KINETUMCTL.md`](KINETUMCTL.md)                           |
| Locate, retain, and inspect service diagnostics    | [`LOGGING.md`](LOGGING.md)                                  |
| Read the architectural overview                    | [`CONCEPTS.md`](CONCEPTS.md)                               |
| See the runtime in motion                          | [`diagrams/README.md`](diagrams/README.md)                 |
