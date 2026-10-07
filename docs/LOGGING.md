# Logging

This reference covers diagnostic format, files, filtering, rotation, loss
accounting, and shutdown.
Photon, CP, and DP use the same frontend and settings. Logging describes an
operation; it never selects packet behavior, configuration outcome, readiness,
rollback, or restart policy.

For process supervision, see [Photon](PHOTON.md). For typed health inspection,
see [kinetumctl](KINETUMCTL.md) and the [gRPC API](GRPC_API.md).

## Table of Contents

**Part 1: Contract and Settings**

1. [Files and Ownership](#1-files-and-ownership)
2. [Record Format](#2-record-format)
3. [Settings](#3-settings)

**Part 2: Runtime Mechanism**

4. [Cold Emission and Writer Lifetime](#4-cold-emission-and-writer-lifetime)
5. [Rotation and Reopen](#5-rotation-and-reopen)
6. [Failure and Health](#6-failure-and-health)

**Part 3: Operations and Integration**

7. [Operator Commands](#7-operator-commands)
8. [Native Integration and Source Map](#8-native-integration-and-source-map)

---

## Part 1: Contract and Settings

### 1. Files and Ownership

The default directory is `/var/log/kinetum`:

```text
/var/log/kinetum/
+-- kinetum_photon.log
+-- kinetum_photon.log.1 ... kinetum_photon.log.7
+-- kinetum_cp.log
+-- kinetum_cp.log.1 ... kinetum_cp.log.7
+-- kinetum_dp.log
+-- kinetum_dp.log.1 ... kinetum_dp.log.7
```

Each process owns its own append descriptor, writer thread, rotation sequence,
and stable `<role>.log.lock` file. The lock excludes another writer for the same
role in that directory, including while the active file is renamed. Another
instance requires another log directory.

`--log-dir` selects an absolute normalized directory. Its parent must exist;
the process can create the terminal directory. The terminal directory must
belong to the effective UID and must not be group- or world-writable. File
admission rejects symbolic links, nonregular objects, multiple hard links,
foreign ownership, and group/world write permission. New directories use mode
`0750`, data files `0640`, and locks `0600`, subject to the process umask.
Operations use the retained directory descriptor rather than resolving the
path again for each write.

Logs are mutable process data. Keep them outside the installed runtime and
its payload manifest. Release and debug builds use the same directory and
retention contract. No collector, syslog daemon, journal configuration, or
external rotation job is required for ordinary operation.

### 2. Record Format

Kinetum writes one fixed, readable text format to files and console mirrors.
Each escaped record occupies one line:

```text
2026-09-27T14:20:03.421000Z [INFO] dut kinetum_dp[26592:26601] module.admitted - module/admit_generation: admitted exact module generation: images=3 contexts=3
```

| Field | Meaning |
| --- | --- |
| Timestamp | Emission UTC in RFC 3339 form with six fractional digits; `-` when unavailable. |
| `[INFO]` | Named severity from the record's metadata. |
| Hostname | Process host; `-` when unavailable or unrepresentable. |
| Application[PID:TID] | Fixed executable role and actual emitting process/thread; unavailable IDs stay absent. |
| Event | Stable identifier, at most 32 printable non-space bytes. |
| Separator | `-` separates the header from message context. |
| Message | Component/function context and owned diagnostic text. Function is omitted when a native interface does not supply it. |

Ordinary platform severities are `debug`, `info`, `warn`, `error`, and `fatal`.
Fatal severity describes a diagnostic; the caller owns the terminal action.
Native adapters preserve supplied severity and metadata.
Native severity names additionally include `EMERG`, `ALERT`, `CRIT`, and `NOTICE`.

Collector header extraction (Python/PCRE named groups), after removing the
terminating LF; `message` retains the component/function prefix and escaped text:

```text
^(?P<timestamp>-|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z) \[(?P<level>DEBUG|INFO|WARN|ERROR|FATAL|EMERG|ALERT|CRIT|NOTICE)\] (?P<host>[!-~]{1,255}) (?P<app>[!-~]{1,48})\[(?P<pid_tid>-|[1-9][0-9]{0,19}(?::[1-9][0-9]{0,19})?)\] (?P<event>[!-~]{1,32}) - (?P<message>[^\r\n]*)$
```

Control and non-ASCII bytes use `\xHH`; a literal backslash is escaped.
Files contain no ANSI color sequences. Raw message storage is bounded to
8 KiB, and any bounded message or metadata truncation is marked explicitly.
One encoded record fits within 34 KiB. Each process serializes its own file;
timestamps do not establish a total order across processes or concurrent callers.

JSON, TextFormat, help, verification reports, and installer acknowledgements
retain their checked delivery contracts.
Finite-tool diagnostics use the same record encoder with synchronous stderr
delivery. Native gRPC diagnostics in finite commands admit ERROR and higher;
ordinary RPC startup messages do not accompany successful command results.
Service gRPC diagnostics follow the configured component level.
Finite tools do not start a background writer.

### 3. Settings

The three service executables accept the same options:

| Option | Default | Contract |
| --- | --- | --- |
| `--log-dir <absolute-dir>` | `/var/log/kinetum` | Exact protected file destination. |
| `--log-level <level>` | `info` | Minimum ordinary severity. |
| `--log-component-level <name>=<level>` | none | One override per known component. |
| `--log-max-bytes <bytes>` | `16777216` | File ceiling, at least 34816 bytes. |
| `--log-keep-files <count>` | `8` | Total steady-state files per role, including active; range `2..32`. |
| `--log-console` | off | Independent stderr mirror using identical records. |

Known components are `cp`, `cp.health`, `dp`, `gluon`, `grpc`, `kinetum_axiom`,
`kinetumctl`, `logging`, `module`, `pack`, `photon`, `provider`, `quark`, and `tls`.
Provider records include the actual instance and runtime generation. Module
lifecycle records include the actual module/context, worker placement, phase,
and epoch.

Unknown names, malformed values, duplicates, noncanonical numbers, and
unrepresentable retention limits reject. Settings are fixed for the invocation;
there is no live configuration reload or environment-selected destination.
Photon forwards the admitted settings explicitly to DP and CP. Each child
performs its own admission.

Startup errors are mirrored to stderr even when ordinary console mirroring is
off. Once the existing service startup gate completes, configured live filters
and the explicit mirror setting apply. This changes diagnostic visibility only.

Cold configuration operations produce these records at the default `info` level:

| Event | Meaning |
| --- | --- |
| `cp.snapshot.requested`, `cp.rollback.requested` | The RPC request passed admission and is being submitted to the mutation owner. |
| `cp.transition.allocated` | A new snapshot transition has a durable mutation sequence and target epoch. |
| `dp.bootstrap.requested`, `dp.bootstrap.completed` | Requested and successfully restored bootstrap snapshot, revision, and epoch. |
| `dp.prepare.requested`, `dp.activate.requested`, `dp.abort.requested` | The cold service received the named operation. |
| `dp.transition.result` | The operation's actual identity resolution, state, status, and failure reason. `PREPARED` and an in-progress observation do not mean `COMPLETE`. An exact retry reports the retained result. |
| `cp.snapshot.applied` | DP completed the transition and CP durably published the active snapshot, revision, and epoch. |
| `cp.confirm.completed`, `cp.guardrails.configured` | The requested confirmation or policy operation succeeded. |

Snapshot identity and revision identify content. Mutation sequence and target
epoch correlate CP and DP records. Configuration payloads and retry keys are not
dumped. CP's `applied` event is not repeated when returning retained success.
At `debug`, CP records preparation, activation, abort, resumption, and retained
replies; DP records completed transition duration.

Refused mutations, confirmed CP pre-commit aborts, and requested DP cancellation
are warnings; transition faults are errors. Failures include CP phase and
reason. Lost replies remain ambiguous while CP queries the outcome; timeout
does not prove activation absent. Status/health polling is quiet. A transition
query outage emits one warning per retry sequence and one recovery event.
These records originate on cold control threads.

## Part 2: Runtime Mechanism

### 4. Cold Emission and Writer Lifetime

```{uml}
@startuml
participant "Caller / native hook" as C
participant "Logging frontend" as F
collections "Bounded records\nand completion slots" as A
queue "Record-index queue" as Q
participant "Single writer" as W
database "Service log file" as L
boundary "Console / emergency stderr" as E

alt Native hook on a packet-owner thread
    C->F: native diagnostic
    F->F: count rejection and publish its count
    F-->C: return without format, lock, queue, wait, or I/O
else Ordinary cold record
    C->F: severity, component, event, message
    F->F: apply severity filter
    opt Filter admits the record
        F->A: claim a fixed record slot
        alt Slot available
            F->A: format into owned bounded bytes
            F->Q: publish record index
        else Arena unavailable or contended
            F->F: reject new record and count
        end
    end
    F-->C: return without waiting for the writer
else Foreign ERROR or higher on a cold thread
    C->F: diagnostic that bypasses suppression
    F->F: construct the owned record
    F->A: claim record and per-record completion slot
    alt Destination unavailable, claim refused, or submission refused
        F->F: count the outcome
        F->E: best-effort already-formatted emergency record
        F-->C: return without waiting
    else Accepted
        F->Q: publish record index and completion identity
        F->F: begin a wait bounded to 100 ms
        note over F,L: Writer service can complete this exact record while the caller waits
    end
end

group Writer service for an accepted record
    W->Q: consume record index
    W->A: borrow owned record bytes
    W->W: escape and encode one complete line
    W->L: checked append / owner rotation
    L-->W: delivered or failed, never merely consumed
    opt Completion requested
        W->A: publish this record's delivered / failed outcome
    end
end

par Writer continues independently
    opt Console mirror enabled
        W->E: mirror after publishing the file result
    end
else Cold foreign caller holds a completion claim
    opt Confirmation requested
        A-->F: exact file result, or wait expires
        alt Delivered
            F-->C: confirmed complete file write
        else Failure or timeout
            F->F: preserve and count the outcome
            F->E: best-effort emergency record
            F-->C: return
        end
    end
end
note over F,A: Caller and writer retire separate claims; timeout cannot free writer-owned storage
@enduml
```

The ordinary arena contains 256 fixed slots. It retains raw messages and
bounded metadata, at most 2.5 MiB before queue bookkeeping, one reserved fatal
record, and one reusable writer encoding buffer. Ordinary producers do not wait for
space or disk. Atomic index leases own arena availability; the MPMC queue carries
completed indices, and eventfd is notification only. Contended acquisition can
reject a new diagnostic without waiting for another producer.
Queues hold no borrowed strings, deferred formatters, or module/provider code.
There is no wait-free or fixed-cycle progress guarantee.

Packet workers never call the cold frontend, format messages, enqueue diagnostics,
or perform logging I/O. Activation and owner-health callbacks remain packet
work even at low cadence. A scope installed once at worker launch covers setup
through retirement. If a native library invokes its hook on that thread, the
host immediately rejects the record using an owner-local counter and one atomic
publication store. It performs no lock, retry loop, clock read, allocation, queue
operation, or I/O. Counts survive worker retirement and appear in logging health.
No logging check is added to ordinary packet turns.

Foreign ERROR and higher records on cold threads bypass severity suppression.
They use the same record arena and file writer, with a preallocated completion
slot holding their exact file result. A successful return from the wait requires
a complete checked file write, not merely queue consumption. The caller and
writer retain separate claims until both finish; a timeout never frees storage
still used by the writer. A bounded caller-owned copy supplies emergency output.

The per-record writer wait is at most 100 ms. Queue refusal, an unavailable
destination, or a failed write selects emergency stderr immediately. Timeout
also attempts emergency stderr but does not prove file loss: a late append may
succeed, producing an exceptional duplicate. Emergency output acquires no logger
lock and is best effort; it can block or interleave with other stderr writers.
A broken stderr pipe is counted without exposing this write's SIGPIPE to the
caller. Normal successful delivery does not enable an otherwise disabled console
mirror. Finite commands retain their synchronous stderr contract.

DP's writer binds to the compiled coordinator CPU before packet workers launch.
It has no epoch or packet authority and requires no new inventory CPU. CP and
Photon retain their existing process-affinity policy.

The logger outlives service threads, gRPC emitters, module/provider retirement,
and accepted native callbacks. After those producers retire, shutdown allows
two seconds to drain accepted diagnostics and join the writer. A writer whose
ownership cannot be retired is a terminal failure; it is never detached and
its arena is never freed while live.

Abort-adjacent diagnostics retain their raw, allocation-free breadcrumbs.
They may offer a separately reserved record for up to 100 ms; failed reservation
returns immediately. They do not acquire ordinary queue capacity or depend on
file delivery before the caller's abort. Neither deadline is a hard real-time
guarantee against kernel I/O stalls or process descheduling, and ordinary append
does not claim crash or power-loss durability.

### 5. Rotation and Reopen

The writer rotates before the next complete record would exceed the active
file's byte limit. It renames within the closed role-name family and never
uses copy-truncate, a broad deletion glob, or truncation after rename failure.
Incomplete crash tails are preserved; later records start on a distinct line
or in the next active file.

At the defaults, retained content is bounded to 128 MiB per role, or 384 MiB
for the three services. These are content limits, not age guarantees or total
filesystem quotas. Lowering a limit does not authorize deleting incompatible
existing data: admission rejects oversized files or archives beyond the selected
retention range.

During rotation, the oldest file can occupy the exact temporary index equal
to `--log-keep-files`. It is removed only after a new active file is admitted.
An interrupted rotation may therefore retain that extra name and an empty active
file. Reopen completes the admitted sequence through any remaining gap without
overwriting a surviving archive. A failure preserves bytes and makes the
destination unavailable.

`SIGUSR1` requests checked reopen of the same destination. It does not select
another directory or change settings. Photon forwards the request to its owned
pair. The recovered file records cumulative loss and the first outage cause
before that cause is cleared from live health. Previously undelivered records
are not replayed.

### 6. Failure and Health

| Condition | Diagnostic fate | Service behavior |
| --- | --- | --- |
| Startup file or lock admission fails | Visible startup error; no alternate destination | Startup fails before service publication. |
| Severity filter excludes a record | No construction and no loss counter | Operation is unchanged. |
| Ordinary arena is full | Reject the new record; increment queue rejection | Accepted records remain owned. |
| Formatting or native record admission fails | Return the reservation; increment format rejection | No formatting exception escapes into the described operation. |
| Append or rotation fails | Preserve bytes; account accepted records without complete delivery; retain first cause | Destination becomes unavailable; packet/configuration work continues. |
| New record during file outage | Count refusal, or account missing file delivery when an independent mirror still accepts it | No hidden persistent sink or replay. |
| Console mirror or emergency stderr fails | Count console failure independently | File delivery remains independent. |
| Foreign ERROR+ confirmation expires | Count timeout; retain writer ownership; attempt emergency stderr | A late file write may still succeed; no false delivery or loss is inferred. |
| Native hook enters on a packet owner | Reject before cold work and publish the owner-local rejection count | No queue, wait, lock, formatter, clock read, or I/O is introduced. |
| Explicit reopen succeeds | Report accumulated loss and prior cause; resume the same file destination | Existing operation and restart policies remain unchanged. |

CP `HealthCheckResponse.logging` and DP `HealthResponse.logging` carry one
`LoggingStatus`:

| Field | Meaning |
| --- | --- |
| `destination` | `AVAILABLE`, `UNAVAILABLE`, or `CLOSED`, using the corresponding `DESTINATION_STATE_*` spelling. |
| `accepted_records` | Records admitted for owned delivery, including internal recovery records. |
| `queue_rejections` | New diagnostics refused by exhausted or contended bounded admission. |
| `format_rejections` | Diagnostics rejected before publication because construction or native input failed. |
| `unavailable_rejections` | New diagnostics refused while the file destination is unavailable. |
| `undelivered_records` | Accepted records without complete file delivery, including partial writes. |
| `write_failures` | Failed file append, rotation, reopen, or close operations. |
| `console_failures` | Failed mirror or emergency stderr delivery. |
| `truncated_records` | Admitted diagnostics carrying explicit truncation. |
| `packet_thread_rejections` | Native hooks refused on packet-owner threads, including retired workers; saturates at the representable ceiling. |
| `delivery_timeouts` | Per-record file-confirmation waits that expired; final file delivery is accounted separately. |
| `failure` | First cause of the current outage, at most 255 printable ASCII bytes. |

Every counter requires explicit presence, including zero. Missing fields never
become healthy zero measurements. Counters are sampled independently while
emitters run; their live values are not an instantaneous conservation equation.
After quiescence they describe the completed population. Logging availability
does not determine CP serving, DP readiness, or mutation availability.

## Part 3: Operations and Integration

### 7. Operator Commands

Run with the default files:

```bash
sudo /opt/kinetum/bin/kinetum_photon --bundle /var/lib/kinetum/bundles/edge
```

Select another instance directory and an optional console mirror:

```bash
sudo /opt/kinetum/bin/kinetum_photon --log-console \
  --bundle /var/lib/kinetum/bundles/edge \
  --log-dir /var/log/kinetum-edge \
  --log-component-level module=debug
```

Inspect files and typed health:

```bash
sudo tail -f /var/log/kinetum/kinetum_dp.log
/opt/kinetum/bin/kinetumctl --endpoint 127.0.0.1:50051 health --service cp --format json
/opt/kinetum/bin/kinetumctl --endpoint 127.0.0.1:50052 health --service dp --format json
```

After resolving a destination failure, send `SIGUSR1` to the exact Photon PID
retained by the process owner. Do not use an indiscriminate process-name match
when multiple instances exist.

### 8. Native Integration and Source Map

Module lifecycle logging keeps its public C callback. The private adapter adds
context identity before copying bytes. Providers receive an instance-bound cold
C capability valid through their destruction callback; query and host proof
remain pure, and packet operation tables carry no logging service.

DPDK uses `rte_openlog_stream()` before EAL initialization through cleanup.
The bridge copies native write fragments with their actual severity and does
not invent a function name or fuse fragments across threads. No DPDK source
patch or payload rebuild is needed for this integration.

Both installed and fetched gRPC 1.51.1 builds use the same GPR callback.
The bridge copies severity, source location, and message before returning to
gRPC; the logging frontend records the emitting thread and time.

| Source | Ownership |
| --- | --- |
| `src/common/log.hpp`, `log.cpp`, `log_service.hpp` | Sole frontend, bounded arena, writer, lifecycle, and live observations. |
| `src/common/log_record.hpp/cpp` | Owned record representation and bounded text encoding. |
| `src/common/packet_thread_log_guard.hpp/cpp` | Launch-lifetime packet exclusion and retained rejection evidence. |
| `src/common/log_options.hpp/cpp` | Shared admission and exact child argv projection. |
| `src/common/log_file.hpp/cpp` | Held files, exclusive lock, append, rotation, and reopen. |
| `src/common/grpc_logging*.hpp/cpp` | Native GPR capture and callback retirement. |
| `src/common/logging_status.hpp/cpp` | Required-presence health projection and reader admission. |
| `src/provider/provider_component_abi.h` | Exact private cold logging capability. |
| `src/cp/control_loop.cpp`, `src/cp/cp_grpc.cpp` | Durable transition events and mutation request/results. |
| `src/dp/dataplane_control_service.cpp` | Cold bootstrap and transition RPC observations. |
| `src/dp/backends/dpdk/dpdk_process_facility.cpp` | Native DPDK stream ownership. |
