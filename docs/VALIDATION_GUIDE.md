# Physical-I/O Validation Guide

The harness exercises Kinetum under two evidence profiles:

- **Local DPDK TAP:** one Linux host, no physical NIC. Bindings create
  `neb_rx`, `neb_tx`, `neb_rx0`, and `neb_rx1`; AF_PACKET sends traffic,
  `tcpdump` captures egress, and the native analyzer measures loss, local
  kernel-path latency, and ordering.
- **Physical DPDK PCI:** explicit PCI bindings and an operator-prepared TRex
  endpoint measure real-NIC loss and stream ownership. DP boundary telemetry
  supplies ordered-CUT evidence; TRex supplies no packet-latency measurement.

`--backend` selects validation infrastructure; the plan alone selects runtime
providers. Photon owns the DP/CP pair. The harness drives epoch, commit-confirmed,
rollback, guardrails, and `full` scenarios through the public CLI; `standard`
makes no mutation. Transition verdicts require agreement among mutation results,
telemetry, generation tags, boundaries, and protocol faults.

> **Evidence boundary:** Dry runs and unit/package checks establish their
> respective authoring, integrity, and implementation contracts. Packet claims
> require live traffic through the installed-root, bundle-only Photon path,
> the selected profile's complete evidence checks, and recorded runtime, host,
> and instrument identities. Scenario code alone is not a physical result.

This guide covers the 0.1.0 runner for development, CI, and physical labs.
Production operation belongs to `GETTING_STARTED.md` and `KINETUMCTL.md`.
Section 22 summarizes validation capabilities and evidence boundaries.

---

## Table of Contents

### Part 1: Concepts and Quick Start

- [Section 1: What This Guide Covers](#1-what-this-guide-covers)
- [Section 2: Background and Audience](#2-background-and-audience)
- [Section 3: Quick Start](#3-quick-start)
- [Section 4: Architecture Overview](#4-architecture-overview)

### Part 2: The Runner

- [Section 5: Command-Line Surface](#5-command-line-surface)
- [Section 6: Test Lifecycle](#6-test-lifecycle)
- [Section 7: Deployments](#7-deployments)
- [Section 8: Validation Profiles and Traffic Drivers](#8-validation-profiles-and-traffic-drivers)

### Part 3: Test Types

- [Section 9: standard](#9-standard)
- [Section 10: epoch](#10-epoch)
- [Section 11: commit-confirmed](#11-commit-confirmed)
- [Section 12: rollback](#12-rollback)
- [Section 13: guardrails](#13-guardrails)

### Part 4: Packet Generation and Capture

- [Section 14: kinetum_tap_sender](#14-kinetum_tap_sender)
- [Section 15: tcpdump Capture and kinetum_tap_analyzer](#15-tcpdump-capture-and-kinetum_tap_analyzer)

### Part 5: Output Artifacts

- [Section 16: Per-Run Files](#16-per-run-files)
- [Section 17: Artifact Schemas](#17-artifact-schemas)

### Part 6: Benchmark Harness

- [Section 18: kinetum_benchmark](#18-kinetum_benchmark)

### Part 7: TAP and Physical PCI Evidence

- [Section 19: TAP vs DPDK PCI](#19-tap-vs-dpdk-pci)

### Part 8: Cross-Cutting

- [Section 20: Process Lifecycle](#20-process-lifecycle)
- [Section 21: Failure Modes](#21-failure-modes)
- [Section 22: Capability Boundaries](#22-capability-boundaries)
- [Section 23: Where to Go Next](#23-where-to-go-next)

---

## 1. What This Guide Covers

This guide documents `validation/kinetum_validation/`, the Python validation
orchestrator that lives alongside the platform sources, plus its two local-TAP
native helpers (`validation/native/kinetum_tap_sender.cpp`,
`validation/native/kinetum_tap_analyzer.cpp`) and the multi-run benchmark
package (`validation/kinetum_benchmark/`).
Together they provide:

- End-to-end packet forwarding validation for development, CI, and physical
  PCI labs.
- Live evidence contracts for boundary ordering, epoch transition,
  commit-confirmed, selective rollback, and telemetry-attributed guardrails.
- A local-TAP pcap pipeline for loss, local kernel-path latency, and packet
  ordering, plus physical TRex counters for loss and stream ownership and DP
  telemetry for ordered-CUT evidence.
- A multi-run benchmark loop with deterministic per-run isolation.

The private kit stays outside the finalized runtime prefix. Installed
`kinetum_pack` builds a real-file bundle; installed Photon owns DP/CP image
selection, bootstrap, pair restart, and teardown. The harness verifies child
ownership and typed CP serving/DP `PACKET_READY` health, never a log line.
Every scenario uses the same admission, with no loose-source, build-symlink,
direct-DP, or module-symlink bypass. A successful dry run checks the bundle but
measures no traffic.

Three concerns are deliberately out of scope here:

- **Production operation.** The harness can validate real DPDK PCI bindings,
  but it does not replace the deployment lifecycle, host preparation, or
  operator commands in `GETTING_STARTED.md` and `KINETUMCTL.md`.
- **Component reference detail.** When this guide names a control plane
  RPC, a snapshot field, or a guardrails trigger, treat it as a pointer
  to the canonical doc (`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`,
  `DATA_PLANE.md`, `GRPC_API.md`, `KINETUMCTL.md`). The validation runner only
  exercises these surfaces; it does not define them.
- **Operator workflows.** Validation is an evidence loop. Operator runbooks for
  applying snapshots, confirming, and rolling back live under
  `KINETUMCTL.md`.

## 2. Background and Audience

Use this guide for:

- Local CP, DP, module, and boundary-protocol validation.
- Checking deployment fixtures after module or snapshot changes.
- Repeated performance measurements under matched conditions (Section 18).
- Integrating physical-I/O validation into CI gates.

For other workflows:

- Production operation: `GETTING_STARTED.md`, `KINETUMCTL.md`.
- SDK and embedding APIs: `MODULE_SDK.md`, `AXIOM.md`, `GLUON.md`.

Familiarity with the following is assumed: DPDK EAL invocation, AF_PACKET
sockets, tcpdump/pcap format, Python asyncio, and the platform vocabulary
in `CONCEPTS.md` (pipeline, plan, region, boundary, epoch, snapshot).

## 3. Quick Start

The canonical live run uses `fan-in-edge-gateway`: two ingress RX/parse/ACL
chains feeding NAT44 and QoS in the third region. It
exercises the same baseline no-mutation path used by the benchmark harness.

Prerequisites:

- A locally prepared, finalized, and installed runtime root containing the
  exact signed provider inventory, host and DPDK components, built-in modules,
  and runtime binaries. Every run selects it with `--runtime-root`.
- The matching private validation wheel installed outside the runtime prefix,
  including its regular native helpers and packaged example inputs.
- Linux with unreserved hugepage capacity covering the compiled DPDK storage
  floor. The TAP profile requires no physical NIC binding.
- Lab hosts need Python 3.12 or newer, the runtime's system prerequisites,
  `ip`, `tcpdump`, and SSH for TRex. Pip installs the package's Python
  dependencies, including Matplotlib for report generation. The operator
  prepares the Python environment and host tools.
- Root privileges (AF_PACKET, TAP interface configuration).

For a physical PCI deployment on Ubuntu 24.04, the operator can obtain
`/usr/bin/dpdk-devbind.py` through the distribution package:

```bash
sudo apt update
sudo apt install --no-install-recommends dpdk
```

This supplies host administration tools independently of Kinetum's privately
linked DPDK. It does not replace the provider's compiled DPDK or require the
source-build bootstrap on a runtime-only host. NIC binding and hugepage
configuration remain operator-owned. Ubuntu's `dpdk` package also includes a
service using `/etc/dpdk/interfaces` and `/etc/dpdk/dpdk.conf` for persistent
host configuration; any authored settings there must agree with the intended
host setup. See Ubuntu's [package contents](https://packages.ubuntu.com/en/noble-updates/amd64/dpdk/filelist)
and [DPDK configuration guide](https://ubuntu.com/server/docs/explanation/networking/about-dpdk/).

Use the completed native build from [Getting Started](GETTING_STARTED.md#1-build)
to produce the private wheel, then transfer it to the prepared lab host of the
same architecture. Documentation rendering and release signing are not
prerequisites for this target:

```bash
cmake --build build --target kinetum_validation_kit
```

On x86-64 the result is
`build/kinetum_validation-0.1.0-py3-none-linux_x86_64.whl`; the AArch64 build
produces the corresponding `linux_aarch64.whl`. On the lab host, the following
example uses `/var/tmp/kinetum-validation` for an operator-owned Python
environment. Run it from the directory containing the transferred wheel:

```bash
python3 -B -m venv /var/tmp/kinetum-validation
/var/tmp/kinetum-validation/bin/python3 -B -m pip install ./kinetum_validation-0.1.0-py3-none-linux_x86_64.whl
```

Pip installs the Python code, example inputs, native helpers, and declared
Python dependencies. The package locates its own installed `data/` directory;
the environment's location is the operator's choice. It must remain outside
the runtime prefix. The wheel contains no build-machine venv. Initial
dependency installation needs access to a package index or locally supplied
dependency wheels.

Build and verify the complete local TAP bundle without starting Photon, DP, or
CP:

```bash
sudo /var/tmp/kinetum-validation/bin/python3 -I -B -X utf8 -m kinetum_validation \
    --runtime-root /opt/kinetum \
    --deployment fan-in-edge-gateway \
    --test-type standard \
    --output-dir /tmp/kinetum_validation_dry_run \
    --dry-run
```

Run the baseline packet path:

```bash
sudo /var/tmp/kinetum-validation/bin/python3 -I -B -X utf8 -m kinetum_validation \
    --runtime-root /opt/kinetum \
    --deployment fan-in-edge-gateway \
    --test-type standard --duration 10
```

Illustrative live output excerpts (rates and counters are measured, not
guaranteed values):

```
Kinetum Physical-I/O Validation
===============================
  Runtime:    /opt/kinetum
  Validation: /var/tmp/kinetum-validation/lib/python3.12/site-packages/kinetum_validation/data
  Deployment: fan-in-edge-gateway
  Test Type:  standard
  PPS:        1000
  Duration:   10s
===============================

2026-09-27T14:20:03.421000Z [INFO] dut kinetum_validation[1000:1000] validation.info - supervisor/_start_process: starting kinetum_photon: /opt/kinetum/bin/kinetum_photon --bundle ...
2026-09-27T14:20:13.421000Z [INFO] dut kinetum_photon[1001:1001] photon.ready - photon/main: supervisor running, press Ctrl+C to stop
2026-09-27T14:20:13.522000Z [INFO] dut kinetum_validation[1000:1000] validation.info - supervisor/_start_process: kinetum_photon is ready

PACKET TEST (64B):  PASSED  loss 0.00%
```

Outputs land in `/tmp/kinetum_validation/` by default. The key files are
`photon.log`, the platform's role files under `logs/`, `capture_64.pcap`, `test_results.json`, and
`dp_stats.json` on exact final collection (one complete validated observation;
a failure leaves status-only `dp_stats.txt`). Transition runs also write
artifacts such as
`transition_summary.json`.

The equivalent bundle-only check for the minimal RX-to-TX baseline is:

```bash
sudo /var/tmp/kinetum-validation/bin/python3 -I -B -X utf8 -m kinetum_validation \
    --runtime-root /opt/kinetum \
    --deployment passthrough \
    --test-type standard \
    --output-dir /tmp/kinetum_validation_passthrough \
    --dry-run
```

The same command can admit and package the inputs selected by a transition
scenario without starting traffic:

```bash
sudo /var/tmp/kinetum-validation/bin/python3 -I -B -X utf8 -m kinetum_validation \
    --runtime-root /opt/kinetum \
    --deployment fan-in-edge-gateway \
    --test-type epoch \
    --epoch-pps 20000 \
    --epoch-duration 15 \
    --output-dir /tmp/kinetum_validation_epoch \
    --dry-run
```

The wheel contains the Python packages, regular native helpers, and example inputs;
runtime binaries and modules remain owned by the finalized runtime. Source
unit tests and Python bytecode caches are excluded. This is internal transport
for lab work, with no public installer, compatibility manifest, or kit
attestation. Only runtime and SDK are public products.

The harness admits disjoint exact runtime/kit roots and selected inputs before
bundle construction. Run admission executes the protected runtime's
`kinetum-info --check --json` through a held information-image descriptor. It
rejects verification or metadata failure and requires runtime, kit, and
information-image versions to agree. The information root, `bin/`, and held
executable must share one protected owner: root or the invoking UID, with no
group/world write access. This permits an unprivileged reader of a root-owned
installation; the native check still owns the complete production-runtime
policy. VERSION files are direct regular files
of at most 256 bytes, containing one ASCII product version and one final LF.
The private kit remains an owner-selected test instrument; it does not
acquire provider-image admission machinery.

## 4. Architecture Overview

```{uml}
@startuml
skinparam linetype ortho
node "Validation process" {
    component "kinetum_validation\nRun owner and orchestration" as RUN
    component "native_tap traffic driver" as TRAFFIC
    artifact "Run artifacts\nphoton.log, test_results.json\nPCAPs and DP statistics" as OUT
    RUN --> TRAFFIC
    RUN --> OUT
}
package "Installed command tools" {
    component "kinetum_pack" as PACK
    artifact "Verified runtime bundle" as BUNDLE
    component "kinetumctl" as CTL
    PACK --> BUNDLE
}
node "Installed supervised runtime" {
    component "kinetum_photon" as PH
    component "kinetum_cp" as CP
    component "kinetum_dp" as DP
    PH --> CP
    PH --> DP
    CP --> DP : gRPC
}
package "TAP traffic and external observation" {
    component "kinetum_tap_sender\nAF_PACKET" as SEND
    rectangle "neb_rx0 / neb_rx1\nIngress TAP interfaces" as RX
    rectangle "neb_tx\nEgress TAP interface" as TX
    component "tcpdump" as CAPTURE
    artifact "PCAP file" as PCAP
    component "kinetum_tap_analyzer\nMeasured JSON result" as ANALYZE
    SEND --> RX
    TX --> CAPTURE
    CAPTURE --> PCAP
    PCAP --> ANALYZE
}
RUN --> PACK : complete inputs
BUNDLE --> PH
RUN --> PH : bundle-only start
RUN --> CTL : exact transition requests
CTL --> CP
TRAFFIC --> SEND
RX --> DP
DP --> TX
ANALYZE -[norank]-> RUN
PCAP -[norank]-> OUT
@enduml
```

This diagram shows the fan-in local TAP profile. One crash-evident run owner serializes
physical execution and owns a fresh artifact root. Before acquiring that lock
or creating the root, the runner admits the exact installed runtime/validation
roots and every selected pipeline, hardware, binding, bootstrap, transition,
and degradation input. The runner owns the validation profile, deployment
inputs, and pass/fail verdict. The installed
packer is the sole bundle/plan producer and
Photon is the sole owner of the DP/CP process pair. The DPDK
TAP PMD is responsible for creating the kernel-visible `neb_*`
interfaces; the runner waits for them to appear in `/sys/class/net/`
before configuring them.

There is exactly one packet path on the wire: AF_PACKET into the RX TAP,
DPDK in `kinetum_dp` processes it through the pipeline, the egress
mbuf is handed back to the TAP PMD, and tcpdump captures from the
egress TAP. Kernel IP forwarding is explicitly disabled on the TAPs
(see Section 8) so the kernel does not double-forward packets.

---

## 5. Command-Line Surface

The installed validation runner enters through the `kinetum_validation` Python
module. A source checkout also provides `validation/run_validation.sh` for
development against explicitly selected validation resources. Python owns every
option and default; the source wrapper forwards the argument vector unchanged.

### 5.1 Python Module Entry

Use the Python interpreter into which the wheel was installed. With the
environment from Section 3, the command is:

```bash
sudo /var/tmp/kinetum-validation/bin/python3 -I -B -X utf8 -m kinetum_validation --runtime-root /opt/kinetum --dry-run
```

The explicit interpreter selects the installed environment even through `sudo`.
`-I` ignores inherited `PYTHON*` settings, implicit working-directory imports,
and the user site; `-B` prevents bytecode writes, and `-X utf8` selects UTF-8.
The package's `data/` directory supplies the default validation resources.

All flags below are parsed by `parse_args()` in `__main__.py` and validated
by `validate_args()` before any subprocess is launched. Long-option
abbreviation is disabled: only the complete kebab-case spelling or a documented
short option is accepted.

| Flag | Default | Notes |
|------|---------|-------|
| `--deployment`, `-d` | `fan-in-edge-gateway` | `fan-in-edge-gateway` or `passthrough`. |
| `--test-type`, `-t` | `standard` | `standard`, `epoch`, `commit-confirmed`, `rollback`, `guardrails`, `full`. |
| `--backend`, `-b` | `dpdk-tap` | Selects `dpdk-tap` or `dpdk-pci` validation infrastructure. It is never propagated to Gluon or DP. |
| `--stream-topology` | `default` | Deployment-binding topology selected before Gluon planning. `rx-rss-2` is available for the fan-in d430 PCI profile. |
| `--storage-profile` | `shared` | Select `per-rx-queue` for separate ingress pools in either fan-in d430 PCI topology. Selects the authored bindings file before planning. |
| `--dry-run` | off | Build and self-verify the complete selected runtime bundle and write metadata without starting Photon/DP/CP. Useful for validating `dpdk-pci` bindings before traffic runs. |
| `--traffic-host` | empty | SSH host or alias for an external traffic endpoint. Required for `dpdk-pci` plus TRex non-dry-run tests. |
| `--traffic-ssh-port` | `0` | SSH port override. `0` uses the SSH client default/configuration. |
| `--traffic-python` | `/usr/bin/python3` | Exact absolute Python executable on the external traffic endpoint. |
| `--traffic-work-dir` | `/tmp/kinetum_traffic` | Exact existing endpoint directory. The runner never creates or guesses it. |
| `--trex-server` | `127.0.0.1` | TRex stateless server address as seen from the traffic endpoint. |
| `--trex-api-path` | empty | Optional path prepended before importing `trex_stl_lib.api` on the traffic endpoint. |
| `--trex-port` | profile default | Ordered TRex port override. Repeat once per selected deployment port. |
| `--pps` | `1000` | Positive target packets per second, bounded to `1..1000000000`. |
| `--count` | `1000` | Positive count-based packet target in the uint32 sequence domain. |
| `--duration` | `0.0` | Finite test duration in seconds. `0.0` selects count-based mode using `--count`; a positive duration must schedule at least one packet and keep `pps * duration` inside uint32. |
| `--packet-size` | `64` | Bytes. Validated to `[64, 9000]`. |
| `--all-sizes` | off | Run packet test for `(64, 128, 256, 512, 1024, 1518)`. |
| `--num-flows` | `1` | Number of traffic-generator flows per ingress port. TRex varies UDP source port per flow; `rx-rss-2` requires at least 64 flows so RSS steering has enough diversity for stream-balance evidence. A transition run also rejects before SSH when the conservative flow/PGID result bound would exceed the shared 16 MiB JSON contract. The native TAP sender is single-flow. |
| `--src-ip` | `10.0.0.100` | Source IP of generated UDP flow. |
| `--dst-ip` | `192.168.1.1` | Destination IP. |
| `--runtime-root` | required | Explicit finalized installed runtime root. It and every consumed `bin/` or `lib/` path component must be absolute and symlink-free. Exact regular runtime executables and, for module deployments, `lib/modules/` are required. |
| `--validation-root` | installed package's `data/` directory | Validation resources containing `VERSION`, `bin/`, and `examples/`. An explicit selection must be absolute, symlink-free, and disjoint from the runtime root in both containment directions. |
| `--dp-endpoint` | `127.0.0.1:50052` | DP gRPC listen address. |
| `--cp-endpoint` | `127.0.0.1:50051` | CP gRPC listen address. |
| `--epoch-duration` | `15.0` | Seconds. Total epoch test duration. |
| `--epoch-pps` | `1000` | Positive epoch-test PPS in `1..1000000000`; rate times duration must schedule at least one packet and fit uint32. |
| `--epoch-transition-time` | `5.0` | Seconds of baseline epoch traffic before the transition. |
| `--epoch-overlap-ms` | `500` | TRex sustained initial/next generation-tag overlap in the positive uint32 millisecond domain. Native TAP requests one pre-authored tag transition. |
| `--output-dir` | `/tmp/kinetum_validation` | Absent absolute final path created once for CP state, logs, captures, and JSON artifacts. Existing output rejects. |
| `--verbose`, `-v` | off | Uses `ConsoleReporter.log_callback` formatting for the Photon ownership-tree stream. Without it, the same stream uses the generic logger. |
| `--no-color` | off | Disables ANSI output in `ConsoleReporter`. |
| `--max-loss` | `1.0` | Pass/fail threshold in percent. |

`--duration 0.0` is the default and selects count-based mode: the
sender runs for `count / pps` seconds after both values pass positive bounded
admission. A positive `--duration`
overrides `--count` and runs for the specified number of seconds.

### 5.2 Shell Wrapper Entry

The source tree's `validation/run_validation.sh` is a thin wrapper around the
source Python module. Select an installed resource directory with
`--validation-root` when exercising source changes. The wrapper uses the source
root's `.venv`, prepared by `tooling/environment/bootstrap_ubuntu.sh`.
It:

- Requires Python 3.12 or newer on the validation host.
- Enters through protected-mode `/bin/bash -p`, rejects interpreter bypass,
  fixes locale, IFS, umask, and the system command path, and removes shell
  startup plus every `LD_*` variable before resolving a helper.
- Removes every inherited `PYTHON*` startup knob, makes the source validation
  directory the sole explicit import root,
  and invokes `.venv/bin/python3` with `-P -s -B -X utf8`. These flags exclude
  implicit working-directory imports and the user site, prevent bytecode-cache
  writes, and select UTF-8 mode. A single isolated interpreter probe checks the
  version before module execution. The remote `--traffic-python` remains an
  instrument-side selection governed by the TRex endpoint probe.
- Executes the Python module with the original arguments. Python owns help,
  option rejection, defaults, configuration output, and run admission.

The wrapper and module therefore have the same count-based default. Author
`--duration 10` for a ten-second run. Help and benchmark reporting need no
privileged runtime; actual run ownership and host effects retain their
existing privilege checks.

## 6. Test Lifecycle

The lifecycle is implemented in `TestOrchestrator._setup` and
`TestOrchestrator.run` in `validation/kinetum_validation/orchestrator.py`.
Scenario functions live in `validation/kinetum_validation/scenarios.py` and
use the resources prepared by that coordinator.
The setup order is fixed. `--dry-run` stops after complete bundle production;
otherwise the selected scenario runs against one packet-ready generation.

```{uml}
@startuml
    autonumber
    participant "~__main~__" as CLI
    participant "held kinetum-info" as Info
    participant "TestOrchestrator" as Orc
    participant "kinetum_pack" as PK
    participant "Supervisor" as Sup
    participant "kinetum_photon" as PH
    participant "DPDKTapBackend" as Bck
    participant "TrafficDriver" as Trf

    CLI->CLI: admit roots + example inputs; acquire run owner
    CLI->Info: ~--check ~--json
    Info-->CLI: verified runtime and exact release metadata
    CLI->Orc: run(config, release metadata)
    Orc->PK: pipeline + hw + bindings + snapshot + modules
    PK-->Orc: self-verified runtime bundle
    alt dry run
        Orc-->CLI: bundle + metadata; no runtime/traffic start
    else live selected scenario
        Orc->Sup: start_runtime(bundle_root)
        Sup->PH: spawn ~--bundle
        PH-->Sup: pair reaches PACKET_READY
        Orc->Bck: setup() (wait for neb_rx/neb_tx)
        Bck->Bck: set MTU + UP, disable kernel forwarding
        Bck-->Orc: backend ready
        Orc->Trf: setup() (validate send/capture surfaces)
        Trf-->Orc: traffic driver ready
        Orc->Orc: publish run metadata with observed traffic identity
        note over Orc: dispatch selected packet/transition scenario
        Orc->Trf: teardown()
        Orc->Bck: teardown()
        Orc->Sup: stop_all()
    end
@enduml
```

The lifecycle order in code is exactly:

Before step 1, direct and benchmark entrances validate the complete selected
example-file set through one shared symlink-free path authority, then acquire
the global run lock and create only the absent final output component. The
held runtime information image must pass `--check --json` before its response
can supply release metadata or bundle construction can begin.

1. `_create_runtime_bundle()` revalidates its immediate inputs and invokes the installed regular
   `kinetum_pack` with the selected pipeline, hardware inventory, exact
   deployment bindings, mandatory bootstrap snapshot, region count, and, when
   required, the installed real-file module directory. The packer runs Axiom,
   Gluon, plan/snapshot canonicalization, manifest construction, and its own
   completed-output verification. The harness has no detached planner path.
2. The runner parses `runtime_bundle/configs/plan.pbtxt` only for traffic-side
   port correlation. With `--dry-run`, it writes metadata with no TRex identity
   and returns here, without starting Photon, DP, CP, or traffic.
3. `_supervisor.start_runtime(bundle_root)` launches only the installed
   `kinetum_photon --bundle <absolute-root>`. Photon resolves its exact DP/CP
   siblings, repeats bundle admission, orders durable CP bootstrap and DP
   activation. The harness waits for both installed child roles and typed CP
   serving/DP `PACKET_READY` observations. It supplies a run-owned log directory
   and enables the existing console mirror. It passes no runtime provider selector, EAL
   override, UDP endpoint override, plan path, module path, or repair mode.
4. `_backend.setup()` polls `/sys/class/net/<iface>` until each TAP
   appears (30 s deadline), then sets MTU and link state up, disables
   kernel IP forwarding and `accept_local` on each TAP. The backend does
   not own packet generation or capture.
5. `make_traffic_driver()` creates the selected traffic driver. For
   TAP live tests this is `NativeTapTrafficDriver`, which owns
   `kinetum_tap_sender` invocation and tcpdump capture. For PCI live tests,
   `TRexTrafficDriver` controls the explicitly prepared external endpoint;
   A PCI dry run compiles and inspects the plan without constructing a traffic
   driver. After successful live driver setup, the runner publishes metadata
   with the observed TRex identity when applicable; failed setup cannot publish
   a completed live metadata record.
6. The dispatcher runs `standard`, exact epoch ordering, commit-confirmed,
   rollback, guardrails, or their `full` composition. Every mutation consumes
   exact CLI result identity and a post-transition coherent observation.
7. `_cleanup()` tears down the traffic driver and backend, then terminates the
   one supervised Photon ownership tree. Photon tears down the DP/CP pair;
   the harness escalates Photon to SIGKILL after
   `PROCESS_SHUTDOWN_TIMEOUT_S = 30` seconds. Every cleanup leg is attempted;
   any unretired owner makes the run fail rather than leaving a successful
   verdict beside uncertain process, capture, or remote-session state.

The supervisor checks direct-child image ownership through Linux `/proc` and
polls the installed CLI's `health --service cp|dp` commands. CP must report
serving and DP must report a complete `PACKET_READY` tuple. Log text never
satisfies readiness, and a valid logging outage does not revoke packet
readiness. The timeout is
`PROCESS_READY_TIMEOUT_S = 30` seconds; process exit or timeout is a hard setup
failure.

## 7. Deployments

`DEPLOYMENT_SPECS` in `config/types.py` defines deployments for the CLI,
supervisor, backend, and orchestrator, avoiding separate per-deployment branches.

| Deployment | Regions | Ports | needs_modules | allow_dag | Snapshots |
|------------|---------|-------|---------------|-----------|-----------|
| `passthrough` | 1 | `wan0->neb_rx (rx)`, `lan0->neb_tx (tx)` | no | no | `config_snapshot.pbtxt` |
| `fan-in-edge-gateway` | 3 | `wan0->neb_rx0 (rx)`, `wan1->neb_rx1 (rx)`, `lan0->neb_tx (tx)` | yes | yes | `config_snapshot.pbtxt`, `config_snapshot_v2.pbtxt`, `config_snapshot_guardrails_degradation.pbtxt` |

Each kebab-case CLI value maps through `DEPLOYMENT_SPECS` to its explicit
underscore-named `examples/<example_dir>/` artifact directory, which contains:

- `<deployment>.axiom.pbtxt` (the pipeline source).
- TAP hardware inventory (`hardware_inventory_tap.pbtxt`).
- `<deployment>_tap_bindings.pbtxt` (complete provider graph and exact
  logical-port/queue/stage bindings for TAP).
- `config_snapshot.pbtxt` (v1), `config_snapshot_v2.pbtxt` (v2), and
  `config_snapshot_guardrails_degradation.pbtxt` for deployments that carry
  modules. The degradation fixture preserves v2 NAT44, QoS, and module
  membership while its exact-hash ACL policy denies the validation UDP flow.
  Scenario admission requires the transition filename to differ from bootstrap
  and the degradation filename to differ from both; neither role can silently
  reuse another fixture.

The columns:

- **Regions.** The exact number of regions Gluon must produce. Host CPU and
  NUMA validation is strict; no development mode filters or repairs a
  placement.
- **Ports.** The physical validation profile carries traffic-side interface
  names and roles only. Typed TAP interface names or PCI BDFs, runtime
  direction, exact I/O-driver/driver-port identity, queue ownership, and
  storage-domain identity live in deployment bindings and hardware inventory.
  Gluon emits the resolved runtime truth into the plan, and the harness reads
  only the exact subset needed to correlate traffic and telemetry.
- **needs_modules.** If `true`, the packer receives the installed
  `/opt/kinetum/lib/modules` directory and copies the exact required regular
  images into the verified bundle. A missing directory, symbolic link, absent
  module, or closure mismatch rejects bundle production; no warning-only
  module path or temporary link exists.
- **allow_dag.** This is the authored pipeline contract carried by the input
  protobuf. The fan-in pipeline sets it because two ingress regions meet at a
  join stage in a third region; the others are linear. The harness does not
  manufacture or override it.
- **Snapshots.** Names of config snapshot files in the example directory.
  `v1` is the permissive baseline; `v2` is the post-transition target used by
  epoch, commit-confirmed, and rollback tests. Guardrails uses only the
  separately named degradation fixture; it never infers that v2 is degraded.
  The snapshot schema is documented in
  `CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`.

## 8. Validation Profiles and Traffic Drivers

A harness backend selects bindings, inventory, traffic endpoint, and host
resource setup. It is not passed to Gluon or DP as a runtime-provider selector.
The profile's traffic driver owns generation, capture, timestamps, and rate
control.

`DPDKTapBackend` is the live local resource profile: it waits for TAP
interfaces, configures them, and prevents Linux from forwarding around
the data plane. `NativeTapTrafficDriver` is the live local packet path: it
invokes the native sender against TAP ingress and captures TAP egress
with tcpdump. `DPDKPCIBackend` is a physical-port descriptor used for
plan-owned physical-NIC runs; non-dry-run tests require an external
traffic driver. Unknown validation-profile values are rejected by CLI argument
parsing, and incompatible profile/driver pairs fail closed in
`make_traffic_driver()`.

### 8.1 DPDKTapBackend

The `DPDKTapBackend` is the host-resource layer for local TAP validation. It
does **not** speak DPDK directly from Python; the plan's exact DPDK facility,
I/O-driver, storage-domain, and stream instances materialize the typed TAP
attachments as ordinary Linux network interfaces. The traffic driver then
operates on those interfaces from user space.

Setup steps, in order:

1. **Wait for interfaces.** `_wait_for_interfaces()` polls
   `/sys/class/net/<iface>` for each traffic-side port in
   `config.backend.ports`. Deadline is
   30 s; timeout raises `RuntimeError`. DP must start first because DPDK creates
   the TAPs during initialization.
2. **Configure interfaces.** For each TAP iface, run
   `ip link set <iface> mtu 9000` using `CONSTANTS.TAP_MTU`, then
   `ip link set <iface> up`.
3. **Disable kernel forwarding.** Write `0` to
   `/proc/sys/net/ipv4/conf/<iface>/forwarding` and
   `/proc/sys/net/ipv4/conf/<iface>/accept_local` for each TAP. This
   is critical: without it the Linux kernel will forward packets
   between `neb_rx` and `neb_tx` in parallel with DPDK, causing
   duplicates on the wire and capturing un-NATted packets that
   bypassed the pipeline.
4. **Return ready.** The backend holds no packet socket or capture
   process. Its lifecycle ends at runtime resource readiness.

### 8.2 Traffic Drivers

Traffic drivers own packet generation and capture. This keeps physical
validation-profile selection orthogonal to whether traffic comes from local
TAP or the exact TRex endpoint protocol.

| Driver | Status | Timestamp source | Rate-control source | Latency source |
|--------|--------|------------------|---------------------|----------------|
| `native-tap` | implemented for `dpdk-tap` | `kernel_af_packet` | `userspace_native_sender` | `kernel_af_packet_pcap` local-path measurement |
| `trex` | implemented for every `dpdk-pci` scenario | `trex_port_stats` / PGID counters | `trex_stl_rate_control` | unavailable |

`NativeTapTrafficDriver` invokes `kinetum_tap_sender` against every
RX-direction TAP interface in the selected backend profile. Multi-ingress
deployments such as `fan-in-edge-gateway` are sent round-robin by the native
sender. Capture is delegated to `tcpdump` against the first TX-direction
TAP. The runner uses these tcpdump flags:

- `-i <egress-tap>` (always `neb_tx` for the shipped deployments).
- `-w <pcap-file>` to write a raw pcap.
- `-B 131072` to request a 128 MiB kernel capture buffer. It reduces capture
  pressure; tcpdump-reported drops still fail the evidence.
- `-s 0` to capture full packets, not snipped headers.
- A BPF filter expression provided by the orchestrator. The standard
  test uses `udp dst port <base_dport>` (`9999` by default) so NAT
  rewrites of the source port do not exclude the packet.

The capture process starts before the sender and must publish its own tcpdump
listening line within five seconds. Stop is a
SIGTERM with a 5 s grace, then SIGKILL with one final 5 s process-retirement
bound. Any child that still cannot be retired remains explicitly owned, and
the run fails.

`TRexTrafficDriver` controls a prepared stateless endpoint over SSH. Operators
install TRex, bind NICs, configure ports, and start `t-rex-64 -i`. The kit's
`scripts/install_trex_ubuntu.sh` downloads/extracts TRex; use 3.08 for Ubuntu
24.04/Python 3.12. On controlled CloudLab hosts with an untrusted Cisco server
chain, `--insecure-download` disables download certificate verification.

The setup probe requires stateless mode and records server version/mode in run
metadata, sidecars, and benchmark summaries. This is provenance, not a version
allowlist. Standard tests use port counters and write
`<capture>.trex_stats.json`, not PCAP. Target-achievement checks pass before any
sidecar is published. Successful output includes `target_pps`, locally derived
`expected_tx_count`, `tx_count`, `achievement_ratio`, and `trex_identity`.

All sidecars retain `port_counter_baseline` and `port_counter_final`, keyed by
decimal port ID with explicit uint64 `opackets`, `ipackets`, `oerrors`, and
`ierrors`. Readers recompute ingress TX, egress RX, and error deltas before
acceptance and again before writing. Missing fields, changed port membership,
regression, and inconsistent totals reject; historical errors are excluded.

Epoch TX/RX comes from PGIDs created for that session. Expected TX uses both
endpoint-monotonic generation-active intervals, recorded as
`measured_generation_intervals`. The start action retains every owned port's
absolute baseline; finish must echo it unchanged. Client-local `clear_stats()`
references cannot span reconnecting actions. Baseline-subtracted `port_tx_count`
and `port_rx_count` must equal PGID aggregates, with zero new ingress `oerrors`
and egress `ierrors`; mismatch reports both pairs. Abort retires capture without
completed evidence. Analysis requires a completed run.

**Epoch traffic.** The endpoint creates both generation-tag stream sets and
starts only the initial set. Stream IDs are port-local; PGIDs are session-wide.
Requests and receipts preserve both identities. TRex pause/resume requires a
session without fixed duration, so the orchestrator owns `--epoch-duration`
and shutdown. It applies configuration and resumes next-tag streams at the
transition point, then pauses initial-tag streams after `--epoch-overlap-ms`.

The verdict requires every DP boundary's exact generation/from/to/cut identity,
OPEN/OPEN completion, no pending control, complete timing, and no new protocol
fault. The sidecar retains raw PGIDs, requested overlap, its lower bound from
post-resume/pre-pause samples, both generation-active intervals, target
achievement, and endpoint-monotonic time provenance. Exactly two tag classes
must have nonzero TX/RX. Every nonzero-target PGID must reach 95 percent of its
target, RX cannot exceed TX, and measured overlap must cover the request.

Reconnects disable TRex's clear-on-connect reference update so earlier traffic
is retained. After pausing final streams and draining traffic, one `get_stats()`
call collects port and PGID observations before ports stop and filters disappear.
Only the dedicated `epoch` phase produces tag-separated PGID evidence; `full`,
commit-confirmed, and rollback may use TRex for their other traffic windows.

**Admission and transport.** Endpoint requests and responses have closed
membership and strict scalar types. Before effects, the endpoint validates the
request; before retaining its response, the local driver rechecks identities,
stream/flow/PGID arithmetic, timestamps, and counters. The fixed endpoint program
is the only command-line payload; JSON travels on SSH stdin with a 16 MiB limit
in both directions. Generation admission proves the maximum result fits before
SSH starts. Per-flow rate divides the requested aggregate by ingress-stream
and flow count, with no one-PPS floor. One-shot requests reject transition,
overlap, and second-tag fields.

Remote Python runs isolated and imports TRex only from `--trex-api-path`.
Local subprocesses strip all `LD_*` variables; other environment, including SSH
agent access, remains caller policy. The endpoint runs in `--traffic-work-dir`.
Ingress destination MACs come from Gluon's six-byte
`plan.ports[].resolved_mac_address`; malformed protobuf bytes reject. DUT ingress
therefore needs no promiscuous mode. TRex observation ports temporarily enable
promiscuous mode during probe/run and appear in sidecar `promiscuous_ports`.

**Cleanup.** Killing validation before cleanup may leave the epoch session
transmitting. The next run resets TRex; immediate manual cleanup uses
`client.reset()` or a `t-rex-64` restart. Normal SIGINT sends SIGTERM to active
SSH, tracks/drains delayed SIGKILL escalation, and retains generation ownership
until finish or abort. Teardown retries abort before releasing that ownership.

### 8.3 DPDKPCIBackend

The `DPDKPCIBackend` is the physical-NIC profile. It does not inject or
capture packets locally. Instead, it validates that the selected backend
profile has peer interfaces, records traffic-driver metadata, and relies
on Gluon to emit all runtime truth into the plan:

- One exact DPDK process-facility instance shared by the DPDK driver and
  storage instances.
- One I/O-driver instance whose canonical typed configuration binds every
  `driver_port_id` to an exact PCI BDF.
- Bounded packet-storage domains with exact population, data room,
  headroom, alignment, cache policy, and optional proven host NUMA node.
- Exact `plan.ports[]` rows carrying logical/I/O-driver/driver-port identity,
  direction, MTU, optional NUMA, and resolved six-byte MAC facts.
- Exact `io_streams[]` carrying every driver queue, descriptor count, owner
  worker, RX allocation domain or TX accepted-domain set, and steering profile.
- Explicit CPU execution-provider bindings for every stage.
- Exact `traffic_steering_profiles[]`: NONE for one RX queue, or RSS with
  authored fields and key bytes. `module_context_domains[]` separately names
  each module's complete context population and ordinal order.
- Exact worker and runtime-service placements from hardware inventory and
  deterministic planning. Native facility arguments are derived later from
  those generic facts; they are not authored or reconstructed by the harness.

Use `--backend dpdk-pci --dry-run` to validate physical bindings, canonical
provider-plan identity, and reproducibility metadata without starting DP/CP. Use
`--backend dpdk-pci --traffic-host <host>` for TRex-backed physical tests once
the external endpoint is configured. The selected backend profile owns the
traffic-driver and evidence-source identities; the CLI does not repeat them.

The source-controlled CloudLab topology request lives at
`validation/cloudlab/fan_in_edge_gateway_profile.py`; the validation wheel
includes that exact source at
`<validation-root>/cloudlab/fan_in_edge_gateway_profile.py`.
It requests only the DUT, TRex peer, and experiment links. It does not attach
private source, an install service, a custom image, or runtime provider policy.
The deployment bindings and hardware inventory remain the only runtime
topology authorities after the lab nodes are instantiated.

The d430 selectors choose one complete authored file under
`examples/fan_in_edge_gateway/`; they never rewrite runtime bindings:

| Stream topology | Storage profile | Bindings file |
|---|---|---|
| `default` | `shared` | `fan_in_edge_gateway_cloudlab_d430_bindings.pbtxt` |
| `default` | `per-rx-queue` | `fan_in_edge_gateway_cloudlab_d430_per_rx_queue_bindings.pbtxt` |
| `rx-rss-2` | `shared` | `fan_in_edge_gateway_cloudlab_d430_rx_rss_2_bindings.pbtxt` |
| `rx-rss-2` | `per-rx-queue` | `fan_in_edge_gateway_cloudlab_d430_rx_rss_2_per_rx_queue_bindings.pbtxt` |

The default topology has one RX queue per ingress. RSS has two lanes and
symmetric steering on each ingress. Separate storage assigns one pool to each
RX queue and lets either NAT/TX owner accept every original domain. Setup verifies
that the emitted plan matches the selected queues, steering, and storage layout
and has no domain-changing conversion before starting Photon. Unsupported
selector combinations reject before effects.

At the end of an RSS live run, the harness fails closed unless
`dp_stats.json` proves every requested RX/TX stream was materialized, every RX
stream saw traffic, software stream rejections remained zero, the
matching RSS steering profiles and module-context populations were
admitted, both lanes carried a material packet share for each ingress, and the
exact packet-storage domains retained headroom. This validates queue-level RSS
stream evidence and runtime worker ownership; physical
scale-out still depends on the corresponding on-target throughput run. Use
`--num-flows >= 64`; TRex varies UDP source port per flow so the RSS key has
enough 5-tuple diversity to distribute.

Per-queue storage without RSS requires the same stream, pool-pressure, and
RX-port evidence, without RSS balance or steering predicates. Run metadata records
`stream_topology`, `storage_profile`, and `binding_file`; benchmark manifests
and aggregation require the same exact selection. Stream TX counts measure
provider acceptance; external capture remains the delivery check.

All live runs collect final statistics using a DP timestamp taken after
traffic completion and the existing drain interval. The harness then waits for
every stream owner's publication to advance beyond that timestamp, with the same runtime
generation and plan. The wait is bounded to 20 seconds with 100-ms polling;
failed queries, contradictory evidence, cancellation, or expiry fail the run.
Each query invokes `kinetumctl` once; the native client owns transport and
application retries. Its default allowance is 127 seconds within the
150-second subprocess limit. Timed scenario reads use their remaining traffic,
confirmation, or observation window instead, cancel and retire the child on
expiry, and reject late results. These reads never extend a scenario window.
Completed worker banks and native port counters do not imply one simultaneous
hardware snapshot.

`run_metadata.json` records release metadata only from the exact installed
`<runtime-root>/bin/kinetum-info --check --json` invocation. Runtime verification
and build facts come from the same response; SDK metadata is not consumed.
There is no DP-help, build-cache, source-tree, or guessed-feature fallback.
The current `build_features` object must contain exactly the two MLIR booleans, and
`platform_capabilities` must be the exact sorted descriptive set. Missing,
malformed, extra, or partial metadata rejects. Capabilities describe the one
complete build; they never select runtime admission or relax evidence. The
image composes one complete response before emission and returns zero only
after complete stdout and stderr delivery. JSON output also requires valid
UTF-8; invalid path or diagnostic bytes produce an error instead of malformed
JSON. The metadata reader gates on that
exit status before parsing, so an output-device failure cannot turn a JSON
prefix into run evidence.

### 8.4 Traffic-driver choreography

Backends own resource setup, while the selected `BackendProfile` owns the exact
traffic driver, timestamp source, rate-control source, and nullable latency
source. Drivers publish no duplicate capability record. Their sole
choreography distinction is `requires_sustained_generation_overlap`: native
TAP performs one immediate pre-authored tag switch, while TRex keeps both tag
streams live for the configured overlap interval. Both paths publish one start
edge, one end edge, and exact generation-separated counts before completion.
None of these harness facts participates in runtime provider admission.

---

## 9. standard

The standard test is the baseline packet-forwarding validation. It sends a
fixed-rate UDP flow and requires exact sender/capture accounting before the
configured loss threshold can authorize success.

**Goal.** Confirm the pipeline forwards the requested-rate packet workload end
to end with loss within threshold, while recording the achieved rate.

**Inputs.**

- Deployment: `passthrough` or `fan-in-edge-gateway`.
- Packet config: PPS, count or duration, packet size, src/dst IP.
- `--max-loss` (default `1.0`%).

**Driver.** `scenarios.run_packet_test(context, packet_size)`.

**Recipe.**

1. Start capture on egress with BPF filter
   `udp dst port <base_dport>`.
2. Invoke the selected traffic sender with the resolved port list and packet
   config. Native TAP uses `NativeSender.run_standard`; physical PCI uses one
   TRex stateless counter session. If `--all-sizes` is set, run one iteration
   per size in `(64, 128, 256, 512, 1024, 1518)`.
3. Sleep 2 s after the sender returns to let in-flight packets drain.
4. Stop capture.
5. Analyze the completed driver evidence. Native TAP runs the native analyzer
   on the pcap with `--expected <tx_count>`; standard TRex validates its port
   counter sidecar without manufacturing a pcap or latency sample.
6. Compute nonnegative `loss_pct = max(0, expected - valid) / expected * 100`.
7. Require positive TX/RX, zero sender errors, exact counter/tag membership,
   and no RX count above TX. Native pcap evidence additionally requires zero
   invalid, duplicate, and out-of-order frames; TRex supplies counter evidence
   and makes no packet-order claim. Then compare loss to `--max-loss`. Build a
   `TestResult` with `passed`,
   `tx_count`, `rx_count`, `loss_pct`, nullable `avg_latency_us`, and
   `throughput_pps`.

**What this proves.** That the runner, selected traffic driver, pipeline, and
validated packet/counter evidence line up end to end. Native TAP exercises the
DPDK TAP PMD, AF_PACKET injection, tcpdump capture, and pcap analyzer; physical
PCI exercises the TRex endpoint and real NIC bindings. For `passthrough` it is
a validation-profile and exact provider-graph bring-up test. For
`fan-in-edge-gateway` it additionally
exercises the full module chain (ACL, NAT44, QoS) under the v1
snapshot. Native TAP records positive achieved throughput but does not turn
the requested pacing rate into a performance pass threshold; physical
throughput qualification belongs to the benchmark campaign.

**Pass criteria.** Exact evidence for the selected driver and
`loss_pct <= max_loss`. Loss percentage alone can never hide a sender error or
counter disagreement; native pcap evidence also rejects a foreign, duplicate,
or reordered frame.

The canonical fan-in `standard` and `full` runs also perform a bounded NAT
exchange after the measured scenarios and their statistics are saved. Each
ingress sends 16 distinct private tuples; captured translations must be unique
for the remote tuple, belong to the active pool, and cover every NAT owner.
Replies enter through the other ingress and must restore the exact private
endpoint with intact payload and valid IPv4/UDP checksums. The active snapshot
must remain unchanged. This check is tied to the canonical scenario, not to
the presence of a NAT module in an arbitrary deployment.

**Artifacts.** `capture_<size>.pcap` or its TRex counter sidecar, `photon.log`,
and `packet_tests[]` in `test_results.json` (Section 17). The NAT check records
sent/captured bytes in `nat_exchange.json` and its verdict in `nat_exchange`.
Its packets do not enter throughput, latency, or RSS-balance measurements.

**Variants.**

- `--all-sizes`: one packet test per standard size.
- `--num-flows`: TRex varies UDP source port per flow; the native sender
  remains single-flow. `rx-rss-2` requires at least 64 flows.

## 10. epoch

The epoch test runs continuous generation-tag-separated traffic, applies one
snapshot mid-flight, and requires one coherent pre/post stats pair with exact
terminal, protocol-fault, and every-boundary CUT/ACK evidence. The packet tag
is a 16-bit traffic-profile discriminator; it never carries or predicts a DP
epoch. Each result is specific to the recorded runtime, profile, and measured
traffic interval.

**Goal.** Validate loss and exact ordered-cut completion during one live
snapshot apply: every compiled boundary must finish the same from/to
generation with drained sequence cut, open sender/receiver phases, complete
edge timing, and zero new typed protocol faults.

**Inputs.**

- Deployment: must satisfy `spec.needs_modules`; `passthrough` rejects before
  run ownership or process effects for every transition-oriented test type.
- `--epoch-duration` (default `15.0` s), `--epoch-pps` (default
  `1000`).
- `--packet-size` (default `64` bytes), shared by the initial and next
  generation streams.
- Snapshots `config_snapshot.pbtxt` (already applied during setup) and
  `config_snapshot_v2.pbtxt` (applied during the transition).

Both gateway snapshots retain a 10 Gb/s per-flow QoS rate. With TRex, the
aggregate target PPS doubles during generation overlap; size the workload for
that peak as well as the egress link capacity.

**Driver.** `scenarios.run_epoch_test(context)`.

**Recipe.**

1. Query one successful exact stats snapshot before starting traffic and use
   its nonzero active epoch as `dp_epoch_start`; failure is terminal and no
   default epoch exists.
2. Start capture on egress.
3. Build a packet config with `pps = epoch.pps`,
   `duration_s = epoch.duration_s`, preserving the configured packet size and
   flow fields.
4. Start the selected sender's generation-tag session with explicit tags 1 and
   2. Native TAP spawns `kinetum_tap_sender` in `--mode generation-tagged`
   with both tags pre-authored and `SIGUSR1` blocked across spawn. TRex starts
   initial-tag PGID streams and keeps next-tag streams paused on the traffic
   endpoint.
5. Let baseline traffic run for `transition_time_s = 5.0` s.
6. Take one pre-transition snapshot with stage, worker, region, and boundary
   rows plus mandatory transition/fault summaries. Runtime/config identity
   must still match step 1 and DP RX must have increased, proving that traffic
   reached the dataplane before mutation.
7. Trigger the transition. Dispatch `KinetumCtl.apply_config(v2)` as
   an async task, then immediately tell the traffic driver to start
   next-tag traffic. Native TAP publishes its sole `SIGUSR1` edge; TRex resumes
   paused next-tag PGID streams. The traffic profile and exact CP-returned epoch
   remain independent evidence dimensions.
8. For sustained-overlap drivers such as TRex, wait `--epoch-overlap-ms`.
   Both drivers then complete their end edge: TRex pauses the initial-tag
   streams; native TAP closes the logical edge without another signal. Await the
   apply completion.
9. Let traffic finish out the remaining duration, stop capture, and analyze
   the packet evidence.
10. After bounded packet drain, take a post-transition stats snapshot.
11. Require the latest terminal to be exact COMPLETE for its recorded
    `from_epoch -> to_epoch`, no retirement freeze or success-block latch,
    zero typed fault delta, and every boundary row to carry matching generation/from/to,
    a cut no greater than the completed dequeue sequence, OPEN/OPEN terminal
    phases, no pending CUT/ACK, and all three checked durations.
12. Only after that exact gate succeeds, compute the same-generation delta and
    append a record to `transition_metrics.jsonl` with
    `transition_type = "epoch"`. Incomplete evidence fails the scenario and
    produces no transition record.

**What a successful live run proves.** Traffic evidence and DP
ownership evidence agree for one real ordered transition. It does not by
itself qualify package identity, another architecture, a subsequent transition,
fault injection, or throughput beyond the measured workload.

No runtime or build selector weakens the ordered-CUT evidence gate. A physical
negative control requires its own explicit mechanism and evidence contract; it
cannot be inferred from missing telemetry or an alternate build label.

**Pass criteria.** Exact sender/capture and two-tag accounting,
`loss_pct <= EPOCH_LOSS_TOLERANCE_PCT` (0.1%), one observed epoch advance,
exact terminal COMPLETE without freeze or a success-block latch, nonzero
boundary population, `completed_boundaries == boundary_count`, and zero
protocol-fault delta. The `zero_loss` artifact field remains literal
`TX == RX`; it is not relabeled true for a tolerated loss. Backpressure is
recorded but is not itself a failure; capacity/performance evaluation remains
part of separate performance qualification.

**Artifacts.** `epoch_capture.pcap` or its TRex generation/PGID sidecar,
`photon.log`, the `epoch_test` block
in `test_results.json`, and exactly one `transition_metrics.jsonl` record
tagged `"epoch"`.

**Variants.** None at the CLI level. Use the benchmark harness to run
N iterations with the same parameters.

## 11. commit-confirmed

This scenario checks confirmation under load and unconfirmed timeout rollback
as specified in `CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`. It normalizes
the setup-provided active baseline before measuring both transitions.

**Goal.** Validate the commit-confirmed surface end to end while
traffic is flowing.

**Inputs.**

- `fan-in-edge-gateway`. Setup applies its bootstrap snapshot once without
  commit-confirmed before the test starts.
- The runner uses `epoch.pps` for one continuous 30 s traffic window spanning
  both measured transitions (default `1000` PPS).
- The scenario owns a fixed 30,000 ms confirmation timeout.

**Driver.** `scenarios.run_commit_confirmed_test(context)`.

**Recipe.**

1. Re-establish the authored baseline through an exact public apply. This makes
   `full` composition independent of content left by the preceding epoch test.
   This normalization is setup choreography, not one of the two measured
   commit-confirmed records.
2. Start the selected capture abstraction and launch continuous traffic for
   30 s through its sender's `run_timed(30.0)`. Allow 1 s of baseline.
3. Take a pre-transition stats snapshot and require positive DP RX since the
   normalized baseline observation from step 1.
4. Call `KinetumCtl.apply_config_with_confirm(snapshot, 30000, expected_revision)`.
   Success must carry snapshot ID, revision, and epoch; CP
   creates pending-confirm state only with exact COMPLETE promotion.
5. Take a post-transition stats snapshot. If both snapshots succeeded,
   append a `transition_metrics.jsonl` record tagged
   `"commit_confirmed"`.
6. Call `KinetumCtl.confirm(snapshot_id, epoch, revision)` with that exact
   apply identity. The CLI adds one retained random retry key. Record
   `time_remaining_ms` reported by CP.
7. Take a stats snapshot to verify the confirmed snapshot remains active.
8. Apply the baseline with a 1500 ms confirmation timeout, do not confirm, and
   require one exact later automatic rollback to the confirmed candidate.
   Append a `commit_confirmed_timeout_rollback` record from complete pre/post
   stage, region, boundary, terminal, fault, and positive-RX evidence.
9. Only after both measured transitions complete, wait for the traffic task,
   stop capture, analyze the selected driver's evidence, and record `tx_count`,
   `rx_count`, `loss_pct`, and available-or-null `avg_latency_us`.
10. Build a result carrying confirmation, timeout rollback, and the shared
    traffic-window evidence.

**What this proves.** That the commit-confirmed RPCs work
end-to-end (apply, confirm), that the apply takes effect under live
traffic, and that loss stays within threshold across the transition.

**Pass criteria.** Confirmation, exact timeout rollback, exact sender/capture
accounting, and `cc_loss_pct <= max_loss` must hold. The result message includes either
`COMMIT-CONFIRMED VALIDATED` or `COMMIT-CONFIRMED FAILED` with the
reason.

**Artifacts.** `commit_confirmed_capture.pcap` or its TRex counter sidecar, the
`commit_confirmed_test` block in `test_results.json`, and exactly two
`transition_metrics.jsonl` records tagged `"commit_confirmed"` and
`"commit_confirmed_timeout_rollback"`.

The timeout result fields are mandatory success evidence.

## 12. rollback

Apply v1 and v2, selectively restore one module from v1, then fully roll back to
v1. Both paths follow `CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`.

**Goal.** Validate selective and full rollback under live traffic, plus
the hybrid snapshot creation behaviour.

**Inputs.**

- Deployment with both `config_snapshot` and `config_snapshot_v2`
  (`fan-in-edge-gateway`).
- The runner uses `epoch.pps` for traffic and tracks per-transition
  stats deltas across four transitions.

**Driver.** `scenarios.run_rollback_test(context)`.

**Recipe.**

1. Take one exact pre-traffic stats snapshot, then start the selected capture
   abstraction (`rollback_capture.pcap` or its TRex sidecar).
2. Launch continuous traffic through the selected sender's `run_timed`.
3. Take the pre-rollback stats snapshot and require unchanged runtime/content
   identity plus a positive DP RX delta from step 1.
4. Require the traffic task still live. **Transition 1: apply v1.**
   `KinetumCtl.apply_config(v1)`. Stats
   snapshot. Append `rollback_apply_v1` record.
5. Require the same traffic task still live. **Transition 2: apply v2.**
   `KinetumCtl.apply_config(v2)`. Stats
   snapshot. Append `rollback_apply_v2` record.
6. Require the same traffic task still live. **Transition 3: selective
   rollback of `kinetum.acl` to v1.**
   `KinetumCtl.rollback()` with `module_ids = ["kinetum.acl"]` and exact active
   revision CAS. CP creates a hybrid snapshot named
   `selective_<sha256(domain,key)>` whose ACL fields come from v1 while NAT44
   and QoS stay at v2. `get-active` then proves module membership, ACL policy
   bytes/hash from v1, byte-identical NAT44/QoS from v2, generated
   ACL revision, and the exact v2 parent identity. Stats snapshot. Append
   `rollback_selective` record.
7. Require the same traffic task still live. **Transition 4: full rollback to
   v1.** `KinetumCtl.rollback()` with
   no module ids restores the entire canonical v1 snapshot. `get-active` must
   equal the previously observed v1 content in every field. The test records
   `full_rollback_success` and the resulting snapshot id. Stats snapshot.
   Append `rollback_full` record.
8. Stop traffic. Stop capture. Analyze the selected driver's evidence. Record
   `tx_count`, `rx_count`, `loss_pct`, and available-or-null `avg_latency_us`.

**What this proves.** That `Rollback` end-to-end works for both
selective and full modes, that the hybrid snapshot mechanism
correctly mixes module-scoped configs from different epochs, and that
loss stays within threshold across four transitions.

**Pass criteria.** All four transitions succeed; sender/capture accounting is
exact and loss is within threshold. The result includes both snapshot ids and the list of
modules rolled back selectively.

**Artifacts.** `rollback_capture.pcap` or its TRex counter sidecar, the
`rollback_test` block in
`test_results.json`, four `transition_metrics.jsonl` records tagged
`rollback_apply_v1`, `rollback_apply_v2`, `rollback_selective`,
`rollback_full`.

**Variants.** None at the CLI level. The set of selectively-rolled-back
modules is fixed to `["kinetum.acl"]`; changing that scenario requires a code
change.

## 13. guardrails

The guardrails scenario proves one telemetry-attributed durable automatic
rollback through the ordinary transition authority:

1. Read exact baseline content, runtime generation, counters, and current
   module-health rows.
2. Configure an explicit threshold policy (100 ms cadence, 1000 ms valid-time
   window, 1% drop bound, 0.99 TX ratio, and minimum population one).
3. Run baseline traffic long enough to build a valid prior-content window and
   require positive accepted TX plus current health for every module context.
4. Apply the deployment's explicit
   `config_snapshot_guardrails_degradation.pbtxt` with exact active-revision
   CAS. This snapshot differs from v2 only in snapshot identity/description and
   the ACL entry whose recomputed hash binds a rule denying the exact
   `10.0.0.100 -> 192.168.1.1 UDP/9999` validation flow.
5. Run candidate traffic and observe positive DP RX, a drop ratio above the
   configured threshold, and accepted-TX rate below the frozen positive
   baseline before accepting a later automatic rollback.
6. While the candidate source remains live, wait boundedly for a later exact
   COMPLETE transition restoring the baseline snapshot. Runtime generation
   must not change.
7. Require unchanged protocol-fault membership, zero fault delta, and write one
   exact `guardrails_rollback` transition record.
8. Disable the policy through the same keyed generation-CAS command. Failure
   cleanup retries this disable before runtime teardown, and unproved policy or
   sender cleanup makes the scenario fail.

Success records baseline/candidate/rollback snapshot IDs, strictly increasing
candidate and rollback epochs, zero protocol faults, and policy convergence.
`full` includes this scenario after rollback has restored the authored
baseline. The harness consumes policy behavior; it does not redefine it.

---

## 14. kinetum_tap_sender

`validation/native/kinetum_tap_sender.cpp` generates local TAP traffic.
`NativeSender` in `engine/native_sender.py` launches it asynchronously and
parses stdout JSON.

### 14.1 CLI Surface

| Flag | Notes |
|------|-------|
| `--mode` | `standard`, `generation-tagged`, or `timed`. |
| `--ports` | One to 64 unique comma-separated TAP interface atoms (round-robin if more than one). |
| `--pps` | Positive target packets per second in `1..1000000000`. |
| `--duration` | Positive finite seconds. |
| `--packet-size` | Bytes. |
| `--src-ip` | Source IPv4. |
| `--dst-ip` | Destination IPv4. |
| `--sport` | Base source UDP port. |
| `--dport` | Destination UDP port. |
| `--initial-generation-tag` | Initial 16-bit packet-profile tag; valid only in generation-tagged mode. |
| `--next-generation-tag` | Distinct 16-bit packet-profile tag selected after SIGUSR1; valid only in generation-tagged mode. |
| `--help` | Print native sender usage. |

The native sender validates every argument before opening sockets.
Unknown flags, missing values, malformed integers/floats, invalid IPv4
addresses, empty port lists, misplaced generation-tag flags, and
generation-tagged mode without both distinct tag values fail with exit code `2`.
`--packet-size` is constrained to `64..9000`, packet rate to the range above,
tags to the uint16 payload field (`0..65535`), and `pps * duration` to the
nonempty uint32 sequence domain. No zero-rate burst mode, minimum-frame repair, or rate
fallback survives.

### 14.2 Frame Layout

Each generated packet is an Ethernet + IPv4 + UDP frame followed by a
fixed Kinetum payload header. `--packet-size` counts these supplied frame bytes,
excluding NIC-added FCS, preamble/SFD, and inter-frame gap. The constants are:

| Constant | Value | Notes |
|----------|-------|-------|
| `MAGIC` | `KINETUM` | 7 bytes. |
| `MAGIC_LEN` | 7 | Length of the magic prefix. |
| `HEADER_SIZE` | 21 | `MAGIC(7) + SEQ(4) + TAG(2) + TIMESTAMP(8)`. |
| `ETH_HDR_LEN` | 14 | Standard. |
| `IP_HDR_LEN` | 20 | No IP options. |
| `UDP_HDR_LEN` | 8 | Standard. |
| `MIN_PKT_SIZE` | 63 | `ETH + IP + UDP + HEADER`; CLI admission is the stricter 64-byte Ethernet minimum. |

Payload layout, byte-by-byte from the start of UDP payload:

- bytes 0..6: `MAGIC` (`K I N E T U M`).
- bytes 7..10: big-endian uint32 process-wide sequence number, monotonically
  increasing from 0 across the complete round-robin port set.
- bytes 11..12: big-endian uint16 generation tag.
- bytes 13..20: big-endian double TX timestamp (seconds from
  `std::chrono::system_clock`).
- bytes 21..: `0x58` (`X`) padding to reach `--packet-size`.

The analyzer reads these fields in lockstep to compute loss, latency, and
per-tag counts. A frame must first satisfy the complete Ethernet/IPv4/UDP
length and profile contract; any failure increments `invalid` and excludes the
frame from valid counters.

### 14.3 Modes

- **`standard`.** Emit packets with `tag = 0`. Used by the standard
  test. The native sender is duration-based; for count-based standard
  tests the Python wrapper converts `count / pps` into a duration
  before launching the binary. Reports `tx_count`, `error_count`, and
  the total elapsed. A steady-clock deadline governs emission; wall time is
  recorded only for sender/analyzer latency correlation. Only an exact full-
  frame packet-socket send advances sequence and TX count; an impossible
  positive short send is fatal rather than partial success. Multi-port
  rotation uses a predicted wrap branch, not a packet-rate integer divide.
- **`generation-tagged`.** Start with `--initial-generation-tag`, observe one
  `SIGUSR1` request in the sender loop, and then use the immutable
  `--next-generation-tag` for every later packet. Both values are validated
  before signal setup or socket creation. The handler writes only one
  `volatile sig_atomic_t` flag; it does not perform I/O, allocation, logging,
  or clock work. Per-tag counts retain the exact emitted distribution.
- **`timed`.** Same fixed-tag duration loop as `standard`, used by the
  commit-confirmed and rollback tests to make the continuous-traffic
  window explicit in the orchestrator.

### 14.4 Output

The sender prints a single JSON object to stdout on completion. Its field
layout is shown below using type placeholders:

```text
{
  "tx_count": <uint64>,
  "error_count": <uint64>,
  "start_time": <double, system-clock seconds>,
  "end_time": <double>,
  "duration_s": <double>,
  "actual_pps": <double>,
  "generation_tag_counts": { "<tag>": <count>, ... }
}
```

Anything else printed by the binary goes to stderr and is forwarded to
the runner's log stream. A non-zero exit code, empty stdout, or
invalid JSON is a hard `RuntimeError` in the wrapping
`NativeSender._run`. The wrapper independently checks executable, interface,
packet, address, port, rate, duration, and sequence-domain facts before it
launches the child. The native image emits its complete lifecycle record
before opening a packet socket and stops before traffic if that record cannot
be delivered. Final JSON and any rate warning are composed completely and
published through the shared process-output authority; partial or failed
stdout/stderr delivery returns exit code `1`.

### 14.5 One-Way Generation-Tag Signal

The Python wrapper validates one distinct initial/next pair before creating the
generation task. It blocks `SIGUSR1` on the spawning thread, starts the native
sender with both immutable values, and restores the parent's exact prior mask
after either successful or failed spawn. The child verifies that it inherited
the blocked signal, installs its `sigaction` handler, and only then unblocks
`SIGUSR1`, all before opening packet sockets. A signal delivered during child
startup therefore remains pending instead of taking the default action.

`start_generation_overlap(next_tag)` requires the exact bound tag and one live
owned child, then sends `SIGUSR1` exactly once. Duplicate edges reject before a
second signal. The handler sets one `volatile sig_atomic_t` flag; the tight loop
observes that flag and selects the already validated next tag. There is no
cross-language atomic object, mapped control file, mutable tag payload, or
mid-run retargeting interface.

Signal delivery and process scheduling do not have a synthetic one-packet-time
bound. The captured packet sequence and packet timestamps are the observation
of when the next tag actually became visible; documentation does not infer that
delay from configured PPS.

## 15. tcpdump Capture and kinetum_tap_analyzer

One `NativeTapTrafficDriver` owns tcpdump capture. The runner has no second
capture process or private pcap parser.

### 15.1 tcpdump Invocation

The native TAP traffic driver wraps tcpdump with:

```text
tcpdump -i <egress-tap> -w <pcap-file> -B 131072 -s 0 <bpf-filter>
```

- `-B 131072` requests a 128 MiB kernel capture buffer. It reduces capture
  pressure; observed kernel drops still invalidate evidence.
- `-s 0` keeps full frames.
- The BPF filter for forwarding tests is
  `udp dst port <base_dport>` (default `9999`). The runner picks the
  filter so that NAT-rewritten source ports do not exclude packets.

### 15.2 Capture Lifecycle

1. Start tcpdump as a child process with stdout to `/dev/null` and
   stderr to a streaming task.
2. Race tcpdump's own listening line against child exit and output-task
   failure under one five-second bound; elapsed sleep is not readiness
   evidence.
3. The sender runs.
4. Sleep 2 s after the sender to let in-flight packets drain into the
   pcap.
5. SIGTERM tcpdump. Wait up to 5 s. SIGKILL on timeout. A nonzero exit or an
   output task that cannot drain after process exit fails the capture.
6. Preserve the completed pcap for one native-analyzer pass. The stop path does
   not run a second line-producing `tcpdump -r` scan merely to compute an
   ignored count; `kinetum_tap_analyzer` is the sole packet-count authority.

The readiness bound and 2 s post-send drain are not CLI tuning.

### 15.3 kinetum_tap_analyzer

`validation/native/kinetum_tap_analyzer.cpp` is the native pcap analyzer. The
Python `PacketAnalyzer` in `engine/analyzer.py` is a thin
`subprocess.run` wrapper.

CLI:

| Flag | Notes |
|------|-------|
| `--pcap` | Required absolute exact regular-file path. |
| `--expected` | Expected packet count in the uint32 sequence domain. |
| `--no-latency` | Skip latency computation. |
| `--help` | Print native analyzer usage. |

Behaviour:

- Require an exact pcap 2.4 Ethernet header whose global snap length can hold
  the 63-byte validation envelope. Each record's captured length must not
  exceed that advertised value, and both captured and original lengths are
  independently capped at 65,535 bytes. Record lengths must be coherent, the
  final header and payload complete, and timestamps in the microsecond domain.
- Walk every captured frame. For each, check the frame is at least
  `ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + HEADER_SIZE` bytes long.
- Require an unfragmented Ethernet/IPv4/IHL-5/UDP frame whose captured,
  original, IP-total, and UDP lengths agree exactly, then verify the magic. A
  nonmatching packet increments `invalid` and is skipped.
- Read the sequence, tag, and TX timestamp; a sequence outside the supplied
  expected population is invalid.
- Detect duplicates with a seen-sequence set.
- Detect out-of-order frames and sequence gaps by comparing each
  sequence number to the previous sequence number.
- Unless the standalone `--no-latency` diagnostic mode is selected, require
  one finite positive TX timestamp and one finite positive bounded latency for
  every valid frame, then compute
  `latency_us = (capture_time - tx_time) * 1e6`. Track avg, min, max, p50, and
  p99. The validation harness always uses this measured native mode.
- Track per-tag counts.
- Count every adjacent tag change and report the first sequence as
  `transition_seq`. Native transition evidence requires exactly one change;
  TRex overlap uses independent PGID classes instead of capture order.
- Compute nonnegative `loss_pct` from the supplied expected count; excess
  observations remain duplicate/error evidence rather than negative loss.
- Emit a single JSON object to stdout. Malformed CLI arguments return
  exit code `2`; corrupted or truncated pcap structure returns exit
  code `1`. The complete locale-independent JSON object is rendered before its
  first output byte, and incomplete delivery also returns `1`.

The wrapper uses `subprocess.run` with a 300 s timeout after capture stops.
This is the sole synchronous post-run step. Success requires empty stderr and
strict UTF-8 stdout before JSON validation.

### 15.4 Analyzer Output

The analyzer emits one JSON object with this field layout (type placeholders):

```text
{
  "total_rx": <int>,
  "valid": <int>,
  "invalid": <int>,
  "duplicates": <int>,
  "out_of_order": <int>,
  "missing_count": <int>,
  "max_gap": <int>,
  "loss_pct": <double>,
  "transition_seq": <int>,
  "tag_transition_count": <int>,
  "tag_counts": { "<tag>": <count>, ... },
  "latency": {
    "count": <int>,
    "avg": <double>,
    "min": <double>,
    "max": <double>,
    "p50": <double>,
    "p99": <double>
  }
}
```

Latency values are in microseconds. The Python `AnalysisResult` accepts one
validated native-analyzer latency publication in `_latency_stats_cache` and
returns copies of that cache. Without such a publication, `latency_stats()`
returns unavailable; it neither recomputes nor manufactures zeros.

---

## 16. Per-Run Files

A single `python3 -m kinetum_validation` invocation writes everything under
one newly created `--output-dir` (default `/tmp/kinetum_validation`). A fixed
crash-released `flock` at `/run/kinetum_validation.lock` excludes another
physical run. Existing output is never deleted or reused. The exact set
of files depends on the test type; the table below covers every
possible artifact.

| File | When written | Source |
|------|--------------|--------|
| `runtime_bundle/` | every successful setup, including dry-run | Complete self-verified output from the installed `kinetum_pack`; existing output rejects instead of being overwritten. |
| `run_metadata.json` | after dry-run bundle production or successful live traffic setup | Exact installed roots, bundle/plan paths, selected bindings/profile, resolved ports, installed build-feature evidence, and nullable observed TRex version/mode. A setup failure before live publication may omit it. |
| `photon.log` | non-dry-run startup | Combined Photon ownership-tree stream, including child output. |
| `logs/` | non-dry-run startup | Platform-owned Photon/CP/DP files, role locks, and bounded rotations. See [Logging](LOGGING.md). |
| `cp_store/` | non-dry-run startup | Fresh durable CP authority retained as run evidence after shutdown. |
| `capture_<size>.pcap` or `capture_<size>.trex_stats.json` | per `standard` size | Native-TAP pcap or exact TRex counter sidecar. |
| `epoch_capture.pcap` or `epoch_capture.trex_stats.json` | `epoch` test | Native-TAP pcap or generation/PGID TRex sidecar. |
| `commit_confirmed_capture.pcap` or matching TRex sidecar | `commit_confirmed` test | Traffic-window evidence. |
| `rollback_capture.pcap` or matching TRex sidecar | `rollback` test | Traffic-window evidence. |
| `test_results.json` | setup rejection, dry-run completion, or completed scenario collection | `RunArtifacts.save_test_results`; an exception or unretired cleanup owner can prevent final publication. |
| `dp_stats.txt` | every completed non-dry packet run | Human-readable projection of one exact successful stats response, or bounded status-only failure evidence. |
| `dp_stats.json` | successful final telemetry collection | Structured final telemetry projection parsed from validated protobuf JSON; unsupported provider values remain absent. A failed query writes status-only `dp_stats.txt` and no JSON. |
| `transition_metrics.jsonl` | per measured transition step | One exact newline-terminated JSON record per scenario-owned transition; appended. Successful scenarios require the exact type multiset below. |
| `transition_summary.json` | after stats save | Per-`transition_type` distributions (min, p50, p95, max). |

No stale-cleanup target or recursive delete exists. Direct runs own exactly the
requested fresh root. Failed final descriptor admission removes only the exact
empty directory that the same attempt created; a failure after ownership is
established preserves its partial evidence. The benchmark owner creates `run_NNN/` children through
its retained root descriptor and keeps the same global lock through all runs,
manifest completion, aggregation, and initial CSV publication.

## 17. Artifact Schemas

Artifact readers must follow these field contracts.

`run_metadata.json` is validated before its first byte is written. It binds the
internal deployment/profile spellings, resolved driver, exact runtime and
validation roots (they must be disjoint in both containment directions),
bundle/plan relation, installed release metadata, resolved
port identities, nullable profile-owned latency source, and complete traffic
endpoint (including the exact remote Python path). Duplicate JSON keys,
unknown/missing fields, indirect paths,
foreign capabilities, conflicting port identities, and scalar coercion reject.

### 17.1 test_results.json

Written by `RunArtifacts.save_test_results` for a completed suite result.
An interrupted or failed cleanup can leave only partial run evidence. Top-level fields:

| Field | Type | Notes |
|-------|------|-------|
| `timestamp` | string (canonical ISO 8601 UTC) | `datetime.now(timezone.utc).isoformat()`. |
| `deployment` | string | `passthrough` or `fan_in_edge_gateway`. |
| `test_type` | string | `standard`, `epoch`, `commit_confirmed`, `rollback`, `guardrails`, `full`. |
| `backend` | string | Physical validation profile (`dpdk_tap` or `dpdk_pci`), not runtime provider authority. |
| `traffic_driver` | string | Selected traffic mechanism. |
| `timestamp_source` | string | Evidence timestamp authority supplied by the selected profile. |
| `rate_control_source` | string | Evidence rate-control authority supplied by the selected profile. |
| `latency_source` | string or null | `kernel_af_packet_pcap` for measured local TAP latency; null when the selected profile has no latency mechanism. |
| `total_duration_s` | float | Rounded to 2 decimals. |
| `setup_failed` | bool | `true` if setup raised before any test ran. |
| `dry_run` | bool | `true` when bundle construction/verification completed without process startup. |
| `all_passed` | bool | Aggregate verdict; a dry-run passes when setup completed even though it executes zero packet tests. |
| `total_tests` | int | Count of executed tests. |
| `passed_tests` | int | |
| `failed_tests` | int | |
| `stats_validation` | object | Whether topology statistics are required, their verdict, and a bounded message. |
| `packet_tests` | array | One entry per packet size that ran. |
| `nat_exchange` | object or null | Canonical standard/full NAT verdict, mapping/return/context counts, duration, and message. |
| `epoch_test` | object or null | Present if epoch test ran. |
| `commit_confirmed_test` | object or null | Present if commit-confirmed test ran. |
| `rollback_test` | object or null | Present if rollback test ran. |
| `guardrails_test` | object or null | Present if guardrails test ran. |

The examples below show a native-TAP result. For TRex,
`latency_source` and every `avg_latency_us` value are JSON null. A successful
native-TAP row requires a positive measured average; a numeric TRex value is a
contract violation. Missing latency never becomes zero.

A `packet_tests[]` entry:

```json
{
  "packet_size": 64,
  "passed": true,
  "tx_count": 1000,
  "rx_count": 1000,
  "loss_pct": 0.00,
  "avg_latency_us": 134.21,
  "throughput_pps": 999.83,
  "duration_s": 1.02,
  "message": "Loss: 0.00%"
}
```

The `epoch_test` block:

```json
{
  "passed": true,
  "duration_s": 15.04,
  "total_sent": 15000,
  "total_received": 15000,
  "initial_generation_sent": 7500,
  "next_generation_sent": 7500,
  "initial_generation_received": 7500,
  "next_generation_received": 7500,
  "generation_tag_transition_seq": 7500,
  "loss_pct": 0.00,
  "avg_latency_us": 142.5,
  "zero_loss": true,
  "transitions_observed": 1,
  "boundary_count": 2,
  "completed_boundaries": 2,
  "protocol_faults_observed": 0,
  "backpressure_events": 23,
  "boundary_ordering_validated": true,
  "message": "..."
}
```

The `commit_confirmed_test` block:

```json
{
  "passed": true,
  "duration_s": 31.10,
  "confirm_success": true,
  "confirm_snapshot_id": "snap-...",
  "confirm_time_remaining_ms": 29473,
  "timeout_rollback_occurred": true,
  "timeout_rollback_snapshot_id": "snap-...",
  "tx_count": 30000,
  "rx_count": 30000,
  "loss_pct": 0.0,
  "avg_latency_us": 141.2,
  "message": "COMMIT-CONFIRMED VALIDATED: ..."
}
```

The `rollback_test` block:

```json
{
  "passed": true,
  "duration_s": 21.55,
  "full_rollback_success": true,
  "full_rollback_snapshot_id": "snap-...",
  "selective_rollback_success": true,
  "selective_rollback_modules": ["kinetum.acl"],
  "selective_rollback_snapshot_id": "selective_<sha256(domain,key)>",
  "tx_count": 20000,
  "rx_count": 20000,
  "loss_pct": 0.0,
  "avg_latency_us": 140.8,
  "message": "..."
}
```

The `guardrails_test` block carries exact baseline, candidate, and rollback
snapshot IDs; candidate and later rollback epochs; policy-configuration truth;
protocol-fault delta; duration; and verdict message. A successful row requires
the rollback ID to equal the baseline, a strictly later rollback epoch, and
zero protocol faults.

### 17.2 dp_stats.json

Written once at the end of a non-dry-run after the Photon-owned pair is ready
and the final telemetry query succeeds.
The harness requests stage, module metric/health, worker, region, boundary,
stream, storage, port, steering, and module-context rows in one call and records
the validated result. A failed query writes a bounded status-only `dp_stats.txt`,
marks required stats evidence failed, and does not create `dp_stats.json`.

The artifact is a dataclass projection of the validated protobuf JSON, not a
second wire schema. Optional wire values become JSON `null` when absent so
availability remains explicit. It never infers protocol settlement from
counter equality.

A transition phase that consumes active snapshot identity requires that one
response to be successful and to carry a nonempty snapshot ID plus nonzero
epoch. Selective and full rollback additionally require the observed active ID
to equal the operation result or requested target. Failed/default observations
cannot authorize a validation verdict.

Top-level fields:

| Field | Type | Notes |
|-------|------|-------|
| `success` | bool | Always true; file existence itself follows successful exact collection. |
| `error` | string | Empty on the only writable success path. |
| `rx_packets` | uint64 | DP total RX from the data path. |
| `tx_packets` | uint64 | Records whose ownership the TX provider accepted; not wire delivery. |
| `dropped_packets` | uint64 | Exactly-once terminal record retirements. |
| `rx_bytes`, `tx_bytes`, `fanout_overflow` | uint64 | Exact engine byte totals and refused fan-out branches. |
| `runtime_generation`, `status_publication_generation` | uint64 | Exact counter/status namespace. |
| `collection_monotonic_ns`, `latest_bank_publication_monotonic_ns` | uint64 | Cold collection and newest included bank times. |
| `active_epoch`, `minimum_retained_epoch`, `last_activated_epoch` | uint64 | Coherent runtime epoch truth. |
| `active_workers`, `expected_workers`, `skipped_publications` | integer | Worker readiness and visible telemetry skips. |
| `active_revision` | int | Revision id of the active snapshot. |
| `active_snapshot_id` | string | |
| `transition_*`, high watermarks, participant counts | scalar | Complete coordinator identity and membership projection. |
| `active_transaction`, `latest_terminal`, `certificate`, `grace` | object or null | Presence-qualified transition evidence. |
| `transition_success_blocked`, `protocol_fault_counts`, `first_protocol_fault` | mixed | Sticky safety latch, complete typed counters, and immutable first fault. |
| `stage_stats` | array | One entry per pipeline stage. |
| `module_counter_stats`, `module_histogram_stats`, `module_epoch_mismatch_stats`, `module_health_stats` | array | Complete selected module observations. |
| `worker_epoch_stats`, `region_epoch_stats`, `boundary_epoch_stats` | array | Exact ownership, cold aggregation, and ordered-cut evidence. |
| `stream_stats` | array | One entry per compiled executable I/O stream with `published_monotonic_ns`, transferred `packets`/`bytes`, and `rejected_packets`. |
| `storage_domain_stats` | array | Compiled capacity plus typed optional occupancy. |
| `port_stats` | array | Exact logical/driver identity plus typed optional native counter tuple. |
| `traffic_steering_stats` | array | One entry per compiled traffic-steering profile. |
| `module_context_domains` | array | Exact module ID and ordered context IDs for each compiled population. |

Stage entry:

```json
{
  "stage_id": "parse",
  "in_packets": 1000,
  "out_packets": 1000,
  "dropped_packets": 0,
  "in_bytes": 64000,
  "out_bytes": 64000
}
```

Compiled-topology entries are collected using the stream, storage-domain,
port, and combined topology flags. They
record the exact materialized plan identities used by the run. Stream rows use
`io_stream_id`, compact `worker_index`, and exact `driver_queue_id`; storage
rows use `storage_domain_id` and preserve optional NUMA presence; port rows use
`io_driver_instance_id` plus `driver_port_id`. No native lcore, physical port
number, pool scope, or provider-local stream index crosses the generic
artifact.

Port and storage-domain rows carry `observation_state`. Exact/approximate states carry
the complete optional value tuple and observation time; `UNSUPPORTED` and
`READ_FAILED` serialize those values as `null`. Missing native telemetry never
looks like clean zero activity.

Boundary epoch entry:

```json
{
  "boundary_id": "boundary.acl0@lane_0.nat@lane_0",
  "boundary_index": 0,
  "transition_generation": 11,
  "from_epoch": 7,
  "to_epoch": 8,
  "cut_sequence": 1000,
  "data_enqueued_sequence": 1000,
  "data_dequeued_sequence": 1000,
  "sender_phase": "BOUNDARY_SENDER_PHASE_OPEN",
  "receiver_phase": "BOUNDARY_RECEIVER_PHASE_OPEN",
  "cut_delivery_duration_ns": 1200,
  "cut_drain_duration_ns": 42000,
  "ack_gate_duration_ns": 142000
}
```

Region entry:

```json
{
  "region_id": 0,
  "worker_count": 1,
  "minimum_active_epoch": 3,
  "maximum_active_epoch": 3,
  "minimum_source_epoch": 3,
  "maximum_source_epoch": 3,
  "active_unretired": 0,
  "future_unretired": 0,
  "fanout_overflow": 0
}
```

### 17.3 transition_metrics.jsonl

One JSON record per exactly validated transition, appended to the file.
Records are written by `RunArtifacts.write_transition_metrics`; an incomplete transition
produces no record. This is the primary structured artifact consumed by the
benchmark aggregator.

Post-transition records consume one exact stats response. Every measured
transition requires a positive same-runtime `rx_packets_delta`, proving that
the dataplane admitted traffic during its evidence interval. They make no
marker-derived settlement claim; exact sequence-CUT convergence, terminal
outcome, and fault deltas come from the final telemetry contract.
Summary and benchmark readers require identical fault, boundary, region, and
stage membership across every record, including stable boundary ID/index
pairs. All three row families are nonempty for an admitted transition scenario.
Missing fault codes and missing numeric fields reject; neither reader supplies
zero or an implicit default.

A successful run must contain exactly this transition-type multiset:

| Test type | Required records |
|-----------|------------------|
| `standard` | none |
| `epoch` | `epoch` |
| `commit_confirmed` | `commit_confirmed`, `commit_confirmed_timeout_rollback` |
| `rollback` | `rollback_apply_v1`, `rollback_apply_v2`, `rollback_selective`, `rollback_full` |
| `guardrails` | `guardrails_rollback` |
| `full` | all eight records above |

`test_results.json`, the terminal benchmark manifest, the merger, and raw
exporter each recheck that relation. A missing, extra, duplicate, malformed, or
wrong-run record invalidates the success artifact.

Per record:

| Field | Type | Notes |
|-------|------|-------|
| `transition_type` | string | `epoch`, `commit_confirmed`, `commit_confirmed_timeout_rollback`, `rollback_apply_v1`, `rollback_apply_v2`, `rollback_selective`, `rollback_full`, or `guardrails_rollback`. |
| `runtime_generation` | uint64 | Must match both snapshots. |
| `transition_generation` | uint64 | Exact terminal mutation sequence shared by every boundary row. |
| `from_epoch`, `to_epoch` | uint64 | Exact transition endpoints. |
| `transition_state`, `transition_success_blocked` | typed/string + bool | Terminal coordinator and safety-latch truth. |
| `rx_packets_delta` | positive uint64 | DP ingress observed across the measured transition interval. |
| `tx_packets_delta` | uint64 | |
| `dropped_packets_delta` | uint64 | Exactly-once terminal retirement delta. |
| `protocol_fault_deltas` | object | Complete code-to-same-generation delta map. |
| `boundary_epoch_stats` | array | Per-boundary identity, sequence, timing, and backpressure deltas. |
| `region_epoch_stats` | array | Per-region epoch/credit truth and fan-out delta. |
| `stage_stats` | array | Per-stage deltas (see below). |

Boundary delta:

```json
{
  "boundary_id": "boundary.acl0@lane_0.nat@lane_0",
  "boundary_index": 0,
  "transition_generation": 11,
  "from_epoch": 7,
  "to_epoch": 8,
  "cut_sequence": 1000,
  "sender_phase": "BOUNDARY_SENDER_PHASE_OPEN",
  "receiver_phase": "BOUNDARY_RECEIVER_PHASE_OPEN",
  "data_enqueued_sequence_delta": 1000,
  "data_dequeued_sequence_delta": 1000,
  "data_backpressure_events_delta": 23,
  "cut_delivery_duration_ns": 1200,
  "cut_drain_duration_ns": 42000,
  "ack_gate_duration_ns": 142000
}
```

Region delta:

```json
{
  "region_id": 0,
  "minimum_active_epoch": 3,
  "maximum_active_epoch": 3,
  "minimum_source_epoch": 3,
  "maximum_source_epoch": 3,
  "active_unretired": 0,
  "future_unretired": 0,
  "activated_participants": 1,
  "worker_count": 1,
  "fanout_overflow_delta": 0
}
```

Stage delta:

```json
{
  "stage_id": "parse",
  "in_packets_delta": 1000,
  "out_packets_delta": 1000,
  "dropped_packets_delta": 0
}
```

### 17.4 transition_summary.json

Computed at the end of every run with at least one transition record.
The runner reads `transition_metrics.jsonl` and emits per-
`transition_type` distributions (min, p50, p95, max) for the key
deltas. This is consumed by the benchmark aggregator alongside the
raw JSONL.

The exact shape mirrors the JSONL but with `{min, p50, p95, max, count}` in
place of each scalar delta. Treat the JSONL as the immutable raw
record and the summary as a convenience.

---

## 18. kinetum_benchmark

The benchmark harness runs the physical-I/O validation suite N times under
matched conditions, writes per-run artifacts under `run_NNN/`, aggregates the
results, and emits CSVs, markdown tables, and SVG figures. The selected
validation profile may be local TAP or physical DPDK PCI/TRex.

### 18.1 Invocation

The `kinetum_benchmark` module is installed by the same private wheel. With the
environment from Section 3, invoke it as
`/var/tmp/kinetum-validation/bin/python3 -I -B -X utf8 -m kinetum_benchmark`.
Use `sudo` for a live `run`. A fresh `run`
uses the same exact installed-root admission, bundle construction, Photon
startup, and selected scenario choreography as the validation runner.
The source-only `validation/run_benchmark.sh` wrapper uses the same protected
Bash and project Python environment described in Section 5.2. The module's
root parser and every subcommand parser likewise reject
abbreviated long options.
Aggregation, export, and reporting remain usable on existing artifacts without
starting the runtime. Every live validation scenario can be repeated; compare
only runs with matching runtime, profile, host, and instrument identities.

Subcommands:

| Subcommand | Notes |
|------------|-------|
| `run` | Execute N benchmark runs. Auto-aggregates and auto-exports CSV at the end. |
| `aggregate` | Validate the terminal manifest and exact per-run membership, then create the merged ledger and summary once. |
| `export-csv` | Validate the complete aggregate and create CSVs once. |
| `report` | Require the immutable aggregate's inclusion policy, then create raw CSVs, markdown tables, and SVG figures under one fresh `<input-dir>/artifacts/`. |

### 18.2 run

Flags:

| Flag | Default | Notes |
|------|---------|-------|
| `--runs`, `-n` | `30` | Number of iterations in `1..999`. |
| `--variant` | `default` | Required printable UTF-8 manifest label, at most 128 bytes. |
| `--inclusion-policy` | `passed-only` | `passed-only` or `all-runs`. Drives which runs are included in the aggregated distributions. |
| `--deployment`, `-d` | `fan-in-edge-gateway` | Same deployment default as the validation runner. |
| `--test-type`, `-t` | `standard` | `standard`, `epoch`, `commit-confirmed`, `rollback`, `guardrails`, or `full`. |
| `--backend` | `dpdk-tap` | Physical profile only; `dpdk-pci` is not propagated as runtime provider identity. |
| `--stream-topology` | `default` | Use `rx-rss-2` with the fan-in d430 PCI profile and `--num-flows >= 64` for RSS evidence. |
| `--storage-profile` | `shared` | Select `per-rx-queue` with either fan-in d430 PCI topology; see the binding matrix in Section 8.3. |
| `--traffic-host` | empty | Required for `dpdk-pci` plus TRex benchmark runs. |
| `--traffic-ssh-port` | `0` | SSH port override; zero uses SSH configuration or its default port. |
| `--traffic-python` | `/usr/bin/python3` | Exact absolute Python image on the traffic endpoint. |
| `--traffic-work-dir` | `/tmp/kinetum_traffic` | Exact existing endpoint directory for remote traffic actions. |
| `--trex-server` | `127.0.0.1` | TRex stateless server address as seen from the traffic endpoint. |
| `--trex-api-path` | empty | Optional path prepended before importing TRex APIs on the traffic endpoint. |
| `--trex-port` | profile default | Ordered TRex port override; repeat once per selected deployment port. |
| `--epoch-transition-time` | `5.0` | Seconds of baseline epoch traffic before transition. |
| `--epoch-overlap-ms` | `500` | TRex sustained initial/next generation-tag overlap in positive uint32 milliseconds. |
| `--pps` | `1000` | Positive value in `1..1000000000`. |
| `--count` | `1000` | Positive value in the uint32 sequence domain. |
| `--packet-size` | `64` | Exact frame size in `64..9000`. |
| `--no-all-sizes` | off | The benchmark default is **all sizes on**. Pass `--no-all-sizes` to limit to a single size. |
| `--runtime-root` | required for `run` | Explicit finalized absolute symlink-free runtime root. Reporting operations do not consume it. |
| `--validation-root` | installed package's `data/` directory | Validation resources with regular helpers and example inputs, disjoint from the runtime prefix. |
| `--epoch-duration` | `15.0` | |
| `--epoch-pps` | `1000` | Positive value in `1..1000000000`; rate times duration must schedule at least one packet and fit uint32. |
| `--output-dir` | `/tmp/kinetum_benchmark` | Must be an absent absolute final path. |
| `--verbose`, `-v` | off | |

The benchmark admits the complete selected example-file set before acquiring
its run owner. That owner then holds the global lock from fresh batch-root creation through all
descriptor-created `run_NNN/` children, terminal manifest validation,
aggregation, and initial CSV export. Every JSON reader uses duplicate-key and
non-finite rejection plus exact schema validation. Optional artifact absence
means no directory entry; a dangling or direct symlink is contradictory input,
never absence. The exit
code is 0 if every run passed, 1 otherwise, and 130 if the loop was
interrupted by SIGINT.

### 18.3 aggregate

Reads `<input-dir>/run_NNN/transition_metrics.jsonl` and
`<input-dir>/run_NNN/test_results.json` across the exact terminal-manifest
membership. Every available run-metadata record must agree with the manifest's
deployment profile, release, roots, traffic endpoint, and immutable port
identity; a run that passed setup cannot omit it. A manifest success without
exact results or the scenario's exact transition multiset rejects, while a
failed run may contribute only a duplicate-free subset of that same multiset.
The command creates `merged_transitions.jsonl` and `benchmark_summary.json`;
pre-existing aggregate output rejects rather than being overwritten. The
summary retains the complete scenario identity, including the nullable latency
source, plus the nullable observed TRex identity. Every TRex run selected for
one distribution must report the same identity; mixed versions reject rather
than being averaged. The summary validates each metric-family and transition
distribution against the selected run population. Unsupported latency has no distribution. A standalone
aggregate must repeat the terminal manifest's inclusion policy; a flag cannot
reinterpret an existing run set.

### 18.4 export-csv

Reads and fully validates the aggregated summary before creating CSV files for
plotting. Existing CSV output rejects rather than being overwritten.

### 18.5 report

Requires an existing validated aggregate whose inclusion policy equals the
requested policy, then writes the following into a newly created direct
`<input-dir>/artifacts/` child:

- Raw CSVs from `raw_export.export_raw`.
- Markdown tables from `tables.generate_tables`, including
  `ordered_cut_boundary_proof.md` and full ACK-gate distributions.
- SVG figures from `plotter.generate_figures`; the epoch-latency CDF exists
  only when at least two real latency samples are available, and an ACK-gate
  CDF exists only when at least one boundary has two samples. SVG IDs use one
  fixed salt and volatile creation dates are omitted, so identical admitted
  inputs under the recorded report environment produce identical bytes.
  Per-transition-type ACK figures retain the complete observed range; no
  fixed physical-latency clipping threshold is applied.

The noninteractive Matplotlib backend is a required report dependency and is
preflighted before the artifact child is created. Pip installs Matplotlib as a
declared dependency of the private package; absence is a command failure, never a
successful report without figures.

### 18.6 Inclusion Policy

Two command-line values are supported. They normalize once to the named
underscore-delimited value stored in the immutable manifest and summary:

- **`passed-only`** (artifact value `passed_only`, default). Only runs whose
  `test_results.json` has
  `all_passed == true` contribute to the aggregated distributions.
  This is the right policy when the goal is to characterize the
  platform's normal-operation distribution.
- **`all-runs`** (artifact value `all_runs`). Every run contributes regardless
  of pass/fail.
  Useful for failure analysis and for audits where the inclusion
  criterion itself is part of the protocol.

The policy is stamped into the aggregated output so downstream
consumers cannot mix policies by accident.

---

## 19. TAP vs DPDK PCI

The local TAP profile and physical DPDK PCI profile exercise the same runtime
contracts through different traffic and capture mechanisms. The diagram below
highlights what differs on the wire and why physical performance claims cannot
be read directly from TAP runs.

```{uml}
@startuml
skinparam linetype ortho
node "Local TAP validation" as TAP {
    rectangle "neb_rx\nkernel TAP" as T_RX
    component "DPDK TAP PMD" as T_DPDK
    component "kinetum_dp" as T_DP
    component "DPDK TAP PMD" as T_DPDK2
    rectangle "neb_tx\nkernel TAP" as T_TX
    component "AF_PACKET inject" as T_INJ
    component "tcpdump capture" as T_TCP
}
node "Physical DPDK PCI validation" as PHYS {
    component "NIC ingress\nPCI bound" as P_NIC1
    component "kinetum_dp" as P_DP
    component "NIC egress\nPCI bound" as P_NIC2
    component "wire ingress" as P_LINE1
    component "wire egress" as P_LINE2
}

T_RX --> T_DPDK
T_DPDK --> T_DP
T_DP --> T_DPDK2
T_DPDK2 --> T_TX
T_INJ --> T_RX
T_TX --> T_TCP
P_NIC1 --> P_DP
P_DP --> P_NIC2
P_LINE1 --> P_NIC1
P_NIC2 --> P_LINE2
@enduml
```

The key deltas:

| Concern | Local TAP validation | Physical DPDK PCI validation |
|---------|-----|---------------------|
| Ingress | AF_PACKET write into TAP, copy through TAP PMD | NIC RX poll mode, zero-copy mbufs |
| Egress | TAP PMD write into kernel TAP, tcpdump copy | NIC TX poll mode, zero-copy mbufs |
| Capture | tcpdump pcap on kernel TAP | TRex PGID and port-counter sidecar |
| Latency evidence | Measured local sender-to-kernel-capture path; includes scheduling and copies | Unavailable; no TRex latency stream is implemented in 0.1.0 |
| Throughput ceiling | bounded by AF_PACKET, tcpdump, kernel ring | bounded by NIC line rate and CPU |
| Kernel forwarding | must be explicitly disabled (see Section 8) | not applicable |
| Bindings | Typed TAP attachments in exact `DeploymentBindings` | Typed PCI-BDF attachments in exact `DeploymentBindings`, e.g. `fan_in_edge_gateway_cloudlab_d430_bindings.pbtxt` |
| Provider graph | Explicit DPDK facility, driver, storage, execution, queue-zero stream, and stage bindings | The same roles, with exact PCI ports and optionally explicit multi-queue RSS |
| Reproducibility | host-only, no NIC required | requires a NIC under test |

What is **the same**:

- The pipeline source (`*.axiom.pbtxt`).
- The plan compilation chain: Axiom admission followed by Gluon lowering
  inside the installed `kinetum_pack` process.
- The same provider-contract, compiled-topology, materialization, packet-record,
  snapshot, module-hosting, and boundary-protocol authorities. Only the typed
  driver attachment and physical evidence differ.
- The CP RPC surface and the snapshot file schema.
- The module ABI and the SDK contract.
- The stats schema and the boundary telemetry counters.

Use local TAP results for correctness and local-path characterization; its
latency includes kernel scheduling and copies and is not wire-latency evidence.
Use the physical DPDK PCI/TRex profile on a real-NIC deployment prepared under
Section 3 for PPS and throughput claims. Kinetum 0.1.0 makes no physical
TRex packet-latency claim. Such a claim requires a separately owned TRex
latency mechanism and its own physical qualification.

---

## 20. Process Lifecycle

The `AsyncProcessSupervisor` in `process/supervisor.py` manages exactly one
installed Photon process. The harness never starts DP or CP directly. Photon
owns the complete child pair, while the harness owns one readiness predicate,
one combined ownership-tree log, and one shutdown handle.

### 20.1 Start

`start_runtime(bundle_root)` follows this exact pattern:

1. Reject a second ownership tree, an indirect/non-executable installed Photon,
   a nonexact bundle, or a non-owned output root.
2. Create `<output-dir>/cp_store` and `<output-dir>/logs` exactly once with mode
   `0700`; retain them as run evidence.
3. Spawn the exact regular installed Photon image with `--bundle`,
   `--cp-listen`, `--dp-endpoint`, `--config-store-dir`, `--log-dir`, and
   `--log-console`. No plan, module,
   provider, root, key, or child-image override is present.
4. Create `photon.log` before spawn, then pipe stdout and stderr into one
   `_stream_output` task. Flush each nonempty line to the file and pass it to
   the configured callback or stderr, with no duplicate in-memory history.
5. Wait at most `PROCESS_READY_TIMEOUT_S` (30 seconds) for both installed child
   roles and typed CP/DP health. Health command children have bounded ownership
   and are retired on cancellation. Child exit, malformed successful evidence,
   output-service failure, or timeout is a hard setup failure.

### 20.2 Stop

`stop(name)` and `stop_all()`:

1. If the process is still running, send SIGTERM via
   `process.terminate()`.
2. Keep draining the combined output pipe while waiting up to
   `PROCESS_SHUTDOWN_TIMEOUT_S` (30 s) for the process to
   exit cleanly.
3. On timeout, log a warning and send SIGKILL via `process.kill()`.
4. Await the log task after process exit, then record the final exit code and
   drop the Photon entry. Canceling the pipe reader before shutdown is
   forbidden because a full pipe can deadlock child cleanup.

A Photon process already exited when harness-owned stop begins is a lifecycle
failure even when its exit code is zero. The supervisor still drains output and
releases local ownership before reporting that failure; an independently ended
runtime cannot be relabeled clean teardown.

Cleanup is idempotent and never deletes the run's CP store or artifacts.

### 20.3 Bundle and Module Ownership

`_create_runtime_bundle()` creates `<output-dir>/runtime_bundle` exactly once.
For module-bearing deployments, it passes the installed real directory
`<runtime-root>/lib/modules` to `kinetum_pack`. The packer resolves the plan's
exact module set, copies regular link-closed images, writes the canonical
bootstrap snapshot and plan, seals the manifest, and self-verifies the complete
tree. Existing output, symbolic-link input, absent module, extra or missing
closure member, malformed snapshot, or plan mismatch rejects. The harness
creates no module symlink, overlay directory, loose-image lookup, or
warning-and-continue path.

### 20.4 Provider Plan and Native Facility Composition

The Photon command line carries the complete bundle, CP listen endpoint,
DP endpoint, fresh CP-store directory, and explicit logging settings. Photon passes the complete bundle
to DP; neither supervisor passes a loose plan, runtime provider identity,
native argument list, UDP endpoint, storage override, or repair mode. The
canonical plan inside the verified bundle is the runtime contract.

Changing cores, storage, TAP interfaces, or PCI attachments means changing the
owning inventory or deployment bindings and recompiling the plan. The harness
consumes the resulting identities; it never reconstructs an EAL command line.
[Gluon bindings](GLUON.md#7-deployment-binding-resolution) define those inputs,
and [DPDK provider construction](PROVIDERS.md#13-dpdk) defines native setup.

For validation hosts that need 2 MB hugepages, the private kit includes
`<validation-root>/scripts/dpdk_hugepages.sh` as an explicit setup
helper. Run it before plan generation, then keep the selected hardware
inventory and storage/facility requirements aligned with the host state used
for that run. A malformed host count or allocation below the requested count
is failure; neither reaches the helper's success result.

### 20.5 CP Store

`start_runtime` creates a fresh per-run CP store directory under
`<output-dir>/cp_store/` and passes it to Photon. Photon passes the
same path to every CP instance in that supervised generation, including a
pair-scoped restart. This guarantees that each validation invocation begins
without prior durable authority while preserving exact restart admission
inside the run. Production deployments keep their store across supervisor
invocations; validation retains its store so the run's durable identities can
be audited after cleanup.

---

## 21. Failure Modes

Use these failure paths with console output, preserved `photon.log` records,
and platform role files under `logs/` to locate faults.

### 21.1 Setup Failures

| Symptom | Likely cause | Where to look |
|---------|--------------|---------------|
| `runtime root must be absolute` / `validation root must be absolute` | A relative source/development path was supplied. | `process/installation.py`; install and select exact roots. |
| `... must not contain symlink indirection` | An installed root or a consumed `bin/`, `lib/`, or `examples/` path component is a symbolic link. | Exact installed-layout admission rejects before bundle or process effects. |
| `installed runtime binary not found as an executable regular file` | The finalized runtime is missing an exact required image. | `<runtime-root>/bin`; no build-tree or `PATH` fallback exists. |
| `validation helper not found as an executable regular file` | The private kit is incomplete. | `<validation-root>/bin/kinetum_tap_sender` and `kinetum_tap_analyzer`. |
| Runtime and private kit roots are not disjoint | The selected roots are equal or one contains the other. | Install/select validation resources outside the runtime prefix; no runtime-parent inference or relocation fallback exists. |
| Runtime information-image protection, self-check, or version rejection during run admission | The selected runtime is incomplete, indirect, writable by another UID, multiply linked, unsigned, or differs from the kit version. | Install the matching finalized runtime. The held information image must pass `--check --json` before its response can become run metadata; rejection prevents bundle construction and traffic. |
| `Pipeline source not found as a regular file: ...` | The installed pipeline input is missing or indirect. | `_create_runtime_bundle` in `orchestrator.py`. |
| `Hardware inventory not found as a regular file: ...` | The selected installed hardware inventory is missing or indirect. | `_create_runtime_bundle` in `orchestrator.py`. |
| `Deployment bindings not found as a regular file: ...` | The exact installed binding input is missing or indirect. | `_create_runtime_bundle` in `orchestrator.py`. |
| `Bootstrap snapshot not found as a regular file: ...` | The deployment lacks its mandatory initial snapshot. | `_create_runtime_bundle`; no synthesized default exists. |
| `validation output root already exists` | The requested run root is not fresh. | Choose a new exact output path; the harness never removes prior evidence. |
| `kinetum_pack failed` | Axiom, Gluon, module closure, plan/snapshot identity, or completed-manifest admission rejected. | The bounded packer diagnostic included in setup output. |
| `another physical-validation run owns the global lock` | Another live run holds `/run/kinetum_validation.lock`. | Wait for that owner to finish; process death releases the lock. |
| `Failed to set MTU` / `Failed to bring up` or forwarding-control failure | TAP host-resource setup lacks root privileges, the required per-interface kernel controls are absent, or the interface is not owned by this run. | `DPDKTapBackend._configure_interfaces`; both `forwarding` and `accept_local` must read back as zero. |
| `Timeout waiting for interfaces: neb_rx, ...` | The pair reached readiness but the expected TAP surface is absent or mismatched. | `photon.log` for materialization/EAL evidence and `DPDKTapBackend._wait_for_interfaces`. |
| `kinetum_photon failed to reach ready state` | The pair did not complete typed readiness within 30 seconds. | `logs/` and `photon.log`; inspect CP serving and DP packet-ready health at their configured endpoints. |
| Runtime rejects its installation root or signed provider inventory | A loose build-tree image, package indirection, unsigned candidate, wrong owner/mode, or incomplete finalized root was launched. | Use the release prepare/finalize/install ceremony. There is no root, inventory, key, or unsigned override. |

### 21.2 Runtime Failures

| Symptom | Likely cause | Where to look |
|---------|--------------|---------------|
| Standard test: high `loss_pct` on `neb_tx` | Dataplane loss, sender shortfall, or tcpdump capture drops. | Sender/analyzer counters, DP stats, and tcpdump stderr for "dropped by kernel". |
| Standard test: `missing_count`, `duplicates`, or `out_of_order` nonzero | Sequence gaps, duplicate sequence numbers, or reordering in the captured stream. | Analyzer JSON plus the pcap. |
| Standard test: `invalid` count high | Frames fail the complete Ethernet/IPv4/UDP generation-envelope contract: protocol/fragment/length coherence, magic, bounded sequence/tag, or valid timestamp evidence. ARP, ICMP, truncated packets, and foreign UDP all fail this gate. | Tighten the BPF filter and inspect the egress pcap for non-test or malformed traffic. |
| Native TAP: `latency.count` is zero | No valid timestamped Kinetum frames were accepted, `--no-latency` was used when invoking the analyzer directly, or timestamp samples were filtered because capture time was not after TX time. | Check `valid`, `invalid`, and the pcap timestamps in analyzer output. |
| Epoch test: `transitions_observed == 0` | CP apply failed, the bounded tag did not switch, or exact pre/post epochs agree. | `photon.log` and the `kinetumctl` result. |
| Epoch test: `loss_pct > 0.1%` | Real loss during transition. | Boundary telemetry deltas in `transition_metrics.jsonl`. |
| Epoch test: incomplete boundary rows or nonzero protocol-fault delta | CUT/ACK identity, drain, timing, or ownership safety did not converge exactly. | Inspect `boundary_epoch_stats`, `protocol_fault_deltas`, and the first-fault record; never infer success from packet loss alone. |
| Commit-confirmed test: `confirm_success == false` | CP rejected snapshot/epoch/revision/key identity or the durable deadline won. | `photon.log` and the exact CLI result. |
| Rollback test: `selective_rollback_success == false` | CP rejected target, module membership, CAS, or transition identity. | `photon.log` and the exact CLI result. |
| Guardrails test did not restore baseline | Valid-time evidence was insufficient, attribution suppressed action, or the durable transition failed. | Policy result, module health, transition metrics, and `photon.log`. |

### 21.3 Cleanup Failures

| Symptom | Likely cause | Where to look |
|---------|--------------|---------------|
| `force killing tcpdump...` | tcpdump did not exit on SIGTERM within 5 s. | Forced capture exit is non-clean and fails the run; inspect the pcap and capture host. |
| `force killing kinetum_photon...` | The Photon-owned pair did not exit within 30 seconds after SIGTERM. | The nonzero forced exit fails cleanup; investigate pair teardown, DP drain, and logger retirement in `logs/` and `photon.log`. |
| Leftover TAP interfaces after a run | DP crashed before un-registering its vdev. | Run `ip link delete <selected-tap-interface>` for each retained interface, or reboot. |
| Existing run root after failure | The run intentionally preserves exact partial evidence. | Inspect it and choose a different root for the next run. |

---

## 22. Capability Boundaries

This section summarizes the exact validation-profile and evidence boundaries.

| Surface | Status | Notes |
|---------|--------|-------|
| `--test-type standard` | **Implemented live and in dry-run.** | Live execution builds one verified bundle, starts installed Photon through pair-wide `PACKET_READY`, and runs baseline forwarding without mutation. Dry-run stops after bundle and metadata production. |
| `--test-type epoch`, `commit-confirmed`, `rollback`, `guardrails`, `full` | **Implemented scenario choreography.** | Each uses exact public CLI results and coherent telemetry. Physical claims require complete live traffic evidence under the recorded runtime/profile/environment identity. |
| `--backend dpdk-pci` | **Implemented for dry-run and TRex-backed physical tests.** | Selects physical bindings only; it is never sent to Gluon or DP. |
| Profile-selected TRex traffic | **Implemented for standard and transition scenarios.** | The `dpdk-pci` profile selects TRex and requires `--traffic-host`; strict remote JSON and PGID evidence fail closed, and setup records one bounded server-reported version in stateless mode. |
| Packet-latency evidence | **Native TAP local characterization only; TRex unsupported.** | Artifacts carry `latency_source = null` and `avg_latency_us = null` for TRex. Aggregation omits latency distributions, tables render `n/a`, and no latency figure is emitted. |
| Runtime cores, facilities, and storage policy | **Plan-owned.** | No validation CLI flag overrides these values. Deployment bindings and hardware inventory provide exact facts; the shared compiler and owning facility materializer validate and render native configuration without a harness-side EAL authority. |
| `--num-flows` | **TRex implemented; native TAP single-flow.** | TRex varies UDP source port per flow and records the value in run specs/manifests. `rx-rss-2` requires `--num-flows >= 64`; transition admission also requires the conservative flow/PGID result to fit the shared bounded JSON contract. The native TAP sender does not vary source port by flow ID. |
| `--no-color` | **Implemented.** | Propagates into `ConsoleReporter`; no ANSI sequence is emitted when disabled. |
| `CommitConfirmedTestResult.timeout_rollback_*` fields | **Implemented evidence.** | Success requires an unconfirmed candidate to roll back to the exact prior content at a later epoch. |
| Live process launch | **Implemented through installed Photon only.** | Exact installed roots admit before bundle effects; the installed packer creates a real-file verified bundle; `start_runtime()` spawns only `kinetum_photon --bundle` and verifies child ownership plus typed CP serving/DP `PACKET_READY` health. Direct DP/CP, build-tree, loose-plan, and module-symlink launch paths do not exist. |
| DP statistics | **Implemented all-or-none.** | DP maps the shared final telemetry schema from coherent banks, transition/certificate/fault publications, compiled topology, and typed provider observations; CP validates active identity and forwards it unchanged. `dp_stats.json` preserves the parsed final fields. RSS and per-queue storage runs require every requested stream/storage/provider row; RSS additionally requires steering and lane-balance evidence. |

---

## 23. Where to Go Next

| If you need to ... | Read |
|--------------------|------|
| Run a production deployment | [`GETTING_STARTED.md`](GETTING_STARTED.md) |
| Understand the platform vocabulary used in this guide | [`CONCEPTS.md`](CONCEPTS.md) |
| Drive CP from `kinetumctl` directly (apply, confirm, rollback) | [`KINETUMCTL.md`](KINETUMCTL.md) |
| Understand the snapshot, guardrails, and rollback model in CP | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| Trace what DP does during a two-phase apply | [`DATA_PLANE.md`](DATA_PLANE.md) |
| Inspect current ordered-CUT boundary behavior | [`DATA_PLANE.md`](DATA_PLANE.md) and [`diagrams/ordered_cut_boundary_protocol.md`](diagrams/ordered_cut_boundary_protocol.md) |
| Understand the module ABI the test loads | [`MODULE_SDK.md`](MODULE_SDK.md) |
| See the built-in module config fields exercised by the snapshots | [`../src/modules/README.md`](../src/modules/README.md) |
| Wire scripts against the platform's gRPC | [`GRPC_API.md`](GRPC_API.md) |
| Produce or verify deployment bundles | [`KINETUM_PACK.md`](KINETUM_PACK.md) |
