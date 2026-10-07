# Getting Started

Build and run `fan_in_edge_gateway`: each ingress worker parses and filters
packets before handing them to the selected NAT44, QoS, and transmit worker.

If you have not seen Kinetum before, read [`CONCEPTS.md`](CONCEPTS.md) first
for the vocabulary used here (pipeline, stage, region, plan, snapshot, epoch).

To install a released or locally prepared package, go to
[Install Kinetum](#5-install-kinetum). Source compilation begins in Section 1;
[Build Packages from Source](#build-packages-from-source) explains producing the
files consumed by that same installer.

> **Scope:** The walkthrough covers build, signed installation, bundle-only
> startup, fixed bootstrap, packet forwarding, live mutation, rollback,
> commit-confirmed convergence, telemetry, and guardrails through the passive
> built-in example. [Active-stage authoring](AXIOM.md#9-active-stages) uses the
> same runtime transition owner.
> Additional provider integrations and release physical evidence are outside
> this onboarding path.

## Table of Contents

- [What You Will Build](#what-you-will-build)
- [Day 0-4: Deployment Lifecycle](#day-0-4-deployment-lifecycle)
- [Prerequisites](#prerequisites)

1. [Build](#1-build)
2. [Compile the Pipeline (Axiom)](#2-compile-the-pipeline-axiom)
3. [Plan the Deployment (Gluon)](#3-plan-the-deployment-gluon)
4. [Package and Verify the Runtime Bundle](#4-package-and-verify-the-runtime-bundle)
5. [Install Kinetum](#5-install-kinetum)
6. [Start the Supervisor (Photon)](#6-start-the-supervisor-photon)
7. [Apply a Live Snapshot](#7-apply-a-live-snapshot)
8. [Observe Exact Runtime Telemetry](#8-observe-exact-runtime-telemetry)
9. [Prepare Private Validation](#9-prepare-private-validation)

- [Build Packages from Source](#build-packages-from-source)
- [Where to Go Next](#where-to-go-next)

---

## What You Will Build

```{uml}
@startuml
skinparam linetype ortho
skinparam ranksep 30
left to right direction
queue "wan0 / RX queue 0" as WAN0
queue "wan1 / RX queue 0" as WAN1
node "Worker W0 / region 0" as W0 {
    component "rx0\nReceive" as RX0
    component "parse0\nIPv4 headers" as PARSE0
    component "acl0\nFirewall" as ACL0
    RX0 -left-> PARSE0
    PARSE0 -left-> ACL0
}
node "Worker W1 / region 1" as W1 {
    component "rx1\nReceive" as RX1
    component "parse1\nIPv4 headers" as PARSE1
    component "acl1\nFirewall" as ACL1
    RX1 -left-> PARSE1
    PARSE1 -left-> ACL1
}
node "Worker W2 / region 2" as W2 {
    component "nat\nNAT44 translation" as NAT
    component "qos\nPer-flow rate limiting" as QOS
    component "tx\nTransmit" as TX
    NAT -left-> QOS
    QOS -left-> TX
}
queue "lan0 / TX queue 0" as LAN

WAN0 --> RX0
WAN1 --> RX1
ACL0 --> NAT
ACL1 --> NAT
TX -left-> LAN
RX0 -[hidden]right-> RX1
@enduml
```

The components inside each worker are **stages**. Logical **regions** group them;
Gluon lowers each region/lane slice into an explicit packet worker and places
the required control services on separate cores. Configuration snapshots (new
ACL rules, new NAT pool, new QoS profile) are assigned monotonically increasing
**epochs**.

## Day 0-4: Deployment Lifecycle

```{uml}
@startuml
skinparam linetype ortho
skinparam ranksep 20
left to right direction

card D0 [
Day 0
====
Prepare
the host
----
Install runtime
and examples
Prepare host
resources
]
card D1 [
Day 1
====
Define the
deployment
----
Author and
validate the
pipeline
Supply hardware
inventory and
bindings
]
card D2 [
Day 2
====
Build the
bundle
----
Package the
plan, snapshot
and modules
Verify the
SHA-256
manifest
]
card D3 [
Day 3
====
Start the
runtime
----
Photon starts
the supervised
DP/CP pair
Admit providers
Reach
PACKET_READY
]
card D4 [
Day 4
====
Operate
and update
----
Observe
telemetry
Apply and
confirm
snapshots
Verify rollback
when needed
]

D0 --> D1
D1 --> D2
D2 --> D3
D3 --> D4
@enduml
```

Day 0 covers [installation](#5-install-kinetum) and host preparation. Days 1-3
cover pipeline authoring, bundling, and startup below. Day 4 uses the live-update
and telemetry commands here, with confirmation and rollback in
[`KINETUMCTL.md`](KINETUMCTL.md#12-the-commit-confirmed-workflow).

## Prerequisites

| Requirement     | Why                                                  |
| --------------- | ---------------------------------------------------- |
| Linux           | Sole supported OS; required for DPDK, affinity, and exact ELF module loading |
| Little-endian x86-64 or AArch64 | Sole supported target architectures for runtime and module images |
| GCC or Clang    | Required GNU-compatible C11 and C++20 compiler semantics |
| CMake 3.28+     | Build system; owns GNU/Clang IPO flags and archive tools |
| KinetumDPDK package | Exact DPDK 24.11.7 source closure produced by the bootstrap script |
| OpenSSL         | Mandatory SHA-256 content identity; optional TLS helpers |
| libelf          | Mandatory same-descriptor ELF admission for provider components |
| libarchive      | System archive library used only by `kinetum_package` |
| zlib            | System compression library used by RPC dependencies and `kinetum_package` |
| strace          | Required by the public package functional tests       |
| libnuma         | Mandatory process-local CPU/host-memory NUMA proof      |
| gRPC 1.51.1 + Protobuf 3.21.12 | RPC and code generation; use installed packages or fetch the same versions with `-DKINETUM_FETCH_DEPS=ON` |
| GoogleTest 1.14.0 | Unit tests; installed or fetched with the same option |
| pytest + pytest-subtests | Python test runner and `unittest` subtest reporting; supplied by the bootstrap |
| Root privileges | Required for DPDK NIC access and TAP integration     |

Run `tooling/environment/bootstrap_ubuntu.sh` on Ubuntu 24.04 before
configuring. It installs Python 3.12, native build/analysis tools, development
libraries, and archive tools through APT. Locked Python packages go into the
source root's `.venv`, owned by the invoking user even under `sudo`.

Both dependency routes use the system Abseil, c-ares, RE2, OpenSSL, and zlib
development packages supplied by bootstrap. Fetching changes the source of
gRPC, Protobuf, and GoogleTest, not their required versions.

Bootstrap verifies and builds DPDK 24.11.7 as a static-PIC package under
`/opt/kinetum/dependencies`, including the pinned i40e close-status correction.
CMake requires that source-policy identity; a missing or stale package fails
configuration. The default package is root-owned and read-only to the build
user. Downloads and publication are verified, and conflicting existing bytes
are preserved and rejected.

This dependency tree is build-only: release archives exclude it, runtime code
does not load from it, and installation preserves it outside runtime-payload
verification.

When the source owner intentionally changes the dependency or builder inputs,
the producer's expected/found diagnostics supply the observed native output
hashes for the tuple policy. Record those observations and rerun the same
producer; all content and structural checks remain mandatory. Updating a pin
does not complete the native reproducibility, closure, or release gates.

Running a typed UDP I/O + host-storage + CPU plan does not require DPDK devices,
hugepages, or root privileges. A DPDK deployment instead names the exact DPDK
facility, driver attachments, storage domain, queues, and execution binding.
Neither path uses a second global selector or inferred default. OpenSSL
development headers remain required even when
`KINETUM_ENABLE_TLS=OFF`; that option disables TLS transport helpers, not the
platform's SHA-256 identity primitive. libelf development headers are also
mandatory: provider-component admission inspects the exact held artifact with
libelf/GElf before any dynamic load. libnuma development headers are mandatory
because Quark intersects machine NUMA facts with the current process's allowed
memory-node mask before accepting host-backed storage.

## 1. Build

Run from the source root. CMake configures and compiles in `build/`; packaging
consumes that completed build. To use another directory, select it in both
CMake commands and invoke its `kinetum_package` with the same `--build-dir`.

```bash
sudo ./tooling/environment/bootstrap_ubuntu.sh
source .venv/bin/activate

cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DKINETUM_ENABLE_TLS=ON \
  -DKINETUM_ENABLE_TESTS=ON \
  -DKINETUM_BUILD_MODULES=ON \
  -DKINETUM_ENABLE_LTO=ON \
  -DKINETUM_ENABLE_NATIVE_ARCH=OFF \
  -DKINETUM_ENABLE_ASAN=OFF \
  -DKINETUM_ENABLE_UBSAN=OFF \
  -DKINETUM_ENABLE_TSAN=OFF \
  -DKINETUM_ENABLE_MLIR=OFF \
  -DKINETUM_ENABLE_MLIR_DIALECT=OFF \
  -DKINETUM_FETCH_DEPS=OFF
cmake --build build -j
```

Kinetum-owned Release targets default to LTO `ON`. If the compiler/linker IPO
probe fails, configuration fails with its diagnostic. Select
`KINETUM_ENABLE_LTO=OFF` explicitly for a non-LTO build.

`KINETUM_ENABLE_MLIR` defaults to `OFF`; the dialect default follows it.
Set `KINETUM_ENABLE_MLIR_DIALECT=OFF` for a frontend-only build. Dialect `ON`
with frontend `OFF`, including contradictory cached values, fails configuration.

The build produces `kinetum_dp` and host/UDP/DPDK component images. Build-tree
artifacts serve tests and package preparation; production DP startup requires a
finalized installation with its signed provider inventory.

Generic tests use `kinetum_tests`. Native DPDK tests use
`kinetum_provider_dpdk_tests` because EAL, ethdev, mempool, and PMD registration
are process-global. Both compile production sources; only the native test
image links DPDK, and it does not load the component. DPDK dependencies stay
private to component/native-test targets. Deployment bindings and the compiled
plan select runtime topology.

`KINETUM_ENABLE_NATIVE_ARCH` selects the CPU instruction set for Kinetum-owned
Release targets:

| Setting | CPU target |
|---------|------------|
| `ON` (default) | `-march=native`: the CPU features visible to the compiler on the build machine, including inside a VM. |
| `OFF`, x86-64 | `-march=corei7`: the compiler's Core i7/Nehalem instruction-set baseline. |
| `OFF`, AArch64 | `-march=armv8-a+crc`: Armv8-A with the CRC extension. |

Both settings work with the same package commands and package tests. Use `ON`
for a package intended for the build machine or a CPU supporting its generated
instructions. This walkthrough uses `OFF` for the declared public-release
baselines. Release optimization and LTO remain enabled in either case; the
selected instruction set can change SIMD code generation, so performance
qualification must use the exact build that will be published. The separately
produced DPDK dependency retains its own pinned tuple settings. Exported SDK
interfaces leave CPU selection to the module author's build.

The remaining package-staging requirements match the configuration above;
test enablement is independent and may be `OFF` when qualification is performed
separately. Packaging reports incompatible settings and requires an explicit
reconfigure and rebuild. It never changes them or creates another build
directory. Compiler semantics and the relevant VPP/DPDK build patterns are
indexed in [Technical References](TECHNICAL_REFERENCES.md).

This produces the core binaries under `build/`:

| Binary                    | Purpose                                               |
| ------------------------- | ----------------------------------------------------- |
| `kinetum_axiom`           | Compile and validate a pipeline definition            |
| `kinetum_gluon`           | Plan a deployment from a pipeline + hardware + bindings |
| `kinetum_photon`          | Single-node supervisor that runs CP and DP            |
| `kinetum_dp`              | Bundle-only dataplane child normally owned by Photon  |
| `kinetum_cp`              | Durable-bootstrap control child normally owned by Photon |
| `kinetumctl`              | CLI client for the control plane                      |
| `kinetum_pack`            | Build a deployable bundle                             |
| `kinetum_bundle_verify`   | Verify a bundle's integrity                           |
| `kinetum-info`            | Inspect and verify the installed runtime              |
| `kinetum_package`         | Prepare, sign, and install independent public packages |

Run the C/C++ unit tests from the source root after compilation:

```bash
ctest --test-dir build --output-on-failure
```

This runs the registered cases from `kinetum_tests` and
`kinetum_provider_dpdk_tests`, plus the GNU/Clang C/C++ SDK consumer checks.
Python tests run separately with pytest:

```bash
python3 -B -m pytest -v validation/tests --build-dir build
python3 -B -m pytest -v tooling/tests --build-dir build
```

The first Python command checks validation, benchmarks, and private-wheel
installation against the completed build; the second checks documentation
tooling, DPDK production, and public packages. Both print test names and results.
Public package tests need `strace`. Documentation tests use fixtures; build the
website separately as described in
[the Documentation Guide](DOCUMENTATION_GUIDE.md#2-build-the-website).

Package checks stage that build's native packager, SDK, and validation resources
through the existing install components into private temporary directories,
then clean up their fixtures. Public package tests retain the staging
requirements above under either CPU setting. These checks do not configure or
compile the platform.

## 2. Compile the Pipeline (Axiom)

Axiom validates the pipeline definition (`.axiom.pbtxt` or `.axiom.mlir`)
against the platform's contract: required RX/TX stages, valid stage kinds,
no missing edges, and no cycles. `--allow-dag` removes the CLI's additional
linear and single-ingress/single-egress constraints; the authored pipeline must
still set `allow_dag: true`, and cycles remain invalid.

```bash
./build/kinetum_axiom \
  --in   examples/fan_in_edge_gateway/fan_in_edge_gateway.axiom.pbtxt \
  --out  build/pipeline.axiom.pbtxt \
  --format pbtxt \
  --allow-dag
```

The output is validated protobuf text. Axiom supplies no missing mode, stage
configuration, edge, or identity default. See
[`AXIOM.md`](AXIOM.md) for the full Axiom schema and validation rules.

## 3. Plan the Deployment (Gluon)

Gluon takes the validated pipeline, your hardware inventory, and complete
`DeploymentBindings`. It produces a deployment plan containing exact process
facilities, I/O drivers, storage domains, execution providers, logical and
driver-local ports, queues, worker/service ownership, storage transitions, and
cross-worker boundaries.

```bash
./build/kinetum_gluon \
  --axiom    build/pipeline.axiom.pbtxt \
  --hw       examples/fan_in_edge_gateway/hardware_inventory_tap.pbtxt \
  --bindings examples/fan_in_edge_gateway/fan_in_edge_gateway_tap_bindings.pbtxt \
  --regions  3 \
  --out      build/plan.pbtxt
```

`--regions 3` gives each ingress its own region and places shared processing in
the join region. The portable fan-in inventory has five process cores: three
packet workers, one transition coordinator, and one lifecycle executor. See
[`GLUON.md`](GLUON.md) for the partitioning and runtime-core placement
algorithms and how `--bindings` resolves to plan ports.

## 4. Package and Verify the Runtime Bundle

Photon consumes one complete bundle, not a loose plan. Package the normalized
pipeline with its exact hardware/bindings, module objects, and explicit
bootstrap snapshot. The packer runs Gluon itself, validates and canonicalizes
the snapshot against the generated plan before creating the output directory,
then self-verifies the completed bundle.

```bash
mkdir -p build/pack_modules
# Stage the three link-closed built-in images. Their proto files are
# host/offline authoring models, not runtime sidecars.
cp build/src/modules/acl/libkinetum_acl.so build/pack_modules/
cp build/src/modules/nat44/libkinetum_nat44.so build/pack_modules/
cp build/src/modules/qos/libkinetum_qos.so build/pack_modules/

./build/kinetum_pack \
  --axiom build/pipeline.axiom.pbtxt \
  --hw examples/fan_in_edge_gateway/hardware_inventory_tap.pbtxt \
  --bindings examples/fan_in_edge_gateway/fan_in_edge_gateway_tap_bindings.pbtxt \
  --modules-dir build/pack_modules \
  --bootstrap-snapshot examples/fan_in_edge_gateway/config_snapshot.pbtxt \
  --regions 3 \
  --out build/fan_in_bundle

# Re-run the same semantic gate after any copy or storage handoff.
./build/kinetum_bundle_verify --bundle build/fan_in_bundle
```

The bundle contains configuration and the exact module closure, never runtime
executables or provider artifacts. Those come only from the separately
installed runtime package. The standalone plan from Section 3 is useful for
inspection. The authoritative
runtime plan is `build/fan_in_bundle/configs/plan.pbtxt`, generated and hashed
inside the bundle workflow. The mandatory canonical snapshot is
`build/fan_in_bundle/configs/config_snapshot.pbtxt`; pack does not synthesize a
default even for a module-free pipeline.

See [`KINETUM_PACK.md`](KINETUM_PACK.md) for the exact manifest, path,
symlink, plan-identity, and snapshot-identity checks.

## 5. Install Kinetum

Released and locally built packages use the same package-specific `.install.sh`.
Choose the runtime for deployment or the SDK for module development, and choose
x86-64 or AArch64 to match the host. Each package is independent.

Public x86-64 packages require the Core i7/Nehalem instruction-set baseline;
public AArch64 packages require Armv8-A with CRC. Locally built native packages
may require additional CPU features. The installer's architecture check does
not test every instruction-set feature or convert machine-specific code.

A source owner first follows [Build Packages from Source](#build-packages-from-source)
to produce the final files, then returns to the local-package instructions here.
Production DP requires a finalized installation with its signed provider
inventory; a loose build tree is not a runnable production root. The integration
harness remains a separate private kit.

### Download and Install a Package

Choose runtime or SDK and then x86-64 or AArch64 on the
[Kinetum 0.1.0 release page](https://github.com/flemingpatel/kinetum/releases/tag/v0.1.0).
Each entry names one package. No build tree, compiler, signing key, or
caller-authored checksum is required.

In a Bash terminal, enable download-failure propagation once:

```bash
set -o pipefail
```

Runtime for x86-64:

```bash
curl -fsSL https://github.com/flemingpatel/kinetum/releases/download/v0.1.0/kinetum-runtime-0.1.0-x86_64.install.sh | sudo /bin/sh
```

Runtime for AArch64:

```bash
curl -fsSL https://github.com/flemingpatel/kinetum/releases/download/v0.1.0/kinetum-runtime-0.1.0-aarch64.install.sh | sudo /bin/sh
```

SDK for x86-64:

```bash
curl -fsSL https://github.com/flemingpatel/kinetum/releases/download/v0.1.0/kinetum-sdk-0.1.0-x86_64.install.sh | sudo /bin/sh
```

SDK for AArch64:

```bash
curl -fsSL https://github.com/flemingpatel/kinetum/releases/download/v0.1.0/kinetum-sdk-0.1.0-aarch64.install.sh | sudo /bin/sh
```

The POSIX-sh entry checks that the chosen architecture matches the host,
installs Ubuntu 24.04 system prerequisites through APT, downloads only its
bound archive, verifies its embedded expected SHA-256, and invokes the native
installer carried in that archive. It never selects another product or
architecture. A missing archive or digest mismatch fails explicitly.
The user does not manually hash or unpack the download.

### Install a Local Package

Use the same script for copied or locally produced packages. These examples
place the matching `.install.sh` and `.tar.gz` in the default `dist/` beneath
the current directory; adjust both paths if the files are elsewhere.

For the x86-64 runtime:

```bash
sudo /bin/sh dist/kinetum-runtime-0.1.0-x86_64.install.sh --offline-directory "$PWD/dist"
```

For the x86-64 SDK:

```bash
sudo /bin/sh dist/kinetum-sdk-0.1.0-x86_64.install.sh --offline-directory "$PWD/dist"
```

For AArch64, use the matching `aarch64.install.sh` and tar. `--offline-directory`
selects the archive directory, not the install prefix, and skips downloads and
APT. Prerequisites must already be installed; source bootstrap supplies them on
build hosts. The script verifies its embedded checksum, privately extracts the
native installer, and follows the normal installation path without manual
hashing or unpacking.

A script produced without `--release-url` requires this explicit local mode.
Without a URL or `--offline-directory`, it fails before any host change; it
never guesses a download address or searches for another archive.

### Installed Layout and Verification

The default prefix is `/opt/kinetum`; `--prefix /absolute/path` selects another
protected prefix. Runtime installation requires root, preserves `sdk/` and
`dependencies/`, and verifies the installed bytes. SDK installation replaces
only `sdk/`. Both validate a complete private candidate before replacement and
retain prior entries until installed verification succeeds. Failed replacement
restores the prior state; an incomplete restoration reports both causes and
retains the recovery tree. Stop services first: installation does not coordinate
live updates or start a service. An interrupted multi-root runtime replacement
can be unavailable; complete a retry before startup.

Inspect the installed runtime at any time with:

```bash
/opt/kinetum/bin/kinetum-info --check
```

This verifies package integrity and provider provenance. It does not start the
runtime or prove packet behavior; live validation remains a separate step.
Without `--check`, the tool reports runtime and SDK presence independently;
an absent SDK is shown as `not installed`, and unavailable resource paths are
omitted. Inspection failures return nonzero. Presence is not an integrity check.
`--check --json` combines runtime verification and build metadata without
requiring the SDK.

For deployment from released packages, use the installed tools and SDK or
source-tree inputs described in [`KINETUM_PACK.md`](KINETUM_PACK.md).
Once the bundle is verified, continue with Section 6 below.

## 6. Start the Supervisor (Photon)

Photon may be invoked from any working directory. It starts the dataplane,
starts the control plane, and exposes the control plane on
`127.0.0.1:50051`.

```bash
sudo /opt/kinetum/bin/kinetum_photon \
  --bundle "$PWD/build/fan_in_bundle"
```

The services write `/var/log/kinetum/kinetum_{photon,cp,dp}.log` with bounded
rotation. Use an explicit absolute `--log-dir` for another instance or an
unprivileged service run, and add `--log-console` for an interactive mirror.
See [Logging](LOGGING.md) for ownership, retention, reopen, and typed health.

A plan that requires DPDK PCI access normally requires root or equivalent
device/hugepage permissions. A UDP/host-storage plan does not acquire those
native resources. The supervisor first repeats complete runtime-bundle
admission, then reports the canonical plan and snapshot paths while retaining
exact child argument vectors internally. It never selects or repairs a provider
from CLI state. The
explicit bundle snapshot is the initial configuration authority; no loose
initial `set-config` command is required.

The production release aggregate contains the exact host and DPDK components.
The UDP component remains a development/conformance implementation and is not
an alternate unsigned startup path or a production-package fallback. A plan
requiring an implementation absent from the signed installed inventory fails
before `CONTROL_READY`; see [`PHOTON.md`](PHOTON.md).

## 7. Apply a Live Snapshot

The bundle snapshot is already active when Photon reports readiness. A later
configuration snapshot uses the same exact module set and deployment
topology, but receives a new CP-allocated epoch. `kinetumctl` generates one
random durable key before its first attempt and retains it across transport
retries:

```bash
/opt/kinetum/bin/kinetumctl --endpoint 127.0.0.1:50051 \
  set-config "$PWD/examples/fan_in_edge_gateway/config_snapshot_v2.pbtxt"
```

The initial snapshot in the bundle configures the baseline ACL rules, NAT pool,
and QoS profiles. Success is returned only after DP PREPARE, ordered worker
CUT/ACK activation, certified old-object retirement, and terminal COMPLETE;
CP then atomically publishes the new active snapshot. A plan, provider graph,
module-image, or topology change still requires a new bundle. See
[`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md)
for live apply, confirmation, and rollback semantics.

## 8. Observe Exact Runtime Telemetry

`stats` returns one all-or-none shared runtime observation. Runtime, engine,
transition, and protocol-fault summaries are mandatory; flags below select
complete optional row families. A missing, changing, malformed, or failed
selected observation returns exit status 1 with no partial stdout payload.

```bash
# Mandatory runtime, engine, transition, and fault summaries
/opt/kinetum/bin/kinetumctl stats

# Logical stages plus registered module metrics and typed health
/opt/kinetum/bin/kinetumctl stats \
  --stage-stats --module-metrics --module-health

# Exact worker, region, and ordered-boundary progress
/opt/kinetum/bin/kinetumctl stats \
  --worker-epoch-stats --region-epoch-stats --boundary-epoch-stats

# Typed provider observations and admitted steering/module-context topology
/opt/kinetum/bin/kinetumctl stats \
  --stream-stats --storage-domain-stats --port-stats --topology-stats
```

Provider rows distinguish exact, approximate, unsupported, and read-failed
observations; absent values are never printed as zero counters. Use
`--format json` for the strict protobuf-JSON shape consumed by validation.

See [`KINETUMCTL.md`](KINETUMCTL.md) for the full subcommand list and
[`GRPC_API.md`](GRPC_API.md) if you want to integrate the control plane
into your own tooling.

## 9. Prepare Private Validation

The private harness target uses Section 1's build and Python environment to
produce `build/kinetum_validation-0.1.0-py3-none-linux_x86_64.whl`, or the
corresponding `linux_aarch64.whl` variant on AArch64. The ordinary build compiles
native helpers but does not create this wheel. The target rebuilds changed or
missing helpers and stages beneath the selected build directory. This example
creates a separate environment at `/var/tmp/kinetum-validation`; pip installs
the harness, example inputs, native helpers, and Python dependencies:

```bash
cmake --build build --target kinetum_validation_kit
python3 -B -m venv /var/tmp/kinetum-validation
/var/tmp/kinetum-validation/bin/python3 -B -m pip install build/kinetum_validation-0.1.0-py3-none-linux_x86_64.whl
sudo /var/tmp/kinetum-validation/bin/python3 -I -B -X utf8 -m kinetum_validation --runtime-root /opt/kinetum --deployment fan-in-edge-gateway --dry-run --output-dir /tmp/kinetum_validation_dry_run
```

Use the wheel built for the lab host's architecture. The operator chooses
the Python environment; the path above is an example. Keep it outside the public
runtime prefix. Run commands explicitly select the runtime, while report
commands consume recorded artifacts without runtime admission. Before live
setup or run metadata, the harness executes the protected runtime's
`kinetum-info --check --json` and reads its verified runtime metadata. Package
resources are located from the installed Python package. Public runtime/SDK
packaging and documentation rendering are independent of this private package.

For the epoch authoring check:

```bash
sudo /var/tmp/kinetum-validation/bin/python3 -I -B -X utf8 -m kinetum_validation --runtime-root /opt/kinetum --deployment fan-in-edge-gateway --test-type epoch --dry-run --output-dir /tmp/kinetum_validation_epoch
```

These checks establish authoring and bundle admission. Packet evidence requires
live traffic, exact runtime identity, recorded host and instrument facts, and
the selected profile's complete result checks. TAP characterizes the local
kernel path; physical NIC claims require the PCI/TRex profile. See
[`VALIDATION_GUIDE.md`](VALIDATION_GUIDE.md) for profiles, evidence boundaries,
and the retained runner options.

## Build Packages from Source

Produce Section 5's installation files from the completed Section 1 build.
Invoke its `kinetum_package`, or a byte-identical copy, to stage through CMake's
install rules without configuring or compiling. Before native provider
admission, preparation checks that the staged packager matches the running
image. Keep the build and its inputs unchanged during preparation.

Source and build files may remain group-writable; preparation checks their
paths and content identity. CMake separately stages protected package files.
Archives, installed files, and signing keys retain their own permission checks.
An SDK-only source owner can proceed directly to
[Prepare the SDK](#prepare-the-sdk); signing identity is required for the runtime.
For a package that will be downloaded, select its publication URL before the
first finalization and use the commands in [Publish One Package](#publish-one-package).
The commands below produce packages for local installation.

```text
Completed build/ from Section 1
       |
       +-- runtime prepare --> unsigned candidate --> sign ---+
       |                                                      |
       +-- SDK prepare ---------------------------------------+
                                                              |
                                              dist/: tar + checksum + installer
                                                              |
                                            Install a Local Package (Section 5)
```

**Release identity.** A source-built runtime needs a private signing seed whose public
anchor matches its compiled verifiers. Use an existing matching seed for
routine preparation. When establishing or rotating that authority, create a
private directory and a new seed explicitly:

```bash
mkdir -m 0700 "$HOME/.kinetum-release"
./build/kinetum_package keygen --output "$HOME/.kinetum-release/provider-ed25519.seed"
```

The directory command is for first-time setup; an existing owner-controlled
private directory can be reused. `keygen` requires that parent to exist,
creates one 32-byte mode-0400 seed without replacement, and reports its public
anchor. Keep a private backup. The seed never belongs in source; generation
code and the single public anchor do. Review the new anchor in
`src/provider/provider_release_trust.cpp`, then rebuild the same selected build
before preparation:

```bash
cmake --build build -j
```

Official verifiers use the platform release anchor. Any downstream source
builder may replace that single anchor and sign with the matching seed for
that build. Rebuild every verifier that will accept the new release identity;
each native runtime build published under that authority must use it.

**Prepare the runtime.** The command below consumes the completed `build/` and
creates `dist/` in the current directory if needed. `VERSION` and the admitted
native tuple determine the archive name; preparation reports its complete
output path. Existing contents are preserved. `--output-dir /chosen/path`
selects another output directory and creates missing directories below an
existing owner-controlled parent without group/other write access. Relative output
paths, including the default `./dist`, are relative to the invocation directory,
not the source root. Key paths and archive output directories reject symbolic
links and `..` components. A failed operation may leave empty output directories;
no rejected archive is published.

```bash
./build/kinetum_package prepare --product runtime --build-dir build
```

On x86-64 this produces
`dist/kinetum-runtime-0.1.0-x86_64.candidate.tar.gz`. The following commands use
that filename; on AArch64 use the reported `aarch64` filename. The candidate
is unsigned input for signing, not an installable runtime. CMake alone chooses
staged membership. Native provider self-admission runs in a disposable process
without key inputs; runtime preparation consumes no documentation.

**Sign the runtime candidate.** `--candidate` selects the exact file produced
above. `--key` selects the private seed whose anchor was
compiled into this release. Signing creates the final archive beside other
outputs in invocation-relative `dist/`, or the explicitly selected
`--output-dir`. It also emits the archive's `.tar.gz.sha256` checksum and
`.install.sh` package installer.

```bash
./build/kinetum_package sign --candidate dist/kinetum-runtime-0.1.0-x86_64.candidate.tar.gz --key "$HOME/.kinetum-release/provider-ed25519.seed"
```

The final runtime files are:

```text
dist/
  kinetum-runtime-0.1.0-x86_64.tar.gz
  kinetum-runtime-0.1.0-x86_64.tar.gz.sha256
  kinetum-runtime-0.1.0-x86_64.install.sh
```

Follow [Install a Local Package](#install-a-local-package) with these files.
The same package script handles installation whether the archive was built
locally or downloaded. A publication URL is unnecessary for this local use.

Signing disables core dumps and completes and reaps archive decoding before it
opens the key. It admits the exact retained descriptor, including owner, mode,
link count, width, and stable identity, and proves the derived anchor. Signing
independently reconstructs the inventory and native receipt without executing
target code. Secret storage and its descriptor retire before final
manifest/archive production. A candidate may be transferred to a separate
signing host: `sign` needs the candidate and key, not its source or build tree.
Its tuple is checked against the candidate's inventory and ELF contents, not
inferred from the signing host.

The native receipt is deterministic unsigned evidence, not cryptographic
builder attestation. The provider signature authenticates the exact DP and
provider closure when checked by a trusted verifier. Archive delivery remains
the release channel's responsibility. SHA-256 is integrity, not a second
publisher signature.

### Prepare the SDK

SDK preparation consumes the same completed build and requires no runtime
archive, signing key, or rendered documentation:

```bash
./build/kinetum_package prepare --product sdk --build-dir build
```

The result is `dist/kinetum-sdk-0.1.0-x86_64.tar.gz` with its matching
`.tar.gz.sha256` and `.install.sh` files on x86-64, or the corresponding
`aarch64` files on the AArch64 builder. Each tar contains its native installer;
the SDK headers remain common to both architectures. Use the same
[local-package installation](#install-a-local-package) from Section 5.

SDK installation replaces only `/opt/kinetum/sdk`. Native preparation checks
exact staged header, metadata, legal, and example byte projections. Keep the
selected build and output directory outside the copied source header/example
trees; preparation rejects overlap before staging or output-directory creation.
The guides and API reference are published as a separate website. Its build and
acceptance workflow is in the [Documentation Guide](DOCUMENTATION_GUIDE.md).

Preparation verifies product bytes; it does not claim release qualification.
The in-tree CTest SDK fixtures compile C11/pkg-config and C++20/CMake consumers
under GNU and Clang and inspect exports, dependency closure, registration,
and unload. Unresolved-import tests prove compilation before requiring link
rejection. Independent qualification repeats those consumer checks against the
distributed SDK on a native host without the platform source tree. Both actual
compiler IDs must match the requested GNU or Clang family; executable filenames
are not the evidence.
The in-tree CTest matrix builds and runs these consumers in Release, supplies
explicit compiler paths, and uses a closed child environment. Neither layer
substitutes for the other.

### Publish One Package

Public releases use `KINETUM_ENABLE_NATIVE_ARCH=OFF` and qualify the exact
result against the declared CPU baseline, including its generated SIMD code
and measured performance. A successful package command proves its artifact
contract; it does not establish that CPU or performance qualification.

For downloadable packages, supply `--release-url` on the first runtime signing
or SDK preparation command. Its value is the versioned HTTPS directory where
the files will be uploaded. The installer always exists; this optional address
enables its download mode. A script received through a pipe cannot discover
that address itself.

Use the following commands in place of the URL-free finalization examples
above when preparing files for publication.

The official Kinetum 0.1.0 release uses this asset directory:

```bash
RELEASE_URL='https://github.com/flemingpatel/kinetum/releases/download/v0.1.0'
```

For your own release, select your repository's versioned asset directory
before finalizing the packages.

Finalize the unsigned runtime candidate:

```bash
./build/kinetum_package sign --candidate dist/kinetum-runtime-0.1.0-x86_64.candidate.tar.gz --key "$HOME/.kinetum-release/provider-ed25519.seed" --release-url "$RELEASE_URL"
```

Or prepare the SDK from the selected build:

```bash
./build/kinetum_package prepare --product sdk --build-dir build --release-url "$RELEASE_URL"
```

Each invocation emits only its chosen package's files. The runtime example
produces:

```text
dist/
  kinetum-runtime-0.1.0-x86_64.tar.gz
  kinetum-runtime-0.1.0-x86_64.tar.gz.sha256
  kinetum-runtime-0.1.0-x86_64.install.sh
```

Upload the completed set to the declared release directory; no collection step,
second publication directory, or other package is required. Choose the URL
first: changing it changes installer bytes, and conflicting existing files are
preserved with an error. Select a separate `--output-dir` for a different set,
including a changed CPU target when retaining the earlier archives.
Unsigned runtime preparation rejects
`--release-url`; only signing produces its installable archive. Each `.sha256`
file contains one standard lowercase SHA-256, two-space, archive-basename row.
The package-specific script embeds that same observed digest. Its native child
always receives it through `--sha256`.

The producer completes and checks bytes privately, then admits existing outputs:
identical contents converge; conflicting bytes remain untouched. It publishes
companions, retires private work, and commits the archive last. Interrupted
publication may leave companions without an archive; an exact retry completes
that prefix. Success requires the complete archive, checksum, and installer
from that invocation. Publication is not atomic across packages or remote uploads.

Reusing a completed build for preparation is allowed; choosing, configuring,
and rebuilding it remain explicit CMake operations. Package production verifies
bytes. Native release qualification remains a separate gate for each tuple.

## Where to Go Next

| If you want to...                                     | Read                                                       |
| --------------------------------------------------- | ---------------------------------------------------------- |
| Understand the platform architecture                | [`CONCEPTS.md`](CONCEPTS.md)                               |
| Author your own pipeline                            | [`AXIOM.md`](AXIOM.md)                                     |
| Understand how planning works                       | [`GLUON.md`](GLUON.md)                                     |
| Write a custom processing module                    | [`MODULE_SDK.md`](MODULE_SDK.md)                           |
| Integrate with the control plane via gRPC           | [`GRPC_API.md`](GRPC_API.md)                               |
| Use `kinetumctl` for operations                     | [`KINETUMCTL.md`](KINETUMCTL.md)                           |
| Locate and retain service diagnostics               | [`LOGGING.md`](LOGGING.md)                                  |
| Set up automated rollback                           | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| See the runtime in motion                           | [`diagrams/README.md`](diagrams/README.md)                 |
