# kinetum_pack

`kinetum_pack` produces a portable **bundle** containing the Axiom pipeline,
Gluon plan, complete bootstrap `ConfigSnapshot`, hardware inventory, required
modules, and SHA-256 manifest. Runtime executables and provider artifacts are
installed separately.

`kinetum_bundle_verify` checks manifest integrity, direct paths, canonical plan
identity, and exact snapshot/module-set agreement. The pure catalog validates
provider roles and canonicalizes their configurations before hashing; the
shared topology compiler validates the complete plan. Pack and Photon use this
same verifier.

This reference covers commands, workflow, manifest grammar, C++ APIs, and
runtime consumption.

Runtime and SDK archives are produced by the separate `kinetum_package` tool.
Their preparation, signing, and installation are covered in
[Getting Started](GETTING_STARTED.md#build-packages-from-source).
For operating a deployed bundle, see [`KINETUMCTL.md`](KINETUMCTL.md).
For authoring pipelines or modules, see [`AXIOM.md`](AXIOM.md),
[`GLUON.md`](GLUON.md), and [`MODULE_SDK.md`](MODULE_SDK.md).
For DP startup, see [`DATA_PLANE.md`](DATA_PLANE.md) and the
[platform architecture diagram](diagrams/platform_architecture.md).

This document is grounded in `src/pack/kinetum_pack_main.cpp`,
`src/pack/kinetum_bundle_verify_main.cpp`,
`src/pack/bundle_manifest.{hpp,cpp}`, `src/pack/runtime_bundle.{hpp,cpp}`,
`src/photon/photon_main.cpp`, `src/dp/dp_main.cpp`, and
`src/common/{sha256.cpp,version.hpp}`.

## Table of Contents

**Part 1: Concepts and Quick Start**

1. [What kinetum_pack and kinetum_bundle_verify Are](#1-what-kinetum_pack-and-kinetum_bundle_verify-are)
2. [Bundle Model and Vocabulary](#2-bundle-model-and-vocabulary)
3. [Bundle Layout](#3-bundle-layout)
4. [Quick Start: Build, Verify, Deploy](#4-quick-start-build-verify-deploy)

**Part 2: kinetum_pack**

5. [Synopsis and Flags](#5-synopsis-and-flags)
6. [The 10-Step Workflow](#6-the-10-step-workflow)
7. [Module Handling](#7-module-handling)
8. [Output Publication](#8-output-publication)
9. [Cleanup on Error](#9-cleanup-on-error)

**Part 3: kinetum_bundle_verify**

10. [Synopsis and Workflow](#10-synopsis-and-workflow)
11. [Shared Runtime-Bundle Admission](#11-shared-runtime-bundle-admission)
12. [Output and Exit Codes](#12-output-and-exit-codes)

**Part 4: The Manifest Format**

13. [Manifest Text Format Spec](#13-manifest-text-format-spec)
14. [Constants and Limits](#14-constants-and-limits)
15. [Parsing and Integrity Rules](#15-parsing-and-integrity-rules)

**Part 5: kinetum_pack_lib API**

16. [Library Surface](#16-library-surface)

**Part 6: Verification Semantics**

17. [The Verification Algorithm](#17-the-verification-algorithm)

**Part 7: Integration with Other Components**

18. [DP Startup Verification](#18-dp-startup-verification)
19. [CI/CD and Audit Workflows](#19-cicd-and-audit-workflows)
20. [Reproducibility Guarantees and Limits](#20-reproducibility-guarantees-and-limits)

**Part 8: Cross-Cutting**

21. [Bundle Integrity Boundary](#21-bundle-integrity-boundary)
22. [Capability Boundaries](#22-capability-boundaries)
23. [Where kinetum_pack and kinetum_bundle_verify Live](#23-where-kinetum_pack-and-kinetum_bundle_verify-live)
24. [Where to Go Next](#24-where-to-go-next)

---

## Part 1: Concepts and Quick Start

### 1. What kinetum_pack and kinetum_bundle_verify Are

Deployment-bundle tooling consists of three artifacts:

- **`kinetum_pack`** is the producer. It takes an Axiom pipeline pbtxt,
  a hardware inventory pbtxt, an explicit complete bootstrap snapshot,
  and optional module shared objects. It runs Gluon, validates the
  snapshot against the generated plan before creating the output tree,
  writes the normalized snapshot, generates the manifest, and passes its
  completed output through the same runtime-bundle verifier consumers use.
- **`kinetum_bundle_verify`** is the offline checker. Given a bundle
  directory, it rejects symbolic-link indirection, verifies every
  manifest entry and rejects extra files, requires the exact canonical
  plan and snapshot paths, verifies the plan content hash, compiles the exact
  provider topology, and canonicalizes the complete snapshot against that
  plan.
- **`kinetum_pack_lib`** is the internal static library that backs both
  binaries. Its high-level `verify_runtime_bundle` authority is consumed
  by the packer's final self-gate, `kinetum_bundle_verify`, Photon, and DP.
  Its lower-level manifest parser/generator/verifier remains available
  for manifest tooling; that lower-level API alone does not admit a runnable
  bundle and is never a DP startup substitute.

Four things this system is not:

- **Not a platform installer.** A bundle has no install script and is
  not a replacement for the runtime tarball. Production hosts install
  the Kinetum runtime first, then consume verified bundles as
  deployment payloads. Every bundle carries configs, plan, modules when
  required, and its manifest; it never carries `/opt/kinetum/bin/*`, provider
  components, or installed-provider release metadata.
- **Not a bundle signer.** The bundle manifest provides only SHA-256
  content integrity. There is no bundle signature, provenance attestation, or
  timestamp authority. The manifest itself is not
  signed; if an unauthorized writer can rewrite the bundle directory, it can
  rewrite the manifest. See Section 21 for the integrity boundary and
  Section 22 for the explicit boundary inventory.
  This statement is bundle-specific: the separately owned installed-provider
  inventory uses its own release-provenance signature contract and is not a
  bundle-manifest signature.
- **Not an archiver.** A bundle is a directory, not a `.tar.gz`. Use
  external archiving tools (tar, zip, OCI layers) on top of a
  bundle if you need a single-file artifact for transport.
- **Not a planner or pipeline author.** `kinetum_pack` invokes the
  Gluon planner under the hood, but the inputs (the Axiom pipeline
  pbtxt, the hardware inventory, and complete deployment bindings) come from
  elsewhere.
  See [`AXIOM.md`](AXIOM.md), [`GLUON.md`](GLUON.md).

### 2. Bundle Model and Vocabulary

| Term | Definition |
|---|---|
| **Bundle** | A directory tree with a defined layout (Section 3) and a `BUNDLE_MANIFEST.txt` file at the root. The configs and module shared objects are bundle-relative, so a verifier can validate the bundle from the directory alone. The bundle is a deployment payload, not an installer; production still needs a runtime installed from the Kinetum runtime tarball. |
| **Runtime-bundle admission** | The high-level `verify_runtime_bundle` gate. It composes symlink-free path validation, exact canonical artifact paths, manifest integrity, plan content identity, complete provider-topology compilation, and plan-bound snapshot identity. Passing `verify_manifest` alone is not equivalent. |
| **Bootstrap snapshot** | The mandatory complete `ConfigSnapshot` at `configs/config_snapshot.pbtxt`. Pack normalizes it against the exact generated plan; it is not an optional file copied for a later ad hoc apply. |
| **Manifest** | A canonical LF-terminated text file (`BUNDLE_MANIFEST.txt`) at the bundle root that lists every regular file with its byte size and SHA-256 hash. It excludes itself to avoid circularity. Metadata has fixed positions, and file paths are strictly increasing. |
| **Relative path** | The exact ASCII path of a bundle file relative to the bundle root. It is lexically canonical, uses `/`, contains no empty, `.` or `..` component, has no whitespace, control byte, backslash, or drive/absolute spelling, and is at most 512 bytes. The grammar has no quoting or normalization step. |
| **Bundle name** | The required line-1 `bundle_name=` value. Pack derives it from the original `--out` basename. It contains 1-255 ASCII letters, digits, periods, underscores, or hyphens and is neither `.` nor `..`. Relocating the completed bundle does not rewrite or reinterpret this identity. |
| **Bundle version** | The required line-2 `bundle_version=` value. It must byte-equal `kinetum::common::KINETUM_VERSION_STRING`, injected by the owning top-level CMake target from the exact root `VERSION`. The parser is the one version wall; a well-formed foreign version is `FAILED_PRECONDITION`, and no default exists. |
| **Manifest entry** | One line of the form `file <rel_path> <size_bytes> <sha256_hex>`. Paths are strictly increasing and therefore unique. Size text is shortest-form unsigned decimal, and the digest is lowercase hexadecimal. |
| **Extra files** | Files present in the bundle directory but not declared in the manifest. `kinetum_bundle_verify` reports these as an integrity alert and fails verification. |
| **Runtime payload manifest** | The separate installed-runtime manifest at `share/kinetum/release/runtime_payload_manifest.sha256`. It defines complete runtime-owned membership and hashes every other runtime-owned file; the verifier admits the manifest itself by exact path and grammar to avoid a circular self-hash. It is not part of a deployment bundle and does not replace the signed provider inventory. |

### 3. Bundle Layout

```
bundle/
  configs/
    pipeline.axiom.pbtxt        (Axiom pipeline, rewritten to remove module_path)
    hardware.pbtxt              (hardware inventory, copied from --hw input)
    plan.pbtxt                  (Gluon execution plan)
    config_snapshot.pbtxt       (mandatory, normalized from --bootstrap-snapshot)
  modules/                      (only if pipeline has module stages)
    <module_id>.so              (one per distinct module_id)
    modules.json                (human-readable metadata, declared but not consumed)
  BUNDLE_MANIFEST.txt           (always; SHA-256 manifest)
  README_BUNDLE.md              (always; required informational metadata)
```

Origin of each subtree:

- **`configs/`**:
  - `pipeline.axiom.pbtxt` is the Axiom pipeline from `--axiom`,
    re-serialized after `kinetum_pack` removes authoring-only module paths
    (Section 7).
  - `hardware.pbtxt` is the inventory from `--hw`, re-serialized.
  - `plan.pbtxt` is the Gluon-generated `DeploymentPlan` proto.
  - `config_snapshot.pbtxt` is mandatory. `kinetum_pack` strictly parses
    `--bootstrap-snapshot`, verifies the generated plan's content hash,
    requires exact two-directional equality with the plan module set,
    verifies supplied hash claims, and writes the canonicalized message.
- **`modules/`**: present only if the pipeline contains
  `STAGE_KIND_MODULE` stages. Each distinct `module_id` (after the
  resolution rules in Section 7) becomes one `<module_id>.so` file.
  `modules.json` is a small JSON metadata file (Section 22 for its
  declared-but-not-consumed status).
- **`BUNDLE_MANIFEST.txt`**: produced last, after every other file
  has been written. Excludes itself.
- **`README_BUNDLE.md`**: a fixed markdown template generated
  from `kinetum_pack`'s `write_bundle_readme` function. Informational
  only; integrity is enforced via the manifest, not the README. Its launch
  commands use the installed runtime prefix and an explicit bundle path, so
  they never infer runtime binaries from the bundle. A write failure aborts
  acceptance and removes the complete rollback-owned output.

The packer retains its output rollback guard through every success record,
flushes and verifies stderr, and only then performs the final nonthrowing
`release()` edge. If success reporting cannot be delivered, pack exits `1`
with the guard armed and removes the complete output directory.

### 4. Quick Start: Build, Verify, Deploy

Build and verify a bundle, then start Photon. The target host needs an installed
runtime; the packaging workstation needs examples from the SDK or source tree.

```sh
# Create one exact publication parent outside the runtime installation root.
/usr/bin/sudo /usr/bin/install -d -m 0755 -- /var/lib/kinetum
/usr/bin/sudo /usr/bin/install -d -m 0755 \
  -o "$(/usr/bin/id -u)" -g "$(/usr/bin/id -g)" -- \
  /var/lib/kinetum/bundles

# 1. Build the bundle. Complete DeploymentBindings are mandatory; runtime
#    binaries remain under the independently installed runtime root.
kinetum_pack \
  --axiom /opt/kinetum/sdk/examples/fan_in_edge_gateway/fan_in_edge_gateway.axiom.pbtxt \
  --hw /opt/kinetum/sdk/examples/fan_in_edge_gateway/hardware_inventory_tap.pbtxt \
  --bindings /opt/kinetum/sdk/examples/fan_in_edge_gateway/fan_in_edge_gateway_tap_bindings.pbtxt \
  --modules-dir /opt/kinetum/lib/modules \
  --bootstrap-snapshot /opt/kinetum/sdk/examples/fan_in_edge_gateway/config_snapshot.pbtxt \
  --regions 3 \
  --out /var/lib/kinetum/bundles/fan_in_edge_v1

# 2. Verify the complete deployment bundle offline before deployment.
kinetum_bundle_verify --bundle /var/lib/kinetum/bundles/fan_in_edge_v1

# 3. Launch the installed Photon image from any working directory. Photon
#    admits the bundle before child spawn, after signal and logging setup.
sudo /opt/kinetum/bin/kinetum_photon --bundle /var/lib/kinetum/bundles/fan_in_edge_v1
```

The shared verifier catches producer drift at pack completion, storage/transport
corruption at handoff, and invalid deployment input before Photon starts
children. Section 18 details the Photon/DP admission split.

---

## Part 2: kinetum_pack

### 5. Synopsis and Flags

```sh
kinetum_pack --axiom <pipeline.axiom.pbtxt> --hw <hardware.pbtxt>
            --bindings <deployment_bindings.pbtxt>
            --bootstrap-snapshot <config_snapshot.pbtxt> --out <bundle_dir>
            [--regions N] [--modules-dir <dir>]
            [-h | --help]
```

Required:

| Flag | Purpose |
|---|---|
| `--axiom <file>` | Path to the Axiom pipeline pbtxt. Loaded with `axiom::load_pipeline_pbtxt` and the `require_linear_pipeline = false` option (DAG pipelines are accepted). |
| `--hw <file>` | Path to the hardware inventory pbtxt (`kinetum.hw.v1.HardwareInventory`). |
| `--bindings <file>` | Path to complete exact `gluon.v1.DeploymentBindings`. Every process facility, I/O driver, packet-storage domain, execution provider, logical port, queue, stage execution target, and storage transition required by the pipeline must be authored explicitly. |
| `--bootstrap-snapshot <file>` | Path to the complete bootstrap `ConfigSnapshot` pbtxt. It must match the exact generated plan module set and all supplied content-hash claims. No snapshot is synthesized. |
| `--out <dir>` | Exact absent output-directory leaf. Its lexically exact parent must already exist and be direct; pack creates only the final leaf. |

Optional:

| Flag | Default | Purpose |
|---|---|---|
| `--regions N` | `2` | Number of logical regions for the planner. Must be a positive base-10 integer with no trailing characters. |
| `--modules-dir <dir>` | empty | Explicit flat module artifact source, resolved once to a canonical directory. It contains main images plus their colocated `.so` dependencies and is **required for every built-in `kinetum.*` module**, even when that stage also supplies `module_path`. |
| `-h`, `--help` | n/a | Print usage to stderr and exit 0. |

All source-side filesystem arguments are admitted before parsing or output
construction. `--axiom`, `--hw`, `--bindings`, `--bootstrap-snapshot`, optional
`--modules-dir`, and explicit module paths may be written as relative
operator input, but pack resolves each exactly once and retains only its
canonical absolute file or directory identity. Any absent, mistyped, or
unresolvable source rejects the whole source specification; no partially
admitted path set is published and no raw CLI path survives into later reads or
copies. The process image, `argv[0]`, `PATH`, and CWD never select runtime files
because a deployment bundle has no runtime-file source authority.

Exit codes: `0` success, `1` runtime error (planning failure, I/O,
module copy, manifest generation), `2` usage error (missing required
flag, unknown flag, malformed numeric value, invalid explicit source
files/directories, a pre-existing output, or an unresolvable built-in module
without `--modules-dir`).

### 6. The 10-Step Workflow

`kinetum_pack` runs a fixed sequence. Each step has its own failure
class and its own log line.

1. **Argument parsing and source admission.** Each unknown flag exits 2
   immediately. The missing-required check happens after the parsing loop (so
   `--help` short-circuits before the check). Pack then resolves its exact
   source specification and atomically admits every required/optional source
   file and directory to
   canonical identity. A failure exits before protobuf parsing or
   output-directory creation. Runtime-binary source selection does not exist.
2. **Load Axiom pipeline.** `axiom::load_pipeline_pbtxt(axiom_path,
   contract_options{require_linear_pipeline = false})`. A failure exits
   1. The pipeline is held as a mutable copy for source-path normalization.
3. **Scan module stages.** Iterate `pipeline.stages()`; for any stage
   with `kind() == STAGE_KIND_MODULE`, extract the typed `module_id` and
   optional `module_path`. Apply the module-resolution rules in
   Section 7. Build the `modules_to_copy` list. Reusing the same
   `module_id` is allowed only when it resolves to the same source
   path; conflicting sources for one ID fail with usage error. After every
   source is admitted, clear all `module_path` fields before planning so the
   emitted plan and bundled pipeline share one bundle-relative authority.
4. **Load hardware inventory.** `read_pbtxt_file` receives the explicit
   64 MiB whole-file bound and the `HardwareInventory` destination. Failure
   exits 1.
5. **Run Gluon planner.** Load the required exact `DeploymentBindings` through
   the same explicit bound, set
   `planner_options{regions, deployment_bindings}`, and invoke the
   provider-neutral planner. Planning failure exits 1. Before any output
   directory is created, verify the completed provider-aware plan identity and
   strictly parse, validate, and normalize the explicit bootstrap snapshot. A
   malformed, incomplete, module-mismatched, oversized, or stale-hash snapshot
   exits 1 without creating `<out>`.
6. **Acquire one rollback-owned output.** Convert a relative argument to an
   absolute lexical identity without normalization, require that identity to
   equal its own lexical normalization, admit its exact existing parent with
   no symbolic-link repair, require its basename to satisfy the one canonical
   bundle-name grammar, and require `<out>` itself to be absent. Create exactly
   that one directory, arm rollback ownership, and create
   `<out>/configs`. A `.`/`..` spelling, indirect parent, or pre-existing file,
   directory, or symlink is a usage error. No `bin/` directory is created.
7. **Handle modules.** If `modules_to_copy` is non-empty: create
   `<out>/modules`, copy each admitted `.so` into
   `<out>/modules/<module_id>.so`, and write the
   informational `modules.json`. Module copy failure triggers
   cleanup-on-error and exits 1. `modules.json` is required; a write failure
   aborts publication.
8. **Save configuration files.** Write the (now-rewritten) pipeline
   to `configs/pipeline.axiom.pbtxt`, the hardware inventory to
   `configs/hardware.pbtxt`, the Gluon plan to `configs/plan.pbtxt`,
   and write the normalized bootstrap snapshot to
   `configs/config_snapshot.pbtxt`. Caller formatting and field order are not
   copied into the bundle. Any failure triggers
   cleanup-on-error and exits 1.
9. **Write required metadata and manifest.** Write `README_BUNDLE.md`, compose
   one structured manifest, and emit `BUNDLE_MANIFEST.txt` only through its
   validating serializer. Every failure is fatal; there is no second emitter
   or WARN-and-continue publication path.
10. **Self-verify and accept.** Pass the completed output through
    `verify_runtime_bundle`. Any manifest, path, plan-identity,
    provider-topology, or snapshot-identity failure removes the whole output.
    Only success disarms rollback and leaves the directory as an accepted
    bundle.

After self-verification, pack prints canonical plan/snapshot paths and an
independent verify command. Re-run that check after copying, archive extraction,
or storage handoff.

### 7. Module Handling

Pack resolves every module stage to a `.so` source before creating output.

#### `module_id` resolution

For each `STAGE_KIND_MODULE` stage in the pipeline:

1. Require the stage's typed `ModuleStageConfig.module_id`.
2. Treat `module_path` only as an optional source-location authority; it never
   derives or repairs module identity.
3. Missing module configuration or an empty `module_id` fails before output
   construction.

The resolved `module_id` must also be safe to use as a bundle
filename. The accepted character set is `A-Z`, `a-z`, `0-9`, `.`,
`_`, and `-`; the values `.` and `..` are rejected. This prevents a
pipeline from escaping `modules/` when pack writes
`<out>/modules/<module_id>.so`.

#### `.so` source resolution

Once `module_id` is known:

- If the stage has an explicit `module_path`, that path is the source. A
  relative operator-supplied path is resolved once at admission; pack requires
  the result to be an existing canonical absolute regular file before it
  creates the output tree. Resolution failure is terminal; there is no fallback
  to a relative representation for a later copy or runtime lookup.
- If `module_path` is absent and `module_id` starts with `"kinetum."`
  (a **built-in module**), `--modules-dir` is required. The mapping
  is source-defined and exact:
  - `kinetum.acl` -> `<modules_dir>/libkinetum_acl.so`
  - `kinetum.nat44` -> `<modules_dir>/libkinetum_nat44.so`
  - `kinetum.qos` -> `<modules_dir>/libkinetum_qos.so`
  `--modules-dir` is a flat lookup directory; pack does not search
  `acl/`, `nat44/`, or `qos/` subdirectories.
  The `kinetum.*` namespace is reserved. Any other identity in it exits 2 with
  `"unknown reserved built-in module_id '<id>'"`, even when a `module_path` is
  present; customer modules use their own organization-qualified namespace.
- If `module_path` is absent and `module_id` does **not** start with
  `"kinetum."`, exit 2 with `"module '<id>' requires module_path"`. There is
  no implicit lookup for non-built-in modules.

Each built-in runtime image is link-closed and owns its strict configuration
parser. Its `.proto` file is a host/offline authoring model and is not a
runtime sidecar. Consequently, no generated-schema `.so` is required or
inferred for ACL, NAT44, or QoS.

After resolving all main images, pack admits every other direct-child
`.so`/`.so.<version>` file in `--modules-dir` as an auxiliary dependency.
Dependency basenames use the same one-component grammar as module IDs;
symbolic links, directories named like shared objects, and unsafe names fail
closed. Dependencies are sorted by basename, copied without renaming, and
covered by `BUNDLE_MANIFEST.txt`. A dependency cannot collide with the packed
`<module_id>.so` name. The complete flat directory is deliberate source
authority; pack does not search for or infer a transitive dependency elsewhere.

#### Pipeline rewriting

After retaining every admitted source path and before invoking Gluon,
`kinetum_pack` normalizes each typed module configuration:

- Present `module_path` is cleared after its source file is admitted.
- The already validated `module_id` remains byte-identical.

The resulting plan and bundled pipeline both carry `module_id` only, never
`module_path`. The later copy consumes the retained admitted source list, and
the runtime resolves modules from
`bundle_dir/modules/<module_id>.so`, which is bundle-relative and
portable.

#### Deduplication

Stages sharing a `module_id` must resolve to the same canonical source path;
pack copies that image once. A conflicting path for the same ID exits 2.

#### `modules.json`

After the `.so` files are copied, `kinetum_pack` writes an
informational JSON file at `modules/modules.json`:

```json
{
  "abi_version": 65536,
  "modules": [
    { "module_id": "kinetum.acl", "so": "modules/kinetum.acl.so" },
    { "module_id": "kinetum.qos", "so": "modules/kinetum.qos.so" }
  ],
  "dependencies": [
    "modules/libmodule_support.so"
  ]
}
```

The dependency list contains only explicit auxiliary module DSOs discovered
in the admitted flat source. It is empty when every packed image is
self-contained, as the three built-ins are. Generated host-authoring schemas
do not appear in it.

`abi_version` is the exact integer `KINETUM_MODULE_ABI_VERSION`; version
0.1.0 is encoded as `0x00010000`, or `65536` in JSON. It is metadata for
the ABI against which the bundled images were built, not a compatibility
range. Failure to write this required file aborts publication. **No tool in the
current source tree consumes `modules.json`.** It is documented here as an
operator-inspection contract; see Section 22.

### 8. Output Publication

`kinetum_pack` has one permanent output shape: deployment configuration plus
the exact module-artifact closure. Runtime executables, provider components,
the signed provider inventory, and runtime release metadata come only from the
installed runtime package. This is a provenance boundary, not an optional
space-saving mode.

The output path names one lexically exact new leaf below an admitted exact
existing directory. Pack neither canonicalizes a caller's `.`/`..` spelling
into another authority nor follows a symbolic parent; it never reuses, merges
with, or clears a pre-existing output. Its basename must satisfy the shared
bundle-name predicate before that leaf is created. Once created, every
configuration, module, dependency, `modules.json`, README, and manifest write
is required. The completed tree must pass the same semantic verifier used at
startup before publication ownership is released.

The high-level verifier independently rejects a `bin/` subtree even if an
external producer adds it to a syntactically valid manifest. Low-level
manifest tests may still use names such as `bin/a` to exercise generic path
grammar; that generic primitive does not define the production bundle layout.

### 9. Cleanup on Error

Every failure after output creation leaves an armed publication owner. Its
destructor removes exactly the new `<out>` leaf and all descendants; it cannot
reach the admitted parent or any pre-existing path because creation would have
failed if the leaf already existed. Cleanup uses non-throwing filesystem
operations. A cleanup failure is process-fatal because returning while a
partial output remains would violate the publication contract.

Callers must therefore pass an absent leaf, not a directory they created in
advance. On successful semantic self-verification the owner is disarmed and the
complete tree remains. A process crash or power loss is outside this in-process
rollback guarantee; deployment automation must publish or move a verified
directory under its own durable artifact-store transaction when crash-atomic
multi-host handoff is required.

---

## Part 3: kinetum_bundle_verify

### 10. Synopsis and Workflow

```sh
kinetum_bundle_verify --bundle <bundle_dir>
kinetum_bundle_verify -h | --help
```

Single argument:

| Flag | Purpose |
|---|---|
| `--bundle <dir>` | Path to the bundle root directory. |

Workflow:

1. **Parse CLI.** Require exactly one `--bundle <dir>` argument.
   Missing values, unknown flags, and missing `--bundle` exit 2.
2. **Admit the runtime bundle.** Call the shared
   `kinetum::pack::verify_runtime_bundle` authority. It rejects
   symbolic-link indirection, verifies the complete manifest, requires
   the exact canonical plan and bootstrap-snapshot paths, strictly
   parses both messages, verifies the plan content hash, and
   canonicalizes the snapshot against the plan's exact module set.
   Any admission failure exits 1 with the returned reason and details.
3. **Report canonical artifacts.** On success, print the canonical
   bundle root, plan path and ID, and bootstrap-snapshot path and ID to
   stdout, then exit 0 only after the complete report is accepted by the
   output descriptor.

The verifier is read-only and permits concurrent readers. Keep the bundle
immutable: verification re-reads and re-hashes canonical artifacts before parsing,
so concurrent mutation is unsupported.

### 11. Shared Runtime-Bundle Admission

The CLI delegates to `verify_runtime_bundle`, also used by pack before
publication and Photon before child startup.

The shared gate performs these ordered checks:

1. Resolve the supplied root to an absolute lexical path while rejecting a
   symbolic link in the root or any existing path component. Require a
   directory.
2. Traverse the complete bundle tree and reject every symbolic-link entry or
   unsupported filesystem object. Runtime bundles contain only directories
   and regular files.
3. Strictly read and parse canonical `BUNDLE_MANIFEST.txt` under the manifest
   size cap. Require exact product version and manifest entries for exactly
   `configs/plan.pbtxt` and
   `configs/config_snapshot.pbtxt` as the runtime artifacts.
4. Invoke the low-level `verify_manifest` authority to validate every declared
   file's size and SHA-256 and to reject extra regular files.
5. Re-read and re-hash the canonical plan immediately before strict protobuf
   parsing, then pass it through the deployment-plan identity authority. That
   authority rejects recursive unknown fields, canonicalizes every
   role-correct provider `Any`, rejects duplicate facility references,
   preserves order-contractual final arrays, and requires the nonempty
   `content_hash` claim to match.
6. Re-read and re-hash the canonical snapshot immediately before strict
   protobuf parsing, then canonicalize it against the exact plan module set and
   verify every supplied module/top-level content-hash claim.

The path checks cover the supplied bundle root, every component leading to it,
all descendants, the manifest, and both canonical config artifacts. They are
stronger than the low-level manifest primitive, whose format intentionally
describes regular-file bytes rather than filesystem indirection.

### 12. Output and Exit Codes

| Exit code | Meaning |
|---|---|
| `0` | Success. Complete SUCCESS banner emitted to **stdout**. |
| `1` | Verification failed. FAILED banner with details emitted to **stderr**. |
| `2` | Usage error: missing `--bundle` or unknown flag. |

#### Success output (stdout)

```
================================================================
VERIFICATION SUCCESSFUL
================================================================
Bundle: /var/lib/kinetum/bundles/fan_in_edge_v1
Plan: /var/lib/kinetum/bundles/fan_in_edge_v1/configs/plan.pbtxt (plan-id)
Bootstrap snapshot: /var/lib/kinetum/bundles/fan_in_edge_v1/configs/config_snapshot.pbtxt (snapshot-id)
Manifest, canonical paths, plan identity, and snapshot identity verified.
================================================================
```

#### Failure output (stderr)

The generic failure block:

```
================================================================
VERIFICATION FAILED
================================================================
Error: <status.message()>
[Details: <status.details()>]
================================================================

Bundle admission failed. Do NOT deploy this bundle.
```

The `Details` line is present only when the returned status carries a nonempty
supplemental diagnostic.

#### Extra-file integrity alert

When the failure reason contains the substring `"extra file"`
(the verifier found a file in the bundle that is not declared in the
manifest), the binary emits an additional alert block instead of the
generic "Do NOT deploy" line:

```
INTEGRITY ALERT: Bundle contains an undeclared file!
This could indicate:
  - Undeclared content injection
  - Bundle contents changed after manifest generation
  - Manifest not regenerated after adding files

Action required:
  1. Inspect the undeclared path in Details
  2. If legitimate, regenerate the manifest
  3. Reject the bundle if the path is unexpected
```

The verifier reports the first undeclared path and stops. One contradiction is
enough to reject the bundle, so an undeclared population cannot become retained
diagnostic state or a post-failure scan target.

#### `stdout`/`stderr` separation

Success goes to stdout and failure goes to stderr. The verifier emits no
separate logger narration: each invocation has one complete report. A delivery
failure exits `1`, including help and usage output.
Scripts can rely on this: `kinetum_bundle_verify --bundle X
> /dev/null` discards the success banner without losing failure
context.

---

## Part 4: The Manifest Format

### 13. Manifest Text Format Spec

The manifest has one canonical ASCII representation. Every line ends with LF,
including the final line. The parser does not trim, skip, reorder, normalize,
or default any input byte.

#### Grammar

```
manifest   := name_line version_line { file_entry }
name_line  := "bundle_name=" <canonical_name> LF
version_line := "bundle_version=" <exact_product_version> LF
file_entry := "file " <rel_path> " " <size_bytes> " " <sha256_hex> LF
```

#### Field rules

- `<canonical_name>` is 1-255 bytes from `[A-Za-z0-9._-]`, excluding the
  complete values `.` and `..`. It occurs exactly once and only on line 1.
- `<exact_product_version>` follows the root `VERSION` grammar: three nonempty
  numeric components plus the optional admitted prerelease/build suffix. It
  must byte-equal the verifier's `KINETUM_VERSION_STRING`, occurs exactly once
  on line 2, and treats a valid foreign product version as incompatible rather
  than an alias.
- `<rel_path>` must satisfy the Section 15 path rules: not empty,
  ASCII, relative, lexically normalized, no empty, `..`, or `.` component,
  no whitespace or control characters, no backslashes, and length less than
  or equal to `MAX_REL_PATH_LENGTH` (Section 14). Paths are strictly increasing
  by byte value. There is no quoting or escaping layer.
- `<size_bytes>` must be an unsigned base-10 integer token with only
  digits (`0`-`9`) in shortest form. Empty tokens, signs, leading zeroes
  except the single value `0`, trailing junk, and overflow reject.
- `<sha256_hex>` is exactly `kinetum::common::SHA256_HEX_LENGTH`
  (64) lowercase hexadecimal characters. Uppercase is not a second canonical
  spelling.

#### Determinism

`generate_manifest_text` sorts file entries lexicographically by `rel_path`,
then emits only through `bundle_manifest::to_text`. That serializer validates
the structured value and submits its bytes to the same strict parser. Identical
bundle-file bytes, output basename, and product version produce byte-identical
manifest text. Gluon's timing metadata can change those file bytes between pack
runs; see Section 20.

#### Self-exclusion

The manifest never contains an entry for its root `BUNDLE_MANIFEST.txt`.
Generation skips it, parsing rejects a supplied self-entry, and the extra-file
scan excludes it. Hashing the manifest would otherwise create a circular
definition.

#### Worked example

```
bundle_name=fan_in_edge_v1
bundle_version=0.1.0
file README_BUNDLE.md 1842 3a7f5b6c9d8e2f1a0b4c7e9d8f6a5b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a
file configs/config_snapshot.pbtxt 2304 05e1f0f258a0dc71b52b75fb6a33afe3597db9e7506fcfaf418cd71e5b71afc8
file configs/hardware.pbtxt 2456 c5f8a71d2f96312c2fe7df277aedb4ce252696d50ea031c906c6a833f8d60df7
file configs/plan.pbtxt 8012 8b7ff59f297a80dbe8b6de0da125928bfd002b1233701078f510a85b375867e0
file configs/pipeline.axiom.pbtxt 4321 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
file modules/kinetum.acl.so 524288 d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5
file modules/modules.json 174 acfd8b849a25649d6cff274c17e723f1b767b07557a6ecb7dac51a8ea199cc73
```

The names, sizes, and digest text above are illustrative format values, not an
inventory or byte claim for a generated example bundle.

### 14. Constants and Limits

Manifest-specific constants are declared by the source-tree-private
`src/pack/bundle_manifest.hpp`.
The SHA-256 width comes from the platform-wide fixed-digest contract in
`src/common/sha256_digest.hpp`; the manifest parser does not maintain a second
numeric authority.

| Constant | Value | Purpose |
|---|---|---|
| `MANIFEST_FILENAME` | `"BUNDLE_MANIFEST.txt"` | The expected manifest filename. Both the generator and the verifier use this constant; renaming requires changing one place. |
| `kinetum::common::SHA256_HEX_LENGTH` | `64` | Platform-wide exact length of a hex-encoded SHA-256 digest. Hash entries with a different length are rejected. |
| `MAX_MANIFEST_SIZE` | `1024 * 1024` (1 MB) | Inclusive byte ceiling enforced incrementally by generation, before serializer publication, and before parsing. Exactly 1 MB is valid when every row is canonical. |
| `MAX_BUNDLE_NAME_LENGTH` | `255` | Inclusive byte ceiling for the canonical bundle-name atom. Pack checks the same predicate before creating its output directory. |
| `MAX_BUNDLE_FILES` | `10000` | Inclusive file-entry ceiling enforced during generation, structured serialization, and parsing. The 10001st row rejects before insertion. |
| `MAX_REL_PATH_LENGTH` | `512` | DoS cap on relative-path length per entry. Long paths are unusual in real bundles; the cap exists to bound parser memory. |

Extra-file validation returns the first undeclared relative path, excluding the
manifest itself.

### 15. Parsing and Integrity Rules

`bundle_manifest::from_text` enforces a fail-closed parse: any
violation rejects the entire manifest. There is no partial accept.

#### Path validation (per entry, in `validate_safe_relative_path`)

| Rule | Rejection reason |
|---|---|
| `rel_path` is empty | `"empty relative path not allowed"` |
| `rel_path.size() > MAX_REL_PATH_LENGTH` | `"relative path exceeds maximum length"` |
| First character is `/` or `\` | `"absolute paths not allowed in manifest"` |
| Second character is `:` (drive-letter form like `C:\path`) | `"absolute paths not allowed in manifest"` |
| Any byte is whitespace, control, DEL, or non-ASCII | `"relative path contains noncanonical whitespace, control, or non-ASCII byte"` |
| Any byte is `\` | `"relative path must use '/' separators, not backslashes"` |
| Any path component equals `..` | `"directory traversal not allowed (.. detected)"` |
| Any path component equals `.` | `"current directory references not allowed (. detected)"` |
| Lexical normalization would change the spelling | `"relative path is not in canonical lexical form"` |
| Path equals root `BUNDLE_MANIFEST.txt` | `"bundle manifest must not list itself"` |

These rules constrain declared paths to the bundle. Execute its files only
after verification and deployment-policy acceptance.

The row parser requires exactly two single-space separators after `file `.
A space in a path therefore fails row arity before path validation. Tabs,
non-ASCII bytes, repeated separators, and other noncanonical path forms fail
their owning validation.

#### Hash validation (per entry)

| Rule | Rejection reason |
|---|---|
| Length not equal to 64 | `"invalid SHA-256 hash length (expected 64 hex chars)"` |
| Any character outside `[0-9a-f]` | `"invalid SHA-256 hash (expected lowercase hexadecimal)"` |

#### Size validation (per entry)

| Rule | Rejection reason |
|---|---|
| Size is empty, signed, zero-padded, contains non-digits or trailing junk, or overflows `uint64_t` | `"invalid file size in manifest"` (with line attached) |

#### Duplicate entry rejection

Each new file path must be greater than the immediately preceding path. One
comparison therefore proves both deterministic ordering and uniqueness. Equal
or regressing paths reject with `"bundle manifest file paths are not strictly
sorted and unique"`; no O(f-squared) duplicate scan exists.

#### Unknown directive rejection (fail-closed)

After the two fixed metadata rows, every row must begin exactly with `file `.
Blank lines, repeated metadata, unknown directives, and alternate prefixes are
malformed. A future format change requires an explicit contract update; it is
never inferred from unknown input.

#### Required metadata and version wall

Name and version are required nonempty input. The parser never fabricates
either value. A malformed name/version shape is `INVALID_ARGUMENT`; a valid
root-`VERSION` representation that differs from `KINETUM_VERSION_STRING` is
`FAILED_PRECONDITION`. This comparison exists once in `from_text`, so every
low- and high-level consumer inherits the same product-version wall.

#### Per-entry overall caps

Two more caps fire during the parse loop, not per entry:

- `MAX_MANIFEST_SIZE` is an inclusive producer-and-parser byte ceiling.
- `MAX_BUNDLE_FILES` is an inclusive producer-and-parser row ceiling.
- Generation accumulates the exact eventual row extent while scanning. The
  checked serializer recomputes it before allocation. A producer cannot emit a
  manifest that its own parser rejects at either exact boundary.

---

## Part 5: kinetum_pack_lib API

### 16. Library Surface

The source-tree-only `kinetum_pack_lib` exposes two layers under
`namespace kinetum::pack`; it is not an installed SDK API.
`runtime_bundle.hpp` owns runnable-bundle admission and bootstrap-snapshot
normalization. `bundle_manifest.hpp` owns the lower-level manifest
format/generation/integrity primitive. Tools that integrate verification
programmatically link the CMake target directly (Section 23).

The high-level `verify_runtime_bundle` authority has exactly four production
consumers:

- `kinetum_pack`, as the final producer self-gate;
- `kinetum_bundle_verify`, as the offline checker;
- Photon, after signal/logging setup and before child construction; and
- DP, which independently re-admits the complete `--bundle` root before host,
  provider, materialization, or gRPC side effects.

Repository tools that link this private target should call
`verify_runtime_bundle` rather than compose the lower-level authorities
themselves when they need to admit a runnable deployment. Out-of-tree tools
use the installed `kinetum_bundle_verify` process contract.

#### `load_and_normalize_bootstrap_snapshot`

```cpp
[[nodiscard]] kinetum::common::status_or<normalized_bootstrap_snapshot>
load_and_normalize_bootstrap_snapshot(
    const std::string &snapshot_path,
    const kinetum::gluon::v1::DeploymentPlan &plan);
```

Verifies the required provider-aware plan content-hash claim through the
deployment-plan identity authority, compiles the complete provider topology,
reads the explicit snapshot under the runtime-artifact bound, rejects unknown
protobuf fields, requires exact two-directional equality with the plan's module
set, verifies caller hash claims, and returns the canonical normalized snapshot
plus its raw 32-byte validation hash. It never synthesizes a default.

#### `verify_runtime_bundle`

```cpp
[[nodiscard]] kinetum::common::status_or<verified_runtime_bundle>
verify_runtime_bundle(const std::string &bundle_root);
```

Runs Section 17's admission and returns canonical absolute root/plan/snapshot
paths, owned verified messages, sorted module images, the bootstrap validation
hash, and the sole compiled provider topology. Plan form/hash and snapshot
module order/hash claims are validated. DP moves that topology into its runtime
and passes the same object to Quark and materialization. Keep the verified tree
immutable while using its paths.

The two canonical relative paths are shared constants:

```cpp
RUNTIME_PLAN_RELATIVE_PATH = "configs/plan.pbtxt"
BOOTSTRAP_SNAPSHOT_RELATIVE_PATH = "configs/config_snapshot.pbtxt"
```

No consumer invents alternate paths or searches for a semantically similar
artifact elsewhere in the bundle.

**Low-level manifest API.** The following functions retain the manifest-only
surface for producer, audit, and non-runnable tooling. A runnable DP always
uses the high-level bundle authority.

#### `generate_manifest_text`

```cpp
[[nodiscard]] kinetum::common::status_or<std::string>
generate_manifest_text(const std::string &bundle_dir);
```

Walks `bundle_dir` recursively (`fs::recursive_directory_iterator`),
hashes every regular file (skipping `BUNDLE_MANIFEST.txt`), sorts
entries lexicographically by relative path, sets `bundle_name` to
`fs::path(bundle_dir).filename()` and `bundle_version` to
`kinetum::common::KINETUM_VERSION_STRING`, and emits through the sole
validating `bundle_manifest::to_text` serializer. The directory basename is
validated before scanning, and exact file-count and serialized-byte extents
are accumulated during the walk.

| Return | Trigger |
|---|---|
| `OK` with text | Success. |
| `NOT_FOUND` | `bundle_dir` does not exist, or an enumerated file is unavailable before hashing. |
| `INVALID_ARGUMENT` | `bundle_dir` exists but is not a directory. |
| `INVALID_ARGUMENT` | The bundle basename is not a canonical bundle name. |
| `INVALID_ARGUMENT` | A bundle file has a relative path that cannot be represented in the manifest grammar. |
| `RESOURCE_EXHAUSTED` | File count or canonical serialized bytes exceed the manifest ceiling. |
| `INTERNAL_ERROR` | Filesystem iteration failure, read failure while hashing, or hash finalization failure. |

The bundle directory must remain immutable throughout generation. A file that
was enumerated but cannot be opened or completely hashed makes the whole
operation fail; it is never omitted from a smaller successful manifest.
`generate_manifest_text` uses the byte count observed by the same stream that
produced the hash, so each completed entry is internally consistent. The
packer's mandatory self-verification independently rereads the completed tree
before publication.

Each file hash goes through `sha256_file_hex_and_size`, which opens
the file once, streams it in fixed-size chunks rather than slurping
the entire file into memory, and returns both the hash and the number
of bytes read from that same stream.

The low-level directory iterator is not a path-provenance authority: its
regular-file query can follow a symlink. High-level runtime-bundle admission
first rejects symlinks anywhere in the supplied path or tree and is mandatory
for deployment. The packer creates a fresh tree from admitted regular sources
and self-gates that tree through the high-level verifier.

#### `verify_manifest`

```cpp
[[nodiscard]] kinetum::common::status
verify_manifest(const std::string &bundle_dir,
                const std::string &manifest_text);
```

Parses `manifest_text` via `bundle_manifest::from_text`, then for
each declared file: opens it, reads its content, computes SHA-256,
and compares. After all entries verify, scans the bundle for extra
files. Fail-fast on the first error.

| Return | Trigger |
|---|---|
| `OK` | All declared files verify and no extra files found. |
| `INVALID_ARGUMENT` | Manifest parse failure. |
| `NOT_FOUND` | A declared file does not exist on disk. |
| `FAILED_PRECONDITION` | Foreign product version, hash mismatch, size mismatch, or extra files detected. |
| `INTERNAL_ERROR` | Filesystem error during verification. |

See Section 17 for the low-level algorithm and its place inside the high-level
runtime-bundle gate.

#### `bundle_manifest::to_text` and `from_text`

```cpp
struct bundle_manifest {
    std::string bundle_name;
    std::string bundle_version;
    std::vector<bundle_file_entry> files;

    kinetum::common::status_or<std::string> to_text() const;

    static kinetum::common::status_or<bundle_manifest>
        from_text(const std::string &txt);
};
```

The round-trip is byte-exact. `from_text` accepts only canonical text;
`to_text` validates complete structured state, uses locale-independent decimal
serialization, emits one representation, and submits that representation to
`from_text` before returning it. Missing metadata, invalid structured state,
and a foreign product version produce status rather than output.

`bundle_file_entry::operator<=>` orders entries by `rel_path` only;
`operator==` compares all fields. Sort order is deterministic by
path, and full equality still catches size/hash differences.

#### When to link the library vs shell out

Call the high-level library when:

- You need the failure reason and detail strings programmatically
  (the binary's banner format is for humans).
- You are integrating into a long-running tool that needs structured status
  and canonical artifact ownership for many bundles.
- You need canonical verified plan/snapshot paths and owned messages before
  creating process or deployment side effects.

Call the low-level manifest API only when the manifest itself is the object of
the tool (for example, displaying per-file sizes or generating an inventory).
It does not prove that a bundle is runnable.

Shell out to the binary when:

- Your tool is in a different language and the binary's exit code
  is the only signal you need.
- You are running verification interactively or in a one-shot CI
  step.

---

## Part 6: Verification Semantics

### 17. The Verification Algorithm

`verify_runtime_bundle` is the one runnable-bundle algorithm. It first rejects
path indirection and unsupported filesystem objects, then requires and parses
the manifest, requires both canonical config artifacts, and calls
`verify_manifest` for complete declared-file and extra-file integrity. It then
re-reads each canonical artifact, checks its bytes against the already parsed
manifest entry, strictly parses the exact bytes, verifies the plan identity,
including every typed provider configuration, compiles the complete provider
topology, and canonicalizes the complete snapshot against that plan. Compiler
failure rejects before snapshot parsing and before any process or native
provider side effect.

The second read/hash of `configs/plan.pbtxt` and
`configs/config_snapshot.pbtxt` narrows the interval between integrity checking
and semantic parsing. Concurrent bundle mutation is unsupported; a mismatch
fails admission rather than parsing bytes that are no longer the ones admitted
by the manifest.

The rest of this section describes the low-level `verify_manifest` step that
the high-level algorithm composes.

#### Step 1: Parse

Call `bundle_manifest::from_text(manifest_text)`. Any parse error
returns immediately. Malformed or noncanonical bytes are `INVALID_ARGUMENT`;
a well-formed foreign product version is `FAILED_PRECONDITION`.

#### Step 2: Per-file hash check (loop over manifest entries)

For each `bundle_file_entry` in declared order:

1. Construct `bundle_dir / entry.rel_path`.
2. Call `kinetum::common::sha256_file_hex_and_size(path)`. This opens
   the file once and hashes it in fixed-size chunks using the
   incremental hasher. Verification memory use is therefore bounded by
   the hash buffer and OpenSSL context, not by the largest file in the
   bundle.
3. If `sha256_file_hex_and_size` returns an error:
   - `NOT_FOUND` -> return `NOT_FOUND` with `"missing file in
     bundle (declared in manifest but not found on disk)"` and the
     `rel_path` as detail.
   - Anything else -> return `INTERNAL_ERROR` with the underlying
     error message.
4. Compare the computed hash to `entry.sha256_hex`. Mismatch
   returns `FAILED_PRECONDITION` with `"SHA-256 hash mismatch for
   file (expected <X>, got <Y>)"` and the `rel_path` as detail.
5. Compare the byte count observed by the same read to
   `entry.size_bytes`. Mismatch returns `FAILED_PRECONDITION` with
   `"size mismatch for file (expected <N> bytes, got <M> bytes)"`.
   The hash check runs first so corrupted content reports as a hash
   mismatch even when the byte count is also wrong.

#### Hash provider

OpenSSL::Crypto is an unconditional build dependency because SHA-256 content
identity is a platform mechanism, not a TLS capability. Every build uses the
same cryptographic implementation; there is no FNV substitute, insecure
override, capability probe, or build-dependent digest meaning. Disabling
`KINETUM_ENABLE_TLS` disables TLS helpers and OpenSSL::SSL linkage only; it does
not remove OpenSSL::Crypto or change bundle hashes.

#### Step 3: Extra-file scan

After every manifest entry verifies, `reject_extra_files` walks the bundle
directory recursively and returns on the first regular file whose `rel_path`
is absent from the manifest's declared set (`MANIFEST_FILENAME` is excluded).

That contradiction returns `FAILED_PRECONDITION` with the message `"bundle
contains extra file not declared in manifest"` and the path in status details.

Runtime-bundle admission additionally derives the complete allowable directory
prefix set from those manifest paths. A symlink, special file, undeclared file,
or undeclared directory therefore rejects at its first tree entry; empty
directory forests cannot turn startup validation into unbounded work.

(The `kinetum_bundle_verify` binary surfaces this as the INTEGRITY
ALERT block described in Section 12; custom callers of
`verify_manifest` get the same string in the returned status.)

#### Single-open hashing

`sha256_file_hex_and_size` hashes and counts bytes from one open stream, tying
size and digest to the same read. It does not make path admission and later use
atomic or permit concurrent bundle mutation. Deletion before open returns
`NOT_FOUND`. Verification stops at the first declared-file error.

#### What the low-level manifest primitive does not verify

- **Symlink provenance.** A low-level regular-file query can follow a link;
  the text format does not encode that distinction. The mandatory high-level
  runtime-bundle gate rejects a symlink in the supplied root, any path
  component, or any tree entry before reading runtime artifacts.
- **Directory metadata** (mtime, permissions, ownership) is not
  checked.
- **Empty directories** are not checked (only files appear in the
  manifest).
- **The manifest itself** is not verified by an in-format digest; it is read as plaintext.
  Tamper-evidence depends on the operator pinning the manifest hash
  externally (e.g., publishing the manifest's own SHA-256 in an
  immutable record).

---

## Part 7: Integration with Other Components

### 18. DP Startup Verification

Runtime-bundle admission is repeated at two process boundaries through one
high-level authority:

1. After signal and logging setup, Photon calls `verify_runtime_bundle` before
   spawning children. It retains the canonical root and exact snapshot/plan
   identities and passes the root to DP as `--bundle`.
2. DP independently calls `verify_runtime_bundle` before host proof, provider
   admission, materialization, or gRPC publication. It moves the verifier's
   sole compiled topology into the runtime generation and passes that same
   object to Quark and the materializer.

DP has no direct-plan or alternate bundle-root flag, plan-parent inference, optional manifest
check, or missing-manifest skip. The complete manifest, canonical plan and
bootstrap paths, exact provider-aware plan identity, module-image set, snapshot
identity, and compiled provider topology are all mandatory. A loose build-tree
image also fails the separate fixed installed-provider-root admission; neither
boundary can substitute for the other.

After bundle admission, DP separately authenticates the installed provider set
and constructs the complete runtime before `CONTROL_READY`.
[Provider admission](PROVIDERS.md#9-installed-component-admission) owns the
fixed-root, signature, component, and host-proof checks; the bundle does not
authorize provider code.

#### What this gives you

The layered production admission closes the storage-and-transport gap:

- CI builds the bundle and produces a manifest.
- CI runs `kinetum_bundle_verify` and posts the result to
  artifact metadata.
- The artifact moves through registry, storage, and onto the
  production node.
- Photon re-reads the manifest, verifies every file, and semantically admits the
  plan and bootstrap snapshot before child construction.
- DP independently repeats complete bundle admission, consumes the sole
  compiled topology, then authenticates and admits its fixed installed-provider
  closure before materialization and control readiness.

Neither verifier protects against an unauthorized writer that
can rewrite the bundle and regenerate the manifest in place. That
case requires manifest signing (Section 21).

Visual reference:
[`diagrams/platform_architecture.md` Section 11 (Data-Plane Host)](diagrams/platform_architecture.md#11-data-plane-host).

### 19. CI/CD and Audit Workflows

The bundle format is designed to slot into a few common patterns.

#### Pattern: build-time bundle production

```sh
# In your CI build job, after `cmake --build`:
mkdir -p build/pack_modules
mkdir -p artifacts
cp build/src/modules/acl/libkinetum_acl.so build/pack_modules/
cp build/src/modules/nat44/libkinetum_nat44.so build/pack_modules/
cp build/src/modules/qos/libkinetum_qos.so build/pack_modules/

build/kinetum_pack \
  --axiom "${PIPELINE_PBTXT}" \
  --hw "${HARDWARE_PBTXT}" \
  --bindings "${BINDINGS_PBTXT}" \
  --modules-dir build/pack_modules \
  --bootstrap-snapshot "${SNAPSHOT_PBTXT}" \
  --regions 3 \
  --out artifacts/bundle

# Re-verify after the packaging/storage handoff. The packer already self-gated.
build/kinetum_bundle_verify --bundle artifacts/bundle

# Compute and pin the manifest hash externally for tamper-evidence.
sha256sum artifacts/bundle/BUNDLE_MANIFEST.txt > artifacts/bundle.manifest.sha256
```

The bundle deliberately contains no platform executables. Install the runtime
package on every target host and transport this bundle as a separate
deployment artifact.

The external digest becomes a tamper-evidence anchor only when it is published
through a separately authenticated, immutable channel. Deployment can then
re-check both the manifest's digest and the content named by the manifest.

#### Pattern: audited config-only rollout

`kinetumctl set-config` can push any standalone
`ConfigSnapshot` pbtxt that matches the running plan and module set.
That live apply creates a snapshot in CP state, but it does not update
any bundle's `BUNDLE_MANIFEST.txt`. The bundle-layer integrity
guarantee covers only the bytes that were present when
`kinetum_pack` generated the manifest.

For production audit hygiene, treat every approved config as a bundle
artifact even when the update is config-only:

```sh
mkdir -p artifacts
kinetum_pack \
  --axiom "${PIPELINE_PBTXT}" \
  --hw "${HARDWARE_PBTXT}" \
  --bindings "${BINDINGS_PBTXT}" \
  --modules-dir /opt/kinetum/lib/modules \
  --bootstrap-snapshot "${APPROVED_CONFIG_SNAPSHOT}" \
  --regions 3 \
  --out artifacts/config_rollout_v2

kinetum_bundle_verify --bundle artifacts/config_rollout_v2

kinetumctl --endpoint "${CP_ENDPOINT}" \
  set-config artifacts/config_rollout_v2/configs/config_snapshot.pbtxt \
  --confirm-timeout 300000
```

The bundle provides audit identity and byte integrity for the snapshot that
was approved. The command above drives the passive ordered transition and
returns only after exact DP COMPLETE. Use `--confirm-timeout` only after a
baseline snapshot is already active, because commit-confirmed needs that
previous snapshot as its rollback target. If an operator applies a loose pbtxt
directly, the snapshot's identity exists only in CP's config store and
operator logs, not in a verified bundle manifest.

#### Pattern: pre-deployment verification

```sh
# At the deployment-orchestration layer, before launching DP:
if ! kinetum_bundle_verify --bundle /var/lib/kinetum/bundles/fan_in_edge_v1; then
  echo "Bundle integrity check failed - aborting deployment"
  exit 1
fi

# Optional: re-check the manifest's pinned external hash.
EXPECTED=$(awk '{print $1}' /etc/kinetum/fan_in_edge_v1.manifest.sha256)
ACTUAL=$(sha256sum /var/lib/kinetum/bundles/fan_in_edge_v1/BUNDLE_MANIFEST.txt | awk '{print $1}')
if [ "${EXPECTED}" != "${ACTUAL}" ]; then
  echo "Manifest hash mismatch (tamper signal) - aborting deployment"
  exit 1
fi

# Then launch Photon, which repeats complete semantic admission before spawn.
exec /opt/kinetum/bin/kinetum_photon \
  --bundle /var/lib/kinetum/bundles/fan_in_edge_v1
```

The producer self-gate, optional handoff check, external manifest-hash pin, and
Photon startup gate are intentionally layered. The two semantic gates consume
one implementation; the external pin adds authenticity context the unsigned
manifest itself cannot provide.

#### Pattern: audit / forensic

For an unknown bundle landing on disk:

```sh
# Was this bundle correctly produced?
kinetum_bundle_verify --bundle <path>

# What does the manifest claim?
cat <path>/BUNDLE_MANIFEST.txt | head -2  # bundle_name, bundle_version
wc -l <path>/BUNDLE_MANIFEST.txt          # rough file count

# Are there any modules?
cat <path>/modules/modules.json 2>/dev/null
ls <path>/modules/*.so 2>/dev/null

# Confirm the deployment artifact did not absorb runtime ownership.
test ! -e <path>/bin && test ! -L <path>/bin
```

`bundle_version` is the code-facing version constant built from the producer's
build-time `KINETUM_VERSION_STR`. Verification requires exact equality with the
consumer's product version; absence never means the consumer's own version.
`modules.json` tells you which modules the pipeline expected. Any
top-level `bin/` entry is a format violation and the high-level verifier rejects
it even if an external producer lists its contents in the manifest.

### 20. Reproducibility Guarantees and Limits

Bundle reproducibility depends on both format guarantees and producer inputs:

#### What is deterministic

- **Manifest entry order.** `generate_manifest_text` sorts file
  entries lexicographically by `rel_path` before serialization. Two
  runs of `kinetum_pack` over identical input directories produce
  identical entry order in the manifest text.
- **Manifest text format.** ASCII text, LF line endings, fixed
  metadata positions, shortest-form decimal sizes, lowercase hashes, strictly
  increasing paths, and fixed field separators. No trimming, defaulting,
  platform-dependent quoting, locale-dependent number text, or JSON ordering
  ambiguity exists.
- **SHA-256 hashes.** SHA-256 is deterministic; the same file bytes
  produce the same hash on every run, on every architecture.
- **The verifier's behavior.** `verify_runtime_bundle` consumes an immutable
  directory tree and produces the same canonical artifacts or error for the
  same bytes and paths.
- **The normalized bootstrap snapshot.** Set-like modules and labels are
  canonicalized and supplied hash claims are normalized. Re-normalizing the
  verifier's accepted snapshot is byte-stable.
- **The provider-aware plan identity.** Every exact provider `Any` is
  role-checked and canonically repacked, facility-reference sets are normalized
  under their declared set semantics, final plan arrays retain contractual
  order, and deterministic serialization defines one content hash for one
  canonical plan.

#### What is not deterministic out of the box

- **Plan timing metadata.** Gluon writes `planned_unix_ms` and
  `planning_duration_ms` into `configs/plan.pbtxt`. They are excluded from the
  semantic plan hash but remain file bytes covered by the bundle manifest, so
  repeated pack runs can produce different manifests for the same deployment.
- **Module shared objects.** Reproducible builds are a module build-system
  concern, not a pack concern. If your
  module's build embeds a timestamp or non-deterministic symbol
  order, two pack runs produce different `.so` files even from
  identical source.
- **`bundle_version` (the `kinetum::common::KINETUM_VERSION_STRING` value).** The
  owning top-level CMake target injects its backing macro from the exact root
  `VERSION`. Both the C++ header and C release marker reject an absent
  definition; manifest parsing rejects a different product version, and package
  verification checks every ELF marker against that source value.
- **`bundle_name`.** Derived from the basename of `--out`. If you
  pass `--out /tmp/build_42`, the bundle name is `build_42`.
  The basename must satisfy the canonical 1-255-byte grammar. Moving the
  completed directory does not rewrite the retained name.
- **Filesystem timestamps and permissions.** Not in the manifest,
  not in the bundle's own format. They reflect whatever the
  underlying filesystem produced during the pack run.
- **Caller formatting of `config_snapshot.pbtxt`.** The explicit snapshot is
  semantic input, but pack writes the canonical normalized protobuf message.
  Whitespace and incidental module/map construction order from the caller are
  not retained.

#### Pinning strategy

If end-to-end reproducibility matters (security-critical
deployments, regulatory compliance, forensic baselines):

- Pin the manifest hash in an external, immutable store, as in
  Section 19's pre-deployment pattern.
- Treat the manifest as the bundle's identity. Two bundles with
  the same manifest hash are the same bundle; two with different
  manifest hashes are different bundles, regardless of how they
  came to be different.

If deterministic drift detection matters but producer authenticity does not,
the manifest's lexicographic sort and SHA-256 hashing are sufficient to detect
different bytes across builds.

---

## Part 8: Cross-Cutting

### 21. Bundle Integrity Boundary

Three categories of content that bundles deliberately exclude.

#### Secrets

The bundle format has no provision for encrypted content, no key
derivation, no secret-store integration. Secrets that the pipeline
or modules need at runtime should be supplied **outside** the bundle:

- TLS keys and certificates: read from the local filesystem with
  paths supplied via runtime flags (e.g., `kinetumctl --tls-cert
  /etc/kinetum/client.pem`). See [`KINETUMCTL.md`](KINETUMCTL.md).
- API tokens, credentials, and license keys: supply them through the
  separately owned secret-management path of the component that consumes
  them.
- Anything you would not want appearing in a checksum log or a CI
  artifact viewer.

The producer-side documentation (`README_BUNDLE.md`) explicitly warns
against bundling files like `.env` or `credentials.json`. The
warning is advisory; the pack does not actively scan for secret-like
files, so producer-side hygiene is your responsibility.

#### Bundle-manifest signing

`BUNDLE_MANIFEST.txt` is unsigned. SHA-256 detects changes to listed bytes, but
does not authenticate a producer who can replace both the files and manifest.

The deployment channel must authenticate the bundle producer. An external
manifest-hash pin (Section 19) is one way to bind the exact manifest through
that trusted channel and re-check it at deployment time. Bundle signing,
key rotation, freshness, and provenance are not authorities in the current
bundle format or verifier.

The [installed provider signature](PROVIDERS.md#9-installed-component-admission)
authenticates the runtime image and provider closure through a trusted verifier.
It does not sign deployment bundles or authenticate runtime-archive delivery.

#### Compression and archiving

For single-file transport, archive the bundle externally; `kinetum_pack`
produces no `.tar.gz`, `.zip`, or other archive:

```sh
tar -C /var/lib/kinetum/bundles -czf fan_in_edge_v1.tar.gz fan_in_edge_v1
sha256sum fan_in_edge_v1.tar.gz > fan_in_edge_v1.tar.gz.sha256
```

The archive's hash is independent of the manifest's hash; both can
be pinned. Verification still happens against the unpacked bundle,
so the deployment script must extract before invoking
`kinetum_bundle_verify` or Photon.

### 22. Capability Boundaries

This inventory separates bundle mechanisms from properties outside the bundle
contract. It also records generated metadata that Kinetum runtime tools do not
consume, so operators do not infer authority from presence alone.

| Feature | Current status | Source / owner | Release implication |
|---|---|---|---|
| Installed-provider provenance | **Separate runtime contract.** DP and `kinetum-info --check` authenticate the installed provider closure. A bundle neither contains nor authorizes that code. | `src/provider/provider_inventory.cpp`; `tooling/release/verification/runtime_verification.cpp` | The provider signature does not sign a bundle or authenticate archive delivery. See Section 21 and [runtime package preparation](GETTING_STARTED.md#build-packages-from-source). |
| Bundle-manifest authenticity | **Outside the bundle contract.** `BUNDLE_MANIFEST.txt` is unsigned and the verifier establishes content integrity and semantic admission, not producer identity. | `src/pack/bundle_manifest.hpp`; `src/pack/kinetum_bundle_verify_main.cpp`; `kinetum_pack_main.cpp` `write_bundle_readme` function | Authenticate delivery through the deployment channel; an externally published manifest digest may bind exact bytes but does not create an in-format signing authority. |
| Build provenance attestation | **Outside the bundle contract.** The format carries no provenance statement and the verifier evaluates none. | `src/pack/runtime_bundle.cpp`; `src/pack/kinetum_bundle_verify_main.cpp` | Establish build provenance independently through the trusted release/build channel. Bundle admission makes no provenance claim. |
| Bundle freshness authority | **Outside the bundle contract.** The format carries no trusted timestamp, expiry, or freshness policy. | `src/pack/bundle_manifest.cpp`; `src/pack/kinetum_bundle_verify_main.cpp` | Enforce age or rollout policy in independently authenticated deployment metadata when required. |
| `modules.json` consumption | **Generated, not read.** Pack writes the file; no tool in `src/` consumes it. | `kinetum_pack_main.cpp` (writer); no consumers | Use it for operator inspection or external CI scripting. Do not depend on runtime tooling reading it. |
| Version injection | **Mandatory.** The top-level CMake authority validates root `VERSION` and privately injects `KINETUM_VERSION_STR` into every owned target. The C++ header and C release marker reject its absence. | `src/common/version.hpp`; `tooling/release/packaging/release_version_marker.c`; top-level `CMakeLists.txt` | A target outside the owning CMake helper is unbuildable. Packaged ELFs must also carry the exact source-version marker. |
| OpenSSL-backed hashing | **Implemented and mandatory in every build.** CMake requires OpenSSL::Crypto independently of the TLS option; no alternate digest implementation exists. | `src/common/sha256.cpp`; top-level `CMakeLists.txt` | A host without OpenSSL development files fails configuration instead of producing a different content-identity mechanism. |
| Parallel hash computation | **Sequential only.** `verify_manifest` walks files in declared order and hashes each in turn. | `src/pack/bundle_manifest.cpp` `verify_manifest` | Verification time is linear in total bundle bytes. |
| Streaming hash computation | **Implemented.** `sha256_file_hex_and_size` hashes files in fixed-size chunks through the incremental hasher and returns the byte count from that same read. | `src/common/sha256.cpp` `sha256_file_hex_and_size`; `bundle_manifest.cpp` `verify_manifest` | Bundle verification is independent of the bounded text-file reader and needs no separate post-hash size query. |
| Mandatory bootstrap snapshot | **Implemented.** Every runnable bundle has an explicit complete snapshot at the canonical path. Pack validates and normalizes it before creating output and never synthesizes a default. | `runtime_bundle.cpp` `load_and_normalize_bootstrap_snapshot`; `kinetum_pack_main.cpp` | Even a module-free passthrough deployment supplies an explicit snapshot. |
| Semantic runtime-bundle admission | **Implemented.** Pack, the standalone verifier, Photon, and DP consume one shared verifier for path, manifest, plan identity, complete provider-topology compilation, and snapshot identity. | `runtime_bundle.cpp` `verify_runtime_bundle` | Passing the low-level manifest check alone does not admit a runnable bundle. |
| Symlink-free deployment bundle | **Implemented.** The supplied root, every existing path component, and every tree entry must be direct filesystem objects; canonical artifacts must be regular files at exact paths. | `runtime_bundle.cpp` `absolute_path_without_symlinks`, `validate_bundle_tree_entries` | Artifact/path indirection fails before semantic parsing or process side effects. |
| Compression / archiving | **Out of scope.** Format does not include this. | `kinetum_pack_main.cpp` Non-Goals section | Use external `tar`/`zip` for transport. |

### 23. Where kinetum_pack and kinetum_bundle_verify Live

Build targets, declared in the top-level `CMakeLists.txt`:

```
add_library(kinetum_provider_topology_compiler STATIC
  src/provider/compiled_provider_topology.cpp
)
target_link_libraries(kinetum_provider_topology_compiler
  PUBLIC kinetum_common kinetum_provider_contracts
  PRIVATE kinetum_axiom_contract
)

add_library(kinetum_deployment_plan_identity STATIC
  src/provider/deployment_plan_identity.cpp
)
target_link_libraries(kinetum_deployment_plan_identity
  PUBLIC kinetum_provider_contracts
  PRIVATE kinetum_common
)

add_library(kinetum_pack_lib STATIC
  src/pack/bundle_manifest.cpp
  src/pack/pack_source_admission.cpp
  src/pack/runtime_bundle.cpp
)
target_include_directories(kinetum_pack_lib PUBLIC src)
target_link_libraries(kinetum_pack_lib
  PUBLIC kinetum_common kinetum_deployment_plan_identity
  PRIVATE kinetum_provider_topology_compiler
)

add_executable(kinetum_pack src/pack/kinetum_pack_main.cpp)
target_link_libraries(kinetum_pack
  PRIVATE kinetum_pack_lib kinetum_axiom_lib kinetum_gluon_lib)

add_executable(kinetum_bundle_verify src/pack/kinetum_bundle_verify_main.cpp)
target_link_libraries(kinetum_bundle_verify PRIVATE kinetum_pack_lib)

add_executable(kinetum_photon src/photon/photon_main.cpp)
target_link_libraries(kinetum_photon PRIVATE kinetum_photon_lib kinetum_pack_lib)
```

The pack library depends publicly on `kinetum_common` and the cold
`kinetum_deployment_plan_identity` composition authority, and privately on the
provider-topology compiler used by runtime-bundle admission. Both provider
targets consume the pure contract catalog and no provider-native
implementation. Full Gluon planner linkage belongs to the producer executable
because only `kinetum_pack` invokes lowering. Verification-only consumers do
not drag Gluon into their link graph. DP and Photon both link the pack library
for independent high-level runtime-bundle admission.

#### Source layout

```
src/pack/
  bundle_manifest.hpp              source-tree library API + structs + constants
  bundle_manifest.cpp              generate + verify + parse
  pack_source_admission.hpp        transactional source-path contract
  pack_source_admission.cpp        canonical source admission
  runtime_bundle.hpp               semantic runtime-bundle API
  runtime_bundle.cpp               path + plan + snapshot admission
  kinetum_pack_main.cpp            the producer binary
  kinetum_bundle_verify_main.cpp   the verifier binary
```

The two `*_main.cpp` files are TU-private; their `namespace { }` blocks
contain the per-binary helpers (`usage`, required module-copy handling,
`write_bundle_readme`, etc.).

#### Installed bundle tools

The runtime package installs `kinetum_pack` and `kinetum_bundle_verify` under
`<prefix>/bin/` (normally `/opt/kinetum/bin/`). Deployment bundles contain
neither executable. The private `kinetum_pack_lib` remains a source-tree
library and is not an installed SDK API.

See [Install Kinetum](GETTING_STARTED.md#5-install-kinetum) for obtaining these
tools and [Build Packages from Source](GETTING_STARTED.md#build-packages-from-source)
for producing runtime and SDK archives.

### 24. Where to Go Next

| If you want to... | Read |
| --- | --- |
| Author the pipeline pbtxt that pack consumes | [`AXIOM.md`](AXIOM.md) |
| Author the hardware inventory pbtxt | [`GLUON.md`](GLUON.md) |
| Understand the planner that pack invokes | [`GLUON.md`](GLUON.md) |
| Build a module whose `.so` ends up in the bundle | [`MODULE_SDK.md`](MODULE_SDK.md) |
| Operate a deployed bundle from the command line | [`KINETUMCTL.md`](KINETUMCTL.md) |
| Understand the wire contract that backs operator commands | [`GRPC_API.md`](GRPC_API.md) |
| Understand DP startup and where verification fits | [`DATA_PLANE.md`](DATA_PLANE.md) |
| See the DP host process visually | [`diagrams/platform_architecture.md` Section 11 (Data-Plane Host)](diagrams/platform_architecture.md#11-data-plane-host) |
| Understand the supervisor that may launch DP after pack | [`PHOTON.md`](PHOTON.md) |
| Understand the control plane the bundle's snapshot pbtxt feeds | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| Build and install runtime or SDK packages | [Getting Started](GETTING_STARTED.md#build-packages-from-source) |
| Run the platform end-to-end | [`GETTING_STARTED.md`](GETTING_STARTED.md) |
| Read the architectural overview | [`CONCEPTS.md`](CONCEPTS.md) |
