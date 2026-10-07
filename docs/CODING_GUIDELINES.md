# Coding Guidelines

**Version:** 0.1.0

## Table of Contents

1. [Naming Conventions](#1-naming-conventions)
2. [Comment Style](#2-comment-style)
3. [File Structure](#3-file-structure)
4. [Formatting](#4-formatting)
5. [Language Usage](#5-language-usage)
6. [Hot Path Rules](#6-hot-path-rules)
7. [Error Handling](#7-error-handling)
8. [Testing](#8-testing)

---

## 1. Naming Conventions

### 1.1 General Rule

All identifiers use `snake_case` unless specified otherwise below.

| Element | Convention | Example |
|---------|-----------|---------|
| Variables (local, member, global) | `snake_case` | `packet_count`, `burst_size` |
| Member variables (private) | `snake_case` with trailing underscore | `state_`, `plan_`, `cores_` |
| Functions and methods | `snake_case` | `probe_host()`, `maybe_pin_worker_()` |
| Classes and structs | `snake_case` | `partitioned_runtime`, `host_topology` |
| Enum class names | `snake_case` | `provider_role`, `log_level` |
| Enum values | `UPPER_CASE` | `IO_DRIVER`, `STORAGE_DOMAIN`, `RUNNING` |
| Namespaces | `snake_case` | `kinetum::quark`, `kinetum::dp` |
| File names | `snake_case` | `runtime_compat.hpp`, `dp_main.cpp` |
| Constants (`constexpr`, `const`) | `UPPER_CASE` | `DEFAULT_TIMEOUT`, `MAX_BATCH_SIZE` |
| Macros | `UPPER_CASE` with prefix | `KINETUM_LOG_ERROR`, `KINETUM_UNLIKELY` |
| Template parameters | `snake_case` | `template <typename value_type>` |

### 1.2 Framework-Mandated Exceptions

External frameworks mandate their own naming conventions. When calling or overriding
framework APIs, use the framework's convention. Do not wrap or rename.

| Framework | Convention | Example | Where |
|-----------|-----------|---------|-------|
| LLVM/MLIR | camelCase methods | `runOnOperation()`, `getAttrOfType()` | `src/axiom/mlir/` |
| Google Test | PascalCase test fixtures | `TEST_F(CpStatsForwardingTest, ...)` | `tests/` |
| Protobuf generated | Generated field accessors (`snake_case` in C++) | `plan.regions_size()`, `region.cpu_core_ids()` | Generated code in the build tree |
| gRPC generated | PascalCase service classes | `ControlService::Service` | Generated code in `gen/` |
| DPDK | snake_case with `rte_` prefix | `rte_eal_init()`, `rte_mbuf` | `src/dp/backends/dpdk/` |

Rule: framework-mandated identifiers are used as-is at the call site. Internal code
wrapping or extending framework types must follow our `snake_case` convention.

---

## 2. Comment Style

### 2.1 Three Comment Syntaxes

| Syntax | Purpose | Parsed by Doxygen |
|--------|---------|-------------------|
| `//` | All code comments (inline, multi-line explanations) | No |
| `/** */` | Documentation blocks (file, class, function, struct) | Yes |
| `///<` | Trailing documentation on members and enum values | Yes |

### 2.2 Code Comments (`//`)

Use `//` for all non-documentation comments. For multi-line explanations inside
function bodies, use consecutive `//` lines:

```cpp
// Walk the complete kernel-accepted CPU set. Begin with the libc extent and
// grow only when sched_getaffinity reports EINVAL, so sparse/high identities
// are not truncated by fixed cpu_set_t storage or a configured-count guess.
for (std::size_t i = 0; i < scan_count; ++i) {
```

Do not use `/* */` for code comments.

Line comments avoid the nested-comment hazard created when a block containing
`/* */` is temporarily disabled during local debugging. Do not commit disabled
code; remove it before review.

### 2.3 Documentation Blocks (`/** */`)

Use `/** */` for all Doxygen-parsed documentation: file headers, classes, structs,
functions, and methods.

```cpp
/**
 * @brief Validate compiled CPU and host-memory requirements against the host.
 *
 * Checks compiled worker/service cores and QUARK_LIVE_HOST memory requirements
 * against probe_host(). Unavailable resources, unknown required NUMA ownership,
 * or placement mismatch fail; the validator never filters or repairs topology.
 *
 * @param topology Sole compiled semantic artifact for the deployment.
 * @param host Host topology from probe_host().
 * @return Compatibility decision and bounded diagnostics.
 */
compat_report validate_runtime_compat(
    const kinetum::provider::compiled_provider_topology& topology,
    const host_topology& host);
```

Document an out-of-line function's purpose, parameters, return, ownership,
concurrency, and performance constraints once, at its header declaration.
Repeating that Doxygen contract above the `.cpp` definition creates a second
copy that can drift.

Types and helpers declared only in `.cpp` files still require declaration
Doxygen. Put implementation reasoning in `//` comments beside the relevant code.

### 2.4 Python Docstrings

Every authored Python module starts with a concise module docstring. Every
class, exception, public or private function, method, property, and nested
callable has a docstring unless it is a framework-mandated one-line protocol
method whose inherited contract is exact and obvious. Tests follow the same
rule; a test method's docstring states the behavior proved, not the mechanics of
the assertions.

Use imperative, contract-oriented prose:

```python
def validate_manifest(path: pathlib.Path) -> Manifest:
    """Return one exact manifest or raise on malformed or indirect input."""
```

For a nontrivial callable, document parameters, return value, raised
exceptions, ownership transfer, side effects, cancellation, concurrency, and
bounds that a caller must know. Do not copy type annotations into prose. A
module or class docstring owns shared context once; individual methods document
only their distinct contract.

Generated Python and third-party code are excluded. The complete owned Python
tree is checked for missing declarations rather than only changed files.

### 2.5 Trailing Member Documentation (`///<`)

Use `///<` for short, single-line documentation on struct/class members and
enum values:

```cpp
enum class log_level {
  DEBUG = 1,  ///< Cold detail, emitted only when the selected filter admits it.
  INFO = 2,   ///< Informational record.
  WARN = 3,   ///< Warning record.
  ERROR = 4,  ///< Error record.
  FATAL = 5,  ///< Critical diagnostic; the caller owns the terminal action.
};

struct host_topology {
  std::vector<host_cpu> cpus;  ///< Sorted CPU IDs with exact/unknown NUMA ownership.
  std::vector<int32_t> memory_numa_nodes;  ///< Sorted nodes with available memory.
  int32_t online_count{0};  ///< Number of system-online CPUs.
  bool valid{false};  ///< Whether topology discovery succeeded.
};
```

For members requiring longer documentation, use a `/** */` block before the member:

```cpp
/**
 * Maximum slab entries to scan per GC cycle.
 * Bounds the work done per GC invocation to prevent
 * latency spikes on the hot path.
 */
uint32_t max_gc_scan{1024};
```

### 2.6 What to Comment

Comment quality rules:

- **Do not** say in comments what can be clearly stated in code.
- **Do** state intent - explain the *why*, not the *what*.
- **Keep** comments crisp. No filler, no redundancy.

---

## 3. File Structure

### 3.1 Header Files (`.hpp`)

```cpp
// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file filename.hpp
 * @brief Single-line purpose statement.
 * @author Fleming Patel
 *
 * Detailed description (1-3 paragraphs):
 * - Architecture overview
 * - Key design decisions
 * - Usage patterns
 *
 * @par Thread Safety
 * Thread safety guarantees (if applicable).
 */

#include <standard_library>
#include "project/includes"

namespace kinetum::subsystem {

// declarations

}  // namespace kinetum::subsystem
```

Each header owns one responsibility and the narrowest dependencies its callers
need. Separate protocol types, synchronization/storage mechanisms, lifecycle
stores, and orchestration when ownership or performance contracts differ.
Hot-path callers must not acquire cold policy through convenience headers.
Umbrella headers may collect stable public utilities; production callers should
prefer the owning header.

### 3.2 Source Files (`.cpp`)

```cpp
// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file filename.cpp
 * @brief Single-line purpose statement.
 * @author Fleming Patel
 *
 * Implementation details (if needed beyond header docs).
 */

#include "src/subsystem/filename.hpp"

#include <standard_library>
#include "project/includes"

namespace kinetum::subsystem {

// implementation

}  // namespace kinetum::subsystem
```

### 3.3 File Header Rules

1. **License first.** Lines 1-2 are always copyright + SPDX. Use `//` (not parsed by Doxygen).
2. **`#pragma once`** for all headers. No `#ifndef` include guards.
3. **`@file` block** uses `/** */` (parsed by Doxygen). Placed after `#pragma once` in headers, after license in source files.
4. **`@author Fleming Patel`** in every `@file` block.
5. **Include order:** own header first (in `.cpp`), then standard library, then project includes.

### 3.4 License Declaration Scope

The root `LICENSE` governs every Kinetum-authored file. Compiled-language
sources and protobuf schemas retain their existing copyright and
`SPDX-License-Identifier: Apache-2.0` headers so generated and redistributed
source fragments carry an immediate machine-readable declaration. Python,
shell, CMake, Markdown, JSON, and template files rely on the root license and do
not receive sporadic per-file headers. Third-party files retain their upstream
notices and are never relabeled as Kinetum-authored work.

---

## 4. Formatting

### 4.1 clang-format

The repository uses a `.clang-format` file based on the Linux kernel style with
project-specific adaptations. Apply formatting with:

```bash
clang-format -i <file>
```

### 4.2 Key Formatting Rules

- Indentation: tabs, 8-wide (Linux kernel style)
- Column limit: 120
- Braces: K&R style for control structures, own line for functions
- Namespace indentation: none (namespace body at column 0)
- Pointer alignment: `type *name` (right-aligned, kernel convention)
- No trailing whitespace
- Single blank line between function definitions
- No blank lines after opening brace or before closing brace

### 4.3 Python Lint

Owned Python code must pass Flake8 and Pylint with the repository configurations
before handoff. Fix production findings instead of adding suppressions.

---

## 5. Language Usage

### 5.1 Generated and Third-Party Code

Generated protobuf/gRPC output and third-party headers are not Kinetum-owned
source. Do not edit generated `.pb.*` / `.grpc.pb.*` files, and do not force
them through Kinetum's owned-code `-Werror` policy. CMake targets that expose
generated build-tree include roots must mark those roots as `SYSTEM` includes.

Kinetum-owned wrappers, call sites, and validation around generated types still
follow this guide's naming, Doxygen, fail-closed, and narrowing-conversion
rules.

The platform and public module SDK support GNU/Clang compilation for
little-endian x86-64 and AArch64 only. CMake compile-probes both languages
before creating platform targets, and the public C and C++ headers enforce the
same target wall. Do not add generic-architecture, empty-attribute, no-op
intrinsic, or descriptor-flag fallbacks. Scalar SIMD remains a valid feature
selection within a supported architecture; it is not permission to admit
another target.

### 5.2 Constants

Use `constexpr` for compile-time constants. Use `UPPER_CASE` naming:

```cpp
constexpr int MAX_BATCH_SIZE = 64;
constexpr uint64_t FNV1A_OFFSET_BASIS = 14695981039346656037ULL;
constexpr auto DEFAULT_TIMEOUT = std::chrono::seconds(30);
```

Do not use `#define` for constants. Do not use the `k` prefix (e.g., `kMaxSize`).

### 5.3 Enums

Use `enum class` (scoped enums). Enum class names are `snake_case`.
Enum values are `UPPER_CASE`:

```cpp
enum class provider_role {
  PROCESS_FACILITY,   ///< Process- or device-scoped native environment
  IO_DRIVER,          ///< Packet ingress/egress implementation
  STORAGE_DOMAIN,     ///< Packet record and payload ownership
  EXECUTION_PROVIDER, ///< Stage execution target
};
```

### 5.4 Namespaces

All platform code lives under `kinetum::` with a subsystem qualifier:

| Namespace | Subsystem |
|-----------|-----------|
| `kinetum::quark` | Strict host topology and runtime compatibility validation |
| `kinetum::provider` | Pure provider contracts and component mechanisms |
| `kinetum::dp` | Dataplane runtime |
| `kinetum::gluon` | Execution planner |
| `kinetum::cp` | Control plane |
| `kinetum::algo` | Algorithm primitives |
| `kinetum::photon` | Supervisor |
| `kinetum::axiom` | Pipeline compiler |
| `kinetum::modules` | Built-in modules |
| `kinetum::pack` | Bundle tools |

Do not use `using namespace` in headers. Closing brace comment is required:
`}  // namespace kinetum::quark`

### 5.5 Protobuf Contract Discipline

An owned protobuf field must have a current producer, consumer, validation
rule, and documented meaning. Do not add speculative, declared-but-unapplied,
or write-only fields. Resolved topology facts live in the compiled plan; a live
configuration or CLI must not expose a second mutable copy.

Build facts and platform capabilities are separate release-metadata classes.
Build facts report exact compile choices. A source-declared capability set is
descriptive only: runtime admission, validation gates, and behavior branches
must never consume it in place of plan or live authority.

Command-line parsers accept only documented complete kebab-case long options
and values, plus explicitly declared short options. Disable implicit prefix
abbreviation (including Python `argparse`'s default), reject old spellings, and
normalize once at the CLI-to-internal boundary when stored identities use a
different representation.

For unreleased internal schemas, make one compact breaking change and update all
owned producers, consumers, fixtures, generated-code call sites, and docs in the
same change. Do not retain dual readers, deprecated aliases, reserved
tombstones, or old field numbers without a real external compatibility
obligation. Released compatibility is a separately versioned product decision,
not a default internal-code constraint.

Private durable protobufs live under an explicit `internal/v1` package and are
never presented as an RPC, SDK, module, provider, or package contract. A durable
state transition that changes two identities atomically must be represented by
one deterministically serialized record and one durable replacement; do not
coordinate dependent sidecar renames. Large immutable content belongs in a
create-only canonical corpus referenced by that atomic head. An unreferenced
object left before head publication must remain valid ordinary corpus content,
not startup corruption or data to repair. Exact active/corpus equality may be
deduplicated only at projection; equal semantic identity with different bytes
is data loss.

- Enum value zero is a prefixed `*_UNSPECIFIED` sentinel and fails admission
  when the field is required.
- C++ switches over generated protobuf enums list every declared value plus the
  generated `INT_MIN/MAX_SENTINEL_DO_NOT_USE_` enumerators explicitly. The
  generated sentinels reject; do not add a `default` that would hide a future
  schema value from `-Wswitch` review.
- A capability enum names only mechanisms with a current producer, consumer,
  validator, and documented owner. Future provider kinds or modes are not
  predeclared merely so current consumers can reject them.
- Use proto3 `optional` presence for patchable scalars; do not pair a value with
  a parallel `set_*` boolean.
- Use unsigned wire types for inherently nonnegative capacities, counts, and
  durations, then validate range before narrowing to runtime types.
- Deterministic IDs and hashes are derived from canonical validated content,
  never map iteration order or incidental emission order.
- A provider configuration `Any` uses the complete exact
  `type.googleapis.com/<fully.qualified.Message>` identity. Do not accept a
  suffix, alternate prefix, descriptor-discovered type, alias, or unknown
  pass-through payload. Decode through the immutable contract catalog, reject
  unknown fields on the outer envelope and recursively in the concrete message
  tree plus invalid enum values. Normalize only fields explicitly declared
  set-like, deterministically serialize, and repack before any identity
  consumer sees the bytes.
- Provider-configuration message graphs must never contain protobuf `map`
  fields or a nested `google.protobuf.Any`. The one outer `Any` is a closed
  envelope resolved by the exact contract catalog; nesting another reopens the
  dynamic-schema escape below that gate. Use a repeated entry message instead
  of a map and declare it either set-like (validated unique and canonically
  sorted) or order-contractual. This keeps canonical wire order and concrete
  type identity owned by the contract.
- A new repeated provider field is order-contractual and hash-sensitive by
  default. Making it set-like requires an owning normalizer, duplicate rule,
  descriptor coverage, and construction-order invariance tests in the same
  change.
- Descriptor tests pin compact field numbers and prove removed contract
  surfaces are absent after an in-place schema replacement.
- A retry/reconciliation wire exposes every behavior-driving classification as
  a typed enum. Every handled non-null response carries non-UNSPECIFIED values;
  producer and consumer mappings are exhaustive in both directions, unknown or
  sentinel input fails closed, and diagnostic text never selects an action.
- A producer that originates a durable mutation generates one cryptographic
  bounded idempotency key before its first transport attempt and retains that
  complete request across every ambiguous retry. Time, PID, host identity,
  empty-key fallback, and key regeneration after timeout are forbidden.
- Generated protobuf files remain generated artifacts and are never edited by
  hand.

---

## 6. Hot Path Rules

Per the Platform Engineering Guide:

- No locks on the hot path
- No `shared_ptr` on the hot path
- No `malloc`/`new` on the hot path
- No exceptions on the hot path
- No virtual dispatch or RTTI on the hot path
- No string construction, formatting, or logging on the hot path
- No system calls on the provider-neutral packet path. A provider's pre-resolved
  burst operation may invoke only the system call intrinsic to its admitted I/O
  mechanism; it may not introduce control, discovery, or clock syscalls
- No packet, stage, module, or provider operation reads a clock directly. The
  sole worker-loop owner may refresh one platform monotonic timestamp once per
  turn; all work in that turn consumes that cached value and pre-resolved
  handles supplied by the platform
- One narrow owner-health exception is permitted only after a non-null health
  callback actually returns. Command/source admission and prior return service
  precede the ordinary turn refresh; one already-scheduled callback may run
  immediately after that refresh. The same worker may then take one additional
  platform monotonic sample, at most once in that turn, solely to measure the
  callback
  against its compiled budget and timestamp that context's completed telemetry
  bank. The sample never replaces the turn's cached packet/callback time and is
  absent for null, suppressed, non-due, module-free, and ordinary packet work.
- Supplemental transition timing is permitted only at four real edge classes:
  immediately before a sender CUT-publication batch, after a receiver's
  complete same-turn CUT/data-drain batch, immediately before a receiver
  ACK-publication batch, and after a sender ACK-consumption batch. Each class
  takes one sample for the complete endpoint batch, never one per boundary.
  These samples are observation-only, occur only while that edge advances, and
  are unreachable from ordinary turns, fixed execution, packet operations, and
  provider burst callbacks.
- Use platform primitives (`versioned_rcu_buffer`, `single_writer_snapshot`,
  `quiescence_domain`, `cuckoo_map`, `aligned_atomic`)

The ordinary refresh, post-health sample, and transition-edge sample contracts
do not prove how the monotonic clock API is served on a target tuple. Release
qualification must inspect every generated call path, trace runtime
clock-related system calls, and measure the cost of each authorized class on
every supported tuple. It must also prove that transition samples occur once
per complete edge batch and are unreachable from ordinary fixed, packet, and
provider execution. A tuple with a packet-worker syscall fallback, per-boundary
sampling loop, or unacceptable measured regression fails qualification;
source-level API shape alone is never evidence of vDSO dispatch or zero cost.

Low-cadence owner-worker callbacks such as health and activation remain hot-path
code: lower frequency does not permit allocation, formatting, logging, blocking,
or a system call on a packet-owning thread.

### 6.1 Owner-Local State and Coherent Publication

Mutable packet-worker state is plain only when one worker is its sole writer.
Foreign threads never read it directly. Publish one complete generation-tagged
snapshot with release ordering and consume it with acquire ordering. Keep queue
capacity, physical storage ownership, and logical work credits as separate
types and invariants.

Each correctness-critical fact has one writable authority. A transport or ABI
may echo identity, but the admission boundary validates equality and designates
the runtime owner. Do not cache a second writable epoch, stage, port, storage,
or provider identity.

See PEG P-6 and Pat-7 through Pat-10 for the ownership and publication
rationale.

### 6.2 Cold Construction and Bounded Activation

Parsing, allocation, graph compilation, provider discovery, and module PREPARE
are cold work. Activation consumes already validated immutable state and must
not allocate, block, parse, take a mutex, perform I/O, or expose a recoverable
failure after commit. Context-lifetime and per-epoch containers use their exact
sealed lifecycle resources; no default PMR or heap fallback may appear.

A cold thread never mutates a live worker context. Publish a bounded command or
immutable view to the sole owner worker instead. See PEG P-9, Pat-7, Pat-10,
and Pat-21.

### 6.3 Foreign Calls, Cancellation, and Wait Predicates

Do not hold a platform mutex, queue lock, launch gate, or condition-variable
lock across module, provider, allocator, logger, or other foreign code. Stage
immutable inputs, release the lock, invoke, then reacquire only to validate and
publish. A call spanning time owns one move-only claim or token whose unresolved
destruction terminates.

Cancellation closes new admission but does not erase accepted work. Collect
every accepted result and retire successful post-cancellation state exactly.
An exceeded authored grace fails stop without reclaiming uncertain ownership.

A condition-variable predicate and every update that can satisfy it use one
mutex protocol. Check and publish under that mutex, then notify. An `eventfd`
is wake-only; its counter is never an ownership count. See PEG Pat-21 and
Pat-22.

### 6.4 Layout and Exact ABI Contracts

Hot-path metadata, ring messages, module ABI types, and provider ABI types pin
size, alignment, standard-layout/trivial-copy properties where applicable, and
every field offset. Cache-line writer/reader ownership belongs in the type's
Doxygen. A C ABI uses fixed-width storage and is compiled as both C11 and C++20.

ABI admission requires exact generated identity in both older and newer
directions. Callback presence, padding, descriptor size, or matching major
version never implies compatibility. An intentional layout change updates the
single header, all implementations, layout assertions, rejection fixtures,
SDK docs, and package proofs in one cut. No dual reader or defaulting shim
survives.

### 6.5 Module and Provider Image Closure

Module implementations compile hidden and export only
`kinetum_module_register`; provider components export only
`kinetum_provider_component_query`. Both reject unresolved non-weak imports,
use immediate local loading, and retain exact dependency ownership. Public
module headers live only under `include/kinetum/` and use canonical angle-bracket
includes in-tree and after installation.

Provider-native source, headers, definitions, and libraries remain private to
the owning component and native-test compile domains. Generic core and tests do
not inherit them. Runtime semantics come from the compiled plan, pure contract
catalog, authenticated installed inventory, and sealed materialized rows in
that order; no directory scan, provider macro, or hot-path lookup substitutes
for those authorities.

See PEG Pat-17 through Pat-20 for the image and provider rules, and
[Providers](PROVIDERS.md) for the ABI, component lifecycle, and integration path.

### 6.6 Release and Documentation Projections

Declare shipped target and installed-header membership once in CMake. Build
aggregates, install components, generated path lists, package manifests,
Doxygen input, the website API reference, and verifiers derive from that authority.
Runtime and SDK are public products. Private validation tooling stays outside
the runtime prefix. The source-build `dependencies/` peer is separately owned.

Keep cohesive private workflows together; a helper or operation does not need
its own header/source pair. A header exists for a real cross-translation-unit
consumer or a distinct ownership boundary. SDK consumer tests exercise actual
CMake/pkg-config, compiler, linker, ELF, and loader behavior; a compile-command
parser is not a substitute for those consequences. In-tree SDK staging is a
fast test gate, while independent qualification uses the distributed SDK on a
native host without platform source.

Package preparation consumes an explicit existing configured build; CMake owns
common package admission and staging. It does not configure or compile inside
the package command. Before using compiled projections, require the staged
packager to match the invoking image. CPU flags remain private to owned targets
and never enter installed SDK interfaces. Keep CPU qualification separate from
package integrity; instruction-set changes require generated-code and
performance validation.

Generate package-specific installers from one template. Publish only complete,
verified outputs with exact cleanup ownership; never replace foreign bytes.
Keep runtime and SDK production independent of each other and of the website.
The website owns its page-time assets. Third-party notices follow redistributed
bytes, not incidental build dependencies. See
[PEG Pat-23](PLATFORM_ENGINEERING_GUIDE.md#pat-23-release-projection-ownership)
for the ownership and publication rules, and
[Getting Started](GETTING_STARTED.md#build-packages-from-source) for the workflow.

---

## 7. Error Handling

- Use `kinetum::common::status` and `kinetum::common::status_or<T>` for
  fallible operations. A `status_or<T>` alternative is fixed at construction;
  replace a surrounding owner instead of assigning the result object.
- Construct the stored `T` directly by copying a copyable lvalue, moving a
  non-const rvalue, or using `std::in_place` with its constructor arguments.
  A pointer or view payload retains its own referenced-data lifetime contract;
  storing it in a result does not make that data owned.
- Fixed diagnostics returned from `noexcept` code use explicit
  `static_status_text`; runtime-composed diagnostics are owned strings at a
  cold boundary. `message()` and `details()` return views borrowed from the
  status and must not outlive or cross a mutation of that status.
- Do not use exceptions as library control flow. Cold standard-library
  allocation and container operations may throw; the nearest owning boundary
  maps expected `bad_alloc`/`length_error` classes to status or terminates when
  ownership has crossed an irreversible edge.
- No exception may cross the C module/provider ABI. A catch-all immediately
  outside a foreign callback exists only to enforce that violation as
  terminate-class; it is not recovery or a hot-path alternative to `noexcept`.
- Check return values. Do not ignore `[[nodiscard]]` returns.

---

## 8. Testing

### 8.1 Test File Naming

Test files are named `test_<unit_under_test>.cpp` and placed in `tests/`.

Python tests for environment and release tooling live in `tooling/tests/`.
CMake/CTest registers the C/C++ tests and native SDK consumer fixtures.
Python suites run explicitly through pytest with verbose, path-based selection;
existing `unittest.TestCase` fixtures retain their assertions and subtests.
Package functional tests own their temporary fixtures from a selected completed
build. Validation, benchmark, and private validation packaging tests live
together in `validation/tests/`.

### 8.2 Test Fixture Naming

Google Test fixtures use PascalCase per framework convention:

```cpp
class CpStatsForwardingTest : public ::testing::Test {
 protected:
  void SetUp() override { ... }
};

TEST_F(CpStatsForwardingTest, forwards_aggregate_counters) { ... }
```

Test case names (second argument to `TEST` / `TEST_F`) use `snake_case`.
Attach one concise Doxygen `@brief` immediately above every Google Test
declaration. It states the behavior proved, not the assertion sequence. Test
sources remain internal verification code: neither the website's Sphinx pages
nor its Doxygen API reference includes `tests/`.

### 8.3 Test Constants

Test-local constants follow the same `UPPER_CASE` convention:

```cpp
constexpr int TEST_REGION_COUNT = 3;
constexpr int TEST_CORE_ID = 2;
```
