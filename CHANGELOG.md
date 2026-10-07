# Changelog

## 0.1.0 (Experimental)

Initial experimental release for Ubuntu 24.04 on x86-64 and AArch64.

### Platform

- Added Axiom pipeline authoring and strict semantic validation, deterministic
  Gluon deployment planning, Quark Linux host-evidence validation, Photon pair
  supervision, a durable control plane, and a provider-neutral data plane.
- Made the deployment plan the sole runtime wiring authority for facilities,
  I/O, packet storage, execution, ports, queues, steering, workers, services,
  and bounded capacities.
- Added exact runtime-bundle admission with canonical plan and bootstrap
  snapshot identity.

### Live configuration

- Added durable two-phase snapshot updates with exact retry identity,
  commit-confirmed operation, full and selective rollback, and restart
  reconciliation.
- Added the sequence-defined DATA/CUT/ACK protocol, worker ownership ledgers,
  exact reader grace, and certificate-gated reclamation for passive and active
  pipelines.
- Added owner-worker active timers, control delivery, pull readiness, retained
  packets, tracked foreign work, cancellation, and same-instance
  recirculation under one bounded conservation model.

### Modules and providers

- Added an exact C11/C++20 module ABI with bounded packet batches and lifecycle
  services, generation-scoped immutable configuration, owner-worker telemetry
  and health, and link-closed image policy.
- Added ACL, NAT44, and QoS built-in modules as ordinary SDK consumers.
- Added a fixed C provider-component ABI, canonical typed provider contracts,
  authenticated installed inventory, and transactional host/DPDK provider
  materialization.
- Added per-queue RX storage bindings and multi-domain TX admission with
  reclamation through each record's original storage owner.
- Pinned the DPDK provider to the exact source-built 24.11.7 static closure,
  with tuple-specific configuration, archive/PMD membership, and generated
  source attribution.

### Observation and policy

- Added one shared all-or-none telemetry schema over completed owner banks,
  coherent transition and health state, protocol-fault evidence, and typed
  provider observations.
- Added explicit guardrails policy, valid-observation-time evaluation,
  attribution, and durable automatic rollback intent through the existing
  mutation authority.
- Added bounded service logging, file rotation/reopen, and explicit
  diagnostic-loss health observations.

### Tools and distribution

- Added `kinetumctl`, runtime bundle production and verification, and runtime
  and SDK packages with checksums, installers, and installation verification.
- Made deployment manifests canonical and version-exact: metadata is required,
  paths are strictly sorted, alternate textual spellings reject, and producer
  count/byte bounds equal parser bounds.
- Added a self-contained Sphinx/MyST website with static PlantUML SVG,
  Doxygen public SDK reference, Apache-2.0 licensing, and package-specific
  third-party notices.

### Validation

Native builds, C++ and Python tests, and package verification passed on
x86-64 and AArch64.
