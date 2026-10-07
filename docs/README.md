# Kinetum Documentation

## What Kinetum Is

Kinetum is a Linux packet-processing platform. You define a pipeline and its
I/O and storage resources; Kinetum plans the work across CPU cores and runs it
as a dataplane. DPDK provides production packet I/O. Built-in ACL, NAT44, and
QoS modules provide filtering, address translation, and rate control; the SDK
supports custom modules. A separate control plane manages live configuration
changes and rollback.

## Start Here

| Need | Read |
|------|------|
| Understand the platform vocabulary and authority model | [`CONCEPTS.md`](CONCEPTS.md) |
| Build, package, start, and inspect a deployment | [`GETTING_STARTED.md`](GETTING_STARTED.md) |
| Recover the end-to-end architecture visually | [`diagrams/platform_architecture.md`](diagrams/platform_architecture.md) |
| Understand live configuration handoff | [`diagrams/ordered_cut_boundary_protocol.md`](diagrams/ordered_cut_boundary_protocol.md) |

## Component References

| Component | Document | Ownership |
|-----------|----------|-----------|
| Axiom | [`AXIOM.md`](AXIOM.md) | Pipeline formats, stage kinds, semantic validation, CLI, and source-tree integration. |
| Gluon | [`GLUON.md`](GLUON.md) | Region planning, exact deployment bindings, provider-graph lowering, plan identity, and source-tree integration. |
| Quark | [`QUARK.md`](QUARK.md) | Linux host CPU/NUMA evidence and strict runtime compatibility. |
| Photon | [`PHOTON.md`](PHOTON.md) | Bundle admission, child lifecycle, readiness, restart, and pair supervision. |
| Control plane | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) | Durable mutation ordering, guardrails, confirmation, and rollback. |
| Data plane | [`DATA_PLANE.md`](DATA_PLANE.md) | Runtime construction, provider materialization, workers, transitions, telemetry, and teardown. |
| Providers | [`PROVIDERS.md`](PROVIDERS.md) | Provider roles, configuration, C ABI, component admission, resource ownership, native implementations, and integration. |
| Module SDK | [`MODULE_SDK.md`](MODULE_SDK.md) | Public C/C++ ABI, lifecycle, packet views, active work, telemetry, health, and build policy. |

## APIs and Tools

| Surface | Document |
|---------|----------|
| gRPC contracts | [`GRPC_API.md`](GRPC_API.md) |
| Operator CLI | [`KINETUMCTL.md`](KINETUMCTL.md) |
| Service diagnostics and retention | [`LOGGING.md`](LOGGING.md) |
| Bundle producer and verifier | [`KINETUM_PACK.md`](KINETUM_PACK.md) |
| Physical-I/O validation and benchmark harness | [`VALIDATION_GUIDE.md`](VALIDATION_GUIDE.md) |

## Engineering References

| Document | Ownership |
|----------|-----------|
| [`PLATFORM_ENGINEERING_GUIDE.md`](PLATFORM_ENGINEERING_GUIDE.md) | Platform-wide doctrine and reusable design patterns. |
| [`CODING_GUIDELINES.md`](CODING_GUIDELINES.md) | Source conventions, Doxygen/docstrings, error handling, ABI discipline, and test shape. |
| [`ALGORITHM_LIBRARY.md`](ALGORITHM_LIBRARY.md) | Public bounded and hot-path algorithm primitives. |
| [`../src/modules/README.md`](../src/modules/README.md) | Built-in ACL, NAT44, and QoS module contracts. |
| [`TECHNICAL_REFERENCES.md`](TECHNICAL_REFERENCES.md) | Normative specifications and directly relevant technical background. |
| [`DOCUMENTATION_GUIDE.md`](DOCUMENTATION_GUIDE.md) | Build, preview, maintain, and publish the documentation website. |

## Visual and Release Indexes

| Document | Use it for |
|----------|------------|
| [`diagrams/README.md`](diagrams/README.md) | Diagram reading paths, source anchors, and maintenance rules. |
| [`diagrams/platform_architecture.md`](diagrams/platform_architecture.md) | Connected architecture, storage, lane, packet, and lifecycle views. |
| [`diagrams/ordered_cut_boundary_protocol.md`](diagrams/ordered_cut_boundary_protocol.md) | DATA/CUT/ACK ordering, drain, reclamation, and alternatives. |
| [`../CHANGELOG.md`](../CHANGELOG.md) | The initial experimental 0.1.0 release. |
