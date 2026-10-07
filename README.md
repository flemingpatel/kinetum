# Kinetum (0.1.0)

Kinetum is a Linux packet-processing platform whose production hot path
targets DPDK. It compiles declared packet pipelines, plans them across
CPU cores, runs them as a long-lived dataplane, and applies configuration
snapshots through an epoch-based reconfiguration subsystem.

> **Epoch-transition status:** Live configuration updates use one
> sequence-defined DATA/CUT/ACK protocol, exact worker ownership
> accounting, owner-worker activation, and quiescence-gated reclamation. The
> control plane exposes durable Prepare/Activate convergence, commit-confirmed
> updates, and evidence-gated guardrails. Physical results apply to the tested
> hardware and configurations; broader qualification remains incomplete.
> Kinetum 0.1.0 has no physical TRex packet-latency measurement contract.

## Status

Kinetum 0.1.0 is the initial experimental release.

- DPDK I/O plus host storage/CPU provider components (production release
  aggregate; final tuple and physical qualification pending)
- UDP I/O provider (development without DPDK devices)

## Get Started

- Build, plan, and run: [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)
- Architectural overview: [`docs/CONCEPTS.md`](docs/CONCEPTS.md)

## Documentation

| Topic                                | Doc                                                                |
| ------------------------------------ | ------------------------------------------------------------------ |
| Architectural overview               | [`docs/CONCEPTS.md`](docs/CONCEPTS.md)                             |
| End-to-end walkthrough               | [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)               |
| Pipeline definition and validation   | [`docs/AXIOM.md`](docs/AXIOM.md)                                   |
| Planning and binding                 | [`docs/GLUON.md`](docs/GLUON.md)                                   |
| Host CPU/NUMA compatibility          | [`docs/QUARK.md`](docs/QUARK.md)                                   |
| Supervisor                           | [`docs/PHOTON.md`](docs/PHOTON.md)                                 |
| Control plane, guardrails, rollback  | [`docs/CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](docs/CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| Dataplane                            | [`docs/DATA_PLANE.md`](docs/DATA_PLANE.md)                           |
| Provider contracts and integration   | [`docs/PROVIDERS.md`](docs/PROVIDERS.md)                           |
| Module SDK                           | [`docs/MODULE_SDK.md`](docs/MODULE_SDK.md)                         |
| gRPC API                             | [`docs/GRPC_API.md`](docs/GRPC_API.md)                             |
| `kinetumctl` reference               | [`docs/KINETUMCTL.md`](docs/KINETUMCTL.md)                         |
| Service logging and retention       | [`docs/LOGGING.md`](docs/LOGGING.md)                               |
| Bundle format                        | [`docs/KINETUM_PACK.md`](docs/KINETUM_PACK.md)                     |
| Physical-I/O validation runner       | [`docs/VALIDATION_GUIDE.md`](docs/VALIDATION_GUIDE.md)             |
| Diagrams                             | [`docs/diagrams/`](docs/diagrams/)                                 |

## Repository Layout

**Contracts**
- `proto/kinetum/axiom/`     pipeline IR
- `proto/kinetum/gluon/`     plan and bindings
- `proto/kinetum/control/`   control API, snapshots, and private durable state
- `proto/kinetum/dataplane/` dataplane RPC wrappers and readiness contracts
- `proto/kinetum/hw/`        hardware inventory schema
- `proto/kinetum/common/`    shared types
- `proto/kinetum/telemetry/` shared operator telemetry
- `proto/kinetum/{provider,facility,io,storage,execution,transition}/` typed provider contracts
- `proto/kinetum/release/`   installed-provider and release evidence

**Core components**
- `src/axiom/`   pipeline compiler and validation
- `src/gluon/`   planner and binding resolution
- `src/quark/`   host topology probe and strict runtime compatibility gate
- `src/photon/`  single-node supervisor
- `src/cp/`      control plane
- `src/dp/`      provider-neutral dataplane runtime and packet mechanisms
- `src/provider/` provider contracts, admission, and component implementations

**Tooling and SDK**
- `src/ctl/`     `kinetumctl` CLI
- `src/pack/`    bundle pack and verify
- `include/kinetum/` public module SDK and algorithm headers
- `src/sdk/`     private host-side module ABI text validation
- `src/modules/` built-in SDK modules (`acl`, `nat44`, `qos`)
- `sdk/`         pkg-config install template (`kinetum.pc.in`)

**Support**
- `include/kinetum/algo/`    algorithm primitives (`cuckoo_map`, `timer_wheel`, hash utilities)
- `src/common/`  shared status, identity, file, protobuf, logging, and time utilities
- `cmake/`       build helpers and the SDK CMake install template
- `third_party/dpdk/` exact source-build policy and imported-target template
- `tooling/environment/` source-build bootstrap, Python dependency locks, and exact DPDK producer
- `tooling/release/` packaging, installation verification, and website production
- `tooling/format.sh` C/C++ source formatting
- `validation/`  private validation and benchmark code, native helpers, lab profiles, and wheel packaging
- `scripts/`     operator-invoked hugepage and TRex shell helpers

**Examples and tests**
- `examples/fan_in_edge_gateway/`    multi-ingress DAG, 3 regions
- `examples/passthrough/`            minimal RX-to-TX pipeline
- `tests/`                            unit and integration tests
- `tooling/tests/`                    Python tests for environment and release tooling
- `validation/tests/`                 validation, benchmark, and private wheel tests
- `docs/`                             platform documentation

## License

Kinetum is licensed under Apache-2.0. See [`LICENSE`](LICENSE),
[`NOTICE`](NOTICE), and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
