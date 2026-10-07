# Architecture Diagrams

These diagrams show ownership and event order across Kinetum. Component guides
own schemas, APIs, limits, and failure tables.

## Document Inventory

| Document | Purpose |
|----------|---------|
| [`platform_architecture.md`](platform_architecture.md) | Connected views of authoring, providers, storage, lanes, packet execution, configuration changes, and teardown. |
| [`ordered_cut_boundary_protocol.md`](ordered_cut_boundary_protocol.md) | Focused DATA/CUT/ACK guide covering fan-in, active and asynchronous drain, certificate/grace, failure behavior, and dual-version execution as an alternative. |

## Reading Paths

| Question | Start | Detailed owner |
|----------|-------|----------------|
| What is the complete platform flow? | [Architecture Section 1](platform_architecture.md#1-end-to-end-overview) | [`CONCEPTS.md`](../CONCEPTS.md), [`GETTING_STARTED.md`](../GETTING_STARTED.md) |
| How does authored intent become a plan? | [Architecture Section 2](platform_architecture.md#2-gluon-planning) | [`GLUON.md`](../GLUON.md), [`QUARK.md`](../QUARK.md) |
| How do drivers, storage, and execution fit together? | [Architecture Section 3](platform_architecture.md#3-providers-and-packet-storage) | [`PROVIDERS.md`](../PROVIDERS.md) |
| How do RSS queues become lanes and workers? | [Architecture Section 4](platform_architecture.md#4-execution-lanes-and-rss) | [`GLUON.md`](../GLUON.md#74-final-port-and-executable-topology), [`MODULE_SDK.md`](../MODULE_SDK.md#session-ownership-across-ingress-queues) |
| Who starts and supervises DP and CP? | [Architecture Section 5](platform_architecture.md#5-photon-supervision) | [`PHOTON.md`](../PHOTON.md) |
| Who serializes configuration mutations? | [Architecture Section 6](platform_architecture.md#6-control-plane) | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](../CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| How do Bootstrap and live updates cross RPC? | [Architecture Section 7](platform_architecture.md#7-transition-rpc-boundary) | [`GRPC_API.md`](../GRPC_API.md), [`DATA_PLANE.md`](../DATA_PLANE.md) |
| How is immutable configuration published? | [Architecture Section 8](platform_architecture.md#8-configuration-publication) | [`DATA_PLANE.md`](../DATA_PLANE.md), [`MODULE_SDK.md`](../MODULE_SDK.md) |
| How can telemetry lead to rollback? | [Architecture Section 9](platform_architecture.md#9-guardrails-and-rollback) | [`CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md`](../CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md) |
| How is module ownership created and retired? | [Architecture Section 10](platform_architecture.md#10-module-lifecycle) | [`MODULE_SDK.md`](../MODULE_SDK.md), [`../src/modules/README.md`](../../src/modules/README.md) |
| What happens when the data plane starts? | [Architecture Section 11](platform_architecture.md#11-data-plane-host) | [`DATA_PLANE.md`](../DATA_PLANE.md), [`KINETUM_PACK.md`](../KINETUM_PACK.md) |
| What is paid by a packet worker? | [Architecture Section 12](platform_architecture.md#12-worker-hot-path) | [`DATA_PLANE.md`](../DATA_PLANE.md), [`PLATFORM_ENGINEERING_GUIDE.md`](../PLATFORM_ENGINEERING_GUIDE.md) |
| How does one packet move and retire? | [Architecture Section 13](platform_architecture.md#13-packet-lifecycle) | [`DATA_PLANE.md`](../DATA_PLANE.md), [`MODULE_SDK.md`](../MODULE_SDK.md) |
| Why does the boundary carry a sequence cut? | [Ordered-CUT guide](ordered_cut_boundary_protocol.md) | [`DATA_PLANE.md`](../DATA_PLANE.md) |

## Stable Source Anchors

Source anchors use file and symbol names so formatting does not invalidate them.

| Area | Primary anchors |
|------|-----------------|
| Planning | `src/gluon/gluon_planner.cpp::plan_impl`, `src/gluon/deployment_bindings_lowering.cpp`, `src/provider/compiled_provider_topology.cpp::compile_provider_topology` |
| Providers and storage | `src/provider/provider_contract_catalog.cpp`, `src/provider/provider_runtime_materialization.cpp`, `src/dp/packet_worker_kernel.cpp::deliver_tx_` |
| Lanes and RSS | `proto/kinetum/gluon/v1/plan.proto::ExecutionLane`, `src/gluon/deployment_bindings_lowering.cpp`, `src/provider/compiled_provider_topology.cpp` |
| Host proof | `src/quark/host_probe.cpp::probe_host`, `src/quark/runtime_compat.cpp::validate_runtime_compat` |
| Supervision | `src/photon/startup.cpp::start_supervised_children`, `src/photon/startup.cpp::supervised_pair_owner` |
| CP mutation | `src/cp/control_loop.cpp::control_loop`, `src/cp/config_store.cpp::config_store`, `src/cp/transition_reconciliation.cpp` |
| Runtime admission | `src/pack/runtime_bundle.cpp::verify_runtime_bundle`, `src/provider/provider_runtime_admission.cpp`, `src/provider/provider_runtime_materialization.cpp` |
| Transition protocol | `src/dp/epoch/epoch_transition_coordinator.cpp`, `src/dp/worker_runtime_command.cpp`, `src/dp/epoch/worker_boundary_sender.cpp`, `src/dp/epoch/worker_boundary_receiver.cpp` |
| Completion and reclamation | `src/dp/epoch/epoch_transition_certificate.cpp`, `src/dp/epoch/epoch_transition_completion.cpp`, `include/kinetum/algo/quiescence.hpp` |
| Module lifecycle | `src/dp/module/module_manager.cpp`, `src/dp/module/module_epoch_store.cpp`, `src/dp/module/module_lifecycle_adapter.cpp` |
| Packet execution | `src/dp/packet_worker_kernel.cpp`, `src/dp/packet_mechanism.cpp`, `src/dp/packet.hpp` |
| Observation | `src/dp/runtime_telemetry_snapshot_source.cpp`, `src/dp/runtime_telemetry_wire.cpp`, `src/dp/runtime_status.cpp` |

## Visual Rules

Keep this visual style for new diagrams and content revisions.

- Author diagrams in PlantUML using its default fonts, colors, and shapes.
- Declare a non-default layout engine in the diagram source so previews and
  the website use the same engine.
- Use orthogonal routing (`skinparam linetype ortho`) for component,
  deployment, object, and state diagrams.
- Use component/deployment diagrams for ownership and dependencies, with
  left-to-right direction where it clarifies the flow.
- Use activity diagrams or ordered phase cards for operating workflows.
- Use sequence diagrams only when event order is the point.
- Use state diagrams only for an actual finite state machine.
- Keep the end-to-end sequence continuous, with stable participants and marked
  phases. Component sections expand its mechanisms.
- Keep labels short, arrow meanings explicit, and crossings rare.
- Keep meanings explicit in labels and shapes; color is never the only distinction.
- Captions state the diagram's scope and assumptions without repeating its steps.
- ASCII sequences keep participant bars and arrow endpoints in fixed columns.
- Use file-plus-symbol source anchors, never source line numbers.

Let PlantUML determine SVG dimensions from the content. Do not set fixed image
widths, heights, scale, or DPI, or add image-sizing CSS. Native spacing,
direction, and hidden layout links may prevent crowding; hidden links carry no
semantic relationship. Sphinx embeds SVGs through the site's standard image
layout. Content revisions retain this renderer, visual style, and sizing policy.

## Maintenance Gate

After a diagram edit:

```bash
./tooling/release/documentation/build_documentation.py
./tooling/release/documentation/build_documentation.py --check-links
```

The gate fails on malformed PlantUML, orphan pages, unresolved references,
remote page assets, generated path leakage, or a mismatch between authored
PlantUML directives and rendered SVG images. The final release review also inspects
every diagram at desktop and narrow widths in the published light theme.
