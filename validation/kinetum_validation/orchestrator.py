"""Test Orchestrator - coordinate test execution across all components.

The orchestrator manages the full test lifecycle:
1. Build one canonical bundle from installed runtime and validation artifacts
2. Start installed Photon and wait through exact PACKET_READY
3. Setup physical validation resources and the selected traffic driver
4. Run the admitted packet tests
5. Analyze results and generate report

Deployment specs own file paths, region counts, fixtures, and backend profiles.
Packet-level NAT qualification is specific to the canonical gateway scenario."""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import List, Optional, Tuple, Union

from .config.types import (
    BackendType,
    CommitConfirmedTestResult,
    DeploymentMode,
    EpochTestResult,
    GuardrailsTestResult,
    NatExchangeResult,
    RollbackTestResult,
    StatsValidationResult,
    StreamTopologyProfile,
    StorageProfile,
    TestConfig,
    TestResult,
    TestSuiteResult,
    TestType,
)
from .backend import DPDKPCIBackend, DPDKTapBackend
from .engine.runtime_release import collect_runtime_release_metadata
from .engine.json_contract import validate_run_metadata
from .process.installation import (
    installed_example_input_errors,
    installed_root_errors,
    is_symlink_free_directory,
    is_symlink_free_regular_file,
)
from .process.system_tools import (
    communicate_bounded_subprocess,
    exact_subprocess_environment,
    RECOVERABLE_EXCEPTIONS,
)
from .process.run_owner import ValidationRunOwner
from .engine.plan_metadata import (
    PlanModuleContextDomainMetadata,
    PlanIoStreamMetadata,
    PlanPortMetadata,
    PlanSteeringProfileMetadata,
    PlanStorageDomainMetadata,
    PlanTopologyMetadata,
    parse_plan_topology,
    resolve_runtime_ports,
)
from .process.supervisor import AsyncProcessSupervisor
from .process.kinetumctl import KinetumCtl
from .process.telemetry import StatsResult
from .report.console import ConsoleReporter
from .traffic import TrafficDriver, make_traffic_driver
from .scenario_context import ScenarioContext
from .report.artifacts import RunArtifacts
from .nat_exchange import run_nat_exchange
from .scenarios import (
    run_epoch_test,
    run_commit_confirmed_test,
    run_guardrails_test,
    run_rollback_test,
    run_packet_test,
)


RX_RSS_2_MIN_STREAM_PACKET_SHARE_DENOMINATOR = 4

PACKER_COMPLETION_TIMEOUT_S = 300.0


@dataclass(frozen=True)
class _IoPlanFacts:
    """Exact plan identities used by stream and storage evidence checks."""

    rx_ports: Tuple[PlanPortMetadata, ...]
    rx_streams: Tuple[PlanIoStreamMetadata, ...]
    tx_streams: Tuple[PlanIoStreamMetadata, ...]
    storage_domains: Tuple[PlanStorageDomainMetadata, ...]
    steering_profiles: Tuple[PlanSteeringProfileMetadata, ...]
    module_context_domains: Tuple[PlanModuleContextDomainMetadata, ...]


class TestOrchestrator:
    """
    Orchestrate physical-I/O validation test execution.

    Coordinates all test components:
    - Installed Photon supervision of the exact DP/CP pair
    - Backend setup (DPDK TAP or PCI profile)
    - Traffic-driver packet generation and capture
    - Result analysis

    Parameters
    ----------
    config : TestConfig
        Test configuration.
    reporter : ConsoleReporter
        Console reporter for output.
    """

    def __init__(
        self,
        config: TestConfig,
        reporter: Optional[ConsoleReporter] = None,
        release_metadata: Optional[dict] = None,
    ) -> None:
        """Bind one immutable run configuration and reporting authority."""
        self.config = config
        self.reporter = (
            reporter
            if reporter is not None
            else ConsoleReporter(verbose=config.verbose)
        )
        self._supervisor: Optional[AsyncProcessSupervisor] = None
        self._backend: Optional[Union[DPDKTapBackend, DPDKPCIBackend]] = None
        self._traffic: Optional[TrafficDriver] = None
        self._kinetumctl: Optional[KinetumCtl] = None
        self._plan_topology: Optional[PlanTopologyMetadata] = None
        self._release_metadata = release_metadata
        self.artifacts = RunArtifacts(config.output_dir, self.reporter)

    def scenario_context(self) -> ScenarioContext:
        """Borrow the exact current resources without transferring coordinator ownership."""
        return ScenarioContext(
            config=self.config, reporter=self.reporter, traffic=self._traffic,
            control=self._kinetumctl, plan_topology=self._plan_topology,
            artifacts=self.artifacts,
        )

    async def run(self) -> TestSuiteResult:
        """
        Run the complete test suite.

        Returns
        -------
        TestSuiteResult
            Combined results from all tests.
        """
        start_time = time.monotonic()
        results: List[TestResult] = []
        nat_result: Optional[NatExchangeResult] = None
        epoch_result: Optional[EpochTestResult] = None
        commit_confirmed_result: Optional[CommitConfirmedTestResult] = None
        rollback_result: Optional[RollbackTestResult] = None
        guardrails_result: Optional[GuardrailsTestResult] = None
        stats_validation = StatsValidationResult()
        execution_failure: Optional[BaseException] = None

        try:
            # Setup
            if not await self._setup():
                suite_result = TestSuiteResult(
                    deployment=self.config.deployment,
                    test_type=self.config.test_type,
                    total_duration_s=time.monotonic() - start_time,
                    setup_failed=True,
                    dry_run=self.config.dry_run,
                )
                self.artifacts.save_test_results(suite_result, self.config.backend_profile)
                return suite_result

            if self.config.dry_run:
                suite_result = TestSuiteResult(
                    deployment=self.config.deployment,
                    test_type=self.config.test_type,
                    total_duration_s=time.monotonic() - start_time,
                    dry_run=True,
                )
                self.artifacts.save_test_results(suite_result, self.config.backend_profile)
                return suite_result

            # Run standard tests
            context = self.scenario_context()
            if self.config.test_type in (TestType.STANDARD, TestType.FULL):
                for size in self.config.packet.sizes_to_test:
                    result = await run_packet_test(context, size)
                    results.append(result)

            # Run epoch test
            if self.config.test_type in (TestType.EPOCH, TestType.FULL):
                epoch_result = await run_epoch_test(context)

            # Run commit-confirmed test.
            if self.config.test_type in (TestType.COMMIT_CONFIRMED, TestType.FULL):
                commit_confirmed_result = await run_commit_confirmed_test(context)

            # Run rollback test.
            if self.config.test_type in (TestType.ROLLBACK, TestType.FULL):
                rollback_result = await run_rollback_test(context)

            if self.config.test_type in (TestType.GUARDRAILS, TestType.FULL):
                guardrails_result = await run_guardrails_test(context)

            # Collect and save DP stats
            stats_validation = await self._save_dp_stats(context)
            if (
                self.config.deployment == DeploymentMode.FAN_IN_EDGE_GATEWAY
                and self.config.test_type in (TestType.STANDARD, TestType.FULL)
            ):
                nat_result = await run_nat_exchange(context)

        except BaseException as exc:
            execution_failure = exc
            if isinstance(exc, RECOVERABLE_EXCEPTIONS):
                self.reporter.print_error("Test failed", str(exc))
            raise

        finally:
            try:
                await self._cleanup()
            except BaseException as cleanup_error:
                if execution_failure is not None:
                    raise RuntimeError(
                        "validation execution and cleanup both failed: "
                        f"execution={execution_failure}; cleanup={cleanup_error}"
                    ) from cleanup_error
                raise

        suite_result = TestSuiteResult(
            deployment=self.config.deployment,
            test_type=self.config.test_type,
            packet_tests=results,
            nat_exchange=nat_result,
            epoch_test=epoch_result,
            commit_confirmed_test=commit_confirmed_result,
            rollback_test=rollback_result,
            guardrails_test=guardrails_result,
            stats_validation=stats_validation,
            total_duration_s=time.monotonic() - start_time,
        )

        # Save test results to JSON
        self.artifacts.save_test_results(suite_result, self.config.backend_profile)

        return suite_result

    async def _setup(self) -> bool:
        """Set up test environment."""
        self.reporter.print_step("SETUP")

        try:
            # Build the only runnable artifact shape. kinetum_pack emits the
            # canonical plan and copies exact regular module images before it
            # seals and self-verifies the bundle manifest.
            bundle_root = await self._create_runtime_bundle()
            if not bundle_root:
                self.reporter.print_error("Failed to create runtime bundle")
                return False
            plan_file = bundle_root / "configs" / "plan.pbtxt"
            self._apply_resolved_plan_ports(plan_file)
            self._io_plan_facts()

            # Photon is the sole child-process and bootstrap authority.
            self._supervisor = AsyncProcessSupervisor(
                config=self.config.process,
                log_callback=self.reporter.log_callback if self.config.verbose else None,
                output_dir=self.config.output_dir,
            )

            if self.config.dry_run:
                self._save_run_metadata(plan_file, bundle_root, None)
                self.reporter.print_progress("Dry run complete; DP/CP processes not started")
                return True

            self.reporter.print_progress(
                "Starting installed Photon through PACKET_READY..."
            )
            await self._supervisor.start_runtime(bundle_root)

            self._kinetumctl = KinetumCtl(
                runtime_root=self.config.process.runtime_root,
                endpoint=self.config.process.cp_endpoint,
            )

            # Setup validation resources (waits for TAP interfaces).
            self.reporter.print_progress("Setting up validation resources...")
            self._backend = self._make_backend()
            await self._backend.setup()

            # Setup the traffic driver after validation resources are ready. For TAP
            # this means capture/send interfaces exist; for PCI the driver
            # remains external to dataplane provider materialization.
            self.reporter.print_progress("Setting up traffic driver...")
            self._traffic = make_traffic_driver(self.config)
            await self._traffic.setup()

            self._save_run_metadata(
                plan_file,
                bundle_root,
                self._traffic.traffic_generator_identity,
            )

            self.reporter.print_progress("Environment ready")
            return True

        except RECOVERABLE_EXCEPTIONS as e:
            self.reporter.print_error("Setup failed", str(e))
            return False

    async def _create_runtime_bundle(self) -> Optional[Path]:
        """
        Build and self-verify one complete runtime bundle with kinetum_pack.

        The installed packer consumes the source pipeline, hardware inventory,
        exact deployment bindings, mandatory bootstrap snapshot, and installed
        regular module images in one operation. No detached-plan compiler path,
        build-tree executable lookup, or module symlink participates.
        """
        examples_dir = self.config.process.examples_dir
        # Determine source files and bindings from deployment spec
        spec = self.config.spec
        profile = self.config.backend_profile
        bindings_file = self.config.bindings_file
        src = examples_dir / spec.example_dir / spec.pipeline_file
        hw = examples_dir / spec.example_dir / profile.hw_file
        bindings = examples_dir / spec.example_dir / bindings_file
        bootstrap_snapshot = (
            examples_dir / spec.example_dir / spec.config_snapshot
        )
        regions = spec.regions

        required_inputs = (
            ("Pipeline source", src),
            ("Hardware inventory", hw),
            ("Deployment bindings", bindings),
            ("Bootstrap snapshot", bootstrap_snapshot),
        )
        for label, path in required_inputs:
            if not is_symlink_free_regular_file(path):
                self.reporter.print_error(
                    f"{label} not found as a regular file: {path}"
                )
                return None

        packer = self.config.process.runtime_bin_dir / "kinetum_pack"
        if (
            not is_symlink_free_regular_file(packer)
            or not os.access(packer, os.X_OK)
        ):
            self.reporter.print_error(
                f"kinetum_pack not found as an executable regular file: {packer}"
            )
            return None

        if spec.needs_modules and (
            not is_symlink_free_directory(self.config.process.module_dir)
        ):
            self.reporter.print_error(
                "Installed module directory not found as a real directory: "
                f"{self.config.process.module_dir}"
            )
            return None

        bundle_root = self.config.output_dir / "runtime_bundle"
        if bundle_root.exists() or bundle_root.is_symlink():
            self.reporter.print_error(
                f"Runtime bundle output already exists: {bundle_root}"
            )
            return None

        command = [
            str(packer),
            "--axiom", str(src),
            "--hw", str(hw),
            "--bindings", str(bindings),
            "--bootstrap-snapshot", str(bootstrap_snapshot),
            "--out", str(bundle_root),
            "--regions", str(regions),
        ]
        if spec.needs_modules:
            command.extend(
                ["--modules-dir", str(self.config.process.module_dir)]
            )

        self.reporter.print_progress(
            f"Creating verified runtime bundle with {packer}"
        )
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=exact_subprocess_environment(),
        )
        try:
            _stdout, stderr = await communicate_bounded_subprocess(
                proc,
                PACKER_COMPLETION_TIMEOUT_S,
                5.0,
            )
        except asyncio.TimeoutError as exc:
            raise RuntimeError("kinetum_pack exceeded its bounded completion window") from exc

        if proc.returncode != 0:
            self.reporter.print_error(
                f"kinetum_pack failed: {stderr.decode().strip()}"
            )
            return None

        plan_file = bundle_root / "configs" / "plan.pbtxt"
        if not is_symlink_free_regular_file(plan_file):
            self.reporter.print_error(
                f"kinetum_pack omitted an exact canonical plan: {plan_file}"
            )
            return None

        self.reporter.print_progress(f"Runtime bundle created: {bundle_root}")
        return bundle_root

    def _apply_resolved_plan_ports(self, plan_file: Path) -> None:
        """Update traffic profile with resolved runtime metadata from plan.ports."""
        topology = parse_plan_topology(plan_file)
        updated_ports = resolve_runtime_ports(
            topology,
            self.config.backend.ports,
            self.config.backend_profile.traffic_driver,
        )
        self._plan_topology = topology
        self.config = replace(
            self.config,
            backend=replace(self.config.backend, ports=updated_ports),
        )

    def _make_backend(self) -> Union[DPDKTapBackend, DPDKPCIBackend]:
        """Create the selected physical validation descriptor."""
        if self.config.backend.backend_type == BackendType.DPDK_TAP:
            return DPDKTapBackend(self.config.backend)
        if self.config.backend.backend_type == BackendType.DPDK_PCI:
            return DPDKPCIBackend(self.config.backend)
        raise RuntimeError(f"unsupported backend: {self.config.backend.backend_type.value}")

    def _stream_topology_stats_required(self) -> bool:
        """Return whether selected stream or storage topology requires evidence."""
        return (
            self.config.stream_topology == StreamTopologyProfile.RX_RSS_2
            or self.config.storage_profile == StorageProfile.PER_RX_QUEUE
        )

    def _validate_storage_profile_topology(self) -> None:
        """Require the selected physical profile's original-buffer storage layout.

        This checks emitted identities, not provider implementation details.
        Missing queues, unused domains, cross-domain conversions, or a TX set
        missing any ingress domain reject before traffic: either NAT owner in
        the canonical fan-in profile can receive from every ingress queue.
        """
        if self._plan_topology is None:
            raise RuntimeError("storage-profile validation requires parsed plan metadata")
        topology = self._plan_topology
        rx_streams = [stream for stream in topology.io_streams if stream.direction == "IO_STREAM_DIRECTION_RX"]
        tx_streams = [stream for stream in topology.io_streams if stream.direction == "IO_STREAM_DIRECTION_TX"]
        if not rx_streams or not tx_streams:
            raise RuntimeError("storage profile requires nonempty RX and TX stream sets")
        allocation_domains = [stream.rx_storage_domain_id for stream in rx_streams]
        if any(domain is None for domain in allocation_domains):
            raise RuntimeError("storage profile contains an RX stream without allocation storage")
        distinct_domains = set(allocation_domains)
        if self.config.storage_profile == StorageProfile.SHARED:
            if len(distinct_domains) != 1:
                raise RuntimeError("shared storage profile requires one RX allocation domain")
        elif self.config.storage_profile == StorageProfile.PER_RX_QUEUE:
            if len(distinct_domains) != len(rx_streams):
                raise RuntimeError("per-rx-queue storage profile requires a distinct domain for every RX queue")
        else:
            raise RuntimeError("storage profile is undeclared")
        storage_ids = {domain.storage_domain_id for domain in topology.storage_domains}
        if len(storage_ids) != len(topology.storage_domains) or storage_ids != distinct_domains:
            raise RuntimeError("storage profile domains differ from its complete RX allocation set")
        for stream in tx_streams:
            if set(stream.tx_storage_domain_ids) != distinct_domains:
                raise RuntimeError(f"TX storage admission differs from ingress domains: {stream.io_stream_id}")
        if any(
            transition.from_storage_domain_id != transition.to_storage_domain_id
            for transition in topology.storage_transitions
        ):
            raise RuntimeError("storage profile requires handoffs that retain original storage domains")

    @staticmethod
    def _required_stats_failure(message: str) -> StatsValidationResult:
        """Build a required stream-topology validation failure."""
        return StatsValidationResult(
            required=True,
            passed=False,
            message=message,
        )

    def _io_plan_facts(self) -> _IoPlanFacts:
        """
        Validate and return plan facts for the selected physical stream/storage topology.

        This gate intentionally consumes emitted identities. It does not mirror
        Gluon's ID grammar, infer a provider from the harness profile, or
        hard-code one provider-instance/storage-domain spelling.
        """
        if self._plan_topology is None:
            raise RuntimeError(
                "stream-topology validation requires parsed plan metadata"
            )
        self._validate_storage_profile_topology()
        rss = self.config.stream_topology == StreamTopologyProfile.RX_RSS_2
        expected_queues = (0, 1) if rss else (0,)

        port_by_name = {
            port.logical_name: port
            for port in self._plan_topology.ports
        }
        missing_ports = [
            port.logical_name
            for port in self.config.backend.rx_ports
            if port.logical_name not in port_by_name
        ]
        if missing_ports:
            raise RuntimeError(
                "plan.ports[] missing RX topology ports: "
                + ", ".join(missing_ports)
            )
        rx_ports = tuple(
            port_by_name[port.logical_name]
            for port in self.config.backend.rx_ports
        )

        def streams_for(port: PlanPortMetadata, direction: str) -> Tuple[PlanIoStreamMetadata, ...]:
            """Resolve the exact authored queue identities for one selected port role."""
            streams = tuple(sorted(
                (
                    stream for stream in self._plan_topology.io_streams
                    if stream.logical_port_id == port.logical_port_id
                    and stream.direction == direction
                ),
                key=lambda stream: (stream.driver_queue_id, stream.io_stream_id),
            ))
            queue_ids = tuple(stream.driver_queue_id for stream in streams)
            if queue_ids != expected_queues:
                raise RuntimeError(
                    f"stream topology requires exact driver queues {list(expected_queues)} for "
                    f"{port.logical_name}, got {list(queue_ids)}"
                )
            return streams

        rx_streams = tuple(
            stream for port in rx_ports
            for stream in streams_for(port, "IO_STREAM_DIRECTION_RX")
        )
        tx_streams = []
        for port in self.config.backend.tx_ports:
            if port.logical_name not in port_by_name:
                raise RuntimeError(f"plan.ports[] missing TX topology port: {port.logical_name}")
            tx_streams.extend(streams_for(port_by_name[port.logical_name], "IO_STREAM_DIRECTION_TX"))

        stream_ids = {
            stream.io_stream_id
            for stream in rx_streams
        }
        referenced_profile_ids = {
            stream.steering_profile_id
            for stream in rx_streams
        }
        if "" in referenced_profile_ids:
            raise RuntimeError(
                "plan contains an RX stream without steering identity"
            )

        profile_by_id = {
            profile.steering_profile_id: profile
            for profile in self._plan_topology.steering_profiles
        }
        missing_profiles = sorted(
            referenced_profile_ids - profile_by_id.keys()
        )
        if missing_profiles:
            raise RuntimeError(
                "plan references missing steering profiles: "
                + ", ".join(missing_profiles)
            )
        for profile_id in sorted(referenced_profile_ids):
            profile = profile_by_id[profile_id]
            required_kind = "TRAFFIC_STEERING_KIND_RSS" if rss else "TRAFFIC_STEERING_KIND_NONE"
            if profile.kind != required_kind:
                raise RuntimeError(
                    "plan references a steering profile incompatible with the selected topology: "
                    f"{profile_id}"
                )
            if not stream_ids.intersection(profile.stream_ids):
                raise RuntimeError(
                    "steering profile has no selected RX stream: "
                    f"{profile_id}"
                )

        storage_by_id = {
            storage.storage_domain_id: storage
            for storage in self._plan_topology.storage_domains
        }
        missing_storage = sorted({
            domain_id
            for stream in rx_streams
            for domain_id in stream.storage_domain_ids
            if domain_id not in storage_by_id
        })
        if missing_storage:
            raise RuntimeError(
                "plan references missing packet-storage domains: "
                + ", ".join(missing_storage)
            )

        return _IoPlanFacts(
            rx_ports=rx_ports,
            rx_streams=rx_streams,
            tx_streams=tuple(tx_streams),
            storage_domains=tuple(
                sorted(
                    self._plan_topology.storage_domains,
                    key=lambda storage: storage.storage_domain_id,
                )
            ),
            steering_profiles=tuple(
                sorted(
                    (
                        profile
                        for profile in self._plan_topology.steering_profiles
                        if profile.kind == "TRAFFIC_STEERING_KIND_RSS"
                    ),
                    key=lambda profile: profile.steering_profile_id,
                )
            ),
            module_context_domains=tuple(
                sorted(
                    self._plan_topology.module_context_domains,
                    key=lambda domain: domain.module_id,
                )
            ),
        )

    def _validate_io_stream_stats(
        self,
        stats: StatsResult,
        expected_streams: Tuple[PlanIoStreamMetadata, ...],
    ) -> Optional[StatsValidationResult]:
        """Validate software transfers and rejections for exact compiled streams."""
        stream_by_id = {
            stream.io_stream_id: stream
            for stream in stats.stream_stats
        }

        missing = [
            stream.io_stream_id
            for stream in expected_streams
            if stream.io_stream_id not in stream_by_id
        ]
        if missing:
            return self._required_stats_failure(
                "missing expected stream stats: " + ", ".join(missing),
            )

        bad_streams = []
        for expected in expected_streams:
            observed = stream_by_id[expected.io_stream_id]
            if observed.logical_port_id != expected.logical_port_id:
                bad_streams.append(
                    f"{expected.io_stream_id} logical_port_id="
                    f"{observed.logical_port_id}"
                )
            direction = {
                "IO_STREAM_DIRECTION_RX": "rx",
                "IO_STREAM_DIRECTION_TX": "tx",
            }[expected.direction]
            if observed.direction != direction:
                bad_streams.append(
                    f"{expected.io_stream_id} direction={observed.direction}"
                )
            if observed.driver_queue_id != expected.driver_queue_id:
                bad_streams.append(
                    f"{expected.io_stream_id} driver_queue_id="
                    f"{observed.driver_queue_id}"
                )
            if observed.published_monotonic_ns <= 0:
                bad_streams.append(f"{expected.io_stream_id} has no owner publication")
            if observed.packets is None or observed.packets < 0 or (direction == "rx" and observed.packets == 0):
                bad_streams.append(f"{expected.io_stream_id} packets={observed.packets}")
            if observed.bytes is None or observed.rejected_packets is None:
                bad_streams.append(f"{expected.io_stream_id} omitted software counters")
            elif observed.rejected_packets != 0:
                bad_streams.append(f"{expected.io_stream_id} rejected_packets={observed.rejected_packets}")

        if bad_streams:
            return self._required_stats_failure(
                "invalid stream evidence: " + ", ".join(bad_streams),
            )
        return None

    def _validate_rx_rss_2_stream_balance(
        self,
        stats: StatsResult,
        expected_ports: Tuple[PlanPortMetadata, ...],
        expected_streams: Tuple[PlanIoStreamMetadata, ...],
    ) -> Optional[StatsValidationResult]:
        """
        Validate that RSS did not collapse a logical port onto one RX stream.

        TRex varies UDP source ports for rx_rss_2 runs. With two RX streams per
        ingress port, both queues must carry a material share of the packets for
        that logical port. This is not an exact 50/50 requirement: hardware RSS
        hashes deterministic flow tuples, and finite flow counts can skew.
        """
        stream_by_id = {
            stream.io_stream_id: stream
            for stream in stats.stream_stats
        }
        bad_balance = []

        for port in expected_ports:
            expected_ids = [
                stream.io_stream_id
                for stream in expected_streams
                if stream.logical_port_id == port.logical_port_id
            ]
            observed_packets = [
                stream_by_id[stream_id].packets
                for stream_id in expected_ids
                if stream_id in stream_by_id
            ]
            if any(value is None for value in observed_packets):
                bad_balance.append(f"{port.logical_name} counters unavailable")
                continue
            total_packets = sum(value for value in observed_packets if value is not None)
            if total_packets <= 0:
                bad_balance.append(f"{port.logical_name} total_packets=0")
                continue

            for stream_id in expected_ids:
                stream = stream_by_id.get(stream_id)
                if stream is None or stream.packets is None:
                    continue
                share = stream.packets / total_packets
                if stream.packets * RX_RSS_2_MIN_STREAM_PACKET_SHARE_DENOMINATOR < total_packets:
                    bad_balance.append(
                        f"{stream_id} share={share:.3f} "
                        f"packets={stream.packets} total={total_packets} "
                        f"min_share={1 / RX_RSS_2_MIN_STREAM_PACKET_SHARE_DENOMINATOR:.3f}"
                    )

        if bad_balance:
            return self._required_stats_failure(
                "unbalanced RX stream distribution: " + ", ".join(bad_balance),
            )
        return None

    def _validate_storage_domain_stats(
        self,
        stats: StatsResult,
        expected_domains: Tuple[PlanStorageDomainMetadata, ...],
    ) -> Optional[StatsValidationResult]:
        """Validate exact packet-storage capacity for every selected domain."""
        storage_by_id = {
            storage.storage_domain_id: storage
            for storage in stats.storage_domain_stats
        }
        expected_ids = {
            storage.storage_domain_id
            for storage in expected_domains
        }
        missing = sorted(expected_ids - storage_by_id.keys())
        if missing:
            return self._required_stats_failure(
                "missing expected packet-storage-domain stats: "
                + ", ".join(missing),
            )
        if set(storage_by_id) != expected_ids:
            return self._required_stats_failure(
                "packet-storage-domain stats identities differ from plan: "
                f"expected {sorted(expected_ids)}, "
                f"got {sorted(storage_by_id)}",
            )

        bad_domains = []
        for expected in expected_domains:
            observed = storage_by_id[expected.storage_domain_id]
            if observed.host_numa_node != expected.host_numa_node:
                bad_domains.append(
                    f"{observed.storage_domain_id} host_numa_node="
                    f"{observed.host_numa_node} expected="
                    f"{expected.host_numa_node}"
                )
            if observed.buffer_count != expected.buffer_count:
                bad_domains.append(
                    f"{observed.storage_domain_id} buffers="
                    f"{observed.buffer_count} expected={expected.buffer_count}"
                )
            if observed.required_min_buffers <= 0:
                bad_domains.append(
                    f"{observed.storage_domain_id} required_min_buffers="
                    f"{observed.required_min_buffers}"
                )
            if observed.buffer_count < observed.required_min_buffers:
                bad_domains.append(
                    f"{observed.storage_domain_id} buffers="
                    f"{observed.buffer_count} required_min_buffers="
                    f"{observed.required_min_buffers}"
                )
            if observed.safety_margin <= 0:
                bad_domains.append(
                    f"{observed.storage_domain_id} safety_margin="
                    f"{observed.safety_margin}"
                )
            if observed.observation_state not in (
                "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT",
                "PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE",
            ):
                bad_domains.append(
                    f"{observed.storage_domain_id} observation_state="
                    f"{observed.observation_state}"
                )
            if observed.available is None or observed.available <= 0:
                bad_domains.append(
                    f"{observed.storage_domain_id} available="
                    f"{observed.available}"
                )
            if observed.in_use is None or observed.in_use < 0:
                bad_domains.append(
                    f"{observed.storage_domain_id} in_use={observed.in_use}"
                )
        if bad_domains:
            return self._required_stats_failure(
                "invalid packet-storage-domain evidence: "
                + ", ".join(bad_domains),
            )
        return None

    def _validate_port_stats(
        self,
        stats: StatsResult,
        expected_ports: Tuple[PlanPortMetadata, ...],
    ) -> Optional[StatsValidationResult]:
        """Validate exact provider counters for the selected logical RX ports."""
        port_by_name = {
            port.logical_name: port
            for port in stats.port_stats
        }
        missing = [
            expected.logical_name
            for expected in expected_ports
            if expected.logical_name not in port_by_name
        ]
        if missing:
            return self._required_stats_failure(
                "missing expected RX port stats: " + ", ".join(missing),
            )

        bad_ports = []
        for expected in expected_ports:
            observed = port_by_name[expected.logical_name]
            if observed.logical_port_id != expected.logical_port_id:
                bad_ports.append(
                    f"{observed.logical_name} logical_port_id="
                    f"{observed.logical_port_id}"
                )
            if (
                observed.io_driver_instance_id
                != expected.io_driver_instance_id
            ):
                bad_ports.append(
                    f"{observed.logical_name} io_driver_instance_id="
                    f"{observed.io_driver_instance_id}"
                )
            if observed.driver_port_id != expected.driver_port_id:
                bad_ports.append(
                    f"{observed.logical_name} "
                    f"driver_port_id={observed.driver_port_id}"
                )
            if (
                observed.observation_state
                != "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT"
            ):
                bad_ports.append(
                    f"{observed.logical_name} observation_state="
                    f"{observed.observation_state}"
                )
            if observed.rx_packets is None or observed.rx_packets <= 0:
                bad_ports.append(
                    f"{observed.logical_name} rx_packets={observed.rx_packets}"
                )
            if observed.rx_missed is None or observed.rx_missed != 0:
                bad_ports.append(
                    f"{observed.logical_name} rx_missed={observed.rx_missed}"
                )
            if observed.rx_errors is None or observed.rx_errors != 0:
                bad_ports.append(
                    f"{observed.logical_name} rx_errors={observed.rx_errors}"
                )
            if observed.tx_errors is None or observed.tx_errors != 0:
                bad_ports.append(
                    f"{observed.logical_name} tx_errors={observed.tx_errors}"
                )
            if observed.rx_no_buffer is None or observed.rx_no_buffer != 0:
                bad_ports.append(
                    f"{observed.logical_name} rx_no_buffer="
                    f"{observed.rx_no_buffer}"
                )

        if bad_ports:
            return self._required_stats_failure(
                "invalid RX port evidence: " + ", ".join(bad_ports),
            )
        return None

    def _validate_rx_rss_2_steering_stats(
        self,
        stats: StatsResult,
        expected_profiles: Tuple[PlanSteeringProfileMetadata, ...],
    ) -> Optional[StatsValidationResult]:
        """Validate RSS traffic-steering profile evidence for rx_rss_2."""
        rss_profiles = [
            profile for profile in stats.traffic_steering_stats
            if profile.kind == "rss"
        ]
        expected_profile_count = len(expected_profiles)
        if len(rss_profiles) != expected_profile_count:
            return self._required_stats_failure(
                "expected "
                f"{expected_profile_count} RSS steering profiles, got "
                f"{len(rss_profiles)}",
            )

        expected_by_id = {
            profile.steering_profile_id: profile
            for profile in expected_profiles
        }
        bad_profiles = []
        for observed in rss_profiles:
            expected = expected_by_id.get(observed.steering_profile_id)
            if expected is None:
                continue
            if tuple(observed.io_stream_ids) != expected.stream_ids:
                bad_profiles.append(
                    f"{observed.steering_profile_id} stream_ids="
                    f"{observed.io_stream_ids} expected="
                    f"{expected.stream_ids}"
                )
        if bad_profiles:
            return self._required_stats_failure(
                "invalid RSS steering evidence: " + ", ".join(bad_profiles),
            )

        observed_profile_ids = {
            profile.steering_profile_id
            for profile in rss_profiles
        }
        expected_profile_ids = set(expected_by_id)
        if observed_profile_ids != expected_profile_ids:
            return self._required_stats_failure(
                "unexpected RSS steering profiles: expected "
                f"{sorted(expected_profile_ids)}, got {sorted(observed_profile_ids)}",
            )
        return None

    def _validate_module_context_domains(
        self,
        stats: StatsResult,
        expected_domains: Tuple[PlanModuleContextDomainMetadata, ...],
    ) -> Optional[StatsValidationResult]:
        """Compare complete module populations and their ordinal order with the plan."""
        observed = {
            domain.module_id: tuple(domain.context_instance_ids)
            for domain in stats.module_context_domains
        }
        expected = {
            domain.module_id: domain.context_instance_ids
            for domain in expected_domains
        }
        if len(observed) != len(stats.module_context_domains) or observed != expected:
            return self._required_stats_failure(
                f"module-context domains differ from plan: expected {expected}, got {observed}",
            )
        return None

    def _validate_stream_topology_stats(
        self,
        stats: StatsResult,
    ) -> StatsValidationResult:
        """
        Validate stats-backed evidence for the selected stream topology.

        Shared single-queue topology has no additional evidence gate. Separate
        RX storage requires exact stream, storage, and port evidence. The `rx_rss_2`
        topology is a physical multi-stream validation shape: every fan-in RX
        logical port must expose driver queue IDs 0 and 1, each RX stream
        must receive traffic, every RX/TX stream must have zero software
        rejections, and
        the admitted steering/domain/storage objects must prove the topology had
        materialized RSS steering, stream balance, and observable packet-buffer
        headroom.
        """
        if not self._stream_topology_stats_required():
            return StatsValidationResult(
                required=False,
                passed=True,
                message="stream-topology stats validation not required",
            )

        if not stats.success:
            return StatsValidationResult(
                required=True,
                passed=False,
                message="DP stats query failed before stream-topology validation",
            )

        expected = self._io_plan_facts()

        validations = [
            self._validate_io_stream_stats(stats, expected.rx_streams + expected.tx_streams),
            self._validate_storage_domain_stats(
                stats,
                expected.storage_domains,
            ),
            self._validate_port_stats(stats, expected.rx_ports),
            self._validate_module_context_domains(stats, expected.module_context_domains),
        ]
        if self.config.stream_topology == StreamTopologyProfile.RX_RSS_2:
            validations.extend((
                self._validate_rx_rss_2_stream_balance(stats, expected.rx_ports, expected.rx_streams),
                self._validate_rx_rss_2_steering_stats(stats, expected.steering_profiles),
            ))
        for validation in validations:
            if validation is not None:
                return validation

        return StatsValidationResult(
            required=True,
            passed=True,
            message=(
                f"validated {len(expected.rx_streams)} RX streams, "
                f"{len(expected.tx_streams)} TX streams, "
                + (
                    f"{len(expected.steering_profiles)} RSS steering profiles, "
                    f"{len(expected.module_context_domains)} module-context domains, "
                    "stream-balance, storage-domain pressure, and port counters"
                    if self.config.stream_topology == StreamTopologyProfile.RX_RSS_2
                    else f"{len(expected.storage_domains)} storage domains, "
                    "storage-domain pressure, and port counters"
                )
            ),
        )

    def _save_run_metadata(
        self,
        plan_file: Path,
        bundle_root: Path,
        trex_identity: Optional[dict[str, str]],
    ) -> None:
        """Persist backend, topology, and observed generator provenance."""
        if self._release_metadata is None:
            raise RuntimeError("run metadata requires admitted runtime release identity")
        profile = self.config.backend_profile
        metadata = {
            "backend": self.config.backend.backend_type.value,
            "traffic_driver": profile.traffic_driver.value,
            "stream_topology": self.config.stream_topology.value,
            "storage_profile": self.config.storage_profile.value,
            "timestamp_source": profile.timestamp_source,
            "rate_control_source": profile.rate_control_source,
            "latency_source": profile.latency_source,
            "binding_file": self.config.bindings_file,
            "hardware_inventory": profile.hw_file,
            "runtime_release": self._release_metadata,
            "runtime_root": str(self.config.process.runtime_root),
            "validation_root": str(self.config.process.validation_root),
            "bundle_root": str(bundle_root),
            "plan_file": str(plan_file),
            "dry_run": self.config.dry_run,
            "ports": [
                {
                    "logical_name": port.logical_name,
                    "traffic_role": port.traffic_role,
                    "runtime_direction": port.runtime_direction,
                    "tap_iface": port.tap_iface,
                    "peer_iface": port.peer_iface,
                    "peer_ip": port.peer_ip,
                    "traffic_port_id": port.traffic_port_id,
                    "runtime_mac": port.runtime_mac,
                }
                for port in self.config.backend.ports
            ],
            "traffic_endpoint": {
                "host": self.config.traffic.host,
                "ssh_port": self.config.traffic.ssh_port,
                "python": self.config.traffic.python,
                "work_dir": self.config.traffic.work_dir,
                "trex_server": self.config.traffic.trex_server,
                "trex_api_path": self.config.traffic.trex_api_path,
                "trex_ports": list(self.config.traffic.trex_ports),
                "trex_identity": trex_identity,
            },
        }
        validate_run_metadata(metadata)
        metadata_file = self.config.output_dir / "run_metadata.json"
        with open(metadata_file, "x", encoding="utf-8") as f:
            json.dump(metadata, f, allow_nan=False, indent=2, sort_keys=True)
            f.write("\n")
        self.reporter.print_progress(f"Run metadata saved to {metadata_file}")

    async def _save_dp_stats(self, context: ScenarioContext) -> StatsValidationResult:
        """Query and save DP statistics to output folder."""
        if not context.control:
            return StatsValidationResult(
                required=True,
                passed=False,
                message="kinetumctl is unavailable for final telemetry",
            )

        try:
            self.reporter.print_progress("Collecting DP statistics...")
            stats = await context.get_final_stats_snapshot()
            # Save structured stats to file
            self.artifacts.write_stats(stats)
            if not stats.success:
                return StatsValidationResult(
                    required=True,
                    passed=False,
                    message="final Data Plane telemetry is unavailable",
                )
            stats_validation = self._validate_stream_topology_stats(stats)
            if stats_validation.required:
                if stats_validation.passed:
                    self.reporter.print_progress(stats_validation.message)
                else:
                    self.reporter.print_warning(stats_validation.message)
            return stats_validation

        except RECOVERABLE_EXCEPTIONS as e:
            self.reporter.print_warning(f"Could not save DP stats: {e}")
            return StatsValidationResult(
                required=True,
                passed=False,
                message=f"could not save DP stats: {e}",
            )

    async def _cleanup(self) -> None:
        """Attempt every teardown and report all cleanup or child-exit failures."""
        self.reporter.print_step("CLEANUP")
        failures: List[Tuple[str, BaseException]] = []

        if self._traffic:
            try:
                await self._traffic.teardown()
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                self.reporter.print_warning(f"Traffic cleanup failed: {exc}")
                failures.append(("traffic", exc))

        if self._backend:
            try:
                await self._backend.teardown()
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                self.reporter.print_warning(f"Backend cleanup failed: {exc}")
                failures.append(("backend", exc))

        if self._supervisor:
            try:
                await self._supervisor.stop_all()
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                self.reporter.print_warning(f"Process cleanup failed: {exc}")
                failures.append(("process", exc))
        if failures:
            first_error = failures[0][1]
            message = (
                "validation cleanup reported failures: "
                + "; ".join(
                    f"{owner}: {type(error).__name__}: {error}"
                    for owner, error in failures
                )
            )
            if not isinstance(first_error, Exception):
                raise first_error
            raise RuntimeError(message) from first_error


async def run_test_suite(
    config: TestConfig,
    run_owner: Optional[ValidationRunOwner] = None,
) -> TestSuiteResult:
    """
    Run complete test suite.

    Parameters
    ----------
    config : TestConfig
        Test configuration.
    run_owner : Optional[ValidationRunOwner]
        Existing batch owner for a benchmark subdirectory. Direct callers omit
        it and this function owns the complete lock/root lifetime.

    Returns
    -------
    TestSuiteResult
        Combined results from all tests.
    """
    scenario_errors = config.spec.scenario_errors(config.test_type)
    if scenario_errors:
        raise RuntimeError(
            "validation scenario admission rejected: "
            + "; ".join(scenario_errors)
        )
    installation_errors = installed_root_errors(
        config.process.runtime_root,
        config.process.validation_root,
        config.spec.needs_modules,
    )
    if installation_errors:
        raise RuntimeError(
            "installed validation layout rejected: "
            + "; ".join(installation_errors)
        )
    example_errors = installed_example_input_errors(
        config.process.validation_root,
        config.spec.example_dir,
        config.required_example_files,
    )
    if example_errors:
        raise RuntimeError(
            "installed scenario inputs rejected: "
            + "; ".join(example_errors)
        )

    if run_owner is None:
        with ValidationRunOwner.acquire(config.output_dir) as acquired_owner:
            return await run_test_suite(config, acquired_owner)
    if not run_owner.owns_directory(config.output_dir):
        raise RuntimeError("validation output directory lacks the live run owner")

    release_metadata = collect_runtime_release_metadata(
        config.process.runtime_root, config.process.validation_root
    )
    reporter = ConsoleReporter(verbose=config.verbose, color=config.color)
    reporter.print_banner(release_metadata["version"])
    reporter.print_config(config)

    orchestrator = TestOrchestrator(config, reporter, release_metadata)
    result = await orchestrator.run()

    reporter.print_suite_result(result)
    return result
