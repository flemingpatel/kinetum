"""Tests for orchestrator setup fail-closed behavior."""

import asyncio
import base64
import copy
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from textwrap import dedent
from unittest.mock import AsyncMock, patch

from kinetum_validation.config.types import (
    AnalysisResult,
    BackendConfig,
    BackendType,
    EpochConfig,
    PacketConfig,
    PacketStats,
    PortSpec,
    ProcessConfig,
    StreamTopologyProfile,
    StorageProfile,
    TestConfig as ValidationConfig,
)
from kinetum_validation.orchestrator import TestOrchestrator as ValidationOrchestrator
from kinetum_validation.scenario_context import ScenarioContext
from kinetum_validation.process.telemetry_validation import boundary_transition_is_complete
from kinetum_validation.scenarios import (
    run_epoch_test,
)
from kinetum_validation.engine.json_contract import PROTOCOL_FAULT_CODE_ORDER
from kinetum_validation.engine.plan_metadata import PlanStorageTransitionMetadata
from kinetum_validation.process.kinetumctl import ApplyConfigResult
from kinetum_validation.process.telemetry import (
    BoundaryEpochStatsResult,
    EpochTransactionStatsResult,
    ModuleContextDomainResult,
    PortStatsResult,
    RegionEpochStatsResult,
    StageStatsResult,
    StatsResult,
    StatsSelection,
    StorageDomainStatsResult,
    StreamStatsResult,
    TrafficSteeringStatsResult,
)


class _FakeEpochKinetumCtl:
    """Kinetumctl replacement for epoch timing tests."""

    def __init__(
        self,
        complete_boundary: bool = True,
        baseline_epoch: int = 2,
    ) -> None:
        """Initialize exact baseline identity and boundary completion mode."""
        self._stats_calls = 0
        self._complete_boundary = complete_boundary
        self._baseline_epoch = baseline_epoch
        self.config_file: Path | None = None

    async def get_stats(self, selection: StatsSelection = StatsSelection()) -> StatsResult:
        """Return pre/post boundary telemetry snapshots."""
        del selection
        self._stats_calls += 1
        if self._stats_calls <= 2:
            packet_count = 0 if self._stats_calls == 1 else 10
            return StatsResult(
                success=True,
                rx_packets=packet_count,
                tx_packets=packet_count,
                active_epoch=self._baseline_epoch,
                active_snapshot_id="v1",
                active_revision=1,
                runtime_generation=1,
                transition_state="EPOCH_TRANSITION_STATE_IDLE",
                protocol_fault_counts={
                    code: 0 for code in PROTOCOL_FAULT_CODE_ORDER
                },
                boundary_epoch_stats=[
                    BoundaryEpochStatsResult(boundary_id="b0"),
                ],
                region_epoch_stats=[
                    RegionEpochStatsResult(
                        region_id=0,
                        worker_count=1,
                        minimum_active_epoch=2,
                        maximum_active_epoch=2,
                        minimum_source_epoch=2,
                        maximum_source_epoch=2,
                        activated_participants=1,
                    ),
                ],
                stage_stats=[
                    StageStatsResult(
                        stage_id="stage0",
                        in_packets=packet_count,
                        out_packets=packet_count,
                    ),
                ],
            )
        return StatsResult(
            success=True,
            rx_packets=110,
            tx_packets=110,
            active_epoch=3,
            active_snapshot_id="v2",
            active_revision=2,
            runtime_generation=1,
            transition_state="EPOCH_TRANSITION_STATE_IDLE",
            latest_terminal=EpochTransactionStatsResult(
                mutation_sequence=3,
                from_epoch=2,
                to_epoch=3,
                outcome="EPOCH_TRANSITION_OUTCOME_COMPLETE",
                failure_code="EPOCH_TRANSITION_FAILURE_CODE_NONE",
            ),
            protocol_fault_counts={
                code: 0 for code in PROTOCOL_FAULT_CODE_ORDER
            },
            boundary_epoch_stats=[
                BoundaryEpochStatsResult(
                    boundary_id="b0",
                    data_enqueued_sequence=100,
                    data_dequeued_sequence=100,
                    transition_generation=3,
                    from_epoch=2,
                    to_epoch=3,
                    cut_sequence=90 if self._complete_boundary else None,
                    sender_phase="BOUNDARY_SENDER_PHASE_OPEN",
                    receiver_phase="BOUNDARY_RECEIVER_PHASE_OPEN",
                    cut_delivery_duration_ns=(10 if self._complete_boundary else None),
                    cut_drain_duration_ns=(20 if self._complete_boundary else None),
                    ack_gate_duration_ns=(40 if self._complete_boundary else None),
                ),
            ],
            region_epoch_stats=[
                RegionEpochStatsResult(
                    region_id=0,
                    worker_count=1,
                    minimum_active_epoch=3,
                    maximum_active_epoch=3,
                    minimum_source_epoch=3,
                    maximum_source_epoch=3,
                    activated_participants=1,
                ),
            ],
            stage_stats=[
                StageStatsResult(
                    stage_id="stage0", in_packets=110, out_packets=110
                ),
            ],
        )

    async def apply_config(
        self, config_file: Path, expected_revision: int | None = None
    ) -> ApplyConfigResult:
        """Accept the transition config."""
        if expected_revision != 1:
            return ApplyConfigResult(success=False, diagnostic="wrong CAS")
        self.config_file = config_file
        return ApplyConfigResult(
            success=True, snapshot_id="v2", revision=2, epoch=3
        )


class _SequenceStatsKinetumCtl:
    """Kinetumctl replacement that returns a configured stats sequence."""

    def __init__(self, stats: list[StatsResult]) -> None:
        """Retain a nonempty observation sequence in caller order."""
        self._stats = stats
        self.calls = 0
        self.selections: list[StatsSelection] = []

    async def get_stats(self, selection: StatsSelection = StatsSelection()) -> StatsResult:
        """Return the next stats snapshot, repeating the last one."""
        self.selections.append(selection)
        index = min(self.calls, len(self._stats) - 1)
        self.calls += 1
        return self._stats[index]


class _FakeEpochSender:
    """Traffic sender that records orchestrator epoch timing."""

    def __init__(self, clock) -> None:
        """Bind the deterministic test clock and empty session state."""
        self._clock = clock
        self.finish_called_at = -1.0
        self.duration_s = 0.0
        self.initial_generation_tag = 0
        self.next_generation_tag = 0
        self.overlap_started_at = -1.0
        self.overlap_ended_at = -1.0
        self.overlap_start_count = 0
        self.overlap_end_count = 0
        self.overlap_ended = False

    async def begin_generation_tags(
        self, duration_s: float, initial_generation_tag: int,
        next_generation_tag: int,
    ) -> None:
        """Record generation-tag start parameters."""
        self.duration_s = duration_s
        self.initial_generation_tag = initial_generation_tag
        self.next_generation_tag = next_generation_tag

    async def start_generation_overlap(self, next_generation_tag: int) -> None:
        """Record the requested next generation tag."""
        if next_generation_tag != self.next_generation_tag:
            raise RuntimeError("generation tag mismatch")
        self.overlap_started_at = self._clock()
        self.overlap_start_count += 1

    async def end_generation_overlap(self) -> None:
        """Record that initial-generation overlap ended."""
        self.overlap_ended_at = self._clock()
        self.overlap_end_count += 1
        self.overlap_ended = True

    async def finish_generation_tags(self) -> PacketStats:
        """Return stats and record when finish was invoked."""
        if self.overlap_start_count != 1 or self.overlap_end_count != 1:
            raise RuntimeError("generation overlap did not complete both edges")
        self.finish_called_at = self._clock()
        stats = PacketStats(tx_count=100, start_time=0.0, end_time=self.finish_called_at)
        stats.generation_tag_counts = {1: 50, 2: 50}
        return stats

    def cancel(self) -> None:
        """No active subprocess exists in this fake."""

    async def abort(self) -> None:
        """No active subprocess exists in this fake."""

    def cleanup(self) -> None:
        """No resources are held by this fake."""


class _FakeEpochTraffic:
    """Traffic driver replacement for epoch timing tests."""

    def __init__(
        self,
        sender: _FakeEpochSender,
        sustained_overlap: bool = True,
    ) -> None:
        """Bind one sender and exact overlap choreography."""
        self.sender = sender
        self.sustained_overlap = sustained_overlap
        self.pcap_file: Path | None = None
        self.filter_expr = ""

    @property
    def requires_sustained_generation_overlap(self) -> bool:
        """Return the choreography selected for this fixture."""
        return self.sustained_overlap

    async def start_capture(self, pcap_file: Path, filter_expr: str) -> None:
        """Accept capture start."""
        self.pcap_file = pcap_file
        self.filter_expr = filter_expr

    async def stop_capture(self) -> None:
        """Retire the accepted capture window."""

    async def analyze_capture(
        self,
        pcap_file: Path,
        expected_count: int,
    ) -> AnalysisResult:
        """Return zero-loss generation-tag analysis."""
        del pcap_file
        result = AnalysisResult(
            total_rx=expected_count,
            valid=expected_count,
            tag_transition_count=0 if self.sustained_overlap else 1,
            transition_seq=-1 if self.sustained_overlap else 50,
        )
        result.tag_counts = {1: 50, 2: 50}
        result.set_latency_stats({
            "avg": 10.0,
            "min": 5.0,
            "max": 20.0,
            "p50": 9.0,
            "p99": 19.0,
        })
        return result

    def make_sender(self, packet_config):
        """Return the fake epoch sender."""
        del packet_config
        return self.sender


class _FakePackerProcess:
    """Minimal subprocess result for canonical-bundle construction tests."""

    def __init__(self, returncode: int, bundle_root: Path) -> None:
        """Retain the exact simulated exit status and output root."""
        self.returncode = returncode
        self._bundle_root = bundle_root

    async def communicate(self):
        """Emit a canonical plan only when the packer succeeds."""
        if self.returncode == 0:
            plan = self._bundle_root / "configs/plan.pbtxt"
            plan.parent.mkdir(parents=True)
            plan.write_text("plan_id: \"fixture\"\n", encoding="utf-8")
            return b"", b""
        return b"", b"packer rejected fixture"


def _config_with_example_dir(root: Path) -> ValidationConfig:
    """Build a TestConfig rooted in one temporary installed layout."""
    return ValidationConfig(
        process=ProcessConfig(
            runtime_root=root / "runtime",
            validation_root=root / "validation",
        ),
        output_dir=root / "out",
    )


def _stage_bundle_inputs(config: ValidationConfig, include_bootstrap: bool = True) -> None:
    """Stage exact regular inputs consumed by the installed bundle builder."""
    runtime_bin = config.process.runtime_bin_dir
    runtime_bin.mkdir(parents=True)
    packer = runtime_bin / "kinetum_pack"
    packer.write_text("", encoding="utf-8")
    packer.chmod(0o755)
    config.process.module_dir.mkdir(parents=True)

    deployment = config.process.examples_dir / config.spec.example_dir
    deployment.mkdir(parents=True)
    for name in (
        config.spec.pipeline_file,
        config.backend_profile.hw_file,
        config.bindings_file,
    ):
        (deployment / name).write_text("fixture\n", encoding="utf-8")
    if include_bootstrap:
        (deployment / config.spec.config_snapshot).write_text(
            "snapshot_id: \"bootstrap\"\n", encoding="utf-8"
        )


class TestCanonicalBundleConstruction(unittest.IsolatedAsyncioTestCase):
    """The bootstrap snapshot enters runtime only through one sealed bundle."""

    async def test_profile_mismatch_rejects_before_runtime_startup(self):
        """Live and dry runs reject mismatched queues or storage before constructing a supervisor."""
        for dry_run in (False, True):
            for topology, storage in (
                (StreamTopologyProfile.DEFAULT, StorageProfile.SHARED),
                (StreamTopologyProfile.RX_RSS_2, StorageProfile.PER_RX_QUEUE),
            ):
                with self.subTest(dry_run=dry_run, topology=topology, storage=storage):
                    with tempfile.TemporaryDirectory() as tmpdir:
                        root = Path(tmpdir)
                        fixture = TestStreamTopologyStatsValidation
                        orch = fixture._rx_rss_2_orchestrator(root)  # pylint: disable=protected-access
                        orch.config = replace(
                            orch.config, dry_run=dry_run,
                            stream_topology=topology, storage_profile=storage,
                        )
                        with patch.object(
                            orch, "_create_runtime_bundle", new=AsyncMock(return_value=root)
                        ), patch("kinetum_validation.orchestrator.AsyncProcessSupervisor") as supervisor:
                            self.assertFalse(await orch._setup())  # pylint: disable=protected-access
                            supervisor.assert_not_called()

    async def test_missing_bootstrap_snapshot_fails_before_packer(self):
        """A deployment-declared bootstrap snapshot is mandatory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _config_with_example_dir(Path(tmpdir))
            _stage_bundle_inputs(config, include_bootstrap=False)
            orch = ValidationOrchestrator(config)

            with patch(
                "kinetum_validation.orchestrator.asyncio.create_subprocess_exec",
                new=AsyncMock(),
            ) as create_process:
                bundle = await orch._create_runtime_bundle()  # pylint: disable=protected-access

            self.assertIsNone(bundle)
            create_process.assert_not_awaited()

    async def test_indirect_bundle_input_fails_before_packer(self):
        """Every selected installed input path component must be real."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _config_with_example_dir(Path(tmpdir))
            _stage_bundle_inputs(config)
            deployment = config.process.examples_dir / config.spec.example_dir
            real_deployment = deployment.with_name(f"{deployment.name}-real")
            deployment.rename(real_deployment)
            deployment.symlink_to(real_deployment, target_is_directory=True)
            orch = ValidationOrchestrator(config)

            with patch(
                "kinetum_validation.orchestrator.asyncio.create_subprocess_exec",
                new=AsyncMock(),
            ) as create_process:
                bundle = await orch._create_runtime_bundle()  # pylint: disable=protected-access

            self.assertIsNone(bundle)
            create_process.assert_not_awaited()

    async def test_packer_receives_the_complete_installed_authority_set(self):
        """The bundle command carries exactly the installed input authority."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _config_with_example_dir(Path(tmpdir))
            _stage_bundle_inputs(config)
            orch = ValidationOrchestrator(config)
            bundle_root = config.output_dir / "runtime_bundle"
            process = _FakePackerProcess(0, bundle_root)

            with patch(
                "kinetum_validation.orchestrator.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ) as create_process:
                bundle = await orch._create_runtime_bundle()  # pylint: disable=protected-access

            self.assertEqual(bundle, bundle_root)
            command = create_process.await_args.args
            deployment = (
                config.process.examples_dir / config.spec.example_dir
            )
            self.assertEqual(
                command,
                (
                    str(config.process.runtime_bin_dir / "kinetum_pack"),
                    "--axiom", str(deployment / config.spec.pipeline_file),
                    "--hw", str(deployment / config.backend_profile.hw_file),
                    "--bindings", str(deployment / config.bindings_file),
                    "--bootstrap-snapshot",
                    str(deployment / config.spec.config_snapshot),
                    "--out", str(bundle_root),
                    "--regions", str(config.spec.regions),
                    "--modules-dir", str(config.process.module_dir),
                ),
            )

    async def test_packer_failure_publishes_no_runnable_bundle(self):
        """Rejected or indirect bundle output cannot reach Photon startup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _config_with_example_dir(Path(tmpdir))
            _stage_bundle_inputs(config)
            orch = ValidationOrchestrator(config)
            bundle_root = config.output_dir / "runtime_bundle"
            process = _FakePackerProcess(1, bundle_root)

            with patch(
                "kinetum_validation.orchestrator.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ):
                bundle = await orch._create_runtime_bundle()  # pylint: disable=protected-access

            self.assertIsNone(bundle)
            self.assertFalse(bundle_root.exists())

            config.output_dir.mkdir()
            bundle_root.symlink_to(config.output_dir / "missing-bundle")
            with patch(
                "kinetum_validation.orchestrator.asyncio.create_subprocess_exec",
                new=AsyncMock(),
            ) as create_process:
                bundle = await orch._create_runtime_bundle()  # pylint: disable=protected-access

            self.assertIsNone(bundle)
            self.assertTrue(bundle_root.is_symlink())
            create_process.assert_not_awaited()


class TestEpochTiming(unittest.IsolatedAsyncioTestCase):
    """Epoch orchestration must preserve the configured traffic duration."""

    async def test_epoch_preserves_packet_configuration_for_both_sender_modes(self):
        """Direct-switch and overlapping traffic preserve packet size and flow identity."""
        for size in (64, 1518, 9000):
            for sustained_overlap in (False, True):
                with (
                    self.subTest(size=size, sustained_overlap=sustained_overlap),
                    tempfile.TemporaryDirectory() as tmpdir,
                ):
                    root = Path(tmpdir)
                    clock = _ObservationClock()
                    config = replace(
                        _config_with_example_dir(root),
                        packet=PacketConfig(
                            pps=123,
                            count=456,
                            duration_s=2.0,
                            packet_size=size,
                            num_flows=8,
                            src_ip="10.20.30.40",
                            dst_ip="192.168.2.1",
                            base_sport=12000,
                            base_dport=10001,
                        ),
                        epoch=EpochConfig(pps=700000, duration_s=60.0),
                        output_dir=root / "out",
                    )
                    config.output_dir.mkdir()
                    config_v2 = (
                        config.process.examples_dir
                        / config.spec.example_dir
                        / config.spec.config_snapshot_v2
                    )
                    config_v2.parent.mkdir(parents=True)
                    config_v2.write_text('snapshot_id: "v2"\n', encoding="utf-8")
                    sender = _FakeEpochSender(clock.monotonic)
                    traffic = _FakeEpochTraffic(sender, sustained_overlap=sustained_overlap)
                    orch = ValidationOrchestrator(config)
                    orch._traffic = traffic  # pylint: disable=protected-access
                    orch._kinetumctl = _FakeEpochKinetumCtl()  # pylint: disable=protected-access

                    with patch.object(traffic, "make_sender", wraps=traffic.make_sender) as make_sender, patch(
                        "kinetum_validation.scenario_context.time", new=clock,
                    ), patch(
                        "kinetum_validation.scenarios.time", new=clock,
                    ), patch(
                        "kinetum_validation.scenario_context.asyncio.sleep", side_effect=clock.sleep,
                    ):
                        result = await run_epoch_test(orch.scenario_context())

                    make_sender.assert_called_once_with(replace(
                        config.packet, pps=config.epoch.pps, duration_s=config.epoch.duration_s,
                    ))
                    self.assertTrue(result.passed, result.message)
                    self.assertEqual(sender.overlap_start_count, 1)
                    self.assertEqual(sender.overlap_end_count, 1)
                    self.assertGreaterEqual(sender.finish_called_at, config.epoch.duration_s)

    async def test_orchestrated_epoch_waits_for_duration_before_finish(self):
        """A sustained-overlap driver must run until epoch duration expires."""
        clock = {"now": 0.0}
        sleeps = []

        def monotonic() -> float:
            """Return the deterministic test clock."""
            return clock["now"]

        async def fake_sleep(delay_s: float) -> None:
            """Advance the deterministic clock without blocking."""
            sleeps.append(delay_s)
            clock["now"] += max(0.0, delay_s)

        class _FakeTime:
            """Minimal time module replacement for orchestrator monotonic calls."""

            @staticmethod
            def monotonic() -> float:
                """Return the fake monotonic clock."""
                return monotonic()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config = _config_with_example_dir(root)
            config = replace(
                config,
                epoch=EpochConfig(
                    duration_s=15.0,
                    transition_time_s=5.0,
                    overlap_window_ms=500,
                ),
                output_dir=root / "out",
            )
            config.output_dir.mkdir()
            config_v2 = (
                config.process.examples_dir
                / config.spec.example_dir
                / config.spec.config_snapshot_v2
            )
            config_v2.parent.mkdir(parents=True)
            config_v2.write_text("snapshot_id: \"v2\"\n", encoding="utf-8")

            sender = _FakeEpochSender(monotonic)
            orch = ValidationOrchestrator(config)
            orch._traffic = _FakeEpochTraffic(sender)  # pylint: disable=protected-access
            orch._kinetumctl = _FakeEpochKinetumCtl()  # pylint: disable=protected-access

            with patch(
                "kinetum_validation.scenario_context.time",
                new=_FakeTime,
            ), patch(
                "kinetum_validation.scenarios.time",
                new=_FakeTime,
            ), patch(
                "kinetum_validation.scenario_context.asyncio.sleep",
                side_effect=fake_sleep,
            ):
                result = await run_epoch_test(orch.scenario_context())  # pylint: disable=protected-access

            self.assertTrue(result.passed)
            self.assertGreaterEqual(sender.finish_called_at, config.epoch.duration_s)
            self.assertEqual(sender.overlap_start_count, 1)
            self.assertEqual(sender.overlap_end_count, 1)
            self.assertAlmostEqual(
                sender.overlap_ended_at - sender.overlap_started_at,
                config.epoch.overlap_window_ms / 1000.0,
            )
            self.assertTrue(any(delay >= 9.0 for delay in sleeps))
            self.assertTrue((config.output_dir / "transition_metrics.jsonl").is_file())
            self.assertFalse(
                boundary_transition_is_complete(BoundaryEpochStatsResult(
                        transition_generation=3,
                        from_epoch=2,
                        to_epoch=3,
                        cut_sequence=0,
                        sender_phase="BOUNDARY_SENDER_PHASE_OPEN",
                        receiver_phase="BOUNDARY_RECEIVER_PHASE_OPEN",
                        cut_delivery_duration_ns=0,
                        cut_drain_duration_ns=0,
                        ack_gate_duration_ns=0,
                    ), 4, 2, 3)
            )

            unavailable = ValidationOrchestrator(config)
            unavailable._kinetumctl = _FakeEpochKinetumCtl(  # pylint: disable=protected-access
                baseline_epoch=0,
            )
            failed = await run_epoch_test(unavailable.scenario_context())  # pylint: disable=protected-access
            self.assertFalse(failed.passed)
            self.assertIn("omitted active snapshot identity", failed.message)

    async def test_unobserved_trex_gate_requires_exact_ordering_evidence(self):
        """A TRex run cannot pass without observing its required ordered gate."""
        clock = {"now": 0.0}

        def monotonic() -> float:
            """Return the deterministic test clock."""
            return clock["now"]

        async def fake_sleep(delay_s: float) -> None:
            """Advance the deterministic clock without blocking."""
            clock["now"] += max(0.0, delay_s)

        class _FakeTime:
            """Minimal time module replacement for orchestrator monotonic calls."""

            @staticmethod
            def monotonic() -> float:
                """Return the fake monotonic clock."""
                return monotonic()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config = replace(
                _config_with_example_dir(root),
                epoch=EpochConfig(
                    duration_s=15.0,
                    transition_time_s=5.0,
                    overlap_window_ms=500,
                ),
                output_dir=root / "out",
            )
            config.output_dir.mkdir()
            config_v2 = (
                config.process.examples_dir
                / config.spec.example_dir
                / config.spec.config_snapshot_v2
            )
            config_v2.parent.mkdir(parents=True)
            config_v2.write_text("snapshot_id: \"v2\"\n", encoding="utf-8")

            sender = _FakeEpochSender(monotonic)
            orch = ValidationOrchestrator(config)
            orch._traffic = _FakeEpochTraffic(sender)  # pylint: disable=protected-access
            orch._kinetumctl = _FakeEpochKinetumCtl(  # pylint: disable=protected-access
                complete_boundary=False,
            )

            with patch(
                "kinetum_validation.scenario_context.time",
                new=_FakeTime,
            ), patch(
                "kinetum_validation.scenarios.time",
                new=_FakeTime,
            ), patch(
                "kinetum_validation.scenario_context.asyncio.sleep",
                side_effect=fake_sleep,
            ):
                result = await run_epoch_test(orch.scenario_context())  # pylint: disable=protected-access

            self.assertFalse(result.passed)
            self.assertFalse(result.boundary_ordering_validated)
            self.assertIn("INCONCLUSIVE", result.message)
            self.assertFalse((config.output_dir / "transition_metrics.jsonl").exists())

    async def test_metadata_cannot_relax_the_observed_gate_requirement(self):
        """Unrecognized build metadata cannot weaken transition evidence."""
        clock = {"now": 0.0}

        def monotonic() -> float:
            """Return the deterministic test clock."""
            return clock["now"]

        async def fake_sleep(delay_s: float) -> None:
            """Advance the deterministic clock without blocking."""
            clock["now"] += max(0.0, delay_s)

        class _FakeTime:
            """Minimal time module replacement for orchestrator monotonic calls."""

            @staticmethod
            def monotonic() -> float:
                """Return the fake monotonic clock."""
                return monotonic()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config = replace(
                _config_with_example_dir(root),
                epoch=EpochConfig(
                    duration_s=15.0,
                    transition_time_s=5.0,
                    overlap_window_ms=500,
                ),
                output_dir=root / "out",
            )
            config.output_dir.mkdir()
            config_v2 = (
                config.process.examples_dir
                / config.spec.example_dir
                / config.spec.config_snapshot_v2
            )
            config_v2.parent.mkdir(parents=True)
            config_v2.write_text("snapshot_id: \"v2\"\n", encoding="utf-8")

            sender = _FakeEpochSender(monotonic)
            orch = ValidationOrchestrator(config)
            orch._release_metadata = {  # pylint: disable=protected-access
                "platform_capabilities": ["unrecognized-description"],
            }
            orch._traffic = _FakeEpochTraffic(sender)  # pylint: disable=protected-access
            orch._kinetumctl = _FakeEpochKinetumCtl(  # pylint: disable=protected-access
                complete_boundary=False,
            )

            with patch(
                "kinetum_validation.scenario_context.time",
                new=_FakeTime,
            ), patch(
                "kinetum_validation.scenarios.time",
                new=_FakeTime,
            ), patch(
                "kinetum_validation.scenario_context.asyncio.sleep",
                side_effect=fake_sleep,
            ):
                result = await run_epoch_test(orch.scenario_context())  # pylint: disable=protected-access

            self.assertFalse(result.passed)
            self.assertFalse(result.boundary_ordering_validated)
            self.assertIn("INCONCLUSIVE", result.message)

    async def test_direct_switch_closes_edge_and_requires_observed_gate(self):
        """A direct tag switch closes its logical edge without a sustained wait."""
        clock = {"now": 0.0}

        def monotonic() -> float:
            """Return the deterministic test clock."""
            return clock["now"]

        async def fake_sleep(delay_s: float) -> None:
            """Advance the deterministic clock without blocking."""
            clock["now"] += max(0.0, delay_s)

        class _FakeTime:
            """Minimal time module replacement for orchestrator monotonic calls."""

            @staticmethod
            def monotonic() -> float:
                """Return the fake monotonic clock."""
                return monotonic()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config = replace(
                _config_with_example_dir(root),
                epoch=EpochConfig(
                    duration_s=15.0,
                    transition_time_s=5.0,
                    overlap_window_ms=500,
                ),
                output_dir=root / "out",
            )
            config.output_dir.mkdir()
            config_v2 = (
                config.process.examples_dir
                / config.spec.example_dir
                / config.spec.config_snapshot_v2
            )
            config_v2.parent.mkdir(parents=True)
            config_v2.write_text("snapshot_id: \"v2\"\n", encoding="utf-8")

            sender = _FakeEpochSender(monotonic)
            orch = ValidationOrchestrator(config)
            orch._traffic = _FakeEpochTraffic(  # pylint: disable=protected-access
                sender,
                sustained_overlap=False,
            )
            orch._kinetumctl = _FakeEpochKinetumCtl(  # pylint: disable=protected-access
                complete_boundary=False,
            )

            with patch(
                "kinetum_validation.scenario_context.time",
                new=_FakeTime,
            ), patch(
                "kinetum_validation.scenarios.time",
                new=_FakeTime,
            ), patch(
                "kinetum_validation.scenario_context.asyncio.sleep",
                side_effect=fake_sleep,
            ):
                result = await run_epoch_test(orch.scenario_context())  # pylint: disable=protected-access

            self.assertFalse(result.passed)
            self.assertFalse(result.boundary_ordering_validated)
            self.assertIn("INCONCLUSIVE", result.message)
            self.assertEqual(sender.overlap_start_count, 1)
            self.assertEqual(sender.overlap_end_count, 1)
            self.assertEqual(sender.overlap_ended_at, sender.overlap_started_at)


class _ObservationClock:
    """Advance an observation deadline without changing the event loop's clock."""

    def __init__(self) -> None:
        """Start at one deterministic local monotonic origin."""
        self.now = 0.0

    def monotonic(self) -> float:
        """Return the current local observation time."""
        return self.now

    async def sleep(self, duration: float) -> None:
        """Advance only the orchestrator's bounded polling clock."""
        self.now += duration


class TestStatsSnapshot(unittest.IsolatedAsyncioTestCase):
    """Stats evidence uses one exact snapshot without inferred settlement."""

    @staticmethod
    def _final_observation(published: int, collected: int) -> StatsResult:
        """Build a complete stream observation over the authored RSS fixture."""
        stats = TestStreamTopologyStatsValidation._clean_rx_rss_2_stats()  # pylint: disable=protected-access
        stats.collection_monotonic_ns = collected
        stats.latest_bank_publication_monotonic_ns = published
        for row in stats.stream_stats:
            row.published_monotonic_ns = published
        return stats

    @staticmethod
    def _final_orchestrator(root: Path) -> ValidationOrchestrator:
        """Reuse the exact authored plan for final-publication membership checks."""
        return TestStreamTopologyStatsValidation._rx_rss_2_orchestrator(root)  # pylint: disable=protected-access

    async def test_final_snapshot_waits_for_every_owner_after_the_barrier(self):
        """Equal-time and partially fresh rows cannot qualify the final observation."""
        with tempfile.TemporaryDirectory() as directory:
            orch = self._final_orchestrator(Path(directory))
            baseline = self._final_observation(100, 200)
            equal = self._final_observation(200, 250)
            partial = self._final_observation(201, 300)
            partial.stream_stats[-1].published_monotonic_ns = 200
            fresh = self._final_observation(301, 400)
            client = _SequenceStatsKinetumCtl([baseline, equal, partial, fresh])
            orch._kinetumctl = client  # pylint: disable=protected-access
            clock = _ObservationClock()
            with patch("kinetum_validation.scenario_context.time", clock), patch(
                "kinetum_validation.scenarios.time", clock
            ), patch(
                "kinetum_validation.scenario_context.asyncio.sleep", clock.sleep
            ):
                observed = await orch.scenario_context().get_final_stats_snapshot()  # pylint: disable=protected-access
            self.assertIs(observed, fresh)
            self.assertEqual(client.calls, 4)

    async def test_final_snapshot_failure_cannot_be_replaced_by_later_success(self):
        """A failed query remains a failure inside the explicit freshness wait."""
        with tempfile.TemporaryDirectory() as directory:
            orch = self._final_orchestrator(Path(directory))
            client = _SequenceStatsKinetumCtl([
                self._final_observation(100, 200),
                StatsResult(success=False, diagnostic="query failed"),
                self._final_observation(301, 400),
            ])
            orch._kinetumctl = client  # pylint: disable=protected-access
            clock = _ObservationClock()
            with patch("kinetum_validation.scenario_context.time", clock), patch(
                "kinetum_validation.scenarios.time", clock
            ), patch(
                "kinetum_validation.scenario_context.asyncio.sleep", clock.sleep
            ), self.assertRaisesRegex(RuntimeError, "observation failed"):
                await orch.scenario_context().get_final_stats_snapshot()  # pylint: disable=protected-access
            self.assertEqual(client.calls, 2)

    async def test_final_snapshot_rejects_identity_membership_and_counter_regression(self):
        """Fresh timestamps cannot legitimize a different or contradictory stream snapshot."""
        baseline = self._final_observation(100, 200)
        fresh = self._final_observation(301, 400)
        changed_generation = copy.deepcopy(fresh)
        changed_generation.runtime_generation += 1
        changed_plan = copy.deepcopy(fresh)
        changed_plan.transition_plan_content_hash = base64.b64encode(b"2" * 32).decode("ascii")
        missing = copy.deepcopy(fresh)
        missing.stream_stats.pop()
        regressed = copy.deepcopy(fresh)
        regressed.stream_stats[0].packets -= 1
        regressed.stream_stats[0].bytes -= 64
        regressed.rx_packets -= 1
        regressed.rx_bytes -= 64
        for candidate in (changed_generation, changed_plan, missing, regressed):
            with self.subTest(candidate=candidate), tempfile.TemporaryDirectory() as directory:
                orch = self._final_orchestrator(Path(directory))
                client = _SequenceStatsKinetumCtl([baseline, candidate])
                orch._kinetumctl = client  # pylint: disable=protected-access
                clock = _ObservationClock()
                with patch("kinetum_validation.scenario_context.time", clock), patch(
                    "kinetum_validation.scenarios.time", clock
                ), patch(
                    "kinetum_validation.scenario_context.asyncio.sleep", clock.sleep
                ), self.assertRaises(RuntimeError):
                    await orch.scenario_context().get_final_stats_snapshot()  # pylint: disable=protected-access
                self.assertEqual(client.calls, 2)

    async def test_final_snapshot_deadline_does_not_accept_stale_values(self):
        """Exhausting the publication deadline fails instead of returning the last sample."""
        with tempfile.TemporaryDirectory() as directory:
            orch = self._final_orchestrator(Path(directory))
            client = _SequenceStatsKinetumCtl([self._final_observation(100, 200)])
            orch._kinetumctl = client  # pylint: disable=protected-access
            clock = _ObservationClock()
            with patch("kinetum_validation.scenario_context.time", clock), patch(
                "kinetum_validation.scenarios.time", clock
            ), patch(
                "kinetum_validation.scenario_context.asyncio.sleep", clock.sleep
            ), patch("kinetum_validation.scenario_context.CONTROL_OBSERVATION_TIMEOUT_S", 0.3), self.assertRaisesRegex(
                RuntimeError, "deadline"
            ):
                await orch.scenario_context().get_final_stats_snapshot()  # pylint: disable=protected-access
            self.assertGreaterEqual(client.calls, 1)

    async def test_final_snapshot_cancellation_propagates(self):
        """Cancellation leaves the observation incomplete rather than returning old evidence."""
        with tempfile.TemporaryDirectory() as directory:
            orch = self._final_orchestrator(Path(directory))
            client = _SequenceStatsKinetumCtl([self._final_observation(100, 200)])
            orch._kinetumctl = client  # pylint: disable=protected-access
            clock = _ObservationClock()
            query = AsyncMock(side_effect=[self._final_observation(100, 200), asyncio.CancelledError()])
            with patch.object(client, "get_stats", query), patch(
                "kinetum_validation.scenario_context.time", clock
            ), patch(
                "kinetum_validation.scenarios.time", clock
            ), patch("kinetum_validation.scenario_context.asyncio.sleep", clock.sleep), self.assertRaises(
                asyncio.CancelledError
            ):
                await orch.scenario_context().get_final_stats_snapshot()  # pylint: disable=protected-access
            self.assertEqual(query.await_count, 2)

    async def test_queries_one_exact_snapshot_without_hidden_retry(self):
        """A second available response cannot replace the first observation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _config_with_example_dir(Path(tmpdir))
            orch = ValidationOrchestrator(config)
            orch._kinetumctl = _SequenceStatsKinetumCtl([  # pylint: disable=protected-access
                StatsResult(
                    success=True,
                    rx_packets=10,
                ),
                StatsResult(
                    success=True,
                    rx_packets=20,
                ),
            ])

            stats = await orch.scenario_context().get_stats_snapshot()  # pylint: disable=protected-access

            self.assertTrue(stats.success)
            self.assertEqual(stats.rx_packets, 10)
            self.assertEqual(orch._kinetumctl.calls, 1)  # pylint: disable=protected-access
            self.assertEqual(
                orch._kinetumctl.selections,  # pylint: disable=protected-access
                [StatsSelection(
                    include_stage_stats=True,
                    include_worker_epoch_stats=True,
                    include_region_epoch_stats=True,
                    include_boundary_epoch_stats=True,
                )],
            )

    async def test_failed_snapshot_remains_an_exact_failed_observation(self):
        """One failed response is returned without synthetic convergence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _config_with_example_dir(Path(tmpdir))
            orch = ValidationOrchestrator(config)
            orch._kinetumctl = _SequenceStatsKinetumCtl([  # pylint: disable=protected-access
                StatsResult(
                    success=False,
                    diagnostic="application unavailable",
                ),
            ])

            stats = await orch.scenario_context().get_stats_snapshot()  # pylint: disable=protected-access

            self.assertFalse(stats.success)
            self.assertEqual(stats.diagnostic, "application unavailable")
            self.assertEqual(orch._kinetumctl.calls, 1)  # pylint: disable=protected-access
            with self.assertRaisesRegex(RuntimeError, "required observation"):
                ScenarioContext.require_active_snapshot_observation(stats, "required observation")

            for malformed in (
                StatsResult(success=True, active_snapshot_id="", active_epoch=7),
                StatsResult(success=True, active_snapshot_id="snapshot-a", active_epoch=0),
            ):
                with self.subTest(malformed=malformed), self.assertRaisesRegex(
                    RuntimeError,
                    "omitted active snapshot identity",
                ):
                    ScenarioContext.require_active_snapshot_observation(malformed, "required observation")

            admitted = StatsResult(
                success=True,
                active_snapshot_id="snapshot-a",
                active_epoch=7,
            )
            self.assertEqual(
                ScenarioContext.require_active_snapshot_observation(admitted, "required observation"),
                ("snapshot-a", 7),
            )
            with self.assertRaisesRegex(RuntimeError, "disagrees with snapshot-b"):
                ScenarioContext.require_active_snapshot_observation(admitted, "required observation", "snapshot-b")


class TestStreamTopologyStatsValidation(unittest.TestCase):
    """Stream-topology evidence gates should fail closed."""

    @staticmethod
    def _rx_rss_2_config(root: Path) -> ValidationConfig:
        """Build a d430-style RX/RSS config for stats validation tests."""
        return replace(
            _config_with_example_dir(root),
            backend=BackendConfig(
                backend_type=BackendType.DPDK_PCI,
                ports=(
                    PortSpec("wan0", "", "rx"),
                    PortSpec("wan1", "", "rx"),
                    PortSpec("lan0", "", "tx"),
                ),
            ),
            stream_topology=StreamTopologyProfile.RX_RSS_2,
        )

    @classmethod
    def _rx_rss_2_orchestrator(cls, root: Path) -> ValidationOrchestrator:
        """Build an orchestrator whose evidence identities come from a plan."""
        plan_file = root / "configs" / "plan.pbtxt"
        plan_file.parent.mkdir(parents=True, exist_ok=True)
        plan_file.write_text(
            dedent(
                """
                packet_storage_domains {
                  storage_domain_id: "storage_fixture_primary"
                  buffer_count: 131071
                  host_numa_node: 0
                }
                ports {
                  logical_name: "wan0"
                  io_driver_instance_id: "driver_fixture_primary"
                  driver_port_id: "wan0"
                  direction: PORT_DIRECTION_RX_ONLY
                  resolved_mac_address: "<\\375\\376\\005\\304\\200"
                }
                ports {
                  logical_port_id: 1
                  logical_name: "wan1"
                  io_driver_instance_id: "driver_fixture_primary"
                  driver_port_id: "wan1"
                  direction: PORT_DIRECTION_RX_ONLY
                  resolved_mac_address: "<\\375\\376\\005\\304\\204"
                }
                ports {
                  logical_port_id: 2
                  logical_name: "lan0"
                  io_driver_instance_id: "driver_fixture_primary"
                  driver_port_id: "lan0"
                  direction: PORT_DIRECTION_TX_ONLY
                  resolved_mac_address: "<\\375\\376\\005\\304\\202"
                }
                io_streams {
                  io_stream_id: "wan0.rx.lane_0"
                  direction: IO_STREAM_DIRECTION_RX
                  lane_id: "lane_0"
                  steering_profile_id: "steering_rss_wan0"
                  rx_storage_domain_id: "storage_fixture_primary"
                }
                io_streams {
                  io_stream_id: "wan0.rx.lane_1"
                  direction: IO_STREAM_DIRECTION_RX
                  lane_id: "lane_1"
                  steering_profile_id: "steering_rss_wan0"
                  driver_queue_id: 1
                  rx_storage_domain_id: "storage_fixture_primary"
                }
                io_streams {
                  io_stream_id: "wan1.rx.lane_0"
                  logical_port_id: 1
                  direction: IO_STREAM_DIRECTION_RX
                  lane_id: "lane_0"
                  steering_profile_id: "steering_rss_wan1"
                  rx_storage_domain_id: "storage_fixture_primary"
                }
                io_streams {
                  io_stream_id: "wan1.rx.lane_1"
                  logical_port_id: 1
                  direction: IO_STREAM_DIRECTION_RX
                  lane_id: "lane_1"
                  steering_profile_id: "steering_rss_wan1"
                  driver_queue_id: 1
                  rx_storage_domain_id: "storage_fixture_primary"
                }
                io_streams {
                  io_stream_id: "lan0.tx.lane_0"
                  logical_port_id: 2
                  direction: IO_STREAM_DIRECTION_TX
                  lane_id: "lane_0"
                  tx_storage {
                    storage_domain_ids: "storage_fixture_primary"
                  }
                }
                io_streams {
                  io_stream_id: "lan0.tx.lane_1"
                  logical_port_id: 2
                  direction: IO_STREAM_DIRECTION_TX
                  lane_id: "lane_1"
                  driver_queue_id: 1
                  tx_storage {
                    storage_domain_ids: "storage_fixture_primary"
                  }
                }
                traffic_steering_profiles {
                  steering_profile_id: "steering_rss_wan0"
                  kind: TRAFFIC_STEERING_KIND_RSS
                  stream_ids: "wan0.rx.lane_0"
                  stream_ids: "wan0.rx.lane_1"
                }
                traffic_steering_profiles {
                  steering_profile_id: "steering_rss_wan1"
                  kind: TRAFFIC_STEERING_KIND_RSS
                  stream_ids: "wan1.rx.lane_0"
                  stream_ids: "wan1.rx.lane_1"
                }
                module_context_domains {
                  module_id: "kinetum.acl"
                  context_instance_ids: "acl0@lane_0"
                  context_instance_ids: "acl0@lane_1"
                  context_instance_ids: "acl1@lane_0"
                  context_instance_ids: "acl1@lane_1"
                }
                module_context_domains {
                  module_id: "kinetum.nat44"
                  context_instance_ids: "nat@lane_0"
                  context_instance_ids: "nat@lane_1"
                }
                module_context_domains {
                  module_id: "kinetum.qos"
                  context_instance_ids: "qos@lane_0"
                  context_instance_ids: "qos@lane_1"
                }
                """
            ),
            encoding="utf-8",
        )
        orchestrator = ValidationOrchestrator(cls._rx_rss_2_config(root))
        orchestrator._apply_resolved_plan_ports(  # pylint: disable=protected-access
            plan_file
        )
        return orchestrator

    @staticmethod
    def _clean_rx_rss_2_stats() -> StatsResult:
        """Return a complete successful RX/RSS stats snapshot."""
        return StatsResult(
            success=True,
            runtime_generation=1,
            transition_plan_content_hash=base64.b64encode(b"1" * 32).decode("ascii"),
            collection_monotonic_ns=200,
            latest_bank_publication_monotonic_ns=100,
            rx_packets=400,
            rx_bytes=25600,
            tx_packets=400,
            tx_bytes=25600,
            stream_stats=[
                StreamStatsResult(
                    io_stream_id=f"{port}.rx.lane_{lane}",
                    logical_port_id=port_id,
                    direction="rx",
                    owning_region_id=0,
                    worker_index=lane,
                    driver_queue_id=lane,
                    published_monotonic_ns=100,
                    packets=100,
                    bytes=6400,
                    rejected_packets=0,
                )
                for port_id, port in enumerate(("wan0", "wan1"))
                for lane in (0, 1)
            ] + [
                StreamStatsResult(
                    io_stream_id=f"lan0.tx.lane_{lane}",
                    logical_port_id=2,
                    direction="tx",
                    owning_region_id=0,
                    worker_index=lane,
                    driver_queue_id=lane,
                    published_monotonic_ns=100,
                    packets=200,
                    bytes=12800,
                    rejected_packets=0,
                )
                for lane in (0, 1)
            ],
            traffic_steering_stats=[
                TrafficSteeringStatsResult(
                    steering_profile_id=f"steering_rss_{port}",
                    kind="rss",
                    io_stream_ids=[
                        f"{port}.rx.lane_0",
                        f"{port}.rx.lane_1",
                    ],
                )
                for port in ("wan0", "wan1")
            ],
            module_context_domains=[
                ModuleContextDomainResult(
                    module_id=module,
                    context_instance_ids=[f"{stage}@lane_{lane}" for stage in stages for lane in (0, 1)],
                )
                for module, stages in (
                    ("kinetum.acl", ("acl0", "acl1")),
                    ("kinetum.nat44", ("nat",)),
                    ("kinetum.qos", ("qos",)),
                )
            ],
            module_context_count=8,
            storage_domain_stats=[
                StorageDomainStatsResult(
                    storage_domain_id="storage_fixture_primary",
                    host_numa_node=0,
                    buffer_count=131071,
                    required_min_buffers=12288,
                    safety_margin=64,
                    observation_state=(
                        "PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE"
                    ),
                    in_use=0,
                    available=131071,
                ),
            ],
            port_stats=[
                PortStatsResult(
                    logical_port_id=port_id,
                    logical_name=port,
                    io_driver_instance_id="driver_fixture_primary",
                    driver_port_id=port,
                    observation_state=(
                        "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT"
                    ),
                    rx_packets=200,
                    tx_packets=0,
                    rx_bytes=12800,
                    tx_bytes=0,
                    rx_missed=0,
                    rx_errors=0,
                    tx_errors=0,
                    rx_no_buffer=0,
                )
                for port_id, port in enumerate(("wan0", "wan1"))
            ],
        )

    def test_default_topology_does_not_require_stream_stats(self):
        """The default topology needs no additional RSS evidence predicate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = ValidationOrchestrator(_config_with_example_dir(Path(tmpdir)))

            result = orch._validate_stream_topology_stats(  # pylint: disable=protected-access
                StatsResult(success=True),
            )

            self.assertFalse(result.required)
            self.assertTrue(result.passed)

    def test_per_queue_storage_requires_every_original_domain_without_rss(self):
        """Per-queue storage requires complete evidence with either queue topology."""
        for rss in (False, True):
            with self.subTest(rss=rss), tempfile.TemporaryDirectory() as tmpdir:
                orch = self._rx_rss_2_orchestrator(Path(tmpdir))
                orch.config = replace(
                    orch.config,
                    storage_profile=StorageProfile.PER_RX_QUEUE,
                    stream_topology=(StreamTopologyProfile.RX_RSS_2 if rss else StreamTopologyProfile.DEFAULT),
                )
                topology = orch._plan_topology  # pylint: disable=protected-access
                self.assertIsNotNone(topology)
                retained = tuple(stream for stream in topology.io_streams if rss or stream.driver_queue_id == 0)
                rx = tuple(
                    replace(stream, rx_storage_domain_id=f"pool_{index}")
                    for index, stream in enumerate(retained)
                    if stream.direction == "IO_STREAM_DIRECTION_RX"
                )
                tx = tuple(
                    replace(stream, tx_storage_domain_ids=tuple(
                        source.rx_storage_domain_id for source in rx
                    ))
                    for stream in retained if stream.direction == "IO_STREAM_DIRECTION_TX"
                )
                domains = tuple(
                    replace(topology.storage_domains[0], storage_domain_id=stream.rx_storage_domain_id)
                    for stream in rx
                )
                profiles = tuple(replace(
                    profile,
                    kind=("TRAFFIC_STEERING_KIND_RSS" if rss else "TRAFFIC_STEERING_KIND_NONE"),
                    stream_ids=tuple(stream.io_stream_id for stream in rx
                                     if stream.steering_profile_id == profile.steering_profile_id),
                ) for profile in topology.steering_profiles)
                exact = replace(topology, io_streams=rx + tx, storage_domains=domains, steering_profiles=profiles)
                orch._plan_topology = exact  # pylint: disable=protected-access
                stats = self._clean_rx_rss_2_stats()
                stats.stream_stats = [stream for stream in stats.stream_stats if rss or stream.driver_queue_id == 0]
                stats.rx_packets = sum(stream.packets for stream in stats.stream_stats if stream.direction == "rx")
                stats.rx_bytes = sum(stream.bytes for stream in stats.stream_stats if stream.direction == "rx")
                stats.tx_packets = sum(stream.packets for stream in stats.stream_stats if stream.direction == "tx")
                stats.tx_bytes = sum(stream.bytes for stream in stats.stream_stats if stream.direction == "tx")
                stats.storage_domain_stats = [
                    replace(stats.storage_domain_stats[0], storage_domain_id=domain.storage_domain_id)
                    for domain in domains
                ]
                result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access
                self.assertTrue(result.required)
                self.assertTrue(result.passed, result.message)
                stats.storage_domain_stats.pop()
                rejected = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access
                self.assertFalse(rejected.passed)

                malformed = (
                    replace(exact, io_streams=(
                        replace(rx[0], rx_storage_domain_id=rx[1].rx_storage_domain_id),
                    ) + rx[1:] + tx),
                    replace(exact, io_streams=rx + (
                        replace(tx[0], tx_storage_domain_ids=(rx[0].rx_storage_domain_id,)),
                    ) + tx[1:]),
                    replace(exact, storage_transitions=(PlanStorageTransitionMetadata(
                        transition_id="copy", from_storage_domain_id=rx[0].rx_storage_domain_id,
                        to_storage_domain_id=rx[1].rx_storage_domain_id,
                    ),)),
                )
                for changed in malformed:
                    orch._plan_topology = changed  # pylint: disable=protected-access
                    with self.assertRaises(RuntimeError):
                        orch._validate_storage_profile_topology()  # pylint: disable=protected-access

    def test_rx_rss_2_requires_all_rx_streams_and_rss_profiles(self):
        """The RX/RSS topology should pass only with complete clean evidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))

            result = orch._validate_stream_topology_stats(  # pylint: disable=protected-access
                self._clean_rx_rss_2_stats(),
            )

            self.assertTrue(result.required)
            self.assertTrue(result.passed)
            self.assertIn("validated 4 RX streams", result.message)
            self.assertIn("2 TX streams", result.message)
            self.assertIn("3 module-context domains", result.message)
            self.assertIn("stream-balance", result.message)
            self.assertIn("storage-domain pressure", result.message)
            self.assertIn("port counters", result.message)

            foreign = self._clean_rx_rss_2_stats()
            foreign.module_context_domains.append(
                ModuleContextDomainResult(
                    module_id="foreign_domain"
                )
            )
            rejected = orch._validate_stream_topology_stats(  # pylint: disable=protected-access
                foreign
            )
            self.assertFalse(rejected.passed)
            self.assertIn("module-context domains differ from plan", rejected.message)

    def test_rx_rss_2_rejects_missing_stream_stats(self):
        """Every planned RX and TX stream must have an observation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            for index in (0, -1):
                with self.subTest(stream_index=index):
                    stats = self._clean_rx_rss_2_stats()
                    stats.stream_stats.pop(index)
                    result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access
                    self.assertTrue(result.required)
                    self.assertFalse(result.passed)
                    self.assertIn("missing expected stream stats", result.message)

    def test_rx_rss_2_rejects_unclean_stream_stats(self):
        """Software stream rejections invalidate multi-stream evidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            for index in (0, -1):
                with self.subTest(stream_index=index):
                    stats = self._clean_rx_rss_2_stats()
                    stats.stream_stats[index].rejected_packets = 1
                    result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access
                    self.assertTrue(result.required)
                    self.assertFalse(result.passed)
                    self.assertIn("rejected_packets=1", result.message)

    def test_rx_rss_2_rejects_unbalanced_stream_distribution(self):
        """RSS rejects a lane below one quarter even beyond float integer precision."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            for first, second in ((399, 1), ((1 << 55) - 1, 3 * (1 << 55) + 1)):
                with self.subTest(first=first, second=second):
                    stats = self._clean_rx_rss_2_stats()
                    for row, packets in zip(stats.stream_stats[:2], (first, second)):
                        row.packets = packets
                        row.bytes = packets * 64
                    stats.rx_packets = sum(row.packets for row in stats.stream_stats if row.direction == "rx")
                    stats.rx_bytes = stats.rx_packets * 64
                    result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access
                    self.assertTrue(result.required)
                    self.assertFalse(result.passed)
                    self.assertIn("unbalanced RX stream distribution", result.message)
                    self.assertIn("min_share=0.250", result.message)

    def test_rx_rss_2_rejects_missing_rss_steering_evidence(self):
        """Multi-stream RX must be backed by admitted RSS steering profiles."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            stats = self._clean_rx_rss_2_stats()
            stats.traffic_steering_stats.pop()

            result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access

            self.assertTrue(result.required)
            self.assertFalse(result.passed)
            self.assertIn("expected 2 RSS steering profiles", result.message)

    def test_rx_rss_2_rejects_missing_storage_domain_evidence(self):
        """Multi-stream RX must carry packet-storage pressure evidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            stats = self._clean_rx_rss_2_stats()
            stats.storage_domain_stats.clear()

            result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access

            self.assertTrue(result.required)
            self.assertFalse(result.passed)
            self.assertIn(
                "missing expected packet-storage-domain stats",
                result.message,
            )

    def test_rx_rss_2_rejects_unexpected_storage_domain_shape(self):
        """The selected shared-storage RSS fixture owns exactly one domain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            stats = self._clean_rx_rss_2_stats()
            stats.storage_domain_stats.append(
                StorageDomainStatsResult(
                    storage_domain_id="storage_dpdk_1",
                    host_numa_node=0,
                    buffer_count=131071,
                    required_min_buffers=12288,
                    safety_margin=64,
                    available=131071,
                ),
            )

            result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access

            self.assertTrue(result.required)
            self.assertFalse(result.passed)
            self.assertIn(
                "packet-storage-domain stats identities differ from plan",
                result.message,
            )

    def test_rx_rss_2_rejects_incomplete_storage_domain_metadata(self):
        """NUMA and sizing facts are part of compiled storage evidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            stats = self._clean_rx_rss_2_stats()
            stats.storage_domain_stats[0].host_numa_node = None
            stats.storage_domain_stats[0].required_min_buffers = 0

            result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access

            self.assertTrue(result.required)
            self.assertFalse(result.passed)
            self.assertIn("host_numa_node=None", result.message)
            self.assertIn("required_min_buffers=0", result.message)

    def test_rx_rss_2_rejects_unavailable_storage_observation(self):
        """A failed native occupancy read invalidates required evidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            stats = self._clean_rx_rss_2_stats()
            stats.storage_domain_stats[0].observation_state = (
                "PROVIDER_OBSERVATION_STATE_READ_FAILED"
            )
            stats.storage_domain_stats[0].in_use = None
            stats.storage_domain_stats[0].available = None

            result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access

            self.assertTrue(result.required)
            self.assertFalse(result.passed)
            self.assertIn("observation_state=PROVIDER_OBSERVATION_STATE_READ_FAILED", result.message)

    def test_rx_rss_2_rejects_missing_port_evidence(self):
        """Multi-stream RX must expose exact logical-port provider counters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            stats = self._clean_rx_rss_2_stats()
            stats.port_stats.pop()

            result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access

            self.assertTrue(result.required)
            self.assertFalse(result.passed)
            self.assertIn("missing expected RX port stats", result.message)

    def test_rx_rss_2_rejects_unclean_port_evidence(self):
        """Port-level misses or read failures invalidate physical RX evidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            stats = self._clean_rx_rss_2_stats()
            stats.port_stats[0].io_driver_instance_id = "wrong_driver"
            stats.port_stats[0].rx_missed = 1
            stats.port_stats[1].observation_state = (
                "PROVIDER_OBSERVATION_STATE_READ_FAILED"
            )
            stats.port_stats[1].rx_packets = None

            result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access

            self.assertTrue(result.required)
            self.assertFalse(result.passed)
            self.assertIn("io_driver_instance_id=wrong_driver", result.message)
            self.assertIn("rx_missed=1", result.message)
            self.assertIn("PROVIDER_OBSERVATION_STATE_READ_FAILED", result.message)

    def test_rx_rss_2_rejects_missing_module_context_domain_evidence(self):
        """Observed module populations must equal the complete compiled populations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._rx_rss_2_orchestrator(Path(tmpdir))
            stats = self._clean_rx_rss_2_stats()
            stats.module_context_domains.pop()

            result = orch._validate_stream_topology_stats(stats)  # pylint: disable=protected-access

            self.assertTrue(result.required)
            self.assertFalse(result.passed)
            self.assertIn("module-context domains differ from plan", result.message)
