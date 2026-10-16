"""Production-shaped tests for final physical scenario choreography."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import tempfile
import time
import unittest
from dataclasses import replace
from functools import partial
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from kinetum_validation.config.types import (
    AnalysisResult,
    BackendConfig,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    PacketStats,
    ProcessConfig,
    TestConfig as ValidationConfig,
    TestType as ValidationTestType,
)
from kinetum_validation.engine.json_contract import PROTOCOL_FAULT_CODE_ORDER
from kinetum_validation.orchestrator import TestOrchestrator as ValidationOrchestrator
from kinetum_validation.scenarios import (
    COMMIT_CONFIRMED_TRAFFIC_S,
    CONFIRM_TIMEOUT_MS,
    CONFIRM_TIMEOUT_ROLLBACK_MS,
    ROLLBACK_TRAFFIC_S,
    GUARDRAILS_TRAFFIC_S,
    GUARDRAILS_ARMING_TIMEOUT_S,
    run_commit_confirmed_test,
    run_guardrails_test,
    run_rollback_test,
)
from kinetum_validation.scenario_context import (
    CONTROL_OBSERVATION_TIMEOUT_S,
    ScenarioContext,
)
from kinetum_validation.process import kinetumctl as control_module
from kinetum_validation.process.guardrails_observation import (
    GuardrailsPolicyIdentity, GuardrailsRead, parse_guardrails_json,
)
from kinetum_validation.process.kinetumctl import (
    ActiveSnapshot,
    ApplyConfigResult,
    ConfirmResult,
    KinetumCtl,
    RollbackResult,
    SnapshotModule,
)
from kinetum_validation.process.telemetry import (
    EpochTransactionStatsResult,
    ModuleHealthStatsResult,
    StatsResult,
    StatsSelection,
    WorkerCounterStatsResult,
)

from .guardrails_fixtures import POLICY_HASH, armed_guardrails_payload, rollback_guardrails_payload
from .traffic_fixtures import complete_native_analysis


def _module(module_id: str, revision: int, policy: bytes) -> SnapshotModule:
    """Build one canonical test module from exact opaque policy bytes."""
    return SnapshotModule(
        module_id=module_id,
        revision=revision,
        config_blob=policy,
        content_type="application/json",
        content_hash=hashlib.sha256(policy).hexdigest(),
        schema_id="",
    )


def _snapshot(
    snapshot_id: str,
    revision: int,
    *,
    acl: bytes,
    nat: bytes,
    qos: bytes,
    parent: str = "",
) -> ActiveSnapshot:
    """Build one exact active snapshot with canonical module ordering."""
    modules = (
        _module("kinetum.acl", revision, acl),
        _module("kinetum.nat44", revision, nat),
        _module("kinetum.qos", revision, qos),
    )
    return ActiveSnapshot(
        snapshot_id=snapshot_id,
        revision=revision,
        created_unix_ms=revision,
        modules=modules,
        description=snapshot_id,
        author="",
        parent_snapshot_id=parent,
        labels=(),
        content_hash=hashlib.sha256(snapshot_id.encode("ascii")).hexdigest(),
    )


def _stats(
    snapshot_id: str,
    revision: int,
    epoch: int,
    rx_packets: int,
    tx_packets: int,
    collection_ns: int,
    *,
    dropped_packets: int = 0,
    health: bool = False,
    complete_from_epoch: int | None = None,
) -> StatsResult:
    """Build one coherent scenario observation with exact counter identity."""
    terminal = None
    if complete_from_epoch is not None:
        terminal = EpochTransactionStatsResult(
            mutation_sequence=epoch,
            from_epoch=complete_from_epoch,
            to_epoch=epoch,
            outcome="EPOCH_TRANSITION_OUTCOME_COMPLETE",
            failure_code="EPOCH_TRANSITION_FAILURE_CODE_NONE",
        )
    health_rows = []
    if health:
        for module_id in ("kinetum.acl", "kinetum.nat44", "kinetum.qos"):
            health_rows.append(ModuleHealthStatsResult(
                module_id=module_id,
                context_instance_id=f"{module_id}@lane_0",
                state="MODULE_HEALTH_STATE_SIGNAL_AVAILABLE",
                observation_epoch=epoch,
            ))
    return StatsResult(
        success=True,
        rx_packets=rx_packets,
        tx_packets=tx_packets,
        dropped_packets=dropped_packets,
        rx_bytes=rx_packets * 64,
        tx_bytes=tx_packets * 64,
        active_epoch=epoch,
        transition_active_epoch=epoch,
        active_snapshot_id=snapshot_id,
        active_revision=revision,
        runtime_generation=7,
        collection_monotonic_ns=collection_ns,
        latest_bank_publication_monotonic_ns=collection_ns,
        expected_workers=1,
        execution_participant_count=1,
        allocated_epoch_high_watermark=epoch,
        transition_plan_content_hash=base64.b64encode(hashlib.sha256(b"scenario-plan").digest()).decode(),
        transition_active_validation_hash=base64.b64encode(hashlib.sha256(snapshot_id.encode()).digest()).decode(),
        worker_counters=[WorkerCounterStatsResult(
            worker_index=0, observation_epoch=epoch, publication_generation=collection_ns,
            published_monotonic_ns=collection_ns, rx_packets=rx_packets, tx_packets=tx_packets,
            dropped_packets=dropped_packets, rx_bytes=rx_packets * 64, tx_bytes=tx_packets * 64, fanout_overflow=0,
        )],
        transition_state="EPOCH_TRANSITION_STATE_IDLE",
        latest_terminal=terminal,
        protocol_fault_counts={
            code: 0 for code in PROTOCOL_FAULT_CODE_ORDER
        },
        module_health_stats=health_rows,
    )


class _ScenarioSender:
    """Traffic sender that returns positive exact local ownership evidence."""

    def __init__(self, held_run: int) -> None:
        """Initialize one sender whose selected run needs explicit completion."""
        if held_run <= 0:
            raise ValueError("held scenario run must be positive")
        self.calls = 0
        self._held_run = held_run
        self._held_run_complete = asyncio.Event()

    async def run_timed(self, duration_s: float) -> PacketStats:
        """Return one positive clean sender interval."""
        if duration_s <= 0.0:
            raise RuntimeError("scenario duration is not positive")
        self.calls += 1
        if self.calls == self._held_run:
            await self._held_run_complete.wait()
        return PacketStats(
            tx_count=100,
            generation_tag_counts={0: 100},
            start_time=float(self.calls),
            end_time=float(self.calls) + duration_s,
            duration_s=duration_s,
        )

    def complete_held_run(self) -> None:
        """Release the selected run after its required observation completes."""
        self._held_run_complete.set()

    def cancel(self) -> None:
        """No child process exists in this fake."""

    async def abort(self) -> None:
        """No asynchronous ownership remains in this fake."""

    def cleanup(self) -> None:
        """No local resource remains in this fake."""


class _ScenarioTraffic:
    """Traffic boundary used by commit and rollback scenario tests."""

    def __init__(self, held_sender_run: int, capture_failure: bool = False) -> None:
        """Initialize one explicitly completed sender and inactive capture."""
        self.sender = _ScenarioSender(held_sender_run)
        self.capture_active = False
        self.capture_failure = capture_failure

    async def start_capture(self, pcap_file: Path, filter_expr: str) -> None:
        """Accept one fresh capture identity."""
        if self.capture_active or not pcap_file.is_absolute() or not filter_expr:
            raise RuntimeError("capture identity is malformed")
        self.capture_active = True

    async def stop_capture(self) -> None:
        """Retire the current capture window."""
        if not self.capture_active:
            return
        self.capture_active = False
        if self.capture_failure:
            raise RuntimeError("capture overflow")

    def make_sender(self, _packet_config) -> _ScenarioSender:
        """Return the one scenario sender."""
        return self.sender

    async def analyze_capture(
        self,
        pcap_file: Path,
        expected_count: int,
    ) -> AnalysisResult:
        """Return exact clean capture evidence for the requested population."""
        del pcap_file
        return complete_native_analysis(((0, expected_count),), 2)


class _ScenarioKinetumCtl:
    """Scripted public CLI boundary for complete scenario state products."""

    def __init__(self, stats: list[StatsResult]) -> None:
        """Retain exact response scripts in caller-provided order."""
        self.stats = list(stats)
        self.apply_results: list[ApplyConfigResult] = []
        self.confirmed_apply_results: list[ApplyConfigResult] = []
        self.rollback_results: list[tuple[tuple[str, ...], RollbackResult]] = []
        self.active_snapshots: list[ActiveSnapshot] = []
        self.confirm_result = ConfirmResult(success=False)
        self.guardrails_calls: list[bool] = []
        self.guardrails_reads: list[GuardrailsRead] = []

    async def get_stats(self, _selection: StatsSelection = StatsSelection()) -> StatsResult:
        """Consume one exact scripted observation."""
        if not self.stats:
            raise RuntimeError("scenario stats script is exhausted")
        return self.stats.pop(0)

    async def apply_config(
        self, _config_file: Path, expected_revision: int | None = None
    ) -> ApplyConfigResult:
        """Consume one ordinary mutation result with an explicit CAS."""
        if expected_revision is None or not self.apply_results:
            return ApplyConfigResult(success=False, diagnostic="missing apply")
        return self.apply_results.pop(0)

    async def apply_config_with_confirm(
        self,
        _config_file: Path,
        confirm_timeout_ms: int,
        expected_revision: int | None = None,
    ) -> ApplyConfigResult:
        """Consume one commit-confirmed mutation result."""
        if (
            confirm_timeout_ms <= 0
            or expected_revision is None
            or not self.confirmed_apply_results
        ):
            return ApplyConfigResult(success=False, diagnostic="missing confirm apply")
        return self.confirmed_apply_results.pop(0)

    async def confirm(
        self, snapshot_id: str, epoch: int, revision: int
    ) -> ConfirmResult:
        """Return the exact configured confirmation result."""
        if (
            snapshot_id != self.confirm_result.snapshot_id
            or epoch != self.confirm_result.epoch
            or revision != self.confirm_result.revision
        ):
            return ConfirmResult(success=False, diagnostic="wrong confirm identity")
        return self.confirm_result

    async def rollback(
        self,
        _snapshot_id: str,
        module_ids: list[str] | None = None,
        expected_revision: int | None = None,
    ) -> RollbackResult:
        """Consume one rollback result with explicit CAS and mode."""
        if expected_revision is None or not self.rollback_results:
            return RollbackResult(success=False, diagnostic="missing rollback")
        expected_modules, result = self.rollback_results.pop(0)
        if tuple(module_ids or ()) != expected_modules:
            return RollbackResult(success=False, diagnostic="wrong rollback mode")
        return result

    async def get_active_snapshot(self) -> ActiveSnapshot:
        """Consume one exact canonical active-content observation."""
        if not self.active_snapshots:
            raise RuntimeError("active snapshot script is exhausted")
        return self.active_snapshots.pop(0)

    async def configure_guardrails(self, enabled: bool, **_policy) -> GuardrailsPolicyIdentity:
        """Record each exact policy enable/disable edge."""
        self.guardrails_calls.append(enabled)
        return GuardrailsPolicyIdentity(len(self.guardrails_calls), POLICY_HASH)

    async def get_guardrails(self) -> GuardrailsRead:
        """Consume one complete policy/evaluator observation without inventing readiness."""
        if not self.guardrails_reads:
            raise RuntimeError("guardrails read script is exhausted")
        return self.guardrails_reads.pop(0)


def _config(root: Path, test_type: ValidationTestType) -> ValidationConfig:
    """Build one module-bearing validation configuration in a fresh tree."""
    config = ValidationConfig(
        deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
        test_type=test_type,
        backend=BackendConfig(
            ports=DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(BackendType.DPDK_TAP).ports,
        ),
        process=ProcessConfig(
            runtime_root=root / "runtime",
            validation_root=root / "private-kit",
        ),
        output_dir=root / "output",
    )
    config.output_dir.mkdir(parents=True)
    example = config.process.examples_dir / config.spec.example_dir
    example.mkdir(parents=True)
    for filename in (
        config.spec.config_snapshot,
        config.spec.config_snapshot_v2,
        config.spec.guardrails_degradation_snapshot,
    ):
        if filename is not None:
            (example / filename).write_text(
                'snapshot_id: "fixture"\n', encoding="utf-8"
            )
    return config


class _ScenarioClock:
    """Advance observation time only through the scenario's bounded polling."""

    def __init__(self) -> None:
        """Start at an exact monotonic origin."""
        self.now = 0.0

    def monotonic(self) -> float:
        """Return the current observation time."""
        return self.now

    async def sleep(self, delay: float) -> None:
        """Advance the requested interval without a real-time wait."""
        self.now = round(self.now + delay, 9)


def _commit_control(survival: list[StatsResult]) -> _ScenarioKinetumCtl:
    """Author the same confirmed transaction with explicit survival observations."""
    control = _ScenarioKinetumCtl([
        _stats("initial", 2, 1, 0, 0, 100),
        _stats("v1", 1, 2, 0, 0, 200),
        _stats("v1", 1, 2, 10, 10, 300),
        _stats("v2", 2, 3, 20, 20, 400),
        *survival,
    ])
    control.apply_results = [ApplyConfigResult(success=True, snapshot_id="v1", revision=1, epoch=2)]
    control.confirmed_apply_results = [
        ApplyConfigResult(success=True, snapshot_id="v2", revision=2, epoch=3),
        ApplyConfigResult(success=True, snapshot_id="v1", revision=1, epoch=4),
    ]
    control.confirm_result = ConfirmResult(
        success=True, snapshot_id="v2", revision=2, epoch=3, time_remaining_ms=1000,
    )
    return control


class TestScenarioChoreography(unittest.IsolatedAsyncioTestCase):
    """Final scenarios must prove traffic, content, and automatic action."""

    async def test_counter_wait_ignores_retrieval_only_progress(self) -> None:
        """A repeated source publication waits until a genuinely new positive ingress interval exists."""
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory), ValidationTestType.COMMIT_CONFIRMED)
            before = _stats("v1", 1, 1, 0, 0, 100)
            repeated = replace(before, collection_monotonic_ns=200)
            fresh = _stats("v1", 1, 1, 10, 10, 300)
            control = _ScenarioKinetumCtl([repeated, fresh])
            orchestrator = ValidationOrchestrator(config)
            orchestrator._kinetumctl = control  # pylint: disable=protected-access
            live = asyncio.create_task(asyncio.Event().wait())
            try:
                with patch("kinetum_validation.scenario_context.asyncio.sleep", new=AsyncMock()):
                    result = await orchestrator.scenario_context().wait_for_traffic_progress(
                        before, time.monotonic() + 1.0, "fixture ingress", live,
                    )
                self.assertIs(result, fresh)
                self.assertFalse(control.stats)
            finally:
                live.cancel()
                await asyncio.gather(live, return_exceptions=True)

    async def test_counter_wait_rejects_changed_same_publication(self) -> None:
        """Invalid evidence is not converted into another wait or positive ingress."""
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory), ValidationTestType.COMMIT_CONFIRMED)
            before = _stats("v1", 1, 1, 0, 0, 100)
            changed = replace(
                before, rx_packets=1, rx_bytes=64, collection_monotonic_ns=200,
                worker_counters=[replace(before.worker_counters[0], rx_packets=1, rx_bytes=64)],
            )
            control = _ScenarioKinetumCtl([changed])
            orchestrator = ValidationOrchestrator(config)
            orchestrator._kinetumctl = control  # pylint: disable=protected-access
            live = asyncio.create_task(asyncio.Event().wait())
            try:
                with self.assertRaisesRegex(ValueError, "changed without publication"):
                    await orchestrator.scenario_context().wait_for_traffic_progress(
                        before, time.monotonic() + 1.0, "fixture ingress", live,
                    )
            finally:
                live.cancel()
                await asyncio.gather(live, return_exceptions=True)

    async def test_unchanged_observation_exhaustion_never_satisfies_readiness(self) -> None:
        """An unchanged result exhausts the original window without adding a fresh allowance."""
        with tempfile.TemporaryDirectory() as directory:
            context = ValidationOrchestrator(_config(Path(directory), ValidationTestType.EPOCH)).scenario_context()
            read = AsyncMock(return_value=False)
            with patch(
                "kinetum_validation.scenario_context.time",
                monotonic=MagicMock(side_effect=[100.0, 100.0, 100.0, 101.0]),
            ), patch("kinetum_validation.scenario_context.asyncio.sleep", new=AsyncMock()), self.assertRaisesRegex(
                RuntimeError, "exhausted its observation window",
            ):
                await context.wait_for_observation(read, bool, 101.0, "fixture readiness")
            read.assert_awaited_once()

    async def test_observation_cancellation_retires_the_inflight_reader(self) -> None:
        """Caller cancellation waits for the observation's cleanup and propagates as cancellation."""
        with tempfile.TemporaryDirectory() as directory:
            context = ValidationOrchestrator(_config(Path(directory), ValidationTestType.EPOCH)).scenario_context()
            entered = asyncio.Event()
            retired = asyncio.Event()

            async def read() -> bool:
                """Hold one observation until cancellation resolves its ownership."""
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    retired.set()
                return True

            waiting = asyncio.create_task(context.wait_for_observation(
                read, bool, time.monotonic() + 10.0, "cancelled observation",
            ))
            try:
                await asyncio.wait_for(entered.wait(), timeout=3.0)
                waiting.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await waiting
                self.assertTrue(retired.is_set())
            finally:
                waiting.cancel()
                await asyncio.gather(waiting, return_exceptions=True)

    async def test_finished_source_rejects_before_observation(self) -> None:
        """A completed traffic task cannot be hidden by an otherwise ready observation."""
        with tempfile.TemporaryDirectory() as directory:
            context = ValidationOrchestrator(_config(Path(directory), ValidationTestType.EPOCH)).scenario_context()
            completed = asyncio.create_task(asyncio.sleep(0))
            await completed
            read = AsyncMock(return_value=True)
            with self.assertRaisesRegex(RuntimeError, "traffic ended early"):
                await context.wait_for_observation(
                    read, bool, time.monotonic() + 1.0, "finished source", completed,
                )
            read.assert_not_awaited()

    async def test_native_retry_allowance_is_capped_by_each_observation_window(self) -> None:
        """One invocation uses at most the remaining window, not a fresh retry allowance."""
        native_retry_seconds = 4 * 30 + sum((1, 2, 4))
        self.assertEqual(native_retry_seconds, 127)
        process_timeout = control_module._KINETUMCTL_PROCESS_TIMEOUT_S  # pylint: disable=protected-access
        self.assertGreater(process_timeout, native_retry_seconds)
        windows = (
            0.25,  # Epoch pre-transition margin.
            GUARDRAILS_ARMING_TIMEOUT_S,
            GUARDRAILS_TRAFFIC_S,
            CONTROL_OBSERVATION_TIMEOUT_S,
            ROLLBACK_TRAFFIC_S,
            COMMIT_CONFIRMED_TRAFFIC_S,
        )
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory), ValidationTestType.EPOCH)
            context = ValidationOrchestrator(config).scenario_context()
            for window in windows:
                with self.subTest(window=window), patch(
                    "kinetum_validation.scenario_context.time",
                    monotonic=MagicMock(return_value=100.0),
                ), patch.object(
                    ScenarioContext, "get_stats_snapshot",
                    new=AsyncMock(return_value=_stats("v1", 1, 1, 0, 0, 100)),
                ) as invoke, patch(
                    "kinetum_validation.scenario_context.asyncio.wait_for",
                    wraps=asyncio.wait_for,
                ) as wait:
                    result = await context.get_stats_before_deadline(100.0 + window, "fixture")
                    self.assertTrue(result.success)
                    invoke.assert_awaited_once()
                    self.assertEqual(wait.call_args.kwargs["timeout"], window)
                    self.assertLess(window, native_retry_seconds)

    async def test_expired_and_late_statistics_cannot_cross_the_observation_deadline(self) -> None:
        """An expired read never starts; a result completing at the deadline is rejected."""
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory), ValidationTestType.EPOCH)
            context = ValidationOrchestrator(config).scenario_context()
            with patch(
                "kinetum_validation.scenario_context.time",
                monotonic=MagicMock(return_value=101.0),
            ), patch.object(ScenarioContext, "get_stats_snapshot", new=AsyncMock()) as invoke:
                with self.assertRaisesRegex(RuntimeError, "deadline expired"):
                    await context.get_stats_before_deadline(100.0, "fixture")
                invoke.assert_not_awaited()
            with patch(
                "kinetum_validation.scenario_context.time",
                monotonic=MagicMock(side_effect=[100.0, 101.0]),
            ), patch.object(
                ScenarioContext, "get_stats_snapshot",
                new=AsyncMock(return_value=_stats("v1", 1, 1, 0, 0, 100)),
            ):
                with self.assertRaisesRegex(RuntimeError, "exceeded its authored deadline"):
                    await context.get_stats_before_deadline(101.0, "fixture")

    async def test_cancelled_statistics_retires_the_native_child_before_return(self) -> None:
        """Scenario cancellation drains the sole native invocation before releasing its owner."""
        entered = asyncio.Event()
        process = MagicMock(returncode=None)

        async def communicate() -> tuple[bytes, bytes]:
            """Block the first communication until cancellation, then return terminal pipes."""
            if process.returncode is None:
                entered.set()
                await asyncio.Event().wait()
            return b"", b""

        def terminate() -> None:
            """Publish the fake child's exact terminal signal result."""
            process.returncode = -15

        process.communicate = AsyncMock(side_effect=communicate)
        process.terminate.side_effect = terminate
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory).resolve(), ValidationTestType.EPOCH)
            binary = config.process.runtime_root / "bin" / "kinetumctl"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            binary.chmod(0o700)
            orchestrator = ValidationOrchestrator(config)
            orchestrator._kinetumctl = KinetumCtl(config.process.runtime_root)  # pylint: disable=protected-access
            context = orchestrator.scenario_context()
            with patch(
                "kinetum_validation.process.kinetumctl.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ) as spawn:
                task = asyncio.create_task(context.get_stats_before_deadline(time.monotonic() + 5.0, "fixture"))
                try:
                    await asyncio.wait_for(entered.wait(), timeout=1.0)
                finally:
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                spawn.assert_awaited_once()
                process.terminate.assert_called_once()
                self.assertEqual(process.returncode, -15)
                self.assertEqual(process.communicate.await_count, 2)

    async def test_commit_confirmed_proves_traffic_before_both_mutations(self) -> None:
        """Confirmed content survives its deadline with fresh traffic before the next mutation."""
        await self._check_commit_confirmed_capture(False)

    async def test_commit_confirmed_capture_failure_preserves_completed_control_evidence(self) -> None:
        """A capture failure keeps the verified confirmation and rollback facts while failing the scenario."""
        await self._check_commit_confirmed_capture(True)

    async def _check_commit_confirmed_capture(self, capture_failure: bool) -> None:
        """Drive both real control phases before an explicitly successful or failed capture stop."""
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory), ValidationTestType.COMMIT_CONFIRMED)
            traffic = _ScenarioTraffic(held_sender_run=1, capture_failure=capture_failure)
            clock = _ScenarioClock()
            control = _commit_control([
                *[_stats("v2", 2, 3, 20, 20, 400)] * 11,
                _stats("v2", 2, 3, 25, 25, 500),
                _stats("v1", 1, 4, 30, 30, 600),
                _stats("v2", 2, 5, 40, 40, 700, complete_from_epoch=4),
                _stats("v2", 2, 5, 50, 50, 900, complete_from_epoch=4),
            ])
            orchestrator = ValidationOrchestrator(config)
            orchestrator._kinetumctl = control  # pylint: disable=protected-access
            orchestrator._traffic = traffic  # pylint: disable=protected-access
            transition_count = 0

            def record_transition(*_args, **_keywords) -> None:
                """Complete traffic only after both transitions are recorded."""
                nonlocal transition_count
                transition_count += 1
                self.assertGreaterEqual(clock.now, 1.0)
                if transition_count == 2:
                    traffic.sender.complete_held_run()

            orchestrator.artifacts.write_transition_metrics = MagicMock(  # pylint: disable=protected-access
                side_effect=record_transition
            )

            with patch(
                "kinetum_validation.scenario_context.asyncio.sleep",
                side_effect=clock.sleep,
            ), patch(
                "kinetum_validation.scenario_context.time", new=clock,
            ), patch(
                "kinetum_validation.scenarios.time", new=clock,
            ):
                result = await run_commit_confirmed_test(orchestrator.scenario_context())

            self.assertEqual(result.passed, not capture_failure, result.message)
            self.assertTrue(result.confirm_success)
            self.assertTrue(result.confirmed_survived_deadline)
            self.assertEqual(result.confirmed_survival_elapsed_ms, 1000)
            self.assertTrue(result.timeout_rollback_occurred)
            self.assertEqual(
                orchestrator.artifacts.write_transition_metrics.call_count,  # pylint: disable=protected-access
                2,
            )
            evidence = json.loads((config.output_dir / "commit_confirmed_capture.traffic.json").read_text())
            self.assertEqual(evidence["sender"]["tx_count"], 100)
            if capture_failure:
                self.assertIn("capture overflow", result.message)
                self.assertIsNone(evidence["analysis"])
            else:
                self.assertEqual(len(evidence["analysis"]["streams"]), 2)
            self.assertFalse(control.stats)

    async def test_commit_confirmed_rejects_early_replacement_and_stalled_traffic(self) -> None:
        """Neither an early rollback nor elapsed time without source progress proves confirmation."""
        repeated = _stats("v2", 2, 3, 20, 20, 400)
        changed_publication = replace(
            repeated, rx_packets=21, rx_bytes=1344,
            worker_counters=[replace(repeated.worker_counters[0], rx_packets=21, rx_bytes=1344)],
        )
        for observations, diagnostic in (
            ([_stats("v1", 1, 4, 30, 30, 500)], "disagrees"),
            ([changed_publication], "changed without publication"),
            ([repeated] * 400, "exhausted its observation window"),
        ):
            with self.subTest(diagnostic=diagnostic), tempfile.TemporaryDirectory() as directory:
                config = _config(Path(directory), ValidationTestType.COMMIT_CONFIRMED)
                clock = _ScenarioClock()
                traffic = _ScenarioTraffic(held_sender_run=1)
                control = _commit_control(observations)
                orchestrator = ValidationOrchestrator(config)
                orchestrator._kinetumctl = control  # pylint: disable=protected-access
                orchestrator._traffic = traffic  # pylint: disable=protected-access
                with patch(
                    "kinetum_validation.scenario_context.asyncio.sleep", side_effect=clock.sleep,
                ), patch(
                    "kinetum_validation.scenario_context.time", new=clock,
                ), patch(
                    "kinetum_validation.scenarios.time", new=clock,
                ):
                    result = await run_commit_confirmed_test(orchestrator.scenario_context())
                self.assertFalse(result.passed)
                self.assertFalse(result.confirmed_survived_deadline)
                self.assertIn(diagnostic, result.message)
                self.assertEqual(len(control.confirmed_apply_results), 1)
                self.assertFalse(traffic.capture_active)
                self.assertFalse((config.output_dir / "transition_metrics.jsonl").exists())

    async def test_confirmation_clock_begins_at_completion_and_rollback_can_precede_poll(self) -> None:
        """Slow apply replies consume scenario time without inventing CP expiry or candidate counters."""
        for first_read in ("candidate", "retiring", "complete", "unchanged_counters"):
            with self.subTest(first_read=first_read), tempfile.TemporaryDirectory() as directory:
                config = _config(Path(directory), ValidationTestType.COMMIT_CONFIRMED)
                traffic = _ScenarioTraffic(held_sender_run=1)
                clock = _ScenarioClock()
                confirmed = _stats("v2", 2, 3, 25, 25, 500)
                candidate = _stats("v1", 1, 4, 30, 30, 600)
                retiring = replace(
                    _stats("v1", 1, 5, 35, 35, 650), transition_active_epoch=4, transition_target_epoch=5,
                    transition_state="EPOCH_TRANSITION_STATE_RETIRING",
                )
                restored = _stats("v2", 2, 5, 40, 40, 700, complete_from_epoch=4)
                forwarding = _stats("v2", 2, 5, 50, 50, 900, complete_from_epoch=4)
                new_epoch_seed = []
                if first_read == "unchanged_counters":
                    restored = replace(
                        restored, rx_packets=30, tx_packets=30, rx_bytes=1920, tx_bytes=1920,
                        worker_counters=candidate.worker_counters, latest_bank_publication_monotonic_ns=600,
                    )
                    new_epoch_seed = [_stats("v2", 2, 5, 40, 40, 800, complete_from_epoch=4)]
                observed_candidate = first_read in {"candidate", "unchanged_counters"}
                intermediate = [candidate] if observed_candidate else [retiring] if first_read == "retiring" else []
                control = _commit_control([
                    *[_stats("v2", 2, 3, 20, 20, 400)] * 11,
                    confirmed,
                    *intermediate,
                    restored,
                    *new_epoch_seed,
                    forwarding,
                ])
                original_apply = control.apply_config_with_confirm

                async def slow_apply(
                    config_file, confirm_timeout_ms, expected_revision, *,
                    observation_clock=clock, apply_request=original_apply,
                ):
                    """Delay the reply while retaining the exact CP completion result."""
                    observation_clock.now += confirm_timeout_ms / 1000.0 + 1.0
                    return await apply_request(config_file, confirm_timeout_ms, expected_revision)

                orchestrator = ValidationOrchestrator(config)
                orchestrator._kinetumctl = control  # pylint: disable=protected-access
                orchestrator._traffic = traffic  # pylint: disable=protected-access
                transitions = []

                def record_transition(
                    records, source, before, after, from_epoch, to_epoch, **_keywords,
                ):
                    """Retain actual counter endpoints separately from the terminal transition epochs."""
                    records.append((before, after, from_epoch, to_epoch))
                    if len(records) == 2:
                        source.complete_held_run()

                orchestrator.artifacts.write_transition_metrics = MagicMock(
                    side_effect=partial(record_transition, transitions, traffic.sender),
                )
                with (
                    patch.object(control, "apply_config_with_confirm", new=AsyncMock(side_effect=slow_apply)) as apply,
                    patch("kinetum_validation.scenario_context.asyncio.sleep", side_effect=clock.sleep),
                    patch("kinetum_validation.scenario_context.time", new=clock),
                    patch("kinetum_validation.scenarios.time", new=clock),
                ):
                    result = await run_commit_confirmed_test(orchestrator.scenario_context())
                self.assertTrue(result.passed, result.message)
                self.assertEqual(
                    [call.args[1] for call in apply.await_args_list],
                    [CONFIRM_TIMEOUT_MS, CONFIRM_TIMEOUT_ROLLBACK_MS],
                )
                self.assertEqual(result.confirmed_survival_elapsed_ms, 1000)
                self.assertTrue(result.timeout_rollback_occurred)
                self.assertEqual(len(transitions), 2)
                self.assertEqual(transitions[1][2:], (4, 5))
                self.assertIs(transitions[1][0], candidate if observed_candidate else confirmed)
                self.assertIs(transitions[1][1], forwarding)
                self.assertFalse(control.stats)
                self.assertFalse(traffic.capture_active)

    async def test_confirmation_rollback_rejects_contradictory_or_stalled_evidence(self) -> None:
        """Skipping the candidate read never weakens exact rollback identity or the authored bound."""
        restored = _stats("v2", 2, 5, 40, 40, 700, complete_from_epoch=4)
        candidate = _stats("v1", 1, 4, 30, 30, 600)
        cases = [
            ([replace(restored, runtime_generation=8)], "runtime/plan identity"),
            ([replace(restored, transition_plan_content_hash="foreign")], "runtime/plan identity"),
            ([replace(restored, transition_success_blocked=True)], "invalid evidence"),
            ([replace(restored, retirement_frozen=True)], "invalid evidence"),
            ([replace(restored, worker_counters=[])], "invalid evidence"),
            ([replace(restored, active_snapshot_id="foreign")], "terminal transition"),
            ([replace(restored, active_revision=3)], "terminal transition"),
            ([replace(restored, transition_active_validation_hash="foreign")], "terminal transition"),
            ([replace(restored, latest_terminal=None)], "terminal transition"),
            ([replace(restored, latest_terminal=replace(
                restored.latest_terminal, from_epoch=3,
            ))], "terminal transition"),
            ([replace(restored, latest_terminal=replace(restored.latest_terminal, to_epoch=6))], "terminal transition"),
            ([replace(restored, latest_terminal=replace(
                restored.latest_terminal, outcome="EPOCH_TRANSITION_OUTCOME_ABORTED",
            ))], "terminal transition"),
            ([_stats("v2", 2, 3, 30, 30, 600)], "terminal transition"),
            ([replace(candidate, active_revision=99)], "active telemetry disagree"),
            ([replace(candidate, transition_active_validation_hash="foreign")], "active telemetry disagree"),
            ([candidate] * 210, "exhausted its observation window"),
            ([restored] * 310, "exhausted its observation window"),
            ([candidate, replace(
                candidate, worker_counters=[replace(candidate.worker_counters[0], published_monotonic_ns=599)],
            )], "changed without publication"),
        ]
        for observations, diagnostic in cases:
            with (
                self.subTest(diagnostic=diagnostic, observed=observations[0]),
                tempfile.TemporaryDirectory() as directory,
            ):
                config = _config(Path(directory), ValidationTestType.COMMIT_CONFIRMED)
                traffic = _ScenarioTraffic(held_sender_run=1)
                clock = _ScenarioClock()
                control = _commit_control([
                    *[_stats("v2", 2, 3, 20, 20, 400)] * 11,
                    _stats("v2", 2, 3, 25, 25, 500),
                    *observations,
                ])
                orchestrator = ValidationOrchestrator(config)
                orchestrator._kinetumctl = control  # pylint: disable=protected-access
                orchestrator._traffic = traffic  # pylint: disable=protected-access
                orchestrator.artifacts.write_transition_metrics = MagicMock()
                with (
                    patch("kinetum_validation.scenario_context.asyncio.sleep", side_effect=clock.sleep),
                    patch("kinetum_validation.scenario_context.time", new=clock),
                    patch("kinetum_validation.scenarios.time", new=clock),
                ):
                    result = await run_commit_confirmed_test(orchestrator.scenario_context())
                self.assertFalse(result.passed)
                self.assertIn(diagnostic, result.message)
                self.assertFalse(result.timeout_rollback_occurred)
                orchestrator.artifacts.write_transition_metrics.assert_called_once()
                self.assertFalse(traffic.capture_active)

    async def test_confirmation_mutations_remain_bounded_by_the_traffic_window(self) -> None:
        """Every confirmation mutation cancels its pending call before scenario traffic is retired."""
        for phase in ("confirmed apply", "confirmation", "unconfirmed apply"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                config = _config(Path(directory), ValidationTestType.COMMIT_CONFIRMED)
                traffic = _ScenarioTraffic(held_sender_run=1)
                clock = _ScenarioClock()
                cancelled = asyncio.Event()
                control = _commit_control([
                    *[_stats("v2", 2, 3, 20, 20, 400)] * 2,
                    _stats("v2", 2, 3, 25, 25, 500),
                ])
                control.confirm_result.time_remaining_ms = 100
                original_apply = control.apply_config_with_confirm

                async def wait_until_cancelled(*_args, retired=cancelled):
                    """Keep an admitted command pending until its authored deadline cancels it."""
                    try:
                        await asyncio.Event().wait()
                    finally:
                        retired.set()

                async def apply_with_pending_phase(
                    config_file, confirm_timeout_ms, expected_revision, *,
                    selected_phase=phase, apply_request=original_apply, pending=wait_until_cancelled,
                ):
                    """Leave exactly the selected mutation in progress; other applies return exact authority."""
                    requested_phase = (
                        "confirmed apply" if confirm_timeout_ms == CONFIRM_TIMEOUT_MS else "unconfirmed apply"
                    )
                    if selected_phase == requested_phase:
                        await pending()
                    return await apply_request(config_file, confirm_timeout_ms, expected_revision)

                orchestrator = ValidationOrchestrator(config)
                orchestrator._kinetumctl = control  # pylint: disable=protected-access
                orchestrator._traffic = traffic  # pylint: disable=protected-access
                orchestrator.artifacts.write_transition_metrics = MagicMock()
                if phase == "confirmation":
                    control.confirm = AsyncMock(side_effect=wait_until_cancelled)
                with (
                    patch.object(
                        control, "apply_config_with_confirm", new=AsyncMock(side_effect=apply_with_pending_phase),
                    ),
                    patch("kinetum_validation.scenarios.COMMIT_CONFIRMED_TRAFFIC_S", 0.3),
                    patch("kinetum_validation.scenario_context.asyncio.sleep", side_effect=clock.sleep),
                    patch("kinetum_validation.scenario_context.time", new=clock),
                    patch("kinetum_validation.scenarios.time", new=clock),
                ):
                    result = await asyncio.wait_for(
                        run_commit_confirmed_test(orchestrator.scenario_context()), timeout=2.0,
                    )
                self.assertFalse(result.passed)
                self.assertIn(phase + " exceeded the traffic window", result.message)
                self.assertTrue(cancelled.is_set())
                self.assertFalse(traffic.capture_active)

    async def test_selective_and_full_rollback_prove_exact_active_content(self) -> None:
        """Hybrid content is ACL-v1 plus untouched v2 state; full is exact v1."""
        await self._check_rollback_capture(False)

    async def test_rollback_capture_failure_preserves_completed_control_evidence(self) -> None:
        """Selective and full rollback proof remains visible when packet capture later fails."""
        await self._check_rollback_capture(True)

    async def _check_rollback_capture(self, capture_failure: bool) -> None:
        """Drive exact selective and full restoration before the selected capture outcome."""
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory), ValidationTestType.ROLLBACK)
            traffic = _ScenarioTraffic(held_sender_run=1, capture_failure=capture_failure)
            baseline = _snapshot(
                "v1", 1, acl=b"acl-v1", nat=b"nat-v1", qos=b"qos-v1"
            )
            candidate = _snapshot(
                "v2", 2, acl=b"acl-v2", nat=b"nat-v2", qos=b"qos-v2"
            )
            candidate_modules = candidate.module_by_id()
            hybrid = ActiveSnapshot(
                snapshot_id="hybrid",
                revision=3,
                created_unix_ms=3,
                modules=(
                    _module("kinetum.acl", 3, b"acl-v1"),
                    candidate_modules["kinetum.nat44"],
                    candidate_modules["kinetum.qos"],
                ),
                description="hybrid",
                author="",
                parent_snapshot_id="v2",
                labels=(),
                content_hash=hashlib.sha256(b"hybrid").hexdigest(),
            )
            control = _ScenarioKinetumCtl([
                _stats("initial", 2, 1, 0, 0, 100),
                _stats("initial", 2, 1, 10, 10, 200),
                _stats("v1", 1, 2, 20, 20, 300),
                _stats("v2", 2, 3, 30, 30, 400),
                _stats("hybrid", 3, 4, 40, 40, 500),
                _stats("v1", 1, 5, 50, 50, 600),
            ])
            control.apply_results = [
                ApplyConfigResult(success=True, snapshot_id="v1", revision=1, epoch=2),
                ApplyConfigResult(success=True, snapshot_id="v2", revision=2, epoch=3),
            ]
            control.rollback_results = [
                (
                    ("kinetum.acl",),
                    RollbackResult(
                        success=True,
                        new_snapshot_id="hybrid",
                        new_revision=3,
                        epoch=4,
                    ),
                ),
                (
                    (),
                    RollbackResult(
                        success=True,
                        new_snapshot_id="v1",
                        new_revision=1,
                        epoch=5,
                    ),
                ),
            ]
            control.active_snapshots = [baseline, candidate, hybrid, baseline]
            orchestrator = ValidationOrchestrator(config)
            orchestrator._kinetumctl = control  # pylint: disable=protected-access
            orchestrator._traffic = traffic  # pylint: disable=protected-access
            transition_count = 0

            def record_transition(*_args, **_keywords) -> None:
                """Complete traffic only after all four transitions are recorded."""
                nonlocal transition_count
                transition_count += 1
                if transition_count == 4:
                    traffic.sender.complete_held_run()

            orchestrator.artifacts.write_transition_metrics = MagicMock(  # pylint: disable=protected-access
                side_effect=record_transition
            )

            with patch(
                "kinetum_validation.scenario_context.asyncio.sleep",
                new=AsyncMock(),
            ):
                result = await run_rollback_test(orchestrator.scenario_context())  # pylint: disable=protected-access

            self.assertEqual(result.passed, not capture_failure, result.message)
            self.assertTrue(result.selective_rollback_success)
            self.assertTrue(result.full_rollback_success)
            self.assertEqual(
                orchestrator.artifacts.write_transition_metrics.call_count,  # pylint: disable=protected-access
                4,
            )
            evidence = json.loads((config.output_dir / "rollback_capture.traffic.json").read_text())
            self.assertEqual(evidence["sender"]["tx_count"], 100)
            if capture_failure:
                self.assertIn("capture overflow", result.message)
                self.assertIsNone(evidence["analysis"])

    async def test_guardrails_uses_dedicated_deterministic_degradation(self) -> None:
        """Automatic rollback follows observed drop and throughput threshold legs."""
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory), ValidationTestType.GUARDRAILS)
            candidate_id = "guardrails-degradation"
            traffic = _ScenarioTraffic(held_sender_run=1)
            control = _ScenarioKinetumCtl([
                _stats("v1", 1, 1, 0, 0, 100, health=True),
                _stats("v1", 1, 1, 100, 100, 1100, health=True),
                _stats(
                    "v1", 1, 3, 300, 150, 2500,
                    dropped_packets=150, complete_from_epoch=2,
                ),
            ])
            control.apply_results = [ApplyConfigResult(
                success=True, snapshot_id=candidate_id, revision=2, epoch=2
            )]
            control.guardrails_reads = [
                parse_guardrails_json(json.dumps(armed_guardrails_payload())),
                parse_guardrails_json(json.dumps(rollback_guardrails_payload())),
            ]
            orchestrator = ValidationOrchestrator(config)
            orchestrator._kinetumctl = control  # pylint: disable=protected-access
            orchestrator._traffic = traffic  # pylint: disable=protected-access
            orchestrator.artifacts.write_transition_metrics = MagicMock()  # pylint: disable=protected-access

            context = orchestrator.scenario_context()
            wait_for_active_snapshot = context.wait_for_active_snapshot

            async def complete_after_convergence(*args, **keywords) -> StatsResult:
                """Complete candidate traffic after exact rollback convergence."""
                observed = await wait_for_active_snapshot(*args, **keywords)
                traffic.sender.complete_held_run()
                return observed

            with patch.object(
                ScenarioContext, "wait_for_active_snapshot",
                new=AsyncMock(side_effect=complete_after_convergence),
            ):
                result = await run_guardrails_test(context)

            self.assertTrue(result.passed, result.message)
            self.assertEqual(result.candidate_snapshot_id, candidate_id)
            self.assertEqual(control.guardrails_calls, [True, False])
            self.assertEqual(traffic.sender.calls, 1)
            self.assertTrue((config.output_dir / "guardrails_evaluation.json").is_file())
            orchestrator.artifacts.write_transition_metrics.assert_called_once()  # pylint: disable=protected-access

    async def test_cleanup_attempts_every_owner_and_reports_child_exit_failure(self) -> None:
        """An already-exited child still fails the run after every teardown is attempted."""
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory), ValidationTestType.STANDARD)
            orchestrator = ValidationOrchestrator(config)
            traffic = MagicMock()
            traffic.teardown = AsyncMock(side_effect=RuntimeError("traffic teardown failed"))
            backend = MagicMock()
            backend.teardown = AsyncMock()
            supervisor = MagicMock()
            supervisor.stop_all = AsyncMock(side_effect=RuntimeError(
                "kinetum_photon exited before harness-requested shutdown: 1"
            ))
            orchestrator._traffic = traffic  # pylint: disable=protected-access
            orchestrator._backend = backend  # pylint: disable=protected-access
            orchestrator._supervisor = supervisor  # pylint: disable=protected-access

            with self.assertRaises(RuntimeError) as raised:
                await orchestrator._cleanup()  # pylint: disable=protected-access

            traffic.teardown.assert_awaited_once()
            backend.teardown.assert_awaited_once()
            supervisor.stop_all.assert_awaited_once()
            self.assertIn("traffic teardown failed", str(raised.exception))
            self.assertIn("exited before harness-requested shutdown: 1", str(raised.exception))
            self.assertTrue(str(raised.exception).startswith("validation cleanup reported failures:"))

    async def test_unexpected_orchestration_error_cannot_become_partial_success(self) -> None:
        """Execution evidence and every cleanup owner survive joint failure."""
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory), ValidationTestType.STANDARD)
            orchestrator = ValidationOrchestrator(config)
            orchestrator._setup = AsyncMock(return_value=True)  # pylint: disable=protected-access
            orchestrator._cleanup = AsyncMock(  # pylint: disable=protected-access
                side_effect=RuntimeError("injected cleanup failure")
            )

            with patch(
                "kinetum_validation.orchestrator.run_packet_test",
                new=AsyncMock(side_effect=RuntimeError("injected orchestration failure")),
            ), self.assertRaises(RuntimeError) as raised:
                await orchestrator.run()

            self.assertIn("injected orchestration failure", str(raised.exception))
            self.assertIn("injected cleanup failure", str(raised.exception))
            orchestrator._cleanup.assert_awaited_once()  # pylint: disable=protected-access

            sender = MagicMock()
            sender.abort = AsyncMock(side_effect=AssertionError("abort failure"))
            sender.cleanup.side_effect = ValueError("local cleanup failure")
            traffic = MagicMock()
            traffic.stop_capture = AsyncMock(side_effect=OSError("capture failure"))
            orchestrator._traffic = traffic  # pylint: disable=protected-access
            with self.assertRaises(RuntimeError) as raised:
                await orchestrator.scenario_context().retire_scenario_traffic("scenario", sender, capture_active=True)

            self.assertIn("abort failure", str(raised.exception))
            self.assertIn("local cleanup failure", str(raised.exception))
            self.assertIn("capture failure", str(raised.exception))
            sender.abort.assert_awaited_once()
            sender.cleanup.assert_called_once()
            traffic.stop_capture.assert_awaited_once()

    def test_deployment_registry_separates_transition_and_degradation_facts(self) -> None:
        """Module deployments own explicit distinct guardrails fixtures."""
        passthrough = DEPLOYMENT_SPECS[DeploymentMode.PASSTHROUGH]
        self.assertIsNone(passthrough.config_snapshot_v2)
        self.assertIsNone(passthrough.guardrails_degradation_snapshot)
        for mode in (
            DeploymentMode.FAN_IN_EDGE_GATEWAY,
        ):
            with self.subTest(mode=mode):
                spec = DEPLOYMENT_SPECS[mode]
                self.assertIsNotNone(spec.config_snapshot_v2)
                self.assertIsNotNone(spec.guardrails_degradation_snapshot)
                self.assertNotEqual(
                    spec.config_snapshot_v2,
                    spec.guardrails_degradation_snapshot,
                )
