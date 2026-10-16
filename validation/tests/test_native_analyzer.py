"""Exact native capture parsing, per-input verdicts, and retained diagnostic evidence."""

from __future__ import annotations

import copy
import asyncio
import json
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import AsyncMock, MagicMock, patch

from kinetum_validation.config.types import (
    AnalysisResult, BackendConfig, BackendType, DEPLOYMENT_SPECS, DeploymentMode,
    PacketStats, ProcessConfig, TestConfig as ValidationConfig, TrafficDriverType,
)
from kinetum_validation.engine.analyzer import PacketAnalyzer
from kinetum_validation.report.artifacts import RunArtifacts
from kinetum_validation.scenario_context import ScenarioContext

from .traffic_fixtures import complete_native_analysis


def _capture_reply() -> dict:
    """Return an independently authored two-input capture with interleaved generations."""
    return {
        "total_rx": 4, "valid": 4, "invalid": 0, "duplicates": 0, "out_of_order": 0,
        "transition_seq": 2, "tag_transition_count": 2, "max_gap": 0,
        "loss_pct": 0.0, "missing_count": 0,
        "latency": {"avg": 10.0, "min": 10.0, "max": 10.0, "p50": 10.0, "p99": 10.0, "count": 4},
        "tag_counts": {"1": 2, "2": 2},
        "streams": [
            {
                "stream_index": 0, "expected_count": 2, "valid": 2, "duplicates": 0,
                "out_of_order": 0, "missing_count": 0, "transition_seq": 2,
                "tag_transition_count": 1, "first_tag": 1, "last_tag": 2,
                "tag_counts": {"1": 1, "2": 1},
            },
            {
                "stream_index": 1, "expected_count": 2, "valid": 2, "duplicates": 0,
                "out_of_order": 0, "missing_count": 0, "transition_seq": 3,
                "tag_transition_count": 1, "first_tag": 1, "last_tag": 2,
                "tag_counts": {"1": 1, "2": 1},
            },
        ],
    }


def _context(root: Path, backend: BackendType) -> ScenarioContext:
    """Bind the exact authored ingress population for the selected traffic driver."""
    profile = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(backend)
    config = ValidationConfig(
        process=ProcessConfig(runtime_root=root / "runtime", validation_root=root / "kit"),
        backend=BackendConfig(backend_type=backend, ports=profile.ports), output_dir=root,
    )
    reporter = MagicMock()
    return ScenarioContext(config, reporter, None, None, None, RunArtifacts(root, reporter))


@contextmanager
def _temporary_workspace() -> Iterator[Path]:
    """Own the test's exact file paths through unittest's cleanup stack."""
    with tempfile.TemporaryDirectory() as directory:
        yield Path(directory).resolve()


class TestNativeAnalyzer(unittest.TestCase):
    """Native output is admitted only with exact input membership and consistent totals."""

    def setUp(self) -> None:
        """Create exact local file identities while mocking only native execution."""
        self.root = self.enterContext(_temporary_workspace())
        self.capture = self.root / "capture.pcap"
        self.capture.write_bytes(b"")
        self.binary = self.root / "kinetum_tap_analyzer"
        self.binary.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
        self.binary.chmod(0o700)

    def parse(self, reply: dict, expected: int = 4, streams: int = 2) -> AnalysisResult:
        """Pass one native JSON observation through the production reader."""
        with patch(
            "kinetum_validation.engine.analyzer.subprocess.run",
            return_value=CompletedProcess([], 0, json.dumps(reply), ""),
        ) as invoke:
            result = PacketAnalyzer(self.capture, self.binary, expected, streams).analyze()
        self.assertEqual(invoke.call_args.args[0], [
            str(self.binary), "--pcap", str(self.capture), "--expected", str(expected),
            "--stream-count", str(streams),
        ])
        return result

    def test_per_input_observations_are_mandatory_and_exact(self) -> None:
        """Absent, duplicate, foreign, or contradictory rows never become a single-stream default."""
        admitted = self.parse(_capture_reply())
        self.assertEqual(admitted.out_of_order, 0)
        self.assertEqual(admitted.tag_transition_count, 2)
        self.assertEqual(admitted.transition_seq, 2)
        self.assertEqual(admitted.max_gap, 0)
        self.assertEqual(admitted.streams[1].last_tag, 2)

        malformed = []
        absent = _capture_reply()
        del absent["streams"]
        malformed.append(absent)
        for field, value in (
            ("streams", []), ("streams", None), ("out_of_order", 1),
            ("tag_transition_count", 1), ("transition_seq", 3), ("max_gap", 1),
            ("valid", 5), ("tag_counts", {"01": 2, "2": 2}),
        ):
            row = _capture_reply()
            row[field] = value
            malformed.append(row)
        for field, value in (
            ("stream_index", 0), ("stream_index", 2), ("expected_count", 3),
            ("missing_count", 1), ("valid", 1), ("duplicates", 1),
            ("transition_seq", 2), ("transition_seq", 5), ("first_tag", None),
            ("last_tag", 1), ("tag_counts", {"2": 2}), ("tag_transition_count", 0),
        ):
            row = _capture_reply()
            row["streams"][1][field] = value
            malformed.append(row)
        for row in malformed:
            with self.subTest(reply=row), self.assertRaisesRegex(RuntimeError, "malformed evidence"):
                self.parse(row)

    def test_duplicate_cannot_replace_one_missing_identity(self) -> None:
        """Four receipts with one duplicate still contain only three of four expected identities."""
        reply = _capture_reply()
        reply.update(valid=3, duplicates=1, transition_seq=2, tag_transition_count=1,
                     missing_count=1, max_gap=1, loss_pct=25.0, tag_counts={"1": 2, "2": 1})
        reply["latency"]["count"] = 3
        reply["streams"][0]["duplicates"] = 1
        reply["streams"][1].update(
            valid=1, missing_count=1, transition_seq=-1, tag_transition_count=0,
            last_tag=1, tag_counts={"1": 1},
        )
        result = self.parse(reply)
        self.assertEqual(result.valid, 3)
        self.assertEqual(result.loss_pct(4), 25.0)
        self.assertEqual(result.missing_count, 1)
        self.assertEqual(result.duplicates, 1)
        false_complete = copy.deepcopy(reply)
        false_complete.update(missing_count=0, max_gap=0, loss_pct=0.0)
        with self.assertRaisesRegex(RuntimeError, "malformed evidence"):
            self.parse(false_complete)

    def test_invalid_populations_reject_before_execution(self) -> None:
        """Unknown stream counts and non-integer packet counts cannot launch analysis."""
        for expected, streams in ((4, 0), (4, 65), (4, True), (-1, 2), (True, 2), (1 << 32, 2)):
            with self.subTest(expected=expected, streams=streams), patch(
                "kinetum_validation.engine.analyzer.subprocess.run",
            ) as invoke, self.assertRaisesRegex(RuntimeError, "out of range"):
                PacketAnalyzer(self.capture, self.binary, expected, streams).analyze()
            invoke.assert_not_called()

    def test_empty_declared_inputs_remain_explicit(self) -> None:
        """An empty capture retains every authored row without packet or latency evidence."""
        reply = _capture_reply()
        reply.update(total_rx=0, valid=0, transition_seq=-1, tag_transition_count=0, tag_counts={}, loss_pct=None)
        reply["latency"] = None
        for row in reply["streams"]:
            row.update(expected_count=0, valid=0, transition_seq=-1, tag_transition_count=0,
                       first_tag=None, last_tag=None, tag_counts={})
        result = self.parse(reply, expected=0)
        self.assertEqual(len(result.streams), 2)
        self.assertIsNone(result.latency_stats())
        self.assertIsNone(_context(self.root, BackendType.DPDK_TAP).measured_average_latency(result))

    def test_empty_capture_retains_measured_total_loss_without_latency(self) -> None:
        """No received packets means measured loss and unavailable latency, not an analyzer failure."""
        reply = _capture_reply()
        reply.update(total_rx=0, valid=0, transition_seq=-1, tag_transition_count=0,
                     tag_counts={}, loss_pct=100.0, missing_count=4, max_gap=4, latency=None)
        for row in reply["streams"]:
            row.update(valid=0, missing_count=2, transition_seq=-1, tag_transition_count=0,
                       first_tag=None, last_tag=None, tag_counts={})
        result = self.parse(reply)
        self.assertEqual(result.loss_pct(4), 100.0)
        self.assertIsNone(result.latency_stats())
        self.assertIsNone(_context(self.root, BackendType.DPDK_TAP).measured_average_latency(result))

    def test_verdict_requires_input_order_and_preserves_driver_availability(self) -> None:
        """TAP requires complete input evidence; TRex counters cannot claim packet ordering."""
        sender = PacketStats(
            tx_count=4, generation_tag_counts={1: 2, 2: 2}, start_time=1.0, end_time=2.0, duration_s=1.0,
        )
        native = _context(self.root, BackendType.DPDK_TAP)
        analysis = self.parse(_capture_reply())
        self.assertTrue(native.traffic_observation_is_clean(sender, analysis))
        damaged = replace(analysis, streams=(replace(analysis.streams[0], out_of_order=1), analysis.streams[1]))
        self.assertFalse(native.traffic_observation_is_clean(sender, damaged))
        counter_only = AnalysisResult(total_rx=4, valid=4, tag_counts={1: 2, 2: 2})
        self.assertFalse(native.traffic_observation_is_clean(sender, counter_only))
        remote = _context(self.root, BackendType.DPDK_PCI)
        self.assertTrue(remote.traffic_observation_is_clean(sender, counter_only))
        self.assertIsNone(counter_only.out_of_order)
        self.assertFalse(remote.traffic_observation_is_clean(sender, analysis))

    def test_failed_traffic_evidence_retains_the_actual_sender_and_input_rows(self) -> None:
        """A failed verdict retains order violations and send errors without repairing observations."""
        context = _context(self.root, BackendType.DPDK_TAP)
        analysis = complete_native_analysis(((0, 4),), 2)
        analysis.streams = (replace(analysis.streams[0], out_of_order=1), analysis.streams[1])
        sender = PacketStats(
            tx_count=4, errors=1, generation_tag_counts={0: 4}, start_time=1.0, end_time=2.0, duration_s=1.0,
        )
        self.assertFalse(context.traffic_observation_is_clean(sender, analysis))
        context.artifacts.write_traffic_evidence(self.capture, TrafficDriverType.NATIVE_TAP, sender, analysis)
        retained = json.loads(self.capture.with_suffix(".traffic.json").read_text())
        self.assertEqual(retained["sender"]["errors"], 1)
        self.assertEqual(retained["analysis"]["out_of_order"], 1)
        self.assertEqual(retained["analysis"]["streams"][0]["out_of_order"], 1)
        self.assertEqual(retained["analysis"]["max_gap"], 0)
        with self.assertRaises(FileExistsError):
            context.artifacts.write_traffic_evidence(self.capture, TrafficDriverType.NATIVE_TAP, sender, analysis)


class TestCaptureCompletionEvidence(unittest.IsolatedAsyncioTestCase):
    """Capture rejection retains source facts without manufacturing analyzed packet counters."""

    async def test_capture_and_analysis_failure_preserve_sender_without_zero_substitution(self) -> None:
        """Both failure edges keep the actual source record and propagate the original diagnostic."""
        for failed_operation in ("stop", "analysis"):
            with self.subTest(failed_operation=failed_operation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                capture = root / "capture.pcap"
                driver = MagicMock()
                driver.stop_capture = AsyncMock(
                    side_effect=RuntimeError("capture drops") if failed_operation == "stop" else None,
                )
                driver.analyze_capture = AsyncMock(side_effect=RuntimeError("invalid pcap"))
                context = replace(_context(root, BackendType.DPDK_TAP), traffic=driver)
                sender = PacketStats(
                    tx_count=4, errors=1, generation_tag_counts={0: 4}, start_time=1.0, end_time=2.0, duration_s=1.0,
                )
                diagnostic = "capture drops" if failed_operation == "stop" else "invalid pcap"
                with self.assertRaisesRegex(RuntimeError, diagnostic):
                    await context.complete_capture(capture, sender)
                retained = json.loads(capture.with_suffix(".traffic.json").read_text())
                self.assertEqual(retained["sender"]["tx_count"], 4)
                self.assertEqual(retained["sender"]["errors"], 1)
                self.assertEqual(retained["sender"]["start_time"], 1.0)
                self.assertIsNone(retained["analysis"])
                if failed_operation == "stop":
                    driver.analyze_capture.assert_not_awaited()
                else:
                    driver.analyze_capture.assert_awaited_once_with(pcap_file=capture, expected_count=4)

    async def test_cancelled_capture_preserves_sender_and_propagates_cancellation(self) -> None:
        """Cancellation cannot become an empty successful analysis after diagnostic publication."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "capture.pcap"
            driver = MagicMock(stop_capture=AsyncMock(side_effect=asyncio.CancelledError))
            driver.analyze_capture = AsyncMock()
            context = replace(_context(root, BackendType.DPDK_TAP), traffic=driver)
            sender = PacketStats(tx_count=4, generation_tag_counts={0: 4}, start_time=1.0, end_time=2.0, duration_s=1.0)
            with self.assertRaises(asyncio.CancelledError):
                await context.complete_capture(capture, sender)
            driver.analyze_capture.assert_not_awaited()
            retained = json.loads(capture.with_suffix(".traffic.json").read_text())
            self.assertEqual(retained["sender"]["tx_count"], 4)
            self.assertIsNone(retained["analysis"])

    async def test_capture_and_artifact_failures_remain_distinguishable(self) -> None:
        """A failed diagnostic write reports both causes and preserves cancellation when present."""
        for failure in (RuntimeError("capture drops"), asyncio.CancelledError()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                driver = MagicMock(stop_capture=AsyncMock(side_effect=failure))
                context = replace(_context(root, BackendType.DPDK_TAP), traffic=driver)
                sender = PacketStats(
                    tx_count=4, generation_tag_counts={0: 4}, start_time=1.0, end_time=2.0, duration_s=1.0,
                )
                with (
                    patch.object(context.artifacts, "write_traffic_evidence", side_effect=OSError("disk full")),
                    patch.object(context.reporter, "print_warning") as warning,
                ):
                    if isinstance(failure, asyncio.CancelledError):
                        with self.assertRaises(asyncio.CancelledError):
                            await context.complete_capture(root / "capture.pcap", sender)
                        self.assertIn("disk full", warning.call_args.args[0])
                    else:
                        with self.assertRaisesRegex(RuntimeError, "completion=capture drops; evidence=disk full"):
                            await context.complete_capture(root / "capture.pcap", sender)
