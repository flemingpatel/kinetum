"""Capture completion requires tcpdump's own loss evidence, independent of packet loss policy."""

import asyncio
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from kinetum_validation.config.types import (
    AnalysisResult,
    BackendConfig,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    PacketConfig,
    ProcessConfig,
    TestConfig as ValidationConfig,
)
from kinetum_validation.traffic.native_tap import NativeTapTrafficDriver


class _CaptureProcess:
    """Keep stderr live until the capture owner requests a normal stop."""

    def __init__(self, statistics: bytes):
        """Retain the terminal statistics and publish only readiness initially."""
        self.pid = 1234
        self.returncode = None
        self.stderr = asyncio.StreamReader()
        self.stderr.feed_data(b"tcpdump: listening on neb_tx, link-type EN10MB\n")
        self.statistics = statistics
        self.stopped = asyncio.Event()
        self.stop_requested = asyncio.Event()
        self.hold_first_stop = False
        self.terminate_calls = 0

    def terminate(self):
        """Publish final statistics and terminal process state exactly once."""
        self.terminate_calls += 1
        self.stop_requested.set()
        if self.hold_first_stop and self.terminate_calls == 1:
            return
        if self.returncode is None:
            self.stderr.feed_data(self.statistics)
            self.stderr.feed_eof()
            self.returncode = 0
            self.stopped.set()

    async def wait(self) -> int:
        """Wait for the same stop edge used by the stderr producer."""
        await self.stopped.wait()
        return self.returncode

    def kill(self):
        """Model forced retirement without fabricating tcpdump's final report."""
        if self.returncode is None:
            self.stderr.feed_eof()
            self.returncode = -9
            self.stopped.set()


def _driver() -> NativeTapTrafficDriver:
    """Construct the canonical local driver without launching native helpers."""
    profile = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(BackendType.DPDK_TAP)
    return NativeTapTrafficDriver(
        ValidationConfig(
            process=ProcessConfig(
                runtime_root=Path("/opt/kinetum"), validation_root=Path("/var/tmp/kinetum-validation"),
            ),
            deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
            backend=BackendConfig(backend_type=BackendType.DPDK_TAP, ports=profile.ports),
        ),
        Path("/unused/kinetum_tap_sender"),
        Path("/unused/kinetum_tap_analyzer"),
    )


def _statistics(captured: int = 100, received: int = 100, drops: int = 0) -> bytes:
    """Produce one complete tcpdump terminal report with explicit counter relationships."""
    return (
        f"{captured} packets captured\n{received} packets received by filter\n"
        f"{drops} packets dropped by kernel\n"
    ).encode("ascii")


class TestNativeTapCapture(unittest.IsolatedAsyncioTestCase):
    """Use the public capture lifecycle to verify native loss evidence and cleanup."""

    async def test_complete_delivery_matches_saved_packet_count(self):
        """Immediate delivery, final counters, and the saved PCAP must agree before analysis succeeds."""
        process = _CaptureProcess(_statistics())
        driver = _driver()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("kinetum_validation.traffic.native_tap.require_system_executable", return_value="/usr/bin/tcpdump"),
            patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn,
            patch("kinetum_validation.traffic.native_tap.PacketAnalyzer") as analyzer,
        ):
            capture = Path(directory) / "capture.pcap"
            analyzer.return_value.analyze.return_value = AnalysisResult(total_rx=100)
            try:
                await driver.start_capture(capture, "udp")
                with self.assertRaisesRegex(RuntimeError, "does not own"):
                    await driver.analyze_capture(capture, 100)
                await driver.stop_capture()
                self.assertEqual(process.returncode, 0)
                self.assertEqual(spawn.await_args.kwargs["env"]["LC_ALL"], "C")
                self.assertIn("--immediate-mode", spawn.await_args.args)
                arguments = spawn.await_args.args
                self.assertEqual(arguments[arguments.index("-s") + 1], "64")
                evidence = json.loads(capture.with_suffix(".capture.json").read_text())
                self.assertEqual(evidence, {
                    "returncode": 0, "error": None,
                    "statistics": {"captured": 100, "received_by_filter": 100, "dropped_by_kernel": 0},
                })
                with self.assertRaisesRegex(RuntimeError, "does not own"):
                    await driver.analyze_capture(Path(directory) / "other.pcap", 100)
                result = await driver.analyze_capture(capture, 100)
                self.assertEqual(result.total_rx, 100)
                analyzer.assert_called_once_with(
                    pcap_file=capture, analyzer_bin=Path("/unused/kinetum_tap_analyzer"),
                    expected_count=100, stream_count=2,
                )
                with self.assertRaisesRegex(RuntimeError, "does not own"):
                    await driver.analyze_capture(capture, 100)
            finally:
                await driver.teardown()

    async def test_capture_bound_covers_size_sweep_and_transition_frames(self):
        """A finite capture limit covers every authored frame, including a larger transition profile."""
        for packet, expected in (
            (PacketConfig(packet_size=128), 128),
            (PacketConfig(packet_size=64, all_sizes=True), 1514),
            (PacketConfig(packet_size=9000), 9000),
            (PacketConfig(packet_size=9000, all_sizes=True), 9000),
        ):
            with (
                self.subTest(packet=packet), tempfile.TemporaryDirectory() as directory,
                patch(
                    "kinetum_validation.traffic.native_tap.require_system_executable", return_value="/usr/bin/tcpdump",
                ),
                patch(
                    "asyncio.create_subprocess_exec", new=AsyncMock(return_value=_CaptureProcess(_statistics())),
                ) as spawn,
            ):
                driver = _driver()
                driver.config = replace(driver.config, packet=packet)
                try:
                    await driver.start_capture(Path(directory) / "capture.pcap", "udp")
                    arguments = spawn.await_args.args
                    self.assertEqual(arguments[arguments.index("-s") + 1], str(expected))
                    self.assertEqual(arguments[arguments.index("-B") + 1], "131072")
                    self.assertIn("--immediate-mode", arguments)
                    await driver.stop_capture()
                finally:
                    await driver.teardown()

    async def test_zero_frame_bound_cannot_select_unbounded_capture(self):
        """An invalid frame size rejects before launching tcpdump with its special zero snap length."""
        driver = _driver()
        driver.config = replace(driver.config, packet=PacketConfig(packet_size=0))
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("kinetum_validation.traffic.native_tap.require_system_executable", return_value="/usr/bin/tcpdump"),
            patch("asyncio.create_subprocess_exec") as spawn,
        ):
            with self.assertRaisesRegex(RuntimeError, "positive frame-size bound"):
                await driver.start_capture(Path(directory) / "capture.pcap", "udp")
            spawn.assert_not_called()

    async def test_lost_missing_or_malformed_capture_evidence_rejects(self):
        """A zero child exit never hides capture drops or absent trustworthy statistics."""
        for statistics, message in (
            (_statistics(drops=1), "reported packet drops"),
            (_statistics() + b"2 packets dropped by interface\n", "reported packet drops"),
            (_statistics(drops=2) + b"0 packets dropped by kernel\n", "capture count regressed"),
            (_statistics() + b"99 packets captured\n", "capture count regressed"),
            (_statistics() + b"99 packets received by filter\n", "capture count regressed"),
            (_statistics(captured=889584, received=891145), "capture is incomplete"),
            (_statistics(captured=101), "capture is incomplete"),
            (b"100 packets captured\n", "omitted capture counters"),
            (b"0 packets dropped by kernel\n", "omitted capture counters"),
            (b"unknown packets dropped by kernel\n", "malformed capture count"),
            (b"4294967296 packets dropped by kernel\n", "malformed capture count"),
            (b"unknown packets captured\n", "malformed capture count"),
            (b"4294967296 packets received by filter\n", "malformed capture count"),
        ):
            with (
                self.subTest(statistics=statistics), tempfile.TemporaryDirectory() as directory,
                patch(
                    "kinetum_validation.traffic.native_tap.require_system_executable", return_value="/usr/bin/tcpdump",
                ),
            ):
                driver = _driver()
                failed = _CaptureProcess(statistics)
                recovered = _CaptureProcess(_statistics(0, 0))
                empty = _CaptureProcess(b"")
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(side_effect=[failed, recovered, empty])):
                    try:
                        await driver.start_capture(Path(directory) / "failed.pcap", "udp")
                        with self.assertRaisesRegex(RuntimeError, message):
                            await driver.stop_capture()
                        self.assertEqual(failed.returncode, 0)
                        evidence = json.loads((Path(directory) / "failed.capture.json").read_text())
                        self.assertIn(message, evidence["error"])
                        self.assertEqual(evidence["returncode"], 0)
                        with self.assertRaisesRegex(RuntimeError, "does not own"):
                            await driver.analyze_capture(Path(directory) / "failed.pcap", 100)
                        # A fresh session proves the failed capture released its owner and counters.
                        await driver.start_capture(Path(directory) / "recovered.pcap", "udp")
                        await driver.stop_capture()
                        await driver.start_capture(Path(directory) / "empty.pcap", "udp")
                        with self.assertRaisesRegex(RuntimeError, "omitted capture counters"):
                            await driver.stop_capture()
                    finally:
                        await driver.teardown()

    async def test_saved_packet_count_must_match_terminal_capture_count(self):
        """A truncated or enlarged PCAP cannot be accepted despite a clean tcpdump report."""
        for saved_count in (99, 101):
            with (
                self.subTest(saved_count=saved_count), tempfile.TemporaryDirectory() as directory,
                patch(
                    "kinetum_validation.traffic.native_tap.require_system_executable", return_value="/usr/bin/tcpdump",
                ),
                patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_CaptureProcess(_statistics()))),
                patch("kinetum_validation.traffic.native_tap.PacketAnalyzer") as analyzer,
            ):
                driver = _driver()
                capture = Path(directory) / "capture.pcap"
                analyzer.return_value.analyze.return_value = AnalysisResult(total_rx=saved_count)
                try:
                    await driver.start_capture(capture, "udp")
                    await driver.stop_capture()
                    with self.assertRaisesRegex(RuntimeError, "PCAP record count disagrees"):
                        await driver.analyze_capture(capture, 100)
                    with self.assertRaisesRegex(RuntimeError, "does not own"):
                        await driver.analyze_capture(capture, 100)
                    self.assertTrue(capture.with_suffix(".capture.json").is_file())
                finally:
                    await driver.teardown()

    async def test_cancelled_stop_retires_child_without_authorizing_analysis(self):
        """Cancellation collects the child and its evidence but never publishes successful completion."""
        process = _CaptureProcess(_statistics())
        process.hold_first_stop = True
        driver = _driver()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("kinetum_validation.traffic.native_tap.require_system_executable", return_value="/usr/bin/tcpdump"),
            patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)),
        ):
            capture = Path(directory) / "capture.pcap"
            await driver.start_capture(capture, "udp")
            stopping = asyncio.create_task(driver.stop_capture())
            try:
                await asyncio.wait_for(process.stop_requested.wait(), timeout=1.0)
                stopping.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await stopping
                self.assertEqual(process.returncode, 0)
                evidence = json.loads(capture.with_suffix(".capture.json").read_text())
                self.assertEqual(evidence["error"], "CancelledError")
                self.assertEqual(evidence["statistics"]["captured"], 100)
                with self.assertRaisesRegex(RuntimeError, "does not own"):
                    await driver.analyze_capture(capture, 100)
            finally:
                if not stopping.done():
                    stopping.cancel()
                await asyncio.gather(stopping, return_exceptions=True)
                await driver.teardown()

    async def test_existing_capture_evidence_is_never_overwritten(self):
        """A foreign completion record rejects before tcpdump is launched."""
        with tempfile.TemporaryDirectory() as directory, patch("asyncio.create_subprocess_exec") as spawn:
            capture = Path(directory) / "capture.pcap"
            evidence = capture.with_suffix(".capture.json")
            evidence.write_text("owned\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "capture output already exists"):
                await _driver().start_capture(capture, "udp")
            spawn.assert_not_called()
            self.assertEqual(evidence.read_text(), "owned\n")

    async def test_premature_and_forced_exit_never_authorize_analysis(self):
        """Even complete counters cannot excuse premature exit, and forced exit retains missing evidence."""
        for premature in (True, False):
            process = _CaptureProcess(_statistics())
            process.hold_first_stop = not premature
            with (
                self.subTest(premature=premature), tempfile.TemporaryDirectory() as directory,
                patch(
                    "kinetum_validation.traffic.native_tap.require_system_executable", return_value="/usr/bin/tcpdump",
                ),
                patch("kinetum_validation.traffic.native_tap._CAPTURE_RETIRE_TIMEOUT_S", 0.01),
                patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)),
            ):
                driver = _driver()
                capture = Path(directory) / "capture.pcap"
                try:
                    await driver.start_capture(capture, "udp")
                    if premature:
                        process.terminate()
                    message = "before harness-requested" if premature else "exited uncleanly"
                    with self.assertRaisesRegex(RuntimeError, message):
                        await driver.stop_capture()
                    evidence = json.loads(capture.with_suffix(".capture.json").read_text())
                    self.assertEqual(evidence["returncode"], 0 if premature else -9)
                    self.assertIn(message, evidence["error"])
                    if not premature:
                        self.assertEqual(evidence["statistics"], {})
                    with self.assertRaisesRegex(RuntimeError, "does not own"):
                        await driver.analyze_capture(capture, 100)
                finally:
                    await driver.teardown()

    async def test_completion_artifact_failure_retires_capture_and_preserves_foreign_file(self):
        """A raced output name cannot publish completion or erase another owner's evidence."""
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("kinetum_validation.traffic.native_tap.require_system_executable", return_value="/usr/bin/tcpdump"),
            patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_CaptureProcess(_statistics()))),
        ):
            driver = _driver()
            capture = Path(directory) / "capture.pcap"
            try:
                await driver.start_capture(capture, "udp")
                evidence = capture.with_suffix(".capture.json")
                evidence.write_text("foreign\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "evidence could not be retained"):
                    await driver.stop_capture()
                with self.assertRaisesRegex(RuntimeError, "does not own"):
                    await driver.analyze_capture(capture, 100)
                self.assertEqual(evidence.read_text(), "foreign\n")
            finally:
                await driver.teardown()
