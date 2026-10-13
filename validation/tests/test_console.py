"""Verify traffic-limit reporting and exact diagnostic presentation."""

import io
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stderr
from pathlib import Path

from kinetum_validation.config.types import (
    CommitConfirmedTestResult, DeploymentMode, EpochTestResult, GuardrailsTestResult,
    NatExchangeResult, PacketConfig, ProcessConfig, RollbackTestResult, StatsValidationResult,
    TestConfig as ValidationConfig, TestResult as PacketTestResult, TestType as ValidationTestType,
)
from kinetum_validation.orchestrator import TestOrchestrator as ValidationOrchestrator
from kinetum_validation.report.console import ConsoleReporter
from kinetum_validation.config import logger


class ConsoleReporterTest(unittest.TestCase):
    """Check duration and count reporting without launching traffic."""

    @staticmethod
    def _configuration(packet: PacketConfig) -> str:
        """Render a configuration with explicit inert resource roots."""
        config = ValidationConfig(
            process=ProcessConfig(
                runtime_root=Path("/opt/kinetum"),
                validation_root=Path("/var/tmp/kinetum-validation"),
            ),
            packet=packet,
        )
        output = io.StringIO()
        with redirect_stderr(output):
            ConsoleReporter(color=False).print_config(config)
        return output.getvalue()

    def test_duration_replaces_ignored_count(self) -> None:
        """Show the configured duration while retaining the target rate."""
        output = self._configuration(PacketConfig(pps=1000, count=37, duration_s=10.0))
        self.assertIn("PPS:        1000", output)
        self.assertIn("Duration:   10s", output)
        self.assertNotIn("Packets:", output)

    def test_zero_duration_reports_packet_count(self) -> None:
        """Show the packet target when duration does not control generation."""
        output = self._configuration(PacketConfig(pps=2000, count=123, duration_s=0.0))
        self.assertIn("PPS:        2000", output)
        self.assertIn("Packets:    123", output)
        self.assertNotIn("Duration:", output)

    def test_fractional_duration_remains_visible(self) -> None:
        """Preserve a positive fractional duration instead of rounding it to zero."""
        output = self._configuration(PacketConfig(duration_s=0.125))
        self.assertIn("Duration:   0.125s", output)
        self.assertNotIn("Packets:", output)

    def test_all_sizes_preserves_the_selected_limit(self) -> None:
        """Keep size selection independent of the count-or-duration limit."""
        for duration in (0.0, 2.5):
            with self.subTest(duration=duration):
                output = self._configuration(PacketConfig(duration_s=duration, all_sizes=True))
                self.assertIn("Sizes:", output)
                self.assertIn("1514", output)
                self.assertEqual("Duration:" in output, duration > 0)
                self.assertEqual("Packets:" in output, duration == 0)

    def test_every_failed_scenario_has_one_banner_and_its_diagnostic(self) -> None:
        """Early failures remain visible without printing default counters as measured zero."""
        for result, name in (
            (PacketTestResult(64, False, message="capture failed"), "64B"),
            (EpochTestResult(False, message="capture failed"), "EPOCH"),
            (CommitConfirmedTestResult(False, message="capture failed"), "COMMIT-CONFIRMED"),
            (RollbackTestResult(False, message="capture failed"), "ROLLBACK"),
            (GuardrailsTestResult(False, message="capture failed"), "GUARDRAILS"),
            (NatExchangeResult(False, message="capture failed"), "NAT EXCHANGE"),
        ):
            with self.subTest(name=name):
                output = io.StringIO()
                with redirect_stderr(output):
                    ConsoleReporter(color=False).print_test_result(result)
                text = output.getvalue()
                self.assertEqual(text.count(f"[RESULT - {name}]"), 1)
                self.assertEqual(text.count("Status:     FAILED"), 1)
                self.assertIn("Message:    capture failed", text)
                self.assertNotIn("TX:", text)
                self.assertNotIn("Loss:", text)
                self.assertNotIn("PASSED", text)

    def test_guardrails_success_names_candidate_and_actual_restoration(self) -> None:
        """The result exposes the two configuration epochs without repeating a success essay."""
        result = GuardrailsTestResult(
            passed=True, policy_configured=True, baseline_snapshot_id="baseline", candidate_snapshot_id="deny",
            rollback_snapshot_id="baseline", candidate_epoch=11, rollback_epoch=12, duration_s=60.1,
            message="GUARDRAILS VALIDATED: exact attributed rollback completed",
        )
        output = io.StringIO()
        with redirect_stderr(output):
            ConsoleReporter(color=False).print_test_result(result)
        text = output.getvalue()
        self.assertIn("[RESULT - GUARDRAILS]", text)
        self.assertIn("Status:     PASSED", text)
        self.assertIn("Candidate: deny (epoch 11)", text)
        self.assertIn("Restored: baseline (epoch 12)", text)
        self.assertIn("Protocol faults: 0", text)
        self.assertNotIn("Message:", text)

    def test_capture_failure_does_not_hide_completed_confirmation(self) -> None:
        """One failed verdict can retain exact completed control facts without claiming measured traffic."""
        result = CommitConfirmedTestResult(
            passed=False, confirm_success=True, confirm_snapshot_id="v2", confirm_time_remaining_ms=4900,
            confirmed_survived_deadline=True, confirmed_survival_elapsed_ms=6000,
            timeout_rollback_occurred=True, timeout_rollback_snapshot_id="v2", duration_s=32.0,
            message="tcpdump reported packet drops during capture: kernel=16597",
        )
        output = io.StringIO()
        with redirect_stderr(output):
            ConsoleReporter(color=False).print_test_result(result)
        text = output.getvalue()
        self.assertIn("Status:     FAILED", text)
        self.assertIn("Confirmed: v2", text)
        self.assertIn("Timeout rollback: v2", text)
        self.assertIn("kernel=16597", text)
        self.assertNotIn("Loss:", text)
        self.assertNotIn("RX:", text)

    def test_failed_loss_verdict_retains_its_observed_packet_counts(self) -> None:
        """A measured forwarding loss stays visible even though the scenario failed its limit."""
        result = PacketTestResult(
            packet_size=64, passed=False, tx_count=100, rx_count=90, loss_pct=10.0,
            avg_latency_us=12.0, throughput_pps=100.0, duration_s=1.0, message="Loss exceeds the configured limit",
        )
        output = io.StringIO()
        with redirect_stderr(output):
            ConsoleReporter(color=False).print_test_result(result)
        text = output.getvalue()
        self.assertIn("Status:     FAILED", text)
        self.assertIn("TX:         100", text)
        self.assertIn("RX:         90", text)
        self.assertIn("Loss:       10.00%", text)


class ConsoleScenarioLifecycleTest(unittest.IsolatedAsyncioTestCase):
    """The coordinator reports every returned verdict, including early scenario failures."""

    async def test_full_run_reports_each_failed_scenario_once(self) -> None:
        """A failure return cannot skip its banner or produce a duplicate from another owner."""
        with tempfile.TemporaryDirectory() as directory:
            config = ValidationConfig(
                process=ProcessConfig(
                    runtime_root=Path(directory) / "runtime", validation_root=Path(directory) / "kit",
                ),
                deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY, test_type=ValidationTestType.FULL,
                packet=PacketConfig(all_sizes=False), output_dir=Path(directory),
            )
            orchestrator = ValidationOrchestrator(config, reporter=ConsoleReporter(color=False))
            output = io.StringIO()
            with (
                redirect_stderr(output),
                mock.patch.object(ValidationOrchestrator, "_setup", new=mock.AsyncMock(return_value=True)),
                mock.patch.object(ValidationOrchestrator, "_cleanup", new=mock.AsyncMock()) as cleanup,
                mock.patch.object(
                    ValidationOrchestrator, "_save_dp_stats", new=mock.AsyncMock(return_value=StatsValidationResult()),
                ),
                mock.patch.object(orchestrator.artifacts, "save_test_results"),
                mock.patch("kinetum_validation.orchestrator.run_packet_test", new=mock.AsyncMock(
                    return_value=PacketTestResult(64, False, message="packet failure"),
                )),
                mock.patch("kinetum_validation.orchestrator.run_epoch_test", new=mock.AsyncMock(
                    return_value=EpochTestResult(False, message="epoch failure"),
                )),
                mock.patch("kinetum_validation.orchestrator.run_commit_confirmed_test", new=mock.AsyncMock(
                    return_value=CommitConfirmedTestResult(False, message="confirm failure"),
                )),
                mock.patch("kinetum_validation.orchestrator.run_rollback_test", new=mock.AsyncMock(
                    return_value=RollbackTestResult(False, message="rollback failure"),
                )),
                mock.patch("kinetum_validation.orchestrator.run_guardrails_test", new=mock.AsyncMock(
                    return_value=GuardrailsTestResult(False, message="guardrails failure"),
                )),
                mock.patch("kinetum_validation.orchestrator.run_nat_exchange", new=mock.AsyncMock(
                    return_value=NatExchangeResult(False, message="NAT failure"),
                )),
            ):
                result = await orchestrator.run()
            self.assertEqual(result.failed_tests, 6)
            cleanup.assert_awaited_once()
            text = output.getvalue()
            for name in ("64B", "EPOCH", "COMMIT-CONFIRMED", "ROLLBACK", "GUARDRAILS", "NAT EXCHANGE"):
                self.assertEqual(text.count(f"[RESULT - {name}]"), 1)
            self.assertEqual(text.count("Status:     FAILED"), 6)


class HarnessLoggingTest(unittest.TestCase):
    """Owned Python diagnostics share platform framing and preserve native records."""

    def test_record_has_real_emitter_fields_and_escaped_message(self) -> None:
        """One record carries the admitted metadata and cannot inject another line."""
        output = io.StringIO()
        with (
            redirect_stderr(output),
            mock.patch.object(logger, "_timestamp", return_value="2026-09-26T14:20:03.421000Z"),
            mock.patch.object(logger, "_HOSTNAME", "dut"),
            mock.patch.object(logger, "_APPLICATION", "kinetum_validation"),
            mock.patch.object(logger.os, "getpid", return_value=42),
            mock.patch.object(logger.threading, "get_native_id", return_value=73),
        ):
            logger.log_info("test", "first\nsecond\x00\\")
        self.assertEqual(
            output.getvalue(),
            "2026-09-26T14:20:03.421000Z [INFO] dut kinetum_validation[42:73] validation.info - "
            "test/test_record_has_real_emitter_fields_and_escaped_message: first\\x0asecond\\x00\\\\\n",
        )

    def test_oversized_text_has_explicit_bounded_truncation(self) -> None:
        """A long diagnostic remains one bounded line with a visible truncation marker."""
        output = io.StringIO()
        with redirect_stderr(output):
            logger.log_error("test", "\x00" * 9000)
        text = output.getvalue()
        self.assertLessEqual(len(text), 34 * 1024)
        self.assertEqual(text.count("\n"), 1)
        self.assertTrue(text.endswith("...[truncated]\n"))

    def test_process_record_is_not_wrapped_or_reclassified(self) -> None:
        """The reporter preserves an upstream record's original severity and identity."""
        record = "2026-09-26T14:20:03.421000Z [ERROR] dut kinetum_dp[42:73] dp.failed - dp/start: failed"
        output = io.StringIO()
        with redirect_stderr(output):
            ConsoleReporter(color=False, verbose=True).log_callback("kinetum_photon", record)
        self.assertEqual(output.getvalue(), record + "\n")
