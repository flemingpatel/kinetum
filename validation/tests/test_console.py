"""Verify traffic-limit reporting and exact diagnostic presentation."""

import io
import unittest
from unittest import mock
from contextlib import redirect_stderr
from pathlib import Path

from kinetum_validation.config.types import PacketConfig, ProcessConfig, TestConfig as ValidationConfig
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
                self.assertIn("1518", output)
                self.assertEqual("Duration:" in output, duration > 0)
                self.assertEqual("Packets:" in output, duration == 0)


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
