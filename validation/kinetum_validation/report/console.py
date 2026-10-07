"""
Console Reporter - real-time test output and result formatting.

Provides structured console output with:
- Real-time progress updates
- Colored status indicators
- Detailed result summaries
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Optional

from ..config.types import (
    TestConfig,
    TestResult,
    TestSuiteResult,
    TestType,
)


class ConsoleReporter:
    """
    Console output for test execution and results.

    Provides real-time streaming output with structured
    formatting for test progress and results.

    Parameters
    ----------
    verbose : bool
        Enable verbose output.
    color : bool
        Enable ANSI color codes.
    """

    # ANSI color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"

    def __init__(self, verbose: bool = False, color: bool = True) -> None:
        """Initialize stderr reporting with explicit verbosity and color."""
        self.verbose = verbose
        self.color = color and sys.stderr.isatty()

    def _c(self, code: str, text: str) -> str:
        """Apply color code if enabled."""
        if self.color:
            return f"{code}{text}{self.RESET}"
        return text

    def _header(self, text: str) -> str:
        """Format header text."""
        return self._c(self.BOLD + self.CYAN, text)

    def _success(self, text: str) -> str:
        """Format success text."""
        return self._c(self.GREEN, text)

    def _error(self, text: str) -> str:
        """Format error text."""
        return self._c(self.RED, text)

    def _warning(self, text: str) -> str:
        """Format warning text."""
        return self._c(self.YELLOW, text)

    def _info(self, text: str) -> str:
        """Format info text."""
        return self._c(self.BLUE, text)

    def print_banner(self, version: str) -> None:
        """Print the version already admitted against runtime and validation resources."""
        banner = f"""
+----------------------------------------------------------------+
|              KINETUM PHYSICAL-I/O VALIDATION                   |
|                     Production Test Suite                      |
|                         Version: {version:<30}|
+----------------------------------------------------------------+
"""
        print(self._header(banner), file=sys.stderr)

    def print_config(self, config: TestConfig) -> None:
        """Print test configuration summary."""
        print(self._header("\n[CONFIG]"), file=sys.stderr)
        print(f"  Deployment: {config.deployment.value}", file=sys.stderr)
        print(f"  Test Type:  {config.test_type.value}", file=sys.stderr)
        print(f"  I/O Profile: {config.backend.backend_type.value}", file=sys.stderr)
        print(f"  Traffic:    {config.backend_profile.traffic_driver.value}", file=sys.stderr)
        if config.dry_run:
            print("  Mode:       dry-run", file=sys.stderr)
        print(f"  PPS:        {config.packet.pps}", file=sys.stderr)
        if config.packet.duration_s > 0:
            print(f"  Duration:   {config.packet.duration_s:g}s", file=sys.stderr)
        else:
            print(f"  Packets:    {config.packet.count}", file=sys.stderr)
        if config.packet.all_sizes:
            print(f"  Sizes:      {config.packet.sizes_to_test}", file=sys.stderr)
        else:
            print(f"  Size:       {config.packet.packet_size}B", file=sys.stderr)
        print(f"  Runtime:    {config.process.runtime_root}", file=sys.stderr)
        print(f"  Validation: {config.process.validation_root}", file=sys.stderr)

        if config.test_type in (TestType.EPOCH, TestType.FULL):
            print(
                f"  Epoch:      {config.epoch.duration_s}s "
                f"@ {config.epoch.pps} PPS",
                file=sys.stderr,
            )

        print("", file=sys.stderr)

    def print_step(self, step: str) -> None:
        """Print step marker."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(
            f"\n{self._header('[')} {timestamp} {self._header(']')} "
            f"{self._info(step)}",
            file=sys.stderr,
        )

    def print_progress(self, message: str) -> None:
        """Print progress message."""
        print(f"  {message}", file=sys.stderr)

    def print_test_result(self, result: TestResult) -> None:
        """Print packet test result."""
        print(self._header(f"\n[RESULT - {result.packet_size}B]"), file=sys.stderr)

        if result.passed:
            status = self._success("PASSED")
        else:
            status = self._error("FAILED")

        print(f"  Status:     {status}", file=sys.stderr)
        print(f"  TX:         {result.tx_count:,}", file=sys.stderr)
        print(f"  RX:         {result.rx_count:,}", file=sys.stderr)

        if result.loss_pct > 1.0:
            print(f"  Loss:       {self._error(f'{result.loss_pct:.2f}%')}", file=sys.stderr)
        elif result.loss_pct > 0:
            print(f"  Loss:       {self._warning(f'{result.loss_pct:.2f}%')}", file=sys.stderr)
        else:
            print(f"  Loss:       {self._success('0.00%')}", file=sys.stderr)

        if result.avg_latency_us is not None:
            print(f"  Latency:    {result.avg_latency_us:.1f}us", file=sys.stderr)
        else:
            print("  Latency:    unavailable", file=sys.stderr)

        print(f"  Throughput: {result.throughput_pps:.0f} PPS", file=sys.stderr)
        print(f"  Duration:   {result.duration_s:.2f}s", file=sys.stderr)

        if result.message:
            print(f"  Message:    {result.message}", file=sys.stderr)

    def print_suite_result(self, result: TestSuiteResult) -> None:
        """Print test suite summary."""
        separator = "=" * 60
        print(f"\n{self._header(separator)}", file=sys.stderr)
        print(self._header("TEST SUITE SUMMARY"), file=sys.stderr)
        print(self._header(separator), file=sys.stderr)

        print(f"\n  Total tests: {result.total_tests}", file=sys.stderr)
        print(
            f"  Passed:      {self._success(str(result.passed_tests))}",
            file=sys.stderr,
        )
        print(
            f"  Failed:      {self._error(str(result.failed_tests))}",
            file=sys.stderr,
        )
        if result.stats_validation.required:
            verdict = (
                self._success("PASS")
                if result.stats_validation.passed
                else self._error("FAIL")
            )
            print(
                f"  Stats gate:  {verdict} {result.stats_validation.message}",
                file=sys.stderr,
            )
        print(f"  Duration:    {result.total_duration_s:.2f}s", file=sys.stderr)

        if result.all_passed:
            print(
                f"\n  {self._success('ALL TESTS PASSED')}",
                file=sys.stderr,
            )
        else:
            print(
                f"\n  {self._error('SOME TESTS FAILED')}",
                file=sys.stderr,
            )

        print(f"\n{self._header(separator)}\n", file=sys.stderr)

    def print_error(self, message: str, detail: Optional[str] = None) -> None:
        """Print error message."""
        print(f"\n{self._error('[ERROR]')} {message}", file=sys.stderr)
        if detail:
            print(f"  {detail}", file=sys.stderr)

    def print_warning(self, message: str) -> None:
        """Print warning message."""
        print(f"{self._warning('[WARN]')} {message}", file=sys.stderr)

    def log_callback(self, _process: str, line: str) -> None:
        """
        Callback for real-time process log streaming.

        Parameters
        ----------
        _process : str
            Managed process name (currently kinetum_photon).
        line : str
            Log line.
        """
        if self.verbose:
            print(line, file=sys.stderr)
