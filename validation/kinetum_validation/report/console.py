"""Render validation progress, runtime diagnostics, and measured results on stderr."""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Optional

from ..statistics import format_number

from ..config.types import (
    CommitConfirmedTestResult,
    EpochTestResult,
    GuardrailsTestResult,
    NatExchangeResult,
    RollbackTestResult,
    TestConfig,
    TestResult,
    TestSuiteResult,
    TestType,
)


_SCENARIO_NAMES = {
    EpochTestResult: "EPOCH",
    CommitConfirmedTestResult: "COMMIT-CONFIRMED",
    RollbackTestResult: "ROLLBACK",
    GuardrailsTestResult: "GUARDRAILS",
    NatExchangeResult: "NAT EXCHANGE",
}


class ConsoleReporter:
    """
    Format scenario verdicts while preserving unavailable observations.

    Parameters
    ----------
    color : bool
        Permit ANSI color when stderr is a terminal.
    """

    # ANSI color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"

    def __init__(self, color: bool = True) -> None:
        """Initialize stderr reporting with explicit color selection."""
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

    def print_test_result(
        self,
        result: TestResult | EpochTestResult | CommitConfirmedTestResult | RollbackTestResult
        | GuardrailsTestResult | NatExchangeResult,
    ) -> None:
        """Render one returned verdict after the scenario retires its resources.

        Failed observations always show their diagnostic. Default counters and
        incomplete control evidence are not presented as measured zero or success.
        """
        name = f"{result.packet_size}B" if isinstance(result, TestResult) else _SCENARIO_NAMES[type(result)]
        print(self._header(f"\n[RESULT - {name}]"), file=sys.stderr)

        if result.passed:
            status = self._success("PASSED")
        else:
            status = self._error("FAILED")

        print(f"  Status:     {status}", file=sys.stderr)
        if isinstance(result, (TestResult, CommitConfirmedTestResult, RollbackTestResult)):
            if result.tx_count is not None:
                self._print_traffic(result.tx_count, result.rx_count, result.loss_pct, result.avg_latency_us)
                if isinstance(result, TestResult):
                    print(f"  TX rate:    {format_number(result.throughput_pps)} PPS", file=sys.stderr)
        elif isinstance(result, EpochTestResult) and result.total_sent is not None:
            self._print_traffic(result.total_sent, result.total_received, result.loss_pct, result.avg_latency_us)
            if result.boundary_count is not None:
                self.print_progress(f"Boundaries: {result.completed_boundaries}/{result.boundary_count} complete")
                self.print_progress(f"Protocol faults: {result.protocol_faults_observed}")
                self.print_progress(f"Backpressure: {result.backpressure_events}")
            if result.initial_generation_sent is not None:
                self.print_progress(
                    f"Initial tag: TX={result.initial_generation_sent:,} RX={result.initial_generation_received:,}"
                )
                self.print_progress(
                    f"Next tag: TX={result.next_generation_sent:,} RX={result.next_generation_received:,}"
                )
            if result.generation_tag_transition_seq >= 0:
                self.print_progress(f"First tag-change sequence: {result.generation_tag_transition_seq}")
        if isinstance(result, CommitConfirmedTestResult):
            if result.confirm_success:
                self.print_progress(f"Confirmed: {result.confirm_snapshot_id}")
                self.print_progress(f"Remaining at confirm: {result.confirm_time_remaining_ms}ms")
            if result.confirmed_survived_deadline:
                self.print_progress(f"Observed survival: {result.confirmed_survival_elapsed_ms}ms")
            if result.timeout_rollback_occurred:
                self.print_progress(f"Timeout rollback: {result.timeout_rollback_snapshot_id}")
        elif isinstance(result, RollbackTestResult):
            if result.full_rollback_success:
                self.print_progress(f"Full rollback: {result.full_rollback_snapshot_id}")
            if result.selective_rollback_success:
                self.print_progress(f"Selective rollback: {result.selective_rollback_snapshot_id}")
                self.print_progress(f"Restored modules: {', '.join(result.selective_rollback_modules)}")
        elif result.passed:
            if isinstance(result, GuardrailsTestResult):
                self.print_progress(f"Candidate: {result.candidate_snapshot_id} (epoch {result.candidate_epoch})")
                self.print_progress(f"Restored: {result.rollback_snapshot_id} (epoch {result.rollback_epoch})")
                self.print_progress(f"Protocol faults: {result.protocol_faults_observed}")
            elif isinstance(result, NatExchangeResult):
                self.print_progress(f"Mappings: {result.session_count}; return packets: {result.return_count}")
                self.print_progress(f"NAT contexts: {result.context_count}")
        if result.duration_s is not None:
            print(f"  Duration:   {format_number(result.duration_s, 2)}s", file=sys.stderr)

        if result.message and not result.passed:
            print(f"  Message:    {result.message}", file=sys.stderr)

    @staticmethod
    def _print_traffic(tx: int, rx: Optional[int], loss_pct: Optional[float], latency_us: Optional[float]) -> None:
        """Print observed traffic values once, preserving explicit latency absence."""
        print(f"  TX:         {tx:,}", file=sys.stderr)
        received = f"{rx:,}" if rx is not None else "unavailable"
        print(f"  RX:         {received}", file=sys.stderr)
        loss = f"{format_number(loss_pct, 2)}%" if loss_pct is not None else "unavailable"
        print(f"  Loss:       {loss}", file=sys.stderr)
        latency = f"{format_number(latency_us, 1)}us" if latency_us is not None else "unavailable"
        print(f"  Latency:    {latency}", file=sys.stderr)

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
        print(line, file=sys.stderr, flush=True)
