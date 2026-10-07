"""Borrowed scenario resources, exact observations, and traffic retirement."""

from __future__ import annotations

import asyncio
import math
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import List, Optional, Tuple

from .config.types import (
    AnalysisResult,
    CommitConfirmedTestResult,
    EpochTestResult,
    PacketStats,
    RollbackTestResult,
    TestConfig,
)
from .engine.plan_metadata import PlanTopologyMetadata
from .process.kinetumctl import ActiveSnapshot, KinetumCtl
from .process.telemetry import StatsResult, StatsSelection
from .report.console import ConsoleReporter
from .traffic import TrafficDriver
from .traffic.base import TrafficSender
from .report.artifacts import RunArtifacts
from .process.system_tools import RECOVERABLE_EXCEPTIONS


TRANSITION_STATS = StatsSelection(
    include_stage_stats=True,
    include_worker_epoch_stats=True,
    include_region_epoch_stats=True,
    include_boundary_epoch_stats=True,
)


INITIAL_GENERATION_TAG = 1

NEXT_GENERATION_TAG = 2

CONTROL_OBSERVATION_POLL_S = 0.1

CONTROL_OBSERVATION_TIMEOUT_S = 20.0

GUARDRAILS_CANDIDATE_TRAFFIC_S = 3.0

GUARDRAILS_MAX_DROP_RATIO = 0.01

GUARDRAILS_MIN_TX_RATIO = 0.99


@dataclass(frozen=True)
class ScenarioContext:
    """Borrow prepared run resources through one scenario's complete cleanup.

    The coordinator owns process and driver teardown. Scenario operations retire
    their own tasks, senders, and capture windows before returning these borrows.
    """

    config: TestConfig
    reporter: ConsoleReporter
    traffic: Optional[TrafficDriver]
    control: Optional[KinetumCtl]
    plan_topology: Optional[PlanTopologyMetadata]
    artifacts: RunArtifacts

    def require_traffic(self) -> TrafficDriver:
        """Return the initialized traffic driver or fail closed."""
        if self.traffic is None:
            raise RuntimeError("traffic driver is not initialized")
        return self.traffic

    @staticmethod
    def traffic_observation_is_clean(
        stats: PacketStats,
        analysis: AnalysisResult,
    ) -> bool:
        """Require exact sender/capture accounting before a traffic pass."""
        counters_exact = not (
            stats.tx_count <= 0
            or stats.errors != 0
            or stats.duration_s <= 0.0
            or not math.isfinite(stats.actual_pps)
            or stats.actual_pps <= 0.0
            or analysis.valid <= 0
            or analysis.valid > stats.tx_count
            or analysis.total_rx != analysis.valid
            or analysis.invalid != 0
            or analysis.duplicates != 0
            or analysis.out_of_order != 0
        )
        tags_exact = (
            sum(stats.generation_tag_counts.values()) == stats.tx_count
            and sum(analysis.tag_counts.values()) == analysis.valid
            and set(analysis.tag_counts).issubset(stats.generation_tag_counts)
        )
        if not counters_exact or not tags_exact:
            return False
        return all(
            count <= stats.generation_tag_counts[generation_tag]
            for generation_tag, count in analysis.tag_counts.items()
        )

    async def get_stats_snapshot(self, selection: StatsSelection = TRANSITION_STATS) -> StatsResult:
        """Query one exact snapshot through one native invocation.

        The default includes stage, worker, region, and boundary observations.
        The native CLI owns retries. A missing control client raises RuntimeError
        before process creation.
        """
        if not self.control:
            raise RuntimeError("kinetumctl not initialized")
        return await self.control.get_stats(selection)

    async def get_stats_before_deadline(
        self,
        deadline: float,
        operation: str,
        selection: StatsSelection = TRANSITION_STATS,
    ) -> StatsResult:
        """Accept one snapshot only within the authored window.

        The deadline caps the native command's retry allowance. Cancellation
        retires its subprocess before propagating; cleanup cannot admit late data.
        """
        remaining = deadline - time.monotonic()
        if not math.isfinite(remaining) or remaining <= 0.0:
            raise RuntimeError(f"{operation} observation deadline expired")
        try:
            result = await asyncio.wait_for(
                self.get_stats_snapshot(selection),
                timeout=remaining,
            )
        except asyncio.TimeoutError as exc:
            raise RuntimeError(
                f"{operation} observation exceeded its authored deadline"
            ) from exc
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{operation} observation exceeded its authored deadline")
        return result

    @staticmethod
    def require_active_snapshot_observation(
        stats: StatsResult,
        operation: str,
        expected_snapshot_id: Optional[str] = None,
    ) -> Tuple[str, int]:
        """
        Return one successful nondefault active snapshot observation.

        Parameters
        ----------
        stats : StatsResult
            Exact single-response observation to admit.
        operation : str
            Stable validation phase used in the failure diagnostic.
        expected_snapshot_id : Optional[str]
            Exact operation-result identity required when supplied.

        Returns
        -------
        Tuple[str, int]
            Nonempty active snapshot identity and nonzero active epoch.

        Raises
        ------
        RuntimeError
            If status failed, required identity is absent, or identity differs.
        """
        if not stats.success:
            raise RuntimeError(
                f"{operation} stats failed: {stats.diagnostic}"
            )
        if not stats.active_snapshot_id or stats.active_epoch <= 0:
            raise RuntimeError(
                f"{operation} stats omitted active snapshot identity"
            )
        if (
            expected_snapshot_id is not None
            and stats.active_snapshot_id != expected_snapshot_id
        ):
            raise RuntimeError(
                f"{operation} stats identity {stats.active_snapshot_id} "
                f"disagrees with {expected_snapshot_id}"
            )
        return stats.active_snapshot_id, stats.active_epoch

    @classmethod
    def require_traffic_progress(
        cls,
        before: StatsResult,
        after: StatsResult,
        operation: str,
    ) -> Tuple[int, int]:
        """Require positive ingress under one unchanged runtime/config identity.

        Parameters
        ----------
        before : StatsResult
            Coherent observation taken before traffic starts.
        after : StatsResult
            Coherent observation taken after the source is expected to run.
        operation : str
            Stable scenario phase for diagnostics.

        Returns
        -------
        Tuple[int, int]
            Positive RX delta and nonnegative accepted-TX delta.

        Raises
        ------
        RuntimeError
            If identity changes, counters regress, or no ingress reaches DP.
        """
        before_snapshot, before_epoch = cls.require_active_snapshot_observation(
            before, f"{operation} start"
        )
        _, after_epoch = cls.require_active_snapshot_observation(
            after, f"{operation} end", before_snapshot
        )
        runtime_exact = (
            before.runtime_generation > 0
            and after.runtime_generation == before.runtime_generation
        )
        content_exact = (
            after_epoch == before_epoch
            and after.active_revision == before.active_revision
        )
        transition_clean = not any((
            before.transition_success_blocked,
            after.transition_success_blocked,
            before.retirement_frozen,
            after.retirement_frozen,
        ))
        if not runtime_exact or not content_exact or not transition_clean:
            raise RuntimeError(f"{operation} crossed runtime/config identity")
        if (
            after.rx_packets <= before.rx_packets
            or after.tx_packets < before.tx_packets
            or after.dropped_packets < before.dropped_packets
        ):
            raise RuntimeError(f"{operation} lacks positive exact DP ingress")
        return (
            after.rx_packets - before.rx_packets,
            after.tx_packets - before.tx_packets,
        )

    @staticmethod
    def require_live_traffic_task(
        task: asyncio.Task,
        operation: str,
    ) -> None:
        """Require one scenario traffic owner to remain unresolved and live."""
        if not task.done():
            return
        try:
            task.result()
        except RECOVERABLE_EXCEPTIONS as exc:
            raise RuntimeError(f"{operation} traffic failed early") from exc
        raise RuntimeError(f"{operation} traffic ended early")

    @staticmethod
    def require_selective_rollback_content(
        baseline: ActiveSnapshot,
        candidate: ActiveSnapshot,
        hybrid: ActiveSnapshot,
        expected_hybrid_id: str,
        expected_hybrid_revision: int,
    ) -> None:
        """Prove ACL-only rollback content without trusting response prose.

        Parameters
        ----------
        baseline : ActiveSnapshot
            Exact v1 content whose ACL must be restored.
        candidate : ActiveSnapshot
            Exact v2 content whose non-ACL state must remain.
        hybrid : ActiveSnapshot
            Candidate generated selective-rollback content.
        expected_hybrid_id : str
            Exact mutation-result snapshot identity.
        expected_hybrid_revision : int
            Exact generated snapshot/module revision.

        Raises
        ------
        RuntimeError
            If any identity or content relation differs.
        """
        baseline_modules = baseline.module_by_id()
        candidate_modules = candidate.module_by_id()
        hybrid_modules = hybrid.module_by_id()
        membership_exact = (
            set(baseline_modules) == set(candidate_modules)
            and set(hybrid_modules) == set(candidate_modules)
            and "kinetum.acl" in hybrid_modules
        )
        snapshot_exact = (
            hybrid.snapshot_id == expected_hybrid_id
            and hybrid.revision == expected_hybrid_revision
            and hybrid.parent_snapshot_id == candidate.snapshot_id
        )
        if not membership_exact or not snapshot_exact:
            raise RuntimeError("selective rollback snapshot identity is not exact")
        for module_id, hybrid_module in hybrid_modules.items():
            if module_id == "kinetum.acl":
                if (
                    hybrid_module.policy_identity
                    != baseline_modules[module_id].policy_identity
                    or hybrid_module.revision != expected_hybrid_revision
                ):
                    raise RuntimeError(
                        "selective rollback did not restore exact ACL content"
                    )
            elif hybrid_module != candidate_modules[module_id]:
                raise RuntimeError(
                    f"selective rollback changed retained module {module_id}"
                )

    async def wait_for_active_snapshot(
        self,
        snapshot_id: str,
        after_epoch: int,
        runtime_generation: int,
        observation_deadline: float,
        required_live_task: Optional[asyncio.Task] = None,
    ) -> StatsResult:
        """Wait boundedly for one exact later active-content observation.

        ``required_live_task`` optionally proves that a scenario-owned traffic
        source remains live through the observed convergence edge.

        Parameters
        ----------
        snapshot_id : str
            Exact content identity that must become active.
        after_epoch : int
            Lower exclusive bound for the resulting active epoch.
        runtime_generation : int
            Runtime generation that must remain unchanged.
        observation_deadline : float
            Authored monotonic traffic deadline, also capped at twenty seconds.
        required_live_task : asyncio.Task, optional
            Traffic owner that must remain live through the observation.

        Returns
        -------
        StatsResult
            First exact later COMPLETE observation for ``snapshot_id``.

        Raises
        ------
        RuntimeError
            If evidence contradicts, traffic ends early, or the bound expires.
        """
        deadline = min(observation_deadline, time.monotonic() + CONTROL_OBSERVATION_TIMEOUT_S)
        last_failure = "no observation"
        while time.monotonic() < deadline:
            if required_live_task is not None and required_live_task.done():
                try:
                    required_live_task.result()
                except RECOVERABLE_EXCEPTIONS as exc:
                    raise RuntimeError(
                        "required traffic failed before control convergence"
                    ) from exc
                raise RuntimeError(
                    "required traffic ended before control convergence"
                )
            observed = await self.get_stats_before_deadline(deadline, "control convergence")
            if not observed.success:
                raise RuntimeError(
                    "control convergence received invalid telemetry: "
                    + (observed.diagnostic or "unavailable")
                )
            if observed.runtime_generation != runtime_generation:
                raise RuntimeError("runtime generation changed during control convergence")
            if observed.transition_success_blocked or observed.retirement_frozen:
                raise RuntimeError("control convergence encountered blocked transition truth")
            if (
                observed.active_snapshot_id == snapshot_id
                and observed.active_epoch > after_epoch
                and observed.latest_terminal is not None
                and observed.latest_terminal.outcome
                == "EPOCH_TRANSITION_OUTCOME_COMPLETE"
                and observed.latest_terminal.to_epoch == observed.active_epoch
            ):
                if required_live_task is not None and required_live_task.done():
                    raise RuntimeError(
                        "required traffic ended before convergence observation"
                    )
                return observed
            last_failure = (
                f"active={observed.active_snapshot_id}@{observed.active_epoch}"
            )
            await asyncio.sleep(CONTROL_OBSERVATION_POLL_S)
        raise RuntimeError(
            f"timed out waiting for exact active snapshot {snapshot_id}: {last_failure}"
        )

    async def wait_for_guardrails_degradation(
        self,
        baseline_tx_rate: float,
        candidate_start: StatsResult,
        candidate_snapshot_id: str,
        candidate_epoch: int,
        candidate_task: asyncio.Task,
        observation_deadline: float,
    ) -> StatsResult:
        """Observe both configured threshold legs before automatic rollback.

        The dedicated candidate denies the exact traffic envelope. This gate
        proves that the DP observed a positive candidate population, terminal
        drops exceeded policy, and accepted-TX rate fell below the frozen
        positive baseline before accepting rollback as guardrails evidence.

        Parameters
        ----------
        baseline_tx_rate : float
            Positive accepted-TX packets per monotonic nanosecond from the
            frozen baseline interval.
        candidate_start : StatsResult
            Exact candidate observation before degradation traffic.
        candidate_snapshot_id : str
            Exact candidate content identity.
        candidate_epoch : int
            Exact candidate activation epoch.
        candidate_task : asyncio.Task
            One owned candidate-traffic operation that must remain valid until
            degradation is observed.
        observation_deadline : float
            Monotonic deadline established when candidate traffic starts.

        Returns
        -------
        StatsResult
            First candidate observation proving both threshold legs.

        Raises
        ------
        RuntimeError
            If identity/counters regress, rollback wins the evidence race, or
            the bounded candidate window never proves degradation.
        """
        if baseline_tx_rate <= 0.0 or not math.isfinite(baseline_tx_rate):
            raise RuntimeError("guardrails baseline TX rate is not exact")

        deadline = observation_deadline
        while time.monotonic() < deadline:
            observed = await self.get_stats_before_deadline(
                deadline, "guardrails degradation",
                selection=replace(TRANSITION_STATS, include_module_health=True),
            )
            self.require_active_snapshot_observation(
                observed, "guardrails degradation observation"
            )
            if observed.runtime_generation != candidate_start.runtime_generation:
                raise RuntimeError(
                    "runtime generation changed during guardrails degradation"
                )
            if observed.active_snapshot_id != candidate_snapshot_id:
                if observed.active_epoch > candidate_epoch:
                    raise RuntimeError(
                        "guardrails rollback preceded deterministic degradation proof"
                    )
                await asyncio.sleep(CONTROL_OBSERVATION_POLL_S)
                continue
            if observed.active_epoch != candidate_epoch:
                raise RuntimeError("guardrails candidate epoch is contradictory")
            if (
                observed.collection_monotonic_ns
                <= candidate_start.collection_monotonic_ns
                or observed.rx_packets < candidate_start.rx_packets
                or observed.tx_packets < candidate_start.tx_packets
                or observed.dropped_packets < candidate_start.dropped_packets
            ):
                raise RuntimeError("guardrails candidate counters regressed")

            elapsed = (
                observed.collection_monotonic_ns
                - candidate_start.collection_monotonic_ns
            )
            rx_delta = observed.rx_packets - candidate_start.rx_packets
            tx_delta = observed.tx_packets - candidate_start.tx_packets
            drop_delta = (
                observed.dropped_packets - candidate_start.dropped_packets
            )
            population = tx_delta + drop_delta
            drop_ratio = drop_delta / population if population > 0 else 0.0
            candidate_tx_rate = tx_delta / elapsed
            tx_ratio = candidate_tx_rate / baseline_tx_rate
            health_exact = bool(observed.module_health_stats) and all(
                row.state == "MODULE_HEALTH_STATE_SIGNAL_AVAILABLE"
                and row.observation_epoch == candidate_epoch
                for row in observed.module_health_stats
            )
            if (
                rx_delta > 0
                and population > 0
                and drop_ratio > GUARDRAILS_MAX_DROP_RATIO
                and tx_ratio < GUARDRAILS_MIN_TX_RATIO
                and health_exact
            ):
                return observed
            if candidate_task.done():
                try:
                    candidate_task.result()
                except RECOVERABLE_EXCEPTIONS as exc:
                    raise RuntimeError(
                        "guardrails candidate traffic failed before evidence"
                    ) from exc
                raise RuntimeError(
                    "guardrails candidate traffic ended before degradation proof"
                )
            await asyncio.sleep(CONTROL_OBSERVATION_POLL_S)
        raise RuntimeError(
            "guardrails candidate lacked deterministic drop/throughput evidence"
        )

    async def stop_capture_if_running(self) -> None:
        """Stop traffic capture or propagate unresolved capture ownership."""
        if self.traffic is not None:
            await self.traffic.stop_capture()

    async def retire_scenario_traffic(
        self,
        label: str,
        sender: Optional[TrafficSender],
        owned_task: Optional[asyncio.Task] = None,
        *,
        cancel_task: bool = False,
        capture_active: bool = False,
    ) -> None:
        """
        Resolve one scenario's task, sender, and capture ownership.

        Parameters
        ----------
        label : str
            Stable scenario name used in a combined cleanup failure.
        sender : TrafficSender, optional
            Exact sender owner to abort and release.
        owned_task : asyncio.Task, optional
            Already observed scenario task whose completion must settle.
        cancel_task : bool
            Whether an unfinished task is cancellation-owned by this cleanup.
        capture_active : bool
            Whether this scenario opened a capture window.
        """
        # Cleanup must survive unexpected test-double/library failures long
        # enough to attempt every independent owner.
        failures: List[Tuple[str, BaseException]] = []

        def remember_failure(owner: str, error: BaseException) -> None:
            """Retain one cleanup failure while later owners still retire."""
            failures.append((owner, error))

        task_cancel_requested = False
        if owned_task is not None:
            if cancel_task and not owned_task.done():
                if sender is not None:
                    try:
                        sender.cancel()
                    except BaseException as exc:  # pylint: disable=broad-exception-caught
                        remember_failure("sender cancel", exc)
                owned_task.cancel()
                task_cancel_requested = True
            try:
                await owned_task
            except asyncio.CancelledError as exc:
                current = asyncio.current_task()
                cancelling = getattr(current, "cancelling", None)
                caller_cancelled = callable(cancelling) and cancelling() > 0
                if not task_cancel_requested or caller_cancelled:
                    remember_failure("traffic task", exc)
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                remember_failure("traffic task", exc)
        if sender is not None:
            try:
                await sender.abort()
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                remember_failure("sender abort", exc)
            try:
                sender.cleanup()
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                remember_failure("sender cleanup", exc)
        if capture_active:
            try:
                await self.stop_capture_if_running()
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                remember_failure("capture", exc)
        if failures:
            first_error = failures[0][1]
            message = (
                f"{label} cleanup did not retire every owner: "
                + "; ".join(
                    f"{owner}: {type(error).__name__}: {error}"
                    for owner, error in failures
                )
            )
            if not isinstance(first_error, Exception):
                self.reporter.print_warning(message)
                raise first_error
            raise RuntimeError(message) from first_error

    async def analyze_capture(
        self,
        pcap_file: Path,
        expected_count: int,
    ) -> AnalysisResult:
        """Analyze a capture window through the active traffic driver."""
        return await self.require_traffic().analyze_capture(
            pcap_file=pcap_file,
            expected_count=expected_count,
        )

    def measured_average_latency(
        self, analysis: AnalysisResult
    ) -> Optional[float]:
        """Return profile-qualified latency without manufacturing absence."""
        stats = analysis.latency_stats()
        source = self.config.backend_profile.latency_source
        if source is None:
            if stats is not None:
                raise RuntimeError(
                    "traffic driver published latency without an owned source"
                )
            return None
        if stats is None or stats["avg"] <= 0.0:
            raise RuntimeError(
                "traffic driver omitted latency from an owned measurement source"
            )
        return stats["avg"]

    async def generate_packets(self, packet_size: int) -> PacketStats:
        """Generate test packets using the native sender."""
        pkt_config = replace(self.config.packet, packet_size=packet_size)
        if pkt_config.pps <= 0 or pkt_config.count <= 0:
            raise RuntimeError("packet generation requires positive count and PPS")
        # Compute duration: if count-based, estimate duration from PPS
        if pkt_config.duration_s > 0:
            duration = pkt_config.duration_s
        else:
            duration = pkt_config.count / pkt_config.pps

        ingress_count = len(self.config.backend.rx_ports)
        self.reporter.print_progress(
            f"Generating ~{int(pkt_config.pps * duration)} packets at "
            f"{pkt_config.pps} PPS"
            + (f" (round-robin across {ingress_count} ingress ports)"
               if ingress_count > 1 else "")
        )

        sender = self.require_traffic().make_sender(pkt_config)
        try:
            stats = await sender.run_standard(duration)
        finally:
            sender.cleanup()
        return stats

    def epoch_result_message(
        self, traffic_within_tolerance: bool, protocol_faults: int,
        completed_boundaries: int, boundary_count: int, transitions: int,
        tx: int, rx: int, dp_epoch: int = 0,
    ) -> str:
        """Generate epoch test result message."""
        exact_zero_loss = tx > 0 and tx == rx
        loss_pct = max(0, tx - rx) / tx * 100.0 if tx > 0 else 0.0
        if (
            traffic_within_tolerance
            and protocol_faults == 0
            and transitions > 0
            and boundary_count > 0
            and completed_boundaries == boundary_count
        ):
            epoch_info = f" (DP epoch={dp_epoch})" if dp_epoch > 0 else ""
            traffic_result = (
                f"Zero loss ({tx} TX = {rx} RX)"
                if exact_zero_loss
                else f"Loss {loss_pct:.2f}% within the admitted validation tolerance"
            )
            return (
                "BOUNDARY ORDERING VALIDATED: "
                f"{traffic_result}, "
                f"{completed_boundaries}/{boundary_count} exact CUT/ACK rows, "
                f"zero protocol faults{epoch_info}"
            )
        if not traffic_within_tolerance:
            return (
                f"TRAFFIC EVIDENCE FAILED: {tx} TX, {rx} RX, "
                f"loss {loss_pct:.2f}%"
            )
        if protocol_faults != 0:
            return (
                "BOUNDARY ORDERING VIOLATION: "
                f"{protocol_faults} typed protocol faults detected "
                f"({tx} TX, {rx} RX)"
            )
        if transitions == 0:
            return "TRANSITION NOT CONFIRMED: Config apply succeeded but epoch advance not detected"
        if completed_boundaries != boundary_count or boundary_count == 0:
            return (
                "BOUNDARY ORDERING INCONCLUSIVE: "
                "exact CUT/ACK boundary evidence is incomplete"
            )
        return "UNKNOWN"

    def print_epoch_results(
        self, result: EpochTestResult, _stats: PacketStats, _analysis: AnalysisResult
    ) -> None:
        """Print detailed epoch test results."""
        self.reporter.print_step("EPOCH TEST RESULTS")

        if result.passed and result.boundary_ordering_validated:
            print(
                "  PASS BOUNDARY ORDERING VALIDATED: "
                + (
                    "zero-loss configuration transition"
                    if result.zero_loss
                    else "configuration transition within validation loss tolerance"
                ),
                file=sys.stderr,
            )
        else:
            print("  FAIL BOUNDARY ORDERING VALIDATION FAILED", file=sys.stderr)

        print("  ==============================================", file=sys.stderr)
        print("  CORE EPOCH METRIC: exact sender/capture accounting", file=sys.stderr)
        print("  ----------------------------------------------", file=sys.stderr)
        print(f"  TX: {result.total_sent}  RX: {result.total_received}", file=sys.stderr)
        traffic_exact = self.traffic_observation_is_clean(_stats, _analysis)
        if traffic_exact and result.total_sent == result.total_received:
            print("  PASS ZERO LOSS ACHIEVED", file=sys.stderr)
        elif result.total_received > result.total_sent:
            print(
                "  DUPLICATE OR FOREIGN RX OBSERVED: "
                f"{result.total_received - result.total_sent} packets",
                file=sys.stderr,
            )
        elif not traffic_exact:
            print(
                "  FAIL TRAFFIC EVIDENCE: "
                f"invalid={_analysis.invalid} duplicates={_analysis.duplicates} "
                f"out_of_order={_analysis.out_of_order} sender_errors={_stats.errors}",
                file=sys.stderr,
            )
        else:
            lost = result.total_sent - result.total_received
            print(
                f"  LOSS OBSERVED: {lost} packets ({result.loss_pct:.2f}%)",
                file=sys.stderr,
            )
        print("  ----------------------------------------------", file=sys.stderr)

        triggered = "Yes" if result.transitions_observed > 0 else "No"
        print(f"  Transition Triggered: {triggered}", file=sys.stderr)

        if result.boundary_ordering_validated:
            print(
                "  PASS BOUNDARY ORDERING VALIDATED: "
                f"boundaries={result.completed_boundaries}/"
                f"{result.boundary_count}, "
                f"backpressure={result.backpressure_events}, faults=0",
                file=sys.stderr,
            )
        if result.initial_generation_sent > 0 or result.next_generation_sent > 0:
            print("  ----------------------------------------------", file=sys.stderr)
            print("  Packet-profile generation tags:", file=sys.stderr)
            print(
                f"    Tag {INITIAL_GENERATION_TAG}: "
                f"TX={result.initial_generation_sent} "
                f"RX={result.initial_generation_received}",
                file=sys.stderr,
            )
            print(
                f"    Tag {NEXT_GENERATION_TAG}: "
                f"TX={result.next_generation_sent} "
                f"RX={result.next_generation_received}",
                file=sys.stderr,
            )
            if result.generation_tag_transition_seq >= 0:
                print(
                    "    Generation-tag transition at seq: "
                    f"{result.generation_tag_transition_seq}",
                    file=sys.stderr,
                )

        print("  ==============================================", file=sys.stderr)
        print(f"  Duration: {result.duration_s:.2f}s", file=sys.stderr)
        print(f"  Message: {result.message}", file=sys.stderr)

    def print_commit_confirmed_results(self, result: CommitConfirmedTestResult) -> None:
        """Print commit-confirmed test results."""
        self.reporter.print_step("COMMIT-CONFIRMED TEST RESULTS")

        if result.passed:
            print("  PASS COMMIT-CONFIRMED VALIDATED", file=sys.stderr)
        else:
            print("  FAIL COMMIT-CONFIRMED FAILED", file=sys.stderr)

        print("  ==============================================", file=sys.stderr)
        print(f"  Snapshot ID: {result.confirm_snapshot_id}", file=sys.stderr)
        print(f"  Confirm Success: {result.confirm_success}", file=sys.stderr)
        if result.confirm_time_remaining_ms > 0:
            print(f"  Time Remaining: {result.confirm_time_remaining_ms}ms", file=sys.stderr)
        print(
            "  Timeout Rollback: "
            f"{result.timeout_rollback_occurred} "
            f"({result.timeout_rollback_snapshot_id})",
            file=sys.stderr,
        )
        print("  ----------------------------------------------", file=sys.stderr)
        print("  Traffic-Under-Transition:", file=sys.stderr)
        print(f"    TX: {result.tx_count}  RX: {result.rx_count}", file=sys.stderr)
        print(f"    Loss: {result.loss_pct:.2f}%", file=sys.stderr)
        latency_text = (
            f"{result.avg_latency_us:.1f} us"
            if result.avg_latency_us is not None
            else "unavailable"
        )
        print(f"    Avg Latency: {latency_text}", file=sys.stderr)
        print("  ==============================================", file=sys.stderr)
        print(f"  Duration: {result.duration_s:.2f}s", file=sys.stderr)
        print(f"  Message: {result.message}", file=sys.stderr)

    def rollback_result_message(
        self, full_success: bool, selective_success: bool,
        traffic_ok: bool, traffic_evidence_exact: bool, loss_pct: float,
    ) -> str:
        """Generate rollback test result message."""
        if not traffic_ok:
            if not traffic_evidence_exact:
                return (
                    "ROLLBACK FAILED: sender/capture accounting or generation-tag "
                    "evidence is not exact"
                )
            return (
                "ROLLBACK FAILED: "
                f"traffic loss {loss_pct:.2f}% exceeds threshold "
                f"{self.config.max_loss_pct}%"
            )
        if full_success and selective_success:
            return "ROLLBACK VALIDATED: full and selective rollback completed"
        if full_success:
            return "ROLLBACK PARTIAL: full rollback completed; selective rollback failed"
        if selective_success:
            return "ROLLBACK PARTIAL: selective rollback completed; full rollback failed"
        return "ROLLBACK FAILED: full and selective rollback failed"

    def print_rollback_results(self, result: RollbackTestResult) -> None:
        """Print rollback test results."""
        self.reporter.print_step("ROLLBACK TEST RESULTS")

        if result.passed:
            print("  PASS ROLLBACK VALIDATED", file=sys.stderr)
        else:
            print("  FAIL ROLLBACK FAILED", file=sys.stderr)

        print("  ==============================================", file=sys.stderr)
        full_text = "PASS" if result.full_rollback_success else "FAIL"
        print(f"  Full Rollback: {full_text}", file=sys.stderr)
        if result.full_rollback_snapshot_id:
            print(f"    New Snapshot: {result.full_rollback_snapshot_id}", file=sys.stderr)
        selective_text = "PASS" if result.selective_rollback_success else "FAIL"
        print(f"  Selective Rollback: {selective_text}", file=sys.stderr)
        if result.selective_rollback_modules:
            print(f"    Modules: {', '.join(result.selective_rollback_modules)}", file=sys.stderr)
            print(f"    New Snapshot: {result.selective_rollback_snapshot_id}", file=sys.stderr)
        print("  ----------------------------------------------", file=sys.stderr)
        print("  Traffic-Under-Transition:", file=sys.stderr)
        print(f"    TX: {result.tx_count}  RX: {result.rx_count}", file=sys.stderr)
        print(f"    Loss: {result.loss_pct:.2f}%", file=sys.stderr)
        latency_text = (
            f"{result.avg_latency_us:.1f} us"
            if result.avg_latency_us is not None
            else "unavailable"
        )
        print(f"    Avg Latency: {latency_text}", file=sys.stderr)
        print("  ==============================================", file=sys.stderr)
        print(f"  Duration: {result.duration_s:.2f}s", file=sys.stderr)
        print(f"  Message: {result.message}", file=sys.stderr)

    async def get_final_stats_snapshot(self) -> StatsResult:
        """Wait within the observation deadline for post-traffic owner publications.

        The first successful DP collection supplies the monotonic time barrier.
        Every later row must retain its plan and generation and advance beyond
        that barrier. A failed query or contradictory observation is not retried.
        Cancellation propagates through the bounded child-process owner.
        """
        if self.plan_topology is None:
            raise RuntimeError("final stream evidence requires parsed plan metadata")
        expected_ids = {stream.io_stream_id for stream in self.plan_topology.io_streams}
        selection = replace(
            TRANSITION_STATS,
            include_module_metrics=True,
            include_module_health=True,
            include_stream_stats=True,
            include_storage_domain_stats=True,
            include_port_stats=True,
            include_topology_stats=True,
        )
        deadline = time.monotonic() + CONTROL_OBSERVATION_TIMEOUT_S
        baseline = await self.get_stats_before_deadline(deadline, "final stream publication", selection=selection)
        if not baseline.success:
            raise RuntimeError(f"final stream baseline query failed: {baseline.diagnostic}")
        if (
            baseline.collection_monotonic_ns <= 0
            or baseline.runtime_generation <= 0 or not baseline.transition_plan_content_hash
        ):
            raise RuntimeError("final stream evidence lacks a valid baseline")
        barrier = baseline.collection_monotonic_ns
        identity = (baseline.runtime_generation, baseline.transition_plan_content_hash)
        previous = {}
        current = baseline
        last_collection = barrier
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError("final stream publication observation deadline expired")
            if not current.success:
                raise RuntimeError(f"final stream observation failed: {current.diagnostic}")
            if (current.runtime_generation, current.transition_plan_content_hash) != identity:
                raise RuntimeError("final stream observation changed runtime/plan identity")
            if current.collection_monotonic_ns < last_collection:
                raise RuntimeError("final stream collection timestamp regressed")
            last_collection = current.collection_monotonic_ns
            rows = {row.io_stream_id: row for row in current.stream_stats}
            if set(rows) != expected_ids or len(rows) != len(current.stream_stats):
                raise RuntimeError("final stream membership differs from the compiled plan")
            for stream_id, row in rows.items():
                counters = (row.published_monotonic_ns, row.packets, row.bytes, row.rejected_packets)
                if (
                    any(value is None for value in counters)
                    or row.published_monotonic_ns <= 0
                    or row.published_monotonic_ns > current.collection_monotonic_ns
                    or (stream_id in previous and any(
                        after < before for before, after in zip(previous[stream_id], counters)
                    ))
                ):
                    raise RuntimeError(f"final stream observation is incomplete or regressed: {stream_id}")
                previous[stream_id] = counters
            if all(row.published_monotonic_ns > barrier for row in rows.values()):
                return current
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("final stream publication observation deadline expired")
            await asyncio.sleep(min(CONTROL_OBSERVATION_POLL_S, remaining))
            current = await self.get_stats_before_deadline(deadline, "final stream publication", selection=selection)

    def print_boundary_ordering(
        self, protocol_faults_observed: int, boundary_ordering_validated: bool,
        completed_boundaries: int, boundary_count: int, total_backpressure: int,
    ) -> None:
        """Report the measured boundary result without changing its verdict."""
        if protocol_faults_observed > 0:
            self.reporter.print_warning(
                "BOUNDARY ORDERING VIOLATION: "
                f"{protocol_faults_observed} protocol faults"
            )
        elif boundary_ordering_validated:
            self.reporter.print_progress(
                "Boundary ordering verified: "
                f"{completed_boundaries}/{boundary_count} exact CUT/ACK rows, "
                f"backpressure_delta={total_backpressure}, 0 protocol faults"
            )
        else:
            warning = "Boundary ordering inconclusive: exact transition evidence is incomplete"
            self.reporter.print_warning(warning)
