"""Borrowed scenario resources, exact observations, and traffic retirement."""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Awaitable, Callable, List, Optional, Tuple, TypeVar

from .config.types import (
    CONSTANTS,
    AnalysisResult,
    DeploymentMode,
    EpochTestResult,
    PacketStats,
    TestConfig,
    TrafficDriverType,
)
from .engine.plan_metadata import PlanTopologyMetadata
from .engine.qos_accounting import qos_accounting_complete
from .process.kinetumctl import ActiveSnapshot, ApplyConfigResult, KinetumCtl
from .process.telemetry import StatsResult, StatsSelection
from .process.epoch_load import EpochLoadPhase
from .process.telemetry_validation import (
    boundary_transition_is_complete, require_stream_observation, worker_counters_are_exact, worker_counters_advanced,
)
from .report.console import ConsoleReporter
from .statistics import format_number
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

EPOCH_LOAD_STATS = replace(TRANSITION_STATS, include_stream_stats=True)


INITIAL_GENERATION_TAG = 1

NEXT_GENERATION_TAG = 2

CONTROL_OBSERVATION_POLL_S = 0.1

CONTROL_OBSERVATION_TIMEOUT_S = 20.0

_Observation = TypeVar("_Observation")


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

    def traffic_observation_is_clean(
        self,
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
            or analysis.out_of_order not in (None, 0)
            or analysis.missing_count != stats.tx_count - analysis.valid
        )
        tags_exact = (
            sum(stats.generation_tag_counts.values()) == stats.tx_count
            and sum(analysis.tag_counts.values()) == analysis.valid
            and set(analysis.tag_counts).issubset(stats.generation_tag_counts)
        )
        if not counters_exact or not tags_exact:
            return False
        if self.config.backend_profile.traffic_driver == TrafficDriverType.NATIVE_TAP:
            streams = analysis.streams
            stream_count = len(self.config.backend.rx_ports)
            if streams is None or len(streams) != stream_count:
                return False
            for index, row in enumerate(streams):
                expected = stats.tx_count // stream_count + int(index < stats.tx_count % stream_count)
                if (
                    row.stream_index != index or row.expected_count != expected
                    or not 0 < row.valid <= expected or row.duplicates != 0
                    or row.missing_count != expected - row.valid
                ):
                    return False
            if sum(row.valid for row in streams) != analysis.valid:
                return False
        elif self.config.backend_profile.traffic_driver != TrafficDriverType.TREX or analysis.streams is not None:
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

    @staticmethod
    async def run_before_deadline(
        action: Callable[[], Awaitable[_Observation]], deadline: float, operation: str,
    ) -> _Observation:
        """Invoke one cancellable operation and accept its result only before the monotonic deadline.

        Expiry before dispatch leaves the action uncalled. On timeout asyncio
        waits for the action's cancellation handling before this raises RuntimeError.
        """
        remaining = deadline - time.monotonic()
        if not math.isfinite(remaining) or remaining <= 0.0:
            raise RuntimeError(f"{operation} deadline expired")
        try:
            result = await asyncio.wait_for(action(), timeout=remaining)
        except asyncio.TimeoutError as exc:
            raise RuntimeError(f"{operation} exceeded its authored deadline") from exc
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{operation} exceeded its authored deadline")
        return result

    async def get_stats_before_deadline(
        self,
        deadline: float,
        operation: str,
        selection: StatsSelection = TRANSITION_STATS,
    ) -> StatsResult:
        """Cap the native statistics command and its retry allowance at the supplied deadline."""
        return await self.run_before_deadline(
            lambda: self.get_stats_snapshot(selection), deadline, f"{operation} observation",
        )

    async def wait_for_observation(
        self,
        read: Callable[[], Awaitable[_Observation]],
        ready: Callable[[_Observation], bool],
        deadline: float,
        operation: str,
        required_live_task: Optional[asyncio.Task] = None,
    ) -> _Observation:
        """Wait within one authored bound for evidence, never for elapsed-time readiness.

        The predicate returns False for valid unfinished observations and raises
        for invalid evidence. Native commands retain RPC retry ownership. Caller
        cancellation propagates through the in-flight command's exact cleanup.
        """
        while True:
            remaining = deadline - time.monotonic()
            if not math.isfinite(remaining) or remaining <= 0:
                raise RuntimeError(f"{operation} exhausted its observation window")
            if required_live_task is not None:
                self.require_live_traffic_task(required_live_task, operation)
            try:
                observed = await asyncio.wait_for(read(), timeout=remaining)
            except asyncio.TimeoutError as exc:
                raise RuntimeError(f"{operation} exceeded its observation deadline") from exc
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{operation} exceeded its observation deadline")
            if required_live_task is not None:
                self.require_live_traffic_task(required_live_task, operation)
            if ready(observed):
                return observed
            await asyncio.sleep(min(CONTROL_OBSERVATION_POLL_S, max(0.0, deadline - time.monotonic())))

    async def wait_for_traffic_progress(
        self,
        before: StatsResult,
        deadline: float,
        operation: str,
        required_live_task: Optional[asyncio.Task],
        selection: StatsSelection = TRANSITION_STATS,
    ) -> StatsResult:
        """Require current-epoch source measurements and positive ingress before mutation.

        Timed traffic supplies its live task. A generation-tag session instead
        owns liveness through its acknowledged overlap and finish operations.
        """
        self.require_active_snapshot_observation(before, operation)
        if before.transition_success_blocked or before.retirement_frozen or not worker_counters_are_exact(before):
            raise RuntimeError(f"{operation} has invalid initial worker observations")
        cursor = before.worker_counters
        seed = before if (
            before.transition_state == "EPOCH_TRANSITION_STATE_IDLE"
            and all(row.observation_epoch == before.active_epoch for row in cursor)
        ) else None

        async def read() -> StatsResult:
            """Obtain one native observation with the requested diagnostic families."""
            return await self.get_stats_snapshot(selection)

        def ready(observed: StatsResult) -> bool:
            """Retain partial progress while rejecting any worker or content contradiction."""
            nonlocal cursor, seed
            self.require_active_snapshot_observation(observed, operation, before.active_snapshot_id)
            identity_changed = (
                observed.runtime_generation != before.runtime_generation
                or observed.active_epoch != before.active_epoch
                or observed.active_revision != before.active_revision
                or observed.transition_plan_content_hash != before.transition_plan_content_hash
                or observed.transition_active_validation_hash != before.transition_active_validation_hash
            )
            if (
                identity_changed
                or observed.transition_success_blocked or observed.retirement_frozen
                or not worker_counters_are_exact(observed)
            ):
                raise RuntimeError(f"{operation} crossed runtime/config identity or invalid evidence")
            worker_counters_advanced(cursor, observed.worker_counters)
            cursor = observed.worker_counters
            if observed.transition_state != "EPOCH_TRANSITION_STATE_IDLE":
                seed = None
                return False
            if any(row.observation_epoch != observed.active_epoch for row in cursor):
                return False
            if seed is None:
                seed = observed
                return False
            if not worker_counters_advanced(seed.worker_counters, cursor) or observed.rx_packets == seed.rx_packets:
                return False
            self.require_traffic_progress(seed, observed, operation)
            return True

        return await self.wait_for_observation(read, ready, deadline, operation, required_live_task)

    def epoch_load_phase(self, expected: StatsResult) -> EpochLoadPhase:
        """Resolve logical-ingress targets from the admitted profile and plan."""
        if self.plan_topology is None:
            raise RuntimeError("epoch load requires parsed plan metadata")
        ingress_names = {port.logical_name for port in self.config.backend.rx_ports}
        ports = [port for port in self.plan_topology.ports if port.logical_name in ingress_names]
        if (
            not ingress_names or {port.logical_name for port in ports} != ingress_names
            or len(ports) != len(ingress_names) or len({port.logical_port_id for port in ports}) != len(ports)
        ):
            raise RuntimeError("epoch ingress ports differ from the compiled plan")
        population_count = 2 if self.require_traffic().requires_sustained_generation_overlap else 1
        target = self.config.epoch.pps * population_count / len(ports)
        return EpochLoadPhase(self.plan_topology, expected, {port.logical_port_id: target for port in ports})

    async def wait_for_epoch_load(
        self, phase: EpochLoadPhase, traffic_deadline: float, sender: TrafficSender,
    ) -> StatsResult:
        """Qualify one phase including its fresh barrier within the remaining traffic budget."""
        deadline = min(time.monotonic() + CONTROL_OBSERVATION_TIMEOUT_S, traffic_deadline - CONSTANTS.EPOCH_TAIL_S)
        operation = f"epoch {phase.identity.epoch} ingress load"

        async def read() -> StatsResult:
            """Fence known source termination around each complete owner-vector read."""
            sender.require_generation_active()
            current = await self.get_stats_snapshot(EPOCH_LOAD_STATS)
            sender.require_generation_active()
            return current

        return await self.wait_for_observation(read, phase.observe, deadline, operation)

    async def wait_for_epoch_completion(
        self, before: StatsResult, applied: ApplyConfigResult, deadline: float, sender: TrafficSender,
    ) -> StatsResult:
        """Observe the exact returned mutation and every boundary before target qualification."""
        if self.plan_topology is None:
            raise RuntimeError("epoch completion lacks the compiled topology")
        cursor = before
        before_rows = {row.boundary_id: row for row in before.boundary_epoch_stats}
        if not before_rows or len(before_rows) != len(before.boundary_epoch_stats):
            raise RuntimeError("epoch completion lacks exact initial boundary membership")

        async def read() -> StatsResult:
            """Keep source ownership live while collecting terminal and stream evidence."""
            sender.require_generation_active()
            current = await self.get_stats_snapshot(EPOCH_LOAD_STATS)
            sender.require_generation_active()
            return current

        def ready(current: StatsResult) -> bool:
            """Reject foreign or failed transitions and wait for exact completion publications."""
            nonlocal cursor
            require_stream_observation(self.plan_topology, cursor, current)
            self.require_active_snapshot_observation(current, "epoch completion")
            if current.transition_success_blocked or current.retirement_frozen:
                raise RuntimeError("epoch completion is blocked or frozen")
            if current.active_epoch < cursor.active_epoch:
                raise RuntimeError("active epoch regressed during completion")
            cursor = current
            if (
                len(current.boundary_epoch_stats) != len(before_rows)
                or {row.boundary_id for row in current.boundary_epoch_stats} != before_rows.keys()
            ):
                raise RuntimeError("epoch completion changed boundary membership")
            if any(row.endpoint_identity() != before_rows[row.boundary_id].endpoint_identity()
                   for row in current.boundary_epoch_stats):
                raise RuntimeError("epoch completion changed boundary endpoints or capacities")
            if current.protocol_fault_counts != before.protocol_fault_counts:
                raise RuntimeError("epoch completion has a protocol fault delta")
            if current.active_epoch == before.active_epoch:
                if (current.active_snapshot_id, current.active_revision) != (
                    before.active_snapshot_id, before.active_revision,
                ):
                    raise RuntimeError("old snapshot identity changed during epoch completion")
                return False
            if (current.active_epoch, current.active_revision, current.active_snapshot_id) != (
                applied.epoch, applied.revision, applied.snapshot_id,
            ):
                raise RuntimeError("epoch completion differs from the Apply result")
            terminal = current.latest_terminal
            if terminal is None or terminal.to_epoch < applied.epoch:
                return False
            if (
                terminal.from_epoch != before.active_epoch or terminal.to_epoch != applied.epoch
                or terminal.outcome != "EPOCH_TRANSITION_OUTCOME_COMPLETE"
                or terminal.failure_code != "EPOCH_TRANSITION_FAILURE_CODE_NONE"
            ):
                raise RuntimeError("epoch completion lacks the exact successful terminal")
            return current.transition_state == "EPOCH_TRANSITION_STATE_IDLE" and all(
                boundary_transition_is_complete(row, terminal.mutation_sequence, before.active_epoch, applied.epoch)
                for row in current.boundary_epoch_stats
            )

        return await self.wait_for_observation(read, ready, deadline, "epoch completion")

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

        def ready(observed: StatsResult) -> bool:
            """Check only control identity and terminal completion, without counter freshness."""
            self.require_active_snapshot_observation(observed, "control convergence")
            if observed.runtime_generation != runtime_generation:
                raise RuntimeError("runtime generation changed during control convergence")
            if observed.transition_success_blocked or observed.retirement_frozen:
                raise RuntimeError("control convergence encountered blocked transition truth")
            return (
                observed.active_snapshot_id == snapshot_id
                and observed.active_epoch > after_epoch
                and observed.latest_terminal is not None
                and observed.latest_terminal.outcome == "EPOCH_TRANSITION_OUTCOME_COMPLETE"
                and observed.latest_terminal.to_epoch == observed.active_epoch
            )

        return await self.wait_for_observation(
            self.get_stats_snapshot, ready, deadline,
            f"exact active snapshot {snapshot_id}", required_live_task,
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
            Owned scenario task whose terminal result must be collected.
        cancel_task : bool
            True for a task that owns traffic: cancel and join it before
            releasing the sender. False for an independent mutation: stop
            traffic first, then collect its outcome without cancelling it.
        capture_active : bool
            Whether this scenario opened a capture window.
        """
        # Cleanup must survive unexpected test-double/library failures long
        # enough to attempt every independent owner.
        failures: List[Tuple[str, BaseException]] = []
        interruption: Optional[asyncio.CancelledError] = None

        def remember_failure(owner: str, error: BaseException) -> None:
            """Retain one cleanup failure while later owners still retire."""
            failures.append((owner, error))

        async def retire_sender() -> None:
            """Attempt both sender retirement and release without skipping another owner."""
            if sender is None:
                return
            try:
                await sender.abort()
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                remember_failure("sender abort", exc)
            try:
                sender.cleanup()
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                remember_failure("sender cleanup", exc)

        if not cancel_task:
            await retire_sender()
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
            while True:
                try:
                    await asyncio.shield(owned_task)
                    break
                except asyncio.CancelledError as exc:
                    current = asyncio.current_task()
                    caller_cancelled = current is not None and current.cancelling() > 0
                    if not task_cancel_requested or caller_cancelled:
                        interruption = exc
                    if owned_task.cancelled():
                        break
                except BaseException as exc:  # pylint: disable=broad-exception-caught
                    remember_failure("scenario task", exc)
                    break
        if cancel_task:
            await retire_sender()
        if capture_active:
            try:
                await self.stop_capture_if_running()
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                remember_failure("capture", exc)
        if failures:
            if interruption is not None:
                failures.insert(0, ("cancellation", interruption))
            first_error = next(
                (error for _, error in failures if isinstance(error, Exception)), failures[0][1],
            )
            message = (
                f"{label} cleanup reported failures: "
                + "; ".join(
                    f"{owner}: {type(error).__name__}: {error}"
                    for owner, error in failures
                )
            )
            if not isinstance(first_error, Exception):
                self.reporter.print_warning(message)
                raise first_error
            raise RuntimeError(message) from first_error
        if interruption is not None:
            raise interruption

    async def complete_capture(
        self,
        pcap_file: Path,
        sender: PacketStats,
    ) -> AnalysisResult:
        """Retire capture and retain sender evidence even when capture or analysis fails.

        An unavailable analysis remains absent. Cancellation and failed ownership
        retirement propagate; writing diagnostics never authorizes a traffic pass.
        """
        analysis = None
        completion_error = None
        try:
            await self.require_traffic().stop_capture()
            analysis = await self.require_traffic().analyze_capture(
                pcap_file=pcap_file, expected_count=sender.tx_count,
            )
            return analysis
        except BaseException as exc:
            completion_error = exc
            raise
        finally:
            try:
                self.artifacts.write_traffic_evidence(
                    pcap_file, self.config.backend_profile.traffic_driver, sender, analysis,
                )
            except RECOVERABLE_EXCEPTIONS as exc:
                if completion_error is not None:
                    message = (
                        "traffic completion and evidence retention failed: "
                        f"completion={completion_error}; evidence={exc}"
                    )
                    if not isinstance(completion_error, Exception):
                        self.reporter.print_warning(message)
                        raise completion_error from None
                    raise RuntimeError(message) from exc
                raise

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
        if analysis.valid == 0:
            if stats is not None:
                raise RuntimeError("traffic driver published latency without received packets")
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

    @staticmethod
    def epoch_result_message(
        result: EpochTestResult, traffic_within_tolerance: bool, generation_tags_valid: bool,
    ) -> str:
        """Explain the complete verdict without reconstructing a weaker success predicate."""
        tx, rx = result.total_sent, result.total_received
        if result.passed:
            traffic_result = (
                f"Zero loss ({tx} TX = {rx} RX)"
                if result.zero_loss
                else f"Loss {format_number(result.loss_pct, 2)}% within the admitted validation tolerance"
            )
            return (
                "BOUNDARY ORDERING VALIDATED: "
                f"{traffic_result}, "
                f"{result.completed_boundaries}/{result.boundary_count} exact CUT/ACK rows, "
                "zero protocol faults"
            )
        if not traffic_within_tolerance:
            return (
                f"TRAFFIC EVIDENCE FAILED: {tx} TX, {rx} RX, "
                f"loss {format_number(result.loss_pct, 2)}%"
            )
        if not generation_tags_valid:
            return "GENERATION-TAG EVIDENCE FAILED: observed tags disagree with the authored traffic profile"
        if result.protocol_faults_observed is not None and result.protocol_faults_observed != 0:
            return (
                "BOUNDARY ORDERING VIOLATION: "
                f"{result.protocol_faults_observed} typed protocol faults detected "
                f"({tx} TX, {rx} RX)"
            )
        if not result.load_qualified:
            return "LOAD NOT QUALIFIED: old and target configurations lack complete ingress-rate evidence"
        if result.transitions_observed == 0:
            return "TRANSITION NOT CONFIRMED: final configuration does not match the Apply result"
        return "BOUNDARY ORDERING INCONCLUSIVE: exact completion or CUT/ACK evidence is incomplete"

    def rollback_result_message(
        self, full_success: bool, selective_success: bool,
        traffic_ok: bool, traffic_evidence_exact: bool, loss_pct: Optional[float],
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
                f"traffic loss {format_number(loss_pct, 2)}% exceeds threshold "
                f"{self.config.max_loss_pct}%"
            )
        if full_success and selective_success:
            return "ROLLBACK VALIDATED: full and selective rollback completed"
        if full_success:
            return "ROLLBACK PARTIAL: full rollback completed; selective rollback failed"
        if selective_success:
            return "ROLLBACK PARTIAL: selective rollback completed; full rollback failed"
        return "ROLLBACK FAILED: full and selective rollback failed"

    async def get_final_stats_snapshot(self) -> StatsResult:
        """Wait within the observation deadline for post-traffic owner publications.

        The first successful DP collection supplies the monotonic time barrier.
        Every later row must retain its plan and generation and advance beyond
        that barrier. A failed query or contradictory observation is not retried.
        Cancellation propagates through the bounded child-process owner.
        """
        if self.plan_topology is None:
            raise RuntimeError("final stream evidence requires parsed plan metadata")
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
        barrier = baseline.collection_monotonic_ns
        cursor = None

        def ready(current: StatsResult) -> bool:
            """Validate every source identity before testing the post-traffic barrier."""
            nonlocal cursor
            try:
                require_stream_observation(self.plan_topology, cursor, current)
            except ValueError as exc:
                raise RuntimeError(f"final stream observation failed: {exc}") from exc
            cursor = current
            qos_complete = (
                qos_accounting_complete(current, self.plan_topology)
                if self.config.deployment == DeploymentMode.FAN_IN_EDGE_GATEWAY else True
            )
            return qos_complete and all(row.published_monotonic_ns > barrier for row in current.worker_counters)

        ready(baseline)

        async def read() -> StatsResult:
            """Query the complete final diagnostic selection under the shared wait's deadline."""
            return await self.get_stats_snapshot(selection)

        return await self.wait_for_observation(read, ready, deadline, "final stream publication")
