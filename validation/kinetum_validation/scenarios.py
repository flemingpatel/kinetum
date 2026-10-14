"""Execute admitted physical traffic and configuration-transition scenarios."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from typing import List, Optional, Tuple

from .config.types import (
    CONSTANTS,
    AnalysisResult,
    CommitConfirmedTestResult,
    EpochTestResult,
    GuardrailsTestResult,
    RollbackTestResult,
    TestResult,
    TransitionType,
)
from .process.installation import is_symlink_free_regular_file
from .process.telemetry import StatsResult
from .process.kinetumctl import ApplyConfigResult
from .process.guardrails_observation import GuardrailsPolicyIdentity, GuardrailsRead
from .scenario_context import (
    ScenarioContext,
    CONTROL_OBSERVATION_TIMEOUT_S,
    TRANSITION_STATS,
    INITIAL_GENERATION_TAG,
    NEXT_GENERATION_TAG,
)
from .report.artifacts import round_latency
from .process.telemetry_validation import (
    boundary_transition_is_complete,
    worker_counters_advanced,
    worker_counters_are_exact,
)
from .process.system_tools import RECOVERABLE_EXCEPTIONS


CONFIRM_TIMEOUT_ROLLBACK_MS = 1500

CONFIRM_TIMEOUT_MS = 5000

COMMIT_CONFIRMED_TRAFFIC_S = 30.0

ROLLBACK_TRAFFIC_S = 20.0

POST_SEND_DRAIN_S = 2.0

GUARDRAILS_POLL_INTERVAL_MS = 100

GUARDRAILS_EVALUATION_WINDOW_MS = 10_000

GUARDRAILS_TRAFFIC_S = 60.0

GUARDRAILS_ARMING_TIMEOUT_S = 30.0

GUARDRAILS_MAX_DROP_RATIO = 0.01

GUARDRAILS_MIN_TX_RATIO = 0.99


def _guardrails_is_armed(read: GuardrailsRead, policy: GuardrailsPolicyIdentity, baseline: StatsResult) -> bool:
    """Require CP's actual armed baseline under the exact configured policy and content."""
    if read.identity != policy:
        raise RuntimeError("guardrails policy changed while awaiting evidence")
    evaluation = read.evaluation
    if evaluation is None or evaluation.observed_identity is None:
        return False
    identity = evaluation.observed_identity
    identity_changed = (
        identity.runtime_generation != baseline.runtime_generation
        or identity.snapshot_id != baseline.active_snapshot_id or identity.epoch != baseline.active_epoch
        or identity.revision != baseline.active_revision
    )
    if (
        identity_changed
        or identity.validation_hash != baseline.transition_active_validation_hash
        or identity.expected_workers != baseline.expected_workers
    ):
        raise RuntimeError("guardrails armed observation crossed baseline identity")
    return evaluation.state == "GUARDRAILS_EVALUATION_STATE_ARMED"


def _guardrails_attribution_is_accepted(
    read: GuardrailsRead,
    policy: GuardrailsPolicyIdentity,
    baseline: StatsResult,
    candidate: ApplyConfigResult,
) -> bool:
    """Prove both detector legs and accepted attribution even when rollback wins the poll race."""
    if read.identity != policy:
        raise RuntimeError("guardrails policy changed during candidate evaluation")
    evaluation = read.evaluation
    if evaluation is None or evaluation.observed_identity is None:
        return False
    if evaluation.observed_identity.runtime_generation != baseline.runtime_generation:
        raise RuntimeError("runtime generation changed during guardrails evaluation")
    completed = evaluation.last_completed
    if completed is not None and completed.candidate.epoch == candidate.epoch and (
        completed.outcome != "GUARDRAILS_EVALUATION_OUTCOME_ROLLBACK_ACCEPTED"
    ):
        raise RuntimeError(f"guardrails candidate ended without rollback: {completed.outcome}")
    proof = evaluation.last_attribution
    if proof is None or proof.candidate.epoch != candidate.epoch or not proof.intent_accepted:
        return False
    identity = proof.candidate
    identity_changed = (
        identity.snapshot_id != candidate.snapshot_id or identity.revision != candidate.revision
        or identity.expected_workers != baseline.expected_workers
        or proof.rollback_snapshot_id != baseline.active_snapshot_id
    )
    if (
        identity_changed
        or proof.recommendation != "GUARDRAILS_RECOMMENDATION_AUTO_ROLLBACK"
        or not proof.evidence_complete or completed is None or completed.candidate != identity
    ):
        raise RuntimeError("guardrails attribution contradicts the exact candidate or rollback target")
    tx_rate, drop_rate = proof.rates()
    rx_delta = sum(new.rx_packets - old.rx_packets for old, new in zip(proof.previous_workers, proof.current_workers))
    if (
        rx_delta <= 0 or tx_rate + drop_rate <= 0
        or drop_rate / (tx_rate + drop_rate) <= GUARDRAILS_MAX_DROP_RATIO
        or tx_rate / proof.baseline_tx_pps >= GUARDRAILS_MIN_TX_RATIO
    ):
        raise RuntimeError("guardrails retained measurements do not prove both degradation thresholds")
    return True


async def run_packet_test(context: ScenarioContext, packet_size: int) -> TestResult:
    """Run packet forwarding test for a specific size."""
    context.reporter.print_step(f"PACKET TEST ({packet_size}B)")

    start_time = time.monotonic()
    pcap_file = context.config.output_dir / f"capture_{packet_size}.pcap"

    try:
        # Start capture
        # NAT changes source address and port in the canonical gateway scenario.
        capture_filter = f"udp dst port {context.config.packet.base_dport}"
        await context.require_traffic().start_capture(pcap_file, capture_filter)

        # Generate packets
        stats = await context.generate_packets(packet_size)

        # Keep capture open for the bounded post-send dataplane drain.
        await asyncio.sleep(POST_SEND_DRAIN_S)

        analysis = await context.complete_capture(
            pcap_file=pcap_file,
            sender=stats,
        )

        # Calculate results
        loss_pct = analysis.loss_pct(stats.tx_count)
        average_latency = context.measured_average_latency(analysis)
        clean_traffic = context.traffic_observation_is_clean(stats, analysis)
        passed = clean_traffic and loss_pct <= context.config.max_loss_pct

        result = TestResult(
            packet_size=packet_size,
            passed=passed,
            tx_count=stats.tx_count,
            rx_count=analysis.valid,
            loss_pct=loss_pct,
            avg_latency_us=average_latency,
            throughput_pps=stats.actual_pps,
            duration_s=time.monotonic() - start_time,
            message=(
                f"Loss: {loss_pct:.2f}%"
                if clean_traffic
                else "Sender or capture evidence is not exact"
            ),
        )

        return result

    except RECOVERABLE_EXCEPTIONS as e:
        await context.stop_capture_if_running()
        return TestResult(
            packet_size=packet_size,
            passed=False,
            duration_s=time.monotonic() - start_time,
            message=str(e),
        )


def _native_generation_transition_is_exact(analysis: AnalysisResult, initial_count: int) -> bool:
    """Require one ordered tag change per ingress within its successful-send populations."""
    if not analysis.streams or initial_count <= 0:
        return False
    stream_count = len(analysis.streams)
    for row in analysis.streams:
        initial_sent = initial_count // stream_count + int(row.stream_index < initial_count % stream_count)
        if (
            row.first_tag != INITIAL_GENERATION_TAG or row.last_tag != NEXT_GENERATION_TAG
            or row.tag_transition_count != 1 or row.transition_seq < initial_count
        ):
            return False
        if (
            not 0 < row.tag_counts.get(INITIAL_GENERATION_TAG, 0) <= initial_sent
            or not 0 < row.tag_counts.get(NEXT_GENERATION_TAG, 0) <= row.expected_count - initial_sent
        ):
            return False
    return True


async def run_epoch_test(context: ScenarioContext) -> EpochTestResult:
    """
    Run epoch transition test (boundary-ordering validation).

    Validates boundary ordering during configuration transitions:
    1. Query one exact current DP epoch.
    2. Start continuous traffic with driver-owned epoch evidence.
    3. Dispatch one configuration mutation during the traffic window.
    4. Continue traffic through the exact adjacent transition.
    5. Require exact traffic within the fixed validation loss bound, one
       COMPLETE terminal identity, every compiled boundary's matching
       CUT/ACK proof, and zero protocol-fault delta.

    Returns
    -------
    EpochTestResult
        Epoch test results.
    """
    context.reporter.print_step("EPOCH TEST (Boundary-Ordering Validation)")

    start_time = time.monotonic()
    epoch_config = context.config.epoch
    pcap_file = context.config.output_dir / "epoch_capture.pcap"

    # -----------------------------------------------------------------
    # Capture exact DP truth before the traffic source starts. Traffic tags
    # never encode this epoch; the two observations prove that packets
    # reached DP before transition mutation begins.
    # -----------------------------------------------------------------
    if not context.control:
        return EpochTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message="Error: exact current-epoch observation is unavailable",
        )
    try:
        traffic_start_stats = await context.get_stats_snapshot()
        _, dp_epoch_start = context.require_active_snapshot_observation(
            traffic_start_stats, "epoch traffic start"
        )
    except RuntimeError as exc:
        return EpochTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message=f"Error: {exc}",
        )
    if dp_epoch_start <= 0:
        return EpochTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message="Error: exact current-epoch observation failed",
        )
    context.reporter.print_progress(f"DP current epoch: {dp_epoch_start}")

    # Traffic drivers own bounded generation-tag evidence. The tag never
    # carries or predicts the independently validated Data Plane epoch.

    sender = None
    apply_task = None
    try:
        # Start capture
        context.reporter.print_progress("Starting packet capture...")
        await context.require_traffic().start_capture(
            pcap_file, f"udp dst port {context.config.packet.base_dport}"
        )

        # Create packet config for epoch test
        epoch_pkt_config = replace(
            context.config.packet,
            pps=epoch_config.pps,
            duration_s=epoch_config.duration_s,
        )

        sender = context.require_traffic().make_sender(epoch_pkt_config)
        sustained_overlap = (
            context.require_traffic().requires_sustained_generation_overlap
        )

        context.reporter.print_progress(
            f"Starting traffic: {epoch_pkt_config.pps} PPS, "
            f"{epoch_pkt_config.packet_size}B for {epoch_pkt_config.duration_s}s"
        )

        await sender.begin_generation_tags(
            epoch_config.duration_s,
            INITIAL_GENERATION_TAG,
            NEXT_GENERATION_TAG,
        )
        transition_deadline = time.monotonic() + epoch_config.transition_time_s
        epoch_end_deadline = time.monotonic() + epoch_config.duration_s

        # Wait for baseline traffic
        transition_time = epoch_config.transition_time_s
        context.reporter.print_progress(
            f"Baseline traffic for {transition_time}s before transition..."
        )
        pre_snapshot_margin = min(0.25, transition_time / 2.0)
        await asyncio.sleep(transition_time - pre_snapshot_margin)

        # -----------------------------------------------------------------
        # PRE-TRANSITION TELEMETRY SNAPSHOT
        # -----------------------------------------------------------------
        pre_stats: Optional[StatsResult] = None
        if context.control:
            pre_stats = await context.wait_for_traffic_progress(
                traffic_start_stats, transition_deadline,
                "epoch pre-transition traffic",
                required_live_task=None,
            )
            context.reporter.print_progress(
                f"Pre-transition snapshot: epoch={pre_stats.active_epoch}"
                f" rx={pre_stats.rx_packets} tx={pre_stats.tx_packets}"
            )

        # -----------------------------------------------------------------
        # EPOCH TRANSITION (boundary-ordering core)
        # -----------------------------------------------------------------
        context.reporter.print_progress(
            f">>> TRIGGERING TRANSITION FROM EPOCH {dp_epoch_start} <<<"
        )

        # Dispatch config apply while the traffic driver creates overlap:
        # native TAP requests its one pre-authored tag transition after
        # apply is dispatched; TRex resumes paused next-tag PGID streams
        # under the same orchestrator clock, then pauses initial-tag streams
        # after the requested overlap window. The mandatory ordered boundary
        # gate holds future-epoch packets until each exact ACK opens its
        # sender.
        config_v2 = None
        if context.control and context.config.spec.config_snapshot_v2:
            config_v2 = (
                context.config.process.examples_dir
                / context.config.spec.example_dir
                / context.config.spec.config_snapshot_v2
            )

        if config_v2 and is_symlink_free_regular_file(config_v2):
            remaining = transition_deadline - time.monotonic()
            if remaining <= 0.0:
                raise RuntimeError(
                    "pre-transition evidence missed the authored transition time"
                )
            await asyncio.sleep(remaining)
            apply_task = asyncio.create_task(
                context.control.apply_config(
                    config_v2, expected_revision=pre_stats.active_revision
                )
            )
            await sender.start_generation_overlap(NEXT_GENERATION_TAG)
            if sustained_overlap:
                context.reporter.print_progress(
                    "Traffic driver started sustained generation-tag overlap"
                )
                await asyncio.sleep(epoch_config.overlap_window_ms / 1000.0)
            else:
                context.reporter.print_progress(
                    f"Generation tag changed to {NEXT_GENERATION_TAG} "
                    "while apply was in flight"
                )
            await sender.end_generation_overlap()
            if sustained_overlap:
                context.reporter.print_progress(
                    "Traffic driver ended initial-generation overlap after "
                    f"{epoch_config.overlap_window_ms} ms"
                )
            applied = await apply_task
            apply_task = None
            if not applied.success:
                raise RuntimeError(
                    f"configuration transition failed: {applied.diagnostic}"
                )
            if applied.epoch <= dp_epoch_start:
                raise RuntimeError("configuration transition returned a stale epoch")
            dp_epoch_next = applied.epoch
            context.reporter.print_progress(
                f"Config v2 applied at exact epoch {dp_epoch_next}"
            )
        else:
            raise RuntimeError("config_snapshot_v2 is not an exact regular file")

        # -----------------------------------------------------------------
        context.reporter.print_progress("Continuing traffic through transition...")
        remaining = epoch_end_deadline - time.monotonic()
        if remaining <= 0.0:
            raise RuntimeError(
                "configuration transition exceeded the authored traffic window"
            )
        await asyncio.sleep(remaining)
        stats = await sender.finish_generation_tags()

        # Keep capture open for the bounded post-send dataplane drain.
        await asyncio.sleep(POST_SEND_DRAIN_S)

        # -----------------------------------------------------------------
        # ANALYZE RESULTS
        # -----------------------------------------------------------------
        context.reporter.print_progress("Analyzing epoch transition...")

        analysis = await context.complete_capture(
            pcap_file=pcap_file,
            sender=stats,
        )

        # Calculate results
        loss_pct = analysis.loss_pct(stats.tx_count)
        epoch_avg_latency = context.measured_average_latency(analysis)
        # Exact sender/capture accounting remains mandatory; the selected
        # validation profile may separately admit its bounded loss SLO.
        traffic_within_tolerance = (
            context.traffic_observation_is_clean(stats, analysis)
            and loss_pct <= CONSTANTS.EPOCH_LOSS_TOLERANCE_PCT
        )

        expected_generation_tags = {
            INITIAL_GENERATION_TAG, NEXT_GENERATION_TAG
        }
        generation_membership_valid = (
            set(stats.generation_tag_counts) == expected_generation_tags
            and set(analysis.tag_counts) == expected_generation_tags
        )
        initial_generation_sent = (
            stats.generation_tag_counts[INITIAL_GENERATION_TAG]
            if generation_membership_valid else 0
        )
        next_generation_sent = (
            stats.generation_tag_counts[NEXT_GENERATION_TAG]
            if generation_membership_valid else 0
        )
        initial_generation_rx = (
            analysis.tag_counts[INITIAL_GENERATION_TAG]
            if generation_membership_valid else 0
        )
        next_generation_rx = (
            analysis.tag_counts[NEXT_GENERATION_TAG]
            if generation_membership_valid else 0
        )
        generation_tags_valid = (
            generation_membership_valid
            and initial_generation_sent > 0
            and next_generation_sent > 0
            and 0 < initial_generation_rx <= initial_generation_sent
            and 0 < next_generation_rx <= next_generation_sent
            and (
                sustained_overlap
                or _native_generation_transition_is_exact(analysis, initial_generation_sent)
            )
        )

        # -----------------------------------------------------------------
        # POST-TRANSITION TELEMETRY SNAPSHOT + DELTA COMPUTATION
        # Captured after traffic generator completes and packets settle.
        # Delta = cumulative counters across the epoch test window,
        # including traffic before, during, and after transition.
        # -----------------------------------------------------------------
        config_applied = False
        dp_epoch_after = 0
        post_stats: Optional[StatsResult] = None
        boundary_count = 0
        completed_boundaries = 0
        protocol_faults_observed = 0
        total_backpressure = 0

        if context.control:
            post_stats = await context.get_stats_snapshot()
            if not post_stats.success:
                context.reporter.print_error(
                    "Post-transition stats collection failed", post_stats.diagnostic,
                )
                raise RuntimeError("Post-transition stats collection failed")
            dp_epoch_after = post_stats.active_epoch
            config_applied = (
                dp_epoch_after == dp_epoch_next
                and post_stats.active_snapshot_id == applied.snapshot_id
                and post_stats.active_revision == applied.revision
            )
            context.reporter.print_progress(
                f"Post-transition snapshot: epoch={post_stats.active_epoch}"
                f" rx={post_stats.rx_packets} tx={post_stats.tx_packets}"
            )

            if pre_stats and pre_stats.success:
                if pre_stats.runtime_generation != post_stats.runtime_generation:
                    raise RuntimeError(
                        "runtime generation changed across epoch evidence"
                    )
                for code, post_count in post_stats.protocol_fault_counts.items():
                    pre_count = pre_stats.protocol_fault_counts.get(code)
                    if pre_count is None or post_count < pre_count:
                        raise RuntimeError(
                            "protocol fault counters regressed or changed membership"
                        )
                    protocol_faults_observed += post_count - pre_count

            boundary_count = len(post_stats.boundary_epoch_stats)
            terminal_generation = (
                post_stats.latest_terminal.mutation_sequence
                if post_stats.latest_terminal is not None
                else 0
            )
            pre_bt_map = {
                bt.boundary_id: bt
                for bt in pre_stats.boundary_epoch_stats
            } if pre_stats and pre_stats.success else {}
            for bt in post_stats.boundary_epoch_stats:
                pre_bt = pre_bt_map.get(bt.boundary_id)
                pre_backpressure = (
                    pre_bt.data_backpressure_events
                    if pre_bt is not None else 0
                )
                if bt.data_backpressure_events < pre_backpressure:
                    raise RuntimeError(
                        f"boundary {bt.boundary_id} backpressure regressed"
                    )
                total_backpressure += (
                    bt.data_backpressure_events - pre_backpressure
                )
                exact_complete = boundary_transition_is_complete(
                    bt, terminal_generation, dp_epoch_start, dp_epoch_after
                )
                if exact_complete:
                    completed_boundaries += 1
                context.reporter.print_progress(
                    f"  {bt.boundary_id}: cut={bt.cut_sequence}"
                    f" enqueued={bt.data_enqueued_sequence}"
                    f" dequeued={bt.data_dequeued_sequence}"
                    f" ack_gate_ns={bt.ack_gate_duration_ns}"
                )

        # Transition confirmed only if DP epoch actually advanced
        transitions_observed = 1 if config_applied else 0

        # -----------------------------------------------------------------
        # BOUNDARY-ORDERING VERDICT:
        # 1. Exact traffic evidence within the selected loss SLO.
        # 2. The exact target epoch completed.
        # 3. Every boundary retained one exact CUT/ACK identity and timing.
        # 4. No typed protocol fault appeared in the transition window.
        # -----------------------------------------------------------------
        terminal_complete = (
            post_stats is not None
            and post_stats.latest_terminal is not None
            and post_stats.latest_terminal.outcome
            == "EPOCH_TRANSITION_OUTCOME_COMPLETE"
            and post_stats.latest_terminal.from_epoch == dp_epoch_start
            and post_stats.latest_terminal.to_epoch == dp_epoch_after
            and not post_stats.transition_success_blocked
            and not post_stats.retirement_frozen
        )
        boundary_ordering_validated = (
            transitions_observed > 0
            and terminal_complete
            and boundary_count > 0
            and completed_boundaries == boundary_count
            and protocol_faults_observed == 0
        )
        if (
            boundary_ordering_validated
            and pre_stats is not None
            and pre_stats.success
            and post_stats is not None
        ):
            context.artifacts.write_transition_metrics(
                pre_stats, post_stats, dp_epoch_start, dp_epoch_after,
                transition_type=TransitionType.EPOCH,
            )
        passed = (
            traffic_within_tolerance
            and generation_tags_valid
            and transitions_observed > 0
            and boundary_ordering_validated
        )

        result = EpochTestResult(
            passed=passed,
            duration_s=time.monotonic() - start_time,
            total_sent=stats.tx_count,
            total_received=analysis.valid,
            initial_generation_sent=initial_generation_sent,
            next_generation_sent=next_generation_sent,
            initial_generation_received=initial_generation_rx,
            next_generation_received=next_generation_rx,
            generation_tag_transition_seq=(
                analysis.transition_seq if analysis.transition_seq >= 0 else -1
            ),
            transitions_observed=transitions_observed,
            loss_pct=loss_pct,
            avg_latency_us=round_latency(epoch_avg_latency),
            boundary_count=boundary_count,
            completed_boundaries=completed_boundaries,
            protocol_faults_observed=protocol_faults_observed,
            backpressure_events=total_backpressure,
            boundary_ordering_validated=boundary_ordering_validated,
        )
        result.message = context.epoch_result_message(result, traffic_within_tolerance, generation_tags_valid)

        return result

    except RECOVERABLE_EXCEPTIONS as e:
        context.reporter.print_error("Epoch test failed", str(e))
        return EpochTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message=f"Error: {e}",
        )
    finally:
        await context.retire_scenario_traffic(
            "epoch",
            sender,
            apply_task,
            capture_active=True,
        )


async def run_commit_confirmed_test(context: ScenarioContext) -> CommitConfirmedTestResult:
    """
    Run commit-confirmed pattern validation test.

    Tests the commit-confirmed pattern from
    docs/CONTROL_PLANE_AND_GUARDRAILS_AND_ROLLBACK.md:
    1. Use the baseline snapshot already applied during setup.
    2. Apply config with a five-second confirmation deadline.
    3. Verify traffic is working (send some test packets).
    4. Confirm within timeout.
    5. Observe the confirmed identity beyond its deadline and prove continued traffic.

    Returns
    -------
    CommitConfirmedTestResult
        Test result including confirm success and timing info.
    """
    context.reporter.print_step("COMMIT-CONFIRMED TEST")

    start_time = time.monotonic()
    spec = context.config.spec
    if spec.config_snapshot_v2 is None:
        return CommitConfirmedTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message="Commit-confirmed test requires a second snapshot",
        )
    config_file = (
        context.config.process.examples_dir
        / spec.example_dir
        / spec.config_snapshot_v2
    )

    if not is_symlink_free_regular_file(config_file):
        return CommitConfirmedTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message=f"Config file not found: {config_file}",
        )

    if not context.control:
        return CommitConfirmedTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message="kinetumctl not initialized",
        )

    cc_gen_task = None
    cc_capturing = False
    cc_sender = None
    result = CommitConfirmedTestResult(passed=False)
    try:
        # FULL runs follow the epoch scenario, which intentionally leaves
        # v2 active. Re-establish the authored baseline through the same
        # public transition surface before arming a v2 confirmation; a
        # same-content pending-confirm record would have no distinct
        # rollback target and must remain inadmissible.
        baseline_file = (
            context.config.process.examples_dir
            / spec.example_dir
            / spec.config_snapshot
        )
        if not is_symlink_free_regular_file(baseline_file):
            raise RuntimeError("commit-confirmed baseline is unavailable")
        current = await context.get_stats_snapshot(selection=replace(TRANSITION_STATS, include_stage_stats=False))
        context.require_active_snapshot_observation(
            current, "commit-confirmed baseline admission"
        )
        normalized = await context.control.apply_config(
            baseline_file, expected_revision=current.active_revision
        )
        if not normalized.success:
            raise RuntimeError(
                "commit-confirmed baseline transition failed: "
                + normalized.diagnostic
            )
        normalized_stats = await context.get_stats_snapshot(
            selection=replace(TRANSITION_STATS, include_stage_stats=False),
        )
        context.require_active_snapshot_observation(
            normalized_stats,
            "commit-confirmed baseline",
            normalized.snapshot_id,
        )
        if (
            normalized_stats.active_epoch != normalized.epoch
            or normalized_stats.active_revision != normalized.revision
        ):
            raise RuntimeError(
                "commit-confirmed baseline result and telemetry disagree"
            )

        # -----------------------------------------------------------------
        # Start continuous traffic before any transitions
        # -----------------------------------------------------------------
        cc_pcap = context.config.output_dir / "commit_confirmed_capture.pcap"

        context.reporter.print_progress("Starting traffic capture for commit-confirmed window...")
        await context.require_traffic().start_capture(
            cc_pcap, f"udp dst port {context.config.packet.base_dport}"
        )
        cc_capturing = True

        cc_pkt_config = replace(
            context.config.packet,
            pps=context.config.epoch.pps,
        )

        cc_sender = context.require_traffic().make_sender(cc_pkt_config)

        context.reporter.print_progress("Starting continuous traffic...")
        cc_deadline = time.monotonic() + COMMIT_CONFIRMED_TRAFFIC_S
        cc_gen_task = asyncio.create_task(
            cc_sender.run_timed(COMMIT_CONFIRMED_TRAFFIC_S)
        )

        # -----------------------------------------------------------------
        # PRE-TRANSITION TELEMETRY SNAPSHOT (under load)
        # -----------------------------------------------------------------
        pre_stats = await context.wait_for_traffic_progress(
            normalized_stats, cc_deadline,
            "commit-confirmed pre-transition traffic",
            cc_gen_task,
        )
        context.require_live_traffic_task(
            cc_gen_task, "commit-confirmed first mutation"
        )

        # -----------------------------------------------------------------
        # Apply the candidate with commit-confirmed mode under load.
        # -----------------------------------------------------------------
        confirm_timeout_ms = CONFIRM_TIMEOUT_MS
        context.reporter.print_progress(
            f"Applying config with --confirm-timeout {confirm_timeout_ms}ms"
        )

        try:
            async with asyncio.timeout(max(0.0, cc_deadline - time.monotonic())):
                apply_result = await context.control.apply_config_with_confirm(
                    config_file,
                    confirm_timeout_ms,
                    expected_revision=pre_stats.active_revision,
                )
        except TimeoutError as exc:
            raise RuntimeError("confirmed apply exceeded the traffic window") from exc

        if not apply_result.success:
            raise RuntimeError(f"Failed to apply config: {apply_result.diagnostic}")

        snapshot_id = apply_result.snapshot_id
        result.confirm_snapshot_id = snapshot_id
        context.reporter.print_progress(f"Config applied: snapshot_id={snapshot_id}")

        # -----------------------------------------------------------------
        # POST-TRANSITION TELEMETRY SNAPSHOT (under load)
        # -----------------------------------------------------------------
        post_stats = await context.get_stats_before_deadline(
            cc_deadline, "post-confirmation transition",
        )
        if not post_stats.success:
            raise RuntimeError(
                "post-confirmation transition telemetry is unavailable"
            )
        applied_identity = (apply_result.snapshot_id, apply_result.revision, apply_result.epoch)
        observed_identity = (post_stats.active_snapshot_id, post_stats.active_revision, post_stats.active_epoch)
        runtime_exact = (
            post_stats.runtime_generation == pre_stats.runtime_generation
            and post_stats.transition_plan_content_hash == pre_stats.transition_plan_content_hash
        )
        transition_ready = (
            post_stats.transition_state == "EPOCH_TRANSITION_STATE_IDLE"
            and not post_stats.transition_success_blocked and not post_stats.retirement_frozen
        )
        if (
            observed_identity != applied_identity or apply_result.epoch <= pre_stats.active_epoch
            or not runtime_exact or not transition_ready
        ):
            raise RuntimeError(
                "commit-confirmed result and telemetry identity disagree"
            )

        # -----------------------------------------------------------------
        # Confirm within the timeout while traffic remains live.
        # -----------------------------------------------------------------
        context.reporter.print_progress(f"Confirming config: {snapshot_id}")

        try:
            async with asyncio.timeout(max(0.0, cc_deadline - time.monotonic())):
                confirm_result = await context.control.confirm(
                    snapshot_id,
                    apply_result.epoch,
                    apply_result.revision,
                )
        except TimeoutError as exc:
            raise RuntimeError("confirmation exceeded the traffic window") from exc

        if not confirm_result.success:
            raise RuntimeError(f"Failed to confirm: {confirm_result.diagnostic}")

        if not 0 < confirm_result.time_remaining_ms <= confirm_timeout_ms:
            raise RuntimeError("confirmation returned an invalid remaining interval")
        result.confirm_success = True
        result.confirm_time_remaining_ms = confirm_result.time_remaining_ms
        confirmed_at = time.monotonic()
        survival_not_before = confirmed_at + confirm_result.time_remaining_ms / 1000.0
        if not worker_counters_are_exact(post_stats):
            raise RuntimeError("confirmed configuration lacks exact worker observations")
        confirmed_cursor = post_stats.worker_counters

        # -----------------------------------------------------------------
        # The expiry boundary is only a time floor. Exact active identity and
        # subsequent source progress are the success evidence.
        # -----------------------------------------------------------------
        context.reporter.print_progress("Observing confirmed config beyond its original deadline...")

        def confirmed_identity_survived(observed: StatsResult) -> bool:
            """Reject any intervening identity change before accepting an after-deadline read."""
            nonlocal confirmed_cursor
            context.require_active_snapshot_observation(observed, "confirmed identity", apply_result.snapshot_id)
            identity_changed = (
                observed.runtime_generation != post_stats.runtime_generation
                or observed.active_revision != apply_result.revision
                or observed.active_epoch != apply_result.epoch
                or observed.transition_plan_content_hash != post_stats.transition_plan_content_hash
                or observed.transition_active_validation_hash != post_stats.transition_active_validation_hash
            )
            if (
                identity_changed or observed.transition_state != "EPOCH_TRANSITION_STATE_IDLE"
                or observed.transition_success_blocked or observed.retirement_frozen
                or not worker_counters_are_exact(observed)
            ):
                raise RuntimeError("confirmed active identity changed unexpectedly")
            worker_counters_advanced(confirmed_cursor, observed.worker_counters)
            confirmed_cursor = observed.worker_counters
            return time.monotonic() >= survival_not_before

        surviving = await context.wait_for_observation(
            context.get_stats_snapshot, confirmed_identity_survived, cc_deadline,
            "confirmed configuration survival", cc_gen_task,
        )
        stats_result = await context.wait_for_traffic_progress(
            surviving, cc_deadline, "confirmed traffic after deadline", cc_gen_task,
        )
        confirmed_survival_elapsed_ms = int((time.monotonic() - confirmed_at) * 1000.0)
        if confirmed_survival_elapsed_ms < confirm_result.time_remaining_ms:
            raise RuntimeError("confirmed configuration was not observed beyond its deadline")
        result.confirmed_survived_deadline = True
        result.confirmed_survival_elapsed_ms = confirmed_survival_elapsed_ms
        context.artifacts.write_transition_metrics(
            pre_stats, stats_result, pre_stats.active_epoch, stats_result.active_epoch,
            transition_type=TransitionType.COMMIT_CONFIRMED,
        )
        context.require_live_traffic_task(
            cc_gen_task, "commit-confirmed timeout rollback"
        )

        try:
            async with asyncio.timeout(max(0.0, cc_deadline - time.monotonic())):
                timeout_apply = await context.control.apply_config_with_confirm(
                    baseline_file,
                    CONFIRM_TIMEOUT_ROLLBACK_MS,
                    expected_revision=stats_result.active_revision,
                )
        except TimeoutError as exc:
            raise RuntimeError("unconfirmed apply exceeded the traffic window") from exc
        if (
            not timeout_apply.success or timeout_apply.epoch <= stats_result.active_epoch
            or timeout_apply.snapshot_id != normalized_stats.active_snapshot_id
            or timeout_apply.revision != normalized_stats.active_revision
        ):
            raise RuntimeError(
                "unconfirmed transition failed: " + timeout_apply.diagnostic
            )
        # CP starts the durable timeout at COMPLETE. The apply reply can arrive
        # after automatic rollback; retain its exact candidate identity without
        # inventing a candidate counter observation or a second expiry clock.
        rollback_before = stats_result
        rollback_cursor = stats_result.worker_counters

        def confirmation_rollback_completed(observed: StatsResult) -> bool:
            """Accept only the exact candidate-to-confirmed terminal transition."""
            nonlocal rollback_before, rollback_cursor
            context.require_active_snapshot_observation(observed, "confirmation rollback")
            if (
                observed.runtime_generation != stats_result.runtime_generation
                or observed.transition_plan_content_hash != stats_result.transition_plan_content_hash
                or observed.transition_success_blocked or observed.retirement_frozen
                or not worker_counters_are_exact(observed)
            ):
                raise RuntimeError("confirmation rollback crossed runtime/plan identity or invalid evidence")
            worker_counters_advanced(rollback_cursor, observed.worker_counters)
            rollback_cursor = observed.worker_counters
            if observed.transition_active_epoch == timeout_apply.epoch:
                if (
                    observed.active_snapshot_id != timeout_apply.snapshot_id
                    or observed.active_revision != timeout_apply.revision
                    or observed.transition_active_validation_hash != normalized_stats.transition_active_validation_hash
                ):
                    raise RuntimeError("unconfirmed result and active telemetry disagree")
                # During RETIRING, packet execution has advanced but CP still
                # owns the predecessor. Keep the earlier counter endpoint.
                if observed.active_epoch == timeout_apply.epoch:
                    rollback_before = observed
                return False
            terminal = observed.latest_terminal
            restored_identity_exact = (
                observed.transition_active_epoch > timeout_apply.epoch
                and observed.active_epoch == observed.transition_active_epoch
                and observed.active_snapshot_id == stats_result.active_snapshot_id
                and observed.active_revision == stats_result.active_revision
                and observed.transition_active_validation_hash == stats_result.transition_active_validation_hash
            )
            terminal_exact = terminal is not None and all((
                terminal.from_epoch == timeout_apply.epoch,
                terminal.to_epoch == observed.active_epoch,
                terminal.outcome == "EPOCH_TRANSITION_OUTCOME_COMPLETE",
                terminal.failure_code == "EPOCH_TRANSITION_FAILURE_CODE_NONE",
            ))
            if not restored_identity_exact or not terminal_exact:
                raise RuntimeError("confirmation rollback lacks the exact candidate-to-confirmed terminal transition")
            return observed.transition_state == "EPOCH_TRANSITION_STATE_IDLE"

        restored = await context.wait_for_observation(
            context.get_stats_snapshot, confirmation_rollback_completed,
            min(cc_deadline, time.monotonic() + CONTROL_OBSERVATION_TIMEOUT_S),
            "confirmation rollback", cc_gen_task,
        )
        restored = await context.wait_for_traffic_progress(
            restored, cc_deadline, "confirmation rollback traffic", cc_gen_task,
        )
        result.timeout_rollback_occurred = True
        result.timeout_rollback_snapshot_id = restored.active_snapshot_id
        context.artifacts.write_transition_metrics(
            rollback_before,
            restored,
            timeout_apply.epoch,
            restored.active_epoch,
            transition_type=TransitionType.COMMIT_CONFIRMED_TIMEOUT_ROLLBACK,
        )

        # The same source and capture remain live through both measured
        # transitions. Only after the automatic rollback is exact may the
        # scenario retire traffic and summarize its packet evidence.
        cc_stats = await cc_gen_task
        await asyncio.sleep(1.0)
        cc_analysis = await context.complete_capture(cc_pcap, cc_stats)
        cc_capturing = False

        cc_tx = cc_stats.tx_count
        cc_rx = cc_analysis.valid
        cc_loss = cc_analysis.loss_pct(cc_tx)
        cc_latency = context.measured_average_latency(cc_analysis)

        # Build result with traffic metrics
        cc_traffic_evidence_exact = context.traffic_observation_is_clean(cc_stats, cc_analysis)
        cc_traffic_ok = (
            cc_traffic_evidence_exact
            and cc_loss <= context.config.max_loss_pct
        )
        traffic_summary = f"traffic TX={cc_tx} RX={cc_rx} loss={cc_loss:.2f}%"
        if cc_traffic_ok:
            cc_message = (
                "COMMIT-CONFIRMED VALIDATED: "
                f"confirmed with {confirm_result.time_remaining_ms}ms remaining, "
                f"retained through {confirmed_survival_elapsed_ms}ms, "
                f"{traffic_summary}"
            )
        elif not cc_traffic_evidence_exact:
            cc_message = (
                "COMMIT-CONFIRMED FAILED: sender/capture accounting or "
                f"generation-tag evidence is not exact, {traffic_summary}"
            )
        else:
            cc_message = (
                "COMMIT-CONFIRMED FAILED: "
                f"traffic loss {cc_loss:.2f}% exceeds threshold "
                f"{context.config.max_loss_pct}%, {traffic_summary}"
            )
        result = replace(
            result,
            passed=cc_traffic_ok,
            duration_s=time.monotonic() - start_time,
            tx_count=cc_tx,
            rx_count=cc_rx,
            loss_pct=round(cc_loss, 4),
            avg_latency_us=round_latency(cc_latency),
            message=cc_message,
        )

        return result

    except RECOVERABLE_EXCEPTIONS as e:
        return replace(
            result,
            duration_s=time.monotonic() - start_time,
            message=f"Error: {e}",
        )
    finally:
        await context.retire_scenario_traffic(
            "commit-confirmed",
            cc_sender,
            cc_gen_task,
            cancel_task=True,
            capture_active=cc_capturing,
        )


async def run_rollback_test(context: ScenarioContext) -> RollbackTestResult:
    """
    Run rollback validation test.

    Proves selective and full rollback with two distinct snapshots:
    1. Apply v1 config (baseline: ACL=1 rule/permit, NAT=300s, QoS=DSCP 10)
    2. Apply v2 config (different: ACL=2 rules/deny, NAT=600s, QoS=DSCP 20)
    3. Selective rollback ACL to v1 -> creates hybrid snapshot
    4. Verify hybrid has: ACL from v1, NAT/QoS from v2
    5. Full rollback to v1 -> restores everything

    Config Differences (for verification):
    ---------------------------------------------------------------------
    | Module  | v1                        | v2                          |
    +---------+---------------------------+-----------------------------+
    | ACL     | 1 rule, default=permit    | 2 rules, default=deny       |
    | NAT44   | timeout=300s              | timeout=600s                |
    | QoS     | 10 Gbps, DSCP 10          | 10 Gbps, DSCP 20            |
    ---------------------------------------------------------------------

    Returns
    -------
    RollbackTestResult
        Test result including rollback success and module info.
    """
    context.reporter.print_step("ROLLBACK TEST")

    start_time = time.monotonic()

    # Both rollback modes require independently authored source and target content.
    spec = context.config.spec
    if spec.config_snapshot_v2 is None:
        return RollbackTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message="Rollback test requires a second snapshot",
        )
    config_v1 = (
        context.config.process.examples_dir
        / spec.example_dir
        / spec.config_snapshot
    )
    config_v2 = (
        context.config.process.examples_dir
        / spec.example_dir
        / spec.config_snapshot_v2
    )

    if not is_symlink_free_regular_file(config_v1):
        return RollbackTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message=f"Config v1 not found: {config_v1}",
        )

    if not is_symlink_free_regular_file(config_v2):
        return RollbackTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message=f"Config v2 not found: {config_v2}",
        )

    if not context.control:
        return RollbackTestResult(
            passed=False,
            duration_s=time.monotonic() - start_time,
            message="kinetumctl not initialized",
        )

    rb_gen_task = None
    rb_capturing = False
    rb_sender = None
    result = RollbackTestResult(passed=False)
    try:
        traffic_start_stats = await context.get_stats_snapshot()
        context.require_active_snapshot_observation(
            traffic_start_stats, "rollback traffic start"
        )

        # -----------------------------------------------------------------
        # Start continuous traffic before any transitions
        # -----------------------------------------------------------------
        rb_pcap = context.config.output_dir / "rollback_capture.pcap"

        context.reporter.print_progress("Starting traffic capture for rollback window...")
        await context.require_traffic().start_capture(
            rb_pcap, f"udp dst port {context.config.packet.base_dport}"
        )
        rb_capturing = True

        rb_pkt_config = replace(
            context.config.packet,
            pps=context.config.epoch.pps,
        )

        rb_sender = context.require_traffic().make_sender(rb_pkt_config)

        context.reporter.print_progress("Starting continuous traffic...")
        rb_deadline = time.monotonic() + ROLLBACK_TRAFFIC_S
        rb_gen_task = asyncio.create_task(rb_sender.run_timed(ROLLBACK_TRAFFIC_S))

        # -----------------------------------------------------------------
        # PRE-TRANSITION TELEMETRY SNAPSHOT (under load)
        # -----------------------------------------------------------------
        pre_rb_stats: Optional[StatsResult] = None
        pre_rb_stats = await context.wait_for_traffic_progress(
            traffic_start_stats, rb_deadline,
            "rollback pre-transition traffic",
            rb_gen_task,
        )
        context.require_live_traffic_task(
            rb_gen_task, "rollback v1 apply"
        )
        context.reporter.print_progress(
            f"Pre-rollback snapshot: epoch={pre_rb_stats.active_epoch}"
        )

        # -----------------------------------------------------------------
        # Transition 1: Apply v1 config (baseline, under load)
        # -----------------------------------------------------------------
        # ACL: 1 rule "allow_all", default=permit
        # NAT44: timeout=300s
        # QoS: DSCP 10; rate and burst allowance are shared by both snapshots.
        # -----------------------------------------------------------------
        context.reporter.print_progress("Applying v1 config (baseline)...")

        apply_v1 = await context.control.apply_config(
            config_v1, expected_revision=pre_rb_stats.active_revision
        )
        if not apply_v1.success:
            return RollbackTestResult(
                passed=False,
                duration_s=time.monotonic() - start_time,
                message=f"Failed to apply v1 config: {apply_v1.diagnostic}",
            )

        stats_v1 = await context.get_stats_before_deadline(rb_deadline, "rollback v1")
        v1_snapshot_id, v1_epoch = context.require_active_snapshot_observation(
            stats_v1,
            "post-v1",
            apply_v1.snapshot_id,
        )
        if v1_epoch != apply_v1.epoch or stats_v1.active_revision != apply_v1.revision:
            raise RuntimeError("v1 mutation result and telemetry identity disagree")
        active_v1 = await context.control.get_active_snapshot()
        if (
            active_v1.snapshot_id != v1_snapshot_id
            or active_v1.revision != apply_v1.revision
        ):
            raise RuntimeError("v1 active content disagrees with mutation result")
        context.reporter.print_progress(
            f"V1 applied: snapshot={v1_snapshot_id} epoch={v1_epoch}"
        )
        context.reporter.print_progress(
            "  V1: ACL=1 rule/permit, NAT=300s, QoS=10Gbps/DSCP10"
        )

        # Record transition 1: pre_rb -> v1 (under load)
        context.artifacts.write_transition_metrics(
            pre_rb_stats, stats_v1,
            pre_rb_stats.active_epoch, v1_epoch,
            transition_type=TransitionType.ROLLBACK_APPLY_V1,
        )
        context.require_live_traffic_task(
            rb_gen_task, "rollback v2 apply"
        )

        # -----------------------------------------------------------------
        # Transition 2: Apply v2 config (different settings)
        # -----------------------------------------------------------------
        # ACL: 2 rules "deny_ssh + allow_rest", default=deny
        # NAT44: timeout=600s
        # QoS: DSCP 20; rate and burst allowance are unchanged.
        # -----------------------------------------------------------------
        context.reporter.print_progress("Applying v2 config (different settings)...")

        apply_v2 = await context.control.apply_config(
            config_v2, expected_revision=stats_v1.active_revision
        )
        if not apply_v2.success:
            return RollbackTestResult(
                passed=False,
                duration_s=time.monotonic() - start_time,
                message=f"Failed to apply v2 config: {apply_v2.diagnostic}",
            )

        stats_v2 = await context.get_stats_before_deadline(rb_deadline, "rollback v2")
        v2_snapshot_id, v2_epoch = context.require_active_snapshot_observation(
            stats_v2,
            "post-v2",
            apply_v2.snapshot_id,
        )
        if v2_epoch != apply_v2.epoch or stats_v2.active_revision != apply_v2.revision:
            raise RuntimeError("v2 mutation result and telemetry identity disagree")
        active_v2 = await context.control.get_active_snapshot()
        if (
            active_v2.snapshot_id != v2_snapshot_id
            or active_v2.revision != apply_v2.revision
        ):
            raise RuntimeError("v2 active content disagrees with mutation result")
        context.reporter.print_progress(
            f"V2 applied: snapshot={v2_snapshot_id} epoch={v2_epoch}"
        )
        context.reporter.print_progress(
            "  V2: ACL=2 rules/deny, NAT=600s, QoS=10Gbps/DSCP20"
        )

        # Record transition 2: v1 -> v2 (chain: stats_v1 is pre)
        context.artifacts.write_transition_metrics(
            stats_v1, stats_v2, v1_epoch, v2_epoch,
            transition_type=TransitionType.ROLLBACK_APPLY_V2,
        )

        # Allow config to take effect
        await asyncio.sleep(0.5)

        # -----------------------------------------------------------------
        # Transition 3: Selective rollback (ACL module only to v1)
        # -----------------------------------------------------------------
        # Expected result: Hybrid snapshot with:
        #   - ACL from v1 (1 rule, permit)
        #   - NAT44 from v2 (600s) - NOT rolled back
        #   - QoS from v2 (DSCP 20) - NOT rolled back
        # -----------------------------------------------------------------
        context.reporter.print_progress(
            "Testing selective rollback (ACL only to v1)..."
        )
        context.require_live_traffic_task(
            rb_gen_task, "selective rollback"
        )

        modules_to_rollback = ["kinetum.acl"]
        rollback_result = await context.control.rollback(
            v1_snapshot_id,
            module_ids=modules_to_rollback,
            expected_revision=stats_v2.active_revision,
        )

        selective_success = rollback_result.success
        hybrid_snapshot_id = rollback_result.new_snapshot_id if selective_success else ""

        # Post-selective snapshot for metrics (and pre for transition 4)
        stats_selective: Optional[StatsResult] = None
        if selective_success:
            # Verify hybrid snapshot is different from both v1 and v2
            is_hybrid = hybrid_snapshot_id not in (
                v1_snapshot_id,
                v2_snapshot_id,
            )
            if is_hybrid:
                context.reporter.print_progress(
                    f"Selective rollback created hybrid: {hybrid_snapshot_id}"
                )
                context.reporter.print_progress(
                    "  Expected: ACL=v1 (1 rule/permit), NAT=v2 (600s), QoS=v2 (10Gbps/DSCP20)"
                )
            else:
                context.reporter.print_warning(
                    "Selective rollback did NOT create hybrid snapshot "
                    f"(got {hybrid_snapshot_id}, expected different from "
                    f"{v1_snapshot_id} and {v2_snapshot_id})"
                )
                selective_success = False

            # Capture post-selective snapshot for transition 3 metrics
            stats_selective = await context.get_stats_before_deadline(rb_deadline, "selective rollback")
            _, selective_epoch = (
                context.require_active_snapshot_observation(
                    stats_selective,
                    "post-selective-rollback",
                    hybrid_snapshot_id,
                )
            )
            if (
                selective_epoch != rollback_result.epoch
                or stats_selective.active_revision
                != rollback_result.new_revision
            ):
                raise RuntimeError(
                    "selective rollback result and telemetry identity disagree"
                )
            active_hybrid = await context.control.get_active_snapshot()
            context.require_selective_rollback_content(
                active_v1,
                active_v2,
                active_hybrid,
                rollback_result.new_snapshot_id,
                rollback_result.new_revision,
            )
            result.selective_rollback_success = selective_success
            result.selective_rollback_modules = modules_to_rollback if selective_success else []
            result.selective_rollback_snapshot_id = hybrid_snapshot_id
            context.artifacts.write_transition_metrics(
                stats_v2, stats_selective,
                v2_epoch, selective_epoch,
                transition_type=TransitionType.ROLLBACK_SELECTIVE,
            )
        else:
            context.reporter.print_warning(
                f"Selective rollback failed: {rollback_result.diagnostic}"
            )

        # -----------------------------------------------------------------
        # Transition 4: Full rollback to v1
        # -----------------------------------------------------------------
        # Expected result: All modules restored to v1 settings
        # -----------------------------------------------------------------
        context.reporter.print_progress("Testing full rollback to v1...")

        # Pre for transition 4: use stats_selective if available, else stats_v2
        pre_full = stats_selective if stats_selective else stats_v2
        context.require_live_traffic_task(rb_gen_task, "full rollback")

        full_rollback_result = await context.control.rollback(
            v1_snapshot_id,
            expected_revision=pre_full.active_revision,
        )

        full_success = full_rollback_result.success

        if full_success and full_rollback_result.new_snapshot_id != v1_snapshot_id:
            context.reporter.print_warning(
                "Full rollback response identity mismatch: "
                f"got {full_rollback_result.new_snapshot_id}, expected "
                f"{v1_snapshot_id}"
            )
            full_success = False

        if full_success:
            # Verify we're back to v1 snapshot
            stats_after_full = await context.get_stats_before_deadline(rb_deadline, "full rollback")
            restored_snapshot, restored_epoch = context.require_active_snapshot_observation(
                stats_after_full,
                "post-full-rollback",
                v1_snapshot_id,
            )
            if (
                restored_epoch != full_rollback_result.epoch
                or stats_after_full.active_revision
                != full_rollback_result.new_revision
            ):
                raise RuntimeError(
                    "full rollback result and telemetry identity disagree"
                )
            active_after_full = await context.control.get_active_snapshot()
            if active_after_full != active_v1:
                raise RuntimeError(
                    "full rollback did not restore exact v1 snapshot content"
                )
            result.full_rollback_success = True
            result.full_rollback_snapshot_id = restored_snapshot

            context.reporter.print_progress(
                f"Full rollback restored: {restored_snapshot}"
            )
            context.reporter.print_progress(
                "  Restored: ACL=v1, NAT=v1, QoS=v1 (all modules)"
            )

            # Record transition 4: selective/v2 -> full rollback
            context.artifacts.write_transition_metrics(
                pre_full, stats_after_full,
                pre_full.active_epoch, restored_epoch,
                transition_type=TransitionType.ROLLBACK_FULL,
            )
        elif not full_rollback_result.success:
            context.reporter.print_warning(
                f"Full rollback failed: {full_rollback_result.diagnostic}"
            )

        # -----------------------------------------------------------------
        # TRAFFIC-UNDER-TRANSITION: Collect and analyze
        # -----------------------------------------------------------------
        rb_pkt_stats = await rb_gen_task
        await asyncio.sleep(1.0)
        rb_analysis = await context.complete_capture(rb_pcap, rb_pkt_stats)
        rb_capturing = False

        rb_tx = rb_pkt_stats.tx_count
        rb_rx = rb_analysis.valid
        rb_loss = rb_analysis.loss_pct(rb_tx)
        rb_latency = context.measured_average_latency(rb_analysis)

        # -----------------------------------------------------------------
        # Build result
        # -----------------------------------------------------------------
        rb_traffic_evidence_exact = context.traffic_observation_is_clean(rb_pkt_stats, rb_analysis)
        traffic_ok = (
            rb_traffic_evidence_exact
            and rb_loss <= context.config.max_loss_pct
        )
        passed = full_success and selective_success and traffic_ok

        result = replace(
            result,
            passed=passed,
            duration_s=time.monotonic() - start_time,
            tx_count=rb_tx,
            rx_count=rb_rx,
            loss_pct=round(rb_loss, 4),
            avg_latency_us=round_latency(rb_latency),
            message=context.rollback_result_message(
                full_success,
                selective_success,
                traffic_ok,
                rb_traffic_evidence_exact,
                rb_loss,
            ),
        )

        return result

    except RECOVERABLE_EXCEPTIONS as e:
        return replace(
            result,
            duration_s=time.monotonic() - start_time,
            message=f"Error: {e}",
        )
    finally:
        await context.retire_scenario_traffic(
            "rollback",
            rb_sender,
            rb_gen_task,
            cancel_task=True,
            capture_active=rb_capturing,
        )


async def run_guardrails_test(context: ScenarioContext) -> GuardrailsTestResult:
    """Drive one exact telemetry-attributed durable automatic rollback."""
    context.reporter.print_step("GUARDRAILS TEST")
    started = time.monotonic()
    degradation_snapshot = context.config.spec.guardrails_degradation_snapshot
    if context.control is None or degradation_snapshot is None:
        return GuardrailsTestResult(
            passed=False,
            duration_s=time.monotonic() - started,
            message=(
                "guardrails requires kinetumctl and an explicit "
                "degradation snapshot"
            ),
        )
    candidate_file = (
        context.config.process.examples_dir
        / context.config.spec.example_dir
        / degradation_snapshot
    )
    if not is_symlink_free_regular_file(candidate_file):
        return GuardrailsTestResult(
            passed=False,
            duration_s=time.monotonic() - started,
            message="guardrails candidate snapshot is unavailable",
        )

    sender = None
    candidate_task: Optional[asyncio.Task] = None
    policy_enabled = False
    policy_cleanup_required = False
    result: Optional[GuardrailsTestResult] = None
    try:
        baseline = await context.get_stats_snapshot()
        baseline_id, baseline_epoch = context.require_active_snapshot_observation(
            baseline, "guardrails baseline"
        )
        policy_cleanup_required = True
        configured_policy = await context.control.configure_guardrails(
            enabled=True,
            poll_interval_ms=GUARDRAILS_POLL_INTERVAL_MS,
            evaluation_window_ms=GUARDRAILS_EVALUATION_WINDOW_MS,
            max_drop_ratio=GUARDRAILS_MAX_DROP_RATIO,
            min_tx_ratio=GUARDRAILS_MIN_TX_RATIO,
            min_packets_per_window=1,
        )
        policy_enabled = configured_policy is not None
        if configured_policy is None:
            raise RuntimeError("guardrails policy configuration failed")

        sender = context.require_traffic().make_sender(context.config.packet)
        traffic_started = time.monotonic()
        traffic_deadline = traffic_started + GUARDRAILS_TRAFFIC_S
        arming_deadline = traffic_started + GUARDRAILS_ARMING_TIMEOUT_S
        candidate_task = asyncio.create_task(sender.run_timed(GUARDRAILS_TRAFFIC_S))
        baseline_ready = await context.wait_for_traffic_progress(
            baseline, arming_deadline, "guardrails baseline traffic", candidate_task,
        )

        def armed(read: GuardrailsRead) -> bool:
            """Wait for the current policy's ten real baseline intervals."""
            return _guardrails_is_armed(read, configured_policy, baseline_ready)

        armed_observation = await context.wait_for_observation(
            context.control.get_guardrails, armed, arming_deadline,
            "guardrails baseline arming", candidate_task,
        )
        arming_elapsed_s = time.monotonic() - traffic_started
        if arming_elapsed_s >= GUARDRAILS_ARMING_TIMEOUT_S:
            raise RuntimeError("guardrails arming completed outside its authored window")
        context.require_live_traffic_task(candidate_task, "guardrails candidate apply")
        context.reporter.print_progress("Applying the ACL fixture that deliberately drops validation traffic...")
        candidate = await asyncio.wait_for(
            context.control.apply_config(
                candidate_file, expected_revision=baseline_ready.active_revision,
            ),
            timeout=max(0.0, traffic_deadline - time.monotonic()),
        )
        if not candidate.success or candidate.epoch <= baseline_epoch or candidate.snapshot_id == baseline_id:
            raise RuntimeError("guardrails candidate transition failed: " + candidate.diagnostic)

        def attributed(read: GuardrailsRead) -> bool:
            """Require retained candidate measurements and the accepted safety intent."""
            return _guardrails_attribution_is_accepted(read, configured_policy, baseline_ready, candidate)

        decision = await context.wait_for_observation(
            context.control.get_guardrails, attributed, traffic_deadline,
            "guardrails candidate attribution", candidate_task,
        )
        restored = await context.wait_for_active_snapshot(
            baseline_id, candidate.epoch, baseline.runtime_generation, traffic_deadline,
            required_live_task=candidate_task,
        )
        if (
            restored.latest_terminal is None
            or restored.latest_terminal.from_epoch != candidate.epoch
            or restored.transition_active_validation_hash != baseline.transition_active_validation_hash
        ):
            raise RuntimeError("guardrails rollback lacks the exact candidate-to-baseline terminal transition")
        worker_counters_advanced(decision.evaluation.last_attribution.current_workers, restored.worker_counters)
        context.artifacts.write_guardrails_evaluation(armed_observation, decision, arming_elapsed_s)
        candidate_traffic = await candidate_task
        candidate_task = None
        if candidate_traffic.tx_count == 0 or candidate_traffic.errors != 0:
            raise RuntimeError("guardrails traffic is not valid evidence")
        if set(restored.protocol_fault_counts) != set(
            baseline.protocol_fault_counts
        ):
            raise RuntimeError("guardrails protocol-fault membership changed")
        protocol_faults = 0
        for code, count in restored.protocol_fault_counts.items():
            before = baseline.protocol_fault_counts[code]
            if count < before:
                raise RuntimeError("guardrails protocol-fault counter regressed")
            protocol_faults += count - before
        if protocol_faults != 0:
            raise RuntimeError("guardrails rollback crossed a protocol fault")
        context.artifacts.write_transition_metrics(
            baseline_ready,
            restored,
            candidate.epoch,
            restored.active_epoch,
            transition_type=TransitionType.GUARDRAILS_ROLLBACK,
        )
        if not await context.control.configure_guardrails(enabled=False):
            raise RuntimeError("guardrails policy could not be disabled")
        policy_enabled = False
        policy_cleanup_required = False
        result = GuardrailsTestResult(
            passed=True,
            duration_s=time.monotonic() - started,
            policy_configured=True,
            baseline_snapshot_id=baseline_id,
            candidate_snapshot_id=candidate.snapshot_id,
            rollback_snapshot_id=restored.active_snapshot_id,
            candidate_epoch=candidate.epoch,
            rollback_epoch=restored.active_epoch,
            protocol_faults_observed=0,
            message="GUARDRAILS VALIDATED: exact attributed rollback completed",
        )
        return result
    except RECOVERABLE_EXCEPTIONS as exc:
        result = GuardrailsTestResult(
            passed=False,
            duration_s=time.monotonic() - started,
            policy_configured=policy_enabled,
            message=f"Error: {exc}",
        )
        return result
    finally:
        cleanup_failures: List[Tuple[str, BaseException]] = []
        if policy_cleanup_required:
            try:
                if not await context.control.configure_guardrails(
                    enabled=False
                ):
                    cleanup_failures.append((
                        "policy",
                        RuntimeError(
                            "guardrails policy cleanup did not converge"
                        ),
                    ))
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                cleanup_failures.append(("policy", exc))
        try:
            await context.retire_scenario_traffic(
                "guardrails",
                sender,
                candidate_task,
                cancel_task=True,
            )
        except BaseException as exc:  # pylint: disable=broad-exception-caught
            cleanup_failures.append(("traffic", exc))
        if cleanup_failures:
            message = "; ".join(
                f"{owner}: {type(error).__name__}: {error}"
                for owner, error in cleanup_failures
            )
            context.reporter.print_warning(message)
            fatal = next(
                (
                    error
                    for _owner, error in cleanup_failures
                    if not isinstance(error, Exception)
                ),
                None,
            )
            if fatal is not None:
                raise fatal
            if result is not None:
                result.passed = False
                result.message = f"{result.message}; {message}"
