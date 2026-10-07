"""Publish run observations, transition evidence, and final results."""

from __future__ import annotations

import json
import math
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, TextIO

from ..config.types import BackendProfile, TestSuiteResult, TransitionType
from ..engine.json_contract import (
    EXPECTED_TRANSITION_TYPES_BY_TEST,
    parse_exact_json_object,
    validate_test_suite_result,
    validate_transition_metric_record,
)
from ..process.installation import is_symlink_free_regular_file
from ..process.telemetry import PortStatsResult, StatsResult
from .console import ConsoleReporter
from ..process.telemetry_validation import boundary_transition_is_complete
from ..process.system_tools import RECOVERABLE_EXCEPTIONS


def round_latency(value: Optional[float]) -> Optional[float]:
    """Round one measured latency while preserving unavailability."""
    return round(value, 2) if value is not None else None


class RunArtifacts:
    """Publish exact run evidence beneath the coordinator's held output root."""

    def __init__(self, output_dir: Path, reporter: ConsoleReporter) -> None:
        """Bind an already-owned output directory and the run's reporter."""
        self.output_dir = output_dir
        self.reporter = reporter

    def write_stats(self, stats: StatsResult) -> None:
        """Write observations or a query-failure note; only success yields JSON and a summary."""
        stats_file = self.output_dir / "dp_stats.txt"
        with open(stats_file, "x", encoding="utf-8") as f:
            f.write("# Kinetum DP Statistics\n")
            f.write("# Collected at end of test\n\n")
            if stats.success:
                f.write(f"rx_packets: {stats.rx_packets}\n")
                f.write(f"tx_packets: {stats.tx_packets}\n")
                f.write(f"dropped_packets: {stats.dropped_packets}\n")
                f.write(f"rx_bytes: {stats.rx_bytes}\n")
                f.write(f"tx_bytes: {stats.tx_bytes}\n")
                f.write(f"runtime_generation: {stats.runtime_generation}\n")
                f.write(
                    f"collection_monotonic_ns: "
                    f"{stats.collection_monotonic_ns}\n"
                )
                f.write(f"active_epoch: {stats.active_epoch}\n")
                f.write(f"active_revision: {stats.active_revision}\n")
                f.write(f"active_snapshot_id: {stats.active_snapshot_id}\n")
                f.write(f"transition_state: {stats.transition_state}\n")
                f.write(
                    f"transition_success_blocked: "
                    f"{stats.transition_success_blocked}\n"
                )

                f.write("\n# Protocol Fault Counters\n")
                for code, count in sorted(stats.protocol_fault_counts.items()):
                    f.write(f"  {code}: {count}\n")

                if stats.stage_stats:
                    f.write("\n# Stage Stats\n")
                    for ss in stats.stage_stats:
                        f.write(f"  {ss.stage_id}:"
                                f" in={ss.in_packets}"
                                f" out={ss.out_packets}"
                                f" drop={ss.dropped_packets}\n")

                if stats.module_counter_stats:
                    f.write("\n# Module Counters\n")
                    for counter in stats.module_counter_stats:
                        f.write(
                            f"  {counter.context_instance_id}/"
                            f"{counter.name}: epoch={counter.epoch}"
                            f" value={counter.value}\n"
                        )

                if stats.module_histogram_stats:
                    f.write("\n# Module Histograms\n")
                    for histogram in stats.module_histogram_stats:
                        f.write(
                            f"  {histogram.context_instance_id}/"
                            f"{histogram.name}: epoch={histogram.epoch}"
                            f" count={histogram.sample_count}"
                            f" p99={histogram.p99}\n"
                        )

                if stats.module_epoch_mismatch_stats:
                    f.write("\n# Module Epoch Mismatches\n")
                    for mismatch in stats.module_epoch_mismatch_stats:
                        f.write(
                            f"  {mismatch.context_instance_id}:"
                            f" epoch={mismatch.observation_epoch}"
                            f" count={mismatch.mismatch_count}"
                            f" first_packet={mismatch.first_packet_epoch}"
                            f" first_active={mismatch.first_active_epoch}\n"
                        )

                if stats.module_health_stats:
                    f.write("\n# Module Health\n")
                    for health in stats.module_health_stats:
                        f.write(
                            f"  {health.context_instance_id}:"
                            f" state={health.state}"
                            f" epoch={health.observation_epoch}"
                            f" score={health.health_score}"
                            f" faults={health.contract_fault_count}\n"
                        )

                if stats.boundary_epoch_stats:
                    f.write("\n# Boundary Epoch Stats\n")
                    for bt in stats.boundary_epoch_stats:
                        f.write(f"  {bt.boundary_id}:"
                                f" enqueued={bt.data_enqueued_sequence}"
                                f" dequeued={bt.data_dequeued_sequence}"
                                f" backpressure={bt.data_backpressure_events}"
                                f" transition={bt.transition_generation}"
                                f" cut={bt.cut_sequence}"
                                f" sender={bt.sender_phase}"
                                f" receiver={bt.receiver_phase}"
                                f" cut_delivery_ns="
                                f"{bt.cut_delivery_duration_ns}"
                                f" cut_drain_ns={bt.cut_drain_duration_ns}"
                                f" ack_gate_ns={bt.ack_gate_duration_ns}\n")

                if stats.worker_epoch_stats:
                    f.write("\n# Worker Epoch Stats\n")
                    for ws in stats.worker_epoch_stats:
                        f.write(f"  {ws.worker_id}:"
                                f" active={ws.active_epoch}"
                                f" source={ws.source_epoch}"
                                f" active_unretired={ws.active_unretired}"
                                f" future={ws.future_epoch}"
                                f" future_unretired={ws.future_unretired}"
                                f" activation_complete="
                                f"{ws.activation_complete}\n")

                if stats.region_epoch_stats:
                    f.write("\n# Region Epoch Stats\n")
                    for rs in stats.region_epoch_stats:
                        f.write(f"  region_{rs.region_id}:"
                                f" active={rs.minimum_active_epoch}.."
                                f"{rs.maximum_active_epoch}"
                                f" source={rs.minimum_source_epoch}.."
                                f"{rs.maximum_source_epoch}"
                                f" active_unretired={rs.active_unretired}"
                                f" future_unretired={rs.future_unretired}"
                                f" activated={rs.activated_participants}/"
                                f"{rs.worker_count}"
                                f" fanout_overflow={rs.fanout_overflow}\n")

                if stats.stream_stats:
                    f.write("\n# Stream Stats\n")
                    for ss in stats.stream_stats:
                        f.write(f"  {ss.io_stream_id}:"
                                f" logical_port={ss.logical_port_id}"
                                f" direction={ss.direction}"
                                f" region={ss.owning_region_id}"
                                f" worker={ss.worker_index}"
                                f" driver_queue={ss.driver_queue_id}"
                                f" published_monotonic_ns={ss.published_monotonic_ns}"
                                f" packets={ss.packets}"
                                f" bytes={ss.bytes}"
                                f" rejected_packets={ss.rejected_packets}\n")

                if stats.storage_domain_stats:
                    f.write("\n# Packet Storage Domain Stats\n")
                    for storage in stats.storage_domain_stats:
                        f.write(
                            f"  {storage.storage_domain_id}:"
                            f" host_numa={storage.host_numa_node}"
                            f" buffers={storage.buffer_count}"
                            f" required_min_buffers="
                            f"{storage.required_min_buffers}"
                            f" safety_margin={storage.safety_margin}"
                            f" observation_state="
                            f"{storage.observation_state}"
                            f" in_use={storage.in_use}"
                            f" available={storage.available}\n"
                        )

                self._write_port_stats_section(f, stats.port_stats)

                if stats.traffic_steering_stats:
                    f.write("\n# Traffic Steering Stats\n")
                    for ts in stats.traffic_steering_stats:
                        f.write(f"  {ts.steering_profile_id}:"
                                f" kind={ts.kind}"
                                f" symmetric={ts.symmetric}"
                                f" io_stream_ids={ts.io_stream_ids}\n")

                if stats.module_context_domains:
                    f.write("\n# Module Context Domains\n")
                    for domain in stats.module_context_domains:
                        f.write(f"  {domain.module_id}:"
                                f" contexts={domain.context_instance_ids}\n")
            else:
                f.write("# Query failed: exact telemetry unavailable\n")
                return
        # Save JSON for programmatic consumption
        stats_json_file = self.output_dir / "dp_stats.json"
        with open(stats_json_file, "x", encoding="utf-8") as f:
            json.dump({
                "success": stats.success,
                "error": stats.diagnostic if not stats.success else "",
                "rx_packets": stats.rx_packets,
                "tx_packets": stats.tx_packets,
                "dropped_packets": stats.dropped_packets,
                "rx_bytes": stats.rx_bytes,
                "tx_bytes": stats.tx_bytes,
                "fanout_overflow": stats.fanout_overflow,
                "runtime_generation": stats.runtime_generation,
                "status_publication_generation":
                    stats.status_publication_generation,
                "collection_monotonic_ns": stats.collection_monotonic_ns,
                "minimum_retained_epoch": stats.minimum_retained_epoch,
                "last_activated_epoch": stats.last_activated_epoch,
                "active_workers": stats.active_workers,
                "expected_workers": stats.expected_workers,
                "latest_bank_publication_monotonic_ns":
                    stats.latest_bank_publication_monotonic_ns,
                "skipped_publications": stats.skipped_publications,
                "active_epoch": stats.active_epoch,
                "active_revision": stats.active_revision,
                "active_snapshot_id": stats.active_snapshot_id,
                "transition_state": stats.transition_state,
                "transition_publication_generation":
                    stats.transition_publication_generation,
                "transition_active_epoch": stats.transition_active_epoch,
                "transition_target_epoch": stats.transition_target_epoch,
                "allocated_epoch_high_watermark":
                    stats.allocated_epoch_high_watermark,
                "mutation_sequence_high_watermark":
                    stats.mutation_sequence_high_watermark,
                "transition_plan_content_hash":
                    stats.transition_plan_content_hash,
                "transition_active_validation_hash":
                    stats.transition_active_validation_hash,
                "participant_set_frozen": stats.participant_set_frozen,
                "execution_participant_count":
                    stats.execution_participant_count,
                "region_count": stats.region_count,
                "boundary_count": stats.boundary_count,
                "source_participant_count":
                    stats.source_participant_count,
                "sink_participant_count": stats.sink_participant_count,
                "module_context_count": stats.module_context_count,
                "quiescence_reader_count":
                    stats.quiescence_reader_count,
                "terminal_history_size": stats.terminal_history_size,
                "retirement_frozen": stats.retirement_frozen,
                "active_transaction": (
                    asdict(stats.active_transaction)
                    if stats.active_transaction is not None else None
                ),
                "latest_terminal": (
                    asdict(stats.latest_terminal)
                    if stats.latest_terminal is not None else None
                ),
                "certificate": (
                    asdict(stats.certificate)
                    if stats.certificate is not None else None
                ),
                "grace": (
                    asdict(stats.grace)
                    if stats.grace is not None else None
                ),
                "transition_success_blocked":
                    stats.transition_success_blocked,
                "protocol_fault_counts": stats.protocol_fault_counts,
                "first_protocol_fault": (
                    asdict(stats.first_protocol_fault)
                    if stats.first_protocol_fault is not None else None
                ),
                "stage_stats": [asdict(row) for row in stats.stage_stats],
                "module_counter_stats": [
                    asdict(row) for row in stats.module_counter_stats
                ],
                "module_histogram_stats": [
                    asdict(row) for row in stats.module_histogram_stats
                ],
                "module_epoch_mismatch_stats": [
                    asdict(row)
                    for row in stats.module_epoch_mismatch_stats
                ],
                "module_health_stats": [
                    asdict(row) for row in stats.module_health_stats
                ],
                "boundary_epoch_stats": [
                    asdict(row) for row in stats.boundary_epoch_stats
                ],
                "region_epoch_stats": [
                    asdict(row) for row in stats.region_epoch_stats
                ],
                "worker_epoch_stats": [
                    asdict(row) for row in stats.worker_epoch_stats
                ],
                "stream_stats": [
                    asdict(row) for row in stats.stream_stats
                ],
                "storage_domain_stats": [
                    asdict(row) for row in stats.storage_domain_stats
                ],
                "port_stats": [
                    asdict(row) for row in stats.port_stats
                ],
                "traffic_steering_stats": [
                    asdict(row) for row in stats.traffic_steering_stats
                ],
                "module_context_domains": [
                    asdict(row)
                    for row in stats.module_context_domains
                ],
            }, f, allow_nan=False, indent=2, sort_keys=True)
            f.write("\n")

        self.reporter.print_progress(f"Stats saved to {stats_file}")

        # Compute transition distributions from JSONL records
        self.write_transition_summary()

    @staticmethod
    def _write_port_stats_section(
        output: TextIO,
        port_stats: List[PortStatsResult],
    ) -> None:
        """Write exact logical-port provider counters to a stats text artifact."""
        if not port_stats:
            return

        output.write("\n# Port Stats\n")
        for ps in port_stats:
            output.write(f"  {ps.logical_name}:"
                         f" logical_port={ps.logical_port_id}"
                         f" io_driver={ps.io_driver_instance_id}"
                         f" driver_port={ps.driver_port_id}"
                         f" observation_state={ps.observation_state}"
                         f" rx_packets={ps.rx_packets}"
                         f" tx_packets={ps.tx_packets}"
                         f" rx_bytes={ps.rx_bytes}"
                         f" tx_bytes={ps.tx_bytes}"
                         f" rx_missed={ps.rx_missed}"
                         f" rx_errors={ps.rx_errors}"
                         f" tx_errors={ps.tx_errors}"
                         f" rx_no_buffer={ps.rx_no_buffer}\n")

    def write_transition_summary(self) -> None:
        """
        Read transition_metrics.jsonl and compute per-transition distributions.

        Writes transition_summary.json with min/p50/p95/max for key metrics
        across all recorded transitions. Requires at least 1 transition record.
        """
        metrics_file = self.output_dir / "transition_metrics.jsonl"
        if metrics_file.is_symlink():
            raise ValueError("transition metrics input is indirect")
        if not metrics_file.exists():
            return
        if not metrics_file.is_file():
            raise ValueError("transition metrics input is not a regular file")

        records = []
        with open(metrics_file, encoding="utf-8") as f:
            for line in f:
                if not line.endswith("\n") or not line[:-1]:
                    raise ValueError(
                        "transition metrics contain a malformed record boundary"
                    )
                record = parse_exact_json_object(
                    line[:-1], "transition metrics record"
                )
                validate_transition_metric_record(record)
                records.append(record)

        if not records:
            return

        expected_membership = None
        for record in records:
            fault_deltas = record["protocol_fault_deltas"]
            boundary_identities = [
                (row["boundary_id"], row["boundary_index"])
                for row in record["boundary_epoch_stats"]
            ]
            region_ids = [
                row["region_id"] for row in record["region_epoch_stats"]
            ]
            stage_ids = [row["stage_id"] for row in record["stage_stats"]]
            malformed_faults = (
                not isinstance(fault_deltas, dict)
                or not fault_deltas
                or any(
                    not isinstance(code, str)
                    or not code
                    or not isinstance(count, int)
                    or isinstance(count, bool)
                    or count < 0
                    for code, count in fault_deltas.items()
                )
            )
            malformed_identity = (
                any(
                    not isinstance(value, str) or not value
                    for value, _index in boundary_identities
                )
                or any(
                    not isinstance(index, int) or isinstance(index, bool)
                    for _value, index in boundary_identities
                )
                or any(
                    not isinstance(value, int) or isinstance(value, bool)
                    for value in region_ids
                )
                or any(
                    not isinstance(value, str) or not value
                    for value in stage_ids
                )
            )
            duplicate_identity = (
                len(boundary_identities) != len(set(boundary_identities))
                or len(region_ids) != len(set(region_ids))
                or len(stage_ids) != len(set(stage_ids))
            )
            if malformed_faults or malformed_identity or duplicate_identity:
                raise ValueError(
                    "transition summary contains malformed row membership"
                )
            membership = (
                tuple(sorted(fault_deltas)),
                tuple(sorted(boundary_identities)),
                tuple(sorted(region_ids)),
                tuple(sorted(stage_ids)),
            )
            if expected_membership is None:
                expected_membership = membership
            elif membership != expected_membership:
                raise ValueError(
                    "transition summary membership changed across evidence records"
                )

        def percentile(values: List[float], pct: float) -> float:
            """Compute percentile using nearest-rank method."""
            if not values:
                return 0.0
            s = sorted(values)
            idx = max(0, min(len(s) - 1, int(math.ceil(pct / 100.0 * len(s))) - 1))
            return s[idx]

        def distribution(values: List[float]) -> dict:
            """Compute min/p50/p95/max distribution."""
            if not values:
                return {"min": 0, "p50": 0, "p95": 0, "max": 0, "count": 0}
            return {
                "min": min(values),
                "p50": percentile(values, 50),
                "p95": percentile(values, 95),
                "max": max(values),
                "count": len(values),
            }

        # Aggregate final sequence-CUT timing and backpressure evidence.
        cut_delivery_by_boundary: dict[str, List[int]] = {}
        cut_drain_by_boundary: dict[str, List[int]] = {}
        ack_gate_by_boundary: dict[str, List[int]] = {}
        backpressure_by_boundary: dict[str, List[int]] = {}
        for rec in records:
            for bd in rec["boundary_epoch_stats"]:
                bid = bd["boundary_id"]
                cut_delivery_by_boundary.setdefault(bid, []).append(
                    bd["cut_delivery_duration_ns"]
                )
                cut_drain_by_boundary.setdefault(bid, []).append(
                    bd["cut_drain_duration_ns"]
                )
                ack_gate_by_boundary.setdefault(bid, []).append(
                    bd["ack_gate_duration_ns"]
                )
                backpressure_by_boundary.setdefault(bid, []).append(
                    bd["data_backpressure_events_delta"]
                )

        # Fan-out overflow is the sole retained region-level drop subtype.
        fanout_by_region: dict[int, List[int]] = {}
        for rec in records:
            for rd in rec["region_epoch_stats"]:
                rid = rd["region_id"]
                fanout_by_region.setdefault(rid, []).append(
                    rd["fanout_overflow_delta"]
                )

        # Aggregate per-stage dropped_packets_delta
        drops_by_stage: dict[str, List[int]] = {}
        for rec in records:
            for sd in rec["stage_stats"]:
                sid = sd["stage_id"]
                drops_by_stage.setdefault(sid, []).append(
                    sd["dropped_packets_delta"]
                )

        # -----------------------------------------------------------------
        # Per-type breakdown: group records by transition_type, compute
        # boundary timing distributions for each type independently.
        # This lets analysis distinguish epoch vs rollback vs commit behavior.
        # -----------------------------------------------------------------
        records_by_type: dict[str, list] = {}
        for rec in records:
            ttype = rec["transition_type"]
            records_by_type.setdefault(ttype, []).append(rec)

        per_type: dict[str, dict] = {}
        for ttype, typed_records in records_by_type.items():
            type_ack_gate: dict[str, List[int]] = {}
            type_region_fanout: dict[int, List[int]] = {}
            for rec in typed_records:
                for bd in rec["boundary_epoch_stats"]:
                    bid = bd["boundary_id"]
                    type_ack_gate.setdefault(bid, []).append(
                        bd["ack_gate_duration_ns"]
                    )
                for rd in rec["region_epoch_stats"]:
                    rid = rd["region_id"]
                    type_region_fanout.setdefault(rid, []).append(
                        rd["fanout_overflow_delta"]
                    )
            per_type[ttype] = {
                "count": len(typed_records),
                "boundary_ack_gate_ns": {
                    bid: distribution(vals)
                    for bid, vals in type_ack_gate.items()
                },
                "region_fanout_overflow": {
                    str(rid): distribution(vals)
                    for rid, vals in type_region_fanout.items()
                },
            }

        summary = {
            "transition_count": len(records),
            "boundary_cut_delivery_ns": {
                bid: distribution(vals)
                for bid, vals in cut_delivery_by_boundary.items()
            },
            "boundary_cut_drain_ns": {
                bid: distribution(vals)
                for bid, vals in cut_drain_by_boundary.items()
            },
            "boundary_ack_gate_ns": {
                bid: distribution(vals)
                for bid, vals in ack_gate_by_boundary.items()
            },
            "boundary_backpressure_events": {
                bid: distribution(vals)
                for bid, vals in backpressure_by_boundary.items()
            },
            "region_fanout_overflow": {
                str(rid): distribution(vals)
                for rid, vals in fanout_by_region.items()
            },
            "stage_drops": {
                sid: distribution(vals)
                for sid, vals in drops_by_stage.items()
            },
            "per_type": per_type,
        }

        summary_file = self.output_dir / "transition_summary.json"
        with open(summary_file, "x", encoding="utf-8") as f:
            json.dump(summary, f, allow_nan=False, indent=2, sort_keys=True)
            f.write("\n")

        self.reporter.print_progress(
            f"Transition summary: {len(records)} transition(s)"
            f" across {len(records_by_type)} type(s)"
        )
        for ttype, info in per_type.items():
            self.reporter.print_progress(
                f"  {ttype}: {info['count']} transition(s)"
            )
        for bid, dist in summary["boundary_ack_gate_ns"].items():
            self.reporter.print_progress(
                f"  {bid} ack_gate_ns: min={dist['min']}"
                f" p50={dist['p50']} p95={dist['p95']} max={dist['max']}"
            )

    def write_transition_metrics(
        self,
        pre: StatsResult,
        post: StatsResult,
        from_epoch: int,
        to_epoch: int,
        transition_type: TransitionType = TransitionType.EPOCH,
    ) -> None:
        """
        Compute per-transition deltas and append to transition_metrics.jsonl.

        Writes one JSON record only for exact boundary timing,
        generation-cumulative counter deltas, and protocol-fault deltas.

        Parameters
        ----------
        pre : StatsResult
            Stats snapshot taken before the transition.
        post : StatsResult
            Stats snapshot taken after the transition.
        from_epoch : int
            Epoch before transition.
        to_epoch : int
            Epoch after transition.
        transition_type : TransitionType
            Tag for this transition kind.
        """
        if pre.runtime_generation != post.runtime_generation:
            raise RuntimeError(
                "runtime generation changed across transition metrics"
            )
        terminal = post.latest_terminal
        terminal_exact = terminal is not None and all((
            terminal.outcome == "EPOCH_TRANSITION_OUTCOME_COMPLETE",
            terminal.failure_code == "EPOCH_TRANSITION_FAILURE_CODE_NONE",
            terminal.mutation_sequence > 0,
            terminal.from_epoch == from_epoch,
            terminal.to_epoch == to_epoch,
            not post.transition_success_blocked,
            not post.retirement_frozen,
        ))
        if not terminal_exact:
            raise RuntimeError(
                "transition metrics lack one exact successful terminal identity"
            )

        def delta(current: int, previous: int, identity: str) -> int:
            """Return one monotonic same-generation counter delta."""
            if current < previous:
                raise RuntimeError(f"{identity} regressed within one generation")
            return current - previous

        # Build exact boundary rows keyed by stable boundary identity.
        pre_bt = {bt.boundary_id: bt for bt in pre.boundary_epoch_stats}
        post_bt_ids = {bt.boundary_id for bt in post.boundary_epoch_stats}
        if (
            len(pre_bt) != len(pre.boundary_epoch_stats)
            or len(post_bt_ids) != len(post.boundary_epoch_stats)
            or set(pre_bt) != post_bt_ids
        ):
            raise RuntimeError(
                "boundary membership changed within one runtime generation"
            )
        boundary_deltas = []
        for bt in post.boundary_epoch_stats:
            p = pre_bt.get(bt.boundary_id)
            static_identity_changed = p is not None and any((
                p.boundary_index != bt.boundary_index,
                p.from_stage_instance_index != bt.from_stage_instance_index,
                p.to_stage_instance_index != bt.to_stage_instance_index,
                p.sender_worker_index != bt.sender_worker_index,
                p.receiver_worker_index != bt.receiver_worker_index,
                p.from_region_id != bt.from_region_id,
                p.to_region_id != bt.to_region_id,
                p.data_ring_capacity != bt.data_ring_capacity,
                p.future_output_hold_capacity
                != bt.future_output_hold_capacity,
            ))
            if p is None or static_identity_changed or not boundary_transition_is_complete(
                bt, terminal.mutation_sequence, from_epoch, to_epoch
            ):
                raise RuntimeError(
                    f"boundary {bt.boundary_id} lacks exact completed transition evidence"
                )
            boundary_deltas.append({
                "boundary_id": bt.boundary_id,
                "boundary_index": bt.boundary_index,
                "transition_generation": bt.transition_generation,
                "from_epoch": bt.from_epoch,
                "to_epoch": bt.to_epoch,
                "cut_sequence": bt.cut_sequence,
                "sender_phase": bt.sender_phase,
                "receiver_phase": bt.receiver_phase,
                "data_enqueued_sequence_delta": delta(
                    bt.data_enqueued_sequence,
                    p.data_enqueued_sequence,
                    f"{bt.boundary_id} enqueue sequence",
                ),
                "data_dequeued_sequence_delta": delta(
                    bt.data_dequeued_sequence,
                    p.data_dequeued_sequence,
                    f"{bt.boundary_id} dequeue sequence",
                ),
                "data_backpressure_events_delta": delta(
                    bt.data_backpressure_events,
                    p.data_backpressure_events,
                    f"{bt.boundary_id} backpressure",
                ),
                "cut_delivery_duration_ns": bt.cut_delivery_duration_ns,
                "cut_drain_duration_ns": bt.cut_drain_duration_ns,
                "ack_gate_duration_ns": bt.ack_gate_duration_ns,
            })

        # Build cold region ownership rows and the one retained drop subtype.
        pre_rs = {rs.region_id: rs for rs in pre.region_epoch_stats}
        post_rs_ids = {rs.region_id for rs in post.region_epoch_stats}
        if (
            len(pre_rs) != len(pre.region_epoch_stats)
            or len(post_rs_ids) != len(post.region_epoch_stats)
            or set(pre_rs) != post_rs_ids
        ):
            raise RuntimeError(
                "region membership changed within one runtime generation"
            )
        region_deltas = []
        for rs in post.region_epoch_stats:
            p = pre_rs.get(rs.region_id)
            if p is None or p.worker_count != rs.worker_count:
                raise RuntimeError("region identity changed during transition")
            region_deltas.append({
                "region_id": rs.region_id,
                "minimum_active_epoch": rs.minimum_active_epoch,
                "maximum_active_epoch": rs.maximum_active_epoch,
                "minimum_source_epoch": rs.minimum_source_epoch,
                "maximum_source_epoch": rs.maximum_source_epoch,
                "active_unretired": rs.active_unretired,
                "future_unretired": rs.future_unretired,
                "activated_participants": rs.activated_participants,
                "worker_count": rs.worker_count,
                "fanout_overflow_delta": delta(
                    rs.fanout_overflow,
                    p.fanout_overflow,
                    f"region {rs.region_id} fanout overflow",
                ),
            })

        # Build stage stats deltas (keyed by stage_id)
        pre_ss = {ss.stage_id: ss for ss in pre.stage_stats}
        post_ss_ids = {ss.stage_id for ss in post.stage_stats}
        if (
            len(pre_ss) != len(pre.stage_stats)
            or len(post_ss_ids) != len(post.stage_stats)
            or set(pre_ss) != post_ss_ids
        ):
            raise RuntimeError(
                "stage membership changed within one runtime generation"
            )
        stage_deltas = []
        for ss in post.stage_stats:
            p = pre_ss.get(ss.stage_id)
            if p is None:
                raise RuntimeError("stage identity disappeared during transition")
            stage_deltas.append({
                "stage_id": ss.stage_id,
                "in_packets_delta": delta(
                    ss.in_packets, p.in_packets,
                    f"{ss.stage_id} input packets",
                ),
                "out_packets_delta": delta(
                    ss.out_packets, p.out_packets,
                    f"{ss.stage_id} output packets",
                ),
                "dropped_packets_delta": delta(
                    ss.dropped_packets, p.dropped_packets,
                    f"{ss.stage_id} dropped packets",
                ),
            })

        if set(pre.protocol_fault_counts) != set(post.protocol_fault_counts):
            raise RuntimeError(
                "protocol fault membership changed within one runtime generation"
            )
        protocol_fault_deltas = {
            code: delta(
                count,
                pre.protocol_fault_counts[code],
                f"protocol fault {code}",
            )
            for code, count in post.protocol_fault_counts.items()
        }
        rx_packets_delta = delta(
            post.rx_packets, pre.rx_packets, "engine RX packets"
        )
        if rx_packets_delta == 0:
            raise RuntimeError(
                "transition metrics require positive DP ingress under load"
            )

        record = {
            "transition_type": transition_type,
            "runtime_generation": post.runtime_generation,
            "transition_generation": terminal.mutation_sequence,
            "from_epoch": from_epoch,
            "to_epoch": to_epoch,
            "transition_state": post.transition_state,
            "transition_success_blocked": post.transition_success_blocked,
            "rx_packets_delta": rx_packets_delta,
            "tx_packets_delta": delta(
                post.tx_packets, pre.tx_packets, "engine TX packets"
            ),
            "dropped_packets_delta": delta(
                post.dropped_packets,
                pre.dropped_packets,
                "engine dropped packets",
            ),
            "protocol_fault_deltas": protocol_fault_deltas,
            "boundary_epoch_stats": boundary_deltas,
            "region_epoch_stats": region_deltas,
            "stage_stats": stage_deltas,
        }
        validate_transition_metric_record(record)

        metrics_file = self.output_dir / "transition_metrics.jsonl"
        with open(metrics_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, allow_nan=False, sort_keys=True) + "\n")

        self.reporter.print_progress(
            f"Transition metrics saved: {transition_type} epoch {from_epoch}->{to_epoch}"
        )

        # Print key deltas for immediate visibility
        for bd in boundary_deltas:
            self.reporter.print_progress(
                f"  {bd['boundary_id']}: cut_delivery_ns="
                f"{bd['cut_delivery_duration_ns']}"
                f" cut_drain_ns={bd['cut_drain_duration_ns']}"
                f" ack_gate_ns={bd['ack_gate_duration_ns']}"
            )
        for rd in region_deltas:
            if rd["fanout_overflow_delta"] > 0:
                self.reporter.print_warning(
                    f"  region_{rd['region_id']}: "
                    f"fanout_overflow_delta={rd['fanout_overflow_delta']}"
                )
        for sd in stage_deltas:
            if sd["dropped_packets_delta"] > 0:
                self.reporter.print_progress(
                    f"  {sd['stage_id']}: drop_delta={sd['dropped_packets_delta']}"
                )

    def save_test_results(self, result: TestSuiteResult, profile: BackendProfile) -> None:
        """Save test results to JSON file."""
        try:
            results_file = self.output_dir / "test_results.json"

            # Build JSON-serializable results
            data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "deployment": result.deployment.value,
                "test_type": result.test_type.value,
                "backend": profile.backend_type.value,
                "traffic_driver": profile.traffic_driver.value,
                "timestamp_source": profile.timestamp_source,
                "rate_control_source": profile.rate_control_source,
                "latency_source": profile.latency_source,
                "dry_run": result.dry_run,
                "total_duration_s": round(result.total_duration_s, 2),
                "setup_failed": result.setup_failed,
                "all_passed": result.all_passed,
                "total_tests": result.total_tests,
                "passed_tests": result.passed_tests,
                "failed_tests": result.failed_tests,
                "stats_validation": {
                    "required": result.stats_validation.required,
                    "passed": result.stats_validation.passed,
                    "message": result.stats_validation.message,
                },
                "packet_tests": [],
                "nat_exchange": asdict(result.nat_exchange) if result.nat_exchange is not None else None,
                "epoch_test": None,
                "commit_confirmed_test": None,
                "rollback_test": None,
                "guardrails_test": None,
            }

            # Add packet test results
            for test in result.packet_tests:
                data["packet_tests"].append({
                    "packet_size": test.packet_size,
                    "passed": test.passed,
                    "tx_count": test.tx_count,
                    "rx_count": test.rx_count,
                    "loss_pct": round(test.loss_pct, 2),
                    "avg_latency_us": round_latency(test.avg_latency_us),
                    "throughput_pps": round(test.throughput_pps, 2),
                    "duration_s": round(test.duration_s, 2),
                    "message": test.message,
                })

            # Add epoch test result
            if result.epoch_test:
                data["epoch_test"] = {
                    "passed": result.epoch_test.passed,
                    "duration_s": round(result.epoch_test.duration_s, 2),
                    "total_sent": result.epoch_test.total_sent,
                    "total_received": result.epoch_test.total_received,
                    "initial_generation_sent": (
                        result.epoch_test.initial_generation_sent
                    ),
                    "next_generation_sent": result.epoch_test.next_generation_sent,
                    "initial_generation_received": (
                        result.epoch_test.initial_generation_received
                    ),
                    "next_generation_received": (
                        result.epoch_test.next_generation_received
                    ),
                    "generation_tag_transition_seq": (
                        result.epoch_test.generation_tag_transition_seq
                    ),
                    "loss_pct": round(result.epoch_test.loss_pct, 2),
                    "avg_latency_us": round_latency(
                        result.epoch_test.avg_latency_us
                    ),
                    "zero_loss": result.epoch_test.zero_loss,
                    "transitions_observed": result.epoch_test.transitions_observed,
                    "boundary_count": result.epoch_test.boundary_count,
                    "completed_boundaries": result.epoch_test.completed_boundaries,
                    "protocol_faults_observed": result.epoch_test.protocol_faults_observed,
                    "backpressure_events": result.epoch_test.backpressure_events,
                    "boundary_ordering_validated": (
                        result.epoch_test.boundary_ordering_validated
                    ),
                    "message": result.epoch_test.message,
                }

            # Add commit-confirmed test result
            if result.commit_confirmed_test:
                cc = result.commit_confirmed_test
                data["commit_confirmed_test"] = {
                    "passed": cc.passed,
                    "duration_s": round(cc.duration_s, 2),
                    "confirm_success": cc.confirm_success,
                    "confirm_snapshot_id": cc.confirm_snapshot_id,
                    "confirm_time_remaining_ms": cc.confirm_time_remaining_ms,
                    "timeout_rollback_occurred": cc.timeout_rollback_occurred,
                    "timeout_rollback_snapshot_id": cc.timeout_rollback_snapshot_id,
                    "tx_count": cc.tx_count,
                    "rx_count": cc.rx_count,
                    "loss_pct": round(cc.loss_pct, 4),
                    "avg_latency_us": round_latency(cc.avg_latency_us),
                    "message": cc.message,
                }

            # Add rollback test result
            if result.rollback_test:
                rb = result.rollback_test
                data["rollback_test"] = {
                    "passed": rb.passed,
                    "duration_s": round(rb.duration_s, 2),
                    "full_rollback_success": rb.full_rollback_success,
                    "full_rollback_snapshot_id": rb.full_rollback_snapshot_id,
                    "selective_rollback_success": rb.selective_rollback_success,
                    "selective_rollback_modules": rb.selective_rollback_modules,
                    "selective_rollback_snapshot_id": rb.selective_rollback_snapshot_id,
                    "tx_count": rb.tx_count,
                    "rx_count": rb.rx_count,
                    "loss_pct": round(rb.loss_pct, 4),
                    "avg_latency_us": round_latency(rb.avg_latency_us),
                    "message": rb.message,
                }

            if result.guardrails_test:
                guardrails = result.guardrails_test
                data["guardrails_test"] = {
                    "passed": guardrails.passed,
                    "duration_s": round(guardrails.duration_s, 2),
                    "policy_configured": guardrails.policy_configured,
                    "baseline_snapshot_id": guardrails.baseline_snapshot_id,
                    "candidate_snapshot_id": guardrails.candidate_snapshot_id,
                    "rollback_snapshot_id": guardrails.rollback_snapshot_id,
                    "candidate_epoch": guardrails.candidate_epoch,
                    "rollback_epoch": guardrails.rollback_epoch,
                    "protocol_faults_observed": (
                        guardrails.protocol_faults_observed
                    ),
                    "message": guardrails.message,
                }

            validate_test_suite_result(data)
            if result.nat_exchange is not None:
                evidence_file = self.output_dir / "nat_exchange.json"
                if not is_symlink_free_regular_file(evidence_file):
                    raise RuntimeError("NAT exchange result omitted its packet evidence")
                evidence = parse_exact_json_object(evidence_file.read_text(encoding="utf-8"), "NAT exchange evidence")
                if evidence.get("passed") is not result.nat_exchange.passed:
                    raise RuntimeError("NAT exchange result contradicts its packet evidence")
            self._require_transition_artifacts(result)

            with open(results_file, "x", encoding="utf-8") as f:
                json.dump(data, f, allow_nan=False, indent=2, sort_keys=True)
                f.write("\n")

            self.reporter.print_progress(f"Results saved to {results_file}")

        except RECOVERABLE_EXCEPTIONS as e:
            raise RuntimeError("could not publish exact test results") from e

    def _require_transition_artifacts(self, result: TestSuiteResult) -> None:
        """Require the exact transition-record multiset for a successful run."""
        if not result.all_passed or result.dry_run:
            return
        expected = sorted(
            EXPECTED_TRANSITION_TYPES_BY_TEST[result.test_type.value]
        )
        metrics_file = self.output_dir / "transition_metrics.jsonl"
        if not expected:
            if metrics_file.exists() or metrics_file.is_symlink():
                raise RuntimeError(
                    "fixed-execution result retained transition evidence"
                )
            return
        if not is_symlink_free_regular_file(metrics_file):
            raise RuntimeError("successful scenario omitted transition evidence")

        observed = []
        with open(metrics_file, encoding="utf-8") as stream:
            for line in stream:
                if not line.endswith("\n") or not line[:-1]:
                    raise RuntimeError(
                        "transition evidence contains a malformed record boundary"
                    )
                record = parse_exact_json_object(
                    line[:-1], "transition metrics record"
                )
                validate_transition_metric_record(record)
                observed.append(record["transition_type"])
        if sorted(observed) != expected:
            raise RuntimeError(
                "successful scenario transition evidence is incomplete"
            )
        summary_file = self.output_dir / "transition_summary.json"
        if not is_symlink_free_regular_file(summary_file):
            raise RuntimeError("successful scenario omitted transition summary")
