"""
Benchmark aggregator - merge per-run artifacts and compute distributions.

Reads immutable per-run outputs (transition_metrics.jsonl, test_results.json)
and produces:
  - merged_transitions.jsonl: all transition records with their run identities
  - benchmark_summary.json: scenario-bound two-section summary
      scenario_metrics:   per-test-type counters and available latency
      transition_metrics:  per-transition-type boundary/stage distributions
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List

from kinetum_validation.engine.json_contract import parse_exact_json_object, validate_transition_metric_record
from kinetum_validation.statistics import nearest_rank_percentile

from .contracts import (
    validate_benchmark_result_identity,
    validate_benchmark_run_artifacts,
    validate_benchmark_manifest,
    validate_benchmark_summary_identity,
    validate_benchmark_transition_multiset,
)


def _distribution(values: List[float]) -> dict:
    """Compute min/p50/p95/p99/max distribution."""
    if not values:
        raise ValueError("distribution requires observed samples")
    return {
        "min": min(values),
        "p50": nearest_rank_percentile(values, 50),
        "p95": nearest_rank_percentile(values, 95),
        "p99": nearest_rank_percentile(values, 99),
        "max": max(values),
        "count": len(values),
    }


def _selected_trex_identity(
    results_by_run: Dict[str, dict],
    identities_by_run: Dict[str, dict],
    include_all: bool,
    traffic_driver: str,
) -> dict | None:
    """Return one homogeneous TRex identity for the selected run population."""
    if traffic_driver != "trex":
        return None
    identities = []
    for run_name, result in results_by_run.items():
        if not include_all and not result["all_passed"]:
            continue
        identity = identities_by_run.get(run_name)
        if identity is None:
            if result["setup_failed"]:
                continue
            raise ValueError("selected TRex run omitted its observed identity")
        identities.append(identity)
    if not identities:
        return None
    if any(identity != identities[0] for identity in identities[1:]):
        raise ValueError("selected benchmark runs used different TRex identities")
    return dict(identities[0])


def aggregate(input_dir: Path, inclusion_policy: str = "passed_only") -> None:
    """
    Aggregate benchmark results from per-run directories.

    Reads all run_NNN/ subdirectories, merges their transition_metrics.jsonl
    and test_results.json, and writes:
      - merged_transitions.jsonl
      - benchmark_summary.json

    Parameters
    ----------
    input_dir : Path
        Benchmark root directory containing run_NNN/ subdirectories.
    inclusion_policy : str
        ``passed_only`` or ``all_runs``; must match the terminal manifest.
    """
    if inclusion_policy not in {"passed_only", "all_runs"}:
        raise ValueError("benchmark inclusion policy is undeclared")

    manifest_path = input_dir / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("benchmark manifest is unavailable")
    with open(manifest_path, encoding="utf-8") as manifest_file:
        manifest = parse_exact_json_object(
            manifest_file.read(), "benchmark manifest"
        )
    validate_benchmark_manifest(manifest, completed=True)
    if inclusion_policy != manifest["inclusion_policy"]:
        raise ValueError(
            "aggregate inclusion policy disagrees with the terminal manifest"
        )
    expected_run_dirs = [
        f"run_{row['run_id']:03d}" for row in manifest["results"]["runs"]
    ]
    run_dirs = sorted(
        path for path in input_dir.iterdir() if path.name.startswith("run_")
    )
    if (
        not run_dirs
        or [path.name for path in run_dirs] != expected_run_dirs
        or any(not path.is_dir() or path.is_symlink() for path in run_dirs)
    ):
        raise ValueError("benchmark run-directory membership disagrees with manifest")
    manifest_rows = {
        f"run_{row['run_id']:03d}": row for row in manifest["results"]["runs"]
    }

    print(f"Aggregating {len(run_dirs)} runs from {input_dir}", file=sys.stderr)

    # Step 1: identify passed vs failed runs from test_results.json.
    results_by_run: Dict[str, dict] = {}
    passed_run_names: set = set()
    failed_runs: List[str] = []
    failure_reasons: Dict[str, str] = {}
    trex_identities_by_run: Dict[str, dict] = {}

    for run_dir in run_dirs:
        results_path = run_dir / "test_results.json"
        if results_path.is_symlink():
            raise ValueError(f"{run_dir.name} test results are indirect")
        if not results_path.exists():
            if manifest_rows[run_dir.name]["passed"]:
                raise ValueError(
                    f"{run_dir.name} manifest success has no test results"
                )
            failed_runs.append(run_dir.name)
            failure_reasons[run_dir.name] = manifest_rows[run_dir.name]["error"]
            continue
        if not results_path.is_file():
            raise ValueError(f"{run_dir.name} test results are indirect")
        with open(results_path, encoding="utf-8") as f:
            result = parse_exact_json_object(
                f.read(), f"{run_dir.name} test results"
            )
        validate_benchmark_result_identity(result, manifest)
        if manifest_rows[run_dir.name]["passed"] != result["all_passed"]:
            raise ValueError(
                f"{run_dir.name} manifest and test result disagree"
            )
        metadata_path = run_dir / "run_metadata.json"
        if metadata_path.is_symlink():
            raise ValueError(f"{run_dir.name} run metadata is indirect")
        if metadata_path.exists():
            if not metadata_path.is_file():
                raise ValueError(f"{run_dir.name} run metadata is indirect")
            with open(metadata_path, encoding="utf-8") as metadata_file:
                metadata = parse_exact_json_object(
                    metadata_file.read(), f"{run_dir.name} run metadata"
                )
            validate_benchmark_run_artifacts(
                result,
                metadata,
                manifest,
                str(run_dir),
            )
            trex_identity = metadata["traffic_endpoint"]["trex_identity"]
            if trex_identity is not None:
                trex_identities_by_run[run_dir.name] = trex_identity
        elif not result["setup_failed"]:
            raise ValueError(f"{run_dir.name} omitted run metadata")
        results_by_run[run_dir.name] = result
        if result["all_passed"]:
            passed_run_names.add(run_dir.name)
        else:
            failed_runs.append(run_dir.name)
            failure_reasons[run_dir.name] = manifest_rows[run_dir.name]["error"]

    print(
        f"  {len(passed_run_names)} passed, {len(failed_runs)} failed",
        file=sys.stderr,
    )

    # Step 2: merge transition_metrics.jsonl. The raw ledger contains
    # all runs; distributions use passed runs unless policy says otherwise.
    transitions_by_run: Dict[str, List[dict]] = {
        run_dir.name: [] for run_dir in run_dirs
    }
    merged_path = input_dir / "merged_transitions.jsonl"
    summary_path = input_dir / "benchmark_summary.json"
    if (
        merged_path.exists()
        or merged_path.is_symlink()
        or summary_path.exists()
        or summary_path.is_symlink()
    ):
        raise ValueError("benchmark aggregate outputs already exist")

    for run_dir in run_dirs:
        jsonl_path = run_dir / "transition_metrics.jsonl"
        if jsonl_path.is_symlink():
            raise ValueError(f"{run_dir.name} transition metrics are indirect")
        if not jsonl_path.exists():
            continue
        if not jsonl_path.is_file():
            raise ValueError(f"{run_dir.name} transition metrics are indirect")
        with open(jsonl_path, encoding="utf-8") as transition_file:
            for line in transition_file:
                if not line.endswith("\n") or not line[:-1]:
                    raise ValueError(
                        f"{run_dir.name} transition record boundary is malformed"
                    )
                record = parse_exact_json_object(
                    line[:-1], f"{run_dir.name} transition metric"
                )
                validate_transition_metric_record(record)
                transitions_by_run[run_dir.name].append(record)

    test_type = manifest["scenario"]["test_type"]
    for run_name, records in transitions_by_run.items():
        validate_benchmark_transition_multiset(
            [record["transition_type"] for record in records],
            test_type,
            complete=manifest_rows[run_name]["passed"],
        )

    # Step 3: compute scenario_metrics.
    include_all = inclusion_policy == "all_runs"
    trex_identity = _selected_trex_identity(
        results_by_run,
        trex_identities_by_run,
        include_all,
        manifest["scenario"]["traffic_driver"],
    )
    scenario_metrics = _compute_scenario_metrics(
        list(results_by_run.values()), include_all=include_all
    )

    # Step 4: compute transition_metrics.
    selected_transitions = [
        record
        for run_name, records in transitions_by_run.items()
        if include_all or run_name in passed_run_names
        for record in records
    ]
    transition_metrics = _compute_transition_metrics(selected_transitions)

    # Step 5: write benchmark_summary.json.
    variant = manifest["variant"]
    config = manifest["config"]
    if not isinstance(config, dict) or "epoch_pps" not in config:
        raise ValueError("benchmark manifest omitted epoch PPS")
    epoch_pps = config["epoch_pps"]

    summary = {
        "variant": variant,
        "inclusion_policy": inclusion_policy,
        "scenario": manifest["scenario"],
        "epoch_pps": epoch_pps,
        "total_runs": len(run_dirs),
        "passed_runs": len(passed_run_names),
        "failed_runs": len(failed_runs),
        "failed_run_ids": failed_runs,
        "failure_reasons": failure_reasons,
        "trex_identity": trex_identity,
        "scenario_metrics": scenario_metrics,
        "transition_metrics": transition_metrics,
    }
    validate_benchmark_summary_identity(summary, manifest)

    merged_bytes = "".join(
        json.dumps({**record, "_run": run_name}, allow_nan=False, sort_keys=True) + "\n"
        for run_name, records in transitions_by_run.items()
        for record in records
    )
    summary_bytes = json.dumps(
        summary, allow_nan=False, indent=2, sort_keys=True
    ) + "\n"

    with open(merged_path, "x", encoding="utf-8") as merged_file:
        merged_file.write(merged_bytes)
    transition_count = sum(len(records) for records in transitions_by_run.values())
    passed_transition_count = sum(
        len(records) for run_name, records in transitions_by_run.items()
        if run_name in passed_run_names
    )
    print(
        f"  Merged {transition_count} transition records "
        f"({passed_transition_count} from passed runs) "
        f"into {merged_path.name}",
        file=sys.stderr,
    )

    with open(summary_path, "x", encoding="utf-8") as f:
        f.write(summary_bytes)

    print(f"  Summary written to {summary_path.name}", file=sys.stderr)


def _observed_distributions(rows: List[dict], fields: tuple[str, ...]) -> dict:
    """Aggregate present measurements; absence contributes no sample."""
    metrics = {}
    for name in fields:
        values = [row[name] for row in rows if row[name] is not None]
        if values:
            metrics[name] = _distribution(values)
    return metrics


def _compute_scenario_metrics(results: List[dict], include_all: bool = False) -> dict:
    """Compute per-scenario distributions from admitted per-run measurements."""
    selected = [result for result in results if include_all or result["all_passed"]]
    metrics = {}

    by_size: Dict[int, List[dict]] = {}
    for result in selected:
        for packet in result["packet_tests"]:
            by_size.setdefault(packet["packet_size"], []).append(packet)
    packet_metrics = {}
    for size, rows in sorted(by_size.items()):
        observed = _observed_distributions(rows, (
            "tx_count", "rx_count", "loss_pct", "avg_latency_us", "throughput_pps",
        ))
        if observed:
            packet_metrics[str(size)] = observed
    if packet_metrics:
        metrics["packet_tests"] = packet_metrics

    fields_by_family = {
        "epoch_test": (
            "total_sent", "total_received", "loss_pct", "avg_latency_us",
            "boundary_count", "completed_boundaries", "protocol_faults_observed", "backpressure_events",
        ),
        "commit_confirmed_test": ("tx_count", "rx_count", "loss_pct", "avg_latency_us"),
        "rollback_test": ("tx_count", "rx_count", "loss_pct", "avg_latency_us"),
    }
    for family, fields in fields_by_family.items():
        rows = [
            result[family] for result in selected
            if result[family] is not None and (include_all or result[family]["passed"])
        ]
        observed = _observed_distributions(rows, fields)
        if observed:
            metrics[family] = observed

    guardrail_rows = []
    for result in selected:
        guardrail = result["guardrails_test"]
        if guardrail is None or (not include_all and not guardrail["passed"]):
            continue
        candidate = guardrail["candidate_epoch"]
        rollback = guardrail["rollback_epoch"]
        step = None
        if candidate is not None and rollback is not None:
            if rollback <= candidate:
                raise ValueError("guardrails result has no later rollback epoch")
            step = rollback - candidate
        guardrail_rows.append({
            "duration_s": guardrail["duration_s"],
            "rollback_epoch_step": step,
        })
    guardrail_metrics = _observed_distributions(guardrail_rows, ("duration_s", "rollback_epoch_step"))
    if guardrail_metrics:
        metrics["guardrails_test"] = guardrail_metrics
    return metrics


def _compute_transition_metrics(transitions: List[dict]) -> dict:
    """
    Compute per-transition-type distributions from raw per-run records.

    Same logic as RunArtifacts.write_transition_summary() but across
    multiple runs for statistical depth.
    """
    if not transitions:
        return {}

    expected_membership = None
    for record in transitions:
        validate_transition_metric_record(record)
        fault_deltas = record["protocol_fault_deltas"]
        if not isinstance(fault_deltas, dict) or not fault_deltas or any(
            not isinstance(code, str)
            or not code
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            for code, count in fault_deltas.items()
        ):
            raise ValueError(
                "transition aggregate contains malformed protocol-fault deltas"
            )
        boundary_identities = [
            (row["boundary_id"], row["boundary_index"])
            for row in record["boundary_epoch_stats"]
        ]
        region_ids = [
            row["region_id"] for row in record["region_epoch_stats"]
        ]
        stage_ids = [row["stage_id"] for row in record["stage_stats"]]
        malformed_identity = (
            any(
                not isinstance(value, str)
                or not value
                or not isinstance(index, int)
                or isinstance(index, bool)
                for value, index in boundary_identities
            )
            or any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in region_ids
            )
            or any(not isinstance(value, str) or not value for value in stage_ids)
        )
        duplicate_identity = (
            len(boundary_identities) != len(set(boundary_identities))
            or len(region_ids) != len(set(region_ids))
            or len(stage_ids) != len(set(stage_ids))
        )
        if malformed_identity or duplicate_identity:
            raise ValueError(
                "transition aggregate contains duplicate or malformed row identity"
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
                "transition aggregate membership changed across evidence records"
            )

    # Group by transition_type.
    by_type: Dict[str, List[dict]] = {}
    for rec in transitions:
        ttype = rec["transition_type"]
        if not isinstance(ttype, str) or not ttype:
            raise ValueError("transition aggregate contains no transition type")
        by_type.setdefault(ttype, []).append(rec)

    # Compute per-type distributions.
    per_type: dict = {}
    for ttype, records in sorted(by_type.items()):
        # Exact sequence-CUT timing and backpressure.
        cut_delivery_by_boundary: Dict[str, List[float]] = {}
        cut_drain_by_boundary: Dict[str, List[float]] = {}
        ack_gate_by_boundary: Dict[str, List[float]] = {}
        backpressure_by_boundary: Dict[str, List[float]] = {}
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

        # Fan-out overflow is the sole final region drop subtype.
        fanout_by_region: Dict[int, List[float]] = {}
        for rec in records:
            for rd in rec["region_epoch_stats"]:
                rid = rd["region_id"]
                fanout_by_region.setdefault(rid, []).append(
                    rd["fanout_overflow_delta"]
                )

        # Stage drops
        drops_by_stage: Dict[str, List[float]] = {}
        for rec in records:
            for sd in rec["stage_stats"]:
                sid = sd["stage_id"]
                drops_by_stage.setdefault(sid, []).append(
                    sd["dropped_packets_delta"]
                )

        # RX/TX deltas
        rx_deltas = [rec["rx_packets_delta"] for rec in records]
        tx_deltas = [rec["tx_packets_delta"] for rec in records]
        drop_deltas = [rec["dropped_packets_delta"] for rec in records]
        fault_codes = expected_membership[0]

        per_type[ttype] = {
            "count": len(records),
            "rx_packets_delta": _distribution(rx_deltas),
            "tx_packets_delta": _distribution(tx_deltas),
            "dropped_packets_delta": _distribution(drop_deltas),
            "protocol_fault_deltas": {
                code: _distribution([
                    rec["protocol_fault_deltas"][code]
                    for rec in records
                ])
                for code in fault_codes
            },
            "boundary_cut_delivery_ns": {
                bid: _distribution(vals)
                for bid, vals in sorted(cut_delivery_by_boundary.items())
            },
            "boundary_cut_drain_ns": {
                bid: _distribution(vals)
                for bid, vals in sorted(cut_drain_by_boundary.items())
            },
            "boundary_ack_gate_ns": {
                bid: _distribution(vals)
                for bid, vals in sorted(ack_gate_by_boundary.items())
            },
            "boundary_backpressure_events": {
                bid: _distribution(vals)
                for bid, vals in sorted(backpressure_by_boundary.items())
            },
            "region_fanout_overflow": {
                str(rid): _distribution(vals)
                for rid, vals in sorted(fanout_by_region.items())
            },
            "stage_drops": {
                sid: _distribution(vals)
                for sid, vals in sorted(drops_by_stage.items())
            },
        }

    # Aggregate across all types.
    all_cut_drain: Dict[str, List[float]] = {}
    all_ack_gate: Dict[str, List[float]] = {}
    for rec in transitions:
        for bd in rec["boundary_epoch_stats"]:
            bid = bd["boundary_id"]
            all_cut_drain.setdefault(bid, []).append(
                bd["cut_drain_duration_ns"]
            )
            all_ack_gate.setdefault(bid, []).append(
                bd["ack_gate_duration_ns"]
            )

    return {
        "total_transitions": len(transitions),
        "aggregate": {
            "boundary_cut_drain_ns": {
                bid: _distribution(vals)
                for bid, vals in sorted(all_cut_drain.items())
            },
            "boundary_ack_gate_ns": {
                bid: _distribution(vals)
                for bid, vals in sorted(all_ack_gate.items())
            },
        },
        "per_type": per_type,
    }
