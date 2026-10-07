"""
Benchmark aggregator - merge per-run artifacts and compute distributions.

Reads immutable per-run outputs (transition_metrics.jsonl, test_results.json)
and produces:
  - merged_transitions.jsonl: concatenation of all runs' JSONL
  - benchmark_summary.json: scenario-bound two-section summary
      scenario_metrics:   per-test-type counters and available latency
      transition_metrics:  per-transition-type boundary/stage distributions
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Dict, List

from kinetum_validation.engine.json_contract import parse_exact_json_object, validate_transition_metric_record

from .contracts import (
    validate_benchmark_result_identity,
    validate_benchmark_run_artifacts,
    validate_benchmark_manifest,
    validate_benchmark_summary_identity,
    validate_benchmark_transition_multiset,
)


def _percentile(values: List[float], pct: float) -> float:
    """Compute percentile using nearest-rank method."""
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, min(len(s) - 1, int(math.ceil(pct / 100.0 * len(s))) - 1))
    return s[idx]


def _distribution(values: List[float]) -> dict:
    """Compute min/p50/p95/p99/max distribution."""
    if not values:
        return {"min": 0, "p50": 0, "p95": 0, "p99": 0, "max": 0, "count": 0}
    return {
        "min": min(values),
        "p50": _percentile(values, 50),
        "p95": _percentile(values, 95),
        "p99": _percentile(values, 99),
        "max": max(values),
        "count": len(values),
    }


def _selected_trex_identity(
    results: List[dict],
    identities_by_run: Dict[str, dict],
    include_all: bool,
    traffic_driver: str,
) -> dict | None:
    """Return one homogeneous TRex identity for the selected run population."""
    if traffic_driver != "trex":
        return None
    selected = [
        result for result in results if include_all or result["all_passed"]
    ]
    identities = []
    for result in selected:
        identity = identities_by_run.get(result["_run"])
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
    all_results: List[dict] = []
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
        result["_run"] = run_dir.name
        all_results.append(result)
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
    all_transitions: List[dict] = []
    passed_transitions: List[dict] = []
    transitions_by_run: Dict[str, List[str]] = {
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
                record["_run"] = run_dir.name
                all_transitions.append(record)
                transitions_by_run[run_dir.name].append(record["transition_type"])
                if run_dir.name in passed_run_names:
                    passed_transitions.append(record)

    test_type = manifest["scenario"]["test_type"]
    for run_name, observed_types in transitions_by_run.items():
        validate_benchmark_transition_multiset(
            observed_types,
            test_type,
            complete=manifest_rows[run_name]["passed"],
        )

    # Step 3: compute scenario_metrics.
    include_all = inclusion_policy == "all_runs"
    trex_identity = _selected_trex_identity(
        all_results,
        trex_identities_by_run,
        include_all,
        manifest["scenario"]["traffic_driver"],
    )
    scenario_metrics = _compute_scenario_metrics(all_results, include_all=include_all)

    # Step 4: compute transition_metrics.
    selected_transitions = all_transitions if include_all else passed_transitions
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
        json.dumps(record, allow_nan=False, sort_keys=True) + "\n"
        for record in all_transitions
    )
    summary_bytes = json.dumps(
        summary, allow_nan=False, indent=2, sort_keys=True
    ) + "\n"

    with open(merged_path, "x", encoding="utf-8") as merged_file:
        merged_file.write(merged_bytes)
    print(
        f"  Merged {len(all_transitions)} transition records "
        f"({len(passed_transitions)} from passed runs) "
        f"into {merged_path.name}",
        file=sys.stderr,
    )

    with open(summary_path, "x", encoding="utf-8") as f:
        f.write(summary_bytes)

    print(f"  Summary written to {summary_path.name}", file=sys.stderr)


def _compute_scenario_metrics(results: List[dict], include_all: bool = False) -> dict:
    """
    Compute per-scenario distributions from test_results.json files.

    Aggregates TX/RX/loss and available latency across runs for each test type:
    packet tests (per size), epoch, commit_confirmed, rollback.
    """
    if include_all:
        passed = results
    else:
        passed = [r for r in results if r["all_passed"]]
    if not passed:
        return {}

    metrics: dict = {}

    # Packet tests (per size).
    pkt_by_size: Dict[int, Dict[str, List[float]]] = {}
    for r in passed:
        for pt in r["packet_tests"]:
            size = pt["packet_size"]
            if size not in pkt_by_size:
                pkt_by_size[size] = {
                    "tx_count": [], "rx_count": [],
                    "loss_pct": [], "throughput_pps": [],
                }
            pkt_by_size[size]["tx_count"].append(pt["tx_count"])
            pkt_by_size[size]["rx_count"].append(pt["rx_count"])
            pkt_by_size[size]["loss_pct"].append(pt["loss_pct"])
            if pt["avg_latency_us"] is not None:
                pkt_by_size[size].setdefault("avg_latency_us", []).append(
                    pt["avg_latency_us"]
                )
            pkt_by_size[size]["throughput_pps"].append(pt["throughput_pps"])

    if pkt_by_size:
        metrics["packet_tests"] = {
            str(size): {
                k: _distribution(vals) for k, vals in data.items()
            }
            for size, data in sorted(pkt_by_size.items())
        }

    # Epoch test.
    epoch_loss: List[float] = []
    epoch_latency: List[float] = []
    epoch_sent: List[float] = []
    epoch_received: List[float] = []
    epoch_boundaries: List[float] = []
    epoch_completed_boundaries: List[float] = []
    epoch_protocol_faults: List[float] = []
    epoch_backpressure: List[float] = []
    for r in passed:
        et = r["epoch_test"]
        if et and (include_all or et["passed"]):
            epoch_loss.append(et["loss_pct"])
            if et["avg_latency_us"] is not None:
                epoch_latency.append(et["avg_latency_us"])
            epoch_sent.append(et["total_sent"])
            epoch_received.append(et["total_received"])
            epoch_boundaries.append(et["boundary_count"])
            epoch_completed_boundaries.append(
                et["completed_boundaries"]
            )
            epoch_protocol_faults.append(
                et["protocol_faults_observed"]
            )
            epoch_backpressure.append(et["backpressure_events"])

    if epoch_loss:
        epoch_metrics: dict = {
            "total_sent": _distribution(epoch_sent),
            "total_received": _distribution(epoch_received),
            "loss_pct": _distribution(epoch_loss),
        }
        if epoch_latency:
            epoch_metrics["avg_latency_us"] = _distribution(epoch_latency)
        if epoch_boundaries:
            epoch_metrics["boundary_count"] = _distribution(epoch_boundaries)
            epoch_metrics["completed_boundaries"] = _distribution(
                epoch_completed_boundaries
            )
            epoch_metrics["protocol_faults_observed"] = _distribution(
                epoch_protocol_faults
            )
            epoch_metrics["backpressure_events"] = _distribution(
                epoch_backpressure
            )
        metrics["epoch_test"] = epoch_metrics

    # Commit-confirmed test.
    cc_tx: List[float] = []
    cc_rx: List[float] = []
    cc_loss: List[float] = []
    cc_latency: List[float] = []
    for r in passed:
        cc = r["commit_confirmed_test"]
        if cc and (include_all or cc["passed"]):
            cc_tx.append(cc["tx_count"])
            cc_rx.append(cc["rx_count"])
            cc_loss.append(cc["loss_pct"])
            if cc["avg_latency_us"] is not None:
                cc_latency.append(cc["avg_latency_us"])

    if cc_loss:
        commit_confirmed_metrics = {
            "tx_count": _distribution(cc_tx),
            "rx_count": _distribution(cc_rx),
            "loss_pct": _distribution(cc_loss),
        }
        if cc_latency:
            commit_confirmed_metrics["avg_latency_us"] = _distribution(
                cc_latency
            )
        metrics["commit_confirmed_test"] = commit_confirmed_metrics

    # Rollback test.
    rb_tx: List[float] = []
    rb_rx: List[float] = []
    rb_loss: List[float] = []
    rb_latency: List[float] = []
    for r in passed:
        rb = r["rollback_test"]
        if rb and (include_all or rb["passed"]):
            rb_tx.append(rb["tx_count"])
            rb_rx.append(rb["rx_count"])
            rb_loss.append(rb["loss_pct"])
            if rb["avg_latency_us"] is not None:
                rb_latency.append(rb["avg_latency_us"])

    if rb_loss:
        rollback_metrics = {
            "tx_count": _distribution(rb_tx),
            "rx_count": _distribution(rb_rx),
            "loss_pct": _distribution(rb_loss),
        }
        if rb_latency:
            rollback_metrics["avg_latency_us"] = _distribution(rb_latency)
        metrics["rollback_test"] = rollback_metrics

    guardrail_durations: List[float] = []
    guardrail_epoch_steps: List[float] = []
    for result in passed:
        guardrail = result["guardrails_test"]
        if guardrail and (include_all or guardrail["passed"]):
            epoch_step = guardrail["rollback_epoch"] - guardrail["candidate_epoch"]
            if epoch_step <= 0:
                raise ValueError("guardrails result has no later rollback epoch")
            guardrail_durations.append(guardrail["duration_s"])
            guardrail_epoch_steps.append(epoch_step)
    if guardrail_durations:
        metrics["guardrails_test"] = {
            "duration_s": _distribution(guardrail_durations),
            "rollback_epoch_step": _distribution(guardrail_epoch_steps),
        }

    return metrics


def _compute_transition_metrics(transitions: List[dict]) -> dict:
    """
    Compute per-transition-type distributions from merged JSONL records.

    Same logic as TestOrchestrator.write_transition_summary() but across
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
