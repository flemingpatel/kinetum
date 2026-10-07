"""
CSV exporter - convert benchmark_summary.json to flat CSV for plotting.

Produces two CSV files:
  - benchmark_scenario.csv: per-test-type scenario metrics
  - benchmark_transitions.csv: per-transition-type boundary metrics
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from kinetum_validation.engine.json_contract import (
    parse_exact_json_object,
    require_exact_keys,
    require_object,
)

from .contracts import validate_benchmark_summary_identity


def export_csv(input_dir: Path) -> None:
    """
    Export benchmark_summary.json to CSV files.

    Parameters
    ----------
    input_dir : Path
        Benchmark root directory containing benchmark_summary.json.
    """
    summary_path = input_dir / "benchmark_summary.json"
    if not summary_path.is_file() or summary_path.is_symlink():
        raise ValueError(f"benchmark_summary.json not found in {input_dir}")

    with open(summary_path, encoding="utf-8") as f:
        summary = parse_exact_json_object(f.read(), "benchmark summary")
    manifest_path = input_dir / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError(f"manifest.json not found in {input_dir}")
    with open(manifest_path, encoding="utf-8") as manifest_file:
        manifest = parse_exact_json_object(
            manifest_file.read(), "benchmark manifest"
        )
    validate_benchmark_summary_identity(summary, manifest)

    for filename in ("benchmark_scenario.csv", "benchmark_transitions.csv"):
        output = input_dir / filename
        if output.exists() or output.is_symlink():
            raise ValueError(f"benchmark CSV output already exists: {filename}")

    _export_scenario_csv(input_dir, summary)
    _export_transition_csv(input_dir, summary)


def _validated_distribution(value: object, context: str) -> dict:
    """Return one exact six-field aggregate distribution."""
    distribution = require_object(value, context)
    require_exact_keys(
        distribution,
        {"min", "p50", "p95", "p99", "max", "count"},
        context,
    )
    return distribution


def _export_scenario_csv(output_dir: Path, summary: dict) -> None:
    """Export scenario_metrics section to CSV."""
    scenario = require_object(summary["scenario_metrics"], "scenario metrics")
    if not scenario:
        print("  No scenario metrics to export", file=sys.stderr)
        return

    csv_path = output_dir / "benchmark_scenario.csv"
    rows = []

    # Packet tests
    packet_tests = (
        require_object(scenario["packet_tests"], "packet metrics")
        if "packet_tests" in scenario else {}
    )
    for size, metrics in packet_tests.items():
        for metric_name, dist in metrics.items():
            dist = _validated_distribution(dist, f"packet {size} {metric_name}")
            rows.append({
                "test_type": "packet",
                "variant": f"size_{size}",
                "metric": metric_name,
                "count": dist["count"],
                "min": dist["min"],
                "p50": dist["p50"],
                "p95": dist["p95"],
                "p99": dist["p99"],
                "max": dist["max"],
            })

    # Epoch test
    epoch_metrics = (
        require_object(scenario["epoch_test"], "epoch metrics")
        if "epoch_test" in scenario else {}
    )
    for metric_name, dist in epoch_metrics.items():
        dist = _validated_distribution(dist, f"epoch {metric_name}")
        rows.append({
            "test_type": "epoch",
            "variant": "",
            "metric": metric_name,
            "count": dist["count"],
            "min": dist["min"],
            "p50": dist["p50"],
            "p95": dist["p95"],
            "p99": dist["p99"],
            "max": dist["max"],
        })

    # Commit-confirmed test
    commit_metrics = (
        require_object(scenario["commit_confirmed_test"], "commit-confirmed metrics")
        if "commit_confirmed_test" in scenario else {}
    )
    for metric_name, dist in commit_metrics.items():
        dist = _validated_distribution(dist, f"commit-confirmed {metric_name}")
        rows.append({
            "test_type": "commit_confirmed",
            "variant": "",
            "metric": metric_name,
            "count": dist["count"],
            "min": dist["min"],
            "p50": dist["p50"],
            "p95": dist["p95"],
            "p99": dist["p99"],
            "max": dist["max"],
        })

    # Rollback test
    rollback_metrics = (
        require_object(scenario["rollback_test"], "rollback metrics")
        if "rollback_test" in scenario else {}
    )
    for metric_name, dist in rollback_metrics.items():
        dist = _validated_distribution(dist, f"rollback {metric_name}")
        rows.append({
            "test_type": "rollback",
            "variant": "",
            "metric": metric_name,
            "count": dist["count"],
            "min": dist["min"],
            "p50": dist["p50"],
            "p95": dist["p95"],
            "p99": dist["p99"],
            "max": dist["max"],
        })

    guardrail_metrics = (
        require_object(scenario["guardrails_test"], "guardrails metrics")
        if "guardrails_test" in scenario else {}
    )
    for metric_name, dist in guardrail_metrics.items():
        dist = _validated_distribution(dist, f"guardrails {metric_name}")
        rows.append({
            "test_type": "guardrails",
            "variant": "",
            "metric": metric_name,
            "count": dist["count"],
            "min": dist["min"],
            "p50": dist["p50"],
            "p95": dist["p95"],
            "p99": dist["p99"],
            "max": dist["max"],
        })

    if rows:
        fieldnames = ["test_type", "variant", "metric", "count",
                      "min", "p50", "p95", "p99", "max"]
        with open(csv_path, "x", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"  Scenario CSV: {csv_path} ({len(rows)} rows)", file=sys.stderr)


def _export_transition_csv(output_dir: Path, summary: dict) -> None:
    """Export transition_metrics section to CSV."""
    transition = require_object(summary["transition_metrics"], "transition metrics")
    per_type = (
        require_object(transition["per_type"], "per-type transition metrics")
        if "per_type" in transition else {}
    )
    if not per_type:
        print("  No transition metrics to export", file=sys.stderr)
        return

    csv_path = output_dir / "benchmark_transitions.csv"
    rows = []

    for ttype, data in sorted(per_type.items()):
        data = require_object(data, f"transition type {ttype}")
        # Boundary CUT-drain duration.
        for bid, dist in data["boundary_cut_drain_ns"].items():
            dist = _validated_distribution(dist, f"{ttype} {bid} cut drain")
            rows.append({
                "transition_type": ttype,
                "boundary_id": bid,
                "metric": "cut_drain_ns",
                "count": dist["count"],
                "min": dist["min"],
                "p50": dist["p50"],
                "p95": dist["p95"],
                "p99": dist["p99"],
                "max": dist["max"],
            })

        # Boundary ACK-gate duration.
        for bid, dist in data["boundary_ack_gate_ns"].items():
            dist = _validated_distribution(dist, f"{ttype} {bid} ACK gate")
            rows.append({
                "transition_type": ttype,
                "boundary_id": bid,
                "metric": "ack_gate_ns",
                "count": dist["count"],
                "min": dist["min"],
                "p50": dist["p50"],
                "p95": dist["p95"],
                "p99": dist["p99"],
                "max": dist["max"],
            })

        # Dropped packets delta
        drop_dist = _validated_distribution(
            data["dropped_packets_delta"], f"{ttype} dropped packets"
        )
        if drop_dist["count"] > 0:
            rows.append({
                "transition_type": ttype,
                "boundary_id": "",
                "metric": "dropped_packets_delta",
                "count": drop_dist["count"],
                "min": drop_dist["min"],
                "p50": drop_dist["p50"],
                "p95": drop_dist["p95"],
                "p99": drop_dist["p99"],
                "max": drop_dist["max"],
            })

    if rows:
        fieldnames = ["transition_type", "boundary_id", "metric", "count",
                      "min", "p50", "p95", "p99", "max"]
        with open(csv_path, "x", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(
            f"  Transition CSV: {csv_path} ({len(rows)} rows)",
            file=sys.stderr,
        )
