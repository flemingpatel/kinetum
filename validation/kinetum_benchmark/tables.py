"""
Markdown table generator from benchmark data.

Generates deterministic markdown tables from benchmark_summary.json.
"""

from __future__ import annotations

import sys
from pathlib import Path

from kinetum_validation.engine.json_contract import (
    parse_exact_json_object,
    require_exact_keys,
    require_object,
)
from kinetum_validation.statistics import format_number as _fmt

from .contracts import validate_benchmark_summary_identity


def generate_tables(input_dir: Path, artifacts_dir: Path) -> None:
    """
    Generate markdown tables from benchmark_summary.json.

    Writes to artifacts_dir/tables/:
      - ordered_cut_boundary_proof.md
      - boundary_ack_gate_*.md
      - scenario_traffic.md

    Parameters
    ----------
    input_dir : Path
        Benchmark root directory.
    artifacts_dir : Path
        Output directory for derived artifacts.
    """
    if (
        artifacts_dir != input_dir / "artifacts"
        or not artifacts_dir.is_dir()
        or artifacts_dir.is_symlink()
    ):
        raise ValueError("benchmark table output lacks the exact artifact owner")
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

    tables_dir = artifacts_dir / "tables"
    tables_dir.mkdir(mode=0o750)

    _write_boundary_ordering_table(tables_dir, summary)
    _write_boundary_ack_gate_tables(tables_dir, summary)
    _write_scenario_table(tables_dir, summary)


def _optional_object(parent: dict, key: str, context: str) -> dict:
    """Return one optional object without manufacturing missing content."""
    return require_object(parent[key], context) if key in parent else {}


def _distribution(parent: dict, key: str) -> dict:
    """Return and validate one required six-value distribution."""
    value = require_object(parent[key], f"{key} distribution")
    require_exact_keys(
        value, {"min", "p50", "p95", "p99", "max", "count"},
        f"{key} distribution",
    )
    return value


def _optional_distribution(parent: dict, key: str) -> dict:
    """Return one validated distribution or explicit absence."""
    return _distribution(parent, key) if key in parent else {}


def _statistic_cell(distribution: dict, name: str, precision: int = 0) -> str:
    """Render one observed statistic or explicit unavailability."""
    return _fmt(distribution[name], precision) if distribution else "n/a"


def _write_boundary_ordering_table(tables_dir: Path, summary: dict) -> None:
    """Write the ordered-CUT boundary proof results."""
    scenario = require_object(summary["scenario_metrics"], "scenario metrics")
    epoch = _optional_object(scenario, "epoch_test", "epoch metrics")
    if not epoch or "boundary_count" not in epoch:
        return

    sent = _optional_distribution(epoch, "total_sent")
    received = _optional_distribution(epoch, "total_received")
    loss = _optional_distribution(epoch, "loss_pct")
    latency = _optional_distribution(epoch, "avg_latency_us")
    boundaries = _distribution(epoch, "boundary_count")
    completed = _distribution(epoch, "completed_boundaries")
    protocol_faults = _distribution(epoch, "protocol_faults_observed")
    backpressure = _distribution(epoch, "backpressure_events")

    lines = [
        "# Ordered-CUT Boundary Proof",
        "",
        "| Metric | n | min | p50 | p95 | p99 | max |",
        "|--------|---|-----|-----|-----|-----|-----|",
    ]

    for label, dist in [
        ("boundary_count", boundaries),
        ("completed_boundaries", completed),
        ("protocol_faults_observed", protocol_faults),
        ("backpressure_events", backpressure),
        ("total_sent", sent),
        ("total_received", received),
        ("loss_pct", loss),
        ("avg_latency_us", latency),
    ]:
        if not dist or not isinstance(dist, dict):
            continue
        p = 2 if "latency" in label or "pct" in label else 0
        lines.append(
            f"| {label} | {dist['count']} | {_fmt(dist['min'], p)} | {_fmt(dist['p50'], p)} | "
            f"{_fmt(dist['p95'], p)} | {_fmt(dist['p99'], p)} | {_fmt(dist['max'], p)} |"
        )

    path = tables_dir / "ordered_cut_boundary_proof.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  Table: {path.name}", file=sys.stderr)


def _write_boundary_ack_gate_tables(tables_dir: Path, summary: dict) -> None:
    """Write boundary ACK-gate duration per transition type."""
    transition = require_object(summary["transition_metrics"], "transition metrics")
    per_type = _optional_object(transition, "per_type", "per-type transitions")
    if not per_type:
        return

    # Collect all boundary IDs
    all_bids = set()
    for data in per_type.values():
        all_bids.update(data["boundary_ack_gate_ns"].keys())
    bids = sorted(all_bids)

    for boundary_ordinal, bid in enumerate(bids):
        lines = [
            f"# Boundary ACK-Gate Duration - {bid}",
            "",
            "| Transition Type | n | min | p50 | p95 | p99 | max |",
            "|-----------------|---|-----|-----|-----|-----|-----|",
        ]

        for ttype in sorted(per_type.keys()):
            data = per_type[ttype]
            boundary_metrics = data["boundary_ack_gate_ns"]
            if bid not in boundary_metrics:
                continue
            dist = _distribution(boundary_metrics, bid)
            n = dist["count"]
            lines.append(
                f"| {ttype} | {n} | {_fmt(dist['min'])} | {_fmt(dist['p50'])} | "
                f"{_fmt(dist['p95'])} | {_fmt(dist['p99'])} | {_fmt(dist['max'])} |"
            )

        # Add aggregate
        aggregate = _optional_object(transition, "aggregate", "aggregate transitions")
        aggregate_ack = _optional_object(
            aggregate, "boundary_ack_gate_ns", "aggregate ACK metrics"
        )
        if bid in aggregate_ack:
            agg_dist = _distribution(aggregate_ack, bid)
            n = agg_dist["count"]
            lines.append(
                f"| **aggregate** | {n} | {_fmt(agg_dist['min'])} | {_fmt(agg_dist['p50'])} | "
                f"{_fmt(agg_dist['p95'])} | {_fmt(agg_dist['p99'])} | {_fmt(agg_dist['max'])} |"
            )

        lines.append("")
        lines.append("All values in nanoseconds.")

        path = tables_dir / f"boundary_ack_gate_{boundary_ordinal:03d}.md"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"  Table: {path.name}", file=sys.stderr)


def _write_scenario_table(tables_dir: Path, summary: dict) -> None:
    """Write traffic and latency statistics with their observed sample counts."""
    scenario = require_object(summary["scenario_metrics"], "scenario metrics")
    rows = []
    packets = _optional_object(scenario, "packet_tests", "packet metrics")
    for size, metrics in sorted(packets.items(), key=lambda item: int(item[0])):
        rows.append((f"Packet {size}B", metrics, "tx_count", "rx_count"))
    for family, label, sent, received in (
        ("epoch_test", "Epoch", "total_sent", "total_received"),
        ("commit_confirmed_test", "Commit-confirmed", "tx_count", "rx_count"),
        ("rollback_test", "Rollback", "tx_count", "rx_count"),
    ):
        metrics = _optional_object(scenario, family, family)
        if metrics and sent in metrics:
            rows.append((label, metrics, sent, received))
    if not rows:
        return

    lines = [
        "# Scenario Traffic Summary",
        "",
        "| Test | TX p50 | RX p50 | Traffic n | Loss max | Loss n | "
        "Run-mean latency p50 (us) | Run-mean latency p99 (us) | Latency n |",
        "|------|--------|--------|-----------|----------|--------|"
        "--------------------------|--------------------------|-----------|",
    ]
    for label, metrics, sent, received in rows:
        tx = _optional_distribution(metrics, sent)
        rx = _optional_distribution(metrics, received)
        loss = _optional_distribution(metrics, "loss_pct")
        latency = _optional_distribution(metrics, "avg_latency_us")
        loss_cell = f"{_fmt(loss['max'], 2)}%" if loss else "n/a"
        lines.append(
            f"| {label} | {_statistic_cell(tx, 'p50')} | {_statistic_cell(rx, 'p50')} | "
            f"{_statistic_cell(tx, 'count')} | {loss_cell} | {_statistic_cell(loss, 'count')} | "
            f"{_statistic_cell(latency, 'p50', 2)} | {_statistic_cell(latency, 'p99', 2)} | "
            f"{_statistic_cell(latency, 'count')} |"
        )
    path = tables_dir / "scenario_traffic.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  Table: {path.name}", file=sys.stderr)
