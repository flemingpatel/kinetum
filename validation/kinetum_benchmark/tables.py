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


def _fmt(val, precision=0):
    """Format a number for table display."""
    if isinstance(val, float):
        if precision == 0:
            return f"{val:.0f}"
        return f"{val:.{precision}f}"
    return str(val)


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


def _latency_cells(metrics: dict) -> tuple[str, str]:
    """Return p50/p99 latency cells without manufacturing unsupported data."""
    latency = _optional_distribution(metrics, "avg_latency_us")
    if not latency:
        return "n/a", "n/a"
    return _fmt(latency["p50"], 2), _fmt(latency["p99"], 2)


def _write_boundary_ordering_table(tables_dir: Path, summary: dict) -> None:
    """Write the ordered-CUT boundary proof results."""
    scenario = require_object(summary["scenario_metrics"], "scenario metrics")
    epoch = _optional_object(scenario, "epoch_test", "epoch metrics")
    if not epoch:
        return

    sent = _distribution(epoch, "total_sent")
    received = _distribution(epoch, "total_received")
    loss = _distribution(epoch, "loss_pct")
    latency = _optional_distribution(epoch, "avg_latency_us")
    boundaries = _distribution(epoch, "boundary_count")
    completed = _distribution(epoch, "completed_boundaries")
    protocol_faults = _distribution(epoch, "protocol_faults_observed")
    backpressure = _distribution(epoch, "backpressure_events")

    lines = [
        "# Ordered-CUT Boundary Proof",
        "",
        f"Runs: {sent['count']}",
        "",
        "| Metric | min | p50 | p95 | p99 | max |",
        "|--------|-----|-----|-----|-----|-----|",
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
            f"| {label} | {_fmt(dist['min'], p)} | {_fmt(dist['p50'], p)} | "
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
    """Write traffic counters and available profile-qualified latency."""
    sm = require_object(summary["scenario_metrics"], "scenario metrics")
    if not sm:
        return

    lines = [
        "# Scenario Traffic Summary",
        "",
        "| Test | TX p50 | RX p50 | Loss max | Latency p50 (us) | Latency p99 (us) | n |",
        "|------|--------|--------|----------|-------------------|-------------------|---|",
    ]

    # Packet tests
    packet_metrics = _optional_object(sm, "packet_tests", "packet metrics")
    for size, metrics in sorted(packet_metrics.items(), key=lambda x: int(x[0])):
        tx = _distribution(metrics, "tx_count")
        rx = _distribution(metrics, "rx_count")
        loss = _distribution(metrics, "loss_pct")
        latency_p50, latency_p99 = _latency_cells(metrics)
        n = tx["count"]
        lines.append(
            f"| Packet {size}B | {_fmt(tx['p50'])} | {_fmt(rx['p50'])} | "
            f"{_fmt(loss['max'], 2)}% | {latency_p50} | "
            f"{latency_p99} | {n} |"
        )

    # Epoch
    et = _optional_object(sm, "epoch_test", "epoch metrics")
    if et:
        sent = _distribution(et, "total_sent")
        recv = _distribution(et, "total_received")
        loss = _distribution(et, "loss_pct")
        latency_p50, latency_p99 = _latency_cells(et)
        n = sent["count"]
        lines.append(
            f"| Epoch | {_fmt(sent['p50'])} | {_fmt(recv['p50'])} | "
            f"{_fmt(loss['max'], 2)}% | {latency_p50} | "
            f"{latency_p99} | {n} |"
        )

    # Commit-confirmed
    cc = _optional_object(sm, "commit_confirmed_test", "commit-confirmed metrics")
    if cc:
        tx = _distribution(cc, "tx_count")
        rx = _distribution(cc, "rx_count")
        loss = _distribution(cc, "loss_pct")
        latency_p50, latency_p99 = _latency_cells(cc)
        n = tx["count"]
        lines.append(
            f"| Commit-confirmed | {_fmt(tx['p50'])} | {_fmt(rx['p50'])} | "
            f"{_fmt(loss['max'], 2)}% | {latency_p50} | "
            f"{latency_p99} | {n} |"
        )

    # Rollback
    rb = _optional_object(sm, "rollback_test", "rollback metrics")
    if rb:
        tx = _distribution(rb, "tx_count")
        rx = _distribution(rb, "rx_count")
        loss = _distribution(rb, "loss_pct")
        latency_p50, latency_p99 = _latency_cells(rb)
        n = tx["count"]
        lines.append(
            f"| Rollback | {_fmt(tx['p50'])} | {_fmt(rx['p50'])} | "
            f"{_fmt(loss['max'], 2)}% | {latency_p50} | "
            f"{latency_p99} | {n} |"
        )

    path = tables_dir / "scenario_traffic.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  Table: {path.name}", file=sys.stderr)
