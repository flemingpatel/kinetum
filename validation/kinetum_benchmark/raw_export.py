"""
Raw CSV exporter - per-sample data for true CDF plots.

Reads per-run test_results.json and merged_transitions.jsonl
to produce flat CSVs with one row per sample (not distributions).
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import List

from kinetum_validation.engine.json_contract import (
    parse_exact_json_object,
    require_string,
    validate_transition_metric_record,
)

from .contracts import (
    validate_benchmark_manifest,
    validate_benchmark_result_identity,
    validate_benchmark_run_artifacts,
    validate_benchmark_transition_multiset,
)


def export_raw(input_dir: Path, artifacts_dir: Path,
               inclusion_policy: str = "passed_only") -> None:
    """
    Export raw per-sample CSVs from benchmark data.

    Produces:
      - artifacts/benchmark_scenario_raw.csv
      - artifacts/benchmark_transitions_raw.csv

    Parameters
    ----------
    input_dir : Path
        Benchmark root directory.
    artifacts_dir : Path
        Output directory for derived artifacts.
    inclusion_policy : str
        "passed_only" or "all_runs".
    """
    if inclusion_policy not in {"passed_only", "all_runs"}:
        raise ValueError("benchmark inclusion policy is undeclared")
    if artifacts_dir != input_dir / "artifacts":
        raise ValueError("benchmark artifacts must use the exact direct child")
    manifest = _read_terminal_manifest(input_dir)
    if inclusion_policy != manifest["inclusion_policy"]:
        raise ValueError(
            "raw-export inclusion policy disagrees with the terminal manifest"
        )
    scenario_rows = _build_scenario_raw_rows(
        input_dir, manifest, inclusion_policy
    )
    transition_rows = _build_transition_raw_rows(
        input_dir, manifest, inclusion_policy
    )
    try:
        artifacts_dir.mkdir(mode=0o750)
    except FileExistsError as exc:
        raise ValueError("benchmark artifacts directory already exists") from exc
    if scenario_rows:
        _write_raw_csv(
            artifacts_dir / "benchmark_scenario_raw.csv",
            [
                "run", "all_passed", "test_type", "variant", "tx_count",
                "rx_count", "loss_pct", "avg_latency_us", "throughput_pps",
            ],
            scenario_rows,
            "Raw scenario CSV",
        )
    if transition_rows:
        _write_raw_csv(
            artifacts_dir / "benchmark_transitions_raw.csv",
            list(transition_rows[0]),
            transition_rows,
            "Raw transitions CSV",
        )


def _write_raw_csv(
    path: Path,
    fieldnames: List[str],
    rows: List[dict],
    label: str,
) -> None:
    """Publish one fully composed raw CSV into the fresh artifact root."""
    with open(path, "x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  {label}: {path} ({len(rows)} rows)", file=sys.stderr)


def _csv_latency(value: object) -> object:
    """Project unavailable latency as an explicit empty CSV cell."""
    return "" if value is None else value


def _read_terminal_manifest(input_dir: Path) -> dict:
    """Read one exact terminal benchmark manifest."""
    if not input_dir.is_dir() or input_dir.is_symlink():
        raise ValueError("benchmark input directory is indirect")
    manifest_path = input_dir / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("benchmark manifest is unavailable")
    with open(manifest_path, encoding="utf-8") as manifest_file:
        manifest = parse_exact_json_object(
            manifest_file.read(), "benchmark manifest"
        )
    validate_benchmark_manifest(manifest, completed=True)
    return manifest


def _build_scenario_raw_rows(
    input_dir: Path,
    manifest: dict,
    inclusion_policy: str = "passed_only",
) -> List[dict]:
    """Build one validated row per run and scenario result."""
    expected_names = [
        f"run_{row['run_id']:03d}" for row in manifest["results"]["runs"]
    ]
    manifest_rows = {
        f"run_{row['run_id']:03d}": row for row in manifest["results"]["runs"]
    }
    run_dirs = sorted(
        path for path in input_dir.iterdir() if path.name.startswith("run_")
    )
    if (
        [path.name for path in run_dirs] != expected_names
        or any(not path.is_dir() or path.is_symlink() for path in run_dirs)
    ):
        raise ValueError("benchmark run-directory membership disagrees with manifest")

    include_all = inclusion_policy == "all_runs"
    rows: List[dict] = []

    for run_dir in run_dirs:
        results_path = run_dir / "test_results.json"
        if results_path.is_symlink():
            raise ValueError(f"{run_dir.name} test results are indirect")
        if not results_path.exists():
            if manifest_rows[run_dir.name]["passed"]:
                raise ValueError(
                    f"{run_dir.name} manifest success has no test results"
                )
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
        _validate_run_metadata_if_required(run_dir, result, manifest)
        if not include_all and not result["all_passed"]:
            continue

        run_id = run_dir.name
        run_passed = result["all_passed"]

        # Packet tests
        for pt in result["packet_tests"]:
            rows.append({
                "run": run_id,
                "all_passed": run_passed,
                "test_type": "packet",
                "variant": f"size_{pt['packet_size']}",
                "tx_count": pt["tx_count"],
                "rx_count": pt["rx_count"],
                "loss_pct": pt["loss_pct"],
                "avg_latency_us": _csv_latency(pt["avg_latency_us"]),
                "throughput_pps": pt["throughput_pps"],
            })

        # Epoch test
        et = result["epoch_test"]
        if et and (include_all or et["passed"]):
            rows.append({
                "run": run_id,
                "all_passed": run_passed,
                "test_type": "epoch",
                "variant": "",
                "tx_count": et["total_sent"],
                "rx_count": et["total_received"],
                "loss_pct": et["loss_pct"],
                "avg_latency_us": _csv_latency(et["avg_latency_us"]),
                "throughput_pps": "",
            })

        # Commit-confirmed
        cc = result["commit_confirmed_test"]
        if cc and (include_all or cc["passed"]):
            rows.append({
                "run": run_id,
                "all_passed": run_passed,
                "test_type": "commit_confirmed",
                "variant": "",
                "tx_count": cc["tx_count"],
                "rx_count": cc["rx_count"],
                "loss_pct": cc["loss_pct"],
                "avg_latency_us": _csv_latency(cc["avg_latency_us"]),
                "throughput_pps": "",
            })

        # Rollback
        rb = result["rollback_test"]
        if rb and (include_all or rb["passed"]):
            rows.append({
                "run": run_id,
                "all_passed": run_passed,
                "test_type": "rollback",
                "variant": "",
                "tx_count": rb["tx_count"],
                "rx_count": rb["rx_count"],
                "loss_pct": rb["loss_pct"],
                "avg_latency_us": _csv_latency(rb["avg_latency_us"]),
                "throughput_pps": "",
            })

        guardrails = result["guardrails_test"]
        if guardrails and (include_all or guardrails["passed"]):
            rows.append({
                "run": run_id,
                "all_passed": run_passed,
                "test_type": "guardrails",
                "variant": (
                    f"{guardrails['candidate_snapshot_id']}->"
                    f"{guardrails['rollback_snapshot_id']}"
                ),
                "tx_count": "",
                "rx_count": "",
                "loss_pct": "",
                "avg_latency_us": "",
                "throughput_pps": "",
            })

    return rows


def _validate_run_metadata_if_required(
    run_dir: Path,
    result: dict,
    manifest: dict,
) -> None:
    """Validate run metadata when setup reached its publication boundary."""
    metadata_path = run_dir / "run_metadata.json"
    if metadata_path.is_symlink():
        raise ValueError(f"{run_dir.name} run metadata is indirect")
    if not metadata_path.exists():
        if not result["setup_failed"]:
            raise ValueError(f"{run_dir.name} omitted run metadata")
        return
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


def _build_transition_raw_rows(
    input_dir: Path,
    manifest: dict,
    inclusion_policy: str,
) -> List[dict]:
    """Build validated raw rows from the merged transition ledger."""
    expected_records = _read_per_run_transition_records(input_dir, manifest)
    merged_path = input_dir / "merged_transitions.jsonl"
    if merged_path.is_symlink():
        raise ValueError("merged transition evidence is indirect")
    if not merged_path.exists():
        if expected_records:
            raise ValueError("benchmark aggregate omitted merged transition evidence")
        return []
    if not merged_path.is_file():
        raise ValueError("merged transition evidence is indirect")

    manifest_rows = {
        f"run_{row['run_id']:03d}": row for row in manifest["results"]["runs"]
    }
    included_runs = {
        run_id
        for run_id, row in manifest_rows.items()
        if inclusion_policy == "all_runs" or row["passed"]
    }

    rows: List[dict] = []
    expected_boundary_identities = None
    merged_count = 0

    with open(merged_path, encoding="utf-8") as f:
        for line in f:
            if not line.endswith("\n") or not line[:-1]:
                raise ValueError("merged transition record boundary is malformed")
            merged = parse_exact_json_object(
                line[:-1], "merged transition metric"
            )
            if "_run" not in merged:
                raise ValueError("merged transition metric omitted run identity")
            run_id = require_string(merged["_run"], "transition run identity")
            if run_id not in manifest_rows:
                raise ValueError("merged transition names a foreign run")
            if (
                merged_count >= len(expected_records)
                or merged != expected_records[merged_count]
            ):
                raise ValueError(
                    "merged transition evidence disagrees with per-run truth"
                )
            merged_count += 1
            rec = {key: value for key, value in merged.items() if key != "_run"}
            validate_transition_metric_record(rec)
            if run_id not in included_runs:
                continue

            # Flatten exact sequence-CUT timing into columns.
            b_cut_drain = {}
            b_ack_gate = {}
            boundary_rows = rec["boundary_epoch_stats"]
            for bd in boundary_rows:
                bid = bd["boundary_id"]
                b_cut_drain[bid] = bd["cut_drain_duration_ns"]
                b_ack_gate[bid] = bd["ack_gate_duration_ns"]
            if len(b_cut_drain) != len(boundary_rows):
                raise ValueError(
                    "transition raw export contains duplicate boundary identity"
                )
            boundary_identities = tuple(sorted(
                (row["boundary_id"], row["boundary_index"])
                for row in boundary_rows
            ))
            if expected_boundary_identities is None:
                expected_boundary_identities = boundary_identities
            elif boundary_identities != expected_boundary_identities:
                raise ValueError(
                    "transition boundary membership changed across raw export"
                )

            row = {
                "run": run_id,
                "transition_type": rec["transition_type"],
                "from_epoch": rec["from_epoch"],
                "to_epoch": rec["to_epoch"],
                "rx_packets_delta": rec["rx_packets_delta"],
                "tx_packets_delta": rec["tx_packets_delta"],
                "dropped_packets_delta": rec["dropped_packets_delta"],
            }

            # Add boundary columns dynamically
            for bid in sorted(b_cut_drain.keys()):
                row[f"cut_drain_ns_{bid}"] = b_cut_drain[bid]
                row[f"ack_gate_ns_{bid}"] = b_ack_gate[bid]

            rows.append(row)
    if merged_count != len(expected_records):
        raise ValueError("merged transition evidence omitted per-run truth")

    return rows


def _read_per_run_transition_records(input_dir: Path, manifest: dict) -> List[dict]:
    """Read the exact concatenation that the immutable merged ledger must equal."""
    records: List[dict] = []
    test_type = manifest["scenario"]["test_type"]
    for manifest_row in manifest["results"]["runs"]:
        run_name = f"run_{manifest_row['run_id']:03d}"
        run_dir = input_dir / run_name
        if not run_dir.is_dir() or run_dir.is_symlink():
            raise ValueError("benchmark run-directory membership is inexact")
        path = run_dir / "transition_metrics.jsonl"
        observed_types = []
        if path.is_symlink():
            raise ValueError(f"{run_name} transition metrics are indirect")
        if path.exists():
            if not path.is_file():
                raise ValueError(f"{run_name} transition metrics are indirect")
            with open(path, encoding="utf-8") as stream:
                for line in stream:
                    if not line.endswith("\n") or not line[:-1]:
                        raise ValueError(
                            f"{run_name} transition record boundary is malformed"
                        )
                    record = parse_exact_json_object(
                        line[:-1], f"{run_name} transition metric"
                    )
                    validate_transition_metric_record(record)
                    observed_types.append(record["transition_type"])
                    records.append({**record, "_run": run_name})
        validate_benchmark_transition_multiset(
            observed_types,
            test_type,
            complete=manifest_row["passed"],
        )
    return records
