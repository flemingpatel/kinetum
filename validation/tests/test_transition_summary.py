"""
Tests for transition summaries and benchmark evidence aggregation.

Validates that transition_summary.json correctly groups metrics by
transition_type and computes independent distributions for each type.

Run:
    python3 -B -m pytest -v validation/tests/test_transition_summary.py
"""

import json
import io
import copy
import csv
import tempfile
import unittest
from argparse import Namespace
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from kinetum_benchmark.__main__ import cmd_report
from kinetum_benchmark.aggregator import (
    _compute_scenario_metrics,
    _compute_transition_metrics,
    _selected_trex_identity,
    aggregate as aggregate_benchmark,
)
from kinetum_benchmark.contracts import (
    validate_benchmark_manifest,
    validate_benchmark_result_identity,
    validate_benchmark_summary,
    validate_benchmark_summary_identity,
    validate_benchmark_transition_multiset,
)
from kinetum_benchmark.exporter import export_csv
from kinetum_validation.config.types import (
    AnalysisResult,
    BackendConfig,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    EpochTestResult,
    GuardrailsTestResult,
    ProcessConfig,
    StatsValidationResult,
    TestConfig as ValidationConfig,
    TestResult as ValidationResult,
    TestSuiteResult as ValidationSuiteResult,
    TestType as ValidationTestType,
    TrafficEndpointConfig,
    TransitionType,
)
from kinetum_validation.engine.json_contract import (
    EXPECTED_BUILD_FEATURES,
    EXPECTED_PLATFORM_CAPABILITIES,
    PROTOCOL_FAULT_CODE_ORDER,
    JsonContractError,
    require_object,
    validate_transition_metric_record,
    validate_test_suite_result,
)
from kinetum_validation.orchestrator import TestOrchestrator as ValidationOrchestrator

from kinetum_validation.report.console import ConsoleReporter
from kinetum_validation.report.artifacts import RunArtifacts
from tests.traffic_fixtures import complete_trex_identity


TREX_IDENTITY = complete_trex_identity()
TEST_PROCESS_CONFIG = ProcessConfig(
    runtime_root=Path("/opt/kinetum"),
    validation_root=Path("/var/tmp/kinetum-validation"),
)


def _make_record(
    transition_type: TransitionType,
    from_epoch: int,
    to_epoch: int,
    ack_gate_ns: int,
    fanout_overflow: int = 0,
) -> dict:
    """Build a minimal transition_metrics.jsonl record."""
    return {
        "transition_type": transition_type.value,
        "runtime_generation": 1,
        "transition_generation": to_epoch,
        "from_epoch": from_epoch,
        "to_epoch": to_epoch,
        "transition_state": "EPOCH_TRANSITION_STATE_IDLE",
        "transition_success_blocked": False,
        "counter_observations": {
            "expected_workers": 1,
            "before": {
                "snapshot_id": f"snapshot.{from_epoch}", "active_epoch": from_epoch,
                "collection_monotonic_ns": 100,
                "workers": [{
                    "worker_index": 0, "observation_epoch": from_epoch,
                    "publication_generation": 1, "published_monotonic_ns": 100,
                    "rx_packets": 100, "tx_packets": 100, "dropped_packets": 0,
                    "rx_bytes": 6400, "tx_bytes": 6400, "fanout_overflow": 0,
                }],
            },
            "after": {
                "snapshot_id": f"snapshot.{to_epoch}", "active_epoch": to_epoch,
                "collection_monotonic_ns": 200,
                "workers": [{
                    "worker_index": 0, "observation_epoch": to_epoch,
                    "publication_generation": 2, "published_monotonic_ns": 200,
                    "rx_packets": 1100, "tx_packets": 1100, "dropped_packets": 0,
                    "rx_bytes": 70400, "tx_bytes": 70400, "fanout_overflow": fanout_overflow,
                }],
            },
        },
        "rx_packets_delta": 1000,
        "tx_packets_delta": 1000,
        "dropped_packets_delta": 0,
        "protocol_fault_deltas": {
            code: 0 for code in PROTOCOL_FAULT_CODE_ORDER
        },
        "boundary_epoch_stats": [
            {
                "boundary_id": "region_0->region_1",
                "boundary_index": 0,
                "transition_generation": to_epoch,
                "from_epoch": from_epoch,
                "to_epoch": to_epoch,
                "cut_sequence": 1000,
                "sender_phase": "BOUNDARY_SENDER_PHASE_OPEN",
                "receiver_phase": "BOUNDARY_RECEIVER_PHASE_OPEN",
                "data_enqueued_sequence_delta": 1000,
                "data_dequeued_sequence_delta": 1000,
                "cut_delivery_duration_ns": ack_gate_ns // 4,
                "cut_drain_duration_ns": ack_gate_ns // 2,
                "ack_gate_duration_ns": ack_gate_ns,
                "data_backpressure_events_delta": 1,
            }
        ],
        "region_epoch_stats": [
            {
                "region_id": 0,
                "minimum_active_epoch": to_epoch,
                "maximum_active_epoch": to_epoch,
                "minimum_source_epoch": to_epoch,
                "maximum_source_epoch": to_epoch,
                "active_unretired": 0,
                "future_unretired": 0,
                "activated_participants": 1,
                "worker_count": 1,
                "fanout_overflow_delta": fanout_overflow,
            },
        ],
        "stage_stats": [
            {
                "stage_id": "stage_0",
                "in_packets_delta": 1000,
                "out_packets_delta": 1000,
                "dropped_packets_delta": 0,
            },
        ],
    }


def _distribution(value: int) -> dict:
    """Build one exact single-sample benchmark distribution."""
    return {
        "min": value,
        "p50": value,
        "p95": value,
        "p99": value,
        "max": value,
        "count": 1,
    }


def _epoch_benchmark_summary() -> dict:
    """Build one valid scenario-bound epoch benchmark summary."""
    scenario_metrics = {
        "epoch_test": {
            "total_sent": _distribution(1000),
            "total_received": _distribution(1000),
            "loss_pct": _distribution(0),
            "avg_latency_us": _distribution(10),
            "boundary_count": _distribution(1),
            "completed_boundaries": _distribution(1),
            "protocol_faults_observed": _distribution(0),
            "backpressure_events": _distribution(1),
        }
    }
    return {
        "variant": "test",
        "inclusion_policy": "passed_only",
        "scenario": {
            "deployment": "fan_in_edge_gateway",
            "test_type": "epoch",
            "backend": "dpdk_tap",
            "stream_topology": "default",
            "storage_profile": "shared",
            "traffic_driver": "native_tap",
            "latency_source": "kernel_af_packet_pcap",
            "traffic_host": "",
            "traffic_ssh_port": 0,
            "traffic_python": "/usr/bin/python3",
            "traffic_work_dir": "/tmp/kinetum_traffic",
            "trex_server": "127.0.0.1",
            "trex_api_path": "",
            "trex_ports": [],
        },
        "epoch_pps": 1000,
        "total_runs": 1,
        "passed_runs": 1,
        "failed_runs": 0,
        "failed_run_ids": [],
        "failure_reasons": {},
        "trex_identity": None,
        "scenario_metrics": scenario_metrics,
        "transition_metrics": _compute_transition_metrics([
            _make_record(TransitionType.EPOCH, 1, 2, ack_gate_ns=300)
        ]),
    }


def _epoch_benchmark_manifest() -> dict:
    """Build the terminal manifest owning ``_epoch_benchmark_summary``."""
    summary = _epoch_benchmark_summary()
    return {
        "timestamp": "2026-09-03T12:00:00+00:00",
        "argv": ["kinetum_benchmark", "run", "--runtime-root", "/opt/kinetum"],
        "variant": summary["variant"],
        "inclusion_policy": summary["inclusion_policy"],
        "scenario": summary["scenario"],
        "runs": 1,
        "config": {
            "pps": 1000,
            "count": 1000,
            "packet_size": 64,
            "all_sizes": False,
            "num_flows": 1,
            "epoch_duration": 15.0,
            "epoch_pps": summary["epoch_pps"],
            "epoch_transition_time": 5.0,
            "epoch_overlap_ms": 500,
            "runtime_root": "/opt/kinetum",
            "validation_root": "/var/tmp/kinetum-validation",
        },
        "system": {
            "hostname": "test-host",
            "kernel": "test-kernel",
            "arch": "test-arch",
            "os": "test-os",
        },
        "runtime_release": {
            "source": "/opt/kinetum/bin/kinetum-info",
            "version": "0.1.0",
            "dpdk_version": "24.11.7",
            "tls_enabled": False,
            "build_features": {
                key: False for key in sorted(EXPECTED_BUILD_FEATURES)
            },
            "platform_capabilities": sorted(EXPECTED_PLATFORM_CAPABILITIES),
        },
        "completed": "2026-09-03T12:01:00+00:00",
        "total_duration_s": 60.0,
        "results": {
            "total_runs": 1,
            "passed_runs": 1,
            "failed_runs": 0,
            "runs": [
                {"run_id": 1, "passed": True, "duration_s": 60.0, "error": ""}
            ],
        },
    }


def _epoch_test_result_artifact() -> dict:
    """Build one exact successful epoch test-results artifact."""
    return {
        "timestamp": "2026-09-03T12:00:00+00:00",
        "deployment": "fan_in_edge_gateway",
        "test_type": "epoch",
        "backend": "dpdk_tap",
        "traffic_driver": "native_tap",
        "timestamp_source": "kernel_af_packet",
        "rate_control_source": "userspace_native_sender",
        "latency_source": "kernel_af_packet_pcap",
        "dry_run": False,
        "total_duration_s": 15.0,
        "setup_failed": False,
        "all_passed": True,
        "total_tests": 1,
        "passed_tests": 1,
        "failed_tests": 0,
        "stats_validation": {"required": False, "passed": True, "message": ""},
        "packet_tests": [],
        "nat_exchange": None,
        "epoch_test": {
            "passed": True,
            "duration_s": 15.0,
            "total_sent": 100,
            "total_received": 100,
            "initial_generation_sent": 50,
            "next_generation_sent": 50,
            "initial_generation_received": 50,
            "next_generation_received": 50,
            "generation_tag_transition_seq": 50,
            "loss_pct": 0.0,
            "avg_latency_us": 10.0,
            "zero_loss": True,
            "transitions_observed": 1,
            "boundary_count": 1,
            "completed_boundaries": 1,
            "protocol_faults_observed": 0,
            "backpressure_events": 0,
            "boundary_ordering_validated": True,
            "message": "exact",
        },
        "commit_confirmed_test": None,
        "rollback_test": None,
        "guardrails_test": None,
    }


def _single_scenario_result_artifact(
    test_type: str,
    field: str,
    result: dict,
) -> dict:
    """Build one exact successful artifact for a non-epoch scenario."""
    artifact = _epoch_test_result_artifact()
    artifact["test_type"] = test_type
    artifact["epoch_test"] = None
    artifact[field] = result
    return artifact


def _packet_test_result_artifact() -> dict:
    """Build one exact successful standard packet-test artifact."""
    artifact = _epoch_test_result_artifact()
    artifact.update({
        "test_type": "standard",
        "total_tests": 2,
        "passed_tests": 2,
        "nat_exchange": {
            "passed": True, "session_count": 32, "return_count": 32,
            "context_count": 1, "duration_s": 8.0, "message": "exact",
        },
        "packet_tests": [{
            "packet_size": 64,
            "passed": True,
            "tx_count": 1,
            "rx_count": 1,
            "loss_pct": 0.0,
            "avg_latency_us": 1.0,
            "throughput_pps": 1.0,
            "duration_s": 1.0,
            "message": "exact",
        }],
        "epoch_test": None,
    })
    return artifact


def _commit_confirmed_result_artifact() -> dict:
    """Build one exact successful commit-confirmed artifact."""
    return _single_scenario_result_artifact(
        "commit_confirmed",
        "commit_confirmed_test",
        {
            "passed": True,
            "duration_s": 30.0,
            "confirm_success": True,
            "confirm_snapshot_id": "confirmed",
            "confirm_time_remaining_ms": 1000,
            "confirmed_survived_deadline": True,
            "confirmed_survival_elapsed_ms": 2000,
            "timeout_rollback_occurred": True,
            "timeout_rollback_snapshot_id": "confirmed",
            "tx_count": 100,
            "rx_count": 100,
            "loss_pct": 0.0,
            "avg_latency_us": 1.0,
            "message": "exact",
        },
    )


def _rollback_result_artifact() -> dict:
    """Build one exact successful full-plus-selective rollback artifact."""
    return _single_scenario_result_artifact(
        "rollback",
        "rollback_test",
        {
            "passed": True,
            "duration_s": 30.0,
            "full_rollback_success": True,
            "full_rollback_snapshot_id": "baseline",
            "selective_rollback_success": True,
            "selective_rollback_modules": ["kinetum.acl"],
            "selective_rollback_snapshot_id": "hybrid",
            "tx_count": 100,
            "rx_count": 100,
            "loss_pct": 0.0,
            "avg_latency_us": 1.0,
            "message": "exact",
        },
    )


def _as_trex_latency_unavailable(artifact: dict) -> dict:
    """Convert one complete native artifact to exact TRex latency absence."""
    converted = copy.deepcopy(artifact)
    converted.update({
        "deployment": "fan_in_edge_gateway",
        "backend": "dpdk_pci",
        "traffic_driver": "trex",
        "timestamp_source": "trex_port_stats",
        "rate_control_source": "trex_stl_rate_control",
        "latency_source": None,
    })
    for row in converted["packet_tests"]:
        row["avg_latency_us"] = None
    for field in ("epoch_test", "commit_confirmed_test", "rollback_test"):
        row = converted[field]
        if row is not None:
            row["avg_latency_us"] = None
    if converted["epoch_test"] is not None:
        converted["epoch_test"]["generation_tag_transition_seq"] = -1
    return converted


def _result_latency_rows(artifact: dict) -> list[dict]:
    """Return every latency-bearing row in one test-results artifact."""
    rows = list(artifact["packet_tests"])
    rows.extend(
        artifact[field]
        for field in ("epoch_test", "commit_confirmed_test", "rollback_test")
        if artifact[field] is not None
    )
    return rows


@contextmanager
def _metrics_case():
    """Create an orchestrator pointing at a temp dir with synthetic JSONL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir)
        config = ValidationConfig(process=TEST_PROCESS_CONFIG, output_dir=output_dir)
        orch = ValidationOrchestrator(config)

        # Write synthetic transition records:
        # 1 epoch (ack_gate_ns=300), 2 rollback_apply_v1 (100, 500),
        # 1 rollback_full (200), and 1 commit-confirmed timeout rollback (400)
        records = [
            _make_record(TransitionType.EPOCH, 1, 2, ack_gate_ns=300),
            _make_record(TransitionType.ROLLBACK_APPLY_V1, 2, 3, ack_gate_ns=100),
            _make_record(
                TransitionType.ROLLBACK_APPLY_V1,
                5,
                6,
                ack_gate_ns=500,
                fanout_overflow=2,
            ),
            _make_record(TransitionType.ROLLBACK_FULL, 6, 7, ack_gate_ns=200),
            _make_record(
                TransitionType.COMMIT_CONFIRMED_TIMEOUT_ROLLBACK,
                7,
                8,
                ack_gate_ns=400,
            ),
        ]

        metrics_file = output_dir / "transition_metrics.jsonl"
        with open(metrics_file, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

        yield orch, output_dir


def _write_summary_quietly(orch: ValidationOrchestrator) -> None:
    """Write transition_summary.json while suppressing operator console output."""
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        orch.artifacts.write_transition_summary()


@contextmanager
def _epoch_benchmark_case(inclusion_policy: str):
    """Yield complete TRex artifacts with one final-statistics failure.

    Parameters
    ----------
    inclusion_policy : str
        Exact manifest selection: ``passed_only`` or ``all_runs``.

    Yields
    ------
    Path
        Fresh two-run root whose files are removed on context exit.
    """
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        manifest = _epoch_benchmark_manifest()
        manifest.update(
            inclusion_policy=inclusion_policy, runs=2, total_duration_s=120.0,
            completed="2026-09-03T12:02:00+00:00",
        )
        manifest["config"].update(epoch_pps=100, epoch_duration=10.5)
        manifest["scenario"].update(
            backend="dpdk_pci", traffic_driver="trex",
            latency_source=None, traffic_host="traffic-host",
        )
        manifest["results"].update(total_runs=2, failed_runs=1)
        manifest["results"]["runs"].append({
            "run_id": 2, "passed": False, "duration_s": 60.0,
            "error": "statistics unavailable",
        })
        (root / "manifest.json").write_text(
            json.dumps(manifest, allow_nan=False) + "\n", encoding="utf-8"
        )
        profile = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(BackendType.DPDK_PCI)
        backend = BackendConfig(
            backend_type=BackendType.DPDK_PCI,
            ports=tuple(
                replace(port, runtime_direction=port.traffic_role, runtime_mac=f"02:00:00:00:00:{index:02x}")
                for index, port in enumerate(profile.ports)
            ),
        )
        for run_id, ack_gate_ns in ((1, 100), (2, 900)):
            run_root = root / f"run_{run_id:03d}"
            run_root.mkdir()
            config = ValidationConfig(
                deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
                process=TEST_PROCESS_CONFIG, backend=backend,
                traffic=TrafficEndpointConfig(host="traffic-host"), output_dir=run_root,
            )
            orchestrator = ValidationOrchestrator(config, release_metadata=manifest["runtime_release"])
            bundle = run_root / "runtime_bundle"
            with redirect_stdout(io.StringIO()):
                orchestrator._save_run_metadata(  # pylint: disable=protected-access
                    bundle / "configs/plan.pbtxt", bundle, copy.deepcopy(TREX_IDENTITY)
                )
            result = _as_trex_latency_unavailable(_epoch_test_result_artifact())
            result["epoch_test"].update(
                total_sent=1100, total_received=1100,
                initial_generation_sent=550, next_generation_sent=550,
                initial_generation_received=550, next_generation_received=550,
                boundary_count=2, completed_boundaries=2,
            )
            result.update(
                total_tests=2, passed_tests=2,
                timestamp=f"2026-09-03T12:0{run_id}:00+00:00",
            )
            result["stats_validation"] = {"required": True, "passed": True, "message": "exact"}
            if run_id == 2:
                result.update(all_passed=False, passed_tests=1, failed_tests=1)
                result["stats_validation"].update(passed=False, message="statistics unavailable")
            (run_root / "test_results.json").write_text(
                json.dumps(result, allow_nan=False) + "\n", encoding="utf-8"
            )
            record = _make_record(TransitionType.EPOCH, 1, 2, ack_gate_ns)
            observations = record["counter_observations"]
            observations["expected_workers"] = 3
            for endpoint in ("before", "after"):
                original = observations[endpoint]["workers"][0]
                total = original["rx_packets"]
                observations[endpoint]["workers"] = [
                    {
                        **original, "worker_index": index,
                        "rx_packets": rx, "tx_packets": tx,
                        "rx_bytes": rx * 64, "tx_bytes": tx * 64,
                    }
                    for index, (rx, tx) in enumerate(((total // 2, 0), (total // 2, 0), (0, total)))
                ]
            boundary = record["boundary_epoch_stats"][0]
            record["boundary_epoch_stats"] = [
                {
                    **boundary, "boundary_id": f"boundary.acl{index}.nat", "boundary_index": index,
                    "cut_sequence": 100, "data_enqueued_sequence_delta": 500,
                    "data_dequeued_sequence_delta": 500, "data_backpressure_events_delta": 0,
                }
                for index in range(2)
            ]
            region = record["region_epoch_stats"][0]
            record["region_epoch_stats"] = [{**region, "region_id": index} for index in range(3)]
            record["stage_stats"] = [
                {"stage_id": name, "in_packets_delta": count, "out_packets_delta": count, "dropped_packets_delta": 0}
                for name, count in (
                    ("rx0", 500), ("parse0", 500), ("acl0", 500),
                    ("rx1", 500), ("parse1", 500), ("acl1", 500),
                    ("nat", 1000), ("qos", 1000), ("tx", 1000),
                )
            ]
            (run_root / "transition_metrics.jsonl").write_text(
                json.dumps(record, allow_nan=False) + "\n", encoding="utf-8"
            )
        yield root


class TestBenchmarkAggregation(unittest.TestCase):
    """Aggregation and reporting preserve strict per-run evidence and provenance."""

    def test_partial_guardrails_keeps_elapsed_time_without_fabricating_rollback(self):
        """A failed baseline wait contributes its observed duration but no epoch step."""
        result = _single_scenario_result_artifact(
            "guardrails", "guardrails_test",
            asdict(GuardrailsTestResult(passed=False, duration_s=60.0, message="baseline unavailable")),
        )
        result.update(all_passed=False, passed_tests=0, failed_tests=1)
        validate_test_suite_result(result)
        metrics = _compute_scenario_metrics([result], include_all=True)
        self.assertEqual(metrics, {"guardrails_test": {"duration_s": _distribution(60.0)}})
        self.assertEqual(_compute_scenario_metrics([result]), {})

    def test_failed_loss_measurement_is_included_by_all_runs(self):
        """A failed verdict cannot erase an observed packet deficit from failure analysis."""
        result = _packet_test_result_artifact()
        result.update(all_passed=False, passed_tests=1, failed_tests=1)
        result["packet_tests"][0].update(
            passed=False, tx_count=1000, rx_count=980, loss_pct=2.0, throughput_pps=1000.0, duration_s=2.0,
        )
        validate_test_suite_result(result)
        metrics = _compute_scenario_metrics([result], include_all=True)
        self.assertEqual(metrics["packet_tests"]["64"]["loss_pct"], _distribution(2.0))
        self.assertEqual(_compute_scenario_metrics([result]), {})

    def test_incomplete_failed_trial_adds_no_zero_samples(self):
        """All-runs retains a failed trial while excluding its unavailable measurements."""
        with _epoch_benchmark_case("all_runs") as root:
            run = root / "run_002"
            (run / "test_results.json").unlink()
            (run / "transition_metrics.jsonl").unlink()
            result = ValidationSuiteResult(
                deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY, test_type=ValidationTestType.EPOCH,
                epoch_test=EpochTestResult(passed=False, duration_s=60.0, message="statistics unavailable"),
                stats_validation=StatsValidationResult(required=True, passed=False, message="statistics unavailable"),
                total_duration_s=60.0,
            )
            profile = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(BackendType.DPDK_PCI)
            with patch("kinetum_validation.report.artifacts.datetime", wraps=datetime) as clock, \
                    redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                clock.now.return_value = datetime(2026, 9, 3, 12, 2, tzinfo=timezone.utc)
                RunArtifacts(run, ConsoleReporter(color=False)).save_test_results(result, profile)
                aggregate_benchmark(root, "all_runs")
                export_csv(root)
                self.assertEqual(cmd_report(Namespace(input_dir=root, inclusion_policy="all-runs")), 0)
            summary = json.loads((root / "benchmark_summary.json").read_text())
            self.assertEqual((summary["passed_runs"], summary["failed_runs"]), (1, 1))
            self.assertTrue(all(row["count"] == 1 for row in summary["scenario_metrics"]["epoch_test"].values()))
            self.assertEqual(summary["transition_metrics"]["total_transitions"], 1)
            with (root / "artifacts/benchmark_scenario_raw.csv").open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[1]["run"], "run_002")
            self.assertTrue(all(rows[1][name] == "" for name in ("tx_count", "rx_count", "loss_pct", "avg_latency_us")))

    def test_observed_zero_is_retained_without_inventing_a_loss_percentage(self):
        """A completed empty sender has zero TX/RX/rate but no loss denominator or latency."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            result = ValidationSuiteResult(
                deployment=DeploymentMode.PASSTHROUGH, test_type=ValidationTestType.STANDARD,
                packet_tests=[ValidationResult(
                    packet_size=64, passed=False, tx_count=0, rx_count=0,
                    throughput_pps=0.0, duration_s=1.0, message="no packets sent",
                )],
                stats_validation=StatsValidationResult(required=True, passed=True, message="exact"),
                total_duration_s=1.0,
            )
            profile = DEPLOYMENT_SPECS[DeploymentMode.PASSTHROUGH].backend_profile(BackendType.DPDK_TAP)
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                RunArtifacts(root, ConsoleReporter(color=False)).save_test_results(result, profile)
            recorded = json.loads((root / "test_results.json").read_text())
            row = recorded["packet_tests"][0]
            self.assertIsNone(row["loss_pct"])
            self.assertIsNone(row["avg_latency_us"])
            summary = _compute_scenario_metrics([recorded], include_all=True)["packet_tests"]["64"]
            self.assertEqual(set(summary), {"tx_count", "rx_count", "throughput_pps"})
            self.assertTrue(all(item == _distribution(0) for item in summary.values()))
            row["loss_pct"] = 0.0
            with self.assertRaisesRegex(JsonContractError, "positive TX"):
                validate_test_suite_result(recorded)

    def test_small_nonzero_loss_survives_result_publication_and_summary(self):
        """One missing packet remains nonzero in admitted artifacts and cannot be reported as zero loss."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config = ValidationConfig(
                process=TEST_PROCESS_CONFIG, deployment=DeploymentMode.PASSTHROUGH, output_dir=root,
            )
            orchestrator = ValidationOrchestrator(config)
            result = ValidationSuiteResult(
                deployment=DeploymentMode.PASSTHROUGH, test_type=ValidationTestType.STANDARD,
                packet_tests=[ValidationResult(
                    packet_size=64, passed=True, tx_count=100000000, rx_count=99999999,
                    loss_pct=0.000001, avg_latency_us=10.123456789, throughput_pps=5000000.12345, duration_s=21.0,
                )],
                stats_validation=StatsValidationResult(required=True, passed=True, message="exact"),
                total_duration_s=21.0,
            )
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                orchestrator.artifacts.save_test_results(result, config.backend_profile)
            recorded = json.loads((root / "test_results.json").read_text())
            self.assertEqual(recorded["packet_tests"][0]["loss_pct"], 0.000001)
            self.assertEqual(recorded["packet_tests"][0]["avg_latency_us"], 10.123456789)
            self.assertEqual(recorded["packet_tests"][0]["throughput_pps"], 5000000.12345)
            summary = _compute_scenario_metrics([recorded])
            self.assertEqual(summary["packet_tests"]["64"]["loss_pct"]["max"], 0.000001)
            recorded["packet_tests"][0]["loss_pct"] = 0.0
            with self.assertRaisesRegex(JsonContractError, "counters"):
                validate_test_suite_result(recorded)

    def test_epoch_records_aggregate_and_report_under_both_inclusion_policies(self):
        """Run provenance belongs only to the merged ledger; failed runs follow the chosen policy."""
        for policy, expected_count, maximum in (("passed_only", 1, 100), ("all_runs", 2, 900)):
            with self.subTest(policy=policy), _epoch_benchmark_case(policy) as root:
                original = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
                with redirect_stderr(io.StringIO()):
                    aggregate_benchmark(root, policy)
                    export_csv(root)
                    arguments = Namespace(
                        input_dir=root, inclusion_policy=policy.replace("_", "-"),
                    )
                    self.assertEqual(cmd_report(arguments), 0)
                summary = json.loads((root / "benchmark_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["trex_identity"], TREX_IDENTITY)
                self.assertEqual((summary["passed_runs"], summary["failed_runs"]), (1, 1))
                transitions = summary["transition_metrics"]
                self.assertEqual(transitions["total_transitions"], expected_count)
                for distribution in transitions["aggregate"]["boundary_ack_gate_ns"].values():
                    self.assertEqual(distribution["count"], expected_count)
                    self.assertEqual(distribution["min"], 100)
                    self.assertEqual(distribution["max"], maximum)
                merged = [
                    json.loads(line)
                    for line in (root / "merged_transitions.jsonl").read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual([row["_run"] for row in merged], ["run_001", "run_002"])
                for row in merged:
                    run_name = row.pop("_run")
                    validate_transition_metric_record(row)
                    self.assertEqual(row, json.loads((root / run_name / "transition_metrics.jsonl").read_text()))
                for name in ("benchmark_scenario_raw.csv", "benchmark_transitions_raw.csv"):
                    with (root / "artifacts" / name).open(encoding="utf-8", newline="") as stream:
                        self.assertEqual(len(list(csv.DictReader(stream))), expected_count)
                for name in ("benchmark_scenario.csv", "benchmark_transitions.csv"):
                    with (root / name).open(encoding="utf-8", newline="") as stream:
                        rows = list(csv.DictReader(stream))
                    self.assertTrue(rows)
                    self.assertTrue(all(int(row["count"]) == expected_count for row in rows))
                figures = root / "artifacts" / "figures"
                expected_figures = {
                    "boundary_ack_gate_ns_by_type_000.svg",
                    "boundary_ack_gate_ns_by_type_001.svg",
                }
                if expected_count > 1:
                    expected_figures.add("boundary_ack_gate_ns_cdf.svg")
                self.assertEqual({path.name for path in figures.iterdir()}, expected_figures)
                self.assertEqual(
                    {path.name for path in (root / "artifacts" / "tables").iterdir()},
                    {
                        "ordered_cut_boundary_proof.md", "scenario_traffic.md",
                        "boundary_ack_gate_000.md", "boundary_ack_gate_001.md",
                    },
                )
                for path, contents in original.items():
                    self.assertEqual(path.read_bytes(), contents)

    def test_run_annotation_in_source_artifacts_rejects_before_publication(self):
        """Even an excluded failed run cannot inject merged-ledger metadata into a raw artifact."""
        for name in ("test_results.json", "transition_metrics.jsonl"):
            with self.subTest(artifact=name), _epoch_benchmark_case("passed_only") as root:
                path = root / "run_002" / name
                value = json.loads(path.read_text(encoding="utf-8"))
                value["_run"] = "run_002"
                path.write_text(json.dumps(value, allow_nan=False) + "\n", encoding="utf-8")
                with redirect_stderr(io.StringIO()), self.assertRaisesRegex(JsonContractError, "membership"):
                    aggregate_benchmark(root)
                self.assertFalse((root / "merged_transitions.jsonl").exists())
                self.assertFalse((root / "benchmark_summary.json").exists())


class TestTransitionSummaryPerType(unittest.TestCase):
    """Validate per-type aggregation in transition_summary.json."""

    def test_summary_has_per_type_key(self):
        """Summary should include the per-type aggregation object."""
        with _metrics_case() as (orch, output_dir):
            _write_summary_quietly(orch)

            summary = json.loads((output_dir / "transition_summary.json").read_text(encoding="utf-8"))
        self.assertIn("per_type", summary)

    def test_transition_record_requires_positive_dp_ingress(self):
        """Transition ingress must be positive and uint64-representable."""
        record = _make_record(TransitionType.EPOCH, 1, 2, ack_gate_ns=300)
        record["rx_packets_delta"] = 0

        with self.assertRaisesRegex(JsonContractError, "below its minimum"):
            validate_transition_metric_record(record)

        record["rx_packets_delta"] = 1 << 64
        with self.assertRaisesRegex(JsonContractError, "exceeds its maximum"):
            validate_transition_metric_record(record)

    def test_transition_counters_preserve_their_actual_observation_window(self):
        """A late rollback observer names its earlier baseline without fabricating candidate-only counters."""
        record = _make_record(TransitionType.GUARDRAILS_ROLLBACK, 2, 3, ack_gate_ns=300)
        before = record["counter_observations"]["before"]
        before["active_epoch"] = 1
        before["snapshot_id"] = "baseline"
        before["workers"][0]["observation_epoch"] = 1
        validate_transition_metric_record(record)
        record["counter_observations"]["after"]["workers"][0]["publication_generation"] = 1
        with self.assertRaisesRegex(JsonContractError, "changed without publication"):
            validate_transition_metric_record(record)

    def test_transition_counter_population_and_totals_are_required(self):
        """Missing workers and deltas disconnected from their source endpoints fail admission."""
        record = _make_record(TransitionType.EPOCH, 1, 2, ack_gate_ns=300)
        record["counter_observations"]["expected_workers"] = 2
        with self.assertRaisesRegex(JsonContractError, "exact worker population"):
            validate_transition_metric_record(record)
        record["counter_observations"]["expected_workers"] = 1
        record["rx_packets_delta"] = 999
        with self.assertRaisesRegex(JsonContractError, "contradicts its source observations"):
            validate_transition_metric_record(record)

    def test_epoch_success_requires_both_traffic_generations_and_ordering(self):
        """Boolean success cannot replace exact traffic or content identity."""
        artifact = _epoch_test_result_artifact()
        validate_test_suite_result(artifact)

        for mutation in (
            {"initial_generation_sent": 0, "next_generation_sent": 100},
            {
                "initial_generation_received": 51,
                "next_generation_received": 49,
            },
            {"generation_tag_transition_seq": -1},
            {"boundary_ordering_validated": False},
            {"transitions_observed": 0},
        ):
            with self.subTest(mutation=mutation):
                malformed = copy.deepcopy(artifact)
                malformed["epoch_test"].update(mutation)
                with self.assertRaisesRegex(JsonContractError, "contradictory"):
                    validate_test_suite_result(malformed)

        packet = _as_trex_latency_unavailable(_packet_test_result_artifact())
        validate_test_suite_result(packet)
        for received, loss in ((0, 100.0), (2, 0.0)):
            malformed = copy.deepcopy(packet)
            malformed["packet_tests"][0].update(rx_count=received, loss_pct=loss)
            with self.subTest(received=received), self.assertRaisesRegex(
                JsonContractError, "packet successful traffic population is incomplete"
            ):
                validate_test_suite_result(malformed)

        commit = _commit_confirmed_result_artifact()
        validate_test_suite_result(commit)
        for survival in (
            {"confirmed_survived_deadline": False, "confirmed_survival_elapsed_ms": 0},
            {"confirmed_survival_elapsed_ms": 999},
            {"confirmed_survival_elapsed_ms": 31000},
        ):
            malformed = copy.deepcopy(commit)
            malformed["commit_confirmed_test"].update(survival)
            with self.subTest(survival=survival), self.assertRaises(JsonContractError):
                validate_test_suite_result(malformed)
        malformed = copy.deepcopy(commit)
        del malformed["commit_confirmed_test"]["confirmed_survived_deadline"]
        with self.assertRaises(JsonContractError):
            validate_test_suite_result(malformed)
        commit_result = require_object(
            commit["commit_confirmed_test"], "commit-confirmed fixture"
        )
        commit_result.update({"timeout_rollback_snapshot_id": "foreign"})
        with self.assertRaisesRegex(JsonContractError, "incomplete"):
            validate_test_suite_result(commit)

        rollback = _rollback_result_artifact()
        validate_test_suite_result(rollback)
        rollback_result = require_object(
            rollback["rollback_test"], "rollback fixture"
        )
        rollback_result.update({"selective_rollback_modules": ["kinetum.nat44"]})
        with self.assertRaisesRegex(JsonContractError, "incomplete"):
            validate_test_suite_result(rollback)

        guardrails_result = {
            "passed": True,
            "duration_s": 30.0,
            "policy_configured": True,
            "baseline_snapshot_id": "baseline",
            "candidate_snapshot_id": "candidate",
            "rollback_snapshot_id": "baseline",
            "candidate_epoch": 2,
            "rollback_epoch": 3,
            "protocol_faults_observed": 0,
            "message": "exact",
        }
        guardrails = _single_scenario_result_artifact(
            "guardrails", "guardrails_test", guardrails_result
        )
        validate_test_suite_result(guardrails)
        guardrails_result["candidate_snapshot_id"] = "baseline"
        with self.assertRaisesRegex(JsonContractError, "incomplete"):
            validate_test_suite_result(guardrails)

    def test_latency_availability_is_source_qualified_and_never_zero_filled(self):
        """Latency requires received packets and the profile's owned measurement source."""
        native_artifacts = {
            "packet": _packet_test_result_artifact(),
            "epoch": _epoch_test_result_artifact(),
            "commit_confirmed": _commit_confirmed_result_artifact(),
            "rollback": _rollback_result_artifact(),
        }
        trex_artifacts = {}
        for identity, native in native_artifacts.items():
            with self.subTest(identity=identity, source="native"):
                validate_test_suite_result(native)
                for unavailable in (None, 0.0):
                    malformed = copy.deepcopy(native)
                    for row in _result_latency_rows(malformed):
                        row["avg_latency_us"] = unavailable
                    with self.assertRaises(JsonContractError):
                        validate_test_suite_result(malformed)

            trex = _as_trex_latency_unavailable(native)
            trex_artifacts[identity] = trex
            with self.subTest(identity=identity, source="trex"):
                validate_test_suite_result(trex)
                fabricated = copy.deepcopy(trex)
                for row in _result_latency_rows(fabricated):
                    row["avg_latency_us"] = 0.01
                with self.assertRaisesRegex(
                    JsonContractError, "no owned measurement"
                ):
                    validate_test_suite_result(fabricated)

        native = native_artifacts["epoch"]
        trex = trex_artifacts["epoch"]
        failed_native = copy.deepcopy(native_artifacts["packet"])
        failed_native["packet_tests"][0].update({
            "passed": False,
            "avg_latency_us": None,
        })
        failed_native.update({
            "all_passed": False,
            "passed_tests": 1,
            "failed_tests": 1,
        })
        validate_test_suite_result(failed_native)
        failed_packet = failed_native["packet_tests"][0]
        failed_packet.update(rx_count=0, loss_pct=100.0, avg_latency_us=1.0)
        with self.assertRaisesRegex(JsonContractError, "packet latency has no received population"):
            validate_test_suite_result(failed_native)
        failed_packet["avg_latency_us"] = None
        validate_test_suite_result(failed_native)

        native_metrics = _compute_scenario_metrics([native])
        trex_metrics = _compute_scenario_metrics([trex])
        self.assertIn("avg_latency_us", native_metrics["epoch_test"])
        self.assertNotIn("avg_latency_us", trex_metrics["epoch_test"])

        trex_summary = _epoch_benchmark_summary()
        trex_summary["scenario"].update({
            "deployment": "fan_in_edge_gateway",
            "backend": "dpdk_pci",
            "traffic_driver": "trex",
            "traffic_host": "trex.example",
            "latency_source": None,
        })
        trex_summary["trex_identity"] = copy.deepcopy(TREX_IDENTITY)
        del trex_summary["scenario_metrics"]["epoch_test"]["avg_latency_us"]
        validate_benchmark_summary(trex_summary)
        missing_identity = copy.deepcopy(trex_summary)
        missing_identity["trex_identity"] = None
        with self.assertRaisesRegex(JsonContractError, "TRex identity is missing"):
            validate_benchmark_summary(missing_identity)
        trex_summary["scenario_metrics"]["epoch_test"][
            "avg_latency_us"
        ] = _distribution(1)
        with self.assertRaises(JsonContractError):
            validate_benchmark_summary(trex_summary)

    def test_successful_results_require_positive_measured_extent(self):
        """A successful result cannot carry zero duration or throughput."""
        packet = _packet_test_result_artifact()
        for field in ("duration_s", "throughput_pps"):
            malformed = copy.deepcopy(packet)
            malformed["packet_tests"][0][field] = 0.0
            with self.subTest(field=field), self.assertRaises(JsonContractError):
                validate_test_suite_result(malformed)

        scenario_artifacts = (
            (_epoch_test_result_artifact(), "epoch_test"),
            (_commit_confirmed_result_artifact(), "commit_confirmed_test"),
            (_rollback_result_artifact(), "rollback_test"),
        )
        for artifact, field in scenario_artifacts:
            malformed = copy.deepcopy(artifact)
            malformed[field]["duration_s"] = 0.0
            with self.subTest(field=field), self.assertRaisesRegex(
                JsonContractError, "positive duration"
            ):
                validate_test_suite_result(malformed)

        manifest = _epoch_benchmark_manifest()
        manifest["results"]["runs"][0]["duration_s"] = 0.0
        with self.assertRaises(JsonContractError):
            validate_benchmark_manifest(manifest, completed=True)

    def test_console_reads_only_the_validated_latency_cache(self):
        """Console output consumes cached evidence and prints unavailable truth."""
        analysis = AnalysisResult(total_rx=1, valid=1, tag_counts={0: 1})
        native = ValidationOrchestrator(ValidationConfig(process=TEST_PROCESS_CONFIG))
        with self.assertRaisesRegex(RuntimeError, "omitted latency"):
            native.scenario_context().measured_average_latency(analysis)  # pylint: disable=protected-access

        pci_profile = DEPLOYMENT_SPECS[
            DeploymentMode.FAN_IN_EDGE_GATEWAY
        ].backend_profile(BackendType.DPDK_PCI)
        trex = ValidationOrchestrator(
            ValidationConfig(
                process=TEST_PROCESS_CONFIG,
                backend=BackendConfig(
                    backend_type=BackendType.DPDK_PCI,
                    ports=pci_profile.ports,
                )
            )
        )
        unavailable_latency = trex.scenario_context().measured_average_latency(analysis)
        unavailable_output = io.StringIO()
        with redirect_stderr(unavailable_output):
            ConsoleReporter(color=False).print_test_result(
                ValidationResult(
                    packet_size=64, passed=True, tx_count=1, rx_count=1, loss_pct=0.0,
                    avg_latency_us=unavailable_latency, throughput_pps=1.0, duration_s=1.0,
                )
            )
        self.assertIn("Latency:    unavailable", unavailable_output.getvalue())

        evidence = dict.fromkeys(("avg", "min", "max", "p50", "p99"), 10.0)
        analysis.set_latency_stats(evidence)
        borrowed = analysis.latency_stats()
        self.assertIsNotNone(borrowed)
        borrowed["avg"] = 999.0
        measured_latency = native.scenario_context().measured_average_latency(analysis)
        measured_output = io.StringIO()
        with redirect_stderr(measured_output):
            ConsoleReporter(color=False).print_test_result(
                ValidationResult(
                    packet_size=64, passed=True, tx_count=1, rx_count=1, loss_pct=0.0,
                    avg_latency_us=measured_latency, throughput_pps=1.0, duration_s=1.0,
                )
            )
        self.assertIn("Latency:    10.0us", measured_output.getvalue())
        with self.assertRaisesRegex(ValueError, "valid publication"):
            analysis.set_latency_stats(evidence)

    def test_benchmark_identity_rejects_dry_run_results(self):
        """A setup-only run cannot enter benchmark evidence."""
        dry_run = _epoch_test_result_artifact()
        dry_run.update({
            "dry_run": True,
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "epoch_test": None,
        })

        with self.assertRaisesRegex(JsonContractError, "cannot be a dry run"):
            validate_benchmark_result_identity(
                dry_run, _epoch_benchmark_manifest()
            )

    def test_per_type_counts(self):
        """Per-type counts should reflect only records of that transition type."""
        with _metrics_case() as (orch, output_dir):
            _write_summary_quietly(orch)

            summary = json.loads((output_dir / "transition_summary.json").read_text(encoding="utf-8"))
        per_type = summary["per_type"]

        self.assertEqual(per_type["epoch"]["count"], 1)
        self.assertEqual(per_type["rollback_apply_v1"]["count"], 2)
        self.assertEqual(per_type["rollback_full"]["count"], 1)
        self.assertEqual(
            per_type["commit_confirmed_timeout_rollback"]["count"], 1
        )
        self.assertNotIn("commit_confirmed", per_type)  # not in test data

        with _metrics_case() as (orch, output_dir):
            metrics_file = output_dir / "transition_metrics.jsonl"
            records = [
                json.loads(line)
                for line in metrics_file.read_text(encoding="utf-8").splitlines()
            ]
            aggregate = _compute_transition_metrics(records)
            self.assertEqual(aggregate["per_type"]["epoch"]["count"], 1)
            records[1]["protocol_fault_deltas"] = {}
            metrics_file.write_text(
                "".join(f"{json.dumps(record)}\n" for record in records),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "membership"):
                _write_summary_quietly(orch)
            with self.assertRaisesRegex(ValueError, "protocol-fault"):
                _compute_transition_metrics(records)

        with _metrics_case() as (orch, output_dir):
            metrics_file = output_dir / "transition_metrics.jsonl"
            records = [
                json.loads(line)
                for line in metrics_file.read_text(encoding="utf-8").splitlines()
            ]
            records[1]["boundary_epoch_stats"][0]["boundary_index"] = 7
            metrics_file.write_text(
                "".join(f"{json.dumps(record)}\n" for record in records),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "membership"):
                _write_summary_quietly(orch)
            with self.assertRaisesRegex(ValueError, "membership"):
                _compute_transition_metrics(records)

    def test_global_transition_count(self):
        """Global transition count should include every JSONL record."""
        with _metrics_case() as (orch, output_dir):
            _write_summary_quietly(orch)

            summary = json.loads((output_dir / "transition_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["transition_count"], 5)

    def test_per_type_ack_gate_distribution(self):
        """ACK-gate distributions should be computed independently per type."""
        with _metrics_case() as (orch, output_dir):
            _write_summary_quietly(orch)

            summary = json.loads((output_dir / "transition_summary.json").read_text(encoding="utf-8"))
        per_type = summary["per_type"]

        # epoch: single value 300
        epoch_dist = per_type["epoch"]["boundary_ack_gate_ns"]["region_0->region_1"]
        self.assertEqual(epoch_dist["min"], 300)
        self.assertEqual(epoch_dist["max"], 300)
        self.assertEqual(epoch_dist["count"], 1)

        # rollback_apply_v1: values [100, 500]
        rb_dist = per_type["rollback_apply_v1"]["boundary_ack_gate_ns"]["region_0->region_1"]
        self.assertEqual(rb_dist["min"], 100)
        self.assertEqual(rb_dist["max"], 500)
        self.assertEqual(rb_dist["count"], 2)

    def test_per_type_region_fanout_overflow(self):
        """Region fan-out overflow should be grouped by transition type."""
        with _metrics_case() as (orch, output_dir):
            _write_summary_quietly(orch)

            summary = json.loads((output_dir / "transition_summary.json").read_text(encoding="utf-8"))
        per_type = summary["per_type"]

        # rollback_apply_v1 region 0: drops [0, 2]
        rb_drops = per_type["rollback_apply_v1"]["region_fanout_overflow"]["0"]
        self.assertEqual(rb_drops["min"], 0)
        self.assertEqual(rb_drops["max"], 2)

        # epoch region 0: drops [0]
        epoch_drops = per_type["epoch"]["region_fanout_overflow"]["0"]
        self.assertEqual(epoch_drops["min"], 0)
        self.assertEqual(epoch_drops["max"], 0)

    def test_global_distribution_covers_all_types(self):
        """Global distributions should cover all transition records."""
        with _metrics_case() as (orch, output_dir):
            _write_summary_quietly(orch)

            summary = json.loads((output_dir / "transition_summary.json").read_text(encoding="utf-8"))

        # Global ACK-gate timing covers all 5 records: [100, 200, 300, 400, 500].
        global_dist = summary["boundary_ack_gate_ns"]["region_0->region_1"]
        self.assertEqual(global_dist["min"], 100)
        self.assertEqual(global_dist["max"], 500)
        self.assertEqual(global_dist["count"], 5)

    def test_empty_jsonl_produces_no_summary(self):
        """No records means no summary file is written."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            config = ValidationConfig(process=TEST_PROCESS_CONFIG, output_dir=output_dir)
            orch = ValidationOrchestrator(config)

            # Write empty file
            (output_dir / "transition_metrics.jsonl").write_text("", encoding="utf-8")
            _write_summary_quietly(orch)

            self.assertFalse((output_dir / "transition_summary.json").exists())

    def test_missing_jsonl_produces_no_summary(self):
        """Absence emits no summary, while an indirect input fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            config = ValidationConfig(process=TEST_PROCESS_CONFIG, output_dir=output_dir)
            orch = ValidationOrchestrator(config)

            _write_summary_quietly(orch)

            self.assertFalse((output_dir / "transition_summary.json").exists())

            metrics_file = output_dir / "transition_metrics.jsonl"
            metrics_file.symlink_to(output_dir / "missing-transition-metrics")
            with self.assertRaisesRegex(ValueError, "indirect"):
                _write_summary_quietly(orch)

    def test_benchmark_rejects_mixing_two_valid_storage_profiles(self):
        """Shared and per-queue PCI runs remain distinct benchmark identities."""
        summary = _epoch_benchmark_summary()
        summary["scenario"].update(
            deployment="fan_in_edge_gateway", backend="dpdk_pci",
            traffic_driver="trex", latency_source=None, traffic_host="traffic-host",
        )
        summary["scenario_metrics"]["epoch_test"].pop("avg_latency_us")
        summary["trex_identity"] = copy.deepcopy(TREX_IDENTITY)
        manifest = _epoch_benchmark_manifest()
        manifest["scenario"] = copy.deepcopy(summary["scenario"])
        validate_benchmark_summary_identity(summary, manifest)

        summary["scenario"]["storage_profile"] = "per_rx_queue"
        validate_benchmark_summary(summary)
        with self.assertRaisesRegex(JsonContractError, "identity disagrees"):
            validate_benchmark_summary_identity(summary, manifest)
        manifest["scenario"]["storage_profile"] = "per_rx_queue"
        validate_benchmark_summary_identity(summary, manifest)

    def test_benchmark_capability_ports_match_default_and_overridden_endpoints(self):
        """Valid capability rows for a missing or foreign port cannot enter a report."""
        summary = _epoch_benchmark_summary()
        summary["scenario"].update(
            deployment="fan_in_edge_gateway", backend="dpdk_pci",
            traffic_driver="trex", latency_source=None, traffic_host="traffic-host",
        )
        summary["scenario_metrics"]["epoch_test"].pop("avg_latency_us")
        for override, expected in (([], (0, 1, 2)), ([5, 7, 6], (5, 6, 7))):
            with self.subTest(override=override):
                summary["scenario"]["trex_ports"] = override
                summary["trex_identity"] = complete_trex_identity(ports=expected)
                validate_benchmark_summary(summary)
                for invalid in (expected[:-1], (*expected, 9), (*expected[:-1], 9)):
                    summary["trex_identity"] = complete_trex_identity(ports=invalid)
                    with self.assertRaisesRegex(JsonContractError, "foreign port membership"):
                        validate_benchmark_summary(summary)

    def test_benchmark_summary_is_bound_to_exact_scenario_and_run_population(self):
        """Aggregate validation must reject cross-scenario or invented samples."""
        summary = _epoch_benchmark_summary()
        validate_benchmark_summary(summary)
        manifest = _epoch_benchmark_manifest()
        validate_benchmark_summary_identity(summary, manifest)
        for kit_root in ("/opt/kinetum", "/opt/kinetum/kit", "/opt"):
            malformed = copy.deepcopy(manifest)
            malformed["config"]["validation_root"] = kit_root
            with self.assertRaisesRegex(JsonContractError, "roots overlap"):
                validate_benchmark_manifest(malformed, completed=True)

        summary["inclusion_policy"] = "all_runs"
        with self.assertRaisesRegex(JsonContractError, "terminal manifest"):
            validate_benchmark_summary_identity(summary, manifest)

        selected_runs = {
            "run_001": {"all_passed": True, "setup_failed": False},
            "run_002": {"all_passed": True, "setup_failed": False},
        }
        identities = {
            "run_001": copy.deepcopy(TREX_IDENTITY),
            "run_002": copy.deepcopy(TREX_IDENTITY),
        }
        self.assertEqual(
            _selected_trex_identity(selected_runs, identities, False, "trex"),
            TREX_IDENTITY,
        )
        identities["run_002"] = complete_trex_identity(version="v3.07")
        with self.assertRaisesRegex(ValueError, "different TRex identities"):
            _selected_trex_identity(selected_runs, identities, False, "trex")
        identities["run_002"] = complete_trex_identity(counters=256, filter_mode="fetch all")
        with self.assertRaisesRegex(ValueError, "different TRex identities"):
            _selected_trex_identity(selected_runs, identities, False, "trex")
        self.assertIsNone(
            _selected_trex_identity(
                {"run_001": {"all_passed": False, "setup_failed": True}},
                {},
                True,
                "trex",
            )
        )

        with tempfile.TemporaryDirectory() as temporary:
            benchmark_root = Path(temporary).resolve()
            manifest = _epoch_benchmark_manifest()
            manifest["results"] = {
                "total_runs": 1,
                "passed_runs": 0,
                "failed_runs": 1,
                "runs": [
                    {
                        "run_id": 1,
                        "passed": False,
                        "duration_s": 60.0,
                        "error": "run failed before result publication",
                    }
                ],
            }
            (benchmark_root / "manifest.json").write_text(
                json.dumps(manifest, allow_nan=False) + "\n",
                encoding="utf-8",
            )
            run_root = benchmark_root / "run_001"
            run_root.mkdir()
            (run_root / "test_results.json").symlink_to(
                run_root / "missing-test-results"
            )
            with redirect_stderr(io.StringIO()), self.assertRaisesRegex(
                ValueError, "test results are indirect"
            ):
                aggregate_benchmark(benchmark_root)
            self.assertFalse(
                (benchmark_root / "merged_transitions.jsonl").exists()
            )
            self.assertFalse((benchmark_root / "benchmark_summary.json").exists())

        reversed_time = _epoch_benchmark_manifest()
        reversed_time["completed"] = "2026-09-03T11:59:59+00:00"
        with self.assertRaisesRegex(JsonContractError, "precedes"):
            validate_benchmark_manifest(reversed_time, completed=True)

        summary = _epoch_benchmark_summary()
        summary["scenario"]["test_type"] = "standard"
        with self.assertRaises(JsonContractError):
            validate_benchmark_summary(summary)

        summary = _epoch_benchmark_summary()
        summary["transition_metrics"]["per_type"]["epoch"]["count"] = 2
        with self.assertRaisesRegex(JsonContractError, "sample population"):
            validate_benchmark_summary(summary)

        with self.assertRaisesRegex(JsonContractError, "partial transition"):
            validate_benchmark_transition_multiset(
                ["epoch", "epoch"], "epoch", complete=False
            )

        summary = _epoch_benchmark_summary()
        summary.update({
            "passed_runs": 0,
            "failed_runs": 1,
            "failed_run_ids": ["run_001"],
            "failure_reasons": {"run_001": "summary failure"},
            "scenario_metrics": {},
            "transition_metrics": {},
        })
        manifest = _epoch_benchmark_manifest()
        manifest["results"] = {
            "total_runs": 1,
            "passed_runs": 0,
            "failed_runs": 1,
            "runs": [
                {
                    "run_id": 1,
                    "passed": False,
                    "duration_s": 60.0,
                    "error": "manifest failure",
                }
            ],
        }
        with self.assertRaisesRegex(JsonContractError, "terminal manifest"):
            validate_benchmark_summary_identity(summary, manifest)
