"""
Tests for RunArtifacts.write_transition_summary per-type aggregation.

Validates that transition_summary.json correctly groups metrics by
transition_type and computes independent distributions for each type.

Run:
    python3 -B -m pytest -v validation/tests/test_transition_summary.py
"""

import json
import io
import copy
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

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
from kinetum_validation.config.types import (
    AnalysisResult,
    BackendConfig,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    ProcessConfig,
    TestConfig as ValidationConfig,
    TestResult as ValidationResult,
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


TREX_IDENTITY = {"version": "v3.06", "mode": "STL"}
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

        packet = _packet_test_result_artifact()
        validate_test_suite_result(packet)
        packet["packet_tests"][0].update({"rx_count": 0, "loss_pct": 100.0})
        with self.assertRaisesRegex(JsonContractError, "contradictory"):
            validate_test_suite_result(packet)

        commit = _commit_confirmed_result_artifact()
        validate_test_suite_result(commit)
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
        """Native latency is positive while TRex latency stays unavailable."""
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
        trex_summary["trex_identity"] = dict(TREX_IDENTITY)
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
                ValidationResult(packet_size=64, passed=True, avg_latency_us=unavailable_latency)
            )
        self.assertIn("Latency:    unavailable", unavailable_output.getvalue())

        evidence = {
            "avg": 10.0,
            "min": 5.0,
            "max": 20.0,
            "p50": 9.0,
            "p99": 19.0,
        }
        analysis.set_latency_stats(evidence)
        borrowed = analysis.latency_stats()
        self.assertIsNotNone(borrowed)
        borrowed["avg"] = 999.0
        measured_latency = native.scenario_context().measured_average_latency(analysis)
        measured_output = io.StringIO()
        with redirect_stderr(measured_output):
            ConsoleReporter(color=False).print_test_result(
                ValidationResult(packet_size=64, passed=True, avg_latency_us=measured_latency)
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
        summary["trex_identity"] = dict(TREX_IDENTITY)
        manifest = _epoch_benchmark_manifest()
        manifest["scenario"] = copy.deepcopy(summary["scenario"])
        validate_benchmark_summary_identity(summary, manifest)

        summary["scenario"]["storage_profile"] = "per_rx_queue"
        validate_benchmark_summary(summary)
        with self.assertRaisesRegex(JsonContractError, "identity disagrees"):
            validate_benchmark_summary_identity(summary, manifest)
        manifest["scenario"]["storage_profile"] = "per_rx_queue"
        validate_benchmark_summary_identity(summary, manifest)

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

        selected_runs = [
            {"_run": "run_001", "all_passed": True, "setup_failed": False},
            {"_run": "run_002", "all_passed": True, "setup_failed": False},
        ]
        identities = {
            "run_001": dict(TREX_IDENTITY),
            "run_002": dict(TREX_IDENTITY),
        }
        self.assertEqual(
            _selected_trex_identity(selected_runs, identities, False, "trex"),
            TREX_IDENTITY,
        )
        identities["run_002"] = {"version": "v3.07", "mode": "STL"}
        with self.assertRaisesRegex(ValueError, "different TRex identities"):
            _selected_trex_identity(selected_runs, identities, False, "trex")
        self.assertIsNone(
            _selected_trex_identity(
                [{"_run": "run_001", "all_passed": False, "setup_failed": True}],
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
