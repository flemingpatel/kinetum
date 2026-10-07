"""
Tests for TRex traffic-driver local behavior.

These tests do not require a TRex endpoint. They validate local admission,
stats-backed analysis, and fail-closed generation-tag handling so live runs do
not silently produce misleading artifacts.
"""

import asyncio
import ast
import contextlib
import copy
import inspect
import json
import os
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from functools import partial
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

from kinetum_validation.config.types import (
    BackendConfig,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    PacketConfig,
    ProcessConfig,
    StatsValidationResult,
    TestConfig as ValidationConfig,
    TestType as ValidationTestType,
    TrafficEndpointConfig,
)
from kinetum_validation.orchestrator import TestOrchestrator as ValidationOrchestrator
from kinetum_validation.scenario_context import ScenarioContext

from kinetum_validation.engine.json_contract import JsonContractError
from kinetum_validation.process.kinetumctl import KinetumCtl
from kinetum_validation.process.telemetry import StatsResult
from kinetum_validation.traffic import trex as trex_module
from kinetum_validation.traffic.trex import TRexTrafficDriver


TREX_IDENTITY = {"version": "v3.06", "mode": "STL"}
PORT_COUNTER_BASELINE = {
    "0": {"opackets": 100000, "ipackets": 8, "oerrors": 3, "ierrors": 1},
    "1": {"opackets": 200000, "ipackets": 9, "oerrors": 4, "ierrors": 2},
    "2": {"opackets": 4, "ipackets": 300000, "oerrors": 1, "ierrors": 5},
}


def _port_counter_final(wan0_tx: int, wan1_tx: int, lan0_rx: int) -> dict:
    """Build explicit final port observations while preserving historical errors."""
    counters = copy.deepcopy(PORT_COUNTER_BASELINE)
    counters["0"]["opackets"] += wan0_tx
    counters["1"]["opackets"] += wan1_tx
    counters["2"]["ipackets"] += lan0_rx
    return counters


def _trex_config() -> ValidationConfig:
    """Build a PCI/TRex TestConfig without contacting a traffic endpoint."""
    profile = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(
        BackendType.DPDK_PCI
    )
    resolved_ports = (
        replace(
            profile.ports[0],
            runtime_direction="rx",
            runtime_mac="3c:fd:fe:05:c4:80",
        ),
        replace(
            profile.ports[1],
            runtime_direction="rx",
            runtime_mac="3c:fd:fe:05:c4:84",
        ),
        replace(
            profile.ports[2],
            runtime_direction="tx",
            runtime_mac="3c:fd:fe:05:c4:82",
        ),
    )
    return ValidationConfig(
        process=ProcessConfig(
            runtime_root=Path("/opt/kinetum"),
            validation_root=Path("/var/tmp/kinetum-validation"),
        ),
        deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
        backend=BackendConfig(
            backend_type=BackendType.DPDK_PCI,
            ports=resolved_ports,
        ),
        traffic=TrafficEndpointConfig(
            host="trex.example",
            work_dir="/tmp/kinetum_trex_unit",
        ),
    )


def _remote_helper(name, *dependencies):
    """Compile an endpoint helper and its named function dependencies without endpoint effects."""
    def fail(message, code):
        """Convert endpoint fail-stop into a local test exception."""
        raise RuntimeError(f"{code}: {message}")

    module = ast.parse(trex_module._REMOTE_TREX_SCRIPT)  # pylint: disable=protected-access
    functions = {
        node.name: node for node in module.body if isinstance(node, ast.FunctionDef)
    }
    namespace = {"fail": fail}
    helper_module = ast.Module(
        body=[functions[dependency] for dependency in (*dependencies, name)],
        type_ignores=[],
    )
    exec(  # pylint: disable=exec-used
        compile(helper_module, "<remote_trex_helper>", "exec"),
        namespace,
    )
    return namespace[name]


def _remote_action_execution(action: str) -> str:
    """Return the sole client-owning execution block for one remote action."""
    script = trex_module._REMOTE_TREX_SCRIPT  # pylint: disable=protected-access
    module = ast.parse(script)
    if action == "run":
        for node in module.body:
            if not isinstance(node, ast.Try):
                continue
            for index, statement in enumerate(node.body):
                if isinstance(statement, ast.If) and ast.unparse(statement.test) == "action != 'run'":
                    return ast.unparse(ast.Module(body=node.body[index + 1:], type_ignores=[]))
        raise AssertionError("ordinary remote run has no execution owner")
    matches = []
    for node in ast.walk(module):
        if not isinstance(node, ast.If):
            continue
        comparison = node.test
        if not (
            isinstance(comparison, ast.Compare)
            and isinstance(comparison.left, ast.Name)
            and comparison.left.id == "action"
            and len(comparison.ops) == 1
            and isinstance(comparison.ops[0], ast.Eq)
            and len(comparison.comparators) == 1
            and isinstance(comparison.comparators[0], ast.Constant)
            and comparison.comparators[0].value == action
        ):
            continue
        segment = ast.get_source_segment(script, node)
        if segment is not None and "client." in segment:
            matches.append(segment)
    if len(matches) != 1:
        raise AssertionError(f"remote action {action} has no sole execution owner")
    return matches[0]


def _execute_remote_action(client, spec, monotonic, wall_time):
    """Execute the owned endpoint action against supplied TRex observations."""
    def fail(message, code=1):
        """Reject endpoint failures instead of allowing execution to continue."""
        raise RuntimeError(f"{code}: {message}")

    script = trex_module._REMOTE_TREX_SCRIPT  # pylint: disable=protected-access
    functions = ast.Module(
        body=[node for node in ast.parse(script).body if isinstance(node, ast.FunctionDef)],
        type_ignores=[],
    )
    namespace = {
        "contextlib": contextlib,
        "sys": sys,
        "os": os,
        "time": MagicMock(),
        "client": client,
        "spec": spec,
        "action": spec["action"],
        "ports": spec["ports"],
        "egress_ports": spec["egress_ports"],
        "ingress_streams": spec["ingress_streams"],
        "promisc_ports": [],
    }
    exec(compile(functions, "<remote_trex_functions>", "exec"), namespace)  # pylint: disable=exec-used
    namespace["time"].monotonic.return_value = monotonic
    namespace["time"].time.return_value = wall_time
    namespace["emit"] = MagicMock()
    namespace["fail"] = fail
    namespace["build_generation_stream"] = MagicMock()
    namespace["build_stream"] = MagicMock()
    exec(_remote_action_execution(spec["action"]), namespace)  # pylint: disable=exec-used
    return namespace["emit"].call_args.args[0]


def _counter_client(counters, stats):
    """Model refreshed absolute PortStats separately from client-relative rows."""
    client = MagicMock()
    ports = {}
    for port_text, row in counters.items():
        port = MagicMock()
        port.get_stats.return_value.get.side_effect = row.__getitem__
        ports[int(port_text)] = port
    client.get_port.side_effect = ports.__getitem__
    client.get_stats.return_value = stats
    client.add_streams.return_value = [1, 2]
    return client


async def _analyze_stats_run(
    driver: TRexTrafficDriver,
    pcap_file: Path,
    expected_count: int,
    raw: dict,
):
    """
    Drive one exact stats-backed capture window through analysis.

    Returns
    -------
    AnalysisResult
        Normalized traffic evidence returned by the production driver path.
    """
    await driver.start_capture(pcap_file, "udp")
    driver._trex_identity = dict(TREX_IDENTITY)  # pylint: disable=protected-access
    raw["trex_identity"] = dict(TREX_IDENTITY)
    driver._last_run = raw  # pylint: disable=protected-access
    await driver.stop_capture()
    return await driver.analyze_capture(
        pcap_file=pcap_file,
        expected_count=expected_count,
    )


class _CapturingTRexDriver(TRexTrafficDriver):
    """TRex driver test double that records remote specs."""

    def __init__(
        self,
        probe_identity=None,
        *,
        initialized: bool = True,
        probe_work_dir=None,
    ) -> None:
        """Initialize the production driver with an in-memory remote ledger."""
        super().__init__(_trex_config())
        self.specs = []
        self.cancelled = False
        self.probe_identity = (
            dict(TREX_IDENTITY)
            if probe_identity is None
            else probe_identity
        )
        self.probe_work_dir = probe_work_dir
        if initialized:
            self._trex_identity = dict(TREX_IDENTITY)  # pylint: disable=protected-access

    async def _invoke_remote(self, spec):  # pylint: disable=arguments-differ
        """Validate, record, and answer one endpoint action deterministically."""
        self._validate_remote_request(spec)  # pylint: disable=protected-access
        self.specs.append(spec)
        if spec["action"] == "probe":
            response = {
                "ok": True,
                "action": "probe",
                "ports": [0, 1, 2],
                "stats_keys": ["global"],
                "promiscuous_ports": [2],
                "work_dir": (
                    spec["work_dir"]
                    if self.probe_work_dir is None
                    else self.probe_work_dir
                ),
                "trex_identity": self.probe_identity,
            }
        elif spec["action"] == "generation_start":
            response = {
                "ok": True,
                "action": "generation_start",
                "duration_s": spec["duration_s"],
                "initial_generation_tag": spec["initial_generation_tag"],
                "next_generation_tag": spec["next_generation_tag"],
                "start_time": 1.0,
                "start_monotonic": 10.0,
                "ingress_ports": [0, 1],
                "egress_ports": [2],
                "generation_stream_ids": {
                    "0": {"initial": [1], "next": [2]},
                    "1": {"initial": [1], "next": [2]},
                },
                "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
                "generation_flow_plan": [
                    {
                        "pg_id": 1000, "generation_tag": 1,
                        "logical_name": "wan0", "port_id": 0,
                        "flow_id": 0, "role": "pre_overlap",
                        "expected_tx": 2750,
                    },
                    {
                        "pg_id": 1001, "generation_tag": 2,
                        "logical_name": "wan0", "port_id": 0,
                        "flow_id": 0, "role": "post_overlap",
                        "expected_tx": 5000,
                    },
                    {
                        "pg_id": 1002, "generation_tag": 1,
                        "logical_name": "wan1", "port_id": 1,
                        "flow_id": 0, "role": "pre_overlap",
                        "expected_tx": 2750,
                    },
                    {
                        "pg_id": 1003, "generation_tag": 2,
                        "logical_name": "wan1", "port_id": 1,
                        "flow_id": 0, "role": "post_overlap",
                        "expected_tx": 5000,
                    },
                ],
                "promiscuous_ports": [2],
                "work_dir": spec["work_dir"],
            }
        elif spec["action"] == "generation_resume_next":
            response = {
                "ok": True,
                "action": "generation_resume_next",
                "resumed_stream_ids": {"0": [2], "1": [2]},
                "next_start_time": 1.5,
                "next_start_monotonic": 15.0,
                "timestamp_source": "trex_endpoint_monotonic",
            }
        elif spec["action"] == "generation_pause_initial":
            response = {
                "ok": True,
                "action": "generation_pause_initial",
                "paused_stream_ids": {"0": [1], "1": [1]},
                "initial_pause_time": 2.0,
                "initial_pause_monotonic": 15.5,
                "timestamp_source": "trex_endpoint_monotonic",
            }
        elif spec["action"] == "generation_finish":
            generation_pgid_stats = {
                str(row["pg_id"]): {
                    key: value for key, value in row.items() if key != "pg_id"
                }
                | {
                    "tx_pkts": row["expected_tx"],
                    "rx_pkts": row["expected_tx"],
                }
                for row in spec["generation_flow_plan"]
            }
            response = {
                "ok": True,
                "action": "generation_finish",
                "tx_count": 15500,
                "rx_count": 15500,
                "errors": 0,
                "port_tx_count": 15500,
                "port_rx_count": 15500,
                "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
                "port_counter_final": _port_counter_final(7750, 7750, 15500),
                "start_time": 1.0,
                "start_monotonic": spec["start_monotonic"],
                "end_time": 16.0,
                "ingress_ports": [0, 1],
                "egress_ports": [2],
                "generation_flow_plan": spec["generation_flow_plan"],
                "generation_pgid_stats": generation_pgid_stats,
                "next_start_time": spec["next_start_time"],
                "initial_pause_time": spec["initial_pause_time"],
                "next_pause_time": 16.0,
                "next_start_monotonic": spec["next_start_monotonic"],
                "initial_pause_monotonic": spec["initial_pause_monotonic"],
                "next_pause_monotonic": 25.0,
                "promiscuous_ports": [2],
                "work_dir": spec["work_dir"],
                "generation_tag_counts": {"1": 5500, "2": 10000},
                "tag_counts": {"1": 5500, "2": 10000},
                "generation_overlap_method": "orchestrator_controlled_sustained_overlap",
                "transition_time_s_requested": spec["transition_time_s"],
                "requested_overlap_window_ms": 500,
                "overlap_window_ms_measured": 500.0,
                "overlap_window_timestamp_source": "trex_endpoint_monotonic",
                "expected_tx_count": 15500,
                "expected_tx_count_source": "measured_generation_intervals",
                "steady_state_target_pps": spec["pps"],
                "overlap_aggregate_target_pps": spec["pps"] * 2,
            }
        elif spec["action"] == "generation_abort":
            response = {"ok": True, "action": "generation_abort"}
        elif spec["action"] == "run":
            response = {
                "ok": True,
                "action": "run",
                "tx_count": 10,
                "rx_count": 9,
                "errors": 0,
                "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
                "port_counter_final": _port_counter_final(5, 5, 9),
                "start_time": 1.0,
                "end_time": 2.0,
                "ingress_ports": [0, 1],
                "egress_ports": [2],
                "promiscuous_ports": [2],
                "work_dir": spec["work_dir"],
                "generation_tag_counts": {str(spec["generation_tag"]): 10},
                "tag_counts": {str(spec["generation_tag"]): 9},
            }
        else:
            raise RuntimeError("test TRex action is undeclared")

        expected_keys = trex_module._REMOTE_SUCCESS_KEYS[  # pylint: disable=protected-access
            spec["action"]
        ]
        if set(response) != expected_keys:
            raise RuntimeError("test TRex response field membership is inexact")
        self._validate_remote_success(  # pylint: disable=protected-access
            response, spec["action"], spec
        )
        return response

    def cancel_remote_action(self) -> None:
        """Record cancellation without constructing a remote process."""
        self.cancelled = True


class _FakeRemoteProcess:
    """Minimal asyncio subprocess stand-in for cancel-path tests."""

    def __init__(self) -> None:
        """Initialize a running fake with no terminal status."""
        self.returncode = None
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        """Record SIGTERM and leave the process running until grace expires."""
        self.terminated = True

    def kill(self) -> None:
        """Record SIGKILL and mark the process exited."""
        self.killed = True
        self.returncode = -9

    async def wait(self) -> int:
        """Return once the fake process is considered exited."""
        if self.returncode is None:
            self.returncode = -15
        return self.returncode


class _FailedGenerationStartDriver(TRexTrafficDriver):
    """Driver fake that loses the generation-start response after remote work."""

    def __init__(self) -> None:
        """Initialize one exact action ledger."""
        super().__init__(_trex_config())
        self.actions = []
        self._trex_identity = dict(TREX_IDENTITY)  # pylint: disable=protected-access

    async def _invoke_remote(self, spec):  # pylint: disable=arguments-differ
        """Inject start ambiguity and admit the exact compensating abort."""
        self._validate_remote_request(spec)  # pylint: disable=protected-access
        self.actions.append(spec["action"])
        if spec["action"] == "generation_start":
            raise RuntimeError("injected generation-start response loss")
        if spec["action"] == "generation_abort":
            return {
                "ok": True,
                "action": "generation_abort",
            }
        raise RuntimeError("unexpected fake action")


class TestTRexTrafficDriver(unittest.TestCase):  # pylint: disable=too-many-public-methods
    """Validate local TRex driver semantics."""

    def test_requires_sustained_generation_overlap(self):
        """TRex keeps both packet-profile tag streams live for the window."""
        driver = TRexTrafficDriver(_trex_config())

        self.assertTrue(driver.requires_sustained_generation_overlap)

    def test_probe_records_only_bounded_stateless_server_identity(self):
        """The setup probe alone records bounded stateless provenance."""
        driver = _CapturingTRexDriver(initialized=False)
        asyncio.run(driver.setup())
        self.assertEqual(driver.traffic_generator_identity, TREX_IDENTITY)
        self.assertIn(
            "trex_identity(client.get_server_version())",
            trex_module._REMOTE_TREX_SCRIPT,  # pylint: disable=protected-access
        )
        response_contracts = trex_module._REMOTE_SUCCESS_KEYS  # pylint: disable=protected-access
        self.assertIn("trex_identity", response_contracts["probe"])
        self.assertTrue(
            all(
                "trex_identity" not in fields
                for action, fields in response_contracts.items()
                if action != "probe"
            )
        )
        remote_script = trex_module._REMOTE_TREX_SCRIPT  # pylint: disable=protected-access
        self.assertEqual(remote_script.count("client.get_server_version()"), 1)
        asyncio.run(driver.teardown())
        self.assertIsNone(driver.traffic_generator_identity)

        malformed_identities = (
            {"version": "", "mode": "STL"},
            {"version": "v3.06", "mode": "ASTF"},
            {"version": "v3.06", "mode": "STL", "extra": "x"},
            {"version": "x" * 129, "mode": "STL"},
            {"version": "v3.\N{SNOWMAN}", "mode": "STL"},
        )
        for identity in malformed_identities:
            with self.subTest(identity=identity):
                malformed = _CapturingTRexDriver(identity, initialized=False)
                with self.assertRaises((RuntimeError, ValueError)):
                    asyncio.run(malformed.setup())
                self.assertIsNone(malformed.traffic_generator_identity)

        malformed = _CapturingTRexDriver(
            initialized=False,
            probe_work_dir="/tmp/foreign-trex-work",
        )
        with self.assertRaisesRegex(RuntimeError, "work directory disagrees"):
            asyncio.run(malformed.setup())
        self.assertIsNone(malformed.traffic_generator_identity)

    def test_stats_analysis_writes_sidecar(self):
        """TRex stats should be converted into the standard AnalysisResult."""
        with tempfile.TemporaryDirectory() as tmpdir:
            driver = TRexTrafficDriver(_trex_config())
            raw = {
                "ok": True,
                "action": "run",
                "tx_count": 100,
                "rx_count": 97,
                "errors": 0,
                "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
                "port_counter_final": _port_counter_final(50, 50, 97),
                "tag_counts": {"0": 97},
                "achievement_ratio": 1.0,
            }
            pcap_file = Path(tmpdir) / "capture_64.pcap"

            result = asyncio.run(
                _analyze_stats_run(driver, pcap_file, 100, raw)
            )

            self.assertEqual(result.total_rx, 97)
            self.assertEqual(result.valid, 97)
            self.assertEqual(result.missing_count, 3)
            self.assertIsNone(result.latency_stats())
            result.set_latency_stats({
                "avg": 10.0,
                "min": 5.0,
                "max": 20.0,
                "p50": 9.0,
                "p99": 19.0,
            })
            with self.assertRaisesRegex(RuntimeError, "without an owned source"):
                ValidationOrchestrator(_trex_config()).scenario_context().measured_average_latency(result)
            sidecar = Path(tmpdir) / "capture_64.trex_stats.json"
            self.assertTrue(sidecar.exists())
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(payload["rx_count"], 97)
            self.assertEqual(payload["trex_identity"], TREX_IDENTITY)
            self.assertEqual(payload["port_counter_baseline"], PORT_COUNTER_BASELINE)
            self.assertEqual(payload["port_counter_final"], _port_counter_final(50, 50, 97))

    def test_stats_analysis_accounts_duplicates_without_negative_loss(self):
        """RX counts above expected should be surfaced as duplicates."""
        driver = TRexTrafficDriver(_trex_config())
        raw = {
            "ok": True,
            "action": "run",
            "tx_count": 100,
            "rx_count": 104,
            "errors": 0,
            "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
            "port_counter_final": _port_counter_final(50, 50, 104),
            "tag_counts": {"0": 104},
            "achievement_ratio": 1.0,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            result = asyncio.run(
                _analyze_stats_run(
                    driver,
                    Path(tmpdir) / "capture_64.pcap",
                    100,
                    raw,
                )
            )

        self.assertEqual(result.valid, 100)
        self.assertEqual(result.duplicates, 4)
        self.assertEqual(result.loss_pct(100), 0.0)

    def test_stats_snapshots_reject_before_sidecar_publication(self):
        """Missing, regressing, or inconsistent observations cannot become capture evidence."""
        raw = {
            "ok": True,
            "action": "run",
            "tx_count": 100,
            "rx_count": 97,
            "errors": 0,
            "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
            "port_counter_final": _port_counter_final(50, 50, 97),
            "tag_counts": {"0": 97},
            "achievement_ratio": 1.0,
        }
        invalid_results = []
        for field in ("port_counter_baseline", "port_counter_final"):
            invalid = copy.deepcopy(raw)
            del invalid[field]
            invalid_results.append(invalid)
            for observation in (None, {}, {"foreign": PORT_COUNTER_BASELINE["0"]}):
                invalid_results.append({**raw, field: observation})
            invalid = copy.deepcopy(raw)
            del invalid[field]["0"]["opackets"]
            invalid_results.append(invalid)
            for value in (True, "0", 0.0, -1, 1 << 64):
                invalid = copy.deepcopy(raw)
                invalid[field]["0"]["opackets"] = value
                invalid_results.append(invalid)
        for port, row in PORT_COUNTER_BASELINE.items():
            for field, count in row.items():
                invalid = copy.deepcopy(raw)
                invalid["port_counter_final"][port][field] = count - 1
                invalid_results.append(invalid)
        for field in ("tx_count", "rx_count", "errors"):
            invalid_results.append({**raw, field: raw[field] + 1})
        for port, field in (("0", "oerrors"), ("2", "ierrors")):
            invalid = copy.deepcopy(raw)
            invalid["port_counter_final"][port][field] += 1
            invalid["errors"] = 1
            invalid_results.append(invalid)
        for index, invalid in enumerate(invalid_results):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as tmpdir:
                pcap_file = Path(tmpdir) / "capture.pcap"
                driver = TRexTrafficDriver(_trex_config())
                with self.assertRaises((RuntimeError, JsonContractError)):
                    asyncio.run(_analyze_stats_run(driver, pcap_file, 100, copy.deepcopy(invalid)))
                self.assertFalse(pcap_file.with_suffix(".trex_stats.json").exists())

    def test_generation_sender_uses_orchestrated_overlap_session(self):
        """A complete generation session retains its port observations in the sidecar."""
        driver = _CapturingTRexDriver()
        sender = driver.make_sender(PacketConfig())

        async def run_session(pcap_file):
            """Drive one complete valid generation session through evidence publication."""
            await driver.start_capture(pcap_file, "udp")
            await sender.begin_generation_tags(15.0, 1, 2)
            await sender.start_generation_overlap(2)
            await sender.end_generation_overlap()
            stats = await sender.finish_generation_tags()
            await driver.stop_capture()
            await driver.analyze_capture(pcap_file, stats.tx_count)
            return stats

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = Path(tmpdir) / "epoch_capture.pcap"
            stats = asyncio.run(run_session(pcap_file))
            payload = json.loads(pcap_file.with_suffix(".trex_stats.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["port_counter_baseline"], PORT_COUNTER_BASELINE)
            self.assertEqual(payload["port_counter_final"], _port_counter_final(7750, 7750, 15500))
            self.assertEqual(payload["port_tx_count"], 15500)
            self.assertEqual(payload["port_rx_count"], 15500)
            self.assertEqual(payload["errors"], 0)

        self.assertEqual(
            [spec["action"] for spec in driver.specs],
            [
                "generation_start",
                "generation_resume_next",
                "generation_pause_initial",
                "generation_finish",
            ],
        )
        self.assertEqual(driver.specs[0]["initial_generation_tag"], 1)
        self.assertEqual(driver.specs[0]["next_generation_tag"], 2)
        self.assertNotIn("generation_tag", driver.specs[0])
        self.assertEqual(driver.specs[1]["ingress_ports"], [0, 1])
        self.assertEqual(driver.specs[2]["ingress_ports"], [0, 1])
        self.assertEqual(driver.specs[3]["ingress_ports"], [0, 1])
        self.assertEqual(driver.specs[3]["next_start_monotonic"], 15.0)
        self.assertEqual(driver.specs[3]["initial_pause_monotonic"], 15.5)
        self.assertEqual(driver.specs[3]["port_counter_baseline"], PORT_COUNTER_BASELINE)
        self.assertEqual(
            driver.specs[3]["generation_stream_ids"],
            {
                "0": {"initial": [1], "next": [2]},
                "1": {"initial": [1], "next": [2]},
            },
        )
        self.assertEqual(stats.tx_count, 15500)
        self.assertEqual(stats.generation_tag_counts, {1: 5500, 2: 10000})

    def test_generation_sender_edges_are_linear_and_exactly_once(self):
        """Duplicate resume/pause calls cannot publish a second remote edge."""
        driver = _CapturingTRexDriver()
        sender = driver.make_sender(PacketConfig())

        async def run_session():
            """Drive every legal edge and probe each duplicate."""
            await sender.begin_generation_tags(15.0, 1, 2)
            await sender.start_generation_overlap(2)
            with self.assertRaisesRegex(RuntimeError, "not started"):
                await sender.start_generation_overlap(2)
            await sender.end_generation_overlap()
            with self.assertRaisesRegex(RuntimeError, "already paused"):
                await sender.end_generation_overlap()
            return await sender.finish_generation_tags()

        stats = asyncio.run(run_session())

        self.assertEqual(stats.tx_count, 15500)
        self.assertEqual(
            [spec["action"] for spec in driver.specs],
            [
                "generation_start",
                "generation_resume_next",
                "generation_pause_initial",
                "generation_finish",
            ],
        )

    def test_generation_finish_releases_session_before_result_normalization(self):
        """Malformed terminal counters cannot trigger a second remote abort."""
        driver = _CapturingTRexDriver()
        sender = driver.make_sender(PacketConfig())

        async def run_session() -> None:
            """Complete remote ownership, then inject malformed terminal data."""
            await sender.begin_generation_tags(15.0, 1, 2)
            await sender.start_generation_overlap(2)
            await sender.end_generation_overlap()

            async def malformed_finish(**_kwargs):
                """Publish remote retirement followed by malformed counters."""
                driver._active_generation_session = None  # pylint: disable=protected-access
                return {}

            with patch.object(
                driver, "finish_generation_session", new=malformed_finish
            ):
                with self.assertRaisesRegex(RuntimeError, "omitted required"):
                    await sender.finish_generation_tags()
            sender.cleanup()

        asyncio.run(run_session())
        self.assertNotIn("generation_abort", [row["action"] for row in driver.specs])

    def test_udp_exchange_preserves_exact_request_and_capture_bytes(self):
        """A complete endpoint result returns packet evidence without replacing measurement state."""
        driver = TRexTrafficDriver(_trex_config())
        marker = b"e" * 16
        packet = bytes.fromhex("4500002c00000000401100000a000001c63364094e20c34f00180000") + marker
        frame = bytes.fromhex("001122334455024b4e4154000800") + packet
        response = {"ok": True, "action": "exchange_udp", "frames": [frame.hex()]}
        process = _FakeRemoteProcess()
        process.returncode = 0
        receive = AsyncMock(return_value=(json.dumps(response).encode("ascii"), b""))

        async def exchange():
            """Run one owned exchange and its ordinary teardown."""
            with patch.object(
                trex_module.asyncio, "create_subprocess_exec", new=AsyncMock(return_value=process),
            ), patch.object(trex_module, "communicate_bounded_subprocess", new=receive):
                self.assertEqual(await driver.exchange_udp_packets("wan0", (packet,), marker), (frame,))
            await driver.teardown()

        asyncio.run(exchange())
        request = json.loads(receive.call_args.args[3])
        self.assertEqual(request["packets"], [packet.hex()])
        self.assertEqual(request["capture_marker"], marker.hex())
        self.assertEqual(request["ingress_stream"]["logical_name"], "wan0")
        self.assertEqual(request["egress_ports"], [2])

    def test_udp_exchange_launch_failure_has_no_remote_capture_owner(self):
        """A local SSH launch failure must not manufacture unresolved remote capture ownership."""
        driver = TRexTrafficDriver(_trex_config())
        marker = b"e" * 16
        packet = bytes.fromhex("4500002c00000000401100000a000001c63364094e20c34f00180000") + marker

        async def exchange():
            """Fail before process creation, then complete ordinary local cleanup."""
            with patch.object(
                trex_module.asyncio, "create_subprocess_exec", new=AsyncMock(side_effect=OSError("launch failed")),
            ):
                with self.assertRaisesRegex(OSError, "launch failed"):
                    await driver.exchange_udp_packets("wan0", (packet,), marker)
            await driver.teardown()

        asyncio.run(exchange())

    def test_udp_exchange_ambiguity_cannot_report_capture_retired(self):
        """A lost endpoint result keeps capture retirement unproved while local cleanup still runs."""
        driver = TRexTrafficDriver(_trex_config())
        marker = b"e" * 16
        packet = bytes.fromhex("4500002c00000000401100000a000001c63364094e20c34f00180000") + marker
        cancel = MagicMock()
        await_kill = AsyncMock()
        process = _FakeRemoteProcess()
        process.returncode = -15

        async def exchange():
            """Inject an ambiguous response and require an explicit cleanup failure."""
            with patch.object(
                trex_module.asyncio, "create_subprocess_exec", new=AsyncMock(return_value=process),
            ), patch.object(
                trex_module, "communicate_bounded_subprocess", new=AsyncMock(side_effect=RuntimeError("response lost")),
            ):
                with self.assertRaisesRegex(RuntimeError, "response lost"):
                    await driver.exchange_udp_packets("wan0", (packet,), marker)
            with patch.object(driver, "cancel_remote_action", new=cancel), patch.object(
                driver, "_await_remote_kill_task", new=await_kill,
            ):
                with self.assertRaisesRegex(RuntimeError, "capture retirement is unproved"):
                    await driver.teardown()

        asyncio.run(exchange())
        cancel.assert_called_once_with()
        await_kill.assert_awaited_once_with()

    def test_udp_capture_retires_before_service_mode_on_success_and_failure(self):
        """Endpoint send failures and cancellation still retire the exact capture before service mode."""
        exchange = _remote_helper("exchange_udp")
        ingress = {"port_id": 0, "src_mac": "00:11:22:33:44:55", "dst_mac": "00:11:22:33:44:66"}
        frame = bytes.fromhex("001122334455024b4e4154000800") + b"packet"

        def stop_capture(events, capture_id, output):
            """Publish external bytes and record retirement of the exact captured owner."""
            self.assertEqual(capture_id, 17)
            output.append({"origin": "RX", "port": 2, "binary": frame})
            events.append("capture retired")

        for failure in (None, RuntimeError("send failed"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                events = []
                client = MagicMock()
                client.start_capture.return_value = {"id": 17}
                client.push_packets.side_effect = failure
                client.service_mode.return_value.__exit__.side_effect = (
                    lambda *_, events=events: events.append("service exit")
                )

                client.stop_capture.side_effect = partial(stop_capture, events)
                ethernet = MagicMock()
                exchange.__globals__.update({
                    "ports": [0, 1, 2], "Ether": ethernet, "Raw": MagicMock(),
                    "time": MagicMock(), "EXCHANGE_TIMEOUT_S": 2.0, "EXCHANGE_BYTE_CAPACITY": 256,
                })
                if failure is None:
                    self.assertEqual(exchange(client, ingress, [b"packet"], b"m" * 16, [2]), [frame.hex()])
                else:
                    with self.assertRaises(type(failure)):
                        exchange(client, ingress, [b"packet"], b"m" * 16, [2])
                ethernet.assert_called_once_with(src=ingress["src_mac"], dst=ingress["dst_mac"], type=0x0800)
                self.assertEqual(events, ["capture retired", "service exit"])
                client.service_mode.assert_called_once_with(ports=[0, 1, 2])

    def test_driver_teardown_attempts_process_cleanup_after_session_failure(self):
        """Independent remote-process cleanup runs after session abort fails."""
        driver = _CapturingTRexDriver()
        driver._active_generation_session = {"owned": True}  # pylint: disable=protected-access
        abort = AsyncMock(side_effect=RuntimeError("synthetic abort failure"))
        cancel = MagicMock()
        await_kill = AsyncMock()

        async def run_teardown() -> None:
            """Invoke teardown through its complete failure product."""
            with patch.object(driver, "abort_generation_session", new=abort), patch.object(
                driver, "cancel_remote_action", new=cancel
            ), patch.object(driver, "_await_remote_kill_task", new=await_kill):
                with self.assertRaisesRegex(RuntimeError, "abort failure"):
                    await driver.teardown()

        asyncio.run(run_teardown())
        abort.assert_awaited_once()
        cancel.assert_called_once_with()
        await_kill.assert_awaited_once_with()

    def test_generation_start_ambiguity_executes_exact_abort_before_return(self):
        """A lost start response must not orphan remotely owned streams."""
        driver = _FailedGenerationStartDriver()

        with self.assertRaisesRegex(RuntimeError, "response loss"):
            asyncio.run(
                driver.start_generation_session(
                    PacketConfig(),
                    15.0,
                    1,
                    2,
                )
            )

        self.assertEqual(driver.actions, ["generation_start", "generation_abort"])
        self.assertIsNone(driver._active_generation_session)  # pylint: disable=protected-access

    def test_stream_identity_is_port_qualified_on_both_transport_sides(self):
        """Cross-port reuse is valid; duplicates and role overlap inside one port reject."""
        remote = _remote_helper(
            "exact_generation_stream_ids", "exact_int", "exact_int_array"
        )
        rows = {
            "0": {"initial": [1], "next": [2]},
            "1": {"initial": [2], "next": [1]},
        }
        self.assertEqual(remote(rows, [0, 1]), rows)
        self.assertEqual(
            TRexTrafficDriver.generation_stream_ids({"generation_stream_ids": rows}, "initial"),
            {"0": [1], "1": [2]},
        )
        self.assertEqual(
            TRexTrafficDriver.generation_stream_ids({"generation_stream_ids": rows}, "next"),
            {"0": [2], "1": [1]},
        )
        malformed = [
            {"initial": [1, 1], "next": [2, 3]},
            {"initial": [1], "next": [1]},
            {"initial": [], "next": []},
            {"initial": [1], "next": [2, 3]},
            {"initial": [True], "next": [2]},
            {"initial": [-1], "next": [2]},
            {"initial": [1 << 32], "next": [2]},
        ]
        for row in malformed:
            with self.subTest(row=row):
                invalid = {**rows, "0": row}
                with self.assertRaises((RuntimeError, JsonContractError)):
                    TRexTrafficDriver.generation_stream_ids(
                        {"generation_stream_ids": invalid}, "initial"
                    )
                with self.assertRaises(RuntimeError):
                    remote(invalid, [0, 1])

    def test_stream_action_receipts_preserve_port_membership_and_identity(self):
        """Resume and pause cannot exchange IDs between ports or return a flattened list."""
        driver = _CapturingTRexDriver()
        rows = {
            "0": {"initial": [1], "next": [2]},
            "1": {"initial": [2], "next": [1]},
        }

        async def validate_receipts():
            """Obtain complete valid requests, then independently vary only the reply identity."""
            session = await driver.start_generation_session(PacketConfig(), 15.0, 1, 2)
            try:
                await driver.resume_next_generation(session, 2)
                resume_request = copy.deepcopy(driver.specs[-1])
                await driver.pause_initial_generation(session)
                pause_request = copy.deepcopy(driver.specs[-1])
                for action, field, request, exact in [
                    ("generation_resume_next", "resumed_stream_ids", resume_request,
                     {"0": [2], "1": [1]}),
                    ("generation_pause_initial", "paused_stream_ids", pause_request,
                     {"0": [1], "1": [2]}),
                ]:
                    request["generation_stream_ids"] = copy.deepcopy(rows)
                    driver._validate_remote_request(request)  # pylint: disable=protected-access
                    client = MagicMock(spec=["acquire", "resume_streams", "pause_streams"])
                    emit = MagicMock()
                    exec(  # pylint: disable=exec-used
                        _remote_action_execution(action),
                        {
                            "action": action, "spec": request, "ports": [0, 1],
                            "client": client, "emit": emit, "contextlib": contextlib,
                            "sys": sys, "time": time,
                        },
                    )
                    client.acquire.assert_called_once_with(ports=[0, 1], force=True)
                    active_method, inactive_method = (
                        (client.resume_streams, client.pause_streams)
                        if action == "generation_resume_next"
                        else (client.pause_streams, client.resume_streams)
                    )
                    self.assertEqual(
                        active_method.call_args_list,
                        [call(0, exact["0"]), call(1, exact["1"])],
                    )
                    inactive_method.assert_not_called()
                    emit.assert_called_once()
                    reply = emit.call_args.args[0]
                    self.assertEqual(reply[field], exact)
                    driver._validate_remote_success(reply, action, request)  # pylint: disable=protected-access
                    for invalid in [
                        list(exact["0"] + exact["1"]),
                        {"0": exact["1"], "1": exact["0"]},
                        {"0": exact["0"]},
                        {"0": exact["0"], "2": exact["1"]},
                        {"0": exact["0"] * 2, "1": exact["1"]},
                    ]:
                        with self.subTest(action=action, reply=invalid):
                            reply[field] = invalid
                            with self.assertRaises((RuntimeError, JsonContractError)):
                                driver._validate_remote_success(  # pylint: disable=protected-access
                                    reply, action, request
                                )
            finally:
                await driver.abort_generation_session(session)

        asyncio.run(validate_receipts())

    def test_aborted_capture_has_no_analysis_evidence_and_can_be_replaced(self):
        """An empty window retires without fabricating a completed capture or blocking the next one."""
        driver = _CapturingTRexDriver()

        async def retire_empty_window(root):
            """Retire two distinct empty windows through the normal capture API."""
            for name in ("aborted.pcap", "next.pcap"):
                path = root / name
                await driver.start_capture(path, "udp")
                await driver.stop_capture()
                with self.assertRaisesRegex(RuntimeError, "before a traffic run completed"):
                    await driver.analyze_capture(path, 1)
                self.assertFalse(path.with_suffix(".trex_stats.json").exists())
            await driver.teardown()

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(retire_empty_window(Path(temporary)))

    def test_generation_start_failure_preserves_failed_epoch_result(self):
        """A retired failed start remains an epoch failure in JSON instead of a second cleanup error."""
        driver = _FailedGenerationStartDriver()
        with tempfile.TemporaryDirectory() as temporary:
            config = replace(
                driver.config,
                test_type=ValidationTestType.EPOCH,
                output_dir=Path(temporary),
            )
            orchestrator = ValidationOrchestrator(config, reporter=MagicMock())
            orchestrator._traffic = driver  # pylint: disable=protected-access
            orchestrator._kinetumctl = MagicMock(spec=KinetumCtl)  # pylint: disable=protected-access
            initial = StatsResult(
                success=True,
                active_epoch=1,
                active_snapshot_id="baseline",
            )
            with patch.object(orchestrator, "_setup", new=AsyncMock(return_value=True)), patch.object(
                ScenarioContext, "get_stats_snapshot", new=AsyncMock(return_value=initial)
            ), patch.object(
                orchestrator, "_save_dp_stats", new=AsyncMock(return_value=StatsValidationResult())
            ):
                result = asyncio.run(orchestrator.run())
            self.assertFalse(result.all_passed)
            self.assertEqual(result.failed_tests, 1)
            self.assertIn("response loss", result.epoch_test.message)
            saved = json.loads((Path(temporary) / "test_results.json").read_text())
            self.assertFalse(saved["all_passed"])
            self.assertIn("response loss", saved["epoch_test"]["message"])
            self.assertIsNone(driver._capture_file)  # pylint: disable=protected-access
            self.assertIsNone(driver._completed_capture_file)  # pylint: disable=protected-access
            self.assertIsNone(driver._active_generation_session)  # pylint: disable=protected-access
            self.assertEqual(driver.actions, ["generation_start", "generation_abort"])
            self.assertFalse((Path(temporary) / "epoch_capture.trex_stats.json").exists())

    def test_generation_stats_analysis_uses_tag_counts(self):
        """TRex PGID RX counts populate bounded AnalysisResult tags."""
        driver = TRexTrafficDriver(_trex_config())
        raw = {
            "ok": True,
            "action": "generation_finish",
            "tx_count": 42,
            "rx_count": 42,
            "port_tx_count": 42,
            "port_rx_count": 42,
            "errors": 0,
            "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
            "port_counter_final": _port_counter_final(21, 21, 42),
            "generation_tag_counts": {"1": 20, "2": 22},
            "tag_counts": {"1": 20, "2": 22},
            "overlap_window_ms_measured": 500.0,
            "achievement_ratio": 1.0,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            result = asyncio.run(
                _analyze_stats_run(
                    driver,
                    Path(tmpdir) / "epoch_capture.pcap",
                    42,
                    raw,
                )
            )

        self.assertEqual(result.tag_counts, {1: 20, 2: 22})

    def test_generation_stats_reject_missing_generation_class(self):
        """Generation evidence requires nonzero initial and next PGID classes."""
        driver = TRexTrafficDriver(_trex_config())
        raw = {
            "ok": True,
            "action": "generation_finish",
            "tx_count": 42,
            "rx_count": 42,
            "port_tx_count": 42,
            "port_rx_count": 42,
            "errors": 0,
            "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
            "port_counter_final": _port_counter_final(21, 21, 42),
            "generation_tag_counts": {"1": 42, "2": 0},
            "tag_counts": {"1": 42, "2": 0},
            "overlap_window_ms_measured": 500.0,
            "achievement_ratio": 1.0,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(RuntimeError, "exactly two tag"):
                asyncio.run(
                    _analyze_stats_run(
                        driver,
                        Path(tmpdir) / "epoch_capture.pcap",
                        42,
                        raw,
                    )
                )

    def test_generation_stats_reject_unmeasured_overlap(self):
        """Generation evidence requires a measured positive overlap window."""
        driver = TRexTrafficDriver(_trex_config())
        raw = {
            "ok": True,
            "action": "generation_finish",
            "tx_count": 42,
            "rx_count": 42,
            "port_tx_count": 42,
            "port_rx_count": 42,
            "errors": 0,
            "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
            "port_counter_final": _port_counter_final(21, 21, 42),
            "generation_tag_counts": {"1": 20, "2": 22},
            "tag_counts": {"1": 20, "2": 22},
            "overlap_window_ms_measured": None,
            "achievement_ratio": 1.0,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(RuntimeError, "measured overlap window"):
                asyncio.run(
                    _analyze_stats_run(
                        driver,
                        Path(tmpdir) / "epoch_capture.pcap",
                        42,
                        raw,
                    )
                )

    def test_stats_analysis_rejects_low_traffic_achievement(self):
        """TRex evidence should fail closed when target traffic was not sent."""
        driver = TRexTrafficDriver(_trex_config())
        raw = {
            "ok": True,
            "tx_count": 42,
            "rx_count": 42,
            "errors": 0,
            "port_counter_baseline": copy.deepcopy(PORT_COUNTER_BASELINE),
            "port_counter_final": _port_counter_final(21, 21, 42),
            "action": "run",
            "tag_counts": {"0": 42},
            "target_pps": 1000,
            "expected_tx_count": 15500,
            "achievement_ratio": 42.0 / 15500.0,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = Path(tmpdir) / "epoch_capture.pcap"
            with self.assertRaisesRegex(RuntimeError, "achieved only"):
                asyncio.run(
                    _analyze_stats_run(driver, pcap_file, 42, raw)
                )
            self.assertFalse(pcap_file.with_suffix(".trex_stats.json").exists())

        with self.assertRaisesRegex(RuntimeError, "expected TX disagrees"):
            driver._record_run(  # pylint: disable=protected-access
                {
                    "tx_count": 100,
                    "expected_tx_count": 1,
                },
                PacketConfig(pps=100),
                1.0,
            )

    def test_run_spec_uses_work_dir_runtime_macs_and_egress_observation(self):
        """TRex run specs should carry plan MACs and egress observation ports."""
        driver = _CapturingTRexDriver()

        asyncio.run(
            driver.run_remote_traffic(
                packet_config=PacketConfig(pps=1000),
                duration_s=1.0,
                mode="standard",
                generation_tag=0,
            )
        )

        spec = driver.specs[0]
        self.assertEqual(spec["work_dir"], "/tmp/kinetum_trex_unit")
        self.assertEqual(spec["egress_ports"], [2])
        self.assertEqual(spec["num_flows"], 1)
        self.assertNotIn("initial_generation_tag", spec)
        self.assertNotIn("next_generation_tag", spec)
        self.assertNotIn("transition_time_s", spec)
        self.assertNotIn("overlap_window_ms", spec)
        self.assertNotIn("src_mac", spec)
        self.assertNotIn("dst_mac", spec)
        self.assertEqual(
            [stream["dst_mac"] for stream in spec["ingress_streams"]],
            ["3c:fd:fe:05:c4:80", "3c:fd:fe:05:c4:84"],
        )
        self.assertEqual(
            [stream["src_mac"] for stream in spec["ingress_streams"]],
            ["02:00:00:00:00:01", "02:00:00:00:00:02"],
        )
        self.assertNotIn("egress_promiscuous", driver._last_run)  # pylint: disable=protected-access
        self.assertEqual(driver._last_run["promiscuous_ports"], [2])  # pylint: disable=protected-access

    def test_run_spec_carries_requested_flow_count(self):
        """TRex flow diversity stays inside its bounded evidence result."""
        driver = _CapturingTRexDriver()

        asyncio.run(
            driver.run_remote_traffic(
                packet_config=PacketConfig(pps=1000, num_flows=4),
                duration_s=1.0,
                mode="standard",
                generation_tag=0,
            )
        )

        self.assertEqual(driver.specs[0]["num_flows"], 4)

        oversized = driver._generation_run_spec(  # pylint: disable=protected-access
            PacketConfig(num_flows=65535 - 10000 + 1),
            15.0,
            1,
            2,
        )
        oversized["action"] = "generation_start"
        with self.assertRaisesRegex(RuntimeError, "bounded JSON result"):
            driver._validate_remote_request(oversized)  # pylint: disable=protected-access

    def test_sender_cancel_terminates_remote_action(self):
        """TRex sender cancel should request remote subprocess termination."""
        driver = _CapturingTRexDriver()
        sender = driver.make_sender(PacketConfig())

        sender.cancel()

        self.assertTrue(driver.cancelled)

    def test_cancel_remote_action_drains_tracked_kill_task_on_teardown(self):
        """TRex teardown should not leave fire-and-forget kill tasks pending."""
        driver = TRexTrafficDriver(_trex_config())
        proc = _FakeRemoteProcess()
        driver._remote_proc = proc  # pylint: disable=protected-access

        async def run_cancel():
            """Drive cancellation through the tracked teardown owner."""
            with patch.object(trex_module, "_REMOTE_TERMINATE_GRACE_S", 0.001):
                driver.cancel_remote_action()
                self.assertIsNotNone(driver._remote_kill_task)  # pylint: disable=protected-access
                await driver.teardown()

        asyncio.run(run_cancel())

        self.assertTrue(proc.terminated)
        self.assertIsNone(driver._remote_kill_task)  # pylint: disable=protected-access

    def test_remote_timeout_accounts_for_run_duration(self):
        """Remote action timeout should cover setup and traffic phases."""
        driver = TRexTrafficDriver(_trex_config())

        self.assertEqual(driver._remote_timeout_s({"action": "probe"}), 60.0)  # pylint: disable=protected-access
        self.assertEqual(
            driver._remote_timeout_s({"action": "run", "duration_s": 15.0}),  # pylint: disable=protected-access
            135.0,
        )
        self.assertEqual(
            driver._remote_timeout_s(  # pylint: disable=protected-access
                {"action": "generation_finish", "duration_s": 15.0}
            ),
            135.0,
        )

    def test_remote_runner_acquires_ports_before_stats(self):
        """TRex v3.08 requires explicit port ownership for stats calls."""
        script = trex_module._REMOTE_TREX_SCRIPT  # pylint: disable=protected-access
        transport = inspect.getsource(TRexTrafficDriver._invoke_remote)  # pylint: disable=protected-access

        self.assertIn("set(spec) != spec_keys[action]", script)
        self.assertIn("sys.stdin.buffer.read", script)
        self.assertIn("stdin=asyncio.subprocess.PIPE", transport)
        self.assertIn("spec_bytes", transport)
        self.assertIn("client.acquire(ports=ports, force=True)", script)
        self.assertIn("client.get_stats(ports=ports)", script)
        self.assertIn("client.release(ports=[int(p) for p in spec[\"ports\"]])", script)

    def test_remote_runner_enables_egress_promiscuous_temporarily(self):
        """TRex egress observation ports should accept forwarded L2 frames."""
        script = trex_module._REMOTE_TREX_SCRIPT  # pylint: disable=protected-access

        self.assertIn("promisc_ports = list(egress_ports)", script)
        self.assertIn("client.set_port_attr(ports=egress_ports, promiscuous=True)", script)
        self.assertIn("client.set_port_attr(ports=promisc_ports, promiscuous=False)", script)

    def test_remote_runner_uses_pgid_flow_stats_for_generation_evidence(self):
        """Generation-overlap runs rely on TRex PGID counters."""
        script = trex_module._REMOTE_TREX_SCRIPT  # pylint: disable=protected-access

        self.assertIn("STLFlowStats(pg_id=int(pg_id))", script)
        self.assertIn("start_paused=True", script)
        self.assertIn("flow_spec(spec, flow_id)", script)
        self.assertIn("client.resume_streams(port_id, port_next_ids)", script)
        self.assertIn("client.pause_streams(port_id, port_initial_ids)", script)
        self.assertIn("client.pause_streams(port_id, port_next_ids)", script)
        self.assertIn('flow_stats = stats["flow_stats"]', script)
        self.assertNotIn("client.get_pgid_stats()", script)
        self.assertIn(
            'exact_generation_stream_ids(spec["generation_stream_ids"], ingress_ports)',
            script,
        )
        self.assertNotIn(
            'exact_generation_stream_ids(spec["generation_stream_ids"], ports)',
            script,
        )
        self.assertIn("TRex generation-tag evidence missing flow stats", script)
        self.assertIn("\"overlap_window_ms_measured\": measured_overlap", script)
        self.assertIn(
            "\"expected_tx_count_source\": \"measured_generation_intervals\"",
            script,
        )
        self.assertIn('stat_value(port_stats, port_id, "oerrors")', script)
        self.assertIn('stat_value(port_stats, port_id, "ierrors")', script)
        self.assertIn("orchestrator_controlled_sustained_overlap", script)

    def test_remote_runner_preserves_generation_stats_across_reconnects(self):
        """PGIDs are read before stop retires their receive filters."""
        script = trex_module._REMOTE_TREX_SCRIPT  # pylint: disable=protected-access
        finish_block = _remote_action_execution("generation_finish")

        self.assertIn("_on_connect_clear_stats", script)
        self.assertIn("client.pause_streams(port_id, port_next_ids)", finish_block)
        self.assertLess(
            finish_block.index("client.pause_streams(port_id, port_next_ids)"),
            finish_block.index("stats = client.get_stats(ports=ports)"),
        )
        self.assertLess(
            finish_block.index("stats = client.get_stats(ports=ports)"),
            finish_block.index("client.stop(ports=ingress_ports)"),
        )

    def test_remote_runner_uses_pgid_totals_for_generation_result_counts(self):
        """Generation results retain PGID totals and independent port deltas."""
        finish_block = _remote_action_execution("generation_finish")

        self.assertIn("port_tx_count = sum(", finish_block)
        self.assertIn("port_rx_count = sum(", finish_block)
        self.assertIn("tx_count = sum(tx_by_generation.values())", finish_block)
        self.assertIn("rx_count = sum(rx_by_generation.values())", finish_block)
        self.assertIn("\"port_tx_count\": port_tx_count", finish_block)
        self.assertIn("\"port_rx_count\": port_rx_count", finish_block)
        self.assertLess(
            finish_block.index("tx_by_generation, rx_by_generation, by_pg_id"),
            finish_block.index("tx_count = sum(tx_by_generation.values())"),
        )

    def test_remote_generation_retains_absolute_baseline_across_clients(self):
        """Previous traffic and errors do not enter a reconnected epoch session."""
        driver = TRexTrafficDriver(_trex_config())
        request = {
            **driver._generation_run_spec(PacketConfig(), 15.0, 1, 2),  # pylint: disable=protected-access
            "action": "generation_start",
        }
        relative_zero = {
            int(port): {field: 0 for field in row}
            for port, row in PORT_COUNTER_BASELINE.items()
        }
        start_client = _counter_client(PORT_COUNTER_BASELINE, relative_zero)
        with patch.object(os, "getcwd", return_value=request["work_dir"]):
            session = _execute_remote_action(start_client, request, 10.0, 1.0)
        driver._validate_remote_success(session, "generation_start", request)  # pylint: disable=protected-access
        self.assertEqual(session["port_counter_baseline"], PORT_COUNTER_BASELINE)
        self.assertLess(
            start_client.mock_calls.index(call.get_stats(ports=[0, 1, 2])),
            start_client.mock_calls.index(call.start(ports=[0, 1], force=True)),
        )

        finish_request = {
            **request,
            "action": "generation_finish",
            **{key: session[key] for key in (
                "ingress_ports", "generation_stream_ids", "generation_flow_plan",
                "port_counter_baseline", "start_time", "start_monotonic",
            )},
            "next_start_time": 1.5,
            "next_start_monotonic": 15.0,
            "initial_pause_time": 2.0,
            "initial_pause_monotonic": 15.5,
        }
        driver._validate_remote_request(finish_request)  # pylint: disable=protected-access
        current = copy.deepcopy(PORT_COUNTER_BASELINE)
        current["0"]["opackets"] += 7750
        current["1"]["opackets"] += 7750
        current["2"]["ipackets"] += 15500
        flow_stats = {
            row["pg_id"]: {
                "tx_pkts": {row["port_id"]: row["expected_tx"]},
                "rx_pkts": {2: row["expected_tx"]},
            }
            for row in session["generation_flow_plan"]
        }
        finish_client = _counter_client(current, {"flow_stats": flow_stats})
        with patch.object(os, "getcwd", return_value=request["work_dir"]):
            result = _execute_remote_action(finish_client, finish_request, 25.0, 16.0)
        driver._validate_remote_success(result, "generation_finish", finish_request)  # pylint: disable=protected-access
        self.assertEqual(result["port_tx_count"], 15500)
        self.assertEqual(result["port_rx_count"], 15500)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(result["tx_count"], 15500)
        self.assertEqual(result["rx_count"], 15500)
        self.assertEqual(result["port_counter_baseline"], PORT_COUNTER_BASELINE)
        self.assertEqual(result["port_counter_final"], current)
        finish_client.get_stats.assert_called_once_with(ports=[0, 1, 2])
        finish_client.get_pgid_stats.assert_not_called()
        self.assertLess(
            finish_client.mock_calls.index(call.pause_streams(1, [2])),
            finish_client.mock_calls.index(call.get_stats(ports=[0, 1, 2])),
        )
        self.assertLess(
            finish_client.mock_calls.index(call.get_stats(ports=[0, 1, 2])),
            finish_client.mock_calls.index(call.stop(ports=[0, 1])),
        )

    def test_remote_run_retains_absolute_snapshots_around_traffic(self):
        """Ordinary runs retain measured snapshots without counting historical errors."""
        driver = TRexTrafficDriver(_trex_config())
        request = {
            **driver._packet_run_spec(PacketConfig(), 1.0, 0),  # pylint: disable=protected-access
            "action": "run",
            "mode": "standard",
        }
        driver._validate_remote_request(request)  # pylint: disable=protected-access
        current = copy.deepcopy(PORT_COUNTER_BASELINE)
        final = _port_counter_final(5, 5, 9)
        client = _counter_client(current, {})

        def complete_traffic(**_kwargs):
            """Publish the final absolute observations only after traffic finishes."""
            for port, row in current.items():
                row.update(final[port])

        client.wait_on_traffic.side_effect = complete_traffic
        with patch.object(os, "getcwd", return_value=request["work_dir"]):
            result = _execute_remote_action(client, request, 10.0, 1.0)
        driver._validate_remote_success(result, "run", request)  # pylint: disable=protected-access
        self.assertEqual(set(result), trex_module._REMOTE_SUCCESS_KEYS["run"])  # pylint: disable=protected-access
        self.assertEqual(result["port_counter_baseline"], PORT_COUNTER_BASELINE)
        self.assertEqual(result["port_counter_final"], final)
        self.assertEqual(result["tx_count"], 10)
        self.assertEqual(result["rx_count"], 9)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(client.get_stats.call_args_list, [call(ports=[0, 1, 2])] * 2)
        self.assertLess(
            client.mock_calls.index(call.get_stats(ports=[0, 1, 2])),
            client.mock_calls.index(call.start(ports=[0, 1], duration=1.0, force=True)),
        )
        self.assertLess(
            client.mock_calls.index(call.wait_on_traffic(ports=[0, 1], timeout=31.0)),
            len(client.mock_calls) - 1 - client.mock_calls[::-1].index(call.get_stats(ports=[0, 1, 2])),
        )

    def test_port_counter_baseline_requires_exact_presence_and_uint64_values(self):
        """Both transport boundaries reject incomplete or fabricated baselines."""
        driver = TRexTrafficDriver(_trex_config())
        remote_validate = _remote_helper("exact_port_counters", "exact_int")
        validators = (
            driver._require_port_counters,  # pylint: disable=protected-access
            remote_validate,
        )
        invalid = [None, {}, {**PORT_COUNTER_BASELINE, "3": PORT_COUNTER_BASELINE["0"]}]
        for field in ("opackets", "ipackets", "oerrors", "ierrors"):
            missing = copy.deepcopy(PORT_COUNTER_BASELINE)
            del missing["0"][field]
            invalid.append(missing)
            for value in (True, "0", 0.0, -1, 1 << 64):
                malformed = copy.deepcopy(PORT_COUNTER_BASELINE)
                malformed["0"][field] = value
                invalid.append(malformed)
        for validator in validators:
            args = ([0, 1, 2],) if validator is remote_validate else ("baseline",)
            validator(PORT_COUNTER_BASELINE, *args)
            for bound in (0, (1 << 64) - 1):
                validator({
                    port: {field: bound for field in row}
                    for port, row in PORT_COUNTER_BASELINE.items()
                }, *args)
            for value in invalid:
                with self.subTest(validator=validator.__name__, value=value):
                    with self.assertRaises((RuntimeError, JsonContractError)):
                        validator(value, *args)

    def test_port_counter_deltas_reject_resets_and_preserve_new_errors(self):
        """Each counter rejects regression even when another port compensates."""
        deltas = _remote_helper("port_counter_deltas")
        driver = TRexTrafficDriver(_trex_config())
        for field in ("opackets", "ipackets", "oerrors", "ierrors"):
            with self.subTest(field=field):
                current = copy.deepcopy(PORT_COUNTER_BASELINE)
                current["0"][field] -= 1
                current["1"][field] += 100
                with self.assertRaisesRegex(RuntimeError, f"port 0 {field} regressed: start="):
                    deltas(current, PORT_COUNTER_BASELINE)
                with self.assertRaisesRegex(RuntimeError, f"port 0 {field} regressed"):
                    driver._validated_port_totals({  # pylint: disable=protected-access
                        "action": "run",
                        "port_counter_baseline": PORT_COUNTER_BASELINE,
                        "port_counter_final": current,
                        "tx_count": 99,
                        "rx_count": 0,
                        "errors": 0,
                    })
        current = copy.deepcopy(PORT_COUNTER_BASELINE)
        current["0"]["oerrors"] += 1
        current["2"]["ierrors"] += 2
        result = deltas(current, PORT_COUNTER_BASELINE)
        self.assertEqual(result["0"]["oerrors"], 1)
        self.assertEqual(result["2"]["ierrors"], 2)
        self.assertEqual(result["1"]["oerrors"], 0)

    def test_generation_counter_mismatch_retains_all_four_totals(self):
        """An invalid interval keeps the numbers that explain its failure."""
        driver = _CapturingTRexDriver()
        sender = driver.make_sender(PacketConfig())

        async def run_session():
            """Obtain one fully admitted response before corrupting its totals."""
            await sender.begin_generation_tags(15.0, 1, 2)
            await sender.start_generation_overlap(2)
            await sender.end_generation_overlap()
            await sender.finish_generation_tags()

        asyncio.run(run_session())
        result = copy.deepcopy(driver._last_run)  # pylint: disable=protected-access
        for field in ("port_tx_count", "port_rx_count"):
            with self.subTest(field=field):
                invalid = copy.deepcopy(result)
                invalid[field] = 15501
                port, counter = ("0", "opackets") if field == "port_tx_count" else ("2", "ipackets")
                invalid["port_counter_final"][port][counter] += 1
                with self.assertRaisesRegex(
                    RuntimeError,
                    f"port_tx={invalid['port_tx_count']} pgid_tx=15500 "
                    f"port_rx={invalid['port_rx_count']} pgid_rx=15500",
                ):
                    driver._validate_remote_success(  # pylint: disable=protected-access
                        invalid, "generation_finish", driver.specs[-1]
                    )

    def test_generation_finish_rejects_changed_session_baseline_and_port_totals(self):
        """Self-consistent deltas cannot replace the session's starting observations."""
        driver = _CapturingTRexDriver()
        sender = driver.make_sender(PacketConfig())

        async def run_session():
            """Complete one session before independently corrupting its final evidence."""
            await sender.begin_generation_tags(15.0, 1, 2)
            await sender.start_generation_overlap(2)
            await sender.end_generation_overlap()
            await sender.finish_generation_tags()

        asyncio.run(run_session())
        result = driver._last_run  # pylint: disable=protected-access
        invalid = copy.deepcopy(result)
        invalid["port_counter_baseline"]["0"]["opackets"] += 100
        invalid["port_counter_final"]["0"]["opackets"] += 100
        with self.assertRaisesRegex(RuntimeError, "baseline disagrees with its session"):
            driver._validate_remote_success(  # pylint: disable=protected-access
                invalid, "generation_finish", driver.specs[-1]
            )

        for field in ("port_tx_count", "port_rx_count"):
            with self.subTest(field=field):
                invalid = {**result, field: 15501}
                with self.assertRaisesRegex(RuntimeError, "disagrees with retained port snapshots"):
                    driver._validate_remote_success(  # pylint: disable=protected-access
                        invalid, "generation_finish", driver.specs[-1]
                    )
                with tempfile.TemporaryDirectory() as tmpdir:
                    pcap_file = Path(tmpdir) / "epoch_capture.pcap"
                    analyzer = TRexTrafficDriver(_trex_config())
                    with self.assertRaisesRegex(RuntimeError, "disagrees with retained port snapshots"):
                        asyncio.run(_analyze_stats_run(analyzer, pcap_file, 15500, invalid))
                    self.assertFalse(pcap_file.with_suffix(".trex_stats.json").exists())

    def test_generation_session_starts_without_trex_duration(self):
        """Generation sessions allow TRex pause/resume stream control."""
        script = trex_module._REMOTE_TREX_SCRIPT  # pylint: disable=protected-access
        start = script.index("if action == \"generation_start\":")
        end = script.index("if action == \"generation_resume_next\":")
        generation_start_block = script[start:end]

        self.assertIn(
            "client.start(ports=ingress_ports, force=True)",
            generation_start_block,
        )
        self.assertNotIn("duration=duration_s", generation_start_block)
        self.assertIn(
            "client.start(ports=ingress_ports, duration=duration_s, force=True)",
            script,
        )
        self.assertLess(
            generation_start_block.index("client.start(ports=ingress_ports, force=True)"),
            generation_start_block.index("start_mono = time.monotonic()"),
        )

    def test_remote_port_counter_accepts_int_and_string_port_keys(self):
        """PGID evidence must survive TRex dicts with either key shape."""
        port_counter = _remote_helper("port_counter")

        self.assertEqual(port_counter({1: 7}, 1), 7)
        self.assertEqual(port_counter({"1": 11}, 1), 11)
        with self.assertRaises(RuntimeError):
            port_counter({"1": "not-an-int"}, 1)
        with self.assertRaises(RuntimeError):
            port_counter({"2": "13"}, 1)

        stream_ids = _remote_helper("stream_ids_from_add_result")
        self.assertEqual(stream_ids([10, 11], 2), [10, 11])
        self.assertEqual(stream_ids([[10, 11]], 2), [])
        self.assertEqual(stream_ids({"0": [10, 11]}, 2), [])
        self.assertEqual(stream_ids([-1, 2], 2), [])
        self.assertEqual(stream_ids([1, 1 << 32], 2), [])

    def test_generation_finish_requires_each_pgid_to_reach_its_target(self):
        """Aggregate traffic cannot hide one starved generation-flow row."""
        driver = TRexTrafficDriver(_trex_config())
        plan = [
            {
                "pg_id": 1000,
                "generation_tag": 1,
                "logical_name": "wan0",
                "port_id": 0,
                "flow_id": 0,
                "role": "pre_overlap",
                "expected_tx": 100,
            },
            {
                "pg_id": 1001,
                "generation_tag": 2,
                "logical_name": "wan0",
                "port_id": 0,
                "flow_id": 0,
                "role": "post_overlap",
                "expected_tx": 100,
            },
        ]
        observed = {
            str(row["pg_id"]): {
                **{key: row[key] for key in (
                    "generation_tag", "logical_name", "port_id", "flow_id",
                    "role", "expected_tx",
                )},
                "tx_pkts": 100,
                "rx_pkts": 100,
            }
            for row in plan
        }
        payload = {
            "generation_overlap_method": "orchestrator_controlled_sustained_overlap",
            "overlap_window_timestamp_source": "trex_endpoint_monotonic",
            "expected_tx_count_source": "measured_generation_intervals",
            "start_monotonic": 10.0,
            "next_start_monotonic": 15.0,
            "initial_pause_monotonic": 15.5,
            "next_pause_monotonic": 25.0,
            "overlap_window_ms_measured": 500.0,
            "requested_overlap_window_ms": 500,
            "next_start_time": 1.5,
            "initial_pause_time": 2.0,
            "next_pause_time": 16.0,
            "steady_state_target_pps": 1000,
            "overlap_aggregate_target_pps": 2000,
            "transition_time_s_requested": 5.0,
            "generation_flow_plan": plan,
            "generation_pgid_stats": observed,
            "generation_tag_counts": {"1": 100, "2": 100},
            "tag_counts": {"1": 100, "2": 100},
        }
        driver._validate_generation_finish(payload)  # pylint: disable=protected-access
        payload["generation_pgid_stats"]["1001"]["tx_pkts"] = 94
        payload["generation_tag_counts"]["2"] = 94
        with self.assertRaisesRegex(RuntimeError, "PGID traffic achievement"):
            driver._validate_generation_finish(payload)  # pylint: disable=protected-access

    def test_remote_generation_pgid_base_is_unique_for_many_flows(self):
        """Generation PGID allocation does not collide across ports or flows."""
        generation_pg_id_base = _remote_helper("generation_pg_id_base")

        pg_ids = set()
        for stream_index in range(2):
            for flow_id in range(64):
                initial = generation_pg_id_base(stream_index, flow_id, 64)
                next_generation = initial + 1
                self.assertNotIn(initial, pg_ids)
                self.assertNotIn(next_generation, pg_ids)
                pg_ids.add(initial)
                pg_ids.add(next_generation)

        self.assertEqual(len(pg_ids), 256)

    def test_remote_shell_command_quotes_python_bootstrap(self):
        """OpenSSH remote commands must survive the endpoint shell boundary."""
        driver = TRexTrafficDriver(_trex_config())

        command = driver._remote_shell_command([  # pylint: disable=protected-access
            "/usr/bin/python3",
            "-I",
            "-c",
            trex_module._REMOTE_BOOTSTRAP,  # pylint: disable=protected-access
            "script payload",
            '{"action":"probe"}',
        ])

        self.assertIn("/usr/bin/python3 -I -c 'import base64,sys;", command)
        self.assertIn("'script payload'", command)
        self.assertIn('\'{"action":"probe"}\'', command)

    def test_remote_stdout_is_one_strict_json_object(self):
        """Prefix noise, duplicate keys, and scalar roots reject."""
        parser = TRexTrafficDriver._parse_remote_stdout  # pylint: disable=protected-access
        self.assertEqual(parser(b'{"ok":true}\n'), {"ok": True})
        for payload in (
            b'noise\n{"ok":true}\n',
            b'{"ok":true,"ok":false}\n',
            b'[]\n',
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
                    parser(payload)
