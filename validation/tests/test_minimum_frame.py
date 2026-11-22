# Copyright (c) 2026 Fleming Patel. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise the minimum-frame wire contract, sampling brackets and end-to-end packet accounting."""

import asyncio
import base64
import copy
import json
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from kinetum_validation.config.types import (
    BackendConfig, BackendType, DEPLOYMENT_SPECS, DeploymentMode, PacketConfig, ProcessConfig,
    TestConfig as ValidationConfig, TestType as ValidationTestType,
)
from kinetum_validation.engine.json_contract import PROTOCOL_FAULT_CODES
from kinetum_validation.engine.plan_metadata import parse_plan_topology
from kinetum_validation.minimum_frame import (
    _dut_observation, _reconcile, check_recorded_trial, packet_rates, run_minimum_frame,
)
from kinetum_validation.process.kinetumctl import ApplyConfigResult
from kinetum_validation.process.telemetry import (
    PortStatsResult, StatsResult, StorageDomainStatsResult, StreamStatsResult, WorkerPacketBinding,
)
from kinetum_validation.scenario_context import ScenarioContext
from kinetum_validation.traffic.trex import TRexTrafficDriver
from kinetum_validation.traffic.udp import internet_checksum
from .traffic_fixtures import complete_trex_identity


def _driver(root: Path = Path("/opt/kit"),
            deployment: DeploymentMode = DeploymentMode.PASSTHROUGH) -> TRexTrafficDriver:
    """Bind ingress and return MAC addresses to the two PCI ports in the real registry."""
    profile = DEPLOYMENT_SPECS[deployment].backend_profile(BackendType.DPDK_PCI)
    ports = (replace(profile.ports[0], runtime_mac="02:00:00:00:00:11", runtime_direction="rx"),
             replace(profile.ports[1], runtime_mac="02:00:00:00:00:12", runtime_direction="tx"))
    config = ValidationConfig(
        process=ProcessConfig(Path("/opt/kinetum"), root), deployment=deployment, output_dir=root,
        test_type=ValidationTestType.MINIMUM_FRAME, packet=PacketConfig(num_flows=64, duration_s=1, pps=1000),
        backend=BackendConfig(backend_type=BackendType.DPDK_PCI, ports=ports),
    )
    return TRexTrafficDriver(config)


def _write_plan(root: Path) -> Path:
    """Write the generated plan fields consumed by the installed kit for this two-port test."""
    rows = ['content_hash: "' + 'ab' * 32 + '"', 'worker_placements {', '  worker_id: "w"', '  worker_index: 0',
            '  region_id: 0', '  cpu_core_ids: 2', '}', 'packet_storage_domains {', '  storage_domain_id: "pool"',
            '  buffer_count: 8192', '  host_numa_node: 0', '}']
    for direction, logical_id, name, stream, mac in (("RX", 1, "wan0", "in", "021"), ("TX", 0, "lan0", "out", "022")):
        rows.extend(('ports {', f'  logical_port_id: {logical_id}', f'  logical_name: "{name}"',
                     '  io_driver_instance_id: "driver"', f'  driver_port_id: "{name}"',
                     f'  direction: PORT_DIRECTION_{direction}_ONLY',
                     rf'  resolved_mac_address: "\002\000\000\000\000\{mac}"', '}',
                     'io_streams {', f'  io_stream_id: "{stream}"', f'  direction: IO_STREAM_DIRECTION_{direction}',
                     f'  logical_port_id: {logical_id}', '  owning_worker_id: "w"', '  lane_id: "lane"',
                     '  driver_queue_id: 0', '  descriptor_count: 2048'))
        rows.extend(('  rx_storage_domain_id: "pool"',) if direction == "RX" else
                    ('  tx_storage {', '    storage_domain_ids: "pool"', '  }'))
        rows.append('}')
    plan = root / "runtime_bundle" / "configs" / "plan.pbtxt"
    plan.parent.mkdir(parents=True)
    plan.write_text("\n".join(rows) + "\n", encoding="ascii")
    return plan


def _stats(rx: int, tx: int, missed: int, rejected: int, epoch: int = 2, module: bool = False) -> StatsResult:
    """Publish a settled bank with known per-stream transfers, NIC misses and terminal refusals."""
    stamp = 1000 + 2 * rx
    mode = WorkerPacketBinding(0, "WORKER_PACKET_REPRESENTATION_FULL_RECORD") if module else WorkerPacketBinding(
        0, "WORKER_PACKET_REPRESENTATION_DIRECT_NATIVE", "in", "out", "pool",
    )
    streams = [
        StreamStatsResult(name, port, direction, 0, 0, 0, stamp - 1, count, count * 60, refused)
        for name, port, direction, count, refused in (("in", 1, "rx", rx, 0), ("out", 0, "tx", tx, rejected))
    ]
    ports = [PortStatsResult(port, name, "driver", name, "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT", stamp,
                             delivered_rx, delivered_tx, delivered_rx * 60, delivered_tx * 60, misses, 0, 0, 0)
             for port, name, delivered_rx, delivered_tx, misses in ((1, "wan0", rx, 0, missed), (0, "lan0", 0, tx, 0))]
    return StatsResult(True, dropped_packets=rejected, active_epoch=epoch, active_revision=epoch - 2,
                       active_snapshot_id=f"configuration-{epoch}", runtime_generation=7, expected_workers=1,
                       collection_monotonic_ns=stamp, transition_state="EPOCH_TRANSITION_STATE_IDLE",
                       transition_plan_content_hash=base64.b64encode(bytes.fromhex("ab" * 32)).decode("ascii"),
                       protocol_fault_counts=dict.fromkeys(PROTOCOL_FAULT_CODES, 0), packet_bindings=[mode],
                       stream_stats=streams, port_stats=ports, storage_domain_stats=[
                           StorageDomainStatsResult("pool", 0, 8192),
                       ])


def _tester(sent: int, received: int, frames: list[str]) -> dict:
    """Produce the native tester's absolute counters and time brackets for a finite or timed send."""
    samples = []
    readings = [(100, 0, 0), (200, sent, received)] if frames else [
        (100, 0, 0), (120, 80, received // 10), (180, sent - 80, received * 9 // 10), (200, sent, received),
    ]
    for stamp, outgoing, incoming in readings:
        samples.append({"before_ns": stamp, "after_ns": stamp + 1, "ports": {
            "0": {"opackets": outgoing, "ipackets": 0, "oerrors": 0, "ierrors": 0},
            "1": {"opackets": 0, "ipackets": incoming, "oerrors": 0, "ierrors": 0},
        }})
    return {"ok": True, "action": "minimum_frame", "pgid_demand": 0, "trex_identity": complete_trex_identity((0, 1)),
            "tx_count": sent, "rx_count": received, "errors": 0, "captured": frames,
            "links": [{"port": port, "speed": 10, "link": "UP"} for port in (0, 1)],
            "port_counter_baseline": samples[0]["ports"], "port_counter_final": samples[-1]["ports"],
            "samples": samples}


async def _record_trial(root: Path, deployment: DeploymentMode, missed: int = 2) -> tuple:
    """Drive the kit with a finite tester and a control plane that activates QoS only through Apply."""
    plan_file = _write_plan(root)
    driver = _driver(root, deployment)
    identity = complete_trex_identity((0, 1))
    driver._trex_identity = identity  # pylint: disable=protected-access
    module = deployment == DeploymentMode.PARSER_QOS
    epoch = 2
    rx = tx = misses = refusals = 0
    context = Mock(spec=ScenarioContext)
    context.config = driver.config
    context.plan_topology = parse_plan_topology(plan_file)
    context.require_traffic.return_value = driver

    async def observe():
        """Publish the transfers completed since the last tester action."""
        return _stats(rx, tx, misses, refusals, epoch, module)

    async def apply(_target, expected_revision):
        """Switch the observed marking only for the active base revision."""
        nonlocal epoch
        if expected_revision != epoch - 2:
            raise ValueError("wrong expected revision")
        epoch += 1
        return ApplyConfigResult(True, f"configuration-{epoch}", epoch - 2, epoch)

    async def exchange(request):
        """Exercise the real driver's request, response and frame validation around the simulated link."""
        nonlocal rx, tx, misses, refusals
        action = driver._validate_remote_request(request)  # pylint: disable=protected-access
        if request["capture"]:
            mark = 10 * (epoch - 1) if module else 0
            frames = driver._minimum_frames(mark)  # pylint: disable=protected-access
            raw = _tester(128, 128, frames * 2)
            rx += 128
            tx += 128
        else:
            raw = _tester(1000, 999 - missed, [])
            rx += 1000 - missed
            tx += 999 - missed
            misses += missed
            refusals += 1
        driver._validate_remote_success(raw, action, request)  # pylint: disable=protected-access
        return raw

    context.get_final_stats_snapshot.side_effect = observe
    context.control = Mock(apply_config=AsyncMock(side_effect=apply))
    context.wait_for_active_snapshot.side_effect = lambda *_args: _stats(rx, tx, misses, refusals, epoch, module)
    host = {"default_routes": [{"interface": "eno1", "gateway_hex": "0100000A", "metric": 0}],
            "pci_network_drivers": {"0000:01:00.0": "vfio-pci"}}
    with patch.object(driver, "_invoke_remote", side_effect=exchange), patch(
        "kinetum_validation.minimum_frame._host_observation", return_value=host,
    ):
        row = await run_minimum_frame(context)
    if row.tx_count is None:
        raise AssertionError(row.message)
    metadata = {"plan_file": str(plan_file), "ports": [asdict(p) for p in driver.config.backend.ports],
                "traffic_endpoint": {"trex_ports": [], "trex_identity": identity}, "worker_topology": {
                    "runtime_generation": 7, "worker_count": 1, "bindings": {
                        "rows": [binding.wire_row() for binding in (await observe()).packet_bindings]}}}
    return metadata, {"pps": 1000, "count": 1000}, {"deployment": deployment.value, "packet_tests": [asdict(row)]}


class MinimumFrameTest(unittest.TestCase):
    """Prove that minimum wire size, observed delivery and reported rate have separate witnesses."""

    def test_exact_wire_templates_and_qos_headers(self):
        """Check all 64 flow identities, full IPv4 and UDP checksums, and the allowed DSCP mutation."""
        driver = _driver()
        for dscp in (0, 10, 20):
            frames = driver._minimum_frames(dscp)  # pylint: disable=protected-access
            self.assertEqual(len(set(frames)), 64)
            for flow, encoded in enumerate(frames):
                frame = bytes.fromhex(encoded)
                self.assertEqual((len(frame), frame[12:14]), (60, b"\x08\x00"))
                ip, udp = frame[14:34], frame[34:]
                self.assertEqual((ip[0], ip[1], int.from_bytes(ip[2:4], "big")), (0x45, dscp << 2, 46))
                self.assertEqual(internet_checksum(ip), 0)
                self.assertEqual(internet_checksum(ip[12:20] + b"\x00\x11\x00\x1a" + udp), 0)
                self.assertEqual(int.from_bytes(udp[:2], "big"), 10000 + flow)
                self.assertEqual(udp[8:], b"KINETUM" + bytes([flow]) + bytes(range(10)))

    def test_nic_miss_and_tx_refusal_are_separate_losses(self):
        """A genuine miss and a refused suffix reconcile once; a changed endpoint cannot hide either."""
        with tempfile.TemporaryDirectory() as directory:
            plan = parse_plan_topology(_write_plan(Path(directory)))
        before = _dut_observation(_stats(100, 100, 0, 0), plan, "passthrough")
        after = _dut_observation(_stats(198, 197, 2, 1), plan, "passthrough")
        trial = {"tx_count": 100, "rx_count": 97}
        _reconcile(before, after, trial)
        for stream, field in ((0, "bytes"), (1, "packets"), (1, "rejected_packets")):
            damaged = copy.deepcopy(after)
            damaged["streams"][stream][field] += 1
            with self.assertRaises(RuntimeError):
                _reconcile(before, damaged, trial)
        for key in ("rx_errors", "rx_no_buffer", "rx_missed"):
            damaged = copy.deepcopy(after)
            damaged["ports"][0][key] += 1
            with self.assertRaises(RuntimeError):
                _reconcile(before, damaged, trial)

    def test_rate_bounds_use_only_the_exercised_port_direction(self):
        """Large changes in the reverse direction do not contribute to offered or returned rate."""
        left = {"before_ns": 10, "after_ns": 12, "ports": {"0": {"opackets": 0}, "1": {"ipackets": 0}}}
        right = {"before_ns": 112, "after_ns": 114,
                 "ports": {"0": {"opackets": 100, "ipackets": 9000}, "1": {"ipackets": 90, "opackets": 9000}}}
        trial = {"ingress_port": 0, "egress_port": 1, "samples": [{}, left, right, {}]}
        rates = packet_rates(trial)
        self.assertEqual(rates["offered"]["upper_pps"], 1e9)
        self.assertEqual(rates["returned"]["lower_pps"], 90e9 / 104)
        right["before_ns"] = 12
        with self.assertRaises(RuntimeError):
            packet_rates(trial)

    def test_live_and_offline_verdicts_agree_for_both_graphs_and_for_measured_loss(self):
        """Fresh kit artifacts must reproduce the capture, Apply, counters and loss verdict for each graph."""
        for deployment in (DeploymentMode.PASSTHROUGH, DeploymentMode.PARSER_QOS):
            for missed in (2, 20, 999):
                with self.subTest(deployment=deployment, missed=missed), tempfile.TemporaryDirectory() as name:
                    root = Path(name).resolve(strict=True)
                    metadata, workload, result = asyncio.run(_record_trial(root, deployment, missed))
                    self.assertEqual(result["packet_tests"][0]["passed"], missed == 2)
                    check_recorded_trial(root, metadata, workload, result)

    def test_offline_reader_requires_independent_frames_counts_and_configuration(self):
        """Reject corrupt artifacts even when both the sender and purported return repeat the same error."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            metadata, workload, result = asyncio.run(_record_trial(root, DeploymentMode.PARSER_QOS))
            path = root / "minimum_frame.json"
            evidence = json.loads(path.read_text(encoding="ascii"))
            for defect in ("checksum", "interior counter", "tester error", "missing Apply", "wrong Apply",
                           "opening epoch", "stale publication", "port map", "NIC availability", "tester link",
                           "host routes", "loss verdict"):
                altered = copy.deepcopy(evidence)
                timed = altered["timed"]
                if defect == "checksum":
                    for frames in (timed["templates"], *(a["captured"] for a in altered["captures"])):
                        for index, frame in enumerate(frames):
                            frames[index] = frame[:80] + "0000" + frame[84:]
                elif defect == "interior counter":
                    for sample in timed["samples"][1:3]:
                        sample["ports"]["0"]["opackets"] += 1000
                elif defect == "tester error":
                    timed["errors"] = 5
                elif defect == "missing Apply":
                    del altered["apply"]
                elif defect == "wrong Apply":
                    altered["apply"]["revision"] += 1
                elif defect == "opening epoch":
                    altered["captures"][0]["configuration"]["epoch"] = -1
                elif defect == "stale publication":
                    altered["after"]["ports"][0]["observed_monotonic_ns"] = altered["before"]["collection_ns"]
                elif defect == "port map":
                    altered["after"]["ports"][0]["driver_port_id"] = "lan0"
                elif defect == "NIC availability":
                    altered["before"]["ports"][0]["observation_state"] = "PROVIDER_OBSERVATION_STATE_UNAVAILABLE"
                elif defect == "tester link":
                    timed["links"][0]["link"] = "DOWN"
                elif defect == "host routes":
                    for edge in ("host_before", "host_after"):
                        altered[edge]["default_routes"] = "eno1"
                elif defect == "loss verdict":
                    altered["passed"] = False
                path.write_text(json.dumps(altered), encoding="ascii")
                with self.subTest(defect=defect), self.assertRaises(ValueError):
                    check_recorded_trial(root, metadata, workload, result)
