# Copyright (c) 2026 Fleming Patel. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Qualify a two-port PCI forwarding workload with independently observed 64-byte wire frames."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import asdict
from pathlib import Path

from .config.types import CONSTANTS, DeploymentMode, PacketConfig, TestResult
from .engine.json_contract import (
    MAX_JSON_DOCUMENT_CHARACTERS, PROTOCOL_FAULT_CODES, packet_binding_rows, parse_exact_json_object,
    require_array, require_bool, require_exact_keys, require_int, require_number, require_object, require_string,
)
from .engine.plan_metadata import PlanTopologyMetadata, decode_resolved_mac_address, parse_plan_topology
from .process.installation import is_symlink_free_regular_file
from .process.system_tools import RECOVERABLE_EXCEPTIONS
from .process.telemetry import StatsResult
from .scenario_context import CONTROL_OBSERVATION_TIMEOUT_S, ScenarioContext
from .traffic.trex import TRexTrafficDriver
from .traffic.trex_protocol import (
    REMOTE_SUCCESS_KEYS, require_minimum_capture, require_minimum_observation, source_mac_for_port,
)
from .traffic.udp import minimum_frames


def _host_observation() -> dict:
    """Read the default IPv4 management route and bindings of the DUT's PCI network controllers."""
    routes = []
    for line in Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]:
        fields = line.split()
        if fields[1] == fields[7] == "00000000" and int(fields[3], 16) & 1:
            routes.append({"interface": fields[0], "gateway_hex": fields[2], "metric": int(fields[6])})
    if not routes:
        raise RuntimeError("DUT lacks an observable default management route")
    devices = {}
    for device in Path("/sys/bus/pci/devices").iterdir():
        if int((device / "class").read_text(encoding="ascii"), 16) >> 16 == 2:
            driver = device / "driver"
            devices[device.name] = driver.resolve(strict=True).name if driver.is_symlink() else None
    routes.sort(key=lambda route: (route["metric"], route["interface"], route["gateway_hex"]))
    return {"default_routes": routes, "pci_network_drivers": devices}


def _configuration(stats: StatsResult) -> dict:
    """Read the active configuration at an idle, fault-free observation of one runtime generation."""
    ScenarioContext.require_active_snapshot_observation(stats, "minimum-frame configuration")
    if (stats.transition_state != "EPOCH_TRANSITION_STATE_IDLE" or stats.transition_success_blocked
            or stats.retirement_frozen or set(stats.protocol_fault_counts) != PROTOCOL_FAULT_CODES
            or any(stats.protocol_fault_counts.values())):
        raise RuntimeError("minimum-frame traffic requires a settled, fault-free runtime")
    return {"generation": stats.runtime_generation, "epoch": stats.active_epoch,
            "plan_hash": base64.b64decode(stats.transition_plan_content_hash, validate=True).hex(),
            "snapshot_id": stats.active_snapshot_id, "revision": stats.active_revision}


def _plan_facts(plan: PlanTopologyMetadata) -> dict:
    """Return the authored worker placement and ring depths for the selected two-port circuit."""
    if (not plan.content_hash or len(plan.workers) != 1 or len(plan.io_streams) != 2
            or len(plan.ports) != 2 or len(plan.storage_domains) != 1):
        raise ValueError("minimum-frame plan lacks its exact worker, port, stream or storage population")
    worker, = plan.workers
    directions = {s.direction for s in plan.io_streams}
    domain = plan.storage_domains[0].storage_domain_id
    if worker.worker_index != 0 or worker.cpu < 0 or directions != {"IO_STREAM_DIRECTION_RX", "IO_STREAM_DIRECTION_TX"}:
        raise ValueError("minimum-frame plan has foreign worker placement or stream directions")
    if any(s.owning_worker_id != worker.worker_id or s.descriptor_count <= 0 or s.storage_domain_ids != (domain,)
           for s in plan.io_streams):
        raise ValueError("minimum-frame stream lacks its worker, descriptors or original storage domain")
    return {"content_hash": plan.content_hash, "worker": asdict(worker),
            "descriptors": {s.io_stream_id: s.descriptor_count for s in plan.io_streams}}


def _check_configuration(value: object, plan_hash: str) -> None:
    """Admit an observed configuration identity for this packed plan."""
    config = require_object(value, "DUT configuration")
    require_exact_keys(config, {"plan_hash", "snapshot_id", "revision", "epoch", "generation"}, "DUT configuration")
    require_string(config["snapshot_id"], "DUT snapshot")
    for key in ("revision", "epoch", "generation"):
        require_int(config[key], f"DUT {key}", minimum=0 if key == "revision" else 1, maximum=(1 << 64) - 1)
    if config["plan_hash"] != plan_hash:
        raise ValueError("DUT telemetry refers to a different packed plan")


def _check_dut(row: dict, plan: PlanTopologyMetadata, deployment: str) -> None:
    """Correlate the saved binding and every counter used in the reduction with the packed plan."""
    _check_configuration(row["configuration"], plan.content_hash)
    binding, = packet_binding_rows({"rows": [row["binding"]]}, 1)
    worker, = plan.workers
    expected = {s.io_stream_id: (worker.worker_index, worker.region_id, s.logical_port_id, s.driver_queue_id,
                                 {"IO_STREAM_DIRECTION_RX": "rx", "IO_STREAM_DIRECTION_TX": "tx"}[s.direction])
                for s in plan.io_streams}
    streams = require_array(row["streams"], "DUT stream counters")
    membership = {s["io_stream_id"]: (s["worker_index"], s["owning_region_id"], s["logical_port_id"],
                                      s["driver_queue_id"], s["direction"]) for s in streams}
    if len(streams) != 2 or membership != expected:
        raise ValueError("DUT stream, queue or worker membership differs from its plan")
    ports = require_array(row["ports"], "DUT port counters")
    port_ids = {(p.logical_port_id, p.logical_name, p.io_driver_instance_id, p.driver_port_id) for p in plan.ports}
    if len(ports) != 2 or port_ids != {
        (p["logical_port_id"], p["logical_name"], p["io_driver_instance_id"], p["driver_port_id"]) for p in ports
    }:
        raise ValueError("DUT driver port map differs from its plan")
    if any(p["observation_state"] != "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT" for p in ports):
        raise ValueError("minimum-frame accounting requires exact DUT port observations")
    domain, = plan.storage_domains
    observed, = require_array(row["domains"], "DUT storage domains")
    if (observed["storage_domain_id"], observed["host_numa_node"], observed["buffer_count"]) != (
            domain.storage_domain_id, domain.host_numa_node, domain.buffer_count):
        raise ValueError("DUT storage ownership or NUMA placement differs from its plan")
    if "native_route" in binding:
        route = binding["native_route"]
        if (deployment != "passthrough" or route["storage_domain_id"] != domain.storage_domain_id
                or {s["io_stream_id"]: s["direction"] for s in streams} !=
                {route["rx_stream_id"]: "rx", route["tx_stream_id"]: "tx"}):
            raise ValueError("DUT native route differs from the exercised graph")
    faults = require_object(row["faults"], "DUT protocol faults")
    require_exact_keys(faults, PROTOCOL_FAULT_CODES, "DUT protocol faults")
    for count in faults.values():
        require_int(count, "DUT protocol faults", minimum=0, maximum=0)
    require_int(row["engine_drops"], "DUT engine drops", minimum=0, maximum=(1 << 64) - 1)


def _dut_observation(stats: StatsResult, plan: PlanTopologyMetadata, deployment: str) -> dict:
    """Keep the native observations used for this endpoint and verify their source identities."""
    if stats.packet_bindings is None or len(stats.packet_bindings) != 1:
        raise RuntimeError("minimum-frame workload lacks its actual worker binding")
    row = {"configuration": _configuration(stats), "binding": stats.packet_bindings[0].wire_row(),
           "collection_ns": stats.collection_monotonic_ns, "streams": [asdict(s) for s in stats.stream_stats],
           "ports": [asdict(p) for p in stats.port_stats], "domains": [asdict(d) for d in stats.storage_domain_stats],
           "engine_drops": stats.dropped_packets, "faults": stats.protocol_fault_counts}
    _check_dut(row, plan, deployment)
    return row


def _reconcile(before: dict, after: dict, trial: dict) -> None:
    """Account for every timed frame using independently bracketed tester, NIC and worker observations."""
    if any(before[key] != after[key] for key in ("configuration", "binding", "faults")):
        raise RuntimeError("DUT identity or fault counters changed during forwarding")
    ports = {row["logical_port_id"]: row for row in before["ports"]}
    final_ports = {row["logical_port_id"]: row for row in after["ports"]}
    streams = {row["io_stream_id"]: row for row in before["streams"]}
    deltas = {}
    opening = require_int(before["collection_ns"], "opening DUT collection", minimum=1, maximum=(1 << 64) - 1)
    closing = require_int(after["collection_ns"], "closing DUT collection", minimum=opening + 1, maximum=(1 << 64) - 1)

    def delta(start: dict, end: dict, key: str) -> int:
        """Require two exact nonregressing cumulative counters before subtraction."""
        initial = require_int(start[key], f"opening {key}", minimum=0, maximum=(1 << 64) - 1)
        return require_int(end[key], f"closing {key}", minimum=initial, maximum=(1 << 64) - 1) - initial

    def publication(start: dict, end: dict, key: str) -> None:
        """Require the second observation to be fresh with respect to the opening DUT collection."""
        require_int(start[key], key, minimum=1, maximum=opening)
        require_int(end[key], key, minimum=opening + 1, maximum=closing)

    for row in after["streams"]:
        prior = streams[row["io_stream_id"]]
        port, final = ports[row["logical_port_id"]], final_ports[row["logical_port_id"]]
        fields = ("rx_packets", "rx_missed", "rx_errors", "rx_no_buffer") if row["direction"] == "rx" else (
            "tx_packets", "tx_errors",
        )
        publication(prior, row, "published_monotonic_ns")
        publication(port, final, "observed_monotonic_ns")
        packets = delta(prior, row, "packets")
        refused = delta(prior, row, "rejected_packets")
        port_deltas = {key: delta(port, final, key) for key in fields}
        if delta(prior, row, "bytes") != packets * 60:
            raise RuntimeError("minimum-frame stream lengths or packet counters disagree")
        deltas[row["direction"]] = (packets, refused, port_deltas)
    received, rx_refused, rx_port = deltas["rx"]
    accepted, tx_refused, tx_port = deltas["tx"]
    dropped = delta(before, after, "engine_drops")
    if any((rx_port["rx_errors"], rx_port["rx_no_buffer"], tx_port["tx_errors"])):
        raise RuntimeError("DUT reported hardware errors or RX buffer exhaustion")
    if not all((
        trial["tx_count"] == rx_port["rx_packets"] + rx_port["rx_missed"],
        rx_port["rx_packets"] == received + rx_refused, received == accepted + dropped,
        dropped == tx_refused, tx_port["tx_packets"] == accepted, trial["rx_count"] == accepted,
    )):
        raise RuntimeError("tester, NIC, worker and refusal counts do not conserve the timed population")


def packet_rates(trial: dict) -> dict:
    """Compute achieved offer and return brackets from the two interior refreshes on one tester clock."""
    left, right = trial["samples"][1:3]
    shortest = right["before_ns"] - left["after_ns"]
    longest = right["after_ns"] - left["before_ns"]
    if not 0 < shortest <= longest:
        raise RuntimeError("minimum-frame samples do not bracket a positive interval")
    result = {}
    for label, key, counter in (("offered", "ingress_port", "opackets"), ("returned", "egress_port", "ipackets")):
        port = str(trial[key])
        amount = right["ports"][port][counter] - left["ports"][port][counter]
        if amount < 0 or (label == "offered" and amount == 0):
            raise RuntimeError("minimum-frame interior counters regressed or the sender made no progress")
        result[label] = {"lower_pps": amount * 1e9 / longest, "upper_pps": amount * 1e9 / shortest,
                         "midpoint_pps": amount * 2e9 / (shortest + longest)}
    return result


def _check_configuration_changes(evidence: dict, module: bool) -> None:
    """Tie the two QoS markings to a successful Apply and the timed run to the last observed configuration."""
    captures = evidence["captures"]
    if len(captures) != (2 if module else 1):
        raise ValueError("minimum-frame preflight capture population is incomplete")
    for capture in captures:
        _check_configuration(capture["configuration"], evidence["plan"]["content_hash"])
    first, last = captures[0]["configuration"], captures[-1]["configuration"]
    if last != evidence["before"]["configuration"] or last != evidence["after"]["configuration"]:
        raise ValueError("minimum-frame timed workload differs from its verified configuration")
    if not module:
        if "apply" in evidence:
            raise ValueError("module-free forwarding includes a foreign Apply")
        return
    applied = require_object(evidence.get("apply"), "minimum-frame Apply")
    require_exact_keys(applied, {"success", "diagnostic", "epoch", "snapshot_id", "revision"}, "minimum-frame Apply")
    if (not require_bool(applied["success"], "Apply success") or applied["diagnostic"] != ""
            or (first["generation"], first["plan_hash"]) != (last["generation"], last["plan_hash"])
            or first["snapshot_id"] == last["snapshot_id"] or not first["epoch"] < last["epoch"]):
        raise ValueError("QoS preflight lacks a completed change in one generation")
    if any(applied[key] != last[key] for key in ("epoch", "snapshot_id", "revision")):
        raise ValueError("Apply identity differs from the observed QoS target")


def check_recorded_trial(run_root: Path, metadata: dict, workload: dict, result: dict) -> None:
    """Check a numeric benchmark sample against its packed plan and retained observations.

    Runs exceeding the loss limit still supply measurements. Raise ValueError if the
    expected frames, configuration change, counter deltas or verdict cannot be reproduced.
    """
    path = run_root / "minimum_frame.json"
    plan_file = run_root / "runtime_bundle" / "configs" / "plan.pbtxt"
    if (not is_symlink_free_regular_file(path) or str(plan_file) != metadata["plan_file"]
            or not is_symlink_free_regular_file(plan_file)):
        raise ValueError("minimum-frame evidence or its packed plan is missing or indirect")
    with path.open(encoding="utf-8") as source:
        evidence = parse_exact_json_object(source.read(MAX_JSON_DOCUMENT_CHARACTERS + 1), "minimum-frame evidence")
    try:
        _check_measured_trial(evidence, run_root, parse_plan_topology(plan_file), metadata, workload, result)
    except (KeyError, TypeError, IndexError, RuntimeError) as exc:
        raise ValueError(f"incomplete or contradictory minimum-frame evidence: {exc}") from exc


def _check_measured_trial(evidence: dict, run_root: Path, plan: PlanTopologyMetadata, metadata: dict,
                          workload: dict, result: dict) -> None:
    """Re-derive the measured verdict using the packed plan, configured tester and benchmark population."""
    module = result["deployment"] == "parser_qos"
    required = {"run_root", "plan", "software_bytes", "wire_bytes", "flow_count", "captures", "passed", "pps",
                "max_loss_pct", "duration_s", "tester_retired", "host_before", "host_after", "before", "after",
                "timed", "rates"}
    require_exact_keys(evidence, required | ({"apply"} if module else set()), "measured minimum-frame evidence")
    if evidence["run_root"] != str(run_root) or evidence["plan"] != _plan_facts(plan):
        raise ValueError("minimum-frame evidence differs from its run directory or packed plan")
    if (evidence["software_bytes"], evidence["wire_bytes"], evidence["flow_count"]) != (60, 64, 64):
        raise ValueError("minimum-frame wire or flow population changed")
    rate = require_int(evidence["pps"], "minimum-frame offered PPS", minimum=1)
    seconds = require_number(evidence["duration_s"], "minimum-frame duration", minimum=0.0)
    if (rate, seconds) != (workload["pps"], workload["count"] / workload["pps"]):
        raise ValueError("minimum-frame offered workload differs from the benchmark manifest")
    endpoint = metadata["traffic_endpoint"]
    ports = metadata["ports"]
    ids = endpoint["trex_ports"] or [p["traffic_port_id"] for p in ports]
    ingress, = [(port_id, p) for port_id, p in zip(ids, ports, strict=True) if p["traffic_role"] == "rx"]
    egress, = [port_id for port_id, p in zip(ids, ports, strict=True) if p["traffic_role"] == "tx"]
    port_id, input_port = ingress
    rx_stream, = [s for s in plan.io_streams if s.direction == "IO_STREAM_DIRECTION_RX"]
    rx_port, = [p for p in plan.ports if p.logical_port_id == rx_stream.logical_port_id]
    destination = decode_resolved_mac_address(rx_port.resolved_mac_address)
    if (input_port["logical_name"], input_port["runtime_mac"]) != (rx_port.logical_name, destination):
        raise ValueError("minimum-frame tester ingress differs from the packed plan")
    packet = PacketConfig()
    source = source_mac_for_port(port_id)
    templates = minimum_frames(packet, source, destination)
    _check_configuration_changes(evidence, module)
    trial = evidence["timed"]
    if trial["templates"] != templates:
        raise ValueError("minimum-frame input templates differ from the benchmark workload")
    for index, action in enumerate([*evidence["captures"], trial]):
        capture = index < len(evidence["captures"])
        extra = {"configuration", "expected_dscp"} if capture else {"templates"}
        require_exact_keys(action, REMOTE_SUCCESS_KEYS["minimum_frame"] | {"ingress_port", "egress_port"} | extra,
                           "minimum-frame action")
        actual_ports = tuple(require_int(action[key], key, minimum=0) for key in ("ingress_port", "egress_port"))
        if actual_ports != (port_id, egress):
            raise ValueError("minimum-frame action used different tester ports")
        require_minimum_observation(action, port_id, egress, endpoint["trex_identity"], capture=capture)
        if capture:
            dscp = (10, 20)[index] if module else 0
            if require_int(action["expected_dscp"], "capture DSCP", minimum=0, maximum=63) != dscp:
                raise ValueError("minimum-frame capture declares a foreign marking")
            require_minimum_capture(action, minimum_frames(packet, source, destination, dscp))
    for row in (evidence["before"], evidence["after"]):
        _check_dut(row, plan, result["deployment"])
    before = evidence["before"]
    topology = metadata["worker_topology"]
    if (topology["runtime_generation"] != before["configuration"]["generation"]
            or topology["bindings"]["rows"] != [before["binding"]]):
        raise ValueError("minimum-frame worker binding differs from run metadata")
    _reconcile(before, evidence["after"], trial)
    rates = packet_rates(trial)
    host = require_object(evidence["host_before"], "opening DUT host observation")
    require_exact_keys(host, {"default_routes", "pci_network_drivers"}, "DUT host observation")
    routes = require_array(host["default_routes"], "DUT default routes")
    devices = require_object(host["pci_network_drivers"], "DUT PCI drivers")
    if (not routes or not devices or host != evidence["host_after"]
            or not require_bool(evidence["tester_retired"], "tester retirement") or rates != evidence["rates"]):
        raise ValueError("minimum-frame lifecycle or rate evidence is contradictory")
    sent, received = trial["tx_count"], trial["rx_count"]
    loss = 100.0 * (sent - received) / sent
    limit = require_number(evidence["max_loss_pct"], "minimum-frame loss limit", minimum=0.0, maximum=100.0)
    row, = result["packet_tests"]
    if (limit != CONSTANTS.MAX_ACCEPTABLE_LOSS_PCT
            or require_bool(evidence["passed"], "traffic verdict") != (received > 0 and loss <= limit)
            or require_bool(row["passed"], "packet verdict") != evidence["passed"]):
        raise ValueError("minimum-frame outcome disagrees with the benchmark loss limit")
    if (row["packet_size"], row["tx_count"], row["rx_count"], row["throughput_pps"], row["loss_pct"]) != (
            64, sent, received, rates["offered"]["midpoint_pps"], loss):
        raise ValueError("minimum-frame packet counts, loss or rate differ from the suite result")


def _finish_evidence(run_root: Path, evidence: dict) -> None:
    """Record the closing host observation and retain any earlier failure before reporting a restoration error."""
    host_error = None
    if "host_before" in evidence:
        try:
            evidence["host_after"] = _host_observation()
            if evidence["host_before"] != evidence["host_after"]:
                host_error = "DUT PCI bindings or the management route changed"
        except RECOVERABLE_EXCEPTIONS as exc:
            host_error = f"DUT closing host observation failed: {exc}"
    if host_error:
        evidence["passed"] = False
        evidence["host_error"] = host_error
    encoded = json.dumps(evidence, allow_nan=False, sort_keys=True, indent=2) + "\n"
    if len(encoded) > MAX_JSON_DOCUMENT_CHARACTERS:
        raise RuntimeError("minimum-frame evidence exceeds the kit document bound")
    with (run_root / "minimum_frame.json").open("x", encoding="utf-8") as output:
        output.write(encoded)
    if host_error:
        raise RuntimeError(host_error)


async def run_minimum_frame(context: ScenarioContext) -> TestResult:
    """Verify the returned frames under each configuration, then measure forwarding with capture disabled.

    The caller supplies a fresh run directory and an admitted two-port TRex driver. A failed
    observation returns a failed result. Cancellation propagates after the scenario records
    its partial evidence. Failure to finalize the evidence raises.
    """
    start = time.monotonic()
    config = context.config
    packet = config.packet
    plan = context.plan_topology
    driver = context.require_traffic()
    if plan is None or not isinstance(driver, TRexTrafficDriver):
        raise RuntimeError("minimum-frame workload requires a packed plan and the TRex PCI circuit")
    evidence = {"run_root": str(config.output_dir), "plan": _plan_facts(plan), "software_bytes": 60,
                "wire_bytes": 64, "flow_count": 64, "captures": [], "passed": False, "pps": packet.pps,
                "max_loss_pct": config.max_loss_pct, "duration_s": packet.duration_s or packet.count / packet.pps,
                "tester_retired": False}

    async def capture(initial: StatsResult, dscp: int) -> StatsResult:
        """Bracket one finite capture with the same active configuration and drain its counters before proceeding."""
        configuration = _configuration(initial)
        action = await driver.minimum_frame(capture=True, expected_dscp=dscp)
        current = await context.get_final_stats_snapshot()
        if _configuration(current) != configuration:
            raise RuntimeError("DUT configuration changed during a minimum-frame capture")
        evidence["captures"].append({**action, "configuration": configuration})
        return current

    try:
        evidence["host_before"] = _host_observation()
        module = config.deployment == DeploymentMode.PARSER_QOS
        stats = await capture(await context.get_final_stats_snapshot(), 10 if module else 0)
        if module:
            if context.control is None or config.spec.config_snapshot_v2 is None:
                raise RuntimeError("parser/QoS workload lacks its target snapshot or control client")
            target = config.input_path(config.spec.config_snapshot_v2)
            applied = await context.control.apply_config(target, expected_revision=stats.active_revision)
            evidence["apply"] = asdict(applied)
            if not applied.success:
                raise RuntimeError(applied.diagnostic)
            active = await context.wait_for_active_snapshot(
                applied.snapshot_id, stats.active_epoch, stats.runtime_generation,
                time.monotonic() + CONTROL_OBSERVATION_TIMEOUT_S,
            )
            if (active.active_epoch, active.active_revision) != (applied.epoch, applied.revision):
                raise RuntimeError("parser/QoS Apply identity differs from the active target")
            stats = await capture(active, 20)
        evidence["before"] = _dut_observation(stats, plan, config.deployment.value)
        trial = await driver.minimum_frame(capture=False)
        evidence["timed"] = trial
        evidence["tester_retired"] = True
        evidence["after"] = _dut_observation(await context.get_final_stats_snapshot(), plan, config.deployment.value)
        _check_configuration_changes(evidence, module)
        _reconcile(evidence["before"], evidence["after"], trial)
        sent, received = trial["tx_count"], trial["rx_count"]
        loss = 100.0 * (sent - received) / sent
        rates = packet_rates(trial)
        evidence["rates"] = rates
        evidence["passed"] = received > 0 and loss <= config.max_loss_pct
        return TestResult(64, evidence["passed"], sent, received, loss, throughput_pps=rates["offered"]["midpoint_pps"],
                          duration_s=time.monotonic() - start, message=f"{sent - received} frames missed")
    except RECOVERABLE_EXCEPTIONS as exc:
        evidence["failure"] = str(exc)
        return TestResult(64, False, duration_s=time.monotonic() - start, message=str(exc))
    except BaseException as exc:
        evidence["failure"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        try:
            _finish_evidence(config.output_dir, evidence)
        except RECOVERABLE_EXCEPTIONS as exc:
            if "failure" in evidence:
                raise RuntimeError(f"{evidence['failure']}; minimum-frame finalization: {exc}") from exc
            raise
