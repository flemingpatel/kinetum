"""Check canonical gateway NAT ownership through bounded external packet exchanges."""

from __future__ import annotations

import ipaddress
import json
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Dict, Tuple

from .config.types import DeploymentMode, NatExchangeResult
from .engine.json_contract import parse_exact_json_object, require_array, require_int, require_object, require_string
from .process.kinetumctl import ActiveSnapshot
from .process.system_tools import RECOVERABLE_EXCEPTIONS
from .scenario_context import ScenarioContext


_FLOWS_PER_INGRESS = 16
_REMOTE_IP = "198.51.100.9"
_REMOTE_PORT = 49999


def _checksum(data: bytes) -> int:
    """Compute an independent complete Internet checksum, including an odd tail."""
    padded = data + (b"\x00" if len(data) % 2 else b"")
    total = sum(word[0] for word in struct.iter_unpack("!H", padded))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total ^ 0xffff


@dataclass(frozen=True)
class _Datagram:
    """One exact probe tuple and payload, independent of Ethernet and QoS marking."""

    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    payload: bytes

    def encode(self) -> bytes:
        """Build one fixed-header IPv4/UDP datagram with valid complete checksums."""
        source = ipaddress.IPv4Address(self.source_ip).packed
        destination = ipaddress.IPv4Address(self.destination_ip).packed
        udp_length = 8 + len(self.payload)
        udp = struct.pack("!HHHH", self.source_port, self.destination_port, udp_length, 0) + self.payload
        pseudo = source + destination + struct.pack("!BBH", 0, 17, udp_length)
        checksum = _checksum(pseudo + udp)
        udp = udp[:6] + struct.pack("!H", checksum if checksum else 0xffff) + udp[8:]
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_length, 0, 0x4000, 64, 17, 0,
                             source, destination)
        return header[:10] + struct.pack("!H", _checksum(header)) + header[12:] + udp


def _decode_frame(frame: bytes) -> _Datagram:
    """Reject incomplete, fragmented, or checksum-invalid external packet evidence."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x00":
        raise RuntimeError("NAT exchange did not capture a complete Ethernet/IPv4/UDP frame")
    ip = frame[14:]
    total_length = int.from_bytes(ip[2:4], "big")
    if (
        ip[0] != 0x45 or ip[9] != 17 or not 28 <= total_length <= len(ip)
        or int.from_bytes(ip[6:8], "big") & 0x3fff or _checksum(ip[:20]) != 0
    ):
        raise RuntimeError("NAT exchange captured malformed IPv4 header evidence")
    udp = ip[20:total_length]
    if int.from_bytes(udp[4:6], "big") != len(udp) or udp[6:8] == b"\x00\x00":
        raise RuntimeError("NAT exchange UDP length or checksum presence is incorrect")
    pseudo = ip[12:20] + struct.pack("!BBH", 0, 17, len(udp))
    if _checksum(pseudo + udp) != 0:
        raise RuntimeError("NAT exchange transport checksum is invalid")
    return _Datagram(
        str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20])),
        int.from_bytes(udp[:2], "big"), int.from_bytes(udp[2:4], "big"), udp[8:],
    )


def _captured_datagrams(frames: Tuple[bytes, ...], expected: Tuple[_Datagram, ...]) -> Dict[bytes, _Datagram]:
    """Require exactly one complete external observation per requested payload."""
    decoded = [_decode_frame(frame) for frame in frames]
    by_payload = {packet.payload: packet for packet in decoded}
    if len(by_payload) != len(decoded) or set(by_payload) != {packet.payload for packet in expected}:
        raise RuntimeError("NAT exchange capture has missing, duplicate, or foreign packets")
    return by_payload


def _public_ranges(snapshot: ActiveSnapshot) -> Tuple[Tuple[int, int, int, int], ...]:
    """Read allocation ranges from the exact currently active canonical NAT policy."""
    modules = snapshot.module_by_id()
    if "kinetum.nat44" not in modules:
        raise RuntimeError("canonical gateway snapshot lacks its NAT configuration")
    policy = parse_exact_json_object(modules["kinetum.nat44"].config_blob.decode("utf-8"), "active NAT policy")
    ranges = []
    for value in require_array(policy.get("pools"), "active NAT pools"):
        pool = require_object(value, "active NAT pool")
        minimum = require_int(pool.get("port_min"), "NAT minimum port", minimum=1, maximum=65535)
        maximum = require_int(pool.get("port_max"), "NAT maximum port", minimum=minimum, maximum=65535)
        for value in require_array(pool.get("public_ip_ranges"), "NAT address ranges"):
            endpoints = require_string(value, "NAT address range").split("-")
            if len(endpoints) != 2:
                raise RuntimeError("canonical gateway NAT probe requires authored address intervals")
            first, last = (int(ipaddress.IPv4Address(endpoint)) for endpoint in endpoints)
            if first > last:
                raise RuntimeError("NAT address interval is reversed")
            ranges.append((first, last, minimum, maximum))
    if not ranges:
        raise RuntimeError("NAT exchange requires a nonempty active public pool")
    return tuple(ranges)


async def _exchange(context: ScenarioContext, evidence: dict) -> NatExchangeResult:
    """Verify mappings and cross-ingress replies under one unchanged active snapshot."""
    if context.config.deployment != DeploymentMode.FAN_IN_EDGE_GATEWAY:
        raise RuntimeError("NAT exchange belongs only to the canonical fan-in scenario")
    if context.control is None or context.plan_topology is None:
        raise RuntimeError("NAT exchange lacks exact control or plan authority")
    domains = [domain for domain in context.plan_topology.module_context_domains if domain.module_id == "kinetum.nat44"]
    ingress = context.config.backend.rx_ports
    if len(domains) != 1 or len(ingress) != 2 or not domains[0].context_instance_ids:
        raise RuntimeError("canonical gateway NAT ownership or ingress population is incomplete")
    context_count = len(domains[0].context_instance_ids)
    before = await context.control.get_active_snapshot()
    ranges = _public_ranges(before)
    evidence.update({"snapshot_hash": before.content_hash, "contexts": domains[0].context_instance_ids})
    driver = context.require_traffic()
    owners = set()
    public_endpoints = set()
    sessions = 0
    returns = 0
    for ingress_index, port in enumerate(ingress):
        marker = secrets.token_bytes(16)
        original = tuple(
            _Datagram(f"10.123.{ingress_index}.{flow + 1}", _REMOTE_IP, 20000 + flow, _REMOTE_PORT,
                      marker + struct.pack("!H", flow) + b"\x00" * 14)
            for flow in range(_FLOWS_PER_INGRESS)
        )
        frames = await driver.exchange_udp_packets(
            port.logical_name, tuple(packet.encode() for packet in original), marker,
        )
        evidence["exchanges"].append({"leg": "outbound", "ingress": port.logical_name,
                                      "sent": [packet.encode().hex() for packet in original],
                                      "received": [frame.hex() for frame in frames]})
        observed = _captured_datagrams(frames, original)
        replies = []
        expected_returns = []
        return_marker = secrets.token_bytes(16)
        for flow, packet in enumerate(original):
            translated = observed[packet.payload]
            address = int(ipaddress.IPv4Address(translated.source_ip))
            if (translated.destination_ip, translated.destination_port) != (_REMOTE_IP, _REMOTE_PORT) or not any(
                first <= address <= last and low <= translated.source_port <= high
                for first, last, low, high in ranges
            ):
                raise RuntimeError("NAT exchange outbound endpoint is outside the active allocation policy")
            endpoint = (translated.source_ip, translated.source_port)
            if endpoint in public_endpoints:
                raise RuntimeError("independent NAT sessions share a public endpoint for the same remote tuple")
            public_endpoints.add(endpoint)
            owners.add(translated.source_port % context_count)
            payload = return_marker + struct.pack("!H", flow) + b"\x01" * 14
            replies.append(_Datagram(_REMOTE_IP, translated.source_ip, _REMOTE_PORT, translated.source_port, payload))
            expected_returns.append(_Datagram(_REMOTE_IP, packet.source_ip, _REMOTE_PORT, packet.source_port, payload))
        sessions += len(original)
        return_port = ingress[1 - ingress_index].logical_name
        frames = await driver.exchange_udp_packets(
            return_port, tuple(packet.encode() for packet in replies), return_marker,
        )
        evidence["exchanges"].append({"leg": "return", "ingress": return_port,
                                      "sent": [packet.encode().hex() for packet in replies],
                                      "received": [frame.hex() for frame in frames]})
        observed_returns = _captured_datagrams(frames, tuple(expected_returns))
        if any(observed_returns[packet.payload] != packet for packet in expected_returns):
            raise RuntimeError("NAT exchange return packet did not restore its exact private endpoint")
        returns += len(expected_returns)
    after = await context.control.get_active_snapshot()
    if after != before:
        raise RuntimeError("active snapshot changed during NAT exchange")
    if owners != set(range(context_count)):
        raise RuntimeError("NAT exchange did not exercise every compiled session owner")
    return NatExchangeResult(True, sessions, returns, context_count,
                             message=f"{sessions} mappings and {returns} cross-ingress replies verified")


async def run_nat_exchange(context: ScenarioContext) -> NatExchangeResult:
    """Run the canonical NAT check after measurement, retaining exact wire evidence."""
    context.reporter.print_step("NAT EXCHANGE")
    started = time.monotonic()
    evidence: dict = {"exchanges": []}
    try:
        result = await _exchange(context, evidence)
    except RECOVERABLE_EXCEPTIONS as exc:
        result = NatExchangeResult(False, message=str(exc))
    result.duration_s = time.monotonic() - started
    evidence.update({"passed": result.passed, "message": result.message})
    with (context.config.output_dir / "nat_exchange.json").open("x", encoding="utf-8") as output:
        json.dump(evidence, output, allow_nan=False, indent=2, sort_keys=True)
        output.write("\n")
    if result.passed:
        context.reporter.print_progress(result.message)
    else:
        context.reporter.print_error("NAT exchange failed", result.message)
    return result
