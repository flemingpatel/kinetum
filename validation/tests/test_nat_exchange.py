"""Verify packet evidence, canonical scope, and cleanup for the private NAT scenario."""

import asyncio
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from kinetum_validation import nat_exchange
from kinetum_validation.config.types import (
    BackendConfig,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    ProcessConfig,
    StreamTopologyProfile,
    TestConfig as ValidationConfig,
)
from kinetum_validation.engine.plan_metadata import PlanModuleContextDomainMetadata
from kinetum_validation.process.kinetumctl import ActiveSnapshot, SnapshotModule
from kinetum_validation.scenario_context import ScenarioContext
from kinetum_validation.traffic.base import validate_udp_exchange
from kinetum_validation.traffic import native_tap


_ETHERNET = bytes.fromhex("001122334455024b4e4154000800")


def _snapshot() -> ActiveSnapshot:
    """Return exact known module policy bytes for an isolated packet-check fixture."""
    blob = b'{"pools":[{"public_ip_ranges":["192.0.2.1-192.0.2.10"],"port_min":10000,"port_max":60000}]}'
    return ActiveSnapshot(
        snapshot_id="probe_baseline", revision=1, created_unix_ms=1,
        modules=(SnapshotModule("kinetum.nat44", 1, blob, "application/json", hashlib.sha256(blob).hexdigest(), ""),),
        description="", author="", parent_snapshot_id="", labels=(), content_hash="1" * 64,
    )


class _PacketPeer:
    """Supply external frame observations with one independently injected defect."""

    def __init__(self, fault: str = "") -> None:
        """Start an empty mapping population and record every requested ingress."""
        self.fault = fault
        self.mappings = {}
        self.ingresses = []

    async def exchange_udp_packets(self, ingress, packets, marker):
        """Translate the requested tuple or its return, then apply the requested wire fault."""
        validate_udp_exchange(packets, marker)
        self.ingresses.append(ingress)
        frames = []
        for encoded in packets:
            packet = nat_exchange._decode_frame(_ETHERNET + encoded)  # pylint: disable=protected-access
            if packet.source_ip.startswith("10."):
                step = 2 if self.fault == "one_owner" else 1
                public_port = 10000 if self.fault == "collision" else 10000 + step * len(self.mappings)
                self.mappings[public_port] = (packet.source_ip, packet.source_port)
                observed = replace(packet, source_ip="192.0.2.1", source_port=public_port)
            else:
                address, port = self.mappings[packet.destination_port]
                observed = packet if self.fault == "wrong_return" else replace(
                    packet, destination_ip=address, destination_port=port,
                )
            frame = _ETHERNET + observed.encode()
            if self.fault == "checksum":
                frame = frame[:-1] + bytes([frame[-1] ^ 1])
            frames.append(frame)
        if self.fault == "missing":
            frames.pop()
        if self.fault == "duplicate":
            frames.append(frames[0])
        return tuple(frames)


class NatExchangeTest(unittest.IsolatedAsyncioTestCase):
    """Exercise the complete private scenario without a host or traffic generator."""

    def _context(self, root: Path, peer: _PacketPeer) -> ScenarioContext:
        """Bind typed scenario configuration and explicit two-context plan facts."""
        config = ValidationConfig(
            deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
            process=ProcessConfig(runtime_root=root / "runtime", validation_root=root / "kit"),
            backend=BackendConfig(
                backend_type=BackendType.DPDK_PCI,
                ports=DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(BackendType.DPDK_PCI).ports,
            ),
            stream_topology=StreamTopologyProfile.RX_RSS_2,
            output_dir=root,
        )
        control = MagicMock()
        control.get_active_snapshot = AsyncMock(return_value=_snapshot())
        return ScenarioContext(
            config=config, reporter=MagicMock(), traffic=peer, control=control,
            plan_topology=SimpleNamespace(module_context_domains=(
                PlanModuleContextDomainMetadata("kinetum.nat44", ("nat@lane_0", "nat@lane_1")),
            )),
            artifacts=MagicMock(),
        )

    async def test_exact_wire_translation_and_other_ingress_returns(self):
        """All contexts, distinct sessions, checksums, and exact private replies must agree."""
        with tempfile.TemporaryDirectory() as directory:
            peer = _PacketPeer()
            context = self._context(Path(directory), peer)
            result = await nat_exchange.run_nat_exchange(context)
            self.assertTrue(result.passed, result.message)
            self.assertEqual((result.session_count, result.return_count, result.context_count), (32, 32, 2))
            self.assertEqual(peer.ingresses, ["wan0", "wan1", "wan1", "wan0"])
            evidence = json.loads((Path(directory) / "nat_exchange.json").read_text())
            self.assertTrue(evidence["passed"])
            self.assertEqual(len(evidence["exchanges"]), 4)
            context.control.get_active_snapshot.assert_awaited()

    async def test_packet_defects_cannot_become_counter_only_success(self):
        """Missing, duplicate, corrupt, colliding, or misdirected wire evidence fails."""
        for fault in ("missing", "duplicate", "checksum", "collision", "wrong_return", "one_owner"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                result = await nat_exchange.run_nat_exchange(self._context(Path(directory), _PacketPeer(fault)))
                self.assertFalse(result.passed)
                self.assertTrue(result.message)
                self.assertFalse(json.loads((Path(directory) / "nat_exchange.json").read_text())["passed"])

    async def test_snapshot_change_invalidates_packet_evidence(self):
        """No exchange may claim one policy when control authority changed during it."""
        with tempfile.TemporaryDirectory() as directory:
            context = self._context(Path(directory), _PacketPeer())
            context.control.get_active_snapshot.side_effect = [_snapshot(), replace(_snapshot(), revision=2)]
            result = await nat_exchange.run_nat_exchange(context)
            self.assertFalse(result.passed)
            self.assertIn("snapshot changed", result.message)

    async def test_named_scenario_owns_the_probe(self):
        """The presence of a NAT configuration does not opt an arbitrary deployment into the check."""
        with tempfile.TemporaryDirectory() as directory:
            peer = _PacketPeer()
            context = self._context(Path(directory), peer)
            context = replace(context, config=replace(context.config, deployment=DeploymentMode.PASSTHROUGH))
            result = await nat_exchange.run_nat_exchange(context)
            self.assertFalse(result.passed)
            self.assertEqual(peer.ingresses, [])
            context.control.get_active_snapshot.assert_not_awaited()

    def test_checksum_and_capture_bounds(self):
        """Pin an independent checksum vector and reject bytes outside the exchange contract."""
        checksum = nat_exchange._checksum(  # pylint: disable=protected-access
            bytes.fromhex("0001f203f4f5f6f7"),
        )
        self.assertEqual(checksum, 0x220d)
        packet = nat_exchange._Datagram(  # pylint: disable=protected-access
            "10.0.0.1", "198.51.100.9", 1234, 49999, b"m" * 32,
        )
        encoded = packet.encode()
        validate_udp_exchange((encoded,), b"m" * 16)
        for packets, marker in (((encoded,) * 65, b"m" * 16), ((encoded[:-1],), b"m" * 16), ((encoded,), b"x" * 16)):
            with self.subTest(count=len(packets), marker=marker), self.assertRaises(ValueError):
                validate_udp_exchange(packets, marker)

    async def test_tap_exchange_retires_both_sockets_on_every_terminal_edge(self):
        """Captured bytes, socket failures, and cancellation all release the raw socket owners."""
        profile = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(BackendType.DPDK_TAP)
        config = ValidationConfig(
            deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
            process=ProcessConfig(runtime_root=Path("/unused/runtime"), validation_root=Path("/unused/kit")),
            backend=BackendConfig(backend_type=BackendType.DPDK_TAP, ports=profile.ports),
        )
        marker = b"m" * 16
        packet = nat_exchange._Datagram(  # pylint: disable=protected-access
            "10.0.0.1", "198.51.100.9", 1234, 49999, marker,
        ).encode()
        frame = _ETHERNET + packet
        interface_address = b"\x00" * 16 + b"\x01\x00" + b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 16
        loop = asyncio.get_running_loop()
        for edge in ("complete", "send_failed", "receive_failed", "cancelled"):
            with self.subTest(edge=edge):
                receiver, sender = MagicMock(), MagicMock()
                receiver.__enter__.return_value = receiver
                sender.__enter__.return_value = sender
                sockets = MagicMock()
                sockets.socket.side_effect = [receiver, sender]
                sockets.if_nametoindex.return_value = 3
                send = AsyncMock(return_value=len(frame))
                receive = AsyncMock(side_effect=[frame, TimeoutError()])
                failure = None
                if edge == "send_failed":
                    failure = OSError("send failed")
                    send.side_effect = failure
                elif edge == "receive_failed":
                    failure = OSError("receive failed")
                    receive.side_effect = failure
                elif edge == "cancelled":
                    failure = asyncio.CancelledError()
                    receive.side_effect = failure
                driver = native_tap.NativeTapTrafficDriver(config, Path("/unused/sender"), Path("/unused/analyzer"))
                with patch.object(native_tap, "socket", sockets), patch.object(
                    native_tap.fcntl, "ioctl", return_value=interface_address,
                ), patch.object(loop, "sock_sendto", send), patch.object(loop, "sock_recv", receive):
                    if failure is None:
                        self.assertEqual(await driver.exchange_udp_packets("wan0", (packet,), marker), (frame,))
                    else:
                        with self.assertRaises(type(failure)):
                            await driver.exchange_udp_packets("wan0", (packet,), marker)
                receiver.__exit__.assert_called_once()
                sender.__exit__.assert_called_once()
