"""
Traffic-driver abstraction for validation packet generation and capture.

A traffic driver owns the source of test packets, capture timing, timestamp
semantics, and rate-control evidence. Backends own only runtime resources.
Keeping these roles separate lets the same DPDK PCI backend be exercised by
different external traffic generators without changing plan selection or
backend setup.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional, Protocol, Tuple

from ..config.types import (
    AnalysisResult,
    PacketConfig,
    PacketStats,
    TestConfig,
)

EXCHANGE_PACKET_LIMIT = 64
EXCHANGE_PACKET_BYTES = 256
EXCHANGE_MARKER_BYTES = 16
EXCHANGE_TIMEOUT_S = 2.0


def validate_udp_exchange(packets: Tuple[bytes, ...], marker: bytes) -> None:
    """Admit one bounded IPv4/UDP probe prefix before driver effects.

    Each datagram carries the same exact marker at the start of its UDP
    payload. Drivers add only their endpoint's Ethernet header.
    """
    if not isinstance(marker, bytes) or len(marker) != EXCHANGE_MARKER_BYTES:
        raise ValueError("UDP exchange requires one exact 16-byte capture marker")
    if not 0 < len(packets) <= EXCHANGE_PACKET_LIMIT:
        raise ValueError("UDP exchange packet count is outside its bounded prefix")
    for packet in packets:
        if not isinstance(packet, bytes) or not 28 + len(marker) <= len(packet) <= EXCHANGE_PACKET_BYTES:
            raise ValueError("UDP exchange datagram is outside its byte bound")
        observed = (
            packet[0], packet[9], int.from_bytes(packet[2:4], "big"),
            int.from_bytes(packet[24:26], "big"), packet[28:28 + len(marker)],
        )
        if observed != (0x45, 17, len(packet), len(packet) - 20, marker):
            raise ValueError("UDP exchange contains an incomplete or unmarked datagram")


class TrafficSender(Protocol):
    """Runtime protocol implemented by traffic sender objects."""

    async def run_standard(self, duration_s: float) -> PacketStats:
        """Run standard traffic for a fixed duration."""
        raise NotImplementedError

    async def begin_generation_tags(
        self,
        duration_s: float,
        initial_generation_tag: int,
        next_generation_tag: int,
    ) -> None:
        """Own and schedule one generation-tag session.

        The orchestrator proves source activity independently through a
        positive same-identity DP-RX delta before it mutates configuration.
        """
        raise NotImplementedError

    async def start_generation_overlap(self, next_generation_tag: int) -> None:
        """Start sending packets with the next bounded generation tag."""
        raise NotImplementedError

    async def end_generation_overlap(self) -> None:
        """End initial/next generation-tag coexistence when supported."""
        raise NotImplementedError

    async def finish_generation_tags(self) -> PacketStats:
        """Wait for a generation-tag run and return sender statistics."""
        raise NotImplementedError

    async def run_timed(self, duration_s: float) -> PacketStats:
        """Run timed traffic without a changing generation tag."""
        raise NotImplementedError

    def cancel(self) -> None:
        """Request sender shutdown."""
        raise NotImplementedError

    async def abort(self) -> None:
        """Resolve or report every resource held by an active sender session."""
        raise NotImplementedError

    def cleanup(self) -> None:
        """Release sender resources."""
        raise NotImplementedError


class TrafficDriver(ABC):
    """
    Abstract base class for traffic generation and capture.

    Traffic drivers handle:
    - Packet generation and pacing
    - Packet capture windows
    - Timestamp-source ownership
    - Sender lifecycle creation

    The orchestrator consumes only this interface. The harness's physical
    profile selects validation resources; runtime providers remain plan-owned.
    """

    def __init__(self, config: TestConfig) -> None:
        """Bind the immutable run configuration."""
        self.config = config

    @property
    @abstractmethod
    def requires_sustained_generation_overlap(self) -> bool:
        """Return whether the orchestrator must hold both tag streams live."""
        raise NotImplementedError

    @property
    def traffic_generator_identity(self) -> Optional[Dict[str, str]]:
        """Return observed external-generator provenance, when applicable."""
        return None

    @abstractmethod
    async def setup(self) -> None:
        """Initialize traffic-driver resources."""
        raise NotImplementedError

    @abstractmethod
    async def teardown(self) -> None:
        """Release traffic-driver resources."""
        raise NotImplementedError

    @abstractmethod
    async def start_capture(self, pcap_file: Path, filter_expr: str) -> None:
        """
        Start packet capture.

        Parameters
        ----------
        pcap_file : Path
            Capture output file.
        filter_expr : str
            BPF filter expression.
        """
        raise NotImplementedError

    @abstractmethod
    async def stop_capture(self) -> None:
        """Retire active capture ownership, including after interrupted traffic."""
        raise NotImplementedError

    @abstractmethod
    async def analyze_capture(
        self,
        pcap_file: Path,
        expected_count: int,
    ) -> AnalysisResult:
        """
        Analyze the most recent capture window.

        Drivers that produce PCAP files use their exact native analyzer.
        Drivers that rely on generator-side hardware counters return a
        stats-backed result. The selected profile owns latency availability.

        Parameters
        ----------
        pcap_file : Path
            Exact completed capture identity or sidecar stem.
        expected_count : int
            Exact sender population used for accounting.
        Returns
        -------
        AnalysisResult
            Exact packet/counter evidence and optional validated latency.
        """
        raise NotImplementedError

    @abstractmethod
    def make_sender(self, packet_config: PacketConfig) -> TrafficSender:
        """
        Build a sender for a traffic phase.

        The returned object owns its subprocess and any per-run generation-tag
        transition state.
        """
        raise NotImplementedError

    @abstractmethod
    async def exchange_udp_packets(
        self, logical_ingress: str, packets: Tuple[bytes, ...], marker: bytes,
    ) -> Tuple[bytes, ...]:
        """Inject one bounded probe prefix and return complete captured Ethernet frames.

        The exchange owns and retires its capture independently of measurement
        windows. A bounded timeout may return fewer frames; the scenario must
        reject missing, duplicate, or incorrect packet evidence.
        """
        raise NotImplementedError

    def __repr__(self) -> str:
        """Return a stable diagnostic spelling for the selected driver."""
        driver = self.config.backend_profile.traffic_driver.value
        return f"{self.__class__.__name__}(type={driver})"
