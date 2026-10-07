"""
Native TAP traffic driver.

This driver sends packets with the native ``kinetum_tap_sender`` binary over
local Linux TAP ingress interfaces and captures egress traffic with tcpdump.
It is intentionally tied to TAP traffic semantics, while the DPDK TAP backend
only manages interface readiness.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import socket
import struct
from pathlib import Path
from typing import Optional, Tuple

from ..config.logger import log_info, log_warn
from ..process.system_tools import (
    TCPDUMP_EXECUTABLE,
    exact_subprocess_environment,
    require_system_executable,
)
from ..config.types import AnalysisResult, BackendType, PacketConfig, TestConfig
from ..engine.analyzer import PacketAnalyzer
from ..engine.native_sender import NativeSender
from .base import (
    EXCHANGE_PACKET_BYTES,
    EXCHANGE_PACKET_LIMIT,
    EXCHANGE_TIMEOUT_S,
    TrafficDriver,
    validate_udp_exchange,
)


_CAPTURE_RETIRE_TIMEOUT_S = 5.0
_ETH_P_IP = 0x0800
_SIOCGIFHWADDR = 0x8927
_SOL_PACKET = 263
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_MR_PROMISC = 1


class NativeTapTrafficDriver(TrafficDriver):
    """
    Local AF_PACKET/tcpdump traffic driver for DPDK TAP validation.

    Parameters
    ----------
    config : TestConfig
        Full test configuration, including backend port table.
    sender_bin : Path
        Path to the native sender binary.
    analyzer_bin : Path
        Path to the native pcap analyzer binary.
    """

    def __init__(
        self,
        config: TestConfig,
        sender_bin: Path,
        analyzer_bin: Path,
    ) -> None:
        """Initialize one local TAP traffic and capture owner."""
        super().__init__(config)
        self.sender_bin = sender_bin
        self.analyzer_bin = analyzer_bin
        self._capture_proc: Optional[asyncio.subprocess.Process] = None
        self._capture_task: Optional[asyncio.Task] = None
        self._pcap_file: Optional[Path] = None
        self._capture_ready: Optional[asyncio.Event] = None

    @property
    def requires_sustained_generation_overlap(self) -> bool:
        """Return false because SIGUSR1 performs one immediate tag switch."""
        return False

    async def setup(self) -> None:
        """Validate that TAP traffic interfaces are available in the profile."""
        if self.config.backend.backend_type != BackendType.DPDK_TAP:
            raise RuntimeError("native-tap traffic driver requires dpdk-tap backend")
        if not self._ingress_ifaces:
            raise RuntimeError("native-tap traffic driver requires at least one RX port")
        if not self._capture_iface:
            raise RuntimeError("native-tap traffic driver requires one TX capture port")
        log_info(
            "native_tap",
            "traffic driver ready: ingress="
            + ",".join(self._ingress_ifaces)
            + f" capture={self._capture_iface}",
        )

    async def teardown(self) -> None:
        """Stop capture if still running."""
        if self._capture_proc:
            await self.stop_capture()
        log_info("native_tap", "traffic driver torn down")

    async def exchange_udp_packets(
        self, logical_ingress: str, packets: Tuple[bytes, ...], marker: bytes,
    ) -> Tuple[bytes, ...]:
        """Own one bounded raw TAP exchange independently of tcpdump measurement."""
        validate_udp_exchange(packets, marker)
        if self._capture_proc is not None:
            raise RuntimeError("UDP exchange cannot overlap a measurement capture")
        ports = [port for port in self.config.backend.rx_ports if port.logical_name == logical_ingress]
        if len(ports) != 1:
            raise RuntimeError("UDP exchange requires one exact ingress port")
        interface = ports[0].traffic_iface
        capture_index = socket.if_nametoindex(self._capture_iface)
        interface_bytes = interface.encode("ascii")
        if not 0 < len(interface_bytes) < 16:
            raise RuntimeError("TAP exchange interface exceeds IFNAMSIZ")
        observed = []
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_IP)) as receiver, \
                socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_IP)) as sender:
            receiver.bind((self._capture_iface, 0))
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, EXCHANGE_PACKET_LIMIT * 1024)
            receiver.setsockopt(_SOL_PACKET, _PACKET_ADD_MEMBERSHIP,
                                struct.pack("IHH8s", capture_index, _PACKET_MR_PROMISC, 0, b""))
            sender.bind((interface, 0))
            address = fcntl.ioctl(sender.fileno(), _SIOCGIFHWADDR, struct.pack("16s24x", interface_bytes))
            if len(address) != 40 or struct.unpack_from("H", address, 16)[0] != 1:
                raise RuntimeError("TAP exchange interface is not an Ethernet device")
            destination_mac = address[18:24]
            ethernet = destination_mac + bytes.fromhex("024b4e415400") + struct.pack("!H", _ETH_P_IP)
            receiver.setblocking(False)
            sender.setblocking(False)
            try:
                async with asyncio.timeout(EXCHANGE_TIMEOUT_S):
                    for packet in packets:
                        frame = ethernet + packet
                        sent = await loop.sock_sendto(sender, frame, (interface, 0))
                        if sent != len(frame):
                            raise RuntimeError("TAP exchange did not send one complete frame")
                    while len(observed) <= len(packets):
                        frame = await loop.sock_recv(receiver, EXCHANGE_PACKET_BYTES + 15)
                        if frame[12:14] == b"\x08\x00" and frame[42:42 + len(marker)] == marker:
                            if len(frame) > EXCHANGE_PACKET_BYTES + 14:
                                raise RuntimeError("TAP exchange capture exceeded its frame bound")
                            observed.append(frame)
            except TimeoutError:
                pass
        return tuple(observed)

    async def start_capture(self, pcap_file: Path, filter_expr: str) -> None:
        """
        Start packet capture using tcpdump.

        Parameters
        ----------
        pcap_file : Path
            Capture output file.
        filter_expr : str
            BPF filter expression.
        """
        if self._capture_proc:
            raise RuntimeError("capture already running")
        if pcap_file.exists() or pcap_file.is_symlink():
            raise RuntimeError(f"capture output already exists: {pcap_file}")

        tcpdump = require_system_executable(TCPDUMP_EXECUTABLE, "tcpdump")
        cmd = [
            tcpdump,
            "-i", self._capture_iface,
            "-w", str(pcap_file),
            "-B", "131072",  # 128 MB capture buffer.
            "-s", "0",  # Full packet capture.
            filter_expr,
        ]

        log_info("native_tap", f"starting capture: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            env=exact_subprocess_environment(),
        )
        self._capture_proc = process
        self._pcap_file = pcap_file
        ready_waiter: Optional[asyncio.Task] = None
        exit_waiter: Optional[asyncio.Task] = None
        try:
            self._capture_ready = asyncio.Event()
            self._capture_task = asyncio.create_task(
                self._stream_capture_stderr()
            )
            ready_waiter = asyncio.create_task(self._capture_ready.wait())
            exit_waiter = asyncio.create_task(self._capture_proc.wait())
            done, _pending = await asyncio.wait(
                {ready_waiter, exit_waiter, self._capture_task},
                timeout=5.0,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if (
                ready_waiter not in done
                or exit_waiter in done
                or self._capture_task in done
                or self._capture_proc.returncode is not None
            ):
                if self._capture_task in done:
                    stream_error = self._capture_task.exception()
                    if stream_error is not None:
                        raise RuntimeError(
                            "tcpdump output service failed before readiness"
                        ) from stream_error
                if exit_waiter in done or self._capture_proc.returncode is not None:
                    raise RuntimeError(
                        f"tcpdump exited during startup: {self._capture_proc.returncode}"
                    )
                raise RuntimeError("tcpdump did not publish startup readiness")
        except BaseException as start_error:
            try:
                await self._retire_failed_capture_start()
            except BaseException as cleanup_error:
                raise RuntimeError(
                    "tcpdump startup and ownership retirement both failed: "
                    f"startup={start_error}; cleanup={cleanup_error}"
                ) from cleanup_error
            raise
        finally:
            waiters = tuple(
                waiter
                for waiter in (ready_waiter, exit_waiter)
                if waiter is not None
            )
            for waiter in waiters:
                if not waiter.done():
                    waiter.cancel()
            if waiters:
                await asyncio.gather(*waiters, return_exceptions=True)

        log_info("native_tap", f"capture running (PID: {self._capture_proc.pid})")

    async def _retire_failed_capture_start(self) -> None:
        """Terminate the startup child and resolve its output-task ownership."""
        process = self._capture_proc
        task = self._capture_task
        try:
            if process is not None and process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.terminate()
                try:
                    await asyncio.wait_for(
                        process.wait(), timeout=_CAPTURE_RETIRE_TIMEOUT_S
                    )
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                    try:
                        await asyncio.wait_for(
                            process.wait(), timeout=_CAPTURE_RETIRE_TIMEOUT_S
                        )
                    except asyncio.TimeoutError as exc:
                        raise RuntimeError(
                            "tcpdump process ownership did not retire after forced exit"
                        ) from exc
            if task is not None:
                await asyncio.wait_for(
                    task, timeout=_CAPTURE_RETIRE_TIMEOUT_S
                )
        finally:
            process_retired = process is None or process.returncode is not None
            task_retired = task is None or task.done()
            if process_retired and task_retired:
                self._capture_proc = None
                self._capture_task = None
                self._capture_ready = None
                self._pcap_file = None

    async def stop_capture(self) -> None:
        """Stop packet capture and settle child plus output-task ownership."""
        if not self._capture_proc:
            return

        log_info("native_tap", "stopping capture...")
        process = self._capture_proc
        exited_before_stop = process.returncode is not None
        output_ended_before_stop = (
            self._capture_task is not None and self._capture_task.done()
        )
        try:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                await asyncio.wait_for(
                    process.wait(), timeout=_CAPTURE_RETIRE_TIMEOUT_S
                )
            except asyncio.TimeoutError:
                log_warn("native_tap", "force killing tcpdump...")
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                try:
                    await asyncio.wait_for(
                        process.wait(), timeout=_CAPTURE_RETIRE_TIMEOUT_S
                    )
                except asyncio.TimeoutError as exc:
                    raise RuntimeError(
                        "tcpdump process ownership did not retire after forced exit"
                    ) from exc

            if self._capture_task:
                await asyncio.wait_for(
                    self._capture_task, timeout=_CAPTURE_RETIRE_TIMEOUT_S
                )
            if exited_before_stop or output_ended_before_stop:
                raise RuntimeError(
                    "tcpdump exited before harness-requested capture stop"
                )
            if process.returncode != 0:
                raise RuntimeError(
                    f"tcpdump capture exited uncleanly: {process.returncode}"
                )
            log_info("native_tap", "capture stopped; analyzer owns packet count")
        except BaseException as stop_error:
            try:
                await self._retire_failed_capture_start()
            except BaseException as cleanup_error:
                raise RuntimeError(
                    "tcpdump stop and ownership retirement both failed: "
                    f"stop={stop_error}; cleanup={cleanup_error}"
                ) from cleanup_error
            raise
        finally:
            if (
                process.returncode is not None
                and (self._capture_task is None or self._capture_task.done())
            ):
                self._capture_proc = None
                self._capture_task = None
                self._capture_ready = None
                self._pcap_file = None

    async def analyze_capture(
        self,
        pcap_file: Path,
        expected_count: int,
    ) -> AnalysisResult:
        """Analyze one exact native capture with mandatory latency evidence."""
        analyzer = PacketAnalyzer(
            pcap_file=pcap_file,
            analyzer_bin=self.analyzer_bin,
            expected_count=expected_count,
        )
        return analyzer.analyze()

    def make_sender(self, packet_config: PacketConfig) -> NativeSender:
        """Create a native sender bound to TAP ingress interfaces."""
        return NativeSender(self.sender_bin, self._ingress_ifaces, packet_config)

    @property
    def _ingress_ifaces(self) -> list[str]:
        """Return local TAP interfaces used for traffic injection."""
        return [port.traffic_iface for port in self.config.backend.rx_ports]

    @property
    def _capture_iface(self) -> str:
        """Return the local TAP interface used for traffic capture."""
        tx_ports = self.config.backend.tx_ports
        return tx_ports[0].traffic_iface if tx_ports else ""

    async def _stream_capture_stderr(self) -> None:
        """Stream tcpdump stderr output."""
        if not self._capture_proc or not self._capture_proc.stderr:
            return

        async for line in self._capture_proc.stderr:
            text = line.decode("utf-8", errors="replace").strip()
            if text:
                log_info("capture", text)
                if self._capture_ready is not None and "listening on " in text:
                    self._capture_ready.set()
