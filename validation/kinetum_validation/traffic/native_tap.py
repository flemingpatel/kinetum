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
import json
import re
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
_CAPTURE_STATISTIC_NAMES = {
    "captured": "captured",
    "received by filter": "received_by_filter",
    "dropped by kernel": "dropped_by_kernel",
    "dropped by interface": "dropped_by_interface",
}
_CAPTURE_STATISTIC = re.compile(
    r"([0-9]+) packets? (captured|received by filter|dropped by kernel|dropped by interface)"
)


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
        self._capture_statistics: dict[str, int] = {}
        self._completed_capture: Optional[Tuple[Path, int]] = None

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
        """Retire capture ownership and discard any unconsumed analysis identity."""
        if self._capture_proc:
            await self.stop_capture()
        self._completed_capture = None
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
        if not pcap_file.is_absolute() or pcap_file.suffix != ".pcap":
            raise RuntimeError("capture requires an absolute .pcap output path")
        for output in (pcap_file, pcap_file.with_suffix(".capture.json")):
            if output.exists() or output.is_symlink():
                raise RuntimeError(f"capture output already exists: {output}")

        tcpdump = require_system_executable(TCPDUMP_EXECUTABLE, "tcpdump")
        # Immediate Linux capture reserves fixed-size slots. Bound each slot by
        # every frame this run can send, including transition and size-sweep traffic.
        capture_bytes = max(self.config.packet.packet_size, *self.config.packet.sizes_to_test)
        if capture_bytes <= 0:
            raise RuntimeError("native capture requires a positive frame-size bound")
        cmd = [
            tcpdump,
            "-i", self._capture_iface,
            "-w", str(pcap_file),
            "--immediate-mode",
            "-B", "131072",  # 128 MB capture buffer.
            "-s", str(capture_bytes),
            filter_expr,
        ]

        log_info("native_tap", f"starting capture: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            env={**exact_subprocess_environment(), "LC_ALL": "C"},
            start_new_session=True,
        )
        self._capture_proc = process
        self._pcap_file = pcap_file
        self._capture_statistics = {}
        self._completed_capture = None
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
                    f"startup={type(start_error).__name__}: {start_error}; "
                    f"cleanup={type(cleanup_error).__name__}: {cleanup_error}"
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
                if not task.done():
                    await asyncio.wait_for(task, timeout=_CAPTURE_RETIRE_TIMEOUT_S)
                elif not task.cancelled():
                    # The caller retains the original reader failure. A finished
                    # reader owns no remaining work to retire a second time.
                    task.exception()
        finally:
            process_retired = process is None or process.returncode is not None
            task_retired = task is None or task.done()
            if process_retired and task_retired:
                self._capture_proc = None
                self._capture_task = None
                self._capture_ready = None
                self._pcap_file = None
                self._capture_statistics = {}

    async def stop_capture(self) -> None:
        """Retire tcpdump and require complete delivery into its savefile.

        Retain final counters beside the PCAP even when completion fails. A clean
        Linux capture has equal captured/filter counts and no reported drops;
        the native analyzer independently checks the saved record count later.
        """
        if not self._capture_proc:
            return

        log_info("native_tap", "stopping capture...")
        process = self._capture_proc
        pcap_file = self._pcap_file
        statistics = self._capture_statistics
        capture_error = None
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
            missing = {"captured", "received_by_filter", "dropped_by_kernel"} - statistics.keys()
            if missing:
                raise RuntimeError("tcpdump omitted capture counters: " + ", ".join(sorted(missing)))
            if statistics["dropped_by_kernel"] or statistics.get("dropped_by_interface", 0):
                raise RuntimeError(
                    "tcpdump reported packet drops during capture: "
                    f"captured={statistics['captured']}, received={statistics['received_by_filter']}, "
                    f"kernel={statistics['dropped_by_kernel']}, "
                    f"interface={statistics.get('dropped_by_interface', 'not reported')}"
                )
            if statistics["captured"] != statistics["received_by_filter"]:
                raise RuntimeError(
                    "tcpdump capture is incomplete: "
                    f"captured={statistics['captured']} received_by_filter={statistics['received_by_filter']}"
                )
        except BaseException as stop_error:
            capture_error = str(stop_error) or type(stop_error).__name__
            try:
                await self._retire_failed_capture_start()
            except BaseException as cleanup_error:
                raise RuntimeError(
                    "tcpdump stop and ownership retirement both failed: "
                    f"stop={type(stop_error).__name__}: {stop_error}; "
                    f"cleanup={type(cleanup_error).__name__}: {cleanup_error}"
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
                self._capture_statistics = {}
                if pcap_file is not None:
                    try:
                        with pcap_file.with_suffix(".capture.json").open("x", encoding="utf-8") as output:
                            json.dump({
                                "returncode": process.returncode,
                                "statistics": statistics,
                                "error": capture_error,
                            }, output, allow_nan=False, indent=2, sort_keys=True)
                            output.write("\n")
                    except OSError as exc:
                        raise RuntimeError(
                            "tcpdump evidence could not be retained: "
                            f"capture_error={capture_error}; output_error={exc}"
                        ) from exc
        if pcap_file is None:
            raise RuntimeError("tcpdump completion lost its capture identity")
        self._completed_capture = (pcap_file, statistics["captured"])
        log_info("native_tap", "capture stopped with complete delivery; analyzer will verify the saved count")

    async def analyze_capture(
        self,
        pcap_file: Path,
        expected_count: int,
    ) -> AnalysisResult:
        """Consume the completed capture and cross-check its count before returning evidence."""
        completed = self._completed_capture
        if self._capture_proc is not None or completed is None or completed[0] != pcap_file:
            raise RuntimeError("native analysis does not own the completed capture window")
        try:
            analyzer = PacketAnalyzer(
                pcap_file=pcap_file,
                analyzer_bin=self.analyzer_bin,
                expected_count=expected_count,
                stream_count=len(self._ingress_ifaces),
            )
            result = analyzer.analyze()
            if result.total_rx != completed[1]:
                raise RuntimeError(
                    "native PCAP record count disagrees with tcpdump: "
                    f"pcap={result.total_rx} captured={completed[1]}"
                )
            return result
        finally:
            self._completed_capture = None

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
                if any(text.endswith(name) for name in _CAPTURE_STATISTIC_NAMES):
                    statistic = _CAPTURE_STATISTIC.fullmatch(text)
                    if statistic is None or int(statistic[1]) > (1 << 32) - 1:
                        raise RuntimeError("tcpdump emitted a malformed capture count")
                    name = _CAPTURE_STATISTIC_NAMES[statistic[2]]
                    count = int(statistic[1])
                    if name in self._capture_statistics and count < self._capture_statistics[name]:
                        raise RuntimeError("tcpdump capture count regressed: " + name)
                    self._capture_statistics[name] = count
