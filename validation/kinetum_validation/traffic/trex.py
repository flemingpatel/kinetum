"""
TRex stateless traffic driver.

The driver controls an already-prepared TRex stateless endpoint over SSH. It
does not start TRex, bind NICs, install packages, or write endpoint
configuration; those setup steps remain explicit operator actions. During
probe/run actions it temporarily enables promiscuous mode on TRex observation
ports so port counters can measure forwarded frames independently of the
dataplane's egress L2 destination behavior. Standard tests consume TRex port
counters. Epoch tests use TRex packet-group counters for generation-tag-separated TX/RX
evidence plus dataplane boundary telemetry for the ordering proof.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import json
import posixpath
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..config.logger import log_info, log_warn
from ..engine.json_contract import (
    MAX_JSON_DOCUMENT_CHARACTERS,
    JsonContractError,
    parse_exact_json_object,
    require_array,
    require_bool,
    require_exact_keys,
    require_int,
    require_number,
    require_object,
    require_string,
    require_trex_identity,
)
from ..process.system_tools import (
    SSH_EXECUTABLE,
    communicate_bounded_subprocess,
    exact_subprocess_environment,
    require_system_executable,
)
from ..config.types import (
    AnalysisResult,
    BackendType,
    PacketConfig,
    PacketStats,
    TestConfig,
)
from .base import EXCHANGE_PACKET_BYTES, TrafficDriver, TrafficSender, validate_udp_exchange
from .trex_remote_script import REMOTE_TREX_SCRIPT as _REMOTE_TREX_SCRIPT


_REMOTE_BOOTSTRAP = (
    "import base64,sys; "
    "exec(base64.b64decode(sys.argv[1]).decode('utf-8'))"
)

_REMOTE_PROBE_TIMEOUT_S = 60.0
_REMOTE_RUN_GRACE_TIMEOUT_S = 120.0
_REMOTE_TERMINATE_GRACE_S = 5.0
_GENERATION_RESPONSE_FIXED_RESERVE_BYTES = 1 << 20
_MIN_ACHIEVEMENT_RATIO = 0.95
_UINT64_MAX = (1 << 64) - 1
_UINT32_MAX = (1 << 32) - 1
_GENERATION_TAG_MAX = (1 << 16) - 1
_REMOTE_TIMESTAMP_SOURCE = "trex_endpoint_monotonic"
_STDERR_WARNING_TOKENS = (
    "error",
    "warn",
    "exception",
    "traceback",
    "failed",
    "failure",
    "timeout",
    "refused",
)
_REMOTE_SUCCESS_KEYS = {
    "exchange_udp": frozenset({"ok", "action", "frames"}),
    "probe": frozenset(
        {
            "ok", "action", "ports", "stats_keys", "promiscuous_ports",
            "work_dir", "trex_identity",
        }
    ),
    "run": frozenset(
        {
            "ok", "action", "tx_count", "rx_count", "errors", "start_time",
            "end_time", "ingress_ports", "egress_ports", "promiscuous_ports",
            "work_dir", "generation_tag_counts", "tag_counts",
            "port_counter_baseline", "port_counter_final",
        }
    ),
    "generation_start": frozenset(
        {
            "ok", "action", "duration_s", "initial_generation_tag",
            "next_generation_tag", "start_time", "start_monotonic",
            "ingress_ports", "egress_ports", "generation_stream_ids",
            "generation_flow_plan", "port_counter_baseline", "promiscuous_ports", "work_dir",
        }
    ),
    "generation_resume_next": frozenset(
        {"ok", "action", "resumed_stream_ids", "next_start_time",
         "next_start_monotonic", "timestamp_source"}
    ),
    "generation_pause_initial": frozenset(
        {"ok", "action", "paused_stream_ids", "initial_pause_time",
         "initial_pause_monotonic", "timestamp_source"}
    ),
    "generation_finish": frozenset(
        {
            "ok", "action", "tx_count", "rx_count", "errors", "port_tx_count",
            "port_rx_count", "start_time", "end_time", "ingress_ports",
            "port_counter_baseline", "port_counter_final",
            "egress_ports", "promiscuous_ports", "work_dir",
            "generation_tag_counts", "tag_counts", "generation_flow_plan",
            "generation_pgid_stats", "generation_overlap_method",
            "transition_time_s_requested", "requested_overlap_window_ms",
            "overlap_window_ms_measured", "overlap_window_timestamp_source",
            "expected_tx_count", "expected_tx_count_source",
            "steady_state_target_pps", "overlap_aggregate_target_pps",
            "start_monotonic", "next_start_time", "initial_pause_time",
            "next_pause_time", "next_start_monotonic",
            "initial_pause_monotonic", "next_pause_monotonic",
        }
    ),
    "generation_abort": frozenset({"ok", "action"}),
}
_REMOTE_RUN_BASE_KEYS = frozenset(
    {
        "duration_s", "pps", "packet_size", "num_flows", "src_ip", "dst_ip",
        "sport", "dport", "ports", "ingress_streams",
        "egress_ports", "trex_server", "trex_api_path", "work_dir", "action",
    }
)
_REMOTE_PACKET_RUN_KEYS = _REMOTE_RUN_BASE_KEYS | {"generation_tag"}
_REMOTE_GENERATION_RUN_KEYS = _REMOTE_RUN_BASE_KEYS | {
    "initial_generation_tag", "next_generation_tag", "transition_time_s",
    "overlap_window_ms",
}
_REMOTE_REQUEST_KEYS = {
    "exchange_udp": frozenset({
        "action", "ports", "egress_ports", "trex_server", "trex_api_path", "work_dir",
        "ingress_stream", "packets", "capture_marker",
    }),
    "probe": frozenset(
        {"action", "ports", "egress_ports", "trex_server", "trex_api_path", "work_dir"}
    ),
    "run": _REMOTE_PACKET_RUN_KEYS | {"mode"},
    "generation_start": _REMOTE_GENERATION_RUN_KEYS,
    "generation_resume_next": frozenset(
        {
            "action", "ports", "ingress_ports", "generation_stream_ids",
            "trex_server", "trex_api_path", "work_dir",
        }
    ),
    "generation_pause_initial": frozenset(
        {
            "action", "ports", "ingress_ports", "generation_stream_ids",
            "trex_server", "trex_api_path", "work_dir",
        }
    ),
    "generation_finish": _REMOTE_GENERATION_RUN_KEYS
    | {
        "ingress_ports", "generation_stream_ids", "generation_flow_plan",
        "port_counter_baseline",
        "start_time", "start_monotonic", "next_start_time",
        "next_start_monotonic", "initial_pause_time",
        "initial_pause_monotonic",
    },
    "generation_abort": frozenset(
        {"action", "ports", "ingress_ports", "egress_ports", "trex_server", "trex_api_path", "work_dir"}
    ),
}


def _generation_counts(value: object, context: str) -> Dict[int, int]:
    """Parse one canonical 16-bit generation-tag counter object."""
    counts = require_object(value, context)
    result: Dict[int, int] = {}
    for tag_text, count_value in counts.items():
        if not tag_text.isascii() or not tag_text.isdecimal():
            raise RuntimeError(f"{context} contains a malformed tag")
        tag = int(tag_text)
        if str(tag) != tag_text or tag > _GENERATION_TAG_MAX:
            raise RuntimeError(f"{context} contains a noncanonical tag")
        result[tag] = require_int(
            count_value, f"{context} count", minimum=0, maximum=_UINT64_MAX
        )
    return result


class TRexSender:
    """Sender facade backed by a TRex stateless traffic run."""

    def __init__(self, driver: "TRexTrafficDriver", packet_config: PacketConfig) -> None:
        """Bind one sender facade to its exact driver and packet profile."""
        self._driver = driver
        self._packet_config = packet_config
        self._cancel_requested = False
        self._generation_session: Optional[Dict[str, Any]] = None
        self._next_generation_started: Optional[Dict[str, Any]] = None
        self._initial_generation_paused: Optional[Dict[str, Any]] = None

    async def run_standard(self, duration_s: float) -> PacketStats:
        """Run standard TRex traffic for a fixed duration."""
        return await self._run(duration_s, mode="standard", generation_tag=0)

    async def begin_generation_tags(
        self,
        duration_s: float,
        initial_generation_tag: int,
        next_generation_tag: int,
    ) -> None:
        """Start initial-generation TRex streams and return once active."""
        if self._cancel_requested:
            raise RuntimeError("trex sender was cancelled before start")
        if self._generation_session is not None:
            raise RuntimeError("trex generation-tag session already active")
        if (
            not 0 <= initial_generation_tag <= 0xFFFF
            or not 0 <= next_generation_tag <= 0xFFFF
            or initial_generation_tag == next_generation_tag
        ):
            raise RuntimeError("trex generation tags are outside the packet profile")
        self._generation_session = await self._driver.start_generation_session(
            packet_config=self._packet_config,
            duration_s=duration_s,
            initial_generation_tag=initial_generation_tag,
            next_generation_tag=next_generation_tag,
        )
        if (
            self._generation_session["initial_generation_tag"]
            != initial_generation_tag
            or self._generation_session["next_generation_tag"]
            != next_generation_tag
            or self._generation_session["duration_s"] != duration_s
        ):
            raise RuntimeError("trex generation session disagrees with its request")

    async def start_generation_overlap(self, next_generation_tag: int) -> None:
        """Resume next-generation streams under orchestrator control."""
        if (
            self._generation_session is None
            or self._next_generation_started is not None
            or self._initial_generation_paused is not None
        ):
            raise RuntimeError("trex generation-tag session was not started")
        if next_generation_tag != self._generation_session["next_generation_tag"]:
            raise RuntimeError("trex overlap tag disagrees with the bound session")
        self._next_generation_started = await self._driver.resume_next_generation(
            session=self._generation_session,
            next_generation_tag=next_generation_tag,
        )
        expected_ids = self._driver.generation_stream_ids(
            self._generation_session, "next"
        )
        if self._next_generation_started["resumed_stream_ids"] != expected_ids:
            raise RuntimeError("trex resumed stream identities disagree with the session")

    async def end_generation_overlap(self) -> None:
        """Pause initial-generation streams and record the overlap end."""
        if self._generation_session is None:
            raise RuntimeError("trex generation-tag session was not started")
        if self._next_generation_started is None:
            raise RuntimeError("trex next generation was not started")
        if self._initial_generation_paused is not None:
            raise RuntimeError("trex initial generation was already paused")
        self._initial_generation_paused = await self._driver.pause_initial_generation(
            session=self._generation_session,
        )
        expected_ids = self._driver.generation_stream_ids(
            self._generation_session, "initial"
        )
        if self._initial_generation_paused["paused_stream_ids"] != expected_ids:
            raise RuntimeError("trex paused stream identities disagree with the session")

    async def finish_generation_tags(self) -> PacketStats:
        """Stop generation-tag traffic and return PGID-backed statistics."""
        if self._generation_session is None:
            raise RuntimeError("trex generation-tag session was not started")
        if (
            self._next_generation_started is None
            or self._initial_generation_paused is None
        ):
            raise RuntimeError("trex generation overlap did not complete both edges")
        raw = await self._driver.finish_generation_session(
            packet_config=self._packet_config,
            session=self._generation_session,
            next_generation_started=self._next_generation_started,
            initial_generation_paused=self._initial_generation_paused,
        )
        # The remote owner is terminal once finish returns. Clear the local
        # claim before fallible result normalization so cleanup cannot issue a
        # second abort against an already retired session.
        self._generation_session = None
        self._next_generation_started = None
        self._initial_generation_paused = None
        return self._stats_from_raw(raw)

    async def run_timed(self, duration_s: float) -> PacketStats:
        """Run timed TRex traffic without changing the generation tag."""
        return await self._run(duration_s, mode="timed", generation_tag=0)

    def cancel(self) -> None:
        """Request cancellation and terminate any active remote action."""
        self._cancel_requested = True
        self._driver.cancel_remote_action()

    async def abort(self) -> None:
        """Stop an owned generation-tag session before releasing its identity."""
        if self._generation_session is None:
            return
        await self._driver.abort_generation_session(self._generation_session)
        self._generation_session = None
        self._next_generation_started = None
        self._initial_generation_paused = None

    def cleanup(self) -> None:
        """Release a sender only after its generation session is terminal."""
        if self._generation_session is not None:
            raise RuntimeError("trex generation session ownership is still live")
        self.cancel()

    async def _run(
        self, duration_s: float, mode: str, generation_tag: int
    ) -> PacketStats:
        """Run one remote TRex action and normalize its raw counters."""
        if self._cancel_requested:
            raise RuntimeError("trex sender was cancelled before start")

        raw = await self._driver.run_remote_traffic(
            packet_config=self._packet_config,
            duration_s=duration_s,
            mode=mode,
            generation_tag=generation_tag,
        )
        return self._stats_from_raw(raw)

    @staticmethod
    def _stats_from_raw(raw: Dict[str, Any]) -> PacketStats:
        """Convert raw TRex counters into the sender stats contract."""
        required = {
            "tx_count", "errors", "start_time", "end_time",
            "generation_tag_counts",
        }
        if not required.issubset(raw):
            raise RuntimeError("TRex sender result omitted required evidence")
        stats = PacketStats(
            tx_count=require_int(
                raw["tx_count"], "TRex tx_count", minimum=0,
                maximum=_UINT64_MAX,
            ),
            errors=require_int(
                raw["errors"], "TRex errors", minimum=0,
                maximum=_UINT64_MAX,
            ),
            start_time=require_number(
                raw["start_time"], "TRex start_time", minimum=0.0
            ),
            end_time=require_number(
                raw["end_time"], "TRex end_time", minimum=0.0
            ),
        )
        stats.generation_tag_counts = _generation_counts(
            raw["generation_tag_counts"], "TRex generation_tag_counts"
        )
        if sum(stats.generation_tag_counts.values()) != stats.tx_count:
            raise RuntimeError("TRex generation-tag counts disagree with TX")
        if stats.end_time < stats.start_time:
            raise RuntimeError("TRex sender timestamps regress")
        return stats


class TRexTrafficDriver(TrafficDriver):
    """TRex-driven physical-NIC traffic driver."""

    def __init__(self, config: TestConfig) -> None:
        """Initialize one endpoint owner from exact validation configuration."""
        super().__init__(config)
        self._capture_file: Optional[Path] = None
        self._completed_capture_file: Optional[Path] = None
        self._capture_filter: str = ""
        self._last_run: Optional[Dict[str, Any]] = None
        self._remote_proc: Optional[asyncio.subprocess.Process] = None
        self._remote_kill_task: Optional[asyncio.Task[None]] = None
        self._active_generation_session: Optional[Dict[str, Any]] = None
        self._trex_identity: Optional[Dict[str, str]] = None
        self._udp_exchange_incomplete = False

    @property
    def requires_sustained_generation_overlap(self) -> bool:
        """Return true because both TRex tag streams overlap by explicit time."""
        return True

    @property
    def traffic_generator_identity(self) -> Optional[Dict[str, str]]:
        """Return the TRex identity admitted by the setup probe."""
        return None if self._trex_identity is None else dict(self._trex_identity)

    async def setup(self) -> None:
        """Validate endpoint connectivity and egress observation capability."""
        if self._trex_identity is not None:
            raise RuntimeError("trex traffic driver is already initialized")
        if self.config.backend.backend_type != BackendType.DPDK_PCI:
            raise RuntimeError("trex traffic driver requires dpdk-pci backend")
        if not self.config.traffic.host:
            raise RuntimeError("--traffic-host is required for trex traffic")
        if not self._ingress_port_ids:
            raise RuntimeError("trex traffic requires at least one RX traffic port")
        if not self._egress_port_ids:
            raise RuntimeError("trex traffic requires at least one TX traffic port")
        ingress_streams = self._ingress_streams

        await self._invoke_remote({
            "action": "probe",
            "ports": self._all_port_ids,
            "egress_ports": self._egress_port_ids,
            "trex_server": self.config.traffic.trex_server,
            "trex_api_path": self.config.traffic.trex_api_path,
            "work_dir": self.config.traffic.work_dir,
        })
        if self._trex_identity is None:
            raise RuntimeError("trex probe omitted its admitted identity")
        log_info(
            "trex",
            "traffic driver ready: ingress="
            + ",".join(str(stream["port_id"]) for stream in ingress_streams)
            + " egress="
            + ",".join(str(p) for p in self._egress_port_ids)
            + " version="
            + self._trex_identity["version"],
        )

    async def teardown(self) -> None:
        """Stop every retained remote session before releasing local state."""
        # Cancellation and unexpected session failure must not skip the
        # independent SSH-process owner.
        failure: Optional[BaseException] = None
        if self._active_generation_session is not None:
            try:
                await self.abort_generation_session(
                    self._active_generation_session
                )
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                failure = exc
        try:
            self.cancel_remote_action()
            await self._await_remote_kill_task()
        except BaseException as exc:  # pylint: disable=broad-exception-caught
            if failure is not None:
                failure = RuntimeError(
                    "trex session and remote process retirement both failed: "
                    f"session={failure}; process={exc}"
                )
            else:
                failure = exc
        if self._udp_exchange_incomplete:
            raise RuntimeError(
                "trex UDP capture retirement is unproved"
                + (f"; other cleanup failure: {failure}" if failure is not None else "")
            ) from failure
        if failure is not None:
            raise failure
        self._capture_file = None
        self._completed_capture_file = None
        self._capture_filter = ""
        self._trex_identity = None
        log_info("trex", "traffic driver torn down")

    async def start_capture(self, pcap_file: Path, filter_expr: str) -> None:
        """
        Start a TRex stats-backed capture window.

        TRex port counters are used as capture evidence; no PCAP file is
        produced by this driver.
        """
        if self._capture_file is not None or self._completed_capture_file is not None or self._udp_exchange_incomplete:
            raise RuntimeError("trex capture ownership already active")
        try:
            exact_parent = pcap_file.parent.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError("trex capture output parent is unavailable") from exc
        sidecar = pcap_file.with_suffix(".trex_stats.json")
        path_exact = all((
            pcap_file.is_absolute(),
            exact_parent == pcap_file.parent,
            not pcap_file.exists(),
            not pcap_file.is_symlink(),
            not sidecar.exists(),
            not sidecar.is_symlink(),
        ))
        filter_exact = (
            isinstance(filter_expr, str)
            and bool(filter_expr)
            and len(filter_expr.encode("utf-8")) <= 512
            and filter_expr.isprintable()
        )
        if not path_exact or not filter_exact:
            raise RuntimeError("trex capture request is outside its exact domain")
        self._capture_file = pcap_file
        self._capture_filter = filter_expr
        self._last_run = None
        log_info("trex", f"stats capture window started ({filter_expr})")

    async def stop_capture(self) -> None:
        """Retire the window; only a completed run transfers evidence to analysis."""
        if self._capture_file is None:
            return
        try:
            if self._last_run is None:
                log_info("trex", "stats capture window retired without completed traffic")
                return
            rx_count = require_int(
                self._last_run["rx_count"], "TRex rx_count", minimum=0,
                maximum=_UINT64_MAX,
            )
            log_info("trex", f"stats capture window stopped, {rx_count} packets")
            self._completed_capture_file = self._capture_file
        finally:
            self._capture_file = None
            self._capture_filter = ""

    async def analyze_capture(
        self,
        pcap_file: Path,
        expected_count: int,
    ) -> AnalysisResult:
        """Build counter evidence with explicit latency unavailability."""
        if self.config.backend_profile.latency_source is not None:
            raise RuntimeError("trex latency availability disagrees with its profile")
        if self._last_run is None:
            raise RuntimeError("trex analysis requested before a traffic run completed")
        if self._completed_capture_file != pcap_file:
            raise RuntimeError("trex analysis does not own the completed capture window")
        if (
            self._trex_identity is None
            or require_trex_identity(
                self._last_run.get("trex_identity"), "TRex sidecar identity"
            )
            != self._trex_identity
        ):
            raise RuntimeError("trex sidecar identity disagrees with its setup probe")

        _, rx_count = self._validated_port_totals(self._last_run)
        valid = min(rx_count, expected_count)
        result = AnalysisResult(
            total_rx=rx_count,
            valid=valid,
            duplicates=max(0, rx_count - expected_count),
            missing_count=max(0, expected_count - rx_count),
        )
        for generation_tag, count in self._last_run["tag_counts"].items():
            result.tag_counts[int(generation_tag)] = int(count)
        self._validate_generation_sidecar_evidence()
        achievement_ratio = require_number(
            self._last_run["achievement_ratio"],
            "TRex achievement_ratio",
            minimum=0.0,
        )
        if achievement_ratio < _MIN_ACHIEVEMENT_RATIO:
            target_pps = require_int(
                self._last_run["target_pps"], "TRex target_pps", minimum=1,
                maximum=1_000_000_000,
            )
            tx_count = require_int(
                self._last_run["tx_count"], "TRex tx_count", minimum=0,
                maximum=_UINT64_MAX,
            )
            expected_tx_count = require_int(
                self._last_run["expected_tx_count"],
                "TRex expected_tx_count",
                minimum=1,
                maximum=_UINT64_MAX,
            )
            raise RuntimeError(
                f"trex achieved only {achievement_ratio * 100.0:.1f}% "
                f"of target traffic (target_pps={target_pps}, "
                f"tx_count={tx_count}, expected_tx_count={expected_tx_count})"
            )
        sidecar = pcap_file.with_suffix(".trex_stats.json")
        sidecar_bytes = json.dumps(
            self._last_run,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        with open(sidecar, "x", encoding="utf-8") as stream:
            stream.write(sidecar_bytes)
        self._completed_capture_file = None
        log_info("trex", f"stats analysis saved to {sidecar}")
        return result

    def _validate_generation_sidecar_evidence(self) -> None:
        """
        Fail closed when TRex generation-tag evidence cannot prove the workload shape.

        PGID counters are sidecar evidence for the traffic generator, not the
        dataplane's authority for boundary correctness. For generation-overlap
        runs they must still prove that both traffic classes were transmitted
        and observed, and that the initial/next overlap window was measured.
        """
        if self._last_run["action"] != "generation_finish":
            return

        tx_generations = self._positive_generation_set("generation_tag_counts")
        rx_generations = self._positive_generation_set("tag_counts")
        observed_generations = tx_generations & rx_generations
        if len(observed_generations) != 2:
            raise RuntimeError(
                "trex generation evidence invalid: expected exactly two tag "
                "classes with nonzero TX and RX counters"
            )

        try:
            overlap_ms = require_number(
                self._last_run["overlap_window_ms_measured"],
                "TRex measured generation overlap",
                minimum=0.0,
            )
        except (JsonContractError, KeyError) as exc:
            raise RuntimeError(
                "trex generation evidence invalid: measured overlap window is malformed"
            ) from exc
        if overlap_ms <= 0.0:
            raise RuntimeError(
                "trex generation evidence invalid: measured overlap window is not positive"
            )

    def _positive_generation_set(self, key: str) -> Set[int]:
        """Return generation tags whose exact sidecar counter is positive."""
        return {
            generation_tag
            for generation_tag, count in _generation_counts(
                self._last_run[key], "TRex generation counts"
            ).items()
            if count > 0
        }

    def make_sender(self, packet_config: PacketConfig) -> TrafficSender:
        """Create a TRex sender bound to configured traffic-generator ports."""
        return TRexSender(self, packet_config)

    async def run_remote_traffic(
        self,
        packet_config: PacketConfig,
        duration_s: float,
        mode: str,
        generation_tag: int,
    ) -> Dict[str, Any]:
        """Run one TRex traffic phase and persist the raw endpoint counters."""
        raw = await self._invoke_remote({
            **self._packet_run_spec(packet_config, duration_s, generation_tag),
            "action": "run",
            "mode": mode,
        })
        expected_tags = {generation_tag}
        if (
            set(_generation_counts(
                raw["generation_tag_counts"], "TRex TX generation tags"
            )) != expected_tags
            or set(_generation_counts(
                raw["tag_counts"], "TRex RX generation tags"
            )) != expected_tags
        ):
            raise RuntimeError("trex one-shot generation tag disagrees with its request")
        return self._record_run(raw, packet_config, duration_s)

    async def start_generation_session(
        self,
        packet_config: PacketConfig,
        duration_s: float,
        initial_generation_tag: int,
        next_generation_tag: int,
    ) -> Dict[str, Any]:
        """
        Start an orchestrator-controlled TRex generation-tag session.

        The endpoint creates both PGID stream sets up front, starts only the
        initial generation, and returns after TRex accepts the command.
        """
        if self._active_generation_session is not None:
            raise RuntimeError("trex generation session ownership overlaps")
        request = {
            **self._generation_run_spec(
                packet_config,
                duration_s,
                initial_generation_tag,
                next_generation_tag,
            ),
            "action": "generation_start",
        }
        self._validate_remote_request(request)
        provisional_session = {
            "ingress_ports": self._ingress_port_ids,
            "egress_ports": self._egress_port_ids,
        }
        self._active_generation_session = provisional_session
        try:
            session = await self._invoke_remote(request)
        except BaseException:
            try:
                await self.abort_generation_session(provisional_session)
            except BaseException as cleanup_error:
                raise RuntimeError(
                    "trex generation start failed with unresolved remote ownership"
                ) from cleanup_error
            raise
        self._active_generation_session = session
        return session

    async def resume_next_generation(
        self,
        session: Dict[str, Any],
        next_generation_tag: int,
    ) -> Dict[str, Any]:
        """Resume the paused next-generation TRex streams."""
        if self._active_generation_session is not session:
            raise RuntimeError("trex resume session ownership is foreign")
        self._require_generation_stream_port_membership(session)
        if require_int(
            session["next_generation_tag"], "TRex next generation tag",
            minimum=0, maximum=_GENERATION_TAG_MAX,
        ) != next_generation_tag:
            raise RuntimeError("trex resumed tag disagrees with its session")
        return await self._invoke_remote({
            "action": "generation_resume_next",
            "ports": self._all_port_ids,
            "ingress_ports": session["ingress_ports"],
            "generation_stream_ids": session["generation_stream_ids"],
            "trex_server": self.config.traffic.trex_server,
            "trex_api_path": self.config.traffic.trex_api_path,
            "work_dir": self.config.traffic.work_dir,
        })

    async def pause_initial_generation(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Pause initial-generation streams after the overlap window."""
        if self._active_generation_session is not session:
            raise RuntimeError("trex pause session ownership is foreign")
        self._require_generation_stream_port_membership(session)
        return await self._invoke_remote({
            "action": "generation_pause_initial",
            "ports": self._all_port_ids,
            "ingress_ports": session["ingress_ports"],
            "generation_stream_ids": session["generation_stream_ids"],
            "trex_server": self.config.traffic.trex_server,
            "trex_api_path": self.config.traffic.trex_api_path,
            "work_dir": self.config.traffic.work_dir,
        })

    async def finish_generation_session(
        self,
        packet_config: PacketConfig,
        session: Dict[str, Any],
        next_generation_started: Dict[str, Any],
        initial_generation_paused: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Stop a generation-tag session and persist PGID-backed evidence."""
        if self._active_generation_session is not session:
            raise RuntimeError("trex generation session ownership is foreign")
        raw = await self._invoke_remote({
            **self._generation_run_spec(
                packet_config,
                float(session["duration_s"]),
                int(session["initial_generation_tag"]),
                int(session["next_generation_tag"]),
            ),
            "action": "generation_finish",
            "ingress_ports": session["ingress_ports"],
            "generation_stream_ids": session["generation_stream_ids"],
            "generation_flow_plan": session["generation_flow_plan"],
            "port_counter_baseline": session["port_counter_baseline"],
            "start_time": session["start_time"],
            "start_monotonic": session["start_monotonic"],
            "next_start_time": next_generation_started["next_start_time"],
            "next_start_monotonic": next_generation_started["next_start_monotonic"],
            "initial_pause_time": initial_generation_paused["initial_pause_time"],
            "initial_pause_monotonic": initial_generation_paused["initial_pause_monotonic"],
        })
        session_echo_exact = all((
            raw["generation_flow_plan"] == session["generation_flow_plan"],
            raw["start_time"] == session["start_time"],
            raw["start_monotonic"] == session["start_monotonic"],
            raw["next_start_time"] == next_generation_started["next_start_time"],
            raw["next_start_monotonic"]
            == next_generation_started["next_start_monotonic"],
            raw["initial_pause_time"]
            == initial_generation_paused["initial_pause_time"],
            raw["initial_pause_monotonic"]
            == initial_generation_paused["initial_pause_monotonic"],
        ))
        request_echo_exact = all((
            raw["steady_state_target_pps"] == packet_config.pps,
            raw["requested_overlap_window_ms"]
            == self.config.epoch.overlap_window_ms,
            raw["transition_time_s_requested"]
            == self.config.epoch.transition_time_s,
            set(_generation_counts(
                raw["generation_tag_counts"], "TRex TX generation tags"
            ))
            == {
                int(session["initial_generation_tag"]),
                int(session["next_generation_tag"]),
            },
        ))
        if not session_echo_exact or not request_echo_exact:
            raise RuntimeError("trex finished session identity disagrees")
        start_monotonic = require_number(
            raw["start_monotonic"], "TRex monotonic start", minimum=0.0
        )
        initial_pause_monotonic = require_number(
            raw["initial_pause_monotonic"],
            "TRex initial pause sample", minimum=0.0,
        )
        next_start_monotonic = require_number(
            raw["next_start_monotonic"],
            "TRex next start sample", minimum=0.0,
        )
        next_pause_monotonic = require_number(
            raw["next_pause_monotonic"],
            "TRex next pause sample", minimum=0.0,
        )
        measured_active_seconds = (
            initial_pause_monotonic - start_monotonic
            + next_pause_monotonic - next_start_monotonic
        )
        if measured_active_seconds <= 0.0:
            raise RuntimeError("trex measured generation intervals regress")
        expected_tx_count = int(round(
            float(packet_config.pps) * measured_active_seconds
        ))
        if expected_tx_count <= 0 or expected_tx_count > _UINT64_MAX:
            raise RuntimeError("trex measured expected TX is outside its domain")
        if require_int(
            raw["expected_tx_count"], "TRex expected TX", minimum=1,
            maximum=_UINT64_MAX,
        ) != expected_tx_count:
            raise RuntimeError(
                "trex expected TX disagrees with the local run contract"
            )
        result = self._record_run(
            raw,
            packet_config,
            float(session["duration_s"]),
            expected_tx_count=expected_tx_count,
        )
        self._active_generation_session = None
        return result

    async def abort_generation_session(self, session: Dict[str, Any]) -> None:
        """Stop and release the exact active TRex generation-tag session."""
        if self._active_generation_session is not session:
            raise RuntimeError("trex abort session ownership is foreign")
        await self._invoke_remote({
            "action": "generation_abort",
            "ports": self._all_port_ids,
            "ingress_ports": session["ingress_ports"],
            "egress_ports": self._egress_port_ids,
            "trex_server": self.config.traffic.trex_server,
            "trex_api_path": self.config.traffic.trex_api_path,
            "work_dir": self.config.traffic.work_dir,
        })
        self._active_generation_session = None

    def _packet_run_spec(
        self,
        packet_config: PacketConfig,
        duration_s: float,
        generation_tag: int,
    ) -> Dict[str, Any]:
        """Build one exact packet-run specification without transition residue."""
        return {
            "duration_s": duration_s,
            "pps": packet_config.pps,
            "packet_size": packet_config.packet_size,
            "num_flows": packet_config.num_flows,
            "src_ip": packet_config.src_ip,
            "dst_ip": packet_config.dst_ip,
            "sport": packet_config.base_sport,
            "dport": packet_config.base_dport,
            "generation_tag": generation_tag,
            "ports": self._all_port_ids,
            "ingress_streams": self._ingress_streams,
            "egress_ports": self._egress_port_ids,
            "trex_server": self.config.traffic.trex_server,
            "trex_api_path": self.config.traffic.trex_api_path,
            "work_dir": self.config.traffic.work_dir,
        }

    def _generation_run_spec(
        self,
        packet_config: PacketConfig,
        duration_s: float,
        initial_generation_tag: int,
        next_generation_tag: int,
    ) -> Dict[str, Any]:
        """Build one exact generation-session specification."""
        spec = self._packet_run_spec(
            packet_config,
            duration_s,
            initial_generation_tag,
        )
        del spec["generation_tag"]
        spec.update({
            "initial_generation_tag": initial_generation_tag,
            "next_generation_tag": next_generation_tag,
            "transition_time_s": self.config.epoch.transition_time_s,
            "overlap_window_ms": self.config.epoch.overlap_window_ms,
        })
        return spec

    def _record_run(
        self,
        raw: Dict[str, Any],
        packet_config: PacketConfig,
        duration_s: float,
        expected_tx_count: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Attach local metadata to raw endpoint counters and retain them."""
        if self._trex_identity is None:
            raise RuntimeError("trex run completed without setup provenance")
        raw["target_pps"] = packet_config.pps
        if expected_tx_count is None:
            expected_tx_count = int(round(float(packet_config.pps) * duration_s))
        if expected_tx_count <= 0 or expected_tx_count > _UINT64_MAX:
            raise RuntimeError(
                "trex locally derived expected TX is outside its domain"
            )
        if "expected_tx_count" in raw and require_int(
            raw["expected_tx_count"], "TRex expected_tx_count", minimum=1,
            maximum=_UINT64_MAX,
        ) != expected_tx_count:
            raise RuntimeError(
                "trex remote expected TX disagrees with local derivation"
            )
        raw["expected_tx_count"] = expected_tx_count
        raw["achievement_ratio"] = (
            require_int(
                raw["tx_count"], "TRex tx_count", minimum=0,
                maximum=_UINT64_MAX,
            )
            / expected_tx_count
        )
        raw["capture_filter"] = self._capture_filter
        raw["timestamp_source"] = self.config.backend_profile.timestamp_source
        raw["rate_control_source"] = self.config.backend_profile.rate_control_source
        raw["trex_identity"] = dict(self._trex_identity)
        self._last_run = raw
        return raw

    @staticmethod
    def _generation_result_extent_bound(
        ingress_streams: List[Dict[str, Any]],
        num_flows: int,
    ) -> int:
        """Derive a conservative bound for the largest generation result."""
        # Endpoint JSON is ASCII because json.dumps keeps ensure_ascii enabled.
        # One MiB covers every non-repeated field, bounded endpoint string,
        # array/object delimiter, and future scalar-width margin; repeated flow
        # and PGID rows are charged explicitly below.
        extent = _GENERATION_RESPONSE_FIXED_RESERVE_BYTES
        for stream in ingress_streams:
            for role in ("pre_overlap", "post_overlap"):
                plan_row = {
                    "pg_id": _UINT32_MAX,
                    "generation_tag": _GENERATION_TAG_MAX,
                    "logical_name": stream["logical_name"],
                    "port_id": stream["port_id"],
                    "flow_id": num_flows - 1,
                    "role": role,
                    "expected_tx": _UINT64_MAX,
                }
                observation_row = {
                    key: value
                    for key, value in plan_row.items()
                    if key != "pg_id"
                }
                observation_row.update({
                    "tx_pkts": _UINT64_MAX,
                    "rx_pkts": _UINT64_MAX,
                })
                plan_row_size = len(json.dumps(
                    plan_row, allow_nan=False, separators=(",", ":")
                ).encode("utf-8"))
                observation_row_size = len(json.dumps(
                    observation_row, allow_nan=False, separators=(",", ":")
                ).encode("utf-8"))
                # One comma per array/object member and a quoted uint32 PGID
                # key conservatively complete the repeated JSON framing.
                extent += num_flows * (
                    plan_row_size + observation_row_size + 16
                )
            # Each role contributes one maximal uint32 stream ID plus comma.
            extent += num_flows * 22
        return extent

    async def exchange_udp_packets(
        self, logical_ingress: str, packets: Tuple[bytes, ...], marker: bytes,
    ) -> Tuple[bytes, ...]:
        """Use TRex's bounded packet capture after the measurement window retires."""
        validate_udp_exchange(packets, marker)
        if (self._capture_file is not None or self._remote_proc is not None
                or self._active_generation_session is not None or self._udp_exchange_incomplete):
            raise RuntimeError("UDP exchange cannot overlap a measurement capture")
        streams = [stream for stream in self._ingress_streams if stream["logical_name"] == logical_ingress]
        if len(streams) != 1:
            raise RuntimeError("UDP exchange requires one exact ingress stream")
        result = await self._invoke_remote({
            "action": "exchange_udp",
            "ports": self._all_port_ids,
            "egress_ports": self._egress_port_ids,
            "trex_server": self.config.traffic.trex_server,
            "trex_api_path": self.config.traffic.trex_api_path,
            "work_dir": self.config.traffic.work_dir,
            "ingress_stream": streams[0],
            "packets": [packet.hex() for packet in packets],
            "capture_marker": marker.hex(),
        })
        self._udp_exchange_incomplete = False
        return tuple(bytes.fromhex(frame) for frame in result["frames"])

    def _validate_udp_exchange_request(self, spec: Dict[str, Any]) -> None:
        """Admit exact endpoint ownership and canonical datagram bytes before SSH."""
        ingress = require_object(spec["ingress_stream"], "UDP exchange ingress")
        if ingress not in self._ingress_streams:
            raise RuntimeError("UDP exchange ingress differs from the resolved traffic endpoint")
        values = require_array(spec["packets"], "UDP exchange packets")
        marker = require_string(spec["capture_marker"], "UDP exchange marker")
        try:
            packets = tuple(bytes.fromhex(require_string(value, "UDP exchange packet")) for value in values)
            marker_bytes = bytes.fromhex(marker)
        except ValueError as exc:
            raise RuntimeError("UDP exchange contains malformed hexadecimal bytes") from exc
        if [packet.hex() for packet in packets] != values or marker_bytes.hex() != marker:
            raise RuntimeError("UDP exchange hexadecimal bytes are noncanonical")
        validate_udp_exchange(packets, marker_bytes)

    def _validate_remote_request(self, spec: Dict[str, Any]) -> str:
        """Validate one complete endpoint request before starting SSH."""
        action = require_string(spec.get("action"), "TRex action")
        if action not in _REMOTE_REQUEST_KEYS:
            raise RuntimeError("trex remote action is undeclared")
        require_exact_keys(spec, _REMOTE_REQUEST_KEYS[action], f"TRex {action} request")
        self._require_exact_port_array(
            spec["ports"], self._all_port_ids, "TRex request ports"
        )
        server = require_string(spec["trex_server"], "TRex server")
        api_path = require_string(
            spec["trex_api_path"], "TRex API path", allow_empty=True
        )
        work_dir = require_string(spec["work_dir"], "TRex work directory")
        if (
            server != self.config.traffic.trex_server
            or api_path != self.config.traffic.trex_api_path
            or work_dir != self.config.traffic.work_dir
        ):
            raise RuntimeError("trex remote request carries foreign endpoint identity")
        if (
            server.startswith("-")
            or not server.isprintable()
            or any(character.isspace() for character in server)
            or len(server.encode("utf-8")) > 255
            or any(
                not value.isprintable() or len(value.encode("utf-8")) > 4096
                for value in (api_path, work_dir)
                if value
            )
        ):
            raise RuntimeError("trex remote endpoint identity is malformed")
        for path, name, allow_empty in (
            (spec["work_dir"], "TRex work directory", False),
            (spec["trex_api_path"], "TRex API path", True),
        ):
            if (
                (not allow_empty or path)
                and (
                    not path.startswith("/")
                    or path.startswith("//")
                    or posixpath.normpath(path) != path
                )
            ):
                raise RuntimeError(f"{name} is not one exact absolute path")

        if "egress_ports" in spec:
            self._require_exact_port_array(
                spec["egress_ports"], self._egress_port_ids,
                "TRex request egress ports",
            )
        if action == "exchange_udp":
            self._validate_udp_exchange_request(spec)
        if action in {"run", "generation_start", "generation_finish"}:
            duration = require_number(
                spec["duration_s"], "TRex request duration", minimum=0.0
            )
            pps = require_int(
                spec["pps"], "TRex request PPS", minimum=1,
                maximum=1_000_000_000,
            )
            require_int(
                spec["packet_size"], "TRex request packet size", minimum=64,
                maximum=9000,
            )
            num_flows = require_int(
                spec["num_flows"], "TRex request flow count", minimum=1,
                maximum=65535 - 10000 + 1,
            )
            if (
                duration <= 0.0
                or pps * duration < 1.0
                or pps * duration > _UINT64_MAX
            ):
                raise RuntimeError("trex remote run extent is outside its counter domain")
            sport = require_int(
                spec["sport"], "TRex request sport", minimum=1, maximum=65535
            )
            require_int(
                spec["dport"], "TRex request dport", minimum=1, maximum=65535
            )
            if sport + num_flows - 1 > 65535:
                raise RuntimeError("trex flow source-port range overflows")
            if action == "run":
                require_int(
                    spec["generation_tag"], "TRex request generation tag", minimum=0,
                    maximum=_GENERATION_TAG_MAX,
                )
            for name in ("src_ip", "dst_ip"):
                self._require_ipv4(spec[name], f"TRex request {name}")
            ingress = require_array(spec["ingress_streams"], "TRex ingress streams")
            normalized_ingress = []
            for row in ingress:
                row = require_object(row, "TRex ingress stream")
                require_exact_keys(
                    row, {"logical_name", "port_id", "src_mac", "dst_mac"},
                    "TRex ingress stream",
                )
                normalized_ingress.append(
                    {
                        "logical_name": require_string(
                            row["logical_name"], "TRex ingress logical name"
                        ),
                        "port_id": require_int(
                            row["port_id"], "TRex ingress port", minimum=0,
                            maximum=_UINT32_MAX,
                        ),
                        "src_mac": self._require_mac(
                            row["src_mac"], "TRex ingress source MAC"
                        ),
                        "dst_mac": self._require_mac(
                            row["dst_mac"], "TRex ingress destination MAC"
                        ),
                    }
                )
            if normalized_ingress != self._ingress_streams:
                raise RuntimeError("trex ingress-stream request identity disagrees")
            if 1000 + len(normalized_ingress) * num_flows * 2 > _UINT32_MAX:
                raise RuntimeError("trex generated PGID range overflows")
            if action == "run":
                mode = require_string(spec["mode"], "TRex run mode")
                if mode not in {"standard", "timed"}:
                    raise RuntimeError("trex one-shot run identity is inexact")
        if action in {"generation_start", "generation_finish"}:
            transition = require_number(
                spec["transition_time_s"], "TRex request transition time",
                minimum=0.0,
            )
            overlap_ms = require_int(
                spec["overlap_window_ms"], "TRex request overlap", minimum=1,
                maximum=_UINT32_MAX,
            )
            initial_tag = require_int(
                spec["initial_generation_tag"], "TRex initial generation tag",
                minimum=0, maximum=_GENERATION_TAG_MAX,
            )
            next_tag = require_int(
                spec["next_generation_tag"], "TRex next generation tag",
                minimum=0, maximum=_GENERATION_TAG_MAX,
            )
            tags_exact = initial_tag != next_tag
            timing_exact = (
                0.0 < transition < duration
                and transition + overlap_ms / 1000.0 < duration
            )
            counter_extent_exact = (
                pps * (duration + overlap_ms / 1000.0) <= _UINT64_MAX
            )
            if not all((tags_exact, timing_exact, counter_extent_exact)):
                raise RuntimeError(
                    "trex generation request is outside its exact timing identity"
                )
            if self._generation_result_extent_bound(
                normalized_ingress, num_flows
            ) > MAX_JSON_DOCUMENT_CHARACTERS:
                raise RuntimeError(
                    "trex generation evidence exceeds the bounded JSON result"
                )
        if action in {
            "generation_resume_next", "generation_pause_initial", "generation_finish",
        }:
            self._require_generation_stream_port_membership(spec)
            self.generation_stream_ids(spec, "initial")
        if action in {
            "generation_resume_next", "generation_pause_initial",
            "generation_finish", "generation_abort",
        }:
            self._require_exact_port_array(
                spec["ingress_ports"], self._ingress_port_ids,
                "TRex request ingress ports",
            )
        if action == "generation_finish":
            self._require_port_counters(spec["port_counter_baseline"], "baseline")
            if not require_array(
                spec["generation_flow_plan"], "TRex generation flow plan"
            ):
                raise RuntimeError("trex generation flow plan is empty")
            next_start = require_number(
                spec["next_start_monotonic"], "TRex next monotonic start",
                minimum=0.0,
            )
            start_sample = require_number(
                spec["start_monotonic"], "TRex monotonic start",
                minimum=0.0,
            )
            initial_pause = require_number(
                spec["initial_pause_monotonic"], "TRex initial pause sample",
                minimum=0.0,
            )
            for name in ("start_time", "next_start_time", "initial_pause_time"):
                if require_number(
                    spec[name], f"TRex request {name}", minimum=0.0
                ) <= 0.0:
                    raise RuntimeError("trex generation wall time is not positive")
            if start_sample <= 0.0 or next_start <= start_sample or initial_pause <= next_start:
                raise RuntimeError("trex generation overlap timestamps regress")
        return action

    async def _invoke_remote(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Invoke the endpoint-side TRex runner and return its JSON result."""
        if self._remote_proc is not None:
            raise RuntimeError("trex remote action already in progress")

        action = self._validate_remote_request(spec)

        script_b64 = base64.b64encode(_REMOTE_TREX_SCRIPT.encode("utf-8")).decode("ascii")
        spec_json = json.dumps(
            spec, allow_nan=False, separators=(",", ":"), sort_keys=True
        )
        spec_bytes = spec_json.encode("utf-8")
        if len(spec_bytes) > MAX_JSON_DOCUMENT_CHARACTERS:
            raise RuntimeError("trex remote request exceeds the bounded JSON input")
        remote_args = [
            self.config.traffic.python,
            "-I",
            "-c",
            _REMOTE_BOOTSTRAP,
            script_b64,
        ]
        cmd = self._ssh_prefix + [self._remote_shell_command(remote_args)]
        timeout_s = self._remote_timeout_s(spec)
        log_info("trex", f"remote action: {action}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=exact_subprocess_environment(),
        )
        self._remote_proc = proc
        if action == "exchange_udp":
            self._udp_exchange_incomplete = True
        try:
            stdout, stderr = await communicate_bounded_subprocess(
                proc,
                timeout_s,
                _REMOTE_TERMINATE_GRACE_S,
                spec_bytes,
            )
        except asyncio.TimeoutError as exc:
            raise RuntimeError(
                f"trex remote action '{action}' timed out after {timeout_s:.1f}s"
            ) from exc
        finally:
            if self._remote_proc is proc and proc.returncode is not None:
                self._remote_proc = None
            if proc.returncode is not None:
                await self._discard_remote_kill_task()

        if action == "exchange_udp" and proc.returncode == 0:
            # The endpoint exits zero only after capture, service mode, and client
            # retirement. A later local payload rejection does not undo that proof.
            self._udp_exchange_incomplete = False
        try:
            stderr_text = stderr.decode("utf-8")
        except UnicodeError as exc:
            raise RuntimeError("trex remote action emitted non-UTF-8 diagnostics") from exc
        if stderr:
            self._log_remote_stderr(stderr_text)

        try:
            payload = self._parse_remote_stdout(stdout)
        except RuntimeError as exc:
            if proc.returncode != 0:
                message = f"trex remote action failed: remote command exited {proc.returncode}"
                tail = self._stderr_tail(stderr_text)
                if tail:
                    message = f"{message}; {tail}"
                raise RuntimeError(message) from exc
            raise

        if "ok" not in payload:
            raise RuntimeError("trex remote action omitted its result classification")
        ok = require_bool(payload["ok"], "TRex remote result")
        if proc.returncode != 0 and ok:
            raise RuntimeError(
                "trex remote action exited after success; endpoint cleanup is unproved"
            )
        if not ok:
            require_exact_keys(payload, {"ok", "error"}, "TRex remote failure")
            error = self._safe_remote_text(
                require_string(payload["error"], "TRex remote error"), 2000
            )
            tail = self._stderr_tail(stderr_text)
            if tail:
                error = f"{error}; {tail}"
            raise RuntimeError(f"trex remote action failed: {error}")
        if action not in _REMOTE_SUCCESS_KEYS:
            raise RuntimeError("trex remote action has no response contract")
        expected_keys = _REMOTE_SUCCESS_KEYS[action]
        require_exact_keys(payload, expected_keys, f"TRex {action} response")
        if require_string(payload["action"], "TRex response action") != action:
            raise RuntimeError("trex remote response action disagrees with request")
        self._validate_remote_success(payload, action, spec)
        return payload

    def _validate_remote_success(
        self, payload: Dict[str, Any], action: str, request: Dict[str, Any]
    ) -> None:
        """Validate one response against its exact local request."""
        if action == "exchange_udp":
            frames = require_array(payload["frames"], "UDP exchange captured frames")
            if len(frames) > len(request["packets"]) + 1:
                raise RuntimeError("UDP exchange capture exceeded its packet bound")
            for value in frames:
                encoded = require_string(value, "UDP exchange captured frame")
                try:
                    frame = bytes.fromhex(encoded)
                except ValueError as exc:
                    raise RuntimeError("UDP exchange frame is not hexadecimal") from exc
                if encoded != frame.hex() or not 14 <= len(frame) <= EXCHANGE_PACKET_BYTES + 14:
                    raise RuntimeError("UDP exchange captured an incomplete or oversized frame")
            return
        if action == "probe":
            probe_identity = require_trex_identity(
                payload["trex_identity"], "TRex setup identity"
            )
        if "work_dir" in payload and require_string(
            payload["work_dir"], "TRex work_dir"
        ) != self.config.traffic.work_dir:
            raise RuntimeError("trex remote work directory disagrees")
        if action == "probe":
            self._require_exact_port_array(
                payload["ports"], self._all_port_ids, "TRex probe ports"
            )
            self._require_exact_port_array(
                payload["promiscuous_ports"], self._egress_port_ids,
                "TRex probe promiscuous ports",
            )
            stats_keys = require_array(payload["stats_keys"], "TRex stats keys")
            normalized_keys = [
                require_string(value, "TRex stats key") for value in stats_keys
            ]
            if len(normalized_keys) != len(set(normalized_keys)):
                raise RuntimeError("trex stats keys are duplicated")
            self._trex_identity = probe_identity
        if action in {"run", "generation_finish"}:
            tx_count, rx_count = self._validated_port_totals(payload)
            start_time = require_number(
                payload["start_time"], "TRex start_time", minimum=0.0
            )
            end_time = require_number(
                payload["end_time"], "TRex end_time", minimum=0.0
            )
            if end_time < start_time:
                raise RuntimeError("trex remote timestamps regress")
            tx_tags = _generation_counts(
                payload["generation_tag_counts"], "TRex TX generation tags"
            )
            rx_tags = _generation_counts(
                payload["tag_counts"], "TRex RX generation tags"
            )
            if sum(tx_tags.values()) != tx_count or sum(rx_tags.values()) != rx_count:
                raise RuntimeError("trex generation-tag counters disagree with totals")
            self._require_exact_port_array(
                payload["ingress_ports"], self._ingress_port_ids,
                "TRex ingress ports",
            )
            self._require_exact_port_array(
                payload["egress_ports"], self._egress_port_ids,
                "TRex egress ports",
            )
            self._require_exact_port_array(
                payload["promiscuous_ports"], self._egress_port_ids,
                "TRex promiscuous ports",
            )
        if action == "generation_start":
            self._require_port_counters(payload["port_counter_baseline"], "baseline")
            initial = require_int(
                payload["initial_generation_tag"],
                "TRex initial generation tag",
                minimum=0,
                maximum=_GENERATION_TAG_MAX,
            )
            following = require_int(
                payload["next_generation_tag"],
                "TRex next generation tag",
                minimum=0,
                maximum=_GENERATION_TAG_MAX,
            )
            if (
                initial == following
                or initial != request["initial_generation_tag"]
                or following != request["next_generation_tag"]
            ):
                raise RuntimeError("trex generation session tag identity disagrees")
            duration = require_number(
                payload["duration_s"], "TRex duration", minimum=0.0
            )
            if duration <= 0.0 or duration != request["duration_s"]:
                raise RuntimeError("trex generation duration disagrees")
            require_number(payload["start_time"], "TRex start time", minimum=0.0)
            require_number(
                payload["start_monotonic"], "TRex monotonic start", minimum=0.0
            )
            self._require_exact_port_array(
                payload["ingress_ports"], self._ingress_port_ids,
                "TRex generation ingress ports",
            )
            self._require_exact_port_array(
                payload["egress_ports"], self._egress_port_ids,
                "TRex generation egress ports",
            )
            self._require_exact_port_array(
                payload["promiscuous_ports"], self._egress_port_ids,
                "TRex generation promiscuous ports",
            )
            self._validate_generation_session(
                payload, initial, following, request
            )
        if action in {"generation_resume_next", "generation_pause_initial"}:
            field, role = (
                ("resumed_stream_ids", "next")
                if action == "generation_resume_next"
                else ("paused_stream_ids", "initial")
            )
            expected = self.generation_stream_ids(request, role)
            observed = require_object(payload[field], f"TRex {field}")
            if set(observed) != set(expected):
                raise RuntimeError("trex stream response port membership disagrees")
            for port_text, stream_ids in expected.items():
                if self._require_int_array(
                    observed[port_text], f"TRex {field} port {port_text}"
                ) != stream_ids:
                    raise RuntimeError("trex stream response identities disagree with their port")
        if action == "generation_resume_next":
            require_number(payload["next_start_time"], "TRex next start", minimum=0.0)
            require_number(
                payload["next_start_monotonic"],
                "TRex next monotonic start",
                minimum=0.0,
            )
            if require_string(
                payload["timestamp_source"], "TRex resume timestamp source"
            ) != _REMOTE_TIMESTAMP_SOURCE:
                raise RuntimeError("trex resume timestamp source is foreign")
        if action == "generation_pause_initial":
            require_number(payload["initial_pause_time"], "TRex initial pause", minimum=0.0)
            require_number(
                payload["initial_pause_monotonic"],
                "TRex initial monotonic pause",
                minimum=0.0,
            )
            if require_string(
                payload["timestamp_source"], "TRex pause timestamp source"
            ) != _REMOTE_TIMESTAMP_SOURCE:
                raise RuntimeError("trex pause timestamp source is foreign")
        if action == "generation_finish":
            if payload["port_counter_baseline"] != request["port_counter_baseline"]:
                raise RuntimeError("trex finished counter baseline disagrees with its session")
            overlap = require_number(
                payload["overlap_window_ms_measured"],
                "TRex measured generation overlap",
                minimum=0.0,
            )
            if overlap <= 0.0:
                raise RuntimeError("trex measured generation overlap is not positive")
            require_int(
                payload["expected_tx_count"], "TRex expected TX", minimum=1,
                maximum=_UINT64_MAX,
            )
            self._validate_generation_finish(payload)

    def _require_port_counters(
        self, value: object, name: str,
    ) -> Dict[str, Dict[str, int]]:
        """Admit exact uint64 packet/error observations for every owned port."""
        context = f"TRex port counter {name}"
        rows = require_object(value, context)
        require_exact_keys(
            rows, {str(port) for port in self._all_port_ids}, context,
        )
        result = {}
        for port_text, item in rows.items():
            row = require_object(item, f"{context} port {port_text}")
            require_exact_keys(
                row, {"opackets", "ipackets", "oerrors", "ierrors"},
                f"{context} port {port_text}",
            )
            result[port_text] = {
                field: require_int(
                    count, f"{context} port {port_text} {field}",
                    minimum=0, maximum=_UINT64_MAX,
                )
                for field, count in row.items()
            }
        return result

    def _validated_port_totals(self, payload: Dict[str, Any]) -> tuple[int, int]:
        """Recompute reported TX/RX from retained snapshots before accepting evidence.

        Reject missing observations, per-counter regression, inconsistent totals,
        and new traffic errors. Historical errors remain outside this interval.
        """
        baseline = self._require_port_counters(payload.get("port_counter_baseline"), "baseline")
        final = self._require_port_counters(payload.get("port_counter_final"), "final")
        for port_text, row in final.items():
            for field, count in row.items():
                if count < baseline[port_text][field]:
                    raise RuntimeError(f"trex port {port_text} {field} regressed")
        tx_count = sum(
            final[str(port)]["opackets"] - baseline[str(port)]["opackets"]
            for port in self._ingress_port_ids
        )
        rx_count = sum(
            final[str(port)]["ipackets"] - baseline[str(port)]["ipackets"]
            for port in self._egress_port_ids
        )
        errors = sum(
            final[str(port)]["oerrors"] - baseline[str(port)]["oerrors"]
            for port in self._ingress_port_ids
        ) + sum(
            final[str(port)]["ierrors"] - baseline[str(port)]["ierrors"]
            for port in self._egress_port_ids
        )
        tx_field, rx_field = (
            ("port_tx_count", "port_rx_count")
            if payload["action"] == "generation_finish"
            else ("tx_count", "rx_count")
        )
        for field, count in ((tx_field, tx_count), (rx_field, rx_count), ("errors", errors)):
            if require_int(payload.get(field), f"TRex {field}", minimum=0, maximum=_UINT64_MAX) != count:
                raise RuntimeError(f"trex {field} disagrees with retained port snapshots")
        if errors != 0:
            raise RuntimeError("trex remote result contains traffic errors")
        if payload["action"] == "generation_finish":
            pgid_tx = require_int(payload.get("tx_count"), "TRex PGID TX", minimum=0, maximum=_UINT64_MAX)
            pgid_rx = require_int(payload.get("rx_count"), "TRex PGID RX", minimum=0, maximum=_UINT64_MAX)
            if tx_count != pgid_tx or rx_count != pgid_rx:
                raise RuntimeError(
                    "trex port and PGID aggregate counters disagree: "
                    f"port_tx={tx_count} pgid_tx={pgid_tx} "
                    f"port_rx={rx_count} pgid_rx={pgid_rx}"
                )
        return tx_count, rx_count

    @staticmethod
    def _require_int_array(value: object, context: str) -> List[int]:
        """Return one duplicate-free bounded integer array."""
        result = [
            require_int(item, context, minimum=0, maximum=_UINT32_MAX)
            for item in require_array(value, context)
        ]
        if len(result) != len(set(result)):
            raise RuntimeError(f"{context} contains duplicate identities")
        return result

    @staticmethod
    def _require_ipv4(value: object, context: str) -> str:
        """Return one canonical dotted-decimal IPv4 address."""
        text = require_string(value, context)
        try:
            parsed = ipaddress.IPv4Address(text)
        except ipaddress.AddressValueError as exc:
            raise RuntimeError(f"{context} is malformed") from exc
        if str(parsed) != text:
            raise RuntimeError(f"{context} is noncanonical")
        return text

    @staticmethod
    def _require_mac(value: object, context: str) -> str:
        """Return one canonical lowercase colon-delimited MAC address."""
        text = require_string(value, context)
        parts = text.split(":")
        if (
            len(parts) != 6
            or any(
                len(part) != 2
                or not part.isascii()
                or any(character not in "0123456789abcdef" for character in part)
                for part in parts
            )
        ):
            raise RuntimeError(f"{context} is malformed")
        return text

    def _require_exact_port_array(
        self, value: object, expected: List[int], context: str
    ) -> None:
        """Require one port array to preserve exact configured order."""
        if self._require_int_array(value, context) != expected:
            raise RuntimeError(f"{context} disagrees with configured ports")

    @classmethod
    def generation_stream_ids(
        cls, session: Dict[str, Any], role: str
    ) -> Dict[str, List[int]]:
        """Validate both generations and return one role's stream IDs by owning port."""
        if role not in {"initial", "next"}:
            raise RuntimeError("trex stream role is undeclared")
        rows = require_object(
            session["generation_stream_ids"], "TRex generation stream IDs"
        )
        if not rows or any(
            not isinstance(port_text, str)
            or not port_text.isascii()
            or not port_text.isdecimal()
            or str(int(port_text)) != port_text
            or int(port_text) > _UINT32_MAX
            for port_text in rows
        ):
            raise RuntimeError("trex generation stream port identity is malformed")
        result: Dict[str, List[int]] = {}
        for port_text in sorted(rows, key=int):
            row = require_object(rows[port_text], "TRex generation stream row")
            require_exact_keys(
                row, {"initial", "next"}, "TRex generation stream row"
            )
            initial = cls._require_int_array(row["initial"], "TRex initial stream IDs")
            following = cls._require_int_array(row["next"], "TRex next stream IDs")
            if not initial or len(initial) != len(following):
                raise RuntimeError("trex generation stream per-port cardinality is inexact")
            if set(initial) & set(following):
                raise RuntimeError("trex generation stream identities overlap within a port")
            result[port_text] = initial if role == "initial" else following
        return result

    def _require_generation_stream_port_membership(
        self, session: Dict[str, Any]
    ) -> None:
        """Require stream-row keys to equal the configured ingress ports."""
        rows = require_object(
            session["generation_stream_ids"], "TRex generation stream IDs"
        )
        if set(rows) != {str(port_id) for port_id in self._ingress_port_ids}:
            raise RuntimeError("trex generation stream port membership disagrees")

    def _validate_generation_session(
        self,
        payload: Dict[str, Any],
        initial_tag: int,
        next_tag: int,
        request: Dict[str, Any],
    ) -> None:
        """Validate exact stream and flow ownership returned at session start."""
        self._require_generation_stream_port_membership(payload)
        initial_ids = self.generation_stream_ids(payload, "initial")
        num_flows = require_int(
            request["num_flows"], "TRex requested flow count", minimum=1,
            maximum=65535 - 10000 + 1,
        )
        if any(len(stream_ids) != num_flows for stream_ids in initial_ids.values()):
            raise RuntimeError("trex generation stream per-port cardinality is inexact")
        expected_per_role = len(self._ingress_port_ids) * num_flows

        plan = require_array(
            payload["generation_flow_plan"], "TRex generation flow plan"
        )
        if len(plan) != expected_per_role * 2:
            raise RuntimeError("trex generation flow-plan cardinality is inexact")
        seen_pg_ids = set()
        seen_relations = set()
        logical_by_port = {
            row["port_id"]: row["logical_name"] for row in self._ingress_streams
        }
        stream_index_by_port = {
            row["port_id"]: index
            for index, row in enumerate(self._ingress_streams)
        }
        duration_s = require_number(
            payload["duration_s"], "TRex generation duration", minimum=0.0
        )
        transition_s = require_number(
            request["transition_time_s"], "TRex requested transition time",
            minimum=0.0,
        )
        overlap_s = require_int(
            request["overlap_window_ms"], "TRex requested overlap", minimum=1,
            maximum=_UINT32_MAX,
        ) / 1000.0
        if (
            transition_s <= 0.0
            or overlap_s <= 0.0
            or transition_s + overlap_s >= duration_s
        ):
            raise RuntimeError("trex generation timing is outside the request domain")
        per_flow_pps = (
            require_int(
                request["pps"], "TRex requested PPS", minimum=1,
                maximum=1_000_000_000,
            )
            / float(expected_per_role)
        )
        for item in plan:
            row = require_object(item, "TRex generation flow-plan row")
            require_exact_keys(
                row,
                {
                    "pg_id", "generation_tag", "logical_name", "port_id",
                    "flow_id", "role", "expected_tx",
                },
                "TRex generation flow-plan row",
            )
            pg_id = require_int(
                row["pg_id"], "TRex PGID", minimum=1, maximum=_UINT32_MAX
            )
            tag = require_int(
                row["generation_tag"], "TRex flow generation tag", minimum=0,
                maximum=_GENERATION_TAG_MAX,
            )
            port_id = require_int(
                row["port_id"], "TRex flow port", minimum=0,
                maximum=_UINT32_MAX,
            )
            flow_id = require_int(
                row["flow_id"], "TRex flow identity", minimum=0,
                maximum=num_flows - 1,
            )
            role = require_string(row["role"], "TRex generation flow role")
            expected_tag = initial_tag if role == "pre_overlap" else next_tag
            if role not in {"pre_overlap", "post_overlap"} or tag != expected_tag:
                raise RuntimeError("trex generation flow role and tag disagree")
            if (
                port_id not in logical_by_port
                or require_string(row["logical_name"], "TRex logical port")
                != logical_by_port[port_id]
            ):
                raise RuntimeError("trex generation flow port identity disagrees")
            expected_tx = require_int(
                row["expected_tx"], "TRex expected flow TX", minimum=0,
                maximum=_UINT64_MAX,
            )
            expected_pg_id = (
                1000
                + stream_index_by_port[port_id]
                * num_flows * 2
                + flow_id * 2
                + (1 if role == "post_overlap" else 0)
            )
            expected_flow_tx = int(round(
                per_flow_pps
                * (
                    duration_s - transition_s
                    if role == "post_overlap"
                    else transition_s + overlap_s
                )
            ))
            if pg_id != expected_pg_id or expected_tx != expected_flow_tx:
                raise RuntimeError(
                    "trex generation flow arithmetic disagrees with the request"
                )
            relation = (port_id, flow_id, role)
            if pg_id in seen_pg_ids or relation in seen_relations:
                raise RuntimeError("trex generation flow identity is duplicated")
            seen_pg_ids.add(pg_id)
            seen_relations.add(relation)

    def _validate_generation_finish(self, payload: Dict[str, Any]) -> None:
        """Validate exact timing and PGID accounting at session completion."""
        if require_string(
            payload["generation_overlap_method"], "TRex overlap method"
        ) != "orchestrator_controlled_sustained_overlap":
            raise RuntimeError("trex overlap method is foreign")
        if require_string(
            payload["overlap_window_timestamp_source"],
            "TRex overlap timestamp source",
        ) != _REMOTE_TIMESTAMP_SOURCE:
            raise RuntimeError("trex overlap timestamp source is foreign")
        if require_string(
            payload["expected_tx_count_source"], "TRex expected-TX source"
        ) != "measured_generation_intervals":
            raise RuntimeError("trex expected-TX source is not interval-measured")
        start_sample = require_number(
            payload["start_monotonic"], "TRex monotonic start", minimum=0.0
        )
        next_start = require_number(
            payload["next_start_monotonic"], "TRex next monotonic start",
            minimum=0.0,
        )
        initial_pause = require_number(
            payload["initial_pause_monotonic"], "TRex initial pause sample",
            minimum=0.0,
        )
        next_pause = require_number(
            payload["next_pause_monotonic"], "TRex next pause sample",
            minimum=0.0,
        )
        measured = require_number(
            payload["overlap_window_ms_measured"], "TRex measured overlap",
            minimum=0.0,
        )
        requested_overlap = require_int(
            payload["requested_overlap_window_ms"],
            "TRex requested overlap",
            minimum=1,
            maximum=_UINT32_MAX,
        )
        if (
            next_start <= start_sample
            or initial_pause <= next_start
            or next_pause <= initial_pause
            or abs(measured - ((initial_pause - next_start) * 1000.0)) > 0.001
            or measured + 0.001 < requested_overlap
        ):
            raise RuntimeError("trex measured overlap timestamps disagree")
        require_number(payload["next_start_time"], "TRex next wall start", minimum=0.0)
        require_number(payload["initial_pause_time"], "TRex initial wall pause", minimum=0.0)
        require_number(payload["next_pause_time"], "TRex next wall pause", minimum=0.0)
        if require_int(
            payload["steady_state_target_pps"], "TRex steady target", minimum=1,
            maximum=_UINT32_MAX,
        ) * 2 != require_int(
            payload["overlap_aggregate_target_pps"],
            "TRex overlap target", minimum=2, maximum=_UINT64_MAX,
        ):
            raise RuntimeError("trex overlap target arithmetic disagrees")
        require_number(
            payload["transition_time_s_requested"],
            "TRex requested transition time", minimum=0.0,
        )
        plan = require_array(
            payload["generation_flow_plan"], "TRex generation flow plan"
        )
        plan_by_pgid = {}
        for item in plan:
            row = require_object(item, "TRex generation flow-plan row")
            pg_id = require_int(
                row["pg_id"], "TRex PGID", minimum=1, maximum=_UINT32_MAX
            )
            if pg_id in plan_by_pgid:
                raise RuntimeError("trex generation PGID is duplicated")
            plan_by_pgid[pg_id] = row
        observed = require_object(
            payload["generation_pgid_stats"], "TRex generation PGID stats"
        )
        if set(observed) != {str(value) for value in plan_by_pgid}:
            raise RuntimeError("trex PGID observation membership disagrees")
        tx_by_tag: Dict[int, int] = {}
        rx_by_tag: Dict[int, int] = {}
        for pg_text, item in observed.items():
            row = require_object(item, "TRex generation PGID row")
            require_exact_keys(
                row,
                {
                    "generation_tag", "logical_name", "port_id", "flow_id",
                    "role", "expected_tx", "tx_pkts", "rx_pkts",
                },
                "TRex generation PGID row",
            )
            expected = plan_by_pgid[int(pg_text)]
            tag = require_int(
                row["generation_tag"], "TRex PGID tag", minimum=0,
                maximum=_GENERATION_TAG_MAX,
            )
            normalized_identity = {
                "generation_tag": tag,
                "logical_name": require_string(
                    row["logical_name"], "TRex PGID logical name"
                ),
                "port_id": require_int(
                    row["port_id"], "TRex PGID port", minimum=0,
                    maximum=_UINT32_MAX,
                ),
                "flow_id": require_int(
                    row["flow_id"], "TRex PGID flow", minimum=0,
                    maximum=_UINT32_MAX,
                ),
                "role": require_string(row["role"], "TRex PGID role"),
                "expected_tx": require_int(
                    row["expected_tx"], "TRex PGID expected TX", minimum=0,
                    maximum=_UINT64_MAX,
                ),
            }
            if any(
                observed_value != expected[field]
                for field, observed_value in normalized_identity.items()
            ):
                raise RuntimeError("trex PGID identity disagrees with flow plan")
            tx_packets = require_int(
                row["tx_pkts"], "TRex PGID TX", minimum=0,
                maximum=_UINT64_MAX,
            )
            rx_packets = require_int(
                row["rx_pkts"], "TRex PGID RX", minimum=0,
                maximum=_UINT64_MAX,
            )
            expected_tx = normalized_identity["expected_tx"]
            if (
                rx_packets > tx_packets
                or expected_tx > 0
                and tx_packets * 100 < expected_tx * 95
            ):
                raise RuntimeError("trex PGID traffic achievement is incomplete")
            tx_by_tag[tag] = tx_by_tag.setdefault(tag, 0) + tx_packets
            rx_by_tag[tag] = rx_by_tag.setdefault(tag, 0) + rx_packets
        if tx_by_tag != _generation_counts(
            payload["generation_tag_counts"], "TRex TX generation tags"
        ) or rx_by_tag != _generation_counts(
            payload["tag_counts"], "TRex RX generation tags"
        ):
            raise RuntimeError("trex PGID aggregates disagree with generation totals")

    def cancel_remote_action(self) -> None:
        """Terminate the active remote action, if one is running."""
        proc = self._remote_proc
        if proc is None or proc.returncode is not None:
            return
        self._request_remote_termination(proc)
        if self._remote_kill_task is None or self._remote_kill_task.done():
            self._remote_kill_task = asyncio.get_running_loop().create_task(
                self._kill_remote_proc_after_grace(proc)
            )

    @staticmethod
    def _remote_timeout_s(spec: Dict[str, Any]) -> float:
        """Return an outer timeout for one remote TRex action."""
        if spec["action"] not in {"run", "generation_finish"}:
            return _REMOTE_PROBE_TIMEOUT_S
        duration_s = require_number(
            spec["duration_s"], "TRex remote duration", minimum=0.0
        )
        if duration_s <= 0.0:
            raise RuntimeError("trex remote duration must be positive")
        return max(_REMOTE_PROBE_TIMEOUT_S, duration_s + _REMOTE_RUN_GRACE_TIMEOUT_S)

    async def _kill_remote_proc_after_grace(
        self,
        proc: asyncio.subprocess.Process,
    ) -> None:
        """Escalate a cancelled remote action if SIGTERM does not complete."""
        await asyncio.sleep(_REMOTE_TERMINATE_GRACE_S)
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            try:
                await asyncio.wait_for(
                    proc.wait(), timeout=_REMOTE_TERMINATE_GRACE_S
                )
            except asyncio.TimeoutError as exc:
                raise RuntimeError(
                    "trex remote process did not retire after forced exit"
                ) from exc

    async def _await_remote_kill_task(self) -> None:
        """Wait for the tracked remote-kill task so Ctrl-C leaves no pending task."""
        task = self._remote_kill_task
        if task is None:
            return
        try:
            await task
        finally:
            if self._remote_kill_task is task:
                self._remote_kill_task = None

    async def _discard_remote_kill_task(self) -> None:
        """Cancel a stale escalation task after the remote process already exited."""
        task = self._remote_kill_task
        if task is None:
            self._remote_kill_task = None
            return
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        finally:
            if self._remote_kill_task is task:
                self._remote_kill_task = None

    @staticmethod
    def _request_remote_termination(proc: asyncio.subprocess.Process) -> None:
        """Send SIGTERM to a remote SSH subprocess if it is still active."""
        if proc.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
            log_warn("trex", "remote action termination requested")

    def _log_remote_stderr(self, stderr_text: str) -> None:
        """Log suspicious endpoint stderr lines and keep banners verbose-only."""
        for line in stderr_text.splitlines():
            text = self._safe_remote_text(line.strip(), 2000)
            if not text:
                continue
            if self._stderr_has_warning(text):
                log_warn("trex", text)
            elif self.config.verbose:
                log_info("trex", text)

    @staticmethod
    def _stderr_has_warning(line: str) -> bool:
        """Return true when an endpoint stderr line should be visible by default."""
        lowered = line.lower()
        return any(token in lowered for token in _STDERR_WARNING_TOKENS)

    @staticmethod
    def _stderr_tail(stderr_text: str) -> str:
        """Return a bounded stderr tail for failure diagnostics."""
        lines = [
            TRexTrafficDriver._safe_remote_text(line.strip(), 256)
            for line in stderr_text.splitlines()
            if line.strip()
        ]
        if not lines:
            return ""
        return "stderr tail: " + " | ".join(lines[-8:])[:2000]

    @staticmethod
    def _safe_remote_text(value: str, limit: int) -> str:
        """Return bounded printable ASCII for one untrusted remote diagnostic."""
        return "".join(
            character if 0x20 <= ord(character) <= 0x7E else "?"
            for character in value[:limit]
        )

    @staticmethod
    def _parse_remote_stdout(stdout: bytes) -> Dict[str, Any]:
        """Parse the remote runner's one complete strict JSON document."""
        try:
            decoded = stdout.decode("utf-8")
            payload = parse_exact_json_object(decoded, "TRex remote action")
        except (UnicodeError, JsonContractError) as exc:
            raise RuntimeError("trex remote action produced invalid JSON") from exc
        return payload

    @staticmethod
    def _remote_shell_command(remote_args: List[str]) -> str:
        """Quote a command vector for the OpenSSH remote shell boundary."""
        return " ".join(shlex.quote(arg) for arg in remote_args)

    @property
    def _ssh_prefix(self) -> List[str]:
        """Return the SSH command prefix for the traffic endpoint."""
        host = self.config.traffic.host
        python = self.config.traffic.python
        ssh_port = self.config.traffic.ssh_port
        host_exact = (
            isinstance(host, str)
            and bool(host)
            and not host.startswith("-")
            and host.isprintable()
            and not any(character.isspace() for character in host)
            and len(host.encode("utf-8")) <= 255
        )
        python_exact = (
            isinstance(python, str)
            and python.startswith("/")
            and not python.startswith("//")
            and posixpath.normpath(python) == python
            and python.isprintable()
            and len(python.encode("utf-8")) <= 4096
        )
        port_exact = (
            isinstance(ssh_port, int)
            and not isinstance(ssh_port, bool)
            and 0 <= ssh_port <= 65535
        )
        if not all((host_exact, python_exact, port_exact)):
            raise RuntimeError("trex SSH endpoint identity is malformed")
        prefix = [
            require_system_executable(SSH_EXECUTABLE, "OpenSSH client"),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
        ]
        if ssh_port > 0:
            prefix.extend(["-p", str(ssh_port)])
        prefix.append(host)
        return prefix

    @property
    def _all_port_ids(self) -> List[int]:
        """Return traffic-generator port IDs in deployment port order."""
        overrides = list(self.config.traffic.trex_ports)
        if overrides:
            if len(overrides) != len(self.config.backend.ports):
                raise RuntimeError("trex port override count does not match port table")
            ids = overrides
        else:
            ids = [port.traffic_port_id for port in self.config.backend.ports]

        if (
            not ids
            or len(ids) != len(set(ids))
            or any(
                not isinstance(port_id, int)
                or isinstance(port_id, bool)
                or port_id < 0
                or port_id > _UINT32_MAX
                for port_id in ids
            )
        ):
            raise RuntimeError(
                "trex traffic requires unique uint32 traffic_port_id values"
            )
        return ids

    @property
    def _ingress_port_ids(self) -> List[int]:
        """Return traffic-generator ports that inject ingress traffic."""
        all_ids = self._all_port_ids
        return [
            all_ids[idx]
            for idx, port in enumerate(self.config.backend.ports)
            if port.traffic_role == "rx"
        ]

    @property
    def _ingress_streams(self) -> List[Dict[str, Any]]:
        """Return TRex stream metadata for each ingress runtime port."""
        all_ids = self._all_port_ids
        streams: List[Dict[str, Any]] = []
        for idx, port in enumerate(self.config.backend.ports):
            if port.traffic_role != "rx":
                continue
            if not port.runtime_mac:
                raise RuntimeError(
                    "trex traffic requires runtime_mac for RX port "
                    f"{port.logical_name}"
                )
            port_id = all_ids[idx]
            streams.append({
                "logical_name": port.logical_name,
                "port_id": port_id,
                "src_mac": self._source_mac_for_port(port_id),
                "dst_mac": port.runtime_mac,
            })
        return streams

    @staticmethod
    def _source_mac_for_port(port_id: int) -> str:
        """Return a deterministic locally-administered source MAC for TRex."""
        value = require_int(
            port_id, "TRex source-MAC port", minimum=0, maximum=_UINT32_MAX
        ) + 1
        return (
            f"02:{(value >> 32) & 0xFF:02x}:{(value >> 24) & 0xFF:02x}:"
            f"{(value >> 16) & 0xFF:02x}:{(value >> 8) & 0xFF:02x}:"
            f"{value & 0xFF:02x}"
        )

    @property
    def _egress_port_ids(self) -> List[int]:
        """Return traffic-generator ports that receive egress traffic."""
        all_ids = self._all_port_ids
        return [
            all_ids[idx]
            for idx, port in enumerate(self.config.backend.ports)
            if port.traffic_role == "tx"
        ]
