"""
Native TAP sender client - Python interface to kinetum_tap_sender.

Launches the native sender as a subprocess, publishes one pre-authored
generation-tag transition through SIGUSR1, and reads stats from stdout.
This is the canonical packet-generation mechanism for the validation
harness's local TAP traffic path.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import math
import os
import signal
from pathlib import Path
from typing import Optional, Sequence

from ..config.types import PacketConfig, PacketStats
from ..config.logger import log_info
from ..process.system_tools import (
    communicate_bounded_subprocess,
    exact_subprocess_environment,
    terminate_and_drain_subprocess,
)
from .json_contract import (
    JsonContractError,
    parse_exact_json_object,
    require_exact_keys,
    require_int,
    require_number,
    require_object,
)


_UINT64_MAX = (1 << 64) - 1
_UINT32_MAX = (1 << 32) - 1
_GENERATION_TAG_MAX = (1 << 16) - 1
_MAX_RATE_LIMIT_PPS = 1_000_000_000
_SENDER_COMPLETION_GRACE_S = 10.0
_SENDER_RESULT_KEYS = frozenset(
    {
        "tx_count",
        "error_count",
        "start_time",
        "end_time",
        "duration_s",
        "actual_pps",
        "generation_tag_counts",
    }
)


class NativeSender:
    """
    Client for the kinetum_tap_sender native binary.

    Manages the sender subprocess lifecycle, one-way generation-tag signal,
    and stats collection.

    Parameters
    ----------
    sender_bin : Path
        Path to the kinetum_tap_sender binary.
    ports : sequence of str
        TAP interface names to send on (round-robin).
    config : PacketConfig
        Packet configuration (PPS, size, IPs, ports).
    """

    def __init__(
        self,
        sender_bin: Path,
        ports: Sequence[str],
        config: PacketConfig,
    ) -> None:
        """Bind one exact executable, ingress set, and packet profile."""
        self.sender_bin = sender_bin
        self.ports = tuple(ports)
        self.config = config
        self._process: Optional[asyncio.subprocess.Process] = None
        self._generation_tag_task: Optional[asyncio.Task] = None
        self._expected_next_generation_tag: Optional[int] = None
        self._generation_overlap_started = False
        self._generation_overlap_ended = False

    @staticmethod
    def _generation_tags_are_valid(
        initial_generation_tag: int, next_generation_tag: int
    ) -> bool:
        """Return whether two tags form one exact initial-to-next transition."""
        return (
            isinstance(initial_generation_tag, int)
            and not isinstance(initial_generation_tag, bool)
            and isinstance(next_generation_tag, int)
            and not isinstance(next_generation_tag, bool)
            and 0 <= initial_generation_tag <= _GENERATION_TAG_MAX
            and 0 <= next_generation_tag <= _GENERATION_TAG_MAX
            and initial_generation_tag != next_generation_tag
        )

    async def run_standard(self, duration_s: float) -> PacketStats:
        """Run standard traffic for a fixed duration."""
        return await self._run("standard", duration_s, 0, 0)

    async def _run_generation_tags(
        self,
        duration_s: float,
        initial_generation_tag: int,
        next_generation_tag: int,
    ) -> PacketStats:
        """Run traffic with one pre-authored SIGUSR1 tag transition."""
        return await self._run(
            "generation-tagged", duration_s,
            initial_generation_tag=initial_generation_tag,
            next_generation_tag=next_generation_tag,
        )

    async def begin_generation_tags(
        self,
        duration_s: float,
        initial_generation_tag: int,
        next_generation_tag: int,
    ) -> None:
        """
        Establish ownership of one generation-tag run and schedule its source.

        Native TAP pre-authors both tags and lets the orchestrator publish the
        sole transition signal after this method returns. The orchestrator's
        positive DP-RX delta is the source-activity proof; task scheduling is
        not misrepresented as a child-process readiness handshake.
        """
        if self._generation_tag_task is not None:
            raise RuntimeError("native generation-tag sender already active")
        if not self._generation_tags_are_valid(
            initial_generation_tag, next_generation_tag
        ):
            raise RuntimeError("generation tags do not form one exact transition")
        self._expected_next_generation_tag = next_generation_tag
        self._generation_overlap_started = False
        self._generation_overlap_ended = False
        try:
            self._generation_tag_task = asyncio.create_task(
                self._run_generation_tags(
                    duration_s, initial_generation_tag, next_generation_tag
                )
            )
        except BaseException:
            self._expected_next_generation_tag = None
            raise

    async def start_generation_overlap(self, next_generation_tag: int) -> None:
        """Publish the sole SIGUSR1 edge for the bound next generation tag."""
        process = self._process
        if not isinstance(next_generation_tag, int) or isinstance(
            next_generation_tag, bool
        ):
            raise RuntimeError("generation overlap tag is not an exact integer")
        if (
            self._generation_tag_task is None
            or self._generation_tag_task.done()
            or self._generation_overlap_started
            or self._generation_overlap_ended
            or next_generation_tag != self._expected_next_generation_tag
        ):
            raise RuntimeError("generation overlap does not match the bound next tag")
        if process is None or process.returncode is not None:
            raise RuntimeError("generation overlap has no live native sender")
        try:
            process.send_signal(signal.SIGUSR1)
        except ProcessLookupError as exc:
            raise RuntimeError(
                "native generation-tag sender exited before the transition signal"
            ) from exc
        self._generation_overlap_started = True

    async def end_generation_overlap(self) -> None:
        """Close the logical edge; native TAP has no sustained old stream."""
        if (
            self._generation_tag_task is None
            or self._generation_tag_task.done()
            or not self._generation_overlap_started
            or self._generation_overlap_ended
        ):
            raise RuntimeError("native generation overlap is not active")
        self._generation_overlap_ended = True

    async def finish_generation_tags(self) -> PacketStats:
        """Wait for the active generation-tag sender and return its statistics."""
        if self._generation_tag_task is None:
            raise RuntimeError("native generation-tag sender was not started")
        if not self._generation_overlap_started or not self._generation_overlap_ended:
            raise RuntimeError("native generation overlap did not complete both edges")
        try:
            return await self._generation_tag_task
        finally:
            self._generation_tag_task = None
            self._expected_next_generation_tag = None
            self._generation_overlap_started = False
            self._generation_overlap_ended = False

    async def run_timed(self, duration_s: float) -> PacketStats:
        """Run timed traffic without a changing generation tag."""
        return await self._run("timed", duration_s, 0, 0)

    async def _run(
        self,
        mode: str,
        duration_s: float,
        initial_generation_tag: int,
        next_generation_tag: int,
    ) -> PacketStats:
        """Launch the native sender and collect stats."""
        if self._process is not None:
            raise RuntimeError("native sender process is already active")
        mode_valid = mode in {"standard", "generation-tagged", "timed"}
        duration_valid = (
            isinstance(duration_s, (int, float))
            and not isinstance(duration_s, bool)
            and math.isfinite(float(duration_s))
            and duration_s > 0.0
        )
        ports_valid = self._ports_are_valid()
        rate_valid = (
            isinstance(self.config.pps, int)
            and not isinstance(self.config.pps, bool)
            and 0 < self.config.pps <= _MAX_RATE_LIMIT_PPS
        )
        generation_tags_valid = (
            self._generation_tags_are_valid(
                initial_generation_tag, next_generation_tag
            )
            if mode == "generation-tagged"
            else initial_generation_tag == 0 and next_generation_tag == 0
        )
        if not all((
            mode_valid,
            duration_valid,
            ports_valid,
            rate_valid,
            generation_tags_valid,
        )):
            raise RuntimeError("native sender invocation is outside its exact domain")
        if not self._packet_config_is_valid(float(duration_s)):
            raise RuntimeError("native sender invocation is outside its exact domain")
        cmd = [
            str(self.sender_bin),
            "--mode", mode,
            "--ports", ",".join(self.ports),
            "--pps", str(self.config.pps),
            "--duration", str(duration_s),
            "--packet-size", str(self.config.packet_size),
            "--src-ip", self.config.src_ip,
            "--dst-ip", self.config.dst_ip,
            "--sport", str(self.config.base_sport),
            "--dport", str(self.config.base_dport),
        ]

        try:
            exact_sender = self.sender_bin.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError("native sender executable is unavailable") from exc
        if (
            not self.sender_bin.is_absolute()
            or exact_sender != self.sender_bin
            or not self.sender_bin.is_file()
            or self.sender_bin.is_symlink()
            or not os.access(self.sender_bin, os.X_OK)
        ):
            raise RuntimeError("native sender is not one exact installed executable")

        # Both values are immutable child input; SIGUSR1 selects the second.
        if mode == "generation-tagged":
            cmd.extend(["--initial-generation-tag", str(initial_generation_tag)])
            cmd.extend(["--next-generation-tag", str(next_generation_tag)])

        log_info("native_sender", f"{mode}: {self.config.pps} PPS, "
                 f"{duration_s}s, {len(self.ports)} port(s)")

        try:
            await self._spawn_sender(cmd, mode == "generation-tagged")
            if self._process is None:
                raise RuntimeError("native sender spawn returned no process owner")
            stdout_data, stderr_data = await communicate_bounded_subprocess(
                self._process,
                float(duration_s) + _SENDER_COMPLETION_GRACE_S,
                5.0,
            )
        except asyncio.TimeoutError as exc:
            self._process = None
            raise RuntimeError("native sender exceeded its bounded run window") from exc
        except asyncio.CancelledError:
            self._process = None
            raise
        except BaseException:
            if self._process is not None and self._process.returncode is not None:
                self._process = None
            raise
        returncode = self._process.returncode

        # Log stderr output
        if stderr_data:
            for line in stderr_data.decode(errors="replace").strip().split("\n"):
                if line:
                    log_info("native_sender", line)

        # Check return code before parsing stats
        if returncode != 0:
            self._process = None
            raise RuntimeError(
                f"kinetum_tap_sender exited with code {returncode}"
            )

        # Parse stats from stdout JSON
        if not stdout_data:
            self._process = None
            raise RuntimeError("kinetum_tap_sender produced no stats output")

        try:
            raw_text = stdout_data.decode("utf-8")
            raw = parse_exact_json_object(raw_text, "native sender")
            require_exact_keys(raw, _SENDER_RESULT_KEYS, "native sender")
            tx_count = require_int(
                raw["tx_count"], "sender tx_count", minimum=0,
                maximum=_UINT64_MAX,
            )
            error_count = require_int(
                raw["error_count"], "sender error_count", minimum=0,
                maximum=_UINT64_MAX,
            )
            start_time = require_number(
                raw["start_time"], "sender start_time", minimum=0.0
            )
            end_time = require_number(
                raw["end_time"], "sender end_time", minimum=0.0
            )
            duration = require_number(
                raw["duration_s"], "sender duration", minimum=0.0
            )
            actual_pps = require_number(
                raw["actual_pps"], "sender actual_pps", minimum=0.0
            )
            if end_time < start_time or abs((end_time - start_time) - duration) > 0.002:
                raise JsonContractError("native sender timing is contradictory")
            expected_pps = tx_count / (end_time - start_time) if end_time > start_time else 0.0
            if abs(actual_pps - expected_pps) > max(0.2, expected_pps * 0.001):
                raise JsonContractError("native sender rate is contradictory")
            raw_tags = require_object(
                raw["generation_tag_counts"], "sender generation_tag_counts"
            )
            generation_tag_counts = {}
            for tag_text, count_value in raw_tags.items():
                if not tag_text.isascii() or not tag_text.isdecimal():
                    raise JsonContractError("sender generation tag is malformed")
                generation_tag = int(tag_text)
                if str(generation_tag) != tag_text or generation_tag > _GENERATION_TAG_MAX:
                    raise JsonContractError("sender generation tag is noncanonical")
                generation_tag_counts[generation_tag] = require_int(
                    count_value, f"sender generation tag {generation_tag}",
                    minimum=0, maximum=_UINT64_MAX,
                )
            if sum(generation_tag_counts.values()) != tx_count:
                raise JsonContractError("sender tag counts do not equal sent packets")
        except (UnicodeError, JsonContractError) as e:
            self._process = None
            raise RuntimeError(f"kinetum_tap_sender produced invalid stats: {e}") from e

        stats = PacketStats(
            tx_count=tx_count,
            errors=error_count,
            generation_tag_counts=generation_tag_counts,
            start_time=start_time,
            end_time=end_time,
        )

        self._process = None
        return stats

    async def _spawn_sender(self, cmd: list[str], generation_tagged: bool) -> None:
        """Spawn one child while closing the SIGUSR1 startup race.

        Generation mode blocks SIGUSR1 on the creating thread before spawn, so
        the child inherits a blocked signal. The native image installs its
        handler before unblocking. This method restores the parent's exact
        prior mask after both successful and failed spawn attempts and retires
        a successfully created child if restoration itself fails.
        """
        if not generation_tagged:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=exact_subprocess_environment(),
            )
            return

        try:
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, {signal.SIGUSR1}
            )
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                "failed to block generation signal before sender spawn"
            ) from exc

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=exact_subprocess_environment(),
            )
        except BaseException:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except (OSError, ValueError) as exc:
                raise RuntimeError(
                    "failed to restore generation signal mask after spawn failure"
                ) from exc
            raise

        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        except (OSError, ValueError) as exc:
            try:
                await self._terminate_process()
            except BaseException as cleanup_error:
                raise RuntimeError(
                    "generation signal mask restoration and child retirement failed"
                ) from cleanup_error
            raise RuntimeError(
                "failed to restore generation signal mask after sender spawn"
            ) from exc

    def _ports_are_valid(self) -> bool:
        """Return whether every TAP name fits the native parser exactly."""
        return (
            0 < len(self.ports) <= 64
            and len(self.ports) == len(set(self.ports))
            and all(
                isinstance(port, str)
                and port.isascii()
                and 0 < len(port) < 16
                and all(0x20 < ord(character) <= 0x7E for character in port)
                and "/" not in port
                and "," not in port
                for port in self.ports
            )
        )

    def _packet_config_is_valid(self, duration_s: float) -> bool:
        """Return whether packet fields and run extent fit the native profile."""
        config = self.config
        if not isinstance(config.pps, int) or isinstance(config.pps, bool):
            return False
        scalar_valid = all((
            isinstance(config.packet_size, int),
            not isinstance(config.packet_size, bool),
            64 <= config.packet_size <= 9000,
            isinstance(config.base_sport, int),
            not isinstance(config.base_sport, bool),
            1 <= config.base_sport <= 65535,
            isinstance(config.base_dport, int),
            not isinstance(config.base_dport, bool),
            1 <= config.base_dport <= 65535,
            config.pps * float(duration_s) >= 1.0,
            config.pps * float(duration_s) <= _UINT32_MAX,
        ))
        if not scalar_valid:
            return False
        try:
            return all(
                isinstance(value, str)
                and str(ipaddress.IPv4Address(value)) == value
                for value in (config.src_ip, config.dst_ip)
            )
        except (TypeError, ValueError):
            return False

    def cancel(self) -> None:
        """Send SIGTERM to the sender process."""
        if self._process and self._process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                self._process.terminate()
        if self._generation_tag_task and not self._generation_tag_task.done():
            self._generation_tag_task.cancel()

    async def abort(self) -> None:
        """Cancel an active generation-tag sender and wait for it to settle."""
        self.cancel()
        if self._generation_tag_task:
            try:
                await self._generation_tag_task
            except asyncio.CancelledError:
                pass
            finally:
                self._generation_tag_task = None
                self._expected_next_generation_tag = None
                self._generation_overlap_started = False
                self._generation_overlap_ended = False
        else:
            await self._terminate_process()

    async def _terminate_process(self) -> None:
        """Reap the current child after bounded TERM-to-KILL escalation."""
        process = self._process
        if process is None:
            return
        await terminate_and_drain_subprocess(process, 5.0)
        if process.returncode is None:
            raise RuntimeError("native sender process retirement is unproved")
        if self._process is process:
            self._process = None

    def cleanup(self) -> None:
        """Release local state only after every asynchronous owner retires."""
        if self._generation_tag_task is not None:
            raise RuntimeError("native sender task ownership is still live")
        if self._process is not None:
            if self._process.returncode is None:
                raise RuntimeError("native sender process ownership is still live")
            self._process = None
