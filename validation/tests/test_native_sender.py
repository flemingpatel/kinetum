"""Tests for native TAP sender session ownership."""

import asyncio
import signal
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

from kinetum_validation.config.types import PacketConfig, PacketStats
from kinetum_validation.engine import native_sender as native_sender_module
from kinetum_validation.engine.native_sender import NativeSender


class _HungSenderProcess:
    """Pipe-backed child that exceeds its first communicate bound."""

    def __init__(self) -> None:
        """Initialize one live child and first-attempt barrier."""
        self.returncode = None
        self.communicate_calls = 0
        self.terminated = False
        self.killed = False

    async def communicate(self):
        """Block the first owner and let bounded retirement drain the second."""
        self.communicate_calls += 1
        if self.communicate_calls == 1:
            await asyncio.Event().wait()
        self.returncode = -15
        return b"", b""

    def terminate(self) -> None:
        """Record graceful termination."""
        self.terminated = True

    def kill(self) -> None:
        """Record forced termination if graceful drain also stalls."""
        self.killed = True
        self.returncode = -9


class _FaultingSenderProcess(_HungSenderProcess):
    """Pipe-backed child whose first result collection fails unexpectedly."""

    async def communicate(self):
        """Raise once, then let the shared retirement owner drain the child."""
        self.communicate_calls += 1
        if self.communicate_calls == 1:
            raise OSError("synthetic pipe read failure")
        self.returncode = -15
        return b"", b""


class _PrematureSenderProcess(_HungSenderProcess):
    """Pipe-backed child that returns output before terminal process status."""

    async def communicate(self):
        """Expose a nonterminal first result, then retire after termination."""
        self.communicate_calls += 1
        if self.communicate_calls == 1:
            return b"", b""
        self.returncode = -15
        return b"", b""


class _SignalFaultSenderProcess(_FaultingSenderProcess):
    """Pipe-backed child whose graceful signal reports an ownership error."""

    def terminate(self) -> None:
        """Report failed signaling while the later drain still reaps the child."""
        raise PermissionError("synthetic signal failure")


class _GenerationSignalProcess:
    """Live sender child that records generation-transition signals."""

    def __init__(self) -> None:
        """Initialize one live child with no published signal."""
        self.returncode = None
        self.signals = []

    def send_signal(self, signum: int) -> None:
        """Record one signal delivered by the orchestration owner."""
        self.signals.append(signum)


class _CompletedGenerationProcess(_GenerationSignalProcess):
    """Generation child that returns one canonical initial-tag result."""

    async def communicate(self):
        """Publish one terminal canonical sender result."""
        self.returncode = 0
        return (
            b'{"tx_count":1,"error_count":0,"start_time":1.0,'
            b'"end_time":2.0,"duration_s":1.0,"actual_pps":1.0,'
            b'"generation_tag_counts":{"1":1}}\n',
            b"",
        )


class TestNativeSenderLifecycle(unittest.IsolatedAsyncioTestCase):
    """Generation-tag edges form one exact linear local state machine."""

    async def test_generation_overlap_edges_are_exactly_once(self) -> None:
        """Duplicate start/end/finish operations reject without mutation."""
        sender = NativeSender(
            Path("/unused/kinetum_tap_sender"), ["neb_rx"], PacketConfig()
        )
        expected = PacketStats(tx_count=2, generation_tag_counts={1: 1, 2: 1})
        sender._run_generation_tags = AsyncMock(  # type: ignore[method-assign]  # pylint: disable=protected-access
            return_value=expected
        )

        await sender.begin_generation_tags(1.0, 1, 2)
        process = _GenerationSignalProcess()
        sender._process = process  # type: ignore[assignment]  # pylint: disable=protected-access
        with self.assertRaisesRegex(RuntimeError, "already active"):
            await sender.begin_generation_tags(1.0, 1, 2)
        with self.assertRaisesRegex(RuntimeError, "exact integer"):
            await sender.start_generation_overlap(True)
        await sender.start_generation_overlap(2)
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            await sender.start_generation_overlap(2)
        await sender.end_generation_overlap()
        with self.assertRaisesRegex(RuntimeError, "not active"):
            await sender.end_generation_overlap()

        self.assertIs(await sender.finish_generation_tags(), expected)
        with self.assertRaisesRegex(RuntimeError, "was not started"):
            await sender.finish_generation_tags()
        sender._run_generation_tags.assert_awaited_once_with(1.0, 1, 2)  # pylint: disable=protected-access
        self.assertEqual(process.signals, [signal.SIGUSR1])
        sender._process = None  # pylint: disable=protected-access

    async def test_generation_spawn_restores_parent_signal_mask_on_every_edge(
        self,
    ) -> None:
        """Successful, failed, and restoration-failed spawns retain ownership."""
        with tempfile.TemporaryDirectory() as directory:
            sender_bin = Path(directory).resolve() / "kinetum_tap_sender"
            sender_bin.write_text("#!/bin/sh\n", encoding="utf-8")
            sender_bin.chmod(0o755)
            sender = NativeSender(sender_bin, ["neb_rx"], PacketConfig(pps=1))
            process = _CompletedGenerationProcess()
            inherited = {signal.SIGTERM}
            mask = MagicMock(side_effect=[inherited, inherited])
            spawn = AsyncMock(return_value=process)
            with patch.object(
                native_sender_module.signal, "pthread_sigmask", mask
            ), patch.object(
                native_sender_module.asyncio,
                "create_subprocess_exec",
                new=spawn,
            ):
                result = await sender._run_generation_tags(1.0, 1, 2)  # pylint: disable=protected-access

            self.assertEqual(result.generation_tag_counts, {1: 1})
            self.assertEqual(
                mask.call_args_list,
                [
                    call(signal.SIG_BLOCK, {signal.SIGUSR1}),
                    call(signal.SIG_SETMASK, inherited),
                ],
            )
            command = spawn.await_args.args
            self.assertEqual(
                command,
                (
                    str(sender_bin),
                    "--mode", "generation-tagged",
                    "--ports", "neb_rx",
                    "--pps", "1",
                    "--duration", "1.0",
                    "--packet-size", str(sender.config.packet_size),
                    "--src-ip", sender.config.src_ip,
                    "--dst-ip", sender.config.dst_ip,
                    "--sport", str(sender.config.base_sport),
                    "--dport", str(sender.config.base_dport),
                    "--initial-generation-tag", "1",
                    "--next-generation-tag", "2",
                ),
            )
            self.assertIsNone(sender._process)  # pylint: disable=protected-access

        sender = NativeSender(
            Path("/unused/kinetum_tap_sender"), ["neb_rx"], PacketConfig()
        )
        spawn_failure_mask = MagicMock(side_effect=[set(), set()])
        with patch.object(
            native_sender_module.signal,
            "pthread_sigmask",
            spawn_failure_mask,
        ), patch.object(
            native_sender_module.asyncio,
            "create_subprocess_exec",
            new=AsyncMock(side_effect=OSError("synthetic spawn failure")),
        ):
            with self.assertRaisesRegex(OSError, "spawn failure"):
                await sender._spawn_sender(  # pylint: disable=protected-access
                    ["/unused/kinetum_tap_sender"], True
                )
        self.assertEqual(
            spawn_failure_mask.call_args_list,
            [
                call(signal.SIG_BLOCK, {signal.SIGUSR1}),
                call(signal.SIG_SETMASK, set()),
            ],
        )

        restoration_failure_mask = MagicMock(
            side_effect=[set(), OSError("synthetic restoration failure")]
        )
        restoration_process = _GenerationSignalProcess()

        async def retire_spawned_process() -> None:
            """Resolve the synthetic child after parent-mask restoration fails."""
            restoration_process.returncode = -15
            sender._process = None  # pylint: disable=protected-access

        retire = AsyncMock(side_effect=retire_spawned_process)
        with patch.object(
            native_sender_module.signal,
            "pthread_sigmask",
            restoration_failure_mask,
        ), patch.object(
            native_sender_module.asyncio,
            "create_subprocess_exec",
            new=AsyncMock(return_value=restoration_process),
        ), patch.object(sender, "_terminate_process", new=retire):
            with self.assertRaisesRegex(RuntimeError, "restore generation signal"):
                await sender._spawn_sender(  # pylint: disable=protected-access
                    ["/unused/kinetum_tap_sender"], True
                )
        retire.assert_awaited_once_with()
        self.assertIsNone(sender._process)  # pylint: disable=protected-access

    async def test_native_process_completion_is_duration_bounded(self) -> None:
        """A hung sender is terminated, drained, and removed from ownership."""
        with tempfile.TemporaryDirectory() as directory:
            sender_bin = Path(directory).resolve() / "kinetum_tap_sender"
            sender_bin.write_text("#!/bin/sh\n", encoding="utf-8")
            sender_bin.chmod(0o755)
            sender = NativeSender(
                sender_bin,
                ["neb_rx"],
                PacketConfig(pps=1000),
            )
            process = _HungSenderProcess()
            with patch.object(
                native_sender_module,
                "_SENDER_COMPLETION_GRACE_S",
                0.001,
            ), patch.object(
                native_sender_module.asyncio,
                "create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ):
                with self.assertRaisesRegex(RuntimeError, "bounded run window"):
                    await sender.run_timed(0.001)

            self.assertTrue(process.terminated)
            self.assertFalse(process.killed)
            self.assertIsNone(sender._process)  # pylint: disable=protected-access

            faulting_process = _FaultingSenderProcess()
            with patch.object(
                native_sender_module.asyncio,
                "create_subprocess_exec",
                new=AsyncMock(return_value=faulting_process),
            ):
                with self.assertRaisesRegex(OSError, "pipe read failure"):
                    await sender.run_timed(0.001)

            self.assertTrue(faulting_process.terminated)
            self.assertFalse(faulting_process.killed)
            self.assertIsNone(sender._process)  # pylint: disable=protected-access

            premature_process = _PrematureSenderProcess()
            with patch.object(
                native_sender_module.asyncio,
                "create_subprocess_exec",
                new=AsyncMock(return_value=premature_process),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "without terminal process status"
                ):
                    await sender.run_timed(0.001)

            self.assertTrue(premature_process.terminated)
            self.assertFalse(premature_process.killed)
            self.assertIsNone(sender._process)  # pylint: disable=protected-access

            signal_fault_process = _SignalFaultSenderProcess()
            with patch.object(
                native_sender_module.asyncio,
                "create_subprocess_exec",
                new=AsyncMock(return_value=signal_fault_process),
            ):
                with self.assertRaisesRegex(PermissionError, "signal failure"):
                    await sender.run_timed(0.001)

            self.assertEqual(signal_fault_process.communicate_calls, 2)
            self.assertIsNotNone(signal_fault_process.returncode)
            self.assertIsNone(sender._process)  # pylint: disable=protected-access
