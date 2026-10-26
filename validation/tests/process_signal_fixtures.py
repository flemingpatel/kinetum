"""Run real terminal and child processes for validation cancellation tests."""

import asyncio
import fcntl
import json
import os
from pathlib import Path
import signal
import sys
import termios
from types import SimpleNamespace
from unittest.mock import patch

from kinetum_validation import __main__ as validation_cli
from kinetum_validation.config.types import ProcessConfig, TestConfig
from kinetum_validation.orchestrator import TestOrchestrator
from kinetum_validation.process.supervisor import AsyncProcessSupervisor
from kinetum_validation.traffic.native_tap import NativeTapTrafficDriver
from tests.trex_process_fixtures import run_endpoint


def fixture_command(*arguments: str) -> list[str]:
    """Select this test module explicitly in an isolated child interpreter."""
    bootstrap = (
        "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
        "runpy.run_module('tests.process_signal_fixtures',run_name='__main__')"
    )
    return [sys.executable, '-I', '-B', '-c', bootstrap,
            str(Path(__file__).resolve().parents[1]), *arguments]


def child(root: Path, exit_code: int, *, capture: bool) -> None:
    """Expose signal identity and exit only when signalled or the fixture bound expires."""
    name = 'capture' if capture else 'child'

    def finish(signum, _frame):
        """Record the delivered signal before publishing the requested terminal status."""
        (root / (name + '-signal.txt')).write_text(str(signum), encoding='ascii')
        if capture:
            print('0 packets captured\n0 packets received by filter\n0 packets dropped by kernel', file=sys.stderr)
        raise SystemExit(exit_code)

    signal.signal(signal.SIGINT, finish)
    signal.signal(signal.SIGTERM, finish)
    signal.signal(signal.SIGALRM, finish)
    signal.alarm(15)
    (root / (name + '.json')).write_text(json.dumps({
        'pid': os.getpid(), 'process_group': os.getpgrp(), 'session': os.getsid(0),
    }), encoding='ascii')
    if capture:
        print('listening on fixture0', file=sys.stderr, flush=True)
    else:
        print('CHILD_READY', flush=True)
    signal.pause()


async def harness(root: Path, phase: str, child_exit: int) -> int:
    """Exercise the real CLI, orchestrator and supervisor under a controlling terminal."""
    fcntl.ioctl(sys.stdin.fileno(), termios.TIOCSCTTY, 0)
    config = TestConfig(
        process=ProcessConfig(runtime_root=root / 'runtime', validation_root=root / 'kit'),
        output_dir=root,
    )
    child_ready = asyncio.Event()

    def observe(_name, line):
        """Use a fixture handshake without changing production readiness semantics."""
        if line == 'CHILD_READY':
            child_ready.set()

    supervisor = AsyncProcessSupervisor(config.process, root, observe)
    orchestrator = TestOrchestrator(config)

    async def wait_ready(_process):
        """Expose either the startup wait or the running phase to terminal interruption."""
        await child_ready.wait()
        if phase == 'startup':
            print('INTERRUPT_READY', flush=True)
            await asyncio.Event().wait()

    async def setup():
        """Attach the real process owner before entering its fallible startup path."""
        orchestrator._supervisor = supervisor  # pylint: disable=protected-access
        if phase == 'spawn':
            create_process = asyncio.create_subprocess_exec
            parent_task = asyncio.current_task()

            async def delayed_process(*arguments, **options):
                """Deliver Ctrl+C after real spawn but before ownership returns to the caller."""
                process = await create_process(*arguments, **options)
                if await process.stdout.readline() != b'CHILD_READY\n':
                    raise RuntimeError('fixture child did not become ready')
                print('INTERRUPT_READY', flush=True)
                while not parent_task.cancelling():
                    await asyncio.sleep(0)
                return process

            with patch('kinetum_validation.process.supervisor.asyncio.create_subprocess_exec', new=delayed_process):
                await supervisor._start_process(  # pylint: disable=protected-access
                    'kinetum_photon', fixture_command('photon', str(root), str(child_exit)),
                )
        else:
            await supervisor._start_process(  # pylint: disable=protected-access
                'kinetum_photon', fixture_command('photon', str(root), str(child_exit)),
            )
        if phase == 'capture':
            traffic = NativeTapTrafficDriver(config, root / 'sender', root / 'analyzer')
            orchestrator._traffic = traffic  # pylint: disable=protected-access
            create_process = asyncio.create_subprocess_exec

            async def capture_process(*_arguments, **options):
                """Substitute only the capture image, retaining production pipe/session options."""
                return await create_process(*fixture_command('capture', str(root), '0'), **options)

            with (
                patch(
                    'kinetum_validation.traffic.native_tap.require_system_executable',
                    return_value='/fixture/tcpdump',
                ),
                patch('kinetum_validation.traffic.native_tap.asyncio.create_subprocess_exec', new=capture_process),
            ):
                await traffic.start_capture(root / 'capture.pcap', 'udp')
        return True

    async def packet_test(_context, _size):
        """Hold an active test until the parent writes Ctrl+C to the terminal."""
        print('INTERRUPT_READY', flush=True)
        await asyncio.Event().wait()

    async def run_suite(_config):
        """Keep execution and cleanup in the production orchestration path."""
        return await orchestrator.run()

    with (
        patch.object(supervisor, '_wait_runtime_ready', new=wait_ready),
        patch.object(orchestrator, '_setup', new=setup),
        patch('kinetum_validation.orchestrator.run_packet_test', new=packet_test),
        patch.object(validation_cli, 'parse_args', return_value=SimpleNamespace(verbose=False)),
        patch.object(validation_cli, 'validate_args', return_value=True),
        patch.object(validation_cli, 'build_config', return_value=config),
        patch.object(validation_cli, 'run_test_suite', new=run_suite),
    ):
        return await validation_cli.main()


if __name__ == '__main__':
    if sys.argv[1] in ('photon', 'capture'):
        child(Path(sys.argv[2]), int(sys.argv[3]), capture=sys.argv[1] == 'capture')
    elif sys.argv[1] == 'harness':
        try:
            sys.exit(asyncio.run(harness(Path(sys.argv[2]), sys.argv[3], int(sys.argv[4]))))
        except KeyboardInterrupt:
            print('Interrupted by user', file=sys.stderr)
            sys.exit(130)
    elif sys.argv[1] == 'trex':
        run_endpoint(Path(sys.argv[2]), sys.argv[3])
    else:
        raise ValueError('unknown process fixture role')
