#!/usr/bin/env python3
"""Own bounded subprocess groups for source-tree documentation tooling.

The documentation producer uses this mechanism for dependency setup and
rendering. Installed validation tooling retains its separate
process owner because the documentation and validation package roots have
independent installation contracts and must not import across that boundary.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence


class DocumentationProcessError(RuntimeError):
    """Report one subprocess ownership, deadline, or output-bound failure."""

    def __init__(self, message: str, output: bytes = b"") -> None:
        """Retain a bounded output prefix with one process-owner failure."""

        super().__init__(message)
        self.output = output


@dataclasses.dataclass(frozen=True)
class DocumentationProcessResult:
    """Carry one reaped command's return code and bounded output."""

    returncode: int
    output: bytes = b""


def _validate_request(
    command: Sequence[str], timeout_seconds: float, output_limit_bytes: int | None
) -> None:
    """Reject malformed process requests before creating a child."""

    if not command or any(not isinstance(value, str) or not value for value in command):
        raise DocumentationProcessError("documentation command must be a nonempty argv")
    if timeout_seconds <= 0:
        raise DocumentationProcessError("documentation command timeout must be positive")
    if output_limit_bytes is not None and output_limit_bytes <= 0:
        raise DocumentationProcessError("documentation output bound must be positive")


def _exact_working_directory(path: pathlib.Path) -> pathlib.Path:
    """Resolve one explicit direct directory once for child process execution."""

    if not path.is_absolute():
        raise DocumentationProcessError(
            "documentation command working directory must be absolute"
        )
    absolute = path.absolute()
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DocumentationProcessError(
            "documentation command working directory is unavailable"
        ) from error
    if absolute != resolved or not resolved.is_dir():
        raise DocumentationProcessError(
            "documentation command working directory must be exact"
        )
    return resolved


def _wait_for_exit_without_reaping(
    process: subprocess.Popen[bytes], deadline: float, output: bytes
) -> None:
    """Observe direct-child exit while retaining its process-group identity."""

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise DocumentationProcessError(
                "documentation command timed out", output
            )
        try:
            observation = os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except InterruptedError:
            continue
        if observation is not None:
            return
        time.sleep(min(remaining, 0.01))


def _process_group_has_descendant(group_id: int) -> bool:
    """Return whether Linux procfs names a member other than the held leader."""

    proc_root = pathlib.Path("/proc")
    if not proc_root.is_dir():
        raise DocumentationProcessError(
            "documentation process ownership requires Linux procfs"
        )
    try:
        entries = tuple(os.scandir(proc_root))
    except OSError as error:
        raise DocumentationProcessError(
            "documentation process membership is unavailable"
        ) from error
    for entry in entries:
        if not entry.name.isdecimal() or int(entry.name) == group_id:
            continue
        try:
            with open(f"{entry.path}/stat", "rb") as stat_file:
                raw = stat_file.read(4097)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        except OSError as error:
            raise DocumentationProcessError(
                "documentation process membership read failed"
            ) from error
        close = raw.rfind(b") ")
        fields = raw[close + 2:].split() if close >= 0 else []
        if len(raw) > 4096 or len(fields) < 3:
            raise DocumentationProcessError(
                "documentation process membership is malformed"
            )
        try:
            member_group = int(fields[2])
        except ValueError as error:
            raise DocumentationProcessError(
                "documentation process membership is malformed"
            ) from error
        if member_group == group_id:
            return True
    return False


def _kill_group_and_reap(process: subprocess.Popen[bytes]) -> None:
    """Kill one accepted private process group and reap its direct child."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        process.wait()


def _finish_direct_child(
    process: subprocess.Popen[bytes], deadline: float, output: bytes = b""
) -> int:
    """Classify descendants while the exited leader still pins group identity."""

    _wait_for_exit_without_reaping(process, deadline, output)
    try:
        os.killpg(process.pid, signal.SIGSTOP)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise DocumentationProcessError(
            "documentation command group could not be frozen", output
        ) from error
    if _process_group_has_descendant(process.pid):
        raise DocumentationProcessError(
            "documentation command left a live descendant process", output
        )
    return process.wait()


def run_captured(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    output_limit_bytes: int,
    working_directory: pathlib.Path,
    environment: Mapping[str, str] | None = None,
) -> DocumentationProcessResult:
    """Run one argv under a private group and capture a bounded byte stream."""

    _validate_request(command, timeout_seconds, output_limit_bytes)
    working_directory = _exact_working_directory(working_directory)
    try:
        # A context manager waits only for the direct child; this owner must
        # kill the complete private process group before that wait on failure.
        # pylint: disable-next=consider-using-with
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=working_directory,
            env=None if environment is None else dict(environment),
            start_new_session=True,
        )
    except OSError as error:
        raise DocumentationProcessError("documentation command could not execute") from error

    output = bytearray()
    deadline = time.monotonic() + timeout_seconds
    selector: selectors.BaseSelector | None = None
    try:
        if process.stdout is None:
            raise DocumentationProcessError("documentation command has no output channel")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DocumentationProcessError(
                    "documentation command timed out", bytes(output)
                )
            events = selector.select(timeout=min(remaining, 0.1))
            if not events:
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            if len(output) + len(chunk) > output_limit_bytes:
                retained = output_limit_bytes - len(output)
                if retained > 0:
                    output.extend(chunk[:retained])
                raise DocumentationProcessError(
                    "documentation command produced excessive output", bytes(output)
                )
            output.extend(chunk)
        returncode = _finish_direct_child(process, deadline, bytes(output))
        return DocumentationProcessResult(returncode, bytes(output))
    except BaseException:
        _kill_group_and_reap(process)
        raise
    finally:
        if selector is not None:
            selector.close()
        if process.stdout is not None:
            process.stdout.close()


def run_visible(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    working_directory: pathlib.Path,
    environment: Mapping[str, str] | None = None,
) -> DocumentationProcessResult:
    """Run one argv with inherited output under a bounded private group."""

    _validate_request(command, timeout_seconds, None)
    working_directory = _exact_working_directory(working_directory)
    try:
        # See run_captured(): group cleanup must precede direct-child waiting.
        # pylint: disable-next=consider-using-with
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            cwd=working_directory,
            env=None if environment is None else dict(environment),
            start_new_session=True,
        )
    except OSError as error:
        raise DocumentationProcessError("documentation command could not execute") from error

    deadline = time.monotonic() + timeout_seconds
    try:
        returncode = _finish_direct_child(process, deadline)
        return DocumentationProcessResult(returncode)
    except BaseException:
        _kill_group_and_reap(process)
        raise
