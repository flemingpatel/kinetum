"""Exact system executable identities used by physical validation."""

from __future__ import annotations

import asyncio
import math
import os
from pathlib import Path
from typing import Dict, Optional, Tuple


# Cancellation and programming faults remain outside ordinary operation failures.
RECOVERABLE_EXCEPTIONS = (RuntimeError, OSError, ValueError)


IP_EXECUTABLE = Path("/usr/sbin/ip")
SSH_EXECUTABLE = Path("/usr/bin/ssh")
TCPDUMP_EXECUTABLE = Path("/usr/bin/tcpdump")


def exact_subprocess_environment() -> Dict[str, str]:
    """
    Return the inherited environment without loader interposition authority.

    Exact executable-path admission is meaningful only when ambient ``LD_*``
    variables cannot redirect that image's dependency resolution. Other
    environment entries, including SSH agent state, remain caller policy.
    """
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("LD_")
    }


def _request_subprocess_exit(
    process: asyncio.subprocess.Process,
    *,
    force: bool,
) -> Optional[BaseException]:
    """Request TERM or KILL and return a non-racy signaling failure."""
    if process.returncode is not None:
        return None
    try:
        if force:
            process.kill()
        else:
            process.terminate()
    except ProcessLookupError:
        return None
    # A failed signal is evidence, but later drain/reap attempts must still run.
    except BaseException as exc:  # pylint: disable=broad-exception-caught
        return exc
    return None


async def terminate_and_drain_subprocess(
    process: asyncio.subprocess.Process,
    grace_s: float,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Terminate one pipe-backed child and drain both output streams exactly.

    ``Process.wait()`` alone can deadlock when an interrupted ``communicate()``
    leaves a full pipe. This helper keeps output consumption and process
    reaping under one owner, escalates once after a positive grace, and fails
    rather than abandoning inherited pipe ownership.

    Parameters
    ----------
    process : asyncio.subprocess.Process
        Exact child whose prior ``communicate()`` owner has stopped.
    grace_s : float
        Positive TERM and post-KILL drain bound in seconds.

    Returns
    -------
    Tuple[Optional[bytes], Optional[bytes]]
        Remaining stdout and stderr bytes.

    Raises
    ------
    RuntimeError
        If the grace is invalid or output ownership does not retire after KILL.
    """
    if not math.isfinite(grace_s) or grace_s <= 0.0:
        raise RuntimeError("subprocess retirement grace must be positive")
    # Cancellation and unexpected pipe failures must both retire the child.
    first_failure: Optional[BaseException] = _request_subprocess_exit(
        process, force=False
    )
    try:
        result = await asyncio.wait_for(process.communicate(), timeout=grace_s)
    except BaseException as exc:  # pylint: disable=broad-exception-caught
        if first_failure is None:
            first_failure = exc
        signal_failure = _request_subprocess_exit(process, force=True)
        if signal_failure is not None and isinstance(
            first_failure, asyncio.TimeoutError
        ):
            first_failure = signal_failure
        try:
            result = await asyncio.wait_for(
                process.communicate(), timeout=grace_s
            )
        except BaseException as drain_error:
            if process.returncode is None:
                signal_failure = _request_subprocess_exit(process, force=True)
                if signal_failure is not None:
                    drain_error = signal_failure
                try:
                    await asyncio.wait_for(process.wait(), timeout=grace_s)
                except BaseException as wait_error:
                    raise RuntimeError(
                        "subprocess process ownership did not retire after forced exit"
                    ) from wait_error
            raise RuntimeError(
                "subprocess output ownership did not retire after forced exit"
            ) from drain_error
    if process.returncode is None:
        signal_failure = _request_subprocess_exit(process, force=True)
        try:
            await asyncio.wait_for(process.wait(), timeout=grace_s)
        except BaseException as wait_error:
            raise RuntimeError(
                "subprocess process ownership did not retire after output drain"
            ) from wait_error
        if process.returncode is None:
            raise RuntimeError(
                "subprocess process ownership remained nonterminal after wait"
            )
        if signal_failure is not None and first_failure is None:
            first_failure = signal_failure
    if first_failure is not None and not isinstance(
        first_failure, asyncio.TimeoutError
    ):
        raise first_failure
    return result


async def communicate_bounded_subprocess(
    process: asyncio.subprocess.Process,
    timeout_s: float,
    retirement_grace_s: float,
    input_data: Optional[bytes] = None,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Collect one child result while preserving ownership on every exception.

    A timeout, cancellation, pipe failure, or unexpected exception first
    retires and drains the child through ``terminate_and_drain_subprocess``;
    only then is the original exception re-raised. A cleanup failure replaces
    it with explicit unresolved-ownership failure.

    Parameters
    ----------
    process : asyncio.subprocess.Process
        Exact pipe-backed child to communicate with.
    timeout_s : float
        Positive finite completion bound in seconds.
    retirement_grace_s : float
        Positive finite TERM and post-KILL drain bound in seconds.
    input_data : Optional[bytes]
        Complete optional stdin payload transferred by ``communicate``.

    Returns
    -------
    Tuple[Optional[bytes], Optional[bytes]]
        Complete stdout and stderr bytes.

    Raises
    ------
    RuntimeError
        If either bound is invalid or child retirement cannot be proven.
    BaseException
        The original communication exception after exact child retirement.
    """
    if (
        not math.isfinite(timeout_s)
        or timeout_s <= 0.0
        or not math.isfinite(retirement_grace_s)
        or retirement_grace_s <= 0.0
    ):
        raise RuntimeError("subprocess completion and retirement bounds must be positive")
    try:
        communication = (
            process.communicate()
            if input_data is None
            else process.communicate(input_data)
        )
        result = await asyncio.wait_for(communication, timeout=timeout_s)
    except BaseException:
        await terminate_and_drain_subprocess(process, retirement_grace_s)
        raise
    if process.returncode is None:
        await terminate_and_drain_subprocess(process, retirement_grace_s)
        raise RuntimeError(
            "subprocess communication completed without terminal process status"
        )
    return result


def require_system_executable(path: Path, purpose: str) -> str:
    """Return an exact executable path or fail before process construction."""
    try:
        exact_path = path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError(f"{purpose} executable is unavailable: {path}") from exc
    if (
        not path.is_absolute()
        or not path.is_file()
        or path.is_symlink()
        or exact_path != path
        or not os.access(path, os.X_OK)
    ):
        raise RuntimeError(f"{purpose} is not an exact executable: {path}")
    return os.fspath(path)
