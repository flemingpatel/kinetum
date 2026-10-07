"""
Async Process Supervisor - manage one installed kinetum_photon process.

Provides async process lifecycle management with:
- Installed-root, bundle-only startup
- Real-time stdout/stderr streaming
- Typed CP serving and DP PACKET_READY admission
- Graceful shutdown with timeout
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, TextIO

from ..config.types import CONSTANTS, ProcessConfig
from ..config.logger import log_info, log_warn
from .installation import (
    is_symlink_free_directory,
    is_symlink_free_regular_file,
)
from .system_tools import exact_subprocess_environment
from .kinetumctl import KinetumCtl


class AsyncProcessSupervisor:
    """
    Async supervisor for the installed Photon-owned DP/CP pair.

    Manages process lifecycle with real-time log streaming and
    exact readiness detection. Photon alone owns child-image selection,
    verified-bundle admission, bootstrap ordering, and pair-scoped teardown.

    Parameters
    ----------
    config : ProcessConfig
        Process configuration.
    output_dir : Path
        Fresh run-owned directory for the Photon log and CP durable state.
    log_callback : Callable[[str, str], None], optional
        Called with (process_name, log_line) for each log line.
    """

    def __init__(
        self,
        config: ProcessConfig,
        output_dir: Path,
        log_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        """Bind one run-owned output root and installed process authority."""
        self.config = config
        self.log_callback = log_callback
        self.output_dir = output_dir
        self._processes: Dict[str, asyncio.subprocess.Process] = {}
        self._stream_tasks: Dict[str, asyncio.Task] = {}
        self._log_files: Dict[str, Path] = {}
        self._log_handles: Dict[str, TextIO] = {}

    async def start_runtime(self, bundle_root: Path) -> None:
        """
        Start the installed Photon supervisor over one complete bundle.

        Parameters
        ----------
        bundle_root : Path
            Exact absolute runtime-bundle root produced by kinetum_pack.

        Raises
        ------
        RuntimeError
            If process fails to start or reach ready state.
        FileNotFoundError
            If Photon or the complete bundle is absent.
        """
        if self._processes:
            raise RuntimeError("the Photon ownership tree is already running")

        photon = self.config.runtime_bin_dir / "kinetum_photon"
        if (
            not is_symlink_free_regular_file(photon)
            or not os.access(photon, os.X_OK)
        ):
            raise FileNotFoundError(f"kinetum_photon not found: {photon}")
        if (
            not bundle_root.is_absolute()
            or not is_symlink_free_directory(bundle_root)
        ):
            raise FileNotFoundError(
                f"complete absolute runtime bundle not found: {bundle_root}"
            )

        if not is_symlink_free_directory(self.output_dir):
            raise RuntimeError("validation output root is not exact")
        cp_store_dir = self.output_dir / "cp_store"
        cp_store_dir.mkdir(mode=0o700)
        log_dir = self.output_dir / "logs"
        log_dir.mkdir(mode=0o700)

        cmd = [
            str(photon),
            "--bundle", str(bundle_root),
            "--cp-listen", self.config.cp_endpoint,
            "--dp-endpoint", self.config.dp_endpoint,
            "--config-store-dir", str(cp_store_dir),
            "--log-dir", str(log_dir),
            "--log-console",
        ]

        await self._start_process("kinetum_photon", cmd)

    def _owned_children_started(self, photon_pid: int) -> bool:
        """Require both installed child roles beneath the live Photon process."""
        children_path = Path(f"/proc/{photon_pid}/task/{photon_pid}/children")
        try:
            children = children_path.read_text(encoding="ascii").split()
            expected = {
                self.config.runtime_bin_dir / "kinetum_dp",
                self.config.runtime_bin_dir / "kinetum_cp",
            }
            observed = set()
            for child in children:
                if not child.isascii() or not child.isdecimal() or int(child) <= 0:
                    raise RuntimeError("Photon child inventory contains an invalid PID")
                image = Path(f"/proc/{child}/exe").resolve(strict=True)
                if image in expected:
                    if image in observed:
                        raise RuntimeError("Photon owns duplicate service roles")
                    observed.add(image)
            return observed == expected
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise RuntimeError("could not inspect Photon child ownership") from exc

    async def _wait_runtime_ready(self, process: asyncio.subprocess.Process) -> None:
        """Poll typed health while the parent race owns exit, output, and timeout."""
        cp = KinetumCtl(self.config.runtime_root, self.config.cp_endpoint)
        dp = KinetumCtl(self.config.runtime_root, self.config.dp_endpoint)
        while process.returncode is None:
            if (
                self._owned_children_started(process.pid)
                and await cp.is_ready("cp")
                and await dp.is_ready("dp")
            ):
                return
            await asyncio.sleep(0.1)
        raise RuntimeError("Photon exited before typed packet readiness")

    async def _start_process(
        self,
        name: str,
        cmd: List[str],
    ) -> None:
        """Start a process with readiness detection."""
        log_info("supervisor", f"starting {name}: {' '.join(cmd)}")

        log_path = self.output_dir / "photon.log"
        try:
            # The handle intentionally spans child startup and asynchronous
            # output service; a lexical with-block cannot own that lifetime.
            log_file = open(
                log_path, "x", encoding="utf-8"
            )
        except OSError as exc:
            raise RuntimeError(f"could not create exact process log: {log_path}") from exc
        self._log_files[name] = log_path
        self._log_handles[name] = log_file

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=exact_subprocess_environment(),
            )
        except BaseException:
            log_file.close()
            self._log_handles.pop(name, None)
            self._log_files.pop(name, None)
            raise

        self._processes[name] = process

        # Start log streaming task
        self._stream_tasks[name] = asyncio.create_task(
            self._stream_output(name, process)
        )

        log_info("supervisor", f"{name} started (PID: {process.pid})")

        # Readiness, child exit, and output-service failure race under one
        # bounded wait. A dead child or dead pipe owner cannot consume the full
        # readiness timeout while appearing merely slow.
        ready_waiter = asyncio.create_task(self._wait_runtime_ready(process))
        exit_waiter = asyncio.create_task(process.wait())
        stream_task = self._stream_tasks[name]
        try:
            done, _pending = await asyncio.wait(
                {ready_waiter, exit_waiter, stream_task},
                timeout=CONSTANTS.PROCESS_READY_TIMEOUT_S,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                raise RuntimeError(f"{name} failed to reach ready state")
            if (
                ready_waiter in done
                and exit_waiter not in done
                and stream_task not in done
                and process.returncode is None
            ):
                ready_waiter.result()
                log_info("supervisor", f"{name} is ready")
                return
            if stream_task in done:
                stream_failure = stream_task.exception()
                if stream_failure is not None:
                    raise RuntimeError(
                        f"{name} output service failed before readiness"
                    ) from stream_failure
            if process.returncode is not None or exit_waiter in done:
                raise RuntimeError(f"{name} exited with code {process.returncode}")
            raise RuntimeError(f"{name} failed to reach ready state")
        finally:
            for waiter in (ready_waiter, exit_waiter):
                if not waiter.done():
                    waiter.cancel()
            await asyncio.gather(
                ready_waiter, exit_waiter, return_exceptions=True
            )

    async def _stream_output(
        self,
        name: str,
        process: asyncio.subprocess.Process,
    ) -> None:
        """Preserve process output without turning diagnostic text into authority."""
        if not process.stdout:
            return

        log_file = self._log_handles[name]
        try:
            async for line in process.stdout:
                text = line.decode("utf-8", errors="replace").removesuffix("\n")
                if not text:
                    continue

                log_file.write(text + "\n")
                log_file.flush()

                if self.log_callback:
                    self.log_callback(name, text)
                else:
                    sys.stderr.write(text + "\n")
                    sys.stderr.flush()
        finally:
            log_file.close()
            self._log_handles.pop(name, None)

    async def stop_all(self) -> None:
        """Stop all managed processes gracefully."""
        log_info("supervisor", "stopping all processes...")

        for name in list(self._processes.keys()):
            await self.stop(name)

    async def stop(self, name: str) -> None:
        """Stop a specific process."""
        process = self._processes.get(name)
        if not process:
            return

        log_info("supervisor", f"stopping {name}...")
        exited_before_stop = process.returncode is not None

        # Keep draining the combined output pipe while Photon performs its
        # bounded child cleanup; canceling the reader first can fill the pipe
        # and deadlock the very shutdown being awaited.
        task = self._stream_tasks.get(name)
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=CONSTANTS.PROCESS_SHUTDOWN_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                log_warn("supervisor", f"force killing {name}...")
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                try:
                    await asyncio.wait_for(
                        process.wait(),
                        timeout=CONSTANTS.PROCESS_SHUTDOWN_TIMEOUT_S,
                    )
                except asyncio.TimeoutError as exc:
                    raise RuntimeError(
                        f"{name} process ownership did not retire after forced exit"
                    ) from exc

        task_failure: Optional[BaseException] = None
        if task:
            done, _pending = await asyncio.wait({task}, timeout=5.0)
            if not done:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                task_failure = RuntimeError(
                    f"{name} output service did not drain after process exit"
                )
            elif task.cancelled():
                task_failure = RuntimeError(
                    f"{name} output service was cancelled before retirement"
                )
            else:
                task_failure = task.exception()

        log_info("supervisor", f"{name} stopped (code: {process.returncode})")

        # Cleanup
        self._processes.pop(name, None)
        self._stream_tasks.pop(name, None)
        remaining_handle = self._log_handles.pop(name, None)
        if remaining_handle is not None:
            try:
                remaining_handle.close()
            except OSError as exc:
                if task_failure is None:
                    task_failure = exc
        if task_failure is not None:
            raise RuntimeError(f"{name} output service did not retire cleanly") from task_failure
        if exited_before_stop:
            raise RuntimeError(
                f"{name} exited before harness-requested shutdown: "
                f"{process.returncode}"
            )
        if process.returncode != 0:
            raise RuntimeError(
                f"{name} shutdown did not complete cleanly: {process.returncode}"
            )
