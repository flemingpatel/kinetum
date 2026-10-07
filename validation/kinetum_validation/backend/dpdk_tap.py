"""
DPDK TAP backend lifecycle.

DPDK creates TAP interfaces that appear as regular Linux network interfaces.
This backend waits for those interfaces, sets their MTU, brings them up, and
keeps the kernel from forwarding around Kinetum. Packet injection and capture
are owned by the native TAP traffic driver.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from ..config.logger import log_info
from ..config.types import CONSTANTS
from ..process.system_tools import (
    IP_EXECUTABLE,
    communicate_bounded_subprocess,
    exact_subprocess_environment,
    require_system_executable,
)
from .base import Backend


TAP_INTERFACE_WAIT_TIMEOUT_S = 30.0
TAP_INTERFACE_POLL_INTERVAL_S = 0.5


class DPDKTapBackend(Backend):
    """
    DPDK TAP PMD backend resource manager.

    Parameters
    ----------
    config : BackendConfig
        Backend configuration.
    """

    async def setup(self) -> None:
        """
        Set up DPDK TAP backend.

        Waits for TAP interfaces to appear and configures them for Kinetum DP
        ownership. Traffic generation is initialized by the traffic driver.
        """
        log_info("dpdk_tap", "setting up backend...")

        # Wait for interfaces to appear (created by kinetum_dp)
        await self._wait_for_interfaces(TAP_INTERFACE_WAIT_TIMEOUT_S)

        # Configure interfaces
        await self._configure_interfaces()

        log_info("dpdk_tap", "backend ready")

    async def teardown(self) -> None:
        """Release backend resources."""
        log_info("dpdk_tap", "tearing down backend...")

        log_info("dpdk_tap", "backend torn down")

    async def _wait_for_interfaces(self, timeout: float) -> None:
        """Wait for TAP interfaces to be created by DPDK."""
        interfaces = [p.tap_iface for p in self.config.ports]
        log_info("dpdk_tap", f"waiting for interfaces: {', '.join(interfaces)}")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        pending = set(interfaces)

        while pending and loop.time() < deadline:
            for iface in list(pending):
                if Path(f"/sys/class/net/{iface}").exists():
                    pending.discard(iface)
                    log_info("dpdk_tap", f"interface {iface} ready")

            if pending:
                await asyncio.sleep(TAP_INTERFACE_POLL_INTERVAL_S)

        if pending:
            raise RuntimeError(
                f"Timeout waiting for interfaces: {', '.join(pending)}"
            )

    async def _configure_interfaces(self) -> None:
        """Configure TAP interface MTU, disable kernel forwarding, and bring up."""
        ip_executable = require_system_executable(IP_EXECUTABLE, "ip utility")
        for iface in [p.tap_iface for p in self.config.ports]:
            # Set MTU (required for 1518-byte and jumbo packets)
            proc = await asyncio.create_subprocess_exec(
                ip_executable, "link", "set", iface, "mtu", str(CONSTANTS.TAP_MTU),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                env=exact_subprocess_environment(),
            )
            _, stderr = await communicate_bounded_subprocess(proc, 10.0, 5.0)
            if proc.returncode != 0:
                raise RuntimeError(
                    f"Failed to set MTU on {iface}: {stderr.decode()}"
                )

            # Bring interface up
            proc = await asyncio.create_subprocess_exec(
                ip_executable, "link", "set", iface, "up",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                env=exact_subprocess_environment(),
            )
            _, stderr = await communicate_bounded_subprocess(proc, 10.0, 5.0)
            if proc.returncode != 0:
                raise RuntimeError(
                    f"Failed to bring up {iface}: {stderr.decode()}"
                )

            log_info("dpdk_tap", f"configured {iface}: MTU={CONSTANTS.TAP_MTU}, UP")

        # Without this, Linux kernel forwards packets between neb_rx and neb_tx
        # in addition to DPDK, duplicating traffic and bypassing module policy.
        await self._disable_kernel_forwarding()

    async def _disable_kernel_forwarding(self) -> None:
        """
        Disable kernel IP forwarding on TAP interfaces.

        This prevents the Linux kernel from forwarding packets between
        neb_rx and neb_tx, which would cause packet duplication and
        bypass DPDK processing (e.g., NAT wouldn't be applied).
        """
        for iface in [p.tap_iface for p in self.config.ports]:
            controls = (
                (
                    Path(f"/proc/sys/net/ipv4/conf/{iface}/forwarding"),
                    "forwarding",
                ),
                (
                    Path(f"/proc/sys/net/ipv4/conf/{iface}/accept_local"),
                    "accept_local",
                ),
            )
            for control_path, control_name in controls:
                try:
                    if not control_path.exists():
                        raise RuntimeError(
                            f"kernel {control_name} control is absent for {iface}"
                        )
                    control_path.write_text("0\n", encoding="utf-8")
                    if control_path.read_text(encoding="utf-8").strip() != "0":
                        raise RuntimeError(
                            f"kernel {control_name} control did not retain zero "
                            f"for {iface}"
                        )
                except OSError as exc:
                    raise RuntimeError(
                        f"cannot disable {control_name} on {iface}"
                    ) from exc
            log_info("dpdk_tap", f"disabled kernel forwarding on {iface}")

        log_info("dpdk_tap", "kernel forwarding disabled on TAP interfaces")
