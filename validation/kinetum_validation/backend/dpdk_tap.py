"""
DPDK TAP backend lifecycle.

DPDK creates TAP interfaces that appear as regular Linux network interfaces.
This backend verifies provider-created interfaces are up and keeps the kernel
from forwarding around Kinetum. The provider owns their MTU and link state;
the native TAP traffic driver owns packet injection and capture.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from ..config.logger import log_info
from .base import Backend


TAP_INTERFACE_WAIT_TIMEOUT_S = 30.0
TAP_INTERFACE_POLL_INTERVAL_S = 0.5
_IFF_UP = 0x1


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

        Require provider-created links to be up, then disable kernel forwarding.
        Traffic generation is initialized by the traffic driver.
        """
        log_info("dpdk_tap", "setting up backend...")

        # Wait for interfaces to appear (created by kinetum_dp)
        await self._wait_for_interfaces(TAP_INTERFACE_WAIT_TIMEOUT_S)

        self._verify_interfaces()
        await self._disable_kernel_forwarding()

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

    def _verify_interfaces(self) -> None:
        """Require provider-owned link activation without repairing runtime state."""
        for iface in [p.tap_iface for p in self.config.ports]:
            try:
                flags = int(Path(f"/sys/class/net/{iface}/flags").read_text(encoding="ascii"), 16)
            except (OSError, ValueError) as exc:
                raise RuntimeError(f"cannot read TAP link flags for {iface}") from exc
            if flags < 0 or not flags & _IFF_UP:
                raise RuntimeError(
                    f"provider-owned TAP interface is not up: {iface}"
                )
            log_info("dpdk_tap", f"verified {iface}: UP")

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
