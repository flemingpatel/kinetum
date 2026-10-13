"""TAP validation must observe provider-owned links without repairing them."""

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from kinetum_validation.backend.dpdk_tap import DPDKTapBackend
from kinetum_validation.config.types import (
    BackendConfig,
    BackendType,
    CONSTANTS,
    DEPLOYMENT_SPECS,
    DeploymentMode,
)


@contextmanager
def _tap_host():
    """Own isolated provider links and kernel controls through one backend operation."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)

        def host_path(path: str) -> Path:
            """Map one Linux host path into the private filesystem."""
            return root / path.lstrip("/")

        profile = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(BackendType.DPDK_TAP)
        backend = DPDKTapBackend(BackendConfig(backend_type=BackendType.DPDK_TAP, ports=profile.ports))
        for port in profile.ports:
            interface = host_path(f"/sys/class/net/{port.tap_iface}")
            interface.mkdir(parents=True)
            (interface / "flags").write_text("0x1003\n", encoding="ascii")
            (interface / "mtu").write_text("1500\n", encoding="ascii")
            controls = host_path(f"/proc/sys/net/ipv4/conf/{port.tap_iface}")
            controls.mkdir(parents=True)
            for name in ("forwarding", "accept_local"):
                (controls / name).write_text("1\n", encoding="ascii")
        with patch("kinetum_validation.backend.dpdk_tap.Path", side_effect=host_path):
            yield root, backend


class TestDPDKTapBackend(unittest.IsolatedAsyncioTestCase):
    """Exercise link readiness and forwarding controls through isolated host files."""

    async def test_ready_links_preserve_mtu_and_disable_kernel_forwarding(self):
        """Setup changes only the forwarding controls after provider link activation."""
        with _tap_host() as (root, backend), patch("asyncio.create_subprocess_exec") as subprocess:
            await backend.setup()
            subprocess.assert_not_called()
            for port in backend.config.ports:
                interface = root / f"sys/class/net/{port.tap_iface}"
                self.assertEqual((interface / "flags").read_text(encoding="ascii"), "0x1003\n")
                self.assertEqual((interface / "mtu").read_text(encoding="ascii"), "1500\n")
                controls = root / f"proc/sys/net/ipv4/conf/{port.tap_iface}"
                for name in ("forwarding", "accept_local"):
                    self.assertEqual((controls / name).read_text(encoding="ascii"), "0\n")

    async def test_inactive_or_unreadable_link_rejects_without_repair(self):
        """A down, malformed, or missing link-state file cannot be hidden by setup."""
        for value in ("0x1002\n", "-1\n", "invalid\n", None):
            with (
                self.subTest(flags=value), _tap_host() as (root, backend),
                patch("asyncio.create_subprocess_exec") as subprocess,
            ):
                flags = root / "sys/class/net/neb_rx1/flags"
                if value is None:
                    flags.unlink()
                else:
                    flags.write_text(value, encoding="ascii")
                with self.assertRaisesRegex(RuntimeError, "TAP .*neb_rx1"):
                    await backend.setup()
                subprocess.assert_not_called()
                self.assertEqual(flags.read_text(encoding="ascii") if flags.exists() else None, value)
                self.assertEqual(
                    (root / "proc/sys/net/ipv4/conf/neb_rx0/forwarding").read_text(encoding="ascii"),
                    "1\n",
                )

    async def test_missing_forwarding_control_fails_setup(self):
        """Link readiness alone cannot authorize traffic without forwarding isolation."""
        with _tap_host() as (root, backend):
            (root / "proc/sys/net/ipv4/conf/neb_rx0/forwarding").unlink()
            with self.assertRaisesRegex(RuntimeError, "forwarding control is absent for neb_rx0"):
                await backend.setup()

    def test_default_frame_sizes_fit_the_authored_mtu(self):
        """The default sweep uses supplied frame bytes, with no four-byte FCS double count."""
        self.assertEqual(CONSTANTS.PACKET_SIZES[-1], 14 + 1500)
        self.assertTrue(all(size - 14 <= 1500 for size in CONSTANTS.PACKET_SIZES))
