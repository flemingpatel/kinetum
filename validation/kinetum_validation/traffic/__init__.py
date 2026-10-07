"""
Traffic drivers for Kinetum validation.

The factory derives one traffic driver from the selected backend profile so
the orchestrator does not carry a second driver selector.
"""

from ..config.types import BackendType, TestConfig, TrafficDriverType
from .base import TrafficDriver
from .native_tap import NativeTapTrafficDriver
from .trex import TRexTrafficDriver


def make_traffic_driver(config: TestConfig) -> TrafficDriver:
    """
    Build the selected traffic driver or fail closed for invalid pairings.

    Parameters
    ----------
    config : TestConfig
        Full test configuration.
    Returns
    -------
    TrafficDriver
        Driver selected by the exact backend profile.
    """
    backend_type = config.backend.backend_type
    driver_type = config.backend_profile.traffic_driver

    if driver_type == TrafficDriverType.NATIVE_TAP:
        if backend_type != BackendType.DPDK_TAP:
            raise RuntimeError("native-tap traffic driver requires dpdk-tap backend")
        helper_root = config.process.validation_bin_dir
        return NativeTapTrafficDriver(
            config,
            helper_root / "kinetum_tap_sender",
            helper_root / "kinetum_tap_analyzer",
        )

    if driver_type == TrafficDriverType.TREX:
        if backend_type != BackendType.DPDK_PCI:
            raise RuntimeError("trex traffic driver requires dpdk-pci backend")
        return TRexTrafficDriver(config)

    raise RuntimeError(f"unsupported traffic driver: {driver_type.value}")


__all__ = [
    "TrafficDriver",
    "NativeTapTrafficDriver",
    "TRexTrafficDriver",
    "make_traffic_driver",
]
