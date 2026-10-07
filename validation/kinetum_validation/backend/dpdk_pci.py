"""
DPDK PCI backend descriptor for physical-NIC validation.

The physical backend owns setup metadata only. Real NIC validation uses a
separate exact TRex traffic driver.
"""

from __future__ import annotations

from ..config.logger import log_info
from .base import Backend


class DPDKPCIBackend(Backend):
    """
    DPDK physical PCI backend.

    The selected plan must contain fully bound ``plan.ports[]`` entries whose
    I/O-driver configuration identifies the exact PCI attachments. Native
    facility construction consumes that provider graph; this harness does not
    author or propagate EAL arguments.
    Peer host interfaces are validated here for reproducibility metadata and
    then consumed by the selected traffic driver.
    """

    async def setup(self) -> None:
        """Validate peer metadata while the exact provider plan owns the NIC."""
        missing = [
            port.logical_name for port in self.config.ports
            if not port.peer_iface
        ]
        if missing:
            raise RuntimeError(
                "DPDK PCI backend requires peer interfaces for: "
                + ", ".join(missing)
            )
        log_info("dpdk_pci", "backend metadata validated")

    async def teardown(self) -> None:
        """No local resources are held by the physical backend descriptor."""
        log_info("dpdk_pci", "backend torn down")
