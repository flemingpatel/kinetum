"""
Backend module - data-plane backend resource abstraction.

Backends prepare Kinetum-owned interfaces and metadata. Traffic drivers own
packet generation, capture, timestamp semantics, and rate-control evidence.
"""

from .base import Backend
from .dpdk_pci import DPDKPCIBackend
from .dpdk_tap import DPDKTapBackend

__all__ = [
    "Backend",
    "DPDKPCIBackend",
    "DPDKTapBackend",
]
