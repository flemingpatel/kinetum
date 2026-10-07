"""
Validation-resource lifecycle abstraction for physical-I/O tests.

These profiles make the selected validation environment ready: TAP profiles
wait for provider-created Linux interfaces and physical PCI profiles validate
plan-owned metadata. They never select a runtime provider. Packet generation,
capture, timestamp ownership, and rate-control policy live in traffic drivers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from ..config.types import BackendConfig


class Backend(ABC):
    """
    Abstract base class for validation-resource lifecycle.

    Backends handle:
    - Interface setup/teardown
    - Runtime resource validation
    - Resource management

    Traffic drivers handle packet injection, capture, timestamp ownership, and
    rate control. This split keeps physical resource setup independent from how
    test traffic is generated and from plan-owned runtime provider selection.

    The orchestrator owns setup and teardown explicitly so partial setup and
    cross-component rollback remain in one lifecycle authority.
    """

    def __init__(self, config: BackendConfig) -> None:
        """Bind one backend owner to its immutable physical profile."""
        self.config = config

    @abstractmethod
    async def setup(self) -> None:
        """
        Initialize validation resources.

        Called before any I/O operations. Should:
        - Wait for interfaces to be created (if needed)
        - Configure MTU, bring interfaces up
        - Validate profile-owned metadata and local resources

        Raises
        ------
        RuntimeError
            If setup fails.
        """
        raise NotImplementedError

    @abstractmethod
    async def teardown(self) -> None:
        """
        Release validation resources.

        Called after all I/O operations. Should:
        - Release any held resources
        - Allow interfaces to be cleaned up
        """
        raise NotImplementedError

    def __repr__(self) -> str:
        """Return a stable diagnostic spelling for this backend."""
        return f"{self.__class__.__name__}(type={self.config.backend_type.value})"
