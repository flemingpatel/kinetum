"""
Kinetum Platform - Physical-I/O Validation Framework
====================================================

Asyncio-based test framework for validating Kinetum data-plane behavior using
backend-profiled DPDK interfaces. The default local integration profile is
DPDK TAP; DPDK PCI is available for exact
provider-plan validation and external traffic-generator runs. These harness
profiles do not select a runtime provider.

Design Philosophy (aligned with Kinetum Platform)
------------------------------------------------
- **Mechanism vs Policy**: Framework provides async primitives (mechanism),
  test scenarios compose them into validation logic (policy)
- **Single-loop ownership**: Scenario orchestration runs on one asyncio loop;
  subprocess and traffic resources retain explicit owners
- **Explicit Dependencies**: Local control uses the Python standard library;
  selected profiles invoke exact native helpers and declared system or remote
  test tools
- **Failure Discipline**: Explicit asyncio task ownership and bounded cleanup
  prevent a failed scenario from abandoning process or traffic resources

Architecture
------------
::

    +-----------------------------------------------------------------------+
    |                         TestOrchestrator                              |
    +-----------------------------------------------------------------------+
    | AsyncProcessSupervisor  BackendProfile        TrafficDriver           |
    | (Photon-owned pair)     (validation setup)    (send/capture owner)    |
    |                                                                       |
    |                         ConsoleReporter                               |
    |                         (real-time output)                            |
    +-----------------------------------------------------------------------+

Deployment Modes
----------------
- **PASSTHROUGH**: Simple RX -> TX forwarding (baseline validation)
- **FAN_IN_EDGE_GATEWAY**: Two ingress RX/parse/ACL chains join at NAT, then QoS/TX (3 regions)

Test Types
----------
- **STANDARD**: Live fixed-epoch forwarding (loss, throughput, and
  profile-owned latency when available)
- **EPOCH**: Ordered transition and boundary evidence
- **COMMIT_CONFIRMED / ROLLBACK**: Exact live mutation workflows
- **GUARDRAILS**: Telemetry-attributed durable automatic rollback
- **FULL**: Composition of all implemented workflows

Usage
-----
CLI::

    # Fan-in edge gateway fixed-epoch packet test
    python -m kinetum_validation --runtime-root /opt/kinetum --deployment fan-in-edge-gateway --test-type standard

    # Epoch workflow authoring and verified-bundle dry run
    python -m kinetum_validation --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway --test-type epoch --dry-run

    # Physical-port provider-plan dry run
    python -m kinetum_validation --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway --backend dpdk-pci --dry-run

Programmatic::

    import asyncio
    from pathlib import Path
    from kinetum_validation import (
        VALIDATION_ROOT, TestConfig, ProcessConfig, DeploymentMode, TestType,
    )
    from kinetum_validation.orchestrator import run_test_suite

    async def main():
        config = TestConfig(
            process=ProcessConfig(
                runtime_root=Path("/opt/kinetum"),
                validation_root=VALIDATION_ROOT,
            ),
            deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
            test_type=TestType.STANDARD,
        )
        result = await run_test_suite(config)
        return result.all_passed

    asyncio.run(main())

Version: admitted from the selected validation resources before execution
"""

from pathlib import Path

from .config.types import (
    CONSTANTS,
    BackendConfig,
    BackendProfile,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    DeploymentSpec,
    EpochConfig,
    PacketConfig,
    PortSpec,
    ProcessConfig,
    StreamTopologyProfile,
    TestConfig,
    TestType,
    TestResult,
    EpochTestResult,
    StatsValidationResult,
    TestSuiteResult,
    TrafficEndpointConfig,
    TrafficDriverType,
    PacketStats,
    AnalysisResult,
)


VALIDATION_ROOT = Path(__file__).resolve().parent / "data"

__all__ = [
    "VALIDATION_ROOT",
    "CONSTANTS",
    "BackendConfig",
    "BackendProfile",
    "BackendType",
    "DEPLOYMENT_SPECS",
    "DeploymentMode",
    "DeploymentSpec",
    "EpochConfig",
    "PacketConfig",
    "PortSpec",
    "ProcessConfig",
    "StreamTopologyProfile",
    "TestConfig",
    "TestType",
    "TestResult",
    "EpochTestResult",
    "StatsValidationResult",
    "TestSuiteResult",
    "TrafficEndpointConfig",
    "TrafficDriverType",
    "PacketStats",
    "AnalysisResult",
]
