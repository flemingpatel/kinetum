"""
Core types and constants for Kinetum physical-I/O validation framework.

Configuration records are immutable. Result records remain mutable only while
their owning scenario assembles one terminal observation.

Design:
-------
- DeploymentMode: Which pipeline to test
- TestType: What kind of test to run (standard, epoch, full)
- BackendType: Physical validation-infrastructure profile (dpdk_tap, dpdk_pci)
- StreamTopologyProfile: Binding topology variant selected before planning
- TrafficDriverType: Owner of packet generation/capture timing

The separation allows orthogonal combinations:
  - passthrough + standard  (baseline validation)
  - passthrough + epoch     (not meaningful - no modules to reconfigure)
  - fan_in_edge_gateway + standard (full pipeline validation)
  - fan_in_edge_gateway + epoch    (boundary-ordering validation)
  - fan_in_edge_gateway + dpdk_pci + dry_run (physical plan validation)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
from pathlib import Path
import posixpath
from typing import Dict, List, Optional, Tuple


# Constants

class CONSTANTS:
    """Fixed physical-validation bounds and shared defaults."""

    # Standard packet sizes for testing (DPDK standard sizes)
    PACKET_SIZES: Tuple[int, ...] = (64, 128, 256, 512, 1024, 1518)

    # Process management
    PROCESS_READY_TIMEOUT_S: int = 30
    # Photon owns two child termination graces and its final logging drain.
    PROCESS_SHUTDOWN_TIMEOUT_S: int = 30

    TAP_MTU: int = 9000     # Jumbo frame support

    # gRPC endpoints
    DP_ENDPOINT: str = "127.0.0.1:50052"
    CP_ENDPOINT: str = "127.0.0.1:50051"

    # Test thresholds
    MAX_ACCEPTABLE_LOSS_PCT: float = 1.0
    RX_RSS_2_MIN_NUM_FLOWS: int = 64
    MAX_PACKET_RATE_PPS: int = 1_000_000_000

    # Epoch boundary-ordering test tolerance
    # TAP interfaces may drop a few packets at test boundaries (timing variance)
    # This characterizes kernel/capture timing, not epoch inconsistency.
    # Allow up to 0.1% loss while still validating the epoch mechanism.
    EPOCH_LOSS_TOLERANCE_PCT: float = 0.1


# Enums


class DeploymentMode(Enum):
    """
    Deployment pipeline to test.

    PASSTHROUGH: Simple RX -> TX forwarding (no processing stages)
                 - Baseline validation, TAP PMD testing
                 - Uses the mandatory explicit module-free bootstrap snapshot
                 - Does not admit module-configuration transition scenarios

    FAN_IN_EDGE_GATEWAY: Multi-ingress edge pipeline with fan-in join
                    - Each ingress worker executes RX, parsing, and ACL
                    - NAT selects its session owner in region 2, followed by QoS and TX
                    - Two worker handoffs by default; eight with two RSS lanes
                    - 3 regions, 2 cross-region pipeline edges
                    - Uses built-in ACL, NAT44, and QoS modules
    """
    PASSTHROUGH = "passthrough"
    FAN_IN_EDGE_GATEWAY = "fan_in_edge_gateway"


class TestType(Enum):
    """
    Type of test to run.

    STANDARD: Basic packet forwarding test
              - Send N packets, verify receipt
              - Measure loss and throughput, plus profile-owned latency when available

    EPOCH: boundary-ordering validation for config transitions
           - Continuous traffic while config changes
           - Verify exact packet evidence within the declared validation loss bound
           - Only meaningful for deployments with modules to reconfigure

    COMMIT_CONFIRMED: Commit-confirmed pattern validation
                      - Apply baseline during setup
                      - Apply config with --confirm-timeout
                      - Verify traffic works
                      - Confirm within timeout
                      - Verify auto-rollback if not confirmed

    ROLLBACK: Selective rollback validation
              - Apply multiple configs
              - Rollback specific modules only
              - Verify partial rollback preserves other modules

    GUARDRAILS: Guardrails auto-rollback validation
                - Configure guardrails thresholds
                - Generate traffic that triggers thresholds
                - Verify auto-rollback occurs

    FULL: Run every implemented scenario
    """
    STANDARD = "standard"
    EPOCH = "epoch"
    COMMIT_CONFIRMED = "commit_confirmed"
    ROLLBACK = "rollback"
    GUARDRAILS = "guardrails"
    FULL = "full"


class BackendType(Enum):
    """
    Physical validation-infrastructure profile.

    This selector chooses the test harness's traffic endpoint and host setup.
    It is not propagated into Gluon or the dataplane and does not select a
    runtime provider.

    DPDK_TAP: Linux TAP interfaces attached through DPDK TAP PMD
              - Virtual NICs created by DPDK and configured locally
              - Native TAP traffic driver injects/captures packets

    DPDK_PCI: Real NICs bound by the exact deployment plan
              - Physical PCI ports owned by kinetum_dp
              - External traffic driver required for non-dry-run tests
    """
    DPDK_TAP = "dpdk_tap"
    DPDK_PCI = "dpdk_pci"


class StreamTopologyProfile(Enum):
    """
    Binding topology profile selected before Gluon planning.

    DEFAULT selects deployment bindings with one explicit queue per direction.
    RX_RSS_2 selects deployment bindings with queues 0 and 1 plus an exact RSS
    contract for each fan-in ingress. Neither profile creates a runtime
    provider default.
    """
    DEFAULT = "default"
    RX_RSS_2 = "rx_rss_2"


class StorageProfile(Enum):
    """Select authored shared storage or a separate domain for each RX queue."""

    SHARED = "shared"
    PER_RX_QUEUE = "per_rx_queue"


class TrafficDriverType(Enum):
    """
    Packet generation/capture owner for the selected backend.

    NATIVE_TAP is local AF_PACKET traffic against Linux TAP interfaces.
    TREX drives a remote TRex stateless API endpoint for physical-NIC traffic.
    """
    NATIVE_TAP = "native_tap"
    TREX = "trex"


class TransitionType(str, Enum):
    """
    Epoch transition kind for telemetry classification.

    Each value tags a transition_metrics.jsonl record so distributions
    can be sliced by transition category (epoch vs rollback vs commit).
    Inherits from str so .value is directly usable as a JSON string.
    """
    EPOCH = "epoch"
    COMMIT_CONFIRMED = "commit_confirmed"
    COMMIT_CONFIRMED_TIMEOUT_ROLLBACK = "commit_confirmed_timeout_rollback"
    ROLLBACK_APPLY_V1 = "rollback_apply_v1"
    ROLLBACK_APPLY_V2 = "rollback_apply_v2"
    ROLLBACK_SELECTIVE = "rollback_selective"
    ROLLBACK_FULL = "rollback_full"
    GUARDRAILS_ROLLBACK = "guardrails_rollback"


@dataclass(frozen=True)
class PortSpec:
    """
    One traffic-driver port mapping for validation.

    Runtime port truth lives in the Gluon plan generated from bindings. This
    structure only names the traffic-driver role and peer-side interface used
    for injection or capture. For physical-NIC traffic generators,
    runtime_direction and runtime_mac are copied from the generated plan before
    traffic starts.
    """
    logical_name: str
    tap_iface: str
    traffic_role: str
    peer_iface: str = ""
    peer_ip: str = ""
    traffic_port_id: int = -1
    runtime_direction: str = ""
    runtime_mac: str = ""

    @property
    def traffic_iface(self) -> str:
        """Return the local traffic interface name for TAP-style send/capture."""
        return self.tap_iface or self.peer_iface


@dataclass(frozen=True)
class BackendProfile:
    """
    Physical validation-infrastructure deployment profile.

    A deployment describes the logical pipeline. This profile selects the
    exact deployment bindings, hardware inventory, and traffic endpoint for a
    concrete validation environment. It also names the exact timestamp,
    rate-control, and optional measured-latency authorities used in artifacts.
    It is not a runtime-provider selector.
    """
    backend_type: BackendType
    bindings_files: Dict[Tuple[StreamTopologyProfile, StorageProfile], str]
    hw_file: str
    ports: Tuple[PortSpec, ...]
    traffic_driver: TrafficDriverType
    timestamp_source: str
    rate_control_source: str
    latency_source: Optional[str]

    def bindings_file_for(
        self,
        stream_topology: StreamTopologyProfile,
        storage_profile: StorageProfile,
    ) -> str:
        """Return the authored bindings for one exact topology/storage pair."""
        try:
            return self.bindings_files[stream_topology, storage_profile]
        except KeyError as exc:
            raise ValueError(
                f"{self.backend_type.value} has no bindings for stream topology "
                f"{stream_topology.value} with storage profile {storage_profile.value}"
            ) from exc


@dataclass(frozen=True)
class DeploymentSpec:
    """
    Data-driven deployment descriptor.

    Each DeploymentMode maps to exactly one DeploymentSpec via the
    DEPLOYMENT_SPECS registry. The spec carries every deployment-owned input
    needed by scenario choreography; callers never infer a fixture name from
    another snapshot.

    Attributes
    ----------
    example_dir : str
        Subdirectory under the installed examples root.
    pipeline_file : str
        Axiom pipeline filename.
    config_snapshot : str
        Mandatory permissive bootstrap snapshot filename.
    config_snapshot_v2 : Optional[str]
        Distinct transition and rollback snapshot, or ``None`` for a
        module-free deployment.
    guardrails_degradation_snapshot : Optional[str]
        Dedicated deterministic degradation snapshot, or ``None`` for a
        module-free deployment.
    regions : int
        Exact logical-region count expected from planning.
    needs_modules : bool
        Whether bundle construction requires installed module images.
    backend_profiles : Dict[BackendType, BackendProfile]
        Exact physical validation profiles admitted for this deployment.
    """
    example_dir: str                    # subdir under examples/
    pipeline_file: str                  # .axiom.pbtxt filename
    config_snapshot: str                # mandatory bootstrap snapshot filename
    config_snapshot_v2: Optional[str]   # v2 snapshot for epoch/rollback, or None
    guardrails_degradation_snapshot: Optional[str]
    regions: int                        # Gluon region count
    needs_modules: bool                 # bundle requires installed module images
    backend_profiles: Dict[BackendType, BackendProfile]

    def backend_profile(self, backend_type: BackendType) -> BackendProfile:
        """Return the backend profile or fail closed for unsupported mappings."""
        try:
            return self.backend_profiles[backend_type]
        except KeyError as exc:
            raise ValueError(
                f"{self.example_dir} does not support backend {backend_type.value}"
            ) from exc

    def scenario_errors(self, test_type: TestType) -> List[str]:
        """Return missing deployment facts for one requested scenario."""
        errors = []
        if test_type in {
            TestType.EPOCH,
            TestType.COMMIT_CONFIRMED,
            TestType.ROLLBACK,
            TestType.GUARDRAILS,
            TestType.FULL,
        } and not self.needs_modules:
            errors.append(
                f"Test type '{test_type.value.replace('_', '-')}' requires a "
                "module-based deployment"
            )
        if (
            test_type in {
                TestType.EPOCH,
                TestType.COMMIT_CONFIRMED,
                TestType.ROLLBACK,
                TestType.FULL,
            }
            and self.needs_modules
            and self.config_snapshot_v2 is None
        ):
            errors.append(
                f"Test type '{test_type.value.replace('_', '-')}' requires an "
                "explicit transition snapshot"
            )
        elif (
            test_type in {
                TestType.EPOCH,
                TestType.COMMIT_CONFIRMED,
                TestType.ROLLBACK,
                TestType.FULL,
            }
            and self.needs_modules
            and self.config_snapshot_v2 == self.config_snapshot
        ):
            errors.append(
                f"Test type '{test_type.value.replace('_', '-')}' requires a "
                "transition snapshot distinct from bootstrap"
            )
        if (
            test_type in {TestType.GUARDRAILS, TestType.FULL}
            and self.needs_modules
            and self.guardrails_degradation_snapshot is None
        ):
            errors.append(
                f"Test type '{test_type.value.replace('_', '-')}' requires an "
                "explicit guardrails degradation snapshot"
            )
        elif (
            test_type in {TestType.GUARDRAILS, TestType.FULL}
            and self.needs_modules
            and self.guardrails_degradation_snapshot
            in {self.config_snapshot, self.config_snapshot_v2}
        ):
            errors.append(
                f"Test type '{test_type.value.replace('_', '-')}' requires a "
                "dedicated guardrails degradation snapshot"
            )
        return errors


def required_scenario_example_files(
    spec: DeploymentSpec,
    backend_profile: BackendProfile,
    stream_topology: StreamTopologyProfile,
    storage_profile: StorageProfile,
    test_type: TestType,
) -> Tuple[str, ...]:
    """Return the complete ordered example-file set needed by one run."""
    names = [
        spec.pipeline_file,
        backend_profile.hw_file,
        backend_profile.bindings_file_for(stream_topology, storage_profile),
        spec.config_snapshot,
    ]
    if (
        test_type in {
            TestType.EPOCH,
            TestType.COMMIT_CONFIRMED,
            TestType.ROLLBACK,
            TestType.FULL,
        }
        and spec.config_snapshot_v2 is not None
    ):
        names.append(spec.config_snapshot_v2)
    if (
        test_type in {TestType.GUARDRAILS, TestType.FULL}
        and spec.guardrails_degradation_snapshot is not None
    ):
        names.append(spec.guardrails_degradation_snapshot)
    return tuple(dict.fromkeys(names))


# Deployment Spec Registry - single source of truth for all deployment modes

DEPLOYMENT_SPECS: Dict[DeploymentMode, DeploymentSpec] = {
    DeploymentMode.PASSTHROUGH: DeploymentSpec(
        example_dir="passthrough",
        pipeline_file="passthrough.axiom.pbtxt",
        config_snapshot="config_snapshot.pbtxt",
        config_snapshot_v2=None,
        guardrails_degradation_snapshot=None,
        regions=1,
        needs_modules=False,
        backend_profiles={
            BackendType.DPDK_TAP: BackendProfile(
                backend_type=BackendType.DPDK_TAP,
                bindings_files={
                    (StreamTopologyProfile.DEFAULT, StorageProfile.SHARED): "passthrough_tap_bindings.pbtxt",
                },
                hw_file="hardware_inventory_tap.pbtxt",
                ports=(
                    PortSpec("wan0", "neb_rx", "rx", traffic_port_id=0),
                    PortSpec("lan0", "neb_tx", "tx", traffic_port_id=1),
                ),
                traffic_driver=TrafficDriverType.NATIVE_TAP,
                timestamp_source="kernel_af_packet",
                rate_control_source="userspace_native_sender",
                latency_source="kernel_af_packet_pcap",
            ),
        },
    ),
    DeploymentMode.FAN_IN_EDGE_GATEWAY: DeploymentSpec(
        example_dir="fan_in_edge_gateway",
        pipeline_file="fan_in_edge_gateway.axiom.pbtxt",
        config_snapshot="config_snapshot.pbtxt",
        config_snapshot_v2="config_snapshot_v2.pbtxt",
        guardrails_degradation_snapshot="config_snapshot_guardrails_degradation.pbtxt",
        regions=3,
        needs_modules=True,
        backend_profiles={
            BackendType.DPDK_TAP: BackendProfile(
                backend_type=BackendType.DPDK_TAP,
                bindings_files={
                    (StreamTopologyProfile.DEFAULT, StorageProfile.SHARED): "fan_in_edge_gateway_tap_bindings.pbtxt",
                },
                hw_file="hardware_inventory_tap.pbtxt",
                ports=(
                    PortSpec("wan0", "neb_rx0", "rx", traffic_port_id=0),
                    PortSpec("wan1", "neb_rx1", "rx", traffic_port_id=1),
                    PortSpec("lan0", "neb_tx", "tx", traffic_port_id=2),
                ),
                traffic_driver=TrafficDriverType.NATIVE_TAP,
                timestamp_source="kernel_af_packet",
                rate_control_source="userspace_native_sender",
                latency_source="kernel_af_packet_pcap",
            ),
            BackendType.DPDK_PCI: BackendProfile(
                backend_type=BackendType.DPDK_PCI,
                bindings_files={
                    (StreamTopologyProfile.DEFAULT, StorageProfile.SHARED):
                        "fan_in_edge_gateway_cloudlab_d430_bindings.pbtxt",
                    (StreamTopologyProfile.RX_RSS_2, StorageProfile.SHARED):
                        "fan_in_edge_gateway_cloudlab_d430_rx_rss_2_bindings.pbtxt",
                    (StreamTopologyProfile.DEFAULT, StorageProfile.PER_RX_QUEUE):
                        "fan_in_edge_gateway_cloudlab_d430_per_rx_queue_bindings.pbtxt",
                    (StreamTopologyProfile.RX_RSS_2, StorageProfile.PER_RX_QUEUE):
                        "fan_in_edge_gateway_cloudlab_d430_rx_rss_2_per_rx_queue_bindings.pbtxt",
                },
                hw_file="hardware_inventory_cloudlab_d430.pbtxt",
                ports=(
                    PortSpec(
                        logical_name="wan0",
                        tap_iface="",
                        traffic_role="rx",
                        peer_iface="enp6s0f0np0",
                        peer_ip="10.10.1.1",
                        traffic_port_id=0,
                    ),
                    PortSpec(
                        logical_name="wan1",
                        tap_iface="",
                        traffic_role="rx",
                        peer_iface="enp6s0f2np2",
                        peer_ip="10.10.2.1",
                        traffic_port_id=1,
                    ),
                    PortSpec(
                        logical_name="lan0",
                        tap_iface="",
                        traffic_role="tx",
                        peer_iface="enp6s0f1np1",
                        peer_ip="10.10.3.2",
                        traffic_port_id=2,
                    ),
                ),
                traffic_driver=TrafficDriverType.TREX,
                timestamp_source="trex_port_stats",
                rate_control_source="trex_stl_rate_control",
                latency_source=None,
            ),
        },
    ),
}


# Configuration Dataclasses

@dataclass(frozen=True)
class PacketConfig:
    """
    Packet generation configuration.

    Attributes
    ----------
    pps : int
        Positive target packets per second; no zero-rate burst mode exists.
    count : int
        Positive packet target for count-based tests; ignored when duration is
        positive.
    duration_s : float
        Test duration in seconds (0 = use count).
    packet_size : int
        Packet size in bytes.
    all_sizes : bool
        Test all standard sizes (64, 128, 256, 512, 1024, 1518).
    num_flows : int
        Number of flows for RSS testing.
    src_ip : str
        Source IP address.
    dst_ip : str
        Destination IP address.
    base_sport : int
        Base source port (varied by flow_id).
    base_dport : int
        Base destination port.
    """
    pps: int = 1000
    count: int = 1000
    duration_s: float = 0.0  # 0 = use count
    packet_size: int = 64
    all_sizes: bool = False
    num_flows: int = 1
    src_ip: str = "10.0.0.100"
    dst_ip: str = "192.168.1.1"
    base_sport: int = 10000
    base_dport: int = 9999

    @property
    def sizes_to_test(self) -> Tuple[int, ...]:
        """Return packet sizes to test."""
        if self.all_sizes:
            return CONSTANTS.PACKET_SIZES
        return (self.packet_size,)


@dataclass(frozen=True)
class ProcessConfig:
    """
    Explicit installed runtime and independent private validation-kit roots.

    Attributes
    ----------
    runtime_root : Path
        Exact installed runtime root containing bin/ and lib/modules/.
    validation_root : Path
        Exact private kit root containing bin/ and examples/, outside the runtime.
    dp_endpoint : str
        Data plane gRPC endpoint.
    cp_endpoint : str
        Control plane gRPC endpoint.
    """
    runtime_root: Path
    validation_root: Path
    dp_endpoint: str = CONSTANTS.DP_ENDPOINT
    cp_endpoint: str = CONSTANTS.CP_ENDPOINT

    @property
    def runtime_bin_dir(self) -> Path:
        """Return the fixed binary directory beneath the installed runtime."""
        return self.runtime_root / "bin"

    @property
    def module_dir(self) -> Path:
        """Return the fixed built-in module directory beneath the runtime."""
        return self.runtime_root / "lib" / "modules"

    @property
    def validation_bin_dir(self) -> Path:
        """Return the validation-only native-helper directory."""
        return self.validation_root / "bin"

    @property
    def examples_dir(self) -> Path:
        """Return the private kit's exact example-source directory."""
        return self.validation_root / "examples"


@dataclass(frozen=True)
class EpochConfig:
    """
    Epoch test configuration.

    Attributes
    ----------
    duration_s : float
        Total epoch test duration.
    pps : int
        Packets per second during epoch test.
    transition_time_s : float
        When to trigger epoch transition.
    overlap_window_ms : int
        Sustained overlap window for traffic drivers that schedule both the
        initial and next generation-tag streams instead of switching one live
        sender tag.
    """
    duration_s: float = 15.0
    pps: int = 1000
    transition_time_s: float = 5.0
    overlap_window_ms: int = 500


@dataclass(frozen=True)
class BackendConfig:
    """
    Physical validation-infrastructure configuration.

    Attributes
    ----------
    backend_type : BackendType
        Which physical validation profile to use.
    ports : Tuple[PortSpec, ...]
        Traffic-driver port table derived from the backend profile.
    """
    backend_type: BackendType = BackendType.DPDK_TAP
    ports: Tuple[PortSpec, ...] = (
        PortSpec("wan0", "neb_rx", "rx"),
        PortSpec("lan0", "neb_tx", "tx"),
    )

    @property
    def rx_ports(self) -> Tuple[PortSpec, ...]:
        """RX ports where the test injects packets into DP ingress."""
        return tuple(p for p in self.ports if p.traffic_role == "rx")

    @property
    def tx_ports(self) -> Tuple[PortSpec, ...]:
        """TX ports where the test captures packets from DP egress."""
        return tuple(p for p in self.ports if p.traffic_role == "tx")


@dataclass(frozen=True)
class TrafficEndpointConfig:
    """
    External traffic endpoint configuration.

    The local TAP driver ignores this block. The TRex driver uses it to connect
    to one external traffic-generator endpoint. Runtime provider ownership
    remains exact plan truth and is not represented here.

    Attributes
    ----------
    host : str
        SSH host or configured alias for the external traffic endpoint.
    ssh_port : int
        SSH TCP port, or 0 to use the SSH client default/configured port.
    python : str
        Python executable used on the traffic endpoint.
    work_dir : str
        Directory for temporary endpoint-side artifacts.
    trex_server : str
        TRex stateless server address from the traffic endpoint's perspective.
    trex_api_path : str
        Optional exact directory inserted into the remote interpreter's module
        search path before importing TRex APIs.
    trex_ports : Tuple[int, ...]
        Optional ordered override for traffic-generator port IDs.
    """
    host: str = ""
    ssh_port: int = 0
    python: str = "/usr/bin/python3"
    work_dir: str = "/tmp/kinetum_traffic"
    trex_server: str = "127.0.0.1"
    trex_api_path: str = ""
    trex_ports: Tuple[int, ...] = ()


def _exact_remote_path(value: str, allow_empty: bool) -> bool:
    """Return whether one endpoint path has the admitted POSIX representation."""
    if not value:
        return allow_empty
    return all((
        value.startswith("/"),
        not value.startswith("//"),
        posixpath.normpath(value) == value,
        value.isprintable(),
        len(value.encode("utf-8")) <= 4096,
    ))


def traffic_endpoint_errors(
    endpoint: TrafficEndpointConfig,
    *,
    live: bool,
    expected_port_count: Optional[int] = None,
) -> List[str]:
    """
    Return every exact external-traffic endpoint admission error.

    Parameters
    ----------
    endpoint : TrafficEndpointConfig
        Candidate endpoint identity.
    live : bool
        Whether a remote TRex action will execute.
    expected_port_count : int, optional
        Exact deployment port population for a nonempty override.

    Returns
    -------
    List[str]
        Empty on exact admission; otherwise stable operator diagnostics.
    """
    if not live:
        return [] if endpoint == TrafficEndpointConfig() else [
            "traffic-endpoint options require a live dpdk-pci run"
        ]

    errors = []
    if (
        not endpoint.host
        or endpoint.host.startswith("-")
        or not endpoint.host.isprintable()
        or any(character.isspace() for character in endpoint.host)
        or len(endpoint.host.encode("utf-8")) > 255
    ):
        errors.append("--traffic-host must be one bounded printable non-option atom")
    if (
        not isinstance(endpoint.ssh_port, int)
        or isinstance(endpoint.ssh_port, bool)
        or not 0 <= endpoint.ssh_port <= 65535
    ):
        errors.append("--traffic-ssh-port must be between 0 and 65535")
    for option, value, allow_empty in (
        ("--traffic-python", endpoint.python, False),
        ("--traffic-work-dir", endpoint.work_dir, False),
        ("--trex-api-path", endpoint.trex_api_path, True),
    ):
        if not _exact_remote_path(value, allow_empty):
            errors.append(f"{option} must be a bounded exact absolute path")
    if (
        not endpoint.trex_server
        or endpoint.trex_server.startswith("-")
        or not endpoint.trex_server.isprintable()
        or any(character.isspace() for character in endpoint.trex_server)
        or len(endpoint.trex_server.encode("utf-8")) > 255
    ):
        errors.append("--trex-server must be one bounded printable endpoint")
    if (
        len(endpoint.trex_ports) != len(set(endpoint.trex_ports))
        or any(
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 0 <= port <= (1 << 32) - 1
            for port in endpoint.trex_ports
        )
    ):
        errors.append("--trex-port identities must be unique uint32 values")
    if (
        endpoint.trex_ports
        and expected_port_count is not None
        and len(endpoint.trex_ports) != expected_port_count
    ):
        errors.append(
            "--trex-port overrides must match the selected deployment port count"
        )
    return errors


@dataclass(frozen=True)
class TestConfig:
    """
    Complete test configuration.

    Attributes
    ----------
    deployment : DeploymentMode
        Which pipeline to test.
    test_type : TestType
        What kind of test to run (standard, epoch, full).
    packet : PacketConfig
        Packet generation configuration.
    process : ProcessConfig
        Process configuration.
    epoch : EpochConfig
        Epoch test configuration.
    backend : BackendConfig
        Physical validation profile and traffic-driver metadata.
    traffic : TrafficEndpointConfig
        External traffic endpoint settings for remote traffic drivers.
    stream_topology : StreamTopologyProfile
        Binding topology profile selected before Gluon planning.
    storage_profile : StorageProfile
        Authored storage arrangement selected before Gluon planning.
    output_dir : Path
        Output directory for logs and captures.
    max_loss_pct : float
        Maximum acceptable loss percentage.
    verbose : bool
        Enable verbose output.
    color : bool
        Permit ANSI color when stderr is a terminal.
    dry_run : bool
        Build and admit the complete deployment without starting packet tests.
    """
    process: ProcessConfig
    deployment: DeploymentMode = DeploymentMode.FAN_IN_EDGE_GATEWAY
    test_type: TestType = TestType.STANDARD
    packet: PacketConfig = field(default_factory=PacketConfig)
    epoch: EpochConfig = field(default_factory=EpochConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)
    traffic: TrafficEndpointConfig = field(default_factory=TrafficEndpointConfig)
    stream_topology: StreamTopologyProfile = StreamTopologyProfile.DEFAULT
    storage_profile: StorageProfile = StorageProfile.SHARED
    output_dir: Path = field(default_factory=lambda: Path("/tmp/kinetum_validation"))
    max_loss_pct: float = CONSTANTS.MAX_ACCEPTABLE_LOSS_PCT
    verbose: bool = False
    color: bool = True
    dry_run: bool = False

    @property
    def spec(self) -> DeploymentSpec:
        """Deployment spec for this test configuration."""
        return DEPLOYMENT_SPECS[self.deployment]

    @property
    def backend_profile(self) -> BackendProfile:
        """Backend profile selected for this test configuration."""
        return self.spec.backend_profile(self.backend.backend_type)

    @property
    def bindings_file(self) -> str:
        """Bindings filename selected by backend, stream topology, and storage."""
        return self.backend_profile.bindings_file_for(self.stream_topology, self.storage_profile)

    @property
    def required_example_files(self) -> Tuple[str, ...]:
        """Complete example inputs admitted before run-root ownership."""
        return required_scenario_example_files(
            self.spec,
            self.backend_profile,
            self.stream_topology,
            self.storage_profile,
            self.test_type,
        )


# Result Dataclasses

@dataclass
class PacketStats:
    """
    Statistics from packet generation.

    Mutable for incremental updates during generation.
    """
    tx_count: int = 0
    errors: int = 0
    generation_tag_counts: Dict[int, int] = field(default_factory=dict)
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration_s(self) -> float:
        """Generation duration in seconds."""
        if self.start_time >= 0.0 and self.end_time > self.start_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def actual_pps(self) -> float:
        """Actual packets per second achieved."""
        return self.tx_count / self.duration_s if self.duration_s > 0 else 0.0


@dataclass
class AnalysisResult:
    """
    Results from packet capture analysis.
    """
    total_rx: int = 0
    valid: int = 0
    invalid: int = 0
    duplicates: int = 0
    out_of_order: int = 0
    missing_count: int = 0
    tag_counts: Dict[int, int] = field(default_factory=dict)
    transition_seq: int = -1
    tag_transition_count: int = 0

    def loss_pct(self, expected: int) -> float:
        """Return nonnegative loss; excess observations remain duplicates."""
        if expected <= 0:
            return 0.0
        return max(0, expected - self.valid) / expected * 100

    # Sole validated latency publication from the native analyzer.
    _latency_stats_cache: Optional[Dict[str, float]] = field(
        default=None, init=False, repr=False
    )

    def set_latency_stats(self, stats: Dict[str, float]) -> None:
        """Store one validated native-analyzer latency publication."""
        expected = {"avg", "min", "max", "p50", "p99"}
        if self._latency_stats_cache is not None or set(stats) != expected:
            raise ValueError("latency statistics are not one valid publication")
        if any(
            not isinstance(value, (int, float)) or isinstance(value, bool)
            for value in stats.values()
        ):
            raise ValueError("latency statistics are not one valid publication")
        try:
            normalized = {name: float(value) for name, value in stats.items()}
        except (OverflowError, ValueError) as exc:
            raise ValueError(
                "latency statistics are not one valid publication"
            ) from exc
        if (
            any(not math.isfinite(value) or value <= 0.0 for value in normalized.values())
            or not normalized["min"]
            <= normalized["p50"]
            <= normalized["p99"]
            <= normalized["max"]
            or not normalized["min"] <= normalized["avg"] <= normalized["max"]
        ):
            raise ValueError("latency statistics are not one valid publication")
        self._latency_stats_cache = normalized

    def latency_stats(self) -> Optional[Dict[str, float]]:
        """Return a copy of measured latency or explicit unavailability."""
        return (
            dict(self._latency_stats_cache)
            if self._latency_stats_cache is not None
            else None
        )


@dataclass
class TestResult:
    """
    Result of a single test run.

    ``avg_latency_us`` is present only when the selected profile owns a
    measured latency source; unsupported or unobserved latency is ``None``.
    """
    packet_size: int
    passed: bool
    tx_count: int = 0
    rx_count: int = 0
    loss_pct: float = 0.0
    avg_latency_us: Optional[float] = None
    throughput_pps: float = 0.0
    duration_s: float = 0.0
    message: str = ""


@dataclass
class NatExchangeResult:
    """Packet-level translation evidence outside the measured traffic window."""

    passed: bool
    session_count: int = 0
    return_count: int = 0
    context_count: int = 0
    duration_s: float = 0.0
    message: str = ""


@dataclass
class EpochTestResult:
    """
    Result of epoch transition test.

    ``avg_latency_us`` follows the selected profile's nullable latency law.
    """
    passed: bool
    duration_s: float = 0.0
    total_sent: int = 0
    total_received: int = 0
    initial_generation_sent: int = 0
    next_generation_sent: int = 0
    initial_generation_received: int = 0
    next_generation_received: int = 0
    generation_tag_transition_seq: int = -1
    transitions_observed: int = 0
    loss_pct: float = 0.0
    avg_latency_us: Optional[float] = None
    # Exact ordered-CUT proof from final runtime telemetry.
    boundary_count: int = 0
    completed_boundaries: int = 0
    protocol_faults_observed: int = 0
    backpressure_events: int = 0
    boundary_ordering_validated: bool = False
    message: str = ""

    @property
    def zero_loss(self) -> bool:
        """True if no packets lost during epoch transition."""
        return self.total_sent == self.total_received and self.total_sent > 0


@dataclass
class CommitConfirmedTestResult:
    """
    Result of commit-confirmed pattern test.

    ``avg_latency_us`` follows the selected profile's nullable latency law.
    """
    passed: bool
    duration_s: float = 0.0
    # Confirm scenario
    confirm_success: bool = False
    confirm_snapshot_id: str = ""
    confirm_time_remaining_ms: int = 0
    # Timeout scenario (optional - if we test auto-rollback)
    timeout_rollback_occurred: bool = False
    timeout_rollback_snapshot_id: str = ""
    # Traffic-under-transition metrics
    tx_count: int = 0
    rx_count: int = 0
    loss_pct: float = 0.0
    avg_latency_us: Optional[float] = None
    message: str = ""


@dataclass
class RollbackTestResult:
    """
    Result of rollback test.

    ``avg_latency_us`` follows the selected profile's nullable latency law.
    """
    passed: bool
    duration_s: float = 0.0
    # Full rollback
    full_rollback_success: bool = False
    full_rollback_snapshot_id: str = ""
    # Selective rollback
    selective_rollback_success: bool = False
    selective_rollback_modules: List[str] = field(default_factory=list)
    selective_rollback_snapshot_id: str = ""
    # Traffic-under-transition metrics
    tx_count: int = 0
    rx_count: int = 0
    loss_pct: float = 0.0
    avg_latency_us: Optional[float] = None
    message: str = ""


@dataclass
class GuardrailsTestResult:
    """Result of one telemetry-driven durable automatic rollback scenario.

    Attributes
    ----------
    passed : bool
        Whether the complete deterministic degradation and rollback proof held.
    duration_s : float
        Scenario duration in seconds.
    policy_configured : bool
        Whether the exact guardrails policy was durably admitted.
    baseline_snapshot_id : str
        Permissive content identity used to build the positive baseline.
    candidate_snapshot_id : str
        Dedicated degradation content activated by the scenario.
    rollback_snapshot_id : str
        Content identity restored by automatic rollback.
    candidate_epoch : int
        Exact completed candidate epoch.
    rollback_epoch : int
        Exact later automatic-rollback epoch.
    protocol_faults_observed : int
        Protocol-fault delta across the rollback transition.
    message : str
        Human-readable terminal verdict.
    """

    passed: bool
    duration_s: float = 0.0
    policy_configured: bool = False
    baseline_snapshot_id: str = ""
    candidate_snapshot_id: str = ""
    rollback_snapshot_id: str = ""
    candidate_epoch: int = 0
    rollback_epoch: int = 0
    protocol_faults_observed: int = 0
    message: str = ""


@dataclass
class StatsValidationResult:
    """
    Result of post-run dataplane evidence validation.

    The packet tests prove forwarding behavior. Some physical-I/O profiles also
    require topology evidence from final DP stats, for example multi-stream RSS
    runs where every requested RX stream must be materialized and exercised.

    Attributes
    ----------
    required : bool
        Whether this run shape required stats-backed evidence validation.
    passed : bool
        Whether the required evidence was present and clean.
    message : str
        Human-readable verdict or failure reason.
    """
    required: bool = False
    passed: bool = True
    message: str = ""


@dataclass
class TestSuiteResult:
    """
    Complete test suite results.
    """
    deployment: DeploymentMode
    test_type: TestType
    packet_tests: List[TestResult] = field(default_factory=list)
    nat_exchange: Optional[NatExchangeResult] = None
    epoch_test: Optional[EpochTestResult] = None
    commit_confirmed_test: Optional[CommitConfirmedTestResult] = None
    rollback_test: Optional[RollbackTestResult] = None
    guardrails_test: Optional[GuardrailsTestResult] = None
    stats_validation: StatsValidationResult = field(default_factory=StatsValidationResult)
    total_duration_s: float = 0.0
    setup_failed: bool = False  # True if setup failed before tests could run
    dry_run: bool = False

    @property
    def all_passed(self) -> bool:
        """True if all tests passed, or if dry-run setup completed."""
        if self.dry_run:
            return not self.setup_failed
        # If setup failed or no tests ran, it's a failure
        if self.setup_failed or self.total_tests == 0:
            return False
        packet_pass = all(t.passed for t in self.packet_tests) if self.packet_tests else True
        nat_pass = self.nat_exchange.passed if self.nat_exchange else True
        epoch_pass = self.epoch_test.passed if self.epoch_test else True
        commit_pass = self.commit_confirmed_test.passed if self.commit_confirmed_test else True
        rollback_pass = self.rollback_test.passed if self.rollback_test else True
        guardrails_pass = self.guardrails_test.passed if self.guardrails_test else True
        stats_pass = (
            self.stats_validation.passed
            if self.stats_validation.required
            else True
        )
        return (
            packet_pass and epoch_pass and commit_pass and rollback_pass
            and guardrails_pass and stats_pass and nat_pass
        )

    @property
    def total_tests(self) -> int:
        """Total number of tests."""
        count = len(self.packet_tests)
        if self.nat_exchange:
            count += 1
        if self.epoch_test:
            count += 1
        if self.commit_confirmed_test:
            count += 1
        if self.rollback_test:
            count += 1
        if self.guardrails_test:
            count += 1
        if self.stats_validation.required:
            count += 1
        return count

    @property
    def passed_tests(self) -> int:
        """Number of passed tests."""
        count = sum(1 for t in self.packet_tests if t.passed)
        if self.nat_exchange and self.nat_exchange.passed:
            count += 1
        if self.epoch_test and self.epoch_test.passed:
            count += 1
        if self.commit_confirmed_test and self.commit_confirmed_test.passed:
            count += 1
        if self.rollback_test and self.rollback_test.passed:
            count += 1
        if self.guardrails_test and self.guardrails_test.passed:
            count += 1
        if self.stats_validation.required and self.stats_validation.passed:
            count += 1
        return count

    @property
    def failed_tests(self) -> int:
        """Number of failed tests."""
        return self.total_tests - self.passed_tests
