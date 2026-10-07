#!/usr/bin/env python3
"""
Kinetum Physical-I/O Validation - CLI Entry Point.

Validates Kinetum data-plane packet forwarding through declared DPDK
integration and physical profiles.

Usage:
    python -m kinetum_validation --runtime-root /opt/kinetum --deployment fan-in-edge-gateway --test-type standard
    python -m kinetum_validation --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway --test-type epoch --dry-run

Examples:
    # Fan-in edge gateway full pipeline test
    python -m kinetum_validation --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway \\
        --validation-root /var/tmp/kinetum-validation

    # Epoch transition test (boundary-ordering validation)
    python -m kinetum_validation --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway \\
        --test-type epoch \\
        --dry-run \\
        --validation-root /var/tmp/kinetum-validation

    # Canonical TAP gateway test
    python -m kinetum_validation --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway \\
        --test-type standard \\
        --validation-root /var/tmp/kinetum-validation

    # Full test suite with high throughput
    python -m kinetum_validation --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway \\
        --test-type full \\
        --dry-run \\
        --pps 50000 \\
        --all-sizes

    # Physical-port provider-plan dry run
    python -m kinetum_validation --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway \\
        --backend dpdk-pci \\
        --dry-run

    # Physical-port epoch-overlap validation with TRex
    python -m kinetum_validation --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway \\
        --backend dpdk-pci \\
        --traffic-host traffic-host \\
        --test-type epoch
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import math
import os
import sys
import traceback
from pathlib import Path

from . import VALIDATION_ROOT
from .config.logger import set_log_application
from .config.types import (
    CONSTANTS,
    BackendConfig,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    EpochConfig,
    PacketConfig,
    ProcessConfig,
    StreamTopologyProfile,
    StorageProfile,
    TestConfig,
    TestType,
    TrafficEndpointConfig,
    traffic_endpoint_errors,
)
from .orchestrator import run_test_suite
from .process.installation import installed_root_errors


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="kinetum_validation",
        description="Kinetum Physical-I/O Validation Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
        allow_abbrev=False,
    )

    # Deployment mode
    parser.add_argument(
        "--deployment", "-d",
        type=str,
        choices=[mode.value.replace("_", "-") for mode in DeploymentMode],
        default=DeploymentMode.FAN_IN_EDGE_GATEWAY.value.replace("_", "-"),
        help="Deployment mode: fan-in-edge-gateway (multi-ingress, 3 regions), "
             "passthrough (RX->TX)",
    )

    # Test type
    parser.add_argument(
        "--test-type", "-t",
        type=str,
        choices=[test_type.value.replace("_", "-") for test_type in TestType],
        default=TestType.STANDARD.value,
        help="Test type: standard (forwarding), epoch (boundary-ordering transition), "
             "commit-confirmed, rollback, guardrails, full (implemented tests)",
    )

    # Physical validation-infrastructure profile
    parser.add_argument(
        "--backend", "-b",
        type=str,
        choices=[backend.value.replace("_", "-") for backend in BackendType],
        default=BackendType.DPDK_TAP.value.replace("_", "-"),
        help=(
            "Physical validation profile: dpdk-tap (default) or dpdk-pci; "
            "does not select a runtime provider"
        ),
    )
    parser.add_argument(
        "--stream-topology",
        type=str,
        choices=[profile.value.replace("_", "-") for profile in StreamTopologyProfile],
        default=StreamTopologyProfile.DEFAULT.value.replace("_", "-"),
        help="Binding topology profile selected before Gluon planning",
    )
    parser.add_argument(
        "--storage-profile",
        type=str,
        choices=[profile.value.replace("_", "-") for profile in StorageProfile],
        default=StorageProfile.SHARED.value,
        help="Authored packet-storage profile selected before Gluon planning",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compile the selected plan and write metadata without starting DP/CP",
    )

    # External traffic endpoint configuration
    traffic_group = parser.add_argument_group("External Traffic Endpoint")
    traffic_group.add_argument(
        "--traffic-host",
        type=str,
        default="",
        help="SSH host or alias for an external traffic endpoint",
    )
    traffic_group.add_argument(
        "--traffic-ssh-port",
        type=int,
        default=0,
        help="SSH port for --traffic-host (0 = SSH config/default)",
    )
    traffic_group.add_argument(
        "--traffic-python",
        type=str,
        default="/usr/bin/python3",
        help="Exact Python executable on the traffic endpoint (default: /usr/bin/python3)",
    )
    traffic_group.add_argument(
        "--traffic-work-dir",
        type=str,
        default="/tmp/kinetum_traffic",
        help="Exact existing work directory on the traffic endpoint",
    )
    traffic_group.add_argument(
        "--trex-server",
        type=str,
        default="127.0.0.1",
        help="TRex stateless server address as seen by the traffic endpoint",
    )
    traffic_group.add_argument(
        "--trex-api-path",
        type=str,
        default="",
        help="Optional path prepended before importing trex_stl_lib.api",
    )
    traffic_group.add_argument(
        "--trex-port",
        type=int,
        action="append",
        default=[],
        help="Traffic-generator port ID override; repeat in deployment port order",
    )

    # Packet configuration
    packet_group = parser.add_argument_group("Packet Generation")
    packet_group.add_argument(
        "--pps",
        type=int,
        default=1000,
        help="Target packets per second (default: 1000)",
    )
    packet_group.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of packets (default: 1000, ignored if --duration set)",
    )
    packet_group.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Test duration in seconds (0 = use --count)",
    )
    packet_group.add_argument(
        "--packet-size",
        type=int,
        default=64,
        help="Packet size in bytes (default: 64)",
    )
    packet_group.add_argument(
        "--all-sizes",
        action="store_true",
        help="Test all standard sizes (64, 128, 256, 512, 1024, 1518)",
    )
    packet_group.add_argument(
        "--num-flows",
        type=int,
        default=1,
        help=(
            "Number of traffic-generator flows per ingress port; "
            "rx-rss-2 requires at least "
            f"{CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS}, and transition evidence "
            "must fit the bounded JSON result (default: 1)"
        ),
    )
    packet_group.add_argument(
        "--src-ip",
        type=str,
        default="10.0.0.100",
        help="Source IP address (default: 10.0.0.100)",
    )
    packet_group.add_argument(
        "--dst-ip",
        type=str,
        default="192.168.1.1",
        help="Destination IP address (default: 192.168.1.1)",
    )

    # Process configuration
    process_group = parser.add_argument_group("Process Configuration")
    process_group.add_argument(
        "--runtime-root",
        type=Path,
        required=True,
        help="Explicit finalized installed runtime root",
    )
    process_group.add_argument(
        "--validation-root",
        type=Path,
        default=VALIDATION_ROOT,
        help=(
            "Private validation-kit root containing examples/ and bin/ "
            "(default: root containing the running kit's scripts/)"
        ),
    )
    process_group.add_argument(
        "--dp-endpoint",
        type=str,
        default=CONSTANTS.DP_ENDPOINT,
        help=f"DP gRPC endpoint (default: {CONSTANTS.DP_ENDPOINT})",
    )
    process_group.add_argument(
        "--cp-endpoint",
        type=str,
        default=CONSTANTS.CP_ENDPOINT,
        help=f"CP gRPC endpoint (default: {CONSTANTS.CP_ENDPOINT})",
    )

    # Epoch configuration
    epoch_group = parser.add_argument_group("Epoch Test Configuration")
    epoch_group.add_argument(
        "--epoch-duration",
        type=float,
        default=15.0,
        help="Epoch test duration in seconds (default: 15)",
    )
    epoch_group.add_argument(
        "--epoch-pps",
        type=int,
        default=1000,
        help="Packets per second during epoch test (default: 1000)",
    )
    epoch_group.add_argument(
        "--epoch-transition-time",
        type=float,
        default=5.0,
        help="Seconds of baseline epoch traffic before config transition (default: 5)",
    )
    epoch_group.add_argument(
        "--epoch-overlap-ms",
        type=int,
        default=500,
        help=(
            "TRex sustained initial/next generation-tag overlap in uint32 "
            "milliseconds (default: 500)"
        ),
    )

    # Output configuration
    output_group = parser.add_argument_group("Output Configuration")
    output_group.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/kinetum_validation"),
        help="Output directory for logs and captures (default: /tmp/kinetum_validation)",
    )
    output_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output with process logs",
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    # Test parameters
    test_group = parser.add_argument_group("Test Parameters")
    test_group.add_argument(
        "--max-loss",
        type=float,
        default=CONSTANTS.MAX_ACCEPTABLE_LOSS_PCT,
        help="Maximum acceptable loss percentage (default: 1.0)",
    )

    return parser.parse_args()


def _validate_installation_args(
    args: argparse.Namespace,
    spec,
    errors: list[str],
) -> None:
    """Validate exact installed roots and deployment-level requirements."""
    errors.extend(
        installed_root_errors(
            args.runtime_root,
            args.validation_root,
            spec.needs_modules,
        )
    )

    errors.extend(
        spec.scenario_errors(TestType(args.test_type.replace("-", "_")))
    )


def _validate_backend_args(
    args: argparse.Namespace,
    backend_type: BackendType,
    backend_profile,
    errors: list[str],
) -> None:
    """Validate the selected physical profile and external endpoint."""
    endpoint = TrafficEndpointConfig(
        host=args.traffic_host,
        ssh_port=args.traffic_ssh_port,
        python=args.traffic_python,
        work_dir=args.traffic_work_dir,
        trex_server=args.trex_server,
        trex_api_path=args.trex_api_path,
        trex_ports=tuple(args.trex_port),
    )
    errors.extend(
        traffic_endpoint_errors(
            endpoint,
            live=backend_type == BackendType.DPDK_PCI and not args.dry_run,
            expected_port_count=(
                len(backend_profile.ports) if backend_profile else None
            ),
        )
    )


def _validate_numeric_args(
    args: argparse.Namespace,
    backend_type: BackendType,
    stream_topology: StreamTopologyProfile,
    errors: list[str],
) -> None:
    """Validate scalar numeric ranges."""
    if args.pps <= 0:
        errors.append("--pps must be positive")
    elif args.pps > CONSTANTS.MAX_PACKET_RATE_PPS:
        errors.append("--pps exceeds the traffic rate domain")
    if args.count <= 0:
        errors.append("--count must be positive")
    elif args.count > (1 << 32) - 1:
        errors.append("--count exceeds the packet sequence domain")
    if args.packet_size < 64 or args.packet_size > 9000:
        errors.append("--packet-size must be between 64 and 9000")
    if not math.isfinite(args.max_loss) or args.max_loss < 0 or args.max_loss > 100:
        errors.append("--max-loss must be between 0 and 100")
    if args.num_flows < 1:
        errors.append("--num-flows must be at least 1")
    elif args.num_flows > 65535 - 10000 + 1:
        errors.append("--num-flows exceeds the generated UDP source-port domain")
    if (
        stream_topology == StreamTopologyProfile.RX_RSS_2
        and args.num_flows < CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS
    ):
        errors.append(
            "--stream-topology rx-rss-2 requires "
            f"--num-flows >= {CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS}"
        )
    if args.epoch_pps <= 0:
        errors.append("--epoch-pps must be positive")
    elif args.epoch_pps > CONSTANTS.MAX_PACKET_RATE_PPS:
        errors.append("--epoch-pps exceeds the traffic-generator domain")
    if not math.isfinite(args.epoch_duration) or args.epoch_duration <= 0:
        errors.append("--epoch-duration must be positive")
    if not math.isfinite(args.epoch_transition_time) or args.epoch_transition_time <= 0:
        errors.append("--epoch-transition-time must be positive")
    if args.epoch_transition_time >= args.epoch_duration:
        errors.append("--epoch-transition-time must be less than --epoch-duration")
    if args.epoch_overlap_ms <= 0:
        errors.append("--epoch-overlap-ms must be positive")
    elif args.epoch_overlap_ms > (1 << 32) - 1:
        errors.append("--epoch-overlap-ms exceeds the uint32 evidence domain")
    if (
        args.test_type in ("epoch", "full")
        and backend_type == BackendType.DPDK_PCI
        and 0 < args.epoch_overlap_ms <= (1 << 32) - 1
        and args.epoch_transition_time + (args.epoch_overlap_ms / 1000.0)
        >= args.epoch_duration
    ):
        errors.append(
            "--epoch-transition-time + --epoch-overlap-ms must be less than "
            "--epoch-duration for trex epoch-overlap runs"
        )
    if not math.isfinite(args.duration) or args.duration < 0:
        errors.append("--duration must be non-negative")
    elif args.duration > 0 and args.pps > 0 and args.pps * args.duration < 1:
        errors.append("--pps times --duration must schedule at least one packet")
    elif args.duration > 0 and args.pps > 0 and args.pps * args.duration > (1 << 32) - 1:
        errors.append("--pps times --duration exceeds the packet sequence domain")
    if (
        math.isfinite(args.epoch_duration)
        and args.epoch_pps > 0
        and args.epoch_pps * args.epoch_duration < 1
    ):
        errors.append("epoch traffic must schedule at least one packet")
    elif (
        math.isfinite(args.epoch_duration)
        and args.epoch_pps > 0
        and args.epoch_pps * args.epoch_duration > (1 << 32) - 1
    ):
        errors.append("epoch traffic exceeds the packet sequence domain")
    for option, value in (("--src-ip", args.src_ip), ("--dst-ip", args.dst_ip)):
        try:
            if str(ipaddress.IPv4Address(value)) != value:
                raise ipaddress.AddressValueError(value)
        except ipaddress.AddressValueError:
            errors.append(f"{option} must be canonical dotted-decimal IPv4")
    for option, value in (
        ("--dp-endpoint", args.dp_endpoint),
        ("--cp-endpoint", args.cp_endpoint),
    ):
        if (
            not value
            or len(value.encode("utf-8")) > 512
            or not value.isprintable()
            or any(character.isspace() for character in value)
            or value.startswith("-")
        ):
            errors.append(f"{option} must be one bounded printable endpoint")


def validate_args(args: argparse.Namespace) -> bool:
    """
    Validate command-line arguments.

    Returns
    -------
    bool
        True if arguments are valid.
    """
    errors = []
    spec = DEPLOYMENT_SPECS[DeploymentMode(args.deployment.replace("-", "_"))]
    backend_type = BackendType(args.backend.replace("-", "_"))
    try:
        backend_profile = spec.backend_profile(backend_type)
    except ValueError as e:
        errors.append(str(e))
        backend_profile = None
    stream_topology = StreamTopologyProfile(args.stream_topology.replace("-", "_"))
    storage_profile = StorageProfile(args.storage_profile.replace("-", "_"))
    if backend_profile:
        try:
            backend_profile.bindings_file_for(stream_topology, storage_profile)
        except ValueError as e:
            errors.append(str(e))

    _validate_installation_args(args, spec, errors)
    _validate_backend_args(
        args, backend_type, backend_profile, errors,
    )
    _validate_numeric_args(args, backend_type, stream_topology, errors)
    if not args.output_dir.is_absolute():
        errors.append("--output-dir must be absolute")

    # Print errors
    for error in errors:
        print(f"Error: {error}", file=sys.stderr)

    return len(errors) == 0


def build_config(args: argparse.Namespace) -> TestConfig:
    """Build test configuration from arguments."""
    output_dir = args.output_dir

    packet_config = PacketConfig(
        pps=args.pps,
        count=args.count,
        duration_s=args.duration,
        packet_size=args.packet_size,
        all_sizes=args.all_sizes,
        num_flows=args.num_flows,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
    )

    process_config = ProcessConfig(
        runtime_root=args.runtime_root.resolve(strict=True),
        validation_root=args.validation_root.resolve(strict=True),
        dp_endpoint=args.dp_endpoint,
        cp_endpoint=args.cp_endpoint,
    )

    epoch_config = EpochConfig(
        duration_s=args.epoch_duration,
        pps=args.epoch_pps,
        transition_time_s=args.epoch_transition_time,
        overlap_window_ms=args.epoch_overlap_ms,
    )

    spec = DEPLOYMENT_SPECS[DeploymentMode(args.deployment.replace("-", "_"))]
    backend_type = BackendType(args.backend.replace("-", "_"))
    backend_profile = spec.backend_profile(backend_type)
    backend_config = BackendConfig(
        backend_type=backend_type,
        ports=backend_profile.ports,
    )
    traffic_config = TrafficEndpointConfig(
        host=args.traffic_host,
        ssh_port=args.traffic_ssh_port,
        python=args.traffic_python,
        work_dir=args.traffic_work_dir,
        trex_server=args.trex_server,
        trex_api_path=args.trex_api_path,
        trex_ports=tuple(args.trex_port),
    )

    return TestConfig(
        deployment=DeploymentMode(args.deployment.replace("-", "_")),
        test_type=TestType(args.test_type.replace("-", "_")),
        packet=packet_config,
        process=process_config,
        epoch=epoch_config,
        backend=backend_config,
        traffic=traffic_config,
        stream_topology=StreamTopologyProfile(args.stream_topology.replace("-", "_")),
        storage_profile=StorageProfile(args.storage_profile.replace("-", "_")),
        output_dir=output_dir,
        max_loss_pct=args.max_loss,
        verbose=args.verbose,
        color=not args.no_color,
        dry_run=args.dry_run,
    )


async def main() -> int:
    """
    Main entry point.

    Returns
    -------
    int
        Exit code (0 for success, 1 for failure).
    """
    set_log_application("kinetum_validation")
    args = parse_args()

    if not validate_args(args):
        return 1

    try:
        config = build_config(args)
        result = await run_test_suite(config)
        return 0 if result.all_passed else 1

    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130

    except (RuntimeError, OSError, ValueError) as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    os.umask(0o027)
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
