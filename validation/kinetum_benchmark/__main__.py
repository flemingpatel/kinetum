#!/usr/bin/env python3
"""
Kinetum Benchmark Harness - CLI Entry Point.

Multi-run benchmark harness for the physical-I/O validation framework.

Subcommands:
    run         Execute N benchmark runs with isolated per-run output
    aggregate   Merge per-run artifacts and compute distributions
    export-csv  Convert benchmark summary to CSV for plotting
    report      Generate raw CSV, Markdown, and deterministic SVG projections

Usage:
    # Run 30 iterations of the fixed-epoch packet test
    sudo python3 -m kinetum_benchmark run --runtime-root /opt/kinetum \\
        --deployment fan-in-edge-gateway \\
        --test-type standard \\
        --runs 30

    # Aggregate results (auto-runs after 'run', or standalone)
    python3 -m kinetum_benchmark aggregate \\
        --input-dir /tmp/kinetum_benchmark

    # Export CSV for plotting
    python3 -m kinetum_benchmark export-csv \\
        --input-dir /tmp/kinetum_benchmark

    # Generate the complete derived report
    python3 -m kinetum_benchmark report \\
        --input-dir /tmp/kinetum_benchmark
"""

from __future__ import annotations

import argparse
import asyncio
import math
import os
import sys
from pathlib import Path

from kinetum_validation import VALIDATION_ROOT
from kinetum_validation.engine.json_contract import parse_exact_json_object
from kinetum_validation.config.logger import set_log_application
from kinetum_validation.config.types import (
    CONSTANTS,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    StreamTopologyProfile,
    StorageProfile,
    TestType,
    TrafficEndpointConfig,
    traffic_endpoint_errors,
)
from kinetum_validation.process.installation import installed_root_errors
from kinetum_validation.process.run_owner import ValidationRunOwner

from .contracts import validate_benchmark_summary_identity
from .aggregator import aggregate
from .config.types import BenchmarkConfig, BenchmarkScenarioConfig
from .exporter import export_csv
from .plotter import generate_figures, require_figure_backend
from .raw_export import export_raw
from .runner import admit_benchmark_inputs, run_benchmark
from .tables import generate_tables


_CLI_INCLUSION_POLICIES = {
    "passed-only": "passed_only",
    "all-runs": "all_runs",
}


def _inclusion_policy_from_cli(value: object) -> str:
    """
    Translate one exact kebab-case CLI value to the artifact spelling.

    Parameters
    ----------
    value : object
        Candidate command-line inclusion policy.

    Returns
    -------
    str
        Canonical underscore-delimited value stored in benchmark artifacts.

    Raises
    ------
    ValueError
        If the command-line spelling is undeclared.
    """
    if not isinstance(value, str) or value not in _CLI_INCLUSION_POLICIES:
        raise ValueError("--inclusion-policy is undeclared")
    return _CLI_INCLUSION_POLICIES[value]


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the 'run' subcommand."""
    # Benchmark-specific
    parser.add_argument(
        "--runs", "-n",
        type=int,
        default=30,
        help="Number of benchmark iterations (default: 30)",
    )
    parser.add_argument(
        "--variant",
        type=str,
        default="default",
        help="Build variant label for manifest (default: 'default')",
    )
    parser.add_argument(
        "--inclusion-policy",
        type=str,
        choices=tuple(_CLI_INCLUSION_POLICIES),
        default="passed-only",
        help="Run inclusion policy for aggregation (default: passed-only)",
    )

    # Scenario selection (pass-through to the validation orchestrator)
    parser.add_argument(
        "--deployment", "-d",
        type=str,
        choices=[mode.value.replace("_", "-") for mode in DeploymentMode],
        default=DeploymentMode.FAN_IN_EDGE_GATEWAY.value.replace("_", "-"),
        help="Deployment mode (default: fan-in-edge-gateway)",
    )
    parser.add_argument(
        "--test-type", "-t",
        type=str,
        choices=[test_type.value.replace("_", "-") for test_type in TestType],
        default=TestType.STANDARD.value,
        help="Test type (default: standard)",
    )
    parser.add_argument(
        "--backend",
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
    parser.add_argument("--traffic-host", type=str, default="",
                        help="SSH host or alias for an external traffic endpoint")
    parser.add_argument("--traffic-ssh-port", type=int, default=0,
                        help="SSH port for --traffic-host (0 = SSH config/default)")
    parser.add_argument("--traffic-python", type=str, default="/usr/bin/python3",
                        help="Exact Python executable on the traffic endpoint")
    parser.add_argument("--traffic-work-dir", type=str, default="/tmp/kinetum_traffic",
                        help="Exact existing work directory on the traffic endpoint")
    parser.add_argument("--trex-server", type=str, default="127.0.0.1",
                        help="TRex stateless server address from the traffic endpoint")
    parser.add_argument("--trex-api-path", type=str, default="",
                        help="Optional path prepended before importing TRex APIs")
    parser.add_argument("--trex-port", type=int, action="append", default=[],
                        help="Traffic-generator port ID override; repeat in deployment port order")

    # Packet configuration
    parser.add_argument("--pps", type=int, default=1000,
                        help="Packets per second (default: 1000)")
    parser.add_argument("--count", type=int, default=1000,
                        help="Packet count (default: 1000)")
    parser.add_argument("--packet-size", type=int, default=64,
                        help="Packet size in bytes (default: 64)")
    parser.add_argument("--no-all-sizes", action="store_true",
                        help="Test single packet size only (default: all sizes 64-1518)")
    parser.add_argument(
        "--num-flows",
        type=int,
        default=1,
        help=(
            "Number of traffic-generator flows per ingress port; "
            "rx-rss-2 requires at least "
            f"{CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS}, and transition evidence "
            "must fit the bounded JSON result"
        ),
    )

    # Process configuration
    parser.add_argument("--runtime-root", type=Path, required=True,
                        help="Explicit finalized installed runtime root")
    parser.add_argument(
        "--validation-root",
        type=Path,
        default=VALIDATION_ROOT,
        help="Private kit root (default: root containing the running kit's scripts/)",
    )
    # Epoch configuration
    parser.add_argument("--epoch-duration", type=float, default=15.0,
                        help="Epoch test duration (default: 15s)")
    parser.add_argument("--epoch-pps", type=int, default=1000,
                        help="Epoch test PPS (default: 1000)")
    parser.add_argument("--epoch-transition-time", type=float, default=5.0,
                        help="Seconds of baseline epoch traffic before transition")
    parser.add_argument(
        "--epoch-overlap-ms",
        type=int,
        default=500,
        help="TRex sustained initial/next generation-tag overlap in uint32 ms",
    )

    # Output
    parser.add_argument("--output-dir", type=Path,
                        default=Path("/tmp/kinetum_benchmark"),
                        help="Output directory (default: /tmp/kinetum_benchmark)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")


def _add_aggregate_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the 'aggregate' subcommand."""
    parser.add_argument(
        "--input-dir", "-i",
        type=Path,
        default=Path("/tmp/kinetum_benchmark"),
        help="Benchmark output directory to aggregate (default: /tmp/kinetum_benchmark)",
    )
    parser.add_argument(
        "--inclusion-policy",
        type=str,
        choices=tuple(_CLI_INCLUSION_POLICIES),
        default="passed-only",
        help="Run inclusion policy for aggregation (default: passed-only)",
    )


def _add_export_csv_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the 'export-csv' subcommand."""
    parser.add_argument(
        "--input-dir", "-i",
        type=Path,
        default=Path("/tmp/kinetum_benchmark"),
        help="Benchmark output directory (default: /tmp/kinetum_benchmark)",
    )


def _add_report_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the 'report' subcommand."""
    parser.add_argument(
        "--input-dir", "-i",
        type=Path,
        default=Path("/tmp/kinetum_benchmark"),
        help="Benchmark output directory (default: /tmp/kinetum_benchmark)",
    )
    parser.add_argument(
        "--inclusion-policy",
        type=str,
        choices=tuple(_CLI_INCLUSION_POLICIES),
        default="passed-only",
        help="Run inclusion policy for raw CSV export (default: passed-only)",
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments with subcommands."""
    parser = argparse.ArgumentParser(
        prog="kinetum_benchmark",
        description="Kinetum Benchmark Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
        allow_abbrev=False,
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcommand")
    subparsers.required = True

    # run
    run_parser = subparsers.add_parser(
        "run", help="Execute N benchmark runs", allow_abbrev=False,
    )
    _add_run_args(run_parser)

    # aggregate
    agg_parser = subparsers.add_parser(
        "aggregate",
        help="Merge per-run artifacts and compute distributions",
        allow_abbrev=False,
    )
    _add_aggregate_args(agg_parser)

    # export-csv
    csv_parser = subparsers.add_parser(
        "export-csv", help="Convert benchmark summary to CSV", allow_abbrev=False,
    )
    _add_export_csv_args(csv_parser)

    # report
    report_parser = subparsers.add_parser(
        "report",
        help="Generate raw CSVs, tables, and figures",
        allow_abbrev=False,
    )
    _add_report_args(report_parser)

    return parser.parse_args()


def validate_run_args(
    args: argparse.Namespace,
) -> bool:
    """
    Validate arguments for the benchmark run subcommand.

    Returns
    -------
    bool
        True when all run arguments are valid.
    """
    errors = []
    try:
        _inclusion_policy_from_cli(args.inclusion_policy)
    except ValueError as exc:
        errors.append(str(exc))
    if (
        not args.variant
        or len(args.variant.encode("utf-8")) > 128
        or not args.variant.isprintable()
    ):
        errors.append("--variant must be 1..128 printable UTF-8 bytes")
    if args.runs <= 0 or args.runs > 999:
        errors.append("--runs must be in the range 1..999")
    if args.pps <= 0:
        errors.append("--pps must be positive")
    elif args.pps > CONSTANTS.MAX_PACKET_RATE_PPS:
        errors.append("--pps exceeds the traffic-generator domain")
    if args.count <= 0:
        errors.append("--count must be positive")
    elif args.count > (1 << 32) - 1:
        errors.append("--count exceeds the packet sequence domain")
    if args.packet_size < 64 or args.packet_size > 9000:
        errors.append("--packet-size must be between 64 and 9000")
    if args.num_flows < 1:
        errors.append("--num-flows must be at least 1")
    elif args.num_flows > 65535 - 10000 + 1:
        errors.append("--num-flows exceeds the generated UDP source-port domain")
    if not math.isfinite(args.epoch_duration) or args.epoch_duration <= 0:
        errors.append("--epoch-duration must be positive")
    if args.epoch_pps <= 0:
        errors.append("--epoch-pps must be positive")
    elif args.epoch_pps > CONSTANTS.MAX_PACKET_RATE_PPS:
        errors.append("--epoch-pps exceeds the traffic-generator domain")
    if not math.isfinite(args.epoch_transition_time) or args.epoch_transition_time <= 0:
        errors.append("--epoch-transition-time must be positive")
    if args.epoch_transition_time >= args.epoch_duration:
        errors.append("--epoch-transition-time must be less than --epoch-duration")
    if args.epoch_overlap_ms <= 0:
        errors.append("--epoch-overlap-ms must be positive")
    elif args.epoch_overlap_ms > (1 << 32) - 1:
        errors.append("--epoch-overlap-ms exceeds the uint32 evidence domain")
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
    selected_profile = None
    try:
        stream_topology = StreamTopologyProfile(args.stream_topology.replace("-", "_"))
        storage_profile = StorageProfile(args.storage_profile.replace("-", "_"))
        deployment = DEPLOYMENT_SPECS[
            DeploymentMode(args.deployment.replace("-", "_"))
        ]
        selected_profile = deployment.backend_profile(
            BackendType(args.backend.replace("-", "_"))
        )
        selected_profile.bindings_file_for(stream_topology, storage_profile)
        errors.extend(
            deployment.scenario_errors(
                TestType(args.test_type.replace("-", "_"))
            )
        )
        if (
            stream_topology == StreamTopologyProfile.RX_RSS_2
            and args.num_flows < CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS
        ):
            errors.append(
                "--stream-topology rx-rss-2 requires "
                f"--num-flows >= {CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS}"
            )
    except ValueError as exc:
        errors.append(str(exc))
    if args.backend == "dpdk-pci":
        if (
            args.test_type in ("epoch", "full")
            and 0 < args.epoch_overlap_ms <= (1 << 32) - 1
            and args.epoch_transition_time + (args.epoch_overlap_ms / 1000.0)
            >= args.epoch_duration
        ):
            errors.append(
                "--epoch-transition-time + --epoch-overlap-ms must be less "
                "than --epoch-duration for trex epoch-overlap runs"
            )
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
            live=args.backend == "dpdk-pci",
            expected_port_count=(
                len(selected_profile.ports) if selected_profile else None
            ),
        )
    )
    if not args.output_dir.is_absolute():
        errors.append("--output-dir must be absolute")

    for error in errors:
        print(f"Error: {error}", file=sys.stderr)

    return not errors


async def cmd_run(args: argparse.Namespace) -> int:
    """Execute the 'run' subcommand."""
    if not validate_run_args(args):
        return 2
    spec = DEPLOYMENT_SPECS[DeploymentMode(args.deployment.replace("-", "_"))]
    installation_errors = installed_root_errors(
        args.runtime_root,
        args.validation_root,
        spec.needs_modules,
    )
    for error in installation_errors:
        print(f"Error: {error}", file=sys.stderr)
    if installation_errors:
        return 2

    config = BenchmarkConfig(
        variant=args.variant,
        inclusion_policy=_inclusion_policy_from_cli(args.inclusion_policy),
        scenario=BenchmarkScenarioConfig(
            deployment=args.deployment.replace("-", "_"),
            test_type=args.test_type.replace("-", "_"),
            backend=args.backend.replace("-", "_"),
            stream_topology=args.stream_topology.replace("-", "_"),
            storage_profile=args.storage_profile.replace("-", "_"),
        ),
        runs=args.runs,
        output_dir=args.output_dir,
        runtime_root=args.runtime_root.resolve(strict=True),
        validation_root=args.validation_root.resolve(strict=True),
        pps=args.pps,
        count=args.count,
        packet_size=args.packet_size,
        all_sizes=not args.no_all_sizes,
        num_flows=args.num_flows,
        epoch_duration=args.epoch_duration,
        epoch_pps=args.epoch_pps,
        epoch_transition_time=args.epoch_transition_time,
        epoch_overlap_ms=args.epoch_overlap_ms,
        traffic=TrafficEndpointConfig(
            host=args.traffic_host,
            ssh_port=args.traffic_ssh_port,
            python=args.traffic_python,
            work_dir=args.traffic_work_dir,
            trex_server=args.trex_server,
            trex_api_path=args.trex_api_path,
            trex_ports=tuple(args.trex_port),
        ),
        verbose=args.verbose,
    )

    try:
        admit_benchmark_inputs(config)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    with ValidationRunOwner.acquire(config.output_dir) as run_owner:
        result = await run_benchmark(config, run_owner)

        # Derived artifacts consume the same immutable run set before the
        # physical-run lock is released to another process.
        print("\nAggregating results...", file=sys.stderr)
        aggregate(config.output_dir, inclusion_policy=config.inclusion_policy)
        print("\nExporting CSV...", file=sys.stderr)
        export_csv(config.output_dir)

    if result.interrupted:
        return 130
    return 0 if result.failed_runs == 0 else 1


def cmd_aggregate(args: argparse.Namespace) -> int:
    """Execute the 'aggregate' subcommand."""
    _require_exact_input_directory(args.input_dir)

    aggregate(
        args.input_dir,
        inclusion_policy=_inclusion_policy_from_cli(args.inclusion_policy),
    )
    return 0


def cmd_export_csv(args: argparse.Namespace) -> int:
    """Execute the 'export-csv' subcommand."""
    _require_exact_input_directory(args.input_dir)

    export_csv(args.input_dir)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Execute the 'report' subcommand - raw CSVs, tables, and figures."""
    _require_exact_input_directory(args.input_dir)

    artifacts_dir = args.input_dir / "artifacts"
    print(f"Generating report into {artifacts_dir}/", file=sys.stderr)

    summary_path = args.input_dir / "benchmark_summary.json"
    if not summary_path.is_file() or summary_path.is_symlink():
        raise ValueError("benchmark summary is unavailable")
    summary = parse_exact_json_object(
        summary_path.read_text(encoding="utf-8"), "benchmark summary"
    )
    manifest_path = args.input_dir / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("benchmark manifest is unavailable")
    manifest = parse_exact_json_object(
        manifest_path.read_text(encoding="utf-8"), "benchmark manifest"
    )
    validate_benchmark_summary_identity(summary, manifest)
    inclusion_policy = _inclusion_policy_from_cli(args.inclusion_policy)
    if summary["inclusion_policy"] != inclusion_policy:
        raise ValueError(
            "report inclusion policy disagrees with the immutable aggregate"
        )
    require_figure_backend()

    print("\nRaw CSVs:", file=sys.stderr)
    export_raw(
        args.input_dir,
        artifacts_dir,
        inclusion_policy=inclusion_policy,
    )

    print("\nTables:", file=sys.stderr)
    generate_tables(args.input_dir, artifacts_dir)

    print("\nFigures:", file=sys.stderr)
    generate_figures(args.input_dir, artifacts_dir)

    print("\nReport complete.", file=sys.stderr)
    return 0


def _require_exact_input_directory(path: Path) -> None:
    """Require one absolute symlink-free benchmark input directory."""
    try:
        exact = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"benchmark directory is unavailable: {path}") from exc
    if not path.is_absolute() or exact != path or not path.is_dir() or path.is_symlink():
        raise ValueError(f"benchmark directory is indirect: {path}")


def main() -> int:
    """Main entry point."""
    set_log_application("kinetum_benchmark")
    args = parse_args()

    try:
        if args.command == "run":
            return asyncio.run(cmd_run(args))
        if args.command == "aggregate":
            return cmd_aggregate(args)
        if args.command == "export-csv":
            return cmd_export_csv(args)
        if args.command == "report":
            return cmd_report(args)
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130

    except (RuntimeError, OSError, ValueError) as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.umask(0o027)
    sys.exit(main())
