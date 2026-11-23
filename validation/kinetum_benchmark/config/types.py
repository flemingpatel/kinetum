"""
Core types for Kinetum benchmark harness.

Separates benchmark concerns (multi-run iteration, aggregation)
from validation-run concerns (single-run orchestration).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from kinetum_validation.config.types import (
    EpochConfig,
    StreamTopologyProfile,
    StorageProfile,
    TrafficEndpointConfig,
)


@dataclass(frozen=True)
class BenchmarkScenarioConfig:
    """
    Validation scenario selected for each benchmark iteration.

    Attributes
    ----------
    deployment : str
        Registered validation deployment for each repetition.
    test_type : str
        Validation workload supported by the selected deployment and backend.
    backend : str
        Physical I/O validation profile selected for each run. This chooses
        harness resources, not the runtime provider graph.
    stream_topology : str
        Binding topology profile selected before Gluon planning.
    storage_profile : str
        Authored storage profile selected before Gluon planning.
    """
    deployment: str = "fan_in_edge_gateway"
    test_type: str = "standard"
    backend: str = "dpdk_tap"
    stream_topology: str = StreamTopologyProfile.DEFAULT.value
    storage_profile: str = StorageProfile.SHARED.value


@dataclass(frozen=True)
class BenchmarkConfig:
    """
    Configuration for a benchmark run.

    Attributes
    ----------
    variant : str
        Build or experiment label recorded in the manifest.
    inclusion_policy : str
        Aggregation inclusion policy: passed_only or all_runs.
    scenario : BenchmarkScenarioConfig
        Deployment, physical validation profile, and stream topology. The
        selected profile owns the traffic-driver identity.
    runs : int
        Number of iterations.
    output_dir : Path
        Root output directory for all runs.
    runtime_root : Path
        Finalized installed runtime root.
    validation_root : Path
        Independent private validation-kit root.
    pps : int
        Target packets per second.
    count : int
        Packet count per test.
    packet_size : int
        Packet size in bytes.
    all_sizes : bool
        Test all standard packet sizes.
    num_flows : int
        Number of traffic-generator flows per ingress port.
    epoch_duration : float
        Requested epoch traffic window in seconds, including load qualification.
    epoch_pps : int
        Aggregate PPS across ingress ports; TRex overlap runs two populations at this rate.
    epoch_initial_duration : float
        Initial-generation interval before requesting the next traffic population.
    epoch_overlap_ms : int
        Minimum TRex initial/next generation-tag overlap for transition runs.
    traffic : TrafficEndpointConfig
        External traffic endpoint settings.
    verbose : bool
        Enable runtime DEBUG logging, endpoint details, and run error tracebacks.
    """
    runtime_root: Path
    validation_root: Path
    variant: str = "default"
    inclusion_policy: str = "passed_only"  # passed_only | all_runs
    scenario: BenchmarkScenarioConfig = field(default_factory=BenchmarkScenarioConfig)
    runs: int = 30
    output_dir: Path = field(default_factory=lambda: Path("/tmp/kinetum_benchmark"))
    pps: int = 1000
    count: int = 1000
    packet_size: int = 64
    all_sizes: bool = True
    num_flows: int = 1
    epoch_duration: float = EpochConfig.duration_s
    epoch_pps: int = 1000
    epoch_initial_duration: float = 5.0
    epoch_overlap_ms: int = 500
    traffic: TrafficEndpointConfig = field(default_factory=TrafficEndpointConfig)
    verbose: bool = False


@dataclass
class RunResult:
    """
    Result of a single benchmark run.

    Attributes
    ----------
    run_id : int
        Run number (1-based).
    passed : bool
        Whether all tests passed.
    duration_s : float
        Total run duration in seconds.
    output_dir : Path
        Output directory for this run.
    error : str
        Error message if the run failed.
    """
    run_id: int
    passed: bool
    output_dir: Path
    duration_s: float = 0.0
    error: str = ""


@dataclass
class BenchmarkResult:
    """
    Aggregate result of all benchmark runs.

    Attributes
    ----------
    total_runs : int
        Number of runs attempted.
    passed_runs : int
        Number of runs that passed.
    failed_runs : int
        Number of runs that failed.
    run_results : List[RunResult]
        Per-run results.
    total_duration_s : float
        Total wall-clock time for all runs.
    """
    total_runs: int = 0
    passed_runs: int = 0
    failed_runs: int = 0
    run_results: List[RunResult] = field(default_factory=list)
    total_duration_s: float = 0.0
