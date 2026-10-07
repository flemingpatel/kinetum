"""
Benchmark runner - multi-run iteration over the validation orchestrator.

Each run is isolated in its own output directory (run_001/, run_002/, ...).
Per-run artifacts are immutable after creation. Aggregation is a separate step.
"""

from __future__ import annotations

import asyncio
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from kinetum_validation.config.types import (
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
    required_scenario_example_files,
)
from kinetum_validation.engine.runtime_release import collect_runtime_release_metadata
from kinetum_validation.engine.json_contract import parse_exact_json_object
from kinetum_validation.orchestrator import run_test_suite
from kinetum_validation.process.installation import installed_example_input_errors, installed_root_errors
from kinetum_validation.process.run_owner import ValidationRunOwner

from .contracts import validate_benchmark_manifest
from .config.types import BenchmarkConfig, BenchmarkResult, RunResult


def _system_info() -> dict:
    """Collect host observations without invoking a PATH-selected tool."""
    return {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "os": platform.system(),
    }


def write_manifest(config: BenchmarkConfig, output_dir: Path) -> None:
    """
    Write reproducibility manifest at the start of a benchmark run.

    The manifest records everything needed to reproduce the run:
    exact release identity, system observations, argv, and configuration.
    """
    release_metadata = collect_runtime_release_metadata(
        config.runtime_root,
        config.validation_root,
    )
    profile = DEPLOYMENT_SPECS[
        DeploymentMode(config.scenario.deployment)
    ].backend_profile(BackendType(config.scenario.backend))
    manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "argv": list(sys.argv),
        "variant": config.variant,
        "inclusion_policy": config.inclusion_policy,
        "scenario": {
            "deployment": config.scenario.deployment,
            "test_type": config.scenario.test_type,
            "backend": config.scenario.backend,
            "stream_topology": config.scenario.stream_topology,
            "storage_profile": config.scenario.storage_profile,
            "traffic_driver": profile.traffic_driver.value,
            "latency_source": profile.latency_source,
            "traffic_host": config.traffic.host,
            "traffic_ssh_port": config.traffic.ssh_port,
            "traffic_python": config.traffic.python,
            "traffic_work_dir": config.traffic.work_dir,
            "trex_server": config.traffic.trex_server,
            "trex_api_path": config.traffic.trex_api_path,
            "trex_ports": list(config.traffic.trex_ports),
        },
        "runs": config.runs,
        "config": {
            "pps": config.pps,
            "count": config.count,
            "packet_size": config.packet_size,
            "all_sizes": config.all_sizes,
            "num_flows": config.num_flows,
            "epoch_duration": config.epoch_duration,
            "epoch_pps": config.epoch_pps,
            "epoch_transition_time": config.epoch_transition_time,
            "epoch_overlap_ms": config.epoch_overlap_ms,
            "runtime_root": str(config.runtime_root),
            "validation_root": str(config.validation_root),
        },
        "system": _system_info(),
        "runtime_release": release_metadata,
    }
    validate_benchmark_manifest(manifest, completed=False)

    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "x", encoding="utf-8") as f:
        json.dump(manifest, f, allow_nan=False, indent=2, sort_keys=True)
        f.write("\n")


def _build_test_config(config: BenchmarkConfig, run_dir: Path) -> TestConfig:
    """Build one validation TestConfig for a benchmark iteration."""
    scenario = config.scenario
    spec = DEPLOYMENT_SPECS[DeploymentMode(scenario.deployment)]
    backend_type = BackendType(scenario.backend)
    backend_profile = spec.backend_profile(backend_type)
    return TestConfig(
        deployment=DeploymentMode(scenario.deployment),
        test_type=TestType(scenario.test_type),
        packet=PacketConfig(
            pps=config.pps,
            count=config.count,
            packet_size=config.packet_size,
            all_sizes=config.all_sizes,
            num_flows=config.num_flows,
        ),
        process=ProcessConfig(
            runtime_root=config.runtime_root,
            validation_root=config.validation_root,
        ),
        epoch=EpochConfig(
            duration_s=config.epoch_duration,
            pps=config.epoch_pps,
            transition_time_s=config.epoch_transition_time,
            overlap_window_ms=config.epoch_overlap_ms,
        ),
        backend=BackendConfig(
            backend_type=backend_type,
            ports=backend_profile.ports,
        ),
        traffic=config.traffic,
        stream_topology=StreamTopologyProfile(scenario.stream_topology),
        storage_profile=StorageProfile(scenario.storage_profile),
        output_dir=run_dir,
        verbose=config.verbose,
    )


def admit_benchmark_inputs(config: BenchmarkConfig) -> None:
    """Admit scenario and installed paths before run-root ownership."""
    try:
        deployment = DEPLOYMENT_SPECS[
            DeploymentMode(config.scenario.deployment)
        ]
        test_type = TestType(config.scenario.test_type)
        backend_profile = deployment.backend_profile(
            BackendType(config.scenario.backend)
        )
        stream_topology = StreamTopologyProfile(
            config.scenario.stream_topology
        )
        storage_profile = StorageProfile(config.scenario.storage_profile)
        required_files = required_scenario_example_files(
            deployment,
            backend_profile,
            stream_topology,
            storage_profile,
            test_type,
        )
    except (KeyError, ValueError) as exc:
        raise RuntimeError("benchmark scenario identity is undeclared") from exc
    scenario_errors = deployment.scenario_errors(test_type)
    if scenario_errors:
        raise RuntimeError(
            "benchmark scenario admission rejected: "
            + "; ".join(scenario_errors)
        )
    installation_errors = installed_root_errors(
        config.runtime_root,
        config.validation_root,
        deployment.needs_modules,
    )
    if installation_errors:
        raise RuntimeError(
            "installed benchmark layout rejected: "
            + "; ".join(installation_errors)
        )
    example_errors = installed_example_input_errors(
        config.validation_root,
        deployment.example_dir,
        required_files,
    )
    if example_errors:
        raise RuntimeError(
            "installed benchmark scenario inputs rejected: "
            + "; ".join(example_errors)
        )


async def run_benchmark(
    config: BenchmarkConfig,
    run_owner: ValidationRunOwner | None = None,
) -> BenchmarkResult:
    """
    Execute N benchmark runs, each in an isolated output directory.

    Parameters
    ----------
    config : BenchmarkConfig
        Benchmark configuration.
    run_owner : ValidationRunOwner, optional
        Existing batch owner retained by the CLI through derived-artifact
        publication. Direct callers omit it and this function owns the lock.

    Returns
    -------
    BenchmarkResult
        Aggregate result across all runs.
    """
    admit_benchmark_inputs(config)

    if run_owner is None:
        with ValidationRunOwner.acquire(config.output_dir) as acquired_owner:
            return await _run_benchmark_owned(config, acquired_owner)
    if not run_owner.owns_directory(config.output_dir):
        raise RuntimeError("benchmark output directory lacks the live run owner")
    return await _run_benchmark_owned(config, run_owner)


async def _run_benchmark_owned(
    config: BenchmarkConfig,
    run_owner: ValidationRunOwner,
) -> BenchmarkResult:
    """Execute all iterations beneath one live lock and fresh batch root."""

    output_dir = config.output_dir

    # Write manifest before any runs
    write_manifest(config, output_dir)

    result = BenchmarkResult(total_runs=config.runs)
    overall_start = time.monotonic()

    for i in range(1, config.runs + 1):
        run_dir = run_owner.create_artifact_directory(f"run_{i:03d}")

        print(
            f"\n{'='*60}\n"
            f"  BENCHMARK RUN {i}/{config.runs}\n"
            f"  Output: {run_dir}\n"
            f"{'='*60}",
            file=sys.stderr,
        )

        run_start = time.monotonic()
        run_result = RunResult(run_id=i, passed=False, output_dir=run_dir)

        try:
            test_config = _build_test_config(config, run_dir)
            suite_result = await run_test_suite(test_config, run_owner)
            run_result.passed = suite_result.all_passed
            run_result.duration_s = time.monotonic() - run_start

            if not suite_result.all_passed:
                run_result.error = f"{suite_result.failed_tests} test(s) failed"

        except KeyboardInterrupt:
            run_result.duration_s = time.monotonic() - run_start
            run_result.error = "interrupted by user"
            result.run_results.append(run_result)
            result.failed_runs += 1
            result.interrupted = True
            print(
                f"\n  Run {i}: INTERRUPTED ({run_result.duration_s:.1f}s)",
                file=sys.stderr,
            )
            # Break the loop; the validation orchestrator's finally block
            # already cleaned up Photon, traffic resources, and capture.
            break

        except (RuntimeError, OSError, ValueError, asyncio.TimeoutError) as e:
            run_result.duration_s = time.monotonic() - run_start
            run_result.error = str(e)
            print(f"  Run {i} ERROR: {e}", file=sys.stderr)

        result.run_results.append(run_result)
        if run_result.passed:
            result.passed_runs += 1
        else:
            result.failed_runs += 1

        status = "PASS" if run_result.passed else "FAIL"
        print(
            f"  Run {i}: {status} ({run_result.duration_s:.1f}s)"
            f"{'' if run_result.passed else ' - ' + run_result.error}",
            file=sys.stderr,
        )

    result.total_runs = len(result.run_results)
    result.total_duration_s = time.monotonic() - overall_start

    # Update manifest with run results
    _update_manifest_with_results(output_dir, result)

    print(
        f"\n{'='*60}\n"
        f"  BENCHMARK COMPLETE: {result.passed_runs}/{result.total_runs} passed"
        f" ({result.total_duration_s:.1f}s)\n"
        f"{'='*60}",
        file=sys.stderr,
    )

    return result


def _update_manifest_with_results(output_dir: Path, result: BenchmarkResult) -> None:
    """Update manifest.json with run results after all runs complete."""
    manifest_path = output_dir / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise RuntimeError("benchmark manifest disappeared before completion")

    with open(manifest_path, encoding="utf-8") as f:
        manifest = parse_exact_json_object(f.read(), "benchmark manifest")
    validate_benchmark_manifest(manifest, completed=False)

    manifest["completed"] = datetime.now(timezone.utc).isoformat()
    manifest["total_duration_s"] = round(result.total_duration_s, 2)
    manifest["results"] = {
        "total_runs": result.total_runs,
        "passed_runs": result.passed_runs,
        "failed_runs": result.failed_runs,
        "runs": [
            {
                "run_id": r.run_id,
                "passed": r.passed,
                "duration_s": round(r.duration_s, 2),
                "error": r.error,
            }
            for r in result.run_results
        ],
    }
    validate_benchmark_manifest(manifest, completed=True)

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, allow_nan=False, indent=2, sort_keys=True)
        f.write("\n")
