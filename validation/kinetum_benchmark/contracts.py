"""Validate benchmark manifests, run records, and aggregated evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable

from kinetum_validation.config.types import StreamTopologyProfile, StorageProfile, TrafficEndpointConfig
from kinetum_validation.engine.json_contract import (
    EXPECTED_SCENARIO_METRICS_BY_TEST,
    EXPECTED_TRANSITION_TYPES_BY_TEST,
    JsonContractError,
    PROTOCOL_FAULT_CODES,
    _BACKENDS,
    _DEPLOYMENTS,
    _TEST_TYPES,
    _TRAFFIC_DRIVERS,
    _UINT32_MAX,
    _UINT64_MAX,
    _require_disjoint_release_roots,
    require_absolute_path,
    require_array,
    require_bool,
    require_exact_keys,
    require_int,
    require_key_contract,
    require_number,
    require_object,
    require_optional_string,
    require_string,
    require_timestamp,
    require_trex_identity,
    require_validation_profile,
    validate_run_metadata,
    validate_runtime_release_record,
    validate_test_suite_result,
)


def _validate_benchmark_scenario(value: object) -> Dict[str, Any]:
    """Validate and return one benchmark scenario identity."""
    scenario = require_object(value, "benchmark scenario")
    require_exact_keys(
        scenario,
        {
            "deployment", "test_type", "backend", "stream_topology", "storage_profile",
            "traffic_driver", "traffic_host", "traffic_ssh_port",
            "traffic_python", "traffic_work_dir", "trex_server",
            "trex_api_path", "trex_ports", "latency_source",
        },
        "benchmark scenario",
    )
    for name in (
        "deployment", "test_type", "backend", "stream_topology", "storage_profile",
        "traffic_driver", "traffic_host", "traffic_python", "traffic_work_dir",
        "trex_server", "trex_api_path",
    ):
        require_string(
            scenario[name], f"benchmark scenario {name}", allow_empty=True
        )
    scenario_exact = all((
        scenario["deployment"] in _DEPLOYMENTS,
        scenario["test_type"] in _TEST_TYPES,
        scenario["backend"] in _BACKENDS,
        scenario["stream_topology"] in {"default", "rx_rss_2"},
        scenario["storage_profile"] in {profile.value for profile in StorageProfile},
        scenario["traffic_driver"] in _TRAFFIC_DRIVERS,
        (scenario["backend"] == "dpdk_tap")
        == (scenario["traffic_driver"] == "native_tap"),
        scenario["deployment"] != "passthrough"
        or scenario["test_type"] == "standard",
    ))
    if not scenario_exact:
        raise JsonContractError("benchmark scenario identity is undeclared")
    profile = _benchmark_profile(
        scenario["deployment"],
        scenario["backend"],
        scenario["stream_topology"],
        scenario["storage_profile"],
    )
    if profile.traffic_driver.value != scenario["traffic_driver"]:
        raise JsonContractError("benchmark traffic driver disagrees with its profile")
    latency_source = require_optional_string(
        scenario["latency_source"], "benchmark latency source"
    )
    if latency_source != profile.latency_source:
        raise JsonContractError("benchmark latency source disagrees with its profile")
    if scenario["backend"] == "dpdk_pci" and not scenario["traffic_host"]:
        raise JsonContractError("benchmark TRex endpoint host is missing")
    if scenario["traffic_host"] and (
        scenario["traffic_host"].startswith("-")
        or not scenario["traffic_host"].isprintable()
        or any(character.isspace() for character in scenario["traffic_host"])
        or len(scenario["traffic_host"].encode("utf-8")) > 255
    ):
        raise JsonContractError("benchmark traffic host is malformed")
    if scenario["backend"] == "dpdk_pci" and not scenario["trex_server"]:
        raise JsonContractError("benchmark TRex server is missing")
    if scenario["backend"] == "dpdk_pci" and (
        scenario["trex_server"].startswith("-")
        or not scenario["trex_server"].isprintable()
        or any(character.isspace() for character in scenario["trex_server"])
        or len(scenario["trex_server"].encode("utf-8")) > 255
    ):
        raise JsonContractError("benchmark TRex server is malformed")
    require_int(
        scenario["traffic_ssh_port"], "benchmark SSH port", minimum=0,
        maximum=65535,
    )
    require_absolute_path(
        scenario["traffic_python"], "benchmark traffic Python"
    )
    require_absolute_path(
        scenario["traffic_work_dir"], "benchmark traffic work directory"
    )
    if scenario["trex_api_path"]:
        require_absolute_path(
            scenario["trex_api_path"], "benchmark TRex API path"
        )
    if any(
        len(scenario[name].encode("utf-8")) > 4096
        or not scenario[name].isprintable()
        for name in ("traffic_python", "traffic_work_dir", "trex_api_path")
        if scenario[name]
    ):
        raise JsonContractError("benchmark remote path is malformed")
    ports = [
        require_int(item, "benchmark TRex port", minimum=0, maximum=_UINT32_MAX)
        for item in require_array(scenario["trex_ports"], "benchmark TRex ports")
    ]
    if len(ports) != len(set(ports)):
        raise JsonContractError("benchmark TRex ports are duplicated")
    if ports and len(ports) != len(profile.ports):
        raise JsonContractError("benchmark TRex port override count is inexact")
    if scenario["backend"] == "dpdk_tap":
        neutral = TrafficEndpointConfig()
        if any((
            scenario["traffic_host"] != neutral.host,
            scenario["traffic_ssh_port"] != neutral.ssh_port,
            scenario["traffic_python"] != neutral.python,
            scenario["traffic_work_dir"] != neutral.work_dir,
            scenario["trex_server"] != neutral.trex_server,
            scenario["trex_api_path"] != neutral.trex_api_path,
            tuple(ports) != neutral.trex_ports,
        )):
            raise JsonContractError("benchmark TAP scenario retains TRex residue")
    return scenario


def _benchmark_profile(
    deployment: str,
    backend: str,
    stream_topology: str,
    storage_profile: str,
) -> Any:
    """Resolve one benchmark profile through the validation registry authority."""
    profile = require_validation_profile(deployment, backend)
    try:
        profile.bindings_file_for(StreamTopologyProfile(stream_topology), StorageProfile(storage_profile))
    except ValueError as exc:
        raise JsonContractError("benchmark scenario has no exact profile") from exc
    return profile


def validate_benchmark_transition_multiset(
    observed: Iterable[object],
    test_type: str,
    *,
    complete: bool,
) -> None:
    """Validate one run's transition-type multiset against its scenario."""
    if test_type not in EXPECTED_TRANSITION_TYPES_BY_TEST:
        raise JsonContractError("benchmark transition scenario is undeclared")
    observed_types = [
        require_string(item, "benchmark transition type") for item in observed
    ]
    expected_types = EXPECTED_TRANSITION_TYPES_BY_TEST[test_type]
    if (
        len(observed_types) != len(set(observed_types))
        or not set(observed_types).issubset(expected_types)
        or (complete and sorted(observed_types) != sorted(expected_types))
    ):
        qualification = "complete" if complete else "partial"
        raise JsonContractError(
            f"benchmark {qualification} transition evidence disagrees "
            "with its scenario"
        )


def validate_benchmark_manifest(value: Dict[str, Any], completed: bool) -> None:
    """Validate one initial or terminal benchmark reproducibility manifest."""
    initial_keys = {
        "timestamp", "argv", "variant", "inclusion_policy", "scenario",
        "runs", "config", "system", "runtime_release",
    }
    terminal_keys = initial_keys | {"completed", "total_duration_s", "results"}
    require_exact_keys(
        value, terminal_keys if completed else initial_keys,
        "benchmark manifest",
    )
    require_timestamp(value["timestamp"], "benchmark timestamp")
    variant = require_string(value["variant"], "benchmark variant")
    if len(variant.encode("utf-8")) > 128 or not variant.isprintable():
        raise JsonContractError("benchmark variant is malformed")
    if require_string(
        value["inclusion_policy"], "benchmark inclusion policy"
    ) not in {"passed_only", "all_runs"}:
        raise JsonContractError("benchmark inclusion policy is undeclared")
    arguments = require_array(value["argv"], "benchmark argv")
    if not arguments:
        raise JsonContractError("benchmark argv is empty")
    for argument in arguments:
        require_string(argument, "benchmark argv value", allow_empty=True)
    runs = require_int(value["runs"], "benchmark run count", minimum=1, maximum=999)

    scenario = _validate_benchmark_scenario(value["scenario"])

    config = require_object(value["config"], "benchmark configuration")
    require_exact_keys(
        config,
        {
            "pps", "count", "packet_size", "all_sizes", "num_flows",
            "epoch_duration", "epoch_pps", "epoch_transition_time",
            "epoch_overlap_ms", "runtime_root", "validation_root",
        },
        "benchmark configuration",
    )
    require_int(config["pps"], "benchmark PPS", minimum=1, maximum=1_000_000_000)
    require_int(config["count"], "benchmark count", minimum=1, maximum=_UINT32_MAX)
    require_int(config["packet_size"], "benchmark packet size", minimum=64, maximum=9000)
    require_int(
        config["num_flows"], "benchmark flow count", minimum=1,
        maximum=65535 - 10000 + 1,
    )
    require_int(
        config["epoch_pps"], "benchmark epoch PPS", minimum=1,
        maximum=1_000_000_000,
    )
    require_int(
        config["epoch_overlap_ms"], "benchmark epoch overlap", minimum=1,
        maximum=_UINT32_MAX,
    )
    require_bool(config["all_sizes"], "benchmark all-sizes selection")
    for name in ("epoch_duration", "epoch_transition_time"):
        require_number(config[name], f"benchmark {name}", minimum=0.0)
    overlap_fits = (
        scenario["backend"] != "dpdk_pci"
        or scenario["test_type"] not in {"epoch", "full"}
        or config["epoch_transition_time"]
        + config["epoch_overlap_ms"] / 1000.0
        < config["epoch_duration"]
    )
    timing_exact = all((
        config["epoch_duration"] > 0.0,
        config["epoch_transition_time"] > 0.0,
        config["epoch_transition_time"] < config["epoch_duration"],
        config["epoch_pps"] * config["epoch_duration"] >= 1.0,
        config["epoch_pps"] * config["epoch_duration"] <= _UINT32_MAX,
        overlap_fits,
    ))
    if not timing_exact:
        raise JsonContractError("benchmark epoch timing is contradictory")
    runtime_root = require_absolute_path(
        config["runtime_root"], "benchmark runtime root"
    )
    validation_root = require_absolute_path(
        config["validation_root"], "benchmark validation root"
    )
    _require_disjoint_release_roots(runtime_root, validation_root)

    system = require_object(value["system"], "benchmark system")
    require_exact_keys(system, {"hostname", "kernel", "arch", "os"}, "benchmark system")
    for name in ("hostname", "kernel", "arch", "os"):
        observed = require_string(system[name], f"benchmark system {name}")
        if not observed.isprintable() or len(observed.encode("utf-8")) > 256:
            raise JsonContractError(f"benchmark system {name} is malformed")
    validate_runtime_release_record(value["runtime_release"])
    release = require_object(value["runtime_release"], "runtime release metadata")
    if release["source"] != f"{runtime_root}/bin/kinetum-info":
        raise JsonContractError("benchmark release source is foreign")

    if not completed:
        return
    started = datetime.fromisoformat(value["timestamp"])
    completed_at = datetime.fromisoformat(
        require_timestamp(value["completed"], "benchmark completion timestamp")
    )
    if completed_at < started:
        raise JsonContractError("benchmark completion precedes its start")
    require_number(
        value["total_duration_s"], "benchmark total duration", minimum=0.0
    )
    results = require_object(value["results"], "benchmark results")
    require_exact_keys(
        results, {"total_runs", "passed_runs", "failed_runs", "runs"},
        "benchmark results",
    )
    total = require_int(results["total_runs"], "completed run count", minimum=1, maximum=runs)
    passed = require_int(results["passed_runs"], "passed run count", minimum=0, maximum=total)
    failed = require_int(results["failed_runs"], "failed run count", minimum=0, maximum=total)
    rows = require_array(results["runs"], "benchmark run results")
    if passed + failed != total or len(rows) != total:
        raise JsonContractError("benchmark result totals are contradictory")
    observed_passed = 0
    for index, item in enumerate(rows, start=1):
        row = require_object(item, "benchmark run result")
        require_exact_keys(
            row, {"run_id", "passed", "duration_s", "error"},
            "benchmark run result",
        )
        if require_int(row["run_id"], "benchmark run identity", minimum=1) != index:
            raise JsonContractError("benchmark run identities are not contiguous")
        row_passed = require_bool(row["passed"], "benchmark run success")
        observed_passed += int(row_passed)
        run_duration = require_number(
            row["duration_s"], "benchmark run duration", minimum=0.0
        )
        error = require_string(row["error"], "benchmark run error", allow_empty=True)
        if row_passed == bool(error) or (row_passed and run_duration <= 0.0):
            raise JsonContractError("benchmark run error presence is contradictory")
    if observed_passed != passed:
        raise JsonContractError("benchmark passed-run count is contradictory")


def validate_benchmark_run_artifacts(
    result: Dict[str, Any],
    metadata: Dict[str, Any],
    manifest: Dict[str, Any],
    run_root: str,
) -> None:
    """
    Validate one run's result and metadata against its benchmark authority.

    Parameters
    ----------
    result : Dict[str, Any]
        Parsed per-run test-results artifact.
    metadata : Dict[str, Any]
        Parsed per-run runtime/topology metadata artifact.
    manifest : Dict[str, Any]
        Already admitted terminal benchmark manifest.
    run_root : str
        Exact absolute path of the run directory being consumed.
    """
    validate_benchmark_result_identity(result, manifest)
    validate_run_metadata(metadata)
    scenario = _validate_benchmark_scenario(manifest["scenario"])
    config = require_object(manifest["config"], "benchmark configuration")
    profile = _benchmark_profile(
        scenario["deployment"],
        scenario["backend"],
        scenario["stream_topology"],
        scenario["storage_profile"],
    )
    expected_metadata_identity = {
        "backend": scenario["backend"],
        "traffic_driver": scenario["traffic_driver"],
        "stream_topology": scenario["stream_topology"],
        "storage_profile": scenario["storage_profile"],
        "timestamp_source": profile.timestamp_source,
        "rate_control_source": profile.rate_control_source,
        "latency_source": profile.latency_source,
        "binding_file": profile.bindings_file_for(
            _benchmark_stream_topology(scenario["stream_topology"]),
            StorageProfile(scenario["storage_profile"]),
        ),
        "hardware_inventory": profile.hw_file,
        "runtime_root": config["runtime_root"],
        "validation_root": config["validation_root"],
        "runtime_release": manifest["runtime_release"],
    }
    if any(
        metadata[name] != expected
        for name, expected in expected_metadata_identity.items()
    ):
        raise JsonContractError("benchmark run metadata disagrees with its manifest")
    exact_run_root = require_absolute_path(run_root, "benchmark run root")
    if (
        result["dry_run"]
        or metadata["dry_run"]
        or metadata["bundle_root"] != f"{exact_run_root}/runtime_bundle"
    ):
        raise JsonContractError("benchmark run lifecycle identity is contradictory")

    endpoint = require_object(
        metadata["traffic_endpoint"], "run metadata traffic endpoint"
    )
    expected_endpoint = {
        "host": scenario["traffic_host"],
        "ssh_port": scenario["traffic_ssh_port"],
        "python": scenario["traffic_python"],
        "work_dir": scenario["traffic_work_dir"],
        "trex_server": scenario["trex_server"],
        "trex_api_path": scenario["trex_api_path"],
        "trex_ports": scenario["trex_ports"],
    }
    if any(endpoint[name] != expected for name, expected in expected_endpoint.items()):
        raise JsonContractError("benchmark traffic endpoint identity disagrees")
    _validate_benchmark_profile_ports(metadata["ports"], profile.ports)


def validate_benchmark_result_identity(
    result: Dict[str, Any],
    manifest: Dict[str, Any],
) -> None:
    """Validate one test result against its benchmark scenario identity."""
    validate_test_suite_result(result)
    if result["dry_run"]:
        raise JsonContractError("benchmark result cannot be a dry run")
    scenario = _validate_benchmark_scenario(manifest["scenario"])
    profile = _benchmark_profile(
        scenario["deployment"],
        scenario["backend"],
        scenario["stream_topology"],
        scenario["storage_profile"],
    )
    expected_identity = {
        "deployment": scenario["deployment"],
        "test_type": scenario["test_type"],
        "backend": scenario["backend"],
        "traffic_driver": scenario["traffic_driver"],
        "timestamp_source": profile.timestamp_source,
        "rate_control_source": profile.rate_control_source,
        "latency_source": profile.latency_source,
    }
    if any(result[name] != expected for name, expected in expected_identity.items()):
        raise JsonContractError("benchmark result identity disagrees with its manifest")


def _benchmark_stream_topology(value: str) -> Any:
    """Convert an admitted stream-topology spelling to its registry enum."""
    return StreamTopologyProfile(value)


def _validate_benchmark_profile_ports(
    value: object,
    expected_ports: Iterable[Any],
) -> None:
    """Validate run metadata's immutable port fields against its profile."""
    actual_ports = require_array(value, "benchmark run ports")
    expected_rows = list(expected_ports)
    if len(actual_ports) != len(expected_rows):
        raise JsonContractError("benchmark run port membership is inexact")
    fields = (
        "logical_name", "traffic_role", "tap_iface", "peer_iface", "peer_ip",
        "traffic_port_id",
    )
    for index, (actual_value, expected) in enumerate(
        zip(actual_ports, expected_rows)
    ):
        actual = require_object(actual_value, f"benchmark run port {index}")
        if any(actual[name] != getattr(expected, name) for name in fields):
            raise JsonContractError("benchmark run port identity disagrees")


def _validate_distribution(
    value: object,
    context: str,
    expected_count: int,
    *,
    integral: bool = False,
    maximum: float | None = None,
) -> None:
    """Validate one nonnegative nearest-rank aggregate distribution."""
    distribution = require_object(value, context)
    require_exact_keys(
        distribution,
        {"min", "p50", "p95", "p99", "max", "count"},
        context,
    )
    count = require_int(distribution["count"], f"{context} count", minimum=1)
    if integral:
        values = [
            require_int(
                distribution[name], f"{context} {name}", minimum=0,
                maximum=_UINT64_MAX,
            )
            for name in ("min", "p50", "p95", "p99", "max")
        ]
    else:
        values = [
            require_number(
                distribution[name],
                f"{context} {name}",
                minimum=0.0,
                maximum=maximum,
            )
            for name in ("min", "p50", "p95", "p99", "max")
        ]
    if count != expected_count or values != sorted(values):
        raise JsonContractError(f"{context} distribution is contradictory")


def _validate_distribution_map(
    value: object,
    context: str,
    expected_count: int,
    *,
    integral: bool = False,
) -> frozenset[str]:
    """Validate a nonempty identity-to-distribution mapping."""
    mapping = require_object(value, context)
    if not mapping:
        raise JsonContractError(f"{context} must not be empty")
    for identity, distribution in mapping.items():
        require_string(identity, f"{context} identity")
        _validate_distribution(
            distribution,
            f"{context} {identity}",
            expected_count,
            integral=integral,
        )
    return frozenset(mapping)


def _validate_benchmark_sample_count(
    count: int,
    inclusion_policy: str,
    passed_runs: int,
    total_runs: int,
    context: str,
) -> None:
    """Validate one distribution's selected-run population."""
    if inclusion_policy == "passed_only":
        valid = count == passed_runs
    else:
        valid = max(1, passed_runs) <= count <= total_runs
    if not valid:
        raise JsonContractError(f"{context} sample population is contradictory")


def _validate_latency_distribution(
    value: object,
    context: str,
    base_count: int,
    inclusion_policy: str,
    passed_runs: int,
) -> None:
    """Validate one positive distribution over the observed latency subset."""
    distribution = require_object(value, context)
    count = require_int(
        distribution.get("count"), f"{context} count", minimum=1
    )
    minimum_count = base_count if inclusion_policy == "passed_only" else max(
        1, passed_runs
    )
    if not minimum_count <= count <= base_count:
        raise JsonContractError(f"{context} sample population is contradictory")
    _validate_distribution(distribution, context, count)
    if require_number(distribution["min"], f"{context} minimum") <= 0.0:
        raise JsonContractError(f"{context} contains fabricated zero latency")


def _validate_benchmark_scenario_metrics(
    value: object,
    test_type: str,
    latency_available: bool,
    inclusion_policy: str,
    passed_runs: int,
    total_runs: int,
) -> None:
    """Validate scenario distributions against one exact benchmark identity."""
    metrics_by_family = require_object(value, "scenario metrics")
    expected_families = frozenset(EXPECTED_SCENARIO_METRICS_BY_TEST[test_type])
    actual_families = frozenset(metrics_by_family)
    if inclusion_policy == "passed_only":
        required_families = expected_families if passed_runs else frozenset()
        membership_valid = actual_families == required_families
    else:
        membership_valid = actual_families.issubset(expected_families) and (
            passed_runs == 0 or actual_families == expected_families
        )
    if not membership_valid:
        raise JsonContractError("scenario metric family membership is inexact")

    if "packet_tests" in metrics_by_family:
        _validate_benchmark_packet_metrics(
            metrics_by_family["packet_tests"],
            inclusion_policy,
            passed_runs,
            total_runs,
            latency_available,
        )

    scenario_shapes = {
        "epoch_test": {
            "total_sent", "total_received", "loss_pct",
            "boundary_count", "completed_boundaries",
            "protocol_faults_observed", "backpressure_events",
        },
        "commit_confirmed_test": {
            "tx_count", "rx_count", "loss_pct",
        },
        "rollback_test": {
            "tx_count", "rx_count", "loss_pct",
        },
        "guardrails_test": {"duration_s", "rollback_epoch_step"},
    }
    integral_fields = {
        "total_sent", "total_received", "boundary_count",
        "completed_boundaries", "protocol_faults_observed",
        "backpressure_events", "tx_count", "rx_count",
        "rollback_epoch_step",
    }
    for family, expected_fields in scenario_shapes.items():
        if family not in metrics_by_family:
            continue
        metrics = require_object(metrics_by_family[family], f"{family} metrics")
        carries_latency = family != "guardrails_test"
        latency_required = carries_latency and latency_available and passed_runs > 0
        require_key_contract(
            metrics,
            expected_fields | ({"avg_latency_us"} if latency_required else set()),
            {"avg_latency_us"}
            if carries_latency and latency_available and not latency_required
            else set(),
            f"{family} metrics",
        )
        base_metrics = {
            name: distribution
            for name, distribution in metrics.items()
            if name != "avg_latency_us"
        }
        count = _common_distribution_count(base_metrics, family)
        _validate_benchmark_sample_count(
            count, inclusion_policy, passed_runs, total_runs, family
        )
        for name, distribution in base_metrics.items():
            _validate_distribution(
                distribution,
                f"{family} {name}",
                count,
                integral=name in integral_fields,
                maximum=100.0 if name == "loss_pct" else None,
            )
        if "avg_latency_us" in metrics:
            _validate_latency_distribution(
                metrics["avg_latency_us"],
                f"{family} average latency",
                count,
                inclusion_policy,
                passed_runs,
            )


def _validate_benchmark_packet_metrics(
    value: object,
    inclusion_policy: str,
    passed_runs: int,
    total_runs: int,
    latency_available: bool,
) -> None:
    """Validate every packet-size distribution in one benchmark summary."""
    packet_tests = require_object(value, "packet scenario metrics")
    if not packet_tests:
        raise JsonContractError("packet scenario metrics are empty")
    for packet_size, metrics_value in packet_tests.items():
        if (
            not packet_size.isascii()
            or not packet_size.isdecimal()
            or str(int(packet_size)) != packet_size
            or not 64 <= int(packet_size) <= 9000
        ):
            raise JsonContractError("packet scenario identity is malformed")
        metrics = require_object(metrics_value, "packet scenario row")
        latency_required = latency_available and passed_runs > 0
        base_fields = {
            "tx_count", "rx_count", "loss_pct", "throughput_pps",
        }
        require_key_contract(
            metrics,
            base_fields | ({"avg_latency_us"} if latency_required else set()),
            {"avg_latency_us"}
            if latency_available and not latency_required
            else set(),
            "packet scenario row",
        )
        base_metrics = {
            name: distribution
            for name, distribution in metrics.items()
            if name != "avg_latency_us"
        }
        count = _common_distribution_count(
            base_metrics, f"packet {packet_size}"
        )
        _validate_benchmark_sample_count(
            count,
            inclusion_policy,
            passed_runs,
            total_runs,
            f"packet {packet_size}",
        )
        for name, distribution in base_metrics.items():
            _validate_distribution(
                distribution,
                f"packet {packet_size} {name}",
                count,
                integral=name in {"tx_count", "rx_count"},
                maximum=100.0 if name == "loss_pct" else None,
            )
        if "avg_latency_us" in metrics:
            _validate_latency_distribution(
                metrics["avg_latency_us"],
                f"packet {packet_size} average latency",
                count,
                inclusion_policy,
                passed_runs,
            )


def _common_distribution_count(value: Dict[str, Any], context: str) -> int:
    """Return the one sample count shared by a metric family."""
    counts = set()
    for item in value.values():
        distribution = require_object(item, f"{context} distribution")
        require_exact_keys(
            distribution,
            {"min", "p50", "p95", "p99", "max", "count"},
            f"{context} distribution",
        )
        counts.add(
            require_int(
                distribution["count"],
                f"{context} distribution count",
                minimum=1,
            )
        )
    if len(counts) != 1:
        raise JsonContractError(f"{context} distribution counts disagree")
    return next(iter(counts))


def _validate_benchmark_transition_metrics(
    value: object,
    test_type: str,
    inclusion_policy: str,
    passed_runs: int,
    total_runs: int,
) -> None:
    """Validate transition distributions against one exact benchmark scenario."""
    transition = require_object(value, "benchmark transition metrics")
    expected_types = EXPECTED_TRANSITION_TYPES_BY_TEST[test_type]
    if not transition:
        if passed_runs and expected_types:
            raise JsonContractError("benchmark transition evidence is missing")
        return
    if inclusion_policy == "passed_only" and passed_runs == 0:
        raise JsonContractError("failed runs entered passed-only transitions")
    require_exact_keys(
        transition,
        {"total_transitions", "aggregate", "per_type"},
        "benchmark transition metrics",
    )
    transition_total = require_int(
        transition["total_transitions"],
        "benchmark transition count",
        minimum=1,
    )
    aggregate = require_object(
        transition["aggregate"], "benchmark aggregate transitions"
    )
    require_exact_keys(
        aggregate,
        {"boundary_cut_drain_ns", "boundary_ack_gate_ns"},
        "benchmark aggregate transitions",
    )
    aggregate_cut = _validate_distribution_map(
        aggregate["boundary_cut_drain_ns"],
        "aggregate boundary cut drain",
        transition_total,
        integral=True,
    )
    aggregate_ack = _validate_distribution_map(
        aggregate["boundary_ack_gate_ns"],
        "aggregate boundary ACK gate",
        transition_total,
        integral=True,
    )
    if aggregate_cut != aggregate_ack:
        raise JsonContractError("aggregate boundary membership disagrees")

    per_type = require_object(transition["per_type"], "transition types")
    if not per_type:
        raise JsonContractError("transition type aggregation is empty")
    validate_benchmark_transition_multiset(
        per_type,
        test_type,
        complete=passed_runs > 0,
    )
    observed_total = 0
    expected_region_membership = None
    expected_stage_membership = None
    for transition_type, item in per_type.items():
        row = require_object(item, f"transition type {transition_type}")
        require_exact_keys(
            row,
            {
                "count", "rx_packets_delta", "tx_packets_delta",
                "dropped_packets_delta", "protocol_fault_deltas",
                "boundary_cut_delivery_ns", "boundary_cut_drain_ns",
                "boundary_ack_gate_ns", "boundary_backpressure_events",
                "region_fanout_overflow", "stage_drops",
            },
            f"transition type {transition_type}",
        )
        count = require_int(
            row["count"], f"transition type {transition_type} count", minimum=1
        )
        _validate_benchmark_sample_count(
            count,
            inclusion_policy,
            passed_runs,
            total_runs,
            f"transition type {transition_type}",
        )
        observed_total += count
        _validate_benchmark_transition_type_row(
            row,
            transition_type,
            count,
            aggregate_cut,
        )
        region_membership = frozenset(row["region_fanout_overflow"])
        stage_membership = frozenset(row["stage_drops"])
        if expected_region_membership is None:
            expected_region_membership = region_membership
            expected_stage_membership = stage_membership
        elif (
            region_membership != expected_region_membership
            or stage_membership != expected_stage_membership
        ):
            raise JsonContractError("transition row membership disagrees")
    if observed_total != transition_total:
        raise JsonContractError("benchmark transition totals disagree")


def _validate_benchmark_transition_type_row(
    row: Dict[str, Any],
    transition_type: str,
    count: int,
    expected_boundaries: frozenset[str],
) -> None:
    """Validate one transition-type aggregate and its complete row membership."""
    for name in ("rx_packets_delta", "tx_packets_delta", "dropped_packets_delta"):
        _validate_distribution(
            row[name], f"{transition_type} {name}", count, integral=True
        )
    fault_distributions = require_object(
        row["protocol_fault_deltas"], f"{transition_type} protocol faults"
    )
    require_exact_keys(
        fault_distributions,
        PROTOCOL_FAULT_CODES,
        f"{transition_type} protocol faults",
    )
    for code, distribution in fault_distributions.items():
        _validate_distribution(
            distribution,
            f"{transition_type} protocol fault {code}",
            count,
            integral=True,
        )
        if require_object(
            distribution, f"{transition_type} protocol fault {code}"
        )["max"] != 0:
            raise JsonContractError("successful transition aggregate has a fault")

    boundary_maps = [
        _validate_distribution_map(
            row[name], f"{transition_type} {name}", count, integral=True
        )
        for name in (
            "boundary_cut_delivery_ns", "boundary_cut_drain_ns",
            "boundary_ack_gate_ns", "boundary_backpressure_events",
        )
    ]
    if any(membership != expected_boundaries for membership in boundary_maps):
        raise JsonContractError("transition boundary membership disagrees")
    region_membership = _validate_distribution_map(
        row["region_fanout_overflow"],
        f"{transition_type} region fanout",
        count,
        integral=True,
    )
    if any(
        not identity.isascii()
        or not identity.isdecimal()
        or str(int(identity)) != identity
        for identity in region_membership
    ):
        raise JsonContractError("transition region identity is malformed")
    _validate_distribution_map(
        row["stage_drops"],
        f"{transition_type} stage drops",
        count,
        integral=True,
    )


def validate_benchmark_summary(value: Dict[str, Any]) -> None:
    """Validate one complete benchmark aggregate before derived output."""
    require_exact_keys(
        value,
        {
            "variant", "inclusion_policy", "scenario", "epoch_pps",
            "total_runs", "passed_runs", "failed_runs", "failed_run_ids",
            "failure_reasons", "trex_identity", "scenario_metrics",
            "transition_metrics",
        },
        "benchmark summary",
    )
    variant = require_string(value["variant"], "benchmark summary variant")
    if len(variant.encode("utf-8")) > 128 or not variant.isprintable():
        raise JsonContractError("benchmark summary variant is malformed")
    inclusion_policy = require_string(
        value["inclusion_policy"], "benchmark summary inclusion policy"
    )
    if inclusion_policy not in {"passed_only", "all_runs"}:
        raise JsonContractError("benchmark summary inclusion policy is undeclared")
    scenario = _validate_benchmark_scenario(value["scenario"])
    require_int(
        value["epoch_pps"],
        "benchmark summary epoch PPS",
        minimum=1,
        maximum=1_000_000_000,
    )
    total = require_int(
        value["total_runs"], "benchmark summary runs", minimum=1, maximum=999
    )
    passed = require_int(
        value["passed_runs"],
        "benchmark summary passed runs",
        minimum=0,
        maximum=total,
    )
    failed = require_int(
        value["failed_runs"],
        "benchmark summary failed runs",
        minimum=0,
        maximum=total,
    )
    failed_ids = [
        require_string(item, "benchmark failed run identity")
        for item in require_array(
            value["failed_run_ids"], "benchmark failed run identities"
        )
    ]
    failure_reasons = require_object(
        value["failure_reasons"], "benchmark failure reasons"
    )
    if (
        passed + failed != total
        or len(failed_ids) != failed
        or len(failed_ids) != len(set(failed_ids))
        or failed_ids != sorted(failed_ids)
        or frozenset(failed_ids) != frozenset(failure_reasons)
    ):
        raise JsonContractError("benchmark summary run membership is contradictory")
    for run_id, reason in failure_reasons.items():
        suffix = run_id[4:] if run_id.startswith("run_") else ""
        if (
            len(run_id) != 7
            or not suffix.isascii()
            or not suffix.isdecimal()
            or not 1 <= int(suffix) <= total
            or run_id != f"run_{int(suffix):03d}"
        ):
            raise JsonContractError("benchmark failed run identity is malformed")
        require_string(reason, f"benchmark failure reason {run_id}")

    trex_identity = (
        None
        if value["trex_identity"] is None
        else require_trex_identity(
            value["trex_identity"], "benchmark summary TRex identity"
        )
    )
    scenario_metrics = require_object(
        value["scenario_metrics"], "benchmark scenario metrics"
    )
    transition_metrics = require_object(
        value["transition_metrics"], "benchmark transition metrics"
    )
    if scenario["traffic_driver"] == "trex":
        if (scenario_metrics or transition_metrics) and trex_identity is None:
            raise JsonContractError("benchmark summary TRex identity is missing")
    elif trex_identity is not None:
        raise JsonContractError("benchmark summary retained inactive TRex identity")

    test_type = scenario["test_type"]
    _validate_benchmark_scenario_metrics(
        scenario_metrics,
        test_type,
        scenario["latency_source"] is not None,
        inclusion_policy,
        passed,
        total,
    )
    _validate_benchmark_transition_metrics(
        transition_metrics,
        test_type,
        inclusion_policy,
        passed,
        total,
    )


def validate_benchmark_summary_identity(
    summary: Dict[str, Any],
    manifest: Dict[str, Any],
) -> None:
    """
    Bind one validated aggregate to its terminal benchmark manifest.

    Parameters
    ----------
    summary : Dict[str, Any]
        Parsed aggregate summary.
    manifest : Dict[str, Any]
        Parsed terminal benchmark manifest.

    Raises
    ------
    JsonContractError
        If either artifact is malformed or their immutable identities differ.
    """
    validate_benchmark_summary(summary)
    validate_benchmark_manifest(manifest, completed=True)
    results = require_object(manifest["results"], "benchmark results")
    expected_failed_ids = [
        f"run_{row['run_id']:03d}"
        for row in results["runs"]
        if not row["passed"]
    ]
    scenario_identity_exact = all((
        summary["variant"] == manifest["variant"],
        summary["inclusion_policy"] == manifest["inclusion_policy"],
        summary["scenario"] == manifest["scenario"],
        summary["epoch_pps"] == manifest["config"]["epoch_pps"],
    ))
    run_identity_exact = all((
        summary["total_runs"] == results["total_runs"],
        summary["passed_runs"] == results["passed_runs"],
        summary["failed_runs"] == results["failed_runs"],
        summary["failed_run_ids"] == expected_failed_ids,
    ))
    expected_failures = {
        f"run_{row['run_id']:03d}": row["error"]
        for row in results["runs"]
        if not row["passed"]
    }
    if (
        not scenario_identity_exact
        or not run_identity_exact
        or summary["failure_reasons"] != expected_failures
    ):
        raise JsonContractError(
            "benchmark summary identity disagrees with its terminal manifest"
        )
