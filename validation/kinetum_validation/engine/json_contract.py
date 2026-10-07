"""Strict JSON admission shared by validation and benchmark evidence readers."""

from __future__ import annotations

import ipaddress
import json
import math
import posixpath
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, NoReturn, Tuple

from ..config.types import (
    BackendProfile,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    StreamTopologyProfile,
    StorageProfile,
    TestType,
    TrafficDriverType,
    TrafficEndpointConfig,
)
from ..version_contract import canonical_product_version


_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1
# Four-byte UTF-8 code points keep the decoded document below 64 MiB.
MAX_JSON_DOCUMENT_CHARACTERS = 16 * 1024 * 1024
EXPECTED_BUILD_FEATURES = frozenset(
    {"axiom_mlir_frontend", "axiom_mlir_dialect"}
)
EXPECTED_PLATFORM_CAPABILITIES = frozenset(
    {
        "coherent_runtime_telemetry",
        "commit_confirmed",
        "durable_guardrails",
        "exact_bootstrap",
        "ordered_epoch_transitions",
        "owner_worker_module_health",
        "selective_rollback",
        "synchronous_active_stages",
        "tracked_async_epoch_work",
    }
)
PROTOCOL_FAULT_CODE_ORDER = (
    "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH",
    "EPOCH_PROTOCOL_FAULT_CODE_OLD_DATA_AFTER_SEAL",
    "EPOCH_PROTOCOL_FAULT_CODE_FUTURE_DATA_BEFORE_ACK",
    "EPOCH_PROTOCOL_FAULT_CODE_CUT_IDENTITY_MISMATCH",
    "EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_ACTIVATION",
    "EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_CUT_DRAIN",
    "EPOCH_PROTOCOL_FAULT_CODE_RETIREMENT_BEFORE_QUIESCENCE",
    "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_UNDERFLOW",
    "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_OVERFLOW",
    "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_DOUBLE_RETIRE",
    "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_WRONG_SLOT",
    "EPOCH_PROTOCOL_FAULT_CODE_SEQUENCE_EXHAUSTED",
    "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED",
)
PROTOCOL_FAULT_CODES = frozenset(PROTOCOL_FAULT_CODE_ORDER)
_DEPLOYMENTS = frozenset(mode.value for mode in DeploymentMode)
_TEST_TYPES = frozenset(test_type.value for test_type in TestType)
_BACKENDS = frozenset(backend.value for backend in BackendType)
_TRAFFIC_DRIVERS = frozenset(driver.value for driver in TrafficDriverType)
EXPECTED_TRANSITION_TYPES_BY_TEST = {
    "standard": (),
    "epoch": ("epoch",),
    "commit_confirmed": (
        "commit_confirmed", "commit_confirmed_timeout_rollback",
    ),
    "rollback": (
        "rollback_apply_v1", "rollback_apply_v2", "rollback_selective",
        "rollback_full",
    ),
    "guardrails": ("guardrails_rollback",),
    "full": (
        "epoch", "commit_confirmed", "commit_confirmed_timeout_rollback",
        "rollback_apply_v1", "rollback_apply_v2", "rollback_selective",
        "rollback_full", "guardrails_rollback",
    ),
}
EXPECTED_SCENARIO_METRICS_BY_TEST = {
    "standard": ("packet_tests",),
    "epoch": ("epoch_test",),
    "commit_confirmed": ("commit_confirmed_test",),
    "rollback": ("rollback_test",),
    "guardrails": ("guardrails_test",),
    "full": (
        "packet_tests", "epoch_test", "commit_confirmed_test",
        "rollback_test", "guardrails_test",
    ),
}
TRANSITION_TYPES = frozenset(
    transition_type
    for transition_types in EXPECTED_TRANSITION_TYPES_BY_TEST.values()
    for transition_type in transition_types
)


class JsonContractError(ValueError):
    """Raised when JSON bytes do not satisfy one exact evidence contract."""


def _require_utf8_encoding(value: str, context: str) -> None:
    """Reject a decoded string that cannot be encoded as strict UTF-8."""
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise JsonContractError(f"{context} is not valid UTF-8") from exc


def _validate_decoded_utf8(value: object) -> None:
    """Validate every string in one decoded acyclic JSON value."""
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            _require_utf8_encoding(current, "JSON string")
        elif isinstance(current, dict):
            for key, nested in current.items():
                _require_utf8_encoding(key, "JSON object key")
                pending.append(nested)
        elif isinstance(current, list):
            pending.extend(current)


def parse_exact_json_object(raw_json: str, context: str) -> Dict[str, Any]:
    """
    Parse one JSON object with duplicate-key and non-finite-value rejection.

    Parameters
    ----------
    raw_json : str
        Complete candidate JSON document.
    context : str
        Stable producer name used in diagnostics.

    Returns
    -------
    Dict[str, Any]
        Parsed top-level object.

    Raises
    ------
    JsonContractError
        If parsing fails, a key is duplicated, a non-finite constant appears,
        a decoded string is not strict UTF-8, or the top-level value is not an
        object.
    """
    if (
        not isinstance(raw_json, str)
        or not raw_json
        or len(raw_json) > MAX_JSON_DOCUMENT_CHARACTERS
    ):
        raise JsonContractError(f"{context} returned empty or oversized JSON")
    try:
        value = json.loads(
            raw_json,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
        _validate_decoded_utf8(value)
    except (
        json.JSONDecodeError,
        TypeError,
        JsonContractError,
        MemoryError,
        RecursionError,
    ) as exc:
        raise JsonContractError(f"{context} returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise JsonContractError(f"{context} must return one JSON object")
    return value


def require_exact_keys(
    value: Dict[str, Any], expected: Iterable[str], context: str
) -> None:
    """Require exact object membership in both directions."""
    expected_keys = frozenset(expected)
    actual_keys = frozenset(value)
    if actual_keys != expected_keys:
        raise JsonContractError(
            f"{context} field membership mismatch: "
            f"missing={sorted(expected_keys - actual_keys)} "
            f"unknown={sorted(actual_keys - expected_keys)}"
        )


def require_key_contract(
    value: Dict[str, Any],
    required: Iterable[str],
    optional: Iterable[str],
    context: str,
) -> None:
    """Require all mandatory keys and reject keys outside one declared shape."""
    required_keys = frozenset(required)
    allowed_keys = required_keys | frozenset(optional)
    actual_keys = frozenset(value)
    if not required_keys.issubset(actual_keys) or not actual_keys.issubset(
        allowed_keys
    ):
        raise JsonContractError(
            f"{context} field membership mismatch: "
            f"missing={sorted(required_keys - actual_keys)} "
            f"unknown={sorted(actual_keys - allowed_keys)}"
        )


def require_object(value: object, context: str) -> Dict[str, Any]:
    """Return one object or reject its exact type."""
    if not isinstance(value, dict):
        raise JsonContractError(f"{context} must be an object")
    return value


def require_array(value: object, context: str) -> List[Any]:
    """Return one array or reject its exact type."""
    if not isinstance(value, list):
        raise JsonContractError(f"{context} must be an array")
    return value


def require_string(value: object, context: str, *, allow_empty: bool = False) -> str:
    """Return one string, optionally permitting empty content."""
    if not isinstance(value, str) or (not allow_empty and not value):
        raise JsonContractError(f"{context} must be a valid string")
    _require_utf8_encoding(value, context)
    return value


def require_optional_string(value: object, context: str) -> str | None:
    """Return one nonempty string or explicit JSON null."""
    return None if value is None else require_string(value, context)


def require_trex_identity(value: object, context: str) -> Dict[str, str]:
    """Return one bounded observed TRex server version and stateless mode."""
    identity = require_object(value, context)
    require_exact_keys(identity, {"version", "mode"}, context)
    version = require_string(identity["version"], f"{context} version")
    mode = require_string(identity["mode"], f"{context} mode")
    if (
        not version.isascii()
        or not version.isprintable()
        or len(version.encode("ascii")) > 128
    ):
        raise JsonContractError(f"{context} version is malformed")
    if mode != "STL":
        raise JsonContractError(f"{context} mode is not STL")
    return {"version": version, "mode": mode}


def require_bool(value: object, context: str) -> bool:
    """Return one JSON boolean without integer coercion."""
    if not isinstance(value, bool):
        raise JsonContractError(f"{context} must be a boolean")
    return value


def require_int(
    value: object,
    context: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Return one exact integer inside optional inclusive bounds."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise JsonContractError(f"{context} must be an integer")
    if minimum is not None and value < minimum:
        raise JsonContractError(f"{context} is below its minimum")
    if maximum is not None and value > maximum:
        raise JsonContractError(f"{context} exceeds its maximum")
    return value


def require_number(
    value: object,
    context: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """Return one finite JSON number inside optional inclusive bounds."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise JsonContractError(f"{context} must be a number")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise JsonContractError(f"{context} is outside the numeric domain") from exc
    if not math.isfinite(result):
        raise JsonContractError(f"{context} must be finite")
    if minimum is not None and result < minimum:
        raise JsonContractError(f"{context} is below its minimum")
    if maximum is not None and result > maximum:
        raise JsonContractError(f"{context} exceeds its maximum")
    return result


def require_timestamp(value: object, context: str) -> str:
    """Return one canonical UTC ISO-8601 timestamp string."""
    timestamp = require_string(value, context)
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise JsonContractError(f"{context} is not ISO-8601") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset() != timedelta(0)
        or parsed.isoformat() != timestamp
    ):
        raise JsonContractError(f"{context} is not canonical UTC")
    return timestamp


def _reject_duplicate_pairs(pairs: List[Tuple[str, object]]) -> Dict[str, object]:
    """Construct one object while rejecting its first duplicate key."""
    result: Dict[str, object] = {}
    for key, value in pairs:
        _require_utf8_encoding(key, "JSON object key")
        if key in result:
            raise JsonContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    """Reject NaN and infinity spellings accepted by Python's decoder."""
    raise JsonContractError(f"non-finite JSON constant: {value}")


def validate_transition_metric_record(value: Dict[str, Any]) -> None:
    """Validate one complete successful transition evidence record."""
    require_exact_keys(
        value,
        {
            "transition_type", "runtime_generation", "transition_generation",
            "from_epoch", "to_epoch", "transition_state",
            "transition_success_blocked", "rx_packets_delta", "tx_packets_delta",
            "dropped_packets_delta", "protocol_fault_deltas",
            "boundary_epoch_stats", "region_epoch_stats", "stage_stats",
        },
        "transition metric",
    )
    transition_type = require_string(
        value["transition_type"], "transition metric type"
    )
    if transition_type not in TRANSITION_TYPES:
        raise JsonContractError("transition metric type is undeclared")
    runtime_generation = require_int(
        value["runtime_generation"], "transition runtime generation", minimum=1,
        maximum=(1 << 32) - 1,
    )
    del runtime_generation
    transition_generation = require_int(
        value["transition_generation"], "transition generation", minimum=1,
        maximum=(1 << 64) - 2,
    )
    from_epoch = require_int(
        value["from_epoch"], "transition from epoch", minimum=1,
        maximum=(1 << 64) - 2,
    )
    to_epoch = require_int(
        value["to_epoch"], "transition to epoch", minimum=1,
        maximum=(1 << 64) - 2,
    )
    if to_epoch <= from_epoch:
        raise JsonContractError("transition metric epochs are not monotonic")
    if (
        require_string(value["transition_state"], "transition state")
        != "EPOCH_TRANSITION_STATE_IDLE"
        or require_bool(
            value["transition_success_blocked"], "transition success block"
        )
    ):
        raise JsonContractError("transition metric is not successful IDLE truth")
    require_int(
        value["rx_packets_delta"], "transition rx_packets_delta", minimum=1,
        maximum=_UINT64_MAX,
    )
    for field in ("tx_packets_delta", "dropped_packets_delta"):
        require_int(
            value[field], f"transition {field}", minimum=0,
            maximum=_UINT64_MAX,
        )

    faults = require_object(
        value["protocol_fault_deltas"], "transition protocol-fault deltas"
    )
    if frozenset(faults) != PROTOCOL_FAULT_CODES:
        raise JsonContractError("transition protocol-fault membership is inexact")
    for code, count in faults.items():
        if (
            not code
            or require_int(
                count, f"protocol fault {code}", minimum=0,
                maximum=_UINT64_MAX,
            ) != 0
        ):
            raise JsonContractError("successful transition contains a protocol fault")

    boundaries = require_array(
        value["boundary_epoch_stats"], "transition boundary rows"
    )
    if not boundaries:
        raise JsonContractError("transition boundary membership is empty")
    seen_boundaries = set()
    seen_boundary_indices = set()
    for index, item in enumerate(boundaries):
        row = require_object(item, f"transition boundary {index}")
        require_exact_keys(
            row,
            {
                "boundary_id", "boundary_index", "transition_generation",
                "from_epoch", "to_epoch", "cut_sequence", "sender_phase",
                "receiver_phase", "data_enqueued_sequence_delta",
                "data_dequeued_sequence_delta", "data_backpressure_events_delta",
                "cut_delivery_duration_ns", "cut_drain_duration_ns",
                "ack_gate_duration_ns",
            },
            f"transition boundary {index}",
        )
        boundary_id = require_string(row["boundary_id"], "boundary identity")
        boundary_index = require_int(
            row["boundary_index"], "boundary index", minimum=0,
            maximum=_UINT32_MAX,
        )
        if (
            boundary_id in seen_boundaries
            or boundary_index in seen_boundary_indices
        ):
            raise JsonContractError("transition boundary identity is duplicated")
        seen_boundaries.add(boundary_id)
        seen_boundary_indices.add(boundary_index)
        if (
            require_int(row["transition_generation"], "boundary generation", minimum=1)
            != transition_generation
            or require_int(row["from_epoch"], "boundary from epoch", minimum=1)
            != from_epoch
            or require_int(row["to_epoch"], "boundary to epoch", minimum=1)
            != to_epoch
            or require_string(row["sender_phase"], "boundary sender phase")
            != "BOUNDARY_SENDER_PHASE_OPEN"
            or require_string(row["receiver_phase"], "boundary receiver phase")
            != "BOUNDARY_RECEIVER_PHASE_OPEN"
        ):
            raise JsonContractError("transition boundary identity disagrees")
        for field in (
            "cut_sequence", "data_enqueued_sequence_delta",
            "data_dequeued_sequence_delta", "data_backpressure_events_delta",
            "cut_delivery_duration_ns", "cut_drain_duration_ns",
            "ack_gate_duration_ns",
        ):
            require_int(
                row[field], f"boundary {field}", minimum=0,
                maximum=_UINT64_MAX,
            )

    regions = require_array(value["region_epoch_stats"], "transition region rows")
    if not regions:
        raise JsonContractError("transition region membership is empty")
    seen_regions = set()
    for index, item in enumerate(regions):
        row = require_object(item, f"transition region {index}")
        require_exact_keys(
            row,
            {
                "region_id", "minimum_active_epoch", "maximum_active_epoch",
                "minimum_source_epoch", "maximum_source_epoch", "active_unretired",
                "future_unretired", "activated_participants", "worker_count",
                "fanout_overflow_delta",
            },
            f"transition region {index}",
        )
        region_id = require_int(
            row["region_id"], "region identity", minimum=0,
            maximum=(1 << 31) - 1,
        )
        if region_id in seen_regions:
            raise JsonContractError("transition region identity is duplicated")
        seen_regions.add(region_id)
        if any(
            require_int(row[field], f"region {field}", minimum=1) != to_epoch
            for field in (
                "minimum_active_epoch", "maximum_active_epoch",
                "minimum_source_epoch", "maximum_source_epoch",
            )
        ):
            raise JsonContractError("transition region epoch is not exact")
        require_int(
            row["active_unretired"], "region active credit", minimum=0,
            maximum=_UINT64_MAX,
        )
        if (
            require_int(
                row["future_unretired"], "region future credit", minimum=0,
                maximum=_UINT64_MAX,
            ) != 0
            or require_int(
                row["activated_participants"], "region activated participants",
                minimum=1, maximum=_UINT32_MAX,
            )
            != require_int(
                row["worker_count"], "region worker count", minimum=1,
                maximum=_UINT32_MAX,
            )
        ):
            raise JsonContractError("transition region ownership is incomplete")
        require_int(
            row["fanout_overflow_delta"], "region fanout delta", minimum=0,
            maximum=_UINT64_MAX,
        )

    stages = require_array(value["stage_stats"], "transition stage rows")
    if not stages:
        raise JsonContractError("transition stage membership is empty")
    seen_stages = set()
    for index, item in enumerate(stages):
        row = require_object(item, f"transition stage {index}")
        require_exact_keys(
            row,
            {"stage_id", "in_packets_delta", "out_packets_delta", "dropped_packets_delta"},
            f"transition stage {index}",
        )
        stage_id = require_string(row["stage_id"], "stage identity")
        if stage_id in seen_stages:
            raise JsonContractError("transition stage identity is duplicated")
        seen_stages.add(stage_id)
        for field in ("in_packets_delta", "out_packets_delta", "dropped_packets_delta"):
            require_int(
                row[field], f"stage {field}", minimum=0,
                maximum=_UINT64_MAX,
            )


def require_validation_profile(deployment: str, backend: str) -> Any:
    """Resolve one profile through the sole deployment registry."""
    try:
        return DEPLOYMENT_SPECS[DeploymentMode(deployment)].backend_profile(
            BackendType(backend)
        )
    except (KeyError, ValueError) as exc:
        raise JsonContractError("artifact has no exact validation profile") from exc


def _run_metadata_profile(
    backend: str,
    traffic_driver: str,
    binding_file: str,
    hardware_inventory: str,
) -> BackendProfile:
    """Resolve one metadata profile from exact registry-owned identities."""
    try:
        backend_type = BackendType(backend)
    except ValueError as exc:
        raise JsonContractError("run metadata backend is undeclared") from exc
    candidates = [
        profile
        for spec in DEPLOYMENT_SPECS.values()
        for profile in spec.backend_profiles.values()
        if profile.backend_type == backend_type
        and profile.traffic_driver.value == traffic_driver
        and profile.hw_file == hardware_inventory
        and binding_file in profile.bindings_files.values()
    ]
    if len(candidates) != 1:
        raise JsonContractError("run metadata has no exact evidence profile")
    return candidates[0]


def _require_average_latency(
    value: object,
    context: str,
    latency_source: str | None,
    result_passed: bool,
) -> float | None:
    """Validate one measured average or exact source-qualified absence."""
    if value is None:
        if result_passed and latency_source is not None:
            raise JsonContractError(f"{context} is missing from a successful result")
        return None
    if latency_source is None:
        raise JsonContractError(f"{context} has no owned measurement source")
    measured = require_number(value, context, minimum=0.0)
    if measured <= 0.0:
        raise JsonContractError(f"{context} must be positive when available")
    return measured


def _validate_packet_test_results(items: object, latency_source: str | None) -> None:
    """Validate each packet result and its measured traffic and latency facts."""
    packet_keys = {
        "packet_size", "passed", "tx_count", "rx_count", "loss_pct",
        "avg_latency_us", "throughput_pps", "duration_s", "message",
    }
    for index, item in enumerate(require_array(items, "packet tests")):
        row = require_object(item, f"packet test {index}")
        require_exact_keys(row, packet_keys, f"packet test {index}")
        require_int(row["packet_size"], "packet size", minimum=64, maximum=9000)
        row_passed = require_bool(row["passed"], "packet result")
        tx_count = require_int(
            row["tx_count"], "packet TX", minimum=0, maximum=_UINT64_MAX
        )
        rx_count = require_int(
            row["rx_count"], "packet RX", minimum=0, maximum=_UINT64_MAX
        )
        require_number(
            row["loss_pct"], "packet loss_pct", minimum=0.0, maximum=100.0
        )
        _require_average_latency(
            row["avg_latency_us"],
            "packet average latency",
            latency_source,
            row_passed,
        )
        throughput = require_number(
            row["throughput_pps"], "packet throughput_pps", minimum=0.0
        )
        duration = require_number(
            row["duration_s"], "packet duration_s", minimum=0.0
        )
        require_string(row["message"], "packet message", allow_empty=True)
        expected_loss = (
            max(0, tx_count - rx_count) / tx_count * 100.0
            if tx_count > 0 else 0.0
        )
        traffic_complete = 0 < rx_count <= tx_count and throughput > 0.0 and duration > 0.0
        if (
            abs(float(row["loss_pct"]) - expected_loss) > 0.011
            or (row_passed and not traffic_complete)
        ):
            raise JsonContractError("packet result counters are contradictory")


def _validate_epoch_test_result(
    row: Dict[str, Any], row_passed: bool, latency_source: str | None, traffic_driver: str,
) -> None:
    """Validate the complete epoch test evidence row."""
    for name in (
        "total_sent", "total_received", "initial_generation_sent",
        "next_generation_sent", "initial_generation_received",
        "next_generation_received", "transitions_observed",
        "boundary_count", "completed_boundaries",
        "protocol_faults_observed", "backpressure_events",
    ):
        require_int(
            row[name], f"epoch {name}", minimum=0,
            maximum=_UINT64_MAX,
        )
    require_int(
        row["generation_tag_transition_seq"],
        "epoch generation-tag transition sequence", minimum=-1,
        maximum=_UINT32_MAX,
    )
    require_number(
        row["loss_pct"], "epoch loss percentage", minimum=0.0,
        maximum=100.0,
    )
    _require_average_latency(
        row["avg_latency_us"],
        "epoch average latency",
        latency_source,
        row_passed,
    )
    zero_loss = require_bool(row["zero_loss"], "epoch zero-loss fact")
    ordering_validated = require_bool(
        row["boundary_ordering_validated"],
        "epoch boundary-ordering result",
    )
    require_string(row["message"], "epoch message", allow_empty=True)
    expected_loss = (
        max(0, row["total_sent"] - row["total_received"])
        / row["total_sent"] * 100.0
        if row["total_sent"] > 0 else 0.0
    )
    if (
        row["initial_generation_sent"] + row["next_generation_sent"]
        != row["total_sent"]
        or row["initial_generation_received"]
        + row["next_generation_received"]
        != row["total_received"]
    ):
        raise JsonContractError("epoch result facts are contradictory")
    measured_zero_loss = row["total_sent"] > 0 and row["total_sent"] == row["total_received"]
    if zero_loss != measured_zero_loss or abs(float(row["loss_pct"]) - expected_loss) > 0.011:
        raise JsonContractError("epoch result facts are contradictory")
    if row["completed_boundaries"] > row["boundary_count"] or row["transitions_observed"] > 1:
        raise JsonContractError("epoch result facts are contradictory")
    if ordering_validated and (
        row["boundary_count"] == 0
        or row["completed_boundaries"] != row["boundary_count"]
        or row["protocol_faults_observed"] != 0
    ):
        raise JsonContractError("epoch result facts are contradictory")
    if row_passed and not _epoch_success_is_complete(row, ordering_validated, traffic_driver):
        raise JsonContractError("epoch result facts are contradictory")


def _epoch_success_is_complete(row: Dict[str, Any], ordering_validated: bool, traffic_driver: str) -> bool:
    """Require one ordered transition and externally observed traffic from both generations."""
    if row["transitions_observed"] != 1 or not ordering_validated:
        return False
    if traffic_driver == "native_tap" and row["generation_tag_transition_seq"] < 0:
        return False
    populations = (
        (row["total_sent"], row["total_received"]),
        (row["initial_generation_sent"], row["initial_generation_received"]),
        (row["next_generation_sent"], row["next_generation_received"]),
    )
    return all(0 < received <= sent for sent, received in populations)


def _validate_commit_confirmed_test_result(
    row: Dict[str, Any], row_passed: bool, latency_source: str | None,
) -> None:
    """Validate the complete commit confirmed test evidence row."""
    for name in ("confirm_success", "timeout_rollback_occurred"):
        require_bool(row[name], f"commit-confirmed {name}")
    for name in ("confirm_snapshot_id", "timeout_rollback_snapshot_id"):
        require_string(
            row[name], f"commit-confirmed {name}", allow_empty=True
        )
    for name in ("confirm_time_remaining_ms", "tx_count", "rx_count"):
        require_int(
            row[name], f"commit-confirmed {name}", minimum=0,
            maximum=_UINT64_MAX,
        )
    require_number(
        row["loss_pct"], "commit-confirmed loss", minimum=0.0,
        maximum=100.0,
    )
    _require_average_latency(
        row["avg_latency_us"],
        "commit-confirmed latency",
        latency_source,
        row_passed,
    )
    require_string(
        row["message"], "commit-confirmed message", allow_empty=True
    )
    expected_loss = (
        max(0, row["tx_count"] - row["rx_count"])
        / row["tx_count"] * 100.0
        if row["tx_count"] > 0 else 0.0
    )
    if abs(float(row["loss_pct"]) - expected_loss) > 0.00011:
        raise JsonContractError(
            "commit-confirmed traffic counters are contradictory"
        )
    confirmation_complete = (
        row["confirm_success"] and bool(row["confirm_snapshot_id"])
        and row["confirm_time_remaining_ms"] > 0
    )
    rollback_complete = (
        row["timeout_rollback_occurred"]
        and row["timeout_rollback_snapshot_id"] == row["confirm_snapshot_id"]
    )
    traffic_complete = 0 < row["rx_count"] <= row["tx_count"]
    if row_passed and (not confirmation_complete or not rollback_complete or not traffic_complete):
        raise JsonContractError("commit-confirmed success is incomplete")


def _validate_rollback_test_result(
    row: Dict[str, Any], row_passed: bool, latency_source: str | None,
) -> None:
    """Validate the complete rollback test evidence row."""
    require_bool(row["full_rollback_success"], "full rollback result")
    require_bool(
        row["selective_rollback_success"], "selective rollback result"
    )
    for name in (
        "full_rollback_snapshot_id", "selective_rollback_snapshot_id"
    ):
        require_string(row[name], f"rollback {name}", allow_empty=True)
    modules = [
        require_string(item, "selective rollback module")
        for item in require_array(
            row["selective_rollback_modules"],
            "selective rollback modules",
        )
    ]
    if len(modules) != len(set(modules)):
        raise JsonContractError("selective rollback modules are duplicated")
    for name in ("tx_count", "rx_count"):
        require_int(
            row[name], f"rollback {name}", minimum=0,
            maximum=_UINT64_MAX,
        )
    require_number(
        row["loss_pct"], "rollback loss", minimum=0.0,
        maximum=100.0,
    )
    _require_average_latency(
        row["avg_latency_us"],
        "rollback latency",
        latency_source,
        row_passed,
    )
    require_string(row["message"], "rollback message", allow_empty=True)
    expected_loss = (
        max(0, row["tx_count"] - row["rx_count"])
        / row["tx_count"] * 100.0
        if row["tx_count"] > 0 else 0.0
    )
    if abs(float(row["loss_pct"]) - expected_loss) > 0.00011:
        raise JsonContractError("rollback traffic counters are contradictory")
    operations_complete = row["full_rollback_success"] and row["selective_rollback_success"]
    identities_complete = (
        bool(row["full_rollback_snapshot_id"] and row["selective_rollback_snapshot_id"])
        and row["full_rollback_snapshot_id"] != row["selective_rollback_snapshot_id"]
        and modules == ["kinetum.acl"]
    )
    traffic_complete = 0 < row["rx_count"] <= row["tx_count"]
    if row_passed and (not operations_complete or not identities_complete or not traffic_complete):
        raise JsonContractError("rollback success is incomplete")


def _validate_guardrails_test_result(
    row: Dict[str, Any], row_passed: bool,
) -> None:
    """Validate the complete guardrails test evidence row."""
    require_bool(row["policy_configured"], "guardrails policy result")
    for name in (
        "baseline_snapshot_id", "candidate_snapshot_id",
        "rollback_snapshot_id",
    ):
        require_string(row[name], f"guardrails {name}", allow_empty=True)
    candidate_epoch = require_int(
        row["candidate_epoch"], "guardrails candidate epoch", minimum=0,
        maximum=_UINT64_MAX - 1,
    )
    rollback_epoch = require_int(
        row["rollback_epoch"], "guardrails rollback epoch", minimum=0,
        maximum=_UINT64_MAX - 1,
    )
    faults = require_int(
        row["protocol_faults_observed"], "guardrails protocol faults",
        minimum=0, maximum=_UINT64_MAX,
    )
    require_string(
        row["message"], "guardrails message", allow_empty=True
    )
    content_restored = (
        bool(row["baseline_snapshot_id"] and row["candidate_snapshot_id"])
        and row["candidate_snapshot_id"] != row["baseline_snapshot_id"]
        and row["rollback_snapshot_id"] == row["baseline_snapshot_id"]
    )
    if row_passed and (
        not row["policy_configured"]
        or not content_restored
        or not 0 < candidate_epoch < rollback_epoch
        or faults != 0
    ):
        raise JsonContractError("guardrails success is incomplete")


def validate_test_suite_result(
    value: Dict[str, Any]
) -> None:
    """Validate one immutable per-run test-results artifact."""
    require_exact_keys(
        value,
        {
            "timestamp", "deployment", "test_type", "backend", "traffic_driver",
            "timestamp_source", "rate_control_source", "latency_source",
            "dry_run", "total_duration_s",
            "setup_failed", "all_passed", "total_tests", "passed_tests",
            "failed_tests", "stats_validation", "packet_tests", "epoch_test",
            "commit_confirmed_test", "rollback_test", "guardrails_test", "nat_exchange",
        },
        "test-results artifact",
    )
    require_timestamp(value["timestamp"], "test-results timestamp")
    deployment = require_string(value["deployment"], "test-results deployment")
    test_type = require_string(value["test_type"], "test-results test type")
    backend = require_string(value["backend"], "test-results backend")
    traffic_driver = require_string(
        value["traffic_driver"], "test-results traffic driver"
    )
    if (
        deployment not in _DEPLOYMENTS
        or test_type not in _TEST_TYPES
        or backend not in _BACKENDS
        or traffic_driver not in _TRAFFIC_DRIVERS
    ):
        raise JsonContractError("test-results scenario identity is undeclared")
    if (
        (backend == "dpdk_tap") != (traffic_driver == "native_tap")
        or (deployment == "passthrough" and test_type != "standard")
    ):
        raise JsonContractError("test-results scenario identity is undeclared")
    timestamp_source = require_string(
        value["timestamp_source"], "test-results timestamp source"
    )
    rate_control_source = require_string(
        value["rate_control_source"], "test-results rate-control source"
    )
    latency_source = require_optional_string(
        value["latency_source"], "test-results latency source"
    )
    profile = require_validation_profile(deployment, backend)
    if (
        traffic_driver != profile.traffic_driver.value
        or (timestamp_source, rate_control_source, latency_source)
        != (
            profile.timestamp_source,
            profile.rate_control_source,
            profile.latency_source,
        )
    ):
        raise JsonContractError("test-results evidence sources are foreign")
    for field in ("dry_run", "setup_failed", "all_passed"):
        require_bool(value[field], f"test-results {field}")
    require_number(
        value["total_duration_s"], "test-results duration", minimum=0.0
    )
    total = require_int(
        value["total_tests"], "test-results total", minimum=0,
        maximum=_UINT32_MAX,
    )
    passed = require_int(
        value["passed_tests"], "test-results passed", minimum=0,
        maximum=_UINT32_MAX,
    )
    failed = require_int(
        value["failed_tests"], "test-results failed", minimum=0,
        maximum=_UINT32_MAX,
    )
    if passed + failed != total or (value["all_passed"] and failed != 0):
        raise JsonContractError("test-results totals are contradictory")
    stats = require_object(value["stats_validation"], "stats-validation result")
    require_exact_keys(stats, {"required", "passed", "message"}, "stats-validation result")
    stats_required = require_bool(
        stats["required"], "stats-validation required"
    )
    stats_passed = require_bool(stats["passed"], "stats-validation passed")
    require_string(stats["message"], "stats-validation message", allow_empty=True)
    if not stats_required and not stats_passed:
        raise JsonContractError("optional stats validation cannot report failure")

    _validate_packet_test_results(value["packet_tests"], latency_source)

    optional_shapes = {
        "nat_exchange": {"passed", "session_count", "return_count", "context_count", "duration_s", "message"},
        "epoch_test": {
            "passed", "duration_s", "total_sent", "total_received",
            "initial_generation_sent", "next_generation_sent",
            "initial_generation_received", "next_generation_received",
            "generation_tag_transition_seq", "loss_pct", "avg_latency_us",
            "zero_loss", "transitions_observed", "boundary_count",
            "completed_boundaries", "protocol_faults_observed",
            "backpressure_events", "boundary_ordering_validated", "message",
        },
        "commit_confirmed_test": {
            "passed", "duration_s", "confirm_success", "confirm_snapshot_id",
            "confirm_time_remaining_ms", "timeout_rollback_occurred",
            "timeout_rollback_snapshot_id", "tx_count", "rx_count", "loss_pct",
            "avg_latency_us", "message",
        },
        "rollback_test": {
            "passed", "duration_s", "full_rollback_success",
            "full_rollback_snapshot_id", "selective_rollback_success",
            "selective_rollback_modules", "selective_rollback_snapshot_id",
            "tx_count", "rx_count", "loss_pct", "avg_latency_us", "message",
        },
        "guardrails_test": {
            "passed", "duration_s", "policy_configured", "baseline_snapshot_id",
            "candidate_snapshot_id", "rollback_snapshot_id", "candidate_epoch",
            "rollback_epoch", "protocol_faults_observed", "message",
        },
    }
    present_results = []
    for field, expected in optional_shapes.items():
        item = value[field]
        if item is None:
            continue
        row = require_object(item, f"{field} result")
        require_exact_keys(row, expected, f"{field} result")
        row_passed = require_bool(row["passed"], f"{field} passed")
        present_results.append(row_passed)
        row_duration = require_number(
            row["duration_s"], f"{field} duration", minimum=0.0
        )
        if row_passed and row_duration <= 0.0:
            raise JsonContractError(f"{field} success has no positive duration")

        if field == "epoch_test":
            _validate_epoch_test_result(row, row_passed, latency_source, traffic_driver)

        elif field == "commit_confirmed_test":
            _validate_commit_confirmed_test_result(row, row_passed, latency_source)

        elif field == "rollback_test":
            _validate_rollback_test_result(row, row_passed, latency_source)

        elif field == "guardrails_test":
            _validate_guardrails_test_result(row, row_passed)

        elif field == "nat_exchange":
            sessions = require_int(row["session_count"], "NAT session count", minimum=0, maximum=128)
            returns = require_int(row["return_count"], "NAT return count", minimum=0, maximum=128)
            contexts = require_int(row["context_count"], "NAT context count", minimum=0, maximum=_UINT32_MAX)
            require_string(row["message"], "NAT exchange message", allow_empty=True)
            if row_passed and (sessions == 0 or sessions != returns or not 0 < contexts <= sessions):
                raise JsonContractError("NAT exchange success has incomplete mapping or return evidence")

    expected_total = len(value["packet_tests"]) + len(present_results)
    if stats_required:
        expected_total += 1
    expected_passed = sum(
        require_bool(item["passed"], "packet result")
        for item in value["packet_tests"]
    ) + sum(present_results)
    if stats_required and stats_passed:
        expected_passed += 1
    expected_all_passed = (
        not value["setup_failed"]
        and (value["dry_run"] or (expected_total > 0 and expected_passed == expected_total))
    )
    optional_presence = {
        "nat_exchange": value["nat_exchange"] is not None,
        "epoch": value["epoch_test"] is not None,
        "commit_confirmed": value["commit_confirmed_test"] is not None,
        "rollback": value["rollback_test"] is not None,
        "guardrails": value["guardrails_test"] is not None,
    }
    if value["dry_run"] and (
        expected_total != 0
        or any(optional_presence.values())
        or value["packet_tests"]
    ):
        raise JsonContractError("dry-run result retained live test evidence")
    if value["setup_failed"] and expected_total != 0:
        raise JsonContractError("setup failure retained test results")
    expected_presence = {
        "nat_exchange": deployment == "fan_in_edge_gateway" and test_type in {"standard", "full"},
        "epoch": test_type in {"epoch", "full"},
        "commit_confirmed": test_type in {"commit_confirmed", "full"},
        "rollback": test_type in {"rollback", "full"},
        "guardrails": test_type in {"guardrails", "full"},
    }
    packet_family_expected = test_type in {"standard", "full"}
    if any(
        present and not expected_presence[name]
        for name, present in optional_presence.items()
    ) or (value["packet_tests"] and not packet_family_expected):
        raise JsonContractError(
            "test-results scenario membership contains a foreign family"
        )
    if value["all_passed"] and not value["dry_run"]:
        if optional_presence != expected_presence or (
            packet_family_expected and not value["packet_tests"]
        ):
            raise JsonContractError(
                "successful test-results scenario membership is inexact"
            )
    if (
        total != expected_total
        or passed != expected_passed
        or failed != expected_total - expected_passed
        or value["all_passed"] != expected_all_passed
    ):
        raise JsonContractError("test-results aggregate facts are contradictory")


def require_absolute_path(value: object, context: str) -> str:
    """Return one normalized absolute POSIX path."""
    path = require_string(value, context)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or not path.isprintable()
        or posixpath.normpath(path) != path
    ):
        raise JsonContractError(f"{context} must be an exact absolute path")
    return path


def _require_disjoint_release_roots(runtime_root: str, validation_root: str) -> None:
    """Keep a private kit and a public runtime outside each other's trees."""
    if posixpath.commonpath((runtime_root, validation_root)) in {
        runtime_root, validation_root
    }:
        raise JsonContractError("runtime and private validation-kit roots overlap")


def _require_ascii_atom(
    value: object,
    context: str,
    *,
    allow_empty: bool = False,
    maximum_bytes: int = 255,
) -> str:
    """Return one bounded printable ASCII token without whitespace."""
    text = require_string(value, context, allow_empty=allow_empty)
    if text and (
        not text.isascii()
        or len(text) > maximum_bytes
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in text)
    ):
        raise JsonContractError(f"{context} must be one bounded ASCII atom")
    return text


def _require_canonical_ipv4(
    value: object, context: str, *, allow_empty: bool = False
) -> str:
    """Return one canonical dotted-decimal IPv4 address."""
    text = require_string(value, context, allow_empty=allow_empty)
    if not text:
        return text
    try:
        parsed = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError as exc:
        raise JsonContractError(f"{context} is not IPv4") from exc
    if str(parsed) != text:
        raise JsonContractError(f"{context} is not canonical IPv4")
    return text


def _require_canonical_mac(
    value: object, context: str, *, allow_empty: bool = False
) -> str:
    """Return one canonical lowercase colon-delimited MAC address."""
    text = require_string(value, context, allow_empty=allow_empty)
    if not text:
        return text
    parts = text.split(":")
    if len(parts) != 6 or any(
        len(part) != 2
        or not part.isascii()
        or any(character not in "0123456789abcdef" for character in part)
        for part in parts
    ):
        raise JsonContractError(f"{context} is not a canonical MAC address")
    return text


def validate_run_metadata(value: Dict[str, Any]) -> None:
    """Validate one complete physical-run identity record before publication."""
    require_exact_keys(
        value,
        {
            "backend", "traffic_driver", "stream_topology", "storage_profile", "timestamp_source",
            "rate_control_source", "latency_source", "binding_file", "hardware_inventory",
            "runtime_release", "runtime_root", "validation_root", "bundle_root",
            "plan_file", "dry_run", "ports", "traffic_endpoint",
        },
        "run metadata",
    )
    backend = require_string(value["backend"], "run metadata backend")
    traffic_driver = require_string(
        value["traffic_driver"], "run metadata traffic driver"
    )
    if (
        backend not in _BACKENDS
        or traffic_driver not in _TRAFFIC_DRIVERS
        or (backend == "dpdk_tap") != (traffic_driver == "native_tap")
        or require_string(
            value["stream_topology"], "run metadata stream topology"
        )
        not in {"default", "rx_rss_2"}
        or require_string(value["storage_profile"], "run metadata storage profile")
        not in {profile.value for profile in StorageProfile}
    ):
        raise JsonContractError("run metadata scenario identity is undeclared")
    for name in (
        "timestamp_source", "rate_control_source", "binding_file",
        "hardware_inventory",
    ):
        require_string(value[name], f"run metadata {name}")
    latency_source = require_optional_string(
        value["latency_source"], "run metadata latency source"
    )
    profile = _run_metadata_profile(
        backend,
        traffic_driver,
        value["binding_file"],
        value["hardware_inventory"],
    )
    try:
        expected_binding = profile.bindings_file_for(
            StreamTopologyProfile(value["stream_topology"]),
            StorageProfile(value["storage_profile"]),
        )
    except ValueError as exc:
        raise JsonContractError("run metadata has no exact storage/topology profile") from exc
    if value["binding_file"] != expected_binding:
        raise JsonContractError("run metadata binding differs from its storage/topology profile")
    expected_sources = (
        profile.timestamp_source,
        profile.rate_control_source,
        profile.latency_source,
    )
    if (
        value["timestamp_source"], value["rate_control_source"], latency_source
    ) != expected_sources:
        raise JsonContractError("run metadata evidence sources are foreign")
    require_bool(value["dry_run"], "run metadata dry-run state")
    runtime_root = require_absolute_path(
        value["runtime_root"], "run metadata runtime root"
    )
    validation_root = require_absolute_path(
        value["validation_root"], "run metadata validation root"
    )
    bundle_root = require_absolute_path(
        value["bundle_root"], "run metadata bundle root"
    )
    plan_file = require_absolute_path(
        value["plan_file"], "run metadata plan file"
    )
    _require_disjoint_release_roots(runtime_root, validation_root)
    if plan_file != f"{bundle_root}/configs/plan.pbtxt":
        raise JsonContractError("run metadata path identities disagree")
    validate_runtime_release_record(value["runtime_release"])
    release = require_object(value["runtime_release"], "runtime release metadata")
    if release["source"] != f"{runtime_root}/bin/kinetum-info":
        raise JsonContractError("run metadata release source is foreign")

    ports = require_array(value["ports"], "run metadata ports")
    if len(ports) != len(profile.ports):
        raise JsonContractError("run metadata port membership is inexact")
    port_keys = {
        "logical_name", "traffic_role", "runtime_direction", "tap_iface",
        "peer_iface", "peer_ip", "traffic_port_id", "runtime_mac",
    }
    logical_names = set()
    traffic_port_ids = set()
    profile_fields = (
        "logical_name", "traffic_role", "tap_iface", "peer_iface", "peer_ip",
        "traffic_port_id",
    )
    for index, (item, expected_port) in enumerate(zip(ports, profile.ports)):
        row = require_object(item, f"run metadata port {index}")
        require_exact_keys(row, port_keys, f"run metadata port {index}")
        if any(
            row[field] != getattr(expected_port, field)
            for field in profile_fields
        ):
            raise JsonContractError("run metadata port identity is foreign")
        logical_name = _require_ascii_atom(
            row["logical_name"], f"run metadata port {index} identity"
        )
        traffic_role = require_string(
            row["traffic_role"], f"run metadata port {index} traffic role"
        )
        runtime_direction = require_string(
            row["runtime_direction"], f"run metadata port {index} direction"
        )
        if (
            logical_name in logical_names
            or traffic_role not in {"rx", "tx"}
            or runtime_direction not in {"rx", "tx", "bidirectional"}
            or runtime_direction not in {"bidirectional", traffic_role}
        ):
            raise JsonContractError("run metadata port identity is contradictory")
        logical_names.add(logical_name)
        tap_iface = _require_ascii_atom(
            row["tap_iface"], f"run metadata port {index} tap interface",
            allow_empty=True, maximum_bytes=15,
        )
        peer_iface = _require_ascii_atom(
            row["peer_iface"], f"run metadata port {index} peer interface",
            allow_empty=True, maximum_bytes=15,
        )
        _require_canonical_ipv4(
            row["peer_ip"], f"run metadata port {index} peer IP",
            allow_empty=True,
        )
        runtime_mac = _require_canonical_mac(
            row["runtime_mac"], f"run metadata port {index} runtime MAC",
            allow_empty=True,
        )
        traffic_port_id = require_int(
            row["traffic_port_id"], f"run metadata port {index} traffic ID",
            minimum=-1, maximum=_UINT32_MAX,
        )
        if traffic_driver == "trex":
            if (
                traffic_port_id < 0
                or traffic_port_id in traffic_port_ids
                or not peer_iface
                or (traffic_role == "rx" and not runtime_mac)
            ):
                raise JsonContractError("run metadata TRex port identity is inexact")
            traffic_port_ids.add(traffic_port_id)
        elif not tap_iface:
            raise JsonContractError("run metadata TAP interface is missing")

    endpoint = require_object(
        value["traffic_endpoint"], "run metadata traffic endpoint"
    )
    require_exact_keys(
        endpoint,
        {
            "host", "ssh_port", "python", "work_dir", "trex_server",
            "trex_api_path", "trex_ports", "trex_identity",
        },
        "run metadata traffic endpoint",
    )
    for name in ("host", "trex_server"):
        require_string(
            endpoint[name], f"run metadata traffic {name}", allow_empty=True
        )
        if endpoint[name] and (
            endpoint[name].startswith("-")
            or not endpoint[name].isprintable()
            or any(character.isspace() for character in endpoint[name])
            or len(endpoint[name].encode("utf-8")) > 255
        ):
            raise JsonContractError(
                f"run metadata traffic {name} is malformed"
            )
    require_int(
        endpoint["ssh_port"], "run metadata SSH port", minimum=0, maximum=65535
    )
    for name in ("python", "work_dir"):
        require_absolute_path(
            endpoint[name], f"run metadata traffic {name}"
        )
    if endpoint["trex_api_path"]:
        require_absolute_path(
            endpoint["trex_api_path"], "run metadata TRex API path"
        )
    if any(
        len(endpoint[name].encode("utf-8")) > 4096
        or not endpoint[name].isprintable()
        for name in ("python", "work_dir", "trex_api_path")
        if endpoint[name]
    ):
        raise JsonContractError("run metadata remote path is malformed")
    trex_ports = [
        require_int(item, "run metadata TRex port", minimum=0, maximum=_UINT32_MAX)
        for item in require_array(endpoint["trex_ports"], "run metadata TRex ports")
    ]
    if len(trex_ports) != len(set(trex_ports)):
        raise JsonContractError("run metadata TRex port overrides are duplicated")
    if trex_ports and len(trex_ports) != len(profile.ports):
        raise JsonContractError("run metadata TRex port override count is inexact")
    trex_identity = (
        None
        if endpoint["trex_identity"] is None
        else require_trex_identity(
            endpoint["trex_identity"], "run metadata TRex identity"
        )
    )
    if traffic_driver == "trex" and not value["dry_run"]:
        if not endpoint["host"]:
            raise JsonContractError("run metadata TRex endpoint host is missing")
        if trex_identity is None:
            raise JsonContractError("run metadata TRex identity is missing")
    if traffic_driver == "native_tap" or value["dry_run"]:
        neutral = TrafficEndpointConfig()
        if endpoint != {
            "host": neutral.host,
            "ssh_port": neutral.ssh_port,
            "python": neutral.python,
            "work_dir": neutral.work_dir,
            "trex_server": neutral.trex_server,
            "trex_api_path": neutral.trex_api_path,
            "trex_ports": list(neutral.trex_ports),
            "trex_identity": None,
        }:
            raise JsonContractError("inactive traffic endpoint retained remote residue")


def validate_runtime_release_record(value: object) -> None:
    """Validate normalized release identity embedded in an artifact."""
    release = require_object(value, "runtime release metadata")
    require_exact_keys(
        release,
        {
            "source", "version", "dpdk_version", "tls_enabled",
            "build_features", "platform_capabilities",
        },
        "runtime release metadata",
    )
    for name in ("source", "version", "dpdk_version"):
        require_string(release[name], f"runtime release {name}")
    require_absolute_path(release["source"], "runtime release source")
    if not release["dpdk_version"].isascii() or not release["dpdk_version"].isprintable():
        raise JsonContractError("runtime DPDK version is malformed")
    try:
        canonical_product_version(release["version"])
    except ValueError as exc:
        raise JsonContractError("runtime release version is malformed") from exc
    require_bool(release["tls_enabled"], "runtime release TLS feature")
    features = require_object(release["build_features"], "runtime build features")
    require_exact_keys(features, EXPECTED_BUILD_FEATURES, "runtime build features")
    for name in EXPECTED_BUILD_FEATURES:
        require_bool(features[name], f"runtime build feature {name}")
    if features["axiom_mlir_dialect"] and not features["axiom_mlir_frontend"]:
        raise JsonContractError("runtime MLIR feature relation is contradictory")
    capabilities = [
        require_string(item, "runtime platform capability")
        for item in require_array(
            release["platform_capabilities"], "runtime platform capabilities"
        )
    ]
    if (
        capabilities != sorted(capabilities)
        or len(capabilities) != len(set(capabilities))
        or frozenset(capabilities) != EXPECTED_PLATFORM_CAPABILITIES
    ):
        raise JsonContractError("runtime platform capability membership is inexact")
