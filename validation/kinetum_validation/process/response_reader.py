"""Strict native CLI response decoding with explicit scalar presence and telemetry admission."""

from __future__ import annotations

import base64
import binascii
import re
from typing import List, Optional

from ..engine.json_contract import (
    JsonContractError,
    parse_exact_json_object,
    require_exact_keys,
    require_key_contract,
    require_object,
    require_string,
)
from .telemetry import (
    _PROTOCOL_FAULT_CODE_ORDER,
    _PROTOCOL_FAULT_CODES,
    _TRANSITION_STATES,
    _TRANSITION_OUTCOMES,
    _TRANSITION_FAILURE_CODES,
    _PROTOCOL_FAULT_DISPOSITIONS,
    _PROVIDER_OBSERVATION_STATES,
    _SENDER_PHASES,
    _RECEIVER_PHASES,
    _CERTIFICATE_STATES,
    _CERTIFICATE_FAULTS,
    _MODULE_HEALTH_STATES,
    _PRECOMMIT_FAILURE_CODES,
    _FAIL_STOP_FAILURE_CODES,
    _UINT64_MAX,
    _MAX_EPOCH_ID,
    _MAX_MUTATION_SEQUENCE,
    _RUNTIME_FIELDS,
    _ENGINE_FIELDS,
    _TRANSITION_REQUIRED_FIELDS,
    _TRANSITION_OPTIONAL_FIELDS,
    _TRANSACTION_REQUIRED_FIELDS,
    _TRANSACTION_OPTIONAL_FIELDS,
    _TELEMETRY_CORE_FIELDS,
    _TELEMETRY_ROW_FIELDS,
    StageStatsResult,
    BoundaryEpochStatsResult,
    RegionEpochStatsResult,
    WorkerEpochStatsResult,
    StreamStatsResult,
    StorageDomainStatsResult,
    PortStatsResult,
    TrafficSteeringStatsResult,
    ModuleContextDomainResult,
    ModuleCounterStatsResult,
    ModuleHistogramStatsResult,
    ModuleEpochMismatchStatsResult,
    ModuleHealthStatsResult,
    EpochTransactionStatsResult,
    EpochCertificateStatsResult,
    EpochGraceStatsResult,
    ProtocolFirstFaultResult,
    StatsResult,
)
from .telemetry_validation import stats_are_exact


def wire_uint(value: object, bits: int = 64) -> int:
    """Return one canonical unsigned protobuf-JSON integer of ``bits`` width."""
    if bits <= 0 or bits > 64:
        raise ValueError("telemetry integer width is invalid")
    if bits == 64:
        return protobuf_uint64(value, "telemetry uint64")
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("narrow telemetry integer must be a JSON number")
    if value < 0 or value > (1 << bits) - 1:
        raise ValueError("telemetry integer is outside its exact wire domain")
    return value


def wire_int32(value: object) -> int:
    """Return one canonical signed int32 protobuf-JSON value."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("telemetry int32 must be a JSON number")
    if value < -(1 << 31) or value > (1 << 31) - 1:
        raise ValueError("telemetry int32 is outside its exact wire domain")
    return value


def _wire_bool(value: object) -> bool:
    """Return one JSON boolean without truth-value coercion."""
    if not isinstance(value, bool):
        raise TypeError("telemetry boolean has a noncanonical JSON value")
    return value


def wire_string(value: object) -> str:
    """Return one JSON string without converting another scalar type."""
    if not isinstance(value, str):
        raise TypeError("telemetry string has a noncanonical JSON value")
    return value


def wire_enum(value: object, allowed: frozenset[str]) -> str:
    """Return one declared non-sentinel protobuf enum spelling."""
    enum_value = wire_string(value)
    if enum_value not in allowed:
        raise ValueError("telemetry enum is unspecified or undeclared")
    return enum_value


def _wire_sha256(value: object) -> str:
    """Return one protobuf-JSON bytes value that decodes to exactly 32 bytes."""
    encoded = wire_string(value)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise ValueError("telemetry SHA-256 is not canonical base64") from exc
    if (
        len(decoded) != 32
        or base64.b64encode(decoded).decode("ascii") != encoded
    ):
        raise ValueError("telemetry SHA-256 is not canonical 32-byte base64")
    return encoded


def _wire_object_list(value: object) -> list[dict]:
    """Return one JSON array containing only object rows."""
    if not isinstance(value, list) or not all(
        isinstance(row, dict) for row in value
    ):
        raise TypeError("telemetry row family is not an object array")
    return value


def _wire_string_list(value: object) -> List[str]:
    """Return one JSON string array without scalar coercion."""
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise TypeError("telemetry identity family is not a string array")
    return list(value)


def _wire_optional_uint(
    row: dict, field_name: str, bits: int = 64
) -> Optional[int]:
    """Return one presence-qualified unsigned protobuf-JSON integer."""
    return wire_uint(row[field_name], bits=bits) if field_name in row else None


def _wire_optional_int32(row: dict, field_name: str) -> Optional[int]:
    """Return one presence-qualified signed int32 protobuf-JSON integer."""
    return wire_int32(row[field_name]) if field_name in row else None


def message_shape(
    value: object,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    context: str = "telemetry message",
) -> dict:
    """Return one object after exact required/optional membership admission."""
    row = require_object(value, context)
    require_key_contract(row, required, optional, context)
    return row


def _parse_transaction(row: object) -> EpochTransactionStatsResult:
    """Parse one required exact transaction object."""
    row = message_shape(
        row,
        _TRANSACTION_REQUIRED_FIELDS,
        _TRANSACTION_OPTIONAL_FIELDS,
        "transition transaction",
    )
    result = EpochTransactionStatsResult(
        mutation_sequence=wire_uint(row["mutation_sequence"]),
        from_epoch=wire_uint(row["from_epoch"]),
        to_epoch=wire_uint(row["to_epoch"]),
        validation_hash=_wire_sha256(row["validation_hash"]),
        idempotency_key_digest=_wire_sha256(
            row["idempotency_key_digest"]
        ),
        admitted_monotonic_ns=wire_uint(
            row["admitted_monotonic_ns"]
        ),
        outcome=wire_enum(row["outcome"], _TRANSITION_OUTCOMES),
        failure_code=wire_enum(
            row["failure_code"], _TRANSITION_FAILURE_CODES
        ),
        retirement_frozen=_wire_bool(row["retirement_frozen"]),
        prepared_monotonic_ns=_wire_optional_uint(
            row, "prepared_monotonic_ns"
        ),
        prepared_lease_deadline_monotonic_ns=_wire_optional_uint(
            row, "prepared_lease_deadline_monotonic_ns"
        ),
        prepared_lease_deadline_unix_ms=_wire_optional_uint(
            row, "prepared_lease_deadline_unix_ms"
        ),
        commit_started_monotonic_ns=_wire_optional_uint(
            row, "commit_started_monotonic_ns"
        ),
        retiring_started_monotonic_ns=_wire_optional_uint(
            row, "retiring_started_monotonic_ns"
        ),
        failure_observed_monotonic_ns=_wire_optional_uint(
            row, "failure_observed_monotonic_ns"
        ),
        terminal_monotonic_ns=_wire_optional_uint(
            row, "terminal_monotonic_ns"
        ),
    )
    identity_exact = (
        0 < result.mutation_sequence <= _MAX_MUTATION_SEQUENCE
        and 0 < result.from_epoch < result.to_epoch <= _MAX_EPOCH_ID
        and result.admitted_monotonic_ns > 0
    )
    if (
        not identity_exact
        or not _transaction_times_are_exact(result)
        or not _transaction_lease_is_exact(result)
        or not _transaction_outcome_is_exact(result)
    ):
        raise ValueError("transition transaction violates exact field relations")
    return result


def _transaction_times_are_exact(result: EpochTransactionStatsResult) -> bool:
    """Require observed phase times and failure evidence to follow admission."""
    ordered_times = [
        result.admitted_monotonic_ns,
        result.prepared_monotonic_ns,
        result.commit_started_monotonic_ns,
        result.retiring_started_monotonic_ns,
        result.terminal_monotonic_ns,
    ]
    observed_times = [value for value in ordered_times if value is not None]
    if observed_times != sorted(observed_times):
        return False
    if result.commit_started_monotonic_ns is not None and result.prepared_monotonic_ns is None:
        return False
    if result.retiring_started_monotonic_ns is not None and result.commit_started_monotonic_ns is None:
        return False
    failure_time = result.failure_observed_monotonic_ns
    if failure_time is None:
        return True
    if any(
        prior is not None and failure_time < prior
        for prior in ordered_times[:-1]
    ):
        return False
    return result.terminal_monotonic_ns is None or failure_time <= result.terminal_monotonic_ns


def _transaction_lease_is_exact(result: EpochTransactionStatsResult) -> bool:
    """Require both lease clocks together and a deadline after preparation."""
    deadline = result.prepared_lease_deadline_monotonic_ns
    wall_deadline = result.prepared_lease_deadline_unix_ms
    if (deadline is None) != (wall_deadline is None):
        return False
    if deadline is None:
        return True
    return (
        result.prepared_monotonic_ns is not None
        and deadline > result.prepared_monotonic_ns
        and wall_deadline != 0
    )


def _transaction_outcome_is_exact(result: EpochTransactionStatsResult) -> bool:
    """Require each admitted outcome's phase, failure, and terminal evidence."""
    no_failure = result.failure_code == "EPOCH_TRANSITION_FAILURE_CODE_NONE"
    if no_failure != (result.failure_observed_monotonic_ns is None):
        return False
    retirement_expired = (
        result.failure_code
        == "EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED"
    )
    if result.retirement_frozen != retirement_expired:
        return False
    terminal = result.outcome != "EPOCH_TRANSITION_OUTCOME_NONE"
    if terminal != (result.terminal_monotonic_ns is not None):
        return False
    if result.outcome == "EPOCH_TRANSITION_OUTCOME_COMPLETE":
        phases_present = all(value is not None for value in (
            result.prepared_monotonic_ns,
            result.commit_started_monotonic_ns,
            result.retiring_started_monotonic_ns,
        ))
        return no_failure and phases_present and result.prepared_lease_deadline_monotonic_ns is None
    if result.outcome == "EPOCH_TRANSITION_OUTCOME_ABORTED":
        post_prepare_absent = all(value is None for value in (
            result.prepared_lease_deadline_monotonic_ns,
            result.commit_started_monotonic_ns,
            result.retiring_started_monotonic_ns,
        ))
        return (
            result.failure_code in _PRECOMMIT_FAILURE_CODES
            and result.prepared_monotonic_ns is not None
            and post_prepare_absent
            and not no_failure
        )
    if result.outcome == "EPOCH_TRANSITION_OUTCOME_FAILED_STOP":
        return result.failure_code in _FAIL_STOP_FAILURE_CODES and not no_failure
    return result.failure_code in _FAIL_STOP_FAILURE_CODES | {
        "EPOCH_TRANSITION_FAILURE_CODE_NONE",
        "EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED",
    }


def _stream_direction(value: object) -> str:
    """Normalize one exact protobuf stream-direction enum for evidence code."""
    mapping = {
        "IO_STREAM_DIRECTION_RX": "rx",
        "IO_STREAM_DIRECTION_TX": "tx",
    }
    parsed = wire_string(value)
    if parsed not in mapping:
        raise ValueError("stream direction is unspecified or undeclared")
    return mapping[parsed]


def _steering_kind(value: object) -> str:
    """Normalize one exact protobuf steering enum for evidence code."""
    mapping = {
        "TRAFFIC_STEERING_KIND_NONE": "none",
        "TRAFFIC_STEERING_KIND_RSS": "rss",
    }
    parsed = wire_string(value)
    if parsed not in mapping:
        raise ValueError("steering kind is unspecified or undeclared")
    return mapping[parsed]


def parse_stats_json(raw_json: str) -> StatsResult:
    """
    Parse kinetumctl stats --format json output into a StatsResult.

    Extracted as a standalone function so it can be tested independently
    of subprocess execution.

    Parameters
    ----------
    raw_json : str
        Raw JSON string from kinetumctl stats --format json.

    Returns
    -------
    StatsResult
        Parsed result. success=False if JSON is malformed.
    """
    result = StatsResult(success=True)

    try:
        data = parse_cli_success(
            raw_json,
            frozenset({"active_config", "telemetry"}),
            "statistics response",
        )
        active = message_shape(
            data["active_config"],
            frozenset({"revision", "snapshot_id"}),
            context="active configuration",
        )
        telemetry = message_shape(
            data["telemetry"],
            _TELEMETRY_CORE_FIELDS,
            _TELEMETRY_ROW_FIELDS,
            "runtime telemetry",
        )
        runtime = message_shape(
            telemetry["runtime"], _RUNTIME_FIELDS, context="runtime observation"
        )
        engine = message_shape(
            telemetry["engine"], _ENGINE_FIELDS, context="engine counters"
        )
        transition = message_shape(
            telemetry["transition"],
            _TRANSITION_REQUIRED_FIELDS,
            _TRANSITION_OPTIONAL_FIELDS,
            "transition observation",
        )
        faults = message_shape(
            telemetry["protocol_faults"],
            frozenset({"transition_success_blocked", "counters"}),
            frozenset({"first_fault"}),
            "protocol fault summary",
        )
        result.rx_packets = wire_uint(engine["rx_packets"])
        result.tx_packets = wire_uint(engine["tx_packets"])
        result.dropped_packets = wire_uint(engine["dropped_packets"])
        result.rx_bytes = wire_uint(engine["rx_bytes"])
        result.tx_bytes = wire_uint(engine["tx_bytes"])
        result.fanout_overflow = wire_uint(engine["fanout_overflow"])
        if any(value == _UINT64_MAX for value in (
            result.rx_packets, result.tx_packets, result.rx_bytes, result.tx_bytes,
        )):
            raise ValueError("engine transfer counters are exhausted")
        result.active_epoch = wire_uint(runtime["active_epoch"])
        result.runtime_generation = wire_uint(
            runtime["runtime_generation"]
        )
        result.status_publication_generation = wire_uint(
            runtime["status_publication_generation"]
        )
        result.minimum_retained_epoch = wire_uint(
            runtime["minimum_retained_epoch"]
        )
        result.last_activated_epoch = wire_uint(
            runtime["last_activated_epoch"]
        )
        result.active_workers = wire_uint(
            runtime["active_workers"], bits=32
        )
        result.expected_workers = wire_uint(
            runtime["expected_workers"], bits=32
        )
        result.collection_monotonic_ns = wire_uint(
            runtime["collection_monotonic_ns"]
        )
        result.latest_bank_publication_monotonic_ns = wire_uint(
            runtime["latest_bank_publication_monotonic_ns"]
        )
        result.skipped_publications = wire_uint(
            runtime["skipped_publications"]
        )
        result.transition_state = wire_enum(
            transition["state"], _TRANSITION_STATES
        )
        result.transition_publication_generation = wire_uint(
            transition["publication_generation"]
        )
        result.transition_active_epoch = wire_uint(
            transition["active_epoch"]
        )
        result.transition_target_epoch = wire_uint(
            transition["target_epoch"]
        )
        result.allocated_epoch_high_watermark = wire_uint(
            transition["allocated_epoch_high_watermark"]
        )
        result.mutation_sequence_high_watermark = wire_uint(
            transition["mutation_sequence_high_watermark"]
        )
        result.transition_plan_content_hash = _wire_sha256(
            transition["plan_content_hash"]
        )
        result.transition_active_validation_hash = _wire_sha256(
            transition["active_validation_hash"]
        )
        result.participant_set_frozen = _wire_bool(
            transition["participant_set_frozen"]
        )
        result.execution_participant_count = wire_uint(
            transition["execution_participant_count"], bits=32
        )
        result.region_count = wire_uint(
            transition["region_count"], bits=32
        )
        result.boundary_count = wire_uint(
            transition["boundary_count"], bits=32
        )
        result.source_participant_count = wire_uint(
            transition["source_participant_count"], bits=32
        )
        result.sink_participant_count = wire_uint(
            transition["sink_participant_count"], bits=32
        )
        result.module_context_count = wire_uint(
            transition["module_context_count"], bits=32
        )
        result.quiescence_reader_count = wire_uint(
            transition["quiescence_reader_count"], bits=32
        )
        result.terminal_history_size = wire_uint(
            transition["terminal_history_size"], bits=32
        )
        result.retirement_frozen = _wire_bool(
            transition["retirement_frozen"]
        )
        if "active_transaction" in transition:
            result.active_transaction = _parse_transaction(
                transition["active_transaction"]
            )
        if "latest_terminal" in transition:
            result.latest_terminal = _parse_transaction(
                transition["latest_terminal"]
            )
        if "certificate" in transition:
            certificate = message_shape(
                transition["certificate"],
                frozenset({
                    "evaluated_monotonic_ns", "runtime_generation",
                    "transition_generation", "from_epoch", "to_epoch",
                    "execution_complete", "execution_total", "boundary_complete",
                    "boundary_total", "reader_complete", "reader_total",
                    "fault_index", "state", "fault",
                }),
                context="transition certificate",
            )
            result.certificate = EpochCertificateStatsResult(
                evaluated_monotonic_ns=wire_uint(
                    certificate["evaluated_monotonic_ns"]
                ),
                runtime_generation=wire_uint(
                    certificate["runtime_generation"]
                ),
                transition_generation=wire_uint(
                    certificate["transition_generation"]
                ),
                from_epoch=wire_uint(certificate["from_epoch"]),
                to_epoch=wire_uint(certificate["to_epoch"]),
                execution_complete=wire_uint(
                    certificate["execution_complete"], bits=32
                ),
                execution_total=wire_uint(
                    certificate["execution_total"], bits=32
                ),
                boundary_complete=wire_uint(
                    certificate["boundary_complete"], bits=32
                ),
                boundary_total=wire_uint(
                    certificate["boundary_total"], bits=32
                ),
                reader_complete=wire_uint(
                    certificate["reader_complete"], bits=32
                ),
                reader_total=wire_uint(
                    certificate["reader_total"], bits=32
                ),
                fault_index=wire_uint(
                    certificate["fault_index"], bits=32
                ),
                state=wire_enum(
                    certificate["state"], _CERTIFICATE_STATES
                ),
                fault=wire_enum(
                    certificate["fault"], _CERTIFICATE_FAULTS
                ),
            )
        if "grace" in transition:
            grace = message_shape(
                transition["grace"],
                frozenset({
                    "generation", "readers_complete", "readers_total", "active",
                    "update_frozen",
                }),
                frozenset({
                    "started_monotonic_ns", "completion_observed_monotonic_ns",
                    "finished_monotonic_ns",
                }),
                "transition grace",
            )
            result.grace = EpochGraceStatsResult(
                generation=wire_uint(grace["generation"]),
                started_monotonic_ns=_wire_optional_uint(
                    grace, "started_monotonic_ns"
                ),
                completion_observed_monotonic_ns=_wire_optional_uint(
                    grace, "completion_observed_monotonic_ns"
                ),
                finished_monotonic_ns=_wire_optional_uint(
                    grace, "finished_monotonic_ns"
                ),
                readers_complete=wire_uint(
                    grace["readers_complete"], bits=32
                ),
                readers_total=wire_uint(
                    grace["readers_total"], bits=32
                ),
                active=_wire_bool(grace["active"]),
                update_frozen=_wire_bool(grace["update_frozen"]),
            )
        result.transition_success_blocked = _wire_bool(
            faults["transition_success_blocked"]
        )
        for index, counter in enumerate(
            _wire_object_list(faults["counters"])
        ):
            counter = message_shape(
                counter,
                frozenset({"code", "count"}),
                context="protocol fault counter",
            )
            code = wire_enum(counter["code"], _PROTOCOL_FAULT_CODES)
            if (
                index >= len(_PROTOCOL_FAULT_CODE_ORDER)
                or code != _PROTOCOL_FAULT_CODE_ORDER[index]
                or code in result.protocol_fault_counts
            ):
                raise ValueError("protocol fault counter identity is malformed")
            result.protocol_fault_counts[code] = wire_uint(
                counter["count"]
            )
        if "first_fault" in faults:
            first_fault = message_shape(
                faults["first_fault"],
                frozenset({
                    "code", "disposition", "runtime_generation",
                    "transition_generation", "from_epoch", "to_epoch",
                    "observed_epoch", "worker_index", "boundary_index",
                    "context_index", "stage_instance_index", "expected_value",
                    "observed_value", "observed_monotonic_ns",
                }),
                context="first protocol fault",
            )
            result.first_protocol_fault = ProtocolFirstFaultResult(
                code=wire_enum(
                    first_fault["code"], _PROTOCOL_FAULT_CODES
                ),
                disposition=wire_enum(
                    first_fault["disposition"],
                    _PROTOCOL_FAULT_DISPOSITIONS,
                ),
                runtime_generation=wire_uint(
                    first_fault["runtime_generation"]
                ),
                transition_generation=wire_uint(
                    first_fault["transition_generation"]
                ),
                from_epoch=wire_uint(first_fault["from_epoch"]),
                to_epoch=wire_uint(first_fault["to_epoch"]),
                observed_epoch=wire_uint(
                    first_fault["observed_epoch"]
                ),
                worker_index=wire_uint(
                    first_fault["worker_index"], bits=32
                ),
                boundary_index=wire_uint(
                    first_fault["boundary_index"], bits=32
                ),
                context_index=wire_uint(
                    first_fault["context_index"], bits=32
                ),
                stage_instance_index=wire_uint(
                    first_fault["stage_instance_index"], bits=32
                ),
                expected_value=wire_uint(
                    first_fault["expected_value"]
                ),
                observed_value=wire_uint(
                    first_fault["observed_value"]
                ),
                observed_monotonic_ns=wire_uint(
                    first_fault["observed_monotonic_ns"]
                ),
            )
        result.active_snapshot_id = read_snapshot_id(
            active["snapshot_id"], "active snapshot identity"
        )
        result.active_revision = protobuf_int64(active["revision"], "active revision")

        for ss in _wire_object_list(
            telemetry["stages"] if "stages" in telemetry else []
        ):
            ss = message_shape(
                ss,
                frozenset({
                    "stage_id", "in_packets", "out_packets", "dropped_packets",
                    "in_bytes", "out_bytes",
                }),
                context="stage stats",
            )
            result.stage_stats.append(StageStatsResult(
                stage_id=wire_string(ss["stage_id"]),
                in_packets=wire_uint(ss["in_packets"]),
                out_packets=wire_uint(ss["out_packets"]),
                dropped_packets=wire_uint(ss["dropped_packets"]),
                in_bytes=wire_uint(ss["in_bytes"]),
                out_bytes=wire_uint(ss["out_bytes"]),
            ))

        for counter in _wire_object_list(
            telemetry["module_counters"] if "module_counters" in telemetry else []
        ):
            counter = message_shape(
                counter,
                frozenset({
                    "module_id", "context_instance_id", "context_index",
                    "worker_index", "epoch", "name", "value",
                }),
                context="module counter",
            )
            result.module_counter_stats.append(ModuleCounterStatsResult(
                module_id=wire_string(counter["module_id"]),
                context_instance_id=wire_string(
                    counter["context_instance_id"]
                ),
                context_index=wire_uint(
                    counter["context_index"], bits=32
                ),
                worker_index=wire_uint(
                    counter["worker_index"], bits=32
                ),
                epoch=wire_uint(counter["epoch"]),
                name=wire_string(counter["name"]),
                value=wire_uint(counter["value"]),
            ))

        for histogram in _wire_object_list(
            telemetry["module_histograms"] if "module_histograms" in telemetry else []
        ):
            histogram = message_shape(
                histogram,
                frozenset({
                    "module_id", "context_instance_id", "context_index",
                    "worker_index", "epoch", "name", "sample_count", "sample_sum",
                }),
                frozenset({"minimum", "maximum", "p50", "p90", "p99", "p999"}),
                "module histogram",
            )
            result.module_histogram_stats.append(ModuleHistogramStatsResult(
                module_id=wire_string(histogram["module_id"]),
                context_instance_id=wire_string(
                    histogram["context_instance_id"]
                ),
                context_index=wire_uint(
                    histogram["context_index"], bits=32
                ),
                worker_index=wire_uint(
                    histogram["worker_index"], bits=32
                ),
                epoch=wire_uint(histogram["epoch"]),
                name=wire_string(histogram["name"]),
                sample_count=wire_uint(histogram["sample_count"]),
                sample_sum=wire_uint(histogram["sample_sum"]),
                minimum=_wire_optional_uint(histogram, "minimum"),
                maximum=_wire_optional_uint(histogram, "maximum"),
                p50=_wire_optional_uint(histogram, "p50"),
                p90=_wire_optional_uint(histogram, "p90"),
                p99=_wire_optional_uint(histogram, "p99"),
                p999=_wire_optional_uint(histogram, "p999"),
            ))

        for mismatch in _wire_object_list(
            telemetry["module_epoch_mismatches"]
            if "module_epoch_mismatches" in telemetry else []
        ):
            mismatch = message_shape(
                mismatch,
                frozenset({
                    "module_id", "context_instance_id", "context_index",
                    "worker_index", "observation_epoch", "mismatch_count",
                }),
                frozenset({
                    "first_packet_epoch", "first_active_epoch",
                    "first_stage_instance_index", "first_region_id",
                }),
                "module epoch mismatch",
            )
            result.module_epoch_mismatch_stats.append(
                ModuleEpochMismatchStatsResult(
                    module_id=wire_string(mismatch["module_id"]),
                    context_instance_id=wire_string(
                        mismatch["context_instance_id"]
                    ),
                    context_index=wire_uint(
                        mismatch["context_index"], bits=32
                    ),
                    worker_index=wire_uint(
                        mismatch["worker_index"], bits=32
                    ),
                    observation_epoch=wire_uint(
                        mismatch["observation_epoch"]
                    ),
                    mismatch_count=wire_uint(
                        mismatch["mismatch_count"]
                    ),
                    first_packet_epoch=_wire_optional_uint(
                        mismatch, "first_packet_epoch"
                    ),
                    first_active_epoch=_wire_optional_uint(
                        mismatch, "first_active_epoch"
                    ),
                    first_stage_instance_index=_wire_optional_uint(
                        mismatch, "first_stage_instance_index", bits=32
                    ),
                    first_region_id=_wire_optional_int32(
                        mismatch, "first_region_id"
                    ),
                )
            )

        for health in _wire_object_list(
            telemetry["module_health"] if "module_health" in telemetry else []
        ):
            health = message_shape(
                health,
                frozenset({
                    "module_id", "context_instance_id", "context_index",
                    "worker_index", "stage_instance_index", "state",
                    "publication_generation", "contract_fault_count",
                    "latest_fault_mask", "first_fault_mask",
                }),
                frozenset({
                    "observation_epoch", "observed_at_ns", "callback_duration_ns",
                    "first_fault_epoch", "first_fault_timestamp_ns",
                    "first_fault_duration_ns", "health_score", "health_flags", "reason",
                }),
                "module health",
            )
            reason = health["reason"] if "reason" in health else None
            if reason is not None:
                reason = wire_string(reason)
            result.module_health_stats.append(ModuleHealthStatsResult(
                module_id=wire_string(health["module_id"]),
                context_instance_id=wire_string(
                    health["context_instance_id"]
                ),
                context_index=wire_uint(
                    health["context_index"], bits=32
                ),
                worker_index=wire_uint(
                    health["worker_index"], bits=32
                ),
                stage_instance_index=wire_uint(
                    health["stage_instance_index"], bits=32
                ),
                state=wire_enum(
                    health["state"], _MODULE_HEALTH_STATES
                ),
                publication_generation=wire_uint(
                    health["publication_generation"]
                ),
                observation_epoch=_wire_optional_uint(
                    health, "observation_epoch"
                ),
                observed_at_ns=_wire_optional_uint(
                    health, "observed_at_ns"
                ),
                callback_duration_ns=_wire_optional_uint(
                    health, "callback_duration_ns"
                ),
                contract_fault_count=wire_uint(
                    health["contract_fault_count"]
                ),
                latest_fault_mask=wire_uint(
                    health["latest_fault_mask"], bits=32
                ),
                first_fault_mask=wire_uint(
                    health["first_fault_mask"], bits=32
                ),
                first_fault_epoch=_wire_optional_uint(
                    health, "first_fault_epoch"
                ),
                first_fault_timestamp_ns=_wire_optional_uint(
                    health, "first_fault_timestamp_ns"
                ),
                first_fault_duration_ns=_wire_optional_uint(
                    health, "first_fault_duration_ns"
                ),
                health_score=_wire_optional_uint(
                    health, "health_score", bits=32
                ),
                health_flags=_wire_optional_uint(
                    health, "health_flags", bits=32
                ),
                reason=reason,
            ))

        for bt in _wire_object_list(
            telemetry["boundaries"] if "boundaries" in telemetry else []
        ):
            bt = message_shape(
                bt,
                frozenset({
                    "boundary_id", "boundary_index", "from_stage_instance_index",
                    "to_stage_instance_index", "sender_worker_index",
                    "receiver_worker_index", "from_region_id", "to_region_id",
                    "data_ring_capacity", "future_output_hold_capacity",
                    "data_enqueued_sequence", "data_dequeued_sequence",
                    "data_backpressure_events", "sender_phase", "receiver_phase",
                    "duplicate_cut_count", "duplicate_ack_count",
                }),
                frozenset({
                    "pending_cut_epoch", "pending_cut_sequence", "pending_ack_epoch",
                    "pending_ack_sequence", "transition_generation", "from_epoch",
                    "to_epoch", "cut_sequence", "cut_published_monotonic_ns",
                    "cut_observed_monotonic_ns", "cut_drained_monotonic_ns",
                    "activation_monotonic_ns", "ack_published_monotonic_ns",
                    "ack_observed_monotonic_ns", "cut_delivery_duration_ns",
                    "cut_drain_duration_ns", "ack_gate_duration_ns",
                }),
                "boundary stats",
            )
            result.boundary_epoch_stats.append(BoundaryEpochStatsResult(
                boundary_id=wire_string(bt["boundary_id"]),
                boundary_index=wire_uint(
                    bt["boundary_index"], bits=32
                ),
                from_stage_instance_index=wire_uint(
                    bt["from_stage_instance_index"], bits=32
                ),
                to_stage_instance_index=wire_uint(
                    bt["to_stage_instance_index"], bits=32
                ),
                sender_worker_index=wire_uint(
                    bt["sender_worker_index"], bits=32
                ),
                receiver_worker_index=wire_uint(
                    bt["receiver_worker_index"], bits=32
                ),
                from_region_id=wire_int32(bt["from_region_id"]),
                to_region_id=wire_int32(bt["to_region_id"]),
                data_ring_capacity=wire_uint(
                    bt["data_ring_capacity"], bits=32
                ),
                future_output_hold_capacity=wire_uint(
                    bt["future_output_hold_capacity"], bits=32
                ),
                data_enqueued_sequence=wire_uint(
                    bt["data_enqueued_sequence"]
                ),
                data_dequeued_sequence=wire_uint(
                    bt["data_dequeued_sequence"]
                ),
                data_backpressure_events=wire_uint(
                    bt["data_backpressure_events"]
                ),
                pending_cut_epoch=_wire_optional_uint(
                    bt, "pending_cut_epoch"
                ),
                pending_cut_sequence=_wire_optional_uint(
                    bt, "pending_cut_sequence"
                ),
                pending_ack_epoch=_wire_optional_uint(
                    bt, "pending_ack_epoch"
                ),
                pending_ack_sequence=_wire_optional_uint(
                    bt, "pending_ack_sequence"
                ),
                transition_generation=_wire_optional_uint(
                    bt, "transition_generation"
                ),
                from_epoch=_wire_optional_uint(bt, "from_epoch"),
                to_epoch=_wire_optional_uint(bt, "to_epoch"),
                cut_sequence=_wire_optional_uint(bt, "cut_sequence"),
                sender_phase=wire_enum(
                    bt["sender_phase"], _SENDER_PHASES
                ),
                receiver_phase=wire_enum(
                    bt["receiver_phase"], _RECEIVER_PHASES
                ),
                duplicate_cut_count=wire_uint(
                    bt["duplicate_cut_count"]
                ),
                duplicate_ack_count=wire_uint(
                    bt["duplicate_ack_count"]
                ),
                cut_published_monotonic_ns=_wire_optional_uint(
                    bt, "cut_published_monotonic_ns"
                ),
                cut_observed_monotonic_ns=_wire_optional_uint(
                    bt, "cut_observed_monotonic_ns"
                ),
                cut_drained_monotonic_ns=_wire_optional_uint(
                    bt, "cut_drained_monotonic_ns"
                ),
                activation_monotonic_ns=_wire_optional_uint(
                    bt, "activation_monotonic_ns"
                ),
                ack_published_monotonic_ns=_wire_optional_uint(
                    bt, "ack_published_monotonic_ns"
                ),
                ack_observed_monotonic_ns=_wire_optional_uint(
                    bt, "ack_observed_monotonic_ns"
                ),
                cut_delivery_duration_ns=_wire_optional_uint(
                    bt, "cut_delivery_duration_ns"
                ),
                cut_drain_duration_ns=_wire_optional_uint(
                    bt, "cut_drain_duration_ns"
                ),
                ack_gate_duration_ns=_wire_optional_uint(
                    bt, "ack_gate_duration_ns"
                ),
            ))

        for rs in _wire_object_list(
            telemetry["regions"] if "regions" in telemetry else []
        ):
            rs = message_shape(
                rs,
                frozenset({
                    "region_id", "worker_count", "minimum_active_epoch",
                    "maximum_active_epoch", "minimum_source_epoch",
                    "maximum_source_epoch", "active_unretired", "future_unretired",
                    "activated_participants", "fanout_overflow",
                }),
                frozenset({
                    "minimum_activation_monotonic_ns",
                    "maximum_activation_monotonic_ns",
                }),
                "region stats",
            )
            result.region_epoch_stats.append(RegionEpochStatsResult(
                region_id=wire_int32(rs["region_id"]),
                worker_count=wire_uint(rs["worker_count"], bits=32),
                minimum_active_epoch=wire_uint(
                    rs["minimum_active_epoch"]
                ),
                maximum_active_epoch=wire_uint(
                    rs["maximum_active_epoch"]
                ),
                minimum_source_epoch=wire_uint(
                    rs["minimum_source_epoch"]
                ),
                maximum_source_epoch=wire_uint(
                    rs["maximum_source_epoch"]
                ),
                active_unretired=wire_uint(rs["active_unretired"]),
                future_unretired=wire_uint(rs["future_unretired"]),
                activated_participants=wire_uint(
                    rs["activated_participants"], bits=32
                ),
                minimum_activation_monotonic_ns=_wire_optional_uint(
                    rs, "minimum_activation_monotonic_ns"
                ),
                maximum_activation_monotonic_ns=_wire_optional_uint(
                    rs, "maximum_activation_monotonic_ns"
                ),
                fanout_overflow=wire_uint(rs["fanout_overflow"]),
            ))

        for ws in _wire_object_list(
            telemetry["workers"] if "workers" in telemetry else []
        ):
            ws = message_shape(
                ws,
                frozenset({
                    "worker_id", "worker_index", "region_id", "lane_id",
                    "ledger_publication_generation", "active_epoch", "source_epoch",
                    "active_unretired", "future_unretired",
                    "activation_publication_generation", "activation_complete",
                }),
                frozenset({
                    "future_epoch", "transition_generation", "from_epoch", "to_epoch",
                    "activation_monotonic_ns",
                }),
                "worker stats",
            )
            result.worker_epoch_stats.append(WorkerEpochStatsResult(
                worker_id=wire_string(ws["worker_id"]),
                worker_index=wire_uint(
                    ws["worker_index"], bits=32
                ),
                region_id=wire_int32(ws["region_id"]),
                lane_id=wire_string(ws["lane_id"]),
                ledger_publication_generation=wire_uint(
                    ws["ledger_publication_generation"]
                ),
                active_epoch=wire_uint(ws["active_epoch"]),
                source_epoch=wire_uint(ws["source_epoch"]),
                active_unretired=wire_uint(ws["active_unretired"]),
                future_epoch=_wire_optional_uint(ws, "future_epoch"),
                future_unretired=wire_uint(ws["future_unretired"]),
                activation_publication_generation=wire_uint(
                    ws["activation_publication_generation"]
                ),
                transition_generation=_wire_optional_uint(
                    ws, "transition_generation"
                ),
                from_epoch=_wire_optional_uint(ws, "from_epoch"),
                to_epoch=_wire_optional_uint(ws, "to_epoch"),
                activation_monotonic_ns=_wire_optional_uint(
                    ws, "activation_monotonic_ns"
                ),
                activation_complete=_wire_bool(
                    ws["activation_complete"]
                ),
            ))

        for ss in _wire_object_list(
            telemetry["streams"] if "streams" in telemetry else []
        ):
            ss = message_shape(
                ss,
                frozenset({
                    "io_stream_id", "logical_port_id", "direction", "owning_region_id",
                    "worker_index", "driver_queue_id", "published_monotonic_ns",
                    "packets", "bytes", "rejected_packets",
                }),
                frozenset(),
                "stream stats",
            )
            result.stream_stats.append(StreamStatsResult(
                io_stream_id=wire_string(ss["io_stream_id"]),
                logical_port_id=wire_uint(
                    ss["logical_port_id"], bits=32
                ),
                direction=_stream_direction(ss["direction"]),
                owning_region_id=wire_int32(ss["owning_region_id"]),
                worker_index=wire_uint(
                    ss["worker_index"], bits=32
                ),
                driver_queue_id=wire_uint(
                    ss["driver_queue_id"], bits=32
                ),
                published_monotonic_ns=wire_uint(ss["published_monotonic_ns"]),
                packets=wire_uint(ss["packets"]),
                bytes=wire_uint(ss["bytes"]),
                rejected_packets=wire_uint(ss["rejected_packets"]),
            ))

        for storage in _wire_object_list(
            telemetry["storage_domains"] if "storage_domains" in telemetry else []
        ):
            storage = message_shape(
                storage,
                frozenset({
                    "storage_domain_id", "buffer_count", "required_min_buffers",
                    "safety_margin", "observation_state",
                }),
                frozenset({"host_numa_node", "observed_monotonic_ns", "in_use", "available"}),
                "storage-domain stats",
            )
            result.storage_domain_stats.append(StorageDomainStatsResult(
                storage_domain_id=wire_string(
                    storage["storage_domain_id"]
                ),
                host_numa_node=(
                    wire_int32(storage["host_numa_node"])
                    if "host_numa_node" in storage else None
                ),
                buffer_count=wire_uint(storage["buffer_count"]),
                required_min_buffers=wire_uint(
                    storage["required_min_buffers"]
                ),
                safety_margin=wire_uint(
                    storage["safety_margin"], bits=32
                ),
                observation_state=wire_enum(
                    storage["observation_state"],
                    _PROVIDER_OBSERVATION_STATES,
                ),
                observed_monotonic_ns=_wire_optional_uint(
                    storage, "observed_monotonic_ns"
                ),
                in_use=_wire_optional_uint(storage, "in_use"),
                available=_wire_optional_uint(storage, "available"),
            ))

        for ps in _wire_object_list(
            telemetry["ports"] if "ports" in telemetry else []
        ):
            ps = message_shape(
                ps,
                frozenset({
                    "logical_port_id", "logical_name", "io_driver_instance_id",
                    "driver_port_id", "observation_state",
                }),
                frozenset({
                    "observed_monotonic_ns", "rx_packets", "tx_packets", "rx_bytes",
                    "tx_bytes", "rx_missed", "rx_errors", "tx_errors", "rx_no_buffer",
                }),
                "port stats",
            )
            result.port_stats.append(PortStatsResult(
                logical_port_id=wire_uint(
                    ps["logical_port_id"], bits=32
                ),
                logical_name=wire_string(ps["logical_name"]),
                io_driver_instance_id=wire_string(
                    ps["io_driver_instance_id"]
                ),
                driver_port_id=wire_string(ps["driver_port_id"]),
                observation_state=wire_enum(
                    ps["observation_state"],
                    _PROVIDER_OBSERVATION_STATES,
                ),
                observed_monotonic_ns=_wire_optional_uint(
                    ps, "observed_monotonic_ns"
                ),
                rx_packets=_wire_optional_uint(ps, "rx_packets"),
                tx_packets=_wire_optional_uint(ps, "tx_packets"),
                rx_bytes=_wire_optional_uint(ps, "rx_bytes"),
                tx_bytes=_wire_optional_uint(ps, "tx_bytes"),
                rx_missed=_wire_optional_uint(ps, "rx_missed"),
                rx_errors=_wire_optional_uint(ps, "rx_errors"),
                tx_errors=_wire_optional_uint(ps, "tx_errors"),
                rx_no_buffer=_wire_optional_uint(ps, "rx_no_buffer"),
            ))

        for ts in _wire_object_list(
            telemetry["steering_profiles"] if "steering_profiles" in telemetry else []
        ):
            ts = message_shape(
                ts,
                frozenset({
                    "steering_profile_id", "kind", "symmetric", "io_stream_ids",
                }),
                context="traffic-steering stats",
            )
            result.traffic_steering_stats.append(TrafficSteeringStatsResult(
                steering_profile_id=wire_string(
                    ts["steering_profile_id"]
                ),
                kind=_steering_kind(ts["kind"]),
                symmetric=_wire_bool(ts["symmetric"]),
                io_stream_ids=_wire_string_list(ts["io_stream_ids"]),
            ))

        for domain in _wire_object_list(
            telemetry["module_context_domains"] if "module_context_domains" in telemetry else []
        ):
            domain = message_shape(
                domain,
                frozenset({"module_id", "context_instance_ids"}),
                context="module-context domain",
            )
            result.module_context_domains.append(ModuleContextDomainResult(
                module_id=wire_string(domain["module_id"]),
                context_instance_ids=_wire_string_list(domain["context_instance_ids"]),
            ))

        if not stats_are_exact(result):
            raise ValueError("statistics response lacks exact required identity")

    except (JsonContractError, KeyError, AttributeError, TypeError, ValueError):
        return StatsResult(success=False)

    return result


_SUCCESS_STATUS_OPTIONAL_KEYS = frozenset({"code", "message", "details"})


def parse_cli_success(raw_json: str, fields: frozenset[str], context: str) -> dict:
    """Parse one exact protobuf-JSON success response from kinetumctl."""
    response = parse_exact_json_object(raw_json, context)
    require_exact_keys(response, fields | {"status"}, context)
    status = require_object(response["status"], f"{context} status")
    require_key_contract(
        status,
        {"error_code"},
        _SUCCESS_STATUS_OPTIONAL_KEYS,
        f"{context} status",
    )
    code_ok = "code" not in status or wire_int32(status["code"]) == 0
    error_ok = (
        require_string(status["error_code"], f"{context} error_code")
        == "ERROR_CODE_OK"
    )
    diagnostic_values = [
        require_string(
            status[field], f"{context} status {field}", allow_empty=True
        )
        for field in ("message", "details")
        if field in status
    ]
    if not code_ok or not error_ok or any(diagnostic_values):
        raise JsonContractError(f"{context} status is not canonical success")
    return response


def protobuf_uint64(value: object, context: str) -> int:
    """Parse one canonical protobuf-JSON uint64 decimal string."""
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise JsonContractError(f"{context} must be a canonical uint64 string")
    parsed = int(value)
    if parsed > _UINT64_MAX:
        raise JsonContractError(f"{context} exceeds uint64")
    return parsed


def protobuf_int64(value: object, context: str) -> int:
    """Parse one canonical protobuf-JSON int64 decimal string."""
    if (
        not isinstance(value, str)
        or value == "-0"
        or not re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value)
    ):
        raise JsonContractError(f"{context} must be a canonical int64 string")
    parsed = int(value)
    if parsed < -(1 << 63) or parsed > (1 << 63) - 1:
        raise JsonContractError(f"{context} exceeds int64")
    return parsed


def read_snapshot_id(value: object, context: str) -> str:
    """Parse one bounded UTF-8 snapshot identity without path semantics."""
    identity = require_string(value, context)
    try:
        encoded = identity.encode("utf-8")
    except UnicodeError as exc:
        raise JsonContractError(f"{context} is not valid UTF-8") from exc
    if len(encoded) > 256:
        raise JsonContractError(f"{context} is outside the snapshot-ID domain")
    return identity
