"""Validate runtime telemetry identity, lifecycle ordering, and cross-row conservation."""

from __future__ import annotations

from typing import List, Optional, Tuple

from .telemetry import (
    _PROTOCOL_FAULT_CODES,
    _FAIL_STOP_FAILURE_CODES,
    _UINT16_MAX,
    _UINT32_MAX,
    _UINT64_MAX,
    _MAX_EPOCH_ID,
    _MAX_MUTATION_SEQUENCE,
    _MAX_TRANSITION_RESULT_HISTORY_CAPACITY,
    _MAX_CONFIG_SNAPSHOT_REVISION,
    _MODULE_HEALTH_CONTRACT_FAULT_KNOWN_MASK,
    _MODULE_HEALTH_SIGNAL_FLAG_KNOWN_MASK,
    BoundaryEpochStatsResult,
    RegionEpochStatsResult,
    WorkerEpochStatsResult,
    StreamStatsResult,
    StorageDomainStatsResult,
    PortStatsResult,
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


def _provider_values_are_exact(
    state: str,
    values: Tuple[Optional[int], ...],
) -> bool:
    """Return whether provider-value presence exactly matches typed state."""
    present = tuple(value is not None for value in values)
    available = state in {
        "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT",
        "PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE",
    }
    return all(present) if available else not any(present)


def _protocol_disposition_is_exact(code: str, disposition: str) -> bool:
    """Return whether one fault code has its exact immediate disposition."""
    if code == "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED":
        return (
            disposition
            == "EPOCH_PROTOCOL_FAULT_DISPOSITION_RESOURCE_REFUSED"
        )
    if code == "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH":
        return disposition in {
            "EPOCH_PROTOCOL_FAULT_DISPOSITION_DROP_AND_RETIRE",
            "EPOCH_PROTOCOL_FAULT_DISPOSITION_TERMINATE",
        }
    return disposition == "EPOCH_PROTOCOL_FAULT_DISPOSITION_TERMINATE"


def _protocol_identity_shape_is_exact(first: ProtocolFirstFaultResult) -> bool:
    """Return whether one fault code carries its exact compact namespace."""
    worker = first.worker_index != _UINT32_MAX
    boundary = first.boundary_index != _UINT32_MAX
    context = first.context_index != _UINT32_MAX
    stage = first.stage_instance_index != _UINT32_MAX
    if first.code == "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH":
        return worker and (not context or stage) and (not boundary or not context)
    if first.code in {
        "EPOCH_PROTOCOL_FAULT_CODE_OLD_DATA_AFTER_SEAL",
        "EPOCH_PROTOCOL_FAULT_CODE_FUTURE_DATA_BEFORE_ACK",
        "EPOCH_PROTOCOL_FAULT_CODE_CUT_IDENTITY_MISMATCH",
        "EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_ACTIVATION",
        "EPOCH_PROTOCOL_FAULT_CODE_ACK_BEFORE_CUT_DRAIN",
        "EPOCH_PROTOCOL_FAULT_CODE_SEQUENCE_EXHAUSTED",
    }:
        return worker and boundary and not context
    if first.code in {
        "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_UNDERFLOW",
        "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_OVERFLOW",
        "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_DOUBLE_RETIRE",
        "EPOCH_PROTOCOL_FAULT_CODE_OWNERSHIP_WRONG_SLOT",
    }:
        return worker and not boundary and not context and not stage
    return (
        first.code
        in {
            "EPOCH_PROTOCOL_FAULT_CODE_RETIREMENT_BEFORE_QUIESCENCE",
            "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED",
        }
        and not worker
        and not boundary
        and not context
        and not stage
    )


def _unique_nonempty(values: List[str]) -> bool:
    """Return whether one identity family is complete and duplicate-free."""
    return bool(values) and all(values) and len(values) == len(set(values))


def _optional_group_is_exact(values: Tuple[object, ...]) -> bool:
    """Return whether one presence-qualified field group is all absent/present."""
    present = tuple(value is not None for value in values)
    return not any(present) or all(present)


def _module_metric_identity_is_exact(
    row: ModuleCounterStatsResult | ModuleHistogramStatsResult,
    result: StatsResult,
) -> bool:
    """Require a named metric to belong to one admitted context, worker, and epoch."""
    names_present = bool(row.module_id and row.context_instance_id and row.name)
    return (
        names_present
        and 0 < row.epoch <= _MAX_EPOCH_ID
        and row.context_index < result.module_context_count
        and row.worker_index < result.execution_participant_count
    )


def _module_histogram_is_exact(row: ModuleHistogramStatsResult, result: StatsResult) -> bool:
    """Require distribution presence, percentile order, and saturating sample mass."""
    if not _module_metric_identity_is_exact(row, result):
        return False
    distribution = (row.minimum, row.maximum, row.p50, row.p90, row.p99, row.p999)
    if row.sample_count == 0:
        return row.sample_sum == 0 and all(value is None for value in distribution)
    if any(value is None for value in distribution):
        return False
    minimum, maximum, p50, p90, p99, p999 = distribution
    if not minimum <= p50 <= p90 <= p99 <= p999 <= maximum:
        return False
    lower_mass = minimum * row.sample_count
    upper_mass = maximum * row.sample_count
    if row.sample_sum < lower_mass <= _UINT64_MAX:
        return False
    if lower_mass > _UINT64_MAX and row.sample_sum != _UINT64_MAX:
        return False
    return upper_mass > _UINT64_MAX or row.sample_sum <= upper_mass


def _module_mismatch_is_exact(row: ModuleEpochMismatchStatsResult, result: StatsResult) -> bool:
    """Require the first mismatch identity exactly when its counter is nonzero."""
    if (
        not row.module_id
        or not row.context_instance_id
        or not 0 < row.observation_epoch <= _MAX_EPOCH_ID
        or row.context_index >= result.module_context_count
        or row.worker_index >= result.execution_participant_count
    ):
        return False
    first_fault = (
        row.first_packet_epoch, row.first_active_epoch,
        row.first_stage_instance_index, row.first_region_id,
    )
    if not _optional_group_is_exact(first_fault):
        return False
    if (row.mismatch_count == 0) != (first_fault[0] is None):
        return False
    if first_fault[0] is None:
        return True
    return (
        0 < row.first_packet_epoch <= _MAX_EPOCH_ID
        and 0 < row.first_active_epoch <= _MAX_EPOCH_ID
        and row.first_stage_instance_index <= _UINT16_MAX
        and row.first_region_id >= 0
    )


def _module_health_faults_are_exact(row: ModuleHealthStatsResult) -> bool:
    """Require known fault masks and complete first-fault evidence for a nonzero count."""
    first_fault = (
        row.first_fault_epoch, row.first_fault_timestamp_ns, row.first_fault_duration_ns,
    )
    if not _optional_group_is_exact(first_fault):
        return False
    if (row.contract_fault_count == 0) != (row.first_fault_mask == 0 and first_fault[0] is None):
        return False
    if row.contract_fault_count != 0 and (row.first_fault_mask == 0 or first_fault[0] is None):
        return False
    if row.latest_fault_mask != 0 and row.contract_fault_count == 0:
        return False
    return not (
        row.latest_fault_mask & ~_MODULE_HEALTH_CONTRACT_FAULT_KNOWN_MASK
        or row.first_fault_mask & ~_MODULE_HEALTH_CONTRACT_FAULT_KNOWN_MASK
    )


def _module_health_times_are_exact(row: ModuleHealthStatsResult, result: StatsResult) -> bool:
    """Bound complete health attempts and first-fault observations by collection time."""
    attempt = (row.observation_epoch, row.observed_at_ns, row.callback_duration_ns)
    if not _optional_group_is_exact(attempt):
        return False
    if row.observation_epoch is not None and (
        not 0 < row.observation_epoch <= _MAX_EPOCH_ID
        or not 0 < row.observed_at_ns <= result.collection_monotonic_ns
    ):
        return False
    if row.first_fault_epoch is None:
        return True
    if (
        not 0 < row.first_fault_epoch <= _MAX_EPOCH_ID
        or not 0 < row.first_fault_timestamp_ns <= result.collection_monotonic_ns
        or row.observation_epoch is None
    ):
        return False
    return (
        row.first_fault_epoch <= row.observation_epoch
        and row.first_fault_timestamp_ns <= row.observed_at_ns
    )


def _module_health_signal_is_exact(row: ModuleHealthStatsResult) -> bool:
    """Require all signal fields together, with bounded score, flags, and reason."""
    signal = (row.health_score, row.health_flags, row.reason)
    if not _optional_group_is_exact(signal):
        return False
    if row.health_score is None:
        return True
    return (
        row.health_score <= 100
        and not row.health_flags & ~_MODULE_HEALTH_SIGNAL_FLAG_KNOWN_MASK
        and "\x00" not in row.reason
        and len(row.reason.encode("utf-8")) < 40
    )


def _module_health_publication_is_exact(row: ModuleHealthStatsResult, result: StatsResult) -> bool:
    """Match health availability to its publication, signal, fault, and epoch evidence."""
    if row.state in {
        "MODULE_HEALTH_STATE_CALLBACK_UNAVAILABLE",
        "MODULE_HEALTH_STATE_AWAITING_OBSERVATION",
    }:
        faults_absent = not any((row.contract_fault_count, row.latest_fault_mask, row.first_fault_mask))
        return (
            row.publication_generation == 0
            and row.observation_epoch is None
            and row.health_score is None
            and faults_absent
        )
    if row.state == "MODULE_HEALTH_STATE_SIGNAL_AVAILABLE":
        return (
            row.publication_generation != 0
            and row.observation_epoch == result.active_epoch
            and row.health_score is not None
            and row.latest_fault_mask == 0
        )
    if row.state == "MODULE_HEALTH_STATE_ATTEMPT_SUPPRESSED":
        return (
            row.publication_generation != 0
            and row.observation_epoch == result.active_epoch
            and row.health_score is None
            and row.latest_fault_mask != 0
        )
    return (
        row.state == "MODULE_HEALTH_STATE_STALE_EPOCH"
        and row.publication_generation != 0
        and row.observation_epoch is not None
        and row.health_score is None
        and row.observation_epoch < result.active_epoch
    )


def _module_health_is_exact(row: ModuleHealthStatsResult, result: StatsResult) -> bool:
    """Validate one health row before comparing its context with sibling telemetry."""
    if (
        not row.module_id
        or not row.context_instance_id
        or row.context_index >= result.module_context_count
        or row.worker_index >= result.execution_participant_count
        or row.stage_instance_index > _UINT16_MAX
    ):
        return False
    return (
        _module_health_faults_are_exact(row)
        and _module_health_times_are_exact(row, result)
        and _module_health_signal_is_exact(row)
        and _module_health_publication_is_exact(row, result)
    )


def _module_row_membership_is_exact(result: StatsResult) -> bool:
    """Require complete context membership, unique metric names, and valid row values."""
    module_metric_rows = (
        result.module_counter_stats
        or result.module_histogram_stats
        or result.module_epoch_mismatch_stats
    )
    if module_metric_rows and (
        len(result.module_epoch_mismatch_stats)
        != result.module_context_count
        or [row.context_index for row in result.module_epoch_mismatch_stats]
        != list(range(result.module_context_count))
    ):
        return False
    if result.module_health_stats and (
        len(result.module_health_stats) != result.module_context_count
        or [row.context_index for row in result.module_health_stats]
        != list(range(result.module_context_count))
    ):
        return False
    counter_ids = [
        (row.context_index, row.name) for row in result.module_counter_stats
    ]
    histogram_ids = [
        (row.context_index, row.name) for row in result.module_histogram_stats
    ]
    context_ids = [
        row.context_instance_id for row in result.module_epoch_mismatch_stats
    ]
    if (
        len(counter_ids) != len(set(counter_ids))
        or len(histogram_ids) != len(set(histogram_ids))
        or set(counter_ids) & set(histogram_ids)
        or len(context_ids) != len(set(context_ids))
    ):
        return False
    if any(
        not _module_metric_identity_is_exact(row, result)
        for row in result.module_counter_stats
    ):
        return False
    if any(not _module_histogram_is_exact(row, result) for row in result.module_histogram_stats):
        return False
    if any(not _module_mismatch_is_exact(row, result) for row in result.module_epoch_mismatch_stats):
        return False
    return True


def _module_metric_contexts_are_exact(result: StatsResult) -> bool:
    """Match metric context and epoch identity to the mismatch publication."""
    if result.module_epoch_mismatch_stats:
        identities = result.module_epoch_mismatch_stats
        for row in (
            list(result.module_counter_stats)
            + list(result.module_histogram_stats)
        ):
            if row.context_index >= len(identities):
                return False
            identity = identities[row.context_index]
            if (
                row.module_id != identity.module_id
                or row.context_instance_id != identity.context_instance_id
                or row.worker_index != identity.worker_index
                or row.epoch != identity.observation_epoch
            ):
                return False
    return True


def _module_health_rows_are_exact(result: StatsResult) -> bool:
    """Require unique health contexts and equality with their module identity rows."""
    health_identities = [
        row.context_instance_id for row in result.module_health_stats
    ]
    if len(health_identities) != len(set(health_identities)):
        return False
    for row in result.module_health_stats:
        if not _module_health_is_exact(row, result):
            return False
        if result.module_epoch_mismatch_stats:
            if row.context_index >= len(result.module_epoch_mismatch_stats):
                return False
            identity = result.module_epoch_mismatch_stats[row.context_index]
            if (
                row.module_id != identity.module_id
                or row.context_instance_id != identity.context_instance_id
                or row.worker_index != identity.worker_index
            ):
                return False
    return True


def _module_rows_are_exact(result: StatsResult) -> bool:
    """Validate module row membership, intrinsic values, and shared context identity."""
    return (
        _module_row_membership_is_exact(result)
        and _module_metric_contexts_are_exact(result)
        and _module_health_rows_are_exact(result)
    )


def _certificate_fault_index_is_exact(
    certificate: EpochCertificateStatsResult,
) -> bool:
    """Return whether a certificate fault selects its declared namespace."""
    if certificate.fault in {
        "EPOCH_CERTIFICATE_FAULT_NONE",
        "EPOCH_CERTIFICATE_FAULT_REQUEST_IDENTITY",
        "EPOCH_CERTIFICATE_FAULT_READER_MEMBERSHIP",
    }:
        return certificate.fault_index == _UINT32_MAX
    if certificate.fault in {
        "EPOCH_CERTIFICATE_FAULT_EXECUTION_MEMBERSHIP",
        "EPOCH_CERTIFICATE_FAULT_EXECUTION_STATE",
    }:
        return certificate.fault_index < certificate.execution_total
    return (
        certificate.fault
        in {
            "EPOCH_CERTIFICATE_FAULT_BOUNDARY_MEMBERSHIP",
            "EPOCH_CERTIFICATE_FAULT_BOUNDARY_STATE",
            "EPOCH_CERTIFICATE_FAULT_CUT_IDENTITY",
        }
        and certificate.fault_index < certificate.boundary_total
    )


def _transition_history_is_exact(result: StatsResult) -> bool:
    """Bind current and terminal transactions to the sampled allocator and runtime identity."""
    active = result.active_transaction
    latest = result.latest_terminal
    for transaction in (active, latest):
        if transaction is None:
            continue
        event_times = (
            transaction.admitted_monotonic_ns,
            transaction.prepared_monotonic_ns,
            transaction.commit_started_monotonic_ns,
            transaction.retiring_started_monotonic_ns,
            transaction.failure_observed_monotonic_ns,
            transaction.terminal_monotonic_ns,
        )
        if any(
            value is not None and value > result.collection_monotonic_ns
            for value in event_times
        ):
            return False
    active_state = result.transition_state in {
        "EPOCH_TRANSITION_STATE_PREPARING",
        "EPOCH_TRANSITION_STATE_PREPARED",
        "EPOCH_TRANSITION_STATE_COMMITTING",
        "EPOCH_TRANSITION_STATE_RETIRING",
    } or (
        result.transition_state == "EPOCH_TRANSITION_STATE_FAILED_STOP"
        and result.transition_target_epoch != 0
    )
    if (
        result.participant_set_frozen != active_state
        or active_state != (active is not None)
    ):
        return False
    if active is not None:
        unfinished = active.outcome == "EPOCH_TRANSITION_OUTCOME_NONE" and active.terminal_monotonic_ns is None
        if (
            not unfinished
            or result.transition_target_epoch != active.to_epoch
            or result.transition_active_epoch != active.from_epoch
            or result.allocated_epoch_high_watermark != active.to_epoch
            or result.mutation_sequence_high_watermark
            != active.mutation_sequence
        ):
            return False
    if (result.terminal_history_size == 0) != (latest is None):
        return False
    if latest is not None:
        if (
            latest.outcome == "EPOCH_TRANSITION_OUTCOME_NONE"
            or latest.to_epoch > result.allocated_epoch_high_watermark
            or latest.mutation_sequence > result.mutation_sequence_high_watermark
        ):
            return False
        if result.transition_state == "EPOCH_TRANSITION_STATE_IDLE" and not _terminal_matches_idle_runtime(
            latest, result
        ):
            return False
        if active is not None and (
            active.mutation_sequence <= latest.mutation_sequence
            or active.to_epoch <= latest.to_epoch
        ):
            return False
    return result.retirement_frozen == (active is not None and active.retirement_frozen)


def _terminal_matches_idle_runtime(latest: EpochTransactionStatsResult, result: StatsResult) -> bool:
    """Match completed or aborted terminal history to the idle active content."""
    if latest.outcome == "EPOCH_TRANSITION_OUTCOME_COMPLETE":
        return (
            latest.to_epoch == result.transition_active_epoch
            and latest.validation_hash == result.transition_active_validation_hash
        )
    return (
        latest.outcome == "EPOCH_TRANSITION_OUTCOME_ABORTED"
        and latest.from_epoch == result.transition_active_epoch
    )


def _transition_phase_is_exact(result: StatsResult) -> bool:
    """Require exactly the preparation and failure evidence owned by the active phase."""
    active = result.active_transaction
    if active is not None:
        phase = result.transition_state
        failure_none = (
            active.failure_code == "EPOCH_TRANSITION_FAILURE_CODE_NONE"
        )
        if phase == "EPOCH_TRANSITION_STATE_PREPARING":
            phase_exact = (
                active.prepared_monotonic_ns is None
                and active.prepared_lease_deadline_monotonic_ns is None
                and active.commit_started_monotonic_ns is None
                and active.retiring_started_monotonic_ns is None
                and failure_none
            )
        elif phase == "EPOCH_TRANSITION_STATE_PREPARED":
            phase_exact = (
                active.prepared_monotonic_ns is not None
                and active.prepared_lease_deadline_monotonic_ns is not None
                and active.commit_started_monotonic_ns is None
                and active.retiring_started_monotonic_ns is None
                and failure_none
            )
        elif phase == "EPOCH_TRANSITION_STATE_COMMITTING":
            phase_exact = (
                active.prepared_monotonic_ns is not None
                and active.prepared_lease_deadline_monotonic_ns is None
                and active.commit_started_monotonic_ns is not None
                and active.retiring_started_monotonic_ns is None
                and failure_none
            )
        elif phase == "EPOCH_TRANSITION_STATE_RETIRING":
            phase_exact = (
                active.prepared_monotonic_ns is not None
                and active.prepared_lease_deadline_monotonic_ns is None
                and active.commit_started_monotonic_ns is not None
                and active.retiring_started_monotonic_ns is not None
                and (
                    failure_none
                    or (
                        active.retirement_frozen
                        and active.failure_code
                        == "EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED"
                    )
                )
            )
        else:
            phase_exact = (
                phase == "EPOCH_TRANSITION_STATE_FAILED_STOP"
                and active.failure_code in _FAIL_STOP_FAILURE_CODES
                and active.failure_observed_monotonic_ns is not None
            )
        if not phase_exact:
            return False
    return True


def _transition_runtime_is_exact(result: StatsResult) -> bool:
    """Match active and retained epochs plus grace presence to the transition phase."""
    active = result.active_transaction
    stable_runtime = (
        result.transition_active_epoch == result.active_epoch
        and result.minimum_retained_epoch == result.active_epoch
    )
    retiring_runtime = (
        result.active_epoch == result.transition_target_epoch
        and result.minimum_retained_epoch == result.transition_active_epoch
    )
    phase = result.transition_state
    if phase == "EPOCH_TRANSITION_STATE_IDLE":
        runtime_exact = stable_runtime and result.transition_target_epoch == 0 and not result.retirement_frozen
    elif phase in {
        "EPOCH_TRANSITION_STATE_PREPARING",
        "EPOCH_TRANSITION_STATE_PREPARED",
        "EPOCH_TRANSITION_STATE_COMMITTING",
    }:
        runtime_exact = stable_runtime
    elif phase == "EPOCH_TRANSITION_STATE_RETIRING":
        runtime_exact = retiring_runtime
    else:
        runtime_exact = phase == "EPOCH_TRANSITION_STATE_FAILED_STOP" and (stable_runtime or retiring_runtime)
    if not runtime_exact:
        return False
    committed_phase = result.transition_state in {
        "EPOCH_TRANSITION_STATE_COMMITTING",
        "EPOCH_TRANSITION_STATE_RETIRING",
    }
    active_commit_started = (
        active is not None and active.commit_started_monotonic_ns is not None
    )
    if (
        committed_phase != active_commit_started
        and result.transition_state != "EPOCH_TRANSITION_STATE_FAILED_STOP"
    ) or (active_commit_started and result.grace is None):
        return False
    return True


def _transition_certificate_is_exact(result: StatsResult) -> bool:
    """Validate certificate counts, state, owner identity, and observation time."""
    active = result.active_transaction
    latest = result.latest_terminal
    active_commit_started = (
        active is not None and active.commit_started_monotonic_ns is not None
    )
    certificate = result.certificate
    if certificate is not None:
        if (
            not 0 < certificate.evaluated_monotonic_ns <= result.collection_monotonic_ns
            or certificate.runtime_generation != result.runtime_generation
            or not 0 < certificate.transition_generation <= _MAX_MUTATION_SEQUENCE
            or not 0 < certificate.from_epoch < certificate.to_epoch <= _MAX_EPOCH_ID
        ):
            return False
        populations = (
            (certificate.execution_complete, certificate.execution_total, result.execution_participant_count),
            (certificate.boundary_complete, certificate.boundary_total, result.boundary_count),
            (certificate.reader_complete, certificate.reader_total, result.quiescence_reader_count),
        )
        if any(completed > total or total != expected for completed, total, expected in populations):
            return False
        if not _certificate_state_is_exact(certificate):
            return False
        matches_active = active is not None and (
            certificate.transition_generation == active.mutation_sequence
            and certificate.from_epoch == active.from_epoch
            and certificate.to_epoch == active.to_epoch
        )
        matches_terminal = latest is not None and (
            certificate.transition_generation == latest.mutation_sequence
            and certificate.from_epoch == latest.from_epoch
            and certificate.to_epoch == latest.to_epoch
        )
        if (
            not matches_active
            and not matches_terminal
        ) or (active_commit_started and not matches_active):
            return False
        owner = active if matches_active else latest
        if owner is None or (
            certificate.evaluated_monotonic_ns < owner.admitted_monotonic_ns
            or (
                owner.commit_started_monotonic_ns is not None
                and certificate.evaluated_monotonic_ns
                < owner.commit_started_monotonic_ns
            )
        ):
            return False
    return True


def _certificate_state_is_exact(certificate: EpochCertificateStatsResult) -> bool:
    """Require typed certificate progress to agree with its exact completion populations."""
    contradictory = certificate.state == "EPOCH_CERTIFICATE_STATE_CONTRADICTION"
    faulted = certificate.fault != "EPOCH_CERTIFICATE_FAULT_NONE"
    if contradictory != faulted or not _certificate_fault_index_is_exact(certificate):
        return False
    execution_complete = (
        certificate.execution_complete == certificate.execution_total
        and certificate.boundary_complete == certificate.boundary_total
    )
    if certificate.state == "EPOCH_CERTIFICATE_STATE_INCOMPLETE":
        return not execution_complete
    if certificate.state == "EPOCH_CERTIFICATE_STATE_EXECUTION_COMPLETE":
        return execution_complete and certificate.reader_complete != certificate.reader_total
    if certificate.state == "EPOCH_CERTIFICATE_STATE_RECLAMATION_READY":
        return execution_complete and certificate.reader_complete == certificate.reader_total
    return contradictory


def _transition_grace_is_exact(result: StatsResult) -> bool:
    """Bind reader grace to its committing transaction and terminal completion evidence."""
    active = result.active_transaction
    latest = result.latest_terminal
    active_commit_started = (
        active is not None and active.commit_started_monotonic_ns is not None
    )
    grace = result.grace
    if grace is not None:
        owner = (
            active
            if active is not None
            and active.commit_started_monotonic_ns is not None
            else latest
            if latest is not None
            and latest.commit_started_monotonic_ns is not None
            else None
        )
        if (
            grace.generation <= 0
            or grace.started_monotonic_ns is None
            or not 0 < grace.started_monotonic_ns <= result.collection_monotonic_ns
        ):
            return False
        if (
            grace.readers_complete > grace.readers_total
            or grace.readers_total != result.quiescence_reader_count
            or grace.active == (grace.finished_monotonic_ns is not None)
        ):
            return False
        completion = grace.completion_observed_monotonic_ns
        if completion is not None and (
            not grace.started_monotonic_ns <= completion <= result.collection_monotonic_ns
            or grace.readers_complete != grace.readers_total
        ):
            return False
        if grace.finished_monotonic_ns is not None and (
            completion is None
            or not completion <= grace.finished_monotonic_ns <= result.collection_monotonic_ns
        ):
            return False
        if not _grace_state_is_exact(grace, result):
            return False
        if active_commit_started and not grace.active:
            return False
        if owner is None or grace.started_monotonic_ns != owner.commit_started_monotonic_ns:
            return False
    return True


def _grace_state_is_exact(grace: EpochGraceStatsResult, result: StatsResult) -> bool:
    """Require live grace to belong to a committed phase and retired grace to a completed transaction."""
    if grace.update_frozen and (not grace.active or not result.retirement_frozen):
        return False
    if grace.active:
        return result.transition_state in {
            "EPOCH_TRANSITION_STATE_COMMITTING",
            "EPOCH_TRANSITION_STATE_RETIRING",
            "EPOCH_TRANSITION_STATE_FAILED_STOP",
        }
    return result.latest_terminal is not None and result.latest_terminal.outcome == "EPOCH_TRANSITION_OUTCOME_COMPLETE"


def _transition_is_exact(result: StatsResult) -> bool:
    """Validate transaction history, phase, runtime, certificate, and reader grace in order."""
    return (
        _transition_history_is_exact(result)
        and _transition_phase_is_exact(result)
        and _transition_runtime_is_exact(result)
        and _transition_certificate_is_exact(result)
        and _transition_grace_is_exact(result)
    )


def _protocol_faults_are_exact(result: StatsResult) -> bool:
    """Validate typed counters, first-fault identity, and success-block state."""
    if set(result.protocol_fault_counts) != _PROTOCOL_FAULT_CODES:
        return False
    blocking_fault = any(
        count != 0
        for code, count in result.protocol_fault_counts.items()
        if code
        != "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_ALLOCATOR_EXHAUSTED"
    )
    any_fault = any(result.protocol_fault_counts.values())
    first = result.first_protocol_fault
    if any_fault != (first is not None):
        return False
    if first is None:
        return not result.transition_success_blocked
    transition_identity_exact = (
        (
            first.transition_generation == 0
            and (first.from_epoch == 0 or first.from_epoch <= _MAX_EPOCH_ID)
            and (first.to_epoch == 0 or first.to_epoch <= _MAX_EPOCH_ID)
            and (
                first.from_epoch == 0
                or first.to_epoch == 0
                or first.to_epoch > first.from_epoch
            )
        )
        or (
            0 < first.transition_generation <= _MAX_MUTATION_SEQUENCE
            and 0 < first.from_epoch < first.to_epoch <= _MAX_EPOCH_ID
        )
    )
    return (
        result.transition_success_blocked == blocking_fault
        and first.runtime_generation == result.runtime_generation
        and first.observed_monotonic_ns > 0
        and first.observed_monotonic_ns <= result.collection_monotonic_ns
        and first.code in result.protocol_fault_counts
        and result.protocol_fault_counts[first.code] != 0
        and transition_identity_exact
        and _protocol_identity_shape_is_exact(first)
        and _protocol_disposition_is_exact(first.code, first.disposition)
        and (
            first.worker_index == _UINT32_MAX
            or first.worker_index < result.execution_participant_count
        )
        and (
            first.boundary_index == _UINT32_MAX
            or first.boundary_index < result.boundary_count
        )
        and (
            first.context_index == _UINT32_MAX
            or first.context_index < result.module_context_count
        )
        and (
            first.stage_instance_index == _UINT32_MAX
            or first.stage_instance_index <= _UINT16_MAX
        )
        and not (
            first.worker_index == _UINT32_MAX
            and (
                first.boundary_index != _UINT32_MAX
                or first.context_index != _UINT32_MAX
                or first.stage_instance_index != _UINT32_MAX
            )
        )
        and _UINT32_MAX in (
            first.boundary_index,
            first.context_index,
        )
        and not (
            first.context_index != _UINT32_MAX
            and first.stage_instance_index == _UINT32_MAX
        )
    )


def _worker_row_is_exact(row: WorkerEpochStatsResult, result: StatsResult) -> bool:
    """Require complete worker publication, epoch ownership, and activation evidence."""
    if (
        not row.lane_id
        or not 0 <= row.region_id < result.region_count
        or row.ledger_publication_generation <= 0
        or row.activation_publication_generation <= 0
    ):
        return False
    if not 0 < row.active_epoch <= _MAX_EPOCH_ID or not 0 < row.source_epoch <= _MAX_EPOCH_ID:
        return False
    if row.future_epoch is None:
        if row.future_unretired != 0:
            return False
    elif not row.active_epoch < row.future_epoch <= _MAX_EPOCH_ID:
        return False
    if row.source_epoch not in (row.active_epoch, row.future_epoch):
        return False
    activation = (row.transition_generation, row.from_epoch, row.to_epoch, row.activation_monotonic_ns)
    if not _optional_group_is_exact(activation) or row.activation_complete != (activation[0] is not None):
        return False
    if not row.activation_complete:
        return True
    return (
        0 < row.transition_generation <= _MAX_MUTATION_SEQUENCE
        and 0 < row.from_epoch < row.to_epoch <= _MAX_EPOCH_ID
        and 0 < row.activation_monotonic_ns <= result.collection_monotonic_ns
        and row.active_epoch == row.to_epoch
    )


def _worker_transition_is_exact(row: WorkerEpochStatsResult, result: StatsResult) -> bool:
    """Bind worker activation to the current commit or latest completed transaction."""
    active = result.active_transaction
    if active is not None and active.commit_started_monotonic_ns is not None:
        if row.transition_generation is not None and row.transition_generation > active.mutation_sequence:
            return False
        if row.transition_generation == active.mutation_sequence and (
            row.from_epoch != active.from_epoch or row.to_epoch != active.to_epoch
        ):
            return False
        return (
            result.transition_state != "EPOCH_TRANSITION_STATE_RETIRING"
            or row.transition_generation == active.mutation_sequence
        )
    latest = result.latest_terminal
    if latest is None or latest.outcome != "EPOCH_TRANSITION_OUTCOME_COMPLETE":
        return True
    return (row.transition_generation, row.from_epoch, row.to_epoch) == (
        latest.mutation_sequence, latest.from_epoch, latest.to_epoch,
    )


def _worker_rows_are_exact(result: StatsResult) -> bool:
    """Require a complete dense worker population before cross-row indexing."""
    workers = result.worker_epoch_stats
    if not workers:
        return True
    if (
        len(workers) != result.execution_participant_count
        or [row.worker_index for row in workers] != list(range(result.execution_participant_count))
        or not _unique_nonempty([row.worker_id for row in workers])
    ):
        return False
    return all(_worker_row_is_exact(row, result) and _worker_transition_is_exact(row, result) for row in workers)


def _region_row_is_exact(row: RegionEpochStatsResult, result: StatsResult) -> bool:
    """Require bounded epoch extrema and complete region activation timing."""
    if (
        row.worker_count <= 0
        or not 0 < row.minimum_active_epoch <= row.maximum_active_epoch <= _MAX_EPOCH_ID
        or not 0 < row.minimum_source_epoch <= row.maximum_source_epoch <= _MAX_EPOCH_ID
        or row.activated_participants > row.worker_count
    ):
        return False
    timing = (row.minimum_activation_monotonic_ns, row.maximum_activation_monotonic_ns)
    if not _optional_group_is_exact(timing) or (row.activated_participants == 0) != (timing[0] is None):
        return False
    return timing[0] is None or 0 < timing[0] <= timing[1] <= result.collection_monotonic_ns


def _region_rows_are_exact(result: StatsResult) -> bool:
    """Require complete regions and conservation of worker and overflow totals."""
    regions = result.region_epoch_stats
    if not regions:
        return True
    if (
        len(regions) != result.region_count
        or [row.region_id for row in regions] != list(range(result.region_count))
    ):
        return False
    if not all(_region_row_is_exact(row, result) for row in regions):
        return False
    return (
        sum(row.worker_count for row in regions) == result.execution_participant_count
        and min(sum(row.fanout_overflow for row in regions), _UINT64_MAX) == result.fanout_overflow
    )


def _region_matches_workers(region: RegionEpochStatsResult, members: List[WorkerEpochStatsResult]) -> bool:
    """Compare one admitted region with its nonempty exact worker population."""
    if len(members) != region.worker_count:
        return False
    observed_epochs = (
        min(row.active_epoch for row in members), max(row.active_epoch for row in members),
        min(row.source_epoch for row in members), max(row.source_epoch for row in members),
    )
    if observed_epochs != (
        region.minimum_active_epoch, region.maximum_active_epoch,
        region.minimum_source_epoch, region.maximum_source_epoch,
    ):
        return False
    if (
        min(sum(row.active_unretired for row in members), _UINT64_MAX) != region.active_unretired
        or min(sum(row.future_unretired for row in members), _UINT64_MAX) != region.future_unretired
    ):
        return False
    activation_times = [row.activation_monotonic_ns for row in members if row.activation_complete]
    if len(activation_times) != region.activated_participants:
        return False
    return not activation_times or (
        min(activation_times) == region.minimum_activation_monotonic_ns
        and max(activation_times) == region.maximum_activation_monotonic_ns
    )


def _regions_match_workers(result: StatsResult) -> bool:
    """Compare admitted dense region and worker populations in linear time."""
    if not result.worker_epoch_stats or not result.region_epoch_stats:
        return True
    members = [[] for _ in result.region_epoch_stats]
    for worker in result.worker_epoch_stats:
        members[worker.region_id].append(worker)
    return all(_region_matches_workers(region, members[region.region_id]) for region in result.region_epoch_stats)


def _boundary_identity_is_exact(row: BoundaryEpochStatsResult, result: StatsResult) -> bool:
    """Admit endpoint indices, ring capacities, and bounded DATA sequences before use."""
    if (
        not 0 <= row.from_region_id < result.region_count
        or not 0 <= row.to_region_id < result.region_count
        or row.sender_worker_index >= result.execution_participant_count
        or row.receiver_worker_index >= result.execution_participant_count
        or row.sender_worker_index == row.receiver_worker_index
    ):
        return False
    if any(capacity < 2 or capacity & (capacity - 1) for capacity in (
        row.data_ring_capacity, row.future_output_hold_capacity,
    )):
        return False
    return (
        row.data_enqueued_sequence != _UINT64_MAX
        and row.data_dequeued_sequence != _UINT64_MAX
        and row.data_dequeued_sequence <= row.data_enqueued_sequence
    )


def _pending_control_is_exact(epoch: Optional[int], sequence: Optional[int], data_sequence: int) -> bool:
    """Admit a complete pending control pair bounded by its owning DATA sequence."""
    if (epoch is None) != (sequence is None):
        return False
    if epoch is None:
        return True
    return 0 < epoch <= _MAX_EPOCH_ID and sequence != _UINT64_MAX and sequence <= data_sequence


def _boundary_transition_identity_is_exact(row: BoundaryEpochStatsResult) -> bool:
    """Admit optional transition identity and the CUT sequence it authorizes."""
    transition = (row.transition_generation, row.from_epoch, row.to_epoch)
    if not _optional_group_is_exact(transition):
        return False
    if row.transition_generation is not None and (
        not 0 < row.transition_generation <= _MAX_MUTATION_SEQUENCE
        or not 0 < row.from_epoch < row.to_epoch <= _MAX_EPOCH_ID
    ):
        return False
    return row.cut_sequence is None or (
        row.transition_generation is not None and row.cut_sequence != _UINT64_MAX
    )


def _boundary_times_are_exact(row: BoundaryEpochStatsResult, result: StatsResult) -> bool:
    """Require transition-qualified timestamps to form one bounded causal prefix."""
    times = (
        row.cut_published_monotonic_ns, row.cut_observed_monotonic_ns,
        row.cut_drained_monotonic_ns, row.activation_monotonic_ns,
        row.ack_published_monotonic_ns, row.ack_observed_monotonic_ns,
    )
    if any(value is not None for value in times) and row.transition_generation is None:
        return False
    if any(value is not None and not 0 < value <= result.collection_monotonic_ns for value in times):
        return False
    return all(
        current is None or (previous is not None and previous <= current)
        for previous, current in zip(times, times[1:])
    )


def _boundary_sender_is_exact(row: BoundaryEpochStatsResult) -> bool:
    """Match sender phase to CUT ownership, publication, and ACK consumption."""
    has_cut = row.sender_phase in {
        "BOUNDARY_SENDER_PHASE_CUT_PENDING", "BOUNDARY_SENDER_PHASE_WAITING_ACK", "BOUNDARY_SENDER_PHASE_OPEN",
    }
    if row.sender_phase != "BOUNDARY_SENDER_PHASE_DRAINING" and not has_cut:
        return False
    if (row.cut_sequence is not None) != has_cut:
        return False
    if has_cut and row.cut_sequence > row.data_enqueued_sequence:
        return False
    cut_published = row.sender_phase in {"BOUNDARY_SENDER_PHASE_WAITING_ACK", "BOUNDARY_SENDER_PHASE_OPEN"}
    ack_observed = row.sender_phase == "BOUNDARY_SENDER_PHASE_OPEN"
    presence = (
        (row.pending_cut_epoch, row.sender_phase == "BOUNDARY_SENDER_PHASE_CUT_PENDING"),
        (row.cut_published_monotonic_ns, cut_published),
        (row.ack_observed_monotonic_ns, ack_observed),
    )
    if any((value is not None) != required for value, required in presence):
        return False
    if row.pending_cut_epoch is not None and (
        row.pending_cut_epoch != row.to_epoch or row.pending_cut_sequence != row.cut_sequence
    ):
        return False
    return row.duplicate_ack_count == 0 or ack_observed


def _boundary_phase_pair_is_exact(row: BoundaryEpochStatsResult) -> bool:
    """Require receiver progress to be reachable from the admitted sender phase."""
    if row.sender_phase in {"BOUNDARY_SENDER_PHASE_DRAINING", "BOUNDARY_SENDER_PHASE_CUT_PENDING"}:
        return row.receiver_phase == "BOUNDARY_RECEIVER_PHASE_WAITING_CUT"
    if row.sender_phase == "BOUNDARY_SENDER_PHASE_WAITING_ACK":
        return True
    return row.sender_phase == "BOUNDARY_SENDER_PHASE_OPEN" and row.receiver_phase in {
        "BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED", "BOUNDARY_RECEIVER_PHASE_OPEN",
    }


def _boundary_receiver_is_exact(row: BoundaryEpochStatsResult) -> bool:
    """Match admitted paired receiver progress to DATA drain, activation, and ACK evidence."""
    has_cut = row.receiver_phase in {
        "BOUNDARY_RECEIVER_PHASE_CUT_DRAINING", "BOUNDARY_RECEIVER_PHASE_CUT_DRAINED",
        "BOUNDARY_RECEIVER_PHASE_ACK_PENDING", "BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED",
        "BOUNDARY_RECEIVER_PHASE_OPEN",
    }
    if row.receiver_phase != "BOUNDARY_RECEIVER_PHASE_WAITING_CUT" and not has_cut:
        return False
    cut_pending = row.receiver_phase == "BOUNDARY_RECEIVER_PHASE_CUT_DRAINING"
    drained_before_ack = row.receiver_phase in {
        "BOUNDARY_RECEIVER_PHASE_CUT_DRAINED", "BOUNDARY_RECEIVER_PHASE_ACK_PENDING",
    }
    ack_published = row.receiver_phase in {"BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED", "BOUNDARY_RECEIVER_PHASE_OPEN"}
    cut_drained = drained_before_ack or ack_published
    activated = row.receiver_phase == "BOUNDARY_RECEIVER_PHASE_ACK_PENDING" or ack_published
    if (
        (cut_pending and row.data_dequeued_sequence >= row.cut_sequence)
        or (drained_before_ack and row.data_dequeued_sequence != row.cut_sequence)
    ):
        return False
    if ack_published and row.data_dequeued_sequence < row.cut_sequence:
        return False
    presence = (
        (row.pending_ack_epoch, row.receiver_phase == "BOUNDARY_RECEIVER_PHASE_ACK_PENDING"),
        (row.cut_observed_monotonic_ns, has_cut),
        (row.cut_drained_monotonic_ns, cut_drained),
        (row.activation_monotonic_ns, activated),
        (row.ack_published_monotonic_ns, ack_published),
    )
    if any((value is not None) != required for value, required in presence):
        return False
    if row.pending_ack_epoch is not None and (
        row.pending_ack_epoch != row.to_epoch or row.pending_ack_sequence != row.cut_sequence
    ):
        return False
    return row.duplicate_cut_count == 0 or has_cut


def _boundary_phase_is_exact(row: BoundaryEpochStatsResult) -> bool:
    """Require a clean steady boundary or one valid paired transition state."""
    if row.transition_generation is None:
        control_absent = all(value is None for value in (
            row.pending_cut_epoch, row.pending_ack_epoch, row.cut_sequence,
        ))
        return (
            row.sender_phase == "BOUNDARY_SENDER_PHASE_OPEN"
            and row.receiver_phase == "BOUNDARY_RECEIVER_PHASE_OPEN"
            and control_absent
            and row.duplicate_cut_count == 0
            and row.duplicate_ack_count == 0
        )
    return (
        _boundary_sender_is_exact(row)
        and _boundary_phase_pair_is_exact(row)
        and _boundary_receiver_is_exact(row)
    )


def _boundary_matches_transaction(row: BoundaryEpochStatsResult, result: StatsResult) -> bool:
    """Bind an observed boundary transition to the current commit or latest completion."""
    if row.transition_generation is None:
        return True
    owner = result.active_transaction
    if owner is None or owner.commit_started_monotonic_ns is None:
        owner = result.latest_terminal
        if owner is None or owner.outcome != "EPOCH_TRANSITION_OUTCOME_COMPLETE":
            return True
    return (row.transition_generation, row.from_epoch, row.to_epoch) == (
        owner.mutation_sequence, owner.from_epoch, owner.to_epoch,
    )


def _boundary_durations_are_exact(row: BoundaryEpochStatsResult) -> bool:
    """Require each duration exactly when both admitted endpoint timestamps exist."""
    durations = (
        (row.cut_delivery_duration_ns, row.cut_published_monotonic_ns, row.cut_observed_monotonic_ns),
        (row.cut_drain_duration_ns, row.cut_observed_monotonic_ns, row.cut_drained_monotonic_ns),
        (row.ack_gate_duration_ns, row.cut_published_monotonic_ns, row.ack_observed_monotonic_ns),
    )
    for duration, begin, end in durations:
        if (duration is not None) != (begin is not None and end is not None):
            return False
        if duration is not None and duration != end - begin:
            return False
    return True


def _boundary_row_is_exact(row: BoundaryEpochStatsResult, result: StatsResult) -> bool:
    """Admit boundary structure before phase-dependent indexing and arithmetic."""
    structure_exact = (
        _boundary_identity_is_exact(row, result)
        and _pending_control_is_exact(row.pending_cut_epoch, row.pending_cut_sequence, row.data_enqueued_sequence)
        and _pending_control_is_exact(row.pending_ack_epoch, row.pending_ack_sequence, row.data_dequeued_sequence)
        and _boundary_transition_identity_is_exact(row)
        and _boundary_times_are_exact(row, result)
    )
    if not structure_exact:
        return False
    return (
        _boundary_phase_is_exact(row)
        and _boundary_matches_transaction(row, result)
        and _boundary_durations_are_exact(row)
    )


def _boundary_rows_are_exact(result: StatsResult) -> bool:
    """Require complete boundaries and exact endpoint membership in admitted worker rows."""
    boundaries = result.boundary_epoch_stats
    if not boundaries:
        return True
    if (
        len(boundaries) != result.boundary_count
        or [row.boundary_index for row in boundaries] != list(range(result.boundary_count))
        or not _unique_nonempty([row.boundary_id for row in boundaries])
    ):
        return False
    for row in boundaries:
        if not _boundary_row_is_exact(row, result):
            return False
        workers = result.worker_epoch_stats
        if workers and (
            workers[row.sender_worker_index].region_id != row.from_region_id
            or workers[row.receiver_worker_index].region_id != row.to_region_id
        ):
            return False
    return True


def _worker_region_boundary_rows_are_exact(result: StatsResult) -> bool:
    """Admit each observation family before cross-family conservation and indexing."""
    return (
        _worker_rows_are_exact(result)
        and _region_rows_are_exact(result)
        and _regions_match_workers(result)
        and _boundary_rows_are_exact(result)
    )


def _strictly_increasing_strings(values: List[str]) -> bool:
    """Return whether strings are nonempty, unique, and canonical in order."""
    return bool(values) and all(values) and all(
        left < right for left, right in zip(values, values[1:])
    )


def stream_totals_are_exact(result: StatsResult) -> bool:
    """Check selected stream/engine consistency, not independent delivery evidence."""
    if any(
        row.packets is None or row.bytes is None
        for row in result.stream_stats
    ):
        return False
    for direction, packets, byte_count in (
        ("rx", result.rx_packets, result.rx_bytes),
        ("tx", result.tx_packets, result.tx_bytes),
    ):
        rows = [row for row in result.stream_stats if row.direction == direction]
        packet_total = sum(row.packets for row in rows)
        byte_total = sum(row.bytes for row in rows)
        if (
            packet_total >= _UINT64_MAX or byte_total >= _UINT64_MAX
            or packet_total != packets or byte_total != byte_count
        ):
            return False
    return True


def _stream_row_is_exact(row: StreamStatsResult, result: StatsResult) -> bool:
    """Require owner-published stream identity, counters, and collection bounds."""
    if (
        not row.io_stream_id
        or row.direction not in {"rx", "tx"}
        or not 0 <= row.owning_region_id < result.region_count
        or row.worker_index >= result.execution_participant_count
    ):
        return False
    values = (row.packets, row.bytes, row.rejected_packets)
    if any(value is None or not 0 <= value < _UINT64_MAX for value in values):
        return False
    return (
        0 < row.published_monotonic_ns
        <= min(result.latest_bank_publication_monotonic_ns, result.collection_monotonic_ns)
        and (row.packets == 0) == (row.bytes == 0)
        and row.bytes >= row.packets
    )


def _storage_row_is_exact(row: StorageDomainStatsResult, result: StatsResult) -> bool:
    """Require admitted storage capacity and availability-qualified population conservation."""
    if (
        not row.storage_domain_id
        or not 0 < row.required_min_buffers <= row.buffer_count
        or row.safety_margin <= 0
        or (row.host_numa_node is not None and row.host_numa_node < 0)
    ):
        return False
    values = (row.observed_monotonic_ns, row.in_use, row.available)
    if not _provider_values_are_exact(row.observation_state, values):
        return False
    if row.observed_monotonic_ns is None:
        return True
    return (
        0 < row.observed_monotonic_ns <= result.collection_monotonic_ns
        and row.in_use <= row.buffer_count
        and row.available <= row.buffer_count
        and row.in_use + row.available == row.buffer_count
    )


def _port_row_is_exact(row: PortStatsResult, result: StatsResult) -> bool:
    """Require native port identity and complete availability-qualified counters."""
    values = (
        row.observed_monotonic_ns, row.rx_packets, row.tx_packets,
        row.rx_bytes, row.tx_bytes, row.rx_missed, row.rx_errors,
        row.tx_errors, row.rx_no_buffer,
    )
    if not row.io_driver_instance_id or not row.driver_port_id:
        return False
    if not _provider_values_are_exact(row.observation_state, values):
        return False
    return row.observed_monotonic_ns is None or 0 < row.observed_monotonic_ns <= result.collection_monotonic_ns


def _provider_observations_are_exact(result: StatsResult) -> bool:
    """Admit unique stream, storage, and port observations before resolving references."""
    streams = result.stream_stats
    storage = result.storage_domain_stats
    ports = result.port_stats
    if streams and not _unique_nonempty([row.io_stream_id for row in streams]):
        return False
    if any(not _stream_row_is_exact(row, result) for row in streams):
        return False
    if streams and not stream_totals_are_exact(result):
        return False
    if storage and not _unique_nonempty([row.storage_domain_id for row in storage]):
        return False
    if any(not _storage_row_is_exact(row, result) for row in storage):
        return False
    port_ids = [row.logical_port_id for row in ports]
    if ports and (
        len(port_ids) != len(set(port_ids))
        or not _unique_nonempty([row.logical_name for row in ports])
    ):
        return False
    if any(not _port_row_is_exact(row, result) for row in ports):
        return False
    known_ports = set(port_ids)
    return not (streams and ports) or all(row.logical_port_id in known_ports for row in streams)


def _module_context_domains_are_exact(result: StatsResult) -> bool:
    """Require canonical populations and agreement with selected context observations."""
    domains = result.module_context_domains
    if not domains:
        return True
    if not _strictly_increasing_strings([row.module_id for row in domains]):
        return False
    contexts = {}
    for domain in domains:
        if not _strictly_increasing_strings(domain.context_instance_ids):
            return False
        for identity in domain.context_instance_ids:
            if identity in contexts:
                return False
            contexts[identity] = domain.module_id
    if len(contexts) != result.module_context_count:
        return False
    observations = result.module_epoch_mismatch_stats + result.module_health_stats
    return all(contexts.get(row.context_instance_id) == row.module_id for row in observations)


def _provider_topology_references_are_exact(result: StatsResult) -> bool:
    """Require exact steering references and independent module-context membership."""
    steering = result.traffic_steering_stats
    if steering and not _unique_nonempty([row.steering_profile_id for row in steering]):
        return False
    known_streams = {row.io_stream_id for row in result.stream_stats}
    for row in steering:
        if not row.steering_profile_id or not _strictly_increasing_strings(row.io_stream_ids):
            return False
        if known_streams and any(stream_id not in known_streams for stream_id in row.io_stream_ids):
            return False
    return _module_context_domains_are_exact(result)


def _provider_topology_rows_are_exact(result: StatsResult) -> bool:
    """Validate provider observations before cross-row topology references."""
    return _provider_observations_are_exact(result) and _provider_topology_references_are_exact(result)


def _runtime_frame_is_exact(result: StatsResult) -> bool:
    """Require active configuration identity, packet ownership, and publication timing."""
    if (
        not result.active_snapshot_id
        or not 0 <= result.active_revision <= _MAX_CONFIG_SNAPSHOT_REVISION
        or not 0 < result.active_epoch <= _MAX_EPOCH_ID
        or not 0 < result.runtime_generation <= _UINT32_MAX
    ):
        return False
    if (
        not 0 < result.minimum_retained_epoch <= result.active_epoch
        or result.last_activated_epoch != result.active_epoch
        or result.active_workers <= 0
        or result.active_workers != result.expected_workers
    ):
        return False
    return (
        result.status_publication_generation > 0
        and 0 < result.latest_bank_publication_monotonic_ns <= result.collection_monotonic_ns
    )


def _transition_publication_is_exact(result: StatsResult) -> bool:
    """Bound the coordinator's epoch allocation and exact publication identity."""
    return (
        result.transition_publication_generation > 0
        and 0 < result.transition_active_epoch <= _MAX_EPOCH_ID
        and result.transition_target_epoch <= _MAX_EPOCH_ID
        and result.transition_active_epoch <= result.allocated_epoch_high_watermark <= _MAX_EPOCH_ID
        and 0 < result.mutation_sequence_high_watermark <= _MAX_MUTATION_SEQUENCE
    )


def _participant_counts_are_exact(result: StatsResult) -> bool:
    """Require nonempty participant populations, exact reader membership, and bounded history."""
    counts = (
        result.execution_participant_count, result.region_count,
        result.source_participant_count, result.sink_participant_count,
    )
    return (
        all(count > 0 for count in counts)
        and result.quiescence_reader_count == result.execution_participant_count
        and result.terminal_history_size <= _MAX_TRANSITION_RESULT_HISTORY_CAPACITY
    )


def stats_are_exact(result: StatsResult) -> bool:
    """Admit scalar authorities before dependent telemetry-family checks."""
    if (
        not _runtime_frame_is_exact(result)
        or not _transition_publication_is_exact(result)
        or not _participant_counts_are_exact(result)
    ):
        return False
    if result.stage_stats and not _unique_nonempty([row.stage_id for row in result.stage_stats]):
        return False
    return (
        _transition_is_exact(result)
        and _protocol_faults_are_exact(result)
        and _module_rows_are_exact(result)
        and _worker_region_boundary_rows_are_exact(result)
        and _provider_topology_rows_are_exact(result)
    )


def boundary_transition_is_complete(
    row: BoundaryEpochStatsResult,
    transition_generation: int,
    from_epoch: int,
    to_epoch: int,
) -> bool:
    """Return whether one row is exact terminal evidence for E->N."""
    return all((
        transition_generation > 0,
        row.transition_generation == transition_generation,
        row.from_epoch == from_epoch,
        row.to_epoch == to_epoch,
        row.cut_sequence is not None,
        row.sender_phase == "BOUNDARY_SENDER_PHASE_OPEN",
        row.receiver_phase == "BOUNDARY_RECEIVER_PHASE_OPEN",
        row.pending_cut_epoch is None,
        row.pending_ack_epoch is None,
        row.data_dequeued_sequence <= row.data_enqueued_sequence,
        row.cut_sequence is not None
        and row.cut_sequence <= row.data_dequeued_sequence,
        row.cut_delivery_duration_ns is not None,
        row.cut_drain_duration_ns is not None,
        row.ack_gate_duration_ns is not None,
    ))
