"""Typed runtime telemetry records and their exact wire domains."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..engine.json_contract import PROTOCOL_FAULT_CODE_ORDER


_PROTOCOL_FAULT_CODE_ORDER = PROTOCOL_FAULT_CODE_ORDER
_PROTOCOL_FAULT_CODES = frozenset(_PROTOCOL_FAULT_CODE_ORDER)

_TRANSITION_STATES = frozenset({
    "EPOCH_TRANSITION_STATE_PREPARING",
    "EPOCH_TRANSITION_STATE_PREPARED",
    "EPOCH_TRANSITION_STATE_COMMITTING",
    "EPOCH_TRANSITION_STATE_RETIRING",
    "EPOCH_TRANSITION_STATE_FAILED_STOP",
    "EPOCH_TRANSITION_STATE_IDLE",
})
_TRANSITION_OUTCOMES = frozenset({
    "EPOCH_TRANSITION_OUTCOME_NONE",
    "EPOCH_TRANSITION_OUTCOME_COMPLETE",
    "EPOCH_TRANSITION_OUTCOME_ABORTED",
    "EPOCH_TRANSITION_OUTCOME_FAILED_STOP",
})
_TRANSITION_FAILURE_CODES = frozenset({
    "EPOCH_TRANSITION_FAILURE_CODE_NONE",
    "EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT",
    "EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT",
    "EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE",
    "EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED",
    "EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED",
    "EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED",
    "EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED",
    "EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION",
    "EPOCH_TRANSITION_FAILURE_CODE_RETIREMENT_GRACE_DEADLINE_EXCEEDED",
    "EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE",
    "EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED",
    "EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN",
    "EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT",
})
_PROTOCOL_FAULT_DISPOSITIONS = frozenset({
    "EPOCH_PROTOCOL_FAULT_DISPOSITION_DROP_AND_RETIRE",
    "EPOCH_PROTOCOL_FAULT_DISPOSITION_TERMINATE",
    "EPOCH_PROTOCOL_FAULT_DISPOSITION_RESOURCE_REFUSED",
})
_PROVIDER_OBSERVATION_STATES = frozenset({
    "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT",
    "PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE",
    "PROVIDER_OBSERVATION_STATE_UNSUPPORTED",
    "PROVIDER_OBSERVATION_STATE_READ_FAILED",
})
_SENDER_PHASES = frozenset({
    "BOUNDARY_SENDER_PHASE_UNBOUND",
    "BOUNDARY_SENDER_PHASE_OPEN",
    "BOUNDARY_SENDER_PHASE_DRAINING",
    "BOUNDARY_SENDER_PHASE_CUT_PENDING",
    "BOUNDARY_SENDER_PHASE_WAITING_ACK",
})
_RECEIVER_PHASES = frozenset({
    "BOUNDARY_RECEIVER_PHASE_UNBOUND",
    "BOUNDARY_RECEIVER_PHASE_OPEN",
    "BOUNDARY_RECEIVER_PHASE_WAITING_CUT",
    "BOUNDARY_RECEIVER_PHASE_CUT_DRAINING",
    "BOUNDARY_RECEIVER_PHASE_CUT_DRAINED",
    "BOUNDARY_RECEIVER_PHASE_ACK_PENDING",
    "BOUNDARY_RECEIVER_PHASE_ACK_PUBLISHED",
})
_CERTIFICATE_STATES = frozenset({
    "EPOCH_CERTIFICATE_STATE_INCOMPLETE",
    "EPOCH_CERTIFICATE_STATE_EXECUTION_COMPLETE",
    "EPOCH_CERTIFICATE_STATE_RECLAMATION_READY",
    "EPOCH_CERTIFICATE_STATE_CONTRADICTION",
})
_CERTIFICATE_FAULTS = frozenset({
    "EPOCH_CERTIFICATE_FAULT_NONE",
    "EPOCH_CERTIFICATE_FAULT_REQUEST_IDENTITY",
    "EPOCH_CERTIFICATE_FAULT_EXECUTION_MEMBERSHIP",
    "EPOCH_CERTIFICATE_FAULT_EXECUTION_STATE",
    "EPOCH_CERTIFICATE_FAULT_BOUNDARY_MEMBERSHIP",
    "EPOCH_CERTIFICATE_FAULT_BOUNDARY_STATE",
    "EPOCH_CERTIFICATE_FAULT_CUT_IDENTITY",
    "EPOCH_CERTIFICATE_FAULT_READER_MEMBERSHIP",
})
_MODULE_HEALTH_STATES = frozenset({
    "MODULE_HEALTH_STATE_CALLBACK_UNAVAILABLE",
    "MODULE_HEALTH_STATE_AWAITING_OBSERVATION",
    "MODULE_HEALTH_STATE_SIGNAL_AVAILABLE",
    "MODULE_HEALTH_STATE_ATTEMPT_SUPPRESSED",
    "MODULE_HEALTH_STATE_STALE_EPOCH",
})

_PRECOMMIT_FAILURE_CODES = frozenset({
    "EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT",
    "EPOCH_TRANSITION_FAILURE_CODE_SHUTDOWN_ABORT",
    "EPOCH_TRANSITION_FAILURE_CODE_PREPARE_FAILURE",
    "EPOCH_TRANSITION_FAILURE_CODE_PREPARE_CANCELLED",
    "EPOCH_TRANSITION_FAILURE_CODE_PREPARE_DEADLINE_EXCEEDED",
    "EPOCH_TRANSITION_FAILURE_CODE_PREPARED_LEASE_EXPIRED",
})
_FAIL_STOP_FAILURE_CODES = frozenset({
    "EPOCH_TRANSITION_FAILURE_CODE_COMMIT_DEADLINE_EXCEEDED",
    "EPOCH_TRANSITION_FAILURE_CODE_CERTIFICATE_CONTRADICTION",
    "EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_FAILURE",
    "EPOCH_TRANSITION_FAILURE_CODE_RETIRE_CALLBACK_DEADLINE_EXCEEDED",
    "EPOCH_TRANSITION_FAILURE_CODE_COMMIT_SHUTDOWN",
    "EPOCH_TRANSITION_FAILURE_CODE_PROTOCOL_FAULT",
})
_UINT16_MAX = (1 << 16) - 1
_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1
_MAX_EPOCH_ID = _UINT64_MAX - 1
_MAX_MUTATION_SEQUENCE = _UINT64_MAX - 1
_MAX_TRANSITION_RESULT_HISTORY_CAPACITY = 64
_MAX_CONFIG_SNAPSHOT_REVISION = 1 << 48
_MODULE_HEALTH_CONTRACT_FAULT_KNOWN_MASK = 0x0F
_MODULE_HEALTH_SIGNAL_FLAG_KNOWN_MASK = 0x0103

_RUNTIME_FIELDS = frozenset({
    "runtime_generation", "status_publication_generation", "active_epoch",
    "minimum_retained_epoch", "last_activated_epoch", "active_workers",
    "expected_workers", "collection_monotonic_ns",
    "latest_bank_publication_monotonic_ns", "skipped_publications",
})
_ENGINE_FIELDS = frozenset({
    "rx_packets", "tx_packets", "dropped_packets", "rx_bytes", "tx_bytes",
    "fanout_overflow",
})
_TRANSITION_REQUIRED_FIELDS = frozenset({
    "publication_generation", "state", "active_epoch", "target_epoch",
    "allocated_epoch_high_watermark", "mutation_sequence_high_watermark",
    "plan_content_hash", "participant_set_frozen",
    "execution_participant_count", "region_count", "boundary_count",
    "source_participant_count", "sink_participant_count",
    "module_context_count", "quiescence_reader_count", "terminal_history_size",
    "retirement_frozen", "active_validation_hash",
})
_TRANSITION_OPTIONAL_FIELDS = frozenset({
    "active_transaction", "latest_terminal", "certificate", "grace",
})
_TRANSACTION_REQUIRED_FIELDS = frozenset({
    "mutation_sequence", "from_epoch", "to_epoch", "validation_hash",
    "idempotency_key_digest", "admitted_monotonic_ns", "outcome",
    "failure_code", "retirement_frozen",
})
_TRANSACTION_OPTIONAL_FIELDS = frozenset({
    "prepared_monotonic_ns", "prepared_lease_deadline_monotonic_ns",
    "prepared_lease_deadline_unix_ms", "commit_started_monotonic_ns",
    "retiring_started_monotonic_ns", "failure_observed_monotonic_ns",
    "terminal_monotonic_ns",
})
_TELEMETRY_CORE_FIELDS = frozenset({
    "runtime", "engine", "transition", "protocol_faults",
})
_TELEMETRY_ROW_FIELDS = frozenset({
    "stages", "module_counters", "module_histograms",
    "module_epoch_mismatches", "module_health", "workers", "regions",
    "boundaries", "streams", "storage_domains", "ports",
    "steering_profiles", "module_context_domains",
})


@dataclass(frozen=True)
class StatsSelection:
    """Select optional row families for one native statistics request.

    Attributes
    ----------
    include_stage_stats : bool
        Request per-stage packet and byte counters.
    include_module_metrics : bool
        Request registered counters, histograms, and epoch mismatches.
    include_module_health : bool
        Request coherent owner-worker module-health observations.
    include_worker_epoch_stats : bool
        Request worker epoch, ownership, and activation observations.
    include_region_epoch_stats : bool
        Request region derivations of worker ownership and activation.
    include_boundary_epoch_stats : bool
        Request exact DATA/CUT/ACK boundary progress.
    include_stream_stats : bool
        Request executable I/O stream counters.
    include_storage_domain_stats : bool
        Request packet-storage capacity and population observations.
    include_port_stats : bool
        Request native logical-port observations.
    include_topology_stats : bool
        Request compiled steering and module-context populations.
    """

    include_stage_stats: bool = False
    include_module_metrics: bool = False
    include_module_health: bool = False
    include_worker_epoch_stats: bool = False
    include_region_epoch_stats: bool = False
    include_boundary_epoch_stats: bool = False
    include_stream_stats: bool = False
    include_storage_domain_stats: bool = False
    include_port_stats: bool = False
    include_topology_stats: bool = False


@dataclass
class StageStatsResult:
    """
    Per-stage packet statistics.

    Attributes
    ----------
    stage_id : str
        Stage identifier.
    in_packets : int
        Packets entering this stage.
    out_packets : int
        Packets leaving this stage.
    dropped_packets : int
        Packets dropped at this stage.
    in_bytes : int
        Bytes entering this stage.
    out_bytes : int
        Bytes leaving this stage.
    """
    stage_id: str = ""
    in_packets: int = 0
    out_packets: int = 0
    dropped_packets: int = 0
    in_bytes: int = 0
    out_bytes: int = 0


@dataclass
class BoundaryEpochStatsResult:  # pylint: disable=too-many-instance-attributes
    """
    Exact DATA/CUT/ACK progress for one compiled boundary.

    Stable endpoint identities and plan capacities accompany coherent sender,
    receiver, and transport state. Optional timestamps and durations remain
    ``None`` until their exact transition edge has occurred.
    """
    boundary_id: str = ""
    boundary_index: int = 0
    from_stage_instance_index: int = 0
    to_stage_instance_index: int = 0
    sender_worker_index: int = 0
    receiver_worker_index: int = 0
    from_region_id: int = -1
    to_region_id: int = -1
    data_ring_capacity: int = 0
    future_output_hold_capacity: int = 0
    data_enqueued_sequence: int = 0
    data_dequeued_sequence: int = 0
    data_backpressure_events: int = 0
    pending_cut_epoch: Optional[int] = None
    pending_cut_sequence: Optional[int] = None
    pending_ack_epoch: Optional[int] = None
    pending_ack_sequence: Optional[int] = None
    transition_generation: Optional[int] = None
    from_epoch: Optional[int] = None
    to_epoch: Optional[int] = None
    cut_sequence: Optional[int] = None
    sender_phase: str = "BOUNDARY_SENDER_PHASE_UNSPECIFIED"
    receiver_phase: str = "BOUNDARY_RECEIVER_PHASE_UNSPECIFIED"
    duplicate_cut_count: int = 0
    duplicate_ack_count: int = 0
    cut_published_monotonic_ns: Optional[int] = None
    cut_observed_monotonic_ns: Optional[int] = None
    cut_drained_monotonic_ns: Optional[int] = None
    activation_monotonic_ns: Optional[int] = None
    ack_published_monotonic_ns: Optional[int] = None
    ack_observed_monotonic_ns: Optional[int] = None
    cut_delivery_duration_ns: Optional[int] = None
    cut_drain_duration_ns: Optional[int] = None
    ack_gate_duration_ns: Optional[int] = None


@dataclass
class RegionEpochStatsResult:
    """
    Cold exact aggregation of worker epoch and ownership truth.

    Minimum and maximum epochs expose convergence without turning region state
    into activation authority. Credit totals and activation timestamps are
    derived from the complete selected worker population.
    """
    region_id: int = 0
    worker_count: int = 0
    minimum_active_epoch: int = 0
    maximum_active_epoch: int = 0
    minimum_source_epoch: int = 0
    maximum_source_epoch: int = 0
    active_unretired: int = 0
    future_unretired: int = 0
    activated_participants: int = 0
    minimum_activation_monotonic_ns: Optional[int] = None
    maximum_activation_monotonic_ns: Optional[int] = None
    fanout_overflow: int = 0


@dataclass
class WorkerEpochStatsResult:
    """
    Exact owner-worker epoch, credit, and activation observation.

    The ledger publication owns active/source/future identities and credits.
    The separate activation publication records only a completed transition
    edge; absent optional fields never imply generation zero evidence.
    """
    worker_id: str = ""
    worker_index: int = 0
    region_id: int = -1
    lane_id: str = ""
    ledger_publication_generation: int = 0
    active_epoch: int = 0
    source_epoch: int = 0
    active_unretired: int = 0
    future_epoch: Optional[int] = None
    future_unretired: int = 0
    activation_publication_generation: int = 0
    transition_generation: Optional[int] = None
    from_epoch: Optional[int] = None
    to_epoch: Optional[int] = None
    activation_monotonic_ns: Optional[int] = None
    activation_complete: bool = False


@dataclass
class StreamStatsResult:
    """Carry one owner-published I/O transfer row; TX acceptance is not delivery.

    The identity comes from the compiled stream. The timestamp names its
    worker's last completed bank. Counters require explicit presence, including
    measured zero; rejected packets never transferred across this I/O boundary.
    """

    io_stream_id: str = ""
    logical_port_id: int = 0
    direction: str = "unspecified"
    owning_region_id: int = -1
    worker_index: int = 0
    driver_queue_id: int = 0
    published_monotonic_ns: int = 0
    packets: Optional[int] = None
    bytes: Optional[int] = None
    rejected_packets: Optional[int] = None


@dataclass
class StorageDomainStatsResult:
    """
    Per-packet-storage-domain statistics.

    Attributes
    ----------
    storage_domain_id : str
        Stable packet-storage-domain identifier.
    host_numa_node : Optional[int]
        Exact host NUMA node when present, otherwise None.
    buffer_count : int
        Total buffers in the pool profile.
    required_min_buffers : int
        Computed admission floor for this pool.
    safety_margin : int
        Explicit budget safety margin.
    in_use : int
        Buffers currently in use.
    available : int
        Buffers currently available.
    observation_state : str
        Exact provider availability classification.
    """
    storage_domain_id: str = ""
    host_numa_node: Optional[int] = None
    buffer_count: int = 0
    required_min_buffers: int = 0
    safety_margin: int = 0
    observation_state: str = "PROVIDER_OBSERVATION_STATE_UNSPECIFIED"
    observed_monotonic_ns: Optional[int] = None
    in_use: Optional[int] = None
    available: Optional[int] = None


@dataclass
class PortStatsResult:
    """
    Per-logical-port provider statistics.

    Attributes
    ----------
    logical_port_id : int
        Logical port ID from the deployment plan.
    logical_name : str
        Logical port name from the deployment plan.
    io_driver_instance_id : str
        Exact I/O-driver instance identity.
    driver_port_id : str
        Exact driver-local port identity.
    rx_packets : int
        Packets received by the port.
    tx_packets : int
        Packets transmitted by the port.
    rx_bytes : int
        Bytes received by the port.
    tx_bytes : int
        Bytes transmitted by the port.
    rx_missed : int
        Hardware/PMD receive misses.
    rx_errors : int
        Receive errors reported by the I/O provider.
    tx_errors : int
        Transmit errors reported by the I/O provider.
    observation_state : str
        Exact provider availability classification.
    """
    logical_port_id: int = 0
    logical_name: str = ""
    io_driver_instance_id: str = ""
    driver_port_id: str = ""
    observation_state: str = "PROVIDER_OBSERVATION_STATE_UNSPECIFIED"
    observed_monotonic_ns: Optional[int] = None
    rx_packets: Optional[int] = None
    tx_packets: Optional[int] = None
    rx_bytes: Optional[int] = None
    tx_bytes: Optional[int] = None
    rx_missed: Optional[int] = None
    rx_errors: Optional[int] = None
    tx_errors: Optional[int] = None
    rx_no_buffer: Optional[int] = None


@dataclass
class TrafficSteeringStatsResult:
    """
    Per-traffic-steering-profile statistics.

    Attributes
    ----------
    steering_profile_id : str
        Stable steering profile identifier.
    kind : str
        Steering mechanism.
    symmetric : bool
        Whether reverse tuples must co-steer.
    io_stream_ids : List[str]
        Exact governed stable stream identities.
    """
    steering_profile_id: str = ""
    kind: str = "unspecified"
    symmetric: bool = False
    io_stream_ids: List[str] = field(default_factory=list)


@dataclass
class ModuleContextDomainResult:
    """One module's generation-fixed contexts in exact ordinal order."""

    module_id: str = ""
    context_instance_ids: List[str] = field(default_factory=list)


@dataclass
class ModuleCounterStatsResult:
    """
    Latest absolute value of one registered module counter or gauge.

    Identity is context-scoped. ``epoch`` names the completed module bank from
    which the value was observed; it is never relabeled to the current runtime
    epoch by the validation client.
    """
    module_id: str = ""
    context_instance_id: str = ""
    context_index: int = 0
    worker_index: int = 0
    epoch: int = 0
    name: str = ""
    value: int = 0


@dataclass
class ModuleHistogramStatsResult:
    """
    Cold merged distribution for one registered module histogram.

    Distribution fields remain ``None`` for an empty histogram. A nonempty
    row carries the complete minimum, maximum, and percentile set.
    """
    module_id: str = ""
    context_instance_id: str = ""
    context_index: int = 0
    worker_index: int = 0
    epoch: int = 0
    name: str = ""
    sample_count: int = 0
    sample_sum: int = 0
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    p50: Optional[int] = None
    p90: Optional[int] = None
    p99: Optional[int] = None
    p999: Optional[int] = None


@dataclass
class ModuleEpochMismatchStatsResult:
    """
    Latest absolute exact-epoch mismatch observation for one module context.

    The four first-fault identity fields are all absent or all present. The
    cumulative count is generation-scoped and never interpreted as a packet
    drop count by this client.
    """
    module_id: str = ""
    context_instance_id: str = ""
    context_index: int = 0
    worker_index: int = 0
    observation_epoch: int = 0
    mismatch_count: int = 0
    first_packet_epoch: Optional[int] = None
    first_active_epoch: Optional[int] = None
    first_stage_instance_index: Optional[int] = None
    first_region_id: Optional[int] = None


@dataclass
class ModuleHealthStatsResult:
    """
    Latest coherent owner-worker module-health attempt.

    ``state`` qualifies all optional signal and fault fields. Unavailable,
    stale, and suppressed rows stay explicit; this client never synthesizes a
    healthy score for a missing callback or observation.
    """
    module_id: str = ""
    context_instance_id: str = ""
    context_index: int = 0
    worker_index: int = 0
    stage_instance_index: int = 0
    state: str = "MODULE_HEALTH_STATE_UNSPECIFIED"
    publication_generation: int = 0
    observation_epoch: Optional[int] = None
    observed_at_ns: Optional[int] = None
    callback_duration_ns: Optional[int] = None
    contract_fault_count: int = 0
    latest_fault_mask: int = 0
    first_fault_mask: int = 0
    first_fault_epoch: Optional[int] = None
    first_fault_timestamp_ns: Optional[int] = None
    first_fault_duration_ns: Optional[int] = None
    health_score: Optional[int] = None
    health_flags: Optional[int] = None
    reason: Optional[str] = None


@dataclass
class EpochTransactionStatsResult:
    """
    Exact active or retained terminal transaction observation.

    Hash fields retain protobuf JSON's base64 representation. Optional times
    remain absent until their producer edge; lease projections are paired.
    """
    mutation_sequence: int = 0
    from_epoch: int = 0
    to_epoch: int = 0
    validation_hash: str = ""
    idempotency_key_digest: str = ""
    admitted_monotonic_ns: int = 0
    outcome: str = "EPOCH_TRANSITION_OUTCOME_UNSPECIFIED"
    failure_code: str = "EPOCH_TRANSITION_FAILURE_CODE_UNSPECIFIED"
    retirement_frozen: bool = False
    prepared_monotonic_ns: Optional[int] = None
    prepared_lease_deadline_monotonic_ns: Optional[int] = None
    prepared_lease_deadline_unix_ms: Optional[int] = None
    commit_started_monotonic_ns: Optional[int] = None
    retiring_started_monotonic_ns: Optional[int] = None
    failure_observed_monotonic_ns: Optional[int] = None
    terminal_monotonic_ns: Optional[int] = None


@dataclass
class EpochCertificateStatsResult:
    """
    Last coherent global transition-certificate evaluation.

    Counts are current observations rather than latched maxima. ``fault_index``
    is the compact namespace selected by ``fault`` or the uint32 sentinel.
    """
    evaluated_monotonic_ns: int = 0
    runtime_generation: int = 0
    transition_generation: int = 0
    from_epoch: int = 0
    to_epoch: int = 0
    execution_complete: int = 0
    execution_total: int = 0
    boundary_complete: int = 0
    boundary_total: int = 0
    reader_complete: int = 0
    reader_total: int = 0
    fault_index: int = 0
    state: str = "EPOCH_CERTIFICATE_STATE_UNSPECIFIED"
    fault: str = "EPOCH_CERTIFICATE_FAULT_UNSPECIFIED"


@dataclass
class EpochGraceStatsResult:
    """
    Exact reader-grace identity, progress, and timing observation.

    ``active`` distinguishes an owned grace from a finished historical one;
    ``update_frozen`` records the retained-old-state timeout posture.
    """
    generation: int = 0
    started_monotonic_ns: Optional[int] = None
    completion_observed_monotonic_ns: Optional[int] = None
    finished_monotonic_ns: Optional[int] = None
    readers_complete: int = 0
    readers_total: int = 0
    active: bool = False
    update_frozen: bool = False


@dataclass
class ProtocolFirstFaultResult:
    """
    Immutable fixed numeric identity of the first protocol fault.

    Compact identities retain their wire sentinel when a namespace is not
    applicable. ``disposition`` reports the immediate fail-closed action; the
    separate summary latch states whether transition success is blocked.
    """
    code: str = "EPOCH_PROTOCOL_FAULT_CODE_UNSPECIFIED"
    disposition: str = "EPOCH_PROTOCOL_FAULT_DISPOSITION_UNSPECIFIED"
    runtime_generation: int = 0
    transition_generation: int = 0
    from_epoch: int = 0
    to_epoch: int = 0
    observed_epoch: int = 0
    worker_index: int = 0
    boundary_index: int = 0
    context_index: int = 0
    stage_instance_index: int = 0
    expected_value: int = 0
    observed_value: int = 0
    observed_monotonic_ns: int = 0


@dataclass
class StatsResult:  # pylint: disable=too-many-instance-attributes
    """
    Result from stats query.

    Attributes
    ----------
    success : bool
        Whether query succeeded.
    rx_packets : int
        Total RX packets.
    tx_packets : int
        Total TX packets.
    dropped_packets : int
        Exact terminal packet retirements.
    active_epoch : int
        Current active epoch in DP.
    active_snapshot_id : str
        Current active snapshot ID.
    active_revision : int
        Current active revision.
    runtime_generation : int
        Exact generation owning all counters.
    transition_state : str
        Exact coordinator phase.
    module_counter_stats : list
        Context-scoped registered counter/gauge rows.
    module_histogram_stats : list
        Context-scoped cold merged histogram rows.
    module_epoch_mismatch_stats : list
        Context-scoped exact-epoch mismatch rows.
    module_health_stats : list
        Context-scoped typed health availability and signal rows.
    stage_stats : list
        Per-stage packet statistics.
    boundary_epoch_stats : list
        Per-boundary exact protocol snapshots.
    region_epoch_stats : list
        Per-region ownership derivations.
    worker_epoch_stats : list
        Per-worker exact ownership and activation observations.
    stream_stats : list
        Per-stream executable I/O statistics.
    storage_domain_stats : list
        Per-packet-storage-domain statistics.
    port_stats : list
        Per-logical-port provider statistics.
    traffic_steering_stats : list
        Per-traffic-steering-profile statistics.
    module_context_domains : list
        Canonical module-context populations defining generation-fixed ordinals.
    diagnostic : str
        Failure diagnostic; empty on success.
    """
    success: bool
    rx_packets: int = 0
    tx_packets: int = 0
    dropped_packets: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    fanout_overflow: int = 0
    active_epoch: int = 0
    active_snapshot_id: str = ""
    active_revision: int = 0
    runtime_generation: int = 0
    status_publication_generation: int = 0
    collection_monotonic_ns: int = 0
    minimum_retained_epoch: int = 0
    last_activated_epoch: int = 0
    active_workers: int = 0
    expected_workers: int = 0
    latest_bank_publication_monotonic_ns: int = 0
    skipped_publications: int = 0
    transition_state: str = "EPOCH_TRANSITION_STATE_UNSPECIFIED"
    transition_publication_generation: int = 0
    transition_active_epoch: int = 0
    transition_target_epoch: int = 0
    allocated_epoch_high_watermark: int = 0
    mutation_sequence_high_watermark: int = 0
    transition_plan_content_hash: str = ""
    transition_active_validation_hash: str = ""
    participant_set_frozen: bool = False
    execution_participant_count: int = 0
    region_count: int = 0
    boundary_count: int = 0
    source_participant_count: int = 0
    sink_participant_count: int = 0
    module_context_count: int = 0
    quiescence_reader_count: int = 0
    terminal_history_size: int = 0
    retirement_frozen: bool = False
    active_transaction: Optional[EpochTransactionStatsResult] = None
    latest_terminal: Optional[EpochTransactionStatsResult] = None
    certificate: Optional[EpochCertificateStatsResult] = None
    grace: Optional[EpochGraceStatsResult] = None
    transition_success_blocked: bool = False
    protocol_fault_counts: Dict[str, int] = field(default_factory=dict)
    first_protocol_fault: Optional[ProtocolFirstFaultResult] = None
    stage_stats: List[StageStatsResult] = field(default_factory=list)
    module_counter_stats: List[ModuleCounterStatsResult] = field(default_factory=list)
    module_histogram_stats: List[ModuleHistogramStatsResult] = field(default_factory=list)
    module_epoch_mismatch_stats: List[ModuleEpochMismatchStatsResult] = field(default_factory=list)
    module_health_stats: List[ModuleHealthStatsResult] = field(default_factory=list)
    boundary_epoch_stats: List[BoundaryEpochStatsResult] = field(default_factory=list)
    region_epoch_stats: List[RegionEpochStatsResult] = field(default_factory=list)
    worker_epoch_stats: List[WorkerEpochStatsResult] = field(default_factory=list)
    stream_stats: List[StreamStatsResult] = field(default_factory=list)
    storage_domain_stats: List[StorageDomainStatsResult] = field(default_factory=list)
    port_stats: List[PortStatsResult] = field(default_factory=list)
    traffic_steering_stats: List[TrafficSteeringStatsResult] = field(default_factory=list)
    module_context_domains: List[ModuleContextDomainResult] = field(default_factory=list)
    diagnostic: str = ""
