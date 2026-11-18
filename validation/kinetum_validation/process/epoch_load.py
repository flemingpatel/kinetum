"""Qualify ingress load from complete owner publications within one configuration."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from ..config.types import CONSTANTS
from ..engine.json_contract import (
    MAX_JSON_DOCUMENT_CHARACTERS, parse_exact_json_object, require_array, require_bool, require_exact_keys,
    require_absolute_path, require_int, require_number, require_object, require_string,
)
from ..engine.plan_metadata import PlanTopologyMetadata
from .installation import is_symlink_free_regular_file
from .response_reader import _wire_sha256, read_snapshot_id
from .telemetry import StatsResult, StreamStatsResult, WorkerCounterStatsResult
from .telemetry_validation import require_stream_observation, stream_counters_advanced, worker_counter_values_are_exact


@dataclass(frozen=True)
class EpochLoadIdentity:
    """Bind a rate phase to one complete runtime, configuration and participant set."""

    runtime_generation: int
    plan_hash: str
    snapshot_id: str
    revision: int
    epoch: int
    validation_hash: str
    workers: int

    @classmethod
    def from_stats(cls, stats: StatsResult) -> EpochLoadIdentity:
        """Reject absent configuration authority before retaining its identity."""
        runtime_exact = stats.success and stats.runtime_generation > 0 and stats.expected_workers > 0
        config_exact = all((
            stats.transition_plan_content_hash, stats.active_snapshot_id, stats.active_epoch > 0,
            stats.active_revision >= 0, stats.transition_active_validation_hash,
        ))
        if not runtime_exact or not config_exact:
            raise ValueError("epoch load lacks exact configuration identity")
        return cls(
            stats.runtime_generation, stats.transition_plan_content_hash, stats.active_snapshot_id,
            stats.active_revision, stats.active_epoch, stats.transition_active_validation_hash, stats.expected_workers,
        )


@dataclass(frozen=True)
class EpochLoadSample:
    """Retain the source fields used by both live qualification and artifact validation."""

    identity: EpochLoadIdentity
    collection_monotonic_ns: int
    worker_counters: tuple[WorkerCounterStatsResult, ...]
    stream_stats: tuple[StreamStatsResult, ...]

    @classmethod
    def from_stats(cls, stats: StatsResult) -> EpochLoadSample:
        """Project an admitted read without copying unrelated telemetry families."""
        return cls(EpochLoadIdentity.from_stats(stats), stats.collection_monotonic_ns,
                   tuple(stats.worker_counters), tuple(stats.stream_stats))

    def evidence(self) -> dict:
        """Return the complete persisted source vector without a derived global sample time."""
        return {
            "identity": asdict(self.identity), "collection_monotonic_ns": self.collection_monotonic_ns,
            "workers": [asdict(row) for row in self.worker_counters],
            "streams": [asdict(row) for row in self.stream_stats],
        }


class LoadIntervalState(Enum):
    """Separate source completeness from the only out-of-band verdict, measured rate."""

    INCOMPLETE = "incomplete"
    EXCESSIVE_GAP = "excessive_gap"
    RATE_OUT_OF_BAND = "rate_out_of_band"
    QUALIFIED = "qualified"


@dataclass(frozen=True)
class EpochLoadProof:
    """Retain the admitted phase endpoints and verdict needed to validate a complete run."""

    identity: EpochLoadIdentity
    first: EpochLoadSample
    last: EpochLoadSample
    targets: dict[int, float]
    qualified: bool


def _classify_interval(
    previous: EpochLoadSample, current: EpochLoadSample, targets: dict[int, float],
) -> tuple[LoadIntervalState, Optional[dict[int, float]]]:
    """Reduce admitted same-configuration vectors using the shared qualification policy."""
    if previous.identity != current.identity or current.collection_monotonic_ns < previous.collection_monotonic_ns:
        raise ValueError("load interval changed identity or regressed collection time")
    advanced = stream_counters_advanced(
        previous.worker_counters, current.worker_counters, previous.stream_stats, current.stream_stats,
    )
    elapsed = [
        new.published_monotonic_ns - old.published_monotonic_ns
        for old, new in zip(previous.worker_counters, current.worker_counters)
    ]
    if max(elapsed) > CONSTANTS.EPOCH_LOAD_INTERVAL_MAX_NS:
        return LoadIntervalState.EXCESSIVE_GAP, None
    if min(elapsed) < CONSTANTS.EPOCH_LOAD_INTERVAL_MIN_NS or not advanced:
        return LoadIntervalState.INCOMPLETE, None
    before = {row.io_stream_id: row for row in previous.stream_stats}
    packets: dict[tuple[int, int], int] = {}
    for row in current.stream_stats:
        if row.direction == "rx":
            owner = (row.logical_port_id, row.worker_index)
            packets[owner] = packets.get(owner, 0) + row.packets - before[row.io_stream_id].packets
    rates = {port: 0.0 for port in targets}
    resolution = {port: 0.0 for port in targets}
    for (port, worker), count in packets.items():
        scale = 1_000_000_000 / elapsed[worker]
        rates[port] += count * scale
        resolution[port] += scale
    if any(resolution[port] > target * CONSTANTS.EPOCH_LOAD_RESOLUTION_LIMIT for port, target in targets.items()):
        return LoadIntervalState.INCOMPLETE, None
    if any(
        abs(rates[port] - target) > target * CONSTANTS.EPOCH_LOAD_RATE_TOLERANCE
        for port, target in targets.items()
    ):
        return LoadIntervalState.RATE_OUT_OF_BAND, rates
    return LoadIntervalState.QUALIFIED, rates


def _is_after_barrier(sample: EpochLoadSample, barrier: EpochLoadSample) -> bool:
    """Return whether every worker published this epoch after the phase's collection barrier."""
    return all(
        worker.observation_epoch == sample.identity.epoch
        and worker.published_monotonic_ns > barrier.collection_monotonic_ns
        for worker in sample.worker_counters
    )


class EpochLoadPhase:
    """Own one bounded streak, a freshness barrier and one last rejected interval.

    Observations are immutable borrows from completed statistics reads. The
    caller owns polling and its deadline. At most four qualifying endpoints,
    one rejected pair, the barrier read and the latest cursor are retained.
    Invalid evidence raises ValueError; valid incomplete evidence returns False.
    """

    def __init__(self, topology: PlanTopologyMetadata, expected: StatsResult, targets: dict[int, float]) -> None:
        """Freeze the phase identity and exact logical-ingress targets before polling."""
        self.identity = EpochLoadIdentity.from_stats(expected)
        if (
            expected.transition_state != "EPOCH_TRANSITION_STATE_IDLE"
            or expected.transition_success_blocked or expected.retirement_frozen
        ):
            raise ValueError("epoch load requires a settled configuration")
        self._topology = topology
        ingress = {row.logical_port_id for row in topology.io_streams if row.direction == "IO_STREAM_DIRECTION_RX"}
        if not ingress or set(targets) != ingress or any(
            not math.isfinite(value) or value <= 0.0 for value in targets.values()
        ):
            raise ValueError("epoch load targets differ from the plan's ingress ports")
        require_stream_observation(topology, None, expected)
        if any(row.observation_epoch > self.identity.epoch for row in expected.worker_counters):
            raise ValueError("epoch load worker observation exceeds the active configuration")
        self._targets = dict(targets)
        self._faults = dict(expected.protocol_fault_counts)
        self._last = expected
        self._barrier: Optional[EpochLoadSample] = None
        self._samples: list[EpochLoadSample] = []
        self._rates: list[dict[int, float]] = []
        self._last_rejection: Optional[dict] = None

    @property
    def complete(self) -> bool:
        """Return whether three consecutive complete intervals met every port target."""
        return len(self._rates) == CONSTANTS.EPOCH_LOAD_REQUIRED_INTERVALS

    def validate_observation(self, current: StatsResult) -> EpochLoadSample:
        """Admit continuity from the last phase read without extending its rate streak.

        The caller may use this after qualification to check the traffic tail,
        whose offered rate can differ after overlap ends. Invalid identity or
        counter history raises ValueError; no phase state changes.
        """
        require_stream_observation(self._topology, self._last, current)
        sample = EpochLoadSample.from_stats(current)
        if (
            sample.identity != self.identity
            or current.transition_state != "EPOCH_TRANSITION_STATE_IDLE"
            or current.transition_success_blocked or current.retirement_frozen
            or current.protocol_fault_counts != self._faults
        ):
            raise ValueError("epoch load crossed configuration identity or an unsettled transition")
        if any(row.observation_epoch > self.identity.epoch for row in current.worker_counters):
            raise ValueError("epoch load worker observation exceeds the active configuration")
        return sample

    def observe(self, current: StatsResult) -> bool:
        """Validate continuity, establish completeness, then classify only the rate.

        Counter resolution and common coverage cannot fail as out-of-band
        rates. They wait for a complete interval unless an owner's elapsed
        time exceeds the maximum, which discards the entire prior streak.
        """
        if self.complete:
            raise ValueError("epoch load phase is already complete")
        sample = self.validate_observation(current)
        self._last = current
        if self._barrier is None:
            self._barrier = sample
            return False
        if not _is_after_barrier(sample, self._barrier):
            return False
        if not self._samples:
            self._samples.append(sample)
            return False
        previous = self._samples[-1]
        state, rates = _classify_interval(previous, sample, self._targets)
        if state == LoadIntervalState.INCOMPLETE:
            return False
        if state != LoadIntervalState.QUALIFIED:
            self._reject(previous, sample, state.value, rates)
            return False
        if rates is None:
            raise RuntimeError("qualified interval omitted its rates")
        self._samples.append(sample)
        self._rates.append(rates)
        return self.complete

    def _reject(self, previous: EpochLoadSample, current: EpochLoadSample, reason: str,
                rates: Optional[dict[int, float]] = None) -> None:
        """Retain one failed interval and restart from its admitted current endpoint."""
        self._last_rejection = {
            "reason": reason, "before": previous.evidence(), "after": current.evidence(),
            "rates_pps": {str(port): value for port, value in rates.items()} if rates is not None else None,
        }
        self._samples = [current]
        self._rates.clear()

    def evidence(self) -> dict:
        """Return bounded raw endpoints and policy for independent qualification review."""
        return {
            "identity": asdict(self.identity),
            "target_pps_by_port": {str(port): value for port, value in self._targets.items()},
            "owner_interval_min_ns": CONSTANTS.EPOCH_LOAD_INTERVAL_MIN_NS,
            "owner_interval_max_ns": CONSTANTS.EPOCH_LOAD_INTERVAL_MAX_NS,
            "required_intervals": CONSTANTS.EPOCH_LOAD_REQUIRED_INTERVALS,
            "rate_tolerance": CONSTANTS.EPOCH_LOAD_RATE_TOLERANCE,
            "resolution_limit": CONSTANTS.EPOCH_LOAD_RESOLUTION_LIMIT,
            "barrier": self._barrier.evidence() if self._barrier is not None else None,
            "samples": [row.evidence() for row in self._samples],
            "rates_pps": [{str(port): value for port, value in rates.items()} for rates in self._rates],
            "last_observation": EpochLoadSample.from_stats(self._last).evidence(),
            "last_rejected_interval": self._last_rejection,
            "qualified": self.complete,
        }


def _read_identity(value: object) -> EpochLoadIdentity:
    """Admit the complete persisted runtime/configuration namespace."""
    row = require_object(value, "epoch load identity")
    require_exact_keys(row, {"runtime_generation", "plan_hash", "snapshot_id", "revision", "epoch",
                             "validation_hash", "workers"}, "epoch load identity")
    return EpochLoadIdentity(
        require_int(row["runtime_generation"], "load runtime", minimum=1, maximum=(1 << 32) - 1),
        _wire_sha256(require_string(row["plan_hash"], "load plan hash")),
        read_snapshot_id(row["snapshot_id"], "load snapshot"),
        require_int(row["revision"], "load revision", minimum=0, maximum=1 << 48),
        require_int(row["epoch"], "load epoch", minimum=1, maximum=(1 << 64) - 2),
        _wire_sha256(require_string(row["validation_hash"], "load validation hash")),
        require_int(row["workers"], "load worker population", minimum=1, maximum=(1 << 32) - 1),
    )


def _read_sample(value: object, identity: EpochLoadIdentity) -> EpochLoadSample:
    """Admit exact recorded counters without inventing a native statistics response or plan."""
    row = require_object(value, "epoch load sample")
    require_exact_keys(row, {"identity", "collection_monotonic_ns", "workers", "streams"}, "epoch load sample")
    if _read_identity(row["identity"]) != identity:
        raise ValueError("epoch load sample crossed phase identity")
    collected = require_int(row["collection_monotonic_ns"], "load collection time", minimum=1, maximum=(1 << 64) - 1)
    raw_workers = require_array(row["workers"], "load workers")
    if len(raw_workers) != identity.workers:
        raise ValueError("epoch load worker membership is incomplete")
    workers = []
    worker_fields = {
        "worker_index", "observation_epoch", "publication_generation", "published_monotonic_ns",
        "rx_packets", "tx_packets", "dropped_packets", "rx_bytes", "tx_bytes", "fanout_overflow",
    }
    for index, item in enumerate(raw_workers):
        record = require_object(item, "load worker")
        require_exact_keys(record, worker_fields, "load worker")
        worker = WorkerCounterStatsResult(**{
            name: require_int(number, f"load worker {name}", minimum=0, maximum=(1 << 64) - 1)
            for name, number in record.items()
        })
        if not all((
            worker.worker_index == index, 0 < worker.observation_epoch <= identity.epoch,
            worker.publication_generation > 0, 0 < worker.published_monotonic_ns <= collected,
            worker_counter_values_are_exact(worker),
        )):
            raise ValueError("epoch load worker identity or counters are invalid")
        workers.append(worker)
    if any(sum(values) >= (1 << 64) - 1 for values in zip(*(worker.counter_values() for worker in workers))):
        raise ValueError("epoch load worker counters exhaust the aggregate domain")
    streams = []
    ids = set()
    totals = [[0, 0, 0, 0] for _ in workers]
    stream_fields = {
        "io_stream_id", "logical_port_id", "direction", "owning_region_id", "worker_index", "driver_queue_id",
        "published_monotonic_ns", "packets", "bytes", "rejected_packets",
    }
    for item in require_array(row["streams"], "load streams"):
        record = require_object(item, "load stream")
        require_exact_keys(record, stream_fields, "load stream")
        fields = {
            name: require_int(number, f"load stream {name}", minimum=0, maximum=(1 << 64) - 2)
            for name, number in record.items() if name not in {"io_stream_id", "direction"}
        }
        stream = StreamStatsResult(
            io_stream_id=require_string(record["io_stream_id"], "load stream identity"),
            direction=require_string(record["direction"], "load stream direction"), **fields,
        )
        if (
            stream.io_stream_id in ids or stream.direction not in {"rx", "tx"}
            or stream.worker_index >= len(workers)
            or any(value > (1 << 32) - 1 for value in (
                stream.logical_port_id, stream.owning_region_id, stream.driver_queue_id,
            ))
        ):
            raise ValueError("epoch load stream identity is invalid")
        ids.add(stream.io_stream_id)
        if (
            stream.published_monotonic_ns != workers[stream.worker_index].published_monotonic_ns
            or (stream.packets == 0) != (stream.bytes == 0) or stream.bytes < stream.packets
        ):
            raise ValueError("epoch load stream timestamp or counters are invalid")
        offset = 0 if stream.direction == "rx" else 2
        totals[stream.worker_index][offset] += stream.packets
        totals[stream.worker_index][offset + 1] += stream.bytes
        streams.append(stream)
    if any(values != [worker.rx_packets, worker.rx_bytes, worker.tx_packets, worker.tx_bytes]
           for values, worker in zip(totals, workers)):
        raise ValueError("epoch load stream totals differ from their worker")
    return EpochLoadSample(identity, collected, tuple(workers), tuple(streams))


def _read_port_rates(value: object, ports: Optional[set[int]] = None) -> dict[int, float]:
    """Read a canonical logical-port map without accepting aliased decimal identities."""
    result = {}
    for key, number in require_object(value, "load port rates").items():
        if (
            not isinstance(key, str) or not key.isascii() or not key.isdecimal()
            or str(int(key)) != key or int(key) > (1 << 32) - 1
        ):
            raise ValueError("epoch load port identity is not canonical")
        result[int(key)] = require_number(number, "load port rate", minimum=0.0)
    if not result or (ports is not None and set(result) != ports):
        raise ValueError("epoch load port membership is incomplete")
    return result


def _require_sample_progress(previous: EpochLoadSample, current: EpochLoadSample) -> None:
    """Check continuity across a phase or epoch boundary without interpreting it as a rate."""
    if current.collection_monotonic_ns < previous.collection_monotonic_ns:
        raise ValueError("epoch load collection time regressed")
    stream_counters_advanced(previous.worker_counters, current.worker_counters,
                             previous.stream_stats, current.stream_stats)


def _require_after_barrier(sample: EpochLoadSample, barrier: Optional[EpochLoadSample]) -> None:
    """Require every rate endpoint to belong to its phase after the complete freshness barrier."""
    if barrier is None or not _is_after_barrier(sample, barrier):
        raise ValueError("epoch load sample precedes its phase barrier")


def _read_phase(value: object) -> EpochLoadProof:
    """Recompute every retained accepted interval under the recorded fixed policy."""
    row = require_object(value, "epoch load phase")
    require_exact_keys(row, {
        "identity", "target_pps_by_port", "owner_interval_min_ns", "owner_interval_max_ns", "required_intervals",
        "rate_tolerance", "resolution_limit", "barrier", "samples", "rates_pps", "last_observation",
        "last_rejected_interval", "qualified",
    }, "epoch load phase")
    identity = _read_identity(row["identity"])
    integer_policy = {
        "owner_interval_min_ns": CONSTANTS.EPOCH_LOAD_INTERVAL_MIN_NS,
        "owner_interval_max_ns": CONSTANTS.EPOCH_LOAD_INTERVAL_MAX_NS,
        "required_intervals": CONSTANTS.EPOCH_LOAD_REQUIRED_INTERVALS,
    }
    for name, expected in integer_policy.items():
        if require_int(row[name], f"load policy {name}", minimum=1) != expected:
            raise ValueError("epoch load policy differs from the qualification contract")
    for name, expected in (("rate_tolerance", CONSTANTS.EPOCH_LOAD_RATE_TOLERANCE),
                           ("resolution_limit", CONSTANTS.EPOCH_LOAD_RESOLUTION_LIMIT)):
        if require_number(row[name], f"load policy {name}", minimum=0.0) != expected:
            raise ValueError("epoch load policy differs from the qualification contract")
    last = _read_sample(row["last_observation"], identity)
    ports = {stream.logical_port_id for stream in last.stream_stats if stream.direction == "rx"}
    targets = _read_port_rates(row["target_pps_by_port"], ports)
    if any(not 0 < rate <= 2 * CONSTANTS.MAX_PACKET_RATE_PPS for rate in targets.values()):
        raise ValueError("epoch load target rate is outside its domain")
    barrier = _read_sample(row["barrier"], identity) if row["barrier"] is not None else None
    raw_samples = require_array(row["samples"], "load samples")
    raw_rates = require_array(row["rates_pps"], "load interval rates")
    qualified = require_bool(row["qualified"], "load phase verdict")
    if (
        len(raw_samples) > CONSTANTS.EPOCH_LOAD_REQUIRED_INTERVALS + 1
        or len(raw_rates) != max(0, len(raw_samples) - 1)
        or qualified != (len(raw_rates) == CONSTANTS.EPOCH_LOAD_REQUIRED_INTERVALS)
    ):
        raise ValueError("epoch load streak is incomplete")
    if barrier is None and (raw_samples or row["last_rejected_interval"] is not None):
        raise ValueError("epoch load streak has no freshness barrier")
    samples = [_read_sample(sample, identity) for sample in raw_samples]
    if barrier is not None:
        _require_sample_progress(barrier, last)
        if samples:
            _require_sample_progress(barrier, samples[0])
        elif _is_after_barrier(last, barrier):
            raise ValueError("epoch load omitted its first fresh rate endpoint")
    for sample in samples:
        _require_after_barrier(sample, barrier)
    for previous, current, claimed in zip(samples, samples[1:], raw_rates):
        state, rates = _classify_interval(previous, current, targets)
        if state != LoadIntervalState.QUALIFIED or _read_port_rates(claimed, ports) != rates:
            raise ValueError("epoch load interval does not establish its claimed rate")
    if samples and samples[-1] != last:
        if qualified:
            raise ValueError("qualified epoch load continued after its final rate endpoint")
        state, _ = _classify_interval(samples[-1], last, targets)
        if state != LoadIntervalState.INCOMPLETE:
            raise ValueError("epoch load omitted the outcome of its last interval")
    if row["last_rejected_interval"] is not None:
        rejected = require_object(row["last_rejected_interval"], "rejected load interval")
        require_exact_keys(rejected, {"reason", "before", "after", "rates_pps"}, "rejected load interval")
        previous, current = (_read_sample(rejected[name], identity) for name in ("before", "after"))
        _require_after_barrier(previous, barrier)
        _require_after_barrier(current, barrier)
        _require_sample_progress(barrier, previous)
        state, rates = _classify_interval(previous, current, targets)
        if state not in {LoadIntervalState.EXCESSIVE_GAP, LoadIntervalState.RATE_OUT_OF_BAND}:
            raise ValueError("epoch load rejection classifies an incomplete or qualifying interval")
        if require_string(rejected["reason"], "load rejection reason") != state.value:
            raise ValueError("epoch load rejection reason differs from its source evidence")
        claimed = _read_port_rates(rejected["rates_pps"], ports) if rejected["rates_pps"] is not None else None
        if claimed != rates:
            raise ValueError("epoch load rejected rate differs from its source evidence")
        if not samples or current != samples[0]:
            raise ValueError("epoch load streak did not restart at its last rejected endpoint")
    return EpochLoadProof(identity, barrier if barrier is not None else last, last, targets, qualified)


def validate_epoch_load_evidence(value: object) -> bool:
    """Validate closed evidence and recompute qualification without trusting verdict flags."""
    row = require_object(value, "epoch load evidence")
    require_exact_keys(row, {"run_root", "old", "new", "apply", "load_qualified", "failure"}, "epoch load evidence")
    require_absolute_path(row["run_root"], "epoch load run root")
    old = _read_phase(row["old"]) if row["old"] is not None else None
    new = _read_phase(row["new"]) if row["new"] is not None else None
    applied = row["apply"]
    if applied is not None:
        applied = require_object(applied, "load Apply result")
        require_exact_keys(applied, {"success", "snapshot_id", "revision", "epoch", "diagnostic"}, "load Apply result")
        require_bool(applied["success"], "load Apply success")
        require_string(applied["snapshot_id"], "load Apply snapshot", allow_empty=not applied["success"])
        require_int(applied["revision"], "load Apply revision", minimum=0, maximum=1 << 48)
        require_int(applied["epoch"], "load Apply epoch", minimum=int(applied["success"]), maximum=(1 << 64) - 2)
        require_string(applied["diagnostic"], "load Apply diagnostic", allow_empty=True)
        if applied["success"]:
            read_snapshot_id(applied["snapshot_id"], "load Apply snapshot")
            if applied["diagnostic"]:
                raise ValueError("epoch load Apply success carries a failure diagnostic")
        elif applied["snapshot_id"] or applied["revision"] != 0 or applied["epoch"] != 0:
            raise ValueError("epoch load Apply failure carries success identity")
        if old is None or not old.qualified or (applied["success"] and applied["epoch"] <= old.identity.epoch):
            raise ValueError("epoch load Apply lacks qualified old input or an advancing target")
    if new is not None:
        if old is None or applied is None or not applied["success"]:
            raise ValueError("epoch load target phase lacks a completed Apply")
        if (
            (new.identity.snapshot_id, new.identity.revision, new.identity.epoch)
            != (applied["snapshot_id"], applied["revision"], applied["epoch"])
            or (new.identity.runtime_generation, new.identity.plan_hash, new.identity.workers)
            != (old.identity.runtime_generation, old.identity.plan_hash, old.identity.workers)
            or new.targets != old.targets
        ):
            raise ValueError("epoch load target phase changed its runtime, load or Apply identity")
        _require_sample_progress(old.last, new.first)
    qualified = old is not None and new is not None and old.qualified and new.qualified
    if require_bool(row["load_qualified"], "load verdict") != qualified:
        raise ValueError("epoch load verdict contradicts its source intervals")
    require_string(row["failure"], "epoch load failure", allow_empty=qualified)
    return qualified


def require_epoch_load_artifact(run_dir: Path, qualified: bool, passed: bool) -> Optional[dict]:
    """Require and validate every claimed load result while permitting genuinely absent failure evidence."""
    path = run_dir / "epoch_load.json"
    try:
        path.lstat()
    except FileNotFoundError:
        if qualified or passed:
            raise ValueError("epoch result omitted its load evidence") from None
        return None
    if not is_symlink_free_regular_file(path):
        raise ValueError("epoch load evidence is not an exact regular file")
    with path.open(encoding="utf-8") as source:
        evidence = parse_exact_json_object(source.read(MAX_JSON_DOCUMENT_CHARACTERS + 1), "epoch load evidence")
    observed = validate_epoch_load_evidence(evidence)
    if evidence["run_root"] != str(run_dir):
        raise ValueError("epoch load evidence belongs to a different run")
    if observed != qualified or bool(evidence["failure"]) == passed or (passed and not observed):
        raise ValueError("epoch result contradicts its load evidence")
    return evidence
