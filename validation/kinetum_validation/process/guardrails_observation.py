"""Decode exact policy-bound guardrails readiness and retained measurement evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..engine.json_contract import (
    JsonContractError, parse_exact_json_object, require_array, require_bool,
    require_number,
)
from .response_reader import (
    _wire_sha256, message_shape, parse_cli_success, parse_worker_counter,
    read_snapshot_id, wire_enum, wire_uint,
)
from .telemetry import WorkerCounterStatsResult, _MAX_CONFIG_SNAPSHOT_REVISION
from .telemetry_validation import worker_counter_values_are_exact, worker_counters_advanced


_STATES = frozenset(f"GUARDRAILS_EVALUATION_STATE_{name}" for name in (
    "UNCONFIGURED", "DISABLED", "BASELINE_BUILDING", "ARMED", "EVALUATING", "ROLLBACK_PENDING",
))
_RECOMMENDATIONS = frozenset(f"GUARDRAILS_RECOMMENDATION_{name}" for name in (
    "AUTO_ROLLBACK", "DEFER_TO_HUMAN", "LOG_ONLY",
))
_OUTCOMES = frozenset(f"GUARDRAILS_EVALUATION_OUTCOME_{name}" for name in (
    "WINDOW_COMPLETE", "HISTORY_EXHAUSTED", "INTERVAL_EXCEEDS_WINDOW", "ROLLBACK_ACCEPTED",
))


@dataclass(frozen=True)
class GuardrailsPolicyIdentity:
    """Retain the exact successful ConfigureGuardrails result for later observation fencing."""

    generation: int
    policy_hash: str


@dataclass(frozen=True)
class GuardrailsObservationIdentity:
    """Identify one content observation and its complete worker population."""

    runtime_generation: int
    snapshot_id: str
    epoch: int
    revision: int
    validation_hash: str
    expected_workers: int


@dataclass(frozen=True)
class GuardrailsAttribution:
    """Retain actual source endpoints and distinguish recommendation from accepted intent."""

    candidate: GuardrailsObservationIdentity
    rollback_snapshot_id: str
    previous_workers: tuple[WorkerCounterStatsResult, ...]
    current_workers: tuple[WorkerCounterStatsResult, ...]
    baseline_tx_pps: float
    confidence: Optional[float]
    recommendation: str
    evidence_complete: bool
    intent_accepted: bool

    @property
    def covered_duration_ns(self) -> int:
        """Return the shared source interval after endpoint validation."""
        return (
            min(row.published_monotonic_ns for row in self.current_workers)
            - max(row.published_monotonic_ns for row in self.previous_workers)
        )

    def rates(self) -> tuple[float, float]:
        """Sum owner-specific TX and terminal-drop rates from measurement timestamps."""
        tx_rate = 0.0
        drop_rate = 0.0
        for before, after in zip(self.previous_workers, self.current_workers):
            elapsed = after.published_monotonic_ns - before.published_monotonic_ns
            tx_rate += (after.tx_packets - before.tx_packets) * 1_000_000_000 / elapsed
            drop_rate += (after.dropped_packets - before.dropped_packets) * 1_000_000_000 / elapsed
        return tx_rate, drop_rate


@dataclass(frozen=True)
class GuardrailsCompletedEvaluation:
    """Report why the latest candidate window ended within this policy/runtime namespace."""

    candidate: GuardrailsObservationIdentity
    valid_observation_ns: int
    outcome: str


@dataclass(frozen=True)
class GuardrailsEvaluation:
    """Expose readiness without treating an enabled policy as an armed evaluator."""

    state: str
    policy_generation: int
    observed_identity: Optional[GuardrailsObservationIdentity]
    baseline_intervals: int
    valid_observation_ns: int
    last_completed: Optional[GuardrailsCompletedEvaluation]
    last_attribution: Optional[GuardrailsAttribution]


@dataclass(frozen=True)
class GuardrailsRead:
    """Own one validated native response and its exact bytes for evidence recording."""

    identity: GuardrailsPolicyIdentity
    policy: Optional[dict]
    evaluation: Optional[GuardrailsEvaluation]
    raw_json: str


def _identity(value: object) -> GuardrailsObservationIdentity:
    """Reject incomplete or out-of-domain runtime/content identity."""
    row = message_shape(value, frozenset({
        "runtime_generation", "snapshot_id", "epoch", "revision", "validation_hash", "expected_workers",
    }))
    result = GuardrailsObservationIdentity(
        runtime_generation=wire_uint(row["runtime_generation"]),
        snapshot_id=read_snapshot_id(row["snapshot_id"], "guardrails snapshot"),
        epoch=wire_uint(row["epoch"]),
        revision=wire_uint(row["revision"]),
        validation_hash=_wire_sha256(row["validation_hash"]),
        expected_workers=wire_uint(row["expected_workers"], bits=32),
    )
    if (
        not 0 < result.runtime_generation < 1 << 32
        or not 0 < result.epoch < (1 << 64) - 1
        or result.revision > _MAX_CONFIG_SNAPSHOT_REVISION
        or result.expected_workers == 0
    ):
        raise JsonContractError("guardrails observation identity is invalid")
    return result


def _fraction(value: object) -> float:
    """Admit one finite closed-unit policy or score value."""
    return require_number(value, "guardrails ratio", minimum=0.0, maximum=1.0)


def _policy(value: object) -> dict:
    """Admit the same independent policy budgets and sample floors as CP."""
    row = message_shape(value, frozenset({
        "enabled", "poll_interval_ms", "evaluation_window_ms", "telemetry_history_capacity",
    }), frozenset({"threshold", "correlation", "attribution", "boundary"}))
    enabled = require_bool(row["enabled"], "guardrails enabled")
    poll = wire_uint(row["poll_interval_ms"])
    window = wire_uint(row["evaluation_window_ms"])
    capacity = wire_uint(row["telemetry_history_capacity"], bits=32)
    if not enabled:
        if poll or window or capacity or set(row) & {"threshold", "correlation", "attribution", "boundary"}:
            raise JsonContractError("disabled guardrails policy is not empty")
        return row
    if not 0 < poll <= 3_600_000 or not 0 < window <= 86_400_000 or not 0 < capacity <= 100_000:
        raise JsonContractError("guardrails policy budgets are invalid")
    if ("threshold" in row) == ("correlation" in row) or "attribution" not in row:
        raise JsonContractError("guardrails policy lacks one detector and attribution")
    attribution = message_shape(row["attribution"], frozenset({
        "auto_rollback_threshold", "defer_threshold", "baseline_samples", "degradation_threshold",
    }))
    if (
        not 0 < _fraction(attribution["defer_threshold"]) <= _fraction(attribution["auto_rollback_threshold"])
        or _fraction(attribution["degradation_threshold"]) == 0
        or not 0 < wire_uint(attribution["baseline_samples"], bits=32) <= capacity
    ):
        raise JsonContractError("guardrails attribution policy is invalid")
    if "threshold" in row:
        detector = message_shape(row["threshold"], frozenset({
            "max_drop_ratio", "min_tx_ratio", "min_packets_per_window",
        }))
        _fraction(detector["max_drop_ratio"])
        _fraction(detector["min_tx_ratio"])
        wire_uint(detector["min_packets_per_window"])
    else:
        detector = message_shape(row["correlation"], frozenset({
            "drop_ratio_weight", "throughput_ratio_weight", "module_health_weight", "config_issue_boost",
            "ewma_alpha", "degradation_threshold", "hysteresis_band", "min_samples",
            "normalization_max_drop_ratio", "normalization_min_tx_ratio",
        }))
        values = {name: _fraction(value) for name, value in detector.items() if name != "min_samples"}
        weight = sum(values[name] for name in ("drop_ratio_weight", "throughput_ratio_weight", "module_health_weight"))
        weights_valid = 0 < weight <= 1 and weight + values["config_issue_boost"] <= 1
        smoothing_valid = (
            values["ewma_alpha"] > 0 and values["degradation_threshold"] > 0
            and 0 <= values["hysteresis_band"] <= 0.5
            and values["hysteresis_band"] < values["degradation_threshold"]
        )
        if (
            not weights_valid or not smoothing_valid
            or not 0 < wire_uint(detector["min_samples"], bits=32) <= capacity
            or values["normalization_max_drop_ratio"] == 0
            or not 0 < values["normalization_min_tx_ratio"] < 1
        ):
            raise JsonContractError("guardrails correlation policy is invalid")
    if "boundary" in row:
        boundary = message_shape(row["boundary"], frozenset({"ack_timeout_ms"}))
        if not 0 < wire_uint(boundary["ack_timeout_ms"]) <= window:
            raise JsonContractError("guardrails boundary timeout is invalid")
    return row


def _retained_identity(candidate: GuardrailsObservationIdentity, observed: GuardrailsObservationIdentity) -> None:
    """Require one retained candidate in the current observed runtime namespace."""
    if (
        candidate.runtime_generation != observed.runtime_generation
        or candidate.expected_workers != observed.expected_workers
        or candidate.epoch > observed.epoch
        or (candidate.epoch == observed.epoch and candidate != observed)
    ):
        raise JsonContractError("guardrails retained candidate belongs to another observation namespace")


def _proof(value: object, observed: GuardrailsObservationIdentity, policy: dict) -> GuardrailsAttribution:
    """Validate every retained worker before deriving any candidate rate."""
    row = message_shape(value, frozenset({
        "candidate", "rollback_snapshot_id", "previous_workers", "current_workers",
        "baseline_tx_pps", "recommendation", "evidence_complete", "intent_accepted",
    }), frozenset({"confidence"}))
    proof = GuardrailsAttribution(
        candidate=_identity(row["candidate"]),
        rollback_snapshot_id=read_snapshot_id(row["rollback_snapshot_id"], "guardrails rollback"),
        previous_workers=tuple(
            parse_worker_counter(item) for item in require_array(row["previous_workers"], "previous workers")
        ),
        current_workers=tuple(
            parse_worker_counter(item) for item in require_array(row["current_workers"], "current workers")
        ),
        baseline_tx_pps=require_number(row["baseline_tx_pps"], "baseline TX rate", minimum=0.0),
        confidence=_fraction(row["confidence"]) if "confidence" in row else None,
        recommendation=wire_enum(row["recommendation"], _RECOMMENDATIONS),
        evidence_complete=require_bool(row["evidence_complete"], "attribution completeness"),
        intent_accepted=require_bool(row["intent_accepted"], "attribution intent acceptance"),
    )
    _retained_identity(proof.candidate, observed)
    if (
        proof.rollback_snapshot_id == proof.candidate.snapshot_id
        or proof.baseline_tx_pps <= 0
        or len(proof.previous_workers) != observed.expected_workers
        or len(proof.current_workers) != observed.expected_workers
        or (proof.confidence is not None) != proof.evidence_complete
    ):
        raise JsonContractError("guardrails attribution identity, population, or baseline is invalid")
    for rows in (proof.previous_workers, proof.current_workers):
        for index, worker in enumerate(rows):
            if (
                worker.worker_index != index or worker.observation_epoch != proof.candidate.epoch
                or worker.publication_generation == 0 or worker.published_monotonic_ns == 0
                or not worker_counter_values_are_exact(worker)
            ):
                raise JsonContractError("guardrails attribution has a malformed worker endpoint")
        if any(sum(values) >= (1 << 64) - 1 for values in zip(*(worker.counter_values() for worker in rows))):
            raise JsonContractError("guardrails attribution contains exhausted aggregate counters")
    if not worker_counters_advanced(proof.previous_workers, proof.current_workers):
        raise JsonContractError("guardrails attribution lacks positive common source coverage")
    if proof.covered_duration_ns > wire_uint(policy["evaluation_window_ms"]) * 1_000_000:
        raise JsonContractError("guardrails attribution exceeds its policy window")
    attribution = policy["attribution"]
    expected = "GUARDRAILS_RECOMMENDATION_LOG_ONLY"
    if proof.evidence_complete:
        if proof.confidence >= attribution["auto_rollback_threshold"]:
            expected = "GUARDRAILS_RECOMMENDATION_AUTO_ROLLBACK"
        elif proof.confidence >= attribution["defer_threshold"]:
            expected = "GUARDRAILS_RECOMMENDATION_DEFER_TO_HUMAN"
    if proof.recommendation != expected or (
        proof.intent_accepted and expected != "GUARDRAILS_RECOMMENDATION_AUTO_ROLLBACK"
    ):
        raise JsonContractError("guardrails attribution recommendation or acceptance contradicts policy")
    return proof


def _evaluation(value: object, policy: Optional[dict], generation: int) -> GuardrailsEvaluation:
    """Keep absent evidence absent and reject readiness without its required baseline."""
    row = message_shape(value, frozenset({
        "state", "policy_generation", "baseline_intervals", "valid_observation_ns",
    }), frozenset({"observed_identity", "last_completed", "last_attribution"}))
    state = wire_enum(row["state"], _STATES)
    if wire_uint(row["policy_generation"]) != generation:
        raise JsonContractError("guardrails evaluation policy generation differs")
    baseline = wire_uint(row["baseline_intervals"], bits=32)
    elapsed = wire_uint(row["valid_observation_ns"])
    observed = _identity(row["observed_identity"]) if "observed_identity" in row else None
    enabled = policy is not None and policy["enabled"]
    if not enabled:
        expected = (
            "GUARDRAILS_EVALUATION_STATE_UNCONFIGURED" if policy is None else "GUARDRAILS_EVALUATION_STATE_DISABLED"
        )
        if (
            state not in {expected, "GUARDRAILS_EVALUATION_STATE_ROLLBACK_PENDING"}
            or baseline or elapsed or observed is not None
        ):
            raise JsonContractError("inactive guardrails evaluation retained active evidence")
    elif (
        state in {"GUARDRAILS_EVALUATION_STATE_UNCONFIGURED", "GUARDRAILS_EVALUATION_STATE_DISABLED"}
        or baseline > policy["telemetry_history_capacity"]
        or elapsed > wire_uint(policy["evaluation_window_ms"]) * 1_000_000
    ):
        raise JsonContractError("guardrails evaluation contradicts its policy bounds")
    if state in {"GUARDRAILS_EVALUATION_STATE_ARMED", "GUARDRAILS_EVALUATION_STATE_EVALUATING"} and (
        observed is None or baseline < policy["attribution"]["baseline_samples"]
    ):
        raise JsonContractError("guardrails readiness lacks its baseline")
    if state in {"GUARDRAILS_EVALUATION_STATE_BASELINE_BUILDING", "GUARDRAILS_EVALUATION_STATE_ARMED"} and elapsed:
        raise JsonContractError("guardrails baseline state retained candidate evaluation time")
    if observed is None and (baseline or elapsed or "last_completed" in row or "last_attribution" in row):
        raise JsonContractError("guardrails evaluation has evidence without an observed identity")
    completed = None
    if "last_completed" in row:
        terminal = message_shape(row["last_completed"], frozenset({"candidate", "valid_observation_ns", "outcome"}))
        completed = GuardrailsCompletedEvaluation(
            candidate=_identity(terminal["candidate"]),
            valid_observation_ns=wire_uint(terminal["valid_observation_ns"]),
            outcome=wire_enum(terminal["outcome"], _OUTCOMES),
        )
        _retained_identity(completed.candidate, observed)
        window_ns = wire_uint(policy["evaluation_window_ms"]) * 1_000_000
        if completed.valid_observation_ns > window_ns or (
            completed.outcome == "GUARDRAILS_EVALUATION_OUTCOME_WINDOW_COMPLETE"
            and completed.valid_observation_ns != window_ns
        ) or (
            completed.outcome == "GUARDRAILS_EVALUATION_OUTCOME_HISTORY_EXHAUSTED"
            and completed.valid_observation_ns == 0
        ):
            raise JsonContractError("guardrails completed window exceeds its authored bound")
    proof = _proof(row["last_attribution"], observed, policy) if "last_attribution" in row else None
    if proof is not None:
        matches_current = state == "GUARDRAILS_EVALUATION_STATE_EVALUATING" and proof.candidate == observed
        if (
            matches_current and proof.covered_duration_ns > elapsed
        ) or (
            completed is not None and completed.candidate == proof.candidate
            and proof.covered_duration_ns > completed.valid_observation_ns
        ):
            raise JsonContractError("guardrails attribution exceeds its recorded evaluation time")
    accepted_window = (
        completed is not None and completed.outcome == "GUARDRAILS_EVALUATION_OUTCOME_ROLLBACK_ACCEPTED"
    )
    if accepted_window and (
        proof is None or completed.valid_observation_ns == 0
        or proof.candidate.epoch < completed.candidate.epoch
    ):
        raise JsonContractError("guardrails accepted evaluation lacks its attribution proof")
    if accepted_window and proof.candidate.epoch == completed.candidate.epoch and (
        not proof.intent_accepted or proof.candidate != completed.candidate
    ):
        raise JsonContractError("guardrails accepted evaluation and attribution identities disagree")
    if proof is not None and proof.intent_accepted:
        if completed is None or completed.candidate.epoch < proof.candidate.epoch:
            raise JsonContractError("guardrails accepted attribution lacks its completed evaluation")
        if completed.candidate.epoch == proof.candidate.epoch and (
            not accepted_window or completed.candidate != proof.candidate
        ):
            raise JsonContractError("guardrails attribution and completed outcome disagree")
    return GuardrailsEvaluation(state, generation, observed, baseline, elapsed, completed, proof)


def parse_guardrails_json(raw_json: str) -> GuardrailsRead:
    """Admit one complete native GetGuardrails success or raise on any malformed evidence."""
    response = message_shape(parse_exact_json_object(raw_json, "guardrails read"), frozenset({
        "status", "policy_generation", "policy_hash",
    }), frozenset({"policy", "evaluation"}))
    parse_cli_success(raw_json, frozenset(response) - {"status"}, "guardrails read")
    generation = wire_uint(response["policy_generation"])
    if generation == (1 << 64) - 1 or (generation == 0) != ("policy" not in response):
        raise JsonContractError("guardrails read policy identity is incomplete")
    policy_hash = _wire_sha256(response["policy_hash"]) if generation else response["policy_hash"]
    if generation == 0 and policy_hash != "":
        raise JsonContractError("unconfigured guardrails retained a policy hash")
    policy = _policy(response["policy"]) if "policy" in response else None
    evaluation = _evaluation(response["evaluation"], policy, generation) if "evaluation" in response else None
    return GuardrailsRead(GuardrailsPolicyIdentity(generation, policy_hash), policy, evaluation, raw_json)
