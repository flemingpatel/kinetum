"""Explicit native guardrails response fixtures shared by parsing and scenario tests."""

import base64
import hashlib


POLICY_HASH = base64.b64encode(b"p" * 32).decode("ascii")


def _identity(snapshot: str, epoch: int, revision: int) -> dict:
    """Author one complete single-worker content identity with a stable content hash."""
    return {
        "runtime_generation": "7", "snapshot_id": snapshot,
        "epoch": str(epoch), "revision": str(revision),
        "validation_hash": base64.b64encode(hashlib.sha256(snapshot.encode()).digest()).decode("ascii"),
        "expected_workers": 1,
    }


def _worker(timestamp: int, rx_packets: int, tx_packets: int, dropped: int) -> dict:
    """Author one candidate-epoch measurement with exact packet and byte totals."""
    return {
        "worker_index": 0, "observation_epoch": "2",
        "publication_generation": str(timestamp), "published_monotonic_ns": str(timestamp),
        "counters": {
            "rx_packets": str(rx_packets), "tx_packets": str(tx_packets), "dropped_packets": str(dropped),
            "rx_bytes": str(rx_packets * 64), "tx_bytes": str(tx_packets * 64), "fanout_overflow": "0",
        },
    }


def armed_guardrails_payload() -> dict:
    """Return a complete enabled threshold policy with an actually armed baseline projection."""
    return {
        "status": {"error_code": "ERROR_CODE_OK"},
        "policy_generation": "1", "policy_hash": POLICY_HASH,
        "policy": {
            "enabled": True, "poll_interval_ms": "100", "evaluation_window_ms": "10000",
            "telemetry_history_capacity": 100,
            "threshold": {"max_drop_ratio": 0.01, "min_tx_ratio": 0.99, "min_packets_per_window": "1"},
            "attribution": {
                "auto_rollback_threshold": 0.8, "defer_threshold": 0.5,
                "baseline_samples": 10, "degradation_threshold": 0.3,
            },
        },
        "evaluation": {
            "state": "GUARDRAILS_EVALUATION_STATE_ARMED", "policy_generation": "1",
            "observed_identity": _identity("v1", 1, 1), "baseline_intervals": 10,
            "valid_observation_ns": "0",
        },
    }


def rollback_guardrails_payload() -> dict:
    """Return accepted candidate proof retained after exact restoration of the baseline."""
    result = armed_guardrails_payload()
    evaluation = result["evaluation"]
    evaluation["state"] = "GUARDRAILS_EVALUATION_STATE_BASELINE_BUILDING"
    evaluation["observed_identity"] = _identity("v1", 3, 1)
    evaluation["baseline_intervals"] = 0
    evaluation["last_completed"] = {
        "candidate": _identity("guardrails-degradation", 2, 2),
        "valid_observation_ns": "200", "outcome": "GUARDRAILS_EVALUATION_OUTCOME_ROLLBACK_ACCEPTED",
    }
    evaluation["last_attribution"] = {
        "candidate": _identity("guardrails-degradation", 2, 2), "rollback_snapshot_id": "v1",
        "previous_workers": [_worker(1200, 100, 100, 0)],
        "current_workers": [_worker(1400, 200, 100, 100)],
        "baseline_tx_pps": 100_000_000.0, "confidence": 0.8285714285714286,
        "recommendation": "GUARDRAILS_RECOMMENDATION_AUTO_ROLLBACK",
        "evidence_complete": True, "intent_accepted": True,
    }
    return result
