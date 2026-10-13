"""Validate evaluator readiness, copied source measurements, and retained rollback evidence."""

import copy
import json
import unittest

from kinetum_validation.process.guardrails_observation import parse_guardrails_json

from .guardrails_fixtures import armed_guardrails_payload, rollback_guardrails_payload


class TestGuardrailsObservation(unittest.TestCase):
    """Reject malformed evidence without treating missing evaluation as disabled or armed."""

    def test_enabled_policy_does_not_imply_armed(self) -> None:
        """Policy-only success preserves evaluator absence; an armed row requires its sample floor."""
        payload = armed_guardrails_payload()
        armed = parse_guardrails_json(json.dumps(payload))
        self.assertEqual(armed.evaluation.state, "GUARDRAILS_EVALUATION_STATE_ARMED")
        self.assertEqual(armed.evaluation.baseline_intervals, 10)
        del payload["evaluation"]
        self.assertIsNone(parse_guardrails_json(json.dumps(payload)).evaluation)
        invalid = armed_guardrails_payload()
        invalid["evaluation"]["baseline_intervals"] = 9
        with self.assertRaises(ValueError):
            parse_guardrails_json(json.dumps(invalid))

    def test_retained_attribution_survives_restored_active_identity(self) -> None:
        """The proof remains bound to candidate epoch two after the active identity reaches epoch three."""
        read = parse_guardrails_json(json.dumps(rollback_guardrails_payload()))
        evaluation = read.evaluation
        self.assertEqual(evaluation.observed_identity.epoch, 3)
        self.assertEqual(evaluation.last_attribution.candidate.epoch, 2)
        self.assertTrue(evaluation.last_attribution.intent_accepted)
        self.assertEqual(evaluation.last_attribution.rates(), (0.0, 500_000_000.0))

    def test_missing_foreign_duplicate_and_changed_worker_endpoints_reject(self) -> None:
        """A copied attribution must retain a complete advancing vector in the candidate epoch."""
        for fault in ("missing", "duplicate", "foreign", "unchanged", "regression", "epoch", "time"):
            with self.subTest(fault=fault):
                payload = rollback_guardrails_payload()
                proof = payload["evaluation"]["last_attribution"]
                before = proof["previous_workers"][0]
                after = proof["current_workers"][0]
                if fault == "missing":
                    proof["current_workers"] = []
                elif fault == "duplicate":
                    proof["current_workers"].append(copy.deepcopy(after))
                elif fault == "foreign":
                    after["worker_index"] = 1
                elif fault == "unchanged":
                    after["publication_generation"] = before["publication_generation"]
                elif fault == "regression":
                    after["counters"]["tx_packets"] = "99"
                elif fault == "epoch":
                    after["observation_epoch"] = "3"
                else:
                    after["published_monotonic_ns"] = before["published_monotonic_ns"]
                with self.assertRaises(ValueError):
                    parse_guardrails_json(json.dumps(payload))

    def test_wrong_policy_namespace_or_acceptance_cannot_explain_rollback(self) -> None:
        """Policy generation, runtime identity, recommendation and accepted intent remain distinct checks."""
        for fault in ("policy", "runtime", "recommendation", "unaccepted", "completion", "missing_completion"):
            with self.subTest(fault=fault):
                payload = rollback_guardrails_payload()
                evaluation = payload["evaluation"]
                proof = evaluation["last_attribution"]
                if fault == "policy":
                    evaluation["policy_generation"] = "2"
                elif fault == "runtime":
                    proof["candidate"]["runtime_generation"] = "8"
                elif fault == "recommendation":
                    proof["recommendation"] = "GUARDRAILS_RECOMMENDATION_LOG_ONLY"
                elif fault == "unaccepted":
                    proof["intent_accepted"] = False
                elif fault == "missing_completion":
                    del evaluation["last_completed"]
                else:
                    evaluation["last_completed"]["candidate"]["snapshot_id"] = "foreign"
                with self.assertRaises(ValueError):
                    parse_guardrails_json(json.dumps(payload))

    def test_policy_window_and_poll_cadence_are_independent(self) -> None:
        """A read admits independent positive budgets without reviving ceil(window/poll)."""
        for poll, window in ((1000, 1), (1, 101_000)):
            with self.subTest(poll=poll, window=window):
                payload = armed_guardrails_payload()
                payload["policy"]["poll_interval_ms"] = str(poll)
                payload["policy"]["evaluation_window_ms"] = str(window)
                read = parse_guardrails_json(json.dumps(payload))
                self.assertEqual(read.evaluation.baseline_intervals, 10)

    def test_attribution_duration_fits_recorded_evaluation(self) -> None:
        """Source coverage cannot exceed the policy, current window, or retained completion."""
        for fault in ("completed", "policy", "current", "empty_history"):
            with self.subTest(fault=fault):
                payload = rollback_guardrails_payload()
                evaluation = payload["evaluation"]
                proof = evaluation["last_attribution"]
                if fault in {"policy", "current"}:
                    del evaluation["last_completed"]
                    proof["intent_accepted"] = False
                if fault == "current":
                    evaluation["state"] = "GUARDRAILS_EVALUATION_STATE_EVALUATING"
                    evaluation["observed_identity"] = copy.deepcopy(proof["candidate"])
                    evaluation["baseline_intervals"] = 10
                    evaluation["valid_observation_ns"] = "200"
                if fault == "empty_history":
                    del evaluation["last_attribution"]
                    evaluation["last_completed"]["outcome"] = "GUARDRAILS_EVALUATION_OUTCOME_HISTORY_EXHAUSTED"
                parse_guardrails_json(json.dumps(payload))
                if fault == "completed":
                    evaluation["last_completed"]["valid_observation_ns"] = "199"
                elif fault == "policy":
                    proof["current_workers"][0]["published_monotonic_ns"] = "10000001201"
                elif fault == "current":
                    evaluation["valid_observation_ns"] = "199"
                else:
                    evaluation["last_completed"]["valid_observation_ns"] = "0"
                with self.assertRaises(ValueError):
                    parse_guardrails_json(json.dumps(payload))

    def test_inconclusive_attribution_preserves_score_absence(self) -> None:
        """An unavailable confidence is absent rather than a synthetic zero score."""
        payload = rollback_guardrails_payload()
        del payload["evaluation"]["last_completed"]
        proof = payload["evaluation"]["last_attribution"]
        proof["intent_accepted"] = False
        proof["evidence_complete"] = False
        proof["recommendation"] = "GUARDRAILS_RECOMMENDATION_LOG_ONLY"
        with self.assertRaises(ValueError):
            parse_guardrails_json(json.dumps(payload))
        del proof["confidence"]
        parsed = parse_guardrails_json(json.dumps(payload))
        self.assertIsNone(parsed.evaluation.last_attribution.confidence)
        proof["evidence_complete"] = True
        with self.assertRaises(ValueError):
            parse_guardrails_json(json.dumps(payload))
