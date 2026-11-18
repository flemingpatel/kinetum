"""Verify completeness, phase fences and logical-port rate qualification."""

from dataclasses import replace
import copy
import json
from pathlib import Path
import tempfile
import unittest

from kinetum_validation.config.types import CONSTANTS, EpochConfig, epoch_window_has_capacity
from kinetum_validation.process.epoch_load import (
    EpochLoadPhase, require_epoch_load_artifact, validate_epoch_load_evidence,
)
from kinetum_validation.process.telemetry_validation import require_stream_observation

from .epoch_load_fixtures import load_snapshot, load_topology, qualified_load_evidence


class TestEpochLoad(unittest.TestCase):
    """Exercise rate verdicts only after their complete source evidence exists."""

    def test_artifact_recomputes_source_intervals_instead_of_trusting_flags(self):
        """Wrong policy, claimed rates, counter history or freshness cannot preserve success."""
        proof = qualified_load_evidence(Path("/tmp/epoch-proof"))
        self.assertTrue(validate_epoch_load_evidence(proof))
        for fault in (
            "unknown", "policy", "rate", "generation", "freshness", "verdict",
            "plan_hash", "validation_hash", "snapshot_id", "success_diagnostic", "failed_identity",
            "foreign_port", "later_observation", "omitted_interval", "omitted_seed",
        ):
            with self.subTest(fault=fault):
                damaged = copy.deepcopy(proof)
                phase = damaged["new"]
                if fault == "unknown":
                    phase["unexpected"] = True
                elif fault == "policy":
                    phase["required_intervals"] = 2
                elif fault == "rate":
                    phase["rates_pps"][0]["0"] += 1
                elif fault == "generation":
                    phase["samples"][1]["workers"][0]["publication_generation"] = (
                        phase["samples"][0]["workers"][0]["publication_generation"]
                    )
                elif fault == "freshness":
                    phase["samples"][0]["workers"][0]["observation_epoch"] = 1
                elif fault == "verdict":
                    phase["qualified"] = False
                elif fault in {"plan_hash", "validation_hash", "snapshot_id"}:
                    invalid = "x" * 257 if fault == "snapshot_id" else "not-a-sha256"
                    for item in (damaged["old"], damaged["new"]):
                        item["identity"][fault] = invalid
                        for endpoint in (item["barrier"], item["last_observation"], *item["samples"]):
                            endpoint["identity"][fault] = invalid
                    if fault == "snapshot_id":
                        damaged["apply"]["snapshot_id"] = invalid
                elif fault == "success_diagnostic":
                    damaged["apply"]["diagnostic"] = "failed"
                elif fault == "foreign_port":
                    for endpoint in (phase["barrier"], *phase["samples"]):
                        endpoint["streams"][0]["logical_port_id"] = 99
                elif fault == "later_observation":
                    phase["last_observation"]["collection_monotonic_ns"] += 1
                elif fault in {"omitted_interval", "omitted_seed"}:
                    kept = 3 if fault == "omitted_interval" else 0
                    phase["samples"] = phase["samples"][:kept]
                    phase["rates_pps"] = phase["rates_pps"][:max(0, kept - 1)]
                    phase["qualified"] = False
                    damaged.update(load_qualified=False, failure="load timed out")
                else:
                    damaged["apply"]["success"] = False
                    damaged.update(new=None, load_qualified=False, failure="Apply failed")
                with self.assertRaises(ValueError):
                    validate_epoch_load_evidence(damaged)

    def test_artifact_keeps_missing_and_foreign_run_evidence_distinct(self):
        """Missing failure evidence is allowed; successful or foreign evidence has exact ownership."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertIsNone(require_epoch_load_artifact(root, False, False))
            with self.assertRaisesRegex(ValueError, "omitted"):
                require_epoch_load_artifact(root, True, True)
            proof = qualified_load_evidence(root)
            path = root / "epoch_load.json"
            path.write_text(json.dumps(proof), encoding="utf-8")
            self.assertEqual(require_epoch_load_artifact(root, True, True), proof)
            proof["failure"] = "capture failed after qualification"
            path.write_text(json.dumps(proof), encoding="utf-8")
            self.assertIsNotNone(require_epoch_load_artifact(root, True, False))
            with self.assertRaisesRegex(ValueError, "contradicts"):
                require_epoch_load_artifact(root, True, True)
            proof["run_root"] = str(root / "foreign")
            path.write_text(json.dumps(proof), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different run"):
                require_epoch_load_artifact(root, True, False)
            path.unlink()
            path.symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "regular file"):
                require_epoch_load_artifact(root, False, False)

    def test_phased_workers_qualify_three_intervals_with_short_common_coverage(self):
        """One-second owner intervals remain valid with only 0.10 seconds of common coverage."""
        phase = EpochLoadPhase(load_topology(), load_snapshot(10), {0: 500, 1: 500})
        for step in (11, 12, 13, 14):
            self.assertFalse(phase.observe(load_snapshot(step)))
        self.assertTrue(phase.observe(load_snapshot(15)))
        evidence = phase.evidence()
        self.assertEqual(len(evidence["samples"]), 4)
        self.assertEqual(evidence["rates_pps"], [{"0": 500, "1": 500}] * 3)
        self.assertLess(
            min(row["published_monotonic_ns"] for row in evidence["samples"][1]["workers"])
            - max(row["published_monotonic_ns"] for row in evidence["samples"][0]["workers"]),
            CONSTANTS.EPOCH_LOAD_INTERVAL_MIN_NS,
        )
        with self.assertRaisesRegex(ValueError, "already complete"):
            phase.observe(load_snapshot(16))

    def test_repeated_observations_do_not_create_intervals(self):
        """Repeated polls preserve a single seed without inventing publication progress."""
        phase = EpochLoadPhase(load_topology(), load_snapshot(10), {0: 500, 1: 500})
        phase.observe(load_snapshot(11))
        phase.observe(load_snapshot(12))
        for _ in range(8):
            self.assertFalse(phase.observe(load_snapshot(12)))
        self.assertEqual(len(phase.evidence()["samples"]), 1)

    def test_completed_phase_checks_tail_continuity_without_requalifying_its_rate(self):
        """A lower tail rate is legal, but completed qualification cannot hide later counter regression."""
        phase = EpochLoadPhase(load_topology(), load_snapshot(10, epoch=2), {0: 500, 1: 500})
        for step in (11, 12, 13, 14, 15):
            phase.observe(load_snapshot(step, epoch=2))
        self.assertTrue(phase.complete)
        before = phase.evidence()
        phase.validate_observation(load_snapshot(16, epoch=2, counts=(7750, 7975)))
        self.assertEqual(phase.evidence(), before)
        for changed in (
            load_snapshot(16, epoch=2, counts=(7499, 7975)),
            load_snapshot(16, epoch=2, observation_epoch=1),
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                phase.validate_observation(changed)

    def test_resolution_waits_before_classifying_a_zero_rate(self):
        """Insufficient counter resolution waits even when a computed rate would miss its target."""
        phase = EpochLoadPhase(load_topology(), load_snapshot(10, rates=(0, 100)), {0: 100, 1: 100})
        for step in (11, 12, 13):
            self.assertFalse(phase.observe(load_snapshot(step, rates=(0, 100))))
        self.assertIsNone(phase.evidence()["last_rejected_interval"])
        self.assertFalse(phase.observe(load_snapshot(14, rates=(0, 100))))
        self.assertEqual(phase.evidence()["last_rejected_interval"]["reason"], "rate_out_of_band")

    def test_incomplete_interval_exceeding_ceiling_breaks_streak(self):
        """A low-resolution gap cannot become a long averaged rate window."""
        phase = EpochLoadPhase(load_topology(), load_snapshot(10, rates=(1, 1)), {0: 1, 1: 1})
        for step in (11, 12, 13, 14, 15):
            self.assertFalse(phase.observe(load_snapshot(step, rates=(1, 1))))
        self.assertIsNone(phase.evidence()["last_rejected_interval"])
        self.assertFalse(phase.observe(load_snapshot(16, rates=(1, 1))))
        self.assertEqual(phase.evidence()["last_rejected_interval"]["reason"], "excessive_gap")
        self.assertEqual(len(phase.evidence()["samples"]), 1)

    def test_common_coverage_is_a_completeness_condition(self):
        """Independent progress without common coverage waits until the interval bound expires."""
        offsets = (0, 4_000_000_000, 4_000_000_000)
        phase = EpochLoadPhase(load_topology(), load_snapshot(1, offsets=offsets), {0: 500, 1: 500})
        phase.observe(load_snapshot(2, offsets=offsets))
        phase.observe(load_snapshot(10, offsets=offsets))
        self.assertFalse(phase.observe(load_snapshot(11, offsets=offsets)))
        self.assertIsNone(phase.evidence()["last_rejected_interval"])
        self.assertFalse(phase.observe(load_snapshot(14, offsets=offsets)))
        self.assertEqual(phase.evidence()["last_rejected_interval"]["reason"], "excessive_gap")

    def test_rss_queues_are_combined_by_port_and_owner(self):
        """Uneven queue rates qualify when each logical ingress meets its own target."""
        arguments = {
            "rx_ports": (0, 0, 1), "rates": (400, 100, 500),
            "offsets": (0, 200_000_000, 400_000_000, 600_000_000),
        }
        phase = EpochLoadPhase(load_topology(arguments["rx_ports"]), load_snapshot(10, **arguments), {0: 500, 1: 500})
        for step in (11, 12, 13, 14):
            self.assertFalse(phase.observe(load_snapshot(step, **arguments)))
        self.assertTrue(phase.observe(load_snapshot(15, **arguments)))

    def test_one_ingress_cannot_hide_an_underproducing_peer(self):
        """A correct aggregate rate does not substitute for each port's rate band."""
        phase = EpochLoadPhase(load_topology(), load_snapshot(10, rates=(600, 400)), {0: 500, 1: 500})
        for step in (11, 12, 13):
            self.assertFalse(phase.observe(load_snapshot(step, rates=(600, 400))))
        self.assertEqual(phase.evidence()["last_rejected_interval"]["reason"], "rate_out_of_band")

    def test_regression_and_same_generation_mutation_are_rejected(self):
        """Counter history survives incomplete observations and cannot be reset to hide a contradiction."""
        for change in ("regression", "same_generation", "owner", "config"):
            with self.subTest(change=change):
                phase = EpochLoadPhase(load_topology(), load_snapshot(10), {0: 500, 1: 500})
                phase.observe(load_snapshot(11))
                current = load_snapshot(10 if change == "regression" else 12)
                if change == "same_generation":
                    current.worker_counters = [
                        replace(row, publication_generation=11) for row in current.worker_counters
                    ]
                elif change == "owner":
                    current.stream_stats[0] = replace(current.stream_stats[0], owning_region_id=1)
                elif change == "config":
                    current.active_revision += 1
                with self.assertRaises(ValueError):
                    phase.observe(current)

    def test_cross_epoch_progress_is_retained_but_cannot_form_a_rate_interval(self):
        """Cumulative continuity spans epochs while each rate phase retains its own identity."""
        old = load_snapshot(10)
        target = load_snapshot(11, epoch=3)
        require_stream_observation(load_topology(), old, target)
        old_phase = EpochLoadPhase(load_topology(), old, {0: 500, 1: 500})
        with self.assertRaises(ValueError):
            old_phase.observe(target)
        target_phase = EpochLoadPhase(load_topology(), target, {0: 500, 1: 500})
        self.assertFalse(target_phase.observe(target))
        self.assertFalse(target_phase.observe(target))
        self.assertEqual(target_phase.evidence()["samples"], [])

    def test_window_admission_preserves_the_tail_and_both_phases(self):
        """The default and physical windows fit, while an exact minimum leaves no control time."""
        self.assertEqual(EpochConfig.duration_s, 30)
        self.assertTrue(epoch_window_has_capacity(30, 5, 500, True))
        self.assertTrue(epoch_window_has_capacity(90, 15, 60000, True))
        self.assertFalse(epoch_window_has_capacity(12, 5, 500, True))
        self.assertFalse(epoch_window_has_capacity(75, 15, 60000, True))
        self.assertTrue(epoch_window_has_capacity(30, 5, 60000, False))
        self.assertFalse(epoch_window_has_capacity(30, 5, 1 << 4096, True))
        self.assertFalse(epoch_window_has_capacity(1 << 4096, 5, 500, True))
        self.assertFalse(epoch_window_has_capacity(30, True, 500, True))
