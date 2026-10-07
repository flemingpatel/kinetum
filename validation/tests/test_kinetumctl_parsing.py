"""Tests for exact protobuf-JSON runtime telemetry parsing."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from kinetum_validation.engine.json_contract import (
    JsonContractError,
    parse_exact_json_object,
)
from kinetum_validation.process.kinetumctl import KinetumCtl
from kinetum_validation.process.response_reader import parse_stats_json
from kinetum_validation.process.telemetry import StatsSelection


_FAULT_CODES = [
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
]

_SHA256_JSON = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


class TestKinetumctlMutationIdentity(unittest.IsolatedAsyncioTestCase):
    """Verify the wrapper carries exact commit-confirmed CLI identity."""

    async def test_statistics_selection_preserves_exact_native_options(self) -> None:
        """Optional row selection emits exactly its native CLI flags and preserves refusal."""
        complete = StatsSelection(
            include_stage_stats=True, include_module_metrics=True,
            include_module_health=True, include_worker_epoch_stats=True,
            include_region_epoch_stats=True, include_boundary_epoch_stats=True,
            include_stream_stats=True, include_storage_domain_stats=True,
            include_port_stats=True, include_topology_stats=True,
        )
        for selection, flags in (
            (StatsSelection(), []),
            (complete, [
                "--stage-stats", "--module-metrics", "--module-health",
                "--worker-epoch-stats", "--region-epoch-stats", "--boundary-epoch-stats",
                "--stream-stats", "--storage-domain-stats", "--port-stats", "--topology-stats",
            ]),
        ):
            with self.subTest(selection=selection):
                client = KinetumCtl(Path("/opt/kinetum"))
                invoke = AsyncMock(return_value=(1, "", "statistics unavailable"))
                client._run = invoke  # pylint: disable=protected-access
                result = await client.get_stats(selection)
                invoke.assert_awaited_once_with("stats", "--format", "json", *flags)
                self.assertFalse(result.success)
                self.assertEqual(result.diagnostic, "statistics unavailable")

    async def test_selected_topology_requires_complete_context_domains(self) -> None:
        """Unselected domains may be absent; requested domains must cover the admitted population."""
        for selected, included in ((False, False), (True, False), (True, True)):
            with self.subTest(selected=selected, included=included):
                payload = _full_stats_object()
                if not included:
                    payload["telemetry"].pop("module_context_domains")
                client = KinetumCtl(Path("/opt/kinetum"))
                client._run = AsyncMock(return_value=(0, json.dumps(payload), ""))  # pylint: disable=protected-access
                result = await client.get_stats(StatsSelection(include_topology_stats=selected))
                self.assertEqual(result.success, not selected or included, result.diagnostic)

    async def test_apply_parses_snapshot_revision_and_epoch_together(self) -> None:
        """A successful apply without its complete identity is not success."""
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.pbtxt"
            snapshot.write_text('snapshot_id: "snap"\n', encoding="utf-8")
            client = KinetumCtl(Path(directory))
            client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
                0,
                json.dumps({
                    "status": {"error_code": "ERROR_CODE_OK"},
                    "snapshot_id": "snap",
                    "revision": "0",
                    "epoch": "7",
                }),
                "",
            ))
            result = await client.apply_config_with_confirm(snapshot, 1000)
            self.assertTrue(result.success)
            self.assertEqual(result.snapshot_id, "snap")
            self.assertEqual(result.revision, 0)
            self.assertEqual(result.epoch, 7)
            self.assertEqual(result.diagnostic, "")

            client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
                0,
                json.dumps({"status": {"error_code": "ERROR_CODE_OK"}}),
                "",
            ))
            malformed = await client.apply_config_with_confirm(snapshot, 1000)
            self.assertFalse(malformed.success)

            client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
                0,
                '{"status":{"error_code":"ERROR_CODE_OK"},'
                '"snapshot_id":"snap","snapshot_id":"snap",'
                '"revision":"0","epoch":"7"}',
                "",
            ))
            duplicated = await client.apply_config_with_confirm(snapshot, 1000)
            self.assertFalse(duplicated.success)

            client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
                0,
                json.dumps({
                    "status": {"error_code": "ERROR_CODE_OK"},
                    "snapshot_id": "snap",
                    "revision": "9999999999999999",
                    "epoch": "7",
                }),
                "",
            ))
            oversized = await client.apply_config_with_confirm(snapshot, 1000)
            self.assertFalse(oversized.success)

    async def test_confirm_always_supplies_epoch_revision_and_one_call(self) -> None:
        """Confirm has no optional identity or wildcard path."""
        client = KinetumCtl(Path("/runtime"))
        invocation = AsyncMock(return_value=(
            0,
            json.dumps({
                "status": {"error_code": "ERROR_CODE_OK"},
                "snapshot_id": "snap",
                "time_remaining_ms": "10",
                "epoch": "7",
                "revision": "0",
            }),
            "",
        ))
        client._run = invocation  # pylint: disable=protected-access
        result = await client.confirm("snap", 7, 0)
        self.assertTrue(result.success)
        self.assertEqual(result.epoch, 7)
        self.assertEqual(result.revision, 0)
        self.assertEqual(result.time_remaining_ms, 10)
        self.assertEqual(result.diagnostic, "")
        invocation.assert_awaited_once_with(
            "confirm", "snap", "--epoch", "7", "--revision", "0",
            "--format", "json",
        )

        self.assertFalse((await client.confirm("snap", 0, 0)).success)
        self.assertFalse((await client.confirm("snap", 7, -1)).success)

        client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
            0,
            json.dumps({
                "status": {"error_code": "ERROR_CODE_OK"},
                "snapshot_id": "snap",
                "time_remaining_ms": "0",
                "epoch": "7",
                "revision": "0",
            }),
            "",
        ))
        self.assertFalse((await client.confirm("snap", 7, 0)).success)

        client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
            0,
            json.dumps({
                "status": {"error_code": "ERROR_CODE_OK"},
                "snapshot_id": "snap",
                "time_remaining_ms": "10",
                "epoch": "8",
                "revision": "0",
            }),
            "",
        ))
        self.assertFalse((await client.confirm("snap", 7, 0)).success)

    async def test_rollback_success_carries_identity_without_diagnostic(self) -> None:
        """A successful rollback result carries no failure-output residue."""
        client = KinetumCtl(Path("/runtime"))
        client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
            0,
            json.dumps({
                "status": {"error_code": "ERROR_CODE_OK"},
                "new_snapshot_id": "snap",
                "new_revision": "3",
                "epoch": "8",
            }),
            "retry 1/4\n",
        ))

        result = await client.rollback("snap", expected_revision=2)

        self.assertTrue(result.success)
        self.assertEqual(result.new_snapshot_id, "snap")
        self.assertEqual(result.new_revision, 3)
        self.assertEqual(result.epoch, 8)
        self.assertEqual(result.diagnostic, "")

    async def test_get_active_returns_exact_module_content(self) -> None:
        """Rollback validation can compare canonical module bytes directly."""
        client = KinetumCtl(Path("/runtime"))
        response = {
            "status": {"error_code": "ERROR_CODE_OK"},
            "snapshot": {
                "snapshot_id": "active.snapshot",
                "revision": "4",
                "created_unix_ms": "10",
                "modules": [{
                    "module_id": "kinetum.acl",
                    "revision": "4",
                    "config_blob": "e30=",
                    "content_type": "application/json",
                    "content_hash": (
                        "44136fa355b3678a1146ad16f7e8649e"
                        "94fb4fc21fe77e8310c060f61caaff8a"
                    ),
                }],
                "description": "active",
                "content_hash": "1" * 64,
            },
        }
        client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
            0, json.dumps(response), "retry 1/4\n"
        ))

        active = await client.get_active_snapshot()

        self.assertEqual(active.snapshot_id, "active.snapshot")
        self.assertEqual(active.revision, 4)
        self.assertEqual(active.modules[0].config_blob, b"{}")

        removed_tuning = copy.deepcopy(response)
        removed_tuning["snapshot"]["tuning"] = {}
        client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
            0, json.dumps(removed_tuning), ""
        ))
        with self.assertRaisesRegex(RuntimeError, "malformed success"):
            await client.get_active_snapshot()

        response["snapshot"]["modules"][0]["content_hash"] = "0" * 64
        client._run = AsyncMock(return_value=(  # pylint: disable=protected-access
            0, json.dumps(response), ""
        ))
        with self.assertRaisesRegex(RuntimeError, "malformed success"):
            await client.get_active_snapshot()

    async def test_successful_cli_may_retain_bounded_retry_diagnostics(self) -> None:
        """A retry diagnostic on stderr cannot erase canonical stdout success."""
        with tempfile.TemporaryDirectory() as directory:
            runtime_root = Path(directory)
            binary = runtime_root / "bin" / "kinetumctl"
            binary.parent.mkdir()
            binary.write_text(
                "#!/bin/sh\nprintf '%s\\n' '{\"ok\":true}'\n"
                "printf '%s\\n' 'retry 1/4' >&2\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            client = KinetumCtl(runtime_root)

            return_code, stdout, stderr = await client._run(  # pylint: disable=protected-access
                "health"
            )

            self.assertEqual(return_code, 0)
            self.assertEqual(stdout, '{"ok":true}\n')
            self.assertEqual(stderr, "retry 1/4\n")

    def test_decoded_lone_surrogates_are_not_utf8_evidence(self) -> None:
        """Python decoder permissiveness cannot admit unencodable strings."""
        for raw in (
            '{"value":"\\ud800"}',
            '{"\\ud800":"value"}',
            '{"value":["ok",{"nested":"\\udfff"}]}',
        ):
            with self.subTest(raw=raw), self.assertRaises(JsonContractError):
                parse_exact_json_object(raw, "surrogate fixture")
        self.assertEqual(
            parse_exact_json_object(
                '{"value":"\\ud83d\\ude00"}', "surrogate-pair fixture"
            ),
            {"value": "\U0001f600"},
        )


def _full_stats_object() -> dict:
    """Return one canonical successful control StatsResponse JSON object."""
    return {
        "status": {"error_code": "ERROR_CODE_OK"},
        "active_config": {
            "revision": "3",
            "snapshot_id": "snap_v3",
        },
        "telemetry": {
            "runtime": {
                "runtime_generation": "9",
                "status_publication_generation": "7",
                "active_epoch": "7",
                "minimum_retained_epoch": "7",
                "last_activated_epoch": "7",
                "active_workers": 2,
                "expected_workers": 2,
                "collection_monotonic_ns": "20000",
                "latest_bank_publication_monotonic_ns": "19000",
                "skipped_publications": "0",
            },
            "engine": {
                "rx_packets": "50000",
                "tx_packets": "49500",
                "dropped_packets": "500",
                "rx_bytes": "3200000",
                "tx_bytes": "3168000",
                "fanout_overflow": "2",
            },
            "transition": {
                "publication_generation": "8",
                "state": "EPOCH_TRANSITION_STATE_IDLE",
                "active_epoch": "7",
                "target_epoch": "0",
                "allocated_epoch_high_watermark": "7",
                "mutation_sequence_high_watermark": "11",
                "plan_content_hash": _SHA256_JSON,
                "active_validation_hash": _SHA256_JSON,
                "participant_set_frozen": False,
                "execution_participant_count": 2,
                "region_count": 2,
                "boundary_count": 1,
                "source_participant_count": 1,
                "sink_participant_count": 1,
                "module_context_count": 1,
                "quiescence_reader_count": 2,
                "terminal_history_size": 1,
                "retirement_frozen": False,
                "latest_terminal": {
                    "mutation_sequence": "11",
                    "from_epoch": "6",
                    "to_epoch": "7",
                    "validation_hash": _SHA256_JSON,
                    "idempotency_key_digest": _SHA256_JSON,
                    "admitted_monotonic_ns": "10000",
                    "prepared_monotonic_ns": "11000",
                    "commit_started_monotonic_ns": "12000",
                    "retiring_started_monotonic_ns": "13000",
                    "terminal_monotonic_ns": "18000",
                    "outcome": "EPOCH_TRANSITION_OUTCOME_COMPLETE",
                    "failure_code": "EPOCH_TRANSITION_FAILURE_CODE_NONE",
                    "retirement_frozen": False,
                },
                "certificate": {
                    "evaluated_monotonic_ns": "17000",
                    "runtime_generation": "9",
                    "transition_generation": "11",
                    "from_epoch": "6",
                    "to_epoch": "7",
                    "execution_complete": 2,
                    "execution_total": 2,
                    "boundary_complete": 1,
                    "boundary_total": 1,
                    "reader_complete": 2,
                    "reader_total": 2,
                    "fault_index": 4294967295,
                    "state": "EPOCH_CERTIFICATE_STATE_RECLAMATION_READY",
                    "fault": "EPOCH_CERTIFICATE_FAULT_NONE",
                },
                "grace": {
                    "generation": "4",
                    "started_monotonic_ns": "12000",
                    "completion_observed_monotonic_ns": "16000",
                    "finished_monotonic_ns": "17000",
                    "readers_complete": 2,
                    "readers_total": 2,
                    "active": False,
                    "update_frozen": False,
                },
            },
            "protocol_faults": {
                "transition_success_blocked": False,
                "counters": [
                    {"code": code, "count": "0"}
                    for code in _FAULT_CODES
                ],
            },
            "stages": [
                {
                    "stage_id": "rx",
                    "in_packets": "10000",
                    "out_packets": "10000",
                    "dropped_packets": "0",
                    "in_bytes": "640000",
                    "out_bytes": "640000",
                },
                {
                    "stage_id": "parse",
                    "in_packets": "10000",
                    "out_packets": "9900",
                    "dropped_packets": "100",
                    "in_bytes": "640000",
                    "out_bytes": "633600",
                },
            ],
            "module_counters": [
                {
                    "module_id": "kinetum.test",
                    "context_instance_id": "active@lane_0",
                    "context_index": 0,
                    "worker_index": 0,
                    "epoch": "7",
                    "name": "accepted",
                    "value": "99",
                },
            ],
            "module_histograms": [
                {
                    "module_id": "kinetum.test",
                    "context_instance_id": "active@lane_0",
                    "context_index": 0,
                    "worker_index": 0,
                    "epoch": "7",
                    "name": "latency",
                    "sample_count": "2",
                    "sample_sum": "30",
                    "minimum": "10",
                    "maximum": "20",
                    "p50": "10",
                    "p90": "20",
                    "p99": "20",
                    "p999": "20",
                },
            ],
            "module_epoch_mismatches": [
                {
                    "module_id": "kinetum.test",
                    "context_instance_id": "active@lane_0",
                    "context_index": 0,
                    "worker_index": 0,
                    "observation_epoch": "7",
                    "mismatch_count": "0",
                },
            ],
            "module_health": [
                {
                    "module_id": "kinetum.test",
                    "context_instance_id": "active@lane_0",
                    "context_index": 0,
                    "worker_index": 0,
                    "stage_instance_index": 1,
                    "state": "MODULE_HEALTH_STATE_SIGNAL_AVAILABLE",
                    "publication_generation": "3",
                    "observation_epoch": "7",
                    "observed_at_ns": "19000",
                    "callback_duration_ns": "25",
                    "contract_fault_count": "0",
                    "latest_fault_mask": 0,
                    "first_fault_mask": 0,
                    "health_score": 97,
                    "health_flags": 0,
                    "reason": "healthy",
                },
            ],
            "workers": [
                {
                    "worker_id": "worker_0",
                    "worker_index": 0,
                    "region_id": 0,
                    "lane_id": "lane_0",
                    "ledger_publication_generation": "20",
                    "active_epoch": "7",
                    "source_epoch": "7",
                    "active_unretired": "0",
                    "future_unretired": "0",
                    "activation_publication_generation": "2",
                    "transition_generation": "11",
                    "from_epoch": "6",
                    "to_epoch": "7",
                    "activation_monotonic_ns": "14000",
                    "activation_complete": True,
                },
                {
                    "worker_id": "worker_1",
                    "worker_index": 1,
                    "region_id": 1,
                    "lane_id": "lane_1",
                    "ledger_publication_generation": "21",
                    "active_epoch": "7",
                    "source_epoch": "7",
                    "active_unretired": "0",
                    "future_unretired": "0",
                    "activation_publication_generation": "2",
                    "transition_generation": "11",
                    "from_epoch": "6",
                    "to_epoch": "7",
                    "activation_monotonic_ns": "14100",
                    "activation_complete": True,
                },
            ],
            "regions": [
                {
                    "region_id": 0,
                    "worker_count": 1,
                    "minimum_active_epoch": "7",
                    "maximum_active_epoch": "7",
                    "minimum_source_epoch": "7",
                    "maximum_source_epoch": "7",
                    "active_unretired": "0",
                    "future_unretired": "0",
                    "activated_participants": 1,
                    "minimum_activation_monotonic_ns": "14000",
                    "maximum_activation_monotonic_ns": "14000",
                    "fanout_overflow": "1",
                },
                {
                    "region_id": 1,
                    "worker_count": 1,
                    "minimum_active_epoch": "7",
                    "maximum_active_epoch": "7",
                    "minimum_source_epoch": "7",
                    "maximum_source_epoch": "7",
                    "active_unretired": "0",
                    "future_unretired": "0",
                    "activated_participants": 1,
                    "minimum_activation_monotonic_ns": "14100",
                    "maximum_activation_monotonic_ns": "14100",
                    "fanout_overflow": "1",
                },
            ],
            "boundaries": [
                {
                    "boundary_id": "b_0_1",
                    "boundary_index": 0,
                    "from_stage_instance_index": 0,
                    "to_stage_instance_index": 1,
                    "sender_worker_index": 0,
                    "receiver_worker_index": 1,
                    "from_region_id": 0,
                    "to_region_id": 1,
                    "data_ring_capacity": 1024,
                    "future_output_hold_capacity": 1024,
                    "data_enqueued_sequence": "9900",
                    "data_dequeued_sequence": "9900",
                    "data_backpressure_events": "8",
                    "transition_generation": "11",
                    "from_epoch": "6",
                    "to_epoch": "7",
                    "cut_sequence": "9800",
                    "sender_phase": "BOUNDARY_SENDER_PHASE_OPEN",
                    "receiver_phase": "BOUNDARY_RECEIVER_PHASE_OPEN",
                    "duplicate_cut_count": "0",
                    "duplicate_ack_count": "0",
                    "cut_published_monotonic_ns": "12000",
                    "cut_observed_monotonic_ns": "12500",
                    "cut_drained_monotonic_ns": "13500",
                    "activation_monotonic_ns": "14000",
                    "ack_published_monotonic_ns": "14500",
                    "ack_observed_monotonic_ns": "15000",
                    "cut_delivery_duration_ns": "500",
                    "cut_drain_duration_ns": "1000",
                    "ack_gate_duration_ns": "3000",
                },
            ],
            "streams": [
                {
                    "io_stream_id": "wan0.rx.lane_0",
                    "logical_port_id": 1,
                    "direction": "IO_STREAM_DIRECTION_RX",
                    "owning_region_id": 0,
                    "worker_index": 0,
                    "driver_queue_id": 0,
                    "published_monotonic_ns": "19000",
                    "packets": "50000",
                    "bytes": "3200000",
                    "rejected_packets": "0",
                },
                {
                    "io_stream_id": "lan0.tx.lane_0",
                    "logical_port_id": 2,
                    "direction": "IO_STREAM_DIRECTION_TX",
                    "owning_region_id": 1,
                    "worker_index": 1,
                    "driver_queue_id": 0,
                    "published_monotonic_ns": "19000",
                    "packets": "49500",
                    "bytes": "3168000",
                    "rejected_packets": "0",
                },
            ],
            "storage_domains": [
                {
                    "storage_domain_id": "storage_dpdk_0",
                    "host_numa_node": 0,
                    "buffer_count": "131071",
                    "required_min_buffers": "12288",
                    "safety_margin": 64,
                    "observation_state":
                        "PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE",
                    "observed_monotonic_ns": "19800",
                    "in_use": "1024",
                    "available": "130047",
                },
            ],
            "ports": [
                {
                    "logical_port_id": 1,
                    "logical_name": "wan0",
                    "io_driver_instance_id": "io_dpdk_0",
                    "driver_port_id": "wan0",
                    "observation_state":
                        "PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT",
                    "observed_monotonic_ns": "19900",
                    "rx_packets": "1000",
                    "tx_packets": "0",
                    "rx_bytes": "64000",
                    "tx_bytes": "0",
                    "rx_missed": "2",
                    "rx_errors": "3",
                    "tx_errors": "0",
                    "rx_no_buffer": "0",
                },
                {
                    "logical_port_id": 2,
                    "logical_name": "lan0",
                    "io_driver_instance_id": "io_dpdk_0",
                    "driver_port_id": "lan0",
                    "observation_state":
                        "PROVIDER_OBSERVATION_STATE_UNSUPPORTED",
                },
            ],
            "steering_profiles": [
                {
                    "steering_profile_id": "steering.rss0",
                    "kind": "TRAFFIC_STEERING_KIND_RSS",
                    "symmetric": False,
                    "io_stream_ids": [
                        "lan0.tx.lane_0",
                        "wan0.rx.lane_0",
                    ],
                },
            ],
            "module_context_domains": [
                {
                    "module_id": "kinetum.test",
                    "context_instance_ids": ["active@lane_0"],
                },
            ],
        },
    }


def _full_stats_json() -> str:
    """Serialize the complete canonical fixture."""
    return json.dumps(_full_stats_object())


class TestKinetumctlStatsParsing(unittest.TestCase):
    """Regression tests for exact validation-side stats parsing."""

    def test_full_stats_success(self):
        """The complete canonical response parses successfully."""
        result = parse_stats_json(_full_stats_json())
        self.assertTrue(result.success)
        self.assertEqual(result.diagnostic, "")

    def test_full_stats_aggregate_counters(self):
        """Required runtime, engine, and active-config facts retain identity."""
        result = parse_stats_json(_full_stats_json())
        self.assertEqual(result.runtime_generation, 9)
        self.assertEqual(result.active_epoch, 7)
        self.assertEqual(result.active_snapshot_id, "snap_v3")
        self.assertEqual(result.active_revision, 3)
        self.assertEqual(result.rx_packets, 50000)
        self.assertEqual(result.tx_packets, 49500)
        self.assertEqual(result.dropped_packets, 500)
        self.assertEqual(result.fanout_overflow, 2)

    def test_transition_and_protocol_fault_summaries(self):
        """Typed transition and complete fault membership parse exactly."""
        result = parse_stats_json(_full_stats_json())
        self.assertEqual(result.transition_state, "EPOCH_TRANSITION_STATE_IDLE")
        self.assertIsNotNone(result.latest_terminal)
        self.assertEqual(result.latest_terminal.from_epoch, 6)
        self.assertEqual(result.latest_terminal.to_epoch, 7)
        self.assertEqual(result.latest_terminal.validation_hash, _SHA256_JSON)
        self.assertIsNotNone(result.certificate)
        self.assertEqual(result.certificate.execution_complete, 2)
        self.assertIsNotNone(result.grace)
        self.assertEqual(result.grace.readers_complete, 2)
        self.assertEqual(set(result.protocol_fault_counts), set(_FAULT_CODES))
        self.assertFalse(result.transition_success_blocked)

        malformed = _full_stats_object()
        malformed["telemetry"]["transition"]["participant_set_frozen"] = True
        self.assertFalse(parse_stats_json(json.dumps(malformed)).success)

    def test_full_stats_stage_stats(self):
        """Stage identities and terminal drop counts are preserved."""
        result = parse_stats_json(_full_stats_json())
        self.assertEqual(len(result.stage_stats), 2)
        self.assertEqual(result.stage_stats[1].stage_id, "parse")
        self.assertEqual(result.stage_stats[1].dropped_packets, 100)
        self.assertEqual(result.stage_stats[1].out_bytes, 633600)
        self.assertEqual(result.module_counter_stats[0].value, 99)
        self.assertEqual(result.module_histogram_stats[0].p99, 20)
        self.assertEqual(
            result.module_health_stats[0].state,
            "MODULE_HEALTH_STATE_SIGNAL_AVAILABLE",
        )

    def test_full_stats_boundary_epoch_stats(self):
        """Exact CUT identity, phases, sequences, and durations are preserved."""
        boundary = parse_stats_json(_full_stats_json()).boundary_epoch_stats[0]
        self.assertEqual(boundary.boundary_id, "b_0_1")
        self.assertEqual(boundary.transition_generation, 11)
        self.assertEqual(boundary.cut_sequence, 9800)
        self.assertEqual(boundary.data_enqueued_sequence, 9900)
        self.assertEqual(boundary.data_dequeued_sequence, 9900)
        self.assertEqual(boundary.cut_delivery_duration_ns, 500)
        self.assertEqual(boundary.cut_drain_duration_ns, 1000)
        self.assertEqual(boundary.ack_gate_duration_ns, 3000)

    def test_region_and_worker_epoch_stats(self):
        """Worker truth and its cold region derivation remain distinct."""
        result = parse_stats_json(_full_stats_json())
        self.assertEqual(result.worker_epoch_stats[0].worker_id, "worker_0")
        self.assertTrue(result.worker_epoch_stats[0].activation_complete)
        self.assertEqual(result.region_epoch_stats[0].minimum_active_epoch, 7)
        self.assertEqual(result.region_epoch_stats[0].activated_participants, 1)

    def test_stream_transfer_values_remain_present(self):
        """Software transfer counts retain their owner publication and explicit values."""
        stream = parse_stats_json(_full_stats_json()).stream_stats[0]
        self.assertEqual(stream.published_monotonic_ns, 19000)
        self.assertEqual(stream.direction, "rx")
        self.assertEqual(stream.packets, 50000)
        self.assertEqual(stream.bytes, 3200000)
        self.assertEqual(stream.rejected_packets, 0)

    def test_tx_acceptance_has_explicit_zero_rejections(self):
        """A TX row reports accepted ownership with a measured rejection count."""
        stream = parse_stats_json(_full_stats_json()).stream_stats[1]
        self.assertEqual(stream.published_monotonic_ns, 19000)
        self.assertEqual(stream.packets, 49500)
        self.assertEqual(stream.bytes, 3168000)
        self.assertEqual(stream.rejected_packets, 0)

    def test_stream_counters_require_explicit_zero_presence(self):
        """Zero is valid only when all required stream counter fields are present."""
        payload = _full_stats_object()
        for row in payload["telemetry"]["streams"]:
            for field in ("packets", "bytes", "rejected_packets"):
                row[field] = "0"
        for field in ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes"):
            payload["telemetry"]["engine"][field] = "0"
        self.assertTrue(parse_stats_json(json.dumps(payload)).success)
        for field in ("packets", "bytes", "rejected_packets"):
            with self.subTest(field=field):
                incomplete = copy.deepcopy(payload)
                del incomplete["telemetry"]["streams"][0][field]
                self.assertFalse(parse_stats_json(json.dumps(incomplete)).success)

    def test_summary_transfer_counts_exclude_the_exhaustion_marker(self):
        """Omitting stream details cannot turn exhausted engine totals into exact evidence."""
        fields = ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes")
        for field in fields:
            with self.subTest(field=field):
                payload = _full_stats_object()
                del payload["telemetry"]["streams"]
                for counter in fields:
                    payload["telemetry"]["engine"][counter] = str((1 << 64) - 2)
                self.assertTrue(parse_stats_json(json.dumps(payload)).success)
                payload["telemetry"]["engine"][field] = str((1 << 64) - 1)
                self.assertFalse(parse_stats_json(json.dumps(payload)).success)

    def test_stream_totals_and_publication_reject_contradictions(self):
        """Reject inconsistent transfer totals, exhausted counts, and foreign timestamps."""
        mutations = (
            ("packets", "49999"),
            ("bytes", "3199999"),
            ("rejected_packets", str((1 << 64) - 1)),
            ("published_monotonic_ns", "0"),
            ("published_monotonic_ns", "19001"),
            ("published_monotonic_ns", "20001"),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                payload = _full_stats_object()
                payload["telemetry"]["streams"][0][field] = value
                self.assertFalse(parse_stats_json(json.dumps(payload)).success)
        for field in ("observation_state", "observed_monotonic_ns", "errors"):
            with self.subTest(removed=field):
                payload = _full_stats_object()
                payload["telemetry"]["streams"][0][field] = "0"
                self.assertFalse(parse_stats_json(json.dumps(payload)).success)

    def test_full_stats_storage_domain_stats(self):
        """Approximate storage occupancy remains explicitly classified."""
        storage = parse_stats_json(_full_stats_json()).storage_domain_stats[0]
        self.assertEqual(storage.storage_domain_id, "storage_dpdk_0")
        self.assertEqual(
            storage.observation_state,
            "PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE",
        )
        self.assertEqual(storage.in_use, 1024)
        self.assertEqual(storage.available, 130047)

    def test_full_stats_port_stats(self):
        """Port identity and all native counters map exactly."""
        port = parse_stats_json(_full_stats_json()).port_stats[0]
        self.assertEqual(port.logical_name, "wan0")
        self.assertEqual(port.rx_packets, 1000)
        self.assertEqual(port.rx_missed, 2)
        self.assertEqual(port.rx_no_buffer, 0)

    def test_compiled_topology_uses_stable_ids(self):
        """Steering and module-context rows preserve their exact identities."""
        result = parse_stats_json(_full_stats_json())
        self.assertEqual(
            result.traffic_steering_stats[0].io_stream_ids,
            ["lan0.tx.lane_0", "wan0.rx.lane_0"],
        )
        self.assertEqual(
            result.module_context_domains[0].context_instance_ids,
            ["active@lane_0"],
        )

        explicit_null = _full_stats_object()
        explicit_null["telemetry"]["module_context_domains"][0][
            "context_instance_ids"
        ] = None
        self.assertFalse(parse_stats_json(json.dumps(explicit_null)).success)

    def test_absent_optional_rows_produce_empty_lists(self):
        """Unselected row families remain absent without weakening summaries."""
        data = _full_stats_object()
        for key in (
            "stages",
            "module_counters",
            "module_histograms",
            "module_epoch_mismatches",
            "module_health",
            "workers",
            "regions",
            "boundaries",
            "streams",
            "storage_domains",
            "ports",
            "steering_profiles",
            "module_context_domains",
        ):
            data["telemetry"].pop(key)
        result = parse_stats_json(json.dumps(data))
        self.assertTrue(result.success)
        self.assertEqual(result.stage_stats, [])
        self.assertEqual(result.boundary_epoch_stats, [])
        self.assertEqual(result.region_epoch_stats, [])

        explicit_null = _full_stats_object()
        explicit_null["telemetry"]["stages"] = None
        self.assertFalse(parse_stats_json(json.dumps(explicit_null)).success)

    def test_malformed_json(self):
        """Malformed JSON returns an explicit failed parse."""
        self.assertFalse(parse_stats_json("{not valid json").success)

    def test_empty_and_null_json(self):
        """Empty and null input cannot become zero-valued observations."""
        self.assertFalse(parse_stats_json("").success)
        self.assertFalse(parse_stats_json("null").success)

    def test_missing_required_family_fails_closed(self):
        """A successful wrapper may not omit a mandatory telemetry family."""
        data = _full_stats_object()
        del data["telemetry"]["protocol_faults"]
        self.assertFalse(parse_stats_json(json.dumps(data)).success)

        missing_hash = _full_stats_object()
        del missing_hash["telemetry"]["transition"]["active_validation_hash"]
        self.assertFalse(parse_stats_json(json.dumps(missing_hash)).success)

        malformed_hash = _full_stats_object()
        malformed_hash["telemetry"]["transition"]["active_validation_hash"] = "AA=="
        failed = parse_stats_json(json.dumps(malformed_hash))
        self.assertFalse(failed.success)
        self.assertEqual(failed.rx_packets, 0)
        self.assertEqual(failed.protocol_fault_counts, {})
        self.assertEqual(failed.stage_stats, [])

    def test_fault_membership_and_numeric_shape_fail_closed(self):
        """Duplicate identities and scalar coercions are rejected."""
        duplicate = _full_stats_object()
        duplicate["telemetry"]["protocol_faults"]["counters"][1]["code"] = (
            duplicate["telemetry"]["protocol_faults"]["counters"][0]["code"]
        )
        self.assertFalse(parse_stats_json(json.dumps(duplicate)).success)

        fractional = copy.deepcopy(_full_stats_object())
        fractional["telemetry"]["engine"]["rx_packets"] = 1.5
        self.assertFalse(parse_stats_json(json.dumps(fractional)).success)

        negative = copy.deepcopy(_full_stats_object())
        negative["telemetry"]["engine"]["rx_packets"] = -1
        self.assertFalse(parse_stats_json(json.dumps(negative)).success)

        oversized_generation = copy.deepcopy(_full_stats_object())
        oversized_generation["telemetry"]["runtime"][
            "runtime_generation"
        ] = str(1 << 32)
        self.assertFalse(
            parse_stats_json(json.dumps(oversized_generation)).success
        )

        reserved_epoch = copy.deepcopy(_full_stats_object())
        reserved_epoch["telemetry"]["transition"][
            "allocated_epoch_high_watermark"
        ] = str((1 << 64) - 1)
        self.assertFalse(parse_stats_json(json.dumps(reserved_epoch)).success)

        oversized_history = copy.deepcopy(_full_stats_object())
        oversized_history["telemetry"]["transition"][
            "terminal_history_size"
        ] = 65
        self.assertFalse(
            parse_stats_json(json.dumps(oversized_history)).success
        )

        negative_revision = copy.deepcopy(_full_stats_object())
        negative_revision["active_config"]["revision"] = "-1"
        self.assertFalse(
            parse_stats_json(json.dumps(negative_revision)).success
        )

        unicode_snapshot = copy.deepcopy(_full_stats_object())
        unicode_snapshot["active_config"]["snapshot_id"] = "snapshot.\u03bb"
        self.assertTrue(parse_stats_json(json.dumps(unicode_snapshot)).success)

        oversized_snapshot = copy.deepcopy(_full_stats_object())
        oversized_snapshot["active_config"]["snapshot_id"] = "\u03bb" * 129
        self.assertFalse(
            parse_stats_json(json.dumps(oversized_snapshot)).success
        )

        truthy = copy.deepcopy(_full_stats_object())
        truthy["telemetry"]["workers"][0]["activation_complete"] = "false"
        self.assertFalse(parse_stats_json(json.dumps(truthy)).success)

        duplicated_member = _full_stats_json().replace(
            '"status": {', '"status": {}, "status": {', 1
        )
        self.assertFalse(parse_stats_json(duplicated_member).success)

        status_residue = copy.deepcopy(_full_stats_object())
        status_residue["status"]["message"] = "not canonical success"
        self.assertFalse(parse_stats_json(json.dumps(status_residue)).success)

        removed_status_fields = copy.deepcopy(_full_stats_object())
        removed_status_fields["status"]["request_id"] = "old"
        self.assertFalse(
            parse_stats_json(json.dumps(removed_status_fields)).success
        )

        removed_active_tuning = copy.deepcopy(_full_stats_object())
        removed_active_tuning["active_config"]["tuning"] = {}
        self.assertFalse(
            parse_stats_json(json.dumps(removed_active_tuning)).success
        )

        missing_duration = copy.deepcopy(_full_stats_object())
        del missing_duration["telemetry"]["boundaries"][0][
            "cut_drain_duration_ns"
        ]
        self.assertFalse(parse_stats_json(json.dumps(missing_duration)).success)

        impossible_boundary_phase = copy.deepcopy(_full_stats_object())
        impossible_boundary_phase["telemetry"]["boundaries"][0][
            "sender_phase"
        ] = "BOUNDARY_SENDER_PHASE_WAITING_ACK"
        self.assertFalse(
            parse_stats_json(json.dumps(impossible_boundary_phase)).success
        )

        exhausted_boundary_sequence = copy.deepcopy(_full_stats_object())
        exhausted_boundary_sequence["telemetry"]["boundaries"][0][
            "data_enqueued_sequence"
        ] = str((1 << 64) - 1)
        self.assertFalse(
            parse_stats_json(
                json.dumps(exhausted_boundary_sequence)
            ).success
        )

        cut_ahead_of_data = copy.deepcopy(_full_stats_object())
        cut_ahead_of_data["telemetry"]["boundaries"][0][
            "cut_sequence"
        ] = "1600662"
        self.assertFalse(
            parse_stats_json(json.dumps(cut_ahead_of_data)).success
        )

        incomplete_approximate_storage = copy.deepcopy(_full_stats_object())
        incomplete_approximate_storage["telemetry"]["storage_domains"][0][
            "available"
        ] = "130046"
        self.assertFalse(
            parse_stats_json(json.dumps(incomplete_approximate_storage)).success
        )

        future_worker_activation = copy.deepcopy(_full_stats_object())
        future_worker_activation["telemetry"]["workers"][0][
            "transition_generation"
        ] = "12"
        self.assertFalse(
            parse_stats_json(json.dumps(future_worker_activation)).success
        )

        unknown_health_fault = copy.deepcopy(_full_stats_object())
        health = unknown_health_fault["telemetry"]["module_health"][0]
        health["contract_fault_count"] = "1"
        health["first_fault_mask"] = 1 << 4
        health["first_fault_epoch"] = "6"
        health["first_fault_timestamp_ns"] = "15000"
        health["first_fault_duration_ns"] = "10"
        self.assertFalse(
            parse_stats_json(json.dumps(unknown_health_fault)).success
        )

        stale_signal = copy.deepcopy(_full_stats_object())
        stale_signal["telemetry"]["module_health"][0][
            "observation_epoch"
        ] = "6"
        self.assertFalse(parse_stats_json(json.dumps(stale_signal)).success)

        first_fault_after_attempt = copy.deepcopy(_full_stats_object())
        health = first_fault_after_attempt["telemetry"]["module_health"][0]
        health["contract_fault_count"] = "1"
        health["first_fault_mask"] = 1
        health["first_fault_epoch"] = "8"
        health["first_fault_timestamp_ns"] = "19001"
        health["first_fault_duration_ns"] = "1"
        self.assertFalse(
            parse_stats_json(json.dumps(first_fault_after_attempt)).success
        )

        invalid_health_utf8 = copy.deepcopy(_full_stats_object())
        invalid_health_utf8["telemetry"]["module_health"][0][
            "reason"
        ] = "\ud800"
        self.assertFalse(
            parse_stats_json(json.dumps(invalid_health_utf8)).success
        )

        wrong_region_aggregate = copy.deepcopy(_full_stats_object())
        wrong_region_aggregate["telemetry"]["regions"][0][
            "minimum_active_epoch"
        ] = "6"
        self.assertFalse(
            parse_stats_json(json.dumps(wrong_region_aggregate)).success
        )

        wrong_region_fanout = copy.deepcopy(_full_stats_object())
        wrong_region_fanout["telemetry"]["regions"][0][
            "fanout_overflow"
        ] = "2"
        self.assertFalse(
            parse_stats_json(json.dumps(wrong_region_fanout)).success
        )

        early_certificate = copy.deepcopy(_full_stats_object())
        early_certificate["telemetry"]["transition"]["certificate"][
            "evaluated_monotonic_ns"
        ] = "11000"
        self.assertFalse(
            parse_stats_json(json.dumps(early_certificate)).success
        )

        mismatched_grace_start = copy.deepcopy(_full_stats_object())
        mismatched_grace_start["telemetry"]["transition"]["grace"][
            "started_monotonic_ns"
        ] = "12001"
        self.assertFalse(
            parse_stats_json(json.dumps(mismatched_grace_start)).success
        )

        future_terminal = copy.deepcopy(_full_stats_object())
        future_terminal["telemetry"]["transition"]["latest_terminal"][
            "terminal_monotonic_ns"
        ] = "20001"
        self.assertFalse(
            parse_stats_json(json.dumps(future_terminal)).success
        )

        terminal_before_retiring = copy.deepcopy(_full_stats_object())
        terminal_before_retiring["telemetry"]["transition"][
            "latest_terminal"
        ]["retiring_started_monotonic_ns"] = "18001"
        self.assertFalse(
            parse_stats_json(json.dumps(terminal_before_retiring)).success
        )

        failure_before_prepared = copy.deepcopy(_full_stats_object())
        transition = failure_before_prepared["telemetry"]["transition"]
        terminal = transition["latest_terminal"]
        terminal.update(
            {
                "mutation_sequence": "12",
                "from_epoch": "7",
                "to_epoch": "8",
                "failure_observed_monotonic_ns": "10500",
                "outcome": "EPOCH_TRANSITION_OUTCOME_ABORTED",
                "failure_code": "EPOCH_TRANSITION_FAILURE_CODE_EXPLICIT_ABORT",
            }
        )
        del terminal["commit_started_monotonic_ns"]
        del terminal["retiring_started_monotonic_ns"]
        transition["allocated_epoch_high_watermark"] = "8"
        transition["mutation_sequence_high_watermark"] = "12"
        del transition["certificate"]
        del transition["grace"]
        self.assertFalse(
            parse_stats_json(json.dumps(failure_before_prepared)).success
        )

        reversed_fault_identity = copy.deepcopy(_full_stats_object())
        fault_summary = reversed_fault_identity["telemetry"][
            "protocol_faults"
        ]
        fault_summary["counters"][0]["count"] = "1"
        fault_summary["transition_success_blocked"] = True
        fault_summary["first_fault"] = {
            "code": "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH",
            "disposition": (
                "EPOCH_PROTOCOL_FAULT_DISPOSITION_DROP_AND_RETIRE"
            ),
            "runtime_generation": "9",
            "from_epoch": "8",
            "to_epoch": "7",
            "observed_epoch": "8",
            "worker_index": 0,
            "boundary_index": (1 << 32) - 1,
            "context_index": (1 << 32) - 1,
            "stage_instance_index": (1 << 32) - 1,
            "observed_monotonic_ns": "19900",
        }
        self.assertFalse(
            parse_stats_json(json.dumps(reversed_fault_identity)).success
        )

        unowned_execution_fault = copy.deepcopy(_full_stats_object())
        fault_summary = unowned_execution_fault["telemetry"][
            "protocol_faults"
        ]
        fault_summary["counters"][0]["count"] = "1"
        fault_summary["transition_success_blocked"] = True
        fault_summary["first_fault"] = {
            "code": "EPOCH_PROTOCOL_FAULT_CODE_EPOCH_EXECUTION_MISMATCH",
            "disposition": (
                "EPOCH_PROTOCOL_FAULT_DISPOSITION_DROP_AND_RETIRE"
            ),
            "runtime_generation": "9",
            "observed_epoch": "6",
            "worker_index": (1 << 32) - 1,
            "boundary_index": (1 << 32) - 1,
            "context_index": (1 << 32) - 1,
            "stage_instance_index": (1 << 32) - 1,
            "observed_monotonic_ns": "19000",
        }
        self.assertFalse(
            parse_stats_json(json.dumps(unowned_execution_fault)).success
        )

        unsupported_steering = copy.deepcopy(_full_stats_object())
        unsupported_steering["telemetry"]["steering_profiles"][0][
            "kind"
        ] = "TRAFFIC_STEERING_KIND_EXPLICIT_TABLE"
        self.assertFalse(
            parse_stats_json(json.dumps(unsupported_steering)).success
        )

        unknown_stream_port = copy.deepcopy(_full_stats_object())
        unknown_stream_port["telemetry"]["streams"][0][
            "logical_port_id"
        ] = 99
        self.assertFalse(
            parse_stats_json(json.dumps(unknown_stream_port)).success
        )

        reordered_faults = copy.deepcopy(_full_stats_object())
        counters = reordered_faults["telemetry"]["protocol_faults"][
            "counters"
        ]
        counters[0], counters[1] = counters[1], counters[0]
        self.assertFalse(
            parse_stats_json(json.dumps(reordered_faults)).success
        )
