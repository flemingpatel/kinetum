"""Tests for exact process-supervisor readiness and retirement."""

import asyncio
import json
import unittest
from pathlib import Path
from unittest import mock

from kinetum_validation.config.types import ProcessConfig
from kinetum_validation.process.supervisor import AsyncProcessSupervisor
from kinetum_validation.process.kinetumctl import parse_health_ready


def _logging_status() -> dict:
    """Author every measured-zero counter explicitly for a valid health fixture."""
    return {
        "destination": "DESTINATION_STATE_AVAILABLE",
        "accepted_records": "0", "queue_rejections": "0",
        "format_rejections": "0", "unavailable_rejections": "0",
        "undelivered_records": "0", "write_failures": "0",
        "console_failures": "0", "truncated_records": "0", "failure": "",
        "packet_thread_rejections": "0", "delivery_timeouts": "0",
    }


def _dp_health(state: str) -> dict:
    """Author an exact DP readiness tuple independently of the reader."""
    packet_ready = state == "STATE_PACKET_READY"
    return {
        "state": state, "version": "0.1.0", "runtime_generation": "1",
        "status": {"code": 0, "error_code": "ERROR_CODE_OK", "message": "", "details": ""},
        "active_epoch": "2" if packet_ready else "0",
        "active_workers": 3 if packet_ready else 0, "expected_workers": 3,
        "logging": _logging_status(),
    }


class TestSupervisorReadiness(unittest.TestCase):
    """Require typed serving and packet authority with complete logging observations."""

    def test_control_ready_cannot_authorize_packet_traffic(self):
        """A complete control-ready tuple remains short of packet readiness."""
        self.assertFalse(parse_health_ready(json.dumps(_dp_health("STATE_CONTROL_READY")), "dp"))
        self.assertTrue(parse_health_ready(json.dumps(_dp_health("STATE_PACKET_READY")), "dp"))

    def test_logging_degradation_does_not_select_packet_readiness(self):
        """Lost diagnostics do not revoke independently proven packet authority."""
        response = _dp_health("STATE_PACKET_READY")
        response["logging"].update(
            destination="DESTINATION_STATE_UNAVAILABLE", write_failures="1", failure="append: errno=28",
        )
        self.assertTrue(parse_health_ready(json.dumps(response), "dp"))
        response["active_workers"] = 2
        with self.assertRaises(ValueError):
            parse_health_ready(json.dumps(response), "dp")

    def test_logging_counters_cannot_default_to_zero(self):
        """Each omitted counter rejects rather than becoming healthy zero evidence."""
        counters = set(_logging_status()) - {"destination", "failure"}
        for counter in counters:
            with self.subTest(counter=counter):
                response = _dp_health("STATE_PACKET_READY")
                del response["logging"][counter]
                with self.assertRaises(ValueError):
                    parse_health_ready(json.dumps(response), "dp")

    def test_cp_serving_and_logging_state_are_independent(self):
        """CP serving state stays authoritative while logging reports its own availability."""
        response = {"status": "STATUS_SERVING", "version": "0.1.0", "uptime_seconds": "1", "logging": _logging_status()}
        self.assertTrue(parse_health_ready(json.dumps(response), "cp"))
        response["status"] = "STATUS_NOT_SERVING"
        self.assertFalse(parse_health_ready(json.dumps(response), "cp"))
        response["status"] = "STATUS_UNSPECIFIED"
        with self.assertRaises(ValueError):
            parse_health_ready(json.dumps(response), "cp")


class TestTypedReadinessPoll(unittest.IsolatedAsyncioTestCase):
    """Only owned child roles followed by both typed RPC observations close startup."""

    async def test_waits_for_child_ownership_and_both_health_observations(self):
        """Intermediate ownership and health observations cannot admit traffic."""
        supervisor = AsyncProcessSupervisor(
            ProcessConfig(runtime_root=Path("/opt/kinetum"), validation_root=Path("/var/tmp/kinetum-validation")),
            Path("/tmp/kinetum-supervisor-test"),
        )
        process = mock.Mock(returncode=None, pid=100)
        cp = mock.Mock(is_ready=mock.AsyncMock(side_effect=[False, True, True]))
        dp = mock.Mock(is_ready=mock.AsyncMock(side_effect=[False, True]))
        with (
            mock.patch.object(supervisor, "_owned_children_started", side_effect=[False, True, True, True]),
            mock.patch("kinetum_validation.process.supervisor.KinetumCtl", side_effect=[cp, dp]),
            mock.patch("kinetum_validation.process.supervisor.asyncio.sleep", new_callable=mock.AsyncMock) as sleep,
        ):
            await supervisor._wait_runtime_ready(process)  # pylint: disable=protected-access
        self.assertEqual(cp.is_ready.await_count, 3)
        self.assertEqual(dp.is_ready.await_count, 2)
        self.assertEqual(sleep.await_count, 3)

    async def test_malformed_success_is_terminal(self):
        """Malformed successful health JSON cannot be treated as transient readiness."""
        supervisor = AsyncProcessSupervisor(
            ProcessConfig(runtime_root=Path("/opt/kinetum"), validation_root=Path("/var/tmp/kinetum-validation")),
            Path("/tmp/kinetum-supervisor-test"),
        )
        process = mock.Mock(returncode=None, pid=100)
        cp = mock.Mock(is_ready=mock.AsyncMock(side_effect=ValueError("missing logging counters")))
        dp = mock.Mock(is_ready=mock.AsyncMock(return_value=True))
        with (
            mock.patch.object(supervisor, "_owned_children_started", return_value=True),
            mock.patch("kinetum_validation.process.supervisor.KinetumCtl", side_effect=[cp, dp]),
        ):
            with self.assertRaisesRegex(ValueError, "missing logging counters"):
                await supervisor._wait_runtime_ready(process)  # pylint: disable=protected-access
        dp.is_ready.assert_not_awaited()


class _ExitedProcess:
    """Minimal process object that exited before harness-owned shutdown."""

    returncode = 0

    async def wait(self) -> int:
        """Return the already-owned terminal status."""
        return self.returncode


class TestSupervisorRetirement(unittest.IsolatedAsyncioTestCase):
    """An independently exited Photon cannot be reported as clean teardown."""

    async def test_pre_stop_exit_fails_after_complete_local_cleanup(self) -> None:
        """Even exit zero is a lifecycle failure when Photon dies early."""
        supervisor = AsyncProcessSupervisor(
            ProcessConfig(runtime_root=Path("/opt/kinetum"), validation_root=Path("/var/tmp/kinetum-validation")),
            Path("/tmp/kinetum-supervisor-test"),
        )
        process = _ExitedProcess()
        supervisor._processes["kinetum_photon"] = process  # pylint: disable=protected-access
        stream_task = asyncio.create_task(asyncio.sleep(0))
        await stream_task
        supervisor._stream_tasks["kinetum_photon"] = stream_task  # pylint: disable=protected-access

        with self.assertRaisesRegex(RuntimeError, "exited before"):
            await supervisor.stop("kinetum_photon")

        self.assertFalse(supervisor._processes)  # pylint: disable=protected-access
        self.assertFalse(supervisor._stream_tasks)  # pylint: disable=protected-access
