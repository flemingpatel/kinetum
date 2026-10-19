"""Exercise the complete endpoint admission and cleanup program with a native API fixture."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

from kinetum_validation.traffic.trex_remote_script import REMOTE_TREX_SCRIPT
from tests.traffic_fixtures import complete_trex_identity, native_trex_port_info


class InstrumentClient:
    """Record actual fixture port claims separately from read-only observations."""

    def __init__(self, identity, partial_acquisition=False, partial_attributes=False, connection_failure=False):
        """Retain independently supplied capabilities and an optional native partial failure."""
        self.identity = copy.deepcopy(identity)
        self.partial_acquisition = partial_acquisition
        self.partial_attributes = partial_attributes
        self.connection_failure = connection_failure
        self.mutations = []
        self.acquired = []
        self.promiscuous = set()
        self.disconnect_arguments = None

    def _on_connect_clear_stats(self):
        """Model the native clear-on-connect hook that a read-only client must replace."""
        self.clear_stats()

    def connect(self):
        """Invoke the real hook boundary before any requested observation."""
        self._on_connect_clear_stats()
        if self.connection_failure:
            raise RuntimeError("injected connection failure")

    def get_server_version(self):
        """Return the externally supplied server identity without modifying counters."""
        return {"version": self.identity["version"], "mode": self.identity["mode"]}

    def get_port_info(self, ports):
        """Return only the requested native port-information rows."""
        return [row for row in native_trex_port_info(self.identity) if row["index"] in ports]

    def acquire(self, ports, force):
        """Inject a partial native claim or reject an unexpected mutating request."""
        self.mutations.append(("acquire", tuple(ports), force))
        if self.partial_acquisition:
            self.acquired = [ports[0]]
            raise RuntimeError("injected partial acquisition")
        if self.partial_attributes:
            self.acquired = list(ports)
            return
        raise RuntimeError("unexpected acquisition")

    def reset(self, ports):
        """Record reset of the already acquired port set."""
        if set(ports) != set(self.acquired):
            raise RuntimeError("resetting unclaimed ports")
        self.mutations.append(("reset", tuple(ports)))

    def set_port_attr(self, ports, promiscuous):
        """Model a changed attribute followed by failure, then exact restoration."""
        if not ports or not set(ports).issubset(self.acquired):
            raise RuntimeError("changing attributes without exact port ownership")
        self.mutations.append(("promiscuous", tuple(ports), promiscuous))
        if promiscuous:
            self.promiscuous.add(ports[0])
            raise RuntimeError("injected partial attribute change")
        self.promiscuous.difference_update(ports)

    def get_acquired_ports(self):
        """Return the exact acknowledged claim set, never the requested port set."""
        return list(self.acquired)

    def stop(self, ports):
        """Record stopping only ports that this client actually owns."""
        if not set(ports).issubset(self.acquired):
            raise RuntimeError("stopping an unclaimed port")
        self.mutations.append(("stop", tuple(ports)))

    def release(self, ports):
        """Retire acknowledged ownership after its traffic has stopped."""
        if not set(ports).issubset(self.acquired):
            raise RuntimeError("releasing an unclaimed port")
        self.mutations.append(("release", tuple(ports)))
        self.acquired = [port for port in self.acquired if port not in ports]

    def clear_stats(self):
        """Record a counter mutation so a read-only regression cannot pass."""
        self.mutations.append(("clear_stats",))

    def disconnect(self, stop_traffic, release_ports):
        """Record the exact disconnect policy without performing implicit retirement."""
        self.disconnect_arguments = (stop_traffic, release_ports)
        if stop_traffic or release_ports:
            self.mutations.append(("implicit retirement",))


class TestTRexEndpointAdmission(unittest.TestCase):
    """Run the full rendered program, including its real finally block."""

    def _execute(self, client, action, expected_identity=None, flows=1):
        """Supply JSON and a native API fixture while preserving process-global resources."""
        with tempfile.TemporaryDirectory() as temporary:
            work_dir = str(Path(temporary).resolve())
            spec = {
                "action": action, "ports": [0, 1, 2], "egress_ports": [2],
                "trex_server": "127.0.0.1", "trex_api_path": "", "work_dir": work_dir,
            }
            if action == "generation_start":
                spec.update({
                    "duration_s": 90.0, "pps": 400000, "packet_size": 1514,
                    "num_flows": flows, "src_ip": "10.0.0.1", "dst_ip": "198.51.100.9",
                    "sport": 10000, "dport": 20000,
                    "initial_generation_tag": 1, "next_generation_tag": 2,
                    "transition_time_s": 15.0, "overlap_window_ms": 60000,
                    "trex_identity": copy.deepcopy(expected_identity),
                    "ingress_streams": [
                        {"logical_name": f"wan{port}", "port_id": port,
                         "src_mac": f"02:00:00:00:00:0{port + 1}", "dst_mac": "00:11:22:33:44:55"}
                        for port in (0, 1)
                    ],
                })
            elif action == "exchange_udp":
                marker = b"e" * 16
                packet = bytes.fromhex("4500002c00000000401100000a000001c63364094e20c34f00180000") + marker
                spec.update({
                    "trex_identity": copy.deepcopy(expected_identity),
                    "ingress_stream": {
                        "logical_name": "wan0", "port_id": 0,
                        "src_mac": "02:00:00:00:00:01", "dst_mac": "00:11:22:33:44:55",
                    },
                    "packets": [packet.hex()], "capture_marker": marker.hex(),
                })

            def make_client(server):
                """Return the sole exact instrument endpoint requested by the program."""
                self.assertEqual(server, spec["trex_server"])
                return client

            def result_ok():
                """Represent the native successful callback result without a counter reset."""
                return True

            api = types.ModuleType("trex_stl_lib.api")
            api.STLClient = make_client
            for name in ("Ether", "IP", "Raw", "UDP", "STLFlowStats", "STLPktBuilder", "STLStream", "STLTXCont"):
                setattr(api, name, object)
            result_types = types.ModuleType("trex.common.trex_types")
            result_types.RC_OK = result_ok
            modules = {
                "trex_stl_lib": types.ModuleType("trex_stl_lib"),
                "trex_stl_lib.api": api,
                "trex": types.ModuleType("trex"),
                "trex.common": types.ModuleType("trex.common"),
                "trex.common.trex_types": result_types,
            }
            original_directory = os.getcwd()
            standard_output = io.StringIO()
            standard_error = io.StringIO()
            with io.TextIOWrapper(io.BytesIO(json.dumps(spec).encode("utf-8"))) as standard_input:
                try:
                    with (
                        mock.patch.dict(sys.modules, modules),
                        mock.patch.object(sys, "stdin", standard_input),
                        contextlib.redirect_stdout(standard_output),
                        contextlib.redirect_stderr(standard_error),
                        self.assertRaises(SystemExit) as terminal,
                    ):
                        exec(compile(REMOTE_TREX_SCRIPT, "<trex_endpoint>", "exec"), {})  # pylint: disable=exec-used
                finally:
                    os.chdir(original_directory)
            self.assertEqual(client.disconnect_arguments, (False, False))
            return terminal.exception.code, json.loads(standard_output.getvalue())

    def test_probe_is_read_only_through_connection_and_cleanup(self):
        """A successful setup probe never takes ports, resets counters, or changes attributes."""
        identity = complete_trex_identity()
        client = InstrumentClient(identity)
        code, result = self._execute(client, "probe")
        self.assertEqual(code, 0)
        self.assertEqual(result["trex_identity"], identity)
        self.assertEqual(client.mutations, [])

    def test_missing_connection_hook_rejects_before_native_connection(self):
        """An unsupported API cannot silently regain clear-on-connect behavior."""
        client = InstrumentClient(complete_trex_identity())
        with (
            mock.patch.object(client, "_on_connect_clear_stats", None),
            mock.patch.object(client, "connect") as connect,
        ):
            code, result = self._execute(client, "probe")
        self.assertNotEqual(code, 0)
        self.assertFalse(result["mutation_attempted"])
        self.assertIn("read-only connection hook", result["error"])
        connect.assert_not_called()
        self.assertEqual(client.mutations, [])

    def test_generation_admission_rejects_insufficient_or_changed_capability_without_effects(self):
        """All PGIDs must fit one receiving port before acquisition or cleanup can mutate it."""
        for changed in (False, True):
            with self.subTest(changed=changed):
                observed = complete_trex_identity()
                expected = complete_trex_identity(counters=1023, filter_mode="fetch all") if changed else observed
                client = InstrumentClient(observed)
                code, result = self._execute(client, "generation_start", expected, flows=64)
                self.assertNotEqual(code, 0)
                self.assertFalse(result["ok"])
                self.assertFalse(result["mutation_attempted"])
                self.assertIn("changed" if changed else "requires 256 distinct PGID", result["error"])
                self.assertEqual(client.mutations, [])

    def test_partial_acquisition_retires_only_the_acknowledged_prefix(self):
        """A failed native acquire cannot authorize cleanup of unclaimed observation ports."""
        identity = complete_trex_identity()
        client = InstrumentClient(identity, partial_acquisition=True)
        code, result = self._execute(client, "generation_start", identity)
        self.assertNotEqual(code, 0)
        self.assertTrue(result["mutation_attempted"])
        self.assertIn("partial acquisition", result["error"])
        self.assertEqual(client.mutations, [
            ("acquire", (0, 1, 2), True), ("stop", (0,)), ("release", (0,)),
        ])
        self.assertEqual(client.acquired, [])

    def test_exchange_rechecks_identity_without_requiring_pgid_counters(self):
        """NAT capture rechecks setup identity but consumes no flow-counter capacity."""
        for changed in (False, True):
            with self.subTest(changed=changed):
                observed = complete_trex_identity(counters=0)
                expected = copy.deepcopy(observed)
                if changed:
                    expected["ports"][-1]["driver"] = "different_driver"
                client = InstrumentClient(observed)
                code, result = self._execute(client, "exchange_udp", expected)
                self.assertNotEqual(code, 0)
                self.assertEqual(result["mutation_attempted"], not changed)
                self.assertIn("changed" if changed else "unexpected acquisition", result["error"])
                self.assertEqual(client.mutations, [] if changed else [("acquire", (0, 1, 2), True)])

    def test_partial_attribute_change_is_restored_before_releasing_ownership(self):
        """A mutating API failure does not mean that its attribute change was absent."""
        identity = complete_trex_identity()
        client = InstrumentClient(identity, partial_attributes=True)
        code, result = self._execute(client, "generation_start", identity)
        self.assertNotEqual(code, 0)
        self.assertTrue(result["mutation_attempted"])
        self.assertIn("partial attribute change", result["error"])
        self.assertEqual(client.mutations, [
            ("acquire", (0, 1, 2), True), ("reset", (0, 1, 2)), ("clear_stats",),
            ("promiscuous", (2,), True), ("stop", (0, 1, 2)),
            ("promiscuous", (2,), False), ("release", (0, 1, 2)),
        ])
        self.assertEqual(client.acquired, [])
        self.assertEqual(client.promiscuous, set())

    def test_failed_connection_still_retires_its_client_without_port_effects(self):
        """A failed connection remains owned through explicit nonmutating disconnect."""
        client = InstrumentClient(complete_trex_identity(), connection_failure=True)
        code, result = self._execute(client, "probe")
        self.assertNotEqual(code, 0)
        self.assertFalse(result["mutation_attempted"])
        self.assertIn("connection failure", result["error"])
        self.assertEqual(client.mutations, [])
