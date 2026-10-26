"""Run the complete TRex endpoint program against an observable, process-local API fixture."""

import json
from pathlib import Path
import sys
import time
import types
from unittest.mock import Mock

from kinetum_validation.traffic.trex_remote_script import REMOTE_TREX_SCRIPT
from tests.traffic_fixtures import complete_trex_identity, native_trex_port_info


class Packet:
    """Supply only Scapy's composition and header-length operations for lifecycle tests."""

    def __init__(self, *_arguments, **_keywords):
        """Accept packet-builder fields without constructing or transmitting a packet."""

    def __truediv__(self, _other):
        """Keep the synthetic Ethernet/IPv4/UDP composition together."""
        return self

    def __len__(self):
        """Return the Ethernet/IPv4/UDP header extent used by the payload builder."""
        return 42


class EndpointClient:
    """Expose port ownership and terminal cleanup independently of the local SSH lifetime."""

    def __init__(self, root: Path, mode: str):
        """Bind one trace file and a normal, waiting, hung, or cleanup-failing endpoint."""
        self.root = root
        self.mode = mode
        self.acquired = []
        self.ingress = []
        self.started = False
        self.identity = complete_trex_identity()

    def record(self, name, ports=()):
        """Publish each completed or explicitly attempted fixture API operation."""
        with (self.root / 'endpoint.jsonl').open('a', encoding='utf-8') as output:
            output.write(json.dumps([name, list(ports)]) + '\n')

    def _on_connect_clear_stats(self):
        """Reject the native hook unless the production reader replaces it."""
        raise AssertionError('unexpected connect-time counter reset')

    def connect(self):
        """Exercise the production read-only connection hook."""
        self._on_connect_clear_stats()

    def get_server_version(self):
        """Return the independently authored fixture identity."""
        return {'version': self.identity['version'], 'mode': 'STL'}

    def get_port_info(self, ports):
        """Project only the requested native capability rows."""
        return [row for row in native_trex_port_info(self.identity) if row['index'] in ports]

    def acquire(self, ports, force):
        """Acknowledge the complete requested claim before later mutations."""
        if not force or self.acquired:
            raise AssertionError('invalid fixture acquisition')
        self.acquired = list(ports)
        self.record('acquire', ports)

    def reset(self, ports):
        """Require ownership before resetting the selected ports."""
        if set(ports) != set(self.acquired):
            raise AssertionError('reset without exact ownership')

    def clear_stats(self):
        """Keep the fixture's initial absolute counters at zero."""

    def set_port_attr(self, ports, promiscuous):
        """Record observation setup and restoration under exact ownership."""
        if not set(ports).issubset(self.acquired):
            raise AssertionError('attribute mutation without ownership')
        self.record('promiscuous' if promiscuous else 'restore', ports)

    def add_streams(self, streams, ports):
        """Assign local stream identities without generating traffic."""
        if not set(ports).issubset(self.acquired):
            raise AssertionError('stream creation without ownership')
        return list(range(1, len(streams) + 1))

    def get_stats(self, ports):
        """Refresh no hardware; absolute fixture rows are exposed separately."""
        if not set(ports).issubset(self.acquired):
            raise AssertionError('statistics without ownership')
        return {}

    def get_port(self, port_id):
        """Return deterministic absolute counters for a completed fixture run."""
        counters = {'opackets': 0, 'ipackets': 0, 'oerrors': 0, 'ierrors': 0}
        if self.started and self.mode == 'complete':
            counters['opackets' if port_id in self.ingress else 'ipackets'] = 5 if port_id in self.ingress else 10
        return Mock(get_stats=Mock(return_value=counters))

    def start(self, ports, duration, force):
        """Publish readiness after the start is owned; optionally model an unresponsive RPC."""
        if not force or duration <= 0 or not set(ports).issubset(self.acquired):
            raise AssertionError('invalid fixture start')
        self.ingress = list(ports)
        self.started = True
        self.record('start', ports)
        (self.root / 'endpoint-started').touch()
        if self.mode == 'hang':
            time.sleep(30)

    def is_traffic_active(self, ports):
        """Keep the waiting run active until production cancellation handles it."""
        if ports != self.ingress:
            raise AssertionError('foreign active-port query')
        return self.mode != 'complete' and self.started

    def wait_on_traffic(self, ports, timeout):
        """Record the native receive-drain step after ordinary completion."""
        if self.is_traffic_active(ports) or timeout < 0:
            raise AssertionError('invalid native receive drain')
        self.record('rx-drain', ports)

    def get_acquired_ports(self):
        """Return acknowledged claims, independent of the requested port list."""
        return list(self.acquired)

    def stop(self, ports):
        """Stop only acknowledged ports, with an explicit negative cleanup control."""
        if not set(ports).issubset(self.acquired):
            raise AssertionError('stop without ownership')
        self.record('stop', ports)
        if self.mode == 'cleanup-failure':
            raise RuntimeError('injected endpoint stop failure')
        self.started = False

    def release(self, ports):
        """Retire claims only after traffic stopped."""
        if self.started or set(ports) != set(self.acquired):
            raise AssertionError('release before exact stop')
        self.record('release', ports)
        self.acquired = []

    def disconnect(self, stop_traffic, release_ports):
        """Record disconnect without hiding any unfinished ownership."""
        if stop_traffic or release_ports:
            raise AssertionError('implicit endpoint cleanup')
        self.record('disconnect')


def run_endpoint(root: Path, mode: str) -> None:
    """Execute the actual endpoint source with fake native calls and real input/output pipes."""
    client = EndpointClient(root, mode)
    api = types.ModuleType('trex_stl_lib.api')
    api.STLClient = Mock(return_value=client)
    for name in ('Ether', 'IP', 'Raw', 'UDP', 'STLFlowStats', 'STLPktBuilder', 'STLStream', 'STLTXCont'):
        setattr(api, name, Packet)
    result_types = types.ModuleType('trex.common.trex_types')
    result_types.RC_OK = Mock(return_value=True)
    sys.modules.update({
        'trex_stl_lib': types.ModuleType('trex_stl_lib'), 'trex_stl_lib.api': api,
        'trex': types.ModuleType('trex'), 'trex.common': types.ModuleType('trex.common'),
        'trex.common.trex_types': result_types,
    })
    exec(compile(REMOTE_TREX_SCRIPT, '<trex-endpoint>', 'exec'), {})  # pylint: disable=exec-used
