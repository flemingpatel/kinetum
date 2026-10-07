"""Self-contained endpoint program used by the TRex SSH transport."""

from __future__ import annotations

from ..engine.json_contract import MAX_JSON_DOCUMENT_CHARACTERS
from .base import EXCHANGE_PACKET_BYTES, EXCHANGE_PACKET_LIMIT, EXCHANGE_TIMEOUT_S


_REMOTE_TREX_SCRIPT_TEMPLATE = r"""
import contextlib
import ipaddress
import json
import math
import os
import struct
import sys
import time

JSON_DOCUMENT_CAPACITY = __KINETUM_JSON_DOCUMENT_CAPACITY__
EXCHANGE_PACKET_CAPACITY = __KINETUM_EXCHANGE_PACKET_LIMIT__
EXCHANGE_BYTE_CAPACITY = __KINETUM_EXCHANGE_PACKET_BYTES__
EXCHANGE_TIMEOUT_S = __KINETUM_EXCHANGE_TIMEOUT_S__


def emit(payload, code=0):
    '''Emit one terminal JSON result and exit with the requested status.'''
    print(json.dumps(payload, allow_nan=False, separators=(",", ":")))
    sys.exit(code)


def fail(message, code=1):
    '''Emit one typed failure envelope and terminate the endpoint action.'''
    emit({"ok": False, "error": message}, code)


def reject_duplicate_pairs(pairs):
    '''Build one JSON object while rejecting duplicate member names.'''
    result = {}
    for key, value in pairs:
        try:
            key.encode("utf-8")
        except UnicodeError:
            raise ValueError("remote-spec key is not valid UTF-8")
        if key in result:
            raise ValueError("duplicate remote-spec key: {}".format(key))
        result[key] = value
    return result


try:
    raw_spec = sys.stdin.buffer.read(JSON_DOCUMENT_CAPACITY + 1)
    if not raw_spec or len(raw_spec) > JSON_DOCUMENT_CAPACITY:
        raise ValueError("remote spec is empty or oversized")
    spec = json.loads(
        raw_spec.decode("utf-8"),
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError("non-finite JSON constant: {}".format(value))
        ),
    )
    if not isinstance(spec, dict):
        raise ValueError("remote spec is not an object")
except Exception as exc:  # pragma: no cover - endpoint-side defensive parsing
    fail("invalid remote spec: {}".format(exc), 2)

if "action" not in spec or not isinstance(spec["action"], str):
    fail("remote spec omitted its action", 2)
action = spec["action"]
run_base_keys = {
    "duration_s", "pps", "packet_size", "num_flows", "src_ip", "dst_ip",
    "sport", "dport", "ports", "ingress_streams",
    "egress_ports", "trex_server", "trex_api_path", "work_dir", "action",
}
packet_run_keys = run_base_keys | {"generation_tag"}
generation_run_keys = run_base_keys | {
    "initial_generation_tag", "next_generation_tag", "transition_time_s",
    "overlap_window_ms",
}
spec_keys = {
    "exchange_udp": {
        "action", "ports", "egress_ports", "trex_server", "trex_api_path", "work_dir",
        "ingress_stream", "packets", "capture_marker",
    },
    "probe": {
        "action", "ports", "egress_ports", "trex_server", "trex_api_path",
        "work_dir",
    },
    "run": packet_run_keys | {"mode"},
    "generation_start": generation_run_keys,
    "generation_resume_next": {
        "action", "ports", "ingress_ports", "generation_stream_ids",
        "trex_server", "trex_api_path", "work_dir",
    },
    "generation_pause_initial": {
        "action", "ports", "ingress_ports", "generation_stream_ids",
        "trex_server", "trex_api_path", "work_dir",
    },
    "generation_finish": generation_run_keys | {
        "ingress_ports", "generation_stream_ids", "generation_flow_plan",
        "port_counter_baseline",
        "start_time", "start_monotonic", "next_start_time",
        "next_start_monotonic", "initial_pause_time",
        "initial_pause_monotonic",
    },
    "generation_abort": {
        "action", "ports", "ingress_ports", "egress_ports", "trex_server",
        "trex_api_path", "work_dir",
    },
}
if action not in spec_keys or set(spec) != spec_keys[action]:
    fail("remote spec field membership is inexact", 2)


def exact_int(value, name, minimum, maximum):
    '''Return one exact integer inside the supplied inclusive domain.'''
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        fail(f"{name} is outside its exact integer domain", 2)
    return value


def exact_number(value, name, positive=False):
    '''Return one finite number with optional strict positivity.'''
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or (positive and float(value) <= 0.0)
    ):
        fail("{} is outside its exact numeric domain".format(name), 2)
    return float(value)


def exact_string(value, name, allow_empty=False):
    '''Return one bounded printable UTF-8 string.'''
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or (value and (not value.isprintable() or len(value.encode("utf-8")) > 4096))
    ):
        fail("{} is outside its exact string domain".format(name), 2)
    return value


def trex_identity(value):
    '''Return the bounded server-reported TRex version and stateless mode.'''
    if not isinstance(value, dict) or "version" not in value or "mode" not in value:
        fail("TRex server identity is incomplete", 1)
    version = exact_string(value["version"], "TRex server version")
    mode = exact_string(value["mode"], "TRex server mode")
    if not version.isascii() or len(version.encode("ascii")) > 128:
        fail("TRex server version is malformed", 1)
    if mode != "STL":
        fail("TRex server is not in stateless mode", 1)
    return {"version": version, "mode": mode}


def exact_ipv4(value, name):
    '''Return one canonical dotted-decimal IPv4 address.'''
    text = exact_string(value, name)
    try:
        parsed = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError:
        fail("{} is not an IPv4 address".format(name), 2)
    if str(parsed) != text:
        fail("{} is not canonical dotted-decimal IPv4".format(name), 2)
    return text


def exact_mac(value, name):
    '''Return one canonical lowercase colon-delimited MAC address.'''
    text = exact_string(value, name)
    parts = text.split(":")
    if len(parts) != 6 or any(
        len(part) != 2
        or not part.isascii()
        or any(character not in "0123456789abcdef" for character in part)
        for part in parts
    ):
        fail("{} is not a canonical lowercase MAC address".format(name), 2)
    return text


def exact_int_array(value, name):
    '''Return one unique uint32 identity array in authored order.'''
    if not isinstance(value, list):
        fail("{} is not an array".format(name), 2)
    result = [exact_int(item, name, 0, (1 << 32) - 1) for item in value]
    if len(result) != len(set(result)):
        fail("{} contains duplicate identities".format(name), 2)
    return result


def exact_generation_stream_ids(value, ingress_port_ids):
    '''Admit exact per-ingress-port initial and next stream ownership.'''
    if not isinstance(value, dict):
        fail("generation_stream_ids is not an object", 2)
    expected_ports = {str(port_id) for port_id in ingress_port_ids}
    if not value or set(value) != expected_ports:
        fail("generation_stream_ids has foreign port membership", 2)
    for port_text, row in value.items():
        if (
            not isinstance(port_text, str)
            or not port_text.isascii()
            or not port_text.isdecimal()
            or str(int(port_text)) != port_text
            or not isinstance(row, dict)
            or set(row) != {"initial", "next"}
        ):
            fail("generation_stream_ids row is malformed", 2)
        initial = exact_int_array(row["initial"], "initial stream ids")
        following = exact_int_array(row["next"], "next stream ids")
        if not initial or len(initial) != len(following):
            fail("generation_stream_ids cardinality is inexact", 2)
        if set(initial) & set(following):
            fail("generation stream identities overlap within a port", 2)
    return value


def exact_port_counters(value, port_ids):
    '''Admit one complete per-port uint64 packet and error snapshot.'''
    if not isinstance(value, dict) or set(value) != {str(port) for port in port_ids}:
        fail("port counters have inexact port membership", 2)
    for port_text, row in value.items():
        if not isinstance(row, dict) or set(row) != {"opackets", "ipackets", "oerrors", "ierrors"}:
            fail("port counter row has inexact field membership", 2)
        for field, count in row.items():
            exact_int(count, f"port {port_text} {field}", 0, (1 << 64) - 1)
    return value

def exchange_input():
    '''Admit one bounded marked datagram prefix and its exact ingress endpoint.'''
    ingress = spec["ingress_stream"]
    if not isinstance(ingress, dict) or set(ingress) != {"logical_name", "port_id", "src_mac", "dst_mac"}:
        fail("UDP exchange ingress is malformed", 2)
    exact_string(ingress["logical_name"], "UDP exchange logical ingress")
    port = exact_int(ingress["port_id"], "UDP exchange port", 0, (1 << 32) - 1)
    if port not in ports or port in spec["egress_ports"] or not spec["egress_ports"]:
        fail("UDP exchange port ownership is inexact", 2)
    exact_mac(ingress["src_mac"], "UDP exchange source MAC")
    exact_mac(ingress["dst_mac"], "UDP exchange destination MAC")
    encoded_packets = spec["packets"]
    if not isinstance(encoded_packets, list) or not 0 < len(encoded_packets) <= EXCHANGE_PACKET_CAPACITY:
        fail("UDP exchange packet count is outside its bound", 2)
    try:
        marker_text = exact_string(spec["capture_marker"], "UDP exchange marker")
        marker = bytes.fromhex(marker_text)
        packets = [bytes.fromhex(exact_string(value, "UDP exchange packet")) for value in encoded_packets]
    except ValueError:
        fail("UDP exchange bytes are not hexadecimal", 2)
    if len(marker) != 16 or marker.hex() != marker_text or [packet.hex() for packet in packets] != encoded_packets:
        fail("UDP exchange byte encoding is noncanonical", 2)
    for packet in packets:
        if (not 44 <= len(packet) <= EXCHANGE_BYTE_CAPACITY or packet[0] != 0x45 or packet[9] != 17
                or int.from_bytes(packet[2:4], "big") != len(packet)
                or int.from_bytes(packet[24:26], "big") != len(packet) - 20 or packet[28:44] != marker):
            fail("UDP exchange datagram is incomplete or unmarked", 2)
    return ingress, packets, marker


ports = exact_int_array(spec["ports"], "ports")
exact_string(spec["trex_server"], "trex_server")
exact_string(spec["trex_api_path"], "trex_api_path", allow_empty=True)
exact_string(spec["work_dir"], "work_dir")
if "egress_ports" in spec:
    egress_ports = exact_int_array(spec["egress_ports"], "egress_ports")
    if any(port_id not in ports for port_id in egress_ports):
        fail("egress_ports are not members of ports", 2)
if action == "exchange_udp":
    exchange_ingress, exchange_packets, exchange_marker = exchange_input()
if action in {"run", "generation_start", "generation_finish"}:
    duration_s = exact_number(spec["duration_s"], "duration_s", positive=True)
    pps = exact_int(spec["pps"], "pps", 1, 1000000000)
    exact_int(spec["packet_size"], "packet_size", 64, 9000)
    num_flows = exact_int(
        spec["num_flows"], "num_flows", 1, 65535 - 10000 + 1
    )
    sport = exact_int(spec["sport"], "sport", 1, 65535)
    exact_int(spec["dport"], "dport", 1, 65535)
    if (
        pps * duration_s < 1.0
        or pps * duration_s > (1 << 64) - 1
        or sport + num_flows - 1 > 65535
    ):
        fail("TRex run extent or flow source-port range overflows", 2)
    if action == "run":
        exact_int(spec["generation_tag"], "generation_tag", 0, 65535)
    exact_ipv4(spec["src_ip"], "src_ip")
    exact_ipv4(spec["dst_ip"], "dst_ip")
    if not isinstance(spec["ingress_streams"], list):
        fail("ingress_streams is not an array", 2)
    stream_ports = []
    for stream in spec["ingress_streams"]:
        if not isinstance(stream, dict) or set(stream) != {
            "logical_name", "port_id", "src_mac", "dst_mac"
        }:
            fail("TRex ingress stream shape is inexact", 2)
        stream_port = exact_int(stream["port_id"], "stream port_id", 0, (1 << 32) - 1)
        exact_string(stream["logical_name"], "stream logical_name")
        exact_mac(stream["src_mac"], "stream src_mac")
        exact_mac(stream["dst_mac"], "stream dst_mac")
        stream_ports.append(stream_port)
    if len(stream_ports) != len(set(stream_ports)) or any(
        port_id not in ports for port_id in stream_ports
    ):
        fail("TRex ingress stream ownership is inexact", 2)
    if 1000 + len(stream_ports) * num_flows * 2 > (1 << 32) - 1:
        fail("TRex generated PGID range overflows", 2)
    if action in {"run", "generation_start"} and not stream_ports:
        fail("TRex run requires at least one ingress stream", 2)
if action == "run":
    if exact_string(spec["mode"], "mode") not in {"standard", "timed"}:
        fail("one-shot TRex mode is undeclared", 2)
if action in {"generation_start", "generation_finish"}:
    initial_generation_tag = exact_int(
        spec["initial_generation_tag"], "initial_generation_tag", 0, 65535
    )
    next_generation_tag = exact_int(
        spec["next_generation_tag"], "next_generation_tag", 0, 65535
    )
    transition_s = exact_number(
        spec["transition_time_s"], "transition_time_s", positive=True
    )
    overlap_window_ms = exact_int(
        spec["overlap_window_ms"], "overlap_window_ms", 1, (1 << 32) - 1
    )
    if (
        initial_generation_tag == next_generation_tag
        or transition_s >= duration_s
        or transition_s + overlap_window_ms / 1000.0 >= duration_s
        or pps * (duration_s + overlap_window_ms / 1000.0) > (1 << 64) - 1
    ):
        fail("generation request timing or tag identity is inexact", 2)
if action in {
    "generation_resume_next", "generation_pause_initial", "generation_finish"
}:
    ingress_ports = exact_int_array(spec["ingress_ports"], "ingress_ports")
    if not ingress_ports or any(port_id not in ports for port_id in ingress_ports):
        fail("generation stream ingress membership is inexact", 2)
    exact_generation_stream_ids(spec["generation_stream_ids"], ingress_ports)
if action == "generation_finish":
    exact_port_counters(spec["port_counter_baseline"], ports)
    exact_number(spec["start_time"], "start_time", positive=True)
    next_start = exact_number(
        spec["next_start_monotonic"], "next_start_monotonic", positive=True
    )
    start_sample = exact_number(
        spec["start_monotonic"], "start_monotonic", positive=True
    )
    initial_pause = exact_number(
        spec["initial_pause_monotonic"], "initial_pause_monotonic", positive=True
    )
    exact_number(spec["next_start_time"], "next_start_time", positive=True)
    exact_number(spec["initial_pause_time"], "initial_pause_time", positive=True)
    if next_start <= start_sample or initial_pause <= next_start:
        fail("generation_finish overlap timestamps regress", 2)
    if not isinstance(spec["generation_flow_plan"], list) or not spec[
        "generation_flow_plan"
    ]:
        fail("generation_flow_plan is not a nonempty array", 2)
if action == "generation_abort":
    ingress_ports = exact_int_array(spec["ingress_ports"], "ingress_ports")
    if not ingress_ports or any(port_id not in ports for port_id in ingress_ports):
        fail("generation_abort ingress membership is inexact", 2)

work_dir = spec["work_dir"]
try:
    if (
        not isinstance(work_dir, str)
        or not work_dir.startswith("/")
        or not os.path.isdir(work_dir)
        or os.path.realpath(work_dir) != work_dir
    ):
        raise ValueError("work_dir is not an exact existing directory")
    os.chdir(work_dir)
except Exception as exc:  # pragma: no cover - endpoint filesystem dependent
    fail("failed to enter TRex work_dir {}: {}".format(work_dir, exc), 2)

api_path = spec["trex_api_path"]
if api_path:
    if (
        not isinstance(api_path, str)
        or not api_path.startswith("/")
        or not os.path.isdir(api_path)
        or os.path.realpath(api_path) != api_path
    ):
        fail("TRex API path is not an exact existing directory", 2)
    sys.path.insert(0, api_path)

try:
    from trex_stl_lib.api import (
        Ether,
        IP,
        Raw,
        UDP,
        STLClient,
        STLFlowStats,
        STLPktBuilder,
        STLStream,
        STLTXCont,
    )
except Exception as exc:  # pragma: no cover - depends on endpoint image
    fail("failed to import TRex stateless API: {}".format(exc), 2)

try:
    from trex.common.trex_types import RC_OK
except Exception as exc:  # pragma: no cover - depends on endpoint image
    fail("failed to import exact TRex result type: {}".format(exc), 2)

def stat_value(stats, port_id, field):
    '''Read one exact nonnegative TRex port statistic.'''
    candidates = [key for key in (port_id, str(port_id)) if key in stats]
    if len(candidates) != 1 or not isinstance(stats[candidates[0]], dict):
        fail(f"TRex stats omitted exact port {port_id}", 1)
    entry = stats[candidates[0]]
    if field not in entry:
        fail(f"TRex stats omitted {field} for port {port_id}", 1)
    value = entry[field]
    if not isinstance(value, int) or isinstance(value, bool):
        fail(f"TRex {field} for port {port_id} is malformed", 1)
    if value < 0:
        fail(f"TRex {field} for port {port_id} is negative", 1)
    return value


def absolute_port_counters(client, port_ids):
    '''Read refreshed port counters without the client's clear_stats baseline.

    The caller first refreshes through get_stats(sync_now=True). PortStats.get
    reads the absolute value; get_stats' returned port rows subtract a reference
    that belongs only to that Python client and does not survive reconnects.
    '''
    counters = {}
    for port_id in port_ids:
        stats = client.get_port(port_id).get_stats()
        counters[str(port_id)] = {
            field: stats.get(field)
            for field in ("opackets", "ipackets", "oerrors", "ierrors")
        }
    return exact_port_counters(counters, port_ids)


def port_counter_deltas(current, baseline):
    '''Subtract admitted snapshots, rejecting a reset or regression per counter.'''
    deltas = {}
    for port_text, row in current.items():
        deltas[port_text] = {}
        for field, count in row.items():
            initial = baseline[port_text][field]
            if count < initial:
                fail(
                    f"TRex port {port_text} {field} regressed: start={initial} finish={count}",
                    1,
                )
            deltas[port_text][field] = count - initial
    return deltas


def payload(packet_size, generation_tag):
    '''Build the exact generation-tag payload for one packet profile.'''
    header = (
        b"KINETUM"
        + (0).to_bytes(4, "big")
        + int(generation_tag).to_bytes(2, "big")
        + struct.pack(">d", time.time())
    )
    base = Ether() / IP() / UDP() / Raw(load=b"")
    payload_len = packet_size - len(base)
    if payload_len < len(header):
        fail("TRex packet size cannot carry the generation header", 2)
    return header + (b"X" * (payload_len - len(header)))


def port_counter(counter_map, port_id):
    '''Read one exact nonnegative flow counter for a port.'''
    if not isinstance(counter_map, dict):
        fail("TRex flow counter is not an object", 1)
    candidates = [key for key in (port_id, str(port_id)) if key in counter_map]
    if len(candidates) != 1:
        fail("TRex flow counter omitted exact port {}".format(port_id), 1)
    value = counter_map[candidates[0]]
    if not isinstance(value, int) or isinstance(value, bool):
        fail("TRex flow counter for port {} is malformed".format(port_id), 1)
    if value < 0:
        fail("TRex flow counter for port {} is negative".format(port_id), 1)
    return value


def sum_port_counters(counter_map, port_ids):
    '''Sum exact counters over the complete requested port membership.'''
    return sum(port_counter(counter_map, port_id) for port_id in port_ids)


def stream_ids_from_add_result(result, expected_count):
    '''Normalize one exact unique stream-ID result or return no identity.'''
    if (
        not isinstance(result, list)
        or len(result) != expected_count
        or not all(
            isinstance(value, int) and not isinstance(value, bool)
            and 0 <= value <= (1 << 32) - 1
            for value in result
        )
        or len(result) != len(set(result))
    ):
        return []
    return list(result)


def flow_stat_entry(flow_stats, pg_id):
    '''Return one exact PGID statistics row when uniquely represented.'''
    if not isinstance(flow_stats, dict):
        return None
    candidates = [key for key in (pg_id, str(pg_id)) if key in flow_stats]
    if len(candidates) != 1 or not isinstance(flow_stats[candidates[0]], dict):
        return None
    return flow_stats[candidates[0]]


def flow_spec(spec, flow_id):
    '''Derive one flow-specific source port from the admitted run spec.'''
    flow = dict(spec)
    flow["sport"] = int(spec["sport"]) + int(flow_id)
    if int(flow["sport"]) > 65535:
        fail("TRex flow source port exceeds 65535 for flow {}".format(flow_id), 2)
    return flow


def flow_count(spec):
    '''Return the admitted positive flow population.'''
    try:
        count = int(spec["num_flows"])
    except (TypeError, ValueError):
        fail("TRex num_flows must be an integer", 2)
    if count < 1:
        fail("TRex num_flows must be at least 1", 2)
    return count


def generation_pg_id_base(stream_index, flow_id, num_flows):
    '''Derive the first collision-free PGID for one stream/flow pair.'''
    return 1000 + (int(stream_index) * int(num_flows) * 2) + (int(flow_id) * 2)


def build_packet(stream, spec, generation_tag):
    '''Build one exact Ethernet/IPv4/UDP packet for a stream.'''
    return (
        Ether(src=stream["src_mac"], dst=stream["dst_mac"])
        / IP(src=spec["src_ip"], dst=spec["dst_ip"])
        / UDP(sport=int(spec["sport"]), dport=int(spec["dport"]))
        / Raw(load=payload(spec["packet_size"], generation_tag))
    )


def build_stream(stream, pps, spec, flow_id):
    '''Build one ordinary continuous TRex stream.'''
    port_id = int(stream["port_id"])
    return STLStream(
        name="kinetum_{}_flow_{}".format(port_id, flow_id),
        packet=STLPktBuilder(pkt=build_packet(stream, spec, spec["generation_tag"])),
        mode=STLTXCont(pps=float(pps)),
    )


def build_generation_stream(stream, pps, spec, generation_tag, pg_id, flow_id, start_paused=False):
    '''Build one PGID-observed generation stream with explicit start state.'''
    return STLStream(
        name="kinetum_{}_flow_{}_generation_{}_pg_{}".format(
            stream["port_id"], flow_id, generation_tag, pg_id
        ),
        packet=STLPktBuilder(pkt=build_packet(stream, spec, generation_tag)),
        mode=STLTXCont(pps=float(pps)),
        flow_stats=STLFlowStats(pg_id=int(pg_id)),
        start_paused=bool(start_paused),
    )


def generation_counts_from_flow_stats(flow_stats, generation_flow_plan, egress_ports):
    '''Reduce exact PGID rows into generation TX/RX evidence.'''
    missing = []
    tx_by_generation = {}
    rx_by_generation = {}
    by_pg_id = {}

    for item in generation_flow_plan:
        pg_id = int(item["pg_id"])
        generation_tag = int(item["generation_tag"])
        entry = flow_stat_entry(flow_stats, pg_id)
        if entry is None:
            missing.append(pg_id)
            continue

        tx_pkts = port_counter(entry["tx_pkts"], int(item["port_id"]))
        rx_pkts = sum_port_counters(entry["rx_pkts"], egress_ports)
        tx_by_generation[generation_tag] = tx_by_generation.get(generation_tag, 0) + tx_pkts
        rx_by_generation[generation_tag] = rx_by_generation.get(generation_tag, 0) + rx_pkts
        by_pg_id[str(pg_id)] = {
            "generation_tag": generation_tag,
            "logical_name": item["logical_name"],
            "port_id": int(item["port_id"]),
            "flow_id": int(item["flow_id"]),
            "role": item["role"],
            "expected_tx": int(item["expected_tx"]),
            "tx_pkts": tx_pkts,
            "rx_pkts": rx_pkts,
        }

    if missing:
        fail("TRex generation-tag evidence missing flow stats for pg_id(s): {}".format(missing), 1)

    return tx_by_generation, rx_by_generation, by_pg_id


def connect_client():
    '''Connect without rebasing observations at each generation action.'''
    client = STLClient(server=spec["trex_server"])
    # TRex clear-on-connect creates client-local port and PGID references.
    # A finish-time PGID reference would exclude traffic already sent. Port
    # observations instead use the absolute baseline retained at session start.

    def preserve_stats_on_connect():
        '''Leave PGID observations relative to the newly created stream set.'''
        return RC_OK()

    client._on_connect_clear_stats = preserve_stats_on_connect
    with contextlib.redirect_stdout(sys.stderr):
        client.connect()
    return client

def exchange_udp(client, ingress, packets, marker, egress_ports):
    '''Own one low-rate capture, send explicit Ethernet frames, and retire capture on every edge.'''
    captured = []
    packet_filter = " and ".join(
        "udp[{}:4] = 0x{}".format(8 + offset, marker[offset:offset + 4].hex())
        for offset in range(0, 16, 4)
    )
    with client.service_mode(ports=ports):
        capture = client.start_capture(rx_ports=egress_ports, limit=len(packets) + 1,
                                       mode="fixed", bpf_filter=packet_filter)["id"]
        failure = None
        try:
            # Explicit Scapy Ethernet fields prevent push_packets from replacing
            # the plan-derived destination with the TRex port's L2 defaults.
            frames = [Ether(src=ingress["src_mac"], dst=ingress["dst_mac"], type=0x0800) / Raw(packet)
                      for packet in packets]
            client.push_packets(frames, ports=[ingress["port_id"]], ipg_usec=1000)
            time.sleep(EXCHANGE_TIMEOUT_S)
        except BaseException as exc:
            failure = exc
            raise
        finally:
            try:
                client.stop_capture(capture, output=captured)
            except Exception as cleanup:
                if failure is not None:
                    raise RuntimeError("UDP exchange failed: {}; capture cleanup failed: {}".format(
                        failure, cleanup)) from cleanup
                raise
    frames = []
    if len(captured) > len(packets) + 1:
        raise RuntimeError("UDP exchange capture exceeded its packet bound")
    for row in captured:
        if (not isinstance(row, dict) or row["origin"] != "RX"
                or not isinstance(row["port"], int) or isinstance(row["port"], bool)
                or row["port"] not in egress_ports):
            raise RuntimeError("UDP exchange capture has foreign origin or port")
        frame = row["binary"]
        if not isinstance(frame, bytes) or not 14 <= len(frame) <= EXCHANGE_BYTE_CAPACITY + 14:
            raise RuntimeError("UDP exchange capture contains incomplete or oversized bytes")
        frames.append(frame.hex())
    return frames


client = None
promisc_ports = []
promisc_enabled = False
release_ports_on_exit = True
disconnect_stop_traffic = True
disconnect_release_ports = True
try:
    client = connect_client()
    ports = list(spec["ports"])

    if action in {
        "probe", "run", "generation_start", "generation_finish",
        "generation_abort", "exchange_udp",
    }:
        egress_ports = [int(p) for p in spec["egress_ports"]]
    else:
        egress_ports = []

    if action == "exchange_udp":
        with contextlib.redirect_stdout(sys.stderr):
            client.acquire(ports=ports, force=True)
            client.set_port_attr(ports=egress_ports, promiscuous=True)
            promisc_ports = list(egress_ports)
            promisc_enabled = True
            frames = exchange_udp(client, exchange_ingress, exchange_packets, exchange_marker, egress_ports)
        emit({"ok": True, "action": "exchange_udp", "frames": frames})

    if action == "probe":
        with contextlib.redirect_stdout(sys.stderr):
            client.acquire(ports=ports, force=True)
            if egress_ports:
                client.set_port_attr(ports=egress_ports, promiscuous=True)
                promisc_ports = list(egress_ports)
                promisc_enabled = True
            stats = client.get_stats(ports=ports)
            server_identity = trex_identity(client.get_server_version())
        emit({
            "ok": True,
            "action": "probe",
            "ports": ports,
            "stats_keys": [str(k) for k in stats.keys()],
            "promiscuous_ports": promisc_ports,
            "work_dir": os.getcwd(),
            "trex_identity": server_identity,
        })

    if action in ("run", "generation_start", "generation_finish"):
        ingress_streams = list(spec["ingress_streams"])
    else:
        ingress_streams = []
    if action == "generation_start":
        ingress_ports = [stream["port_id"] for stream in ingress_streams]
        duration_s = float(spec["duration_s"])
        transition_s = float(spec["transition_time_s"])
        overlap_s = float(spec["overlap_window_ms"]) / 1000.0
        if transition_s <= 0.0:
            fail("TRex generation overlap requires positive transition_time_s", 2)
        if overlap_s <= 0.0:
            fail("TRex generation overlap requires positive overlap_window_ms", 2)
        if transition_s + overlap_s >= duration_s:
            fail("TRex generation overlap requires transition + overlap < duration", 2)

        num_flows = flow_count(spec)
        per_stream_pps = float(spec["pps"]) / float(
            len(ingress_ports) * num_flows
        )
        initial_generation_tag = spec["initial_generation_tag"]
        next_generation_tag = spec["next_generation_tag"]
        generation_flow_plan = []
        generation_stream_ids = {}

        with contextlib.redirect_stdout(sys.stderr):
            client.acquire(ports=ports, force=True)
            client.reset(ports=ports)
            client.clear_stats()
            if egress_ports:
                client.set_port_attr(ports=egress_ports, promiscuous=True)
                promisc_ports = list(egress_ports)
                promisc_enabled = True

            for idx, stream in enumerate(ingress_streams):
                port_id = int(stream["port_id"])
                generation_stream_ids[str(port_id)] = {"initial": [], "next": []}
                for flow_id in range(num_flows):
                    flow = flow_spec(spec, flow_id)
                    base_pg_id = generation_pg_id_base(idx, flow_id, num_flows)
                    initial_pg_id = base_pg_id
                    next_pg_id = base_pg_id + 1
                    added = client.add_streams(
                        [
                            build_generation_stream(
                                stream=stream,
                                pps=per_stream_pps,
                                spec=flow,
                                generation_tag=initial_generation_tag,
                                pg_id=initial_pg_id,
                                flow_id=flow_id,
                                start_paused=False,
                            ),
                            build_generation_stream(
                                stream=stream,
                                pps=per_stream_pps,
                                spec=flow,
                                generation_tag=next_generation_tag,
                                pg_id=next_pg_id,
                                flow_id=flow_id,
                                start_paused=True,
                            ),
                        ],
                        ports=[port_id],
                    )
                    stream_ids = stream_ids_from_add_result(added, 2)
                    if len(stream_ids) != 2:
                        fail(
                            "TRex did not return two stream ids for port {} flow {}: {}".format(
                                port_id, flow_id, added
                            ),
                            1,
                        )
                    generation_stream_ids[str(port_id)]["initial"].append(int(stream_ids[0]))
                    generation_stream_ids[str(port_id)]["next"].append(int(stream_ids[1]))
                    generation_flow_plan.extend([
                        {
                            "pg_id": initial_pg_id,
                            "generation_tag": initial_generation_tag,
                            "logical_name": stream["logical_name"],
                            "port_id": port_id,
                            "flow_id": flow_id,
                            "role": "pre_overlap",
                            "expected_tx": int(
                                round(per_stream_pps * (transition_s + overlap_s))
                            ),
                        },
                        {
                            "pg_id": next_pg_id,
                            "generation_tag": next_generation_tag,
                            "logical_name": stream["logical_name"],
                            "port_id": port_id,
                            "flow_id": flow_id,
                            "role": "post_overlap",
                            "expected_tx": int(
                                round(per_stream_pps * (duration_s - transition_s))
                            ),
                        },
                    ])

            client.get_stats(ports=ports)
            port_counter_baseline = absolute_port_counters(client, ports)
            client.start(ports=ingress_ports, force=True)
            start_wall = time.time()
            start_mono = time.monotonic()

        release_ports_on_exit = False
        disconnect_stop_traffic = False
        disconnect_release_ports = False
        emit({
            "ok": True,
            "action": "generation_start",
            "duration_s": duration_s,
            "initial_generation_tag": initial_generation_tag,
            "next_generation_tag": next_generation_tag,
            "start_time": start_wall,
            "start_monotonic": start_mono,
            "ingress_ports": ingress_ports,
            "egress_ports": egress_ports,
            "generation_stream_ids": generation_stream_ids,
            "generation_flow_plan": generation_flow_plan,
            "port_counter_baseline": port_counter_baseline,
            "promiscuous_ports": promisc_ports,
            "work_dir": os.getcwd(),
        })

    if action == "generation_resume_next":
        stream_ids = spec["generation_stream_ids"]
        next_ids = {}
        with contextlib.redirect_stdout(sys.stderr):
            client.acquire(ports=ports, force=True)
            for port_id_text, ids in stream_ids.items():
                port_id = int(port_id_text)
                port_next_ids = [int(stream_id) for stream_id in ids["next"]]
                client.resume_streams(port_id, port_next_ids)
                next_ids[port_id_text] = port_next_ids
        resume_wall = time.time()
        resume_mono = time.monotonic()
        release_ports_on_exit = False
        disconnect_stop_traffic = False
        disconnect_release_ports = False
        emit({
            "ok": True,
            "action": "generation_resume_next",
            "resumed_stream_ids": next_ids,
            "next_start_time": resume_wall,
            "next_start_monotonic": resume_mono,
            "timestamp_source": "trex_endpoint_monotonic",
        })

    if action == "generation_pause_initial":
        stream_ids = spec["generation_stream_ids"]
        initial_ids = {}
        pause_wall = time.time()
        pause_mono = time.monotonic()
        with contextlib.redirect_stdout(sys.stderr):
            client.acquire(ports=ports, force=True)
            for port_id_text, ids in stream_ids.items():
                port_id = int(port_id_text)
                port_initial_ids = [int(stream_id) for stream_id in ids["initial"]]
                client.pause_streams(port_id, port_initial_ids)
                initial_ids[port_id_text] = port_initial_ids
        release_ports_on_exit = False
        disconnect_stop_traffic = False
        disconnect_release_ports = False
        emit({
            "ok": True,
            "action": "generation_pause_initial",
            "paused_stream_ids": initial_ids,
            "initial_pause_time": pause_wall,
            "initial_pause_monotonic": pause_mono,
            "timestamp_source": "trex_endpoint_monotonic",
        })

    if action == "generation_finish":
        ingress_ports = [int(p) for p in spec["ingress_ports"]]
        generation_flow_plan = list(spec["generation_flow_plan"])
        stream_ids = spec["generation_stream_ids"]
        start_mono = spec["start_monotonic"]
        next_start_mono = spec["next_start_monotonic"]
        initial_pause_mono = spec["initial_pause_monotonic"]

        next_pause_wall = time.time()
        next_pause_mono = time.monotonic()
        with contextlib.redirect_stdout(sys.stderr):
            client.acquire(ports=ports, force=True)
            for port_id_text, ids in stream_ids.items():
                port_id = int(port_id_text)
                port_next_ids = [int(stream_id) for stream_id in ids["next"]]
                client.pause_streams(port_id, port_next_ids)
            time.sleep(0.2)
            stats = client.get_stats(ports=ports)
            port_counter_final = absolute_port_counters(client, ports)
            port_stats = port_counter_deltas(
                port_counter_final, spec["port_counter_baseline"]
            )
            client.stop(ports=ingress_ports)
        promisc_ports = list(egress_ports)
        promisc_enabled = bool(promisc_ports)
        end_time = time.time()

        port_tx_count = sum(stat_value(port_stats, port_id, "opackets") for port_id in ingress_ports)
        port_rx_count = sum(stat_value(port_stats, port_id, "ipackets") for port_id in egress_ports)
        error_count = (
            sum(stat_value(port_stats, port_id, "oerrors") for port_id in ingress_ports)
            + sum(stat_value(port_stats, port_id, "ierrors") for port_id in egress_ports)
        )
        if not isinstance(stats, dict) or "flow_stats" not in stats:
            fail("TRex PGID result omitted flow_stats", 1)
        flow_stats = stats["flow_stats"]
        tx_by_generation, rx_by_generation, by_pg_id = generation_counts_from_flow_stats(
            flow_stats,
            generation_flow_plan,
            egress_ports,
        )
        tx_count = sum(tx_by_generation.values())
        rx_count = sum(rx_by_generation.values())

        measured_overlap = (
            float(initial_pause_mono) - float(next_start_mono)
        ) * 1000.0
        measured_active_s = (
            float(initial_pause_mono) - float(start_mono)
            + float(next_pause_mono) - float(next_start_mono)
        )
        expected_tx_count = int(round(float(spec["pps"]) * measured_active_s))
        if (
            measured_overlap + 0.001 < float(spec["overlap_window_ms"])
            or measured_active_s <= 0.0
            or expected_tx_count <= 0
            or expected_tx_count > (1 << 64) - 1
        ):
            fail("TRex measured generation intervals are incomplete", 1)

        payload_out = {
            "ok": True,
            "action": "generation_finish",
            "tx_count": tx_count,
            "rx_count": rx_count,
            "errors": error_count,
            "port_tx_count": port_tx_count,
            "port_rx_count": port_rx_count,
            "port_counter_baseline": spec["port_counter_baseline"],
            "port_counter_final": port_counter_final,
            "start_time": float(spec["start_time"]),
            "start_monotonic": start_mono,
            "end_time": end_time,
            "ingress_ports": ingress_ports,
            "egress_ports": egress_ports,
            "promiscuous_ports": egress_ports,
            "work_dir": os.getcwd(),
            "generation_tag_counts": {str(k): v for k, v in tx_by_generation.items()},
            "tag_counts": {str(k): v for k, v in rx_by_generation.items()},
            "generation_flow_plan": generation_flow_plan,
            "generation_pgid_stats": by_pg_id,
            "generation_overlap_method": "orchestrator_controlled_sustained_overlap",
            "transition_time_s_requested": float(spec["transition_time_s"]),
            "requested_overlap_window_ms": int(spec["overlap_window_ms"]),
            "overlap_window_ms_measured": measured_overlap,
            "overlap_window_timestamp_source": "trex_endpoint_monotonic",
            "expected_tx_count": expected_tx_count,
            "expected_tx_count_source": "measured_generation_intervals",
            "steady_state_target_pps": int(spec["pps"]),
            "overlap_aggregate_target_pps": int(spec["pps"]) * 2,
            "next_start_time": spec["next_start_time"],
            "initial_pause_time": spec["initial_pause_time"],
            "next_pause_time": next_pause_wall,
            "next_start_monotonic": next_start_mono,
            "initial_pause_monotonic": initial_pause_mono,
            "next_pause_monotonic": next_pause_mono,
        }
        emit(payload_out)

    if action == "generation_abort":
        with contextlib.redirect_stdout(sys.stderr):
            client.acquire(ports=ports, force=True)
            client.stop(ports=spec["ingress_ports"])
        promisc_ports = list(egress_ports)
        promisc_enabled = bool(promisc_ports)
        emit({
            "ok": True,
            "action": "generation_abort",
        })

    if action != "run":
        fail("unsupported TRex action: {}".format(action), 2)
    ingress_ports = [stream["port_id"] for stream in ingress_streams]
    duration_s = float(spec["duration_s"])
    mode = spec["mode"]

    num_flows = flow_count(spec)
    per_stream_pps = float(spec["pps"]) / float(len(ingress_ports) * num_flows)
    with contextlib.redirect_stdout(sys.stderr):
        client.acquire(ports=ports, force=True)
        client.reset(ports=ports)
        client.clear_stats()
        if egress_ports:
            client.set_port_attr(ports=egress_ports, promiscuous=True)
            promisc_ports = list(egress_ports)
            promisc_enabled = True

        for stream in ingress_streams:
            port_id = int(stream["port_id"])
            client.add_streams(
                [
                    build_stream(
                        stream=stream,
                        pps=per_stream_pps,
                        spec=flow_spec(spec, flow_id),
                        flow_id=flow_id,
                    )
                    for flow_id in range(num_flows)
                ],
                ports=[port_id],
            )

        client.get_stats(ports=ports)
        port_counter_baseline = absolute_port_counters(client, ports)

    start_time = time.time()
    with contextlib.redirect_stdout(sys.stderr):
        client.start(ports=ingress_ports, duration=duration_s, force=True)
        client.wait_on_traffic(
            ports=ingress_ports,
            timeout=duration_s + 30.0,
        )
        client.get_stats(ports=ports)
        port_counter_final = absolute_port_counters(client, ports)
    end_time = time.time()

    port_stats = port_counter_deltas(port_counter_final, port_counter_baseline)
    tx_count = sum(stat_value(port_stats, port_id, "opackets") for port_id in ingress_ports)
    rx_count = sum(stat_value(port_stats, port_id, "ipackets") for port_id in egress_ports)
    error_count = (
        sum(stat_value(port_stats, port_id, "oerrors") for port_id in ingress_ports)
        + sum(stat_value(port_stats, port_id, "ierrors") for port_id in egress_ports)
    )

    payload_out = {
        "ok": True,
        "action": "run",
        "tx_count": tx_count,
        "rx_count": rx_count,
        "errors": error_count,
        "port_counter_baseline": port_counter_baseline,
        "port_counter_final": port_counter_final,
        "start_time": start_time,
        "end_time": end_time,
        "ingress_ports": ingress_ports,
        "egress_ports": egress_ports,
        "promiscuous_ports": promisc_ports,
        "work_dir": os.getcwd(),
        "generation_tag_counts": {str(spec["generation_tag"]): tx_count},
        "tag_counts": {str(spec["generation_tag"]): rx_count},
    }

    emit(payload_out)
except Exception as exc:  # pragma: no cover - depends on endpoint runtime
    fail("TRex remote execution failed: {}".format(exc), 1)
finally:
    if client is not None:
        cleanup_errors = []
        if promisc_enabled and release_ports_on_exit:
            try:
                with contextlib.redirect_stdout(sys.stderr):
                    client.set_port_attr(ports=promisc_ports, promiscuous=False)
            except Exception as exc:
                cleanup_errors.append("promiscuous reset failed: {}".format(exc))
        if release_ports_on_exit:
            try:
                with contextlib.redirect_stdout(sys.stderr):
                    client.release(ports=[int(p) for p in spec["ports"]])
            except Exception as exc:
                cleanup_errors.append("port release failed: {}".format(exc))
        try:
            with contextlib.redirect_stdout(sys.stderr):
                client.disconnect(
                    stop_traffic=disconnect_stop_traffic,
                    release_ports=disconnect_release_ports,
                )
        except Exception as exc:
            cleanup_errors.append("client disconnect failed: {}".format(exc))
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))
"""

REMOTE_TREX_SCRIPT = _REMOTE_TREX_SCRIPT_TEMPLATE.replace(
    "__KINETUM_JSON_DOCUMENT_CAPACITY__",
    str(MAX_JSON_DOCUMENT_CHARACTERS),
).replace("__KINETUM_EXCHANGE_PACKET_LIMIT__", str(EXCHANGE_PACKET_LIMIT)).replace(
    "__KINETUM_EXCHANGE_PACKET_BYTES__", str(EXCHANGE_PACKET_BYTES)
).replace("__KINETUM_EXCHANGE_TIMEOUT_S__", str(EXCHANGE_TIMEOUT_S))
