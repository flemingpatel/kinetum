"""One request/response grammar and generation-PGID authority for TRex actions."""

import math

from ..engine.json_contract import (
    require_array, require_bool, require_exact_keys, require_int, require_number, require_object, require_trex_identity,
)

REMOTE_SUCCESS_KEYS = {
    "minimum_frame": frozenset({
        "ok", "action", "trex_identity", "pgid_demand", "links", "captured", "samples",
        "tx_count", "rx_count", "errors", "port_counter_baseline", "port_counter_final",
    }),
    "exchange_udp": frozenset({"ok", "action", "frames", "trex_identity", "pgid_demand"}),
    "probe": frozenset(
        {
            "ok", "action", "ports", "work_dir", "trex_identity",
        }
    ),
    "run": frozenset(
        {
            "ok", "action", "tx_count", "rx_count", "errors", "start_time",
            "end_time", "duration_s", "ingress_ports", "egress_ports", "promiscuous_ports",
            "work_dir", "generation_tag_counts", "tag_counts",
            "port_counter_baseline", "port_counter_final", "trex_identity", "pgid_demand",
        }
    ),
    "generation_start": frozenset(
        {
            "ok", "action", "duration_s", "initial_generation_tag",
            "next_generation_tag", "start_time", "start_monotonic",
            "ingress_ports", "egress_ports", "generation_stream_ids",
            "generation_flow_plan", "port_counter_baseline", "promiscuous_ports", "work_dir",
            "trex_identity", "pgid_demand",
        }
    ),
    "generation_resume_next": frozenset(
        {"ok", "action", "resumed_stream_ids", "next_start_time",
         "next_start_monotonic", "timestamp_source"}
    ),
    "generation_pause_initial": frozenset(
        {"ok", "action", "paused_stream_ids", "initial_pause_time",
         "initial_pause_monotonic", "timestamp_source"}
    ),
    "generation_finish": frozenset(
        {
            "ok", "action", "tx_count", "rx_count", "errors", "port_tx_count",
            "port_rx_count", "start_time", "end_time", "duration_s", "ingress_ports",
            "port_counter_baseline", "port_counter_final", "trex_identity", "pgid_demand",
            "egress_ports", "promiscuous_ports", "work_dir",
            "generation_tag_counts", "tag_counts", "generation_flow_plan",
            "generation_pgid_stats", "generation_overlap_method",
            "initial_duration_s_requested", "requested_overlap_window_ms",
            "overlap_window_ms_measured", "overlap_window_timestamp_source",
            "expected_tx_count", "expected_tx_count_source",
            "steady_state_target_pps", "overlap_aggregate_target_pps",
            "start_monotonic", "next_start_time", "initial_pause_time",
            "next_pause_time", "next_start_monotonic",
            "initial_pause_monotonic", "next_pause_monotonic",
        }
    ),
    "generation_abort": frozenset({"ok", "action"}),
}
REMOTE_RUN_BASE_KEYS = frozenset(
    {
        "duration_s", "pps", "packet_size", "num_flows", "src_ip", "dst_ip",
        "sport", "dport", "ports", "ingress_streams",
        "egress_ports", "trex_server", "trex_api_path", "work_dir", "action", "trex_identity",
    }
)
REMOTE_PACKET_RUN_KEYS = REMOTE_RUN_BASE_KEYS | {"generation_tag"}
REMOTE_GENERATION_RUN_KEYS = REMOTE_RUN_BASE_KEYS | {
    "initial_generation_tag", "next_generation_tag", "initial_duration_s",
    "overlap_window_ms",
}
REMOTE_REQUEST_KEYS = {
    "minimum_frame": frozenset({
        "action", "ports", "egress_ports", "trex_server", "trex_api_path", "work_dir", "trex_identity",
        "ingress_port", "frames", "capture", "pps", "duration_s",
    }),
    "exchange_udp": frozenset({
        "action", "ports", "egress_ports", "trex_server", "trex_api_path", "work_dir",
        "ingress_stream", "packets", "capture_marker", "trex_identity",
    }),
    "probe": frozenset(
        {"action", "ports", "egress_ports", "trex_server", "trex_api_path", "work_dir"}
    ),
    "run": REMOTE_PACKET_RUN_KEYS | {"mode"},
    "generation_start": REMOTE_GENERATION_RUN_KEYS,
    "generation_resume_next": frozenset(
        {
            "action", "ports", "ingress_ports", "generation_stream_ids",
            "trex_server", "trex_api_path", "work_dir",
        }
    ),
    "generation_pause_initial": frozenset(
        {
            "action", "ports", "ingress_ports", "generation_stream_ids",
            "trex_server", "trex_api_path", "work_dir",
        }
    ),
    "generation_finish": REMOTE_GENERATION_RUN_KEYS
    | {
        "ingress_ports", "generation_stream_ids", "generation_flow_plan",
        "port_counter_baseline",
        "start_time", "start_monotonic", "next_start_time",
        "next_start_monotonic", "initial_pause_time",
        "initial_pause_monotonic",
    },
    "generation_abort": frozenset(
        {"action", "ports", "ingress_ports", "egress_ports", "trex_server", "trex_api_path", "work_dir"}
    ),
}


class TRexRemoteFailure(RuntimeError):
    """Retain whether a rejected endpoint action attempted a mutating call."""

    def __init__(self, message: str, mutation_attempted: bool) -> None:
        """Preserve the endpoint's explicit before-effects rejection evidence."""
        super().__init__(message)
        self.mutation_attempted = mutation_attempted


def source_mac_for_port(port_id: int) -> str:
    """Return the deterministic locally administered MAC used for this tester ingress."""
    value = require_int(port_id, "TRex source-MAC port", minimum=0, maximum=0xffffffff) + 1
    return (b"\x02" + value.to_bytes(5, "big")).hex(":")


def require_port_counters(value: object, name: str, ports: list[int]) -> dict:
    """Admit all four absolute uint64 counters for every selected tester port."""
    context = f"TRex port counter {name}"
    rows = require_object(value, context)
    require_exact_keys(rows, {str(port) for port in ports}, context)
    for port, item in rows.items():
        row = require_object(item, f"{context} port {port}")
        require_exact_keys(row, {"opackets", "ipackets", "oerrors", "ierrors"}, f"{context} port {port}")
        for field, count in row.items():
            require_int(count, f"{context} port {port} {field}", minimum=0, maximum=(1 << 64) - 1)
    return rows


def port_counter_totals(payload: dict, ports: list[int], ingresses: list[int], egresses: list[int]) -> tuple[int, int]:
    """Derive sent, received and error counts from native endpoints, including PGID agreement when present."""
    before = require_port_counters(payload.get("port_counter_baseline"), "baseline", ports)
    after = require_port_counters(payload.get("port_counter_final"), "final", ports)
    for port, row in after.items():
        for field, count in row.items():
            if count < before[port][field]:
                raise RuntimeError(f"trex port {port} {field} regressed")

    def delta(selected: list[int], field: str) -> int:
        """Sum the observed deltas only in the exercised direction."""
        return sum(after[str(port)][field] - before[str(port)][field] for port in selected)

    tx, rx = delta(ingresses, "opackets"), delta(egresses, "ipackets")
    errors = delta(ingresses, "oerrors") + delta(egresses, "ierrors")
    generation = payload["action"] == "generation_finish"
    tx_field, rx_field = ("port_tx_count", "port_rx_count") if generation else ("tx_count", "rx_count")
    for field, count in ((tx_field, tx), (rx_field, rx), ("errors", errors)):
        if require_int(payload.get(field), f"TRex {field}", minimum=0, maximum=(1 << 64) - 1) != count:
            raise RuntimeError(f"trex {field} disagrees with retained port snapshots")
    if errors:
        raise RuntimeError("trex remote result contains traffic errors")
    if generation:
        pgid_tx = require_int(payload.get("tx_count"), "TRex PGID TX", minimum=0, maximum=(1 << 64) - 1)
        pgid_rx = require_int(payload.get("rx_count"), "TRex PGID RX", minimum=0, maximum=(1 << 64) - 1)
        if (pgid_tx, pgid_rx) != (tx, rx):
            raise RuntimeError(f"trex port and PGID aggregate counters disagree: port_tx={tx} pgid_tx={pgid_tx} "
                               f"port_rx={rx} pgid_rx={pgid_rx}")
    return tx, rx


def require_minimum_observation(payload: dict, ingress: int, egress: int, identity: dict, *, capture: bool) -> None:
    """Check live or retained tester identity, links, counts, monotonic sample brackets and capture extent."""
    ports = [ingress, egress]
    if (payload["action"] != "minimum_frame" or not require_bool(payload["ok"], "TRex success")
            or require_trex_identity(payload["trex_identity"], "TRex admitted instrument identity") != identity
            or [row["port_id"] for row in identity["ports"]] != sorted(ports)
            or require_int(payload["pgid_demand"], "TRex PGID demand", minimum=0) != 0):
        raise ValueError("minimum-frame action or tester identity differs from the admitted instrument")
    sent, received = port_counter_totals(payload, ports, [ingress], [egress])
    if sent == 0 or received > sent:
        raise ValueError("minimum-frame port populations are contradictory")
    links = require_array(payload["links"], "tester links")
    observed = []
    for item in links:
        link = require_object(item, "tester link")
        require_exact_keys(link, {"port", "link", "speed"}, "tester link")
        observed.append(require_int(link["port"], "tester port", minimum=0, maximum=0xffffffff))
        if link["link"] != "UP" or require_number(link["speed"], "tester link speed") <= 0:
            raise ValueError("tester link is down or has no observed speed")
    if sorted(observed) != sorted(ports):
        raise ValueError("tester links differ from the exercised ports")
    samples = require_array(payload["samples"], "minimum-frame counter samples")
    if len(samples) != (2 if capture else 4):
        raise ValueError("minimum-frame counter sample population is incomplete")
    last_ns = 0
    prior = {}
    for item in samples:
        sample = require_object(item, "minimum-frame sample")
        require_exact_keys(sample, {"before_ns", "after_ns", "ports"}, "minimum-frame sample")
        lower = require_int(sample["before_ns"], "sample opening", minimum=last_ns + 1, maximum=(1 << 64) - 1)
        last_ns = require_int(sample["after_ns"], "sample closing", minimum=lower, maximum=(1 << 64) - 1)
        counters = require_port_counters(sample["ports"], "sample", ports)
        if prior and any(value < prior[port][key] for port, row in counters.items() for key, value in row.items()):
            raise ValueError("minimum-frame tester counters regressed")
        prior = counters
    if samples[0]["ports"] != payload["port_counter_baseline"] or samples[-1]["ports"] != payload["port_counter_final"]:
        raise ValueError("minimum-frame endpoints disagree with the retained samples")
    frames = require_array(payload["captured"], "minimum-frame capture")
    if len(frames) != (128 if capture else 0) or any(
        not isinstance(frame, str) or len(frame) != 120 for frame in frames
    ):
        raise ValueError("minimum-frame capture has an incorrect frame count or length")


def require_minimum_capture(payload: dict, expected: list[str]) -> None:
    """Require two independent byte-exact returns for each flow, in any return order."""
    if (payload["tx_count"], payload["rx_count"]) != (128, 128) or sorted(payload["captured"]) != sorted(expected * 2):
        raise ValueError("minimum-frame return counts, headers or checksums differ from the expected frames")


def generation_pgid_layout(ingress_count: int, num_flows: int) -> dict:
    """Derive disjoint generation IDs and counter demand without allocating rows.

    The two ranges preserve ingress-major, flow-minor order. Their cardinality,
    excluding the allocation offset, is the demand at each observation port.
    This exact function is projected into the endpoint program.
    """
    if any(
        not isinstance(value, int) or isinstance(value, bool)
        or not 1 <= value <= 0xffffffff
        for value in (ingress_count, num_flows)
    ):
        raise RuntimeError("TRex PGID population is outside its integer domain")
    first = 1000
    population = ingress_count * num_flows
    end = first + population * 2
    if end - 1 > 0xffffffff:
        raise RuntimeError("trex generated PGID range overflows")
    initial = range(first, end, 2)
    following = range(first + 1, end, 2)
    return {
        "initial": initial,
        "next": following,
        "demand": len(initial) + len(following),
    }


def require_generation_flow_plan(plan: object, ingress_streams: list, num_flows: int,
                                 initial_tag: int, next_tag: int) -> None:
    """Validate exact PGID ownership without forecasting a population's duration.

    The enclosing request owns admitted ingress metadata and distinct tags.
    Endpoint and consumer share the closed row grammar and PGID calculation.
    """
    layout = generation_pgid_layout(len(ingress_streams), num_flows)
    if not isinstance(plan, list) or len(plan) != layout["demand"]:
        raise RuntimeError("trex generation flow-plan cardinality is inexact")
    ports = {row["port_id"]: (index, row["logical_name"]) for index, row in enumerate(ingress_streams)}
    if len(ports) != len(ingress_streams):
        raise RuntimeError("trex generation ingress identity is duplicated")
    fields = {"pg_id", "generation_tag", "logical_name", "port_id", "flow_id", "role"}
    seen = set()
    for row in plan:
        if not isinstance(row, dict) or set(row) != fields:
            raise RuntimeError("trex generation flow-plan fields are inexact")
        if any(
            not isinstance(row[name], int) or isinstance(row[name], bool) or not 0 <= row[name] <= 0xffffffff
            for name in ("pg_id", "generation_tag", "port_id", "flow_id")
        ):
            raise RuntimeError("trex generation flow-plan integer identity is invalid")
        role = row["role"]
        if not isinstance(role, str) or role not in {"pre_overlap", "post_overlap"}:
            raise RuntimeError("trex generation flow role is invalid")
        port = ports.get(row["port_id"])
        if port is None or row["logical_name"] != port[1] or row["flow_id"] >= num_flows:
            raise RuntimeError("trex generation flow port or index disagrees")
        expected_tag = initial_tag if role == "pre_overlap" else next_tag
        population = layout["initial" if role == "pre_overlap" else "next"]
        expected_pgid = population[port[0] * num_flows + row["flow_id"]]
        if row["generation_tag"] != expected_tag or row["pg_id"] != expected_pgid:
            raise RuntimeError("trex generation flow identity disagrees with the request")
        if row["pg_id"] in seen:
            raise RuntimeError("trex generation PGID is duplicated")
        seen.add(row["pg_id"])


def generation_flow_expected_tx(pps: int, ingress_count: int, num_flows: int, active_duration_s: float) -> int:
    """Derive one positive uint64 flow expectation from its measured active interval.

    Both the endpoint and consumer execute this expression. Divide to obtain
    the configured flow rate before multiplying by duration: reassociation can
    change rounding at a half-packet boundary. No forecast duration is accepted.
    """
    if any(
        not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 0xffffffff
        for value in (pps, ingress_count, num_flows)
    ) or not isinstance(active_duration_s, (int, float)) or isinstance(active_duration_s, bool):
        raise RuntimeError("TRex measured flow expectation has invalid inputs")
    try:
        active_duration_s = float(active_duration_s)
    except OverflowError as exc:
        raise RuntimeError("TRex measured duration is outside its numeric domain") from exc
    if not math.isfinite(active_duration_s) or active_duration_s <= 0.0:
        raise RuntimeError("TRex measured flow expectation has invalid inputs")
    flow_rate = float(pps) / float(ingress_count * num_flows)
    expected = flow_rate * active_duration_s
    if not math.isfinite(expected) or not 0 < expected < (1 << 64):
        raise RuntimeError("TRex measured flow expectation is outside uint64")
    count = int(round(expected))
    if not 0 < count < (1 << 64):
        raise RuntimeError("TRex measured interval cannot establish a positive flow population")
    return count


def require_trex_capacity(identity: dict, observation_ports: list, demand: int) -> None:
    """Admit per-port reported flow-counter capacity for one exact PGID demand.

    Callers supply an already validated identity. Standard port-counter runs
    use zero demand; they do not require flow-statistic support. This same
    function is projected into the endpoint program.
    """
    if not isinstance(demand, int) or isinstance(demand, bool) or demand < 0:
        raise RuntimeError("TRex PGID demand is malformed")
    by_port = {row["port_id"]: row for row in identity["ports"]}
    for port_id in observation_ports:
        if port_id not in by_port:
            raise RuntimeError("TRex observation port capability is missing")
        row = by_port[port_id]
        if demand and (
            "flow_stats" not in row["rx_caps"] or row["rx_counters"] < demand
        ):
            raise RuntimeError(
                f"TRex observation port {port_id} requires {demand} distinct PGID counters, "
                f"reports {row['rx_counters']} in {row['rx_filter_mode']} mode"
            )
