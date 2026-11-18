"""One request/response grammar and generation-PGID authority for TRex actions."""

import math

REMOTE_SUCCESS_KEYS = {
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
