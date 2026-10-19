"""One request/response grammar and generation-PGID authority for TRex actions."""

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
            "transition_time_s_requested", "requested_overlap_window_ms",
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
    "initial_generation_tag", "next_generation_tag", "transition_time_s",
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
