"""Complete synthetic per-input traffic observations for scenario fixtures."""

from collections import Counter

from kinetum_validation.config.types import AnalysisResult, StreamAnalysisResult


def complete_trex_identity(
    ports=(0, 1, 2), counters=127, filter_mode="hardware match", version="v3.06",
) -> dict:
    """Author complete independent instrument observations for selected fixture ports."""
    return {
        "version": version,
        "mode": "STL",
        "ports": [
            {"port_id": port, "driver": "net_i40e", "rx_caps": ["flow_stats", "latency"],
             "rx_counters": counters, "rx_filter_mode": filter_mode}
            for port in sorted(ports)
        ],
    }


def native_trex_port_info(identity: dict) -> list:
    """Represent the fixture's observations in the native get_port_info response shape."""
    return [
        {"index": row["port_id"], "driver": row["driver"], "rx_filter_mode": row["rx_filter_mode"],
         "rx": {"caps": list(row["rx_caps"]), "counters": row["rx_counters"]}}
        for row in identity["ports"]
    ]


def complete_native_analysis(
    generation_counts: tuple[tuple[int, int], ...], stream_count: int,
) -> AnalysisResult:
    """Summarize a lossless round-robin capture from ordered (tag, count) runs.

    Each input receives sequence IDs one round-robin cycle apart. Count each
    input's share in one step per generation.
    """
    total = 0
    tag_counts = Counter()
    run_ends = []
    for tag, count in generation_counts:
        if count < 0:
            raise ValueError("a generation cannot contain a negative packet count")
        if count:
            total += count
            tag_counts[tag] += count
            run_ends.append((tag, total))

    streams = []
    for index in range(stream_count):
        counts = Counter()
        next_sequence = index
        first_tag = last_tag = None
        transition_seq = -1
        changes = 0
        for tag, end in run_ends:
            sequences = range(next_sequence, end, stream_count)
            if not sequences:
                continue
            if first_tag is None:
                first_tag = tag
            elif last_tag != tag:
                if changes == 0:
                    transition_seq = next_sequence
                changes += 1
            last_tag = tag
            counts[tag] += len(sequences)
            next_sequence = sequences[-1] + stream_count
        valid = sum(counts.values())
        streams.append(StreamAnalysisResult(
            stream_index=index,
            expected_count=valid,
            valid=valid,
            duplicates=0,
            out_of_order=0,
            missing_count=0,
            transition_seq=transition_seq,
            tag_transition_count=changes,
            first_tag=first_tag,
            last_tag=last_tag,
            tag_counts=dict(counts),
        ))
    result = AnalysisResult(
        total_rx=total, valid=total, streams=tuple(streams), max_gap=0, tag_counts=dict(tag_counts),
    )
    if total:
        result.set_latency_stats(dict.fromkeys(("avg", "min", "max", "p50", "p99"), 10.0))
    return result
