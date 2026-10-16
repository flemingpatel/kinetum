"""Complete synthetic per-input traffic observations for scenario fixtures."""

from collections import Counter

from kinetum_validation.config.types import AnalysisResult, StreamAnalysisResult


def complete_native_analysis(
    generation_counts: tuple[tuple[int, int], ...], stream_count: int,
) -> AnalysisResult:
    """Author a complete ordered capture from explicit source generations and inputs."""
    packets = []
    for tag, count in generation_counts:
        first = len(packets)
        packets.extend((sequence, tag) for sequence in range(first, first + count))
    streams = []
    for index in range(stream_count):
        received = [(sequence, tag) for sequence, tag in packets if sequence % stream_count == index]
        changes = [
            sequence for (_, previous), (sequence, tag) in zip(received, received[1:]) if tag != previous
        ]
        streams.append(StreamAnalysisResult(
            stream_index=index,
            expected_count=len(received),
            valid=len(received),
            duplicates=0,
            out_of_order=0,
            missing_count=0,
            transition_seq=changes[0] if changes else -1,
            tag_transition_count=len(changes),
            first_tag=received[0][1] if received else None,
            last_tag=received[-1][1] if received else None,
            tag_counts=dict(Counter(tag for _, tag in received)),
        ))
    result = AnalysisResult(
        total_rx=len(packets), valid=len(packets), streams=tuple(streams),
        max_gap=0,
        tag_counts=dict(Counter(tag for _, tag in packets)),
    )
    if packets:
        result.set_latency_stats(dict.fromkeys(("avg", "min", "max", "p50", "p99"), 10.0))
    return result
