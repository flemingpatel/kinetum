"""Exact empirical percentiles shared by validation summaries and benchmark reports."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def nearest_rank_index(count: int, percentile: int) -> int:
    """Return the zero-based nearest rank for a positive sample count and percentile 0..100."""
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise ValueError("percentile requires observed samples")
    if isinstance(percentile, bool) or not isinstance(percentile, int) or not 0 <= percentile <= 100:
        raise ValueError("percentile must be an integer in 0..100")
    return max(1, (percentile * count + 99) // 100) - 1


def nearest_rank_percentile(values: Sequence[float], percentile: int) -> float:
    """Return the observed value at the requested integer percentile.

    Use one-based rank ``ceil(percentile * count / 100)``; percentile zero
    selects the minimum. Samples must be finite numbers admitted by the caller.
    Sorting uses a copy and leaves the input unchanged. Empty samples or a
    percentile outside the integer range 0..100 raise ValueError.
    """
    rank = nearest_rank_index(len(values), percentile)
    return sorted(values)[rank]


def validate_percentile_population(count: int, values: Mapping[int, float]) -> None:
    """Validate ordered admitted quantiles, including equal values at shared ranks."""
    if not values:
        raise ValueError("percentile population contains no measurements")
    values_by_rank = {}
    previous = None
    for percentile, measured in sorted(values.items()):
        rank = nearest_rank_index(count, percentile)
        if previous is not None and measured < previous:
            raise ValueError("percentiles are not ordered")
        if rank in values_by_rank and values_by_rank[rank] != measured:
            raise ValueError("percentiles contradict their sample count")
        values_by_rank[rank] = measured
        previous = measured


def format_number(value: int | float | None, precision: int = 0) -> str:
    """Format admitted finite measurements without turning a nonzero value into zero.

    Integer counters keep their exact decimal representation. Floats use the
    requested decimal places, or six significant digits when fixed formatting
    would erase a nonzero observation.
    """
    if value is None:
        return "n/a"
    if not isinstance(value, float):
        return str(value)
    text = f"{value:.{precision}f}"
    return f"{value:.6g}" if value != 0.0 and float(text) == 0.0 else text
