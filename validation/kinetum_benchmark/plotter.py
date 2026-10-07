"""
Figure generator - static SVG plots from benchmark data.

Uses matplotlib only. No interactive output, no notebooks.
Deterministic: same input always produces the same figures.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Any, Dict, List

try:
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


# Fixed style constants
COLORS = {
    "epoch": "#2196F3",
    "commit_confirmed": "#4CAF50",
    "rollback_apply_v1": "#FF9800",
    "rollback_apply_v2": "#F44336",
    "rollback_selective": "#9C27B0",
    "rollback_full": "#795548",
}
FIGURE_WIDTH = 8
FIGURE_HEIGHT = 5
FONT_SIZE = 10
LABEL_SIZE = 9
DPI = 150


def require_figure_backend() -> None:
    """Require the one noninteractive figure backend before artifact creation."""
    if not HAS_MATPLOTLIB:
        raise RuntimeError(
            "benchmark report requires the installed matplotlib backend"
        )


def generate_figures(input_dir: Path, artifacts_dir: Path) -> None:
    """
    Generate static SVG figures from benchmark data.

    Reads raw CSVs from artifacts_dir and produces:
      - artifacts/figures/epoch_latency_cdf.svg when latency is available
      - artifacts/figures/boundary_ack_gate_ns_cdf.svg
      - artifacts/figures/boundary_ack_gate_ns_by_type_*.svg

    Parameters
    ----------
    input_dir : Path
        Benchmark root directory.
    artifacts_dir : Path
        Output directory for derived artifacts.
    """
    if (
        artifacts_dir != input_dir / "artifacts"
        or not artifacts_dir.is_dir()
        or artifacts_dir.is_symlink()
    ):
        raise ValueError("benchmark figure output lacks the exact artifact owner")
    require_figure_backend()

    figures_dir = artifacts_dir / "figures"
    figures_dir.mkdir(mode=0o750)

    plt.rcParams.update({
        "font.size": FONT_SIZE,
        "axes.labelsize": LABEL_SIZE,
        "axes.titlesize": FONT_SIZE + 1,
        "xtick.labelsize": LABEL_SIZE,
        "ytick.labelsize": LABEL_SIZE,
        "legend.fontsize": LABEL_SIZE,
        "figure.dpi": DPI,
    })

    _plot_epoch_latency_cdf(artifacts_dir, figures_dir)
    _plot_boundary_ack_gate_cdf(artifacts_dir, figures_dir)
    _plot_boundary_ack_gate_by_type(artifacts_dir, figures_dir)


def _read_transitions_raw(artifacts_dir: Path) -> List[dict]:
    """Read benchmark_transitions_raw.csv from artifacts directory."""
    csv_path = artifacts_dir / "benchmark_transitions_raw.csv"
    if csv_path.is_symlink():
        raise ValueError("raw transition CSV is indirect")
    if not csv_path.exists():
        return []
    if not csv_path.is_file():
        raise ValueError("raw transition CSV is not a regular file")
    rows = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def _cdf(values: List[float]):
    """Compute CDF x/y arrays from a list of values."""
    s = sorted(values)
    n = len(s)
    x = s
    y = [(i + 1) / n for i in range(n)]
    return x, y


def _save_svg(figure: Any, path: Path) -> None:
    """Write one timestamp-free deterministic SVG and always close its figure."""
    try:
        with plt.rc_context({"svg.hashsalt": "kinetum-benchmark"}):
            figure.savefig(
                path,
                format="svg",
                bbox_inches="tight",
                metadata={"Creator": "Kinetum benchmark", "Date": None},
            )
    finally:
        plt.close(figure)


def _plot_epoch_latency_cdf(artifacts_dir: Path, figures_dir: Path) -> None:
    """Plot epoch average latency only when at least two samples exist."""
    csv_path = artifacts_dir / "benchmark_scenario_raw.csv"
    if csv_path.is_symlink():
        raise ValueError("raw scenario CSV is indirect")
    if not csv_path.exists():
        return
    if not csv_path.is_file():
        raise ValueError("raw scenario CSV is not a regular file")

    latencies = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["test_type"] == "epoch":
                latency_text = row["avg_latency_us"]
                if not latency_text:
                    continue
                val = float(latency_text)
                if val <= 0:
                    raise ValueError("epoch latency evidence is not positive")
                latencies.append(val)

    if len(latencies) < 2:
        return

    x, y = _cdf(latencies)

    fig, ax = plt.subplots(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT))
    ax.plot(x, y, color=COLORS["epoch"], linewidth=2)
    ax.set_xlabel("Average Latency (us)")
    ax.set_ylabel("CDF")
    ax.set_title("Epoch Test Latency Distribution")
    ax.set_ylim(0, 1.05)
    ax.grid(True, alpha=0.3)
    ax.axhline(y=0.5, color="gray", linestyle="--", alpha=0.4, linewidth=0.8)
    ax.axhline(y=0.95, color="gray", linestyle="--", alpha=0.4, linewidth=0.8)

    path = figures_dir / "epoch_latency_cdf.svg"
    _save_svg(fig, path)
    print(f"  Figure: {path.name}", file=sys.stderr)


def _plot_boundary_ack_gate_cdf(artifacts_dir: Path, figures_dir: Path) -> None:
    """CDF of exact ACK-gate duration across all transitions."""
    rows = _read_transitions_raw(artifacts_dir)
    if not rows:
        return

    ack_gate_cols = [k for k in rows[0].keys() if k.startswith("ack_gate_ns_")]
    if not ack_gate_cols:
        return

    series = []
    for col in sorted(ack_gate_cols):
        values = [float(r[col]) for r in rows if r[col]]
        if len(values) < 2:
            continue
        series.append((col, [value / 1000.0 for value in values]))
    if not series:
        return

    fig, ax = plt.subplots(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT))

    line_colors = ["#2196F3", "#F44336", "#4CAF50", "#FF9800"]
    for i, (col, values_us) in enumerate(series):
        x, y = _cdf(values_us)
        label = col.removeprefix("ack_gate_ns_")
        color = line_colors[i % len(line_colors)]
        ax.plot(x, y, color=color, linewidth=2, label=label)

    ax.set_xlabel("Boundary ACK-Gate Duration (us)")
    ax.set_ylabel("CDF")
    ax.set_title("Boundary ACK-Gate Duration (All Transitions)")
    ax.set_ylim(0, 1.05)
    if all(value > 0.0 for _column, values in series for value in values):
        ax.set_xscale("log")
    ax.grid(True, alpha=0.3)
    ax.axhline(y=0.5, color="gray", linestyle="--", alpha=0.4, linewidth=0.8)
    ax.axhline(y=0.95, color="gray", linestyle="--", alpha=0.4, linewidth=0.8)
    ax.legend(loc="lower right")

    path = figures_dir / "boundary_ack_gate_ns_cdf.svg"
    _save_svg(fig, path)
    print(f"  Figure: {path.name}", file=sys.stderr)


def _plot_boundary_ack_gate_by_type(artifacts_dir: Path, figures_dir: Path) -> None:
    """Plot full-range ACK-gate duration by transition type and boundary."""
    rows = _read_transitions_raw(artifacts_dir)
    if not rows:
        return

    ack_gate_cols = [k for k in rows[0].keys() if k.startswith("ack_gate_ns_")]
    if not ack_gate_cols:
        return

    # Abbreviated labels for readability
    label_map = {
        "commit_confirmed": "commit",
        "epoch": "epoch",
        "rollback_apply_v1": "rb_v1",
        "rollback_apply_v2": "rb_v2",
        "rollback_full": "rb_full",
        "rollback_selective": "rb_sel",
    }

    for boundary_ordinal, col in enumerate(sorted(ack_gate_cols)):
        boundary_id = col.removeprefix("ack_gate_ns_")

        # Group by transition type
        by_type: Dict[str, List[float]] = {}
        for r in rows:
            ttype = r["transition_type"]
            val = float(r[col]) / 1000.0  # ns to us
            by_type.setdefault(ttype, []).append(val)

        types_sorted = sorted(by_type.keys())
        data = [by_type[t] for t in types_sorted]
        colors = [COLORS.get(t, "#999999") for t in types_sorted]
        labels = [label_map.get(t, t) for t in types_sorted]

        # Full-range plot
        fig, ax = plt.subplots(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT))
        bp = ax.boxplot(data, labels=labels, patch_artist=True, widths=0.6)
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
        ax.set_ylabel("Boundary ACK-Gate Duration (us)")
        ax.set_title(f"ACK-Gate Duration by Transition Type ({boundary_id})")
        ax.grid(True, axis="y", alpha=0.3)
        plt.xticks(rotation=30, ha="right")

        path = figures_dir / (
            f"boundary_ack_gate_ns_by_type_{boundary_ordinal:03d}.svg"
        )
        _save_svg(fig, path)
        print(f"  Figure: {path.name}", file=sys.stderr)
