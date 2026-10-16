"""Tests for benchmark report dependency and artifact preflight."""

import contextlib
import io
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from kinetum_benchmark import __main__ as benchmark_cli
from kinetum_benchmark import plotter
from kinetum_benchmark.aggregator import _distribution
from kinetum_benchmark.plotter import (
    _boxplot_statistics,
    _plot_boundary_ack_gate_cdf,
    _plot_epoch_latency_cdf,
    _save_svg,
)
from kinetum_benchmark.raw_export import _csv_latency
from kinetum_benchmark.tables import (
    _statistic_cell,
    _write_boundary_ordering_table,
)


class TestBenchmarkReportPreflight(unittest.TestCase):
    """Report prerequisites must fail before derived artifact ownership."""

    def test_missing_figure_backend_creates_no_partial_artifact_tree(self) -> None:
        """Matplotlib unavailability rejects before CSV/table publication."""
        with tempfile.TemporaryDirectory() as directory:
            benchmark_root = Path(directory).resolve()
            (benchmark_root / "benchmark_summary.json").write_text(
                "{}\n", encoding="utf-8"
            )
            (benchmark_root / "manifest.json").write_text(
                "{}\n", encoding="utf-8"
            )
            arguments = Namespace(
                input_dir=benchmark_root,
                inclusion_policy="passed-only",
            )
            with patch.object(
                benchmark_cli,
                "parse_exact_json_object",
                side_effect=[{"inclusion_policy": "passed_only"}, {}],
            ), patch.object(
                benchmark_cli, "validate_benchmark_summary_identity"
            ), patch.object(
                benchmark_cli,
                "require_figure_backend",
                side_effect=RuntimeError("matplotlib unavailable"),
            ), patch.object(
                benchmark_cli, "export_raw"
            ) as export_raw, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "matplotlib unavailable"):
                    benchmark_cli.cmd_report(arguments)

            export_raw.assert_not_called()
            self.assertFalse((benchmark_root / "artifacts").exists())

    def test_unavailable_latency_stays_absent_in_every_report_projection(self) -> None:
        """Null latency becomes n/a or empty and never a zero-valued figure."""
        self.assertEqual(_statistic_cell({}, "p50", 2), "n/a")
        self.assertEqual(_csv_latency(None), "")
        measured = {
            "avg_latency_us": {
                "min": 1.0,
                "p50": 2.0,
                "p95": 3.0,
                "p99": 4.0,
                "max": 5.0,
                "count": 100,
            }
        }
        self.assertEqual(_statistic_cell(measured["avg_latency_us"], "p50", 2), "2.00")
        self.assertEqual(_statistic_cell(measured["avg_latency_us"], "p99", 2), "4.00")

        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory).resolve()
            figures = artifacts / "figures"
            figures.mkdir()
            csv_path = artifacts / "benchmark_scenario_raw.csv"
            csv_path.write_text(
                "test_type,avg_latency_us\nepoch,\n",
                encoding="utf-8",
            )
            _plot_epoch_latency_cdf(artifacts, figures)
            self.assertFalse((figures / "epoch_latency_cdf.svg").exists())

            csv_path.write_text(
                "test_type,avg_latency_us\nepoch,0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "not positive"):
                _plot_epoch_latency_cdf(artifacts, figures)

            csv_path.write_text(
                "test_type,avg_latency_us\nepoch,1.5\nepoch,2.5\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stderr(io.StringIO()):
                _plot_epoch_latency_cdf(artifacts, figures)
            figure = figures / "epoch_latency_cdf.svg"
            first = figure.read_bytes()
            figure.unlink()
            with contextlib.redirect_stderr(io.StringIO()):
                _plot_epoch_latency_cdf(artifacts, figures)
            self.assertEqual(figure.read_bytes(), first)
            self.assertNotIn(b"<dc:date>", first)

    def test_insufficient_ack_population_creates_no_empty_cdf(self) -> None:
        """A one-sample ACK series cannot become a content-free CDF figure."""
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory).resolve()
            figures = artifacts / "figures"
            figures.mkdir()
            (artifacts / "benchmark_transitions_raw.csv").write_text(
                "transition_type,ack_gate_ns_boundary\nepoch,1000\n",
                encoding="utf-8",
            )

            _plot_boundary_ack_gate_cdf(artifacts, figures)

            self.assertFalse(
                (figures / "boundary_ack_gate_ns_cdf.svg").exists()
            )

    def test_cdfs_preserve_empirical_steps_and_duplicate_sample_weight(self) -> None:
        """TAP run means and boundary durations cannot imply interpolated observations."""
        cases = (
            (
                "benchmark_scenario_raw.csv",
                "test_type,avg_latency_us\nepoch,1\nepoch,1\nepoch,3\n",
                _plot_epoch_latency_cdf,
            ),
            (
                "benchmark_transitions_raw.csv",
                "transition_type,ack_gate_ns_boundary\nepoch,1000\nepoch,1000\nepoch,3000\n",
                _plot_boundary_ack_gate_cdf,
            ),
        )
        for filename, contents, render in cases:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                artifacts = Path(directory).resolve()
                figures = artifacts / "figures"
                figures.mkdir()
                (artifacts / filename).write_text(contents, encoding="utf-8")
                with patch.object(plotter, "_save_svg", wraps=_save_svg) as save, \
                        contextlib.redirect_stderr(io.StringIO()):
                    render(artifacts, figures)
                line = save.call_args.args[0].axes[0].lines[0]
                vertices = line.get_path().vertices.tolist()
                self.assertEqual(vertices[0], [1.0, 0.0])
                self.assertEqual(vertices[-1], [3.0, 1.0])
                self.assertTrue(all(
                    first[0] == second[0] or first[1] == second[1]
                    for first, second in zip(vertices, vertices[1:])
                ))
                self.assertAlmostEqual(max(y for x, y in vertices if x == 1.0), 2 / 3)

    def test_boxplot_percentiles_match_summary_and_keep_outliers(self) -> None:
        """The plotted p50 equals the table's p50, with Tukey outliers retained."""
        values = [20.0, 2.0, 8.0, 1.0]
        statistics = _boxplot_statistics(values)
        self.assertEqual(statistics, {
            "q1": 1.0, "med": 2.0, "q3": 8.0,
            "whislo": 1.0, "whishi": 8.0, "fliers": [20.0],
        })
        self.assertEqual(statistics["med"], _distribution(values)["p50"])
        self.assertEqual(_boxplot_statistics([4.0, 4.0]), {
            "q1": 4.0, "med": 4.0, "q3": 4.0,
            "whislo": 4.0, "whishi": 4.0, "fliers": [],
        })
        with self.assertRaises(ValueError):
            _distribution([])

    def test_ordered_cut_table_uses_current_artifact_identity(self) -> None:
        """The boundary proof publishes under its ordered-CUT identity."""
        observations = {
            "total_sent": 100,
            "total_received": 100,
            "loss_pct": 0.0,
            "boundary_count": 2,
            "completed_boundaries": 2,
            "protocol_faults_observed": 0,
            "backpressure_events": 0,
        }
        summary = {
            "scenario_metrics": {
                "epoch_test": {
                    name: _distribution([value]) for name, value in observations.items()
                }
            }
        }
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(
            io.StringIO()
        ):
            tables = Path(directory)
            _write_boundary_ordering_table(tables, summary)

            output = tables / "ordered_cut_boundary_proof.md"
            self.assertTrue(output.is_file())
            self.assertTrue(
                output.read_text(encoding="utf-8").startswith(
                    "# Ordered-CUT Boundary Proof\n"
                )
            )
