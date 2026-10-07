"""Tests for benchmark report dependency and artifact preflight."""

import contextlib
import io
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from kinetum_benchmark import __main__ as benchmark_cli
from kinetum_benchmark.plotter import (
    _plot_boundary_ack_gate_cdf,
    _plot_epoch_latency_cdf,
)
from kinetum_benchmark.raw_export import _csv_latency
from kinetum_benchmark.tables import (
    _latency_cells,
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
        self.assertEqual(_latency_cells({}), ("n/a", "n/a"))
        self.assertEqual(_csv_latency(None), "")
        measured = {
            "avg_latency_us": {
                "min": 1.0,
                "p50": 2.0,
                "p95": 3.0,
                "p99": 4.0,
                "max": 5.0,
                "count": 1,
            }
        }
        self.assertEqual(_latency_cells(measured), ("2.00", "4.00"))

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

    def test_ordered_cut_table_uses_current_artifact_identity(self) -> None:
        """The boundary proof publishes under its ordered-CUT identity."""
        distribution = {
            "min": 1,
            "p50": 1,
            "p95": 1,
            "p99": 1,
            "max": 1,
            "count": 1,
        }
        summary = {
            "scenario_metrics": {
                "epoch_test": {
                    name: dict(distribution)
                    for name in (
                        "total_sent",
                        "total_received",
                        "loss_pct",
                        "boundary_count",
                        "completed_boundaries",
                        "protocol_faults_observed",
                        "backpressure_events",
                    )
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
