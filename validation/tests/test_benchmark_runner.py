"""Verify batch termination and attempted-run records across real async cancellation."""

import asyncio
import contextlib
import io
import itertools
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from kinetum_benchmark import runner
from kinetum_benchmark.config.types import BenchmarkConfig


class TestBenchmarkRunner(unittest.IsolatedAsyncioTestCase):
    """Keep publication observations separate from scenario cleanup and batch progress."""

    def setUp(self):
        """Own one temporary batch directory and a recorder for its directory claims."""
        temporary = tempfile.mkdtemp(prefix="kinetum-benchmark-test-")
        self.addCleanup(shutil.rmtree, temporary)
        root = Path(temporary).resolve()
        self.config = BenchmarkConfig(
            runtime_root=root / "runtime", validation_root=root / "kit",
            output_dir=root / "batch", runs=3,
        )
        self.config.output_dir.mkdir()
        self.events = []
        self.published = []
        self.owner = mock.Mock()

        def create_directory(name):
            """Create only the next claimed child under the fixture's owned root."""
            path = self.config.output_dir / name
            path.mkdir()
            return path

        self.owner.create_artifact_directory.side_effect = create_directory

    async def run_batch(self, scenario, publication_failure=None):
        """Run with controlled monotonic samples and observe the terminal manifest data."""
        def publish(root, result):
            """Record finalization only after the scenario's cleanup has returned."""
            self.assertEqual(root, self.config.output_dir)
            self.assertTrue(all(row.duration_s >= 0.25 for row in result.run_results))
            self.events.append("manifest")
            self.published.append(result)
            if publication_failure is not None:
                raise publication_failure

        clock = mock.Mock(spec=["monotonic"])
        clock.monotonic.side_effect = itertools.count(1.0, 0.25)
        # Replace this module's clock binding, leaving asyncio's real deadlines intact.
        with mock.patch.object(runner, "time", clock), mock.patch.object(
            runner, "write_manifest",
        ), mock.patch.object(
            runner, "run_test_suite", side_effect=scenario,
        ), mock.patch.object(
            runner, "_update_manifest_with_results", side_effect=publish,
        ), contextlib.redirect_stderr(io.StringIO()):
            return await runner._run_benchmark_owned(self.config, self.owner)  # pylint: disable=protected-access

    async def test_failed_verdict_keeps_the_remaining_iterations(self):
        """A returned failed verdict has completed cleanup and does not end the batch."""
        async def scenario(config, owner):
            """Return one complete failed verdict between two complete successes."""
            self.assertIs(owner, self.owner)
            passed = config.output_dir.name != "run_002"
            return mock.Mock(all_passed=passed, failed_tests=0 if passed else 1)

        result = await self.run_batch(scenario)
        self.assertEqual((result.total_runs, result.passed_runs, result.failed_runs), (3, 2, 1))
        self.assertEqual([row.run_id for row in result.run_results], [1, 2, 3])
        self.assertEqual(self.published, [result])
        self.assertEqual(self.owner.create_artifact_directory.call_count, 3)

    async def test_execution_exception_stops_before_another_run(self):
        """An execution or cleanup exception propagates with the completed prefix retained."""
        async def scenario(config, owner):
            """Fail the second run after recording its cleanup boundary."""
            self.assertIs(owner, self.owner)
            name = config.output_dir.name
            try:
                if name == "run_002":
                    raise RuntimeError("remote retirement is unproved")
                return mock.Mock(all_passed=True)
            finally:
                self.events.append(f"cleanup:{name}")

        with self.assertRaisesRegex(RuntimeError, "remote retirement is unproved"):
            await self.run_batch(scenario)
        self.assertEqual(self.events, ["cleanup:run_001", "cleanup:run_002", "manifest"])
        self.assertEqual(len(self.published), 1)
        result = self.published[0]
        self.assertEqual((result.total_runs, result.passed_runs, result.failed_runs), (2, 1, 1))
        self.assertIn("remote retirement is unproved", result.run_results[-1].error)
        self.assertFalse((self.config.output_dir / "run_003").exists())

    async def test_task_cancellation_finishes_cleanup_and_records_the_attempted_prefix(self):
        """Task.cancel propagates after asynchronous cleanup and one manifest update."""
        entered = asyncio.Event()

        async def scenario(config, owner):
            """Wait in the second run until the caller delivers actual task cancellation."""
            self.assertIs(owner, self.owner)
            name = config.output_dir.name
            try:
                if name == "run_002":
                    entered.set()
                    await asyncio.Future()
                return mock.Mock(all_passed=True)
            finally:
                await asyncio.sleep(0)
                self.events.append(f"cleanup:{name}")

        task = asyncio.create_task(self.run_batch(scenario))
        try:
            await asyncio.wait_for(entered.wait(), timeout=5.0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(self.events, ["cleanup:run_001", "cleanup:run_002", "manifest"])
        self.assertEqual(len(self.published), 1)
        result = self.published[0]
        self.assertEqual((result.total_runs, result.passed_runs, result.failed_runs), (2, 1, 1))
        self.assertIn("CancelledError", result.run_results[-1].error)
        self.assertFalse((self.config.output_dir / "run_003").exists())

    async def test_manifest_failure_retains_the_original_execution_failure(self):
        """A failed manifest update reports both causes and cannot start another iteration."""
        async def scenario(_config, _owner):
            """Report an execution failure without a complete scenario result."""
            raise RuntimeError("unresolved cleanup")

        with self.assertRaisesRegex(
            RuntimeError, "execution=RuntimeError: unresolved cleanup; publication=OSError: publication failed",
        ):
            await self.run_batch(scenario, OSError("publication failed"))
        self.assertEqual(self.owner.create_artifact_directory.call_count, 1)
