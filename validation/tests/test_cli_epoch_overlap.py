"""
Tests for TRex epoch-overlap CLI admission.

The validation and benchmark CLIs are the public switchboard for physical
TRex evidence. These tests keep transition authoring, run ownership, and
overlap bounds from drifting independently of the traffic driver.
"""

import asyncio
import contextlib
import io
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from kinetum_benchmark import __main__ as benchmark_cli
from kinetum_benchmark import runner as benchmark_runner
from kinetum_benchmark.config.types import (
    BenchmarkConfig,
    BenchmarkScenarioConfig,
)
from kinetum_validation import __main__ as validation_cli
from kinetum_validation import orchestrator as validation_orchestrator
from kinetum_validation.config.types import (
    CONSTANTS, DEPLOYMENT_SPECS, DeploymentMode,
    ProcessConfig,
    StorageProfile,
    TestConfig as ValidationConfig,
    TestType as ValidationTestType,
)


def _validation_args(runtime_root, validation_root, *extra_args):
    """Parse validation CLI args with TRex physical defaults."""
    argv = [
        "kinetum_validation",
        "--deployment", "fan-in-edge-gateway",
        "--backend", "dpdk-pci",
        "--traffic-host", "traffic-host",
        "--test-type", "epoch",
        "--runtime-root", str(runtime_root),
        "--validation-root", str(validation_root),
        "--output-dir", str(runtime_root.parent / "validation-output"),
        *extra_args,
    ]
    with mock.patch.object(sys, "argv", argv):
        return validation_cli.parse_args()


def _benchmark_args(*extra_args):
    """Parse benchmark CLI args with TRex physical defaults."""
    argv = [
        "kinetum_benchmark",
        "run",
        "--runtime-root", "/opt/kinetum",
        "--validation-root", "/var/tmp/kinetum-validation",
        "--deployment", "fan-in-edge-gateway",
        "--backend", "dpdk-pci",
        "--traffic-host", "traffic-host",
        "--test-type", "epoch",
        *extra_args,
    ]
    with mock.patch.object(sys, "argv", argv):
        return benchmark_cli.parse_args()


def _installed_roots(tmpdir):
    """Create the exact installed-root shape admitted by the CLI."""
    root = Path(tmpdir).resolve(strict=True)
    runtime_root = root / "runtime"
    validation_root = root / "private-kit"
    runtime_bin = runtime_root / "bin"
    validation_bin = validation_root / "bin"
    runtime_bin.mkdir(parents=True)
    validation_bin.mkdir(parents=True)
    (runtime_root / "lib/modules").mkdir(parents=True)
    (validation_root / "examples").mkdir()
    for name in (
        "kinetum-info",
        "kinetum_cp",
        "kinetum_dp",
        "kinetum_pack",
        "kinetum_photon",
        "kinetumctl",
    ):
        binary = runtime_bin / name
        binary.write_text("", encoding="utf-8")
        binary.chmod(0o755)
    for name in ("kinetum_tap_sender", "kinetum_tap_analyzer"):
        binary = validation_bin / name
        binary.write_text("", encoding="utf-8")
        binary.chmod(0o755)
    return runtime_root, validation_root


class TestEpochOverlapCLI(unittest.TestCase):
    """Validate CLI admission for orchestrated TRex epoch-overlap runs."""

    def test_storage_profile_selects_the_same_fixture_in_both_clis(self):
        """Both entry points select explicit per-queue bindings independently of RSS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            roots = _installed_roots(tmpdir)
            for topology in ("default", "rx-rss-2"):
                options = (
                    "--storage-profile", "per-rx-queue",
                    "--stream-topology", topology,
                    "--num-flows", str(CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS),
                )
                with self.subTest(topology=topology), contextlib.redirect_stderr(io.StringIO()):
                    validation_args = _validation_args(*roots, *options)
                    benchmark_args = _benchmark_args(*options)
                    self.assertTrue(validation_cli.validate_args(validation_args))
                    self.assertTrue(benchmark_cli.validate_run_args(benchmark_args))
                    config = validation_cli.build_config(validation_args)
                    self.assertEqual(config.storage_profile, StorageProfile.PER_RX_QUEUE)
                    self.assertIn("per_rx_queue_bindings.pbtxt", config.bindings_file)
                    self.assertEqual(benchmark_args.storage_profile, "per-rx-queue")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                _validation_args(*roots, "--storage-profile", "per_rx_queue")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                _benchmark_args("--storage-profile", "per_rx_queue")

    def test_storage_profile_rejects_undeclared_tap_combination(self):
        """Neither CLI replaces a missing per-queue fixture with shared storage."""
        with tempfile.TemporaryDirectory() as tmpdir, contextlib.redirect_stderr(io.StringIO()):
            options = ("--backend", "dpdk-tap", "--storage-profile", "per-rx-queue")
            self.assertFalse(validation_cli.validate_args(_validation_args(*_installed_roots(tmpdir), *options)))
            self.assertFalse(benchmark_cli.validate_run_args(_benchmark_args(*options)))

    def test_validation_cli_accepts_trex_epoch_overlap_syntax(self):
        """Validation CLI should accept the retained TRex transition syntax."""
        with mock.patch.object(sys, "argv", ["kinetum_validation"]), contextlib.redirect_stderr(
            io.StringIO()
        ) as stderr, self.assertRaises(SystemExit) as rejected:
            validation_cli.parse_args()
        self.assertEqual(rejected.exception.code, 2)
        self.assertIn("--runtime-root", stderr.getvalue())
        with mock.patch.object(sys, "argv", ["kinetum_validation", "--runtime-root", "/opt/kinetum"]):
            defaults = validation_cli.parse_args()
        self.assertEqual(
            defaults.validation_root,
            Path(validation_cli.__file__).resolve().parent / "data",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_root, validation_root = _installed_roots(tmpdir)
            args = _validation_args(
                runtime_root, validation_root,
                "--epoch-duration", "15",
                "--epoch-transition-time", "5",
                "--epoch-overlap-ms", "500",
            )

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                self.assertTrue(validation_cli.validate_args(args))

            dry_with_remote_residue = _validation_args(
                runtime_root, validation_root, "--dry-run"
            )
            dry_exact = _validation_args(
                runtime_root, validation_root,
                "--dry-run", "--traffic-host", "",
            )
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(
                    validation_cli.validate_args(dry_with_remote_residue)
                )
                self.assertTrue(validation_cli.validate_args(dry_exact))

            abbreviated = [
                "kinetum_validation",
                "--runtime-root", str(runtime_root),
                "--validation-root", str(validation_root),
                "--epoch-over",
                "500",
            ]
            with mock.patch.object(
                sys, "argv", abbreviated
            ), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit
            ):
                validation_cli.parse_args()

            retired_option = [
                "kinetum_validation",
                "--runtime-root", str(runtime_root),
                "--validation-root", str(validation_root),
                "--traffic-driver",
                "trex",
            ]
            with mock.patch.object(
                sys, "argv", retired_option
            ), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit
            ):
                validation_cli.parse_args()

    def test_validation_live_modes_have_no_local_capability_gate(self):
        """Every implemented scenario requires its exact deployment facts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_root, validation_root = _installed_roots(tmpdir)
            for test_type in (
                "standard", "epoch", "commit-confirmed", "rollback",
                "guardrails", "full",
            ):
                with self.subTest(test_type=test_type):
                    args = _validation_args(
                        runtime_root, validation_root,
                        "--test-type", test_type,
                    )
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertTrue(validation_cli.validate_args(args))

            for test_type in (
                "epoch", "commit-confirmed", "rollback", "guardrails", "full",
            ):
                with self.subTest(passthrough_test_type=test_type):
                    args = _validation_args(
                        runtime_root,
                        validation_root,
                        "--deployment", "passthrough",
                        "--backend", "dpdk-tap",
                        "--test-type", test_type,
                    )
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertFalse(validation_cli.validate_args(args))

            mode = DeploymentMode.FAN_IN_EDGE_GATEWAY
            incomplete = replace(
                DEPLOYMENT_SPECS[mode], config_snapshot_v2=None
            )
            with mock.patch.dict(
                validation_cli.DEPLOYMENT_SPECS, {mode: incomplete}
            ):
                for test_type in (
                    "epoch", "commit-confirmed", "rollback", "full"
                ):
                    with self.subTest(missing_transition=test_type):
                        args = _validation_args(
                            runtime_root,
                            validation_root,
                            "--test-type", test_type,
                        )
                        with contextlib.redirect_stderr(io.StringIO()):
                            self.assertFalse(
                                validation_cli.validate_args(args)
                            )

            reused = replace(
                DEPLOYMENT_SPECS[mode],
                config_snapshot_v2=DEPLOYMENT_SPECS[mode].config_snapshot,
            )
            with mock.patch.dict(
                validation_cli.DEPLOYMENT_SPECS, {mode: reused}
            ), contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertFalse(
                    validation_cli.validate_args(
                        _validation_args(runtime_root, validation_root)
                    )
                )
            self.assertIn("distinct from bootstrap", stderr.getvalue())

    def test_guardrails_requires_an_explicit_degradation_fixture_fact(self):
        """Every CLI/library entry rejects a missing degradation fixture."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_root, validation_root = _installed_roots(tmpdir)
            args = _validation_args(
                runtime_root,
                validation_root,
                "--test-type",
                "guardrails",
            )
            mode = DeploymentMode.FAN_IN_EDGE_GATEWAY
            incomplete = replace(
                DEPLOYMENT_SPECS[mode], guardrails_degradation_snapshot=None
            )
            with mock.patch.dict(
                validation_cli.DEPLOYMENT_SPECS, {mode: incomplete}
            ):
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertFalse(validation_cli.validate_args(args))
                self.assertIn(
                    "explicit guardrails degradation", stderr.getvalue()
                )

                benchmark_args = _benchmark_args(
                    "--test-type", "guardrails"
                )
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertFalse(
                        benchmark_cli.validate_run_args(benchmark_args)
                    )
                self.assertIn(
                    "explicit guardrails degradation", stderr.getvalue()
                )

                validation_output = Path(tmpdir) / "validation-output"
                validation_config = ValidationConfig(
                    process=ProcessConfig(runtime_root=runtime_root, validation_root=validation_root),
                    deployment=mode,
                    test_type=ValidationTestType.GUARDRAILS,
                    output_dir=validation_output,
                )
                with self.assertRaisesRegex(
                    RuntimeError, "explicit guardrails degradation"
                ):
                    asyncio.run(
                        validation_orchestrator.run_test_suite(
                            validation_config
                        )
                    )

                benchmark_output = Path(tmpdir) / "benchmark-output"
                benchmark_config = BenchmarkConfig(
                    runtime_root=runtime_root,
                    validation_root=validation_root,
                    scenario=BenchmarkScenarioConfig(
                        deployment=mode.value,
                        test_type=ValidationTestType.GUARDRAILS.value,
                    ),
                    output_dir=benchmark_output,
                )
                with self.assertRaisesRegex(
                    RuntimeError, "explicit guardrails degradation"
                ):
                    asyncio.run(
                        benchmark_runner.run_benchmark(benchmark_config)
                    )

            self.assertFalse(validation_output.exists())
            self.assertFalse(benchmark_output.exists())

            reused = replace(
                DEPLOYMENT_SPECS[mode],
                guardrails_degradation_snapshot=(
                    DEPLOYMENT_SPECS[mode].config_snapshot_v2
                ),
            )
            with mock.patch.dict(
                validation_cli.DEPLOYMENT_SPECS, {mode: reused}
            ), contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertFalse(validation_cli.validate_args(args))
            self.assertIn("dedicated guardrails degradation", stderr.getvalue())

    def test_no_color_reaches_the_reporter_configuration(self):
        """The public color switch must not stop at argument parsing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = _validation_args(
                *_installed_roots(tmpdir), "--no-color"
            )
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertTrue(validation_cli.validate_args(args))
            self.assertFalse(validation_cli.build_config(args).color)

    def test_validation_main_dispatches_live_transition_without_precreating_output(self):
        """Main delegates a valid live scenario to the run owner."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_root, validation_root = _installed_roots(tmpdir)
            output_dir = Path(tmpdir) / "packet-output"
            argv = [
                "kinetum_validation",
                "--deployment", "fan-in-edge-gateway",
                "--backend", "dpdk-pci",
                "--traffic-host", "traffic-host",
                "--test-type", "epoch",
                "--runtime-root", str(runtime_root),
                "--validation-root", str(validation_root),
                "--output-dir", str(output_dir),
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                validation_cli,
                "run_test_suite",
                new=mock.AsyncMock(return_value=mock.Mock(all_passed=True)),
            ) as run_suite, contextlib.redirect_stderr(io.StringIO()):
                exit_code = asyncio.run(validation_cli.main())

            self.assertEqual(exit_code, 0)
            run_suite.assert_awaited_once()
            self.assertFalse(output_dir.exists())

    def test_programmatic_validation_dispatches_transition_with_live_run_owner(self):
        """The library entry point accepts EPOCH after exact root admission."""
        config = ValidationConfig(
            process=ProcessConfig(
                runtime_root=Path("/opt/kinetum"), validation_root=Path("/var/tmp/kinetum-validation"),
            ),
            test_type=ValidationTestType.EPOCH, output_dir=Path("/tmp/owned"),
        )
        owner = mock.Mock()
        owner.owns_directory.return_value = True
        expected = mock.Mock(all_passed=True)
        with mock.patch.object(
            validation_orchestrator, "installed_root_errors", return_value=[]
        ), mock.patch.object(
            validation_orchestrator,
            "installed_example_input_errors",
            return_value=[],
        ), mock.patch.object(
            validation_orchestrator,
            "collect_runtime_release_metadata",
            return_value={"version": "0.1.0"},
        ), mock.patch.object(
            validation_orchestrator, "ConsoleReporter"
        ), mock.patch.object(
            validation_orchestrator, "TestOrchestrator"
        ) as orchestrator_type:
            orchestrator_type.return_value.run = mock.AsyncMock(
                return_value=expected
            )
            result = asyncio.run(
                validation_orchestrator.run_test_suite(config, owner)
            )

        self.assertIs(result, expected)
        orchestrator_type.return_value.run.assert_awaited_once()

    def test_programmatic_validation_rejects_installed_root_indirection(self):
        """The library admits roots and selected example files before ownership."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_root, validation_root = _installed_roots(tmpdir)
            runtime_alias = Path(tmpdir) / "runtime-alias"
            runtime_alias.symlink_to(runtime_root, target_is_directory=True)
            output_dir = Path(tmpdir) / "validation-output"
            config = ValidationConfig(
                test_type=ValidationTestType.STANDARD,
                process=ProcessConfig(
                    runtime_root=runtime_alias,
                    validation_root=validation_root,
                ),
                output_dir=output_dir,
            )

            with mock.patch.object(
                validation_orchestrator, "ConsoleReporter"
            ) as reporter_type, mock.patch.object(
                validation_orchestrator, "TestOrchestrator"
            ) as orchestrator_type:
                with self.assertRaisesRegex(
                    RuntimeError, "installed validation layout rejected"
                ):
                    asyncio.run(validation_orchestrator.run_test_suite(config))

            reporter_type.assert_not_called()
            orchestrator_type.assert_not_called()
            self.assertFalse(output_dir.exists())

            direct_config = ValidationConfig(
                test_type=ValidationTestType.STANDARD,
                process=ProcessConfig(
                    runtime_root=runtime_root,
                    validation_root=validation_root,
                ),
                output_dir=Path(tmpdir) / "missing-input-output",
            )
            missing = validation_orchestrator.installed_example_input_errors(
                direct_config.process.validation_root,
                direct_config.spec.example_dir,
                direct_config.required_example_files,
            )
            self.assertTrue(missing)
            deployment_root = (
                direct_config.process.examples_dir
                / direct_config.spec.example_dir
            )
            deployment_root.mkdir()
            for name in direct_config.required_example_files:
                (deployment_root / name).write_text("fixture\n", encoding="utf-8")
            self.assertEqual(
                validation_orchestrator.installed_example_input_errors(
                    direct_config.process.validation_root,
                    direct_config.spec.example_dir,
                    direct_config.required_example_files,
                ),
                [],
            )

    def test_validation_cli_rejects_overlap_outside_duration(self):
        """Validation CLI rejects timing and representability overflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            installed_roots = _installed_roots(tmpdir)
            for extra_args in (
                (
                    "--epoch-duration", "5.2",
                    "--epoch-transition-time", "5",
                    "--epoch-overlap-ms", "500",
                ),
                ("--epoch-overlap-ms", str(1 << 32)),
            ):
                with self.subTest(extra_args=extra_args):
                    args = _validation_args(*installed_roots, *extra_args)
                    with contextlib.redirect_stdout(
                        io.StringIO()
                    ), contextlib.redirect_stderr(io.StringIO()):
                        self.assertFalse(validation_cli.validate_args(args))

    def test_validation_cli_rejects_unsupported_stream_topology(self):
        """Validation CLI should reject topology profiles unsupported by backend."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_root, validation_root = _installed_roots(tmpdir)
            argv = [
                "kinetum_validation",
                "--deployment", "fan-in-edge-gateway",
                "--backend", "dpdk-tap",
                "--stream-topology", "rx-rss-2",
                "--runtime-root", str(runtime_root),
                "--validation-root", str(validation_root),
            ]
            with mock.patch.object(sys, "argv", argv):
                args = validation_cli.parse_args()

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                self.assertFalse(validation_cli.validate_args(args))

    def test_validation_cli_rejects_rx_rss_2_without_flow_diversity(self):
        """RSS topology should require enough generated flows for balance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = _validation_args(
                *_installed_roots(tmpdir),
                "--stream-topology", "rx-rss-2",
                "--num-flows", str(CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS - 1),
            )

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                self.assertFalse(validation_cli.validate_args(args))

    def test_validation_cli_accepts_rx_rss_2_with_flow_diversity(self):
        """RSS topology should accept the explicit balance-proof workload."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = _validation_args(
                *_installed_roots(tmpdir),
                "--stream-topology", "rx-rss-2",
                "--num-flows", str(CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS),
            )

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                self.assertTrue(validation_cli.validate_args(args))

    def test_validation_cli_rejects_installed_root_symlink_indirection(self):
        """An alias cannot become the runtime or validation authority."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_root, validation_root = _installed_roots(tmpdir)
            runtime_alias = Path(tmpdir) / "runtime-alias"
            runtime_alias.symlink_to(runtime_root, target_is_directory=True)
            args = _validation_args(
                runtime_alias,
                validation_root,
                "--test-type",
                "standard",
            )

            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertFalse(validation_cli.validate_args(args))

            self.assertIn("symlink indirection", stderr.getvalue())

    def test_validation_cli_rejects_nested_installed_path_indirection(self):
        """No consumed bin, lib, or examples path component may be indirect."""
        for domain, relative_path in (
            ("runtime", Path("bin")),
            ("runtime", Path("lib")),
            ("kit", Path("bin")),
            ("kit", Path("examples")),
        ):
            with self.subTest(path=relative_path), tempfile.TemporaryDirectory() as tmpdir:
                runtime_root, validation_root = _installed_roots(tmpdir)
                base = runtime_root if domain == "runtime" else validation_root
                indirect = base / relative_path
                real = indirect.with_name(f"{indirect.name}-real")
                indirect.rename(real)
                indirect.symlink_to(real, target_is_directory=True)
                args = _validation_args(
                    runtime_root,
                    validation_root,
                    "--test-type",
                    "standard",
                )

                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertFalse(validation_cli.validate_args(args))

                self.assertIn("symlink indirection", stderr.getvalue())

    def test_benchmark_cli_accepts_trex_epoch_overlap(self):
        """Benchmark CLI accepts exact overlap and kebab-case policy values."""
        with mock.patch.object(sys, "argv", ["kinetum_benchmark", "run"]), contextlib.redirect_stderr(
            io.StringIO()
        ) as stderr, self.assertRaises(SystemExit) as rejected:
            benchmark_cli.parse_args()
        self.assertEqual(rejected.exception.code, 2)
        self.assertIn("--runtime-root", stderr.getvalue())
        for command in ("aggregate", "export-csv", "report"):
            with self.subTest(command=command), mock.patch.object(
                sys, "argv", ["kinetum_benchmark", command, "--input-dir", "/tmp/recorded-benchmark"]
            ):
                reporting = benchmark_cli.parse_args()
                self.assertEqual(reporting.command, command)
                self.assertEqual(reporting.input_dir, Path("/tmp/recorded-benchmark"))

        args = _benchmark_args(
            "--epoch-duration", "15",
            "--epoch-transition-time", "5",
            "--epoch-overlap-ms", "500",
            "--inclusion-policy", "all-runs",
        )

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(benchmark_cli.validate_run_args(args))
        self.assertEqual(args.inclusion_policy, "all-runs")

        for rejected_option, rejected_value in (
            ("--inclusion-policy", "all_runs"),
            ("--inclusion-pol", "all-runs"),
            ("--traffic-driver", "trex"),
        ):
            with self.subTest(rejected_option=rejected_option):
                argv = [
                    "kinetum_benchmark", "run",
                    "--runtime-root", "/opt/kinetum",
                    rejected_option, rejected_value,
                ]
                with mock.patch.object(
                    sys, "argv", argv
                ), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
                    SystemExit
                ):
                    benchmark_cli.parse_args()

    def test_benchmark_run_dispatches_live_transition_without_precreating_output(self):
        """Benchmark CLI delegates live transition runs to the batch owner."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "benchmark-output"
            runtime_root, validation_root = _installed_roots(tmpdir)
            args = _benchmark_args(
                "--runtime-root", str(runtime_root),
                "--validation-root", str(validation_root),
                "--output-dir", str(output_dir),
            )
            run_owner = mock.Mock()

            with mock.patch.object(
                benchmark_cli,
                "installed_root_errors",
                return_value=[],
            ), mock.patch.object(
                benchmark_cli,
                "run_benchmark",
                new=mock.AsyncMock(
                    return_value=mock.Mock(interrupted=False, failed_runs=0)
                ),
            ) as run_benchmark, mock.patch.object(
                benchmark_cli,
                "admit_benchmark_inputs",
            ) as admit_inputs, mock.patch.object(
                benchmark_cli.ValidationRunOwner,
                "acquire",
                return_value=contextlib.nullcontext(run_owner),
            ) as acquire, mock.patch.object(
                benchmark_cli, "aggregate"
            ), mock.patch.object(
                benchmark_cli, "export_csv"
            ), contextlib.redirect_stderr(io.StringIO()):
                exit_code = asyncio.run(benchmark_cli.cmd_run(args))

            self.assertEqual(exit_code, 0)
            admit_inputs.assert_called_once()
            run_benchmark.assert_awaited_once()
            self.assertEqual(
                run_benchmark.await_args.args[0].inclusion_policy,
                "passed_only",
            )
            acquire.assert_called_once_with(output_dir)
            self.assertIs(run_benchmark.await_args.args[1], run_owner)
            self.assertFalse(output_dir.exists())

    def test_programmatic_benchmark_dispatches_transition_to_fresh_run_owner(self):
        """The library path has no separate transition-capability gate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "benchmark-output"
            config = BenchmarkConfig(
                runtime_root=Path("/opt/kinetum"),
                validation_root=Path("/var/tmp/kinetum-validation"),
                scenario=BenchmarkScenarioConfig(test_type="epoch"),
                output_dir=output_dir,
            )

            expected = mock.Mock()
            with mock.patch.object(
                benchmark_runner, "installed_root_errors", return_value=[]
            ), mock.patch.object(
                benchmark_runner,
                "installed_example_input_errors",
                return_value=[],
            ), mock.patch.object(
                benchmark_runner.ValidationRunOwner,
                "acquire",
                return_value=contextlib.nullcontext(mock.Mock()),
            ), mock.patch.object(
                benchmark_runner,
                "_run_benchmark_owned",
                new=mock.AsyncMock(return_value=expected),
            ) as owned_run:
                result = asyncio.run(benchmark_runner.run_benchmark(config))

            self.assertIs(result, expected)
            owned_run.assert_awaited_once()
            self.assertFalse(output_dir.exists())

    def test_programmatic_benchmark_rejects_installed_root_indirection(self):
        """Benchmark admission rejects indirect roots and missing inputs pre-lock."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_root, validation_root = _installed_roots(tmpdir)
            runtime_alias = Path(tmpdir) / "runtime-alias"
            runtime_alias.symlink_to(runtime_root, target_is_directory=True)
            output_dir = Path(tmpdir) / "benchmark-output"
            config = BenchmarkConfig(
                scenario=BenchmarkScenarioConfig(test_type="standard"),
                runtime_root=runtime_alias,
                validation_root=validation_root,
                output_dir=output_dir,
            )

            with self.assertRaisesRegex(
                RuntimeError, "installed benchmark layout rejected"
            ):
                asyncio.run(benchmark_runner.run_benchmark(config))

            self.assertFalse(output_dir.exists())

            missing_output = Path(tmpdir) / "missing-input-output"
            direct = BenchmarkConfig(
                scenario=BenchmarkScenarioConfig(test_type="standard"),
                runtime_root=runtime_root,
                validation_root=validation_root,
                output_dir=missing_output,
            )
            with self.assertRaisesRegex(RuntimeError, "scenario inputs"):
                asyncio.run(benchmark_runner.run_benchmark(direct))
            self.assertFalse(missing_output.exists())

    def test_benchmark_standard_uses_installed_root_admission(self):
        """Benchmark execution shares the symlink-free installation gate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_root, validation_root = _installed_roots(tmpdir)
            runtime_alias = Path(tmpdir) / "runtime-alias"
            runtime_alias.symlink_to(runtime_root, target_is_directory=True)
            output_dir = Path(tmpdir) / "benchmark-output"
            args = _benchmark_args(
                "--test-type",
                "standard",
                "--runtime-root",
                str(runtime_alias),
                "--validation-root",
                str(validation_root),
                "--output-dir",
                str(output_dir),
            )

            with mock.patch.object(
                benchmark_cli, "run_benchmark", new=mock.AsyncMock()
            ) as run_benchmark, contextlib.redirect_stderr(io.StringIO()) as stderr:
                exit_code = asyncio.run(benchmark_cli.cmd_run(args))

            self.assertEqual(exit_code, 2)
            run_benchmark.assert_not_awaited()
            self.assertFalse(output_dir.exists())
            self.assertIn("symlink indirection", stderr.getvalue())

    def test_benchmark_cli_rejects_overlap_outside_duration(self):
        """Benchmark CLI rejects timing and representability overflow."""
        for extra_args in (
            (
                "--epoch-duration", "5.2",
                "--epoch-transition-time", "5",
                "--epoch-overlap-ms", "500",
            ),
            ("--epoch-overlap-ms", str(1 << 32)),
        ):
            with self.subTest(extra_args=extra_args):
                args = _benchmark_args(*extra_args)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertFalse(benchmark_cli.validate_run_args(args))

    def test_benchmark_cli_rejects_unsupported_stream_topology(self):
        """Benchmark CLI should reject topology profiles unsupported by backend."""
        argv = [
            "kinetum_benchmark",
            "run",
            "--runtime-root", "/opt/kinetum",
            "--deployment", "fan-in-edge-gateway",
            "--backend", "dpdk-tap",
            "--stream-topology", "rx-rss-2",
        ]
        with mock.patch.object(sys, "argv", argv):
            args = benchmark_cli.parse_args()

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(benchmark_cli.validate_run_args(args))

    def test_benchmark_cli_rejects_rx_rss_2_without_flow_diversity(self):
        """RSS benchmark topology should require balance-proof flow diversity."""
        args = _benchmark_args(
            "--stream-topology", "rx-rss-2",
            "--num-flows", str(CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS - 1),
        )

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(benchmark_cli.validate_run_args(args))

    def test_benchmark_cli_accepts_rx_rss_2_with_flow_diversity(self):
        """RSS benchmark topology should admit the balance-proof workload."""
        args = _benchmark_args(
            "--stream-topology", "rx-rss-2",
            "--num-flows", str(CONSTANTS.RX_RSS_2_MIN_NUM_FLOWS),
        )

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(benchmark_cli.validate_run_args(args))
