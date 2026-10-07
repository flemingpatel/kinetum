"""Check private validation packaging against staged bytes and a local pip installation.

The selected completed build supplies native helpers. A class fixture stages and
packages them without compiling the platform, then installs into a temporary
target using the Python dependencies already present in the test environment.
No package index or host installation is used during these checks.
"""

from __future__ import annotations

from collections.abc import Iterator
from email.parser import BytesParser
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

from packaging.requirements import Requirement
from packaging.utils import parse_wheel_filename
from packaging.version import Version
import pytest


def _run_tool(arguments: list[str], directory: Path) -> subprocess.CompletedProcess[str]:
    """Run one Linux fixture tool and retire its process group before cleanup.

    Keep the leader unreaped until group retirement so its numeric identity
    cannot be reused. File-backed output lets the frontend and backend finish
    without filling a pipe or making descendant-held pipes prolong a timeout.
    """
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        with subprocess.Popen(
            arguments, cwd=directory, stdin=subprocess.DEVNULL, stdout=output,
            stderr=error, start_new_session=True, umask=0o022,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                 "TMPDIR": os.fspath(directory), "PIP_CONFIG_FILE": os.devnull},
        ) as process:
            try:
                deadline = time.monotonic() + 300
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(arguments, 300)
                    if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                        break
                    time.sleep(min(remaining, 0.01))
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        output.seek(0)
        error.seek(0)
        result = subprocess.CompletedProcess(
            arguments, process.returncode, output.read().decode("utf-8"), error.read().decode("utf-8"),
        )
    result.check_returncode()
    return result


def _module_command(installed: Path, module: str, *arguments: str) -> list[str]:
    """Run an installed target through the current interpreter's isolated module entrance."""
    program = (
        "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
        "runpy.run_module(sys.argv.pop(1),run_name='__main__')"
    )
    return [sys.executable, "-I", "-B", "-X", "utf8", "-c", program,
            os.fspath(installed), module, *arguments]


@pytest.mark.usefixtures("installed_validation_package")
class ValidationPackageTest(unittest.TestCase):
    """Verify installed package identity, resources, and native helper execution."""

    stage: Path
    wheel: Path
    installed: Path
    working_directory: Path

    def test_wheel_contains_exact_staged_files_and_matching_native_tag(self) -> None:
        """Every staged member survives packaging and the wheel tag matches both ELF images."""
        expected = {
            path.relative_to(self.stage).as_posix(): hashlib.sha256(path.read_bytes()).digest()
            for package in ("kinetum_validation", "kinetum_benchmark")
            for path in (self.stage / package).rglob("*") if path.is_file()
        }
        with zipfile.ZipFile(self.wheel) as archive:
            actual = {
                name: hashlib.sha256(archive.read(name)).digest()
                for name in archive.namelist()
                if name.startswith(("kinetum_validation/", "kinetum_benchmark/")) and not name.endswith("/")
            }
            self.assertEqual(set(actual), set(expected))
            for name, digest in expected.items():
                self.assertEqual(actual[name], digest, name)
            self.assertFalse(any("__pycache__" in name or name.endswith((".pyc", ".pyo")) for name in actual))
            wheel_records = [name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")]
            self.assertEqual(len(wheel_records), 1)
            metadata = BytesParser().parsebytes(archive.read(wheel_records[0]))
            self.assertEqual(metadata["Root-Is-Purelib"], "false")
            expected_platform = f"linux_{platform.machine()}"
            self.assertEqual(metadata.get_all("Tag"), [f"py3-none-{expected_platform}"])
            name, version, _, tags = parse_wheel_filename(self.wheel.name)
            self.assertEqual(name, "kinetum-validation")
            self.assertEqual({tag.platform for tag in tags}, {expected_platform})
            packaged_version = archive.read("kinetum_validation/data/VERSION").decode("ascii").strip()
            self.assertEqual(version, Version(packaged_version))
            machine = {"x86_64": 62, "aarch64": 183}[platform.machine()]
            for helper in ("kinetum_tap_sender", "kinetum_tap_analyzer"):
                member = f"kinetum_validation/data/bin/{helper}"
                native_bytes = archive.read(member)
                header = native_bytes[:20]
                self.assertEqual(header[:6], b"\x7fELF\x02\x01", helper)
                self.assertEqual(int.from_bytes(header[18:20], "little"), machine, helper)
                self.assertEqual((archive.getinfo(member).external_attr >> 16) & 0o111, 0o111, helper)
                marker = b"KINETUM_RELEASE_VERSION=" + packaged_version.encode("ascii") + b"\0"
                self.assertTrue(marker in native_bytes, f"{helper} compiled version differs from package VERSION")

    def test_installed_modules_use_their_own_resources_with_isolated_startup(self) -> None:
        """Installed module defaults stay inside the installation despite hostile ambient imports."""
        hostile = self.working_directory / "hostile"
        hostile.mkdir()
        marker = hostile / "startup-executed"
        (hostile / "sitecustomize.py").write_text(
            "from pathlib import Path\n" + f"Path({os.fspath(marker)!a}).touch()\n", encoding="ascii"
        )
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
            "PYTHONPATH": os.fspath(hostile),
        }
        probe = (
            "import json,sys;sys.path.insert(0,sys.argv[1]);"
            "from kinetum_validation import VALIDATION_ROOT;"
            "from importlib.metadata import version;"
            "print(json.dumps({'root':str(VALIDATION_ROOT),'version':version('kinetum-validation')}))"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", probe, os.fspath(self.installed)],
            cwd=hostile, env=environment, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, check=False, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        data = self.installed / "kinetum_validation/data"
        self.assertEqual(observed["root"], os.fspath(data))
        self.assertEqual(Version(observed["version"]), Version((data / "VERSION").read_text().strip()))
        for module in ("kinetum_validation", "kinetum_benchmark"):
            with self.subTest(module=module):
                result = subprocess.run(
                    _module_command(self.installed, module, "--help"),
                    cwd=hostile, env=environment, stdin=subprocess.DEVNULL, capture_output=True,
                    text=True, check=False, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)
        self.assertFalse(marker.exists())

    def test_missing_resources_reject_before_runtime_execution(self) -> None:
        """Incomplete selected resources cannot execute a runtime command or create run output."""
        with tempfile.TemporaryDirectory(dir=self.working_directory) as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            (runtime / "bin").mkdir(parents=True)
            (runtime / "lib/modules").mkdir(parents=True)
            marker = root / "runtime-executed"
            for name in ("kinetum-info", "kinetum_cp", "kinetum_dp", "kinetum_pack", "kinetum_photon", "kinetumctl"):
                binary = runtime / "bin" / name
                binary.write_text("#!/bin/sh\ntouch " + shlex.quote(os.fspath(marker)) + "\n", encoding="utf-8")
                binary.chmod(0o755)
            resources = root / "resources"
            resources.mkdir()
            output = root / "run"
            result = subprocess.run(
                _module_command(self.installed, "kinetum_validation", "--runtime-root", os.fspath(runtime),
                                "--validation-root", os.fspath(resources), "--output-dir", os.fspath(output),
                                "--dry-run"),
                cwd=root, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("validation helper", result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse(output.exists())

    def test_installed_native_helpers_execute_without_build_tree_paths(self) -> None:
        """Pip preserves native helper bytes and executable permissions at the new location."""
        for name in ("kinetum_tap_sender", "kinetum_tap_analyzer"):
            with self.subTest(helper=name):
                binary = self.installed / "kinetum_validation/data/bin" / name
                staged = self.stage / "kinetum_validation/data/bin" / name
                self.assertEqual(hashlib.sha256(binary.read_bytes()).digest(),
                                 hashlib.sha256(staged.read_bytes()).digest())
                self.assertTrue(os.access(binary, os.X_OK))
                result = _run_tool([os.fspath(binary), "--help"], self.working_directory)
                self.assertIn(name, result.stdout)


@pytest.fixture(scope="class")
def installed_validation_package(package_build_directory: Path) -> Iterator[None]:
    """Own staging, wheel construction, and local installation for the whole class."""
    with tempfile.TemporaryDirectory(prefix="kinetum-validation-package-") as temporary:
        root = Path(temporary).resolve(strict=True)
        try:
            _run_tool(
                ["/usr/bin/cmake", "--install", os.fspath(package_build_directory),
                 "--config", "Release", "--component", "KinetumValidationKit",
                 "--prefix", os.fspath(root / "stage")], root,
            )
            stage = root / "stage/validation"
            _run_tool(
                [sys.executable, "-I", "-B", "-m", "build", "--no-isolation", "--wheel",
                 "--outdir", os.fspath(root / "wheels")], stage,
            )
            wheels = list((root / "wheels").glob("*.whl"))
            if len(wheels) != 1:
                raise RuntimeError("validation fixture did not produce exactly one wheel")
            wheel = wheels[0]
            with zipfile.ZipFile(wheel) as archive:
                metadata_paths = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
                if len(metadata_paths) != 1:
                    raise RuntimeError("validation wheel must contain exactly one package metadata record")
                metadata = BytesParser().parsebytes(archive.read(metadata_paths[0]))
            requirements = [Requirement(value) for value in metadata.get_all("Requires-Dist", [])]
            if {requirement.name for requirement in requirements} != {"matplotlib"}:
                raise RuntimeError("validation wheel must declare its reporting dependency only")
            for requirement in requirements:
                installed_version = importlib.metadata.version(requirement.name)
                if not requirement.specifier.contains(installed_version):
                    raise RuntimeError(f"test environment does not satisfy {requirement}")
            installed = root / "installed"
            _run_tool(
                [sys.executable, "-I", "-B", "-m", "pip", "--isolated", "install",
                 "--no-index", "--no-deps", "--no-compile", "--disable-pip-version-check", "--no-input",
                 "--cache-dir", os.fspath(root / "pip-cache"),
                 "--target", os.fspath(installed), os.fspath(wheel)], root,
            )
        except subprocess.CalledProcessError as exc:
            pytest.exit(f"validation package fixture failed: {exc}\n{exc.stdout}{exc.stderr}",
                        returncode=pytest.ExitCode.TESTS_FAILED)
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, subprocess.TimeoutExpired,
                importlib.metadata.PackageNotFoundError) as exc:
            pytest.exit(f"validation package fixture failed: {exc}", returncode=pytest.ExitCode.TESTS_FAILED)
        ValidationPackageTest.stage = stage
        ValidationPackageTest.wheel = wheel
        ValidationPackageTest.installed = installed
        ValidationPackageTest.working_directory = root
        yield
