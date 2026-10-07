"""Tests for exact installed runtime release-metadata admission."""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kinetum_validation.engine.runtime_release import (
    EXPECTED_BUILD_FEATURES,
    EXPECTED_PLATFORM_CAPABILITIES,
    collect_runtime_release_metadata,
)
from kinetum_validation.process.system_tools import exact_subprocess_environment
from kinetum_validation.version_contract import read_product_version_file


def _write_executable(path: Path, payload: str) -> None:
    """Serve only the combined runtime-verification JSON operation."""
    path.write_text(
        "#!/bin/sh\n"
        '[ "$#" -eq 2 ] && [ "$1" = --check ] && [ "$2" = --json ] || exit 2\n'
        "printf '%s\\n' " + shlex.quote(payload) + "\n",
        encoding="ascii",
    )
    path.chmod(0o755)


def _release_layout(root: Path) -> tuple[Path, Path, Path]:
    """Create exact runtime/validation version roots and return info path."""
    root = root.resolve(strict=True)
    runtime_root = root / "runtime"
    validation_root = root / "private-kit"
    (runtime_root / "bin").mkdir(parents=True)
    validation_root.mkdir()
    for directory in (runtime_root, runtime_root / "bin", validation_root):
        directory.chmod(0o755)
    (runtime_root / "VERSION").write_text("0.1.0\n", encoding="ascii")
    (validation_root / "VERSION").write_text("0.1.0\n", encoding="ascii")
    return runtime_root, validation_root, runtime_root / "bin" / "kinetum-info"


def _exact_payload(runtime_root: Path) -> dict:
    """Return a successful runtime-verification record with no SDK metadata."""
    prefix = os.fspath(runtime_root)
    return {
        "version": "0.1.0",
        "dpdk_version": "24.11.7",
        "tls_enabled": True,
        "build_features": {
            key: False for key in sorted(EXPECTED_BUILD_FEATURES)
        },
        "platform_capabilities": sorted(EXPECTED_PLATFORM_CAPABILITIES),
        "prefix": prefix,
        "status": "ok",
        "errors": 0,
        "runtime_payload": {"verified": True},
        "provider_release": {"verified": True},
        "components": [{"name": "Runtime payload manifest", "present": True}],
        "paths": {
            "binaries": f"{prefix}/bin",
            "modules": f"{prefix}/lib/modules",
        },
    }


class RuntimeReleaseMetadataTest(unittest.TestCase):
    """Validate one refusing release-metadata authority."""

    def test_missing_information_image_has_no_fallback(self) -> None:
        """Neither DP help nor build-tree state can replace kinetum-info."""
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root, validation_root, _ = _release_layout(Path(temporary))
            _write_executable(runtime_root / "bin" / "kinetum_dp", "{}")
            with self.assertRaisesRegex(RuntimeError, "kinetum-info"):
                collect_runtime_release_metadata(runtime_root, validation_root)

    def test_exact_child_environment_removes_loader_interposition(self) -> None:
        """Subprocesses and privileged wrappers reject ambient startup authority."""
        with mock.patch.dict(
            os.environ,
            {
                "LD_PRELOAD": "/tmp/foreign.so",
                "LD_LIBRARY_PATH": "/tmp/foreign-libraries",
                "KINETUM_TEST_VALUE": "kept",
            },
            clear=True,
        ):
            child_environment = exact_subprocess_environment()

        self.assertNotIn("LD_PRELOAD", child_environment)
        self.assertNotIn("LD_LIBRARY_PATH", child_environment)
        self.assertEqual(child_environment["KINETUM_TEST_VALUE"], "kept")

        scripts_root = Path(__file__).resolve().parents[1]
        for wrapper_name in ("run_validation.sh", "run_benchmark.sh"):
            with self.subTest(wrapper=wrapper_name):
                source = (scripts_root / wrapper_name).read_text(encoding="ascii")
                self.assertTrue(source.startswith("#!/bin/bash -p\n"))
                self.assertIn("[[ $- == *p* ]] ||", source)
                self.assertIn(
                    "unset BASH_ENV CDPATH ENV GLOBIGNORE POSIXLY_CORRECT",
                    source,
                )
                self.assertIn('for KINETUM_ENVIRONMENT_NAME in "${!LD_@}"', source)
                self.assertIn(
                    'for KINETUM_ENVIRONMENT_NAME in "${!PYTHON@}"', source
                )
                self.assertIn('export PYTHONPATH="${SCRIPT_DIR}"', source)
                launches = [line.strip() for line in source.splitlines() if line.lstrip().startswith("exec ")]
                self.assertTrue(launches)
                for command in launches:
                    self.assertTrue(command.startswith('exec "${PYTHON_BIN}" -P -s -B -X utf8 -m '), command)
                self.assertIn("sys.version_info.major != 3 or sys.version_info.minor < 12", source)
                with tempfile.TemporaryDirectory() as temporary:
                    hostile = Path(temporary)
                    marker = hostile / "startup-executed"
                    (hostile / "sitecustomize.py").write_text(
                        "from pathlib import Path\n"
                        f"Path({os.fspath(marker)!r}).touch()\n",
                        encoding="ascii",
                    )
                    startup = hostile / "shell-startup"
                    startup.write_text(
                        "touch " + shlex.quote(os.fspath(marker)) + "\n",
                        encoding="ascii",
                    )
                    result = subprocess.run(
                        ["/bin/bash", "-p", os.fspath(scripts_root / wrapper_name), "--help"],
                        cwd=hostile,
                        env={**os.environ, "PYTHONPATH": os.fspath(hostile), "BASH_ENV": os.fspath(startup)},
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(marker.exists())

    def test_runtime_verification_precedes_metadata_and_run_admission(self) -> None:
        """Unprotected code and failing verification stop before metadata can be read."""
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root, validation_root, info = _release_layout(Path(temporary))
            marker = Path(temporary) / "metadata-read"
            info.write_text(
                "#!/bin/sh\ncase \"$1\" in\n"
                "--check) exit 1 ;;\n"
                "--json) touch " + shlex.quote(os.fspath(marker)) + " ;;\n"
                "*) exit 2 ;;\nesac\n",
                encoding="ascii",
            )
            info.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "verification failed"):
                collect_runtime_release_metadata(runtime_root, validation_root)
            self.assertFalse(marker.exists())

            for path in (runtime_root, info.parent, info):
                with self.subTest(unprotected=path):
                    original_mode = path.stat().st_mode & 0o7777
                    path.chmod(original_mode | 0o020)
                    try:
                        with self.assertRaisesRegex(RuntimeError, "owner-protected"):
                            collect_runtime_release_metadata(runtime_root, validation_root)
                        self.assertFalse(marker.exists())
                    finally:
                        path.chmod(original_mode)
            alias = Path(temporary) / "info-alias"
            os.link(info, alias)
            with self.assertRaisesRegex(RuntimeError, "owner-protected"):
                collect_runtime_release_metadata(runtime_root, validation_root)
            self.assertFalse(marker.exists())

    def test_incomplete_duplicate_and_inexact_metadata_fail_closed(self) -> None:
        """Malformed metadata and contradictory runtime-verification outcomes reject."""
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root, validation_root, info = _release_layout(Path(temporary))
            exact = _exact_payload(runtime_root)
            payloads = [
                "{}",
                '{"version":"0.1.0","version":"0.1.0"}',
                json.dumps({**exact, "unknown": True}, separators=(",", ":")),
            ]
            missing = _exact_payload(runtime_root)
            missing["platform_capabilities"].pop()
            payloads.append(json.dumps(missing, separators=(",", ":")))
            for key, value in (
                ("prefix", f"{runtime_root}/"),
                ("prefix", f"{runtime_root}/."),
                ("prefix", f"{runtime_root.parent}//{runtime_root.name}"),
                ("prefix", "/foreign"),
                ("status", "failed"),
                ("errors", 1),
                ("errors", False),
                ("runtime_payload", {"verified": False}),
                ("runtime_payload", {"verified": 1}),
                ("provider_release", {"verified": False}),
                ("provider_release", {"verified": True, "error": "contradiction"}),
                ("components", []),
                ("components", [{"name": "image", "present": False}]),
                ("components", [{"name": "image", "present": 1}]),
                ("components", [{"name": "", "present": True}]),
                ("components", [{"name": "image", "present": True}] * 2),
                ("paths", {"binaries": f"{runtime_root}/bin"}),
                ("paths", {**exact["paths"], "modules": "/foreign/lib/modules"}),
                ("paths", {**exact["paths"], "headers": f"{runtime_root}/sdk/include/kinetum"}),
            ):
                payloads.append(json.dumps({**exact, key: value}, separators=(",", ":")))
            for index, payload in enumerate(payloads):
                with self.subTest(index=index):
                    _write_executable(info, payload)
                    with self.assertRaises(RuntimeError):
                        collect_runtime_release_metadata(
                            runtime_root, validation_root
                        )

    def test_root_owned_information_image_admits_an_unprivileged_reader(self) -> None:
        """One root-owned image is readable by a non-root caller; mixed ownership rejects."""
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root, validation_root, info = _release_layout(Path(temporary))
            _write_executable(info, json.dumps(_exact_payload(runtime_root), separators=(",", ":")))
            original_stat = Path.stat
            original_fstat = os.fstat

            def owner_metadata(metadata: os.stat_result, uid: int) -> os.stat_result:
                """Model ownership without changing host privileges or fixture permissions."""
                fields = list(metadata)
                fields[stat.ST_UID] = uid
                return os.stat_result(fields)

            def root_stat(path: Path, **kwargs) -> os.stat_result:
                """Retain real path/type/mode facts while modeling the installed root's UID."""
                metadata = original_stat(path, **kwargs)
                return owner_metadata(metadata, 0) if path in (runtime_root, info.parent, info) else metadata

            for image_owner in (0, 1001):
                with self.subTest(image_owner=image_owner):
                    def image_fstat(descriptor: int, uid: int = image_owner) -> os.stat_result:
                        """Supply the selected ownership for the held image observation."""
                        return owner_metadata(original_fstat(descriptor), uid)

                    with (
                        mock.patch.object(Path, "stat", root_stat),
                        mock.patch("kinetum_validation.engine.runtime_release.os.geteuid", return_value=1000),
                        mock.patch("kinetum_validation.engine.runtime_release.os.fstat", side_effect=image_fstat),
                    ):
                        if image_owner == 0:
                            result = collect_runtime_release_metadata(runtime_root, validation_root)
                            self.assertEqual(result["version"], "0.1.0")
                        else:
                            with self.assertRaisesRegex(RuntimeError, "owner-protected"):
                                collect_runtime_release_metadata(runtime_root, validation_root)

    def test_exact_installed_metadata_reports_build_and_capability_facts(self) -> None:
        """One verified runtime record admits a runtime-only installation."""
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root, validation_root, info = _release_layout(Path(temporary))
            _write_executable(
                info,
                json.dumps(_exact_payload(runtime_root), separators=(",", ":")),
            )
            metadata = collect_runtime_release_metadata(
                runtime_root, validation_root
            )
            self.assertFalse((runtime_root / "sdk").exists())
            self.assertEqual(metadata["source"], os.fspath(info))
            self.assertEqual(metadata["version"], "0.1.0")
            self.assertEqual(metadata["dpdk_version"], "24.11.7")
            self.assertEqual(
                set(metadata["build_features"]), EXPECTED_BUILD_FEATURES
            )
            self.assertEqual(
                set(metadata["platform_capabilities"]),
                EXPECTED_PLATFORM_CAPABILITIES,
            )

            (validation_root / "VERSION").write_text(
                " 0.1.0\n", encoding="ascii"
            )
            with self.assertRaisesRegex(RuntimeError, "VERSION is malformed"):
                collect_runtime_release_metadata(runtime_root, validation_root)

            malformed = _exact_payload(runtime_root)
            malformed["version"] = "0.1"
            _write_executable(
                info, json.dumps(malformed, separators=(",", ":"))
            )
            (runtime_root / "VERSION").write_text("0.1\n", encoding="ascii")
            (validation_root / "VERSION").write_text(
                "0.1\n", encoding="ascii"
            )
            with self.assertRaisesRegex(RuntimeError, "version is malformed"):
                collect_runtime_release_metadata(runtime_root, validation_root)

            version_file = validation_root / "VERSION"
            exact_bound = "1.1." + "1" * 251
            version_file.write_bytes((exact_bound + "\n").encode("ascii"))
            self.assertEqual(read_product_version_file(version_file), exact_bound)
            for malformed_bytes in (
                (exact_bound + "1\n").encode("ascii"), b"0.1.0\r\n", b"0.1.0\n\n", b"0.1.0", b"\xff\n",
            ):
                with self.subTest(version_bytes=malformed_bytes[:16]):
                    version_file.write_bytes(malformed_bytes)
                    with self.assertRaises(ValueError):
                        read_product_version_file(version_file)
            version_file.unlink()
            version_file.symlink_to(runtime_root / "VERSION")
            with self.assertRaises(OSError):
                read_product_version_file(version_file)
            version_file.unlink()
            os.mkfifo(version_file)
            with self.assertRaises(ValueError):
                read_product_version_file(version_file)
