"""Run functional checks of the native packager and piped POSIX installation.

An explicit completed build supplies the installer and SDK through its existing
install components. The suite owns the temporary stage and its cleanup. These
checks exercise package production, archive admission, and installation behavior;
distributed-SDK qualification without source remains a separate native gate.
"""

from __future__ import annotations

import binascii
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import gzip
import hashlib
import io
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import unittest

import pytest


SOURCE_ROOT = Path(__file__).resolve().parents[2]


def _environment() -> dict[str, str]:
    """Use the same fixed tool namespace without ambient loader/Python inputs."""
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def _member(name: str, data: bytes = b"", *, directory: bool = False) -> tuple[tarfile.TarInfo, bytes]:
    """Author one independent canonical TAR member expectation."""
    member = tarfile.TarInfo(name)
    member.uid = member.gid = member.mtime = 0
    member.uname = member.gname = ""
    member.mode = 0o755 if directory else 0o644
    member.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    member.size = 0 if directory else len(data)
    return member, data


def _write_archive(path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    """Write fixture bytes with the standard library, independently of native code."""
    with path.open("wb") as output, gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for member, data in members:
                archive.addfile(member, io.BytesIO(data) if member.isfile() else None)


@pytest.mark.usefixtures("package_build")
class PackageCommandTest(unittest.TestCase):
    """Validate real process exits, namespace effects, and independently authored bytes."""

    binary: Path
    sdk_root: Path
    strace: Path
    build_dir: Path

    def setUp(self) -> None:
        """Own protected fixtures and the compiled product's version/tuple identity."""
        self.addCleanup(os.umask, os.umask(0o022))
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        temporary = self.resources.enter_context(tempfile.TemporaryDirectory(prefix="kinetum-package-test-"))
        self.root = Path(temporary).resolve(strict=True)
        self.version = (self.sdk_root / "VERSION").read_text(encoding="ascii").removesuffix("\n")
        self.arch = platform.machine()
        self.envelope_name = f"kinetum-sdk-{self.version}"
        self.asset = self.root / f"kinetum-sdk-{self.version}-{self.arch}.tar.gz"
        self.prefix = self.root / "installed"

    def _run(self, *arguments: str, stdout=subprocess.PIPE) -> subprocess.CompletedProcess[str]:
        """Invoke the production image with a bounded wait and no input stream."""
        return subprocess.run(
            [os.fspath(self.binary), *arguments], stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=subprocess.PIPE, text=True, check=False,
            timeout=120, env=_environment(), cwd=self.root,
        )

    def _install(self, stdout=subprocess.PIPE, *, expected_digest: bool = False) -> subprocess.CompletedProcess[str]:
        """Install fixture bytes, optionally asserting an independently authored digest."""
        arguments = ["install", "--archive", os.fspath(self.asset), "--prefix", os.fspath(self.prefix)]
        if expected_digest:
            arguments.extend(("--sha256", hashlib.sha256(self.asset.read_bytes()).hexdigest()))
        return self._run(*arguments, stdout=stdout)

    def _configure_staging_fixture(self, source: Path, build: Path, payload_code: str = "") -> None:
        """Configure a real CMake install fixture without compiling or claiming release qualification."""
        source.mkdir(parents=True, exist_ok=True)
        (source / "VERSION").write_text(self.version + "\n", encoding="ascii")
        (source / "VERSION").chmod(0o664)
        shutil.copyfile(self.binary, source / "kinetum_package")
        (source / "kinetum_package").chmod(0o775)
        (source / "CMakeLists.txt").write_text(
            'cmake_minimum_required(VERSION 3.28)\nproject(package_fixture NONE)\n'
            'install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/kinetum_package" DESTINATION . '
            'COMPONENT KinetumPackageEnvelope EXCLUDE_FROM_ALL)\n'
            f'install(CODE [===[{payload_code}]===] COMPONENT KinetumRuntimePayload EXCLUDE_FROM_ALL)\n',
            encoding="utf-8",
        )
        configured = subprocess.run(
            ["/usr/bin/cmake", "-S", os.fspath(source), "-B", os.fspath(build)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False,
            timeout=30, env=_environment(),
        )
        self.assertEqual(configured.returncode, 0, configured.stderr)
        # Build inputs may be group-writable; CMake stages protected product files.
        (build / "CMakeCache.txt").chmod(0o664)

    def _sdk_fixture(self) -> Path:
        """Stage the actual SDK files and native installer for independent archive fixtures."""
        envelope = self.root / self.envelope_name
        envelope.mkdir()
        shutil.copytree(self.sdk_root, envelope / "sdk")
        shutil.copyfile(self.binary, envelope / "kinetum_package")
        (envelope / "kinetum_package").chmod(0o755)
        self._write_manifest(envelope / "sdk")
        return envelope

    @staticmethod
    def _write_manifest(payload: Path) -> None:
        """Author checksum rows from fixture bytes, never using the production generator."""
        manifest = payload / "share/kinetum/release/sdk_payload_manifest.sha256"
        rows = []
        for path in sorted(payload.rglob("*")):
            if path.is_file() and path != manifest:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                rows.append(f"{digest}  {path.relative_to(payload).as_posix()}\n")
        manifest.write_text("".join(rows), encoding="ascii")

    def _archive_tree(self, envelope: Path) -> None:
        """Archive the complete fixture with independently chosen canonical metadata."""
        members = [_member(self.envelope_name, directory=True)]
        for path in sorted(envelope.rglob("*")):
            name = f"{self.envelope_name}/{path.relative_to(envelope).as_posix()}"
            member, data = _member(name, b"" if path.is_dir() else path.read_bytes(), directory=path.is_dir())
            member.mode = 0o755 if path.is_dir() or os.access(path, os.X_OK) else 0o644
            members.append((member, data))
        _write_archive(self.asset, members)

    def _refuses_members(self, members: list[tuple[tarfile.TarInfo, bytes]], diagnostic: str) -> None:
        """Require the intended archive-admission failure before installation-prefix creation."""
        _write_archive(self.asset, members)
        result = self._install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(diagnostic, result.stderr)
        self.assertFalse(self.prefix.exists())
        self.assertFalse(list(self.root.glob(".kinetum-package-*")))

    def test_commands_reject_cross_operation_and_repeated_inputs(self) -> None:
        """Preparation cannot accept keys, signing cannot select code, and inputs are unique."""
        seed = self.root / "must-not-exist.seed"
        for arguments in (
            ("prepare", "--key", "release.seed"),
            ("prepare", "--source-root", "."),
            ("prepare", "--target-tuple", "linux-gnu-x86_64"),
            ("prepare", "--documentation-root", "."),
            ("prepare", "--output", "archive.tar.gz"),
            ("sign", "--signing-key-fd", "3"),
            ("sign", "--source-root", "."),
            ("sign", "--build-dir", "."),
            ("sign", "--target-tuple", "linux-gnu-x86_64"),
            ("sign", "--output", "archive.tar.gz"),
            ("sign", "--component", "foreign.so"),
            ("prepare", "--product", "runtime", "--build-dir", os.fspath(self.build_dir),
             "--release-url", "https://invalid.example/release"),
            ("keygen", "--output", os.fspath(seed), "--output", os.fspath(seed)),
            ("unknown-operation",),
        ):
            with self.subTest(arguments=arguments):
                result = self._run(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(seed.exists())
                self.assertFalse(list(self.root.glob(".kinetum-*")))
        for digest in ("0" * 63, "A" * 64, "g" * 64):
            with self.subTest(digest=digest):
                result = self._run("install", "--archive", os.fspath(self.asset), "--sha256", digest)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("--sha256", result.stderr)
        for url in ("http://invalid.example/release", "https://invalid.example/release/",
                    "https://user@invalid.example/release", "https://invalid.example/release?query=1",
                    "https://invalid.example/'$(touch marker)'"):
            with self.subTest(url=url):
                result = self._run("sign", "--candidate", os.fspath(self.asset), "--key", os.fspath(seed),
                                   "--release-url", url)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse((self.root / "dist").exists())
                self.assertFalse(seed.exists())

    def test_sdk_replacement_preserves_every_peer_domain(self) -> None:
        """SDK replacement preserves peer objects, metadata and bytes and converges on retry."""
        envelope = self._sdk_fixture()
        self._archive_tree(envelope)
        self.prefix.mkdir(mode=0o755)
        for name in ("VERSION", "bin/runtime-sentinel", "dependencies/native-sentinel"):
            path = self.prefix / name
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            path.write_bytes(b"independent owner\n")
            path.chmod(0o644)
        peer_metadata = {path: path.stat(follow_symlinks=False) for path in self.prefix.rglob("*")}
        for attempt in range(2):
            superseded = self.prefix / "sdk/superseded-file"
            if attempt == 1:
                superseded.write_bytes(b"prior owned SDK contents\n")
                superseded.chmod(0o644)
            result = self._install(expected_digest=attempt == 1)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((self.prefix / "sdk/VERSION").read_bytes(), (self.sdk_root / "VERSION").read_bytes())
            for name in ("VERSION", "bin/runtime-sentinel", "dependencies/native-sentinel"):
                self.assertEqual((self.prefix / name).read_bytes(), b"independent owner\n")
            for path, before in peer_metadata.items():
                after = path.stat(follow_symlinks=False)
                for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
                              "st_mtime_ns", "st_ctime_ns"):
                    self.assertEqual(getattr(after, field), getattr(before, field), f"{path}: {field}")
            self.assertFalse(list(self.root.glob(".kinetum-package-*")))
            self.assertFalse(superseded.exists())

    def test_sdk_preparation_keeps_outputs_outside_input_trees(self) -> None:
        """Existing builds and new output roots cannot lie inside copied SDK inputs."""
        source = self.root / "source"
        input_trees = (source / "examples", source / "include/kinetum")
        for index, tree in enumerate(input_trees):
            for role in ("build", "output"):
                with self.subTest(tree=tree, role=role):
                    build = (tree if role == "build" else self.root) / f"build-{index}-{role}"
                    output = (tree if role == "output" else self.root) / f"output-{index}-{role}"
                    self._configure_staging_fixture(source, build)
                    cache = (build / "CMakeCache.txt").read_bytes()
                    result = self._run(
                        "prepare", "--product", "sdk", "--build-dir", os.fspath(build),
                        "--output-dir", os.fspath(output),
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("outside projected input trees", result.stderr)
                    self.assertEqual((build / "CMakeCache.txt").read_bytes(), cache)
                    self.assertFalse(output.exists())
                    self.assertFalse(list(tree.glob(".kinetum-package-*")))

    def test_prepare_requires_existing_unambiguous_build_inputs(self) -> None:
        """Missing, empty, malformed, or duplicate consumed cache entries never start staging."""
        build = self.root / "build"
        output = self.root / "dist"
        command = ("prepare", "--product", "runtime", "--build-dir", os.fspath(build))
        missing = self._run(*command)
        self.assertNotEqual(missing.returncode, 0)
        self.assertFalse(build.exists())
        build.mkdir()
        for cache in (None, "", "CMAKE_HOME_DIRECTORY:INTERNAL=\n",
                      "CMAKE_HOME_DIRECTORY\n", "CMAKE_HOME_DIRECTORY:INTERNAL=/absent\n",
                      f"CMAKE_HOME_DIRECTORY:INTERNAL={self.root}\n" * 2):
            with self.subTest(cache=cache):
                if cache is not None:
                    (build / "CMakeCache.txt").write_text(cache, encoding="utf-8")
                rejected = self._run(*command)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(output.exists())

        bounded = self.root / "bounded-build"
        self._configure_staging_fixture(self.root / "bounded-source", bounded,
                                        'message(FATAL_ERROR "cache reached staging")')
        cache_file = bounded / "CMakeCache.txt"
        original = cache_file.read_bytes()
        at_bound = original + b"#" + b"x" * (4 * 1024**2 - len(original) - 2) + b"\n"
        command = ("prepare", "--product", "runtime", "--build-dir", os.fspath(bounded))
        for content, diagnostic in ((at_bound, "cache reached staging"),
                                    (at_bound + b"\n", "exceeds the admission size bound")):
            with self.subTest(size=len(content)):
                cache_file.write_bytes(content)
                result = self._run(*command)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)

    def test_prepare_selects_existing_build_and_matches_its_packager(self) -> None:
        """Two builds remain explicit choices; a different image rejects before payload staging."""
        for name in ("first", "second"):
            source = self.root / f"{name}-source"
            build = self.root / f"{name}-build"
            marker = self.root / f"{name}-staged"
            self._configure_staging_fixture(
                source, build, f'file(WRITE [==[{marker}]==] "selected")\n'
                'message(FATAL_ERROR "fixture payload boundary")',
            )
            (source / "CMakeLists.txt").write_text('message(FATAL_ERROR "must not reconfigure")\n', encoding="ascii")
            command = ("prepare", "--product", "runtime", "--build-dir", os.fspath(build))
            cache = (build / "CMakeCache.txt").read_bytes()
            selected = self._run(*command)
            self.assertNotEqual(selected.returncode, 0)
            self.assertIn("fixture payload boundary", selected.stderr)
            self.assertEqual(marker.read_text(encoding="ascii"), "selected")
            self.assertEqual((build / "CMakeCache.txt").read_bytes(), cache)
            marker.unlink()
            with (source / "kinetum_package").open("ab") as different:
                different.write(b"different build")
            mismatched = self._run(*command)
            self.assertNotEqual(mismatched.returncode, 0)
            self.assertIn("invoke that build's kinetum_package", mismatched.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse(list((self.root / "dist").glob(".kinetum-*")))

    def test_release_staging_requires_release_configuration(self) -> None:
        """The selected build stages Release and refuses Debug under either CPU mode."""
        stage = self.root / "stage"
        result = subprocess.run(
            ["/usr/bin/cmake", "--install", os.fspath(self.build_dir), "--config", "Debug",
             "--component", "KinetumPackageEnvelope", "--prefix", os.fspath(stage)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False,
            timeout=30, env=_environment(),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires the Release configuration", result.stderr)
        self.assertFalse(stage.exists())
        accepted = subprocess.run(
            ["/usr/bin/cmake", "--install", os.fspath(self.build_dir), "--config", "Release",
             "--component", "KinetumPackageEnvelope", "--prefix", os.fspath(stage)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False,
            timeout=30, env=_environment(),
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual({path.name for path in stage.iterdir()}, {"kinetum_package"})
        installer = stage / "kinetum_package"
        self.assertEqual(installer.read_bytes(), self.binary.read_bytes())
        self.assertEqual(installer.stat().st_mode & 0o7777, 0o755)

    def test_sign_creates_selected_output_directory_without_replacing_contents(self) -> None:
        """Default and nested output roots are created; existing bytes and modes are preserved."""
        candidate = self.root / f"kinetum-runtime-{self.version}-{self.arch}.candidate.tar.gz"
        candidate.write_bytes(b"invalid gzip")
        key = self.root / "unopened.seed"
        for selection in (None, "nested/artifacts", "existing"):
            output = self.root / (selection or "dist")
            with self.subTest(selection=selection):
                if selection == "existing":
                    output.mkdir(mode=0o700)
                    (output / "sentinel").write_bytes(b"preserved")
                arguments = ["sign", "--candidate", os.fspath(candidate), "--key", os.fspath(key)]
                if selection is not None:
                    arguments.extend(("--output-dir", selection))
                result = self._run(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(output.is_dir())
                self.assertEqual(output.stat().st_mode & 0o7777, 0o700 if selection == "existing" else 0o755)
                self.assertFalse(list(output.glob(".kinetum-*")))
                self.assertFalse(list(output.glob("*.tar.gz")))
        self.assertEqual((self.root / "existing/sentinel").read_bytes(), b"preserved")
        for name in ("alias", "ordinary-file", "absent-alias"):
            output = self.root / name
            if name == "ordinary-file":
                output.write_bytes(b"preserved")
            else:
                output.symlink_to(self.root / ("existing" if name == "alias" else "absent"))
            result = self._run("sign", "--candidate", os.fspath(candidate), "--key", os.fspath(key),
                               "--output-dir", os.fspath(output))
            self.assertNotEqual(result.returncode, 0)
        writable = self.root / "writable"
        writable.mkdir()
        writable.chmod(0o777)
        rejected = self._run("sign", "--candidate", os.fspath(candidate), "--key", os.fspath(key),
                             "--output-dir", os.fspath(writable / "new-output"))
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("owned protected parent", rejected.stderr)
        self.assertFalse((writable / "new-output").exists())
        self.assertEqual(writable.stat().st_mode & 0o7777, 0o777)
        self.assertEqual((self.root / "ordinary-file").read_bytes(), b"preserved")
        self.assertFalse((self.root / "absent").exists())
        rejected = self._run("sign", "--candidate", os.fspath(candidate), "--key", os.fspath(key),
                             "--output-dir", "alias/../erased-link")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse((self.root / "erased-link").exists())

    def test_unmanifested_entries_reject_before_domain_replacement(self) -> None:
        """An undeclared payload file cannot replace any prior SDK byte."""
        envelope = self._sdk_fixture()
        (envelope / "sdk/extra").write_bytes(b"unlisted\n")
        self._archive_tree(envelope)
        (self.prefix / "sdk").mkdir(parents=True)
        marker = self.prefix / "sdk/owner-state"
        marker.write_bytes(b"original\n")
        result = self._install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_bytes(), b"original\n")

    def test_manifest_rows_require_exact_separator_and_final_newline(self) -> None:
        """The native reader rejects single-space and unterminated fixture rows."""
        envelope = self._sdk_fixture()
        manifest = envelope / "sdk/share/kinetum/release/sdk_payload_manifest.sha256"
        original = manifest.read_bytes()
        for malformed in (original.replace(b"  ", b" ", 1), original[:-1]):
            with self.subTest(malformed=malformed[:80]):
                manifest.write_bytes(malformed)
                self._archive_tree(envelope)
                result = self._install()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.prefix.exists())

    def test_indirect_destination_rejects_without_touching_its_target(self) -> None:
        """An SDK destination alias cannot redirect replacement outside the prefix."""
        envelope = self._sdk_fixture()
        self._archive_tree(envelope)
        self.prefix.mkdir()
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "sentinel").write_bytes(b"preserve")
        (self.prefix / "sdk").symlink_to(foreign, target_is_directory=True)
        result = self._install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((foreign / "sentinel").read_bytes(), b"preserve")
        alias = self.root / "indirect-parent"
        alias.symlink_to(foreign, target_is_directory=True)
        self.prefix = alias / "installation"
        result = self._install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((foreign / "installation").exists())
        self.assertEqual((foreign / "sentinel").read_bytes(), b"preserve")

    def test_envelope_requires_a_native_versioned_installer(self) -> None:
        """Foreign tuples, missing or stale ELF version markers, and scripted installers reject."""
        envelope = self._sdk_fixture()
        self._archive_tree(envelope)
        other_arch = "aarch64" if self.arch == "x86_64" else "x86_64"
        foreign = self.root / f"kinetum-sdk-{self.version}-{other_arch}.tar.gz"
        foreign.write_bytes(self.asset.read_bytes())
        result = self._run("install", "--archive", os.fspath(foreign), "--prefix", os.fspath(self.prefix))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the native host tuple", result.stderr)
        self.assertFalse(self.prefix.exists())
        installer = envelope / "kinetum_package"
        original = installer.read_bytes()
        version_marker = b"KINETUM_RELEASE_VERSION=" + self.version.encode("ascii") + b"\0"
        other_version = ("1" if self.version[0] != "1" else "2") + self.version[1:]
        for needle, replacement, diagnostic in (
            (version_marker, b"KINETUM_RELEASE_VERSION=" + other_version.encode("ascii") + b"\0",
             "ELF compiled version disagrees with package VERSION"),
            (b"kinetum_release_version_marker\0", b"xinetum_release_version_marker\0",
             "ELF lacks one exact compiled version marker"),
        ):
            with self.subTest(rejection=diagnostic):
                self.assertIn(needle, original)
                self.assertEqual(len(needle), len(replacement))
                installer.write_bytes(original.replace(needle, replacement))
                self._archive_tree(envelope)
                rejected = self._install()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(diagnostic, rejected.stderr)
                self.assertFalse(self.prefix.exists())
                self.assertFalse(list(self.root.glob(".kinetum-package-*")))
        installer.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        self._archive_tree(envelope)
        result = self._install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.prefix.exists())
        self.assertFalse(list(self.root.glob(".kinetum-package-*")))

    def test_checksum_mismatch_precedes_archive_decode(self) -> None:
        """Delivery integrity precedes codec work, whose malformed streams still reject."""
        self.asset.write_bytes(b"not gzip")
        for mode in (0o664, 0o646):
            with self.subTest(archive_mode=mode):
                self.asset.chmod(mode)
                rejected = self._install()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("forbidden writable permission bits", rejected.stderr)
                self.assertFalse(self.prefix.exists())
        self.asset.chmod(0o644)
        result = self._run(
            "install", "--archive", os.fspath(self.asset), "--sha256", "0" * 64,
            "--prefix", os.fspath(self.prefix),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256", result.stderr)
        self.assertFalse(self.prefix.exists())
        envelope = self._sdk_fixture()
        self._archive_tree(envelope)
        original = self.asset.read_bytes()

        # Author corrupt CRC/length fields independently of the decoder.
        bad_crc = bytearray(original)
        bad_crc[-8] ^= 1
        bad_length = bytearray(original)
        bad_length[-4] ^= 1
        header = bytearray(original[:10])
        header[3] |= 2
        wrong_header_crc = ((binascii.crc32(header) & 0xffff) ^ 1).to_bytes(2, "little")
        bad_header_crc = bytes(header) + wrong_header_crc + original[10:]
        malformed_streams = (
            b"not gzip", original[:-1], original + b"unconsumed trailer",
            bytes(bad_crc), bytes(bad_length), bad_header_crc,
        )
        for malformed in malformed_streams:
            with self.subTest(stream=malformed[-24:]):
                self.asset.write_bytes(malformed)
                rejected = self._install()
                self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                self.assertFalse(self.prefix.exists())
                self.assertFalse(list(self.root.glob(".kinetum-package-*")))

        decoded = gzip.decompress(original)
        split = len(decoded) // 2
        self.asset.write_bytes(gzip.compress(decoded[:split], mtime=0) + gzip.compress(decoded[split:], mtime=0))
        admitted = self._install()
        self.assertEqual(admitted.returncode, 0, admitted.stderr)

    def test_extraction_rejects_traversal_before_creating_any_member(self) -> None:
        """No relative, absolute, or backslash escape reaches a destination name."""
        for name in ("../escape", "/escape", f"{self.envelope_name}/../escape", f"{self.envelope_name}/a\\b"):
            with self.subTest(name=name):
                self._refuses_members([_member(self.envelope_name, directory=True), _member(name, b"bad")],
                                      "payload manifest path")
                self.assertFalse((self.root / "escape").exists())

    def test_extraction_rejects_links_duplicates_and_noncanonical_order(self) -> None:
        """Links, special objects, duplicate names and reordered members fail closed."""
        root = _member(self.envelope_name, directory=True)
        ordinary = _member(f"{self.envelope_name}/a", b"a")
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                member, data = _member(f"{self.envelope_name}/link")
                member.type = kind
                member.linkname = "a" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                self._refuses_members([root, ordinary, (member, data)],
                                      "archive member has forbidden type or authority-bearing metadata")
        self._refuses_members([root, ordinary, ordinary], "strictly ordered unique membership")
        self._refuses_members([root, _member(f"{self.envelope_name}/b", b"b"), ordinary],
                              "strictly ordered unique membership")
        self._refuses_members([root, _member(f"{self.envelope_name}/missing/child", b"child")],
                              "declared parent directory")
        self._refuses_members([root, ordinary, _member(f"{self.envelope_name}/empty", directory=True)],
                              "archive directory membership is incomplete or unbound")

    def test_extraction_rejects_authority_bearing_metadata(self) -> None:
        """Foreign owner, group, mode, and timestamp fields cannot enter a package."""
        changes = (("uid", 1), ("gid", 1), ("uname", "foreign"), ("gname", "foreign"), ("mode", 0o666), ("mtime", 1))
        for field, value in changes:
            with self.subTest(field=field):
                member, data = _member(f"{self.envelope_name}/a", b"a")
                setattr(member, field, value)
                self._refuses_members([_member(self.envelope_name, directory=True), (member, data)],
                                      "archive member has forbidden type or authority-bearing metadata")

    def test_pax_comments_do_not_change_file_authority(self) -> None:
        """A non-authoritative PAX comment does not change an otherwise exact install."""
        envelope = self._sdk_fixture()
        self._archive_tree(envelope)
        with tarfile.open(self.asset, "r:gz") as archive:
            members = []
            for member in archive:
                data = archive.extractfile(member).read() if member.isfile() else b""
                member.pax_headers = {"comment": "fixture annotation"}
                members.append((member, data))
        _write_archive(self.asset, members)
        result = self._install()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_file_bound_checks_claim_before_reading_payload(self) -> None:
        """The inclusive file bound distinguishes a truncated body from an overbound claim."""
        for claimed, overbound in ((2 * 1024**3, False), (2 * 1024**3 + 1, True)):
            with self.subTest(claimed=claimed):
                root, _ = _member(self.envelope_name, directory=True)
                member, _ = _member(f"{self.envelope_name}/a")
                member.size = claimed
                raw = root.tobuf(tarfile.USTAR_FORMAT) + member.tobuf(tarfile.USTAR_FORMAT) + b"\0" * 1024
                self.asset.write_bytes(gzip.compress(raw, mtime=0))
                result = self._install()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual("file-byte bound" in result.stderr, overbound, result.stderr)
                self.assertFalse(self.prefix.exists())

    def test_keygen_is_private_and_never_replaces_an_existing_seed(self) -> None:
        """Generated keys have exact custody, expose only public text, and never overwrite."""
        seed = self.root / "release.seed"
        result = self._run("keygen", "--output", os.fspath(seed))
        self.assertEqual(result.returncode, 0, result.stderr)
        original = seed.read_bytes()
        self.assertEqual(len(original), 32)
        self.assertEqual(seed.stat().st_mode & 0o7777, 0o400)
        self.assertEqual(seed.stat().st_nlink, 1)
        self.assertRegex(result.stdout, r"Public anchor: [0-9a-f]{64}\n")
        repeated = self._run("keygen", "--output", os.fspath(seed))
        self.assertNotEqual(repeated.returncode, 0)
        self.assertEqual(seed.read_bytes(), original)
        self.assertFalse(list(self.root.glob(".kinetum-seed-*")))

    def test_sign_opens_protected_key_only_after_archive_decoder_retires(self) -> None:
        """The real sign entrance reaps decoding before opening a direct, metadata-admitted key."""
        self.envelope_name = f"kinetum-runtime-{self.version}"
        self.asset = self.root / f"{self.envelope_name}-{self.arch}.candidate.tar.gz"
        envelope = self.root / self.envelope_name
        payload = envelope / "runtime"
        payload.mkdir(parents=True)
        # This minimal candidate reaches key admission; it has no provider
        # inventory and cannot represent a prepared or signed runtime product.
        for name in ("VERSION", "LICENSE", "NOTICE"):
            shutil.copyfile(SOURCE_ROOT / name, payload / name)
        shutil.copyfile(SOURCE_ROOT / "tooling/release/packaging/runtime_THIRD_PARTY_NOTICES.md",
                        payload / "THIRD_PARTY_NOTICES.md")
        shutil.copyfile(self.build_dir / "release-packaging/runtime_README.md", payload / "README.md")
        shutil.copyfile(self.binary, envelope / "kinetum_package")
        (envelope / "kinetum_package").chmod(0o755)
        self._archive_tree(envelope)
        seed = self.root / "selected.seed"
        seed.write_bytes(b"x" * 32)
        seed.chmod(0o400)
        trace = self.root / "sign.trace"
        result = subprocess.run(
            [os.fspath(self.strace), "-f", "-s", "4096", "-o", os.fspath(trace),
             "-e", "trace=openat,close,pread64,prlimit64,prctl,wait4,execve",
             os.fspath(self.binary), "sign", "--candidate", os.fspath(self.asset), "--key", os.fspath(seed)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False,
            timeout=30, env=_environment(), cwd=self.root,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not derive the configured production trust anchor", result.stderr)
        calls = trace.read_text(encoding="utf-8")
        # Dump protection also prevents an unprivileged tracer from reading
        # pathname buffers. Descriptor numbers, byte counts and offsets remain
        # observable. The dummy seed is this fixture's sole 32-byte read at zero.
        reads = list(re.finditer(r'(?m)^(\d+)\s+pread64\((\d+), [^\n]*, 32, 0\)\s+= 32$', calls))
        self.assertEqual(len(reads), 1, "expected one complete 32-byte seed read")
        key_read = reads[0]
        parent = re.search(r'(?m)^(\d+)\s+execve\(', calls)
        self.assertIsNotNone(parent, "signing process is absent from the trace")
        self.assertEqual(key_read[1], parent[1], "the seed must be read by the signing parent")
        openings = list(re.finditer(
            rf'(?m)^{parent[1]}\s+openat\([^\n]*\)\s+= {key_read[2]}$', calls[:key_read.start()]
        ))
        self.assertTrue(openings, "the signing parent did not open the seed descriptor before reading it")
        opened = openings[-1]
        for flag in ("O_RDONLY", "O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
            self.assertIn(flag, opened[0])
        self.assertIsNone(
            re.search(rf'(?m)^{parent[1]}\s+close\({key_read[2]}\)\s+= 0$',
                      calls[opened.end():key_read.start()]),
            "the signing parent closed the seed descriptor before reading it",
        )
        before = "\n".join(re.findall(rf'(?m)^{parent[1]}\s+(.*)$', calls[:opened.start()]))
        self.assertIsNotNone(re.search(r'prlimit64\([^\n]*RLIMIT_CORE[^\n]*rlim_cur=0[^\n]*= 0', before),
                             "core dumps were not disabled before opening the seed")
        self.assertIsNotNone(re.search(r'prctl\(PR_SET_DUMPABLE, (?:0|SUID_DUMP_DISABLE)\)[^\n]*= 0', before),
                             "dump protection was not enabled before opening the seed")
        self.assertIsNotNone(re.search(r'(?:wait4\(|<\.\.\. wait4 resumed>)[^\n]*= [1-9][0-9]*', before),
                             "the decoder was not reaped before opening the seed")
        self.assertFalse("execve(" in calls[opened.end():], "a program was executed after opening the seed")
        for mode, data, diagnostic in ((0o600, b"x" * 32, "mode must be exactly 0400"),
                                       (0o400, b"x" * 31, "exactly 32 raw bytes"),
                                       (0o400, b"x" * 33, "exactly 32 raw bytes")):
            with self.subTest(mode=mode, size=len(data)):
                seed.chmod(0o600)
                seed.write_bytes(data)
                seed.chmod(mode)
                rejected = self._run("sign", "--candidate", os.fspath(self.asset), "--key", os.fspath(seed))
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(diagnostic, rejected.stderr)
        alias = self.root / "key-alias"
        alias.symlink_to(seed)
        rejected = self._run("sign", "--candidate", os.fspath(self.asset), "--key", os.fspath(alias))
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("cannot open direct signing-key file", rejected.stderr)
        self.assertFalse(list((self.root / "dist").glob(".kinetum-*")))
        self.assertFalse(list((self.root / "dist").glob("*.tar.gz")))

    def test_failed_output_delivery_precedes_publication_or_installation(self) -> None:
        """A full output device prevents seed/package publication and SDK replacement."""
        with open("/dev/full", "wb") as full:
            seed = self.root / "undelivered.seed"
            result = self._run("keygen", "--output", os.fspath(seed), stdout=full)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(seed.exists())
            output = self.root / "undelivered-package"
            result = self._run("prepare", "--product", "sdk", "--build-dir", os.fspath(self.build_dir),
                               "--output-dir", os.fspath(output), "--release-url", "https://invalid.example/release",
                               stdout=full)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])
            envelope = self._sdk_fixture()
            self._archive_tree(envelope)
            result = self._install(stdout=full)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.prefix.exists())
        self.assertFalse(list(self.root.glob(".kinetum-seed-*")))
        self.assertFalse(list(self.root.glob(".kinetum-package-*")))

    def _prepare_sdk(self, output: Path, release_url: str | None) -> tuple[Path, Path, Path]:
        """Run real SDK production and return independently named expected output paths."""
        arguments = ["prepare", "--product", "sdk", "--build-dir", os.fspath(self.build_dir),
                     "--output-dir", os.fspath(output)]
        if release_url is not None:
            arguments.extend(("--release-url", release_url))
        result = self._run(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        name = f"kinetum-sdk-{self.version}-{self.arch}"
        return output / f"{name}.tar.gz", output / f"{name}.tar.gz.sha256", output / f"{name}.install.sh"

    def test_sdk_preparation_publishes_exact_independent_delivery_files(self) -> None:
        """Every final SDK has an installer; a missing download URL rejects before host effects."""
        release_url = "https://invalid.example/kinetum/release"
        for url in (None, release_url):
            with self.subTest(release_url=url):
                output = self.root / ("local" if url is None else "published")
                archive, checksum, script = self._prepare_sdk(output, url)
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                self.assertEqual(checksum.read_text(encoding="ascii"), f"{digest}  {archive.name}\n")
                expected = {archive.name, checksum.name, script.name}
                body = script.read_bytes()
                self.assertIn(f"digest={digest}\n".encode("ascii"), body)
                self.assertIn(f"asset=kinetum-sdk-{self.version}-{self.arch}.tar.gz\n".encode("ascii"), body)
                self.assertIn(f"[ \"$machine\" = '{self.arch}' ]".encode("ascii"), body)
                self.assertIn(f"release_url='{url or ''}'\n".encode("ascii"), body)
                self.assertTrue(body.endswith(b"}"))
                help_result = subprocess.run(
                    ["/bin/sh", os.fspath(script), "--help"], stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, check=False, timeout=10, env=_environment(),
                )
                self.assertEqual(help_result.returncode, 0, help_result.stderr)
                self.assertEqual(help_result.stdout,
                                 f"Kinetum sdk {self.version} ({self.arch}) installer\n"
                                 "Options: --prefix /absolute/path --offline-directory /asset/directory\n")
                if url is None:
                    trace = self.root / "missing-url.trace"
                    rejected = subprocess.run(
                        [os.fspath(self.strace), "-f", "-o", os.fspath(trace), "-e",
                         "trace=execve,mkdir,mkdirat,unlink,unlinkat,rename,renameat2",
                         "/bin/sh", "-s", "--", "--prefix", os.fspath(self.prefix)],
                        input=body, capture_output=True, check=False, timeout=10, env=_environment(),
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn(b"no download URL; use --offline-directory", rejected.stderr)
                    calls = trace.read_text(encoding="utf-8")
                    self.assertEqual(calls.count("execve("), 1, "missing-URL rejection executed a child")
                    self.assertIsNone(
                        re.search(r"\b(?:mkdir|mkdirat|unlink|unlinkat|rename|renameat2)\(", calls),
                        "missing-URL rejection mutated the filesystem",
                    )
                    self.assertFalse(self.prefix.exists())
                self.assertEqual({path.name for path in output.iterdir()}, expected)
                for path in output.iterdir():
                    self.assertEqual(path.stat().st_mode & 0o7777, 0o644)

    def test_delivery_publication_orders_companions_before_the_archive(self) -> None:
        """The actual syscall trace places both completed delivery files before the archive commit."""
        output = self.root / "published"
        trace = self.root / "publication.trace"
        result = subprocess.run(
            [os.fspath(self.strace), "-f", "-yy", "-s", "4096", "-o", os.fspath(trace),
             "-e", "trace=renameat2", os.fspath(self.binary), "prepare", "--product", "sdk",
             "--build-dir", os.fspath(self.build_dir), "--output-dir", os.fspath(output),
             "--release-url", "https://invalid.example/release"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False,
            timeout=120, env=_environment(), cwd=self.root,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        name = f"kinetum-sdk-{self.version}-{self.arch}"
        expected = [f"{name}.tar.gz.sha256", f"{name}.install.sh", f"{name}.tar.gz"]
        published = []
        for line in trace.read_text(encoding="utf-8").splitlines():
            if f"<{output}>" in line and line.rstrip().endswith("= 0"):
                published.extend(filename for filename in expected if f'"{filename}"' in line)
        self.assertEqual(published, expected)

    def test_delivery_retry_converges_from_each_completed_companion_prefix(self) -> None:
        """Exact retries preserve existing files and complete either interrupted publication prefix."""
        output = self.root / "published"
        url = "https://invalid.example/release"
        archive, checksum, script = self._prepare_sdk(output, url)
        files = (checksum, script, archive)
        expected = {path.name: path.read_bytes() for path in files}
        inodes = {path.name: path.stat().st_ino for path in files}
        self._prepare_sdk(output, url)
        self.assertEqual({path.name: path.stat().st_ino for path in files}, inodes)
        for retained in (0, 1, 2):
            with self.subTest(completed_companions=retained):
                for path in files[retained:]:
                    path.unlink()
                preserved = {path.name: path.stat().st_ino for path in files[:retained]}
                self._prepare_sdk(output, url)
                self.assertEqual({path.name: path.read_bytes() for path in files}, expected)
                self.assertEqual({path.name: path.stat().st_ino for path in files[:retained]}, preserved)
                self.assertEqual({path.name for path in output.iterdir()}, set(expected))

    def test_delivery_foreign_outputs_reject_before_any_new_publication(self) -> None:
        """A conflicting archive or companion stays untouched and prevents every new public file."""
        name = f"kinetum-sdk-{self.version}-{self.arch}"
        for index, foreign_name in enumerate((f"{name}.tar.gz", f"{name}.tar.gz.sha256", f"{name}.install.sh")):
            with self.subTest(foreign=foreign_name):
                output = self.root / f"conflict-{index}"
                output.mkdir(mode=0o755)
                foreign = output / foreign_name
                foreign.write_bytes(b"existing unrelated bytes\n")
                foreign.chmod(0o644)
                result = self._run(
                    "prepare", "--product", "sdk", "--build-dir", os.fspath(self.build_dir),
                    "--output-dir", os.fspath(output), "--release-url", "https://invalid.example/release",
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("different bytes", result.stderr)
                self.assertEqual(foreign.read_bytes(), b"existing unrelated bytes\n")
                self.assertEqual({path.name for path in output.iterdir()}, {foreign_name})

    def test_concurrent_delivery_preserves_one_exact_package_identity(self) -> None:
        """Equal producers converge; changing an absent or authored URL cannot replace a winning entry."""
        first_url = "https://invalid.example/first"
        for index, urls in enumerate(((None, None), (first_url, first_url),
                                      (None, first_url), (first_url, "https://invalid.example/second"))):
            with self.subTest(urls=urls):
                output = self.root / f"publication-{index}"
                commands = [
                    ["prepare", "--product", "sdk", "--build-dir", os.fspath(self.build_dir),
                     "--output-dir", os.fspath(output)] + ([] if url is None else ["--release-url", url])
                    for url in urls
                ]
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(self._run, *command) for command in commands]
                    results = [future.result(timeout=150) for future in futures]
                self.assertEqual(sorted(result.returncode for result in results),
                                 [0, 0] if urls[0] == urls[1] else [0, 1],
                                 [result.stderr for result in results])
                name = f"kinetum-sdk-{self.version}-{self.arch}"
                archive = output / f"{name}.tar.gz"
                checksum = output / f"{name}.tar.gz.sha256"
                script = output / f"{name}.install.sh"
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                self.assertEqual(checksum.read_text(encoding="ascii"), f"{digest}  {archive.name}\n")
                body = script.read_text(encoding="ascii")
                for url, result in zip(urls, results):
                    if result.returncode == 0:
                        self.assertIn(f"release_url='{url or ''}'\n", body)
                self.assertEqual({path.name for path in output.iterdir()},
                                 {path.name for path in (archive, checksum, script)})

    def test_actual_piped_install_detaches_child_input(self) -> None:
        """Local and published entries share installation with detached child input and a mandatory digest."""
        for index, url in enumerate((None, "https://invalid.example/release")):
            with self.subTest(release_url=url):
                archive, _, script = self._prepare_sdk(self.root / f"package-{index}", url)
                trace = self.root / "pipe.trace"
                result = subprocess.run(
                    [os.fspath(self.strace), "-f", "-yy", "-s", "64", "-o", os.fspath(trace), "-e",
                     "trace=execve,read,/^dup[23]$", "/bin/sh", "-s", "--",
                     "--offline-directory", os.fspath(archive.parent),
                     "--prefix", os.fspath(self.prefix)],
                    input=script.read_bytes(), capture_output=True, check=False, timeout=120, env=_environment(),
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertTrue((self.prefix / "sdk/VERSION").is_file())
                calls = trace.read_text(encoding="utf-8")
                installer_calls = [line for line in calls.splitlines()
                                   if "execve(" in line and '"install"' in line and '"--archive"' in line]
                self.assertTrue(installer_calls, "the script did not invoke native installation")
                for invocation in installer_calls:
                    self.assertIn('"--sha256", "' + hashlib.sha256(archive.read_bytes()).hexdigest() + '"', invocation)
                script_input = re.search(r"(?m)^(\d+)\s+read\(0<(pipe:\[\d+\])>,", calls)
                self.assertIsNotNone(script_input, "the shell did not read its script from a pipe")
                # dash closes the old fd 0 before duplication. Its successful
                # return identifies the new stdin even when the argument is bare.
                detached = re.search(
                    rf"(?m)^{script_input[1]}\s+dup[23]\([^\n]*\)\s+= "
                    r"0</dev/null(?:<[^>\n]*>)?>$", calls,
                )
                self.assertIsNotNone(detached, "the shell did not redirect stdin to /dev/null")
                child_exec = re.search(rf"(?m)^(?!{script_input[1]}\s)\d+\s+execve\(", calls)
                self.assertIsNotNone(child_exec, "the trace contains no child execution")
                self.assertLess(detached.end(), child_exec.start(), "a child executed before stdin redirection")
                self.assertIsNone(
                    re.search(rf"(?m)^\d+\s+read\(\d+<{re.escape(script_input[2])}>,", calls[detached.end():]),
                    "the script pipe was read after stdin redirection",
                )

    def test_truncated_piped_compound_performs_zero_effects(self) -> None:
        """Removing the terminal compound token executes no child or installation work."""
        for index, url in enumerate((None, "https://invalid.example/release")):
            archive, _, script = self._prepare_sdk(self.root / f"package-{index}", url)
            body = script.read_bytes()
            for size in (len(body) // 2, len(body) - 1):
                with self.subTest(release_url=url, size=size):
                    trace = self.root / "truncated.trace"
                    result = subprocess.run(
                        [os.fspath(self.strace), "-f", "-o", os.fspath(trace), "-e",
                         "trace=execve,mkdir,mkdirat,unlink,unlinkat,rename,renameat2",
                         "/bin/sh", "-s", "--", "--offline-directory", os.fspath(archive.parent),
                         "--prefix", os.fspath(self.prefix)],
                        input=body[:size], capture_output=True, check=False, timeout=10, env=_environment(),
                    )
                    self.assertNotEqual(result.returncode, 0)
                    calls = trace.read_text(encoding="utf-8")
                    self.assertEqual(calls.count("execve("), 1, "the truncated script executed a child")
                    self.assertIsNone(
                        re.search(r"\b(?:mkdir|mkdirat|unlink|unlinkat|rename|renameat2)\(", calls),
                        "the truncated script mutated the filesystem",
                    )
                    self.assertFalse(self.prefix.exists())

    def test_prepare_cancellation_retires_its_descendants(self) -> None:
        """SIGTERM during real CMake staging stops its whole group before returning."""
        source = self.root / "source"
        build = self.root / "build"
        self._configure_staging_fixture(
            source, build,
            'execute_process(COMMAND /bin/sh -c '
            '"echo $$ > child.pid; while [ ! -f release ]; do sleep 0.1; done" '
            f'WORKING_DIRECTORY [==[{build}]==])',
        )
        output = self.root / "dist" / f"kinetum-runtime-{self.version}-{self.arch}.candidate.tar.gz"
        process = self.resources.enter_context(subprocess.Popen(
            [os.fspath(self.binary), "prepare", "--product", "runtime", "--build-dir", os.fspath(build)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=_environment(), cwd=self.root,
        ))
        try:
            deadline = time.monotonic() + 20.0
            marker = build / "child.pid"
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.is_file())
            child_pid = int(marker.read_text(encoding="ascii").strip())
            process.send_signal(signal.SIGTERM)
            _, error = process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0, error)
            self.assertIn(b"interrupted", error)
            stat_file = Path(f"/proc/{child_pid}/stat")
            try:
                state = stat_file.read_text(encoding="ascii").rsplit(") ", 1)[1].split()[0]
            except FileNotFoundError:
                pass
            else:
                self.assertEqual(state, "Z")
            self.assertFalse(output.exists())
        finally:
            if process.poll() is None:
                if build.is_dir():
                    (build / "release").touch()
                process.send_signal(signal.SIGTERM)
                try:
                    process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=10)


@pytest.fixture(scope="class")
def package_build(package_build_directory: Path) -> Iterator[None]:
    """Stage the selected build once and remove its private files after the class.

    Missing inputs or failed staging abort the run before any package test.
    The temporary directory is reclaimed on setup failure, test failure, or
    normal fixture teardown; collection alone performs no staging.
    """
    build_dir = package_build_directory
    strace = shutil.which("strace", path=_environment()["PATH"])
    if strace is None:
        pytest.exit("package functional tests require strace", returncode=pytest.ExitCode.USAGE_ERROR)

    with tempfile.TemporaryDirectory(prefix="kinetum-package-suite-") as temporary:
        stage = Path(temporary).resolve(strict=True)
        for component in ("KinetumPackageEnvelope", "KinetumSDK"):
            try:
                subprocess.run(
                    ["/usr/bin/cmake", "--install", os.fspath(build_dir), "--config", "Release",
                     "--prefix", os.fspath(stage), "--component", component],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True,
                    timeout=120, env=_environment(),
                )
            except subprocess.CalledProcessError as exc:
                pytest.exit(f"{component} fixture staging failed:\n{exc.stdout}{exc.stderr}",
                            returncode=pytest.ExitCode.TESTS_FAILED)
            except (OSError, subprocess.TimeoutExpired) as exc:
                pytest.exit(f"{component} fixture staging failed: {exc}", returncode=pytest.ExitCode.TESTS_FAILED)
        PackageCommandTest.binary = (stage / "kinetum_package").resolve(strict=True)
        PackageCommandTest.sdk_root = (stage / "sdk").resolve(strict=True)
        PackageCommandTest.strace = Path(strace).resolve(strict=True)
        PackageCommandTest.build_dir = build_dir
        yield
